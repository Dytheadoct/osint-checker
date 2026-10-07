// OSINT checker: принимает координаты, отдаёт флаг, если точка в радиусе от эталона.
// Только stdlib, один статический бинарник.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed static
var staticFS embed.FS

// ---------- конфиг ----------

type config struct {
	secret       string        // флаг
	lat, lon     float64       // эталон
	radius       float64       // метры
	freeTries    int           // неверных попыток без блокировки
	minInterval  time.Duration // минимальная пауза между любыми попытками с одного ключа
	lockBase     time.Duration // первая блокировка после исчерпания freeTries
	lockMax      time.Duration // потолок блокировки
	decay        time.Duration // через сколько тишины счётчик ошибок обнуляется
	globalPerMin int           // потолок попыток в минуту на весь сервис
	trustProxy   bool          // доверять последнему X-Forwarded-For (за reverse proxy)
}

func envStr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envFloat(k string, d float64) float64 {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		log.Fatalf("bad %s: %v", k, err)
	}
	return f
}

func envInt(k string, d int) int {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("bad %s: %v", k, err)
	}
	return n
}

func envDur(k string, d time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	x, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("bad %s: %v", k, err)
	}
	return x
}

func loadConfig() *config {
	c := &config{
		secret:       os.Getenv("FLAG"),
		lat:          envFloat("TARGET_LAT", math.NaN()),
		lon:          envFloat("TARGET_LON", math.NaN()),
		radius:       envFloat("RADIUS_M", 10),
		freeTries:    envInt("FREE_TRIES", 5),
		minInterval:  envDur("MIN_INTERVAL", 2*time.Second),
		lockBase:     envDur("LOCK_BASE", 30*time.Second),
		lockMax:      envDur("LOCK_MAX", time.Hour),
		decay:        envDur("DECAY", time.Hour),
		globalPerMin: envInt("GLOBAL_PER_MIN", 300),
		trustProxy:   envStr("TRUST_PROXY", "0") == "1",
	}
	if c.secret == "" || math.IsNaN(c.lat) || math.IsNaN(c.lon) {
		log.Fatal("FLAG, TARGET_LAT and TARGET_LON must be set")
	}
	if c.lat < -90 || c.lat > 90 || c.lon < -180 || c.lon > 180 || c.radius <= 0 {
		log.Fatal("target coordinates or radius out of range")
	}
	return c
}

// ---------- геометрия и разбор ввода ----------

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371008.8 // средний радиус Земли, м
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dp := p2 - p1
	dl := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dp/2)*math.Sin(dp/2) + math.Cos(p1)*math.Cos(p2)*math.Sin(dl/2)*math.Sin(dl/2)
	return 2 * R * math.Asin(math.Min(1, math.Sqrt(a)))
}

var numRe = regexp.MustCompile(`[-+]?\d+(?:[.,]\d+)?`)

// parseCoords понимает "52.97, 36.07", "52.97,36.07", "52,97; 36,07", "52.97 36.07".
// Любые посторонние символы -> отказ (строгий белый список).
func parseCoords(s string) (lat, lon float64, ok bool) {
	if s == "" || len(s) > 64 {
		return
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || strings.ContainsRune(" \t,.;+-", c)) {
			return
		}
	}
	m := numRe.FindAllString(s, -1)
	if len(m) != 2 {
		return
	}
	var err error
	if lat, err = strconv.ParseFloat(strings.Replace(m[0], ",", ".", 1), 64); err != nil {
		return
	}
	if lon, err = strconv.ParseFloat(strings.Replace(m[1], ",", ".", 1), 64); err != nil {
		return
	}
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return
	}
	return lat, lon, true
}

// extract достаёт строку с координатами из JSON {"coords":"..."}, form coords=... или сырого тела.
func extract(body []byte) string {
	s := strings.TrimSpace(string(body))
	if strings.HasPrefix(s, "{") {
		var j struct {
			Coords string `json:"coords"`
		}
		if json.Unmarshal(body, &j) == nil {
			return j.Coords
		}
		return ""
	}
	if v, err := url.ParseQuery(s); err == nil && v.Get("coords") != "" {
		return v.Get("coords")
	}
	return s
}

// ---------- лимитер ----------

type entry struct {
	fails     int
	lockUntil time.Time
	nextOK    time.Time
	last      time.Time
}

type limiter struct {
	mu   sync.Mutex
	m    map[string]*entry
	cfg  *config
	gWin time.Time
	gCnt int
}

const maxEntries = 200000

func newLimiter(cfg *config) *limiter { return &limiter{m: make(map[string]*entry), cfg: cfg} }

// allow атомарно решает, пускать ли запрос, и резервирует слот (minInterval),
// поэтому пачка параллельных запросов пропускает максимум один.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.gWin) >= time.Minute {
		l.gWin, l.gCnt = now, 0
	}
	if l.gCnt >= l.cfg.globalPerMin {
		return false, l.gWin.Add(time.Minute).Sub(now)
	}
	e := l.m[key]
	if e == nil {
		if len(l.m) >= maxEntries {
			return false, 30 * time.Second
		}
		e = &entry{}
		l.m[key] = e
	}
	if now.After(e.lockUntil) && now.Sub(e.last) > l.cfg.decay {
		e.fails = 0
	}
	if now.Before(e.lockUntil) {
		return false, e.lockUntil.Sub(now)
	}
	if now.Before(e.nextOK) {
		return false, e.nextOK.Sub(now)
	}
	e.nextOK = now.Add(l.cfg.minInterval)
	e.last = now
	l.gCnt++
	return true, 0
}

// fail фиксирует неверный ответ и возвращает назначенную блокировку (0 если не назначена).
func (l *limiter) fail(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	if e == nil {
		return 0
	}
	e.fails++
	e.last = now
	if e.fails <= l.cfg.freeTries {
		return 0
	}
	n := min(e.fails-l.cfg.freeTries-1, 20)
	d := l.cfg.lockBase << n
	if d <= 0 || d > l.cfg.lockMax {
		d = l.cfg.lockMax
	}
	e.lockUntil = now.Add(d)
	return d
}

func (l *limiter) gc() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		l.mu.Lock()
		for k, e := range l.m {
			if now.After(e.lockUntil) && now.Sub(e.last) > l.cfg.decay {
				delete(l.m, k)
			}
		}
		l.mu.Unlock()
	}
}

// ---------- HTTP ----------

type server struct {
	cfg *config
	lim *limiter
}

type resp struct {
	OK         bool   `json:"ok"`
	Msg        string `json:"msg,omitempty"`
	Flag       string `json:"flag,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

func reply(w http.ResponseWriter, code int, v resp) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientKey: IPv4 как есть, IPv6 агрегируем до /64 (иначе ротация адресов внутри префикса обходит лимит).
func (s *server) clientKey(r *http.Request) string {
	var ip net.IP
	if s.cfg.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			p := strings.Split(xff, ",")
			ip = net.ParseIP(strings.TrimSpace(p[len(p)-1])) // последний = добавлен нашим прокси
		}
	}
	if ip == nil {
		h, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			h = r.RemoteAddr
		}
		if ip = net.ParseIP(h); ip == nil {
			return h
		}
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

func (s *server) check(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		reply(w, http.StatusMethodNotAllowed, resp{Msg: "используйте POST"})
		return
	}
	key := s.clientKey(r)
	now := time.Now()

	// Лимит проверяется ДО разбора и сравнения координат: пока клиент заблокирован,
	// ответ не зависит от ввода, поэтому оракула нет (в т.ч. для верного ответа).
	if ok, wait := s.lim.allow(key, now); !ok {
		secs := int(math.Ceil(wait.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		reply(w, http.StatusTooManyRequests, resp{Msg: "слишком много попыток", RetryAfter: secs})
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil {
		reply(w, http.StatusRequestEntityTooLarge, resp{Msg: "слишком большой запрос"})
		return
	}
	lat, lon, ok := parseCoords(extract(body))
	if !ok {
		reply(w, http.StatusBadRequest, resp{Msg: "не удалось разобрать координаты"})
		return
	}

	d := haversine(lat, lon, s.cfg.lat, s.cfg.lon)
	if d <= s.cfg.radius {
		log.Printf("SOLVED ip=%s lat=%.6f lon=%.6f dist=%.1fm", key, lat, lon, d)
		reply(w, http.StatusOK, resp{OK: true, Msg: "верно", Flag: s.cfg.secret})
		return
	}

	lock := s.lim.fail(key, time.Now())
	// Расстояние пишем только в лог организатора; пользователю не отдаём (анти-трилатерация).
	log.Printf("MISS ip=%s lat=%.6f lon=%.6f dist=%.1fm lock=%s", key, lat, lon, d, lock)
	out := resp{Msg: "неверно"}
	if lock > 0 {
		out.RetryAfter = int(math.Ceil(lock.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(out.RetryAfter))
	}
	reply(w, http.StatusOK, out)
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func healthcheck(addr string) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		os.Exit(1)
	}
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	os.Exit(0)
}

func main() {
	hc := flag.Bool("healthcheck", false, "probe /healthz and exit (for container HEALTHCHECK)")
	flag.Parse()
	addr := envStr("ADDR", ":8080")
	if *hc {
		healthcheck(addr)
	}

	cfg := loadConfig()
	s := &server{cfg: cfg, lim: newLimiter(cfg)}
	go s.lim.gc()

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal(err)
	}
	static := http.FileServer(http.FS(sub))

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/api/check", s.check)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		static.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           secure(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()

	log.Printf("listening on %s, radius=%.0fm, free_tries=%d, trust_proxy=%v", addr, cfg.radius, cfg.freeTries, cfg.trustProxy)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
