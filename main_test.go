package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseCoords(t *testing.T) {
	good := map[string][2]float64{
		"10.123456, 20.654321": {10.123456, 20.654321},
		"10.123456,20.654321":  {10.123456, 20.654321},
		"10,123456; 20,654321": {10.123456, 20.654321},
		"  -33.8688 151.2093 ": {-33.8688, 151.2093},
	}
	for in, want := range good {
		lat, lon, ok := parseCoords(in)
		if !ok || lat != want[0] || lon != want[1] {
			t.Errorf("%q: got %v %v %v", in, lat, lon, ok)
		}
	}
	bad := []string{"", "abc", "10.5", "91, 10", "10, 181", "10.9°N 20.1°E", "10.1;20.2;30.3",
		"10.1, 20.2 OR 1=1", strings.Repeat("1", 100)}
	for _, in := range bad {
		if _, _, ok := parseCoords(in); ok {
			t.Errorf("%q must be rejected", in)
		}
	}
}

func TestExtract(t *testing.T) {
	for _, in := range []string{`{"coords":"1.5, 2.5"}`, `coords=1.5%2C+2.5`, `coords=1.5,2.5`, `1.5, 2.5`} {
		if _, _, ok := parseCoords(extract([]byte(in))); !ok {
			t.Errorf("%q not parsed", in)
		}
	}
}

func TestRadius(t *testing.T) {
	const lat, lon = 10.0, 20.0
	for _, tc := range []struct {
		m  float64
		in bool
	}{{0, true}, {9, true}, {11, false}, {50, false}} {
		d := haversine(lat, lon, lat+tc.m/111195.0, lon)
		if (d <= 10) != tc.in {
			t.Errorf("offset %.0fm: dist=%.2f", tc.m, d)
		}
	}
}

func TestLimiter(t *testing.T) {
	cfg := &config{freeTries: 2, minInterval: time.Second, lockBase: 10 * time.Second,
		lockMax: time.Minute, decay: time.Hour, globalPerMin: 1000}
	l := newLimiter(cfg)
	now := time.Unix(1000, 0)

	if ok, _ := l.allow("a", now); !ok {
		t.Fatal("first request must pass")
	}
	if ok, _ := l.allow("a", now.Add(100*time.Millisecond)); ok {
		t.Fatal("request inside min interval must be blocked")
	}
	if ok, _ := l.allow("b", now); !ok {
		t.Fatal("other key must be independent")
	}
	if d := l.fail("a", now); d != 0 {
		t.Fatalf("free try 1 locked: %v", d)
	}
	now = now.Add(2 * time.Second)
	l.allow("a", now)
	if d := l.fail("a", now); d != 0 {
		t.Fatalf("free try 2 locked: %v", d)
	}
	now = now.Add(2 * time.Second)
	l.allow("a", now)
	if d := l.fail("a", now); d != 10*time.Second {
		t.Fatalf("first lock = %v, want 10s", d)
	}
	if ok, _ := l.allow("a", now.Add(5*time.Second)); ok {
		t.Fatal("must be locked")
	}
	now = now.Add(11 * time.Second)
	if ok, _ := l.allow("a", now); !ok {
		t.Fatal("lock must expire")
	}
	if d := l.fail("a", now); d != 20*time.Second {
		t.Fatalf("second lock = %v, want 20s (escalation)", d)
	}
	// долгое затишье обнуляет счётчик
	now = now.Add(3 * time.Hour)
	if ok, _ := l.allow("a", now); !ok {
		t.Fatal("must pass after decay")
	}
	if d := l.fail("a", now); d != 0 {
		t.Fatalf("after decay should be free again, got %v", d)
	}
}

func TestGlobalLimit(t *testing.T) {
	cfg := &config{freeTries: 5, lockBase: time.Second, lockMax: time.Minute, decay: time.Hour, globalPerMin: 2}
	l := newLimiter(cfg)
	now := time.Unix(1000, 0)
	for i, k := range []string{"a", "b"} {
		if ok, _ := l.allow(k, now); !ok {
			t.Fatalf("req %d must pass", i)
		}
	}
	if ok, _ := l.allow("c", now); ok {
		t.Fatal("global cap must block")
	}
	if ok, _ := l.allow("c", now.Add(61*time.Second)); !ok {
		t.Fatal("global window must reset")
	}
}

func TestClientKey(t *testing.T) {
	direct := &server{cfg: &config{}}
	mk := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("POST", "/api/check", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	// IPv6: весь /64 — один ключ
	if a, b := direct.clientKey(mk("[2001:db8:1:2::1]:1000", "")), direct.clientKey(mk("[2001:db8:1:2:ffff::9]:2000", "")); a != b {
		t.Errorf("same /64 must share a key: %s vs %s", a, b)
	}
	if a, b := direct.clientKey(mk("[2001:db8:1:2::1]:1", "")), direct.clientKey(mk("[2001:db8:1:3::1]:1", "")); a == b {
		t.Errorf("different /64 must differ")
	}
	// без доверия к прокси XFF игнорируется
	if a, b := direct.clientKey(mk("10.0.0.1:1", "1.1.1.1")), direct.clientKey(mk("10.0.0.1:1", "2.2.2.2")); a != b {
		t.Errorf("XFF must be ignored when proxy is not trusted")
	}
	// с доверием — берётся последний элемент
	proxy := &server{cfg: &config{trustProxy: true}}
	if got := proxy.clientKey(mk("10.0.0.1:1", "1.1.1.1, 7.7.7.7")); got != "7.7.7.7" {
		t.Errorf("got %s, want 7.7.7.7", got)
	}
	// мусор в XFF -> откат на RemoteAddr
	if got := proxy.clientKey(mk("10.0.0.1:1", "garbage")); got != "10.0.0.1" {
		t.Errorf("got %s, want 10.0.0.1", got)
	}
}
