// Клиентский таймер — только для удобства. Реальная защита целиком на сервере.
const f = document.getElementById('f'), c = document.getElementById('c'),
      b = document.getElementById('b'), r = document.getElementById('r');
let timer;

function show(text, cls) { r.textContent = text; r.className = cls || ''; }

function lock(sec) {
  clearInterval(timer);
  let left = Math.max(1, sec | 0);
  b.disabled = true;
  const tick = () => {
    if (left <= 0) { clearInterval(timer); b.disabled = false; show(''); return; }
    show('Слишком много попыток. Повторите через ' + left + ' с', 'warn');
    left--;
  };
  tick();
  timer = setInterval(tick, 1000);
}

f.addEventListener('submit', async (e) => {
  e.preventDefault();
  b.disabled = true;
  show('…');
  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ coords: c.value }),
    });
    const j = await res.json();
    if (res.status === 429 || j.retry_after) { lock(j.retry_after || 5); return; }
    if (j.ok) { show(j.flag, 'ok'); b.disabled = false; return; }
    show(j.msg || 'ошибка', 'bad');
  } catch (_) {
    show('Ошибка сети', 'bad');
  }
  setTimeout(() => { b.disabled = false; }, 2000);
});
