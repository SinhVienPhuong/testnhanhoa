/**
 * Page controller: theme toggle, tool tabs + patch-panel ports, live server
 * status, lab filters and the contact form. Each tool lives in /js/tools/.
 */
import { $, $$, api, formatDuration, toast } from './util.js';
import { initSubnet } from './tools/subnet.js';
import { initVlsm } from './tools/vlsm.js';
import { initDns } from './tools/dns.js';
import { initHeaders } from './tools/headers.js';
import { initIp, loadIp } from './tools/ip.js';
import { initPassword } from './tools/password.js';

/* ------------------------------------------------------------------ theme */
function initTheme() {
  const root = document.documentElement;
  const media = matchMedia('(prefers-color-scheme: dark)');
  const current = () => root.getAttribute('data-theme') || (media.matches ? 'dark' : 'light');
  const update = () => {
    const meta = $$('meta[name="theme-color"]');
    const color = current() === 'dark' ? '#121820' : '#E9EDF1';
    meta.forEach((m) => m.setAttribute('content', color));
  };
  $('[data-theme-toggle]').addEventListener('click', () => {
    const next = current() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try {
      localStorage.setItem('theme', next);
    } catch {
      /* private mode: theme just won't persist */
    }
    update();
  });
}

/* ------------------------------------------------------- tabs and ports */
const ipLoaded = { done: false };

function initTabs() {
  const tabs = $$('[role=tab]');
  const ports = $$('.port');

  function select(name, { focus = false, scroll = false } = {}) {
    const tab = tabs.find((t) => t.dataset.tab === name);
    if (!tab) return;
    tabs.forEach((t) => {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      $('#' + t.getAttribute('aria-controls')).hidden = !on;
    });
    ports.forEach((p) => p.setAttribute('aria-current', String(p.dataset.port === name)));
    if (focus) tab.focus();
    if (scroll) $('#cong-cu').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    if (name === 'ip' && !ipLoaded.done) {
      ipLoaded.done = true;
      loadIp();
    }
    history.replaceState(null, '', '#cong-cu-' + name);
  }

  tabs.forEach((t, i) => {
    t.addEventListener('click', () => select(t.dataset.tab));
    // WAI-ARIA tabs keyboard pattern
    t.addEventListener('keydown', (e) => {
      const keys = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 };
      if (!(e.key in keys)) return;
      e.preventDefault();
      const next = tabs[(keys[e.key] + tabs.length) % tabs.length];
      select(next.dataset.tab, { focus: true });
    });
  });

  ports.forEach((p) => p.addEventListener('click', () => select(p.dataset.port, { scroll: true })));
  document.addEventListener('tool:open', (e) => select(e.detail));

  // Deep links: /#cong-cu-dns (on load and when the hash changes in place)
  addEventListener('hashchange', () => {
    const h = location.hash.match(/^#cong-cu-(\w+)$/);
    if (h) select(h[1], { scroll: true });
  });
  const m = location.hash.match(/^#cong-cu-(\w+)$/);
  if (m) {
    select(m[1]);
    // wait for fonts/layout so the scroll lands on the right spot
    const go = () => $('#cong-cu').scrollIntoView();
    document.readyState === 'complete' ? requestAnimationFrame(go) : addEventListener('load', go, { once: true });
  }
  else ports[0].setAttribute('aria-current', 'true');
}

/* ------------------------------------------------- live server status */
function setLeds(state) {
  // Client-side tools work even if the API is down
  $$('.port').forEach((p) => {
    const led = p.querySelector('.led');
    led.className = 'led ' + (p.dataset.local ? 'on' : state);
  });
  $('[data-sys-led]').className = 'led led-sys ' + state;
}

async function pollStatus() {
  const sysText = $('[data-sys-text]');
  const ro = (k, v) => ($(`[data-ro="${k}"]`).textContent = v);
  const t0 = performance.now();
  try {
    const h = await api('/api/health', { timeout: 6000 });
    const rtt = Math.round(performance.now() - t0);
    setLeds('on');
    sysText.textContent = `Máy chủ hoạt động, Node ${h.node}`;
    ro('rtt', `${rtt} ms`);
    ro('uptime', formatDuration(h.uptimeSec));
  } catch {
    setLeds('down');
    sysText.textContent = 'Không kết nối được máy chủ';
    ro('rtt', '—');
    ro('uptime', '—');
  }
}

async function loadReadout() {
  try {
    const r = await api('/api/ip', { timeout: 6000 });
    $('[data-ro="ip"]').textContent = r.ip;
    $('[data-ro="proto"]').textContent = r.protocol;
  } catch {
    $('[data-ro="ip"]').textContent = '—';
    $('[data-ro="proto"]').textContent = location.protocol === 'https:' ? 'HTTPS' : 'HTTP';
  }
}

function initStatus() {
  setLeds('wait');
  pollStatus();
  loadReadout();
  // Refresh every 30 s while the tab is visible
  setInterval(() => document.visibilityState === 'visible' && pollStatus(), 30_000);
}

/* --------------------------------------------------------- lab filter */
function initLabFilter() {
  const chips = $$('.chip');
  const labs = $$('[data-labs] > li');
  chips.forEach((c) =>
    c.addEventListener('click', () => {
      const f = c.dataset.filter;
      chips.forEach((x) => x.setAttribute('aria-pressed', String(x === c)));
      labs.forEach((l) => (l.hidden = f !== '*' && l.dataset.category !== f));
    }),
  );
}

/* -------------------------------------------------------- contact form */
function initContact() {
  const form = $('[data-contact-form]');
  const status = $('[data-contact-status]');
  const btn = form.querySelector('[type=submit]');
  const msg = form.elements.namedItem('message');
  const counter = $('[data-count]');
  const startedAt = Date.now();
  const fields = ['name', 'email', 'message'];

  msg.addEventListener('input', () => (counter.textContent = msg.value.length));

  function setFieldError(name, text) {
    const input = form.elements.namedItem(name);
    const err = $(`#c-${name}-err`);
    if (text) {
      input.setAttribute('aria-invalid', 'true');
      err.textContent = text;
      err.hidden = false;
    } else {
      input.removeAttribute('aria-invalid');
      err.hidden = true;
    }
  }

  function validateLocal(data) {
    const errs = {};
    if (data.name.trim().length < 2) errs.name = 'Hãy nhập tên (ít nhất 2 ký tự).';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(data.email.trim())) errs.email = 'Email chưa đúng định dạng, ví dụ ten@congty.vn.';
    if (data.message.trim().length < 10) errs.message = 'Nội dung cần ít nhất 10 ký tự.';
    return errs;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    const errs = validateLocal(data);
    fields.forEach((f) => setFieldError(f, errs[f]));
    status.className = 'form-status';
    if (Object.keys(errs).length) {
      form.elements.namedItem(Object.keys(errs)[0]).focus();
      return;
    }
    btn.disabled = true;
    status.textContent = 'Đang gửi…';
    try {
      await api('/api/contact', { method: 'POST', body: { ...data, startedAt } });
      form.reset();
      counter.textContent = '0';
      status.textContent = 'Đã gửi tin nhắn. Mình sẽ trả lời qua email sớm nhất có thể.';
      status.classList.add('ok');
      toast('Đã gửi tin nhắn');
    } catch (err) {
      if (err.fields) fields.forEach((f) => setFieldError(f, err.fields[f]));
      status.textContent = err.message;
      status.classList.add('err');
    } finally {
      btn.disabled = false;
    }
  });
}

/* ------------------------------------------------------------- boot */
function safe(fn) {
  try {
    fn();
  } catch (e) {
    console.error(e); // one broken tool must not take down the page
  }
}

safe(initTheme);
safe(initTabs);
safe(initStatus);
safe(initLabFilter);
safe(initContact);
safe(initSubnet);
safe(initVlsm);
safe(initDns);
safe(initHeaders);
safe(initIp);
safe(initPassword);
