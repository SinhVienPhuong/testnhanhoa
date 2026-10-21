/** Shared browser helpers. */

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/** Escape text for safe insertion into innerHTML templates. */
export function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/** fetch + JSON with a timeout; throws Error(message from server) on non-2xx. */
export async function api(url, { method = 'GET', body, timeout = 15000 } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  let res;
  try {
    res = await fetch(url, {
      method,
      signal: ctrl.signal,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new Error(e.name === 'AbortError' ? 'Máy chủ phản hồi quá lâu. Thử lại sau.' : 'Không kết nối được tới máy chủ. Kiểm tra mạng rồi thử lại.');
  } finally {
    clearTimeout(timer);
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON */
  }
  if (!res.ok) {
    const err = new Error(data?.error || `Lỗi ${res.status}.`);
    err.status = res.status;
    err.fields = data?.fields;
    throw err;
  }
  return data;
}

let toastTimer;
export function toast(message) {
  const el = $('[data-toast]');
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 2400);
}

export async function copy(text, label = 'Đã sao chép') {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for http:// or older browsers
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast(label);
}

export function loading(el, text = 'Đang xử lý…') {
  el.innerHTML = `<p class="loading"><span class="led" aria-hidden="true"></span>${esc(text)}</p>`;
}

export function showError(el, message) {
  el.innerHTML = `<div class="note bad" role="alert"><b>Lỗi</b><span>${esc(message)}</span></div>`;
}

export function busy(button, on) {
  if (!button) return;
  button.disabled = on;
  button.setAttribute('aria-busy', String(on));
}

export function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

export function formatNumber(n) {
  return new Intl.NumberFormat('vi-VN').format(n);
}

export function formatDuration(sec) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d} ngày ${h} giờ`;
  if (h) return `${h} giờ ${m} phút`;
  if (m) return `${m} phút`;
  return `${sec} giây`;
}

/** Flash a port LED to show traffic on that tool. */
export function activity(port) {
  const led = document.querySelector(`.port[data-port="${port}"] .led`);
  if (!led || !led.classList.contains('on')) return;
  led.classList.remove('activity');
  void led.offsetWidth; // restart animation
  led.classList.add('activity');
}

export function downloadText(filename, text, type = 'text/csv;charset=utf-8') {
  const blob = new Blob(['﻿' + text], { type }); // BOM so Excel reads UTF-8
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(a.href);
    a.remove();
  }, 0);
}
