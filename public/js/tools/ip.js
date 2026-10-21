/** "IP của bạn" — what the server sees about this visitor. */
import { $, esc, api, showError, copy, activity } from '../util.js';
import { lookupPtr } from './dns.js';

function describeUa(ua) {
  const os =
    /Windows NT 10/.test(ua) ? 'Windows 10/11' :
    /Windows NT/.test(ua) ? 'Windows' :
    /Android ([\d.]+)/.test(ua) ? 'Android ' + ua.match(/Android ([\d.]+)/)[1] :
    /iPhone|iPad/.test(ua) ? 'iOS / iPadOS' :
    /Mac OS X/.test(ua) ? 'macOS' :
    /Linux/.test(ua) ? 'Linux' : 'Không rõ';
  const browser =
    /Edg\/([\d]+)/.test(ua) ? 'Edge ' + ua.match(/Edg\/(\d+)/)[1] :
    /OPR\/([\d]+)/.test(ua) ? 'Opera ' + ua.match(/OPR\/(\d+)/)[1] :
    /CocCoc/.test(ua) ? 'Cốc Cốc' :
    /Chrome\/([\d]+)/.test(ua) ? 'Chrome ' + ua.match(/Chrome\/(\d+)/)[1] :
    /Firefox\/([\d]+)/.test(ua) ? 'Firefox ' + ua.match(/Firefox\/(\d+)/)[1] :
    /Safari\//.test(ua) ? 'Safari' : 'Không rõ';
  return { os, browser };
}

export async function loadIp() {
  const out = $('[data-ip-out]');
  activity('ip');
  try {
    const r = await api('/api/ip');
    const { os, browser } = describeUa(r.userAgent);
    const rows = [
      ['Địa chỉ IP', r.ip],
      ['Loại', r.family],
      ['Kết nối', `${r.protocol}, HTTP/${r.httpVersion}`],
      ['Hệ điều hành', os],
      ['Trình duyệt', browser],
      ['Ngôn ngữ', r.acceptLanguage.split(',')[0] || '—'],
      ['Do Not Track', r.dnt ? 'Bật' : 'Tắt'],
    ];
    out.innerHTML = `
      <div class="out-head">
        <h3 class="mono">${esc(r.ip)}</h3>
        <div class="pw-buttons">
          <button type="button" class="btn btn-quiet btn-sm" data-ip-copy>Sao chép IP</button>
          <button type="button" class="btn btn-quiet btn-sm" data-ip-ptr>Tra PTR cho IP này</button>
        </div>
      </div>
      <dl class="kv">${rows.map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>
      <p class="table-note mono">${esc(r.userAgent)}</p>`;
    out.querySelector('[data-ip-copy]').addEventListener('click', () => copy(r.ip, 'Đã sao chép IP'));
    out.querySelector('[data-ip-ptr]').addEventListener('click', () => {
      document.dispatchEvent(new CustomEvent('tool:open', { detail: 'dns' }));
      lookupPtr(r.ip);
    });
    return r;
  } catch (err) {
    showError(out, err.message);
    return null;
  }
}

export function initIp() {
  $('[data-ip-refresh]').addEventListener('click', loadIp);
}
