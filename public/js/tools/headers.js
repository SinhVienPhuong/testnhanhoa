/** Security header scanner — calls /api/headers. */
import { $, esc, api, loading, showError, busy, activity } from '../util.js';

const STATUS_LABEL = { pass: 'Đạt', warn: 'Nên sửa', fail: 'Thiếu' };
const LEVEL_LABEL = { good: 'Tốt', info: 'Ghi chú', warn: 'Cảnh báo', bad: 'Rủi ro' };

function tlsBlock(t) {
  if (!t) return '<p class="empty">Trang dùng HTTP, không có chứng chỉ SSL.</p>';
  const rows = [
    ['Cấp cho', t.subject],
    ['Đơn vị cấp', t.issuer],
    ['Hết hạn', new Date(t.validTo).toLocaleDateString('vi-VN')],
    ['Còn lại', `${t.daysLeft} ngày`],
    ['Giao thức', t.protocol],
    ['Cipher', t.cipher],
    ['Tin cậy', t.trusted ? 'Có' : 'Không'],
  ];
  return `<dl class="kv">${rows.map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v ?? '—')}</dd></div>`).join('')}</dl>`;
}

export function initHeaders() {
  const form = $('[data-headers-form]');
  const out = $('[data-headers-out]');
  const btn = form.querySelector('[type=submit]');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = form.elements.namedItem('url').value.trim();
    if (!url) return form.elements.namedItem('url').focus();
    busy(btn, true);
    loading(out, `Đang quét ${url}…`);
    activity('headers');
    try {
      const r = await api(`/api/headers?${new URLSearchParams({ url })}`, { timeout: 30000 });
      const redirects =
        r.redirects.length > 1
          ? `<p class="table-note">Chuỗi chuyển hướng: ${r.redirects.map((x) => `<span class="mono">${esc(x.status)} ${esc(x.url)}</span>`).join(' → ')}</p>`
          : '';
      out.innerHTML = `
        <div class="grade-row">
          <div class="grade ${esc(r.grade)}" aria-label="Xếp hạng ${esc(r.grade)}">${esc(r.grade)}</div>
          <div class="grade-meta">
            <p class="score">${r.score}/100 điểm</p>
            <p class="mono">${esc(r.finalUrl)}</p>
            <p class="muted">HTTP ${esc(r.status)}, ${r.timeMs} ms${r.ip ? `, IP ${esc(r.ip)}` : ''}</p>
          </div>
        </div>
        ${redirects}
        ${r.notes.length ? `<div class="notes">${r.notes.map((n) => `<div class="note ${esc(n.level)}"><b>${LEVEL_LABEL[n.level]}</b><span>${esc(n.text)}</span></div>`).join('')}</div>` : ''}
        <div class="two-col">
          <div>
            <h3 class="sub-title">Kiểm tra từng header</h3>
            <ul class="checks-list">${r.checks
              .map(
                (c) => `<li>
                  <span class="badge ${esc(c.status)}">${STATUS_LABEL[c.status]}</span>
                  <div><span class="name">${esc(c.name)}</span><p class="detail">${esc(c.detail)}</p>${c.value ? `<code>${esc(c.value.length > 180 ? c.value.slice(0, 180) + '… (xem đầy đủ bên dưới)' : c.value)}</code>` : ''}</div>
                </li>`,
              )
              .join('')}</ul>
          </div>
          <div>
            <h3 class="sub-title">Chứng chỉ SSL</h3>
            ${tlsBlock(r.tls)}
          </div>
        </div>
        <details>
          <summary>Toàn bộ response header (${Object.keys(r.headers).length})</summary>
          <pre>${Object.entries(r.headers).map(([k, v]) => `${esc(k)}: ${esc(v)}`).join('\n')}</pre>
        </details>`;
    } catch (err) {
      showError(out, err.message);
    } finally {
      busy(btn, false);
    }
  });
}
