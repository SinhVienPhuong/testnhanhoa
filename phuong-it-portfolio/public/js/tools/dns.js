/** DNS lookup — calls /api/dns. */
import { $, esc, api, loading, showError, busy, activity } from '../util.js';

const LEVEL_LABEL = { good: 'Tốt', info: 'Ghi chú', warn: 'Cảnh báo', bad: 'Rủi ro' };

function notes(list) {
  if (!list?.length) return '';
  return `<div class="notes">${list.map((n) => `<div class="note ${esc(n.level)}"><b>${LEVEL_LABEL[n.level] || ''}</b><span>${esc(n.text)}</span></div>`).join('')}</div>`;
}

function recordTable(r) {
  if (r.error) return `<div class="note bad"><b>${esc(r.error.code)}</b><span>${esc(r.error.message)}</span></div>`;
  if (!r.records.length) return `<p class="empty">${esc(r.empty || 'Không có bản ghi.')}</p>`;

  const extra = r.type === 'MX' ? ['Priority'] : r.type === 'A' || r.type === 'AAAA' ? ['TTL'] : [];
  if (r.type === 'SOA') {
    const s = r.records[0];
    const rows = [
      ['Primary NS', s.value],
      ['Hostmaster', s.hostmaster],
      ['Serial', s.serial],
      ['Refresh', `${s.refresh} s`],
      ['Retry', `${s.retry} s`],
      ['Expire', `${s.expire} s`],
      ['Minimum TTL', `${s.minttl} s`],
    ];
    return `<dl class="kv">${rows.map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>`;
  }
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Giá trị</th>${extra.map((h) => `<th>${h}</th>`).join('')}</tr></thead>
      <tbody>${r.records
        .map(
          (x) => `<tr><td class="mono wrap">${esc(x.value)}</td>${
            r.type === 'MX' ? `<td>${esc(x.priority)}</td>` : extra.length ? `<td>${esc(x.ttl)} s</td>` : ''
          }</tr>`,
        )
        .join('')}</tbody>
    </table></div>`;
}

function block(r, title) {
  return `
    <div class="dns-block">
      <div class="out-head">
        <h3>${esc(title || `${r.type} ${r.name}`)}</h3>
        <span class="muted mono">${esc(r.resolver.label)}, ${r.timeMs} ms${r.cached ? ', từ cache' : ''}</span>
      </div>
      ${recordTable(r)}
      ${notes(r.insights)}
    </div>`;
}

export function initDns() {
  const form = $('[data-dns-form]');
  const out = $('[data-dns-out]');
  const mailBtn = $('[data-dns-mail]');
  const submitBtn = form.querySelector('[type=submit]');

  const q = (name, type, resolver) =>
    api(`/api/dns?${new URLSearchParams({ name, type, resolver })}`);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const { name, type, resolver } = Object.fromEntries(new FormData(form));
    if (!name.trim()) return form.elements.namedItem('name').focus();
    busy(submitBtn, true);
    loading(out, `Đang tra ${type} cho ${name}…`);
    activity('dns');
    try {
      out.innerHTML = block(await q(name, type, resolver));
    } catch (err) {
      showError(out, err.message);
    } finally {
      busy(submitBtn, false);
    }
  });

  // Mail health check: MX + SPF + DMARC in parallel
  mailBtn.addEventListener('click', async () => {
    const name = form.elements.namedItem('name').value.trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!name) {
      form.elements.namedItem('name').focus();
      return;
    }
    const resolver = form.elements.namedItem('resolver').value;
    busy(mailBtn, true);
    loading(out, `Đang kiểm tra cấu hình email của ${name}…`);
    activity('dns');
    try {
      const [mx, txt, dmarc] = await Promise.all([q(name, 'MX', resolver), q(name, 'TXT', resolver), q('_dmarc.' + name, 'TXT', resolver)]);
      const spf = { ...txt, records: txt.records.filter((r) => r.value.toLowerCase().startsWith('v=spf1')) };
      if (!spf.records.length && !spf.error) spf.empty = 'Không có bản ghi SPF. Bất kỳ máy chủ nào cũng có thể gửi mail mạo danh domain này.';
      spf.insights = txt.insights.filter((n) => /SPF/.test(n.text));
      const dm = { ...dmarc, records: dmarc.records.filter((r) => r.value.toLowerCase().startsWith('v=dmarc1')) };
      if (!dm.records.length && !dm.error) dm.empty = 'Không có DMARC. Nên thêm ít nhất v=DMARC1; p=none để bắt đầu giám sát.';
      if (dmarc.error?.code === 'ENOTFOUND') {
        dm.error = null;
        dm.empty = 'Không có DMARC. Nên thêm ít nhất v=DMARC1; p=none để bắt đầu giám sát.';
      }
      out.innerHTML = block(mx, `MX: máy chủ nhận mail của ${name}`) + block(spf, 'SPF: ai được phép gửi mail') + block(dm, `DMARC: _dmarc.${name}`);
    } catch (err) {
      showError(out, err.message);
    } finally {
      busy(mailBtn, false);
    }
  });

  // PTR needs an IP — guide the user
  form.elements.namedItem('type').addEventListener('change', () => {
    form.elements.namedItem('name').placeholder = form.elements.namedItem('type').value === 'PTR' ? '8.8.8.8' : 'nhanhoa.com';
  });
}

/** Called from other tools ("Tra PTR cho IP này"). */
export function lookupPtr(ip) {
  const form = $('[data-dns-form]');
  form.elements.namedItem('name').value = ip;
  form.elements.namedItem('type').value = 'PTR';
  form.requestSubmit();
}
