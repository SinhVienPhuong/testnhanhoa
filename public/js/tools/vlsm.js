/** VLSM planner — allocates subnets largest-first inside a parent network. */
import { parseInput, vlsm } from '../lib/subnet.js';
import { $, $$, esc, formatNumber, debounce, downloadText, copy, activity } from '../util.js';

const EXAMPLE = [
  ['Kế toán', 60],
  ['Kinh doanh', 28],
  ['Server', 10],
  ['IT', 12],
  ['Ban giám đốc', 6],
  ['Link WAN', 2],
];

export function initVlsm() {
  const form = $('[data-vlsm-form]');
  const rowsEl = $('[data-vlsm-rows]');
  const netInput = $('#vlsm-net');
  const err = $('#vlsm-err');
  const out = $('[data-vlsm-out]');
  let seq = 0;
  let last = null;

  function addRow(name = '', hosts = '') {
    const id = ++seq;
    const row = document.createElement('div');
    row.className = 'vlsm-row';
    row.innerHTML = `
      <input aria-label="Tên subnet ${id}" name="name" placeholder="VLAN, phòng ban…" maxlength="40" value="${esc(name)}">
      <input aria-label="Số host subnet ${id}" name="hosts" type="number" min="1" max="16777214" inputmode="numeric" placeholder="Số host" value="${esc(hosts)}">
      <button type="button" class="del" aria-label="Xoá subnet ${id}">×</button>`;
    row.querySelector('.del').addEventListener('click', () => {
      row.remove();
      render();
    });
    rowsEl.appendChild(row);
    return row;
  }

  function render() {
    const parsed = parseInput(netInput.value);
    const reqs = $$('.vlsm-row', rowsEl)
      .map((r) => ({ name: r.querySelector('[name=name]').value.trim(), hosts: Number(r.querySelector('[name=hosts]').value) }))
      .filter((r) => r.hosts);

    let message = parsed.error;
    let result;
    if (!message) {
      if (!reqs.length) message = 'Thêm ít nhất một subnet kèm số host.';
      else {
        result = vlsm(parsed.ip, parsed.prefix, reqs);
        message = result.error;
      }
    }
    if (message) {
      err.textContent = message;
      err.hidden = false;
      out.innerHTML = '';
      last = null;
      return;
    }
    err.hidden = true;
    activity('vlsm');
    last = result;

    const pct = (n) => ((n / result.total) * 100).toFixed(2);
    out.innerHTML = `
      <div class="out-head">
        <h3>Đã dùng ${formatNumber(result.used)} / ${formatNumber(result.total)} địa chỉ (${pct(result.used)}%)</h3>
        <div class="pw-buttons">
          <button type="button" class="btn btn-quiet btn-sm" data-vlsm-copy>Sao chép</button>
          <button type="button" class="btn btn-quiet btn-sm" data-vlsm-csv>Tải CSV</button>
        </div>
      </div>
      <div class="alloc" role="img" aria-label="Tỷ lệ không gian địa chỉ đã cấp phát">
        ${result.rows.map((r) => `<span title="${esc(r.name)} ${r.cidr}" data-w="${pct(2 ** (32 - Number(r.cidr.split('/')[1])))}"></span>`).join('')}
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Tên</th><th>Cần</th><th>Subnet</th><th>Subnet mask</th><th>Dải host</th><th>Broadcast</th><th>Dùng được</th><th>Dư</th></tr></thead>
        <tbody>${result.rows
          .map(
            (r) => `<tr>
              <td>${esc(r.name)}</td><td>${formatNumber(r.requested)}</td>
              <td class="mono">${r.cidr}</td><td class="mono">${r.netmask}</td>
              <td class="mono">${r.firstHost} – ${r.lastHost}</td><td class="mono">${r.broadcast ?? '—'}</td>
              <td>${formatNumber(r.usableHosts)}</td><td>${formatNumber(r.wasted)}</td></tr>`,
          )
          .join('')}</tbody>
      </table></div>
      <p class="table-note">Còn trống ${formatNumber(result.free)} địa chỉ để mở rộng sau.</p>`;

    // widths set through CSSOM (allowed by CSP, unlike inline style attributes)
    out.querySelectorAll('.alloc span').forEach((s) => (s.style.width = s.dataset.w + '%'));
    out.querySelector('[data-vlsm-csv]').addEventListener('click', () => downloadText('vlsm.csv', toCsv(last)));
    out.querySelector('[data-vlsm-copy]').addEventListener('click', () =>
      copy(last.rows.map((r) => `${r.name}\t${r.cidr}\t${r.netmask}\t${r.firstHost}-${r.lastHost}`).join('\n')),
    );
  }

  function toCsv(r) {
    const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const head = ['Tên', 'Số host cần', 'Subnet', 'Subnet mask', 'Host đầu', 'Host cuối', 'Broadcast', 'Host dùng được', 'Dư'];
    const lines = r.rows.map((x) => [x.name, x.requested, x.cidr, x.netmask, x.firstHost, x.lastHost, x.broadcast, x.usableHosts, x.wasted].map(q).join(','));
    return [head.map(q).join(','), ...lines].join('\r\n');
  }

  EXAMPLE.forEach(([n, h]) => addRow(n, h));
  $('[data-vlsm-add]').addEventListener('click', () => addRow().querySelector('input').focus());
  form.addEventListener('input', debounce(render, 150));
  form.addEventListener('submit', (e) => e.preventDefault());
  render();
}
