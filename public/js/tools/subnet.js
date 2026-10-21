/** Subnet calculator — runs fully in the browser using the shared module. */
import { parseInput, calculate, split, ipToInt } from '../lib/subnet.js';
import { $, esc, formatNumber, debounce, copy, activity } from '../util.js';

export function initSubnet() {
  const form = $('[data-subnet-form]');
  const input = $('#subnet-q');
  const splitSel = $('#subnet-split');
  const err = $('#subnet-err');
  const out = $('[data-subnet-out]');
  let lastPrefix = null;

  function fillSplitOptions(prefix) {
    if (prefix === lastPrefix) return;
    lastPrefix = prefix;
    const keep = splitSel.value;
    const opts = ['<option value="">Không chia</option>'];
    for (let p = prefix + 1; p <= Math.min(32, prefix + 12); p++) {
      opts.push(`<option value="${p}">/${p} (${formatNumber(2 ** (p - prefix))} subnet)</option>`);
    }
    splitSel.innerHTML = opts.join('');
    if ([...splitSel.options].some((o) => o.value === keep)) splitSel.value = keep;
    splitSel.disabled = prefix >= 32;
  }

  function bitsBar(r) {
    const ip = ipToInt(r.address);
    let cells = '';
    for (let o = 0; o < 4; o++) {
      cells += '<div class="octet">';
      for (let b = 0; b < 8; b++) {
        const pos = o * 8 + b; // 0 = most significant bit
        const bit = (ip >>> (31 - pos)) & 1;
        cells += `<span class="${pos < r.prefix ? 'n' : 'h'}">${bit}</span>`;
      }
      cells += '</div>';
    }
    return `
      <div class="bits" role="img" aria-label="${r.prefix} bit mạng, ${32 - r.prefix} bit host">
        <div class="bits-row">${cells}</div>
        <p class="bits-legend"><span><i class="n"></i>${r.prefix} bit mạng</span><span><i class="h"></i>${32 - r.prefix} bit host</span></p>
      </div>`;
  }

  function render() {
    const parsed = parseInput(input.value);
    if (parsed.error) {
      err.textContent = parsed.error;
      err.hidden = false;
      input.setAttribute('aria-invalid', 'true');
      return;
    }
    err.hidden = true;
    input.removeAttribute('aria-invalid');
    activity('subnet');

    const r = calculate(parsed.ip, parsed.prefix);
    fillSplitOptions(r.prefix);

    const rows = [
      ['Network', r.network],
      ['Broadcast', r.broadcast ?? (r.prefix === 32 ? 'Không có (/32)' : 'Không có (/31, RFC 3021)')],
      ['Subnet mask', r.netmask],
      ['Wildcard mask', r.wildcard],
      ['Host đầu tiên', r.firstHost],
      ['Host cuối cùng', r.lastHost],
      ['Số host dùng được', formatNumber(r.usableHosts)],
      ['Tổng số địa chỉ', formatNumber(r.totalAddresses)],
      ['CIDR', r.cidr],
      ['Lớp (classful)', r.ipClass],
      ['Phạm vi', r.scope],
      ['Reverse zone', r.reverseZone],
    ];

    let html = `
      <div class="out-head">
        <h3><span class="mono">${esc(r.address)}/${r.prefix}</span></h3>
        <button type="button" class="btn btn-quiet btn-sm" data-copy-subnet>Sao chép kết quả</button>
      </div>
      ${bitsBar(r)}
      <dl class="kv">${rows.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>`;

    const to = Number(splitSel.value);
    if (to) {
      const s = split(parsed.ip, parsed.prefix, to, 256);
      if (!s.error) {
        html += `
          <div class="out-head"><h3>Chia ${esc(r.cidr)} thành ${formatNumber(s.count)} subnet /${to}</h3></div>
          <div class="table-wrap"><table>
            <thead><tr><th>#</th><th>Subnet</th><th>Dải host</th><th>Broadcast</th><th>Số host</th></tr></thead>
            <tbody>${s.rows
              .map(
                (row, i) =>
                  `<tr><td>${i + 1}</td><td class="mono">${row.cidr}</td><td class="mono">${row.firstHost} – ${row.lastHost}</td><td class="mono">${row.broadcast ?? '—'}</td><td>${formatNumber(row.usableHosts)}</td></tr>`,
              )
              .join('')}</tbody>
          </table></div>
          ${s.count > s.shown ? `<p class="table-note">Đang hiển thị ${s.shown} trên tổng ${formatNumber(s.count)} subnet.</p>` : ''}`;
      }
    }
    out.innerHTML = html;
    out.querySelector('[data-copy-subnet]').addEventListener('click', () => {
      copy(rows.map(([k, v]) => `${k}: ${v}`).join('\n'), 'Đã sao chép kết quả');
    });
  }

  form.addEventListener('submit', (e) => e.preventDefault());
  input.addEventListener('input', debounce(render, 120));
  splitSel.addEventListener('change', render);
  render();
}
