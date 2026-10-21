/** Password generator — crypto.getRandomValues, unbiased, never leaves the browser. */
import { $, copy, activity } from '../util.js';

const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
};
const AMBIGUOUS = /[Il1O0o|`'"]/g;

/** Uniform random integer in [0, max) using rejection sampling (no modulo bias). */
function randomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf);
  while (buf[0] >= limit);
  return buf[0] % max;
}

export function generate({ length, lower, upper, digits, symbols, noAmbiguous }) {
  const chosen = Object.entries({ lower, upper, digits, symbols })
    .filter(([, on]) => on)
    .map(([k]) => (noAmbiguous ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]));
  if (!chosen.length) return { password: '', entropy: 0 };
  const pool = chosen.join('');
  // Guarantee at least one character from every selected set, then fill the rest
  const chars = chosen.map((set) => set[randomInt(set.length)]);
  while (chars.length < length) chars.push(pool[randomInt(pool.length)]);
  // Fisher–Yates shuffle so the guaranteed characters aren't always first
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return { password: chars.join(''), entropy: length * Math.log2(pool.length) };
}

function crackTime(entropy) {
  // Offline attack against a fast hash on a GPU rig: ~1e10 guesses/second, average = half the space
  const seconds = 2 ** (entropy - 1) / 1e10;
  if (seconds < 1) return 'dưới 1 giây';
  const units = [
    [31_536_000 * 1e9, 'tỷ năm'],
    [31_536_000 * 1e6, 'triệu năm'],
    [31_536_000, 'năm'],
    [86_400, 'ngày'],
    [3_600, 'giờ'],
    [60, 'phút'],
    [1, 'giây'],
  ];
  for (const [s, label] of units) {
    if (seconds >= s) {
      const v = seconds / s;
      return v > 1e6 ? 'hơn 1 triệu ' + label : `khoảng ${Math.round(v).toLocaleString('vi-VN')} ${label}`;
    }
  }
}

export function initPassword() {
  const form = $('[data-pw-form]');
  const value = $('[data-pw-value]');
  const lenLabel = $('[data-pw-len]');
  const meter = $('[data-pw-meter] span');
  const strength = $('[data-pw-strength]');

  function opts() {
    return {
      length: Number(form.elements.namedItem('length').value),
      lower: form.elements.namedItem('lower').checked,
      upper: form.elements.namedItem('upper').checked,
      digits: form.elements.namedItem('digits').checked,
      symbols: form.elements.namedItem('symbols').checked,
      noAmbiguous: form.elements.namedItem('noAmbiguous').checked,
    };
  }

  function run() {
    const o = opts();
    lenLabel.textContent = o.length;
    const { password, entropy } = generate(o);
    activity('password');
    if (!password) {
      value.textContent = 'Chọn ít nhất một nhóm ký tự.';
      meter.style.width = '0';
      strength.textContent = '';
      return;
    }
    value.textContent = password;
    const bits = Math.round(entropy);
    const level =
      bits < 50 ? ['Yếu', 'var(--red)'] :
      bits < 70 ? ['Trung bình', 'var(--amber)'] :
      bits < 100 ? ['Mạnh', 'var(--green)'] : ['Rất mạnh', 'var(--green)'];
    meter.style.width = Math.min(100, (bits / 128) * 100) + '%';
    meter.style.backgroundColor = level[1];
    strength.innerHTML = '';
    const b = document.createElement('strong');
    b.textContent = level[0];
    strength.append(b, `: ${bits} bit entropy. Dò vét cạn ngoại tuyến (10 tỷ lần thử/giây) mất ${crackTime(entropy)}.`);
  }

  form.addEventListener('input', run);
  form.addEventListener('submit', (e) => e.preventDefault());
  $('[data-pw-new]').addEventListener('click', run);
  $('[data-pw-copy]').addEventListener('click', () => value.textContent && copy(value.textContent, 'Đã sao chép mật khẩu'));
  run();
}
