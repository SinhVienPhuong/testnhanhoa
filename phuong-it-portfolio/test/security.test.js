import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isBlockedAddress, normalizeHostname, clientIp } from '../src/lib/net.js';
import { RateLimiter } from '../src/security.js';
import { parseTarget, gradeHeaders } from '../src/routes/headers-check.js';
import { validateContact } from '../src/routes/contact.js';

test('SSRF guard blocks internal IPv4 and IPv6 addresses', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.5.5', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::a00:1']) {
    assert.equal(isBlockedAddress(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
    assert.equal(isBlockedAddress(ip), false, ip);
  }
  assert.equal(isBlockedAddress('not-an-ip'), true);
});

test('parseTarget rejects dangerous URLs', () => {
  assert.throws(() => parseTarget('http://127.0.0.1'), /nội bộ/);
  assert.throws(() => parseTarget('http://[::1]/'), /nội bộ/);
  assert.throws(() => parseTarget('file:///etc/passwd'), /http/);
  assert.throws(() => parseTarget('https://example.com:22'), /cổng/);
  assert.throws(() => parseTarget('https://user:pass@example.com'), /đăng nhập/);
  assert.throws(() => parseTarget('http://localhost'), /không hợp lệ/);
  assert.equal(parseTarget('example.com').href, 'https://example.com/');
});

test('hostname normalisation', () => {
  assert.equal(normalizeHostname('  NhanHoa.com. '), 'nhanhoa.com');
  assert.equal(normalizeHostname('https://www.example.com/path?q=1'), 'www.example.com');
  assert.equal(normalizeHostname('_dmarc.example.com'), '_dmarc.example.com');
  assert.equal(normalizeHostname('bad_host!.com'), null);
  assert.equal(normalizeHostname('-bad.com'), null);
  assert.equal(normalizeHostname('a'.repeat(64) + '.com'), null);
  assert.match(normalizeHostname('tênmiền.vn'), /^xn--/);
});

test('clientIp only trusts X-Forwarded-For when configured', () => {
  const req = { headers: { 'x-forwarded-for': '203.0.113.9, 10.0.0.1' }, socket: { remoteAddress: '::ffff:10.0.0.1' } };
  assert.equal(clientIp(req, true), '203.0.113.9');
  assert.equal(clientIp(req, false), '10.0.0.1');
  const spoof = { headers: { 'x-forwarded-for': 'garbage' }, socket: { remoteAddress: '10.0.0.1' } };
  assert.equal(clientIp(spoof, true), '10.0.0.1');
});

test('rate limiter: allows up to the limit, then blocks until the window passes', () => {
  let now = 0;
  const rl = new RateLimiter({ now: () => now });
  for (let i = 0; i < 3; i++) assert.equal(rl.check('k', 3, 1000).ok, true);
  const blocked = rl.check('k', 3, 1000);
  assert.equal(blocked.ok, false);
  assert.equal(blocked.retryAfter, 1);
  assert.equal(rl.check('other', 3, 1000).ok, true, 'keys are independent');
  now = 1001;
  assert.equal(rl.check('k', 3, 1000).ok, true);
  rl.stop();
});

test('header grading: hardened site scores A, bare site scores F', () => {
  const good = gradeHeaders(
    {
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'camera=()',
    },
    { https: true },
  );
  assert.equal(good.grade, 'A');
  assert.equal(good.score, 100);

  const bad = gradeHeaders({ server: 'Apache/2.4.29 (Ubuntu)', 'x-powered-by': 'PHP/7.2.1' }, { https: false });
  assert.equal(bad.grade, 'F');
  assert.equal(bad.checks.find((c) => c.id === 'disclosure').status, 'warn');
});

test('header grading flags unsafe-inline CSP and weak cookies', () => {
  const r = gradeHeaders(
    { 'content-security-policy': "script-src 'self' 'unsafe-inline'" },
    { https: true, setCookie: ['sid=abc; Path=/', 'ok=1; Secure; HttpOnly; SameSite=Lax'] },
  );
  assert.equal(r.checks.find((c) => c.id === 'csp').status, 'warn');
  assert.equal(r.checks.find((c) => c.id === 'cookies').status, 'warn');
  assert.equal(r.cookies.length, 2);
});

test('contact validation', () => {
  const ok = validateContact({ name: 'Lan', email: 'lan@congty.vn', message: 'Cần hỗ trợ mạng LAN.' });
  assert.ok(ok.value);
  assert.equal(ok.spam, false);

  const bad = validateContact({ name: 'A', email: 'nope', message: 'ngắn' });
  assert.deepEqual(Object.keys(bad.errors).sort(), ['email', 'message', 'name']);

  const bot = validateContact({ name: 'Bot', email: 'b@x.io', message: 'Buy cheap stuff now!!', website: 'http://spam' });
  assert.equal(bot.spam, true);

  const fast = validateContact({ name: 'Bot', email: 'b@x.io', message: 'Filled in 0.5 seconds', startedAt: 1000 }, 1500);
  assert.equal(fast.spam, true);

  const links = validateContact({ name: 'Spam', email: 's@x.io', message: 'http://a http://b http://c http://d' });
  assert.ok(links.errors.message);
});
