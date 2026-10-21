/**
 * Integration tests: boot the real app on a random port and talk HTTP to it.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';

let server;
let base;
let dataDir;

before(async () => {
  dataDir = mkdtempSync(path.join(tmpdir(), 'portfolio-test-'));
  const config = loadConfig({
    skipDotEnv: true,
    port: 0,
    host: '127.0.0.1',
    env: 'test',
    noWatch: true,
    dataDir,
    adminToken: 'test-admin-token',
    logRequests: false,
    trustProxy: true,
    telegram: { botToken: '', chatId: '' },
  });
  server = createApp(config);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  server.closeAllConnections?.();
  rmSync(dataDir, { recursive: true, force: true });
});

const get = (p, headers = {}) => fetch(base + p, { headers });
const post = (p, body, headers = {}) =>
  fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });

test('health endpoint', async () => {
  const r = await get('/api/health');
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.status, 'ok');
  assert.ok(j.version);
});

test('home page is server-rendered with content and security headers', async () => {
  const r = await get('/');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /text\/html/);
  assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('strict-transport-security'), null, 'no HSTS over plain http');
  const html = await r.text();
  assert.match(html, /<h1[^>]*>Bùi Hữu Phương<\/h1>/);
  assert.match(html, /class="lab"/);
  assert.doesNotMatch(html, /\{\{/, 'no unreplaced template tags');
});

test('HSTS is sent when the proxy says the request was HTTPS', async () => {
  const r = await get('/', { 'X-Forwarded-Proto': 'https' });
  assert.match(r.headers.get('strict-transport-security'), /max-age=31536000/);
  assert.match(r.headers.get('content-security-policy'), /upgrade-insecure-requests/);
});

test('ETag revalidation returns 304', async () => {
  const first = await get('/css/style.css');
  const etag = first.headers.get('etag');
  assert.ok(etag);
  const second = await get('/css/style.css', { 'If-None-Match': etag });
  assert.equal(second.status, 304);
});

test('compression is applied to text assets', async () => {
  const r = await get('/css/style.css', { 'Accept-Encoding': 'gzip' });
  assert.equal(r.headers.get('content-encoding'), 'gzip');
});

test('shared subnet module is served to the browser', async () => {
  const r = await get('/js/lib/subnet.js');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /javascript/);
  assert.match(await r.text(), /export function calculate/);
});

test('path traversal and dotfiles are not served', async () => {
  for (const p of ['/..%2f..%2fpackage.json', '/%2e%2e/%2e%2e/server.js', '/.env', '/fonts/../../src/app.js', '/%00']) {
    const r = await get(p);
    assert.notEqual(r.status, 200, p);
  }
});

test('404 page for unknown routes, JSON 404 for unknown API', async () => {
  const page = await get('/khong-ton-tai');
  assert.equal(page.status, 404);
  assert.match(await page.text(), /không tồn tại/);
  const apiR = await get('/api/khong-ton-tai');
  assert.equal(apiR.status, 404);
  assert.ok((await apiR.json()).error);
});

test('405 with Allow header for wrong method', async () => {
  const r = await fetch(base + '/api/health', { method: 'DELETE' });
  assert.equal(r.status, 405);
  assert.equal(r.headers.get('allow'), 'GET');
});

test('subnet API', async () => {
  const r = await get('/api/subnet?q=' + encodeURIComponent('10.10.10.10/22') + '&split=24');
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.network, '10.10.8.0');
  assert.equal(j.split.count, 4);
  const bad = await get('/api/subnet?q=999.1.1.1');
  assert.equal(bad.status, 400);
});

test('VLSM API', async () => {
  const r = await post('/api/vlsm', { network: '192.168.0.0/24', requirements: [{ name: 'A', hosts: 50 }, { name: 'B', hosts: 20 }] });
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.rows[0].cidr, '192.168.0.0/26');
});

test('X-Forwarded-For is honoured for the visitor IP', async () => {
  const r = await get('/api/ip', { 'X-Forwarded-For': '203.0.113.7' });
  const j = await r.json();
  assert.equal(j.ip, '203.0.113.7');
});

test('DNS API validates input before querying', async () => {
  const r = await get('/api/dns?name=' + encodeURIComponent('bad name!') + '&type=A');
  assert.equal(r.status, 400);
  const t = await get('/api/dns?name=example.com&type=ANY');
  assert.equal(t.status, 400);
  const ptr = await get('/api/dns?name=example.com&type=PTR');
  assert.equal(ptr.status, 400);
});

test('header scanner refuses internal targets (SSRF)', async () => {
  for (const u of ['http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]', 'http://10.0.0.1']) {
    const r = await get('/api/headers?url=' + encodeURIComponent(u));
    assert.equal(r.status, 400, u);
  }
});

test('contact: rejects non-JSON (CSRF) and cross-origin posts', async () => {
  const form = await fetch(base + '/api/contact', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'name=a',
  });
  assert.equal(form.status, 415);
  const cross = await post('/api/contact', { name: 'X' }, { Origin: 'https://evil.example' });
  assert.equal(cross.status, 403);
});

test('contact: validation errors come back per field', async () => {
  const r = await post('/api/contact', { name: '', email: 'x', message: '' }, { 'X-Forwarded-For': '198.51.100.1' });
  assert.equal(r.status, 422);
  const j = await r.json();
  assert.ok(j.fields.name && j.fields.email && j.fields.message);
});

test('contact: stores the message and admin can read it with the token', async () => {
  const ip = { 'X-Forwarded-For': '198.51.100.2' };
  const r = await post('/api/contact', { name: 'Lan', email: 'lan@congty.vn', message: 'Cần tư vấn mạng văn phòng 20 người.', topic: 'support' }, ip);
  assert.equal(r.status, 201);

  const noAuth = await get('/api/admin/messages');
  assert.equal(noAuth.status, 401);
  const wrong = await get('/api/admin/messages', { Authorization: 'Bearer nope' });
  assert.equal(wrong.status, 401);

  const ok = await get('/api/admin/messages', { Authorization: 'Bearer test-admin-token' });
  assert.equal(ok.status, 200);
  const j = await ok.json();
  assert.equal(j.messages[0].email, 'lan@congty.vn');
});

test('contact: rate limit kicks in', async () => {
  const ip = { 'X-Forwarded-For': '198.51.100.99' };
  let last;
  for (let i = 0; i < 6; i++) last = await post('/api/contact', { name: 'Spam', email: 's@x.io', message: 'Tin nhắn số ' + i + ' để thử rate limit' }, ip);
  assert.equal(last.status, 429);
  assert.ok(last.headers.get('retry-after'));
});

test('oversized body is rejected', async () => {
  const r = await post('/api/contact', { message: 'x'.repeat(20_000) }, { 'X-Forwarded-For': '198.51.100.3' });
  assert.equal(r.status, 413);
});

test('robots.txt and sitemap.xml', async () => {
  assert.match(await (await get('/robots.txt')).text(), /Disallow: \/api\//);
  assert.match(await (await get('/sitemap.xml')).text(), /<urlset/);
});
