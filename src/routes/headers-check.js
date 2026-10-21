/**
 * Website security header scanner.
 *
 * Fetches a public URL from the server and grades its HTTP security headers,
 * cookies and TLS certificate. Because the server makes the request on the
 * visitor's behalf this is a classic SSRF surface, so every hop is locked down:
 *   - only http/https on ports 80/443
 *   - the hostname is resolved by us and EVERY resolved address must be public
 *   - the socket connects to the address we validated (no DNS-rebinding window)
 *   - redirects are followed manually (max 5), re-validating each hop
 *   - the body is never read; we abort right after the headers arrive
 */
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';
import { isBlockedAddress, normalizeHostname } from '../lib/net.js';
import { HttpError } from '../http.js';

const TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 5;
const USER_AGENT = 'Mozilla/5.0 (compatible; HeaderCheck/1.0; +portfolio security tool)';

export function parseTarget(input) {
  let s = String(input || '').trim();
  if (!s) throw new HttpError(400, 'Hãy nhập URL hoặc tên miền.');
  if (s.length > 2048) throw new HttpError(400, 'URL quá dài.');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  let url;
  try {
    url = new URL(s);
  } catch {
    throw new HttpError(400, 'URL không hợp lệ.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new HttpError(400, 'Chỉ hỗ trợ http:// và https://.');
  if (url.username || url.password) throw new HttpError(400, 'URL không được chứa thông tin đăng nhập.');
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  if (port !== 80 && port !== 443) throw new HttpError(400, 'Chỉ cho phép cổng 80 và 443.');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isBlockedAddress(host)) throw new HttpError(400, 'Không cho phép quét địa chỉ nội bộ / private.');
  } else if (!normalizeHostname(host) || !host.includes('.')) {
    throw new HttpError(400, 'Tên miền không hợp lệ.');
  }
  return url;
}

/**
 * DNS lookup hook passed to http(s).request. Rejects the connection if ANY
 * resolved address is private, so an attacker can't mix a public and a private A record.
 */
export function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
    if (err) return callback(err);
    if (!addresses.length) return callback(Object.assign(new Error('No address'), { code: 'ENOTFOUND' }));
    const bad = addresses.find((a) => isBlockedAddress(a.address));
    if (bad) {
      return callback(Object.assign(new Error('Blocked private address'), { code: 'EBLOCKED', address: bad.address }));
    }
    if (options && options.all) return callback(null, addresses);
    callback(null, addresses[0].address, addresses[0].family);
  });
}

function fetchHead(url) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'https:' ? https : http;
    const started = Date.now();
    const req = lib.request(
      url,
      {
        method: 'GET',
        lookup: safeLookup,
        headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,*/*;q=0.8' },
        timeout: TIMEOUT_MS,
        // We inspect the certificate ourselves and report problems instead of failing
        rejectUnauthorized: false,
        agent: false,
      },
      (res) => {
        let tls = null;
        if (url.protocol === 'https:' && res.socket?.getPeerCertificate) {
          const cert = res.socket.getPeerCertificate();
          const authError = res.socket.authorizationError || null;
          if (cert && cert.valid_to) {
            const validTo = new Date(cert.valid_to);
            tls = {
              protocol: res.socket.getProtocol?.() || null,
              cipher: res.socket.getCipher?.()?.name || null,
              subject: cert.subject?.CN || null,
              issuer: cert.issuer?.O || cert.issuer?.CN || null,
              validFrom: new Date(cert.valid_from).toISOString(),
              validTo: validTo.toISOString(),
              daysLeft: Math.floor((validTo - Date.now()) / 86_400_000),
              altNames: (cert.subjectaltname || '').split(', ').map((s) => s.replace(/^DNS:/, '')).filter(Boolean).slice(0, 10),
              trusted: !authError,
              error: authError ? String(authError) : null,
            };
          }
        }
        const result = {
          status: res.statusCode,
          headers: res.headers,
          rawSetCookie: res.headers['set-cookie'] || [],
          remoteAddress: res.socket?.remoteAddress || null,
          timeMs: Date.now() - started,
          tls,
        };
        res.destroy(); // never download the body
        resolve(result);
      },
    );
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    req.end();
  });
}

const NET_ERRORS = {
  EBLOCKED: 'Tên miền trỏ tới địa chỉ nội bộ / private — bị chặn để chống SSRF.',
  ENOTFOUND: 'Không phân giải được tên miền.',
  ETIMEDOUT: 'Hết thời gian chờ kết nối (8 giây).',
  ECONNREFUSED: 'Máy chủ từ chối kết nối.',
  ECONNRESET: 'Kết nối bị ngắt giữa chừng.',
  EHOSTUNREACH: 'Không tới được máy chủ.',
  EPROTO: 'Lỗi bắt tay TLS.',
};

export async function fetchWithRedirects(startUrl) {
  const chain = [];
  let url = startUrl;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    let r;
    try {
      r = await fetchHead(url);
    } catch (e) {
      throw new HttpError(502, NET_ERRORS[e.code] || `Không kết nối được: ${e.code || e.message}`);
    }
    chain.push({ url: url.href, status: r.status });
    const loc = r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc) {
      if (i === MAX_REDIRECTS) throw new HttpError(502, `Quá ${MAX_REDIRECTS} lần chuyển hướng.`);
      url = parseTarget(new URL(loc, url).href); // re-validate every hop
      continue;
    }
    return { final: r, finalUrl: url, chain };
  }
  throw new HttpError(502, 'Chuyển hướng lỗi.');
}

/** Grade a set of response headers. Pure function — unit tested. */
export function gradeHeaders(headers, { https: isHttps, setCookie = [] } = {}) {
  const h = (k) => headers[k.toLowerCase()];
  const checks = [];
  const add = (id, name, ok, weight, detail, value) => checks.push({ id, name, status: ok, weight, detail, value: value ?? null });

  // Strict-Transport-Security
  const hsts = h('strict-transport-security');
  if (!isHttps) add('hsts', 'Strict-Transport-Security', 'fail', 20, 'Trang không dùng HTTPS nên không thể áp dụng HSTS.');
  else if (!hsts) add('hsts', 'Strict-Transport-Security', 'fail', 20, 'Thiếu HSTS: trình duyệt có thể bị hạ cấp xuống HTTP (SSL stripping).');
  else {
    const maxAge = Number((hsts.match(/max-age=(\d+)/i) || [])[1] || 0);
    if (maxAge < 15552000) add('hsts', 'Strict-Transport-Security', 'warn', 20, 'max-age nên ≥ 6 tháng (15552000).', hsts);
    else add('hsts', 'Strict-Transport-Security', 'pass', 20, 'HSTS bật với thời hạn đủ dài.', hsts);
  }

  // Content-Security-Policy
  const csp = h('content-security-policy');
  if (!csp) add('csp', 'Content-Security-Policy', 'fail', 25, 'Thiếu CSP: không có lớp chặn XSS ở phía trình duyệt.');
  else if (/unsafe-inline/.test(csp) && /script-src[^;]*unsafe-inline/.test(csp))
    add('csp', 'Content-Security-Policy', 'warn', 25, "script-src cho phép 'unsafe-inline' nên CSP gần như không chặn được XSS.", csp);
  else if (/unsafe-eval/.test(csp)) add('csp', 'Content-Security-Policy', 'warn', 25, "CSP có 'unsafe-eval'.", csp);
  else add('csp', 'Content-Security-Policy', 'pass', 25, 'Có CSP và không dùng unsafe-inline cho script.', csp);

  // Clickjacking
  const xfo = h('x-frame-options');
  const fa = csp && /frame-ancestors/i.test(csp);
  if (fa || /^(deny|sameorigin)$/i.test(String(xfo || '').trim()))
    add('frame', 'Chống clickjacking', 'pass', 15, fa ? 'Dùng CSP frame-ancestors.' : `X-Frame-Options: ${xfo}.`, xfo || null);
  else add('frame', 'Chống clickjacking', 'fail', 15, 'Thiếu X-Frame-Options hoặc CSP frame-ancestors: trang có thể bị nhúng iframe để lừa click.');

  // X-Content-Type-Options
  const xcto = h('x-content-type-options');
  if (String(xcto || '').toLowerCase() === 'nosniff') add('xcto', 'X-Content-Type-Options', 'pass', 10, 'Chặn MIME sniffing.', xcto);
  else add('xcto', 'X-Content-Type-Options', 'fail', 10, 'Thiếu "nosniff": trình duyệt có thể đoán sai kiểu file và chạy script.');

  // Referrer-Policy
  const rp = h('referrer-policy');
  if (!rp) add('referrer', 'Referrer-Policy', 'warn', 10, 'Thiếu Referrer-Policy: URL đầy đủ có thể lộ sang site khác.');
  else if (/unsafe-url|no-referrer-when-downgrade/i.test(rp)) add('referrer', 'Referrer-Policy', 'warn', 10, 'Chính sách quá lỏng.', rp);
  else add('referrer', 'Referrer-Policy', 'pass', 10, 'Đã giới hạn thông tin Referer.', rp);

  // Permissions-Policy
  const pp = h('permissions-policy');
  if (pp) add('permissions', 'Permissions-Policy', 'pass', 10, 'Đã giới hạn quyền camera, micro, vị trí...', pp);
  else add('permissions', 'Permissions-Policy', 'warn', 10, 'Thiếu Permissions-Policy (nên tắt các API không dùng).');

  // Information disclosure
  const leaks = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']
    .filter((k) => h(k) && /\d/.test(String(h(k))))
    .map((k) => `${k}: ${h(k)}`);
  if (leaks.length) add('disclosure', 'Lộ phiên bản phần mềm', 'warn', 10, 'Header tiết lộ phiên bản, giúp kẻ tấn công dò lỗ hổng: ' + leaks.join('; '));
  else add('disclosure', 'Lộ phiên bản phần mềm', 'pass', 10, 'Không thấy header tiết lộ số phiên bản.');

  // Cookies
  const cookies = setCookie.map((c) => {
    const name = c.split('=')[0].trim();
    const lower = c.toLowerCase();
    return {
      name,
      secure: /;\s*secure/.test(lower),
      httpOnly: /;\s*httponly/.test(lower),
      sameSite: (lower.match(/;\s*samesite=(\w+)/) || [])[1] || null,
    };
  });
  const weak = cookies.filter((c) => (isHttps && !c.secure) || !c.httpOnly || !c.sameSite);
  if (cookies.length) {
    if (weak.length)
      add('cookies', 'Cookie', 'warn', 0, `${weak.length}/${cookies.length} cookie thiếu cờ Secure, HttpOnly hoặc SameSite: ${weak.map((c) => c.name).join(', ')}.`);
    else add('cookies', 'Cookie', 'pass', 0, 'Mọi cookie đều có Secure, HttpOnly và SameSite.');
  }

  const max = checks.reduce((s, c) => s + c.weight, 0);
  const got = checks.reduce((s, c) => s + (c.status === 'pass' ? c.weight : c.status === 'warn' ? c.weight / 2 : 0), 0);
  const score = max ? Math.round((got / max) * 100) : 0;
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, checks, cookies };
}

export async function checkHeaders(rawUrl) {
  const url = parseTarget(rawUrl);
  const { final, finalUrl, chain } = await fetchWithRedirects(url);
  const isHttpsFinal = finalUrl.protocol === 'https:';
  const graded = gradeHeaders(final.headers, { https: isHttpsFinal, setCookie: final.rawSetCookie });
  const notes = [];
  if (url.protocol === 'http:' && !isHttpsFinal) notes.push({ level: 'bad', text: 'Trang không chuyển hướng HTTP sang HTTPS.' });
  if (final.tls && !final.tls.trusted) notes.push({ level: 'bad', text: `Chứng chỉ SSL không hợp lệ: ${final.tls.error}.` });
  if (final.tls && final.tls.daysLeft < 0) notes.push({ level: 'bad', text: 'Chứng chỉ SSL đã hết hạn.' });
  else if (final.tls && final.tls.daysLeft < 15) notes.push({ level: 'warn', text: `Chứng chỉ SSL còn ${final.tls.daysLeft} ngày là hết hạn.` });

  const shown = {};
  for (const [k, v] of Object.entries(final.headers)) shown[k] = Array.isArray(v) ? v.join('\n') : String(v);

  return {
    url: url.href,
    finalUrl: finalUrl.href,
    status: final.status,
    timeMs: final.timeMs,
    ip: final.remoteAddress,
    redirects: chain,
    tls: final.tls,
    ...graded,
    notes,
    headers: shown,
  };
}
