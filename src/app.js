/**
 * HTTP application: routing, middleware-style concerns (security headers,
 * rate limits, logging, error handling) and wiring of all handlers.
 */
import http from 'node:http';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { watch, readFileSync } from 'node:fs';

import { log } from './logger.js';
import { applySecurityHeaders, RateLimiter } from './security.js';
import { StaticServer, sendBuffer } from './static.js';
import { sendJson, readJson, HttpError, isHttps, escapeHtml } from './http.js';
import { clientIp } from './lib/net.js';
import * as subnet from './lib/subnet.js';
import { dnsLookup, RECORD_TYPES, RESOLVERS } from './routes/dns.js';
import { checkHeaders } from './routes/headers-check.js';
import { ContactStore, handleContact } from './routes/contact.js';
import { renderIndex, TEMPLATE_PATH } from './render.js';

/** Per-endpoint limits: [requests, window ms] */
const LIMITS = {
  api: [120, 60_000],
  dns: [30, 60_000],
  headers: [10, 60_000],
  contact: [5, 10 * 60_000],
  admin: [20, 60_000],
};

export function createApp(config) {
  const startedAt = Date.now();
  const limiter = new RateLimiter();
  const store = new ContactStore(config.dataDir);
  const statics = new StaticServer(config.publicDir, {
    // Shared module: the browser imports exactly the code the server tests
    '/js/lib/subnet.js': path.join(config.root, 'src', 'lib', 'subnet.js'),
  });

  // ---------- home page (rendered from content/site.json) ----------
  let index;
  const renderHome = () => {
    try {
      index = renderIndex(TEMPLATE_PATH(config.root), config.contentFile, config);
      index.lastModified = new Date().toUTCString();
    } catch (err) {
      log.error('render failed', { err: err.message });
      if (!index) throw err; // fail fast on boot, keep old page on hot reload
    }
  };
  renderHome();
  if (config.env !== 'production' && !config.noWatch) {
    for (const f of [config.contentFile, TEMPLATE_PATH(config.root)]) {
      try {
        watch(f, { persistent: false }, () => {
          renderHome();
          log.info('home page re-rendered', { file: path.basename(f) });
        });
      } catch {
        /* watch not supported: ignore */
      }
    }
  }

  const notFoundPage = (() => {
    try {
      return readFileSync(path.join(config.publicDir, '404.html'));
    } catch {
      return Buffer.from('<h1>404</h1>');
    }
  })();

  // ---------- helpers ----------
  function limit(req, res, bucket) {
    const [max, windowMs] = LIMITS[bucket];
    const r = limiter.check(`${bucket}:${req.ip}`, max, windowMs);
    res.setHeader('RateLimit-Limit', max);
    res.setHeader('RateLimit-Remaining', r.remaining);
    if (!r.ok) {
      res.setHeader('Retry-After', r.retryAfter);
      throw new HttpError(429, `Bạn thao tác quá nhanh. Thử lại sau ${r.retryAfter} giây.`);
    }
  }

  function requireMethod(req, ...methods) {
    if (!methods.includes(req.method)) {
      throw new HttpError(405, `Phương thức ${req.method} không được hỗ trợ.`, { allow: methods.join(', ') });
    }
  }

  function sameOrigin(req) {
    // Defence in depth for state-changing requests on top of the JSON content-type check
    const origin = req.headers.origin;
    if (!origin) return true;
    try {
      return new URL(origin).host === req.headers.host;
    } catch {
      return false;
    }
  }

  function health() {
    const mem = process.memoryUsage();
    return {
      status: 'ok',
      version: config.version,
      uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
      node: process.version,
      platform: `${os.type()} ${os.arch()}`,
      memoryMB: Math.round(mem.rss / 1024 / 1024),
      time: new Date().toISOString(),
    };
  }

  // ---------- API routes ----------
  const routes = {
    'GET /api/health': (req, res) => sendJson(res, 200, health()),

    'GET /api/ip': (req, res) => {
      limit(req, res, 'api');
      sendJson(res, 200, {
        ip: req.ip,
        family: req.ip.includes(':') ? 'IPv6' : 'IPv4',
        protocol: req.secure ? 'HTTPS' : 'HTTP',
        httpVersion: req.httpVersion,
        userAgent: String(req.headers['user-agent'] || ''),
        acceptLanguage: String(req.headers['accept-language'] || ''),
        dnt: req.headers.dnt === '1',
        serverTime: new Date().toISOString(),
      });
    },

    'GET /api/subnet': (req, res, url) => {
      limit(req, res, 'api');
      const parsed = subnet.parseInput(url.searchParams.get('q') || '');
      if (parsed.error) throw new HttpError(400, parsed.error);
      const result = subnet.calculate(parsed.ip, parsed.prefix);
      const splitTo = url.searchParams.get('split');
      if (splitTo) {
        const s = subnet.split(parsed.ip, parsed.prefix, Number(splitTo), 256);
        if (s.error) throw new HttpError(400, s.error);
        result.split = s;
      }
      sendJson(res, 200, result);
    },

    'POST /api/vlsm': async (req, res) => {
      limit(req, res, 'api');
      const body = await readJson(req);
      const parsed = subnet.parseInput(String(body.network || ''));
      if (parsed.error) throw new HttpError(400, parsed.error);
      const r = subnet.vlsm(parsed.ip, parsed.prefix, body.requirements);
      if (r.error) throw new HttpError(400, r.error);
      sendJson(res, 200, r);
    },

    'GET /api/dns/meta': (req, res) => {
      res.setHeader('Cache-Control', 'public, max-age=3600');
      sendJson(res, 200, {
        types: RECORD_TYPES,
        resolvers: Object.entries(RESOLVERS).map(([key, v]) => ({ key, label: v.label })),
      });
    },

    'GET /api/dns': async (req, res, url) => {
      limit(req, res, 'dns');
      const result = await dnsLookup({
        name: url.searchParams.get('name'),
        type: url.searchParams.get('type'),
        resolver: url.searchParams.get('resolver'),
      });
      sendJson(res, 200, result);
    },

    'GET /api/headers': async (req, res, url) => {
      limit(req, res, 'headers');
      sendJson(res, 200, await checkHeaders(url.searchParams.get('url')));
    },

    'POST /api/contact': async (req, res) => {
      if (!sameOrigin(req)) throw new HttpError(403, 'Yêu cầu không hợp lệ.');
      limit(req, res, 'contact');
      const body = await readJson(req, 8 * 1024);
      const out = await handleContact(body, {
        store,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        telegram: config.telegram,
      });
      sendJson(res, 201, out);
    },

    'GET /api/admin/messages': async (req, res, url) => {
      // Disabled entirely unless an ADMIN_TOKEN is configured
      if (!config.adminToken) throw new HttpError(404, 'Không tìm thấy.');
      limit(req, res, 'admin');
      const given = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const a = crypto.createHash('sha256').update(given).digest();
      const b = crypto.createHash('sha256').update(config.adminToken).digest();
      if (!given || !crypto.timingSafeEqual(a, b)) {
        res.setHeader('WWW-Authenticate', 'Bearer');
        throw new HttpError(401, 'Sai hoặc thiếu token.');
      }
      const includeSpam = url.searchParams.get('spam') === '1';
      const all = await store.list(500);
      sendJson(res, 200, { count: all.length, messages: all.filter((m) => includeSpam || !m.spam).slice(0, 200) });
    },
  };

  // ---------- dynamic text files ----------
  function baseUrl(req) {
    if (config.siteUrl) return config.siteUrl;
    return `${req.secure ? 'https' : 'http'}://${escapeHtml(req.headers.host || 'localhost')}`;
  }

  const textRoutes = {
    '/robots.txt': (req) => ['User-agent: *', 'Allow: /', 'Disallow: /api/', `Sitemap: ${baseUrl(req)}/sitemap.xml`, ''].join('\n'),
    '/sitemap.xml': (req) =>
      `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${baseUrl(req)}/</loc><changefreq>weekly</changefreq></url></urlset>\n`,
  };

  // ---------- request handler ----------
  async function handle(req, res) {
    const started = process.hrtime.bigint();
    req.id = crypto.randomUUID().slice(0, 8);
    req.ip = clientIp(req, config.trustProxy);
    req.secure = isHttps(req, config.trustProxy);
    res.setHeader('X-Request-Id', req.id);
    applySecurityHeaders(res, { https: req.secure });

    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      sendJson(res, 400, { error: 'URL không hợp lệ.' });
      return;
    }
    const pathname = url.pathname;

    res.on('finish', () => {
      if (!config.logRequests) return;
      if (pathname === '/api/health' && res.statusCode === 200) return; // keep probe noise out of logs
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      log.info('req', { id: req.id, ip: req.ip, m: req.method, p: pathname, s: res.statusCode, ms: Math.round(ms * 10) / 10 });
    });

    try {
      if (pathname.startsWith('/api/')) {
        const key = `${req.method === 'HEAD' ? 'GET' : req.method} ${pathname}`;
        const handler = routes[key];
        if (!handler) {
          const allowed = Object.keys(routes)
            .filter((k) => k.endsWith(' ' + pathname))
            .map((k) => k.split(' ')[0]);
          if (allowed.length) {
            if (req.method === 'OPTIONS') {
              res.setHeader('Allow', allowed.join(', '));
              res.statusCode = 204;
              res.end();
              return;
            }
            throw new HttpError(405, 'Phương thức không được hỗ trợ.', { allow: allowed.join(', ') });
          }
          throw new HttpError(404, 'Không tìm thấy API.');
        }
        await handler(req, res, url);
        return;
      }

      if (textRoutes[pathname]) {
        requireMethod(req, 'GET', 'HEAD');
        const body = textRoutes[pathname](req);
        res.setHeader('Content-Type', pathname.endsWith('.xml') ? 'application/xml; charset=utf-8' : 'text/plain; charset=utf-8');
        res.setHeader('Cache-Control', 'public, max-age=3600');
        res.end(req.method === 'HEAD' ? undefined : body);
        return;
      }

      if (pathname === '/' || pathname === '/index.html') {
        requireMethod(req, 'GET', 'HEAD');
        await sendBuffer(req, res, index, 'text/html; charset=utf-8', 'public, max-age=0, must-revalidate', true);
        return;
      }

      if (await statics.serve(req, res, pathname)) return;

      // Not found
      if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Phương thức không được hỗ trợ.', { allow: 'GET, HEAD' });
      res.setHeader('Cache-Control', 'no-store');
      await sendBuffer(req, res, { raw: notFoundPage, etag: '"404"' }, 'text/html; charset=utf-8', 'no-store', true, 404);
    } catch (err) {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (err instanceof HttpError) {
        if (err.extra.allow) res.setHeader('Allow', err.extra.allow);
        const { allow, ...rest } = err.extra;
        sendJson(res, err.status, { error: err.message, ...rest });
      } else {
        log.error('unhandled', { id: req.id, err: err.stack || String(err) });
        sendJson(res, 500, { error: 'Lỗi máy chủ. Mã tra cứu: ' + req.id });
      }
    }
  }

  const server = http.createServer({ requestTimeout: 30_000, headersTimeout: 15_000 }, (req, res) => {
    handle(req, res);
  });
  server.keepAliveTimeout = 65_000; // longer than common load balancer idle timeouts (60 s)
  server.on('close', () => limiter.stop());
  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });
  return server;
}
