/**
 * Static file server with path-traversal protection, ETag revalidation,
 * gzip/brotli for text assets, and sensible cache lifetimes.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { promisify } from 'node:util';
import crypto from 'node:crypto';

const gzip = promisify(zlib.gzip);
const brotli = promisify(zlib.brotliCompress);

export const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
};

const COMPRESSIBLE = new Set(['.html', '.css', '.js', '.mjs', '.json', '.svg', '.txt', '.xml', '.webmanifest']);

function cacheControlFor(ext) {
  if (ext === '.woff2') return 'public, max-age=2592000, immutable'; // 30 days
  if (['.png', '.jpg', '.jpeg', '.webp', '.ico', '.svg'].includes(ext)) return 'public, max-age=604800'; // 7 days
  // HTML/CSS/JS: always revalidate (cheap 304 thanks to ETag), so deploys show up immediately
  return 'public, max-age=0, must-revalidate';
}

/** Pick the best encoding the client accepts. */
export function negotiateEncoding(header = '') {
  const h = String(header).toLowerCase();
  if (/\bbr\b/.test(h)) return 'br';
  if (/\bgzip\b/.test(h)) return 'gzip';
  return null;
}

export class StaticServer {
  /**
   * @param {string} root      directory to serve
   * @param {Record<string,string>} aliases  url path -> absolute file path (e.g. shared modules)
   */
  constructor(root, aliases = {}) {
    this.root = path.resolve(root);
    this.aliases = aliases;
    this.cache = new Map(); // absPath -> { mtimeMs, etag, raw, gzip?, br? }
  }

  /** Map a URL pathname to an absolute file path inside root, or null. */
  resolve(pathname) {
    if (this.aliases[pathname]) return this.aliases[pathname];
    let decoded;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      return null;
    }
    if (decoded.includes('\0')) return null;
    if (decoded.endsWith('/')) decoded += 'index.html';
    const abs = path.resolve(this.root, '.' + path.posix.normalize('/' + decoded));
    // Must stay inside root (blocks ../../etc/passwd and encoded variants)
    if (abs !== this.root && !abs.startsWith(this.root + path.sep)) return null;
    // Never serve dotfiles (.env, .git, ...)
    if (path.relative(this.root, abs).split(path.sep).some((seg) => seg.startsWith('.'))) return null;
    return abs;
  }

  async load(abs) {
    const st = await fs.stat(abs);
    if (!st.isFile()) return null;
    const hit = this.cache.get(abs);
    if (hit && hit.mtimeMs === st.mtimeMs && hit.size === st.size) return hit;
    const raw = await fs.readFile(abs);
    const entry = {
      mtimeMs: st.mtimeMs,
      size: st.size,
      raw,
      etag: '"' + crypto.createHash('sha1').update(raw).digest('base64url').slice(0, 20) + '"',
      lastModified: st.mtime.toUTCString(),
    };
    this.cache.set(abs, entry);
    return entry;
  }

  /**
   * Try to serve the request. Returns true if a response was sent.
   */
  async serve(req, res, pathname) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return false;
    const abs = this.resolve(pathname);
    if (!abs) return false;
    let entry;
    try {
      entry = await this.load(abs);
    } catch {
      return false;
    }
    if (!entry) return false;
    const ext = path.extname(abs).toLowerCase();
    await sendBuffer(req, res, entry, MIME[ext] || 'application/octet-stream', cacheControlFor(ext), COMPRESSIBLE.has(ext));
    return true;
  }
}

/**
 * Send a cached entry ({raw, etag, gzip?, br?}) with conditional GET + compression.
 * Shared with the rendered index page.
 */
export async function sendBuffer(req, res, entry, type, cacheControl, compressible, status = 200) {
  res.setHeader('Content-Type', type);
  res.setHeader('Cache-Control', cacheControl);
  res.setHeader('ETag', entry.etag);
  if (entry.lastModified) res.setHeader('Last-Modified', entry.lastModified);
  if (compressible) res.setHeader('Vary', 'Accept-Encoding');

  if (status === 200 && req.headers['if-none-match'] === entry.etag) {
    res.statusCode = 304;
    res.end();
    return;
  }

  let body = entry.raw;
  const enc = compressible && entry.raw.length > 1024 ? negotiateEncoding(req.headers['accept-encoding']) : null;
  if (enc === 'br') {
    entry.br ??= await brotli(entry.raw, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 9 } });
    body = entry.br;
  } else if (enc === 'gzip') {
    entry.gzip ??= await gzip(entry.raw, { level: 9 });
    body = entry.gzip;
  }
  if (enc) res.setHeader('Content-Encoding', enc);
  res.setHeader('Content-Length', body.length);
  res.statusCode = status;
  res.end(req.method === 'HEAD' ? undefined : body);
}
