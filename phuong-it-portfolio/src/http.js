/**
 * Small HTTP helpers shared by all route handlers.
 */

export class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

export function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  // API responses are personalised (your IP, your lookup) — never cache them in shared caches
  if (!res.hasHeader('Cache-Control')) res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Length', Buffer.byteLength(body));
  res.end(body);
}

/**
 * Read and parse a JSON request body with a hard size cap.
 * Rejects non-JSON content types so a plain HTML form on another site
 * cannot post to the API (CSRF via simple requests).
 */
export function readJson(req, limitBytes = 16 * 1024) {
  return new Promise((resolve, reject) => {
    const type = String(req.headers['content-type'] || '').toLowerCase();
    if (!type.startsWith('application/json')) {
      reject(new HttpError(415, 'Content-Type phải là application/json.'));
      req.resume();
      return;
    }
    const declared = Number(req.headers['content-length'] || 0);
    if (declared > limitBytes) {
      reject(new HttpError(413, 'Dữ liệu gửi lên quá lớn.'));
      req.resume();
      return;
    }
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limitBytes) {
        reject(new HttpError(413, 'Dữ liệu gửi lên quá lớn.'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text ? JSON.parse(text) : {});
      } catch {
        reject(new HttpError(400, 'JSON không hợp lệ.'));
      }
    });
    req.on('error', reject);
  });
}

export function isHttps(req, trustProxy) {
  if (req.socket?.encrypted) return true;
  if (!trustProxy) return false;
  const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  return proto === 'https';
}

export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
