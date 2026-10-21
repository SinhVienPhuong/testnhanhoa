/**
 * HTTP security headers and an in-memory rate limiter.
 */

/**
 * Strict CSP: no inline scripts, no third-party origins. Fonts are self-hosted,
 * so the page loads nothing from outside its own domain.
 */
export const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; '),
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

export function applySecurityHeaders(res, { https }) {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  // HSTS and request upgrading only once the site is actually served over HTTPS,
  // otherwise local development on http://localhost would break.
  if (https) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', SECURITY_HEADERS['Content-Security-Policy'] + '; upgrade-insecure-requests');
  }
}

/**
 * Sliding-window rate limiter keyed by client IP + bucket name.
 * Memory-bounded: stale keys are swept periodically and the map is capped.
 */
export class RateLimiter {
  constructor({ maxKeys = 10_000, sweepMs = 60_000, now = () => Date.now() } = {}) {
    this.hits = new Map(); // key -> number[] (timestamps)
    this.maxKeys = maxKeys;
    this.now = now;
    this.timer = setInterval(() => this.sweep(), sweepMs);
    this.timer.unref?.();
  }

  /**
   * @returns {{ok: boolean, remaining: number, retryAfter: number}}
   */
  check(key, limit, windowMs) {
    const t = this.now();
    let arr = this.hits.get(key);
    if (!arr) {
      if (this.hits.size >= this.maxKeys) this.sweep(true);
      arr = [];
      this.hits.set(key, arr);
    }
    while (arr.length && arr[0] <= t - windowMs) arr.shift();
    if (arr.length >= limit) {
      const retryAfter = Math.max(1, Math.ceil((arr[0] + windowMs - t) / 1000));
      return { ok: false, remaining: 0, retryAfter };
    }
    arr.push(t);
    arr.windowMs = windowMs;
    return { ok: true, remaining: limit - arr.length, retryAfter: 0 };
  }

  sweep(aggressive = false) {
    const t = this.now();
    for (const [k, arr] of this.hits) {
      const w = arr.windowMs || 60_000;
      if (!arr.length || arr[arr.length - 1] <= t - w || aggressive) this.hits.delete(k);
      if (aggressive && this.hits.size < this.maxKeys / 2) break;
    }
  }

  stop() {
    clearInterval(this.timer);
  }
}
