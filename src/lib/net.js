/**
 * Server-side network helpers: client IP extraction, hostname validation,
 * and the address checks that protect the header scanner from SSRF.
 */
import net from 'node:net';
import { ipToInt, classifyIp } from './subnet.js';

/**
 * Real client IP. Behind a reverse proxy (Vibe Hosting, Nginx, Cloudflare) the socket
 * address is the proxy, so we read X-Forwarded-For — but only when TRUST_PROXY is on,
 * otherwise anyone could spoof their IP to dodge rate limits.
 */
export function clientIp(req, trustProxy) {
  if (trustProxy) {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && net.isIP(cf.trim())) return normalizeIp(cf.trim());
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string') {
      const first = xff.split(',')[0].trim();
      if (net.isIP(first)) return normalizeIp(first);
    }
    const xri = req.headers['x-real-ip'];
    if (typeof xri === 'string' && net.isIP(xri.trim())) return normalizeIp(xri.trim());
  }
  return normalizeIp(req.socket?.remoteAddress || '');
}

/** Strip IPv4-mapped IPv6 prefix (::ffff:1.2.3.4 -> 1.2.3.4). */
export function normalizeIp(ip) {
  if (typeof ip !== 'string') return '';
  const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return m ? m[1] : ip;
}

/**
 * RFC 1123 hostname: labels 1-63 chars, letters/digits/hyphen, no leading/trailing hyphen,
 * total <= 253. Underscore allowed for SRV/DKIM-style names (_dmarc.example.com).
 * Unicode (IDN) names are converted to punycode first via URL.
 */
export function normalizeHostname(input) {
  if (typeof input !== 'string') return null;
  let h = input.trim().toLowerCase();
  if (!h || h.length > 253 + 10) return null;
  // Allow users to paste a full URL
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#]/)[0];
  h = h.replace(/:\d+$/, '').replace(/\.$/, '');
  if (!h) return null;
  if (/[^\x00-\x7f]/.test(h)) {
    try {
      h = new URL(`http://${h}`).hostname;
    } catch {
      return null;
    }
  }
  if (h.length > 253) return null;
  const labels = h.split('.');
  if (labels.length < 1) return null;
  for (const l of labels) {
    if (!/^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/.test(l)) return null;
  }
  return h;
}

/**
 * True if an address must never be fetched by the server (SSRF protection):
 * loopback, RFC1918, CGNAT, link-local (incl. cloud metadata 169.254.169.254),
 * multicast, reserved, and their IPv6 equivalents.
 */
export function isBlockedAddress(ip) {
  const family = net.isIP(ip);
  if (family === 4) {
    const n = ipToInt(ip);
    if (n === null) return true;
    return classifyIp(n) !== null; // any special-purpose range is blocked
  }
  if (family === 6) {
    const a = ip.toLowerCase();
    const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isBlockedAddress(mapped[1]);
    if (a === '::' || a === '::1') return true;
    const firstHextet = parseInt(expandV6(a)[0], 16);
    if ((firstHextet & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
    if ((firstHextet & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if ((firstHextet & 0xff00) === 0xff00) return true; // ff00::/8 multicast
    if (a.startsWith('2001:db8:') || a === '2001:db8::') return true; // documentation
    if (a.startsWith('64:ff9b:')) return true; // NAT64 can reach internal v4
    if ((firstHextet & 0xe000) !== 0x2000) return true; // only 2000::/3 is global unicast
    return false;
  }
  return true;
}

function expandV6(addr) {
  const [head, tail] = addr.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail ? tail.split(':') : [];
  const fill = tail !== undefined ? new Array(8 - h.length - t.length).fill('0') : [];
  return [...h, ...fill, ...t].map((x) => x || '0');
}
