/**
 * DNS lookup tool: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV and PTR (reverse).
 */
import { Resolver } from 'node:dns/promises';
import net from 'node:net';
import { normalizeHostname } from '../lib/net.js';
import { HttpError } from '../http.js';

export const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'SRV', 'PTR'];

export const RESOLVERS = {
  system: { label: 'Mặc định của máy chủ', servers: null },
  cloudflare: { label: 'Cloudflare 1.1.1.1', servers: ['1.1.1.1', '1.0.0.1'] },
  google: { label: 'Google 8.8.8.8', servers: ['8.8.8.8', '8.8.4.4'] },
  quad9: { label: 'Quad9 9.9.9.9', servers: ['9.9.9.9', '149.112.112.112'] },
};

const ERROR_TEXT = {
  ENODATA: 'Tên miền tồn tại nhưng không có bản ghi loại này.',
  ENOTFOUND: 'Không tìm thấy tên miền (NXDOMAIN).',
  ESERVFAIL: 'DNS server trả về SERVFAIL (thường do lỗi DNSSEC hoặc nameserver của domain hỏng).',
  EREFUSED: 'DNS server từ chối truy vấn (REFUSED).',
  ETIMEOUT: 'Hết thời gian chờ phản hồi từ DNS server.',
  ECONNREFUSED: 'Không kết nối được tới DNS server.',
  EBADNAME: 'Tên miền không hợp lệ.',
};

// Tiny TTL cache so repeated clicks don't hammer upstream resolvers
const cache = new Map();
const CACHE_MS = 30_000;
const CACHE_MAX = 500;

function resolverFor(key) {
  const def = RESOLVERS[key];
  const r = new Resolver({ timeout: 3000, tries: 2 });
  if (def?.servers) r.setServers(def.servers);
  return r;
}

async function query(resolver, name, type) {
  switch (type) {
    case 'A':
      return (await resolver.resolve4(name, { ttl: true })).map((r) => ({ value: r.address, ttl: r.ttl }));
    case 'AAAA':
      return (await resolver.resolve6(name, { ttl: true })).map((r) => ({ value: r.address, ttl: r.ttl }));
    case 'MX':
      return (await resolver.resolveMx(name))
        .sort((a, b) => a.priority - b.priority)
        .map((r) => ({ value: r.exchange, priority: r.priority }));
    case 'TXT':
      return (await resolver.resolveTxt(name)).map((chunks) => ({ value: chunks.join('') }));
    case 'NS':
      return (await resolver.resolveNs(name)).sort().map((v) => ({ value: v }));
    case 'CNAME':
      return (await resolver.resolveCname(name)).map((v) => ({ value: v }));
    case 'SOA': {
      const s = await resolver.resolveSoa(name);
      return [
        {
          value: s.nsname,
          hostmaster: s.hostmaster,
          serial: s.serial,
          refresh: s.refresh,
          retry: s.retry,
          expire: s.expire,
          minttl: s.minttl,
        },
      ];
    }
    case 'CAA':
      return (await resolver.resolveCaa(name)).map((r) => {
        const tag = Object.keys(r).find((k) => k !== 'critical');
        return { value: `${r.critical} ${tag} "${r[tag]}"` };
      });
    case 'SRV':
      return (await resolver.resolveSrv(name)).map((r) => ({
        value: `${r.priority} ${r.weight} ${r.port} ${r.name}`,
      }));
    case 'PTR':
      return (await resolver.reverse(name)).map((v) => ({ value: v }));
    default:
      throw new HttpError(400, 'Loại bản ghi không được hỗ trợ.');
  }
}

/** Human hints that turn raw records into something a helpdesk person can act on. */
function insights(name, type, records) {
  const out = [];
  if (type === 'TXT') {
    const spf = records.filter((r) => r.value.toLowerCase().startsWith('v=spf1'));
    if (spf.length > 1) out.push({ level: 'warn', text: 'Có nhiều hơn 1 bản ghi SPF — mail server sẽ coi là lỗi (permerror). Hãy gộp lại thành 1.' });
    if (spf.length === 1) {
      const v = spf[0].value;
      if (/\+all\b/.test(v)) out.push({ level: 'bad', text: 'SPF kết thúc bằng "+all": bất kỳ ai cũng gửi mail giả mạo domain này được.' });
      else if (/~all\b/.test(v)) out.push({ level: 'info', text: 'SPF dùng "~all" (softfail). Khi đã ổn định nên chuyển sang "-all".' });
      else if (/-all\b/.test(v)) out.push({ level: 'good', text: 'SPF dùng "-all": chặn mail giả mạo chặt chẽ.' });
    }
    if (spf.length === 0 && !name.startsWith('_')) out.push({ level: 'info', text: 'Không thấy SPF. Thử tra TXT của _dmarc.' + name + ' để kiểm tra DMARC.' });
    const dmarc = records.find((r) => r.value.toLowerCase().startsWith('v=dmarc1'));
    if (dmarc) {
      const p = (dmarc.value.match(/;\s*p=(\w+)/i) || [])[1];
      if (p === 'none') out.push({ level: 'info', text: 'DMARC p=none: chỉ giám sát, chưa chặn mail giả mạo.' });
      if (p === 'quarantine' || p === 'reject') out.push({ level: 'good', text: `DMARC p=${p}: mail giả mạo sẽ bị ${p === 'reject' ? 'từ chối' : 'đưa vào spam'}.` });
    }
  }
  if (type === 'CAA' && records.length) out.push({ level: 'good', text: 'Có CAA: chỉ các CA được liệt kê mới cấp được chứng chỉ SSL cho domain.' });
  if (type === 'NS' && records.length === 1) out.push({ level: 'warn', text: 'Chỉ có 1 nameserver — nên có ít nhất 2 để dự phòng.' });
  if (type === 'MX' && records.some((r) => net.isIP(r.value))) out.push({ level: 'bad', text: 'MX trỏ thẳng vào IP — sai chuẩn RFC, MX phải là tên miền.' });
  return out;
}

export async function dnsLookup({ name: rawName, type: rawType, resolver: rawResolver }) {
  const type = String(rawType || 'A').toUpperCase();
  if (!RECORD_TYPES.includes(type)) throw new HttpError(400, `Loại bản ghi phải là một trong: ${RECORD_TYPES.join(', ')}.`);
  const resolverKey = RESOLVERS[rawResolver] ? rawResolver : 'system';

  let name;
  if (type === 'PTR') {
    const ip = String(rawName || '').trim();
    if (!net.isIP(ip)) throw new HttpError(400, 'Tra ngược (PTR) cần nhập địa chỉ IP, ví dụ 8.8.8.8.');
    name = ip;
  } else {
    name = normalizeHostname(rawName);
    if (!name) throw new HttpError(400, 'Tên miền không hợp lệ. Ví dụ: nhanhoa.com');
  }

  const cacheKey = `${resolverKey}|${type}|${name}`;
  const hit = cache.get(cacheKey);
  if (hit && hit.expires > Date.now()) return { ...hit.data, cached: true };

  const started = process.hrtime.bigint();
  let records = [];
  let error = null;
  try {
    records = await query(resolverFor(resolverKey), name, type);
  } catch (e) {
    if (e instanceof HttpError) throw e;
    if (e.code === 'ENODATA') records = [];
    else error = { code: e.code || 'ERROR', message: ERROR_TEXT[e.code] || 'Truy vấn DNS thất bại.' };
  }
  const ms = Number(process.hrtime.bigint() - started) / 1e6;

  const data = {
    name,
    type,
    resolver: { key: resolverKey, label: RESOLVERS[resolverKey].label },
    timeMs: Math.round(ms * 10) / 10,
    records,
    error,
    insights: error ? [] : insights(name, type, records),
    empty: !error && records.length === 0 ? ERROR_TEXT.ENODATA : null,
  };

  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
  cache.set(cacheKey, { data, expires: Date.now() + CACHE_MS });
  return { ...data, cached: false };
}
