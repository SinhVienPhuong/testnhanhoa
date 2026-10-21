/**
 * IPv4 subnet calculator.
 *
 * Isomorphic ES module: no Node.js APIs, so the same file runs on the server
 * (/api/subnet) and in the browser (served at /js/lib/subnet.js).
 */

const MAX_U32 = 0xffffffff;

/** Parse dotted-quad IPv4 into an unsigned 32-bit integer. Returns null if invalid. */
export function ipToInt(ip) {
  if (typeof ip !== 'string') return null;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    // Reject empty, signs, leading zeros ("010" is ambiguous: octal vs decimal)
    if (!/^(0|[1-9]\d{0,2})$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

/** Convert an unsigned 32-bit integer to dotted-quad. */
export function intToIp(n) {
  n = n >>> 0;
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** Prefix length (0-32) to netmask integer. */
export function prefixToMask(prefix) {
  if (prefix === 0) return 0;
  return (MAX_U32 << (32 - prefix)) >>> 0;
}

/** Netmask integer to prefix length, or null if the mask is not contiguous. */
export function maskToPrefix(mask) {
  mask = mask >>> 0;
  const inverted = ~mask >>> 0;
  // A valid mask's inverse is 2^k - 1, so inverted & (inverted + 1) === 0
  if ((inverted & (inverted + 1)) !== 0) return null;
  let prefix = 0;
  for (let m = mask; m & 0x80000000; m = (m << 1) >>> 0) prefix++;
  return prefix;
}

/** Binary string with dots between octets, e.g. 11000000.10101000.00000001.00000000 */
export function toBinary(n) {
  const s = (n >>> 0).toString(2).padStart(32, '0');
  return s.match(/.{8}/g).join('.');
}

const SPECIAL_RANGES = [
  ['0.0.0.0/8', 'Mạng "this network" (RFC 1122)'],
  ['10.0.0.0/8', 'Private (RFC 1918)'],
  ['100.64.0.0/10', 'Shared address space / CGNAT (RFC 6598)'],
  ['127.0.0.0/8', 'Loopback (RFC 1122)'],
  ['169.254.0.0/16', 'Link-local / APIPA (RFC 3927)'],
  ['172.16.0.0/12', 'Private (RFC 1918)'],
  ['192.0.0.0/24', 'IETF protocol assignments (RFC 6890)'],
  ['192.0.2.0/24', 'Documentation TEST-NET-1 (RFC 5737)'],
  ['192.88.99.0/24', '6to4 relay anycast (deprecated)'],
  ['192.168.0.0/16', 'Private (RFC 1918)'],
  ['198.18.0.0/15', 'Benchmarking (RFC 2544)'],
  ['198.51.100.0/24', 'Documentation TEST-NET-2 (RFC 5737)'],
  ['203.0.113.0/24', 'Documentation TEST-NET-3 (RFC 5737)'],
  ['224.0.0.0/4', 'Multicast (RFC 5771)'],
  ['240.0.0.0/4', 'Reserved (RFC 1112)'],
  ['255.255.255.255/32', 'Limited broadcast'],
].map(([cidr, label]) => {
  const [ip, p] = cidr.split('/');
  const prefix = Number(p);
  return { base: ipToInt(ip), mask: prefixToMask(prefix), prefix, label };
});

/** Return the special-purpose range an address belongs to, or null for public unicast. */
export function classifyIp(n) {
  n = n >>> 0;
  // Most specific match wins
  let best = null;
  for (const r of SPECIAL_RANGES) {
    if (((n & r.mask) >>> 0) === r.base && (!best || r.prefix > best.prefix)) best = r;
  }
  return best ? best.label : null;
}

export function ipClass(n) {
  const first = n >>> 24;
  if (first < 128) return 'A';
  if (first < 192) return 'B';
  if (first < 224) return 'C';
  if (first < 240) return 'D (multicast)';
  return 'E (reserved)';
}

/**
 * Parse user input. Accepts:
 *   192.168.1.10/24
 *   192.168.1.10 255.255.255.0
 *   192.168.1.10/255.255.255.0
 *   192.168.1.10           (treated as /32)
 */
export function parseInput(input) {
  if (typeof input !== 'string') return { error: 'Thiếu địa chỉ IP.' };
  const s = input.trim().replace(/\s+/g, ' ');
  if (!s) return { error: 'Thiếu địa chỉ IP.' };
  if (s.length > 64) return { error: 'Chuỗi nhập quá dài.' };

  const m = s.match(/^([\d.]+)(?:\s*\/\s*|\s+)?([\d.]+)?$/);
  if (!m) return { error: 'Định dạng không hợp lệ. Ví dụ: 192.168.1.10/24' };

  const ip = ipToInt(m[1]);
  if (ip === null) return { error: `"${m[1]}" không phải địa chỉ IPv4 hợp lệ.` };

  let prefix = 32;
  if (m[2] !== undefined) {
    if (m[2].includes('.')) {
      const mask = ipToInt(m[2]);
      if (mask === null) return { error: `"${m[2]}" không phải subnet mask hợp lệ.` };
      prefix = maskToPrefix(mask);
      if (prefix === null) return { error: `Subnet mask "${m[2]}" không liên tục (các bit 1 phải nằm liền nhau).` };
    } else {
      if (!/^\d{1,2}$/.test(m[2])) return { error: 'Prefix phải là số từ 0 đến 32.' };
      prefix = Number(m[2]);
      if (prefix > 32) return { error: 'Prefix phải là số từ 0 đến 32.' };
    }
  }
  return { ip, prefix };
}

/** Core calculation for one IP + prefix. */
export function calculate(ip, prefix) {
  const mask = prefixToMask(prefix);
  const wildcard = ~mask >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;
  const size = 2 ** (32 - prefix);

  let firstHost, lastHost, usableHosts;
  if (prefix === 32) {
    firstHost = lastHost = network;
    usableHosts = 1;
  } else if (prefix === 31) {
    // RFC 3021: both addresses usable on point-to-point links
    firstHost = network;
    lastHost = broadcast;
    usableHosts = 2;
  } else {
    firstHost = network + 1;
    lastHost = broadcast - 1;
    usableHosts = size - 2;
  }

  return {
    input: `${intToIp(ip)}/${prefix}`,
    address: intToIp(ip),
    prefix,
    cidr: `${intToIp(network)}/${prefix}`,
    netmask: intToIp(mask),
    wildcard: intToIp(wildcard),
    network: intToIp(network),
    broadcast: prefix >= 31 ? null : intToIp(broadcast),
    firstHost: intToIp(firstHost),
    lastHost: intToIp(lastHost),
    totalAddresses: size,
    usableHosts,
    ipClass: ipClass(ip),
    scope: classifyIp(ip) || 'Public (định tuyến được trên Internet)',
    isPrivate: isRfc1918(ip),
    binary: {
      address: toBinary(ip),
      netmask: toBinary(mask),
      network: toBinary(network),
    },
    hex: '0x' + (ip >>> 0).toString(16).toUpperCase().padStart(8, '0'),
    reverseZone: reverseZone(network, prefix),
  };
}

export function isRfc1918(n) {
  n = n >>> 0;
  return (
    (n & 0xff000000) >>> 0 === 0x0a000000 ||
    (n & 0xfff00000) >>> 0 === 0xac100000 ||
    (n & 0xffff0000) >>> 0 === 0xc0a80000
  );
}

/** in-addr.arpa zone name for the network (octet-aligned, as used by BIND / Windows DNS). */
export function reverseZone(network, prefix) {
  const octets = intToIp(network).split('.');
  const keep = Math.max(1, Math.floor(prefix / 8));
  return octets.slice(0, Math.min(keep, 3)).reverse().join('.') + '.in-addr.arpa';
}

/**
 * Split a network into equal subnets of newPrefix.
 * Returns at most `limit` rows plus the total count so the UI can say "showing 64 of 1024".
 */
export function split(network, prefix, newPrefix, limit = 256) {
  if (!Number.isInteger(newPrefix) || newPrefix < prefix || newPrefix > 32) {
    return { error: `Prefix mới phải nằm trong khoảng /${prefix} đến /32.` };
  }
  const base = (network & prefixToMask(prefix)) >>> 0;
  const count = 2 ** (newPrefix - prefix);
  const step = 2 ** (32 - newPrefix);
  const rows = [];
  for (let i = 0; i < Math.min(count, limit); i++) {
    const net = base + i * step;
    const c = calculate(net, newPrefix);
    rows.push({
      cidr: c.cidr,
      firstHost: c.firstHost,
      lastHost: c.lastHost,
      broadcast: c.broadcast,
      usableHosts: c.usableHosts,
    });
  }
  return { count, shown: rows.length, rows };
}

/**
 * VLSM: allocate subnets for a list of host requirements inside a parent network,
 * largest first (the standard method taught for CCNA / enterprise VLAN design).
 */
export function vlsm(network, prefix, requirements) {
  if (!Array.isArray(requirements) || requirements.length === 0) {
    return { error: 'Cần ít nhất một yêu cầu số host.' };
  }
  if (requirements.length > 64) return { error: 'Tối đa 64 subnet.' };

  const parentBase = (network & prefixToMask(prefix)) >>> 0;
  const parentEnd = parentBase + 2 ** (32 - prefix); // exclusive

  const reqs = requirements
    .map((r, i) => ({ name: String(r.name || `Subnet ${i + 1}`).slice(0, 40), hosts: Number(r.hosts), order: i }))
    .filter((r) => Number.isInteger(r.hosts) && r.hosts > 0);
  if (reqs.length !== requirements.length) return { error: 'Số host phải là số nguyên dương.' };

  reqs.sort((a, b) => b.hosts - a.hosts || a.order - b.order);

  let cursor = parentBase;
  const rows = [];
  for (const r of reqs) {
    // smallest block with at least hosts + 2 addresses (network + broadcast)
    let p = 32;
    while (p > 0 && 2 ** (32 - p) - 2 < r.hosts) p--;
    if (2 ** (32 - p) - 2 < r.hosts) {
      return { error: `"${r.name}" cần ${r.hosts} host, vượt quá kích thước IPv4.` };
    }
    const size = 2 ** (32 - p);
    // align cursor to block size
    cursor = Math.ceil(cursor / size) * size;
    if (cursor + size > parentEnd) {
      return { error: `Không đủ không gian địa chỉ trong /${prefix} cho "${r.name}" (${r.hosts} host).` };
    }
    const c = calculate(cursor, p);
    rows.push({
      name: r.name,
      requested: r.hosts,
      cidr: c.cidr,
      netmask: c.netmask,
      firstHost: c.firstHost,
      lastHost: c.lastHost,
      broadcast: c.broadcast,
      usableHosts: c.usableHosts,
      wasted: c.usableHosts - r.hosts,
    });
    cursor += size;
  }
  const used = cursor - parentBase;
  return { rows, used, free: parentEnd - cursor, total: parentEnd - parentBase };
}
