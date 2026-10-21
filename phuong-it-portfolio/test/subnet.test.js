import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ipToInt, intToIp, parseInput, calculate, split, vlsm, maskToPrefix, classifyIp } from '../src/lib/subnet.js';

test('ipToInt / intToIp round-trip and strict parsing', () => {
  assert.equal(ipToInt('192.168.1.1'), 0xc0a80101);
  assert.equal(intToIp(0xc0a80101), '192.168.1.1');
  assert.equal(ipToInt('255.255.255.255'), 0xffffffff);
  assert.equal(ipToInt('0.0.0.0'), 0);
  for (const bad of ['256.1.1.1', '1.2.3', '1.2.3.4.5', '01.2.3.4', 'a.b.c.d', '1..2.3', '', ' ']) {
    assert.equal(ipToInt(bad), null, bad);
  }
});

test('maskToPrefix rejects non-contiguous masks', () => {
  assert.equal(maskToPrefix(ipToInt('255.255.255.0')), 24);
  assert.equal(maskToPrefix(ipToInt('255.255.252.0')), 22);
  assert.equal(maskToPrefix(0), 0);
  assert.equal(maskToPrefix(ipToInt('255.0.255.0')), null);
});

test('parseInput accepts CIDR, space mask, slash mask and bare IP', () => {
  assert.deepEqual(parseInput('10.0.0.1/8'), { ip: ipToInt('10.0.0.1'), prefix: 8 });
  assert.deepEqual(parseInput('10.0.0.1 255.255.0.0'), { ip: ipToInt('10.0.0.1'), prefix: 16 });
  assert.deepEqual(parseInput('10.0.0.1/255.255.255.128'), { ip: ipToInt('10.0.0.1'), prefix: 25 });
  assert.deepEqual(parseInput('10.0.0.1'), { ip: ipToInt('10.0.0.1'), prefix: 32 });
  assert.ok(parseInput('10.0.0.1/33').error);
  assert.ok(parseInput('10.0.0.1 255.0.255.0').error);
  assert.ok(parseInput('hello').error);
});

test('calculate: classic /24', () => {
  const r = calculate(ipToInt('192.168.10.25'), 24);
  assert.equal(r.network, '192.168.10.0');
  assert.equal(r.broadcast, '192.168.10.255');
  assert.equal(r.firstHost, '192.168.10.1');
  assert.equal(r.lastHost, '192.168.10.254');
  assert.equal(r.usableHosts, 254);
  assert.equal(r.wildcard, '0.0.0.255');
  assert.equal(r.isPrivate, true);
  assert.equal(r.reverseZone, '10.168.192.in-addr.arpa');
});

test('calculate: /31 point-to-point and /32 host routes', () => {
  const p31 = calculate(ipToInt('10.0.0.0'), 31);
  assert.equal(p31.usableHosts, 2);
  assert.equal(p31.broadcast, null);
  const p32 = calculate(ipToInt('8.8.8.8'), 32);
  assert.equal(p32.usableHosts, 1);
  assert.equal(p32.firstHost, '8.8.8.8');
});

test('calculate: /0 does not overflow', () => {
  const r = calculate(ipToInt('1.2.3.4'), 0);
  assert.equal(r.network, '0.0.0.0');
  assert.equal(r.broadcast, '255.255.255.255');
  assert.equal(r.totalAddresses, 2 ** 32);
});

test('classifyIp picks the most specific special range', () => {
  assert.match(classifyIp(ipToInt('169.254.169.254')), /Link-local/);
  assert.match(classifyIp(ipToInt('100.64.1.1')), /CGNAT/);
  assert.equal(classifyIp(ipToInt('8.8.8.8')), null);
});

test('split /24 into /26', () => {
  const s = split(ipToInt('192.168.10.0'), 24, 26);
  assert.equal(s.count, 4);
  assert.deepEqual(s.rows.map((r) => r.cidr), ['192.168.10.0/26', '192.168.10.64/26', '192.168.10.128/26', '192.168.10.192/26']);
  assert.ok(split(ipToInt('10.0.0.0'), 24, 20).error);
});

test('split caps rows but reports the full count', () => {
  const s = split(ipToInt('10.0.0.0'), 8, 24, 256);
  assert.equal(s.count, 65536);
  assert.equal(s.shown, 256);
});

test('vlsm allocates largest first, aligned, without overlap', () => {
  const r = vlsm(ipToInt('172.16.0.0'), 22, [
    { name: 'Small', hosts: 6 },
    { name: 'Big', hosts: 60 },
    { name: 'WAN', hosts: 2 },
  ]);
  assert.deepEqual(r.rows.map((x) => [x.name, x.cidr]), [
    ['Big', '172.16.0.0/26'],
    ['Small', '172.16.0.64/29'],
    ['WAN', '172.16.0.72/30'],
  ]);
  assert.equal(r.used, 64 + 8 + 4);
});

test('vlsm reports when the parent network is too small', () => {
  const r = vlsm(ipToInt('192.168.1.0'), 24, [{ name: 'Huge', hosts: 300 }]);
  assert.match(r.error, /Không đủ/);
});

test('vlsm rejects bad host counts', () => {
  assert.ok(vlsm(ipToInt('10.0.0.0'), 8, [{ hosts: -1 }]).error);
  assert.ok(vlsm(ipToInt('10.0.0.0'), 8, []).error);
});
