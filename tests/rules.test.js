// Run with: node --test tests/rules.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const r = require("../src/rules.js");

test("ipv4ToUint32: valid and invalid", () => {
  assert.equal(r.ipv4ToUint32("0.0.0.0"), 0);
  assert.equal(r.ipv4ToUint32("255.255.255.255"), 0xffffffff);
  assert.equal(r.ipv4ToUint32("1.2.3.4"), 0x01020304);
  assert.equal(r.ipv4ToUint32("256.0.0.1"), null);
  assert.equal(r.ipv4ToUint32("1.2.3"), null);
  assert.equal(r.ipv4ToUint32("a.b.c.d"), null);
});

test("maskToUint32: cidr and dotted", () => {
  assert.equal(r.maskToUint32("0"), 0);
  assert.equal(r.maskToUint32("32"), 0xffffffff);
  assert.equal(r.maskToUint32("24"), 0xffffff00);
  assert.equal(r.maskToUint32("22"), 0xfffffc00);
  assert.equal(r.maskToUint32("255.255.255.0"), 0xffffff00);
  assert.equal(r.maskToUint32("255.255.252.0"), 0xfffffc00);
  assert.equal(r.maskToUint32("33"), null);
  assert.equal(r.maskToUint32("255.0.255.0"), null);  // non-contiguous
});

test("uint32MaskToCidrBits", () => {
  assert.equal(r.uint32MaskToCidrBits(0), 0);
  assert.equal(r.uint32MaskToCidrBits(0xffffff00), 24);
  assert.equal(r.uint32MaskToCidrBits(0xfffffc00), 22);
  assert.equal(r.uint32MaskToCidrBits(0xffffffff), 32);
});

test("parseRules: mikrotik-style plain CIDRs", () => {
  const raw = `217.198.190.0/24
217.172.118.0/24
217.172.100.0/24`;
  const out = r.parseRules(raw);
  assert.equal(out.valid, 3);
  assert.equal(out.skipped.length, 0);
  assert.equal(out.compiled[0].src, "217.198.190.0/24");
});

test("parseRules: ocserv no-route style with dotted mask", () => {
  const raw = `no-route = 37.130.204.0/255.255.252.0
no-route = 37.137.0.0/255.255.0.0`;
  const out = r.parseRules(raw);
  assert.equal(out.valid, 2);
  assert.equal(out.compiled[0].net, r.ipv4ToUint32("37.130.204.0"));
  assert.equal(out.compiled[0].mask, 0xfffffc00);
});

test("parseRules: comments and blanks ignored", () => {
  const raw = `# This is a comment
// another comment
; semicolon comment

1.2.3.0/24
`;
  const out = r.parseRules(raw);
  assert.equal(out.valid, 1);
  assert.equal(out.skipped.length, 0);
});

test("parseRules: mikrotik print output extracts CIDR", () => {
  const raw = ` 0   ;;; SecureListUpdate-p0
     DOMAddList       217.198.190.0/24                     2026-05-21 03:00:05
 1   ;;; SecureListUpdate-p0
     DOMAddList       217.172.118.0/24                     2026-05-21 03:00:05`;
  const out = r.parseRules(raw);
  // The "0" and "1" lines don't have a CIDR; the DOMAddList lines do.
  assert.equal(out.valid, 2);
});

test("parseRules: invalid lines go to skipped", () => {
  const raw = `1.2.3.0/24
not an ip
999.0.0.0/24
1.2.3.0/33`;
  const out = r.parseRules(raw);
  assert.equal(out.valid, 1);
  assert.equal(out.skipped.length, 3);
});

test("parseRules: host bits in network are normalized", () => {
  const raw = `1.2.3.4/24`;
  const out = r.parseRules(raw);
  assert.equal(out.compiled[0].net, r.ipv4ToUint32("1.2.3.0"));
});

test("matchIP: basic match and no-match", () => {
  const {compiled} = r.parseRules(`192.168.1.0/24\n10.0.0.0/8\n8.8.8.0/24`);
  assert.equal(r.matchIP("192.168.1.50", compiled).status, "match");
  assert.equal(r.matchIP("10.99.99.99", compiled).status, "match");
  assert.equal(r.matchIP("8.8.8.8", compiled).status, "match");
  assert.equal(r.matchIP("8.8.4.4", compiled).status, "no-match");
  assert.equal(r.matchIP("1.1.1.1", compiled).status, "no-match");
});

test("matchIP: IPv6 returns na", () => {
  const {compiled} = r.parseRules(`1.2.3.0/24`);
  assert.equal(r.matchIP("2001:db8::1", compiled).status, "na");
  assert.equal(r.matchIP("::1", compiled).status, "na");
});

test("matchIP: empty ruleset returns disabled", () => {
  assert.equal(r.matchIP("1.2.3.4", []).status, "disabled");
  assert.equal(r.matchIP("1.2.3.4", null).status, "disabled");
});

test("matchIP: returns the matching rule", () => {
  const {compiled} = r.parseRules(`10.0.0.0/8\n192.168.1.0/24`);
  const result = r.matchIP("10.5.5.5", compiled);
  assert.equal(result.status, "match");
  assert.equal(result.rule.src, "10.0.0.0/8");
});

test("statusToVisual: match-check meaning", () => {
  const {compiled} = r.parseRules(`1.2.3.0/24`);
  const m = r.matchIP("1.2.3.4", compiled);
  const v = r.statusToVisual(m, r.MATCH_MEANING_CHECK, 1);
  assert.equal(v.icon, "check");
  assert.equal(v.color, "green");
  assert.match(v.tooltip, /matches 1\.2\.3\.0\/24/);

  const nm = r.matchIP("9.9.9.9", compiled);
  const vn = r.statusToVisual(nm, r.MATCH_MEANING_CHECK, 1);
  assert.equal(vn.icon, "x");
  assert.equal(vn.color, "red");
});

test("statusToVisual: match-x meaning inverts", () => {
  const {compiled} = r.parseRules(`1.2.3.0/24`);
  const m = r.matchIP("1.2.3.4", compiled);
  const v = r.statusToVisual(m, r.MATCH_MEANING_X, 1);
  assert.equal(v.icon, "x");
  assert.equal(v.color, "red");

  const nm = r.matchIP("9.9.9.9", compiled);
  const vn = r.statusToVisual(nm, r.MATCH_MEANING_X, 1);
  assert.equal(vn.icon, "check");
  assert.equal(vn.color, "green");
});

test("statusToVisual: IPv6 shows dash regardless of meaning", () => {
  const {compiled} = r.parseRules(`1.2.3.0/24`);
  const m = r.matchIP("2001:db8::1", compiled);
  for (const meaning of [r.MATCH_MEANING_CHECK, r.MATCH_MEANING_X]) {
    const v = r.statusToVisual(m, meaning, 1);
    assert.equal(v.icon, "dash");
    assert.equal(v.color, "gray");
  }
});

test("statusToVisual: disabled shows nothing", () => {
  const m = r.matchIP("1.2.3.4", []);
  const v = r.statusToVisual(m, r.MATCH_MEANING_CHECK, 0);
  assert.equal(v.icon, "none");
});

test("performance: 2100 rules x 100 IPs is fast", () => {
  const lines = [];
  for (let i = 0; i < 2100; i++) {
    lines.push(`10.${i >> 8}.${i & 0xff}.0/24`);
  }
  const {compiled} = r.parseRules(lines.join("\n"));
  assert.equal(compiled.length, 2100);
  const start = Date.now();
  for (let i = 0; i < 100; i++) {
    r.matchIP(`10.${(i*7) >> 8}.${(i*7) & 0xff}.50`, compiled);
  }
  const elapsed = Date.now() - start;
  // Even O(n*m) = 210k comparisons should be well under 50ms.
  assert.ok(elapsed < 50, `took ${elapsed}ms (expected <50)`);
});
