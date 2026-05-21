/*
CIDR rule matching for IPvFoo+Rules fork.

Parses a user-pasted ruleset (IPv4 CIDRs in various formats) and matches IPs
against it. Pure functions; safe to load in service worker, popup, options,
or Node test runner.

Storage layout (chrome.storage.local):
  rules:raw           string   The original textarea contents.
  rules:compiled      array    [{net: uint32, mask: uint32, line: int, src: string}, ...]
  rules:meta          object   {total, valid, skipped, ts}
  rules:matchMeaning  string   "match-check" (default) | "match-x"
  rules:enabled       bool     master toggle (default true once rules exist)
*/

"use strict";

const RULES_RAW = "rules:raw";
const RULES_COMPILED = "rules:compiled";
const RULES_META = "rules:meta";
const RULES_MATCH_MEANING = "rules:matchMeaning";
const RULES_ENABLED = "rules:enabled";

const MATCH_MEANING_CHECK = "match-check";  // match -> ✅
const MATCH_MEANING_X = "match-x";          // match -> ❌
const DEFAULT_MATCH_MEANING = MATCH_MEANING_CHECK;

// Result of matchIP:
//   {status: "match",    rule: {...}}   IP is in a rule
//   {status: "no-match"}                IP didn't match any rule
//   {status: "na"}                      IPv6 address with IPv4-only ruleset, or invalid
//   {status: "disabled"}                rules feature off or no rules loaded

// ---- IPv4 helpers ----

function ipv4ToUint32(addr) {
  // Returns uint32 or null on parse failure.
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = parseInt(p, 10);
    if (n < 0 || n > 255) return null;
    out = ((out << 8) | n) >>> 0;
  }
  return out >>> 0;
}

function maskToUint32(mask) {
  // Accept "/22" style (already stripped of slash) or "255.255.252.0" style.
  if (/^\d{1,2}$/.test(mask)) {
    const bits = parseInt(mask, 10);
    if (bits < 0 || bits > 32) return null;
    if (bits === 0) return 0;
    return (0xffffffff << (32 - bits)) >>> 0;
  }
  if (mask.includes(".")) {
    const u = ipv4ToUint32(mask);
    if (u === null) return null;
    // Validate it's a contiguous netmask (1s then 0s).
    const inv = (~u) >>> 0;
    if (((inv + 1) & inv) !== 0) return null;
    return u;
  }
  return null;
}

function uint32ToIPv4(u) {
  return [(u >>> 24) & 0xff, (u >>> 16) & 0xff, (u >>> 8) & 0xff, u & 0xff].join(".");
}

function uint32MaskToCidrBits(mask) {
  // Count leading 1s. Returns -1 if not a valid contiguous mask.
  if (mask === 0) return 0;
  const inv = (~mask) >>> 0;
  if (((inv + 1) & inv) !== 0) return -1;
  let n = 0;
  let m = mask >>> 0;
  while (m) { n += m & 1; m = m >>> 1; }
  return n;
}

// ---- Parser ----

// Match a CIDR anywhere in a line. Accepts "/22" or "/255.255.252.0".
// Captures: ip (1-4), mask (5).
const CIDR_RE = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\/\s*(\d{1,3}(?:\.\d{1,3}\.\d{1,3}\.\d{1,3})?)/;

function parseRules(rawText) {
  const compiled = [];
  const skipped = [];
  const lines = (rawText || "").split(/\r?\n/);
  let lineNum = 0;
  for (const rawLine of lines) {
    lineNum++;
    const line = rawLine.trim();
    if (!line) continue;
    // Comment lines.
    if (line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) continue;

    const m = line.match(CIDR_RE);
    if (!m) {
      skipped.push({lineNum, text: rawLine, reason: "no CIDR found"});
      continue;
    }
    const ip = m[1];
    const maskStr = m[2];
    const net = ipv4ToUint32(ip);
    const mask = maskToUint32(maskStr);
    if (net === null) {
      skipped.push({lineNum, text: rawLine, reason: "invalid IPv4 address"});
      continue;
    }
    if (mask === null) {
      skipped.push({lineNum, text: rawLine, reason: "invalid mask"});
      continue;
    }
    // Normalize network: zero out host bits.
    const normNet = (net & mask) >>> 0;
    compiled.push({net: normNet, mask: mask, line: lineNum, src: line});
  }
  return {
    compiled,
    skipped,
    total: lines.length,
    valid: compiled.length,
  };
}

// ---- Matcher ----

// Test if a string looks like an IPv4 dotted address. Quick-and-loose.
function isIPv4(s) {
  return typeof s === "string" && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s);
}

// Test if a string looks like an IPv6 address (contains colon).
function isIPv6(s) {
  return typeof s === "string" && s.includes(":");
}

function matchIP(addrStr, compiled) {
  if (!compiled || compiled.length === 0) {
    return {status: "disabled"};
  }
  if (isIPv6(addrStr)) {
    return {status: "na"};
  }
  if (!isIPv4(addrStr)) {
    return {status: "na"};
  }
  const u = ipv4ToUint32(addrStr);
  if (u === null) return {status: "na"};
  for (const rule of compiled) {
    if (((u & rule.mask) >>> 0) === rule.net) {
      return {status: "match", rule};
    }
  }
  return {status: "no-match"};
}

// Translate (status, matchMeaning) -> visual + tooltip data.
// Returns {icon: "check"|"x"|"dash"|"none", color: "green"|"red"|"gray"|null, tooltip: string}
function statusToVisual(matchResult, matchMeaning, ruleCount) {
  const meaning = matchMeaning || DEFAULT_MATCH_MEANING;
  switch (matchResult.status) {
    case "disabled":
      return {icon: "none", color: null, tooltip: ""};
    case "na":
      return {icon: "dash", color: "gray", tooltip: "IPv6 or invalid — IPv4 rules don't apply"};
    case "match": {
      const r = matchResult.rule;
      const cidr = `${uint32ToIPv4(r.net)}/${uint32MaskToCidrBits(r.mask)}`;
      if (meaning === MATCH_MEANING_X) {
        return {icon: "x", color: "red", tooltip: `matches ${cidr} (line ${r.line})`};
      }
      return {icon: "check", color: "green", tooltip: `matches ${cidr} (line ${r.line})`};
    }
    case "no-match": {
      const txt = `no match in ${ruleCount.toLocaleString()} rule${ruleCount === 1 ? "" : "s"}`;
      if (meaning === MATCH_MEANING_X) {
        return {icon: "check", color: "green", tooltip: txt};
      }
      return {icon: "x", color: "red", tooltip: txt};
    }
  }
  return {icon: "none", color: null, tooltip: ""};
}

// CommonJS export for Node tests; harmless in browser (module is undefined).
if (typeof module !== "undefined") {
  module.exports = {
    RULES_RAW, RULES_COMPILED, RULES_META, RULES_MATCH_MEANING, RULES_ENABLED,
    MATCH_MEANING_CHECK, MATCH_MEANING_X, DEFAULT_MATCH_MEANING,
    ipv4ToUint32, maskToUint32, uint32ToIPv4, uint32MaskToCidrBits,
    parseRules, matchIP, statusToVisual,
    isIPv4, isIPv6,
  };
}
