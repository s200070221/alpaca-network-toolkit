// ═══════════════════════════════════════════════════════════════════════════
// vuln-check.js — 韌體版本比對已知漏洞（2026-10-24，XN19；防火牆分析與交換器分析共用，主控在 network_analyzer/result）
// 不內建任何廠商漏洞資料：使用者自備 CSV（vendor,product,affected,fixed,cve,severity,kev,note），工具只負責
// 讀出設定檔的韌體版本、依各廠牌版本格式比較是否落在 affected 範圍。純函式、不碰 DOM，以單一全域物件 VulnCheck 對外。
// 版本格式（各取第一個符合的片段，比對時缺少的段視為 0）：
//   fortios 7.2.5（build 不比）、panos 10.2.9-h1、asa 9.18(4)22、ftd 7.2.5.1、junos 21.4R3-S5.3、
//   ios 15.2(7)E8（train 字母不同視為無法比較）、iosxe 17.9.4a、nxos 9.3(10)／10.2(5)M、eos 4.30.2F（train 字母不比）、aoscx 10.11.1020
// affected：以 ; 或 | 分隔多段，任一段符合即受影響。每段可寫
//   「7.2.0-7.2.6」（含頭尾；右側須以數字開頭，因此 10.2.9-h1、21.4R3-S5 不會被當成範圍）、
//   「<7.4.3」「<=7.0.13」「>=7.4.0 <7.4.3」（空白分隔的條件須同時成立）、「7.2.*」（前綴）或單一版本（相等）
// ═══════════════════════════════════════════════════════════════════════════
const VulnCheck = (function () {
  const ALIASES = [
    [/^(fortigate|fortios|fortinet)$/, 'fortios'], [/^(pan-?os|palo ?alto( networks)?|paloalto)$/, 'panos'],
    [/^(cisco )?asa$/, 'asa'], [/^(cisco )?(ftd|firepower|fmc ?ftd|secure firewall threat defense)$/, 'ftd'],
    [/^(junos|juniper|srx|junos os)$/, 'junos'], [/^(cisco )?ios$/, 'ios'], [/^(cisco )?ios[- ]?xe$/, 'iosxe'],
    [/^(cisco )?nx-?os$/, 'nxos'], [/^(arista|eos|arista eos)$/, 'eos'], [/^(aruba ?cx|aos-?cx|arubaos-?cx)$/, 'aoscx'],
  ];
  const SCHEMES = ['fortios', 'panos', 'asa', 'ftd', 'junos', 'ios', 'iosxe', 'nxos', 'eos', 'aoscx'];
  function scheme(v) {
    const s = String(v || '').trim().toLowerCase();
    if (SCHEMES.includes(s)) return s;
    const a = ALIASES.find(([re]) => re.test(s));
    return a ? a[1] : '';
  }
  // 設備（防火牆 parsed.vendor 或交換器 vendor 代碼）＋版本字串 → 版本格式；Cisco 交換器依版本寫法分 IOS／IOS-XE
  function deviceScheme(vendor, version) {
    const v = String(vendor || '').trim();
    const map = { FortiGate: 'fortios', PaloAlto: 'panos', 'Cisco ASA': 'asa', 'Cisco FTD': 'ftd', Juniper: 'junos', juniper: 'junos',
      nxos: 'nxos', arista: 'eos', aruba: 'aoscx' };
    if (map[v]) return map[v];
    if (v === 'cisco') {
      const s = String(version || '');
      if (/\d+\.\d+\(\d+\)/.test(s)) return 'ios';
      const m = s.match(/^(\d+)\./);
      return m && +m[1] >= 16 ? 'iosxe' : '';
    }
    return '';
  }
  const lc = c => (c ? c.toLowerCase().charCodeAt(0) - 96 : 0);
  // 版本 → {nums, train}；無法解析回傳 null
  function parse(sch, ver) {
    const s = String(ver || '').trim();
    let m;
    switch (sch) {
      case 'fortios': m = s.match(/(\d+)\.(\d+)\.(\d+)/); return m ? { nums: m.slice(1, 4).map(Number) } : null;
      case 'panos': m = s.match(/(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?/i); return m ? { nums: [+m[1], +m[2], +m[3], +(m[4] || 0)] } : null;
      case 'asa': m = s.match(/(\d+)\.(\d+)\((\d+)(?:\.(\d+))?\)(\d+)?/); return m ? { nums: [+m[1], +m[2], +m[3], +(m[4] || 0), +(m[5] || 0)] } : null;
      case 'junos': m = s.match(/(\d+)\.(\d+)[A-Z](\d+)(?:-S(\d+)(?:\.(\d+))?)?/i); return m ? { nums: [+m[1], +m[2], +m[3], +(m[4] || 0), +(m[5] || 0)] } : null;
      case 'ios': m = s.match(/(\d+)\.(\d+)\((\d+)\)([A-Z]+)?(\d+)?([a-z])?/); return m ? { nums: [+m[1], +m[2], +m[3], +(m[5] || 0), lc(m[6])], train: m[4] || '' } : null;
      case 'iosxe': m = s.match(/(\d+)\.(\d+)\.(\d+)([a-z])?/); return m ? { nums: [+m[1], +m[2], +m[3], lc(m[4])] } : null;
      case 'nxos': m = s.match(/(\d+)\.(\d+)\((\d+)([a-z])?\)/); return m ? { nums: [+m[1], +m[2], +m[3], lc(m[4])] } : null;
      case 'ftd': case 'eos': case 'aoscx': m = s.match(/\d+(?:\.\d+)+/); return m ? { nums: m[0].split('.').map(Number) } : null;
      default: return null;
    }
  }
  // a、b 為 parse() 結果；回傳 -1／0／1，train 不同（Cisco IOS）回傳 null
  function cmp(a, b) {
    if (!a || !b) return null;
    if ((a.train || b.train) && a.train !== b.train) return null;
    const n = Math.max(a.nums.length, b.nums.length);
    for (let i = 0; i < n; i++) { const x = a.nums[i] || 0, y = b.nums[i] || 0; if (x !== y) return x < y ? -1 : 1; }
    return 0;
  }
  // 單段範圍是否包含 ver；格式錯誤或無法比較回傳 null
  function inPart(sch, v, part) {
    const p = part.trim();
    if (!p) return null;
    const star = p.match(/^([\d.]+)\.\*$/);
    if (star) { const pre = star[1].split('.').map(Number); return pre.every((x, i) => v.nums[i] === x); }
    const rg = p.match(/^(.+?)\s*-\s*(\d.*)$/);
    if (rg) { const lo = parse(sch, rg[1]), hi = parse(sch, rg[2]); const a = cmp(v, lo), b = cmp(v, hi); return a === null || b === null || !lo || !hi ? null : a >= 0 && b <= 0; }
    const conds = p.split(/\s+(?=[<>=])/).filter(Boolean);
    let ok = true;
    for (const c of conds) {
      const m = c.match(/^(<=|>=|<|>|=)?\s*(.+)$/);
      const t = parse(sch, m[2]);
      const r = cmp(v, t);
      if (r === null || !t) return null;
      const op = m[1] || '=';
      ok = ok && (op === '<' ? r < 0 : op === '<=' ? r <= 0 : op === '>' ? r > 0 : op === '>=' ? r >= 0 : r === 0);
    }
    return ok;
  }
  // 回傳 true／false／null（版本或範圍無法判斷）
  function inRange(sch, ver, affected) {
    const v = parse(sch, ver);
    if (!v) return null;
    let unknown = false;
    for (const part of String(affected || '').split(/[;|]/)) {
      if (!part.trim()) continue;
      const r = inPart(sch, v, part);
      if (r === true) return true;
      if (r === null) unknown = true;
    }
    return unknown ? null : false;
  }
  function csvLine(t) {
    const out = []; let cur = '', q = false;
    for (let i = 0; i < t.length; i++) {
      const ch = t[i];
      if (q) { if (ch === '"' && t[i + 1] === '"') { cur += '"'; i++; } else if (ch === '"') q = false; else cur += ch; }
      else if (ch === '"') q = true; else if (ch === ',') { out.push(cur.trim()); cur = ''; } else cur += ch;
    }
    out.push(cur.trim());
    return out;
  }
  // CSV → {entries:[{line, vendor, scheme, product, affected, fixed, cve, severity, kev, note}], errors:[{line, reason}]}；reason：header｜vendor｜affected｜cve
  function parseCsv(text) {
    const entries = [], errors = [];
    let cols = null;
    String(text || '').replace(/^﻿/, '').replace(/\r\n?/g, '\n').split('\n').forEach((raw, i) => {
      const t = raw.trim();
      if (!t || t.startsWith('#')) return;
      const cells = csvLine(t);
      if (!cols) {
        cols = cells.map(c => c.toLowerCase().replace(/\s+/g, '_'));
        if (!['vendor', 'affected', 'cve'].every(k => cols.includes(k))) { errors.push({ line: i + 1, reason: 'header' }); cols = []; }
        return;
      }
      if (!cols.length) return;
      const v = k => { const j = cols.indexOf(k); return j < 0 ? '' : (cells[j] || ''); };
      const sch = scheme(v('vendor'));
      if (!sch) { errors.push({ line: i + 1, reason: 'vendor' }); return; }
      if (!v('affected')) { errors.push({ line: i + 1, reason: 'affected' }); return; }
      if (!v('cve')) { errors.push({ line: i + 1, reason: 'cve' }); return; }
      entries.push({ line: i + 1, vendor: v('vendor'), scheme: sch, product: v('product'), affected: v('affected'), fixed: v('fixed'), cve: v('cve'),
        severity: v('severity'), kev: /^(y|yes|true|1|kev)$/i.test(v('kev')), note: v('note') });
    });
    return { entries, errors };
  }
  // devices：[{name, vendor, version}]；回傳 [{name, vendor, version, scheme, status, hits:[entry], unknown:[entry]}]
  // status：affected（落在至少一筆範圍）｜ok｜unknown（有規則但版本或範圍無法判斷）｜noVersion｜noRules｜unsupported
  function check(devices, entries) {
    return (devices || []).map(d => {
      const sch = deviceScheme(d.vendor, d.version);
      const base = { name: d.name || '', vendor: d.vendor || '', version: d.version || '', scheme: sch, hits: [], unknown: [] };
      if (!sch) return Object.assign(base, { status: 'unsupported' });
      const rules = (entries || []).filter(e => e.scheme === sch);
      if (!rules.length) return Object.assign(base, { status: 'noRules' });
      if (!parse(sch, d.version)) return Object.assign(base, { status: 'noVersion' });
      rules.forEach(e => { const r = inRange(sch, d.version, e.affected); if (r === true) base.hits.push(e); else if (r === null) base.unknown.push(e); });
      return Object.assign(base, { status: base.hits.length ? 'affected' : base.unknown.length ? 'unknown' : 'ok' });
    });
  }
  const CSV_HEADER = 'vendor,product,affected,fixed,cve,severity,kev,note';
  return { scheme, deviceScheme, parse, cmp, inRange, parseCsv, check, SCHEMES, CSV_HEADER };
})();
