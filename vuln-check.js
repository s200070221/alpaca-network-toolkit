// ═══════════════════════════════════════════════════════════════════════════
// vuln-check.js — 韌體版本比對已知漏洞（2026-10-24，XN19；防火牆分析與交換器分析共用，主控在 network_analyzer/result）
// 不內建任何廠商漏洞資料：使用者自備 CSV（vendor,product,affected,fixed,cve,severity,kev,note），工具只負責
// 讀出設定檔的韌體版本、依各廠牌版本格式比較是否落在 affected 範圍。純函式、不碰 DOM，以單一全域物件 VulnCheck 對外。
// 版本格式（各取第一個符合的片段，比對時缺少的段視為 0）：
//   fortios 7.2.5（build 不比）、panos 10.2.9-h1、asa 9.18(4)22、ftd 7.2.5.1、junos 21.4R3-S5.3、
//   ios 15.2(7)E8（train 字母不同視為無法比較）、iosxe 17.9.4a、nxos 9.3(10)／10.2(5)M、eos 4.30.2F（train 字母不比）、aoscx 10.11.1020、
//   routeros 7.23.3（beta／rc 視為無法比較）、os10 10.5.6.13（Dell SmartFabric OS10）、
//   sonicos 6.5.4.14-109n／7.0.1-5035（點分補足 4 段＋build，結尾字母不比；範圍的 - 前後須有空白，以免與 build 混淆）
//   bigip 17.1.1.4（F5 BIG-IP，XN106；點分取前 4 段，Build 與工程 hotfix 的後續段不比）
//   netscaler 14.1-43.50（ns.conf 檔頭 #NS14.1 Build 43.50、show version 的 NS14.1: Build 43.50.nc 也接受；train＋build，範圍規則同 sonicos）
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
    [/^(mikrotik|routeros|mikrotik routeros)$/, 'routeros'], [/^(dell ?os10|os10|dell-os10|smartfabric os10)$/, 'os10'],
    [/^(check ?point|gaia|check ?point gaia)$/, 'gaia'], [/^(sonicwall|sonicos|sonicwall sonicos)$/, 'sonicos'],
    [/^(citrix|netscaler|citrix adc|netscaler adc|netscaler gateway|citrix netscaler|netscaler adc and gateway)$/, 'netscaler'],
    [/^(f5|big-?ip|f5 big-?ip|tmos)$/, 'bigip'],
  ];
  const SCHEMES = ['fortios', 'panos', 'asa', 'ftd', 'junos', 'ios', 'iosxe', 'nxos', 'eos', 'aoscx', 'routeros', 'os10', 'gaia', 'sonicos', 'netscaler', 'bigip'];
  function scheme(v) {
    const s = String(v || '').trim().toLowerCase();
    if (SCHEMES.includes(s)) return s;
    const a = ALIASES.find(([re]) => re.test(s));
    return a ? a[1] : '';
  }
  // 設備（防火牆 parsed.vendor 或交換器 vendor 代碼）＋版本字串 → 版本格式；Cisco 交換器依版本寫法分 IOS／IOS-XE
  function deviceScheme(vendor, version) {
    const v = String(vendor || '').trim();
    // Dell OS9（FTOS，9.x）與 OS10 是不同作業系統，交換器 parser 同樣標 dell-os10，OS10 公告不適用（XN58）
    if (v === 'dell-os10' && /^\s*[1-9]\./.test(String(version || ''))) return '';
    const map = { FortiGate: 'fortios', PaloAlto: 'panos', 'Cisco ASA': 'asa', 'Cisco FTD': 'ftd', Juniper: 'junos', juniper: 'junos',
      nxos: 'nxos', arista: 'eos', aruba: 'aoscx', MikroTik: 'routeros', routeros: 'routeros', 'dell-os10': 'os10', CheckPoint: 'gaia', SonicWall: 'sonicos', 'F5 BIG-IP': 'bigip' };
    if (map[v]) return map[v];
    // Cisco IOS／IOS-XE 路由器（防火牆分析 XN139）：設定檔的 version 行只有主次版本（15.7、17.9），16 以上為 IOS-XE，其餘為 IOS（需補填完整版本）
    if (v === 'Cisco IOS') return deviceScheme('cisco', version) || (/^(\d+)\./.test(String(version || '')) && +String(version).match(/^(\d+)/)[1] >= 16 ? 'iosxe' : 'ios');
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
      case 'routeros': m = s.match(/(\d+)\.(\d+)(?:\.(\d+))?(?![\d.]|beta|rc)/i); return m ? { nums: [+m[1], +m[2], +(m[3] || 0)] } : null;
      case 'ftd': case 'eos': case 'aoscx': case 'os10': m = s.match(/\d+(?:\.\d+)+/); return m ? { nums: m[0].split('.').map(Number) } : null;
      // Check Point Gaia（XN42）：train（R81.20）＋選填 Jumbo Hotfix Take；設定檔只有 train，Take 需使用者補填（cpinfo -y all）
      case 'gaia': m = s.match(/^R?(\d+)(?:\.(\d+))?(?:\s*(?:with\s+)?(?:jumbo\s*(?:hotfix)?|jhf|hf)?\s*(?:take|t)?\s*(\d+))?\s*$/i);
        if (!m || (m[3] != null && !/take|jhf|jumbo|\bt\s*\d|hf/i.test(s))) return null;
        return { nums: [+m[1], +(m[2] || 0)], take: m[3] != null ? +m[3] : null };
      // SonicOS（XN26）：Gen5 5.9.2.14-12o、Gen6 6.5.4.14-109n、Gen7 7.0.1-5035；點分補足 4 段再接 build 號，結尾字母（n／o／p）不比
      case 'sonicos': m = s.match(/(\d+(?:\.\d+)+)(?:-(\d+)[a-z]*)?/i);
        if (!m) return null;
        { const d = m[1].split('.').map(Number).slice(0, 4); while (d.length < 4) d.push(0); return { nums: d.concat(+(m[2] || 0)) }; }
      case 'bigip': m = s.match(/\d+(?:\.\d+)+/); return m ? { nums: m[0].split('.').map(Number).slice(0, 4) } : null;
      case 'netscaler': m = s.match(/(\d+)\.(\d+)(?:\s*-\s*|:?\s*build\s*)(\d+)\.(\d+)/i); return m ? { nums: m.slice(1, 5).map(Number) } : null;
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
    // gaia：「R81.10」整個 train 受影響；「R81.20 take<=158」同 train 且 Take 已知才比較，Take 未知回 null
    if (sch === 'gaia') {
      const g = p.match(/^R?(\d+)(?:\.(\d+))?(?:\s+take\s*<=\s*(\d+))?$/i);
      if (!g) return null;
      if (v.nums[0] !== +g[1] || v.nums[1] !== +(g[2] || 0)) return false;
      if (g[3] == null) return true;
      return v.take == null ? null : v.take <= +g[3];
    }
    const star = p.match(/^([\d.]+)\.\*$/);
    if (star) { const pre = star[1].split('.').map(Number); return pre.every((x, i) => v.nums[i] === x); }
    // SonicOS 版本本身含 -build，範圍須寫成「a - b」（前後空白）
    const rg = p.match(sch === 'sonicos' || sch === 'netscaler' ? /^(.+?)\s+-\s+(\d.*)$/ : /^(.+?)\s*-\s*(\d.*)$/);
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
  // 受影響功能是否啟用（XN66）：entry.requires 為功能代號（+ 連接多個條件，全部成立才受影響），features 為 {代號: true|false|null}。
  // 任一條件為 false（設定檔明確未啟用）→ 該筆由 hits 移到 inactive；true／null／未提供者不動。
  // 只有 hits 全部移走時 status 才改為 inactive。回傳新物件，不改動傳入的 result
  function applyFeatures(result, features) {
    if (!result || !features) return result;
    const off = e => String(e.requires || '').split('+').some(k => k && features[k] === false);
    const hits = (result.hits || []).filter(e => !off(e)), inactive = (result.hits || []).filter(off);
    if (!inactive.length) return result;
    return Object.assign({}, result, { hits, inactive, status: hits.length ? result.status : 'inactive' });
  }
  const CSV_HEADER = 'vendor,product,affected,fixed,cve,severity,kev,note';
  // 內建起始清單（vuln-seed.js 載入後掛上 BUILTIN／BUILTIN_ASOF）與使用者 CSV 合併：
  // 內建在前、使用者在後；同一 cve＋scheme 以使用者的為準（可覆蓋或停用內建判斷）。
  // 內建資料會過期，呼叫端須顯示 BUILTIN_ASOF 並提醒自行更新；「未落在範圍」永遠不等於安全。
  function withBuiltin(userEntries) {
    const user = userEntries || [];
    const seen = new Set(user.map(e => (e.cve || '').toUpperCase() + '|' + e.scheme));
    const builtin = (API.BUILTIN || []).filter(e => !seen.has((e.cve || '').toUpperCase() + '|' + e.scheme))
      .map(e => Object.assign({}, e, { builtin: true }));
    return builtin.concat(user);
  }
  // 從 show version 類輸出讀出完整版本（XN141）。句型依 ntc-templates（Apache-2.0）tests 的真實輸出：
  // Cisco IOS／IOS-XE show version、FortiGate get system status、ASA show version、Palo Alto show system info、Junos show version、
  // NX-OS show version、Arista show version、Aruba CX show system、RouterOS /system resource print。
  // ios／iosxe 兩種寫法都試（設定檔的 version 行判斷不出是哪一種），回傳能被該格式解析的版本；讀不出回傳 ''
  const SHOW_VER_RE = {
    iosxe: [/Cisco IOS Software\b[^\n]*?Version\s+(\d+\.\d+\.\d+[a-z]?)\s*[,\n]/, /Cisco IOS XE Software,\s*Version\s+(\d+\.\d+\.\d+[a-z]?)\s*$/m],
    ios: [/Cisco IOS Software\b[^\n]*?Version\s+(\d+\.\d+\(\d+[^)\s]*\)[A-Za-z0-9]*)\s*[,\n]/],
    fortios: [/^Version:\s*\S+\s+v(\d+\.\d+\.\d+)\b/m],
    asa: [/Cisco Adaptive Security Appliance Software Version\s+(\d+\.\d+\(\d+(?:\.\d+)?\)\d*)/],
    panos: [/^\s*sw-version:\s*(\d\S*)/m],
    junos: [/^\s*Junos:\s*(\d\S*)/m],
    nxos: [/NXOS:\s*version\s+(\d+\.\d+\([^)\s]+\)\S*)/, /^\s*system:\s*version\s+(\d+\.\d+\([^)\s]+\)\S*)/m],
    eos: [/Software image version:\s*(\d\S*)/],
    aoscx: [/(?:ArubaOS-CX|AOS-CX) Version\s*:\s*([A-Z]{2}\.\d+(?:\.\d+)+)/],
    routeros: [/^\s*version:\s*(\d+\.\d+(?:\.\d+)?)\s*(?:\(|$)/m],
  };
  // 各格式要執行的指令（卡片說明用；指令本身不翻譯）
  const SHOW_VER_CMDS = { ios: 'show version', iosxe: 'show version', fortios: 'get system status', asa: 'show version', panos: 'show system info',
    junos: 'show version', nxos: 'show version', eos: 'show version', aoscx: 'show system', routeros: '/system resource print' };
  function versionFromText(text, sch) {
    const t = String(text || '').replace(/\r\n?/g, '\n');
    const tries = sch === 'ios' || sch === 'iosxe' ? [sch, sch === 'ios' ? 'iosxe' : 'ios'] : [sch];
    for (const k of tries) for (const re of SHOW_VER_RE[k] || []) {
      const m = t.match(re);
      if (m && parse(k, m[1])) return m[1];
    }
    return '';
  }
  const API = { scheme, deviceScheme, parse, cmp, inRange, parseCsv, check, withBuiltin, applyFeatures, versionFromText, SHOW_VER_SCHEMES: Object.keys(SHOW_VER_RE), SHOW_VER_CMDS, SCHEMES, CSV_HEADER, BUILTIN: [], BUILTIN_ASOF: '' };
  return API;
})();
