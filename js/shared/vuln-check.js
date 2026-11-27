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
//   ivanti 22.7R2.6／25.1.1.3（Ivanti Connect Secure，XN184；R 前後與點分各段依序比較，22.x 與 25.x 編號可直接比大小）
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
    [/^(ivanti|ics|ivanti ics|connect secure|ivanti connect secure|pulse ?secure|pulse connect secure)$/, 'ivanti'],
  ];
  const SCHEMES = ['fortios', 'panos', 'asa', 'ftd', 'junos', 'ios', 'iosxe', 'nxos', 'eos', 'aoscx', 'routeros', 'os10', 'gaia', 'sonicos', 'netscaler', 'bigip', 'ivanti'];
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
      // Ivanti Connect Secure（XN184）：22.7R2.6 → 22,7,2,6；9.1R18 → 9,1,18；25.x 改為純點分 25.1.1.3
      // 只有主次版號（22.7、25.1）視為版本不完整，不可補 0 後比對（會把未寫 R 的版本誤判為受影響）
      case 'ivanti': m = s.match(/(\d+)\.(\d+)R(\d+)(?:\.(\d+))?/i);
        if (m) return { nums: [+m[1], +m[2], +m[3], +(m[4] || 0)] };
        m = s.match(/\d+\.\d+\.\d+(?:\.\d+)?/); return m ? { nums: m[0].split('.').map(Number) } : null;
      case 'netscaler': m = s.match(/(\d+)\.(\d+)(?:\s*-\s*|:?\s*build\s*)(\d+)\.(\d+)/i); return m ? { nums: m.slice(1, 5).map(Number) } : null;
      default: return null;
    }
  }
  // 要比對的設備版本至少要有幾段（點分格式）：只輸入主次版號（FTD 7.2、AOS-CX 10.13）時補 0 比對會誤判為受影響，
  // 視為版本不完整。只套用在設備版本，清單範圍的界值（如 EOS 的 4.30）不受限
  const MIN_PARTS = { ftd: 3, eos: 3, aoscx: 3, os10: 3, bigip: 3 };
  function parseDevice(sch, ver) {
    const v = parse(sch, ver);
    return v && (!MIN_PARTS[sch] || v.nums.length >= MIN_PARTS[sch]) ? v : null;
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
    const v = parseDevice(sch, ver);
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
      if (!parseDevice(sch, d.version)) return Object.assign(base, { status: 'noVersion' });
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
  // 內建情資距今天數（UX37）：asof 為 YYYY-MM-DD，now 可傳 Date 或毫秒（測試用）；日期不合格回傳 null
  function asofAgeDays(asof, now) {
    const m = String(asof || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (!m) return null;
    const t = Date.UTC(+m[1], +m[2] - 1, +m[3]), n = now == null ? Date.now() : +now;
    return isFinite(t) && isFinite(n) ? Math.max(0, Math.floor((n - t) / 86400000)) : null;
  }
  const STALE_DAYS = 30;
  // 記住補填版本（UX38，使用者勾選才寫入 localStorage fw_vuln_ver／sw_vuln_ver）：{主機名稱: {v, ts}}，最多 VER_STORE_MAX 筆
  // 讀入時略過原型污染名稱與不合格內容；主機名稱為空、- 或 unknown 時不記
  const VER_STORE_MAX = 50, VER_OK = /^[\w.()\- ]{1,40}$/;
  // Switch／Router 為 Cisco 出廠預設主機名稱，多台同名，不記也不帶入（RV4）
  const verHostOk = h => typeof h === 'string' && h.length > 0 && h.length <= 128 && !/^(-|unknown|switch|router|__proto__|constructor|prototype)$/i.test(h);
  // 設定檔讀得到的版本（可能只有主次版本，如 FortiGate 7.04）與記住的版本前兩段數字不同時，視為不是同一份韌體，不帶入（RV4）
  function verCompatible(cfgVer, stored) {
    const two = v => (String(v || '').match(/\d+/g) || []).slice(0, 2).map(Number);
    const a = two(cfgVer), b = two(stored);
    return a.length < 2 || b.length < 2 || (a[0] === b[0] && a[1] === b[1]);
  }
  function verStoreParse(text) {
    const out = Object.create(null);
    let o; try { o = JSON.parse(text || '{}'); } catch (e) { return out; }
    if (!o || typeof o !== 'object' || Array.isArray(o)) return out;
    for (const k of Object.keys(o)) {
      const e = o[k];
      if (verHostOk(k) && e && typeof e.v === 'string' && VER_OK.test(e.v)) out[k] = { v: e.v, ts: +e.ts || 0 };
    }
    return out;
  }
  function verStorePut(map, host, v, now) {
    if (!verHostOk(host) || !VER_OK.test(String(v || ''))) return map;
    const all = Object.create(null);
    Object.keys(map || {}).forEach(k => { all[k] = map[k]; });
    all[host] = { v: String(v), ts: now == null ? Date.now() : +now };
    const out = Object.create(null);
    Object.keys(all).sort((a, b) => all[b].ts - all[a].ts).slice(0, VER_STORE_MAX).forEach(k => { out[k] = all[k]; });
    return out;
  }
  const API = { asofAgeDays, STALE_DAYS, verStoreParse, verStorePut, verHostOk, verCompatible, VER_STORE_MAX, scheme, deviceScheme, parse, parseDevice, cmp, inRange, parseCsv, check, withBuiltin, applyFeatures, versionFromText, SHOW_VER_SCHEMES: Object.keys(SHOW_VER_RE), SHOW_VER_CMDS, SCHEMES, CSV_HEADER, BUILTIN: [], BUILTIN_ASOF: '' };
  return API;
})();
