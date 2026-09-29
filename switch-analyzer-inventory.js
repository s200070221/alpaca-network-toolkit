// ── 多設備資產清冊（2026-09-29 新增，第六輪 WF） ───────────────────────────
// 一次上傳多份交換器設定，每份各自 parseAny() 後彙整成一張表：主機名稱、廠牌、型號、版本、
// 管理 IP（推測）、NTP、Syslog、SNMP、本機帳號數、Telnet、健康度。純函式、無 DOM 依賴，
// 頂層識別字一律 inv 前綴（多個 classic <script> 共用全域詞法作用域，避免撞名）。

// NTP 伺服器：parseAny() 本身沒有解析系統 NTP，這裡依各家語法逐行擷取（皆為各廠牌常見寫法，
// 行首關鍵字足以區分，不需先判斷廠牌）：
//   ntp server [vrf X] [ip|ipv6] ADDR      Cisco IOS／NX-OS／Arista／Aruba CX／Dell OS10／Ruijie／Alcatel／ProCurve 新版
//   ntp-service [ipv6] unicast-server ADDR  Comware
//   sntp server priority N ADDR             ProCurve 舊版
//   sntp server "ADDR"                      Netgear／EdgeSwitch（ICOS，官方範例帶引號）
//   configure ntp server add ADDR           ExtremeXOS（官方 User Guide NTP Configuration Example）
//   ntp server-name "NAME"                 ArubaOS-Switch（ProCurve）以主機名稱指定
//   set system ntp server ADDR／ntp { server ADDR; }  Junos
//   config system ntp → config ntpserver → set server "ADDR"  FortiSwitch
//   /system ntp client set servers=A,B（v7）或 primary-ntp=A secondary-ntp=B（v6）  RouterOS
//   ntp 區塊內縮排 server ADDR               Brocade／Ruckus ICX（FastIron NTP 設定模式）
//   NTP_SERVER 表格的 key                    SONiC config_db.json
function invParseNTP(cfg) {
  const text = String(cfg || '').replace(/\r\n/g, '\n');
  const out = [];
  const add = v => { const s = String(v || '').replace(/^"|"$/g, '').replace(/;$/, ''); if (s && s !== '0.0.0.0' && !out.includes(s)) out.push(s); };
  const each = (re, fn) => { let m; while ((m = re.exec(text)) !== null) fn(m); };
  each(/^\s*ntp\s+server\s+(?:vrf\s+\S+\s+)?(?:ip\s+|ipv6\s+)?(?!vrf\b)("?[\w.:\-]+"?)/gm, m => add(m[1]));
  each(/^\s*ntp-service\s+(?:ipv6\s+)?unicast-server\s+(?:name\s+)?(\S+)/gm, m => add(m[1]));
  each(/^\s*sntp\s+server\s+priority\s+\d+\s+(\S+)/gm, m => add(m[1]));
  each(/^\s*sntp\s+server\s+(?!priority\b)("?[\w.:\-]+"?)/gm, m => add(m[1]));
  each(/^\s*config(?:ure)?\s+ntp\s+server\s+add\s+(\S+)/gm, m => add(m[1]));
  each(/^\s*ntp\s+server-name\s+("?[^"\s]+"?)/gm, m => add(m[1]));
  each(/^\s*set\s+system\s+ntp\s+server\s+(\S+)/gm, m => add(m[1]));
  each(/^\s*ntp\s*\{([\s\S]*?)^\s*\}/gm, m => { let s; const re = /^\s*server\s+([^\s;{]+)/gm; while ((s = re.exec(m[1])) !== null) add(s[1]); });
  each(/^\s*config\s+ntpserver\b([\s\S]*?)^\s*end\b/gm, m => { let s; const re = /set\s+server\s+"?([^"\s]+)"?/g; while ((s = re.exec(m[1])) !== null) add(s[1]); });
  each(/\/system\s+ntp\s+client\s*\n?\s*set\s+([^\n]+)/gm, m => {
    const sv = m[1].match(/\bservers=(\S+)/); if (sv) sv[1].split(',').forEach(add);
    ['primary-ntp', 'secondary-ntp'].forEach(k => { const x = m[1].match(new RegExp('\\b' + k + '=(\\S+)')); if (x) add(x[1]); });
  });
  each(/^ntp\s*\n((?:[ \t]+[^\n]*\n?)+)/gm, m => { let s; const re = /^\s+server\s+(\S+)/gm; while ((s = re.exec(m[1])) !== null) add(s[1]); });
  if (/^\s*\{/.test(text)) { try { Object.keys(JSON.parse(text).NTP_SERVER || {}).forEach(add); } catch (e) { /* 非 JSON 略過 */ } }
  return out;
}

// 管理 IP（推測）：設定檔沒有「這是管理 IP」的標記，依序取
//   (1) 名稱／描述含 mgmt／manage／oob／管理 的介面 IP
//   (2) 名稱含 mgmt／manage 的 VLAN 對應的 SVI IP
//   (3) 第一個 VLAN 介面（SVI）或 Loopback 的 IP
//   (4) 任一介面 IP
function invIpOf(i) {
  return (String((i && i.ip) || '').match(/^\s*(\d+\.\d+\.\d+\.\d+)/) || [])[1] || '';
}
function invGuessMgmtIP(parsed) {
  const ifs = ((parsed && parsed.interfaces) || []).filter(i => invIpOf(i));
  const MG = /mgmt|manage|oob|管理/i;
  let hit = ifs.find(i => MG.test(i.name || '') || MG.test(i.desc || ''));
  if (hit) return invIpOf(hit);
  const mgVlans = ((parsed && parsed.vlans) || []).filter(v => MG.test(v.name || '')).map(v => String(v.id));
  hit = ifs.find(i => { const m = String(i.name || '').match(/^(?:vlan|vlan-interface|vlanif|ve|irb\.)\s*-?(\d+)$/i); return m && mgVlans.includes(m[1]); });
  if (hit) return invIpOf(hit);
  hit = ifs.find(i => /^(vlan|vlan-interface|vlanif|ve|irb|loopback|lo)/i.test(i.name || '') || i.type === 'loopback' || i.type === 'svi');
  if (hit) return invIpOf(hit);
  return ifs.length ? invIpOf(ifs[0]) : '';
}

function invModel(parsed) {
  const s = (parsed && parsed.sys) || {};
  const host = s.hostname || '';
  for (const v of [s.model, s.platform]) {
    const t = String(v || '').trim();
    if (t && t !== '-' && t !== '—' && !t.startsWith(host)) return t;
  }
  const mem = ((parsed && parsed.stack && parsed.stack.members) || []).find(m => m.model && m.model !== '—' && m.model !== '-');
  return mem ? mem.model : '';
}

// healthFn（選填）：傳入 computeSwitchHealth，測試時可省略
function invBuildRow(fileName, cfg, parsed, healthFn) {
  const s = parsed.sys || {};
  const snmp = parsed.snmp || {};
  const health = healthFn ? healthFn(parsed) : null;
  const ver = String(s.version || '').trim();
  return {
    file: fileName,
    hostname: s.hostname || '',
    vendor: parsed.vendor || '',
    model: invModel(parsed),
    version: ver === '-' || ver === 'all' ? '' : ver,
    mgmtIp: invGuessMgmtIP(parsed),
    ntp: invParseNTP(cfg),
    syslog: ((parsed.syslog && parsed.syslog.servers) || []).map(x => x.host),
    snmpCommunities: (snmp.communities || []).length,
    snmpV3Users: (snmp.v3Users || []).length,
    users: (parsed.users || []).length,
    telnet: !!(parsed.mgmtAccess && parsed.mgmtAccess.telnet),
    vlans: (parsed.vlans || []).length,
    interfaces: (parsed.interfaces || []).length,
    score: health ? health.score : null,
    grade: health ? health.grade : '',
  };
}

// 同名主機（例如同一台的新舊設定）標出來，避免清冊重複計算
function invDuplicateHosts(rows) {
  const cnt = {};
  rows.forEach(r => { const k = (r.hostname || '').toLowerCase(); if (k) cnt[k] = (cnt[k] || 0) + 1; });
  return Object.keys(cnt).filter(k => cnt[k] > 1);
}

// ── 自訂黃金範本規則（2026-09-29 新增，第六輪 WG） ────────────────────────────
// 每行一條規則：
//   + 內容   必須存在（至少一行符合）
//   - 內容   不得存在（任何一行符合即違規）
// 內容一般寫法比對「整行」（去頭尾空白、不分大小寫），可用 * （任意字元）與 ?（單一字元）；
// 以 re: 開頭改用正規表示式（不分大小寫、不自動錨定，需要整行比對請自行加 ^ $）。
// 行尾「 ## 說明」為規則名稱；空行與 # 開頭的註解行略過。
function invParseRules(text) {
  const rules = [];
  const errors = [];
  String(text || '').replace(/\r\n/g, '\n').split('\n').forEach((raw, idx) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const m = line.match(/^([+\-])\s*(.*)$/);
    if (!m || !m[2].trim()) { errors.push({ line: idx + 1, text: line }); return; }
    let body = m[2], label = '';
    const li = body.indexOf(' ## ');
    if (li >= 0) { label = body.slice(li + 4).trim(); body = body.slice(0, li); }
    body = body.trim();
    let re;
    try {
      if (/^re:/i.test(body)) re = new RegExp(body.slice(3).trim(), 'i');
      else re = new RegExp('^' + body.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
    } catch (e) { errors.push({ line: idx + 1, text: line }); return; }
    rules.push({ mode: m[1] === '+' ? 'must' : 'mustNot', pattern: body, label: label || (m[1] + ' ' + body), re });
  });
  return { rules, errors };
}
// 回傳每條規則的結果 {ok, hit}：hit 為第一個符合的設定行（必須存在時是證據，不得存在時是違規行）
function invCheckRules(cfg, rules) {
  const lines = String(cfg || '').replace(/\r\n/g, '\n').split('\n').map(l => l.trim()).filter(Boolean);
  return rules.map(r => {
    const hit = lines.find(l => r.re.test(l)) || '';
    return { ok: r.mode === 'must' ? !!hit : !hit, hit };
  });
}

// ── 跨設備一致性檢查（2026-09-29 新增，第六輪 WH） ───────────────────────────
// entries：[{hostname, parsed}]。只看 IPv4。
//   vlanNames：同一 VLAN ID 在不同設備名稱不一致（空名稱不列入比較，大小寫視為相同）
//   dupIps：同一 IP 出現在兩個以上介面（跨設備或同設備）
//   overlaps：不同設備的介面網段互相包含但前綴長度不同（同網段同長度是正常的多台閘道／VRRP，不列入；/31、/32 略過）
// 「某 VLAN 在相鄰交換器的 trunk 沒放行」需要知道誰接誰（LLDP），多份設定檔本身沒有這個資訊，不在此檢查範圍。
function invParseV4(str) {
  const m = String(str || '').match(/(\d+)\.(\d+)\.(\d+)\.(\d+)(?:[ \t]*\/[ \t]*(\d{1,2})|[ \t]+(\d+\.\d+\.\d+\.\d+))?/);
  if (!m || [m[1], m[2], m[3], m[4]].some(x => +x > 255)) return null;
  const ip = ((+m[1]) * 16777216) + ((+m[2]) << 16 >>> 0) + ((+m[3]) << 8) + (+m[4]);
  let len = m[5] !== undefined ? +m[5] : null;
  if (len === null && m[6]) {
    const mk = m[6].split('.').reduce((a, b) => a * 256 + (+b), 0);
    len = 0; for (let b = 31; b >= 0; b--) { if (Math.floor(mk / 2 ** b) % 2) len++; else break; }
  }
  if (len === null || len > 32) len = 32;
  return { ip, len, text: m[1] + '.' + m[2] + '.' + m[3] + '.' + m[4] };
}
function invDeviceAddrs(parsed) {
  const out = [], seen = new Set();
  const add = (iface, raw) => {
    const a = invParseV4(typeof raw === 'object' && raw ? (raw.cidr || ((raw.ip || '') + ' ' + (raw.mask || ''))) : raw);
    if (!a || a.ip === 0) return;
    const k = iface + '|' + a.text;
    if (seen.has(k)) return;
    seen.add(k); out.push(Object.assign({ iface }, a));
  };
  for (const i of (parsed.interfaces || [])) {
    if (/^\s*\d+\.\d+\.\d+\.\d+/.test(String(i.ip || ''))) add(i.name, i.ip);
    (i.secondaryIps || []).forEach(x => add(i.name, x));
  }
  for (const v of (parsed.vlans || [])) (v.ipSubnets || []).forEach(x => add('VLAN ' + v.id, x));
  return out;
}
function invConsistency(entries) {
  const res = { vlanNames: [], dupIps: [], overlaps: [] };
  // VLAN 名稱
  const byId = {};
  entries.forEach(e => (e.parsed.vlans || []).forEach(v => {
    const name = String(v.name || '').trim();
    if (!name) return;
    const id = String(v.id);
    (byId[id] = byId[id] || {});
    const k = name.toLowerCase();
    (byId[id][k] = byId[id][k] || { name, hosts: [] });
    if (!byId[id][k].hosts.includes(e.hostname)) byId[id][k].hosts.push(e.hostname);
  }));
  Object.keys(byId).sort((a, b) => a - b).forEach(id => { const names = Object.values(byId[id]); if (names.length > 1) res.vlanNames.push({ id, names }); });
  // 重複 IP 與網段重疊
  const all = [];
  entries.forEach(e => invDeviceAddrs(e.parsed).forEach(a => all.push(Object.assign({ host: e.hostname }, a))));
  const byIp = {};
  all.forEach(a => { (byIp[a.text] = byIp[a.text] || []).push(a); });
  Object.keys(byIp).forEach(ip => { if (byIp[ip].length > 1) res.dupIps.push({ ip, where: byIp[ip].map(a => ({ host: a.host, iface: a.iface })) }); });
  const nets = all.filter(a => a.len < 31).map(a => { const size = 2 ** (32 - a.len); return Object.assign({}, a, { net: Math.floor(a.ip / size) * size, size }); });
  const seenPair = new Set();
  for (let i = 0; i < nets.length; i++) for (let j = i + 1; j < nets.length; j++) {
    const a = nets[i], b = nets[j];
    if (a.host === b.host || a.len === b.len) continue;
    const [big, small] = a.len < b.len ? [a, b] : [b, a];
    if (small.net >= big.net && small.net < big.net + big.size) {
      const key = [big.host, big.iface, small.host, small.iface].join('|');
      if (seenPair.has(key)) continue;
      seenPair.add(key);
      res.overlaps.push({ a: { host: big.host, iface: big.iface, cidr: big.text + '/' + big.len }, b: { host: small.host, iface: small.iface, cidr: small.text + '/' + small.len } });
    }
  }
  return res;
}

// ── 帳號與密碼保存方式盤點（2026-09-29 新增，第七輪 AD） ────────────────────
// entries：[{hostname, parsed}]。依各廠牌 parser 已算好的 pwdType／pwdWeak／hasPwd 歸類保存方式，
// 不重新解析密碼字串：
//   plain      明碼（plaintext／simple，或 parser 標為弱且無其他型別）          → 高風險
//   type7      Cisco type 7 等可直接還原的弱加密（type7-weak／encrypted）         → 高風險
//   reversible 廠牌可逆加密（cipher／ciphertext，設備以固定金鑰加密、非雜湊）     → 中風險
//   legacy     MD5 雜湊（可離線暴力破解）                                         → 中風險
//   strong     強雜湊（hash／scrypt／pbkdf2／sha256／sha512／bcrypt）
//   nopwd      未設密碼                                                           → 高風險
//   unknown    設定檔看不出保存方式（如 RouterOS 匯出不含密碼、FortiSwitch ENC）
// 另標示預設帳號名稱與同名帳號出現在多台（可能是共用帳號，稽核常要求個人帳號）。
const ACCT_STRONG=new Set(['hash','scrypt','pbkdf2','sha256','sha512','bcrypt']);
const ACCT_DEFAULT_NAMES=/^(admin|administrator|root|guest|test|cisco|manager|operator|user|support)$/i;
function invAccountStorage(u){
  const t=String(u.pwdType||'').toLowerCase();
  if(u.hasPwd===false||t==='none')return 'nopwd';
  if(t==='plaintext'||t==='simple')return 'plain';
  if(t==='type7-weak'||t==='encrypted')return 'type7';
  if(t==='cipher')return 'reversible';
  if(t==='md5')return 'legacy';
  if(ACCT_STRONG.has(t))return 'strong';
  if(u.pwdWeak===true)return 'plain';
  return 'unknown';
}
const ACCT_RISK={plain:'high',type7:'high',nopwd:'high',reversible:'medium',legacy:'medium',strong:'low',unknown:'low'};
function invAccounts(entries){
  const rows=[];
  (entries||[]).forEach(e=>((e.parsed&&e.parsed.users)||[]).forEach(u=>{
    const name=u.name||u.username||'';
    if(!name)return;
    const storage=invAccountStorage(u);
    rows.push({host:e.hostname,name,role:u.role||u.group||(u.privilege?'privilege-'+u.privilege:''),storage,risk:ACCT_RISK[storage],isDefault:ACCT_DEFAULT_NAMES.test(name)});
  }));
  const hostsByName={};
  rows.forEach(r=>{const k=r.name.toLowerCase();(hostsByName[k]=hostsByName[k]||new Set()).add(r.host);});
  rows.forEach(r=>{r.deviceCount=hostsByName[r.name.toLowerCase()].size;});
  const order={high:0,medium:1,low:2};
  rows.sort((a,b)=>order[a.risk]-order[b.risk]||a.name.localeCompare(b.name)||a.host.localeCompare(b.host));
  const summary={total:rows.length,weak:rows.filter(r=>r.storage==='plain'||r.storage==='type7').length,
    nopwd:rows.filter(r=>r.storage==='nopwd').length,medium:rows.filter(r=>r.risk==='medium').length,
    defaults:rows.filter(r=>r.isDefault).length,shared:new Set(rows.filter(r=>r.deviceCount>1).map(r=>r.name.toLowerCase())).size};
  return {rows,summary};
}
