// ============================================================
// [6] 去識別化模組（重用 config_anonymizer 核心引擎邏輯，改配 CEF/Syslog 欄位；
// 詳見 config_anonymizer/result/config-anonymizer.html 的 mappings/anonIP/checkResidual）
// ============================================================
const mappings = { ip: new Map(), hostname: new Map(), user: new Map(), mac: new Map() };
const ctrs = { n1: 0, n2: 0, n3: 0, ip6: 0, dev: 0, usr: 0, mac: 0 };
const anonOutputIPs = new Set();
// 已配發的假主機名稱／假帳號：同一段文字被處理兩次時不再把假值當原值再換一次（對照表不會出現假值→假值）
const fakeNames = new Set();
// 原始 log 中出現過的位址：配發假位址時跳過（原始 log 本身含 192.0.2／198.51.100／203.0.113／2001:db8::N 時，
// 另一個位址可能被配到同一個假值，兩台主機變成同一個位址；同 config_anonymizer 的 srcIPv4／srcIPv6）
const srcIPv4 = new Set(), srcIPv6 = new Set();
// 保留網段結構模式（2026-10-02，第十輪 ZN，與 config_anonymizer 同一套規則各自維護一份）
const subnetMaps = { top: new Map(), topUsed: new Set(), oct3: new Map(), oct3Used: new Set() };
// 結果統計（2026-08-18 新增，比照 config_anonymizer 既有 stats/renderAnonSummary() 慣例）：
// 先前去識別化跑完只能下載結果，畫面上完全看不到「換了幾筆」，補上與 config_anonymizer
// 一致的統計物件，只在「建立新映射」分支計數（cache-hit 重用既有映射不重複計數）
const stats = { ip: 0, hostname: 0, user: 0, mac: 0 };
// 254 位址回捲碰撞偵測（比照 config_anonymizer 既有 bucketSeen 機制搬移，2026-08-19 新增）：
// 各類別 RFC5737 輸出網段僅一個 /24，超過 254 個不同來源 IP 時 ctrs.n1/n2/n3 計數器會回捲
// 並與較早的位址碰撞，不改變既有輸出格式/回捲邏輯，僅用於溢位警告
const bucketSeen = { n1: new Set(), n2: new Set(), n3: new Set() };
// 匯入既有對照表（跨工具聯動，見 config_anonymizer 的對應 applyImportedMappings()，各自
// 維護一份、不跨檔引用）：匯入後的種子存進 IMPORTED_SEED，因為 resetAnonState() 每次執行
// 去識別化前都會清空 mappings，種子必須在每次清空後重新套用才能在同一分頁內存活多次執行
let IMPORTED_SEED = null;
function resetAnonState() {
  mappings.ip.clear(); mappings.hostname.clear(); mappings.user.clear(); mappings.mac.clear();
  anonOutputIPs.clear(); fakeNames.clear();
  Object.values(subnetMaps).forEach(m => m.clear());
  Object.assign(ctrs, { n1: 0, n2: 0, n3: 0, ip6: 0, dev: 0, usr: 0, mac: 0 });
  Object.assign(stats, { ip: 0, hostname: 0, user: 0, mac: 0 });
  Object.keys(bucketSeen).forEach(k => bucketSeen[k].clear());
  if (IMPORTED_SEED) applyImportedMappings(IMPORTED_SEED);
}
// 把匯入 JSON 的 original→mapped 逐筆寫回 mappings，讓 anonIP()/anonHostname()/anonUser()/
// anonMAC() 的 cache-hit 分支直接沿用同一組假值；同時墊高對應計數器，避免之後「新出現」的
// 原始值被分配到與匯入值相撞的假值。只套用「自己也認得」的類別（ip/hostname/user/mac），
// 未知類別（如 config_anonymizer 才有的 ssid/alias/vdom）靜默略過。session 內已存在的原始
// 值不覆蓋（first-seen-wins）。
function applyImportedMappings(parsed) {
  const applied = { ip: 0, hostname: 0, user: 0, mac: 0 };
  let skipped = 0;
  if (!parsed || typeof parsed !== 'object' || !parsed.mappings || typeof parsed.mappings !== 'object') {
    return { applied, skipped };
  }
  // 記住這份種子，讓每次執行去識別化前清空 mappings 後都能重新套用，使匯入在同一分頁內對
  // 多次「執行去識別化」持續生效。2026-08-27 稽核修復：先前是 `IMPORTED_SEED = parsed`
  // 整份直接取代，使用者若連續匯入兩份不同的對照表檔案，第二次匯入會讓 IMPORTED_SEED 整個
  // 換成第二份，resetAnonState() 重新套用時第一份的內容就消失了——因為 anonymizeEvents()
  // 一開始就呼叫 resetAnonState()，這不是「第二次執行才出事」的邊界情況，是匯入兩份後第一次
  // 執行就會直接漏掉第一份。改為累加合併進 IMPORTED_SEED.mappings，同一原始值以先匯入者為準
  // （與下面套用到即時 mappings 的 first-seen-wins 語意一致）
  if (!IMPORTED_SEED) IMPORTED_SEED = { mappings: {} };
  // 對照表檔案可能來自他人：__proto__／constructor／prototype 鍵會取到原型再寫入（原型污染），一律略過
  const badKey = k => k === '__proto__' || k === 'constructor' || k === 'prototype';
  for (const cat of Object.keys(parsed.mappings)) {
    const src = parsed.mappings[cat];
    if (badKey(cat) || !src || typeof src !== 'object') continue;
    if (!IMPORTED_SEED.mappings[cat]) IMPORTED_SEED.mappings[cat] = {};
    const dst = IMPORTED_SEED.mappings[cat];
    for (const k of Object.keys(src)) { if (!badKey(k) && !Object.prototype.hasOwnProperty.call(dst, k)) dst[k] = src[k]; }
  }
  for (const cat of Object.keys(parsed.mappings)) {
    if (!Object.prototype.hasOwnProperty.call(mappings, cat) || !(mappings[cat] instanceof Map)) continue;
    const entries = parsed.mappings[cat];
    if (!entries || typeof entries !== 'object') continue;
    for (const original of Object.keys(entries)) {
      const mapped = entries[original];
      if (typeof mapped !== 'string' || !mapped) { skipped++; continue; }
      if (mappings[cat].has(original)) { skipped++; continue; }

      if (cat === 'ip') {
        let m;
        if ((m = mapped.match(/^192\.0\.2\.(\d+)$/))) ctrs.n1 = Math.max(ctrs.n1, +m[1]);
        else if ((m = mapped.match(/^198\.51\.100\.(\d+)$/))) ctrs.n2 = Math.max(ctrs.n2, +m[1]);
        else if ((m = mapped.match(/^203\.0\.113\.(\d+)$/))) ctrs.n3 = Math.max(ctrs.n3, +m[1]);
        else if ((m = mapped.match(/^2001:db8::(\d+)$/))) ctrs.ip6 = Math.max(ctrs.ip6, +m[1]);
        else if (registerSubnetMapping(original, mapped)) {
          // 對照表來自保留網段結構模式：本工具也改用同一模式，新位址才會落在相同假網段
          const cb = typeof document !== 'undefined' && document.getElementById('deid-preserve-subnet');
          if (cb) cb.checked = true;
        }
        else { skipped++; continue; }
        mappings.ip.set(original, mapped);
        anonOutputIPs.add(mapped);
      } else if (cat === 'mac') {
        const ctr = parseInt(String(mapped).slice(2), 10);
        if (isNaN(ctr)) { skipped++; continue; }
        ctrs.mac = Math.max(ctrs.mac, ctr);
        mappings.mac.set(original, { hex: mapped });
      } else {
        // hostname/user：config_anonymizer 用 "-device-" 前綴、本工具用 "host-"/"user-"，
        // 用通用「取結尾連續數字」正則墊高計數器，不需要寫死特定前綴字面詞
        const m = mapped.match(/(\d+)$/);
        const n = m ? +m[1] : 0;
        if (cat === 'hostname') ctrs.dev = Math.max(ctrs.dev, n);
        else if (cat === 'user') ctrs.usr = Math.max(ctrs.usr, n);
        mappings[cat].set(original, mapped);
        fakeNames.add(mapped);
      }
      applied[cat] = (applied[cat] || 0) + 1;
    }
  }
  return { applied, skipped };
}
const IPV4_SHAPE_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
function isValidIPv4(s) {
  if (!IPV4_SHAPE_RE.test(s)) return false;
  return s.split('.').every(p => +p <= 255);
}
function classifyIP(ip) {
  const [a, b] = ip.split('.').map(Number);
  // 0 開頭（0.0.0.0＝未指定／任意位址，常見於 Palo Alto CSV 的 NAT 欄位、防火牆 any 規則）不是
  // 主機位址，保留原樣；config_anonymizer 同名函式 2026-09-30 已修正，這份副本未同步（2026-10-01）
  if (a === 0 || a === 127 || a >= 224) return 'skip';
  if (a === 10) return 'n2';
  if (a === 172 && b >= 16 && b <= 31) return 'n3';
  if (a === 192 && b === 168) return 'n1';
  return 'n3';
}
// ---- 保留網段結構（2026-10-02，第十輪 ZN，規則與 config_anonymizer 的 anonIPSubnet() 相同）----
// 第 1、2 段整組換成假 /16、第 3 段在同一假 /16 內一對一換掉、第 4 段保留；0／255 原樣保留。
// 假位址放在 241-253 開頭（Class E 保留位址），248／252 為遮罩值不使用
const SUBNET_PUB_FIRST = [244, 245, 246, 247, 249, 250, 251, 253];
const SUBNET_FAKE_RE = /^(?:24[1-7]|249|25[013])\.\d+\.\d+\.\d+$/;
function _octetCandidates(v) { return v === 0 || v === 255 ? [v] : Array.from({ length: 254 }, (_, i) => i + 1); }
let _subnetPubCands = null;
function _subnetAlloc(map, used, key, cands) {
  if (map.has(key)) return map.get(key);
  const v = cands.find(c => !used.has(c));
  if (v === undefined) return null;
  map.set(key, v); used.add(v);
  return v;
}
function anonIPSubnet(ip) {
  const [a, b, c, d] = ip.split('.').map(Number);
  let cands;
  if (a === 10) cands = _octetCandidates(b).map(x => '241.' + x);
  else if (a === 172 && b >= 16 && b <= 31) cands = Array.from({ length: 16 }, (_, i) => '242.' + (16 + i));
  else if (a === 192 && b === 168) cands = ['243.168'];
  else {
    if (!_subnetPubCands) _subnetPubCands = SUBNET_PUB_FIRST.flatMap(f => Array.from({ length: 254 }, (_, i) => f + '.' + (i + 1)));
    cands = _subnetPubCands;
  }
  const top = _subnetAlloc(subnetMaps.top, subnetMaps.topUsed, a + '.' + b, cands);
  if (!top) return null;
  const o3 = _subnetAlloc(subnetMaps.oct3, subnetMaps.oct3Used, top + '|' + c, _octetCandidates(c).map(x => top + '.' + x));
  return o3 ? o3 + '.' + d : null;
}
function registerSubnetMapping(orig, mapped) {
  if (!isValidIPv4(orig) || !SUBNET_FAKE_RE.test(mapped)) return false;
  const [a, b, c] = orig.split('.').map(Number);
  const [x, y, z] = mapped.split('.');
  const top = x + '.' + y, k = a + '.' + b;
  if (!subnetMaps.top.has(k)) { subnetMaps.top.set(k, top); subnetMaps.topUsed.add(top); }
  if (subnetMaps.top.get(k) === top && !subnetMaps.oct3.has(top + '|' + c)) {
    subnetMaps.oct3.set(top + '|' + c, top + '.' + z); subnetMaps.oct3Used.add(top + '.' + z);
  }
  return true;
}
// opts.preserveLastOctet（2026-08-20 新增，移植自 config_anonymizer 既有邏輯）：開啟後不同
// 子網但末位相同的 IP 會被映射成相同的假 IP（保留末段方便交叉比對同一台主機在不同網段的紀錄）
function anonIP(ip, opts) {
  const hit = mappings.ip.get(ip);
  if (hit !== undefined) return hit;
  if (!isValidIPv4(ip)) return ip;
  const cls = classifyIP(ip);
  if (cls === 'skip') return ip;
  if (anonOutputIPs.has(ip)) return ip;
  const sub = opts && opts.preserveSubnet ? anonIPSubnet(ip) : null;
  if (sub) {
    mappings.ip.set(ip, sub);
    anonOutputIPs.add(sub);
    stats.ip++;
    return sub;
  }
  bucketSeen[cls].add(ip);
  const lastPart = opts && opts.preserveLastOctet ? Number(ip.split('.')[3]) : null;
  let mapped;
  const pre = cls === 'n1' ? '192.0.2.' : cls === 'n2' ? '198.51.100.' : '203.0.113.';
  // 保留末段時若假位址剛好是原檔已有的位址，改用一般配發（否則兩台主機變成同一個位址）
  if (lastPart != null && !srcIPv4.has(pre + lastPart)) mapped = pre + lastPart;
  else for (let i = 0; i < 254; i++) { ctrs[cls] = (ctrs[cls] % 254) + 1; mapped = pre + ctrs[cls]; if (!srcIPv4.has(mapped)) break; }
  mappings.ip.set(ip, mapped);
  anonOutputIPs.add(mapped);
  stats.ip++;
  return mapped;
}
function anonHostname(name) {
  if (!name || !String(name).trim()) return name;
  const key = String(name).trim();
  if (mappings.hostname.has(key)) return mappings.hostname.get(key);
  if (fakeNames.has(key)) return name;
  ctrs.dev++;
  const mapped = `host-${String(ctrs.dev).padStart(3, '0')}`;
  mappings.hostname.set(key, mapped);
  fakeNames.add(mapped);
  stats.hostname++;
  return mapped;
}
function anonUser(name) {
  if (!name || !String(name).trim()) return name;
  const key = String(name).trim();
  if (mappings.user.has(key)) return mappings.user.get(key);
  if (fakeNames.has(key)) return name;
  ctrs.usr++;
  const mapped = `user-${String(ctrs.usr).padStart(3, '0')}`;
  mappings.user.set(key, mapped);
  fakeNames.add(mapped);
  stats.user++;
  return mapped;
}
function formatMAC(hex, original) {
  const bytes = hex.match(/.{2}/g);
  if (/\./.test(original)) return bytes.join('').match(/.{4}/g).join('.');
  if (/-/.test(original)) return bytes.join('-');
  if (/^[0-9a-f]{12}$/i.test(original)) return bytes.join('');
  return bytes.join(':');
}
function anonMAC(mac) {
  const norm = mac.replace(/[:.-]/g, '').toLowerCase();
  if (mappings.mac.has(norm)) return formatMAC(mappings.mac.get(norm).hex, mac);
  ctrs.mac++;
  const hex = '02' + String(ctrs.mac).padStart(10, '0').slice(-10);
  mappings.mac.set(norm, { hex });
  stats.mac++;
  return formatMAC(hex, mac);
}
// 前後不可接數字或「.數字」（版本號、OID 不當成位址），但句尾的句點可以（Azure Firewall 的 to 10.0.3.4. Action:）
const IPv4_RE = /(?<!\d|\d\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d|\.\d)/g;
// 2026-08-09 稽核修復：去識別化模組先前完全沒有 IPv6 支援，真實 IPv6 位址在自由文字 msg
// 中會原樣殘留；比照 config_anonymizer 已有的 IPv6_RE/anonIPv6() 邏輯移植（ctrs.ip6 計數器
// 早已存在於上方 ctrs 物件定義，先前只是缺對應的正則與函式，形同虛設）
// 2026-08-09 稽核修復（移植自 config_anonymizer 後實測發現）：原本開頭排除的
// `(?<![:\w])` 連 ":" 都排除，導致真實常見的「介面名稱:IP」格式（如 Cisco ASA
// deny log 的 "src outside:2001:db8::1/443"，冒號直接緊鄰位址前）完全匹配不到——
// IPv6 位址前一個字元剛好也是冒號時被誤判為「這是某個更長序列的中段」而跳過整個
// 位址。改為只排除英數字元 `(?<!\w)`，MAC 位址的排除交由呼叫端既有的 MAC_SHAPE_RE
// 判斷式負責（MAC 固定 6 組 2 碼、不含 "::" 縮寫，本身就不會被此正則的形狀比對命中，
// 不依賴這個 lookbehind）。IPv6_RE/MAC_SHAPE_RE 定義已搬到檔案上方（IP_RE_G 旁），
// 供情資比對/掃描偵測的候選 IP 擷取共用，此處沿用同一份不重複定義
// IPv6 正規化（2026-09-29 QB）：同一位址的不同寫法（大小寫、省略前導零、:: 縮寫與否）轉成
// 8 組小寫、去前導零的標準形式；無法解析（含 IPv4 內嵌等）時回傳 null，維持原本逐字比對
function canonIPv6(ip) {
  const s = String(ip).toLowerCase();
  if (!/^[0-9a-f:]+$/.test(s) || (s.match(/::/g) || []).length > 1) return null;
  let parts;
  if (s.includes('::')) {
    const [a, b] = s.split('::');
    const head = a ? a.split(':') : [], tail = b ? b.split(':') : [];
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    parts = [...head, ...Array(fill).fill('0'), ...tail];
  } else parts = s.split(':');
  if (parts.length !== 8 || parts.some(p => !/^[0-9a-f]{1,4}$/.test(p))) return null;
  return parts.map(p => p.replace(/^0+(?=.)/, '')).join(':');
}
function anonIPv6(ip) {
  if (mappings.ip.has(ip)) return mappings.ip.get(ip);
  // 已配發的假值不再換一次（同一段文字被處理兩次時 2001:db8::1 會再被換成 ::2）
  if (anonOutputIPs.has(String(ip).toLowerCase())) return ip;
  // 映射表裡已有同一位址的其他寫法時沿用同一個假值（不新增狀態，匯入的對照表種子與批次共用映射也適用）
  const c = canonIPv6(ip);
  if (c) {
    for (const [k, v] of mappings.ip) {
      if (k.includes(':') && canonIPv6(k) === c) { mappings.ip.set(ip, v); return v; }
    }
  }
  let mapped;
  for (let i = 0; i < 1000; i++) { ctrs.ip6++; mapped = `2001:db8::${ctrs.ip6}`; if (!srcIPv6.has(mapped)) break; }
  mappings.ip.set(ip, mapped);
  anonOutputIPs.add(mapped);
  stats.ip++;
  return mapped;
}
const MAC_COLON_RE = /\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/g;
const MAC_HYPHEN_RE = /\b([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b/g;
const MAC_DOT_RE = /\b([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b/g;
// 會被替換的 IPv6 至少 4 組（有 :: 或連續 3 組「十六進位:」），其餘行略過整段 IPv6 正則（第二十八輪 OP3）
const IPV6_HINT_RE = /::|(?:[0-9a-fA-F]{1,4}:){3}/;
function replaceIPsInLine(line, opts) {
  // ::ffff:IPv4 映射位址：IPv4 部分與一般 IPv4 用同一對照（否則 IPv6 正則只吃到 ::ffff:10，剩下的 .1.2.3 又被另外替換）
  const mapped = [];
  line = line.replace(/(?<![0-9A-Fa-f:])::ffff:(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/gi, (m, v4) => { mapped.push(v4); return '\u0000' + (mapped.length - 1) + '\u0000'; });
  if (IPV6_HINT_RE.test(line)) line = line.replace(IPv6_RE, m => (m.split(':').length >= 4 && !MAC_SHAPE_RE.test(m) ? anonIPv6(m) : m));
  line = line.replace(IPv4_RE, m => (isValidIPv4(m) && classifyIP(m) !== 'skip' ? anonIP(m, opts) : m));
  return mapped.length ? line.replace(/\u0000(\d+)\u0000/g, (m, i) => '::ffff:' + (isValidIPv4(mapped[i]) && classifyIP(mapped[i]) !== 'skip' ? anonIP(mapped[i], opts) : mapped[i])) : line;
}
function replaceMACsInLine(line) {
  return line.replace(MAC_COLON_RE, m => anonMAC(m)).replace(MAC_HYPHEN_RE, m => anonMAC(m)).replace(MAC_DOT_RE, m => anonMAC(m));
}
// email（含網址編碼的 %40）換假帳號
const EMAIL_ANON_RE = /[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
function anonEmails(text) {
  return String(text).replace(EMAIL_ANON_RE, m => anonUser(m));
}
// Windows 使用者資料夾 \Users\帳號\ 換假帳號（Public／Default 等內建資料夾保留）
function anonWinUserPaths(text) {
  return String(text).replace(/(\\Users\\)([^\\]+)/gi, (m, p, u) => /^(?:Public|Default|Default User|All Users)$/i.test(u) ? m : p + anonUser(u));
}
// 自由文字通用替換：IP、MAC、email、使用者資料夾（欄位語意不明時的最低處理）
function anonFreeText(text, opts) {
  return anonWinUserPaths(anonEmails(replaceMACsInLine(replaceIPsInLine(String(text), opts))));
}
const CEF_SENSITIVE_KEYS = ['src', 'dst', 'shost', 'dhost', 'dvchost', 'suser', 'duser', 'sourceUserName', 'destinationUserName'];
// CEF／LEEF 共用：帳號類與主機類欄位（含 LEEF 的 accountName／identHostName／devName），其餘欄位一律做通用替換
const CEFLEEF_USER_KEYS = new Set(['suser', 'duser', 'suid', 'duid', 'sourceUserName', 'destinationUserName', 'sourceUserId', 'destinationUserId', 'accountName', 'usrName']);
const CEFLEEF_HOST_KEYS = new Set(['shost', 'dhost', 'dvchost', 'sourceHostName', 'destinationHostName', 'deviceHostName', 'identHostName', 'devName']);
// ipKeys：值必須是位址的欄位，不是合法 IPv4（如 IPv6）時一律 REDACTED；網址欄位的主機名稱以 DNS 名稱對照替換
function anonCefLeefFields(f, ipKeys, opts) {
  Object.keys(f).forEach(k => {
    const v = f[k];
    if (v === undefined || v === null || v === '') return;
    if (ipKeys.includes(k)) f[k] = isValidIPv4(String(v)) ? anonIP(String(v), opts) : 'REDACTED';
    else if (CEFLEEF_USER_KEYS.has(k)) f[k] = anonUser(v);
    else if (CEFLEEF_HOST_KEYS.has(k)) f[k] = anonHostname(v);
    else {
      let x = anonFreeText(v, opts);
      if (k === 'request' || k === 'url') x = x.replace(/^([a-z][\w+.-]*:\/\/)([^\/:?#\s]+)/i, (m, p, h) => p + (isValidIPv4(h) ? h : anonDnsName(h)));
      f[k] = x;
    }
  });
}
// parseCEFLine() 用 unescapeCEF() 把 header 欄位裡跳脫過的 \| \\ 還原成原始字元存進物件，
// 重建行時需要反向操作，否則 header 值裡若含未跳脫的 | 會讓後面欄位全部錯位
function escapeCEFHeader(v) {
  return String(v == null ? '' : v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}
function rebuildCEFLine(evt) {
  const ext = Object.entries(evt.fields).map(([k, v]) => `${k}=${String(v).replace(/\\/g, '\\\\').replace(/=/g, '\\=')}`).join(' ');
  const h = escapeCEFHeader;
  return `CEF:${h(evt.version || '0')}|${h(evt.deviceVendor || '')}|${h(evt.deviceProduct || '')}|${h(evt.deviceVersion || '')}|${h(evt.sigId || '')}|${h(evt.msg || '')}|${h(evt.severityRaw || '')}|${ext}`;
}
// LEEF 官方預先定義的欄位裡，src/dst/srcPreNAT/dstPreNAT/srcPostNAT/dstPostNAT 皆為 IP 位址型別，
// usrName 為使用者名稱型別，去識別化邏輯依型別分流（非逐一硬寫死判斷式）
const LEEF_SENSITIVE_KEYS = ['src', 'dst', 'srcPreNAT', 'dstPreNAT', 'srcPostNAT', 'dstPostNAT', 'usrName'];
function rebuildLEEFLine(evt) {
  const delimChar = /^2/.test(evt.version || '') ? resolveLEEFDelimiter(evt.delimiterRaw) : '\t';
  const ext = Object.entries(evt.fields).map(([k, v]) => `${k}=${v}`).join(delimChar);
  const header = [`LEEF:${evt.version || '1.0'}`, evt.vendor || '', evt.product || '', evt.productVersion || '', evt.eventId || ''];
  if (/^2/.test(evt.version || '')) header.push(evt.delimiterRaw || '');
  return header.join('|') + '|' + ext;
}
// FortiOS 欄位型別分類：只涵蓋直接識別使用者/裝置身分的 IP／主機名稱／MAC 三類，範圍刻意排除
// policyname/vd/srcssid/policyid 等策略與組態中繼資料，比照既有 CEF_SENSITIVE_KEYS 只處理
// IP/host/user 的既定窄範圍，不擴大成 config_anonymizer 那種連物件名稱都去識別化的做法
const FORTIGATE_IP_KEYS = ['srcip', 'dstip', 'ip', 'transip'];
const FORTIGATE_HOST_KEYS = ['srcname', 'hostname'];
const FORTIGATE_MAC_KEYS = ['mac', 'srcmac', 'mastersrcmac'];
// 帳號欄位（FortiOS Log Message Reference：user／unauthuser）與管理介面來源 ui（如 GUI(10.1.1.5)）
// 原本未去識別化，設定變更與已認證流量 log 的帳號、管理 IP 會外洩（2026-09-29 WD 發現）
const FORTIGATE_USER_KEYS = ['user', 'unauthuser'];
// 依 parseFortiGateKV() 記錄的原始欄位順序與引號樣式原樣重建，維持 FortiOS 原生 log 語法
// （數字欄位通常裸寫、字串欄位通常加雙引號），去識別化後的檔案才能繼續被其他工具當一般
// FortiOS log 讀取；fieldOrder/fieldsQuoted 缺失時（理論上不會，僅防禦）退回既有 key 順序
function rebuildFortiGateLine(evt) {
  const order = evt.fieldOrder || Object.keys(evt.fields || {});
  const quoted = evt.fieldsQuoted || new Set();
  return order.map(k => {
    const v = evt.fields[k] === undefined ? '' : String(evt.fields[k]);
    if (quoted.has(k) || /[\s"]/.test(v)) return `${k}="${v.replace(/"/g, '\\"')}"`;
    return `${k}=${v}`;
  }).join(' ');
}
// SD-PARAM 的原始 SD-ID 名稱（如 "origin"、"exampleSDID@32473"）在 parseStructuredData()
// 階段已被攤平捨棄、只留參數 key=value，故重建時無法還原原始 SD-ID，改用固定佔位 "sdid"；
// 重建的重點是不讓已去識別化的參數值整段消失，非逐字還原原始 SD 語法
function rebuildStructuredData(fields) {
  const keys = Object.keys(fields || {});
  if (!keys.length) return '-';
  const params = keys.map(k => `${k}="${String(fields[k]).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(' ');
  return `[sdid ${params}]`;
}
// Windows Event Log 去識別化後重建 raw XML：不追求逐字還原原始屬性順序/命名空間宣告細節，
// 產出一份結構有效、內容已去識別化的 <Event> 片段（供下載/複製結果使用）
const WINEVENT_SYSTEM_KEYS = ['EventID', 'Level', 'Channel', 'Computer', 'EventRecordID', 'Provider'];
function rebuildWinEventXML(evt) {
  const f = evt.fields || {};
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  let xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>';
  xml += `<Provider Name="${esc(f.Provider || '')}"/><EventID>${esc(f.EventID || '')}</EventID><Level>${esc(f.Level || '')}</Level>`;
  xml += `<TimeCreated SystemTime="${esc(evt.timestampRaw || '')}"/><EventRecordID>${esc(f.EventRecordID || '')}</EventRecordID>`;
  xml += `<Channel>${esc(f.Channel || '')}</Channel><Computer>${esc(evt.host || '')}</Computer></System><EventData>`;
  Object.keys(f).forEach(k => {
    if (WINEVENT_SYSTEM_KEYS.includes(k) || k === 'srcip' || k === 'failCode' || k === 'failReason' || k === 'failKind') return; // srcip 是解析階段新增的別名鏡射欄位，非原始 Data，不重複輸出
    xml += `<Data Name="${esc(k)}">${esc(f[k])}</Data>`;
  });
  xml += '</EventData></Event>';
  return xml;
}
// RFC3164 TAG 重建：原始 "sshd[812]:" 的 PID 先前重建時被丟掉（QC）
function syslogTag(evt) {
  return evt.appName ? `${evt.appName}${evt.procid ? '[' + evt.procid + ']' : ''}: ` : '';
}
function rebuildSyslogRaw(evt) {
  if (evt.format === 'pancsv') return evt.msg || '';
  if (evt.format === 'ciscoios' || evt.format === 'vpnauth' || evt.format === 'haproxy') return `${evt.rawPrefix || ''}${evt.msg || ''}`;
  if (evt.format === 'comware') return `${evt.rawHead || ''}${evt.host} ${evt.rawTag || ''}${evt.msg || ''}`;
  if (evt.format === 'mikrotik') {
    const pri = evt.facility === null ? '' : `<${evt.facility * 8 + Number(evt.severityRaw || 0)}>`;
    return `${pri}${evt.timestampRaw ? evt.timestampRaw + ' ' : ''}${evt.msg || ''}`;
  }
  // 原本就沒有 PRI 的 rfc3164 事件（facility===null 是解析階段留下的判斷依據，見
  // parseRFC3164Line）重建時同樣不帶 PRI，避免無中生有塞入假造的 <0>
  if (evt.format === 'rfc3164' && evt.facility === null) {
    return `${evt.timestampRaw || ''} ${evt.host ? evt.host + ' ' : ''}${syslogTag(evt)}${evt.msg || ''}`;
  }
  const priBase = (evt.facility || 0) * 8 + Number(evt.severityRaw || 0);
  if (evt.format === 'rfc5424') {
    const sdFields = evt.sdKeys ? Object.fromEntries(evt.sdKeys.filter(k => evt.fields && evt.fields[k] !== undefined).map(k => [k, evt.fields[k]])) : evt.fields;
    return `<${priBase}>1 ${evt.timestampRaw || '-'} ${evt.host || '-'} ${evt.appName || '-'} ${evt.procid || '-'} ${evt.msgid || '-'} ${rebuildStructuredData(sdFields)} ${evt.msg || ''}`;
  }
  // 原始沒有主機名稱（如 pfSense 遠端 syslog）時不輸出多餘空白
  return `<${priBase}>${evt.timestampRaw || ''} ${evt.host ? evt.host + ' ' : ''}${syslogTag(evt)}${evt.msg || ''}`;
}
// JSON log 沒有 CEF 的固定 extension key 名單，借用 [2] JSON 匯入用的別名表（SRC_IP_KEYS/
// DST_IP_KEYS/HOST_KEYS/MSG_KEYS）逐一比對 clone.fields 實際存在的 key 做去識別化；
// JSON_USER_KEYS 為此模組專屬（其餘別名表無使用者欄位概念，故未定義於別名表附近）
const JSON_USER_KEYS = ['user', 'username', 'user_name', 'userName', 'account', 'accountName', 'user.name'];
// 巢狀物件／陣列：產生新的副本（不改到原始事件），帳號物件（如 user:{name}）內的名稱類字串換假帳號，
// 主機類鍵換假主機名稱，其餘字串一律通用替換；不會把整個物件交給 anonUser()
const JSON_NESTED_USER_SUBKEYS = /^(?:name|full_name|email|id|account|login)$/i;
function anonJsonNested(v, k, opts, inUser) {
  if (Array.isArray(v)) return v.map(x => anonJsonNested(x, k, opts, inUser));
  if (v && typeof v === 'object') {
    const o = {};
    const u = inUser || JSON_USER_KEYS.includes(k);
    Object.keys(v).forEach(c => { o[c] = anonJsonNested(v[c], c, opts, u); });
    return o;
  }
  if (typeof v !== 'string' || !v) return v;
  if (JSON_USER_KEYS.includes(k) || (inUser && JSON_NESTED_USER_SUBKEYS.test(k))) return anonUser(v);
  if (HOST_KEYS.includes(k)) return isValidIPv4(v) ? anonIP(v, opts) : anonHostname(v);
  return anonFreeText(v, opts);
}
function anonymizeJSONFields(fields, opts) {
  Object.keys(fields).forEach(k => {
    const v = fields[k];
    if (v === undefined || v === null) return;
    if (typeof v === 'object') { fields[k] = anonJsonNested(v, k, opts, false); return; }
    // key 本身已被歸類為 IP 型別欄位（如 srcip）但值不是合法 IPv4（如 IPv6）時，不可原樣放行，
    // 一律 REDACTED（比照 CEF 分支既有的 fallback 邏輯），避免看似已去識別化實際仍外洩
    if (SRC_IP_KEYS.includes(k) || DST_IP_KEYS.includes(k)) fields[k] = isValidIPv4(String(v)) ? anonIP(String(v), opts) : 'REDACTED';
    else if (HOST_KEYS.includes(k)) fields[k] = anonHostname(v);
    else if (JSON_USER_KEYS.includes(k)) fields[k] = anonUser(v);
    // 其餘字串欄位（含 message 類）一律通用替換：nat_ip、peer、email 等未列名的欄位也不留原值
    else if (typeof v === 'string') fields[k] = anonFreeText(v, opts);
  });
  return fields;
}
// 廠牌 log 拆出的欄位（MikroTik／pfSense／Palo Alto，見 parseMikroTikMsg()／parseVendorCSVFields()）：
// IP／MAC 欄位與 msg 同步去識別化；帳號在 msg 中的位置固定——MikroTik 為 login failure for user X／
// user X logged in，Palo Alto 為 CSV 第 12、13 欄（來源／目的使用者）——一併替換。
// ipsDone=true 表示呼叫端已對全部欄位做過通用 IP 替換（rfc5424 分支），避免重複映射
function anonymizeNetFields(clone, opts, ipsDone) {
  const f = clone.fields;
  if (!ipsDone) {
    ['srcip', 'dstip', 'natsrcip', 'natdstip'].forEach(k => { if (f[k]) f[k] = isValidIPv4(f[k]) ? anonIP(f[k], opts) : 'REDACTED'; });
    if (f.srcmac) f.srcmac = anonMAC(f.srcmac);
  }
  // netfilter：msg 的 MAC= 已在通用替換前處理（見 anonNetfilterMac()），這裡只換拆出的 MAC 欄位
  if (clone.netVendor === 'netfilter') {
    if (f.dstmac) f.dstmac = anonMAC(f.dstmac);
    if (ipsDone && f.srcmac) f.srcmac = anonMAC(f.srcmac);
    return;
  }
  if (clone.netVendor === 'paloalto') {
    const cols = splitCSVSimple(clone.msg || '');
    // 帳號欄位依類型：TRAFFIC／THREAT 12、13；GLOBALPROTECT 12（另 14 為電腦名稱）；USERID 9（第十五輪 VC）
    const lt = cols[3], hip = /^HIP-?MATCH$/.test(lt || '');
    const userCols = lt === 'USERID' ? [9] : (lt === 'GLOBALPROTECT' ? [12] : (hip ? [7] : (lt === 'CONFIG' ? [10] : [12, 13])));
    userCols.forEach(i => { if (cols[i]) cols[i] = anonUser(cols[i]); });
    // CONFIG 路徑為管理者帳號（mgt-config users <帳號>，XN41）：路徑、變更前後內容中的帳號一併替換
    const pm = lt === 'CONFIG' && String(cols[13] || '').match(/(?:^|\s)mgt-config\s+users\s+(\S+)/);
    if (pm) {
      const o = pm[1], a = anonUser(o), re = new RegExp('(^|[^\\w.-])' + o.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![\\w-])', 'g');
      [13, 14, 15].forEach(i => { if (cols[i]) cols[i] = cols[i].replace(re, '$1' + a); });
      if (f.cfgpath) f.cfgpath = String(f.cfgpath).replace(re, '$1' + a);
    }
    // 電腦名稱與設備名稱欄（Beats 欄位對照：TRAFFIC 52、THREAT 59、GLOBALPROTECT 14／33、USERID 25、HIPMATCH 9／24）
    const machineCol = lt === 'GLOBALPROTECT' ? 14 : (hip ? 9 : -1);
    if (machineCol >= 0 && cols[machineCol]) { cols[machineCol] = anonHostname(cols[machineCol]); if (f.machine) f.machine = cols[machineCol]; }
    const devCol = { TRAFFIC: 52, THREAT: 59, GLOBALPROTECT: 33, USERID: 25 }[lt] || (hip ? 24 : -1);
    if (devCol >= 0 && cols[devCol]) { cols[devCol] = anonHostname(cols[devCol]); if (f.devname) f.devname = cols[devCol]; }
    if (f.user) f.user = cols[userCols[0]];
    if (lt === 'THREAT' && f.url !== undefined) f.url = cols[31];
    clone.msg = cols.map(v => /[",]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v).join(',');
    return;
  }
  if (f.user) {
    const u = anonUser(f.user);
    clone.msg = (clone.msg || '').replace(/(\blogin failure for user )(\S+)( from )/, `$1${u}$3`)
      .replace(/(\buser )(\S+)( logged (?:in|out) from )/, `$1${u}$3`);
    f.user = u;
  }
  // Juniper RT_FLOW 結構化紀錄：SD 段的 username 重建時會寫回，換成同一個假帳號
  if (clone.netVendor === 'junos' && f.username && f.user) f.username = f.user;
}
// 訊息內的帳號（2026-09-29 QC）：OpenSSH／PAM 固定語法中的帳號位置，與訊息內 user=／ruser=／
// username= 鍵值；先前 rfc3164/rfc5424/asa 只替換 IP/MAC，帳號以明碼留在去識別化結果。
// 只比對固定語法，不猜測任意單字是否為帳號
const MSG_USER_PATTERNS = [
  /(\bFailed \S+ for (?:invalid user )?)(\S+)(?= from )/g,
  /(\bAccepted \S+ for )(\S+)(?= from )/g,
  /(\bInvalid user )(\S+)(?= from )/g,
  /(\b(?:Disconnected from|Connection closed by|Received disconnect from|Connection reset by) (?:invalid |authenticating )?user )(\S+)(?= )/g,
  /(\bsession (?:opened|closed) for user )([^\s(]+)/g,
  /(\b(?:user|ruser|username)=)([^\s;,]+)/g,
  // 設定變更記錄的帳號（WD）：Cisco CONFIG_I（by 後為 vty／console 等線路名稱時不是帳號，不替換）、
  // Comware SHELL_CMD 的 -User=、Juniper UI_COMMIT、MikroTik「changed by」
  /(\bConfigured from \S+ by )(?!(?:vty\d+|console|con\d+|tty\d+|aux\d*)\b)(\S+)/g,
  /(-User=)([^;\-*][^;]*)(?=;)/g,
  /(\bUser ')([^']+)(?=' requested)/g,
  /(\bUser ')([^']+)(?=',? (?:running|executed)\b)/g,
  // Cisco ASA 認證訊息（第二十輪 FB）：for user "X"、Uname: X、user = X、User <X>
  /(\bfor user ")(?!\*+")([^"]+)/g,
  /(\bUname: )(\S+)/g,
  // ASA 502101 的操作者、Cisco IOS archive log config 的 CFGLOG_LOGGEDCMD（操作者與 username 指令的帳號；XN35）
  /(\bExecutor: )(\S+)/g,
  /(\bUser:)(?!unknown user\b)([^\s:]+)(?=\s+logged command:)/g,
  /(\blogged command:(?:!config:\s*)?username\s+)(\S+)/g,
  /(\buser = )(?!\*+)([^\s:,]+)/gi,
  /(\bUser <)([^>]+)(?=>)/g,
  /(\b(?:added|changed|moved|removed) by )(\S+)$/g,
  // Firepower 事件的 `User: 帳號,`（No Authentication Required／Unknown 等系統值不換；第十六輪 PD）
  /((?:^|,\s*)User:\s+)(?!No Authentication Required\b|Unknown\b|Not Found\b)([^,]+?)(?=,|$)/g,
];
function anonUsersInMsg(msg) {
  let out = msg || '';
  MSG_USER_PATTERNS.forEach(re => { out = out.replace(re, (m, pre, u) => pre + anonUser(u)); });
  return out;
}
// Web 存取 log 去識別化：整行 IP／MAC 通用替換，帳號欄位依位置替換（Apache/nginx 第 3 欄 %u；
// IIS 依 #Fields 的 cs-username 欄），IIS 的 s-computername 改為假主機名。網址 query 內的參數值
// （可能含 token／email）不在處理範圍，已知限制
function anonymizeWebEvent(clone, opts) {
  const f = clone.fields;
  ['srcip', 'dstip'].forEach(k => { if (f[k]) f[k] = replaceIPsInLine(f[k], opts); });
  // 網址、查詢字串與 Referer 內的 email（含 %40 編碼）換假帳號
  let raw = anonEmails(replaceMACsInLine(replaceIPsInLine(clone.raw, opts)));
  Object.keys(f).forEach(k => { if (typeof f[k] === 'string' && f[k].length > 3) f[k] = anonEmails(f[k]); });
  // Referer 網址的主機名稱：內部網域換假名（公開網域由 anonDnsName 保留）
  const refHost = (String(f.referer || '').match(/^[a-z][\w+.-]*:\/\/([^\/:?#\s"]+)/i) || [])[1];
  if (refHost && !isValidIPv4(refHost)) {
    const n = anonDnsName(refHost);
    if (n !== refHost) { raw = raw.split('://' + refHost).join('://' + n); f.referer = f.referer.split('://' + refHost).join('://' + n); }
  }
  // Origin／Host 標頭（XN78）的主機名稱同樣換假名，兩者換成同一組假值，比對結果不變
  [['origin', urlHostOf(f.origin)], ['vhost', String(f.vhost || '').replace(/:\d+$/, '')]].forEach(([k, h]) => {
    if (!h || isValidIPv4(h)) return;
    const n = anonDnsName(h);
    if (n !== h) { raw = raw.split(h).join(n); f[k] = String(f[k]).split(h).join(n); }
  });
  // ELB：負載平衡器名稱與 ARN 內的帳號 ID、資源名稱（第十六輪 PH）
  if (f.elb) {
    if (clone.host) { const h = anonHostname(clone.host); raw = raw.split(clone.host).join(h); clone.host = h; }
    raw = raw.replace(/(arn:aws[\w-]*:[\w-]*:[\w-]*:)(\d{12})(:)/g, (m, p, id, c) => p + anonHostname(id) + c)
      .replace(/(:(?:targetgroup|certificate|loadbalancer\/(?:app|net))\/)([^\/\s"]+)/g, (m, p, n) => p + anonHostname(n));
  }
  // S3 存取紀錄（第二十輪 FF）：擁有者正規 ID、儲存貯體換假名，要求者 ARN 的帳號 ID 與使用者／角色工作階段名稱換掉，再重拆欄位
  if (f.s3) {
    const m = raw.match(S3_ACCESS_RE);
    if (m) {
      // 正規 ID 換成同樣 64 位十六進位的假值（對照編號補在 f 之後），去識別化後仍可再解析
      const fakeId = id => { const n = (anonHostname(id).match(/\d+$/) || ['0'])[0]; return ('f'.repeat(64) + n).slice(-64); };
      const owner = m[1] === '-' ? '-' : fakeId(m[1]), bucket = anonHostname(m[2]);
      let rq = m[10];
      if (/^[0-9a-f]{64}$/.test(rq)) rq = fakeId(rq);
      else rq = rq.replace(/^(arn:aws[\w-]*:[\w-]*:[\w-]*:)(\d+)(:)/, (x, a, id, c) => a + anonHostname(id) + c)
        .replace(/(:(?:user|assumed-role\/[^\/\s]+)\/)([^\/\s]+)$/, (x, a, n) => a + anonUser(n))
        .replace(/(:assumed-role\/)([^\/\s]+)(?=\/)/, (x, a, n) => a + anonHostname(n));
      // 依位置重組：擁有者、儲存貯體、[時間] 遠端 IP 不動、要求者換掉，其後原樣（URI 中的 /儲存貯體 一併換）
      const head = `${owner} ${bucket} [${m[3]}/${m[4]}/${m[5]}:${m[6]} ${m[7]}${m[8]}] ${m[9]} ${rq} `;
      const tail = raw.slice(raw.indexOf(' ' + m[11] + ' ') + 1).split(m[2]).join(bucket);
      raw = head + tail;
      const ev = parseS3AccessLine(raw, clone.lineNo);
      if (ev) { clone.fields = ev.fields; clone.host = ev.host; clone.msg = ev.msg; }
    }
    clone.raw = raw;
    return;
  }
  if (f.winfw !== undefined) {
    const ev = winFwEvent(clone.w3cCols, raw, clone.lineNo, clone.winfwUtc);
    if (ev) { clone.fields = ev.fields; clone.msg = ev.msg; }
    clone.raw = raw;
    return;
  }
  // Squid：帳號欄換假帳號、網址內的非公開網域以主機名稱對照替換（同 DNS），再重拆欄位
  if (f.squid) {
    const parts = raw.split(/(\s+)/);
    const tok = parts.filter((x, i) => i % 2 === 0);
    if (tok[7] && tok[7] !== '-') tok[7] = anonUser(tok[7]);
    if (tok[6]) tok[6] = tok[6].replace(/^((?:[a-z][\w+.-]*:\/\/)?)([^\/:\s]+)/i, (m, p, h) => p + (isValidIPv4(h) ? h : anonDnsName(h)));
    // 階層欄（HIER_DIRECT/主機、FIRSTUP_PARENT/上層 proxy）在 log_ip_on_direct off 或 cache peer 時是主機名稱
    if (tok[8]) tok[8] = tok[8].replace(/^([A-Z_]+\/)(.+)$/, (m, p, h) => p + (h === '-' || isValidIPv4(h) || /^[0-9A-Fa-f:]+$/.test(h) ? h : anonDnsName(h)));
    raw = parts.map((x, i) => i % 2 === 0 ? tok[i / 2] : x).join('');
    const ev = parseSquidLine(raw, clone.lineNo);
    if (ev) { clone.fields = ev.fields; clone.msg = ev.msg; }
    clone.raw = raw;
    return;
  }
  if (clone.format === 'weblog') {
    if (f.user) { f.user = anonUser(f.user); raw = raw.replace(/^(\S+ \S+ )\S+(?= \[)/, `$1${f.user}`); }
  } else {
    const parts = raw.split(' ');
    const ui = clone.w3cCols.indexOf('cs-username'), hi = clone.w3cCols.indexOf('s-computername');
    if (f.user && ui >= 0) { f.user = anonUser(f.user); parts[ui] = f.user; f['cs-username'] = f.user; }
    if (hi >= 0 && parts[hi] !== '-') { clone.host = anonHostname(parts[hi]); parts[hi] = clone.host; f['s-computername'] = clone.host; }
    ['c-ip', 's-ip'].forEach(k => { const i = clone.w3cCols.indexOf(k); if (i >= 0) f[k] = parts[i]; });
    raw = parts.join(' ');
  }
  clone.raw = raw;
  clone.msg = replaceIPsInLine(clone.msg || '', opts);
}
// netfilter 核心 LOG 的 MAC= 是目的 MAC、來源 MAC 與 EtherType 連寫成一串（見 parseNetfilterLog()），
// 通用 MAC 比對只換得到前 6 段，剩下的會被 IPv6 比對誤當位址，須在通用替換之前逐段處理
function anonNetfilterMac(msg) {
  return String(msg || '').replace(/\bMAC=((?:[0-9a-fA-F]{2}:){11}[0-9a-fA-F]{2})((?::[0-9a-fA-F]{2})*)/, (m, macs, tail) => {
    const h = macs.split(':');
    return 'MAC=' + anonMAC(h.slice(0, 6).join(':')) + ':' + anonMAC(h.slice(6, 12).join(':')) + tail;
  });
}
// Syslog 內的 JSON 訊息（第十九輪 ED）：帳號類鍵換假帳號、主機類鍵換假名，其餘字串換 IP／MAC，
// 重新序列化成訊息（保留 @cee: 前綴）並重拆欄位；RFC5424 結構化資料段的欄位保留
const JSON_MSG_USER_KEYS = new Set(['user', 'username', 'user_name', 'userid', 'user_id', 'account', 'accountname', 'issuer', 'src_user', 'login', 'sourceuser', 'targetuser', 'targetusername', 'email']);
const JSON_MSG_HOST_KEYS = new Set(['host', 'hostname', 'computer', 'computername', 'device', 'devicename', 'machine']);
function anonJsonMsg(clone, opts) {
  const lead = (String(clone.msg || '').match(/^\s*(?:@cee:\s*)?/) || [''])[0];
  const r = parseJsonInMsg(clone.msg);
  if (!r) { clone.msg = anonUsersInMsg(replaceMACsInLine(replaceIPsInLine(clone.msg || '', opts))); return; }
  const walk = o => Object.keys(o).forEach(k => {
    const v = o[k];
    if (v && typeof v === 'object') walk(v);
    else if (typeof v === 'string' && v) {
      const lk = k.toLowerCase();
      o[k] = JSON_MSG_USER_KEYS.has(lk) ? anonUser(v) : JSON_MSG_HOST_KEYS.has(lk) ? anonHostname(v) : anonUsersInMsg(replaceMACsInLine(replaceIPsInLine(v, opts)));
    }
  });
  walk(r.obj);
  clone.msg = lead + JSON.stringify(r.obj);
  const keep = {};
  (clone.sdKeys || []).forEach(k => { if (clone.fields[k] !== undefined) keep[k] = clone.fields[k]; });
  clone.fields = Object.assign(jsonMsgFields(r.obj), keep);
}
// DNS 查詢紀錄去識別化（第二十一輪 GA）：查詢名稱以主機名稱對照替換（反解名稱 in-addr.arpa 內含位址，一併替換；
// 常見公開網域保留），用戶端位址走既有 IP 替換，之後由去識別化後的文字重新拆欄位
const DNS_PUBLIC_RE = /(?:^|\.)(?:google\.com|googleapis\.com|gstatic\.com|microsoft\.com|windows\.com|windowsupdate\.com|office\.com|office365\.com|apple\.com|icloud\.com|amazonaws\.com|cloudflare\.com|akamaiedge\.net|akamai\.net|ntp\.org|example\.(?:com|net|org))$/i;
const DNS_NAME_TOKEN_RE = /(?<![\w.@-])((?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})\.)+[A-Za-z][A-Za-z0-9-]{1,62}\.?)(?![\w-])/g;
function anonDnsName(n) {
  const t = dnsName(n);
  if (!t || DNS_PUBLIC_RE.test(t)) return n;
  return anonHostname(t.toLowerCase()) + (String(n).endsWith('.') ? '.' : '');
}
function anonDnsText(text) {
  return String(text || '')
    .replace(/(?:\(\d+\)[^\s()]+)+\(0\)/g, m => encodeWinDnsName(anonDnsName(decodeWinDnsName(m))))
    .replace(DNS_NAME_TOKEN_RE, m => anonDnsName(m));
}
function anonymizeDnsEvent(clone, opts) {
  if (clone.format === 'dns') {
    const line = clone.dnsWrap ? String(clone.dnsWrap.obj[clone.dnsWrap.key]).trim() : clone.raw;
    const anonLine = replaceIPsInLine(anonDnsText(line), opts);
    const re = parseDnsServerLine(anonLine, clone.lineNo);
    if (re) { clone.fields = re.fields; clone.msg = re.msg; }
    if (clone.dnsWrap) {
      const o = { ...clone.dnsWrap.obj, [clone.dnsWrap.key]: anonLine };
      clone.raw = replaceIPsInLine(JSON.stringify(o), opts);
      delete clone.dnsWrap;
    } else clone.raw = anonLine;
    return;
  }
  // syslog 外殼（named[pid]:／dnsmasq[pid]:）
  if (clone.host) clone.host = anonHostname(clone.host);
  const sd = {};
  (clone.sdKeys || []).forEach(k => { if (clone.fields[k] !== undefined) sd[k] = replaceIPsInLine(String(clone.fields[k]), opts); });
  clone.msg = replaceMACsInLine(replaceIPsInLine(anonDnsText(clone.msg), opts));
  const re = parseDnsInMsg(clone.appName, clone.msg);
  const linked = clone.fields.srcip;
  clone.fields = { ...sd, ...(re ? re.fields : {}) };
  // dnsmasq 回應行的用戶端是由前一筆查詢補上的（訊息本身沒有），沿用同一組對照
  if (!clone.fields.srcip && linked) clone.fields.srcip = replaceIPsInLine(String(linked), opts);
  clone.raw = rebuildSyslogRaw(clone);
}
// DHCP 租約紀錄去識別化（第二十一輪 GC）：位址、MAC（Windows 為 12 位十六進位，維持原格式）、主機名稱與帳號替換後重新拆欄位
function anonymizeDhcpEvent(clone, opts) {
  if (clone.format === 'dhcp') {
    const c = clone.raw.split(',');
    if (c[4]) c[4] = replaceIPsInLine(c[4], opts);
    if (c[5]) c[5] = anonHostname(c[5]);
    if (/^[0-9a-fA-F]{12}$/.test(c[6] || '')) { const a = anonMAC(c[6]).replace(/:/g, ''); c[6] = c[6] === c[6].toUpperCase() ? a.toUpperCase() : a; }
    else if (c[6]) c[6] = replaceMACsInLine(c[6]);
    if (c[7]) c[7] = anonUser(c[7]);
    const line = replaceMACsInLine(replaceIPsInLine(c.join(','), opts));
    const re = parseWinDhcpLine(line, clone.lineNo);
    if (re) { clone.fields = re.fields; clone.msg = re.msg; }
    clone.raw = line;
    return;
  }
  if (clone.host) clone.host = anonHostname(clone.host);
  const sd = {};
  (clone.sdKeys || []).forEach(k => { if (clone.fields[k] !== undefined) sd[k] = replaceIPsInLine(String(clone.fields[k]), opts); });
  let msg = clone.msg || '';
  const h = clone.fields.dhcpHost;
  if (h) msg = msg.replace(new RegExp('([( ])' + h.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?=\\)|\\s*$)'), (m, p) => p + anonHostname(h));
  clone.msg = replaceMACsInLine(replaceIPsInLine(msg, opts));
  const re = parseDhcpInMsg(clone.appName, clone.msg);
  clone.fields = { ...sd, ...(re ? re.fields : {}) };
  clone.raw = rebuildSyslogRaw(clone);
}
// Cisco ISE 去識別化（第二十一輪 GE）：帳號類鍵換假帳號（值為 MAC 時交給 MAC 替換）、設備與節點名稱換主機名稱對照、
// AcsSessionID 開頭的 ISE 節點名稱一併替換，位址與 MAC 走既有替換後重新拆欄位
const ISE_USER_KEYS = new Set(['UserName', 'User-Name', 'OriginalUserName', 'AdminName', 'GuestUserName', 'Identity']);
const ISE_HOST_KEYS = new Set(['NetworkDeviceName', 'PsnHostName', 'Hostname']);
function anonymizeIseEvent(clone, opts) {
  if (clone.host) clone.host = anonHostname(clone.host);
  const sd = {};
  (clone.sdKeys || []).forEach(k => { if (clone.fields[k] !== undefined) sd[k] = replaceIPsInLine(String(clone.fields[k]), opts); });
  const msg = String(clone.msg || '').replace(/((?:^|,\s*)([A-Za-z][\w .-]*?)=)([^,]*)/g, (m, lead, k, v) => {
    if (!v.trim()) return m;
    if (ISE_USER_KEYS.has(k) && !/^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$/.test(v.trim())) return lead + anonUser(v.trim());
    if (ISE_HOST_KEYS.has(k)) return lead + anonHostname(v.trim());
    if (k === 'AcsSessionID') return lead + v.replace(/^[^/]+/, h => anonHostname(h));
    return m;
  });
  clone.msg = replaceMACsInLine(replaceIPsInLine(msg, opts));
  const re = parseIseMsg(clone.msg);
  const ts = clone.timestamp;
  clone.fields = { ...sd, ...(re ? re.fields : {}) };
  clone.timestamp = ts;
  clone.raw = rebuildSyslogRaw(clone);
}
// sshd／sudo 去識別化（第二十二輪 HB）：訊息中的帳號（含 PWD 路徑內）換假帳號、金鑰指紋遮蔽、位址替換後重新拆欄位
function anonymizeSshEvent(clone, opts) {
  if (clone.host) clone.host = anonHostname(clone.host);
  const sd = {};
  (clone.sdKeys || []).forEach(k => { if (clone.fields[k] !== undefined) sd[k] = replaceIPsInLine(String(clone.fields[k]), opts); });
  // 金鑰指紋：同一把金鑰換成同一個假值（XN80），跨來源使用的判斷在去識別化後仍成立
  let msg = String(clone.msg || '').replace(/( ssh2: \S+ )((?:SHA256|MD5):)?(.+)$/, (m, p, pre, fp) => p + (pre || 'SHA256:') + 'REDACTED-' + anonHostname(fp));
  [...new Set([clone.fields.user, clone.fields.runAs].filter(Boolean))].forEach(u => {
    msg = msg.replace(new RegExp('(^|[^\\w.-])' + u.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![\\w-])', 'g'), '$1' + anonUser(u));
  });
  clone.msg = replaceMACsInLine(replaceIPsInLine(msg, opts));
  const re = parseSshdMsg(clone.appName, clone.msg);
  clone.fields = { ...sd, ...(re ? re.fields : {}) };
  clone.raw = rebuildSyslogRaw(clone);
}
// OpenVPN／strongSwan／FreeRADIUS 去識別化（第二十三輪 IA～IC）：帳號、憑證名稱與 IKE ID 換假帳號，RADIUS 記錄的密碼一律遮蔽、
// 用戶端名稱換假主機名稱，位址與 MAC 替換後重新拆欄位；跨行互補帶入的位址（指派位址、對端位址）比照替換
function anonymizeVpnAuthEvent(clone, opts) {
  const f0 = clone.fields;
  if (clone.host) clone.host = anonHostname(clone.host);
  const sd = {};
  (clone.sdKeys || []).forEach(k => { if (f0[k] !== undefined) sd[k] = replaceIPsInLine(String(f0[k]), opts); });
  let msg = String(clone.msg || '');
  if (f0.radius) {
    msg = msg.replace(/: \[(.*?)\] \(from client (\S+) /, (x, who, cl) => {
      const i = who.indexOf('/', /^host\//i.test(who) ? 5 : 0);
      const u = i >= 0 ? who.slice(0, i) : who;
      return `: [${u ? anonUser(u) : ''}${i >= 0 ? '/REDACTED_PASSWORD' : ''}] (from client ${anonHostname(cl)} `;
    }).replace(/\(from client ([^)\s]+)\)/, (x, cl) => `(from client ${isValidIPv4(cl) ? cl : anonHostname(cl)})`);
  } else {
    [...new Set([f0.user, f0.cn, f0.localId, f0.authId].filter(Boolean))].sort((a, b) => b.length - a.length).forEach(u => {
      msg = msg.replace(new RegExp('(^|[^\\w.@-])' + u.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![\\w@-])', 'g'), '$1' + anonUser(u));
    });
    // 憑證主體（OpenVPN VERIFY OK／ERROR、strongSwan DN 形式的 ID）中的 CN 也換假帳號
    msg = msg.replace(/\bCN=([^,/\s\]']+)/g, (x, v) => 'CN=' + anonUser(v));
    // strongSwan 的「位址[IKE ID]」：未拆出欄位的行（looking for peer configs matching …）也要換；ID 為位址或 %any 時留給位址替換
    msg = msg.replace(/(\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)\[([^\]\s]+)\]/g, (m, ip, id) =>
      ip + '[' + (isValidIPv4(id) || /^[0-9A-Fa-f:]+$/.test(id) || id === '%any' || /^(?:C|CN|O|OU)=/.test(id) ? id : id.includes('@') || !id.includes('.') ? anonUser(id) : anonHostname(id)) + ']');
  }
  clone.msg = replaceMACsInLine(replaceIPsInLine(msg, opts));
  if (f0.radius) clone.msg = clone.msg.replace(/( cli )([0-9A-Fa-f]{12})\b/, (m, p, x) => p + anonMAC(x));
  const re = parseVpnAuthMsg(clone.appName, clone.msg);
  clone.fields = { ...sd, ...(re ? re.fields : {}) };
  ['assignIp', 'srcip', 'srcport'].forEach(k => { if (f0[k] && !clone.fields[k]) clone.fields[k] = replaceIPsInLine(String(f0[k]), opts); });
  clone.raw = rebuildSyslogRaw(clone);
}
// HAProxy 去識別化（第二十三輪 IE）：伺服器名稱換假主機名稱、擷取的標頭中非公開網域以主機名稱對照替換（同 DNS），位址替換後重拆欄位
function anonymizeHaproxyEvent(clone, opts) {
  if (clone.host) clone.host = anonHostname(clone.host);
  let msg = String(clone.msg || '').replace(/^(\S+ \[[^\]]+\] \S+ [^\s/]+\/)(\S+)/, (m, p, sv) => p + (/^<NOSRV>$/.test(sv) ? sv : anonHostname(sv)))
    .replace(/\{([^}]*)\}/g, (m, v) => '{' + v.split('|').map(x => /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d+)?$/.test(x) && !isValidIPv4(x.replace(/:\d+$/, '')) ? x.replace(/^[^:]+/, h => anonDnsName(h)) : x).join('|') + '}');
  // 自訂格式的目的主機欄（非位址時）比照 DNS 以主機名稱對照替換
  const dh = clone.fields.dsthost;
  if (dh) msg = msg.replace(new RegExp('(\\] \\S+ [^\\s/]+\\/\\S+ )' + dh.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ' '), '$1' + anonDnsName(dh) + ' ');
  clone.msg = replaceIPsInLine(msg, opts);
  const re = parseHaproxyMsg(clone.appName, clone.msg);
  clone.fields = re ? re.fields : {};
  clone.raw = rebuildSyslogRaw(clone);
}
// Cloudflare Logpush（第二十六輪 SE）：深拷貝後換 IP；網域類欄位以主機名稱對照替換，Referer 換網址的主機、路徑與查詢字串只換 IP，
// Cookie 與請求／回應標頭的值一律遮蔽
function anonymizeCloudflareEvent(clone, opts) {
  const a = JSON.parse(JSON.stringify(clone.cfRaw));
  const walk = (o, secret) => Object.keys(o).forEach(k => { const v = o[k];
    if (v && typeof v === 'object') { walk(v, secret || /^(?:Cookies|RequestHeaders|ResponseHeaders)$/.test(k)); return; }
    if (typeof v !== 'string' || !v) return;
    let x;
    if (secret) x = 'REDACTED';
    else if (/(?:Host|ZoneName)$/.test(k)) x = isValidIPv4(v) ? replaceIPsInLine(v, opts) : anonDnsName(v);
    else if (/Referer$/.test(k)) x = replaceIPsInLine(v, opts).replace(/^([a-z][\w+.-]*:\/\/)([^\/:?#]+)/i, (m, p, h) => p + (isValidIPv4(h) ? h : anonDnsName(h)));
    else if (/(?:URI|Path|Query)$/.test(k)) x = replaceIPsInLine(v, opts);
    else x = replaceMACsInLine(replaceIPsInLine(v, opts));
    o[k] = x; });
  walk(a, false);
  const ev = cloudflareEvent(a, clone.lineNo);
  Object.assign(clone, { cfRaw: a, fields: ev.fields, msg: ev.msg, raw: ev.raw, host: ev.host });
  return clone;
}
// F5 Telemetry（XN119）：深拷貝後逐欄處理：主機名稱類欄位換主機名稱對照、帳號欄換假帳號、原始請求只留請求行與 Host（Cookie、Authorization
// 等標頭與內容遮蔽），其他字串換位址、MAC、Email；工作階段編號保留
const F5TS_HOST_KEYS = /^(?:hostname|http_host|dest_fqdn|source_fqdn|route_domain|translated_route_domain|ip_address_intelligence)$/;
const F5TS_USER_KEYS = /^(?:username|user|source_user|Username|User_Name)$/;
function anonymizeF5tsEvent(clone, opts) {
  const a = JSON.parse(JSON.stringify(clone.f5Raw));
  Object.keys(a).forEach(k => {
    const v = a[k];
    if (typeof v !== 'string' || !f5na(v)) return;
    if (F5TS_HOST_KEYS.test(k)) a[k] = replaceIPsInLine(v, opts).replace(/^[^:\s]+/, h => isValidIPv4(h) ? h : anonDnsName(h));
    else if (F5TS_USER_KEYS.test(k)) a[k] = anonUser(v);
    else if (k === 'request') {
      const lines = v.split(/\r?\n/);
      a[k] = lines.map((l, i) => i === 0 ? replaceIPsInLine(l, opts) : /^Host:/i.test(l) ? 'Host: ' + l.replace(/^Host:\s*/i, '').replace(/^[^:\s]+/, h => isValidIPv4(h) ? replaceIPsInLine(h, opts) : anonDnsName(h)) : (l.trim() ? l.replace(/:.*$/, ': REDACTED') : l)).join('\r\n');
    } else if (/^(?:session_id|Session_Id|Session_ID|support_id|flow_id)$/.test(k)) return;
    else a[k] = anonFreeText(v, opts);
  });
  const ev = f5tsEvent(a, clone.lineNo);
  Object.assign(clone, { f5Raw: a, fields: ev.fields, msg: ev.msg, raw: ev.raw, host: ev.host });
  return clone;
}
// ModSecurity（XN118）：深拷貝後換位址；Host 標頭換主機名稱；Cookie、Set-Cookie、Authorization 標頭與回應內容遮蔽；
// 請求路徑只換位址（同 weblog），規則訊息換位址、Email
const MODSEC_SECRET_HDR = /^(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key)$/i;
function anonymizeModsecEvent(clone, opts) {
  const a = JSON.parse(JSON.stringify(clone.modsecRaw));
  const walk = (o, key) => Object.keys(o).forEach(k => {
    const v = o[k];
    if (v && typeof v === 'object') { walk(v, k); return; }
    if (typeof v !== 'string' || !v) return;
    if (key === 'headers' && MODSEC_SECRET_HDR.test(k)) o[k] = 'REDACTED';
    else if (key === 'headers' && /^host$/i.test(k)) o[k] = replaceIPsInLine(v, opts).replace(/^[^:\s]+/, h => isValidIPv4(h) ? h : anonDnsName(h));
    else if (/^(?:body|response_body)$/.test(k)) o[k] = 'REDACTED';
    else o[k] = anonFreeText(v, opts);
  });
  walk(a, '');
  const ev = modsecEvent(a, clone.lineNo);
  Object.assign(clone, { modsecRaw: a, fields: ev.fields, msg: ev.msg, raw: ev.raw });
  return clone;
}
// Vault 稽核（XN117）：深拷貝後換來源位址；帳號（display_name、metadata 的 username／email／account_id、登入路徑最後一段）換假帳號；
// 路徑保留掛載點、sys／auth 與 data／metadata 等固定段，其餘段以主機名稱對照換成同一組假值（機密名稱數量不變）；
// hmac 值不處理，其他字串換位址、MAC、Email
const VAULT_KEEP_SEG = /^(?:data|metadata|login|sys|auth|token|policy|policies|audit|mounts|generate-root|lookup-self|capabilities-self|config|roles?|issue|creds|users?|groups?)$/;
function anonVaultPath(p) {
  const seg = String(p || '').split('/');
  if (seg[0] === 'sys') return p;
  return seg.map((x, i) => i === 0 || !x || VAULT_KEEP_SEG.test(x) ? x : (seg[0] === 'auth' && seg[i - 1] === 'login' ? anonUser(x) : anonHostname(x))).join('/');
}
function anonymizeVaultEvent(clone, opts) {
  const a = JSON.parse(JSON.stringify(clone.vaultRaw));
  const walk = (o, key) => Object.keys(o).forEach(k => {
    const v = o[k];
    if (v && typeof v === 'object') { walk(v, k); return; }
    if (typeof v !== 'string' || !v || /^hmac-sha256:/.test(v)) return;
    if (k === 'remote_address') o[k] = replaceIPsInLine(v, opts);
    else if (k === 'display_name' || (key === 'metadata' && /^(?:username|email|account_id|name|role_name|service_account_name)$/.test(k))) o[k] = /^(?:root|token)$/.test(v) ? v : anonUser(v);
    else if (k === 'path') o[k] = anonVaultPath(v);
    else o[k] = anonFreeText(v, opts);
  });
  walk(a, '');
  const ev = vaultEvent(a, clone.lineNo);
  Object.assign(clone, { vaultRaw: a, fields: ev.fields, msg: ev.msg, raw: ev.raw });
  return clone;
}
// Zscaler NSS（XN113）：深拷貝 event 後逐欄處理再重建。帳號欄（可為 %40 編碼）換假帳號、主機名稱欄以主機名稱對照替換，
// 網址欄（含 base64 的 b64url／b64referer）換主機部分，組織與檔名類欄位一律遮蔽；其餘字串換位址、MAC、Email
const ZS_USER_KEYS = new Set(['login', 'user', 'adminid', 'deviceowner']);
const ZS_HOST_KEYS = new Set(['host', 'devicehostname', 'devicename', 'cltdomain', 'dns_req', 'dns_resp', 'df_hosthead', 'df_hostname', 'ehost']);
const ZS_URL_KEYS = new Set(['url', 'eurl', 'referer', 'ereferer', 'refererhost', 'b64url', 'b64referer']);
const ZS_REDACT_KEYS = new Set(['company', 'department', 'dept', 'location', 'locationname', 'loc', 'filename', 'upload_filename', 'fileName', 'devicemodel']);
function anonZsUrl(v, opts) {
  return replaceIPsInLine(String(v), opts).replace(/^((?:[a-z][\w+.-]*:\/\/)?)([^\/:?#\s]+)/i, (m, p, h) => p + (isValidIPv4(h) ? h : anonDnsName(h)));
}
function anonymizeZscalerEvent(clone, opts) {
  const a = JSON.parse(JSON.stringify(clone.zsRaw));
  const walk = o => Object.keys(o).forEach(k => {
    const v = o[k];
    if (v && typeof v === 'object') { walk(v); return; }
    if (typeof v !== 'string' || !zsVal(v)) return;
    if (ZS_USER_KEYS.has(k)) { let u = v; try { u = decodeURIComponent(v); } catch (e) { /* 原樣 */ } o[k] = isValidIPv4(u) ? anonIP(u, opts) : anonUser(u); }
    else if (ZS_REDACT_KEYS.has(k)) o[k] = 'REDACTED';
    else if (ZS_HOST_KEYS.has(k)) o[k] = isValidIPv4(v) || v.includes(':') && /^[0-9a-f:.]+$/i.test(v) ? replaceIPsInLine(v, opts) : anonDnsName(v);
    else if (ZS_URL_KEYS.has(k)) {
      if (/^b64/.test(k)) { try { o[k] = btoa(anonZsUrl(atob(v), opts)); } catch (e) { o[k] = 'REDACTED'; } }
      else if (k === 'eurl') { let u = v; try { u = decodeURIComponent(v); } catch (e) { /* 原樣 */ } o[k] = encodeURIComponent(anonZsUrl(u, opts)); }
      else o[k] = anonZsUrl(v, opts);
    } else o[k] = anonFreeText(v, opts);
  });
  walk(a.event);
  const ev = zscalerEvent(a, clone.lineNo);
  Object.assign(clone, { zsRaw: a, fields: ev.fields, msg: ev.msg, raw: ev.raw });
  return clone;
}
// Windows 事件去識別化（第三十一輪審查修正）：位址保留 -、LOCAL 與 ::ffff: 前綴；帳號 - 與內建帳號保留，電腦帳號（$ 結尾、
// 可帶 @領域）依主機短名對照、MSOL_ 前綴保留；主機名稱與網域以第一段（大寫）對照，FQDN 與短名、電腦帳號換完仍對得上
const WIN_BUILTIN_DOMAIN_RE = /^(?:NT AUTHORITY|NT SERVICE|BUILTIN|Window Manager|Font Driver Host|WORKGROUP|-)$/i;
function anonWinAddr(v, opts) {
  if (/^(?:-|LOCAL|::1|localhost)$/i.test(v)) return v;
  if (isValidIPv4(v)) return anonIP(v, opts);
  if (/^(?:::ffff:)?[0-9A-Fa-f:.]+$/i.test(v) && v.includes(':')) return replaceIPsInLine(v, opts);
  return 'REDACTED';
}
function anonWinHost(name) {
  const v = String(name || '').trim();
  if (!v || v === '-' || isValidIPv4(v)) return name;
  const i = v.indexOf('.');
  const short = anonHostname((i >= 0 ? v.slice(0, i) : v).toUpperCase());
  return i >= 0 ? short + '.' + anonDnsName(v.slice(i + 1)) : short;
}
function anonWinDomain(v) {
  if (!v || WIN_BUILTIN_DOMAIN_RE.test(v)) return v;
  const i = v.indexOf('.');
  const first = anonHostname((i >= 0 ? v.slice(0, i) : v).toUpperCase());
  return i >= 0 ? first + '.' + anonDnsName(v.slice(i + 1)) : first;
}
function anonWinAccount(v) {
  if (!v || v === '-' || /^(?:SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|krbtgt)$/i.test(v)) return v;
  let m = v.match(/^([^\\\s@]+)\$(?:@(.+))?$/);
  if (m) return anonWinHost(m[1]) + '$' + (m[2] ? '@' + anonWinDomain(m[2]) : '');
  if ((m = v.match(/^(MSOL_|AAD_|Sync_)(.+)$/i))) return m[1] + anonUser(m[2]);
  return anonUser(v);
}
function anonymizeWinEventFields(clone, evt, opts) {
    // Windows Event Log 沒有 CEF/LEEF 那種官方固定 sensitive-key 清單，比照既有 JSON 分支
    // 精神：srcip（parseWinEventFragment 已從 IpAddress/ClientAddress/SourceAddress 對映
    // 而來的別名欄位）視為 IP 型別去識別化；常見安全事件的使用者帳號欄位另外處理，
    // 避免真實帳號名稱外洩；其餘未知 Data 欄位（Provider 特有語意，本工具不臆測）維持原樣
    if (clone.fields.srcip) clone.fields.srcip = anonWinAddr(clone.fields.srcip, opts);
    WINEVENT_SRCIP_KEYS.forEach(k => { if (clone.fields[k]) clone.fields[k] = anonWinAddr(clone.fields[k], opts); });
    WINEVENT_USER_KEYS.forEach(k => { if (clone.fields[k]) clone.fields[k] = anonWinAccount(clone.fields[k]); });
    // 其餘 Data 欄位：Sysmon 的 User（網域\帳號）換假帳號、*Hostname／WorkstationName 換假主機名稱，
    // 其他值一律做 IP／MAC／email／使用者資料夾的通用替換（SourceIp、DestinationIp、Image 路徑等）
    Object.keys(clone.fields).forEach(k => {
      const v = clone.fields[k];
      if (typeof v !== 'string' || !v || v === '-' || k === 'srcip' || WINEVENT_SYSTEM_KEYS.includes(k) || WINEVENT_SRCIP_KEYS.includes(k) || WINEVENT_USER_KEYS.includes(k)) return;
      // 目錄與憑證事件（第三十輪 WN4／WN5）：DN 依 LDAP 規則、帳號類欄位換假帳號、DNS 主機名稱以主機名稱對照
      if (/^(?:ObjectDN|Subject|DistinguishedName)$/.test(k) || (k === 'AttributeValue' && /^\s*(?:CN|OU|DC)=/i.test(v))) { clone.fields[k] = anonLdapDn(v); return; }
      if (/^(?:SourceUserName|OldTargetUserName|NewTargetUserName|SamAccountName|MemberName)$/.test(k)) { clone.fields[k] = /^\s*(?:CN|OU|DC)=/i.test(v) ? anonLdapDn(v) : anonUser(v); return; }
      if (k === 'DnsHostName') { clone.fields[k] = anonWinHost(v); return; }
      if (k === 'DSName') { clone.fields[k] = anonDnsName(v); return; }
      if (/(?:DomainName|AccountDomain)$/.test(k)) { clone.fields[k] = anonWinDomain(v); return; }
      // 4648 的目標主機與 4769 的服務帳號（電腦帳號保留 $），主機登入關係表去識別化後仍可對應
      if (k === 'TargetServerName') { clone.fields[k] = /^(?:localhost|-)$/i.test(v) ? v : (isValidIPv4(v) ? anonIP(v, opts) : anonWinHost(v)); return; }
      if (k === 'ServiceName' && /\$$/.test(v)) { clone.fields[k] = anonWinAccount(v); return; }
      if (k === 'ServiceName' && evt.fields.EventID === '4769' && !/^krbtgt$/i.test(v)) { clone.fields[k] = anonUser(v); return; }
      if (k === 'ServicePrincipalNames' || k === 'AttributeValue' || k === 'AllowedToDelegateTo') { clone.fields[k] = anonFreeText(v, opts).replace(/(\/)([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)/g, (m, sl, h) => sl + anonDnsName(h)); return; }
      if (k === 'User' || k === 'AccountName' || k === 'Requester' || (/^Data\d+$/.test(k) && /^[\w.-]+\\[^\\\s]+$/.test(v))) {
        const m = v.match(/^([^\\]+)\\(.+)$/);
        // NT AUTHORITY\SYSTEM 等內建帳號保留
        if (m && /^(?:NT AUTHORITY|NT SERVICE|BUILTIN|Window Manager|Font Driver Host)$/i.test(m[1])) return;
        clone.fields[k] = m ? anonWinDomain(m[1]) + '\\' + anonWinAccount(m[2]) : anonWinAccount(v);
      } else if (/Hostname$/i.test(k) || k === 'WorkstationName' || k === 'Workstation') clone.fields[k] = isValidIPv4(v) ? anonIP(v, opts) : anonWinHost(v);
      // 遠端桌面 1149 的 Param1 帳號、Param2 網域
      else if (evt.fields.rdp === 'auth' && k === 'Param1') clone.fields[k] = anonUser(v);
      else if (evt.fields.rdp === 'auth' && k === 'Param2') clone.fields[k] = anonWinDomain(v);
      else clone.fields[k] = anonFreeText(v, opts);
    });
    if (clone.host) clone.host = anonWinHost(clone.host);
    if (clone.fields.Computer) clone.fields.Computer = clone.host;
    // 描述文字（XML 的 RenderingInfo、Winlogbeat／NXLog 的 message、CSV 描述）內的帳號與主機名稱改成同一組假值
    let msg = String(clone.msg || '');
    Object.keys(evt.fields).forEach(k => { const v = evt.fields[k], nv = clone.fields[k]; if (typeof v === 'string' && v.length >= 3 && v !== nv && !/^\d+$/.test(v) && typeof nv === 'string') msg = msg.split(v).join(nv); });
    if (evt.host && evt.host.length >= 3) msg = msg.split(evt.host).join(clone.host);
    clone.msg = anonFreeText(msg, opts);
    clone.raw = rebuildWinEventXML(clone);
}
// Windows NPS DTS XML 去識別化（XN65）：以白名單逐標籤處理——數值類保留，帳號、主機、位址、MAC 換成對照表假值，
// Called-Station-Id 的「MAC:SSID」兩段分開處理，其餘（Vendor-Specific 十六進位內含 SSID 等文字、Class、Session、原則名稱、Connect-Info）一律 REDACTED
const NPS_KEEP_TAGS = new Set(['Timestamp', 'Packet-Type', 'Reason-Code', 'Authentication-Type', 'NAS-Port-Type', 'Service-Type', 'Provider-Type', 'Client-Vendor',
  'Event-Source', 'Framed-MTU', 'NAS-Port', 'EAP-Friendly-Name', 'Framed-Protocol', 'Tunnel-Type', 'Tunnel-Medium-Type', 'Acct-Status-Type', 'Acct-Authentic',
  'Acct-Delay-Time', 'Acct-Session-Time', 'Acct-Input-Octets', 'Acct-Output-Octets', 'Acct-Input-Packets', 'Acct-Output-Packets', 'Acct-Terminate-Cause', 'Quarantine-Update-Non-Compliant']);
const NPS_USER_TAGS = new Set(['User-Name', 'SAM-Account-Name', 'Fully-Qualifed-User-Name']);
const NPS_HOST_TAGS = new Set(['Computer-Name', 'Client-Friendly-Name', 'NAS-Identifier']);
const NPS_IP_TAGS = new Set(['Client-IP-Address', 'NAS-IP-Address', 'Framed-IP-Address']);
function anonymizeNpsEvent(clone, opts) {
  const line = String(clone.raw || '').replace(/<([A-Za-z][\w-]*)( data_type="\d+">)([^<]*)<\/\1>/g, (m, tag, mid, v) => {
    let nv;
    if (NPS_KEEP_TAGS.has(tag) || v === '') nv = v;
    else if (NPS_USER_TAGS.has(tag)) nv = anonUser(v);
    else if (NPS_HOST_TAGS.has(tag)) nv = anonHostname(v);
    else if (NPS_IP_TAGS.has(tag)) nv = replaceIPsInLine(v, opts);
    else if (tag === 'Calling-Station-Id') nv = replaceMACsInLine(v) === v ? 'REDACTED' : replaceMACsInLine(v);
    else if (tag === 'Called-Station-Id') { const i = v.indexOf(':', 17); const mac = i > 0 ? v.slice(0, i) : v; nv = (replaceMACsInLine(mac) === mac ? 'REDACTED' : replaceMACsInLine(mac)) + (i > 0 ? ':REDACTED' : ''); }
    else nv = 'REDACTED';
    return `<${tag}${mid}${nv}</${tag}>`;
  });
  const re = parseNpsLine(line, clone.lineNo);
  clone.raw = line;
  if (re) { clone.fields = re.fields; clone.msg = re.msg; clone.host = re.host; }
  else { clone.fields = { nps: 1 }; clone.msg = ''; clone.host = clone.host ? anonHostname(clone.host) : ''; }
}
// Aruba ClearPass 去識別化（XN134）：以白名單逐鍵處理——CPPM_KEEP_KEYS 保留，帳號／主機／位址／MAC 換對照表假值，
// 其餘（告警與描述文字、服務與原則名稱、角色、認證來源、指紋）一律 REDACTED；表頭主機與 RFC5424 origin 的位址一併換掉後重新解析
const CPPM_KEEP_KEYS = new Set(['Common.Login-Status', 'Common.Error-Code', 'Common.Request-Timestamp', 'Common.Session-Log-Timestamp', 'RADIUS.Session-Log-Timestamp', 'Common.Auth-Type', 'RADIUS.Auth-Method',
  'Common.Source', 'Common.Monitor-Mode', 'Common.Alerts-Present', 'Common.Audit-Posture-Token', 'Common.System-Posture-Token', 'Common.Connection-Status', 'Common.Request-Id', 'eventId',
  'Timestamp', 'timestamp', 'Level', 'level', 'Category', 'category', 'Action', 'action_key', 'Source', 'event_source', 'session_id', 'service_name', 'monitor_mode', 'auth_type', 'audit_apt', 'spt',
  'device_category', 'device_family', 'device_name', 'mac_vendor', 'updated_at', 'added_at']);
const CPPM_USER_KEYS = new Set(['Common.Username', 'User']);
const CPPM_HOST_KEYS = new Set(['Common.NAS-Name', 'hostname']);
const CPPM_IP_KEYS = new Set(['Common.NAS-IP-Address', 'WEBAUTH.Host-IP-Address', 'CppmNode.CPPM-Node', 'ip_address', 'static_ip']);
const CPPM_MAC_KEYS = new Set(['Common.Host-MAC-Address', 'mac_address']);
function cppmAnonValue(key, v, opts) {
  if (v === '' || CPPM_KEEP_KEYS.has(key)) return v;
  if (CPPM_USER_KEYS.has(key)) return anonUser(v);
  if (CPPM_HOST_KEYS.has(key)) return anonHostname(v);
  if (CPPM_IP_KEYS.has(key)) { const t = v.replace(/\s+/g, ''); return replaceIPsInLine(t, opts); }
  // 沒有分隔符的 12 碼 MAC 先補上冒號再換對照表假值（同一 MAC 換同一假值，同一終端多帳號的判斷才不會消失）
  if (CPPM_MAC_KEYS.has(key)) { const c = /^[0-9a-fA-F]{12}$/.test(v) ? v.match(/../g).join(':') : v, m = replaceMACsInLine(c); return m === c ? 'REDACTED' : m; }
  return 'REDACTED';
}
function anonymizeClearPassEvent(clone, opts) {
  const raw = String(clone.raw || '');
  let line = raw;
  const s = raw.match(CPPM_STD_RE), r = s ? null : raw.match(CPPM_5424_RE);
  if (s) {
    const body = s[5].split(CPPM_SPLIT_RE).map(p => { const i = p.indexOf('='); if (i <= 0) return 'REDACTED';
      const k = p.slice(0, i).trim(), key = k.includes('.') ? k.replace(/\s+/g, '') : k;
      return key + '=' + cppmAnonValue(key, p.slice(i + 1).replace(/,\s*$/, '').trim(), opts); }).join(',');
    const head = raw.slice(0, raw.length - s[5].length);
    line = head.replace(' ' + s[3] + ' ' + s[4] + ' ', ' ' + anonHostname(s[3]) + ' ' + s[4] + ' ') + body;
  } else if (r) {
    const i = raw.lastIndexOf('[clearPass@14823 ');
    const sd = raw.slice(i).replace(/([A-Za-z][\w.\-]*)="((?:[^"\\]|\\.)*)"/g, (m, k, v) => `${k}="${cppmAnonValue(k, v.replace(/\\([\]"\\])/g, '$1'), opts).replace(/(["\\\]])/g, '\\$1')}"`);
    line = replaceIPsInLine(raw.slice(0, i), opts).replace(' ' + r[2] + ' ClearPass ', ' ' + anonHostname(r[2]) + ' ClearPass ') + sd;
  }
  const re = parseClearPassLine(line, clone.lineNo);
  clone.raw = line;
  if (re) { clone.fields = re.fields; clone.msg = re.msg; clone.host = re.host; }
  else { clone.fields = { cppm: 'other' }; clone.msg = ''; clone.host = clone.host ? anonHostname(clone.host) : ''; }
}
// GitLab 結構化 log 去識別化（XN81）：深拷貝原始物件，帳號欄位與權杖訊息內的帳號換假帳號，專案路徑與主機名稱換假名，
// 其餘字串換 IP／MAC，再以 gitlabEvent() 重建；同一帳號、專案、權杖編號換成同一組假值，偵測結果不變
const GL_USER_KEYS = new Set(['username', 'meta.user', 'author_name', 'meta.root_namespace']);
const GL_NAME_KEYS = new Set(['target_details', 'meta.project', 'host']);
function anonymizeGitlabEvent(evt, opts) {
  const o = JSON.parse(JSON.stringify(evt.glRaw));
  const walk = x => Object.keys(x).forEach(k => {
    const v = x[k];
    if (v && typeof v === 'object') { walk(v); return; }
    if (typeof v !== 'string' || !v) return;
    if (GL_USER_KEYS.has(k)) x[k] = anonUser(v);
    else if (GL_NAME_KEYS.has(k)) x[k] = v.split('/').map(seg => anonHostname(seg)).join('/');
    else if (k === 'message') x[k] = replaceIPsInLine(v.replace(/'([^']*)'/g, (m, u) => /^\d+$/.test(u) ? m : "'" + anonUser(u) + "'"), opts);
    else x[k] = replaceMACsInLine(replaceIPsInLine(v, opts));
  });
  walk(o);
  const out = gitlabEvent(o, evt.lineNo);
  return Object.assign({ ...evt }, { raw: out.raw, glRaw: o, fields: out.fields, msg: out.msg, host: out.host, url: out.url || evt.url });
}
function anonymizeEvent(evt, opts) {
  if (evt.glRaw) return anonymizeGitlabEvent(evt, opts);
  if (evt.format === 'nps') { const c = { ...evt, fields: { ...evt.fields } }; anonymizeNpsEvent(c, opts); return c; }
  if (evt.format === 'clearpass') { const c = { ...evt, fields: { ...evt.fields } }; anonymizeClearPassEvent(c, opts); return c; }
  if (evt.format === 'radacct') { const c = { ...evt, fields: { ...evt.fields } }; anonymizeRadacctEvent(c, opts); return c; }
  if (evt.fields && evt.fields.ldap) { const c = { ...evt, fields: { ...evt.fields } }; anonymizeLdapEvent(c, opts); return c; }
  if (evt.fields && evt.fields.haproxy) { const c = { ...evt, fields: { ...evt.fields } }; anonymizeHaproxyEvent(c, opts); return c; }
  // 未拆出欄位的 VPN 記錄行（charon 的 looking for peer configs 等）也走同一套，IKE ID 才會一併替換
  if (isVpnAuthFields(evt.fields) || evt.format === 'vpnauth' || (/^rfc(?:3164|5424)$/.test(evt.format) && /^(?:charon|ipsec|openvpn|ovpn-|radiusd)/.test(evt.appName || ''))) { const c = { ...evt, fields: { ...(evt.fields || {}) } }; anonymizeVpnAuthEvent(c, opts); return c; }
  if (evt.dbRaw || evt.format === 'dbfile' || (evt.fields && evt.fields.dbKind)) return anonymizeDbEvent(evt, opts);
  if (evt.format === 'pcs') return anonymizePcsEvent(evt, opts);
  if (evt.netVendor === 'watchguard') return anonymizeWatchGuardEvent(evt, opts);
  if (evt.format === 'netscaler') return anonymizeNetScalerEvent(evt, opts);
  if (evt.netVendor === 'qnap') return anonymizeQnapEvent(evt, opts);
  if (evt.netVendor === 'arubacx') return anonymizeArubaCxEvent(evt, opts);
  if (evt.netVendor === 'veeam') return anonymizeVeeamEvent(evt, opts);
  if (evt.fields && (evt.fields.ssh || evt.fields.sudo)) { const c = { ...evt, fields: { ...evt.fields } }; anonymizeSshEvent(c, opts); return c; }
  if (evt.fields && evt.fields.ise) { const c = { ...evt, fields: { ...evt.fields } }; anonymizeIseEvent(c, opts); return c; }
  if (evt.fields && evt.fields.dhcp) { const c = { ...evt, fields: { ...evt.fields } }; anonymizeDhcpEvent(c, opts); return c; }
  if (evt.fields && evt.fields.dns && !evt.azfwRaw) { const c = { ...evt, fields: { ...evt.fields } }; anonymizeDnsEvent(c, opts); return c; }
  const clone = { ...evt, fields: { ...evt.fields } };
  if (clone.netVendor === 'netfilter') clone.msg = anonNetfilterMac(clone.msg);
  if (clone.netVendor === 'cloudflare' && clone.cfRaw) return anonymizeCloudflareEvent(clone, opts);
  if (clone.netVendor === 'zscaler' && clone.zsRaw) return anonymizeZscalerEvent(clone, opts);
  if (clone.netVendor === 'vault' && clone.vaultRaw) return anonymizeVaultEvent(clone, opts);
  if (clone.netVendor === 'modsec' && clone.modsecRaw) return anonymizeModsecEvent(clone, opts);
  if (clone.netVendor === 'f5' && clone.f5Raw) return anonymizeF5tsEvent(clone, opts);
  if (clone.netVendor === 'meraki' && /^<\d{1,3}>1 \d{9,11}\./.test(clone.raw || '')) return anonymizeMerakiEvent(clone, opts);
  if (clone.netVendor === 'stormshield') return anonymizeStormshieldEvent(clone, opts);
  if (clone.netVendor === 'fortimail' || clone.netVendor === 'fortimanager') return anonymizeFortiMgmtEvent(clone, opts);
  if (evt.format === 'weblog' || evt.format === 'w3c') { anonymizeWebEvent(clone, opts); return clone; }
  if (evt.format === 'flowlog') { anonymizeFlowEvent(clone, opts); return clone; }
  if (evt.format === 'umbrella') { anonUmbrellaEvent(clone, opts); return clone; }
  if (evt.format === 'cef') {
    anonCefLeefFields(clone.fields, ['src', 'dst'], opts);
    // 表頭的事件名稱（如 Login from 10.5.5.5）同樣做通用替換
    clone.msg = anonFreeText(clone.msg || '', opts);
    if (clone.host) clone.host = anonHostname(clone.host);
    // CEF 包在 Syslog 信封裡的事件（cef-syslog），重建時要連同信封 ts/host 一併輸出，
    // host 用已去識別化後的 clone.host（避免信封裡的原始主機名外洩），保留原信封格式
    if (clone.syslogPrefix) clone.raw = `${clone.syslogPrefix.pri || ''}${clone.syslogPrefix.ts} ${clone.host || anonHostname(clone.syslogPrefix.host)} ${rebuildCEFLine(clone)}`;
    else clone.raw = (clone.rawPri || '') + rebuildCEFLine(clone);
  } else if (evt.format === 'asa') {
    // ASA msg 是明碼文字（無結構化欄位），比照 rfc3164/rfc5424 既有處理模式，僅通用文字
    // 正則替換（IP/MAC），範圍刻意不擴及使用者名稱，維持專案「寧可漏報不誤判」原則
    clone.msg = anonUsersInMsg(replaceMACsInLine(replaceIPsInLine(clone.msg || '', opts)));
    // 拆出的欄位（第十三輪 NF）由去識別化後的訊息重新拆，不留原始位址
    clone.fields = parseASAFields(clone.msgid, clone.msg);
    // 表頭原樣保留（第十五輪 VB），只把主機名稱換成假名；舊資料沒有 asaHead 時照原本格式重建
    if (clone.asaHead) {
      const h = clone.host ? anonHostname(clone.host) : '';
      clone.raw = (clone.host ? clone.asaHead.replace(new RegExp('(\\s)' + clone.host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?=[\\s:])'), '$1' + h) : clone.asaHead) + clone.msg;
      clone.host = h;
    } else clone.raw = `${clone.timestampRaw}: %ASA-${clone.severityRaw}-${clone.msgid}: ${clone.msg}`;
  } else if (evt.format === 'leef') {
    // IP 型別欄位但值非合法 IPv4（如 IPv6）時不可原樣放行，比照 CEF/JSON 一律 REDACTED；其餘欄位通用替換
    anonCefLeefFields(clone.fields, LEEF_SENSITIVE_KEYS.filter(k => k !== 'usrName'), opts);
    if (clone.fields.devName) clone.host = clone.fields.devName;
    clone.raw = (clone.rawPri || '') + rebuildLEEFLine(clone);
  } else if (evt.format === 'kvfw') {
    anonymizeKvFwEvent(clone, opts);
  } else if (evt.format === 'fortigate') {
    FORTIGATE_IP_KEYS.forEach(k => {
      const v = clone.fields[k];
      if (!v) return;
      clone.fields[k] = isValidIPv4(v) ? anonIP(v, opts) : 'REDACTED';
    });
    // 其餘值為 IPv4 的欄位（VPN 的 remip／locip／tunnelip／assignip、NAT 的 tranip 等）一律替換（第二十二輪 HA 發現 tunnelip 原樣留下）
    Object.keys(clone.fields).forEach(k => { const v = clone.fields[k]; if (!FORTIGATE_IP_KEYS.includes(k) && typeof v === 'string' && isValidIPv4(v)) clone.fields[k] = anonIP(v, opts); });
    FORTIGATE_HOST_KEYS.forEach(k => { if (clone.fields[k]) clone.fields[k] = anonHostname(clone.fields[k]); });
    FORTIGATE_MAC_KEYS.forEach(k => { if (clone.fields[k]) clone.fields[k] = anonMAC(clone.fields[k]); });
    // 帳號也會出現在 msg／logdesc／ui 文字裡（如 Administrator admin logged in），原值先記下再一併替換（第十五輪 VA 發現）
    const fgUsers = [];
    FORTIGATE_USER_KEYS.forEach(k => { const v = clone.fields[k]; if (v) { const a = anonUser(v); if (a !== v) fgUsers.push([v, a]); clone.fields[k] = a; } });
    // 設定變更紀錄的物件若是帳號（管理者 system.admin、本機使用者 user.local），cfgobj 即帳號名稱，msg 也會帶出（XN35）
    if (/^(?:system\.admin|user\.local)$/.test(clone.fields.cfgpath || '') && clone.fields.cfgobj) {
      const v = clone.fields.cfgobj, a = anonUser(v);
      if (a !== v) fgUsers.push([v, a]);
      clone.fields.cfgobj = a;
    }
    const fgUserRe = t => fgUsers.reduce((acc, [o, a]) => acc.replace(new RegExp('(^|[^\\w.-])' + o.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![\\w-])', 'g'), '$1' + a), String(t));
    ['msg', 'logdesc', 'ui'].forEach(k => { if (clone.fields[k]) clone.fields[k] = fgUserRe(clone.fields[k]); });
    if (clone.msg) clone.msg = fgUserRe(clone.msg);
    if (clone.fields.ui) clone.fields.ui = replaceIPsInLine(clone.fields.ui, opts);
    if (clone.fields.msg) clone.fields.msg = replaceMACsInLine(replaceIPsInLine(clone.fields.msg, opts));
    if (clone.fields.logdesc) clone.fields.logdesc = replaceMACsInLine(replaceIPsInLine(clone.fields.logdesc, opts));
    // 設定變更的屬性值（位址物件 subnet[…]、trusthost 等）含位址
    if (clone.fields.cfgattr) clone.fields.cfgattr = fgUserRe(replaceMACsInLine(replaceIPsInLine(clone.fields.cfgattr, opts)));
    if (clone.host) clone.host = anonHostname(clone.host);
    // clone.host 來自 fields.devname（見 parseFortiGateLine），先前只更新了 clone.host 這個
    // 獨立副本，從未回寫進 clone.fields.devname——rebuildFortiGateLine() 是依 fields 原樣
    // 重建整行文字，devname 從未被排除或替換，導致下載/匯出的去識別化 log 檔案裡 FortiGate
    // 裝置真實主機名稱仍以明碼保留，即便畫面顯示的 host 欄位看起來已是假值（2026-09 全功能
    // 審查發現；比照下方 winevent 分支 clone.fields.Computer 回寫既有正確寫法）
    if (clone.fields.devname) clone.fields.devname = clone.host;
    clone.msg = replaceMACsInLine(replaceIPsInLine(clone.msg || '', opts));
    clone.raw = (clone.fgPri || '') + rebuildFortiGateLine(clone);
  } else if (evt.format === 'json') {
    anonymizeJSONFields(clone.fields, opts);
    // Cisco Secure Endpoint：原始事件深拷貝後換 IP／MAC，電腦名稱換假名、路徑中的使用者資料夾換假帳號，再重新整理欄位
    // 雲端身分平台：原始事件深拷貝後換 IP，帳號（含 email）換假名，再重新整理欄位（第十六輪 PF）
    if (clone.cloudRaw) {
      const a = JSON.parse(JSON.stringify(clone.cloudRaw));
      const ci0 = cloudAuthInfo(clone.cloudRaw);
      // Duo 驗證裝置名稱常含電話號碼、存取裝置主機名稱與別名（第二十三輪 IF）
      if (ci0 && ci0.vendor === 'duo') {
        if (a.auth_device && a.auth_device.name) a.auth_device.name = anonHostname(a.auth_device.name);
        if (a.access_device && a.access_device.hostname) a.access_device.hostname = anonHostname(a.access_device.hostname);
        if (a.alias) a.alias = anonUser(a.alias);
        // 位址後面可能直接接埠號寫法（#1234、p1234、.1234），先取出開頭的位址再替換
        ['access_device', 'auth_device'].forEach(k => {
          const d = a[k];
          if (!d || typeof d.ip !== 'string') return;
          const m = d.ip.match(/^(\[?)((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|[0-9A-Fa-f:]*::[0-9A-Fa-f:]*|\d{1,3}(?:\.\d{1,3}){3})/);
          if (m) d.ip = m[1] + replaceIPsInLine(m[2], opts) + d.ip.slice(m[0].length);
        });
      }
      const USER_KEY_RE = /^(?:userPrincipalName|userName|UserId|alternateId|email|identity|userDisplayName|displayName|UserKey|principalId|userId)$/;
      const walk = o => Object.keys(o).forEach(k => { const v = o[k]; if (v && typeof v === 'object') walk(v); else if (typeof v === 'string') {
        // Kubernetes 內建身分（system: 開頭，含 GKE 經 Cloud Audit Logs 記錄的）保留，判斷高風險操作時要排除控制平面元件；service account 只換名稱
        const k8sSys = ci0 && (ci0.vendor === 'k8s' || ci0.vendor === 'gcpaudit') && /^system:/.test(v);
        let x = k8sSys ? v.replace(/^(system:serviceaccount:[^:]+:)(.+)$/, (m, p, n) => p + anonUser(n))
          : (USER_KEY_RE.test(k) || (ci0 && v === ci0.user)) && v ? anonUser(v) : replaceMACsInLine(replaceIPsInLine(v, opts));
        x = x.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, m => anonUser(m));
        // AWS ARN 的帳號 ID 與 user／role 名稱、accountId 欄位（帳號 ID 比照雲端流量紀錄以主機名稱對照替換）
        if (k === 'accountId' && /^\d{12}$/.test(x)) x = anonHostname(x);
        // AWS 存取金鑰 ID（AKIA 長期金鑰、ASIA 暫時金鑰）
        x = x.replace(/\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b/g, 'REDACTED_KEY');
        // Azure 資源 ID 的訂閱 GUID 與資源群組、GCP 專案 ID（第二十輪 FE）
        x = x.replace(/(\/subscriptions\/)([0-9a-fA-F-]{36})/gi, (m, p, id) => p + anonHostname(id.toLowerCase()))
          .replace(/(\/resourceGroups\/)([^\/\s"]+)/gi, (m, p, n) => p + anonHostname(n))
          .replace(/(\bprojects\/)([a-z][a-z0-9-]{4,28}[a-z0-9])(?=\/|$)/g, (m, p, n) => p + anonHostname(n));
        if ((k === 'project_id' || k === 'subscriptionId' || k === 'tenantId') && x) x = anonHostname(x);
        x = x.replace(/^(arn:aws[\w-]*:[\w-]*:[\w-]*:)(\d{12})(:)/, (m, p, id, c) => p + anonHostname(id) + c)
          // assumed-role ARN 的第二段是工作階段名稱（常為使用者帳號），與角色名稱一併替換
          .replace(/(:assumed-role\/)([^\/\s"]+)\/([^\/\s"]+)/, (m, p, r, u) => p + anonUser(r) + '/' + anonUser(u))
          .replace(/(:(?:user|role)\/)([^\/\s"]+)/, (m, p, u) => p + anonUser(u));
        o[k] = x; } });
      walk(a);
      const ci = cloudAuthInfo(a);
      const ev = cloudAuthEvent(a, ci, clone.lineNo);
      Object.assign(clone, { cloudRaw: a, fields: ev.fields, msg: ev.msg, raw: ev.raw });
      if (clone.host) clone.host = anonHostname(clone.host);
      return clone;
    }
    // 雲端防火牆（第二十二輪 HE）：深拷貝後換 IP／MAC，防火牆名稱與資源 ID 的訂閱／資源群組換假名、非公開網域以主機名稱對照替換，再重建
    if (clone.nfwRaw || clone.azfwRaw) {
      const a = JSON.parse(JSON.stringify(clone.nfwRaw || clone.azfwRaw));
      const walk = o => Object.keys(o).forEach(k => { const v = o[k]; if (v && typeof v === 'object') walk(v); else if (typeof v === 'string' && v) {
        let x;
        if (k === 'firewall_name') x = anonHostname(v);
        else if (k === 'resourceId') x = v.replace(/(\/SUBSCRIPTIONS\/)([0-9a-fA-F-]{36})/i, (m, p, id) => p + anonHostname(id.toLowerCase())).replace(/(\/RESOURCEGROUPS\/)([^\/]+)/i, (m, p, n) => p + anonHostname(n)).replace(/[^\/]+$/, n => anonHostname(n));
        else if (/^(?:hostname|Fqdn|sni|QueryName)$/i.test(k)) x = isValidIPv4(v) ? replaceIPsInLine(v, opts) : anonDnsName(v);
        else if (k === 'msg' || k === 'TargetUrl') x = anonDnsText(replaceIPsInLine(v, opts));
        else x = replaceMACsInLine(replaceIPsInLine(v, opts));
        o[k] = x; } });
      walk(a);
      const ev = clone.nfwRaw ? nfwEvent(a, clone.lineNo) : azfwEvent(a, clone.lineNo);
      Object.assign(clone, { fields: ev.fields, msg: ev.msg, raw: ev.raw, host: ev.host, nfwRaw: ev.nfwRaw, azfwRaw: ev.azfwRaw });
      return clone;
    }
    // Microsoft Defender（第十八輪 TK）：深拷貝後帳號類欄位與 email 換假帳號、主機名稱換假名、其餘換 IP／MAC，重建同一筆告警
    if (clone.netVendor === 'defender' && clone.defRaw) {
      const a = JSON.parse(JSON.stringify(clone.defRaw));
      const walk = o => Object.keys(o).forEach(k => { const v = o[k]; if (v && typeof v === 'object') walk(v); else if (typeof v === 'string' && v) {
        let x;
        if (/^(?:userName|accountName|userPrincipalName|assignedTo|aadUserId|userSid)$/.test(k)) x = anonUser(v);
        else if (/^(?:computerDnsName|deviceDnsName|domainName|hostName)$/.test(k)) x = anonHostname(v);
        else x = replaceMACsInLine(replaceIPsInLine(v, opts)).replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, m => anonUser(m));
        o[k] = x; } });
      walk(a);
      const all = defenderEvents(a, clone.lineNo);
      const ev = all.find(x => x.fields.title === clone.fields.title) || all[0];
      if (ev) Object.assign(clone, { defRaw: a, fields: ev.fields, msg: ev.msg, raw: ev.raw, host: ev.host });
      return clone;
    }
    // CrowdStrike Falcon（第十八輪 TJ）：深拷貝後換 IP／MAC；帳號（UserName／UserId，含 email）換假名、
    // 主機名稱（ComputerName／HostName／HostnameField／MachineDomain）換假名、路徑中的使用者資料夾換假帳號
    if (clone.netVendor === 'falcon' && clone.falconRaw) {
      const a = JSON.parse(JSON.stringify(clone.falconRaw));
      const walk = o => Object.keys(o).forEach(k => { const v = o[k]; if (v && typeof v === 'object') walk(v); else if (typeof v === 'string' && v) {
        let x;
        if (/^(?:UserName|UserId)$/.test(k)) x = anonUser(v);
        else if (/^(?:ComputerName|HostName|HostnameField|MachineDomain)$/.test(k)) x = anonHostname(v);
        else x = replaceMACsInLine(replaceIPsInLine(v, opts)).replace(/(\\Users\\)([^\\]+)/gi, (m, p, u) => p + anonUser(u)).replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, m => anonUser(m));
        o[k] = x; } });
      walk(a);
      const ev = falconEvent(a, clone.lineNo);
      Object.assign(clone, { falconRaw: a, fields: ev.fields, msg: ev.msg, raw: ev.raw, host: ev.host });
      return clone;
    }
    // Zeek（第十八輪 TI）：原始物件深拷貝後換 IP／MAC，再重建欄位與訊息
    if (clone.netVendor === 'zeek' && clone.zeekRaw) {
      const a = JSON.parse(JSON.stringify(clone.zeekRaw));
      // 密碼遮蔽；帳號（kerberos client 為「帳號/領域」）換假帳號；主機與查詢名稱以 DNS 名稱對照替換；其餘通用替換
      const realm = r => /\./.test(r) ? anonDnsName(r) : r;
      const walk = o => Object.keys(o).forEach(k => { const v = o[k]; if (v && typeof v === 'object') walk(v); else if (typeof v === 'string' && v && v !== '-') {
        let x;
        if (k === 'password') x = 'REDACTED_PASSWORD';
        else if (k === 'username' || k === 'user' || k === 'client') x = v.replace(/^([^\/@]+)(?:([\/@])(.+))?$/, (m, u, sep, r) => anonUser(u) + (sep ? sep + realm(r) : ''));
        else if (k === 'service') x = v.replace(/^([^\/]+\/)(.+)$/, (m, sv, r) => sv + realm(r));
        else if (/^(?:hostname|host|server_name|query)$/.test(k)) x = isValidIPv4(v) || v.includes(':') ? replaceIPsInLine(v, opts) : anonDnsName(v);
        else x = anonFreeText(v, opts);
        o[k] = x; } });
      walk(a);
      const ev = zeekEvent(a, clone.lineNo);
      Object.assign(clone, { zeekRaw: a, fields: ev.fields, msg: ev.msg, raw: ev.raw });
      return clone;
    }
    if (clone.netVendor === 'amp' && clone.ampRaw) {
      const a = JSON.parse(JSON.stringify(clone.ampRaw));
      const host = a.computer && a.computer.hostname;
      const walk = o => Object.keys(o).forEach(k => { const v = o[k]; if (v && typeof v === 'object') walk(v); else if (typeof v === 'string') {
        let x = replaceMACsInLine(replaceIPsInLine(v, opts));
        if (k === 'hostname' && x) x = anonHostname(x);
        x = x.replace(/(\\Users\\)([^\\]+)/gi, (m, p, u) => p + anonUser(u));
        o[k] = x; } });
      walk(a);
      clone.ampRaw = a;
      clone.fields = ampFields(a);
      clone.host = clone.fields.computer || (host ? anonHostname(host) : '');
      clone.msg = [a.event_type, a.detection, clone.fields.filename].filter(Boolean).join(' — ');
      clone.raw = JSON.stringify(a);
      return clone;
    }
    // Suricata：巢狀物件（ether 的 MAC、http／dns／tls 內的位址）一律以通用 IP／MAC 規則替換
    if (clone.netVendor === 'suricata') {
      // 巢狀物件先深拷貝，避免改到原始事件（clone 只淺拷貝第一層）
      Object.keys(clone.fields).forEach(k => { if (clone.fields[k] && typeof clone.fields[k] === 'object') clone.fields[k] = JSON.parse(JSON.stringify(clone.fields[k])); });
      const walk = o => Object.keys(o).forEach(k => { const v = o[k]; if (v && typeof v === 'object') walk(v); else if (typeof v === 'string') o[k] = replaceMACsInLine(replaceIPsInLine(v, opts)); });
      Object.keys(clone.fields).forEach(k => { if (clone.fields[k] && typeof clone.fields[k] === 'object') walk(clone.fields[k]); });
    }
    if (clone.host) clone.host = anonHostname(clone.host);
    clone.msg = replaceMACsInLine(replaceIPsInLine(clone.msg || '', opts));
    clone.raw = JSON.stringify(clone.fields);
  } else if (evt.format === 'winevent') {
    anonymizeWinEventFields(clone, evt, opts);
  } else if (evt.format === 'rfc5424' && evt.cpKV) {
    anonCheckPointEvent(clone, opts);
  } else if (evt.format === 'rfc5424') {
    // Structured Data 的 SD-PARAM 無固定命名規格，無法像 CEF/JSON 依欄位語意分流處理，
    // 一律用通用 IP/MAC 正則替換（與 msg 文字的既有處理方式一致），避免整段欄位被捨棄
    if (clone.host) clone.host = anonHostname(clone.host);
    const anonFields = {};
    Object.keys(clone.fields || {}).forEach(k => { anonFields[k] = replaceMACsInLine(replaceIPsInLine(String(clone.fields[k]), opts)); });
    clone.fields = anonFields;
    if (clone.jsonMsg) anonJsonMsg(clone, opts);
    else {
      clone.msg = anonUsersInMsg(replaceMACsInLine(replaceIPsInLine(clone.msg || '', opts)));
      if (clone.netVendor === 'sonicwall' || clone.netVendor === 'sophos') anonKvFwMsg(clone, opts);
      else if (clone.netFields) anonymizeNetFields(clone, opts, true);
    }
    clone.raw = rebuildSyslogRaw(clone);
  } else {
    if (clone.host) clone.host = anonHostname(clone.host);
    if (clone.jsonMsg) anonJsonMsg(clone, opts);
    else if (clone.netVendor === 'sonicwall' || clone.netVendor === 'sophos') anonKvFwMsg(clone, opts);
    else {
      clone.msg = anonUsersInMsg(replaceMACsInLine(replaceIPsInLine(clone.msg || '', opts)));
      if (clone.netFields) anonymizeNetFields(clone, opts, false);
    }
    clone.raw = rebuildSyslogRaw(clone);
  }
  return clone;
}
// 雲端流量紀錄：位址欄位（含 pkt-srcaddr 等）、帳號與資源 ID、NIC MAC；AWS 依欄位順序重建整行，
// Azure 重建 tuple 字串（規則名稱保留）
function anonymizeFlowEvent(clone, opts) {
  const f = clone.fields;
  const ip = v => (isValidIPv4(v) ? anonIP(v, opts) : (String(v).includes(':') ? anonIPv6(v) : v));
  ['srcip', 'dstip', 'srcaddr', 'dstaddr', 'pkt-srcaddr', 'pkt-dstaddr'].forEach(k => { if (f[k]) f[k] = ip(f[k]); });
  ['account-id', 'interface-id', 'instance-id', 'vpc-id', 'subnet-id', 'interface', 'ecs-cluster-name', 'ecs-container-instance-id'].forEach(k => { if (f[k] && f[k] !== 'unknown') f[k] = anonHostname(f[k]); });
  if (f.srcmac) f.srcmac = anonMAC(f.srcmac);
  if (clone.host) clone.host = anonHostname(clone.host);
  // GCP：原始紀錄深拷貝後換 IP，專案、VPC、子網路、VM 名稱以主機名稱對照替換，再重新整理欄位
  if (clone.netVendor === 'gcp' && clone.gcpRaw) {
    const a = JSON.parse(JSON.stringify(clone.gcpRaw));
    const HOSTISH = /^(?:project_id|vm_name|vpc_name|subnetwork_name|subnetwork_id|instance_id|network)$/;
    const walk = o => Object.keys(o).forEach(k => { const v = o[k]; if (v && typeof v === 'object') walk(v); else if (typeof v === 'string') {
      o[k] = HOSTISH.test(k) && v !== 'default' ? anonHostname(v) : replaceIPsInLine(v, opts); } });
    walk(a);
    if (clone.gcpRaw.logName) a.logName = String(clone.gcpRaw.logName).replace(/^projects\/([^/]+)/, (m, pj) => 'projects/' + anonHostname(pj));
    const rd = a.jsonPayload && a.jsonPayload.rule_details;
    if (rd && rd.reference) rd.reference = String(rd.reference).replace(/^network:([^/]+)/, (m, n) => 'network:' + (n === 'default' ? n : anonHostname(n)));
    const ev = gcpFlowEvent(a, clone.lineNo);
    Object.assign(clone, { gcpRaw: a, fields: ev.fields, raw: ev.raw, msg: ev.msg, host: ev.host });
    return;
  }
  if (clone.netVendor === 'aws' && clone.flowCols) {
    clone.raw = clone.flowCols.map(c => (c === 'action' ? ({ deny: 'REJECT', accept: 'ACCEPT' }[f.action] || '-') : (f[c] !== undefined ? f[c] : '-'))).join(' ');
  } else {
    const t = String(clone.raw).split(',');
    t[1] = f.srcip || t[1]; t[2] = f.dstip || t[2];
    clone.raw = t.join(',');
    if (clone.flowMac) clone.flowMac = (f.srcmac || '').replace(/:/g, '').toUpperCase();
  }
  clone.msg = flowMsg(f);
}
function anonymizeEvents(events, opts) {
  resetAnonState();
  srcIPv4.clear(); srcIPv6.clear();
  // 原檔既有位址只需從原始行、訊息與欄位收集（整批 JSON.stringify 在 10 萬筆時達百 MB，第二十八輪 OP3）
  for (const e of events) {
    const all = (e.raw || '') + '\n' + (e.msg || '') + '\n' + (e.fields ? JSON.stringify(e.fields) : '');
    for (const m of all.matchAll(/(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d])/g)) srcIPv4.add(m[0]);
    if (all.includes('2001:')) for (const m of all.matchAll(/(?<![0-9A-Fa-f:])2001:db8::[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])/gi)) srcIPv6.add(m[0].toLowerCase());
  }
  // IP 對照的主機名稱與帳號（srcName／dstName／srcUser／dstUser）去識別化後依替換後的租約與 VPN 紀錄重新對應
  const out = events.map(evt => anonymizeEvent(evt, opts)).map(e => {
    if (!e.fields || !(e.fields.srcName || e.fields.dstName || e.fields.srcUser || e.fields.dstUser)) return e;
    const { srcName, dstName, srcUser, dstUser, ...rest } = e.fields;
    return { ...e, fields: rest };
  });
  return annotateAddrOwners(linkDbConns(out));
}
// 去識別化結果轉回文字：W3C（IIS、Windows 防火牆）事件在欄位定義改變處補回 #Software／#Time Format／#Fields 表頭，
// 下載後再匯入仍能依欄位解析（第二十二輪 HC）
function anonEventsToText(events) {
  const out = [];
  let lastHead = '';
  events.forEach(e => {
    if (e.w3cCols) {
      const head = (e.netVendor === 'winfw' ? `#Software: Microsoft Windows Firewall\n#Time Format: ${e.winfwUtc ? 'UTC' : 'Local'}\n` : '') + '#Fields: ' + e.w3cCols.join(' ');
      if (head !== lastHead) { out.push(head); lastHead = head; }
    }
    out.push(e.raw);
  });
  return out.join('\n');
}
function checkResidualLog(text) {
  const warnings = [];
  const ipLike = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  const macLike = /\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b/;
  text.split('\n').forEach((line, i) => {
    if (!line.trim()) return;
    const ipMatches = line.match(new RegExp(ipLike.source, 'g'));
    // 去識別化刻意保留的位址（0.x 未指定、127.x 迴路、224 以上群播／保留，見 classifyIP()）不算殘留
    // 有段落超過 255 的點分數字是版本號（如 Duo security_agents 的 1.24.0.967），不是位址
    if (ipMatches && ipMatches.some(m => isValidIPv4(m) && !/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(m) && classifyIP(m) !== 'skip')) warnings.push({ line: i + 1, text: line.trim() });
    // 2026-08-09 稽核修復：先前只檢查 IPv4，救援網對 IPv6 完全沒有偵測能力
    const ip6Matches = line.match(new RegExp(IPv6_RE.source, 'g'));
    // 迴路 ::1 與群播 ffxx:: 不是主機位址（比照 IPv4 的 127／224 以上），不算殘留
    if (ip6Matches && ip6Matches.some(m => !/^2001:db8::/i.test(m) && !MAC_SHAPE_RE.test(m) && m !== '::' && !/^(?:::1|ff[0-9a-f]{2}:)/i.test(m))) warnings.push({ line: i + 1, text: line.trim() });
    const macMatches = line.match(new RegExp(macLike.source, 'g'));
    if (macMatches && macMatches.some(m => !/^02/i.test(m.replace(/[:.-]/g, '')))) warnings.push({ line: i + 1, text: line.trim() });
  });
  return warnings;
}
// ISO 3166-1 alpha-2 → 名稱＋洲別對照表：供 resolveCountryInfo() 把國家代碼/字串解析成可讀
// 名稱＋分組依據。涵蓋 UN 會員國＋常見地區/屬地（約 240 筆，實測完整 v2fly geoip.dat 含 250
// 個 distinct 代碼，未收錄的極少數代碼會由 resolveCountryInfo() 優雅降級為「其他/未分類」，
// 不影響功能，只是少了分組資訊）。純參考資料，非比對邏輯依據——checkbox 的 value 仍是原始
// 字串，這份表只用來決定「顯示什麼名稱」與「歸在哪一組」
const COUNTRY_INFO = {
  AF:{name:'Afghanistan',continent:'asia'},AM:{name:'Armenia',continent:'asia'},AZ:{name:'Azerbaijan',continent:'asia'},BH:{name:'Bahrain',continent:'asia'},BD:{name:'Bangladesh',continent:'asia'},BT:{name:'Bhutan',continent:'asia'},BN:{name:'Brunei',continent:'asia'},KH:{name:'Cambodia',continent:'asia'},CN:{name:'China',continent:'asia'},CY:{name:'Cyprus',continent:'asia'},GE:{name:'Georgia',continent:'asia'},HK:{name:'Hong Kong',continent:'asia'},IN:{name:'India',continent:'asia'},ID:{name:'Indonesia',continent:'asia'},IR:{name:'Iran',continent:'asia'},IQ:{name:'Iraq',continent:'asia'},IL:{name:'Israel',continent:'asia'},JP:{name:'Japan',continent:'asia'},JO:{name:'Jordan',continent:'asia'},KZ:{name:'Kazakhstan',continent:'asia'},KP:{name:'North Korea',continent:'asia'},KR:{name:'South Korea',continent:'asia'},KW:{name:'Kuwait',continent:'asia'},KG:{name:'Kyrgyzstan',continent:'asia'},LA:{name:'Laos',continent:'asia'},LB:{name:'Lebanon',continent:'asia'},MO:{name:'Macau',continent:'asia'},MY:{name:'Malaysia',continent:'asia'},MV:{name:'Maldives',continent:'asia'},MN:{name:'Mongolia',continent:'asia'},MM:{name:'Myanmar',continent:'asia'},NP:{name:'Nepal',continent:'asia'},OM:{name:'Oman',continent:'asia'},PK:{name:'Pakistan',continent:'asia'},PS:{name:'Palestine',continent:'asia'},PH:{name:'Philippines',continent:'asia'},QA:{name:'Qatar',continent:'asia'},SA:{name:'Saudi Arabia',continent:'asia'},SG:{name:'Singapore',continent:'asia'},LK:{name:'Sri Lanka',continent:'asia'},SY:{name:'Syria',continent:'asia'},TW:{name:'Taiwan',continent:'asia'},TJ:{name:'Tajikistan',continent:'asia'},TH:{name:'Thailand',continent:'asia'},TL:{name:'Timor-Leste',continent:'asia'},TR:{name:'Turkey',continent:'asia'},TM:{name:'Turkmenistan',continent:'asia'},AE:{name:'United Arab Emirates',continent:'asia'},UZ:{name:'Uzbekistan',continent:'asia'},VN:{name:'Vietnam',continent:'asia'},YE:{name:'Yemen',continent:'asia'},
  AL:{name:'Albania',continent:'europe'},AD:{name:'Andorra',continent:'europe'},AT:{name:'Austria',continent:'europe'},BY:{name:'Belarus',continent:'europe'},BE:{name:'Belgium',continent:'europe'},BA:{name:'Bosnia and Herzegovina',continent:'europe'},BG:{name:'Bulgaria',continent:'europe'},HR:{name:'Croatia',continent:'europe'},CZ:{name:'Czechia',continent:'europe'},DK:{name:'Denmark',continent:'europe'},EE:{name:'Estonia',continent:'europe'},FO:{name:'Faroe Islands',continent:'europe'},FI:{name:'Finland',continent:'europe'},FR:{name:'France',continent:'europe'},DE:{name:'Germany',continent:'europe'},GI:{name:'Gibraltar',continent:'europe'},GR:{name:'Greece',continent:'europe'},GG:{name:'Guernsey',continent:'europe'},VA:{name:'Vatican City',continent:'europe'},HU:{name:'Hungary',continent:'europe'},IS:{name:'Iceland',continent:'europe'},IE:{name:'Ireland',continent:'europe'},IM:{name:'Isle of Man',continent:'europe'},IT:{name:'Italy',continent:'europe'},JE:{name:'Jersey',continent:'europe'},XK:{name:'Kosovo',continent:'europe'},LV:{name:'Latvia',continent:'europe'},LI:{name:'Liechtenstein',continent:'europe'},LT:{name:'Lithuania',continent:'europe'},LU:{name:'Luxembourg',continent:'europe'},MT:{name:'Malta',continent:'europe'},MD:{name:'Moldova',continent:'europe'},MC:{name:'Monaco',continent:'europe'},ME:{name:'Montenegro',continent:'europe'},NL:{name:'Netherlands',continent:'europe'},MK:{name:'North Macedonia',continent:'europe'},NO:{name:'Norway',continent:'europe'},PL:{name:'Poland',continent:'europe'},PT:{name:'Portugal',continent:'europe'},RO:{name:'Romania',continent:'europe'},RU:{name:'Russia',continent:'europe'},SM:{name:'San Marino',continent:'europe'},RS:{name:'Serbia',continent:'europe'},SK:{name:'Slovakia',continent:'europe'},SI:{name:'Slovenia',continent:'europe'},ES:{name:'Spain',continent:'europe'},SJ:{name:'Svalbard and Jan Mayen',continent:'europe'},SE:{name:'Sweden',continent:'europe'},CH:{name:'Switzerland',continent:'europe'},UA:{name:'Ukraine',continent:'europe'},GB:{name:'United Kingdom',continent:'europe'},AX:{name:'Aland Islands',continent:'europe'},
  DZ:{name:'Algeria',continent:'africa'},AO:{name:'Angola',continent:'africa'},BJ:{name:'Benin',continent:'africa'},BW:{name:'Botswana',continent:'africa'},IO:{name:'British Indian Ocean Territory',continent:'africa'},BF:{name:'Burkina Faso',continent:'africa'},BI:{name:'Burundi',continent:'africa'},CV:{name:'Cabo Verde',continent:'africa'},CM:{name:'Cameroon',continent:'africa'},CF:{name:'Central African Republic',continent:'africa'},TD:{name:'Chad',continent:'africa'},KM:{name:'Comoros',continent:'africa'},CG:{name:'Congo',continent:'africa'},CD:{name:'DR Congo',continent:'africa'},CI:{name:"Cote d'Ivoire",continent:'africa'},DJ:{name:'Djibouti',continent:'africa'},EG:{name:'Egypt',continent:'africa'},GQ:{name:'Equatorial Guinea',continent:'africa'},ER:{name:'Eritrea',continent:'africa'},SZ:{name:'Eswatini',continent:'africa'},ET:{name:'Ethiopia',continent:'africa'},GA:{name:'Gabon',continent:'africa'},GM:{name:'Gambia',continent:'africa'},GH:{name:'Ghana',continent:'africa'},GN:{name:'Guinea',continent:'africa'},GW:{name:'Guinea-Bissau',continent:'africa'},KE:{name:'Kenya',continent:'africa'},LS:{name:'Lesotho',continent:'africa'},LR:{name:'Liberia',continent:'africa'},LY:{name:'Libya',continent:'africa'},MG:{name:'Madagascar',continent:'africa'},MW:{name:'Malawi',continent:'africa'},ML:{name:'Mali',continent:'africa'},MR:{name:'Mauritania',continent:'africa'},MU:{name:'Mauritius',continent:'africa'},YT:{name:'Mayotte',continent:'africa'},MA:{name:'Morocco',continent:'africa'},MZ:{name:'Mozambique',continent:'africa'},NA:{name:'Namibia',continent:'africa'},NE:{name:'Niger',continent:'africa'},NG:{name:'Nigeria',continent:'africa'},RE:{name:'Reunion',continent:'africa'},RW:{name:'Rwanda',continent:'africa'},SH:{name:'Saint Helena',continent:'africa'},ST:{name:'Sao Tome and Principe',continent:'africa'},SN:{name:'Senegal',continent:'africa'},SC:{name:'Seychelles',continent:'africa'},SL:{name:'Sierra Leone',continent:'africa'},SO:{name:'Somalia',continent:'africa'},ZA:{name:'South Africa',continent:'africa'},SS:{name:'South Sudan',continent:'africa'},SD:{name:'Sudan',continent:'africa'},TZ:{name:'Tanzania',continent:'africa'},TG:{name:'Togo',continent:'africa'},TN:{name:'Tunisia',continent:'africa'},UG:{name:'Uganda',continent:'africa'},EH:{name:'Western Sahara',continent:'africa'},ZM:{name:'Zambia',continent:'africa'},ZW:{name:'Zimbabwe',continent:'africa'},
  AI:{name:'Anguilla',continent:'namerica'},AG:{name:'Antigua and Barbuda',continent:'namerica'},AW:{name:'Aruba',continent:'namerica'},BS:{name:'Bahamas',continent:'namerica'},BB:{name:'Barbados',continent:'namerica'},BZ:{name:'Belize',continent:'namerica'},BM:{name:'Bermuda',continent:'namerica'},VG:{name:'British Virgin Islands',continent:'namerica'},CA:{name:'Canada',continent:'namerica'},KY:{name:'Cayman Islands',continent:'namerica'},CR:{name:'Costa Rica',continent:'namerica'},CU:{name:'Cuba',continent:'namerica'},CW:{name:'Curacao',continent:'namerica'},DM:{name:'Dominica',continent:'namerica'},DO:{name:'Dominican Republic',continent:'namerica'},SV:{name:'El Salvador',continent:'namerica'},GL:{name:'Greenland',continent:'namerica'},GD:{name:'Grenada',continent:'namerica'},GP:{name:'Guadeloupe',continent:'namerica'},GT:{name:'Guatemala',continent:'namerica'},HT:{name:'Haiti',continent:'namerica'},HN:{name:'Honduras',continent:'namerica'},JM:{name:'Jamaica',continent:'namerica'},MQ:{name:'Martinique',continent:'namerica'},MX:{name:'Mexico',continent:'namerica'},MS:{name:'Montserrat',continent:'namerica'},NI:{name:'Nicaragua',continent:'namerica'},PA:{name:'Panama',continent:'namerica'},PR:{name:'Puerto Rico',continent:'namerica'},BL:{name:'Saint Barthelemy',continent:'namerica'},KN:{name:'Saint Kitts and Nevis',continent:'namerica'},LC:{name:'Saint Lucia',continent:'namerica'},MF:{name:'Saint Martin',continent:'namerica'},PM:{name:'Saint Pierre and Miquelon',continent:'namerica'},VC:{name:'Saint Vincent and the Grenadines',continent:'namerica'},SX:{name:'Sint Maarten',continent:'namerica'},TT:{name:'Trinidad and Tobago',continent:'namerica'},TC:{name:'Turks and Caicos Islands',continent:'namerica'},US:{name:'United States',continent:'namerica'},VI:{name:'U.S. Virgin Islands',continent:'namerica'},
  AR:{name:'Argentina',continent:'samerica'},BO:{name:'Bolivia',continent:'samerica'},BR:{name:'Brazil',continent:'samerica'},CL:{name:'Chile',continent:'samerica'},CO:{name:'Colombia',continent:'samerica'},EC:{name:'Ecuador',continent:'samerica'},FK:{name:'Falkland Islands',continent:'samerica'},GF:{name:'French Guiana',continent:'samerica'},GY:{name:'Guyana',continent:'samerica'},PY:{name:'Paraguay',continent:'samerica'},PE:{name:'Peru',continent:'samerica'},SR:{name:'Suriname',continent:'samerica'},UY:{name:'Uruguay',continent:'samerica'},VE:{name:'Venezuela',continent:'samerica'},
  AS:{name:'American Samoa',continent:'oceania'},AU:{name:'Australia',continent:'oceania'},CK:{name:'Cook Islands',continent:'oceania'},FJ:{name:'Fiji',continent:'oceania'},PF:{name:'French Polynesia',continent:'oceania'},GU:{name:'Guam',continent:'oceania'},KI:{name:'Kiribati',continent:'oceania'},MH:{name:'Marshall Islands',continent:'oceania'},FM:{name:'Micronesia',continent:'oceania'},NR:{name:'Nauru',continent:'oceania'},NC:{name:'New Caledonia',continent:'oceania'},NZ:{name:'New Zealand',continent:'oceania'},NU:{name:'Niue',continent:'oceania'},NF:{name:'Norfolk Island',continent:'oceania'},MP:{name:'Northern Mariana Islands',continent:'oceania'},PW:{name:'Palau',continent:'oceania'},PG:{name:'Papua New Guinea',continent:'oceania'},PN:{name:'Pitcairn Islands',continent:'oceania'},WS:{name:'Samoa',continent:'oceania'},SB:{name:'Solomon Islands',continent:'oceania'},TK:{name:'Tokelau',continent:'oceania'},TO:{name:'Tonga',continent:'oceania'},TV:{name:'Tuvalu',continent:'oceania'},VU:{name:'Vanuatu',continent:'oceania'},WF:{name:'Wallis and Futuna',continent:'oceania'},
  AQ:{name:'Antarctica',continent:'other'},TF:{name:'French Southern Territories',continent:'other'},BV:{name:'Bouvet Island',continent:'other'},HM:{name:'Heard Island and McDonald Islands',continent:'other'},GS:{name:'South Georgia and South Sandwich Islands',continent:'other'},UM:{name:'U.S. Minor Outlying Islands',continent:'other'}
};
// 代碼查不到時（表格未收錄，或匯入資料庫本身用非 ISO 碼的其他寫法）優雅降級：continent 歸
// 'other'，name 原樣顯示輸入字串，不會因表格不完整而整個功能壞掉。CSV 型資料庫可能直接用
// 全名而非 ISO 碼（如既有 GEO_COUNTRY_GROUPS 的 aliases 本身就有全名），故查不到代碼時再嘗試
// 用名稱反查一次
function resolveCountryInfo(raw) {
  const code = String(raw).trim().toUpperCase();
  if (COUNTRY_INFO[code]) return { code, name: COUNTRY_INFO[code].name, continent: COUNTRY_INFO[code].continent };
  const hit = Object.entries(COUNTRY_INFO).find(([, info]) => info.name.toLowerCase() === code.toLowerCase());
  if (hit) return { code: hit[0], name: hit[1].name, continent: hit[1].continent };
  return { code: null, name: String(raw), continent: 'other' };
}
// ── 調查案件包（2026-10-22，第三十三輪 XN11）────────────────────────────────
// 勾選的問題（relatedEvents）＋行為者（eventMatchesActor）的事件合併成時間軸，同一事件只列一次，依時間排序，
// 超過 CASE_MAX_EVENTS 筆只保留最早的部分並記錄總數。去識別化由 UI 端以整份 log 的 ANON_EVENTS 對應替換
// （與「下載去識別化 log」「匯出對照表」同一組假值），問題摘要與行為者名稱以 caseReplaceMapped() 依對照表替換
const CASE_MAX_EVENTS = 500;
function buildCaseTimeline(issues, actors, events) {
  const seen = new Set(), out = [];
  const add = e => { if (e && !seen.has(e)) { seen.add(e); out.push(e); } };
  (issues || []).forEach(is => (is.relatedEvents || []).forEach(add));
  (actors || []).forEach(a => (events || []).forEach(e => { if (eventMatchesActor(e, a)) add(e); }));
  out.sort((x, y) => (effectiveTime(x) || 0) - (effectiveTime(y) || 0));
  return { events: out.slice(0, CASE_MAX_EVENTS), total: out.length };
}
// pairs：[原值, 假值]；長的先換，原值前後不可緊接英數字、點或冒號（避免 10.0.0.1 誤換 10.0.0.12 的前段）
// MAC 對照（mappings.mac：鍵為去掉分隔符號的 12 位十六進位，值為 {hex}）→ 案件包替換用的 [原值, 假值]：
// 摘要與備註可能寫成冒號、連字號、點或不分隔，各種寫法都對應到同格式的假值
function caseMacPairs(macMap) {
  const out = [];
  for (const [n, v] of macMap || []) {
    const o = String(n).match(/.{2}/g), f = String((v && v.hex) || v).match(/.{2}/g);
    if (!o || !f || o.length !== 6 || f.length !== 6) continue;
    out.push([o.join(':'), f.join(':')], [o.join('-'), f.join('-')], [o.join('').match(/.{4}/g).join('.'), f.join('').match(/.{4}/g).join('.')], [o.join(''), f.join('')]);
  }
  return out;
}
function caseReplaceMapped(text, pairs) {
  let s = String(text == null ? '' : text);
  if (!pairs || !pairs.length) return s;
  const list = pairs.filter(([o]) => o).sort((a, b) => b[0].length - a[0].length);
  const map = new Map(list.map(([o, f]) => [o.toLowerCase(), f]));
  const re = new RegExp('(?<![\\w.:])(' + list.map(([o]) => o.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')(?![\\w:]|\\.\\w)', 'gi');
  return s.replace(re, m => map.get(m.toLowerCase()) || m);
}
// model：{title, summary, generatedAt, deid, totalEvents, labels:{…已翻譯字串}, issues:[{label, sev, sevLabel, count, mitre,
// basis, sample, status, note, first, last}], actors:[{actor, events, first, last}], events:[{time, host, cat, msg}]}
// 輸出自含 HTML（無 script，CSP 只允許內嵌樣式），所有值一律 esc()
function buildCasePackHtml(m) {
  const L = m.labels || {};
  const SEV = { Critical: '#ef4444', High: '#fb923c', Medium: '#f59e0b', Low: '#38bdf8', Info: '#64748b' };
  const td = v => `<td>${esc(v == null || v === '' ? '-' : v)}</td>`;
  const issues = (m.issues || []).map(i => `<tr><td>${esc(i.label)}${i.mitre ? ` <span class="mitre">${esc(i.mitre)}</span>` : ''}</td>` +
    `<td><span class="sev" style="background:${SEV[i.sev] || '#64748b'}">${esc(i.sevLabel)}</span></td>${td(i.count)}${td(i.first)}${td(i.last)}` +
    `<td class="mono">${esc(i.basis || '-')}</td><td class="mono">${esc(i.sample || '-')}</td>${td(i.status)}${td(i.note)}</tr>`).join('');
  const actors = (m.actors || []).map(a => `<tr>${td(a.actor)}${td(a.events)}${td(a.first)}${td(a.last)}</tr>`).join('');
  const events = (m.events || []).map(e => `<tr>${td(e.time)}${td(e.host)}${td(e.cat)}<td class="mono">${esc(e.msg || '-')}</td></tr>`).join('');
  // 指標（XN76）：外部位址、網域、雜湊；去識別化模式只顯示說明（假值不能拿去封鎖）
  const iocRows = (m.iocs || []).map(x => `<tr>${td(x.kind)}<td class="mono">${esc(x.value)}</td>${td(x.cats)}${td(x.sevLabel)}</tr>`).join('');
  // 憑證處置清單（XN91）：去識別化模式下識別碼已是假值，不附
  const rotRows = (m.rotation || []).map(r => `<tr><td>${esc(r.kind)}</td><td class="mono">${esc(r.id)}</td><td>${esc(r.where)}</td><td>${esc(r.cat)}</td></tr>`).join('');
  const rotSec = rotRows ? `<h2>${esc(L.rotTitle || '')}（${m.rotation.length}）</h2><p class="note">${esc(L.rotHint || '')}</p><table><thead><tr><th>${esc(L.rotKind || '')}</th><th>${esc(L.rotId || '')}</th><th>${esc(L.rotWhere || '')}</th><th>${esc(L.rotSource || '')}</th></tr></thead><tbody>${rotRows}</tbody></table>` : '';
  const iocSec = m.iocDeid ? `<h2>${esc(L.iocs)}</h2><p class="note">${esc(L.iocDeid || '')}</p>`
    : iocRows ? `<h2>${esc(L.iocs)}（${m.iocs.length}）</h2><p class="note">${esc(L.iocNote || '')}</p><table><thead><tr><th>${esc(L.colKind)}</th><th>${esc(L.colValue)}</th><th>${esc(L.colCategory)}</th><th>${esc(L.colSeverity)}</th></tr></thead><tbody>${iocRows}</tbody></table>` +
      `<pre class="mono" style="background:#f8fafc;border:1px solid #cbd5e1;padding:8px;font-size:12px;white-space:pre-wrap">${esc(m.iocs.map(x => x.value).join('\n'))}</pre>` : '';
  const more = m.totalEvents > (m.events || []).length ? `<p class="note">${esc(String(L.truncated || '').replace('{n}', (m.events || []).length).replace('{total}', m.totalEvents))}</p>` : '';
  return `<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(m.title || L.title)}</title>
<style>body{font-family:system-ui,"Microsoft JhengHei",sans-serif;margin:24px;color:#1e293b;background:#fff}h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:22px 0 8px;border-bottom:1px solid #cbd5e1;padding-bottom:4px}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #cbd5e1;padding:4px 6px;text-align:left;vertical-align:top}th{background:#f1f5f9}
.mono{font-family:Consolas,Menlo,monospace;word-break:break-all}.sev{color:#fff;border-radius:3px;padding:1px 6px;font-size:11px}.mitre{background:#e0e7ff;color:#3730a3;border-radius:3px;padding:0 4px;font-size:11px}
.meta{color:#475569;font-size:12px}.note{color:#475569;font-size:12px}.summary{white-space:pre-wrap;background:#f8fafc;border-left:3px solid #6366f1;padding:8px 10px;font-size:13px}</style>
</head><body>
<h1>${esc(m.title || L.title)}</h1>
<div class="meta">${esc(L.generated || '')} ${esc(m.generatedAt || '')} · ${esc(m.deid ? L.deidOn : L.deidOff)}</div>
<p class="note">${esc(L.disclaimer || '')}</p>
${L.untrusted ? `<p class="note">${esc(L.untrusted)}</p>` : ''}
${m.summary ? `<h2>${esc(L.summary)}</h2><div class="summary">${esc(m.summary)}</div>` : ''}
<h2>${esc(L.issues)}（${(m.issues || []).length}）</h2>
${issues ? `<table><thead><tr><th>${esc(L.colCategory)}</th><th>${esc(L.colSeverity)}</th><th>${esc(L.colCount)}</th><th>${esc(L.colFirst)}</th><th>${esc(L.colLast)}</th><th>${esc(L.colBasis)}</th><th>${esc(L.colSample)}</th><th>${esc(L.colStatus)}</th><th>${esc(L.colNote)}</th></tr></thead><tbody>${issues}</tbody></table>` : `<p class="note">-</p>`}
${actors ? `<h2>${esc(L.actors)}（${(m.actors || []).length}）</h2><table><thead><tr><th>${esc(L.colActor)}</th><th>${esc(L.colEvents)}</th><th>${esc(L.colFirst)}</th><th>${esc(L.colLast)}</th></tr></thead><tbody>${actors}</tbody></table>` : ''}
${rotSec}
${iocSec}
<h2>${esc(L.timeline)}（${m.totalEvents || 0}）</h2>
${more}
${events ? `<table><thead><tr><th>${esc(L.colTime)}</th><th>${esc(L.colHost)}</th><th>${esc(L.colCategory)}</th><th>${esc(L.colMessage)}</th></tr></thead><tbody>${events}</tbody></table>` : `<p class="note">-</p>`}
</body></html>
`;
}
// ── 建議一併匯入的 log（2026-10-22，XN16 使用者調整）─────────────────────────
// COMPANION_SOURCES：依事件的 format／netVendor 判斷目前匯入了哪類來源；recs 為建議另外匯入的 log（comp.* 說明），
// 對應來源已經匯入的建議（COMPANION_COVERS）不再列出。服務異常的問題另帶 companions（detectServiceHealth）
const COMPANION_SOURCES = [
  ['firewall', e => ['asa', 'fortigate', 'pancsv', 'kvfw'].includes(e.format) || ['paloalto', 'checkpoint', 'junos', 'h3c', 'netfilter', 'sonicwall', 'sophos', 'pfsense', 'mikrotik', 'winfw', 'azfw', 'watchguard'].includes(e.netVendor), ['dhcp', 'aaa', 'dns', 'ids', 'edr']],
  ['winevent', e => e.format === 'winevent', ['dcLogs', 'sysmon', 'dns', 'dhcp', 'firewall']],
  ['ldap', e => e.format === 'ldap' || e.netVendor === 'ldap', ['journal', 'appClients', 'peerLdap', 'network']],
  ['radius', e => e.netVendor === 'freeradius' || e.format === 'radacct', ['ldapServer', 'dbServer', 'nas', 'homeServer', 'dhcp']],
  ['ise', e => e.netVendor === 'ciscoise', ['nas', 'ldapServer', 'dhcp']],
  // Windows NPS（XN65）：認證最終由網域控制站驗證帳號，RADIUS 用戶端是 AP／交換器
  ['nps', e => e.netVendor === 'nps', ['dcLogs', 'nas', 'dhcp']],
  // Aruba ClearPass（XN134）：認證來源多為 AD／LDAP，RADIUS 用戶端是 AP／交換器
  ['clearpass', e => e.netVendor === 'clearpass', ['dcLogs', 'nas', 'dhcp']],
  ['vpn', e => ['openvpn', 'strongswan', 'pcs'].includes(e.netVendor), ['aaa', 'firewall', 'dhcp']],
  // Ivanti Connect Secure（XN97）：設備韌體本工具不比對，固定提醒依官方公告確認修補
  ['pcs', e => e.netVendor === 'pcs', ['pcsFirmware']],
  ['dns', e => e.format === 'dns' || ['bind', 'dnsmasq', 'umbrella'].includes(e.netVendor), ['dhcp', 'firewall', 'edr']],
  ['dhcp', e => e.format === 'dhcp' || ['windhcp', 'iscdhcp'].includes(e.netVendor), ['dns', 'firewall', 'aaa']],
  ['web', e => e.format === 'w3c' || ['web', 'haproxy'].includes(e.netVendor), ['firewall', 'appLog', 'dns']],
  // Appsmith（XN79）：路徑屬 Appsmith 的 web 事件；GitLab 與資料庫稽核本工具不分析，建議保全
  // GitLab（XN81）：權杖與程式庫存取要搭配主機登入與連線紀錄確認
  ['gitlab', e => e.netVendor === 'gitlab', ['ssh', 'firewall', 'dbAudit']],
  ['appsmith', e => isWebEvent(e) && (APPSMITH_PATH_RE.test(e.fields.url) || /\/api\/v1\/users\//.test(e.fields.url)), ['appsmithOrigin', 'ssh', 'firewall', 'gitlab', 'dbAudit']],
  ['ids', e => ['suricata', 'zeek'].includes(e.netVendor), ['firewall', 'dns', 'dhcp', 'edr']],
  ['edr', e => ['falcon', 'defender', 'amp'].includes(e.netVendor), ['winevent', 'firewall', 'dns']],
  ['cloud', e => ['cloudtrail', 'azact', 'gcpaudit', 'entra', 'entraaudit', 'okta', 'm365', 'gws', 'duo'].includes(e.netVendor), ['flowlog', 'firewall', 'edr']],
  ['flowlog', e => e.format === 'flowlog', ['cloudAudit', 'ids']],
  ['k8s', e => e.netVendor === 'k8s', ['cloudAudit', 'appLog', 'flowlog']],
  ['ssh', e => e.netVendor === 'linuxauth', ['journal', 'firewall', 'aaa']],
  // 資料庫連線 log（XN90）：登入來源要搭配主機登入與連線紀錄確認
  ['db', e => !!(e.fields && e.fields.dbKind), ['firewall', 'ssh', 'appLog']],
  ['netdev', e => ['ciscoios', 'comware'].includes(e.format), ['aaa', 'dhcp', 'monitoring']],
];
// 建議項目 → 已匯入時視為已涵蓋的來源
const COMPANION_COVERS = { dhcp: ['dhcp'], dns: ['dns'], firewall: ['firewall'], ids: ['ids'], edr: ['edr'], winevent: ['winevent'], dcLogs: ['dcLogs'], sysmon: ['sysmon'],
  aaa: ['radius', 'ise', 'vpn', 'nps', 'clearpass'], ldapServer: ['ldap'], peerLdap: [], homeServer: [], nas: ['netdev'], flowlog: ['flowlog'], cloudAudit: ['cloud'], ssh: ['ssh'], fileAudit: [], appsmithOrigin: ['appsmithOrigin'], gitlab: ['gitlab'], dbAudit: ['db'], pcsFirmware: [] };
function companionSourcesOf(events) {
  const found = new Set();
  for (const e of events) for (const [id, test] of COMPANION_SOURCES) if (!found.has(id) && test(e)) found.add(id);
  return COMPANION_SOURCES.map(s => s[0]).filter(id => found.has(id));
}
// Windows 事件裡已經有網域控制站或 Sysmon 的事件時，對應建議視為已涵蓋（只看 DC 才會記錄的 Kerberos 4768／4769／4771）
const COMPANION_EXTRA_COVERS = [
  ['dcLogs', e => e.format === 'winevent' && !!e.fields && ['4768', '4769', '4771'].includes(e.fields.EventID)],
  ['sysmon', e => e.format === 'winevent' && !!e.fields && e.fields.Channel === SYSMON_CHANNEL],
  ['appsmithOrigin', e => !!e.fields && !!e.fields.origin],
];
function companionCoveredOf(events) {
  const found = new Set();
  for (const e of events) for (const [id, test] of COMPANION_EXTRA_COVERS) if (!found.has(id) && test(e)) found.add(id);
  return [...found];
}
// 回傳 [{source, recs:[未涵蓋的建議]}]；covered（選填）為 companionCoveredOf() 的結果
function companionRecsFor(sources, covered) {
  const have = new Set(sources.concat(covered || []));
  return sources.map(id => {
    const recs = (COMPANION_SOURCES.find(s => s[0] === id) || [, , []])[2].filter(r => !(COMPANION_COVERS[r] || []).some(src => have.has(src)));
    return { source: id, recs };
  }).filter(x => x.recs.length);
}
// ==== STATE / UI（以下不供測試沙箱抽取，依賴 document） ====
