// ============================================================
// [5] 威脅情資本機比對（僅本機靜態清單，不連網）
// ============================================================
// IP/CIDR 欄位名稱判斷準則，CSV 表頭與 JSON key 共用同一套規則；Spamhaus DROP 系列 JSON 匯出
// 用的欄位名稱是 "cidr" 非 "ip"/"addr"，故需涵蓋 cidr/network 而不只 ip/addr。
// 先前用無邊界的子字串比對（/ip|addr|cidr|network/i），"zip"／"equipment"／"recipient"／
// "principal" 等常見英文欄名都含字面 "ip" 子字串會被誤判命中，導致真正的 ip/domain 欄位
// 反而未被選中（誤判順序在前的欄位優先命中）（2026-09 全功能審查發現）。改用依大小寫轉換／
// 分隔符號切出的欄位「token」做精確比對，只有整個 token 等於已知詞彙、或以已知前綴+ip 組成
// 複合詞（如 srcip/dstip 這類威脅情資清單常見縮寫）才視為命中
function _fieldTokens(key) {
  return String(key).replace(/([a-z0-9])([A-Z])/g, '$1_$2').split(/[^A-Za-z0-9]+/).map(t => t.toLowerCase()).filter(Boolean);
}
const IP_FIELD_TOKENS = new Set(['ip', 'addr', 'address', 'cidr', 'network']);
const IP_FIELD_PREFIX_WORDS = new Set(['src', 'dst', 'source', 'destination', 'remote', 'local', 'client', 'server', 'attacker', 'victim', 'host', 'device']);
function isIPFieldName(key) {
  return _fieldTokens(key).some(t => {
    if (IP_FIELD_TOKENS.has(t)) return true;
    return t.length > 2 && t.endsWith('ip') && IP_FIELD_PREFIX_WORDS.has(t.slice(0, -2));
  });
}
// 相容既有呼叫端字面使用 IP_FIELD_RE.test(...) 的寫法
const IP_FIELD_RE = { test: isIPFieldName };

function extractIPFieldFromObj(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const key = Object.keys(obj).find(k => isIPFieldName(k));
  if (!key) return null;
  const v = obj[key];
  return (typeof v === 'string' || typeof v === 'number') ? String(v) : null;
}

// 2026-08-20 新增：威脅情資 domain 型清單支援（僅 exact match，不做萬用字元/子網域比對——
// 子網域比對規則因情資清單格式而異，查無統一標準，比照專案「不猜測」慣例先做最小可用版本）。
// DOMAIN_FIELD_RE 判斷準則同 IP_FIELD_RE，僅在 IP 欄位找不到時才 fallback 嘗試，避免誤把
// 同時含 ip 與 domain 兩欄的清單錯誤解讀成 domain 清單；同樣改用 token 精確比對（2026-09 全功能審查修復）
const DOMAIN_FIELD_TOKENS = new Set(['domain', 'fqdn', 'hostname']);
function isDomainFieldName(key) {
  return _fieldTokens(key).some(t => DOMAIN_FIELD_TOKENS.has(t));
}
const DOMAIN_FIELD_RE = { test: isDomainFieldName };
function extractDomainFieldFromObj(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const key = Object.keys(obj).find(k => isDomainFieldName(k));
  if (!key) return null;
  const v = obj[key];
  return (typeof v === 'string' || typeof v === 'number') ? String(v) : null;
}

// 通用 JSON/NDJSON 解析，情資清單與主要 log 匯入共用。涵蓋兩種常見形態：
// (1) NDJSON/JSON Lines——逐行各自是獨立合法 JSON 物件（Spamhaus DROP JSON 匯出即此格式，
//     整份檔案本身不是單一合法 JSON 文件，不能直接對整段文字做 JSON.parse）
// (2) 標準 JSON——單一陣列，或物件包一層陣列欄位（如 {"data":[...]}）
// 「整段文字剛好是單一 JSON 物件」的情況回傳於 singleObj，是否要當作 1 筆資料處理交給呼叫端
// 各自判斷（情資清單看有沒有 IP 欄位，log 匯入看像不像一筆事件），避免把判斷邏輯耦合在共用函式裡。
// 解析失敗（純文字/CSV 等非 JSON 格式）兩者皆回傳 null，讓呼叫端 fallback 到既有邏輯
function parseJSONOrNDJSON(text, objectArraysOnly) {
  const trimmed = text.trim();
  if (!trimmed) return { arr: null, singleObj: null };
  const lines = trimmed.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length > 1) {
    // 先前要求「每一行都必須合法 JSON」（allValid），只要有一行壞掉（如下載中斷、單筆記錄
    // 損毀）就整份退回下方的 JSON.parse(trimmed) 嘗試，該嘗試對非單一合法 JSON 文件的
    // NDJSON 文字必定失敗，最終連前面原本合法的每一行資料都一併靜默遺失。改為逐行
    // try/catch、壞行單獨跳過（比照同檔案 parseAsnDropList() 既有慣例），只計入解析成功
    // 且為物件的行；至少半數行成功才視為 NDJSON，比例過低代表這其實是分行排版過的單一
        // JSON 文件（pretty-print），仍退回下方整段解析路徑，避免把縮排片段誤判成多筆小物件
    // （2026-09 全功能審查發現）
    const objs = [];
    for (const l of lines) {
      // 只試 { 或 [ 開頭的行，一般文字 log 不必逐行丟例外（第二十八輪 OP3）
      if (l[0] !== '{' && l[0] !== '[') continue;
      // MySQL Enterprise Audit JSON 檔為陣列、每行結尾帶逗號（XN90），去掉結尾逗號再試
      try { const parsed = JSON.parse(l); if (parsed && typeof parsed === 'object') objs.push(parsed); } catch (e) {
        if (l.endsWith(',')) { try { const parsed = JSON.parse(l.slice(0, -1)); if (parsed && typeof parsed === 'object') objs.push(parsed); } catch (e2) { /* 壞行跳過 */ } }
      }
    }
    if (objs.length && objs.length >= lines.length / 2) return { arr: objs, singleObj: null };
  }
  try {
    const data = JSON.parse(trimmed);
    if (Array.isArray(data)) return { arr: data, singleObj: null };
    // 單筆 Zeek log 的 matched／sources 等欄位是陣列，不可當成資料陣列取出（第十八輪 TI）
    if (data && typeof data === 'object' && isZeekLog(data)) return { arr: null, singleObj: data };
    if (data && typeof data === 'object') {
      // objectArraysOnly（log 事件）：只把「元素是物件」的陣列當成資料陣列，tags 這類字串陣列是單筆 log 的欄位；
      // 情資清單仍接受 {"ips":["1.2.3.4"]} 這種字串陣列（深度掃描 2026-10-16）
      const arrKeys = Object.keys(data).filter(k => Array.isArray(data[k]) && (!objectArraysOnly || data[k].some(x => x && typeof x === 'object')));
      if (arrKeys.length) {
        // 物件內有多個陣列鍵時（常見威脅情資 API 回應形狀：metadata 陣列排在真正資料陣列
        // 之前），先前無條件取第一個陣列鍵，真正資料常因此被忽略。優先挑選「陣列元素本身
        // 是物件且含 IP/domain 特徵欄位」的鍵，其次挑選常見資料陣列命名慣例，皆無命中才
        // 維持原本「第一個陣列鍵」的 fallback 行為（2026-09 全功能審查發現）
        const COMMON_DATA_KEYS = new Set(['data', 'list', 'results', 'entries', 'items']);
        let arrKey = arrKeys.find(k => {
          const first = data[k][0];
          return first && typeof first === 'object' && !Array.isArray(first) &&
            Object.keys(first).some(fk => isIPFieldName(fk) || isDomainFieldName(fk));
        });
        if (!arrKey) arrKey = arrKeys.find(k => COMMON_DATA_KEYS.has(k.toLowerCase()));
        if (!arrKey) arrKey = arrKeys[0];
        return { arr: data[arrKey], singleObj: null };
      }
      return { arr: null, singleObj: data };
    }
  } catch (e) { /* 非 JSON，交給呼叫端 fallback 邏輯處理 */ }
  return { arr: null, singleObj: null };
}
function parseIntelListJSON(text) {
  const { arr, singleObj } = parseJSONOrNDJSON(text);
  if (arr) return arr;
  if (singleObj && ((intelIndicatorsFromObj(singleObj) || []).length || extractIPFieldFromObj(singleObj) || extractDomainFieldFromObj(singleObj))) return [singleObj];
  return null;
}

// 常見情資來源的指標欄位（第十九輪 EB）：OTX（indicator＋type）、abuse.ch URLhaus（url／host）、
// abuse.ch malware／MalwareBazaar（md5_hash／sha1_hash／sha256_hash）、MISP（Event.Attribute[]、
// Event.Object[].Attribute[] 的 type／value，複合型 a|b 依型別取對應段）、ThreatQ（value＋type.name）、
// STIX 2 indicator（pattern 中的 ipv4-addr／ipv6-addr／domain-name／url／file:hashes）。
// URL 取主機名稱；其他型別（檔名、登錄機碼、email 等）不取。回傳 null 代表不是這些來源的形狀
const INTEL_HASH_LENS = { 32: 'md5', 40: 'sha1', 64: 'sha256' };
function intelHostOfUrl(u) {
  const m = String(u || '').trim().match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)/i);
  return m ? m[1].replace(/^\[|\]$/g, '').toLowerCase() : null;
}
function intelValueByKind(kind, v) {
  if (v === undefined || v === null || v === '') return null;
  const s = String(v).trim();
  if (kind === 'url') return intelHostOfUrl(s);
  if (kind === 'hash') return /^[0-9a-f]+$/i.test(s) && INTEL_HASH_LENS[s.length] ? s.toLowerCase() : null;
  if (kind === 'domain') return s.toLowerCase();
  return s;   // ip／cidr
}
// 型別字串 → ip／domain／url／hash（不認得回傳空字串）
function intelKindOf(type) {
  const t = String(type || '').toLowerCase();
  if (/^(ip|ipv4|ipv6|ip address|ipv6 address|cidr|ip-src|ip-dst|ipv4-addr|ipv6-addr)$/.test(t)) return 'ip';
  if (/^(domain|hostname|fqdn|domain-name)$/.test(t)) return 'domain';
  if (/^(url|uri|link)$/.test(t)) return t === 'uri' ? '' : 'url';
  if (/^(md5|sha1|sha-1|sha256|sha-256|filehash-md5|filehash-sha1|filehash-sha256)$/.test(t)) return 'hash';
  return '';
}
function intelIndicatorsFromObj(item) {
  if (!item || typeof item !== 'object') return null;
  const out = [];
  const push = (kind, v) => { const x = intelValueByKind(kind, v); if (x && !out.includes(x)) out.push(x); };
  if (typeof item.indicator === 'string' && item.type) {             // OTX
    push(intelKindOf(item.type), item.indicator); return out;
  }
  if (item.Event && typeof item.Event === 'object') {                 // MISP
    const attrs = [];
    const add = a => { if (Array.isArray(a)) attrs.push(...a); else if (a && typeof a === 'object') attrs.push(a); };
    add(item.Event.Attribute);
    (Array.isArray(item.Event.Object) ? item.Event.Object : (item.Event.Object ? [item.Event.Object] : [])).forEach(o => add(o && o.Attribute));
    attrs.forEach(a => {
      const types = String(a.type || '').split('|'), vals = String(a.value || '').split('|');
      types.forEach((t, i) => { const k = intelKindOf(t); if (k) push(k, vals[i]); });
    });
    return out;
  }
  if (typeof item.pattern === 'string' && /\[\s*[a-z0-9-]+:/i.test(item.pattern)) {   // STIX 2
    const re = /([a-z0-9-]+):([a-z0-9_.'-]+)\s*=\s*'((?:[^'\\]|\\.)*)'/gi;
    let m;
    while ((m = re.exec(item.pattern))) {
      const obj = m[1].toLowerCase();
      if (obj === 'file' && /^hashes\./i.test(m[2])) push('hash', m[3]);
      else if (m[2].toLowerCase() === 'value') push(intelKindOf(obj), m[3]);
    }
    return out;
  }
  if (item.value !== undefined && item.type && typeof item.type === 'object' && item.type.name) {   // ThreatQ
    push(intelKindOf(item.type.name), item.value); return out;
  }
  if (item.urlhaus_reference || (typeof item.url === 'string' && typeof item.host === 'string')) {   // URLhaus
    push('ip', item.host || intelHostOfUrl(item.url)); return out;
  }
  if (item.md5_hash || item.sha256_hash || item.sha1_hash) {          // abuse.ch malware／MalwareBazaar
    push('hash', item.sha256_hash); push('hash', item.sha1_hash); push('hash', item.md5_hash); return out;
  }
  return null;
}

function parseIntelList(text, name) {
  const norm = text.replace(/\r\n/g, '\n');
  const jsonArr = parseIntelListJSON(norm);
  if (jsonArr) {
    const entries = [];
    jsonArr.forEach(item => {
      if (typeof item === 'string') { entries.push({ value: item, meta: {} }); return; }
      const known = intelIndicatorsFromObj(item);
      if (known) { known.forEach(v => entries.push({ value: v, meta: item })); return; }
      const val = extractIPFieldFromObj(item) || extractDomainFieldFromObj(item);
      if (val) entries.push({ value: val, meta: item });
    });
    return { name: name || '未命名清單', entries };
  }
  const lines = norm.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#') && !l.startsWith(';'));
  const entries = [];
  const isCSV = lines.length > 0 && lines[0].includes(',');
  if (isCSV) {
    const header = lines[0].split(',').map(h => h.trim().toLowerCase());
    const ipCol = header.findIndex(h => IP_FIELD_RE.test(h));
    // domain 欄位偵測（2026-08-20 新增）：只在找不到 IP 欄位時才 fallback 嘗試，找不到
    // 兩者其中之一時仍沿用既有慣例退回第一欄，避免破壞既有無表頭關鍵字的 CSV 清單相容性
    const domCol = ipCol < 0 ? header.findIndex(h => DOMAIN_FIELD_RE.test(h)) : -1;
    const valCol = ipCol >= 0 ? ipCol : (domCol >= 0 ? domCol : 0);
    for (let i = 1; i < lines.length; i++) {
      const cols = lines[i].split(',');
      const val = (cols[valCol] || '').trim();
      if (val) entries.push({ value: val, meta: Object.fromEntries(header.map((h, idx) => [h, (cols[idx] || '').trim()])) });
    }
  } else {
    lines.forEach(l => { const v = l.split(/\s+/)[0]; if (v) entries.push({ value: v, meta: {} }); });
  }
  return { name: name || '未命名清單', entries };
}

