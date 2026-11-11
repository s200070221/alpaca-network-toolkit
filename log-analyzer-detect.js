// ============================================================
// IP→ASN 資料庫解析＋查詢（2026-08-23 新增，純函式，尚未接線任何 UI）：補齊已知限制
// 「Spamhaus ASN-DROP 這類以 ASN 為主鍵的情資不支援比對，需額外 IP→ASN 資料庫」缺的那塊——
// 讓「給一個 IP，查出它屬於哪個 ASN」變成可能。三個常見免費來源（IPtoASN.com ip2asn-*.tsv／
// DB-IP IP to ASN Lite CSV／IPinfo.io ASN CSV）皆已對外查證，欄位順序共通為
// 「起始IP, 結束IP, ASN, [組織名稱...]」，差異只在分隔符（IPtoASN 為 tab，其餘為逗號）與
// 欄位數；不寫死三套獨立 parser，改用內容特徵定位 ASN 欄位（比照本檔 IP_FIELD_RE 用內容
// 而非寫死欄位名稱的既有慣例），單一函式涵蓋三個來源。
// ============================================================

function intToIpv4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}
// BigInt → 完整展開（無 "::" 縮寫）的 8 組 16-bit hex 字串，供 CIDR 字串輸出；
// ipv6ToBigInt() 本來就接受無縮寫的 8 組形式，不需要額外做 "::" 壓縮
function bigIntToIpv6(big) {
  const groups = [];
  for (let i = 7; i >= 0; i--) groups.push(((big >> BigInt(i * 16)) & 0xFFFFn).toString(16));
  return groups.join(':');
}
// Range→CIDR 標準演算法：從 start 開始，每次找「目前位址對齊、且不超出範圍終點 end」的
// 最大區塊，輸出成 CIDR，移動到下一段，直到覆蓋整個範圍。用 Math.pow 而非 << 位元位移計算
// 區塊大小——JS 的 << 對位移量取模 32（"1<<32" 錯誤地等於 1 而非 4294967296），最大可能
// 區塊（整個 /0）必須避開位元運算，改用一般數字運算（IPv4 32-bit 範圍內精度足夠安全）
function ipv4RangeToCIDRs(startIp, endIp) {
  let start = ipToInt(startIp); const end = ipToInt(endIp);
  if (start === null || end === null || start > end) return [];
  const cidrs = [];
  while (start <= end) {
    let maxBlockBits = 0;
    for (let b = 0; b <= 32; b++) { if (start % Math.pow(2, b) === 0) maxBlockBits = b; else break; }
    while (maxBlockBits > 0 && (start + Math.pow(2, maxBlockBits) - 1) > end) maxBlockBits--;
    cidrs.push(intToIpv4(start) + '/' + (32 - maxBlockBits));
    start += Math.pow(2, maxBlockBits);
  }
  return cidrs;
}
// 同上演算法，IPv6 版本改用 BigInt（128-bit，見 ipv6ToBigInt()/ipv6MaskForBits() 既有慣例）
function ipv6RangeToCIDRs(startIp, endIp) {
  let start = ipv6ToBigInt(startIp); const end = ipv6ToBigInt(endIp);
  if (start === null || end === null || start > end) return [];
  const cidrs = [];
  while (start <= end) {
    let maxBlockBits = 0n;
    for (let b = 0n; b <= 128n; b++) { if (start % (2n ** b) === 0n) maxBlockBits = b; else break; }
    while (maxBlockBits > 0n && (start + (2n ** maxBlockBits) - 1n) > end) maxBlockBits--;
    cidrs.push(bigIntToIpv6(start) + '/' + (128n - maxBlockBits).toString());
    start += 2n ** maxBlockBits;
  }
  return cidrs;
}
// 輸出形狀與 parseIntelList() 完全相同 {name, entries:[{value, meta}]}，buildIntelIndex()
// 不需任何修改即可直接吃。範圍不保證對齊 CIDR 邊界，逐列拆成一或多個 CIDR；同一 ASN 對應
// 多筆 entries 是既有索引設計本來就支援的形狀（GeoIP CIDR 資料庫就是同一種「一個屬性對應
// 多個不連續 CIDR」形狀）。ASN 欄位找不到（如表頭列，"asn"/"asn_number" 這類欄名不符合
// AS+數字的格式特徵）或 ASN=0（IPtoASN 未分配/不可路由慣例）皆靜默跳過，比照 buildIntelIndex()
// 對無效 CIDR 的既有寬容慣例
// 簡易 RFC4180 引號感知逐欄切割：本檔既有 parseIntelList() 的 CSV 路徑是單純 split(',')，
// 但 ASN 組織名稱常見內嵌逗號（如 IPinfo.io 真實資料 "Cloudflare, Inc."），沿用簡單切割
// 會誤切成多欄；僅供 parseAsnDatabase() 使用，不影響 parseIntelList() 既有行為/既有測試
function splitCSVLine(line) {
  const out = []; let cur = ''; let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else { inQuotes = false; } }
      else cur += c;
    } else {
      if (c === '"') inQuotes = true;
      else if (c === ',') { out.push(cur); cur = ''; }
      else cur += c;
    }
  }
  out.push(cur);
  return out;
}
// 2026-08-23 改為 chunked async：完整版 IP→ASN 資料庫常有數十萬列（比多數 GeoIP CIDR
// 清單大一截），同步一次跑完會卡住主執行緒。比照 buildIntelIndex() 既有慣例，用同一個
// INTEL_INDEX_CHUNK／yieldToUI()（皆定義在本檔下方，函式宣告會被提升，執行期呼叫不受
// 文字順序影響）每處理 CHUNK 行讓出一次主執行緒；onProgress(done, total) 選填，供未來
// 若接線上傳 UI 時顯示進度百分比，省略時行為不變（純函式呼叫端需 await，這是本次
// 改動唯一的破壞性變更——呼叫端已同步更新）
async function parseAsnDatabase(text, name, onProgress) {
  const norm = text.replace(/\r\n/g, '\n');
  const lines = norm.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  const entries = [];
  if (!lines.length) return { name: name || '未命名 ASN 資料庫', entries };
  const delim = lines[0].includes('\t') ? '\t' : ',';
  for (let li = 0; li < lines.length; li++) {
    if (li > 0 && li % INTEL_INDEX_CHUNK === 0) { await yieldToUI(); if (onProgress) onProgress(li, lines.length); }
    const line = lines[li];
    const cols = (delim === '\t' ? line.split('\t') : splitCSVLine(line)).map(c => c.trim());
    if (cols.length < 3) continue;
    const startIp = cols[0], endIp = cols[1];
    let asn = null, asnColIdx = -1;
    for (let i = 2; i < cols.length; i++) {
      const m = /^(?:AS)?(\d+)$/i.exec(cols[i]);
      if (m) { asn = m[1]; asnColIdx = i; break; }
    }
    if (asn === null || asn === '0') continue;
    const asName = cols.slice(asnColIdx + 1).join(', ');
    const isV6 = startIp.includes(':');
    const cidrs = isV6 ? ipv6RangeToCIDRs(startIp, endIp) : ipv4RangeToCIDRs(startIp, endIp);
    cidrs.forEach(cidr => entries.push({ value: cidr, meta: { asn: 'AS' + asn, asName } }));
  }
  return { name: name || '未命名 ASN 資料庫', entries };
}
// 薄封裝：intelLookup() 已經會回傳命中 entry，這裡只是少打一次 .meta，方便查詢端直接拿到
// {asn, asName}；索引本身用既有 buildIntelIndex(parseAsnDatabase(text, name)) 建立即可，
// 不需要專用的建索引函式
function lookupASN(asnIndex, ip) {
  const hit = intelLookup(asnIndex, ip);
  return hit ? { asn: hit.meta.asn, asName: hit.meta.asName } : null;
}

// 風險 ASN 清單解析（如 Spamhaus ASN-DROP，2026-08-31 新增）：直接 fetch 官方
// https://www.spamhaus.org/drop/asndrop.txt 確認該檔案本身已於 2026 年停用（內容僅剩三行
// 註解，指向 JSON 版本），再直接 fetch https://www.spamhaus.org/drop/asndrop.json 逐行確認
// 真實格式為 JSON Lines（非單一 JSON 陣列，逐行各自一個完整 JSON 物件，行與行之間沒有逗號
// 分隔），每筆記錄形如 {"asn":245,"rir":"arin","domain":"...","cc":"US","asname":"PRC-AS"}，
// 本函式只需要 asn／asname 兩個欄位，其餘（rir/domain/cc）非本工具風險比對範圍不擷取。
// 與 parseAsnDatabase() 是完全不同性質的資料（後者是 IP range→ASN 對照表，前者是純 ASN
// 風險名單、無任何 IP 欄位），故獨立成一個函式、不共用解析邏輯或索引結構。
function parseAsnDropList(text) {
  const list = [];
  const seen = new Set();
  (text || '').split(/\r?\n/).forEach(line => {
    const t = line.trim();
    if (!t || t.startsWith(';') || t.startsWith('#')) return; // 相容舊版 .txt 的分號註解行
    let obj;
    try { obj = JSON.parse(t); } catch (e) { return; }
    if (!obj || typeof obj.asn !== 'number') return;
    const asn = 'AS' + obj.asn;
    if (seen.has(asn)) return;
    seen.add(asn);
    list.push({ asn, asName: obj.asname || '' });
  });
  return list;
}

// v2fly/Xray geoip.dat：protobuf 二進位格式，schema 固定為
// GeoIPList{repeated GeoIP entry=1{string country_code=1; repeated CIDR cidr=2{bytes ip=1; uint32 prefix=2;}}}。
// 手刻 varint + length-delimited 通用解碼（依 tag/wireType 判讀，非猜測固定 byte offset），
// 只需支援這一種已知 schema，不引入任何 protobuf 函式庫（比照全套工具零依賴原則）
function geoDatReadVarint(bytes, pos) {
  let result = 0, mul = 1, b;
  do {
    b = bytes[pos++];
    result += (b & 0x7f) * mul;
    mul *= 128;
  } while (b & 0x80);
  return [result, pos];
}
function geoDatReadTag(bytes, pos) {
  const [v, next] = geoDatReadVarint(bytes, pos);
  return [v >>> 3, v & 0x7, next];
}
function geoDatReadLenDelim(bytes, pos) {
  const [len, next] = geoDatReadVarint(bytes, pos);
  return [bytes.slice(next, next + len), next + len];
}
function geoDatParseCIDR(bytes) {
  let pos = 0, ip = null, prefix = null;
  while (pos < bytes.length) {
    const [fieldNum, wireType, next] = geoDatReadTag(bytes, pos);
    pos = next;
    if (wireType === 2) {
      const [val, next2] = geoDatReadLenDelim(bytes, pos);
      pos = next2;
      if (fieldNum === 1) ip = val;
    } else if (wireType === 0) {
      const [val, next2] = geoDatReadVarint(bytes, pos);
      pos = next2;
      if (fieldNum === 2) prefix = val;
    } else {
      break; // 非預期的 wire type，schema 外欄位，停止解析這個子訊息
    }
  }
  return { ip, prefix };
}
function geoDatParseEntry(bytes) {
  let pos = 0, countryCode = '', cidrs = [];
  while (pos < bytes.length) {
    const [fieldNum, wireType, next] = geoDatReadTag(bytes, pos);
    pos = next;
    if (wireType !== 2) break; // GeoIP 訊息兩個欄位皆為 length-delimited
    const [val, next2] = geoDatReadLenDelim(bytes, pos);
    pos = next2;
    if (fieldNum === 1) countryCode = new TextDecoder().decode(val);
    else if (fieldNum === 2) cidrs.push(geoDatParseCIDR(val));
  }
  return { countryCode, cidrs };
}
// 16-byte raw IPv6 → 冒號十六進位字串，套用最長連續零群組的 "::" 縮寫（僅縮寫首個最長的
// 連續零群組，符合一般慣例；ip.dat 記錄本身無壓縮格式需求，此處純粹是為了可讀性與讓
// buildIntelIndex()/ipv6ToBigInt() 能正常解析）
function formatIPv6Bytes(bytes) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  groups.forEach((g, i) => {
    if (g === '0') { if (curStart === -1) curStart = i; curLen++; }
    else { if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; } curStart = -1; curLen = 0; }
  });
  if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
  if (bestLen < 2) return groups.join(':');
  const head = groups.slice(0, bestStart).join(':');
  const tail = groups.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}
// 輸出形狀與 parseIntelList() 一致（{name, entries:[{value, meta}]}），可直接餵給既有
// buildIntelIndex()，索引/查詢/CIDR 分桶效能優化全數共用，不重新設計一套比對邏輯
function parseGeoIPDat(buffer) {
  const bytes = new Uint8Array(buffer);
  let pos = 0;
  const entries = [];
  while (pos < bytes.length) {
    const [fieldNum, wireType, next] = geoDatReadTag(bytes, pos);
    pos = next;
    if (wireType !== 2) break;
    const [val, next2] = geoDatReadLenDelim(bytes, pos);
    pos = next2;
    if (fieldNum !== 1) continue;
    const entry = geoDatParseEntry(val);
    entry.cidrs.forEach(c => {
      if (!c.ip || (c.ip.length !== 4 && c.ip.length !== 16)) return; // 僅解析 IPv4(4-byte)/IPv6(16-byte)
      const value = c.ip.length === 4 ? `${Array.from(c.ip).join('.')}/${c.prefix}` : `${formatIPv6Bytes(c.ip)}/${c.prefix}`;
      entries.push({ value, meta: { country: entry.countryCode } });
    });
  }
  return { name: 'geoip.dat', entries };
}
function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
// IPv6 是 128-bit，JS 位元運算子（<<、>>>）僅支援 32-bit，改用 BigInt。"::" 縮寫展開成 8
// 組 16-bit hex 後串成單一 BigInt；格式不合法（如多個 "::"、非 hex 字元、組數不對）回傳 null
function ipv6ToBigInt(ip) {
  if (!ip || ip.indexOf(':') === -1) return null;
  const parts = ip.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  if (parts.length === 1) { if (head.length !== 8) return null; }
  else if (head.length + tail.length >= 8) return null;
  const missing = parts.length === 2 ? 8 - head.length - tail.length : 0;
  const groups = parts.length === 2 ? [...head, ...Array(missing).fill('0'), ...tail] : head;
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}
// 2026-08-10 效能修復：真實規模 GeoIP 資料庫（如完整版 v2fly geoip.dat，數十萬筆 IPv6 CIDR）
// 實測顯示 buildIntelIndex() 在混入大量 IPv6 entries 時耗時遠超線性成長（113萬筆/15%v6 約
// 5 秒，340萬筆/15%v6 卻要 36 秒），根因是這個函式原本每筆 entry 都重新做一次 BigInt 位移
// 運算，但前綴長度實際只有 0-128 共 129 種可能值，數十萬筆 entries 等於重複計算同樣的答案
// 數十萬次。改用小型快取（最多 129 筆，記憶體成本可忽略），同一前綴長度只計算一次
const _ipv6MaskCache = new Map();
function ipv6MaskForBits(bits) {
  let m = _ipv6MaskCache.get(bits);
  if (m === undefined) {
    m = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
    _ipv6MaskCache.set(bits, m);
  }
  return m;
}
function cidrMatch(ip, cidr) {
  const [base, bits] = cidr.split('/');
  const ipInt = ipToInt(ip), baseInt = ipToInt(base);
  if (ipInt === null || baseInt === null) return false;
  const maskBits = bits === undefined ? 32 : Number(bits);
  if (maskBits === 0) return true;
  const mask = maskBits >= 32 ? 0xFFFFFFFF : (~((1 << (32 - maskBits)) - 1)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}
// CIDR 條目依前綴長度（bits，如 /16~/32，實務上一份清單最多幾十種）分桶存放，每桶是
// 「遮罩後的網段整數 → entry」的 Map；查詢時只需對清單裡實際出現過的前綴長度各做一次遮罩＋
// Map.get()，取代逐筆走訪比對。大量 CIDR（數千筆）情資清單下是數百倍等級的加速——原本
// intelLookup() 是 O(CIDR 筆數) 線性掃描，真實規模（如 fetch_threat_intel.ps1 合併出的
// 數千筆 CIDR）疊加大量 log 事件時，會是造成瀏覽器「卡住」的根本原因，不是單純檔案讀取慢
// countries：附帶收集 entry.meta.country 的 distinct 值（排序後陣列），供 GeoIP 資料庫比對
// UI 動態產生「該資料庫實際涵蓋哪些國家」的勾選清單使用（見 getImportedGeoCountries()）。
// 對 INTEL_LISTS／SAFE_LISTS 這類沒有 country 欄位的一般情資清單而言只是多一個空陣列，
// 成本可忽略，不需要為 GeoIP 另開一份專用索引函式
// 2026-08-10 稽核修復：原本用 forEach() 一次跑完整份清單，大型清單（真實 GeoIP 資料庫常見
// 數十萬筆）會同步阻塞主執行緒近 1 秒甚至更久、期間畫面完全無回應，使用者會誤以為當掉。
// 改為 async + 一般 for 迴圈，每處理 CHUNK 筆呼叫一次 yieldToUI() 讓出主執行緒，讓瀏覽器
// 分頁在整個建索引過程中維持可重繪/可互動（三個呼叫端 doIntelUpload/doSafelistUpload/
// doGeoUpload 皆已改為 async 並 await 本函式，見對應段落）
const INTEL_INDEX_CHUNK = 5000;
// 讓出一次主執行緒（純函式、不依賴 document，故放在測試沙箱可抽取的範圍內，供 buildIntelIndex()
// 這類大型清單分段處理使用）。改用 MessageChannel（業界標準的 setImmediate polyfill 手法）而非
// setTimeout(fn,0)：瀏覽器對密集/巢狀零延遲計時器有最短延遲節流（HTML5 規範規定連續巢狀呼叫從
// 第 5 層起最短 4ms，背景分頁節流更嚴重），大型 GeoIP 資料庫（buildIntelIndex 每 5000 筆 yield
// 一次，340萬筆等於 680 次呼叫）實測光是 setTimeout 版 yieldToUI() 本身就吃掉 10 秒以上，是
// 2026-08-10 稽核修復「上傳完全卡死」的主因之一；MessageChannel 不受此節流限制，同樣 680 次
// 呼叫實測從 10 秒降到 50 毫秒
function yieldToUI() {
  return new Promise(resolve => {
    const ch = new MessageChannel();
    ch.port2.onmessage = () => resolve();
    ch.port1.postMessage(null);
  });
}
// onProgress(done, total) 選填：處理大型清單時每 CHUNK 筆回報一次進度，供上傳函式更新按鈕
// 文字顯示百分比（見 doIntelUpload/doSafelistUpload/doGeoUpload）；省略時行為不變、向下相容
async function buildIntelIndex(intelList, onProgress) {
  const exact = new Map(), cidrByPrefix = new Map(), cidr6ByPrefix = new Map(), countrySet = new Set();
  let cidrCount = 0, cidr6Count = 0, hasBroadCidr = false;
  const entries = intelList.entries;
  for (let i = 0; i < entries.length; i++) {
    if (i > 0 && i % INTEL_INDEX_CHUNK === 0) { await yieldToUI(); if (onProgress) onProgress(i, entries.length); }
    const e = entries[i];
    if (e.meta && e.meta.country) countrySet.add(e.meta.country);
    if (!e.value.includes('/')) {
      // 單一位址（IPv4/IPv6 皆可）：intelLookup() 的 exact.has(ip) 是純字串比對，本來就不挑
      // v4/v6，直接存進同一個 Map 即可，不需要分開處理。domain 型清單的條目也是走這條路徑
      // 存進同一個 exact Map（2026-08-20 新增，見 intelLookupDomain()）——DNS 名稱不分大小寫，
      // 存入前先正規化成小寫，查詢端 intelLookupDomain() 查詢時同步轉小寫才能正確命中
      // 2026-09-22 修復：先前只有「網域形狀」(isDomainShape()) 的條目會轉小寫，雜湊值（純
      // 十六進位、不含 '.'，不符合 DOMAIN_SHAPE_RE）原樣存入；但 extractCandidateHashes()
      // 抽取事件端雜湊時一律轉小寫，若情資清單內是大寫十六進位雜湊（VirusTotal 等常見匯出
      // 格式），exact.has() 永遠查不到、比對功能靜默失效。改為「非合法 IPv4 位址」
      // （ipToInt() 回傳 null）就一併轉小寫——雜湊與網域皆不分大小寫，IPv4 類值因為
      // ipToInt() 不為 null 而維持原樣，不影響既有 IPv4/CIDR 比對行為
      // 2026-09-22（續）修復：上一輪僅涵蓋雜湊，IPv6 位址（ipv6ToBigInt() 不為 null）當時仍
      // 被歸類為「IP 類值」而維持原樣不轉小寫，但 IPv6 十六進位部分本身大小寫不敏感（同一位
      // 址可用大寫或小寫十六進位表示），exact.has() 是純字串比對，情資清單與事件欄位擷取出
      // 的 IPv6 大小寫只要不一致就會靜默查無命中。改為只有「合法 IPv4 位址」才維持原樣，其餘
      // （IPv6／雜湊／網域，皆不分大小寫）一律轉小寫；查詢端 intelLookup() 對 IPv6 值同步轉
      // 小寫後才查 exact，CIDR/CIDR6 前綴比對是數值運算不受影響，不動到那條路徑
      const isIPv4Shape = ipToInt(e.value) !== null;
      exact.set(isIPv4Shape ? e.value : e.value.toLowerCase(), e); continue;
    }
    const [base, bitsRaw] = e.value.split('/');
    if (base.includes(':')) {
      const bits = bitsRaw === undefined ? 128 : Number(bitsRaw);
      const baseInt = ipv6ToBigInt(base);
      if (baseInt === null || !Number.isInteger(bits) || bits < 0 || bits > 128) continue; // 無效 CIDR 靜默略過，比照 IPv4 分支既有慣例
      // 2026-08-10 效能修復：真實 v2fly geoip.dat（77萬筆 IPv6，非本輪先前用隨機亂數合成測試
      // 資料能重現的規模）實測 Map 直接用 BigInt 當 key 會產生嚴重雜湊碰撞，20萬筆就要 14.5
      // 秒且資料量 x2 耗時 x4（明顯 O(n²)，隨機亂數 key 因雜湊分布均勻不會踩到這個問題，才會
      // 一直沒被抓到）；改用 BigInt.toString(36) 字串當 key 後同規模僅 0.3 秒，137萬筆全量僅
      // 2.7 秒，且恢復線性成長——V8 對字串的雜湊/相等比較是高度最佳化路徑，BigInt 則否
      const masked = (baseInt & ipv6MaskForBits(bits)).toString(36);
      if (!cidr6ByPrefix.has(bits)) cidr6ByPrefix.set(bits, new Map());
      cidr6ByPrefix.get(bits).set(masked, e);
      cidr6Count++;
      // IPv6 版的過寬 CIDR 警告，比例比照 IPv4（bits<=8 佔 32-bit 的 25%）：128-bit 的 25% 是 32
      if (bits <= 32) hasBroadCidr = true;
      continue;
    }
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    const baseInt = ipToInt(base);
    // 2026-08-09 稽核修復：原本只檢查 baseInt/bits 是否為 null/NaN，未驗證 bits 落在 0-32
    // 合法範圍；bits 為負數時（如格式錯誤的 "x.x.x.x/-1"）會落入下方位移運算，JS 位移運算子
    // 對 ≥32 的位移量取模 32，產生不可預期（非崩潰但邏輯錯誤）的遮罩值，而非被判定無效略過
    if (baseInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) continue; // 無效 CIDR 靜默略過，比照既有 cidrMatch() 對無效輸入回傳 false 的寬容慣例
    const mask = bits === 0 ? 0 : (bits >= 32 ? 0xFFFFFFFF : (~((1 << (32 - bits)) - 1)) >>> 0);
    const masked = (baseInt & mask) >>> 0;
    if (!cidrByPrefix.has(bits)) cidrByPrefix.set(bits, new Map());
    cidrByPrefix.get(bits).set(masked, e);
    cidrCount++;
    // 2026-08-09 稽核修復：CIDR /0 誤放入白名單（safeIndexes）會讓 matchThreatIntel() 對
    // 每一個候選 IP 都命中該索引直接 return，等於整個「已知情資命中」偵測全面靜默失效且
    // 無任何警告；prefix ≤ 8 已是異常寬鬆（單一條目涵蓋逾 1600 萬個位址），標記供上傳流程
    // 提示使用者（console.warn 供除錯；UI 端見 renderSafeList() 對 hasBroadCidr 的 ⚠️ 標示）
    if (bits <= 8) hasBroadCidr = true;
  }
  if (hasBroadCidr) console.warn(`[log_analyzer] 情資清單「${intelList.name}」含異常寬鬆的 CIDR（前綴 ≤ 8，IPv6 則 ≤ 32），若用於安全清單會讓比對全面失效`);
  return { name: intelList.name, exact, cidrByPrefix, cidr6ByPrefix, count: exact.size + cidrCount + cidr6Count, hasBroadCidr, countries: Array.from(countrySet).sort() };
}
// CIDR 桶依前綴長度由大到小（最具體優先）排序後才查詢——先前直接依 Map 插入順序（即該
// 前綴長度在清單中首次出現的順序）逐一嘗試，命中第一個就回傳，非「最長前綴匹配」。階層式
// 委派的清單（如 ISP 大區塊內再切出客戶專屬子區塊）會依清單列順序而非何者更具體決定命中
// 結果，同一份資料調換兩行順序就會給出不同答案（2026-09 全功能審查發現）。前綴長度種類
// 數量有限（IPv4 最多 33 種、IPv6 最多 129 種），每次查詢排序的額外開銷可忽略
function intelLookup(index, ip) {
  // IPv6 十六進位部分大小寫不敏感，buildIntelIndex() 已將 IPv6 exact 值正規化為小寫存入
  // （2026-09-22 續修復），查詢端比照轉小寫再查 exact，避免情資清單與事件擷取值大小寫不一致
  // 導致靜默查無命中；IPv4（不含 ':'）維持原樣，CIDR/CIDR6 前綴比對走數值運算不受此影響
  const exactKey = ip.includes(':') ? ip.toLowerCase() : ip;
  if (index.exact.has(exactKey)) return index.exact.get(exactKey);
  if (ip.includes(':')) {
    const ip6Int = ipv6ToBigInt(ip);
    if (ip6Int === null) return null;
    const bitsList6 = [...index.cidr6ByPrefix.keys()].sort((a, b) => b - a);
    for (const bits of bitsList6) {
      const bucket = index.cidr6ByPrefix.get(bits);
      const hit = bucket.get((ip6Int & ipv6MaskForBits(bits)).toString(36)); // key 格式須與 buildIntelIndex() 一致（字串非 BigInt，見上方效能修復註解）
      if (hit) return hit;
    }
    return null;
  }
  const ipInt = ipToInt(ip);
  if (ipInt === null) return null;
  const bitsList = [...index.cidrByPrefix.keys()].sort((a, b) => b - a);
  for (const bits of bitsList) {
    const bucket = index.cidrByPrefix.get(bits);
    const mask = bits === 0 ? 0 : (bits >= 32 ? 0xFFFFFFFF : (~((1 << (32 - bits)) - 1)) >>> 0);
    const hit = bucket.get((ipInt & mask) >>> 0);
    if (hit) return hit;
  }
  return null;
}
// domain 型情資（2026-08-20 新增）：exact match，不做萬用字元/子網域比對（見上方
// extractDomainFieldFromObj 註解）。查詢與存入（buildIntelIndex）皆先轉小寫再比對
const DOMAIN_SHAPE_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
function isDomainShape(v) { return DOMAIN_SHAPE_RE.test(v); }
function intelLookupDomain(index, domain) {
  return index.exact.get(String(domain).toLowerCase()) || null;
}
// 候選網域擷取欄位別名 + msg 文字掃描正則（要求至少一段字母 TLD，天然排除 IPv4/純數字誤判）
const DOMAIN_CANDIDATE_KEYS = ['domain', 'fqdn', 'url', 'requestUrl', 'request'];
const DOMAIN_SCAN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
function extractHostFromValue(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  if (!s) return null;
  const urlM = s.match(/^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i);
  if (urlM) return urlM[1].toLowerCase();
  return isDomainShape(s) ? s.toLowerCase() : null;
}
function extractCandidateDomains(evt) {
  const out = new Set();
  if (evt.fields) {
    const h = extractHostFromValue(pickField(evt.fields, DOMAIN_CANDIDATE_KEYS));
    if (h) out.add(h);
  }
  const scan = String(evt.msg || '').match(DOMAIN_SCAN_RE) || [];
  scan.forEach(m => { if (!isValidIPv4(m)) out.add(m.toLowerCase()); });
  return Array.from(out);
}
function extractCandidateIPs(evt) {
  if (evt.format === 'cef') return [evt.fields.src, evt.fields.dst, evt.fields.shost, evt.fields.dhost].filter(Boolean);
  // json/leef 皆有固定欄位別名可查（比照 getEventNetTuple()），結構化命中的 IP 與 msg 文字
  // 掃描結果併入（不取代），因為 msg 文字裡仍可能有額外 IP
  if ((evt.format === 'json' || evt.format === 'leef' || evt.format === 'fortigate' || evt.format === 'winevent') && evt.fields) {
    // FortiOS traffic log 的 srcip/dstip 在結構化 fields，msg 常是空字串；event/system log
    // 則相反（msg 有內容但通常不含 IP），兩者都掃，邏輯與既有 json/leef 分支一致
    const structured = [pickField(evt.fields, SRC_IP_KEYS), pickField(evt.fields, DST_IP_KEYS)].filter(Boolean);
    return Array.from(new Set([...structured, ...extractIPsFromText(evt.msg)]));
  }
  // RFC5424 Structured Data 無固定 SD-PARAM 命名規格，無法比照 json/leef 用別名精準指認
  // src/dst，改為對所有欄位值做通用 IP 掃描（情資比對只需要「是否出現過」，不需分辨 src/dst）
  if (evt.format === 'rfc5424' && evt.fields && Object.keys(evt.fields).length) {
    const sdText = Object.values(evt.fields).join(' ');
    return Array.from(new Set([...extractIPsFromText(sdText), ...extractIPsFromText(evt.msg)]));
  }
  return extractIPsFromText(evt.msg);
}
// IOC 萃取匯出（2026-09-16 新增，同日續作補上雜湊）：重用既有 extractCandidateIPs()/
// extractCandidateDomains()。雜湊 IOC 目前僅涵蓋 Sysmon EventID 1 的 Hashes 欄位（唯一帶
// 雜湊資料的既有欄位，detectSysmonKeywordWatchlist() 已把它列為比對欄位之一，但只當成不透明
// 字串塞進關鍵字比對 haystack，從未解析內部結構），格式為 KEY=VALUE,KEY=VALUE,...（如
// MD5=...,SHA256=...,IMPHASH=...）。僅解析 MD5/SHA1/SHA256 三種標準檔案雜湊（依長度驗證），
// IMPHASH（Import Hash，比對用途與檔案身分雜湊不同、非通用威脅情資格式）刻意不納入。其餘日誌
// 格式（CEF/LEEF/RFC5424/RFC3164/FortiGate/JSON）查無任何雜湊欄位既有 alias 或 fixture 佐證，
// 不新增臆測性解析
function extractCandidateHashes(evt) {
  const out = new Set();
  const raw = evt && evt.fields && evt.fields.Hashes;
  if (raw) {
    const lens = { MD5: 32, SHA1: 40, SHA256: 64 };
    String(raw).split(',').forEach(pair => {
      const eq = pair.indexOf('=');
      if (eq < 0) return;
      const key = pair.slice(0, eq).trim().toUpperCase();
      const v = pair.slice(eq + 1).trim();
      if (lens[key] && v.length === lens[key] && /^[0-9a-fA-F]+$/.test(v)) out.add(v.toLowerCase());
    });
  }
  // 端點與網路 log 的單一雜湊欄位（第十九輪 EC）：Cisco Secure Endpoint／CrowdStrike Falcon／
  // Microsoft Defender／Sophos 的 sha256、Falcon 的 md5、Zeek files.log 的 md5／sha1／sha256
  const f = evt && evt.fields;
  if (f && !f.Hashes) {
    [['md5', 32], ['sha1', 40], ['sha256', 64]].forEach(([k, n]) => {
      const v = typeof f[k] === 'string' ? f[k].trim() : '';
      if (v.length === n && /^[0-9a-fA-F]+$/.test(v)) out.add(v.toLowerCase());
    });
  }
  return Array.from(out);
}
function buildIOCList(events) {
  const ips = new Set();
  const domains = new Set();
  const hashes = new Set();
  (events || []).forEach(e => {
    extractCandidateIPs(e).forEach(v => ips.add(v));
    extractCandidateDomains(e).forEach(v => domains.add(v));
    extractCandidateHashes(e).forEach(v => hashes.add(v));
  });
  const out = [];
  ips.forEach(v => out.push({ type: 'ip', value: v }));
  domains.forEach(v => out.push({ type: 'domain', value: v }));
  hashes.forEach(v => out.push({ type: 'hash', value: v }));
  return out;
}
// IOC 匯出來源標記（2026-09-18 新增，「不需真實範例的 6 項新功能」第 2 項）：buildIOCList()
// 是既有純函式、已有 IOC-01~10 測試直接呼叫（簽章是吃扁平事件陣列），不修改以維持零回歸；
// 改用獨立函式從 issue 陣列（而非攤平後的事件）建立來源索引，doExportIOCs() 同時呼叫兩者、
// 查表附加額外欄位。同一 IP/網域/雜湊可能被多個不同分類命中（如同時是 knownIOC 又命中某條
// 自訂規則），故用 Set 收集全部來源分類，firstSeen 取最早時間。categories 存原始 category
// 字串（非人類可讀標籤）——issueCategoryLabel() 定義在 STATE/UI 邊界之後（依賴 ISSUES
// 全域變數查 custom: 前綴類別名稱），此函式維持純函式、可被主測試沙箱直接呼叫，標籤轉換
// 留給呼叫端 doExportIOCs()（本來就在邊界之後）負責
function buildIOCProvenanceIndex(issues) {
  const idx = new Map();
  const upsert = (is, type, value) => {
    const key = type + ':' + value;
    if (!idx.has(key)) idx.set(key, { categories: new Set(), severities: new Set(), firstSeen: null });
    const rec = idx.get(key);
    rec.categories.add(is.category);
    rec.severities.add(is.severityNorm);
    const t = issueTime(is, 'first');
    if (t && (rec.firstSeen === null || t < rec.firstSeen)) rec.firstSeen = t;
  };
  (issues || []).forEach(is => {
    (is.relatedEvents || []).forEach(e => {
      extractCandidateIPs(e).forEach(v => upsert(is, 'ip', v));
      extractCandidateDomains(e).forEach(v => upsert(is, 'domain', v));
      extractCandidateHashes(e).forEach(v => upsert(is, 'hash', v));
    });
  });
  return idx;
}
// ── IOC 匯出 STIX 2.1／MISP（2026-10-21，第三十三輪 XN10）────────────────────
// 與 CSV 同一批來源（問題清單相關事件），但這兩種格式是給外部情資平台用，另外：
//   - 只收格式正確的 IP（CEF 的 shost/dhost 可能是主機名稱）
//   - 排除內部與特殊用途位址（RFC1918、CGNAT、loopback、link-local、ULA、多播、保留），避免把內部網段送到外部平台；
//     文件用位址（RFC 5737／3849）不涉及隱私，保留
//   - 這些是「問題事件中出現過」的候選值，未經判定為惡意：STIX indicator_types 為 anomalous-activity，MISP to_ids 為 false
const IOC_INTERNAL_V4 = [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4]];
function iocIsInternalIP(ip) {
  const v = String(ip);
  if (isValidIPv4(v)) return IOC_INTERNAL_V4.some(([n, b]) => cidrMatch(v, n + '/' + b));
  const t = v.toLowerCase();
  return t === '::' || t === '::1' || /^f[cd][0-9a-f]{0,2}:/.test(t) || /^fe[89ab][0-9a-f]?:/.test(t) || /^ff[0-9a-f]{0,2}:/.test(t);
}
function iocIPKind(v) {
  if (isValidIPv4(v)) return 'ipv4';
  return /^[0-9a-f:.]+$/i.test(v) && v.includes(':') && (v.match(/:/g) || []).length >= 2 ? 'ipv6' : '';
}
const IOC_HASH_KIND = { 32: 'md5', 40: 'sha1', 64: 'sha256' };
// issues → [{kind:'ipv4'|'ipv6'|'domain'|'md5'|'sha1'|'sha256', value, categories:[], severity, firstSeen, asSrc}]
// 另回傳 excluded（被排除的內部位址數）；asSrc＝曾以來源位址出現（MISP ip-src／ip-dst 依此判斷）
function buildIOCExportRecords(issues) {
  const idx = buildIOCProvenanceIndex(issues);
  const srcs = new Set();
  (issues || []).forEach(is => (is.relatedEvents || []).forEach(e => { const s = getEventNetTuple(e).src; if (s && s !== '-') srcs.add(s); }));
  const records = [];
  let excluded = 0;
  idx.forEach((rec, key) => {
    const i = key.indexOf(':');
    const type = key.slice(0, i), value = key.slice(i + 1);
    let kind = type === 'domain' ? 'domain' : type === 'hash' ? IOC_HASH_KIND[value.length] : iocIPKind(value);
    if (!kind) return;
    if ((kind === 'ipv4' || kind === 'ipv6') && iocIsInternalIP(value)) { excluded++; return; }
    const severity = [...rec.severities].sort((a, b) => SEV_RANK[a] - SEV_RANK[b])[0] || '';
    // issueTime() 回傳毫秒數，轉成 Date 給 STIX valid_from／MISP 備註使用
    records.push({ kind, value, categories: [...rec.categories], severity, firstSeen: rec.firstSeen ? new Date(rec.firstSeen) : null, asSrc: srcs.has(value) });
  });
  return { records, excluded };
}
function iocUuid4() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
// STIX 2.1 patterning：字串常值內的 \ 與 ' 須跳脫；雜湊鍵 SHA-1／SHA-256 含連字號要加引號（OASIS cti-pattern-validator 範例）
const STIX_PATTERN_PATH = { ipv4: 'ipv4-addr:value', ipv6: 'ipv6-addr:value', domain: 'domain-name:value', md5: 'file:hashes.MD5', sha1: "file:hashes.'SHA-1'", sha256: "file:hashes.'SHA-256'" };
function stixPattern(kind, value) { return `[${STIX_PATTERN_PATH[kind]} = '${String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}']`; }
// opts：{now:Date, uuid:fn, label:fn(category)→顯示名稱}；必要欄位依 OASIS cti-stix2-json-schemas（indicator：pattern／
// pattern_type／valid_from；共通：type／spec_version／id／created／modified；bundle：type／id）
function buildStixBundle(records, opts) {
  const o = opts || {}, uuid = o.uuid || iocUuid4, label = o.label || (c => c);
  const now = (o.now || new Date()).toISOString();
  return {
    type: 'bundle', id: 'bundle--' + uuid(),
    objects: records.map(r => ({
      type: 'indicator', spec_version: '2.1', id: 'indicator--' + uuid(), created: now, modified: now,
      name: `${r.kind}: ${r.value}`,
      description: [r.categories.map(label).join('; '), r.severity].filter(Boolean).join(' | '),
      indicator_types: ['anomalous-activity'],
      pattern: stixPattern(r.kind, r.value), pattern_type: 'stix', pattern_version: '2.1',
      valid_from: r.firstSeen instanceof Date && !isNaN(r.firstSeen) ? r.firstSeen.toISOString() : now,
    })),
  };
}
// MISP 事件（MISP core format RFC）：只填不依賴特定 MISP 執行個體的欄位，id／org_id 等由匯入的 MISP 補上。
// 類別與型別：IP／網域為 Network activity（ip-src／ip-dst／domain），雜湊為 Artifacts dropped
const MISP_THREAT_LEVEL = { Critical: '1', High: '1', Medium: '2', Low: '3', Info: '3' };
function buildMispEvent(records, opts) {
  const o = opts || {}, uuid = o.uuid || iocUuid4, label = o.label || (c => c);
  const now = o.now || new Date();
  const ts = String(Math.floor(now.getTime() / 1000));
  const top = records.map(r => r.severity).sort((a, b) => SEV_RANK[a] - SEV_RANK[b])[0];
  return {
    Event: {
      uuid: uuid(), info: o.info || `Alpaca Network Toolkit log analysis (${records.length} indicators)`,
      date: now.toISOString().slice(0, 10), threat_level_id: MISP_THREAT_LEVEL[top] || '4', analysis: '0', distribution: '0',
      published: false, timestamp: ts,
      Attribute: records.map(r => ({
        uuid: uuid(),
        type: r.kind === 'ipv4' || r.kind === 'ipv6' ? (r.asSrc ? 'ip-src' : 'ip-dst') : r.kind,
        category: r.kind === 'md5' || r.kind === 'sha1' || r.kind === 'sha256' ? 'Artifacts dropped' : 'Network activity',
        value: r.value, to_ids: false, distribution: '5', timestamp: ts,
        comment: [r.categories.map(label).join('; '), r.severity, r.firstSeen instanceof Date && !isNaN(r.firstSeen) ? 'first seen ' + r.firstSeen.toISOString() : ''].filter(Boolean).join(' | '),
      })),
    },
  };
}
// 情資比對必須在去識別化「之前」的原始事件上執行，否則比對到的是假 IP（見規劃文件第 6 節）
// safeIndexes（已知安全清單，選填、預設空陣列，既有 2 參數呼叫完全不受影響）：命中安全清單
// 的候選 IP 直接跳過、不產生 knownIOC 問題——與威脅情資是同一套 buildIntelIndex/intelLookup
// 索引結構，只是語意相反（用途是排除公開清單常混入的內網/bogon 網段這類誤判，見
// fetch_threat_intel.ps1 私有位址過濾的同類問題）
function matchThreatIntel(events, intelIndexes, safeIndexes) {
  const safe = safeIndexes || [];
  const issues = [];
  events.forEach(evt => {
    const ips = extractCandidateIPs(evt);
    ips.forEach(ip => {
      if (safe.some(idx => intelLookup(idx, ip))) return;
      intelIndexes.forEach(index => {
        const hit = intelLookup(index, ip);
        if (hit) {
          issues.push({
            category: 'knownIOC', severityNorm: 'Critical', count: 1,
            firstSeen: evt.timestamp, lastSeen: evt.timestamp,
            sampleRaw: evt.raw, relatedHosts: [ip], relatedEvents: [evt], confidence: 'confirmed',
            intelSource: index.name, intelMeta: hit.meta
          });
        }
      });
    });
    // domain 型情資比對（2026-08-20 新增），與上方 IP 迴圈同構、共用同一套 issue 形狀，
    // 差別只在查詢函式改用 intelLookupDomain()（exact match，見該函式定義處註解）
    const domains = extractCandidateDomains(evt);
    domains.forEach(domain => {
      if (safe.some(idx => intelLookupDomain(idx, domain))) return;
      intelIndexes.forEach(index => {
        const hit = intelLookupDomain(index, domain);
        if (hit) {
          issues.push({
            category: 'knownIOC', severityNorm: 'Critical', count: 1,
            firstSeen: evt.timestamp, lastSeen: evt.timestamp,
            sampleRaw: evt.raw, relatedHosts: [domain], relatedEvents: [evt], confidence: 'confirmed',
            intelSource: index.name, intelMeta: hit.meta
          });
        }
      });
    });
  });
  return issues;
}
// 雜湊威脅情資比對（2026-09-18 新增，「不需真實範例的 6 項新功能」第 3 項）：完整比照
// matchThreatIntel() 的 IP 分支既有慣例（逐事件、非聚合，每筆命中各自一筆 issue），差別只在
// 用 extractCandidateHashes() 取候選值。intelLookup() 本身第一步就是 index.exact.has(value)，
// 對非 CIDR 形狀（含雜湊）的值天生泛用，IP 專屬的 CIDR 邏輯只在 exact 沒命中時才會執行、
// 對雜湊值必定安全 no-op（ipToInt() 對雜湊字串回傳 null 導致提早 return null），故可直接重用
// 不需另寫查找函式。刻意不加安全清單參數——雜湊沒有類似 bogon/內網網段的「安全清單」概念
function matchHashIntel(events, hashIndexes) {
  const indexes = hashIndexes || [];
  if (!indexes.length) return [];
  const issues = [];
  events.forEach(evt => {
    extractCandidateHashes(evt).forEach(h => {
      indexes.forEach(index => {
        const hit = intelLookup(index, h);
        if (hit) {
          issues.push({
            category: 'knownHashIOC', severityNorm: 'Critical', count: 1,
            firstSeen: evt.timestamp, lastSeen: evt.timestamp,
            sampleRaw: evt.raw, relatedHosts: [h], relatedEvents: [evt], confidence: 'confirmed',
            intelSource: index.name, intelMeta: hit.meta
          });
        }
      });
    });
  });
  return issues;
}
// IP-based GeoIP 資料庫比對：架構比照 matchThreatIntel()，差別是命中後多一層「該筆情資的
// meta.country 是否落在 riskCountries」判斷（riskCountries 與 detectGeoRiskEvents() 共用同一份
// 使用者勾選清單，只是比對來源不同——一個讀 log 自帶欄位，一個查 GeoIP CIDR 資料庫）；
// geoIndexes/riskCountries 任一為空時直接回傳 []，與既有 geo 相關函式的零影響慣例一致
function detectGeoIPLookup(events, geoIndexes, riskCountries) {
  const indexes = geoIndexes || [];
  const risk = (riskCountries || []).map(c => String(c).trim().toLowerCase()).filter(Boolean);
  if (!indexes.length || !risk.length) return [];
  const issues = [];
  events.forEach(evt => {
    const ips = extractCandidateIPs(evt);
    ips.forEach(ip => {
      indexes.forEach(index => {
        const hit = intelLookup(index, ip);
        const country = hit && hit.meta && hit.meta.country;
        if (!country || !risk.includes(String(country).trim().toLowerCase())) return;
        issues.push({
          category: 'geoIPRisk', severityNorm: 'Medium', count: 1,
          firstSeen: evt.timestamp, lastSeen: evt.timestamp,
          sampleRaw: evt.raw, geoCountry: country, geoIp: ip, geoSource: index.name,
          relatedHosts: [ip], relatedEvents: [evt], confidence: 'heuristic'
        });
      });
    });
  });
  return issues;
}
// ASN 風險比對（2026-08-27 接線，parseAsnDatabase()/lookupASN() 本身於 2026-08-23 就已完成，
// 當時使用者明確選擇只做解析＋查詢、不接線 UI，這次補上）。buildIntelIndex() 收集的
// index.countries 只認 entry.meta.country（見該函式），ASN 資料 meta 是 {asn,asName}，故
// index.countries 對 ASN 索引恆為空陣列，不能沿用 getImportedGeoCountries() 的做法；改為
// 直接走訪 index 內部三個儲存位置（exact／cidrByPrefix／cidr6ByPrefix）收集 distinct ASN。
// 不修改 buildIntelIndex() 本身——INTEL_LISTS/SAFE_LISTS/GEO_LISTS 三個既有消費者共用同一份
// 函式，風險與效益不成比例。
function getIndexDistinctAsns(index) {
  const map = new Map(); // asn -> asName
  const collect = e => { if (e && e.meta && e.meta.asn && !map.has(e.meta.asn)) map.set(e.meta.asn, e.meta.asName || ''); };
  index.exact.forEach(collect);
  index.cidrByPrefix.forEach(bucket => bucket.forEach(collect));
  index.cidr6ByPrefix.forEach(bucket => bucket.forEach(collect));
  return Array.from(map, ([asn, asName]) => ({ asn, asName })).sort((a, b) => a.asn.localeCompare(b.asn, undefined, { numeric: true }));
}
function getImportedAsns(asnLists) {
  const map = new Map();
  (asnLists || []).forEach(l => getIndexDistinctAsns(l.index).forEach(({ asn, asName }) => { if (!map.has(asn)) map.set(asn, asName); }));
  return Array.from(map, ([asn, asName]) => ({ asn, asName })).sort((a, b) => a.asn.localeCompare(b.asn, undefined, { numeric: true }));
}
// ASN 版本無「預設風險清單」——國家有可查證的洲別/風險分組知識（GEO_COUNTRY_GROUPS），ASN
// 編號沒有這種可公開引用的通用「已知風險名單」，硬湊會違反專案「不猜測」原則，故風險清單
// 一律來自使用者自己上傳的資料庫內容，未匯入時 riskAsns 傳空陣列，本函式直接回傳 []
function detectAsnRisk(events, asnIndexes, riskAsns) {
  const indexes = asnIndexes || [];
  const risk = new Set((riskAsns || []).filter(Boolean));
  if (!indexes.length || !risk.size) return [];
  const issues = [];
  events.forEach(evt => {
    extractCandidateIPs(evt).forEach(ip => {
      indexes.forEach(index => {
        const hit = lookupASN(index, ip);
        if (!hit || !risk.has(hit.asn)) return;
        issues.push({
          category: 'asnRisk', severityNorm: 'Medium', count: 1,
          firstSeen: evt.timestamp, lastSeen: evt.timestamp,
          sampleRaw: evt.raw, asnValue: hit.asn, asnName: hit.asName, asnIp: ip, asnSource: index.name,
          relatedHosts: [ip], relatedEvents: [evt], confidence: 'heuristic'
        });
      });
    });
  });
  return issues;
}
// ── VPN 成功登入來自代管／VPS 網段（2026-10-27，第三十四輪 XN25）──
// 依據 Akira 對 SonicWall SSL VPN 的攻擊（2025-07～09，Arctic Wolf）：合法 VPN 登入多來自寬頻或 SD-WAN，惡意登入
// 來自 VPS 代管業者。代管業者不等於惡意，與 ASN-DROP 風險清單分開，只看 VPN／遠端存取「成功」登入。
// 成功登入只用既有解析欄位（每種都有測試範例）：FortiGate tunnel-up（有 user 才是使用者 VPN，site-to-site IPsec
// 沒有 user）、ASA AnyConnect 722051、Palo Alto GlobalProtect 成功（公網 IP 在 natsrcip）、OpenVPN 連線建立、
// strongSwan IKE_SA established 且同一 SA 有指派虛擬 IP（遠端存取；site-to-site 到雲端 VPN 閘道本來就在代管網段）。
// SonicWall、Check Point 與雲端身分服務的登入沒有已驗證的成功登入欄位，不列入
const ASA_VPN_PUBLIC_RE = /\bUser <([^>]+)> IP <([^>]+)> IPv4 Address </;
function vpnLoginSuccessOf(e, raSaKeys) {
  const f = e.fields || {};
  if (/^tunnel-up$/i.test(f.action || '') && f.user && f.remip) return { user: f.user, ip: f.remip, src: 'fortigate' };
  if (f.logtype === 'GLOBALPROTECT' && /^success/i.test(f.status || '') && /auth|connected|login/i.test(f.eventid || '') && f.natsrcip)
    return { user: f.user || '', ip: f.natsrcip, src: 'globalprotect' };
  if (f.ovpn === 'connect' && f.srcip) return { user: f.user || '', ip: f.srcip, src: 'openvpn' };
  // Ivanti／Pulse Connect Secure 登入成功（XN94）：表頭的用戶端位址
  if (f.pcs === 'login' && f.srcip) return { user: f.user || '', ip: f.srcip, src: 'ivanti' };
  // Stormshield SSL VPN（XN122）：xvpn 的 tunnel opened 且 error=0
  if (e.netVendor === 'stormshield' && f.sns === 'xvpn' && f.snsError === '0' && /opened/i.test(f.snsMsg || '') && f.srcip) return { user: f.user || '', ip: f.srcip, src: 'stormshield' };
  // Cisco Meraki AnyConnect（XN120）：anyconnect_vpn_auth_success 的 Peer IP
  if (e.netVendor === 'meraki' && f.vpnAuth === 'ok' && f.srcip) return { user: f.user || '', ip: f.srcip, src: 'meraki' };
  if (e.netVendor === 'netscaler' && f.nsAuth === 'ok' && f.nsModule === 'SSLVPN' && f.srcip) return { user: f.user || '', ip: f.srcip, src: 'netscaler' };
  if (f.ipsec === 'up' && f.srcip && raSaKeys && raSaKeys.has(`${e.host}|${f.saName}|${f.saId}`)) return { user: f.user || '', ip: f.srcip, src: 'strongswan' };
  if (/722051/.test(e.msgid || e.raw || '')) {
    const m = String(e.msg || e.raw || '').match(ASA_VPN_PUBLIC_RE);
    if (m && m[2] && m[2] !== '0.0.0.0') return { user: m[1], ip: m[2], src: 'asa' };
  }
  return null;
}
// 代管業者 ASN 清單：情資整理頁輸出的 JSON Lines（形狀同 ASN-DROP）交給 parseAsnDropList()；其餘逐行讀
// 「AS123 # 名稱」（X4BNet lists_vpn 的 datacenter/ASN.txt）或「123,"名稱"」（bad-asn-list，表頭 ASN,Entity 略過）
function parseHostingAsnList(text) {
  const t = String(text || '').replace(/^﻿/, '');
  if (/^\s*\{/.test(t)) return parseAsnDropList(t);
  const list = [], seen = new Set();
  t.split(/\r?\n/).forEach(line => {
    const m = line.match(/^\s*(?:AS)?(\d{1,10})\s*(?:[,\t#]\s*(.*))?$/i);
    if (!m || Number(m[1]) <= 0) return;
    const asn = 'AS' + Number(m[1]);
    if (seen.has(asn)) return;
    seen.add(asn);
    list.push({ asn, asName: (m[2] || '').replace(/^#\s*/, '').replace(/^"|"$/g, '').trim() });
  });
  return list;
}
function detectVpnFromHosting(events, asnIndexes, hostingAsns) {
  const indexes = asnIndexes || [];
  const hosting = new Map((hostingAsns || []).filter(x => x && x.asn).map(x => [x.asn, x.asName || '']));
  if (!indexes.length || !hosting.size) return [];
  const raSaKeys = new Set();
  events.forEach(e => { const f = e.fields || {}; if (f.ipsec === 'assign' && f.saId) raSaKeys.add(`${e.host}|${f.saName}|${f.saId}`); });
  const byKey = new Map();
  events.forEach(e => {
    const v = vpnLoginSuccessOf(e, raSaKeys);
    if (!v) return;
    let hit = null;
    for (const index of indexes) { hit = lookupASN(index, v.ip); if (hit) break; }
    if (!hit || !hosting.has(hit.asn)) return;
    const key = `${v.user}|${hit.asn}`;
    let is = byKey.get(key);
    if (!is) {
      is = { category: 'vpnHostingLogin', severityNorm: 'High', count: 0, firstSeen: e.timestamp, lastSeen: e.timestamp,
        asnValue: hit.asn, asnName: hosting.get(hit.asn) || hit.asName, vpnSrc: v.src, vpnIps: [], relatedHosts: [], relatedEvents: [], confidence: 'heuristic' };
      byKey.set(key, is);
    }
    is.count++;
    if (e.timestamp && (!is.firstSeen || e.timestamp < is.firstSeen)) is.firstSeen = e.timestamp;
    if (e.timestamp && (!is.lastSeen || e.timestamp > is.lastSeen)) is.lastSeen = e.timestamp;
    if (!is.vpnIps.includes(v.ip)) is.vpnIps.push(v.ip);
    is.relatedHosts = [v.user, ...is.vpnIps].filter(Boolean);
    is.relatedEvents.push(e);
    Object.assign(is, sampleOf('sample.vpnHostingLogin', { user: v.user || '?', ip: is.vpnIps.join(', '), asn: is.asnValue, name: is.asnName || '', src: v.src, n: is.count }));
  });
  return [...byKey.values()];
}
// 商用 VPN 位址清單（XN36，CISA AA26-293A：SafePay 從 Mullvad 位址登入受害者 VPN）：情資整理頁輸出的 NDJSON {cidr}、
// 每行一個位址或 CIDR，或直接匯入 Mullvad relay 清單 JSON（app 端點 {wireguard:{relays}, bridge:{relays}} 或網站端點陣列，
// 取 active 不為 false 的 ipv4_addr_in；relay 為伺服器連入位址，出口不一定相同）。只收 IPv4，回傳 [{cidr, source}]
function parseAnonVpnList(text) {
  const t = String(text || '').replace(/^\uFEFF/, '').trim();
  const out = [], seen = new Set();
  const add = (v, source) => {
    const m = String(v || '').trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
    if (!m || !isValidIPv4(m[1]) || (m[2] !== undefined && Number(m[2]) > 32)) return;
    const cidr = m[1] + '/' + (m[2] === undefined ? 32 : Number(m[2]));
    if (seen.has(cidr)) return;
    seen.add(cidr);
    out.push({ cidr, source: source || '' });
  };
  if (/^[\[{]/.test(t)) {
    let o = null;
    try { o = JSON.parse(t); } catch (e) { o = null; }
    if (o && (Array.isArray(o) || o.wireguard || o.bridge)) {
      const relays = Array.isArray(o) ? o : [...((o.wireguard && o.wireguard.relays) || []), ...((o.bridge && o.bridge.relays) || [])];
      relays.forEach(r => { if (r && r.active !== false && r.ipv4_addr_in) add(r.ipv4_addr_in, 'mullvad'); });
      return out;
    }
  }
  t.split(/\r?\n/).forEach(line => {
    const l = line.trim();
    if (!l || l.startsWith('#') || l.startsWith(';')) return;
    if (l.startsWith('{')) { try { const j = JSON.parse(l); add(j.cidr || j.ip, j.source); } catch (e) { /* 格式不符略過 */ } return; }
    add(l.split(/[\s;,]+/)[0], '');
  });
  return out;
}
// VPN 成功登入（vpnLoginSuccessOf()）的來源位址落在商用 VPN 清單：依帳號合併；使用商用 VPN 不等於惡意，需人工確認
function detectVpnFromAnonVpn(events, anonList) {
  const ranges = (anonList || []).map(x => {
    const [base, bits] = String(x.cidr || '').split('/');
    const b = ipToInt(base), n = Number(bits);
    if (b === null || !(n >= 0 && n <= 32)) return null;
    const mask = n === 0 ? 0 : n >= 32 ? 0xFFFFFFFF : (~((1 << (32 - n)) - 1)) >>> 0;
    const lo = (b & mask) >>> 0;
    return { lo, hi: (lo + (~mask >>> 0)) >>> 0, cidr: x.cidr, source: x.source || '' };
  }).filter(Boolean);
  if (!ranges.length) return [];
  const raSaKeys = new Set();
  events.forEach(e => { const f = e.fields || {}; if (f.ipsec === 'assign' && f.saId) raSaKeys.add(`${e.host}|${f.saName}|${f.saId}`); });
  const byUser = new Map();
  events.forEach(e => {
    const v = vpnLoginSuccessOf(e, raSaKeys);
    if (!v || !isValidIPv4(v.ip)) return;
    const ip = ipToInt(v.ip);
    const hit = ranges.find(r => ip >= r.lo && ip <= r.hi);
    if (!hit) return;
    const key = String(v.user || '').toLowerCase() + '|' + v.src;
    let is = byUser.get(key);
    if (!is) {
      is = { category: 'vpnAnonLogin', severityNorm: 'High', count: 0, firstSeen: e.timestamp, lastSeen: e.timestamp,
        vpnSrc: v.src, vpnIps: [], anonLists: [], relatedHosts: [], relatedEvents: [], confidence: 'heuristic' };
      byUser.set(key, is);
    }
    is.count++;
    if (e.timestamp && (!is.firstSeen || e.timestamp < is.firstSeen)) is.firstSeen = e.timestamp;
    if (e.timestamp && (!is.lastSeen || e.timestamp > is.lastSeen)) is.lastSeen = e.timestamp;
    if (!is.vpnIps.includes(v.ip)) is.vpnIps.push(v.ip);
    hit.source.split(',').filter(Boolean).forEach(src => { if (!is.anonLists.includes(src)) is.anonLists.push(src); });
    is.relatedHosts = [v.user, ...is.vpnIps].filter(Boolean);
    is.relatedEvents.push(e);
    Object.assign(is, sampleOf('sample.vpnAnonLogin', { user: v.user || '?', ip: is.vpnIps.join(', '), src: v.src, n: is.count, list: is.anonLists.join(', ') || '-' }));
  });
  return [...byUser.values()];
}
// 遠端管理工具（RMM）網域（XN37，Group-IB k0t 以 MeshCentral／Atera 常駐；CISA AA23-025A）：情資整理頁輸出的 NDJSON {domain, tool}、
// 每行「網域[,工具]」，或直接匯入 LOLRMM rmm_tools.json。共用雲端／平台網域不收（與情資整理頁 RMM_SHARED_SUFFIXES 同一份）
const RMM_SHARED_SUFFIXES = ['windows.net', 'azureedge.net', 'azure.com', 'azurewebsites.net', 'azurefd.net', 'microsoft.com', 'amazonaws.com', 'cloudfront.net',
  'googleapis.com', 'google.com', 'gstatic.com', 'googleusercontent.com', 'akamaized.net', 'akamaiedge.net', 'akamai.net', 'edgekey.net', 'edgesuite.net',
  'fastly.net', 'cloudflare.com', 'cloudflare.net', 'github.com', 'githubusercontent.com', 'ghcr.io', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
  'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app', 'herokuapp.com', 'firebaseio.com', 'appspot.com', 'digicert.com', 'letsencrypt.org',
  'sentry.io', 'apple.com', 'icloud.com', 'live.com', 'office.com', 'msftconnecttest.com', 'ngrok.io', 'ngrok.com', 'dropbox.com', 'box.com'];
function rmmCleanDomain(v) {
  let d = String(v || '').trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[\/?#]/)[0].replace(/:\d+$/, '').replace(/\.$/, '');
  if (d.includes('*')) { const p = d.split('.'); let i = -1; p.forEach((x, k) => { if (x.includes('*')) i = k; }); d = p.slice(i + 1).join('.'); }
  if (!/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(d) || /^[\d.]+$/.test(d)) return '';
  return RMM_SHARED_SUFFIXES.some(x => d === x || d.endsWith('.' + x)) ? '' : d;
}
function parseRmmList(text) {
  const t = String(text || '').replace(/^\uFEFF/, '').trim();
  const out = [], seen = new Set();
  const add = (dom, tool) => { const d = rmmCleanDomain(dom); if (d && !seen.has(d)) { seen.add(d); out.push({ domain: d, tool: String(tool || '').trim() }); } };
  if (t.startsWith('[')) {
    let o = null;
    try { o = JSON.parse(t); } catch (e) { o = null; }
    if (Array.isArray(o)) {
      o.forEach(x => ((x && x.Artifacts && x.Artifacts.Network) || []).forEach(n => ((n && n.Domains) || []).forEach(d => add(d, x.Name))));
      return out;
    }
  }
  t.split(/\r?\n/).forEach(line => {
    const l = line.trim();
    if (!l || l.startsWith('#')) return;
    if (l.startsWith('{')) { try { const j = JSON.parse(l); add(j.domain, j.tool); } catch (e) { /* 格式不符略過 */ } return; }
    const [d, ...rest] = l.split(',');
    add(d, rest.join(','));
  });
  return out;
}
// DNS 查詢、proxy／web 紀錄的網域落在 RMM 清單（完全相同或子網域）：依工具＋用戶端合併；允許清單（工具名稱或網域）排除公司自用的 RMM
function detectRmmTools(events, rmmList, allow) {
  const byDom = new Map((rmmList || []).filter(x => x && x.domain).map(x => [x.domain, x.tool || x.domain]));
  if (!byDom.size) return [];
  const allowList = (allow || []).map(a => String(a).trim().toLowerCase()).filter(Boolean);
  const lookup = name => {
    const l = String(name || '').toLowerCase().replace(/\.$/, '').split('.');
    for (let i = 0; i < l.length - 1; i++) { const d = l.slice(i).join('.'); if (byDom.has(d)) return d; }
    return null;
  };
  const allowed = (tool, name) => allowList.some(a => tool.toLowerCase() === a || name === a || name.endsWith('.' + a));
  const groups = new Map();
  events.forEach(e => {
    const q = dnsQueryOf(e), f = e.fields || {};
    const names = new Set([...(q ? [q.name] : []), ...extractCandidateDomains(e)].map(n => String(n).toLowerCase()));
    for (const n of names) {
      const d = lookup(n);
      if (!d) continue;
      const tool = byDom.get(d);
      if (allowed(tool, n)) continue;
      const client = (q && q.client) || f.srcip || e.host || '-';
      const key = tool.toLowerCase() + '|' + client;
      let g = groups.get(key);
      if (!g) { g = { tool, client, names: [], list: [] }; groups.set(key, g); }
      if (!g.names.includes(n)) g.names.push(n);
      g.list.push(e);
      break;
    }
  });
  return [...groups.values()].map(g => {
    g.list.sort((a, b) => effectiveTime(a) - effectiveTime(b));
    return {
      category: 'rmmTool', severityNorm: 'Medium', count: g.list.length,
      firstSeen: g.list[0].timestamp || null, lastSeen: g.list[g.list.length - 1].timestamp || null,
      rmmTool: g.tool, rmmDomains: g.names, rmmClient: g.client,
      ...sampleOf('sample.rmmTool', { client: g.client, tool: g.tool, list: g.names.slice(0, 3).join(', '), n: g.list.length }),
      relatedHosts: [g.client !== '-' ? g.client : '', ...g.names].filter(Boolean), relatedEvents: g.list, confidence: 'heuristic'
    };
  });
}
// 地理速度異常（impossible travel）偵測：誠實標註為「國家層級」heuristic，非真實距離/時速
// 計算（COUNTRY_INFO 僅有國家/洲別，無經緯度）。actor key 優先用使用者欄位（WINEVENT_USER_KEYS／
// JSON_USER_KEYS，取不到才 fallback 用 e.host），國家資料來源：FortiGate 走既有 srccountry
// 欄位（detectGeoRiskEvents 同款邏輯），其餘格式走 geoIndexes GeoIP 資料庫查詢（detectGeoIPLookup
// 同款邏輯）。同一 actor 在短時間窗內出現 2 個以上不同國家時標記
function detectGeoVelocity(events, geoIndexes, opts) {
  const windowMs = (opts && opts.geoVelocityWindowMs) || 60 * 60000;
  const indexes = geoIndexes || [];
  function actorKey(e) {
    // 速度偵測跨格式比對同一人（Windows 的 網域\帳號 與 sshd 的帳號），只取帳號部分
    const u = (e.fields && eventUserKey(e)) || null;
    return (u && u.replace(/^[^\\]*\\/, '').toLowerCase()) || e.host || null;
  }
  function eventCountries(e) {
    if (e.format === 'fortigate' && e.fields && e.fields.srccountry) return [{ country: e.fields.srccountry, ip: e.fields.srcip || '' }];
    if (!indexes.length) return [];
    const out = [];
    extractCandidateIPs(e).forEach(ip => {
      indexes.forEach(index => {
        const hit = intelLookup(index, ip);
        const country = hit && hit.meta && hit.meta.country;
        if (country) out.push({ country: String(country).trim(), ip });
      });
    });
    return out;
  }
  const byActor = new Map();
  events.forEach(e => {
    const actor = actorKey(e);
    if (!actor) return;
    const hits = eventCountries(e);
    if (!hits.length) return;
    if (!byActor.has(actor)) byActor.set(actor, []);
    hits.forEach(h => byActor.get(actor).push({ e, country: h.country, ip: h.ip }));
  });
  // 2026-08-27 稽核修復：先前用 countries.size===2 精確匹配，比照 detectLateralMovement()
  // 同一輪稽核發現的同款問題——視窗內國家數一旦超過 2 就不再觸發，同一 actor 短時間內出現
  // 3、4 個國家跟剛好 2 個國家在畫面上長得一樣。改為同一波事件 episode 追蹤，持續就地更新
  // count/geoCountries/lastSeen/relatedEvents 到目前為止看過的最大範圍，視窗國家數掉回 2
  // 以下才結束這一波，之後再度達標視為新的一波
  const issues = [];
  for (const [actor, list] of byActor) {
    const sorted = [...list].sort((a, b) => effectiveTime(a.e) - effectiveTime(b.e));
    let winStart = 0;
    let episode = null;
    for (let i = 0; i < sorted.length; i++) {
      const ti = effectiveTime(sorted[i].e);
      while (effectiveTime(sorted[winStart].e) < ti - windowMs) winStart++;
      const windowItems = sorted.slice(winStart, i + 1);
      const countries = new Set(windowItems.map(it => it.country));
      if (countries.size >= 2) {
        if (!episode) {
          episode = {
            category: 'geoVelocity', severityNorm: 'Medium', count: countries.size,
            firstSeen: windowItems[0].e.timestamp || null, lastSeen: windowItems[windowItems.length - 1].e.timestamp || null,
            ...sampleOf('sample.velocity', { actor, min: windowMs / 60000, list: Array.from(countries).join(' / ') }),
            geoCountries: Array.from(countries),
            relatedHosts: [actor], relatedEvents: windowItems.map(it => it.e), confidence: 'heuristic'
          };
          issues.push(episode);
        } else {
          // lastSeen 每步都延伸；count/geoCountries/relatedEvents 只在國家數創新高時才更新
          // 代表快照，理由同 detectLateralMovement() 上方註解
          episode.lastSeen = windowItems[windowItems.length - 1].e.timestamp || null;
          if (countries.size > episode.count) {
            episode.count = countries.size;
            Object.assign(episode, sampleOf('sample.velocity', { actor, min: windowMs / 60000, list: Array.from(countries).join(' / ') }));
            episode.geoCountries = Array.from(countries);
            episode.relatedEvents = windowItems.map(it => it.e);
          }
        }
      } else {
        episode = null;
      }
    }
  }
  return issues;
}
// ASN 速度異常：比照 detectGeoVelocity() 的「國家層級」heuristic 精神，改用 ASN 維度——
// 同一 actor（使用者優先，取不到才 fallback host）短時間窗內出現於 2 個以上不同 ASN，
// 常見於 VPN/代理跳轉或帳號在不同雲端環境間快速切換。透過 lookupASN() 查詢已上傳的 ASN
// 資料庫（asnIndexes，即 ASN_LISTS），與「風險 ASN 標記」勾選清單彼此獨立，不需要使用者
// 額外勾選任何項目；沒有已上傳的 ASN 資料庫時直接回傳 []，行為與既有 detectAsnRisk() 一致
function detectAsnVelocity(events, asnIndexes, opts) {
  const windowMs = (opts && opts.asnVelocityWindowMs) || 60 * 60000;
  const indexes = asnIndexes || [];
  if (!indexes.length) return [];
  function actorKey(e) {
    // 速度偵測跨格式比對同一人（Windows 的 網域\帳號 與 sshd 的帳號），只取帳號部分
    const u = (e.fields && eventUserKey(e)) || null;
    return (u && u.replace(/^[^\\]*\\/, '').toLowerCase()) || e.host || null;
  }
  function eventAsns(e) {
    const out = [];
    extractCandidateIPs(e).forEach(ip => {
      indexes.forEach(index => {
        const hit = lookupASN(index, ip);
        if (hit && hit.asn) out.push({ asn: hit.asn, asName: hit.asName, ip });
      });
    });
    return out;
  }
  const byActor = new Map();
  events.forEach(e => {
    const actor = actorKey(e);
    if (!actor) return;
    const hits = eventAsns(e);
    if (!hits.length) return;
    if (!byActor.has(actor)) byActor.set(actor, []);
    hits.forEach(h => byActor.get(actor).push({ e, asn: h.asn, asName: h.asName, ip: h.ip }));
  });
  // episode 追蹤邏輯完全比照 detectGeoVelocity()：ASN 數創新高才更新快照，掉回 2 以下才結束
  // 這一波，之後再度達標視為新的一波，避免同一持續行為被單一固定快照蓋掉真實規模
  const issues = [];
  for (const [actor, list] of byActor) {
    const sorted = [...list].sort((a, b) => effectiveTime(a.e) - effectiveTime(b.e));
    let winStart = 0;
    let episode = null;
    for (let i = 0; i < sorted.length; i++) {
      const ti = effectiveTime(sorted[i].e);
      while (effectiveTime(sorted[winStart].e) < ti - windowMs) winStart++;
      const windowItems = sorted.slice(winStart, i + 1);
      const asnMap = new Map(windowItems.map(it => [it.asn, it.asName]));
      if (asnMap.size >= 2) {
        const label = Array.from(asnMap.entries()).map(([a, n]) => n ? `${a}(${n})` : a).join(' / ');
        if (!episode) {
          episode = {
            category: 'asnVelocity', severityNorm: 'Medium', count: asnMap.size,
            firstSeen: windowItems[0].e.timestamp || null, lastSeen: windowItems[windowItems.length - 1].e.timestamp || null,
            ...sampleOf('sample.velocity', { actor, min: windowMs / 60000, list: label }),
            asnList: Array.from(asnMap.keys()),
            relatedHosts: [actor], relatedEvents: windowItems.map(it => it.e), confidence: 'heuristic'
          };
          issues.push(episode);
        } else {
          episode.lastSeen = windowItems[windowItems.length - 1].e.timestamp || null;
          if (asnMap.size > episode.count) {
            episode.count = asnMap.size;
            Object.assign(episode, sampleOf('sample.velocity', { actor, min: windowMs / 60000, list: label }));
            episode.asnList = Array.from(asnMap.keys());
            episode.relatedEvents = windowItems.map(it => it.e);
          }
        }
      } else {
        episode = null;
      }
    }
  }
  return issues;
}

// 把彙整後的問題（頻率異常／掃描 heuristic／情資命中）反向標記回各自觸發問題的原始事件，
// 讓「事件清單」逐筆也能看到「疑似猜密碼」「疑似 port scan」這類註記，不必只看彙整後的
// 「問題清單」才知道某筆事件為何被判定有問題；同一事件可能同時觸發多種問題（notes 為陣列）
function annotateEventsWithIssues(events, issues) {
  events.forEach(e => { e.notes = []; });
  issues.forEach(issue => {
    (issue.relatedEvents || []).forEach(e => {
      if (!e.notes.includes(issue.category)) e.notes.push(issue.category);
    });
  });
}

// ── Sigma 規則（部分語法，第二十六輪 SD）──────────────────────────────────────
// 依 SigmaHQ sigma-specification（rules specification 與 modifiers appendix）：detection 下各搜尋識別碼，
// map 為 AND、list 為 OR（字串清單為關鍵字搜尋），值清單為 OR（|all 改 AND）；值不分大小寫，可用 * ? 萬用字元；
// 支援修飾子 contains／startswith／endswith／all／re（含 i m s）／exists／cased／windash／cidr／lt／lte／gt／gte／neq；
// condition 支援 and／or／not／括號／1 of x*／all of x*／them，條件為清單時以 OR 連接。
// 不支援的修飾子（base64、utf16、expand、fieldref、時間類）、多文件、correlation 規則一律回報原因不匯入。
// logsource.product 為 windows 時只比對 Windows 事件。欄位名稱不分大小寫，另接受 Image→NewProcessName 等常見對應
const SIGMA_MODS = new Set(['contains', 'startswith', 'endswith', 'all', 're', 'i', 'm', 's', 'exists', 'cased', 'windash', 'cidr', 'lt', 'lte', 'gt', 'gte', 'neq']);
const SIGMA_FIELD_ALIASES = { image: ['NewProcessName'], parentimage: ['ParentProcessName'], provider_name: ['Provider'], eventlog: ['Channel'] };
const SIGMA_LEVEL_SEV = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' };
function _sigmaSplitKV(t) {
  let q = '';
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === q) { if (q === "'" && t[i + 1] === "'") { i++; continue; } q = ''; } continue; }
    if ((c === "'" || c === '"') && (i === 0 || /[\s\[,]/.test(t[i - 1]))) { q = c; continue; }
    if (c === ':' && (i === t.length - 1 || t[i + 1] === ' ')) return { k: _sigmaScalar(t.slice(0, i).trim()), v: t.slice(i + 1).trim() };
  }
  return null;
}
function _sigmaScalar(v) {
  const t = String(v).trim();
  if (t.startsWith("'") && t.endsWith("'") && t.length >= 2) return t.slice(1, -1).replace(/''/g, "'");
  if (t.startsWith('"') && t.endsWith('"') && t.length >= 2) { try { return JSON.parse(t); } catch (e) { return t.slice(1, -1); } }
  if (t.startsWith('[') && t.endsWith(']')) return t.slice(1, -1).split(/,(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/).map(x => x.trim()).filter(x => x !== '').map(_sigmaScalar);
  if (t === 'null' || t === '~' || t === '') return null;
  if (t === 'true') return true;
  if (t === 'false') return false;
  return t;
}
function _sigmaStripComment(t) {
  let q = '';
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === q) { if (q === "'" && t[i + 1] === "'") { i++; continue; } q = ''; } continue; }
    if ((c === "'" || c === '"') && (i === 0 || /[\s\[,:]/.test(t[i - 1]))) q = c;
    else if (c === '#' && (i === 0 || /\s/.test(t[i - 1]))) return t.slice(0, i).trimEnd();
  }
  return t;
}
// 極簡 YAML：只處理 Sigma 規則會用到的 map／list／純量、引號字串、[a, b] 與 | > 區塊字串；不支援錨點與多文件
function sigmaYaml(text) {
  const raw = String(text || '').replace(/\r\n/g, '\n').replace(/\t/g, '  ').split('\n');
  const lines = [];
  let docs = 0;
  for (let i = 0; i < raw.length; i++) {
    const l = raw[i];
    if (/^---\s*$/.test(l)) { if (lines.length) docs++; continue; }
    if (/^\s*(#|$)/.test(l)) continue;
    const ind = l.match(/^ */)[0].length;
    const m = l.match(/^(\s*(?:-\s+)?[^:#]+:)\s*[|>][-+]?\s*$/);
    if (m) {
      const buf = [];
      while (i + 1 < raw.length && (/^\s*$/.test(raw[i + 1]) || raw[i + 1].match(/^ */)[0].length > ind)) buf.push(raw[++i].trim());
      lines.push({ ind, text: m[1].trim() + ' ' + JSON.stringify(buf.join('\n').trim()) });
      continue;
    }
    lines.push({ ind, text: _sigmaStripComment(l.trim()) });
  }
  if (docs) throw new Error('multi_doc');
  let pos = 0;
  const isItem = t => t === '-' || t.startsWith('- ');
  function node(ind) { return isItem(lines[pos].text) ? list(ind) : map(ind); }
  function map(ind) {
    const o = {};
    while (pos < lines.length && lines[pos].ind === ind && !isItem(lines[pos].text)) {
      const kv = _sigmaSplitKV(lines[pos].text);
      if (!kv) throw new Error('yaml');
      pos++;
      if (kv.v !== '') o[kv.k] = _sigmaScalar(kv.v);
      else if (pos < lines.length && lines[pos].ind > ind) o[kv.k] = node(lines[pos].ind);
      else if (pos < lines.length && lines[pos].ind === ind && isItem(lines[pos].text)) o[kv.k] = list(ind);
      else o[kv.k] = null;
    }
    if (pos < lines.length && lines[pos].ind > ind) throw new Error('yaml');
    return o;
  }
  function list(ind) {
    const a = [];
    while (pos < lines.length && lines[pos].ind === ind && isItem(lines[pos].text)) {
      const rest = lines[pos].text.replace(/^-\s*/, '');
      if (rest === '') { pos++; a.push(pos < lines.length && lines[pos].ind > ind ? node(lines[pos].ind) : null); continue; }
      if (_sigmaSplitKV(rest) && !/^['"\[]/.test(rest.trim())) {
        const ci = ind + lines[pos].text.length - rest.length;
        lines[pos] = { ind: ci, text: rest };
        a.push(map(ci));
      } else { a.push(_sigmaScalar(rest)); pos++; }
    }
    return a;
  }
  return lines.length ? node(lines[0].ind) : {};
}
function _sigmaErr(code, detail) { const e = new Error(code); e.detail = detail || ''; return e; }
function _sigmaWild(v, cased, pre, post) {
  let out = '';
  const t = String(v);
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (c === '\\' && (t[i + 1] === '*' || t[i + 1] === '?' || t[i + 1] === '\\')) { out += t[i + 1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); i++; }
    else if (c === '*') out += '[\\s\\S]*';
    else if (c === '?') out += '[\\s\\S]';
    else out += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + (pre ? '[\\s\\S]*' : '') + out + (post ? '[\\s\\S]*' : '') + '$', cased ? '' : 'i');
}
const _sigmaDash = s => String(s).replace(/[-\/–—―]/g, '-');
function _sigmaValueTest(mods, value) {
  const has = m => mods.includes(m);
  if (value === null) return { nullTest: true };
  if (has('re')) {
    // 開頭的內嵌旗標（如 (?i)）轉成 JavaScript 旗標
    let src = String(value), inl = '';
    const m = src.match(/^\(\?([ims]+)\)/);
    if (m) { inl = m[1]; src = src.slice(m[0].length); }
    const fl = [...new Set(((has('i') ? 'i' : '') + (has('m') ? 'm' : '') + (has('s') ? 's' : '') + inl).split(''))].join('');
    try { const re = new RegExp(src, fl); return x => re.test(x); } catch (e) { throw _sigmaErr('regex', String(value)); }
  }
  if (has('cidr')) return x => isValidIPv4(x) && cidrMatch(x, String(value));
  for (const op of ['lt', 'lte', 'gt', 'gte']) if (has(op)) {
    const n = Number(value);
    return x => { const v = Number(x); return x !== '' && !isNaN(v) && (op === 'lt' ? v < n : op === 'lte' ? v <= n : op === 'gt' ? v > n : v >= n); };
  }
  const wd = has('windash');
  const re = _sigmaWild(wd ? _sigmaDash(value) : value, has('cased'), has('contains') || has('endswith'), has('contains') || has('startswith'));
  return x => re.test(wd ? _sigmaDash(x) : x);
}
function _sigmaCompileField(key, val) {
  const parts = String(key).split('|');
  const field = parts[0], mods = parts.slice(1).map(m => m.toLowerCase());
  const bad = mods.find(m => !SIGMA_MODS.has(m));
  if (bad) throw _sigmaErr('modifier', bad);
  const vals = Array.isArray(val) ? val : [val];
  if (mods.includes('exists')) { const want = vals[0] === true || String(vals[0]).toLowerCase() === 'true'; return { field, exists: want }; }
  const tests = vals.map(v => _sigmaValueTest(mods, v === undefined ? null : (typeof v === 'boolean' ? String(v) : v)));
  return { field, tests, all: mods.includes('all'), neq: mods.includes('neq') };
}
function _sigmaCompileSel(v) {
  if (Array.isArray(v)) {
    if (v.every(x => x === null || typeof x !== 'object')) return { any: v.map(x => _sigmaWild(String(x), false, true, true)), kw: true };
    return { or: v.map(x => _sigmaCompileSel(x)) };
  }
  if (v && typeof v === 'object') {
    const conds = [];
    Object.keys(v).forEach(k => {
      if (k === '|all') { const list = Array.isArray(v[k]) ? v[k] : [v[k]]; conds.push({ kwAll: list.map(x => _sigmaWild(String(x), false, true, true)) }); }
      else conds.push(_sigmaCompileField(k, v[k]));
    });
    return { and: conds };
  }
  if (typeof v === 'string' || typeof v === 'number') return { any: [_sigmaWild(String(v), false, true, true)], kw: true };
  throw _sigmaErr('detection');
}
// 條件運算式 → 語法樹；優先序 or < and < not < x of < 括號
function _sigmaParseCond(text, ids) {
  const toks = String(text).match(/\(|\)|[^\s()]+/g) || [];
  let i = 0;
  const peek = () => (toks[i] || '').toLowerCase();
  const matchIds = pat => {
    if (pat === 'them') return ids.filter(x => !x.startsWith('_'));
    const re = new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
    const hit = ids.filter(x => re.test(x));
    if (!hit.length) throw _sigmaErr('ident', pat);
    return hit;
  };
  function orE() { let n = andE(); while (peek() === 'or') { i++; n = { op: 'or', a: n, b: andE() }; } return n; }
  function andE() { let n = notE(); while (peek() === 'and') { i++; n = { op: 'and', a: n, b: notE() }; } return n; }
  function notE() { if (peek() === 'not') { i++; return { op: 'not', a: notE() }; } return atom(); }
  function atom() {
    const t = toks[i];
    if (t === undefined) throw _sigmaErr('condition', text);
    if (t === '(') { i++; const n = orE(); if (toks[i] !== ')') throw _sigmaErr('condition', text); i++; return n; }
    if ((t === '1' || t.toLowerCase() === 'all' || t.toLowerCase() === 'any') && (toks[i + 1] || '').toLowerCase() === 'of') {
      i += 2; const pat = toks[i++]; if (!pat) throw _sigmaErr('condition', text);
      return { op: t === '1' || t.toLowerCase() === 'any' ? 'oneOf' : 'allOf', ids: matchIds(pat) };
    }
    if (/^\d+$/.test(t)) throw _sigmaErr('condition', text);
    i++;
    if (!ids.includes(t)) throw _sigmaErr('ident', t);
    return { op: 'id', id: t };
  }
  const n = orE();
  if (i < toks.length) throw _sigmaErr('condition', text);
  return n;
}
// 回傳 {title, severity, mitre, tags, windowsOnly, sels, cond} 或 {error, detail}
function parseSigmaRule(text) {
  let doc;
  try { doc = sigmaYaml(text); } catch (e) { return { error: e.message === 'multi_doc' ? 'multi_doc' : 'yaml', detail: '' }; }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { error: 'yaml', detail: '' };
  if (doc.correlation || doc.action) return { error: 'correlation', detail: '' };
  const det = doc.detection;
  if (!det || typeof det !== 'object' || det.condition == null) return { error: 'no_detection', detail: '' };
  try {
    const sels = {};
    Object.keys(det).forEach(k => { if (k !== 'condition' && k !== 'timeframe') sels[k] = _sigmaCompileSel(det[k]); });
    const ids = Object.keys(sels);
    const conds = (Array.isArray(det.condition) ? det.condition : [det.condition]).map(c => _sigmaParseCond(String(c), ids));
    const cond = conds.reduce((a, b) => a ? { op: 'or', a, b } : b, null);
    const tags = Array.isArray(doc.tags) ? doc.tags.map(String) : [];
    const t = tags.map(x => (x.match(/^attack\.(t\d{4}(?:\.\d{3})?)$/i) || [])[1]).find(Boolean);
    const ls = doc.logsource && typeof doc.logsource === 'object' ? doc.logsource : {};
    return { title: String(doc.title || doc.id || 'Sigma'), severity: SIGMA_LEVEL_SEV[String(doc.level || '').toLowerCase()] || 'Medium',
      mitre: t ? t.toUpperCase() : '', tags, windowsOnly: String(ls.product || '').toLowerCase() === 'windows',
      category: String(ls.category || '').toLowerCase(), service: String(ls.service || '').toLowerCase(), sels, cond };
  } catch (e) { return { error: e.message || 'detection', detail: e.detail || '' }; }
}
function _sigmaFieldValue(e, field) {
  const f = e.fields || {};
  const want = String(field).toLowerCase();
  const names = [want, ...((SIGMA_FIELD_ALIASES[want] || []).map(x => x.toLowerCase()))];
  for (const n of names) { const k = Object.keys(f).find(x => x.toLowerCase() === n); if (k !== undefined && f[k] != null && typeof f[k] !== 'object') return String(f[k]); }
  // 點號欄位（userIdentity.type）沿巢狀物件逐層找，不分大小寫
  if (want.includes('.')) {
    let o = f;
    for (const part of want.split('.')) {
      if (!o || typeof o !== 'object') return undefined;
      const k = Object.keys(o).find(x => x.toLowerCase() === part);
      if (k === undefined) return undefined;
      o = o[k];
    }
    return o != null && typeof o !== 'object' ? String(o) : undefined;
  }
  return undefined;
}
// logsource（product windows）的 category／service 對應 Windows 事件：Sysmon 事件編號（Channel 為 Sysmon）、
// 4688 為 Security 的處理程序建立、4103／4104 為 PowerShell；未列出的 category 不限定
const SIGMA_SYSMON_CHANNEL_RE = /Sysmon/i;
const SIGMA_WIN_CATEGORY = {
  process_creation: e => (_sigmaSysmon(e) && _sigmaEid(e) === '1') || _sigmaEid(e) === '4688',
  network_connection: e => _sigmaSysmon(e) && _sigmaEid(e) === '3',
  process_termination: e => _sigmaSysmon(e) && _sigmaEid(e) === '5',
  driver_load: e => _sigmaSysmon(e) && _sigmaEid(e) === '6',
  image_load: e => _sigmaSysmon(e) && _sigmaEid(e) === '7',
  create_remote_thread: e => _sigmaSysmon(e) && _sigmaEid(e) === '8',
  raw_access_thread: e => _sigmaSysmon(e) && _sigmaEid(e) === '9',
  process_access: e => _sigmaSysmon(e) && _sigmaEid(e) === '10',
  file_event: e => _sigmaSysmon(e) && _sigmaEid(e) === '11',
  registry_add: e => _sigmaSysmon(e) && _sigmaEid(e) === '12',
  registry_delete: e => _sigmaSysmon(e) && _sigmaEid(e) === '12',
  registry_set: e => _sigmaSysmon(e) && _sigmaEid(e) === '13',
  registry_rename: e => _sigmaSysmon(e) && _sigmaEid(e) === '14',
  registry_event: e => _sigmaSysmon(e) && ['12', '13', '14'].includes(_sigmaEid(e)),
  create_stream_hash: e => _sigmaSysmon(e) && _sigmaEid(e) === '15',
  pipe_created: e => _sigmaSysmon(e) && ['17', '18'].includes(_sigmaEid(e)),
  wmi_event: e => _sigmaSysmon(e) && ['19', '20', '21'].includes(_sigmaEid(e)),
  dns_query: e => _sigmaSysmon(e) && _sigmaEid(e) === '22',
  file_delete: e => _sigmaSysmon(e) && ['23', '26'].includes(_sigmaEid(e)),
  ps_module: e => _sigmaEid(e) === '4103',
  ps_script: e => _sigmaEid(e) === '4104',
};
const SIGMA_WIN_SERVICE = { security: /^Security$/i, system: /^System$/i, sysmon: SIGMA_SYSMON_CHANNEL_RE, powershell: /PowerShell/i, application: /^Application$/i };
function _sigmaEid(e) { return String((e.fields || {}).EventID || ''); }
function _sigmaSysmon(e) { return SIGMA_SYSMON_CHANNEL_RE.test(String((e.fields || {}).Channel || '')); }
function _sigmaSelMatch(sel, e, hay) {
  if (sel.or) return sel.or.some(x => _sigmaSelMatch(x, e, hay));
  if (sel.any) return sel.any.some(re => re.test(hay));
  return sel.and.every(c => {
    if (c.kwAll) return c.kwAll.every(re => re.test(hay));
    const v = _sigmaFieldValue(e, c.field);
    if ('exists' in c) return c.exists ? v !== undefined : v === undefined;
    const one = t => t.nullTest ? (v === undefined || v === '') : (v !== undefined && t(v));
    if (c.neq) return v !== undefined && !c.tests.some(one);
    return c.all ? c.tests.every(one) : c.tests.some(one);
  });
}
function sigmaMatchEvent(rule, e) {
  if (rule.windowsOnly) {
    if (e.format !== 'winevent') return false;
    const cat = SIGMA_WIN_CATEGORY[rule.category];
    if (cat && !cat(e)) return false;
    const svc = SIGMA_WIN_SERVICE[rule.service];
    if (svc && !svc.test(String((e.fields || {}).Channel || ''))) return false;
  }
  const hay = [e.raw, e.msg, JSON.stringify(e.fields || {})].join(' ');
  const memo = {};
  const sel = id => (id in memo ? memo[id] : (memo[id] = _sigmaSelMatch(rule.sels[id], e, hay)));
  const ev = n => n.op === 'id' ? sel(n.id) : n.op === 'not' ? !ev(n.a) : n.op === 'and' ? ev(n.a) && ev(n.b) : n.op === 'or' ? ev(n.a) || ev(n.b)
    : n.op === 'oneOf' ? n.ids.some(sel) : n.ids.every(sel);
  return ev(rule.cond);
}
const _sigmaCache = new Map();
function sigmaCompiled(text) {
  if (!_sigmaCache.has(text)) _sigmaCache.set(text, parseSigmaRule(text));
  return _sigmaCache.get(text);
}
// ── 自訂規則匯出 Sigma（2026-10-21，第三十三輪 XN9）────────────────────────
// 依 SigmaHQ sigma-specification：必要區段只有 title／logsource／detection（logsource 子欄位皆選填），
// 字串清單為全文 OR 比對、預設不分大小寫，萬用字元 * ? 與反斜線以 \ 跳脫；level 為
// informational／low／medium／high／critical。只輸出能無損表達的規則：
//   sigma：原文照出；contains：keywords 清單（不限格式或限 Windows 事件〔logsource product: windows，
//   本工具匯入時同樣只比對 winevent〕）；regex（比對整筆事件文字，Sigma 須指定欄位才能用 |re）與
//   其他格式篩選（沒有對應的 logsource）不輸出並回報原因。多條規則以 --- 分隔（pySigma 以 safe_load_all 讀取）
const SEV_SIGMA_LEVEL = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Info: 'informational' };
function sigmaEscapeKeyword(s) { return String(s).replace(/\\/g, '\\\\').replace(/\*/g, '\\*').replace(/\?/g, '\\?'); }
function _sigmaQuote(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }
// 回傳 {ok:true, yaml} 或 {ok:false, reason}（reason：regex／format／empty／sigma_invalid）
function customRuleToSigma(rule, date) {
  if (!rule || !String(rule.pattern || '').trim()) return { ok: false, reason: 'empty' };
  if (rule.matchType === 'sigma') return sigmaCompiled(rule.pattern).error ? { ok: false, reason: 'sigma_invalid' } : { ok: true, yaml: String(rule.pattern).replace(/\r\n/g, '\n').replace(/\s+$/, '') };
  if (rule.matchType === 'regex') return { ok: false, reason: 'regex' };
  if (rule.formatFilter && rule.formatFilter !== 'winevent') return { ok: false, reason: 'format' };
  const lines = [
    'title: ' + _sigmaQuote(rule.name || 'Custom rule'),
    'status: experimental',
    "description: 'Exported from Alpaca Network Toolkit log analyzer custom rule (case-insensitive full-text keyword search)'",
  ];
  if (date) lines.push('date: ' + date);
  lines.push('logsource:', rule.formatFilter === 'winevent' ? '    product: windows' : "    definition: 'Any log source (full-text keyword search)'");
  lines.push('detection:', '    keywords:', '        - ' + _sigmaQuote(sigmaEscapeKeyword(rule.pattern)), '    condition: keywords',
    'level: ' + (SEV_SIGMA_LEVEL[rule.severity] || 'medium'));
  return { ok: true, yaml: lines.join('\n') };
}
// 多條規則合成一份 YAML：開頭註解列出未輸出的規則與原因；回傳 {text, exported, skipped:[{name,reason}]}
function customRulesToSigmaDoc(rules, date) {
  const docs = [], skipped = [];
  (rules || []).forEach(r => {
    const res = customRuleToSigma(r, date);
    if (res.ok) docs.push(res.yaml); else skipped.push({ name: r && r.name || '', reason: res.reason });
  });
  const head = skipped.length ? skipped.map(s => `# skipped: ${String(s.name).replace(/[\r\n]/g, ' ')} (${s.reason})`).join('\n') + '\n' : '';
  return { text: head + docs.join('\n---\n') + (docs.length ? '\n' : ''), exported: docs.length, skipped };
}

// 問題清單「比對依據」欄：說明該筆問題具體為何被判定成立，不是重複「範例」欄的原始 log 行。
// knownIOC／freq 兩類先前完全沒有這個資訊（範例欄只印原始行，看不出是哪個 IP／對到清單哪條
// 規則／為何達門檻）；possibleScan 兩種 heuristic 的 sampleRaw 本身已是合成說明文字，這裡
// 回傳 '-' 避免重複。內容全是 IP/CIDR/ID/數字這類語言無關資料，不需要 i18n 翻譯
function formatIssueBasis(is) {
  // 漏洞利用嘗試與帶 CVE 的 IDS 告警（XN17）：依據欄列出 CVE（不分語言）
  if (is.category === 'exploitAttempt') return `${(is.cves || []).join(', ')} | ${is.exploitSig}${is.exploitOk ? ' | 2xx=' + is.exploitOk : ''}`;
  if (is.category === 'idsAlert' && is.cves && is.cves.length) return is.cves.join(', ');
  if (is.category === 'knownIOC' || is.category === 'knownHashIOC') {
    const ip = (is.relatedHosts && is.relatedHosts[0]) || '';
    const meta = is.intelMeta || {};
    const metaParts = Object.keys(meta)
      .filter(k => meta[k] !== undefined && meta[k] !== null && String(meta[k]).trim() !== '' && String(meta[k]) !== ip)
      .map(k => `${k}=${meta[k]}`);
    return [ip, ...metaParts].filter(Boolean).join(' | ') || '-';
  }
  if (is.category.startsWith('freq:') && is.windowMs !== undefined) {
    return `${is.count}/${is.threshold} @ ${Math.round(is.windowMs / 1000)}s`;
  }
  if (is.category === 'volumeAnomaly') {
    return `${formatBytesHuman(is.totalBytes)}${is.volumeSrc ? ' | ' + is.volumeSrc : ''}`;
  }
  if (is.category === 'geoRisk') {
    return `${is.geoCountry} (${is.geoDirection})${is.geoIp ? ' | ' + is.geoIp : ''}`;
  }
  if (is.category === 'geoIPRisk') {
    return `${is.geoCountry} | ${is.geoIp}${is.geoSource ? ' | ' + is.geoSource : ''}`;
  }
  if (is.category === 'mfaFatigue') {
    return `denies=${is.mfaDenies} → success`;
  }
  if (is.category === 'appsmithOriginReset') return `${APPSMITH_CVE} | Origin=${is.appsmithOrigin} | site=${is.appsmithSite}`;
  if (is.category === 'appsmithResetFlow' || is.category === 'appsmithResetBurst') return 'Appsmith /api/v1/users/forgotPassword → resetPassword';
  if (/^appsmith(ExternalRisky|ScriptedApi|Exposed)$/.test(is.category)) return `Appsmith ${(is.appsmithKinds || []).join(', ')}${is.appsmithUa ? ' | UA=' + is.appsmithUa : ''}${is.appsmithSrcs ? ' | src=' + is.appsmithSrcs : ''}`;
  if (/^gitlab(CiVarRead|MassClone)$/.test(is.category)) return `targets=${(is.glTargets || []).join(', ')}`;
  if (is.category === 'gitlabTokenMultiSource') return `token=${is.credKey} | src=${(is.relatedHosts || []).join(', ')}`;
  if (is.category === 'promptInjection') return `text=${(is.promptInjText || []).join(' / ')}`;
  if (is.category === 'credFileExposed') return `files=${(is.credFiles || []).join(', ')} | 2xx`;
  if (is.category === 'secretBulkRead') return `secrets=${(is.credSecrets || []).join(', ')}`;
  if (is.category === 'cloudKeyMultiSource' || is.category === 'sshKeyMultiSource') return `key=${is.credKey} | src=${(is.relatedHosts || []).join(', ')}`;
  if (is.category === 'appCredentialAdded') return `app=${is.credApp} | ${(is.relatedEvents[0] && is.relatedEvents[0].msgid) || ''}`;
  if (is.category === 'adminLoginExternal') return `src=${is.adminSrc} | user=${is.adminAcct}${is.adminMethod ? ' | ' + is.adminMethod : ''} | fails=${is.adminFails}`;
  if (is.category === 'adminLoginFailExternal') return `srcs=${is.adminSrcs} | users=${is.adminUsers} | fails=${is.count} @ 24h`;
  if (is.category === 'netAdminAdd') {
    return `acct=${is.adminAcct}${is.adminPriv ? ' | priv=' + is.adminPriv : ''}${is.adminBy ? ' | by=' + is.adminBy : ''}`;
  }
  if (is.category === 'distributedSpray') {
    return `srcs=${is.spraySrcs} | users=${is.sprayUsers} | fails=${is.count} @ 24h`;
  }
  if (is.category === 'rmmTool') {
    return `tool=${is.rmmTool} | domain=${is.rmmDomains.join(',')} | client=${is.rmmClient}`;
  }
  if (is.category === 'vpnAnonLogin') {
    return `${is.vpnIps.join(', ')} | ${is.vpnSrc} | list=${is.anonLists.join(',') || '-'}`;
  }
  if (is.category === 'vpnHostingLogin') {
    return `${is.asnValue}${is.asnName ? ' ' + is.asnName : ''} | ${is.vpnIps.join(', ')} | ${is.vpnSrc}`;
  }
  if (is.category === 'asnRisk') {
    return `${is.asnValue}${is.asnName ? ' ' + is.asnName : ''} | ${is.asnIp}${is.asnSource ? ' | ' + is.asnSource : ''}`;
  }
  if (is.category === 'beaconing') {
    return `CV=${is.beaconCv.toFixed(3)} | interval≈${Math.round(is.beaconIntervalMs / 1000)}s`;
  }
  if (is.category === 'lateralMovement') {
    return `EventID 4624 | hosts=${is.count}`;
  }
  if (is.category === 'privEsc') {
    return is.privEscEventId ? `EventID ${is.privEscEventId}` : 'keyword (heuristic)';
  }
  if (is.category === 'geoVelocity') {
    return (is.geoCountries || []).join(' / ');
  }
  if (is.category === 'passTheHash') {
    return `EventID 4624 | LogonType=9(NewCredentials) | TargetUserName=${is.pthUserName}`;
  }
  if (is.category === 'kerberoasting') {
    return `EventID 4769 | etype=0x17(RC4) | ServiceName=${is.kerbServiceName}`;
  }
  if (is.category === 'asrepRoasting') {
    return `EventID 4768 | etype=0x17(RC4) | PreAuthType=0 | TargetUserName=${is.asrepUserName}`;
  }
  if (is.category === 'asrepRoastingRisk') {
    return `EventID 4738 | +DONT_REQUIRE_PREAUTH | TargetUserName=${is.uacRiskUserName}`;
  }
  if (is.category === 'lsassAccess') {
    return `EventID 10 | TargetImage=lsass.exe | GrantedAccess=${is.lsassGrantedAccess} | SourceImage=${is.lsassSourceImage}`;
  }
  if (is.category === 'sysmonRegistryPersistence') {
    return `EventID 13 | ${is.regTargetObject} | ${is.regImage}${is.regDetails ? ' = ' + is.regDetails : ''}`;
  }
  if (is.category === 'adminShareAccess') {
    return `EventID ${is.winEventId} | ShareName=${is.shareName}`;
  }
  if (is.category === 'processCreate') {
    return `${is.procMatchedKeyword} | ${is.procNewProcess}${is.procParent ? ' ← ' + is.procParent : ''}`;
  }
  if (is.category === 'asnVelocity') {
    return (is.asnList || []).join(' / ');
  }
  if (is.category === 'sysmonProcessCreate') {
    return `${is.sysmonMatchedKeyword} | ${is.sysmonImage}${is.sysmonParentImage ? ' ← ' + is.sysmonParentImage : ''}`;
  }
  if (is.category === 'sysmonRemoteThread') {
    return `${is.threadMatchedKeyword} | ${is.threadSourceImage} → ${is.threadTargetImage}`;
  }
  if (is.category === 'powershellScriptBlock') {
    return `${is.psMatchedKeyword} | ${(is.psScriptBlockText||'').slice(0,120)}`;
  }
  if (is.category === 'sysmonImageLoad') {
    return `${is.imgLoadMatchedKeyword} | ${is.imgLoadImage} ← ${is.imgLoadImageLoaded}`;
  }
  if (is.category === 'powershellModuleLog') {
    return `${is.psModuleMatchedKeyword} | ${(is.psModuleContextInfo||'').slice(0,120)}`;
  }
  if (is.winEventId) {
    return `EventID ${is.winEventId}`;
  }
  return '-';
}
function formatBytesHuman(n) {
  const bytes = Number(n) || 0;
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let val = bytes / 1024, i = 0;
  while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
  return `${val.toFixed(1)} ${units[i]}`;
}
// fetch_threat_intel.ps1 這類合併多來源情資輸出的 NDJSON，同一網段被多個來源收錄時
// intelMeta.source 會是逗號分隔字串（如 "firehol_level1,cins_army"），這裡統一拆開存取，
// 問題清單「情資來源」欄與來源篩選下拉共用同一套拆分邏輯，避免各自寫一次逗號 split
function getIssueIntelSources(is) {
  if ((is.category !== 'knownIOC' && is.category !== 'knownHashIOC') || !is.intelMeta || !is.intelMeta.source) return [];
  return String(is.intelMeta.source).split(',').map(s => s.trim()).filter(Boolean);
}
function getDistinctIntelSources(issues) {
  const set = new Set();
  issues.forEach(is => getIssueIntelSources(is).forEach(s => set.add(s)));
  return Array.from(set).sort();
}
function filterIssuesBySource(issues, source) {
  if (!source) return issues;
  return issues.filter(is => getIssueIntelSources(is).includes(source));
}
// 問題清單抑制/調校清單（2026-09-15 新增）：使用者可將特定分類標記為「已知雜訊」不再顯示，
// 純渲染層過濾（比照 filterIssuesBySource() 既有分工——buildIssueList() 本身維持不受影響，
// 純函式，不含任何過濾邏輯），故意不套用到 CSV/HTML 報表匯出（與 ISSUES_SOURCE_FILTER 既有
// 「僅畫面即時篩選、不影響匯出」慣例一致，避免匯出結果因螢幕設定不同而缺漏真實命中的問題）
function filterIssuesBySuppressed(issues, suppressedSet) {
  if (!suppressedSet || !suppressedSet.size) return issues;
  return issues.filter(is => !suppressedSet.has(is.category));
}
// 依處理狀態篩選（2026-09-29 新增）：mode 為 ''（全部）／'open'／'confirmed'／'falsePositive'
// （只看該狀態）或 'hideFalsePositive'（隱藏誤判）；statusOf(issue) 回傳該問題的狀態字串。
// 比照 filterIssuesBySuppressed() 只影響畫面呈現，不套用到 CSV／報表匯出
function filterIssuesByStatus(issues, statusOf, mode) {
  if (!mode) return issues;
  if (mode === 'hideFalsePositive') return issues.filter(is => statusOf(is) !== 'falsePositive');
  return issues.filter(is => statusOf(is) === mode);
}
// opts 可覆寫偵測門檻（皆為選填，未提供則沿用各函式自身預設值）：
// windowMs/freqThreshold 對應頻率異常，scanThreshold 對應 CEF/Syslog 兩種掃描 heuristic 共用門檻
// 自訂偵測規則建構器（2026-09-16 新增）：讓使用者自建任意數量的「名稱＋嚴重度＋比對方式
// （關鍵字/正則）＋比對樣式＋選填格式篩選」規則，比對範圍不逐欄位挑選（fields 隨格式而異，
// 逐欄位挑選在跨格式情境下體驗不佳），改比對幾乎涵蓋所有情境的組合字串（raw/host/appName/
// msg/fields 全部攤平）。與既有兩段式開關偵測器（如 detectProcessCreation()）的差異：
// 一條規則命中的「全部」事件聚合成一筆 issue（count=命中數），而非每筆事件各自一筆——避免
// 過寬的規則洗版問題清單，聚合後的單筆 issue 仍可展開看到樣本事件（relatedEvents 上限 50 筆）
function ruleMatchesEvent(rule, haystackLower, haystackRaw) {
  if (rule.matchType === 'regex') {
    let re;
    try { re = new RegExp(rule.pattern, 'i'); } catch (e) { return false; }
    return re.test(haystackRaw);
  }
  return haystackLower.includes(String(rule.pattern).toLowerCase());
}
function detectCustomRules(events, rules) {
  const list = Array.isArray(rules) ? rules : [];
  const issues = [];
  list.forEach(rule => {
    if (!rule || !rule.enabled || !rule.pattern) return;
    if (rule.matchType === 'regex') {
      try { new RegExp(rule.pattern); } catch (e) { return; }
    }
    const sg = rule.matchType === 'sigma' ? sigmaCompiled(rule.pattern) : null;
    if (sg && sg.error) return;
    const matches = [];
    events.forEach(e => {
      if (sg) { if (sigmaMatchEvent(sg, e)) matches.push(e); return; }
      if (rule.formatFilter && e.format !== rule.formatFilter) return;
      const haystackRaw = [e.raw, e.host, e.appName, e.msg, JSON.stringify(e.fields || {})].join(' ');
      if (!ruleMatchesEvent(rule, haystackRaw.toLowerCase(), haystackRaw)) return;
      matches.push(e);
    });
    if (!matches.length) return;
    const hosts = [];
    matches.forEach(e => { if (e.host && !hosts.includes(e.host)) hosts.push(e.host); });
    const times = matches.map(e => e.timestamp).filter(Boolean);
    issues.push({
      // 嚴重度只接受固定五級：設定檔或工作區檔案可被竄改，值會進到畫面的 class 屬性
      category: 'custom:' + rule.id, customRuleName: rule.name, severityNorm: ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(rule.severity) ? rule.severity : 'Medium',
      count: matches.length,
      firstSeen: times.length ? new Date(arrMin(times.map(t => +t))) : null,
      lastSeen: times.length ? new Date(arrMax(times.map(t => +t))) : null,
      sampleRaw: matches[0].raw, relatedHosts: hosts.slice(0, 20), relatedEvents: matches.slice(0, 50),
      confidence: 'heuristic', customRuleId: rule.id, customRuleMatchType: rule.matchType, customRulePattern: rule.pattern,
      chainStage: rule.stage || '', mitre: sg && sg.mitre ? sg.mitre : undefined
    });
  });
  return issues;
}
// 登入失敗原因彙整（第三十輪 WN2）：Windows 登入失敗事件 5 筆以上時列一筆 Low，依原因統計筆數與帳號數；
// 「帳號不存在」有 5 個以上不同帳號時升為 Medium（常見於帳號列舉或密碼噴灑使用過時名單）
const WIN_FAIL_SUMMARY_MIN = 5;
function detectWinFailReasons(events) {
  const list = events.filter(e => e.format === 'winevent' && e.fields && e.fields.failKind);
  if (list.length < WIN_FAIL_SUMMARY_MIN) return [];
  const by = new Map();
  list.forEach(e => {
    const r = e.fields.failReason;
    if (!by.has(r)) by.set(r, { n: 0, users: new Set(), kind: e.fields.failKind });
    const g = by.get(r);
    g.n++;
    const u = e.fields.TargetUserName || e.fields.TargetAccountName;
    if (u && u !== '-') g.users.add(String(u).toLowerCase());
  });
  const rows = [...by.entries()].sort((a, b) => b[1].n - a[1].n);
  const unknownUsers = new Set();
  rows.forEach(([, g]) => { if (g.kind === 'unknownUser') g.users.forEach(u => unknownUsers.add(u)); });
  const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
  return [{
    category: 'winFailReasons', severityNorm: unknownUsers.size >= 5 ? 'Medium' : 'Low', count: list.length,
    firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
    ...sampleOf('sample.winFailReasons', { n: list.length, list: rows.slice(0, 5).map(([r, g]) => `${r} ×${g.n}` + (g.users.size ? ` (${g.users.size})` : '')).join('; ') }),
    relatedHosts: [...new Set(list.map(e => e.host).filter(Boolean))], relatedEvents: sorted, confidence: 'confirmed',
    failKinds: Object.fromEntries(rows.map(([r, g]) => [r, g.n]))
  }];
}
// 密碼噴灑（第三十輪 WN7）：同一來源位址 1 小時內對 5 個以上不同帳號認證失敗、且平均每帳號不超過 3 次
// （與針對單一帳號的暴力破解區分）；適用所有歸為 authFail 的事件（Windows、LDAP、RADIUS、SSH、VPN、雲端登入…）。
// Windows 的 IpAddress 可能是 ::ffff:IPv4 形式，先轉成 IPv4；同一來源同時段只列一次
const SPRAY_MIN_USERS = 5, SPRAY_MAX_AVG = 3, SPRAY_WINDOW_MS = 60 * 60 * 1000;
function authFailActor(e) {
  const f = e.fields || {};
  let src = f.srcip || f.src || f.IpAddress || f.ipAddress || '';
  // FortiGate 管理登入舊版只有 ui="ssh(位址)"（XN48）
  if (!src) { const al = adminLoginOf(e); if (al) src = al.src; }
  src = String(src).replace(/^::ffff:/i, '');
  if (!src || src === '-' || src === '::1' || src === '127.0.0.1') return null;
  const t = f.TargetUserName && f.TargetUserName !== '-' ? f.TargetUserName : '';
  const u = t || f.user || pickField(f, WINEVENT_USER_KEYS) || pickField(f, JSON_USER_KEYS);
  if (!u || u === '-') return null;
  return { src, user: String(u).replace(/^[^\\]+\\/, '').toLowerCase() };
}
function detectPasswordSpray(events) {
  const bySrc = new Map();
  events.forEach(e => {
    if (e.category !== 'authFail') return;
    // LDAP 繫結失敗已由 ldapBruteForce 依來源列出帳號清單，不重複列密碼噴灑
    if (e.fields && e.fields.ldap) return;
    const a = authFailActor(e);
    if (!a) return;
    if (!bySrc.has(a.src)) bySrc.set(a.src, []);
    bySrc.get(a.src).push({ e, user: a.user });
  });
  const issues = [];
  for (const [src, list] of bySrc) {
    const sorted = list.sort((a, b) => effectiveTime(a.e) - effectiveTime(b.e));
    // 滑動視窗以帳號計數累加（不每筆重建集合，大量失敗時才不會平方成長）
    let start = 0, best = null;
    const cnt = new Map();
    for (let i = 0; i < sorted.length; i++) {
      const t = effectiveTime(sorted[i].e);
      cnt.set(sorted[i].user, (cnt.get(sorted[i].user) || 0) + 1);
      while (t - effectiveTime(sorted[start].e) > SPRAY_WINDOW_MS) {
        const u = sorted[start].user, c = cnt.get(u) - 1;
        if (c) cnt.set(u, c); else cnt.delete(u);
        start++;
      }
      if (cnt.size >= SPRAY_MIN_USERS && (i - start + 1) / cnt.size <= SPRAY_MAX_AVG && (!best || cnt.size > best.n)) best = { s: start, e: i, n: cnt.size };
    }
    if (best) { const win = sorted.slice(best.s, best.e + 1); best = { win, users: new Set(win.map(x => x.user)) }; }
    if (!best) continue;
    const ev = best.win.map(x => x.e);
    issues.push({
      category: 'passwordSpray', severityNorm: 'High', count: ev.length,
      firstSeen: ev[0].timestamp || null, lastSeen: ev[ev.length - 1].timestamp || null,
      ...sampleOf('sample.passwordSpray', { src, users: best.users.size, n: ev.length, list: [...best.users].slice(0, 5).join(', ') }),
      relatedHosts: [src, ...[...best.users].slice(0, 5)], relatedEvents: ev, confidence: 'heuristic'
    });
  }
  return issues;
}
// 分散式密碼噴灑（2026-10-27，第三十五輪 XN30）：依 Huntress（LSHIY，輪替約 1.28 萬個 IP、每個 IP 次數壓低）、
// Check Point、Guardz（90 天、25 國以上來源、低於鎖定門檻）報告，攻擊分散到很多來源時 detectPasswordSpray() 抓不到。
// 只看外部來源（iocIsInternalIP() 排除私有／保留位址；內部噴灑由 passwordSpray 處理）。24 小時內試過 ≥2 個帳號的
// 來源算噴灑來源（員工打錯密碼通常是一個來源對一個帳號），噴灑來源 ≥5 個且涵蓋 ≥10 個帳號時列出帳號最多的視窗；
// 已由 passwordSpray 列出的來源（excludeSrcs）不重複計入。滑動視窗以計數增減，不每筆重建集合
const DSPRAY_WINDOW_MS = 24 * 60 * 60 * 1000, DSPRAY_MIN_SOURCES = 5, DSPRAY_MIN_USERS = 10, DSPRAY_SRC_MIN_USERS = 2;
function detectDistributedSpray(events, excludeSrcs) {
  const skip = new Set(excludeSrcs || []);
  const list = [];
  events.forEach(e => {
    if (e.category !== 'authFail' || (e.fields && e.fields.ldap)) return;
    const a = authFailActor(e);
    if (!a || skip.has(a.src) || iocIsInternalIP(a.src)) return;
    list.push({ e, src: a.src, user: a.user });
  });
  if (list.length < DSPRAY_MIN_SOURCES * DSPRAY_SRC_MIN_USERS) return [];
  list.sort((a, b) => effectiveTime(a.e) - effectiveTime(b.e));
  const bySrc = new Map(), cover = new Map();
  let spraying = 0, start = 0, best = null;
  const inc = u => cover.set(u, (cover.get(u) || 0) + 1);
  const dec = u => { const c = cover.get(u) - 1; if (c) cover.set(u, c); else cover.delete(u); };
  const add = x => {
    const m = bySrc.get(x.src) || new Map();
    bySrc.set(x.src, m);
    const c = m.get(x.user) || 0;
    m.set(x.user, c + 1);
    if (c) return;
    if (m.size === DSPRAY_SRC_MIN_USERS) { spraying++; m.forEach((_, u) => inc(u)); }
    else if (m.size > DSPRAY_SRC_MIN_USERS) inc(x.user);
  };
  const remove = x => {
    const m = bySrc.get(x.src), c = m.get(x.user) - 1;
    if (c) { m.set(x.user, c); return; }
    const was = m.size;
    m.delete(x.user);
    if (was === DSPRAY_SRC_MIN_USERS) { spraying--; dec(x.user); m.forEach((_, u) => dec(u)); }
    else if (was > DSPRAY_SRC_MIN_USERS) dec(x.user);
    if (!m.size) bySrc.delete(x.src);
  };
  for (let i = 0; i < list.length; i++) {
    add(list[i]);
    const t = effectiveTime(list[i].e);
    while (t - effectiveTime(list[start].e) > DSPRAY_WINDOW_MS) remove(list[start++]);
    // 帳號數最多的視窗；帳號數相同時取噴灑來源較多者（同一波攻擊持續時，視窗會延伸到後面的來源）
    if (spraying >= DSPRAY_MIN_SOURCES && cover.size >= DSPRAY_MIN_USERS && (!best || cover.size > best.n || (cover.size === best.n && spraying > best.k))) best = { s: start, e: i, n: cover.size, k: spraying };
  }
  if (!best) return [];
  const win = list.slice(best.s, best.e + 1);
  const usersBySrc = new Map();
  win.forEach(x => { if (!usersBySrc.has(x.src)) usersBySrc.set(x.src, new Set()); usersBySrc.get(x.src).add(x.user); });
  const srcs = [...usersBySrc].filter(([, us]) => us.size >= DSPRAY_SRC_MIN_USERS).map(([s]) => s);
  const srcSet = new Set(srcs);
  const hits = win.filter(x => srcSet.has(x.src));
  const users = [...new Set(hits.map(x => x.user))];
  const ev = hits.map(x => x.e);
  return [{
    category: 'distributedSpray', severityNorm: 'High', count: ev.length,
    firstSeen: ev[0].timestamp || null, lastSeen: ev[ev.length - 1].timestamp || null,
    sprayUsers: users.length, spraySrcs: srcs.length,
    ...sampleOf('sample.distributedSpray', { srcs: srcs.length, users: users.length, n: ev.length, list: users.slice(0, 5).join(', ') }),
    relatedHosts: [...srcs.slice(0, 5), ...users.slice(0, 5)], relatedEvents: ev, confidence: 'heuristic'
  }];
}
// AD 物件高風險異動（第三十輪 WN4／WN5）：
//   5136（目錄服務物件已修改，需在網域控制站開啟「稽核目錄服務變更」並設定 SACL）：AttributeLDAPDisplayName 為
//     servicePrincipalName（使用者物件，可被拿來 Kerberoasting）、msDS-AllowedToActOnBehalfOfOtherIdentity（資源型委派）、
//     msDS-AllowedToDelegateTo（限制委派）、msDS-KeyCredentialLink（Shadow Credentials）、sIDHistory、scriptPath（登入指令碼）、
//     gPLink（連結群組原則）；或 ObjectDN 為 CN=AdminSDHolder 的任何異動
//   4742（電腦帳號已變更）：ServicePrincipalNames 或 AllowedToDelegateTo 有值（未變更的欄位為 -）
//   4741（電腦帳號已建立）：依建立者彙整（Low，MachineAccountQuota 濫用時可看出非管理員大量建立）
//   4887（憑證服務核發憑證）：依申請者彙整（Low）；要求屬性含 SAN: 時（申請者自行指定主體別名，ESC6 等濫用）升為 High
const AD_RISKY_ATTRS = { serviceprincipalname: 'T1098', 'msds-allowedtoactonbehalfofotheridentity': 'T1098', 'msds-allowedtodelegateto': 'T1098', 'msds-keycredentiallink': 'T1098', sidhistory: 'T1134.005', scriptpath: 'T1037.003', gplink: 'T1484.001' };
function detectAdChanges(events) {
  const issues = [];
  const time = (a, b) => effectiveTime(a) - effectiveTime(b);
  const changes = new Map();
  const add = (key, e, attr, obj, mitre) => { if (!changes.has(key)) changes.set(key, { list: [], attr, obj, mitre }); changes.get(key).list.push(e); };
  // 安全描述元變更成對記錄：刪除舊值（%%14675）與加入新值（%%14674），以 OpCorrelationID 對應；只看新值多出來的 ACE
  const sdOld = new Map();
  const isSdDel = f => /14675|Deleted/i.test(f.OperationType || '');
  events.forEach(e => { const f = e.fields; if (e.format === 'winevent' && f && f.EventID === '5136' && isSdDel(f) && /^ntsecuritydescriptor$/i.test(f.AttributeLDAPDisplayName || '')) sdOld.set(f.OpCorrelationID || '', String(f.AttributeValue || '').toLowerCase()); });
  const newReplAce = f => {
    if (isSdDel(f)) return false;
    const old = sdOld.get(f.OpCorrelationID || '') || '';
    // 網域控制站、唯讀網域控制站、Domain／Enterprise Admins 預設就有複寫權限（RID 498／516／521／512／519）
    return (String(f.AttributeValue || '').toLowerCase().match(/\([^()]*\)/g) || []).some(ace =>
      DS_REPL_GUIDS.some(g => ace.includes(g + ';;s-1-5-21-')) && !/-(?:498|516|521|512|519)\)$/.test(ace) && !old.includes(ace));
  };
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    const f = e.fields;
    if (f.EventID === '5136') {
      const attr = String(f.AttributeLDAPDisplayName || '');
      const obj = String(f.ObjectDN || '');
      const a = attr.toLowerCase();
      if (/^CN=AdminSDHolder,CN=System,/i.test(obj)) add(obj + '|' + attr, e, attr, obj, 'T1098');
      // 安全描述元加入目錄複寫權限（授予 DCSync 能力的後門，Sigma win_security_account_backdoor_dcsync_rights）
      else if (a === 'ntsecuritydescriptor' && newReplAce(f)) add(obj + '|' + attr, e, attr, obj, 'T1003.006');
      else if (AD_RISKY_ATTRS[a] && !(a === 'serviceprincipalname' && !/^user$/i.test(f.ObjectClass || ''))) add(obj + '|' + attr, e, attr, obj, AD_RISKY_ATTRS[a]);
    } else if (f.EventID === '4742') {
      ['ServicePrincipalNames', 'AllowedToDelegateTo'].forEach(k => { if (f[k] && f[k].trim() && f[k].trim() !== '-') add((f.TargetUserName || '') + '|' + k, e, k, f.TargetUserName || '', 'T1098'); });
    }
  });
  for (const [, g] of changes) {
    const sorted = [...g.list].sort(time);
    const who = [...new Set(sorted.map(e => e.fields.SubjectUserName).filter(x => x && x !== '-'))];
    issues.push({ category: 'adSensitiveChange', severityNorm: 'High', count: sorted.length, mitre: g.mitre,
      firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf('sample.adSensitiveChange', { who: who.join(', ') || '-', attr: g.attr, obj: g.obj || '-' }),
      relatedHosts: [...who, ...new Set(sorted.map(e => e.host).filter(Boolean))], relatedEvents: sorted, confidence: 'confirmed' });
  }
  const groupBy = (list, keyOf) => { const m = new Map(); list.forEach(e => { const k = keyOf(e) || '-'; if (!m.has(k)) m.set(k, []); m.get(k).push(e); }); return m; };
  const win = events.filter(e => e.format === 'winevent' && e.fields);
  for (const [who, l] of groupBy(win.filter(e => e.fields.EventID === '4741'), e => e.fields.SubjectUserName)) {
    const sorted = [...l].sort(time);
    issues.push({ category: 'computerAccountCreated', severityNorm: 'Low', count: sorted.length,
      firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf('sample.computerAccountCreated', { who, n: sorted.length, list: sorted.map(e => e.fields.TargetUserName).filter(Boolean).slice(0, 5).join(', ') || '-' }),
      relatedHosts: [who], relatedEvents: sorted, confidence: 'confirmed' });
  }
  for (const [who, l] of groupBy(win.filter(e => e.fields.EventID === '4887'), e => e.fields.Requester)) {
    const sorted = [...l].sort(time);
    const san = sorted.filter(e => /\bSAN:/i.test(e.fields.Attributes || ''));
    issues.push({ category: 'certIssued', severityNorm: san.length ? 'High' : 'Low', count: sorted.length, ...(san.length ? { mitre: 'T1649' } : {}),
      firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf(san.length ? 'sample.certIssuedSan' : 'sample.certIssued', { who, n: sorted.length, san: san.length }),
      relatedHosts: [who], relatedEvents: sorted, confidence: san.length ? 'heuristic' : 'confirmed' });
  }
  return issues;
}
// RADIUS 伺服器異常（第三十輪 RA3）：
//   radiusUnknownClient：未登記的設備送來請求（依來源位址，Medium）
//   radiusBadSecret：共用密鑰不符（依來源位址，Medium；設定錯誤或偽造封包）
//   radiusTlsFail：EAP-TLS／PEAP 的 TLS 失敗（依原因，Low；憑證過期或未知 CA 常造成整批終端連不上）
//   radiusBlast：BlastRADIUS（CVE-2024-3596）檢查發現封包沒有 Message-Authenticator（依設備，Medium）
//   radiusMacMultiUser：同一個終端 MAC 1 小時內以 3 個以上不同帳號認證（Medium；共用或冒用帳號）
const RADIUS_MAC_USERS_MIN = 3;
// ── 服務狀態與異常偵測（XN16）──────────────────────────────────────────────
// 同一服務＋主機的事件依時間排序：當機 60 秒內的多筆（systemd 兩行、kernel segfault）合併為一次；非預期重啟為前一次啟動之後
// 沒有停止／當機紀錄又出現啟動（多半是當機但 log 沒寫原因）。每個問題帶 companions：建議一併匯入的 log（使用者調整 1）
const SVC_LABEL = { openldap: 'OpenLDAP', '389ds': '389 Directory Server', freeradius: 'FreeRADIUS' };
const SVC_BACKEND_COMP = { sql: ['dbServer', 'network'], ldap: ['ldapServer', 'network'] };
function svcEpisodes(list, gapMs) {
  const eps = [];
  let last = -Infinity;
  list.forEach(e => { const tm = effectiveTime(e) || 0; if (!eps.length || tm - last > gapMs) eps.push([e]); else eps[eps.length - 1].push(e); last = tm; });
  return eps;
}
function detectServiceHealth(events) {
  const issues = [];
  const sv = events.filter(e => e.fields && e.fields.svc);
  if (!sv.length) return issues;
  const time = (a, b) => (effectiveTime(a) || 0) - (effectiveTime(b) || 0);
  const groupBy = (list, keyOf) => { const m = new Map(); list.forEach(e => { const k = keyOf(e); if (k === null || k === undefined) return; if (!m.has(k)) m.set(k, []); m.get(k).push(e); }); return m; };
  const why = l => [...new Set(l.map(e => e.fields.svcDetail).filter(Boolean))].slice(0, 3).join('; ');
  const push = (cat, sev, list, key, p, host, companions) => {
    const s = [...list].sort(time);
    issues.push({ category: cat, severityNorm: sev, count: p.n || s.length, firstSeen: s[0].timestamp || null, lastSeen: s[s.length - 1].timestamp || null,
      ...sampleOf(key, { n: s.length, ...p }), relatedHosts: host ? [host] : [], relatedEvents: s, confidence: 'confirmed', companions });
  };
  for (const [k, l] of groupBy(sv, e => e.fields.svcName + '|' + (e.host || ''))) {
    const [name, host] = k.split('|');
    const svc = SVC_LABEL[name] || name, h = host || '-';
    const s = [...l].sort(time), of = kind => s.filter(e => e.fields.svc === kind);
    const crashes = svcEpisodes(of('crash'), 60000);
    if (crashes.length) {
      const w = why(crashes.flat());
      push('svcCrash', 'High', crashes.flat(), w ? 'sample.svcCrash' : 'sample.svcCrashUnknown', { svc, host: h, n: crashes.length, why: w }, host, ['journal', 'kernel', 'coredump', 'debug', 'monitoring']);
    }
    let started = false, clean = true;
    const unexpected = [];
    s.forEach(e => { const v = e.fields.svc; if (v === 'start') { if (started && !clean) unexpected.push(e); started = true; clean = false; } else if (v === 'stop' || v === 'stopping' || v === 'crash') clean = true; });
    if (unexpected.length) push('svcUnexpectedRestart', 'Medium', unexpected, 'sample.svcUnexpectedRestart', { svc, host: h }, host, ['journal', 'kernel', 'coredump', 'monitoring']);
    const comp = name === 'freeradius' ? ['journal', 'debug'] : ['disk', 'journal'];
    [['dbError', 'svcDbError', 'High', comp], ['bindFail', 'svcBindFail', 'High', ['portowner', 'journal']], ['resource', 'svcResource', 'Medium', ['limits', 'monitoring', 'journal']],
      ['replFail', 'svcReplFail', 'Medium', ['peerLdap', 'network']]].forEach(([kind, cat, sev, c]) => {
      const l2 = of(kind);
      if (l2.length) push(cat, sev, l2, 'sample.' + cat, { svc, host: h, why: why(l2) }, host, c);
    });
    const disk = of('diskLow');
    if (disk.length) push('svcDiskLow', disk.some(e => e.fields.svcCritical) ? 'High' : 'Medium', disk, 'sample.svcDiskLow', { svc, host: h, why: why(disk) }, host, ['disk', 'monitoring']);
    for (const [be, l3] of groupBy(of('backendFail'), e => e.fields.svcBackend || 'other')) {
      push('svcBackendFail', 'High', l3, 'sample.svcBackendFail', { svc, host: h, backend: be, why: why(l3) }, host, SVC_BACKEND_COMP[be] || ['backend', 'network']);
    }
    for (const [home, l4] of groupBy(s.filter(e => /^home(Zombie|Dead|Alive)$/.test(e.fields.svc)), e => e.fields.svcHome)) {
      const bad = l4.filter(e => e.fields.svc !== 'homeAlive');
      if (!bad.length) continue;
      const last = l4[l4.length - 1].fields.svc;
      push('svcUpstreamDown', bad.some(e => e.fields.svc === 'homeDead') ? 'High' : 'Medium', bad, 'sample.svcUpstreamDown',
        { svc, host: h, home, state: bad.some(e => e.fields.svc === 'homeDead') ? 'dead' : 'zombie', last: last === 'homeAlive' ? 'alive' : (last === 'homeDead' ? 'dead' : 'zombie') }, host, ['homeServer', 'network']);
    }
    const noHome = of('noHome');
    if (noHome.length) push('svcNoUpstream', 'High', noHome, 'sample.svcNoUpstream', { svc, host: h, why: why(noHome) || '-' }, host, ['homeServer', 'network']);
  }
  return issues;
}
// 服務健康卡片：每個服務＋主機的啟停統計與停機時間（停止或當機到下一次啟動），以及上游 RADIUS 的狀態變化
function buildServiceTimeline(events) {
  const rows = new Map(), homes = new Map();
  [...events].filter(e => e.fields && e.fields.svc).sort((a, b) => (effectiveTime(a) || 0) - (effectiveTime(b) || 0)).forEach(e => {
    const f = e.fields, k = f.svcName + '|' + (e.host || '');
    if (!rows.has(k)) rows.set(k, { svc: f.svcName, host: e.host || '', starts: 0, stops: 0, crashes: 0, errors: 0, downMs: 0, state: '', last: null, _down: null, _lastCrash: -Infinity });
    const r = rows.get(k), tm = effectiveTime(e) || 0;
    if (f.svc === 'start') { r.starts++; if (r._down !== null && tm >= r._down) r.downMs += tm - r._down; r._down = null; r.state = 'running'; }
    else if (f.svc === 'stop') { r.stops++; if (r._down === null) r._down = tm; r.state = 'stopped'; }
    else if (f.svc === 'crash') { if (tm - r._lastCrash > 60000) r.crashes++; r._lastCrash = tm; if (r._down === null) r._down = tm; r.state = 'crashed'; }
    else if (f.svc === 'stopping') { if (r.state !== 'crashed') r.state = 'stopping'; }
    else if (!/^home/.test(f.svc)) r.errors++;
    r.last = e.timestamp || r.last;
    if (/^home(Zombie|Dead|Alive)$/.test(f.svc)) {
      if (!homes.has(f.svcHome)) homes.set(f.svcHome, { home: f.svcHome, zombie: 0, dead: 0, alive: 0, state: '', last: null });
      const hs = homes.get(f.svcHome), st = f.svc.slice(4).toLowerCase();
      hs[st]++; hs.state = st; hs.last = e.timestamp || hs.last;
    }
  });
  return { services: [...rows.values()].map(({ _down, _lastCrash, ...r }) => r), homes: [...homes.values()] };
}
function detectRadiusIssues(events) {
  const issues = [];
  const rad = events.filter(e => e.fields && e.fields.radius);
  // Windows NPS 的 Accept／Reject 一併判斷同一終端多帳號（XN70），其餘 RADIUS 檢查只看 FreeRADIUS
  const nps = events.filter(e => e.fields && e.fields.mac && e.fields.user && ((e.format === 'nps' && (e.fields.npsPacket === 2 || e.fields.npsPacket === 3))
    || (e.format === 'clearpass' && (e.fields.cppmStatus === 'ACCEPT' || e.fields.cppmStatus === 'REJECT'))));  // ClearPass（XN134）
  if (!rad.length && !nps.length) return issues;
  const time = (a, b) => effectiveTime(a) - effectiveTime(b);
  const groupBy = (list, keyOf) => { const m = new Map(); list.forEach(e => { const k = keyOf(e); if (!k) return; if (!m.has(k)) m.set(k, []); m.get(k).push(e); }); return m; };
  const push = (cat, sev, list, key, p, rel) => {
    const sorted = [...list].sort(time);
    issues.push({ category: cat, severityNorm: sev, count: sorted.length, firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf(key, { n: sorted.length, ...p }), relatedHosts: rel, relatedEvents: sorted, confidence: 'confirmed' });
  };
  for (const [src, l] of groupBy(rad.filter(e => e.fields.radius === 'unknownClient'), e => e.fields.srcip)) push('radiusUnknownClient', 'Medium', l, 'sample.radiusUnknownClient', { src }, [src]);
  for (const [src, l] of groupBy(rad.filter(e => e.fields.radius === 'badSecret'), e => e.fields.srcip)) push('radiusBadSecret', 'Medium', l, 'sample.radiusBadSecret', { src, nas: l[0].fields.netHost || '-' }, [src]);
  for (const [src, l] of groupBy(rad.filter(e => e.fields.radius === 'blastradius'), e => e.fields.netHost || e.fields.srcip || e.host || '-')) push('radiusBlast', 'Medium', l, src === '-' ? 'sample.radiusBlastUnknown' : 'sample.radiusBlast', { src }, src === '-' ? [] : [src]);
  for (const [why, l] of groupBy(rad.filter(e => e.fields.radius === 'tlsfail'), e => e.fields.failReason)) {
    const users = [...new Set(l.map(e => e.fields.user).filter(Boolean))];
    push('radiusTlsFail', 'Low', l, 'sample.radiusTlsFail', { why, users: users.slice(0, 5).join(', ') || '-' }, users.slice(0, 5));
  }
  // MAC 以去分隔符的 12 碼小寫分組（NPS 用連字號、FreeRADIUS 依 NAS 而定），摘要顯示第一筆的原始寫法
  for (const [, l] of groupBy(rad.filter(e => (e.fields.radius === 'accept' || e.fields.radius === 'reject') && e.fields.mac && e.fields.user).concat(nps), e => macKey(e.fields.mac))) {
    const mac = l[0].fields.mac;
    const sorted = [...l].sort(time);
    let best = null, start = 0;
    for (let i = 0; i < sorted.length; i++) {
      while (effectiveTime(sorted[i]) - effectiveTime(sorted[start]) > 60 * 60 * 1000) start++;
      const win = sorted.slice(start, i + 1), users = new Set(win.map(e => e.fields.user.toLowerCase()));
      if (users.size >= RADIUS_MAC_USERS_MIN && (!best || users.size > best.users.size)) best = { win, users };
    }
    if (best) push('radiusMacMultiUser', 'Medium', best.win, 'sample.radiusMacMultiUser', { mac, users: [...best.users].slice(0, 5).join(', ') }, [mac, ...[...best.users].slice(0, 5)]);
  }
  return issues;
}
// AD 網域控制站的 LDAP 簽章與通道繫結事件（第三十輪 LD3，Directory Service 頻道，Provider Microsoft-Windows-ActiveDirectory_DomainService）：
//   2889：用戶端以未簽章的 SASL（繫結類型 0）或未加密的簡單繫結（1）連線，EventData 為未具名的 Data：
//     第 1 個為「位址:埠」、第 2 個為帳號、第 3 個為繫結類型（依 Microsoft PFE 的 Query-InsecureLDAPBinds.ps1）；
//     需開啟 16 LDAP Interface Events 診斷層級 2。依用戶端位址＋帳號彙整，簡單繫結（明碼密碼）為 High、未簽章為 Medium
//   2887（24 小時內未簽章／明碼繫結次數）、3039（未送通道繫結權杖）、3040（24 小時內未受保護的繫結次數）：欄位結構未查證，
//     只以事件本身列 Low，摘要用事件原文
const WIN_DS_CHANNEL = 'Directory Service';
function detectLdapSigning(events) {
  const issues = [];
  const ds = events.filter(e => e.format === 'winevent' && e.fields && e.fields.Channel === WIN_DS_CHANNEL);
  const binds = new Map();
  ds.filter(e => e.fields.EventID === '2889').forEach(e => {
    const f = e.fields;
    const k = `${f.IpAddress || ''}|${f.TargetUserName || ''}|${f.ldapBindType}`;
    if (!binds.has(k)) binds.set(k, []);
    binds.get(k).push(e);
  });
  for (const [k, l] of binds) {
    const [ip, who, type] = k.split('|');
    const sorted = [...l].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    issues.push({ category: 'ldapUnsignedBind', severityNorm: type === 'simple' ? 'High' : 'Medium', count: sorted.length,
      firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf(type === 'simple' ? 'sample.ldapSimpleBindDc' : 'sample.ldapUnsignedBindDc', { src: ip || '-', user: who || '-', n: sorted.length }),
      relatedHosts: [ip, who, ...new Set(sorted.map(e => e.host))].filter(Boolean), relatedEvents: sorted, confidence: 'confirmed' });
  }
  ds.filter(e => /^(?:2887|3039|3040)$/.test(e.fields.EventID)).forEach(e => {
    issues.push({ category: 'ldapUnsignedBind', severityNorm: 'Low', count: 1, firstSeen: e.timestamp || null, lastSeen: e.timestamp || null,
      sampleRaw: e.msg || e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e], confidence: 'confirmed', winEventId: e.fields.EventID });
  });
  return issues;
}
// DCSync（第三十輪 WN6，條件依 SigmaHQ win_security_ad_replication_non_machine_account 與 Elastic detection-rules
// credential_access_dcsync_replication_rights）：4662 的 Properties 含目錄複寫權限 GUID（DS-Replication-Get-Changes／-All／
// -In-Filtered-Set）、AccessMask 0x100（控制存取），且操作者不是電腦帳號（$ 結尾）、MSOL_ 同步帳號、NT AUTHORITY 或
// Window Manager。需要在網域根物件設定 SACL 並開啟「目錄服務存取」稽核才會產生
const DS_REPL_GUIDS = ['1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'];
function detectDcsync(events) {
  const by = new Map();
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields || e.fields.EventID !== '4662') return;
    const f = e.fields, props = String(f.Properties || '').toLowerCase(), who = String(f.SubjectUserName || '');
    if (!DS_REPL_GUIDS.some(g => props.includes(g))) return;
    if (f.AccessMask && !/^0x0*100$/i.test(f.AccessMask)) return;
    if (!who || who.endsWith('$') || /^MSOL_/i.test(who) || /^NT AUT/i.test(who) || f.SubjectDomainName === 'Window Manager') return;
    const k = `${f.SubjectDomainName || ''}\\${who}`;
    if (!by.has(k)) by.set(k, []);
    by.get(k).push(e);
  });
  const issues = [];
  for (const [who, l] of by) {
    const sorted = [...l].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    issues.push({ category: 'dcsync', severityNorm: 'Critical', count: sorted.length,
      firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf('sample.dcsync', { who, n: sorted.length, hosts: [...new Set(sorted.map(e => e.host).filter(Boolean))].join(', ') || '-' }),
      relatedHosts: [who.split('\\').pop(), ...new Set(sorted.map(e => e.host).filter(Boolean))], relatedEvents: sorted, confidence: 'heuristic' });
  }
  return issues;
}
// ── AD 多台主機交互（第三十一輪 HX1／HX2）──
// 網域名稱統一為第一段大寫（CORP.EXAMPLE 與 CORP 視為同一網域；NetBIOS 名稱與 DNS 第一段不同的網域會被當成兩個，已知限制）
const WIN_BUILTIN_DOMAINS = /^(?:NT AUTHORITY|NT SERVICE|BUILTIN|Window Manager|Font Driver Host|-)$/i;
function normWinDomain(d) {
  const v = String(d || '').trim();
  if (!v || v === '-') return '';
  return (v.includes('.') && !isValidIPv4(v) ? v.split('.')[0] : v).toUpperCase();
}
// Windows 事件的帳號鍵：依 WINEVENT_USER_KEYS 順序取第一個不是 - 的帳號，接上對應的網域（Subject*→SubjectDomainName、
// Target*→TargetDomainName；user@REALM 或 UPN 取 @ 後的第一段），沒有網域時只有帳號。其他格式維持原本的帳號欄位
// 電腦帳號（$ 結尾，如 4624 的 Subject 為被登入主機自己）先略過，沒有其他帳號時才用
function winUserKey(f) {
  for (const pass of [0, 1]) for (const k of WINEVENT_USER_KEYS) {
    let v = f[k];
    if (!v || v === '-' || (pass === 0 && /\$(?:@|$)/.test(String(v)))) continue;
    v = String(v);
    let d = '';
    const at = v.match(/^([^@\\]+)@([^@\s]+)$/);
    if (at) { v = at[1]; d = at[2]; }
    else if (v.includes('\\')) { [d, v] = v.split('\\'); }
    else d = f[k.startsWith('Subject') ? 'SubjectDomainName' : 'TargetDomainName'];
    const nd = normWinDomain(d);
    return nd && !WIN_BUILTIN_DOMAINS.test(nd) ? `${nd}\\${v}` : v;
  }
  return null;
}
function eventUserKey(e) {
  if (!e.fields) return null;
  if (e.format === 'winevent') { const u = winUserKey(e.fields); if (u) return u; }
  return pickField(e.fields, WINEVENT_USER_KEYS) || pickField(e.fields, JSON_USER_KEYS);
}
// 主機名稱統一為短名大寫（APP01.corp.example、APP01$ → APP01），位址維持原樣
function hostShort(n) {
  const v = String(n || '').trim().replace(/\$$/, '');
  if (!v || isValidIPv4(v) || v.includes(':')) return v;
  return v.split('.')[0].toUpperCase();
}
// 主機登入關係（HX1）：來源→目的的邊，依事件種類：
//   4624／4625：來源 IpAddress（WorkstationName 補來源名稱）→ 事件主機；方式為登入類型名稱
//   4648：事件主機以明確認證連往 TargetServerName（localhost 除外）
//   1149、LocalSessionManager 21／25：遠端桌面
//   5140／5145：來源 IpAddress 存取事件主機的共用資料夾
//   4769（網域控制站）：帳號從 IpAddress 要求 ServiceName（電腦帳號為該主機，否則為服務帳號）的票證，krbtgt 除外
// 電腦帳號（$ 結尾）自己的登入與票證、本機迴路來源不列入。位址可對到名稱時（WorkstationName、DHCP 對照）以名稱表示
function buildHostLogonGraph(events) {
  const ipName = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (e.format !== 'winevent' || !f) return;
    const ip = String(f.IpAddress || '').replace(/^::ffff:/i, '');
    const ws = f.WorkstationName && f.WorkstationName !== '-' ? f.WorkstationName : '';
    if (isValidIPv4(ip) && (ws || f.srcName)) ipName.set(ip, hostShort(ws || f.srcName));
  });
  const edges = new Map();
  const add = (e, src, dst, method, ok, user) => {
    src = String(src || '').replace(/^::ffff:/i, '');
    if (!src || !dst || src === '-' || /^(?:127\.0\.0\.1|::1|localhost)$/i.test(src)) return;
    const sName = isValidIPv4(src) ? (ipName.get(src) || (e.fields.srcName ? hostShort(e.fields.srcName) : '')) : hostShort(src);
    const s = sName || src, d = hostShort(dst);
    if (!d || s === d) return;
    const k = `${s}|${d}`;
    if (!edges.has(k)) edges.set(k, { src: s, srcIp: isValidIPv4(src) ? src : '', dst: d, users: new Map(), methods: new Set(), ok: 0, fail: 0, first: null, last: null, events: [] });
    const g = edges.get(k);
    if (user) g.users.set(user, (g.users.get(user) || 0) + 1);
    g.methods.add(method);
    if (ok) g.ok++; else g.fail++;
    if (!g.srcIp && isValidIPv4(src)) g.srcIp = src;
    const t = e.timestamp;
    if (t && (!g.first || t < g.first)) g.first = t;
    if (t && (!g.last || t > g.last)) g.last = t;
    g.events.push(e);
  };
  events.forEach(e => {
    const f = e.fields;
    if (e.format !== 'winevent' || !f) return;
    const user = winUserKey(f), id = f.EventID;
    const tgt = String(f.TargetUserName || '');
    if (id === '4624' || id === '4625') {
      if (tgt.endsWith('$')) return;
      add(e, f.IpAddress, e.host, f.logonTypeName || ('LogonType ' + (f.LogonType || '?')), id === '4624', user);
    } else if (id === '4648') {
      const ts = String(f.TargetServerName || '');
      if (!ts || /^(?:localhost|-)$/i.test(ts) || tgt.endsWith('$')) return;
      add(e, e.host, ts, 'ExplicitCredential', true, f.TargetUserName ? winUserKey({ TargetUserName: f.TargetUserName, TargetDomainName: f.TargetDomainName }) : user);
    } else if (f.rdp === 'auth' || f.rdp === 'logon' && id !== '4624' || f.rdp === 'reconnect') {
      add(e, f.IpAddress, e.host, 'RemoteDesktop', true, user);
    } else if (id === '5140' || id === '5145') {
      if (String(f.SubjectUserName || '').endsWith('$')) return;
      add(e, f.IpAddress, e.host, 'Share ' + String(f.ShareName || '').replace(/^\\\\\*\\/, ''), true, user);
    } else if (id === '4769') {
      const svc = String(f.ServiceName || '');
      if (!svc || /^krbtgt$/i.test(svc) || /\$@/.test(tgt) || tgt.endsWith('$')) return;
      add(e, f.IpAddress, svc, 'Kerberos', /^0x0+$/i.test(f.Status || '0x0'), user);
    }
  });
  return [...edges.values()].sort((a, b) => (b.ok + b.fail) - (a.ok + a.fail));
}
const HOST_GRAPH_COLS = ['src', 'srcIp', 'dst', 'users', 'methods', 'ok', 'fail', 'first', 'last'];
function hostGraphRows(edges) {
  const iso = t => (t ? t.toISOString() : '');
  return edges.map(g => ({ src: g.src, srcIp: g.srcIp, dst: g.dst, users: [...g.users.entries()].sort((a, b) => b[1] - a[1]).map(([u, n]) => `${u}(${n})`).join(' '), methods: [...g.methods].join(' '), ok: g.ok, fail: g.fail, first: iso(g.first), last: iso(g.last) }));
}
// Mermaid：節點代號依出現順序，標籤的引號與角括號改用實體（同交換器拓樸匯出）
function hostGraphMermaid(edges) {
  const ids = new Map();
  const id = n => { if (!ids.has(n)) ids.set(n, 'h' + ids.size); return ids.get(n); };
  const q = s => String(s).replace(/"/g, '#quot;').replace(/</g, '#lt;').replace(/>/g, '#gt;');
  const lines = ['graph LR'];
  edges.forEach(g => { id(g.src); id(g.dst); });
  ids.forEach((k, n) => lines.push(`  ${k}["${q(n)}"]`));
  edges.forEach(g => {
    const label = `${[...g.methods].join(', ')} ${g.ok}✓${g.fail ? ' ' + g.fail + '✗' : ''}`;
    lines.push(`  ${id(g.src)} -->|"${q(label)}"| ${id(g.dst)}`);
  });
  return lines.join('\n') + '\n';
}
// draw.io（未壓縮 mxfile）：節點排成網格，失敗多於成功的邊以紅色表示
function hostGraphDrawio(edges, title) {
  const x = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const nodes = [];
  edges.forEach(g => { [g.src, g.dst].forEach(n => { if (!nodes.includes(n)) nodes.push(n); }); });
  const cols = Math.max(1, Math.ceil(Math.sqrt(nodes.length)));
  const cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>'];
  nodes.forEach((n, i) => cells.push(`<mxCell id="n${i}" value="${x(n)}" style="rounded=1;whiteSpace=wrap;html=1;" vertex="1" parent="1"><mxGeometry x="${40 + (i % cols) * 220}" y="${40 + Math.floor(i / cols) * 140}" width="140" height="44" as="geometry"/></mxCell>`));
  edges.forEach((g, i) => {
    const label = `${[...g.methods].join(', ')} ${g.ok}/${g.fail}`;
    const color = g.fail > g.ok ? 'strokeColor=#d6312b;' : '';
    cells.push(`<mxCell id="e${i}" value="${x(label)}" style="endArrow=classic;html=1;${color}" edge="1" parent="1" source="n${nodes.indexOf(g.src)}" target="n${nodes.indexOf(g.dst)}"><mxGeometry relative="1" as="geometry"/></mxCell>`);
  });
  return `<mxfile><diagram name="${x(title || 'Host logons')}"><mxGraphModel><root>${cells.join('')}</root></mxGraphModel></diagram></mxfile>\n`;
}
// 跨網域登入（HX2）：成功的 4624（電腦帳號、本機帳號與內建帳號除外）中，帳號網域與被登入主機所屬網域不同；
// 主機網域取自同一主機事件中其電腦帳號（主機短名$）的 SubjectDomainName。依「帳號網域→主機網域」彙整，Low
function detectCrossDomainLogons(events) {
  const hostDom = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (e.format !== 'winevent' || !f || !e.host) return;
    if (String(f.SubjectUserName || '').toUpperCase() === hostShort(e.host) + '$') { const d = normWinDomain(f.SubjectDomainName); if (d) hostDom.set(hostShort(e.host), d); }
  });
  const by = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (e.format !== 'winevent' || !f || f.EventID !== '4624' || String(f.TargetUserName || '').endsWith('$')) return;
    const hd = hostDom.get(hostShort(e.host)), ud = normWinDomain(f.TargetDomainName);
    if (!hd || !ud || ud === hd || WIN_BUILTIN_DOMAINS.test(ud) || ud === hostShort(e.host)) return;
    const k = `${ud}|${hd}`;
    if (!by.has(k)) by.set(k, []);
    by.get(k).push(e);
  });
  const issues = [];
  for (const [k, l] of by) {
    const [ud, hd] = k.split('|');
    const sorted = [...l].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    const users = [...new Set(sorted.map(e => `${ud}\\${e.fields.TargetUserName}`))];
    const hosts = [...new Set(sorted.map(e => hostShort(e.host)))];
    issues.push({ category: 'crossDomainLogon', severityNorm: 'Low', count: sorted.length,
      firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf('sample.crossDomainLogon', { from: ud, to: hd, n: sorted.length, users: users.slice(0, 5).join(', '), hosts: hosts.slice(0, 5).join(', ') }),
      relatedHosts: [...users.slice(0, 5), ...hosts.slice(0, 5)], relatedEvents: sorted, confidence: 'confirmed' });
  }
  return issues;
}
function buildIssueList(events, intelIndexes, opts) {
  const o = opts || {};
  const analyzed = analyzeEvents(events);
  const intel = matchThreatIntel(analyzed, intelIndexes || [], o.safeIndexes || []);
  const hashIntel = matchHashIntel(analyzed, o.hashIndexes || []);
  const freq = detectFrequencyIssues(analyzed, { windowMs: o.windowMs, threshold: o.freqThreshold });
  const scanCef = detectScanHeuristicCEF(analyzed, { threshold: o.scanThreshold });
  const scanSys = detectScanHeuristicSyslog(analyzed, { threshold: o.scanThreshold });
  const scanWeb = detectWebScan(analyzed);
  const exploitWeb = detectExploitAttempts(analyzed);
  const dnsAnom = detectDnsAnomalies(analyzed);
  const nacFail = detectNacAuthFail(analyzed);
  const sshBrute = detectSshBruteSuccess(analyzed);
  const adminLogins = detectAdminLogins(analyzed);
  const winFail = detectWinFailReasons(analyzed);
  const ldapIss = detectLdapIssues(analyzed);
  const spray = detectPasswordSpray(analyzed);
  const dspray = detectDistributedSpray(analyzed, spray.map(is => is.relatedHosts[0]));
  const mfaFatigue = detectMfaFatigue(analyzed);
  const npsRej = detectNpsRejects(analyzed).concat(detectClearPassRejects(analyzed));
  const nsSess = detectNsSessionMultiIp(analyzed);
  const qnapIss = detectQnap(analyzed);
  const veeamIss = detectVeeam(analyzed);
  const vaultIss = detectVault(analyzed);
  const mtTamper = detectMikroTikTamper(analyzed);
  const riskyPorts = detectRiskyPortAccess(analyzed);
  const fortiMgmtIss = detectFortiMgmt(analyzed);
  const appsmith = detectAppsmithReset(analyzed);
  const appsmithIntr = detectAppsmithIntrusion(analyzed);
  const credTheft = detectCredTheft(analyzed);
  const gitlabIss = detectGitlab(analyzed);
  const awsAcct = detectAwsAccount(analyzed);
  const dbAuth = detectDbAuth(analyzed);
  const webshell = detectWebshell(analyzed);
  const esxi = detectEsxi(analyzed);
  const promptInj = detectPromptInjection(analyzed);
  const rdpIss = detectRdpAndCleartext(analyzed);
  const adIss = detectAdChanges(analyzed);
  const radIss = detectRadiusIssues(analyzed);
  const svcIss = detectServiceHealth(analyzed);
  const ldapSign = detectLdapSigning(analyzed);
  const dcsync = detectDcsync(analyzed);
  const crossDom = detectCrossDomainLogons(analyzed);
  const idsAlerts = detectIdsAlerts(analyzed);
  const netOps = detectNetOpsIssues(analyzed);
  const netAdmin = detectNetAdminChange(analyzed);
  const volume = detectVolumeAnomalies(analyzed, { thresholdBytes: o.volumeThreshold });
  const geo = detectGeoRiskEvents(analyzed, o.riskCountries || []);
  const geoIP = detectGeoIPLookup(analyzed, o.geoIndexes || [], o.riskCountries || []);
  const beaconing = detectBeaconing(analyzed);
  const lateral = detectLateralMovement(analyzed, { lateralExclude: o.lateralExclude, lateralTypes: o.lateralTypes });
  const privEsc = detectPrivEsc(analyzed);
  const geoVelocity = detectGeoVelocity(analyzed, o.geoIndexes || []);
  const asnRisk = detectAsnRisk(analyzed, o.asnIndexes || [], o.riskAsns || []);
  const vpnHosting = detectVpnFromHosting(analyzed, o.asnIndexes || [], o.hostingAsns || []);
  const vpnAnon = detectVpnFromAnonVpn(analyzed, o.anonVpn || []);
  const rmmIss = detectRmmTools(analyzed, o.rmm || [], o.rmmAllow || []);
  const acctAudit = detectAccountAuditEvents(analyzed);
  const passTheHash = detectPassTheHash(analyzed);
  const kerberoasting = detectKerberoasting(analyzed);
  const asrepRoasting = detectAsrepRoasting(analyzed);
  const asrepRoastingRisk = detectAsrepRoastingRisk(analyzed);
  const lsassAccess = detectLsassAccess(analyzed);
  const sysmonRegPersist = detectSysmonRegistryPersistence(analyzed);
  const adminShare = detectAdminShareAccess(analyzed);
  const procCreate = detectProcessCreation(analyzed, { enable4688: o.enable4688, procWatchlist: o.procWatchlist });
  const asnVelocity = detectAsnVelocity(analyzed, o.asnIndexes || []);
  const sysmonProcCreate = detectSysmonProcessCreate(analyzed, { enableSysmonProc: o.enableSysmonProc, sysmonProcWatchlist: o.sysmonProcWatchlist });
  const sysmonRemoteThread = detectSysmonRemoteThread(analyzed, { enableSysmonThread: o.enableSysmonThread, sysmonThreadWatchlist: o.sysmonThreadWatchlist });
  const psScriptBlock = detectPowerShellScriptBlock(analyzed, { enablePsScriptBlock: o.enablePsScriptBlock, psScriptBlockWatchlist: o.psScriptBlockWatchlist });
  const sysmonImageLoad = detectSysmonImageLoad(analyzed, { enableSysmonImageLoad: o.enableSysmonImageLoad, sysmonImageLoadWatchlist: o.sysmonImageLoadWatchlist });
  const psModuleLog = detectPowerShellModuleLogging(analyzed, { enablePsModuleLog: o.enablePsModuleLog, psModuleLogWatchlist: o.psModuleLogWatchlist });
  const timeGap = detectTimeGaps(analyzed, { gapThresholdMs: o.gapThresholdMs });
  const custom = detectCustomRules(analyzed, o.customRules);
  const all = [...vpnHosting, ...vpnAnon, ...rmmIss, ...dspray, ...mfaFatigue, ...npsRej, ...nsSess, ...qnapIss, ...veeamIss, ...vaultIss, ...mtTamper, ...riskyPorts, ...fortiMgmtIss, ...appsmith, ...appsmithIntr, ...credTheft, ...gitlabIss, ...awsAcct, ...dbAuth, ...webshell, ...esxi, ...promptInj, ...intel, ...hashIntel, ...freq, ...scanCef, ...scanSys, ...scanWeb, ...exploitWeb, ...dnsAnom, ...nacFail, ...sshBrute, ...adminLogins, ...winFail, ...ldapIss, ...spray, ...rdpIss, ...adIss, ...radIss, ...svcIss, ...ldapSign, ...dcsync, ...crossDom, ...idsAlerts, ...netOps, ...netAdmin, ...volume, ...geo, ...geoIP, ...beaconing, ...lateral, ...privEsc, ...geoVelocity, ...asnRisk, ...acctAudit, ...passTheHash, ...kerberoasting, ...asrepRoasting, ...asrepRoastingRisk, ...lsassAccess, ...sysmonRegPersist, ...adminShare, ...procCreate, ...asnVelocity, ...sysmonProcCreate, ...sysmonRemoteThread, ...psScriptBlock, ...sysmonImageLoad, ...psModuleLog, ...timeGap, ...custom];
  all.push(...detectOffHours(all, analyzed, o.offHours));
  all.push(...detectUnusualHours(analyzed, o.actorHourBaseline));
  all.push(...detectNewSources(analyzed, o.actorSourceBaseline, o));
  all.sort((a, b) => SEV_RANK[a.severityNorm] - SEV_RANK[b.severityNorm] || b.count - a.count);
  annotateEventsWithIssues(analyzed, all);
  return all;
}

// 健檢分數卡 A-F（2026-09-15 新增）：比照 switch_analyzer 的 computeSwitchHealth()／
// firewall_analyzer 的 computeFirewallHealth() 同一套「score=100 起算、逐項扣分、
// clamp 0-100、A≥90/B≥75/C≥60/D≥40/else F」慣例，但改吃 log_analyzer 已有的 ISSUES
// （buildIssueList() 產物，本來就有 5 級 severityNorm）而非重新呼叫多個 detect 函式。
// 每筆 issue 的扣分額度上限 5 次（Math.min(issue.count,5)），避免單一高頻類別（如
// freq:authFail 短時間大量觸發）把分數直接歸零、蓋過其他類別的訊號
const HEALTH_WEIGHT = { Critical: 10, High: 7, Medium: 4, Low: 2, Info: 1 };
function computeLogHealth(issues) {
  let score = 100;
  const out = [];
  (issues || []).forEach(is => {
    const w = HEALTH_WEIGHT[is.severityNorm] || HEALTH_WEIGHT.Info;
    score -= Math.min(is.count, 5) * w;
    out.push({ sev: is.severityNorm, label: tr(CAT_KEY_MAP[is.category.startsWith('freq:') ? is.category.slice(5) : is.category] || 'cat.other'), count: is.count });
  });
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  const gradeColor = grade === 'A' ? 'var(--green)' : grade === 'B' ? 'var(--teal)' : grade === 'C' ? 'var(--yellow)' : grade === 'D' ? 'var(--orange)' : 'var(--red)';
  return { score, grade, gradeColor, issues: out };
}

// MITRE ATT&CK Navigator layer.json 匯出（2026-09-15 新增）：schema 已用 WebFetch 查證官方
// mitre-attack/attack-navigator repo 的 layers/spec/v4.5/layerformat.md——頂層必要欄位
// name/domain（domain enum 固定用 'enterprise-attack'）；versions 物件必要子欄位 navigator
// （≥"4.9.0"）/layer（固定字串 "4.5"）；techniques[] 僅 techniqueID 必要，score/comment 等
// 皆選填。遍歷 ISSUES，比照 renderIssues()/exportLogReport()/buildCSVRows() 三處都在用的
// baseCat（去除 freq: 前綴）查表邏輯，查無 MITRE_MAP 對應則跳過（沿用「只標註已建立對應
// 的分類」既有原則），依 techniqueID 分組加總 score
function buildMitreLayer(issues) {
  const byTech = new Map();
  (issues || []).forEach(is => {
    const baseCat = is.category.startsWith('freq:') ? is.category.slice(5) : is.category;
    const tid = (is.mitre || MITRE_MAP[baseCat]);
    if (!tid) return;
    if (!byTech.has(tid)) byTech.set(tid, { score: 0, comments: [] });
    const cur = byTech.get(tid);
    cur.score += is.count;
    cur.comments.push(`${tr(CAT_KEY_MAP[baseCat] || 'cat.other')}: ${is.count}`);
  });
  const techniques = Array.from(byTech, ([techniqueID, v]) => ({ techniqueID, score: v.score, comment: v.comments.join('; ') }));
  const maxScore = techniques.length ? arrMax(techniques.map(t => t.score)) : 1;
  return {
    name: `log_analyzer — ${new Date().toISOString()}`,
    versions: { attack: '15', navigator: '4.9.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: tr('mitre.disclaimer'),
    techniques,
    gradient: { colors: ['#ffffff', '#ff6666'], minValue: 0, maxValue: Math.max(1, maxScore) },
  };
}

// 基準線比對模式（2026-09-15 新增）：通用鍵值比對 diff 函式，獨立實作一份（不跨檔案 import
// firewall_analyzer 的同名函式，沿用本專案「各工具各自維護一份純函式」慣例）。回傳
// {added, removed, changed}，changed 項目帶 {key, old, new, diffFields}
function diffArrayByKey(oldArr, newArr, keyFn, compareFields) {
  const oldMap = new Map((oldArr || []).map(o => [keyFn(o), o]));
  const newMap = new Map((newArr || []).map(o => [keyFn(o), o]));
  const added = [], removed = [], changed = [];
  newMap.forEach((n, k) => {
    if (!oldMap.has(k)) { added.push(n); return; }
    const o = oldMap.get(k);
    const diffFields = (compareFields || []).filter(f => o[f] !== n[f]);
    if (diffFields.length) changed.push({ key: k, old: o, new: n, diffFields });
  });
  oldMap.forEach((o, k) => { if (!newMap.has(k)) removed.push(o); });
  return { added, removed, changed };
}
// 基準線快照：比照 buildCSVRows() 已算好的扁平列形狀（category/severityNorm/count/confidence/
// firstSeen/lastSeen），只存精簡摘要，不含 relatedEvents/relatedHosts 等含 PII 的完整事件物件
function buildBaselineSnapshot(issues, events, tzOffsetMin, srcOpts) {
  const snap = {
    sourceTool: 'log_analyzer',
    generatedAt: new Date().toISOString(),
    issues: (issues || []).map(is => ({
      category: is.category, severityNorm: is.severityNorm, count: is.count, confidence: is.confidence,
      intelSource: is.category === 'knownIOC' ? (getIssueIntelSources(is)[0] || null)
        : is.category === 'knownHashIOC' ? (is.intelSource || null)
        : null,
      firstSeen: is.firstSeen || null, lastSeen: is.lastSeen || null,
    })),
  };
  // 帳號常用時段（第二十五輪 LD）：只存帳號與 24 小時筆數
  if (events && events.length) {
    snap.actorHours = buildActorHourBaseline(events, tzOffsetMin);
    snap.actorSources = buildActorSourceBaseline(events, srcOpts);
  }
  return snap;
}
// diff key：knownIOC 額外併入 intelSource，避免不同情資清單來源被誤判成同一筆。
// 呼叫端（renderBaselineDiff()）兩側格式不同——舊基準線是 buildBaselineSnapshot() 已攤平
// 的 intelSource 欄位，新的一側是即時 ISSUES（intelSource 巢狀於 intelMeta.source，需靠
// getIssueIntelSources() 查表），故 is.intelSource 為 undefined 時 fallback 呼叫查表函式，
// 兩種格式皆可正確取得來源
function _baselineDiffKey(is) {
  if (is.category === 'knownIOC') {
    const src = is.intelSource != null ? is.intelSource : (getIssueIntelSources(is)[0] || '');
    return `knownIOC/${src}`;
  }
  // knownHashIOC（2026-09-21 修復）：不像 knownIOC 有「合併多來源 NDJSON」的 intelMeta.source
  // 概念，雜湊清單本身就是使用者上傳的具名清單，直接用 intelSource（清單名稱）差異化即可——
  // 先前落到下方 return is.category fallback，不同雜湊清單的命中會被誤判成同一筆（分析師備註
  // 也共用這把鍵，可能串錯筆）
  if (is.category === 'knownHashIOC') return `knownHashIOC/${is.intelSource || ''}`;
  return is.category;
}
function diffBaseline(oldIssues, newIssues) {
  return diffArrayByKey(oldIssues, newIssues, _baselineDiffKey, ['severityNorm', 'count', 'confidence']);
}
// 前後期比較（第十二輪 MG）：依 _baselineDiffKey 對應，列出新增（只在本期）、消失（只在前期）、持續（兩期都有，
// 附筆數變化 delta）。排序：新增（本期筆數多者在前）→ 持續（變化幅度大者在前）→ 消失。
// summary.up／down 為持續項目中筆數增加／減少的數量
function comparePeriods(oldIssues, newIssues) {
  const pick = is => ({ severityNorm: is.severityNorm, count: Number(is.count) || 0 });
  // 同一鍵有多筆（如依嚴重度拆開的 ldapUnsignedBind）時筆數相加、嚴重度取最高，不讓後一筆蓋掉前一筆
  const rank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  const collect = (list, m) => (list || []).forEach(is => {
    const k = _baselineDiffKey(is), o = m.get(k);
    if (!o) { m.set(k, { category: is.category, severityNorm: is.severityNorm, count: Number(is.count) || 0 }); return; }
    o.count += Number(is.count) || 0;
    if ((rank[is.severityNorm] || 0) > (rank[o.severityNorm] || 0)) o.severityNorm = is.severityNorm;
  });
  const oldMap = new Map(), newMap = new Map();
  collect(oldIssues, oldMap);
  collect(newIssues, newMap);
  const added = [], persist = [], removed = [];
  newMap.forEach((n, k) => {
    const o = oldMap.get(k);
    if (o) persist.push({ key: k, category: n.category, status: 'persist', old: pick(o), new: pick(n), delta: (Number(n.count) || 0) - (Number(o.count) || 0) });
    else added.push({ key: k, category: n.category, status: 'added', old: null, new: pick(n), delta: Number(n.count) || 0 });
  });
  oldMap.forEach((o, k) => { if (!newMap.has(k)) removed.push({ key: k, category: o.category, status: 'removed', old: pick(o), new: null, delta: -(Number(o.count) || 0) }); });
  added.sort((a, b) => b.new.count - a.new.count);
  persist.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));
  removed.sort((a, b) => b.old.count - a.old.count);
  return { rows: added.concat(persist, removed), summary: { added: added.length, removed: removed.length, persist: persist.length,
    up: persist.filter(r => r.delta > 0).length, down: persist.filter(r => r.delta < 0).length } };
}
// 前期 log 的期間（事件時間最早／最晚；沒有時間的事件不計），回傳 {from,to}（毫秒）或 null
function eventsTimeRange(events) {
  let from = Infinity, to = -Infinity;
  (events || []).forEach(e => { const t = +e.timestamp; if (Number.isFinite(t) && t > 0) { if (t < from) from = t; if (t > to) to = t; } });
  return from === Infinity ? null : { from, to };
}

// 事件關聯分析（2026-08-12 新增）：串出「疑似攻擊鏈」——同一行為者 IP 先出現偵察跡象，
// 接著嘗試存取、甚至命中已知惡意情資，時間夠接近就視為同一起事件的不同階段，而非互不相關的
// 單筆問題。issue.relatedHosts 在不同偵測函式代表的意義不一致（detectFrequencyIssues 用回報
// 設備自己的主機名 e.host 分組；detectScanHeuristicCEF／detectVolumeAnomalies 用實際攻擊來源
// IP），不可直接當關聯鍵，改為對 relatedEvents 逐筆呼叫既有 getEventNetTuple() 重新推導。
function deriveIssueActor(issue) {
  const counts = new Map();
  (issue.relatedEvents || []).forEach(e => {
    const t = getEventNetTuple(e);
    const ip = (t.src && t.src !== '-') ? t.src : ((t.dst && t.dst !== '-') ? t.dst : null);
    if (ip) counts.set(ip, (counts.get(ip) || 0) + 1);
  });
  let best = null, bestN = -1;
  for (const [ip, n] of counts) { if (n > bestN) { best = ip; bestN = n; } }
  if (best) return best;
  return (issue.relatedHosts && issue.relatedHosts[0]) || null;
}

// deriveIssueActor() 的「帳號」版本（攻擊鏈關聯分組軸，2026-09 新增）：投票邏輯與既有函式
// 完全比照（同一 actor 在 relatedEvents 內出現次數最多者勝出），差別只在改用使用者帳號欄位
// （WINEVENT_USER_KEYS／JSON_USER_KEYS，與 detectGeoVelocity()/detectAsnVelocity() 的
// actorKey() 同款查找順序）而非 IP。查無帳號欄位時回傳 null（不像 deriveIssueActor() 會
// fallback 到 relatedHosts——host 語意是「回報設備」非「帳號」，混用會產生誤導的分組）；
// 刻意不改動 deriveIssueActor() 本身，避免既有以 IP 為預設分組軸的行為在真實資料下跟著變動。
function deriveIssueActorByUser(issue) {
  const counts = new Map();
  (issue.relatedEvents || []).forEach(e => {
    const u = eventUserKey(e);
    if (u) counts.set(u, (counts.get(u) || 0) + 1);
  });
  let best = null, bestN = -1;
  for (const [u, n] of counts) { if (n > bestN) { best = u; bestN = n; } }
  return best;
}

// 行為者檢視（2026-09-24 新增）：給定一個行為者字串（IP、帳號或主機名稱），彙整所有相關
// 事件、問題與攻擊鏈。事件比對：來源/目的 IP（getEventNetTuple()）、帳號欄位（與
// deriveIssueActorByUser() 同一組 WINEVENT_USER_KEYS／JSON_USER_KEYS）或 host 任一相等即算；
// 帳號比對不分大小寫（Windows 帳號本身不分大小寫），IP／host 維持精確比對。問題比對：
// deriveIssueActor()/deriveIssueActorByUser() 結果、relatedHosts 或任一 relatedEvents 命中；
// 攻擊鏈比對：chain.actor 相等（不分大小寫，攻擊鏈可能以帳號分組，與帳號比對一致）。
// 帳號鍵比對：不分大小寫；輸入不含網域時只比帳號部分（CORP\\alice 也符合 alice）
function userKeyMatches(u, actor) {
  if (!u || !actor) return false;
  const a = String(actor).toLowerCase(), v = String(u).toLowerCase();
  return v === a || (!a.includes('\\') && v.split('\\').pop() === a);
}
function eventMatchesActor(e, actor) {
  if (!actor) return false;
  const t = getEventNetTuple(e);
  if (t.src === actor || t.dst === actor || e.host === actor) return true;
  return userKeyMatches(eventUserKey(e), actor);
}
function buildActorProfile(actor, events, issues, chains) {
  const a = String(actor || '').trim();
  if (!a) return { actor: a, events: [], issues: [], chains: [], firstSeen: 0, lastSeen: 0 };
  const evs = (events || []).filter(e => eventMatchesActor(e, a));
  const iss = (issues || []).filter(is =>
    deriveIssueActor(is) === a ||
    userKeyMatches(deriveIssueActorByUser(is), a) ||
    (is.relatedHosts || []).includes(a) ||
    (is.relatedEvents || []).some(e => eventMatchesActor(e, a)));
  const chs = (chains || []).filter(c => userKeyMatches(c.actor, a));
  const times = evs.map(e => effectiveTime(e)).filter(t => t > 0);
  // 補強（2026-10-14，第二十四輪 JC）：24 小時分布（瀏覽器時區）、往來對象（對端位址出現次數前 10）、
  // 位址歸屬（annotateAddrOwners() 補的 srcName／srcUser／dstName／dstUser，只取行為者那一端）
  const hours = new Array(24).fill(0);
  const peers = new Map(), owners = new Set();
  evs.forEach(e => {
    if (e.timestamp) hours[e.timestamp.getHours()]++;
    const t = getEventNetTuple(e), f = e.fields || {};
    const side = t.src === a ? 'src' : (t.dst === a ? 'dst' : '');
    const peer = side === 'src' ? t.dst : (side === 'dst' ? t.src : (t.src !== '-' ? t.src : t.dst));
    if (peer && peer !== '-' && peer !== a) peers.set(peer, (peers.get(peer) || 0) + 1);
    if (side) [f[side + 'Name'], f[side + 'User']].forEach(v => { if (v) owners.add(String(v)); });
  });
  return { actor: a, events: evs, issues: iss, chains: chs,
    firstSeen: times.length ? arrMin(times) : 0, lastSeen: times.length ? arrMax(times) : 0,
    hours, peers: [...peers].sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1)).slice(0, 10).map(([peer, count]) => ({ peer, count })),
    owners: [...owners] };
}
// 行為者候選清單：攻擊鏈 actor＋每筆問題推導出的 IP／帳號，去重後依出現順序回傳（供輸入框提示）
function listKnownActors(issues, chains) {
  const set = new Set();
  (chains || []).forEach(c => { if (c.actor) set.add(c.actor); });
  (issues || []).forEach(is => {
    const ip = deriveIssueActor(is); if (ip) set.add(ip);
    const u = deriveIssueActorByUser(is); if (u) set.add(u);
  });
  return [...set];
}

// 篩選條件預設集（2026-09-24 新增）：preset = {name, resultsSearch, issuesSearch, issuesSource,
// issuesStatus（2026-09-29 新增）, suppressed:[]}。upsertFilterPreset() 同名覆蓋（保留原位置），新名稱加到最前面，總數上限 20；
// 名稱去首尾空白後為空則不變更。純函式，回傳新陣列不修改輸入
const FILTER_PRESET_MAX = 20;
function upsertFilterPreset(list, preset) {
  const name = String((preset && preset.name) || '').trim();
  const arr = Array.isArray(list) ? list.slice() : [];
  if (!name) return arr;
  const p = { name, resultsSearch: preset.resultsSearch || '', issuesSearch: preset.issuesSearch || '',
    issuesSource: preset.issuesSource || '', issuesStatus: preset.issuesStatus || '',
    suppressed: Array.isArray(preset.suppressed) ? preset.suppressed.slice() : [] };
  const i = arr.findIndex(x => x && x.name === name);
  if (i >= 0) arr[i] = p; else arr.unshift(p);
  return arr.slice(0, FILTER_PRESET_MAX);
}

// firstSeen/lastSeen 可能為 null（possibleScan 系列偵測函式本來就沒填），退回從 relatedEvents
// 用既有 effectiveTime() 取最早/最晚
function issueTime(issue, which) {
  const key = which === 'first' ? 'firstSeen' : 'lastSeen';
  if (issue[key]) return +issue[key];
  const events = issue.relatedEvents || [];
  if (!events.length) return 0;
  const times = events.map(e => effectiveTime(e));
  return which === 'first' ? arrMin(times) : arrMax(times);
}

// 階段對照：possibleScan／freq:denyBlock→偵察；freq:authFail→嘗試存取；knownIOC→已知惡意
// 來源；volumeAnomaly→疑似後續行為。geoRisk／geoIPRisk／asnRisk 不納入（訊號性質是「風險」
// 非「攻擊階段」——命中已匯入的風險名單只代表該筆事件的來源/ASN 落在使用者自訂清單，不像
// 其餘類別本身就帶有明確的攻擊行為時序意義）
// 2026-08-29 擴大（使用者發想 5 項新功能第 5 項）：把 buildIssueList() 實際會產生的其餘
// issue 類別（非純標籤分類——specialPrivLogon/explicitCredLogon/groupEnum/sysmonNetConn/
// sysmonFileCreate/sysmonDnsQuery 這幾個只在 classifyByKeyword() 標記個別事件、從未經由任何
// detect*() 進到 buildIssueList() 的 issues 陣列，故不會、也不需要出現在此表）依語意分進四
// 階段：
//   access（嘗試存取/憑證濫用進行中）：kerberoasting、lateralMovement、adminShareAccess、
//     acctLockout（與 freq:authFail 同屬密碼猜測類訊號）、geoVelocity/asnVelocity（同一身分
//     短時間內出現在不合理的多個位置/ASN，訊號本質是「憑證正被使用中」而非事後結果）、
//     tokenPrivAdjust（2026-09 新增，Token 權限調整常見於憑證竊取工具存取 lsass.exe 前的
//     準備動作，語意上更接近「正在嘗試取得存取能力」而非事後確認的惡意活動）
//   malicious（確認的惡意/高影響活動）：privEsc、groupRemoved、pwReset、acctDeleted、
//     auditPolicyChanged、auditCleared、persistence、registryValueChange（2026-09 新增，
//     與既有 sysmonRegistryPersistence 同屬機碼變更訊號）、processCreate/sysmonProcessCreate
//     （皆為使用者自行輸入可疑關鍵字命中，非例行事件）、beaconing（C2 特徵）
//   postActivity（例行後果/容量類，非攻擊行為本身）：acctStatusChange、auditLogFull
const CHAIN_STAGE_MAP = {
  mtFwTamper: 'malicious', mtUserChange: 'malicious', mtPersistence: 'malicious', mtProxyEnable: 'malicious', mtServiceChange: 'malicious',
  riskyPortProbe: 'recon', riskyPortSweep: 'recon', riskyPortAllowed: 'access',
  possibleScan: 'recon', 'freq:denyBlock': 'recon', idsAlert: 'malicious', exploitAttempt: 'access', appsmithOriginReset: 'access', appsmithResetFlow: 'access', appsmithResetBurst: 'recon', appsmithExternalRisky: 'access', appsmithScriptedApi: 'malicious', credFileExposed: 'access', appCredentialAdded: 'postActivity', gitlabCiVarRead: 'malicious', webshellCmd: 'postActivity', webshellUpload: 'postActivity', webshellNewScript: 'postActivity', esxiRemoteAccess: 'access', esxiDefenseOff: 'postActivity', esxiAccountChange: 'postActivity', esxiVmImpact: 'postActivity', dbAdminRemote: 'access', dbExternalLogin: 'access', dbAuthFailBurst: 'access', gitlabMassClone: 'postActivity', gitlabTokenCreated: 'postActivity',
  'freq:authFail': 'access', knownIOC: 'malicious', knownHashIOC: 'malicious', volumeAnomaly: 'postActivity',
  passTheHash: 'access', kerberoasting: 'access', asrepRoasting: 'access', lsassAccess: 'access', lateralMovement: 'access', adminShareAccess: 'access', acctLockout: 'access', tokenPrivAdjust: 'access',
  geoVelocity: 'access', asnVelocity: 'access', vpnHostingLogin: 'access', vpnAnonLogin: 'access', rmmTool: 'malicious', netAdminAdd: 'malicious',
  privEsc: 'malicious', groupRemoved: 'malicious', pwReset: 'malicious', acctDeleted: 'malicious', asrepRoastingRisk: 'malicious',
  auditPolicyChanged: 'malicious', auditCleared: 'malicious', persistence: 'malicious', sysmonRegistryPersistence: 'malicious', registryValueChange: 'malicious',
  processCreate: 'malicious', sysmonProcessCreate: 'malicious', sysmonRemoteThread: 'malicious', powershellScriptBlock: 'malicious', sysmonImageLoad: 'malicious', powershellModuleLog: 'malicious', beaconing: 'malicious',
  dnsDga: 'malicious', dnsTunnel: 'malicious', dnsNxBurst: 'malicious', nacAuthFail: 'access', npsRejectBurst: 'access', cppmRejectBurst: 'access', nsSessionMultiIp: 'access', vpnSessionMultiIp: 'access', qnapSnapshotDelete: 'postActivity', qnapMassFileChange: 'postActivity', veeamMalware: 'malicious', veeamDefenseOff: 'postActivity', vaultAuditDisabled: 'postActivity', fmgUnregDevice: 'access', veeamDeleteAttempt: 'postActivity', sshBruteSuccess: 'access', adminLoginExternal: 'access', adminLoginFailExternal: 'access', ldapBruteForce: 'access', ldapEnum: 'recon', passwordSpray: 'access', distributedSpray: 'access', mfaFatigue: 'access', adSensitiveChange: 'malicious', sidHistory: 'malicious', dsrmPassword: 'malicious', dcsync: 'malicious', k8sExec: 'malicious', k8sSecretAccess: 'malicious', duoFraud: 'access',
  acctStatusChange: 'postActivity', auditLogFull: 'postActivity'
};
const CHAIN_STAGE_ORDER = ['recon', 'access', 'malicious', 'postActivity'];
// 自訂偵測規則的 category 是動態值（'custom:'+rule.id），永遠查不到 CHAIN_STAGE_MAP 這個
// 靜態表；改用此 helper 統一查表，查無靜態對應時 fallback 到 issue 自己的 chainStage 欄位
// （僅 detectCustomRules() 產生的 issue 有這個欄位，內建分類沒有，||undefined 不會誤觸發）
function _issueChainStage(is) { return CHAIN_STAGE_MAP[is.category] || is.chainStage || undefined; }

// 以行為者 IP 分組，同一行為者的 issue 依時間排序後用可調整時間窗做貪婪分段——窗內的歸同一條
// 鏈，超過窗就切下一條；至少涵蓋 2 種不同階段才算「鏈」（單一階段不成鏈，避免把互不相關的單一
// 問題硬湊成鏈）。opts.groupBy==='user' 時改用 deriveIssueActorByUser()（帳號軸，2026-09
// 新增），預設（未指定或非 'user'）維持既有 deriveIssueActor()（IP 軸）不變。
function detectCorrelationChains(issues, opts) {
  const windowMs = (opts && opts.chainWindowMs) || 30 * 60000;
  const deriveActor = (opts && opts.groupBy === 'user') ? deriveIssueActorByUser : deriveIssueActor;
  const eligible = issues.filter(is => _issueChainStage(is));
  const byActor = new Map();
  eligible.forEach(is => {
    const actor = deriveActor(is);
    if (!actor) return;
    if (!byActor.has(actor)) byActor.set(actor, []);
    byActor.get(actor).push(is);
  });
  const chains = [];
  for (const [actor, list] of byActor) {
    const sorted = [...list].sort((a, b) => issueTime(a, 'first') - issueTime(b, 'first'));
    let group = [sorted[0]];
    const flush = () => {
      const stages = new Set(group.map(is => _issueChainStage(is)));
      if (stages.size < 2) return;
      const stageEntries = group.map(is => ({ stage: _issueChainStage(is), issue: is, time: issueTime(is, 'first') }))
        .sort((a, b) => a.time - b.time);
      const times = group.flatMap(is => [issueTime(is, 'first'), issueTime(is, 'last')]);
      const first = arrMin(times), last = arrMax(times);
      const sevRank = arrMin(group.map(is => SEV_RANK[is.severityNorm]));
      const severityNorm = Object.keys(SEV_RANK).find(k => SEV_RANK[k] === sevRank);
      chains.push({ actor, stages: stageEntries, severityNorm, firstSeen: first, lastSeen: last, spanMs: last - first });
    };
    for (let i = 1; i < sorted.length; i++) {
      if (issueTime(sorted[i], 'first') - issueTime(group[group.length - 1], 'first') <= windowMs) group.push(sorted[i]);
      else { flush(); group = [sorted[i]]; }
    }
    flush();
  }
  chains.sort((a, b) => SEV_RANK[a.severityNorm] - SEV_RANK[b.severityNorm] || b.stages.length - a.stages.length);
  return chains;
}

