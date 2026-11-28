// config-anonymizer-core.js — 語言切換、送到其他工具、去識別化引擎（mappings 到 checkResidual）（RV17-B 從 config-anonymizer.html 拆出，內容未改）
let _lang = 'zhTW';
// 翻譯：共用 toolkit-common.js 的 tkTr()（彩蛋語言退回規則、leet／uwu／cat／bean 轉換）
function tr(key) { return tkTr(LANG, _lang, key); }
function tip(key, label) {
  var t = tr(key);
  if (!t || t === key) return label;
  return '<span data-tip="' + t.replace(/"/g,'&quot;') + '">' + label + '<sup style="font-size:8px;opacity:.45;margin-left:2px;cursor:help">ⓘ</sup></span>';
}
// 語言偏好跨工具共用（2026-09-29，PB）：共用 localStorage key 'cw_lang'（比照主題 'cw_theme'），
// 只記住三種正式語言；彩蛋語言需各工具各自解鎖，不跨工具帶入。未存過時依瀏覽器語言決定
// 無障礙（UE，2026-09-29 新增）：沒有可存取名稱的輸入欄位，自動關聯到緊鄰的標籤——前一個兄弟元素是
// 沒有 for 的 <label> 時補 for；是 <span> 時以 aria-labelledby 指向它（語言切換後名稱跟著更新）。
// 已有 label／aria／title／placeholder（瀏覽器本身會當名稱）者不動。函式在 toolkit-common.js
// <html lang> 對應（2026-09-29，PB）：螢幕閱讀器依此決定朗讀語言；中文系彩蛋語言視為 zh-TW
// 從其他工具交接過來時的提示列（XN56）：內容已帶入，告訴使用者下一步並可直接執行；切換語言時重繪
var _handoff = null;
function renderHandoffBar() {
  var bar = document.getElementById('handoff-bar');
  if (!bar) return;
  if (!_handoff) { bar.hidden = true; bar.textContent = ''; return; }
  bar.textContent = '';
  var msg = document.createElement('span');
  msg.textContent = tr('handoff.loaded').replace('{name}', _handoff.name || '-').replace('{lines}', _handoff.lines);
  var btn = document.createElement('button');
  btn.type = 'button'; btn.className = 'anon-btn'; btn.id = 'handoff-run';
  btn.textContent = tr('handoff.run');
  btn.onclick = function () { _handoff = null; renderHandoffBar(); runAnonymize(); };
  bar.append(msg, btn);
  bar.hidden = false;
}
function showHandoffBar(name, text) {
  _handoff = { name: name, lines: String(text || '').split(/\r\n|\r|\n/).length };
  renderHandoffBar();
  var tour = document.getElementById('tour'); if (tour) tour.hidden = true;
  var ab = document.getElementById('anon-btn'); if (ab) ab.classList.add('handoff-focus');
}
// 下載去識別化結果後、尚未匯出對照表（或加密還原包）時提醒保存（UX38）；對照表含原始資料，不與結果打包
function showMapRemind(batch) {
  const el = document.getElementById('map-remind');
  if (!el) return;
  el.textContent = '';
  const sp = document.createElement('span'); sp.textContent = '🔑 ' + tr('map.remind');
  const b = document.createElement('button'); b.className = 'btn btn-ghost btn-sm'; b.style.marginLeft = '8px';
  b.textContent = tr(batch ? 'batch.export_map' : 'map.remind_btn'); b.onclick = () => (batch ? exportBatchMapping() : exportMapping());
  el.dataset.batch = batch ? '1' : '';
  el.append(sp, b); el.hidden = false;
  placeMapRemind();
}
// 各 .view 為 absolute 填滿 #content，提醒放在 #content 會被蓋住（RV9）：顯示時移到目前頁面的最上方，切換頁面時跟著移
function placeMapRemind() {
  const el = document.getElementById('map-remind'), v = document.querySelector('#content > .view.active');
  if (el && v && !el.hidden && el.parentElement !== v) v.prepend(el);
}
function hideMapRemind() { const el = document.getElementById('map-remind'); if (el) { el.hidden = true; el.textContent = ''; } }
function markMappingSaved() { STATE.mappingExported = true; hideMapRemind(); }
function setLang(code) {
  _lang = code;
  saveLangPref(code);
  window.renderToolkitVersion&&renderToolkitVersion(code);
  renderHandoffBar();
  { const mr = document.getElementById('map-remind'); if (mr && !mr.hidden) showMapRemind(mr.dataset.batch === '1'); }
  document.documentElement.lang = htmlLangFor(code);
  document.querySelectorAll('[data-i18n]').forEach(function(el) {
    var k = el.dataset.i18n;
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') el.placeholder = tr(k);
    else el.textContent = tr(k);
  });
  document.querySelectorAll('[data-i18n-title]').forEach(function(el) { el.title = tr(el.dataset.i18nTitle); });
  document.querySelectorAll('[data-tip-key]').forEach(function(el) { var t = tr(el.dataset.tipKey); if (t && t !== el.dataset.tipKey) el.dataset.tip = t; });
  // optgroup labels
  var fwGrp = document.getElementById('optgrp-fw');
  var swGrp = document.getElementById('optgrp-sw');
  if (fwGrp) fwGrp.label = tr('upload.vendor_fw');
  if (swGrp) swGrp.label = tr('upload.vendor_sw');
  document.querySelectorAll('.lang-btn').forEach(function(b) { b.classList.toggle('active', b.dataset.lang === code); });
  _onLangChange();
  if (typeof renderDescWarn === 'function' && STATE.anonymized) renderDescWarn();
}
function _onLangChange() {
  // 若有已解析結果，重繪動態區域
  if (STATE && STATE.anonymized) {
    var changed = 0;
    var origLines = STATE.original.split('\n');
    var anonLines = STATE.anonymized.split('\n');
    for (var i = 0; i < origLines.length; i++) { if (origLines[i] !== anonLines[i]) changed++; }
    var totalLines = Math.max(origLines.length, anonLines.length);
    document.getElementById('orig-line-cnt').textContent = totalLines + ' ' + tr('unit.line');
    document.getElementById('anon-line-cnt').textContent = totalLines + ' ' + tr('unit.line');
    document.getElementById('changed-cnt').textContent = changed + ' ' + tr('unit.changed');
    renderStats(STATE.vendor, changed);
    if (STATE.lastStats) renderAnonSummary(STATE.lastStats);
    renderMappingTable();
    renderReportSection(false);
  } else {
    document.getElementById('orig-line-cnt').textContent = '0 ' + tr('unit.line');
    document.getElementById('anon-line-cnt').textContent = '0 ' + tr('unit.line');
    document.getElementById('changed-cnt').textContent = '0 ' + tr('unit.changed');
  }
  // placeholder 更新（textarea 動態刷新）
  var pa = document.getElementById('paste-input');
  if (pa) pa.placeholder = tr('upload.placeholder');
  var rp = document.getElementById('restore-pwd');
  if (rp) rp.placeholder = tr('restore.pwd_placeholder');
  var e1 = document.getElementById('enc-pwd1');
  if (e1) e1.placeholder = tr('modal.pwd1_placeholder');
  var e2 = document.getElementById('enc-pwd2');
  if (e2) e2.placeholder = tr('modal.pwd2_placeholder');
  // 含 HTML tag 的段落（innerHTML，{acmap}/{redacted} 為佔位符）
  var acmapCode = '<code style="color:var(--accent)">.acmap</code>';
  var redactedCode = '<code style="color:#fbbf24">REDACTED_*</code>';
  var rdp = document.getElementById('restore-desc-p');
  if (rdp) rdp.innerHTML = tr('restore.desc_text').replace('{acmap}', acmapCode);
  var rwv = document.getElementById('restore-warn-div');
  if (rwv) rwv.innerHTML = tr('restore.warn_text').replace('{redacted}', redactedCode);
  var med = document.getElementById('modal-encrypt-desc-p');
  if (med) med.innerHTML = tr('modal.encrypt_desc');
  renderCustomRules();
}

// ============================================================
// [1] STATE
// ============================================================
// mappings 快照：runAnonymize() 完成後把當次全域 mappings 複製一份存在這裡，
// exportMapping()/doExportEncrypted() 一律讀這份快照而非即時全域 mappings，避免使用者
// 切去「批次處理」跑完後，回到單檔案畫面點擊匯出時，實際匯出的是批次最後一個檔案的映射
// （批次流程與單檔案流程共用同一份全域 mappings 物件，批次跑完會把它覆蓋成最後一筆資料）
const STATE = { original:'', anonymized:'', filename:'', vendor:null, mappings:null, vendorCandidates:[], reportMeta:null, reportDiffViewed:false, reportHash:'', lastStats:null };
let _anonChainTarget = null; // {href} — set when opened from network_analyzer "anonymize & analyze"
// Phase 4 第 18 項：新增 switch-config-generator.html 為第三個轉送目標（原僅 fw/sw 兩家）。
// 提升到頂層供 _sendToAnalysisTool() 與下方接收 `_netAnalyzer_anonThenOpen` 的 IIFE 共用，
// 避免兩處各自宣告一份容易漂移
const TOOL_HREFS = ['firewall-analyzer-fixed.html', 'switch-config-parser.html', 'switch-config-generator.html'];
// 2026-09 資安審查修復：改寫入獨立 key `_netAnalyzer_anonResult`（原本沿用 `_netAnalyzer_pending`
// 會與 hub 直接轉送寫入的同一把 key 搶寫，接收端可能誤把 raw 內容當成已匿名化內容載入）；並在
// window.open() 被彈出視窗攔截（回傳 null）時立刻清掉剛寫入的 key，避免已匿名化內容無限期殘留。
// 2026-09 資安審查修復：localStorage.setItem() 超過瀏覽器容量上限會拋出 QuotaExceededError，
// 未接住會讓後面的 window.open() 完全不執行、按鈕看起來沒反應；彈出視窗被攔截時原本也是靜默清
// key、不提示使用者。比照 network-analyzer.html 的 _dispatchWithPending()/_dispatchWithAnon()
// 已修過的同款問題補上 try/catch 與提示。
// Phase 4 第 18 項：原本這顆按鈕只在使用者從 hub 的「去識別化後分析」流程進來時才會出現
// （_anonChainTarget 只會被那個流程設定），本工具本身完全無法主動選擇轉送目標。改為只要
// 匿名化完成就一律顯示，並新增 #send-to-tool-select 讓使用者自行選擇 3 個目標之一；
// _anonChainTarget 有值時（沿用 hub 既有流程）優先用它，維持既有行為不變
function _sendToAnalysisTool() {
  if (!STATE.anonymized) return;
  const sel = document.getElementById('send-to-tool-select');
  const href = _anonChainTarget ? _anonChainTarget.href : TOOL_HREFS[Number(sel ? sel.value : 0)] || TOOL_HREFS[0];
  let wrote = false;
  try {
    localStorage.setItem('_netAnalyzer_anonResult', JSON.stringify({
      name: STATE.filename || 'anonymized.txt', text: STATE.anonymized, ts: Date.now(), vendor: null
    }));
    wrote = true;
  } catch (e) { alert(tr('err.send_fail')); }
  const w = window.open(href, '_blank');
  if (wrote && !w) { localStorage.removeItem('_netAnalyzer_anonResult'); alert(tr('err.send_popup_blocked')); }
}
const mappings = { ip:new Map(), hostname:new Map(), user:new Map(), ssid:new Map(), alias:new Map(), vdom:new Map(), mac:new Map() };
// mappings 的 7 個可逆映射類別名稱曾在 4 處各自重複列出（buildMappingSnapshot()／
// runAnonymize() 的 STATE.mappings 快照／doExportEncrypted() 的 reverseMap.reverse／
// restoreConfig()），2026-09-18 一次回歸即源自其中一處漏同步更新，統一成單一權威清單避免
// 未來再度漂移
const MAPPING_CATEGORIES = ['ip', 'hostname', 'user', 'ssid', 'alias', 'vdom', 'mac'];
// 殘留偵測：可設定的公司網域尾綴（2026-09-14 新增），使用者可自行填入自家網域（如
// "@acme.com" 或 "acme.local"），checkResidual() 逐行掃描時額外比對是否含有此字串；
// 與既有 email 通用偵測互補——email 偵測抓「看起來像 email 的任何字串」，此設定則抓
// 「即使不成 email 格式、只要出現公司網域字樣」的情況（如純網域名稱出現在憑證 CN 欄位）
let COMPANY_DOMAIN_SUFFIX = '';
// 殘留偵測：自訂監看關鍵字清單（2026-09-23 新增，多筆版本）。與 COMPANY_DOMAIN_SUFFIX
// 同樣是「純偵測、不取代」機制，差異在於這裡支援多筆、換行分隔的關鍵字（如多個內部代號/
// 專案代稱），checkResidual() 逐行掃描時對每個關鍵字做純字面字串比對（不支援正則，避免
// 使用者輸入含特殊字元時誤傷或造成 ReDoS 風險）。**務必與 customRules（取代用自訂規則）
// 區隔**：customRules 是使用者主動要求「找到就取代」的正則規則，這裡是「找到就示警、
// 不做任何取代」的純監看清單，兩者語意不同，不可共用同一份儲存變數或 UI 區塊。
let CUSTOM_WATCH_KEYWORDS = [];
// checkResidual() 高熵字串偵測（Shannon entropy，2026-09-15 新增，預設關閉）：偵測「不含已知
// 機敏關鍵字，但字串本身亂度極高」的殘留（如未加任何前後綴的原始 API 金鑰/token，cloudKeyRe
// 固定前綴啟發式抓不到的情況）。預設關閉——一般設定檔本來就含大量看似隨機的識別碼（序號/UUID/
// 憑證指紋等），無差別開啟容易洗版，比照 COMPANY_DOMAIN_SUFFIX 既有慣例採「模組級旗標＋UI
// 開關」opt-in 設計。單一保守門檻值（非按字元集分別調參，簡化實作），標註為可調常數供未來依
// 實測調整
let ENTROPY_CHECK_ENABLED = false;
const ENTROPY_THRESHOLD = 4.0, ENTROPY_MIN_LEN = 16;
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
// checkResidual() 的 MAC 殘留判斷需要知道上次 anonymize() 是否啟用了 MAC OUI 隨機化
// （2026-09-14 新增）：固定模式輸出的第一 byte 恆為字面 '02'，可精確比對；隨機化模式的
// 第一 byte 只保證特定位元模式（非字面 '02'），若不分模式一律套用寬鬆的位元判斷，會讓
// 固定模式下「剛好符合該位元模式的真實 MAC」被誤判成「已匿名化」而漏掉真正的殘留
// （如 aa:bb:cc:dd:ee:ff 第一 byte 0xaa 恰好也符合該位元模式）
let LAST_MAC_RANDOM_OUI = false;
// 匯入既有對照表的種子（比照 log_analyzer 對應的 IMPORTED_SEED，各自維護一份、不跨檔引用）：
// 單檔模式的真正執行入口是 anonymize()（非 resetAll()——resetAll() 是「重置」按鈕，本身確實
// 不清 mappings，但每次按「開始去識別化」都會呼叫 anonymize()，該函式開頭本來就會清空
// mappings/ctrs/stats/bucketSeen，這點與 runBatch() 逐檔重置是同一類問題，故 anonymize() 與
// runBatch() 皆需在重置後呼叫 seedLiveMappingsFromImported(IMPORTED_SEED) 重新套用；否則使用者
// 匯入對照表後第一次按「開始去識別化」，剛匯入的假值就會被洗掉、改產生一組全新的假值，跨工具
// 一致性功能形同虛設（2026-09-02 審查發現的既有缺口，此前只修好了 runBatch() 那一條路徑）
let IMPORTED_SEED = null;
const ctrs = { n1:0, n2:0, n3:0, ip6:0, dev:0, usr:0, ssid:0, alias:0, vdom:0, mac:0 };
// 各類別已見過的不重複來源 IP 集合，供偵測 ctrs.n1/n2/n3 回捲碰撞用（每類別 RFC5737
// 輸出網段僅一個 /24，超過 254 個不同來源 IP 時計數器會回捲並與較早的位址碰撞；
// 不改變既有輸出格式，僅用於溢位警告，詳見 renderStats() 的 bucketSeen 溢位檢查）
const bucketSeen = { n1:new Set(), n2:new Set(), n3:new Set() };
const stats = { ip:0, hostname:0, user:0, password:0, key:0, community:0, ssid:0, comment:0, vdom:0, mac:0 };
// 已使用的匿名化輸出 IP 集合（防止二次映射，如 MikroTik 兩段式處理）
const anonOutputIPs = new Set();
// 原檔中出現過的 IPv4 字面值：逐一對應配發假位址時跳過這些值。原檔本身含 192.0.2／198.51.100／203.0.113
// 位址時，原本另一個位址可能被配到同一個假值（兩台主機變成同一個位址，還原時也分不開）
const srcIPv4 = new Set(), srcIPv6 = new Set();
// 原檔中已出現的假名稱（xx-device-N、user-N）：配發主機名稱／帳號假值時跳過，避免對已去識別化過的檔案再處理一次時，
// 新配發的假值與原檔既有的同名值撞在一起（比照 srcIPv4）
const srcFakeNames = new Set();
// 設備序號對照（原始序號 → SERIAL-X 加流水號）：同一序號在檔案內各處替換成同一個假值；序號不提供還原
const serialMap = new Map();
// 保留網段結構模式（2026-10-02，第十輪 ZN）的逐層對照：top＝原始 /16 → 假 /16，
// oct3＝「假 /16|原始第三段」→ 假第三段；used 記錄已配發的假值，確保不同來源不會撞在一起
const subnetMaps = { top: new Map(), topUsed: new Set(), oct3: new Map(), oct3Used: new Set() };

// ============================================================
// [2] VENDOR DETECTION
// ============================================================
// 應用程式環境變數檔（XN93，見 anonAppEnv()）：至少 3 行「大寫名稱=值」
const ENV_FILE_RE = /^(?:export\s+)?[A-Z][A-Z0-9_]*=[^\n]*\n(?:[ \t]*(?:#[^\n]*)?\n)*(?:export\s+)?[A-Z][A-Z0-9_]*=[^\n]*\n(?:[ \t]*(?:#[^\n]*)?\n)*(?:export\s+)?[A-Z][A-Z0-9_]*=/m;
const VENDOR_SIGS = {
  cisco_nxos:  { p:[/Cisco Nexus/i, /^feature\s+\w+/m, /^vdc\s+\S+\s+id\s+\d+/m, /^version\s+\d+\.\d+\(\d+\)/m, /^!Command:\s*show running-config/m], min:1 },
  fortiswitch: { p:[/^config system global/m, /^config switch physical-port/m], min:2 },
  fortigate:   { p:[/^#config-version=/m, /^config system global/m, /FortiGate-/i], min:1 },
  comware:     { p:[/^\s*sysname\s+\S/m, /HPE Comware|H3C Comware/i, /^\s*version\s+\d+[\d.]+,\s*Release/m], min:1 },
  // XML 匯出檔（running-config.xml）根標籤帶屬性 <config version="…" urldb=…>，後接 <devices>
  paloalto:    { p:[/^set deviceconfig system/m, /^set vsys vsys/m, /Palo Alto Networks/i, /<config\b[^>]*>[\s\S]{0,300}<devices>/, /<device-group>\s*<entry\b/], min:1 },
  // Junos 設定檔有兩種輸出風格：扁平 "set" 格式與階層式大括號格式（"system { host-name X; }"）；
  // 原本簽章只認 set 格式，對大括號格式真實匯出檔會誤判為 unknown（比照 firewall_analyzer
  // FW_VENDOR_SIGS.juniper 已修復的落差補上對應訊號，2026-07-21 查核發現此處從未同步修正）
  juniper:     { p:[/^set system host-name/m, /^set interfaces .* family inet/m, /Juniper Networks|JUNOS/i, /^system\s*\{/m, /^\s*host-name\s+\S+;/m], min:1 },
  checkpoint:  { p:[/^set hostname /m, /^set interface .* ipv4-address/m, /Check Point/i], min:2 },
  // min 由 1 提高為 2：單靠字面 "Sophos" 一個訊號太寬鬆，Cisco 等其他廠牌設定檔內若剛好有一行
  // 註解提到 Sophos（如 "! migrated from Sophos"）就會被誤判，導致真正廠牌的密碼/敏感規則完全
  // 不執行、明碼外洩；額外補上第 4 個 XML schema 訊號（Sophos XG 匯出檔特有標籤），確保真實
  // Sophos XG XML 匯出檔仍可命中 2 個訊號（<Sophos/> 文字 + XML schema 標籤）
  sophos:      { p:[/Sophos/i, /<Configuration[^>]*SophosFirewall/, /^set admin-settings/m, /<(?:IPHostList|FirewallRuleList|WebFilterPolicy|IPsecVPNList)>/], min:2 },
  pfsense:     { p:[/<pfsense>/i, /pfSense|OPNsense/i, /<version>[\d.]+<\/version>/], min:1 },
  sonicwall:   { p:[/<SonicWALLconfig/i, /SonicWall|SonicOS/i], min:1 },
  mikrotik:    { p:[/^\/ip\s+(?:firewall|address|route)/m, /^\/system\s+identity/m, /RouterOS/i], min:1 },
  arista:      { p:[/^! device:.* EOS/m, /Arista Networks/i, /^management api http-commands/m, /^!\s*Software image version:\s*EOS/m, /^!\s*device:\s*\S+.*\(Arista\s/m, /^!?\s*boot system flash[:\s]\s*\/?\S*\.swi\s*$/m], min:1 },
  extreme:     { p:[/^create vlan\s+/m, /^configure sys-name/m, /ExtremeXOS|ExtremeEOS/i], min:1 },
  alcatel:     { p:[/^(?:->\s*)?system name\s+/m, /^stack set slot\s+/m, /OmniSwitch/i], min:1 },
  brocade:     { p:[/^vlan\s+\d+\s+(?:name\s+\S+\s+)?by\s+port/m, /^stack unit\s+\d+/m, /FastIron|ICX/i], min:1 },
  // min 由 1 提高為 2：單靠字面 "Aruba" 一個訊號太寬鬆，理由同 sophos
  aruba_cx:    { p:[/^!Version ArubaOS-CX\b/m, /vlan trunk (?:allowed|native)/m, /^vsf\s*$/m, /Aruba/i], min:2 },
  // 第 4 條：帶引號 hostname 之後出現以埠號開頭的 untagged／tagged（無 `; J9xxxA` 檔頭時，與 switch_analyzer 同步，2026-10-01）
  procurve:    { p:[/^;\s*(?:HP\s|Aruba\s|J\d{4}[A-Z])/m, /^oobm$/m, /^trunk\s+[\dA-Za-z,\/\-]+\s+[Tt]rk\d+/m, /^hostname\s+"[^"\n]*"\s*$[\s\S]*?^\s+(?:un)?tagged\s+[A-Z]?\d/m], min:1 },
  // Dell OS9（FTOS）沿用同一處理：`! Dell Networking OS` 檔頭、ManagementEthernet／fortyGigE 介面、stack-unit
  dell_os10:   { p:[/^interface\s+ethernet\d+\/\d+\/\d+/m, /^vlt-domain\s+\d+/m, /Dell.*OS10/i, /^!\s*Dell Networking OS\b/m, /^interface\s+(?:ManagementEthernet|fortyGigE)\s+\d+\/\d+/m, /^stack-unit\s+\d+\b/m], min:1 },
  // ASA Version／NGFW Version banner、nameif、獨立一行 failover 皆為 ASA/FTD 專屬語法，
  // Cisco IOS 交換器不會出現；NGFW Version 讓沿用同一套 Lina CLI 語法的 FTD 也一併命中，
  // 比照 firewall_analyzer 的 CiscoFTDParser 委派 CiscoASAParser 慣例，不另開 ciscoftd 分支
  ciscoasa:    { p:[/^ASA Version\s+\S+/m, /^NGFW Version\s+\S+/m, /^nameif\s+\S+/m, /^failover\s*$/m], min:1 },
  // Cisco Business（CBS250／350、Catalyst 1200／1300、SG300／350，2026-10-02）：固定檔頭，與 switch_analyzer 的 isCiscoBusiness() 一致
  cisco_biz:   { p:[/^config-file-header\s*$/m, /^ssd-control-start\s*$/m, /^file SSD indicator\s+\S+/m], min:1 },
  fsos:        { p:[/^!?\s*Fiberstore Co\., Limited/m, /^!?\s*FSOS Software, /m, /by FS\.COM\b/m], min:1 },
  cisco_ios:   { p:[/^version \d+\.\d+\s*$/m, /^hostname /m, /Cisco IOS/i], min:2 },
  // 務必與 firewall_analyzer 的 FW_VENDOR_SIGS.zyxel 保持一致（2026-07-30 新增），避免兩邊
  // 簽章各自維護後逐漸失步（既有註解已警告過 juniper 曾發生過這個問題）
  zyxel:       { p:[/^secure-policy\s+(?:insert\s+)?\d+/m, /^address-object\s+\S+\s+\S+/m, /^service-object\s+\S+\s+(tcp|udp)/im, /ZyWALL|USG FLEX|Zyxel/i], min:2 },
  // 務必與 firewall_analyzer 的 FW_VENDOR_SIGS.edgerouter 保持一致（2026-08-01 新增）。
  // EdgeOS config.boot 頂層區塊名稱（system{}/interfaces{}/firewall{}）與 Junos 大括號格式
  // 重疊，簽章刻意避開這些通用區塊名稱，只採 EdgeOS 特有關鍵字，min:2 避免與 juniper 混淆
  // 務必與 firewall_analyzer 的 FW_VENDOR_SIGS.vyos 保持一致（2026-10-02 新增）：VyOS 與 EdgeOS 同源，
  // 只能靠 // vyos-config-version 檔尾或 1.4 起 firewall ipv4 {forward|input|output|name} 結構區分，排在 edgerouter 前
  // 雲端安全群組 JSON（AWS describe-security-groups／Azure NSG），務必與 firewall_analyzer 的 FW_VENDOR_SIGS.cloudsg 一致（2026-10-02）
  // H3C SecPath 防火牆（2026-10-05，KB）：務必與 firewall_analyzer 的 FW_VENDOR_SIGS.h3c 一致，排在 comware 前
  h3c_secpath: { p:[/^\s*security-policy\s+ipv?6?\s*$/m, /^\s*security-zone\s+name\s+\S+/m], min:2 },
  // Netgate TNSR（2026-10-06，ML）：務必與 firewall_analyzer 的 FW_VENDOR_SIGS.tnsr 一致
  tnsr:        { p:[/^nacm\s+(?:enable|disable|group\s)[\s\S]*^dataplane\s|^dataplane\s[\s\S]*^nacm\s+(?:enable|disable|group\s)/m, /^[ \t]+access-list\s+(?:input|output)\s+acl\s+\S+\s+sequence\s+\d+/m, /^vpf\s+(?:filter\s+ruleset|options)\b/m, /^[ \t]+next-hop\s+\d+\s+via\s/m], min:1 },
  // 無線控制器（2026-10-05，KD／KH／KI）：務必與 firewall_analyzer 的 FW_VENDOR_SIGS.wlc 一致，排在 comware／cisco_ios 前
  wlc:         { p:[/^(?:config\s+)?wlan\s+create\s+\d+\s+\S+/m, /^\s*wlan\s+service-template\s+\S+/m, /^\s*wlan\s+ssid-profile\s+\S+/m, /^wlan\s+\S+\s+\d{1,4}\s+\S+/m], min:1 },
  // Check Point Management API JSON（第十八輪 TL），與 firewall_analyzer detectFwVendor() 的判斷一致
  checkpoint_api: { p:[/"objects-dictionary"\s*:/, /"type"\s*:\s*"(?:access|nat)-(?:rule|section)"/], min:2 },
  cloudsg:     { p:[/"IpPermissions(?:Egress)?"\s*:\s*\[/, /"(?:default)?[sS]ecurityRules"\s*:\s*\[/, /"destCidr"\s*:/, /"applianceIp"\s*:/, /"publicPort"\s*:/, /"kind"\s*:\s*"compute#firewall"/, /"NetworkAclId"\s*:/, /"ruleCollections"\s*:\s*\[/, /"kind"\s*:\s*"compute#firewallPolicy"/, /"kind"\s*:\s*"NetworkPolicy"/, /^\s*kind:\s*NetworkPolicy\b/m, /"(?:ingress|egress)[-_]?[sS]ecurity[-_]?[rR]ules"\s*:\s*\[/, /"(?:source|destination)[-_]?[tT]ype"\s*:\s*"(?:CIDR_BLOCK|SERVICE_CIDR_BLOCK|NETWORK_SECURITY_GROUP)"/], min:1 },
  // 務必與 firewall_analyzer 的 FW_VENDOR_SIGS.netfilter 保持一致（2026-10-02 新增）
  // Cumulus Linux NVUE（YAML 的 `- set:` 段或 nv set 指令），務必與 switch_analyzer isCumulusNVUE() 一致（2026-10-02）
  // Allied Telesis AlliedWare Plus：與 switch_analyzer isAlliedWare() 一致（2026-10-02）
  awplus:      { p:[/^interface\s+port\d+\.\d+\.\d+/m, /AlliedWare Plus/i, /^vlan database\s*$\n(?:[ \t]+.*\n)*?[ \t]+vlan\s+[\d,-]+\s+state\s+enable/m], min:1 },
  // Extreme VOSS／Fabric Engine（2026-10-05，KG）：與 switch_analyzer isVOSS() 一致
  // Broadcom EFOS（2026-10-06，MM）：與 switch_analyzer isEFOS() 一致，排在 edgeswitch／netgear 前
  netgearsmart:{ p:[/^SYSTEM CONFIG FILE ::= BEGIN\s*$/m, /^!\s*System Description:\s*NETGEAR\b/mi], min:2 },
  // NVIDIA Onyx（XN156，與 switch_analyzer isOnyx() 相同）
  onyx:{ p:[/^##\s*Product release:\s*\S/m, /^##\s*Running database\b/m, /^\s*(?:no\s+)?cli\s+default\s+prefix-modes\s+enable\s*$/m], min:2 },
  // Zyxel GS／XGS（XN155，與 switch_analyzer isZyxelSw() 相同）：檔頭兩行，或 VLAN 的 fixed／forbidden／untagged
  zyxelsw:{ p:[/^;\s*Product Name\s*=\s*\S/m, /^;\s*Firmware Version\s*=\s*\S/m, /^\s*fixed\s+[\d,\-]+\s*$/m, /^\s*forbidden\s+\S*/m], min:2 },
  // D-Link DGS（XN154，與 switch_analyzer isDLink() 相同）：檔頭版權行（單一訊號即判定）
  dlink:{ p:[/^#\s*Copyright\(C\)\s*\d{4}\s+D-Link Corporation/mi], min:1 },
  // TP-Link JetStream（XN153，與 switch_analyzer isTpLink() 相同）：介面命名＋general 埠／pvid／user name 其一
  tplink:{ p:[/^interface\s+(?:fastEthernet|gigabitEthernet|two-gigabitEthernet|ten-gigabitEthernet)\s+\d+\/\d+\/\d+\s*$/m, /^\s*switchport\s+general\s+allowed\s+vlan\s+\S+\s+(?:tagged|untagged)\s*$|^user\s+name\s+\S+\s+(?:privilege\s+(?:admin|operator|power_user|user)\s+)?(?:password|secret)\b|^\s*switchport\s+pvid\s+\d+\s*$/m], min:2 },
  efos:        { p:[/^!System Description\s+"EFOS\b/m, /^!System Software Version\s+"[\s\S]*^serviceport\s+(?:ip|protocol)\b[\s\S]*^port-channel\s+name\s+\d+\/\d+\s/m], min:1 },
  voss:        { p:[/^#\s*box type\s*:\s*(?:VSP|XA|\d{4})/m, /^vlan\s+create\s+[\d,\-]+(?:\s+name\s+"[^"]*")?\s+type\s+port-mstprstp\s+\d+/m], min:1 },
  cumulus:     { p:[/^\s*-\s+set:\s*$\n(?:.*\n)*?\s+(?:interface|bridge|system|router|vrf):\s*$/m, /nvue-api-version/, /^nv set (?:interface|bridge|system|router|vrf|service) /m], min:1 },
  netfilter:   { p:[/^# Generated by ip6?tables-save/m, /^:(?:INPUT|FORWARD|OUTPUT|PREROUTING|POSTROUTING)\s+(?:ACCEPT|DROP|-)\s+\[\d+:\d+\]/m, /^\s*type\s+(?:filter|nat)\s+hook\s+(?:input|forward|output|prerouting|postrouting)\b/m], min:1 },
  vyos:        { p:[/vyos-config-version/, /^#\s*Version:\s+VyOS\b/m, /^set firewall global-options /m, /^\/\/ Release version:\s*\d/m, /^set firewall ipv[46] (?:forward|input|output|name) /m, /^\s+ipv[46]\s*\{\s*\n\s+(?:forward|input|output|name)\b/m], min:1 },
  edgerouter:  { p:[/ethernet\s+eth\d+\s*\{/m, /default-action\s+(drop|accept)/m, /outbound-interface\s+\S+/m, /address-group\s+\S+\s*\{/m, /UBNT|EdgeRouter|EdgeOS|EdgeMax/i], min:2 },
  // 務必與 firewall_analyzer 的 FW_VENDOR_SIGS.openwrt 保持一致（2026-08-01 新增）。UCI
  // stanza 格式與其餘 22 家皆不同語法家族，本身辨識度已高，仍用 min:2 避免巧合誤判
  openwrt:     { p:[/^config\s+interface(\s|$)/m, /^\s*option\s+proto\s/m, /^config\s+(zone|rule|redirect|forwarding)(\s|$)/m, /^package\s+(network|firewall|dhcp)/m], min:2 },
  // 務必與 switch_analyzer 的 detectVendor() 保持一致（2026-09-09 新增）。planet 務必排在
  // ruijie 之前——ruijie 簽章含通用的 switchport mode hybrid 弱訊號，若排在 planet 之後，
  // 含 hybrid 介面的 Planet 設定檔會被 ruijie 判斷式提前攔截誤判（switch_analyzer 自己已
  // 踩過這個坑並記載在 detectVendor() 註解中）
  planet:      { p:[/^hostname\s+\S+/m, /^interface\s+ethernet\s+\d+\/\d+\/\d+/m, /^\s*switchport mode\s+(trunk|access|hybrid)/m], min:3 },
  ruijie:      { p:[/^interface\s+AggregatePort\s*\d+/im, /switchport mode hybrid/m, /^switch virtual domain\s+\d+/m, /\bRGOS\b/i, /^rldp\b/im, /^nfpp\s*$/im], min:1 },
  // netgear/edgeswitch 共用 Broadcom ICOS 表頭 !Current Configuration:，靠品牌字串/
  // edgeswitch 原生 vlan participation 語法互相排除，min:2 避免任一方單靠共用表頭誤判
  netgear:     { p:[/^!Current Configuration:/m, /(NETGEAR|M4300)/i], min:2 },
  edgeswitch:  { p:[/^!Current Configuration:/m, /UBNT|EdgeSwitch|^\s*vlan participation (?:include|exclude|auto)/im], min:2 },
  // SONiC 是本檔案唯一 JSON 格式來源，與其餘 28 家語法家族完全不重疊，零碰撞風險
  sonic:       { p:[/"DEVICE_METADATA"\s*:/, /"PORTCHANNEL_MEMBER"\s*:/], min:1 },
  // WatchGuard Firebox config.xml，簽章與 firewall_analyzer 的 WatchGuardParser.detect() 保持一致
  watchguard:  { p:[/<abs-policy-list/, /<interface-list/, /<address-group-list/], min:3 },
  // Windows NPS 設定匯出（netsh nps export，XN72）
  nps_export:  { p:[/<Microsoft_Internet_Authentication_Service\b/, /<Microsoft_Radius_Protocol\b/], min:1 },
  // Citrix NetScaler ADC／Gateway ns.conf（XN105）：檔頭 #NSxx.x Build、set ns config -IPAddress、add ns ip、set ns hostName
  netscaler:   { p:[/^#NS\d+\.\d+ Build /m, /^set ns config -IPAddress /m, /^add ns ip6? /m, /^set ns hostName /m,
    /^(?:add|bind) (?:lb|cs|gslb|vpn|authentication) vserver /m, /^add ssl certKey /m, /^add (?:service|serviceGroup) \S+ /m], min:2 },
  // F5 BIG-IP（XN106）：bigip.conf、tmsh list 輸出或 Oxidized 錄製，tmsh 頂層區塊至少 2 項（與入口頁 isBigipConf() 相同）
  bigip:       { p:[/^#TMSH-VERSION: /m, /^ltm (?:virtual|pool|node) \S+ \{/m, /^net self \S+ \{/m, /^net vlan \S+ \{/m, /^sys global-settings \{/m,
    /^auth user \S+ \{/m, /^sys (?:httpd|sshd|snmp) \{/m, /^sys management-ip /m, /Sys::Version/], min:2 },
  // 應用程式環境變數（XN93）：.env 至少 3 行「大寫名稱=值」（中間可夾空行與註解），或 docker-compose 的 services: 加 environment:；
  // 排在 VENDOR_ORDER 最後，其他廠牌都沒命中時才採用（與入口頁 detectTool() 相同）
  appenv:      { p:[ENV_FILE_RE, /^services:\s*$[\s\S]*^\s+environment:\s*$/m], min:1 }
};
// sophos／aruba_cx 兩家的簽章相對寬鬆（各自僅需命中 2 個訊號，且其中一個訊號是單純字面
// "Sophos"/"Aruba" 文字比對），故刻意排在最後——讓其他更具結構特徵的廠牌訊號優先判定，
// 只有在都沒命中時才輪到這兩家，降低誤判機率
const VENDOR_ORDER = [
  'nps_export','netscaler','bigip','checkpoint_api','cisco_nxos','fortiswitch','fortigate','h3c_secpath','tnsr','wlc','comware','paloalto','cloudsg','cumulus','voss','efos','netgearsmart','tplink','dlink','zyxelsw','onyx','awplus','netfilter','vyos','edgerouter','openwrt','juniper',
  'checkpoint','pfsense','sonicwall','watchguard','mikrotik','fsos','arista',
  'extreme','alcatel','brocade','procurve','dell_os10','planet','ruijie','netgear','edgeswitch','sonic',
  'ciscoasa','cisco_biz','cisco_ios',
  'zyxel','sophos','aruba_cx','appenv'
];
const VENDOR_LABELS = {
  fortigate:'FortiGate',fortiswitch:'FortiSwitch',sophos:'Sophos XG',
  checkpoint:'Check Point',paloalto:'Palo Alto PAN-OS',pfsense:'pfSense/OPNsense',
  sonicwall:'SonicWall',mikrotik:'MikroTik RouterOS',juniper:'Juniper JunOS',
  comware:'H3C / HPE Comware',h3c_secpath:'H3C SecPath',tnsr:'Netgate TNSR',wlc:'Wireless LAN Controller',cisco_ios:'Cisco IOS/IOS-XE',cisco_biz:'Cisco Business (CBS/SG)',fsos:'FS.com FSOS',cisco_nxos:'Cisco NX-OS',
  arista:'Arista EOS',aruba_cx:'Aruba CX',procurve:'Aruba ProCurve',
  dell_os10:'Dell OS10',extreme:'Extreme XOS',alcatel:'Alcatel OmniSwitch',
  brocade:'Brocade FastIron',ciscoasa:'Cisco ASA/FTD',zyxel:'Zyxel USG/ATP',
  edgerouter:'EdgeRouter (EdgeOS)',openwrt:'OpenWrt (UCI)',vyos:'VyOS',netfilter:'Linux iptables/nftables',cloudsg:'AWS / Azure / Meraki',checkpoint_api:'Check Point Management API (JSON)',cumulus:'NVIDIA Cumulus Linux (NVUE)',voss:'Extreme VOSS / Fabric Engine',efos:'Broadcom EFOS',netgearsmart:'Netgear Smart Managed Pro',tplink:'TP-Link JetStream',dlink:'D-Link DGS',zyxelsw:'Zyxel GS/XGS',onyx:'NVIDIA Onyx',awplus:'Allied Telesis AlliedWare Plus',
  planet:'Planet Technology',ruijie:'Ruijie (RGOS)',netgear:'Netgear M4300 (ICOS)',
  edgeswitch:'Ubiquiti EdgeSwitch',sonic:'SONiC (config_db.json)',watchguard:'WatchGuard Firebox',nps_export:'Windows NPS 設定匯出（netsh nps export）',netscaler:'Citrix NetScaler ADC／Gateway（ns.conf）',bigip:'F5 BIG-IP（bigip.conf／tmsh list）',
  appenv:'應用程式環境變數（.env／docker-compose）',
  unknown:''
};

// 廠牌自動偵測候選清單（2026-09-23 新增）：VENDOR_ORDER 既定優先權判斷順序完全不變
// （仍是「先命中先回傳」決定最終 vendor），只是額外把「後續也命中 min 門檻的其他廠牌」
// 收集進 candidates，供 UI 顯示「其他可能候選」提示，讓使用者在偵測疑似有誤時知道還有
// 哪些選項可以手動切換過去。detectVendor() 維持既有簽章與行為，改呼叫此函式取第一個結果。
function detectVendorCandidates(text) {
  // 去除貼上內容開頭的 UTF-8 BOM，否則以行首錨點比對的簽章會漏判
  text = String(text || '').replace(/^\uFEFF/, '');
  // RANCID 備份檔頭（第十七輪 QC）：第一行標明內容類型時優先採用，其餘命中的廠牌列為候選
  const RANCID_ANON = { 'cisco-nx': 'cisco_nxos', arista: 'arista', juniper: 'juniper', paloalto: 'paloalto' };
  const rc = ((text.match(/^[!#]RANCID-CONTENT-TYPE:\s*([\w-]+)/m) || [])[1] || '').toLowerCase();
  let vendor = RANCID_ANON[rc] || 'unknown';
  const candidates = [];
  for (const id of VENDOR_ORDER) {
    if (id === vendor) continue;
    const { p, min } = VENDOR_SIGS[id];
    let m = 0;
    for (const pat of p) { if (pat.test(text)) m++; }
    if (m >= min) {
      if (vendor === 'unknown') vendor = id; else candidates.push(id);
    }
  }
  return { vendor, candidates };
}
function detectVendor(text) {
  return detectVendorCandidates(text).vendor;
}

// ============================================================
// [3] IP / HOSTNAME / USER ANONYMIZATION ENGINE
// ============================================================
// 位址替換核心在共用 anon-core.js（RV16，與 log 工具共用）：IPv4 驗證／分類、IPv4／IPv6 假位址、保留網段結構
const { isValidIPv4, classifyIP, canonIPv6 } = AnonCore;
const { anonIP, anonIPSubnet, registerSubnetMapping, anonIPv6 } = AnonCore.create({ mappings, ctrs, stats, anonOutputIPs, srcIPv4, srcIPv6, subnetMaps, bucketSeen });

function getOpts() {
  return {
    ip:             document.getElementById('opt-ip').checked,
    hostname:       document.getElementById('opt-hostname').checked,
    user:           document.getElementById('opt-user').checked,
    comments:       document.getElementById('opt-comments').checked,
    vdom:           document.getElementById('opt-vdom').checked,
    mac:            document.getElementById('opt-mac').checked,
    macRandomOui:   document.getElementById('opt-mac-random').checked,
    preserveLastOctet: document.getElementById('opt-last-octet').checked,
    preserveSubnet: !!(document.getElementById('opt-subnet') || {}).checked
  };
}


// 依原始分隔符風格（冒號/連字號/點號）產生對應格式的匿名 MAC，一致性映射比照 anonIP
function anonMAC(mac, opts) {
  const norm = mac.replace(/[:.-]/g, '').toLowerCase();
  if (mappings.mac.has(norm)) return formatMAC(mappings.mac.get(norm).hex, mac);
  ctrs.mac++;
  let hex;
  // MAC OUI 隨機化（2026-09-14 新增）：預設沿用既有固定 '02' 前綴＋遞增計數器（可預期、
  // 好對照）；勾選後改用 crypto.getRandomValues() 隨機產生後 5 byte，讓輸出彼此無法用
  // 遞增序號反推裝置順序，同時仍保留 locally-administered bit（第一 byte 第 2 低位元
  // 設 1）＋清 multicast bit（第 1 低位元設 0），避免與真實廠牌 OUI 或群播位址混淆
  if (opts && opts.macRandomOui) {
    const bytes = new Uint8Array(6);
    crypto.getRandomValues(bytes);
    bytes[0] = (bytes[0] & 0xfe) | 0x02;
    hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  } else {
    // 第一 octet 設 U/L bit（locally administered），避免與真實廠牌 OUI 混淆
    hex = '02' + String(ctrs.mac).padStart(10, '0').slice(-10);
  }
  mappings.mac.set(norm, { hex });
  stats.mac++;
  return formatMAC(hex, mac);
}
function formatMAC(hex, original) {
  const bytes = hex.match(/.{2}/g);
  if (/\./.test(original)) return bytes.join('').match(/.{4}/g).join('.');
  if (/-/.test(original)) return bytes.join('-');
  return bytes.join(':');
}

function anonHostname(name, prefix, opts) {
  if (!name || !name.trim()) return name;
  const key = name.trim();
  if (mappings.hostname.has(key)) return mappings.hostname.get(key);
  let mapped;
  do { ctrs.dev++; mapped = `${prefix}-device-${String(ctrs.dev).padStart(3, '0')}`; } while (srcFakeNames.has(mapped));
  mappings.hostname.set(key, mapped);
  stats.hostname++;
  return mapped;
}

function anonUser(name) {
  if (!name || !name.trim()) return name;
  const key = name.trim();
  if (mappings.user.has(key)) return mappings.user.get(key);
  let mapped;
  do { ctrs.usr++; mapped = `user-${String(ctrs.usr).padStart(3, '0')}`; } while (srcFakeNames.has(mapped));
  mappings.user.set(key, mapped);
  stats.user++;
  return mapped;
}
// 引用既有帳號的欄位（群組成員等）：只替換已在對照表中的帳號，避免把非帳號的值誤當帳號
function anonKnownUser(name) {
  const key = String(name || '').trim();
  return mappings.user.has(key) ? mappings.user.get(key) : name;
}
// 電子郵件：帳號部分沿用帳號對照、網域改為保留給文件用途的 example.com
// 完整位址另記一筆帳號對照（假位址 → 原位址），還原時才能連網域一起換回；不同網域的同名帳號
// （john@a.com、john@b.com）若會得到相同假位址，改配新的帳號序號，避免還原時分不開
function anonEmail(addr) {
  const m = String(addr || '').match(/^([^@\s]+)@\S+$/);
  if (!m) return addr;
  const key = String(addr).trim();
  if (mappings.user.has(key)) return mappings.user.get(key);
  const used = new Set(mappings.user.values());
  let fake = anonUser(m[1]) + '@example.com';
  while (used.has(fake) || srcFakeNames.has(fake)) { ctrs.usr++; fake = `user-${String(ctrs.usr).padStart(3, '0')}@example.com`; }
  mappings.user.set(key, fake);
  return fake;
}

// 匯入既有對照表（跨工具聯動，見 log_analyzer 對應的 applyImportedMappings()，各自維護
// 一份、不跨檔引用，比照專案既有 anonIP/anonHostname 等去識別化模組的隔離慣例）：把匯入
// JSON 的 original→mapped 逐筆寫回 mappings，讓後續 anonIP()/anonHostname()/anonUser()/
// anonMAC() 的 cache-hit 分支直接沿用同一組假值；同時把對應計數器墊高，避免之後「新出現」
// 的原始值被分配到與匯入值相撞的假值。只套用「自己也認得」的類別，未知類別靜默略過
// （不需要知道對方工具的類別集合，天然向前相容）。session 內已存在的原始值不覆蓋
// （first-seen-wins），避免匯入打亂已經算出的結果。
//
// 拆成兩段（2026-08-28（續3）修復 runBatch() 洗掉匯入種子的問題）：本函式先把 parsed.mappings
// 累加合併進 IMPORTED_SEED（同一原始值以先匯入者為準，容許使用者連續匯入多份不重疊的對照表），
// 再呼叫 seedLiveMappingsFromImported() 把累加後的種子套用進 live mappings；runBatch() 逐檔
// 重置 mappings 後，直接呼叫 seedLiveMappingsFromImported(IMPORTED_SEED) 即可重新套用，不需要
// 重新走一次合併邏輯
function applyImportedMappings(parsed) {
  if (!parsed || typeof parsed !== 'object' || !parsed.mappings || typeof parsed.mappings !== 'object') {
    return { applied: { ip: 0, hostname: 0, user: 0, mac: 0, ssid: 0, alias: 0, vdom: 0 }, skipped: 0 };
  }
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
  // 套用進 live mappings 時只處理「這次呼叫帶進來的」parsed.mappings，不是累加後的完整
  // IMPORTED_SEED——single-file 模式下 live mappings 本來就不會被清空，之前呼叫已經套用過的
  // 條目仍在，若這裡改成套用完整 IMPORTED_SEED 會讓每次呼叫重新命中舊條目的 first-seen-wins
  // 判斷式，導致回傳的 applied/skipped 統計混入本次呼叫以外的資料。IMPORTED_SEED 本身仍持續
  // 累加，供 runBatch() 逐檔重置後套用完整種子用
  return seedLiveMappingsFromImported(parsed);
}
// 把 IMPORTED_SEED（或任何相同形狀的 { mappings } 物件）寫入 live mappings + 墊高 ctrs，
// 即上面 applyImportedMappings() 原本的函式體，抽出來讓 runBatch() 逐檔重置後也能重新套用
function seedLiveMappingsFromImported(seed) {
  const applied = { ip: 0, hostname: 0, user: 0, mac: 0, ssid: 0, alias: 0, vdom: 0 };
  let skipped = 0;
  if (!seed || typeof seed !== 'object' || !seed.mappings || typeof seed.mappings !== 'object') {
    return { applied, skipped };
  }
  for (const cat of Object.keys(seed.mappings)) {
    if (!Object.prototype.hasOwnProperty.call(mappings, cat) || !(mappings[cat] instanceof Map)) continue; // 本工具不認得的類別，靜默略過
    const entries = seed.mappings[cat];
    if (!entries || typeof entries !== 'object') continue;
    for (const original of Object.keys(entries)) {
      const mapped = entries[original];
      if (typeof mapped !== 'string' || !mapped) { skipped++; continue; }
      if (mappings[cat].has(original)) { skipped++; continue; } // first-seen-wins，不覆蓋

      if (cat === 'ip') {
        let m;
        if ((m = mapped.match(/^192\.0\.2\.(\d+)$/))) ctrs.n1 = Math.max(ctrs.n1, +m[1]);
        else if ((m = mapped.match(/^198\.51\.100\.(\d+)$/))) ctrs.n2 = Math.max(ctrs.n2, +m[1]);
        else if ((m = mapped.match(/^203\.0\.113\.(\d+)$/))) ctrs.n3 = Math.max(ctrs.n3, +m[1]);
        else if ((m = mapped.match(/^2001:db8::(\d+)$/))) ctrs.ip6 = Math.max(ctrs.ip6, +m[1]);
        else if (registerSubnetMapping(original, mapped)) { /* 保留網段結構模式的假位址 */ }
        else { skipped++; continue; } // 不是本工具產生的假 IP 格式，不猜測，跳過
        mappings.ip.set(original, mapped);
        anonOutputIPs.add(mapped);
      } else if (cat === 'mac') {
        // anonMAC() 把十進位計數器字串直接當 hex 字面值使用（見 anonMAC() 實作），
        // 還原時原樣以十進位解析取回計數器值
        const ctr = parseInt(String(mapped).slice(2), 10);
        if (isNaN(ctr)) { skipped++; continue; }
        ctrs.mac = Math.max(ctrs.mac, ctr);
        mappings.mac.set(original, { hex: mapped });
      } else {
        // hostname/user/ssid/alias/vdom：不同類別/工具的前綴字面詞不同（config_anonymizer
        // 用 "-device-"，log_analyzer 用 "host-"），用通用「取結尾連續數字」正則墊高對應
        // 計數器，不需要寫死特定前綴字面詞
        const m = mapped.match(/(\d+)$/);
        const n = m ? +m[1] : 0;
        if (cat === 'hostname') ctrs.dev = Math.max(ctrs.dev, n);
        else if (cat === 'user') ctrs.usr = Math.max(ctrs.usr, n);
        else if (cat === 'ssid') ctrs.ssid = Math.max(ctrs.ssid, n);
        else if (cat === 'alias') ctrs.alias = Math.max(ctrs.alias, n);
        else if (cat === 'vdom') ctrs.vdom = Math.max(ctrs.vdom, n);
        mappings[cat].set(original, mapped);
      }
      applied[cat] = (applied[cat] || 0) + 1;
    }
  }
  return { applied, skipped };
}

function anonSSID(name) {
  if (!name || !name.trim()) return name;
  const key = name.trim();
  if (mappings.ssid.has(key)) return mappings.ssid.get(key);
  ctrs.ssid++;
  const mapped = `ssid-${String(ctrs.ssid).padStart(3, '0')}`;
  mappings.ssid.set(key, mapped);
  stats.ssid++;
  return mapped;
}

function anonVDOM(name) {
  if (!name || !name.trim()) return name;
  const key = name.trim();
  if (mappings.vdom.has(key)) return mappings.vdom.get(key);
  ctrs.vdom++;
  const mapped = `vdom-${String(ctrs.vdom).padStart(3, '0')}`;
  mappings.vdom.set(key, mapped);
  stats.vdom++;
  return mapped;
}

function anonAlias(name) {
  if (!name || !name.trim()) return name;
  const key = name.trim();
  if (mappings.alias.has(key)) return mappings.alias.get(key);
  ctrs.alias++;
  const mapped = `alias-${String(ctrs.alias).padStart(3, '0')}`;
  mappings.alias.set(key, mapped);
  stats.comment++;
  return mapped;
}

// 通用備註/描述/remark 替換（各廠牌共用）
function replaceDescLine(line, opts) {
  if (!opts.comments) return line;
  // description "text" 或 description text（不含引號）
  const d1 = line.replace(/^(\s*description\s+)"([^"]+)"/, '$1"REDACTED_COMMENT"');
  if (d1 !== line) { stats.comment++; return d1; }
  const d2 = line.replace(/^(\s*description\s+)(?!")(\S.{2,})$/, '$1REDACTED_COMMENT');
  if (d2 !== line) { stats.comment++; return d2; }
  // Cisco ACL remark
  const rm = line.replace(/^(\s*remark\s+)(.+)$/, '$1REDACTED_COMMENT');
  if (rm !== line) { stats.comment++; return rm; }
  return line;
}

// IPv4 regex — avoid matching bare version-number segments
// 前面緊接英文字母的不算（Cisco Business 檔頭 v3.2.1.1、RCBS3.2.1.1_950 這類版本字串原本被換成假位址）
const IPv4_RE = /(?<![.\dA-Za-z])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![.\d])/g;
// IPv6（含 :: 零壓縮縮寫）— 原本的簡化版本只認得展開式（8 組或至少 3 組以冒號結尾），
// 完全無法匹配真實世界最常見的 :: 縮寫格式（如 2001:db8::1、fe80::1），已改用涵蓋
// 全 8 組/:: 縮寫全部位置（開頭/中間/結尾/單獨 ::）的完整寫法
const IPv6_RE = /(?<![:\w])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))(?![:\w])/g;
// 冒號格式 MAC（恰好 6 組、每組恰好 2 碼）與 IPv6_RE 的形狀重疊，真實 IPv6 地址不會是這個形狀
// （沒有 :: 縮寫、每組固定 2 碼），排除避免誤判成 IPv6（不論 opts.mac 是否開啟皆須排除，這是
// IPv6_RE 本身既有的誤判風險，非僅本次新增 MAC 功能才會踩到）
const MAC_SHAPE_RE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;

// Generic line-level IP replacement (skips version/comment lines)
function replaceIPsInLine(line, opts) {
  if (/^(?:#config-version=|#build|!! IOS|! Last|!Software|version\s+\d+\.\d+\s*$)/.test(line.trim())) return line;
  // 4 組以上，或含 :: 的縮寫（如 fe80::1、2002::；時間 12:34:56 不含 ::），:: 與 ::1 比照 0.0.0.0／127.x 保留（2026-10-06）
  line = line.replace(IPv6_RE, m => ((m.split(':').length >= 4 || (m.includes('::') && m !== '::' && m !== '::1')) && !MAC_SHAPE_RE.test(m) ? anonIPv6(m) : m));
  line = line.replace(IPv4_RE, m => (isValidIPv4(m) && classifyIP(m) !== 'skip' ? anonIP(m, opts) : m));
  return line;
}

// MAC address 三種常見分隔格式：冒號、連字號、Cisco 點號（3 組 4 碼）
const MAC_COLON_RE = /\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/g;
const MAC_HYPHEN_RE = /\b([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b/g;
const MAC_DOT_RE = /\b([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b/g;

// Generic line-level MAC replacement — 三種格式各自獨立 replace，彼此不重疊，
// 也與 IPv4_RE（4 組十進位）結構不同不會誤判
function replaceMACsInLine(line, opts) {
  line = line.replace(MAC_COLON_RE, m => anonMAC(m, opts));
  line = line.replace(MAC_HYPHEN_RE, m => anonMAC(m, opts));
  line = line.replace(MAC_DOT_RE, m => anonMAC(m, opts));
  return line;
}

// Replace IP+CIDR in a value string
function replaceIPCIDR(val, opts) {
  return val.replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/\d+)?/g, (m, ip, pfx = '') => {
    if (!isValidIPv4(ip) || classifyIP(ip) === 'skip') return m;
    return anonIP(ip, opts) + pfx;
  });
}

// XML 類廠牌 IP 補掃（2026-10-01）：pfSense／OPNsense、SonicWall、Sophos、WatchGuard 原本只替換
// 標籤白名單內的 IP，白名單外的元素照原樣輸出（實測 OPNsense DHCP <start_addr>/<end_addr>、
// pfSense HA <synchronizetoip>、SonicWall NAT <TranslatedDestination> 與監控 <Target>）。
// 比照 anonPaloAltoXML() 全文掃描；標籤名稱或屬性含 version 的元素跳過，避免
// <FirmwareVersion>6.5.4.4</FirmwareVersion> 這類四段版本號被當成 IP 替換。
const XML_VERSION_ELEM_RE = /(<([\w.:-]*version[\w.:-]*)\b[^>]*>[^<]*<\/\2>)/i;
function replaceIPsInXmlText(text, opts) {
  return text.split(new RegExp(XML_VERSION_ELEM_RE.source, 'gi'))
    .map((seg, i) => (i % 3 === 0 ? replaceIPsInLine(seg, opts) : (i % 3 === 1 ? seg : '')))
    .join('');
}

// ============================================================
// [4] VENDOR ANONYMIZERS
// ============================================================

// ---- FortiGate ----
function anonFortiGate(text, opts) {
  const lines = text.split('\n');
  const out = [];
  const stack = [];
  let inSysAdmin = false, inSysGlobal = false, inWifiVap = false;
  let inUserLocal = false, inUserGroup = false; // config user local／config user group
  let inGlobal = false;        // multivdom 的 config global（hostname 直接在此）
  let inSnmpCommunity = false; // config system snmp community（set name = community string）
  // VDOM tracking：depth=0 時 edit 行才是 VDOM 名稱
  let inVdomSection = false, vdomDepth = 0;

  for (let line of lines) {
    const t = line.trim();

    // ── 區塊追蹤 ──────────────────────────────────────────
    if (/^config\s/.test(t)) {
      stack.push(t);
      if (t === 'config system admin')            inSysAdmin = true;
      if (t === 'config user local')              inUserLocal = true;
      if (t === 'config user group')              inUserGroup = true;
      if (t === 'config system global')           inSysGlobal = true;
      if (t === 'config wireless-controller vap') inWifiVap = true;
      if (t === 'config global')                  inGlobal = true;
      if (t === 'config system snmp community')   inSnmpCommunity = true;
      if (t === 'config vdom') { inVdomSection = true; vdomDepth = 0; }
      else if (inVdomSection)  vdomDepth++;
    } else if (t === 'end' && stack.length) {
      const s = stack.pop();
      if (s === 'config system admin')            inSysAdmin = false;
      if (s === 'config user local')              inUserLocal = false;
      if (s === 'config user group')              inUserGroup = false;
      if (s === 'config system global')           inSysGlobal = false;
      if (s === 'config wireless-controller vap') inWifiVap = false;
      if (s === 'config global')                  inGlobal = false;
      if (s === 'config system snmp community')   inSnmpCommunity = false;
      if (s === 'config vdom')                    inVdomSection = false;
      else if (inVdomSection && vdomDepth > 0)    vdomDepth--;
    }

    // ── Header 行（#config-version / #hostname）────────────
    if (/^#config-version=/.test(t)) {
      if (opts.user) {
        line = line.replace(/((?:^|:)user=)([^:\s]+)/, (m, p, n) => p + anonUser(n));
      }
      // 多 VDOM 的 vd1=root:vd2=名稱：與 config vdom 內的 edit 使用同一 VDOM 對照
      if (opts.vdom) line = line.replace(/(:vd\d+=)([^:\s]+)/g, (m, p, n) => p + anonVDOM(n));
      // 不做 IP 替換（版本號保留），直接推出
      out.push(line);
      continue;
    }
    if (/^#hostname=/.test(t) && opts.hostname) {
      line = line.replace(/^(#hostname=)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
      out.push(line);
      continue;
    }

    // ── 密碼 / hash / key ──────────────────────────────────
    if (/\bset\s+(?:password|passwd)\s+ENC\s+/.test(line)) {
      line = line.replace(/(set\s+(?:password|passwd)\s+ENC\s+)\S+/, '$1REDACTED_HASH');
      stats.password++;
    } else {
      const pR = line.replace(/^(\s*set\s+(?:password|passwd)\s+)\S+/, '$1REDACTED_HASH');
      if (pR !== line) { stats.password++; line = pR; }
    }
    // PSK（psksecret 或 psk）
    const pskR = line.replace(/^(\s*set\s+psk(?:secret)?\s+"?)[^"\n]+("?)$/, '$1REDACTED_PSK$2');
    if (pskR !== line) { stats.key++; line = pskR; }
    // key / api-key / secret / auth-password / priv-password / sim-pin / auth-pwd / priv-pwd（SNMPv3）
    // api-key（2026-09 新增）：config system sdn-connector 子區塊 set api-key "..."，真實
    // FortiOS 語法（AWS/Azure/GCP/Kubernetes 等 SDN connector 皆用同一個 api-key 欄位存取
    // 雲端 API 憑證），先前完全沒有遮蔽規則涵蓋
    // secondary-/tertiary- 前綴（2026-10-01）：config user radius 的 secondary-secret／tertiary-secret 與
    // config user tacacs+ 的 secondary-key／tertiary-key 是備援伺服器的共用金鑰，原本未遮蔽
    // passphrase：wireless-controller vap 的 WiFi 密碼（2026-10-01 原本未遮蔽）
    const keyR = line.replace(/^(\s*set\s+(?:(?:secondary-|tertiary-)?(?:key|secret)|api-key|auth-password|priv-password|sim-pin|auth-pwd|priv-pwd|passphrase)\s+"?)[^"\n]+("?)$/, '$1REDACTED_KEY$2');
    if (keyR !== line) { stats.key++; line = keyR; }
    // OSPF MD5 認證金鑰（2026-08-24 新增）：舊版 config router ospf > config ospf-interface >
    // set md5-key <id> <key>；FortiOS 7.0+ 改用 config router key-chain > config key >
    // set key-string <key>（BGP neighbor password 已被上方通用 set password 規則涵蓋，非缺口）
    const ospfKeyR = line.replace(/^(\s*set\s+md5-key\s+\d+\s+)\S+/, '$1REDACTED_KEY').replace(/^(\s*set\s+key-string\s+)\S+/, '$1REDACTED_KEY');
    if (ospfKeyR !== line) { stats.key++; line = ospfKeyR; }
    // community（set community "..."，非 SNMP community name block）
    const comR = line.replace(/^(\s*set\s+community\s+"?)[^"\n]+("?)$/, '$1REDACTED_COMMUNITY$2');
    if (comR !== line) { stats.community++; line = comR; }
    // SNMP community name block（config system snmp community > set name "..."）
    if (inSnmpCommunity) {
      const snmpNR = line.replace(/^(\s*set\s+name\s+"?)[^"\n]+("?)$/, (m, p, s2) => { stats.community++; return p + 'REDACTED_COMMUNITY' + s2; });
      if (snmpNR !== line) line = snmpNR;
    }

    // ── Hostname（config system global 或 multivdom config global）
    if (opts.hostname && (inSysGlobal || inGlobal)) {
      // 保留原本的引號（原本一律去掉，set hostname "FW-01" 變成 set hostname dev-…，還原後格式也不同）
      line = line.replace(/^(\s*set\s+hostname\s+)(\S+)/, (m, p, n) => { const q = n.startsWith('"') ? '"' : ''; return p + q + anonHostname(n.replace(/"/g, ''), 'fw', opts) + q; });
    }

    // ── VDOM 名稱（config vdom 內 depth=0 的 edit）────────
    if (opts.vdom && inVdomSection && vdomDepth === 0) {
      // 帶引號：edit "VDOM_NAME"
      line = line.replace(/^(\s*edit\s+)"([^"]+)"/, (m, p, n) => p + '"' + anonVDOM(n) + '"');
      // 不帶引號：edit VDOM_NAME
      line = line.replace(/^(\s*edit\s+)([A-Za-z]\S*)$/, (m, p, n) => p + anonVDOM(n));
    }
    // set vdom "VDOM_NAME"（跨檔案替換已知的 VDOM 名稱）
    if (opts.vdom) {
      line = line.replace(/^(\s*set\s+vdom\s+)"([^"]+)"/, (m, p, n) => {
        const mapped = mappings.vdom.get(n) || anonVDOM(n);
        return p + '"' + mapped + '"';
      });
    }

    // ── WiFi SSID（VAP 名稱與 set ssid）──────────────────
    if (opts.hostname && inWifiVap) {
      line = line.replace(/^(\s*set\s+ssid\s+)"([^"]+)"/, (m, p, n) => p + '"' + anonSSID(n) + '"');
      line = line.replace(/^(\s*edit\s+)"([^"]+)"/, (m, p, n) => p + '"' + anonSSID(n) + '"');
    }

    // ── Username (admin / PPPoE / WWAN) ───────────────────
    if (opts.user) {
      // 管理者帳號與本機使用者帳號（config user local，原本未處理，帳號名稱原樣留在輸出中）
      if (inSysAdmin || inUserLocal) {
        line = line.replace(/^(\s*edit\s+)"([^"]+)"/, (m, p, n) => p + '"' + anonUser(n) + '"');
      }
      // 使用者群組成員引用上方已替換的本機帳號
      if (inUserGroup) {
        line = line.replace(/^(\s*set\s+member\s+)(.+)$/, (m, p, rest) => p + rest.replace(/"([^"]+)"/g, (mm, n) => '"' + anonKnownUser(n) + '"'));
      }
      line = line.replace(/^(\s*set\s+email-to\s+")([^"]+)(")/, (m, p, e, c) => p + anonEmail(e) + c);
      // PPPoE / WWAN / LTE modem username（set username "user@carrier"）
      const uR = line.replace(/^(\s*set\s+username\s+"?)([^"\n]+)("?)$/, (m, p, n, s) => {
        if (!n.trim()) return m;  // 空字串保留
        stats.user++;
        return p + anonUser(n.trim()) + s;
      });
      if (uR !== line) line = uR;
    }

    // ── 備註 / 別名 / 描述 ────────────────────────────────
    if (opts.comments) {
      line = line.replace(/^(\s*set\s+alias\s+)"([^"]+)"/, (m, p, n) => p + '"' + anonAlias(n) + '"');
      const cR = line.replace(/^(\s*set\s+(?:comments?|description)\s+)"([^"]*)"/, (m, p) => { stats.comment++; return p + '"REDACTED_COMMENT"'; });
      if (cR !== line) line = cR;
    }

    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    out.push(line);
  }
  return out.join('\n');
}

// ---- FortiSwitch (FortiOS CLI for switches) ----
function anonFortiSwitch(text, opts) {
  const lines = text.split('\n');
  const out = [];
  const stack = [];
  let inAdmin = false, inGlobal = false, inSnmpCommunity = false;

  for (let line of lines) {
    const t = line.trim();
    if (/^config\s/.test(t)) {
      stack.push(t);
      if (t === 'config system admin') inAdmin = true;
      if (t === 'config system global') inGlobal = true;
      if (t === 'config system snmp community') inSnmpCommunity = true;
    } else if (t === 'end' && stack.length) {
      const s = stack.pop();
      if (s === 'config system admin') inAdmin = false;
      if (s === 'config system global') inGlobal = false;
      if (s === 'config system snmp community') inSnmpCommunity = false;
    }
    // FortiSwitch 密碼：支援 ENC 兩段格式（同 FortiGate）
    if (/\bset\s+(?:password|passwd)\s+ENC\s+/.test(line)) {
      line = line.replace(/(set\s+(?:password|passwd)\s+ENC\s+)\S+/, '$1REDACTED_HASH');
      stats.password++;
    } else {
      const pR = line.replace(/^(\s*set\s+(?:password|passwd)\s+)\S+/, '$1REDACTED_HASH');
      if (pR !== line) { stats.password++; line = pR; }
    }
    // key / secret / auth-pwd / priv-pwd（同 FortiGate）
    const keyR = line.replace(/^(\s*set\s+(?:(?:secondary-|tertiary-)?(?:key|secret)|auth-password|priv-password|auth-pwd|priv-pwd)\s+"?)[^"\n]+("?)$/, '$1REDACTED_KEY$2');
    if (keyR !== line) { stats.key++; line = keyR; }
    // OSPF MD5 認證金鑰（2026-08-24 新增，同 FortiGate）：config router key-chain > config key >
    // set key-string <key>（BGP neighbor password 已被上方通用 set password 規則涵蓋，非缺口）
    const ospfKeyR = line.replace(/^(\s*set\s+key-string\s+)\S+/, '$1REDACTED_KEY');
    if (ospfKeyR !== line) { stats.key++; line = ospfKeyR; }
    // community（set community "..." 或 community-name）
    const cR = line.replace(/^(\s*set\s+community(?:-name)?\s+"?)[^"\n]+("?)$/, '$1REDACTED_COMMUNITY$2');
    if (cR !== line) { stats.community++; line = cR; }
    // SNMP community name block（config system snmp community > set name "..."）
    if (inSnmpCommunity) {
      const snmpNR = line.replace(/^(\s*set\s+name\s+"?)[^"\n]+("?)$/, (m, p, s2) => { stats.community++; return p + 'REDACTED_COMMUNITY' + s2; });
      if (snmpNR !== line) line = snmpNR;
    }
    if (opts.hostname && inGlobal) {
      line = line.replace(/^(\s*set\s+hostname\s+)(\S+)/, (m, p, n) => { const q = n.startsWith('"') ? '"' : ''; return p + q + anonHostname(n.replace(/"/g,''),'sw',opts) + q; });
    }
    if (opts.user && inAdmin) {
      line = line.replace(/^(\s*edit\s+)"([^"]+)"/, (m, p, n) => p + '"' + anonUser(n) + '"');
    }
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    out.push(line);
  }
  return out.join('\n');
}

// ---- Sophos XG CLI ----
function anonSophosCLI(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(set\s+hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
    }
    const pR = line.replace(/^(set\s+(?:admin-settings\s+admin-password|snmpv3\s+(?:auth|priv)password|ipsec-vpn\s+preshared-key|user\s+add\s+username\s+\S+\s+password)\s+)(\S+)/, '$1REDACTED_HASH');
    if (pR !== line) { stats.password++; line = pR; }
    if (opts.user) {
      line = line.replace(/^(set\s+user\s+add\s+username\s+)(\S+)(\s+password\s+)/, (m, p, n, rest) => p + anonUser(n) + rest);
    }
    const comR = line.replace(/^(set\s+snmpv2\s+community-string\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    const kR = line.replace(/^(\s*(?:set\s+radius-server|set\s+tacacs).+?\s+key\s+)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Sophos XML backup ----
function anonSophosXML(text, opts) {
  // CDATA-aware tag replacement helpers
  // 修正既有 bug：\[／\] 在樣板字串中非合法跳脫序列，JS 會靜默去掉反斜線，
  // 導致組出來的 RegExp 語法錯誤（Unterminated group）。原始寫法下這兩個
  // 函式對任何輸入都會直接拋錯，anonSophosXML() 實質上從未真正運作過，
  // 只是先前沒有測試實際呼叫過 anonymize(text,'sophos',opts) 才未被發現。
  function replaceTag(t, tag, newVal) {
    return t.replace(new RegExp(`(<${tag}>)(<!\\[CDATA\\[)[^\\]]*(\\]\\]>)(<\\/${tag}>)`, 'g'), `$1$2${newVal}$3$4`)
            .replace(new RegExp(`(<${tag}>)[^<]*(<\\/${tag}>)`, 'g'), `$1${newVal}$2`);
  }
  // 2026-07-27 查證官方 Sophos Firewall API 文件（docs.sophos.com）＋真實 fixture
  // （firewall_analyzer/test_config/sophos_test.xml）後，改呼叫共用 replaceIPsInLine()
  // 取代原本的 isValidIPv4() 嚴格全值比對：(1) 補上 IPv6 支援（原本任何 IPv6 值皆會因
  // isValidIPv4() 判 false 而原樣外洩）；(2) 涵蓋官方 DHCP Server 範圍標籤 <IP> 是
  // "start-end" 連字號格式（非單純一個 IP），全值比對會直接判定不符而放行，
  // replaceIPsInLine() 逐一掃描比對則可正確找到並替換範圍內的兩個位址
  function replaceTagIP(t, tag, opts2) {
    return t.replace(new RegExp(`(<${tag}>)(<!\\[CDATA\\[)([^\\]]+)(\\]\\]>)(<\\/${tag}>)`, 'g'), (m, o, cd, val, ce, c) =>
      o + cd + replaceIPsInLine(val.trim(), opts2) + ce + c
    ).replace(new RegExp(`(<${tag}>)([^<]+)(<\\/${tag}>)`, 'g'), (m, o, val, c) =>
      o + replaceIPsInLine(val.trim(), opts2) + c
    );
  }

  text = replaceTag(text, 'Password', 'REDACTED_HASH');
  text = replaceTag(text, 'SharedSecret', 'REDACTED_PSK');
  text = replaceTag(text, 'CommunityString', 'REDACTED_COMMUNITY');
  text = replaceTag(text, 'Secret', 'REDACTED_KEY');
  stats.password += (text.match(/REDACTED_HASH/g) || []).length;
  stats.key += (text.match(/REDACTED_PSK|REDACTED_KEY/g) || []).length;
  stats.community += (text.match(/REDACTED_COMMUNITY/g) || []).length;

  if (opts.hostname) {
    // DeviceName：SophosParser.parseDeviceInfo() 優先讀取的主機名稱標籤，原本未處理
    text = text.replace(/(<(HostName|DeviceName)>)(<!\[CDATA\[)?([^\]<]+?)(\]\]>)?(<\/\2>)/g, (m, o, t2, cd, name, ce, c) =>
      o + (cd||'') + anonHostname(name.trim(), 'fw', opts) + (ce||'') + c);
  }
  // 本機／管理者帳號與群組成員（標籤依 SophosParser.parseUsers()）；原本完全未處理
  if (opts.user) {
    text = text.replace(/<(User|Administrator|AdminUser)>([\s\S]*?)<\/\1>/g, (m, tag, body) =>
      `<${tag}>` + body.replace(/(<(Name|Username)>)([^<]+)(<\/\2>)/g, (mm, o, t2, n, c) => o + anonUser(n.trim()) + c)
        .replace(/(<(Email|EmailAddress)>)([^<]+)(<\/\2>)/g, (mm, o, t2, e, c) => o + anonEmail(e.trim()) + c) + `</${tag}>`);
    text = text.replace(/<(Group|UserGroup)>([\s\S]*?)<\/\1>/g, (m, tag, body) =>
      `<${tag}>` + body.replace(/(<(Member|User)>)([^<]+)(<\/\2>)/g, (mm, o, t2, n, c) => o + anonKnownUser(n.trim()) + c) + `</${tag}>`);
  }
  if (opts.ip) {
    // 標籤清單依官方 Sophos Firewall API 文件（docs.sophos.com/nsg/sophos-firewall；
    // VPNIPSecConnection 用 RemoteHost 而非先前假設的 RemoteGateway；DHCPRelay 用
    // DHCPServerIP；IPRange 型別 IPHost 物件用 StartIPAddress/EndIPAddress；IPv4 DHCP
    // Server 用 IP（start-end 連字號範圍）＋PrimaryDNSServer/SecondaryDNSServer）＋真實
    // fixture（StaticRoute Destination、DHCPServer 巢狀 IPRange From/To 與舊式平坦
    // StartIP/EndIP 兩種格式並存）交叉比對後補齊，原本 8 個標籤會讓 IPsec 對端位址、
    // DHCP 位址範圍、DHCP Relay 伺服器位址、靜態路由目的網段全部明碼外洩；RemoteGateway/
    // ServerIP/StartIP/EndIP/From/To 為既有 fixture 出現過的變體名稱一併保留防禦性涵蓋
    for (const tag of ['IPAddress','ExternalAddress','PrimaryAddress','SecondaryAddress','Gateway',
                        'DNSServer','NTPServer','SyslogServer','PrimaryDNSServer','SecondaryDNSServer',
                        'RemoteHost','RemoteGateway','Destination','StartIPAddress','EndIPAddress',
                        'DHCPServerIP','ServerIP','IP','StartIP','EndIP','From','To']) {
      text = replaceTagIP(text, tag, opts);
    }
    // SSL VPN split-tunnel 允許清單（SSLVPNPolicy/PermittedNetworkResourcesIPv4|IPv6/Resource，
    // 依官方 Sophos Firewall XML API 文件查證）：內容可能是具名物件參照（如 #PortA）或直接
    // IP/CIDR，用 replaceIPCIDR() 只替換符合 IP 格式的內容，物件參照原樣保留不誤傷
    text = text.replace(/(<Resource>)(<!\[CDATA\[)?([^\]<]+?)(\]\]>)?(<\/Resource>)/g, (m, o, cd, val, ce, c) =>
      o + (cd||'') + replaceIPCIDR(val, opts) + (ce||'') + c);
    // 白名單外的元素補掃（CDATA 內容同樣在掃描範圍內）
    text = replaceIPsInXmlText(text, opts);
  }
  // 2026-08-09 稽核修復：anonSophosXML() 先前完全沒有處理 MAC 位址，即使 opts.mac 已勾選；
  // SophosParser.parseInterfaces() 已驗證真實欄位 <MACAddress> 存在（介面實體 MAC），比照
  // replaceTagIP() 既有的 CDATA-aware 寫法新增 replaceTagMAC()
  if (opts.mac) {
    function replaceTagMAC(t, tag) {
      return t.replace(new RegExp(`(<${tag}>)(<!\\[CDATA\\[)([^\\]]+)(\\]\\]>)(<\\/${tag}>)`, 'g'), (m, o, cd, val, ce, c) =>
        o + cd + replaceMACsInLine(val.trim(), opts) + ce + c
      ).replace(new RegExp(`(<${tag}>)([^<]+)(<\\/${tag}>)`, 'g'), (m, o, val, c) =>
        o + replaceMACsInLine(val.trim(), opts) + c
      );
    }
    text = replaceTagMAC(text, 'MACAddress');
  }
  // OSPF/BGP MD5 認證金鑰（2026-08-24 查證後排除）：Sophos CLI 為 FRR-based、Cisco 風格語法
  // 已由官方 CLI 文件索引頁確認，但無法取得可直接查證的官方指令頁面文字，社群/KB 來源提及的
  // `neighbor <ip> password <auth>`／OSPF Key ID+Key 欄位皆非主要文件直接佐證；Entities.xml
  // 備份格式是否明碼儲存此類金鑰亦查無確認。無真實範例可比對，比照專案既有原則不猜測新增規則。
  return text;
}

function anonSophos(text, opts) {
  return text.trim().startsWith('<') ? anonSophosXML(text, opts) : anonSophosCLI(text, opts);
}

// ---- Check Point Gaia CLI ----
function anonCheckPoint(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(set\s+hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
    }
    // 密碼雜湊與明碼密碼（set user NAME password VALUE，原本未遮蔽，明碼原樣留在輸出中）
    const pR = line.replace(/^(set\s+user\s+\S+\s+password-hash\s+)(\S+)/, '$1REDACTED_HASH').replace(/^(set\s+user\s+\S+\s+password\s+)(\S+)/, '$1REDACTED_PASSWORD');
    if (pR !== line) { stats.password++; line = pR; }
    if (opts.user) {
      line = line.replace(/^(set\s+user\s+\S+\s+realname\s+)(.+)/, '$1"REDACTED"');
      // 同一帳號的 uid／role-name／shell 等每一行都要一致替換帳號名稱（原本只處理 password-hash 與 realname）
      line = line.replace(/^(set\s+user\s+)(\S+)/, (m, p, n) => p + anonUser(n));
      // 2026-10-01：objects 匯出的 :AdminInfo 區塊 `:login (NAME)` 與 `set access-role R users A,B`
      // 的帳號清單原本未處理，勾選帳號匿名化後仍留下原帳號
      line = line.replace(/^(\s*:login\s+\()([^)\s]+)(\))/, (m, p, n, c) => p + anonUser(n) + c);
      line = line.replace(/^(set\s+access-role\s+\S+\s+users\s+)(\S+)/, (m, p, list) => p + list.split(',').map(n => (n ? anonUser(n) : n)).join(','));
      // SNMPv3 帳號（比照 Cisco snmp-server user 的處理）
      line = line.replace(/^(set\s+snmp\s+v3\s+user\s+)("?)([^"\s]+)("?)/, (m, p, q1, n, q2) => p + q1 + anonUser(n) + q2);
    }
    const comR = line.replace(/^(set\s+snmp\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    const kR = line.replace(/^(set\s+(?:tacacs|radius)\s+server\s+\S+\s+(?:key|secret)\s+)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    // OSPF/BGP MD5 認證金鑰（2026-08-24 新增，官方 Gaia Advanced Routing Admin Guide 查證）：
    // OSPF `set ospf ... authtype cryptographic key N algorithm md5 secret "VALUE"`；
    // BGP `set bgp ... peer X authtype md5 secret VALUE`，兩者皆以 algorithm/authtype md5
    // 緊接 secret 欄位為特徵，同一正則涵蓋（secret 可能帶或不帶雙引號）
    const routeKeyR = line.replace(/((?:algorithm|authtype)\s+md5\s+secret\s+"?)[^"\s]+("?)/, '$1REDACTED_KEY$2');
    if (routeKeyR !== line) { stats.key++; line = routeKeyR; }
    // objects_5_0.C passwd
    const objR = line.replace(/^(\s*:\s*\(passwd\s+")([^"]+)(")/, '$1REDACTED_HASH$3');
    if (objR !== line) { stats.password++; line = objR; }
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Palo Alto PAN-OS (set format 與 XML 格式皆支援) ----
// 2026-08-09 稽核修復：原本函式僅涵蓋 "set" 純文字格式，但 PaloAltoParser（firewall_analyzer）
// 同時支援 XML 候選設定格式（isXml()/xv() 等 helper），XML 上傳檔先前完全沒有任何機敏欄位
// 遮蔽（僅通用 IP 掃描仍生效）。已對照 PaloAltoParser 與真實 fixture
// （firewall_analyzer/test_config/paloalto_test.xml）交叉確認的標籤：<hostname>（巢狀於
// <system>）、<pre-shared-key><key>VALUE</key></pre-shared-key>；SNMP community 依 Parser
// parseSnmp() 兩種既有格式（<snmp-community-string> 與 <snmp-community><entry name="X"/>>）
// 一併涵蓋。管理者帳號與密碼雜湊（2026-10-05 補上）：XML 格式為 <mgt-config><users><entry name="帳號">
// <phash>雜湊</phash>，依 Palo Alto 官方 iron-skillet 的防火牆與 Panorama 設定檔確認
function anonPaloAltoXML(text, opts) {
  text = text.replace(/(<phash>)([^<]*)(<\/phash>)/g, (m, o, v, c) => { stats.password++; return o + 'REDACTED_HASH' + c; });
  if (opts.user) {
    text = text.replace(/(<mgt-config>[\s\S]*?<users>)([\s\S]*?)(<\/users>)/, (m, a, body, c) =>
      a + body.replace(/(<entry\s+name=")([^"]+)(")/g, (mm, p, n, q) => p + anonUser(n) + q) + c);
  }
  if (opts.hostname) {
    text = text.replace(/(<hostname>)([^<]+)(<\/hostname>)/i, (m, o, name, c) => o + anonHostname(name.trim(), 'fw', opts) + c);
  }
  // pre-shared-key 巢狀在 <authentication><pre-shared-key><key>VALUE</key></pre-shared-key>
  text = text.replace(/(<pre-shared-key>\s*<key>)([^<]+)(<\/key>\s*<\/pre-shared-key>)/gi, (m, o, v, c) => { stats.key++; return o + 'REDACTED_PSK' + c; });
  // SNMP community：Format A <snmp-community-string>X</snmp-community-string>；
  // Format B <snmp-community><entry name="X"/></snmp-community>（community 值即 entry name）
  text = text.replace(/(<snmp-community-string>)([^<]+)(<\/snmp-community-string>)/gi, (m, o, v, c) => { stats.community++; return o + 'REDACTED_COMMUNITY' + c; });
  text = text.replace(/(<snmp-community>\s*<entry\s+name=")([^"]+)("\s*\/?>)/gi, (m, o, v, c) => { stats.community++; return o + 'REDACTED_COMMUNITY' + c; });
  if (opts.ip) text = replaceIPsInLine(text, opts);
  if (opts.mac) text = replaceMACsInLine(text, opts);
  return text;
}
function anonPaloAlto(text, opts) {
  if (text.trimStart().startsWith('<')) return anonPaloAltoXML(text, opts);
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(set\s+deviceconfig\s+system\s+hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
    }
    // 帳號名稱：同一帳號的 permissions／public-key 等其他行也要一致替換，原本只處理 phash 那一行，
    // 其餘行留下原始帳號名稱（外洩），解析時還會多出一個帳號
    if (opts.user) line = line.replace(/^(set\s+mgt-config\s+users\s+)(\S+)/, (m, p, n) => p + anonUser(n));
    const pR = line.replace(/^(set\s+mgt-config\s+users\s+\S+\s+phash\s+)(\S+)/, '$1REDACTED_HASH');
    if (pR !== line) { stats.password++; line = pR; }
    // 實際路徑在 gateway 名稱後有 authentication（Batfish ipsec-tunnel 測試設定，第十七輪 QA），兩種寫法都認
    const pskR = line.replace(/^(set\s+network\s+ike\s+gateway\s+\S+\s+(?:authentication\s+)?pre-shared-key\s+key\s+)(\S+)/, '$1REDACTED_PSK');
    if (pskR !== line) { stats.key++; line = pskR; }
    // OSPF 認證設定檔 `… protocol ospf auth-profile 名稱 password 值`／`md5 N key 值`（Batfish palo_alto ospf 測試設定）
    const ospfR = line.replace(/(\bauth-profile\s+\S+\s+(?:password|md5\s+\d+\s+key)\s+)(\S+)/, '$1REDACTED_KEY');
    if (ospfR !== line) { stats.key++; line = ospfR; }
    // 大括號格式的 `password 值;`（外部動態清單 auth 等）
    const braceR = line.replace(/^(\s*password\s+)([^;\s]+)(;)/, '$1REDACTED_PASSWORD$3');
    if (braceR !== line) { stats.password++; line = braceR; }
    if (opts.user) line = line.replace(/^(\s*username\s+)([^;\s]+)(;)/, (m, p, u, e) => p + anonUser(u) + e);
    // SNMP community（允許 community 在行尾，移除必要尾端空白）
    const comR = line.replace(/^(.+\s+community\s+)(\S+)/, (m, p, c) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    if (comR !== line) line = comR;
    const secR = line.replace(/^(.+\s+secret\s+)(\S+)$/, '$1REDACTED_KEY');
    if (secR !== line) { stats.key++; line = secR; }
    // BGP peer `connection-options authentication password "值"`（paloalto_complex_test.conf）
    const bgpPwR = line.replace(/(\sauthentication\s+password\s+)("[^"]*"|\S+)/, (m, p, v) => (/REDACTED/.test(v) ? m : p + (v[0] === '"' ? '"REDACTED_PASSWORD"' : 'REDACTED_PASSWORD')));
    if (bgpPwR !== line) { stats.password++; line = bgpPwR; }
    // SNMPv3 trap 伺服器帳號 `… server NMS-V3 user 名稱`
    if (opts.user) line = line.replace(/^(set\s+.*\bserver-profile\s+snmp-trap\s+.*\sserver\s+\S+\s+user\s+)(\S+)/, (m, p, u) => p + anonUser(u));
    // BGP peer 認證金鑰（`set network virtual-router <vr> protocol bgp auth-profile <name>
    // secret <value>`，官方 PAN-OS Ansible 模組 panos_bgp_auth 查證，中高信心度）已被上面這條
    // 通用 `... secret VALUE` 規則涵蓋，非缺口。OSPF 認證（OSPF Auth Profile 物件，PAN-OS
    // Networking Admin Guide 僅確認 GUI 欄位名稱與 profile 架構，2026-08-24 查證後未能找到
    // 對應的 CLI `set`/XML 欄位逐字語法佐證）比照專案「不猜測」原則不新增規則。
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- pfSense / OPNsense XML ----
function anonPfSense(text, opts) {
  // OSPF/BGP MD5 認證金鑰（2026-08-24 查證）：pfSense OSPF/BGP 僅透過 pfSense-pkg-frr 套件
  // 提供，GUI 欄位皆命名為「Password」，官方套件原始碼（frr_ospf.inc/frr_bgp.inc，
  // pfsense/FreeBSD-ports repo）確認對應 config.xml 元素為 <password>，與下方既有
  // `<password>` 標籤規則同名同格式，已天生涵蓋，非缺口，不需新增規則。
  const lines = text.split('\n');
  const out = [];
  let inUser = false, inGroup = false; // <group> 區塊內的 <member> 為帳號名稱
  // shared_key／tls 跨行狀態（2026-08-08 查證修正）：對外查證 pfsensible/core GitHub
  // issue #132 確認 pfSense OpenVPN 的 <shared_key>／<tls> 欄位儲存的是保留原始換行的
  // PEM 格式文字（"-----BEGIN OpenVPN Static key V1-----" 區塊），不是像憑證管理員的
  // <cert>/<prv> 那樣整段 base64 壓成單行；原本的單行正則要求開始/結束標籤同一行才會
  // 比對到，跨行時完全比對不到、金鑰明碼原樣殘留在輸出（checkResidual() 的 PEM 區塊
  // 偵測雖然抓得到殘留警告，但根本問題是 anonPfSense() 本身沒有真的把它遮蔽）；<tls>
  // 標籤先前甚至完全沒有對應規則，不論單行多行都不會被處理。修法比照既有 inUser 的
  // context flag 慣例：進入沒有收尾標籤的開始行時記住目前是哪個標籤，之後逐行捨棄金鑰
  // 內容本體，直到遇到收尾標籤行才恢復輸出
  let multilineKeyTag = null;

  for (let line of lines) {
    // 目前處於跨行金鑰區塊中間：這一整行是金鑰內容本體，直接捨棄；只有含收尾標籤的那行
    // 才恢復輸出（且只保留收尾標籤本身，之前殘留的金鑰內容一併捨棄）
    if (multilineKeyTag) {
      const closeRe = new RegExp(`<\\/${multilineKeyTag}>`);
      const m = line.match(closeRe);
      if (m) {
        out.push(line.slice(m.index));
        multilineKeyTag = null;
      }
      continue;
    }

    // 先開啟 context flag，再做所有替換，最後才關閉 flag（避免單行含 <user>…</user> 時 flag 被同一行清除）
    if (/<user>/.test(line)) inUser = true;
    if (/<group>/.test(line)) inGroup = true;

    // Passwords
    const pR = line.replace(/(<(?:password|bcrypt-hash|md5-hash)>)([^<]*)(<\/[^>]+>)/, '$1REDACTED_HASH$3');
    if (pR !== line) { stats.password++; line = pR; }
    // PSK：支援 <preshared_key> 與 <pre-shared-key>（連字號格式）
    // <passphrase>：無線 <wireless><wpa><passphrase>（2026-10-01 原本未遮蔽）
    const pskR = line.replace(/(<(?:preshared_key|pre-shared-key|passphrase)>)([^<]*)(<\/[^>]+>)/, '$1REDACTED_PSK$3');
    if (pskR !== line) { stats.key++; line = pskR; }
    // 無線 SSID（比照 FortiGate VAP，歸在主機名稱選項下）
    if (opts.hostname) line = line.replace(/(<ssid>)([^<]+)(<\/ssid>)/, (m, o, n, c) => o + anonSSID(n) + c);
    // shared_key（OpenVPN Static Key 模式）／tls（tls-auth/tls-crypt 金鑰）：先嘗試同一行
    // 內完整標籤（沿用既有簡單 case，涵蓋人工精簡過或單行匯出的情況），比對不到才檢查
    // 「這行只有開始標籤、沒有收尾標籤」的跨行起點情形，後續行交給上面的 multilineKeyTag
    // 分支逐行捨棄，直到遇到收尾標籤
    for (const kt of ['shared_key', 'tls']) {
      const sameLineRe = new RegExp(`(<${kt}>)([^<]*)(<\\/${kt}>)`);
      const sameLineR = line.replace(sameLineRe, `$1REDACTED_KEY$3`);
      if (sameLineR !== line) {
        stats.key++;
        line = sameLineR;
        continue;
      }
      if (new RegExp(`<${kt}>`).test(line)) {
        line = line.replace(new RegExp(`<${kt}>`), `<${kt}>REDACTED_KEY`);
        stats.key++;
        multilineKeyTag = kt;
      }
    }
    // 憑證管理員的 <crt>／<prv>（base64 單行 PEM，含私鑰）與 OPNsense <httpdPassword> 等名稱以 password／secret 結尾的標籤
    // （Oxidized pfSense CE 2.7.2／OPNsense 真實錄製，第十六輪 PA）
    const certR = line.replace(/(<prv>)([^<]+)(<\/prv>)/, '$1REDACTED_KEY$3').replace(/(<crt>)([^<]+)(<\/crt>)/, '$1REDACTED_CERT$3');
    if (certR !== line) { stats.key++; line = certR; }
    const pwTagR = line.replace(/(<([A-Za-z_]*(?:[Pp]assword|[Ss]ecret))>)([^<]+)(<\/\2>)/, '$1REDACTED_PASSWORD$4');
    if (pwTagR !== line) { stats.password++; line = pwTagR; }
    const comR = line.replace(/(<(?:rocommunity|rwcommunity|community)>)([^<]*)(<\/[^>]+>)/, '$1REDACTED_COMMUNITY$3');
    if (comR !== line) { stats.community++; line = comR; }
    const bpR = line.replace(/(<bindpw>)([^<]*)(<\/bindpw>)/, '$1REDACTED_PASSWORD$3');
    if (bpR !== line) { stats.password++; line = bpR; }

    if (opts.hostname) {
      line = line.replace(/(<hostname>)([^<]+)(<\/hostname>)/, (m, o, n, c) => o + anonHostname(n, 'fw', opts) + c);
    }
    if (opts.user && inUser) {
      line = line.replace(/(<name>)([^<]+)(<\/name>)/, (m, o, n, c) => o + anonUser(n) + c);
    }

    // 替換完畢後才關閉 context flag（處理單行含 open+close tag 的情況）
    // 群組成員（<group><member>帳號</member>）：成員可能出現在帳號定義之前，直接以帳號對照替換；
    // 純數字為 uid，不處理
    if (opts.user && inGroup) line = line.replace(/(<member>)([^<]+)(<\/member>)/g, (m, o, n, c) => (/^\d+$/.test(n) ? m : o + anonUser(n) + c));
    if (/<\/user>/.test(line)) inUser = false;
    if (/<\/group>/.test(line)) inGroup = false;
    if (opts.ip) {
      // 單一 IP 值標籤：對外查證官方 pfSense/OPNsense config.xml 匯出結構＋真實 fixture
      // （firewall_analyzer/test_config/pfsense_complex_test.xml）後發現，原本只認 7 個標籤
      // 且僅 IPv4，導致 DNS/NTP 的 IPv6 值、interface IPv6 位址（ipaddrv6）、IPsec
      // remote-gateway、RADIUS host（原本僅限 authserver 區塊內才替換，radius server 的
      // host 完全漏掉）、DHCP range from/to、syslog remoteserver 系列/sourceip、unbound 靜態
      // host ip、timeservers（多值，空白分隔）皆明碼外洩；改呼叫共用 replaceIPsInLine() 對
      // 擷取出的單一標籤內容做掃描（同時涵蓋 IPv4/IPv6，且因內部為 /g 全域比對，天然支援
      // timeservers 這種單一標籤內含多個空白分隔位址的情況），非 IP 內容（如 host 標籤下的
      // 純 hostname、schedule 的 from/to 時間值）因不符合 IPv4/IPv6 格式會被自動跳過，不會誤傷
      line = line.replace(/(<(?:ipaddr|ipaddrv6|gateway|remote-gateway|ntpserver|dnsserver|nameserver|syslogip|server|host|ip|from|to|dns_server[1-4]|remoteserver\d?|sourceip|timeservers)>)([^<]+)(<\/[^>]+>)/, (m, o, val, c) => o + replaceIPsInLine(val.trim(), opts) + c);
      // CIDR / 多值標籤：新增 tunnel_network／local_network（OpenVPN，可能逗號分隔多筆）／
      // target（NAT），replaceIPCIDR() 本身即支援 /g 多筆與可選 CIDR 遮罩
      line = line.replace(/(<(?:network|address|destination|source|tunnel_network|local_network|target)>)([^<]+)(<\/[^>]+>)/, (m, o, val, c) => {
        return o + replaceIPCIDR(val, opts) + c;
      });
      // 白名單外的元素（DHCP start_addr/end_addr、synchronizetoip 等）補掃
      line = replaceIPsInXmlText(line, opts);
    }
    // MAC address（staticmap 靜態 DHCP／ARP 綁定等）：原本完全未接線，static-map 的
    // <mac>aa:bb:cc:dd:ee:ff</mac> 不論 opts.mac 開關為何皆會明碼外洩
    if (opts.mac) line = replaceMACsInLine(line, opts);
    out.push(line);
  }
  return out.join('\n');
}

// ---- SonicWall XML（<6.2，6.2+ 已停用 XML 匯出，見 firewall_analyzer SonicWallParser 同一限制）----
function anonSonicWall(text, opts) {
  // 標籤清單依 firewall_analyzer SonicWallParser 已驗證的真實欄位命名（parseDeviceInfo/parseSnmp/
  // parseInterfaces/parseRoutes/parseVPN/parseNAT），非憑空猜測
  function replaceTag(t, tag, newVal) {
    return t.replace(new RegExp(`(<${tag}>)[^<]*(<\\/${tag}>)`, 'g'), `$1${newVal}$2`);
  }
  function replaceTagIP(t, tag, opts2) {
    return t.replace(new RegExp(`(<${tag}>)([^<]+)(<\\/${tag}>)`, 'g'), (m, o, val, c) =>
      o + replaceIPsInLine(val.trim(), opts2) + c);
  }
  if (opts.hostname) {
    for (const tag of ['DeviceName', 'HostName', 'Hostname']) {
      text = text.replace(new RegExp(`(<${tag}>)([^<]*)(<\\/${tag}>)`, 'g'), (m, o, n, c) => o + anonHostname(n.trim(), 'fw', opts) + c);
    }
  }
  for (const tag of ['Community', 'ROCommunity', 'TrapCommunity']) {
    const before = text;
    text = replaceTag(text, tag, 'REDACTED_COMMUNITY');
    if (text !== before) stats.community++;
  }
  if (opts.ip) {
    // 標籤清單經 SonicWallParser 全部 parse* 函式的 gv() 呼叫逐一交叉比對，涵蓋
    // Interfaces/AddressObjects/Routes/NAT/VPN/DHCP/DNS/SNMP trap 各區塊出現過的別名
    for (const tag of ['IPAddress', 'IpAddress', 'IP', 'Gateway', 'PrimaryGateway', 'PrimaryPeer',
                        'RemoteGateway', 'PeerIP', 'LocalNetwork', 'LocalSubnet', 'RemoteNetwork', 'RemoteSubnet',
                        'Destination', 'DestNetwork', 'StartIP', 'StartIp', 'EndIP', 'EndIp',
                        'DNS1', 'DNS2', 'PrimaryDNS', 'SecondaryDNS',
                        'TranslatedSource', 'PublicIP', 'MappedIP',
                        'Server', 'ServerIP', 'AcceptedHost',
                        'TrapServer1', 'TrapServer2', 'TrapServer3', 'TrapServer']) {
      text = replaceTagIP(text, tag, opts);
    }
    // 白名單外的元素（NAT TranslatedDestination、WAN 監控 Target 等）補掃
    text = replaceIPsInXmlText(text, opts);
  }
  // 本機帳號與群組成員（標籤依 SonicWallParser.parseUsers()：User／LocalUser／UserEntry 的
  // Name／UserName／Email，UserGroup／UserGroupEntry 的 Member／MemberName）；原本完全未處理
  if (opts.user) {
    text = text.replace(/<(User|LocalUser|UserEntry)>([\s\S]*?)<\/\1>/g, (m, tag, body) =>
      `<${tag}>` + body.replace(/(<(Name|UserName)>)([^<]+)(<\/\2>)/g, (mm, o, t2, n, c) => o + anonUser(n.trim()) + c)
        .replace(/(<(Email|EmailAddress)>)([^<]+)(<\/\2>)/g, (mm, o, t2, e, c) => o + anonEmail(e.trim()) + c) + `</${tag}>`);
    text = text.replace(/<(UserGroup|UserGroupEntry)>([\s\S]*?)<\/\1>/g, (m, tag, body) =>
      `<${tag}>` + body.replace(/(<(Member|MemberName)>)([^<]+)(<\/\2>)/g, (mm, o, t2, n, c) => o + anonKnownUser(n.trim()) + c) + `</${tag}>`);
  }
  if (opts.mac) text = replaceMACsInLine(text, opts);
  // 已知缺口：官方 .exp 匯出是否包含管理者密碼／VPN 預先共用金鑰(PSK)／RADIUS-TACACS 密鑰
  // 的明碼欄位，目前查無官方文件或真實 fixture 佐證——SonicWallParser 的 parseVPN()／
  // parseUsers() 皆未解析任何此類欄位。故本函式不對特定標籤做金鑰遮蔽，避免重演「憑空
  // 猜測標籤名稱、事後被真實資料打臉」的既有教訓，待未來取得真實範例再補上。
  // OSPF/BGP MD5 認證金鑰（2026-08-24 查證後排除）：SonicOS Advanced Routing Services 官方
  // 文件確認 OSPF 認證類型可設為 MD5、CLI 模組（route ars-ospf 等）存在，但查無任何官方文件
  // 揭露實際 CLI 指令或 .exp 匯出的欄位名稱；BGP MD5 認證在現行 SonicOS 版本是否支援也查無
  // 可信來源確認。無真實範例可比對，比照上述既有原則不猜測新增規則。
  return text;
}

// ---- MikroTik RouterOS ----
function anonMikroTik(text, opts) {
  const lines = text.split('\n');
  const out = [];
  let inSystemIdentity = false, inSnmpCommunity = false, inUser = false, inLteApn = false;

  for (let line of lines) {
    const t = line.trim();
    if (/^\//.test(t)) inLteApn = /^\/interface\s+lte\s+apn\s*$/.test(t);
    // 追蹤 /system identity 區塊
    if (/^\/system\s+identity\s*$/.test(t)) { inSystemIdentity = true; inSnmpCommunity = false; inUser = false; }
    else if (/^\/snmp\s+community\s*$/.test(t)) { inSnmpCommunity = true; inSystemIdentity = false; inUser = false; }
    else if (/^\/user\s*$/.test(t)) { inUser = true; inSystemIdentity = false; inSnmpCommunity = false; }
    else if (/^\//.test(t)) { inSystemIdentity = false; inSnmpCommunity = false; inUser = false; }

    // Hostname: 單行 /system identity set name=xxx，或區塊內的 set name=
    if (opts.hostname) {
      line = line.replace(/^(\/system\s+identity\s+set\s+name=)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
      if (inSystemIdentity) {
        line = line.replace(/^(set\s+name=)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
      }
    }
    // User: /user add name=xxx password=yyy
    // 2026-09-22 修復：原本 (\s+.+\s+password=) 要求 name= 與 password= 之間至少有 1 個額外
    // 欄位，但官方 /ppp secret 匯出常見依字母序排列屬性（local-address/name/password/
    // remote-address/service），name= 之後常常緊接 password=（中間無其他欄位），此時原正則
    // 完全不命中、使用者名稱明碼外洩（密碼仍會被下方通用 password= 正則遮蔽）。改用非固定
    // 欄位數寫法（(?:\s+\S+)* 允許 0 個或多個中介欄位），兩種格式皆可正確命中。
    if (opts.user) {
      // 有 user= 欄位的行（/interface lte apn、pppoe-client、l2tp／ovpn／sstp-client 等），帳號在 user=，
      // name= 是介面或設定檔名稱（2026-10-02，第 13 輪：原本把 name= 當帳號換掉，user= 的真正帳號反而原樣留下）
      if (/(?<![\w.-])user=/.test(line)) line = line.replace(/(?<![\w.-])user=("([^"]*)"|\S+)/, (m, all, q) => 'user=' + (q !== undefined ? '"' + anonUser(q) + '"' : anonUser(all)));
      else line = line.replace(/\bname=(\S+)((?:\s+\S+)*\s+password=)(\S+)/, (m, n, mid, h) => 'name=' + anonUser(n) + mid + 'REDACTED_PASSWORD');
      // /user 區塊的帳號（RouterOS 匯出不含密碼，原本因沒有 password= 而整筆未處理）
      if (inUser) line = line.replace(/^(\s*add\s+(?:.*\s)?name=)(\S+)/, (m, p, n) => p + (/^user-\d{3}$/.test(n) ? n : anonUser(n)));
    }
    // 行動網路 APN（2026-10-02，第 13 輪）：企業專用 APN 常含公司網域（如 internet.acme-corp），
    // 比照 SSID 歸在主機名稱選項下；/interface lte apn 區塊的 name= 是 APN 設定檔名稱，
    // 與 /interface lte 的 apn-profiles= 引用同一個名稱，三處用同一份對照保持一致
    if (opts.hostname) {
      line = line.replace(/(?<![\w.-])(apn=)("[^"]*"|\S+)/, (m, p, v) => p + anonHostname(v.replace(/^"|"$/g, ''), 'apn', opts))
        .replace(/(?<![\w.-])(apn-profiles=)(\S+)/, (m, p, v) => p + v.split(',').map(x => anonHostname(x, 'apn', opts)).join(','));
      if (inLteApn) line = line.replace(/^(\s*(?:add|set)\s+(?:.*\s)?name=)("[^"]*"|\S+)/, (m, p, v) => p + anonHostname(v.replace(/^"|"$/g, ''), 'apn', opts));
    }
    // comment= 備註（2026-10-02，第 13 輪：原本未處理，規則／介面備註常含公司或地點名稱）
    if (opts.comments) {
      const cmR = line.replace(/(?<![\w.-])comment=("[^"]*"|\S+)/g, 'comment="REDACTED_COMMENT"');
      if (cmR !== line) { stats.comment++; line = cmR; }
    }
    // 全域比對（2026-10-01）：/snmp community 同一行有 authentication-password= 與 encryption-password=，
    // 原本只替換第一個
    const pR = line.replace(/\bpassword=(\S+)/g, 'password=REDACTED_PASSWORD');
    if (pR !== line) { stats.password++; line = pR; }
    // PSK / IPsec
    // 另含無線 security-profiles 的 wpa-pre-shared-key=／wpa2-pre-shared-key=（原本未遮蔽）
    // 另含 RouterOS v7 /interface wifi 的 security.passphrase=
    const pskR = line.replace(/\b((?:wpa2?-)?pre-?shared-key=|(?:security\.)?passphrase=)("[^"]*"|\S+)/g, '$1REDACTED_PSK');
    if (pskR !== line) { stats.key++; line = pskR; }
    // SSID：舊版 /interface wireless 的 ssid=、v7 /interface wifi 的 configuration.ssid=（比照 FortiGate VAP 歸在主機名稱選項下）
    if (opts.hostname) line = line.replace(/((?<![\w-])(?:configuration\.)?ssid=)("([^"]*)"|([^\s"]+))/g, (m, p, all, q, b) => p + (q !== undefined ? '"' + anonSSID(q) + '"' : anonSSID(b)));
    const secR = line.replace(/\bsecret=(\S+)/, 'secret=REDACTED_KEY');
    if (secR !== line) { stats.key++; line = secR; }
    // OSPF/BGP MD5 認證金鑰（2026-08-24 新增，官方文件 authentication-key／tcp-md5-key 皆標記
    // [sensitive]）：/routing ospf interface-template ... authentication-key=VALUE；
    // /routing bgp connection ... tcp-md5-key=VALUE
    const routeKeyR = line.replace(/\bauthentication-key=(\S+)/, 'authentication-key=REDACTED_KEY').replace(/\btcp-md5-key=(\S+)/, 'tcp-md5-key=REDACTED_KEY');
    if (routeKeyR !== line) { stats.key++; line = routeKeyR; }
    // SNMP community：/snmp community set 0 name=VALUE（單行）
    const comR = line.replace(/(\/snmp\s+community\s+\S+\s+name=)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    // 區塊模式：/snmp community 後跟 set [N] name=VALUE
    if (inSnmpCommunity) {
      // 真實 /export 為 `set [ find default=yes ] … name=public`、`add addresses=… name=X`，name= 不一定緊接 set
      const comR2 = /^(?:set|add)\s/.test(line) ? line.replace(/\b(name=)("[^"]*"|\S+)/, '$1REDACTED_COMMUNITY') : line;
      if (comR2 !== line) { stats.community++; line = comR2; }
    }
    // IPv4 in key=value (address=, gateway=, etc.) - handle separately before generic replaceIPsInLine
    if (opts.ip) {
      line = line.replace(/\b(address|gateway|dns-server|ntp-server|peer|server)=([\d.]+)(\/\d+)?/g, (m, key, ip, pfx = '') => {
        if (!isValidIPv4(ip) || classifyIP(ip) === 'skip') return m;
        return `${key}=${anonIP(ip, opts)}${pfx}`;
      });
      // 其餘 IPv4（不含 key=value 格式）＋ IPv6（如 /ipv6 address／/ipv6 dns 等，key=value 格式
      // 未特別處理故需交給共用 helper 掃描整行才不會遺漏）
      line = replaceIPsInLine(line, opts);
    }
    if (opts.mac) line = replaceMACsInLine(line, opts);
    out.push(line);
  }
  return out.join('\n');
}

// ---- Zyxel USG/ATP (ZLD) ----
// 2026-07-30 新增。ZLD 是 flat CLI（configure terminal 進 Global Config，非 XML），比照
// anonMikroTik() 逐行處理慣例。hostname 用 "hostname X"（Global Config 單行）；secure-policy
// 規則本身只引用 address-object/service-object「名稱」不含明碼值，真正含 IP 的是
// address-object 定義行本身（`address-object NAME VALUE`，VALUE 可能是單一 IP／範圍／
// 子網），交由下方通用 replaceIPsInLine() 逐行掃描即可正確涵蓋，不需要額外的欄位級正則
// （與 MikroTik 的 key=value 格式不同，Zyxel 是裸值不需要 key= 前綴比對）。
// 管理者密碼／VPN PSK（2026-08-31 新增，官方 Zyxel 文件二次查證後推翻先前「不猜測」保留
// 態度）：管理者密碼語法直接對應 CLAUDE.md 已記載的 Users 語法本身（`username NAME
// [nopassword|password PW] user-type ...`，Zyxel Support Campus 官方 KB 逐字確認建立/
// 修改管理員帳號的完整指令序列 `username <username> password <password> user-type
// admin`）；VPN PSK 官方 Zyxel Support Campus 知識庫文章（批次設定多組 IPSec VPN 的
// pre-shared key 教學）確認容器與關鍵字為 `isakmp policy <name>` 子模式內的裸
// `keystring <value>`。與 OSPF/BGP 金鑰同樣錨定具體關鍵字，不泛用掃描。
function anonZyxel(text, opts) {
  const lines = text.split('\n');
  const out = [];
  for (let line of lines) {
    if (opts.hostname) {
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
    }
    // OSPF/BGP MD5 認證金鑰（2026-08-24 新增，官方 ZLD CLI Reference Guide Ch.18.2/18.3 查證）：
    // interface `ip ospf message-digest-key <id> md5 <password>`／area `authentication
    // message-digest-key <id> md5 <authkey>`／virtual-link 同款語法；BGP `neighbor <ip>
    // password <password>`。與其他欄位不同，此為本函式目前唯一新增的機敏欄位規則（parser
    // 未解析的其餘欄位仍維持既有「不猜測」原則不處理，見上方函式註解）
    const ospfKeyR = line.replace(/^(\s*(?:ip\s+ospf|\[no\]\s+area\s+\S+(?:\s+virtual-link\s+\S+)?\s+authentication)\s+message-digest-key\s+\d+\s+md5\s+)\S+/, '$1REDACTED_KEY');
    if (ospfKeyR !== line) { stats.key++; line = ospfKeyR; }
    const bgpKeyR = line.replace(/^(\s*(?:\[no\]\s+)?neighbor\s+\S+\s+password\s+)\S+/, '$1REDACTED_KEY');
    if (bgpKeyR !== line) { stats.key++; line = bgpKeyR; }
    // 管理者密碼（2026-08-31 新增）：`username NAME password PW user-type ...`
    const pwR = line.replace(/^(\s*username\s+\S+\s+password\s+)\S+/, '$1REDACTED_PASSWORD');
    if (pwR !== line) { stats.password++; line = pwR; }
    // 帳號名稱（原本只遮密碼，帳號名稱原樣留在輸出中）
    if (opts.user) line = line.replace(/^(\s*username\s+)(\S+)(?=\s+(?:password|nopassword|user-type)\b)/, (m, p, n) => p + anonUser(n));
    // VPN PSK（2026-08-31 新增）：`isakmp policy NAME` 子模式內裸 `keystring VALUE`
    const pskR = line.replace(/^(\s*keystring\s+)\S+$/, '$1REDACTED_PSK');
    if (pskR !== line) { stats.key++; line = pskR; }
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    out.push(line);
  }
  return out.join('\n');
}

// ---- EdgeRouter (Ubiquiti EdgeOS) ----
// 2026-08-01 新增。config.boot 是巢狀大括號格式（非扁平 CLI／非 key=value），比照
// anonZyxel() 逐行處理慣例：hostname 巢狀在 system{} 區塊內（"    host-name X"，非頂層裸
// 指令，故正則需容許前導空白）；firewall rule 的 source/destination address、NAT 的
// address/inside-address/outside-address、static route 的 next-hop 皆為裸值 IP/CIDR，
// 交由下方通用 replaceIPsInLine() 逐行掃描即可正確涵蓋，不需要額外的欄位級正則。
// 管理者密碼／VPN PSK（2026-08-31 新增，官方文件二次查證後推翻先前「不猜測」保留態度）：
// 管理者密碼官方 EdgeOS 文件確認即時輸入用 `authentication plaintext-password SECRET`，
// 但 commit 後真實存進 config.boot／`show configuration` 的形式是雜湊過的
// `encrypted-password $6$...`（VyOS/EdgeOS 同源機制，真實範例已交叉確認），兩種皆比照
// 既有 md5-key/password 慣例錨定整行處理；VPN PSK 官方 EdgeOS 文件確認站對站 IPSec／
// L2TP remote-access 皆共用同一關鍵字 `authentication pre-shared-secret SECRET`（巢狀在
// `vpn ipsec site-to-site peer X` 或 `vpn l2tp remote-access ipsec-settings` 底下，但
// config.boot 巢狀大括號格式下該行本身只剩裸關鍵字+值，比照本函式其餘規則的既有慣例
// 直接錨定關鍵字，不需要追蹤父層區塊）。DHCP Server 等其餘欄位因 parser 端仍未解析，
// 依既有原則維持不處理。
function anonEdgeRouter(text, opts) {
  const lines = text.split('\n');
  const out = [];
  for (let line of lines) {
    if (opts.hostname) {
      line = line.replace(/^(\s*host-name\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
    }
    // OSPF/BGP MD5 認證金鑰（2026-08-24 新增，VyOS/EdgeOS 同源官方文件查證，中信心度——
    // EdgeOS 官方 CLI 手冊未直接取得，語法依產品血緣沿用 VyOS 官方文件）：巢狀大括號格式下
    // 該行僅剩裸關鍵字+值（"    md5-key VALUE"／"        password VALUE"），比照本函式
    // hostname 既有寫法容許前導空白；password 特意錨定整行僅此關鍵字，避免誤傷其他區塊
    const ospfKeyR = line.replace(/^(\s*md5-key\s+)\S+$/, '$1REDACTED_KEY');
    if (ospfKeyR !== line) { stats.key++; line = ospfKeyR; }
    const bgpKeyR = line.replace(/^(\s*password\s+)\S+$/, '$1REDACTED_KEY');
    if (bgpKeyR !== line) { stats.key++; line = bgpKeyR; }
    // 管理者密碼（2026-08-31 新增）：真實 config.boot 存的是雜湊形式 `encrypted-password`；
    // `plaintext-password` 為即時輸入指令形式，一併處理避免使用者貼上未 commit 的片段漏遮
    const encPwR = line.replace(/^(\s*encrypted-password\s+)\S+$/, '$1REDACTED_HASH');
    if (encPwR !== line) { stats.password++; line = encPwR; }
    const plainPwR = line.replace(/^(\s*plaintext-password\s+)\S+$/, '$1REDACTED_PASSWORD');
    if (plainPwR !== line) { stats.password++; line = plainPwR; }
    // VPN PSK（2026-08-31 新增）：站對站 IPSec／L2TP remote-access 共用同一關鍵字
    const pskR = line.replace(/^(\s*pre-shared-secret\s+)\S+$/, '$1REDACTED_PSK');
    if (pskR !== line) { stats.key++; line = pskR; }
    // 帳號名稱：system login 的 `user NAME {` 與 L2TP／VPN local-users 的 `username NAME {`
    if (opts.user) line = line.replace(/^(\s*(?:user|username)\s+)(\S+)(\s*\{)/, (m, p, n, c) => p + anonUser(n) + c);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    out.push(line);
  }
  return out.join('\n');
}

// ---- Cisco Business（CBS／Catalyst 1200／1300／SG）----
// 2026-10-02 新增（第十輪發想 ZE）。設定語法沿用 Cisco IOS 規則（username … password encrypted、snmp-server
// community／location／contact、description），另處理固定檔頭第 2 行的主機名稱（config-file-header 下一行），
// 與 hostname 指令用同一份對照
function anonCiscoBiz(text, opts) {
  const out = anonCiscoIOS(text, opts).split('\n');
  const i = out.findIndex(l => /^config-file-header\s*$/.test(l));
  if (opts.hostname && i >= 0 && out[i + 1] && /^\S+\s*$/.test(out[i + 1])) out[i + 1] = anonHostname(out[i + 1].trim(), 'sw', opts);
  return out.join('\n');
}

// ---- FS.com FSOS（第十六輪 PI）----
// 兩種韌體的 Oxidized 真實錄製：S3400（`! Fiberstore Co., Limited Internetwork Operating System Software`，Cisco 式語法）與
// S5850（`! FSOS Software, S5850`，介面 eth-0-N）。沿用 IOS 規則，另處理 IOS 規則沒涵蓋的寫法：
// `snmp-server community 7|8 名稱`（型別數字在前）、`snmp-server user … auth sha256 7 驗證金鑰 加密金鑰`、
// RADIUS 群組內 ` server 位址 key 7 金鑰`、show version 的 `Serial num:`／`System serial number is`、提示字元 `! 主機名稱#`
function anonFSOS(text, opts) {
  const orig = text.split('\n');
  const out = anonCiscoIOS(text, opts).split('\n');
  if (out.length !== orig.length) return out.join('\n');
  return out.map((l, i) => {
    const o = orig[i];
    if (/^snmp-server\s+community\s+[78]\s+\S+/.test(o)) { stats.community++; return o.replace(/^(snmp-server\s+community\s+[78]\s+)\S+/, '$1REDACTED_COMMUNITY'); }
    // 帳號沿用 IOS 規則換過的名稱，金鑰從原始行處理（IOS 規則會把 auth 關鍵字當成金鑰）：雜湊演算法與型別數字後接驗證金鑰、選填加密金鑰
    if (/^snmp-server\s+user\s/.test(o)) {
      const u = (l.match(/^snmp-server\s+user\s+(\S+)/) || [])[1];
      stats.key++;
      return o.replace(/^(snmp-server\s+user\s+)\S+/, (m, p) => p + (u || 'REDACTED'))
        .replace(/(\b(?:sha\d*|md5)\s+[078]\s+)\S+(\s+\S+)?/i, (m, p, k2) => p + 'REDACTED_KEY' + (k2 ? ' REDACTED_KEY' : ''))
        .replace(/\b[0-9a-fA-F]{16,}\b/g, 'REDACTED_KEY');
    }
    if (/^\s+server\s+\S+\s+.*\bkey\s+/.test(o)) { stats.key++; return l.replace(/(\bkey\s+(?:\d\s+)?)\S+/, '$1REDACTED_KEY'); }
    if (/^!\s*(?:Serial num:|System serial number is)/.test(o)) return l.replace(/(Serial num:\s*|serial number is\s+)([A-Z0-9]{6,})/i, '$1SERIAL-X');
    if (opts.hostname && /^(?:!\s*)?[\w.-]+#\s*$/.test(o)) return o.replace(/^((?:!\s*)?)([\w.-]+)(#)/, (m, p, n, h) => p + anonHostname(n, 'sw', opts) + h);
    return l;
  }).join('\n');
}

// ---- Linux netfilter（iptables-save／nft list ruleset）----
// 2026-10-02 新增（第十輪發想 ZB）。規則本身只有位址、介面、埠，沒有帳號密碼；需遮蔽的是 IP（含 --to-destination
// 位址:埠、nft 的 { 清單 } 與集合 elements）、規則備註（iptables `--comment "…"`、nft `comment "…"`）與記錄前綴
// （`--log-prefix "…"`／`log prefix "…"`，常含主機或客戶名稱，歸在備註選項）
function anonNetfilter(text, opts) {
  return text.split('\n').map(line => {
    if (opts.comments) {
      // iptables 是 `-m comment --comment "…"`（前面的 comment 是模組名稱），nft 是 `comment "…"`（一律帶引號）
      line = line.replace(/(--comment\s+)("[^"]*"|\S+)/g, (m, p) => { stats.comment++; return p + '"REDACTED_COMMENT"'; })
        .replace(/((?<![-\w])comment\s+)("[^"]*")/g, (m, p) => { stats.comment++; return p + '"REDACTED_COMMENT"'; })
        .replace(/(--log-prefix\s+|\blog\s+prefix\s+)("[^"]*"|\S+)/g, (m, p) => { stats.comment++; return p + '"REDACTED "'; });
    }
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- VyOS ----
// 2026-10-02 新增（第十輪發想 ZA）。與 EdgeOS 同為 Vyatta 語系，同時處理 config.boot（`key value`）與
// show configuration commands 的 set 指令（`… key 'value'`）兩種寫法；欄位依 vyos-1x 官方 smoketest 確認：
// system login user／encrypted-password／plaintext-password、pppoe authentication username／password、
// vpn ipsec authentication psk … secret（1.4）與 pre-shared-secret（1.3）、wireguard private-key／preshared-key、
// service snmp community（標籤名稱即 community 字串）／contact／location、OSPF md5-key、BGP password
function anonVyOS(text, opts) {
  // 值：config.boot 為裸值或雙引號，set 指令為單引號
  const V = `('[^']*'|"[^"]*"|[^\\s{}]+)`;
  const red = (line, key, rep, kind) => line.replace(new RegExp(`((?:^|\\s)${key}\\s+)${V}(\\s*)$`), (m, p, v, tail) => {
    stats[kind]++;
    const q = /^['"]/.test(v) ? v[0] : '';
    return p + q + rep + q + tail;
  });
  const swap = (line, key, fn) => line.replace(new RegExp(`((?:^|\\s)${key}\\s+)${V}`), (m, p, v) => {
    const q = /^['"]/.test(v) ? v[0] : '';
    return p + q + fn(q ? v.slice(1, -1) : v) + q;
  });
  return text.split('\n').map(line => {
    if (opts.hostname) line = swap(line, 'host-name', v => anonHostname(v, 'fw', opts));
    line = red(line, 'encrypted-password', 'REDACTED_HASH', 'password');
    line = red(line, 'plaintext-password', 'REDACTED_PASSWORD', 'password');
    line = red(line, 'password', 'REDACTED_PASSWORD', 'password');
    line = red(line, '(?:pre-shared-secret|secret)', 'REDACTED_PSK', 'key');
    line = red(line, '(?:private-key|preshared-key|md5-key|private\\s+key)', 'REDACTED_KEY', 'key');
    // show version 檔頭（Oxidized 等備份工具會一併收集）的硬體序號與 UUID
    if (opts.hostname) line = line.replace(/^(#\s*Hardware (?:S\/N|UUID):\s*)(\S.*)$/, (m, p) => { stats.hostname++; return p + 'REDACTED'; });
    // SNMP community：標籤名稱本身就是 community 字串（community X { authorization ro } 或 set … community X authorization 'ro'）
    line = line.replace(/((?:^|\s)community\s+)('[^']*'|"[^"]*"|[^\s{}]+)/, (m, p, v) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    if (opts.comments) line = red(line, '(?:contact|location)', 'REDACTED_COMMENT', 'comment');
    if (opts.user) {
      line = line.replace(/((?:^|\s)user\s+)([^\s{}'"]+)(?=\s*\{|\s+\S)/, (m, p, n) => p + (/^user-\d{3}$/.test(n) ? n : anonUser(n)));
      line = swap(line, 'username', v => /^user-\d{3}$/.test(v) ? v : anonUser(v));
    }
    if (opts.comments) line = red(line, 'description', 'REDACTED_COMMENT', 'comment');
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Netgate TNSR ----
// 2026-10-06（第十二輪 ML）新增。show configuration running cli 逐行處理：system name（主機名稱）、
// auth user 與 nacm group 的 member（帳號，同一對照）、password 行（auth user 的雜湊與 BGP neighbor
// 密碼）、snmp community community-name（欄位依 Oxidized tnsr 模型的遮蔽規則與真實錄製）、description；
// IP／MAC 交給通用替換
function anonTNSR(text, opts) {
  return text.split('\n').map(line => {
    let m;
    if (opts.hostname && (m = /^(system\s+name\s+)(\S+)\s*$/.exec(line))) return m[1] + anonHostname(m[2], 'fw', opts);
    if ((m = /^(\s*password(?:\s+\d+)?\s+)(\S.*)$/.exec(line))) { stats.password++; return m[1] + (/^\$\d\$/.test(m[2]) ? 'REDACTED_HASH' : 'REDACTED_PASSWORD'); }
    line = line.replace(/^(snmp\s+community\s+community-name\s+)(\S+)/, (x, p) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    if (opts.user) {
      line = line.replace(/^(auth\s+user\s+)(\S+)/, (x, p, n) => p + anonUser(n));
      line = line.replace(/^(\s+member\s+)(\S+)\s*$/, (x, p, n) => p + anonUser(n));
    }
    if (opts.comments && (m = /^(\s*description\s+)(\S.*)$/.exec(line))) { stats.comment++; line = m[1] + 'REDACTED_COMMENT'; }
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- OpenWrt (UCI) ----
// 2026-08-01 新增。UCI 是 package/config/option/list 的 stanza 格式，`option ipaddr
// '1.2.3.4'` 為帶引號裸值（非 key=value），比照 anonZyxel()/anonEdgeRouter() 逐行處理
// 慣例，交由下方通用 replaceIPsInLine()/replaceMACsInLine() 掃描即可正確涵蓋，不需要
// 額外的欄位級正則。hostname：parser 端（firewall_analyzer OpenWrtParser）本輪未查證
// 完整語法佐證維持空值，比照專案既有原則「parser 沒解析的欄位不猜測遮蔽」，此函式亦
// 不新增對應規則。
// 2026-08-09 補上機敏欄位規則（查證官方 openwrt.org 文件確認欄位命名）：`config
// wifi-iface` 的 `option key 'X'`（WPA/WPA2 PSK，/etc/config/wireless）與 `config
// interface` 的 `option password 'X'`（PPPoE/VPN 帳密，/etc/config/network）此前完全
// 未處理、明碼原樣輸出；`key1`~`key4`（WEP）因欄位名稱不同不受此正則影響，維持不處理
// （不猜測未查證欄位）。
// OSPF/BGP MD5 認證金鑰（2026-08-24 查證後確認架構性排除，非查證不足）：標準 OpenWrt
// 核心 UCI（/etc/config/network）本身不含任何動態路由協定，OSPF/BGP 須額外安裝 FRR／Quagga／
// BIRD 等路由daemon 套件，這些套件一律使用自己的原生設定檔格式（/etc/frr/frr.conf、
// /etc/quagga/{ospfd,bgpd}.conf，Cisco 風格文字檔），完全不在 UCI `/etc/config/*` 範圍內；
// 唯一有 UCI 包裝層的 BIRD（bird4-uci）官方文件確認其 UCI schema 沒有 BGP 密碼欄位、OSPF
// 完全不支援。與本工具既有的「OpenWrt 本機帳號管理不適用」記錄同一類情況，此工具解析的
// UCI 設定檔格式天生不涵蓋 OSPF/BGP 認證金鑰，不新增規則。
function anonOpenWrt(text, opts) {
  const lines = text.split('\n');
  const out = [];
  for (let line of lines) {
    line = line.replace(/^(\s*option\s+key\s+)(['"]?)([^'"\n]*)(\2)\s*$/, (m, p, q, v, q2) => p + q + 'REDACTED_PSK' + q2);
    // wifi-iface 的 SSID（比照 FortiGate VAP，歸在主機名稱選項下；2026-10-01 原本未處理）
    if (opts.hostname) line = line.replace(/^(\s*option\s+ssid\s+)(['"]?)([^'"\n]+)(\2)\s*$/, (m, p, q, v, q2) => p + q + anonSSID(v) + q2);
    line = line.replace(/^(\s*option\s+password\s+)(['"]?)([^'"\n]*)(\2)\s*$/, (m, p, q, v, q2) => p + q + 'REDACTED_PASSWORD' + q2);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    out.push(line);
  }
  return out.join('\n');
}

// H3C 與 HPE Comware 依明確廠牌字樣分開標示（第十一輪 KA，與 switch_analyzer comwareBrand() 同規則）；
// 去識別化規則兩者相同，只影響畫面上的廠牌名稱
function vendorBrandLabel(vendor, text) {
  if (vendor !== 'comware') return '';
  const t = String(text || '');
  const h3c = /\bH3C Comware\b|New H3C Technologies|^\s*sysname\s+H3C\s*$|cloud-management (?:server|backup-server) domain\s+\S*h3c/im.test(t);
  const hpe = /\bHPE? Comware\b|Hewlett[- ]Packard|^\s*sysname\s+HPE?\s*$/im.test(t);
  return h3c && !hpe ? 'H3C Comware' : hpe && !h3c ? 'HPE Comware' : '';
}
// ---- H3C／HPE Comware ----
function anonComware(text, opts) {
  const lines = text.split('\n');
  const sysnames = [...text.matchAll(/^\s*sysname\s+(\S+)/gm)].map(m => m[1]);
  const out = [];
  let inLocalUser = false, currentUser = null;

  for (let line of lines) {
    const t = line.trim();
    // local-user <name> starts a user block
    const luMatch = t.match(/^local-user\s+(\S+)/);
    if (luMatch) { inLocalUser = true; currentUser = luMatch[1]; }
    if (t === '#' || (inLocalUser && /^(?:local-user|interface|vlan|ip\s+route|ospf|bgp)\s/.test(t) && !luMatch)) {
      inLocalUser = false; currentUser = null;
    }

    if (opts.hostname) {
      // Comware 設定行有前導空格，以 \s* 兼容
      line = line.replace(/^(\s*sysname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
      // 連同指令輸出一起貼上時，提示字元 <主機名稱>／[主機名稱…] 也含主機名稱（2026-10-05，KA 測試發現）
      line = line.replace(/^<([^>\s]+)>/, (m, n) => '<' + anonHostname(n, 'sw', opts) + '>');
      if (sysnames.length) line = line.replace(/^\[([^\]\s]+)\]/, (m, n) => { const h = sysnames.find(x => n === x || n.startsWith(x + '-')); return h ? '[' + anonHostname(h, 'sw', opts) + n.slice(h.length) + ']' : m; });
    }
    if (opts.user && luMatch) {
      line = line.replace(/^(\s*local-user\s+)(\S+)/, (m, p, n) => p + anonUser(n));
    }
    // Passwords inside user context（cipher / hash / simple 三種格式）
    const pR = line.replace(/^(\s+password\s+(?:cipher|hash|simple)\s+)(\S+)/, '$1REDACTED_HASH');
    if (pR !== line) { stats.password++; line = pR; }
    // key cipher / shared-key cipher — 允許出現在行中間（如 primary authentication IP port key cipher VALUE）
    // 2026-10-01：radius／hwtacacs scheme 視圖的 `key {authentication|accounting|authorization} {cipher|simple} VALUE`
    // （Comware V7）原本只認 `key cipher`，用途關鍵字與明碼 simple 格式皆漏遮
    const kR = line.replace(/\b((?:key|shared-key)\s+(?:(?:authentication|accounting|authorization)\s+)?(?:cipher|simple)\s+)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    // community-name cipher/plain（snmp-agent community string in user/snmp context）
    const comNameR = line.replace(/^(\s+community-name\s+(?:cipher|plain)\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comNameR !== line) { stats.community++; line = comNameR; }
    // snmp-agent community read|write [simple|cipher] 名稱（2026-10-09 修正：display current-configuration 行首縮排一格、
    // V7 的 simple／cipher 關鍵字與雙引號名稱原本都會讓名稱漏遮或結尾引號遺失，真實範例 HPE 5720 即漏遮）
    const snmpComR = line.replace(/^(\s*snmp-agent\s+community\s+(?:read|write|read-write)\s+(?:(?:simple|cipher)\s+)?)("[^"]*"|\S+)/, (m, p, c) => { stats.community++; return p + (c[0] === '"' ? '"REDACTED_COMMUNITY"' : 'REDACTED_COMMUNITY'); });
    if (snmpComR !== line) line = snmpComR;
    // target-host 的 securityname：v1／v2c 即 community 名稱，v3 為 SNMPv3 使用者
    const thR = line.replace(/^(\s*snmp-agent\s+target-host\b.*?\bsecurityname\s+)(\S+)/, (m, p, n) => p + (/\bv3\b/.test(line) ? (opts.user ? anonUser(n) : n) : 'REDACTED_COMMUNITY'));
    if (thR !== line) { stats.community++; line = thR; }
    // snmp-agent usm-user：auth/priv 密碼
    if (/^\s*snmp-agent\s+usm-user/.test(line)) {
      line = line.replace(/(\bauth\s+\S+\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
      line = line.replace(/(\bpriv\s+\S+\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
      // 不帶引號格式
      line = line.replace(/(\bauth\s+\S+\s+)(\S+)(\s+priv)/, '$1REDACTED_KEY$3');
      line = line.replace(/(\bpriv\s+\S+\s+)(\S+)$/, '$1REDACTED_KEY');
      // V7 語法 `{cipher|simple} authentication-mode sha PW privacy-mode aes128 PW`
      line = line.replace(/(\bauthentication-mode\s+\S+\s+)(\S+)/, '$1REDACTED_KEY');
      line = line.replace(/(\bprivacy-mode\s+\S+\s+)(\S+)/, '$1REDACTED_KEY');
      stats.key++;
    }
    // super password [role R] {hash|simple|cipher} VALUE（切換角色用密碼）
    const superR = line.replace(/^(\s*super\s+password\s+(?:role\s+\S+\s+)?(?:hash|simple|cipher)\s+)(\S+)/, '$1REDACTED_HASH');
    if (superR !== line) { stats.password++; line = superR; }
    const authR = line.replace(/^(\s+authentication-string\s+cipher\s+)(\S+)/, '$1REDACTED_HASH');
    if (authR !== line) { stats.password++; line = authR; }
    // OSPF/BGP MD5 認證金鑰（2026-08-24 新增，官方 H3C OSPF/BGP Commands 查證，高信心度）：
    // `ospf authentication-mode {hmac-md5|md5} <key-id> {cipher|plain} <VALUE>`（area 或
    // interface 視圖）；BGP `peer <ip> password {cipher|simple} <VALUE>`；兩者皆非本檔案既有
    // `key cipher`/`password cipher|hash|simple` 泛用規則能命中的形狀（前者關鍵字是 key-id
    // 數字而非字面 key、後者非行首緊接 password），需獨立規則
    const ospfKeyR = line.replace(/^(\s*ospf\s+authentication-mode\s+(?:hmac-md5|md5)\s+\d+\s+(?:cipher|plain)\s+)\S+/, '$1REDACTED_KEY');
    if (ospfKeyR !== line) { stats.key++; line = ospfKeyR; }
    const bgpKeyR = line.replace(/^(\s*peer\s+\S+\s+password\s+(?:cipher|simple)\s+)\S+/, '$1REDACTED_KEY');
    if (bgpKeyR !== line) { stats.key++; line = bgpKeyR; }
    // IRF member serial numbers: "irf member N serial-number VALUE"
    const irf_sn = line.replace(/^(\s*irf\s+member\s+\d+\s+serial-number\s+)(\S+)/i, '$1SERIAL-X');
    if (irf_sn !== line) { stats.key++; line = irf_sn; }

    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    out.push(line);
  }
  return out.join('\n');
}

// ---- Cisco IOS / IOS-XE ----
// Cisco 語系共用機敏欄位（2026-09-29 QA）：實測 Cisco IOS 設定有 20 種機敏值原本以明碼殘留。
// 語法依 Cisco 官方命令參考確認（HSRP standby authentication、snmp-server host、IKEv2 keyring
// pre-shared-key local/remote 等）。Arista／Ruijie／Planet／NX-OS 同為 Cisco 風格指令，一併套用；
// 該廠牌沒有的語法不會命中，只會多遮不會少遮。回傳處理後的行
const CISCO_STYLE_SECRET_RULES = [
  // line con/vty/aux 等區塊內的 password（可帶加密等級 0/5/7）
  { re: /^(\s+password\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_PASSWORD', stat: 'password' },
  // key chain 內的 key-string
  { re: /^(\s+key-string\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
  // tacacs-server／radius-server host 行內金鑰
  { re: /^((?:tacacs-server|radius-server)\s+host\s+\S+.*?\s+key\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
  // aaa group server 內的 server-private ... key
  { re: /^(\s*server-private\s+\S+.*?\s+key\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
  // Arista 寫法 `md5 7 VALUE`（型別在值前）；Cisco IOS 是 `md5 VALUE 7`（型別在值後），單一數字跳過不影響後者
  { re: /^(ntp\s+authentication-key\s+\d+\s+md5\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
  // HSRP／VRRP 認證：md5 key-string、text、舊版不帶關鍵字的純字串（md5 key-chain 為名稱，不遮）
  { re: /^(\s+(?:standby|vrrp)\s+(?:\d+\s+)?authentication\s+(?:md5\s+key-string\s+(?:\d\s+)?|text\s+))(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
  { re: /^(\s+(?:standby|vrrp)\s+(?:\d+\s+)?authentication\s+)(?!md5\b|text\b)(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
  // crypto keyring／IKEv2 keyring 的預先共用金鑰
  { re: /^(\s+pre-shared-key\s+(?:(?:local|remote)\s+|address\s+\S+(?:\s+\S+)?\s+key\s+|hostname\s+\S+\s+key\s+)?(?:\d\s+)?)(\S+)/, tag: 'REDACTED_PSK', stat: 'key' },
  { re: /^(\s+ppp\s+chap\s+password\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_PASSWORD', stat: 'password' },
  { re: /^(\s+ppp\s+pap\s+sent-username\s+\S+\s+password\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_PASSWORD', stat: 'password' },  // 以下原本只寫在 anonCiscoIOS()，Arista／Ruijie／Planet／NX-OS 各自的函式缺漏，改為共用
  // sha512：Arista `enable password sha512 $6$…`
  { re: /^(enable\s+(?:secret|password)\s+(?:level\s+\d+\s+)?(?:\d\s+|sha512\s+)?)(\S+)/, tag: 'REDACTED_HASH', stat: 'password' },
  { re: /^(username\s+\S+\s+.*?\b(?:secret|password)\s+(?:(?:\d|encrypted)\s+)?)(\S+)/, tag: 'REDACTED_HASH', stat: 'password' },
  { re: /^((?:tacacs-server|radius-server)\s+key\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
  { re: /^(\s+key\s+(?:\d\s+)?)([A-Za-z]\S*)$/, tag: 'REDACTED_KEY', stat: 'key' },
  { re: /^(crypto\s+isakmp\s+key\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_PSK', stat: 'key' },
  { re: /^(\s*ip\s+ospf\s+(?:authentication-key|message-digest-key\s+\d+\s+md5)\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
  { re: /^(\s+neighbor\s+\S+\s+password\s+(?:\d\s+)?)(\S+)/, tag: 'REDACTED_PASSWORD', stat: 'password' },
  { re: /^(snmp-server\s+user\s+.*?\bauth\s+\S+\s+)(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
  { re: /^(snmp-server\s+user\s+.*?\bpriv\s+\S+(?:\s+\d+)?\s+)(\S+)/, tag: 'REDACTED_KEY', stat: 'key' },
];
function anonCiscoStyleSecrets(line, opts) {
  // 已被廠牌函式遮蔽（REDACTED_*）的值不再處理，避免統計重複計數
  for (const r of CISCO_STYLE_SECRET_RULES) {
    line = line.replace(r.re, (m, pre, tok) => {
      if (tok.startsWith('REDACTED')) return m;
      stats[r.stat]++;
      return pre + r.tag;
    });
  }
  // snmp-server host：v1/v2c 時該位置是 community；v3 時是帳號名稱
  line = line.replace(/^(snmp-server\s+host\s+\S+\s+(?:vrf\s+\S+\s+)?(?:informs\s+|traps\s+)?(version\s+(?:1|2c|3\s+(?:auth|noauth|priv))\s+)?)(\S+)/, (m, pre, ver, tok) => {
    if (ver && /version\s+3/.test(ver)) return opts.user ? pre + anonUser(tok) : m;
    stats.community++;
    return pre + 'REDACTED_COMMUNITY';
  });
  // SNMPv3 使用者帳號名稱
  if (opts.user) line = line.replace(/^(snmp-server\s+user\s+)(\S+)/, (m, p, n) => p + anonUser(n));
  // PPP PAP 傳送的帳號名稱
  if (opts.user) line = line.replace(/^(\s+ppp\s+pap\s+sent-username\s+)(\S+)/, (m, p, n) => p + anonUser(n));
  return line;
}
function anonCiscoIOS(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    // 設定檔開頭 `! Last configuration change at … by 帳號`／`! NVRAM config last updated at … by 帳號`
    // 會帶出最後修改者的帳號名稱，原本未處理
    if (opts.user) {
      line = line.replace(/^(!\s*(?:Last configuration change|NVRAM config last updated)\b.*\bby\s+)(\S+)/, (m, p, n) => p + anonUser(n));
    }
    // enable secret/password
    const enR = line.replace(/^(enable\s+(?:secret|password)\s+(?:\d+\s+)?)(\S+)/, '$1REDACTED_HASH');
    if (enR !== line) { stats.password++; line = enR; }
    // username line
    if (opts.user) {
      line = line.replace(/^(username\s+)(\S+)(\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:(?:\d+|encrypted)\s+)?)(\S+)/, (m, p, n, mid, h) => p + anonUser(n) + mid + 'REDACTED_HASH');
    } else {
      const uR = line.replace(/^(username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:(?:\d+|encrypted)\s+)?)(\S+)/, '$1REDACTED_HASH');
      if (uR !== line) { stats.password++; line = uR; }
    }
    // SNMP community
    const comR = line.replace(/^(snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    // BGP neighbor password
    const bgpR = line.replace(/^(\s+neighbor\s+\S+\s+password\s+(?:\d+\s+)?)(\S+)/, '$1REDACTED_PASSWORD');
    if (bgpR !== line) { stats.password++; line = bgpR; }
    // TACACS/RADIUS key（舊格式 radius-server key N VALUE + 新格式 server block）
    const kR = line.replace(/^((?:tacacs-server|radius-server)\s+key\s+(?:\d+\s+)?)(\S+)/, '$1REDACTED_KEY')
                   .replace(/^(\s+key\s+\d+\s+)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    // AAA server block 新格式：" key VALUE"（無數字前綴，僅字母開頭的 key）
    const kBlockR = line.replace(/^(\s+key\s+)([A-Za-z]\S+)$/, '$1REDACTED_KEY');
    if (kBlockR !== line) { stats.key++; line = kBlockR; }
    // isakmp key
    const isakmpR = line.replace(/^(crypto\s+isakmp\s+key\s+)(\S+)(\s+address\s+)/, '$1REDACTED_PSK$3');
    if (isakmpR !== line) { stats.key++; line = isakmpR; }
    // OSPF auth
    const ospfR = line.replace(/^(\s+ip\s+ospf\s+(?:authentication-key|message-digest-key\s+\d+\s+md5)\s+)(\S+)/, '$1REDACTED_KEY');
    if (ospfR !== line) { stats.key++; line = ospfR; }
    // SNMPv3 user 行內密碼：auth <proto> AUTH_PASS priv <proto> [N] PRIV_PASS
    if (/^snmp-server\s+user/.test(line)) {
      line = line.replace(/(\bauth\s+\S+\s+)(\S+)(?=\s)/, '$1REDACTED_KEY');
      line = line.replace(/(\bpriv\s+\S+(?:\s+\d+)?\s+)(\S+)$/, '$1REDACTED_KEY');
      stats.key++;
    }
    line = anonCiscoStyleSecrets(line, opts);
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Cisco ASA / Cisco FTD（沿用 ASA 的 Lina CLI 語法，同一函式涵蓋）----
// 語法已對照 firewall_analyzer 的 CiscoASAParser（firewall-analyzer-fixed.html 約行 9631 起）查證，
// 非臆測；ASA 沒有 enable secret，只有 enable password；VPN PSK 有三種語法（ikev1/ikev2/舊版 isakmp）
function anonCiscoASA(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
    }
    // enable password（ASA 無 enable secret）
    const enR = line.replace(/^(enable\s+password\s+)(\S+)/, '$1REDACTED_HASH');
    if (enR !== line) { stats.password++; line = enR; }
    // passwd（Telnet／登入密碼，`passwd 雜湊 encrypted`；Oxidized ASA 5512 真實錄製，第十六輪 PA）
    const pwdR = line.replace(/^(passwd\s+)(\S+)/, '$1REDACTED_HASH');
    if (pwdR !== line) { stats.password++; line = pwdR; }
    // username line
    if (opts.user) {
      line = line.replace(/^(username\s+)(\S+)(\s+password\s+)(\S+)/, (m, p, n, mid) => p + anonUser(n) + mid + 'REDACTED_HASH');
    } else {
      const uR = line.replace(/^(username\s+\S+\s+password\s+)(\S+)/, '$1REDACTED_HASH');
      if (uR !== line) { stats.password++; line = uR; }
    }
    // VPN PSK：ikev1/ikev2 pre-shared-key（tunnel-group ipsec-attributes 區塊內）
    const ikePskR = line.replace(/^(\s*ikev[12]\s+(?:local-authentication\s+|remote-authentication\s+)?pre-shared-key\s+)(\S+)/, '$1REDACTED_PSK');
    if (ikePskR !== line) { stats.key++; line = ikePskR; }
    // 舊版 crypto isakmp key
    const isakmpR = line.replace(/^(crypto\s+isakmp\s+key\s+)(\S+)(\s+address\s+)/, '$1REDACTED_PSK$3');
    if (isakmpR !== line) { stats.key++; line = isakmpR; }
    // SNMP community（全域 + host 行內）
    const comR = line.replace(/^(snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    const comHostR = line.replace(/^(snmp-server\s+host\s+\S+\s+\S+\s+(?:community\s+)?)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comHostR !== line) { stats.community++; line = comHostR; }
    // SNMPv3 `snmp-server user U G v3 [encrypted] auth {md5|sha} PW priv {des|3des|aes N} PW`（2026-10-01，原本未遮蔽）
    if (/^snmp-server\s+user\s/.test(line)) {
      const v3R = line.replace(/(\bauth\s+\S+\s+)(\S+)/, '$1REDACTED_KEY').replace(/(\bpriv\s+\S+(?:\s+\d+)?\s+)(\S+)/, '$1REDACTED_KEY');
      if (v3R !== line) { stats.key++; line = v3R; }
    }
    // TACACS/RADIUS key（與 IOS 同語法）
    const kR = line.replace(/^((?:tacacs-server|radius-server)\s+key\s+(?:\d+\s+)?)(\S+)/, '$1REDACTED_KEY')
                   .replace(/^(\s+key\s+\d+\s+)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    const kBlockR = line.replace(/^(\s+key\s+)([A-Za-z]\S+)$/, '$1REDACTED_KEY');
    if (kBlockR !== line) { stats.key++; line = kBlockR; }
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Cisco NX-OS ----
function anonCiscoNXOS(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
      // 預設 VDC 名稱即主機名稱（`vdc NAME id 1`），沿用同一個對照
      line = line.replace(/^(vdc\s+)(\S+)(\s+id\s+\d+)/, (m, p, n, r) => p + anonHostname(n, 'sw', opts) + r);
    }
    if (opts.user) {
      line = line.replace(/^(username\s+)(\S+)(\s+password\s+\d+\s+)(\S+)/, (m, p, n, mid, h) => p + anonUser(n) + mid + 'REDACTED_HASH');
      line = line.replace(/^(username\s+)(\S+)(\s+role\s+)/, (m, p, n, r) => p + anonUser(n) + r);
    } else {
      const uR = line.replace(/^(username\s+\S+\s+password\s+\d+\s+)(\S+)/, '$1REDACTED_HASH');
      if (uR !== line) { stats.password++; line = uR; }
    }
    const comR = line.replace(/^(snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    const bgpR = line.replace(/^(\s+password\s+\d+\s+)(\S+)/, '$1REDACTED_PASSWORD');
    if (bgpR !== line) { stats.password++; line = bgpR; }
    // TACACS/RADIUS key：舊格式 + host inline key（radius-server host IP ... key N VALUE）
    const kR = line.replace(/^((?:tacacs-server|radius-server)\s+key\s+\d+\s+)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    const kHostR = line.replace(/^((?:radius-server|tacacs-server)\s+host\s+\S+.*?\s+key\s+\d+\s+)(\S+)/, '$1REDACTED_KEY');
    if (kHostR !== line) { stats.key++; line = kHostR; }
    // OSPF auth key（NX-OS 與 IOS 相同格式）
    const ospfR = line.replace(/^(\s+ip\s+ospf\s+(?:authentication-key|message-digest-key\s+\d+\s+md5)\s+)(\S+)/, '$1REDACTED_KEY');
    if (ospfR !== line) { stats.key++; line = ospfR; }
    // SNMPv3 user 行內密碼
    if (/^snmp-server\s+user/.test(line)) {
      line = line.replace(/(\bauth\s+\S+\s+)(\S+)(?=\s)/, '$1REDACTED_KEY');
      line = line.replace(/(\bpriv\s+\S+(?:\s+\d+)?\s+)(\S+)$/, '$1REDACTED_KEY');
      stats.key++;
    }
    line = anonCiscoStyleSecrets(line, opts);
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Juniper JunOS (set 格式 + 階層式大括號格式皆支援) ----
// 2026-07-21 查核發現：本函式原本只認 "set ..." 扁平格式，真實 SRX 常見的階層式大括號輸出
// （"system { host-name X; }"）會讓 hostname/密碼/SNMP community/PSK/認證金鑰完全不被比對到、
// 明碼輸出；比照 firewall_analyzer FW_VENDOR_SIGS.juniper 已修復的簽章落差，逐項補上無 "set"
// 前綴的等效比對。大括號格式跨行巢狀、無法單靠單行判斷完整路徑，故部分訊號（如 OSPF/RADIUS
// 的 key/secret）改用較寬鬆的關鍵字比對，寧可過度遮罩也不要漏掉真正的機敏值。
function anonJuniper(text, opts) {
  const one = line => {
    if (opts.hostname) {
      line = line.replace(/^(set\s+system\s+host-name\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'fw', opts));
      line = line.replace(/^(\s*host-name\s+)(\S+?);/, (m, p, n) => p + anonHostname(n, 'fw', opts) + ';');
    }
    if (opts.user) {
      line = line.replace(/^(set\s+system\s+login\s+user\s+)(\S+)(\s+)/, (m, p, n, r) => p + anonUser(n) + r);
      line = line.replace(/^(\s*user\s+)(\S+)(\s*\{)/, (m, p, n, r) => p + anonUser(n) + r);
    }
    // Encrypted passwords + plain-text-password
    let pR = line.replace(/^(set\s+system\s+(?:root-authentication|login\s+user\s+\S+.*?authentication)\s+(?:encrypted-password|plain-text-password)\s+)"([^"]+)"/, '$1"REDACTED_HASH"');
    if (pR === line) pR = line.replace(/^(\s*(?:encrypted-password|plain-text-password)\s+)"([^"]+)"/, '$1"REDACTED_HASH"');
    if (pR !== line) { stats.password++; line = pR; }
    // SNMP community
    let comR = line.replace(/^(set\s+snmp\s+community\s+)"?([^"\s]+)"?(\s+)/, '$1"REDACTED_COMMUNITY"$3');
    if (comR === line) comR = line.replace(/^(\s*community\s+)"([^"]+)"/, '$1"REDACTED_COMMUNITY"');
    if (comR !== line) { stats.community++; line = comR; }
    // SNMPv3 authentication-password / privacy-password
    // 設定檔實際儲存的是加密後的 authentication-key／privacy-key "$9$…"（-password 是輸入時的明碼寫法），
    // set 格式原本只認 -password（2026-10-01）
    const snmpV3R = line.replace(/(\b(?:authentication-password|privacy-password|authentication-key|privacy-key)\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
    if (snmpV3R !== line) { stats.key++; line = snmpV3R; }
    // IKE PSK
    let pskR = line.replace(/^(set\s+security\s+ike\s+.+\s+pre-shared-key\s+ascii-text\s+)"([^"]+)"/, '$1"REDACTED_PSK"');
    if (pskR === line) pskR = line.replace(/^(\s*pre-shared-key\s+ascii-text\s+)"([^"]+)"/, '$1"REDACTED_PSK"');
    if (pskR !== line) { stats.key++; line = pskR; }
    // BGP auth key
    let bgpR = line.replace(/^(set\s+protocols\s+bgp\s+.+\s+authentication-key\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
    if (bgpR === line) bgpR = line.replace(/^(\s*authentication-key\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
    if (bgpR !== line) { stats.key++; line = bgpR; }
    // OSPF auth key
    let ospfR = line.replace(/^(set\s+protocols\s+ospf\s+.+\s+key\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
    if (ospfR === line) ospfR = line.replace(/^(\s*(?:md5\s+\d+\s+)?key\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
    if (ospfR !== line) { stats.key++; line = ospfR; }
    // archive-sites 的 `"網址" password "$9$…"`（Oxidized SRX300 真實錄製，第十六輪 PA；網址內嵌帳密由 anonUrlCredentials() 處理）
    const arcR = line.replace(/(\s+password\s+)"([^"]+)"/, '$1"REDACTED_PASSWORD"');
    if (arcR !== line) { stats.password++; line = arcR; }
    // 其他路徑的 secret（`set system accounting destination radius|tacplus server 位址 secret "…"`、
    // `set access radius-server 位址 secret|preauthentication-secret "…"`；Batfish juniper 測試設定，第十七輪 QA）
    const secAnyR = line.replace(/(\b(?:secret|preauthentication-secret)\s+)"([^"]+)"/g, '$1"REDACTED_KEY"');
    if (secAnyR !== line) { stats.key++; line = secAnyR; }
    // IKE `pre-shared-key hexadecimal "…"`（現有規則只認 ascii-text）與 MACsec `pre-shared-key ckn 值 cak 值`／大括號內 `ckn 值; cak "值";`
    const hexR = line.replace(/(\bpre-shared-key\s+hexadecimal\s+)"([^"]+)"/, '$1"REDACTED_PSK"').replace(/(\bpre-shared-key\s+hexadecimal\s+)(?!")(\S+?)(;?)$/, '$1REDACTED_PSK$3');
    if (hexR !== line) { stats.key++; line = hexR; }
    const cakR = line.replace(/(\b(?:ckn|cak)\s+)("?)([^"\s;]+)\2/g, (m, p, q, v) => v.startsWith('REDACTED') ? m : p + q + 'REDACTED_KEY' + q);
    if (cakR !== line) { stats.key++; line = cakR; }
    // TACACS/RADIUS secret
    let kR = line.replace(/^(set\s+system\s+(?:tacplus|radius)-server\s+\S+\s+secret\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
    if (kR === line) kR = line.replace(/^(\s*secret\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
    if (kR !== line) { stats.key++; line = kR; }
    // Serial in show chassis hardware: "[S/N: XXXXXXXXXX]"
    const jn_sn = line.replace(/(\[S\/N:\s*)([A-Z0-9]{4,})\]/, '$1SERIAL-X]');
    if (jn_sn !== line) { stats.key++; line = jn_sn; }
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  };
  // `set groups 名稱 …`（apply-groups 用的設定群組，第十七輪 QA）：群組內的指令與頂層同一套規則
  return text.split('\n').map(line => {
    const g = line.match(/^(set\s+groups\s+\S+\s+)(\S[\s\S]*)$/);
    return g ? g[1] + one('set ' + g[2]).replace(/^set /, '') : one(line);
  }).join('\n');
}

// ---- Arista EOS ----
function anonArista(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      // 版本 banner: ! device: SW-ARISTA-01, EOS-4.26
      line = line.replace(/^(!\s*device:\s+)([^,\s]+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    if (opts.user) {
      line = line.replace(/^(username\s+)(\S+)(\s+(?:nopassword|privilege|secret|role).*?(?:sha512|5|7|0)?\s+)(\S+)$/, (m, p, n, mid, h) => {
        if (mid.includes('nopassword')) return m;
        return p + anonUser(n) + mid + 'REDACTED_HASH';
      });
    } else {
      // secret sha512 <雜湊>（Arista 標準寫法）原本只認數字型別，未勾選帳號匿名化時雜湊原樣留下
      const uR = line.replace(/^(username\s+\S+\s+.+?(?:secret|password)\s+(?:\d+|sha512)\s+)(\S+)$/, '$1REDACTED_HASH');
      if (uR !== line) { stats.password++; line = uR; }
    }
    const comR = line.replace(/^(snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    const bgpR = line.replace(/^(\s+neighbor\s+\S+\s+password\s+\d+\s+)(\S+)/, '$1REDACTED_PASSWORD');
    if (bgpR !== line) { stats.password++; line = bgpR; }
    // radius-server/tacacs-server global key（數字前綴可選）
    const kR = line.replace(/^((?:tacacs-server|radius-server)\s+key\s+(?:\d+\s+)?)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    // AAA server block 新格式：" key VALUE"（無數字前綴）
    const kBlockR = line.replace(/^(\s+key\s+)([A-Za-z]\S+)$/, '$1REDACTED_KEY');
    if (kBlockR !== line) { stats.key++; line = kBlockR; }
    const ospfR = line.replace(/^(\s+ip\s+ospf\s+(?:authentication-key|message-digest-key\s+\d+\s+md5)\s+)(\S+)/, '$1REDACTED_KEY');
    if (ospfR !== line) { stats.key++; line = ospfR; }
    // SNMPv3 user 行內密碼
    if (/^snmp-server\s+user/.test(line)) {
      line = line.replace(/(\bauth\s+\S+\s+)(\S+)(?=\s)/, '$1REDACTED_KEY');
      line = line.replace(/(\bpriv\s+\S+(?:\s+\d+)?\s+)(\S+)$/, '$1REDACTED_KEY');
      stats.key++;
    }
    line = anonCiscoStyleSecrets(line, opts);
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Aruba CX ----
function anonArubaCX(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    if (opts.user) {
      line = line.replace(/^(user\s+)(\S+)(\s+group\s+\S+\s+password\s+\S+\s+)(\S+)/, (m, p, n, mid, h) => p + anonUser(n) + mid + 'REDACTED_HASH');
      line = line.replace(/^(username\s+)(\S+)(\s+password\s+ciphertext\s+)(\S+)/, (m, p, n, mid, h) => p + anonUser(n) + mid + 'REDACTED_HASH');
    } else {
      const pR = line.replace(/^(user\s+\S+\s+group\s+\S+\s+password\s+\S+\s+)(\S+)/, '$1REDACTED_HASH')
                     .replace(/^(username\s+\S+\s+password\s+ciphertext\s+)(\S+)/, '$1REDACTED_HASH');
      if (pR !== line) { stats.password++; line = pR; }
    }
    const comR = line.replace(/^(snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    // `snmp-server host 位址 trap|inform version v2c community 名稱`（Oxidized AOS-CX 真實錄製，第十六輪 PA）
    const comHostR = line.replace(/^(snmp-server\s+host\s+\S+\s.*?\bcommunity\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comHostR !== line) { stats.community++; line = comHostR; }
    // AOS-CX 金鑰前有 ciphertext／plaintext 修飾詞，原本把修飾詞當成金鑰值、真正的值原樣留下（2026-10-01）
    const kR = line.replace(/^((?:radius-server|tacacs-server)\s+host\s+\S+\s+(?:.*?\s)?key\s+(?:ciphertext\s+|plaintext\s+)?)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    // snmpv3 user U auth sha auth-pass {ciphertext|plaintext} PW priv aes priv-pass {ciphertext|plaintext} PW
    const v3R = line.replace(/(\b(?:auth|priv)-pass\s+(?:ciphertext\s+|plaintext\s+)?)(\S+)/g, '$1REDACTED_KEY');
    if (v3R !== line) { stats.key++; line = v3R; }
    // OSPF/BGP MD5 認證金鑰（2026-08-24 新增，官方 HPE Aruba Networking AOS-CX CLI Reference
    // 查證，高信心度，官方範例逐字確認）：`ip ospf message-digest-key <id> md5
    // [ciphertext|plaintext] <key>`；`neighbor <ip|group> password [ciphertext|plaintext]
    // <password>`（config-bgp 子模式）
    const ospfKeyR = line.replace(/^(\s*ip\s+ospf\s+message-digest-key\s+\d+\s+md5\s+(?:ciphertext|plaintext)\s+)\S+/, '$1REDACTED_KEY');
    if (ospfKeyR !== line) { stats.key++; line = ospfKeyR; }
    const bgpKeyR = line.replace(/^(\s*neighbor\s+\S+\s+password\s+(?:ciphertext|plaintext)\s+)\S+/, '$1REDACTED_KEY');
    if (bgpKeyR !== line) { stats.key++; line = bgpKeyR; }
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Dell OS10 ----
function anonDellOS10(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    // 密碼型別數字改為選填（2026-10-01）：OS10 官方語法是 `username NAME password PWD role ROLE
    // [priv-lvl N]`，running-config 通常直接接 $6$ 雜湊、沒有型別數字，原本規則要求
    // `password <數字> <值>`，這種寫法整行原樣輸出；另涵蓋 OS9 `username N privilege P password T V`
    const userPwRe = /^(username\s+)(\S+)(\s+(?:privilege\s+\d+\s+)?(?:password|secret)\s+(?:\d\s+)?)(\S+)/;
    const pR = line.replace(userPwRe, (m, p, n, mid, h) => p + (opts.user ? anonUser(n) : n) + mid + 'REDACTED_HASH');
    if (pR !== line) { stats.password++; line = pR; }
    const comR = line.replace(/^(snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    // radius/tacacs host key（允許中間插入 auth-port/acct-port）
    // 型別數字（OS10 `key 9 <加密值>`／`key 0 <明碼>`）原本被當成金鑰值，真正的值原樣留下（2026-10-01）
    const kR = line.replace(/^((?:radius-server|tacacs-server)\s+host\s+\S+.*?\s+key\s+(?:\d\s+)?)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    const enR = line.replace(/^(enable\s+password\s+(?:\d\s+)?)(\S+)/, '$1REDACTED_HASH');
    if (enR !== line) { stats.password++; line = enR; }
    // OSPF/BGP MD5 認證金鑰（2026-08-24 新增，官方 Dell SmartFabric OS10 User Guide 查證）：
    // OSPF `ip ospf message-digest-key <id> md5 <key-string>`（中信心度，未查得 cipher/
    // plaintext 修飾詞是否存在，保守比對 md5 之後整段裸值）；BGP `router bgp` neighbor 子模式
    // 內裸行 `password {9 <hash>|<password>}`（中高信心度），刻意錨定行首僅 password 關鍵字，
    // 避免誤傷上方 username ... password ... 這條不同語意的規則
    const ospfKeyR = line.replace(/^(\s*ip\s+ospf\s+message-digest-key\s+\d+\s+md5\s+)\S+/, '$1REDACTED_KEY');
    if (ospfKeyR !== line) { stats.key++; line = ospfKeyR; }
    const bgpKeyR = line.replace(/^(\s*password\s+(?:9\s+)?)\S+$/, '$1REDACTED_KEY');
    if (bgpKeyR !== line) { stats.key++; line = bgpKeyR; }
    // SNMPv3 user 行內密碼
    if (/^snmp-server\s+user/.test(line)) {
      line = line.replace(/(\bauth\s+\S+\s+)(\S+)(?=\s)/, '$1REDACTED_KEY');
      line = line.replace(/(\bpriv\s+\S+(?:\s+\d+)?\s+)(\S+)$/, '$1REDACTED_KEY');
      stats.key++;
    }
    line = replaceDescLine(line, opts);
    // 檔頭 `! Dell Networking OS, Version 9.14.2.16`／`! Build: 9.14.2.16` 的版本號長得像 IPv4，維持原文
    if (opts.ip && !/^!\s*(?:Dell\b.*\bVersion\b|Build\s*:)/i.test(line)) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Extreme Networks ExtremeXOS ----
function anonExtreme(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(configure\s+sys-name\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    if (opts.user) {
      // 格式 A: create account <role> "name" encrypted "hash"（各格式互斥，避免二次映射）
      const aA = line.replace(/^(create\s+account\s+\S+\s+)"([^"]+)"(\s+encrypted\s+)"([^"]+)"/, (m, p, n, mid, h) => p + '"' + anonUser(n) + '"' + mid + '"REDACTED_HASH"');
      if (aA !== line) { line = aA; }
      // 格式 B: create account <role> <name> encrypted "hash"（未命中格式 A 才執行）
      else {
        const aB = line.replace(/^(create\s+account\s+\S+\s+)(\S+)(\s+encrypted\s+)"([^"]+)"/, (m, p, n, mid, h) => p + anonUser(n) + mid + '"REDACTED_HASH"');
        if (aB !== line) { line = aB; }
        // 格式 D: create account <role> "name" "plaintext"
        else {
          const aD = line.replace(/^(create\s+account\s+\S+\s+)"([^"]+)"\s+"([^"]+)"$/, (m, p, n, h) => { stats.password++; return p + '"' + anonUser(n) + '" "REDACTED_HASH"'; });
          if (aD !== line) { line = aD; }
          // 格式 C: create account <role> "name"（官方語法第三個 token 是帳號名稱，密碼另以
          // encrypted 或互動輸入；原本誤當成明碼密碼換成 REDACTED_HASH，多個帳號會變成同名）
          else {
            const aC = line.replace(/^(create\s+account\s+\S+\s+)"([^"]+)"$/, (m, p, n) => p + '"' + anonUser(n) + '"');
            if (aC !== line) line = aC;
          }
        }
      }
    } else {
      // encrypted 格式
      const pR = line.replace(/(encrypted\s+)"([^"]+)"/, '$1"REDACTED_HASH"');
      if (pR !== line) { stats.password++; line = pR; }
      // 格式 D: create account <role> "name" "plaintext"
      else {
        // 未勾選帳號匿名化：帳號名稱維持原樣，只遮蔽密碼
        const pD = line.replace(/^(create\s+account\s+\S+\s+"[^"]+"\s+)"([^"]+)"$/, '$1"REDACTED_HASH"');
        if (pD !== line) { stats.password++; line = pD; }
        // 格式 C（create account <role> "name"）只有帳號名稱，未勾選帳號匿名化時維持原樣
      }
    }
    // SNMP community-name（引號與非引號格式）
    const comR = line.replace(/(\bcommunity-name\s+)"?([^"\s]+)"?/, '$1"REDACTED_COMMUNITY"');
    if (comR !== line) { stats.community++; line = comR; }
    // 通用 community 替換（configure snmp add trapreceiver ... community "VALUE"）
    // 另含 `configure snmp add community {readonly|readwrite} [encrypted] "…"`（原本 readonly 擋在中間不命中）
    const comR2 = line.replace(/(\bcommunity\s+(?:(?:readonly|readwrite)\s+)?(?:encrypted\s+)?)"([^"]+)"/, '$1"REDACTED_COMMUNITY"');
    if (comR2 !== line) { stats.community++; line = comR2; }
    // SNMPv3 user auth/priv：configure snmpv3 add user ... authentication <type> "<pass>" privacy <type> "<pass>"
    if (/snmpv3.*user/.test(line)) {
      line = line.replace(/(\bauthentication\s+\S+\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
      line = line.replace(/(\bprivacy\s+\S+\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
      stats.key++;
    }
    // shared-secret（引號與非引號格式）
    // `shared-secret encrypted "…"`：原本把 encrypted 當成值（2026-10-01）
    const kR = line.replace(/(\bshared-secret\s+(?:encrypted\s+)?)"?([^"\s]+)"?/, '$1"REDACTED_KEY"');
    if (kR !== line) { stats.key++; line = kR; }
    // OSPF md5-key：configure ospf ... md5-key N "VALUE"
    const ospfR = line.replace(/(\bmd5-key\s+\d+\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
    if (ospfR !== line) { stats.key++; line = ospfR; }
    // BGP authentication（configure bgp neighbor ... authentication "VALUE"）
    const bgpR = line.replace(/(\bauthentication\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
    if (bgpR !== line) { stats.key++; line = bgpR; }
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Alcatel OmniSwitch ----
function anonAlcatel(text, opts) {
  return text.split('\n').map(line => {
    let out = line;
    if (opts.hostname) {
      out = out.replace(/^((?:->\s*)?system\s+name\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    if (opts.user) {
      // 格式 A: user <name> password <type> <hash> [read-write|read-only ...] — type = bcrypt/md5/sha256/cleartext
      out = out.replace(/^((?:->\s*)?user\s+)(\S+)(\s+password\s+(?:bcrypt|md5|sha\d+|cleartext)\s+)(\S+)/, (m, p, n, mid, h) => { stats.password++; return p + anonUser(n) + mid + 'REDACTED_HASH'; });
      // 格式 B: user <name> password <hash>（無 type keyword）
      if (!/REDACTED_HASH/.test(out)) {
        out = out.replace(/^((?:->\s*)?user\s+)(\S+)(\s+password\s+)(\S+)/, (m, p, n, mid, h) => { stats.password++; return p + anonUser(n) + mid + 'REDACTED_HASH'; });
      }
    } else {
      const pR = out.replace(/(password\s+(?:bcrypt|md5|sha\d+|cleartext)\s+)(\S+)/, '$1REDACTED_HASH')
                     .replace(/(user\s+\S+\s+password\s+)(\S+)/, '$1REDACTED_HASH');
      if (pR !== out) { stats.password++; out = pR; }
    }
    // SNMP community（含引號格式）
    // AOS Release 8 寫法 `snmp community-map "STR" user "U" {enable|disable}`（原本只認舊式 community map community-name）
    const comR = out.replace(/(snmp\s+community\s+map\s+community-name\s+)"?([^"\s]+)"?/, '$1"REDACTED_COMMUNITY"')
                    .replace(/(snmp\s+community-map\s+)"?([^"\s]+)"?/, '$1"REDACTED_COMMUNITY"')
                    // 陷阱接收端 `snmp trap receiver IP community "STR"`（alcatel_complex_test.cfg）
                    .replace(/(snmp\s+trap\s+receiver\s+\S+\s+(?:.*\s)?community\s+)"?([^"\s]+)"?/, '$1"REDACTED_COMMUNITY"');
    if (comR !== out) { stats.community++; out = comR; }
    // SNMPv3 帳號名稱（`snmp user 名稱 sha …`）比照本機帳號以同一對照替換
    if (opts.user) out = out.replace(/^((?:->\s*)?snmp\s+user\s+)("[^"]+"|\S+)/, (m, p, n) => p + (n[0] === '"' ? '"' + anonUser(n.slice(1, -1)) + '"' : anonUser(n)));
    // SNMPv3 user: snmp user <name> <auth_type> "<auth_pass>" <priv_type> "<priv_pass>"
    if (/\bsnmp\s+user\b/.test(out)) {
      out = out.replace(/(\b(?:sha|md5|sha256)\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
      out = out.replace(/(\b(?:aes|des|aes256)\s+)"([^"]+)"/, '$1"REDACTED_KEY"');
      stats.key++;
    }
    // OSPF auth-key（ip ospf interface "intf" auth-key "VALUE"）
    const ospfR = out.replace(/(\bauth-key\s+)"?([^"\s]+)"?/, '$1"REDACTED_KEY"');
    if (ospfR !== out) { stats.key++; out = ospfR; }
    // AAA radius/tacacs key
    const kR = out.replace(/(\s+key\s+)"?([^"\s]+)"?/, '$1"REDACTED_KEY"');
    if (kR !== out) { stats.key++; out = kR; }
    out = replaceDescLine(out, opts);
    if (opts.ip) out = replaceIPsInLine(out, opts);
    if (opts.mac) out = replaceMACsInLine(out, opts);
    return out;
  }).join('\n');
}

// ---- Brocade FastIron / ICX ----
function anonBrocade(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    // username <name> [privilege N] password [型別] <值>（2026-10-01 合併原格式 A／B）：原本格式 A
    // 要求型別數字、格式 B 不認型別數字，`username X password 8 $1$…`（FastIron 常見）只把型別
    // 數字 8 換掉、雜湊原樣留下，`username X privilege 4 password 明碼` 則兩條都不命中
    const pR = line.replace(/^(username\s+)(\S+)(\s+(?:privilege\s+\d+\s+)?password\s+(?:\d\s+)?)(\S+)/, (m, p, n, mid, h) => p + (opts.user ? anonUser(n) : n) + mid + 'REDACTED_HASH');
    if (pR !== line) { stats.password++; line = pR; }
    // BGP neighbor password（無數字前綴）
    const bgpR = line.replace(/^(\s+neighbor\s+\S+\s+password\s+(?:\d+\s+)?)(\S+)/, '$1REDACTED_PASSWORD');
    if (bgpR !== line) { stats.password++; line = bgpR; }
    // SNMP community
    // FastIron 加密儲存時在值前加型別數字（`snmp-server community 2 $… ro`、`key 2 $…`、
    // `enable super-user-password 8 $1$…`），原本把型別數字當成值、真正的值原樣留下（2026-10-01）
    const comR = line.replace(/^(snmp-server\s+community\s+(?:\d\s+)?)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    // radius/tacacs-server host ... [auth-port N] [acct-port N] [default] key [型別] VALUE，另含全域 key
    const kR = line.replace(/^((?:radius|tacacs)-server\s+(?:host\s+\S+.*?\s+)?key\s+(?:\d\s+)?)(\S+)/, '$1REDACTED_KEY');
    if (kR !== line) { stats.key++; line = kR; }
    const enR = line.replace(/^(enable\s+(?:super-user-password|port-config-password|read-only-password)\s+(?:\d\s+)?)(\S+)/, '$1REDACTED_HASH');
    if (enR !== line) { stats.password++; line = enR; }
    // OSPF MD5 auth
    // FastIron 寫法 `ip ospf [N] md5-authentication key-id N key [0|1|2] 金鑰`（FastIron 08.0.60 文件，2026-10-09）
    const ospfR = line.replace(/^(\s+ip\s+ospf\s+(?:authentication-key|message-digest-key\s+\d+\s+md5|(?:\d+\s+)?md-?5-authentication\s+key-id\s+\d+\s+key(?:\s+\d)?)\s+)(\S+)/, '$1REDACTED_KEY');
    if (ospfR !== line) { stats.key++; line = ospfR; }
    // SNMPv3 user 行內密碼
    if (/^snmp-server\s+user/.test(line)) {
      line = line.replace(/(\bauth\s+\S+\s+)(\S+)(?=\s)/, '$1REDACTED_KEY');
      line = line.replace(/(\bpriv\s+\S+(?:\s+\d+)?\s+)(\S+)$/, '$1REDACTED_KEY');
      stats.key++;
    }
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Generic (unknown vendor) — apply common patterns ----
// 通用模式行內敏感關鍵字（2026-09-29 補強）：未知廠牌無語法可依，改為「關鍵字出現在行內任何位置
// （前後非英數或連字號，避免 password-policy 之類設定名稱誤中）＋空白或 =／: 分隔」即遮蔽其後的值；
// 值前最多 2 個加密類型／編號代碼（如 `7`、`md5`、`1 md5`、`encrypted`）一併跳過，只遮真正的值。
// 寧可多遮：通用模式常用於回報無法解析的設定檔，漏遮的代價遠高於多遮
const GENERIC_SECRET_RE = /(^|[^\w-])(password|passwd|secret|passphrase|isakmp\s+key|pre-shared-key|pre-shared-secret|preshared-key|psk|wpa-psk|community|key-string|keystring|auth-key|authentication-key|auth-password|priv-password|api-key|token)(?![\w-])((?:\s+|\s*[=:]\s*)(?:(?:\d+|md5|sha\d*|cipher|encrypted|hash|plain|plaintext|simple|text)\s+){0,2})("[^"]*"|'[^']*'|[^\s"']+)/gi;
// 通用模式第二輪補強（2026-09-29，RA）：帳號名稱、行中描述、SNMP 位置／聯絡人、email、網域名稱。
// 網域名稱比對「至少一個點、最後一段為 2 字母以上、非常見檔案副檔名」的字串，沿用 hostname
// 對照類別（可由對照表還原）；公開網域（如 pool.ntp.org）也會被替換——通用模式寧可多遮
const GENERIC_USER_RE = /^(\s*(?:username|user-name|local-user|user)\s+)("[^"]+"|[^\s"]+)/i;
// 行內「鍵=值」帳號欄位（log 與 CEF 常見：user=／usr=／suser=／duser= 等）
const GENERIC_USER_KV_RE = /(\b(?:user|usr|username|user-name|login|account|suser|duser)=)("[^"]*"|[^\s|,;"]+)/gi;
const GENERIC_DESC_RE = /(\s(?:description|desc|remark|comment|comments|alias)(?:\s+|\s*[=:]\s*))("[^"]*"|[^"\s].*)$/i;
const GENERIC_SNMP_INFO_RE = /(\b(?:location|contact|sys-?location|sys-?contact|syslocation|syscontact)(?:\s+|\s*[=:]\s*))(.+)$/i;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const FILE_EXT_RE = /^(?:bin|img|cfg|conf|txt|log|xml|json|pkg|tar|gz|tgz|zip|exe|dll|so|py|sh|pem|crt|cer|key|lic|iso|ova|html?|js|css|swi|spk|out|dat|db)$/i;
const FQDN_RE = /(?<![\w.@-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))(?![\w.-])/g;
function anonGenericDomains(line, opts) {
  return line.replace(FQDN_RE, (m, fq, tld) => {
    if (FILE_EXT_RE.test(tld) || /^example\./i.test(fq) || /\.example$/i.test(fq)) return m;
    return anonHostname(fq, 'dom', opts);
  });
}
function anonGeneric(text, opts) {
  return text.split('\n').map(line => {
    // Generic password patterns
    const pR = line.replace(/^(\s*(?:password|passwd|secret|enable\s+secret)\s+(?:\d+\s+)?)(\S{8,})/, '$1REDACTED_HASH');
    if (pR !== line) { stats.password++; line = pR; }
    line = line.replace(GENERIC_SECRET_RE, (m, pre, kw, sep, val) => {
      if (/REDACTED/.test(val)) return m;
      if (/community/i.test(kw)) stats.community++; else stats.password++;
      const q = /^["']/.test(val) ? val[0] : '';
      return pre + kw + sep + q + 'REDACTED_SECRET' + q;
    });
    if (opts.hostname) {
      line = line.replace(/^\s*(?:hostname|sysname|system-name|switchname|device-name|set\s+hostname|set\s+system\s+host-name)\s+"?([^\s"]+)/i, (m, n) => m.replace(n, anonHostname(n, 'fw', opts)));
    }
    line = replaceDescLine(line, opts);
    if (opts.comments && !/REDACTED_COMMENT/.test(line)) {
      const d = line.replace(GENERIC_DESC_RE, (m, pre, val) => pre + (val[0] === '"' ? '"REDACTED_COMMENT"' : 'REDACTED_COMMENT'));
      if (d !== line) { stats.comment++; line = d; }
    }
    // SNMP location／contact 是實體地點與聯絡人（個人資料），比照 email 不論選項一律遮蔽
    if (/snmp|sys-?(?:location|contact)|syslocation|syscontact/i.test(line)) {
      const sn = line.replace(GENERIC_SNMP_INFO_RE, (m, pre, val) => /REDACTED/.test(val) ? m : pre + 'REDACTED_COMMENT');
      if (sn !== line) { stats.comment++; line = sn; }
    }
    if (opts.user) {
      line = line.replace(GENERIC_USER_RE, (m, pre, name) => {
        const q = name[0] === '"' ? '"' : '';
        const raw = q ? name.slice(1, -1) : name;
        return /REDACTED/.test(raw) ? m : pre + q + anonUser(raw) + q;
      });
      line = line.replace(GENERIC_USER_KV_RE, (m, pre, val) => {
        const q = val[0] === '"' ? '"' : '';
        const raw = q ? val.slice(1, -1) : val;
        return (!raw || /REDACTED/.test(raw)) ? m : pre + q + anonUser(raw) + q;
      });
    }
    // email 不論選項一律遮蔽（個人資料），在網域名稱替換之前處理，避免 email 的網域部分被拆開替換
    line = line.replace(EMAIL_RE, () => { stats.user++; return 'REDACTED_EMAIL'; });
    if (opts.hostname) line = anonGenericDomains(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ============================================================
// [5] MAIN ORCHESTRATOR
// ============================================================
// ---- Aruba ProCurve / ArubaOS-Switch ----
// 2026-07-22 對外查證真實 HPE 5412zl（KB.16.05 韌體）匯出檔後修復 3 個既有 bug：
// (1) 密碼雜湊完全沒被遮罩——原本 regex 抓 password manager/operator 後的下一個 token，
//     真實語法該 token 常是 `user-name`（子句本身，非雜湊值），導致抓錯目標，真實 SHA1
//     雜湊原樣外洩到「匿名化後」的輸出，且完全沒有處理新式 aaa authentication local-user
//     語法，雜湊值同樣外洩——皆屬安全性缺陷（憑證外洩），非僅顯示問題
// (2) SNMP community／hostname 皆用「兩個 .replace() 串接」處理有引號/無引號兩種情境，
//     但兩者無條件依序執行：第一個 regex 已正確處理有引號情境並保留引號，第二個原意是
//     「無引號時的備援」，卻會把已遮罩的字串（`"REDACTED_XXX"`）當成 \S+ 再誤配一次，
//     引號被吃掉、hostname 甚至因此重複呼叫 anonHostname() 產生多餘映射——不外洩原始值，
//     但輸出語法錯誤（真實 ArubaOS-Switch 語法字串值需要引號）。改為 if/else 互斥判斷
function anonProCurve(text, opts) {
  return text.split('\n').map(line => {
    // hostname "NAME" or hostname NAME（互斥判斷，避免已遮罩值被第二條規則二次誤配）
    if (opts.hostname) {
      if (/^hostname\s+"/.test(line)) {
        line = line.replace(/^(hostname\s+)"([^"]+)"/, (m, p, n) => `${p}"${anonHostname(n, 'sw', opts)}"`);
      } else if (/^hostname\s+\S/.test(line)) {
        line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
      }
    }
    // password manager/operator [user-name "NAME"] sha1 "HASH"：user-name 子句可省略，
    // 用非貪婪跳過任意中間內容直接鎖定 sha1 後的雜湊值本身
    const pwR = line.replace(/^(password\s+(?:manager|operator)\s+.*?sha1\s+)"?[^"\s]+"?/, (m, p) => p + '"REDACTED_HASH"');
    if (pwR !== line) { stats.password++; line = pwR; }
    // aaa authentication local-user "NAME" group "GROUP" password sha1 "HASH"（新式 AAA 本機帳號，
    // 原本完全沒有對應處理，雜湊值直接外洩）
    const aaaR = line.replace(/^(aaa authentication local-user\s+.*?sha1\s+)"?[^"\s]+"?/, (m, p) => p + '"REDACTED_HASH"');
    if (aaaR !== line) { stats.password++; line = aaaR; }
    // 帳號名稱：`password … user-name "NAME"` 與 `aaa authentication local-user "NAME"`（原本只遮雜湊）
    if (opts.user) {
      line = line.replace(/^(password\s+(?:manager|operator)\s+user-name\s+)"?([^"\s]+)"?/, (m, p, n) => p + '"' + anonUser(n) + '"')
                 .replace(/^(aaa authentication local-user\s+)"?([^"\s]+)"?/, (m, p, n) => p + '"' + anonUser(n) + '"');
    }
    // snmp-server community "STR" or bare STR（互斥判斷）
    let comR = line;
    if (/^snmp-server\s+community\s+"/.test(line)) {
      comR = line.replace(/^(snmp-server\s+community\s+)"([^"]+)"/, '$1"REDACTED_COMMUNITY"');
    } else if (/^snmp-server\s+community\s+\S/.test(line)) {
      comR = line.replace(/^(snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    }
    if (comR !== line) { stats.community++; line = comR; }
    // snmpv3 engineid "XX:XX:...:XX"：先前完全未遮罩（非刻意排除，純遺漏）。引擎 ID 本身
    // 不含使用者機敏資料，但屬裝置唯一識別碼，比照既有 MAC/序號類慣例一併遮罩
    const engR = line.replace(/^(snmpv3\s+engineid\s+)"?[0-9a-fA-F:]+"?/, (m, p) => p + '"REDACTED_ENGINEID"');
    if (engR !== line) { line = engR; }
    // radius/tacacs key：原規則寫成 `radius\s+…`，真實指令是 `radius-server host X key "…"`／
    // `tacacs-server key "…"`（帶連字號），從未命中（2026-10-01）
    const kR = line.replace(/^((?:radius|tacacs)(?:-server)?\s+(?:.*?\s)?(?:encrypted-)?key\s+)("[^"]*"|\S+)/, (m, p, v) => p + (v[0] === '"' ? '"REDACTED_KEY"' : 'REDACTED_KEY'));
    if (kR !== line) { stats.key++; line = kR; }
    // snmpv3 user "U" auth {md5|sha} "PW" priv {des|aes} "PW"（原本未遮蔽）
    if (/^snmpv3\s+user\s/.test(line)) {
      const v3R = line.replace(/(\bauth\s+\S+\s+)("[^"]*"|\S+)/, '$1"REDACTED_KEY"').replace(/(\bpriv\s+\S+\s+)("[^"]*"|\S+)/, '$1"REDACTED_KEY"');
      if (v3R !== line) { stats.key++; line = v3R; }
    }
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Planet Technology (SGS-6341 系列) ----
// hostname／帳號密碼皆沿用 Cisco 語法（switch_analyzer parsePlanetUsers 本身就是直接呼叫
// parseCiscoUsers()，非另開一套），SNMP community 落在 switch_analyzer 的通用 else 分支、
// 語法與其餘廠牌相同。無 VRRP 認證欄位佐證（資料形狀雖有 authKey 欄位但 parser 從未填值）、
// 無 VLAN 命名語法，皆不猜測不實作
function anonPlanet(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    if (opts.user) {
      line = line.replace(/^(username\s+)(\S+)(\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:\d+\s+)?)(\S+)/, (m, p, n, mid) => p + anonUser(n) + mid + 'REDACTED_HASH');
    } else {
      const uR = line.replace(/^(username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:\d+\s+)?)(\S+)/, '$1REDACTED_HASH');
      if (uR !== line) { stats.password++; line = uR; }
    }
    const comR = line.replace(/^(\s*snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    line = anonCiscoStyleSecrets(line, opts);
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Ruijie (RGOS) ----
// hostname／帳號密碼／SNMP community 與 Planet 相同（同樣沿用 Cisco 語法），額外補 BGP
// neighbor password 與 OSPF message-digest-key——switch_analyzer 的 parseRoutingAuth()
// 確認 Ruijie 走 Cisco 認證分支，語法逐字相同（非猜測）。VRRP 無認證欄位佐證，不實作
function anonRuijie(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(hostname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    if (opts.user) {
      line = line.replace(/^(username\s+)(\S+)(\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:\d+\s+)?)(\S+)/, (m, p, n, mid) => p + anonUser(n) + mid + 'REDACTED_HASH');
    } else {
      const uR = line.replace(/^(username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:\d+\s+)?)(\S+)/, '$1REDACTED_HASH');
      if (uR !== line) { stats.password++; line = uR; }
    }
    // Web 管理帳號 `webmaster level N username 帳號 password [型別] 值`（ruijie_realistic_sample2.cfg）
    line = line.replace(/^(\s*webmaster\s+level\s+\d+\s+username\s+)(\S+)(\s+password\s+(?:\d+\s+)?)(\S+)/, (m, p, n, mid) => { stats.password++; return p + (opts.user ? anonUser(n) : n) + mid + 'REDACTED_HASH'; });
    const comR = line.replace(/^(\s*snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    const bgpR = line.replace(/^(\s+neighbor\s+\S+\s+password\s+(?:\d+\s+)?)(\S+)/, '$1REDACTED_PASSWORD');
    if (bgpR !== line) { stats.password++; line = bgpR; }
    const ospfKeyR = line.replace(/^(\s*ip\s+ospf\s+message-digest-key\s+\d+\s+md5\s+)(\S+)/, '$1REDACTED_KEY');
    if (ospfKeyR !== line) { stats.key++; line = ospfKeyR; }
    line = anonCiscoStyleSecrets(line, opts);
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Netgear M4300 (ICOS) ----
// hostname 用 snmp-server sysname（非 hostname 關鍵字）；帳號密碼為 Broadcom ICOS 專屬單行
// 語法 username NAME password PASSWORD level N（與 Cisco 家族不同，關鍵字不在行首無法沿用
// 既有 replace 鏈，尾端 level N 需保留不可被吃掉）；VRRP 認證 authentication simple KEY 為
// switch_analyzer 已解析的真實欄位（rec.authKey），非猜測
function anonNetgear(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(snmp-server\s+sysname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    if (opts.user) {
      line = line.replace(/^(username\s+)(\S+)(\s+password\s+)(\S+)(\s+level\s+\d+)/, (m, p, n, mid, h, lvl) => p + anonUser(n) + mid + 'REDACTED_HASH' + lvl);
    } else {
      const uR = line.replace(/^(username\s+\S+\s+password\s+)(\S+)(\s+level\s+\d+)/, '$1REDACTED_HASH$3');
      if (uR !== line) { stats.password++; line = uR; }
    }
    const comR = line.replace(/^(\s*snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    const vrrpKeyR = line.replace(/^(\s*authentication\s+simple\s+)(\S+)/, '$1REDACTED_KEY');
    if (vrrpKeyR !== line) { stats.key++; line = vrrpKeyR; }
    line = anonIcosSecrets(line);
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Broadcom EFOS（2026-10-06，第十二輪 MM）----
// FASTPATH 系，與 Netgear／EdgeSwitch 同源但帳號與主機名稱帶引號：hostname "X"、snmp-server sysname "X"（同一假名）、
// username "帳號" password X encryption-type aes level N encrypted、snmp-server community "名稱" ro；欄位依 Oxidized 真實錄製
function anonEFOS(text, opts) {
  const q = (v, fn) => (/^".*"$/.test(v) ? '"' + fn(v.slice(1, -1)) + '"' : fn(v));
  return text.split('\n').map(line => {
    if (opts.hostname) line = line.replace(/^((?:hostname|snmp-server\s+sysname)\s+)(".*"|\S+)\s*$/, (m, p, n) => p + q(n, v => anonHostname(v, 'sw', opts)));
    line = line.replace(/^(username\s+)(".*?"|\S+)(\s+password\s+)(\S+)/, (m, p, n, mid) => { stats.password++; return p + (opts.user ? q(n, anonUser) : n) + mid + 'REDACTED_HASH'; });
    line = line.replace(/^(\s*snmp-server\s+community\s+)(".*?"|\S+)/, (m, p, c) => { stats.community++; return p + (/^"/.test(c) ? '"REDACTED_COMMUNITY"' : 'REDACTED_COMMUNITY'); });
    line = anonIcosSecrets(line);
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Netgear Smart Managed Pro（GS7xx，第十三輪 NC）----
// 語法依 Oxidized 的 GS752TPP 真實錄製：檔頭註解 `! System Name:`／`! Serial Number:`／`! MAC Address:`、
// system name／location "…"、username "…" secret encrypted …、snmp community "…" … ro、snmp host … "community"、
// snmp user "名稱" "群組" auth md5 encrypted …
function anonNetgearSmart(text, opts) {
  const q = (v, fn) => (/^".*"$/.test(v) ? '"' + fn(v.slice(1, -1)) + '"' : fn(v));
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(system\s+name\s+)(".*"|\S+)\s*$/, (m, p, n) => p + q(n, v => anonHostname(v, 'sw', opts)));
      line = line.replace(/^(!\s*System Name:\s*)(\S+)\s*$/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    line = line.replace(/^(!\s*(?:Serial Number:|SN\s*:)\s*)\S+/, '$1REDACTED_SERIAL');
    line = line.replace(/^(system\s+location\s+)(".*"|\S+)/, (m, p, v) => { stats.comment++; return p + (/^"/.test(v) ? '"REDACTED_LOCATION"' : 'REDACTED_LOCATION'); });
    line = line.replace(/^(username\s+)(".*?"|\S+)(\s+(?:secret|password)\s+(?:encrypted\s+)?)(\S+)/, (m, p, n, mid) => { stats.password++; return p + (opts.user ? q(n, anonUser) : n) + mid + 'REDACTED_HASH'; });
    line = line.replace(/^(snmp\s+community\s+)(".*?"|\S+)/, (m, p, c) => { stats.community++; return p + (/^"/.test(c) ? '"REDACTED_COMMUNITY"' : 'REDACTED_COMMUNITY'); });
    line = line.replace(/^(snmp\s+host\s+\S+.*?\bversion\s+\S+\s+)(".*?"|\S+)/, (m, p, c) => { stats.community++; return p + (/^"/.test(c) ? '"REDACTED_COMMUNITY"' : 'REDACTED_COMMUNITY'); });
    line = line.replace(/^(snmp\s+user\s+)(".*?"|\S+)(.*?\bencrypted\s+)(\S+)/, (m, p, n, mid) => { stats.key++; return p + (opts.user ? q(n, anonUser) : n) + mid + 'REDACTED_KEY'; });
    // 韌體／Loader 版本號（6.0.10.14）長得像 IP，維持原文
    if (/^!\s*(?:Firmware|Loader) Version\s*:/i.test(line)) return line;
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- NVIDIA Onyx（MLNX-OS，單行前綴式 running-config，XN156）----
// 語法依官方 Onyx User Manual：hostname、username 名稱 password [0|7] 密碼、snmp-server community 名稱、snmp-server host … 名稱、
// interface … description 文字、vlan N name "名稱"；檔頭 ## Hostname／## Product release
function anonOnyx(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(\s*hostname\s+)(\S+)\s*$/, (m, p, n) => p + anonHostname(n, 'sw', opts));
      line = line.replace(/^(##[ \t]*Hostname:[ \t]*)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    line = line.replace(/^(\s*username\s+)(\S+)(\s+password\s+(?:[07]\s+)?)(\S+)/, (m, p, n, mid) => { stats.password++; return p + (opts.user ? anonUser(n) : n) + mid + 'REDACTED_HASH'; });
    if (opts.user) line = line.replace(/^(\s*username\s+)(\S+)(\s+(?:capability|nopassword|full-name|disable)\b.*)$/, (m, p, n, rest) => p + anonUser(n) + rest);
    line = line.replace(/^(\s*snmp-server\s+community\s+)(\S+)/, (m, p) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    line = line.replace(/^(\s*snmp-server\s+host\s+(?:vrf\s+\S+\s+)?\S+\s+(?:traps|informs)\s+(?:version\s+(?:1|2c)\s+)?)(\S+)\s*$/, (m, p) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    if (opts.comments) {
      line = line.replace(/^(\s*interface\s+\S+\s+\S+\s+description\s+)(.+)$/, (m, p) => { stats.comment++; return p + 'REDACTED_DESC'; });
      line = line.replace(/^(\s*vlan\s+\d+\s+name\s+)(.+)$/, (m, p) => { stats.comment++; return p + 'REDACTED_DESC'; });
    }
    if (/^##[ \t]*(?:Product release|Version summary|Build)/i.test(line)) return line;
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Zyxel GS／XGS 交換器（ZyNOS 式 CLI，XN155）----
// 語法依官方 Ethernet Switch CLI Reference Guide：hostname、admin-password [cipher] 密碼、logins username 名稱 password [cipher] 密碼 …、
// snmp-server get-community／set-community [cipher] 名稱、VLAN 與埠的 name、ip route … name 名稱
function anonZyxelSw(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) line = line.replace(/^(\s*hostname\s+)(\S+)\s*$/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    line = line.replace(/^(\s*admin-password\s+(?:cipher\s+)?)(\S+)/, (m, p) => { stats.password++; return p + 'REDACTED_HASH'; });
    line = line.replace(/^(\s*logins\s+username\s+)(\S+)(\s+password\s+(?:cipher\s+)?)(\S+)/, (m, p, n, mid) => { stats.password++; return p + (opts.user ? anonUser(n) : n) + mid + 'REDACTED_HASH'; });
    line = line.replace(/^(\s*snmp-server\s+(?:get|set|trap)-community\s+(?:cipher\s+)?)(\S+)/, (m, p) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    // 埠名稱（interface port-channel 子模式的 name）與 VLAN 名稱比照描述處理
    if (opts.comments) line = line.replace(/^(\s+name\s+)(?!\d+\s*$)(.+)$/, (m, p) => { stats.comment++; return p + 'REDACTED_DESC'; });
    line = line.replace(/^(\s*ip\s+route\s+.*\bname\s+)(\S+)/, (m, p) => p + 'REDACTED_NAME');
    // 檔頭韌體版本（V4.90(ABPL.0)b3）不是位址
    if (/^;\s*Firmware Version/i.test(line)) return line;
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- D-Link DGS（Cisco 風格 CLI，XN154）----
// 語法依官方 DGS-1510 CLI Reference Guide：snmp-server name／location、username 帳號 [privilege N] [nopassword | password [0|7|15] 密碼]、
// enable password [level N] [0|7|15] 密碼、snmp-server community [0|7] 名稱 …、snmp-server host 位址 [version …] 名稱、description
function anonDLink(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) line = line.replace(/^(snmp-server\s+name\s+)(.+)$/, (m, p, n) => p + anonHostname(n.trim(), 'sw', opts));
    line = line.replace(/^(snmp-server\s+location\s+)(.+)$/, (m, p) => { stats.comment++; return p + 'REDACTED_LOCATION'; });
    line = line.replace(/^(username\s+)(\S+)((?:\s+privilege\s+\d+)?\s+password\s+(?:(?:0|7|15)\s+)?)(\S+)/, (m, p, n, mid) => { stats.password++; return p + (opts.user ? anonUser(n) : n) + mid + 'REDACTED_HASH'; });
    line = line.replace(/^(username\s+)(\S+)((?:\s+privilege\s+\d+)?\s+nopassword\s*)$/, (m, p, n, mid) => p + (opts.user ? anonUser(n) : n) + mid);
    line = line.replace(/^(enable\s+password\s+(?:level\s+\d+\s+)?(?:(?:0|7|15)\s+)?)(\S+)/, (m, p) => { stats.password++; return p + 'REDACTED_HASH'; });
    line = line.replace(/^(snmp-server\s+community\s+(?:[07]\s+)?)(\S+)/, (m, p) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    line = line.replace(/^(snmp-server\s+host\s+\S+(?:\s+version\s+(?:1|2c|3\s+\S+))?\s+)(\S+)/, (m, p) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    // 檔頭的韌體版本（Build 1.30.003）不是位址
    if (/^#\s*Firmware:/i.test(line)) return line;
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- TP-Link JetStream／Omada 受管交換器（XN153）----
// 語法依官方 CLI Reference Guide（Managed Switches）：hostname／location、user name 帳號 [privilege …] {password|secret} [類型] 值、
// snmp-server community 名稱 {read-only|read-write} 檢視、description（介面與 SVI）
function anonTpLink(text, opts) {
  const q = (v, fn) => (/^".*"$/.test(v) ? '"' + fn(v.slice(1, -1)) + '"' : fn(v));
  return text.split('\n').map(line => {
    if (opts.hostname) line = line.replace(/^(hostname\s+)(".*"|\S+)\s*$/, (m, p, n) => p + q(n, v => anonHostname(v, 'sw', opts)));
    line = line.replace(/^(location\s+)(".*"|\S+.*)$/, (m, p, v) => { stats.comment++; return p + (/^"/.test(v) ? '"REDACTED_LOCATION"' : 'REDACTED_LOCATION'); });
    line = line.replace(/^(user\s+name\s+)(".*?"|\S+)((?:\s+privilege\s+\S+)?\s+(?:password|secret)\s+(?:\d\s+)?)(\S+)/, (m, p, n, mid) => { stats.password++; return p + (opts.user ? q(n, anonUser) : n) + mid + 'REDACTED_HASH'; });
    line = line.replace(/^(snmp-server\s+community\s+)(".*?"|\S+)/, (m, p, c) => { stats.community++; return p + (/^"/.test(c) ? '"REDACTED_COMMUNITY"' : 'REDACTED_COMMUNITY'); });
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- Ubiquiti EdgeSwitch (ICOS) ----
// 與 Netgear 同源 Broadcom ICOS，hostname／帳號密碼語法逐字相同；EdgeSwitch 無 L3/VRRP
// 支援（switch_analyzer parser 硬編碼 vrrp:[]，裝置架構限制——VLAN Routing 邏輯介面 ID 由
// 裝置動態配置，非查證不足），故不比照 Netgear 加 VRRP 認證欄位
function anonEdgeSwitch(text, opts) {
  return text.split('\n').map(line => {
    if (opts.hostname) {
      line = line.replace(/^(snmp-server\s+sysname\s+)(\S+)/, (m, p, n) => p + anonHostname(n, 'sw', opts));
    }
    if (opts.user) {
      line = line.replace(/^(username\s+)(\S+)(\s+password\s+)(\S+)(\s+level\s+\d+)/, (m, p, n, mid, h, lvl) => p + anonUser(n) + mid + 'REDACTED_HASH' + lvl);
    } else {
      const uR = line.replace(/^(username\s+\S+\s+password\s+)(\S+)(\s+level\s+\d+)/, '$1REDACTED_HASH$3');
      if (uR !== line) { stats.password++; line = uR; }
    }
    const comR = line.replace(/^(\s*snmp-server\s+community\s+)(\S+)/, '$1REDACTED_COMMUNITY');
    if (comR !== line) { stats.community++; line = comR; }
    line = anonIcosSecrets(line);
    line = replaceDescLine(line, opts);
    if (opts.ip) line = replaceIPsInLine(line, opts);
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// Netgear／EdgeSwitch（同為 Broadcom ICOS）共用的金鑰與 enable 密碼遮蔽（2026-10-01，原本兩家皆未處理）：
// `radius server key {auth|acct} IP [encrypted] KEY`、tacacs-server host 子模式的 `key [encrypted] KEY`、
// `enable {password|passwd} [encrypted] PW`
function anonIcosSecrets(line) {
  const rules = [
    [/^(\s*radius\s+server\s+key\s+(?:auth|acct)\s+\S+\s+(?:encrypted\s+)?)(\S+)/, 'REDACTED_KEY', 'key'],
    [/^(\s+key\s+(?:encrypted\s+)?)(\S+)$/, 'REDACTED_KEY', 'key'],
    [/^(\s*enable\s+pass(?:word|wd)\s+(?:encrypted\s+)?)(\S+)/, 'REDACTED_HASH', 'password'],
  ];
  for (const [re, tag, st] of rules) {
    const r = line.replace(re, '$1' + tag);
    if (r !== line) { stats[st]++; line = r; }
  }
  return line;
}

// ---- WatchGuard Firebox (config.xml) ----
// XML tag-based，比照 anonPfSense/anonSophosXML 模板（逐行處理＋開關 context 旗標，非真正
// DOM 解析）。firewall_analyzer 的 WatchGuardParser 多輪關鍵字搜尋查無任何 password/secret/
// psk/snmp 標籤佐證（非查證不足，是這份 XML 格式本身沒有這些欄位），故本函式不做任何
// REDACTED_HASH/KEY/COMMUNITY 類替換，只處理 IP／描述／物件名稱。<name> 只在
// address-group/alias/abs-policy 區塊內才視為識別性物件名稱重新命名，介面自身的 <name>
// （如 eth0，非識別性）刻意不受影響。opts.comments 沿用既有 checkbox 語意
// （title="含 alias、description、remark"），與 FortiGate 對 anonAlias() 的既有用法一致
// Windows NPS 設定匯出（netsh nps export exportPSK=YES，XN72）：RADIUS 用戶端與遠端 RADIUS 伺服器群組成員的共用密鑰為明碼。
// 依 richardhicks/aovpntools Get-RadiusSharedSecret.ps1，用戶端密鑰在 …/Microsoft_Radius_Protocol/Children/Clients/Children/<用戶端>/Properties/Shared_Secret
// 的元素文字；屬性寫法與伺服器群組成員的元素名稱查無範例，凡元素名稱含 Secret 且有值一律遮蔽。其餘（位址、名稱）走通用處理
function anonNpsExport(text, opts) {
  const red = text.replace(/<([A-Za-z_][\w.-]*secret[\w.-]*)(\s[^>]*)?>([^<]+)<\/\1>/gi, (m, tag, attrs, v) => {
    if (!v.trim()) return m;
    stats.key++;
    return `<${tag}${attrs || ''}>REDACTED_KEY</${tag}>`;
  });
  return anonGeneric(red, opts);
}
// Citrix NetScaler ns.conf（XN105）：語法依 NetScaler CLI（set/add/bind 物件 名稱 -參數 值），範例依 f5devcentral/vscode-f5-flipper
// 測試資料（Apache-2.0）。設備加密存放的值一律寫成「值 -encrypted」，該值整段換成 REDACTED_SECRET（系統帳號為 REDACTED_HASH）；
// 未加密的金鑰參數（LDAP 綁定密碼、RADIUS 金鑰、憑證私鑰密碼等）同樣遮蔽；LDAP 綁定 DN 與搜尋基底含帳號與網域，換成 REDACTED_DN；
// SNMP community 遮蔽；本機帳號換假名（預設帳號 nsroot 保留，供稽核判斷）；憑證與私鑰的檔名不是機密，不處理。其餘交給 anonGeneric()
const NS_SECRET_FLAG_RE = /(-(?:ldapBindDnPassword|radKey|passcrypt|password|sharedSecret|secret|tacacsSecret|serverKey|authPassword|privPassword|clientSecret|preSharedKey|psk|keyValue)\s+)("[^"]*"|\S+)/gi;
function anonNetScaler(text, opts) {
  const red = text.split('\n').map(line => {
    if (/^\s*#/.test(line)) return line;
    let l = line;
    // 系統帳號：set|add system user 名稱 雜湊 -encrypted
    l = l.replace(/^((?:set|add) system user )(\S+)(\s+)(\S+)(\s+-encrypted\b)/, (m, p, name, sp, hash, enc) => {
      stats.password++;
      return p + (opts.user && name !== 'nsroot' ? anonUser(name) : name) + sp + 'REDACTED_HASH' + enc;
    });
    // 其餘「值 -encrypted」：值是設備加密後的字串
    l = l.replace(/(\s)("[^"]*"|[0-9A-Fa-f]{16,})(\s+-encrypted\b)/g, (m, sp, v, enc) => { if (/REDACTED/.test(v)) return m; stats.password++; return sp + 'REDACTED_SECRET' + enc; });
    l = l.replace(NS_SECRET_FLAG_RE, (m, p, v) => { if (/REDACTED/.test(v)) return m; stats.password++; return p + 'REDACTED_SECRET'; });
    l = l.replace(/(-ldap(?:BindDn|Base)\s+)("[^"]*"|\S+)/gi, (m, p, v) => { if (/REDACTED/.test(v)) return m; stats.user++; return p + 'REDACTED_DN'; });
    l = l.replace(/^(add snmp community )(\S+)/, (m, p, v) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    l = l.replace(/(-communityName\s+)(\S+)/, (m, p, v) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    if (opts.user) l = l.replace(/^((?:set|add|bind|rm) system user )(\S+)/, (m, p, name) => name === 'nsroot' || /REDACTED|^user-\d+$/.test(name) ? m : p + anonUser(name));
    if (opts.hostname) l = l.replace(/^(set ns hostName )(\S+)/, (m, p, n) => p + anonHostname(n, 'ns', opts));
    if (opts.comments) l = l.replace(/(-comment\s+)("[^"]*"|\S+)/g, (m, p, v) => { stats.comment++; return p + '"REDACTED_COMMENT"'; });
    return l;
  }).join('\n');
  return anonGeneric(red, opts);
}
// F5 BIG-IP tmsh 設定（XN106）：語法依 tmsh（區塊「模組 類型 名稱 {」、屬性「名稱 值」一行一項），範例依 Oxidized tmos 錄製與
// f5devcentral/vscode-f5-flipper 測試資料。密碼雜湊、金鑰、LDAP 綁定密碼、RADIUS／TACACS 金鑰、SNMPv3 密碼、IPsec 預先共用金鑰一律遮蔽；
// LDAP 綁定 DN 與搜尋基底換 REDACTED_DN；SNMP community-name 遮蔽；本機帳號（auth user 名稱與 partition-access 不變）換假名，
// 預設帳號 admin／root 保留；hostname 換假主機名稱；description 依「遮蔽備註」選項。其餘（位址、網域）交給 anonGeneric()
const F5_SECRET_ATTR_RE = /^(\s*)(encrypted-password|password|passphrase|secret|bind-pw|preshared-key(?:-encrypted)?|shared-secret|auth-password(?:-encrypted)?|privacy-password(?:-encrypted)?|key-secret|client-secret|api-key|secret-key|psk)(\s+)(\S.*)$/;
const F5_KEEP_USERS = new Set(['admin', 'root']);
function anonBigip(text, opts) {
  const red = text.split('\n').map(line => {
    let l = line;
    if (/^\s*#/.test(l) && !/^#\s+\S/.test(l)) return l;
    const sm = l.match(F5_SECRET_ATTR_RE);
    if (sm && !/REDACTED|^none$|^""$/.test(sm[4].trim())) { stats.password++; return sm[1] + sm[2] + sm[3] + (/encrypted-password/.test(sm[2]) ? 'REDACTED_HASH' : 'REDACTED_SECRET'); }
    l = l.replace(/^(\s*(?:bind-dn|search-base-dn|user-template)\s+)("[^"]*"|\S+)\s*$/, (m, p, v) => { if (/REDACTED|^none$/.test(v)) return m; stats.user++; return p + 'REDACTED_DN'; });
    l = l.replace(/^(\s*community-name\s+)(\S+)/, (m, p, v) => { stats.community++; return p + 'REDACTED_COMMUNITY'; });
    if (opts.user) l = l.replace(/^(auth user )(\S+)( \{)/, (m, p, name, b) => F5_KEEP_USERS.has(name) || /^user-\d+$/.test(name) ? m : p + anonUser(name) + b);
    if (opts.hostname) l = l.replace(/^(\s*hostname\s+)(\S+)\s*$/, (m, p, n) => p + anonHostname(n, 'f5', opts));
    if (opts.comments) l = l.replace(/^(\s*description\s+)("[^"]*"|\S+)\s*$/, (m, p, v) => { stats.comment++; return p + '"REDACTED_COMMENT"'; });
    return l;
  }).join('\n');
  // 版本號（17.1.1.4）長得像 IPv4，先換成佔位字串，anonGeneric() 之後再還原
  const vers = [];
  const kept = red.replace(/^(#TMSH-VERSION: |#?\s*(?:Version|Build)\s+)(\d+(?:\.\d+)+)\s*$/gm, (m, p, v) => { vers.push(v); return p + `__F5VER${vers.length - 1}__`; });
  return anonGeneric(kept, opts).replace(/__F5VER(\d+)__/g, (m, i) => vers[+i]);
}
// 應用程式環境變數（XN93）：.env（KEY=值、export KEY=值）與 docker-compose environment（- KEY=值 清單或 KEY: 值 對應）。
// 名稱含密碼、金鑰、權杖等字樣的值，或值本身是常見權杖格式（GitHub ghp_／gho_、GitLab glpat-、Slack xox?-、AWS AKIA／ASIA、Stripe sk_live_、JWT）
// 一律換成 REDACTED_KEY；${變數} 參照與空值保留。連線字串內的帳密由 anonymize() 最後的 anonUrlCredentials() 處理，位址與網域走 anonGeneric()
const ENV_SECRET_NAME_RE = /PASS|PWD|SECRET|TOKEN|KEY|PRIVATE|CREDENTIAL|DSN|SALT|COOKIE|SIGNATURE|CERT/i;
const ENV_SECRET_VALUE_RE = /^(?:ghp_|gho_|ghs_|glpat-|xox[abpr]-|AKIA|ASIA|sk_live_|rk_live_|eyJ[A-Za-z0-9_-]{8,}\.)[A-Za-z0-9_\-.]{8,}/;
function anonAppEnv(text, opts) {
  const red = text.split('\n').map(line => {
    const m = line.match(/^(\s*(?:-\s*)?(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.]*)(\s*=\s*|:\s+)(.*)$/);
    if (!m || /^\s*#/.test(line)) return line;
    const [, pre, name, sep, raw] = m;
    // docker-compose 的鍵（image:、ports: 等）只處理 environment 底下的大寫名稱
    if (sep.trim() === ':' && !/^[A-Z][A-Z0-9_]*$/.test(name)) return line;
    const q = /^["']/.test(raw) ? raw[0] : '';
    const val = q && raw.endsWith(q) && raw.length > 1 ? raw.slice(1, -1) : raw.trim();
    if (!val || /^\$\{[^}]*\}$/.test(val) || /REDACTED/.test(val)) return line;
    if (!ENV_SECRET_NAME_RE.test(name) && !ENV_SECRET_VALUE_RE.test(val)) return line;
    stats.key++;
    return pre + name + sep + q + 'REDACTED_KEY' + q;
  }).join('\n');
  return anonGeneric(red, opts);
}
function anonWatchGuard(text, opts) {
  const IP_TAGS = ['ip', 'default-gateway', 'gateway-ip', 'host-ip-addr', 'ip-network-addr', 'start-ip-addr', 'end-ip-addr', 'dest-address'];
  let ctx = null; // 'addrgrp' | 'alias' | 'policy' | null
  // 位址群組／別名的名稱也出現在別名成員（<aliasname>）與規則來源／目的（<item>名稱</item>）裡，
  // 定義處換名但引用處沒換，規則就對不上物件（2026-10-02 發現）；先收集定義過的名稱，引用處一併換
  const defined = new Set();
  for (const m of text.matchAll(/<(address-group|alias)>\s*<name>([^<]+)<\/name>/g)) defined.add(m[2]);
  return text.split('\n').map(line => {
    if (opts.comments) line = line.replace(/(<(aliasname|item)>)([^<]+)(<\/\2>)/, (m, o, t, n, c) => defined.has(n) ? o + anonAlias(n) + c : m);
    if (/<address-group>/.test(line)) ctx = 'addrgrp';
    else if (/<alias>/.test(line)) ctx = 'alias';
    else if (/<abs-policy>/.test(line)) ctx = 'policy';
    else if (/<\/(?:address-group|alias|abs-policy)>/.test(line)) ctx = null;

    if (opts.comments && ctx && /<name>/.test(line)) {
      line = line.replace(/(<name>)([^<]+)(<\/name>)/, (m, o, n, c) => o + anonAlias(n) + c);
    }
    if (opts.comments) {
      const dR = line.replace(/(<description>)([^<]+)(<\/description>)/, '$1REDACTED_COMMENT$3');
      if (dR !== line) { stats.comment++; line = dR; }
    }
    if (opts.ip) {
      for (const tag of IP_TAGS) {
        line = line.replace(new RegExp(`(<${tag}>)([^<]+)(</${tag}>)`), (m, o, v, c) =>
          (isValidIPv4(v) && classifyIP(v) !== 'skip') ? o + anonIP(v, opts) + c : m);
      }
      // 白名單外的元素與 IPv6／CIDR 值補掃
      line = replaceIPsInXmlText(line, opts);
    }
    if (opts.mac) line = replaceMACsInLine(line, opts);
    return line;
  }).join('\n');
}

// ---- SONiC (config_db.json) ----
// JSON tree-walk，本檔案其餘 28 家皆是逐行文字保留式替換，SONiC 是唯一 JSON 格式來源，
// 沒有其他做法可行，故 JSON.stringify(db,null,2) 會重新格式化整份輸出（縮排/欄位順序可能
// 與原始檔案不同，僅保證內容正確性，不保留原始文字格式，是刻意的架構差異非疏漏）。
// 無帳號密碼可遮蔽（架構排除：帳號走 Linux useradd，非宣告式設定檔範圍，非查無語法）；
// SNMP_COMMUNITY 的 community 字串是物件 key 本身，非一般 value，需整個重新 keying；
// ACL_TABLE/ACL_RULE 的表名/規則名同樣是 JSON key，改鍵名複雜度與風險不成比例，
// 比照專案「不過度工程」原則不處理，記錄為已知限制
// ---- 雲端安全群組 JSON（AWS describe-security-groups／Azure NSG，2026-10-02 新增，第十輪 ZC）----
// 與 SONiC 同樣以 JSON 樹狀走訪處理（輸出會重新排版）。欄位依 firewall_analyzer CloudSGParser 已查證的形狀：
// AWS 帳號（OwnerId／UserId）、資源 ID（sg-／vpc-／pl-…）、群組名稱與 Name 標籤；Azure 訂閱 GUID、資源 ID 路徑內的
// 資源群組／NSG 名稱、resourceGuid／etag；各處的描述與 IP。同一 ID 全檔一致對應，群組互相參照（UserIdGroupPairs）
// 換完仍對得上；規則名稱（Allow-HTTPS、Azure 預設規則名稱）保留。
// Meraki MX Dashboard API 回應（ZD）：L3 規則 comment、轉送／1:1 NAT／VLAN／靜態路由的 name、networkId、各處 IP；
// 多個回應前後相接時逐段處理
// 精簡 YAML 讀取（Kubernetes NetworkPolicy 的 kubectl -o yaml／官方範例用，與 firewall_analyzer CloudSGParser 的 yamlLite() 同一份邏輯、另行維護）：縮排區塊對應與序列、「- 鍵: 值」、{}／[] 空集合、引號字串、數字、
// true／false／null、| 與 > 區塊字串、註解與 --- 多文件；不支援錨點、別名、流式集合內容與多行純量
function yamlLite(text) {
  const docs = [];
  String(text || '').replace(/\r\n/g, '\n').split(/^---[^\n]*$/m).forEach(doc => {
    const lines = doc.split('\n').filter(l => l.trim() && !/^\s*#/.test(l)).map(l => ({ ind: l.match(/^ */)[0].length, t: l.trim(), raw: l }));
    if (!lines.length) return;
    let i = 0;
    const isItem = t => t === '-' || t.startsWith('- ');
    const unq = v => (/^"[\s\S]*"$/.test(v) ? (() => { try { return JSON.parse(v); } catch (e) { return v.slice(1, -1); } })() : /^'[\s\S]*'$/.test(v) ? v.slice(1, -1).replace(/''/g, "'") : v);
    const scalar = v => {
      // 行尾註解：引號字串只去掉結尾引號之後的 # 註解，引號內的 # 保留
      const qm = v.match(/^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*')(?:\s+#.*)?$/);
      v = qm ? qm[1] : v.replace(/\s+#.*$/, '');
      if (v === '{}') return {};
      if (v === '[]') return [];
      // 流式清單（policyTypes: [Ingress, Egress]），只支援純量成員
      if (/^\[[^\[\]{}]*\]$/.test(v)) return v.slice(1, -1).split(',').map(x => x.trim()).filter(Boolean).map(scalar);
      if (/^["']/.test(v)) return unq(v);
      if (/^-?\d+(?:\.\d+)?$/.test(v)) return Number(v);
      if (/^(?:true|false)$/.test(v)) return v === 'true';
      if (/^(?:null|~)$/.test(v)) return null;
      return v;
    };
    const KEY_RE = /^("[^"]*"|'[^']*'|[^\s"'{[#-][^:]*?|-[^\s][^:]*?):(?:\s+(.*))?$/;
    function block(ind) { return isItem(lines[i].t) ? seq(ind) : map(ind); }
    function map(ind) {
      const o = {};
      while (i < lines.length && lines[i].ind === ind && !isItem(lines[i].t)) {
        const m = lines[i].t.match(KEY_RE);
        if (!m) throw new Error('YAML: ' + lines[i].t);
        i++;
        const k = unq(m[1].trim()), v = m[2] === undefined ? '' : m[2].trim();
        if (/^[|>][-+]?$/.test(v)) {
          const buf = [];
          while (i < lines.length && lines[i].ind > ind) { buf.push(lines[i].raw.slice(lines[i].ind)); i++; }
          o[k] = buf.join(v[0] === '|' ? '\n' : ' ');
        } else if (v) o[k] = scalar(v);
        else if (i < lines.length && (lines[i].ind > ind || (lines[i].ind === ind && isItem(lines[i].t)))) o[k] = block(lines[i].ind);
        else o[k] = null;
      }
      return o;
    }
    function seq(ind) {
      const a = [];
      while (i < lines.length && lines[i].ind === ind && isItem(lines[i].t)) {
        const rest = lines[i].t.replace(/^-\s*/, '');
        if (!rest) { i++; a.push(i < lines.length && lines[i].ind > ind ? block(lines[i].ind) : null); continue; }
        if (KEY_RE.test(rest)) {
          lines[i] = { ind: ind + lines[i].t.length - rest.length, t: rest, raw: ' '.repeat(ind + lines[i].t.length - rest.length) + rest };
          a.push(map(lines[i].ind));
        } else { a.push(scalar(rest)); i++; }
      }
      return a;
    }
    docs.push(block(lines[0].ind));
  });
  return docs.length === 1 ? docs[0] : docs;
}
function anonCloudSG(text, opts) {
  let db;
  try { db = JSON.parse(text); } catch (e) {
    try { db = JSON.parse(text.replace(/,(\s*[}\]])/g, '$1')); } catch (e2) {
      // Meraki：多個 API 回應前後相接（每段由行首的 { 或 [ 開始），逐段處理後照原順序接回
      const parts = text.split(/\n(?=[{[])/);
      if (parts.length > 1 && parts.every(p => { try { JSON.parse(p); return true; } catch { return false; } })) return parts.map(p => anonCloudSG(p, opts)).join('\n');
      // Kubernetes NetworkPolicy 的 YAML：轉成物件後同樣處理，輸出為 JSON（kubectl 可直接套用）
      if (!/^\s*kind:\s*NetworkPolicy\b/m.test(text)) return anonGeneric(text, opts);
      try { db = yamlLite(text); } catch (e3) { return anonGeneric(text, opts); }
    }
  }
  const fake = (orig, make) => {
    if (mappings.alias.has(orig)) return mappings.alias.get(orig);
    ctrs.alias++;
    const v = make(ctrs.alias);
    mappings.alias.set(orig, v);
    return v;
  };
  const name = v => opts.hostname && v ? anonHostname(v, 'sg', opts) : v;
  const proj = v => fake('gcp-project:' + v, n => `project-${n}`);
  const ids = s => (/^\/subscriptions\//i.test(s) ? s.replace(/\/(resourceGroups|networkSecurityGroups|virtualNetworks|networkInterfaces|applicationSecurityGroups|subnets|firewallPolicies|ipGroups)\/([^/"]+)/gi, (m, k, v) => `/${k}/${name(v)}`) : s)
    .replace(/\b(sg|vpc|pl|subnet|eni|igw|nat|rtb|acl|aclassoc|vpce|tgw|i)-[0-9a-f]{8,17}\b/g, (m, p) => fake(m, n => `${p}-${String(n).padStart(17, '0')}`))
    // GCP（第二十一輪 GF）：資源 URL 的專案與 VPC 網路名稱（服務帳戶電子郵件由通用的電子郵件替換處理）
    .replace(/\/projects\/([^/"]+)/g, (m, v) => '/projects/' + proj(v))
    .replace(/\/networks\/([^/"]+)/g, (m, v) => '/networks/' + name(v))
    // OCI 資源 OCID（第二十三輪 IH）：最後一段唯一識別碼換掉（類型與區域保留），compartment／tenancy 的 OCID 同樣處理；
    // 假值只用英文字母（數字編號轉成字母），殘留檢查才不會當成金鑰
    .replace(/\b(ocid1\.[a-z0-9]+\.oc\d+\.[a-z0-9-]*\.)([a-z0-9]{16,})\b/g, (m, p, u) => p + fake(m, n => 'anonymizedocid' + String(n).replace(/\d/g, d => 'abcdefghij'[d])))
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, m => /^[0-]+$/.test(m) ? m : fake(m.toLowerCase(), n => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`))
  ;
  // NSG 本身的 name（規則的 name 不換）
  const nsgObjs = new Set(), k8sMeta = new Set();
  (function find(o, d) {
    if (!o || typeof o !== 'object' || d > 6) return;
    const p = o.properties && typeof o.properties === 'object' ? o.properties : o;
    if (Array.isArray(p.securityRules) || Array.isArray(p.defaultSecurityRules)) nsgObjs.add(o);
    // Kubernetes NetworkPolicy 的 metadata（第二十三輪 IG）
    if (o.kind === 'NetworkPolicy' && o.metadata && typeof o.metadata === 'object') k8sMeta.add(o.metadata);
    (Array.isArray(o) ? o : Object.values(o)).forEach(v => find(v, d + 1));
  })(db, 0);
  const walk = (o, key, parent) => {
    if (Array.isArray(o)) return o.map(v => walk(v, key, o));
    if (o && typeof o === 'object') {
      for (const k of Object.keys(o)) {
        if (/^(?:tags|freeform[-_]?[tT]ags)$/.test(k) && o[k] && typeof o[k] === 'object' && !Array.isArray(o[k])) {
          if (opts.comments) for (const t of Object.keys(o[k])) o[k][t] = anonAlias(String(o[k][t]));
          continue;
        }
        // OCI defined-tags 為「命名空間 → 鍵 → 值」兩層，值比照 freeform-tags
        if (/^defined[-_]?[tT]ags$/.test(k) && o[k] && typeof o[k] === 'object' && !Array.isArray(o[k])) {
          if (opts.comments) for (const ns of Object.values(o[k])) if (ns && typeof ns === 'object') for (const t of Object.keys(ns)) ns[t] = anonAlias(String(ns[t]));
          continue;
        }
        // NetworkPolicy 常以 namespaceSelector.matchLabels.name 指定 namespace，與 namespace 名稱用同一對照
        if (k === 'namespaceSelector' && o[k] && o[k].matchLabels && typeof o[k].matchLabels.name === 'string') o[k].matchLabels.name = name(o[k].matchLabels.name);
        o[k] = walk(o[k], k, o);
      }
      return o;
    }
    if (typeof o === 'number' && /^(OwnerId|UserId)$/.test(key)) o = String(o);
    if (typeof o !== 'string' || !o) return o;
    if (/^(OwnerId|UserId)$/.test(key) && /^\d{12}$/.test(o)) return opts.hostname ? fake(o, n => String(100000000000 + n)) : o;
    // Azure Firewall Policy 與 GCP 防火牆政策的 FQDN（第二十二輪 HF／HG）：非公開網域以主機名稱對照替換
    if (/^(targetFqdns|destinationFqdns|translatedFqdn|destFqdns|srcFqdns)$/.test(key) && opts.hostname && !PUBLIC_DOMAIN_RE.test(o)) return anonHostname(o, 'sg', opts);
    if (/^description$/i.test(key)) { if (opts.comments) { stats.comment++; return 'REDACTED_COMMENT'; } return o; }
    // Meraki（2026-10-02，ZD）：L3 規則的 comment（Meraki 自動產生的 Default rule 保留）、轉送／NAT／VLAN／路由的 name、networkId
    if (key === 'comment' && parent && 'policy' in parent) { if (opts.comments && o !== 'Default rule') { stats.comment++; return 'REDACTED_COMMENT'; } return o; }
    if (key === 'name' && parent && ('lanIp' in parent || 'applianceIp' in parent || 'gatewayIp' in parent)) return opts.comments ? anonAlias(o) : o;
    if (key === 'networkId' && opts.hostname) return fake(o, n => `N_${String(n).padStart(8, '0')}`);
    if (/^(GroupName|resourceGroup)$/.test(key) || (key === 'name' && nsgObjs.has(parent))) return name(o);
    // Kubernetes NetworkPolicy（第二十三輪 IG）：政策名稱、namespace 與選擇 namespace 用的 kubernetes.io/metadata.name 標籤值以同一對照替換；
    // kubectl 留下的 last-applied-configuration 註記是整份原始設定，一律遮蔽
    if ((key === 'name' || key === 'namespace') && k8sMeta.has(parent)) return name(o);
    if (key === 'kubernetes.io/metadata.name') return name(o);
    // OCI 安全清單名稱（CLI 為 display-name、REST 為 displayName）
    if (/^display[-_]?[nN]ame$/.test(key)) return name(o);
    if (key === 'kubectl.kubernetes.io/last-applied-configuration') return 'REDACTED_COMMENT';
    // GCP 防火牆政策本身與關聯的名稱（第二十二輪 HG，關聯名稱常含網路名稱）
    if (key === 'name' && parent && (parent.kind === 'compute#firewallPolicy' || 'attachmentTarget' in parent)) return name(o);
    // AWS Tags 為 [{Key, Value}]：Name 標籤視同名稱，其餘值視同備註
    if (key === 'Value' && parent && 'Key' in parent) return parent.Key === 'Name' ? name(o) : (opts.comments ? anonAlias(o) : o);
    let v = opts.hostname ? ids(o) : o;
    if (opts.ip) v = replaceIPsInLine(v, opts);
    return v;
  };
  walk(db, '', null);
  let out = JSON.stringify(db, null, 2);
  if (opts.mac) out = replaceMACsInLine(out, opts);
  return out;
}

// ---- Check Point Management API JSON（第十八輪 TL）----
// show-access-rulebase／show-nat-rulebase 與 show-* 物件清單（firewall_analyzer parseMgmtApi() 讀的格式），可多個回應前後相接。
// UID 保留（規則以 UID 引用物件，換掉會斷），自訂位址物件、規則、區段與 layer 名稱以物件名稱對照替換（同名一致，勾選備註時），
// 預先定義物件（domain-type 為 data domain、Any／Accept／Original 等系統型別）保留；comments 為 REDACTED_COMMENT；
// 閘道名稱以主機名稱對照；meta-info 的建立者／修改者帳號換假名（System 保留）；其餘字串做 IP 替換
const CP_API_BUILTIN_TYPES = /^(?:CpmiAnyObject|RulebaseAction|Track|Global|Internet|CpmiHostCkp)$/;
const CP_API_GW_TYPES = /^(?:simple-gateway|simple-cluster|CpmiGatewayCluster|CpmiClusterMember|CpmiGatewayPlain|checkpoint-host|Gateway)$/i;
function anonCheckPointApi(text, opts) {
  const parts = text.split(/\n(?=[{[])/);
  if (parts.length > 1 && parts.every(p => { try { JSON.parse(p); return true; } catch { return false; } })) return parts.map(p => anonCheckPointApi(p, opts)).join('\n');
  let db;
  try { db = JSON.parse(text); } catch (e) { return anonGeneric(text, opts); }
  const builtin = o => (o.domain && o.domain['domain-type'] === 'data domain') || CP_API_BUILTIN_TYPES.test(o.type || '') || o.name === 'Original';
  const walk = (o, key, parent) => {
    if (Array.isArray(o)) return o.map(v => walk(v, key, o));
    if (o && typeof o === 'object') {
      for (const k of Object.keys(o)) o[k] = walk(o[k], k, o);
      return o;
    }
    if (typeof o !== 'string' || !o) return o;
    if (key === 'name' && parent && !Array.isArray(parent)) {
      if ('domain-type' in parent) return o;                             // domain 物件名稱（SMC User 等）
      if (CP_API_GW_TYPES.test(parent.type || '')) return opts.hostname ? anonHostname(o, 'gw', opts) : o;
      if (builtin(parent) || /^service-/.test(parent.type || '')) return o;   // 服務名稱比照其他廠牌保留
      if ('rulebase' in parent && !parent.type && o === 'Network') return o; // 預設 layer 名稱
      return opts.comments ? anonAlias(o) : o;
    }
    if (key === 'comments') { if (opts.comments && o.trim()) { stats.comment++; return 'REDACTED_COMMENT'; } return o; }
    if ((key === 'creator' || key === 'last-modifier') && o !== 'System') return opts.user ? anonUser(o) : o;
    if (key === 'uid' || key === 'type' || /-uid$/.test(key) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(o)) return o;
    return opts.ip ? replaceIPsInLine(o, opts) : o;
  };
  walk(db, '', null);
  let out = JSON.stringify(db, null, 2);
  if (opts.mac) out = replaceMACsInLine(out, opts);
  return out;
}

// ---- Allied Telesis AlliedWare Plus ----
// 2026-10-02 新增（第十輪 ZH）。帳號、community、描述、主機名稱與 IOS 同語法，沿用 anonCiscoIOS()；
// 另處理 AW+ 的 `ssh server allow-users 帳號`（log host 的位址由通用 IP 替換處理）
function anonAlliedWare(text, opts) {
  const out = anonCiscoIOS(text, opts);
  return opts.user ? out.replace(/^(ssh server allow-users\s+)(\S+)/gm, (m, p, n) => p + anonUser(n)) : out;
}

// ---- NVIDIA Cumulus Linux（NVUE）----
// 2026-10-02 新增（第十輪 ZI）。欄位依 switch_analyzer parseCumulus() 已查證的 NVUE 樹狀結構：YAML 依縮排算出上層路徑，
// nv set 指令以前面的字為路徑，兩者共用同一組規則——system hostname、system aaa user 的帳號名稱（鍵）、hashed-password、
// full-name、snmp-server readonly-community（鍵即 community）、snmp-server username（v3 帳號）與其下 auth-*／encrypt-*
// 的金鑰（同樣是鍵）、description；其餘再做 IP／MAC 替換
function anonCumulus(text, opts) {
  const rule = (path, tok) => {
    const last = path[path.length - 1], prev = path[path.length - 2];
    if (last === 'hostname' && prev === 'system') return opts.hostname ? anonHostname(tok, 'sw', opts) : tok;
    if (last === 'user' && prev === 'aaa') return opts.user ? anonUser(tok) : tok;
    if (last === 'hashed-password') { if (tok === '*') return tok; stats.password++; return 'REDACTED_HASH'; }
    if (last === 'full-name') return opts.user ? 'REDACTED' : tok;
    if (last === 'readonly-community') { stats.community++; return 'REDACTED_COMMUNITY'; }
    if (last === 'username' && prev === 'snmp-server') return opts.user ? anonUser(tok) : tok;
    if (/^(?:auth|encrypt)-/.test(last || '')) { stats.key++; return 'REDACTED_KEY'; }
    if (last === 'description' && opts.comments) { stats.comment++; return 'REDACTED_COMMENT'; }
    return tok;
  };
  const quote = (orig, v) => (/^'/.test(orig) ? `'${v}'` : /^"/.test(orig) ? `"${v}"` : (/\s/.test(v) ? `'${v}'` : v));
  const unq = t => t.replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1');
  const finish = line => { if (opts.ip) line = replaceIPsInLine(line, opts); if (opts.mac) line = replaceMACsInLine(line, opts); return line; };
  const stack = [];
  return text.split('\n').map(line => {
    const cmd = line.match(/^(\s*nv set\s+)(.+)$/);
    if (cmd) {
      const toks = cmd[2].match(/'[^']*'|"[^"]*"|\S+/g) || [];
      const out = toks.map((t, i) => quote(t, rule(toks.slice(0, i).map(unq), unq(t))));
      return finish(cmd[1] + out.join(' '));
    }
    if (/^\s*-\s+\w+:\s*$/.test(line)) { stack.length = 0; return line; }
    const m = line.match(/^(\s*)('[^']*'|"[^"]*"|\S.*?):(\s+(.*)|$)/);
    if (!m) return finish(line);
    const indent = m[1].length;
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
    const path = stack.map(x => x.key);
    const key = unq(m[2]);
    const newKey = rule(path, key);
    let rest = m[3];
    const val = m[4];
    if (val !== undefined && val !== '{}' && !/^[|>]/.test(val)) rest = rest.replace(val, quote(val, rule(path.concat(key), unq(val))));
    stack.push({ indent, key });
    return finish(m[1] + (newKey === key ? m[2] : quote(m[2], newKey)) + ':' + rest);
  }).join('\n');
}

function anonSonic(text, opts) {
  let db;
  try { db = JSON.parse(text); } catch (e) { return anonGeneric(text, opts); }

  if (opts.hostname && db.DEVICE_METADATA && db.DEVICE_METADATA.localhost && db.DEVICE_METADATA.localhost.hostname) {
    db.DEVICE_METADATA.localhost.hostname = anonHostname(db.DEVICE_METADATA.localhost.hostname, 'sw', opts);
  }
  const rekey = (obj, fn) => obj ? Object.fromEntries(Object.entries(obj).map(([k, v]) => [fn(k), v])) : obj;
  if (opts.ip) {
    for (const t of ['INTERFACE', 'VLAN_INTERFACE', 'PORTCHANNEL_INTERFACE', 'STATIC_ROUTE']) {
      if (db[t]) db[t] = rekey(db[t], k => replaceIPsInLine(k, opts));
    }
    if (db.STATIC_ROUTE) for (const rec of Object.values(db.STATIC_ROUTE)) {
      if (rec.nexthop) rec.nexthop = replaceIPsInLine(String(rec.nexthop), opts);
    }
    if (db.BGP_NEIGHBOR) {
      for (const rec of Object.values(db.BGP_NEIGHBOR)) if (rec.local_addr) rec.local_addr = replaceIPsInLine(String(rec.local_addr), opts);
      db.BGP_NEIGHBOR = rekey(db.BGP_NEIGHBOR, k => replaceIPsInLine(k, opts));
    }
    if (db.SYSLOG_SERVER) {
      db.SYSLOG_SERVER = rekey(db.SYSLOG_SERVER, k => replaceIPsInLine(k, opts));
      for (const rec of Object.values(db.SYSLOG_SERVER)) if (rec.source) rec.source = replaceIPsInLine(rec.source, opts);
    }
    if (db.ACL_RULE) for (const rec of Object.values(db.ACL_RULE)) {
      for (const f of ['SRC_IP', 'DST_IP', 'SRC_IPV6', 'DST_IPV6']) if (rec[f]) rec[f] = replaceIPsInLine(rec[f], opts);
    }
  }
  if (opts.comments && db.BGP_NEIGHBOR) {
    for (const rec of Object.values(db.BGP_NEIGHBOR)) if (rec.name) rec.name = anonAlias(rec.name);
  }
  if (db.SNMP_COMMUNITY) {
    const renamed = {};
    let i = 0;
    for (const meta of Object.values(db.SNMP_COMMUNITY)) { i++; stats.community++; renamed[`REDACTED_COMMUNITY_${i}`] = meta; }
    db.SNMP_COMMUNITY = renamed;
  }
  let out = JSON.stringify(db, null, 2);
  if (opts.mac) out = replaceMACsInLine(out, opts);
  return out;
}

// ---- 無線控制器（2026-10-05，KD／KH／KI）----
// Catalyst 9800（IOS-XE）、AireOS、Aruba Mobility Controller／Instant、H3C WX。先處理 WLAN 專屬欄位
// （PSK、SSID 與 WLAN／SSID profile 名稱、AP 管理帳密），再交給同語系的既有規則（9800→IOS、H3C WX→Comware、
// AireOS 與 Aruba→通用）。欄位依 firewall_analyzer 的 parseWlcWifi() 已解析的語法，另加 Oxidized 真實錄製中
// 出現的 Aruba／9800 機敏欄位（virtual-controller-key、ap-console-password、mgmtuser 等）
function anonWlc(text, opts) {
  const kind = /^(?:config\s+)?wlan\s+create\s+\d+\s+\S+/m.test(text) ? 'aireos'
    : /^\s*wlan\s+service-template\s+\S+/m.test(text) ? 'h3cwx'
    : /^\s*wlan\s+ssid-profile\s+\S+/m.test(text) ? 'aruba' : 'cisco9800';
  const red = (tok, kindStat) => { stats[kindStat]++; return tok; };
  const ss = n => {
    const q = /^".*"$/.test(n) ? '"' : '';
    return opts.hostname ? q + anonSSID(q ? n.slice(1, -1) : n) + q : n;
  };
  const pre = text.split('\n').map(line => {
    let m;
    if (kind === 'cisco9800') {
      if ((m = /^(wlan\s+)(\S+)(\s+\d{1,4}\s+)(.+)$/.exec(line))) return m[1] + ss(m[2]) + m[3] + ss(m[4].trim());
      if ((m = /^(\s+wlan\s+)(\S+)(\s+policy\s+.*)$/.exec(line))) return m[1] + ss(m[2]) + m[3];
      if ((m = /^(\s*security\s+wpa\s+psk\s+set-key\s+(?:ascii|hex)\s+\d+\s+).+$/.exec(line))) return m[1] + red('REDACTED_PSK', 'key');
      // AP profile 的 dot1x／mgmtuser 帳密（密碼可含空白，取到 secret 或行尾）
      if ((m = /^(\s*(?:dot1x|mgmtuser)\s+username\s+)(\S+)(\s+password\s+\d+\s+)(.+?)(?:(\s+secret\s+\d+\s+).+)?$/.exec(line)))
        return m[1] + (opts.user ? anonUser(m[2]) : m[2]) + m[3] + red('REDACTED_PASSWORD', 'password') + (m[5] ? m[5] + red('REDACTED_SECRET', 'password') : '');
    } else if (kind === 'aireos') {
      const l = line.replace(/^\s+/, '');
      if ((m = /^((?:config\s+)?wlan\s+create\s+\d+\s+)(\S+)(?:(\s+)(\S+))?(.*)$/.exec(l))) return m[1] + ss(m[2]) + (m[4] ? m[3] + ss(m[4]) : '') + m[5];
      if ((m = /^((?:config\s+)?wlan\s+security\s+wpa\s+akm\s+psk\s+set-key\s+(?:ascii|hex)\s+)\S+(\s+\d+\s*)$/.exec(l))) return m[1] + red('REDACTED_PSK', 'key') + m[2];
      if ((m = /^((?:config\s+)?radius\s+(?:auth|acct)\s+add\s+\d+\s+\S+\s+\d+\s+(?:ascii|hex)\s+)\S+(.*)$/.exec(l))) return m[1] + red('REDACTED_KEY', 'key') + m[2];
      if (opts.hostname && (m = /^((?:config\s+)?sysname\s+)(\S+)/.exec(l))) return m[1] + anonHostname(m[2], 'wlc', opts);
    } else if (kind === 'aruba') {
      if ((m = /^(\s*wpa-passphrase\s+)("[^"]*"|\S+)\s*$/.exec(line))) return m[1] + (m[2][0] === '"' ? '"' + red('REDACTED_PSK', 'key') + '"' : red('REDACTED_PSK', 'key'));
      if ((m = /^(\s*essid\s+)("[^"]*"|\S+)\s*$/.exec(line))) return m[1] + ss(m[2]);
      if ((m = /^(\s*(?:wlan\s+ssid-profile|ssid-profile)\s+)("[^"]*"|\S+)\s*$/.exec(line))) return m[1] + ss(m[2]);
      if ((m = /^(\s*(?:key|virtual-controller-key|ap-console-password|bkup-passwords|ike\s+authentication\s+pre-share)\s+)("[^"]*"|\S+)\s*$/.exec(line)))
        return m[1] + (m[2][0] === '"' ? '"' + red('REDACTED_KEY', 'key') + '"' : red('REDACTED_KEY', 'key'));
      if ((m = /^(authentication\s+)(?!pre-share\b|rsa-sig\b|ecdsa)(\S+)\s*$/.exec(line))) return m[1] + red('REDACTED_KEY', 'key');
      if ((m = /^(\s*peer-ip-address\s+\S+\s+ipsec\s+)\S+\s*$/.exec(line))) return m[1] + red('REDACTED_KEY', 'key');
      if ((m = /^(\s*snmp-server\s+host\s+\S+\s+version\s+(?:1|2c)\s+)(\S+)(.*)$/.exec(line))) return m[1] + red('REDACTED_COMMUNITY', 'community') + m[3];
      if (opts.hostname && (m = /^(name\s+)(\S+)\s*$/.exec(line))) return m[1] + anonHostname(m[2], 'wlc', opts);
      if (opts.hostname && (m = /^(organization\s+)(.+)$/.exec(line))) return m[1] + 'REDACTED_ORG';
      if (opts.hostname && (m = /^(\s*nas-identifier\s+)("?)([^"\s]+)("?)\s*$/.exec(line))) return m[1] + m[2] + anonHostname(m[3], 'wlc', opts) + m[4];
      if ((m = /^(\s*wlan\s+access-rule\s+)("[^"]*"|\S+)\s*$/.exec(line))) return m[1] + ss(m[2]);
      // 管理帳號：Instant `hash-mgmt-user 名稱 password hash …`、控制器 `mgmt-user 名稱 角色 …`
      if (opts.user && (m = /^(\s*(?:hash-)?mgmt-user\s+)(\S+)(\s.*)$/.exec(line))) line = m[1] + anonUser(m[2]) + m[3];
      // Instant 檔頭的 AP 清單（# 名稱  IP  型號 …）：AP 名稱可含空白，取到 IP 之前。名稱不可含冒號或逗號，
      // IP（可帶 *）之後須以兩個以上空白接下一欄，避免把 `# ROM: … Version CPBoot 1.2.9.0 (build …)`、
      // `# ArubaOS (MODEL: …), Version 8.10.0.7 LSR` 這類版本行誤當成 AP 清單
      if (opts.hostname && (m = /^(#\s+)([^\s:,][^:,]*?)(\s+\d{1,3}(?:\.\d{1,3}){3}\*?\s{2,}\S.*)$/.exec(line))) return m[1] + anonHostname(m[2].trim(), 'ap', opts) + m[3];
    } else if (kind === 'h3cwx') {
      if ((m = /^(\s*ssid\s+)(.+?)\s*$/.exec(line))) return m[1] + ss(m[2]);
      if ((m = /^(\s*preshared-key\s+(?:pass-phrase|raw-key)\s+(?:simple|cipher)\s+)\S+/.exec(line))) return m[1] + red('REDACTED_PSK', 'key');
      if ((m = /^(\s*(?:wlan\s+)?service-template\s+)(?!enable\b|disable\b)(\S+)(.*)$/.exec(line))) return m[1] + ss(m[2]) + m[3];
      if (opts.hostname && (m = /^(wlan\s+ap\s+)(\S+)(.*)$/.exec(line))) return m[1] + anonHostname(m[2], 'ap', opts) + m[3];
    }
    return line;
  }).join('\n');
  const out = (kind === 'cisco9800' ? anonCiscoIOS : kind === 'h3cwx' ? anonComware : anonGeneric)(pre, opts).split('\n');
  // AireOS 的 wlan security … 指令已在上面處理過 PSK；通用規則會把 `akm psk enable` 的 enable 當成金鑰，改用處理後的行
  const preLines = pre.split('\n');
  if (kind === 'aireos' && preLines.length === out.length) preLines.forEach((l, i) => { if (/^\s*(?:config\s+)?wlan\s+security\s/.test(l)) out[i] = l; });
  // 版本號（Aruba 的 version 8.10.0.0-8.10.0、ArubaOS … Version 8.10.0.6）長得像 IPv4，維持原文
  const orig = text.split('\n');
  // 控制器檔頭 `# ROM: System Bootstrap, Version CPBoot 1.2.9.0 (build …)` 的版本號前另有名稱，一併保留
  if (orig.length === out.length) orig.forEach((l, i) => { if (/\bversion\s+(?:[A-Za-z]\S*\s+)?\d+\.\d+\.\d+\.\d+/i.test(l) && !/\b(?:host|server|ip)\b/i.test(l)) out[i] = l; });
  return out.join('\n');
}

// ---- Extreme VOSS／Fabric Engine（2026-10-05，KG）----
// 欄位依 switch_analyzer parseVOSS() 已解析的語法：prompt／snmp-server name（主機名稱）、snmp-server location／contact、
// 埠與 MLT 的 name（描述）；其餘交給通用規則（IP、密碼、community）。檔頭的 software version 長得像 IPv4，維持原文
function anonVOSS(text, opts) {
  const pre = text.split('\n').map(line => {
    let m;
    if (opts.hostname && (m = /^((?:prompt|snmp-server\s+name)\s+)("?)([^"\n]+?)("?)\s*$/.exec(line))) return m[1] + m[2] + anonHostname(m[3], 'sw', opts) + m[4];
    if (opts.comments && (m = /^(\s*name\s+|mlt\s+\d+\s+enable\s+name\s+|mlt\s+\d+\s+name\s+)("[^"]*"|\S+)\s*$/.exec(line))) {
      stats.comment++; return m[1] + (m[2][0] === '"' ? '"REDACTED_COMMENT"' : 'REDACTED_COMMENT');
    }
    return line;
  }).join('\n');
  const out = anonGeneric(pre, opts).split('\n'), orig = text.split('\n');
  if (orig.length === out.length) orig.forEach((l, i) => { if (/^#\s*software version\s*:/i.test(l)) out[i] = l; });
  return out.join('\n');
}

const VENDOR_FNS = {
  fortigate: anonFortiGate, fortiswitch: anonFortiSwitch,
  sophos: anonSophos, checkpoint: anonCheckPoint, paloalto: anonPaloAlto,
  pfsense: anonPfSense, sonicwall: anonSonicWall, mikrotik: anonMikroTik,
  comware: anonComware, h3c_secpath: anonComware, tnsr: anonTNSR, wlc: anonWlc, cisco_ios: anonCiscoIOS, cisco_biz: anonCiscoBiz, fsos: anonFSOS, cisco_nxos: anonCiscoNXOS,
  juniper: anonJuniper, arista: anonArista, aruba_cx: anonArubaCX,
  procurve: anonProCurve,
  dell_os10: anonDellOS10, extreme: anonExtreme, alcatel: anonAlcatel,
  brocade: anonBrocade, ciscoasa: anonCiscoASA, zyxel: anonZyxel,
  edgerouter: anonEdgeRouter, openwrt: anonOpenWrt, vyos: anonVyOS, netfilter: anonNetfilter, cloudsg: anonCloudSG, checkpoint_api: anonCheckPointApi, cumulus: anonCumulus, voss: anonVOSS, efos: anonEFOS, netgearsmart: anonNetgearSmart, tplink: anonTpLink, dlink: anonDLink, zyxelsw: anonZyxelSw, onyx: anonOnyx, awplus: anonAlliedWare,
  planet: anonPlanet, ruijie: anonRuijie, netgear: anonNetgear,
  edgeswitch: anonEdgeSwitch, sonic: anonSonic, watchguard: anonWatchGuard, nps_export: anonNpsExport, netscaler: anonNetScaler, bigip: anonBigip, appenv: anonAppEnv,
  unknown: anonGeneric
};

function anonymize(text, vendor, opts, keepState) {
  // CRLF 正規化：全部廠牌函式皆以 text.split('\n') 逐行處理，大量機敏欄位遮蔽正則是緊貼
  // 字串結尾錨點 $ 的寫法（如 \S+$／.+$），CRLF 換行殘留的尾端 \r 會讓這些正則完全不命中，
  // 導致密碼／PSK／SNMP community／SNMPv3 privacy 密碼等明碼原樣留在「去識別化後」的輸出中，
  // 且 checkResidual() 逐行比對關鍵字也偵測不到（因外洩內容本身不含關鍵字，關鍵字在區塊開頭
  // 另一行），使用者會誤以為輸出已完全乾淨（2026-09 全功能審查發現，比照本專案 switch/firewall
  // 系列工具既有的 CRLF 正規化慣例）
  // 開頭 UTF-8 BOM 會讓第一行的行首錨點遮蔽規則（如 hostname）不命中，一併去除
  text = (text || '').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  LAST_MAC_RANDOM_OUI = !!(opts && opts.macRandomOui);
  // Reset state（第 4 參數 keepState，2026-09-22 新增，預設 falsy＝維持既有「每次呼叫皆重置」
  // 行為不變）：批次模式「批次內共用映射」開關開啟時，runBatch() 會傳入 true 跳過這段重置，
  // 讓 mappings/ctrs/bucketSeen 在整個批次內累積，同一真實值才能在不同檔案間持續得到相同假值；
  // ctrs 務必與 mappings 一起保留，否則新值的遞增序號可能與前一檔案已配發過的序號相撞。
  if (!keepState) {
    mappings.ip.clear(); mappings.hostname.clear(); mappings.user.clear(); mappings.ssid.clear(); mappings.alias.clear(); mappings.vdom.clear(); mappings.mac.clear();
    anonOutputIPs.clear();
    Object.values(subnetMaps).forEach(m => m.clear());
    Object.assign(ctrs, { n1:0, n2:0, n3:0, ip6:0, dev:0, usr:0, ssid:0, alias:0, vdom:0, mac:0 });
    Object.assign(stats, { ip:0, hostname:0, user:0, password:0, key:0, community:0, ssid:0, comment:0, vdom:0, mac:0 });
    // 254 位址回捲警告用的追蹤集合，先前只有 runBatch() 逐檔重置，單檔案流程（本函式）
    // 從未重置過，導致同一 session 內連續處理多份互不相關的檔案時警告會跨檔案累積誤報
    Object.keys(bucketSeen).forEach(k => bucketSeen[k].clear());
    // 比照 runBatch() 的既有修復：重置後若有已匯入的跨工具對照表種子，須重新套用進 live
    // mappings，否則每次執行去識別化都會把剛匯入的假值洗掉、改產生全新假值（見上方 IMPORTED_SEED
    // 宣告處的說明）。
    if (IMPORTED_SEED) seedLiveMappingsFromImported(IMPORTED_SEED);
    srcIPv4.clear(); srcIPv6.clear(); srcFakeNames.clear(); serialMap.clear();
  }
  for (const m of text.matchAll(/(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d])/g)) srcIPv4.add(m[0]);
  for (const m of text.matchAll(/(?<![0-9A-Fa-f:])2001:db8::[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])/gi)) srcIPv6.add(m[0].toLowerCase());
  for (const m of text.matchAll(/(?<![\w.-])(?:[a-z]+-device-\d{3,}|user-\d{3,}(?:@example\.com)?)(?![\w-])/g)) srcFakeNames.add(m[0]);

  const fn = VENDOR_FNS[vendor] || anonGeneric;
  const res = anonDomainNames(anonUrlCredentials(anonPemBlocks(anonContactInfo(anonCommentsFallback(fn(text, opts), opts, vendor))), opts), opts);
  return anonMappedHostnames(anonSerials(anonSnmpV3Users(res, opts), opts), opts);
}
// 目前所有對照的假值（各類別），最後補掃時不可再動到這些值
function currentFakeValues() {
  const set = new Set();
  for (const cat of ['hostname', 'user', 'ssid', 'alias', 'vdom']) for (const v of mappings[cat].values()) set.add(v);
  return set;
}
// 已有對照的原始主機名稱（4 字元以上、不等於任何假值）組成的比對正則；前後不可緊接英數字、底線、點或連字號
function mappedHostnameRe() {
  const fakes = currentFakeValues();
  const keys = [...mappings.hostname.keys()].filter(k => k.length >= 4 && !k.includes('\n') && !fakes.has(k))
    .sort((a, b) => b.length - a.length).map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return keys.length ? new RegExp(`(?<![A-Za-z0-9_.-])(?:${keys.join('|')})(?![A-Za-z0-9_.-])`, 'g') : null;
}
// 主機名稱補掃（不分廠牌）：主機名稱已有對照，但同一名稱還出現在其他地方（Cisco `! hostname X` 註解、
// Junos `set snmp name "X"`、FTD `! ---[ X ]---`、FortiGate `# Hostname: X`、AOS-CX `! Hostname : X`），
// 以同一假值替換（可還原）
function anonMappedHostnames(text, opts) {
  if (opts && opts.hostname === false) return text;
  const re = mappedHostnameRe();
  return re ? text.replace(re, m => mappings.hostname.get(m)) : text;
}
// SNMPv3 帳號名稱（不分廠牌，依各廠牌實際語法）：Cisco 家族／Brocade／Dell OS10 `snmp-server user 名稱`、
// Comware `snmp-agent usm-user v3 名稱`、Extreme `configure snmpv3 add user 名稱`、Junos `set snmp v3 usm local-engine user 名稱`、
// Sophos `set snmpv3 user 名稱`、Netgear Smart／Alcatel `snmp user 名稱`、FortiGate／FortiSwitch `config system snmp user` 內的 edit；
// 已是假值（廠牌函式先處理過）者不再處理
const SNMPV3_USER_RES = [
  /^(\s*snmp-server\s+user\s+)("?)([^\s"]+)/,
  /^(\s*snmp-agent\s+usm-user\s+v3\s+)("?)([^\s"]+)/,
  /^(\s*configure\s+snmpv3\s+add\s+user\s+)("?)([^\s"]+)/,
  /^(\s*set\s+snmp\s+v3\s+usm\s+(?:local-engine|remote-engine\s+\S+)\s+user\s+)("?)([^\s";]+)/,
  /^(\s*set\s+snmpv3\s+user\s+)("?)([^\s"]+)/,
  /^(\s*(?:->\s*)?snmp\s+user\s+)("?)([^\s"]+)/,
];
function anonSnmpV3Users(text, opts) {
  if (!opts || !opts.user) return text;
  const fakes = currentFakeValues();
  let inFgSnmpUser = false, depth = 0;
  return text.split('\n').map(line => {
    const t = line.trim();
    if (t === 'config system snmp user') { inFgSnmpUser = true; depth = 0; return line; }
    if (inFgSnmpUser) {
      if (/^config\s/.test(t)) depth++;
      else if (t === 'end') { if (depth) depth--; else inFgSnmpUser = false; }
      else if (!depth) return line.replace(/^(\s*edit\s+")([^"]+)(")/, (m, p, n, q) => (fakes.has(n) ? m : p + anonUser(n) + q));
      return line;
    }
    for (const re of SNMPV3_USER_RES) {
      const r = line.replace(re, (m, p, q, n) => (fakes.has(n) || /^REDACTED/.test(n) ? m : p + q + anonUser(n)));
      if (r !== line) return r;
    }
    return line;
  }).join('\n');
}
// 設備序號（不分廠牌，tip.serial 承諾序號會被替換）：`Serial Number／Nbr／No／#: 值`、`SN: 值`、`S/N: 值`、
// FortiGate 受管 FortiSwitch `set sn "值"` 與以序號為名稱的 `edit "S124…"`、H3C `serial-id 值`、XML <SerialNumber>、
// MikroTik `# serial number = 值`、Cisco `Processor (board) ID 值`。同一序號對應同一假值，並補換檔案內其他位置的同一序號
// （AOS-CX 硬體表格）；AOS-CX `Base MAC Address : 34c515-000000` 以 MAC 對照替換。版本字串不在這些標籤後，不受影響
const SERIAL_VAL = '([A-Za-z0-9][A-Za-z0-9._/-]{3,})';
const SERIAL_LABEL_RES = [
  new RegExp('(\\bSerial[- ]?(?:Number|Nbr|No\\.?|#)\\s*[:=]\\s*"?)' + SERIAL_VAL, 'gi'),
  new RegExp('(\\bSN\\s*:\\s*)' + SERIAL_VAL, 'g'),
  new RegExp('(\\bS\\/N\\s*[:=]?\\s*)' + SERIAL_VAL, 'g'),
  new RegExp('(^\\s*set\\s+sn\\s+")' + SERIAL_VAL, 'g'),
  new RegExp('(^\\s*serial-id\\s+)' + SERIAL_VAL, 'g'),
  new RegExp('(<SerialNumber>)' + SERIAL_VAL, 'g'),
  new RegExp('(\\bProcessor\\s+(?:board\\s+)?ID\\s*:?\\s*)' + SERIAL_VAL, 'g'),
  /(^\s*edit\s+")(S\d{3}[A-Z0-9]{12})(?=")/g,
];
function fakeSerial(v) {
  if (!serialMap.has(v)) serialMap.set(v, 'SERIAL-X' + String(serialMap.size + 1).padStart(4, '0'));
  return serialMap.get(v);
}
function anonSerials(text, opts) {
  let out = text.split('\n').map(line => {
    for (const re of SERIAL_LABEL_RES) {
      line = line.replace(re, (m, p, v) => (/^(?:SERIAL-X|REDACTED|N\/?A$)/i.test(v) ? m : p + fakeSerial(v)));
    }
    if (opts && opts.mac) line = line.replace(/(\bBase MAC Address\s*:\s*)([0-9A-Fa-f]{6})-([0-9A-Fa-f]{6})\b/, (m, p, a, b) => {
      const hex = anonMAC((a + b).match(/.{2}/g).join(':'), opts).replace(/:/g, '');
      return p + hex.slice(0, 6) + '-' + hex.slice(6);
    });
    return line;
  }).join('\n');
  const keys = [...serialMap.keys()].filter(k => k.length >= 6).map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  if (keys.length) out = out.replace(new RegExp(`(?<![A-Za-z0-9])(?:${keys.join('|')})(?![A-Za-z0-9])`, 'g'), m => serialMap.get(m));
  return out;
}
// 網域名稱（第十八輪 TA）：各廠牌模式原本只遮主機名稱，`ip domain-name`、`domain-name`、FortiGate `set domain`／
// FQDN 位址物件、VPN 對端 `fqdn`、NTP 伺服器主機名稱等內部網域原樣保留，可直接辨識公司。不分廠牌：含 domain／fqdn
// 關鍵字的行與 NTP 行中的網域名稱以主機名稱對照替換（可還原）；公開網域（廠牌雲端、時間伺服器、example）保留
const PUBLIC_DOMAIN_RE = /(?:^|\.)(?:ntp\.org|nist\.gov|time\.gov|google\.com|googleapis\.com|gstatic\.com|windows\.com|microsoft\.com|windowsupdate\.com|apple\.com|cloudflare\.com|amazon\.com|amazonaws\.com|fortinet\.com|fortinet\.net|fortiguard\.com|fortiguard\.net|forticloud\.com|paloaltonetworks\.com|cisco\.com|meraki\.com|juniper\.net|arubanetworks\.com|hpe\.com|ui\.com|ubnt\.com|mikrotik\.com|checkpoint\.com|sonicwall\.com|zyxel\.com|netgate\.com|openwrt\.org|example\.(?:com|net|org)|localdomain)$/i;
const DOMAIN_LINE_RE = /\b(?:domain|domain-name|domain-list|domain-search|dns-domain|search-domain|default-domain|domainname|fqdn)\b|<(?:domain|fqdn|domainname)>|^\s*(?:\S+\s+)*(?:s?ntp|ntp-service|ntp-server)\b/i;
function anonDomainNames(text, opts) {
  if (opts && opts.hostname === false) return text;
  return text.split('\n').map(line => {
    if (!DOMAIN_LINE_RE.test(line) || /^\s*(?:#|!|\/\/)/.test(line)) return line;
    return line.replace(FQDN_RE, (m, fq, tld) => {
      if (FILE_EXT_RE.test(tld) || PUBLIC_DOMAIN_RE.test(fq) || /\.example$/i.test(fq)) return m;
      return anonHostname(fq, 'dom', opts);
    });
  }).join('\n');
}
// PEM 區塊（第十三輪 NA 實跑 Oxidized 的 FortiGate 91G 錄製發現）：FortiGate 的 set private-key／set certificate、
// 其他廠牌貼上的金鑰與憑證都是多行 PEM，逐行規則只處理到開頭那一行，私鑰內文原樣殘留（checkResidual() 只會警示）。
// 不分廠牌，保留 BEGIN／END 行，內文換成 REDACTED_PEM；憑證雖為公開資料，內文可能含內部主機名稱與組織資訊，一併遮蔽
// 網址內嵌帳密（`ftp://帳號:密碼@主機/`，備份／archive 網址常見；第十六輪 PA）不分廠牌處理：密碼換成 REDACTED_PASSWORD，
// 勾選帳號匿名化時帳號也換掉
function anonUrlCredentials(text, opts) {
  return text.replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^\s:@\/"'<>]+):([^\s@\/"'<>]+)@/gi, (m, sch, u, pw) => {
    if (pw === 'REDACTED_PASSWORD') return m;
    stats.password++;
    return sch + (opts && opts.user ? anonUser(u) : u) + ':REDACTED_PASSWORD@';
  }).replace(/\b((?:s?ftp|pasvftp|scp|https?):\/\/)([^\s:@\/"'<>]+)@/gi, (m, sch, u) => (opts && opts.user && !/^user-\d+$/.test(u)) ? sch + anonUser(u) + '@' : m);
}
function anonPemBlocks(text) {
  return text.replace(/(-----BEGIN ([A-Za-z0-9 ]+)-----)([\s\S]*?)(-----END \2-----)/g, (m, b, kind, body, e) => {
    if (/^\s*REDACTED_PEM\s*$/.test(body)) return m;
    stats.key++;
    return b + '\nREDACTED_PEM\n' + e;
  });
}

// 備註／描述補掃（2026-10-02，第 13 輪）：「備註/描述/別名」選項原本只在部分廠牌函式內處理，
// 實測 FortiSwitch、EdgeRouter、pfSense、SonicWall、Sophos、Zyxel、Palo Alto、Check Point、Juniper 等
// 共 121 種描述行勾選後仍原樣留下（常含公司、地點、人名）。改在派送後統一補掃常見寫法；
// 已是 REDACTED_COMMENT 的值不重複計數。SONiC 為 JSON，由 anonSonic() 自行處理。
const COMMENT_FALLBACK_RES = [
  // 行內 description／comment(s)／remark "帶引號值"（FortiSwitch／Juniper／Check Point／Palo Alto set 格式、Alcatel、EdgeRouter）
  [/(\b(?:description|comments?|remark)\s+)"([^"]*)"/g, (m, p, v) => p + '"REDACTED_COMMENT"', 2],
  // Sophos 介面別名 set interface X alias "Y"
  [/^(\s*set\s+interface\s+\S+\s+alias\s+)"([^"]*)"/, (m, p, v) => p + '"REDACTED_COMMENT"', 2],
  // 行首（可有 set）description／comment(s) 不帶引號（EdgeRouter、Zyxel、FortiSwitch）
  [/^(\s*(?:set\s+)?(?:description|comments?)\s+)(?!")([^;\s].*?)(;?)$/, (m, p, v, end) => p + 'REDACTED_COMMENT' + end, 2],
  // BGP neighbor X description 不帶引號（Arista／Cisco 家族）
  [/^(\s*neighbor\s+\S+\s+description\s+)(?!")(.+)$/, (m, p, v) => p + 'REDACTED_COMMENT', 2],
  // ACL 行內 remark（Cisco ASA／IOS 編號 ACL）
  [/^(\s*access-list\s+\S+\s+(?:line\s+\d+\s+)?remark\s+)(.+)$/, (m, p, v) => p + 'REDACTED_COMMENT', 2],
  // XML 標籤（pfSense／OPNsense <descr>、Palo Alto <description>／<comment>、SonicWall <Comment>、Sophos <Description>），含 CDATA
  [/<(descr|description|Description|comment|Comment)>(<!\[CDATA\[[\s\S]*?\]\]>|[^<]+)<\/\1>/g, (m, tag, v) => `<${tag}>REDACTED_COMMENT</${tag}>`, 2],
];
function anonCommentsFallback(text, opts, vendor) {
  if (!opts || !opts.comments || vendor === 'sonic' || vendor === 'cloudsg' || vendor === 'checkpoint_api') return text;
  return text.split('\n').map(line => {
    for (const [re, fn, vi] of COMMENT_FALLBACK_RES) {
      line = line.replace(re, (...a) => {
        const v = String(a[vi] || '');
        if (!v.trim() || /REDACTED_COMMENT|CDATA\[REDACTED_COMMENT/.test(v)) return a[0];
        stats.comment++;
        return fn(...a);
      });
    }
    return line;
  }).join('\n');
}

// 聯絡資訊補掃（2026-10-01）：通用模式（anonGeneric）一律遮蔽 email 與 SNMP 位置／聯絡人（個人資料），
// 但各廠牌專屬函式多數沒有對應規則，實測 11 家廠牌範例去識別化後仍留下 noc@acme-corp.com、
// 「Server Room B2, ACME HQ Taipei」等內容。改在派送後統一補掃，各廠牌行為與通用模式一致。
// 已是 @example.com 的位址（anonEmail() 的輸出）不再處理，避免帳號對照被重複替換。
const CONTACT_LINE_RES = [
  /^(\s*snmp-server\s+(?:location|contact)\s+)(.+)$/i,                        // Cisco 家族／ASA／ProCurve
  /^(\s*snmp-agent\s+sys-info\s+(?:location|contact)\s+)(.+)$/i,              // Comware
  /^(\s*(?:->\s*)?system\s+(?:location|contact)\s+)(.+)$/i,                   // Alcatel
  /^(\s*configure\s+(?:snmp\s+)?sys-?(?:location|contact)\s+)(.+)$/i,         // Extreme
  /^(\s*set\s+contact-info\s+)(.+)$/i,                                        // FortiGate／FortiSwitch
  /^(\s*set\s+(?:.*\s)?snmp(?:-system)?\s+(?:location|contact)\s+)(.+)$/i,    // Juniper／Check Point／Palo Alto set
  /^(\s*(?:location|contact)\s+)("[^"]*")(\s*;\s*)$/i                         // Junos 階層式 snmp { location "…"; }
];
function anonContactInfo(text) {
  return text.split('\n').map(line => {
    if (!/REDACTED/.test(line)) {
      for (const re of CONTACT_LINE_RES) {
        const r = line.replace(re, (m, pre, val, tail) => pre + (val[0] === '"' ? '"REDACTED_COMMENT"' : 'REDACTED_COMMENT') + (tail || ''));
        if (r !== line) { stats.comment++; line = r; break; }
      }
      // MikroTik /snmp set contact=… location=…
      if (/\bcontact=/.test(line)) {
        line = line.replace(/\b(contact|location)=("[^"]*"|\S+)/g, (m, k, v) => { stats.comment++; return k + '=' + (v[0] === '"' ? '"REDACTED_COMMENT"' : 'REDACTED_COMMENT'); });
      }
      // XML：pfSense <syscontact>/<syslocation>、SonicWall <Contact>
      line = line.replace(/(<(syscontact|syslocation|Contact)>)([^<]+)(<\/\2>)/g, (m, o, t, v, c) => { stats.comment++; return o + 'REDACTED_COMMENT' + c; });
    }
    return line.replace(EMAIL_RE, e => (/@example\.com$/i.test(e) ? e : anonEmail(e)));
  }).join('\n');
}

// ============================================================
// [6] RESIDUAL CHECK
// ============================================================
// 對照表搜尋（2026-09-24 新增）：原始值或替換值任一包含查詢字串（不分大小寫）即保留；
// 空查詢回傳全部。entries 為 [原始, 替換] 陣列，純函式供 renderMappingTable() 與測試共用
function filterMappingEntries(entries, query) {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return entries;
  return entries.filter(([orig, anon]) => String(orig).toLowerCase().includes(q) || String(anon).toLowerCase().includes(q));
}
// 殘留警告 CSV（2026-09-24 新增）：rows 為 {line,text,dismissed}；儲存格以 = + - @ 開頭時前綴
// 單引號中和公式注入（比照 CLAUDE.md 跨工具 CSV 匯出既有規範），雙引號逸出後整格加引號
function _residualCsvCell(v) {
  let s = String(v == null ? '' : v);
  if (/^[=+\-@]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}
function buildResidualWarningsCSV(rows, headers) {
  const lines = [headers.map(_residualCsvCell).join(',')];
  rows.forEach(r => lines.push([r.line, r.text, r.dismissed ? 'Y' : ''].map(_residualCsvCell).join(',')));
  return lines.join('\n');
}
// ── 無法解析設定檔回報（2026-09-29 新增）──────────────────────────────────
// 使用者把「分析工具無法辨識廠牌／解析結果過少」的設定檔去識別化後，透過 public repo 的
// issue 表單回報（方案 A：純前端、無後端，頁面不持有任何 GitHub 權杖）。設定檔內容不放進
// 網址（瀏覽器與 GitHub 網址長度有限），改為複製到剪貼簿讓使用者貼到表單欄位，過長時改下載
// .txt 附檔；網址只預填短欄位。回報內容會公開，故送出前強制：已去識別化、填寫上傳原因、
// 看過去識別化前後差異頁、殘留警告全數勾選已審閱、勾選同意公開（reportBlockReason() 依序
// 檢查，回傳第一個未滿足項）
const REPORT_REPO_URL = 'https://github.com/s200070221/alpaca-network-toolkit';
const REPORT_ISSUE_TEMPLATE = 'unparsed-config.yml';
const REPORT_BODY_MAX = 60000;   // GitHub issue 欄位上限 65536 字元，保留餘裕
const REPORT_PREFILL_MAX = 1500; // 網址預填的上傳原因上限
const REPORT_TRIGGERS = ['unknown_vendor', 'sparse', 'manual'];
function reportBlockReason(c) {
  if (!c.anonText) return 'no_output';
  if (!String(c.reason || '').trim()) return 'no_reason';
  if (!c.diffViewed) return 'no_diff';
  if (c.unreviewed > 0) return 'unreviewed';
  if (!c.confirmed) return 'no_confirm';
  return '';
}
// 來自其他工具的中繼資料只保留已知欄位並限制長度（localStorage 內容不可信）
function sanitizeReportMeta(m) {
  m = m || {};
  const str = (v, n) => String(v == null ? '' : v).replace(/[\r\n]+/g, ' ').slice(0, n);
  const stats = {};
  if (m.stats && typeof m.stats === 'object') Object.keys(m.stats).slice(0, 10).forEach(k => {
    const v = m.stats[k]; if (typeof v === 'number' && isFinite(v)) stats[str(k, 30)] = v;
  });
  return { tool: str(m.tool, 40) || 'config_anonymizer', trigger: REPORT_TRIGGERS.includes(m.trigger) ? m.trigger : 'manual',
    vendor: str(m.vendor, 40) || 'unknown', stats };
}
function _reportStatsText(stats) { return Object.keys(stats || {}).map(k => k + '=' + stats[k]).join(', '); }
function buildReportText(meta, form, anonText) {
  const L = ['# alpaca-network-toolkit unparsed config report', '# tool: ' + meta.tool, '# trigger: ' + meta.trigger,
    '# detected_vendor: ' + meta.vendor];
  if (form.model) L.push('# device_model: ' + String(form.model).replace(/[\r\n]+/g, ' '));
  if (meta.hash) L.push('# content_sha256: ' + meta.hash);
  const st = _reportStatsText(meta.stats);
  if (st) L.push('# parse_stats: ' + st);
  L.push('# lines: ' + String(anonText).split('\n').length, '# reason:');
  String(form.reason || '').split(/\r?\n/).forEach(l => L.push('#   ' + l));
  L.push('', '----- BEGIN ANONYMIZED CONFIG -----', anonText, '----- END ANONYMIZED CONFIG -----', '');
  return L.join('\n');
}
function buildReportIssueUrl(meta, form) {
  const q = new URLSearchParams();
  q.set('template', REPORT_ISSUE_TEMPLATE);
  // 標題附內容雜湊前 8 碼（2026-09-29，RE）：同一份內容重複回報時標題相同，triage 時易於辨識
  q.set('title', '[unparsed] ' + meta.vendor + ' / ' + meta.tool + (meta.hash ? ' #' + meta.hash.slice(0, 8) : ''));
  q.set('tool', meta.tool);
  q.set('trigger', meta.trigger);
  q.set('vendor', meta.vendor);
  const st = _reportStatsText(meta.stats);
  if (st) q.set('stats', st);
  if (form.model) q.set('model', String(form.model).slice(0, 200));
  const reason = String(form.reason || '');
  q.set('reason', reason.length > REPORT_PREFILL_MAX ? reason.slice(0, REPORT_PREFILL_MAX) + '…' : reason);
  return REPORT_REPO_URL + '/issues/new?' + q.toString();
}
function reportFileName(meta, ts) {
  const d = new Date(ts), p = n => String(n).padStart(2, '0');
  const safe = v => String(v).replace(/[^\w.-]+/g, '_');
  return `unparsed_${safe(meta.vendor)}_${safe(meta.tool)}_${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}.txt`;
}

// ── 設定檔外洩影響盤點（2026-10-27，第三十四輪 XN22）────────────────────────
// 依據 SonicWall MySonicWall 雲端備份外洩（2025-09，官方要求更換設定檔內所有密碼、PSK、目錄服務帳密、
// SNMP community、API token）。不另寫廠牌規則：沿用各廠牌去識別化已換成 REDACTED_* 的機密欄位，
// 依該行（比不到時依上層區塊標頭）的關鍵字分類。分類關鍵字取自 test_config 全部範例的實際輸出。
// 識別資訊類（COMMENT／LOCATION／EMAIL／SERIAL／ORG／DOMAIN／ENGINEID）與公開的憑證不列。
const LEAK_CAT_ORDER = ['adminCred', 'vpnPsk', 'aaaKey', 'snmpCommunity', 'snmpV3', 'wifi', 'routingAuth', 'privateKey', 'apiToken', 'urlCred', 'otherSecret'];
// 依序比對（先比到者優先）；只放明確關鍵字，單獨的 password／secret／key 不算（需看上層區塊）
// FortiGate 憑證／SSH 本機金鑰的 password 是私鑰保護密碼，歸私鑰；行動網路（wwan／lte／apn）排在無線之前
const LEAK_CAT_RULES = [
  ['privateKey', /private[- ]?key|<prv>|certificate local|ssh local-(key|ca)/],
  ['aaaKey', /radius|tacacs|tacplus|shared[-_]secret|server-private|bindpw|\bldap\b|bind-?pw/],
  ['otherSecret', /wwan|lte-modem|\blte\b|sim-pin|\bapn\b/],
  ['wifi', /\bwpa|set-key|passphrase|\bwlan\b|wi-?fi|wireless|\bssid\b/],
  ['vpnPsk', /pre-?shared|pre-share|psksecret|isakmp|\bipsec\b|\bike(v[12])?\b|<shared_key>|\bpsk\b|phase1|\bvpn\b|openvpn/],
  ['snmpCommunity', /communit/],
  ['snmpV3', /snmp.*\b(user|usm|auth|priv)|authpassword|privpassword|auth-pwd|priv-pwd|snmpv3/],
  ['routingAuth', /\bospf|\bbgp\b|\brip\b|\bisis\b|\bvrrp\b|\bhsrp\b|\bglbp\b|neighbor|message-digest|md5-key|authentication-key|key-string|key chain|\bntp\b/],
  ['apiToken', /api[-_ ]?key|\btoken\b/],
  ['otherSecret', /pppoe|dot1x|\bl2tp\b|\bchap\b|\bha\b|high-availability|cluster|virtual-controller-key|\brepository\b/],
  ['adminCred', /\buser(name|s)?\b|\baccounts?\b|\benable\b|\badmin|\blogin\b|\broot\b|local-user|phash|mgmtuser|webmaster|console-passw|bkup-passw/],
];
const LEAK_TOKEN_RE = /REDACTED_(KEY|HASH|PASSWORD|PSK|SECRET|COMMUNITY|TOKEN|PEM|CERT)\b/;
function _leakRuleCat(s) {
  // 先拿掉佔位字串與假帳號（REDACTED_KEY 的 key、user-001 的 user 不可當成關鍵字）
  const t = String(s).toLowerCase().replace(/redacted_\w+/g, ' ').replace(/\buser-\d+\b/g, ' ');
  const hit = LEAK_CAT_RULES.find(([, re]) => re.test(t));
  return hit ? hit[0] : null;
}
function _leakIndent(l) { return (l.match(/^[ \t]*/) || [''])[0].replace(/\t/g, '    ').length; }
// 上層區塊標頭（縮排較淺的前幾行，最多往上 40 行）；RouterOS 以行首 /path 為區塊；沒有縮排的錄製
// （如 Oxidized 的 Aruba 控制器，以 ! 分隔區塊）改取同一段落往上最多 6 行
function _leakRouterOsHeader(lines, i) {
  if (!/^(add|set)\s/.test(lines[i])) return null;
  for (let k = i - 1; k >= 0 && k >= i - 200; k--) if (/^\//.test(lines[k])) return lines[k];
  return null;
}
function _leakAncestors(lines, i) {
  const out = [];
  let ind = _leakIndent(lines[i]);
  for (let k = i - 1; k >= 0 && k >= i - 40 && ind > 0; k--) {
    if (!lines[k].trim()) continue;
    const d = _leakIndent(lines[k]);
    if (d < ind) { out.push(lines[k]); ind = d; }
  }
  if (!out.length && _leakIndent(lines[i]) === 0) {
    for (let k = i - 1; k >= 0 && k >= i - 6; k--) {
      if (/^\s*(!|#|exit\b|\}|$)/.test(lines[k])) break;
      out.push(lines[k]);
    }
  }
  return out;
}
function leakCategoryOf(lines, i) {
  const line = lines[i];
  if (/:REDACTED_PASSWORD@/.test(line)) return 'urlCred';
  const m = line.match(LEAK_TOKEN_RE);
  if (!m) return null;
  const tok = m[1];
  if (tok === 'CERT') return null;
  if (tok === 'PEM') return /PRIVATE KEY/i.test(lines[i - 1] || '') ? 'privateKey' : null;
  if (tok === 'COMMUNITY') return 'snmpCommunity';
  if (tok === 'TOKEN') return 'apiToken';
  // RouterOS 以區塊（/radius、/user、/ip ipsec peer…）為準，該行的 service=login 之類不算
  let start = i;
  while (start > 0 && /\\\s*$/.test(lines[start - 1])) start--;
  const hdr = _leakRouterOsHeader(lines, start);
  const hc = hdr && _leakRuleCat(hdr);
  if (hc) return hc;
  // 以反斜線續行的指令（RouterOS）合併成一行再判斷
  const own = _leakRuleCat(lines.slice(start, i + 1).join(' '));
  if (own) return own;
  // 上層只比到帳號類（如 YAML 的 username:）時再往上找更明確的類別（如 snmp-server 底下的 SNMPv3 使用者）
  let weak = null;
  const anc = _leakAncestors(lines, i);
  for (const a of anc) {
    const c = _leakRuleCat(a);
    if (c === 'adminCred') weak = weak || c;
    else if (c) return c;
  }
  // 上層有 snmp 區塊（如 Cumulus 的 snmp-server: → username:）時是 SNMPv3 使用者，不是登入帳號
  if (weak) return anc.some(a => /\bsnmp/i.test(a)) ? 'snmpV3' : weak;
  return tok === 'PSK' ? 'vpnPsk' : tok === 'KEY' ? 'otherSecret' : 'adminCred';
}
// restoreLine(行, 索引)：把假值換回原值（畫面上傳入以 STATE.mappings 整份 restoreConfig() 後的對應行），機密值本身不可逆、仍為 REDACTED_*
function buildLeakInventory(anonText, origText, restoreLine) {
  const lines = String(anonText || '').replace(/\r\n?/g, '\n').split('\n');
  const origCount = String(origText || '').replace(/\r\n?/g, '\n').split('\n').length;
  const lineMapped = origCount === lines.length;
  const items = [];
  const byCat = Object.create(null);
  lines.forEach((l, i) => {
    const cat = leakCategoryOf(lines, i);
    if (!cat) return;
    const text = (typeof restoreLine === 'function' ? restoreLine(l, i) : l).trim();
    items.push({ cat, line: i + 1, text });
    (byCat[cat] = byCat[cat] || { count: 0, lines: [] }).count++;
    byCat[cat].lines.push(i + 1);
  });
  return { items, byCat, lineMapped, cats: LEAK_CAT_ORDER.filter(c => byCat[c]) };
}
// 廠牌另有缺口時的註記 key（依各廠牌去識別化函式註解：SonicWall 未處理管理者密碼／PSK／RADIUS 金鑰、
// WatchGuard 未處理密碼類、Sophos／Check Point 規則信心較低、未知廠牌只依關鍵字）
const LEAK_UNCOVERED = { sonicwall: 'leak.gap_sonicwall', watchguard: 'leak.gap_watchguard', sophos: 'leak.gap_lowconf', checkpoint: 'leak.gap_lowconf', unknown: 'leak.gap_unknown' };
// 匯出：rows 欄位 [類別, 行號, 內容, 處理建議, 處理狀態]；CSV 沿用 _residualCsvCell() 中和公式注入
function buildLeakInventoryCSV(inv, label, advice, headers, lineLabel) {
  const out = [headers.map(_residualCsvCell).join(',')];
  inv.items.forEach(it => out.push([label(it.cat), lineLabel(it.line), it.text, advice(it.cat), ''].map(_residualCsvCell).join(',')));
  return out.join('\n');
}
function buildLeakInventoryMarkdown(inv, label, advice, title, lineLabel) {
  const md = ['# ' + title, ''];
  inv.cats.forEach(c => {
    md.push(`## ${label(c)}（${inv.byCat[c].count}）`, '', advice(c), '');
    inv.items.filter(it => it.cat === c).forEach(it => md.push(`- [ ] ${lineLabel(it.line)}: \`${it.text.replace(/`/g, "'")}\``));
    md.push('');
  });
  return md.join('\n');
}

const DOMAIN_KW_RESIDUAL_RE = /\b(?:domain-name|domain|dns-domain|search-domain|domain-list|fqdn)\b(?:\s+|\s*[=:]\s*)"?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b/i;
const INTERNAL_DOMAIN_RE = /\b(?:[A-Za-z0-9-]+\.)+(?:local|lan|corp|internal|intra|intranet|localdomain|home|priv|private)(?![\w.-])/i;
// BGP community 相關設定行（第十七輪 QD，checkResidual() 用）
const BGP_COMMUNITY_LINE_RE = /\b(?:(?:ip|ipv6)\s+(?:ext|large-)?community-list|community-list|(?:set|match|delete|add)\s+(?:ext|large-)?community|policy-options\s+community|aggregate-route\s+community|bgp\s+community|bgp-community|community-count|(?:then|from)\s+community|policy-statement\b.*\bcommunity)\b|^\s*community\s+(?:add|set|delete)\s|^\s*(?:set\s+)?(?:groups\s+\S+\s+)?routing-options\b.*\bcommunity\b|^\s*community\s+\S+\s+(?:members|invert-match)\b/i;
function checkResidual(text) {
  const warnings = [];
  const lines = text.split('\n');
  const sensitiveKw = /\b(password|passwd|secret|psk|community|private.key|auth.key|shared.key|preshared)\b/i;
  // 2026-08-09 補上：上面 sensitiveKw 的 \b 單字邊界對駝峰式 XML 標籤（如
  // <AdminPassword>／<SharedSecret>／<CommunityString>，Sophos/SonicWall 等 XML 系廠牌
  // 慣用命名風格）內部不成立（緊鄰字元同屬 \w，無邊界可比對），已用 Node 實測確認會漏檢。
  // 另補一條規則：比對「標籤名稱含機敏關鍵字」且「內容非空、未遮蔽」的單行 <Tag>value</Tag>
  // 配對，範圍限縮在 XML 標籤上下文，避免無限縮範圍導致誤報率過高。
  const camelTagRe = /<([A-Za-z]*(?:password|passwd|secret|psk|community|sharedkey|presharedkey)[A-Za-z]*)>([^<]+)<\/\1>/gi;
  const hashLike = /[A-Za-z0-9+/=]{24,}/;
  // 雲端服務金鑰前綴啟發式（2026-09 新增）：AWS Access Key ID（AKIA+16碼，共20碼，短於
  // hashLike 的 24 字元門檻抓不到）、GitHub 個人/OAuth/App token（ghp_/gho_/ghu_/ghs_/ghr_，
  // 含底線 `_` 不屬於 hashLike 字元類別，比對常在底線處提前截斷）、Slack token
  // （xoxb-/xoxp-/xoxa-/xoxr-/xoxs-，含連字號同樣會被 hashLike 截斷）、Google API Key
  // （AIza+35碼）、JWT（eyJ 開頭的三段 base64url，以 `.` 分隔，同樣含 hashLike 字元類別外的
  // 符號）。前綴具體度高、誤報率低，各廠牌官方文件與工具（如 AWS/GitHub/Slack 官方文件、
  // git-secrets／trufflehog 等外洩掃描工具）皆公開記載這些固定前綴格式。
  // 2026-09-21 新增：Stripe secret/restricted key（sk_/rk_live|test_，pk_ 開頭是設計上可公開
  // 的 publishable key 刻意不列入）與 npm 自動化 token（npm_），同樣是官方文件明載的固定前綴格式
  const cloudKeyRe = /\b(AKIA[0-9A-Z]{16}|gh[oprsu]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,})\b/;
  const ipLike = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  const macLike = /\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b/;
  // URL 內嵌帳密偵測（2026-09-21 新增）：scheme://user:pass@host 常見於 NTP/syslog/webhook/
  // repo URL 等設定欄位，本工具無對應匿名化函式（結構複雜、各廠牌語法差異大，不硬猜），
  // 純粹找得到就示警，比照既有 email 偵測同一設計精神
  const urlCredRe = /\b[a-z][a-z0-9+.-]*:\/\/[^\s\/@]+:[^\s\/@]+@[^\s\/]+/i;

  // 已有對照的原始主機名稱仍出現在輸出中（含註解行）即示警
  const hostRe = mappedHostnameRe();
  lines.forEach((line, i) => {
    const t = line.trim();
    if (hostRe && t) { hostRe.lastIndex = 0; if (hostRe.test(t)) warnings.push({ line: i + 1, text: t }); }
    if (!t || t.startsWith('#') || t.startsWith('!') || t.startsWith('//')) return;
    // 注意：不可在此整行短路略過（同一行可能同時有「已正確遮罩的欄位」與「規則沒涵蓋到、
    // 仍是明碼的另一個欄位」，例如 `set psk REDACTED_PSK peer 10.20.30.40`）；REDACTED
    // 排除改在下方各檢查點對「實際比對到的內容」個別判斷。

    const lineNum = i + 1;
    // 2026-09-22 擴充：拆分關鍵字清單先前只有 password/passwd/secret/psk/community，未涵蓋
    // sensitiveKw 上面已包含的 auth.key／shared.key／preshared，兩份清單不一致；補齊後兩處
    // 關鍵字判斷一致，避免這幾類欄位在「關鍵字後無實際內容」（如僅提及欄位名稱、無值）情境
    // 下的行為與其餘關鍵字不一致。
    // 關鍵字後只剩冒號、引號或 *（YAML 鍵行的值在下一行、NVUE 的 '*' 代表未設密碼）不算殘留（2026-10-02）
    // `service password-encryption`（Cisco IOS／AW+ 的功能開關）不是密碼
    // Aruba 的 `opmode wpa2-psk-aes` 是加密模式名稱，不是金鑰（2026-10-05）
    // AireOS 的 `wlan security wpa akm psk enable|disable N` 是功能開關
    // BGP 的 `send-community standard|extended|large|both`（Cisco IOS、FRR／TNSR）是功能開關（2026-10-06）
    // Junos 密碼政策（system login password minimum-length 等）、ssh no-password-authentication、MACsec pre-shared-key-chain 名稱不是密碼（第十七輪 QD）
    // 值為 PEM 開頭行（內文已由 anonPemBlocks() 換成 REDACTED_PEM，下一行起才是內文）不算殘留（第十三輪 NA）
    if (/^[^"]*"?-----BEGIN [A-Za-z0-9 ]+-----\s*$/.test(t.replace(/^.*?(?:private.key|certificate|key)\s+/i, '')) && /^REDACTED_PEM\s*$/.test(lines[i + 1] || '')) return;
    // BGP community（路由屬性，不是 SNMP community，第十七輪 QD）：ip community-list、route-map set／match community、
    // Junos policy-options community 名稱 members、靜態／彙總路由的 community、ASA community-list、值為 AS:編號或知名 community
    const bgpComm = !/snmp/i.test(t) && (BGP_COMMUNITY_LINE_RE.test(t) || /\bcommunity\s+\[?\s*(?:\d+:\d+|no-export|no-advertise|local-as|internet|gshut)\b/i.test(t));
    const tk = (bgpComm ? t.replace(/(?:ext|large-?)?community(?:-list)?/gi, '') : t).replace(/\bsend-community\b(?:\s+\S+)?/gi, '').replace(/\bpassword-encryption\b/gi, '').replace(/\bno-password-authentication\b|\bpre-shared-key-chain\b|\bpassword\s+(?:minimum|maximum|change-type|format)[\w-]*\s+\S+/gi, '').replace(/^\s*opmode\s+\S+/i, 'opmode').replace(/\bakm\s+psk\s+(?:enable|disable)\b/i, 'akm');
    if (sensitiveKw.test(tk) && !/^[:'"*\s]*$/.test(tk.replace(/\s+/g, ' ').split(/password|passwd|secret|psk|community|auth.?key|shared.?key|pre.?shared/i).pop().trim())) {
      if (!/REDACTED/.test(t)) warnings.push({ line: lineNum, text: t });
    }
    camelTagRe.lastIndex = 0;
    let camelM;
    while ((camelM = camelTagRe.exec(t)) !== null) {
      const val = camelM[2].trim();
      if (val && !/REDACTED/.test(val)) warnings.push({ line: lineNum, text: t });
    }
    // 網址路徑逐段檢查（GCP 資源 URL 的 compute/v1/projects/… 連起來不是金鑰；webhook 權杖等單一長段仍會命中，第二十一輪 GF）
    // Azure 資源 ID（/subscriptions/…/providers/…）與 GCP 安全標記 ID（tagValues/數字）同樣逐段判斷（第二十二輪 HF／HG）
    const tHash = t.replace(/\bhttps?:\/\/[^\s"'?#]+|\/subscriptions\/[^\s"']+|\btag(?:Values|Keys)\/\d+/gi, u => u.replace(/\//g, ' '));
    if (hashLike.test(tHash) && !/[^\x20-\x7e]/.test(t) && !/REDACTED/.test(t)) {
      const match = tHash.match(hashLike);
      // 只有字母與斜線的長字串（JSON 欄位名稱如 destinationAddressPrefixes、資源類型路徑）不是金鑰；
      // 雜湊／base64 幾乎必含數字或 + =（2026-10-02，雲端 JSON 誤報）
      if (match && !/^[\d.]+$/.test(match[0]) && /[1-9+=]/.test(match[0])) {
        warnings.push({ line: lineNum, text: t });
      }
    }
    // 雲端金鑰前綴命中即視為殘留，不受 hashLike 24 字元門檻限制（seen dedupe 沿用下方既有
    // 機制，若同一行 hashLike 已經命中過，這裡即使重複命中也會在 dedupe 階段被合併成一筆）
    if (cloudKeyRe.test(t) && !/REDACTED/.test(t)) {
      warnings.push({ line: lineNum, text: t });
    }
    if (urlCredRe.test(t) && !/REDACTED/.test(t)) {
      warnings.push({ line: lineNum, text: t });
    }
    // 高熵字串偵測（2026-09-15 新增，預設關閉，見 ENTROPY_CHECK_ENABLED 宣告處說明）：逐 token
    // 切分後對每個夠長、未命中既有 IP/MAC/REDACTED 排除規則的 token 計算熵值
    if (ENTROPY_CHECK_ENABLED) {
      t.split(/[\s"'=,;:]+/).forEach(tok => {
        if (tok.length < ENTROPY_MIN_LEN) return;
        if (ipLike.test(tok) || macLike.test(tok) || /REDACTED/.test(tok)) return;
        if (shannonEntropy(tok) >= ENTROPY_THRESHOLD) warnings.push({ line: lineNum, text: t });
      });
    }
    // 排除已正確匿名化的 IP：anonIP() 一律輸出 RFC5737 文件用網段
    // （192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24），不視為殘留。
    // 一行可能有多個 IP（如 NAT/ACL 常見的 src/dst 對），須逐一檢查每個相符項目，
    // 不能只驗證第一個就判定整行安全（`.match()` 不加 g 只會回傳第一個匹配）
    // 前後還接著「.數字」的是更長的點分數字（SNMP OID 如 1.3.6.1.2.1），不是 IP（2026-10-02）
    // 緊接在 version／Version 之後的是版本號（Aruba 的 version 8.10.0.0-8.10.0），不是 IP（2026-10-05）
    const ipMatches = t.replace(/\bversion\s*:?\s*\d+(?:\.\d+){3}/gi, 'version').match(new RegExp('(?<![\\d.])' + ipLike.source + '(?!\\.\\d)', 'g'));
    // 去識別化刻意保留的位址（0.x 預設路由／萬用遮罩、127.x、224 以上的群播與子網路遮罩，見 classifyIP()）
    // 不算殘留；原本每條預設路由、ACL 萬用遮罩都被列為殘留，匯出時一再跳出確認（2026-10-01）
    if (ipMatches && ipMatches.some(m => !/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(m) && !(isValidIPv4(m) && classifyIP(m) === 'skip'))) {
      warnings.push({ line: lineNum, text: t });
    }
    // IPv6 殘留檢查（2026-07-27 補上）：先前 ipLike 只認 IPv4，checkResidual 對 IPv6 完全
    // 沒有偵測能力——即使某廠牌函式確實有呼叫 anonIPv6()，一旦未來哪次修改不慎漏接，這道
    // 安全網也無法察覺，等同於 IPv6 位址沒有任何救援機制。排除已正確匿名化的 anonIPv6()
    // 固定輸出前綴 2001:db8::，並排除冒號格式 MAC（理由同上方 IPv4/MAC 邏輯，IPv6_RE／
    // MAC_SHAPE_RE 沿用共用引擎定義，不重新定義一份僅供殘留檢查用的近似正則）
    const ip6Matches = t.match(new RegExp(IPv6_RE.source, 'g'));
    // ::／::/0 為「任何 IPv6 位址」，與 0.0.0.0 同樣刻意保留（2026-10-02）
    if (ip6Matches && ip6Matches.some(m => !/^2001:db8::/i.test(m) && !MAC_SHAPE_RE.test(m) && m !== '::' && m !== '::1')) {
      warnings.push({ line: lineNum, text: t });
    }
    // 排除已正確匿名化的 MAC：固定模式（預設）anonMAC() 輸出第一 octet 恆為字面 '02'，可
    //精確比對；MAC OUI 隨機化模式（2026-09-14 新增）第一 octet 改為隨機值，只保證位元模式
    // （locally-administered bit=1 且 multicast bit=0），須改用位元判斷。依 LAST_MAC_RANDOM_OUI
    // 分流，避免固定模式下「剛好符合該位元模式的真實 MAC」（如 aa:bb:cc:dd:ee:ff）被誤判成
    // 已匿名化而漏掉真正的殘留。同樣須逐一檢查每個相符項目（一行可能有多個 MAC）
    const macMatches = t.match(new RegExp(macLike.source, 'g'));
    if (macMatches && macMatches.some(m => {
      const firstByte = parseInt(m.replace(/[:.-]/g, '').slice(0, 2), 16);
      return LAST_MAC_RANDOM_OUI
        ? ((firstByte & 0x02) !== 0x02 || (firstByte & 0x01) !== 0)
        : firstByte !== 0x02;
    })) {
      warnings.push({ line: lineNum, text: t });
    }
    // email／公司網域尾綴偵測（2026-09-14 新增）：email 位址本身沒有對應的 anonXxx()
    // 匿名化函式（本工具原本就不處理 email 欄位），故此處純粹是「找得到就一律示警」，
    // 不像上面 IP/MAC/IPv6 需要排除已正確匿名化的輸出格式
    // 去識別化自己產生的 user-N@example.com 不算（第二十一輪 GF）
    const emailMatches = (t.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || []).filter(m => !/@example\.(?:com|net|org)$/i.test(m));
    if (emailMatches.length) {
      warnings.push({ line: lineNum, text: t });
    }
    // 網域名稱殘留（2026-09-29 新增，RB）：只在「domain-name 類關鍵字後」或「內部網域結尾」時示警，
    // 公開網域（如 pool.ntp.org、廠牌更新伺服器）不列入，避免各廠牌模式大量誤報
    // PAN-OS 設定固定以 localhost.localdomain 當裝置節點名稱（Panorama／防火牆 XML 皆然），不是內部網域（2026-10-05）
    // 公開網域（anonDomainNames() 刻意保留者，第十八輪 TA）不算殘留
    const tDom = t.replace(FQDN_RE, (m, fq) => PUBLIC_DOMAIN_RE.test(fq) ? 'public' : m);
    if (!/REDACTED/.test(t) && (DOMAIN_KW_RESIDUAL_RE.test(tDom) || INTERNAL_DOMAIN_RE.test(tDom.replace(/\blocalhost\.localdomain\b/gi, '')))) {
      warnings.push({ line: lineNum, text: t });
    }
    if (COMPANY_DOMAIN_SUFFIX && t.toLowerCase().includes(COMPANY_DOMAIN_SUFFIX.toLowerCase())) {
      warnings.push({ line: lineNum, text: t });
    }
    // 自訂監看關鍵字（2026-09-23 新增）：純字面字串比對（非正則），逐一比對每個關鍵字，
    // 命中任一即列入殘留警告；與上方 COMPANY_DOMAIN_SUFFIX 同款寫法（大小寫不敏感）
    if (CUSTOM_WATCH_KEYWORDS.length) {
      const tLower = t.toLowerCase();
      for (const kw of CUSTOM_WATCH_KEYWORDS) {
        if (kw && tLower.includes(kw.toLowerCase())) { warnings.push({ line: lineNum, text: t }); break; }
      }
    }
  });

  // PEM/多行機敏區塊殘留偵測（憑證、私鑰等逐行規則無法識別，需整塊比對）
  const pemRe = /-----BEGIN[^-]+-----[\s\S]*?-----END[^-]+-----/g;
  let pemMatch;
  while ((pemMatch = pemRe.exec(text)) !== null) {
    if (!/REDACTED/.test(pemMatch[0])) {
      const lineNum = text.slice(0, pemMatch.index).split('\n').length;
      warnings.push({ line: lineNum, text: pemMatch[0].split('\n')[0] + ' …' });
    }
  }

  // Deduplicate
  const seen = new Set();
  return warnings.filter(w => { const k = w.line + ':' + w.text; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 50);
}
