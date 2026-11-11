// ============================================================
// [9] 事件綁定
// ============================================================
// yieldToUI() 已搬到前面「[1] 中介格式與共用常數」區塊（靠近 buildIntelIndex()，且本身是
// 不依賴 document 的純函式，屬於測試沙箱可抽取範圍，見該處註解）；doAnalyze() 沿用同一份
// 定義讓「階段之間」有機會畫面更新，各階段內部仍是單次同步呼叫，行為不變
function showProgress(labelKey) {
  const el = document.getElementById('progress-label');
  el.classList.add('active');
  document.getElementById('progress-text').textContent = tr(labelKey);
}
function hideProgress() {
  document.getElementById('progress-label').classList.remove('active');
}
// 2026-08-09 稽核修復：doAnalyze() 是 async 函式，過程中多次 await yieldToUI() 讓出主執行緒，
// 依序覆寫模組層級共享狀態（RAW_TEXT/EVENTS/ISSUES/ANON_EVENTS）；按鈕本身沒有在執行期間
// disable，快速連點或上傳新檔後又再次點擊會讓兩次呼叫交錯執行，較新一次可能在較舊一次的
// await 空檔被覆寫，最終畫面可能是兩次執行結果的混合。比照 network_analyzer 既有的
// _dropGen 世代計數器防呆模式：每次呼叫遞增世代號，await 之後比對是否仍是最新一次呼叫，
// 不是則靜默中止（不覆寫任何狀態、不隱藏可能屬於新一次呼叫的進度條）
let _analyzeGen = 0;
// 內建範例（PD，2026-09-29 新增）：第一次使用可一鍵試用；只用 RFC 5737 文件用 IP，並刻意含幾項稽核會標出的問題
const LOG_SAMPLE_TEXT = "<38>1 2026-09-29T08:00:01Z sample-fw01 sshd 1201 - - Failed password for invalid user admin from 203.0.113.50 port 50122 ssh2\n<38>1 2026-09-29T08:00:03Z sample-fw01 sshd 1201 - - Failed password for invalid user admin from 203.0.113.50 port 50124 ssh2\n<38>1 2026-09-29T08:00:05Z sample-fw01 sshd 1201 - - Failed password for invalid user root from 203.0.113.50 port 50126 ssh2\n<38>1 2026-09-29T08:00:07Z sample-fw01 sshd 1201 - - Failed password for invalid user test from 203.0.113.50 port 50128 ssh2\n<38>1 2026-09-29T08:00:09Z sample-fw01 sshd 1201 - - Failed password for invalid user guest from 203.0.113.50 port 50130 ssh2\n<38>1 2026-09-29T08:00:11Z sample-fw01 sshd 1201 - - Failed password for invalid user oracle from 203.0.113.50 port 50132 ssh2\n<38>1 2026-09-29T08:01:10Z sample-fw01 sshd 1202 - - Accepted password for alice from 192.0.2.25 port 50200 ssh2\n<134>Sep 29 08:02:00 sample-fw01 kernel: DROP IN=wan1 SRC=198.51.100.7 DST=192.0.2.10 PROTO=TCP DPT=22\n<134>Sep 29 08:02:01 sample-fw01 kernel: DROP IN=wan1 SRC=198.51.100.7 DST=192.0.2.10 PROTO=TCP DPT=23\n<134>Sep 29 08:02:02 sample-fw01 kernel: DROP IN=wan1 SRC=198.51.100.7 DST=192.0.2.10 PROTO=TCP DPT=80\n<134>Sep 29 08:02:03 sample-fw01 kernel: DROP IN=wan1 SRC=198.51.100.7 DST=192.0.2.10 PROTO=TCP DPT=443\n<134>Sep 29 08:02:04 sample-fw01 kernel: DROP IN=wan1 SRC=198.51.100.7 DST=192.0.2.10 PROTO=TCP DPT=3389\n<134>Sep 29 08:02:05 sample-fw01 kernel: DROP IN=wan1 SRC=198.51.100.7 DST=192.0.2.10 PROTO=TCP DPT=445\nCEF:0|SampleVendor|SampleFW|1.0|100|Traffic denied|5|src=198.51.100.8 dst=192.0.2.20 dpt=3389 proto=TCP act=deny\nCEF:0|SampleVendor|SampleFW|1.0|101|Admin login|3|src=192.0.2.25 suser=alice act=allow outcome=success\n";
function loadSampleLog() { doClear(); document.getElementById('paste-area').value = LOG_SAMPLE_TEXT; doAnalyze(); }

// 分析選項（門檻、情資清單、選擇性偵測）：doAnalyze() 與前期 log 比較（第十二輪 MG）共用，兩期用同一組條件
function collectAnalyzeOpts() {
  const indexes = INTEL_LISTS.map(l => l.index);
  const hashIndexes = HASH_INTEL_LISTS.map(l => l.index);
  const safeIndexes = SAFE_LISTS.map(l => l.index);
  const geoIndexes = GEO_LISTS.map(l => l.index);
  const asnIndexes = ASN_LISTS.map(l => l.index);
  // 2026-08-09 稽核修復：原本用 `||` 取預設值，使用者刻意填 0（HTML min 屬性只是 UI 提示，
  // 手動輸入不受限制）時，`0 || default` 會把合法的 0 當成「未填」而換回預設值，明確設定
  // 被靜默忽略且畫面無任何提示；改用顯式判斷，僅在非有限數字或 ≤0 時才 fallback
  const numOr = (id, def) => { const n = Number(document.getElementById(id).value); return Number.isFinite(n) && n > 0 ? n : def; };
  const windowSec = numOr('opt-freq-window', 60);
  const freqThreshold = numOr('opt-freq-threshold', 5);
  const scanThreshold = numOr('opt-scan-threshold', 5);
  const volumeThreshold = numOr('opt-volume-threshold', 50) * 1024 * 1024;
  const riskCountries = getRiskCountries();
  const riskAsns = getRiskAsns();
  const enable4688 = document.getElementById('opt-enable-4688').checked;
  const procWatchlist = (document.getElementById('opt-proc-watchlist').value || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const enableSysmonProc = document.getElementById('opt-enable-sysmon-proc').checked;
  const sysmonProcWatchlist = (document.getElementById('opt-sysmon-proc-watchlist').value || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const enableSysmonThread = document.getElementById('opt-enable-sysmon-thread').checked;
  const sysmonThreadWatchlist = (document.getElementById('opt-sysmon-thread-watchlist').value || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const enablePsScriptBlock = document.getElementById('opt-enable-ps-scriptblock').checked;
  const psScriptBlockWatchlist = (document.getElementById('opt-ps-scriptblock-watchlist').value || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const enableSysmonImageLoad = document.getElementById('opt-enable-sysmon-imageload').checked;
  const sysmonImageLoadWatchlist = (document.getElementById('opt-sysmon-imageload-watchlist').value || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const enablePsModuleLog = document.getElementById('opt-enable-ps-modulelog').checked;
  const psModuleLogWatchlist = (document.getElementById('opt-ps-modulelog-watchlist').value || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const gapThresholdMin = numOr('opt-gap-threshold', 60);
  // 非上班時間（JB）：時區位移空白時用瀏覽器目前時區；「+8」「-5」「5.5」等小時數
  const val = id => (document.getElementById(id).value || '').trim();
  const tzRaw = val('opt-tz-offset').replace(/^UTC/i, '');
  const tzHours = /^[+-]?\d{1,2}(?:\.\d+)?$/.test(tzRaw) ? Number(tzRaw) : null;
  const offHours = {
    enabled: document.getElementById('opt-enable-offhours').checked,
    start: parseWorkTime(val('opt-work-start'), 8 * 60), end: parseWorkTime(val('opt-work-end'), 18 * 60),
    days: parseWorkDays(val('opt-work-days')),
    tzOffsetMin: tzHours !== null && Math.abs(tzHours) <= 14 ? Math.round(tzHours * 60) : 'local',
    holidays: new Set(val('opt-holidays').split(/[\s,]+/).filter(x => /^\d{4}-\d{2}-\d{2}$/.test(x))),
  };
  const actorHourBaseline = BASELINE_SNAPSHOT && BASELINE_SNAPSHOT.actorHours ? BASELINE_SNAPSHOT.actorHours : null;
  // 橫向移動排除（第三十一輪 HX3）
  const lateralExclude = val('opt-lateral-exclude').split(/[\s,]+/).filter(Boolean);
  const lateralTypes = val('opt-lateral-types').split(/[\s,]+/).filter(x => /^\d{1,2}$/.test(x));
  const actorSourceBaseline = BASELINE_SNAPSHOT && BASELINE_SNAPSHOT.actorSources ? BASELINE_SNAPSHOT.actorSources : null;
  return { indexes, opts: { lateralExclude, lateralTypes, offHours, actorHourBaseline, actorSourceBaseline, windowMs: windowSec * 1000, freqThreshold, scanThreshold, safeIndexes, hashIndexes, volumeThreshold, riskCountries, geoIndexes, riskAsns, hostingAsns: IMPORTED_HOSTING_ASNS, anonVpn: IMPORTED_ANONVPN, rmm: IMPORTED_RMM, rmmAllow: String((document.getElementById('opt-rmm-allow') || {}).value || '').split(/[,，\s]+/).filter(Boolean), asnIndexes, enable4688, procWatchlist, enableSysmonProc, sysmonProcWatchlist, enableSysmonThread, sysmonThreadWatchlist, enablePsScriptBlock, psScriptBlockWatchlist, enableSysmonImageLoad, sysmonImageLoadWatchlist, enablePsModuleLog, psModuleLogWatchlist, gapThresholdMs: gapThresholdMin * 60000, customRules: customDetectRules } };
}
async function doAnalyze() {
  const text = PENDING_LARGE_TEXT !== null ? PENDING_LARGE_TEXT : document.getElementById('paste-area').value;
  if (!text.trim()) return;
  const myGen = ++_analyzeGen;
  const btn = document.getElementById('btn-analyze');
  if (btn) btn.disabled = true;
  try {
    RAW_TEXT = text;
    showProgress('import.progress_parsing');
    await yieldToUI();
    if (myGen !== _analyzeGen) return;
    if (!PARSE_CACHE || PARSE_CACHE.text !== text) {
      // 大檔逐段解析並顯示行數進度（UX26）
      const r = await parseLogTextAsync(text, (n, total) => {
        document.getElementById('progress-text').textContent = tr('import.progress_lines').replace('{n}', n.toLocaleString()).replace('{total}', total.toLocaleString());
      }, () => myGen !== _analyzeGen);
      if (!r || myGen !== _analyzeGen) return;
      PARSE_CACHE = { text, events: r.events, unparsed: r.unparsed };
    }
    const { events, unparsed } = PARSE_CACHE;
    UNPARSED_LINES = unparsed;
    EVENTS = annotateEventsWithSourceFile(events, SOURCE_FILE_BOUNDARIES);
    showProgress('import.progress_analyzing');
    await yieldToUI();
    if (myGen !== _analyzeGen) return;
    const { indexes, opts } = collectAnalyzeOpts();
    ISSUES = buildIssueList(EVENTS, indexes, opts);
    // 漏洞利用嘗試彩蛋（XN20，payload-sniff.js）：log 裡出現攻擊字串是正常內容，只與偵測結果連動
    if (typeof PayloadSniff !== 'undefined') { const xm = PayloadSniff.logMessage(ISSUES, currentLang); if (xm) showEggToast(xm, 7000); }
    ANON_EVENTS = null;
    showProgress('import.progress_correlating');
    await yieldToUI();
    if (myGen !== _analyzeGen) return;
    const numOr = (id, def) => { const n = Number(document.getElementById(id).value); return Number.isFinite(n) && n > 0 ? n : def; };
    const chainWindowMin = numOr('opt-chain-window', 30);
    const chainGroupBy = document.getElementById('opt-chain-groupby').value;
    CHAINS = detectCorrelationChains(ISSUES, { chainWindowMs: chainWindowMin * 60000, groupBy: chainGroupBy });
    showProgress('import.progress_rendering');
    await yieldToUI();
    if (myGen !== _analyzeGen) return;
    renderResults();
    renderTopN();
    renderIssues();
    renderChains();
    renderTimeline();
    renderBaselineDiff();
    logEggsAfterAnalyze();
    renderNextBar();
    // 跨工具活動時間軸（2026-09-23 新增）：寫入 `_netAnalyzer_activityHistory` rolling-history
    // （持續累積歷史，無 TTL，比照 config_anonymizer 既有 `_netAnalyzer_anonHistory` 樣式），
    // 供 network_analyzer hub 合併顯示；分析成功（跑到這裡代表沒有中途 return/拋錯）才寫入
    try {
      let _hist = [];
      try { _hist = JSON.parse(localStorage.getItem('_netAnalyzer_activityHistory') || '[]'); } catch(e) { _hist = []; }
      const _name = (FILE_METADATA && FILE_METADATA.names) ? FILE_METADATA.names : '';
      _hist.unshift({ tool: 'log_analyzer', name: _name, vendor: null, ts: Date.now() });
      localStorage.setItem('_netAnalyzer_activityHistory', JSON.stringify(_hist.slice(0, 5)));
      // 綜合健檢報告（2026-09-30 新增，第八輪 XA）：`_netAnalyzer_summaries` 同一工具＋名稱只留最新一筆、最多 20 筆；
      // 只存事件數、問題數（高／中風險、未處理）與前三項問題名稱，不存 log 原文
      let _sum = [];
      try { _sum = JSON.parse(localStorage.getItem('_netAnalyzer_summaries') || '[]'); } catch(e) { _sum = []; }
      if (!Array.isArray(_sum)) _sum = [];
      const _top = ISSUES.slice().sort((a, b) => SEV_RANK[a.severityNorm] - SEV_RANK[b.severityNorm] || b.count - a.count).slice(0, 3)
        .map(is => ({ label: issueCategoryLabel(is.category), count: is.count, sev: is.severityNorm }));
      const _entry = { tool: 'log_analyzer', name: _name, vendor: null, ts: Date.now(), events: EVENTS.length, n: ISSUES.length,
        crit: ISSUES.filter(is => is.severityNorm === 'Critical' || is.severityNorm === 'High').length,
        warn: ISSUES.filter(is => is.severityNorm === 'Medium').length,
        open: ISSUES.filter(is => issueStatusOf(_baselineDiffKey(is)) === 'open').length, top: _top };
      // 問題數趨勢（第二十五輪 LH）：覆蓋前把同一來源上一筆的問題數放進 history，最多 5 筆
      const _prev = _sum.find(x => x && x.tool === 'log_analyzer' && x.name === _name);
      // 兩分鐘內重新分析（例如載入前期 log 後自動重跑）視為同一次，不另記一筆歷史
      _entry.history = !_prev ? [] : (Date.now() - (_prev.ts || 0) < 120000 ? (Array.isArray(_prev.history) ? _prev.history : [])
        : [{ ts: _prev.ts, n: _prev.n, crit: _prev.crit }].concat(Array.isArray(_prev.history) ? _prev.history : []).slice(0, 5));
      _sum = _sum.filter(x => !(x && x.tool === 'log_analyzer' && x.name === _name));
      _sum.unshift(_entry);
      localStorage.setItem('_netAnalyzer_summaries', JSON.stringify(_sum.slice(0, 20)));
    } catch(e) { /* localStorage 滿了或被封鎖時靜默略過，不影響分析主流程 */ }
  } finally {
    if (myGen === _analyzeGen) { hideProgress(); if (btn) btn.disabled = false; }
  }
}
// 分析結果提示列（第二十九輪 NU7／NU9）：有事件時列出事件數、問題數與三個主要下一步；有內容卻一筆事件都解析不出來時
//（多半是貼錯工具，例如設定檔）提示交給入口頁判斷（一次性交接 key `_netAnalyzer_route`）
// 首次使用導覽（第二十九輪 NU6）：上傳區的三步驟提示，持續性 key `_netAnalyzer_tourSeen`（{工具:1}，已加入入口頁 WS_KEYS）；
// 按「知道了」或第一次分析出結果後不再顯示。行內卡片不覆蓋畫面
function _tourSeen(){try{return JSON.parse(localStorage.getItem('_netAnalyzer_tourSeen')||'{}')||{};}catch(e){return {};}}
function tourInit(){const el=document.getElementById('tour');if(el&&!_tourSeen()['log'])el.hidden=false;}
function tourDone(){const el=document.getElementById('tour');if(el)el.hidden=true;try{const s=_tourSeen();if(s['log'])return;s['log']=1;localStorage.setItem('_netAnalyzer_tourSeen',JSON.stringify(s));}catch(e){}}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',tourInit);else tourInit();
// 匯入區收合（UX18）：有事件才收合；使用者點貼上框或「展開匯入區」即展開，之後重新分析會再收合
function setImportCompact(on) {
  const card = document.getElementById('import-card');
  if (!card) return;
  card.classList.toggle('compact', !!on);
  if (!on) return;
  const src = (document.getElementById('file-loaded-label').textContent || '').trim() || tr('import.compact_paste');
  document.getElementById('import-compact-text').textContent = tr('import.compact').replace('{src}', src).replace('{n}', EVENTS.length.toLocaleString());
  document.getElementById('btn-import-edit').textContent = tr('import.edit');
}
function renderNextBar() {
  setImportCompact(!!(RAW_TEXT || '').trim() && EVENTS.length > 0);
  renderHealthStatic();  // 分析完成的各路徑都會呼叫這裡，健檢分數一併更新（UX07）
  renderRotation();  // 憑證處置清單同時更新（XN91）
  document.body.classList.toggle('no-results', !EVENTS.length);  // 分析前不顯示空的結果卡片（UX36）
  const b = document.getElementById('next-bar');
  if (!b) return;
  const text = RAW_TEXT || '';
  if (!text.trim()) { b.style.display = 'none'; b.innerHTML = ''; if (window.AlpacaBuddy) window.AlpacaBuddy.setDuty(null); return; }
  b.style.display = 'flex';
  if (!EVENTS.length) {
    // 解析不出事件時說出原因並連到取得檔案說明（XN53，file-howto.js）
    const fh = window.FileHowto, k = fh ? fh.classify({ text }) : 'text';
    b.innerHTML = `<span>⚠ ${esc(tr('nextbar.empty'))}${fh ? ' ' + esc(fh.explain(k, currentLang)) : ''}</span><button class="btn" onclick="routeToHub()">${esc(tr('nextbar.route'))}</button>`
      + (fh ? `<button class="btn" data-empty-howto onclick="FileHowto.open()">${esc(fh.title(currentLang))}</button>` : '');
    if (window.AlpacaBuddy) window.AlpacaBuddy.setDuty(null);
    return;
  }
  tourDone();
  // 標籤是「嚴重 {n} 項」，只計 Critical（與交換器、防火牆一致）
  const high = ISSUES.filter(i => i.severityNorm === 'Critical').length;
  // 羊駝值勤模式（XN49）：有嚴重問題時戴安全帽，泡泡只說先看哪一項
  if (window.AlpacaBuddy) window.AlpacaBuddy.setDuty(high ? { n: high, top: issueCategoryLabel(ISSUES.find(i => i.severityNorm === 'Critical').category), go: () => document.getElementById('issues-card').scrollIntoView({ behavior: 'smooth', block: 'start' }) } : null);
  const go = id => `document.getElementById('${id}').scrollIntoView({behavior:'smooth',block:'start'})`;
  b.innerHTML = `<span style="font-weight:600">${esc(tr('nextbar.log_summary').replace('{events}', EVENTS.length).replace('{issues}', ISSUES.length))}${high ? ` · <span style="color:var(--red)">${esc(tr('nextbar.crit').replace('{n}', high))}</span>` : ''}</span>`
    // 0 個問題不等於安全（XN48）：只代表已支援的偵測規則沒有命中
    + (ISSUES.length ? '' : `<span data-zero-note style="font-size:12px;color:var(--text-dim)">${esc(tr('nextbar.zero_note'))}</span>`)
    + `<button class="btn" onclick="${go('issues-card')}">${esc(tr('nextbar.issues'))}</button><button class="btn" onclick="exportLogReport()">${esc(tr('nextbar.report'))}</button><button class="btn" onclick="${go('deid-card')}">${esc(tr('nextbar.share'))}</button>`
    // 已對照防火牆設定的組數（XN131）
    + (FW_VERDICTS.size ? (() => { let a = 0, d = 0; FW_VERDICTS.forEach(v => { if (v.action === 'accept') a++; else if (v.action === 'deny') d++; });
      return `<span data-fwv-sum style="font-size:12px;color:var(--text-dim)" title="${esc(tr('fwv.report_note'))}">🛡 ${esc(tr('fwv.summary').replace('{a}', a).replace('{d}', d))}</span>`; })() : '')
    // 區段導覽（UX36）：結果列固定在頂端，只列目前有內容的區段
    + `<nav class="nb-nav">` + [['health-card', tr('nav.health')], ['results-card', tr('nav.events')], CHAINS.length ? ['correlation-card', tr('nav.chains') + ' ' + CHAINS.length] : null]
      .filter(Boolean).map(x => `<button data-nb-go="${x[0]}" onclick="${go(x[0])}">${esc(x[1])}</button>`).join('') + `</nav>`;
}
function routeToHub() {
  const text = RAW_TEXT || document.getElementById('paste-area').value || '';
  if (!text.trim()) return;
  let wrote = false;
  try { localStorage.setItem('_netAnalyzer_route', JSON.stringify({ name: (FILE_METADATA && FILE_METADATA.names) || '', text, from: 'log', ts: Date.now() })); wrote = true; } catch (e) { alert(tr('err.storage_full')); return; }
  const w = window.open('network-analyzer.html', '_blank');
  if (wrote && !w) { try { localStorage.removeItem('_netAnalyzer_route'); } catch (e) {} alert(tr('err.popup_blocked')); }
}
function doClear() {
  document.getElementById('paste-area').value = '';
  document.getElementById('file-loaded-label').textContent = '';
  document.getElementById('large-file-notice').style.display = 'none';
  PENDING_LARGE_TEXT = null;
  FW_VERDICTS = new Map();  // 防火牆設定對照結果一併清空（XN131）
  RAW_TEXT = ''; EVENTS = []; ISSUES = []; CHAINS = []; ANON_EVENTS = null; UNPARSED_LINES = []; PARSE_CACHE = null;
  SOURCE_FILE_BOUNDARIES = []; RESULTS_FILE_FILTER = '';
  FILE_METADATA = null;
  renderResults(); renderTopN(); renderFileMetadata(); renderIssues(); renderChains(); renderTimeline(); renderBaselineDiff();
  renderNextBar();
}
// 支援一次選取/拖放多個檔案：依原始順序平行讀取後 join 成單一文字餵給既有分析流程，
// 大檔案門檻判斷改用合併後的總行數/總位元組數；file 參數同時相容單一 File（Array.isArray
// 防呆），呼叫端一律傳陣列
// 2026-08-09 稽核修復：連續兩次選檔/拖放時，較慢的一次（如較大檔案）晚完成會覆蓋較快一次
// 已寫入的 PENDING_LARGE_TEXT／file-loaded-label，造成顯示與實際暫存內容不一致；比照
// doAnalyze() 與 network_analyzer 既有的 _dropGen 模式加上世代計數器
let _uploadGen = 0;
function doUploadFile(files) {
  const fileList = Array.isArray(files) ? files : [files];
  const myGen = ++_uploadGen;
  Promise.all(fileList.map(f => readUploadEntries(f))).then(async lists => {
    if (myGen !== _uploadGen) return;
    // zip 內的檔案各自當成一個來源檔（第二十五輪 LC）
    const entries = lists.flat();
    const contents = entries.map(e => e.text);
    const trimmed = contents.map(c => c.replace(/\s+$/, ''));
    const text = trimmed.join('\n');
    // 多檔上傳真正分組（2026-09 新增）：依各檔實際貢獻的行數建立行號→檔名對照表，僅在
    // 2 個以上檔案時才有分組意義（單檔上傳/貼上文字維持既有無分組行為，見 resolveSourceFile()）
    let cursor = 1;
    SOURCE_FILE_BOUNDARIES = entries.map((f, i) => {
      const lineCount = (trimmed[i].match(/\n/g) || []).length + 1;
      const startLine = cursor;
      cursor += lineCount;
      return { name: f.name, startLine, endLine: cursor - 1 };
    });
    // .gz 以解壓後大小判斷大型檔案門檻
    const totalSize = entries.reduce((sum, f, i) => sum + Math.max(f.size, contents[i].length), 0);
    const lineCount = (text.match(/\n/g) || []).length + 1;
    const names = entries.map(f => f.name).join(', ');
    const notice = document.getElementById('large-file-notice');
    const textarea = document.getElementById('paste-area');
    if (lineCount > LARGE_FILE_LINE_THRESHOLD || totalSize > LARGE_FILE_BYTE_THRESHOLD) {
      PENDING_LARGE_TEXT = text;
      textarea.value = '';
      notice.textContent = tr('import.large_file_notice').replace('{name}', names).replace('{lines}', lineCount.toLocaleString());
      notice.style.display = 'block';
    } else {
      PENDING_LARGE_TEXT = null;
      textarea.value = text;
      notice.style.display = 'none';
    }
    document.getElementById('file-loaded-label').textContent = tr('import.file_loaded') + names;
    const rawJoined = contents.join('\n');
    const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawJoined));
    if (myGen !== _uploadGen) return;
    const sha256 = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    FILE_METADATA = { names, totalSize, lineCount, sha256, uploadedAt: new Date().toISOString() };
    renderFileMetadata();
  }).catch(e => { if (myGen === _uploadGen) alert(tr(/^zip/.test(e && e.message) ? 'msg.zip_unsupported' : 'msg.file_read_error')); });
}
// 2026-08-10 稽核修復：三個上傳函式先前完全同步執行（含 buildIntelIndex() 建索引），大型
// 清單會讓畫面凍結、看起來像當掉；改為 async + await buildIntelIndex()（本身已分段 yield），
// 並在處理期間 disable 對應按鈕當作「處理中」的視覺回饋（比照 doAnalyze() 既有 disabled 寫法，
// 不新增文字/UI 元素以避免觸發 11 語言 i18n 新增 key 的額外工作量）
// 2026-08-10 稽核修復：真實規模 GeoIP/情資清單即使已分段 yield 仍需數秒到十餘秒處理時間，
// 純 disabled 按鈕沒有任何「還在動」的視覺回饋，容易被誤以為卡死；改把百分比數字直接附加在
// 按鈕自己的文字後面（如「上傳清單 47%」），完成後還原——數字語言中立，不需另外新增 i18n key
function doIntelUpload(file, name, date) {
  const reader = new FileReader();
  reader.onload = async () => {
    const btn = document.getElementById('btn-intel-add');
    const origLabel = btn ? btn.textContent : '';
    if (btn) btn.disabled = true;
    try {
      const list = parseIntelList(reader.result, name || file.name);
      const index = await buildIntelIndex(list, (done, total) => { if (btn) btn.textContent = origLabel + ' ' + Math.floor(done / total * 100) + '%'; });
      INTEL_LISTS.push({ name: list.name, date: date || '', index });
      renderIntelList();
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = origLabel; }
    }
  };
  reader.readAsText(file);
}
// 雜湊威脅情資清單上傳（2026-09-18 新增，「不需真實範例的 6 項新功能」第 3 項）：完整比照
// doIntelUpload() 既有慣例；parseIntelList()/buildIntelIndex() 本來就格式中立（非 IP 專屬，
// 純文字檔逐行第一個 token 當作一筆值），純文字雜湊清單（每行一個雜湊）不需要任何新解析邏輯
function doHashIntelUpload(file, name, date) {
  const reader = new FileReader();
  reader.onload = async () => {
    const btn = document.getElementById('btn-hashintel-add');
    const origLabel = btn ? btn.textContent : '';
    if (btn) btn.disabled = true;
    try {
      const list = parseIntelList(reader.result, name || file.name);
      const index = await buildIntelIndex(list, (done, total) => { if (btn) btn.textContent = origLabel + ' ' + Math.floor(done / total * 100) + '%'; });
      HASH_INTEL_LISTS.push({ name: list.name, date: date || '', index });
      renderHashIntelList();
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = origLabel; }
    }
  };
  reader.readAsText(file);
}
function doSafelistUpload(file, name) {
  const reader = new FileReader();
  reader.onload = async () => {
    const btn = document.getElementById('btn-safelist-add');
    const origLabel = btn ? btn.textContent : '';
    if (btn) btn.disabled = true;
    try {
      const list = parseIntelList(reader.result, name || file.name);
      const index = await buildIntelIndex(list, (done, total) => { if (btn) btn.textContent = origLabel + ' ' + Math.floor(done / total * 100) + '%'; });
      SAFE_LISTS.push({ name: list.name, index });
      renderSafeList();
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = origLabel; }
    }
  };
  reader.readAsText(file);
}
// 方案 A（純文字/CSV，表頭需含 country 欄位）走既有 parseIntelList()＋readAsText；方案 B
// （v2fly/Xray geoip.dat 二進位）依副檔名 .dat 走 parseGeoIPDat()＋readAsArrayBuffer，兩條路徑
// 最終都餵給同一個 buildIntelIndex()，索引結構與後續查詢完全共用
function doGeoUpload(file, name) {
  const isDat = /\.dat$/i.test(file.name);
  const reader = new FileReader();
  reader.onload = async () => {
    const btn = document.getElementById('btn-geo-add');
    const origLabel = btn ? btn.textContent : '';
    if (btn) btn.disabled = true;
    try {
      const list = isDat ? parseGeoIPDat(reader.result) : parseIntelList(reader.result, name || file.name);
      if (name) list.name = name;
      const index = await buildIntelIndex(list, (done, total) => { if (btn) btn.textContent = origLabel + ' ' + Math.floor(done / total * 100) + '%'; });
      GEO_LISTS.push({ name: list.name, index });
      renderGeoList();
      renderGeoRiskChecks();
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = origLabel; }
    }
  };
  if (isDat) reader.readAsArrayBuffer(file); else reader.readAsText(file);
}
// ASN 資料庫僅有純文字/CSV/TSV 格式（IPtoASN.com／DB-IP IP to ASN Lite／IPinfo.io 三個來源
// 皆是，見 parseAsnDatabase() 自身的委派邏輯自動判斷分隔符），不像 GeoIP 需要分流處理二進位
// .dat 格式，故只需一條 readAsText 路徑
function doAsnUpload(file, name) {
  const reader = new FileReader();
  reader.onload = async () => {
    const btn = document.getElementById('btn-asn-add');
    const origLabel = btn ? btn.textContent : '';
    if (btn) btn.disabled = true;
    try {
      const list = await parseAsnDatabase(reader.result, name || file.name, (done, total) => { if (btn) btn.textContent = origLabel + ' ' + Math.floor(done / total * 100) + '%'; });
      const index = await buildIntelIndex(list, (done, total) => { if (btn) btn.textContent = origLabel + ' ' + Math.floor(done / total * 100) + '%'; });
      ASN_LISTS.push({ name: list.name, index });
      renderAsnList();
      renderAsnRiskChecks();
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = origLabel; }
    }
  };
  reader.readAsText(file);
}
function doRunDeid() {
  if (!EVENTS.length) return;
  const preserveLastOctet = document.getElementById('deid-preserve-last-octet')?.checked || false;
  const preserveSubnet = document.getElementById('deid-preserve-subnet')?.checked || false;
  ANON_EVENTS = anonymizeEvents(EVENTS, { preserveLastOctet, preserveSubnet });
  renderDeidSummary();
}
// 比照 config_anonymizer 既有 renderAnonSummary() 慣例，跑完後在按鈕列下方顯示一行
// 精簡統計（僅顯示 >0 的類別），全部為 0 時整段隱藏不佔版面
function renderDeidSummary() {
  const el = document.getElementById('deid-summary');
  if (!el) return;
  const items = [
    [stats.ip, tr('deid.stat_ip')],
    [stats.hostname, tr('deid.stat_hostname')],
    [stats.user, tr('deid.stat_user')],
    [stats.mac, tr('deid.stat_mac')],
  ].filter(([n]) => n > 0);
  const bucketLabels = { n1: '192.168.x.x', n2: '10.x.x.x', n3: '172.16-31.x.x' };
  const overflow = Object.keys(bucketSeen).filter(k => bucketSeen[k].size > 254);
  if (!items.length && !overflow.length) { el.style.display = 'none'; return; }
  let html = items.length
    ? '<span class="sum-label">' + tr('deid.stat_replaced') + '：</span>' +
      items.map(([n, l]) => `<span class="sum-item"><b>${n}</b>${l}</span>`).join('')
    : '';
  overflow.forEach(k => {
    html += `<span class="sum-item" style="color:var(--red)">${tr('deid.stat_bucket_overflow').replace('{range}', bucketLabels[k]).replace('{count}', bucketSeen[k].size)}</span>`;
  });
  el.innerHTML = html;
  el.style.display = 'flex';
}
function doDownloadDeid() {
  if (!ANON_EVENTS) doRunDeid();
  const text = tr('notice.disclaimer') + '\n' + anonEventsToText(ANON_EVENTS) + '\n';
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'log_deidentified.txt'; a.click();
  URL.revokeObjectURL(url);
}
// 匯出對照表（跨工具聯動，見 config_anonymizer 的對應 exportMapping()）：讓另一個工具
// （或本工具下次匯入）可以沿用同一組假值，比照 config_anonymizer 的 Blob/download 寫法
function exportMapping() {
  if (!ANON_EVENTS) doRunDeid();
  const obj = {
    sourceTool: 'log_analyzer',
    generatedAt: new Date().toISOString(),
    mappings: {
      ip: Object.fromEntries(mappings.ip),
      hostname: Object.fromEntries(mappings.hostname),
      user: Object.fromEntries(mappings.user),
      mac: Object.fromEntries([...mappings.mac].map(([k, v]) => [k, (v && v.hex) || v]))
    }
  };
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'log-anonymize-mapping.json'; a.click();
  URL.revokeObjectURL(url);
}
// 檔案雜湊/監管鏈中繼資料匯出（2026-09-14 新增）：比照 exportMapping() 的 Blob+<a download>
// JSON 匯出樣式，單筆記錄非表格故不比照 doExportCSV()
function doExportFileMetadata() {
  if (!FILE_METADATA) return;
  const obj = { sourceTool: 'log_analyzer', ...FILE_METADATA };
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'log-file-metadata.json'; a.click();
  URL.revokeObjectURL(url);
}
// 基準線比對模式（2026-09-15 新增）：比照 exportMapping()/importMappingFile() 的 JSON 檔案
// 匯出/匯入樣式（非 localStorage——基準線屬於分析輸出資料，與 SAFE_LISTS/INTEL_LISTS 刻意
// 不持久化的既有原則一致）。BASELINE_SNAPSHOT 為 null 代表尚未載入任何基準線。
let BASELINE_SNAPSHOT = null;
function exportBaseline() {
  const _o = collectAnalyzeOpts().opts;
  const obj = buildBaselineSnapshot(ISSUES, EVENTS, _o.offHours.tzOffsetMin, _o);
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'log-baseline.json'; a.click();
  URL.revokeObjectURL(url);
}
function importBaselineFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    let parsed;
    try { parsed = JSON.parse(reader.result); }
    catch (e) { alert(tr('msg.baseline_import_invalid')); return; }
    if (!parsed || !Array.isArray(parsed.issues)) { alert(tr('msg.baseline_import_invalid')); return; }
    BASELINE_SNAPSHOT = parsed;
    const label = document.getElementById('baseline-import-status');
    if (label) {
      label.textContent = tr('msg.baseline_imported').replace('{n}', parsed.issues.length);
      label.style.display = '';
    }
    if (EVENTS.length && (parsed.actorHours || parsed.actorSources)) doAnalyze(); else renderBaselineDiff();
  };
  reader.readAsText(file, 'UTF-8');
}
function onBaselineImportSelect(e) { if (e.target.files[0]) importBaselineFile(e.target.files[0]); }
// 前期 log（第十二輪 MG）：以目前的分析條件（collectAnalyzeOpts()）分析前期 log，只保留問題摘要（不留事件原文），
// 存成與基準線相同形狀的快照並附期間；多個檔案合併成一期
function loadPrevPeriodLog(files) {
  const list = Array.from(files || []);
  if (!list.length) return;
  Promise.all(list.map(f => readTextFile(f))).then(texts => {
    const { events } = parseLogText(texts.join('\n').replace(/\r\n/g, '\n'));
    if (!events.length) { alert(tr('msg.prev_log_empty')); return; }
    const { indexes, opts } = collectAnalyzeOpts();
    opts.actorHourBaseline = null;
    opts.actorSourceBaseline = null;
    const issues = buildIssueList(events, indexes, opts);
    const range = eventsTimeRange(events);
    const fmt = t => new Date(t).toLocaleString();
    BASELINE_SNAPSHOT = Object.assign(buildBaselineSnapshot(issues, events, opts.offHours.tzOffsetMin, opts), { period: { name: list.map(f => gzipFileLabel(f.name)).join(', '), events: events.length, from: range ? range.from : null, to: range ? range.to : null } });
    const label = document.getElementById('baseline-import-status');
    if (label) {
      label.textContent = tr('msg.prev_log_loaded').replace('{name}', BASELINE_SNAPSHOT.period.name).replace('{n}', events.length)
        .replace('{range}', range ? fmt(range.from) + ' ~ ' + fmt(range.to) : '-');
      label.style.display = '';
    }
    // 已有分析結果時重新分析，帶入帳號常用時段基線
    if (EVENTS.length) doAnalyze(); else renderBaselineDiff();
  }).catch(e => alert(tr(/^zip/.test(e && e.message) ? 'msg.zip_unsupported' : 'msg.file_read_error')));
}
// 比較表（第十二輪 MG 改寫）：基準線 JSON 與前期 log 共用，列出新增／消失／持續與筆數變化。
// snap.period（前期 log 才有）存在時欄位稱「前期／本期」，否則「基準線／目前」
function buildBaselineDiffHtml(cmp, snap) {
  if (!cmp || !cmp.rows.length) return `<div class="empty">${tr('baseline.no_diff')}</div>`;
  const isLog = !!(snap && snap.period);
  const st = { added: tr('baseline.status_added'), removed: tr('baseline.status_removed'), persist: tr('baseline.status_persist') };
  const color = { added: 'var(--red)', removed: 'var(--green)', persist: 'var(--text-dim)' };
  const cell = v => v ? `${esc(v.severityNorm)} / ${v.count}` : '-';
  const chg = r => r.status !== 'persist' ? '' : r.delta > 0 ? `<span style="color:var(--red)">▲ ${r.delta}</span>` : r.delta < 0 ? `<span style="color:var(--green)">▼ ${-r.delta}</span>` : '0';
  const s = cmp.summary;
  let html = `<div style="font-size:12px;margin-bottom:6px">${esc(tr('baseline.summary').replace('{added}', s.added).replace('{removed}', s.removed).replace('{persist}', s.persist).replace('{up}', s.up).replace('{down}', s.down))}</div>`;
  const rows = cmp.rows.map(r => `<tr><td style="color:${color[r.status]}">${esc(st[r.status])}</td><td>${esc(issueCategoryLabel(r.category))}${r.key !== r.category ? ` <span style="color:var(--text-dim);font-size:11px">${esc(r.key.slice(r.category.length + 1))}</span>` : ''}</td><td>${cell(r.old)}</td><td>${cell(r.new)}</td><td>${chg(r)}</td></tr>`).join('');
  return html + `<div class="tbl-wrap"><table><thead><tr><th>${tr('baseline.col_status')}</th><th>${tr('baseline.col_category')}</th><th>${tr(isLog ? 'period.col_prev' : 'baseline.col_old')}</th><th>${tr(isLog ? 'period.col_cur' : 'baseline.col_new')}</th><th>${tr('baseline.col_change')}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
function renderBaselineDiff() {
  const el = document.getElementById('baseline-diff-result');
  if (!el) return;
  if (!BASELINE_SNAPSHOT) { el.innerHTML = ''; return; }
  el.innerHTML = buildBaselineDiffHtml(comparePeriods(BASELINE_SNAPSHOT.issues, ISSUES), BASELINE_SNAPSHOT);
}
// 靜態文字（標題/按鈕）比照 renderHealthStatic() 既有模式，每次 setLang()/renderAll() 重繪
function renderBaselineStatic() {
  document.getElementById('t-baseline-title').textContent = tr('baseline.title');
  document.getElementById('btn-baseline-export').textContent = tr('baseline.export_btn');
  document.getElementById('btn-baseline-import').textContent = tr('baseline.import_btn');
  document.getElementById('btn-prev-log').textContent = tr('baseline.prev_log_btn');
  document.getElementById('btn-prev-log').title = tr('baseline.prev_log_tip');
}
// 匯入既有對照表：讀取使用者上傳的 mapping.json（本工具或 config_anonymizer 匯出皆可），
// 套用 applyImportedMappings() 後回饋匯入筆數。DOM 相關，不進純函式測試沙箱。
function importMappingFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    let parsed;
    try { parsed = JSON.parse(reader.result); }
    catch (e) { alert(tr('msg.mapping_import_invalid')); return; }
    const { applied, skipped } = applyImportedMappings(parsed);
    const total = Object.values(applied).reduce((a, b) => a + b, 0);
    if (total === 0 && skipped === 0) { alert(tr('msg.mapping_import_invalid')); return; }
    const label = document.getElementById('mapping-import-status');
    if (label) {
      label.textContent = tr('msg.mapping_imported').replace('{n}', total);
      label.style.display = '';
    }
  };
  reader.readAsText(file, 'UTF-8');
}
function onMappingImportSelect(e) { if (e.target.files[0]) importMappingFile(e.target.files[0]); }
// 2026-09 資安審查修復：CSV 儲存格若以 =/+/-/@ 開頭，Excel/Sheets 開啟時會當成公式執行
// （如日誌內容/主機名剛好是 `=cmd|'/c calc'!A1` 這類字串），單純跳脫雙引號無法防範；補上開頭
// 字元中和——命中時前綴一個單引號強制視為純文字，Excel 顯示時會自動隱藏這個前綴單引號。
// doExportCSV()/doExportEventsCSV() 共用同一顆函式。
function csvCell(v) {
  let s = String(v == null ? '' : v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replace(/"/g, '""')}"`;
}
function doExportCSV() {
  const rows = buildCSVRows(ISSUES);
  const csv = rows.map(r => r.map(csvCell).join(',')).join('\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'log_issues.csv'; a.click();
}
// MITRE ATT&CK Navigator layer.json 匯出（2026-09-15 新增）：buildMitreLayer() 為純函式，
// 這裡只負責 Blob+<a download>（比照既有 doExportCSV() 樣式）
function doExportMitreLayer() {
  const layer = buildMitreLayer(ISSUES);
  const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'log_analyzer_mitre_layer.json'; a.click();
}
// IOC 萃取匯出（2026-09-16 新增）：範圍限定「問題清單相關事件」（ISSUES 的 relatedEvents），
// 而非全部 EVENTS——避免大型 log 檔匯出成千上萬筆與資安無關的內部 IP，訊噪比更高，比照既有
// 情資比對「聚焦已標記問題」的既有精神；buildIOCList() 為純函式，這裡只負責彙整事件來源+
// Blob 下載（CSV 欄位沿用既有 csvCell() 中和公式注入）
function doExportIOCs() {
  const scopedEvents = ISSUES.flatMap(is => is.relatedEvents || []);
  const iocs = buildIOCList(scopedEvents);
  const provIdx = buildIOCProvenanceIndex(ISSUES);
  const rows = [['type', 'value', 'category', 'severity', 'first_seen'], ...iocs.map(i => {
    const rec = provIdx.get(i.type + ':' + i.value);
    if (!rec) return [i.type, i.value, '', '', ''];
    const severity = [...rec.severities].sort((a, b) => SEV_RANK[a] - SEV_RANK[b])[0] || '';
    const categoryLabels = [...rec.categories].map(c => issueCategoryLabel(c)).join(';');
    return [i.type, i.value, categoryLabels, severity, rec.firstSeen ? fmtTime(rec.firstSeen) : ''];
  })];
  const csv = rows.map(r => r.map(csvCell).join(',')).join('\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'log_analyzer_iocs.csv'; a.click();
}
// STIX 2.1／MISP 匯出（XN10）：純函式 buildIOCExportRecords()／buildStixBundle()／buildMispEvent() 在 STATE 邊界之前
function doExportIOCsShared(fmt) {
  const box = document.getElementById('ioc-export-msg');
  const { records, excluded } = buildIOCExportRecords(ISSUES);
  if (!records.length) { if (box) box.textContent = tr('ioc.export_none').replace('{x}', excluded); return; }
  const label = c => issueCategoryLabel(c);
  const doc = fmt === 'stix' ? buildStixBundle(records, { label }) : buildMispEvent(records, { label });
  const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = fmt === 'stix' ? 'log_analyzer_iocs.stix.json' : 'log_analyzer_iocs.misp.json'; a.click();
  if (box) box.textContent = tr('ioc.export_msg').replace('{n}', records.length).replace('{x}', excluded);
}
// 事件清單匯出（正規化成表格後以 CSV 呈現）：匯出目前畫面上的檢視——尊重目前搜尋框篩選與
// 目前排序欄位/方向，與 renderResults() 用完全相同的 filterEvents→sortEventsByColumn 管線，
// 確保「匯出的 CSV＝畫面上看到的表格」。欄位固定包含 src/dst/port/proto（不受畫面 4 個
// 可選欄位 checkbox 限制，CSV 作為完整結構化匯出不受版面空間約束）。表頭沿用 renderResults()
// 表格已在用的既有 i18n key（results.col_*），不新增翻譯負擔。
// 事件 CSV 欄位與單列內容（doExportEventsCSV() 與行為者檢視 CSV 匯出共用，2026-09-29 抽出）
const EVENT_CSV_COLS = ['severity', 'time', 'host', 'format', 'category', 'notes', 'src', 'dst', 'port', 'proto', 'url', 'sourcefile', 'msg'];
function buildEventCsvRow(e) {
  const notes = (e.notes || []).map(noteKeyForCategory).filter(Boolean).map(k => tr(k)).join('; ');
  const tuple = getEventNetTuple(e);
  const urlDisplay = [e.httpMethod, e.url].filter(Boolean).join(' ');
  return [tr(SEV_KEY_MAP[e.severityNorm]), fmtTime(e.timestamp), e.host, e.format,
    tr(CAT_KEY_MAP[e.category] || 'cat.other'), notes, ipWithName(tuple.src, (e.fields || {}).srcName, (e.fields || {}).srcUser), ipWithName(tuple.dst, (e.fields || {}).dstName, (e.fields || {}).dstUser), tuple.port, tuple.proto, urlDisplay, e.sourceFile || '-', eventDisplayMsg(e)];
}
function doExportEventsCSV() {
  const filtered = filterEventsBySourceFile(filterEventsByTimeRange(filterEvents(EVENTS, document.getElementById('results-search').value.trim()), TIMELINE_RANGE_FILTER), RESULTS_FILE_FILTER);
  const sorted = sortEventsByColumn(filtered, SORT_COL, SORT_DIR);
  const rows = [EVENT_CSV_COLS.map(k => tr('results.col_' + k))];
  sorted.forEach(e => rows.push(buildEventCsvRow(e)));
  const csv = rows.map(r => r.map(csvCell).join(',')).join('\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'log_events.csv'; a.click();
}

// ── HTML 報表／PDF 匯出（比照 switch_analyzer exportHTMLReport 既有慣例：組一份完全獨立、
// 自帶樣式的 standalone HTML；mode='print' 時開新視窗直接呼叫瀏覽器列印，使用者可選「另存
// 為 PDF」，兩種輸出共用同一份報表內容，不重新設計兩套邏輯）──────────────────────────
const REPORT_CSS = `*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.5;color:#333;background:#f8f9fa;padding:20px}
.wrap{max-width:1200px;margin:0 auto}
h1{color:#2c3e50;margin-bottom:20px;font-size:24px;border-left:5px solid #3498db;padding-left:12px}
h2{font-size:17px;color:#2c3e50;margin-bottom:12px;border-left:4px solid #3498db;padding-left:10px}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.06);padding:20px;margin-bottom:20px;border:1px solid #e8ecef}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.meta-item{background:#f8f9fa;border-radius:6px;padding:10px 14px;border:1px solid #e9ecef}
.meta-label{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#888;font-weight:600}
.meta-value{font-size:20px;font-weight:700;color:#2c3e50;margin-top:2px;font-family:monospace}
table{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}
th{background:#2c3e50;color:#fff;padding:8px 9px;text-align:left;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;-webkit-print-color-adjust:exact;print-color-adjust:exact}
td{padding:7px 9px;border-bottom:1px solid #eee;vertical-align:top;word-break:break-word;overflow-wrap:break-word}
tr:nth-child(even) td{background:#f9fafb}
.mono{font-family:'Courier New',monospace;font-size:11px}
.badge{display:inline-block;padding:1px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}
.empty{text-align:center;color:#aaa;font-style:italic;padding:16px 0}
.rpt-subtitle{color:#64748b;font-size:12px;margin-bottom:20px;font-family:monospace;border-left:4px solid #3498db;padding-left:8px}
@media print{body{background:#fff;padding:0}.card{box-shadow:none;break-inside:avoid}th{-webkit-print-color-adjust:exact;print-color-adjust:exact}}`;

const REPORT_SEV_COLOR = { Critical: '#ef4444', High: '#fb923c', Medium: '#f59e0b', Low: '#38bdf8', Info: '#64748b' };

function buildReportTimelineSVG(events) {
  const { buckets, startTime, endTime, bucketMs } = buildTimelineBuckets(events);
  if (!buckets.length) return `<div class="empty">${esc(tr('results.empty'))}</div>`;
  const n = buckets.length, barAreaH = 60, chartW = 1000, gap = 1;
  const barW = chartW / n - gap;
  const maxTotal = Math.max(1, ...buckets.map(b => b.total));
  const bars = buckets.map((b, i) => {
    const x = i * (chartW / n);
    let y = barAreaH;
    return TL_SEV_ORDER.map(sev => {
      const h = (b[sev] / maxTotal) * barAreaH;
      y -= h;
      return h > 0 ? `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" fill="${REPORT_SEV_COLOR[sev]}"/>` : '';
    }).join('');
  }).join('');
  const axis = `<text x="0" y="76" font-size="10" fill="#888" text-anchor="start">${esc(tlFmtTime(startTime))}</text>
    <text x="${chartW / 2}" y="76" font-size="10" fill="#888" text-anchor="middle">${esc(tlFmtTime((startTime + endTime) / 2))}</text>
    <text x="${chartW}" y="76" font-size="10" fill="#888" text-anchor="end">${esc(tlFmtTime(endTime))}</text>`;
  return `<svg viewBox="0 0 ${chartW} 84" preserveAspectRatio="none" style="width:100%;height:100px">${bars}${axis}</svg>`;
}

// 報表自動摘要（2026-09-23 新增）：純樣板字串組裝，用既有 ISSUES/CHAINS 資料與
// summarizeBySeverity() 既有嚴重度統計組出一段白話文字，放在報表最前面（標題之後、其餘
// 章節之前），讓下載的報表不用逐張表格才看得出重點。抽成純函式方便測試，不額外臆測
// 不存在的欄位——summarizeBySeverity() 本來就適用任何含 severityNorm 欄位的陣列，ISSUES
// 天生符合（issuesRows 渲染時就是直接讀 is.severityNorm）
// 主管摘要（2026-09-30 新增，第八輪 XG）：報表開頭的白話文字——分析期間與事件量、建議優先處理的
// 前三項問題（嚴重度高者優先，同級依筆數）、尚未處理的問題數（處理狀態仍為「未處理」者）。
// 既有 buildReportSummaryText() 的數量統計維持不變，放在此摘要之後
function buildLogExecSummary(issues, events, statusOf) {
  const lines = [];
  const ts = events.map(e => e.timestamp ? new Date(e.timestamp).getTime() : NaN).filter(t => !isNaN(t));
  if (ts.length) lines.push(tr('exec.period').replace('{from}', fmtTime(arrMin(ts))).replace('{to}', fmtTime(arrMax(ts))).replace('{events}', events.length));
  else lines.push(tr('exec.events_only').replace('{events}', events.length));
  if (!issues.length) { lines.push(tr('exec.none')); return lines; }
  const top = issues.slice().sort((a, b) => SEV_RANK[a.severityNorm] - SEV_RANK[b.severityNorm] || b.count - a.count).slice(0, 3);
  lines.push(tr('exec.top').replace('{list}', top.map(is => tr('exec.item').replace('{label}', issueCategoryLabel(is.category)).replace('{sev}', tr(SEV_KEY_MAP[is.severityNorm] || '') || is.severityNorm).replace('{count}', is.count)).join(tr('exec.sep'))));
  const open = issues.filter(is => statusOf(is) === 'open').length;
  lines.push(open ? tr('exec.pending').replace('{n}', open).replace('{total}', issues.length) : tr('exec.all_handled'));
  return lines;
}
function buildReportSummaryText(issues, chains) {
  const sum = summarizeBySeverity(issues);
  // 2026-09-24 修正：「高風險」含 Critical＋High。先前只計 High，Critical 等級問題反而不列入
  // 高風險數字（例：1 筆「嚴重」問題摘要顯示 0 筆高風險），與使用者直覺相反
  return tr('report.summary')
    .replace('{total}', issues.length)
    .replace('{high}', sum.Critical + sum.High)
    .replace('{medium}', sum.Medium)
    .replace('{chains}', chains.length);
}

// 問題清單 Markdown 匯出（2026-09-24 新增）：供貼到工單／Wiki。問題列沿用 buildCSVRows() 同一份
// ISSUES 與相同欄位語意（MITRE 查表去 freq: 前綴、分析師備註），攻擊鏈沿用 buildChainsRowsHtml()
// 的階段序列文字；表格儲存格需跳脫 | 與換行，避免破壞 Markdown 表格結構
function _mdCell(v) { return String(v == null ? '' : v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, ' '); }
function buildIssuesMarkdown(issues, chains) {
  const L = [`# ${tr('report.title')}`, '', `## ${tr('exec.title')}`, '', ...buildLogExecSummary(issues, EVENTS, is => issueStatusOf(_baselineDiffKey(is))).map(x => '- ' + x), '', buildReportSummaryText(issues, chains), '',
    `## ${tr('issues.title')}`, ''];
  if (!issues.length) {
    L.push(tr('issues.empty'));
  } else {
    L.push(`| ${tr('issues.col_category')} | ${tr('issues.col_severity')} | ${tr('issues.col_count')} | ${tr('chain.col_first')} | ${tr('chain.col_last')} | MITRE | ${tr('issues.col_basis')} | ${tr('issues.col_note')} | ${tr('issues.col_status')} |`,
      '|---|---|---|---|---|---|---|---|---|');
    issues.forEach(is => {
      const baseCat = is.category.startsWith('freq:') ? is.category.slice(5) : is.category;
      L.push(`| ${_mdCell(issueCategoryLabel(is.category))} | ${_mdCell(tr(SEV_KEY_MAP[is.severityNorm] || '') || is.severityNorm)} | ${is.count} | ${_mdCell(fmtTime(is.firstSeen))} | ${_mdCell(fmtTime(is.lastSeen))} | ${(is.mitre || MITRE_MAP[baseCat]) || ''} | ${_mdCell(formatIssueBasis(is))} | ${_mdCell(issueNotes[_baselineDiffKey(is)] || '')} | ${_mdCell(issueStatusLabel(_baselineDiffKey(is)))} |`);
    });
  }
  L.push('', `## ${tr('chain.title')}`, '');
  if (!chains.length) {
    L.push(tr('chain.empty'));
  } else {
    L.push(`| ${tr('chain.col_actor')} | ${tr('issues.col_severity')} | ${tr('chain.col_stages')} | ${tr('chain.col_first')} | ${tr('chain.col_last')} |`,
      '|---|---|---|---|---|');
    chains.forEach(c => {
      const stages = c.stages.map(st => tr(CHAIN_STAGE_KEY_MAP[st.stage])).join(' → ');
      L.push(`| ${_mdCell(c.actor)} | ${_mdCell(tr(SEV_KEY_MAP[c.severityNorm] || '') || c.severityNorm)} | ${_mdCell(stages)} | ${_mdCell(fmtTime(c.firstSeen))} | ${_mdCell(fmtTime(c.lastSeen))} |`);
    });
  }
  const rot = buildRotationList(issues);
  if (rot.length) {
    L.push('', `## ${tr('rot.title')}`, '', tr('rot.hint'), '', `| ${tr('rot.col_kind')} | ${tr('rot.col_id')} | ${tr('rot.col_where')} | ${tr('rot.col_source')} |`, '|---|---|---|---|');
    rot.forEach(r => L.push(`| ${_mdCell(tr('rot.kind_' + r.kind))} | ${_mdCell(r.id)} | ${_mdCell(tr('rot.where_' + r.kind))} | ${_mdCell(issueCategoryLabel(r.cat))} |`));
  }
  L.push('', `> ${tr('mitre.disclaimer')}`, '');
  return L.join('\n');
}
// 憑證處置清單表格（XN91）：頁面與 HTML 報告共用；report=true 時包成報告卡片，清單為空時回傳空字串
function rotationTableHtml(list, report) {
  if (!list.length) return '';
  const rows = list.map(r => `<tr><td>${esc(tr('rot.kind_' + r.kind))}</td><td class="mono">${esc(r.id)}</td><td>${esc(tr('rot.where_' + r.kind))}</td><td>${esc(issueCategoryLabel(r.cat))}</td></tr>`).join('');
  const tbl = `<p class="hint">${esc(tr('rot.hint'))}</p><div class="tbl-wrap"><table><thead><tr><th>${esc(tr('rot.col_kind'))}</th><th>${esc(tr('rot.col_id'))}</th><th>${esc(tr('rot.col_where'))}</th><th>${esc(tr('rot.col_source'))}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  return report ? `<div class="card" style="border-left:4px solid #d97706"><h2>${esc(tr('rot.title'))}（${list.length}）</h2>${tbl}</div>` : tbl;
}
function renderRotation() {
  const card = document.getElementById('rotation-card');
  if (!card) return;
  const list = buildRotationList(ISSUES);
  card.style.display = list.length ? '' : 'none';
  document.getElementById('t-rotation-title').textContent = tr('rot.title') + (list.length ? `（${list.length}）` : '');
  document.getElementById('rotation-body').innerHTML = rotationTableHtml(list, false);
}
function doExportIssuesMarkdown() {
  const blob = new Blob([buildIssuesMarkdown(ISSUES, CHAINS)], { type: 'text/markdown;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'log_issues.md'; a.click();
}
// 行為者檢視匯出（2026-09-29 新增）：Markdown 含摘要／問題／攻擊鏈／相關事件，事件不受畫面
// ACTOR_EVENT_SHOW_MAX 顯示上限限制（匯出即為完整清單）；無資料的小節整節省略，與畫面一致。
// CSV 為該行為者全部相關事件，欄位與 doExportEventsCSV() 共用 buildEventCsvRow()
function sortActorEvents(events) { return [...events].sort((x, y) => effectiveTime(x) - effectiveTime(y)); }
function buildActorProfileMarkdown(p) {
  const summary = tr('actor.summary').replace('{events}', p.events.length).replace('{issues}', p.issues.length).replace('{chains}', p.chains.length);
  const range = p.firstSeen ? `（${fmtTime(p.firstSeen)} ～ ${fmtTime(p.lastSeen)}）` : '';
  const L = [`# ${tr('actor.title')} — ${p.actor}`, '', summary + range, ''];
  if (p.owners && p.owners.length) L.push(tr('actor.owners') + p.owners.join(', '), '');
  if (p.hours && p.events.some(e => e.timestamp)) {
    L.push(`## ${tr('actor.hours_title')}`, '', '| ' + p.hours.map((n, h) => h).join(' | ') + ' |', '|' + p.hours.map(() => '---').join('|') + '|', '| ' + p.hours.join(' | ') + ' |', '');
  }
  if (p.peers && p.peers.length) {
    L.push(`## ${tr('actor.peers_title')}`, '', `| ${tr('actor.col_peer')} | ${tr('issues.col_count')} |`, '|---|---|');
    p.peers.forEach(x => L.push(`| ${_mdCell(x.peer)} | ${x.count} |`));
    L.push('');
  }
  if (p.issues.length) {
    L.push(`## ${tr('issues.title')}`, '', `| ${tr('issues.col_category')} | ${tr('issues.col_severity')} | ${tr('issues.col_count')} | ${tr('issues.col_status')} |`, '|---|---|---|---|');
    p.issues.forEach(is => L.push(`| ${_mdCell(issueCategoryLabel(is.category))} | ${_mdCell(tr(SEV_KEY_MAP[is.severityNorm] || '') || is.severityNorm)} | ${is.count} | ${_mdCell(issueStatusLabel(_baselineDiffKey(is)))} |`));
    L.push('');
  }
  if (p.chains.length) {
    L.push(`## ${tr('chain.title')}`, '', `| ${tr('issues.col_severity')} | ${tr('chain.col_stages')} | ${tr('chain.col_first')} | ${tr('chain.col_last')} |`, '|---|---|---|---|');
    p.chains.forEach(c => L.push(`| ${_mdCell(tr(SEV_KEY_MAP[c.severityNorm] || '') || c.severityNorm)} | ${_mdCell(c.stages.map(st => tr(CHAIN_STAGE_KEY_MAP[st.stage])).join(' → '))} | ${_mdCell(fmtTime(c.firstSeen))} | ${_mdCell(fmtTime(c.lastSeen))} |`));
    L.push('');
  }
  if (p.events.length) {
    L.push(`## ${tr('actor.events_title')}`, '', `| ${tr('results.col_time')} | ${tr('results.col_severity')} | ${tr('results.col_host')} | ${tr('results.col_msg')} |`, '|---|---|---|---|');
    sortActorEvents(p.events).forEach(e => L.push(`| ${_mdCell(fmtTime(e.timestamp))} | ${_mdCell(tr(SEV_KEY_MAP[e.severityNorm] || '') || e.severityNorm)} | ${_mdCell(e.host)} | ${_mdCell(eventDisplayMsg(e))} |`));
    L.push('');
  }
  return L.join('\n');
}
// 檔名只保留英數與 . _ -，其餘字元（IP 的冒號、帳號的反斜線等）換成底線
function actorExportFileName(actor, ext) { return 'log_actor_' + (String(actor).replace(/[^\w.-]+/g, '_') || 'unknown') + '.' + ext; }
function doExportActorMarkdown() {
  const p = LAST_ACTOR_PROFILE; if (!p) return;
  const blob = new Blob([buildActorProfileMarkdown(p)], { type: 'text/markdown;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = actorExportFileName(p.actor, 'md'); a.click();
}
function doExportActorCSV() {
  const p = LAST_ACTOR_PROFILE; if (!p) return;
  const rows = [EVENT_CSV_COLS.map(k => tr('results.col_' + k)), ...sortActorEvents(p.events).map(buildEventCsvRow)];
  const csv = rows.map(r => r.map(csvCell).join(',')).join('\n');
  const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = actorExportFileName(p.actor, 'csv'); a.click();
}

// 攻擊鏈章節（報表匯出，2026-09-23 新增）：比照畫面上 renderChains() 的呈現邏輯（含每條鏈的
// 階段序列與 MITRE 徽章，重用既有 MITRE_MAP 查表，不重複定義一份新的），抽成純函式方便測試。
// 沒有攻擊鏈時比照 issuesRows 既有慣例顯示一列 chain.empty 提示，而非整個章節消失
function buildChainsRowsHtml(chains) {
  if (!chains.length) return `<tr><td colspan="6" class="empty">${esc(tr('chain.empty'))}</td></tr>`;
  return chains.map(c => {
    const stageText = c.stages.map(s => {
      const baseCat = s.issue.category.startsWith('freq:') ? s.issue.category.slice(5) : s.issue.category;
      const mitreId = (s.issue.mitre || MITRE_MAP[baseCat]);
      const mitreBadge = mitreId ? ` <span class="mitre-badge" title="${esc(tr('mitre.disclaimer'))}">${esc(mitreId)}</span>` : '';
      return `<span class="badge" style="background:${REPORT_SEV_COLOR[s.issue.severityNorm]}">${esc(tr(CHAIN_STAGE_KEY_MAP[s.stage]))}</span>${mitreBadge}`;
    }).join(' → ');
    return `<tr>
      <td>${esc(c.actor)}</td>
      <td><span class="badge" style="background:${REPORT_SEV_COLOR[c.severityNorm]}">${esc(tr(SEV_KEY_MAP[c.severityNorm]))}</span></td>
      <td>${stageText}</td>
      <td>${esc(fmtTime(c.firstSeen))}</td>
      <td>${esc(fmtTime(c.lastSeen))}</td>
      <td>${esc(spanText(c.spanMs))}</td></tr>`;
  }).join('');
}

function exportLogReport(mode) {
  if (!EVENTS.length) return;
  const sum = summarizeBySeverity(EVENTS);
  const formats = [...new Set(EVENTS.map(e => e.format).filter(Boolean))];
  const metaCards = Object.keys(SEV_KEY_MAP).map(k =>
    `<div class="meta-item"><div class="meta-label">${esc(tr(SEV_KEY_MAP[k]))}</div><div class="meta-value" style="color:${REPORT_SEV_COLOR[k]}">${sum[k]}</div></div>`
  ).join('');
  const issuesRows = ISSUES.length ? ISSUES.map(is => {
    let catLabel;
    const baseCat = is.category.startsWith('freq:') ? is.category.slice(5) : is.category;
    if (is.category.indexOf('custom:') === 0) {
      // 2026-09-22 修復：自訂規則類別（'custom:'+規則id）先前落到下方 else 分支查
      // CAT_KEY_MAP（查無對應鍵，一律顯示「其他」），比照 issueCategoryLabel() 既有邏輯
      // 改為顯示該筆自訂規則名稱；customRuleName 是使用者可匯入的文字，esc() 一次後輸出
      catLabel = esc(is.customRuleName || is.category);
    } else if (is.category.startsWith('freq:')) {
      catLabel = tr('cat.freqLabel') + tr(CAT_KEY_MAP[baseCat] || 'cat.other');
    } else {
      catLabel = tr(CAT_KEY_MAP[is.category] || 'cat.other');
      // is.intelSource（使用者自訂的情資清單名稱）在此已跳脫過一次，外層樣板不可再包一次
      // esc()，否則含 &/</>/" 的名稱會被雙重跳脫顯示成亂碼實體字串（如 &amp;amp;T）
      // （2026-09 全功能審查發現，比照 renderIssues() 既有正確寫法：catLabel 組好後不再
      // 額外 esc()）
      if ((is.category === 'knownIOC' || is.category === 'knownHashIOC') && is.intelSource) catLabel += ` (${esc(is.intelSource)})`;
    }
    // 2026-09-10 新增：MITRE 標註比照 renderIssues() 補上，確保下載/列印的報表與畫面上看到的
    // 資訊一致（先前只有即時畫面有徽章，分享出去的報表反而遺漏這項資訊）
    const mitreId = (is.mitre || MITRE_MAP[baseCat]);
    const mitreBadge = mitreId ? ` <span class="mitre-badge" title="${esc(tr('mitre.disclaimer'))}">${esc(mitreId)}</span>` : '';
    return `<tr>
      <td>${catLabel}${mitreBadge}</td>
      <td><span class="badge" style="background:${REPORT_SEV_COLOR[is.severityNorm]}">${esc(tr(SEV_KEY_MAP[is.severityNorm]))}</span></td>
      <td>${is.count}</td>
      <td>${esc(tr('conf.' + is.confidence))}</td>
      <td>${esc(getIssueIntelSources(is).join(', ') || '-')}</td>
      <td class="mono">${esc(formatIssueBasis(is))}</td>
      <td class="mono">${esc(issueSample(is))}</td>
      <td>${esc(issueNotes[_baselineDiffKey(is)] || '')}</td>
      <td>${esc(issueStatusLabel(_baselineDiffKey(is)))}</td></tr>`;
  }).join('') : `<tr><td colspan="9" class="empty">${esc(tr('issues.empty'))}</td></tr>`;
  // 樣本事件：僅取嚴重度最高的前 50 筆，避免報表過長；完整清單請使用既有的事件清單 CSV 匯出
  const sampleEvents = sortEventsByColumn(EVENTS, 'severity', 'asc').slice(0, 50);
  const eventsRows = sampleEvents.map(e => `<tr>
    <td><span class="badge" style="background:${REPORT_SEV_COLOR[e.severityNorm]}">${esc(tr(SEV_KEY_MAP[e.severityNorm]))}</span></td>
    <td class="mono">${esc(fmtTime(e.timestamp))}</td>
    <td>${esc(e.host)}</td>
    <td>${esc(e.format)}</td>
    <td>${esc(tr(CAT_KEY_MAP[e.category] || 'cat.other'))}</td>
    <td class="mono">${esc(eventDisplayMsg(e))}</td></tr>`).join('');
  const chainsRows = buildChainsRowsHtml(CHAINS);
  const summaryText = buildReportSummaryText(ISSUES, CHAINS);
  // 建議立即處理（XN54）：尚未處理的 Critical／High 問題，依嚴重度與次數，最多 5 項；沒有就不輸出
  const urgent = ISSUES.filter(is => (is.severityNorm === 'Critical' || is.severityNorm === 'High') && issueStatusOf(_baselineDiffKey(is)) === 'open')
    .sort((a, b) => SEV_RANK[a.severityNorm] - SEV_RANK[b.severityNorm] || b.count - a.count).slice(0, 5);
  const urgentHtml = urgent.length ? `<div class="card" style="border-left:4px solid #dc2626"><h2>${esc(tr('report.urgent_title'))}</h2><ol style="padding-left:20px">${urgent.map(is =>
    `<li style="margin:6px 0"><span class="badge" style="background:${REPORT_SEV_COLOR[is.severityNorm]}">${esc(tr(SEV_KEY_MAP[is.severityNorm]))}</span> ${esc(issueCategoryLabel(is.category))} (${is.count})<div class="mono" style="font-size:12px;color:#555">${esc(issueSample(is))}</div></li>`).join('')}</ol></div>` : '';
  // 防火牆設定對照（XN131）：有對照結果時列出各問題的放行／阻擋組數
  const fwvRows = FW_VERDICTS.size ? ISSUES.map(is => ({ is, v: fwVerdictSummary(is.relatedEvents, FW_VERDICTS) })).filter(x => x.v.accept + x.v.deny + x.v.unknown) : [];
  const fwvReportHtml = fwvRows.length ? `<div class="card"><h2>${esc(tr('fwv.report_title'))}</h2><p style="font-size:12px;color:#555">${esc(tr('fwv.report_note'))}</p><ul style="padding-left:20px">${fwvRows.map(x =>
    `<li style="margin:4px 0">${esc(issueCategoryLabel(x.is.category))}：${esc([x.v.accept ? tr('fwv.allow').replace('{n}', x.v.accept) : '', x.v.deny ? tr('fwv.deny').replace('{n}', x.v.deny) : '', x.v.unknown ? tr('fwv.unknown').replace('{n}', x.v.unknown) : ''].filter(Boolean).join('、'))}${x.v.reachable ? ' — ' + esc(tr('fwv.reachable').replace('{n}', x.v.reachable)) : ''}${x.v.mismatch ? ' — ' + esc(tr('fwv.mismatch').replace('{n}', x.v.mismatch)) : ''}</li>`).join('')}</ul></div>` : '';

  const reportHtml = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${esc(tr('app.title'))} — ${esc(tr('report.title'))}</title>
<style>${REPORT_CSS}</style></head><body><div class="wrap">
<h1>${esc(tr('app.title'))} — ${esc(tr('report.title'))}</h1>
<div class="rpt-subtitle">${esc(tr('report.generated_by'))} · ${esc(new Date().toLocaleString())} · ${esc(tr('report.total_events'))}: ${EVENTS.length} · ${esc(tr('report.formats'))}: ${esc(formats.join(', ') || '-')}</div>
<div class="card"><h2>${esc(tr('exec.title'))}</h2>${buildLogExecSummary(ISSUES, EVENTS, is => issueStatusOf(_baselineDiffKey(is))).map(x => `<p style="margin:4px 0">${esc(x)}</p>`).join('')}<p style="margin:8px 0 0">${esc(summaryText)}</p></div>
${urgentHtml}
${fwvReportHtml}
${rotationTableHtml(buildRotationList(ISSUES), true)}
<div class="card"><h2>${esc(tr('report.severity_summary'))}</h2><div class="meta-grid">${metaCards}</div></div>
<div class="card"><h2>${esc(tr('results.timeline_label'))}</h2>${buildReportTimelineSVG(EVENTS)}</div>
<div class="card"><h2>${esc(tr('issues.title'))}</h2><table><thead><tr><th>${esc(tr('issues.col_category'))}</th><th>${esc(tr('issues.col_severity'))}</th><th>${esc(tr('issues.col_count'))}</th><th>${esc(tr('issues.col_confidence'))}</th><th>${esc(tr('issues.col_source'))}</th><th>${esc(tr('issues.col_basis'))}</th><th>${esc(tr('issues.col_sample'))}</th><th>${esc(tr('issues.col_note'))}</th><th>${esc(tr('issues.col_status'))}</th></tr></thead><tbody>${issuesRows}</tbody></table></div>
<div class="card"><h2>${esc(tr('chain.title'))}</h2><table><thead><tr><th>${esc(tr('chain.col_actor'))}</th><th>${esc(tr('issues.col_severity'))}</th><th>${esc(tr('chain.col_stages'))}</th><th>${esc(tr('chain.col_first'))}</th><th>${esc(tr('chain.col_last'))}</th><th>${esc(tr('chain.col_span'))}</th></tr></thead><tbody>${chainsRows}</tbody></table></div>
<div class="card"><h2>${esc(tr('report.sample_events'))}（${sampleEvents.length}/${EVENTS.length}）</h2><table><thead><tr><th>${esc(tr('results.col_severity'))}</th><th>${esc(tr('results.col_time'))}</th><th>${esc(tr('results.col_host'))}</th><th>${esc(tr('results.col_format'))}</th><th>${esc(tr('results.col_category'))}</th><th>${esc(tr('results.col_msg'))}</th></tr></thead><tbody>${eventsRows}</tbody></table></div>
</div></body></html>`;

  if (mode === 'print') {
    const printWin = window.open('', '_blank');
    if (!printWin) { alert(tr('err.popup_blocked')); return; }
    printWin.document.open(); printWin.document.write(reportHtml); printWin.document.close();
    printWin.onload = () => { printWin.focus(); printWin.print(); };
  } else {
    const blob = new Blob([reportHtml], { type: 'text/html;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'log_report.html'; a.click();
  }
}

// 空白範例 CSV 供使用者下載後編輯再匯入安全清單；cidr 欄位名稱本身就命中 parseIntelList()
// 既有的 IP_FIELD_RE 判斷邏輯（不限定 CIDR，單一 IP 亦可），其餘欄位（name/note）原樣存入
// meta，不影響比對，純粹供使用者自己註記用途。**不可比照 doExportCSV() 加雙引號**——
// parseIntelList() 的 CSV 分支是單純 line.split(',')，不解析引號跳脫，加了引號會讓匯入值
// 變成帶著字面雙引號的髒資料（如 `"10.0.0.0/8"` 而非 `10.0.0.0/8`），比對永遠不會命中；
// 純文字 plain CSV（比照既有 sample_intel.csv fixture 慣例）才是這個匯入路徑實際吃的格式
function doDownloadSafelistTemplate() {
  const rows = [['cidr', 'name', 'note'],
    ['10.0.0.0/8', '公司內網範例', '可依實際情況修改或刪除此列'],
    ['198.51.100.5', '單一IP範例', '']];
  const csv = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'safelist_template.csv'; a.click();
}

document.getElementById('btn-upload').onclick = () => document.getElementById('file-input').click();
document.getElementById('file-input').onchange = e => { if (e.target.files.length) doUploadFile(Array.from(e.target.files)); };
document.getElementById('btn-analyze').onclick = doAnalyze;
['col-src', 'col-dst', 'col-port', 'col-proto', 'col-url'].forEach(id => document.getElementById(id).onchange = renderResults);
document.getElementById('btn-clear').onclick = doClear;
// Ctrl／⌘＋Enter 在貼上框直接開始（UX24）；按鈕加提示與 aria-keyshortcuts
(function () {
  var ta = document.getElementById('paste-area'), btn = document.getElementById('btn-analyze');
  if (!ta) return;
  ta.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); doAnalyze(); }
  });
  if (btn) { btn.setAttribute('aria-keyshortcuts', 'Control+Enter Meta+Enter'); btn.title = (btn.title ? btn.title + ' ' : '') + '(Ctrl/⌘+Enter)'; }
})();
document.getElementById('btn-import-edit').onclick = () => { setImportCompact(false); document.getElementById('paste-area').focus(); };
document.getElementById('paste-area').addEventListener('focus', () => setImportCompact(false));
document.getElementById('btn-sample').onclick = loadSampleLog;
// 入口頁「看範例」（第二十九輪 NU4）：網址帶 ?demo=1 時開頁即載入範例並分析
window.addEventListener('load', function () { if (/[?&]demo=1(?:&|$)/.test(location.search)) setTimeout(function () { loadSampleLog(); }, 0); });
document.getElementById('btn-intel-add').onclick = () => document.getElementById('intel-file-input').click();
// 情資清單整理頁直接送來的清單（postMessage，不經 localStorage）：只接受本頁開啟的整理頁，或開啟本頁的整理頁
const INTEL_BUILDER_WINS = new Set();
['t-intel-builder', 't-guide-builder'].forEach(id => {
  const a = document.getElementById(id);
  if (a) a.onclick = ev => { ev.preventDefault(); const w = window.open(a.getAttribute('href')); if (w) INTEL_BUILDER_WINS.add(w); else location.href = a.getAttribute('href'); };
});
const INTEL_MSG_ORIGIN = (location.protocol === 'file:' || location.origin === 'null') ? '*' : location.origin;
if (window.opener) { try { window.opener.postMessage({ type: '_naIntelReady' }, INTEL_MSG_ORIGIN); } catch (e) { /* 開啟者已關閉 */ } }
// 防火牆分析回傳的設定對照結果（XN131）：只接受本頁開啟的防火牆分析頁，內容經 parseFwBatchReply() 逐欄驗證
window.addEventListener('message', e => {
  if (!e.data || e.data.type !== '_naFwBatchResult' || !FW_QUERY_WINS.has(e.source)) return;
  if (INTEL_MSG_ORIGIN !== '*' && e.origin !== location.origin) return;
  const m = parseFwBatchReply(e.data);
  if (!m || !EVENTS.length) return;
  m.forEach((v, k) => FW_VERDICTS.set(k, v));
  renderIssues(); renderChains(); renderNextBar();
});
window.addEventListener('message', e => {
  const d = e.data;
  if (!d || (d.type !== '_naIntelHello' && d.type !== '_naIntelLists')) return;
  if (!(INTEL_BUILDER_WINS.has(e.source) || (window.opener && e.source === window.opener))) return;
  if (INTEL_MSG_ORIGIN !== '*' && e.origin !== location.origin) return;
  if (d.type === '_naIntelHello') { e.source.postMessage({ type: '_naIntelReady' }, INTEL_MSG_ORIGIN); return; }
  if (!Array.isArray(d.files)) return;
  const today = new Date().toISOString().slice(0, 10);
  d.files.forEach(f => {
    if (!f || typeof f.text !== 'string' || typeof f.name !== 'string') return;
    const file = new File([f.text], f.name.replace(/[^\w.-]/g, '_'), { type: 'text/plain' });
    if (f.kind === 'hash') doHashIntelUpload(file, '', today);
    else if (f.kind === 'asn') doAsnRiskUpload(file);
    else if (f.kind === 'hosting') doAsnHostingUpload(file);
    else if (f.kind === 'anonvpn') doAnonVpnUpload(file);
    else if (f.kind === 'rmm') doRmmUpload(file);
    else if (f.kind === 'ip' || f.kind === 'domain') doIntelUpload(file, '', today);
  });
  const det = document.getElementById('optional-sources');
  if (det) det.open = true;
  const card = document.getElementById('intel-card');
  if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
  window.focus();
});
document.getElementById('intel-file-input').onchange = e => {
  if (e.target.files[0]) {
    doIntelUpload(e.target.files[0], document.getElementById('intel-name-input').value, document.getElementById('intel-date-input').value);
    document.getElementById('intel-name-input').value = ''; document.getElementById('intel-date-input').value = '';
  }
};
document.getElementById('btn-hashintel-add').onclick = () => document.getElementById('hashintel-file-input').click();
document.getElementById('hashintel-file-input').onchange = e => {
  if (e.target.files[0]) {
    doHashIntelUpload(e.target.files[0], document.getElementById('hashintel-name-input').value, document.getElementById('hashintel-date-input').value);
    document.getElementById('hashintel-name-input').value = ''; document.getElementById('hashintel-date-input').value = '';
  }
};
document.getElementById('btn-safelist-add').onclick = () => document.getElementById('safelist-file-input').click();
document.getElementById('safelist-file-input').onchange = e => {
  if (e.target.files[0]) {
    doSafelistUpload(e.target.files[0], document.getElementById('safelist-name-input').value);
    document.getElementById('safelist-name-input').value = '';
  }
};
document.getElementById('btn-safelist-template').onclick = doDownloadSafelistTemplate;
document.getElementById('btn-geo-add').onclick = () => document.getElementById('geo-file-input').click();
document.getElementById('geo-file-input').onchange = e => {
  if (e.target.files[0]) {
    doGeoUpload(e.target.files[0], document.getElementById('geo-name-input').value);
    document.getElementById('geo-name-input').value = '';
  }
};
document.getElementById('btn-asn-add').onclick = () => document.getElementById('asn-file-input').click();
document.getElementById('asn-file-input').onchange = e => {
  if (e.target.files[0]) {
    doAsnUpload(e.target.files[0], document.getElementById('asn-name-input').value);
    document.getElementById('asn-name-input').value = '';
  }
};
document.getElementById('btn-asn-risk-add').onclick = () => document.getElementById('asn-risk-file-input').click();
document.getElementById('asn-risk-file-input').onchange = e => {
  if (e.target.files[0]) doAsnRiskUpload(e.target.files[0]);
  e.target.value = '';
};
document.getElementById('btn-asn-hosting-add').onclick = () => document.getElementById('asn-hosting-file-input').click();
document.getElementById('btn-anonvpn-add').onclick = () => document.getElementById('anonvpn-file-input').click();
document.getElementById('anonvpn-file-input').onchange = e => { if (e.target.files[0]) doAnonVpnUpload(e.target.files[0]); e.target.value = ''; };
document.getElementById('btn-rmm-add').onclick = () => document.getElementById('rmm-file-input').click();
document.getElementById('rmm-file-input').onchange = e => { if (e.target.files[0]) doRmmUpload(e.target.files[0]); e.target.value = ''; };
document.getElementById('asn-hosting-file-input').onchange = e => {
  if (e.target.files[0]) doAsnHostingUpload(e.target.files[0]);
  e.target.value = '';
};
document.getElementById('btn-deid-run').onclick = doRunDeid;
document.getElementById('btn-deid-download').onclick = doDownloadDeid;
document.getElementById('btn-export-csv').onclick = doExportCSV;
document.getElementById('btn-export-map').onclick = exportMapping;
document.getElementById('mapping-import-input').onchange = onMappingImportSelect;
document.getElementById('btn-export-events-csv').onclick = doExportEventsCSV;
document.getElementById('btn-fw-batch').onclick = sendFwBatchQuery;
document.getElementById('btn-export-file-metadata').onclick = doExportFileMetadata;
document.getElementById('btn-mitre-layer').onclick = () => doExportMitreLayer();
document.getElementById('btn-export-ioc').onclick = () => doExportIOCs();
document.getElementById('btn-export-stix').onclick = () => doExportIOCsShared('stix');
document.getElementById('btn-case-export').onclick = doExportCasePack;
document.getElementById('btn-export-misp').onclick = () => doExportIOCsShared('misp');
document.getElementById('btn-export-md').onclick = () => doExportIssuesMarkdown();
// 匯出選單（UX36）：點項目、點外面或按 Esc 收起
(function () {
  const m = document.getElementById('export-menu');
  if (!m) return;
  m.querySelector('.exp-menu-panel').addEventListener('click', e => { if (e.target.closest('button')) m.open = false; });
  document.addEventListener('click', e => { if (m.open && !m.contains(e.target)) m.open = false; });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && m.open) { m.open = false; m.querySelector('summary').focus(); } });
})();
document.getElementById('btn-actor-show').onclick = () => showActorProfile();
document.getElementById('btn-actor-export-md').onclick = () => doExportActorMarkdown();
document.getElementById('btn-actor-export-csv').onclick = () => doExportActorCSV();
document.getElementById('btn-hostgraph-csv').onclick = () => downloadHostGraph('csv');
document.getElementById('btn-hostgraph-mermaid').onclick = () => downloadHostGraph('mermaid');
document.getElementById('btn-hostgraph-drawio').onclick = () => downloadHostGraph('drawio');
document.getElementById('actor-input').addEventListener('keydown', e => { if (e.key === 'Enter') showActorProfile(); });
document.getElementById('btn-html-report').onclick = () => exportLogReport();
document.getElementById('btn-print-report').onclick = () => exportLogReport('print');
document.getElementById('btn-baseline-export').onclick = exportBaseline;
document.getElementById('baseline-import-input').onchange = onBaselineImportSelect;
document.getElementById('prev-log-input').onchange = e => { loadPrevPeriodLog(e.target.files); e.target.value = ''; };
document.getElementById('timeline-chart').addEventListener('mousedown', _onTimelineMouseDown);
// 搜尋框防抖（2026-09-29，PA）：停止輸入 200ms 後才重畫，避免大量事件時每個字都觸發一次重畫
let _resultsSearchTimer = null;
document.getElementById('results-search').oninput = () => { clearTimeout(_resultsSearchTimer); _resultsSearchTimer = setTimeout(renderResults, 200); };
document.getElementById('results-file-filter').onchange = e => { RESULTS_FILE_FILTER = e.target.value; renderResults(); };
document.getElementById('issues-search').oninput = renderIssues;
document.getElementById('issues-source-filter').onchange = e => { ISSUES_SOURCE_FILTER = e.target.value; renderIssues(); };
document.getElementById('issues-status-filter').onchange = () => { saveSettings(); renderIssues(); };
document.getElementById('filter-preset-select').onchange = e => applyFilterPreset(e.target.value);
document.getElementById('btn-filter-preset-save').onclick = saveCurrentFilterPreset;
document.getElementById('btn-filter-preset-delete').onclick = deleteFilterPreset;

// 拖放檔案匯入：直接放到貼上區域上，重用既有的檔案上傳邏輯，不需要另外解析拖放事件內容
const pasteArea = document.getElementById('paste-area');
pasteArea.addEventListener('dragover', e => e.preventDefault());
pasteArea.addEventListener('drop', e => {
  e.preventDefault();
  const files = Array.from(e.dataTransfer.files || []);
  if (files.length) doUploadFile(files);
});
// 大檔案上傳後 textarea 會刻意留空（見 doUploadFile）；使用者若之後手動輸入/貼上新內容，
// 視為要改用 textarea 內容，PENDING_LARGE_TEXT 讓出優先權並收起提示，避免兩者衝突
pasteArea.addEventListener('input', () => {
  if (PENDING_LARGE_TEXT !== null) {
    PENDING_LARGE_TEXT = null;
    document.getElementById('large-file-notice').style.display = 'none';
  }
  // 使用者手動編輯內容後，先前依上傳檔案行數算出的行號→檔名對照表可能已與實際文字不符
  // （行數位移），一併清空避免後續分析誤標來源檔案（doUploadFile() 以程式寫入 .value 不會
  // 觸發此事件，僅真正手動輸入才會，見該函式與此處對應註解）
  if (SOURCE_FILE_BOUNDARIES.length) { SOURCE_FILE_BOUNDARIES = []; RESULTS_FILE_FILTER = ''; }
});

// 記住上次的門檻／可選欄位設定（僅此工具本機儲存，不涉及任何伺服器傳輸）
const LS_SETTINGS_KEY = 'log_analyzer_settings_v1';
const SETTINGS_TEXT_IDS = ['opt-lateral-exclude', 'opt-lateral-types', 'issues-status-filter', 'opt-freq-window', 'opt-freq-threshold', 'opt-scan-threshold', 'opt-volume-threshold', 'opt-proc-watchlist', 'opt-sysmon-proc-watchlist', 'opt-sysmon-thread-watchlist', 'opt-ps-scriptblock-watchlist', 'opt-sysmon-imageload-watchlist', 'opt-ps-modulelog-watchlist', 'opt-chain-groupby', 'opt-work-start', 'opt-work-end', 'opt-work-days', 'opt-tz-offset', 'opt-holidays'];
const SETTINGS_CHECK_IDS = ['col-src', 'col-dst', 'col-port', 'col-proto', 'col-url', 'opt-enable-4688', 'opt-enable-sysmon-proc', 'opt-enable-sysmon-thread', 'opt-enable-ps-scriptblock', 'opt-enable-sysmon-imageload', 'opt-enable-ps-modulelog', 'opt-enable-offhours'];
// 地理位置勾選清單持久化：僅有意義於「未匯入模式」（GEO_LISTS 跟 INTEL_LISTS/SAFE_LISTS 一樣
// 不會存進 localStorage，重新整理頁面一定會回到未匯入狀態，已匯入模式的勾選本來就無法跨
// 重整存活）；checkbox 由 renderGeoRiskChecks() 動態產生，用容器上的事件委派而非逐一綁定
function saveSettings() {
  const s = {};
  SETTINGS_TEXT_IDS.forEach(id => { s[id] = document.getElementById(id).value; });
  SETTINGS_CHECK_IDS.forEach(id => { s[id] = document.getElementById(id).checked; });
  s['geo-risk-checked'] = Array.from(document.querySelectorAll('#geo-risk-checks input:checked')).map(el => el.value);
  // 抑制清單直接以 SUPPRESSED_CATEGORIES 為準（非讀 checkbox DOM）：分類清單隨每次分析結果
  // 變動，重新整理後在還沒跑分析前 checkbox 根本不存在，Set 本身才是唯一持久真相來源
  s['issues-suppressed'] = Array.from(SUPPRESSED_CATEGORIES);
  // 自訂偵測規則是物件陣列，不適合塞進上面的扁平 id 清單機制，比照 issues-suppressed 的
  // 「特例欄位」寫法直接整份存
  s['custom-rules'] = customDetectRules;
  // 分析師備註同樣是「特例欄位」寫法：一個 {key: text} 物件，非扁平 id 清單
  s['issue-notes'] = issueNotes;
  s['issue-status'] = issueStatus;
  s['filter-presets'] = FILTER_PRESETS;
  try { localStorage.setItem(LS_SETTINGS_KEY, JSON.stringify(s)); } catch (e) { /* 私密瀏覽模式等情況下 localStorage 可能不可用，靜默略過即可，非核心功能 */ }
}
function loadSettings() {
  let s;
  try { s = JSON.parse(localStorage.getItem(LS_SETTINGS_KEY) || 'null'); } catch (e) { s = null; }
  if (!s) return;
  SETTINGS_TEXT_IDS.forEach(id => { if (s[id] !== undefined) document.getElementById(id).value = s[id]; });
  SETTINGS_CHECK_IDS.forEach(id => { document.getElementById(id).checked = !!s[id]; });
  const box = document.getElementById('geo-risk-checks');
  if (Array.isArray(s['geo-risk-checked']) && box.dataset.mode !== 'imported') {
    const set = new Set(s['geo-risk-checked']);
    document.querySelectorAll('#geo-risk-checks input').forEach(el => { el.checked = set.has(el.value); });
  }
  if (Array.isArray(s['issues-suppressed'])) SUPPRESSED_CATEGORIES = new Set(s['issues-suppressed']);
  // 重新指派 id 避免與 session 內已有規則衝突（比照 config_anonymizer 匯入邏輯的既有理由）
  if (Array.isArray(s['custom-rules'])) {
    // 與匯入檔案相同的白名單驗證（工作區檔案可被他人竄改，未驗證的嚴重度會進到 class 屬性）
    customDetectRules = s['custom-rules'].map(sanitizeCustomRule).filter(Boolean);
    renderCustomRules();
  }
  if (s['issue-notes'] && typeof s['issue-notes'] === 'object') issueNotes = s['issue-notes'];
  if (s['issue-status'] && typeof s['issue-status'] === 'object') issueStatus = s['issue-status'];
  if (Array.isArray(s['filter-presets'])) FILTER_PRESETS = s['filter-presets'].filter(p => p && p.name);
}
renderGeoRiskChecks();
renderAsnRiskImportList();
renderAsnRiskChecks();
[...SETTINGS_TEXT_IDS, ...SETTINGS_CHECK_IDS].forEach(id => document.getElementById(id).addEventListener('change', saveSettings));
document.getElementById('geo-risk-checks').addEventListener('change', saveSettings);
document.getElementById('geo-risk-filter').addEventListener('input', e => filterGeoRiskChecks(e.target.value));
document.getElementById('asn-risk-filter').addEventListener('input', e => filterAsnRiskChecks(e.target.value));
document.getElementById('issues-suppress-checks').addEventListener('change', e => {
  if (!e.target.classList.contains('issues-suppress-check')) return;
  if (e.target.checked) SUPPRESSED_CATEGORIES.add(e.target.value); else SUPPRESSED_CATEGORIES.delete(e.target.value);
  saveSettings();
  renderIssues();
});
loadSettings();
autoLabelControls();
if (SETTINGS_CHECK_IDS.some(id => id.indexOf('opt-enable-') === 0 && document.getElementById(id).checked)) document.getElementById('adv-options').open = true;
renderFilterPresetSelect(); // 篩選預設集清單在 loadSettings() 才讀回，需再重繪下拉選單

renderAll();

// 2026-08-19 新增：接上 network_analyzer 拖放派送機制（比照 switch_analyzer/firewall_
// analyzer/config_anonymizer/switch_config_generator 既有各自獨立實作的慣例，非共用函式）
// 2026-09 資安審查修復：JSON 解析失敗／已過期的 key 一律清除（不論是否為本工具負責消費），讓
// 任一工具頁面被開啟都能順手清掉整個交接命名空間裡的殘留，縮小放棄交接流程後明碼機敏內容殘留的
// 曝險窗口；本工具非匿名化轉送鏈的目標，故不消費 `_netAnalyzer_anonThenOpen`/`_netAnalyzer_anonResult`，
// 僅在過期時順手清掉。
(function(){
  var TTL = {_netAnalyzer_pending:10000, _netAnalyzer_anonThenOpen:30000, _netAnalyzer_anonResult:30000, _netAnalyzer_swParsedModel:30000, _netAnalyzer_fwQuery:30000, _netAnalyzer_swPortQuery:30000, _netAnalyzer_route:30000};
  var ownData = null;
  Object.keys(TTL).forEach(function(k){
    var raw = localStorage.getItem(k);
    if (!raw) return;
    try {
      var d = JSON.parse(raw);
      if (Date.now() - d.ts > TTL[k]) { localStorage.removeItem(k); return; }
      if (k === '_netAnalyzer_pending') ownData = d;
    } catch(e) { localStorage.removeItem(k); }
  });
  if (!ownData) return;
  localStorage.removeItem('_netAnalyzer_pending');
  var pa = document.getElementById('paste-area');
  if (pa) pa.value = ownData.text;
  doAnalyze();
})();

// 主題切換（2026-08-25 新增，比照其餘 5 工具既有的 setTheme()/toggleTheme() 慣例搬過來，
// 本工具先前完全沒有主題切換機制，CSS 已用 body[data-theme=...] 選擇器，零 CSS 改動即可相容）
function setTheme(t){document.body.dataset.theme=t;const b=document.getElementById('theme-btn');if(b)b.textContent=t==='light'?'🌙':'☀️';localStorage.setItem('cw_theme',t);}
function toggleTheme(){setTheme(document.body.dataset.theme==='light'?'dark':'light');}
(function(){const s=localStorage.getItem('cw_theme');const p=s||(window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');if(p==='light')setTheme('light');})();
