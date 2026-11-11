// ============================================================
// [3] Severity 排序與統計
// ============================================================
const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
function sortEventsBySeverity(events) {
  return [...events].sort((a, b) => SEV_RANK[a.severityNorm] - SEV_RANK[b.severityNorm] || a.lineNo - b.lineNo);
}
function summarizeBySeverity(events) {
  const summary = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  events.forEach(e => { summary[e.severityNorm] = (summary[e.severityNorm] || 0) + 1; });
  return summary;
}
// 事件時間軸視覺化用：依 effectiveTime()（既有函式，無時間戳事件已有「用行號模擬時序」的
// fallback，這裡沿用不重新設計）把整批事件的時間範圍等分成 bucketCount 個桶，每桶依嚴重度
// 分類計數，供 renderTimeline() 畫堆疊長條圖；純資料運算，不碰 DOM，可獨立測試
function buildTimelineBuckets(events, bucketCount) {
  const n = bucketCount || 48;
  if (!events.length) return { buckets: [], startTime: null, endTime: null, bucketMs: 0, untimed: 0 };
  // 有時間戳的事件與沒有的混在一起時，只畫有時間戳的（無時間事件以行號代替會落在 1970 年，把橫軸拉長）；
  // 全部沒有時間戳時才沿用行號順序
  const timed = events.filter(e => e.timestamp);
  const untimed = timed.length ? events.length - timed.length : 0;
  if (timed.length) events = timed;
  const times = events.map(effectiveTime);
  const startTime = arrMin(times), endTime = arrMax(times);
  const span = Math.max(endTime - startTime, 1);
  const bucketMs = span / n;
  const buckets = Array.from({ length: n }, () => ({ Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0, total: 0 }));
  events.forEach(e => {
    const t = effectiveTime(e);
    let idx = Math.floor((t - startTime) / bucketMs);
    if (idx >= n) idx = n - 1;
    if (idx < 0) idx = 0;
    const sev = e.severityNorm && buckets[idx][e.severityNorm] !== undefined ? e.severityNorm : 'Info';
    buckets[idx][sev]++;
    buckets[idx].total++;
  });
  return { buckets, startTime, endTime, bucketMs, untimed };
}
// HTML 跳脫（2026-09 隨 buildTimelineSVG() 一併搬到測試沙箱可抽取範圍——純函式零 document
// 依賴，原本放在後段 UI 區塊純屬歷史慣例，搬移不影響任何呼叫端行為，僅讓其成為可測試單元）
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
// 事件時間軸：純前端 SVG 堆疊長條圖，不引入圖表函式庫（比照全套工具零依賴、單一 HTML 檔的
// 既有原則）。v1 固定反映全部 EVENTS，不隨搜尋框篩選連動，避免範圍擴大；資料運算由
// buildTimelineBuckets() 負責（純函式，另有獨立測試）
const TL_SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const TL_SEV_COLOR = { Critical: 'var(--red)', High: 'var(--orange)', Medium: 'var(--yellow)', Low: 'var(--accent3)', Info: 'var(--text-dim)' };
function tlFmtTime(ms) {
  return new Date(ms).toLocaleString(undefined, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}
// renderTimeline() 的座標計算部分抽成純函式（2026-09 新增，Phase 3 item 14：log_analyzer
// UI 層測試覆蓋），輸入 buildTimelineBuckets() 的輸出＋目前的時間範圍篩選狀態
// （selectedRange，即 TIMELINE_RANGE_FILTER，改為參數傳入維持純函式），輸出完整 SVG 字串；
// renderTimeline() 只需再組 <svg> 外框並塞進 DOM，不重算任何座標
// 攻擊鏈區段（2026-09-29 新增）：把每條攻擊鏈 [firstSeen, lastSeen] 映射成時間軸下方色條的
// x／寬度，並以貪婪法分配列（lane）避免重疊，最多 maxLanes 列（超出者疊在最後一列）。
// 時間無效（非有限數值）或與事件時間範圍完全無交集的攻擊鏈略過；超出範圍的部分裁切到邊界；
// 寬度至少 2 單位，確保單一時間點的攻擊鏈仍看得見。純函式，供 buildTimelineSVG() 使用
function buildTimelineChainLanes(chains, startTime, endTime, chartW, maxLanes) {
  chartW = chartW || 1000; maxLanes = maxLanes || 4;
  const span = Math.max(endTime - startTime, 1);
  const laneEnds = [];
  return (chains || [])
    .filter(c => Number.isFinite(c.firstSeen) && Number.isFinite(c.lastSeen) && c.lastSeen >= startTime && c.firstSeen <= endTime)
    .sort((a, b) => a.firstSeen - b.firstSeen)
    .map(c => {
      const x = (Math.max(c.firstSeen, startTime) - startTime) / span * chartW;
      const x2 = (Math.min(c.lastSeen, endTime) - startTime) / span * chartW;
      const w = Math.max(2, x2 - x);
      let lane = laneEnds.findIndex(end => end < x);
      if (lane === -1) lane = laneEnds.length < maxLanes ? laneEnds.length : maxLanes - 1;
      laneEnds[lane] = Math.max(laneEnds[lane] || 0, x + w);
      return { chain: c, x, w, lane };
    });
}
function buildTimelineSVG(buckets, startTime, endTime, bucketMs, selectedRange, chains) {
  const n = buckets.length;
  const barAreaH = 50, chartW = 1000, gap = 1;
  const barW = chartW / n - gap;
  const maxTotal = Math.max(1, ...buckets.map(b => b.total));
  const bars = buckets.map((b, i) => {
    const x = i * (chartW / n);
    let y = barAreaH;
    const segs = TL_SEV_ORDER.map(sev => {
      const h = (b[sev] / maxTotal) * barAreaH;
      y -= h;
      return h > 0 ? `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" fill="${TL_SEV_COLOR[sev]}"/>` : '';
    }).join('');
    const bucketStart = startTime + i * bucketMs;
    const bucketEnd = bucketStart + bucketMs;
    const title = `${tlFmtTime(bucketStart)}\n${TL_SEV_ORDER.map(s => `${s}: ${b[s]}`).join(' / ')}`;
    // 高亮條件（2026-09-15 改為區間重疊判斷，取代原本的單一 bucket 精確比對）：拖曳選取
    // 可能橫跨多個 bucket，selectedRange 不再保證恰好等於某個 bucket 的 [start,end)，
    // 改用「兩區間是否有交集」判斷，單一 bucket 點擊選取時行為與原本完全相同
    const selected = selectedRange && bucketStart < selectedRange.end && bucketEnd > selectedRange.start;
    const highlight = selected ? `<rect x="${x.toFixed(1)}" y="0" width="${barW.toFixed(1)}" height="${barAreaH}" fill="none" stroke="var(--accent)" stroke-width="1.5"/>` : '';
    return `<g style="cursor:pointer" onclick="selectTimelineRange(${bucketStart},${bucketEnd})"><title>${esc(title)}</title><rect x="${x.toFixed(1)}" y="0" width="${barW.toFixed(1)}" height="${barAreaH}" fill="transparent"/>${segs}${highlight}</g>`;
  }).join('');
  // 攻擊鏈色條畫在長條圖下方（每列高 5、間距 2），有色條時整張圖與時間刻度一併往下延伸；
  // 點擊色條以該攻擊鏈的時間範圍篩選事件清單（沿用既有 selectTimelineRange()）
  const lanes = buildTimelineChainLanes(chains, startTime, endTime, chartW);
  const laneCount = lanes.length ? arrMax(lanes.map(l => l.lane)) + 1 : 0;
  const extraH = laneCount * 7;
  const chainBars = lanes.map(l => {
    const c = l.chain;
    const title = `${tr('chain.title')}: ${c.actor}\n${c.stages.map(st => tr(CHAIN_STAGE_KEY_MAP[st.stage])).join(' → ')}\n${tlFmtTime(c.firstSeen)} ~ ${tlFmtTime(c.lastSeen)}`;
    return `<g class="tl-chain" style="cursor:pointer" onclick="selectTimelineRange(${c.firstSeen},${c.lastSeen + 1})"><title>${esc(title)}</title><rect x="${l.x.toFixed(1)}" y="${53 + l.lane * 7}" width="${l.w.toFixed(1)}" height="5" rx="1" fill="${TL_SEV_COLOR[c.severityNorm] || TL_SEV_COLOR.Info}"/></g>`;
  }).join('');
  const axisY = 64 + extraH;
  const axis = `<text class="tl-axis" x="0" y="${axisY}" text-anchor="start">${esc(tlFmtTime(startTime))}</text>
    <text class="tl-axis" x="${chartW / 2}" y="${axisY}" text-anchor="middle">${esc(tlFmtTime((startTime + endTime) / 2))}</text>
    <text class="tl-axis" x="${chartW}" y="${axisY}" text-anchor="end">${esc(tlFmtTime(endTime))}</text>`;
  const h = 70 + extraH;
  return `<svg viewBox="0 0 ${chartW} ${h}" preserveAspectRatio="none"${extraH ? ` style="height:${h}px"` : ''}>${bars}${chainBars}${axis}</svg>`;
}
// 拖曳框選（brush-to-zoom，2026-09-15 新增）：畫面像素 X 座標 → bucket 索引，
// buildTimelineSVG() 既有正向映射 x = i*(chartW/n) 的反向版本，純函式供測試沙箱涵蓋，
// UI 事件綁定（mousedown/mousemove/mouseup）於下方 STATE/UI 區塊 TIMELINE_RANGE_FILTER 附近
function xToBucketIndex(viewBoxX, n, chartW) {
  chartW = chartW || 1000;
  if (n <= 0) return 0;
  const idx = Math.floor(viewBoxX / (chartW / n));
  return Math.max(0, Math.min(n - 1, idx));
}
// 事件清單可點欄位標題排序；預設 col='severity' dir='asc' 時排序結果與既有 sortEventsBySeverity()
// 完全相同（SEV_RANK 本身就是嚴重度由高到低遞增編號），不影響既有預設呈現行為
function sortEventsByColumn(events, col, dir) {
  const mul = dir === 'desc' ? -1 : 1;
  const getVal = e => {
    if (col === 'time') return effectiveTime(e);
    if (col === 'host') return (e.host || '').toLowerCase();
    if (col === 'format') return e.format || '';
    if (col === 'category') return e.category || '';
    return SEV_RANK[e.severityNorm];
  };
  return [...events].sort((a, b) => {
    const va = getVal(a), vb = getVal(b);
    if (va < vb) return -1 * mul;
    if (va > vb) return 1 * mul;
    return a.lineNo - b.lineNo;
  });
}
// 事件清單搜尋框：對主機/內容/原始行文字做不分大小寫子字串比對，僅影響表格顯示，不重新計算
// 問題清單或統計摘要（那些是分析當下對「全部資料」算出的結果，篩選只是換一種檢視角度）
function filterEvents(events, query) {
  if (!query) return events;
  const q = query.toLowerCase();
  return events.filter(e => (e.host || '').toLowerCase().includes(q) || (e.msg || '').toLowerCase().includes(q) || (e.raw || '').toLowerCase().includes(q));
}
// 時間軸點擊篩選（2026-09 新增）用的純函式，state/UI 綁定見下方 TIMELINE_RANGE_FILTER 附近
function filterEventsByTimeRange(events, range) {
  if (!range) return events;
  return events.filter(e => { const t = +e.timestamp; return t >= range.start && t < range.end; });
}

// ============================================================
// [4] 基本資安分析引擎
// ============================================================
const KEYWORD_CATEGORIES = [
  { id: 'authFail', re: /\b(fail(?:ed|ure)?|invalid|incorrect|denied)\b[\s\S]{0,30}\b(login|logon|auth(?:entication)?|password|credential)\b|\b(login|logon|auth(?:entication)?)\b[\s\S]{0,30}\bfail/i },
  // reset-client/reset-server 併入 denyBlock：真實廠牌 CEF 常把「連線遭安全設備主動中斷」
  // 表示為 reset 系列動作（如 PAN-OS/ASA act=reset-server），語意上等同封鎖/拒絕連線；
  // 刻意要求 reset 後面接 client/server/connection/session 才算數，避免「password reset」
  // 這類與資安阻擋無關的一般文字被誤判
  { id: 'denyBlock', re: /\b(deny|denied|drop|dropped|block|blocked|reject|rejected)\b|\breset[-\s]?(?:client|server|connection|session)\b/i },
  { id: 'attack', re: /\b(attack|intrusion|malware|virus|exploit|trojan|worm)\b/i },
  { id: 'scanFlood', re: /\b(scan(?:ning)?|flood(?:ing)?|dos|ddos)\b/i },
  { id: 'exceedThreshold', re: /\b(exceed(?:ed)?|threshold|limit\s+reached|rate\s*limit)\b/i }
];
// CEF 的人類可讀 Name 欄位在真實匯出常是泛用字串（如 "Traffic Event"，多家廠牌一致），
// 實際判定結果落在 act/outcome/reason 等 extension 欄位（如 act=drop/deny/block、
// reason="Malicious IP Match"），只看 Name/deviceProduct 會讓大多數事件誤判為 other；
// Syslog 無此 extension 概念，僅 CEF 格式才額外檢查這些欄位
// 2026-08-27 稽核修復：WEL 事件先前完全仰賴下方 KEYWORD_CATEGORIES 對 Status/SubStatus/
// FailureReason 等欄位值做英文關鍵字比對，但真實 wevtutil/Event Viewer XML 匯出的這些欄位
// 值是十六進位代碼（如 Status="0xc000006d"）或未展開的訊息表佔位符（如 FailureReason=
// "%%2313"），根本不含 "fail"/"invalid" 這類英文字，導致最基本的「登入失敗」事件（4625）
// 實測會分類成 other、完全漏判。改為先比對官方文件明載的標準 Windows Security 稽核
// EventID，比照既有 PRIV_ESC_WINEVENT_IDS 慣例，命中就直接判定 authFail，不依賴欄位文字
// 內容；4625=帳號登入失敗、4771=Kerberos 預先驗證失敗（網域控制站對應事件，環境常只記錄
// 這個而非 4625），皆為 Microsoft 官方文件明載的標準事件 ID，非猜測
// 2026-08-28 擴充：4772=Kerberos TGT 要求失敗、4773=Kerberos 服務票證要求失敗，語意皆等同
// 認證失敗（Microsoft 官方文件明載），併入既有集合沿用同一套頻率式暴力破解偵測，不需新分類
const AUTH_FAIL_WINEVENT_IDS = new Set(['4625', '4771', '4772', '4773']);
// 2026-08-28 新增：僅標記事件分類、不建立獨立 issue（避免例行事件洗版問題清單），比照
// AUTH_FAIL_WINEVENT_IDS 寫法；4672=登入時被授予特殊權限（標出此次登入具管理員等級權限）、
// 4648=明確認證登入（RunAs／橫向移動訊號），皆為官方文件明載的標準 EventID
const SPECIAL_PRIV_LOGON_WINEVENT_IDS = new Set(['4672']);
const EXPLICIT_CRED_LOGON_WINEVENT_IDS = new Set(['4648']);
// 2026-09 新增：4798（列舉使用者的本機群組成員）／4799（列舉安全性群組成員）比照上方同款
// 純標籤分類慣例——這兩個在有部署現代 Windows 的環境是例行高量體事件（任何程式查詢群組
// 成員都會觸發），若當獨立 issue 處理會洗版問題清單，故只標記事件分類供②事件清單顯示，
// 不建立獨立 issue、不進 CHAIN_STAGE_MAP
const GROUP_ENUM_WINEVENT_IDS = new Set(['4798', '4799']);
// 2026-08-29 新增：Sysmon（Microsoft Sysinternals）純標籤分類，比照上方兩組 Set 同款慣例，
// 只標記事件、不建立獨立 issue（3/11/22 在有部署 Sysmon 的端點上事件量體與 4688 同級，
// 無條件計入問題清單會洗版）；務必以 Channel 值收斂範圍，避免誤判其他 Provider 剛好用到
// 同一組低位數 EventID。EventID 1(ProcessCreate) 的選擇性關鍵字偵測見 detectSysmonProcessCreate()
const SYSMON_CHANNEL = 'Microsoft-Windows-Sysmon/Operational';
const SYSMON_TAG_EVENT_IDS = { '3': 'sysmonNetConn', '11': 'sysmonFileCreate', '22': 'sysmonDnsQuery' };
// 2026-08-28（續）新增：4776=NTLM 認證嘗試，與 AUTH_FAIL_WINEVENT_IDS 內其餘 EventID 不同——
// 成功／失敗共用同一個 EventID，需額外解析 Status 欄位（'0x0'=成功；任何非零值=失敗，如
// 0xC000006A=密碼錯誤、0xC0000064=帳號不存在、0xC0000234=帳號被鎖定、0xC0000072=帳號停用，
// 皆為 Microsoft 官方「4776(S, F)」文件列出的標準錯誤碼，非臆測），故獨立判斷式處理，
// 不併入純 EventID 比對的 Set；命中後沿用既有 authFail 分類，不新增分類
// 2026-09-10 新增：4768=Kerberos TGT（初始驗證票證）要求，與 4776 同一類「成功／失敗共用
// 同一個 EventID」情境——XML 的 Data 欄位名稱是 Status（第三十輪查證 elastic/beats 4768 測試資料與 OSSEM-DD
// 事件結構修正；「Result Code」只是描述文字的標籤，事件檢視器 CSV 才會出現），'0x0'=成功；任何非零值=失敗（如
// 0x6=帳號不存在、0x12/0x18=帳號停用或預先驗證失敗、0x17=密碼過期，皆為 Microsoft 官方
// 「4768(S, F)」文件列出的標準 Kerberos 錯誤碼，非臆測）。命中後同樣沿用既有 authFail 分類，
// 不新增分類、不需要新 i18n key。AS-REP Roasting heuristic 見 detectAsrepRoasting()
function classifyByKeyword(evt) {
  // DNS 查詢紀錄本身不是事件（BIND 的 query failed 等字樣不可落入認證失敗等關鍵字），異常由 detectDnsAnomalies() 判斷
  if (evt.fields && ((evt.fields.dns && evt.fields.domain) || evt.fields.dhcp)) return 'other';
  if (evt.fields && evt.fields.ise) return iseAuthFailed(evt.fields) ? 'authFail' : 'other';
  if (evt.netVendor === 'azfw' && evt.fields) return evt.fields.threatIntel ? 'attack' : (evt.fields.action === 'deny' ? 'denyBlock' : 'other');
  if (evt.netVendor === 'winfw') return evt.fields && evt.fields.action === 'deny' ? 'denyBlock' : 'other';
  if (evt.fields && (evt.fields.ssh || evt.fields.sudo)) return sshAuthFailed(evt.fields) ? 'authFail' : 'other';
  if (isVpnAuthFields(evt.fields)) return vpnAuthFailed(evt.fields) ? 'authFail' : 'other';
  if (evt.fields && evt.fields.ldap) return ldapBindFailed(evt.fields) ? 'authFail' : 'other';
  if (evt.fields && evt.fields.dbAuth) return evt.fields.dbAuth === 'fail' ? 'authFail' : 'other';
  if (evt.fields && evt.fields.pcs) return /Fail$/.test(evt.fields.pcs) ? 'authFail' : 'other';
  if (evt.fields && evt.fields.radacct) return 'other';
  if (evt.fields && evt.fields.haproxy) return haproxyDenied(evt.fields) ? 'denyBlock' : 'other';
  if (evt.netVendor === 'cloudflare' && evt.fields) return CF_DENY_RE.test(evt.fields.action || '') ? 'denyBlock' : 'other';
  // FortiMail／FortiManager（XN123）
  if ((evt.netVendor === 'fortimail' || evt.netVendor === 'fortimanager') && evt.fields) {
    const ff = evt.fields;
    if (ff.virus || ff.fmgUnreg) return 'attack';
    if (ff.fmLogin === 'fail' || ff.fmWebmail === 'fail') return 'authFail';
    const n = netOpsInfo(evt); return n ? n.kind : 'other';
  }
  // Stormshield（XN122）
  if (evt.netVendor === 'stormshield' && evt.fields) {
    const sf = evt.fields;
    if (sf.sns === 'alarm') return sf.alarmClass && sf.alarmClass !== 'system' ? 'attack' : 'other';
    if (sf.sns === 'auth' || sf.sns === 'xvpn') return (sf.snsError && sf.snsError !== '0') || /fail/i.test(sf.snsMsg || '') ? 'authFail' : 'other';
    if (sf.sns === 'server') { const n = netOpsInfo(evt); return n ? n.kind : 'other'; }
    return sf.action === 'deny' ? 'denyBlock' : 'other';
  }
  // Meraki（XN120）：IDS、AMP 惡意檔案、SSID 偽冒＝attack；flows deny＝denyBlock；802.1X 失敗與 AnyConnect 拒絕＝authFail
  if (evt.netVendor === 'meraki' && evt.fields) {
    const mf = evt.fields;
    if (mf.alertName || /malicious/i.test(mf.disposition || '') || mf.merakiEvent === 'ssid_spoofing_detected') return 'attack';
    if (mf.merakiEvent === '8021x_eap_failure' || mf.vpnAuth === 'fail') return 'authFail';
    return mf.action === 'deny' ? 'denyBlock' : 'other';
  }
  // F5 Telemetry（XN119）：ASM 攻擊＝attack、AFM Drop／Reject 與 ASM 只有攔截＝denyBlock、APM Logon_Deny＝authFail；LTM 依 HTTP 狀態但 401 不算認證失敗
  if (evt.netVendor === 'f5' && evt.fields) {
    const ff = evt.fields;
    if (ff.asmAttack) return 'attack';
    if (ff.f5 === 'ASM') return /^blocked$/i.test(ff.asmStatus || '') ? 'denyBlock' : 'other';
    if (ff.f5 === 'AFM') return /^(?:drop|reject)$/.test(ff.action || '') ? 'denyBlock' : 'other';
    if (ff.f5 === 'APM') return /deny/i.test(ff.apmResult || '') ? 'authFail' : 'other';
    return ff.status === '403' ? 'denyBlock' : 'other';
  }
  // ModSecurity（XN118）：有規則命中＝attack（idsAlert），沒有規則但被攔截＝denyBlock
  if (evt.netVendor === 'modsec' && evt.fields) return evt.fields.waf && evt.fields.waf.length ? 'attack' : (evt.fields.wafBlocked ? 'denyBlock' : 'other');
  // Vault（XN117）：只看 response；登入錯誤＝authFail、其他 permission denied＝denyBlock、sys/ 設定變更＝configChange
  if (evt.netVendor === 'vault' && evt.fields) {
    const vf = evt.fields;
    if (vf.vault !== 'response') return 'other';
    if (vf.error) return VAULT_LOGIN_RE.test(vf.path) ? 'authFail' : (/permission denied/i.test(vf.error) ? 'denyBlock' : 'other');
    const n = netOpsInfo(evt); return n ? n.kind : 'other';
  }
  // Zscaler（XN113）：威脅＝attack、封鎖＝denyBlock；web 的 401／403 是上游網站的回應，不算本機認證失敗；管理稽核登入失敗＝authFail
  if (evt.netVendor === 'zscaler' && evt.fields) {
    const zf = evt.fields;
    if (zf.zs === 'audit') { const n = netOpsInfo(evt); return n ? n.kind : (zsAuditFailed(zf) ? 'authFail' : 'other'); }
    if (zf.threat) return 'attack';
    return /^Block/i.test(zf.action || '') ? 'denyBlock' : 'other';
  }
  if (evt.netVendor === 'squid' && evt.fields) return /DENIED/.test(evt.fields.squid) && evt.fields.status !== '407' ? 'denyBlock' : 'other';
  if ((evt.format === 'weblog' || evt.format === 'w3c') && evt.fields) {
    return evt.fields.status === '401' ? 'authFail' : (evt.fields.status === '403' ? 'denyBlock' : 'other');
  }
  const netOps = netOpsInfo(evt);
  if (netOps) return netOps.kind;
  // Windows NPS（XN65）：Access-Reject 為認證失敗，其餘（請求、允許、計費）不分類
  if (evt.format === 'nps') return evt.fields && evt.fields.npsPacket === 3 ? 'authFail' : 'other';
  // Aruba ClearPass（XN134）：Login-Status REJECT 為認證失敗
  if (evt.format === 'clearpass') return evt.fields && evt.fields.cppmStatus === 'REJECT' ? 'authFail' : 'other';
  if (evt.format === 'winevent' && evt.fields && evt.fields.EventID === '4776' && evt.fields.Status && evt.fields.Status !== '0x0') return 'authFail';
  if (evt.format === 'winevent' && evt.fields && evt.fields.EventID === '4768') { const rc = evt.fields.Status || evt.fields['Result Code']; if (rc && !/^0x0+$/i.test(rc)) return 'authFail'; }
  if (evt.format === 'winevent' && evt.fields && AUTH_FAIL_WINEVENT_IDS.has(evt.fields.EventID)) return 'authFail';
  if (evt.format === 'winevent' && evt.fields && SPECIAL_PRIV_LOGON_WINEVENT_IDS.has(evt.fields.EventID)) return 'specialPrivLogon';
  if (evt.format === 'winevent' && evt.fields && EXPLICIT_CRED_LOGON_WINEVENT_IDS.has(evt.fields.EventID)) return 'explicitCredLogon';
  if (evt.format === 'winevent' && evt.fields && GROUP_ENUM_WINEVENT_IDS.has(evt.fields.EventID)) return 'groupEnum';
  if (evt.format === 'winevent' && evt.fields && evt.fields.Channel === SYSMON_CHANNEL && SYSMON_TAG_EVENT_IDS[evt.fields.EventID]) return SYSMON_TAG_EVENT_IDS[evt.fields.EventID];
  const parts = [evt.msg || '', evt.appName || ''];
  if (evt.format === 'cef' && evt.fields) {
    parts.push(evt.fields.act || '', evt.fields.outcome || '', evt.fields.reason || '', evt.fields.deviceAction || '');
  }
  if (evt.format === 'leef' && evt.fields) {
    // LEEF 的 EventID（msg）常是廠牌內部代碼，實際語意常落在 extension 的 cat 欄位
    // （官方範例：cat=Failed／cat=Success），比照 CEF 額外檢查
    parts.push(evt.fields.cat || '');
  }
  if (evt.format === 'fortigate' && evt.fields) {
    // FortiOS traffic log 幾乎不帶 msg，語意落在 action（accept/deny/...）；event/system log
    // 則常在 logdesc 帶人類可讀描述（msg 欄位有時為空），比照 CEF 額外檢查
    parts.push(evt.fields.action || '', evt.fields.logdesc || '');
  }
  if (evt.format === 'json' && evt.fields) {
    // JSON 事件的 fields 就是原始 parse 出的物件本身（無統一規格），msg 常是空泛文字，
    // 額外用 ACTION_KEYS 別名撈出 action/outcome/result 等結構化欄位輔助分類
    parts.push(pickField(evt.fields, ACTION_KEYS) || '');
  }
  if (evt.jsonMsg && evt.fields) parts.push(evt.fields.action || '');
  if (evt.format === 'winevent' && evt.fields) {
    // WEL 原始 XML 無 rendered message（見 parseWinEventFragment 註解），語意落在
    // EventData 欄位；常見安全事件（登入/帳號變更）欄位名稱補進比對文字
    parts.push(evt.fields.SubjectUserName || '', evt.fields.TargetUserName || '',
      evt.fields.Status || '', evt.fields.FailureReason || '', evt.fields.SubStatus || '');
  }
  // Microsoft Defender（第十八輪 TK）：告警歸 attack，Informational 或判定為誤報／良性者為 other
  if (evt.netVendor === 'defender' && evt.fields) {
    const d = evt.fields;
    if (d.severity === 'Informational' || /falsePositive|FalsePositive|Benign|NotMalicious/i.test(d.determination || '')) return 'other';
    return 'attack';
  }
  // CrowdStrike Falcon（第十八輪 TJ）：偵測與事件彙整為 attack、主控台登入失敗為 authFail
  if (evt.netVendor === 'falcon' && evt.fields) {
    const c = evt.fields;
    if (c.falconType === 'DetectionSummaryEvent' || c.falconType === 'IncidentSummaryEvent') return 'attack';
    if (c.falconType === 'AuthActivityAuditEvent' && c.success === 'false') return 'authFail';
    return 'other';
  }
  // Zeek（第十八輪 TI）：SSH 登入失敗、notice／intel 告警、連線被拒（REJ）或無回應（S0）
  if (evt.netVendor === 'zeek' && evt.fields) {
    const z = evt.fields;
    if (z.zeekType === 'ssh' && z.authSuccess === 'false') return 'authFail';
    if (z.zeekType === 'notice' || z.zeekType === 'intel') return 'attack';
    if (z.action === 'deny') return 'denyBlock';
    return 'other';
  }
  // netfilter 核心 LOG：前綴已判斷出拒絕時直接歸為封鎖（前綴如 "RDP-DROP"，連字號相連的字也算）
  if (evt.netVendor === 'netfilter' && evt.fields && evt.fields.action === 'deny') return 'denyBlock';
  // 雲端流量紀錄：REJECT／拒絕的 tuple 歸為封鎖
  if (evt.format === 'flowlog' && evt.fields && evt.fields.action === 'deny') return 'denyBlock';
  // Juniper SRX RT_FLOW_SESSION_DENY
  if (evt.netVendor === 'junos' && evt.fields && evt.fields.action === 'deny') return 'denyBlock';
  // H3C 防火牆 SESSION／FILTER 紀錄的 Event／Action 為拒絕
  if (evt.netVendor === 'h3c' && evt.fields && evt.fields.action === 'deny') return 'denyBlock';
  // Suricata 告警（第十四輪 OG）：IPS 模式 blocked 歸封鎖，其餘告警歸攻擊；非告警事件（flow／dns…）不分類
  if (evt.netVendor === 'suricata') return evt.fields && evt.fields.alert ? (String(evt.fields.alert.action).toLowerCase() === 'blocked' ? 'denyBlock' : 'attack') : 'other';
  // Cisco Secure Endpoint 威脅事件（第十五輪 VH）
  // Firepower 事件（第十六輪 PD）：入侵與惡意程式歸 attack，存取控制 Block 歸 denyBlock，其餘連線／檔案事件不靠關鍵字
  // （規則名稱、IntrusionPolicy 等欄位常含 Intrusion 字樣，原本整批被誤判）
  if (evt.format === 'asa' && evt.fields && evt.fields.fpEvent) {
    const f = evt.fields;
    if (f.fpEvent === '430001' || f.fpEvent === '430005') return 'attack';
    if (f.fpEvent === '430004' && (/^malware$/i.test(f.disposition || '') || (f.threat && !/^unknown$/i.test(f.threat)))) return 'attack';
    if (f.action === 'deny' || /^block/i.test(f.fileaction || '') || (f.sicategory && /block/i.test(f.reason || ''))) return 'denyBlock';
    // 連到信譽清單上的位址／網址但只監看放行
    if (f.sicategory) return 'attack';
    return 'other';
  }
  // ASA 認證訊息（第二十輪 FB）：被拒歸 authFail（訊息含 denied／rejected 原本被當成連線遭拒），成功不分類
  if (evt.format === 'asa' && evt.fields && evt.fields.auth) return evt.fields.auth === 'fail' ? 'authFail' : 'other';
  // 雲端身分平台登入失敗（第十六輪 PF）
  if (evt.format === 'json' && evt.cloudRaw) {
    const ci = cloudAuthInfo(evt.cloudRaw);
    if (ci && ci.login && !ci.ok) return 'authFail';
    // Kubernetes 授權拒絕（403）
    if (ci && ci.vendor === 'k8s' && ci.status === 403) return 'denyBlock';
  }
  if (evt.netVendor === 'amp') return AMP_THREAT_RE.test(evt.msgid || '') && !/no detections?/i.test(evt.msgid || '') ? 'attack' : 'other';
  // Cisco Umbrella 封鎖（第十五輪 VG）
  if (evt.netVendor === 'umbrella' && evt.fields && evt.fields.action === 'deny') return 'denyBlock';
  // Check Point（第十五輪 VE）
  if (evt.netVendor === 'checkpoint' && evt.fields && evt.fields.action === 'deny') return 'denyBlock';
  // Juniper IDP／IDS 告警與 AAMW 惡意程式（第十五輪 VF）：拒絕歸封鎖，其餘歸攻擊；UTM／SECINTEL 只看動作
  if (evt.netVendor === 'junos' && evt.fields && evt.fields.jsec) {
    const js = evt.fields;
    // SD 原本的 action 欄位（DROP／BLOCK…）優先保留，故以原值判斷
    if (/^(?:deny|drop|dropped|block|blocked|reject|close)\b/i.test(String(js.action || '')) || /_BLOCKED$/.test(js.event || '')) return 'denyBlock';
    if (js.jsec === 'idp' || js.jsec === 'ids' || js.malware) return 'attack';
  }
  // PAN-OS 入侵類威脅（第二十輪 FC）：阻擋（deny／drop／reset／block）歸 denyBlock，只告警或放行歸 attack
  if (evt.netVendor === 'paloalto' && evt.fields && evt.fields.logtype === 'THREAT' && PAN_IDS_SUBTYPES.has(evt.fields.subtype)) return /^(?:deny|drop|reset|block|sinkhole)/i.test(evt.fields.action || '') ? 'denyBlock' : 'attack';
  // GlobalProtect 登入失敗（第十五輪 VC）
  if (evt.netVendor === 'paloalto' && evt.fields && evt.fields.logtype === 'GLOBALPROTECT' && /^fail/i.test(evt.fields.status || '')) return 'authFail';
  // SonicWall／Sophos（第十四輪 OH）
  if ((evt.netVendor === 'sonicwall' || evt.netVendor === 'sophos') && evt.fields && evt.fields.action === 'deny') return 'denyBlock';
  // Veeam（XN112）：MFA／權杖認證失敗歸 authFail、惡意活動歸 attack，其他 Veeam 事件為 other
  if (evt.netVendor === 'veeam' && evt.fields) return evt.fields.veeamKind === 'authFail' ? 'authFail' : evt.fields.veeamKind === 'malware' ? 'attack' : 'other';
  // QNAP（XN111）：連線紀錄的 Login Fail 歸 authFail，其餘連線紀錄為 other；事件紀錄交給關鍵字分類
  // HPE Aruba CX（XN121）：管理登入失敗＝authFail；其餘交給 netOpsInfo（介面、迴圈、設定變更）
  if (evt.netVendor === 'arubacx' && evt.fields && evt.fields.cx) { if (evt.fields.cxLogin === 'fail') return 'authFail'; const n = netOpsInfo(evt); return n ? (n.kind === 'configChange' ? 'configChange' : 'other') : 'other'; }
  if (evt.netVendor === 'qnap' && evt.fields && evt.fields.qnap === 'conn') return /^Login Fail/i.test(evt.fields.qnapAction || '') ? 'authFail' : 'other';
  // NetScaler（XN109）：登入失敗歸 authFail；登入、登出與管理指令為 other（指令另由 netOpsInfo 產生 configChange）
  if (evt.netVendor === 'netscaler' && evt.fields && (evt.fields.nsAuth || evt.fields.nsLogout || evt.fields.command)) return evt.fields.nsAuth === 'fail' ? 'authFail' : 'other';
  // WatchGuard（XN108）：管理／使用者認證被拒歸 authFail、IPS 簽章歸 attack、流量拒絕歸 denyBlock
  if (evt.netVendor === 'watchguard' && evt.fields) {
    const f = evt.fields;
    if (f.wgAdmin || f.wgAuth) return f.wgAdmin === 'fail' || f.wgAuth === 'fail' ? 'authFail' : 'other';
    // 設定變更另由 netOpsInfo() 產生 configChange；帳號鎖定是前面失敗的結果，不重複計入認證失敗
    if (f.wgCfg || f.wgLockout) return 'other';
    if (f.signature_name) return 'attack';
    if (f.action === 'deny') return 'denyBlock';
  }
  const text = parts.join(' ');
  for (const c of KEYWORD_CATEGORIES) { if (c.re.test(text)) return c.id; }
  return 'other';
}
function analyzeEvents(events) {
  events.forEach(e => {
    e.category = classifyByKeyword(e);
    if (!NETOPS_CATEGORIES.has(e.category) || e.format === 'fortigate') return;
    const n = netOpsInfo(e);
    if (n && (n.user || n.srcip)) {
      e.fields = { ...(e.fields || {}) };
      if (n.user && !e.fields.user) e.fields.user = n.user;
      if (n.srcip && !e.fields.srcip) e.fields.srcip = n.srcip;
      e.netFields = true;
    }
  });
  return events;
}
// 陣列最小／最大值：Math.min(...陣列) 在十幾萬筆時會超出呼叫堆疊
function arrMin(a) { let m = Infinity; for (const v of a) { const x = +v; if (x < m) m = x; } return m; }
function arrMax(a) { let m = -Infinity; for (const v of a) { const x = +v; if (x > m) m = x; } return m; }
function effectiveTime(e) {
  return e.timestamp ? e.timestamp.getTime() : e.lineNo * 1000;
}
// 同 host+category 在時間窗內重複次數達門檻視為頻率式問題（generic、不依賴廠牌事件字典）；
// 無時間戳的事件以行號模擬時間先後順序（假設 log 檔案本身大致依時間序寫入）
function detectFrequencyIssues(events, opts) {
  const windowMs = (opts && opts.windowMs) || 60000;
  const threshold = (opts && opts.threshold) || 5;
  const groups = new Map();
  events.forEach(e => {
    if (NETOPS_CATEGORIES.has(e.category)) return;
    // 沒有真實時間戳的事件以行號模擬時間，「每分鐘幾筆」沒有意義，不列入（比照 detectTimeGaps()）
    if (!e.timestamp) return;
    // DNS 查詢與 DHCP 租約本來就是大量的一般紀錄，不算「其他」類的頻率異常
    if ((e.category || 'other') === 'other' && e.fields && (e.fields.dns || e.fields.dhcp || e.fields.ldap || e.fields.radacct)) return;
    // 有來源位址的 LDAP 繫結失敗由 detectLdapIssues() 的 ldapBruteForce 依來源彙整，這裡不重複列頻率問題
    if (e.category === 'authFail' && e.fields && e.fields.ldap && e.fields.srcip) return;
    const key = `${e.host || '?'}|${e.category || 'other'}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(e);
  });
  // episode 追蹤（比照 detectLateralMovement() 既有修法）：先前用 windowCount===threshold
  // 精確匹配，視窗內計數一旦超過門檻就不再觸發也不再更新，長時間/高密度的持續攻擊會被凍結
  // 在「恰好等於門檻值」那一刻的快照，count/lastSeen/relatedEvents 從此不再更新，嚴重低估
  // 規模（2026-09 全功能審查發現）。改為達門檻時開案，之後持續就地更新到目前為止看過的
  // 最大範圍，直到視窗計數掉回門檻以下才結束這一波
  const issues = [];
  for (const [key, list] of groups) {
    const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    const times = sorted.map(effectiveTime);
    const [host, category] = key.split('|');
    let winStart = 0;
    let episode = null, bestStart = 0, bestEnd = 0;
    // 短時間大量事件時視窗可達數萬筆，逐筆 slice 會呈平方成長（第二十八輪 OP1）：
    // 只記錄最大視窗的起訖索引，波段結束時才取出事件
    const closeEpisode = () => { if (episode) episode.relatedEvents = sorted.slice(bestStart, bestEnd + 1); episode = null; };
    for (let i = 0; i < sorted.length; i++) {
      const ti = times[i];
      while (times[winStart] < ti - windowMs) winStart++;
      const windowCount = i - winStart + 1;
      if (windowCount >= threshold) {
        if (!episode) {
          episode = {
            category: `freq:${category}`,
            // 「其他」類只是量多，不代表有問題，列為 Low
            severityNorm: category === 'authFail' ? 'Critical' : category === 'other' ? 'Low' : 'High',
            count: windowCount,
            firstSeen: sorted[winStart].timestamp || null,
            lastSeen: sorted[i].timestamp || null,
            sampleRaw: sorted[i].raw,
            relatedHosts: [host],
            relatedEvents: [],
            confidence: 'confirmed',
            windowMs, threshold
          };
          bestStart = winStart; bestEnd = i;
          issues.push(episode);
        } else {
          episode.lastSeen = sorted[i].timestamp || null;
          if (windowCount > episode.count) {
            episode.count = windowCount;
            episode.sampleRaw = sorted[i].raw;
            bestStart = winStart; bestEnd = i;
          }
        }
      } else {
        closeEpisode();
      }
    }
    closeEpisode();
  }
  return issues;
}
// 時間戳斷點檢查（2026-09-14 新增）：依 effectiveTime() 排序後，相鄰兩筆事件間隔超過門檻
// 視為可能的日誌蒐集中斷（斷點期間可能有事件未被收集），純算術不依賴任何廠牌格式；無時間戳
// 事件用行號模擬時間序（與 effectiveTime() 既有假設一致），此情境下的「間隔」語意是行號差
// 換算的虛擬秒數，不代表真實時間長度，故只在至少有一筆事件帶有真實 e.timestamp 時才回報
// 非上班時間高權限操作（2026-10-14，第二十四輪 JB）：預設關閉。cfg = {enabled, start, end（分鐘，start≤t<end 為上班），
// days（上班的星期，0=日）, tzOffsetMin（UTC 位移分鐘）, holidays（YYYY-MM-DD 集合）}；以設定的時區換算時間
// （ts＋位移後讀 UTC 欄位），不受瀏覽器所在時區影響。取既有敏感類問題的事件，再加 sudo 指令與 4672 特殊權限登入，
// 依行為者（帳號優先）彙整；只標記時間，不判斷操作本身好壞
const OFF_HOURS_ISSUE_CATS = new Set(['adminLoginExternal', 'dbAdminRemote', 'dbExternalLogin', 'appsmithResetFlow', 'appsmithExternalRisky', 'appCredentialAdded', 'sshKeyMultiSource', 'gitlabTokenCreated', 'gitlabMassClone', 'awsRootUsage', 'adminLoginFailExternal', 'dcsync', 'rdpLogon', 'adSensitiveChange', 'sidHistory', 'dsrmPassword', 'privEsc', 'pwReset', 'groupRemoved', 'acctDeleted', 'auditPolicyChanged', 'auditCleared', 'persistence', 'configChange', 'netAdminAdd', 'k8sExec', 'k8sSecretAccess']);
function parseWorkTime(v, def) {
  const m = String(v || '').trim().match(/^(\d{1,2}):?(\d{2})?$/);
  if (!m || +m[1] > 24 || +(m[2] || 0) > 59) return def;
  return Math.min(24 * 60, +m[1] * 60 + +(m[2] || 0));
}
function parseWorkDays(v) {
  const set = new Set();
  String(v || '').split(/[,\s]+/).filter(Boolean).forEach(part => {
    const m = part.match(/^([0-7])(?:-([0-7]))?$/);
    if (!m) return;
    const a = +m[1] % 7, b = m[2] === undefined ? a : +m[2] % 7;
    for (let d = a, i = 0; i < 7; d = (d + 1) % 7, i++) { set.add(d); if (d === b) break; }
  });
  return set.size ? set : new Set([1, 2, 3, 4, 5]);
}
// UTC 位移：'local' 代表依瀏覽器時區逐筆換算（跨夏令時間的 log 每筆用當時的位移），其餘為固定分鐘數
function tzOffsetAt(ts, tz) {
  return tz === 'local' ? -ts.getTimezoneOffset() : (Number(tz) || 0);
}
function isOffHours(ts, cfg) {
  if (!ts) return false;
  const d = new Date(ts.getTime() + tzOffsetAt(ts, cfg.tzOffsetMin) * 60000);
  const t = d.getUTCHours() * 60 + d.getUTCMinutes();
  // 跨午夜時段的凌晨部分（t < end）屬於前一天的班，上班日與假日依前一天判斷
  const day = cfg.start > cfg.end && t < cfg.end ? new Date(d.getTime() - 86400000) : d;
  const ymd = day.toISOString().slice(0, 10);
  if (cfg.holidays && cfg.holidays.has(ymd)) return true;
  if (!cfg.days.has(day.getUTCDay())) return true;
  // 跨午夜的上班時段（如 22:00-06:00）：落在結束與開始之間才是時段外
  return cfg.start <= cfg.end ? (t < cfg.start || t >= cfg.end) : (t >= cfg.end && t < cfg.start);
}
// 事件的「操作者」帳號：Windows 事件中 TargetUserName 多半是被操作的對象（被加入的群組、被建立的帳號），
// 只有登入／驗證類事件的 TargetUserName 才是登入者，其餘以 SubjectUserName 為準；SYSTEM、服務帳號與電腦帳號（$ 結尾）不算
const ACTOR_LOGON_EVENT_IDS = new Set(['4624', '4625', '4634', '4647', '4648', '4768', '4769', '4771', '4772', '4776', '4778', '4779']);
const ACTOR_SKIP_RE = /^(?:-|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|.*\$)$/i;
function eventActorUser(e) {
  const f = e.fields || {};
  const ok = u => (u && !ACTOR_SKIP_RE.test(String(u).trim()) ? String(u) : '');
  if (f.user) return ok(f.user);
  if (e.format === 'winevent') {
    return ACTOR_LOGON_EVENT_IDS.has(String(f.EventID)) ? (ok(f.TargetUserName) || ok(f.SubjectUserName)) : (ok(f.SubjectUserName) || ok(f.TargetUserName));
  }
  return ok(f.SubjectUserName) || ok(f.TargetUserName);
}
function offHoursActor(e) {
  const f = e.fields || {};
  return eventActorUser(e) || f.srcip || e.host || '';
}
function detectOffHours(issues, events, cfg) {
  if (!cfg || !cfg.enabled) return [];
  const picked = new Map();
  const take = (e, cat) => {
    if (!e || !e.timestamp || picked.has(e) || !isOffHours(e.timestamp, cfg)) return;
    picked.set(e, cat);
  };
  (issues || []).forEach(is => { if (OFF_HOURS_ISSUE_CATS.has(is.category)) (is.relatedEvents || []).forEach(e => take(e, is.category)); });
  (events || []).forEach(e => {
    if (e.fields && e.fields.sudo === 'command') take(e, 'sudo');
    else if (e.category === 'specialPrivLogon') take(e, 'specialPrivLogon');
  });
  const byActor = new Map();
  picked.forEach((cat, e) => {
    const a = offHoursActor(e) || '-';
    if (!byActor.has(a)) byActor.set(a, []);
    byActor.get(a).push({ e, cat });
  });
  const out = [];
  byActor.forEach((list, actor) => {
    list.sort((x, y) => x.e.timestamp - y.e.timestamp);
    const first = list[0];
    const local = new Date(first.e.timestamp.getTime() + tzOffsetAt(first.e.timestamp, cfg.tzOffsetMin) * 60000).toISOString().slice(0, 16).replace('T', ' ');
    const kind = first.cat === 'sudo' ? { key: 'sample.offHours_sudo' } : { key: 'cat.' + first.cat };
    out.push({
      category: 'offHours', severityNorm: 'Medium', count: list.length,
      firstSeen: first.e.timestamp, lastSeen: list[list.length - 1].e.timestamp,
      ...sampleOf('sample.offHours', { actor, n: list.length, time: local, kind }),
      relatedHosts: [actor], relatedEvents: list.map(x => x.e), confidence: 'heuristic'
    });
  });
  return out;
}
// 帳號常用時段基線（第二十五輪 LD）：只統計帳號（不取 IP／主機），每個帳號 24 小時各幾筆；
// 小時以基線本身記錄的時區位移換算，本期偵測沿用同一位移
function usualHourActor(e) {
  return eventActorUser(e);
}
function eventLocalHour(ts, tzOffsetMin) {
  return new Date(ts.getTime() + tzOffsetAt(ts, tzOffsetMin) * 60000).getUTCHours();
}
function buildActorHourBaseline(events, tzOffsetMin) {
  const actors = {};
  (events || []).forEach(e => {
    const a = e.timestamp ? usualHourActor(e) : '';
    if (!a) return;
    if (!actors[a]) actors[a] = new Array(24).fill(0);
    actors[a][eventLocalHour(e.timestamp, tzOffsetMin)]++;
  });
  return { tzOffsetMin: tzOffsetMin === 'local' ? 'local' : (tzOffsetMin || 0), actors };
}
const UNUSUAL_HOUR_MIN_BASE = 20;
// 帳號在基線至少 20 筆，本期事件所在小時與前後一小時在基線都沒有紀錄時列入，依帳號彙整
function detectUnusualHours(events, baseline) {
  if (!baseline || !baseline.actors || typeof baseline.actors !== 'object') return [];
  const tz = baseline.tzOffsetMin === 'local' ? 'local' : (Number(baseline.tzOffsetMin) || 0);
  const byActor = new Map();
  (events || []).forEach(e => {
    const a = e.timestamp ? usualHourActor(e) : '';
    const base = a && baseline.actors[a];
    if (!Array.isArray(base) || base.length !== 24) return;
    if (base.reduce((x, y) => x + (Number(y) || 0), 0) < UNUSUAL_HOUR_MIN_BASE) return;
    const h = eventLocalHour(e.timestamp, tz);
    if ([h + 23, h, h + 1].some(x => Number(base[x % 24]) > 0)) return;
    if (!byActor.has(a)) byActor.set(a, []);
    byActor.get(a).push({ e, h });
  });
  const out = [];
  byActor.forEach((list, actor) => {
    list.sort((x, y) => x.e.timestamp - y.e.timestamp);
    const hours = [...new Set(list.map(x => x.h))].sort((x, y) => x - y).map(h => String(h).padStart(2, '0') + ':00').join(', ');
    out.push({
      category: 'unusualHour', severityNorm: 'Low', count: list.length,
      firstSeen: list[0].e.timestamp, lastSeen: list[list.length - 1].e.timestamp,
      ...sampleOf('sample.unusualHour', { actor, n: list.length, hours }),
      relatedHosts: [actor], relatedEvents: list.map(x => x.e), confidence: 'heuristic'
    });
  });
  return out;
}
// 帳號新登入來源（第二十六輪 SB）：沿用 LD 的帳號判斷，來源鍵依可用資料由粗到細選一種：
// 已載入 ASN 資料庫 → ASN；否則已載入地理資料庫 → 國家；否則 IPv4 /24、IPv6 /48。認證失敗事件不列入
function sourceKeyType(opts) {
  if (opts && opts.asnIndexes && opts.asnIndexes.length) return 'asn';
  if (opts && opts.geoIndexes && opts.geoIndexes.length) return 'country';
  return 'net';
}
function eventSourceIp(e) {
  const f = e.fields || {};
  const ip = String(f.srcip || f.IpAddress || f.src || '').trim().replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, '$1');
  if (!ip || ip === '-' || /^(127\.|::1$|0\.0\.0\.0$)/.test(ip)) return '';
  return /^\d+\.\d+\.\d+\.\d+$/.test(ip) || /^[0-9a-f:]+$/i.test(ip) && ip.includes(':') ? ip : '';
}
function sourceKeyOf(e, keyType, opts) {
  const ip = eventSourceIp(e);
  if (!ip) return '';
  if (keyType === 'asn') {
    for (const idx of opts.asnIndexes) { const h = lookupASN(idx, ip); if (h && h.asn) return 'AS' + String(h.asn).replace(/^AS/i, ''); }
    return '';
  }
  if (keyType === 'country') {
    for (const idx of opts.geoIndexes) { const h = intelLookup(idx, ip); const c = h && h.meta && h.meta.country; if (c) return String(c).trim().toUpperCase(); }
    return '';
  }
  if (ip.includes(':')) {
    // 先展開成 8 組再取前 3 組，同一網段的不同寫法（::、補零）才會得到同一個鍵
    const n = ipv6ToBigInt(ip.split('%')[0]);
    if (n === null) return '';
    return [(n >> 112n) & 0xffffn, (n >> 96n) & 0xffffn, (n >> 80n) & 0xffffn].map(x => x.toString(16)).join(':') + '::/48';
  }
  return ip.split('.').slice(0, 3).join('.') + '.0/24';
}
const NEW_SOURCE_MAX_KEYS = 50;
function buildActorSourceBaseline(events, opts) {
  const keyType = sourceKeyType(opts);
  const actors = {};
  (events || []).forEach(e => {
    const a = usualHourActor(e);
    if (!a || e.category === 'authFail') return;
    const k = sourceKeyOf(e, keyType, opts || {});
    if (!k) return;
    const rec = actors[a] || (actors[a] = { n: 0, keys: [] });
    rec.n++;
    if (!rec.keys.includes(k) && rec.keys.length < NEW_SOURCE_MAX_KEYS) rec.keys.push(k);
  });
  return { keyType, actors };
}
// 帳號在基線至少 20 筆、基線與本期的來源鍵種類相同，本期來源鍵不在基線時列入，依帳號彙整
function detectNewSources(events, baseline, opts) {
  if (!baseline || !baseline.actors || typeof baseline.actors !== 'object') return [];
  const keyType = sourceKeyType(opts);
  if (baseline.keyType !== keyType) return [];
  const byActor = new Map();
  (events || []).forEach(e => {
    const a = usualHourActor(e);
    const base = a && baseline.actors[a];
    if (!base || !Array.isArray(base.keys) || (Number(base.n) || 0) < UNUSUAL_HOUR_MIN_BASE || e.category === 'authFail') return;
    const k = sourceKeyOf(e, keyType, opts || {});
    if (!k || base.keys.includes(k)) return;
    if (!byActor.has(a)) byActor.set(a, []);
    byActor.get(a).push({ e, k });
  });
  const out = [];
  byActor.forEach((list, actor) => {
    list.sort((x, y) => (x.e.timestamp || 0) - (y.e.timestamp || 0));
    const keys = [...new Set(list.map(x => x.k))];
    out.push({
      category: 'newSource', severityNorm: 'Low', count: list.length,
      firstSeen: list[0].e.timestamp || null, lastSeen: list[list.length - 1].e.timestamp || null,
      ...sampleOf('sample.newSource', { actor, n: list.length, sources: keys.slice(0, 5).join(', ') + (keys.length > 5 ? ' …' : '') }),
      relatedHosts: [actor], relatedEvents: list.map(x => x.e), confidence: 'heuristic'
    });
  });
  return out;
}
// 時間缺口摘要用的時間與間隔文字（本地時間，與語言無關）
function fmtGapTime(d) {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function fmtGapDur(ms) {
  const m = Math.round(ms / 60000), d = Math.floor(m / 1440), h = Math.floor((m % 1440) / 60);
  return (d ? d + 'd ' : '') + (d || h ? h + 'h ' : '') + (m % 60) + 'm';
}
function detectTimeGaps(events, opts) {
  const gapThresholdMs = (opts && opts.gapThresholdMs) || 3600000;
  if (!events.length) return [];
  // 2026-09-21 修復：先前只檢查「至少一筆」事件有真實時間戳就對全部事件（含無時間戳的）排序
  // 比較，無時間戳事件的 effectiveTime() fallback 是 lineNo*1000（約 1970 年附近），真實環境
  // 常見同一批事件裡部分有真實時間戳、部分沒有（非全有或全無），混合情境下假時間戳事件會排
  // 在真時間戳事件之前，兩者交界處產生一個長達數十年的假「間隔」問題。改為只對有真實時間戳
  // 的事件子集排序比較，避免混入行號模擬時間
  const realEvents = events.filter(e => e.timestamp);
  if (realEvents.length < 2) return [];
  const sorted = [...realEvents].sort((a, b) => effectiveTime(a) - effectiveTime(b));
  const issues = [];
  for (let i = 1; i < sorted.length; i++) {
    const gap = effectiveTime(sorted[i]) - effectiveTime(sorted[i - 1]);
    if (gap >= gapThresholdMs) {
      issues.push({
        category: 'timeGap',
        severityNorm: 'Low',
        count: 1,
        firstSeen: sorted[i - 1].timestamp || null,
        lastSeen: sorted[i].timestamp || null,
        ...sampleOf('sample.timeGap', { from: fmtGapTime(sorted[i - 1].timestamp), to: fmtGapTime(sorted[i].timestamp), dur: fmtGapDur(gap) }),
        relatedHosts: [...new Set([sorted[i - 1].host, sorted[i].host].filter(Boolean))],
        relatedEvents: [sorted[i - 1], sorted[i]],
        confidence: 'heuristic',
        gapMs: gap,
      });
    }
  }
  return issues;
}
// CEF 結構化欄位（src+dst/dpt）可靠度較高的掃描 heuristic：同一 src 短時間對多個不同
// dst/dpt 組合存取
function detectScanHeuristicCEF(events, opts) {
  const threshold = (opts && opts.threshold) || 5;
  const bySrc = new Map();
  // MikroTik 防火牆 log（parseMikroTikMsg() 拆出 srcip/dstip/dstport）同屬結構化欄位，一併納入
  const tupleOf = e => e.format === 'cef' ? { src: e.fields.src, dst: e.fields.dst, dpt: e.fields.dpt }
    : (e.netFields ? { src: e.fields.srcip, dst: e.fields.dstip, dpt: e.fields.dstport } : null);
  events.forEach(e => {
    const t = e.fields ? tupleOf(e) : null;
    if (!t || !t.src || !(t.dst || t.dpt)) return;
    if (!bySrc.has(t.src)) bySrc.set(t.src, { targets: new Set(), events: [] });
    const g = bySrc.get(t.src);
    g.targets.add(`${t.dst || ''}:${t.dpt || ''}`);
    g.events.push(e);
  });
  const issues = [];
  for (const [src, g] of bySrc) {
    if (g.targets.size >= threshold) {
      issues.push({
        category: 'possibleScan', severityNorm: 'High', count: g.targets.size,
        firstSeen: null, lastSeen: null,
        ...sampleOf('sample.portScan', { src, n: g.targets.size }),
        relatedHosts: [src], relatedEvents: g.events, confidence: 'heuristic'
      });
    }
  }
  return issues;
}
const IP_RE_G = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
function isPlausibleIPv4(ip) { return ip.split('.').every(p => Number(p) <= 255); }
// IPv6_RE/MAC_SHAPE_RE 原本只給去識別化模組用（下方 replaceIPsInLine() 仍引用同一份定義），
// 搬到這裡讓情資比對/掃描偵測的候選 IP 擷取也能共用，不重複定義兩份正則
const IPv6_RE = /(?<!\w)(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))(?![:\w])/g;
// 冒號格式 MAC 與 IPv6_RE 的形狀重疊，真實 IPv6 地址不會是這個形狀（沒有 :: 縮寫、每組固定
// 2 碼），排除避免誤判成 IPv6
// 6 段以上、每段兩位十六進位的串一律視為 MAC（含 netfilter 核心 LOG 的 MAC= 目的＋來源＋EtherType 連寫串，
// 2026-10-02），不當 IPv6 處理
const MAC_SHAPE_RE = /^([0-9A-Fa-f]{2}:){5,}[0-9A-Fa-f]{2}$/;
function extractIPsFromText(text) {
  if (!text) return [];
  const v4 = (text.match(IP_RE_G) || []).filter(isPlausibleIPv4);
  const v6 = (text.match(IPv6_RE) || []).filter(m => m.split(':').length >= 4 && !MAC_SHAPE_RE.test(m));
  return Array.from(new Set([...v4, ...v6]));
}
// 通用 key=value / key="value" 擷取：FortiGate 等廠牌原生 syslog log body 常見用這種語法
// （非 CEF，但語法相近，非結構化格式的 RFC3164/5424 MSG 欄位裡常見），僅供「可選顯示欄位」
// 這類輔助資訊 best-effort 擷取用，不用於格式判定或嚴重度依據
function extractKeyValueFields(text) {
  const fields = {};
  if (!text) return fields;
  const re = /([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|(\S+))/g;
  let m;
  // key 一律轉小寫存入：部分廠牌（如 UniFi kernel netfilter 記錄，SRC=/DST=/PROTO=/SPT=/DPT=）
  // 全大寫，轉小寫後即可直接命中既有別名表（SRC_IP_KEYS 等皆收小寫），值本身大小寫不動
  while ((m = re.exec(text))) fields[m[1].toLowerCase()] = m[2] !== undefined ? m[2] : m[3];
  return fields;
}
// ECS（Elastic Common Schema）風格點號鍵名（如 source.ip）皆已加入下方各別名表，
// 由 pickField() 的巢狀路徑走訪負責解析，各表本身不需額外處理
const SRC_IP_KEYS = ['srcip', 'src_ip', 'source_ip', 'src', 'source.ip'];
const DST_IP_KEYS = ['dstip', 'dst_ip', 'destination_ip', 'dst', 'destination.ip', 'dest_ip'];
const SRC_PORT_KEYS = ['srcport', 'src_port', 'sport', 'spt', 'srcPort', 'source.port'];
const DST_PORT_KEYS = ['dstport', 'dst_port', 'dport', 'dpt', 'dstPort', 'destination.port', 'dest_port'];
const PROTO_KEYS = ['proto', 'protocol', 'network.protocol'];
// 主要 log 匯入 JSON 事件用的欄位別名（無統一規格，依常見命名慣例 best-effort 對應）
const TS_KEYS = ['timestamp', 'time', 'date', '@timestamp', 'eventTime', 'event_time'];
const SEV_KEYS = ['severity', 'level', 'priority', 'severityLevel', 'log.level'];
const HOST_KEYS = ['host', 'hostname', 'device', 'source', 'computer', 'dvc', 'host.name'];
const MSG_KEYS = ['message', 'msg', 'description', 'text', 'log'];
const APP_KEYS = ['appName', 'application', 'process', 'program', 'service', 'process.name'];
// 2026-08-20 新增：URL/HTTP 欄位表。CEF 官方擴充字典有 request（URL，含 query string）/
// requestMethod；FortiGate log 欄位字典有 url/method。其餘格式（LEEF/RFC5424/RFC3164/ASA）
// 無固定命名規格，比照既有慣例不猜測，留空
const URL_KEYS = ['url', 'request'];
const HTTP_METHOD_KEYS = ['requestMethod', 'method'];
// JSON 事件的動作/結果欄位別名（供 classifyByKeyword() 比照 CEF/LEEF/FortiGate 的結構化欄位
// 加強比對慣例使用，2026-08-19 新增；含 ECS 風格點號鍵名 event.action/event.outcome）
const ACTION_KEYS = ['action', 'outcome', 'result', 'status', 'disposition', 'reason', 'event.action', 'event.outcome'];
// pickField()：對含 '.' 的 key 先嘗試扁平字面比對（例如 log shipper 匯出的 "event.outcome"
// 本身就是字面上帶點號的第一層 key，這是 ACTION_KEYS 原本就已支援的情況，須維持不回歸），
// 找不到才逐層走訪真正巢狀的 ECS JSON（如 {source:{ip:'1.2.3.4'}}），兩種輸入皆可正確命中
function pickField(fields, keys) {
  for (const k of keys) {
    if (fields[k] !== undefined) return fields[k];
    if (k.indexOf('.') !== -1) {
      const nested = k.split('.').reduce((o, p) => (o == null ? o : o[p]), fields);
      if (nested !== undefined) return nested;
    }
  }
  return null;
}
// 可選顯示欄位（來源/目的 IP、Port、通訊協定）的統一資料來源：CEF 走結構化 extension 欄位；
// Syslog 無正式 extension 概念，改用上面的 key=value best-effort 擷取，抓不到時維持 '-'，
// 不強行用正則臆測不存在的資訊
// log → 防火牆反查（2026-09-30 新增，第八輪 XB）：把事件的來源／目的／目的埠／協定整理成防火牆
// 規則查詢的條件。port 欄位是 getEventNetTuple() 的顯示字串（「來源埠→目的埠」），只取目的埠；
// 協定對應到防火牆查詢下拉的 TCP／UDP／ICMP（含 IANA 協定號 6／17／1），其餘視為不限。
// 來源或目的缺一就回傳 null（不顯示按鈕）
function buildFwQueryPayload(tuple) {
  const clean = v => { const t = String(v == null ? '' : v).trim(); return t === '-' ? '' : t; };
  const src = clean(tuple && tuple.src), dst = clean(tuple && tuple.dst);
  // 只接受 IP 位址字元（IPv4／IPv6，可帶 /前綴長度）：防火牆查詢只吃位址，也避免 log 內容夾帶字元進 onclick
  const isAddr = v => /^[0-9A-Fa-f:.]+(\/\d{1,3})?$/.test(v) && /[.:]/.test(v);
  if (!isAddr(src) || !isAddr(dst)) return null;
  const portRaw = clean(tuple.port);
  const dport = clean(portRaw.includes('→') ? portRaw.split('→')[1] : portRaw);
  const p = clean(tuple.proto).toLowerCase();
  const proto = (p === 'tcp' || p === '6') ? 'TCP' : (p === 'udp' || p === '17') ? 'UDP' : (p === 'icmp' || p === '1') ? 'ICMP' : 'any';
  return { src, dst, port: /^\d{1,5}$/.test(dport) ? dport : '', proto };
}
// log → 防火牆批次反查（第十二輪 ME）：事件的實際結果——明確的 action 欄位優先（各解析器已正規化為
// accept／deny，或廠牌原值 allow／permit／pass），其次為 denyBlock 分類；FortiGate 流量 log 的
// close／timeout／start／server-rst／client-rst 都是規則已放行的工作階段結束方式（Fortinet 官方 KB
// 「understanding action close, reset and timeout in FortiGate forward traffic logs」），也算放行。
// 判斷不出來（如一般 syslog）回傳空字串，不列入批次；ASA 的 106023／106100／302013／302015 由 parseASAFields() 帶 action
const FW_DENY_ACTION_RE = /^(?:deny|denied|drop|dropped|block|blocked|reject|rejected)$/i;
const FW_ALLOW_ACTION_RE = /^(?:accept|accepted|allow|allowed|permit|permitted|pass|passed)$/i;
const FORTI_ALLOW_ACTION_RE = /^(?:close|timeout|start|server-rst|client-rst)$/i;
function eventFwOutcome(e) {
  const f = (e && e.fields) || {};
  const a = String(f.action || f.act || '').trim();
  if (a) {
    if (FW_DENY_ACTION_RE.test(a)) return 'deny';
    if (FW_ALLOW_ACTION_RE.test(a)) return 'accept';
    if (e.format === 'fortigate' && FORTI_ALLOW_ACTION_RE.test(a)) return 'accept';
  }
  // MikroTik 規則 log 沒有動作欄位，看 log-prefix 是否寫明（XN129）
  const lp = String(f.logprefix || '');
  if (lp && /\b(?:drop|deny|block|reject)/i.test(lp)) return 'deny';
  if (lp && /\b(?:accept|allow|permit)/i.test(lp)) return 'accept';
  return e && e.category === 'denyBlock' ? 'deny' : '';
}
// 依「來源、目的、協定、目的埠、實際結果」彙整，依筆數取前 FW_BATCH_MAX 組，輸出防火牆批次查詢 CSV
// （src,dst,proto,port,expect,count；expect 為 log 的實際結果，count 只供對照）
const FW_BATCH_MAX = 200;
// opts.includeUnknown（XN131）：log 看不出結果的事件也送出（expect 留空），由防火牆設定判斷
function buildFwBatchCsv(events, opts) {
  const groups = new Map();
  (events || []).forEach(e => {
    const out = eventFwOutcome(e);
    if (!out && !(opts && opts.includeUnknown)) return;
    const q = buildFwQueryPayload(getEventNetTuple(e));
    if (!q) return;
    const k = [q.src, q.dst, q.proto, q.port, out].join('|');
    const g = groups.get(k);
    if (g) g.count++; else groups.set(k, Object.assign({}, q, { expect: out, count: 1 }));
  });
  const list = [...groups.values()].sort((a, b) => b.count - a.count);
  const top = list.slice(0, FW_BATCH_MAX);
  const csv = ['src,dst,proto,port,expect,count'].concat(top.map(r => [r.src, r.dst, r.proto, r.port, r.expect, r.count].join(','))).join('\n');
  return { csv, rows: top.length, total: list.length };
}
function sendFwBatchQuery() {
  const filtered = filterEventsBySourceFile(filterEventsByTimeRange(filterEvents(EVENTS, document.getElementById('results-search').value.trim()), TIMELINE_RANGE_FILTER), RESULTS_FILE_FILTER);
  const b = buildFwBatchCsv(filtered);
  if (!b.rows) { alert(tr('fwq.batch_none')); return; }
  if (b.total > b.rows && !confirm(tr('fwq.batch_cut').replace('{total}', b.total).replace('{n}', b.rows))) return;
  sendToFirewallQuery({ batch: b.csv });
}
// 一次性交接 key `_netAnalyzer_fwQuery`（TTL 30 秒，防火牆頁開啟時立刻取出並清除；比照既有
// `_netAnalyzer_pending` 慣例，彈出視窗被攔截時立刻清掉剛寫入的 key）
function sendToFirewallQuery(q) {
  // 寫入失敗（容量不足等）與彈出視窗被攔截分開提示
  try { localStorage.setItem('_netAnalyzer_fwQuery', JSON.stringify(Object.assign({}, q, { ts: Date.now() }))); } catch (e) { alert(tr('err.storage_full')); return; }
  const w = window.open('firewall-analyzer-fixed.html', '_blank');
  if (!w) { try { localStorage.removeItem('_netAnalyzer_fwQuery'); } catch (e) {} alert(tr('err.popup_blocked')); }
  else FW_QUERY_WINS.add(w);  // 只接受自己開啟的防火牆分析頁回傳的對照結果（XN131）
}
// 防火牆設定對照結果（XN131）：防火牆分析算完批次查詢後以 postMessage 回傳每組連線的判斷，
// 只含 log 自己送出的連線與 accept／deny／mixed／unknown，不含設定內容。逐欄驗證，任何一列不合格整批丟棄
const FW_VERDICT_ACTIONS = ['accept', 'deny', 'mixed', 'unknown'];
function fwTupleKey(q) { return [q.src, q.dst, q.proto, q.port].join('|'); }
function parseFwBatchReply(d) {
  if (!d || d.type !== '_naFwBatchResult' || !Array.isArray(d.rows) || !d.rows.length || d.rows.length > FW_BATCH_MAX) return null;
  const isAddr = v => typeof v === 'string' && v.length <= 49 && /^[0-9A-Fa-f:.]+(\/\d{1,3})?$/.test(v) && /[.:]/.test(v);
  const out = new Map();
  for (const r of d.rows) {
    if (!r || !isAddr(r.src) || !isAddr(r.dst)) return null;
    if (!['any', 'TCP', 'UDP', 'ICMP'].includes(r.proto)) return null;
    if (typeof r.port !== 'string' || !/^\d{0,5}$/.test(r.port)) return null;
    if (!FW_VERDICT_ACTIONS.includes(r.action)) return null;
    out.set(fwTupleKey(r), { action: r.action, nat: r.nat === true });
  }
  return out;
}
// 一組事件（某個問題或某條攻擊鏈）的對照統計，以「來源、目的、協定、目的埠」為一組：
// accept／deny／unknown（含 mixed）／unchecked 為組數；reachable＝設定放行而 log 看不出結果（設定上打得到）；
// mismatch＝log 的結果與設定判斷相反（設定檔可能不是當時的版本，或實際進入介面與查詢推得的不同）
function fwVerdictSummary(events, verdicts) {
  const sum = { accept: 0, deny: 0, unknown: 0, unchecked: 0, reachable: 0, mismatch: 0 };
  if (!verdicts || !verdicts.size) return sum;
  const groups = new Map();
  (events || []).forEach(e => {
    const q = buildFwQueryPayload(getEventNetTuple(e));
    if (!q) return;
    const k = fwTupleKey(q);
    if (!groups.has(k)) groups.set(k, new Set());
    groups.get(k).add(eventFwOutcome(e));
  });
  groups.forEach((outs, k) => {
    const v = verdicts.get(k);
    if (!v) { sum.unchecked++; return; }
    if (v.action === 'accept') { sum.accept++; if (outs.has('deny')) sum.mismatch++; else if (!outs.has('accept')) sum.reachable++; }
    else if (v.action === 'deny') { sum.deny++; if (outs.has('accept')) sum.mismatch++; }
    else sum.unknown++;
  });
  return sum;
}
// log → 交換器介面對照（2026-10-02，第九輪發想 YH）：介面反覆上下線／err-disable／PoE 異常問題，
// 帶設備名稱與介面名稱開啟交換器分析，載入該設備設定後顯示該埠的描述、VLAN、管理狀態與 LLDP 對端。
// 一次性交接 key `_netAnalyzer_swPortQuery`（TTL 30 秒，交換器頁開啟時取出並清除）。
// 只接受介面名稱常見字元（英數、/ . : - 與空白），也避免 log 內容夾帶字元進 onclick
function buildSwPortPayload(is) {
  const iface = String((is && is.netIface) || '').trim(), host = String((is && is.netHost) || '').trim();
  if (!iface || !/^[A-Za-z][A-Za-z0-9\/.:\- ]{0,63}$/.test(iface)) return null;
  const q = { host: /^[\w.\-]{1,64}$/.test(host) ? host : '', iface, kind: is.category, count: is.count || 0 };
  // MAC 飄移另帶第二個埠、MAC 與 VLAN（同樣只接受對應字元）
  const iface2 = String(is.netIface2 || '').trim();
  if (iface2 && /^[A-Za-z][A-Za-z0-9\/.:\- ]{0,63}$/.test(iface2)) q.iface2 = iface2;
  if (/^[0-9a-fA-F.:-]{12,17}$/.test(String(is.netMac || ''))) q.mac = String(is.netMac);
  if (/^\d{1,4}$/.test(String(is.netVlan || ''))) q.vlan = String(is.netVlan);
  return q;
}
function sendToSwitchPort(q) {
  try { localStorage.setItem('_netAnalyzer_swPortQuery', JSON.stringify(Object.assign({}, q, { ts: Date.now() }))); } catch (e) { alert(tr('err.storage_full')); return; }
  const w = window.open('switch-config-parser.html', '_blank');
  if (!w) { try { localStorage.removeItem('_netAnalyzer_swPortQuery'); } catch (e) {} alert(tr('err.popup_blocked')); }
}
function swPortBtn(is) {
  const q = buildSwPortPayload(is);
  if (!q) return '';
  return `<button class="fwq-btn swq-btn" onclick="sendToSwitchPort(${esc(JSON.stringify(q))})" title="${esc(tr('swq.btn_tip'))}" aria-label="${esc(tr('swq.btn_tip'))}">🔌</button> `;
}
function getEventNetTuple(e) {
  if (e.format === 'cef' && e.fields) {
    const spt = e.fields.spt, dpt = e.fields.dpt;
    return {
      src: e.fields.src || '-',
      dst: e.fields.dst || '-',
      port: (spt || dpt) ? `${spt || '-'}→${dpt || '-'}` : '-',
      proto: e.fields.proto || '-'
    };
  }
  if ((e.format === 'json' || e.format === 'leef' || e.format === 'fortigate' || e.format === 'winevent') && e.fields) {
    const src = pickField(e.fields, SRC_IP_KEYS);
    const dst = pickField(e.fields, DST_IP_KEYS);
    const spt = pickField(e.fields, SRC_PORT_KEYS);
    const dpt = pickField(e.fields, DST_PORT_KEYS);
    const proto = pickField(e.fields, PROTO_KEYS);
    return {
      src: src || '-',
      dst: dst || '-',
      port: (spt || dpt) ? `${spt || '-'}→${dpt || '-'}` : '-',
      proto: proto || '-'
    };
  }
  // RFC5424 Structured Data 無固定 SD-PARAM 命名規格，僅在剛好命中常見別名（src/srcip 等）
  // 時才視為結構化欄位；命中任一欄位才採用，否則落回下面的 msg 文字 key=value 擷取
  // （SD 內容已被 splitSDandMSG() 從 msg 切走，兩者不會重複比對到同一段文字）
  // rfc3164／mikrotik 的 fields 只有 MikroTik 訊息拆解時才有內容（見 parseMikroTikMsg()），
  // 一般 rfc3164 為空物件，照舊落回下方 msg 文字擷取
  if ((e.format === 'rfc5424' || e.format === 'rfc3164' || e.format === 'asa' || e.format === 'mikrotik' || e.format === 'weblog' || e.format === 'w3c' || e.format === 'ciscoios' || e.format === 'comware' || e.format === 'flowlog' || e.format === 'kvfw' || e.format === 'pancsv' || e.format === 'umbrella' || e.format === 'dns' || e.format === 'dhcp' || e.format === 'vpnauth' || e.format === 'haproxy') && e.fields && Object.keys(e.fields).length) {
    const src = pickField(e.fields, SRC_IP_KEYS);
    const dst = pickField(e.fields, DST_IP_KEYS);
    const spt = pickField(e.fields, SRC_PORT_KEYS);
    const dpt = pickField(e.fields, DST_PORT_KEYS);
    const proto = pickField(e.fields, PROTO_KEYS);
    if (src || dst || spt || dpt || proto) {
      return {
        src: src || '-',
        dst: dst || '-',
        port: (spt || dpt) ? `${spt || '-'}→${dpt || '-'}` : '-',
        proto: proto || '-'
      };
    }
  }
  const kv = extractKeyValueFields(e.msg);
  const src = pickField(kv, SRC_IP_KEYS);
  const dst = pickField(kv, DST_IP_KEYS);
  const spt = pickField(kv, SRC_PORT_KEYS);
  const dpt = pickField(kv, DST_PORT_KEYS);
  const proto = pickField(kv, PROTO_KEYS);
  return {
    src: src || '-',
    dst: dst || '-',
    port: (spt || dpt) ? `${spt || '-'}→${dpt || '-'}` : '-',
    proto: proto || '-'
  };
}
// Top-N 摘要儀表板（2026-09-14 新增）：純函式，field 為 'src'（來源 IP，經 getEventNetTuple()
// 取值，'-' 視為無資料排除）／'user'（使用者帳號，比照 deriveIssueActorByUser() 同款
// WINEVENT_USER_KEYS→JSON_USER_KEYS 查找順序）／'category'（e.category，沿用既有分類文字，
// 未分類事件仍計入 'other'，與 buildIssueList() 的既有假設一致）。回傳依出現次數由多到少排序，
// 取前 n 筆 {value,count}
function buildTopNSummary(events, field, n) {
  const counts = new Map();
  events.forEach(e => {
    let v = null;
    if (field === 'src') {
      const t = getEventNetTuple(e);
      // IPv4 對應位址（::ffff:10.0.0.1，網域控制站 Kerberos 事件常見）與 IPv4 視為同一來源
      v = (t.src && t.src !== '-') ? String(t.src).replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '') : null;
    } else if (field === 'user') {
      v = eventUserKey(e);
    } else if (field === 'category') {
      v = e.category || 'other';
    }
    if (!v) return;
    counts.set(v, (counts.get(v) || 0) + 1);
  });
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}
// Syslog 自由文字 best-effort 掃描 heuristic：可信度低於 CEF 結構化版本（固定 Medium 而非 High）
// 時間窗（10 分鐘）內同一設備訊息出現的不同 IP 數達門檻才列為疑似掃描；設備自身的位址
// （主機欄位本身是位址、「to 介面:位址」等介面端）不計入；設備登入／認證紀錄（fields.auth）的位址
// 是登入用戶端與設備本身，不是掃描目標，整筆略過（第二十九輪審查：sample_asa_auth.log 誤報）
const SCAN_SYSLOG_WINDOW_MS = 10 * 60 * 1000;
function detectScanHeuristicSyslog(events, opts) {
  const threshold = (opts && opts.threshold) || 5;
  const windowMs = (opts && opts.windowMs) || SCAN_SYSLOG_WINDOW_MS;
  const byHost = new Map();
  events.filter(e => e.format !== 'cef' && !e.netFields).forEach(e => {
    // JSON／RFC5424 等格式缺 host 欄位時 parser 預設值是空字串 ''，若不排除會讓多筆彼此
    // 無關、只是剛好都沒帶 host 的事件被聚合進同一個 '' bucket，各自訊息裡的 IP 被合併計數
    // 誤判成同一來源的掃描（比照同檔案 detectBeaconing() 的 e.host||null 既有防呆手法，
    // 2026-09 全功能審查發現）
    if (!e.host) return;
    if (e.fields && e.fields.auth) return;
    const own = new Set([e.host]);
    for (const m of String(e.msg || '').matchAll(/\b(?:to|on|at|via)\s+[A-Za-z][\w./-]*:(\d{1,3}(?:\.\d{1,3}){3})/g)) own.add(m[1]);
    const ips = extractIPsFromText(e.msg).filter(ip => !own.has(ip));
    if (!ips.length) return;
    if (!byHost.has(e.host)) byHost.set(e.host, []);
    byHost.get(e.host).push({ e, ips });
  });
  const issues = [];
  for (const [host, list] of byHost) {
    list.sort((a, b) => effectiveTime(a.e) - effectiveTime(b.e));
    // 滑動時間窗：記錄窗內各 IP 出現次數，取不同 IP 數最多的那一段
    const cnt = new Map();
    let ws = 0, best = 0, bs = 0, be = -1;
    for (let i = 0; i < list.length; i++) {
      list[i].ips.forEach(ip => cnt.set(ip, (cnt.get(ip) || 0) + 1));
      const ti = effectiveTime(list[i].e);
      while (effectiveTime(list[ws].e) < ti - windowMs) {
        list[ws].ips.forEach(ip => { const c = cnt.get(ip) - 1; if (c) cnt.set(ip, c); else cnt.delete(ip); });
        ws++;
      }
      if (cnt.size > best) { best = cnt.size; bs = ws; be = i; }
    }
    if (best >= threshold) {
      const evs = list.slice(bs, be + 1).map(x => x.e);
      issues.push({
        category: 'possibleScan', severityNorm: 'Medium', count: best,
        firstSeen: evs[0].timestamp || null, lastSeen: evs[evs.length - 1].timestamp || null,
        ...sampleOf('sample.msgIps', { host, n: best }),
        relatedHosts: [host], relatedEvents: evs, confidence: 'heuristic'
      });
    }
  }
  return issues;
}
// 定期信標（Beaconing/C2）偵測：同一 src→dst（或 src→host，dst 無法辨識時退回目的主機名）
// 分組後，比對相鄰事件時間間隔是否高度規律（變異係數 CV=標準差/平均值 低於門檻）。真實 C2
// 心跳流量常見固定或抖動極小的週期（如每 60±5 秒回報一次），與人類/應用程式自然流量的不規則
// 間隔可明顯區分；純統計 heuristic，不解讀封包內容，confidence 固定 'heuristic'
// 至少觀察 10 分鐘、週期至少 5 秒：短時間的每秒探測（如 12 秒內 12 筆）不是信標
const BEACON_MIN_SPAN_MS = 10 * 60 * 1000;
const BEACON_MIN_PERIOD_MS = 5000;
function detectBeaconing(events, opts) {
  const minSamples = (opts && opts.minSamples) || 5;
  const cvThreshold = (opts && opts.cvThreshold) || 0.15;
  const minSpan = (opts && opts.minSpanMs != null) ? opts.minSpanMs : BEACON_MIN_SPAN_MS;
  const minPeriod = (opts && opts.minPeriodMs != null) ? opts.minPeriodMs : BEACON_MIN_PERIOD_MS;
  const groups = new Map();
  events.forEach(e => {
    // 沒有真實時間戳的事件（effectiveTime 以行號模擬）間隔沒有意義，不列入（比照 detectTimeGaps()）
    if (!e.timestamp) return;
    // DNS 查詢紀錄的對象是 DNS 伺服器（主機欄位），用戶端規律查詢屬正常行為，異常交給 detectDnsAnomalies()
    if (e.fields && (e.fields.dns || e.fields.dhcp || e.fields.ssh || e.fields.sudo || e.fields.ldap || e.fields.radacct || isVpnAuthFields(e.fields))) return;
    const t = getEventNetTuple(e);
    const src = (t.src && t.src !== '-') ? t.src : null;
    if (!src) return;
    const dst = (t.dst && t.dst !== '-') ? t.dst : (e.host || null);
    if (!dst) return;
    const key = `${src}|${dst}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(e);
  });
  const issues = [];
  for (const [key, list] of groups) {
    if (list.length < minSamples + 1) continue;
    const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    const deltas = [];
    for (let i = 1; i < sorted.length; i++) deltas.push(effectiveTime(sorted[i]) - effectiveTime(sorted[i - 1]));
    if (deltas.length < minSamples) continue;
    const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    if (mean < minPeriod) continue;
    if (effectiveTime(sorted[sorted.length - 1]) - effectiveTime(sorted[0]) < minSpan) continue;
    const variance = deltas.reduce((a, b) => a + (b - mean) ** 2, 0) / deltas.length;
    const cv = Math.sqrt(variance) / mean;
    if (cv < cvThreshold) {
      const [src, dst] = key.split('|');
      issues.push({
        category: 'beaconing', severityNorm: 'Medium', count: sorted.length,
        firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
        ...sampleOf('sample.beacon', { src, dst, n: sorted.length, cv: cv.toFixed(3), sec: Math.round(mean / 1000) }),
        relatedHosts: [src, dst], relatedEvents: sorted, confidence: 'heuristic',
        beaconCv: cv, beaconIntervalMs: mean
      });
    }
  }
  return issues;
}
// 橫向移動偵測：明確限縮範圍為 Windows Event Log（僅此格式有結構化的「登入成功」欄位——
// EventID 4624；其餘格式僅有 authFail 關鍵字分類，無法可靠反向推論「成功」，不對 CEF/Syslog
// 等格式臆測）。同一來源 IP（srcip，來自 WINEVENT_SRCIP_KEYS 映射）在時間窗內對 N 個以上不同
// 目的主機（e.host，即 WEL System/Computer）產生 4624 事件時標記為疑似橫向移動
function detectLateralMovement(events, opts) {
  const windowMs = (opts && opts.lateralWindowMs) || 30 * 60000;
  const threshold = (opts && opts.lateralThreshold) || 3;
  // 第三十一輪 HX3：opts.lateralExclude（位址、CIDR 或主機名稱，如備份與監控主機）不列入；opts.lateralTypes 非空時只計入這些登入類型
  const excl = (opts && opts.lateralExclude) || [], types = (opts && opts.lateralTypes) || [];
  const excluded = f => excl.some(x => {
    const ip = String(f.srcip).replace(/^::ffff:/i, '');
    if (/^[\d.]+(?:\/\d{1,2})?$/.test(x)) return isValidIPv4(ip) && cidrMatch(ip, x);
    const n = hostShort(x);
    return [f.WorkstationName, f.srcName].some(v => v && v !== '-' && hostShort(v) === n);
  });
  const bySrc = new Map();
  events.filter(e => e.format === 'winevent' && e.fields && e.fields.EventID === '4624' && e.fields.srcip && !/^(?:-|127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)$/.test(e.fields.srcip) && e.host && (!types.length || types.includes(String(e.fields.LogonType))) && !excluded(e.fields))
    .forEach(e => {
      if (!bySrc.has(e.fields.srcip)) bySrc.set(e.fields.srcip, []);
      bySrc.get(e.fields.srcip).push(e);
    });
  // 2026-08-27 稽核修復：先前用 hosts.size===threshold 精確匹配，視窗內主機數一旦超過門檻
  // 就不再觸發（也不再更新既有問題），橫向移動 3 台主機跟 30 台主機在畫面上長得一樣（count
  // 永遠停在門檻值）。改為「同一波事件」episode 追蹤：視窗內主機數達門檻時開一筆問題並持續
  // 就地更新 count/lastSeen/relatedHosts/relatedEvents 到目前為止看過的最大範圍，直到視窗
  // 主機數掉回門檻以下才結束這一波；之後若再度達門檻，視為新的一波，開新的一筆問題（同一
  // 來源在時間上分開的兩次橫向移動，仍分別各自成案，不會被合併成一筆）
  const issues = [];
  for (const [src, list] of bySrc) {
    const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    // 摘要帶出來源主機名稱（WorkstationName 或 DHCP 對照），與主機登入關係表一致
    const nm = list.map(e => e.fields.WorkstationName || e.fields.srcName).find(v => v && v !== '-');
    const srcLabel = nm ? `${src} (${hostShort(nm)})` : src;
    let winStart = 0;
    let episode = null;
    // 視窗內各主機出現次數累加維護，只在達門檻時才切出事件清單
    const hc = new Map();
    for (let i = 0; i < sorted.length; i++) {
      const ti = effectiveTime(sorted[i]);
      hc.set(sorted[i].host, (hc.get(sorted[i].host) || 0) + 1);
      while (effectiveTime(sorted[winStart]) < ti - windowMs) {
        const h = sorted[winStart].host, c = hc.get(h) - 1;
        if (c) hc.set(h, c); else hc.delete(h);
        winStart++;
      }
      if (hc.size >= threshold) {
        const last = sorted[i];
        if (!episode) {
          const windowEvents = sorted.slice(winStart, i + 1);
          episode = {
            category: 'lateralMovement', severityNorm: 'High', count: hc.size,
            firstSeen: windowEvents[0].timestamp || null, lastSeen: last.timestamp || null,
            ...sampleOf('sample.lateral', { src: srcLabel, n: hc.size }),
            relatedHosts: [src, ...hc.keys()], relatedEvents: windowEvents, confidence: 'heuristic'
          };
          issues.push(episode);
        } else {
          // lastSeen 每步都延伸（代表這一波事件持續到哪個時間點）；count/relatedHosts/
          // relatedEvents 只在規模創新高時才更新代表快照，避免視窗尾端自然縮小（較舊事件
          // 隨時間滑出視窗）反而把先前記錄到的較大規模覆蓋掉
          episode.lastSeen = last.timestamp || null;
          if (hc.size > episode.count) {
            episode.count = hc.size;
            Object.assign(episode, sampleOf('sample.lateral', { src: srcLabel, n: hc.size }));
            episode.relatedHosts = [src, ...hc.keys()];
            episode.relatedEvents = sorted.slice(winStart, i + 1);
          }
        }
      } else {
        episode = null;
      }
    }
  }
  return issues;
}
// 權限提升/新帳號建立偵測：(a) 通用關鍵字規則（比照 KEYWORD_CATEGORIES 既有寫法，任何格式皆可
// 命中，confidence 'heuristic'）；(b) Windows Event Log 專屬——硬編碼官方 Security Event ID
// （4720=帳號建立、4732/4728=加入系統管理/內建群組、4756=加入通用群組，皆為 Microsoft 官方文件
// 明確定義的既有事實，非臆測），confidence 'confirmed'。(b) 命中的事件優先，不重複套用 (a) 造成
// 同一事件產生兩筆問題
const PRIV_ESC_KEYWORD_RE = /\b(created|added|granted|elevated|promoted)\b[\s\S]{0,30}\b(admin|administrator|root|privilege|role|group)\b/i;
const PRIV_ESC_WINEVENT_IDS = new Set(['4720', '4728', '4732', '4756']);
function detectPrivEsc(events) {
  const issues = [];
  events.forEach(e => {
    if (e.format === 'winevent' && e.fields && PRIV_ESC_WINEVENT_IDS.has(e.fields.EventID)) {
      issues.push({
        category: 'privEsc', severityNorm: 'High', count: 1,
        firstSeen: e.timestamp, lastSeen: e.timestamp,
        sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
        confidence: 'confirmed', privEscEventId: e.fields.EventID
      });
      return;
    }
    // RouterOS「物件 added／changed by 帳號」由 detectMikroTikTamper()／configChange 處理，不以關鍵字重複列（XN129）
    if (PRIV_ESC_KEYWORD_RE.test(e.msg || '') && !mikrotikCfgOf(e)) {
      issues.push({
        category: 'privEsc', severityNorm: 'Medium', count: 1,
        firstSeen: e.timestamp, lastSeen: e.timestamp,
        sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
        confidence: 'heuristic'
      });
    }
  });
  return issues;
}
// 2026-08-28 新增：Windows Event Log 帳號生命週期／稽核清除／持久性建立事件偵測，比照
// PRIV_ESC_WINEVENT_IDS 既有樣板——皆為 Microsoft 官方文件明載的標準 Security/System 稽核
// EventID，命中即單筆 confirmed issue，不需頻率門檻。4740=帳號鎖定、4724=管理員重設他人
// 密碼（帳號被接管高信號）、4729/4733/4757=移出安全群組（既有 PRIV_ESC_WINEVENT_IDS 只涵蓋
// 加入群組的反向缺口）、4767/4722/4725=解鎖/啟用/停用（例行帳號狀態變更，severity 較低）、
// 1102=稽核記錄被清除（單筆即高風險）、4697/4698=服務安裝／排程工作建立（PsExec／持久性
// 典型指標）
const ACCOUNT_AUDIT_WINEVENT_MAP = {
  '4740': { category: 'acctLockout', severityNorm: 'Medium' },
  '4724': { category: 'pwReset', severityNorm: 'High' },
  '4729': { category: 'groupRemoved', severityNorm: 'High' },
  '4733': { category: 'groupRemoved', severityNorm: 'High' },
  '4757': { category: 'groupRemoved', severityNorm: 'High' },
  '4767': { category: 'acctStatusChange', severityNorm: 'Info' },
  '4722': { category: 'acctStatusChange', severityNorm: 'Info' },
  '4725': { category: 'acctStatusChange', severityNorm: 'Info' },
  '1102': { category: 'auditCleared', severityNorm: 'Critical' },
  '4697': { category: 'persistence', severityNorm: 'Medium' },
  '4698': { category: 'persistence', severityNorm: 'Medium' },
  // 2026-08-28（續2）新增：4726=帳號被刪除（常見於攻擊者滅證，刪除自建帳號）、4719=系統
  // 稽核政策被變更（攻擊者常先關稽核再動手，跟既有 1102 同屬稽核完整性訊號，故同為
  // Critical）、1104=安全記錄已滿（可能為刻意灌爆記錄使舊事件遭覆蓋，亦可能只是正常保留
  // 政策，嚴重度低於 1102/4719）、7045=服務安裝（System 頻道版本，與既有 4697 的 Security
  // 頻道版本語意相同，沿用同一個 persistence 分類）
  '4726': { category: 'acctDeleted', severityNorm: 'High' },
  '4719': { category: 'auditPolicyChanged', severityNorm: 'Critical' },
  '1104': { category: 'auditLogFull', severityNorm: 'Medium' },
  '7045': { category: 'persistence', severityNorm: 'Medium' },
  // 2026-09 新增：4657=登錄值變更（原生 Windows Security 稽核事件，與 Sysmon EventID 13 語意
  // 重疊但來源不同，涵蓋未部署 Sysmon 的環境；泛指任一登錄值變更，非專指持久化路徑，故獨立
  // 分類非併入 sysmonRegistryPersistence，severity 中等——多數命中屬正常系統/應用程式行為，
  // 需人工核對是否落在敏感機碼路徑）、4703=Token 權限被調整（常見於憑證竊取工具啟用
  // SeDebugPrivilege 以存取 lsass.exe 記憶體的前置動作，但合法系統/服務行為也會觸發，故亦
  // 為中等而非高風險，避免與 lsassAccess 的窄範圍組合訊號混淆優先度）。皆為 Microsoft 官方
  // 文件明載的標準 Security 稽核 EventID
  '4657': { category: 'registryValueChange', severityNorm: 'Medium' },
  '4703': { category: 'tokenPrivAdjust', severityNorm: 'Medium' },
  // 第三十輪 WN5：4765／4766 SID History 被加入（或嘗試失敗）、4794 目錄服務還原模式（DSRM）管理員密碼被設定、4781 帳號改名
  '4765': { category: 'sidHistory', severityNorm: 'High' },
  '4766': { category: 'sidHistory', severityNorm: 'High' },
  '4794': { category: 'dsrmPassword', severityNorm: 'High' },
  '4781': { category: 'acctStatusChange', severityNorm: 'Info' }
};
// AWS CloudTrail 高風險操作（第十六輪 PG）：對應既有 Windows 稽核分類；只計成功的呼叫（無 errorCode）。事件名稱依
// AWS CloudTrail／IAM API 名稱，Beats aws cloudtrail 模組的真實測試 log 皆有範例
const CLOUDTRAIL_RISK_MAP = {
  StopLogging: { category: 'auditCleared', severityNorm: 'Critical' },
  DeleteTrail: { category: 'auditCleared', severityNorm: 'Critical' },
  UpdateTrail: { category: 'auditPolicyChanged', severityNorm: 'High' },
  PutEventSelectors: { category: 'auditPolicyChanged', severityNorm: 'High' },
  CreateUser: { category: 'privEsc', severityNorm: 'High' },
  AddUserToGroup: { category: 'privEsc', severityNorm: 'High' },
  AttachUserPolicy: { category: 'privEsc', severityNorm: 'High' },
  AttachGroupPolicy: { category: 'privEsc', severityNorm: 'High' },
  AttachRolePolicy: { category: 'privEsc', severityNorm: 'High' },
  PutUserPolicy: { category: 'privEsc', severityNorm: 'High' },
  RemoveUserFromGroup: { category: 'groupRemoved', severityNorm: 'Medium' },
  DeleteUser: { category: 'acctDeleted', severityNorm: 'High' },
  UpdateLoginProfile: { category: 'pwReset', severityNorm: 'High' },
  CreateLoginProfile: { category: 'persistence', severityNorm: 'Medium' },
  CreateAccessKey: { category: 'persistence', severityNorm: 'Medium' },
  DeactivateMFADevice: { category: 'acctStatusChange', severityNorm: 'High' },
  DeleteVirtualMFADevice: { category: 'acctStatusChange', severityNorm: 'High' }
};
// Azure Activity Log／GCP Cloud Audit Logs 高風險操作（第二十輪 FE）：只計成功的操作，比照 CloudTrail 對應既有稽核分類。
// Azure 以 operationName（小寫比對）、GCP 以 methodName 結尾比對（SetIamPolicy 各服務皆同名）
const AZURE_RISK_MAP = {
  'microsoft.authorization/roleassignments/write': { category: 'privEsc', severityNorm: 'High' },
  'microsoft.authorization/roleassignments/delete': { category: 'groupRemoved', severityNorm: 'Medium' },
  'microsoft.authorization/roledefinitions/write': { category: 'privEsc', severityNorm: 'High' },
  'microsoft.insights/diagnosticsettings/delete': { category: 'auditCleared', severityNorm: 'Critical' },
  'microsoft.insights/diagnosticsettings/write': { category: 'auditPolicyChanged', severityNorm: 'High' }
};
const GCP_RISK_MAP = [
  [/(?:^|\.)SetIamPolicy$/, { category: 'privEsc', severityNorm: 'High' }],
  [/(?:^|\.)CreateServiceAccount$/, { category: 'privEsc', severityNorm: 'High' }],
  [/(?:^|\.)CreateServiceAccountKey$/, { category: 'persistence', severityNorm: 'Medium' }],
  [/(?:^|\.)DeleteServiceAccount$/, { category: 'acctDeleted', severityNorm: 'High' }],
  [/\.ConfigServiceV2\.DeleteSink$/, { category: 'auditCleared', severityNorm: 'Critical' }],
  [/\.ConfigServiceV2\.UpdateSink$/, { category: 'auditPolicyChanged', severityNorm: 'High' }]
];
function cloudRiskOf(e) {
  if (!e.cloudRaw) return null;
  const ci = cloudAuthInfo(e.cloudRaw);
  // Azure 寫入類操作先記 Start 再記 Success，只計完成的那筆
  if (!ci || !ci.ok || ci.pending) return null;
  if (ci.vendor === 'cloudtrail') return CLOUDTRAIL_RISK_MAP[ci.event] || null;
  if (ci.vendor === 'azact') return AZURE_RISK_MAP[String(ci.event).toLowerCase()] || null;
  if (ci.vendor === 'gcpaudit') {
    // GKE 的 Kubernetes 稽核：methodName 為 io.k8s.<群組>.<版本>.<資源>[.<子資源>].<動詞>（如 io.k8s.core.v1.pods.exec.create，
    // 依 Elastic 官方 GKE 偵測規則），拆出動詞與資源後套用同一套 Kubernetes 判斷
    const km = String(ci.event).match(/^io\.k8s\.(?:[\w.]+\.)?v\d\w*\.([a-z]+)(?:\.([a-z]+))?\.([a-z]+)$/);
    if (km) return k8sRiskOf({ user: ci.user, verb: km[3], resource: km[2] ? `${km[1]}/${km[2]}` : km[1] });
    const h = GCP_RISK_MAP.find(([re]) => re.test(ci.event)); return h ? h[1] : null;
  }
  if (ci.vendor === 'k8s') return k8sRiskOf(ci);
  return null;
}
// Kubernetes 高風險操作（第二十三輪 ID）：只計已完成且成功的請求；控制平面元件（system: 開頭，service account 與匿名除外）不列。
// 建立／修改 RBAC 角色與綁定為 privEsc；pods/exec、pods/attach（kubectl exec／attach，新版以 get 走 WebSocket）為 k8sExec；
// 讀取 Secret 為 k8sSecretAccess（list／watch 一次取得全部，嚴重度較高）
const K8S_RBAC_RE = /^(?:clusterroles|clusterrolebindings|roles|rolebindings)$/;
function k8sRiskOf(ci) {
  if (/^system:(?!serviceaccount:|anonymous$)/.test(ci.user || '')) return null;
  if (/^(?:create|update|patch)$/.test(ci.verb) && K8S_RBAC_RE.test(ci.resource)) return { category: 'privEsc', severityNorm: 'High' };
  if (/^(?:get|create)$/.test(ci.verb) && /^pods\/(?:exec|attach)$/.test(ci.resource)) return { category: 'k8sExec', severityNorm: 'Medium' };
  if (/^(?:get|list|watch)$/.test(ci.verb) && ci.resource === 'secrets') return { category: 'k8sSecretAccess', severityNorm: ci.verb === 'get' ? 'Medium' : 'High' };
  return null;
}
// 雲端防火牆／安全群組規則變更（第二十輪 FE）：成功的操作列為設定變更（netOpsInfo）
const CLOUD_FW_CHANGE_RE = /^(?:AuthorizeSecurityGroup(?:Ingress|Egress)|RevokeSecurityGroup(?:Ingress|Egress)|ModifySecurityGroupRules|CreateSecurityGroup|DeleteSecurityGroup|(?:Create|Replace|Delete)NetworkAclEntry|microsoft\.network\/(?:networksecuritygroups(?:\/securityrules)?|azurefirewalls|firewallpolicies(?:\/rulecollectiongroups)?)\/(?:write|delete)|v1\.compute\.firewalls\.(?:insert|patch|update|delete)|(?:create|update|patch|delete|deletecollection) networkpolicies)$/i;
// MFA 推播疲勞（2026-10-27，第三十五輪 XN31）：攻擊者已有密碼時連續發推播，直到使用者按下同意。依 Datadog、Northwave
// 的偵測方式：同一帳號 30 分鐘內 ≥3 次 MFA 未通過，且最後一次後 30 分鐘內登入成功。MFA 未通過只用已查證的欄位：
// Entra ID resultType 500121（Microsoft 文件：強式驗證請求失敗，含使用者拒絕與未完成 MFA）；Duo result denied 且 factor
// 為推播（Elastic cisco_duo 真實測試資料 denied／user_mistake／duo_push；官方 reason 完整清單查無，不依 reason 判斷；
// fraud 由 duoFraud 處理）。Okta Identity Engine 與 Classic 事件類型不同，查證前不列入
const MFA_FATIGUE_MIN = 3, MFA_FATIGUE_WINDOW_MS = 30 * 60 * 1000;
function mfaDenyOf(e, ci) {
  const o = e.cloudRaw || {};
  if (ci.vendor === 'entra') return String(o.resultType) === '500121';
  if (ci.vendor === 'duo') return o.result === 'denied' && /push/i.test(String(o.factor || ''));
  return false;
}
// Windows NPS 同一帳號短時間內多次被拒（XN65）：NPS 記錄沒有使用者電腦的 IP（只有 AP／交換器與 MAC），
// 改以帳號彙整；原因多為原則或設定不符（48 沒有符合的網路原則、65 撥入權限等）時註明不是密碼錯誤
const NPS_REJECT_WINDOW_MS = 60 * 60 * 1000, NPS_REJECT_MIN = 5;
function detectNpsRejects(events) {
  const byUser = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (e.format !== 'nps' || !f || f.npsPacket !== 3 || !f.user) return;
    const k = String(f.user).toLowerCase();
    if (!byUser.has(k)) byUser.set(k, []);
    byUser.get(k).push(e);
  });
  const issues = [];
  for (const list of byUser.values()) {
    const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    let best = null;
    for (let i = 0, j = 0; j < sorted.length; j++) {
      while (effectiveTime(sorted[j]) - effectiveTime(sorted[i]) > NPS_REJECT_WINDOW_MS) i++;
      if (j - i + 1 >= NPS_REJECT_MIN && (!best || j - i + 1 > best.length)) best = sorted.slice(i, j + 1);
    }
    if (!best) continue;
    const cnt = new Map();
    best.forEach(e => { const r = e.fields.npsReasonName || '?'; cnt.set(r, (cnt.get(r) || 0) + 1); });
    const reasons = [...cnt.entries()].sort((a, b) => b[1] - a[1]).map(([r, n]) => `${r}×${n}`).join(', ');
    const policyMostly = best.filter(e => NPS_POLICY_REASONS.has(e.fields.npsReason)).length * 2 > best.length;
    const user = best[0].fields.user, nas = [...new Set(best.map(e => e.fields.nasName || e.fields.nasIp).filter(Boolean))];
    issues.push({
      category: 'npsRejectBurst', severityNorm: 'Medium', count: best.length,
      firstSeen: best[0].timestamp || null, lastSeen: best[best.length - 1].timestamp || null,
      ...sampleOf(policyMostly ? 'sample.npsRejectPolicy' : 'sample.npsReject', { user, n: best.length, reasons, nas: nas.slice(0, 3).join(', ') || '-' }),
      relatedHosts: [user, ...nas.slice(0, 3)], relatedEvents: best, confidence: 'heuristic'
    });
  }
  return issues;
}
// Aruba ClearPass 同一帳號短時間內多次被拒（XN134）：與 NPS 相同以帳號彙整（紀錄裡是 NAS 與終端 MAC，沒有使用者電腦的來源位址），
// 原因以 Common.Error-Code 彙整
function detectClearPassRejects(events) {
  const byUser = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (e.format !== 'clearpass' || !f || f.cppmStatus !== 'REJECT' || !f.user) return;
    const k = String(f.user).toLowerCase();
    if (!byUser.has(k)) byUser.set(k, []);
    byUser.get(k).push(e);
  });
  const issues = [];
  for (const list of byUser.values()) {
    const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    let best = null;
    for (let i = 0, j = 0; j < sorted.length; j++) {
      while (effectiveTime(sorted[j]) - effectiveTime(sorted[i]) > NPS_REJECT_WINDOW_MS) i++;
      if (j - i + 1 >= NPS_REJECT_MIN && (!best || j - i + 1 > best.length)) best = sorted.slice(i, j + 1);
    }
    if (!best) continue;
    const cnt = new Map();
    best.forEach(e => { const r = e.fields.cppmError || '?'; cnt.set(r, (cnt.get(r) || 0) + 1); });
    const reasons = [...cnt.entries()].sort((a, b) => b[1] - a[1]).map(([r, n]) => `${r}×${n}`).join(', ');
    const user = best[0].fields.user, nas = [...new Set(best.map(e => e.fields.nasName || e.fields.nasIp).filter(Boolean))];
    issues.push({
      category: 'cppmRejectBurst', severityNorm: 'Medium', count: best.length,
      firstSeen: best[0].timestamp || null, lastSeen: best[best.length - 1].timestamp || null,
      ...sampleOf('sample.cppmReject', { user, n: best.length, reasons, nas: nas.slice(0, 3).join(', ') || '-' }),
      relatedHosts: [user, ...nas.slice(0, 3)], relatedEvents: best, confidence: 'heuristic'
    });
  }
  return issues;
}
function detectMfaFatigue(events) {
  const byUser = new Map();
  events.forEach(e => {
    if (!e.cloudRaw || (e.netVendor !== 'entra' && e.netVendor !== 'duo')) return;
    const ci = cloudAuthInfo(e.cloudRaw);
    if (!ci || !ci.login || !ci.user) return;
    const kind = mfaDenyOf(e, ci) ? 'deny' : ci.ok ? 'ok' : null;
    if (!kind) return;
    const key = ci.vendor + '|' + String(ci.user).toLowerCase();
    if (!byUser.has(key)) byUser.set(key, []);
    byUser.get(key).push({ e, kind, ci });
  });
  const issues = [];
  for (const list of byUser.values()) {
    list.sort((a, b) => effectiveTime(a.e) - effectiveTime(b.e));
    let denies = [];
    for (const x of list) {
      const t = effectiveTime(x.e);
      if (x.kind === 'deny') {
        denies = denies.filter(d => t - effectiveTime(d.e) <= MFA_FATIGUE_WINDOW_MS);
        denies.push(x);
        continue;
      }
      if (denies.length >= MFA_FATIGUE_MIN && t - effectiveTime(denies[denies.length - 1].e) <= MFA_FATIGUE_WINDOW_MS) {
        const evs = [...denies.map(d => d.e), x.e];
        const ip = x.ci.ip || '';
        issues.push({
          category: 'mfaFatigue', severityNorm: 'High', count: denies.length,
          firstSeen: evs[0].timestamp || null, lastSeen: x.e.timestamp || null, mfaDenies: denies.length,
          ...sampleOf('sample.mfaFatigue', { user: x.ci.user, n: denies.length, app: CLOUD_AUTH_APP[x.ci.vendor] || x.ci.vendor, ip }),
          relatedHosts: [x.ci.user, ip].filter(Boolean), relatedEvents: evs, confidence: 'heuristic'
        });
        break;
      }
      denies = [];
    }
  }
  return issues;
}
function detectAccountAuditEvents(events) {
  const issues = [];
  events.forEach(e => {
    // Duo 使用者回報詐騙推播（第二十三輪 IF）：密碼已外洩、攻擊者在嘗試通過 MFA
    if (e.netVendor === 'duo' && e.cloudRaw && e.cloudRaw.result === 'fraud') {
      issues.push({ category: 'duoFraud', severityNorm: 'High', count: 1, firstSeen: e.timestamp, lastSeen: e.timestamp, sampleRaw: e.msg,
        relatedHosts: [e.fields.user, e.fields.srcip].filter(Boolean), relatedEvents: [e], confidence: 'confirmed' });
      return;
    }
    if ((e.netVendor === 'azact' || e.netVendor === 'gcpaudit' || e.netVendor === 'k8s') && e.cloudRaw) {
      const hit = cloudRiskOf(e);
      if (hit) issues.push({
        category: hit.category, severityNorm: hit.severityNorm, count: 1,
        firstSeen: e.timestamp, lastSeen: e.timestamp,
        sampleRaw: e.msg, relatedHosts: e.fields.user ? [e.fields.user] : [], relatedEvents: [e],
        confidence: 'confirmed', cloudTrailEvent: e.msgid
      });
      return;
    }
    if (e.netVendor === 'cloudtrail' && e.cloudRaw && !e.cloudRaw.errorCode) {
      const hit = CLOUDTRAIL_RISK_MAP[e.cloudRaw.eventName];
      if (hit) issues.push({
        category: hit.category, severityNorm: hit.severityNorm, count: 1,
        firstSeen: e.timestamp, lastSeen: e.timestamp,
        sampleRaw: e.msg, relatedHosts: e.fields.user ? [e.fields.user] : [], relatedEvents: [e],
        confidence: 'confirmed', cloudTrailEvent: e.cloudRaw.eventName
      });
      return;
    }
    if (e.format !== 'winevent' || !e.fields) return;
    const hit = ACCOUNT_AUDIT_WINEVENT_MAP[e.fields.EventID];
    if (!hit) return;
    issues.push({
      category: hit.category, severityNorm: hit.severityNorm, count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'confirmed', winEventId: e.fields.EventID
    });
  });
  return issues;
}
// Kerberoasting 偵測（heuristic，非單一 EventID 本身即代表惡意，採業界既有廣泛使用的偵測
// 組合）：EventID 4769（服務票證要求）+ TicketEncryptionType=0x17（RC4，可離線暴力破解）+
// ServiceName 非機器帳號（不以 $ 結尾）且非 krbtgt。TicketEncryptionType／ServiceName 皆為
// Microsoft 官方 4769 事件描述明載的 EventData 欄位，parseWinEventFragment() 已通用擷取任意
// 具名 Data 欄位，無需額外解析邏輯
function detectKerberoasting(events) {
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    if (e.fields.EventID !== '4769') return;
    if (e.fields.TicketEncryptionType !== '0x17') return;
    const svc = e.fields.ServiceName || '';
    if (!svc || svc.endsWith('$') || svc === 'krbtgt') return;
    issues.push({
      category: 'kerberoasting', severityNorm: 'High', count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'heuristic', kerbServiceName: svc
    });
  });
  return issues;
}
// Pass-the-Hash 偵測（heuristic，2026-09 新增）：EventID 4624（登入成功）+ LogonType='9'
// （NewCredentials，官方 Microsoft Logon Type 對照表定義為「RunAs /netonly 建立的新登入工作階段
// 型別」）。Pass-the-Hash 的標準手法是攻擊者取得帳號 NTLM 雜湊後，用 `runas /netonly` 搭配該
// 雜湊建立新的認證內容而不需要明文密碼，MITRE ATT&CK T1550.002（Use Alternate Authentication
// Material: Pass the Hash）官方程序範例明確以此為偵測訊號之一。parseWinEventFragment() 對
// LogonType 欄位無過濾，parser 端不需改動。**誤判風險需誠實標註**：LogonType=9 本身也有完全
// 合法的用途（一般使用者主動執行 `runas /netonly` 存取遠端資源、部分排程工作/服務帳號設計），
// 故僅列為 heuristic 而非 confirmed，比照既有 detectKerberoasting()/detectAsrepRoasting() 慣例。
function detectPassTheHash(events) {
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    if (e.fields.EventID !== '4624') return;
    if (e.fields.LogonType !== '9') return;
    const usr = e.fields.TargetUserName || '';
    if (!usr || usr.endsWith('$')) return;
    issues.push({
      category: 'passTheHash', severityNorm: 'Medium', count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'heuristic', pthUserName: usr
    });
  });
  return issues;
}
// AS-REP Roasting 偵測（heuristic，直接鏡像 detectKerberoasting() 的手法，同屬業界廣泛使用的
// Kerberos 離線暴力破解偵測組合）：EventID 4768（TGT 要求）+ PreAuthType 缺欄位或為 '0'（代表
// 該帳號被設定「不需要 Kerberos 預先驗證」，攻擊者可直接取得可離線暴力破解的加密資料，不需
// 事先知道密碼）+ TicketEncryptionType=0x17（RC4）。PreAuthType／TicketEncryptionType 皆為
// Microsoft 官方 4768 事件描述明載的 EventData 欄位；PreAuthType 缺欄位與值為 '0' 在不同
// wevtutil/PowerShell 匯出情境下都可能代表「無預先驗證」，故兩者皆視為命中，只有明確帶有
// 非零 PreAuthType（代表確實執行了預先驗證，如 2=加密時間戳）才排除
function detectAsrepRoasting(events) {
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    if (e.fields.EventID !== '4768') return;
    if (e.fields.TicketEncryptionType !== '0x17') return;
    const preAuth = e.fields.PreAuthType;
    if (preAuth !== undefined && preAuth !== '' && preAuth !== '0') return;
    const usr = e.fields.TargetUserName || '';
    if (!usr || usr.endsWith('$')) return;
    issues.push({
      category: 'asrepRoasting', severityNorm: 'High', count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'heuristic', asrepUserName: usr
    });
  });
  return issues;
}
// AS-REP Roasting 風險示警（heuristic，比 detectAsrepRoasting() 更早一步的訊號——偵測帳號何時
// 被設定成「不需要 Kerberos 預先驗證」，而非偵測攻擊者何時已在利用這個弱點）：EventID 4738
// （帳號屬性變更）+ 官方 Data 欄位 OldUacValue／NewUacValue（十六進位 userAccountControl 值，
// 已對外查證確認為真實 XML 欄位名稱）+ DONT_REQUIRE_PREAUTH 旗標位元 0x400000 於 New 中新增
// （Old 未設、New 已設，即該旗標剛被打開，非原本就設定好的既有帳號）。0x400000 為 Microsoft
// ADS_USER_FLAG_ENUM／AD userAccountControl 標準常數，非本次新查證範圍。
function decodeHexUac(v) {
  if (v === undefined || v === null || v === '') return null;
  const n = parseInt(v, 16);
  return Number.isFinite(n) ? n : null;
}
function detectAsrepRoastingRisk(events) {
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    if (e.fields.EventID !== '4738') return;
    const oldUac = decodeHexUac(e.fields.OldUacValue);
    const newUac = decodeHexUac(e.fields.NewUacValue);
    if (oldUac === null || newUac === null) return;
    const FLAG = 0x400000;
    if ((oldUac & FLAG) || !(newUac & FLAG)) return; // 只認「新增」這個旗標的變更，原本就有或本來就沒有都不算
    const usr = e.fields.TargetUserName || '';
    if (!usr || usr.endsWith('$')) return;
    issues.push({
      category: 'asrepRoastingRisk', severityNorm: 'High', count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'heuristic', uacRiskUserName: usr
    });
  });
  return issues;
}
// LSASS 記憶體存取偵測（heuristic，SOC 界偵測 Mimikatz 類憑證竊取最常用的單一訊號）：Sysmon
// EventID 10（ProcessAccess）+ TargetImage 以 \lsass.exe 結尾（不分大小寫）+ GrantedAccess 命中
// 已查證的已知惡意存取權限清單。欄位（TargetImage／GrantedAccess／SourceImage）與 GrantedAccess
// 已知惡意值（0x1010／0x1038／0x1410／0x1438／0x143a／0x1fffff／0x1f1fff／0x0810，涵蓋
// Mimikatz sekurlsa／lsadump 模組與 ProcDump 等常見工具）皆已對外查證確認（TrustedSec
// SysmonCommunityGuide＋多篇 Splunk/Elastic 偵測規則交叉確認）；來源明確指出 Sysmon 本身也是
// 做字面值比對而非位元運算，比對設計沿用此慣例，非自行發明的位元判斷
const LSASS_BAD_GRANTED_ACCESS = new Set(['0x1010','0x1038','0x1410','0x1438','0x143a','0x1fffff','0x1f1fff','0x0810']);
function detectLsassAccess(events) {
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    if (e.fields.Channel !== SYSMON_CHANNEL) return;
    if (e.fields.EventID !== '10') return;
    const target = (e.fields.TargetImage || '').toLowerCase();
    if (!target.endsWith('\\lsass.exe')) return;
    const granted = (e.fields.GrantedAccess || '').toLowerCase();
    if (!LSASS_BAD_GRANTED_ACCESS.has(granted)) return;
    issues.push({
      category: 'lsassAccess', severityNorm: 'High', count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'heuristic', lsassSourceImage: e.fields.SourceImage || '', lsassGrantedAccess: granted
    });
  });
  return issues;
}
// Registry 持久化偵測（heuristic，比照 detectLsassAccess() 精神——條件本身已夠窄，不需要
// opt-in 開關）：Sysmon EventID 13（RegistryEvent Value Set）+ TargetObject 命中 Windows
// 標準自動啟動登錄機碼路徑 \CurrentVersion\Run\ 或 \CurrentVersion\RunOnce\（業界極度標準的
// 持久化偵測手法，非本輪新查證的 Windows 內建行為）。欄位（EventType／TargetObject／Details）
// 皆為 Sysmon 官方 Event ID 13 文件明載標準欄位，已對外查證確認（ultimatewindowssecurity.com／
// gravwell.io／Elastic 交叉確認）。明確排除 EventID 12(CreateKey/DeleteKey)／14(RenameKey)——
// 13(SetValue) 是絕大多數 SOC 文章聚焦的標準訊號，12/14 屬於變體手法，非本輪範圍
function detectSysmonRegistryPersistence(events) {
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    if (e.fields.Channel !== SYSMON_CHANNEL) return;
    if (e.fields.EventID !== '13') return;
    const target = e.fields.TargetObject || '';
    if (!/\\CurrentVersion\\(Run|RunOnce)\\/i.test(target)) return;
    issues.push({
      category: 'sysmonRegistryPersistence', severityNorm: 'Medium', count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'heuristic', regTargetObject: target, regImage: e.fields.Image || '', regDetails: e.fields.Details || ''
    });
  });
  return issues;
}
// 系統管理共用資料夾存取偵測（heuristic，經典橫向移動訊號，PsExec 等工具的必經路徑）：
// EventID 5140（存取到網路共用資料夾）／5145（檢查是否可存取，僅代表檢查非實際存取）+
// 官方 ShareName 欄位（固定格式 \\*\<名稱>）比對 Windows 內建系統管理共用資料夾命名慣例
// （ADMIN$／IPC$／磁碟機代號$，如 C$，皆為 Microsoft 官方文件明載的預設系統管理共用資料夾，
// 非臆測）。正常環境中合法工具（備份代理／WMI／GPO 軟體派送等）也會頻繁存取，非必然惡意，
// 故 confidence 標示為 heuristic，非官方 EventID 本身即代表攻擊
const ADMIN_SHARE_RE = /\\(ADMIN\$|IPC\$|[A-Za-z]\$)$/i;
function detectAdminShareAccess(events) {
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    if (e.fields.EventID !== '5140' && e.fields.EventID !== '5145') return;
    const share = e.fields.ShareName || '';
    if (!ADMIN_SHARE_RE.test(share)) return;
    issues.push({
      category: 'adminShareAccess', severityNorm: 'Medium', count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'heuristic', winEventId: e.fields.EventID, shareName: share
    });
  });
  return issues;
}
// EventID 4688（處理程序建立）選擇性解析：官方文件此類事件在典型 AD/端點環境量體遠高於其餘
// 已支援的 WEL 類別，貿然無條件計入問題清單會洗版，故設計為預設關閉的選擇性開關（opts.enable4688）。
// parseWinEventFragment() 已通用擷取任意具名 Data 欄位，NewProcessName/CommandLine/ParentProcessName
// 無需額外解析邏輯。比照 ASN 風險清單「使用者自己提供比對依據、工具不臆測」的既有原則：開關開啟後，
// 仍只有使用者自行輸入的可疑關鍵字清單（opts.procWatchlist）命中時才產生問題，關鍵字清單為空時
// 只是持續掃描但不產生任何問題，避免每筆正常的處理程序建立洗版問題清單
function detectProcessCreation(events, opts) {
  const o = opts || {};
  if (!o.enable4688) return [];
  const keywords = (o.procWatchlist || []).map(k => String(k).trim().toLowerCase()).filter(Boolean);
  if (!keywords.length) return [];
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    if (e.fields.EventID !== '4688') return;
    const newProc = e.fields.NewProcessName || '';
    const cmdLine = e.fields.CommandLine || '';
    const parentProc = e.fields.ParentProcessName || '';
    const haystack = `${newProc} ${cmdLine} ${parentProc}`.toLowerCase();
    const hitKw = keywords.find(k => haystack.includes(k));
    if (!hitKw) return;
    issues.push({
      category: 'processCreate', severityNorm: 'Medium', count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'heuristic', winEventId: '4688',
      procNewProcess: newProc, procCommandLine: cmdLine, procParent: parentProc, procMatchedKeyword: hitKw
    });
  });
  return issues;
}
// Sysmon（Microsoft Sysinternals，公開文件廣為人知，不需額外對外查證）：parseWinEventFragment()
// 對 Channel 值本來就無過濾，Sysmon 事件（Channel=Microsoft-Windows-Sysmon/Operational）不需改動
// parser 即可通用解析出任意具名 Data 欄位。依「事件量體」分兩層處理，避免重演 4688 若無節流會洗版
// 問題清單的教訓：
// (1) 純標籤分類（比照既有 4672/4648 樣板，見 classifyByKeyword() 對應分支）：EventID 3(NetworkConnect)
//     /11(FileCreate)/22(DNSQuery) 只標記事件供②事件清單顯示，不建立獨立 issue——這三類在有部署
//     Sysmon 的端點上事件量體與 4688 同級甚至更高，無條件計入問題清單同樣會洗版
// (2) 選擇性關鍵字偵測（本函式，完整比照 detectProcessCreation() 兩段式開關樣板）：EventID 1
//     (ProcessCreate)，預設關閉（opts.enableSysmonProc）+ 使用者自行輸入可疑關鍵字清單
//     （opts.sysmonProcWatchlist），比對範圍比 4688 更廣（Sysmon 獨有欄位：Image/CommandLine/
//     ParentImage/ParentCommandLine/Hashes，皆為 Sysmon 官方 Event ID 1 文件明載的標準欄位）
// SYSMON_CHANNEL 定義見上方 classifyByKeyword() 附近（SYSMON_TAG_EVENT_IDS 旁）
//
// 共用核心（2026-09 從四個各自獨立實作的函式抽取）：detectSysmonProcessCreate/
// detectSysmonRemoteThread/detectPowerShellScriptBlock/detectSysmonImageLoad 結構完全一致——
// opt-in 開關檢查 → 關鍵字清單非空檢查 → 依 Channel/EventID 過濾單筆事件 → 多欄位組合成
// haystack → 關鍵字比對 → 命中則組 issue。差異只在頻道/EventID/要比對哪些欄位/issue 額外
// 欄位命名（formatIssueBasis() 依各分類專屬鍵名讀取顯示文字，如 sysmonImage／
// threadSourceImage／psScriptBlockText 各不相同，無法做成全自動欄位命名），故用 buildExtra
// callback 讓呼叫端自訂輸出欄位；純重構，不改變任何既有 issue 資料形狀或比對邏輯。
function detectSysmonKeywordWatchlist(events, opts, cfg) {
  const o = opts || {};
  if (!o[cfg.enableKey]) return [];
  const keywords = (o[cfg.watchlistKey] || []).map(k => String(k).trim().toLowerCase()).filter(Boolean);
  if (!keywords.length) return [];
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'winevent' || !e.fields) return;
    if (e.fields.Channel !== cfg.channel) return;
    if (e.fields.EventID !== cfg.eventId) return;
    const f = {};
    cfg.fields.forEach(name => { f[name] = e.fields[name] || ''; });
    const haystack = cfg.fields.map(name => f[name]).join(' ').toLowerCase();
    const hitKw = keywords.find(k => haystack.includes(k));
    if (!hitKw) return;
    issues.push({
      category: cfg.category, severityNorm: 'Medium', count: 1,
      firstSeen: e.timestamp, lastSeen: e.timestamp,
      sampleRaw: e.raw, relatedHosts: e.host ? [e.host] : [], relatedEvents: [e],
      confidence: 'heuristic', winEventId: cfg.eventId,
      ...cfg.buildExtra(f, hitKw)
    });
  });
  return issues;
}
function detectSysmonProcessCreate(events, opts) {
  return detectSysmonKeywordWatchlist(events, opts, {
    enableKey: 'enableSysmonProc', watchlistKey: 'sysmonProcWatchlist',
    channel: SYSMON_CHANNEL, eventId: '1', category: 'sysmonProcessCreate',
    fields: ['Image', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'Hashes'],
    buildExtra: (f, hitKw) => ({ sysmonImage: f.Image, sysmonCommandLine: f.CommandLine, sysmonParentImage: f.ParentImage, sysmonMatchedKeyword: hitKw }),
  });
}
// Process Injection 選擇性關鍵字偵測（完整比照 detectSysmonProcessCreate() 兩段式開關樣板，預設
// 關閉）：Sysmon EventID 8（CreateRemoteThread，跨行程建立執行緒，常見的 process injection 手法）
// + 使用者自行輸入可疑關鍵字清單，比對 SourceImage／TargetImage／StartModule（皆為 Sysmon 官方
// Event ID 8 文件明載的標準欄位；StartModule／StartFunction 官方文件註明可能因推斷不到目標記憶體
// 位址對應的模組而為空字串，此時該欄位單純不參與比對，不影響其餘欄位比對）。不比照 detectLsassAccess()
// 做成 always-on heuristic——CreateRemoteThread 本身雖不常見，但仍有除錯器/特定合法軟體會觸發，
// 誤判率遠高於「存取 lsass.exe 且 GrantedAccess 命中已知惡意值」這種窄範圍組合，故維持保守的
// opt-in 設計，需使用者自行提供比對依據才會產生問題
function detectSysmonRemoteThread(events, opts) {
  return detectSysmonKeywordWatchlist(events, opts, {
    enableKey: 'enableSysmonThread', watchlistKey: 'sysmonThreadWatchlist',
    channel: SYSMON_CHANNEL, eventId: '8', category: 'sysmonRemoteThread',
    fields: ['SourceImage', 'TargetImage', 'StartModule'],
    buildExtra: (f, hitKw) => ({ threadSourceImage: f.SourceImage, threadTargetImage: f.TargetImage, threadMatchedKeyword: hitKw }),
  });
}
// PowerShell Script Block Logging 選擇性關鍵字偵測（完整比照 detectSysmonProcessCreate() 兩段式
// 開關樣板，預設關閉）：EventID 4104，獨立頻道 Microsoft-Windows-PowerShell/Operational（非
// Security／Sysmon，parseWinEventFragment() 對 Channel 值本來就無過濾不需改動）+ 使用者自行輸入
// 可疑關鍵字清單，比對 ScriptBlockText（官方文件明載欄位，內容為 PowerShell 編譯前的完整指令碼
// 文字，含 Base64/字串串接等常見混淆手法解碼後的內容，即使指令碼經過模糊化仍可比對到明文關鍵字）
const POWERSHELL_CHANNEL = 'Microsoft-Windows-PowerShell/Operational';
function detectPowerShellScriptBlock(events, opts) {
  return detectSysmonKeywordWatchlist(events, opts, {
    enableKey: 'enablePsScriptBlock', watchlistKey: 'psScriptBlockWatchlist',
    channel: POWERSHELL_CHANNEL, eventId: '4104', category: 'powershellScriptBlock',
    fields: ['ScriptBlockText'],
    buildExtra: (f, hitKw) => ({ psScriptBlockText: f.ScriptBlockText, psMatchedKeyword: hitKw }),
  });
}
// DLL 側載/注入選擇性關鍵字偵測（完整比照兩段式開關樣板，預設關閉）：Sysmon EventID 7
// （ImageLoad，處理程序載入 DLL/OCX 等映像檔）+ 使用者自行輸入可疑關鍵字清單，比對
// ImageLoaded／Image／OriginalFileName（皆為 Sysmon 官方 Event ID 7 文件明載標準欄位）。
// **官方文件與多篇來源皆強調此事件類型預設關閉、且是 Sysmon 所有事件類型中量體最高者之一
// （比 EventID 1 處理程序建立更誇張，未妥善節流會產生每日數百萬筆事件），故此處的兩段式
// 開關（預設關閉＋需使用者自行提供關鍵字清單才會產生問題）比其餘 Sysmon 選擇性偵測更關鍵，
// 絕不可做成 always-on**
function detectSysmonImageLoad(events, opts) {
  return detectSysmonKeywordWatchlist(events, opts, {
    enableKey: 'enableSysmonImageLoad', watchlistKey: 'sysmonImageLoadWatchlist',
    channel: SYSMON_CHANNEL, eventId: '7', category: 'sysmonImageLoad',
    fields: ['Image', 'ImageLoaded', 'OriginalFileName'],
    buildExtra: (f, hitKw) => ({ imgLoadImage: f.Image, imgLoadImageLoaded: f.ImageLoaded, imgLoadMatchedKeyword: hitKw }),
  });
}
// PowerShell Module Logging 選擇性關鍵字偵測（2026-09 新增，完整比照 detectPowerShellScriptBlock()
// 兩段式開關樣板，預設關閉）：EventID 4103，與 4104 同一獨立頻道 Microsoft-Windows-PowerShell/
// Operational（POWERSHELL_CHANNEL 定義見上方）。官方文件記載此事件的 Payload 內容包在
// ContextInfo 欄位（含 Command Name／Command Type 等）中，某些匯出情境下另有獨立 Payload
// 欄位列出實際參數值，兩者皆比對以涵蓋不同匯出格式差異。
function detectPowerShellModuleLogging(events, opts) {
  return detectSysmonKeywordWatchlist(events, opts, {
    enableKey: 'enablePsModuleLog', watchlistKey: 'psModuleLogWatchlist',
    channel: POWERSHELL_CHANNEL, eventId: '4103', category: 'powershellModuleLog',
    fields: ['ContextInfo', 'Payload'],
    buildExtra: (f, hitKw) => ({ psModuleContextInfo: f.ContextInfo, psModuleMatchedKeyword: hitKw }),
  });
}
// 異常流量偵測：僅 FortiGate（sentbyte+rcvdbyte）與 CEF（官方 extension 欄位 in+out）有明確規格
// 佐證的位元組欄位，LEEF/RFC3164/RFC5424/JSON 無官方預定義位元組欄位，不臆測、寧可漏報不誤判
function detectVolumeAnomalies(events, opts) {
  const threshold = (opts && opts.thresholdBytes) || 50 * 1024 * 1024;
  const issues = [];
  events.forEach(e => {
    let sent = 0, rcvd = 0, src = '';
    if (e.format === 'fortigate' && e.fields && (e.fields.sentbyte !== undefined || e.fields.rcvdbyte !== undefined)) {
      sent = Number(e.fields.sentbyte) || 0;
      rcvd = Number(e.fields.rcvdbyte) || 0;
      src = e.fields.srcip || '';
    } else if (e.format === 'cef' && e.fields && (e.fields.in !== undefined || e.fields.out !== undefined)) {
      sent = Number(e.fields.out) || 0;
      rcvd = Number(e.fields.in) || 0;
      src = e.fields.src || '';
    } else {
      return;
    }
    const total = sent + rcvd;
    if (total >= threshold) {
      issues.push({
        category: 'volumeAnomaly', severityNorm: 'High', count: 1,
        firstSeen: e.timestamp, lastSeen: e.timestamp,
        sampleRaw: e.raw, totalBytes: total, volumeSrc: src,
        relatedHosts: src ? [src] : [], relatedEvents: [e], confidence: 'heuristic'
      });
    }
  });
  return issues;
}
// 地理位置風險標記：僅 FortiGate（srccountry/dstcountry，已於真實樣本驗證存在此欄位），
// CEF/LEEF 無對應標準欄位不臆測；riskCountries 為空陣列時不執行，維持既有行為零影響
function detectGeoRiskEvents(events, riskCountries) {
  const list = (riskCountries || []).map(c => String(c).trim().toLowerCase()).filter(Boolean);
  if (!list.length) return [];
  const issues = [];
  events.forEach(e => {
    if (e.format !== 'fortigate' || !e.fields) return;
    [
      { country: e.fields.srccountry, ip: e.fields.srcip, dir: 'src' },
      { country: e.fields.dstcountry, ip: e.fields.dstip, dir: 'dst' }
    ].forEach(({ country, ip, dir }) => {
      if (!country) return;
      if (!list.includes(String(country).trim().toLowerCase())) return;
      issues.push({
        category: 'geoRisk', severityNorm: 'Medium', count: 1,
        firstSeen: e.timestamp, lastSeen: e.timestamp,
        sampleRaw: e.raw, geoCountry: country, geoDirection: dir, geoIp: ip || '',
        relatedHosts: ip ? [ip] : [], relatedEvents: [e], confidence: 'heuristic'
      });
    });
  });
  return issues;
}

