const EGG_LANGS = ['tlh','pirate','leet','emoji','uwu','bureau','cat','bean','alpaca','yanse','wuxia'];
let unlockedEggs = { tlh:false, pirate:false, leet:false, emoji:false, uwu:false, bureau:false, cat:false, bean:false, alpaca:false, yanse:false };
// 語言偏好跨工具共用（2026-09-29，PB）：共用 localStorage key 'cw_lang'（比照主題 'cw_theme'），
// 只記住三種正式語言；彩蛋語言需各工具各自解鎖，不跨工具帶入。未存過時依瀏覽器語言決定
function loadLangPref() {
  try { const v = localStorage.getItem('cw_lang'); if (v === 'zhTW' || v === 'en' || v === 'ja') return v; } catch (e) {}
  const n = ((typeof navigator !== 'undefined' && navigator.language) || '').toLowerCase();
  return n.indexOf('ja') === 0 ? 'ja' : (n.indexOf('zh') === 0 || !n ? 'zhTW' : 'en');
}
// 無障礙（UE，2026-09-29 新增）：沒有可存取名稱的輸入欄位，自動關聯到緊鄰的標籤——前一個兄弟元素是
// 沒有 for 的 <label> 時補 for；是 <span> 時以 aria-labelledby 指向它（語言切換後名稱跟著更新）。
// 已有 label／aria／title／placeholder（瀏覽器本身會當名稱）者不動。各工具各自一份，不跨檔引用
function autoLabelControls() {
  var n = 0;
  document.querySelectorAll('input:not([type=hidden]):not([type=file]),select,textarea').forEach(function (el) {
    if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.title || el.placeholder || el.closest('label')) return;
    if (el.id && document.querySelector('label[for="' + el.id + '"]')) return;
    var lb = el.previousElementSibling;
    if (!lb || !/^(LABEL|SPAN)$/.test(lb.tagName) || lb.querySelector('input,select,textarea')) return;
    if (lb.tagName === 'LABEL' && !lb.htmlFor && el.id) { lb.htmlFor = el.id; return; }
    if (!lb.id) lb.id = 'auto-lbl-' + (++n);
    el.setAttribute('aria-labelledby', lb.id);
  });
}
function saveLangPref(code) {
  if (code === 'zhTW' || code === 'en' || code === 'ja') { try { localStorage.setItem('cw_lang', code); } catch (e) {} }
}
let currentLang = loadLangPref();
const LANG_BTN_LABEL = { zhTW:'繁中', en:'EN', ja:'日本語', tlh:"Qo'noS", pirate:'☠ Arr', leet:'1337', emoji:'🌈', uwu:'UwU', bureau:'公文', cat:'nyaa', bean:'🥕🫛🌽', alpaca:'🦙咩', yanse:'😮‍💨 算了', wuxia:'武林' };

function leetify(s) { return s.replace(/[aeiostl]/gi, c => ({a:'4',e:'3',i:'1',o:'0',s:'5',t:'7',l:'|'}[c.toLowerCase()] || c)); }
function uwuify(s) { return s.replace(/th/gi,'d').replace(/[rl]/gi,'w').replace(/n([aeiou])/gi,'ny$1'); }
const BEAN_MAP = { a:'🫘', e:'🥦', i:'🥕', o:'🥔', u:'🍆' };
function beanify(s) { return s.replace(/[aeiou]/gi, c => BEAN_MAP[c.toLowerCase()] || c); }

// ── 跨工具導覽（2026-08-24 新增）：見 switch_analyzer 同名函式註解
function toggleToolsNav(e) {
  if (e) e.stopPropagation();
  const p = document.getElementById('tools-nav-panel');
  if (!p) return;
  p.style.display = (p.style.display === 'none' || !p.style.display) ? 'block' : 'none';
}
document.addEventListener('click', function (e) {
  const p = document.getElementById('tools-nav-panel');
  if (p && p.style.display === 'block' && !p.contains(e.target) && e.target.id !== 'tools-nav-btn') {
    p.style.display = 'none';
  }
});

function tr(key) {
  if (currentLang === 'leet') return leetify(LANG.en[key] || LANG.zhTW[key] || key);
  if (currentLang === 'uwu') return uwuify(LANG.en[key] || LANG.zhTW[key] || key);
  if (currentLang === 'cat') return LANG.cat[key] || ((LANG.en[key] || LANG.zhTW[key] || key) + ' 喵~');
  if (currentLang === 'bean') return LANG.bean[key] || beanify(LANG.en[key] || LANG.zhTW[key] || key);
  return (LANG[currentLang] && LANG[currentLang][key]) || LANG.zhTW[key] || key;
}

// ============================================================
// [8] UI 狀態與繪製
// ============================================================
let RAW_TEXT = '';
// 本次分析無法解析的原始行（RC 回報用），重新分析或清除時重設
let UNPARSED_LINES = [];
let EVENTS = [];
let INTEL_LISTS = []; // { name, date, index }
let HASH_INTEL_LISTS = []; // { name, date, index }（2026-09-18 新增，結構同 INTEL_LISTS）
let SAFE_LISTS = []; // { name, index }（已知安全清單／白名單，結構同 INTEL_LISTS 但不含 date）
let GEO_LISTS = []; // { name, index }（GeoIP CIDR→國家資料庫，結構同 SAFE_LISTS；index 內每筆 entry 的 meta.country 供 detectGeoIPLookup() 查詢）
let ASN_LISTS = []; // { name, index }（IP→ASN 資料庫，結構同 GEO_LISTS；index 內每筆 entry 的 meta.asn/asName 供 lookupASN() 查詢，2026-08-27 接線）
// 風險 ASN 清單匯入（如 Spamhaus ASN-DROP，2026-08-31 新增）：{asn, asName} 陣列，語意與
// ASN_LISTS（IP→ASN 對照資料庫）完全不同——此處是「哪些 ASN 本身是已知風險」的名單，不含
// 任何 IP/CIDR 資料，故不可塞進 ASN_LISTS，需獨立儲存。與 detectAsnRisk() 消費的
// riskAsns（字串陣列）之間由 renderAsnRiskChecks()/getRiskAsns() 的 checkbox 機制銜接，
// 見該函式對應註解
let IMPORTED_RISK_ASNS = [];
// 代管業者 ASN 清單（XN25，parseHostingAsnList()）：只存記憶體，供 detectVpnFromHosting() 比對 VPN 成功登入
let IMPORTED_HOSTING_ASNS = [];
// 商用 VPN 位址清單（XN36，parseAnonVpnList()）：只存記憶體，供 detectVpnFromAnonVpn() 比對 VPN 成功登入
let IMPORTED_ANONVPN = [];
// 遠端管理工具網域清單（XN37，parseRmmList()）：只存記憶體，供 detectRmmTools() 比對
let IMPORTED_RMM = [];
// 記錄「曾經因風險清單匯入而被自動勾選過一次」的 ASN（2026-08-31 新增，修復 renderAsnRiskChecks()
// 的邊界案例：同一 ASN 若先因 IP→ASN 資料庫上傳而出現在勾選清單中〔未勾選〕，之後才被匯入
// 的風險清單標記為風險，若只靠「是否曾經渲染過」判斷會誤判為使用者已決定不勾，導致真正的
// 風險匯入被忽略。改為「只要曾經自動勾選過一次即不重複強制」，之後皆尊重使用者手動狀態）
const AUTO_CHECKED_RISK_ASNS = new Set();
let ISSUES = [];
let CHAINS = [];
let ANON_EVENTS = null;
// 檔案上傳超過門檻時，全文不塞進可見的 paste-area textarea（本身就會讓瀏覽器 reflow 卡頓，
// 與後續解析快慢無關），改存這裡；doAnalyze() 優先讀這個變數，沒有才回退讀 textarea.value
let PENDING_LARGE_TEXT = null;
// 只改分析條件再按「分析」時文字未變，沿用上次解析結果（第二十八輪 OP4）；分析過程對事件的改動
// （category 重算、netOps 補欄位、notes 每次重設）可重複執行，不受分析條件影響
let PARSE_CACHE = null;
const LARGE_FILE_LINE_THRESHOLD = 20000;
const LARGE_FILE_BYTE_THRESHOLD = 2 * 1024 * 1024;
// 多檔上傳真正分組（2026-09 新增）：doUploadFile() 上傳 2 個以上檔案時才會填值（見該函式），
// 供 doAnalyze() 呼叫 annotateEventsWithSourceFile() 使用；使用者若在 paste-area 手動編輯
// 內容（見下方 pasteArea 'input' 監聽），行號對照表可能已與實際文字不符，一併清空避免誤標
let SOURCE_FILE_BOUNDARIES = [];
let RESULTS_FILE_FILTER = '';
// 檔案雜湊/監管鏈中繼資料（2026-09-14 新增）：doUploadFile() 對原始上傳文字（reformatting 前）
// 算 SHA-256，連同既有已算好的 lineCount/names/totalSize 一併存入，供 doExportFileMetadata()
// 匯出；貼上文字（非上傳檔案）情境下維持 null，不臆測雜湊
let FILE_METADATA = null;

function fmtTime(d) { return d ? new Date(d).toLocaleString() : '-'; }
// 關聯鏈涵蓋時間跨度顯示，語言中立（純數字+單位），比照專案既有「數字語言中立、不特地建 i18n key」慣例
function spanText(ms) {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60), rs = s % 60;
  if (m < 60) return `${m}m${rs ? ' ' + rs + 's' : ''}`;
  const h = Math.floor(m / 60), rm = m % 60;
  return `${h}h${rm ? ' ' + rm + 'm' : ''}`;
}

const CAT_KEY_MAP = { mtFwTamper:'cat.mtFwTamper', mtUserChange:'cat.mtUserChange', mtPersistence:'cat.mtPersistence', mtProxyEnable:'cat.mtProxyEnable', mtServiceChange:'cat.mtServiceChange', riskyPortAllowed:'cat.riskyPortAllowed', riskyPortProbe:'cat.riskyPortProbe', riskyPortSweep:'cat.riskyPortSweep', esxiRemoteAccess:'cat.esxiRemoteAccess', esxiDefenseOff:'cat.esxiDefenseOff', esxiAccountChange:'cat.esxiAccountChange', esxiVmImpact:'cat.esxiVmImpact', webshellCmd:'cat.webshellCmd', webshellUpload:'cat.webshellUpload', webshellNewScript:'cat.webshellNewScript', dbAdminRemote:'cat.dbAdminRemote', dbExternalLogin:'cat.dbExternalLogin', dbNewSource:'cat.dbNewSource', dbAuthFailBurst:'cat.dbAuthFailBurst', exploitAttempt:'cat.exploitAttempt', appsmithOriginReset:'cat.appsmithOriginReset', appsmithResetFlow:'cat.appsmithResetFlow', appsmithResetBurst:'cat.appsmithResetBurst', appsmithExternalRisky:'cat.appsmithExternalRisky', appsmithScriptedApi:'cat.appsmithScriptedApi', appsmithExposed:'cat.appsmithExposed', credFileExposed:'cat.credFileExposed', secretBulkRead:'cat.secretBulkRead', cloudKeyMultiSource:'cat.cloudKeyMultiSource', sshKeyMultiSource:'cat.sshKeyMultiSource', appCredentialAdded:'cat.appCredentialAdded', gitlabCiVarRead:'cat.gitlabCiVarRead', gitlabTokenMultiSource:'cat.gitlabTokenMultiSource', gitlabMassClone:'cat.gitlabMassClone', gitlabTokenCreated:'cat.gitlabTokenCreated', awsRootUsage:'cat.awsRootUsage', awsConsoleNoMfa:'cat.awsConsoleNoMfa', promptInjection:'cat.promptInjection', svcCrash:'cat.svcCrash', svcUnexpectedRestart:'cat.svcUnexpectedRestart', svcDbError:'cat.svcDbError', svcDiskLow:'cat.svcDiskLow', svcBindFail:'cat.svcBindFail', svcResource:'cat.svcResource', svcReplFail:'cat.svcReplFail', svcBackendFail:'cat.svcBackendFail', svcUpstreamDown:'cat.svcUpstreamDown', svcNoUpstream:'cat.svcNoUpstream', crossDomainLogon:'cat.crossDomainLogon', radiusUnknownClient:'cat.radiusUnknownClient', radiusBadSecret:'cat.radiusBadSecret', radiusTlsFail:'cat.radiusTlsFail', radiusBlast:'cat.radiusBlast', radiusMacMultiUser:'cat.radiusMacMultiUser', ldapUnsignedBind:'cat.ldapUnsignedBind', dcsync:'cat.dcsync', adSensitiveChange:'cat.adSensitiveChange', sidHistory:'cat.sidHistory', dsrmPassword:'cat.dsrmPassword', computerAccountCreated:'cat.computerAccountCreated', certIssued:'cat.certIssued', rdpLogon:'cat.rdpLogon', cleartextLogon:'cat.cleartextLogon', passwordSpray:'cat.passwordSpray', ldapBruteForce:'cat.ldapBruteForce', ldapPlainBind:'cat.ldapPlainBind', ldapAnonBind:'cat.ldapAnonBind', ldapEnum:'cat.ldapEnum', winFailReasons:'cat.winFailReasons', offHours:'cat.offHours', unusualHour:'cat.unusualHour', newSource:'cat.newSource', idsAlert:'cat.idsAlert', authFail:'cat.authFail', denyBlock:'cat.denyBlock', attack:'cat.attack', scanFlood:'cat.scanFlood', exceedThreshold:'cat.exceedThreshold', other:'cat.other', possibleScan:'cat.possibleScan', knownIOC:'cat.knownIOC', volumeAnomaly:'cat.volumeAnomaly', geoRisk:'cat.geoRisk', geoIPRisk:'cat.geoIPRisk', beaconing:'cat.beaconing', lateralMovement:'cat.lateralMovement', privEsc:'cat.privEsc', geoVelocity:'cat.geoVelocity', asnRisk:'cat.asnRisk', vpnHostingLogin:'cat.vpnHostingLogin', vpnAnonLogin:'cat.vpnAnonLogin', rmmTool:'cat.rmmTool', distributedSpray:'cat.distributedSpray', mfaFatigue:'cat.mfaFatigue', netAdminAdd:'cat.netAdminAdd', acctLockout:'cat.acctLockout', pwReset:'cat.pwReset', groupRemoved:'cat.groupRemoved', acctStatusChange:'cat.acctStatusChange', auditCleared:'cat.auditCleared', persistence:'cat.persistence', passTheHash:'cat.passTheHash',kerberoasting:'cat.kerberoasting', asrepRoasting:'cat.asrepRoasting', asrepRoastingRisk:'cat.asrepRoastingRisk', lsassAccess:'cat.lsassAccess', sysmonRegistryPersistence:'cat.sysmonRegistryPersistence', specialPrivLogon:'cat.specialPrivLogon', explicitCredLogon:'cat.explicitCredLogon', acctDeleted:'cat.acctDeleted',registryValueChange:'cat.registryValueChange',tokenPrivAdjust:'cat.tokenPrivAdjust',groupEnum:'cat.groupEnum', auditPolicyChanged:'cat.auditPolicyChanged', auditLogFull:'cat.auditLogFull', adminShareAccess:'cat.adminShareAccess', processCreate:'cat.processCreate', asnVelocity:'cat.asnVelocity', sysmonNetConn:'cat.sysmonNetConn', sysmonFileCreate:'cat.sysmonFileCreate', sysmonDnsQuery:'cat.sysmonDnsQuery', sysmonProcessCreate:'cat.sysmonProcessCreate', sysmonRemoteThread:'cat.sysmonRemoteThread', powershellScriptBlock:'cat.powershellScriptBlock', sysmonImageLoad:'cat.sysmonImageLoad',powershellModuleLog:'cat.powershellModuleLog', timeGap:'cat.timeGap', knownHashIOC:'cat.knownHashIOC', linkUpDown:'cat.linkUpDown', linkFlap:'cat.linkFlap', macFlap:'cat.macFlap', errDisable:'cat.errDisable', stpChange:'cat.stpChange', poeFault:'cat.poeFault', hwAlarm:'cat.hwAlarm', configChange:'cat.configChange', dnsDga:'cat.dnsDga', dnsTunnel:'cat.dnsTunnel', dnsNxBurst:'cat.dnsNxBurst', nacAuthFail:'cat.nacAuthFail', npsRejectBurst:'cat.npsRejectBurst', nsSessionMultiIp:'cat.nsSessionMultiIp', vpnSessionMultiIp:'cat.vpnSessionMultiIp', qnapSnapshotDelete:'cat.qnapSnapshotDelete', qnapMassFileChange:'cat.qnapMassFileChange', veeamMalware:'cat.veeamMalware', vaultAuditDisabled:'cat.vaultAuditDisabled', fmgUnregDevice:'cat.fmgUnregDevice', vaultRootUse:'cat.vaultRootUse', veeamDefenseOff:'cat.veeamDefenseOff', veeamDeleteAttempt:'cat.veeamDeleteAttempt', sshBruteSuccess:'cat.sshBruteSuccess', adminLoginExternal:'cat.adminLoginExternal', adminLoginFailExternal:'cat.adminLoginFailExternal', k8sExec:'cat.k8sExec', k8sSecretAccess:'cat.k8sSecretAccess', duoFraud:'cat.duoFraud' };
// MITRE ATT&CK 技術編號參考標籤（2026-09-01 新增，純靜態查表，不新增偵測邏輯）：只對業界已有
// 明確 established 對應的分類標註，語意含糊或屬於「風險標記」而非「技術行為」的分類（如
// knownIOC/volumeAnomaly/processCreate 等）刻意留空，不臆測湊數（geoRisk/geoIPRisk/asnRisk
// 例外，這三個雖是風險標記但語意明確對應 T1078，故仍標註，見下方）。僅供參考，非事件的
// 最終定性判斷——同一 EventID 組合在真實環境也可能對應多種技術，見 mitre.disclaimer 提示文字。
// 注意：key 必須是 buildIssueList() 實際會產生的 issue category（見 CAT_KEY_MAP），純標籤分類
// （classifyByKeyword() 專用、從未進 issues 陣列的 specialPrivLogon/explicitCredLogon/
// sysmonNetConn/sysmonFileCreate/sysmonDnsQuery，見 line 2456 附近說明）刻意不收錄，收錄了也
// 永遠查不到對應的 is.category，是查無意義的死碼。
const MITRE_MAP = {
  mtFwTamper:'T1562.004', mtUserChange:'T1136.001', mtPersistence:'T1053.005', mtProxyEnable:'T1090', mtServiceChange:'T1562.004',
  riskyPortAllowed:'T1190', riskyPortProbe:'T1595.001', riskyPortSweep:'T1595.001',
  authFail:'T1110', acctLockout:'T1110', exploitAttempt:'T1190', npsRejectBurst:'T1110', nsSessionMultiIp:'T1550.004', vpnSessionMultiIp:'T1550.004', qnapSnapshotDelete:'T1490', qnapMassFileChange:'T1486', veeamDefenseOff:'T1562.001', vaultAuditDisabled:'T1562.008', fmgUnregDevice:'T1190', vaultRootUse:'T1078.003', veeamDeleteAttempt:'T1490', appsmithOriginReset:'T1190', appsmithResetFlow:'T1098', appsmithResetBurst:'T1190', appsmithExternalRisky:'T1190', appsmithScriptedApi:'T1059', credFileExposed:'T1552.001', secretBulkRead:'T1555', cloudKeyMultiSource:'T1078.004', sshKeyMultiSource:'T1552.004', appCredentialAdded:'T1098.001', gitlabCiVarRead:'T1552', gitlabTokenMultiSource:'T1078', gitlabMassClone:'T1213.003', gitlabTokenCreated:'T1098.001', awsRootUsage:'T1078.004', webshellCmd:'T1505.003', webshellUpload:'T1505.003', webshellNewScript:'T1505.003', esxiRemoteAccess:'T1021.004', esxiDefenseOff:'T1562.001', esxiAccountChange:'T1098', esxiVmImpact:'T1490', dbAdminRemote:'T1078', dbExternalLogin:'T1078', dbNewSource:'T1078', dbAuthFailBurst:'T1110', awsConsoleNoMfa:'T1078.004',
  // VPN 成功登入來自代管網段（XN25）：T1133 External Remote Services
  vpnHostingLogin:'T1133', vpnAnonLogin:'T1133', rmmTool:'T1219',
  // DNS 異常（第二十一輪 GB）：DGA T1568.002（Dynamic Resolution: Domain Generation Algorithms）、DNS 通道 T1071.004（Application Layer Protocol: DNS）
  dnsDga:'T1568.002', dnsTunnel:'T1071.004', sshBruteSuccess:'T1110', adminLoginExternal:'T1078', adminLoginFailExternal:'T1110', ldapBruteForce:'T1110', ldapEnum:'T1087.002', passwordSpray:'T1110.003', distributedSpray:'T1110.003', mfaFatigue:'T1621', netAdminAdd:'T1136.001', rdpLogon:'T1021.001', adSensitiveChange:'T1098', sidHistory:'T1134.005', dsrmPassword:'T1098', dcsync:'T1003.006',
  // Kubernetes（第二十三輪 ID）：T1609 Container Administration Command、T1552.007 Unsecured Credentials: Container API
  k8sExec:'T1609', k8sSecretAccess:'T1552.007',
  // Duo 詐騙回報（第二十三輪 IF）：T1621 Multi-Factor Authentication Request Generation
  duoFraud:'T1621',
  passTheHash:'T1550.002',
  kerberoasting:'T1558.003',
  asrepRoasting:'T1558.004', asrepRoastingRisk:'T1558.004',
  lsassAccess:'T1003.001',
  sysmonRegistryPersistence:'T1547.001',
  // 2026-09-22 新增：registryValueChange（EventID 4657，任意登錄值變更）對應 T1112（Modify
  // Registry）——MITRE ATT&CK 框架內「修改登錄」的標準技術編號，語意明確無爭議，不同於先前
  // 排除的 tokenPrivAdjust（3 個來源給出 3 種不同編號，信心度不足），故直接採納不額外查證
  registryValueChange:'T1112',
  lateralMovement:'T1021',
  adminShareAccess:'T1021.002',
  privEsc:'T1098', groupRemoved:'T1098', pwReset:'T1098',
  acctDeleted:'T1531',
  auditCleared:'T1070.001',
  auditPolicyChanged:'T1562.002',
  persistence:'T1053.005',
  beaconing:'T1071',
  possibleScan:'T1595',
  geoVelocity:'T1078', asnVelocity:'T1078', geoRisk:'T1078', geoIPRisk:'T1078', asnRisk:'T1078',
};
// doExportCSV() 的資料列組裝部分抽成純函式（2026-09 新增，Phase 3 item 14：log_analyzer UI
// 層測試覆蓋），輸入 ISSUES 陣列，輸出含表頭列的完整二維陣列；doExportCSV() 只需再做
// csvCell()/Blob 下載，不重算任何欄位。2026-09-10 新增 mitre 欄位：比照 renderIssues()/
// exportLogReport() 的 MITRE_MAP 查表邏輯，freq: 前綴分類需先去除前綴才查得到；CSV 為純文字
// 沒有徽章的必要，查無對應時留空字串，MITRE ID 本身是固定格式（如 T1558.003）不含逗號/引號
// 等特殊字元，不需額外跳脫
// 先查什麼（2026-09-29 新增，第七輪 NE）：常見分類的白話說明與第一步排查建議（i18n next.<分類>），
// 沒有撰寫說明的分類（多為 Windows／Sysmon 細項）不顯示
function nextStepHtml(cat) {
  const t = tr('next.' + cat);
  if (!t || t === 'next.' + cat) return '';
  return `<details class="next-step"><summary>${esc(tr('next.title'))}</summary><div>${esc(t)}</div></details>`;
}
function buildCSVRows(issues) {
  const rows = [['category', 'severity', 'count', 'confidence', 'source', 'basis', 'firstSeen', 'lastSeen', 'sample', 'mitre', 'note', 'status']];
  issues.forEach(is => {
    const baseCat = is.category.startsWith('freq:') ? is.category.slice(5) : is.category;
    // 分析師備註（2026-09-16 新增）：issueNotes 是模組級全域（定義於本區塊之外），此函式雖為
    // 「純函式」慣例但本來就已在 STATE/UI 邊界之後與其餘全域狀態同一作用域，維持一致寫法
    rows.push([is.category, is.severityNorm, is.count, is.confidence, getIssueIntelSources(is).join(','), formatIssueBasis(is), fmtTime(is.firstSeen), fmtTime(is.lastSeen), issueSample(is).replace(/[\r\n]+/g, ' '), (is.mitre || MITRE_MAP[baseCat]) || '', issueNotes[_baselineDiffKey(is)] || '', issueStatusOf(_baselineDiffKey(is))]);
  });
  return rows;
}
// 事件清單「疑似問題」欄位用的簡短判定標籤，與問題清單既有的 cat.* 分類標籤分開維護，
// 用詞更直接（如「疑似猜密碼」而非「頻率異常：認證失敗」），方便逐筆事件快速辨識
const NOTE_KEY_MAP = { 'freq:authFail':'note.bruteForce', 'freq:denyBlock':'note.scanOrMisconfig', possibleScan:'note.possibleScan', knownIOC:'note.knownIOC' };
function noteKeyForCategory(cat) {
  if (NOTE_KEY_MAP[cat]) return NOTE_KEY_MAP[cat];
  if (cat.startsWith('freq:')) return 'note.freqAnomaly';
  return null;
}
const SEV_KEY_MAP = { Critical:'sev.critical', High:'sev.high', Medium:'sev.medium', Low:'sev.low', Info:'sev.info' };
// badge 的 class 只輸出固定五級，其他值一律當 Info（避免外部資料進到 class 屬性）
function sevClass(s) { return Object.prototype.hasOwnProperty.call(SEV_KEY_MAP, s) ? s : 'Info'; }

function renderLangBar() {
  const bar = document.getElementById('lang-bar');
  const all = ['zhTW','en','ja', ...EGG_LANGS];
  bar.innerHTML = all.map(l => {
    const isEgg = EGG_LANGS.includes(l);
    const shown = !isEgg || unlockedEggs[l];
    return `<button id="lang-${l}" class="lang-btn ${l===currentLang?'active':''} ${shown?'':'hidden'}" data-lang="${l}">${LANG_BTN_LABEL[l]}</button>`;
  }).join('');
  bar.querySelectorAll('.lang-btn').forEach(b => b.onclick = () => { currentLang = b.dataset.lang; saveLangPref(currentLang); renderAll(); });
}

function showEggToast(msg, duration) {
  // 彩蛋改由右下角羊駝呈現（XN49，alpaca-buddy.js）：主動彩蛋出泡泡、被動彩蛋收進口袋
  if (window.AlpacaBuddy) return window.AlpacaBuddy.say(msg, duration);
  const t = document.createElement('div');
  t.className = 'egg-toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.classList.add('show'), 20);
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 400); }, duration || 3500);
}

// 彩蛋：每個 .lang-egg 圖示各自對應一種語言，三連擊解鎖並立即切換＋顯示 toast
const _EGG = {
  'egg-pirate': { lang:'pirate', toast:"☠️ Ahoy! Ye be speakin' pirate now, matey! Arr!" },
  'egg-leet':   { lang:'leet',   toast:'1337 5P34K 4C71V473D.' },
  'egg-emoji':  { lang:'emoji',  toast:'🌈✨🎉 3moji mod3 4ctiv4t3d! 🦄💫🌟' },
  'egg-uwu':    { lang:'uwu',    toast:'🐾 Hewwo fwend~ UwU wanguage activeated! OwO' },
  'egg-bureau': { lang:'bureau', toast:'📋 本系統正式進入公文模式，請依規定格式呈現。' },
  'egg-cat':    { lang:'cat',    toast:'🐱 Nyaa~！喵語模式啟動了喵！' },
  'egg-bean':   { lang:'bean',   toast:'🥕🫛🌽 豆語模式啟動！蔬菜智慧已降臨！🌽🫛🥕' },
  'egg-alpaca': { lang:'alpaca', toast:'🦙 咩咩咩！羊咩碼啟動-aca！' },
  'egg-yanse':  { lang:'yanse',  toast:'😮‍💨 厭世模式啟動，反正早晚都要加班。' },
  'egg-wuxia':  { lang:'wuxia',  toast:'⚔️ 武林秘笈已然出鞘！江湖兒女，且看今朝！' }
};
const _eggN = {};
document.querySelectorAll('.lang-egg').forEach(el => {
  _eggN[el.id] = 0;
  let t;
  el.addEventListener('click', () => {
    clearTimeout(t);
    _eggN[el.id]++;
    t = setTimeout(() => { _eggN[el.id] = 0; }, 1500);
    if (_eggN[el.id] >= 3) {
      _eggN[el.id] = 0;
      const c = _EGG[el.id];
      unlockedEggs[c.lang] = true;
      currentLang = c.lang;
      renderAll();
      showEggToast(c.toast);
    }
  });
});
// 彩蛋：右下角迷你羊駝三連擊解鎖 tlh（Klingon），與其餘 7 種一般彩蛋語言分開處理，比照既有工具慣例
(function(){
  let n = 0, t;
  document.getElementById('mini-alpaca').addEventListener('click', () => {
    clearTimeout(t);
    n++;
    t = setTimeout(() => { n = 0; }, 2000);
    if (n >= 3) {
      n = 0;
      unlockedEggs.tlh = true;
      currentLang = 'tlh';
      renderAll();
      showEggToast("🖖 Qapla'! tlhIngan Hol yIlo'!");
    }
  });
})();
// 彩蛋：連續按 Esc 三次（1500ms 內）視為「不想分析了」，顯示吐槽 toast 並清空目前分析結果
// （doClear() 為既有「清空」按鈕呼叫的同一個函式，等同重新開啟分析器）。與 _EGG 那組「切換
// 語言」彩蛋不同——這則 toast 不綁定特定語言，改走 i18n（'egg.escToast'，11 語言皆已補齊），
// 顯示內容會依使用者目前選擇的介面語言呈現
(function(){
  let n = 0, t;
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    clearTimeout(t);
    n++;
    t = setTimeout(() => { n = 0; }, 1500);
    if (n >= 3) {
      n = 0;
      showEggToast(tr('egg.escToast'));
      doClear();
    }
  });
})();

// 彩蛋：Konami Code（↑↑↓↓←→←→BA）→ Log Rain，比照防火牆工具的 Matrix Rain，雨滴換成各廠牌 log 片段（2026-10-14）
(function(){
  const SEQ = ['ArrowUp','ArrowUp','ArrowDown','ArrowDown','ArrowLeft','ArrowRight','ArrowLeft','ArrowRight','b','a'];
  let idx = 0;
  document.addEventListener('keydown', e => {
    const k = e.key.length === 1 ? e.key.toLowerCase() : e.key;
    idx = k === SEQ[idx] ? idx + 1 : (k === SEQ[0] ? 1 : 0);
    if (idx === SEQ.length) { idx = 0; startLogRain(); }
  });
})();
function startLogRain() {
  if (document.querySelector('.matrix-overlay')) return;
  const overlay = document.createElement('div');
  overlay.className = 'matrix-overlay';
  document.body.appendChild(overlay);
  const words = ['%ASA-6-302013', 'sshd[42]: Failed password', 'RT_FLOW_SESSION_DENY', 'action=deny', 'EventID 4625', 'CEF:0|', 'NXDOMAIN', 'TCP_DENIED/403', '%LINK-3-UPDOWN', 'type=traffic', 'Sysmon 10 lsass.exe', '🦙 alpaca[1]: ok'];
  const cols = Math.floor(window.innerWidth / 150) + 2;
  for (let i = 0; i < cols; i++) {
    const col = document.createElement('div');
    col.className = 'matrix-col';
    col.style.left = (i * 150) + 'px';
    col.style.animation = `matrixDrop ${5 + Math.random() * 6}s linear forwards`;
    col.style.animationDelay = (Math.random() * 2.5) + 's';
    const lines = 12 + Math.floor(Math.random() * 10);
    for (let j = 0; j < lines; j++) {
      const span = document.createElement('span');
      span.textContent = words[Math.floor(Math.random() * words.length)];
      span.style.color = j === lines - 1 ? '#ffffff' : `rgba(0,200,240,${0.25 + Math.random() * 0.75})`;
      col.appendChild(span);
    }
    overlay.appendChild(col);
  }
  const close = () => overlay.remove();
  overlay.addEventListener('click', close);
  setTimeout(close, 9000);
}
// 彩蛋：分析完成後——log 裡出現羊駝字樣優先，否則問題清單為 0 時報平安（2026-10-14）
function logEggsAfterAnalyze() {
  if (!EVENTS.length) return;
  if ([114514, 1919, 810].includes(EVENTS.length)) showEggToast(tr('egg.smelly'), 4500);
  // 有事件剛好發生在本地時間 11:45:14
  else if (EVENTS.some(e => e.timestamp instanceof Date && e.timestamp.getHours() === 11 && e.timestamp.getMinutes() === 45 && e.timestamp.getSeconds() === 14)) showEggToast(tr('egg.smelly_time'), 4500);
  else if (EVENTS.some(e => /alpaca|llama|羊駝/i.test(e.raw || ''))) showEggToast(tr('egg.log_alpaca_spotted'), 4500);
  else if (!ISSUES.length) showEggToast(tr('egg.log_peaceful'), 4500);
}
// 彩蛋：愚人節（本機日期 4/1）標題前加 🦙 並跳提示；window._aprilFools 供會重設標題的工具沿用（2026-10-14，6 個工具各一份）
(function(){
  const d=new Date();
  if(d.getMonth()!==3||d.getDate()!==1)return;
  window._aprilFools=true;
  document.title='🦙 '+document.title.replace(/^🦙 /,'');
  setTimeout(()=>showEggToast(tr('egg.april_fools')),1500);
})();
// 彩蛋：鍵盤依序輸入 1145141919810（輸入框內也算）→ toast，文案 egg.smelly 依語言顯示（2026-10-14，6 個工具各一份）
(function(){
  const SEQ = '1145141919810';
  // 連續輸入時依序換句（冰紅茶、屋頂），之後循環
  const SMELLY_LINES=['egg.smelly','egg.smelly_tea','egg.smelly_roof'];let smellyN=0;
  let buf = '';
  document.addEventListener('keydown', e => {
    if (!e.key || e.key.length !== 1) return;
    buf = (buf + e.key).slice(-SEQ.length);
    if(buf===SEQ){buf='';showEggToast(tr(SMELLY_LINES[smellyN++%SMELLY_LINES.length]));}
  });
})();

function renderStatic() {
  document.getElementById('app-title').textContent = tr('app.title');
  document.getElementById('app-sub').textContent = tr('app.subtitle');
  // 跨工具導覽面板（2026-08-24 新增）：本檔案沒有通用的 [data-i18n] 掃描機制（靠 renderAll()
  // 整段重繪），比照本函式既有逐一手動更新慣例，範圍限定在導覽面板內
  document.querySelectorAll('#tools-nav-panel [data-i18n], #tour [data-i18n]').forEach(el => { el.textContent = tr(el.dataset.i18n); });
  document.getElementById('disclaimer').textContent = '⚠ ' + tr('notice.disclaimer');
  document.getElementById('t-import-title').textContent = tr('import.title');
  document.getElementById('t-import-hint').textContent = tr('import.hint');
  document.getElementById('t-import-origin').textContent = tr('import.appsmith_hint');
  document.getElementById('t-import-short').textContent = tr('import.short');
  document.getElementById('t-import-formats').textContent = tr('import.formats');
  document.getElementById('t-optsrc').textContent = tr('optsrc.summary');
  document.getElementById('paste-area').placeholder = tr('import.paste_placeholder');
  document.getElementById('btn-upload').textContent = tr('import.upload_btn');
  document.getElementById('btn-analyze').textContent = tr('import.analyze_btn');
  document.getElementById('btn-clear').textContent = tr('import.clear_btn');
  document.getElementById('btn-sample').textContent = tr('import.sample_btn');
  document.getElementById('lbl-adv-options').textContent = tr('opt.advanced');
  document.getElementById('lbl-freq-window').textContent = tr('opt.freqWindow');
  document.getElementById('lbl-freq-threshold').textContent = tr('opt.freqThreshold');
  document.getElementById('lbl-scan-threshold').textContent = tr('opt.scanThreshold');
  document.getElementById('lbl-volume-threshold').textContent = tr('opt.volumeThreshold');
  document.getElementById('lbl-chain-window').textContent = tr('opt.chainWindow');
  document.getElementById('lbl-gap-threshold').textContent = tr('opt.gapThreshold');
  document.getElementById('lbl-chain-groupby').textContent = tr('opt.chainGroupBy');
  document.getElementById('opt-chain-groupby-ip').textContent = tr('opt.chainGroupByIp');
  document.getElementById('opt-chain-groupby-user').textContent = tr('opt.chainGroupByUser');
  document.getElementById('lbl-geo-risk').textContent = tr('opt.geoRiskLabel');
  document.getElementById('geo-risk-filter').placeholder = tr('opt.geoRiskFilter');
  document.getElementById('lbl-asn-risk').textContent = tr('opt.asnRiskLabel');
  document.getElementById('asn-risk-filter').placeholder = tr('opt.asnRiskFilter');
  document.getElementById('lbl-enable-4688').textContent = tr('opt.enable4688');
  document.getElementById('opt-proc-watchlist').placeholder = tr('opt.procWatchlist');
  document.getElementById('lbl-enable-sysmon-proc').textContent = tr('opt.enableSysmonProc');
  document.getElementById('opt-sysmon-proc-watchlist').placeholder = tr('opt.sysmonProcWatchlist');
  document.getElementById('lbl-enable-sysmon-thread').textContent = tr('opt.enableSysmonThread');
  document.getElementById('opt-sysmon-thread-watchlist').placeholder = tr('opt.sysmonThreadWatchlist');
  document.getElementById('lbl-enable-ps-scriptblock').textContent = tr('opt.enablePsScriptBlock');
  document.getElementById('opt-ps-scriptblock-watchlist').placeholder = tr('opt.psScriptBlockWatchlist');
  document.getElementById('lbl-enable-sysmon-imageload').textContent = tr('opt.enableSysmonImageLoad');
  document.getElementById('opt-sysmon-imageload-watchlist').placeholder = tr('opt.sysmonImageLoadWatchlist');
  document.getElementById('lbl-enable-ps-modulelog').textContent = tr('opt.enablePsModuleLog');
  document.getElementById('opt-ps-modulelog-watchlist').placeholder = tr('opt.psModuleLogWatchlist');
  document.getElementById('lbl-enable-offhours').textContent = tr('opt.enableOffHours');
  document.getElementById('lbl-work-time').textContent = tr('opt.workTime');
  document.getElementById('lbl-work-days').textContent = tr('opt.workDays');
  document.getElementById('lbl-tz-offset').textContent = tr('opt.tzOffset');
  document.getElementById('opt-tz-offset').placeholder = tr('opt.tzOffsetPh');
  document.getElementById('lbl-holidays').textContent = tr('opt.holidays');
  document.getElementById('lbl-lateral-exclude').textContent = tr('opt.lateral_exclude');
  document.getElementById('opt-lateral-exclude').placeholder = tr('opt.lateral_exclude_ph');
  document.getElementById('lbl-lateral-types').textContent = tr('opt.lateral_types');
  document.getElementById('opt-lateral-types').placeholder = '3,10';
  document.getElementById('t-hostgraph-title').textContent = tr('hostgraph.title');
  document.getElementById('t-hostgraph-hint').textContent = tr('hostgraph.hint');
  ['svchealth-title', 'svchealth-hint', 'svchealth-cmds', 'svchealth-cmds-hint', 'companion-title', 'companion-hint', 'companion-all'].forEach(k => {
    document.getElementById('t-' + k).textContent = tr(k.replace('svchealth-', 'svch.').replace('companion-', 'companion.').replace('-hint', '_hint').replace('cmds_hint', 'cmds_hint'));
  });
  document.getElementById('btn-hostgraph-csv').textContent = tr('hostgraph.csv');
  document.getElementById('btn-hostgraph-mermaid').textContent = tr('hostgraph.mermaid');
  document.getElementById('btn-hostgraph-drawio').textContent = tr('hostgraph.drawio');
  document.getElementById('opt-holidays').placeholder = 'YYYY-MM-DD, …';
  document.getElementById('lbl-optional-cols').textContent = tr('results.optional_cols');
  document.getElementById('lbl-col-src').textContent = tr('results.col_src');
  document.getElementById('lbl-col-dst').textContent = tr('results.col_dst');
  document.getElementById('lbl-col-port').textContent = tr('results.col_port');
  document.getElementById('lbl-col-proto').textContent = tr('results.col_proto');
  document.getElementById('lbl-col-url').textContent = tr('results.col_url');
  document.getElementById('results-search').placeholder = tr('results.search_placeholder');
  document.getElementById('issues-search').placeholder = tr('issues.search_placeholder');
  document.getElementById('t-results-title').textContent = tr('results.title');
  document.getElementById('t-topn-title').textContent = tr('topn.title');
  document.getElementById('t-issues-title').textContent = tr('issues.title');
  document.getElementById('t-correlation-title').textContent = tr('chain.title');
  document.getElementById('t-actor-title').textContent = tr('actor.title');
  document.getElementById('actor-input').placeholder = tr('actor.placeholder');
  document.getElementById('btn-actor-show').textContent = tr('actor.show_btn');
  document.getElementById('btn-actor-export-md').textContent = tr('issues.export_md_btn');
  document.getElementById('btn-actor-export-csv').textContent = tr('actor.export_csv_btn');
  document.getElementById('lbl-filter-preset').textContent = tr('preset.label');
  document.getElementById('lbl-issues-status-filter').textContent = tr('status.filter_label');
  const statusOpts = document.querySelectorAll('#issues-status-filter option');
  ['status.filter_all', 'status.filter_open', 'status.filter_confirmed', 'status.filter_fp', 'status.filter_hide_fp'].forEach((k, i) => { statusOpts[i].textContent = tr(k); });
  document.getElementById('btn-filter-preset-save').textContent = tr('preset.save_btn');
  document.getElementById('btn-filter-preset-delete').textContent = tr('preset.delete_btn');
  renderFilterPresetSelect();
  document.getElementById('t-intel-title').textContent = tr('intel.title');
  document.getElementById('t-intel-hint').textContent = tr('intel.hint');
  document.getElementById('t-intel-builder').textContent = tr('intel.builder_link');
  document.getElementById('intel-name-input').placeholder = tr('intel.name_placeholder');
  document.getElementById('intel-date-input').placeholder = tr('intel.date_placeholder');
  document.getElementById('btn-intel-add').textContent = tr('intel.add_btn');
  document.getElementById('t-hashintel-title').textContent = tr('hashintel.title');
  document.getElementById('t-hashintel-hint').textContent = tr('hashintel.hint');
  document.getElementById('hashintel-name-input').placeholder = tr('hashintel.name_placeholder');
  document.getElementById('hashintel-date-input').placeholder = tr('hashintel.date_placeholder');
  document.getElementById('btn-hashintel-add').textContent = tr('hashintel.add_btn');
  document.getElementById('t-safelist-title').textContent = tr('safelist.title');
  document.getElementById('t-safelist-hint').textContent = tr('safelist.hint');
  document.getElementById('safelist-name-input').placeholder = tr('safelist.name_placeholder');
  document.getElementById('btn-safelist-add').textContent = tr('safelist.add_btn');
  document.getElementById('btn-safelist-template').textContent = tr('safelist.template_btn');
  document.getElementById('t-geo-title').textContent = tr('geo.title');
  document.getElementById('t-geo-hint').textContent = tr('geo.hint');
  document.getElementById('geo-name-input').placeholder = tr('geo.name_placeholder');
  document.getElementById('btn-geo-add').textContent = tr('geo.add_btn');
  document.getElementById('t-asn-title').textContent = tr('asn.title');
  document.getElementById('t-asn-hint').textContent = tr('asn.hint');
  document.getElementById('asn-name-input').placeholder = tr('asn.name_placeholder');
  document.getElementById('btn-asn-add').textContent = tr('asn.add_btn');
  document.getElementById('t-asn-risk-import-title').textContent = tr('asn.risk_import_title');
  document.getElementById('t-asn-risk-import-hint').textContent = tr('asn.risk_import_hint');
  document.getElementById('t-asn-hosting-title').textContent = tr('asn.hosting_title');
  document.getElementById('t-asn-hosting-hint').textContent = tr('asn.hosting_hint');
  document.getElementById('btn-asn-hosting-add').textContent = tr('asn.hosting_add');
  document.getElementById('t-anonvpn-title').textContent = tr('anonvpn.title');
  document.getElementById('t-anonvpn-hint').textContent = tr('anonvpn.hint');
  document.getElementById('btn-anonvpn-add').textContent = tr('anonvpn.add');
  renderAnonVpnList();
  document.getElementById('t-rmm-title').textContent = tr('rmm.title');
  document.getElementById('t-rmm-hint').textContent = tr('rmm.hint');
  document.getElementById('btn-rmm-add').textContent = tr('rmm.add');
  document.getElementById('lbl-rmm-allow').textContent = tr('rmm.allow');
  document.getElementById('opt-rmm-allow').placeholder = tr('rmm.allow_ph');
  renderRmmList();
  renderAsnHostingList();
  document.getElementById('btn-asn-risk-add').textContent = tr('asn.risk_import_add_btn');
  document.getElementById('t-customrules-title').textContent = tr('customrule.title');
  document.getElementById('t-customrules-hint').textContent = tr('customrule.hint');
  document.getElementById('btn-customrule-add').textContent = tr('customrule.add_btn');
  document.getElementById('btn-customrule-export').textContent = tr('customrule.export_btn');
  document.getElementById('btn-sigma-export').textContent = tr('sigma.export_btn');
  document.getElementById('btn-customrule-import').textContent = tr('customrule.import_btn');
  document.getElementById('btn-sigma-import').textContent = tr('sigma.import_btn');
  renderCustomRules();
  document.getElementById('t-guide-title').textContent = tr('guide.title');
  document.getElementById('guide-body').textContent = tr('guide.body');
  document.getElementById('t-guide-builder').textContent = tr('intel.builder_link');
  document.getElementById('t-deid-title').textContent = tr('deid.title');
  document.getElementById('t-deid-hint').textContent = tr('deid.hint');
  document.getElementById('t-deid-preserve-last-octet').textContent = tr('deid.preserve_last_octet');
  document.getElementById('t-deid-preserve-subnet').textContent = tr('deid.preserve_subnet');
  document.getElementById('t-deid-preserve-subnet-wrap').title = tr('deid.preserve_subnet_hint');
  document.getElementById('btn-deid-run').textContent = tr('deid.run_btn');
  document.getElementById('btn-deid-download').textContent = tr('deid.download_btn');
  document.getElementById('btn-import-map').textContent = tr('btn.import_map');
  document.getElementById('btn-import-map').title = tr('tip.import_mapping');
  document.getElementById('btn-export-map').textContent = tr('btn.export_map');
  document.getElementById('btn-export-map').title = tr('tip.export_map');
  document.getElementById('t-hint-cross-tool-mapping').textContent = tr('hint.crossToolMapping');
  document.getElementById('btn-export-csv').textContent = tr('export.csv_btn');
  document.getElementById('btn-export-events-csv').textContent = tr('results.export_csv_btn');
  document.getElementById('btn-fw-batch').textContent = tr('fwq.batch_btn');
  document.getElementById('btn-fw-batch').title = tr('fwq.batch_tip');
  document.getElementById('l-btn-mitre-layer').textContent = tr('btn.mitre_layer');
  document.getElementById('l-btn-export-ioc').textContent = tr('issues.export_ioc_btn');
  document.getElementById('l-btn-export-stix').textContent = tr('ioc.export_stix_btn');
  ['case-title', 'case-hint'].forEach(k => { document.getElementById('t-' + k).textContent = tr(k.replace('-', '.')); });
  ['case-name', 'case-issues', 'case-actors', 'case-summary', 'case-deid'].forEach(k => { document.getElementById('lbl-' + k).textContent = tr('case.lbl_' + k.slice(5)); });
  document.getElementById('case-actors').placeholder = tr('case.actors_ph');
  document.getElementById('btn-case-export').textContent = tr('case.export_btn');
  document.getElementById('l-btn-export-misp').textContent = tr('ioc.export_misp_btn');
  document.getElementById('l-btn-export-md').textContent = tr('issues.export_md_btn');
  document.getElementById('btn-html-report').textContent = tr('btn.html_report');
  document.getElementById('l-btn-print-report').textContent = tr('btn.print_full_report');
  document.getElementById('t-export-menu').textContent = tr('export.menu');
  ['pdf', 'md', 'ioc', 'stix', 'misp', 'mitre'].forEach(k => { document.getElementById('d-export-' + k).textContent = tr('export.d_' + k); });
  document.getElementById('footer-note').textContent = tr('footer.note');
  window.renderToolkitVersion&&renderToolkitVersion(currentLang);
  window.FileHowto&&FileHowto.render(currentLang);
  renderHealthStatic();
  renderBaselineStatic();
}

// 可選顯示欄位（來源/目的 IP、Port、通訊協定）僅 CEF/JSON 有結構化欄位可用；Syslog 走 key=value
// best-effort 擷取，抓不到一律顯示 "-"（自由文字內容仍可從「內容」欄位自行判讀，不強行臆測）
const SORTABLE_COLS = ['severity', 'time', 'host', 'format', 'category'];
let SORT_COL = 'severity', SORT_DIR = 'asc';
let ISSUES_SOURCE_FILTER = '';
// 問題清單抑制/調校清單（2026-09-15 新增）：使用者手動標記為「已知雜訊」不再顯示的分類；
// 純渲染層過濾（filterIssuesBySuppressed() 已搬到 [1] 區塊，不依賴 document），與
// ISSUES_SOURCE_FILTER 同一分工——buildIssueList() 本身不受影響，僅影響畫面呈現，
// 故意不套用到 CSV/HTML 報表匯出（與 ISSUES_SOURCE_FILTER 既有慣例一致）
let SUPPRESSED_CATEGORIES = new Set();
// 問題項目分析師備註（2026-09-16 新增）：{[_baselineDiffKey(is)]: noteText}，鍵沿用既有
// _baselineDiffKey()（分類層級粒度，見該函式定義處說明），與 SUPPRESSED_CATEGORIES 同一粒度——
// ISSUES 每次分析都整批重建，沒有比分類更細的跨執行穩定識別鍵，備註本質上等同「這整個分類的
// 既有註記」
let issueNotes = {};
// 問題處理狀態（2026-09-24 新增）：{[_baselineDiffKey(is)]: 'confirmed'|'falsePositive'}，
// 鍵與粒度完全比照 issueNotes（分類層級）；未設定即視為 'open'（未處理），不存進物件
let issueStatus = {};
const ISSUE_STATUS_VALUES = ['open', 'confirmed', 'falsePositive'];
function issueStatusOf(key) { return issueStatus[key] || 'open'; }
function issueStatusLabel(key) { return tr('status.' + issueStatusOf(key)); }
function onIssueStatusChange(key, val) {
  if (val === 'open' || !ISSUE_STATUS_VALUES.includes(val)) delete issueStatus[key]; else issueStatus[key] = val;
  saveSettings();
  renderIssues();
}
// 篩選條件預設集 UI（2026-09-24 新增）：清單存在既有 saveSettings() 的 'filter-presets' 特例欄位
let FILTER_PRESETS = [];
function renderFilterPresetSelect() {
  const sel = document.getElementById('filter-preset-select');
  const cur = sel.value;
  sel.innerHTML = '';
  const o0 = document.createElement('option'); o0.value = ''; o0.textContent = tr('preset.choose'); sel.appendChild(o0);
  FILTER_PRESETS.forEach(p => { const o = document.createElement('option'); o.value = p.name; o.textContent = p.name; sel.appendChild(o); });
  sel.value = FILTER_PRESETS.some(p => p.name === cur) ? cur : '';
  document.getElementById('btn-filter-preset-delete').disabled = !sel.value;
}
function saveCurrentFilterPreset() {
  const sel = document.getElementById('filter-preset-select');
  const name = prompt(tr('preset.name_prompt'), sel.value || '');
  if (name === null || !name.trim()) return;
  FILTER_PRESETS = upsertFilterPreset(FILTER_PRESETS, {
    name,
    resultsSearch: document.getElementById('results-search').value,
    issuesSearch: document.getElementById('issues-search').value,
    issuesSource: ISSUES_SOURCE_FILTER,
    issuesStatus: document.getElementById('issues-status-filter').value,
    suppressed: Array.from(SUPPRESSED_CATEGORIES),
  });
  saveSettings();
  sel.value = name.trim();
  renderFilterPresetSelect();
}
function applyFilterPreset(name) {
  const p = FILTER_PRESETS.find(x => x.name === name);
  document.getElementById('btn-filter-preset-delete').disabled = !p;
  if (!p) return;
  document.getElementById('results-search').value = p.resultsSearch || '';
  document.getElementById('issues-search').value = p.issuesSearch || '';
  ISSUES_SOURCE_FILTER = p.issuesSource || '';
  document.getElementById('issues-status-filter').value = p.issuesStatus || '';
  SUPPRESSED_CATEGORIES = new Set(p.suppressed || []);
  saveSettings();
  renderResults();
  renderIssues();
}
function deleteFilterPreset() {
  const sel = document.getElementById('filter-preset-select');
  if (!sel.value) return;
  FILTER_PRESETS = FILTER_PRESETS.filter(p => p.name !== sel.value);
  sel.value = '';
  saveSettings();
  renderFilterPresetSelect();
}
function onIssueNoteClick(key) {
  const next = prompt(tr('issues.note_prompt'), issueNotes[key] || '');
  if (next === null) return; // 使用者取消
  if (next.trim()) issueNotes[key] = next.trim(); else delete issueNotes[key];
  saveSettings();
  renderIssues();
}
// 時間軸點擊/拖曳篩選：{start,end} 毫秒時間戳範圍，或 null 表示未篩選。單擊一個 bucket 或
// 拖曳橫跨多個 bucket 皆呼叫同一個 selectTimelineRange()；再次選取與目前完全相同的範圍視為
// 取消篩選（切換式，不需要額外「清除」按鈕也能操作，但仍保留可點擊的狀態文字供明確清除與
// 可見性）。純函式 filterEventsByTimeRange()/xToBucketIndex() 已搬到上方 [1] 區塊（不依賴
// document，供測試沙箱抽取），這裡只留狀態變數與依賴 DOM 的 UI 綁定函式
let TIMELINE_RANGE_FILTER = null;
function clearTimelineRangeFilter() {
  if (!TIMELINE_RANGE_FILTER) return;
  TIMELINE_RANGE_FILTER = null;
  renderTimeline();
  renderResults();
}
function selectTimelineRange(start, end) {
  const same = TIMELINE_RANGE_FILTER && TIMELINE_RANGE_FILTER.start === start && TIMELINE_RANGE_FILTER.end === end;
  TIMELINE_RANGE_FILTER = same ? null : { start, end };
  renderTimeline();
  renderResults();
}
// 拖曳框選（brush-to-zoom，2026-09-15 新增）：#timeline-chart 上 mousedown 記錄起點與目前
// renderTimeline() 算好的 bucket 中繼資料（_TL_DRAG_META，每次 renderTimeline() 重新賦值），
// mousemove 更新覆蓋層視覺回饋，拖曳距離小於門檻視為一般點擊——不主動呼叫 selectTimelineRange()，
// 讓瀏覽器原生 click 事件落在被點擊的那個 bucket <g onclick> 上自然觸發既有單擊行為，避免
// 「拖曳沒超過門檻」與「原生 click」重複觸發兩次
let _TL_DRAG_META = null;
let _TL_DRAG_STATE = null;
const TL_DRAG_THRESHOLD_PX = 5;
function _tlChartXFromEvent(e, chartEl) {
  const rect = chartEl.getBoundingClientRect();
  const px = Math.max(0, Math.min(rect.width, e.clientX - rect.left));
  return (px / rect.width) * 1000;
}
function _onTimelineMouseDown(e) {
  if (!_TL_DRAG_META || e.button !== 0) return;
  const chart = document.getElementById('timeline-chart');
  _TL_DRAG_STATE = { startClientX: e.clientX, startViewBoxX: _tlChartXFromEvent(e, chart), dragging: false };
  e.preventDefault();
}
function _onTimelineMouseMove(e) {
  if (!_TL_DRAG_STATE) return;
  if (!_TL_DRAG_STATE.dragging && Math.abs(e.clientX - _TL_DRAG_STATE.startClientX) < TL_DRAG_THRESHOLD_PX) return;
  _TL_DRAG_STATE.dragging = true;
  const chart = document.getElementById('timeline-chart');
  const rect = chart.getBoundingClientRect();
  const curViewBoxX = _tlChartXFromEvent(e, chart);
  const x0 = Math.min(_TL_DRAG_STATE.startViewBoxX, curViewBoxX) / 1000 * rect.width;
  const x1 = Math.max(_TL_DRAG_STATE.startViewBoxX, curViewBoxX) / 1000 * rect.width;
  let overlay = document.getElementById('timeline-drag-overlay');
  if (!overlay) { overlay = document.createElement('div'); overlay.id = 'timeline-drag-overlay'; chart.appendChild(overlay); }
  overlay.style.left = x0 + 'px';
  overlay.style.width = (x1 - x0) + 'px';
  overlay.style.display = '';
}
function _onTimelineMouseUp(e) {
  if (!_TL_DRAG_STATE) return;
  const state = _TL_DRAG_STATE;
  _TL_DRAG_STATE = null;
  const overlay = document.getElementById('timeline-drag-overlay');
  if (overlay) overlay.style.display = 'none';
  if (!state.dragging || !_TL_DRAG_META) return;
  const chart = document.getElementById('timeline-chart');
  const endViewBoxX = _tlChartXFromEvent(e, chart);
  const { n, startTime, bucketMs } = _TL_DRAG_META;
  const i0 = xToBucketIndex(Math.min(state.startViewBoxX, endViewBoxX), n);
  const i1 = xToBucketIndex(Math.max(state.startViewBoxX, endViewBoxX), n);
  selectTimelineRange(startTime + i0 * bucketMs, startTime + (i1 + 1) * bucketMs);
}
document.addEventListener('mousemove', _onTimelineMouseMove);
document.addEventListener('mouseup', _onTimelineMouseUp);
// 地理位置風險標記勾選清單：比對的是 log 原始 GeoIP 欄位字串本身（純英文，非 UI 顯示語意
// 文字），不逐語言翻譯。這份是「未匯入 GeoIP 資料庫」時的預設清單，每個真實國家一筆、內含
// aliases（同一國家的多種寫法+ISO 兩碼）；顯示用的 label 不再寫死，改由 resolveCountryInfo()
// 依 id 動態解析（見 renderGeoRiskChecks()），避免兩份資料各自維護走鐘。risk:true 為長期穩定
// 的高風險/制裁國家分類（非隨時事變動的「戰爭中國家」判斷）；一般國家也補上 ISO 別名，避免
// 「風險國家能查、一般國家不能查」的不一致
const GEO_COUNTRY_GROUPS = [
  { id: 'kp', risk: true, aliases: ['North Korea', "Korea, Democratic People's Republic of", 'KP'] },
  { id: 'ru', risk: true, aliases: ['Russia', 'Russian Federation', 'RU'] },
  { id: 'ir', risk: true, aliases: ['Iran', 'Iran, Islamic Republic of', 'IR'] },
  { id: 'sy', risk: true, aliases: ['Syria', 'Syrian Arab Republic', 'SY'] },
  { id: 'by', risk: false, aliases: ['Belarus', 'BY'] },
  { id: 'cu', risk: false, aliases: ['Cuba', 'CU'] },
  { id: 've', risk: false, aliases: ['Venezuela', 'VE'] },
  { id: 'mm', risk: false, aliases: ['Myanmar', 'MM'] },
  { id: 'af', risk: false, aliases: ['Afghanistan', 'AF'] },
  { id: 'iq', risk: false, aliases: ['Iraq', 'IQ'] },
  { id: 'ye', risk: false, aliases: ['Yemen', 'YE'] },
  { id: 'sd', risk: false, aliases: ['Sudan', 'SD'] },
  { id: 'cn', risk: false, aliases: ['China', 'CN'] },
  { id: 'vn', risk: false, aliases: ['Vietnam', 'VN'] },
  { id: 'pk', risk: false, aliases: ['Pakistan', 'PK'] },
  { id: 'in', risk: false, aliases: ['India', 'IN'] },
  { id: 'ng', risk: false, aliases: ['Nigeria', 'NG'] },
  { id: 'br', risk: false, aliases: ['Brazil', 'BR'] },
  { id: 'us', risk: false, aliases: ['United States', 'US'] },
  { id: 'gb', risk: false, aliases: ['United Kingdom', 'GB'] },
  { id: 'de', risk: false, aliases: ['Germany', 'DE'] },
  { id: 'fr', risk: false, aliases: ['France', 'FR'] },
  { id: 'jp', risk: false, aliases: ['Japan', 'JP'] },
  { id: 'tw', risk: false, aliases: ['Taiwan', 'TW'] },
  { id: 'sg', risk: false, aliases: ['Singapore', 'SG'] },
  { id: 'au', risk: false, aliases: ['Australia', 'AU'] }
];
// 已匯入 GeoIP 資料庫時，比對用的 riskCountries 應該直接是該資料庫實際出現過的字串（見
// GEO_LISTS[].index.countries，buildIntelIndex() 附帶收集），而非猜測的別名——避免「CSV 用
// 自己的寫法、跟預設別名對不上導致永遠比對不到」的問題。isKnownRiskCountry() 只用來決定
// 這些實際字串裡哪些該預設打勾，大小寫不敏感比對 GEO_COUNTRY_GROUPS 的風險別名聯集
const GEO_RISK_ALIAS_SET = new Set(GEO_COUNTRY_GROUPS.filter(g => g.risk).flatMap(g => g.aliases).map(s => s.toLowerCase()));
function isKnownRiskCountry(str) { return GEO_RISK_ALIAS_SET.has(String(str).trim().toLowerCase()); }
function getImportedGeoCountries() {
  const set = new Set();
  GEO_LISTS.forEach(l => (l.index.countries || []).forEach(c => { if (c) set.add(c); }));
  return Array.from(set).sort();
}
// 雙模式渲染：未匯入 GeoIP 資料庫時用預設 26 國分組清單（checkbox value 為 group id，讀取
// 時展開 aliases）；已匯入時改用該資料庫實際涵蓋的國家字串（checkbox value 就是原始字串，
// 不需展開）。重繪前先讀出目前已勾選的值，重繪後對新清單裡仍存在的值還原勾選，避免每次
// 匯入/移除清單都把使用者已調整過的勾選整組重置
// 分組順序固定：高風險獨立一組排最前，其餘依洲別（亞/歐/非/北美/南美/大洋洲/其他）；純
// UI 排列依據，不影響 getRiskCountries() 的比對邏輯
const GEO_CONTINENT_ORDER = ['asia', 'europe', 'africa', 'namerica', 'samerica', 'oceania', 'other'];
function renderGeoRiskChecks() {
  const box = document.getElementById('geo-risk-checks');
  const prevMode = box.dataset.mode;
  const imported = getImportedGeoCountries();
  const usingImported = imported.length > 0;
  const newMode = usingImported ? 'imported' : 'default';
  // 「保留使用者已調整過的勾選」只在同一種模式下才有意義（value 命名空間相同：預設模式是
  // group id、匯入模式是原始國家字串）；模式切換當下（例如剛匯入、或移除到 0 筆）舊的勾選
  // 值屬於另一套命名空間，不該拿來比對，一律改用該筆項目自己的 risk 旗標決定預設勾選
  const prevChecked = prevMode === newMode
    ? new Set(Array.from(box.querySelectorAll('input:checked')).map(el => el.value))
    : null;
  // label 不再寫死，統一透過 resolveCountryInfo() 動態解析成「名稱 (代碼)」，未匯入/已匯入
  // 兩種模式共用同一份對照表，確保呈現一致
  const items = usingImported
    ? imported.map(c => {
        const info = resolveCountryInfo(c);
        return { value: c, label: `${info.name}${info.code ? ' (' + info.code + ')' : ''}`, risk: isKnownRiskCountry(c), continent: info.continent };
      })
    : GEO_COUNTRY_GROUPS.map(g => {
        const info = resolveCountryInfo(g.id);
        return { value: g.id, label: `${info.name} (${info.code || g.id.toUpperCase()})`, risk: g.risk, continent: info.continent };
      });
  box.dataset.mode = newMode;
  const groups = [{ key: 'risk', title: tr('geo.riskGroupLabel'), items: items.filter(it => it.risk) }];
  GEO_CONTINENT_ORDER.forEach(c => groups.push({ key: c, title: tr('geo.continent.' + c), items: items.filter(it => !it.risk && it.continent === c) }));
  box.innerHTML = groups.filter(g => g.items.length).map(g => {
    const rows = g.items.map(it => {
      const checked = prevChecked ? prevChecked.has(it.value) : it.risk;
      return `<label class="geo-risk-item"><input type="checkbox" class="geo-risk-check" value="${esc(it.value)}"${checked ? ' checked' : ''}> ${esc(it.label)}</label>`;
    }).join('');
    return `<div class="geo-risk-group" data-group="${g.key}"><div class="geo-risk-group-title">${esc(g.title)}</div><div class="geo-risk-group-items">${rows}</div></div>`;
  }).join('');
  filterGeoRiskChecks(document.getElementById('geo-risk-filter').value);
}
// 篩選需連帶處理群組：某群組內所有項目都被篩掉時，該群組（含標題）也要一併隱藏，避免篩選
// 結果出現一堆空標題
function filterGeoRiskChecks(q) {
  const needle = String(q || '').trim().toLowerCase();
  document.querySelectorAll('#geo-risk-checks .geo-risk-group').forEach(group => {
    let anyVisible = false;
    group.querySelectorAll('.geo-risk-item').forEach(label => {
      const hit = !needle || label.textContent.toLowerCase().includes(needle);
      label.style.display = hit ? '' : 'none';
      if (hit) anyVisible = true;
    });
    group.style.display = anyVisible ? '' : 'none';
  });
}
// riskCountries 讀取：未匯入模式下 checkbox value 是 group id，需展開成該 group 的 aliases；
// 已匯入模式下 checkbox value 本身就是要比對的字串，直接回傳即可
function getRiskCountries() {
  const box = document.getElementById('geo-risk-checks');
  const checkedValues = Array.from(box.querySelectorAll('input:checked')).map(el => el.value);
  if (box.dataset.mode === 'imported') return checkedValues;
  const idSet = new Set(checkedValues);
  return GEO_COUNTRY_GROUPS.filter(g => idSet.has(g.id)).flatMap(g => g.aliases);
}
function renderTimeline() {
  document.getElementById('lbl-timeline').textContent = tr('results.timeline_label');
  const statusEl = document.getElementById('timeline-filter-status');
  const chart = document.getElementById('timeline-chart');
  const { buckets, startTime, endTime, bucketMs, untimed } = buildTimelineBuckets(EVENTS);
  if (untimed) document.getElementById('lbl-timeline').textContent += ' · ' + tr('timeline.untimed').replace('{n}', untimed);
  if (!buckets.length) { chart.innerHTML = `<div class="empty">${tr('results.empty')}</div>`; statusEl.style.display = 'none'; document.getElementById('timeline-chain-hint').style.display = 'none'; _TL_DRAG_META = null; return; }
  chart.innerHTML = buildTimelineSVG(buckets, startTime, endTime, bucketMs, TIMELINE_RANGE_FILTER, CHAINS);
  const chainHint = document.getElementById('timeline-chain-hint');
  chainHint.textContent = tr('timeline.chain_hint');
  chainHint.style.display = chart.querySelector('.tl-chain') ? '' : 'none';
  _TL_DRAG_META = { n: buckets.length, startTime, bucketMs };
  if (TIMELINE_RANGE_FILTER) {
    statusEl.textContent = `🔍 ${tlFmtTime(TIMELINE_RANGE_FILTER.start)} ~ ${tlFmtTime(TIMELINE_RANGE_FILTER.end)} ✕`;
    statusEl.style.display = '';
  } else {
    statusEl.style.display = 'none';
  }
}
// 無法解析 log 回報提示列（2026-09-29 新增，RC）：只把無法解析的行（最多 200 行）帶到
// config_anonymizer 的回報流程（通用模式去識別化、差異檢視、殘留審閱後才能開啟 GitHub 回報頁），
// 沿用既有 `_netAnalyzer_pending` 交接 key，額外帶 report 中繼資料
function renderReportBar() {
  const bar = document.getElementById('report-bar');
  if (!bar) return;
  const trig = RAW_TEXT ? logReportTrigger(EVENTS.length, UNPARSED_LINES.length) : '';
  if (!trig) { bar.style.display = 'none'; bar.innerHTML = ''; return; }
  const total = EVENTS.length + UNPARSED_LINES.length;
  const msg = tr('report.bar_' + trig).replace('{n}', UNPARSED_LINES.length).replace('{pct}', Math.round(UNPARSED_LINES.length / total * 100));
  bar.innerHTML = `⚠ ${esc(msg)} <button class="btn" style="margin-left:8px" onclick="sendLogReportToAnonymizer()">📮 ${esc(tr('report.bar_btn'))}</button>`;
  bar.style.display = '';
}
function sendLogReportToAnonymizer() {
  const sample = buildLogReportSample(UNPARSED_LINES);
  if (!sample) return;
  let wrote = false;
  try {
    localStorage.setItem('_netAnalyzer_pending', JSON.stringify({
      name: 'unparsed-log.txt', text: sample, ts: Date.now(), vendor: null,
      report: { tool: 'log_analyzer', trigger: logReportTrigger(EVENTS.length, UNPARSED_LINES.length) || 'manual', vendor: 'unknown',
        stats: { events: EVENTS.length, unparsed: UNPARSED_LINES.length } }
    }));
    wrote = true;
  } catch (e) { alert(tr('err.storage_full')); return; }
  // 寫入失敗已在上面提示並結束；這裡只有 window.open 回傳 null 才是彈出視窗被攔截
  const w = window.open('config-anonymizer.html', '_blank');
  if (wrote && !w) { localStorage.removeItem('_netAnalyzer_pending'); alert(tr('err.popup_blocked')); }
}
// 目前事件清單顯示上限：搜尋／排序／篩選／重新分析時重設為一頁，只有「再顯示」按鈕會保留並增加
let RESULTS_LIMIT = RESULTS_PAGE_SIZE;
function showMoreResults() {
  RESULTS_LIMIT += RESULTS_PAGE_SIZE;
  renderResults(true);
}
// keepLimit 必須嚴格等於 true：本函式也直接當事件處理器使用，會收到事件物件
// 事件清單訊息欄開頭的「到防火牆查詢」小按鈕（來源／目的欄預設隱藏，故放在一定顯示的訊息欄）；條件以 JSON.stringify()＋跳脫雙引號塞進 onclick（本專案既有慣例）
function fwqBtn(tuple, e) {
  const q = buildFwQueryPayload(tuple);
  if (!q) return '';
  // EdgeRouter／VyOS log 前綴帶規則集與編號時一併送出，防火牆端標出設定中對應的規則（第十六輪 PC）
  const rs = e && e.fields && e.fields.ruleset, rn = e && e.fields && e.fields.rulenum;
  if (rs && rn && /^[\w.-]+$/.test(rs) && /^(?:\d+|default)$/.test(rn)) q.rule = rs + '/' + rn;
  const arg = esc(JSON.stringify(q));
  return `<button class="fwq-btn" onclick="sendToFirewallQuery(${arg})" title="${esc(tr('fwq.btn_tip'))}" aria-label="${esc(tr('fwq.btn_tip'))}">🛡</button> `;
}
function renderResults(keepLimit) {
  if (keepLimit !== true) RESULTS_LIMIT = RESULTS_PAGE_SIZE;
  renderReportBar();
  const thead = document.querySelector('#results-table thead');
  const tbody = document.querySelector('#results-table tbody');
  const showSrc = document.getElementById('col-src').checked;
  const showDst = document.getElementById('col-dst').checked;
  const showPort = document.getElementById('col-port').checked;
  const showProto = document.getElementById('col-proto').checked;
  const showUrl = document.getElementById('col-url').checked;
  // 多檔上傳真正分組（2026-09 新增）：SOURCE_FILE_BOUNDARIES 只在真正上傳 2 個以上檔案時才有
  // 值，來源檔案欄與篩選下拉自動出現/隱藏，不另外做使用者勾選開關（單檔/貼上文字情境下顯示
  // 這欄毫無意義，等同一直重複同一個檔名）
  const showFile = SOURCE_FILE_BOUNDARIES.length >= 2;
  const fileFilterSelect = document.getElementById('results-file-filter');
  if (showFile) {
    const names = getDistinctSourceFiles(EVENTS);
    const prevValue = fileFilterSelect.value;
    fileFilterSelect.innerHTML = `<option value="">${tr('results.filter_all_files')}</option>` + names.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
    fileFilterSelect.value = names.includes(RESULTS_FILE_FILTER) ? RESULTS_FILE_FILTER : '';
    if (fileFilterSelect.value !== prevValue) RESULTS_FILE_FILTER = fileFilterSelect.value;
    fileFilterSelect.style.display = '';
  } else {
    fileFilterSelect.style.display = 'none';
  }
  const extraCount = [showSrc, showDst, showPort, showProto, showUrl, showFile].filter(Boolean).length;
  const headExtra = (showSrc ? `<th>${tr('results.col_src')}</th>` : '')
    + (showDst ? `<th>${tr('results.col_dst')}</th>` : '')
    + (showPort ? `<th>${tr('results.col_port')}</th>` : '')
    + (showProto ? `<th>${tr('results.col_proto')}</th>` : '')
    + (showUrl ? `<th>${tr('results.col_url')}</th>` : '')
    + (showFile ? `<th>${tr('results.col_sourcefile')}</th>` : '');
  const sortLabel = k => {
    const arrow = SORT_COL === k ? (SORT_DIR === 'asc' ? ' ▲' : ' ▼') : '';
    return `<th class="sortable-col" data-col="${k}">${tr('results.col_' + k)}${arrow}</th>`;
  };
  thead.innerHTML = `<tr>${sortLabel('severity')}${sortLabel('time')}${sortLabel('host')}${sortLabel('format')}${sortLabel('category')}<th>${tr('results.col_notes')}</th>${headExtra}<th>${tr('results.col_msg')}</th></tr>`;
  thead.querySelectorAll('.sortable-col').forEach(th => th.onclick = () => {
    const col = th.dataset.col;
    if (SORT_COL === col) { SORT_DIR = SORT_DIR === 'asc' ? 'desc' : 'asc'; } else { SORT_COL = col; SORT_DIR = 'asc'; }
    renderResults();
  });
  const filtered = filterEventsBySourceFile(filterEventsByTimeRange(filterEvents(EVENTS, document.getElementById('results-search').value.trim()), TIMELINE_RANGE_FILTER), RESULTS_FILE_FILTER);
  const sorted = sortEventsByColumn(filtered, SORT_COL, SORT_DIR);
  if (!sorted.length) {
    // 已有事件但被搜尋／篩選濾光時，提示「沒有符合」而非「尚無資料」，避免誤以為資料不見
    tbody.innerHTML = `<tr><td colspan="${7 + extraCount}" class="empty">${tr(EVENTS.length ? 'results.no_match' : 'results.empty')}</td></tr>`;
  } else {
    const page = resultsPageInfo(sorted.length, RESULTS_LIMIT);
    tbody.innerHTML = sorted.slice(0, page.shown).map(e => {
      const notes = (e.notes || []).map(noteKeyForCategory).filter(Boolean);
      const notesHtml = notes.length
        ? notes.map(k => `<span class="note-badge">${esc(tr(k))}</span>`).join(' ')
        : '';
      const tuple = getEventNetTuple(e);
      const urlDisplay = [e.httpMethod, e.url].filter(Boolean).join(' ');
      const ef = e.fields || {};
      const extraCells = (showSrc ? `<td>${esc(ipWithName(tuple.src, ef.srcName, ef.srcUser))}</td>` : '')
        + (showDst ? `<td>${esc(ipWithName(tuple.dst, ef.dstName, ef.dstUser))}</td>` : '')
        + (showPort ? `<td>${esc(tuple.port)}</td>` : '')
        + (showProto ? `<td>${esc(tuple.proto)}</td>` : '')
        + (showUrl ? `<td>${esc(urlDisplay)}</td>` : '')
        + (showFile ? `<td>${esc(e.sourceFile || '-')}</td>` : '');
      return `<tr>
      <td><span class="badge ${sevClass(e.severityNorm)}">${tr(SEV_KEY_MAP[e.severityNorm])}</span></td>
      <td>${esc(fmtTime(e.timestamp))}</td><td>${esc(e.host)}</td><td>${esc(e.format)}</td>
      <td>${esc(tr(CAT_KEY_MAP[e.category] || 'cat.other'))}</td><td>${notesHtml}</td>${extraCells}<td>${fwqBtn(tuple, e)}${esc(eventDisplayMsg(e))}</td></tr>`;
    }).join('') + (page.remaining > 0
      ? `<tr class="results-more-row"><td colspan="${7 + extraCount}" class="empty">${esc(tr('results.showing').replace('{shown}', page.shown).replace('{total}', sorted.length))} <button class="btn" onclick="showMoreResults()">${esc(tr('results.show_more').replace('{n}', Math.min(RESULTS_PAGE_SIZE, page.remaining)))}</button></td></tr>`
      : '');
  }
  const sum = summarizeBySeverity(EVENTS);
  const box = document.getElementById('results-summary');
  box.innerHTML = tr('results.summary_label') + ' ' + Object.keys(SEV_KEY_MAP).map(k => `<span class="summary-chip"><span class="badge ${k}">${tr(SEV_KEY_MAP[k])}</span> ${sum[k]}</span>`).join('');
}

// 分類顯示標籤（freq: 前綴／CAT_KEY_MAP 查表）：renderIssues() 表格列與抑制清單面板共用
// 同一套標籤邏輯，避免兩處各自維護一份容易兜不起來
function issueCategoryLabel(category) {
  // 自訂規則類別（'custom:'+規則id）不查 CAT_KEY_MAP（會落到泛用「其他」，看不出是哪條規則），
  // 從 ISSUES 找回對應那筆的 customRuleName（使用者自訂文字，本身已是要顯示的字串，不需 i18n 查表）
  if (category.indexOf('custom:') === 0) {
    const found = ISSUES.find(is => is.category === category);
    return found && found.customRuleName ? found.customRuleName : category;
  }
  const baseCat = category.startsWith('freq:') ? category.slice(5) : category;
  return category.startsWith('freq:') ? tr('cat.freqLabel') + tr(CAT_KEY_MAP[baseCat] || 'cat.other') : tr(CAT_KEY_MAP[category] || 'cat.other');
}
// 問題清單抑制/調校清單面板：比照 renderGeoRiskChecks() 既有樣式（checkbox 清單反映目前
// 資料出現過的選項），選項來源刻意用「未套用抑制篩選前」的 ISSUES 全集，讓使用者仍能看到
// 已抑制的分類並隨時取消抑制，而非篩掉後就再也選不到
function renderIssuesSuppressPanel() {
  const row = document.getElementById('issues-suppress-row');
  const box = document.getElementById('issues-suppress-checks');
  document.getElementById('lbl-issues-suppress').textContent = tr('issues.suppress_label');
  const cats = Array.from(new Set(ISSUES.map(is => is.category))).sort();
  row.style.display = cats.length ? '' : 'none';
  box.innerHTML = cats.map(c => {
    const checked = SUPPRESSED_CATEGORIES.has(c);
    return `<label class="geo-risk-item"><input type="checkbox" class="issues-suppress-check" value="${esc(c)}"${checked ? ' checked' : ''}> ${esc(issueCategoryLabel(c))}</label>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════════
// 自訂偵測規則建構器 UI（2026-09-16 新增）：CRUD+匯出入比照 config_anonymizer 既有
// customRules 編輯器範本（addCustomRule()/removeCustomRule()/toggleCustomRule()/
// renderCustomRules()），欄位由 pattern/replacement 改為 name/severity/matchType/
// pattern/formatFilter。DOM 相依，不進 Node 測試沙箱，瀏覽器實機驗證。
// ══════════════════════════════════════════════════════════════════
let customDetectRules = [];
let _customRuleIdSeq = 0;
const CUSTOM_RULE_FORMATS = ['cef', 'leef', 'rfc5424', 'rfc3164', 'asa', 'ciscoios', 'comware', 'fortigate', 'mikrotik', 'weblog', 'w3c', 'json', 'winevent', 'flowlog', 'kvfw', 'pancsv', 'umbrella', 'dns', 'dhcp', 'ldap', 'radacct'];
function _isValidCustomRuleRegex(pattern) {
  try { new RegExp(pattern); return true; } catch (e) { return false; }
}
function addCustomDetectRule() {
  customDetectRules.push({ id: ++_customRuleIdSeq, name: '', enabled: true, severity: 'Medium', matchType: 'contains', pattern: '', formatFilter: '', stage: '' });
  renderCustomRules();
}
function removeCustomDetectRule(id) {
  const i = customDetectRules.findIndex(r => r.id === id);
  if (i >= 0) customDetectRules.splice(i, 1);
  renderCustomRules();
  saveSettings();
}
function toggleCustomDetectRule(id) {
  const r = customDetectRules.find(r => r.id === id);
  if (r) { r.enabled = !r.enabled; saveSettings(); }
}
function onCustomRuleField(id, field, value) {
  const r = customDetectRules.find(r => r.id === id);
  if (!r) return;
  r[field] = value;
  saveSettings();
  if (field === 'pattern' || field === 'matchType') renderCustomRules();
}
function renderCustomRules() {
  const wrap = document.getElementById('custom-rules-list');
  if (!wrap) return;
  if (!customDetectRules.length) { openOptionalSources(); wrap.innerHTML = ''; return; }
  openOptionalSources();
  wrap.innerHTML = customDetectRules.map(r => {
    if (r.matchType === 'sigma') {
      const sg = sigmaCompiled(r.pattern);
      return `<div class="rule-row">
      <div class="rule-row-head">
        <label class="rule-toggle"><input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleCustomDetectRule(${r.id})"><span class="slider"></span></label>
        <span class="rule-badge">#${r.id}</span><span class="rule-badge">Sigma</span>${sg.mitre ? `<span class="rule-badge">${esc(sg.mitre)}</span>` : ''}
        <button class="rule-del" onclick="removeCustomDetectRule(${r.id})" title="${esc(tr('customrule.delete_title'))}">✕</button>
      </div>
      <input class="rule-input" placeholder="${esc(tr('customrule.name_ph'))}" value="${esc(r.name)}" oninput="onCustomRuleField(${r.id},'name',this.value)">
      <select class="rule-select" onchange="onCustomRuleField(${r.id},'severity',this.value)">
        ${['Critical', 'High', 'Medium', 'Low', 'Info'].map(s => `<option value="${s}"${r.severity === s ? ' selected' : ''}>${esc(tr('sev.' + s.toLowerCase()))}</option>`).join('')}
      </select>
      <details><summary>${esc(tr('sigma.show_yaml'))}</summary><pre style="white-space:pre-wrap;font-size:11px;max-height:240px;overflow:auto">${esc(r.pattern)}</pre></details>
    </div>`;
    }
    const validRegex = r.matchType !== 'regex' || !r.pattern || _isValidCustomRuleRegex(r.pattern);
    return `<div class="rule-row">
      <div class="rule-row-head">
        <label class="rule-toggle"><input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleCustomDetectRule(${r.id})"><span class="slider"></span></label>
        <span class="rule-badge">#${r.id}</span>
        <button class="rule-del" onclick="removeCustomDetectRule(${r.id})" title="${esc(tr('customrule.delete_title'))}">✕</button>
        ${!validRegex ? `<span class="rule-badge err">${esc(tr('customrule.invalid_regex'))}</span>` : ''}
      </div>
      <input class="rule-input" placeholder="${esc(tr('customrule.name_ph'))}" value="${esc(r.name)}" oninput="onCustomRuleField(${r.id},'name',this.value)">
      <div class="rule-row-head">
        <select class="rule-select" onchange="onCustomRuleField(${r.id},'severity',this.value)">
          ${['Critical', 'High', 'Medium', 'Low', 'Info'].map(s => `<option value="${s}"${r.severity === s ? ' selected' : ''}>${esc(tr('sev.' + s.toLowerCase()))}</option>`).join('')}
        </select>
        <select class="rule-select" onchange="onCustomRuleField(${r.id},'matchType',this.value)">
          <option value="contains"${r.matchType === 'contains' ? ' selected' : ''}>${esc(tr('customrule.matchtype_contains'))}</option>
          <option value="regex"${r.matchType === 'regex' ? ' selected' : ''}>${esc(tr('customrule.matchtype_regex'))}</option>
        </select>
      </div>
      <input class="rule-input${validRegex ? '' : ' invalid'}" placeholder="${esc(tr('customrule.pattern_ph'))}" value="${esc(r.pattern)}" oninput="onCustomRuleField(${r.id},'pattern',this.value)">
      <select class="rule-select" onchange="onCustomRuleField(${r.id},'formatFilter',this.value)">
        <option value=""${r.formatFilter ? '' : ' selected'}>${esc(tr('customrule.format_any'))}</option>
        ${CUSTOM_RULE_FORMATS.map(f => `<option value="${f}"${r.formatFilter === f ? ' selected' : ''}>${f.toUpperCase()}</option>`).join('')}
      </select>
      <select class="rule-select" onchange="onCustomRuleField(${r.id},'stage',this.value)" data-tip="${esc(tr('customrule.stage_hint'))}">
        <option value=""${r.stage ? '' : ' selected'}>${esc(tr('customrule.stage_none'))}</option>
        ${CHAIN_STAGE_ORDER.map(s => `<option value="${s}"${r.stage === s ? ' selected' : ''}>${esc(tr('customrule.stage_' + s))}</option>`).join('')}
      </select>
    </div>`;
  }).join('');
}
function exportCustomDetectRules() {
  const obj = {
    sourceTool: 'log_analyzer', generatedAt: new Date().toISOString(),
    rules: customDetectRules.map(r => ({ name: r.name, enabled: r.enabled, severity: r.severity, matchType: r.matchType, pattern: r.pattern, formatFilter: r.formatFilter, stage: r.stage || '' })),
  };
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'log-analyzer-custom-rules.json'; a.click();
  URL.revokeObjectURL(url);
}
// 自訂規則匯出 Sigma（XN9）：customRulesToSigmaDoc() 在 STATE 邊界之前；結果顯示在 Sigma 匯入的同一行訊息
function exportCustomRulesSigma() {
  const box = document.getElementById('sigma-import-msg');
  const d = new Date();
  const date = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const res = customRulesToSigmaDoc(customDetectRules, date);
  const skippedText = res.skipped.length ? ' ' + tr('sigma.export_skipped').replace('{n}', res.skipped.length).replace('{list}', res.skipped.map(s => s.name || '-').join('、')) : '';
  if (!res.exported) { if (box) box.textContent = tr('sigma.export_none') + skippedText; return; }
  const blob = new Blob([res.text], { type: 'application/x-yaml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'log-analyzer-custom-rules.sigma.yml'; a.click();
  URL.revokeObjectURL(url);
  if (box) box.textContent = tr('sigma.exported').replace('{n}', res.exported) + skippedText;
}
// 自訂規則的欄位驗證：匯入檔案與還原設定（localStorage／工作區）共用同一份白名單，不合格回傳 null
function sanitizeCustomRule(r) {
  if (!r || typeof r.name !== 'string' || typeof r.pattern !== 'string') return null;
  return {
    id: ++_customRuleIdSeq, name: r.name, enabled: r.enabled !== false,
    severity: ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(r.severity) ? r.severity : 'Medium',
    matchType: r.matchType === 'regex' ? 'regex' : r.matchType === 'sigma' ? 'sigma' : 'contains',
    pattern: r.pattern, formatFilter: CUSTOM_RULE_FORMATS.includes(r.formatFilter) ? r.formatFilter : '',
    stage: CHAIN_STAGE_ORDER.includes(r.stage) ? r.stage : ''
  };
}
function importCustomDetectRulesFile(file) {
  const reader = new FileReader();
  reader.onerror = () => alert(tr('msg.file_read_error'));
  reader.onload = () => {
    let parsed;
    try { parsed = JSON.parse(reader.result); }
    catch (e) { alert(tr('customrule.import_invalid')); return; }
    const rules = Array.isArray(parsed.rules) ? parsed.rules : (Array.isArray(parsed) ? parsed : null);
    if (!rules) { alert(tr('customrule.import_invalid')); return; }
    let n = 0;
    rules.forEach(r => {
      const ok = sanitizeCustomRule(r);
      if (!ok) return;
      customDetectRules.push(ok);
      n++;
    });
    if (n === 0) { alert(tr('customrule.import_invalid')); return; }
    renderCustomRules();
    saveSettings();
    alert(tr('customrule.imported_msg').replace('{n}', n));
  };
  reader.readAsText(file, 'UTF-8');
}

// Sigma 規則匯入（第二十六輪 SD）：每個 .yml 一條規則，pattern 存原始 YAML（設定與匯出一併保存），名稱與嚴重度取自 title／level
function sigmaErrorText(r) {
  return tr('sigma.err_' + r.error).replace('{detail}', r.detail || '');
}
function importSigmaFiles(files) {
  const list = Array.from(files || []);
  if (!list.length) return;
  Promise.all(list.map(f => f.text().then(t => ({ name: f.name, text: t })))).then(items => {
    let n = 0;
    const fails = [];
    items.forEach(it => {
      const r = parseSigmaRule(it.text);
      if (r.error) { fails.push(it.name + '：' + sigmaErrorText(r)); return; }
      customDetectRules.push({ id: ++_customRuleIdSeq, name: r.title, enabled: true, severity: r.severity, matchType: 'sigma', pattern: it.text, formatFilter: '', stage: '' });
      n++;
    });
    renderCustomRules();
    saveSettings();
    const box = document.getElementById('sigma-import-msg');
    if (box) box.textContent = tr('sigma.imported').replace('{n}', n) + (fails.length ? ' ' + tr('sigma.failed').replace('{n}', fails.length) + ' ' + fails.join('；') : '');
  }).catch(() => alert(tr('msg.file_read_error')));
}

function renderIssues() {
  const thead = document.querySelector('#issues-table thead');
  const tbody = document.querySelector('#issues-table tbody');
  document.getElementById('lbl-issues-source-filter').textContent = tr('issues.source_filter_label');

  const sourceSelect = document.getElementById('issues-source-filter');
  const sources = getDistinctIntelSources(ISSUES);
  const filterRow = document.getElementById('issues-card').querySelector('.btn-row');
  filterRow.style.display = sources.length ? '' : 'none';
  const prevValue = sourceSelect.value;
  sourceSelect.innerHTML = `<option value="">${tr('issues.filter_all_sources')}</option>` + sources.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('');
  sourceSelect.value = sources.includes(ISSUES_SOURCE_FILTER) ? ISSUES_SOURCE_FILTER : '';
  if (sourceSelect.value !== prevValue) ISSUES_SOURCE_FILTER = sourceSelect.value;
  renderIssuesSuppressPanel();
  renderCasePicker();
  // UX31：折疊列摘要＝目前生效的篩選與抑制條件數；有條件時自動展開，避免使用者看不到為何問題變少
  const nActive = (ISSUES_SOURCE_FILTER ? 1 : 0) + (document.getElementById('issues-status-filter').value ? 1 : 0) + SUPPRESSED_CATEGORIES.size;
  document.getElementById('issues-filters-summary').textContent = tr('issues.filters_summary') + (nActive ? tr('issues.filters_active').replace('{n}', nActive) : '');
  if (nActive) document.getElementById('issues-filters').open = true;

  const statusMode = document.getElementById('issues-status-filter').value;
  const visible = filterIssuesByStatus(filterIssuesBySuppressed(filterIssuesBySource(ISSUES, ISSUES_SOURCE_FILTER), SUPPRESSED_CATEGORIES), is => issueStatusOf(_baselineDiffKey(is)), statusMode);
  // UX28：沒有任何問題帶情資來源時不顯示「情資來源」欄（未匯入情資時整欄都是 -）；
  // 每格帶 data-label，手機寬度以 CSS 改成一個問題一張卡片（#issues-table 的 @media 規則）
  const hasSource = visible.some(is => getIssueIntelSources(is).length > 0);
  const L = k => esc(tr('issues.col_' + k));
  thead.innerHTML = `<tr><th>${L('category')}</th><th>${L('severity')}</th><th>${L('count')}</th><th>${L('confidence')}</th>${hasSource ? `<th>${L('source')}</th>` : ''}<th>${L('basis')}</th><th>${L('sample')}</th><th>${L('note')}</th><th>${L('status')}</th></tr>`;
  // 問題清單搜尋框（比照 #results-search／filterEvents() 既有樣板）：對分類標籤/來源/判斷依據/
  // 樣本原始文字做不分大小寫子字串比對，僅影響表格顯示，不重新計算分析結果
  const searchQuery = document.getElementById('issues-search').value.trim().toLowerCase();
  const rows = visible.map(is => {
    const baseCat = is.category.startsWith('freq:') ? is.category.slice(5) : is.category;
    // 2026-09-22 資安修復：issueCategoryLabel() 對 custom: 類別會直接回傳使用者可匯入的
    // 自訂規則名稱（customRuleName，未跳脫），先前這裡直接塞進 innerHTML 造成 Stored XSS。
    // 在此處立刻 esc() 一次（而非在下方樣板字串處對整個 catLabel 再包一次 esc()）：下一行
    // intelSource 是另外組裝、自己已經 esc() 過一次，若改成在樣板處對「已含 intelSource」的
    // 完整 catLabel 整串再 esc() 一次，會把 intelSource 的部分雙重跳脫（比照 exportLogReport()
    // 該處既有註解說明的同一個陷阱），故改為只對 issueCategoryLabel() 的回傳值單獨跳脫
    let catLabel = esc(issueCategoryLabel(is.category));
    if ((is.category === 'knownIOC' || is.category === 'knownHashIOC') && is.intelSource) catLabel += ` (${esc(is.intelSource)})`;
    const mitreId = (is.mitre || MITRE_MAP[baseCat]);
    const mitreBadge = mitreId ? ` <span class="mitre-badge" title="${esc(tr('mitre.disclaimer'))}">${esc(mitreId)}</span>` : '';
    const sourceCell = getIssueIntelSources(is).join(', ') || '-';
    const basisText = formatIssueBasis(is);
    // 分析師備註（2026-09-16 新增）：鍵沿用既有 _baselineDiffKey()（分類層級粒度，與
    // SUPPRESSED_CATEGORIES 同一粒度，非逐筆 issue 更細的識別——ISSUES 每次分析都整批重建，
    // 沒有比分類更細的跨執行穩定鍵）
    const noteKey = _baselineDiffKey(is);
    const noteText = issueNotes[noteKey] || '';
    // 動態值塞進 onclick 屬性一律用 JSON.stringify()+跳脫雙引號（本專案既有慣例，見
    // firewall-analyzer-audit.js 等既有 onclick 寫法），而非自行處理單引號跳脫
    const noteKeyArg = esc(JSON.stringify(noteKey));
    const noteCell = `<button class="note-btn${noteText ? ' has-note' : ''}" onclick="onIssueNoteClick(${noteKeyArg})" title="${esc(noteText || tr('issues.note_prompt'))}">📝</button>`;
    const status = issueStatusOf(noteKey);
    const statusCell = `<select onchange="onIssueStatusChange(${noteKeyArg}, this.value)">${ISSUE_STATUS_VALUES.map(v => `<option value="${v}"${v === status ? ' selected' : ''}>${esc(tr('status.' + v))}</option>`).join('')}</select>`;
    const searchText = `${catLabel} ${sourceCell} ${basisText} ${issueSample(is)} ${noteText} ${tr('status.' + status)}`.toLowerCase();
    const html = `<tr${status === 'falsePositive' ? ' style="opacity:.55"' : ''}>
      <td class="is-cat">${catLabel}${mitreBadge}${nextStepHtml(baseCat)}</td>
      <td class="is-inl" data-label="${L('severity')}"><span class="badge ${sevClass(is.severityNorm)}">${tr(SEV_KEY_MAP[is.severityNorm])}</span></td>
      <td class="is-inl" data-label="${L('count')}">${is.count}</td>
      <td class="is-inl" data-label="${L('confidence')}"><span class="conf-tag ${is.confidence}">${tr('conf.' + is.confidence)}</span></td>
      ${hasSource ? `<td data-label="${L('source')}">${esc(sourceCell)}</td>` : ''}
      <td data-label="${L('basis')}">${esc(basisText)}</td>
      <td class="is-sample" data-label="${L('sample')}">${swPortBtn(is)}${issueActorLink(is)}${esc(issueSample(is))}</td>
      <td class="is-inl">${noteCell}</td>
      <td class="is-inl">${statusCell}</td></tr>`;
    return { html, searchText };
  }).filter(r => !searchQuery || r.searchText.includes(searchQuery));
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="${hasSource ? 9 : 8}" class="empty">${tr('issues.empty')}</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(r => r.html).join('');
}

// 調查案件包 UI（第三十三輪 XN11）：buildCaseTimeline()／caseReplaceMapped()／buildCasePackHtml() 在 STATE 邊界之前。
// 勾選以「分類＋摘要」為鍵存在 CASE_SELECTED（狀態或備註變更重畫清單時保留勾選）；去識別化沿用整份 log 的 ANON_EVENTS
let CASE_SELECTED = new Set();
const caseIssueKey = is => is.category + '|' + issueSample(is);
function renderCasePicker() {
  const box = document.getElementById('case-issues');
  if (!box) return;
  const keys = new Set(ISSUES.map(caseIssueKey));
  CASE_SELECTED = new Set([...CASE_SELECTED].filter(k => keys.has(k)));
  box.innerHTML = ISSUES.length ? ISSUES.map((is, i) => {
    const k = caseIssueKey(is);
    return `<label style="display:block"><input type="checkbox" data-i="${i}"${CASE_SELECTED.has(k) ? ' checked' : ''}> ${esc(issueCategoryLabel(is.category))}` +
      ` <span class="badge ${sevClass(is.severityNorm)}">${esc(tr(SEV_KEY_MAP[is.severityNorm]))}</span> ×${is.count} <span style="color:var(--text-dim)">${esc(issueSample(is).slice(0, 80))}</span></label>`;
  }).join('') : `<span style="color:var(--text-dim)">${esc(tr('issues.empty'))}</span>`;
  box.querySelectorAll('input[data-i]').forEach(cb => { cb.onchange = () => { const k = caseIssueKey(ISSUES[+cb.dataset.i]); if (cb.checked) CASE_SELECTED.add(k); else CASE_SELECTED.delete(k); }; });
  const dl = document.getElementById('case-actor-list');
  if (dl) dl.innerHTML = listKnownActors(ISSUES, CHAINS).slice(0, 200).map(a => `<option value="${esc(a)}">`).join('');
}
function doExportCasePack() {
  const msg = document.getElementById('case-msg');
  const sel = ISSUES.filter(is => CASE_SELECTED.has(caseIssueKey(is)));
  const actors = document.getElementById('case-actors').value.split(/[,，;\n]/).map(s => s.trim()).filter(Boolean);
  if (!sel.length && !actors.length) { msg.textContent = tr('case.need_pick'); return; }
  const deid = document.getElementById('case-deid').checked;
  const tl = buildCaseTimeline(sel, actors, EVENTS);
  let evs = tl.events, pairs = [];
  if (deid) {
    if (!ANON_EVENTS || ANON_EVENTS.length !== EVENTS.length) doRunDeid();
    const idx = new Map(EVENTS.map((e, i) => [e, i]));
    evs = tl.events.map(e => ANON_EVENTS[idx.get(e)] || e);
    pairs = [...mappings.ip, ...mappings.hostname, ...mappings.user].map(([o, f]) => [String(o), String(f)]);
    pairs.push(...caseMacPairs(mappings.mac));
  }
  const R = s => deid ? caseReplaceMapped(s, pairs) : String(s == null ? '' : s);
  const model = {
    title: R(document.getElementById('case-name').value.trim()) || tr('case.default_title'),
    summary: R(document.getElementById('case-summary').value.trim()),
    generatedAt: new Date().toLocaleString(), deid, totalEvents: tl.total,
    labels: { title: tr('case.default_title'), generated: tr('case.generated'), deidOn: tr('case.deid_on'), deidOff: tr('case.deid_off'), truncated: tr('case.truncated'),
      disclaimer: tr('case.disclaimer'), summary: tr('case.lbl_summary'), issues: tr('case.sec_issues'), actors: tr('case.sec_actors'), timeline: tr('case.sec_timeline'),
      colCategory: tr('issues.col_category'), colSeverity: tr('issues.col_severity'), colCount: tr('issues.col_count'), colFirst: tr('case.col_first'), colLast: tr('case.col_last'),
      colBasis: tr('issues.col_basis'), colSample: tr('case.col_sample'), colStatus: tr('case.col_status'), colNote: tr('case.col_note'), colActor: tr('case.col_actor'),
      colEvents: tr('case.col_events'), colTime: tr('case.col_time'), colHost: tr('case.col_host'), colMessage: tr('case.col_message'),
      iocs: tr('case.sec_iocs'), iocNote: tr('case.ioc_note'), iocDeid: tr('case.ioc_deid'), untrusted: tr('case.untrusted_note'), rotTitle: tr('rot.title'), rotHint: tr('rot.hint'), rotKind: tr('rot.col_kind'), rotId: tr('rot.col_id'), rotWhere: tr('rot.col_where'), rotSource: tr('rot.col_source'), colKind: tr('case.col_ioc_kind'), colValue: tr('case.col_ioc_value') },
    // 所選問題涉及的外部指標（XN76，沿用 buildIOCExportRecords：排除內部位址）；去識別化時不附
    iocDeid: deid,
    rotation: deid ? [] : buildRotationList(sel).map(r => ({ kind: tr('rot.kind_' + r.kind), id: r.id, where: tr('rot.where_' + r.kind), cat: issueCategoryLabel(r.cat) })),
    iocs: deid ? [] : buildIOCExportRecords(sel).records.map(r => ({ kind: r.kind, value: r.value, cats: r.categories.map(c => issueCategoryLabel(c)).join(', '), sevLabel: r.severity ? tr(SEV_KEY_MAP[r.severity]) : '-' })),
    issues: sel.map(is => {
      const base = is.category.startsWith('freq:') ? is.category.slice(5) : is.category, key = _baselineDiffKey(is);
      return { label: R(issueCategoryLabel(is.category) + ((is.category === 'knownIOC' || is.category === 'knownHashIOC') && is.intelSource ? ` (${is.intelSource})` : '')),
        sev: is.severityNorm, sevLabel: tr(SEV_KEY_MAP[is.severityNorm]), count: is.count, mitre: is.mitre || MITRE_MAP[base] || '',
        basis: R(formatIssueBasis(is)), sample: R(issueSample(is)), status: issueStatusLabel(key), note: R(issueNotes[key] || ''),
        first: fmtTime(issueTime(is, 'first')), last: fmtTime(issueTime(is, 'last')) };
    }),
    actors: actors.map(a => { const p = buildActorProfile(a, EVENTS, [], []); return { actor: R(a), events: p.events.length, first: fmtTime(p.firstSeen), last: fmtTime(p.lastSeen) }; }),
    // 沒有時間戳的事件 effectiveTime() 以行號排序，顯示時不可當成時間（會變成 1970 年）
    events: evs.map(e => ({ time: e.timestamp ? fmtTime(e.timestamp.getTime()) : '-', host: e.host || '', cat: tr(CAT_KEY_MAP[e.category] || 'cat.other'), msg: String(e.raw || eventDisplayMsg(e) || '').slice(0, 2000) }))
  };
  const blob = new Blob([buildCasePackHtml(model)], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob), a = document.createElement('a');
  const d = new Date(), pad = n => String(n).padStart(2, '0');
  a.href = url; a.download = `case_${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}.html`; a.click();
  URL.revokeObjectURL(url);
  msg.textContent = tr('case.done').replace('{i}', sel.length).replace('{a}', actors.length).replace('{n}', tl.total);
}

// 行為者檢視 UI（2026-09-24 新增）：資料彙整交給純函式 buildActorProfile()，這裡只負責渲染；
// 事件明細最多顯示 100 筆（依時間排序），避免大型 log 一次塞入過多 DOM
const ACTOR_EVENT_SHOW_MAX = 100;
function renderActorList() {
  const dl = document.getElementById('actor-list');
  dl.innerHTML = '';
  listKnownActors(ISSUES, CHAINS).forEach(a => { const o = document.createElement('option'); o.value = a; dl.appendChild(o); });
}
// 目前畫面上的行為者檢視結果（供匯出按鈕使用），無結果時為 null 並停用匯出按鈕
let LAST_ACTOR_PROFILE = null;
function setActorExportProfile(p) {
  LAST_ACTOR_PROFILE = p;
  document.getElementById('btn-actor-export-md').disabled = !p;
  document.getElementById('btn-actor-export-csv').disabled = !p;
}
// 問題清單的行為者連結（JC）：帳號優先否則 IP，點擊帶入行為者檢視
function issueActorLink(is) {
  const a = deriveIssueActorByUser(is) || deriveIssueActor(is);
  if (!a) return '';
  return `<a href="#actor-card" class="actor-link" title="${esc(tr('actor.title'))}: ${esc(a)}" onclick="showActorProfile(${esc(JSON.stringify(String(a)))});return false;">👤</a> `;
}
function showActorProfile(actor) {
  const input = document.getElementById('actor-input');
  if (actor !== undefined) input.value = actor;
  const box = document.getElementById('actor-result');
  const a = input.value.trim();
  setActorExportProfile(null);
  if (!a) { box.innerHTML = ''; return; }
  const p = buildActorProfile(a, EVENTS, ISSUES, CHAINS);
  if (!p.events.length && !p.issues.length && !p.chains.length) {
    box.innerHTML = `<div class="empty">${esc(tr('actor.none'))}</div>`;
    return;
  }
  setActorExportProfile(p);
  const summary = tr('actor.summary').replace('{events}', p.events.length).replace('{issues}', p.issues.length).replace('{chains}', p.chains.length);
  const range = p.firstSeen ? ` （${esc(fmtTime(new Date(p.firstSeen)))} ～ ${esc(fmtTime(new Date(p.lastSeen)))}）` : '';
  const issueRows = p.issues.map(is => `<tr><td>${esc(issueCategoryLabel(is.category))}</td><td><span class="badge ${sevClass(is.severityNorm)}">${esc(tr(SEV_KEY_MAP[is.severityNorm]))}</span></td><td>${is.count}</td><td>${esc(issueStatusLabel(_baselineDiffKey(is)))}</td></tr>`).join('');
  const chainRows = p.chains.map(c => `<tr><td><span class="badge ${sevClass(c.severityNorm)}">${esc(tr(SEV_KEY_MAP[c.severityNorm]))}</span></td><td>${c.stages.map(st => esc(tr(CHAIN_STAGE_KEY_MAP[st.stage]))).join(' → ')}</td><td>${esc(fmtTime(c.firstSeen))}</td><td>${esc(fmtTime(c.lastSeen))}</td></tr>`).join('');
  const evSorted = [...p.events].sort((x, y) => effectiveTime(x) - effectiveTime(y));
  const eventRows = evSorted.slice(0, ACTOR_EVENT_SHOW_MAX).map(e => `<tr><td class="mono">${esc(fmtTime(e.timestamp))}</td><td><span class="badge ${sevClass(e.severityNorm)}">${esc(tr(SEV_KEY_MAP[e.severityNorm]))}</span></td><td>${esc(e.host)}</td><td class="mono">${esc(eventDisplayMsg(e))}</td></tr>`).join('');
  const more = p.events.length > ACTOR_EVENT_SHOW_MAX ? `<div class="hint">${esc(tr('actor.more').replace('{n}', ACTOR_EVENT_SHOW_MAX))}</div>` : '';
  const maxH = Math.max(1, ...p.hours);
  const hourBars = p.events.some(e => e.timestamp) ? `<h3>${esc(tr('actor.hours_title'))}</h3><div class="actor-hours" style="display:flex;align-items:flex-end;gap:2px;height:60px">`
    + p.hours.map((n, h) => `<div title="${h}:00 · ${n}" style="flex:1;background:var(--accent);opacity:${n ? 0.35 + 0.65 * n / maxH : 0.12};height:${n ? Math.max(4, Math.round(56 * n / maxH)) : 2}px"></div>`).join('')
    + `</div><div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-dim)"><span>0</span><span>6</span><span>12</span><span>18</span><span>23</span></div>` : '';
  const peerRows = p.peers.map(x => `<tr><td class="mono"><a href="#actor-card" class="actor-link" onclick="showActorProfile(${esc(JSON.stringify(x.peer))});return false;">${esc(x.peer)}</a></td><td>${x.count}</td></tr>`).join('');
  box.innerHTML = `<p><strong>${esc(a)}</strong>：${esc(summary)}${range}</p>`
    + (p.owners.length ? `<p>${esc(tr('actor.owners'))}${esc(p.owners.join(', '))}</p>` : '')
    + hourBars
    + (peerRows ? `<h3>${esc(tr('actor.peers_title'))}</h3><div class="tbl-wrap"><table><thead><tr><th>${esc(tr('actor.col_peer'))}</th><th>${esc(tr('issues.col_count'))}</th></tr></thead><tbody>${peerRows}</tbody></table></div>` : '')
    + (issueRows ? `<h3>${esc(tr('issues.title'))}</h3><div class="tbl-wrap"><table><thead><tr><th>${esc(tr('issues.col_category'))}</th><th>${esc(tr('issues.col_severity'))}</th><th>${esc(tr('issues.col_count'))}</th><th>${esc(tr('issues.col_status'))}</th></tr></thead><tbody>${issueRows}</tbody></table></div>` : '')
    + (chainRows ? `<h3>${esc(tr('chain.title'))}</h3><div class="tbl-wrap"><table><thead><tr><th>${esc(tr('issues.col_severity'))}</th><th>${esc(tr('chain.col_stages'))}</th><th>${esc(tr('chain.col_first'))}</th><th>${esc(tr('chain.col_last'))}</th></tr></thead><tbody>${chainRows}</tbody></table></div>` : '')
    + (eventRows ? `<h3>${esc(tr('actor.events_title'))}</h3><div class="tbl-wrap"><table><thead><tr><th>${esc(tr('chain.col_first'))}</th><th>${esc(tr('issues.col_severity'))}</th><th>Host</th><th>Message</th></tr></thead><tbody>${eventRows}</tbody></table></div>${more}` : '');
}

const CHAIN_STAGE_KEY_MAP = { recon: 'chain.stage_recon', access: 'chain.stage_access', malicious: 'chain.stage_malicious', postActivity: 'chain.stage_postActivity' };
// 主機登入關係（第三十一輪 HX1）：表格最多顯示 HOST_GRAPH_SHOW 列，匯出為全部
const HOST_GRAPH_SHOW = 300;
let HOST_GRAPH = [];
// 服務健康與建議一併匯入的 log（XN16）：資料由 buildServiceTimeline()／detectServiceHealth()／companionSourcesOf() 產生
// 檢查指令（工具離線，不會連線到伺服器；列出指令供使用者在伺服器上執行）
const SVC_CMDS = [
  ['svch.svc_common', 'svch.cmd_status', 'systemctl status slapd | dirsrv@<instance> | radiusd | freeradius'],
  ['svch.svc_common', 'svch.cmd_journal', 'journalctl -u <unit> --since "-2h"'],
  ['svch.svc_common', 'svch.cmd_core', 'coredumpctl list'],
  ['svch.svc_common', 'svch.cmd_kernel', 'dmesg -T | grep -iE "segfault|out of memory"'],
  ['OpenLDAP', 'svch.cmd_alive', 'ldapsearch -x -H ldap://<server> -b "" -s base namingContexts'],
  ['OpenLDAP', 'svch.cmd_monitor', 'ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=monitor'],
  ['OpenLDAP', 'svch.cmd_mapsize', 'mdb_stat -e /var/lib/ldap'],
  ['OpenLDAP', 'svch.cmd_debug', 'slapd -d stats'],
  ['389 Directory Server', 'svch.cmd_status', 'dsctl <instance> status'],
  ['389 Directory Server', 'svch.cmd_health', 'dsctl <instance> healthcheck'],
  ['389 Directory Server', 'svch.cmd_monitor', 'dsconf <instance> monitor server'],
  ['389 Directory Server', 'svch.cmd_disk', 'dsconf <instance> monitor disk'],
  ['FreeRADIUS', 'svch.cmd_debug', 'radiusd -X   (Debian/Ubuntu: freeradius -X)'],
  ['FreeRADIUS', 'svch.cmd_homes', 'radmin -e "show home_server list"'],
  ['FreeRADIUS', 'svch.cmd_stats', 'radmin -e "stats client auth"'],
  ['FreeRADIUS', 'svch.cmd_statusserver', 'echo "Message-Authenticator = 0x00" | radclient <server>:18121 status <secret>'],
];
function fmtDownMs(ms) {
  if (!ms) return '-';
  const s = Math.round(ms / 1000), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h ? `${h}h ${m}m` : (m ? `${m}m ${s % 60}s` : `${s}s`);
}
function renderServiceHealth() {
  const card = document.getElementById('svchealth-card');
  const tl = buildServiceTimeline(EVENTS);
  card.style.display = tl.services.length ? '' : 'none';
  if (!tl.services.length) return;
  const cols = ['svc', 'host', 'starts', 'stops', 'crashes', 'errors', 'down', 'state', 'last'];
  document.querySelector('#svchealth-table thead').innerHTML = '<tr>' + cols.map(c => `<th>${esc(tr('svch.col_' + c))}</th>`).join('') + '</tr>';
  document.querySelector('#svchealth-table tbody').innerHTML = tl.services.map(s => {
    const v = { svc: SVC_LABEL[s.svc] || s.svc, host: s.host || '-', starts: s.starts, stops: s.stops, crashes: s.crashes, errors: s.errors, down: fmtDownMs(s.downMs),
      state: tr('svch.state_' + (s.state || 'unknown')), last: fmtTime(s.last) };
    return '<tr>' + cols.map(c => `<td${c === 'crashes' && s.crashes ? ' style="color:var(--red)"' : (c === 'state' && s.state === 'crashed' ? ' style="color:var(--red)"' : '')}>${esc(v[c])}</td>`).join('') + '</tr>';
  }).join('');
  const hc = ['home', 'zombie', 'dead', 'alive', 'state', 'last'];
  document.getElementById('svchealth-homes').innerHTML = tl.homes.length ? `<h3 style="font-size:13px;margin:12px 0 6px">${esc(tr('svch.homes_title'))}</h3><div class="tbl-wrap"><table><thead><tr>` +
    hc.map(c => `<th>${esc(tr('svch.col_' + (c === 'state' ? 'state' : c === 'last' ? 'last' : c)))}</th>`).join('') + '</tr></thead><tbody>' +
    tl.homes.map(h => `<tr><td>${esc(h.home)}</td><td>${h.zombie}</td><td>${h.dead}</td><td>${h.alive}</td><td${h.state !== 'alive' ? ' style="color:var(--red)"' : ''}>${esc(tr('svch.home_' + h.state))}</td><td>${esc(fmtTime(h.last))}</td></tr>`).join('') +
    '</tbody></table></div>' : '';
  const adv = ISSUES.filter(is => is.companions && is.companions.length);
  document.getElementById('svchealth-advice').innerHTML = adv.length ? `<h3 style="font-size:13px;margin:12px 0 4px">${esc(tr('svch.advice_title'))}</h3><p class="hint">${esc(tr('svch.advice_hint'))}</p><ul style="font-size:12px;margin:4px 0 0 18px">` +
    adv.map(is => `<li><b>${esc(issueCategoryLabel(is.category))}</b>：${esc(issueSample(is))}<ul style="margin:2px 0 6px 16px">${is.companions.map(c => `<li>${esc(tr('comp.' + c))}</li>`).join('')}</ul></li>`).join('') + '</ul>' : '';
  document.querySelector('#svchealth-cmds-table thead').innerHTML = `<tr><th>${esc(tr('svch.col_svc'))}</th><th>${esc(tr('svch.col_purpose'))}</th><th>${esc(tr('svch.col_cmd'))}</th></tr>`;
  document.querySelector('#svchealth-cmds-table tbody').innerHTML = SVC_CMDS.map(([s, k, c]) => `<tr><td>${esc(s.startsWith('svch.') ? tr(s) : s)}</td><td>${esc(tr(k))}</td><td style="font-family:monospace">${esc(c)}</td></tr>`).join('');
}
function renderCompanions() {
  const card = document.getElementById('companion-card');
  card.style.display = EVENTS.length ? '' : 'none';
  if (!EVENTS.length) return;
  const srcs = companionSourcesOf(EVENTS), recs = companionRecsFor(srcs, companionCoveredOf(EVENTS));
  const srcLabel = id => tr('compsrc.' + id);
  let h = `<div style="font-size:12px;margin-bottom:6px">${esc(tr('companion.detected'))}${esc(srcs.length ? srcs.map(srcLabel).join('、') : '-')}</div>`;
  h += recs.length ? '<ul style="font-size:12px;margin:4px 0 0 18px">' + recs.map(r => `<li><b>${esc(srcLabel(r.source))}</b><ul style="margin:2px 0 6px 16px">${r.recs.map(c => `<li>${esc(tr('comp.' + c))}</li>`).join('')}</ul></li>`).join('') + '</ul>'
    : `<div class="hint">${esc(tr('companion.none'))}</div>`;
  // 逐問題建議（XN79）：服務類的已在服務狀態卡列出，這裡只列其他帶 companions 的問題（如 Appsmith）
  const adv = ISSUES.filter(is => is.companions && is.companions.length && !/^svc/.test(is.category));
  // 建議相同的問題合併成一組，避免同樣的建議重複列出；同類問題只列一次名稱
  const groups = new Map();
  adv.forEach(is => { const k = is.companions.join('|'); if (!groups.has(k)) groups.set(k, { comps: is.companions, cats: new Set() }); groups.get(k).cats.add(is.category); });
  if (groups.size) h += `<div style="font-size:12px;font-weight:600;margin:10px 0 4px">${esc(tr('companion.issue_title'))}</div><ul style="font-size:12px;margin:4px 0 0 18px">`
    + [...groups.values()].map(g => `<li><b>${[...g.cats].map(c => esc(issueCategoryLabel(c))).join('、')}</b><ul style="margin:2px 0 6px 16px">${g.comps.map(c => `<li>${esc(tr('comp.' + c))}</li>`).join('')}</ul></li>`).join('') + '</ul>';
  document.getElementById('companion-body').innerHTML = h;
  document.querySelector('#companion-all-table thead').innerHTML = `<tr><th>${esc(tr('companion.col_source'))}</th><th>${esc(tr('companion.col_recs'))}</th></tr>`;
  document.querySelector('#companion-all-table tbody').innerHTML = COMPANION_SOURCES.map(([id, , list]) => `<tr><td>${esc(srcLabel(id))}</td><td>${list.map(c => esc(tr('comp.' + c))).join('<br>')}</td></tr>`).join('');
}
function renderHostGraph() {
  HOST_GRAPH = buildHostLogonGraph(EVENTS);
  const card = document.getElementById('hostgraph-card');
  card.style.display = HOST_GRAPH.length ? '' : 'none';
  if (!HOST_GRAPH.length) return;
  document.querySelector('#hostgraph-table thead').innerHTML = '<tr>' + HOST_GRAPH_COLS.map(c => `<th>${esc(tr('hostgraph.col_' + c))}</th>`).join('') + '</tr>';
  document.querySelector('#hostgraph-table tbody').innerHTML = hostGraphRows(HOST_GRAPH.slice(0, HOST_GRAPH_SHOW)).map(r => '<tr>' + HOST_GRAPH_COLS.map(c => {
    const v = (c === 'first' || c === 'last') ? fmtTime(r[c] || null) : r[c];
    return `<td${c === 'fail' && r.fail > r.ok ? ' style="color:var(--red)"' : ''}>${esc(v === '' ? '-' : v)}</td>`;
  }).join('') + '</tr>').join('');
  document.getElementById('hostgraph-count').textContent = tr('hostgraph.count').replace('{n}', HOST_GRAPH.length).replace('{shown}', Math.min(HOST_GRAPH.length, HOST_GRAPH_SHOW));
}
function downloadHostGraph(kind) {
  if (!HOST_GRAPH.length) return;
  let text, type, ext;
  if (kind === 'csv') {
    const rows = [HOST_GRAPH_COLS.map(c => tr('hostgraph.col_' + c)), ...hostGraphRows(HOST_GRAPH).map(r => HOST_GRAPH_COLS.map(c => r[c]))];
    text = '\ufeff' + rows.map(r => r.map(csvCell).join(',')).join('\n'); type = 'text/csv;charset=utf-8'; ext = 'csv';
  } else if (kind === 'mermaid') { text = hostGraphMermaid(HOST_GRAPH); type = 'text/plain;charset=utf-8'; ext = 'mmd'; }
  else { text = hostGraphDrawio(HOST_GRAPH, tr('hostgraph.title')); type = 'application/xml'; ext = 'drawio'; }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type })); a.download = 'host-logons.' + ext; a.click();
}
function renderChains() {
  renderHostGraph();
  renderServiceHealth();
  renderCompanions();
  // 行為者檢視（2026-09-24 新增）跟著攻擊鏈一起刷新：候選清單重建；輸入框已有值就重算
  // 目前這份資料下的結果（重新分析後舊結果不應殘留），清除全部時一併清空
  renderActorList();
  if (!EVENTS.length) document.getElementById('actor-input').value = '';
  showActorProfile();
  const thead = document.querySelector('#correlation-table thead');
  const tbody = document.querySelector('#correlation-table tbody');
  thead.innerHTML = `<tr><th>${tr('chain.col_actor')}</th><th>${tr('issues.col_severity')}</th><th>${tr('chain.col_stages')}</th><th>${tr('chain.col_first')}</th><th>${tr('chain.col_last')}</th><th>${tr('chain.col_span')}</th><th></th></tr>`;
  // 🛡（XN129）：把這條鏈上有結果的連線（來源、目的、協定、埠、實際結果）以批次送到防火牆分析，對照設定是否放行
  tbody.onclick = ev => {
    const b = ev.target.closest('[data-chain-fw]');
    if (!b || b.disabled) return;
    const c = CHAINS[+b.getAttribute('data-chain-fw')];
    const csv = c ? chainFwBatch(c) : null;
    if (csv) sendToFirewallQuery({ batch: csv.csv });
  };
  // 沒有攻擊鏈時只留一行說明，不畫空表格（UX36）
  const chEmpty = document.getElementById('chains-empty');
  chEmpty.style.display = CHAINS.length ? 'none' : '';
  chEmpty.textContent = CHAINS.length ? '' : tr('chain.empty');
  document.querySelector('#correlation-card .tbl-wrap').style.display = CHAINS.length ? '' : 'none';
  if (!CHAINS.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">${tr('chain.empty')}</td></tr>`;
    return;
  }
  tbody.innerHTML = CHAINS.map((c, ci) => {
    const fwb = chainFwBatch(c);
    const fwBtn = `<button class="fwq-btn" data-chain-fw="${ci}"${fwb ? '' : ' disabled'} title="${esc(tr(fwb ? 'chain.fw_btn' : 'chain.fw_none'))}" aria-label="${esc(tr(fwb ? 'chain.fw_btn' : 'chain.fw_none'))}">🛡</button>`;
    // MITRE 徽章（2026-09-21 新增）：比照 renderIssues()/exportLogReport() 既有 MITRE_MAP
    // 查表+mitre-badge 樣式，讓攻擊鏈關聯表也能看出各階段對應的 ATT&CK 技術
    const stageText = c.stages.map(s => {
      const baseCat = s.issue.category.startsWith('freq:') ? s.issue.category.slice(5) : s.issue.category;
      const mitreId = (s.issue.mitre || MITRE_MAP[baseCat]);
      const mitreBadge = mitreId ? ` <span class="mitre-badge" title="${esc(tr('mitre.disclaimer'))}">${esc(mitreId)}</span>` : '';
      return `<span class="badge ${sevClass(s.issue.severityNorm)}">${tr(CHAIN_STAGE_KEY_MAP[s.stage])}</span>${mitreBadge}`;
    }).join(' → ');
    return `<tr>
      <td><a href="#actor-card" class="actor-link" onclick="showActorProfile(${esc(JSON.stringify(c.actor))});return false;">${esc(c.actor)}</a></td>
      <td><span class="badge ${sevClass(c.severityNorm)}">${tr(SEV_KEY_MAP[c.severityNorm])}</span></td>
      <td>${stageText}</td>
      <td>${fmtTime(c.firstSeen)}</td>
      <td>${fmtTime(c.lastSeen)}</td>
      <td>${spanText(c.spanMs)}</td>
      <td>${fwBtn}</td></tr>`;
  }).join('');
}
// 攻擊鏈上各問題的事件中，有放行／拒絕結果的連線組成防火牆批次查詢 CSV（沒有任何可查的連線回傳 null）
function chainFwBatch(c) {
  const evs = [...new Set((c.stages || []).flatMap(s => (s.issue && s.issue.relatedEvents) || []))];
  const b = buildFwBatchCsv(evs);
  return b.rows ? b : null;
}

// Top-N 摘要儀表板渲染（2026-09-14 新增）：三張小表格（來源IP／使用者／分類）共用同一組
// thead/tbody 手刻慣例，資料來源固定用全量 EVENTS（非套用 results-search 篩選後的子集，
// 與③問題清單/②事件清單分頁各自獨立的統計視角一致，避免使用者篩選事件清單時誤以為
// Top-N 也跟著篩選但實際沒有）
function renderTopN() {
  document.getElementById('lbl-topn-src').textContent = tr('topn.src_title');
  document.getElementById('lbl-topn-user').textContent = tr('topn.user_title');
  document.getElementById('lbl-topn-category').textContent = tr('topn.category_title');
  [
    { field: 'src', tableId: 'topn-src-table' },
    { field: 'user', tableId: 'topn-user-table' },
    { field: 'category', tableId: 'topn-category-table' },
  ].forEach(spec => {
    const thead = document.querySelector(`#${spec.tableId} thead`);
    const tbody = document.querySelector(`#${spec.tableId} tbody`);
    thead.innerHTML = `<tr><th>${tr('topn.col_value')}</th><th>${tr('topn.col_count')}</th></tr>`;
    const top = buildTopNSummary(EVENTS, spec.field, 10);
    tbody.innerHTML = top.length
      ? top.map(r => `<tr><td>${esc(spec.field === 'category' ? tr(CAT_KEY_MAP[r.value] || 'cat.other') : r.value)}</td><td>${r.count}</td></tr>`).join('')
      : `<tr><td colspan="2" class="empty">${tr('topn.empty')}</td></tr>`;
  });
}

// 檔案雜湊/監管鏈中繼資料顯示（2026-09-14 新增）：FILE_METADATA 為 null（貼上文字而非上傳
// 檔案、或尚未上傳）時整列隱藏，避免顯示無意義的空值
function renderFileMetadata() {
  const row = document.getElementById('file-metadata-row');
  const label = document.getElementById('file-metadata-label');
  document.getElementById('btn-export-file-metadata').textContent = tr('filemeta.export_btn');
  if (!FILE_METADATA) { row.style.display = 'none'; return; }
  label.textContent = `SHA-256: ${FILE_METADATA.sha256} · ${FILE_METADATA.lineCount} ${tr('filemeta.lines_suffix')} · ${formatBytesHuman(FILE_METADATA.totalSize)}`;
  row.style.display = '';
}

// 健檢分數卡 A-F（2026-09-15 新增）：靜態文字（標題/按鈕）與 switch/firewall 既有模式一致
// 每次 setLang()/renderAll() 都重繪，實際分數則比照既有「手動觸發」慣例只在按鈕點擊時計算
function renderHealthStatic() {
  document.getElementById('t-health-title').textContent = tr('health.title');
  const btn = document.getElementById('health-btn');
  // 與防火牆／交換器分析一致：有分析結果就直接顯示健檢分數（只依問題清單計算，成本低）（UX07）
  if (btn) btn.style.display = EVENTS.length ? 'none' : '';
  if (btn) btn.textContent = tr('health.run');
  if (EVENTS.length) _doLogHealthCheck();
  else { const r = document.getElementById('health-result'); if (r) r.innerHTML = ''; }
}
function _doLogHealthCheck() {
  const btn = document.getElementById('health-btn');
  if (btn) btn.textContent = tr('health.recheck');
  const res = computeLogHealth(ISSUES);
  const sevColors = { Critical: 'var(--red)', High: 'var(--orange)', Medium: 'var(--yellow)', Low: 'var(--accent)', Info: 'var(--text-dim)' };
  const sevIcon = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪' };
  let h = `<div style="display:flex;align-items:center;gap:14px;margin-bottom:12px">
    <div style="font-size:48px;font-weight:700;color:${res.gradeColor};line-height:1">${res.grade}</div>
    <div><div style="font-size:13px;color:var(--text-dim)">${tr('health.title')}</div>
    <div style="font-size:20px;font-weight:600;color:${res.gradeColor}">${res.score} / 100</div></div>
  </div>`;
  if (!res.issues.length) {
    h += `<div style="color:var(--green);font-size:13px">${tr('health.ok')}</div>`;
  } else {
    h += res.issues.map(i => `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;padding:6px 10px;background:var(--surface2);border-radius:6px;border-left:3px solid ${sevColors[i.sev] || 'var(--border)'}">
      <span style="font-size:14px">${sevIcon[i.sev] || ''}</span>
      <span style="font-size:13px;color:var(--text)">${esc(i.label)}</span>
      <span style="margin-left:auto;font-size:12px;color:var(--text-dim)">${i.count}</span>
    </div>`).join('');
  }
  const el = document.getElementById('health-result');
  if (el) el.innerHTML = h;
}

// 選用資料（情資、白名單、GeoIP／ASN、自訂規則）數量由 0 變成大於 0 時才自動展開一次；
// 之後重新繪製（切換語言等）不再強制展開，使用者手動收合的狀態得以保留
let _optSrcLastCount = 0;
function optionalSourceCount() {
  return INTEL_LISTS.length + HASH_INTEL_LISTS.length + SAFE_LISTS.length + GEO_LISTS.length + ASN_LISTS.length + IMPORTED_RISK_ASNS.length + IMPORTED_HOSTING_ASNS.length + IMPORTED_ANONVPN.length + IMPORTED_RMM.length + customDetectRules.length;
}
function openOptionalSources() {
  const n = optionalSourceCount();
  const d = document.getElementById('optional-sources');
  if (d && n > 0 && _optSrcLastCount === 0) d.open = true;
  _optSrcLastCount = n;
}
function renderIntelList() {
  const box = document.getElementById('intel-list');
  if (!INTEL_LISTS.length) { openOptionalSources(); box.innerHTML = `<div class="empty">${tr('intel.empty')}</div>`; return; }
  openOptionalSources();
  box.innerHTML = INTEL_LISTS.map((l, i) => `<div class="intel-row">
    <span class="n">${esc(l.name)} — ${l.index.count} ${tr('intel.count_label')}${l.date ? ' · ' + esc(l.date) : ''}</span>
    <button class="btn" data-idx="${i}" data-act="rm-intel">${tr('intel.remove_btn')}</button>
  </div>`).join('');
  box.querySelectorAll('[data-act="rm-intel"]').forEach(b => b.onclick = () => { INTEL_LISTS.splice(Number(b.dataset.idx), 1); renderIntelList(); });
}

function renderHashIntelList() {
  const box = document.getElementById('hashintel-list');
  if (!HASH_INTEL_LISTS.length) { openOptionalSources(); box.innerHTML = `<div class="empty">${tr('hashintel.empty')}</div>`; return; }
  openOptionalSources();
  box.innerHTML = HASH_INTEL_LISTS.map((l, i) => `<div class="intel-row">
    <span class="n">${esc(l.name)} — ${l.index.count} ${tr('intel.count_label')}${l.date ? ' · ' + esc(l.date) : ''}</span>
    <button class="btn" data-idx="${i}" data-act="rm-hashintel">${tr('intel.remove_btn')}</button>
  </div>`).join('');
  box.querySelectorAll('[data-act="rm-hashintel"]').forEach(b => b.onclick = () => { HASH_INTEL_LISTS.splice(Number(b.dataset.idx), 1); renderHashIntelList(); });
}

function renderSafeList() {
  const box = document.getElementById('safelist-list');
  if (!SAFE_LISTS.length) { openOptionalSources(); box.innerHTML = `<div class="empty">${tr('safelist.empty')}</div>`; return; }
  openOptionalSources();
  box.innerHTML = SAFE_LISTS.map((l, i) => `<div class="intel-row">
    <span class="n">${l.index.hasBroadCidr ? '⚠️ ' : ''}${esc(l.name)} — ${l.index.count} ${tr('intel.count_label')}</span>
    <button class="btn" data-idx="${i}" data-act="rm-safelist">${tr('intel.remove_btn')}</button>
  </div>`).join('');
  box.querySelectorAll('[data-act="rm-safelist"]').forEach(b => b.onclick = () => { SAFE_LISTS.splice(Number(b.dataset.idx), 1); renderSafeList(); });
}

function renderGeoList() {
  const box = document.getElementById('geo-list');
  if (!GEO_LISTS.length) { openOptionalSources(); box.innerHTML = `<div class="empty">${tr('geo.empty')}</div>`; return; }
  openOptionalSources();
  box.innerHTML = GEO_LISTS.map((l, i) => `<div class="intel-row">
    <span class="n">${esc(l.name)} — ${l.index.count} ${tr('intel.count_label')}</span>
    <button class="btn" data-idx="${i}" data-act="rm-geo">${tr('intel.remove_btn')}</button>
  </div>`).join('');
  box.querySelectorAll('[data-act="rm-geo"]').forEach(b => b.onclick = () => { GEO_LISTS.splice(Number(b.dataset.idx), 1); renderGeoList(); renderGeoRiskChecks(); });
}

function renderAsnList() {
  const box = document.getElementById('asn-list');
  if (!ASN_LISTS.length) { openOptionalSources(); box.innerHTML = `<div class="empty">${tr('asn.empty')}</div>`; return; }
  openOptionalSources();
  box.innerHTML = ASN_LISTS.map((l, i) => `<div class="intel-row">
    <span class="n">${esc(l.name)} — ${l.index.count} ${tr('intel.count_label')}</span>
    <button class="btn" data-idx="${i}" data-act="rm-asn">${tr('intel.remove_btn')}</button>
  </div>`).join('');
  box.querySelectorAll('[data-act="rm-asn"]').forEach(b => b.onclick = () => { ASN_LISTS.splice(Number(b.dataset.idx), 1); renderAsnList(); renderAsnRiskChecks(); });
}
// ASN 版本無「未匯入時的預設清單」模式（見 detectAsnRisk() 上方註解，ASN 沒有可查證的通用
// 風險名單），清單永遠只來自使用者自己上傳的資料庫；未匯入時容器留空不渲染任何 checkbox。
// 候選集合來源已於 2026-08-31 擴大為兩個：①IP→ASN 對照資料庫（ASN_LISTS）裡出現過的 ASN
// ②直接匯入的風險 ASN 清單（IMPORTED_RISK_ASNS，如 Spamhaus ASN-DROP）——後者因為使用者
// 上傳目的就是要標記這些 ASN 為風險，故預設勾選（除非使用者自己取消勾選，用 prevChecked
// 判斷是否為使用者手動取消，而非每次重繪都強制勾選）
function renderAsnRiskChecks() {
  const box = document.getElementById('asn-risk-checks');
  if (!box) return;
  const prevChecked = new Set(Array.from(box.querySelectorAll('input:checked')).map(el => el.value));
  const fromDb = getImportedAsns(ASN_LISTS);
  const merged = new Map(fromDb.map(x => [x.asn, x.asName]));
  const riskSourced = new Set();
  IMPORTED_RISK_ASNS.forEach(it => {
    if (!merged.has(it.asn)) merged.set(it.asn, it.asName || '');
    riskSourced.add(it.asn);
  });
  const items = Array.from(merged, ([asn, asName]) => ({ asn, asName })).sort((a, b) => a.asn.localeCompare(b.asn, undefined, { numeric: true }));
  box.innerHTML = items.map(it => {
    // 風險清單匯入的 ASN 首次出現時強制勾選一次（不論先前是否已因 DB 上傳而渲染過但未勾選），
    // 之後一律尊重使用者當下的勾選狀態（含使用者自行取消勾選）
    let checked;
    if (riskSourced.has(it.asn) && !AUTO_CHECKED_RISK_ASNS.has(it.asn)) {
      checked = true;
      AUTO_CHECKED_RISK_ASNS.add(it.asn);
    } else {
      checked = prevChecked.has(it.asn);
    }
    const label = `${it.asn}${it.asName ? '（' + it.asName + '）' : ''}`;
    return `<label class="geo-risk-item"><input type="checkbox" class="asn-risk-check" value="${esc(it.asn)}"${checked ? ' checked' : ''}> ${esc(label)}</label>`;
  }).join('');
}
function renderAsnRiskImportList() {
  const box = document.getElementById('asn-risk-import-list');
  if (!box) return;
  if (!IMPORTED_RISK_ASNS.length) { openOptionalSources(); box.innerHTML = `<div class="empty">${tr('asn.risk_import_empty')}</div>`; return; }
  openOptionalSources();
  box.innerHTML = `<div class="intel-row"><span class="n">${IMPORTED_RISK_ASNS.length} ${tr('intel.count_label')}</span>
    <button class="btn" id="btn-asn-risk-clear">${tr('intel.remove_btn')}</button></div>`;
  const clearBtn = document.getElementById('btn-asn-risk-clear');
  if (clearBtn) clearBtn.onclick = () => { IMPORTED_RISK_ASNS = []; renderAsnRiskImportList(); renderAsnRiskChecks(); };
}
function renderAsnHostingList() {
  const box = document.getElementById('asn-hosting-list');
  if (!box) return;
  if (!IMPORTED_HOSTING_ASNS.length) { box.innerHTML = `<div class="empty">${esc(tr('asn.hosting_empty'))}</div>`; return; }
  openOptionalSources();
  box.innerHTML = `<div class="intel-row"><span class="n">${IMPORTED_HOSTING_ASNS.length} ${tr('intel.count_label')}</span>
    <button class="btn" id="btn-asn-hosting-clear">${tr('intel.remove_btn')}</button></div>`;
  document.getElementById('btn-asn-hosting-clear').onclick = () => { IMPORTED_HOSTING_ASNS = []; renderAsnHostingList(); };
}
function renderAnonVpnList() {
  const box = document.getElementById('anonvpn-list');
  if (!box) return;
  if (!IMPORTED_ANONVPN.length) { box.innerHTML = `<div class="empty">${esc(tr('anonvpn.empty'))}</div>`; return; }
  openOptionalSources();
  box.innerHTML = `<div class="intel-row"><span class="n">${IMPORTED_ANONVPN.length} ${tr('intel.count_label')}</span>
    <button class="btn" id="btn-anonvpn-clear">${tr('intel.remove_btn')}</button></div>`;
  document.getElementById('btn-anonvpn-clear').onclick = () => { IMPORTED_ANONVPN = []; renderAnonVpnList(); };
}
function renderRmmList() {
  const box = document.getElementById('rmm-list');
  if (!box) return;
  if (!IMPORTED_RMM.length) { box.innerHTML = `<div class="empty">${esc(tr('rmm.empty'))}</div>`; return; }
  openOptionalSources();
  const tools = new Set(IMPORTED_RMM.map(x => x.tool).filter(Boolean)).size;
  box.innerHTML = `<div class="intel-row"><span class="n">${IMPORTED_RMM.length} ${tr('intel.count_label')}（${esc(tr('rmm.tools').replace('{n}', tools))}）</span>
    <button class="btn" id="btn-rmm-clear">${tr('intel.remove_btn')}</button></div>`;
  document.getElementById('btn-rmm-clear').onclick = () => { IMPORTED_RMM = []; renderRmmList(); };
}
function doRmmUpload(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const seen = new Set(IMPORTED_RMM.map(x => x.domain));
    parseRmmList(reader.result).forEach(it => { if (!seen.has(it.domain)) { seen.add(it.domain); IMPORTED_RMM.push(it); } });
    renderRmmList();
  };
  reader.readAsText(file);
}
function doAnonVpnUpload(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const seen = new Set(IMPORTED_ANONVPN.map(x => x.cidr));
    parseAnonVpnList(reader.result).forEach(it => { if (!seen.has(it.cidr)) { seen.add(it.cidr); IMPORTED_ANONVPN.push(it); } });
    renderAnonVpnList();
  };
  reader.readAsText(file);
}
function doAsnHostingUpload(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const seen = new Set(IMPORTED_HOSTING_ASNS.map(x => x.asn));
    parseHostingAsnList(reader.result).forEach(it => { if (!seen.has(it.asn)) { seen.add(it.asn); IMPORTED_HOSTING_ASNS.push(it); } });
    renderAsnHostingList();
  };
  reader.readAsText(file);
}
function doAsnRiskUpload(file) {
  const reader = new FileReader();
  reader.onload = () => {
    const parsed = parseAsnDropList(reader.result);
    const seen = new Set(IMPORTED_RISK_ASNS.map(x => x.asn));
    parsed.forEach(it => { if (!seen.has(it.asn)) { seen.add(it.asn); IMPORTED_RISK_ASNS.push(it); } });
    renderAsnRiskImportList();
    renderAsnRiskChecks();
  };
  reader.readAsText(file);
}
function filterAsnRiskChecks(q) {
  const query = (q || '').trim().toLowerCase();
  document.querySelectorAll('#asn-risk-checks .geo-risk-item').forEach(el => {
    el.style.display = !query || el.textContent.toLowerCase().includes(query) ? '' : 'none';
  });
}
function getRiskAsns() {
  const box = document.getElementById('asn-risk-checks');
  if (!box) return [];
  return Array.from(box.querySelectorAll('input:checked')).map(el => el.value);
}

// <html lang> 對應（2026-09-29，PB）：螢幕閱讀器依此決定朗讀語言；中文系彩蛋語言視為 zh-TW
function htmlLangFor(code) {
  if (code === 'ja') return 'ja';
  return ['zhTW', 'bureau', 'cat', 'bean', 'alpaca', 'yanse', 'wuxia'].indexOf(code) >= 0 ? 'zh-TW' : 'en';
}
function renderAll() {
  document.documentElement.lang = htmlLangFor(currentLang);
  renderLangBar();
  renderStatic();
  renderResults();
  renderTopN();
  renderFileMetadata();
  renderIssues();
  renderChains();
  renderTimeline();
  renderNextBar();
  renderIntelList();
  renderHashIntelList();
  renderSafeList();
  renderGeoList();
  renderAsnList();
  renderBaselineDiff();
}

