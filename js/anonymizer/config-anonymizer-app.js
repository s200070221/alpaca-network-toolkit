// config-anonymizer-app.js — 去識別化頁的畫面、匯出入與事件（RV17-B 從 config-anonymizer.html 拆出，內容未改）

// 2026-09 資安審查修復：供 renderStats() 顯示與 downloadAnonymized()/copyToClipboard() 匯出前
// 攔截共用，避免 bucketSeen 溢位判斷邏輯兩處維護。回傳 checkResidual() 的殘留警告加上逐 bucket
// 的 RFC5737 位址回捲溢位警告（見下方各項判斷式原始出處）。
function getResidualWarnings() {
  const warnings = checkResidual(STATE.anonymized);
  // 各類別 RFC5737 輸出網段僅一個 /24（254 個位址），超過即回捲並與較早位址碰撞，
  // 使該類別的匿名化不再是 1:1 可逆對應；不更動既有輸出格式/回捲邏輯，僅示警提醒
  const bucketLabels = { n1:'192.168.x.x', n2:'10.x.x.x', n3:'172.16-31.x.x' };
  Object.keys(bucketSeen).forEach(k => {
    if (bucketSeen[k].size > 254) {
      warnings.push({ line: 0, text: tr('warn.ip_bucket_overflow').replace('{range}', bucketLabels[k]).replace('{count}', bucketSeen[k].size) });
    }
  });
  return warnings;
}

// 殘留警告逐項忽略（2026-09-14 新增）：使用者已人工確認某筆警告是誤報或可接受風險後，
// 勾選忽略；key 格式與 checkResidual() 內部去重 key 一致（line+':'+text），session 內
// 有效（重新整理頁面即清空，避免真正的殘留被永久靜音而遺忘）
const dismissedResidualKeys = new Set();
function _residualKey(w) { return w.line + ':' + w.text; }
// downloadAnonymized()/copyToClipboard() 的匯出前確認攔截改用此函式（濾掉已忽略項目），
// renderResidualWarnings() 畫面顯示仍用未過濾的 getResidualWarnings()，讓使用者能看見
// 並取消先前的忽略決定
function getActiveResidualWarnings() {
  return getResidualWarnings().filter(w => !dismissedResidualKeys.has(_residualKey(w)));
}

// ============================================================
// [7] DIFF RENDERER
// ============================================================
function renderDiff(original, anonymized) {
  const origLines = original.split('\n');
  const anonLines = anonymized.split('\n');
  let origHTML = '', anonHTML = '', changedCount = 0;

  const escape = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const max = Math.max(origLines.length, anonLines.length);
  for (let i = 0; i < max; i++) {
    const o = origLines[i] ?? '';
    const a = anonLines[i] ?? '';
    const changed = o !== a;
    if (changed) changedCount++;
    const cls = changed ? ' changed' : '';
    origHTML += `<div class="code-line${cls}"><span class="ln">${i+1}</span><span class="lc">${escape(o)}</span></div>`;
    anonHTML += `<div class="code-line${cls}"><span class="ln">${i+1}</span><span class="lc">${escape(a)}</span></div>`;
  }
  return { origHTML, anonHTML, changedCount, totalLines: max };
}

// ============================================================
// [8] EXPORT
// ============================================================
// 正向映射快照（key→value，供人工檢視/匯入回填用，與 .acmap 還原包的反向映射方向不同、
// 不可共用）：mappings 實際有 7 類可逆映射，exportMapping()／批次模式先前各自維護不同子集
// （前者缺 ssid/alias/vdom、後者缺 alias/mac），2026-09-18 統一改用此函式作唯一權威來源，
// 避免未來再度各自漂移。mac Map 內部值是 {hex} 物件（見 anonMAC()），取出純 hex 字串。
function buildMappingSnapshot(m) {
  const out = {};
  MAPPING_CATEGORIES.forEach(cat => {
    out[cat] = cat === 'mac'
      ? Object.fromEntries([...m.mac].map(([k, v]) => [k, (v && v.hex) || v]))
      : Object.fromEntries(m[cat]);
  });
  return out;
}
function exportMapping() {
  if (!confirm(tr('warn.export_map_confirm'))) return;
  const m = STATE.mappings || mappings; // 快照優先，理論上 runAnonymize() 後必定存在
  const obj = {
    sourceTool: 'config_anonymizer',
    vendor: STATE.vendor,
    generatedAt: new Date().toISOString(),
    mappings: buildMappingSnapshot(m)
  };
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type:'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'anonymize-mapping.json'; a.click();
  URL.revokeObjectURL(url);
  markMappingSaved();
}

// 匯入既有對照表（跨工具聯動，見 log_analyzer 的對應功能與本檔 applyImportedMappings()）：
// 讀取使用者上傳的 mapping.json（本工具或 log_analyzer 匯出皆可），套用純函式邏輯後回饋
// 匯入筆數，並重繪對照表分頁讓使用者立刻看到結果。DOM 相關，不進純函式測試沙箱。
function importMappingFile(file) {
  const reader = new FileReader();
  reader.onerror = () => alert(tr('msg.file_read_error'));
  reader.onload = () => {
    let parsed;
    try { parsed = JSON.parse(reader.result); }
    catch (e) { alert(tr('msg.mapping_import_invalid')); return; }
    const { applied, skipped } = applyImportedMappings(parsed);
    const total = Object.values(applied).reduce((a, b) => a + b, 0);
    const label = document.getElementById('mapping-import-status');
    if (total === 0 && skipped === 0) {
      alert(tr('msg.mapping_import_invalid'));
      return;
    }
    if (label) {
      label.textContent = tr('msg.mapping_imported').replace('{n}', total);
      label.style.display = '';
    }
    renderMappingTable();
  };
  reader.readAsText(file, 'UTF-8');
}
function onMappingImportSelect(e) { if (e.target.files[0]) importMappingFile(e.target.files[0]); }

function downloadAnonymized() {
  if (!STATE.anonymized) return;
  // 2026-09 資安審查修復：畫面上的 #warn-list 只是被動顯示，先前沒有任何地方擋下匯出/複製
  // 動作，使用者可能沒注意到警告清單就直接把還沒去識別化乾淨的設定檔傳出去，補一道確認攔截
  if (getActiveResidualWarnings().length && !confirm(tr('warn.residual_confirm'))) return;
  const ext = STATE.filename ? STATE.filename.replace(/^.*(\.[^.]+)$/, '$1') : '.txt';
  const base = STATE.filename ? STATE.filename.replace(/\.[^.]+$/, '') : 'config';
  const blob = new Blob([STATE.anonymized], { type:'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `${base}-anonymized${ext}`; a.click();
  URL.revokeObjectURL(url);
  if (!STATE.mappingExported) showMapRemind();
}

async function copyToClipboard() {
  if (!STATE.anonymized) return;
  if (getActiveResidualWarnings().length && !confirm(tr('warn.residual_confirm'))) return;
  try {
    await navigator.clipboard.writeText(STATE.anonymized);
    const btn = document.getElementById('btn-copy');
    const btnSpan = btn.querySelector('[data-i18n]');
    if (btnSpan) btnSpan.textContent = tr('status.copied_short'); else btn.textContent = tr('status.copied_short');
    setTimeout(() => { if (btnSpan) btnSpan.textContent = tr('btn.copy'); else btn.textContent = tr('btn.copy'); }, 1500);
  } catch {}
}

// ============================================================
// [9] UI
// ============================================================
let _syncScrolling = false;
function syncScroll(src, targetId) {
  if (_syncScrolling) return;
  _syncScrolling = true;
  const target = document.getElementById(targetId);
  if (target) { target.scrollTop = src.scrollTop; target.scrollLeft = src.scrollLeft; }
  _syncScrolling = false;
}

// 返回回報區塊的浮動按鈕只在回報流程中需要（從回報區塊點「查看差異」或由其他工具帶入回報）；
// 回報區塊在任何去識別化完成後都會顯示，原本只看區塊是否顯示，一般使用也會一直浮在對照窗上
let _reportBackWanted = false;
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  const navEl = document.getElementById('nav-' + name);
  if (navEl) navEl.classList.add('active');
  placeMapRemind();
  // 回報流程（2026-09-29 新增）：開過差異頁即記為已查看；回報區塊顯示中才在差異頁顯示返回按鈕
  if (name === 'preview' && STATE.anonymized) { STATE.reportDiffViewed = true; updateReportState(); }
  const back = document.getElementById('report-back-btn');
  const sec = document.getElementById('report-section');
  if (back) back.style.display = (name === 'preview' && sec && sec.style.display !== 'none' && (_reportBackWanted || STATE.reportMeta)) ? '' : 'none';
}

// ── 功能 A：自訂 Regex 規則 ────────────────────────────────────────
const customRules = [];
let _ruleIdSeq = 0;
const _ruleDebounce = {};

function addCustomRule() {
  customRules.push({ id: ++_ruleIdSeq, pattern: '', replacement: '', enabled: true });
  renderCustomRules();
}
// 通用敏感樣式規則範本庫（2026-09-14 新增）：一鍵套用常見敏感樣式，省去使用者自行手刻
// regex 的門檻；沿用既有 addCustomRule() 資料結構，只是預先填好 pattern/replacement
// 而非空白起始，套用後立刻算一次命中數＋預覽高亮（比照使用者手動輸入後的既有行為）
function addCustomRuleFromTemplate(pattern, replacement) {
  const id = ++_ruleIdSeq;
  customRules.push({ id, pattern, replacement, enabled: true });
  updateRuleMatchCount(id);
  renderCustomRules();
}
function addEmailRuleTemplate() {
  addCustomRuleFromTemplate('[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', 'REDACTED_EMAIL');
}
// 公司網域範本：若「公司網域尾綴」欄位已填值則直接沿用（跳脫特殊字元後組成精確比對），
// 否則退回一般性的網域樣式（讓使用者自行填入實際網域再套用）
function addCompanyDomainRuleTemplate() {
  const inp = document.getElementById('opt-company-domain');
  const suffix = COMPANY_DOMAIN_SUFFIX || (inp ? inp.value.trim() : '');
  const pattern = suffix
    ? suffix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    : '[a-zA-Z0-9-]+\\.(com|net|org|local)';
  addCustomRuleFromTemplate(pattern, 'REDACTED_DOMAIN');
}
// 弱 SNMP community 範本：僅涵蓋業界公認的預設弱名稱（public/private），比照 switch_analyzer/
// firewall_analyzer 既有稽核規則同款判斷範圍，不臆測其他自訂命名慣例
function addWeakSnmpCommunityRuleTemplate() {
  addCustomRuleFromTemplate('\\b(public|private)\\b', 'REDACTED_COMMUNITY');
}
function removeCustomRule(id) {
  const i = customRules.findIndex(r => r.id === id);
  if (i >= 0) customRules.splice(i, 1);
  renderCustomRules();
}
function toggleCustomRule(id) {
  const r = customRules.find(r => r.id === id);
  if (r) { r.enabled = !r.enabled; renderCustomRules(); }
}
// 匯出/匯入自訂規則（2026-09 新增）：直接複用 exportMapping()/importMappingFile() 的既有模式
// （Blob+<a download> 下載、FileReader+JSON.parse+alert() 錯誤提示）；不匯出 id（匯入時用
// ++_ruleIdSeq 重新指派，避免與既有規則的 id 衝突），純本地自訂規則不需要跨工具 schema 相容。
// 稽核摘要匯出（2026-09-14 新增）：比照 exportCustomRules() 的 Blob+<a download> JSON 匯出
// 樣式，內容刻意只含數量統計與中繼資料，不含任何機敏值本身（IP/hostname/使用者名稱等映射
// 內容一律不寫入），可放心分享給第三方稽核或留存紀錄使用
function exportAuditSummary() {
  if (!STATE.anonymized) return;
  const obj = {
    sourceTool: 'config_anonymizer',
    generatedAt: new Date().toISOString(),
    vendor: STATE.vendor,
    filename: STATE.filename,
    stats: { ...stats },
    residualWarningCount: getResidualWarnings().length,
    residualWarningDismissedCount: dismissedResidualKeys.size,
  };
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type:'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'anonymize-audit-summary.json'; a.click();
  URL.revokeObjectURL(url);
}
function exportCustomRules() {
  const obj = {
    sourceTool: 'config_anonymizer',
    generatedAt: new Date().toISOString(),
    rules: customRules.map(r => ({ pattern: r.pattern, replacement: r.replacement, enabled: r.enabled })),
  };
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type:'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'anonymize-custom-rules.json'; a.click();
  URL.revokeObjectURL(url);
}
function importCustomRulesFile(file) {
  const reader = new FileReader();
  reader.onerror = () => alert(tr('msg.file_read_error'));
  reader.onload = () => {
    let parsed;
    try { parsed = JSON.parse(reader.result); }
    catch (e) { alert(tr('msg.rules_import_invalid')); return; }
    const rules = Array.isArray(parsed.rules) ? parsed.rules : (Array.isArray(parsed) ? parsed : null);
    if (!rules) { alert(tr('msg.rules_import_invalid')); return; }
    let n = 0;
    rules.forEach(r => {
      if (!r || typeof r.pattern !== 'string') return;
      customRules.push({ id: ++_ruleIdSeq, pattern: r.pattern, replacement: String(r.replacement || ''), enabled: r.enabled !== false });
      n++;
    });
    if (n === 0) { alert(tr('msg.rules_import_invalid')); return; }
    renderCustomRules();
    const label = document.getElementById('rules-import-status');
    if (label) { label.textContent = tr('msg.rules_imported').replace('{n}', n); label.style.display = ''; }
  };
  reader.readAsText(file, 'UTF-8');
}
function onCustomRulesImportSelect(e) { if (e.target.files[0]) importCustomRulesFile(e.target.files[0]); }
function renderCustomRules() {
  const wrap = document.getElementById('custom-rules-list');
  if (!wrap) return;
  if (!customRules.length) { wrap.innerHTML = ''; return; }
  wrap.innerHTML = customRules.map(r => {
    const valid = !r.pattern || _isValidRegex(r.pattern);
    const hits = r._hits != null ? r._hits : -1;
    const badgeCls = !r.pattern ? 'rule-badge' : (!valid ? 'rule-badge err' : (hits > 0 ? 'rule-badge hit' : 'rule-badge'));
    const badgeTxt = !r.pattern ? '' : (!valid ? esc(tr('opt.rule_invalid')) : (hits >= 0 ? tr('opt.rule_hits').replace('{n}', hits) : ''));
    const redosRisky = valid && isRedosRisky(r.pattern);
    return `<div class="rule-row">
      <div class="rule-row-head">
        <label class="toggle" style="margin:0;flex-shrink:0"><input type="checkbox" ${r.enabled?'checked':''} onchange="toggleCustomRule(${r.id})"><span class="slider"></span></label>
        <span class="rule-badge">#${r.id}</span>
        <button class="rule-del" onclick="removeCustomRule(${r.id})" title="${tr('btn.delete')}">✕</button>
        ${badgeTxt ? `<span class="${badgeCls}">${badgeTxt}</span>` : ''}
        ${redosRisky ? `<span data-tip="${esc(tr('opt.rule_redos_risk'))}" style="cursor:help">⚠️</span>` : ''}
      </div>
      <input class="rule-input${valid?'':' invalid'}" placeholder="${esc(tr('opt.rule_pattern'))}" value="${esc(r.pattern)}"
        oninput="onRulePatternInput(${r.id},this.value)">
      <input class="rule-input" placeholder="${esc(tr('opt.rule_replacement'))}" value="${esc(r.replacement)}"
        oninput="onRuleReplInput(${r.id},this.value)">
    </div>`;
  }).join('');
}
function onRulePatternInput(id, val) {
  const r = customRules.find(r => r.id === id);
  if (!r) return;
  r.pattern = val;
  r._hits = -1;
  clearTimeout(_ruleDebounce[id]);
  _ruleDebounce[id] = setTimeout(() => { updateRuleMatchCount(id); renderCustomRules(); }, 300);
}
function onRuleReplInput(id, val) {
  const r = customRules.find(r => r.id === id);
  if (r) r.replacement = val;
}
function _isValidRegex(p) {
  try { new RegExp(p); return true; } catch(e) { return false; }
}
// ReDoS 高風險樣式偵測（2026-09-18 新增，全專案首次；非完整靜態分析，僅偵測最常見的巢狀量詞
// 災難性回溯樣式，如 (a+)+／(a*)+／(a+)*／(a{2,})+；語法合法但可能是效能陷阱時純視覺警示，
// 不阻擋儲存或執行，尊重使用者對自己規則的判斷，比照既有 _isValidRegex() 非阻擋式慣例）
const REDOS_RISK_RE = /\([^()]*[+*]\)[+*]|\([^()]*\{\d*,\}?\)[+*{]/;
function isRedosRisky(pattern) {
  if (!pattern) return false;
  if (pattern.length > 300) return true;
  return REDOS_RISK_RE.test(pattern);
}
function updateRuleMatchCount(id) {
  const r = customRules.find(r => r.id === id);
  if (!r || !r.pattern || !_isValidRegex(r.pattern)) { clearRulePreviewHighlight(); return; }
  const src = STATE.original || (document.getElementById('paste-input') ? document.getElementById('paste-input').value : '');
  if (!src) return;
  try { r._hits = (src.match(new RegExp(r.pattern, 'g')) || []).length; } catch(e) { r._hits = -1; }
  highlightRulePreview(r);
}
// 自訂規則即時預覽命中（2026-09-14 新增）：使用者編輯 pattern 時（沿用既有 300ms debounce），
// 除了既有的命中「數量」統計，額外在 #orig-body 對應行號上加 .rule-preview-hit class，讓
// 使用者不用等按下「開始去識別化」就能看到這條規則實際會命中哪些行；僅在已載入設定檔
// （STATE.original 非空、#orig-body 已渲染過內容）時生效
function clearRulePreviewHighlight() {
  document.querySelectorAll('#orig-body .rule-preview-hit').forEach(el => el.classList.remove('rule-preview-hit'));
}
function highlightRulePreview(rule) {
  clearRulePreviewHighlight();
  if (!STATE.original || !rule.pattern || !_isValidRegex(rule.pattern)) return;
  const origBody = document.getElementById('orig-body');
  if (!origBody) return;
  const lineEls = origBody.querySelectorAll('.code-line');
  if (!lineEls.length) return;
  let re;
  try { re = new RegExp(rule.pattern); } catch(e) { return; }
  STATE.original.split('\n').forEach((line, i) => {
    if (lineEls[i] && re.test(line)) lineEls[i].classList.add('rule-preview-hit');
  });
}
function applyCustomRules(text) {
  let out = text;
  for (const r of customRules) {
    if (!r.enabled || !r.pattern || !_isValidRegex(r.pattern)) continue;
    try { out = out.replace(new RegExp(r.pattern, 'g'), r.replacement); } catch(e) {}
  }
  return out;
}

// ── 功能 B：還原驗證 diff ───────────────────────────────────────────
function buildRestoreDiff(anonText, restoredText) {
  const aLines = anonText.split('\n');
  const rLines = restoredText.split('\n');
  const len = Math.max(aLines.length, rLines.length);
  let nRestored = 0, nRedacted = 0, nUnchanged = 0;
  const rows = [];
  for (let i = 0; i < len; i++) {
    const a = aLines[i] ?? '';
    const r = rLines[i] ?? '';
    let cls = '', status = '';
    if (a === r) {
      if (/REDACTED_/.test(r)) { cls = 'diff-row-redacted'; nRedacted++; status = '🔒'; }
      else { cls = 'diff-row-unchanged'; nUnchanged++; }
    } else {
      if (/REDACTED_/.test(r)) { cls = 'diff-row-redacted'; nRedacted++; status = '🔒'; }
      else { cls = 'diff-row-restored'; nRestored++; status = '✓'; }
    }
    rows.push({ ln: i+1, a, r, cls, status });
  }
  // summary
  const wrap = document.getElementById('restore-diff-wrap');
  const sumEl = document.getElementById('restore-diff-summary');
  const bodyEl = document.getElementById('restore-diff-body');
  if (!wrap) return;
  sumEl.innerHTML = [
    `<div class="diff-stat green"><span>✓</span><span>${tr('diff.restored').replace('{n}', nRestored)}</span></div>`,
    `<div class="diff-stat orange"><span>🔒</span><span>${tr('diff.redacted').replace('{n}', nRedacted)}</span></div>`,
    `<div class="diff-stat gray"><span>─</span><span>${tr('diff.unchanged').replace('{n}', nUnchanged)}</span></div>`,
  ].join('');
  // table — fold unchanged runs > 3
  let html = '<table class="diff-table">';
  let i = 0;
  while (i < rows.length) {
    const row = rows[i];
    if (row.cls === 'diff-row-unchanged') {
      // collect consecutive unchanged
      let j = i;
      while (j < rows.length && rows[j].cls === 'diff-row-unchanged') j++;
      const count = j - i;
      if (count > 5) {
        // show first 2
        for (let k = i; k < i+2; k++) html += _diffRow(rows[k]);
        html += `<tr><td colspan="3" style="text-align:center;color:var(--text-muted);font-size:10px;padding:4px">… ${count-4} 行未變動 …</td></tr>`;
        for (let k = j-2; k < j; k++) html += _diffRow(rows[k]);
      } else {
        for (let k = i; k < j; k++) html += _diffRow(rows[k]);
      }
      i = j;
    } else {
      html += _diffRow(row);
      i++;
    }
  }
  html += '</table>';
  bodyEl.innerHTML = html;
  wrap.style.display = '';
}
function _diffRow(row) {
  return `<tr class="${row.cls}"><td>${row.ln}</td><td>${esc(row.r)}${row.status ? ' <span style="opacity:.5;font-size:9px">'+row.status+'</span>' : ''}</td></tr>`;
}

// ── 功能 C：批次處理 ────────────────────────────────────────────────
const BATCH = { files: [] };

function batchDragOver(e) { e.preventDefault(); document.getElementById('batch-drop').classList.add('drag-over'); }
function batchDragLeave(e) { document.getElementById('batch-drop').classList.remove('drag-over'); }
function batchDrop(e) {
  e.preventDefault();
  document.getElementById('batch-drop').classList.remove('drag-over');
  batchAddFiles([...e.dataTransfer.files]);
}
function batchSelect(e) { batchAddFiles([...e.target.files]); e.target.value = ''; }
function batchAddFiles(files) {
  let pending = files.length;
  if (!pending) return;
  for (const f of files) {
    const reader = new FileReader();
    reader.onerror = () => alert(tr('msg.file_read_error'));
    reader.onload = ev => {
      BATCH.files.push({ name: f.name, text: ev.target.result, vendor: null, status: 'pending', result: null, mapping: null });
      if (--pending === 0) renderBatchList();
    };
    reader.readAsText(f, 'UTF-8');
  }
}
function renderBatchList() {
  const list = document.getElementById('batch-file-list');
  const ctrl = document.getElementById('batch-controls');
  if (!list) return;
  if (!BATCH.files.length) { list.innerHTML = ''; if (ctrl) ctrl.style.display = 'none'; return; }
  if (ctrl) ctrl.style.display = '';
  list.innerHTML = BATCH.files.map((f, i) => {
    const vl = f.vendor ? (VENDOR_LABELS[f.vendor] || f.vendor) : (f.status === 'pending' ? `<span style="opacity:.5">${tr('upload.vendor_auto')}</span>` : '');
    const sc = f.status === 'done' ? 'p-allow' : f.status === 'error' ? 'p-deny' : f.status === 'processing' ? 'p-warn' : 'p-dim';
    const st = tr('batch.' + f.status) || f.status;
    // 殘留警告徽章（2026-09-21 新增）：單檔模式的 downloadAnonymized()/copyToClipboard() 皆有
    // getActiveResidualWarnings() 攔截，批次模式先前完全沒有這道安全網——批量處理場景風險
    // 更高，保護反而更少
    const residualBadge = (f.status === 'done' && f.residualWarnings && f.residualWarnings.length)
      ? `<span class="pill p-warn" style="font-size:10px" data-tip="${esc(tr('batch.residual_hint'))}">⚠ ${f.residualWarnings.length}</span>` : '';
    return `<div class="batch-file-row">
      <span class="batch-file-name" title="${esc(f.name)}">${esc(f.name)}</span>
      <span style="font-size:10px;color:var(--text-muted)">${vl}</span>
      <span class="pill ${sc}" style="font-size:10px">${esc(st)}</span>
      ${residualBadge}
    </div>`;
  }).join('');
  const zipBtn = document.getElementById('btn-batch-zip');
  if (zipBtn) zipBtn.disabled = !BATCH.files.every(f => f.status === 'done');
  const mapBtn = document.getElementById('btn-batch-map');
  if (mapBtn) mapBtn.disabled = !BATCH.files.length || !BATCH.files.every(f => f.status === 'done');
}
async function runBatch() {
  BATCH.mappingExported = false; hideMapRemind();
  const opts = getOpts();
  const prog = document.getElementById('batch-progress');
  // 2026-09-22 新增：批次內共用映射開關（預設關閉，維持既有逐檔重置行為向下相容）。開啟後
  // 同一批次上傳同一站點多台設備時，相同的真實 IP/主機名稱在不同檔案間會得到相同假值，方便
  // 使用者用假名跨檔案關聯分析。實際重置與否交由 anonymize() 第 4 參數 keepState 控制
  // （anonymize() 本身每次呼叫本來就會無條件重置 mappings/ctrs/stats/bucketSeen，若只在
  // runBatch() 這層跳過重置、anonymize() 內部仍會重置一次，等於完全無效）。
  const sharedMapping = !!document.getElementById('opt-batch-shared-mapping')?.checked;
  // 2026-09-22（續，bug fix）：sharedMapping 是整批次固定不變的布林值，若直接原樣傳給每一檔案
  // 的 anonymize() 當 keepState，批次「第一個」檔案也會跳過重置，沿用批次開始「前」殘留在全域
  // mappings 裡的任何舊狀態（可能來自稍早的單檔模式操作、或前一次已執行完的另一個批次），使匯出
  // 的 mapping-all.json 混入不屬於這批檔案的真實 IP/主機名稱對應，與 UI 文案「批次『內』共用
  // 映射」語意不符。改用 isFirstInRun 追蹤「這次 runBatch() 執行以來是否已經嘗試呼叫過
  // anonymize()」，只有真正執行到 anonymize() 那一行才消耗（`continue` 跳過的已完成檔案不消
  // 耗），確保批次的第一次有效處理必定重置，之後才依 sharedMapping 決定是否保留狀態。
  // isFirstInRun 在呼叫前（try 區塊外）就先翻成 false，即使該次 anonymize() 之後拋錯，也視為
  // 「已嘗試過」不再是首檔——若第一個檔案處理失敗，第二個檔案不會被誤判成本次執行的首檔而又
  // 觸發一次多餘重置，維持後續檔案彼此間的映射一致性。
  let isFirstInRun = true;
  for (let i = 0; i < BATCH.files.length; i++) {
    const f = BATCH.files[i];
    if (f.status === 'done') continue;
    f.status = 'processing';
    f.vendor = detectVendor(f.text);
    renderBatchList();
    if (prog) prog.textContent = `${i+1} / ${BATCH.files.length}`;
    await new Promise(r => setTimeout(r, 0)); // yield to UI
    const keepState = sharedMapping && !isFirstInRun;
    isFirstInRun = false;
    try {
      f.result = applyCustomRules(anonymize(f.text, f.vendor, opts, keepState));
      f.mapping = buildMappingSnapshot(mappings);
      f.residualWarnings = checkResidual(f.result);
      f.status = 'done';
    } catch(e) { f.status = 'error'; f.errMsg = String(e); }
    renderBatchList();
  }
  if (prog) prog.textContent = tr('batch.summary').replace('{n}', BATCH.files.filter(f=>f.status==='done').length).replace('{r}', BATCH.files.reduce((s,f)=>s+(f.mapping?Object.keys(f.mapping.ip||{}).length+Object.keys(f.mapping.hostname||{}).length:0),0));
  // restore STATE mappings from last single-file operation if any
}
function clearBatch() {
  BATCH.files = [];
  document.getElementById('batch-progress').textContent = '';
  renderBatchList();
}
function downloadBatchZip() {
  // 殘留警告聚合攔截（2026-09-21 新增），比照單檔模式既有 getActiveResidualWarnings() 攔截
  // 精神，先於既有的「匯出對照表」通用確認彈窗檢查
  const totalResidual = BATCH.files.reduce((s, f) => s + ((f.residualWarnings && f.residualWarnings.length) || 0), 0);
  if (totalResidual && !confirm(tr('warn.residual_confirm'))) return;
  // RV4：zip 只放去識別化結果與摘要；對照表（含原始資料）改由「匯出批次對照表」另外下載，避免整包寄出時一併外流
  const entries = [];
  for (const f of BATCH.files) {
    if (f.status !== 'done') continue;
    const base = f.name.replace(/\.[^.]+$/, '');
    const ext  = (f.name.match(/\.([^.]+)$/) || ['','.txt'])[1];
    entries.push({ name: base + '-anonymized.' + ext, data: _strToU8(f.result) });
  }
  const summary = BATCH.files.map(f => `${f.name}\t${f.vendor||'unknown'}\t${tr('batch.'+f.status)}\t${(f.residualWarnings&&f.residualWarnings.length)||0}`).join('\n');
  entries.push({ name: 'batch-summary.txt', data: _strToU8('Filename\tVendor\tStatus\tResidualWarnings\n' + summary) });
  const blob = makeZip(entries);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'anonymized-batch.zip'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  if (!BATCH.mappingExported) showMapRemind(true);
}
// 批次對照表（RV4）：格式與原本 zip 內的 mapping-all.json 相同，單獨下載
function exportBatchMapping() {
  const done = BATCH.files.filter(f => f.status === 'done');
  if (!done.length || !confirm(tr('warn.export_map_confirm'))) return;
  const allMappings = {};
  done.forEach(f => { allMappings[f.name] = f.mapping; });
  const blob = new Blob([JSON.stringify({ generatedAt: new Date().toISOString(), files: allMappings }, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'mapping-all.json'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  BATCH.mappingExported = true; hideMapRemind();
}

// ── 純 JS ZIP 寫入器（STORED 無壓縮）──────────────────────────────
function _strToU8(s) {
  return new TextEncoder().encode(s);
}
// 寫入器在共用 toolkit-data.js；entries：[{name, data: Uint8Array}]
function makeZip(entries) {
  return new Blob([ToolkitData.createZip(entries)], { type: 'application/zip' });
}

function setButtons(enabled) {
  ['btn-copy','btn-export-map','btn-export-encrypted','btn-download','btn-reset'].forEach(id => {
    document.getElementById(id).disabled = !enabled;
  });
}

function onDragOver(e) { e.preventDefault(); document.getElementById('drop-zone').classList.add('dragover'); }
function onDragLeave() { document.getElementById('drop-zone').classList.remove('dragover'); }
function onDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) loadFile(file);
}
function onFileSelect(e) { if (e.target.files[0]) loadFile(e.target.files[0]); }

function loadFile(file) {
  STATE.filename = file.name;
  document.getElementById('file-name-label').textContent = '📄 ' + file.name;
  document.getElementById('file-name-label').style.display = '';
  const reader = new FileReader();
  reader.onerror = () => alert(tr('msg.file_read_error'));
  reader.onload = e => {
    document.getElementById('paste-input').value = e.target.result;
  };
  reader.readAsText(file, 'UTF-8');
}

// 內建範例（PD，2026-09-29 新增）：第一次使用可一鍵試用；只用 RFC 5737 文件用 IP，並刻意含幾項稽核會標出的問題
const ANON_SAMPLE_CONFIG = "! Sample config - RFC 5737 documentation IPs only, not a real device\nversion 15.2\nhostname SAMPLE-SW01\n!\nenable secret 5 $1$SMPL$SampleHashOnly000000\nusername admin privilege 15 secret 0 Sample-Pass1\n!\nvlan 10\n name USERS\nvlan 20\n name SERVERS\nvlan 99\n name MGMT\n!\ninterface GigabitEthernet1/0/1\n description PC-01\n switchport mode access\n switchport access vlan 10\n spanning-tree portfast\n!\ninterface GigabitEthernet1/0/2\n description SERVER-01\n switchport mode access\n switchport access vlan 20\n!\ninterface GigabitEthernet1/0/3\n shutdown\n!\ninterface GigabitEthernet1/0/24\n description UPLINK-CORE\n switchport mode trunk\n switchport trunk allowed vlan 10,20,99\n!\ninterface Vlan99\n ip address 192.0.2.10 255.255.255.0\n!\nip route 0.0.0.0 0.0.0.0 192.0.2.1\nsnmp-server community public RO\nlogging host 198.51.100.20\n!\nline vty 0 4\n transport input telnet\n!\nend\n";
function loadSampleConfig() {
  document.getElementById('paste-input').value = ANON_SAMPLE_CONFIG;
  document.getElementById('vendor-sel').value = 'auto';
  runAnonymize();
}
// 入口頁「看範例」（第二十九輪 NU4）：網址帶 ?demo=1 時開頁即載入範例並分析
// DOMContentLoaded 而非 load：load 會等外部字型樣式表，連不到 Google Fonts 時範例要等到逾時才出現
document.addEventListener('DOMContentLoaded', function () { if (/[?&]demo=1(?:&|$)/.test(location.search)) setTimeout(function () { loadSampleConfig(); }, 0); });

// 首次使用導覽（第二十九輪 NU6）：上傳區的三步驟提示，持續性 key `_netAnalyzer_tourSeen`（{工具:1}，已加入入口頁 WS_KEYS）；
// 按「知道了」或第一次分析出結果後不再顯示。行內卡片不覆蓋畫面
function tourInit(){const el=document.getElementById('tour');if(el&&!_tourSeen()['anon'])el.hidden=false;}
function tourDone(){const el=document.getElementById('tour');if(el)el.hidden=true;try{const s=_tourSeen();if(s['anon'])return;s['anon']=1;localStorage.setItem('_netAnalyzer_tourSeen',JSON.stringify(s));}catch(e){}}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',tourInit);else tourInit();
// 描述／備註未遮蔽提示（UX25）：「遮蔽備註」關閉時，輸出中仍有 description／remark／comment 等行就提醒，
// 一鍵開啟後重新去識別化；不改預設（描述常是排錯需要的資訊）
const DESC_LINE_RE = /^\s*(?:description|desc|remark|comment|comments|alias)\s*[=:]?\s*\S/i;
function countPlainDescLines(text) {
  return String(text || '').split('\n').filter(l => !/REDACTED/.test(l) && (DESC_LINE_RE.test(l) || GENERIC_DESC_RE.test(l))).length;
}
function renderDescWarn() {
  const box = document.getElementById('desc-warn');
  if (!box) return;
  const on = document.getElementById('opt-comments').checked;
  const n = on ? 0 : countPlainDescLines(STATE.anonymized);
  if (!n) { box.style.display = 'none'; box.textContent = ''; return; }
  box.textContent = '';
  const msg = document.createElement('span'); msg.textContent = tr('desc.warn').replace('{n}', n) + ' ';
  const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'btn btn-sm'; btn.textContent = tr('desc.mask_btn');
  btn.addEventListener('click', () => { document.getElementById('opt-comments').checked = true; runAnonymize(); });
  box.append(msg, btn);
  box.style.display = 'block';
}
function runAnonymize() {
  // 交接提示列（XN56）完成任務，執行後收起
  if (_handoff) { _handoff = null; renderHandoffBar(); }
  var _hf = document.getElementById('anon-btn'); if (_hf) _hf.classList.remove('handoff-focus');
  const text = document.getElementById('paste-input').value.trim();
  if (!text) return;
  STATE.mappingExported = false; hideMapRemind();
  STATE.original = text;
  // 可疑注入字串彩蛋（XN20，payload-sniff.js）：只提示，不影響分析
  if (typeof PayloadSniff !== 'undefined') PayloadSniff.notify(text, _lang, m => showEggToast(m, 7000));
  const opts = getOpts();

  // Vendor detection
  const sel = document.getElementById('vendor-sel').value;
  // 候選清單只在「自動偵測」模式下才有意義（手動選定廠牌時使用者已明確決定，不需要提示）
  let vendor, vendorCandidates = [];
  if (sel === 'auto') {
    const d = detectVendorCandidates(text);
    vendor = d.vendor;
    vendorCandidates = d.candidates;
  } else {
    vendor = sel;
  }
  STATE.vendor = vendor;
  STATE.vendorCandidates = vendorCandidates;

  // Run anonymization
  STATE.anonymized = applyCustomRules(anonymize(text, vendor, opts));
  // 彩蛋：原文有 114.51.4.x 或 11.45.14.x（第二十七輪），同一頁面只提示一次
  if (!window._smellyIpShown && /(?:^|[^\d.])(?:114\.51\.4|11\.45\.14)\.\d{1,3}(?![\d.])/m.test(text)) {
    window._smellyIpShown = true;
    setTimeout(() => showEggToast(tr('egg.smelly_ip')), 800);
  }
  // 快照這次的 mappings（見 STATE 宣告處註解），供匯出功能專用，不受後續批次操作影響
  // 2026-09-21 修復：先前僅快照 4 類（缺 ssid/alias/vdom），buildMappingSnapshot() 統一匯出路徑
  // 改為要求全部 7 類後，exportMapping()/doExportEncrypted() 優先讀取此快照，m.ssid 等值為
  // undefined 時 Object.fromEntries(undefined) 會直接拋錯——單檔模式匯出因而全面壞掉，改用
  // MAPPING_CATEGORIES 統一權威清單迭代，避免同一種遺漏再度發生
  STATE.mappings = {};
  MAPPING_CATEGORIES.forEach(cat => { STATE.mappings[cat] = new Map(mappings[cat]); });

  // Update vendor badge
  const badge = document.getElementById('vendor-badge');
  badge.textContent = vendor === 'unknown' ? tr('upload.vendor_unknown') : (vendorBrandLabel(vendor, STATE.original) || VENDOR_LABELS[vendor] || vendor);
  badge.style.display = '';

  // Render diff
  const { origHTML, anonHTML, changedCount, totalLines } = renderDiff(STATE.original, STATE.anonymized);
  document.getElementById('orig-body').innerHTML = '<pre>' + origHTML + '</pre>';
  document.getElementById('anon-body').innerHTML = '<pre>' + anonHTML + '</pre>';
  document.getElementById('orig-line-cnt').textContent = totalLines + ' ' + tr('unit.line');
  document.getElementById('anon-line-cnt').textContent = totalLines + ' ' + tr('unit.line');
  document.getElementById('changed-cnt').textContent = changedCount + ' ' + tr('unit.changed');

  // Stats
  renderStats(vendor, changedCount);
  const _sc = document.getElementById('struct-check-result'); if (_sc) _sc.textContent = '';
  const _sb = document.getElementById('btn-struct-check'); if (_sb) _sb.disabled = !structCheckTool(vendor, text);
  STATE.lastStats = stats;
  renderAnonSummary(stats);
  renderDescWarn();

  // Mapping table
  renderMappingTable();

  // Enable buttons
  setButtons(true);

  // Navigate to preview（由其他工具帶入的回報流程改到統計頁，回報區塊與殘留警告同頁）
  _reportBackWanted = false;
  renderReportSection(true);
  if (STATE.reportMeta) {
    showView('log');
    const _rs = document.getElementById('report-section');
    if (_rs && _rs.scrollIntoView) _rs.scrollIntoView({ block: 'start' });
  } else {
    showView('preview');
  }

  // Phase 4 第 18 項：原本僅在 hub「去識別化後分析」流程才顯示，改為匿名化完成就一律顯示
  // 送往工具的按鈕＋選單，讓使用者可主動選擇轉送目標（不限於 hub 流程帶入的那一個）
  var _chainBtn = document.getElementById('btn-send-to-tool');
  var _chainSel = document.getElementById('send-to-tool-select');
  if (_chainBtn) _chainBtn.style.display = '';
  if (_chainSel) {
    _chainSel.style.display = '';
    if (_anonChainTarget) {
      var _idx = TOOL_HREFS.indexOf(_anonChainTarget.href);
      if (_idx >= 0) _chainSel.value = String(_idx);
    } else if (!_chainSel.dataset.touched) {
      // UX27：依偵測到的廠牌預設送往的工具（沿用結構保持度自檢的判斷）；使用者改過就不再覆蓋
      var _def = defaultSendTool(vendor, STATE.original);
      if (_def >= 0) _chainSel.value = String(_def);
    }
  }

  // Phase 4 第 17 項：rolling history 供 network_analyzer hub 顯示「最近由去識別化工具處理」
  // 摘要卡片；無 TTL（持續累積的小型歷史，非一次性交接），僅保留最近 5 筆
  try {
    var _hist = [];
    try { _hist = JSON.parse(localStorage.getItem('_netAnalyzer_anonHistory') || '[]'); } catch(e) { _hist = []; }
    _hist.unshift({ name: STATE.filename || '', vendor: vendor || null, ts: Date.now() });
    localStorage.setItem('_netAnalyzer_anonHistory', JSON.stringify(_hist.slice(0, 5)));
  } catch(e) { /* localStorage 滿了或被封鎖時靜默略過，不影響匿名化主流程 */ }
  tourDone();

  // ── 條件型彩蛋 ────────────────────────────────────────────
  // 彩蛋2：特殊 hostname（涵蓋 sysname/hostname/set hostname）
  const _hnm = STATE.original.match(/(?:^|\n)\s*(?:sysname|hostname|set\s+hostname)\s+"?([^\s"#\r\n]+)"?/i);
  if(_hnm) {
    const _h = _hnm[1].toLowerCase();
    const _SHN = {skynet:tr('egg.skynet'), hal9000:tr('egg.hal9000'), hal9:tr('egg.hal9000'), jarvis:tr('egg.jarvis'), gandalf:tr('egg.gandalf'), skywalker:tr('egg.skywalker'), ollama:tr('egg.ollama'), alpaca:tr('egg.ollama')};
    for(const [k,v] of Object.entries(_SHN)) if(_h.includes(k)) { setTimeout(()=>showEggToast(v),1200); break; }
  }
  // 彩蛋3：深夜工程師模式
  const _hr = new Date().getHours();
  if(_hr >= 0 && _hr < 5) setTimeout(()=>showEggToast(tr('egg.late_night')),2000);
  // 彩蛋7：乾淨設定
  if(changedCount === 0) setTimeout(()=>showEggToast(tr('egg.clean_config')),1500);
}

// ── 結構保持度自檢（2026-10-02，第九輪發想 YD）──
// 以隱藏 iframe 開啟對應分析工具（?structcheck=1，該頁不碰交接 key），postMessage 送出原始檔與
// 去識別化結果，對方各自解析後只回傳數量。不直接呼叫 iframe 內函式，離線 file:// 開啟時也能運作。
const STRUCT_FW_VENDORS = new Set(['fortigate','sophos','checkpoint','paloalto','pfsense','sonicwall','ciscoasa','zyxel','edgerouter','openwrt','watchguard','vyos','netfilter','cloudsg','checkpoint_api','h3c_secpath','tnsr','bigip']);
const STRUCT_LABELS = { vlans:'VLAN', interfaces:'Interface', routes:'Route', users:'User', acls:'ACL', lacp:'LACP', vrrp:'VRRP', dhcp:'DHCP', policies:'Policy', addresses:'Address', services:'Service', nat:'NAT', vpn:'VPN' };
// MikroTik／Juniper 兩個分析工具都支援：有防火牆規則／security 區塊時交給防火牆分析，否則交給交換器解析
// UX27：去識別化後「送往分析工具」的預設目標（TOOL_HREFS 索引）；無線控制器交給防火牆分析（WiFi 頁），
// NPS 設定與應用程式環境變數沒有對應的分析工具，回傳 -1 維持原選擇
function defaultSendTool(vendor, text) {
  if (vendor === 'wlc') return 0;
  if (vendor === 'nps_export' || vendor === 'appenv' || vendor === 'netscaler') return -1;
  const page = structCheckTool(vendor, text);
  return page ? TOOL_HREFS.indexOf(page) : -1;
}
function structCheckTool(vendor, text) {
  if (!vendor || vendor === 'unknown' || vendor === 'nps_export' || vendor === 'appenv' || vendor === 'netscaler') return null;
  if (STRUCT_FW_VENDORS.has(vendor)) return 'firewall-analyzer-fixed.html';
  if (vendor === 'mikrotik') return /^\/ip\s+firewall\s+(?:filter|nat)\b/m.test(text) ? 'firewall-analyzer-fixed.html' : 'switch-config-parser.html';
  if (vendor === 'juniper') return /^\s*security\s*\{|^set\s+security\s/m.test(text) ? 'firewall-analyzer-fixed.html' : 'switch-config-parser.html';
  // Cisco IOS 路由器（XN139）：沒有 switchport，且有 Zone-Based Firewall、inside source NAT 或 CBAC 時交給防火牆分析（與入口頁 _isIosRouterFw() 相同）
  if (vendor === 'cisco_ios') return !/^\s*switchport\b/m.test(text) && !/^feature \S+/m.test(text) &&
    (/^zone(?:-pair)? security \S+/m.test(text) || /^ip nat inside source /m.test(text) || /^ip inspect name /m.test(text)) ? 'firewall-analyzer-fixed.html' : 'switch-config-parser.html';
  return 'switch-config-parser.html';
}
// 只列出任一邊非零的項目；ok=false 代表數量不同
function compareStructCounts(a, b) {
  return Object.keys(a || {}).filter(k => (a[k] || 0) || ((b || {})[k] || 0))
    .map(k => ({ key: k, orig: a[k] || 0, anon: (b || {})[k] || 0, ok: (a[k] || 0) === ((b || {})[k] || 0) }));
}
// 分析結論比對（第十輪 ZO）：健康度分數＋每個命中的稽核項目數量；任一邊有的項目都列出。
// 回傳 null 代表分析工具沒回傳結論（不顯示這一段）
function compareStructAnalysis(ra, rb) {
  if (!ra || !rb || !ra.health || !rb.health) return null;
  const rows = [{ key: 'health', label: tr('struct.health_row'), orig: `${ra.health.score}（${ra.health.grade}）`, anon: `${rb.health.score}（${rb.health.grade}）`, ok: ra.health.score === rb.health.score }];
  const a = ra.audit || {}, b = rb.audit || {};
  [...new Set([...Object.keys(a), ...Object.keys(b)])].forEach(id => {
    const x = a[id], y = b[id];
    rows.push({ key: id, label: (x || y).label || id, orig: x ? x.v : 0, anon: y ? y.v : 0, ok: (x ? x.v : 0) === (y ? y.v : 0) });
  });
  return rows;
}
let _structSeq = 0;
function runStructCheck() {
  const out = document.getElementById('struct-check-result');
  const btn = document.getElementById('btn-struct-check');
  if (!out || !STATE.original || !STATE.anonymized) return;
  const page = structCheckTool(STATE.vendor, STATE.original);
  if (!page) { out.textContent = tr('struct.unknown_vendor'); return; }
  const id = 'sc' + (++_structSeq) + '_' + Date.now();
  const toolName = tr(page.startsWith('firewall') ? 'nav.tool_fw' : 'nav.tool_switch');
  out.textContent = tr('struct.running');
  if (btn) btn.disabled = true;
  const ifr = document.createElement('iframe');
  ifr.style.display = 'none';
  let timer = null;
  const done = msg => {
    window.removeEventListener('message', onMsg);
    clearTimeout(timer);
    ifr.remove();
    if (btn) btn.disabled = false;
    if (msg !== undefined) out.textContent = msg;
  };
  function onMsg(e) {
    if (e.source !== ifr.contentWindow || !e.data) return;
    if (e.data.type === '_naStructReady') {
      // 內容含原始設定檔：http(s) 下限定同源頁面才收得到；file:// 的 origin 是 'null'，只能用 '*'
      ifr.contentWindow.postMessage({ type: '_naStructCheck', id, texts: [STATE.original, STATE.anonymized] }, (location.protocol === 'file:' || location.origin === 'null') ? '*' : location.origin);
      return;
    }
    if (e.data.type !== '_naStructResult' || e.data.id !== id) return;
    const [ra, rb] = e.data.results || [];
    const err = (ra && ra.error) || (rb && rb.error);
    if (err || !ra || !rb) { done(tr('struct.parse_err').replace('{msg}', err || '-')); return; }
    const rows = compareStructCounts(ra.counts, rb.counts);
    const bad = rows.filter(r => !r.ok).length;
    done();
    const head = bad ? tr('struct.mismatch').replace('{n}', bad) : tr('struct.ok').replace('{tool}', toolName).replace('{n}', rows.length);
    out.innerHTML = `<div style="margin-bottom:6px;font-weight:600;color:${bad ? 'var(--orange)' : 'var(--green)'}">${esc(head)}</div>` +
      `<table class="struct-table" style="border-collapse:collapse"><tr><th style="text-align:left;padding:2px 10px 2px 0">${esc(tr('struct.col_item'))}</th><th style="padding:2px 10px">${esc(tr('struct.col_orig'))}</th><th style="padding:2px 10px">${esc(tr('struct.col_anon'))}</th><th></th></tr>` +
      rows.map(r => `<tr data-key="${esc(r.key)}"><td style="padding:2px 10px 2px 0">${esc(STRUCT_LABELS[r.key] || r.key)}</td><td style="text-align:right;padding:2px 10px">${r.orig}</td><td style="text-align:right;padding:2px 10px">${r.anon}</td><td>${r.ok ? '✅' : '⚠️'}</td></tr>`).join('') + '</table>';
    const ar = compareStructAnalysis(ra, rb);
    if (ar) {
      const abad = ar.filter(r => !r.ok).length;
      const ahead = abad ? tr('struct.analysis_mismatch').replace('{n}', abad) : tr('struct.analysis_ok');
      out.innerHTML += `<div style="margin:12px 0 6px;font-weight:600">${esc(tr('struct.analysis_title'))}</div>` +
        `<div style="margin-bottom:6px;font-weight:600;color:${abad ? 'var(--orange)' : 'var(--green)'}">${esc(ahead)}</div>` +
        (abad ? `<div style="margin-bottom:6px;font-size:12px;color:var(--text-dim)">${esc(tr('struct.analysis_hint'))}</div>` : '') +
        `<table class="struct-table struct-analysis" style="border-collapse:collapse"><tr><th style="text-align:left;padding:2px 10px 2px 0">${esc(tr('struct.col_item'))}</th><th style="padding:2px 10px">${esc(tr('struct.col_orig'))}</th><th style="padding:2px 10px">${esc(tr('struct.col_anon'))}</th><th></th></tr>` +
        ar.map(r => `<tr data-key="${esc(r.key)}"><td style="padding:2px 10px 2px 0">${esc(r.label)}</td><td style="text-align:right;padding:2px 10px">${esc(r.orig)}</td><td style="text-align:right;padding:2px 10px">${esc(r.anon)}</td><td>${r.ok ? '✅' : '⚠️'}</td></tr>`).join('') + '</table>';
    }
  }
  window.addEventListener('message', onMsg);
  timer = setTimeout(() => done(tr('struct.unavailable')), 20000);
  ifr.src = page + '?structcheck=1';
  document.body.appendChild(ifr);
}

function renderAnonSummary(s) {
  const el = document.getElementById('anon-summary');
  if (!el) return;
  const items = [
    [s.ip,        tr('stat.ip')],
    [s.password + s.key, tr('stat.password')],
    [s.hostname,  tr('stat.hostname')],
    [s.user,      tr('stat.user')],
    [s.community, tr('stat.community')],
    [s.ssid,      tr('stat.ssid')],
    [s.vdom,      'VDOM'],
  ].filter(([n]) => n > 0);
  if (!items.length) { el.style.display = 'none'; return; }
  el.innerHTML = '<span class="sum-label">' + tr('stat.replaced') + '：</span>' +
    items.map(([n, l]) => `<span class="sum-item"><b>${n}</b>${l}</span>`).join('');
  el.style.display = 'flex';
}

function renderStats(vendor, changedCount) {
  const grid = document.getElementById('stat-grid');
  const items = [
    { sv: stats.ip, sl: tr('stat.ip') },
    { sv: stats.hostname, sl: tr('stat.hostname') },
    { sv: stats.user, sl: tr('stat.user') },
    { sv: stats.password, sl: tr('stat.password') },
    { sv: stats.key, sl: tr('stat.key') },
    { sv: stats.community, sl: tr('stat.community') },
    { sv: stats.ssid, sl: tr('stat.ssid') },
    { sv: stats.vdom, sl: tr('stat.vdom') },
    { sv: stats.comment, sl: tr('stat.comment') }
  ];
  grid.innerHTML = items.map(i => `<div class="stat-card"><div class="sv">${i.sv}</div><div class="sl">${i.sl}</div></div>`).join('');

  // Vendor info
  document.getElementById('vendor-info-row').innerHTML =
    `<span class="vb" style="background:rgba(0,200,240,.15);color:var(--accent);border:1px solid var(--accent)">${vendor === 'unknown' ? tr('upload.vendor_unknown') : (vendorBrandLabel(vendor, STATE.original) || VENDOR_LABELS[vendor] || vendor)}</span>`;
  renderVendorCandidates();

  renderResidualWarnings();
  renderLeakInventory();
}

// 設定檔外洩影響盤點（XN22）：用整份還原後的文字取得各行原值（還原不改變行數），機密值仍為 REDACTED_*
function currentLeakInventory() {
  if (!STATE.anonymized) return null;
  const rev = {};
  MAPPING_CATEGORIES.forEach(cat => {
    if (cat === 'mac' || !STATE.mappings || !STATE.mappings[cat]) return;
    rev[cat] = Object.fromEntries([...STATE.mappings[cat]].map(([k, v]) => [v, k]));
  });
  const restored = restoreConfig(STATE.anonymized, rev).replace(/\r\n?/g, '\n').split('\n');
  return buildLeakInventory(STATE.anonymized, STATE.original, (l, i) => restored[i] != null ? restored[i] : l);
}
function leakLineLabel(inv) {
  return n => (inv.lineMapped ? tr('log.line_prefix') : tr('leak.anon_line')) + ' ' + n;
}
function renderLeakInventory() {
  const body = document.getElementById('leak-body');
  if (!body) return;
  const inv = currentLeakInventory();
  if (!inv) { body.innerHTML = ''; return; }
  const gap = LEAK_UNCOVERED[STATE.vendor];
  const notes = [tr('leak.note_encrypted'), tr('leak.note_scope')];
  if (gap) notes.unshift(tr(gap));
  if (!inv.lineMapped && inv.items.length) notes.push(tr('leak.note_lines'));
  const lab = leakLineLabel(inv);
  let h = '';
  if (!inv.items.length) h += `<div class="no-warn">${esc(tr('leak.none'))}</div>`;
  else {
    h += `<table class="map-table" style="margin-bottom:6px"><thead><tr><th>${esc(tr('leak.col_cat'))}</th><th>${esc(tr('leak.col_count'))}</th><th>${esc(tr('leak.col_action'))}</th></tr></thead><tbody>`;
    inv.cats.forEach(c => {
      const rows = inv.items.filter(it => it.cat === c).map(it => `<div style="word-break:break-all"><code>${esc(lab(it.line))}: ${esc(it.text)}</code></div>`).join('');
      h += `<tr><td><details><summary>${esc(tr('leak.cat_' + c))}</summary>${rows}</details></td><td>${inv.byCat[c].count}</td><td>${esc(tr('leak.act_' + c))}</td></tr>`;
    });
    h += '</tbody></table>';
  }
  h += notes.map(n => `<div style="color:var(--yellow);margin-top:4px">⚠ ${esc(n)}</div>`).join('');
  body.innerHTML = h;
}
function exportLeakInventory(kind) {
  const inv = currentLeakInventory();
  if (!inv) return;
  if (!inv.items.length) { alert(tr('leak.none')); return; }
  if (!confirm(tr('leak.export_confirm'))) return;
  const label = c => tr('leak.cat_' + c), advice = c => tr('leak.act_' + c), lab = leakLineLabel(inv);
  let data, name, type;
  if (kind === 'md') {
    data = buildLeakInventoryMarkdown(inv, label, advice, tr('leak.title').replace(/^\W+\s*/, ''), lab);
    name = 'leak-inventory.md'; type = 'text/markdown;charset=utf-8';
  } else {
    data = '\uFEFF' + buildLeakInventoryCSV(inv, label, advice, [tr('leak.col_cat'), tr('csv.residual_line'), tr('leak.col_text'), tr('leak.col_action'), tr('leak.col_status')], lab);
    name = 'leak-inventory.csv'; type = 'text/csv;charset=utf-8';
  }
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

// 廠牌候選清單顯示（2026-09-23 新增）：STATE.vendorCandidates 只在自動偵測時才會有值，
// 沒有其他候選時整段隱藏不顯示（比照既有 no-warn-msg 顯示/隱藏慣例）
function renderVendorCandidates() {
  const el = document.getElementById('vendor-candidates-row');
  if (!el) return;
  const cands = STATE.vendorCandidates || [];
  if (!cands.length) { el.style.display = 'none'; el.textContent = ''; return; }
  const labels = cands.map(id => esc(VENDOR_LABELS[id] || id)).join(tr('log.vendor_candidates_sep'));
  el.innerHTML = esc(tr('log.vendor_candidates_prefix')) + labels;
  el.style.display = '';
}

// Residual warnings 渲染（2026-09-14 從 renderStats() 抽出獨立函式）：讓「公司網域尾綴」
// 輸入框變更時（onCompanyDomainInput()）能單獨重繪這一區塊，不需要重跑整個 renderStats()
// （後者依賴 vendor/changedCount 參數，此處無從取得）。每筆警告皆帶一個忽略 checkbox
// （2026-09-14 新增），勾選後寫入 dismissedResidualKeys，畫面本身仍顯示（讓使用者能再次
//取消忽略），只有 getActiveResidualWarnings()（匯出前的確認攔截用）會濾掉已忽略項目
// 回報區塊 UI（2026-09-29 新增）：純函式見 reportBlockReason() 等（checkResidual() 上方）
function currentReportMeta() {
  const m = STATE.reportMeta || sanitizeReportMeta({ tool: 'config_anonymizer', trigger: STATE.vendor === 'unknown' ? 'unknown_vendor' : 'manual', vendor: STATE.vendor });
  return STATE.reportHash ? { ...m, hash: STATE.reportHash } : m;
}
function currentReportForm() {
  return { reason: document.getElementById('report-reason').value.trim(), model: document.getElementById('report-model').value.trim() };
}
function renderReportSection(resetConfirm) {
  const sec = document.getElementById('report-section');
  if (!sec) return;
  sec.style.display = STATE.anonymized ? '' : 'none';
  // 每次重新去識別化都需要重新確認與重看差異（內容可能已不同）；切換語言只重繪文字不重設
  if (resetConfirm) {
    document.getElementById('report-confirm').checked = false; STATE.reportDiffViewed = false;
    // 去識別化內容的 SHA-256（RE）：非同步計算，算完才帶入回報；crypto.subtle 不可用時（非安全
    // 環境）略過，不影響回報流程。以內容比對避免舊結果晚到時覆蓋新內容
    STATE.reportHash = '';
    const content = STATE.anonymized;
    if (content && typeof crypto !== 'undefined' && crypto.subtle) {
      sha256Hex(content).then(h => { if (STATE.anonymized === content) { STATE.reportHash = h; renderReportSection(false); } }).catch(() => {});
    }
  }
  const m = currentReportMeta();
  const st = _reportStatsText(m.stats);
  document.getElementById('report-meta').textContent = tr('report.meta').replace('{tool}', m.tool)
    .replace('{trigger}', tr('report.trigger_' + m.trigger)).replace('{vendor}', m.vendor) + (st ? '（' + st + '）' : '')
    + (m.hash ? '　#' + m.hash.slice(0, 8) : '');
  updateReportState();
}
function updateReportState() {
  const sec = document.getElementById('report-section');
  if (!sec) return;
  const unreviewed = getResidualWarnings().filter(w => !dismissedResidualKeys.has(_residualKey(w))).length;
  const block = reportBlockReason({ anonText: STATE.anonymized, reason: document.getElementById('report-reason').value,
    diffViewed: STATE.reportDiffViewed, unreviewed, confirmed: document.getElementById('report-confirm').checked });
  const ds = document.getElementById('report-diff-state');
  ds.textContent = STATE.reportDiffViewed ? tr('report.diff_viewed') : '';
  ds.style.color = 'var(--green)';
  document.getElementById('report-open-btn').disabled = !!block;
  document.getElementById('report-download-btn').disabled = !!block;
  const status = document.getElementById('report-status');
  status.style.color = 'var(--text-dim)';
  status.textContent = block ? tr('report.err_' + block).replace('{n}', unreviewed) : '';
}
function openReportDiff() {
  if (!STATE.anonymized) return;
  _reportBackWanted = true;
  showView('preview');
}
function downloadReportFile() {
  if (document.getElementById('report-download-btn').disabled) return;
  const m = currentReportMeta();
  const blob = new Blob([buildReportText(m, currentReportForm(), STATE.anonymized)], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = reportFileName(m, Date.now()); a.click();
}
async function openReportIssue() {
  if (document.getElementById('report-open-btn').disabled) return;
  const m = currentReportMeta(), f = currentReportForm();
  const status = document.getElementById('report-status');
  // 先開分頁（需在使用者點擊的同步流程內，否則會被攔截），再處理剪貼簿
  const w = window.open(buildReportIssueUrl(m, f), '_blank');
  let msg;
  if (STATE.anonymized.length > REPORT_BODY_MAX) {
    downloadReportFile(); msg = tr('report.too_long').replace('{max}', REPORT_BODY_MAX);
  } else {
    try { await navigator.clipboard.writeText(STATE.anonymized); msg = tr('report.copied'); }
    catch (e) { downloadReportFile(); msg = tr('report.copy_failed'); }
  }
  if (!w) msg = tr('report.popup_blocked') + ' ' + msg;
  status.style.color = 'var(--green)';
  status.textContent = msg;
}

function renderResidualWarnings() {
  const warnings = getResidualWarnings();
  const warnList = document.getElementById('warn-list');
  const noWarnMsg = document.getElementById('no-warn-msg');
  warnList.innerHTML = '';
  if (warnings.length) {
    noWarnMsg.style.display = 'none';
    warnings.forEach(w => {
      const key = _residualKey(w);
      const li = document.createElement('li');
      li.className = 'warn-item';
      li.style.display = 'flex';
      li.style.alignItems = 'center';
      li.style.gap = '6px';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = dismissedResidualKeys.has(key);
      cb.title = tr('opt.dismiss_warning_hint');
      cb.onchange = () => {
        if (cb.checked) dismissedResidualKeys.add(key); else dismissedResidualKeys.delete(key);
        updateReportState();
        span.style.opacity = cb.checked ? '.5' : '1';
        span.style.textDecoration = cb.checked ? 'line-through' : 'none';
      };
      const span = document.createElement('span');
      span.textContent = `${tr('log.line_prefix')} ${w.line}: ${w.text.substring(0, 120)}`;
      if (cb.checked) { span.style.opacity = '.5'; span.style.textDecoration = 'line-through'; }
      li.appendChild(cb);
      li.appendChild(span);
      warnList.appendChild(li);
    });
  } else {
    noWarnMsg.style.display = '';
  }
  // 殘留警告清單變動（例如新增監看關鍵字）會改變「未審閱數」，回報按鈕狀態需同步
  updateReportState();
}

// 公司網域尾綴輸入框變更（2026-09-14 新增）：更新全域狀態後只需重繪殘留警告區塊
function onCompanyDomainInput(v) {
  COMPANY_DOMAIN_SUFFIX = (v || '').trim();
  if (STATE.anonymized) renderResidualWarnings();
}
// 自訂監看關鍵字 textarea 變更（2026-09-23 新增）：換行分隔，去除空行/前後空白後存成陣列
function onWatchKeywordsInput(v) {
  CUSTOM_WATCH_KEYWORDS = (v || '').split('\n').map(s => s.trim()).filter(Boolean);
  if (STATE.anonymized) renderResidualWarnings();
}
// 高熵字串偵測開關切換（2026-09-15 新增）：比照 onCompanyDomainInput() 同款模式——設定旗標後
// 只需重繪殘留警告區塊，不需重跑整個 anonymize()（checkResidual() 是對「已匿名化後的輸出文字」
// 做救援網掃描，與匿名化本身的替換邏輯無關）
function onEntropyCheckToggle(checked) {
  ENTROPY_CHECK_ENABLED = !!checked;
  if (STATE.anonymized) renderResidualWarnings();
}

// 對照表搜尋框目前查詢字串（2026-09-24 新增）；resetAll() 時清空
let MAPPING_FILTER_QUERY = '';
function onMappingFilterInput(v) {
  MAPPING_FILTER_QUERY = v || '';
  renderMappingTable();
}
// 殘留警告 CSV 匯出（2026-09-24 新增）：內容是匿名化後仍疑似含機敏資訊的原文，下載前先確認
function exportResidualWarningsCSV() {
  if (!STATE.anonymized) return;
  const warnings = getResidualWarnings();
  if (!warnings.length) { alert(tr('log.no_warn')); return; }
  if (!confirm(tr('warn.residual_export_confirm'))) return;
  const rows = warnings.map(w => ({ line: w.line, text: w.text, dismissed: dismissedResidualKeys.has(_residualKey(w)) }));
  const csv = buildResidualWarningsCSV(rows, [tr('csv.residual_line'), tr('csv.residual_text'), tr('csv.residual_dismissed')]);
  const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'anonymize-residual-warnings.csv'; a.click();
  URL.revokeObjectURL(url);
}
function renderMappingTable() {
  const ipBody = document.getElementById('ip-map-body');
  const hostnameBody = document.getElementById('hostname-map-body');
  const userBody = document.getElementById('user-map-body');
  const ipEmpty = document.getElementById('ip-map-empty');
  const hostnameEmpty = document.getElementById('hostname-map-empty');
  const userEmpty = document.getElementById('user-map-empty');

  function fillTable(mapObj, tbody, emptyEl) {
    tbody.innerHTML = '';
    const entries = filterMappingEntries([...mapObj.entries()], MAPPING_FILTER_QUERY);
    if (entries.length === 0) {
      emptyEl.style.display = '';
      return;
    }
    emptyEl.style.display = 'none';
    entries.forEach(([orig, anon]) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${esc(orig)}</td><td class="arrow">→</td><td>${esc(anon)}</td>`;
      tbody.appendChild(tr);
    });
  }

  fillTable(mappings.ip, ipBody, ipEmpty);
  fillTable(mappings.hostname, hostnameBody, hostnameEmpty);
  fillTable(mappings.user, userBody, userEmpty);

  const ssidSection = document.getElementById('ssid-map-section');
  if (ssidSection) {
    ssidSection.style.display = mappings.ssid.size > 0 ? '' : 'none';
    fillTable(mappings.ssid, document.getElementById('ssid-map-body'), document.getElementById('ssid-map-empty'));
  }

  const aliasSection = document.getElementById('alias-map-section');
  if (aliasSection) {
    aliasSection.style.display = mappings.alias.size > 0 ? '' : 'none';
    fillTable(mappings.alias, document.getElementById('alias-map-body'), document.getElementById('alias-map-empty'));
  }
  const vdomSection = document.getElementById('vdom-map-section');
  if (vdomSection) {
    vdomSection.style.display = mappings.vdom.size > 0 ? '' : 'none';
    fillTable(mappings.vdom, document.getElementById('vdom-map-body'), document.getElementById('vdom-map-empty'));
  }
}

function resetAll() {
  STATE.original = ''; STATE.anonymized = ''; STATE.filename = ''; STATE.vendor = null; STATE.mappings = null;
  STATE.reportMeta = null;
  ['report-reason', 'report-model'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  renderReportSection(true);
  // 2026-09-21 修復：先前從未清空，殘留警告忽略狀態會跨檔案殘留——若新載入的設定檔殘留警告
  // 剛好在同一行號＋同一文字（_residualKey() 的鍵），會被誤判為使用者已審閱過而靜默略過
  dismissedResidualKeys.clear();
  const _sc = document.getElementById('struct-check-result'); if (_sc) _sc.textContent = '';
  const _sb = document.getElementById('btn-struct-check'); if (_sb) _sb.disabled = true;
  MAPPING_FILTER_QUERY = '';
  const mappingFilterEl = document.getElementById('mapping-filter');
  if (mappingFilterEl) mappingFilterEl.value = '';
  document.getElementById('paste-input').value = '';
  document.getElementById('file-name-label').style.display = 'none';
  document.getElementById('vendor-badge').style.display = 'none';
  document.getElementById('vendor-sel').value = 'auto';
  document.getElementById('file-input').value = '';
  document.getElementById('orig-body').innerHTML = '';
  document.getElementById('anon-body').innerHTML = '';
  setButtons(false);
  showView('upload');
  const diffWrap = document.getElementById('restore-diff-wrap');
  if (diffWrap) diffWrap.style.display = 'none';
}

// Init
document.addEventListener('DOMContentLoaded', () => {
  setButtons(false);
  showView('upload');
  setLang(loadLangPref());
  autoLabelControls();
// ── 彩蛋：Rage quit（連按 Esc 三次）────────────────────────
(function(){
  var _rq=0,_rqT;
  document.addEventListener('keydown',function(e){
    if(e.key!=='Escape')return;
    clearTimeout(_rqT);
    _rq++;
    _rqT=setTimeout(function(){_rq=0;},1500);
    if(_rq>=3){_rq=0;showEggToast(tr('egg.rage_quit'));}
  });
})();
  // 2026-09 資安審查修復：JSON 解析失敗／已過期的 key 一律清除（不論是否為本工具負責消費的
  // key），讓任一工具頁面被開啟都能順手清掉整個交接命名空間裡的殘留，縮小放棄交接流程（如彈出
  // 視窗被攔截、使用者關掉分頁）後明碼機敏內容殘留的曝險窗口；本工具負責消費 `_netAnalyzer_pending`
  // （hub 直接轉送）與 `_netAnalyzer_anonThenOpen`（hub 要求先匿名化再轉送）兩把 key，但本工具自己
  // 「匿名化完成後轉送給下一個工具」改寫入獨立 key `_netAnalyzer_anonResult`（見 _sendToAnalysisTool()），
  // 不再沿用 `_netAnalyzer_pending`，避免與 hub 直接轉送的寫入互相搶寫/誤讀（故此處不消費該 key）。
  (function(){
    var TTL = {_netAnalyzer_pending:10000, _netAnalyzer_anonThenOpen:30000, _netAnalyzer_anonResult:30000, _netAnalyzer_swParsedModel:30000, _netAnalyzer_fwQuery:30000, _netAnalyzer_swPortQuery:30000, _netAnalyzer_route:30000};
    var parsed = {};
    // 隱私模式或封鎖網站資料時 localStorage 存取會拋例外，整段略過（不影響頁面其餘功能）
    Object.keys(TTL).forEach(function(k){
      try {
        var raw = localStorage.getItem(k);
        if (!raw) return;
        try {
          var d = JSON.parse(raw);
          if (Date.now() - d.ts > TTL[k]) { localStorage.removeItem(k); return; }
          parsed[k] = d;
        } catch(e) { localStorage.removeItem(k); }
      } catch(e) {}
    });
    if (parsed['_netAnalyzer_pending']) {
      localStorage.removeItem('_netAnalyzer_pending');
      var d = parsed['_netAnalyzer_pending'];
      var pa = document.getElementById('paste-input');
      if (pa) pa.value = d.text;
      STATE.original = d.text;
      STATE.filename = d.name;
      var lbl = document.getElementById('file-name-label');
      if (lbl) { lbl.textContent = d.name; lbl.style.display = ''; }
      // 回報流程（2026-09-29 新增）：分析工具偵測到無法辨識廠牌／解析結果過少時帶入 report
      // 中繼資料；強制開啟全部遮蔽選項（保留最後一段 IP 會洩漏資訊，關閉），自動執行去識別化
      if (d.report) {
        STATE.reportMeta = sanitizeReportMeta(d.report);
        ['opt-ip', 'opt-hostname', 'opt-user', 'opt-comments', 'opt-vdom', 'opt-mac'].forEach(function(id) {
          var cb = document.getElementById(id); if (cb) cb.checked = true;
        });
        var lo = document.getElementById('opt-last-octet'); if (lo) lo.checked = false;
        var so = document.getElementById('opt-subnet'); if (so) so.checked = false;
        setTimeout(function() { var btn = document.getElementById('anon-btn'); if (btn) btn.click(); }, 300);
      } else {
        showHandoffBar(d.name, d.text);
      }
    }
    if (parsed['_netAnalyzer_anonThenOpen']) {
      localStorage.removeItem('_netAnalyzer_anonThenOpen');
      var d2 = parsed['_netAnalyzer_anonThenOpen'];
      var pa2 = document.getElementById('paste-input');
      if (pa2) pa2.value = d2.text;
      STATE.original = d2.text;
      STATE.filename = d2.name;
      _anonChainTarget = { href: TOOL_HREFS[d2.toolIdx] || TOOL_HREFS[0] };
      var lbl2 = document.getElementById('file-name-label');
      if (lbl2) { lbl2.textContent = d2.name; lbl2.style.display = ''; }
      // Auto-run anonymization
      setTimeout(function() { var btn = document.getElementById('anon-btn'); if (btn) btn.click(); }, 300);
    }
  })();
  (function(){
    var _t = document.createElement('div');
    _t.className = 'global-tip';
    document.body.appendChild(_t);
    document.addEventListener('mouseover', function(e) {
      var el = e.target.closest('[data-tip]');
      if (!el) return;
      _t.textContent = el.dataset.tip;
      _t.style.display = 'block';
      var r = el.getBoundingClientRect(), tw = _t.offsetWidth, th = _t.offsetHeight;
      var x = r.left + r.width / 2 - tw / 2;
      x = Math.max(8, Math.min(x, window.innerWidth - tw - 8));
      var y = r.top - th - 8;
      _t.style.left = x + 'px';
      _t.style.top = (y < 8 ? r.bottom + 8 : y) + 'px';
    });
    document.addEventListener('mouseout', function(e) { if (e.target.closest('[data-tip]')) _t.style.display = 'none'; });
    document.addEventListener('scroll', function() { _t.style.display = 'none'; }, true);
  })();
});

// ── Toast helper ────────────────────────────────────────────
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
  const SEQ='1145141919810';
  // 連續輸入時依序換句（冰紅茶、屋頂），之後循環
  const SMELLY_LINES=['egg.smelly','egg.smelly_tea','egg.smelly_roof'];let smellyN=0;
  let buf='';
  document.addEventListener('keydown',e=>{
    if(!e.key||e.key.length!==1)return;
    buf=(buf+e.key).slice(-SEQ.length);
    if(buf===SEQ){buf='';showEggToast(tr(SMELLY_LINES[smellyN++%SMELLY_LINES.length]));}
  });
})();

function showEggToast(msg, duration=3500) {
  // 彩蛋改由右下角羊駝呈現（XN49，alpaca-buddy.js）：主動彩蛋出泡泡、被動彩蛋收進口袋
  if (window.AlpacaBuddy) return window.AlpacaBuddy.say(msg, duration);
  const t = document.createElement('div');
  t.className = 'egg-toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.classList.add('show'), 20);
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 400); }, duration);
}

// ============================================================
// EASTER EGGS
// ============================================================

// ── 彩蛋 1：鎖頭快點 5 下 → Bean Rain 🫘 ──────────────────
(function setupBeanRain() {
  let n = 0, t = null;
  const logo = document.querySelector('.sidebar-logo .icon');
  if (!logo) return;
  logo.addEventListener('click', () => {
    n++; clearTimeout(t);
    t = setTimeout(() => { n = 0; }, 2000);
    if (n >= 5) { n = 0; startBeanRain(); }
  });
})();

function startBeanRain() {
  const overlay = document.createElement('div');
  overlay.className = 'bean-rain-overlay';
  document.body.appendChild(overlay);
  const items = ['🔒','🔑','🫘','🫘','🟢','🔵','🔴','🫛','🟡','🔐','🛡️'];
  let count = 0;
  const iv = setInterval(() => {
    if (count++ > 90) { clearInterval(iv); setTimeout(() => overlay.remove(), 3000); return; }
    const b = document.createElement('div');
    b.className = 'bean';
    b.textContent = items[Math.floor(Math.random() * items.length)];
    b.style.left = Math.random() * 100 + 'vw';
    b.style.fontSize = (16 + Math.random() * 22) + 'px';
    const dur = 2 + Math.random() * 3;
    b.style.animation = `beanFall ${dur}s linear forwards`;
    b.style.animationDelay = Math.random() * 1.5 + 's';
    overlay.appendChild(b);
  }, 55);
  setTimeout(() => { clearInterval(iv); setTimeout(() => overlay.remove(), 3000); }, 5500);
}

// ── 彩蛋 2：Konami Code → Matrix REDACTED Rain ─────────────
(function setupKonami() {
  const SEQ = [38,38,40,40,37,39,37,39,66,65]; // ↑↑↓↓←→←→BA
  let idx = 0;
  document.addEventListener('keydown', e => {
    idx = (e.keyCode === SEQ[idx]) ? idx + 1 : 0;
    if (idx === SEQ.length) { idx = 0; startMatrixRain(); }
  });
})();

function startMatrixRain() {
  if (document.querySelector('.matrix-overlay')) return;
  const overlay = document.createElement('div');
  overlay.className = 'matrix-overlay';
  document.body.appendChild(overlay);

  const words = [
    'REDACTED_HASH','REDACTED_PSK','REDACTED_KEY',
    'REDACTED_PASSWORD','REDACTED_COMMUNITY','REDACTED_COMMENT',
    'REDACTED_CERT','REDACTED_TOKEN','REDACTED',
    '192.0.2.x','198.51.100.x','203.0.113.x',
    'user-001','fw-device-001','ssid-001','alias-001',
    '██████████','░░░░░░░░░░'
  ];
  const cols = Math.floor(window.innerWidth / 96) + 2;
  for (let i = 0; i < cols; i++) {
    const col = document.createElement('div');
    col.className = 'matrix-col';
    col.style.left = (i * 96) + 'px';
    const dur = 5 + Math.random() * 6;
    col.style.animation = `matrixDrop ${dur}s linear forwards`;
    col.style.animationDelay = (Math.random() * 2.5) + 's';
    const lines = 12 + Math.floor(Math.random() * 10);
    for (let j = 0; j < lines; j++) {
      const span = document.createElement('span');
      span.textContent = words[Math.floor(Math.random() * words.length)];
      const brightness = 0.25 + Math.random() * 0.75;
      span.style.color = j === lines - 1 ? '#ffffff' : `rgba(0,200,240,${brightness})`;
      span.style.textShadow = j === lines - 1 ? '0 0 8px #00c8f0' : 'none';
      col.appendChild(span);
    }
    overlay.appendChild(col);
  }
  // 點擊或 9 秒後關閉
  const close = () => overlay.remove();
  overlay.addEventListener('click', close);
  setTimeout(close, 9000);
}

// ── 彩蛋 3：廠牌 badge 點 7 下 → 羊駝核可 ─────────────────
(function setupBadgeSecret() {
  let n = 0, t = null;
  document.getElementById('vendor-badge').addEventListener('click', () => {
    n++; clearTimeout(t);
    t = setTimeout(() => { n = 0; }, 2500);
    if (n >= 7) {
      n = 0;
      const badge = document.getElementById('vendor-badge');
      badge.classList.add('rainbow-flash');
      const orig = badge.textContent;
      badge.textContent = tr('egg.approved');
      setTimeout(() => {
        badge.classList.remove('rainbow-flash');
        badge.textContent = orig;
      }, 2000);
    }
  });
})();

// 彩蛋：羊駝 3 連擊解鎖克林貢
(function(){
  var _kN=0,_kT;
  document.addEventListener('click',function(e){
    var ac=document.getElementById('alpaca-corner');
    if(!ac||(!ac.contains(e.target)&&ac!==e.target))return;
    clearTimeout(_kT);_kN++;
    _kT=setTimeout(function(){_kN=0;},1500);
    if(_kN>=3){
      _kN=0;
      document.getElementById('lang-klingon').style.display='';
      setLang('tlh');
      var t=document.createElement('div');t.className='qapla-toast';
      t.textContent="🖖 Qapla'! tlhIngan Hol DaghojneS!";
      document.body.appendChild(t);
      t.addEventListener('animationend',function(ev){if(ev.animationName==='qapla-out')t.remove();});
    }
  });
})();

// ── 彩蛋 4：羊駝角落 + Console 彩蛋 ───────────────────────
(function setupAlpaca() {
  const el = document.createElement('div');
  el.id = 'alpaca-corner';
  el.setAttribute('title', tr('egg.alpaca_title'));
  el.style.cssText = 'position:fixed;bottom:16px;right:16px;z-index:2147483647;opacity:.85;transition:opacity .3s;cursor:pointer;pointer-events:auto;user-select:none;';
  el.onmouseenter = function() { this.style.opacity = '1'; };
  el.onmouseleave = function() { this.style.opacity = '.85'; };
  // 點羊駝 → bean rain
  el.onclick = () => startBeanRain();
  el.innerHTML = '<svg width="48" height="56" viewBox="0 0 48 56" xmlns="http://www.w3.org/2000/svg">'
    + '<ellipse cx="24" cy="38" rx="14" ry="12" fill="#c8b89a"/>'
    + '<rect x="18" y="20" width="8" height="16" rx="4" fill="#c8b89a"/>'
    + '<ellipse cx="22" cy="16" rx="9" ry="8" fill="#d4c4a0"/>'
    + '<ellipse cx="15" cy="10" rx="3" ry="5" fill="#c8b89a"/>'
    + '<ellipse cx="29" cy="10" rx="3" ry="5" fill="#c8b89a"/>'
    + '<ellipse cx="15" cy="10" rx="1.5" ry="3" fill="#e8b4b8"/>'
    + '<ellipse cx="29" cy="10" rx="1.5" ry="3" fill="#e8b4b8"/>'
    + '<circle cx="18" cy="15" r="2" fill="#4a3728"/>'
    + '<circle cx="26" cy="15" r="2" fill="#4a3728"/>'
    + '<circle cx="18.7" cy="14.3" r=".6" fill="#fff"/>'
    + '<circle cx="26.7" cy="14.3" r=".6" fill="#fff"/>'
    + '<ellipse cx="22" cy="20" rx="3" ry="2" fill="#b09070"/>'
    + '<circle cx="20.5" cy="20" r=".8" fill="#7a5a40"/>'
    + '<circle cx="23.5" cy="20" r=".8" fill="#7a5a40"/>'
    + '<ellipse cx="22" cy="9" rx="7" ry="4" fill="#e8dcc8"/>'
    + '<ellipse cx="18" cy="8" rx="4" ry="3" fill="#e8dcc8"/>'
    + '<ellipse cx="26" cy="8" rx="4" ry="3" fill="#e8dcc8"/>'
    + '<rect x="13" y="47" width="5" height="8" rx="2.5" fill="#b09070"/>'
    + '<rect x="20" y="47" width="5" height="8" rx="2.5" fill="#b09070"/>'
    + '<rect x="28" y="47" width="5" height="8" rx="2.5" fill="#b09070"/>'
    + '<ellipse cx="37" cy="36" rx="4" ry="3" fill="#d4c4a0"/>'
    + '</svg>';
  document.body.appendChild(el);
})();

// ============================================================
// [RESTORE] 加密還原包功能
// ============================================================

// ---- 加密 / 解密引擎（Web Crypto API：PBKDF2 + AES-GCM-256）----
async function encryptMap(obj, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const km   = await crypto.subtle.importKey('raw',
    new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key  = await crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:200000, hash:'SHA-256' },
    km, { name:'AES-GCM', length:256 }, false, ['encrypt']);
  const enc  = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key,
    new TextEncoder().encode(JSON.stringify(obj)));
  const out  = new Uint8Array(28 + enc.byteLength);
  out.set(salt, 0); out.set(iv, 16); out.set(new Uint8Array(enc), 28);
  return btoa(String.fromCharCode(...out));
}

// 對匿名化後文字算 SHA-256 雜湊（十六進位字串），供 .acmap 綁定來源設定檔用；
// 複用既有 encryptMap/decryptMap 已使用的 crypto.subtle，不引入新依賴
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function decryptMap(b64, password) {
  const buf  = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const salt = buf.slice(0, 16), iv = buf.slice(16, 28), data = buf.slice(28);
  const km   = await crypto.subtle.importKey('raw',
    new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key  = await crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:200000, hash:'SHA-256' },
    km, { name:'AES-GCM', length:256 }, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plain));
}

// ---- 加密匯出 Modal ----
function showEncryptModal() {
  document.getElementById('enc-pwd1').value = '';
  document.getElementById('enc-pwd2').value = '';
  document.getElementById('enc-modal-err').textContent = '';
  const overlay = document.getElementById('encrypt-modal-overlay');
  overlay.style.display = 'flex';
}

function closeEncryptModal() {
  document.getElementById('encrypt-modal-overlay').style.display = 'none';
}

async function confirmEncrypt() {
  const p1 = document.getElementById('enc-pwd1').value;
  const p2 = document.getElementById('enc-pwd2').value;
  const errEl = document.getElementById('enc-modal-err');
  if (!p1) { errEl.textContent = tr('modal.err_no_pwd'); return; }
  if (p1 !== p2) { errEl.textContent = tr('modal.err_pwd_mismatch'); return; }
  errEl.textContent = '';
  closeEncryptModal();
  await doExportEncrypted(p1);
}

async function doExportEncrypted(password) {
  // 綁定來源設定檔：對匿名化後的輸出文字（匯出與還原時皆可取得，原始未匿名化文字則不行）
  // 算雜湊存入還原包，讓 doRestore() 可比對上傳檔案是否為同一批次產生，非本次強制要求
  // 一致，僅示警不阻擋還原（見 doRestore() 內 hashMismatch 判斷）
  const sourceHash = await sha256Hex(STATE.anonymized || '');
  const m = STATE.mappings || mappings; // 快照優先，理由見 STATE 宣告處註解
  const reverseMap = {
    vendor: STATE.vendor,
    created: new Date().toISOString(),
    sourceHash,
    // reverse 原本只打包 ip/hostname/user 3 類，但 mappings 實際有 7 類可逆映射（見檔案開頭
    // const mappings 宣告），ssid/alias/vdom/mac 4 類先前遺漏，導致含 WiFi SSID／VDOM 名稱／
    // 裝置別名／MAC 位址的設定檔用 .acmap 還原時這 4 類會維持匿名化狀態且無任何警告
    // （2026-09-18 修復，「9 個已確認 bug」第 6 項）。2026-09-21 改用 MAPPING_CATEGORIES 統一
    // 迭代時，意外發現 mac 類別直接把 {hex} 物件當 Map key 用（[v,k] 的 v 未解開 .hex），
    // Object.fromEntries() 會把物件字面轉成 "[object Object]" 字串鍵，MAC 位址還原功能自
    // 這個功能誕生以來從未真正生效過。修復本身比預期複雜：anonMAC()/formatMAC() 只儲存去分
    // 隔符的雜湊值本身（.hex／Map key），實際輸出的冒號／連字號／Cisco點號格式是依「該次出現
    // 的原始文字格式」動態決定，同一筆映射在設定檔中可能以不同格式各出現一次，單純 1:1 字串
    // 還原無法完整涵蓋每種格式。範圍限縮為只重建冒號格式（formatMAC() 查無 . 或 - 時的預設
    // 分支，最常見/最泛用的 MAC 表示法），連字號/Cisco點號格式的出現方式暫不支援完整還原——
    // 仍是相較「完全不還原」的淨改善，非本輪企圖解決的完整規模
    reverse: (() => {
      const out = {};
      MAPPING_CATEGORIES.forEach(cat => {
        if (cat === 'mac') {
          out.mac = {};
          for (const [k, v] of m.mac) {
            const hex = (v && v.hex) || v;
            if (typeof hex !== 'string') continue;
            out.mac[formatMAC(hex, 'x:x')] = formatMAC(k, 'x:x');
          }
        } else {
          out[cat] = Object.fromEntries([...m[cat]].map(([k, v]) => [v, k]));
        }
      });
      return out;
    })(),
    // .acmap 還原包擴充打包 customRules／dismissedResidualKeys（2026-09-15 新增，皆為選填
    // 欄位，回溯相容舊版 .acmap 檔案不含這兩欄）。customRules 沿用既有 exportCustomRules()
    // 已定義好、拿掉 id 的匯出形狀；dismissedResidualKeys 是 Set，JSON 不支援 Set 需轉陣列。
    // 隱私考量：兩者皆維持在 reverseMap 內部，隨整個物件一起 AES-GCM 加密（與既有 IP/主機名稱/
    // 使用者名稱 reverse map 同一信任邊界，dismissedResidualKeys 的 key 內容含原始被標記行
    // 文字，可能是未遮罩片段，不可獨立於加密結構之外）
    customRules: customRules.map(r => ({ pattern: r.pattern, replacement: r.replacement, enabled: r.enabled })),
    dismissedResidualKeys: [...dismissedResidualKeys],
  };
  try {
    const b64  = await encryptMap(reverseMap, password);
    const base = (STATE.filename || 'config').replace(/\.[^.]+$/, '');
    const blob = new Blob([b64], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = base + '.acmap'; a.click();
    URL.revokeObjectURL(url);
    markMappingSaved();
  } catch(e) {
    alert(tr('err.encrypt_fail') + e.message);
  }
}

// ---- 還原邏輯 ----
function restoreConfig(anonText, rev) {
  // ssid/alias/vdom/mac 4 類 2026-09-18 補上（見 doExportEncrypted() 對應修復註解）；
  // 向下相容舊版 .acmap（無這 4 類欄位）：rev.ssid||{} 等 fallback 安全處理不拋錯。
  // 2026-09-21 改用 MAPPING_CATEGORIES 統一迭代，避免未來新增類別時漏改這裡
  const map = new Map();
  MAPPING_CATEGORIES.forEach(cat => Object.entries(rev[cat] || {}).forEach(([anon, orig]) => { if (anon && !map.has(anon)) map.set(anon, orig); }));
  if (!map.size) return anonText;
  // 一次替換（長字串優先）且假值前後不可緊接英數字或「.數字」：原本逐一以純字串替換，假值 203.0.113.3
  // 會換進 203.0.113.31，已換回的原值也可能被後面的項目再換一次
  const keys = [...map.keys()].sort((a, b) => b.length - a.length).map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const re = new RegExp(`(?<![A-Za-z0-9])(?:${keys.join('|')})(?![A-Za-z0-9]|\\.\\d)`, 'g');
  return anonText.replace(re, m => map.get(m));
}

// ---- 還原模式 UI 狀態 ----
const RESTORE_STATE = { anonText: null, anonFilename: null, mapB64: null };

function restoreFileDrop(e, which) {
  e.preventDefault();
  const el = e.currentTarget;
  el.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) loadRestoreFile(file, which);
}

function restoreFileSelect(e, which) {
  const file = e.target.files[0];
  if (file) loadRestoreFile(file, which);
}

function loadRestoreFile(file, which) {
  const reader = new FileReader();
  reader.onerror = () => alert(tr('msg.file_read_error'));
  reader.onload = ev => {
    const content = ev.target.result;
    const dropEl  = document.getElementById('restore-' + which + '-drop');
    const labelEl = document.getElementById('restore-' + which + '-label');
    dropEl.classList.add('loaded');
    if (which === 'anon') {
      RESTORE_STATE.anonText     = content;
      RESTORE_STATE.anonFilename = file.name;
      labelEl.textContent = '✓ ' + file.name;
    } else {
      RESTORE_STATE.mapB64 = content.trim();
      labelEl.textContent  = '✓ ' + file.name;
    }
  };
  reader.readAsText(file, 'utf-8');
}

async function doRestore() {
  const statusEl = document.getElementById('restore-status');
  const outArea  = document.getElementById('restore-output-area');
  statusEl.style.display = 'none';
  outArea.style.display  = 'none';

  const { anonText, mapB64 } = RESTORE_STATE;
  const pwd = document.getElementById('restore-pwd').value;

  if (!anonText) { showRestoreStatus('err', tr('err.no_anon_file')); return; }
  if (!mapB64)   { showRestoreStatus('err', tr('err.no_map_file')); return; }
  if (!pwd)      { showRestoreStatus('err', tr('err.no_pwd')); return; }

  try {
    const rev = await decryptMap(mapB64, pwd);
    if (!rev.reverse) throw new Error(tr('err.bad_format'));
    // 綁定來源設定檔比對：舊版 .acmap（無 sourceHash）略過比對以維持向下相容；
    // 不一致時只警告不阻擋還原，因為合法情境仍可能是「還原對象是匿名化後又手動微調過的檔案」
    let hashMismatch = false;
    if (rev.sourceHash) {
      const uploadedHash = await sha256Hex(anonText);
      hashMismatch = uploadedHash !== rev.sourceHash;
    }
    const restored = restoreConfig(anonText, rev.reverse);

    // customRules／dismissedResidualKeys 還原（2026-09-15 新增，皆為選填欄位，回溯相容不含
    // 這兩欄的舊版 .acmap）。重複還原會累加不去重，與既有 importCustomRulesFile() 同款行為
    // 一致，非新引入的不一致
    let restoredRulesCount = 0, restoredDismissedCount = 0;
    if (Array.isArray(rev.customRules)) {
      rev.customRules.forEach(r => {
        if (!r || typeof r.pattern !== 'string') return;
        customRules.push({ id: ++_ruleIdSeq, pattern: r.pattern, replacement: String(r.replacement || ''), enabled: r.enabled !== false });
        restoredRulesCount++;
      });
      if (restoredRulesCount) renderCustomRules();
    }
    if (Array.isArray(rev.dismissedResidualKeys)) {
      rev.dismissedResidualKeys.forEach(k => {
        if (typeof k === 'string') { dismissedResidualKeys.add(k); restoredDismissedCount++; }
      });
    }

    // 計算還原行數
    const origLines = anonText.split('\n');
    const restLines = restored.split('\n');
    let changed = 0;
    for (let i = 0; i < origLines.length; i++) {
      if (origLines[i] !== restLines[i]) changed++;
    }

    // 顯示結果
    RESTORE_STATE.restoredText = restored;
    RESTORE_STATE.restoredFilename = (RESTORE_STATE.anonFilename || 'restored').replace(/\.[^.]+$/, '') + '_restored.txt';
    renderRestoreOutput(restored);
    document.getElementById('restore-line-cnt').textContent = restLines.length + tr('restore.line_of_total') + changed + tr('restore.line_restored');
    outArea.style.display = 'block';
    // changed===0 可能代表上傳的設定檔與加密還原包並非同一批次產生（映射表對不上任何內容），
    // 用 warn 等級而非 ok 提醒使用者確認，避免誤以為還原成功
    if (hashMismatch) {
      showRestoreStatus('warn', tr('restore.hash_mismatch_warn'));
    } else if (changed === 0) {
      showRestoreStatus('warn', tr('restore.zero_changed_warn'));
    } else {
      let msg = tr('restore.success_prefix') + changed + tr('restore.success_suffix');
      if (restoredRulesCount) msg += tr('msg.restore_rules_count').replace('{n}', restoredRulesCount);
      if (restoredDismissedCount) msg += tr('msg.restore_dismissed_count').replace('{n}', restoredDismissedCount);
      showRestoreStatus('ok', msg);
    }
  } catch(e) {
    if (e.name === 'OperationError' || (e.message || '').includes('decrypt') || (e.message || '').includes('Decrypt')) {
      showRestoreStatus('err', tr('err.decrypt_fail'));
    } else {
      // 不附加原始瀏覽器錯誤訊息（e.message 未在地化，如 atob 失敗的英文訊息），只顯示既有
      // i18n 文案
      showRestoreStatus('err', tr('err.restore_fail'));
    }
  }
}

function showRestoreStatus(type, msg) {
  const el = document.getElementById('restore-status');
  el.className = 'restore-status ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}

function renderRestoreOutput(text) {
  const body = document.getElementById('restore-body');
  const lines = text.split('\n');
  body.innerHTML = lines.map((l, i) =>
    '<div class="line-row"><span class="ln">' + (i+1) + '</span><span class="lc">' +
    l.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</span></div>'
  ).join('');
  // 顯示還原驗證 diff
  if (RESTORE_STATE.anonText) {
    buildRestoreDiff(RESTORE_STATE.anonText, text);
  }
}

function downloadRestored() {
  if (!RESTORE_STATE.restoredText) { showRestoreStatus('err', tr('err.no_restore_result')); return; }
  const blob = new Blob([RESTORE_STATE.restoredText], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = RESTORE_STATE.restoredFilename || 'restored.txt'; a.click();
  URL.revokeObjectURL(url);
}

function copyRestored() {
  navigator.clipboard.writeText(RESTORE_STATE.restoredText || '').then(() => {
    showRestoreStatus('ok', tr('status.copied'));
  });
}

// Console 彩蛋
console.log('%c\n ██████╗ ███████╗██████╗  █████╗  ██████╗████████╗███████╗██████╗\n ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n ██████╔╝█████╗  ██║  ██║███████║██║        ██║   █████╗  ██║  ██║\n ██╔══██╗██╔══╝  ██║  ██║██╔══██║██║        ██║   ██╔══╝  ██║  ██║\n ██║  ██║███████╗██████╔╝██║  ██║╚██████╗   ██║   ███████╗██████╔╝\n ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚═════╝\n', 'color:#00c8f0;font-family:monospace;font-size:10px;line-height:1.4');
// 彩蛋：lang-egg 代表物三連擊
(function(){
  var _EGG={
    'egg-pirate':{lang:'pirate',btn:'lang-pirate',toast:"☠️ Ahoy! Ye be speakin' pirate now, matey! Arr!"},
    'egg-leet':  {lang:'leet',  btn:'lang-leet',  toast:'1337 5P34K 4C71V473D. H4X0R M0D3 0N.'},
    'egg-emoji': {lang:'emoji', btn:'lang-emoji',  toast:'🌈✨🎉 3moji mod3 4ctiv4t3d! 🦄💫🌟'},
    'egg-uwu':   {lang:'uwu',   btn:'lang-uwu',   toast:'🐾 Hewwo fwend~ UwU wanguage activeated! OwO'},
    'egg-bureau':{lang:'bureau',btn:'lang-bureau',toast:'📋 啟動跨部門作業流程。本系統正式進入公文模式。請依規定格式呈現。'},
    'egg-cat':   {lang:'cat',   btn:'lang-cat',   toast:'🐱 Nyaa~！喵語模式啟動了喵！meow meow owo'},
    'egg-bean':  {lang:'bean',  btn:'lang-bean',  toast:'🥕🫛🌽 豆語模式啟動！蔬菜智慧已降臨！🌽🫛🥕'},
    'egg-alpaca':{lang:'alpaca',btn:'lang-alpaca',toast:'🦙 咩咩咩！羊咩碼啟動-aca！設定咩去咩識別-aca！🦙'},'egg-yanse':{lang:'yanse',btn:'lang-yanse',toast:'💀 overtime detected...厭世工程師模式啟動，反正早晚都要加班'},
    'egg-wuxia': {lang:'wuxia', btn:'lang-wuxia', toast:'⚔️ 武林秘笈已然出鞘！江湖兒女，且看今朝！'},
  };
  var _eN={},_eT={};
  document.querySelectorAll('.lang-egg').forEach(function(el){
    _eN[el.id]=0;
    el.addEventListener('click',function(){
      clearTimeout(_eT[el.id]);
      _eN[el.id]++;
      _eT[el.id]=setTimeout(function(){_eN[el.id]=0;},1500);
      if(_eN[el.id]>=3){
        _eN[el.id]=0;
        var c=_EGG[el.id];
        document.getElementById(c.btn).style.display='';
        setLang(c.lang);
        showEggToast(c.toast);
      }
    });
  });
})();

console.log('%c Config Anonymizer  ·  羊駝驅動的去識別化工具 🦙', 'color:#10b981;font-family:monospace;font-size:13px;font-weight:bold');
console.log('%c 彩蛋提示 → 鎖頭 ×5 | Konami Code ↑↑↓↓←→←→BA | badge ×7 | 點羊駝', 'color:#64748b;font-family:monospace;font-size:10px');

// 黑/白模式切換
// ── 跨工具導覽（2026-08-24 新增）：見 switch_analyzer 同名函式註解
document.addEventListener('click',function(e){
  const p=document.getElementById('tools-nav-panel');
  if(p&&p.style.display==='block'&&!p.contains(e.target)&&e.target.id!=='tools-nav-btn'){
    p.style.display='none';
  }
});

function setTheme(t){document.body.dataset.theme=t;const b=document.getElementById('theme-btn');if(b)b.textContent=t==='light'?'🌙':'☀️';try{localStorage.setItem('cw_theme',t);}catch(e){}}
(function(){let s=null;try{s=localStorage.getItem('cw_theme');}catch(e){}const p=s||(window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');if(p==='light')setTheme('light');})();


// Ctrl／⌘＋Enter 在貼上框直接開始（UX24）；按鈕加提示與 aria-keyshortcuts
(function () {
  var ta = document.getElementById('paste-input'), btn = document.getElementById('anon-btn');
  if (!ta) return;
  ta.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runAnonymize(); }
  });
  if (btn) { btn.setAttribute('aria-keyshortcuts', 'Control+Enter Meta+Enter'); btn.title = (btn.title ? btn.title + ' ' : '') + '(Ctrl/⌘+Enter)'; }
})();
