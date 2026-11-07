// network-analyzer.html 拆出的模組（XN101）：工作區打包。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// ── 工作區打包（2026-10-07，第十二輪 MH）──────────────────────────────
// 各工具共用同一個瀏覽器儲存區（跨工具交接也靠這點），故由入口頁統一匯出／還原。只處理下列白名單
// key；一次性交接 key（_netAnalyzer_pending 等）不列入。content 群組（產生器模板／草稿，可能含 IP、
// 帳號、密碼）與附加檔案（去識別化對照表、log 基準線等，各工具另外匯出的檔案）預設不附，勾選才附。
// 還原時只寫入白名單內、格式正確的值；附加檔案只提供下載，由使用者到對應工具匯入。
const WS_FORMAT = 'alpaca-workspace';
const WS_KEYS = [
  { key: 'cw_lang', tool: 'common', group: 'settings' }, { key: '_netAnalyzer_eggLoud', tool: 'common', group: 'settings' }, { key: 'cw_theme', tool: 'common', group: 'settings' }, { key: 'cw_sb', tool: 'common', group: 'settings' },
  { key: 'sw_golden_rules', tool: 'switch_analyzer', group: 'settings' }, { key: 'sw_eol_list', tool: 'switch_analyzer', group: 'settings' }, { key: 'sw_vuln_list', tool: 'switch_analyzer', group: 'settings' },
  { key: 'sw_audit_marks', tool: 'switch_analyzer', group: 'settings', json: true }, { key: 'sw_audit_reviewer', tool: 'switch_analyzer', group: 'settings' },
  { key: 'fw_accepted_risks', tool: 'firewall_analyzer', group: 'settings', json: true }, { key: 'fw_naming_rules', tool: 'firewall_analyzer', group: 'settings', json: true },
  { key: 'fw_expiry_keywords', tool: 'firewall_analyzer', group: 'settings' },
  { key: 'fw_vuln_list', tool: 'firewall_analyzer', group: 'settings' },
  { key: 'fw_log_retention_days', tool: 'firewall_analyzer', group: 'settings' },
  { key: 'fw_audit_marks', tool: 'firewall_analyzer', group: 'settings', json: true }, { key: 'fw_audit_reviewer', tool: 'firewall_analyzer', group: 'settings' },
  { key: 'log_analyzer_settings_v1', tool: 'log_analyzer', group: 'settings', json: true },
  { key: '_netAnalyzer_intelSources', tool: 'log_analyzer', group: 'settings', json: true }, { key: '_netAnalyzer_intelLastCounts', tool: 'log_analyzer', group: 'settings', json: true }, { key: 'intel_builder_lang', tool: 'log_analyzer', group: 'settings' },
  { key: 'switch_analyzer_health_history_v1', tool: 'switch_analyzer', group: 'history', json: true },
  { key: 'firewall_analyzer_health_history_v1', tool: 'firewall_analyzer', group: 'history', json: true },
  { key: '_netAnalyzer_summaries', tool: 'common', group: 'history', json: true }, { key: '_netAnalyzer_activityHistory', tool: 'common', group: 'history', json: true },
  { key: '_netAnalyzer_anonHistory', tool: 'config_anonymizer', group: 'history', json: true },
  { key: '_netAnalyzer_achievements', tool: 'common', group: 'history', json: true },
  { key: '_netAnalyzer_tourSeen', tool: 'common', group: 'settings', json: true },
  { key: 'cw_templates', tool: 'switch_config_generator', group: 'content', json: true },
  { key: 'cw_section_templates', tool: 'switch_config_generator', group: 'content', json: true },
  { key: 'cw_draft', tool: 'switch_config_generator', group: 'content', json: true },
];
const WS_MAX_VALUE = 4 * 1024 * 1024, WS_MAX_ATTACH = 10;
function _wsValid(def, v) {
  if (typeof v !== 'string' || v.length > WS_MAX_VALUE) return false;
  if (!def.json) return true;
  try { JSON.parse(v); return true; } catch (e) { return false; }
}
// store 需有 getItem(key)；opts.includeContent 附上 content 群組，opts.attachments 為 [{name,text}]
function buildWorkspace(store, opts, now) {
  opts = opts || {};
  const items = {};
  WS_KEYS.forEach(d => {
    if (d.group === 'content' && !opts.includeContent) return;
    let v = null;
    try { v = store.getItem(d.key); } catch (e) { v = null; }
    if (v !== null && v !== '' && _wsValid(d, v)) items[d.key] = v;
  });
  const ws = { format: WS_FORMAT, version: 1, created: (now || new Date()).toISOString(), includeContent: !!opts.includeContent, items };
  if (opts.includeContent && opts.attachments && opts.attachments.length) ws.attachments = opts.attachments.slice(0, WS_MAX_ATTACH).map(a => ({ name: String(a.name || 'file').slice(0, 120), text: String(a.text || '') }));
  return ws;
}
// 回傳 {ok, created, items:{key:value}, attachments:[{name,text}], skipped} 或 {ok:false}
function parseWorkspace(text) {
  let o;
  try { o = JSON.parse(text); } catch (e) { return { ok: false }; }
  if (!o || o.format !== WS_FORMAT || !o.items || typeof o.items !== 'object' || Array.isArray(o.items)) return { ok: false };
  const items = {}; let skipped = 0;
  Object.keys(o.items).forEach(k => {
    const d = WS_KEYS.find(x => x.key === k);
    if (d && _wsValid(d, o.items[k])) items[k] = o.items[k]; else skipped++;
  });
  const attachments = (Array.isArray(o.attachments) ? o.attachments : []).filter(a => a && typeof a.name === 'string' && typeof a.text === 'string' && a.text.length <= WS_MAX_VALUE)
    .slice(0, WS_MAX_ATTACH).map(a => ({ name: a.name.replace(/[\\/:*?"<>|\r\n]/g, '_').slice(0, 120) || 'file', text: a.text }));
  return { ok: true, created: typeof o.created === 'string' ? o.created : '', items, attachments, skipped };
}
function applyWorkspace(store, items) {
  let n = 0;
  Object.keys(items).forEach(k => {
    if (!WS_KEYS.some(d => d.key === k)) return;
    try { store.setItem(k, items[k]); n++; } catch (e) { /* 容量不足等情況略過該項 */ }
  });
  return n;
}
function _wsLabel(k) {
  const d = WS_KEYS.find(x => x.key === k);
  const tool = d.tool === 'common' ? tr('ws.tool_common') : tr('activity.tool_' + d.tool);
  return `${tool}｜${tr('ws.group_' + d.group)}｜${k}`;
}
function _wsDownload(name, text, type) {
  const blob = new Blob([text], { type: type || 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
function _wsSetResult(nodes) {
  const box = document.getElementById('ws-result');
  if (!box) return;
  box.innerHTML = '';
  nodes.forEach(n => box.appendChild(typeof n === 'string' ? Object.assign(document.createElement('div'), { textContent: n }) : n));
}
async function exportWorkspace() {
  const inc = !!(document.getElementById('ws-include-content') || {}).checked;
  const files = inc ? Array.from((document.getElementById('ws-attach-input') || {}).files || []) : [];
  const attachments = [];
  for (const f of files.slice(0, WS_MAX_ATTACH)) { if (f.size <= WS_MAX_VALUE) attachments.push({ name: f.name, text: await f.text() }); }
  const ws = buildWorkspace(localStorage, { includeContent: inc, attachments });
  const n = Object.keys(ws.items).length, a = (ws.attachments || []).length;
  if (!n && !a) { _wsSetResult([tr('ws.empty')]); return; }
  // 含設定內容或附加檔案時檔名標示 with-content，並提醒不要放到公開位置（XN89）
  const hasContent = inc && (a > 0 || WS_KEYS.some(d => d.group === 'content' && ws.items[d.key] !== undefined));
  _wsDownload('alpaca_workspace_' + new Date().toISOString().slice(0, 10) + (hasContent ? '_with-content' : '') + '.json', JSON.stringify(ws, null, 1));
  _wsSetResult([tr('ws.exported').replace('{n}', n).replace('{a}', a)].concat(hasContent ? [tr('ws.content_warn')] : []));
}
function loadWorkspaceFile(file) {
  if (!file) return;
  file.text().then(text => {
    const r = parseWorkspace(text);
    if (!r.ok) { _wsSetResult([tr('ws.invalid')]); return; }
    const keys = Object.keys(r.items);
    const nodes = [tr('ws.preview').replace('{time}', r.created ? new Date(r.created).toLocaleString() : '-').replace('{n}', keys.length).replace('{a}', r.attachments.length)];
    const ul = document.createElement('ul');
    ul.style.cssText = 'margin:4px 0 4px 18px;padding:0';
    keys.forEach(k => { const li = document.createElement('li'); li.textContent = _wsLabel(k); ul.appendChild(li); });
    nodes.push(ul);
    if (r.skipped) nodes.push(tr('ws.skipped').replace('{n}', r.skipped));
    if (keys.length) {
      const btn = document.createElement('button');
      btn.id = 'ws-restore-btn'; btn.textContent = tr('ws.restore'); btn.style.cssText = 'font-size:12px;margin:4px 0';
      btn.onclick = () => {
        const n = applyWorkspace(localStorage, r.items);
        const rest = [tr('ws.restored').replace('{n}', n)];
        if (r.attachments.length) rest.push(_wsAttachNode(r.attachments));
        _wsSetResult(rest);
        ['renderRecentAnonHistory', 'renderActivityTimeline', 'renderHealthSummary'].forEach(f => { if (typeof window[f] === 'function') window[f](); });
      };
      nodes.push(btn);
    }
    if (r.attachments.length) nodes.push(_wsAttachNode(r.attachments));
    _wsSetResult(nodes);
  });
}
function _wsAttachNode(atts) {
  const d = document.createElement('div');
  d.className = 'ws-attachments';
  d.appendChild(document.createTextNode(tr('ws.attach_dl') + ' '));
  atts.forEach(a => {
    const s = document.createElement('span');
    s.textContent = a.name; s.setAttribute('role', 'button'); s.tabIndex = 0;
    s.style.cssText = 'cursor:pointer;text-decoration:underline;margin-right:10px';
    s.onclick = () => _wsDownload(a.name, a.text, 'text/plain;charset=utf-8');
    d.appendChild(s);
  });
  return d;
}
function renderWorkspaceCard() {
  const set = (id, k) => { const e = document.getElementById(id); if (e) e.textContent = tr(k); };
  set('ws-title', 'ws.title'); set('ws-desc', 'ws.desc'); set('ws-export-btn', 'ws.export'); set('ws-import-btn', 'ws.import');
  set('ws-include-content-lbl', 'ws.include_content'); set('ws-attach-lbl', 'ws.attach'); set('ws-attach-hint', 'ws.attach_hint');
  renderLsPanel();
}

// ── 本機儲存資料盤點與清除（XN104）────────────────────────────────────
// 各工具共用同一個瀏覽器儲存區；這裡只列 key、所屬工具與大小（不顯示內容），標出可能含設定原文、
// 帳密（content 群組、一次性交接 key）或檔名／設備名稱（歷史類）的項目，讓使用者在共用電腦上清除。
const LS_NAME_KEYS = ['_netAnalyzer_anonHistory', '_netAnalyzer_summaries', '_netAnalyzer_activityHistory'];
// entries：[{key,size}]；回傳依風險（secret → names → none）、工具、key 排序的列。純函式
function lsInventory(entries) {
  const handoff = Object.keys(typeof HANDOFF_TTL === 'object' ? HANDOFF_TTL : {});
  const order = { secret: 0, names: 1, none: 2 };
  return (entries || []).filter(e => e && typeof e.key === 'string').map(e => {
    const d = WS_KEYS.find(x => x.key === e.key);
    let tool = d ? d.tool : 'other', group = d ? d.group : 'other', risk = 'none';
    if (handoff.includes(e.key)) { tool = 'common'; group = 'handoff'; }
    if (group === 'content' || group === 'handoff') risk = 'secret';
    else if (LS_NAME_KEYS.includes(e.key)) risk = 'names';
    return { key: e.key, size: Number(e.size) || 0, tool, group, risk };
  }).sort((a, b) => order[a.risk] - order[b.risk] || a.tool.localeCompare(b.tool) || a.key.localeCompare(b.key));
}
function _lsEntries() {
  const out = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k != null) out.push({ key: k, size: (localStorage.getItem(k) || '').length * 2 });
    }
  } catch (e) { /* 儲存區被封鎖時視為空 */ }
  return out;
}
function _lsSize(n) { return n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B'; }
function renderLsPanel() {
  const box = document.getElementById('ls-body');
  if (!box) return;
  const set = (id, k) => { const e = document.getElementById(id); if (e) e.textContent = tr(k); };
  set('ls-summary', 'ls.title'); set('ls-desc', 'ls.desc'); set('ls-clear-sel', 'ls.clear_sel'); set('ls-clear-all', 'ls.clear_all');
  const rows = lsInventory(_lsEntries());
  box.innerHTML = '';
  if (!rows.length) { box.textContent = tr('ls.empty'); return; }
  const tbl = document.createElement('table');
  tbl.className = 'ls-table';
  tbl.style.cssText = 'width:100%;border-collapse:collapse;font-size:12px';
  const head = document.createElement('tr');
  ['', tr('ls.col_tool'), tr('ls.col_key'), tr('ls.col_size'), tr('ls.col_risk')].forEach(t => {
    const th = document.createElement('th'); th.textContent = t; th.style.cssText = 'text-align:left;padding:2px 6px;border-bottom:1px solid var(--border,#334155)'; head.appendChild(th);
  });
  tbl.appendChild(head);
  rows.forEach(r => {
    const tr_ = document.createElement('tr');
    tr_.setAttribute('data-ls-key', r.key);
    const cb = document.createElement('input'); cb.type = 'checkbox'; cb.className = 'ls-cb'; cb.value = r.key;
    const tool = r.tool === 'common' ? tr('ws.tool_common') : r.tool === 'other' ? tr('ls.tool_other') : tr('activity.tool_' + r.tool);
    const cells = [cb, tool, r.key, _lsSize(r.size), r.risk === 'none' ? '' : tr('ls.risk_' + r.risk)];
    cells.forEach((c, i) => {
      const td = document.createElement('td'); td.style.cssText = 'padding:2px 6px;word-break:break-all';
      if (typeof c === 'string') td.textContent = c; else td.appendChild(c);
      if (i === 4 && r.risk !== 'none') { td.style.color = r.risk === 'secret' ? 'var(--red,#ef4444)' : 'var(--yellow,#f59e0b)'; td.setAttribute('data-ls-risk', r.risk); }
      tr_.appendChild(td);
    });
    tbl.appendChild(tr_);
  });
  box.appendChild(tbl);
}
function _lsAfterClear(n) {
  renderLsPanel();
  ['renderRecentAnonHistory', 'renderActivityTimeline', 'renderHealthSummary'].forEach(f => { if (typeof window[f] === 'function') window[f](); });
  const st = document.getElementById('ls-status');
  if (st) st.textContent = tr('ls.cleared').replace('{n}', n);
}
function lsClearSelected() {
  const keys = Array.from(document.querySelectorAll('#ls-body .ls-cb:checked')).map(c => c.value);
  if (!keys.length) return;
  let n = 0;
  keys.forEach(k => { try { localStorage.removeItem(k); n++; } catch (e) { /* 略過 */ } });
  _lsAfterClear(n);
}
function lsClearAll() {
  if (!confirm(tr('ls.confirm_all'))) return;
  const keys = _lsEntries().map(e => e.key);
  let n = 0;
  keys.forEach(k => { try { localStorage.removeItem(k); n++; } catch (e) { /* 略過 */ } });
  _lsAfterClear(n);
}

