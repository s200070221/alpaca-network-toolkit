// network-analyzer.html 拆出的模組（XN101）：成就徽章與活動時間軸。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// ── 成就徽章（2026-10-14，第二十四輪 ED）──────────────────────────────
// 活動紀錄只留最近幾筆，故用過的工具另外累積在 `_netAnalyzer_achievements`（{unlocked:{id:ts}, tools:[]}，
// 持續累積、無 TTL，已加入 WS_KEYS）。computeAchievements() 為純函式：依合併後的活動紀錄、健檢摘要與已累積的工具清單判斷
const ACHIEVEMENTS = [
  { id: 'first', icon: '🐣' }, { id: 'all5', icon: '🦙' }, { id: 'night', icon: '🌙' }, { id: 'weekend', icon: '📅' }, { id: 'clean', icon: '🏅' },
];
const ACH_TOOLS = ['firewall_analyzer', 'switch_analyzer', 'log_analyzer', 'config_anonymizer', 'switch_config_generator'];
function computeAchievements(activity, summaries, knownTools) {
  const tools = new Set(knownTools || []);
  (activity || []).forEach(a => { if (ACH_TOOLS.includes(a.tool)) tools.add(a.tool); });
  const ids = new Set();
  if (tools.size) ids.add('first');
  if (ACH_TOOLS.every(t => tools.has(t))) ids.add('all5');
  (activity || []).forEach(a => {
    if (!a.ts) return;
    const d = new Date(a.ts);
    if (d.getHours() < 5) ids.add('night');
    if (d.getDay() === 0 || d.getDay() === 6) ids.add('weekend');
  });
  if ((summaries || []).some(x => x && x.grade === 'A')) ids.add('clean');
  return { ids, tools: [...tools] };
}
function _readAchStore() {
  let st = null;
  try { st = JSON.parse(localStorage.getItem('_netAnalyzer_achievements') || 'null'); } catch(e) { st = null; }
  if (!st || typeof st !== 'object') st = {};
  if (!st.unlocked || typeof st.unlocked !== 'object') st.unlocked = {};
  if (!Array.isArray(st.tools)) st.tools = [];
  return st;
}
function checkAchievements() {
  const st = _readAchStore();
  const r = computeAchievements(_readActivityTimelineMerged(), _readToolSummaries(), st.tools);
  const fresh = [...r.ids].filter(id => !st.unlocked[id]);
  fresh.forEach(id => { st.unlocked[id] = Date.now(); });
  st.tools = r.tools;
  try { localStorage.setItem('_netAnalyzer_achievements', JSON.stringify(st)); } catch(e) { /* 無法寫入時只顯示本次結果 */ }
  renderAchievements();
  fresh.forEach((id, i) => setTimeout(() => showEggToast(tr('ach.unlocked').replace('{name}', tr('ach.' + id))), 1200 + i * 2500));
}
function renderAchievements() {
  const box = document.getElementById('ach-list');
  if (!box) return;
  document.getElementById('ach-title').textContent = tr('ach.title');
  const st = _readAchStore();
  box.innerHTML = '';
  ACHIEVEMENTS.forEach(a => {
    const on = !!st.unlocked[a.id];
    const el = document.createElement('span');
    el.className = 'ach-badge' + (on ? ' on' : '');
    el.title = tr('ach.' + a.id + '_desc');
    el.textContent = a.icon + ' ' + tr('ach.' + a.id);
    el.style.cssText = 'display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:12px;border:1px solid var(--border,#334155);font-size:12px;' + (on ? '' : 'opacity:.35;filter:grayscale(1)');
    box.appendChild(el);
  });
}
function _readActivityTimelineMerged() {
  const act = _readObjArray('_netAnalyzer_activityHistory');
  const anon = _readObjArray('_netAnalyzer_anonHistory');
  const merged = act.map(h => ({ tool: h.tool || '', name: h.name || '', vendor: h.vendor || null, ts: h.ts || 0 }))
    .concat(anon.map(h => ({ tool: 'config_anonymizer', name: h.name || '', vendor: h.vendor || null, ts: h.ts || 0 })));
  merged.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  return merged;
}
function renderActivityTimeline() {
  const titleTextEl = document.getElementById('activity-timeline-title-text');
  if (titleTextEl) titleTextEl.textContent = tr('hub.activity_title');
  const exportBtn = document.getElementById('activity-timeline-export-btn');
  if (exportBtn) exportBtn.textContent = tr('hub.activity_export');
  const clearBtn = document.getElementById('activity-timeline-clear-btn');
  if (clearBtn) clearBtn.textContent = tr('hub.activity_clear');
  const box = document.getElementById('activity-timeline-list');
  if (!box) return;
  const all = _readActivityTimelineMerged();
  // 依工具篩選（2026-09-24 新增）：選項只列出目前紀錄中實際出現過的工具，
  // 重建選項時保留使用者原本的選擇（該工具紀錄被清空時自動回到「全部」）
  const filterEl = document.getElementById('activity-timeline-filter');
  let selTool = filterEl ? filterEl.value : '';
  const tools = [...new Set(all.map(h => h.tool).filter(Boolean))];
  if (!tools.includes(selTool)) selTool = '';
  if (filterEl) {
    filterEl.innerHTML = '';
    const optAll = document.createElement('option');
    optAll.value = ''; optAll.textContent = tr('hub.activity_filter_all');
    filterEl.appendChild(optAll);
    tools.forEach(t => {
      const o = document.createElement('option');
      o.value = t; o.textContent = tr('activity.tool_' + t);
      filterEl.appendChild(o);
    });
    filterEl.value = selTool;
    filterEl.style.display = tools.length > 1 ? '' : 'none';
  }
  const merged = selTool ? all.filter(h => h.tool === selTool) : all;
  box.innerHTML = '';
  if (exportBtn) exportBtn.style.display = all.length ? '' : 'none';
  if (clearBtn) clearBtn.style.display = all.length ? '' : 'none';
  if (!merged.length) {
    const empty = document.createElement('div');
    empty.className = 'recent-anon-empty';
    empty.textContent = tr('hub.activity_empty');
    box.appendChild(empty);
    return;
  }
  // 用 DOM API 逐一建構（非 innerHTML+字串拼接），name 來自使用者本機檔名，比照
  // renderRecentAnonHistory() 既有 Stored XSS 防護慣例，一律用 textContent 賦值
  merged.slice(0, ACTIVITY_TIMELINE_MAX_SHOW).forEach(h => {
    const meta = ACTIVITY_TOOL_META[h.tool] || { icon: '🔧', href: '#' };
    const row = document.createElement('a');
    row.className = 'recent-anon-item';
    row.href = meta.href;
    row.style.display = 'block';
    row.style.textDecoration = 'none';
    row.style.color = 'inherit';
    const when = h.ts ? new Date(h.ts).toLocaleString() : '';
    const toolLabel = tr('activity.tool_' + h.tool);
    let text = meta.icon + ' ' + when + ' — ' + toolLabel;
    if (h.vendor) text += '（' + h.vendor + '）';
    if (h.name) text += ' — ' + h.name;
    row.textContent = text;
    box.appendChild(row);
  });
}
// 純前端本機匯出，不涉及任何外傳（Blob + URL.createObjectURL，比照本專案「離線可用」的
// 一貫原則）；匯出內容就是目前畫面上顯示的合併時間軸資料（未受 8 筆顯示上限截斷前的完整清單）
// 清除時間軸（2026-09-24 新增）：時間軸同時顯示 `_netAnalyzer_activityHistory` 與
// `_netAnalyzer_anonHistory`，只清前者會讓去識別化紀錄殘留在畫面上造成「按了沒反應」的錯覺，
// 故兩者一併清除（確認訊息已註明含去識別化紀錄），並同步重繪上方既有的去識別化卡片
function clearActivityTimeline() {
  if (!confirm(tr('hub.activity_clear_confirm'))) return;
  try {
    localStorage.removeItem('_netAnalyzer_activityHistory');
    localStorage.removeItem('_netAnalyzer_anonHistory');
  } catch(e) { /* localStorage 被封鎖時靜默略過 */ }
  if (typeof renderRecentAnonHistory === 'function') renderRecentAnonHistory();
  renderActivityTimeline();
}
function exportActivityTimeline() {
  const merged = _readActivityTimelineMerged();
  const blob = new Blob([JSON.stringify(merged, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'network_analyzer_activity_' + Date.now() + '.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

