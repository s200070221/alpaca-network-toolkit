// network-analyzer.html 拆出的模組（XN101）：綜合健檢報告。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// ── 綜合健檢報告（2026-09-30 新增，第八輪 XA）────────────────────────────────
// 資料來源 `_netAnalyzer_summaries`：交換器／防火牆分析完成時寫入 {tool,name,vendor,ts,score,grade,n,crit,warn,top}
// （防火牆另有 accepted），log 分析寫入 {tool,name,ts,events,n,crit,warn,open,top}；每個工具＋名稱只留最新一筆。
// 項目名稱（top[].label）是各工具分析當下的介面語言。純本機彙整，不連網
function _readToolSummaries() {
  // top 只留物件項目：工作區還原可能寫入形狀不對的內容，避免後續 .map 拋錯中斷整個入口頁初始化
  // kev／cves（XN63，韌體落在已遭利用漏洞範圍）：只接受非負整數與 CVE 編號格式
  return _readObjArray('_netAnalyzer_summaries').filter(x => x.tool)
    .map(x => Object.assign({}, x, { top: Array.isArray(x.top) ? x.top.filter(t => t && typeof t === 'object') : [],
      kev: Number.isInteger(x.kev) && x.kev > 0 ? x.kev : 0,
      cves: Array.isArray(x.cves) ? x.cves.filter(c => typeof c === 'string' && /^CVE-\d{4}-\d+$/.test(c)).slice(0, 5) : [] }));
}
const HS_GRADE_ORDER = ['F', 'D', 'C', 'B', 'A'];
function _hsCell(v) { return String(v == null ? '' : v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, ' '); }
function _hsName(x) { return x.name || tr('hs.unnamed'); }
// 趨勢（第二十五輪 LH）：與 history[0]（上一次分析）比較分數與問題數；沒有上一次時回傳空字串
function _hsTrend(x) {
  const prev = x && Array.isArray(x.history) ? x.history[0] : null;
  if (!prev) return '';
  const sign = d => (d > 0 ? '+' : '') + d;
  const parts = [];
  if (typeof prev.score === 'number' && typeof x.score === 'number')
    parts.push(tr('hs.trend_score').replace('{old}', prev.score).replace('{new}', x.score).replace('{delta}', sign(x.score - prev.score)));
  if (typeof prev.n === 'number' && typeof x.n === 'number')
    parts.push(tr('hs.trend_issues').replace('{old}', prev.n).replace('{new}', x.n).replace('{delta}', sign(x.n - prev.n)));
  return parts.join(tr('hs.sep'));
}
// 趨勢小圖（第二十六輪 SH）：歷次（舊→新）加本次的分數，log 用問題數，以方塊字表示高低；少於兩次時回傳空字串
const HS_SPARK = '▁▂▃▄▅▆▇█';
function _hsSeries(x) {
  const key = x.tool === 'log_analyzer' ? 'n' : 'score';
  const vals = (Array.isArray(x.history) ? x.history.slice().reverse() : []).map(h => h && h[key]).concat([x[key]]);
  return vals.filter(v => typeof v === 'number');
}
function _hsSpark(x) {
  const v = _hsSeries(x);
  if (v.length < 2) return '';
  const lo = Math.min(...v), hi = Math.max(...v);
  return v.map(n => HS_SPARK[hi === lo ? 3 : Math.round((n - lo) / (hi - lo) * 7)]).join('');
}
// 彩蛋（第二十六輪 SI）：設備摘要兩台以上且全部 A 級、或某台分數比上次進步 30 分以上時提示；同一份摘要只提示一次
function _hsEggs(list) {
  try {
    const devs = list.filter(x => x.tool !== 'log_analyzer');
    const seen = k => { if (sessionStorage.getItem(k)) return true; sessionStorage.setItem(k, '1'); return false; };
    if (devs.length >= 2 && devs.every(x => x.grade === 'A') && !seen('_hsEggAllA_' + devs.map(x => x.ts).join(','))) { showEggToast(tr('egg.all_a')); return; }
    const up = devs.find(x => Array.isArray(x.history) && x.history[0] && typeof x.history[0].score === 'number' && typeof x.score === 'number' && x.score - x.history[0].score >= 30);
    if (up && !seen('_hsEggComeback_' + up.ts)) showEggToast(tr('egg.comeback').replace('{name}', _hsName(up)).replace('{old}', up.history[0].score).replace('{new}', up.score));
  } catch (e) { /* sessionStorage 不可用時略過 */ }
}
function buildHubHealthReport(list, now) {
  const devs = list.filter(x => x.tool !== 'log_analyzer');
  const logs = list.filter(x => x.tool === 'log_analyzer');
  const L = [`# ${tr('hs.report_title')}`, '', `- ${tr('hs.generated')}: ${(now || new Date()).toISOString()}`, ''];
  L.push(`## ${tr('hs.overview')}`, '');
  if (!list.length) { L.push(tr('hs.empty'), ''); return L.join('\n'); }
  L.push('- ' + tr('hs.count').replace('{sw}', devs.filter(x => x.tool === 'switch_analyzer').length).replace('{fw}', devs.filter(x => x.tool === 'firewall_analyzer').length).replace('{log}', logs.length));
  if (devs.length) {
    const dist = HS_GRADE_ORDER.slice().reverse().map(g => `${g} ${devs.filter(x => x.grade === g).length}`).join(tr('hs.sep'));
    L.push('- ' + tr('hs.grades').replace('{dist}', dist));
    const worst = devs.filter(x => x.grade === 'F' || x.grade === 'D').sort((a, b) => a.score - b.score);
    L.push('- ' + (worst.length ? tr('hs.worst').replace('{list}', worst.map(x => `${_hsName(x)} (${x.grade}, ${x.score})`).join(tr('hs.sep'))) : tr('hs.no_worst')));
    // 韌體落在已遭利用漏洞範圍（XN63）；沒有時不寫「沒有」——版本可能不完整，不能下結論
    const kevDevs = devs.filter(x => x.kev > 0);
    if (kevDevs.length) L.push('- ' + tr('hs.kev').replace('{list}', kevDevs.map(x => `${_hsName(x)} (${x.cves.join(', ') || x.kev})`).join(tr('hs.sep'))));
  }
  const logHigh = logs.filter(x => x.crit > 0);
  if (logs.length) L.push('- ' + (logHigh.length ? tr('hs.log_high').replace('{list}', logHigh.map(x => `${_hsName(x)} (${x.crit})`).join(tr('hs.sep'))) : tr('hs.log_no_high')));
  // 跨設備共同問題：同一個項目名稱出現在兩台以上設備的前三項中
  const freq = {};
  list.forEach(x => (x.top || []).forEach(t => { (freq[t.label] = freq[t.label] || []).push(_hsName(x)); }));
  const common = Object.keys(freq).filter(k => freq[k].length > 1).sort((a, b) => freq[b].length - freq[a].length);
  if (common.length) L.push('- ' + tr('hs.common').replace('{list}', common.slice(0, 5).map(k => `${k} (${freq[k].length})`).join(tr('hs.sep'))));
  L.push('', `## ${tr('hs.detail')}`, '',
    `| ${tr('hs.col_tool')} | ${tr('hs.col_name')} | ${tr('hs.col_time')} | ${tr('hs.col_grade')} | ${tr('hs.col_trend')} | ${tr('hs.col_history')} | ${tr('hs.col_risk')} | ${tr('hs.col_top')} | ${tr('hs.col_note')} |`,
    '|---|---|---|---|---|---|---|---|---|');
  list.slice().sort((a, b) => (a.tool === 'log_analyzer') - (b.tool === 'log_analyzer') || HS_GRADE_ORDER.indexOf(a.grade) - HS_GRADE_ORDER.indexOf(b.grade) || (a.score || 0) - (b.score || 0)).forEach(x => {
    const isLog = x.tool === 'log_analyzer';
    const grade = isLog ? '—' : `${x.grade} (${x.score})`;
    const top = (x.top || []).map(t => `${t.label} (${t.count})`).join(tr('hs.sep')) || '—';
    const note = isLog ? tr('hs.note_log').replace('{events}', x.events || 0).replace('{n}', x.n || 0).replace('{open}', x.open || 0)
      : [x.kev ? tr('hs.kev_row').replace('{n}', x.kev) + (x.cves.length ? ' ' + x.cves.join(', ') : '') : '',
         x.accepted ? tr('hs.note_accepted').replace('{n}', x.accepted) : ''].filter(Boolean).join(tr('hs.sep'));
    L.push(`| ${_hsCell(tr('activity.tool_' + x.tool))} | ${_hsCell(_hsName(x) + (x.vendor ? ' (' + x.vendor + ')' : ''))} | ${_hsCell(x.ts ? new Date(x.ts).toLocaleString() : '')} | ${grade} | ${_hsCell(_hsTrend(x) || '—')} | ${_hsCell(_hsSeries(x).length > 1 ? _hsSeries(x).join(' → ') : '—')} | ${x.crit || 0} / ${x.warn || 0} | ${_hsCell(top)} | ${_hsCell(note)} |`);
  });
  L.push('', `> ${tr('hs.source_note')}`, '');
  return L.join('\n');
}
function renderHealthSummary() {
  const t = document.getElementById('health-summary-title');
  if (t) t.textContent = tr('hs.title');
  const dl = document.getElementById('health-summary-dl-btn'), cl = document.getElementById('health-summary-clear-btn');
  if (dl) dl.textContent = tr('hs.download');
  if (cl) cl.textContent = tr('hub.activity_clear');
  const box = document.getElementById('health-summary-list');
  if (!box) return;
  const list = _readToolSummaries();
  if (dl) dl.style.display = list.length ? '' : 'none';
  if (cl) cl.style.display = list.length ? '' : 'none';
  box.innerHTML = '';
  if (!list.length) {
    const e = document.createElement('div'); e.className = 'recent-anon-empty'; e.textContent = tr('hs.empty'); box.appendChild(e); return;
  }
  // 名稱與項目來自設定檔／log 內容，一律用 textContent 建構（比照 renderActivityTimeline 的 XSS 防護慣例）
  list.slice(0, 8).forEach(x => {
    const row = document.createElement('div');
    row.className = 'recent-anon-item';
    const meta = ACTIVITY_TOOL_META[x.tool] || { icon: '🔧' };
    const head = x.tool === 'log_analyzer'
      ? tr('hs.row_log').replace('{n}', x.n || 0).replace('{crit}', x.crit || 0).replace('{open}', x.open || 0)
      : tr('hs.row_dev').replace('{grade}', x.grade).replace('{score}', x.score).replace('{crit}', x.crit || 0);
    const trend = _hsTrend(x), spark = _hsSpark(x);
    const kev = x.kev ? ' | ⚠ ' + tr('hs.kev_row').replace('{n}', x.kev) : '';
    row.textContent = `${meta.icon} ${_hsName(x)} — ${head}${kev}${trend ? ' | ' + tr('hs.trend_label') + ' ' + trend + (spark ? ' ' + spark : '') : ''}${x.top && x.top.length ? ' | ' + x.top.map(t => t.label).join(tr('hs.sep')) : ''}`;
    box.appendChild(row);
  });
  _hsEggs(list);
}
function downloadHubHealthReport() {
  const blob = new Blob([buildHubHealthReport(_readToolSummaries())], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'network_health_report_' + Date.now() + '.md';
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
function clearHealthSummary() {
  if (!confirm(tr('hs.clear_confirm'))) return;
  try { localStorage.removeItem('_netAnalyzer_summaries'); } catch (e) {}
  renderHealthSummary();
}

