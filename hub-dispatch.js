// network-analyzer.html 拆出的模組（XN101）：交接到各工具（_dispatchWithPending／_dispatchWithAnon）、最近去識別化紀錄、活動紀錄常數。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// 2026-07-24 修復既有隱患：真實設定檔（尤其含大量位址/服務物件的 FortiGate 匯出）可能達數 MB，
// 超過瀏覽器單一來源 localStorage 容量上限（多數瀏覽器 5-10MB）時 setItem() 會拋出
// QuotaExceededError，若未接住會讓後面的 window.open() 完全不執行，使用者看起來就是「按鈕沒反應」。
// 補上 try/catch：交接失敗時仍正常開啟工具分頁（只是不會自動帶入該檔案，使用者需手動上傳），並提示原因
// 2026-09 資安審查修復：window.open() 若被瀏覽器彈出視窗攔截會回傳 null，此時目標分頁不會開啟、
// 也不會有任何程式碼去讀取並清除剛寫入的 key，導致明碼設定內容無限期留在 localStorage（這是「放棄
// 交接流程」最常見的真實觸發情境）。補上偵測：write 成功但視窗開不成時，立刻清掉剛寫入的 key 並提示。
// keepOverlay（2026-09-24 新增）：多檔清單逐檔開啟時為 true，開完一個檔案不關閉拖放層，
// 讓使用者繼續開下一個；單檔流程不傳，行為不變
function _dispatchWithPending(toolIdx, vendor, keepOverlay) {
  if (!_dropPending) return;
  let wrote = false;
  try {
    localStorage.setItem('_netAnalyzer_pending', JSON.stringify({
      name: _dropPending.name, text: _dropPending.text, ts: Date.now(), vendor: vendor || null
    }));
    wrote = true;
  } catch(e) { alert(tr('drop.pending_too_large')); }
  const w = window.open(TOOLS[toolIdx].href, '_blank');
  if (wrote && !w) { localStorage.removeItem('_netAnalyzer_pending'); alert(tr('drop.popup_blocked')); }
  if (!keepOverlay) setTimeout(() => document.getElementById('drop-overlay').classList.remove('active'), 350);
  _dropPending = null;
  return !!(wrote && w);
}
function _dispatchWithAnon(toolIdx, vendor) {
  if (!_dropPending) return;
  let wrote = false;
  try {
    localStorage.setItem('_netAnalyzer_anonThenOpen', JSON.stringify({
      name: _dropPending.name, text: _dropPending.text, ts: Date.now(), toolIdx, vendor: vendor || null
    }));
    wrote = true;
  } catch(e) { alert(tr('drop.pending_too_large')); }
  const w = window.open(TOOLS[2].href, '_blank');
  if (wrote && !w) { localStorage.removeItem('_netAnalyzer_anonThenOpen'); alert(tr('drop.popup_blocked')); }
  setTimeout(() => document.getElementById('drop-overlay').classList.remove('active'), 350);
  _dropPending = null;
}
// 2026-09 資安審查修復：本頁自己在載入時也順手清掉「已過期」的交接 key——使用者若曾經拖放
// 過檔案但流程中斷（例如上面的彈出視窗攔截偵測補上之前就已發生過的舊資料、或其他分頁開了但
// 使用者沒有理它），繞回首頁時不需要專屬處理程序也能清掉殘留，縮小明碼內容的曝險窗口。本頁本身
// 是這些 key 的生產端、不消費任何一個，故只做過期即清，不讀取 .text 內容。
(function(){
  var TTL = {_netAnalyzer_pending:10000, _netAnalyzer_anonThenOpen:30000, _netAnalyzer_anonResult:30000, _netAnalyzer_swParsedModel:30000, _netAnalyzer_fwQuery:30000, _netAnalyzer_swPortQuery:30000, _netAnalyzer_route:30000};
  // 瀏覽器封鎖儲存區時 localStorage 存取本身會丟錯，整段包起來避免中斷後續腳本
  try {
    Object.keys(TTL).forEach(function(k){
      var raw = localStorage.getItem(k);
      if (!raw) return;
      try {
        var d = JSON.parse(raw);
        if (Date.now() - d.ts > TTL[k]) localStorage.removeItem(k);
      } catch(e) { localStorage.removeItem(k); }
    });
  } catch(e) {}
})();

// Phase 4 第 17 項：顯示 config_anonymizer 寫入的 rolling-history（`_netAnalyzer_anonHistory`，
// 最近 5 筆 {name,vendor,ts}，無 TTL——這是持續累積的小型歷史，不是一次性交接 key，故不與上面
// 的 TTL 清理邏輯共用）。查無資料時顯示空狀態文字。呼叫點：頁面載入時一次＋setLang() 內
// （語言切換時標題/空狀態文字需要重新翻譯，比照既有 renderCards() 呼叫慣例）
// 讀取持續性歷史 key：只回傳物件元素（工作區還原或手動修改可能寫入 [null] 等形狀不對的值）
function _readObjArray(key) {
  let a = [];
  try { a = JSON.parse(localStorage.getItem(key) || '[]'); } catch (e) { a = []; }
  return Array.isArray(a) ? a.filter(h => h && typeof h === 'object' && !Array.isArray(h)) : [];
}
function renderRecentAnonHistory() {
  var titleTextEl = document.getElementById('recent-anon-title-text');
  if (titleTextEl) titleTextEl.textContent = tr('hub.recent_anon_title');
  var clearBtn = document.getElementById('recent-anon-clear-btn');
  if (clearBtn) clearBtn.textContent = tr('hub.recent_anon_clear');
  var box = document.getElementById('recent-anon-list');
  if (!box) return;
  var hist = [];
  hist = _readObjArray('_netAnalyzer_anonHistory');
  box.innerHTML = '';
  if (clearBtn) clearBtn.style.display = hist.length ? '' : 'none';
  if (!hist.length) {
    var empty = document.createElement('div');
    empty.className = 'recent-anon-empty';
    empty.textContent = tr('hub.recent_anon_empty');
    box.appendChild(empty);
    return;
  }
  // 用 DOM API 逐一建構（非 innerHTML+字串拼接），h.name 來自使用者本機檔名，比照本專案
  // 既有 Stored XSS 修復慣例避免未跳脫字串進 innerHTML；2026-09-14 新增：每筆歷史紀錄改包一層
  // <a> 導覽連結（比照既有工具導覽連結樣式），純導覽不帶資料 payload，label 部分仍用
  // textContent 賦值維持既有 XSS 防護慣例
  hist.forEach(function(h){
    var row = document.createElement('a');
    row.className = 'recent-anon-item';
    row.href = 'config-anonymizer.html';
    row.style.display = 'block';
    row.style.textDecoration = 'none';
    row.style.color = 'inherit';
    var when = h.ts ? new Date(h.ts).toLocaleString() : '';
    row.textContent = '🔒 ' + when + (h.name ? (' — ' + h.name) : '');
    box.appendChild(row);
  });
}
// Rolling-history 清除按鈕（2026-09-14 新增）：筆數上限（現況寫死在 config-anonymizer.html
// 的 .slice(0,5)）本輪不做成可設定，僅提供清除功能
function clearRecentAnonHistory() {
  localStorage.removeItem('_netAnalyzer_anonHistory');
  renderRecentAnonHistory();
}

// 任務 1（2026-09-23 新增）：跨工具活動時間軸。合併兩個 rolling-history key——
// `_netAnalyzer_activityHistory`（log_analyzer／switch_config_generator 等工具共用，
// {tool,name,vendor,ts}）與既有 `_netAnalyzer_anonHistory`（config_anonymizer 專用，
// {name,vendor,ts}）——依 ts 新到舊排序後統一顯示。兩者皆為「持續累積歷史」，無 TTL，
// 不進上方 `_dispatchWithPending`/`_dispatchWithAnon` 旁那個一次性交接 key 的過期清理迴圈
// （CLAUDE.md 已特別提醒這兩種性質不同、不可套用同一套清理規則）。
const ACTIVITY_TOOL_META = {
  log_analyzer:              { icon: '📜', href: 'log-analyzer.html' },
  switch_config_generator:   { icon: '🛠️', href: 'switch-config-generator.html' },
  switch_analyzer:           { icon: '🔀', href: 'switch-config-parser.html' },
  firewall_analyzer:         { icon: '🛡️', href: 'firewall-analyzer-fixed.html' },
  config_anonymizer:         { icon: '🔒', href: 'config-anonymizer.html' },
};
const ACTIVITY_TIMELINE_MAX_SHOW = 8;
