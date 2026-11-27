// network-analyzer.html 拆出的模組（UX39）：首頁改成單純導引頁，原本直接排在首頁上的功能（任務引導、網站憑證檢查、
// 設備版本比對、綜合健檢、使用紀錄與成就、工作區、術語辭典）各自成為一個「畫面」，點首頁卡片才開啟，首頁本身只顯示卡片。
// 畫面以網址 #<畫面 id> 切換（可加書籤、瀏覽器上一頁回首頁）；畫面容器為 .hub-view[data-view]，內容沿用原本區塊。
// 也接受畫面內元素的 id（例如 #cert-paste、#gl-vlan），往上找到所屬畫面再開啟，舊連結照常可用。
// 與其他 hub-*.js 共用全域（不包 IIFE），載入在 hub-drop.js 之後、hub-init.js 之前。
const HUB_VIEWS = ['tasks', 'certcheck', 'devcheck', 'health', 'history', 'workspace', 'glossary'];
let _hubView = '', _hubFromHome = false;
// 網址錨點 → 畫面 id（不是畫面也不在畫面內時回傳 ''，代表首頁）
function hubViewOfHash(hash) {
  // 網址錨點可能是不合格的百分比編碼（手打或外部連結），解不開時當成首頁
  let id = '';
  try { id = decodeURIComponent(String(hash || '').replace(/^#/, '')); } catch (e) { return ''; }
  if (!id) return '';
  if (HUB_VIEWS.includes(id)) return id;
  const el = document.getElementById(id), box = el && el.closest ? el.closest('.hub-view') : null;
  return box ? box.getAttribute('data-view') || '' : '';
}
// 顯示某個畫面（id 為空或不認得＝首頁）；opts.keepHash：不改網址（辭典 #gl-<id> 等由呼叫端自己處理捲動）
function showHubView(id, opts) {
  const v = HUB_VIEWS.includes(id) ? id : '';
  const o = opts || {};
  if (!o.keepHash && v && location.hash.replace(/^#/, '') !== v) {
    // 從首頁點進來時記住，回首頁時用瀏覽器上一頁，避免歷史紀錄越堆越多
    _hubFromHome = !_hubView;
    history.pushState(null, '', '#' + v);
  }
  _hubView = v;
  document.body.classList.toggle('hub-in-view', !!v);
  document.querySelectorAll('.hub-view').forEach(el => { el.hidden = el.getAttribute('data-view') !== v; });
  const home = document.getElementById('cards'), bar = document.getElementById('hub-view-bar');
  if (home) home.hidden = !!v;
  if (bar) bar.hidden = !v;
  if (!o.keepHash) window.scrollTo(0, 0);
}
function hubGoHome() {
  if (_hubFromHome) { _hubFromHome = false; history.back(); return; }
  history.pushState(null, '', location.pathname + location.search);
  showHubView('');
}
// 依目前網址切換（載入時與上一頁／下一頁）；辭典的 #gl-<id> 交給 openGlossary() 展開該詞條
function hubRoute() {
  const v = hubViewOfHash(location.hash);
  if (v === 'glossary' && /^#gl-/.test(location.hash)) { openGlossary(); return; }
  _hubFromHome = false;
  showHubView(v, { keepHash: true });
  if (v && location.hash.replace(/^#/, '') !== v) {
    const el = document.getElementById(location.hash.slice(1));
    if (el) setTimeout(() => el.scrollIntoView({ block: 'start' }), 0);
  }
}
window.addEventListener('hashchange', hubRoute);
window.addEventListener('popstate', hubRoute);
// 首頁的畫面卡片（a[href="#<id>"]）與任務卡內的 #certcheck 等連結：改用 pushState 切換，回首頁時能用上一頁
document.addEventListener('click', e => {
  const a = e.target && e.target.closest ? e.target.closest('a[href^="#"]') : null;
  if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey) return;
  const v = hubViewOfHash(a.getAttribute('href'));
  if (!v || /^#gl-/.test(a.getAttribute('href'))) return;
  e.preventDefault();
  showHubView(v);
});
