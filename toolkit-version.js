// 整套工具共用的版本號與「本版新增」（2026-10-21，第三十三輪 XN3）。
// 7 個頁面以 <script src="toolkit-version.js"> 載入；頁面放一個 data-toolkit-version 佔位元素，
// 切換語言時呼叫 renderToolkitVersion(lang)。版本號＝GitHub Release tag，發版時只改這個檔案：
// 把 TOOLKIT_VERSION 改成發版日期，CHANGELOG 最前面插入一筆（items 只寫 zhTW／en，其餘語言顯示 en）。
(function () {
  const TOOLKIT_VERSION = '2026.10.21';
  const CHANGELOG = [
    {
      version: '2026.10.21',
      items: {
        zhTW: [
          '第一個標註版本號的版本，之後每次更新都會在這裡列出新增內容',
          '所有頁面加上內容安全政策（CSP），由瀏覽器強制禁止工具把資料送到外部（情資整理頁抓取清單除外）',
          '交換器產生器：修復「下載 Word」一直無法使用的問題',
          'log 分析：支援 FreeRADIUS、OpenLDAP／389 DS 與更多 Windows log 格式，新增 AD 主機登入關係表與跨網域登入',
          '新增情資清單整理頁：勾選公開情資來源一鍵下載，整理成 log 分析可直接匯入的格式',
          '第一次使用體驗：各工具可一鍵載入範例、分析後顯示下一步提示列、貼錯工具時提示改用哪個工具',
        ],
        en: [
          'First release with a version number; future updates will be listed here',
          'All pages now ship a Content Security Policy, so the browser itself blocks the tools from sending data anywhere (except the threat-intel builder fetching lists)',
          'Switch Config Generator: fixed "Download Word", which never worked before',
          'Log Analyzer: FreeRADIUS, OpenLDAP / 389 DS and more Windows log formats; AD host logon map and cross-domain logons',
          'New threat-intel builder page: pick public intel sources, download them in one go and convert to the Log Analyzer import format',
          'First-run experience: one-click samples in every tool, a next-step bar after analysis, and a hint when a file belongs to another tool',
        ],
      },
    },
  ];
  // 標籤 12 語言（leet／uwu 等演算法語言與未列出的語言退回 en）
  const LABELS = {
    zhTW:   { whatsNew: '本版新增', title: '版本 {v} 更新內容', close: '關閉' },
    en:     { whatsNew: "What's new", title: 'What changed in {v}', close: 'Close' },
    ja:     { whatsNew: '更新内容', title: 'バージョン {v} の更新内容', close: '閉じる' },
    tlh:    { whatsNew: 'chu\' De\'', title: '{v} chu\' De\'', close: 'SoQmoH' },
    pirate: { whatsNew: 'New plunder', title: 'Plunder added in {v}, arr!', close: 'Belay that' },
    emoji:  { whatsNew: '🆕✨', title: '📦 {v} 🆕', close: '❌' },
    bureau: { whatsNew: '本版異動公告', title: '版本 {v} 異動事項公告', close: '結案歸檔' },
    cat:    { whatsNew: '本版新增喵', title: '版本 {v} 新玩具喵', close: '關掉喵' },
    bean:   { whatsNew: '本版新增豆', title: '版本 {v} 新長出的豆', close: '收豆' },
    alpaca: { whatsNew: '羊駝新貨', title: '羊駝 {v} 新草料咩', close: '回去吃草' },
    yanse:  { whatsNew: '又更新了', title: '{v} 又改了什麼，看看就好', close: '算了' },
    wuxia:  { whatsNew: '新練絕學', title: '第 {v} 卷新增武學', close: '收功' },
  };

  const lbl = lang => LABELS[lang] || LABELS.en;
  const itemsOf = (entry, lang) => entry.items[lang] || entry.items.en;
  // 只有 zhTW 用繁中內容；ja 與彩蛋語言之中，中文系彩蛋（bureau／cat／bean／alpaca／yanse／wuxia）也用繁中
  const contentLang = lang => (['zhTW', 'bureau', 'cat', 'bean', 'alpaca', 'yanse', 'wuxia'].includes(lang) ? 'zhTW' : 'en');

  let current = 'zhTW';
  function openDialog() {
    let dlg = document.getElementById('toolkit-whatsnew');
    if (dlg) dlg.remove();
    const L = lbl(current);
    dlg = document.createElement('dialog');
    dlg.id = 'toolkit-whatsnew';
    // margin:auto 必須明寫：各頁的 *{margin:0} 重設會蓋掉 <dialog> 預設置中
    dlg.style.cssText = 'margin:auto;max-width:560px;width:calc(100% - 32px);border:1px solid var(--border,#ccc);border-radius:10px;padding:18px 20px;' +
      'background:var(--surface,var(--card,#fff));color:var(--text,#222);font-size:14px;line-height:1.6';
    const h = document.createElement('h3');
    h.style.cssText = 'margin:0 0 10px;font-size:16px';
    h.textContent = L.title.replace('{v}', TOOLKIT_VERSION);
    const ul = document.createElement('ul');
    ul.style.cssText = 'margin:0 0 14px;padding-left:20px';
    for (const t of itemsOf(CHANGELOG[0], contentLang(current))) {
      const li = document.createElement('li');
      li.textContent = t;
      ul.appendChild(li);
    }
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = L.close;
    btn.style.cssText = 'float:right;padding:4px 14px;border:1px solid var(--border,#ccc);border-radius:6px;background:transparent;color:inherit;cursor:pointer';
    btn.addEventListener('click', () => dlg.close());
    dlg.append(h, ul, btn);
    document.body.appendChild(dlg);
    dlg.showModal();
  }

  function renderToolkitVersion(lang) {
    if (lang) current = lang;
    const L = lbl(current);
    document.querySelectorAll('[data-toolkit-version]').forEach(el => {
      el.textContent = '';
      el.append(document.createTextNode(TOOLKIT_VERSION + ' · '));
      const a = document.createElement('a');
      a.href = '#';
      a.textContent = L.whatsNew;
      a.style.cssText = 'color:var(--accent,inherit);text-decoration:underline;cursor:pointer';
      a.addEventListener('click', e => { e.preventDefault(); openDialog(); });
      el.appendChild(a);
    });
  }

  window.TOOLKIT_VERSION = TOOLKIT_VERSION;
  window.TOOLKIT_CHANGELOG = CHANGELOG;
  window.renderToolkitVersion = renderToolkitVersion;
  // 頁面自己的 setLang 會再呼叫一次；這裡先依共用語言偏好畫出來
  document.addEventListener('DOMContentLoaded', () => {
    let lang = '';
    try { lang = localStorage.getItem('cw_lang') || ''; } catch (e) {}
    renderToolkitVersion(lang || 'zhTW');
  });
})();
