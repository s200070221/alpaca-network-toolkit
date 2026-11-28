// network-analyzer.html 拆出的模組（XN101）：tr／setLang、工具卡片 TOOLS、任務卡 TASKS、術語辭典、showEggToast。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// ── tr / setLang ───────────────────────────────────────────────────
let _lang = 'zhTW';
// 翻譯：共用 toolkit-common.js 的 tkTr()（彩蛋語言退回規則、leet／uwu／cat／bean 轉換）
function tr(k) { return tkTr(LANG, _lang, k); }

function tip(key, label, n) {
  // n：說明文字中的 {n}（支援廠牌數，XN52 由 TOOLS 清單長度算出，不寫死在文字裡）
  const t = n == null ? tr(key) : tr(key).replace('{n}', n);
  if (!t || t === key) return label;
  return `<span data-tip="${t.replace(/"/g,'&quot;')}">${label}<sup style="font-size:8px;opacity:.45;margin-left:2px;cursor:help">ⓘ</sup></span>`;
}
// 語言偏好跨工具共用（2026-09-29，PB）：共用 localStorage key 'cw_lang'（比照主題 'cw_theme'），
// 只記住三種正式語言；彩蛋語言需各工具各自解鎖，不跨工具帶入。未存過時依瀏覽器語言決定
// 無障礙（UE，2026-09-29 新增）：沒有可存取名稱的輸入欄位，自動關聯到緊鄰的標籤——前一個兄弟元素是
// 沒有 for 的 <label> 時補 for；是 <span> 時以 aria-labelledby 指向它（語言切換後名稱跟著更新）。
// 已有 label／aria／title／placeholder（瀏覽器本身會當名稱）者不動。函式在 toolkit-common.js
function setLang(lang) {
  _lang = lang;
  saveLangPref(lang);
  document.documentElement.lang = lang === 'zhTW' ? 'zh-TW' : lang;
  window.renderToolkitVersion&&renderToolkitVersion(lang);
  document.querySelectorAll('.lang-btn[data-lang]').forEach(b => {
    b.classList.toggle('active', b.dataset.lang === lang);
  });
  document.getElementById('h-sub').textContent = tr('suite.sub');
  document.getElementById('h-hero').textContent = tr('suite.hero');
  ['h-step1', 'h-step2', 'h-step3'].forEach((id, i) => { document.getElementById(id).textContent = tr('hero.step' + (i + 1)); });
  document.getElementById('h-notice').textContent = tr('notice.place');
  document.getElementById('h-footer').innerHTML = tip('tip.footer', tr('suite.footer'));
  document.getElementById('alpaca-btn').title = tr('egg.alpaca');
  document.getElementById('logo-btn').title = tr('egg.logo_hint');
  // 跨工具導覽面板（2026-08-24 新增）：本檔案 setLang() 慣例是逐一手動更新指定元素，
  // 沒有通用的 [data-i18n] 掃描機制，故比照既有寫法，範圍限定在導覽面板內
  document.querySelectorAll('#tools-nav-panel [data-i18n]').forEach(el => { el.textContent = tr(el.dataset.i18n); });
  _updateDropText();
  renderTasks();
  renderCards();
  window.renderCertCard && renderCertCard();
  window.renderDevCheckCard && renderDevCheckCard();
  renderRecentAnonHistory();
  renderActivityTimeline();
  renderAchievements();
  renderHealthSummary();
  renderWorkspaceCard();
  document.getElementById('gl-title').textContent = tr('gl.title');
  document.getElementById('gl-intro').textContent = tr('gl.intro');
  document.getElementById('gl-search').placeholder = tr('gl.search');
  renderGlossary();
}

// 術語小辭典（第二十九輪 NU8）：顯示名稱 gl.<id>_n、說明 gl.<id>（i18n）；GLOSSARY 的英文名稱也納入搜尋
const GLOSSARY = [['vdom', 'VDOM / vsys'], ['zone', 'Zone'], ['shadow', 'Shadowed rule'], ['anyany', 'Any-any'], ['nat', 'NAT / VIP'], ['hitcount', 'Hit count'], ['health', 'Health score'], ['vlan', 'VLAN'], ['access', 'Access port'], ['trunk', 'Trunk port / Native VLAN'], ['hybrid', 'Hybrid port'], ['svi', 'SVI'], ['lacp', 'LACP'], ['vrrp', 'VRRP / HSRP'], ['stack', 'Stack (IRF / StackWise / VSF)'], ['mlag', 'MLAG / vPC / VLT'], ['stp', 'STP / BPDU Guard'], ['snoop', 'DHCP Snooping / DAI / IPSG'], ['dot1x', '802.1X / Port Security'], ['acl', 'ACL'], ['ospf', 'OSPF / BGP'], ['lldp', 'LLDP'], ['syslog', 'Syslog / CEF'], ['beaconing', 'Beaconing'], ['ioc', 'IOC / Threat intel'], ['mitre', 'MITRE ATT&CK'], ['kerberoast', 'Kerberoasting / AS-REP Roasting'], ['sigma', 'Sigma'], ['deid', 'De-identification / mapping table'], ['golden', 'Golden baseline']];
function _glEsc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function renderGlossary() {
  const box = document.getElementById('gl-list');
  if (!box) return;
  const q = (document.getElementById('gl-search').value || '').trim().toLowerCase();
  // 搜尋同時比對英文名稱、目前語言的名稱與說明
  const items = GLOSSARY.filter(([id, name]) => !q || (name + ' ' + tr('gl.' + id + '_n') + ' ' + tr('gl.' + id)).toLowerCase().includes(q));
  box.innerHTML = items.length
    ? items.map(([id, name]) => `<details class="gl-item" id="gl-${id}"${q ? ' open' : ''}><summary>${_glEsc(tr('gl.' + id + '_n'))}</summary><div>${_glEsc(tr('gl.' + id))}</div></details>`).join('')
    : `<div class="recent-anon-empty">${_glEsc(tr('gl.empty'))}</div>`;
}
// 由網址 #glossary 或 #gl-<id> 開啟（其他工具導覽面板的連結）
function openGlossary() {
  const card = document.getElementById('glossary');
  if (!card) return;
  if (typeof showHubView === 'function') showHubView('glossary', { keepHash: true });
  const m = /^#gl-([a-z0-9]+)$/.exec(location.hash);
  const search = document.getElementById('gl-search');
  // 指定的術語被目前搜尋條件過濾掉時，先清除搜尋
  if (m && !document.getElementById('gl-' + m[1]) && search.value) { search.value = ''; renderGlossary(); }
  const el = m && document.getElementById('gl-' + m[1]);
  if (el) el.open = true;
  setTimeout(() => (el || card).scrollIntoView({ block: 'start' }), 0);
}
window.addEventListener('hashchange', () => { if (/^#gl/.test(location.hash)) openGlossary(); });
// ── renderCards ───────────────────────────────────────────────────
const _missing = new Set();
const TIP_KEY = { fw:'fw_analyzer', sw:'sw_analyzer', ca:'cfg_anon', gen:'gen', log:'log_analyzer' };

// 任務入口（XN52）：每張任務卡＝說明＋開啟工具連結＋怎麼取得檔案（file-howto.js）；連結皆為固定頁面，不帶使用者資料
const TASKS = [
  { id: 'check', links: [['firewall-analyzer-fixed.html', 'nav.tool_fw'], ['switch-config-parser.html', 'nav.tool_switch']], howto: ['fw', 'sw'] },
  { id: 'log', links: [['log-analyzer.html', 'nav.tool_log']], howto: ['log'] },
  { id: 'conv', links: [['firewall-analyzer-fixed.html', 'task.conv_fw'], ['switch-config-generator.html', 'task.conv_sw']], howto: ['fw', 'sw'] },
  { id: 'anon', links: [['config-anonymizer.html', 'nav.tool_ca']], howto: ['fw', 'sw', 'log'] },
  // 懷疑被入侵（XN95）：依序列出步驟，只連到固定頁面、不帶資料
  { id: 'breach', links: [['log-analyzer.html', 'nav.tool_log'], ['config-anonymizer.html', 'nav.tool_ca']], howto: ['log'], steps: 4 },
  // 檢查網站憑證（XN101）：連到本頁的憑證檢查卡片，取得檔案由卡片內的腳本教學說明
  { id: 'cert', links: [['#certcheck', 'task.cert_go']], howto: [], steps: 3 },
  // 設備版本快速比對（XN107）：連到本頁卡片
  { id: 'devcheck', links: [['#devcheck', 'task.devcheck_go']], howto: [] },
  // 畫實體接線圖（XN199）：範例連到交換器分析的接線拓樸範例（?demo=cabling，固定合成資料）；另連到拓樸設計頁（XN202，手繪接線）
  { id: 'cabling', links: [['switch-config-parser.html?demo=cabling', 'task.cabling_demo'], ['switch-config-parser.html', 'nav.tool_switch'], ['firewall-analyzer-fixed.html', 'nav.tool_fw'], ['topology-designer.html', 'task.cabling_design']], howto: ['sw'], steps: 4 },
];
function renderTasks() {
  const grid = document.getElementById('tasks-grid');
  if (!grid) return;
  document.getElementById('tasks-title').textContent = tr('task.title');
  const open = new Set([...grid.querySelectorAll('details[open]')].map(d => d.dataset.task));
  grid.innerHTML = TASKS.map(t => `<div class="task-card" data-task="${t.id}"><h3>${_glEsc(tr('task.' + t.id + '_t'))}</h3><p>${_glEsc(tr('task.' + t.id + '_d'))}</p>`
    + (t.steps ? `<ol class="task-steps">${Array.from({ length: t.steps }, (_, i) => `<li>${_glEsc(tr('task.' + t.id + '_s' + (i + 1)))}</li>`).join('')}</ol>` : '')
    + `<div class="task-links">${t.links.map(([href, key]) => `<a href="${href}">${_glEsc(tr(key))}</a>`).join('')}</div>`
    + (window.FileHowto && t.howto.length ? `<details data-task="${t.id}"${open.has(t.id) ? ' open' : ''}><summary>${_glEsc(FileHowto.title(_lang))}</summary>${FileHowto.listHtml(t.howto, _lang)}</details>` : '')
    + `</div>`).join('');
  // 拖放提示對所有任務卡都相同，只在卡片下方說一次（UX13）
  const drop = document.getElementById('tasks-drop');
  if (drop) drop.textContent = tr('task.drop');
}
// 首頁卡片（UX39）：首頁只當導引頁，依用途分組列出工具卡、附加工具卡與首頁內功能畫面卡（hub-views.js 切換）。
// TOOLS 的順序被拖放交接以索引使用（hub-dispatch.js），分組只影響顯示，不可改動 TOOLS 順序。
// EXTRA_TOOLS：不在 TOOLS（沒有支援廠牌清單）的其他頁面或功能；文字 key hx.<id>_t／hx.<id>_d
const EXTRA_TOOLS = [
  // 多台接線拓樸：交換器分析資產清冊裡的功能（?view=inventory 直接開到資產清冊）
  { id: 'cabling', icon: '🧵', color: '#a855f7', href: 'switch-config-parser.html?view=inventory', demo: 'switch-config-parser.html?demo=cabling', experimental: true },
  { id: 'designer', icon: '✏️', color: '#22c55e', href: 'topology-designer.html', experimental: true },
  { id: 'intel', icon: '🛰️', color: '#f97316', href: 'threat-intel-builder.html' },
];
// 分組：tools＝TOOLS 的 id、extra＝EXTRA_TOOLS 的 id、views＝HUB_VIEWS 的 id（hub-views.js）；組名 key hg.<id>
const HUB_GROUPS = [
  { id: 'analyze', tools: ['fw', 'sw', 'log'], extra: ['cabling'] },
  { id: 'build', tools: ['gen'], extra: ['designer'] },
  { id: 'data', tools: ['ca'], extra: ['intel'] },
  { id: 'check', views: ['certcheck', 'devcheck'] },
  { id: 'mine', views: ['health', 'history', 'workspace'] },
  { id: 'help', views: ['tasks', 'glossary'] },
];
// 首頁內功能畫面的卡片圖示（畫面本身在 network-analyzer.html 的 .hub-view；文字 key hv.<id>_t／hv.<id>_d）
const HUB_VIEW_ICONS = { tasks: '🧭', certcheck: '🔐', devcheck: '🩺', health: '📋', history: '🕘', workspace: '💼', glossary: '📖' };
const _expBadge = () => `<span class="card-badge card-badge-experimental">${tr('suite.experimental')}</span>`;
function _toolCardHtml(t) {
  const miss = _missing.has(t.id);
  return `
    <div class="card hub-card${miss ? ' card-missing' : ''}" data-tool="${t.id}" style="--card-color:${t.color}"${miss ? '' : ` onclick="openTool('${t.href}')"`}>
      <div class="hub-card-head"><span class="card-icon">${t.icon}</span>
        <div class="card-title">${tip('tip.' + (TIP_KEY[t.id] || 'cfg_anon'), tr(t.id + '.title'), t.vendors.length)}${t.experimental ? _expBadge() : ''}</div></div>
      <p class="card-desc">${tr(t.id + '.desc').replace('{n}', t.vendors.length)}</p>
      <details class="card-vendors" onclick="event.stopPropagation()"><summary>${tr('hub.vendor_list').replace('{n}', t.vendors.length)}</summary>
        <div class="card-tags">
        ${t.vendors.map(v => {
          const label = v.startsWith('$') ? tr(v.slice(1)) : v;
          const slug = VENDOR_PERSONA_KEY[v];
          const persona = slug ? tr('egg.vendor_' + slug) : '';
          return persona ? `<span class="tag" data-tip="${persona.replace(/"/g,'&quot;')}">${label}</span>` : `<span class="tag">${label}</span>`;
        }).join('')}
        </div></details>
      ${miss
        ? `<div class="card-warn">⚠ ${tr('warn.missing')}</div>`
        : `<div class="card-actions"><button class="card-open">${tr('suite.open')}</button><button class="card-demo" onclick="event.stopPropagation();openTool('${t.href}?demo=1')">${tr('hub.demo')}</button></div>`}
    </div>`;
}
function _extraCardHtml(x) {
  return `
    <div class="card hub-card" data-tool="${x.id}" style="--card-color:${x.color}" onclick="openTool('${x.href}')">
      <div class="hub-card-head"><span class="card-icon">${x.icon}</span><div class="card-title">${_glEsc(tr('hx.' + x.id + '_t'))}${x.experimental ? _expBadge() : ''}</div></div>
      <p class="card-desc">${_glEsc(tr('hx.' + x.id + '_d'))}</p>
      <div class="card-actions"><button class="card-open">${tr('suite.open')}</button>${x.demo ? `<button class="card-demo" onclick="event.stopPropagation();openTool('${x.demo}')">${tr('hub.demo')}</button>` : ''}</div>
    </div>`;
}
function _viewCardHtml(id) {
  return `
    <a class="card hub-card hub-view-card" data-view-card="${id}" href="#${id}" style="--card-color:#64748b">
      <div class="hub-card-head"><span class="card-icon">${HUB_VIEW_ICONS[id] || '•'}</span><div class="card-title">${_glEsc(tr('hv.' + id + '_t'))}</div></div>
      <p class="card-desc">${_glEsc(tr('hv.' + id + '_d'))}</p>
    </a>`;
}
function renderCards() {
  const wrap = document.getElementById('cards');
  const toolById = id => TOOLS.find(t => t.id === id), extraById = id => EXTRA_TOOLS.find(x => x.id === id);
  wrap.innerHTML = HUB_GROUPS.map(g => `<section class="hub-group" data-group="${g.id}"><h2 class="hub-group-title">${_glEsc(tr('hg.' + g.id))}</h2><div class="hub-grid">`
    + (g.tools || []).map(id => _toolCardHtml(toolById(id))).join('')
    + (g.extra || []).map(id => _extraCardHtml(extraById(id))).join('')
    + (g.views || []).map(_viewCardHtml).join('')
    + '</div></section>').join('');

  const back = document.getElementById('hub-back');
  if (back) back.textContent = '← ' + tr('hv.back');
}

function openTool(href) { window.open(href, '_blank'); }

async function checkFiles() {
  if (location.protocol === 'file:') {
    document.getElementById('h-notice').style.display = 'none';
    renderCards();
    return;
  }
  // 只有伺服器明確回 404（重試一次仍是）才算缺檔；網路中斷、部署更新中、伺服器不支援 HEAD 等暫時狀況不當成缺檔，
  // 避免 GitHub Pages 剛部署或連線不穩時整排卡片誤顯示「找不到工具檔案」
  const status = async href => { try { return (await fetch(href, { method: 'HEAD', cache: 'no-store' })).status; } catch { return 0; } };
  await Promise.all(TOOLS.map(async t => {
    if (await status(t.href) !== 404) return;
    await new Promise(r => setTimeout(r, 1500));
    if (await status(t.href) === 404) _missing.add(t.id);
  }));
  renderCards();
  document.getElementById('h-notice').style.display = _missing.size === 0 ? 'none' : '';
}

// ── showEggToast（共用）────────────────────────────────────────────
function showEggToast(msg) {
  // 彩蛋改由右下角羊駝呈現（XN49，alpaca-buddy.js）：主動彩蛋出泡泡、被動彩蛋收進口袋
  if (window.AlpacaBuddy) return window.AlpacaBuddy.say(msg, undefined);
  const t = document.createElement('div');
  t.className = 'qapla-toast';
  t.textContent = msg;
  document.body.appendChild(t);
  t.addEventListener('animationend', e => { if(e.animationName==='qapla-out') t.remove(); });
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

