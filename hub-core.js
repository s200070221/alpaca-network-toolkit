// network-analyzer.html 拆出的模組（XN101）：tr／setLang、工具卡片 TOOLS、任務卡 TASKS、術語辭典、showEggToast。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// ── tr / setLang ───────────────────────────────────────────────────
let _lang = 'zhTW';
function tr(k){
  if(_lang==='leet'){const s=LANG.en[k]||LANG.zhTW[k]||k;return s.replace(/a/gi,'4').replace(/e/gi,'3').replace(/i/gi,'1').replace(/o/gi,'0').replace(/s/gi,'5').replace(/t/gi,'7').replace(/l/gi,'|');}
  if(_lang==='uwu'){const s=LANG.en[k]||LANG.zhTW[k]||k;return s.replace(/r/g,'w').replace(/R/g,'W').replace(/l/g,'w').replace(/L/g,'W').replace(/th/g,'d').replace(/Th/g,'D').replace(/n([aeiou])/g,'ny$1').replace(/N([AEIOU])/g,'Ny$1');}
  if(_lang==='cat'){const d=LANG.cat&&LANG.cat[k];if(d)return d;const base=LANG.zhTW[k]||LANG.en[k]||k;return base+(/[一-鿿]$/.test(base)?'喵~':' nyaa~');}
  if(_lang==='bean'){const d=LANG.bean&&LANG.bean[k];if(d)return d;const base=LANG.en[k]||LANG.zhTW[k]||k;const vg=['🥕','🫛','🌽'];return base.split('').map(c=>c===' '?' ':vg[c.charCodeAt(0)%3]).join('');}
  return (LANG[_lang]||LANG.zhTW)[k]||LANG.en[k]||k;
}

function tip(key, label, n) {
  // n：說明文字中的 {n}（支援廠牌數，XN52 由 TOOLS 清單長度算出，不寫死在文字裡）
  const t = n == null ? tr(key) : tr(key).replace('{n}', n);
  if (!t || t === key) return label;
  return `<span data-tip="${t.replace(/"/g,'&quot;')}">${label}<sup style="font-size:8px;opacity:.45;margin-left:2px;cursor:help">ⓘ</sup></span>`;
}
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
function renderCards() {
  const wrap = document.getElementById('cards');
  wrap.innerHTML = TOOLS.map(t => {
    const miss = _missing.has(t.id);
    return `
    <div class="card${miss ? ' card-missing' : ''}" style="--card-color:${t.color}"${miss ? '' : ` onclick="openTool('${t.href}')"`}>
      <div class="card-icon">${t.icon}</div>
      <div>
        <div class="card-title">
          ${tip('tip.' + (TIP_KEY[t.id] || 'cfg_anon'), tr(t.id + '.title'), t.vendors.length)}
          <span class="card-badge">${tr(t.id + '.badge')}</span>
          ${t.experimental ? `<span class="card-badge card-badge-experimental">${tr('suite.experimental')}</span>` : ''}
        </div>
      </div>
      <p class="card-desc">${tr(t.id + '.desc').replace('{n}', t.vendors.length)}</p>
      <div class="card-tags">
        ${t.vendors.map(v => {
          const label = v.startsWith('$') ? tr(v.slice(1)) : v;
          const slug = VENDOR_PERSONA_KEY[v];
          const persona = slug ? tr('egg.vendor_' + slug) : '';
          return persona ? `<span class="tag" data-tip="${persona.replace(/"/g,'&quot;')}">${label}</span>` : `<span class="tag">${label}</span>`;
        }).join('')}
        ${t.vendors.length > 10 ? `<button class="tag-more" onclick="event.stopPropagation();_toggleTags(this)">${tr('hub.tags_more').replace('{n}', t.vendors.length)}</button>` : ''}
      </div>
      <div class="card-features">
        ${t.features.map(f => `<span class="feat">${tr(f)}</span>`).join('')}
      </div>
      ${miss
        ? `<div class="card-warn">⚠ ${tr('warn.missing')}</div>`
        : `<div class="card-actions"><button class="card-open">${tr('suite.open')}</button><button class="card-demo" onclick="event.stopPropagation();openTool('${t.href}?demo=1')">${tr('hub.demo')}</button></div>`}
    </div>`;
  }).join('');
}

function openTool(href) { window.open(href, '_blank'); }
function _toggleTags(btn) {
  const box = btn.parentElement, open = box.classList.toggle('open');
  btn.textContent = open ? tr('hub.tags_less') : tr('hub.tags_more').replace('{n}', box.querySelectorAll('.tag').length);
}

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

