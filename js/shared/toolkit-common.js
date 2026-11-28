// toolkit-common.js — 6 個工具與拓樸設計頁共用的語言與介面函式（RV16 第 3 階段）
// 原本各工具各有一份相同的 tr()／autoLabelControls()／loadLangPref() 等，改為只留這一份。
// 例外：本檔不包 IIFE，直接以頂層 function 宣告（測試以 new Function() 串接模組時可直接以名稱呼叫）；
// 只宣告下列名稱，各工具不可再宣告同名的 const／let／function（test_global_names 檢查）。
// 載入順序：各頁緊接在 toolkit-version.js 之後。

// 彩蛋語言缺 key 時先退回的語言：外語風格退回 en，中文風格退回 zhTW（之後再退 en→zhTW→key）
var TK_LANG_FALLBACK = { ja: 'en', tlh: 'en', pirate: 'en', emoji: 'en', bureau: 'zhTW', alpaca: 'zhTW', yanse: 'zhTW', wuxia: 'zhTW' };

function tkLeet(s) { return s.replace(/a/gi, '4').replace(/e/gi, '3').replace(/i/gi, '1').replace(/o/gi, '0').replace(/s/gi, '5').replace(/t/gi, '7').replace(/l/gi, '|'); }
function tkUwu(s) { return s.replace(/r/g, 'w').replace(/R/g, 'W').replace(/l/g, 'w').replace(/L/g, 'W').replace(/th/g, 'd').replace(/Th/g, 'D').replace(/n([aeiou])/g, 'ny$1').replace(/N([AEIOU])/g, 'Ny$1'); }

// L：該工具的語言物件（{zhTW:{…}, en:{…}, …}）；lang：目前語言代碼；key：字串 key
function tkTr(L, lang, key) {
  var zh = L.zhTW || {}, en = L.en || {};
  // leet／uwu 沒有儲存區塊，套用英文（缺則中文）即時轉換
  if (lang === 'leet') return tkLeet(en[key] || zh[key] || key);
  if (lang === 'uwu') return tkUwu(en[key] || zh[key] || key);
  // cat／bean 先查自己的區塊，缺才用演算法
  if (lang === 'cat') { var c = L.cat && L.cat[key]; if (c) return c; var cb = zh[key] || en[key] || key; return cb + (/[一-鿿]$/.test(cb) ? '喵~' : ' nyaa~'); }
  if (lang === 'bean') { var b = L.bean && L.bean[key]; if (b) return b; var bb = en[key] || zh[key] || key; var vg = ['🥕', '🫛', '🌽']; return bb.split('').map(function (ch) { return ch === ' ' ? ' ' : vg[ch.charCodeAt(0) % 3]; }).join(''); }
  var v = L[lang] && L[lang][key];
  if (v) return v;
  var fb = TK_LANG_FALLBACK[lang];
  if (fb && L[fb] && L[fb][key]) return L[fb][key];
  return (lang === 'en' ? zh[key] : en[key]) || zh[key] || en[key] || key;
}

// 沒有標籤的輸入欄位，以前一個 label／span 當無障礙名稱
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

// 語言偏好（cw_lang，只記 zhTW／en／ja；彩蛋語言不記）
function loadLangPref() {
  try { const v = localStorage.getItem('cw_lang'); if (v === 'zhTW' || v === 'en' || v === 'ja') return v; } catch (e) {}
  const n = ((typeof navigator !== 'undefined' && navigator.language) || '').toLowerCase();
  return n.indexOf('ja') === 0 ? 'ja' : (n.indexOf('zh') === 0 || !n ? 'zhTW' : 'en');
}
function saveLangPref(code) {
  if (code === 'zhTW' || code === 'en' || code === 'ja') { try { localStorage.setItem('cw_lang', code); } catch (e) {} }
}
// <html lang> 屬性
function htmlLangFor(code) {
  if (code === 'ja') return 'ja';
  return ['zhTW', 'bureau', 'cat', 'bean', 'alpaca', 'yanse', 'wuxia'].indexOf(code) >= 0 ? 'zh-TW' : 'en';
}

// 頂端「其他工具」選單
function toggleToolsNav(e) {
  if (e) e.stopPropagation();
  const p = document.getElementById('tools-nav-panel');
  if (!p) return;
  p.style.display = (p.style.display === 'none' || !p.style.display) ? 'block' : 'none';
}

// ── 以下為防火牆／交換器分析／產生器／log／去識別化／入口頁共用的小型介面函式（RV17-C）──
function toggleTheme(){setTheme(document.body.dataset.theme==='light'?'dark':'light');}
// 第一次使用導覽已看過的工具（_netAnalyzer_tourSeen）
function _tourSeen(){try{return JSON.parse(localStorage.getItem('_netAnalyzer_tourSeen')||'{}')||{};}catch(e){return {};}}
// Markdown 表格儲存格：跳脫反斜線與 |、換行改空白
function _mdCell(v){return String(v==null?'':v).replace(/\\/g,'\\\\').replace(/\|/g,'\\|').replace(/\r?\n/g,' ');}
function dlTxt(t,fn){const b=new Blob([t],{type:'text/plain;charset=utf-8;'});const url=URL.createObjectURL(b);const a=document.createElement('a');a.href=url;a.download=fn;a.click();URL.revokeObjectURL(url);}
function buildHealthSparklineSVG(entries){
  const w=280,h=60,pad=6;
  const list=(entries||[]).slice().reverse();
  if(!list.length) return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"></svg>`;
  const yOf=score=>pad+(100-score)/100*(h-2*pad);
  const titleOf=e=>`${e.score} (${new Date(e.ts).toLocaleDateString()})`;
  if(list.length===1){
    const y=yOf(list[0].score);
    return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"><circle cx="${w/2}" cy="${y.toFixed(1)}" r="3" fill="var(--accent)"><title>${titleOf(list[0])}</title></circle></svg>`;
  }
  const stepX=(w-2*pad)/(list.length-1);
  const pts=list.map((e,i)=>({x:pad+i*stepX,y:yOf(e.score),e}));
  const path=pts.map((p,i)=>`${i===0?'M':'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const dots=pts.map(p=>`<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.5" fill="var(--accent)"><title>${titleOf(p.e)}</title></circle>`).join('');
  return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"><path d="${path}" fill="none" stroke="var(--accent)" stroke-width="1.5"/>${dots}</svg>`;
}

// 名詞小辭典（第七輪 NC）：表頭（th）文字含常見網路名詞時，自動加上滑鼠提示（[data-tip]）與 ⓘ 標記。
// 以 MutationObserver 監看畫面變動後統一處理；已有 data-tip 的表頭不覆蓋；切換語言時依 data-gl-term 以新語言更新。
// 翻譯用該頁的 tr('gl.<id>')；after：每次處理完後再執行（產生器用來補表格輸入欄的 aria-label）
function tkGlossary(after){
  var TERMS=[["native", "Native VLAN"], ["vlan", "VLAN"], ["trunk", "Trunk"], ["svi", "SVI"], ["lacp", "LACP"], ["vrrp", "VRRP"], ["hsrp", "HSRP"], ["stp", "STP"], ["bpdu", "BPDU"], ["portfast", "PortFast"], ["dot1x", "802.1X"], ["acl", "ACL"], ["qos", "QoS"], ["ospf", "OSPF"], ["bgp", "BGP"], ["snmp", "SNMP"], ["nat", "NAT"], ["vdom", "VDOM"], ["vpn", "VPN"], ["dhcp", "DHCP"], ["lldp", "LLDP"], ["mtu", "MTU"], ["poe", "PoE"], ["vrf", "VRF"]];
  var RE=TERMS.map(function(t){return [t[0],t[1],new RegExp('(^|[^A-Za-z0-9])'+t[1].replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'($|[^A-Za-z0-9])','i')];});
  function tipOf(k,term){var s=tr('gl.'+k);return (!s||s==='gl.'+k)?'':term+': '+s;}
  function mark(th){
    if(!th.querySelector('sup.gl-mark')){var sup=document.createElement('sup');sup.className='gl-mark';sup.textContent='ⓘ';sup.style.cssText='font-size:8px;opacity:.45;margin-left:2px;cursor:help';th.appendChild(sup);}
  }
  function applyGlossary(){
    var ths=document.querySelectorAll('th');
    for(var i=0;i<ths.length;i++){
      var th=ths[i], k=th.getAttribute('data-gl-term');
      if(k){var t=tipOf(k,th.getAttribute('data-gl-label'));if(t&&th.getAttribute('data-tip')!==t)th.setAttribute('data-tip',t);if(t)mark(th);continue;}
      if(th.hasAttribute('data-gl-skip'))continue;
      if(th.hasAttribute('data-tip')||th.querySelector('[data-tip]')){th.setAttribute('data-gl-skip','1');continue;}
      var text=th.textContent||'', hit=null;
      for(var j=0;j<RE.length;j++){if(RE[j][2].test(text)){hit=RE[j];break;}}
      if(!hit){th.setAttribute('data-gl-skip','1');continue;}
      var tip=tipOf(hit[0],hit[1]);
      if(!tip)continue;
      th.setAttribute('data-gl-term',hit[0]);th.setAttribute('data-gl-label',hit[1]);th.setAttribute('data-tip',tip);mark(th);
    }
  }
  window.applyGlossary=applyGlossary;
  var timer=null;
  function schedule(){clearTimeout(timer);timer=setTimeout(function(){applyGlossary();if(after)after();},150);}
  if(document.body)new MutationObserver(schedule).observe(document.body,{childList:true,subtree:true,characterData:true});
  schedule();
}

// 頂端選單（UX19）：展開時依按鈕位置定位面板（fixed，避免手機寬度橫向捲動的工具列裁切），
// 同時只開一個；點選項目、點選單外或按 Esc 即收起
function tkTbMenu(){
  function place(d) {
    var r = d.querySelector('summary').getBoundingClientRect(), p = d.querySelector('.tb-menu-panel');
    p.style.top = Math.round(r.bottom + 4) + 'px';
    p.style.left = Math.round(Math.max(8, Math.min(r.left, window.innerWidth - p.offsetWidth - 8))) + 'px';
  }
  function closeAll(except) { document.querySelectorAll('details.tb-menu[open]').forEach(function (d) { if (d !== except) d.open = false; }); }
  document.addEventListener('toggle', function (e) {
    var d = e.target;
    if (!d.classList || !d.classList.contains('tb-menu') || !d.open) return;
    closeAll(d); place(d);
  }, true);
  document.addEventListener('click', function (e) {
    var m = e.target.closest && e.target.closest('details.tb-menu');
    if (!m) { closeAll(null); return; }
    if (e.target.closest('.tb-menu-panel button')) m.open = false;
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeAll(null); });
  window.addEventListener('resize', function () { closeAll(null); });
}
