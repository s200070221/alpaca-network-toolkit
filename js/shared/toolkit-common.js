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
