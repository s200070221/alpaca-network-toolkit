// ════════════════════════════════════════════════════════════════════════
// firewall-analyzer-eggs.js — 頁面初始化與彩蛋（2026-08-17 從 firewall-analyzer-app.js
// 拆出）。這段內容在原始檔案中本來就已經在 App 的 `(() => {...})()` IIFE 結束之後（第一輪
// 18 檔模組拆分時漏掃了 IIFE 結束後的尾段，物理位置放錯純屬歷史遺留），純屬頂層、無巢狀，
// 只透過 App 已用 `window.` 暴露的函式（`_loadFromPending`/`showEggToast`）互動，故搬移
// 零 closure 風險。涵蓋：pending-load 自動載入、全域 tooltip、羊駝/lang-egg 彩蛋、
// Console banner、明暗主題切換。
// ════════════════════════════════════════════════════════════════════════

(function(){
  var _p = localStorage.getItem('_netAnalyzer_pending');
  if (!_p) return;
  try {
    var d = JSON.parse(_p);
    if (Date.now() - d.ts > 10000) { localStorage.removeItem('_netAnalyzer_pending'); return; }
    localStorage.removeItem('_netAnalyzer_pending');
    if (window._loadFromPending) window._loadFromPending(d.text, d.vendor || 'f');
  } catch(e) {}
})();

// 初始化語言
setLang('zhTW');

// 名詞解釋 tooltip
(function(){
  var _t = document.createElement('div');
  _t.className = 'global-tip';
  document.body.appendChild(_t);
  document.addEventListener('mouseover', function(e) {
    var el = e.target.closest('[data-tip]');
    if (!el) return;
    _t.textContent = el.dataset.tip;
    _t.style.display = 'block';
    var r = el.getBoundingClientRect(), tw = _t.offsetWidth, th = _t.offsetHeight;
    var x = r.left + r.width / 2 - tw / 2;
    x = Math.max(8, Math.min(x, window.innerWidth - tw - 8));
    var y = r.top - th - 8;
    _t.style.left = x + 'px';
    _t.style.top = (y < 8 ? r.bottom + 8 : y) + 'px';
  });
  document.addEventListener('mouseout', function(e) {
    if (e.target.closest('[data-tip]')) _t.style.display = 'none';
  });
  document.addEventListener('scroll', function() { _t.style.display = 'none'; }, true);
})();

// 彩蛋：羊駝 3 連擊解鎖克林貢
(function(){
  var _kN=0,_kT;
  document.addEventListener('click',function(e){
    var ac=document.getElementById('alpaca-corner');
    if(!ac||(!ac.contains(e.target)&&ac!==e.target))return;
    clearTimeout(_kT);_kN++;
    _kT=setTimeout(function(){_kN=0;},1500);
    if(_kN>=3){
      _kN=0;
      document.getElementById('lang-klingon').style.display='';
      setLang('tlh');
      var t=document.createElement('div');t.className='qapla-toast';
      t.textContent="🖖 Qapla'! tlhIngan Hol DaghojneS!";
      document.body.appendChild(t);
      t.addEventListener('animationend',function(ev){if(ev.animationName==='qapla-out')t.remove();});
    }
  });
})();

// 彩蛋：lang-egg 代表物三連擊
(function(){
  var _EGG={
    'egg-pirate':{lang:'pirate',btn:'lang-pirate',toast:"☠️ Ahoy! Ye be speakin' pirate now, matey! Arr!"},
    'egg-leet':  {lang:'leet',  btn:'lang-leet',  toast:'1337 5P34K 4C71V473D. H4X0R M0D3 0N.'},
    'egg-emoji': {lang:'emoji', btn:'lang-emoji',  toast:'🌈✨🎉 3moji mod3 4ctiv4t3d! 🦄💫🌟'},
    'egg-uwu':   {lang:'uwu',   btn:'lang-uwu',   toast:'🐾 Hewwo fwend~ UwU wanguage activeated! OwO'},
    'egg-bureau':{lang:'bureau',btn:'lang-bureau',toast:'📋 啟動跨部門作業流程。本系統正式進入公文模式。請依規定格式呈現。'},
    'egg-cat':   {lang:'cat',   btn:'lang-cat',   toast:'🐱 Nyaa~！喵語模式啟動了喵！meow meow owo'},
    'egg-bean':  {lang:'bean',  btn:'lang-bean',  toast:'🥕🫛🌽 豆語模式啟動！蔬菜智慧已降臨！🌽🫛🥕'},
    'egg-alpaca':{lang:'alpaca',btn:'lang-alpaca',toast:'🦙 咩咩咩！羊咩碼啟動-aca！防咩火咩牆-aca！🦙'},'egg-yanse':{lang:'yanse',btn:'lang-yanse',toast:'💀 overtime detected...防火牆規則看不完，厭世模式啟動'},
    'egg-wuxia': {lang:'wuxia', btn:'lang-wuxia', toast:'⚔️ 武林秘笈已然出鞘！江湖兒女，且看今朝！'},
  };
  var _eN={},_eT={};
  document.querySelectorAll('.lang-egg').forEach(function(el){
    _eN[el.id]=0;
    el.addEventListener('click',function(){
      clearTimeout(_eT[el.id]);
      _eN[el.id]++;
      _eT[el.id]=setTimeout(function(){_eN[el.id]=0;},1500);
      if(_eN[el.id]>=3){
        _eN[el.id]=0;
        var c=_EGG[el.id];
        document.getElementById(c.btn).style.display='';
        setLang(c.lang);
        showEggToast(c.toast);
      }
    });
  });
})();

// Console 彩蛋
console.log('%c FW Analyzer v4.0  ·  羊駝驅動的防火牆解析工具 🦙','color:#00c8f0;font-family:monospace;font-size:13px;font-weight:bold');
console.log('%c 彩蛋提示 → 盾牌 ×5 | Konami Code ↑↑↓↓←→←→BA | tb-meta ×7 | 點羊駝','color:#64748b;font-family:monospace;font-size:10px');

// 黑/白模式切換
function setTheme(t){document.body.dataset.theme=t;const b=document.getElementById('theme-btn');if(b)b.textContent=t==='light'?'🌙':'☀️';localStorage.setItem('cw_theme',t);}
function toggleTheme(){setTheme(document.body.dataset.theme==='light'?'dark':'light');}
(function(){const s=localStorage.getItem('cw_theme');const p=s||(window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');if(p==='light')setTheme('light');})();
