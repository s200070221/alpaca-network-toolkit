// network-analyzer.html 拆出的模組（XN101）：初始化、Rage quit 彩蛋、跨工具導覽與主題；必須最後載入。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// ── Init ──────────────────────────────────────────────────────────
setLang(loadLangPref());
checkAchievements();
autoLabelControls();
// ── 彩蛋：Rage quit（連按 Esc 三次）────────────────────────
(function(){
  var _rq=0,_rqT;
  document.addEventListener('keydown',function(e){
    if(e.key!=='Escape')return;
    clearTimeout(_rqT);
    _rq++;
    _rqT=setTimeout(function(){_rq=0;},1500);
    if(_rq>=3){_rq=0;showEggToast(tr('egg.rage_quit'));}
  });
})();
document.getElementById('alpaca-btn').title = tr('egg.alpaca');
checkFiles();
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
  document.addEventListener('mouseout', function(e) { if (e.target.closest('[data-tip]')) _t.style.display = 'none'; });
  document.addEventListener('scroll', function() { _t.style.display = 'none'; }, true);
})();

// 黑/白模式切換
// ── 跨工具導覽（2026-08-24 新增）：見 switch_analyzer 同名函式註解
function toggleToolsNav(e){
  if(e)e.stopPropagation();
  const p=document.getElementById('tools-nav-panel');
  if(!p)return;
  p.style.display=(p.style.display==='none'||!p.style.display)?'block':'none';
}
document.addEventListener('click',function(e){
  const p=document.getElementById('tools-nav-panel');
  if(p&&p.style.display==='block'&&!p.contains(e.target)&&e.target.id!=='tools-nav-btn'){
    p.style.display='none';
  }
});

function setTheme(t){document.documentElement.setAttribute('data-theme',t);document.body.dataset.theme=t;const b=document.getElementById('theme-btn');if(b)b.textContent=t==='light'?'🌙':'☀️';try{localStorage.setItem('cw_theme',t);}catch(e){}}
function toggleTheme(){setTheme(document.body.dataset.theme==='light'?'dark':'light');}
(function(){let s=null;try{s=localStorage.getItem('cw_theme');}catch(e){}const p=s||(window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');if(p==='light')setTheme('light');})();

