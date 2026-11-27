// network-analyzer.html 拆出的模組（XN101）：彩蛋 A～D（羊駝三連擊、lang-egg、Konami、Logo 連按）。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// ── Easter egg C：Alpaca 三連擊 → 克林貢 ─────────────────────────
let _alpacaN = 0, _alpacaTimer;
document.getElementById('alpaca-btn').addEventListener('click', () => {
  clearTimeout(_alpacaTimer);
  _alpacaN++;
  _alpacaTimer = setTimeout(() => { _alpacaN = 0; }, 1500);
  if (_alpacaN >= 3) {
    _alpacaN = 0;
    document.getElementById('lang-klingon').style.display = '';
    setLang('tlh');
    showEggToast("🖖 Qapla'! tlhIngan Hol DaghojneS!");
  }
});

// ── Easter egg D：lang-egg 代表物三連擊 ──────────────────────────
const _EGG = {
  'egg-pirate': {lang:'pirate', btn:'lang-pirate', toast:"☠️ Ahoy! Ye be speakin' pirate now, matey! Arr!"},
  'egg-leet':   {lang:'leet',   btn:'lang-leet',   toast:'1337 5P34K 4C71V473D. H4X0R M0D3 0N.'},
  'egg-emoji':  {lang:'emoji',  btn:'lang-emoji',  toast:'🌈✨🎉 3moji mod3 4ctiv4t3d! 🦄💫🌟'},
  'egg-uwu':    {lang:'uwu',   btn:'lang-uwu',   toast:'🐾 Hewwo fwend~ UwU wanguage activeated! OwO'},
  'egg-bureau': {lang:'bureau',btn:'lang-bureau',toast:'📋 啟動跨部門作業流程。本系統正式進入公文模式。請依規定格式呈現。'},
  'egg-cat':    {lang:'cat',   btn:'lang-cat',   toast:'🐱 Nyaa~！喵語模式啟動了喵！meow meow owo'},
  'egg-bean':   {lang:'bean',  btn:'lang-bean',  toast:'🥕🫛🌽 豆語模式啟動！蔬菜智慧已降臨！🌽🫛🥕'},
    'egg-alpaca':{lang:'alpaca',btn:'lang-alpaca',toast:'🦙 咩咩咩！羊咩碼啟動-aca！網路咩析-aca！🦙'},'egg-yanse':{lang:'yanse',btn:'lang-yanse',toast:'💀 overtime detected...厭世工程師模式啟動，反正早晚都要加班'},
    'egg-wuxia': {lang:'wuxia', btn:'lang-wuxia', toast:'⚔️ 武林秘笈已然出鞘！江湖兒女，且看今朝！'},
};
const _eggN={}, _eggT={};
document.querySelectorAll('.lang-egg').forEach(el => {
  _eggN[el.id]=0;
  el.addEventListener('click', () => {
    clearTimeout(_eggT[el.id]);
    _eggN[el.id]++;
    _eggT[el.id]=setTimeout(()=>{ _eggN[el.id]=0; }, 1500);
    if(_eggN[el.id]>=3){
      _eggN[el.id]=0;
      const c=_EGG[el.id];
      document.getElementById(c.btn).style.display='';
      setLang(c.lang);
      showEggToast(c.toast);
    }
  });
});

// ── Easter egg A：Konami Code ─────────────────────────────────────
const _KONAMI = ['ArrowUp','ArrowUp','ArrowDown','ArrowDown',
                 'ArrowLeft','ArrowRight','ArrowLeft','ArrowRight','b','a'];
let _kIdx = 0;
document.addEventListener('keydown', e => {
  _kIdx = (e.key === _KONAMI[_kIdx]) ? _kIdx + 1 : (e.key === _KONAMI[0] ? 1 : 0);
  if (_kIdx === _KONAMI.length) {
    _kIdx = 0;
    // 卡片彈跳
    document.querySelectorAll('.card').forEach(c => {
      c.classList.remove('card-bounce');
      void c.offsetWidth;
      c.classList.add('card-bounce');
      c.addEventListener('animationend', () => c.classList.remove('card-bounce'), {once:true});
    });
    // 羊駝遊行
    const parade = document.createElement('div');
    parade.className = 'alpaca-parade';
    parade.textContent = '🦙'.repeat(10);
    document.body.appendChild(parade);
    parade.addEventListener('animationend', () => parade.remove());
  }
});

// ── Easter egg B：Logo 連按 5 下 ──────────────────────────────────
let _logoN = 0, _logoTimer;
document.getElementById('logo-btn').addEventListener('click', () => {
  clearTimeout(_logoTimer);
  _logoN++;
  _logoTimer = setTimeout(() => { _logoN = 0; }, 2000);
  if (_logoN >= 5) {
    _logoN = 0;
    const overlay = document.createElement('div');
    overlay.className = 'egg-overlay';
    const toast = document.createElement('div');
    toast.className = 'egg-toast';
    toast.innerHTML = `
      <div class="egg-toast-icon">🦙</div>
      <div class="egg-toast-title">${tr('egg.stats_title')}</div>
      ${TOOLS.map(t => `
        <div class="egg-stat-row">
          <span>${t.icon} ${tr(t.id + '.title')}</span>
          <span class="egg-stat-val">${t.vendors.length} ${tr('egg.vendors')}</span>
        </div>`).join('')}
      <div class="egg-toast-hint">${tr('egg.stats_hint')}</div>`;
    overlay.addEventListener('click', () => { overlay.remove(); toast.remove(); });
    document.body.appendChild(overlay);
    document.body.appendChild(toast);
  }
});

