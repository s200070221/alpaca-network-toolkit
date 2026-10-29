// ── 羊駝夥伴（2026-10-29，第三十九輪 XN49）──────────────────────────────────────────
// 彩蛋一律由右下角羊駝呈現，不再從頂端彈出 toast（原本會蓋住結果列）：
// - 主動彩蛋（使用者剛按過鍵盤、或剛點過彩蛋元素：羊駝、口袋按鈕、.lang-egg）→ 羊駝旁的泡泡
// - 被動彩蛋（分析結果、時段、計時、愚人節、可疑注入字串…）→ 收進「羊駝口袋」，口袋按鈕顯示未讀數；
//   使用者可開「被動彩蛋直接說出來」（localStorage _netAnalyzer_eggLoud，入口頁 WS_KEYS）
// - 值勤模式 setDuty({n, top, go})：有嚴重發現時羊駝戴 ⛑️、泡泡只說「先看哪一項」，被動彩蛋一律進口袋
// - 頁面頂端的 .lang-egg（彩蛋語言解鎖圖示）整個搬進口袋面板的「換裝」區（搬移不是複製，原本的監聽照常有效）
// 6 頁共用一份（主控 network_analyzer/result，同步 5 個工具與 public，qa/test_config/test_alpaca_buddy.mjs 檢查相同）；
// 文字表自帶 12 語言（比照 payload-sniff.js），不進各工具 LANG。各頁的 showEggToast() 改呼叫 AlpacaBuddy.say()。
(function () {
  'use strict';
  const TEXT = {
    zhTW: { pocket: '羊駝口袋', empty: '口袋還是空的。分析時遇到的小彩蛋會收在這裡，不會打斷你。', wardrobe: '換裝（彩蛋語言，各連點 3 次解鎖）', loud: '被動彩蛋直接說出來', duty: '⛑️ 值勤中：有 {n} 個嚴重項目，先看：{top}', go: '前往', close: '關閉', open: '打開羊駝口袋',
      llama: '🦙 羊駝表示：我沒有出演海盜相關電影，更沒有被當作籌碼送給某個好萊塢明星' },
    en: { pocket: "Alpaca's pocket", empty: 'Nothing here yet. Little easter eggs found during analysis are kept here instead of interrupting you.', wardrobe: 'Wardrobe (egg languages — click each 3 times to unlock)', loud: 'Say passive easter eggs out loud', duty: '⛑️ On duty: {n} critical item(s). Look at this first: {top}', go: 'Go', close: 'Close', open: "Open the alpaca's pocket",
      llama: '🦙 The alpaca would like to state: I did not star in any pirate movie, and I was certainly never handed over to a Hollywood star as a bargaining chip.' },
    ja: { pocket: 'アルパカのポケット', empty: 'まだ空っぽです。分析中に見つかった小さなイースターエッグは、邪魔をしないようにここにしまっておきます。', wardrobe: '着せ替え（イースターエッグ言語。それぞれ 3 回クリックで解放）', loud: '受動的なイースターエッグをその場で表示', duty: '⛑️ 当番中：重大な項目が {n} 件。まずはこちら：{top}', go: '移動', close: '閉じる', open: 'アルパカのポケットを開く',
      llama: '🦙 アルパカより：海賊映画には出演していませんし、ハリウッドスターへの交渉材料として差し出されたこともありません' },
    tlh: { pocket: "alpaca qoD", empty: "pagh. Hoch Daj DaSamlu'bogh naDev pol.", wardrobe: "Hol (wa'logh wej yI'uy)", loud: "Daj DaSamlu'bogh yIjatlh", duty: "⛑️ ghIQ: {n} ghot'e' Qob. wa'DIch yIlegh: {top}", go: "yIjaH", close: "yISoQmoH", open: "alpaca qoD yIpoSmoH",
      llama: "🦙 alpaca jatlh: pirate Qul'a'Daq jIQujbe', Hollywood Sujwa'pu'vaD jInobbe'!" },
    pirate: { pocket: "Th' alpaca's treasure pouch", empty: "Empty as a sunken hold. Trinkets found while plunderin' get stashed here, quiet-like.", wardrobe: "Sea chest o' costumes (click each 3 times to unlock)", loud: "Shout passive trinkets from th' crow's nest", duty: "⛑️ All hands! {n} critical item(s). Inspect this first: {top}", go: "Sail", close: "Belay", open: "Open th' alpaca's pouch",
      llama: "🦙 Th' alpaca swears on th' code: never sailed in any pirate picture, nor was it ever traded to some Hollywood star as a bargainin' chip, arr!" },
    emoji: { pocket: '🦙👜', empty: '👜🫙… 🥚➡️👜🤫', wardrobe: '👗🎭 (👆×3 🔓)', loud: '🥚📢', duty: '⛑️🚨 {n} ❗ 👀➡️ {top}', go: '➡️', close: '✖️', open: '🦙👜🔓',
      llama: '🦙🙅‍♂️🏴‍☠️🎬 🙅‍♂️🎁➡️🌟🎬' },
    bureau: { pocket: '羊駝口袋（收文簿）', empty: '本口袋目前尚無收文。分析期間所得彩蛋均依規存放於此，不另行打擾。', wardrobe: '換裝（彩蛋語言，各連點三次即予核定）', loud: '被動彩蛋即時公告', duty: '⛑️ 值勤中：計有嚴重項目 {n} 項，請先行檢視：{top}', go: '前往辦理', close: '結案', open: '調閱羊駝口袋',
      llama: '🦙 羊駝鄭重聲明：本駝未曾出演任何海盜相關電影，亦未曾被作為籌碼移交予任何好萊塢明星，特此聲明' },
    cat: { pocket: '羊駝口袋喵', empty: '口袋還是空的喵。分析時遇到的小彩蛋會收在這裡，不吵你喵。', wardrobe: '換裝喵（彩蛋語言，各連點 3 次解鎖）', loud: '被動彩蛋直接說出來喵', duty: '⛑️ 值勤中喵：有 {n} 個嚴重項目，先看：{top}', go: '前往喵', close: '關閉喵', open: '打開羊駝口袋喵',
      llama: '🦙 羊駝表示：我沒有出演海盜相關電影，更沒有被當作籌碼送給某個好萊塢明星喵' },
    bean: { pocket: '🫛羊駝口袋', empty: '🫛口袋還是空的。分析時遇到的小彩蛋會收在這裡，不會打斷你。', wardrobe: '🫛換裝（彩蛋語言，各連點 3 次解鎖）', loud: '🫛被動彩蛋直接說出來', duty: '🫛⛑️ 值勤中：有 {n} 個嚴重項目，先看：{top}', go: '🫛前往', close: '🫛關閉', open: '🫛打開羊駝口袋',
      llama: '🫛🦙 羊駝表示：我沒有出演海盜相關電影，更沒有被當作籌碼送給某個好萊塢明星' },
    alpaca: { pocket: '咩的口袋-aca', empty: '口袋還是空的咩。分析時撿到的小彩蛋會先收著，不吵你-aca。', wardrobe: '換裝-aca（彩蛋語言，各連點 3 次解鎖）', loud: '被動彩蛋直接咩出來', duty: '⛑️ 咩在值勤：有 {n} 個嚴重項目，先看：{top}', go: '咩過去', close: '收起來-aca', open: '打開咩的口袋',
      llama: '🦙 咩鄭重表示：本咩沒有出演海盜相關電影，更沒有被當作籌碼送給某個好萊塢明星-aca' },
    yanse: { pocket: '羊駝口袋（反正也沒人看）', empty: '空的。彩蛋都收在這，反正你也忙。', wardrobe: '換裝（彩蛋語言，連點 3 次，有空再說）', loud: '被動彩蛋硬要說出來', duty: '⛑️ 唉，值勤中：有 {n} 個嚴重項目，先看：{top}', go: '去吧', close: '算了', open: '打開羊駝口袋（如果你堅持）',
      llama: '🦙 羊駝表示：我沒有出演海盜相關電影，更沒有被當作籌碼送給某個好萊塢明星……解釋好累' },
    wuxia: { pocket: '羊駝錦囊', empty: '錦囊尚空。行走江湖所得奇遇，皆暫存於此，不擾閣下修行。', wardrobe: '易容（彩蛋語言，各連點三下方可參悟）', loud: '奇遇即時昭告', duty: '⛑️ 守關中：有 {n} 處要害，請先察看：{top}', go: '前往', close: '收起錦囊', open: '開啟羊駝錦囊',
      llama: '🦙 羊駝聲明：在下從未出演海上盜匪之戲，更未曾被當作籌碼贈予西方影壇名角' },
  };
  const LANGS = Object.keys(TEXT);
  const POCKET_MAX = 30, ACTIVE_MS = 1200;
  const t = (k, lang) => (TEXT[lang] || TEXT.en)[k] || TEXT.en[k] || k;
  // 主動或被動：最近 ACTIVE_MS 內有使用者動作（keydown、點彩蛋元素）＝主動
  const classify = (now, lastAct) => (now - lastAct <= ACTIVE_MS ? 'active' : 'passive');
  const dutyText = (n, top, lang) => t('duty', lang).replace('{n}', n).replace('{top}', top || '-');
  const curLang = () => {
    try { if (typeof _lang !== 'undefined') return _lang; } catch (e) { /* 未宣告 */ }
    try { if (typeof currentLang !== 'undefined') return currentLang; } catch (e) { /* 未宣告 */ }
    return 'zhTW';
  };
  const pocket = [];
  let lastAct = 0, unread = 0, duty = null, dutyShownKey = '', hideTimer = null;
  const hasDoc = typeof document !== 'undefined';
  const loud = () => { try { return localStorage.getItem('_netAnalyzer_eggLoud') === '1'; } catch (e) { return false; } };
  const setLoud = v => { try { if (v) localStorage.setItem('_netAnalyzer_eggLoud', '1'); else localStorage.removeItem('_netAnalyzer_eggLoud'); } catch (e) { /* 無法儲存時只影響這次 */ } };

  // ── 畫面元素（第一次需要時才建立）──
  const $ = id => (hasDoc ? document.getElementById(id) : null);
  const css = (el, s) => { Object.assign(el.style, s); return el; };
  // 羊駝：沿用頁面上固定在角落的那隻（#mini-alpaca／#alpaca-corner），沒有就自己放一隻
  function mascot() {
    for (const id of ['mini-alpaca', 'alpaca-corner']) {
      const el = $(id);
      if (el && getComputedStyle(el).position === 'fixed' && el.offsetWidth) return el;
    }
    let el = $('alpaca-buddy-mascot');
    if (!el) {
      el = css(document.createElement('div'), { position: 'fixed', bottom: '16px', right: '16px', zIndex: '9999', fontSize: '32px', cursor: 'pointer', userSelect: 'none', lineHeight: '1' });
      el.id = 'alpaca-buddy-mascot'; el.textContent = '🦙';
      el.addEventListener('click', () => togglePanel());
      document.body.appendChild(el);
    }
    return el;
  }
  // 依羊駝位置算出：右緣距離與上緣距離（fixed 定位用）
  function anchor() {
    const r = mascot().getBoundingClientRect();
    return { right: Math.max(8, window.innerWidth - r.right), bottom: Math.max(8, window.innerHeight - r.top + 8), left: r.left, top: r.top, w: r.width };
  }
  function pocketBtn() {
    let b = $('alpaca-pocket-btn');
    if (!b) {
      b = css(document.createElement('button'), { position: 'fixed', zIndex: '10000', border: '1px solid rgba(128,128,128,.4)', borderRadius: '14px', padding: '2px 7px', fontSize: '13px', cursor: 'pointer', background: 'var(--surface,#fff)', color: 'var(--text,#222)', lineHeight: '1.4' });
      b.id = 'alpaca-pocket-btn'; b.type = 'button';
      b.addEventListener('click', () => togglePanel());
      document.body.appendChild(b);
    }
    const a = anchor();
    css(b, { right: (window.innerWidth - a.left + 4) + 'px', top: (a.top + 2) + 'px' });
    b.textContent = '🎒' + (unread ? ' ' + unread : '');
    b.title = t('open', curLang());
    b.setAttribute('aria-label', t('open', curLang()));
    return b;
  }
  function helmet() {
    let h = $('alpaca-helmet');
    if (!duty) { if (h) h.remove(); return; }
    if (!h) {
      h = css(document.createElement('span'), { position: 'fixed', zIndex: '10000', fontSize: '18px', pointerEvents: 'none', lineHeight: '1' });
      h.id = 'alpaca-helmet'; h.textContent = '⛑️';
      document.body.appendChild(h);
    }
    const a = anchor();
    css(h, { left: (a.left + a.w / 2 - 9) + 'px', top: (a.top - 12) + 'px' });
  }
  // 泡泡：羊駝上方，可關閉；值勤泡泡另帶「前往」
  function bubble(text, ms, goFn) {
    let el = $('alpaca-bubble');
    if (!el) {
      el = css(document.createElement('div'), { position: 'fixed', zIndex: '10001', maxWidth: 'min(340px, calc(100vw - 32px))', padding: '10px 30px 10px 12px', borderRadius: '12px', border: '1px solid var(--accent,#0aa)', background: 'var(--surface2,var(--surface,#fff))', color: 'var(--text,#222)', fontSize: '13px', lineHeight: '1.5', boxShadow: '0 4px 18px rgba(0,0,0,.18)' });
      el.id = 'alpaca-bubble'; el.className = 'alpaca-bubble';
      el.setAttribute('role', 'status');
      document.body.appendChild(el);
    }
    const a = anchor();
    css(el, { right: a.right + 'px', bottom: a.bottom + 'px', display: 'block' });
    el.textContent = '';
    const msg = document.createElement('span'); msg.textContent = text; el.appendChild(msg);
    if (goFn) {
      const g = css(document.createElement('button'), { marginLeft: '8px', fontSize: '12px', cursor: 'pointer' });
      g.type = 'button'; g.textContent = t('go', curLang()); g.setAttribute('data-buddy-go', '');
      g.addEventListener('click', () => { hideBubble(); try { goFn(); } catch (e) { /* 頁面自行處理 */ } });
      el.appendChild(g);
    }
    const x = css(document.createElement('button'), { position: 'absolute', top: '4px', right: '6px', border: 'none', background: 'none', cursor: 'pointer', fontSize: '14px', color: 'inherit' });
    x.type = 'button'; x.textContent = '✕'; x.title = t('close', curLang()); x.addEventListener('click', hideBubble);
    el.appendChild(x);
    clearTimeout(hideTimer);
    hideTimer = setTimeout(hideBubble, ms || 5000);
  }
  function hideBubble() { const el = $('alpaca-bubble'); if (el) el.style.display = 'none'; }

  // ── 口袋面板：值勤行、收集到的彩蛋、換裝（.lang-egg）、被動彩蛋開關 ──
  function panelEl() {
    let p = $('alpaca-panel');
    if (!p) {
      p = css(document.createElement('div'), { position: 'fixed', zIndex: '10002', width: 'min(340px, calc(100vw - 32px))', maxHeight: '60vh', overflow: 'auto', padding: '12px', borderRadius: '12px', border: '1px solid var(--border,#ccc)', background: 'var(--surface,#fff)', color: 'var(--text,#222)', fontSize: '13px', boxShadow: '0 6px 24px rgba(0,0,0,.22)', display: 'none' });
      p.id = 'alpaca-panel';
      p.innerHTML = '<div style="display:flex;justify-content:space-between;align-items:center;font-weight:700;margin-bottom:6px"><span data-buddy="title"></span><button type="button" data-buddy="close" style="border:none;background:none;cursor:pointer;font-size:14px;color:inherit">✕</button></div>'
        + '<div data-buddy="duty" style="margin-bottom:8px"></div><div data-buddy="list" style="margin-bottom:10px"></div>'
        + '<div data-buddy="wtitle" style="font-size:12px;opacity:.75;margin-bottom:4px"></div><div data-buddy="wardrobe" style="display:flex;flex-wrap:wrap;gap:6px;font-size:18px;margin-bottom:10px"></div>'
        + '<label style="display:flex;gap:6px;align-items:center;font-size:12px"><input type="checkbox" data-buddy="loud"><span data-buddy="loudlbl"></span></label>';
      p.querySelector('[data-buddy="close"]').addEventListener('click', () => { p.style.display = 'none'; });
      p.querySelector('[data-buddy="loud"]').addEventListener('change', e => setLoud(e.target.checked));
      document.body.appendChild(p);
    }
    return p;
  }
  // 頁面頂端的彩蛋語言圖示搬進換裝區（只搬一次）
  function adoptLangEggs() {
    const w = panelEl().querySelector('[data-buddy="wardrobe"]');
    document.querySelectorAll('.lang-egg').forEach(el => { if (el.parentNode !== w) { el.style.opacity = '1'; w.appendChild(el); } });
  }
  function renderPanel() {
    const p = panelEl(), lang = curLang();
    p.querySelector('[data-buddy="title"]').textContent = '🦙 ' + t('pocket', lang);
    const d = p.querySelector('[data-buddy="duty"]');
    d.textContent = duty ? dutyText(duty.n, duty.top, lang) : '';
    d.style.display = duty ? '' : 'none';
    const list = p.querySelector('[data-buddy="list"]');
    list.textContent = '';
    if (!pocket.length) { const e = document.createElement('div'); e.style.opacity = '.7'; e.textContent = t('empty', lang); list.appendChild(e); }
    pocket.forEach(x => { const r = document.createElement('div'); r.setAttribute('data-buddy-item', ''); r.style.cssText = 'padding:4px 0;border-bottom:1px dashed rgba(128,128,128,.3)'; r.textContent = x.text; list.appendChild(r); });
    p.querySelector('[data-buddy="wtitle"]').textContent = t('wardrobe', lang);
    p.querySelector('[data-buddy="loudlbl"]').textContent = t('loud', lang);
    p.querySelector('[data-buddy="loud"]').checked = loud();
    const a = anchor();
    css(p, { right: a.right + 'px', bottom: a.bottom + 'px' });
  }
  function togglePanel(force) {
    if (!hasDoc) return;
    const p = panelEl();
    const show = force === undefined ? p.style.display === 'none' : !!force;
    if (show) { adoptLangEggs(); renderPanel(); p.style.display = 'block'; hideBubble(); unread = 0; pocketBtn(); }
    else p.style.display = 'none';
  }

  // ── 對外介面 ──
  // 彩蛋訊息：主動→泡泡；被動→口袋（開關開啟且不在值勤中時也出泡泡）
  function say(msg, dur) {
    if (!msg) return;
    const kind = classify(Date.now(), lastAct);
    if (kind === 'passive') {
      pocket.unshift({ text: String(msg), ts: Date.now() });
      if (pocket.length > POCKET_MAX) pocket.length = POCKET_MAX;
      unread++;
      if (!hasDoc) return;
      pocketBtn();
      if ($('alpaca-panel') && $('alpaca-panel').style.display !== 'none') renderPanel();
      if (!loud() || duty) return;
    }
    if (hasDoc) bubble(String(msg), Math.max(dur || 0, 4000));
  }
  // 值勤模式：info＝{n, top, go}；null 解除。同一組 n＋top 只主動跳一次泡泡
  function setDuty(info) {
    duty = info && info.n > 0 ? { n: info.n, top: info.top || '', go: info.go || null } : null;
    if (!hasDoc) return;
    helmet(); pocketBtn();
    const key = duty ? duty.n + '|' + duty.top : '';
    if (duty && key !== dutyShownKey) { dutyShownKey = key; bubble(dutyText(duty.n, duty.top, curLang()), 9000, duty.go); }
    if (!duty) dutyShownKey = '';
    if ($('alpaca-panel') && $('alpaca-panel').style.display !== 'none') renderPanel();
  }
  // 切換語言或視窗大小改變時重畫位置與文字
  function refresh() {
    if (!hasDoc || !document.body) return;
    pocketBtn(); helmet();
    if ($('alpaca-panel') && $('alpaca-panel').style.display !== 'none') renderPanel();
  }

  if (hasDoc) {
    // 使用者動作：任何按鍵、點彩蛋元素（羊駝、口袋按鈕、彩蛋語言圖示）
    document.addEventListener('keydown', () => { lastAct = Date.now(); }, true);
    document.addEventListener('click', e => {
      const el = e.target && e.target.closest ? e.target.closest('.lang-egg,#mini-alpaca,#alpaca-corner,#alpaca-btn,#alpaca-buddy-mascot,#alpaca-pocket-btn,#alpaca-panel') : null;
      if (el) lastAct = Date.now();
    }, true);
    // 自製彩蛋：輸入 sparrow 或 llama，羊駝出面澄清（主動彩蛋，使用者 2026-10-29 提議）
    let buf = '';
    document.addEventListener('keydown', e => {
      if (!e.key || e.key.length !== 1) return;
      buf = (buf + e.key.toLowerCase()).slice(-7);
      if (/(?:sparrow|llama)$/.test(buf)) { buf = ''; say(t('llama', curLang()), 7000); }
    });
    const start = () => { adoptLangEggs(); pocketBtn(); };
    // 防火牆、去識別化的角落羊駝由程式在載入後建立，稍等再定位
    if (document.readyState === 'complete') setTimeout(start, 300);
    else window.addEventListener('load', () => setTimeout(start, 300));
    window.addEventListener('resize', refresh);
  }
  const api = { say, setDuty, refresh, togglePanel, pocket: () => pocket.map(x => x.text), classify, dutyText, TEXT, LANGS, POCKET_MAX, ACTIVE_MS,
    _reset() { pocket.length = 0; unread = 0; duty = null; dutyShownKey = ''; lastAct = 0; } };
  if (typeof window !== 'undefined') window.AlpacaBuddy = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})();
