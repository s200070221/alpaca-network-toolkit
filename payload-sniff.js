// ═══════════════════════════════════════════════════════════════════════════
// payload-sniff.js — 可疑注入字串彩蛋（2026-10-24，XN20；主控在 network_analyzer/result，同步到 5 個工具 result 與 public）
// 設定檔裡出現常見的注入測試字串時，跳一則調侃的羊駝提示。工具輸出前一律跳脫，這些字串本來就不會被執行；
// 這裡只負責「看到了」，不改變任何分析結果。log 工具不用 sniff()（log 裡出現攻擊字串是正常內容），
// 改用 logMessage() 與漏洞利用嘗試偵測連動。文字表比照 toolkit-version.js 自帶 12 語言；全域物件 PayloadSniff
// ═══════════════════════════════════════════════════════════════════════════
const PayloadSniff = (function () {
  const MAX_SCAN = 2 * 1024 * 1024;
  const KINDS = [
    ['xss', /<script\b|<img\b[^>\n]*\bonerror\s*=|<svg\b[^>\n]*\bonload\s*=|javascript:\s*alert\s*\(/i],
    ['proto', /__proto__|constructor\s*(?:\.|\[\s*["'])\s*prototype/],
    ['ssti', /\{\{\s*7\s*\*\s*7\s*\}\}|\$\{\s*7\s*\*\s*7\s*\}|<%=\s*7\s*\*\s*7\s*%>/],
    ['jndi', /\$\{\s*jndi\s*:/i],
    ['sqli', /'\s*or\s+'?1'?\s*=\s*'?1|\bunion\s+(?:all\s+)?select\s+(?:null|\d|@@|user\(|version\()|;\s*drop\s+table\s+\w/i],
    ['csvf', /(?:^|[,;\t"])\s*=\s*(?:cmd\s*\||hyperlink\s*\(|dde\s*\()/im],
    ['traversal', /(?:\.\.[\/\\]){3,}(?:etc[\/\\]passwd|windows[\/\\]win\.ini)/i],
    ['cmdi', /\$\(\s*(?:id|whoami|uname)\b[^)]*\)|`\s*(?:id|whoami|uname)\b[^`]*`|[;|&]\s*(?:curl|wget)\s+https?:\/\//i],
  ];
  // 訊息只說「是哪一類」，不重複引用原字串
  const MSG = {
    zhTW: { xss: "🦙 設定檔裡藏了網頁腳本？羊駝只會把它當成一個很長、很難念的名字，這裡每個字都會跳脫，什麼也不會跳出來。",
      proto: "🦙 想動物件原型？這招羊駝前兩天才學會擋，換一招吧。", ssti: "🦙 樣板運算式？羊駝會算數學，但不會幫你執行。",
      jndi: "🦙 JNDI 查詢字串？羊駝不是 Java，不會出門幫你拿東西，只會記下來。", sqli: "🦙 SQL 注入？這裡沒有資料庫，只有一隻正在吃草的羊駝。",
      csvf: "🦙 想在匯出的 CSV 埋公式？匯出前會自動加單引號，試算表只會看到一串字。", traversal: "🦙 路徑穿越？這是瀏覽器裡的靜態頁，往上爬三層也只會爬到羊駝的草堆。",
      cmdi: "🦙 指令注入？羊駝知道自己是誰，不需要你提醒，也不會幫你執行。", more: "（羊駝的鼻子另外還聞到 {n} 種可疑字串）",
      logXpl: "🦙 有人拿 {name} 來敲門，羊駝已經登記在問題清單上了。", logXplOk: "🦙 這次不是玩笑：{name} 的利用請求拿到 2xx 回應，請先看問題清單、檢查那台主機。" },
    en: { xss: "🦙 A web script hidden in a config file? The alpaca just reads it as a very long, awkward name. Everything here is escaped, so nothing pops up.",
      proto: "🦙 Poking at object prototypes? The alpaca learned to block that just the other day. Try another trick.", ssti: "🦙 A template expression? The alpaca can do math, it just won't run it for you.",
      jndi: "🦙 A JNDI lookup string? The alpaca isn't Java and won't go fetch anything. It just writes it down.", sqli: "🦙 SQL injection? There's no database here, only an alpaca eating grass.",
      csvf: "🦙 Planting a formula in the exported CSV? A quote is added before export, so the spreadsheet just sees text.", traversal: "🦙 Path traversal? This is a static page in your browser; three levels up is just the alpaca's haystack.",
      cmdi: "🦙 Command injection? The alpaca knows who it is, thanks, and won't run that for you.", more: "(the alpaca also sniffed {n} more kind(s) of suspicious string)",
      logXpl: "🦙 Someone came knocking with {name}. The alpaca has logged it in the issue list.", logXplOk: "🦙 Not a joke this time: {name} exploit requests got a 2xx response. Check the issue list and that host first." },
    ja: { xss: "🦙 設定ファイルに Web スクリプト？アルパカはとても長くて読みにくい名前として読むだけです。ここでは全部エスケープされるので何も表示されません。",
      proto: "🦙 オブジェクトのプロトタイプをいじるつもり？アルパカはつい先日防ぎ方を覚えました。別の手をどうぞ。", ssti: "🦙 テンプレート式？アルパカは計算できますが、実行はしません。",
      jndi: "🦙 JNDI ルックアップ？アルパカは Java ではないので取りに行きません。メモするだけです。", sqli: "🦙 SQL インジェクション？ここにデータベースはありません。草を食べているアルパカがいるだけです。",
      csvf: "🦙 エクスポートする CSV に数式を仕込むつもり？出力前に引用符を付けるので、ただの文字列です。", traversal: "🦙 パストラバーサル？ここはブラウザの静的ページです。3 階層上がっても干し草の山があるだけです。",
      cmdi: "🦙 コマンドインジェクション？アルパカは自分が誰か知っていますし、実行もしません。", more: "（ほかにも {n} 種類の怪しい文字列を嗅ぎつけました）",
      logXpl: "🦙 誰かが {name} でノックしてきました。問題一覧に記録済みです。", logXplOk: "🦙 今回は冗談ではありません：{name} の悪用リクエストに 2xx 応答があります。まず問題一覧とそのホストを確認してください。" },
    tlh: { xss: "🦙 ghItlhDaq script? Qagh! Hoch escape. pagh tu'lu'.", proto: "🦙 prototype? ghojta' alpaca. latlh mIw yIlo'.", ssti: "🦙 template? mI' toghlaH alpaca; ta'be'.",
      jndi: "🦙 JNDI? Java ghaHbe' alpaca.", sqli: "🦙 SQL? De' pa' tu'lu'be'. alpaca Sop neH.", csvf: "🦙 CSV formula? quote chel. ghItlh neH.",
      traversal: "🦙 wej Dung yIghoS: Sopbe'wI' neH.", cmdi: "🦙 alpaca ghaH alpaca. ta'be'.", more: "(latlh {n})",
      logXpl: "🦙 {name} lo'taH jagh. ghItlhta' alpaca.", logXplOk: "🦙 Qagh law'! {name} 2xx jang. DaH yIQIj!" },
    pirate: { xss: "🦙 A script stowed in the config, ye scallywag? The alpaca reads it as a fancy ship's name. Nothin' pops up on this vessel, arr!",
      proto: "🦙 Fiddlin' with prototypes, matey? That hull was patched just the other day. Try another trick!", ssti: "🦙 A template riddle? The alpaca counts the coins but won't run 'em.",
      jndi: "🦙 A JNDI map? This alpaca don't sail to strange ports for ye. Logged in the captain's book.", sqli: "🦙 SQL tricks? There be no treasure database here, only an alpaca munchin' grass.",
      csvf: "🦙 Buryin' a formula in the CSV? We add a quote before export. Just ink on parchment, arr!", traversal: "🦙 Climbin' up the rigging? Three decks up there be naught but hay!",
      cmdi: "🦙 Givin' orders to the crew? The alpaca ain't walkin' yer plank.", more: "(and the alpaca's nose caught {n} more scent(s) o' mischief)",
      logXpl: "🦙 Some scoundrel came knockin' with {name}. Logged in the captain's book.", logXplOk: "🦙 No jest this time, matey: {name} got a 2xx answer. Check the issue list first!" },
    emoji: { xss: "🦙👀📜➡️🔤 ✅", proto: "🦙🧬🔧❌", ssti: "🦙🧮✅ ▶️❌", jndi: "🦙☕❌📝", sqli: "🦙🗄️❌🌱", csvf: "🦙📊💣❌", traversal: "🦙🪜🪜🪜➡️🌾", cmdi: "🦙⌨️❌",
      more: "(👃 +{n})", logXpl: "🦙🚪✊ {name} 📝✅", logXplOk: "🦙🚨 {name} 2xx ❗📋👀" },
    bureau: { xss: "🦙【本案】查設定檔內含網頁腳本字樣，一律以純文字登載，不予執行，請陳請人知悉。", proto: "🦙【本案】物件原型一案業已修正完畢，請改以其他方式陳情。",
      ssti: "🦙【本案】樣板運算式經核算無誤，惟本局僅負責核算，不負責執行。", jndi: "🦙【本案】所請外出調閱資料一節，礙難照辦，已建檔備查。",
      sqli: "🦙【本案】查本單位並無資料庫，僅有羊駝一頭，所請不予受理。", csvf: "🦙【本案】擬於匯出報表夾帶公式一節，已依規定於匯出前加註單引號。",
      traversal: "🦙【本案】越級陳情，經查上三層僅為草料倉庫。", cmdi: "🦙【本案】身分查詢一案，本羊駝身分明確，免予執行。", more: "（另查有可疑字串 {n} 案，併案辦理）",
      logXpl: "🦙【本案】查有人以 {name} 叩關，業已登錄於問題清單。", logXplOk: "🦙【急件】{name} 利用請求已獲 2xx 回應，請即刻查明該主機。" },
    cat: { xss: "🐱 設定檔裡藏腳本喵？本喵只會把它當成很長的名字唸出來，什麼都不會跳出來喵。", proto: "🐱 想動原型喵？這招前兩天被本喵拍掉了，換一根逗貓棒吧喵。",
      ssti: "🐱 樣板算式喵？本喵算得出來，但不幫你執行喵。", jndi: "🐱 要本喵出門幫你拿東西？不要喵，本喵要睡覺。", sqli: "🐱 這裡沒有資料庫喵，只有一個紙箱。",
      csvf: "🐱 CSV 埋公式喵？加了單引號，只是一串字喵。", traversal: "🐱 往上爬三層喵？上面只有貓跳台。", cmdi: "🐱 叫本喵執行指令？本喵只聽罐頭的喵。", more: "（還聞到 {n} 種怪味道喵）",
      logXpl: "🐱 有人拿 {name} 來抓門喵，記在問題清單了。", logXplOk: "🐱 不是玩笑喵：{name} 拿到 2xx 回應，快去看那台主機喵！" },
    bean: { xss: "🫛 豆莢裡藏腳本？豆子只會把它當成很長的名字，什麼都沒發芽。", proto: "🫛 想改豆子的祖宗？前兩天才補好，換一招吧。", ssti: "🫛 算式豆子會算，但不會照著長。",
      jndi: "🫛 豆子不會滾出去幫你拿東西。", sqli: "🫛 這裡沒有資料庫，只有一盤毛豆。", csvf: "🫛 CSV 裡的公式已經被剝殼成純文字。", traversal: "🫛 往上爬三層也只有豆架。",
      cmdi: "🫛 豆子不接受指令，只接受水和陽光。", more: "（另外還有 {n} 顆可疑的豆子）", logXpl: "🫛 有人拿 {name} 來敲豆莢，已記在問題清單。", logXplOk: "🫛 這次是真的：{name} 拿到 2xx 回應，快看問題清單！" },
    alpaca: { xss: "🦙 咩～藏腳本？羊駝只會當成很長的名字念出來咩，什麼都不會跳出來。", proto: "🦙 想動原型咩？這招剛擋下來，換一招咩。", ssti: "🦙 算式羊駝會算咩，但不幫你跑。",
      jndi: "🦙 羊駝不出門幫你拿東西咩，記下來了。", sqli: "🦙 這裡沒有資料庫咩，只有草。", csvf: "🦙 CSV 公式已經加上單引號咩。", traversal: "🦙 爬三層也只有草堆咩。",
      cmdi: "🦙 羊駝不聽指令咩，只吃草。", more: "（羊駝還聞到 {n} 種怪味咩）", logXpl: "🦙 有人拿 {name} 來敲柵欄咩，記在問題清單了。", logXplOk: "🦙 不是開玩笑咩：{name} 拿到 2xx，快去看那台主機！" },
    yanse: { xss: "🦙 塞腳本？當成名字，就這樣。", proto: "🦙 動原型？擋了，就這樣。", ssti: "🦙 算式？不執行，就這樣。", jndi: "🦙 JNDI？不去，就這樣。", sqli: "🦙 SQL？沒資料庫，就這樣。",
      csvf: "🦙 CSV 公式？加單引號，就這樣。", traversal: "🦙 往上爬？只有草，就這樣。", cmdi: "🦙 下指令？不聽，就這樣。", more: "（還有 {n} 種，就這樣）",
      logXpl: "🦙 {name} 來敲門，記了，就這樣。", logXplOk: "🦙 {name} 拿到 2xx，快去看，就這樣。" },
    wuxia: { xss: "🦙 暗器藏於卷宗之中？在下一律以白紙黑字收錄，暗器自然失效。", proto: "🦙 欲撼祖師牌位？此門數日前已補上，閣下另尋他法。", ssti: "🦙 奇門算式，在下算得出，卻不依式行功。",
      jndi: "🦙 請在下遠赴他山取物？恕難從命，已記入冊。", sqli: "🦙 此處並無藏經閣，只有一頭吃草的羊駝。", csvf: "🦙 欲於帳冊暗藏機關？出冊前已加封印，只剩字跡。",
      traversal: "🦙 欲翻牆越院？連上三重，也只見草料堆。", cmdi: "🦙 號令在下？羊駝只聽掌門，不聽外人。", more: "（另察覺 {n} 路暗招）",
      logXpl: "🦙 有人以 {name} 叩關，已記入問題清單。", logXplOk: "🦙 非同兒戲：{name} 已破關得 2xx 回應，速往查看那台主機！" },
  };
  const LANGS = Object.keys(MSG);
  const pick = lang => MSG[lang] || MSG.en;
  const fill = (s, p) => String(s).replace(/\{(\w+)\}/g, (m, k) => (p && p[k] !== undefined ? String(p[k]) : m));
  function sniff(text) {
    const t = String(text || '').slice(0, MAX_SCAN);
    return KINDS.filter(([, re]) => re.test(t)).map(([k]) => k);
  }
  function message(kind, lang, p) { return fill(pick(lang)[kind] || '', p); }
  const shown = new Set();
  // 同一頁同一種類只提示一次；回傳顯示的訊息（沒有新的種類時回傳空字串）
  function notify(text, lang, show) {
    const fresh = sniff(text).filter(k => !shown.has(k));
    if (!fresh.length) return '';
    fresh.forEach(k => shown.add(k));
    const msg = message(fresh[0], lang) + (fresh.length > 1 ? ' ' + message('more', lang, { n: fresh.length - 1 }) : '');
    if (typeof show === 'function') show(msg);
    return msg;
  }
  // log 工具：issues 為 buildIssueList() 結果；有漏洞利用嘗試時回傳訊息（2xx 用嚴肅版），同一頁只提示一次
  let logShown = false;
  function logMessage(issues, lang) {
    const xs = (issues || []).filter(i => i.category === 'exploitAttempt');
    if (!xs.length || logShown) return '';
    logShown = true;
    const ok = xs.find(i => i.exploitOk);
    const nameOf = i => (i.sampleTpl && i.sampleTpl.p && i.sampleTpl.p.name) || i.exploitSig || '';
    return ok ? message('logXplOk', lang, { name: nameOf(ok) }) : message('logXpl', lang, { name: nameOf(xs[0]) });
  }
  return { sniff, message, notify, logMessage, KINDS: KINDS.map(k => k[0]), LANGS, _reset() { shown.clear(); logShown = false; } };
})();
