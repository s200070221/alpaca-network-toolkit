// ════════════════════════════════════════════════════════════════════════════
// file-howto.js — 怎麼從設備取得檔案（2026-10-29，XN52）與錯誤檔案判斷（XN53）；主控在 network_analyzer/result，同步到防火牆、交換器分析、log 工具 result 與 public
// 入口頁任務卡、防火牆上傳頁、log 上傳區共用的「取得設定檔／log 的指令與 GUI 路徑」表。只收能確定的指令與選單路徑，
// 查不到可靠來源的廠牌不列；交換器的指令與交換器分析的 swExportCmds() 相同（qa test_hub_tasks 比對）。
// 介面文字比照 payload-sniff.js 自帶 12 語言；GUI 路徑只寫 zhTW／en／ja，中文系彩蛋語言用 zhTW、其餘用 en。全域物件 FileHowto
// ════════════════════════════════════════════════════════════════════════════
const FileHowto = (function () {
  // 各列：[名稱, CLI 指令（可空）, GUI 路徑 {zhTW,en,ja}（可空）]
  const FW = [
    ['FortiGate', 'show full-configuration', { zhTW: '右上角管理者選單 → Configuration → Backup', en: 'Admin menu (top right) → Configuration → Backup', ja: '右上の管理者メニュー → Configuration → Backup' }],
    ['Palo Alto', 'show config running', { zhTW: 'Device → Setup → Operations → Export named configuration snapshot', en: 'Device → Setup → Operations → Export named configuration snapshot', ja: 'Device → Setup → Operations → Export named configuration snapshot' }],
    ['Cisco ASA / FTD', 'show running-config', null],
    ['Juniper SRX', 'show configuration | display set', null],
    ['pfSense', '', { zhTW: 'Diagnostics → Backup & Restore（下載 config.xml）', en: 'Diagnostics → Backup & Restore (download config.xml)', ja: 'Diagnostics → Backup & Restore（config.xml をダウンロード）' }],
    ['OPNsense', '', { zhTW: 'System → Configuration → Backups（下載 config.xml）', en: 'System → Configuration → Backups (download config.xml)', ja: 'System → Configuration → Backups（config.xml をダウンロード）' }],
    ['MikroTik RouterOS', '/export', null],
    ['VyOS / EdgeRouter', 'show configuration commands', null],
    ['Linux iptables', 'iptables-save', null],
    ['Linux nftables', 'nft list ruleset', null],
    ['OpenWrt', 'uci export firewall', null],
  ];
  // 與交換器分析 swExportCmds() 相同
  const SW = [
    ['H3C / HPE Comware', 'display current-configuration'], ['Cisco IOS / IOS-XE', 'show running-config'], ['Cisco NX-OS', 'show running-config'],
    ['Cisco Business (CBS/SG)', 'show running-config'], ['Arista EOS', 'show running-config'], ['Aruba CX', 'show running-config'],
    ['Aruba ProCurve', 'show running-config'], ['FortiSwitch', 'show full-configuration'], ['Juniper EX/QFX', 'show configuration'],
    ['Dell OS10', 'show running-configuration'], ['Ruckus/Brocade ICX', 'show running-config'], ['Extreme EXOS', 'show configuration'],
    ['Extreme VOSS', 'show running-config'], ['Alcatel OmniSwitch', 'show configuration snapshot'], ['MikroTik RouterOS', '/export'],
    ['Ruijie RGOS', 'show running-config'], ['Netgear / EdgeSwitch', 'show running-config'], ['Planet', 'show running-config'],
    ['NVIDIA Cumulus', 'nv config show'], ['SONiC', 'cat /etc/sonic/config_db.json'],
  ].map(r => [r[0], r[1], null]);
  const LOG = [
    ['FortiGate', '', { zhTW: 'Log & Report → 選擇日誌類型 → 下載', en: 'Log & Report → (log type) → Download', ja: 'Log & Report → ログ種別を選択 → ダウンロード' }],
    ['Palo Alto', '', { zhTW: 'Monitor → Logs → Traffic／Threat → 匯出 CSV', en: 'Monitor → Logs → Traffic / Threat → Export to CSV', ja: 'Monitor → Logs → Traffic／Threat → CSV にエクスポート' }],
    ['Windows', 'wevtutil qe Security /c:5000 /rd:true /f:renderedxml > security.xml', { zhTW: '事件檢視器 → 在「安全性」按右鍵 → 另存所有事件 → CSV', en: 'Event Viewer → right-click Security → Save All Events As → CSV', ja: 'イベント ビューアー → 「セキュリティ」を右クリック → すべてのイベントを名前を付けて保存 → CSV' }],
    ['Windows PowerShell', 'Get-WinEvent -LogName Security -MaxEvents 5000 | Export-Csv security.csv -NoTypeInformation', null],
    ['Linux', 'cat /var/log/auth.log', { zhTW: '或直接使用 syslog 伺服器上收到的檔案（.gz 可直接匯入）', en: 'Or use the files on your syslog server (.gz can be imported directly)', ja: 'または syslog サーバー上のファイル（.gz はそのまま取り込み可）' }],
    ['AWS CloudTrail / VPC Flow Logs', 'aws s3 cp s3://<bucket>/<prefix>/ ./logs --recursive', { zhTW: '從 S3 下載的 .gz 檔可直接匯入', en: '.gz files downloaded from S3 can be imported directly', ja: 'S3 からダウンロードした .gz はそのまま取り込み可' }],
  ];
  const KINDS = { fw: FW, sw: SW, log: LOG };
  const T = {
    zhTW: { title: '怎麼從設備取得檔案', src: '設備／來源', cli: 'CLI 指令', gui: '網頁介面', copy: '複製', copied: '已複製', hint: 'CLI 指令的輸出存成文字檔、或從網頁介面下載的檔案，直接拖進來即可。不要用只顯示部分設定的指令。' },
    en: { title: 'How to get the file from your device', src: 'Device / source', cli: 'CLI command', gui: 'Web UI', copy: 'Copy', copied: 'Copied', hint: 'Save the CLI output as a text file, or use the file downloaded from the web UI, and drop it here. Avoid commands that show only part of the configuration.' },
    ja: { title: '機器からファイルを取得する方法', src: '機器／ソース', cli: 'CLI コマンド', gui: 'Web UI', copy: 'コピー', copied: 'コピーしました', hint: 'CLI の出力をテキストファイルに保存するか、Web UI でダウンロードしたファイルをそのままドロップしてください。設定の一部しか表示しないコマンドは避けてください。' },
    tlh: { title: "De' yIlI'! (How to get the file)", src: 'Device / source', cli: 'CLI ra\'', gui: 'Web UI', copy: 'yIqon', copied: "qon'lu'pu'", hint: 'Save the CLI output as a text file, or use the file downloaded from the web UI, and drop it here.' },
    pirate: { title: 'How to haul the file off yer device', src: 'Vessel / source', cli: 'CLI orders', gui: 'Web UI', copy: 'Copy', copied: 'Copied, arr', hint: 'Stow the CLI output in a text file, or use the file from the web UI, and toss it aboard here.' },
    emoji: { title: '📥 How to get the file', src: '🖥 Device', cli: '⌨️ CLI', gui: '🌐 Web UI', copy: '📋', copied: '✅', hint: '💾 Save CLI output as text, or use the web UI download, then drop it here.' },
    bureau: { title: '設備檔案調閱程序', src: '設備／來源', cli: 'CLI 指令', gui: '網頁介面', copy: '複製', copied: '已複製（存查）', hint: 'CLI 輸出請存成文字檔、或由網頁介面下載檔案後送入本處辦理。請勿使用僅顯示部分設定之指令。' },
    cat: { title: '怎麼從設備叼檔案回來喵', src: '設備／來源', cli: 'CLI 指令', gui: '網頁介面', copy: '複製', copied: '已複製喵', hint: '把 CLI 輸出存成文字檔，或從網頁介面下載，叼過來丟進來就好喵。' },
    bean: { title: '怎麼從設備挖出檔案', src: '設備／來源', cli: 'CLI 指令', gui: '網頁介面', copy: '複製', copied: '已複製', hint: '把 CLI 輸出存成文字檔，或從網頁介面下載，整顆丟進來。' },
    alpaca: { title: '羊駝教你從設備取得檔案', src: '設備／來源', cli: 'CLI 指令', gui: '網頁介面', copy: '複製', copied: '已複製咩', hint: '把 CLI 輸出存成文字檔，或從網頁介面下載，拖進來給羊駝看。' },
    yanse: { title: '怎麼從設備取得檔案，唉', src: '設備／來源', cli: 'CLI 指令', gui: '網頁介面', copy: '複製', copied: '已複製', hint: 'CLI 輸出存成文字檔，或從網頁介面下載，拖進來就好，唉。' },
    wuxia: { title: '取經之道', src: '門派／來源', cli: 'CLI 口訣', gui: '網頁介面', copy: '抄錄', copied: '已抄錄', hint: '以 CLI 口訣將設定謄錄成文字檔，或自網頁介面取回，投入此處即可。' },
  };
  const ZH_EGGS = ['bureau', 'cat', 'bean', 'alpaca', 'yanse', 'wuxia'];
  const t = (lang) => T[lang] || T.en;
  const guiLang = (lang) => (lang === 'zhTW' || ZH_EGGS.indexOf(lang) >= 0) ? 'zhTW' : lang === 'ja' ? 'ja' : 'en';
  const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  function rows(kind) { return (KINDS[kind] || []).map(r => ({ name: r[0], cli: r[1], gui: r[2] })); }
  // kinds：['fw','sw'] 等；回傳表格 HTML（全部跳脫，複製按鈕以 data-howto-copy 事件代理處理）
  function tableHtml(kinds, lang) {
    const L = t(lang), gl = guiLang(lang);
    const list = [].concat(...[].concat(kinds).map(rows));
    let h = '<div class="howto-hint" style="font-size:12px;opacity:.8;margin:4px 0 6px">' + esc(L.hint) + '</div>'
      + '<div style="overflow-x:auto"><table class="howto-table" style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr>'
      + ['src', 'cli', 'gui'].map(k => '<th style="text-align:left;padding:4px 6px;border-bottom:1px solid rgba(128,128,128,.35)">' + esc(L[k]) + '</th>').join('') + '</tr></thead><tbody>';
    list.forEach(r => {
      h += '<tr><td style="padding:4px 6px;white-space:nowrap;vertical-align:top">' + esc(r.name) + '</td><td style="padding:4px 6px;vertical-align:top">'
        + (r.cli ? '<code style="font-size:11px">' + esc(r.cli) + '</code> <button type="button" class="howto-copy" data-howto-copy="' + esc(r.cli) + '" style="font-size:11px;cursor:pointer">' + esc(L.copy) + '</button>' : '-')
        + '</td><td style="padding:4px 6px;vertical-align:top">' + (r.gui ? esc(r.gui[gl] || r.gui.en) : '-') + '</td></tr>';
    });
    return h + '</tbody></table></div>';
  }
  // 窄版（入口頁任務卡）：每個來源一段，名稱、指令、網頁介面上下排列
  function listHtml(kinds, lang) {
    const L = t(lang), gl = guiLang(lang);
    const list = [].concat(...[].concat(kinds).map(rows));
    return '<div class="howto-hint" style="font-size:12px;opacity:.8;margin:4px 0 6px">' + esc(L.hint) + '</div><ul class="howto-list" style="list-style:none;margin:0;padding:0;font-size:12px">'
      + list.map(r => '<li style="padding:5px 0;border-top:1px dashed rgba(128,128,128,.3)"><b>' + esc(r.name) + '</b>'
        + (r.cli ? '<div><code style="font-size:11px;word-break:break-all">' + esc(r.cli) + '</code> <button type="button" class="howto-copy" data-howto-copy="' + esc(r.cli) + '" style="font-size:11px;cursor:pointer">' + esc(L.copy) + '</button></div>' : '')
        + (r.gui ? '<div style="opacity:.85">' + esc(L.gui) + '：' + esc(r.gui[gl] || r.gui.en) + '</div>' : '') + '</li>').join('') + '</ul>';
  }
  // ── 錯誤檔案判斷（XN53）：說出「這是什麼檔、為什麼不能用、該改拿什麼」──
  // f：{name, head（檔頭 Uint8Array，可省略）, text（已解碼文字）, error（讀 zip 的錯誤訊息，可省略）}
  const MAGIC = [
    ['pdf', [0x25, 0x50, 0x44, 0x46, 0x2d]], ['image', [0x89, 0x50, 0x4e, 0x47]], ['image', [0xff, 0xd8, 0xff]], ['image', [0x47, 0x49, 0x46, 0x38]],
    ['evtx', [0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65]], ['pcap', [0xd4, 0xc3, 0xb2, 0xa1]], ['pcap', [0xa1, 0xb2, 0xc3, 0xd4]], ['pcap', [0x0a, 0x0d, 0x0d, 0x0a]],
    ['archive', [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]], ['archive', [0x52, 0x61, 0x72, 0x21]], ['archive', [0x42, 0x5a, 0x68]], ['office', [0xd0, 0xcf, 0x11, 0xe0]],
  ];
  const EXT = [['pdf', /\.pdf$/i], ['office', /\.(docx?|xlsx?|pptx?|odt|ods)$/i], ['image', /\.(png|jpe?g|gif|bmp|webp|heic)$/i], ['evtx', /\.evtx$/i],
    ['pcap', /\.(pcap|pcapng|cap)$/i], ['archive', /\.(7z|rar|tar|tgz|bz2|xz)$/i]];
  function classify(f) {
    const name = String((f && f.name) || ''), head = f && f.head, text = String((f && f.text) || '');
    if (f && f.error === 'zipEncrypted') return 'zipEncrypted';
    if (f && f.error === 'zip64') return 'zip64';
    if (head && head.length) for (const [k, m] of MAGIC) if (m.every((b, i) => head[i] === b)) return k;
    for (const [k, re] of EXT) if (re.test(name)) return k;
    if (/^%PDF-/.test(text)) return 'pdf';
    if (/^ElfFile/.test(text)) return 'evtx';
    if (/\[Content_Types\]\.xml/.test(text.slice(0, 4096))) return 'office';
    if (!text.trim()) return 'empty';
    const s = text.slice(0, 4096);
    let bad = 0;
    for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c === 0 || c === 0xfffd) bad++; }
    return bad / s.length > 0.01 ? 'binary' : 'text';
  }
  const EX = {
    zhTW: { empty: '檔案是空的，或讀不到內容。', pdf: '這是 PDF 文件，不是設定檔或 log。請從設備匯出文字格式的設定或 log。',
      office: '這是 Office 文件（Word／Excel／PowerPoint）。請上傳設備匯出的原始文字檔，不要貼到文件裡再存檔。', image: '這是圖片，工具讀不了截圖。請從設備匯出文字格式的設定或 log。',
      evtx: '這是 Windows 二進位事件檔（.evtx），目前不支援。請用事件檢視器「另存所有事件」為 CSV，或用 wevtutil 匯出 XML。', pcap: '這是封包擷取檔（pcap），不是設定檔或 log。若要分析流量，請改用防火牆或 IDS 的 log。',
      archive: '這是 7z／rar／tar 等壓縮檔，請先解壓再上傳（.zip 與 .gz 可以直接上傳）。', zipEncrypted: '這個 zip 有密碼保護，請先解壓再上傳。', zip64: '這個 zip 太大（zip64 格式），請先解壓再上傳。',
      binary: '這個檔案不是文字檔（可能是備份檔或加密匯出），工具只讀得懂文字格式的設定與 log。', text: '看不出這是哪種設定檔或 log。請確認是完整的設定匯出，或手動選擇工具試試。' },
    en: { empty: 'The file is empty or could not be read.', pdf: 'This is a PDF document, not a config or log. Export the config or log from the device as text.',
      office: 'This is an Office document (Word/Excel/PowerPoint). Upload the raw text file exported from the device instead of pasting it into a document.', image: 'This is an image; screenshots cannot be read. Export the config or log from the device as text.',
      evtx: 'This is a binary Windows event file (.evtx), which is not supported. Use Event Viewer "Save All Events As" CSV, or export XML with wevtutil.', pcap: 'This is a packet capture (pcap), not a config or log. To analyze traffic, use firewall or IDS logs instead.',
      archive: 'This is a 7z/rar/tar archive. Extract it first (.zip and .gz can be uploaded directly).', zipEncrypted: 'This zip is password-protected. Extract it first.', zip64: 'This zip is too large (zip64). Extract it first.',
      binary: 'This is not a text file (it may be a backup or encrypted export). The tools only read text configs and logs.', text: 'Could not tell which config or log this is. Make sure it is a full config export, or pick a tool manually.' },
    ja: { empty: 'ファイルが空か、内容を読み取れません。', pdf: 'これは PDF 文書で、設定ファイルやログではありません。機器から設定やログをテキスト形式でエクスポートしてください。',
      office: 'これは Office 文書（Word／Excel／PowerPoint）です。文書に貼り付けず、機器からエクスポートしたテキストファイルをそのままアップロードしてください。', image: 'これは画像で、スクリーンショットは読み取れません。機器から設定やログをテキスト形式でエクスポートしてください。',
      evtx: 'これは Windows のバイナリイベントファイル（.evtx）で、対応していません。イベント ビューアーで CSV として保存するか、wevtutil で XML をエクスポートしてください。', pcap: 'これはパケットキャプチャ（pcap）で、設定やログではありません。通信を分析するにはファイアウォールや IDS のログを使ってください。',
      archive: 'これは 7z／rar／tar などの圧縮ファイルです。先に展開してください（.zip と .gz はそのままアップロード可）。', zipEncrypted: 'この zip はパスワード保護されています。先に展開してください。', zip64: 'この zip は大きすぎます（zip64）。先に展開してください。',
      binary: 'テキストファイルではありません（バックアップや暗号化エクスポートの可能性）。ツールはテキスト形式の設定とログのみ読み取れます。', text: 'どの設定ファイルやログか判別できません。設定全体のエクスポートか確認するか、ツールを手動で選んでください。' },
  };
  function explain(kind, lang) { const L = EX[guiLang(lang)] || EX.en; return L[kind] || L.text; }
  // 該看哪一種取得方式
  function howtoKinds(kind) { return kind === 'evtx' ? ['log'] : ['fw', 'sw', 'log']; }
  // 展開頁面上的取得檔案說明並捲過去（工具頁「解析不出內容」時的連結）；sel 預設第一個 details[data-file-howto]
  function open(sel) {
    if (typeof document === 'undefined') return;
    const el = document.querySelector(sel || 'details[data-file-howto]');
    if (!el) return;
    if (el.tagName === 'DETAILS') el.open = true;
    setTimeout(() => el.scrollIntoView({ block: 'start' }), 50);
  }
  function title(lang) { return t(lang).title; }
  // 工具頁：<details data-file-howto="fw,sw"> 由各頁 setLang() 呼叫 FileHowto.render(語言) 填入（保留展開狀態）
  function render(lang) {
    if (typeof document === 'undefined') return;
    document.querySelectorAll('details[data-file-howto]').forEach(el => {
      const kinds = el.getAttribute('data-file-howto').split(',').filter(k => KINDS[k]);
      el.innerHTML = '<summary style="cursor:pointer;font-size:12px">' + esc(title(lang)) + '</summary>' + tableHtml(kinds, lang);
    });
  }
  if (typeof document !== 'undefined') {
    document.addEventListener('click', e => {
      const b = e.target && e.target.closest ? e.target.closest('[data-howto-copy]') : null;
      if (!b) return;
      const txt = b.getAttribute('data-howto-copy'), lang = (typeof window !== 'undefined' && (window._lang || window.currentLang)) || 'zhTW';
      const done = () => { const old = b.textContent; b.textContent = t(lang).copied; setTimeout(() => { b.textContent = old; }, 1200); };
      try { navigator.clipboard.writeText(txt).then(done, () => {}); } catch (err) { /* 不支援剪貼簿時使用者可自行選取 */ }
    });
  }
  return { rows, tableHtml, listHtml, title, render, open, classify, explain, howtoKinds, T, EX, KINDS: Object.keys(KINDS) };
})();
if (typeof window !== 'undefined') window.FileHowto = FileHowto;
