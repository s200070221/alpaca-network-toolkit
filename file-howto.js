// ════════════════════════════════════════════════════════════════════════════
// file-howto.js — 怎麼從設備取得檔案（2026-10-29，XN52；主控在 network_analyzer/result，同步到防火牆、log 工具 result 與 public）
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
  return { rows, tableHtml, listHtml, title, render, T, KINDS: Object.keys(KINDS) };
})();
if (typeof window !== 'undefined') window.FileHowto = FileHowto;
