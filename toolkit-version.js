// 整套工具共用的版本號與「本版新增」（2026-10-21，第三十三輪 XN3）。
// 7 個頁面以 <script src="toolkit-version.js"> 載入；頁面放一個 data-toolkit-version 佔位元素，
// 切換語言時呼叫 renderToolkitVersion(lang)。版本號＝GitHub Release tag，發版時只改這個檔案：
// 把 TOOLKIT_VERSION 改成發版日期，CHANGELOG 最前面插入一筆（items 只寫 zhTW／en，其餘語言顯示 en）。
(function () {
  const TOOLKIT_VERSION = '2026.10.31';
  const CHANGELOG = [
    {
      version: '2026.10.31',
      items: {
        zhTW: [
          'log 分析：已知漏洞利用嘗試新增 19 條 2025～2026 年 CISA KEV 樣式（PAN-OS、Cisco ASA／FTD WebVPN、FortiWeb、UniFi OS、FortiSandbox、Ivanti EPMM、SharePoint ToolShell、SAP NetWeaver 等），只收網址本身看得出利用的樣式',
          '防火牆多台路徑查詢：可貼上 Juniper SRX 的 show route 輸出，取代設定檔的靜態路由（含 OSPF、BGP 等動態路由）',
        ],
        en: [
          'Log analyzer: 19 new exploit-attempt patterns for 2025–2026 CISA KEV entries (PAN-OS, Cisco ASA/FTD WebVPN, FortiWeb, UniFi OS, FortiSandbox, Ivanti EPMM, SharePoint ToolShell, SAP NetWeaver and more), only where the URL itself shows the exploit',
          'Firewall multi-device path query: paste Juniper SRX show route output to replace the static routes from the config (including OSPF, BGP and other dynamic routes)',
        ],
      },
    },
    {
      version: '2026.10.30',
      items: {
        zhTW: [
          '防火牆設定轉換：同時有 IPv4 與 IPv6 的規則只轉換 IPv4 並列出規則，僅 IPv6 的規則不再輸出成無法匯入的設定，遺失清單與注意事項會說明；轉換注意事項依介面語言顯示',
          '交換器分析：韌體落在已遭利用（CISA KEV）漏洞範圍時計入健康度、總覽結論與報告，結果列可直接前往韌體比對；修正 Dell OS9 被拿去比對 OS10 公告的誤判',
          '防火牆與交換器分析：新舊設定檔比對時直接列出這次變更的安全影響（新增、增加、減少、已解決的稽核項目與健康度變化）',
          '韌體漏洞比對支援 Check Point Gaia：補填「R81.20 Take 141」即可比對內建 KEV 清單',
          '入口頁綜合健檢標示哪幾台設備的韌體落在已遭利用漏洞範圍，健檢報告列出 CVE',
        ],
        en: [
          'Firewall conversion: dual-stack rules convert only the IPv4 part and are listed, IPv6-only rules are no longer output as configs that cannot be imported, and both are explained in the data-loss list and notes; conversion notes follow the UI language',
          'Switch analyzer: firmware in range of exploited (CISA KEV) vulnerabilities now counts toward health, the overview verdict and reports, with a result-bar link to the firmware check; fixed Dell OS9 being matched against OS10 advisories',
          'Firewall and switch analyzers: comparing old and new configs now shows the security impact of the change (new, increased, reduced and resolved findings and the health change)',
          'Firmware vulnerability check supports Check Point Gaia: enter "R81.20 Take 141" to match the built-in KEV list',
          'Home page health summary marks devices whose firmware is in range of exploited vulnerabilities, and the report lists the CVEs',
        ],
      },
    },
    {
      version: '2026.10.29',
      items: {
        zhTW: [
          '入口頁改以任務引導：先選「檢查設定、看 log、換設備、交給廠商前遮蔽」，並列出各廠牌怎麼從設備取得檔案；放錯檔案（PDF、Office、圖片、.evtx、封包檔、加密壓縮檔）時直接說明原因',
          '防火牆與交換器分析：分析完先看結論（健康度、先處理 3 件、下一步），稽核頁只先列有發現的項目，各處高風險數字統一',
          '防火牆分析：韌體落在已遭利用（CISA KEV）漏洞範圍時計入健康度、在結果列提示並列出 CVE；新增「優先處理」清單',
          '報告可直接交給主管：防火牆報告改淺色可列印、風險等級在地化，三個工具的報告都有「建議立即處理」',
          '設定轉換：防火牆轉換精靈（依目標型號對應埠、顯示每個埠的用途、轉換後驗證規則行為與安全稽核比對、下載轉換報告與埠對應表）；交換器可從分析頁直接轉成其他廠牌並帶入 LLDP／CDP 鄰居',
          'log 分析：新增管理介面從外部位址登入偵測（FortiGate、Cisco ASA）與 PAN-OS 新增管理者偵測；0 個問題時提示不代表安全',
          'eBGP 鄰居未設定進出過濾的稽核支援 FortiGate 與 Juniper（並修正 FortiGate BGP 鄰居解析）',
          '彩蛋改由右下角羊駝呈現，不再遮住畫面；副標改為白話說明；去識別化工具接到其他工具送來的內容時可直接執行',
        ],
        en: [
          'Home page now starts from tasks (check configs, check logs, migrate devices, mask before sharing) and shows how to get the file from each device; wrong files (PDF, Office, images, .evtx, packet captures, encrypted archives) get a clear explanation',
          'Firewall and switch analyzers: results open on a summary (health, top 3 fixes, next steps), audit pages list findings first, and high-risk counts now match everywhere',
          'Firewall analyzer: firmware in range of known exploited (CISA KEV) vulnerabilities now counts toward health, is flagged in the result bar with CVEs, and leads a new "Fix first" list',
          'Reports ready for managers: the firewall report is now light and printable with localized risk levels, and all three tools\' reports include "Recommended for immediate action"',
          'Config conversion: firewall conversion wizard (port mapping by target model, port usage, rule-behavior and security-audit comparison after conversion, conversion report and port map download); switches can be converted to another vendor straight from the analyzer with LLDP/CDP neighbors',
          'Log analyzer: new detection of management logins from external addresses (FortiGate, Cisco ASA) and of new PAN-OS admins; zero findings now notes that this does not mean safe',
          'The eBGP neighbor filtering check now covers FortiGate and Juniper (and FortiGate BGP neighbor parsing is fixed)',
          'Easter eggs now come from the alpaca in the corner instead of covering the page; subtitles use plain language; the anonymizer can run right away on content handed over from other tools',
        ],
      },
    },
    {
      version: '2026.10.28',
      items: {
        zhTW: [
          '韌體漏洞比對：內建清單改為 CISA KEV＋重大廠商公告，補上 FortiOS 2026-10-22 修補版、PAN-OS PHP2Shell、Juniper／NX-OS／Arista／Aruba CX／Dell OS10 近期公告與 Cisco ASA 項目，並新增 MikroTik RouterOS 與 Dell OS10 版本比對',
          '交換器分析：安全稽核頁也能比對韌體漏洞；新增管理連線未限制來源、未記錄指令與設定變更、eBGP 鄰居未設定進出過濾、存取埠未啟用迴圈偵測等稽核項目',
          '防火牆分析：新增 FortiGate 管理者密碼仍為 SHA256 舊雜湊、未啟用 private-data-encryption 稽核；pfSense／OPNsense 漏洞卡片提醒 PHP2Shell 修補',
          'log 分析：新增分散式密碼噴灑、MFA 推播疲勞、網路設備新增管理者帳號等偵測，並補上相關紀錄的去識別化',
          'log 分析：VPN 成功登入來自代管業者網段或商用 VPN 位址時列出；DNS／proxy 紀錄出現遠端管理工具（RMM）網域時提示，可設允許清單',
          '情資整理頁：新增代管業者 ASN、商用 VPN 位址（X4BNet、Mullvad）與 LOLRMM 遠端管理工具網域來源',
          '去識別化工具：新增設定檔外洩影響盤點，依類別列出被遮蔽的機密並提供處置清單',
          '修正 ProCurve 堆疊機型 1/1-1/24 埠範圍解析，並強化測試框架',
        ],
        en: [
          'Firmware vulnerability check: the built-in list now combines CISA KEV with critical vendor advisories, adding the FortiOS 2026-10-22 fixes, PAN-OS PHP2Shell, recent Juniper / NX-OS / Arista / Aruba CX / Dell OS10 advisories and Cisco ASA entries, plus MikroTik RouterOS and Dell OS10 version checks',
          'Switch analyzer: the security audit page also checks firmware vulnerabilities; new checks for unrestricted management access, missing command and change logging, eBGP neighbors without route filtering, and access ports without loop detection',
          'Firewall analyzer: new checks for FortiGate admin passwords still using the legacy SHA256 hash and for private-data-encryption not enabled; pfSense / OPNsense cards remind about the PHP2Shell fix',
          'Log analyzer: new detections for distributed password spraying, MFA push fatigue and admin accounts added on network devices, with matching anonymization fixes',
          'Log analyzer: flags successful VPN logins from hosting provider networks or commercial VPN addresses, and DNS / proxy records hitting remote management (RMM) tool domains with an allow list',
          'Threat intel builder: new sources for hosting provider ASNs, commercial VPN addresses (X4BNet, Mullvad) and LOLRMM remote management tool domains',
          'Config anonymizer: new leak impact inventory that lists masked secrets by category with an action checklist',
          'Fixed ProCurve stacked port ranges such as 1/1-1/24 and hardened the test harnesses',
        ],
      },
    },
    {
      version: '2026.10.25',
      items: {
        zhTW: [
          '防火牆分析：多台路徑查詢第二階段，可貼上各台路由表（9 種輸出格式）與手動串接對應表，並換算 FortiGate／ASA／FTD／netfilter／MikroTik 的來源 NAT',
          '防火牆分析：高風險曝險服務稽核，找出開在外部介面的 FortiGate／Palo Alto／ASA／FTD／Juniper 管理介面與 VPN 入口並附 CISA KEV 範例 CVE；FortiGate 依管理者 trusthost 判斷是否已限制來源',
          '交換器分析：Cisco Smart Install 與 IOS-XE Web UI 對外曝險檢查',
          '防火牆／交換器分析：韌體版本比對已知漏洞，內建近年 CISA KEV 起始清單並標示情資截止日（只標受影響、不標安全），也可匯入自備 CSV',
          'log 分析：偵測 web 存取紀錄中的已知漏洞利用嘗試（20 種，CVE 皆在 CISA KEV），IDS 告警的 CVE 顯示在依據欄',
          '安全強化：修正多處原型污染、去識別化跨頁訊息限定同源、產生器上傳程式顯示 SHA-256 與警語、CI 供應鏈強化',
          '彩蛋：設定檔裡藏了注入測試字串時，羊駝會出來吐槽一下（不影響分析結果）',
        ],
        en: [
          'Firewall analyzer: multi-firewall path query phase 2 accepts pasted routing tables (9 output formats) and a manual link map, and translates source NAT for FortiGate / ASA / FTD / netfilter / MikroTik',
          'Firewall analyzer: exposed high-risk services audit flags FortiGate / Palo Alto / ASA / FTD / Juniper management and VPN portals on external interfaces, with example CISA KEV CVEs; FortiGate admin trusthost is taken into account',
          'Switch analyzer: exposure checks for Cisco Smart Install and IOS-XE Web UI',
          'Firewall / switch analyzer: firmware version check against known vulnerabilities, with a built-in starter list of recent CISA KEV entries and its intel date (flags affected only, never safe), plus your own CSV',
          'Log analyzer: detects known exploit attempts in web access logs (20 patterns, all CVEs in CISA KEV); CVEs in IDS alerts are shown in the basis column',
          'Hardening: prototype-pollution fixes, same-origin-only postMessage for anonymizer checks, SHA-256 and a warning for generator uploads, CI supply-chain hardening',
          'Easter egg: if a config hides injection test strings, the alpaca has a word with you (analysis is unaffected)',
        ],
      },
    },
    {
      version: '2026.10.22.1',
      items: {
        zhTW: [
          '防火牆分析：多台防火牆路徑查詢，另外上傳路徑上各台設定，逐台判斷目的 NAT、路由與規則，找出流量經過哪幾台、在哪條規則被擋（第一階段，附限制警語與各廠牌查路由表指令）',
          '防火牆分析：匯入規則命中數後提出安全重排建議，只跨越確定不會比對到同一流量的規則；FortiGate 可下載 move 指令',
          '交換器分析：終端定位頁可貼上光模組 DOM（show interfaces transceiver），依裝置自帶門檻與旗標找出光功率、溫度等異常',
          '交換器產生器：產生結果可另存 Ansible playbook 或 Netmiko 腳本（不寫入帳密，Netmiko 預設只印出指令）',
          'log 分析：調查案件包，勾選問題與行為者匯出自含 HTML（時間軸、MITRE、處理狀態與備註，可去識別化）交接給資安團隊',
          'log 分析：辨識 OpenLDAP／389 DS／FreeRADIUS 服務本身的啟停、當機、資料庫與上游 RADIUS 異常，新增服務健康卡片與檢查指令，並依來源建議一併匯入的 log',
          '網頁版開過一次後斷網也能使用，並可安裝成桌面 App',
        ],
        en: [
          'Firewall analyzer: multi-firewall path query; upload every firewall on the path and each device is checked for destination NAT, route and rule to show which devices traffic crosses and where it is blocked (phase 1, with limitation warnings and per-vendor routing-table commands)',
          'Firewall analyzer: safe rule reorder suggestions from imported hit counts, only moving past rules that can never match the same traffic; FortiGate move commands can be downloaded',
          'Switch analyzer: paste transceiver DOM output (show interfaces transceiver) on the endpoint page to find optics out of range, judged by the device\'s own thresholds and flags',
          'Switch generator: save the result as an Ansible playbook or a Netmiko script (no credentials stored; the Netmiko script only prints commands unless run with --apply)',
          'Log analyzer: investigation case pack exporting selected issues and actors as a self-contained HTML file (timeline, MITRE, status and notes, optionally de-identified) for handover',
          'Log analyzer: recognizes OpenLDAP / 389 DS / FreeRADIUS service start/stop, crashes, database and upstream RADIUS problems, with a service health card, check commands and suggestions for logs to import alongside',
          'The web version keeps working offline after one visit and can be installed as a desktop app',
        ],
      },
    },
    {
      version: '2026.10.22',
      items: {
        zhTW: [
          '交換器分析：終端定位頁可貼上 show interfaces／display interface，找出 CRC、碰撞、半雙工等實體層問題',
          '交換器分析：資產清冊可匯入自備的韌體支援期限（EoS／EoL）CSV，列出已過期或即將到期的設備',
          'log 分析：自訂規則可匯出 Sigma YAML，IOC 可匯出 STIX 2.1 與 MISP 格式',
          '交換器產生器：VLAN 卡片新增 VLSM 子網規劃，依主機數切子網並一鍵填入 VLAN、VRRP 與 DHCP',
        ],
        en: [
          'Switch analyzer: paste show interfaces / display interface output on the endpoint page to find CRC, collision, half-duplex and other physical-layer problems',
          'Switch analyzer: import your own firmware end-of-sale / end-of-support CSV on the inventory page to list expired or soon-to-expire devices',
          'Log analyzer: export custom rules as Sigma YAML and IOCs as STIX 2.1 or MISP',
          'Switch generator: VLSM subnet planner in the VLAN card carves subnets by host count and fills VLAN, VRRP and DHCP in one click',
        ],
      },
    },
    {
      version: '2026.10.21',
      items: {
        zhTW: [
          '第一個標註版本號的版本，之後每次更新都會在這裡列出新增內容',
          '所有頁面加上內容安全政策（CSP），由瀏覽器強制禁止工具把資料送到外部（情資整理頁抓取清單除外）',
          '交換器產生器：修復「下載 Word」一直無法使用的問題',
          'log 分析：支援 FreeRADIUS、OpenLDAP／389 DS 與更多 Windows log 格式，新增 AD 主機登入關係表與跨網域登入',
          '新增情資清單整理頁：勾選公開情資來源一鍵下載，整理成 log 分析可直接匯入的格式',
          '第一次使用體驗：各工具可一鍵載入範例、分析後顯示下一步提示列、貼錯工具時提示改用哪個工具',
        ],
        en: [
          'First release with a version number; future updates will be listed here',
          'All pages now ship a Content Security Policy, so the browser itself blocks the tools from sending data anywhere (except the threat-intel builder fetching lists)',
          'Switch Config Generator: fixed "Download Word", which never worked before',
          'Log Analyzer: FreeRADIUS, OpenLDAP / 389 DS and more Windows log formats; AD host logon map and cross-domain logons',
          'New threat-intel builder page: pick public intel sources, download them in one go and convert to the Log Analyzer import format',
          'First-run experience: one-click samples in every tool, a next-step bar after analysis, and a hint when a file belongs to another tool',
        ],
      },
    },
  ];
  // 標籤 12 語言（leet／uwu 等演算法語言與未列出的語言退回 en）
  const LABELS = {
    zhTW:   { whatsNew: '本版新增', title: '版本 {v} 更新內容', close: '關閉' },
    en:     { whatsNew: "What's new", title: 'What changed in {v}', close: 'Close' },
    ja:     { whatsNew: '更新内容', title: 'バージョン {v} の更新内容', close: '閉じる' },
    tlh:    { whatsNew: 'chu\' De\'', title: '{v} chu\' De\'', close: 'SoQmoH' },
    pirate: { whatsNew: 'New plunder', title: 'Plunder added in {v}, arr!', close: 'Belay that' },
    emoji:  { whatsNew: '🆕✨', title: '📦 {v} 🆕', close: '❌' },
    bureau: { whatsNew: '本版異動公告', title: '版本 {v} 異動事項公告', close: '結案歸檔' },
    cat:    { whatsNew: '本版新增喵', title: '版本 {v} 新玩具喵', close: '關掉喵' },
    bean:   { whatsNew: '本版新增豆', title: '版本 {v} 新長出的豆', close: '收豆' },
    alpaca: { whatsNew: '羊駝新貨', title: '羊駝 {v} 新草料咩', close: '回去吃草' },
    yanse:  { whatsNew: '又更新了', title: '{v} 又改了什麼，看看就好', close: '算了' },
    wuxia:  { whatsNew: '新練絕學', title: '第 {v} 卷新增武學', close: '收功' },
  };

  const lbl = lang => LABELS[lang] || LABELS.en;
  const itemsOf = (entry, lang) => entry.items[lang] || entry.items.en;
  // 只有 zhTW 用繁中內容；ja 與彩蛋語言之中，中文系彩蛋（bureau／cat／bean／alpaca／yanse／wuxia）也用繁中
  const contentLang = lang => (['zhTW', 'bureau', 'cat', 'bean', 'alpaca', 'yanse', 'wuxia'].includes(lang) ? 'zhTW' : 'en');

  let current = 'zhTW';
  function openDialog() {
    let dlg = document.getElementById('toolkit-whatsnew');
    if (dlg) dlg.remove();
    const L = lbl(current);
    dlg = document.createElement('dialog');
    dlg.id = 'toolkit-whatsnew';
    // margin:auto 必須明寫：各頁的 *{margin:0} 重設會蓋掉 <dialog> 預設置中
    dlg.style.cssText = 'margin:auto;max-width:560px;width:calc(100% - 32px);border:1px solid var(--border,#ccc);border-radius:10px;padding:18px 20px;' +
      'background:var(--surface,var(--card,#fff));color:var(--text,#222);font-size:14px;line-height:1.6';
    const h = document.createElement('h3');
    h.style.cssText = 'margin:0 0 10px;font-size:16px';
    h.textContent = L.title.replace('{v}', TOOLKIT_VERSION);
    const ul = document.createElement('ul');
    ul.style.cssText = 'margin:0 0 14px;padding-left:20px';
    for (const t of itemsOf(CHANGELOG[0], contentLang(current))) {
      const li = document.createElement('li');
      li.textContent = t;
      ul.appendChild(li);
    }
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = L.close;
    btn.style.cssText = 'float:right;padding:4px 14px;border:1px solid var(--border,#ccc);border-radius:6px;background:transparent;color:inherit;cursor:pointer';
    btn.addEventListener('click', () => dlg.close());
    dlg.append(h, ul, btn);
    document.body.appendChild(dlg);
    dlg.showModal();
  }

  // 各工具支援廠牌數（XN52）：唯一來源是入口頁 TOOLS[].vendors 的清單長度（qa test_hub_tasks 比對），
  // 頁面文字寫 {n}，元素加 data-vendor-count="fw|sw|ca|gen|log" 後由 fillVendorCounts() 填入
  const TOOLKIT_VENDOR_COUNTS = { fw: 28, sw: 25, ca: 48, gen: 19, log: 51 };
  function fillVendorCounts() {
    if (typeof document === 'undefined') return;
    document.querySelectorAll('[data-vendor-count]').forEach(el => {
      const n = TOOLKIT_VENDOR_COUNTS[el.getAttribute('data-vendor-count')];
      if (n != null && el.textContent.indexOf('{n}') >= 0) el.textContent = el.textContent.split('{n}').join(String(n));
    });
  }
  function renderToolkitVersion(lang) {
    // 各頁 setLang() 先呼叫本函式才套用 data-i18n 文字，數字等目前這輪語言切換完成後再填
    setTimeout(fillVendorCounts, 0);
    if (lang) current = lang;
    const L = lbl(current);
    document.querySelectorAll('[data-toolkit-version]').forEach(el => {
      el.textContent = '';
      el.append(document.createTextNode(TOOLKIT_VERSION + ' · '));
      const a = document.createElement('a');
      a.href = '#';
      a.textContent = L.whatsNew;
      a.style.cssText = 'color:var(--accent,inherit);text-decoration:underline;cursor:pointer';
      a.addEventListener('click', e => { e.preventDefault(); openDialog(); });
      el.appendChild(a);
    });
  }

  window.TOOLKIT_VERSION = TOOLKIT_VERSION;
  window.TOOLKIT_CHANGELOG = CHANGELOG;
  window.renderToolkitVersion = renderToolkitVersion;
  window.TOOLKIT_VENDOR_COUNTS = TOOLKIT_VENDOR_COUNTS;
  window.fillVendorCounts = fillVendorCounts;
  // 頁面自己的 setLang 會再呼叫一次；這裡先依共用語言偏好畫出來
  document.addEventListener('DOMContentLoaded', () => {
    let lang = '';
    try { lang = localStorage.getItem('cw_lang') || ''; } catch (e) {}
    renderToolkitVersion(lang || 'zhTW');
  });
  // 離線使用（第三十三輪 XN2）：只在 https 且非本機開發主機時註冊 sw.js（GitHub Pages 或自架 https 站）；
  // file:// 與 localhost 不註冊，避免開發時讀到快取的舊模組。sw.js 不存在（工具各自的 result／dist 單檔）時註冊失敗、忽略
  if ('serviceWorker' in navigator && location.protocol === 'https:' && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname)) {
    window.addEventListener('load', () => { navigator.serviceWorker.register('sw.js').catch(() => {}); });
  }
})();
