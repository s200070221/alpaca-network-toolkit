// 整套工具共用的版本號與「本版新增」（2026-10-21，第三十三輪 XN3）。
// 7 個頁面以 <script src="toolkit-version.js"> 載入；頁面放一個 data-toolkit-version 佔位元素，
// 切換語言時呼叫 renderToolkitVersion(lang)。版本號＝GitHub Release tag，發版時只改這個檔案：
// 把 TOOLKIT_VERSION 改成發版日期，CHANGELOG 最前面插入一筆（items 只寫 zhTW／en，其餘語言顯示 en）。
(function () {
  const TOOLKIT_VERSION = '2026.11.19';
  const CHANGELOG = [
    {
      version: '2026.11.19',
      items: {
        zhTW: [
          '交換器產生器：「批次套用」新增一鍵關閉未使用的埠（只關閉 access、沒有描述、VLAN 空白或 1 的埠），並列出沒有埠使用的 VLAN（只列出不刪除）',
          '交換器跨廠牌轉換：來源埠有 PoE 而目標型號或對應的埠沒有 PoE 時提示；常用機種的埠名稱、上行埠與 PoE 範圍已對照 NetBox 與原廠文件修正，無法查證者在標籤註明「未查證」',
          '防火牆轉換：依官方文件檢查物件與規則名稱長度、可用字元（FortiGate、Palo Alto、Cisco ASA、Zyxel、pfSense），只提示不自動改名；規則中的字面位址自動建成物件（h_／n_／r_ 開頭）',
          '防火牆轉換：多 VDOM 設定可一次轉完全部 VDOM，下載 zip（每個 VDOM 一個資料夾＋說明檔），並逐一讀回驗證規則結果',
          '防火牆轉換：目的 NAT（轉埠）修正 Juniper、Cisco ASA、pfSense、Sophos、Palo Alto、FortiGate、MikroTik 的輸出；無法表達者一律停用並註記待確認，轉換驗證會比對 NAT 是否遺失或範圍變大',
          '設定檔去識別化：修正沒有交接內容時頂端出現空白提示列',
        ],
        en: [
          'Switch generator: one-click shutdown of unused ports in batch apply (access ports with no description and VLAN blank or 1 only), plus a list of VLANs no port uses (listed, not deleted)',
          'Switch cross-vendor conversion: warns when a PoE source port maps to a target model or port without PoE; common models\' port names, uplinks and PoE ranges checked against NetBox and vendor documentation, unverifiable ones labeled "unverified"',
          'Firewall conversion: checks object and rule name length and allowed characters per vendor documentation (FortiGate, Palo Alto, Cisco ASA, Zyxel, pfSense), warning only; literal addresses in rules become objects automatically (h_/n_/r_ prefixes)',
          'Firewall conversion: multi-VDOM configs can convert every VDOM at once into a zip (one folder per VDOM plus a README), each read back and verified',
          'Firewall conversion: destination NAT (port forwarding) output fixed for Juniper, Cisco ASA, pfSense, Sophos, Palo Alto, FortiGate and MikroTik; anything inexpressible is disabled and marked for review, and verification checks for lost or widened NAT',
          'Config anonymizer: fixed an empty banner shown at the top when nothing was handed over',
        ],
      },
    },
    {
      version: '2026.11.18.1',
      items: {
        zhTW: [
          '內建漏洞清單更新至 2026-11-18：新增 Check Point Quantum Security Gateway 已遭利用漏洞 CVE-2026-123039（R81.20 Take 173 以前、R82 Take 130 以前、R82.10 Take 50 以前、R82.20 Take 10 以前）',
        ],
        en: [
          'Built-in vulnerability list updated to 2026-11-18: adds the exploited Check Point Quantum Security Gateway vulnerability CVE-2026-123039 (R81.20 up to Take 173, R82 up to Take 130, R82.10 up to Take 50, R82.20 up to Take 10)',
        ],
      },
    },
    {
      version: '2026.11.18',
      items: {
        zhTW: [
          '修正：防火牆轉成 MikroTik 時，沒有目的位址的目的 NAT 會變成沒有任何條件、把所有新連線導到內部主機；現在帶上來源的進入介面，連進入介面也沒有時輸出為停用並標註需人工確認；埠號不再輸出成 dst-port=-',
          '修正：去識別化下載結果後的「另外保存對照表」提醒被頁面蓋住看不到',
          '防火牆讀不到型號時選擇的型號，結果卡片固定顯示在稽核頁前面，並可改選',
          '修正：log 分析「建議一併匯入」的 ClearPass 來源標籤；交換器分析型號上限表在手機上的欄位間距',
        ],
        en: [
          'Fix: when converting a firewall to MikroTik, destination NAT without a destination address became a rule with no conditions that sent every new connection to the internal host; the source in-interface is now kept, rules with neither are output disabled and marked for review, and ports are no longer written as dst-port=-',
          'Fix: the anonymizer reminder to keep the mapping after downloading was hidden behind the page',
          'A firewall model picked manually (when the config has none) keeps its result card at the top of the audit page and can be changed',
          'Fix: ClearPass source label in the log analyzer\'s suggested logs; column spacing of the switch analyzer model-limit table on phones',
        ],
      },
    },
    {
      version: '2026.11.17.1',
      items: {
        zhTW: [
          '修正：產生器匯入的 VRF 靜態路由會變成全域路由；路由表新增 VRF 欄位，不支援 VRF 路由的廠牌改為不輸出並提示',
          '修正：LACP 成員名稱含空白（Ruijie、Planet、Ruckus、Dell OS9）時被拆開；NX-OS 不在介面表的成員埠遺失；Netgear 介面下一跳少了 interface 關鍵字',
          '產生器支援 IPv6 BGP 鄰居（Cisco、Arista、Ruijie、NX-OS、Juniper、Comware），依官方文件在 IPv6 位址家族啟用鄰居',
          '「匯入→產生→讀回」自動比對擴大到靜態路由、OSPF、BGP、LACP、VRRP 與 SVI 位址',
        ],
        en: [
          'Fix: VRF static routes imported into the generator became global routes; the route table now has a VRF column, and vendors that cannot output VRF routes leave them out with a tip',
          'Fix: LACP member names containing spaces (Ruijie, Planet, Ruckus, Dell OS9) were split apart; NX-OS members not in the interface table were lost; Netgear interface next hops lacked the interface keyword',
          'The generator supports IPv6 BGP neighbors (Cisco, Arista, Ruijie, NX-OS, Juniper, Comware), activating them in the IPv6 address family per the vendor documentation',
          'The automated import → generate → read-back comparison now also covers static routes, OSPF, BGP, LACP, VRRP and SVI addresses',
        ],
      },
    },
    {
      version: '2026.11.17',
      items: {
        zhTW: [
          '修正：ProCurve 與 RouterOS 產生器遺失 trunk 埠的 native VLAN（ProCurve 改為該 VLAN 的 untagged，RouterOS 改為 bridge port pvid＋untagged）',
          '產生器匯入既有設定檔更順：BGP／OSPF Router ID 改為選填（空白只提示）；描述與名稱頭尾的雙引號自動去除；RouterOS 主機名稱可含 + 與 .',
          '使用說明補上近期功能；新增「交換器分析範例匯入產生器後重新產生並讀回」的自動比對測試',
        ],
        en: [
          'Fix: the ProCurve and RouterOS generators lost the native VLAN of trunk ports (ProCurve now uses untagged in that VLAN, RouterOS uses bridge port pvid plus untagged)',
          'Smoother config import in the generator: BGP/OSPF Router ID is now optional (blank only shows a tip); surrounding double quotes in descriptions and names are removed; RouterOS hostnames may contain + and .',
          'User guides cover recent features; new automated test that imports switch analyzer samples into the generator, regenerates and reads them back',
        ],
      },
    },
    {
      version: '2026.11.16.1',
      items: {
        zhTW: [
          '型號上限更好用：產生器可只標記型號不重建介面表並說明上限與分組限制；防火牆讀不到型號時可手動選；交換器分析依 Aruba CX 版本前綴比對上限',
          '記住補填的韌體版本（選用，依主機名稱）；內建漏洞情資超過 30 天提醒；Aruba CX 自動讀取設定檔中的韌體版本',
          '去識別化：下載後提醒另外保存對照表；批次 zip 不再夾帶對照表（改為單獨匯出），避免整包寄出時原始資料外流',
          'log 工具兩段式關鍵字偵測可「帶入範例」（取自 SigmaHQ 規則）；TP-Link／D-Link 結果標示尚未以真實設定檔驗證',
          '防火牆轉換：Zyxel 依範圍查找物件並認得各廠牌內建服務；MikroTik 位址清單引用與目的 NAT 正確轉換；無法轉換而停用的規則加註記',
          '修正：匯入 5945 設定檔保留速率、CloudTrail root 去識別化後仍可偵測；新增防火牆轉換讀回與 log 去識別化前後比對的自動測試',
        ],
        en: [
          'Model limits are easier to use: the generator can tag a model without rebuilding the interface table and explains limits and port groups; the firewall audit lets you pick a model when none is found; the switch analyzer checks Aruba CX limits from the firmware prefix',
          'Remember filled-in firmware versions (optional, by hostname); warn when built-in vulnerability data is over 30 days old; Aruba CX firmware version is read from the config',
          'Anonymizer: reminds you to keep the mapping after downloading; the batch ZIP no longer bundles the mapping (export it separately) so original data is not sent along',
          'Log analyzer keyword watchlists can "Add examples" taken from SigmaHQ rules; TP-Link/D-Link results note they are not yet verified against real configs',
          'Firewall conversion: Zyxel resolves objects by scope and knows vendor built-in services; MikroTik address-list references and destination NAT convert correctly; rules disabled because they cannot be converted are annotated',
          'Fixes: importing a 5945 config keeps port speeds, CloudTrail root is still detected after anonymization; new automated tests for firewall conversion readback and log anonymization',
        ],
      },
    },
    {
      version: '2026.11.16',
      items: {
        zhTW: [
          '交換器分析新增 4 家：TP-Link JetStream、D-Link DGS、Zyxel GS／XGS、NVIDIA Onyx（依官方 CLI 手冊；入口頁判斷與去識別化同步支援）',
          '型號數量上限：Palo Alto 依官方型號比較頁、Juniper SRX 依官方 Policy Object 表；交換器產生器加入 Aruba CX 6000／6100／6200 與 HPE FlexFabric 5945（依官方文件）',
          '交換器產生器：5945 48SFP28 前面板每 4 個 SFP28 埠一組須同速率，改速率時同組連動並以 interface range 下 speed，介面名稱不變',
          'log 工具支援 Windows NPS 資料庫相容格式 log（逗號分隔），沿用 NPS 拒絕次數、同一終端多帳號等偵測與去識別化',
          'Zyxel 防火牆轉換依官方 CLI 手冊改用 object-group 位址／服務群組、FQDN 物件與 description，轉換結果可讀回驗證',
          '修正：Juniper 規則中「[ A B ]」多值清單未展開造成查詢誤判、型號上限名稱切割、產生器 SVI 計數未含 VRRP 列',
        ],
        en: [
          'Switch analyzer adds 4 vendors: TP-Link JetStream, D-Link DGS, Zyxel GS/XGS, NVIDIA Onyx (per official CLI references; hub detection and anonymizer updated)',
          'Model capacity limits: Palo Alto per the official model comparison data, Juniper SRX per the official policy object table; switch generator adds Aruba CX 6000/6100/6200 and HPE FlexFabric 5945 (per official documents)',
          'Switch generator: on the 5945 48SFP28, every 4 front-panel SFP28 ports form a group that must share one speed; changing speed updates the whole group and emits speed via interface range without renaming interfaces',
          'Log analyzer supports Windows NPS database-compatible (comma-separated) logs, reusing NPS reject burst, multi-account endpoint detection and anonymization',
          'Zyxel firewall conversion now uses object-group address/service groups, FQDN objects and description per the official CLI reference, and can be read back for verification',
          'Fixes: Juniper "[ A B ]" multi-value lists not expanded in queries, model-limit name splitting, generator SVI count missing VRRP rows',
        ],
      },
    },
    {
      version: '2026.11.14',
      items: {
        zhTW: [
          'FortiGate 型號與版本限制：小記憶體機種移除 SSL VPN／proxy 類功能、各機型 SSL VPN 與 Agentless VPN 支援，依官方文件比對設定檔使用的功能',
          'FortiGate 數量上限：依官方 Maximum Values 表比對位址、服務、規則、本機使用者等物件數量，稽核頁、報告與轉換精靈都會提示超過或接近上限',
          '防火牆轉換結果可下載匯入順序包（zip＋說明）：FortiGate、Cisco ASA、MikroTik、Zyxel 依相依順序分檔；Palo Alto、Juniper、EdgeRouter、pfSense、OpenWrt、FTD 附整份載入說明',
          'Check Point 轉換改輸出 Management API 指令（Gaia clish 只放系統設定），Sophos 另提供 XML API 匯入包；巢狀位址／服務群組依成員順序輸出',
          'Cisco ASA／FTD 轉換與稽核比對各型號的 VLAN 子介面上限；交換器產生器選 Cisco Catalyst 型號時比對 VLAN、SVI、STP 實例、ACL 與聚合埠規格上限',
          '修正：OpenWrt 規則引用未定義 zone 的查詢、Check Point／Sophos 規則中的字面位址與服務改建成物件、ASA 群組成員格式正規化',
        ],
        en: [
          'FortiGate model and version limits: checks features in the config against official notes (SSL VPN / proxy features removed on 2GB models, SSL VPN and Agentless VPN support by model)',
          'FortiGate maximum values: compares address, service, policy, local user and other object counts with the official Maximum Values table in the audit, report and conversion wizard',
          'Firewall conversions can be downloaded as an import-order package (zip + README): FortiGate, Cisco ASA, MikroTik and Zyxel split by dependency order; Palo Alto, Juniper, EdgeRouter, pfSense, OpenWrt and FTD include load instructions',
          'Check Point conversion now outputs Management API commands (Gaia clish only for system settings) and Sophos gets an XML API import package; nested address / service groups are ordered by membership',
          'Cisco ASA / FTD conversion and audit check VLAN subinterface limits per model; the switch generator checks VLAN, SVI, STP instance, ACL and port-channel limits for Cisco Catalyst models',
          'Fixes: OpenWrt queries for rules referencing undefined zones, Check Point / Sophos literal addresses and services become objects, ASA group member formats are normalized',
        ],
      },
    },
    {
      version: '2026.11.12.1',
      items: {
        zhTW: [
          '多台路徑查詢支援 IPv6：依各台設定檔的介面 IPv6 位址與 IPv6 靜態路由串接（FortiGate、Cisco ASA、Palo Alto、Juniper SRX、MikroTik、VyOS、EdgeRouter、TNSR）',
          'Cisco IOS 路由器的 Zone-Based Firewall 加入 self zone（到路由器本身的流量），管理介面曝險不再誤報被 self zone 擋掉的服務',
          '防火牆與交換器分析的韌體卡片可貼上 show version 類輸出，自動讀出完整版本並比對已知漏洞',
        ],
        en: [
          'Multi-device path tracing supports IPv6, chaining devices by interface IPv6 addresses and IPv6 static routes (FortiGate, Cisco ASA, Palo Alto, Juniper SRX, MikroTik, VyOS, EdgeRouter, TNSR)',
          'Cisco IOS router Zone-Based Firewall now evaluates the self zone (traffic to the router), so management services blocked by self-zone policy are no longer reported as exposed',
          'Firmware cards in the firewall and switch analyzers accept pasted show version output and read the full version for vulnerability matching',
        ],
      },
    },
    {
      version: '2026.11.12',
      items: {
        zhTW: [
          '防火牆分析支援 Cisco IOS／IOS-XE 路由器（介面 ACL、Zone-Based Firewall、NAT、路由與管理服務）；多台路徑查詢的來源 NAT 加入 Cisco IOS、Palo Alto 與 Juniper SRX；管理介面有來源限制時不再列為對外曝險',
          'log 分析可把可疑連線送到防火牆分析，依設定判斷放行或拒絕並標在問題清單與攻擊鏈；新增 RouterOS 入侵後行為與高風險服務埠偵測、Aruba ClearPass、PAN-OS 管理介面登入、Okta MFA 推播疲勞',
          'log 分析版面調整：分析前隱藏結果卡片、結果列固定在上方並有區段導覽、匯出收成一個選單',
          '交換器分析支援 Aruba CX 的介面錯誤計數器與光模組 DOM',
        ],
        en: [
          'Firewall analyzer supports Cisco IOS/IOS-XE routers (interface ACLs, Zone-Based Firewall, NAT, routes and management services); multi-device path source NAT adds Cisco IOS, Palo Alto and Juniper SRX; management services restricted by source are no longer listed as exposed',
          'Log analyzer can send suspicious connections to the firewall analyzer and mark whether the config allows or denies them in the issue list and attack chains; new RouterOS post-compromise and risky service port detections, Aruba ClearPass, PAN-OS admin logins and Okta MFA push fatigue',
          'Log analyzer layout: result cards hidden before analysis, sticky result bar with section navigation, exports grouped in one menu',
          'Switch analyzer supports Aruba CX interface error counters and optics DOM',
        ],
      },
    },
    {
      version: '2026.11.11',
      items: {
        zhTW: [
          'EdgeRouter、VyOS、OpenWrt、iptables／nftables 比照 MikroTik 依鏈的方式查詢（到設備本身與轉送分開、jump 展開、鏈尾預設動作），並檢查管理介面與 DNS 是否從 WAN 打得到、WAN 新連線是否可轉送到內部、UPnP 與沒有入口條件的目的 NAT',
          '路由器類設定轉成其他廠牌時依鏈展開，不再把鏈名當成介面，到設備本身的規則與只比對既有連線的規則改以警語列出',
          '健康度：路由器管理介面對 WAN 開放會扣分；只開放特定服務的規則不再算成 any-any；iptables 取反位址判斷修正',
        ],
        en: [
          'EdgeRouter, VyOS, OpenWrt and iptables/nftables are queried by chain like MikroTik (traffic to the device and forwarded traffic evaluated separately, jump expanded, chain default actions applied), with checks for management and DNS reachable from WAN, new WAN connections forwarded inside, UPnP and destination NAT without an entry condition',
          'Router configs are expanded by chain when converted to other vendors: chain names are no longer used as interfaces, and rules for traffic to the device and rules that only match existing connections are listed as caveats',
          'Health score: router management open to WAN now lowers the score; rules that allow only specific services are no longer counted as any-any; negated iptables addresses fixed',
        ],
      },
    },
    {
      version: '2026.11.10',
      items: {
        zhTW: [
          '防火牆分析支援 F5 BIG-IP（介面、路由、virtual server、AFM 規則、管理介面來源限制；摘要頁列出只分析的項目）；入口頁版本比對與去識別化也支援 BIG-IP',
          'MikroTik RouterOS 依 Linux netfilter 的方式查詢（input／forward 鏈、jump、介面清單、未命中即放行），新增路由器面檢查（WAN 打得到 Winbox／API／WebFig、DNS 開放解析、proxy／SOCKS、WAN 新連線轉送、排程下載等）與 hairpin NAT 檢查；支援 RouterOS 6.x 版本讀取與交換晶片 VLAN；只放行既有連線的規則不再算 any-any',
          'log 分析支援 Zscaler、HashiCorp Vault、ModSecurity、F5 Telemetry Streaming、Cisco Meraki、HPE Aruba CX、Stormshield、FortiMail／FortiManager；MikroTik 管理介面從外部位址登入會列出',
        ],
        en: [
          'Firewall analyzer supports F5 BIG-IP (interfaces, routes, virtual servers, AFM rules, management source restrictions; the summary page lists what is analyzed); the hub version check and the anonymizer also support BIG-IP',
          'MikroTik RouterOS queries follow Linux netfilter semantics (input/forward chains, jump, interface lists, accept when nothing matches); new router checks (Winbox/API/WebFig reachable from WAN, open DNS resolver, proxy/SOCKS, new WAN connections forwarded inside, scheduled downloads, etc.) and hairpin NAT checks; RouterOS 6.x versions and switch-chip VLANs are read; rules that only allow established connections no longer count as any-any',
          'Log analyzer supports Zscaler, HashiCorp Vault, ModSecurity, F5 Telemetry Streaming, Cisco Meraki, HPE Aruba CX, Stormshield and FortiMail/FortiManager; MikroTik admin logins from external addresses are listed',
        ],
      },
    },
    {
      version: '2026.11.07.1',
      items: {
        zhTW: [
          '入口頁新增「設備版本快速比對」：沒有設定檔也能輸入 NetScaler、FortiGate、Palo Alto 等 15 種韌體版本，與已遭利用漏洞清單離線比對；貼上 NetScaler ns.conf 會讀出版本並檢查管理介面與 Gateway 是否對外',
          'log 分析支援 WatchGuard Firebox（流量、IPS、管理與使用者認證、設定變更）與 Citrix NetScaler（VPN 登入、管理指令；新增同一工作階段從多個位址使用的偵測）',
          '去識別化支援 NetScaler ns.conf；內建漏洞清單新增 NetScaler 13 筆（CitrixBleed 系列等）',
        ],
        en: [
          'New device version quick check on the hub: without a config file, enter one of 15 firmware version formats (NetScaler, FortiGate, Palo Alto, etc.) and compare it offline with the exploited-vulnerability list; pasting a NetScaler ns.conf reads the version and checks whether management and Gateway are exposed',
          'Log analyzer supports WatchGuard Firebox (traffic, IPS, admin and user authentication, config changes) and Citrix NetScaler (VPN logins, admin commands; new detection for one session used from multiple addresses)',
          'Anonymizer supports NetScaler ns.conf; the built-in vulnerability list adds 13 NetScaler entries (CitrixBleed family and others)',
        ],
      },
    },
    {
      version: '2026.11.07',
      items: {
        zhTW: [
          '防火牆：目的是防火牆自己的位址時，依設定判斷管理來源限制（FortiGate local-in-policy、Palo Alto 允許來源、ASA http／ssh）',
          '隱私：交換器產生器的表單草稿不再暫存密碼、認證金鑰與 SNMP community；入口頁新增「本機儲存資料」，列出這個瀏覽器存了哪些資料並可清除',
          '易用性：去識別化依廠牌預設送往的工具；log 問題清單在手機改成卡片；手機寬度按鈕加大；產生器範例模式提示表單與結果位置；log 篩選與抑制收合；交換器分析 0 的統計卡排後',
        ],
        en: [
          'Firewall: when the destination is the firewall itself, management source restrictions are checked from the config (FortiGate local-in-policy, Palo Alto permitted IPs, ASA http/ssh)',
          'Privacy: the switch generator no longer keeps passwords, auth keys or SNMP communities in form drafts; the hub has a new "Data stored in this browser" panel to review and clear stored data',
          'Usability: the anonymizer sends to the matching analyzer by default; the log issue list shows as cards on phones; larger buttons on phones; generator sample mode points to the form and output; log filters and suppression are collapsed; zero-value switch summary cards move to the end',
        ],
      },
    },
    {
      version: '2026.11.06',
      items: {
        zhTW: [
          '維護版：程式註解與測試範例改用文件專用位址與通用名稱，功能與 2026.11.05.1 相同',
        ],
        en: [
          'Maintenance release: code comments and test samples now use documentation addresses and generic names; features are the same as 2026.11.05.1',
        ],
      },
    },
    {
      version: '2026.11.05.1',
      items: {
        zhTW: [
          '入口頁新增網站憑證檢查：下載 Windows／Linux／macOS 腳本抓取憑證鏈與 TLS 版本，在本頁離線檢查信任鏈、缺中繼、效期、主機名稱、多送的憑證與 CT 紀錄（內部根憑證只存記憶體）',
          '防火牆查詢：設定判斷與實測不符時列出可能原因（用戶端預設閘道不是這台、目的是防火牆自己的位址、沒有路由、回程不對稱等）與驗證指令；批次查詢不符的列可展開，命中數 0 的本機目的規則加註',
          '韌體漏洞比對支援 SonicWall SonicOS 版本格式',
        ],
        en: [
          'New website certificate check on the hub: download a Windows/Linux/macOS script to fetch the chain and TLS versions, then check trust chain, missing intermediates, validity, hostname, extra certificates and CT records offline (internal roots stay in memory)',
          'Firewall query: when real traffic differs from the rule result, lists possible causes (client gateway is not this firewall, destination is the firewall itself, no route, asymmetric return, etc.) with verification commands; mismatched batch rows can be expanded and zero-hit rules to local addresses are marked',
          'Firmware vulnerability check supports SonicWall SonicOS version format',
        ],
      },
    },
    {
      version: '2026.11.05',
      items: {
        zhTW: [
          '更好上手：log 分析完匯入區自動收合、問題清單直接出現在第一個畫面；大檔解析時顯示已解析行數',
          '交換器分析與防火牆頂端按鈕收成「匯出」「送到其他工具」兩個選單並附用途說明；貼上框按 Ctrl+Enter（⌘+Enter）直接分析',
          '去識別化提示還有幾行描述／備註未遮蔽，可一鍵遮蔽並重做；手機上羊駝不再跳出泡泡遮住按鈕；產生器的產生按鈕固定在底部',
        ],
        en: [
          'Easier to use: after analysis the log importer collapses so the issue list shows on the first screen; large files show how many lines have been parsed',
          'Switch analyzer and firewall top bars group Export and Send-to-tool into two menus with short descriptions; press Ctrl+Enter (⌘+Enter) in the paste box to analyze',
          'Anonymizer warns how many description/remark lines are still unmasked and can mask them in one click; on phones the alpaca no longer pops bubbles over buttons; the generator keeps its Generate button pinned at the bottom',
        ],
      },
    },
    {
      version: '2026.11.04.1',
      items: {
        zhTW: [
          'log 分析：偵測 webshell 存取跡象——網址參數帶系統指令、上傳目錄下的腳本被執行、只被少數來源 POST 的腳本（皆需人工確認）',
          'log 分析：偵測 VMware ESXi 可疑操作——SSH 被開啟或 root 遠端登入、防護設定被關閉、帳號與權限變更、虛擬機大量關機與刪除快照',
          '韌體漏洞比對：內建清單截止日更新；匯入 Ivanti Connect Secure log 時提醒依官方公告確認韌體修補',
        ],
        en: [
          'Log analyzer: detects signs of webshells — system commands in URL parameters, scripts executed from upload directories, and scripts used only via POST by a few sources (all need manual review)',
          'Log analyzer: detects suspicious VMware ESXi activity — SSH enabled or remote root logins, protections turned off, account and permission changes, and VMs mass powered off or snapshots removed',
          'Firmware vulnerability check: built-in list date refreshed; importing Ivanti Connect Secure logs now reminds you to confirm firmware patches against Ivanti advisories',
        ],
      },
    },
    {
      version: '2026.11.04',
      items: {
        zhTW: [
          'log 分析：支援 PostgreSQL／MySQL 連線與認證 log，列出管理帳號從其他主機登入、帳號從外部位址或新來源登入、認證失敗暴增後成功；支援 Ivanti Connect Secure／Pulse Secure VPN log',
          'log 分析：偵測到憑證可能外洩時列出「憑證處置清單」（要更換或撤銷的金鑰、權杖、帳號識別碼與處理位置，不含機密值），頁面、報告、Markdown 與案件包都有',
          '防火牆分析：列出特定來源可連網際網路任何位址、任何服務的允許規則（低風險、不計健康度，請確認是否為伺服器網段）；去識別化支援 .env 與 docker-compose 環境變數',
          '入口頁：新增「懷疑被入侵」任務卡，依序說明保全 log、分析、更換憑證與交給外部前遮蔽',
        ],
        en: [
          'Log analyzer: supports PostgreSQL/MySQL connection and authentication logs, flagging admin accounts logging in from other hosts, logins from external addresses or new sources, and bursts of failures followed by success; supports Ivanti Connect Secure / Pulse Secure VPN logs',
          'Log analyzer: when credentials may have leaked, a "credentials to rotate" list shows the key, token and account identifiers to replace or revoke and where to do it (no secret values), in the page, reports, Markdown and case packs',
          'Firewall analyzer: lists allow rules letting a specific source reach any internet address on any service (low risk, not in the health score — check whether it is a server network); the anonymizer supports .env and docker-compose environment variables',
          'Hub: new "Suspect a compromise" task card walking through preserving logs, analyzing, rotating credentials and masking data before sharing',
        ],
      },
    },
    {
      version: '2026.11.03.1',
      items: {
        zhTW: [
          'log 分析：可偵測 Appsmith 等內部工具遭入侵的跡象（重設密碼連結被導向他站、外部操作資料來源與管理設定、以程式直接呼叫高風險 API），並在匯入區說明要匯入哪些 log',
          'log 分析：可偵測憑證與密鑰外洩跡象——.env／.git 等密鑰檔被下載、雲端機密被大量讀取、同一把 AWS 或 SSH 金鑰從多個位址使用、Entra 應用程式被加上憑證；新增 AWS root 使用與主控台未用 MFA',
          'log 分析：支援 GitLab log，列出 CI/CD 變數讀取、權杖從多個位址使用、短時間大量下載程式庫與建立權杖；log 內出現針對 AI 的提示注入字串時提示',
          '安全強化：產生器上傳的分析頁雜湊不是官方版本時須確認才執行；Release 附建置來源證明（gh attestation verify）；工作區含設定內容時檔名標示並提醒；情資整理頁限制單一來源大小',
        ],
        en: [
          'Log analyzer: detects signs of intrusion through internal tools such as Appsmith (password-reset links redirected elsewhere, external operations on data sources and admin settings, scripted calls to high-risk APIs), and the import area explains which logs to collect',
          'Log analyzer: detects signs of credential and secret theft — secret files such as .env/.git downloaded, bulk reads of cloud secrets, one AWS or SSH key used from many addresses, credentials added to Entra applications; plus AWS root usage and console sign-in without MFA',
          'Log analyzer: supports GitLab logs, flagging CI/CD variable reads, tokens used from many addresses, bulk repository downloads and token creation; flags prompt-injection text aimed at AI inside logs',
          'Hardening: the generator only runs an uploaded analyzer page after confirmation unless its hash matches an official release; releases include build provenance (gh attestation verify); workspace exports with config content are labeled and warned; the threat-intel builder limits source size',
        ],
      },
    },
    {
      version: '2026.11.03',
      items: {
        zhTW: [
          'log 分析：支援 Windows NPS（RADIUS）記錄，同一帳號短時間多次被拒、同一終端用多個帳號認證都會列出，並可配合 DHCP 把帳號對應到 IP；調查案件包附外部位址、網域與雜湊清單',
          '韌體漏洞比對：漏洞需要的功能（如 SSL VPN、IOS-XE 網頁介面、SNMP）在設定檔確定沒啟用時，標示「設定未啟用受影響功能」且不扣健康度；交換器多設備清冊同樣適用',
          '防火牆分析：無線網路完全開放或 WEP、只用 TKIP 等舊式加密時列入稽核與健康度；去識別化支援 Windows NPS 設定匯出檔（共用密鑰會遮蔽）',
          '交換器分析：標示手機與筆電的隨機 MAC 並列出隨機 MAC 多的埠；介面描述寫的設備與 LLDP 實際鄰居不同時列出；情資整理頁顯示與上次整理的筆數增減',
          '畫面好讀度：log 先顯示問題清單與健檢分數、時間軸不再被沒有時間的事件拉長；「先處理」標題寫出共幾件；手機版頂端按鈕改單行滑動；切換語言時去識別化摘要與產生器檢查面板一起換語言',
        ],
        en: [
          'Log analyzer: Windows NPS (RADIUS) logs are supported — repeated rejects for one account and one device using several accounts are flagged, and accounts can be mapped to IPs via DHCP; investigation case packs now include external IPs, domains and hashes',
          'Firmware vulnerability check: when a vulnerable feature (e.g. SSL VPN, IOS-XE web UI, SNMP) is confirmed disabled in the config, the CVE is shown as "affected feature not enabled" and does not reduce the health score; also applies to the switch multi-device inventory',
          'Firewall analyzer: Wi-Fi SSIDs that are fully open, use WEP, or rely on legacy encryption such as TKIP are now part of the audit and health score; the anonymizer supports Windows NPS configuration exports (shared secrets are redacted)',
          'Switch analyzer: randomized phone/laptop MACs are marked and ports with many of them are listed; interface descriptions naming a different device than the actual LLDP neighbor are listed; the threat-intel builder shows count changes since the last run',
          'Readability: the log analyzer shows issues and the health score first, and the timeline is no longer stretched by events without a timestamp; "fix first" headings state the total; the mobile top toolbar is a single scrollable row; switching language now updates the anonymizer summary and generator check panel',
        ],
      },
    },
    {
      version: '2026.11.02',
      items: {
        zhTW: [
          '入口頁：捲到頁尾時頁尾的羊駝不再與右下角羊駝重疊（頁尾羊駝收進口袋面板的換裝區，連點三次切 Klingon 的彩蛋照常可用）',
        ],
        en: [
          'Hub page: the footer alpaca no longer overlaps the corner alpaca when scrolled to the bottom (it now lives in the pocket panel wardrobe; triple-clicking it still switches to Klingon)',
        ],
      },
    },
    {
      version: '2026.11.01',
      items: {
        zhTW: [
          '防火牆設定轉換：轉 FortiGate、Palo Alto、Juniper 時輸出 IPv6 位址物件、群組與規則，同時有 IPv4 與 IPv6 位址的規則拆成兩條；轉其他廠牌時不輸出 IPv6 並列出受影響的規則',
          '交換器分析：Cisco IOS／IOS-XE 的 SSH 開在非 22 埠、ACL 10／20／50 放行公網位址時列為「需人工確認」（依 CISA AA25-239A 描述的手法，不代表已遭入侵）',
          '內建韌體漏洞清單更新到 CISA KEV 2026-10-30（新增 Cisco ASA／FTD CVE-2026-76418）；Juniper 位址範圍與 FQDN 物件的各種寫法都能正確讀取',
        ],
        en: [
          'Firewall config conversion: IPv6 address objects, groups and rules are now written when converting to FortiGate, Palo Alto or Juniper; rules with both IPv4 and IPv6 addresses are split in two. Other targets skip IPv6 and list the affected rules',
          'Switch analyzer: Cisco IOS/IOS-XE SSH on a port other than 22 and ACL 10/20/50 permitting public addresses are flagged for review (patterns described in CISA AA25-239A; not proof of compromise)',
          'Built-in firmware vulnerability list updated to CISA KEV 2026-10-30 (adds Cisco ASA/FTD CVE-2026-76418); all forms of Juniper address ranges and FQDN objects are now read correctly',
        ],
      },
    },
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
  const TOOLKIT_VENDOR_COUNTS = { fw: 30, sw: 29, ca: 52, gen: 19, log: 70 };
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
