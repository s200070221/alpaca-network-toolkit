# 🦙 Alpaca Network Toolkit（羊駝網管工具包）

多廠牌防火牆／交換器設定檔解析、匿名化、比對與產生工具組。純前端 JavaScript 實作，下載後即可離線執行，**所有解析與運算皆在瀏覽器本地端完成，設定檔內容不會上傳至任何伺服器**。

線上體驗（無需下載）：**https://s200070221.github.io/alpaca-network-toolkit/**

或直接下載本 repo 後，用瀏覽器開啟 `network-analyzer.html`（六工具入口頁）。

## 工具一覽

| 工具 | 檔案 | 說明 |
|---|---|---|
| 🛡️ 防火牆設定分析器 | `firewall-analyzer-fixed.html` + `firewall-analyzer-*.js`（25 個模組檔） | 解析 FortiGate／Sophos XG／Check Point／Palo Alto／Juniper SRX／pfSense／OPNsense／SonicWall／MikroTik／Cisco ASA/FTD／Zyxel USG-ATP／EdgeRouter (EdgeOS)／OpenWrt (UCI)／WatchGuard Firebox／VyOS／Linux iptables・nftables 設定檔，以及 AWS 安全群組／Azure NSG／Cisco Meraki MX（API 回應 JSON），共 18 種來源；視覺化規則、路由、NAT、VPN、位址物件，支援 IP／埠查詢、遮蔽分析、合規稽核與健康度評分、新舊（HA 主備）設定比對與設定檔格式互轉。FortiGate／Cisco ASA/FTD／Palo Alto／Juniper SRX 可另外貼上規則命中數，找出從未或長期未命中的規則 |
| 🔀 交換器設定解析器 | `switch-config-parser.html` + `switch-analyzer-*.js`（29 個模組檔） | 解析 HPE Comware／Cisco IOS-XE／NX-OS／Cisco Business (CBS/SG)／Aruba CX／ProCurve／FortiSwitch／Juniper EX/QFX／Extreme／Alcatel OmniSwitch／Ruckus-Brocade ICX／Dell OS10／Arista EOS／MikroTik RouterOS／Ruijie RGOS／Netgear M4300／Ubiquiti EdgeSwitch／SONiC／Planet／Allied Telesis AlliedWare Plus／NVIDIA Cumulus Linux (NVUE) 共 21 家廠牌，視覺化 Port/VLAN/路由/堆疊拓撲，另有安全稽核與健康度評分、設定比對、配線表與終端定位（MAC／ARP 表） |
| 🛠️ 交換器設定產生器 | `switch-config-generator.html` + `switch-generator-*.js`（23 個模組檔） | 表單輸入產生 18 家廠牌（Comware／FortiSwitch／Aruba CX／Cisco IOS-XE／Juniper／Dell OS10／NX-OS／Arista／Brocade ICX／Alcatel／Extreme／ProCurve／RouterOS／Ruijie／Netgear／EdgeSwitch／SONiC／Planet）的交換器設定，含 IPv6、次要IP、OSPF/OSPFv3、BGP、VRRP、ACL、QoS、堆疊等；支援 CSV 批次產生、設定模板庫，並可反向匯入既有設定檔帶入表單（也可從交換器設定解析器直接送過來） |
| 🔒 設定檔去識別化工具 | `config-anonymizer.html` | 支援 35 種防火牆／交換器／雲端設定格式，一致性替換 IP／主機名稱／帳號／密碼／金鑰／community／MAC 等敏感資訊，供分享或求助使用；可選擇保留網段結構（同網段換成同一個假網段，查詢與路由結果不變）、檢查去識別化前後結構是否一致，對照表可用 AES-256 加密保存以便還原；IPv4/IPv6 皆完整支援 |
| 📜 Log 分析與去識別化工具 🧪實驗中 | `log-analyzer.html` | 匯入交換器／防火牆／伺服器 log（CEF、LEEF、標準 Syslog RFC3164/RFC5424、FortiGate key=value、Cisco ASA、Cisco IOS／Comware 設備 log、Juniper SRX RT_FLOW、MikroTik、Linux iptables/nftables LOG、Windows 事件 XML 與 Sysmon、AWS VPC／Azure NSG 流量紀錄、IIS／Web 存取紀錄、JSON），依嚴重程度排序並找出可能問題（頻率異常、掃描、認證失敗、Kerberoasting、橫向移動、介面異常、MAC 飄移、跨事件攻擊鏈等，附 MITRE ATT&CK 編號），支援本機威脅情資與 ASN 清單比對（僅本機、不連網）、敏感欄位去識別化與 CSV／報表匯出；事件可一鍵帶到防火牆反查規則、介面異常可帶到交換器查看該埠。`fetch_threat_intel.ps1` 為選用的獨立輔助腳本，在瀏覽器外下載並合併公開黑名單為單一檔案供匯入，工具本身仍維持不連網 |
| 🌐 六工具入口頁 | `network-analyzer.html` | 自動偵測拖入設定檔的廠牌並導向對應工具 |

> 部分工具的 JavaScript 已拆分成獨立 `.js` 檔（開發/除錯較方便），使用 `<script src>` 引入、非 ES module，因此 `file://` 雙擊開啟與 GitHub Pages 都能正常運作。**下載或分享這類工具時請連同對應 `.js` 檔一起、放在同一資料夾**，只複製單一 `.html` 會無法運作；建議直接下載整個 repo。如果需要純單一檔案版本（例如只想寄一個附件），執行 `build-standalone.ps1` 會在 `dist/` 產生合併回單檔的版本。

## 使用說明文件

`docs/` 資料夾內提供各工具的詳細使用說明（.docx）：[防火牆設定分析器](docs/firewall-analyzer-guide.docx)／[交換器設定解析器](docs/switch-config-parser-guide.docx)／[交換器設定產生器](docs/switch-config-generator-guide.docx)／[設定檔去識別化工具](docs/config-anonymizer-guide.docx)／[六工具入口頁](docs/network-analyzer-guide.docx)／[Log 分析與去識別化工具](docs/log-analyzer-guide.docx)。

工具之間的串接（例如 log 分析帶到防火牆反查規則、帶到交換器查看介面，去識別化後轉送分析工具）與各自需要的前置作業，見 [工具串接說明](docs/tool-integration-guide.docx)。

## 特色

- **零伺服器、零安裝**：純 JS + HTML，下載即用，或直接透過 GitHub Pages 線上開啟
- **多語系**：繁體中文／English／日本語（另有多組隱藏彩蛋語言）
- **廣泛廠牌支援**：防火牆 18 種來源（含 AWS／Azure／Meraki 雲端）、交換器 21 家廠牌、去識別化 35 種設定格式

## 授權與使用限制

本 repository **未提供任何開源授權（No License）**。原始碼與內容僅供瀏覽與個人評估使用，**不得複製、修改、再散布或用於商業用途**。如需授權使用，請自行聯繫作者。

This repository does **not** grant any open-source license. Content is provided for viewing and personal evaluation only — copying, modification, and redistribution are **not permitted** without explicit permission from the author.

## 免責聲明

本工具組所有匯出/產生之設定文字僅供參考，實際套用前請自行審閱並謹慎驗證，使用者需自行承擔風險。
