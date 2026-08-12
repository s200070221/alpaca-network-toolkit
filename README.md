# 🦙 Alpaca Network Toolkit（羊駝網管工具包）

多廠牌防火牆／交換器設定檔解析、匿名化、比對與產生工具組。純前端 JavaScript 實作，下載後即可離線執行，**所有解析與運算皆在瀏覽器本地端完成，設定檔內容不會上傳至任何伺服器**。

線上體驗（無需下載）：**https://s200070221.github.io/alpaca-network-toolkit/**

或直接下載本 repo 後，用瀏覽器開啟 `network-analyzer.html`（六工具入口頁）。

## 工具一覽

| 工具 | 檔案 | 說明 |
|---|---|---|
| 🛡️ 防火牆設定分析器 | `firewall-analyzer-fixed.html` + `firewall-analyzer-*.js`（18 個模組檔） | 解析 FortiGate／Sophos XG／Check Point／Palo Alto／Juniper／pfSense／SonicWall／MikroTik／Cisco ASA/FTD／Zyxel USG-ATP／EdgeRouter (EdgeOS)／OpenWrt (UCI) 等 13 家廠牌設定檔，視覺化規則、路由、VPN、位址物件；支援設定檔格式互轉與稽核。9 家廠牌（FortiGate／Palo Alto／Juniper／SonicWall／MikroTik／Sophos／Check Point／pfSense／EdgeRouter）的政策規則已支援 IPv4/IPv6 位址分類，FortiGate 另支援 IPv6 政策/NAT66/靜態路由；FortiGate／Juniper／Palo Alto／EdgeRouter／MikroTik 5 家另支援介面次要IP（Secondary IP）解析 |
| 🔀 交換器設定解析器 | `switch-config-parser.html` | 解析 HPE Comware／Cisco IOS-XE／NX-OS／Aruba CX／ProCurve／FortiSwitch／Juniper／Extreme／Alcatel／Brocade-ICX／Dell OS10／Arista／MikroTik RouterOS／Ruijie RGOS／Netgear M4300／Ubiquiti EdgeSwitch 等 16 家廠牌，視覺化 Port/VLAN/路由/堆疊拓撲。Comware／Cisco IOS-XE／Arista／Aruba CX／Juniper／Dell OS10／Cisco NX-OS／Ruckus-Brocade ICX／Netgear M4300／FortiSwitch／SONiC／Ruijie RGOS／Alcatel OmniSwitch 共 13 家已支援 Interface/VLAN SVI 的 IPv6；Comware／Cisco IOS-XE／Aruba CX／FortiSwitch 4 家另支援介面次要IP（Secondary IP） |
| 🛠️ 交換器設定產生器 | `switch-config-generator.html` | 表單輸入產生上述廠牌的交換器設定指令，並支援反向匯入既有設定檔自動帶入表單。同上 13 家已支援輸出 Interface/VLAN SVI 的 IPv6 設定，4 家已支援輸出次要IP設定 |
| 🔒 設定檔去識別化工具 | `config-anonymizer.html` | 掃描並一致性替換設定檔中的 IP／主機名稱／密碼等敏感資訊，供分享/求助使用，支援 AES-256 加密還原對照表；IPv4/IPv6 皆完整支援 |
| 📜 Log 分析與去識別化工具 🧪實驗中 | `log-analyzer.html` | 匯入交換器/防火牆 log（CEF、LEEF、標準 Syslog RFC3164/RFC5424、FortiGate 原生 key=value），依嚴重程度排序並找出可能問題（頻率異常、掃描 heuristic），支援本機威脅情資清單比對（僅本機、不連網，含 IPv4/IPv6 CIDR）與敏感欄位去識別化，事件清單可正規化匯出為 CSV；`fetch_threat_intel.ps1` 為選用的獨立輔助腳本，在瀏覽器外下載並合併公開黑名單為單一檔案供匯入，工具本身仍維持不連網 |
| 🌐 六工具入口頁 | `network-analyzer.html` | 自動偵測拖入設定檔的廠牌並導向對應工具 |

> 部分工具的 JavaScript 已拆分成獨立 `.js` 檔（開發/除錯較方便），使用 `<script src>` 引入、非 ES module，因此 `file://` 雙擊開啟與 GitHub Pages 都能正常運作。**下載或分享這類工具時請連同對應 `.js` 檔一起、放在同一資料夾**，只複製單一 `.html` 會無法運作；建議直接下載整個 repo。如果需要純單一檔案版本（例如只想寄一個附件），執行 `build-standalone.ps1` 會在 `dist/` 產生合併回單檔的版本。

## 使用說明文件

`docs/` 資料夾內提供各工具的詳細使用說明（.docx）：[防火牆設定分析器](docs/firewall-analyzer-guide.docx)／[交換器設定解析器](docs/switch-config-parser-guide.docx)／[交換器設定產生器](docs/switch-config-generator-guide.docx)／[設定檔去識別化工具](docs/config-anonymizer-guide.docx)／[六工具入口頁](docs/network-analyzer-guide.docx)／[Log 分析與去識別化工具](docs/log-analyzer-guide.docx)。

## 特色

- **零伺服器、零安裝**：純 JS + HTML，下載即用，或直接透過 GitHub Pages 線上開啟
- **多語系**：繁體中文／English／日本語（另有多組隱藏彩蛋語言）
- **廣泛廠牌支援**：合計涵蓋 23 家網通設備廠牌的設定檔語法

## 授權與使用限制

本 repository **未提供任何開源授權（No License）**。原始碼與內容僅供瀏覽與個人評估使用，**不得複製、修改、再散布或用於商業用途**。如需授權使用，請自行聯繫作者。

This repository does **not** grant any open-source license. Content is provided for viewing and personal evaluation only — copying, modification, and redistribution are **not permitted** without explicit permission from the author.

## 免責聲明

本工具組所有匯出/產生之設定文字僅供參考，實際套用前請自行審閱並謹慎驗證，使用者需自行承擔風險。
