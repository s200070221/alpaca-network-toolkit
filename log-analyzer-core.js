// ============================================================
// [1] 中介格式與共用常數
// ============================================================
// 問題摘要多語化（2026-10-14）：偵測函式位於測試沙箱區段、無法呼叫 tr()，改另存 sampleTpl={key,p}；
// sampleRaw 以 SAMPLE_ZH（內容須與 LANG.zhTW 的 sample.* 相同，測試會比對）產生繁中版本供測試與舊資料，
// 畫面、報表與 CSV 由 issueSample() 依目前語言重新套版。參數值可為另一組 {key,p}；pre 參數非空時接上 sample.sep
const SAMPLE_ZH = {
  'sample.mtFwTamper': 'MikroTik {host} 的防火牆規則被 {who} 刪除或變更（{items}，{n} 次）；同設備 24 小時內外部登入來源：{src}。攻擊者取得管理權限後常移除防護規則，請確認是否為授權變更',
  'sample.mtUserChange': 'MikroTik {host} 的帳號被 {who} 新增或變更（{items}，{n} 次）；同設備 24 小時內外部登入來源：{src}。請確認是否為授權的帳號',
  'sample.mtPersistence': 'MikroTik {host} 的排程或腳本被 {who} 新增或變更（{items}，{n} 次）；同設備 24 小時內外部登入來源：{src}。遭入侵的 RouterOS 常以排程定期下載並執行腳本，請檢查內容',
  'sample.mtProxyEnable': 'MikroTik {host} 的 proxy／SOCKS 設定被 {who} 變更（{items}，{n} 次）；同設備 24 小時內外部登入來源：{src}。遭入侵的設備常被開啟 SOCKS 當成轉送跳板，請確認',
  'sample.mtServiceChange': 'MikroTik {host} 的管理服務設定被 {who} 變更（{items}，{n} 次）；同設備 24 小時內外部登入來源：{src}。可能放寬了 Winbox／API 等的允許來源，請對照目前的 /ip service 設定',
  'sample.riskyPortAllowed': '外部位址連到 {svc} 且紀錄為放行（{n} 次，來源 {srcs} 個：{ips}；目的 {dsts}；已遭利用漏洞：{cves}），這類服務不應對網際網路開放，請確認',
  'sample.riskyPortProbe': '外部位址探測 {svc}（{n} 次，來源 {srcs} 個：{ips}；目的 {dsts}；已遭利用漏洞：{cves}），紀錄為拒絕或看不出結果；設備只記錄部分放行流量時，請另外確認是否有放行',
  'sample.riskyPortSweep': '外部位址 {src} 在 1 小時內探測了 {n} 種高風險服務（{items}），符合針對已知漏洞服務的掃描樣式',
  'sample.svcCrash': '{svc}（主機 {host}）異常終止 {n} 次：{why}',
  'sample.svcCrashUnknown': '{svc}（主機 {host}）異常終止 {n} 次，log 未寫出原因',
  'sample.svcUnexpectedRestart': '{svc}（主機 {host}）在沒有停止紀錄的情況下重新啟動 {n} 次，可能曾當機但原因未記錄',
  'sample.svcDbError': '{svc}（主機 {host}）資料庫錯誤 {n} 次：{why}',
  'sample.svcDiskLow': '{svc}（主機 {host}）磁碟空間不足 {n} 次：{why}',
  'sample.svcBindFail': '{svc}（主機 {host}）無法監聽連接埠 {n} 次：{why}',
  'sample.svcResource': '{svc}（主機 {host}）資源不足或處理逾時 {n} 次：{why}',
  'sample.svcReplFail': '{svc}（主機 {host}）複寫失敗 {n} 次：{why}',
  'sample.svcBackendFail': '{svc}（主機 {host}）連不到後端 {backend} {n} 次：{why}',
  'sample.svcUpstreamDown': '{svc}（主機 {host}）的上游 RADIUS {home} 失去回應 {n} 次（標為 {state}），最後狀態 {last}',
  'sample.svcNoUpstream': '{svc}（主機 {host}）找不到可用的上游 RADIUS {n} 次：{why}',
  'sample.sep': '：',
  'sample.sshBruteSuccess': '{pre}{src} 失敗 {n} 次（{users}）後以 {user} 登入成功',
  'sample.adminLoginExternal': '{host}管理介面從外部位址 {src} 以 {user} 登入成功（{method}，之前失敗 {fails} 次）',
  'sample.adminLoginFailExternal': '{host}管理介面從外部位址登入失敗 {n} 次（來源 {srcs}；帳號 {users}）',
  'sample.vpnHostingLogin': '{user} 從代管業者網段 {asn} {name}（{ip}）成功登入 VPN（{src}）{n} 次',
  'sample.vpnAnonLogin': '{user} 從商用 VPN 位址 {ip} 成功登入 VPN（{src}）{n} 次（清單：{list}）',
  'sample.rmmTool': '{client} 連線遠端管理工具 {tool}（{list}）{n} 次',
  'sample.configChange': '{pre}{who}{from} 變更設定 {n} 次{last}',
  'sample.configChange_from': ' 從 {v}',
  'sample.configChange_last': '（最後一筆：{v}）',
  'sample.no_account': '（未記錄帳號）',
  'sample.webProbe': 'src={src} -> {n} 個不同路徑回應 404（Web 路徑探測）',
  'sample.exploitAttempt': '{src} 送出符合 {name}（{cve}）已知漏洞利用樣式的請求 {n} 次（目標 {host}），未見成功回應',
  'sample.exploitAttemptOk': '{src} 送出符合 {name}（{cve}）已知漏洞利用樣式的請求 {n} 次（目標 {host}），其中 {ok} 次回應 2xx，可能已利用成功，請檢查目標主機',
  'sample.dns': '{client} -> {text}：{names}',
  'sample.dnsDga': '{n} 個疑似演算法產生的網域',
  'sample.dnsNx': '{n} 個不同名稱查無此網域（NXDOMAIN）',
  'sample.dnsTunnel': '疑似 DNS tunneling（{reg}，{n} 個超長或大量子網域）',
  'sample.portScan': 'src={src} -> {n} 個不同 dst/dpt 組合',
  'sample.msgIps': 'host={host} 訊息內容出現 {n} 個不同 IP（文字擷取，非結構化欄位）',
  'sample.beacon': '{src} -> {dst}：{n} 筆事件，間隔變異係數 {cv}（週期約 {sec}s）',
  'sample.lateral': '{src} -> {n} 個不同主機成功登入（EventID 4624）',
  'sample.velocity': '{actor}：{min} 分鐘內出現於 {list}',
  'sample.offHours': '{actor}：非上班時間 {n} 筆高權限操作（最早 {time}，{kind}）',
  'sample.offHours_sudo': 'sudo 指令',
  'sample.unusualHour': '{actor}：{n} 筆事件落在前期不曾活動的時段（{hours}）',
  'sample.newSource': '{actor}：{n} 筆事件來自前期沒有出現過的來源（{sources}）',
  'sample.ldapBrute': '{src} 繫結失敗 {n} 次（{users}）',
  'sample.ldapBruteOk': '{src} 繫結失敗 {n} 次（{users}）後以 {user} 繫結成功',
  'sample.ldapPlainBind': '{src} 以 {user} 在未加密連線上簡單繫結 {n} 次（密碼為明碼）',
  'sample.ldapAnonBind': '{src} 匿名繫結 {n} 次',
  'sample.ldapEnum': '{src} 大範圍搜尋 {n} 次，共回傳 {entries} 筆（{base}）',
  'sample.passwordSpray': '{src} 對 {users} 個帳號認證失敗共 {n} 次（{list}）',
  'sample.mfaFatigue': '{user} 的 {app} MFA 連續 {n} 次被拒或未回應後隨即登入成功（{ip}）',
  'sample.appsmithOriginReset': '{src} 對 Appsmith 送出忘記密碼／驗證信請求 {n} 次（成功 {ok} 次），Origin 為 {origin}，與本站 {site} 不同，符合 CVE-2026-22794 的利用方式',
  'sample.appsmithResetFlow': '外部位址 {src} 申請 Appsmith 重設密碼 {req} 次後 1 小時內改密碼成功 {done} 次，請確認是否為帳號本人',
  'sample.appsmithResetFlowAdmin': '外部位址 {src} 申請 Appsmith 重設密碼後改密碼成功，30 分鐘內又存取管理 API {admin} 次，請確認是否為帳號本人',
  'sample.appsmithResetBurst': '{src} 在 1 小時內申請 Appsmith 重設密碼或驗證信 {n} 次',
  'sample.appsmithExternalRisky': '外部位址 {src} 對 Appsmith 執行高風險操作 {n} 次（成功 {ok} 次：{kinds}），內部工具不應從外部操作，請確認來源與版本是否已更新',
  'sample.appsmithScriptedUa': '{src} 以程式（{ua}）直接呼叫 Appsmith 高風險 API {n} 次（成功 {ok} 次：{kinds}），請確認是否為已知的自動化作業',
  'sample.appsmithScriptedNoUi': '{src} 沒有一般網頁操作紀錄就直接呼叫 Appsmith 高風險 API {n} 次（成功 {ok} 次：{kinds}），請確認是否為已知的自動化作業',
  'sample.credFileExposed': '{src} 成功下載密鑰檔 {n} 次（{files}），檔案內的密碼與金鑰應視為已外洩並更換',
  'sample.secretBulkRead': '{who} 在 1 小時內讀取 {n} 個不同機密（{app}；來源 {ips}），請確認是否為已知的部署或備份作業',
  'sample.cloudKeyMultiSource': 'AWS 長期存取金鑰 {key}（{user}）在 24 小時內從 {n} 個位址使用（{ips}），金鑰可能被複製到別處',
  'sample.sshKeyMultiSource': 'SSH 金鑰 {key}（帳號 {user}）在 24 小時內從 {n} 個來源登入（{ips}），金鑰可能被複製到別處',
  'sample.appCredentialAdded': 'Entra 應用程式 {app} 被 {who} 加上新的憑證或密碼 {n} 次，請確認是否為預期的變更',
  'sample.gitlabCiVarRead': '{user}（{src}）透過 API 讀取 GitLab CI/CD 變數，涉及 {n} 個專案或群組（{targets}），變數常含部署金鑰與資料庫密碼，請確認是否為預期作業',
  'sample.gitlabTokenMultiSource': 'GitLab 權杖 {key}（{user}）在 24 小時內從 {n} 個位址使用（{ips}），權杖可能被複製到別處',
  'sample.gitlabMassClone': '{user}（{src}）在 1 小時內下載 {n} 個 GitLab 專案的程式庫，請確認是否為預期作業',
  'sample.gitlabTokenCreated': '{by} 建立了 GitLab 個人存取權杖（編號 {id}）',
  'sample.gitlabTokenCreatedOther': '{by} 替其他帳號 {for} 建立了 GitLab 個人存取權杖（編號 {id}），請確認是否為預期作業',
  'sample.awsRootUsage': 'AWS root 帳號從 {src} 執行 {n} 次操作（{events}），root 只應用於少數必要作業，請確認是否為本人並檢查 MFA',
  'sample.awsConsoleNoMfa': '{user} 未使用 MFA 登入 AWS 主控台 {n} 次（來源 {ips}），密碼外洩時沒有第二道防線',
  'sample.esxiRemoteAccess': 'ESXi 主機 {host} 出現遠端存取變更：{items}，SSH 平常應關閉，請確認是否為維運人員操作',
  'sample.esxiDefenseOff': 'ESXi 主機 {host} 的防護設定被關閉：{items}，攻擊者常在加密前先關掉這些設定，請立即確認',
  'sample.esxiAccountChange': 'ESXi 主機 {host} 的帳號或權限被變更：{items}，請確認是否為授權的變更',
  'sample.esxiVmImpact': 'ESXi 主機 {host} 的虛擬機被大量操作：{items}，勒索軟體加密前常先關機並刪除快照，請確認備份與操作來源',
  'sample.webshellCmd': '{path} 的網址參數帶有系統指令或通道工具參數 {n} 次（來源 {srcs}），可能是 webshell，請檢查該檔案與主機',
  'sample.webshellUpload': '上傳／靜態檔目錄下的腳本 {path} 被成功執行 {n} 次（來源 {srcs}），這類目錄正常不應有可執行程式，請檢查是否被植入 webshell',
  'sample.webshellNewScript': '腳本 {path} 只被 {srcs} 以 POST 存取 {n} 次、沒有其他人開過，可能是被植入的 webshell，請確認檔案來源',
  'sample.dbAdminRemote': '{kind} 管理帳號 {user} 從 {src} 登入 {n} 次（資料庫 {dbs}），管理帳號通常只從本機或固定維運主機使用，請確認來源',
  'sample.dbExternalLogin': '{kind} 帳號 {user} 從外部位址 {src} 登入 {n} 次，資料庫通常不應直接對外，請確認來源與帳密是否外洩',
  'sample.dbNewSource': '{kind} 帳號 {user} 平常從 {base} 登入，這份 log 中出現新的來源 {src}，請確認是否為新增的應用程式主機',
  'sample.dbAuthFailBurst': '{kind} 帳號 {user} 在 1 小時內認證失敗 {n} 次（來源 {srcs}），可能是猜測密碼或應用程式設定錯誤',
  'sample.dbAuthFailThenOk': '{kind} 帳號 {user} 在 1 小時內認證失敗 {n} 次（來源 {srcs}）後登入成功，請確認是否為猜中密碼',
  'sample.promptInjection': '{src} 送出的 log 欄位含有針對 AI 的提示注入字串 {n} 次（{text}），把 log 或報告交給 AI 分析時，請勿讓 AI 照其中文字行事',
  'sample.appsmithExposed': 'Appsmith 可從 {n} 個外部位址連線（{srcs}），內部工具不應對外；若是刻意公開的應用，請確認版本已更新',
  'sample.npsReject': '{user} 在 1 小時內被 NPS 拒絕 {n} 次（{reasons}；RADIUS 用戶端 {nas}）',
  'sample.fmgUnregDevice': 'FortiManager {host} 加入了未註冊設備 {items}（{n} 次），這是 CVE-2024-47575（FortiJump）公布的入侵跡象之一，請依 Fortinet 公告確認是否為授權操作',
  'sample.vaultAuditDisabled': '{who} 從 {ips} 停用了 Vault 稽核裝置 {items}（{n} 次），停用後的操作不會再留下紀錄，請確認是否為授權操作',
  'sample.vaultRootUse': 'Vault 的 root token 從 {ips} 被使用或產生 {n} 次（{items}），root token 應只在緊急時產生並在用完後撤銷，請確認用途',
  'sample.veeamMalware': '{host} 的 Veeam 在備份中偵測到可能的惡意活動 {n} 次（{items}），請確認受影響的工作負載並避免從可疑還原點還原',
  'sample.veeamDefenseOff': '{host} 的 Veeam 防護設定被變更 {n} 次（{items}；帳號 {users}），攻擊者常在加密前先關閉備份防護，請確認是否為授權操作',
  'sample.veeamDeleteAttempt': '{host} 的 Veeam 有 {n} 次刪除備份的嘗試被擋下（{items}），可能有人想刪除不可變更的備份，請確認來源帳號',
  'sample.qnapSnapshotDelete': '{host} 的快照被 {user}（來源 {src}）手動刪除 {n} 次，勒索軟體加密前常先刪除快照，請確認是否為授權操作',
  'sample.qnapMassFileChange': '{user} 從 {src}（{conn}）在 10 分鐘內刪除或改名 {n} 個檔案（{host}），可能是用戶端中毒後加密共享資料夾，也可能是正常整理，請確認',
  'sample.vpnSessionMultiIp': '{vendor} {host} 的工作階段 {session}（{user}）在 1 小時內從 {n} 個位址使用：{ips}，可能是工作階段被他人重用，也可能是用戶端換網路，請確認',
  'sample.nsSessionMultiIp': '{host} 的工作階段 {session}（{user}）在 1 小時內從 {n} 個位址使用：{ips}，可能是工作階段被他人重用（CitrixBleed 類漏洞），也可能是用戶端換網路，請確認',
  'sample.npsRejectPolicy': '{user} 在 1 小時內被 NPS 拒絕 {n} 次（{reasons}；RADIUS 用戶端 {nas}），多為原則或設定不符，不是密碼錯誤',
  'sample.netAdminAdd': '{host}新增或提升管理者帳號 {acct}（權限 {priv}，操作者 {by}，來源 {ip}）',
  'sample.distributedSpray': '{srcs} 個外部來源對 {users} 個帳號認證失敗共 {n} 次，每個來源只試少數帳號（{list}）',
  'sample.rdpLogon': '{src} 以遠端桌面登入 {n} 次（帳號 {users}；主機 {hosts}）',
  'sample.cleartextLogon': '{user} 明碼網路登入（LogonType 8）{n} 次（{procs}）',
  'sample.adSensitiveChange': '{who} 變更 {obj} 的 {attr}',
  'sample.computerAccountCreated': '{who} 建立 {n} 個電腦帳號（{list}）',
  'sample.certIssued': '{who} 取得 {n} 張憑證',
  'sample.certIssuedSan': '{who} 取得 {n} 張憑證，其中 {san} 張的要求自行指定主體別名（SAN）',
  'sample.radiusUnknownClient': '未登記的設備 {src} 送來 {n} 個 RADIUS 請求',
  'sample.radiusBadSecret': '{src}（{nas}）共用密鑰不符 {n} 次',
  'sample.radiusTlsFail': 'EAP TLS 失敗 {n} 次：{why}（{users}）',
  'sample.radiusMacMultiUser': '終端 {mac} 以 {users} 等帳號認證共 {n} 次',
  'sample.radiusBlast': '{src} 送來缺少 Message-Authenticator 的 RADIUS 封包 {n} 次（BlastRADIUS 風險，設備需更新）',
  'sample.radiusBlastUnknown': 'RADIUS 伺服器收到缺少 Message-Authenticator 的封包 {n} 次（紀錄未寫出來源設備；BlastRADIUS 風險，設備需更新）',
  'sample.timeGap': '{from} 到 {to} 之間沒有任何紀錄（間隔 {dur}）',
  'sample.ldapUnsignedBindDc': '{src} 以 {user} 未簽章繫結網域控制站 {n} 次',
  'sample.ldapSimpleBindDc': '{src} 以 {user} 在未加密連線上簡單繫結網域控制站 {n} 次（密碼為明碼）',
  'sample.dcsync': '{who} 向網域控制站要求目錄複寫 {n} 次（{hosts}）',
  'sample.crossDomainLogon': '{from} 網域帳號登入 {to} 網域主機 {n} 次（{users}；{hosts}）',
  'sample.winFailReasons': '{n} 筆 Windows 登入失敗，依原因（括號為帳號數）：{list}',
};
function renderSampleTpl(tpl, lookup) {
  if (!tpl || typeof tpl !== 'object') return tpl == null ? '' : String(tpl);
  const p = tpl.p || {};
  return String(lookup(tpl.key)).replace(/\{(\w+)\}/g, (m, k) => {
    if (!(k in p)) return m;
    const v = renderSampleTpl(p[k], lookup);
    return k === 'pre' && v ? v + lookup('sample.sep') : v;
  });
}
// 問題摘要依目前語言套版，沒有 sampleTpl 的問題沿用 sampleRaw；tr() 定義在 UI 區段，測試沙箱內沒有時用繁中
function issueSample(is) {
  if (!is.sampleTpl) return is.sampleRaw || '';
  return renderSampleTpl(is.sampleTpl, typeof tr === 'function' ? tr : k => SAMPLE_ZH[k]);
}
// 讀取上傳檔案（2026-10-14，JA）：開頭為 gzip 標記 1f 8b 時以瀏覽器內建 DecompressionStream 解壓
// （S3 上的 VPC Flow Logs／CloudTrail／ELB 紀錄、輪替後的 syslog 多為 .gz），其餘以 UTF-8 解碼；
// 解壓失敗丟出錯誤由呼叫端提示。gzipFileLabel() 顯示名稱去掉 .gz
// 多個 gzip 成員串接（cat a.gz b.gz > all.gz）時 Chromium 的 DecompressionStream 會拒絕，
// 失敗時依成員檔頭（1f 8b 08）切開逐段解壓；檔頭位元組也可能出現在壓縮資料中，該處解壓失敗就繼續往後找
async function gunzipText(buf) {
  const one = b => new Response(new Blob([b]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  try { return await one(buf); } catch (e) {
    const parts = [];
    let start = 0;
    for (let i = 1; i + 2 < buf.length; i++) {
      if (buf[i] !== 0x1f || buf[i + 1] !== 0x8b || buf[i + 2] !== 0x08) continue;
      try { parts.push(await one(buf.subarray(start, i))); start = i; } catch (e2) { /* 不是成員邊界 */ }
    }
    if (!parts.length) throw e;
    parts.push(await one(buf.subarray(start)));
    return parts.join('');
  }
}
async function decodeLogBytes(buf) {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) return gunzipText(buf);
  // 依 BOM 判斷 UTF-16（與 FileReader.readAsText 相同行為），其餘 UTF-8
  const enc = buf[0] === 0xff && buf[1] === 0xfe ? 'utf-16le' : (buf[0] === 0xfe && buf[1] === 0xff ? 'utf-16be' : 'utf-8');
  return new TextDecoder(enc).decode(buf);
}
// .zip（2026-10-14，第二十五輪 LC）：由檔尾的 End of Central Directory 找中央目錄，逐筆讀本地檔頭後的資料；
// 只支援不壓縮（method 0）與 deflate（method 8，DecompressionStream('deflate-raw')）。加密、zip64、其他壓縮方式
// 丟出 Error('zip…')，由呼叫端提示；資料夾與 macOS 的 __MACOSX／._ 附屬檔略過
function isZipBytes(buf) { return buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04; }
async function readZipEntries(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) { if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; } }
  if (eocd < 0) throw new Error('zipFormat');
  const count = dv.getUint16(eocd + 10, true), cdOff = dv.getUint32(eocd + 16, true);
  if (count === 0xffff || cdOff === 0xffffffff) throw new Error('zip64');
  const out = [];
  let p = cdOff;
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || dv.getUint32(p, true) !== 0x02014b50) throw new Error('zipFormat');
    const flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true);
    const nlen = dv.getUint16(p + 28, true), elen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true), loff = dv.getUint32(p + 42, true);
    const name = new TextDecoder('utf-8').decode(buf.subarray(p + 46, p + 46 + nlen));
    p += 46 + nlen + elen + clen;
    if (name.endsWith('/') || /(^|\/)__MACOSX\//.test(name) || /(^|\/)\._/.test(name)) continue;
    if (flags & 1) throw new Error('zipEncrypted');
    if (csize === 0xffffffff || loff === 0xffffffff) throw new Error('zip64');
    const start = loff + 30 + dv.getUint16(loff + 26, true) + dv.getUint16(loff + 28, true);
    const data = buf.subarray(start, start + csize);
    let bytes;
    if (method === 0) bytes = data;
    else if (method === 8) bytes = new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).arrayBuffer());
    else throw new Error('zipMethod');
    out.push({ name, bytes });
  }
  return out;
}
// 上傳檔案展開成 [{name,size,text}]：zip 內每個檔案各為一筆（名稱「壓縮檔/內部路徑」），其餘一個檔案一筆
async function readUploadEntries(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  if (!isZipBytes(buf)) return [{ name: gzipFileLabel(file.name), size: file.size, text: await decodeLogBytes(buf) }];
  const list = await readZipEntries(buf);
  const out = [];
  for (const e of list) out.push({ name: file.name + '/' + gzipFileLabel(e.name), size: e.bytes.length, text: await decodeLogBytes(e.bytes) });
  return out;
}
async function readTextFile(file) {
  return (await readUploadEntries(file)).map(e => e.text).join('\n');
}
function gzipFileLabel(name) {
  return String(name || '').replace(/\.gz$/i, '');
}
function sampleOf(key, p) {
  const tpl = { key, p };
  return { sampleRaw: renderSampleTpl(tpl, k => SAMPLE_ZH[k]), sampleTpl: tpl };
}
// CEF Severity（原生 0-10）→ 共用 5 級；CEF 官方慣例 0-3 Low／4-6 Medium／7-8 High／9-10 Very-High，
// 本工具把 Very-High 併入 Critical，避免共用尺度多出一級
function normCEFSeverity(sevRaw) {
  const n = Number(sevRaw);
  if (!Number.isNaN(n)) {
    if (n >= 9) return 'Critical';
    if (n >= 7) return 'High';
    if (n >= 4) return 'Medium';
    if (n >= 0) return 'Low';
  }
  // CEF 官方 spec 的 Severity 欄位同時允許數字（0-10）與文字詞彙（如 High/Medium/Low/
  // Very-High）兩種合法寫法，先前只做 Number() 轉換，文字型一律 NaN 直接退回 Info，
  // 真實使用文字型 severity 的來源會被系統性降級成最低關注度（2026-09 全功能審查發現）；
  // 沿用下方 SEV_WORD_MAP 既有詞彙表（於本函式之後宣告，但函式呼叫時機在整份 script
  // 執行完畢之後，const 已完成初始化，可安全參照）
  const s = String(sevRaw || '');
  for (const w of SEV_WORD_MAP) { if (w.re.test(s)) return w.level; }
  return 'Info';
}
// Syslog Severity（RFC5424/3164 共用 PRI 拆出的 0-7，0=Emergency...7=Debug）→ 共用 5 級
function normSyslogSeverity(sevRaw) {
  const n = Number(sevRaw);
  if (Number.isNaN(n)) return 'Info';
  if (n <= 2) return 'Critical';
  if (n === 3) return 'High';
  if (n === 4) return 'Medium';
  if (n <= 6) return 'Low';
  return 'Info';
}
// FortiOS level= 為官方固定 8 級文字列舉（emergency/alert/critical/error/warning/notice/
// information/debug），語意與 RFC5424 數字 0-7 嚴重度一一對應，換算成數字後直接重用
// normSyslogSeverity() 既有分桶邏輯，不另訂一套門檻
const FORTIGATE_LEVEL_NUM = { emergency: 0, alert: 1, critical: 2, error: 3, warning: 4, notice: 5, information: 6, debug: 7 };
function normFortiGateSeverity(sevRaw) {
  const n = FORTIGATE_LEVEL_NUM[String(sevRaw || '').toLowerCase()];
  return normSyslogSeverity(n === undefined ? NaN : n);
}
// JSON log 沒有統一嚴重度規格，各家詞彙差異很大；數字一律沿用 syslog 0-7 慣例（RFC5424/ECS
// log.syslog.severity.code 皆用此範圍，比 CEF 0-10 更常見於通用工具），文字則用常見詞彙比對，
// 兩者都比對不到時給最低關注度 Info（避免無依據臆測成高風險，寧可漏報不誤報）
const SEV_WORD_MAP = [
  { re: /emerg|critical|fatal/i, level: 'Critical' },
  { re: /alert|error|err\b|high/i, level: 'High' },
  { re: /warn|medium/i, level: 'Medium' },
  { re: /notice|info|low/i, level: 'Low' },
  { re: /debug|trace/i, level: 'Info' }
];
function normGenericSeverity(sevRaw) {
  if (sevRaw === undefined || sevRaw === null || sevRaw === '') return 'Info';
  const n = Number(sevRaw);
  if (!Number.isNaN(n)) return normSyslogSeverity(n);
  const s = String(sevRaw);
  for (const w of SEV_WORD_MAP) { if (w.re.test(s)) return w.level; }
  return 'Info';
}

