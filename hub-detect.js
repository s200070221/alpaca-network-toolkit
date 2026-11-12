// network-analyzer.html 拆出的模組（XN101）：拖放判斷：VENDOR_NAMES、detectTool()、命中規則說明。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// ── 拖入自動分派 ──────────────────────────────────────────────────
// 2026-08-09 稽核修復：新增 z/r/u/sonic 對應 detectTool() 新補的訊號規則，缺這幾項會讓
// `detected.vendor ? VENDOR_NAMES[detected.vendor] : null` 對這些 vendor code 求值出
// undefined（非 null），下游模板可能把字面 "undefined" 顯示在畫面上
const VENDOR_NAMES = {t:'Cisco FTD',netgearsmart:'Netgear Smart Managed Pro',voss:'Extreme VOSS / Fabric Engine',efos:'Broadcom EFOS',h3c:'H3C Comware',h:'H3C SecPath',e:'Netgate TNSR',b:'F5 BIG-IP',o:'Cisco IOS router',l:'Wireless LAN Controller',hpe:'HPE Comware',f:'FortiGate',s:'Sophos XG',c:'Check Point',p:'Palo Alto',j:'Juniper SRX',x:'pfSense',w:'SonicWall',m:'MikroTik',a:'Cisco ASA',arista:'Arista EOS',z:'Zyxel USG/ATP',r:'EdgeRouter (EdgeOS)',v:'VyOS',n:'Linux iptables/nftables',k:'AWS / Azure 安全群組',awsflow:'AWS VPC Flow Logs',azureflow:'Azure NSG／VNet Flow Logs',u:'OpenWrt (UCI)',sonic:'SONiC',cumulus:'NVIDIA Cumulus Linux',awplus:'Allied Telesis AlliedWare Plus',ciscobiz:'Cisco Business (CBS/SG)',g:'WatchGuard Firebox',
  // 2026-08-19 新增：log_analyzer 拖放偵測的格式標籤（非廠牌，沿用同一份對照表顯示於拖放
  // 提示 chip），key 與 detectTool() 回傳的 vendor 字串一致
  rfc5424:'Syslog RFC5424', meraki:'Cisco Meraki', stormshield:'Stormshield SNS', fortimail:'FortiMail', fortimanager:'FortiManager', cef:'CEF', leef:'LEEF', nps:'Windows NPS', clearpass:'Aruba ClearPass', dbfile:'PostgreSQL／MySQL', pcs:'Ivanti Connect Secure', nps_export:'Windows NPS 設定匯出', appenv:'.env／docker-compose', 'cef-syslog':'CEF-in-Syslog', asa:'Cisco ASA Syslog',kvfw:'SonicWall／Sophos Firewall Log',pancsv:'Palo Alto PAN-OS CSV',umbrella:'Cisco Umbrella CSV',elb:'AWS ELB Access Log',s3access:'AWS S3 Access Log',dnslog:'DNS 查詢紀錄',dhcplog:'DHCP 租約紀錄',winfw:'Windows 防火牆 log',vpnauth:'OpenVPN／strongSwan／FreeRADIUS log',squid:'Squid access.log',awsnfw:'AWS Network Firewall log',azfw:'Azure Firewall log',zeek:'Zeek Log (TSV)', fortigate:'FortiGate 原生 Log', rfc3164:'Syslog RFC3164', json:'JSON/NDJSON Log', winevent:'Windows Event Log',
  ciscoios:'Cisco IOS Log', comwarelog:'Comware Log', isosyslog:'Syslog（ISO 時間）', w3c:'IIS W3C Log', weblog:'Web Access Log', mikrotiklog:'MikroTik Log', ldap:'OpenLDAP／389 Directory Server log', radacct:'FreeRADIUS detail（radacct）'};
let _dropPending = null;
// 快速連續拖放/選檔的競態防呆：每次啟動新的 FileReader 讀取時遞增，onload 觸發時比對
// 是否仍是最新一次讀取的世代號，避免較舊、讀取較慢（如檔案較大）的結果晚於較新的讀取
// 完成，反而覆蓋畫面上顯示/寫入 _dropPending 的較新結果
let _dropGen = 0;

const LOG_JSON_KEYS = ['message','msg','severity','timestamp','@timestamp','log'];
// Cisco Secure Endpoint 事件 API 回應（{version, metadata, data:[事件…]}，事件有 event_type／computer／connector_guid），與 log_analyzer isCiscoAmpEvent() 一致
function _isAmpEvent(o) { return !!o && typeof o === 'object' && typeof o.event_type === 'string' && !!o.computer && o.connector_guid !== undefined; }
function _isLogJsonObj(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  if (o.data && (Array.isArray(o.data) ? o.data.length && o.data.every(_isAmpEvent) : _isAmpEvent(o.data))) return true;
  // 雲端身分／稽核紀錄（第十六輪 PF／PG）：Entra ID sign-in、Okta、Microsoft 365 稽核、Google Workspace Reports、
  // AWS CloudTrail（含 {"Records":[…]}），判斷與 log_analyzer cloudAuthInfo() 一致
  if (Array.isArray(o.Records) && o.Records.length && o.Records[0] && o.Records[0].eventSource && o.Records[0].eventName) return true;
  if ((/SignInLogs$/.test(String(o.category || '')) && 'resultType' in o) || (typeof o.eventType === 'string' && o.outcome && o.actor && o.published) ||
      (typeof o.Operation === 'string' && o.Workload && o.CreationTime) || (o.kind === 'admin#reports#activity' && o.id) ||
      (o.eventSource && o.eventName && o.eventTime && o.userIdentity)) return true;
  // Azure Activity Log、GCP Cloud Audit Logs（第二十輪 FE，與 log_analyzer cloudAuthInfo() 一致）
  if ((typeof o.operationName === 'string' && typeof o.resourceId === 'string' && o.time && 'resultType' in o) ||
      (o.protoPayload && /google\.cloud\.audit\.AuditLog$/.test(String(o.protoPayload['@type'] || '')) && o.timestamp)) return true;
  // Duo 驗證 log（第二十三輪 IF）：Admin API 回應或逐筆項目
  if ((o.response && Array.isArray(o.response.authlogs)) || (typeof o.txid === 'string' && typeof o.result === 'string' && typeof o.event_type === 'string')) return true;
  // Kubernetes 稽核 log（第二十三輪 ID）：單筆 Event 或 EventList
  if ((o.kind === 'Event' || o.kind === 'EventList') && /^audit\.k8s\.io\//.test(String(o.apiVersion || ''))) return true;
  // AKS 診斷 log 包裝的 Kubernetes 稽核（category kube-audit／kube-audit-admin）
  if (/^kube-audit(?:-admin)?$/i.test(String(o.category || '')) && o.properties && o.properties.log) return true;
  if (Array.isArray(o.records) && o.records.length && /^kube-audit/i.test(String((o.records[0] || {}).category || ''))) return true;
  // Microsoft Defender for Endpoint 告警／365 Defender 事件（第十八輪 TK，與 log_analyzer 判斷一致）
  if ((typeof o.title === 'string' && ('alertCreationTime' in o || 'creationTime' in o) && 'detectionSource' in o) || ('incidentId' in o && 'incidentName' in o && o.alerts && typeof o.alerts === 'object')) return true;
  // Windows 事件 JSON（第三十輪 WN1）：Winlogbeat／Elastic Agent 的 winlog.event_id、NXLog 的 EventID＋Channel＋SourceName
  if ((o.winlog && typeof o.winlog === 'object' && o.winlog.event_id !== undefined) || (o.EventID !== undefined && typeof o.Channel === 'string' && (o.SourceName !== undefined || o.ProviderGuid !== undefined))) return true;
  // Cloudflare Logpush（第二十六輪 SE，與 log_analyzer isCloudflareEvent() 一致）
  if (typeof o.RayID === 'string' && typeof o.ClientIP === 'string' && ('EdgeStartTimestamp' in o || 'Datetime' in o)) return true;
  // F5 BIG-IP Telemetry Streaming（XN119，與 log_analyzer isF5Telemetry() 一致）
  if (typeof o.telemetryEventCategory === 'string' && /^(?:LTM|ASM|AFM|APM)$/.test(o.telemetryEventCategory)) return true;
  // ModSecurity 稽核 log JSON（XN118，與 log_analyzer isModsecAudit() 一致：v3 transaction.messages、v2 audit_data＋request_line）
  if (o.transaction && typeof o.transaction === 'object' && ((o.transaction.request && 'messages' in o.transaction) || (o.audit_data && o.request && 'request_line' in o.request))) return true;
  // HashiCorp Vault 稽核 log（XN117，與 log_analyzer isVaultAudit() 一致）
  if ((o.type === 'request' || o.type === 'response') && o.request && typeof o.request.path === 'string' && 'auth' in o && o.time) return true;
  // Zscaler Internet Access NSS JSON（XN113，與 log_analyzer isZscalerNss() 一致）
  if (typeof o.sourcetype === 'string' && /^zscalernss-(?:web|fw|dns|audit)$/i.test(o.sourcetype) && o.event && typeof o.event === 'object') return true;
  // CrowdStrike Falcon Streaming API 事件（第十八輪 TJ）
  if (o.metadata && typeof o.metadata.eventType === 'string' && o.event && typeof o.event === 'object') return true;
  // Zeek JSON log（第十八輪 TI，與 log_analyzer isZeekLog() 一致）
  if (o.ts !== undefined && ('id.orig_h' in o || typeof o.uid === 'string' || typeof o.fuid === 'string' || typeof o._path === 'string' ||
      (typeof o.ts === 'number' && (typeof o.peer === 'string' || 'peer_descr' in o || Array.isArray(o.uids) || 'certificate.version' in o || (typeof o.src === 'string' && typeof o.dst === 'string'))))) return true;
  return _isAmpEvent(o) || LOG_JSON_KEYS.some(k => k in o);
}
function _isLogJsonHead(trimmed) {
  try { const d = JSON.parse(trimmed); return Array.isArray(d) && _isLogJsonObj(d[0]); } catch(e) { /* 不是單一 JSON 文件 */ }
  // 多個縮排物件前後相接的 CrowdStrike Falcon 串流匯出（第十八輪 TJ）
  if (/^\{\s*"metadata"\s*:\s*\{[^{}]*"eventType"\s*:/.test(trimmed) && /\n\s*"event"\s*:\s*\{/.test(trimmed)) return true;
  try { return trimmed.charAt(0) === '{' && _isLogJsonObj(JSON.parse(trimmed.split('\n')[0].trim())); } catch(e) { return false; }
}
const LOG_HEAD_SIGS = [
  // Stormshield SNS（XN122，與 log_analyzer SNS_LINE_RE 一致）
  [/^(?:<\d{1,3}>)?id=firewall time="\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}" fw="[^"]*" tz=[+-]\d{4}\s/m, 'stormshield'],
  // 第三十輪（與 log_analyzer 一致）：FreeRADIUS detail 檔（ctime 時間行後接縮排屬性）、389 Directory Server access log、
  // 事件檢視器 CSV 與 PowerShell Export-Csv 的 Windows 事件
  [/^[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4}\s*\n[ \t]+[A-Za-z][\w-]* = /m, 'radacct'],
  [/^\[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*[+-]\d{4}\] conn=\d+ |^[0-9a-f]{8}\.[0-9a-f]{8} (?:0x[0-9a-f]+ )?conn=\d+ /m, 'ldap'],
  [/^(?:Level|Keywords|層級|關鍵字),(?:Date and Time|日期和時間),(?:Source|來源),(?:Event ID|事件識別碼),/m, 'winevent'],
  [/^"?(?:Message|Id)"?,(?=[^\n]*"?ProviderName"?)(?=[^\n]*"?TimeCreated"?)/m, 'winevent'],
  [/^(?:<\d{1,3}>)?(?:\d+:\s+)?(?:[*.]?(?:(?:[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+)?\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Za-z]{2,5})?|\d+[ywdh]\d+[ywdhm](?:\d+[dhm])?)\s*:\s*)?%[A-Z][A-Z0-9_]*-\d-[A-Z0-9_]+:/m, 'ciscoios'],
  [/^(?:<\d{1,3}>)?%?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?::\d{1,3})?\s+\d{4}\s+\S+\s+(?:%%\d{2})?[A-Z][A-Z0-9_]*\/\d\/[A-Z0-9_]+(?:\([a-z]\))?:/m, 'comwarelog'],
  [/^(?:<\d{1,3}>)?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\s+\S+\s/m, 'isosyslog'],
  // Zeek TSV log（第十八輪 TI）：#separator 與 #fields 表頭（欄位以 Tab 分隔）
  [/^#separator\s[^\n]*\n(?:#[^\n]*\n)*#fields\t/m, 'zeek'],
  [/^#Software: Microsoft Windows Firewall/m, 'winfw'],
  // OpenVPN／strongSwan charon.log／FreeRADIUS radius.log 記錄檔（第二十三輪 IA～IC，與 log_analyzer vpnFileKind() 一致）
  [/^(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4}) (?:OpenVPN \d|(?:[^\s/]+\/)?[0-9A-Fa-f.:]+:\d+ (?:MULTI|TLS|VERIFY|\[|SIG))|^[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4} : (?:Auth|Info|Error|ERROR|Warning|WARNING|Proxy|Debug): |^(?:[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} )?\d{2}\[(?:IKE|CFG|NET|ENC|KNL|DMN|MGR|CHD|JOB|LIB|ASN|TLS|ESP|APP|IMC|IMV|PTS|TNC)\] /m, 'vpnauth'],
  // 雲端防火牆 log（第二十二輪 HE）：AWS Network Firewall（firewall_name＋event）、Azure Firewall 診斷 log（category）
  [/"firewall_name"\s*:\s*"[^"]*"[\s\S]{0,200}?"event"\s*:\s*\{/, 'awsnfw'],
  [/"category"\s*:\s*"(?:AzureFirewall\w+|AZFW\w+)"/, 'azfw'],
  // Squid 原生 access.log（第二十二輪 HD，與 log_analyzer SQUID_LINE_RE 一致）
  [/^\d{9,11}\.\d{3}\s+\d+\s+\S+\s+[A-Z_]+\/\d{3}\s+\d+\s+\S+\s+\S+\s+\S+\s+[A-Z_]+\/\S+\s+\S+\s*$/m, 'squid'],
  [/^#Fields:\s/m, 'w3c'],
  // DNS 伺服器查詢紀錄（第二十一輪 GA，與 log_analyzer BIND_FILE_RE／COREDNS_RE／WINDNS_RE 及 syslog 內 named／dnsmasq 訊息一致）
  [/^\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)? (?:[\w-]+: )*client |^\S+ \[(?:INFO|DEBUG|WARNING|ERROR)\] (?:\[[^\]]+\] )?\S+:\d+ - \d+ "\S+ \S+ \S+ \w+ |^\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}:\d{2}(?: [AP]M)? +[0-9A-Fa-f]+ +PACKET |\bnamed\[\d+\]: client (?:@0x[0-9a-f]+ )?\S+#\d+ |\bdnsmasq\[\d+\]: query\[\w+\] /m, 'dnslog'],
  [/^\s*Microsoft DHCP Service Activity Log|^ID,Date,Time,Description,IP Address,Host Name,MAC Address|\bdhcpd\[\d+\]: DHCP(?:ACK|OFFER|REQUEST|DISCOVER|RELEASE|DECLINE|NAK) |\bdnsmasq-dhcp\[\d+\]: (?:\d+ )?DHCP[A-Z]+\(/m, 'dhcplog'],
  // AWS S3 伺服器存取紀錄（第二十輪 FF）：64 位十六進位擁有者 ID、儲存貯體、[時間]
  [/^[0-9a-f]{64} \S+ \[\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] /m, 's3access'],
  [/^\S+ \S+ \S+ \[\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "/m, 'weblog'],
  [/^(?:<\d{1,3}>)?(?:(?:\d{4}-\d{2}-\d{2}|\d{2}-\d{2}|[A-Za-z]{3}\/\d{2}(?:\/\d{4})?)\s+)?\d{2}:\d{2}:\d{2}\s+[a-z][a-z0-9-]*(?:,[a-z][a-z0-9-]*)*,(?:critical|error|warning|info|debug)\b|^(?:<\d{1,3}>)?(?:(?:\d{4}-\d{2}-\d{2}|\d{2}-\d{2}|[A-Za-z]{3}\/\d{2}(?:\/\d{4})?)\s+)?\d{2}:\d{2}:\d{2}\s+(?:critical|error|warning|info|debug)(?:,[a-z][a-z0-9-]*)*\s/m, 'mikrotiklog'],
];
// 雲端安全群組 JSON 的欄位簽章（detectTool 與命中說明共用）
const AZURE_FLOW_RE = /"category"\s*:\s*"(?:NetworkSecurityGroupFlowEvent|FlowLogFlowEvent)"/;
// 與 log_analyzer parseAwsFlowLogs() 的判斷一致：第一行為含 srcaddr／dstaddr 的欄位名稱，或預設 v2 格式的一行
const AWS_FLOW_RE = /^(?:(?=[a-z][a-z0-9 -]*\bsrcaddr\b)(?=[a-z][a-z0-9 -]*\bdstaddr\b)[a-z][a-z0-9-]*(?: [a-z][a-z0-9-]*)+|\d+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \d+ \d+ (?:ACCEPT|REJECT|-) (?:OK|NODATA|SKIPDATA))\s*(?:\n|$)/;
const CUMULUS_RE = t => (/^\s*-\s+set:\s*$/m.test(t) && (/nvue-api-version/.test(t) || /^\s+(?:interface|bridge|system|router|vrf):\s*$/m.test(t))) ||
  /^nv set (?:interface|bridge|system|router|vrf|service) /m.test(t);
// Meraki MX Dashboard API 回應（L3 規則 destCidr、VLAN applianceIp、通訊埠轉送 publicPort），與 firewall_analyzer FW_VENDOR_SIGS.cloudsg 一致
const K8S_NETPOL_YAML_RE = /^\s*kind:\s*NetworkPolicy\b/m;
const CLOUD_SG_RE = /"(?:IpPermissions(?:Egress)?|(?:default)?[sS]ecurityRules)"\s*:\s*\[|"(?:destCidr|applianceIp|publicPort|NetworkAclId)"\s*:|"kind"\s*:\s*"compute#firewall"|"ruleCollections"\s*:\s*\[|"kind"\s*:\s*"compute#firewallPolicy"|"kind"\s*:\s*"NetworkPolicy"|"(?:ingress|egress)[-_]?[sS]ecurity[-_]?[rR]ules"\s*:\s*\[|"(?:source|destination)[-_]?[tT]ype"\s*:\s*"(?:CIDR_BLOCK|SERVICE_CIDR_BLOCK|NETWORK_SECURITY_GROUP)"/;
const EDGEROUTER_SIGS = [/ethernet\s+eth\d+\s*\{/m, /default-action\s+(drop|accept)/m, /outbound-interface\s+\S+/m, /address-group\s+\S+\s*\{/m, /UBNT|EdgeRouter|EdgeOS|EdgeMax/i];
function _isEdgeRouter(t) { return EDGEROUTER_SIGS.filter(r => r.test(t)).length >= 2; }
// Cisco IOS 路由器當防火牆（XN139），detectTool() 與 _detectToolReasons() 共用
const _isIosRouterFw = text => /^interface \S+/m.test(text) && !/^\s*switchport\b/m.test(text) && !/^feature \S+/m.test(text) && !/\bRGOS\b/.test(text) &&
  /^(?:version \d|hostname \S)/m.test(text) && (/^zone(?:-pair)? security \S+/m.test(text) || /^ip nat inside source /m.test(text) || /^ip inspect name /m.test(text));
function detectTool(text) {
  const t = text.slice(0, 8000);
  // Windows NPS 設定匯出（netsh nps export，XN72）：內含明碼 RADIUS 共用密鑰，只交給去識別化工具（與 config_anonymizer VENDOR_SIGS 相同）
  if (/<Microsoft_Internet_Authentication_Service\b|<Microsoft_Radius_Protocol\b/.test(t)) return {idx:2, vendor:'nps_export'};
  // 2026-08-09 稽核修復：SONiC（config_db.json 純 JSON，非文字 CLI）先前完全沒有偵測規則，
  // 拖放 SONiC 設定檔會落到「無法自動識別」；必須排在最前面（比照 switch_analyzer 自己
  // detectVendor() 的既有慣例，其餘廠牌皆為行首正則不可能以 "{" 開頭，零副作用）。注意：
  // 用完整 text 而非上面截斷到 8000 字元的 t——真實 config_db.json 常遠超 8000 字元，
  // 截斷後 JSON.parse 必定因不完整而失敗
  {
    const trimmedFull = text.trim();
    // Check Point Management API JSON（第十七輪 QG）：rulebase 回應含 objects-dictionary 與 access／nat 規則
    if (/^[\[{]/.test(trimmedFull) && /"objects-dictionary"\s*:/.test(text) && /"type"\s*:\s*"(?:access|nat)-(?:rule|section)"/.test(text)) return {idx:0, vendor:'c'};
    // 雲端安全群組 JSON（AWS describe-security-groups／Azure NSG，2026-10-02），訊號與 FW_VENDOR_SIGS.cloudsg 一致
    if (/^[\[{]/.test(trimmedFull) && CLOUD_SG_RE.test(text)) return {idx:0, vendor:'k'};
    // Kubernetes NetworkPolicy 的 YAML（kubectl -o yaml、官方範例），與 firewall_analyzer CloudSGParser 的 YAML 判斷一致
    if (K8S_NETPOL_YAML_RE.test(text)) return {idx:0, vendor:'k'};
    // Cumulus Linux NVUE（2026-10-02）：YAML 的 `- set:` 段或 nv set 指令，判斷式與 switch_analyzer isCumulusNVUE() 一致
    if (CUMULUS_RE(text)) return {idx:1, vendor:'cumulus'};
    // 雲端流量紀錄（2026-10-02）：Azure NSG／VNet flow logs 的 JSON 與 AWS VPC Flow Logs（預設格式或第一行欄位名稱）
    if (AZURE_FLOW_RE.test(text) && /"flowTuples"/.test(text)) return {idx:4, vendor:'azureflow'};
    if (AWS_FLOW_RE.test(trimmedFull)) return {idx:4, vendor:'awsflow'};
    if (trimmedFull.charAt(0) === '{') {
      try {
        const obj = JSON.parse(trimmedFull);
        if (obj && typeof obj === 'object' && obj.DEVICE_METADATA && (obj.VLAN || obj.PORT || obj.INTERFACE)) return {idx:1, vendor:'sonic'};
        // 2026-08-19 新增：單筆 JSON log 事件（log_analyzer 的 JSON/NDJSON 格式），須排在
        // SONiC 判斷之後（避免搶先攔截）但仍在所有文字 CLI 判斷式之前；僅在常見 log 欄位
        // 命中時才判定，避免任意 JSON 都被導向 log_analyzer
        if (_isLogJsonObj(obj)) return {idx:4, vendor:'json'};
      } catch(e) { /* 非合法 JSON，繼續往下走既有文字 CLI 判斷鏈 */ }
    }
    // 2026-10-01：多筆 NDJSON（每行一個物件，整段 JSON.parse 必定失敗）與 JSON 事件陣列原本
    // 都落到「無法自動識別」，改以第一行／第一個元素判斷，欄位條件與上方單筆事件相同
    if (_isLogJsonHead(trimmedFull)) return {idx:4, vendor:'json'};
  }
  // 2026-09 全功能審查發現：log_analyzer 已支援 Windows Event Log（wevtutil XML 匯出，
  // parseWinEventLogEvents() 判斷簽章），但這份獨立維護的拖放偵測規則從未同步補上，訊號
  // 逐字沿用該處判斷式；用完整 text 而非截斷到 8000 字元的 t，比照上方 SONiC 判斷式既有
  // 慣例（xmlns 屬性雖通常在檔案很前面，但避免真實大型匯出檔邊界情況漏判）
  if (/<Event[\s>][\s\S]*?xmlns=["']http:\/\/schemas\.microsoft\.com\/win\/2004\/08\/events\/event["']/.test(text)) return {idx:4, vendor:'winevent'};
  // Windows NPS DTS XML（XN65，與 log_analyzer NPS_DTS_RE 相同）：每行一筆 <Event><Timestamp data_type=…>，含 Packet-Type 或 Event-Source
  if (/^<Event><Timestamp data_type="\d+">[^<]*<\/Timestamp>.*<(?:Packet-Type|Event-Source) data_type=/m.test(t)) return {idx:4, vendor:'nps'};
  // Aruba ClearPass Syslog Export（XN134，與 log_analyzer CPPM_STD_RE／CPPM_5424_RE 相同）
  if (/^(?:<\d{1,3}>)?\s*\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d{3})? \S+ .+? \d+ \d+ \d+ (?:(?:Common|RADIUS|TACACS|WEBAUTH|CppmNode)\.[A-Za-z][\w\- ]*|event_source|session_id|mac_address|Timestamp)=/m.test(t) || /^<\d{1,3}>1 \S+ \S+ ClearPass .*\[clearPass@14823 /m.test(t)) return {idx:4, vendor:'clearpass'};
  // PostgreSQL／MySQL 伺服器 log 與 MySQL Enterprise Audit JSON（XN90，與 log_analyzer PG_FILE_RE／MYSQL_ERR_RE／MYSQL_GEN_RE／isMysqlAuditEvent 相同）
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? (?:[A-Z]{2,5}|[+-]\d{2}(?::?\d{2})?) \[\d+\]:?.*?\b(?:LOG|FATAL|ERROR|WARNING|NOTICE|INFO|PANIC|DETAIL|HINT|STATEMENT|LOCATION|CONTEXT|DEBUG[1-5]?):\s/m.test(t)
    || /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}) +\d+ \[(?:System|Warning|Note|ERROR|Error)\] /m.test(t)
    || /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\t\s*\d+ [A-Z][A-Za-z ]*?\t/m.test(t)
    || /^\{\s*"timestamp"\s*:\s*"[^"]*",\s*"id"\s*:\s*\d+,\s*"class"\s*:\s*"\w+",\s*"event"\s*:\s*"\w+",\s*"connection_id"\s*:/m.test(t)) return {idx:4, vendor:'dbfile'};
  // 2026-08-19 新增：log_analyzer 接上拖放派送（先前唯一沒接上此機制的工具）。log 格式
  // 判斷必須排在所有設定檔判斷式之前——RFC3164 syslog 訊息內文常含 "Interface
  // GigabitEthernet..." 這類交換器泛用 fallback（下方 idx:1 區塊）會誤判的字串，ASA
  // syslog 訊息內文也可能含 "access-list" 字樣與下方 idx:0 的 ASA 設定檔判斷式擦邊；
  // 訊號直接沿用 log_analyzer 自身 detectLineFormat() 的既有正則（改用 multiline 逐行
  // 掃描取代單行限定），維持兩邊判斷邏輯一致，非另外自創
  // Ivanti／Pulse Connect Secure（XN94，與 log_analyzer PCS_LINE_RE 相同）：須在 rfc5424 之前
  if (/^(?:<\d{1,3}>\d*\s?|[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ \d+ )\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})? \S+ PulseSecure: - - - /m.test(t)) return {idx:4, vendor:'pcs'};
  // Cisco Meraki（XN120，與 log_analyzer MERAKI_LINE_RE 相同）：RFC5424 外殼但時間為 epoch 秒
  if (/^<\d{1,3}>1 \d{9,11}\.\d+ \S+ [a-z][\w-]*(?: |$)/m.test(t))            return {idx:4, vendor:'meraki'};
  if (/^<\d{1,3}>1\s/m.test(t))                                              return {idx:4, vendor:'rfc5424'};
  if (/^(?:<\d{1,3}>\s*)?CEF:\d+\|/m.test(t))                                return {idx:4, vendor:'cef'};
  if (/^(?:<\d{1,3}>\s*)?LEEF:\d+(?:\.\d+)?\|/im.test(t))                    return {idx:4, vendor:'leef'};
  if (/^(?:<\d{1,3}>\s*)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+CEF:\d+\|/m.test(t)) return {idx:4, vendor:'cef-syslog'};
  if (/^(?:<\d{1,3}>\s*)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}:\s*%ASA-\d-\d+:/m.test(t)) return {idx:4, vendor:'asa'};
  // FortiMail／FortiManager（XN123，與 log_analyzer FML_LINE_RE／FMG_LINE_RE 一致）：欄位為 log_id
  if (/^(?:<\d{1,3}>)?date=\d{4}-\d{2}-\d{2},time=\d{2}:\d{2}:\d{2}(?:\.\d+)?,device_id=[^,]+,log_id=\d+,/m.test(t)) return {idx:4, vendor:'fortimail'};
  if (/^(?:<\d{1,3}>)?date=\d{4}-\d{2}-\d{2} time=\d{2}:\d{2}:\d{2} tz="?[+-]\d{4}"?\s[^\n]*\blog_id="?\d{10}"?/m.test(t)) return {idx:4, vendor:'fortimanager'};
  if (/^date=\d{4}-\d{2}-\d{2}\s+time=\d{2}:\d{2}:\d{2}\b/m.test(t) && /\blogid=/.test(t)) return {idx:4, vendor:'fortigate'};
  // FortiGate 經 syslog 送出時帶 <PRI>、6.4 起可能以 devname 開頭（第十五輪 VD，與 log 工具 detectLineFormat() 同一判斷）
  if (/^(?:<\d{1,3}>)?(?=[^\n]*\bdate=\d{4}-\d{2}-\d{2}\s)(?=[^\n]*\stime=\d{2}:\d{2}:\d{2}\b)(?=[^\n]*\blogid="?\d{10}\b)[a-z_]+=/m.test(t)) return {idx:4, vendor:'fortigate'};
  // 沒有 syslog 外殼的 PAN-OS CSV（第十五輪 VC，與 log 工具 PAN_CSV_LINE_RE 相同）
  if (/^\d+,(?:\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z),[^,]*,(?:TRAFFIC|THREAT|GLOBALPROTECT|USERID|HIPMATCH|HIP-MATCH|SYSTEM|CONFIG|DECRYPTION|AUTHENTICATION),/m.test(t)) return {idx:4, vendor:'pancsv'};
  // Cisco Umbrella CSV 匯出（第十五輪 VG）：DNS／Proxy／IP 為引號包住的「YYYY-MM-DD hh:mm:ss」開頭，Cloud Firewall 為不加引號時間＋[來源 ID]
  if (/^"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}","[^"\n]*","[^"\n]*","[^"\n]*","[^"\n]*","(?:Allowed|Blocked|\d+)"/m.test(t) ||
      /^"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}","[^"\n]*","[^"\n]*","[^"\n]*","[^"\n]*","[^"\n]*","(?:ALLOWED|BLOCKED)","\w+:\/\//m.test(t) ||
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\[\d+\],[^\n]*,(?:INBOUND|OUTBOUND),/m.test(t)) return {idx:4, vendor:'umbrella'};
  // AWS ELB 存取紀錄（第十六輪 PH，與 log_analyzer ELB_LINE_RE／NLB_LINE_RE 一致）：Classic／ALB／NLB
  if (/^(?:(?:https?|h2|grpcs|wss?) )?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z \S+ \S+:\d+ \S+ -?[\d.]+ -?[\d.]+ -?[\d.]+ (?:\d{3}|-) (?:\d{3}|-) \d+ \d+ "/m.test(t) || /^tls \S+ \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} net\/\S+ /m.test(t)) return {idx:4, vendor:'elb'};
  // SonicWall／Sophos Firewall 原生 key=value（log 工具 kvfw）
  if (/^(?:<\d{1,3}>)?(?:id=\S+\s+sn=\S+\s+time="|device="SFW"\s)/m.test(t)) return {idx:4, vendor:'kvfw'};
  // Cisco ASA／FTD 帶主機、時區或 EMBLEM 類別的表頭（行內出現 %ASA-／%FTD-等級-六位數訊息號）
  if (/^(?:<\d{1,3}>)?\s*[A-Z][a-z]{2}\s+\d{1,2}\s[^\n]*%(?:ASA|FTD)-(?:[a-z]+-)?\d-\d{6}:/m.test(t)) return {idx:4, vendor:'asa'};
  if (/^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s/m.test(t))            return {idx:4, vendor:'rfc3164'};
  // 2026-10-01：log_analyzer 後續新增的格式（WC／BA／BB 與 MikroTik）未同步到這裡——Cisco IOS／
  // Comware 設備 log 內文的 "Interface GigabitEthernet…" 會被下方交換器 fallback 規則攔截、誤送到
  // 交換器分析；其餘格式則判定為無法識別。判斷式逐字沿用 log_analyzer 的 CISCO_IOS_LOG_RE／
  // COMWARE_LOG_RE／ISO_SYSLOG_LINE_RE／WEB_ACCESS_RE／MikroTik topics 規則（去掉行尾擷取）
  for (const [re, v] of LOG_HEAD_SIGS) if (re.test(t)) return {idx:4, vendor:v};
  // RANCID 備份檔頭（第十七輪 QC）：第一行標明內容類型；juniper 可能是交換器或防火牆，交給下方規則判斷
  {
    const rc = ((t.match(/^[!#]RANCID-CONTENT-TYPE:\s*([\w-]+)/m) || [])[1] || '').toLowerCase();
    if (rc === 'paloalto') return {idx:0, vendor:'p'};
    if (rc === 'arista') return {idx:1, vendor:'arista'};
    if (rc === 'cisco-nx') return {idx:1, vendor:null};
  }
  // 真實錄製（Oxidized 等）在設定前常有數十行版本資訊，config firewall policy 會落在前 8000 字元之外，
  // 而 config system global 會被下方 FortiSwitch 規則攔截（第十三輪 NA）；FortiGate 的 config-version
  // 以 FG 開頭（FGT／FGVM／FG40F…），FortiSwitch 不是
  if (/^#config-version=FG/m.test(t) || /config firewall policy|config vdom/i.test(t)) return {idx:0, vendor:'f'};
  // H3C SecPath 防火牆（2026-10-05，KB）：security-policy 視圖＋security-zone，判斷式與 FW_VENDOR_SIGS.h3c 一致；
  // 須排在下方 Comware 交換器判斷之前（同為 sysname／display current-configuration 格式）。用完整 text，
  // 真實設定檔的 security-policy 常在 8000 字元之後
  if (/^\s*security-policy\s+ipv?6?\s*$/m.test(text) && /^\s*security-zone\s+name\s+\S+/m.test(text)) return {idx:0, vendor:'h'};
  // Netgate TNSR（2026-10-06，ML）：判斷式與 FW_VENDOR_SIGS.tnsr 一致（nacm＋dataplane、介面 ACL sequence、VPF、next-hop N via）
  if (/^nacm\s+(?:enable|disable|group\s)[\s\S]*^dataplane\s|^dataplane\s[\s\S]*^nacm\s+(?:enable|disable|group\s)/m.test(text) || /^[ \t]+access-list\s+(?:input|output)\s+acl\s+\S+\s+sequence\s+\d+/m.test(text) ||
      /^vpf\s+(?:filter\s+ruleset|options)\b/m.test(text) || /^[ \t]+next-hop\s+\d+\s+via\s/m.test(text)) return {idx:0, vendor:'e'};
  // F5 BIG-IP（XN116）：tmsh 頂層區塊至少 2 項，與 FW_VENDOR_SIGS.bigip、hub-devcheck.js isBigipConf() 一致
  if ([/^#TMSH-VERSION: /m, /^ltm (?:virtual|pool|node) \S+ \{/m, /^net self \S+ \{/m, /^net vlan \S+ \{/m, /^sys global-settings \{/m,
    /^auth user \S+ \{/m, /^sys (?:httpd|sshd|snmp) \{/m, /^sys management-ip /m, /Sys::Version/].filter(r => r.test(text)).length >= 2) return {idx:0, vendor:'b'};
  // 無線控制器（2026-10-05，KD／KH／KI）：判斷式與 FW_VENDOR_SIGS.wlc 一致，送到防火牆分析器的 WiFi 分析；
  // 須排在 Cisco IOS／Comware 交換器判斷之前（9800 為 IOS-XE、H3C WX 為 Comware 格式）
  if (/^(?:config\s+)?wlan\s+create\s+\d+\s+\S+/m.test(text) || /^\s*wlan\s+service-template\s+\S+/m.test(text) ||
      /^\s*wlan\s+ssid-profile\s+\S+/m.test(text) || /^wlan\s+\S+\s+\d{1,4}\s+\S+/m.test(text)) return {idx:0, vendor:'l'};
  // Extreme VOSS／Fabric Engine（2026-10-05，KG）：判斷式與 switch_analyzer isVOSS() 一致（config.cfg 檔頭 box type、vlan create … type port-mstprstp）
  if (/^#\s*box type\s*:\s*(?:VSP|XA|\d{4})/m.test(text) || /^vlan\s+create\s+[\d,\-]+(?:\s+name\s+"[^"]*")?\s+type\s+port-mstprstp\s+\d+/m.test(text) ||
      (/^boot config flags\s/m.test(text) && /^#\s*cli mode\s*:/m.test(text))) return {idx:1, vendor:'voss'};
  // Broadcom EFOS（2026-10-06，MM）：判斷式與 switch_analyzer isEFOS() 一致
  if (/^!System Description\s+"EFOS\b/m.test(text) || (/^!System Software Version\s+"/m.test(text) && /^serviceport\s+(?:ip|protocol)\b/m.test(text) && /^port-channel\s+name\s+\d+\/\d+\s/m.test(text))) return {idx:1, vendor:'efos'};
  // Netgear Smart Managed Pro（第十三輪 NC）：與 switch_analyzer isNetgearSmart() 一致；system name 會被下方 Alcatel 規則攔截
  if (/^SYSTEM CONFIG FILE ::= BEGIN\s*$/m.test(t) && /^!\s*System Description:\s*NETGEAR\b/mi.test(t)) return {idx:1, vendor:'netgearsmart'};
  // 2026-08-20 稽核修復：原本只認扁平 `set security policies` 語法，Junos 階層式大括號
  // 格式（`security { policies { from-zone X to-zone Y { ... } } }`，juniper_srx_test.conf
  // 真實範例即此格式）完全比對不到，會落穿到下方新增的交換器 Juniper 判斷式被誤判為
  // switch_analyzer（兩者皆用 Junos 階層式 interfaces{}/routing-options{} 頂層區塊，語法
  // 高度重疊，唯一可靠的區分點是 SRX 特有的 security zones/policies 概念，交換器沒有）
  if (/set security policies/i.test(t)||/^\s*from-zone\s+\S+\s+to-zone\s+\S+/m.test(t))    return {idx:0, vendor:'j'};
  if (/^set hostname\s+\S+/m.test(t) && /^set interface\s+\S+\s+ipv4-address/m.test(t)) return {idx:0, vendor:'c'};
  // Palo Alto：原本只認 PAN-OS XML 匯出（<config><devices>），比照 firewall_analyzer 自己的
  // FW_VENDOR_SIGS.paloalto 補上 flat "set" CLI 匯出格式（set deviceconfig system/set vsys），
  // 這是 firewall-analyzer-parser-paloalto.js 也支援、但先前完全沒被拖放偵測認出的格式
  // Panorama 匯出（KF）：開頭是 <mgt-config><devices/>，改以 device-group 判斷
  if (/<config\b[^>]*>[\s\S]{0,300}<devices>/m.test(t) || /<device-group>\s*<entry\b/.test(text) || /^set deviceconfig system/m.test(t) || /^set vsys vsys/m.test(t) || /Palo Alto Networks/i.test(t)) return {idx:0, vendor:'p'};
  // MikroTik 防火牆訊號：僅認 /ip firewall（真正的防火牆規則區塊）。原本連 /interface bridge
  // 也一併判定為防火牆，但 /interface bridge 是純交換器功能（VLAN filtering／橋接），純交換器
  // 匯出檔（無任何 /ip firewall 規則）會被誤導向防火牆分析器；/interface bridge 判斷改移到
  // 下方與其餘交換器廠牌訊號同一批次（見下方 idx:1 區塊）
  if (/\/ip firewall/i.test(t))                                              return {idx:0, vendor:'m'};
  // Cisco FTD／ASA 的 show running-config 開頭版本行（第十三輪 NA）：截斷或規則很少的錄製可能沒有 access-list
  if (/^NGFW Version\s+\S+/m.test(t))                                         return {idx:0, vendor:'t'};
  if (/^ASA Version\s+\S+/m.test(t))                                          return {idx:0, vendor:'a'};
  if (/nameif\s+\w+/i.test(t) && /access-list/i.test(t))                    return {idx:0, vendor:'a'};
  // Cisco IOS／IOS-XE 路由器（XN139）：沒有任何 switchport，且有 Zone-Based Firewall、inside source NAT 或 CBAC → 防火牆分析
  // （與 CiscoIOSParser.detect() 一致，排除 NX-OS 的 feature 與 Ruijie RGOS；只有介面 ACL 的仍交給交換器分析）。用完整 text，NAT 常在檔尾
  if (_isIosRouterFw(text))                                                   return {idx:0, vendor:'o'};
  // Sophos：原本的 /firewall-policy\s*\{/im 是從未對照過真實格式的捏造規則（該字串不存在於
  // firewall-analyzer-parser-sophos.js 支援的任何真實匯出格式），永遠不會命中；比照
  // firewall-analyzer-app.js 的 FW_VENDOR_SIGS.sophos 改用多重特徵＋最低命中數（同一份規則
  // 已在 firewall_analyzer 自己的偵測驗證過），避免單一寬鬆關鍵字造成誤判
  if ((function(){
    var sigs=[/Sophos/i, /<Configuration[^>]*SophosFirewall/, /^set admin-settings/m, /<(?:IPHostList|FirewallRuleList|WebFilterPolicy|IPsecVPNList)>/];
    var hits=0; for (var i=0;i<sigs.length;i++) if (sigs[i].test(t)) hits++;
    return hits>=2;
  })())                                                                       return {idx:0, vendor:'s'};
  // WatchGuard Firebox（config.xml 匯出）：firewall_analyzer 已支援解析（vendor code 'g'，
  // 見 firewall-analyzer-parser-watchguard.js 的 detect()），但這份獨立維護的簡化偵測規則
  // 從未同步補上，拖放 WatchGuard 設定檔會判定「無法自動識別」，即使彩蛋人格文案
  // egg.vendor_watchguard 早已存在。訊號逐字移植自該廠牌 parser 自己的 detect() 三重特徵
  // 組合（2026-09 全功能審查發現）
  if (/<abs-policy-list/i.test(t) && /<interface-list/i.test(t) && /<address-group-list/i.test(t)) return {idx:0, vendor:'g'};
  if (/<SonicWALL/i.test(t))                                                 return {idx:0, vendor:'w'};
  // 2026-09-21 稽核修復：原判斷式 /pfctl\b|set filterip/i 從未對照過真實 pfSense/OPNsense
  // 匯出格式（config.xml，XML 根標籤為 <pfsense>/<opnsense>），永遠不會命中；訊號逐字比照
  // firewall_analyzer 自己的 FW_VENDOR_SIGS.pfsense（firewall-analyzer-app.js）改用根標籤／
  // 廠牌字樣特徵
  if (/<pfsense>/i.test(t) || /<opnsense>/i.test(t) || /pfSense|OPNsense/i.test(t))          return {idx:0, vendor:'x'};
  // 2026-08-09 稽核修復：Zyxel／EdgeRouter／OpenWrt 三家 firewall_analyzer／config_anonymizer
  // 已支援一段時間（2026-07-30／08-01 新增），但這份獨立維護的簡化偵測規則從未同步補上，
  // 訊號簡化移植自 firewall_analyzer 的 FW_VENDOR_SIGS 對應項目（各取 2 個特徵組合比對，
  // 避免單一訊號誤判）
  if (/^secure-policy\s+(?:insert\s+)?\d+/m.test(t) && /^address-object\s+\S+\s+\S+/m.test(t)) return {idx:0, vendor:'z'};
  // Linux netfilter（2026-10-02）：iptables-save 檔頭／內建鏈宣告或 nft 的 hook 宣告，訊號與 FW_VENDOR_SIGS.netfilter 一致
  if (/^# Generated by ip6?tables-save/m.test(t) || /^:(?:INPUT|FORWARD|OUTPUT|PREROUTING|POSTROUTING)\s+(?:ACCEPT|DROP|-)\s+\[\d+:\d+\]/m.test(t) || /^\s*type\s+(?:filter|nat)\s+hook\s+(?:input|forward|output|prerouting|postrouting)\b/m.test(t)) return {idx:0, vendor:'n'};
  // VyOS（2026-10-02）：與 EdgeOS 同源，訊號與 firewall_analyzer 的 FW_VENDOR_SIGS.vyos 一致，須排在 EdgeRouter 前
  if (/vyos-config-version/.test(t) || /^#\s*Version:\s+VyOS\b/m.test(t) || /^set firewall global-options /m.test(t) || /^\/\/ Release version:\s*\d/m.test(t) || /^set firewall ipv[46] (?:forward|input|output|name) /m.test(t) || /^\s+ipv[46]\s*\{\s*\n\s+(?:forward|input|output|name)\b/m.test(t)) return {idx:0, vendor:'v'};
  // EdgeRouter：比照 FW_VENDOR_SIGS.edgerouter 五個訊號中任兩個（沒有 NAT 的設定沒有 outbound-interface）
  if (_isEdgeRouter(t))                                                                        return {idx:0, vendor:'r'};
  if (/^config\s+interface(\s|$)/m.test(t) && /^package\s+(network|firewall|dhcp)/m.test(t)) return {idx:0, vendor:'u'};
  // Arista EOS: unique signatures (must check before generic Cisco patterns)
  if (/^!\s*device:\s*\S+.*\(Arista\s/m.test(t) || /^!\s*Software image version:\s*EOS/m.test(t) || /^!?\s*boot system flash[:\s]\s*\/?\S*\.swi\s*$/m.test(t) ||
      (/^interface\s+Ethernet\d+(?:\/\d+)*\s*$/m.test(t) && /^ip routing$/m.test(t)))
    return {idx:1, vendor:'arista'};
  // Allied Telesis AlliedWare Plus（2026-10-02）：port1.0.1 埠名或 vlan database 的 state enable，與 switch_analyzer isAlliedWare() 一致
  if (/^interface\s+port\d+\.\d+\.\d+/m.test(t) || /AlliedWare Plus/i.test(t) || (/^vlan database\s*$/m.test(t) && /^\s+vlan\s+[\d,-]+\s+state\s+enable/m.test(t))) return {idx:1, vendor:'awplus'};
  // Cisco Business（CBS／SG／Catalyst 1200/1300）設定檔開頭固定為 config-file-header
  if (/^config-file-header\s*$/m.test(t) || /^@?ssd-control-start/m.test(t)) return {idx:1, vendor:'ciscobiz'};
  // NX-OS／ProCurve 另認的訊號與 switch_analyzer detectVendor() 同步（2026-10-01）
  if ((/^feature\s+\w+/m.test(t) && (/Cisco\s+Nexus/i.test(t)||/^vdc\s+\S+\s+id/m.test(t))) || /^version\s+\d+\.\d+\(\d+\)/m.test(t) || /^!Command:\s*show running-config/m.test(t) || /^!\s*Cisco Nexus Operating System \(NX-OS\)/m.test(t)) return {idx:1, vendor:null};
  if (/^;\s*(?:HP\s|Aruba\s|J\d{4}[A-Z])/m.test(t)||/^oobm$/m.test(t)||/^trunk\s+\S+\s+[Tt]rk\d+/m.test(t)||(/^hostname\s+"[^"\n]*"\s*$/m.test(t)&&/^\s+(?:un)?tagged\s+[A-Z]?\d/m.test(t))) return {idx:1, vendor:null};
  if (/feature\s+(vpc|lacp)|vlan database/i.test(t))                        return {idx:1, vendor:null};
  // H3C 與 HPE Comware 依明確廠牌字樣分開標示（第十一輪 KA，與 switch_analyzer comwareBrand() 同規則），判斷不出時不標
  if (/sysname\s+\w|irf domain/i.test(t)) {
    const h3c = /\bH3C Comware\b|New H3C Technologies|^\s*sysname\s+H3C\s*$|cloud-management (?:server|backup-server) domain\s+\S*h3c/im.test(t);
    const hpe = /\bHPE? Comware\b|Hewlett[- ]Packard|^\s*sysname\s+HPE?\s*$/im.test(t);
    return {idx:1, vendor: h3c && !hpe ? 'h3c' : hpe && !h3c ? 'hpe' : null};
  }
  // MikroTik RouterOS 純交換器訊號（VLAN filtering／橋接，無 /ip firewall 規則時走到這裡）
  if (/\/interface bridge/i.test(t))                                        return {idx:1, vendor:null};
  // RouterOS 匯出但沒有 /ip firewall、也沒有橋接（純路由器，如 CHR）：交給防火牆分析器的 MikroTik（第十三輪 NA）
  if (/^\/(?:interface ethernet|ip address|system identity)\s*$/m.test(t) && (/\[\s*find\s+default-name=/.test(t) || /^#.*\bRouterOS\b/m.test(t) || /^#\s+(?:software id|version):/m.test(t))) return {idx:0, vendor:'m'};
  // 2026-08-20 稽核修復：Dell OS10／Netgear M4300／EdgeSwitch／Extreme／Alcatel／Brocade
  // ICX／Juniper 交換器 7 家 switch_analyzer 早已支援解析，但這份獨立維護的簡化偵測規則
  // 從未同步補上，拖放這些廠牌的設定檔會判定「無法自動識別」。訊號逐字移植自
  // switch_analyzer 自己的 detectVendor()（switch-analyzer-core.js），比照既有 Zyxel／
  // EdgeRouter／OpenWrt 訊號移植慣例，皆 vendor:null（不掛廠牌徽章，比照 NX-OS／
  // ProCurve／Comware 既有做法）。Juniper 交換器訊號（family ethernet-switching／
  // virtual-chassis／Junos 階層式 interfaces{}+protocols{}+routing-options{}）與上方
  // Juniper SRX 防火牆訊號（set security policies，扁平 set 語法）完全不同語法家族，
  // 且 SRX 判斷式已在更前面的 idx:0 區塊攔截，不會衝突。
  if (/^interface\s+ethernet\d+\/\d+\/\d+/im.test(t)||
      /^vlt-domain\s+\d+/m.test(t)||
      /^!\s*Dell (?:EMC )?Networking OS/m.test(t)||
      /^interface\s+ManagementEthernet/m.test(t)||
      /^interface\s+fortyGigE\s/m.test(t)||
      /^stack-unit\s+\d+/m.test(t))                                          return {idx:1, vendor:null};
  if (/^!Current Configuration:/m.test(t)&&/(NETGEAR|M4300)/i.test(t))       return {idx:1, vendor:null};
  if (/^!Current Configuration:/m.test(t)&&(/UBNT|EdgeSwitch/i.test(t)||/^\s*vlan participation (include|exclude|auto)/m.test(t))) return {idx:1, vendor:null};
  if (/^create vlan\s+"?\S/m.test(t)||
      /^configure sys-name\s+/m.test(t)||
      /^enable sharing\s+\S+\s+grouping/m.test(t)||
      /^configure vlan\s+/m.test(t)||
      /^configure iproute add\s+/m.test(t)||
      /^enable sharing\s+[\d:]/m.test(t)||/^configure vlan\s+\S+\s+dhcp-address-range/m.test(t)) return {idx:1, vendor:null};
  if (/^(?:->\s*)?system name\s+/m.test(t)||
      /^(?:->\s*)?stack set slot\s+/m.test(t)||
      /^(?:->\s*)?ip interface\s+/m.test(t)||
      /vlan\s+\d+\s+members\s+port/i.test(t)||
      /^stacking\s+slot\s+\d/m.test(t)||
      /^vlan\s+\d+\s+admin-state\s+enable/m.test(t)||
      /^dhcp-server\s+(?:admin-state|range)\s+/m.test(t)||
      /^linkagg\s+lacp\s+\d+\s+admin-state/m.test(t)||
      /^interfaces\s+\S+\s+linkagg\s+\d/m.test(t))                          return {idx:1, vendor:null};
  if (/^vlan\s+\d+\s+(?:name\s+\S+\s+)?by\s+port/m.test(t)||
      /^stack unit\s+\d+/m.test(t)||
      /^!\s+HW:\s+Stackable\s+ICX/m.test(t)||/^!\s+Copyright \(c\) Ruckus Networks/m.test(t)||
      /^\s+tagged\s+e(?:thernet)?\s*[\d/]+/m.test(t)||
      /^\s+untagged\s+e(?:thernet)?\s*[\d/]+/m.test(t)||
      /^ip dhcp-server pool\s/m.test(t)||
      /^lag\s+"\S+"\s+(?:dynamic|static)\s+id\s+\d+/m.test(t)||
      /^ip vrrp-extended vrid\s/m.test(t))                                   return {idx:1, vendor:null};
  if (/^version\s+\d+\.\d+R/m.test(t)||/^virtual-chassis\s*\{/m.test(t)||/family\s+ethernet-switching/m.test(t)||((/^interfaces\s*\{/m.test(t)||/^protocols\s*\{/m.test(t))&&/routing-options\s*\{/m.test(t))) return {idx:1, vendor:null};
  // 2026-08-24 稽核修復：FortiSwitch／Aruba CX／Ruijie 三家 switch_analyzer 早已支援解析，但這份
  // 獨立維護的簡化偵測規則從未同步補上，拖放這三家的設定檔會判定「無法自動識別」。訊號逐字移植自
  // switch_analyzer 自己的 detectVendor()（switch-analyzer-core.js），比照既有 Dell／Netgear／
  // EdgeSwitch／Extreme／Alcatel／Brocade／Juniper 移植慣例，皆 vendor:null（不掛廠牌徽章，交由
  // switch_analyzer 自己的 detectVendor() 做真正的廠牌判定）。FortiSwitch 判斷式須排在上方 idx:0
  // 的 FortiGate 防火牆判斷式（`config firewall policy|config vdom`）之後——已滿足，因為此區塊本來
  // 就在所有 idx:0 判斷式之後才會走到，真正的 FortiGate 匯出檔會被前面的判斷式先攔截 return。
  if (/^config system global/m.test(t) || /^config switch physical-port/m.test(t) || /^config router ospf/m.test(t)) return {idx:1, vendor:null};
  if (/^!Version ArubaOS-CX\b/m.test(text) || /^vsf\s*$/m.test(t) || /vlan trunk allowed/.test(t) || /vlan trunk native/.test(t) || /vlan access\s+\d/.test(t) || /vrf attach\s/.test(t)) return {idx:1, vendor:null};
  // Planet Technology SGS-6341 系列：switch_analyzer 已支援解析（見 switch-analyzer-core.js
  // detectVendor()），但這份獨立維護的簡化偵測規則從未同步補上。訊號逐字移植自該處三重弱訊號
  // 組合（hostname + "ethernet 1/0/5" 命名〔ethernet 與 slot/port 間有空格，與 Dell OS10
  // 無空格版本不同〕+ switchport mode），且必須排在下方 Ruijie 判斷式之前——Ruijie 判斷式含
  // 通用的 "switchport mode hybrid" 弱訊號，會提前攔截含 hybrid 介面的 Planet 設定檔
  // （2026-09 全功能審查發現，比照原始碼同一個踩坑教訓）
  if (/^hostname\s+\S+/m.test(t) && /^interface\s+ethernet\s+\d+\/\d+\/\d+/m.test(t) && /^\s*switchport mode\s+(trunk|access|hybrid)/m.test(t)) return {idx:1, vendor:null};
  if (/^interface\s+AggregatePort\s*\d+/im.test(t) || /switchport mode hybrid/m.test(t) || /^switch virtual domain\s+\d+/m.test(t) || /\bRGOS\b/i.test(t) || /^rldp\b/im.test(t) || /^nfpp\s*$/im.test(t)) return {idx:1, vendor:null};
  // 2026-08-09 稽核修復：此廣義 fallback 規則（僅認泛用關鍵字，不掛廠牌徽章）原本排在
  // NX-OS／ProCurve／Comware 等專屬判斷式之前，若一份 NX-OS 或 ProCurve 設定檔恰好在前
  // 8000 字內同時含這些泛用關鍵字，會被提前攔截導致徽章顯示不精準（仍會正確路由到 switch
  // 工具，只是拖放提示看不到正確的廠牌人格徽章）；移到所有專屬廠牌判斷式之後
  if (/spanning-tree|interface\s+(GigabitEthernet|FastEthernet|TenGigabitEthernet)/i.test(t)) return {idx:1, vendor:null};
  // 應用程式環境變數（.env、docker-compose environment，XN93）：其他判斷都沒命中才採用，交給去識別化（與 config_anonymizer VENDOR_SIGS.appenv 相同）
  if (/^(?:export\s+)?[A-Z][A-Z0-9_]*=[^\n]*\n(?:[ \t]*(?:#[^\n]*)?\n)*(?:export\s+)?[A-Z][A-Z0-9_]*=[^\n]*\n(?:[ \t]*(?:#[^\n]*)?\n)*(?:export\s+)?[A-Z][A-Z0-9_]*=/m.test(t)
    || /^services:\s*$[\s\S]*^\s+environment:\s*$/m.test(t)) return {idx:2, vendor:'appenv'};
  return null;
}

// 任務 2（2026-09-23 新增）：拖放結果除錯面板用的「命中規則說明」清單。detectTool() 本身
// 是經過多輪稽核修復、順序高度講究的巢狀 if-chain，直接重構抽出「命中原因」風險太高（容易
// 打亂既有判斷順序造成回歸）；改為在旁另建一份唯讀、僅供顯示用的規則說明清單，逐條複製
// detectTool() 同一份判斷式、順序完全一致——故「第一個命中的規則」保證等於 detectTool()
// 實際採用的規則，不需要也不會影響既有派送邏輯。這裡的說明文字比照專案既有「彩蛋 toast 文案
// 與 data-tip 提示皆寫死，不走 i18n」慣例，固定使用繁體中文（僅供除錯用途，非核心操作文字）。
function _detectToolReasons(text) {
  const t = text.slice(0, 8000);
  return [
    { reason: 'JSON 設定檔含 DEVICE_METADATA 與 VLAN/PORT/INTERFACE 表格 → SONiC config_db.json', test: () => {
        const trimmedFull = text.trim();
        if (trimmedFull.charAt(0) !== '{') return false;
        try { const obj = JSON.parse(trimmedFull); return !!(obj && typeof obj === 'object' && obj.DEVICE_METADATA && (obj.VLAN || obj.PORT || obj.INTERFACE)); } catch(e) { return false; }
      } },
    { reason: '命中 Check Point Management API JSON（rulebase 回應的 objects-dictionary 與 access／nat 規則）', test: () => /^[\[{]/.test(text.trim()) && /"objects-dictionary"\s*:/.test(text) && /"type"\s*:\s*"(?:access|nat)-(?:rule|section)"/.test(text) },
    { reason: '命中 Cumulus Linux NVUE 設定（YAML 的 `- set:` 段或 `nv set` 指令）', test: () => CUMULUS_RE(text) },
    { reason: '命中 AWS 安全群組（IpPermissions）、AWS Network ACL（NetworkAclId）、Azure NSG（securityRules）、Azure Firewall Policy（ruleCollections）、GCP network firewall policy（compute#firewallPolicy）、GCP 防火牆規則（compute#firewall）、OCI 安全清單／NSG、Kubernetes NetworkPolicy 或 Meraki MX API（destCidr／applianceIp／publicPort）JSON', test: () => /^[\[{]/.test(text.trim()) && CLOUD_SG_RE.test(text) },
    { reason: '命中 Kubernetes NetworkPolicy YAML（kind: NetworkPolicy）', test: () => K8S_NETPOL_YAML_RE.test(text) },
    { reason: '命中 Azure NSG／VNet flow logs（category 為 NetworkSecurityGroupFlowEvent／FlowLogFlowEvent 且含 flowTuples）', test: () => AZURE_FLOW_RE.test(text) && /"flowTuples"/.test(text) },
    { reason: '命中 AWS VPC Flow Logs（預設 v2 格式，或第一行為含 srcaddr／dstaddr 的欄位名稱）', test: () => AWS_FLOW_RE.test(text.trim()) },
    { reason: 'JSON 物件含常見 log 欄位（message/msg/severity/timestamp/@timestamp/log）→ JSON/NDJSON Log', test: () => {
        const trimmedFull = text.trim();
        if (trimmedFull.charAt(0) !== '{') return false;
        try {
          const obj = JSON.parse(trimmedFull);
          return _isLogJsonObj(obj);
        } catch(e) { return false; }
      } },
    { reason: '多筆 NDJSON 第一行或 JSON 陣列第一個元素含常見 log 欄位 → JSON/NDJSON Log', test: () => { const tf = text.trim(); return (tf.charAt(0) === '{' || tf.charAt(0) === '[') && _isLogJsonHead(tf); } },
    { reason: '命中 Windows NPS 設定匯出（netsh nps export）的 Microsoft_Internet_Authentication_Service／Microsoft_Radius_Protocol 元素，內含明碼 RADIUS 共用密鑰，交給去識別化', test: () => /<Microsoft_Internet_Authentication_Service\b|<Microsoft_Radius_Protocol\b/.test(t) },
    { reason: '命中 Windows Event Log XML 匯出的 xmlns 屬性簽章', test: () => /<Event[\s>][\s\S]*?xmlns=["']http:\/\/schemas\.microsoft\.com\/win\/2004\/08\/events\/event["']/.test(text) },
    { reason: '命中 Windows NPS DTS XML 記錄（<Event><Timestamp data_type=…> 與 Packet-Type）', test: () => /^<Event><Timestamp data_type="\d+">[^<]*<\/Timestamp>.*<(?:Packet-Type|Event-Source) data_type=/m.test(t) },
    { reason: '命中 Aruba ClearPass Syslog Export 的輸出（「篩選器名稱 序號 1 0」後接 Common.*／event_source 等鍵，或 RFC5424 的 clearPass@14823 結構化資料）', test: () => /^(?:<\d{1,3}>)?\s*\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d{3})? \S+ .+? \d+ \d+ \d+ (?:(?:Common|RADIUS|TACACS|WEBAUTH|CppmNode)\.[A-Za-z][\w\- ]*|event_source|session_id|mac_address|Timestamp)=/m.test(t) || /^<\d{1,3}>1 \S+ \S+ ClearPass .*\[clearPass@14823 /m.test(t) },
    { reason: '命中 Ivanti Connect Secure／Pulse Secure 事件 log（PulseSecure: - - - 開頭的 syslog）', test: () => /^(?:<\d{1,3}>\d*\s?|[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ \d+ )\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})? \S+ PulseSecure: - - - /m.test(t) },
    { reason: '命中 Syslog RFC5424 表頭格式 `<PRI>1 `', test: () => /^<\d{1,3}>1\s/m.test(t) },
    { reason: '命中 CEF `CEF:0|...` 表頭', test: () => /^(?:<\d{1,3}>\s*)?CEF:\d+\|/m.test(t) },
    { reason: '命中 LEEF `LEEF:2.0|...` 表頭', test: () => /^(?:<\d{1,3}>\s*)?LEEF:\d+(?:\.\d+)?\|/im.test(t) },
    { reason: '命中包在傳統 Syslog 信封裡的 CEF（月份/時間戳記後接 CEF:）', test: () => /^(?:<\d{1,3}>\s*)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+CEF:\d+\|/m.test(t) },
    { reason: '命中 Cisco ASA Syslog `%ASA-X-XXXXXX:` 格式', test: () => /^(?:<\d{1,3}>\s*)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}:\s*%ASA-\d-\d+:/m.test(t) },
    { reason: '命中 FortiGate 原生 log（`date=... time=...` + `logid=`）', test: () => /^date=\d{4}-\d{2}-\d{2}\s+time=\d{2}:\d{2}:\d{2}\b/m.test(t) && /\blogid=/.test(t) },
    { reason: '命中 FortiGate 經 syslog 送出的 log（`<PRI>` 開頭或 devname 開頭，同一行有 date=、time= 與 10 位數 logid）', test: () => /^(?:<\d{1,3}>)?(?=[^\n]*\bdate=\d{4}-\d{2}-\d{2}\s)(?=[^\n]*\stime=\d{2}:\d{2}:\d{2}\b)(?=[^\n]*\blogid="?\d{10}\b)[a-z_]+=/m.test(t) },
    { reason: '命中沒有 syslog 外殼的 Palo Alto PAN-OS CSV（`1,時間,序號,TRAFFIC|THREAT|GLOBALPROTECT|USERID…,`）', test: () => /^\d+,(?:\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z),[^,]*,(?:TRAFFIC|THREAT|GLOBALPROTECT|USERID|HIPMATCH|HIP-MATCH|SYSTEM|CONFIG|DECRYPTION|AUTHENTICATION),/m.test(t) },
    { reason: '命中 AWS ELB Access Log 存取紀錄（Classic／ALB／NLB 欄位順序）', test: () => { const t = text.slice(0, 8000); return /^(?:(?:https?|h2|grpcs|wss?) )?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z \S+ \S+:\d+ \S+ -?[\d.]+ -?[\d.]+ -?[\d.]+ (?:\d{3}|-) (?:\d{3}|-) \d+ \d+ "/m.test(t) || /^tls \S+ \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} net\/\S+ /m.test(t); } },
    { reason: '命中 Cisco Umbrella CSV 匯出（DNS／IP／Proxy／Cloud Firewall 欄位形狀）', test: () => /^"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}","[^"\n]*","[^"\n]*","[^"\n]*","[^"\n]*","(?:Allowed|Blocked|\d+)"/m.test(t) ||
      /^"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}","[^"\n]*","[^"\n]*","[^"\n]*","[^"\n]*","[^"\n]*","(?:ALLOWED|BLOCKED)","\w+:\/\//m.test(t) ||
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\[\d+\],[^\n]*,(?:INBOUND|OUTBOUND),/m.test(t) },
    { reason: '命中 SonicWall（`id=… sn=… time="…"`）或 Sophos Firewall（`device="SFW"`）原生 log', test: () => /^(?:<\d{1,3}>)?(?:id=\S+\s+sn=\S+\s+time="|device="SFW"\s)/m.test(t) },
    { reason: '命中 Cisco ASA／FTD syslog（帶主機、時區或類別的表頭，行內有 `%ASA-` 或 `%FTD-` 等級與六位數訊息號）', test: () => /^(?:<\d{1,3}>)?\s*[A-Z][a-z]{2}\s+\d{1,2}\s[^\n]*%(?:ASA|FTD)-(?:[a-z]+-)?\d-\d{6}:/m.test(t) },
    { reason: '命中標準 Syslog RFC3164 表頭', test: () => /^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s/m.test(t) },
    ...LOG_HEAD_SIGS.map(([re, v]) => ({ reason: '命中 ' + VENDOR_NAMES[v] + ' 行首格式（與 log_analyzer 判斷式相同）', test: () => re.test(t) })),
    { reason: 'RANCID 備份檔頭 `!RANCID-CONTENT-TYPE:` 標明內容類型（paloalto／arista／cisco-nx）', test: () => /^[!#]RANCID-CONTENT-TYPE:\s*(?:paloalto|arista|cisco-nx)\b/mi.test(t) },
    { reason: '命中 FortiGate 設定檔（`#config-version=FG…` 檔頭，或 `config firewall policy`／`config vdom`）', test: () => /^#config-version=FG/m.test(t) || /config firewall policy|config vdom/i.test(t) },
    { reason: '命中 H3C SecPath 防火牆的 security-policy 視圖＋security-zone 宣告', test: () => /^\s*security-policy\s+ipv?6?\s*$/m.test(text) && /^\s*security-zone\s+name\s+\S+/m.test(text) },
    { reason: '命中 Netgate TNSR（nacm＋dataplane 設定、介面 `access-list input acl … sequence`、VPF 或 `next-hop N via`）', test: () => /^nacm\s+(?:enable|disable|group\s)[\s\S]*^dataplane\s|^dataplane\s[\s\S]*^nacm\s+(?:enable|disable|group\s)/m.test(text) || /^[ \t]+access-list\s+(?:input|output)\s+acl\s+\S+\s+sequence\s+\d+/m.test(text) ||/^vpf\s+(?:filter\s+ruleset|options)\b/m.test(text) || /^[ \t]+next-hop\s+\d+\s+via\s/m.test(text) },
    { reason: '命中無線控制器 WLAN 設定（AireOS `wlan create`、H3C WX `wlan service-template`、Aruba `wlan ssid-profile`、Catalyst 9800 `wlan 名稱 ID SSID`）→ 防火牆分析器的 WiFi 分析', test: () => /^(?:config\s+)?wlan\s+create\s+\d+\s+\S+/m.test(text) || /^\s*wlan\s+service-template\s+\S+/m.test(text) || /^\s*wlan\s+ssid-profile\s+\S+/m.test(text) || /^wlan\s+\S+\s+\d{1,4}\s+\S+/m.test(text) },
    { reason: '命中 Broadcom EFOS（`!System Description "EFOS`，或檔頭 System Software Version＋serviceport＋port-channel name）', test: () => /^!System Description\s+"EFOS\b/m.test(text) || (/^!System Software Version\s+"/m.test(text) && /^serviceport\s+(?:ip|protocol)\b/m.test(text) && /^port-channel\s+name\s+\d+\/\d+\s/m.test(text)) },
    { reason: '命中 Netgear Smart Managed Pro（`SYSTEM CONFIG FILE ::= BEGIN`＋`! System Description: NETGEAR`）', test: () => /^SYSTEM CONFIG FILE ::= BEGIN\s*$/m.test(t) && /^!\s*System Description:\s*NETGEAR\b/mi.test(t) },
    { reason: '命中 Extreme VOSS／Fabric Engine（config.cfg 檔頭 box type、`vlan create … type port-mstprstp` 或 boot config flags＋cli mode）', test: () => /^#\s*box type\s*:\s*(?:VSP|XA|\d{4})/m.test(text) || /^vlan\s+create\s+[\d,\-]+(?:\s+name\s+"[^"]*")?\s+type\s+port-mstprstp\s+\d+/m.test(text) || (/^boot config flags\s/m.test(text) && /^#\s*cli mode\s*:/m.test(text)) },
    { reason: '命中 Juniper SRX 安全政策關鍵字（`set security policies` 或階層式 `from-zone ... to-zone ...`）', test: () => /set security policies/i.test(t) || /^\s*from-zone\s+\S+\s+to-zone\s+\S+/m.test(t) },
    { reason: '命中 Check Point Gaia `set hostname` + `set interface ... ipv4-address`', test: () => /^set hostname\s+\S+/m.test(t) && /^set interface\s+\S+\s+ipv4-address/m.test(t) },
    { reason: '命中 Palo Alto PAN-OS（XML `<config><devices>`、`set deviceconfig system`、`set vsys` 或廠牌字樣）', test: () => /<config\b[^>]*>[\s\S]{0,300}<devices>/m.test(t) || /^set deviceconfig system/m.test(t) || /^set vsys vsys/m.test(t) || /Palo Alto Networks/i.test(t) },
    { reason: '命中 MikroTik RouterOS 防火牆區塊 `/ip firewall`', test: () => /\/ip firewall/i.test(t) },
    { reason: '命中 Cisco FTD `NGFW Version` 版本行', test: () => /^NGFW Version\s+\S+/m.test(t) },
    { reason: '命中 Cisco ASA `ASA Version` 版本行', test: () => /^ASA Version\s+\S+/m.test(t) },
    { reason: '命中 Cisco ASA `nameif` + `access-list`', test: () => /nameif\s+\w+/i.test(t) && /access-list/i.test(t) },
    { reason: '命中 Cisco IOS 路由器（沒有 switchport，有 zone security／ip nat inside source／ip inspect）', test: () => _isIosRouterFw(text) },
    { reason: '命中 Sophos 多重特徵組合（≥2 項：Sophos 字樣／SophosFirewall 標籤／admin-settings／IPHostList 等清單標籤）', test: () => {
        const sigs = [/Sophos/i, /<Configuration[^>]*SophosFirewall/, /^set admin-settings/m, /<(?:IPHostList|FirewallRuleList|WebFilterPolicy|IPsecVPNList)>/];
        let hits = 0; for (let i = 0; i < sigs.length; i++) if (sigs[i].test(t)) hits++;
        return hits >= 2;
      } },
    { reason: '命中 WatchGuard Firebox config.xml 三重特徵（interface-list/abs-policy-list/address-group-list）', test: () => /<abs-policy-list/i.test(t) && /<interface-list/i.test(t) && /<address-group-list/i.test(t) },
    { reason: '命中 SonicWall `<SonicWALL>` 標籤', test: () => /<SonicWALL/i.test(t) },
    { reason: '命中 pfSense/OPNsense config.xml 根標籤或廠牌字樣', test: () => /<pfsense>/i.test(t) || /<opnsense>/i.test(t) || /pfSense|OPNsense/i.test(t) },
    { reason: '命中 Zyxel ZLD `secure-policy` + `address-object`', test: () => /^secure-policy\s+(?:insert\s+)?\d+/m.test(t) && /^address-object\s+\S+\s+\S+/m.test(t) },
    { reason: '命中 Linux iptables-save 檔頭／內建鏈宣告，或 nft list ruleset 的 `type filter hook` 宣告', test: () => /^# Generated by ip6?tables-save/m.test(t) || /^:(?:INPUT|FORWARD|OUTPUT|PREROUTING|POSTROUTING)\s+(?:ACCEPT|DROP|-)\s+\[\d+:\d+\]/m.test(t) || /^\s*type\s+(?:filter|nat)\s+hook\s+(?:input|forward|output|prerouting|postrouting)\b/m.test(t) },
    { reason: '命中 VyOS 檔尾 `// vyos-config-version`、`// Release version` 或 1.4 起 `firewall ipv4 forward/input/output/name` 結構', test: () => /vyos-config-version/.test(t) || /^#\s*Version:\s+VyOS\b/m.test(t) || /^set firewall global-options /m.test(t) || /^\/\/ Release version:\s*\d/m.test(t) || /^set firewall ipv[46] (?:forward|input|output|name) /m.test(t) || /^\s+ipv[46]\s*\{\s*\n\s+(?:forward|input|output|name)\b/m.test(t) },
    { reason: '命中 EdgeRouter EdgeOS 特徵（`ethernet ethN {`、`default-action`、`outbound-interface`、`address-group`、廠牌字樣）任兩項', test: () => _isEdgeRouter(t) },
    { reason: '命中 OpenWrt UCI `config interface` + `package network/firewall/dhcp`', test: () => /^config\s+interface(\s|$)/m.test(t) && /^package\s+(network|firewall|dhcp)/m.test(t) },
    { reason: '命中 Arista EOS 裝置字樣、`boot system flash *.swi`，或 Ethernet 介面命名 + `ip routing`', test: () => /^!\s*device:\s*\S+.*\(Arista\s/m.test(t) || /^!\s*Software image version:\s*EOS/m.test(t) || /^!?\s*boot system flash[:\s]\s*\/?\S*\.swi\s*$/m.test(t) || (/^interface\s+Ethernet\d+(?:\/\d+)*\s*$/m.test(t) && /^ip routing$/m.test(t)) },
    { reason: '命中 Allied Telesis AlliedWare Plus（`interface port1.0.1` 埠名或 vlan database 的 `state enable`）', test: () => /^interface\s+port\d+\.\d+\.\d+/m.test(t) || /AlliedWare Plus/i.test(t) || (/^vlan database\s*$/m.test(t) && /^\s+vlan\s+[\d,-]+\s+state\s+enable/m.test(t)) },
    { reason: '命中 Cisco Business（CBS／SG／Catalyst 1200/1300）設定檔表頭 `config-file-header`', test: () => /^config-file-header\s*$/m.test(t) || /^@?ssd-control-start/m.test(t) },
    { reason: '命中 Cisco NX-OS `feature` 指令 + Nexus/vdc 字樣、`version N.N(N)` 版本格式或 `!Command: show running-config` 檔頭', test: () => (/^feature\s+\w+/m.test(t) && (/Cisco\s+Nexus/i.test(t) || /^vdc\s+\S+\s+id/m.test(t))) || /^version\s+\d+\.\d+\(\d+\)/m.test(t) || /^!Command:\s*show running-config/m.test(t) || /^!\s*Cisco Nexus Operating System \(NX-OS\)/m.test(t) },
    { reason: '命中 HP/Aruba ProCurve 註解表頭、`trunk ... TrkN` 語法，或帶引號 hostname＋VLAN 內以埠號開頭的 untagged／tagged', test: () => /^;\s*(?:HP\s|Aruba\s|J\d{4}[A-Z])/m.test(t) || /^oobm$/m.test(t) || /^trunk\s+\S+\s+[Tt]rk\d+/m.test(t) || (/^hostname\s+"[^"\n]*"\s*$/m.test(t) && /^\s+(?:un)?tagged\s+[A-Z]?\d/m.test(t)) },
    { reason: '命中 `feature vpc/lacp` 或 `vlan database`', test: () => /feature\s+(vpc|lacp)|vlan database/i.test(t) },
    { reason: '命中 Comware（H3C／HPE）`sysname` 或 `irf domain`；含 H3C／HPE 廠牌字樣時分開標示', test: () => /sysname\s+\w|irf domain/i.test(t) },
    { reason: '命中 MikroTik RouterOS 橋接區塊 `/interface bridge`（無防火牆規則，判定為純交換器）', test: () => /\/interface bridge/i.test(t) },
    { reason: '命中 MikroTik RouterOS 匯出（`/interface ethernet` 等區塊＋`[ find default-name=`），沒有防火牆也沒有橋接 → 防火牆分析器的 MikroTik', test: () => /^\/(?:interface ethernet|ip address|system identity)\s*$/m.test(t) && (/\[\s*find\s+default-name=/.test(t) || /^#.*\bRouterOS\b/m.test(t) || /^#\s+(?:software id|version):/m.test(t)) },
    { reason: '命中 Dell OS10／Brocade／Juniper 等交換器介面命名簽章（ethernet slot/port、vlt-domain、ManagementEthernet 等）', test: () => /^interface\s+ethernet\d+\/\d+\/\d+/im.test(t) || /^vlt-domain\s+\d+/m.test(t) || /^!\s*Dell (?:EMC )?Networking OS/m.test(t) || /^interface\s+ManagementEthernet/m.test(t) || /^interface\s+fortyGigE\s/m.test(t) || /^stack-unit\s+\d+/m.test(t) },
    { reason: '命中 Netgear M4300 表頭 `!Current Configuration:` + NETGEAR/M4300 字樣', test: () => /^!Current Configuration:/m.test(t) && /(NETGEAR|M4300)/i.test(t) },
    { reason: '命中 Ubiquiti EdgeSwitch 表頭 + UBNT/EdgeSwitch 字樣或 `vlan participation` 語法', test: () => /^!Current Configuration:/m.test(t) && (/UBNT|EdgeSwitch/i.test(t) || /^\s*vlan participation (include|exclude|auto)/m.test(t)) },
    { reason: '命中 Extreme ExtremeXOS `create vlan`／`configure sys-name`／`enable sharing` 等指令', test: () => /^create vlan\s+"?\S/m.test(t) || /^configure sys-name\s+/m.test(t) || /^enable sharing\s+\S+\s+grouping/m.test(t) || /^configure vlan\s+/m.test(t) || /^configure iproute add\s+/m.test(t) || /^enable sharing\s+[\d:]/m.test(t) || /^configure vlan\s+\S+\s+dhcp-address-range/m.test(t) },
    { reason: '命中 Alcatel OmniSwitch `system name`／`ip interface`／`stack set slot` 等指令', test: () => /^(?:->\s*)?system name\s+/m.test(t) || /^(?:->\s*)?stack set slot\s+/m.test(t) || /^(?:->\s*)?ip interface\s+/m.test(t) || /vlan\s+\d+\s+members\s+port/i.test(t) || /^stacking\s+slot\s+\d/m.test(t) || /^vlan\s+\d+\s+admin-state\s+enable/m.test(t) || /^dhcp-server\s+(?:admin-state|range)\s+/m.test(t) || /^linkagg\s+lacp\s+\d+\s+admin-state/m.test(t) || /^interfaces\s+\S+\s+linkagg\s+\d/m.test(t) },
    { reason: '命中 Brocade/Ruckus ICX `vlan ... by port`／`stack unit`／`tagged/untagged ethernet` 等指令', test: () => /^vlan\s+\d+\s+(?:name\s+\S+\s+)?by\s+port/m.test(t) || /^stack unit\s+\d+/m.test(t) || /^!\s+HW:\s+Stackable\s+ICX/m.test(t) || /^!\s+Copyright \(c\) Ruckus Networks/m.test(t) || /^\s+tagged\s+e(?:thernet)?\s*[\d/]+/m.test(t) || /^\s+untagged\s+e(?:thernet)?\s*[\d/]+/m.test(t) || /^ip dhcp-server pool\s/m.test(t) || /^lag\s+"\S+"\s+(?:dynamic|static)\s+id\s+\d+/m.test(t) || /^ip vrrp-extended vrid\s/m.test(t) },
    { reason: '命中 Juniper 交換器 Junos 階層式 `interfaces{}`/`protocols{}`/`routing-options{}` 或 `virtual-chassis`', test: () => /^version\s+\d+\.\d+R/m.test(t) || /^virtual-chassis\s*\{/m.test(t) || /family\s+ethernet-switching/m.test(t) || ((/^interfaces\s*\{/m.test(t) || /^protocols\s*\{/m.test(t)) && /routing-options\s*\{/m.test(t)) },
    { reason: '命中 FortiSwitch `config system global`／`config switch physical-port`／`config router ospf`', test: () => /^config system global/m.test(t) || /^config switch physical-port/m.test(t) || /^config router ospf/m.test(t) },
    { reason: '命中 Aruba CX（`!Version ArubaOS-CX`、`vsf`／`vlan trunk allowed`／`vrf attach` 等指令）', test: () => /^!Version ArubaOS-CX\b/m.test(text) || /^vsf\s*$/m.test(t) || /vlan trunk allowed/.test(t) || /vlan trunk native/.test(t) || /vlan access\s+\d/.test(t) || /vrf attach\s/.test(t) },
    { reason: '命中 Planet Technology 三重弱訊號（hostname + `ethernet 1/0/5` 命名 + switchport mode）', test: () => /^hostname\s+\S+/m.test(t) && /^interface\s+ethernet\s+\d+\/\d+\/\d+/m.test(t) && /^\s*switchport mode\s+(trunk|access|hybrid)/m.test(t) },
    { reason: '命中 Ruijie RGOS `AggregatePort`／`switchport mode hybrid`／`RGOS` 等字樣', test: () => /^interface\s+AggregatePort\s*\d+/im.test(t) || /switchport mode hybrid/m.test(t) || /^switch virtual domain\s+\d+/m.test(t) || /\bRGOS\b/i.test(t) || /^rldp\b/im.test(t) || /^nfpp\s*$/im.test(t) },
    { reason: '命中泛用交換器關鍵字（spanning-tree／GigabitEthernet 等介面命名），僅能判斷為交換器，無法辨識確切廠牌', test: () => /spanning-tree|interface\s+(GigabitEthernet|FastEthernet|TenGigabitEthernet)/i.test(t) },
    { reason: '命中應用程式環境變數檔（.env 至少 3 行「大寫名稱=值」，或 docker-compose 的 services:＋environment:），內含密碼與金鑰，交給去識別化', test: () => /^(?:export\s+)?[A-Z][A-Z0-9_]*=[^\n]*\n(?:[ \t]*(?:#[^\n]*)?\n)*(?:export\s+)?[A-Z][A-Z0-9_]*=[^\n]*\n(?:[ \t]*(?:#[^\n]*)?\n)*(?:export\s+)?[A-Z][A-Z0-9_]*=/m.test(t) || /^services:\s*$[\s\S]*^\s+environment:\s*$/m.test(t) },
  ];
}
function explainDetectedTool(text) {
  const rules = _detectToolReasons(text);
  for (const r of rules) {
    try { if (r.test()) return r.reason; } catch(e) { /* 個別規則測試失敗不影響其餘規則判斷 */ }
  }
  return null;
}

