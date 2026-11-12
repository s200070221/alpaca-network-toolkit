// ============================================================
// [2] 格式偵測與 Parser
// ============================================================
// 待議／未定案（規劃階段已記錄，本次 v1 不展開）：CEF 包在 Syslog 信封裡的巢狀格式
// （<PRI>TIMESTAMP HOST CEF:0|...）僅剝除最前面的 PRI，不解析信封其餘欄位；
// 純粹的 CEF/RFC5424/RFC3164 三種獨立格式為 v1 唯一支援範圍。
// RFC6587 octet-counting（TCP syslog 每筆前加「長度 空白」），第十五輪 VC
const OCTET_COUNT_RE = /^\d{1,6} (?=<\d{1,3}>)/;
// 沒有 syslog 外殼的 PAN-OS CSV（`FUTURE_USE,接收時間,序號,類型,…`，GUI 匯出或轉送後剝掉表頭）
const PAN_CSV_LINE_RE = /^\d+,(?:\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z),[^,]*,(?:TRAFFIC|THREAT|GLOBALPROTECT|USERID|HIPMATCH|HIP-MATCH|SYSTEM|CONFIG|DECRYPTION|AUTHENTICATION),/;
function detectLineFormat(line) {
  line = line.replace(OCTET_COUNT_RE, '');
  if (PAN_CSV_LINE_RE.test(line)) return 'pancsv';
  if (UMBRELLA_LINE_RE.test(line) && umbrellaKind(splitCSVSimple(line))) return 'umbrella';
  if (ELB_LINE_RE.test(line) || NLB_LINE_RE.test(line)) return 'elb';
  if (S3_ACCESS_RE.test(line)) return 's3';
  if (BIND_FILE_RE.test(line) || COREDNS_RE.test(line) || WINDNS_RE.test(line)) return 'dns';
  if (WINDHCP_ROW_RE.test(line)) return 'dhcp';
  if (NPS_DTS_RE.test(line)) return 'nps';
  if (CPPM_STD_RE.test(line) || CPPM_5424_RE.test(line)) return 'clearpass';
  if (DS389_LINE_RE.test(line) || OPENLDAP26_LINE_RE.test(line) || DS389_ERR_RE.test(line) || isOpenLdap26SvcLine(line)) return 'ldap';
  // PostgreSQL／MySQL 伺服器 log 檔（XN90）
  if (PG_FILE_RE.test(line) || MYSQL_ERR_RE.test(line) || MYSQL_GEN_RE.test(line)) return 'dbfile';
  // Ivanti／Pulse Connect Secure（XN94）：外殼可能是 RFC5424 或 RFC3164，須在兩者之前判斷
  if (PCS_LINE_RE.test(line)) return 'pcs';
  // Citrix NetScaler 原生 syslog（XN109）
  if (NS_LINE_RE.test(line) || NS5424_RE.test(line)) return 'netscaler';
  // Stormshield SNS（XN122）：<pri> 後直接是 id=firewall time="…" fw="…" tz=
  if (SNS_LINE_RE.test(line)) return 'stormshield';
  // Cisco Meraki（XN120）：RFC5424 外殼但時間為 epoch 秒，須在 rfc5424 之前判斷
  if (MERAKI_LINE_RE.test(line)) return 'meraki';
  if (/^<\d{1,3}>1\s/.test(line)) return 'rfc5424';
  // OpenVPN／strongSwan／FreeRADIUS 記錄檔（第二十三輪 IA～IC），須在下面的 rfc3164 判斷之前（charon.log 的時間與 syslog 相同）
  if (vpnFileKind(line)) return 'vpnauth';
  if (/^(?:<\d{1,3}>\s*)?CEF:\d+\|/.test(line)) return 'cef';
  if (/^(?:<\d{1,3}>\s*)?LEEF:\d+(?:\.\d+)?\|/i.test(line)) return 'leef';
  // CEF 包在 RFC3164 風格 Syslog 信封裡（ArcSight 官方 CEF spec 範例格式：
  // "Sep 19 08:26:10 host CEF:0|Vendor|..."）；必須排在下面的通用 rfc3164 判定之前，
  // 否則會被 rfc3164 截胡，CEF body 整段被當成自由文字 msg
  if (/^(?:<\d{1,3}>\s*)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+CEF:\d+\|/.test(line)) return 'cef-syslog';
  // Cisco ASA %ASA-LEVEL-MSGID: 語法，時間戳含年份（與下面通用 rfc3164 無年份格式天生互斥，
  // 不需要調整既有規則順序即可正確分流）
  // 第十五輪 VB：年份可省略、時間後可接時區或主機（`主機 :`、`主機 程式[pid]:`）、%FTD- 與 EMBLEM 類別欄（%ASA-session-5-…）
  if (ASA_LINE_RE.test(line)) return 'asa';
  // Cisco IOS／Comware 原生 log（show logging／display logbuffer 或直送 syslog）：時間後直接接
  // %設施-等級-助記碼（Cisco）或 設施/等級/摘要（Comware），2026-09-29 WC 新增
  if (CISCO_IOS_LOG_RE.test(line)) return 'ciscoios';
  if (COMWARE_LOG_RE.test(line)) return 'comware';
  // PRI 選填：本機檔案/裝置匯出常見 rsyslog 樣板已剝除 PRI（如 UniFi kernel netfilter
  // 流量記錄，經查證真實範例確認），並非每種 rfc3164 來源都保留 <PRI> 前綴
  if (/^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s/.test(line)) return 'rfc3164';
  // 同樣的「時間 主機 TAG: 訊息」結構但時間為 ISO 8601（2026-09-29 BA）：rsyslog 高精度預設格式
  // （RSYSLOG_FileFormat／ForwardFormat，可帶 <PRI>）與 journalctl -o short-iso（時區 +0800 無冒號）；
  // 與 RFC5424 的差別是 <PRI> 後沒有版本號 "1 "，上面的 rfc5424 判斷已先排除
  if (ISO_SYSLOG_LINE_RE.test(line)) return 'rfc3164';
  // FortiOS 原生 log（execute log filter／GUI 下載／memory 緩衝區匯出）沒有 syslog 外殼，
  // 直接以固定順序的 date=/time=/logid= 開頭，與上面幾種格式互斥，可高信心判定
  // 經 syslog 送出時前面帶 <PRI>（第十四輪 VA：Beats fortinet 真實測試 log 全為此形式）
  // FortiOS 6.4 起欄位順序可能以 devname 開頭，改為：key=value 開頭且同時有 date=、time= 與 10 位數 logid
  // FortiMail／FortiManager（XN123）：欄位為 log_id（FortiGate 為 logid），須在 FortiGate 之前判斷
  if (FML_LINE_RE.test(line)) return 'fortimail';
  if (FMG_LINE_RE.test(line)) return 'fortimanager';
  if (/^(?:<\d{1,3}>)?[a-z_]+=/.test(line) && /(?:^|[\s>])date=\d{4}-\d{2}-\d{2}\s/.test(line) && /\stime=\d{2}:\d{2}:\d{2}\b/.test(line) && /\blogid="?\d{10}\b/.test(line)) return 'fortigate';
  // SonicWall／Sophos Firewall（SFOS）直送 syslog 沒有時間主機外殼，<PRI> 後直接是 key=value（第十四輪 OH）
  if (KVFW_LINE_RE.test(line)) return 'kvfw';
  if (SQUID_LINE_RE.test(line)) return 'squid';
  if (HAPROXY_RAW_RE.test(line) && parseHaproxyLine(line, 0)) return 'haproxy';
  if (WEB_ACCESS_RE.test(line)) return 'weblog';
  // MikroTik RouterOS 本機 /log print 匯出（無 syslog 外殼）與不含時間／主機名的遠端 syslog，
  // 需開頭為 <PRI> 或時間，且接著的 topics 清單含嚴重度字（見 splitMikroTikTopics()）才判定
  const mt = line.match(MIKROTIK_LINE_RE);
  if (mt && (mt[1] !== undefined || mt[3]) && splitMikroTikTopics(mt[4])) return 'mikrotik';
  return 'unknown';
}

function splitUnescaped(str, sep, maxSplits) {
  // 依 sep 切割，"\\"+sep 視為跳脫字元不切割；切滿 maxSplits 次後剩餘全部歸入最後一段
  const parts = [];
  let cur = '', i = 0, n = 0;
  while (i < str.length) {
    if (str[i] === '\\' && i + 1 < str.length) { cur += str[i] + str[i + 1]; i += 2; continue; }
    if (str[i] === sep && n < maxSplits) { parts.push(cur); cur = ''; i++; n++; continue; }
    cur += str[i]; i++;
  }
  parts.push(cur);
  return parts;
}
function unescapeCEF(s) {
  // 四條規則鏈式呼叫（先前依序 \| → \= → \n → \\）在「跳脫反斜線後緊接字面 n」的組合
  // （官方跳脫後應為 \\ + n，例如路徑 C:\notes.txt 跳脫成 C:\\notes.txt）會被 \n 規則
  // 提前吃掉第二個反斜線+n 誤判成換行，導致 \\ 規則已找不到完整雙反斜線可正確還原
  // （2026-09 全功能審查發現）；改用單一 pass 掃描，四種二字元跳脫序列一次性正確消耗，
  // 不會互相污染
  return s.replace(/\\\\|\\\||\\=|\\n/g, m => m === '\\\\' ? '\\' : m === '\\|' ? '|' : m === '\\=' ? '=' : '\n');
}
function parseCEFExtension(ext) {
  // key=value 空白分隔，value 可延伸到下一個 "key=" 出現前；用「找出所有 key= 起始位置」的
  // 方式切分，比單純空白 split 更能處理 value 本身含空白的情況（CEF extension 常見寫法）
  const fields = {};
  if (!ext) return fields;
  const keyRe = /([A-Za-z][A-Za-z0-9._]*)=/g;
  const marks = [];
  let m;
  while ((m = keyRe.exec(ext))) marks.push({ key: m[1], idx: m.index, valStart: m.index + m[0].length });
  for (let i = 0; i < marks.length; i++) {
    const end = i + 1 < marks.length ? marks[i + 1].idx : ext.length;
    let val = ext.slice(marks[i].valStart, end).trim();
    val = val.replace(/\\=/g, '=').replace(/\\n/g, '\n').replace(/\\\\/g, '\\');
    fields[marks[i].key] = val;
  }
  return fields;
}
function extractCEFTimestamp(fields) {
  const raw = fields.rt || fields.end || fields.start;
  if (!raw) return null;
  if (/^\d{10,13}$/.test(raw)) {
    const n = Number(raw);
    const d = new Date(String(raw).length <= 10 ? n * 1000 : n);
    return isNaN(d.getTime()) ? null : d;
  }
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d;
}
// LEEF 官方規格提供 devTimeFormat extension 欄位讓發送端明確標示 devTime 的日期格式
// （devTime 本身沒有固定格式），先前完全未讀取這個欄位，一律丟給 new Date() 用瀏覽器
// 預設寬鬆解析猜測，曖昧的數字格式（如 05/03/2026）會被誤判成錯誤的月/日順序，緊湊格式
// （如 20260305100000）甚至直接解析失敗回傳 null（2026-09 全功能審查發現）。支援常見
// SimpleDateFormat 樣式 token（yyyy/MM/dd/HH/mm/ss/SSS），依 devTimeFormat 標示的位置
// 精確切出每個欄位再組成日期，無法比對時退回既有 new Date() 行為（不猜測、寧可用原本
// 已知的降級路徑）
const LEEF_DATE_TOKEN_RE = /y{2,4}|M{1,2}|d{1,2}|H{1,2}|m{1,2}|s{1,2}|S{1,3}/g;
function parseLEEFDevTime(devTime, devTimeFormat) {
  if (!devTime) return null;
  if (!devTimeFormat) return extractCEFTimestamp({ rt: devTime });
  let pattern = '', lastIndex = 0, tm;
  const tokens = [];
  LEEF_DATE_TOKEN_RE.lastIndex = 0;
  while ((tm = LEEF_DATE_TOKEN_RE.exec(devTimeFormat))) {
    pattern += devTimeFormat.slice(lastIndex, tm.index).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    tokens.push(tm[0][0]);
    pattern += `(\\d{${tm[0].length}})`;
    lastIndex = tm.index + tm[0].length;
  }
  pattern += devTimeFormat.slice(lastIndex).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = tokens.length ? devTime.match(new RegExp('^' + pattern)) : null;
  if (!m) return extractCEFTimestamp({ rt: devTime });
  const vals = {};
  tokens.forEach((t, i) => { vals[t] = Number(m[i + 1]); });
  const d = new Date(vals.y || 1970, (vals.M || 1) - 1, vals.d || 1, vals.H || 0, vals.m || 0, vals.s || 0, vals.S || 0);
  return isNaN(d.getTime()) ? extractCEFTimestamp({ rt: devTime }) : d;
}
function parseCEFLine(line, lineNo) {
  let body = line;
  const priMatch = body.match(/^<\d{1,3}>\s*/);
  if (priMatch) body = body.slice(priMatch[0].length);
  if (body.indexOf('CEF:') !== 0) return null;
  body = body.slice(4);
  const parts = splitUnescaped(body, '|', 7).map(unescapeCEF);
  if (parts.length < 8) return null;
  const [version, deviceVendor, deviceProduct, deviceVersion, sigId, name, severityRaw, extension] = parts;
  const fields = parseCEFExtension(extension);
  return {
    format: 'cef', raw: line, lineNo, rawPri: priMatch ? priMatch[0] : '',
    version, deviceVendor, deviceProduct, deviceVersion, sigId,
    timestamp: extractCEFTimestamp(fields),
    timestampRaw: fields.rt || fields.end || fields.start || '',
    host: fields.dvchost || fields.shost || fields.dhost || '',
    severityRaw, severityNorm: normCEFSeverity(severityRaw),
    facility: null, facilityAuth: false,
    appName: deviceProduct, procid: '', msgid: '',
    url: pickField(fields, URL_KEYS) || '', httpMethod: pickField(fields, HTTP_METHOD_KEYS) || '',
    msg: name, fields
  };
}
// CEF 包在 RFC3164 Syslog 信封裡（ArcSight 官方 spec 範例格式，見 detectLineFormat 註解）：
// 拆出信封 pri/ts/host 後，body 本身就是合法的 "CEF:..." 字串，直接交給既有 parseCEFLine()
// 重用其 header/extension 解析邏輯，事件 .format 維持 'cef' 不另開格式標籤，讓 classifyByKeyword／
// extractCandidateIPs／anonymizeEvent 的既有 cef 分支自動適用；額外掛 syslogPrefix 供重建時還原信封
function parseCEFInSyslogLine(line, lineNo) {
  const m = line.match(/^(<\d{1,3}>\s*)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(CEF:[\s\S]*)$/);
  if (!m) return null;
  const [, pri, ts, host, cefBody] = m;
  const cefEvt = parseCEFLine(cefBody, lineNo);
  if (!cefEvt) return null;
  cefEvt.raw = line;
  // pri：信封原本的 <PRI>（去識別化重建時保留，否則下載結果少了優先權欄位）
  cefEvt.syslogPrefix = { pri: pri || '', ts, host };
  // CEF extension 本身沒有 rt=/dvchost= 時，用信封資訊補上（parseCEFLine 既有判斷順位優先採 extension）
  if (!cefEvt.timestamp) cefEvt.timestamp = parseSyslogTimestamp(ts, 'bsd');
  if (!cefEvt.timestampRaw) cefEvt.timestampRaw = ts;
  if (!cefEvt.host) cefEvt.host = host;
  return cefEvt;
}

// LEEF（IBM QRadar Log Event Extended Format）：header 語法「LEEF:Version|Vendor|Product|
// Version|EventID|」（1.0，extension 固定用 TAB 分隔）或「LEEF:2.0|Vendor|Product|Version|
// EventID|DelimiterCharacter|」（2.0，extension 分隔符可自訂，header 裡以字面字元或
// x/0x 開頭的十六進位碼表示，如 x5E 代表 ^）。規格未提供人類可讀的 Name 欄位，用 EventID
// 當 msg（官方範例 EventID 常直接是描述性文字如 "Logon Failure"）；query 語意常見落在
// extension 的 cat 欄位，故 classifyByKeyword() 額外檢查該欄位（見下方）
function resolveLEEFDelimiter(raw) {
  if (!raw) return '\t';
  const m = raw.match(/^0?x([0-9A-Fa-f]{1,4})$/);
  if (m) return String.fromCharCode(parseInt(m[1], 16));
  return raw;
}
function splitLEEFExtension(ext, delimChar) {
  const fields = {};
  if (!ext) return fields;
  ext.split(delimChar).forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    fields[pair.slice(0, idx).trim()] = pair.slice(idx + 1);
  });
  return fields;
}
function parseLEEFLine(line, lineNo) {
  let body = line;
  const priMatch = body.match(/^<\d{1,3}>\s*/);
  if (priMatch) body = body.slice(priMatch[0].length);
  if (!/^LEEF:/i.test(body)) return null;
  body = body.slice(5);
  const isV2 = /^2(?:\.\d+)?\|/.test(body);
  const headerSplits = isV2 ? 6 : 5;
  const parts = splitUnescaped(body, '|', headerSplits).map(unescapeCEF);
  if (parts.length < headerSplits + 1) return null;
  let version, vendor, product, productVersion, eventId, delimiterRaw, extension;
  if (isV2) { [version, vendor, product, productVersion, eventId, delimiterRaw, extension] = parts; }
  else { [version, vendor, product, productVersion, eventId, extension] = parts; delimiterRaw = ''; }
  const delimChar = isV2 ? resolveLEEFDelimiter(delimiterRaw) : '\t';
  const fields = splitLEEFExtension(extension, delimChar);
  return {
    format: 'leef', raw: line, lineNo, rawPri: priMatch ? priMatch[0] : '',
    version, vendor, product, productVersion, eventId, delimiterRaw,
    timestamp: parseLEEFDevTime(fields.devTime, fields.devTimeFormat), timestampRaw: fields.devTime || '',
    host: '',
    severityRaw: fields.sev, severityNorm: normCEFSeverity(fields.sev),
    facility: null, facilityAuth: false,
    appName: product, procid: '', msgid: '',
    msg: eventId, fields
  };
}

// 無年份時間的年份推算（2026-09-29 QD）：先假設為參考時間的年份，若因此落在參考時間一天以後
// （未來），代表其實是去年的記錄——例如 1 月分析 12 月的 log，或同一份 log 跨越 12/31→1/1
// 時 12 月那段原本會被排到 1 月之後、產生相隔將近一年的假時間斷點。留一天緩衝容許時區差
const YEAR_ROLLOVER_GRACE_MS = 24 * 60 * 60 * 1000;
function fixFutureYear(d, now) {
  const ref = now || new Date();
  if (d.getTime() - ref.getTime() > YEAR_ROLLOVER_GRACE_MS) d.setFullYear(d.getFullYear() - 1);
  return d;
}
function parseSyslogTimestamp(ts, kind, now) {
  if (kind === 'iso') {
    const d = new Date(ts);
    return isNaN(d.getTime()) ? null : d;
  }
  // 2 月 29 日：非閏年時 Date 會進位成 3 月 1 日，改為往前找最近一個日期不在未來的閏年
  if (/^Feb\s+29\b/i.test(String(ts).trim())) {
    const ref = now || new Date();
    for (let y = ref.getFullYear(); y > ref.getFullYear() - 9; y--) {
      if (!(y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0))) continue;
      const d = new Date(`${String(ts).trim()} ${y}`);
      if (!isNaN(d.getTime()) && d.getTime() - ref.getTime() <= YEAR_ROLLOVER_GRACE_MS) return d;
    }
    return null;
  }
  // RFC3164 無年份／時區資訊：以參考時間的年份推算，落在未來則改為去年（見 fixFutureYear()）
  const d = new Date(`${ts} ${(now || new Date()).getFullYear()}`);
  return isNaN(d.getTime()) ? null : fixFutureYear(d, now);
}
function splitSDandMSG(rest) {
  if (rest[0] === '-') return { sd: '-', msg: rest.slice(1).replace(/^\s+/, '') };
  let i = 0, depth = 0, sdEnd = -1;
  while (i < rest.length) {
    const c = rest[i];
    if (c === '"') { i++; while (i < rest.length && rest[i] !== '"') { if (rest[i] === '\\') i++; i++; } i++; continue; }
    if (c === '[') { depth++; i++; continue; }
    if (c === ']') {
      depth--; i++;
      if (depth === 0) { if (rest[i] === '[') continue; sdEnd = i; break; }
      continue;
    }
    i++;
  }
  if (sdEnd === -1) sdEnd = rest.length;
  return { sd: rest.slice(0, sdEnd), msg: rest.slice(sdEnd).replace(/^\s+/, '') };
}
function parseStructuredData(sd) {
  const fields = {};
  if (!sd || sd === '-') return fields;
  const blockRe = /\[([^\s\]]+)((?:\s+[^\s=]+="(?:[^"\\]|\\.)*")*)\]/g;
  let m;
  while ((m = blockRe.exec(sd))) {
    const sdId = m[1];
    const paramRe = /([^\s=]+)="((?:[^"\\]|\\.)*)"/g;
    let p;
    while ((p = paramRe.exec(m[2]))) {
      const val = p[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
      // 多個 SD-ELEMENT 若含相同 SD-PARAM 名稱（RFC5424 官方範例本身就示範這種命名慣例），
      // 後解析的元素先前會直接覆寫前面同名欄位、資料靜默遺失。改為第一次出現保留原鍵名
      // （維持既有下游消費端讀取慣例，不影響最常見的單一 SD-ELEMENT 情境），後續同名 key
      // 改存進 SD-ID 命名空間鍵，資料不再遺失（2026-09 全功能審查發現）
      if (Object.prototype.hasOwnProperty.call(fields, p[1])) {
        fields[`${sdId}.${p[1]}`] = val;
      } else {
        fields[p[1]] = val;
      }
    }
  }
  return fields;
}
// Syslog 訊息本體為 JSON 物件（第十九輪 ED）：應用程式與部分產品（如 CyberArk Vault 的 syslog 稽核記錄）以
// JSON 物件當訊息，可帶 rsyslog CEE 前綴 @cee:。巢狀物件攤平為「最後一層鍵名（小寫）→值」（同名取第一個），
// 再依常見鍵名取連線元組、帳號與動作；位址欄位須為合法 IP。原始物件另存 jsonMsgObj 供去識別化重建
const JSON_MSG_KEYS = {
  srcip: ['srcip', 'src_ip', 'source_ip', 'sourceip', 'src', 'client_ip', 'clientip', 'remote_addr', 'remote_ip', 'remoteip', 'station', 'ip_address', 'ipaddress', 'ip'],
  dstip: ['dstip', 'dst_ip', 'destination_ip', 'destinationip', 'dest_ip', 'dst', 'server_ip', 'serverip', 'target_ip'],
  srcport: ['srcport', 'src_port', 'source_port', 'sport', 'client_port'],
  dstport: ['dstport', 'dst_port', 'destination_port', 'dest_port', 'dport', 'server_port'],
  proto: ['proto', 'protocol', 'transport'],
  user: ['user', 'username', 'user_name', 'userid', 'user_id', 'account', 'accountname', 'issuer', 'src_user', 'login'],
  action: ['action', 'outcome', 'result', 'status', 'event_action']
};
function jsonMsgLeaves(o, out) {
  Object.keys(o).forEach(k => {
    const v = o[k];
    if (v && typeof v === 'object' && !Array.isArray(v)) jsonMsgLeaves(v, out);
    else if ((typeof v === 'string' && v !== '') || typeof v === 'number' || typeof v === 'boolean') { const lk = k.toLowerCase(); if (!(lk in out)) out[lk] = String(v); }
  });
  return out;
}
function jsonMsgFields(o) {
  const leaf = jsonMsgLeaves(o, {});
  const f = {};
  const ipOk = v => isValidIPv4(v) || (v.includes(':') && ipv6ToBigInt(v) !== null);
  Object.keys(JSON_MSG_KEYS).forEach(k => {
    const hit = JSON_MSG_KEYS[k].find(x => leaf[x] !== undefined && (!/ip$/.test(k) || ipOk(leaf[x])));
    if (hit) f[k] = leaf[hit];
  });
  if (/^(?:deny|denied|drop|dropped|block|blocked|reject|rejected)$/i.test(f.action || '')) f.action = 'deny';
  else if (/^(?:allow|allowed|accept|accepted|permit|permitted|pass)$/i.test(f.action || '')) f.action = 'accept';
  return Object.assign(leaf, f);
}
function parseJsonInMsg(msg) {
  const t = String(msg || '').trim().replace(/^@cee:\s*/, '');
  if (!/^\{[\s\S]*\}$/.test(t)) return null;
  let o;
  try { o = JSON.parse(t); } catch (e) { return null; }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
  return { vendor: '', fields: jsonMsgFields(o), obj: o };
}
function parseRFC5424Line(line, lineNo) {
  // 主機後直接接 JSON 訊息、省略 APP-NAME／PROCID／MSGID 的寫法（CyberArk Vault 等，第十九輪 ED）視為三者皆為 -
  const mj = line.match(/^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\{[\s\S]*\})\s*$/);
  const m = mj ? [mj[0], mj[1], mj[2], mj[3], '-', '-', '-', '- ' + mj[4]] : line.match(/^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([\s\S]*)$/);
  if (!m) return null;
  const [, pri, ts, host, app, procid, msgid, rest] = m;
  const { sd, msg } = splitSDandMSG(rest);
  const priNum = Number(pri);
  const facility = Math.floor(priNum / 8);
  const severityRaw = priNum % 8;
  // Check Point Log Exporter 的 SD 段是 [key:"value"; key:"value"]（第十五輪 VE），另存原值與順序供重建
  const cp = parseCheckPointSD(sd);
  if (cp) return checkPointEvent(line, lineNo, { pri: priNum, ts, host, app, procid, msgid, msg }, cp);
  const fields = parseStructuredData(sd);
  // 原本就在結構化資料段的欄位，去識別化重建時只寫回這些（廠牌訊息拆出的欄位不該被塞進 SD 段）
  const sdKeys = Object.keys(fields);
  const mt = parseMikroTikMsg(msg);
  let vf = mt ? null : (parseVeeamMsg(rest) || parseVendorCSVFields(app === '-' ? '' : app, msg));
  if (!mt && !vf) { const jf = parseJunosRtFlow(msgid, fields, msg); if (jf) vf = { vendor: 'junos', fields: jf }; }
  if (!mt && !vf) { const js = parseJunosSecLog(app, msgid, fields); if (js) vf = { vendor: 'junos', fields: js }; }
  if (!mt && !vf) { const hf = parseH3CFlowLog(msg); if (hf) vf = { vendor: 'h3c', fields: hf }; }
  if (!mt && !vf) { const cf = parseCiscoAclInMsg(msg); if (cf) vf = { vendor: 'ciscoios', fields: cf }; }
  if (!mt && !vf) vf = parseIseMsg(msg);
  if (!mt && !vf) vf = parseSshdMsg(app === '-' ? '' : app, msg);
  if (!mt && !vf) vf = parseVpnAuthMsg(app === '-' ? '' : app, msg);
  if (!mt && !vf) vf = parseHaproxyMsg(app === '-' ? '' : app, msg);
  if (!mt && !vf) vf = parseLdapMsg(app === '-' ? '' : app, msg);
  if (!mt && !vf) vf = parseDbMsg(app === '-' ? '' : app, msg);
  if (!mt && !vf) vf = parseSvcSysMsg(app === '-' ? '' : app, msg);
  if (!mt && !vf) vf = parseDhcpInMsg(app === '-' ? '' : app, msg);
  if (!mt && !vf) vf = parseDnsInMsg(app === '-' ? '' : app, msg);
  if (!mt && !vf) vf = parseQnapMsg(app === '-' ? '' : app, msg);
  if (!mt && !vf) vf = parseArubaCxMsg(msg);
  if (!mt && !vf) vf = parseKvFwInMsg(msg);
  if (!mt && !vf) vf = parseJsonInMsg(msg);
  const extra = mt ? mt.fields : (vf ? vf.fields : null);
  if (extra) Object.keys(extra).forEach(k => { if (fields[k] === undefined) fields[k] = extra[k]; });
  return {
    format: 'rfc5424', raw: line, lineNo, mikrotik: !!mt, netFields: !!(mt || vf), netVendor: mt ? 'mikrotik' : (vf ? vf.vendor : ''), sdKeys,
    ...(vf && vf.obj ? { jsonMsg: true } : {}),
    timestamp: parseSyslogTimestamp(ts, 'iso'), timestampRaw: ts,
    host, appName: app === '-' ? '' : app, procid: procid === '-' ? '' : procid, msgid: msgid === '-' ? '' : msgid,
    severityRaw, severityNorm: normSyslogSeverity(severityRaw),
    facility, facilityAuth: (facility === 4 || facility === 10),
    msg: (vf && vf.msg) || msg, fields
  };
}
// Check Point Log Exporter（第十五輪 VE）：RFC5424，SD 段為 [key:"value"; …]，欄位名稱依 Elastic Beats checkpoint 模組的
// 真實測試 log（src／dst／s_port／service〔目的埠〕／proto〔協定號碼〕／service_id／action〔Accept／Drop／Reject…〕／rule_name／
// rule_uid／inzone／outzone／ifname／ifdir／origin〔閘道〕／xlatesrc／xlatedst／src_user_name）
const CP_PROTO = { '6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6', '47': 'gre', '50': 'esp' };
function parseCheckPointSD(sd) {
  if (!/^\[[A-Za-z_][\w]*:"/.test(sd || '')) return null;
  const kv = {}, order = [];
  const re = /([A-Za-z_][\w]*):"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(sd))) { if (!(m[1] in kv)) order.push(m[1]); kv[m[1]] = m[2]; }
  return order.length ? { kv, order } : null;
}
function normalizeCheckPoint(kv) {
  const f = {}, ok = v => v && v !== '0.0.0.0';
  if (ok(kv.src)) f.srcip = kv.src;
  if (ok(kv.dst)) f.dstip = kv.dst;
  if (kv.s_port) f.srcport = kv.s_port;
  if (/^\d+$/.test(kv.service || '')) f.dstport = kv.service;
  if (kv.proto) f.proto = CP_PROTO[kv.proto] || kv.proto;
  const a = String(kv.action || '');
  if (/^(?:drop|reject|block|prevent)$/i.test(a)) f.action = 'deny';
  else if (/^accept$/i.test(a)) f.action = 'accept';
  [['rule', 'rule_name'], ['srczone', 'inzone'], ['dstzone', 'outzone'], ['srcintf', 'ifname'], ['servicename', 'service_id'], ['user', 'src_user_name']]
    .forEach(([k, s2]) => { if (kv[s2]) f[k] = kv[s2]; });
  if (ok(kv.xlatesrc)) f.natsrcip = kv.xlatesrc;
  if (ok(kv.xlatedst)) f.natdstip = kv.xlatedst;
  return f;
}
function checkPointEvent(line, lineNo, h, cp) {
  const f = normalizeCheckPoint(cp.kv);
  return {
    format: 'rfc5424', raw: line, lineNo, netFields: true, netVendor: 'checkpoint', sdKeys: [], cpKV: cp.kv, cpOrder: cp.order,
    timestamp: parseSyslogTimestamp(h.ts, 'iso'), timestampRaw: h.ts,
    host: h.host === '-' ? '' : h.host, appName: h.app === '-' ? '' : h.app, procid: h.procid === '-' ? '' : h.procid, msgid: h.msgid === '-' ? '' : h.msgid,
    severityRaw: h.pri % 8, severityNorm: normSyslogSeverity(h.pri % 8), facility: Math.floor(h.pri / 8), facilityAuth: false,
    msg: h.msg || cp.kv.sys_message || [cp.kv.product, cp.kv.action, cp.kv.service_id].filter(Boolean).join(' '), cpMsgEmpty: !h.msg,
    fields: Object.assign({}, cp.kv, f)
  };
}
function rebuildCheckPointSD(evt) {
  return '[' + evt.cpOrder.map(k => `${k}:"${String(evt.cpKV[k] === undefined ? '' : evt.cpKV[k])}"`).join('; ') + ']';
}
// 去識別化：原值全部換 IP／MAC，帳號與管理者、閘道 SIC 名稱另換，再重新整理對照欄位
const CP_USER_KEYS = ['src_user_name', 'dst_user_name', 'user', 'administrator'];
const CP_HOST_KEYS = ['originsicname', 'machine', 'src_machine_name', 'dst_machine_name'];
function anonCheckPointEvent(clone, opts) {
  const kv = Object.assign({}, clone.cpKV);
  Object.keys(kv).forEach(k => {
    const v = kv[k];
    if (!v) return;
    if (CP_USER_KEYS.includes(k)) kv[k] = anonUser(v);
    else if (CP_HOST_KEYS.includes(k)) kv[k] = anonHostname(v);
    else kv[k] = replaceMACsInLine(replaceIPsInLine(String(v), opts));
  });
  clone.cpKV = kv;
  clone.fields = Object.assign({}, kv, normalizeCheckPoint(kv));
  if (clone.host) clone.host = anonHostname(clone.host);
  clone.msg = replaceMACsInLine(replaceIPsInLine(clone.msg || '', opts));
  // 重建原始行時訊息部分（MSG）可能是空的，這時 msg 只是顯示用摘要，不寫回
  const origMsg = clone.cpMsgEmpty ? '' : clone.msg;
  clone.raw = `<${clone.facility * 8 + Number(clone.severityRaw || 0)}>1 ${clone.timestampRaw || '-'} ${clone.host || '-'} ${clone.appName || '-'} ${clone.procid || '-'} ${clone.msgid || '-'} ${rebuildCheckPointSD(clone)}${origMsg ? ' ' + origMsg : ''}`;
}
const ISO_SYSLOG_TS_SRC = '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})';
const ISO_SYSLOG_LINE_RE = new RegExp('^(?:<\\d{1,3}>)?' + ISO_SYSLOG_TS_SRC + '\\s+\\S+\\s');
// journalctl 的 +0800 補成 +08:00 再交給 Date 解析
function parseISOSyslogTimestamp(ts) {
  return parseSyslogTimestamp(ts.replace(/([+-]\d{2})(\d{2})$/, '$1:$2'), 'iso');
}
function parseRFC3164Line(line, lineNo) {
  const m = line.match(new RegExp('^(?:<(\\d{1,3})>)?([A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}|' + ISO_SYSLOG_TS_SRC + ')\\s+(\\S+)\\s+([\\s\\S]*)$'));
  if (!m) return null;
  let [, pri, ts, host, rest] = m;
  // 不帶主機名稱的 BSD syslog（pfSense 官方文件明載送往遠端的 syslog 不含主機名）：主機欄位
  // 位置其實是 TAG（如 filterlog[123]:），主機名稱本身不會以冒號結尾，據此判斷後歸回訊息
  if (/^[\w./-]+(?:\[\d+\])?:$/.test(host)) { rest = host + ' ' + rest; host = ''; }
  // PAN-OS 短表頭（時間後直接是 CSV 的 `1,YYYY/MM/DD`，第十五輪 VC）：沒有主機名稱
  else if (/^\d+,\d{4}\/\d{2}\/\d{2}$/.test(host)) { rest = host + ' ' + rest; host = ''; }
  const isoTs = /^\d{4}-/.test(ts);
  // 缺 PRI 時無從得知 facility/severity，設為 null／固定 'Info'（查無依據時寧可漏報不誤報，
  // 比照 normGenericSeverity 對無法辨識嚴重度的既有慣例），不可用 Number(undefined)=NaN
  // 或預設 0 反推，那會誤植出不存在的 facility/severity 語意
  const hasPri = pri !== undefined;
  const priNum = hasPri ? Number(pri) : null;
  const facility = hasPri ? Math.floor(priNum / 8) : null;
  const severityRaw = hasPri ? priNum % 8 : null;
  const mt = parseMikroTikMsg(rest);
  // WatchGuard 表頭在程式名稱前多了序號、叢集成員與本機時間（XN108），只在訊息以 msg_id="…" 開頭時採用
  const wg = mt ? null : rest.match(WG_HEAD_RE);
  const tagMatch = mt ? null : (wg ? [null, wg[4], wg[5], wg[6]] : rest.match(/^([\w./-]+)(?:\[(\d+)\])?:\s*([\s\S]*)$/));
  // PID 先前被正則擷取後直接捨棄，procid 一律寫死空字串，與 RFC5424/ASA 事件的 schema
  // 不一致，下游若依賴 procid 做行為者關聯會少一個可用訊號（2026-09 全功能審查發現）
  const appName = tagMatch ? tagMatch[1] : '';
  const procid = tagMatch && tagMatch[2] ? tagMatch[2] : '';
  const msg = tagMatch ? tagMatch[3] : rest;
  let vf = mt ? null : (wg ? parseWatchGuardMsg(msg) : parseVendorCSVFields(appName, msg));
  if (vf && wg) { if (wg[1] && /^[0-9A-Z]{10,}$/.test(wg[1])) vf.fields.wgSerial = wg[1]; if (wg[3]) vf.fields.wgTime = wg[3]; }
  if (!mt && !vf) { const jf = parseJunosRtFlow('', null, msg); if (jf) vf = { vendor: 'junos', fields: jf }; }
  if (!mt && !vf) { const hf = parseH3CFlowLog(msg); if (hf) vf = { vendor: 'h3c', fields: hf }; }
  if (!mt && !vf) { const cf = parseCiscoAclInMsg(msg); if (cf) vf = { vendor: 'ciscoios', fields: cf }; }
  if (!mt && !vf) vf = parseIseMsg(msg);
  if (!mt && !vf) vf = parseSshdMsg(appName, msg);
  if (!mt && !vf) vf = parseVpnAuthMsg(appName, msg);
  if (!mt && !vf) vf = parseHaproxyMsg(appName, msg);
  if (!mt && !vf) vf = parseLdapMsg(appName, msg);
  if (!mt && !vf) vf = parseDbMsg(appName, msg);
  if (!mt && !vf) vf = parseSvcSysMsg(appName, msg);
  if (!mt && !vf) vf = parseDhcpInMsg(appName, msg);
  if (!mt && !vf) vf = parseDnsInMsg(appName, msg);
  if (!mt && !vf) vf = parseQnapMsg(appName, msg);
  if (!mt && !vf) vf = parseArubaCxMsg(msg);
  if (!mt && !vf) vf = parseKvFwInMsg(msg);
  if (!mt && !vf) vf = parseJsonInMsg(msg);
  return {
    format: 'rfc3164', raw: line, lineNo, mikrotik: !!mt, netFields: !!(mt || vf), netVendor: mt ? 'mikrotik' : (vf ? vf.vendor : ''),
    ...(vf && vf.obj ? { jsonMsg: true } : {}),
    timestamp: wg && wg[3] ? new Date(wg[3]) : (vf && vf.vendor === 'sophos' && sfosTime(vf.fields)) || (isoTs ? parseISOSyslogTimestamp(ts) : parseSyslogTimestamp(ts, 'bsd')), timestampRaw: wg && wg[3] ? wg[3] : ts,
    host, appName, procid, msgid: wg && vf ? vf.fields.wgMsgId : '',
    severityRaw, severityNorm: hasPri ? normSyslogSeverity(severityRaw) : (mt && mt.topics.length ? mikrotikTopicSeverity(mt.topics) : 'Info'),
    facility, facilityAuth: hasPri && (facility === 4 || facility === 10),
    msg, fields: mt ? mt.fields : (vf ? vf.fields : {})
  };
}
// Cisco ASA %ASA-LEVEL-MSGID: 語法（官方 ASA 設定手冊確認），時間戳含年份與標準 RFC3164
// 不同，不需比照 parseSyslogTimestamp('bsd') 補當前年份 hack，new Date() 可直接正確解析；
// classifyByKeyword/extractCandidateIPs 不需另開分支——msg 是明碼文字（如 "Deny tcp src..."），
// 既有通用關鍵字掃描與 IP 擷取 fallback 已涵蓋，此為重用既有機制、非遺漏
// Cisco ASA／FTD 行（第十五輪 VB，表頭變體依 Elastic Beats cisco asa／ftd 模組的真實測試 log）：
// [<PRI>]Mmm dd [yyyy] hh:mm:ss[.ms][ 時區][ 主機[ 程式[pid]]][ ]:? %ASA|FTD-[類別-]等級-訊息號: 訊息
// FTD 的 Lina 引擎與 ASA 共用訊息號與格式，一律以 parseASAFields() 拆欄位
const ASA_TZ = '(?:UTC|GMT|EDT|EST|CDT|CST|MDT|MST|PDT|PST|CET|CEST|JST|KST|AEST|BST|IST|HKT|SGT)';
// 第十六輪 PD：時間也可為 ISO 8601（FMC／FTD 轉送的 Firepower 事件 `2019-08-15T16:03:31Z firepower  %FTD-1-430002:`），
// 程式名稱可不帶 pid（`CISCO-SENSOR-3D Alerts %NGIPS-0-430003:`），族群另含 NGIPS
const ASA_LINE_RE = new RegExp('^(?:<(\\d{1,3})>\\s*)?([A-Z][a-z]{2}\\s+\\d{1,2}(?:\\s+\\d{4})?\\s+\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?|\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?)(?:\\s+' + ASA_TZ + ')?' +
  '(?:\\s+([^\\s:%\\[]+)(?:\\s+[\\w.-]+(?:\\[\\d+\\])?)?)?\\s*:?\\s*%(ASA|FTD|NGIPS)-(?:[a-z]+-)?(\\d)-(\\d+):\\s*([\\s\\S]*)$');
function parseASALine(line, lineNo) {
  const m = line.match(ASA_LINE_RE);
  if (!m) return null;
  const [, pri, ts, host, fam, level, msgId, msg] = m;
  const d = /^\d{4}-/.test(ts) ? new Date(ts) : /\s\d{4}\s/.test(ts) ? new Date(ts) : parseSyslogTimestamp(ts.replace(/\.\d+$/, ''), 'bsd');
  return {
    format: 'asa', raw: line, lineNo,
    timestamp: d && !isNaN(d.getTime()) ? d : null, timestampRaw: ts,
    host: host || '', appName: fam === 'ASA' ? '' : fam, procid: '', msgid: msgId,
    severityRaw: level, severityNorm: normSyslogSeverity(Number(level)),
    facility: pri !== undefined ? Math.floor(Number(pri) / 8) : null, facilityAuth: false,
    msg, fields: parseASAFields(msgId, msg),
    // 去識別化重建用：訊息前的原樣表頭（主機名稱另外替換）
    asaHead: line.slice(0, line.length - msg.length)
  };
}
// ASA 連線與 ACL 訊息拆欄位（第十三輪 NF），格式依 Cisco ASA Syslog Messages 指南（搜尋摘要，cisco.com 被擋）：
//   106023 Deny 協定 src 介面:位址/埠 dst 介面:位址/埠 … by access-group "ACL"
//   106100 access-list ACL permitted|denied 協定 介面/位址(埠) -> 介面/位址(埠) hit-cnt …
//   302013／302015 Built inbound|outbound TCP|UDP connection ID for 介面:位址/埠 (對應位址/埠) to 介面:位址/埠 (…)
//     兩端固定先列安全等級較低的介面；inbound 為第一個列出的一端發起，outbound 為第二個（to）一端發起。
//     Built 代表規則已放行（action 記為 accept）
// 「介面:位址/埠」以第一個冒號分介面（IPv6 位址本身含冒號），最後一個 / 分埠
// Firepower 事件（FTD／NGIPS 430001 入侵、430002／430003 連線開始／結束、430004 檔案、430005 惡意程式檔案；第十六輪 PD）：
// 訊息為「欄位: 值, 欄位: 值」清單，欄位名稱依 Elastic Beats cisco 模組（asa-ftd-pipeline）與其 ftd 真實測試 log。
// 值可能含逗號（Message、URI），以「, 下一個欄位名稱: 」切分
const FIREPOWER_ACTION = { allow: 'accept', trust: 'accept', fastpath: 'accept', block: 'deny', 'block with reset': 'deny', 'interactive block': 'deny', 'interactive block with reset': 'deny' };
function parseFirepowerKV(msg) {
  const kv = {};
  String(msg || '').split(/,\s*(?=[A-Z][A-Za-z0-9_ ]{1,40}:\s)/).forEach(part => {
    const i = part.indexOf(':');
    if (i > 0) kv[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  });
  return kv;
}
function parseFirepowerFields(msgId, msg) {
  const kv = parseFirepowerKV(msg);
  const f = { fpEvent: msgId };
  const set = (k, v) => { if (v !== undefined && v !== '') f[k] = v; };
  set('srcip', kv.SrcIP); set('dstip', kv.DstIP);
  if (/^\d+$/.test(kv.SrcPort || '')) f.srcport = kv.SrcPort;
  if (/^\d+$/.test(kv.DstPort || '')) f.dstport = kv.DstPort;
  if (kv.Protocol) f.proto = kv.Protocol.toLowerCase();
  set('srcintf', kv.IngressInterface); set('dstintf', kv.EgressInterface);
  set('srczone', kv.IngressZone); set('dstzone', kv.EgressZone);
  set('rule', kv.AccessControlRuleName); set('policy', kv.ACPolicy);
  const act = (kv.AccessControlRuleAction || '').toLowerCase();
  if (FIREPOWER_ACTION[act]) f.action = FIREPOWER_ACTION[act];
  if (kv.User && !/^No Authentication Required$/i.test(kv.User)) f.user = kv.User;
  set('app', kv.ApplicationProtocol); set('url', kv.URI);
  // Security Intelligence（IP／URL／DNS 信譽清單）：AccessControlRuleReason 如 IP Monitor／IP Block，類別在 *SICategory
  set('reason', kv.AccessControlRuleReason);
  set('sicategory', kv.IPReputationSICategory || kv.URLSICategory || kv.DNSSICategory);
  // 入侵事件：Message 為特徵名稱，GID:SID 為特徵編號，Priority 1 最高
  if (msgId === '430001') { set('signature', kv.Message); set('sid', kv.GID && kv.SID ? kv.GID + ':' + kv.SID : kv.SID); set('priority', kv.Priority); set('classification', kv.Classification); }
  // 檔案／惡意程式事件
  if (msgId === '430004' || msgId === '430005') {
    set('filename', kv.FileName); set('fileaction', kv.FileAction); set('disposition', kv.SHA_Disposition || kv.Disposition);
    set('threat', kv.ThreatName); set('sha256', kv.FileSHA256);
  }
  return f;
}
function parseASAFields(msgId, msg) {
  if (/^43000[1-5]$/.test(msgId)) return parseFirepowerFields(msgId, msg);
  const ep = tok => {
    const i = tok.indexOf(':'); if (i < 0) return null;
    const rest = tok.slice(i + 1), j = rest.lastIndexOf('/');
    return { intf: tok.slice(0, i), ip: j < 0 ? rest : rest.slice(0, j), port: j < 0 ? '' : rest.slice(j + 1) };
  };
  const pack = (proto, a, b, action, acl) => {
    if (!a || !b) return {};
    const f = { proto: String(proto).toLowerCase(), srcintf: a.intf, srcip: a.ip, dstintf: b.intf, dstip: b.ip, action };
    if (/^\d+$/.test(a.port)) f.srcport = a.port;
    if (/^\d+$/.test(b.port)) f.dstport = b.port;
    if (acl) f.acl = acl;
    return f;
  };
  let m;
  if (msgId === '106023' && (m = msg.match(/^Deny\s+(\S+)\s+src\s+(\S+)\s+dst\s+(\S+?)(?:\s|$)[\s\S]*?(?:by\s+access-group\s+"?([^"\s]+)"?)?/)))
    return pack(m[1], ep(m[2]), ep(m[3]), 'deny', m[4]);
  if (msgId === '106100' && (m = msg.match(/^access-list\s+(\S+)\s+(permitted|denied|est-allowed)\s+(\S+)\s+([^\/\s]+)\/([^(\s]+)\((\d+)\)\s+->\s+([^\/\s]+)\/([^(\s]+)\((\d+)\)/))) {
    const f = pack(m[3], { intf: m[4], ip: m[5], port: m[6] }, { intf: m[7], ip: m[8], port: m[9] }, m[2] === 'denied' ? 'deny' : 'accept', m[1]);
    return f;
  }
  if ((msgId === '302013' || msgId === '302015') && (m = msg.match(/^Built\s+(inbound|outbound)\s+(TCP|UDP)\s+connection\s+\d+\s+for\s+(\S+)\s+\([^)]*\)[\s\S]*?\s+to\s+(\S+)\s+\(/))) {
    const a = ep(m[3]), b = ep(m[4]);
    return m[1] === 'inbound' ? pack(m[2], a, b, 'accept') : pack(m[2], b, a, 'accept');
  }
  // 302020 Built inbound|outbound ICMP connection for faddr F gaddr G laddr L [type T code C]（第十四輪 OF，
  // 格式依 Elastic Beats cisco 模組的真實測試 log 與其 grok 規則）：inbound 由外部 faddr 發起、outbound 由內部 laddr
  // 發起；位址可帶「介面:」前綴與「/序號」；gaddr 為轉換後位址不列入
  if (msgId === '302020' && (m = msg.match(/^Built\s+(inbound|outbound)\s+ICMP\s+connection\s+for\s+faddr\s+(\S+)(?:\s+\([^)]*\))?\s+gaddr\s+\S+\s+laddr\s+(\S+)(?:\s+\([^)]*\))?(?:\s+type\s+(\d+)\s+code\s+(\d+))?/))) {
    const ad = tok => { const t = tok.replace(/\/\d+$/, ''); const im = t.match(/^([A-Za-z][\w.-]*):(\d[\d.]*|[0-9a-fA-F:]*:[0-9a-fA-F:]*)$/); return im ? { intf: im[1], ip: im[2], port: '' } : { intf: '', ip: t, port: '' }; };
    const f = m[1] === 'inbound' ? pack('icmp', ad(m[2]), ad(m[3]), 'accept') : pack('icmp', ad(m[3]), ad(m[2]), 'accept');
    ['srcintf', 'dstintf'].forEach(k => { if (!f[k]) delete f[k]; });
    if (m[4]) { f.icmptype = m[4]; f.icmpcode = m[5]; }
    return f;
  }
  // 302014／302016 Teardown TCP|UDP connection N for 介面:位址/埠 to 介面:位址/埠 duration … bytes N [原因]：訊息不含方向，
  // 只在一端埠號 < 1024、另一端 ≥ 1024 時把低埠那端當目的；判斷不出來不拆。不帶 action（連線建立已由 302013／302015 計入）
  if ((msgId === '302014' || msgId === '302016') && (m = msg.match(/^Teardown\s+(TCP|UDP)\s+connection\s+\S+\s+for\s+(\S+?)(?:\([^)]*\))?\s+to\s+(\S+?)(?:\([^)]*\))?\s+duration\s+(\S+)\s+bytes\s+(\d+)\s*([^(]*)/))) {
    const a = ep(m[2]), b = ep(m[3]);
    if (!a || !b) return {};
    const pa = Number(a.port), pb = Number(b.port);
    let f;
    if (pa < 1024 && pb >= 1024) f = pack(m[1], b, a, '');
    else if (pb < 1024 && pa >= 1024) f = pack(m[1], a, b, '');
    else return {};
    delete f.action;
    f.duration = m[4]; f.bytes = m[5];
    if (m[6].trim()) f.reason = m[6].trim();
    return f;
  }
  // 認證訊息（第二十輪 FB，格式依 Elastic Beats cisco 模組真實測試 log 與 Cisco ASA syslog 訊息說明）：auth 為 fail／success，
  // 帳號為 ***** 等遮蔽值時不列。605004／605005 管理登入、611101／611102 使用者認證、113004／113005／113012／113015 AAA、
  // 716039 WebVPN／管理認證被拒（兩種句型）
  const au = (auth, user, ip, extra) => {
    const f = Object.assign({ auth }, extra || {});
    const u = String(user || '').trim().replace(/^"|"$/g, '');
    if (u && !/^\*+$/.test(u)) f.user = u;
    if (ip) f.srcip = ip;
    return f;
  };
  if ((msgId === '605004' || msgId === '605005') && (m = msg.match(/^Login (denied|permitted) from (\S+?)\/(\d+) to (\S+?):(\S+?)\/(\S+) for user "?([^"]*)"?/)))
    return au(m[1] === 'denied' ? 'fail' : 'success', m[7], m[2], { srcport: m[3], dstintf: m[4], dstip: m[5], service: m[6] });
  if ((msgId === '611101' || msgId === '611102') && (m = msg.match(/^User authentication (succeeded|failed): IP address: (\S+?), Uname: (\S+)/)))
    return au(m[1] === 'failed' ? 'fail' : 'success', m[3], m[2]);
  if (/^1130(?:04|05|12|15)$/.test(msgId) && /authentication/i.test(msg)) {
    m = msg.match(/\buser = ([^:,]+?)\s*(?::|,|$)/i);
    const ip = (msg.match(/\buser IP = (\S+)/i) || [])[1];
    return au(/Rejected/i.test(msg) ? 'fail' : 'success', m ? m[1] : '', ip);
  }
  if (msgId === '716039') {
    m = msg.match(/^Group <([^>]*)> User <([^>]*)> IP <([^>]*)>/) || msg.match(/group = (\S+) user = (\S+)/);
    return au('fail', m ? m[2] : '', m && m[3] ? m[3] : '', m ? { group: m[1] } : {});
  }
  return {};
}
// Cisco IOS／IOS-XE ACL 記錄（第十四輪 OI）：%SEC-6-IPACCESSLOGP／DP／NP／RP／SP／S、%IPV6-6-ACCESSLOGP 等，
// 「list ACL permitted|denied 協定 來源[(埠)] -> 目的[(埠)] [(類型[/代碼])], N packet(s)」；標準 ACL（IPACCESSLOGS）
// 只有「list ACL denied 來源 N packet」。格式依 Elastic Beats cisco 模組 ios 真實測試 log
function parseCiscoAclLog(mnem, body) {
  if (!/^(?:IP)?ACCESSLOG\w*$/.test(mnem || '')) return null;
  const t = String(body || '');
  let m = t.match(/^list\s+(\S+)\s+(permitted|denied)\s+(\S+)\s+(\S+?)(?:\((\d+)\))?\s+->\s+(\S+?)(?:\((\d+)\))?(?:\s+\((\d+)(?:\/(\d+))?\))?,\s+(\d+)\s+packets?/);
  if (m) {
    const f = { acl: m[1], action: m[2] === 'denied' ? 'deny' : 'accept', proto: m[3].toLowerCase(), srcip: m[4], dstip: m[6], packets: m[10] };
    if (m[5]) f.srcport = m[5];
    if (m[7]) f.dstport = m[7];
    if (m[8]) { f.icmptype = m[8]; if (m[9]) f.icmpcode = m[9]; }
    return f;
  }
  m = t.match(/^list\s+(\S+)\s+(permitted|denied)\s+(\S+)\s+(\d+)\s+packets?/);
  return m ? { acl: m[1], action: m[2] === 'denied' ? 'deny' : 'accept', srcip: m[3], packets: m[4] } : null;
}
// 包在 syslog 信封裡的 Cisco 訊息（`序號: 時間: %SEC-6-IPACCESSLOGP: …`）
function parseCiscoAclInMsg(msg) {
  const m = String(msg || '').match(/%(?:SEC|IPV6)-\d-((?:IP)?ACCESSLOG\w*):\s*([\s\S]*)$/);
  return m ? parseCiscoAclLog(m[1], m[2]) : null;
}
// FortiOS 原生 key=value 逐欄擷取：與 extractKeyValueFields()（供既有格式的可選欄位 best-effort
// 擷取用）分開實作，因為這裡需要保留「原始欄位順序」與「原始是否加雙引號」供去識別化後原樣重建，
// 那個既有函式只回傳攤平的 key→value，兩者用途不同不可合併
function parseFortiGateKV(line) {
  const fields = {}, order = [], quoted = new Set();
  const re = /([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|(\S*))/g;
  let m;
  while ((m = re.exec(line))) {
    const key = m[1], val = m[2] !== undefined ? m[2] : (m[3] || '');
    fields[key] = val;
    order.push(key);
    if (m[2] !== undefined) quoted.add(key);
  }
  return { fields, order, quoted };
}
function parseFortiGateLine(line, lineNo) {
  // syslog 送出的 <PRI> 前綴剝除後保留，去識別化重建時原樣加回（第十五輪 VA）
  const pm = line.match(/^<(\d{1,3})>/);
  const { fields, order, quoted } = parseFortiGateKV(pm ? line.slice(pm[0].length) : line);
  const timestampRaw = fields.date && fields.time ? `${fields.date} ${fields.time}` : (fields.date || '');
  const ts = timestampRaw ? new Date(timestampRaw.replace(' ', 'T')) : null;
  return {
    format: 'fortigate', raw: line, lineNo,
    timestamp: ts && !isNaN(ts.getTime()) ? ts : null, timestampRaw,
    host: fields.devname || '', appName: fields.subtype || '', procid: '', msgid: '',
    severityRaw: fields.level, severityNorm: normFortiGateSeverity(fields.level),
    facility: null, facilityAuth: false,
    url: fields.url || '', httpMethod: fields.method || '',
    msg: fields.msg || '', fields, fieldOrder: order, fieldsQuoted: quoted, fgPri: pm ? pm[0] : '',
    ...(pm ? { facility: Math.floor(Number(pm[1]) / 8) } : {})
  };
}
// SonicWall 與 Sophos Firewall（SFOS）原生 key=value log（第十四輪 OH）。
// - SonicWall：`id=名稱 sn=序號 time="…" fw=位址 pri=N c=N m=訊息號 msg="…" n=N src=位址:埠:介面 dst=位址:埠:介面 proto=tcp/埠`
//   （OSSEC 解碼器內附的真實樣本與 FortiSIEM 的 SonicWall 設定指南；位址或埠可能空白）。動作看 fw_action（drop／forward），
//   沒有時以 msg 判斷：dropped／denied／blocked 為拒絕，Connection Opened／Closed 為放行，判斷不出不帶 action
// - Sophos：`device="SFW" date=… time=… device_name=… log_type="Firewall" log_subtype="Allowed|Denied" status="Allow|Deny"
//   fw_rule_id=… in_interface=… out_interface=… src_ip=… dst_ip=… protocol="TCP" src_port=… dst_port=…`
//   （Elastic Beats sophos xg 模組的真實測試 log，舊版 SFOS 格式）
// - Sophos 新版（XN110，依 Elastic integrations sophos xg 測試 log test-xg-*-new.log）：沒有 device="SFW"，改成
//   `device_name="…" timestamp="2021-11-15T18:28:48-0600" device_model=… device_serial_id=… log_id=… log_type=… log_component=… log_subtype=…
//   severity="Information"`，其餘欄位名稱相同；時間取 timestamp（含時區）
// 可單獨一行（<PRI> 後直接 key=value，format kvfw）或包在 syslog 信封裡（rfc3164／rfc5424 訊息內）
const KVFW_LINE_RE = /^(?:<\d{1,3}>)?(?:id=\S+\s+sn=\S+\s+time="|device="SFW"\s|device_name="[^"]*"\s+timestamp="\d{4}-)/;
// Sophos 新版的 timestamp：2021-11-15T18:28:48-0600（時區沒有冒號）
function sfosTime(k) {
  const t = String((k && k.timestamp) || '');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(t)) return null;
  const d = new Date(t.replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
  return isNaN(d.getTime()) ? null : d;
}
function _kvEndpoint(v) {
  const m = String(v || '').replace(/\s+/g, '').match(/^([^:]*):(\d*):?(.*)$/);
  return m ? { ip: m[1], port: m[2], intf: m[3] } : { ip: String(v || ''), port: '', intf: '' };
}
function normalizeKvFw(kv) {
  if (kv.id !== undefined && kv.sn !== undefined && kv.m !== undefined) {
    const f = {}, a = _kvEndpoint(kv.src), b = _kvEndpoint(kv.dst);
    if (a.ip) f.srcip = a.ip; if (a.port) f.srcport = a.port; if (a.intf) f.srcintf = a.intf;
    if (b.ip) f.dstip = b.ip; if (b.port) f.dstport = b.port; if (b.intf) f.dstintf = b.intf;
    const pr = String(kv.proto || '').split('/')[0];
    if (pr) f.proto = pr.toLowerCase();
    const fa = String(kv.fw_action || '').toLowerCase(), msg = String(kv.msg || '');
    if (fa === 'drop' || /\b(?:dropped|denied|blocked)\b/i.test(msg)) f.action = 'deny';
    else if (fa === 'forward' || /^Connection (?:Opened|Closed)$/i.test(msg)) f.action = 'accept';
    if (kv.usr || kv.user) f.user = kv.usr || kv.user;
    return { vendor: 'sonicwall', fields: f };
  }
  if ((kv.device === 'SFW' || (kv.device_serial_id !== undefined && kv.log_component !== undefined)) && kv.log_type !== undefined) {
    const f = {}, map = { src_ip: 'srcip', dst_ip: 'dstip', src_port: 'srcport', dst_port: 'dstport', in_interface: 'srcintf', out_interface: 'dstintf', fw_rule_id: 'policyid', user_name: 'user' };
    Object.keys(map).forEach(k => { if (kv[k] && kv[k] !== '0') f[map[k]] = kv[k]; });
    if (kv.protocol) f.proto = kv.protocol.toLowerCase();
    const st = String(kv.status || kv.log_subtype || '');
    if (/^(?:deny|denied|drop|dropped|reject)$/i.test(st)) f.action = 'deny';
    else if (/^(?:allow|allowed)$/i.test(st)) f.action = 'accept';
    return { vendor: 'sophos', fields: f };
  }
  return null;
}
// WatchGuard Firebox（XN108）：表頭「主機 [序號] [(本機 ISO 時間)] 程式[pid]: msg_id="XXXX-XXXX" 內容」，欄位順序依 Elastic
// integrations watchguard_firebox ingest pipeline 的 grok：流量為「Allow|Deny 進入介面 送出介面 [封包長度] 協定 [表頭長度 TTL]
// 來源 目的 [來源埠 目的埠] … (規則名稱)」，其後 key="value"；事件句型取自同套件測試 log（3E00 管理登入、5000 WSM 登入、
// 1100 使用者認證、0101 管理者修改設定）。只拆能確定的句型，其餘保留原文
const WG_HEAD_RE = /^(?:([^\s(]\S*)\s+)?(?:([^\s(]\S*)\s+)?(?:\((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\)\s+)?([\w./-]+)(?:\[(\d+)\])?:\s+(msg_id="[0-9A-F]{4}-[0-9A-F]{4}"[\s\S]*)$/;
const WG_TRAFFIC_RE = /^(Allow|Deny)\s+(\S+)\s+(\S+)(?:\s+\d+)?\s+([a-z]+|\d+)(?:\s+\d+\s+\d+)?\s+([\d.]+|[0-9A-Fa-f:]+)\s+([\d.]+|[0-9A-Fa-f:]+)(?:\s+(\d+)\s+(\d+))?\b/;
const WG_IP = '(\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f:]+)';
const WG_EVENT_RES = [
  [new RegExp('^Management user (\\S+) from ' + WG_IP + ' logged in'), 'admin', 'ok'],
  [new RegExp('^Management user (\\S+) from ' + WG_IP + ' log in attempt was rejected'), 'admin', 'fail'],
  [new RegExp('^WSM User (\\S+) from ' + WG_IP + ' log in attempt was rejected'), 'admin', 'fail'],
  [new RegExp('^Authentication of .+? user \\[([^\\]]+)\\] from ' + WG_IP + ' was accepted'), 'auth', 'ok'],
  [new RegExp('^Authentication of .+? user \\[([^\\]]+)\\] from ' + WG_IP + ' was rejected'), 'auth', 'fail'],
  [new RegExp('^Management user (\\S+) from ' + WG_IP + ' modified '), 'cfg', 'ok'],
];
function parseWatchGuardMsg(msg) {
  const m = String(msg || '').match(/^msg_id="([0-9A-F]{4}-[0-9A-F]{4})"\s+([\s\S]*)$/);
  if (!m) return null;
  const body = m[2], f = { wgMsgId: m[1] };
  const t = body.match(WG_TRAFFIC_RE);
  if (t) {
    f.action = t[1] === 'Deny' ? 'deny' : 'accept';
    f.srcintf = t[2]; f.dstintf = t[3]; f.proto = t[4].toLowerCase(); f.srcip = t[5]; f.dstip = t[6];
    if (t[7]) { f.srcport = t[7]; f.dstport = t[8]; }
    const pol = body.match(/\(([^()]*)\)\s*$/);
    if (pol) f.policy = pol[1];
    const kv = parseFortiGateKV(body).fields;
    ['signature_name', 'signature_id', 'severity', 'app_name', 'virus', 'src_user', 'dst_user'].forEach(k => { if (kv[k]) f[k] = kv[k]; });
    if (kv.src_user) f.user = kv.src_user;
    if (kv.msg) f.wgMsg = kv.msg;
    return { vendor: 'watchguard', fields: f };
  }
  for (const [re, kind, res] of WG_EVENT_RES) {
    const e = body.match(re);
    if (e) {
      f.user = e[1]; f.srcip = e[2];
      if (kind === 'admin') f.wgAdmin = res; else if (kind === 'auth') f.wgAuth = res; else f.wgCfg = true;
      return { vendor: 'watchguard', fields: f };
    }
  }
  const lo = body.match(/^User (\S+) is locked out/);
  if (lo) { f.user = lo[1]; f.wgLockout = true; }
  return { vendor: 'watchguard', fields: f };
}
// 包在 syslog 信封裡的 SonicWall／Sophos 訊息
function parseKvFwInMsg(msg) {
  const t = String(msg || '');
  if (!/(?:^|\s)(?:id=\S+\s+sn=|device="SFW"|device_serial_id=)/.test(t)) return null;
  const n = normalizeKvFw(parseFortiGateKV(t).fields);
  return n ? { vendor: n.vendor, fields: Object.assign({}, parseFortiGateKV(t).fields, n.fields) } : null;
}
const SFOS_SEVERITY = { emergency: 0, alert: 1, critical: 2, error: 3, warning: 4, notice: 5, information: 6, debug: 7 };
function parseKvFwLine(line, lineNo) {
  const pm = line.match(/^<(\d{1,3})>/);
  const body = pm ? line.slice(pm[0].length) : line;
  const kv = parseFortiGateKV(body);
  const n = normalizeKvFw(kv.fields);
  if (!n) return null;
  const k = kv.fields;
  let ts = null, timestampRaw = '';
  if (n.vendor === 'sonicwall') { timestampRaw = k.time || ''; ts = timestampRaw ? new Date(timestampRaw.replace(/\s+UTC$/i, 'Z').replace(' ', 'T')) : null; }
  else if (sfosTime(k)) { timestampRaw = k.timestamp; ts = sfosTime(k); }
  else { timestampRaw = k.date && k.time ? `${k.date} ${k.time}` : ''; ts = timestampRaw ? new Date(timestampRaw.replace(' ', 'T')) : null; }
  const sev = n.vendor === 'sonicwall' ? Number(k.pri) : SFOS_SEVERITY[String(k.priority || k.severity || '').toLowerCase()];
  const sevNum = Number.isFinite(sev) ? sev : (pm ? Number(pm[1]) % 8 : 6);
  return {
    format: 'kvfw', raw: line, lineNo, netFields: true, netVendor: n.vendor,
    timestamp: ts && !isNaN(ts.getTime()) ? ts : null, timestampRaw,
    // SonicWall 的 id 預設值 firewall 不是主機名稱，不當成主機
    host: n.vendor === 'sonicwall' ? (k.id && k.id !== 'firewall' ? k.id : '') : (k.device_name || ''),
    appName: n.vendor === 'sonicwall' ? (k.m ? 'm=' + k.m : '') : (k.log_type || ''), procid: '', msgid: n.vendor === 'sophos' ? (k.log_subtype || '') : (k.m || ''),
    severityRaw: String(sevNum), severityNorm: normSyslogSeverity(sevNum),
    facility: pm ? Math.floor(Number(pm[1]) / 8) : null, facilityAuth: false,
    msg: n.vendor === 'sonicwall' ? (k.msg || '') : (k.message || [k.log_component, k.log_subtype].filter(Boolean).join(' ')),
    fields: Object.assign({}, k, n.fields), kv: k, kvOrder: kv.order, kvQuoted: kv.quoted, kvPri: pm ? pm[0] : ''
  };
}
// 去識別化：所有值先換 IP／MAC（SonicWall 的 src／dst 是「位址:埠:介面」），帳號與主機／序號另外換，再重新整理對照欄位
const KVFW_USER_KEYS = ['usr', 'user', 'user_name', 'user_gp'];
const KVFW_HOST_KEYS = ['id', 'sn', 'device_name', 'device_id', 'device_serial_id'];
function anonKvFwValues(src, vendor, opts) {
  const kv = Object.assign({}, src);
  Object.keys(kv).forEach(key => {
    const v = kv[key];
    if (!v) return;
    if (KVFW_USER_KEYS.includes(key)) kv[key] = anonUser(v);
    else if (KVFW_HOST_KEYS.includes(key) && !(vendor === 'sonicwall' && key === 'id' && v === 'firewall')) kv[key] = anonHostname(v);
    else kv[key] = replaceMACsInLine(replaceIPsInLine(String(v), opts));
  });
  return kv;
}
// 包在 syslog 信封裡的訊息：訊息本身就是 key=value，依同一套規則遮蔽後重建，欄位由遮蔽後訊息重新拆
function anonKvFwMsg(clone, opts) {
  const p = parseFortiGateKV(clone.msg || '');
  const kv = anonKvFwValues(p.fields, clone.netVendor, opts);
  const lead = (String(clone.msg || '').match(/^\s*/) || [''])[0];
  clone.msg = lead + rebuildFortiGateLine({ fields: kv, fieldOrder: p.order, fieldsQuoted: p.quoted });
  const r = parseKvFwInMsg(clone.msg);
  // RFC5424 結構化資料段的欄位（已在前面遮蔽）保留，訊息拆出的同名欄位以遮蔽後的值覆蓋
  clone.fields = Object.assign({}, clone.fields, r ? r.fields : {});
}
function anonymizeKvFwEvent(clone, opts) {
  const kv = anonKvFwValues(clone.kv, clone.netVendor, opts);
  const n = normalizeKvFw(kv);
  clone.kv = kv;
  clone.fields = Object.assign({}, kv, n ? n.fields : {});
  if (clone.host) clone.host = clone.netVendor === 'sonicwall' ? (kv.id && kv.id !== 'firewall' ? kv.id : '') : (kv.device_name || '');
  clone.msg = replaceMACsInLine(replaceIPsInLine(clone.msg || '', opts));
  clone.raw = clone.kvPri + rebuildFortiGateLine({ fields: kv, fieldOrder: clone.kvOrder, fieldsQuoted: clone.kvQuoted });
}
// MikroTik RouterOS log（2026-09-29 新增）：語法依兩份獨立的真實 Logstash grok 規則
// （coolacid/logstash-grok、frap/logstash 的 patterns/mikrotik）與 MikroTik 論壇、fail2ban
// 回報的實際 log 交叉確認：訊息開頭為 topics（逗號分隔，如 system,error,critical／
// firewall,info），防火牆 log 為「[前綴 ]鏈: in:介面 out:介面, [src-mac MAC, ]proto P[ (旗標)],
// 來源[:埠]->目的[:埠], [NAT ..., ]len N」，登入為「login failure for user U from IP via 方式」
// 與「user U logged in|out from IP via 方式」。BSD syslog 模式下 topics 可能不存在，故 topics
// 為選填，但沒有 topics 時必須命中防火牆或登入語法才視為 MikroTik 訊息。
// pfSense filterlog 與 Palo Alto 流量／威脅 log 的 CSV 欄位拆解（2026-09-29 BC）：
// - pfSense：欄位順序依官方文件 Raw Filter Log Format（pfsense/docs GitHub 原始檔）——共通 9 欄
//   （規則號、子規則、anchor、tracker、實體介面、原因、動作、方向、IP 版本）；IPv4 再接 TOS、ECN、TTL、
//   ID、Offset、Flags、協定 ID、協定名稱，IPv6 再接 Class、Flow Label、Hop Limit、協定名稱、協定 ID；
//   兩者之後為長度、來源 IP、目的 IP，TCP/UDP 再接來源埠、目的埠。TAG 必須是 filterlog
// - Palo Alto：官方 Syslog Field Descriptions，TRAFFIC 與 THREAT 前 31 欄相同——索引 1 接收時間、
//   2 序號、3 類型、7 來源、8 目的、11 規則、12 來源使用者、14 應用程式、16/17 來源／目的 zone、
//   18/19 進／出介面、24/25 來源／目的埠、29 協定、30 動作；以「類型為 TRAFFIC/THREAT、接收時間為
//   YYYY/MM/DD」判定，不依賴主機名稱
function splitCSVSimple(line) {
  const out = []; let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out;
}
function parsePfSenseFilterlog(csv) {
  const f = csv.split(',');
  if (f.length < 20 || (f[8] !== '4' && f[8] !== '6')) return null;
  const v4 = f[8] === '4';
  const [protoText, base] = v4 ? [f[16], 17] : [f[12], 14];
  const fields = { rule: f[0], inintf: f[4], reason: f[5], action: f[6], direction: f[7], proto: protoText,
    srcip: f[base + 1], dstip: f[base + 2] };
  if (/^(tcp|udp)$/i.test(protoText)) { fields.srcport = f[base + 3]; fields.dstport = f[base + 4]; }
  return fields;
}
// GLOBALPROTECT／USERID（第十五輪 VC）：欄位位置依 Elastic Beats panw 模組 input 設定的欄位對照與其真實測試 log——
// GLOBALPROTECT：7 vsys、8 事件、9 階段、12 使用者、13 來源地區、14 電腦名稱、15 公用 IP、17 私有 IP、25 原因、28 狀態（success／failure）、33 設備名稱；
// USERID：4 子類型、8 來源 IP、9 使用者、10 資料來源名稱
function parsePaloAltoCSV(csv) {
  const f = splitCSVSimple(csv);
  // 時間為 YYYY/MM/DD hh:mm:ss，或 Prisma Access 等雲端轉送的 ISO 8601
  if (!/^\d{4}(?:\/\d{2}\/\d{2} |-\d{2}-\d{2}T)/.test(f[1] || '')) return null;
  if (f[3] === 'GLOBALPROTECT' && f.length >= 29) {
    const g = { logtype: f[3], vsys: f[7], eventid: f[8], stage: f[9], status: f[28] };
    if (f[12]) g.user = f[12];
    if (f[14]) g.machine = f[14];
    if (f[17] && f[17] !== '0.0.0.0') g.srcip = f[17];
    if (f[15] && f[15] !== '0.0.0.0') g.natsrcip = f[15];
    if (f[25]) g.reason = f[25];
    if (f[33]) g.devname = f[33];
    return g;
  }
  // HIPMATCH（Beats 欄位對照）：7 使用者、8 vsys、9 電腦名稱、11 來源 IP、12 HIP 名稱、24 設備名稱
  if (/^HIP-?MATCH$/.test(f[3]) && f.length >= 13) {
    const g = { logtype: 'HIPMATCH', vsys: f[8], hipname: f[12] };
    if (f[7]) g.user = f[7];
    if (f[9]) g.machine = f[9];
    if (f[11] && f[11] !== '0.0.0.0') g.srcip = f[11];
    return g;
  }
  if (f[3] === 'USERID' && f.length >= 11) {
    const g = { logtype: f[3], subtype: f[4], vsys: f[7] };
    if (f[8]) g.srcip = f[8];
    if (f[9]) g.user = f[9];
    if (f[10]) g.datasource = f[10];
    return g;
  }
  // CONFIG（官方 Config Log Fields 與 Beats 測試 log，第二十輪 FD）：7 來源位址、8 vsys、9 指令、10 管理者、11 用戶端（Web／CLI）、12 結果、13 設定路徑
  if (f[3] === 'CONFIG' && f.length >= 14) {
    const g = { logtype: 'CONFIG', vsys: f[8], cmd: f[9], client: f[11], result: f[12], cfgpath: String(f[13] || '').trim() };
    if (f[7]) g.srcip = f[7];
    // 14 變更前、15 變更後（XN41）：只留「變更前為空」與變更後內容中的管理角色，不保留設定內容本身
    if (f.length >= 16) {
      g.cfgnew = String(f[14] || '').trim() ? 'no' : 'yes';
      const rm = String(f[15] || '').match(/\b(superuser|superreader|deviceadmin|devicereader|vsysadmin|vsysreader)\b/);
      if (rm) g.cfgrole = rm[1];
    }
    if (f[10]) g.user = f[10];
    return g;
  }
  // SYSTEM（XN133）：4 子類型、7 vsys、8 事件、9 物件、12 模組、13 嚴重度、14 描述（欄位位置依 splunk-connect-for-syslog 的測試行）。
  // 認證事件的描述依 Palo Alto 官方 System Log Reference：auth-success「authenticated for user '帳號'. …, admin role '角色', … From: 來源.」、
  // auth-fail「failed authenticated for user '帳號'. … From: 來源.」（實機另見 failed authentication 的寫法，兩者都收）。
  // 描述帶 admin role 才是登入防火牆管理介面；沒有角色的是 GlobalProtect／Authentication Portal 等使用者認證
  if (f[3] === 'SYSTEM' && f.length >= 15) {
    const g = { logtype: 'SYSTEM', subtype: f[4], vsys: f[7], eventid: f[8] };
    if (f[4] === 'auth' && (f[8] === 'auth-success' || f[8] === 'auth-fail')) {
      const d = String(f[14] || '');
      // 「Admin 帳號 failed to authenticate N times…」「Admin 帳號's account is being disabled…」：帳號鎖定通知，只記帳號
      const lock = d.match(/^Admin (\S+?)(?:'s account is being disabled| failed to authenticate \d+ times)/);
      if (lock) g.user = lock[1];
      const m = d.match(/^\s*(failed authenticat(?:ed|ion)|authenticated) for user '([^']*)'/);
      if (m) {
        g.panAuth = m[1] === 'authenticated' ? 'ok' : 'fail';
        if (m[2]) g.user = m[2];
        const from = d.match(/\bFrom: ([0-9A-Fa-f:.]+?)\.?\s*$/);
        if (from && /[.:]/.test(from[1])) g.srcip = from[1];
        const role = d.match(/\badmin role '([^']+)'/);
        if (role) g.adminRole = role[1];
        const ap = d.match(/\bauth profile '([^']+)'/);
        if (ap) g.authProfile = ap[1];
      }
    }
    return g;
  }
  if (f.length < 31 || !/^(TRAFFIC|THREAT)$/.test(f[3])) return null;
  const fields = { logtype: f[3], subtype: f[4], srcip: f[7], dstip: f[8], rule: f[11], app: f[14],
    srczone: f[16], dstzone: f[17], inintf: f[18], outintf: f[19], srcport: f[24], dstport: f[25], proto: f[29], action: f[30] };
  if (f[12]) fields.user = f[12];
  // THREAT 另有 31 URL／檔名、32 威脅名稱（名稱(編號)）、33 類別、34 嚴重度、35 方向（官方 Threat Log Fields 與 Beats 測試 log，第二十輪 FC）
  if (f[3] === 'THREAT' && f.length >= 35) {
    if (f[31]) fields.url = f[31];
    const tm = String(f[32] || '').match(/^([\s\S]*?)\s*\((\d+)\)$/);
    if (f[32]) { fields.threat = tm ? tm[1] : f[32]; if (tm) fields.threatid = tm[2]; }
    if (f[33]) fields.category = f[33];
    if (f[34]) fields.threatsev = f[34];
    if (f[35]) fields.direction = f[35];
  }
  return fields;
}
// PAN-OS 入侵類威脅子類型（第二十輪 FC）：URL 過濾、檔案封鎖、資料過濾不算
const PAN_IDS_SUBTYPES = new Set(['virus', 'spyware', 'vulnerability', 'wildfire', 'wildfire-virus']);
const PAN_THREAT_SEV = { critical: 1, high: 1, medium: 2, low: 3, informational: 3 };
// Cisco Umbrella CSV 匯出（第十五輪 VG）：欄位順序依 Elastic Beats cisco umbrella 模組的 CSV 欄位定義與真實測試 log。
// Beats 依檔名分辨四種類型，這裡依欄位形狀判斷（`umbrellaKind()`）：
//   DNS：時間、使用者、身分、內部 IP、外部 IP、動作（Allowed／Blocked）、查詢類型「1 (A)」、回應碼、網域、類別…
//   IP：時間、使用者、來源 IP、來源埠、目的 IP、目的埠、類別（共 7 欄）
//   Proxy：時間、身分、內部 IP、外部 IP、目的 IP、內容類型、判定（ALLOWED／BLOCKED）、URL、參照、UA、狀態碼…類別（第 16 欄）
//   Cloud Firewall：時間（不加引號）、[來源 ID]、使用者、身分類型、方向、協定號碼、位元組、來源 IP、來源埠、目的 IP、目的埠、資料中心、規則 ID、判定（ALLOW／BLOCK）
const UMBRELLA_LINE_RE = /^(?:"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\[\d+\],)/;
function umbrellaKind(c) {
  if (/^\[\d+\]$/.test(c[1] || '') && c.length >= 14 && /^(?:INBOUND|OUTBOUND)$/i.test(c[4])) return 'cdfw';
  if (c.length >= 9 && /^(?:Allowed|Blocked)$/i.test(c[5]) && /^\d+ \(\w+\)$/.test(c[6] || '')) return 'dns';
  if (c.length >= 16 && /^(?:ALLOWED|BLOCKED)$/i.test(c[6]) && /^\w+:\/\//.test(c[7] || '')) return 'proxy';
  if (c.length === 7 && /^\d+$/.test(c[3]) && /^\d+$/.test(c[5])) return 'ip';
  return '';
}
const UMBRELLA_COLS = {
  dns: { user: 1, ident: 2, srcip: 3, natsrcip: 4, verdict: 5, qtype: 6, rcode: 7, domain: 8, categories: 9 },
  ip: { user: 1, srcip: 2, srcport: 3, dstip: 4, dstport: 5, categories: 6 },
  proxy: { ident: 1, srcip: 2, natsrcip: 3, dstip: 4, verdict: 6, url: 7, status: 10, categories: 15 },
  cdfw: { originid: 1, user: 2, idtype: 3, direction: 4, proto: 5, bytes: 6, srcip: 7, srcport: 8, dstip: 9, dstport: 10, datacenter: 11, ruleid: 12, verdict: 13 }
};
function umbrellaFields(c, kind) {
  const f = { umbrellaType: kind };
  Object.entries(UMBRELLA_COLS[kind]).forEach(([k, i]) => { if (c[i]) f[k] = c[i]; });
  if (f.domain) f.domain = f.domain.replace(/\.$/, '');
  if (f.proto) f.proto = FLOW_PROTO[f.proto] || f.proto;
  if (f.verdict) { if (/^block/i.test(f.verdict)) f.action = 'deny'; else if (/^allow/i.test(f.verdict)) f.action = 'accept'; }
  return f;
}
function parseUmbrellaLine(line, lineNo) {
  const c = splitCSVSimple(line), kind = umbrellaKind(c);
  if (!kind) return null;
  const f = umbrellaFields(c, kind);
  const t = new Date(c[0].replace(' ', 'T') + 'Z');
  const what = kind === 'dns' ? `${f.verdict || ''} ${f.qtype || ''} ${f.domain || ''}` : (kind === 'proxy' ? `${f.verdict || ''} ${f.url || ''}` : `${f.verdict || ''} ${f.srcip || ''}${f.srcport ? ':' + f.srcport : ''} -> ${f.dstip || ''}${f.dstport ? ':' + f.dstport : ''}`);
  return {
    format: 'umbrella', raw: line, lineNo, netFields: true, netVendor: 'umbrella', umbrellaQuoted: line[0] === '"',
    timestamp: isNaN(t.getTime()) ? null : t, timestampRaw: c[0],
    host: '', appName: 'umbrella-' + kind, procid: '', msgid: kind,
    severityRaw: '', severityNorm: f.action === 'deny' ? 'Low' : 'Info', facility: null, facilityAuth: false,
    msg: what.trim(), fields: f, umbrellaCols: c
  };
}
// 去識別化：帳號／身分欄換假名、其餘欄位換 IP，依原引號格式重建後重新拆欄位
function anonUmbrellaEvent(clone, opts) {
  const c = clone.umbrellaCols.slice(), kind = clone.fields.umbrellaType, cols = UMBRELLA_COLS[kind];
  c.forEach((v, i) => {
    if (!v) return;
    if (i === cols.user || i === cols.ident) c[i] = v.split(/,\s*/).map(u => anonUser(u)).join(', ');
    else if (i > 0) c[i] = replaceMACsInLine(replaceIPsInLine(v, opts));
  });
  clone.umbrellaCols = c;
  clone.fields = umbrellaFields(c, kind);
  clone.raw = c.map(v => clone.umbrellaQuoted ? '"' + v.replace(/"/g, '""') + '"' : (/[",]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v)).join(',');
  clone.msg = replaceIPsInLine(clone.msg || '', opts);
}
function parsePanCSVLine(line, lineNo) {
  const f = splitCSVSimple(line);
  const fields = parsePaloAltoCSV(line) || { logtype: f[3], subtype: f[4] };
  const t = new Date(/T/.test(f[1] || '') ? f[1] : String(f[1]).replace(/\//g, '-').replace(' ', 'T'));
  return {
    // SYSTEM 沒有來源或帳號時也走廠牌去識別化（設備名稱欄與描述內的管理者帳號，XN133）
    format: 'pancsv', raw: line, lineNo, netFields: !!(fields.srcip || fields.user) || fields.logtype === 'SYSTEM', netVendor: 'paloalto',
    timestamp: isNaN(t.getTime()) ? null : t, timestampRaw: f[1] || '',
    host: '', appName: f[3] || '', procid: '', msgid: f[4] || '',
    severityRaw: '', severityNorm: 'Info', facility: null, facilityAuth: false,
    msg: line, fields
  };
}
// Linux netfilter（iptables／nftables）核心 LOG 訊息（2026-10-02，第十輪發想 ZK）：格式依 Linux 核心
// net/netfilter/nf_log_syslog.c——「log 前綴」IN=介面 OUT=介面 [PHYSIN=… PHYSOUT=…] [MAC=目的:來源:型別]
// SRC=… DST=… LEN=… … PROTO=TCP|UDP|ICMP|數字 [SPT=… DPT=…]；iptables LOG 與 nftables log 共用同一格式。
// 前綴是管理者自訂文字，含 DROP／BLOCK／REJECT／DENY 視為拒絕、ACCEPT／ALLOW／PASS 視為允許，其餘不判斷
function parseNetfilterLog(msg) {
  const m = String(msg || '').match(/^(?:\[\s*\d+\.\d+\]\s*)?([\s\S]*?)\bIN=(\S*) OUT=(\S*) (?:PHYSIN=\S+ )?(?:PHYSOUT=\S+ )?(?:MAC=(\S*) )?SRC=(\S+) DST=(\S+) ([\s\S]*)$/);
  if (!m) return null;
  const [, prefix, inIf, outIf, mac, src, dst, rest] = m;
  const fields = { inintf: inIf, outintf: outIf, srcip: src, dstip: dst };
  const px = prefix.trim().replace(/^\[|\]$/g, '').trim();
  if (px) fields.logprefix = px;
  const hex = (mac || '').split(':');
  if (hex.length >= 12) { fields.dstmac = hex.slice(0, 6).join(':'); fields.srcmac = hex.slice(6, 12).join(':'); }
  const g = re => (rest.match(re) || [])[1];
  const proto = g(/\bPROTO=(\S+)/); if (proto) fields.proto = proto;
  const spt = g(/\bSPT=(\d+)/), dpt = g(/\bDPT=(\d+)/);
  if (spt) fields.srcport = spt; if (dpt) fields.dstport = dpt;
  const len = g(/\bLEN=(\d+)/); if (len) fields.len = len;
  // EdgeRouter／VyOS 1.3 的 `[規則集-規則編號-A|D|R]` 與 VyOS 1.4 起的 `[ipv4|ipv6|bri-FWD|INP|OUT|PRE-filter-編號-動作]`、
  // `[ipv4-NAM-規則集-編號-動作]`（編號可為 default＝預設動作；A＝accept、D＝drop、R＝reject；格式依 Beats iptables 模組
  // 的 Ubiquiti 解析規則、vyos-1x smoketest test_firewall.py，第十六輪 PC）。ruleset 與 VyOS 解析器的規則鏈名稱一致
  const vy = px.match(/^(?:(ipv4|ipv6|bri)-(FWD|INP|OUT|PRE|NAM)-)?(.+)-(\d+|default)-([ADR])$/);
  if (vy) {
    const HOOK = { FWD: 'forward', INP: 'input', OUT: 'output', PRE: 'prerouting' };
    fields.ruleset = vy[1] && vy[2] !== 'NAM' ? `${vy[1]}-${HOOK[vy[2]]}` : vy[3];
    fields.rulenum = vy[4];
    fields.action = vy[5] === 'A' ? 'accept' : 'deny';
  // 前綴常以底線連字（DROP_INPUT、FW_BLOCK），以非英文字母為邊界（第二十輪 FA）
  } else if (/(?:^|[^a-z])(?:drop|dropped|block|blocked|reject|rejected|deny|denied)(?![a-z])/i.test(px)) fields.action = 'deny';
  else if (/(?:^|[^a-z])(?:accept|accepted|allow|allowed|pass)(?![a-z])/i.test(px)) fields.action = 'accept';
  return fields;
}
// Juniper SRX 工作階段紀錄 RT_FLOW（2026-10-02，第十輪 ZL）：
// - 結構化（RFC5424，`set system syslog … structured-data`）：MSGID 為 RT_FLOW_SESSION_CREATE／CLOSE／DENY，SD 段
//   [junos@2636… source-address="…" source-port="…" destination-address="…" destination-port="…" protocol-id="…"
//   policy-name="…" source-zone-name="…" destination-zone-name="…" nat-source-address="…" reason="…" bytes-from-client="…"]，
//   欄位名稱依 elastic/beats juniper srx 模組的真實測試紀錄（x-pack/filebeat/module/juniper/srx/test/flow.log）
// - 純文字（BSD syslog）：`RT_FLOW_SESSION_DENY: session denied 11.22.33.44/36619->55.66.77.88/23 junos-telnet 6(0) 政策 來源區域 目的區域 …`、
//   `RT_FLOW_SESSION_CREATE: session created 192.168.1.102/58662->8.8.8.8/53 junos-dns-udp …`（Juniper 社群與文件實例）；
//   只取第一組位址／埠與服務，拒絕紀錄另取協定、政策與區域（建立／關閉紀錄後段欄位依版本而異，不猜測）
const JUNOS_FLOW_PROTO = { '6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6' };
function parseJunosRtFlow(msgid, sd, msg) {
  const ev = (msgid || '').match(/^RT_FLOW_SESSION_(CREATE|CLOSE|DENY)/) || String(msg || '').match(/\bRT_FLOW_SESSION_(CREATE|CLOSE|DENY)\b/);
  if (!ev) return null;
  const kind = ev[1].toLowerCase();
  const f = { flowEvent: kind, action: kind === 'deny' ? 'deny' : 'accept' };
  if (sd && sd['source-address']) {
    const v = k => (sd[k] && sd[k] !== 'N/A' && sd[k] !== 'None' ? sd[k] : '');
    f.srcip = v('source-address'); f.dstip = v('destination-address');
    if (v('source-port')) f.srcport = v('source-port');
    if (v('destination-port')) f.dstport = v('destination-port');
    if (v('protocol-id')) f.proto = JUNOS_FLOW_PROTO[v('protocol-id')] || v('protocol-id');
    [['policy', 'policy-name'], ['srczone', 'source-zone-name'], ['dstzone', 'destination-zone-name'], ['service', 'service-name'],
     ['natsrcip', 'nat-source-address'], ['natdstip', 'nat-destination-address'], ['srcintf', 'packet-incoming-interface'], ['reason', 'reason'],
     ['user', 'username'], ['app', 'application']].forEach(([k, src]) => { if (v(src) && v(src) !== 'UNKNOWN') f[k] = v(src); });
    if (sd['bytes-from-client'] !== undefined) f.bytes = String(Number(sd['bytes-from-client'] || 0) + Number(sd['bytes-from-server'] || 0));
    return f.srcip ? f : null;
  }
  const m = String(msg || '').match(/session (?:created|denied|closed[^:]*:)\s*([0-9a-fA-F.:]+)\/(\d+)-+>([0-9a-fA-F.:]+)\/(\d+)\s+(\S+)(?:\s+(\d+)\(\d+\)\s+(\S+)\s+(\S+)\s+(\S+))?/);
  if (!m) return null;
  Object.assign(f, { srcip: m[1], srcport: m[2], dstip: m[3], dstport: m[4] });
  if (m[5] !== 'None') f.service = m[5];
  if (kind === 'deny' && m[6]) Object.assign(f, { proto: JUNOS_FLOW_PROTO[m[6]] || m[6], policy: m[7], srczone: m[8], dstzone: m[9] });
  return f;
}
// Juniper SRX 其他安全紀錄（第十五輪 VF）：RT_IDP（IDP_ATTACK_LOG_EVENT）、RT_IDS（RT_SCREEN_*）、RT_UTM（WEBFILTER_*）、
// RT_AAMW（SRX_AAMW_ACTION_LOG／AAMW_MALWARE_EVENT_LOG）、RT_SECINTEL（SECINTEL_ACTION_LOG），RFC5424 SD 欄位名稱依 Elastic Beats
// juniper srx 模組的真實測試 log。action 含 drop／block／reject／deny／close 為拒絕，*_PERMITTED 為放行；
// IDP 攻擊與 IDS 螢幕告警帶 attack（attack-name）與 threatsev，交給 detectIdsAlerts() 建 idsAlert 問題
const JUNOS_SEC_KIND = { RT_IDP: 'idp', RT_IDS: 'ids', RT_UTM: 'utm', RT_AAMW: 'aamw', RT_SECINTEL: 'secintel' };
function parseJunosSecLog(app, msgid, sd) {
  const kind = JUNOS_SEC_KIND[app];
  if (!kind || !sd) return null;
  const v = k => (sd[k] && !/^(?:N\/A|None|UNKNOWN)$/i.test(sd[k]) ? sd[k] : '');
  const f = { jsec: kind, event: msgid || '' };
  const src = v('source-address') || v('client-ip');
  if (src) f.srcip = src;
  if (v('destination-address')) f.dstip = v('destination-address');
  if (v('source-port')) f.srcport = v('source-port');
  if (v('destination-port')) f.dstport = v('destination-port');
  if (v('protocol-name')) f.proto = v('protocol-name').toLowerCase();
  else if (v('protocol-id')) f.proto = JUNOS_FLOW_PROTO[v('protocol-id')] || v('protocol-id');
  [['attack', 'attack-name'], ['threatsev', 'threat-severity'], ['policy', 'policy-name'], ['srczone', 'source-zone-name'], ['dstzone', 'destination-zone-name'],
   ['user', 'username'], ['url', 'url'], ['category', 'category'], ['feed', 'feed-name'], ['malware', 'malware-info'], ['srcintf', 'interface-name']].forEach(([k, s2]) => { if (v(s2)) f[k] = v(s2); });
  const act = v('action') + ' ' + v('action-detail');
  if (/\b(?:drop|block|blocked|reject|deny|close)\b/i.test(act) || /_BLOCKED$/.test(msgid || '')) f.action = 'deny';
  else if (/_PERMITTED$/.test(msgid || '') || /\b(?:permit|accept|allow)\b/i.test(act)) f.action = 'accept';
  return f.srcip || f.attack || f.malware ? f : null;
}
// H3C 防火牆工作階段／過濾紀錄（2026-10-05，第十一輪 KC）：Comware V7 安全產品的 SESSION_IPV4_FLOW、
// FILTER_ZONE_IPV4_EXECUTION 等訊息內容為「欄位名稱(編號)=值;」串接，欄位名稱依 H3C Security Products
// Comware 7 System Log Messages Reference 與 Flow log 設定文件的搜尋摘要確認（h3c.com 被網路政策擋下，信心度中等）：
// Protocol(1001)、SrcIPAddr(1003)、SrcPort(1004)、NatSrcIPAddr(1005)、NatSrcPort(1006)、DstIPAddr(1007)、DstPort(1008)、
// NatDstIPAddr(1009)、RcvIfName(1023)、SrcZoneName(1025)、DstZoneName(1035)、Event(1048)、Action(1053)、Acl(1068)。
// 依欄位名稱取值（不依編號），未列出的欄位不拆；Event／Action 含 deny／drop／block／reject 視為拒絕
const H3C_FLOW_KEYS = { Protocol: 'proto', SrcIPAddr: 'srcip', SrcPort: 'srcport', NatSrcIPAddr: 'natsrcip', NatSrcPort: 'natsrcport',
  DstIPAddr: 'dstip', DstPort: 'dstport', NatDstIPAddr: 'natdstip', RcvIfName: 'srcintf', SrcZoneName: 'srczone', DstZoneName: 'dstzone', Acl: 'acl' };
function parseH3CFlowLog(msg) {
  const t = String(msg || '');
  if (!/\bSrcIPAddr\(\d{4}\)=/.test(t)) return null;
  const kv = {};
  t.replace(/([A-Za-z]+)\(\d{4}\)=([^;]*)/g, (m, k, v) => { kv[k] = v.trim(); return m; });
  if (!kv.SrcIPAddr || !kv.DstIPAddr) return null;
  const f = {};
  Object.keys(H3C_FLOW_KEYS).forEach(k => { if (kv[k]) f[H3C_FLOW_KEYS[k]] = kv[k]; });
  if (f.proto) f.proto = f.proto.toLowerCase();
  const ev = kv.Event || kv.Action || '';
  if (ev) f.flowEvent = ev;
  if (/deny|denied|drop|block|reject/i.test(ev)) f.action = 'deny';
  else if (/permit|pass|accept|allow|creat/i.test(ev)) f.action = 'accept';
  return f;
}
function parseVendorCSVFields(appName, msg) {
  if (appName === 'filterlog') { const fields = parsePfSenseFilterlog(msg || ''); return fields ? { vendor: 'pfsense', fields } : null; }
  const nf = parseNetfilterLog(msg);
  if (nf) return { vendor: 'netfilter', fields: nf };
  const pa = parsePaloAltoCSV(msg || '');
  return pa ? { vendor: 'paloalto', fields: pa } : null;
}
// ── 網路設備原生 log 與維運事件（2026-09-29 WC／WD）─────────────────────────────
// Cisco IOS（Cisco 官方 System Message Guide 與 show logging 實例）：
//   [<PRI>][序號: ][*|.]時間: %設施-等級-助記碼: 訊息；時間可為「Mmm dd [yyyy] hh:mm:ss[.ms] [時區]」
//   或開機後經過時間（00:00:47、1w2d）。後者沒有日期，時間留空
// Comware（H3C System Log Messages Reference 與 Information center 命令參考）：
//   display logbuffer：%Mmm dd hh:mm:ss:ms yyyy 系統名稱 設施/等級/摘要: 訊息
//   syslog：<PRI>Mmm dd hh:mm:ss yyyy 系統名稱 %%10設施/等級/摘要(l): 訊息
const CISCO_IOS_LOG_RE = /^(?:<(\d{1,3})>)?(?:(\d+):\s+)?(?:([*.]?)((?:[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+)?\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Za-z]{2,5})?|\d+[ywdh]\d+[ywdhm](?:\d+[dhm])?)\s*:\s*)?%([A-Z][A-Z0-9_]*)-(\d)-([A-Z0-9_]+):\s*([\s\S]*)$/;
const COMWARE_LOG_RE = /^(?:<(\d{1,3})>)?(%?)([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})(?::(\d{1,3}))?\s+(\d{4})\s+(\S+)\s+((?:%%\d{2})?([A-Z][A-Z0-9_]*)\/(\d)\/([A-Z0-9_]+)(?:\([a-z]\))?:\s*)([\s\S]*)$/;
function parseCiscoIOSLine(line, lineNo) {
  const m = line.match(CISCO_IOS_LOG_RE);
  if (!m) return null;
  const [, pri, , , ts, fac, level, mnem, msg] = m;
  let timestamp = null;
  const tm = ts && ts.match(/^([A-Z][a-z]{2})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d{1,2}:\d{2}:\d{2})/);
  if (tm) {
    const d = new Date(`${tm[1]} ${tm[2]} ${tm[3] || new Date().getFullYear()} ${tm[4]}`);
    if (!isNaN(d.getTime())) timestamp = tm[3] ? d : fixFutureYear(d);
  }
  const hasPri = pri !== undefined;
  const facility = hasPri ? Math.floor(Number(pri) / 8) : null;
  const acl = parseCiscoAclLog(mnem, msg);
  return {
    format: 'ciscoios', raw: line, lineNo, netFields: !!acl, netVendor: acl ? 'ciscoios' : '',
    timestamp, timestampRaw: ts || '',
    host: '', appName: fac, procid: '', msgid: mnem,
    severityRaw: level, severityNorm: normSyslogSeverity(Number(level)),
    facility, facilityAuth: false,
    msg, fields: acl || {},
    // 重建（去識別化）用：訊息前的原樣前綴不含主機名稱／IP／帳號
    rawPrefix: line.slice(0, line.length - msg.length)
  };
}
function parseComwareLine(line, lineNo) {
  const m = line.match(COMWARE_LOG_RE);
  if (!m) return null;
  const [, pri, pct, ts, , yyyy, host, tag, fac, level, digest, msg] = m;
  const d = new Date(`${ts.replace(/\s+\d{2}:.*/, '')} ${yyyy} ${ts.match(/\d{2}:\d{2}:\d{2}/)[0]}`);
  const hasPri = pri !== undefined;
  const facility = hasPri ? Math.floor(Number(pri) / 8) : null;
  const hostIdx = line.indexOf(' ' + host + ' ');
  const hf = parseH3CFlowLog(msg);
  return {
    format: 'comware', raw: line, lineNo, netFields: !!hf, netVendor: hf ? 'h3c' : '',
    timestamp: isNaN(d.getTime()) ? null : d, timestampRaw: `${ts} ${yyyy}`,
    host, appName: fac, procid: '', msgid: digest,
    severityRaw: level, severityNorm: normSyslogSeverity(Number(level)),
    facility, facilityAuth: false,
    msg, fields: hf || {},
    rawHead: line.slice(0, hostIdx + 1), rawTag: tag
  };
}
// 維運事件辨識：回傳 {kind, iface, state, layer, user, srcip, detail, major} 或 null。
// 各廠牌語法（皆為官方文件或實際 log 查得的固定句型）：
// - Cisco：LINK-x-UPDOWN／LINEPROTO-x-UPDOWN、PM-x-ERR_DISABLE、SPANTREE-*、ILPOWER-*、ENVMON／
//   PLATFORM_ENV／ENVIRONMENT(AL)-*、SYS-5-CONFIG_I；經 syslog 轉存時也會出現在其他格式的訊息中
// - Comware：IFNET/x/PHY_UPDOWN、IFNET/x/LINK_UPDOWN、SHELL/x/SHELL_CMD
// - Juniper：SNMP_TRAP_LINK_DOWN／UP、UI_COMMIT
// - FortiGate：logid 0100044546（屬性設定）／0100044547（物件屬性設定）
// - MikroTik：「… changed by 帳號」
const ASA_READONLY_CMD_RE = /^(?:show|sh|ping|traceroute|terminal|more|dir|enable|exit|quit|help|who|history|logout)\b/i;
const COMWARE_READONLY_CMD_RE = /^\s*(dis(?:play)?|ping|tracert|quit|return|screen-length|terminal|undo\s+terminal|dir|more|save|sys(?:tem-view)?|help|history|super)\b/i;
function netOpsInfo(evt) {
  if (!evt) return null;
  const f = evt.fields || {};
  // Aruba ClearPass 稽核紀錄（XN134）：管理者對設定的新增／修改／刪除
  if (evt.netVendor === 'clearpass') return f.cppm === 'audit' ? { kind: 'configChange', user: f.user || '', srcip: '', detail: [f.cppmAction, f.cppmCategory].filter(Boolean).join(' ') } : null;
  if (evt.format === 'fortigate') {
    if (f.logid === '0100044546' || f.logid === '0100044547') {
      const ipm = String(f.ui || '').match(/\(([\d.:a-fA-F]+)\)/);
      return { kind: 'configChange', user: f.user || '', srcip: ipm ? ipm[1] : '', detail: [f.action, f.cfgpath, f.cfgobj].filter(Boolean).join(' ') };
    }
    return null;
  }
  if (evt.cloudRaw) {
    const ci = cloudAuthInfo(evt.cloudRaw);
    if (ci && ci.ok && !ci.pending && CLOUD_FW_CHANGE_RE.test(ci.event || '')) return { kind: 'configChange', user: ci.user || '', srcip: f.srcip || '', detail: ci.event };
    return null;
  }
  // Cisco ASA／FTD 指令紀錄（第二十輪 FD，句型依 Cisco ASA syslog 訊息說明與 Beats 測試 log）：111008 User 'X' executed the 'cmd' command、
  // 111010 User 'X', running 'CLI' from IP 位址, executed 'cmd'；show／ping 等唯讀指令不算
  if (evt.format === 'asa' && (evt.msgid === '111008' || evt.msgid === '111010')) {
    const t = evt.msg || '';
    const mm = t.match(/^User '([^']*)', running '[^']*' from IP (\S+), executed '([\s\S]*)'\s*$/) || t.match(/^User '([^']*)' executed the '([\s\S]*)' command/);
    if (!mm) return null;
    const cmd = (mm.length === 4 ? mm[3] : mm[2]).trim();
    if (ASA_READONLY_CMD_RE.test(cmd)) return null;
    return { kind: 'configChange', user: mm[1], srcip: mm.length === 4 ? mm[2] : '', detail: cmd };
  }
  // FortiMail／FortiManager（XN123）：FortiMail kevent／config；FortiManager 物件、腳本、政策套件與設備設定由使用者執行（非 System）
  if (evt.netVendor === 'fortimail' && f.fmType === 'kevent' && f.fmSub === 'config') return { kind: 'configChange', user: f.user || '', srcip: f.srcip || '', detail: f.fmMsg || '' };
  if (evt.netVendor === 'fortimanager' && f.user && !f.fmgUnreg && !/^(?:system|fgfm)$/i.test(f.user) && (/^(?:objcfg|scrmgr|scply)$/.test(f.fmSub) || (f.fmSub === 'dvm' && /device/i.test(f.fmAction || ''))))
    return { kind: 'configChange', user: f.user, srcip: f.srcip || '', detail: f.fmChanges || f.fmMsg || f.fmAction || '' };
  // Stormshield（XN122）：管理指令（server log）error=0 且不是查詢類指令
  if (evt.netVendor === 'stormshield' && f.sns === 'server' && f.snsError === '0' && f.snsMsg && !SNS_READONLY_CMD_RE.test(f.snsMsg))
    return { kind: 'configChange', user: f.user || '', srcip: f.srcip || '', detail: f.snsMsg };
  // Vault（XN117）：sys/ 底下政策、認證方式、稽核裝置、掛載點等成功的建立／修改／刪除
  if (evt.netVendor === 'vault' && f.vault === 'response' && !f.error && /^(?:create|update|delete)$/.test(f.op) && VAULT_CHANGE_RE.test(f.path || ''))
    return { kind: 'configChange', user: f.user || '', srcip: f.srcip || '', detail: `${f.op} ${f.path}` };
  // Zscaler（XN113）：管理入口網站稽核中成功的建立／修改／刪除／啟用（登入、登出、下載等不算）
  if (evt.netVendor === 'zscaler' && f.zs === 'audit' && f.action && /^SUCCESS$/i.test(f.result || '') && !/^LOGIN$/i.test(f.zsCat || '') && !ZS_READONLY_ACTION_RE.test(f.action))
    return { kind: 'configChange', user: f.user || '', srcip: f.srcip || '', detail: [f.action, [f.zsCat, f.zsSub].filter(Boolean).join('/'), f.resource].filter(Boolean).join(' ') };
  // Veeam（XN112）：帳號、認證資料、角色、加密密碼、MFA 與四眼授權的變更
  if (evt.netVendor === 'veeam' && (f.veeamKind === 'change' || f.veeamKind === 'defense')) return { kind: 'configChange', user: f.user || '', srcip: f.srcip || '', detail: evt.msg || '' };
  // QNAP（XN111）：帳號、群組、共享資料夾、網路設定的變更（有帳號才算，系統自動作業不算）
  if (evt.netVendor === 'qnap' && f.qnap === 'event' && f.user && !/^system$/i.test(f.user) && /^(?:Users|User Groups|Shared Folders|Network & Virtual Switch|Privilege Settings)$/.test(f.app || '')
    && /\] (?:Created|Deleted|Changed|Edited|Added|Removed|Enabled|Disabled)\b/.test(f.content || '')) return { kind: 'configChange', user: f.user, srcip: f.srcip || '', detail: f.content };
  // NetScaler（XN109）：UI CMD_EXECUTED，show／stat 等唯讀指令與失敗的指令不算
  if (evt.netVendor === 'netscaler' && f.command && f.nsEvent === 'CMD_EXECUTED') {
    if (/^(?:show|sh|stat|ping|traceroute|help|whoami|exit|quit|logout|login|batch|shell)\b/i.test(f.command) || !/^Success/i.test(f.status || '')) return null;
    return { kind: 'configChange', user: f.user || '', srcip: f.srcip || '', detail: f.command };
  }
  // WatchGuard（XN108）：0101-0001「Management user X from IP modified 項目」
  if (evt.netVendor === 'watchguard' && f.wgCfg) {
    const mm = String(evt.msg || '').match(/ modified (.+)$/);
    return { kind: 'configChange', user: f.user || '', srcip: f.srcip || '', detail: mm ? mm[1] : '' };
  }
  // Palo Alto CONFIG 紀錄（第二十輪 FD）：管理者、來源位址、指令與設定路徑
  if (evt.netVendor === 'paloalto' && f.logtype === 'CONFIG') {
    if (/^show$/i.test(f.cmd || '')) return null;
    return { kind: 'configChange', user: f.user || '', srcip: f.srcip || '', detail: [f.cmd, f.cfgpath, f.result].filter(Boolean).join(' ') };
  }
  let fac = '', tag = '', lvl = null, text = evt.msg || '';
  // HPE Aruba CX（XN121）：依事件編號判斷
  if (evt.netVendor === 'arubacx' && evt.fields && evt.fields.cx) {
    const cf = evt.fields, id = cf.cx, t = cf.cxText || '';
    let x;
    if ((id === '403' || id === '404') && (x = t.match(/^Link status for interface (\S+) is (up|down)/i))) return { kind: 'linkUpDown', iface: x[1], state: x[2].toLowerCase(), layer: 'phy' };
    if (/^(?:2801|2802|2809)$/.test(id)) { x = t.match(/^Ports? (?:TX )?(\S+)/); return { kind: 'errDisable', iface: x ? x[1] : '', detail: 'loop-protect' }; }
    if (id === '2007' || id === '5004') { x = t.match(/^Port (\S+) disabled/); return { kind: 'errDisable', iface: x ? x[1] : '', detail: 'bpdu-protection' }; }
    if (id === '4104') { x = t.match(/UDLD interface (\S+) is blocked/); return { kind: 'errDisable', iface: x ? x[1] : '', detail: 'udld' }; }
    if (id === '4801' && (x = t.match(/^MAC (\S+) moved from port (\S+) to port (\S+) on VLAN (\d+)/))) return { kind: 'macFlap', mac: x[1].toLowerCase(), vlan: x[4], iface: x[2], iface2: x[3] };
    if (/^(?:2014|2016|5008)$/.test(id)) { x = t.match(/VLAN (\d+)/i); return { kind: 'stpChange', detail: t.slice(0, 60), vlan: x ? x[1] : '', major: false }; }
    if (/^[23]\d\d$/.test(id) && /^LOG_(?:WARN|ERR|CRIT|ALERT|EMER)/.test(cf.cxLevel || '')) return { kind: 'hwAlarm', detail: t.slice(0, 80) };
    if ((id === '4613' || id === '4614') && (x = t.match(/^(\S+) has (?:written|copied)/))) return { kind: 'configChange', user: x[1], srcip: '', detail: t };
    return null;
  }
  if (evt.format === 'ciscoios' || evt.format === 'comware') { fac = evt.appName; tag = evt.msgid; lvl = Number(evt.severityRaw); }
  else {
    let m = text.match(/%([A-Z][A-Z0-9_]*)-(\d)-([A-Z0-9_]+):\s*([\s\S]*)/);
    if (m) { fac = m[1]; lvl = Number(m[2]); tag = m[3]; text = m[4]; }
    else if ((m = text.match(/\b([A-Z][A-Z0-9_]*)\/(\d)\/([A-Z0-9_]+)(?:\([a-z]\))?:\s*([\s\S]*)/))) { fac = m[1]; lvl = Number(m[2]); tag = m[3]; text = m[4]; }
  }
  let m;
  // 介面上下線
  if ((fac === 'LINK' || fac === 'LINEPROTO') && tag === 'UPDOWN') {
    m = text.match(/Interface ([^,\s]+), changed state to (administratively down|up|down)/i);
    if (m) return { kind: 'linkUpDown', iface: m[1], state: /down/i.test(m[2]) ? 'down' : 'up', layer: fac === 'LINK' ? 'phy' : 'proto' };
  }
  if (fac === 'IFNET' && (tag === 'PHY_UPDOWN' || tag === 'LINK_UPDOWN')) {
    m = text.match(/on the interface (\S+?) changed to (up|down)/i);
    if (m) return { kind: 'linkUpDown', iface: m[1], state: m[2].toLowerCase(), layer: tag === 'PHY_UPDOWN' ? 'phy' : 'proto' };
  }
  if ((m = text.match(/\bSNMP_TRAP_LINK_(DOWN|UP): ifIndex \d+, ifAdminStatus [^,]+, ifOperStatus [^,]+, ifName (\S+)/))) {
    return { kind: 'linkUpDown', iface: m[2], state: m[1].toLowerCase(), layer: 'phy' };
  }
  // MAC 飄移（2026-10-02，第十輪 ZQ）：同一 MAC 在兩個埠之間來回學習，常見於迴圈或未設定聚合的雙連線。句型：
  // Cisco IOS／IOS-XE `%SW_MATM-4-MACFLAP_NOTIF: Host 286e.d422.926d in vlan 1 is flapping between port Gi1/0/12 and port Gi1/0/11`
  // （Cisco 官方 Troubleshoot MAC Flaps 文件與社群實例）；NX-OS `%L2FM-4-L2FM_MAC_MOVE: Mac 0050.5695.1ac8 in vlan 150
  // has moved from Po6 to Po5`（Cisco 官方 L2FM_MAC_MOVE 說明）；H3C `MAC address 0000-0012-0034 in vlan 500 has flapped
  // from port XGE2/10/0/16 to port GE1/3/0/1 1 time(s).`（H3C MAC Address Table Commands 文件範例）
  if ((m = text.match(/\bHost ([0-9a-fA-F.:-]{12,17}) in vlan (\d+) is flapping between port (\S+?) and port (\S+?)[.,]?(?=\s|$)/i)) ||
      (m = text.match(/\bMac ([0-9a-fA-F.:-]{12,17}) in vlan (\d+) has moved from (\S+?) to (\S+?)\.?(?=\s|$)/i)) ||
      (m = text.match(/\bMAC address ([0-9a-fA-F.:-]{12,17}) in vlan (\d+) has flapped from port (\S+?) to port (\S+?)(?=\s|$)/i))) {
    return { kind: 'macFlap', mac: m[1].toLowerCase(), vlan: m[2], iface: m[3], iface2: m[4] };
  }
  // err-disable（含 BPDU Guard 關閉 port）
  if (tag === 'ERR_DISABLE' || /\bin err-disable state\b/i.test(text)) {
    m = text.match(/putting (\S+) in err-disable/i) || text.match(/ on (\S+?),/);
    const cause = text.match(/^(\S+) error detected/i);
    return { kind: 'errDisable', iface: m ? m[1] : '', detail: cause ? cause[1] : '' };
  }
  if (fac === 'SPANTREE' && tag === 'BLOCK_BPDUGUARD') {
    m = text.match(/port (\S+?)[ .,]/);
    return { kind: 'errDisable', iface: m ? m[1] : '', detail: 'bpduguard' };
  }
  if (fac === 'SPANTREE') {
    m = text.match(/vlan (\d+)/i) || text.match(/VLAN0*(\d+)/);
    return { kind: 'stpChange', detail: tag, vlan: m ? m[1] : '', major: /ROOTCHANGE|GUARD_BLOCK/.test(tag) };
  }
  // PoE：拒絕供電、過載、控制器錯誤（一般的授予供電不列入）
  if (fac === 'ILPOWER' && (/DENY|ERR|FAULT|OVERDRAWN|SHUT/.test(tag) || (lvl !== null && lvl <= 4))) {
    m = text.match(/Interface (\S+?)[:,\s]/) || text.match(/ on (\S+?)[:,\s]/);
    return { kind: 'poeFault', iface: m ? m[1] : '', detail: tag };
  }
  // 硬體環境告警（風扇、電源、溫度）：嚴重度 4（警告）以上才列入
  if (/^(ENVMON|PLATFORM_ENV|ENVIRONMENT|ENVIRONMENTAL)$/.test(fac) && lvl !== null && lvl <= 4) {
    return { kind: 'hwAlarm', detail: tag };
  }
  // 設定變更
  if (fac === 'SYS' && tag === 'CONFIG_I') {
    m = text.match(/Configured from (\S+) by (\S+)(?: on (\S+))?(?: \(([^)]+)\))?/);
    const by = m ? m[2] : '';
    const isLine = /^(vty\d+|console|con\d+|tty\d+|aux\d*)$/i.test(by);
    return { kind: 'configChange', user: isLine ? '' : by, srcip: m && m[4] ? m[4] : '', detail: m ? `${m[1]} ${isLine ? by : (m[3] || '')}`.trim() : '' };
  }
  if (fac === 'SHELL' && tag === 'SHELL_CMD') {
    m = text.match(/-Line=([^-]*)-IPAddr=([^-]*)-User=([^;]*); Command is (.*)$/);
    if (!m || COMWARE_READONLY_CMD_RE.test(m[4])) return null;
    const clean = v => (v && v !== '**' ? v : '');
    return { kind: 'configChange', user: clean(m[3]), srcip: clean(m[2]), detail: m[4].trim() };
  }
  if ((m = text.match(/\bUI_COMMIT: User '([^']+)' requested '([^']+)' operation/))) {
    return { kind: 'configChange', user: m[1], detail: m[2] };
  }
  const mc = evt.mikrotik ? mikrotikCfgOf(evt) : null;
  if (mc) return { kind: 'configChange', user: mc.user, detail: `${mc.obj} ${mc.op}` };
  return null;
}
const NETOPS_CATEGORIES = new Set(['linkUpDown', 'errDisable', 'stpChange', 'poeFault', 'hwAlarm', 'configChange', 'macFlap']);
// 維運問題彙整：
// - linkFlap：同一設備同一介面在 LINK_FLAP_WINDOW_MS 內 down ≥ LINK_FLAP_MIN 次（有實體層訊息時只算實體層，
//   避免同一次斷線的實體層與協定層訊息重複計算）
// - errDisable／poeFault：依設備＋介面；stpChange／hwAlarm：依設備；configChange：依設備＋帳號
const LINK_FLAP_WINDOW_MS = 10 * 60 * 1000, LINK_FLAP_MIN = 3;
function detectNetOpsIssues(events) {
  const infoOf = e => e._netOps !== undefined ? e._netOps : (e._netOps = netOpsInfo(e));
  const groups = new Map();
  const add = (key, e) => { if (!groups.has(key)) groups.set(key, []); groups.get(key).push(e); };
  events.forEach(e => {
    const n = infoOf(e);
    if (!n) return;
    const host = e.host || '-';
    if (n.kind === 'linkUpDown') add(`linkFlap|${host}|${n.iface}`, e);
    else if (n.kind === 'errDisable' || n.kind === 'poeFault') add(`${n.kind}|${host}|${n.iface}`, e);
    else if (n.kind === 'stpChange' || n.kind === 'hwAlarm') add(`${n.kind}|${host}|`, e);
    else if (n.kind === 'configChange') add(`configChange|${host}|${n.user || n.srcip || '-'}`, e);
    else if (n.kind === 'macFlap') add(`macFlap|${host}|${n.mac}`, e);
  });
  const SEV = { errDisable: 'High', hwAlarm: 'High', poeFault: 'Medium', configChange: 'Low', linkFlap: 'Medium', macFlap: 'Medium' };
  const issues = [];
  for (const [key, list] of groups) {
    const [kind, host, sub] = key.split('|');
    const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    let related = sorted, count = sorted.length;
    if (kind === 'linkFlap') {
      const hasPhy = sorted.some(e => infoOf(e).layer === 'phy');
      const downs = sorted.filter(e => infoOf(e).state === 'down' && (!hasPhy || infoOf(e).layer === 'phy'));
      let best = 0;
      for (let i = 0, j = 0; i < downs.length; i++) {
        while (effectiveTime(downs[i]) - effectiveTime(downs[j]) > LINK_FLAP_WINDOW_MS) j++;
        best = Math.max(best, i - j + 1);
      }
      if (best < LINK_FLAP_MIN) continue;
      count = downs.length;
    }
    const sev = kind === 'stpChange' ? (sorted.some(e => infoOf(e).major) ? 'Medium' : 'Low') : SEV[kind];
    const first = sorted[0], last = sorted[sorted.length - 1];
    const who = kind === 'configChange' ? [...new Set(sorted.map(e => infoOf(e).user).filter(Boolean))].join(', ') : '';
    const from = kind === 'configChange' ? [...new Set(sorted.map(e => infoOf(e).srcip).filter(Boolean))].join(', ') : '';
    const detailSample = infoOf(last).detail || '';
    issues.push({
      category: kind, severityNorm: sev, count,
      firstSeen: first.timestamp || null, lastSeen: last.timestamp || null,
      ...(kind === 'configChange'
        ? sampleOf('sample.configChange', { pre: host !== '-' ? host : '', who: who || { key: 'sample.no_account' },
          from: from ? { key: 'sample.configChange_from', p: { v: from } } : '', n: count,
          last: detailSample ? { key: 'sample.configChange_last', p: { v: detailSample } } : '' })
        : { sampleRaw: `${host !== '-' ? host + ' ' : ''}${sub ? sub + '：' : ''}${last.raw}` }),
      relatedHosts: [host !== '-' ? host : '', sub].filter(Boolean), relatedEvents: related,
      confidence: kind === 'linkFlap' ? 'heuristic' : 'confirmed',
      // 介面類問題另存設備與介面，供「到交換器設定查看」按鈕使用（YH）
      ...(kind === 'linkFlap' || kind === 'errDisable' || kind === 'poeFault' ? { netHost: host !== '-' ? host : '', netIface: sub } : {}),
      // MAC 飄移：帶出涉及的兩個埠（依出現次數）、MAC 與 VLAN，供交換器分析對照兩個埠與終端定位（ZQ）
      ...(kind === 'macFlap' ? (() => {
        const cnt = new Map();
        sorted.forEach(e => [infoOf(e).iface, infoOf(e).iface2].forEach(p => cnt.set(p, (cnt.get(p) || 0) + 1)));
        const ports = [...cnt.keys()].sort((a, b) => cnt.get(b) - cnt.get(a));
        return { netHost: host !== '-' ? host : '', netIface: ports[0] || '', netIface2: ports[1] || '', netMac: sub, netVlan: infoOf(last).vlan || '' };
      })() : {})
    });
  }
  return issues;
}
// 新增或提升管理者帳號（XN35，依 Group-IB k0t 報告：登入防火牆後建立不限來源的管理者當後門）。
// 回傳 {acct, priv, by, srcip, kind:'add'|'priv'} 或 null。只認已查證的訊息：
// - FortiGate：logid 0100044547 action="Add" cfgpath="system.admin"（Fortinet PSIRT SSO 濫用分析範例 log）；
//   SSO 管理者第一次登入也會產生同樣紀錄，需人工確認
// - Cisco ASA／FTD：502101 New user added to local dbase、502103 User priv level changed（只列權限提高）
// - Cisco IOS／IOS-XE：archive log config notify syslog 的 PARSER-5-CFGLOG_LOGGEDCMD「username … privilege 15」
// - Palo Alto PAN-OS（XN41）：CONFIG log 路徑含 mgt-config users <帳號>、結果 Succeeded，指令為 add／clone，
//   或 set 且變更前為空（CLI 新增）；edit（改密碼等）不列。CSV 欄位依 Elastic panw 測試範例，管理者以
//   set mgt-config users 建立依 Palo Alto KB；未取得新增管理者的實際 log 行，路徑格式由一般 CONFIG 範例推得
// Juniper（UI_CFG_AUDIT_SET）、MikroTik、Comware 查無可引用的新增帳號樣本，不評估
// RouterOS 設定變更（XN129）：官方 Log 文件的寫法為「物件 added／changed／moved／removed by 帳號」（topics system,info，
// 例：mangle rule added by admin、item added by admin）；回傳 {obj, op, user}，不是這種句型回傳 null
const MIKROTIK_CFG_RE = /^(.+?) (added|changed|moved|removed) by (\S+)$/;
function mikrotikCfgOf(evt) {
  if (!evt || !evt.mikrotik) return null;
  const m = String(evt.msg || '').replace(/^[a-z][a-z0-9-]*(?:,[a-z][a-z0-9-]*)*\s+/, '').match(MIKROTIK_CFG_RE);
  return m ? { obj: m[1].trim(), op: m[2], user: m[3] } : null;
}
function netAdminChangeOf(evt) {
  if (!evt) return null;
  const f = evt.fields || {}, t = evt.msg || '';
  let m;
  if (evt.format === 'fortigate') {
    if (f.logid !== '0100044547' || f.cfgpath !== 'system.admin' || f.action !== 'Add' || !f.cfgobj) return null;
    const ipm = String(f.ui || '').match(/\(([\d.:a-fA-F]+)\)/), pm = String(f.cfgattr || '').match(/accprofile\[([^\]]*)\]/);
    return { acct: f.cfgobj, priv: pm ? pm[1] : '', by: f.user || '', srcip: ipm ? ipm[1] : '', kind: 'add' };
  }
  // HPE Aruba CX（XN121）：4609（REST）／4701「User 帳號 added 新帳號 with role 角色」，只列 administrators／admin 角色
  if (evt.netVendor === 'arubacx' && (f.cx === '4609' || f.cx === '4701') && (m = String(f.cxText || '').match(/^User (\S+) added (\S+) with role (\S+?)\.?$/)) && /^admin/i.test(m[3]))
    return { acct: m[2], priv: m[3], by: m[1], srcip: '', kind: 'add' };
  if (evt.format === 'asa') {
    if (evt.msgid === '502101' && (m = t.match(/New user added to local dbase: Uname: (\S+) Priv: (\d+)(?:.*?Executor: (\S+))?/))) {
      return { acct: m[1], priv: m[2], by: m[3] || '', srcip: '', kind: 'add' };
    }
    if (evt.msgid === '502103' && (m = t.match(/User priv level changed: Uname: (\S+) From: (\d+) To: (\d+)/)) && +m[3] > +m[2]) {
      return { acct: m[1], priv: `${m[2]}→${m[3]}`, by: '', srcip: '', kind: 'priv' };
    }
    return null;
  }
  if (evt.netVendor === 'paloalto' && f.logtype === 'CONFIG') {
    m = String(f.cfgpath || '').match(/(?:^|\s)mgt-config\s+users\s+(\S+)/);
    if (!m || !/^succeeded$/i.test(f.result || '')) return null;
    const cmd = String(f.cmd || '').toLowerCase();
    if (!(cmd === 'add' || cmd === 'clone' || (cmd === 'set' && f.cfgnew === 'yes'))) return null;
    return { acct: m[1].replace(/^['"]|['"]$/g, ''), priv: f.cfgrole || '', by: f.user || '', srcip: f.srcip || '', kind: 'add' };
  }
  if ((m = t.match(/User:(.*?)\s+logged command:(?:!config:\s*)?username\s+(\S+)\b.*\bprivilege\s+15\b/))) {
    if (evt.format === 'ciscoios' ? evt.msgid !== 'CFGLOG_LOGGEDCMD' : !/%PARSER-\d-CFGLOG_LOGGEDCMD\b/.test(evt.raw || '')) return null;
    return { acct: m[2], priv: '15', by: m[1].trim(), srcip: '', kind: 'add' };
  }
  return null;
}
// 同一設備＋帳號合併成一筆；原本的 configChange 照常產生
function detectNetAdminChange(events) {
  const groups = new Map();
  events.forEach(e => {
    const a = netAdminChangeOf(e);
    if (!a) return;
    const host = e.host || '-', key = host + '|' + a.acct.toLowerCase();
    if (!groups.has(key)) groups.set(key, { host, list: [] });
    groups.get(key).list.push({ e, a });
  });
  const issues = [];
  for (const g of groups.values()) {
    g.list.sort((x, y) => effectiveTime(x.e) - effectiveTime(y.e));
    const first = g.list[0], last = g.list[g.list.length - 1];
    const by = [...new Set(g.list.map(x => x.a.by).filter(Boolean))].join(', ');
    const ips = [...new Set(g.list.map(x => x.a.srcip).filter(Boolean))];
    const priv = last.a.priv;
    issues.push({
      category: 'netAdminAdd', severityNorm: 'High', count: g.list.length,
      firstSeen: first.e.timestamp || null, lastSeen: last.e.timestamp || null,
      adminAcct: first.a.acct, adminPriv: priv, adminBy: by,
      ...(g.list.every(x => x.a.kind === 'priv') ? { mitre: 'T1098' } : {}),
      ...sampleOf('sample.netAdminAdd', { host: g.host !== '-' ? g.host + ' ' : '', acct: first.a.acct, priv: priv || '-', by: by || '-', ip: ips.join(', ') || '-' }),
      relatedHosts: [g.host !== '-' ? g.host : '', first.a.acct, ...ips].filter(Boolean), relatedEvents: g.list.map(x => x.e), confidence: 'heuristic'
    });
  }
  return issues;
}
// Web 存取 log（2026-09-29 BB）：
// - Apache／nginx：Common／Combined Log Format（Apache httpd 官方 Log Files 文件
//   `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"`；nginx 內建 log_format combined 相同）。
//   引號內的 " 由伺服器跳脫為 \"
// - IIS：W3C Extended（Microsoft 官方：空白分隔、時間為 UTC、空值為 -、欄位依 #Fields: 指令而定，
//   不可假設固定順序），由 parseW3CLogEvents() 在文字層級依 #Fields 逐行對應
// 狀態碼分類：401→authFail、403→denyBlock；其餘不以網址文字做關鍵字分類（避免 /login 之類路徑誤判）
const WEB_ACCESS_RE = /^(\S+) (\S+) (\S+) \[(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+-]\d{2})(\d{2})\] "((?:[^"\\]|\\.)*)" (\d{3}) (\S+)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?/;
const WEB_MONTHS = { Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06', Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12' };
function webStatusSeverity(status) {
  const n = Number(status);
  return n >= 500 ? 'Medium' : (n >= 400 ? 'Low' : 'Info');
}
function webEvent(format, raw, lineNo, ts, tsRaw, host, fields) {
  return {
    format, raw, lineNo, netFields: true, netVendor: 'web',
    timestamp: ts && !isNaN(ts.getTime()) ? ts : null, timestampRaw: tsRaw,
    host: host || '', appName: '', procid: '', msgid: '',
    severityRaw: fields.status, severityNorm: webStatusSeverity(fields.status),
    facility: null, facilityAuth: false,
    url: fields.url || '', httpMethod: fields.method || '',
    msg: `${fields.method || '-'} ${fields.url || '-'} ${fields.status}`, fields
  };
}
// AWS Elastic Load Balancing 存取紀錄（第十六輪 PH）：格式依 AWS 官方文件（Classic／ALB／NLB access logs）與 Elastic Beats
// aws elb 模組的 grok 規則與真實測試 log——
//   Classic：時間 名稱 用戶端:埠 後端:埠|- 三個處理時間 ELB狀態碼 後端狀態碼 收位元組 送位元組 "要求" "UA" 加密套件 TLS版本
//   ALB：類型(http|https|h2|grpcs|ws|wss) 時間 app/名稱/ID 用戶端:埠 目標:埠|- 三個時間 ELB狀態碼 目標狀態碼 位元組 位元組 "要求" "UA" …
//   NLB：tls 版本 時間 net/名稱/ID 監聽器 用戶端:埠 目的:埠 …（無 HTTP 狀態）
// 以 weblog 格式輸出（狀態碼分類與 Web 路徑探測沿用），fields.elb 記類型；主機為負載平衡器名稱
const ELB_LINE_RE = /^(?:(https?|h2|grpcs|wss?) )?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+) (\S+:\d+) (\S+) (-?[\d.]+) (-?[\d.]+) (-?[\d.]+) (\d{3}|-) (\d{3}|-) (\d+) (\d+) "([^"]*)" "([^"]*)"/;
const NLB_LINE_RE = /^tls (\S+) (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) (net\/\S+) (\S+) (\S+:\d+) (\S+:\d+) /;
function splitHostPort(v) { const i = String(v).lastIndexOf(':'); return i < 0 ? [v, ''] : [v.slice(0, i).replace(/^\[|\]$/g, ''), v.slice(i + 1)]; }
function parseElbLine(line, lineNo) {
  let m = line.match(ELB_LINE_RE);
  if (m) {
    const [, type, ts, name, client, backend, , , , elbStatus, tgtStatus, rbytes, sbytes, request] = m;
    const [srcip, srcport] = splitHostPort(client);
    const req = request.split(' ');
    const fields = { elb: type ? 'alb' : 'classic', srcip, srcport, method: req.length >= 2 && req[0] !== '-' ? req[0] : '', url: req.length >= 2 && req[1] !== '-' ? req[1] : '',
      status: elbStatus === '-' ? '' : elbStatus, bytes: sbytes, rbytes };
    if (backend !== '-') { const [dstip, dstport] = splitHostPort(backend); fields.dstip = dstip; fields.dstport = dstport; }
    if (tgtStatus !== '-') fields.targetstatus = tgtStatus;
    if (!fields.method) fields.elb += '-tcp';
    return webEvent('weblog', line, lineNo, new Date(ts), ts, name.replace(/^app\//, '').split('/')[0], fields);
  }
  m = line.match(NLB_LINE_RE);
  if (m) {
    const [, , ts, name, listener, client, dest] = m;
    const [srcip, srcport] = splitHostPort(client), [dstip, dstport] = splitHostPort(dest);
    const fields = { elb: 'nlb', srcip, srcport, dstip, dstport, listener, status: '' };
    const evt = webEvent('weblog', line, lineNo, new Date(ts + 'Z'), ts, name.split('/')[1] || name, fields);
    evt.msg = `TLS ${srcip}:${srcport} -> ${dstip}:${dstport}`;
    return evt;
  }
  return null;
}
// AWS S3 伺服器存取紀錄（第二十輪 FF，欄位順序依 AWS 官方 S3 使用者指南 Server access log format 與 Beats 測試 log）：
// 擁有者正規 ID（64 位十六進位）、儲存貯體、[時間]、遠端 IP、要求者（正規 ID／IAM ARN／svc:服務／-）、要求 ID、操作、
// 物件鍵、"要求 URI"、HTTP 狀態、錯誤碼、傳送位元組、物件大小…；以 weblog 事件輸出（403 歸 denyBlock 沿用），主機為儲存貯體
const S3_ACCESS_RE = /^([0-9a-f]{64}|-) (\S+) \[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+-]\d{2})(\d{2})\] (\S+) (\S+) (\S+) (\S+) (\S+) ("(?:[^"\\]|\\.)*"|-) (\d{3}|-) (\S+) (\S+)/;
function parseS3AccessLine(line, lineNo) {
  const m = line.match(S3_ACCESS_RE);
  if (!m || !WEB_MONTHS[m[4]]) return null;
  const [, owner, bucket, dd, mon, yyyy, hms, tzh, tzm, ip, requester, reqid, op, key, uri, status, err, bytes] = m;
  const req = uri === '-' ? [] : uri.slice(1, -1).split(' ');
  const fields = { s3: 'access', owner, bucket, operation: op, method: req[0] || '', url: req[1] || (key !== '-' ? key : ''), status: status === '-' ? '' : status, bytes: bytes === '-' ? '0' : bytes, reqid };
  if (ip !== '-') fields.srcip = ip;
  if (requester !== '-') fields.requester = requester;
  if (key !== '-') fields.key = key;
  if (err !== '-') fields.error = err;
  const ts = new Date(`${yyyy}-${WEB_MONTHS[mon]}-${dd}T${hms}${tzh}:${tzm}`);
  const evt = webEvent('weblog', line, lineNo, ts, `${dd}/${mon}/${yyyy}:${hms} ${tzh}${tzm}`, bucket, fields);
  evt.msg = `${op} ${fields.url || '-'} ${fields.status || '-'}${fields.error ? ' ' + fields.error : ''}`;
  return evt;
}
// ── DNS 伺服器查詢紀錄（第二十一輪 GA）──
// 共用欄位：dns（query／reply／error／upstream）、domain（查詢名稱，去掉結尾的點）、qtype、rcode、srcip／srcport（用戶端）
//   BIND（依 bind9 原始碼 lib/ns/client.c ns_client_logv() 與 lib/ns/query.c log_query()／log_queryerror()）：
//     client [@0x位址 ]IP#埠[/key 金鑰] (名稱)[: view 名稱]: query: 名稱 類別 類型 旗標 (伺服器位址)[ECS]
//     client … : query failed (NXDOMAIN) for 名稱/類別/類型 at 檔案:行（query-errors 類別）
//     檔案輸出前綴 dd-Mon-yyyy hh:mm:ss.mmm [類別: ][嚴重度: ]，或 syslog 的 named[pid]:
//   dnsmasq／Pi-hole（依 dnsmasq src/cache.c log_query()）：query[類型] 名稱 from IP、reply|cached|config 名稱 is 結果
//     （結果 NXDOMAIN／NODATA…），log-queries=extra 時前面另有「序號 IP/埠 」；回應行沒有用戶端，由同一名稱的前一筆查詢補上
//   CoreDNS log plugin（依 Elastic Beats coredns 模組的真實測試 log）：時間 [INFO] IP:埠 - 編號 "類型 類別 名稱 協定 大小 do 緩衝" RCODE 旗標 大小 耗時s
//   Windows DNS Server 偵錯 log（依 NXLog xm_msdns 文件範例）：日期 時間 [AM|PM] 執行緒 PACKET 編號 UDP|TCP Rcv|Snd IP 交易編號 [R] 操作碼 [旗標 RCODE] 類型 (3)www(7)example(3)com(0)
//     Rcv 且非回應為用戶端查詢，Snd 回應為給用戶端的答覆（帶 RCODE）；其餘為對上游的轉送
const DNS_MONTHS = { Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06', Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12' };
const BIND_CLIENT_RE = /client (?:@0x[0-9a-fA-F]+ )?([0-9a-fA-F:.]+)#(\d+)(?:\/key \S+)? \([^)]*\)(?:: view [^:]+)?: (?:query: (\S+) (\S+) (\S+) (\S*) \(([^)]*)\)|query failed \(([\w-]+)\) for (\S+?)\/(\S+?)\/(\S+?) at )/;
const DNSMASQ_RE = /^(?:(?:TCP|UDP) )?(?:(\d+) ([0-9a-fA-F:.]+)\/(\d+) )?(?:query\[(\w+)\] (\S+) from ([0-9a-fA-F:.]+)|(reply|cached|cached-stale|config) (\S+) is (\S+))/;
const BIND_FILE_RE = /^(\d{2})-([A-Z][a-z]{2})-(\d{4}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? (?:[\w-]+: )*(client [\s\S]*)$/;
const COREDNS_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) \[(?:INFO|DEBUG|WARNING|ERROR)\] (?:\[[^\]]+\] )?\[?([0-9a-fA-F:.]+?)\]?:(\d+) - (\d+) "(\S+) (\S+) (\S+) (\w+) (\d+) (\w+) (\d+)" (\S+) (\S+) (\d+) ([\d.]+)s/;
const WINDNS_RE = /^(\d{1,2})\/(\d{1,2})\/(\d{4}) (\d{1,2}):(\d{2}):(\d{2})(?: ([AP]M))? +[0-9A-Fa-f]+ +PACKET +[0-9A-Fa-f]+ +(UDP|TCP) +(Rcv|Snd) +([0-9a-fA-F:.]+) +[0-9a-fA-F]{4} +(R +)?(\S) +\[[0-9A-Fa-f]{4} +[A-Z ]*?(\w+)\] +(\S+) +(\S+)/;
const dnsName = n => String(n || '').replace(/\.$/, '');
function parseBindMsg(msg) {
  const m = String(msg || '').match(BIND_CLIENT_RE);
  if (!m) return null;
  if (m[3]) return { dns: 'query', srcip: m[1], srcport: m[2], domain: dnsName(m[3]), qclass: m[4], qtype: m[5], qflags: m[6], dnsServer: m[7] };
  return { dns: 'error', srcip: m[1], srcport: m[2], rcode: m[8].toUpperCase(), domain: dnsName(m[9]), qclass: m[10], qtype: m[11] };
}
function parseDnsmasqMsg(msg) {
  const m = String(msg || '').match(DNSMASQ_RE);
  if (!m) return null;
  const f = m[1] ? { dnsId: m[1] } : {};
  if (m[4]) return { ...f, dns: 'query', qtype: m[4], domain: dnsName(m[5]), srcip: m[6], ...(m[3] ? { srcport: m[3] } : {}) };
  const r = m[9];
  return { ...f, dns: 'reply', domain: dnsName(m[8]), answer: r, source: m[7], ...(/^(?:NXDOMAIN|NODATA|SERVFAIL|REFUSED)/.test(r) ? { rcode: r.replace(/-IPv[46]$/, '') } : { rcode: 'NOERROR' }),
    ...(m[2] ? { srcip: m[2], srcport: m[3] } : {}) };
}
// syslog 外殼內的 DNS 訊息（rfc3164／rfc5424 解析時呼叫）：dnsmasq 需程式名稱為 dnsmasq／pihole，BIND 的 client … query: 句型本身已夠明確
function parseDnsInMsg(appName, msg) {
  if (/dnsmasq|pihole/i.test(appName || '')) { const f = parseDnsmasqMsg(msg); if (f) return { vendor: 'dnsmasq', fields: f }; }
  const b = parseBindMsg(msg);
  return b ? { vendor: 'bind', fields: b } : null;
}
function dnsEvent(raw, lineNo, ts, tsRaw, vendor, f, extra) {
  return {
    format: 'dns', raw, lineNo, netFields: false, netVendor: vendor,
    timestamp: ts && !isNaN(ts.getTime()) ? ts : null, timestampRaw: tsRaw,
    host: '', appName: vendor, procid: '', msgid: '', severityRaw: f.rcode || '', severityNorm: 'Info',
    facility: null, facilityAuth: false,
    msg: `${f.qtype || ''} ${f.domain || ''} ${f.rcode || ''}${f.srcip ? ' from ' + f.srcip : ''}`.replace(/\s+/g, ' ').trim(), fields: f, ...(extra || {})
  };
}
function decodeWinDnsName(s) { return String(s).replace(/\(\d+\)/g, '.').replace(/^\.+|\.+$/g, ''); }
function encodeWinDnsName(n) { return n.split('.').filter(Boolean).map(l => `(${l.length})${l}`).join('') + '(0)'; }
function parseDnsServerLine(line, lineNo) {
  let m = line.match(BIND_FILE_RE);
  if (m && DNS_MONTHS[m[2]]) {
    const f = parseBindMsg(m[5]);
    if (!f) return null;
    return dnsEvent(line, lineNo, new Date(`${m[3]}-${DNS_MONTHS[m[2]]}-${m[1]}T${m[4]}`), line.slice(0, line.indexOf(' ', 12)), 'bind', f);
  }
  if ((m = line.match(COREDNS_RE))) {
    const f = { dns: 'reply', srcip: m[2], srcport: m[3], dnsId: m[4], qtype: m[5], qclass: m[6], domain: dnsName(m[7]), proto: m[8], rcode: m[12].toUpperCase(), duration: m[15] };
    return dnsEvent(line, lineNo, new Date(m[1]), m[1], 'coredns', f);
  }
  if ((m = line.match(WINDNS_RE))) {
    const [, a, b, y, hh, mi, ss, ap, proto, dir, ip, resp, op, rcode, qtype, enc] = m;
    if (op !== 'Q') return null;
    // 日期順序：有 AM/PM 為 月/日（美式地區設定），否則依數值判斷（大於 12 者為日），都不大於 12 時當作 日/月
    let mo, d;
    if (+a > 12) [d, mo] = [a, b];
    else if (+b > 12 || ap) [mo, d] = [a, b];
    else [d, mo] = [a, b];
    let h = +hh; if (ap === 'PM' && h < 12) h += 12; if (ap === 'AM' && h === 12) h = 0;
    const ts = new Date(`${y}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}T${String(h).padStart(2, '0')}:${mi}:${ss}`);
    const isResp = !!resp;
    const f = { qtype, domain: decodeWinDnsName(enc), proto: proto.toLowerCase(), qnameRaw: enc };
    if (dir === 'Rcv' && !isResp) Object.assign(f, { dns: 'query', srcip: ip });
    else if (dir === 'Snd' && isResp) Object.assign(f, { dns: 'reply', srcip: ip, rcode: rcode.toUpperCase() });
    else Object.assign(f, { dns: 'upstream', dnsServer: ip, ...(isResp ? { rcode: rcode.toUpperCase() } : {}) });
    return dnsEvent(line, lineNo, ts, line.slice(0, line.indexOf('PACKET')).trim(), 'windns', f);
  }
  return null;
}
// dnsmasq 回應行沒有用戶端位址：由同一主機、同一名稱（extra 模式為同一序號）的前一筆查詢補上
function linkDnsReplies(events) {
  const last = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (!f || !f.dns || !f.domain || e.netVendor !== 'dnsmasq') return;
    const k = `${e.host}|${f.dnsId || f.domain.toLowerCase()}`;
    if (f.dns === 'query' && f.srcip) last.set(k, f.srcip);
    else if (f.dns === 'reply' && !f.srcip && last.has(k)) f.srcip = last.get(k);
  });
  return events;
}
// ── Linux sshd／sudo 認證紀錄（第二十二輪 HB，句型依 Elastic Beats system 模組 auth 的真實測試 log 與 grok 規則）──
//   sshd：Accepted|Failed 方法 for [invalid user ]帳號 from 位址 port 埠 ssh2、Invalid user 帳號 from 位址[ port 埠]、
//     Did not receive identification string from 位址、Connection closed by|Disconnected from [authenticating|invalid user 帳號 ]位址 port 埠 [preauth]
//   sudo：帳號 : [錯誤 ; ]TTY=… ; PWD=… ; USER=身分 ; COMMAND=指令（有錯誤如 user NOT in sudoers 時為拒絕）
// 欄位：ssh（accepted／failed／invalid／noident／preauth）或 sudo（command／denied）、user、srcip、srcport、method、runAs、command
const SSHD_AUTH_RE = /^(Accepted|Failed) (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)/;
const SSHD_KEYFP_RE = / ssh2: (\S+) ((?:SHA256|MD5):\S+)/;
const SSHD_INVALID_RE = /^Invalid user (\S*) from (\S+?)(?: port (\d+))?$/;
const SSHD_NOIDENT_RE = /^Did not receive identification string from (\S+?)(?: port (\d+))?$/;
const SSHD_PREAUTH_RE = /^(?:Connection closed by|Disconnected from) (?:(?:authenticating|invalid) user (\S+) )?(\S+) port (\d+) \[preauth\]/;
// USER 與 COMMAND 之間可能有 GROUP=／TSID=／ENV= 等欄位
const SUDO_RE = /^\s*(\S+) : (?:(.+?) ; )?TTY=(\S+) ; PWD=(.*?) ; USER=(\S+) ; (?:[A-Z]+=.*? ; )*COMMAND=(.*)$/;
function parseSshdMsg(appName, msg) {
  const s = String(msg || '').trim();
  let m;
  if (/^sshd/i.test(appName || '')) {
    if ((m = s.match(SSHD_AUTH_RE))) {
      // 公鑰登入結尾帶「ssh2: 金鑰類型 指紋」（openssh-portable auth.c：ssh2%s%s，sshkey_type＋sshkey_fingerprint），XN80
      const fp = s.match(SSHD_KEYFP_RE);
      return { vendor: 'linuxauth', fields: { ssh: m[1].toLowerCase(), method: m[2], user: m[4], srcip: m[5], srcport: m[6], ...(m[3] ? { invalidUser: true } : {}), ...(fp ? { keyType: fp[1], keyfp: fp[2] } : {}) } };
    }
    if ((m = s.match(SSHD_INVALID_RE))) return { vendor: 'linuxauth', fields: { ssh: 'invalid', user: m[1], srcip: m[2], ...(m[3] ? { srcport: m[3] } : {}), invalidUser: true } };
    if ((m = s.match(SSHD_NOIDENT_RE))) return { vendor: 'linuxauth', fields: { ssh: 'noident', srcip: m[1], ...(m[2] ? { srcport: m[2] } : {}) } };
    if ((m = s.match(SSHD_PREAUTH_RE))) return { vendor: 'linuxauth', fields: { ssh: 'preauth', ...(m[1] ? { user: m[1] } : {}), srcip: m[2], srcport: m[3] } };
    return null;
  }
  if (/^sudo$/i.test(appName || '') && (m = s.match(SUDO_RE))) {
    return { vendor: 'linuxauth', fields: { sudo: m[2] ? 'denied' : 'command', user: m[1], runAs: m[5], command: m[6], tty: m[3], ...(m[2] ? { sudoError: m[2] } : {}) } };
  }
  return null;
}
const sshAuthFailed = f => !!f && (f.ssh === 'failed' || f.ssh === 'invalid' || f.sudo === 'denied');
// 同一來源多次 SSH 登入失敗後成功（第二十二輪 HB）：成功前 SSH_BRUTE_WINDOW_MS 內同來源失敗達 SSH_BRUTE_MIN 次
const SSH_BRUTE_MIN = 5;
const SSH_BRUTE_WINDOW_MS = 60 * 60 * 1000;
function detectSshBruteSuccess(events) {
  const bySrc = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (!f || !f.ssh || !f.srcip || !e.timestamp || !(f.ssh === 'accepted' || sshAuthFailed(f))) return;
    if (!bySrc.has(f.srcip)) bySrc.set(f.srcip, []);
    bySrc.get(f.srcip).push(e);
  });
  const issues = [];
  for (const [src, list] of bySrc) {
    const sorted = [...list].sort((a, b) => a.timestamp - b.timestamp);
    const fails = [];
    sorted.forEach(e => {
      const t = e.timestamp.getTime();
      if (e.fields.ssh !== 'accepted') {
        // 同一次連線 sshd 會先記 Invalid user 再記 Failed password for invalid user，同來源埠只算一次
        const last = fails[fails.length - 1];
        if (last && e.fields.srcport && last.fields.srcport === e.fields.srcport && t - last.timestamp.getTime() <= 60000 && (last.fields.ssh === 'invalid' || e.fields.ssh === 'invalid')) return;
        fails.push(e); return;
      }
      const recent = fails.filter(x => t - x.timestamp.getTime() <= SSH_BRUTE_WINDOW_MS);
      if (recent.length < SSH_BRUTE_MIN) return;
      const users = [...new Set(recent.map(x => x.fields.user).filter(Boolean))];
      issues.push({
        category: 'sshBruteSuccess', severityNorm: 'High', count: recent.length + 1,
        firstSeen: recent[0].timestamp, lastSeen: e.timestamp,
        ...sampleOf('sample.sshBruteSuccess', { pre: e.host || '', src, n: recent.length, users: users.slice(0, 5).join(', '), user: e.fields.user }),
        relatedHosts: [src, e.fields.user, e.host].filter(Boolean), relatedEvents: [...recent, e], confidence: 'heuristic'
      });
      fails.length = 0;
    });
  }
  return issues;
}
// 防火牆管理介面登入（2026-10-29，第三十九輪 XN48）：回傳 {vendor, user, src, ok, method} 或 null。只認已查證的訊息：
// - FortiGate：logid 0100032001 Admin login successful／0100032002 Admin login failed（Elastic fortinet_fortigate 測試 log、
//   Wazuh fortigate.ini 的真實行）。新版帶 srcip／method，舊版只有 ui="https(位址)"／"ssh(位址)"；jsconsole、fgfm 等沒有位址者略過
// - Cisco ASA／FTD：605004 Login denied／605005 Login permitted（parseAsaAuth 已解析成 auth／user／srcip）
// PAN-OS 管理者認證查無可引用樣本，不評估
const FG_UI_IP_RE = /\b([a-zA-Z_]+)\(([0-9a-fA-F.:]+)\)/;
function adminLoginOf(evt) {
  const f = evt && evt.fields;
  if (!f) return null;
  if (evt.format === 'fortigate' && (f.logid === '0100032001' || f.logid === '0100032002')) {
    const m = String(f.ui || '').match(FG_UI_IP_RE) || String(f.msg || evt.msg || '').match(FG_UI_IP_RE);
    const src = f.srcip || (m ? m[2] : '');
    if (!src) return null;
    const um = String(f.msg || evt.msg || '').match(/^(?:Administrator|User)\s+(\S+)/);
    return { vendor: 'fortigate', user: f.user || (um ? um[1] : ''), src, ok: f.logid === '0100032001', method: f.method || (m ? m[1] : '') };
  }
  // QNAP（XN111）：HTTP／HTTPS 連線存取 Administration 的登入
  if (evt.netVendor === 'qnap' && f.qnap === 'conn' && f.srcip && /^Administration$/i.test(f.resource || '') && /HTTP/i.test(f.conntype || '') && /^Login (?:Success|Fail)/i.test(f.qnapAction || ''))
    return { vendor: 'qnap', user: f.user || '', src: f.srcip, ok: /^Login Success/i.test(f.qnapAction), method: f.conntype };
  // FortiMail／FortiManager（XN123）：管理介面登入（ui／userfrom 的「方式(位址)」）
  if ((evt.netVendor === 'fortimail' || evt.netVendor === 'fortimanager') && f.fmLogin && f.srcip) return { vendor: evt.netVendor, user: f.user || '', src: f.srcip, ok: f.fmLogin === 'ok', method: f.method || '' };
  // HPE Aruba CX（XN121）：SSH／REST／TELNET／CONSOLE 管理登入（REST 成功事件記的是識別名稱而不是位址時沒有來源，略過）
  if (evt.netVendor === 'arubacx' && f.cxLogin && f.srcip) return { vendor: 'arubacx', user: f.user || '', src: f.srcip, ok: f.cxLogin === 'ok', method: f.cxProto || '' };
  if (evt.netVendor === 'watchguard' && f.wgAdmin && f.srcip) return { vendor: 'watchguard', user: f.user || '', src: f.srcip, ok: f.wgAdmin === 'ok', method: f.wgMsgId === '5000-0001' ? 'WSM' : 'Web UI' };
  // MikroTik RouterOS（XN124，v6 與 v7 相同）：「user X logged in from IP via winbox／ssh／web／api…」與
  // 「login failure for user X from IP via …」，登入對象是 RouterOS 本身的管理介面；MAC 位址登入（mac-telnet、MAC Winbox）沒有 IP，略過
  if (evt.netVendor === 'mikrotik' && f.srcip && f.method && !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(f.srcip)) {
    if (f.loginaction === 'logged in') return { vendor: 'mikrotik', user: f.user || '', src: f.srcip, ok: true, method: f.method };
    if (!f.loginaction && /\blogin failure for user\b/.test(evt.msg || evt.raw || '')) return { vendor: 'mikrotik', user: f.user || '', src: f.srcip, ok: false, method: f.method };
  }
  // PAN-OS（XN133）：SYSTEM auth-success／auth-fail 且描述帶 admin role（登入防火牆管理介面）
  if (evt.netVendor === 'paloalto' && f.logtype === 'SYSTEM' && f.panAuth && f.adminRole && f.srcip)
    return { vendor: 'paloalto', user: f.user || '', src: f.srcip, ok: f.panAuth === 'ok', method: f.adminRole };
  if (evt.format === 'asa' && (evt.msgid === '605004' || evt.msgid === '605005') && f.auth && f.srcip) {
    return { vendor: 'asa', user: f.user || '', src: f.srcip, ok: f.auth === 'success', method: f.service || '' };
  }
  return null;
}
// 外部位址的管理介面登入（XN48）：管理介面不應從網際網路登入，成功即列出（High）；成功前 ADMIN_LOGIN_WINDOW_MS 內
// 同來源或同帳號失敗達 ADMIN_LOGIN_FAIL_BEFORE 次升為 Critical。外部位址失敗 ADMIN_LOGIN_FAIL_MIN 次以上且之後沒有成功
// 另列 adminLoginFailExternal（Medium），補頻率偵測（1 分鐘 5 次）抓不到的慢速嘗試。內部位址不列（iocIsInternalIP）
const ADMIN_LOGIN_WINDOW_MS = 24 * 60 * 60 * 1000, ADMIN_LOGIN_FAIL_BEFORE = 3, ADMIN_LOGIN_FAIL_MIN = 5;
function detectAdminLogins(events) {
  const byHost = new Map();
  events.forEach(e => {
    const a = adminLoginOf(e);
    if (!a || !e.timestamp || iocIsInternalIP(a.src)) return;
    const h = e.host || '-';
    if (!byHost.has(h)) byHost.set(h, []);
    byHost.get(h).push({ e, a, t: e.timestamp.getTime() });
  });
  const issues = [];
  for (const [host, list] of byHost) {
    list.sort((x, y) => x.t - y.t);
    const ok = new Map(), usedFails = new Set();
    list.forEach((x, i) => {
      if (!x.a.ok) return;
      const user = String(x.a.user || '').toLowerCase();
      const fails = list.slice(0, i).filter(y => !y.a.ok && x.t - y.t <= ADMIN_LOGIN_WINDOW_MS && (y.a.src === x.a.src || (user && String(y.a.user || '').toLowerCase() === user)));
      fails.forEach(y => usedFails.add(y));
      const key = user + '|' + x.a.src;
      if (!ok.has(key)) ok.set(key, { list: [], fails: new Set() });
      const g = ok.get(key);
      g.list.push(x); fails.forEach(y => g.fails.add(y));
    });
    for (const g of ok.values()) {
      const first = g.list[0], last = g.list[g.list.length - 1], fails = [...g.fails].sort((x, y) => x.t - y.t);
      const crit = fails.length >= ADMIN_LOGIN_FAIL_BEFORE;
      const ev = [...fails, ...g.list].map(x => x.e);
      issues.push({
        category: 'adminLoginExternal', severityNorm: crit ? 'Critical' : 'High', count: g.list.length,
        firstSeen: (fails[0] || first).e.timestamp || null, lastSeen: last.e.timestamp || null,
        adminAcct: first.a.user || '-', adminSrc: first.a.src, adminFails: fails.length, adminMethod: first.a.method || '',
        ...sampleOf('sample.adminLoginExternal', { host: host !== '-' ? host + ' ' : '', user: first.a.user || '-', src: first.a.src, method: first.a.method || '-', fails: fails.length }),
        relatedHosts: [first.a.src, first.a.user, host !== '-' ? host : ''].filter(Boolean), relatedEvents: ev, confidence: 'heuristic'
      });
    }
    // 外部失敗、之後沒有成功：同設備 24 小時視窗內達門檻即列，依設備合併
    const rest = list.filter(x => !x.a.ok && !usedFails.has(x));
    let st = 0, best = null;
    for (let i = 0; i < rest.length; i++) {
      while (rest[i].t - rest[st].t > ADMIN_LOGIN_WINDOW_MS) st++;
      if (i - st + 1 >= ADMIN_LOGIN_FAIL_MIN && (!best || i - st > best.e - best.s)) best = { s: st, e: i };
    }
    if (best) {
      const win = rest.slice(best.s, best.e + 1);
      const srcs = [...new Set(win.map(x => x.a.src))], users = [...new Set(win.map(x => x.a.user).filter(Boolean))];
      issues.push({
        category: 'adminLoginFailExternal', severityNorm: 'Medium', count: win.length,
        firstSeen: win[0].e.timestamp || null, lastSeen: win[win.length - 1].e.timestamp || null,
        adminSrcs: srcs.length, adminUsers: users.length,
        ...sampleOf('sample.adminLoginFailExternal', { host: host !== '-' ? host + ' ' : '', n: win.length, srcs: srcs.slice(0, 5).join(', '), users: users.slice(0, 5).join(', ') || '-' }),
        relatedHosts: [...srcs.slice(0, 5), host !== '-' ? host : ''].filter(Boolean), relatedEvents: win.map(x => x.e), confidence: 'heuristic'
      });
    }
  }
  return issues;
}
// ── VPN／RADIUS 認證伺服器 log（第二十三輪 IA～IC）──
// OpenVPN（依 OpenVPN 原始碼 src/openvpn 的 multi.c、ssl_verify.c、socket.c、sig.c）：用戶端訊息前綴為「憑證名稱/位址:埠」
//   （尚未取得名稱時只有「位址:埠」，見 multi_instance_string()）；
//   MULTI_sva: pool returned IPv4=指派位址, IPv6=…／MULTI: Learn: 位址 -> 名稱/位址:埠／[名稱] Peer Connection Initiated with [AF_INET]位址:埠／
//   TLS: Username/Password|auth-token authentication succeeded|failed for username '帳號'／TLS Auth Error: …／VERIFY ERROR: …／
//   TLS Error: TLS handshake failed／SIGTERM|SIGUSR1[soft,原因] received, client-instance exiting|restarting
// strongSwan charon（依 src/libcharon 的 ike_init.c、ike_establish.c、main_mode.c、ike_config.c、mode_config.c、ike_delete.c、
//   psk_authenticator.c、pubkey_authenticator.c、eap_authenticator.c；syslog 與檔案記錄前綴「執行緒[群組] [<連線名稱|編號>] 」，
//   見 sys_logger.c／file_logger.c）：%H is initiating IKE_SA 名稱[編號]、IKE_SA 名稱[編號] established|deleting IKE_SA 名稱[編號] between
//   本端位址[ID]...對端位址[ID]、assigning virtual IP 位址 to peer 'ID'、tried N shared key(s) for 'ID' - 'ID', but MAC mismatched、
//   no trusted … public key found for 'ID'、EAP method … failed for peer ID、received AUTHENTICATION_FAILED notify error
// FreeRADIUS 3.x（依 src/main/auth.c 的 rad_authlog()／auth_name()）：[(請求編號) ]Login OK|Login incorrect|Invalid user|Rejected in post-auth
//   [ (原因)]: [帳號[/密碼]] (from client 名稱 port 埠[ cli 主叫端][ via …])；開啟 auth_badpass／auth_goodpass 時方括號內帶密碼，去識別化一律遮蔽
// 欄位：ovpn／ipsec／radius（事件種類）、user、cn（OpenVPN 憑證名稱）、srcip、srcport、assignIp、saName／saId、localIp／localId、
//   netHost（RADIUS 用戶端）、nasPort、mac、failReason
// OpenVPN 2.4 起 CN 保留空白（John Doe/1.2.3.4:5），CN 為斜線前不含冒號與方括號的文字
const OVPN_PREFIX_RE = /^(?:([^/:\[\]]+?)\/)?([0-9A-Fa-f.:]+):(\d+) ([\s\S]*)$/;
function parseOpenVpnMsg(msg) {
  let s = String(msg || '').trim(), cn = '', srcip = '', srcport = '', m;
  const p = s.match(OVPN_PREFIX_RE);
  if (p && /[.:]/.test(p[2])) { cn = p[1] || ''; srcip = p[2]; srcport = p[3]; s = p[4]; }
  const f = {};
  if ((m = s.match(/^MULTI_sva: pool returned IPv4=(\S+?), IPv6=(.+)$/))) {
    f.ovpn = 'assign';
    if (usableIp(m[1])) f.assignIp = m[1];
    if (!/Not enabled/.test(m[2])) f.assignIp6 = m[2].trim();
  } else if ((m = s.match(/^MULTI: Learn: (\S+) -> (?:([^\s/]+)\/)?\S+$/))) {
    f.ovpn = 'learn';
    if (usableIp(m[1])) f.assignIp = m[1];
    if (!cn && m[2]) cn = m[2];
  } else if ((m = s.match(/^\[([^\]]+)\] Peer Connection Initiated with /))) {
    f.ovpn = 'connect'; cn = cn || m[1];
  } else if ((m = s.match(/^TLS: Username\/(?:Password|auth-token) authentication (succeeded|failed|deferred) for username '([^']*)'/))) {
    // deferred 是交給外掛非同步驗證，結果另有記錄，不算成功
    f.ovpn = m[1] === 'failed' ? 'authfail' : m[1] === 'deferred' ? 'info' : 'authok'; if (m[2]) f.user = m[2];
  } else if (/^TLS Auth Error: /.test(s)) { f.ovpn = 'authfail'; f.failReason = s.slice(16); }
  else if (/^VERIFY ERROR: /.test(s)) { f.ovpn = 'verifyfail'; f.failReason = s.slice(14); }
  else if (/^TLS Error: TLS handshake failed/.test(s)) f.ovpn = 'tlsfail';
  else if ((m = s.match(/^SIG\w+\[[^,\]]*,?([^\]]*)\] received, client-instance (?:exiting|restarting)/))) { f.ovpn = 'exit'; if (m[1]) f.exitReason = m[1]; }
  else if (srcip) f.ovpn = 'info';
  else return null;
  if (cn) { f.cn = cn; if (!f.user) f.user = cn; }
  if (srcip) Object.assign(f, { srcip, srcport });
  return { vendor: 'openvpn', fields: f };
}
const SW_PREFIX_RE = /^(?:\d{2}\[[A-Z]{2,4}\] )?(?:<([^|>]*)\|(\d+)> )?([\s\S]*)$/;
const SW_SA_RE = /^(?:IKE_SA (\S+)\[(\d+)\] established|deleting IKE_SA (\S+)\[(\d+)\]) between (\S+?)\[([^\]]*)\]\.\.\.(\S+?)\[([^\]]*)\]/;
function parseStrongSwanMsg(msg) {
  const p = String(msg || '').trim().match(SW_PREFIX_RE);
  const s = p[3], f = {};
  let m;
  if (p[2]) { f.saName = p[1]; f.saId = p[2]; }
  if ((m = s.match(/^(\S+) is initiating (?:IKE_SA (\S+)\[(\d+)\]|an IKE_SA|a Main Mode IKE_SA)/))) {
    f.ipsec = 'init'; f.srcip = m[1];
    if (m[3]) { f.saName = m[2]; f.saId = m[3]; }
  } else if ((m = s.match(SW_SA_RE))) {
    Object.assign(f, { ipsec: m[1] ? 'up' : 'down', saName: m[1] || m[3], saId: m[2] || m[4], localIp: m[5], localId: m[6], srcip: m[7], user: m[8] });
  } else if ((m = s.match(/^assigning virtual IP (\S+) to peer '(.*)'$/))) {
    f.ipsec = 'assign'; f.user = m[2];
    if (usableIp(m[1])) f.assignIp = m[1]; else f.assignIp6 = m[1];
  } else if ((m = s.match(/^tried \d+ shared keys? for '(.*?)' - '(.*)', but MAC mismatched/))) { Object.assign(f, { ipsec: 'authfail', localId: m[1], user: m[2], failReason: 'PSK MAC mismatched' }); }
  else if ((m = s.match(/^no trusted \S+ public key found for '(.*)'/))) { Object.assign(f, { ipsec: 'authfail', user: m[1], failReason: 'no trusted public key' }); }
  else if ((m = s.match(/^EAP method (\S+) failed for peer (.+)$/))) {
    // 對端沒有 ID 時印出的是位址
    const id = m[2].trim();
    Object.assign(f, { ipsec: 'authfail', failReason: `EAP ${m[1]} failed` }, usableIp(id) ? { srcip: id } : { user: id });
  }
  else if (/^received AUTHENTICATION_FAILED notify error/.test(s)) { f.ipsec = 'authfail'; f.failReason = 'AUTHENTICATION_FAILED'; }
  else if ((m = s.match(/^authentication of '(.*?)' (\(myself\) )?with (.+) successful/))) { f.ipsec = 'authok'; if (m[2]) f.localId = m[1]; else f.authId = m[1]; }
  else return null;
  return { vendor: 'strongswan', fields: f };
}
const RADIUS_AUTH_RE = /^(?:\((\d+)\) )?(Login OK|Login incorrect|Invalid user|Rejected in post-auth)(?: \((.*?)\))?: \[(.*?)\] \(from client (\S+) port (\d+)(?: cli (\S+?))?(?: via [^)]*)?\)/;
// 第三十輪 RA2（依 FreeRADIUS v3 原始碼 listen.c／process.c／lib/radius.c／rlm_eap_tls）：
//   Ignoring request to … from unknown client 位址 port 埠 proto udp → radius unknownClient
//   Dropping packet without response because of error: Received packet from 位址 with invalid Message-Authenticator!  (Shared secret is incorrect.) (from client 名稱)
//   Received 封包類型 packet from client 位址 with invalid Request Authenticator!  (Shared secret is incorrect.) → radius badSecret
//   [(編號) ]eap_tls: ERROR: TLS Alert read|write:fatal:原因、(TLS) 名稱 - Alert read:fatal:原因 → radius tlsfail（failReason 為原因）
//   BlastRADIUS check: Received packet without Message-Authenticator. → radius blastradius
const RADIUS_UNKNOWN_RE = /Ignoring request to .*? from unknown client (\S+) port (\d+)/;
const RADIUS_SECRET_RE = /Received (?:\S+ packet from client|packet from) (\S+) with invalid (?:Message|Request)[- ]Authenticator!.*?(?:\(from client (\S+?)\))?\s*$/;
const RADIUS_TLS_RE = /^(?:\((\d+)\) )?(?:eap_\w+: ERROR: )?(?:\(TLS\) \S+ - )?TLS Alert (?:read|write):fatal:(.+)$|^(?:\((\d+)\) )?(?:\(TLS\) \S+ - )Alert (?:read|write):fatal:(.+)$/;
function parseFreeRadiusMsg(msg) {
  const t = String(msg || '').trim();
  let x;
  if ((x = t.match(RADIUS_UNKNOWN_RE))) return { vendor: 'freeradius', fields: { radius: 'unknownClient', srcip: x[1], srcport: x[2] } };
  if ((x = t.match(RADIUS_SECRET_RE))) return { vendor: 'freeradius', fields: { radius: 'badSecret', srcip: x[1], ...(x[2] ? { netHost: x[2] } : {}) } };
  if ((x = t.match(RADIUS_TLS_RE))) return { vendor: 'freeradius', fields: { radius: 'tlsfail', failReason: (x[2] || x[4]).trim(), ...((x[1] || x[3]) ? { reqId: x[1] || x[3] } : {}) } };
  if (/^BlastRADIUS check: /.test(t)) { const c = t.match(/\bclient (\S+?)[.,)]?(?:\s|$)/); return { vendor: 'freeradius', fields: { radius: 'blastradius', ...(c ? { netHost: c[1] } : {}) } }; }
  const m = t.match(RADIUS_AUTH_RE);
  if (!m) return null;
  // 機器驗證的帳號本身帶斜線（host/PC01.corp.local），之後的斜線才是記錄下來的密碼
  const slash = m[4].indexOf('/', /^host\//i.test(m[4]) ? 5 : 0);
  const f = { radius: m[2] === 'Login OK' ? 'accept' : 'reject', user: slash >= 0 ? m[4].slice(0, slash) : m[4], netHost: m[5], nasPort: m[6] };
  if (m[1]) f.reqId = m[1];
  if (slash >= 0) f.pwLogged = true;
  if (m[2] !== 'Login OK') f.failReason = m[3] || m[2];
  if (m[7]) { if (usableIp(m[7])) f.srcip = m[7]; else f.mac = m[7]; }
  return { vendor: 'freeradius', fields: f };
}
// ── 服務狀態與異常（2026-10-22，第三十三輪 XN16）────────────────────────────
// 訊息字串依原始碼逐字查證：OpenLDAP servers/slapd（main.c「slapd starting／slapd stopped.」、daemon.c「daemon: bind(N) failed errno=…」
//   「daemon: accept(N) failed errno=…」「slapd shutdown: waiting for N operations/tasks to finish」、backend.c「backend_startup_one (type=…,
//   suffix="…"): bi_db_open failed! (N)」、back-mdb init.c「mdb_db_open: database "…" cannot be opened: …」、id2entry.c「mdb_put failed: …」、
//   liblmdb「MDB_MAP_FULL／MDB_CORRUPTED／MDB_PANIC」、syncrepl.c「do_syncrepl: rid rc N retrying|quitting」）、389-ds-base（daemon.c
//   「slapd started.  Listening on …」「slapd shutting down - …」「Disk space is [critically ]low on disk (…)」、main.c「slapd stopped.」、
//   bdb_layer.c「Serious Error---Failed to checkpoint database」、replication「Unable to acquire replica」）、FreeRADIUS v3.2（process.c
//   「Ready to process requests」「Marking home server A port P as zombie|as dead.|alive」「Failed to find live home server」「Dropping request
//   (N is too many)」、radiusd.c「Exiting normally／Exiting due to internal error: …」、listen.c「Failed binding to …: …」、threads.c
//   「Unresponsive child for request N, in component C module M」、connection.c「rlm_x (名稱): Opening connection failed／No connections
//   available and at max connection limit」、rlm_ldap「Bind with … to … failed: …」），以及 systemd 單元結束與 kernel segfault 行。
// fields：svc（start／stopping／stop／crash／dbError／diskLow／bindFail／resource／replFail／backendFail／homeZombie／homeDead／homeAlive／noHome）、
//   svcName（openldap／389ds／freeradius）、svcDetail、svcDb、svcHome（「位址:埠」）、svcBackend（sql／ldap／redis…）、svcCritical
const SVC_APP = { slapd: 'openldap', 'ns-slapd': '389ds', dirsrv: '389ds', radiusd: 'freeradius', freeradius: 'freeradius' };
function svcNameOfApp(app) {
  const a = String(app || '').toLowerCase().replace(/\[.*$/, '').replace(/\.service$/, '');
  return /^dirsrv@/.test(a) ? '389ds' : (SVC_APP[a] || '');
}
function parseLdapSvc(name, t) {
  if (!name) return null;
  let x;
  const r = o => ({ vendor: 'ldap', fields: Object.assign({ svcName: name }, o) });
  if (/^slapd start(?:ing|ed)\b/.test(t)) return r({ svc: 'start' });
  if (/^slapd stopped\./.test(t)) return r({ svc: 'stop' });
  if (/^(?:daemon: shutdown requested and initiated|slapd shutdown: waiting|slapd shutting down)\b/.test(t)) return r({ svc: 'stopping' });
  if ((x = t.match(/^daemon: bind\(-?\d+\) failed errno=(\d+) \((.*?)\)/))) return r({ svc: 'bindFail', svcDetail: `errno=${x[1]} (${x[2]})` });
  if ((x = t.match(/^daemon: accept\(-?\d+\) failed errno=(\d+) \((.*?)\)/))) return r({ svc: 'resource', svcDetail: `accept errno=${x[1]} (${x[2]})` });
  if ((x = t.match(/^backend_startup_one \(type=(\S+), suffix="(.*?)"\): bi_db_open failed! \((-?\d+)\)/))) return r({ svc: 'dbError', svcDb: x[2], svcDetail: `bi_db_open failed (${x[1]}, ${x[3]})` });
  if ((x = t.match(/^mdb_db_open: database "(.*?)"(?: cannot be opened)?: (.*)$/))) return r({ svc: 'dbError', svcDb: x[1], svcDetail: x[2].replace(/\s*Administrator intervention needed!\s*$/, '') });
  if ((x = t.match(/\bmdb_put failed: (.*?)\((-?\d+)\)/))) return r({ svc: 'dbError', svcDetail: x[1].trim() });
  if ((x = t.match(/\b(MDB_MAP_FULL|MDB_CORRUPTED|MDB_PANIC)\b/))) return r({ svc: 'dbError', svcDetail: x[1] });
  if ((x = t.match(/^do_syncrepl: (\S+) rc (-?\d+) (retrying|quitting)/))) return r({ svc: 'replFail', svcDetail: `${x[1]} rc ${x[2]} ${x[3]}` });
  if ((x = t.match(/^Disk space is (critically )?low on disk \((.*?)\)/))) return r({ svc: 'diskLow', svcDetail: x[2], svcCritical: !!x[1] });
  if (/Failed to checkpoint database/.test(t)) return r({ svc: 'dbError', svcDetail: 'Failed to checkpoint database' });
  if (/Unable to acquire replica/.test(t)) return r({ svc: 'replFail', svcDetail: 'Unable to acquire replica' });
  return null;
}
function parseFreeRadiusSvc(msg) {
  const t = String(msg || '').trim();
  let x;
  const r = o => ({ vendor: 'freeradius', fields: Object.assign({ svcName: 'freeradius' }, o) });
  if (/^Ready to process requests\b/.test(t)) return r({ svc: 'start' });
  if (/^Exiting normally\b/.test(t)) return r({ svc: 'stop' });
  if ((x = t.match(/^Exiting due to internal error: (.*)$/))) return r({ svc: 'crash', svcDetail: x[1] });
  if ((x = t.match(/^Failed binding to (?!interface )(.+?): (.+)$/))) return r({ svc: 'bindFail', svcDetail: `${x[1]}: ${x[2]}` });
  if ((x = t.match(/Marking home server (\S+) port (\d+) as (zombie|dead)/))) return r({ svc: x[3] === 'dead' ? 'homeDead' : 'homeZombie', svcHome: `${x[1]}:${x[2]}` });
  if ((x = t.match(/Marking home server (\S+) port (\d+) alive/))) return r({ svc: 'homeAlive', svcHome: `${x[1]}:${x[2]}` });
  if ((x = t.match(/Failed to find live home server(?: for realm (\S+?))?(?::|$)/))) return r({ svc: 'noHome', svcDetail: x[1] || '' });
  if ((x = t.match(/Unresponsive child for request (\d+), in component (\S+) module (\S+)/))) return r({ svc: 'resource', svcDetail: `Unresponsive child: ${x[2]} / ${x[3]}` });
  if ((x = t.match(/^Dropping request \((\d+) is too many\)/))) return r({ svc: 'resource', svcDetail: `max_requests (${x[1]})` });
  if ((x = t.match(/^(rlm_(\w+)) \((\S+?)\): (Opening connection failed|No connections available and at max connection limit|Last connection attempt failed|Cannot open new connection, already at max)/))) return r({ svc: 'backendFail', svcBackend: x[2], svcDetail: `${x[1]} (${x[3]}): ${x[4]}` });
  if ((x = t.match(/Bind with (.+?) to (.+?) failed: (.+)$/))) return r({ svc: 'backendFail', svcBackend: 'ldap', svcDetail: `${x[2]}: ${x[3]}` });
  return null;
}
// systemd 單元結束（Main process exited, code=dumped|killed|exited, status=…／Failed with result '…'）與 kernel segfault 行
function parseSvcSysMsg(appName, msg) {
  const app = String(appName || '').toLowerCase().replace(/\[.*$/, '');
  const t = String(msg || '').trim();
  let x;
  if (app === 'systemd' || app === 'init') {
    x = t.match(/^(\S+?\.service): (?:Main process exited, code=(\w+), status=(\S+?)\.?$|Failed with result '([\w-]+)'\.?$)/);
    if (!x) return null;
    const name = svcNameOfApp(x[1]);
    if (!name) return null;
    const v = name === 'freeradius' ? 'freeradius' : 'ldap';
    if (x[2]) return x[2] === 'exited' && /^0\//.test(x[3]) ? null : { vendor: v, fields: { svcName: name, svc: 'crash', svcDetail: `code=${x[2]}, status=${x[3]}` } };
    return x[4] === 'success' ? null : { vendor: v, fields: { svcName: name, svc: 'crash', svcDetail: `result=${x[4]}` } };
  }
  if (app === 'kernel' && (x = t.match(/(?:^|\]\s*)(slapd|ns-slapd|radiusd|freeradius)\[(\d+)\]: segfault at /))) {
    const name = SVC_APP[x[1]];
    return { vendor: name === 'freeradius' ? 'freeradius' : 'ldap', fields: { svcName: name, svc: 'crash', svcDetail: `segfault (pid ${x[2]})` } };
  }
  return null;
}
function parseVpnAuthMsg(appName, msg) {
  const a = String(appName || '');
  if (/^(?:openvpn|ovpn)/i.test(a)) return parseOpenVpnMsg(msg);
  if (/^(?:charon|ipsec$|strongswan)/i.test(a)) return parseStrongSwanMsg(msg);
  if (/^(?:radiusd|freeradius)$/i.test(a)) return parseFreeRadiusMsg(msg) || parseFreeRadiusSvc(msg);
  return null;
}
// TLS 失敗已有同一請求的 Login incorrect 行（radPaired）時只算那一行，避免一次失敗算兩次
const vpnAuthFailed = f => !!f && (f.ovpn === 'authfail' || f.ovpn === 'verifyfail' || f.ipsec === 'authfail' || f.radius === 'reject' || (f.radius === 'tlsfail' && !f.radPaired));
const isVpnAuthFields = f => !!f && !!(f.ovpn || f.ipsec || f.radius);
// 不經 syslog 的記錄檔：OpenVPN log 檔（ISO 或 ctime 時間＋訊息）、strongSwan charon.log（[月 日 時間 ]執行緒[群組] 訊息，
// time_format 未設定時沒有時間）、FreeRADIUS radius.log（ctime : 等級: 訊息）
const VPN_CTIME_SRC = '[A-Z][a-z]{2} [A-Z][a-z]{2} [ \\d]\\d \\d{2}:\\d{2}:\\d{2} \\d{4}';
const RADIUS_FILE_RE = new RegExp(`^(${VPN_CTIME_SRC}) : (Auth|Info|Error|ERROR|Warning|WARNING|Proxy|Debug): ([\\s\\S]*)$`);
const OVPN_FILE_RE = new RegExp(`^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}|${VPN_CTIME_SRC}) ([\\s\\S]*)$`);
const CHARON_FILE_RE = /^(?:([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) )?(\d{2}\[[A-Z]{2,4}\] [\s\S]*)$/;
const OVPN_FILE_HINT_RE = /^(?:OpenVPN \d|Initialization Sequence Completed|(?:[^/:\[\]]+?\/)?[0-9A-Fa-f.:]+:\d+ \S)/;
function vpnFileKind(line) {
  let m = line.match(RADIUS_FILE_RE);
  if (m) return { app: 'radiusd', vendor: 'freeradius', tsRaw: m[1], level: m[2], msg: m[3], prefix: line.slice(0, line.length - m[3].length) };
  if ((m = line.match(CHARON_FILE_RE))) return { app: 'charon', vendor: 'strongswan', tsRaw: m[1] || '', bsd: true, msg: m[2], prefix: line.slice(0, line.length - m[2].length) };
  if ((m = line.match(OVPN_FILE_RE)) && (OVPN_FILE_HINT_RE.test(m[2]) || parseOpenVpnMsg(m[2]))) return { app: 'openvpn', vendor: 'openvpn', tsRaw: m[1], msg: m[2], prefix: line.slice(0, line.length - m[2].length) };
  return null;
}
function parseVpnFileLine(line, lineNo) {
  const k = vpnFileKind(line);
  if (!k) return null;
  const vf = parseVpnAuthMsg(k.app, k.msg);
  const f = vf ? vf.fields : {};
  const ts = !k.tsRaw ? null : k.bsd ? parseSyslogTimestamp(k.tsRaw, 'bsd') : new Date(k.tsRaw);
  return {
    format: 'vpnauth', raw: line, lineNo, netFields: !!vf, netVendor: k.vendor,
    timestamp: ts && !isNaN(ts.getTime()) ? ts : null, timestampRaw: k.tsRaw,
    host: '', appName: k.app, procid: '', msgid: '', severityRaw: k.level || '', severityNorm: k.level ? normGenericSeverity(k.level === 'Auth' ? 'info' : k.level) : 'Info',
    facility: null, facilityAuth: false, msg: k.msg, rawPrefix: k.prefix, fields: f
  };
}
// 同一工作階段的事件互補：strongSwan 依連線名稱＋編號帶入對端位址（認證失敗訊息沒有位址）、依編號或對端 ID 帶入
// 指派位址給 deleting IKE_SA；OpenVPN 依用戶端「位址:埠」帶入指派位址給 client-instance exiting（位址歸屬結束點）
// ── FreeRADIUS detail 檔（第三十輪 RA1）──
// rlm_detail 寫入的 radacct/<NAS>/detail-YYYYMMDD 與 auth-detail：每筆以 ctime 時間行開頭（Tue Oct 20 10:00:00 2026），
// 之後每行以 Tab 縮排「屬性 = 值」（字串帶雙引號），空行分隔；檔案寫入時另加 Timestamp = Unix 秒。
// 欄位：radacct（start／stop／interim／on／off／request）、user、assignIp（Framed-IP-Address）、mac（Calling-Station-Id）、
// netHost（NAS-Identifier 或 NAS-IP-Address）、nasPort、sessionId、sessionTime、terminateCause、bytesIn／bytesOut；
// Start／Interim 與 Stop 交給 addrAssignOf() 建立位址歸屬
const RADDETAIL_HEAD_RE = new RegExp(`^(${VPN_CTIME_SRC})\\s*$`);
const RADDETAIL_ATTR_RE = /^[ \t]+([A-Za-z][\w-]*(?::[\w-]+)?) = (.*)$/;
// 可與其他 log 串接上傳：只取「時間行＋縮排屬性行」區塊，回傳事件與用掉的行（0 起算）
function parseRadiusDetail(text) {
  const lines = Array.isArray(text) ? text : text.split('\n');
  const events = [], used = new Set();
  let cur = null;
  const flush = () => {
    if (!cur) return;
    const a = cur.attrs, f = { radacctAttrs: a, radacctQuoted: cur.quoted, radacctPairs: cur.pairs };
    const st = String(a['Acct-Status-Type'] || '').toLowerCase();
    f.radacct = { start: 'start', stop: 'stop', 'interim-update': 'interim', 'alive': 'interim', 'accounting-on': 'on', 'accounting-off': 'off' }[st] || (st ? st : 'request');
    if (a['User-Name']) f.user = a['User-Name'];
    if (a['Framed-IP-Address']) f.assignIp = a['Framed-IP-Address'];
    if (a['Calling-Station-Id']) f.mac = a['Calling-Station-Id'];
    const nas = a['NAS-Identifier'] || a['NAS-IP-Address'] || '';
    if (nas) f.netHost = nas;
    if (a['NAS-IP-Address']) f.nasIp = a['NAS-IP-Address'];
    if (a['NAS-Port-Id'] || a['NAS-Port']) f.nasPort = a['NAS-Port-Id'] || a['NAS-Port'];
    if (a['Acct-Session-Id']) f.sessionId = a['Acct-Session-Id'];
    if (a['Acct-Session-Time']) f.sessionTime = a['Acct-Session-Time'];
    if (a['Acct-Terminate-Cause']) f.terminateCause = a['Acct-Terminate-Cause'];
    if (a['Acct-Input-Octets']) f.bytesIn = a['Acct-Input-Octets'];
    if (a['Acct-Output-Octets']) f.bytesOut = a['Acct-Output-Octets'];
    if (a['Packet-Src-IP-Address']) f.srcip = a['Packet-Src-IP-Address'];
    let ts = new Date(cur.tsRaw);
    if (a.Timestamp && /^\d+$/.test(a.Timestamp)) ts = new Date(Number(a.Timestamp) * 1000);
    const msg = `${st ? 'Accounting-' + (a['Acct-Status-Type']) : 'Access-Request'} ${f.user || '-'}${f.assignIp ? ' ' + f.assignIp : ''}${f.mac ? ' cli ' + f.mac : ''}${nas ? ' via ' + nas : ''}${f.terminateCause ? ' (' + f.terminateCause + ')' : ''}`;
    events.push({
      format: 'radacct', raw: cur.raw.join('\n') + '\n', lineNo: cur.lineNo, netFields: true, netVendor: 'freeradius',
      timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: cur.tsRaw, host: '', appName: 'radiusd', procid: '', msgid: '',
      severityRaw: '', severityNorm: 'Info', facility: null, facilityAuth: false, msg, fields: f
    });
    cur = null;
  };
  lines.forEach((line, i) => {
    const h = line.match(RADDETAIL_HEAD_RE);
    if (h && RADDETAIL_ATTR_RE.test(lines[i + 1] || '')) { flush(); cur = { tsRaw: h[1], lineNo: i + 1, attrs: {}, quoted: [], pairs: [], raw: [line] }; used.add(i); return; }
    const m = cur && line.match(RADDETAIL_ATTR_RE);
    if (m) {
      const v = m[2].trim(), q = /^".*"$/.test(v);
      const val = q ? v.slice(1, -1).replace(/\\"/g, '"') : v;
      // 同名屬性（如多行 Cisco-AVPair）attrs 只留第一筆，pairs 保留全部供重組
      if (!(m[1] in cur.attrs)) cur.attrs[m[1]] = val;
      if (q) cur.quoted.push(m[1]);
      cur.pairs.push([m[1], val, q]);
      cur.raw.push(line); used.add(i); return;
    }
    flush();
  });
  flush();
  return { events, used };
}
// 去識別化：屬性值依名稱處理（帳號、MAC、位址、NAS 名稱、Called-Station-Id 的 SSID 後綴），其餘值做通用替換，重組成原格式
const RADDETAIL_SECRET_RE = /^(?:User-Password|CHAP-Password|MS-CHAP-Challenge|MS-CHAP2-Response|MS-CHAP-Response|EAP-Message|Message-Authenticator|State|Class)$/i;
// 不帶分隔符號的 12 碼 MAC（3c5282112233）
const MAC_BARE_RE = /\b[0-9A-Fa-f]{12}\b/g;
const anonBareMACs = s => String(s).replace(MAC_BARE_RE, m => /[A-Fa-f]/.test(m) || /^0/.test(m) ? anonMAC(m) : m);
// Called-Station-Id：「MAC[:SSID]」、12 碼 MAC 或位址（VPN 類 NAS）；SSID 本身可含冒號
const RAD_CALLED_RE = /^((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12})(?:[:-](.+))?$/;
function anonCalledStationId(v, opts) {
  const m = String(v).match(RAD_CALLED_RE);
  if (m) return anonMAC(m[1]) + (m[2] !== undefined ? v.charAt(m[1].length) + anonHostname(m[2]) : '');
  return anonEmails(replaceMACsInLine(replaceIPsInLine(String(v), opts)));
}
function anonymizeRadacctEvent(clone, opts) {
  const fv = clone.fields;
  const pairs0 = fv.radacctPairs || Object.keys(fv.radacctAttrs || {}).map(k => [k, fv.radacctAttrs[k], (fv.radacctQuoted || []).includes(k)]);
  const pairs = pairs0.map(([k, v, q]) => {
    let o;
    if (RADDETAIL_SECRET_RE.test(k)) o = 'REDACTED';
    else if (/^(?:User-Name|Stripped-User-Name)$/i.test(k)) o = anonUser(v);
    else if (/^NAS-Identifier$/i.test(k)) o = isValidIPv4(v) ? replaceIPsInLine(v, opts) : anonHostname(v);
    else if (/^Called-Station-Id$/i.test(k)) o = anonCalledStationId(v, opts);
    else if (/^Calling-Station-Id$/i.test(k)) o = anonBareMACs(replaceMACsInLine(replaceIPsInLine(v, opts)));
    // 網域（Realm）與 SSID 類屬性（Aruba-Essid-Name、Ruckus-SSID、Called-Station-SSID…）
    else if (/^(?:Realm|Stripped-User-Domain)$/i.test(k)) o = v.includes('.') ? anonDnsName(v) : anonHostname(v);
    else if (/ssid/i.test(k)) o = anonHostname(v);
    else o = anonEmails(replaceMACsInLine(replaceIPsInLine(v, opts)));
    return [k, o, q];
  });
  const head = clone.raw.split('\n')[0];
  const raw = [head, ...pairs.map(([k, v, q]) => `\t${k} = ${q ? '"' + String(v).replace(/"/g, '\\"') + '"' : v}`)].join('\n') + '\n';
  const ev = parseRadiusDetail(raw).events[0];
  if (ev) Object.assign(clone, { fields: ev.fields, msg: ev.msg });
  clone.raw = raw;
}
function linkVpnSessions(events) {
  // FreeRADIUS：同一請求編號的 TLS 錯誤補上該請求 Login incorrect 行的帳號、NAS 與用戶端（第三十輪 RA2）
  // 請求編號在服務重啟後會重新計數，只取時間最接近（60 秒內；無時間時 50 行內）的那一行
  const radReq = new Map();
  events.forEach(e => { const f = e.fields; if (f && f.radius && f.radius !== 'tlsfail' && f.reqId && f.user) { const k = `${e.host}|${f.reqId}`; if (!radReq.has(k)) radReq.set(k, []); radReq.get(k).push(e); } });
  events.forEach(e => {
    const f = e.fields;
    if (!f || f.radius !== 'tlsfail' || !f.reqId) return;
    let best = null, bestD = Infinity;
    (radReq.get(`${e.host}|${f.reqId}`) || []).forEach(x => {
      const d = e.timestamp && x.timestamp ? Math.abs(x.timestamp - e.timestamp) : Math.abs(x.lineNo - e.lineNo) * 1000;
      if (d < bestD) { best = x; bestD = d; }
    });
    if (!best || bestD > 60000) return;
    const r = best.fields;
    ['user', 'netHost', 'nasPort', 'mac', 'srcip'].forEach(k => { if (r[k] && !f[k]) f[k] = r[k]; });
    if (r.radius === 'reject') f.radPaired = true;
  });
  const sa = new Map(), peer = new Map(), ovpn = new Map(), lastUp = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (!f) return;
    if (f.ipsec) {
      const k = f.saId ? `${e.host}|${f.saName}|${f.saId}` : '';
      const s = k ? (sa.get(k) || {}) : {};
      if (f.srcip) s.srcip = f.srcip; else if (s.srcip) f.srcip = s.srcip;
      if (f.ipsec === 'up' && k && f.user) lastUp.set(`${e.host}|${f.user}`, k);
      if (f.ipsec === 'assign' && f.assignIp) {
        s.assignIp = f.assignIp;
        if (f.user) peer.set(`${e.host}|${f.user}`, f.assignIp);
        // 沒有 <連線|編號> 前綴的 syslog：指派位址記到同帳號最近建立的 SA，同帳號多個 SA 結束時才不會對錯位址
        const up = !k && f.user ? sa.get(lastUp.get(`${e.host}|${f.user}`)) : null;
        if (up && !up.assignIp) up.assignIp = f.assignIp;
      }
      if (f.ipsec === 'down' && !f.assignIp) {
        const ip = s.assignIp || peer.get(`${e.host}|${f.user}`);
        if (ip) f.assignIp = ip;
        peer.delete(`${e.host}|${f.user}`);
      }
      if (k) sa.set(k, s);
    } else if (f.ovpn && f.srcip) {
      const k = `${e.host}|${f.srcip}|${f.srcport}`;
      if ((f.ovpn === 'assign' || f.ovpn === 'learn') && f.assignIp) ovpn.set(k, f.assignIp);
      else if (f.ovpn === 'exit' && !f.assignIp && ovpn.has(k)) { f.assignIp = ovpn.get(k); ovpn.delete(k); }
    }
  });
  return events;
}
// ── LDAP 伺服器 log（第三十輪 LD1／LD2）──
// OpenLDAP slapd（loglevel stats，syslog 程式名稱 slapd）：conn=N fd=N ACCEPT from IP=位址:埠 (IP=監聽位址:埠)、
//   conn=N op=N BIND dn="…" method=128（128 為簡單繫結）、BIND dn="…" mech=SIMPLE [bind_]ssf=N ssf=N、RESULT tag=97 err=49 …、
//   SRCH base="…" scope=2 deref=0 filter="…"、SEARCH RESULT tag=101 err=0 nentries=N、conn=N fd=N TLS established tls_ssf=N ssf=N、
//   conn=N op=N STARTTLS、conn=N fd=N closed；2.5 起 RESULT 多 qtime／etime
// 389 Directory Server access log（[時間] conn=N …）：conn=N fd=N slot=N [SSL ]connection from 位址 to 位址、
//   BIND dn="…" method=128 version=3、RESULT err=49 tag=97 nentries=0 etime=…、SRCH base="…" scope=2 filter="…" attrs=…、
//   conn=N TLS1.3 256-bit AES-GCM、conn=N op=N fd=N Disconnect - 原因 - 代碼（依 389ds/389-ds-base 原始碼與 logconv 測試）
// 欄位：ldap（accept／bind／result／search／searchres／tls／starttls／closed／op）、conn、op、srcip、srcport、dstport、dn、method、
//   tag、err、base、scope、filter、nentries；linkLdapConns() 依連線補上 srcip、user、dn，BIND 結果改為 bindok／bindfail
const LDAP_CONN_RE = /^conn=(\d+)\s+(?:op=(-?\d+)\s+)?(?:fd=\d+\s+)?(?:slot=\d+\s+)?([\s\S]*)$/;
const ldapHostPort = s => { const m = String(s).match(/^\[?([0-9A-Fa-f:.]+?)\]?:(\d+)$/); return m ? [m[1], m[2]] : [String(s), '']; };
// OpenLDAP 2.6 寫檔（logfile）每行前綴「十六進位秒.十六進位微秒 0x執行緒 」，syslog 內同樣可能出現
const LDAP26_PREFIX_RE = /^[0-9a-f]{8}\.[0-9a-f]{8} (?:0x[0-9a-f]+ )?/;
function parseLdapBody(body) {
  const m = String(body || '').trim().replace(LDAP26_PREFIX_RE, '').match(LDAP_CONN_RE);
  if (!m) return null;
  const f = { conn: m[1] };
  if (m[2] !== undefined) f.op = m[2];
  const s = m[3];
  let x;
  if ((x = s.match(/^ACCEPT from IP=(\S+) \(IP=(\S+)\)/))) {
    const [ip, port] = ldapHostPort(x[1]), [, lport] = ldapHostPort(x[2]);
    Object.assign(f, { ldap: 'accept', srcip: ip, srcport: port, dstport: lport });
  } else if (/^ACCEPT from PATH=/.test(s)) Object.assign(f, { ldap: 'accept', ldapLocal: true });
  else if ((x = s.match(/^(SSL )?connection from (\S+) to (\S+)/))) {
    // 389 本機 LDAPI：connection from local to /var/run/slapd-執行個體.socket
    if (x[2] === 'local' || /^\//.test(x[3])) Object.assign(f, { ldap: 'accept', ldapLocal: true });
    else Object.assign(f, { ldap: 'accept', srcip: x[2], dstip: x[3] });
    if (x[1]) f.ldapTls = true;
  } else if ((x = s.match(/^BIND dn="(.*?)" method=(\w+)(?:.*?\bmech=(\S+))?/))) Object.assign(f, { ldap: 'bind', dn: x[1], method: x[2], ...(x[3] ? { mech: x[3] } : {}) });
  else if ((x = s.match(/^BIND dn="(.*?)" mech=(\S+)/))) Object.assign(f, { ldap: 'bindmech', dn: x[1], mech: x[2] });
  else if ((x = s.match(/^SRCH base="(.*?)" scope=(\d)(?: deref=\d)? filter="(.*?)"/))) Object.assign(f, { ldap: 'search', base: x[1], scope: x[2], filter: x[3] });
  else if ((x = s.match(/^(SEARCH )?RESULT\b(.*)$/))) {
    const kv = k => ((x[2].match(new RegExp('\\b' + k + '=(\\S+)')) || [])[1]);
    Object.assign(f, { ldap: x[1] || kv('tag') === '101' ? 'searchres' : 'result', tag: kv('tag') || '', err: kv('err') || '' });
    if (kv('nentries') !== undefined) f.nentries = kv('nentries');
    // 389 的 SASL 繫結結果行另帶 dn="…"（實際身分）
    const rdn = x[2].match(/\bdn="(.*?)"/);
    if (rdn) f.resultDn = rdn[1];
    const t = x[2].match(/\btext=(.*)$/) || x[2].match(/ - (.+)$/);
    if (t && t[1].trim()) f.ldapText = t[1].trim();
  } else if (/^TLS established/.test(s) || /^TLS\d|^SSL\d/.test(s)) f.ldap = 'tls';
  else if (/^STARTTLS/.test(s) || /^EXT oid="?1\.3\.6\.1\.4\.1\.1466\.20037\b/.test(s)) f.ldap = 'starttls';
  else if (/^(?:closed|Disconnect)\b/.test(s)) f.ldap = 'closed';
  else if ((x = s.match(/^([A-Z]+)\b/))) Object.assign(f, { ldap: 'op', ldapOp: x[1] });
  else return null;
  return f;
}
function parseLdapMsg(appName, msg) {
  if (!/^(?:slapd|ns-slapd|dirsrv)/i.test(appName || '')) return null;
  const f = parseLdapBody(msg);
  // 不是 conn= 連線紀錄時看是不是服務本身的訊息（XN16）
  if (!f) return parseLdapSvc(svcNameOfApp(appName), String(msg || '').trim().replace(LDAP26_PREFIX_RE, ''));
  return { vendor: 'ldap', fields: f };
}
// ── Ivanti Connect Secure／Pulse Connect Secure 事件 log（XN94）──
// 格式依 Elastic integrations pulse_connect_secure 套件的 ingest pipeline grok 與 sample_event：
// syslog 表頭（<PRI>版本 或「月 日 時間 主機 版本」）ISO 時間 設備 PulseSecure: - - - 本地時間 - 節點 - [用戶端位址] 帳號(領域)[角色] - 訊息；
// 訊息依同一份 grok：Agent login succeeded|failed for 帳號/領域 (session:…) from 位址 with 用戶端、Login succeeded|failed… Reason: 原因、
// Primary authentication successful|failed…、VPN Tunneling: Session started|ended for user (session:…) with IPv4 address 位址。管理介面登入句型未查證不解析
const PCS_LINE_RE = /^(?:<\d{1,3}>\d*\s?|[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ \d+ )(\d{4}-\d{2}-\d{2}[T ]\d{2}:?\d{2}(?::?\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?) (\S+) PulseSecure: - - - (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\S+) - \[([^\]]*)\] (.*?) - ([\s\S]*)$/;
function parsePcsUser(s) {
  const m = String(s || '').match(/^(?:.*?::)?(?:[^\\()]*\\{1,2})?([^()@\[]*?)(?:@[^()]*)?\(([^)]*)\)\[([^\]]*)\]/);
  return m ? { user: m[1].trim(), realm: m[2], roles: m[3] } : { user: '', realm: '', roles: '' };
}
function parsePcsMsg(msg) {
  const s = String(msg || '').trim();
  let m;
  if ((m = s.match(/^Agent login (succeeded|failed) for (.*?) \(session:\s*(\S+?)\) from (\S+) with (.+?)\.?$/))) return { pcs: m[1] === 'failed' ? 'loginFail' : 'login', pcsSession: m[3], ua: m[5] };
  if ((m = s.match(/^Login (succeeded|failed)\b(?:[^(]*?\(session:\s*([^)\s]+)\))?(?:[\s\S]*?\. Reason: (.*))?/))) return { pcs: m[1] === 'failed' ? 'loginFail' : 'login', ...(m[2] ? { pcsSession: m[2] } : {}), ...(m[3] ? { pcsReason: m[3].trim() } : {}) };
  if ((m = s.match(/^Primary authentication (successful|failed)/))) return { pcs: m[1] === 'failed' ? 'primaryFail' : 'primary' };
  if ((m = s.match(/^VPN Tunneling: Session (started|ended) for user \(session:\s*(\S+?)\) with (\S+) address (\S+?)(?:, hostname (\S+))?$/))) return { pcs: m[1] === 'started' ? 'tunnel' : 'tunnelEnd', pcsSession: m[2], assignip: m[4] };
  return {};
}
function parsePcsLine(line, lineNo) {
  const m = line.match(PCS_LINE_RE);
  if (!m) return null;
  const u = parsePcsUser(m[6]);
  const f = { ...parsePcsMsg(m[7]), pcsNode: m[4] };
  if (u.user && !/^System$/i.test(u.user)) f.user = u.user;
  if (u.realm) f.realm = u.realm;
  if (u.roles) f.roles = u.roles;
  if (isValidIPv4(m[5]) || (m[5].includes(':') && /^[0-9a-f:.]+$/i.test(m[5]))) f.srcip = m[5];
  const tsRaw = m[1], ts = new Date(tsRaw.replace(' ', 'T').replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
  return {
    format: 'pcs', raw: line, lineNo, netFields: !!f.pcs, netVendor: 'pcs',
    timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: tsRaw, host: m[2], appName: 'PulseSecure', procid: '', msgid: '',
    severityRaw: '', severityNorm: /Fail$/.test(f.pcs || '') ? 'Low' : 'Info', facility: null, facilityAuth: true, msg: m[7], rawPrefix: line.slice(0, line.length - m[7].length), fields: f
  };
}
// 去識別化：表頭的設備、節點、用戶端位址與帳號換假值，訊息內的帳號、工作階段編號與位址一併替換後重新解析
function anonymizePcsEvent(evt, opts) {
  const f = evt.fields || {};
  let raw = evt.raw;
  if (f.user) raw = raw.split(f.user + '(').join(anonUser(f.user) + '(').replace(new RegExp('for ' + f.user.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/', 'g'), 'for ' + anonUser(f.user) + '/');
  if (f.realm) raw = raw.split('(' + f.realm + ')').join('(' + anonHostname(f.realm) + ')').split('/' + f.realm + ' (').join('/' + anonHostname(f.realm) + ' (');
  if (f.roles) raw = raw.split('[' + f.roles + ']').join('[REDACTED]');
  if (f.pcsSession) raw = raw.split(f.pcsSession).join('REDACTED');
  if (f.pcsNode) raw = raw.split(' - ' + f.pcsNode + ' - ').join(' - ' + anonHostname(f.pcsNode) + ' - ');
  if (evt.host && !isValidIPv4(evt.host)) raw = raw.split(' ' + evt.host + ' ').join(' ' + anonHostname(evt.host) + ' ');
  raw = raw.replace(/^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} )(\S+)/, (m, p, h) => p + (isValidIPv4(h) ? h : anonHostname(h)))
    .replace(/(auth server )(.+?)( \()/, (m, p, n, q) => p + anonHostname(n) + q)
    .replace(/(for [^\/\s]+\/)(\S+?)(?= \(| from)/g, (m, p, n) => p + anonHostname(n))
    .replace(/(\(session:\s*)[^)\s]+/g, '$1REDACTED')
    .replace(/(, hostname )(\S+)/, (m, p, h) => p + anonHostname(h));
  raw = replaceMACsInLine(replaceIPsInLine(raw, opts));
  return parsePcsLine(raw, evt.lineNo) || { ...evt, raw, msg: replaceIPsInLine(String(evt.msg || ''), opts), fields: {} };
}
// QNAP NAS（QTS）qulogd（XN111）：依 Elastic integrations qnap_nas ingest pipeline：「conn log:」與「event log:」，
// 共用「Users: [網域\\]帳號, Source IP: 位址, Computer name: 名稱」（--- 與 127.0.0.1 視為沒有），連線紀錄另有 Connection type、
// Accessed resources（可能含逗號）、Action；事件紀錄另有 Application、Category、Content。只拆這兩種句型
const QNAP_CONN_RE = /^conn log: Users: (.*?), Source IP: (.*?), Computer name: (.*?), Connection type: (.*?), Accessed resources: (.*), Action: (.*?)\s*$/;
const QNAP_EVENT_RE = /^event log: Users: (.*?), Source IP: (.*?), Computer name: (.*?)(?:, Application: (.*?), Category: (.*?))?, Content: ([\s\S]*)$/;
// HPE Aruba CX 事件 log（XN121）：訊息為「Event|事件編號|LOG_等級|模組|槽位|內容」，句型與編號依 Elastic integrations hpe_aruba_cx
// 套件的測試 log（AOS-CX Event Log Message Reference 的範例）。只拆出確定的項目：
//   管理登入 5209 SSH／4655 REST／12904 TELNET／13001 CONSOLE 成功、4601／4656／4662／5210／5215／5216／5220～5222／12905／12909／13002／13005 失敗
//   （接 adminLoginOf()）；介面上下線 403／404、Loop-protect 關閉埠 2801／2802／2809、BPDU 保護關閉埠 2007／5004、UDLD 封鎖 4104、
//   MAC 在埠間移動 4801、STP 封鎖 2014／2016／5008、風扇與電源 2xx／3xx 警告以上、寫入或複製設定 4613／4614（接 netOpsInfo()）
const ARUBACX_RE = /^Event\|(\d+)\|(LOG_[A-Z]+)\|([^|]*)\|([^|]*)\|([\s\S]*)$/;
const ARUBACX_LOGIN_OK = new Set(['5209', '4655', '12904', '13001']);
const ARUBACX_LOGIN_FAIL = new Set(['4601', '4656', '4662', '5210', '5215', '5216', '5220', '5221', '5222', '12905', '12909', '13002', '13005']);
function parseArubaCxMsg(msg) {
  const m = String(msg || '').match(ARUBACX_RE);
  if (!m) return null;
  const [, id, level, module, slot, text] = m;
  const f = { cx: id, cxLevel: level, cxModule: module, cxText: text.trim() };
  if (slot && slot !== '-') f.cxSlot = slot;
  const t = f.cxText;
  let x;
  if (ARUBACX_LOGIN_OK.has(id) || ARUBACX_LOGIN_FAIL.has(id)) {
    f.cxLogin = ARUBACX_LOGIN_OK.has(id) ? 'ok' : 'fail';
    if ((x = t.match(/^User (\S+) (?:logged in|login) from (\S+?)\.? (?:through|for) (\w+) session/))) { f.user = x[1]; if (/^[0-9a-f:.]+$/i.test(x[2]) && /[.:]/.test(x[2])) f.srcip = x[2]; f.cxProto = x[3]; }
    else if ((x = t.match(/^SSH session from (\S+) (?:for user|denied because username) (\S+)/))) { f.srcip = x[1]; f.user = x[2]; f.cxProto = 'SSH'; }
    else if ((x = t.match(/^Authentication failed for user (\S+)/))) f.user = x[1];
    else if ((x = t.match(/^RADIUS authorize-only request failed for SSH session from (\S+) for user (\S+?)\.?$/))) { f.srcip = x[1]; f.user = x[2]; f.cxProto = 'SSH'; }
  }
  return { vendor: 'arubacx', fields: f };
}
function parseQnapMsg(appName, msg) {
  if (!/^q(?:u)?logd$/.test(appName || '')) return null;
  const t = String(msg || '');
  const c = t.match(QNAP_CONN_RE), e = c ? null : t.match(QNAP_EVENT_RE);
  if (!c && !e) return null;
  const m = c || e, f = { qnap: c ? 'conn' : 'event' };
  const u = m[1].trim();
  if (u && u !== '---') { const d = u.match(/^([^\\]+)\\(.+)$/); if (d) { f.domain = d[1]; f.user = d[2]; } else f.user = u; }
  const ip = m[2].trim();
  if (ip && ip !== '---' && ip !== '127.0.0.1' && /^[\d.]+$|:/.test(ip)) f.srcip = ip;
  if (m[3].trim() && m[3].trim() !== '---') f.computer = m[3].trim();
  if (c) { f.conntype = c[4].trim(); f.resource = c[5].trim(); f.qnapAction = c[6].trim(); }
  else { if (e[4]) f.app = e[4].trim(); if (e[5]) f.category = e[5].trim(); f.content = e[6].trim(); }
  return { vendor: 'qnap', fields: f };
}
// QNAP（XN111）：帳號、電腦名稱、主機名稱換掉；存取的資源路徑與內容中雙引號內的名稱遮蔽；位址通用替換後重新解析
// HPE Aruba CX（XN121）：主機名稱、內容中的帳號（User X、user X、for user X、added X with role、session from User X）換假帳號，
// 再換位址與 MAC 後依原外殼重新解析
const ARUBACX_USER_RES = [/\b(User:? )(\S+?)(\.?)(?= (?:logged|login|added|has|removed)\b)/g, /\b(for user )(\S+?)(\.?)(?=[\s,.]|$)/g, /\b(added )(\S+)( with role\b)/g,
  /\b(with User )(\S+)()/g, /\b(from user )(\S+)()/g, /\b(username )(\S+)()/g, /\b(Session (?:started|ended) for user )([^,\s]+)()/g, /^(\S+)( has (?:written|copied))()/];
function anonymizeArubaCxEvent(evt, opts) {
  let raw = String(evt.raw || '');
  if (evt.host && !isValidIPv4(evt.host)) raw = raw.split(' ' + evt.host + ' ').join(' ' + anonHostname(evt.host) + ' ');
  const idx = raw.indexOf('Event|');
  if (idx >= 0) {
    const segs = raw.slice(idx).split('|');
    let text = segs.slice(5).join('|');
    ARUBACX_USER_RES.forEach(re => { text = re.source.startsWith('^') ? text.replace(re, (m, u, rest) => anonUser(u) + rest) : text.replace(re, (m, p, u, q) => p + anonUser(u) + q); });
    raw = raw.slice(0, idx) + segs.slice(0, 5).join('|') + '|' + text;
  }
  raw = replaceMACsInLine(replaceIPsInLine(raw, opts));
  return (evt.format === 'rfc5424' ? parseRFC5424Line(raw, evt.lineNo) : parseRFC3164Line(raw, evt.lineNo)) || { ...evt, raw, fields: {} };
}
function anonymizeQnapEvent(evt, opts) {
  const f = evt.fields || {};
  let raw = evt.raw;
  if (evt.host && !isValidIPv4(evt.host)) raw = raw.split(' ' + evt.host + ' ').join(' ' + anonHostname(evt.host) + ' ');
  if (f.user) raw = raw.replace(/(Users: (?:[^,\\]+\\)?)([^,]+)(?=, Source IP:)/, (m, p, u) => p + anonUser(u));
  if (f.domain) raw = raw.replace(/(Users: )([^,\\]+)(\\)/, (m, p, d, q) => p + anonHostname(d) + q);
  if (f.computer) raw = raw.replace(/(Computer name: )([^,]+)/, (m, p, n) => p + anonHostname(n));
  raw = raw.replace(/(Accessed resources: )(.*)(, Action: )/, (m, p, r, q) => p + (r.trim() === '---' ? r : ((r.match(/^\[[^\]]+\]/) || [''])[0] + ' REDACTED_PATH').trim()) + q);
  raw = raw.replace(/(Content: [\s\S]*)/, m => m.replace(/"[^"]*"/g, '"REDACTED"'));
  raw = replaceMACsInLine(replaceIPsInLine(raw, opts));
  return parseRFC3164Line(raw, evt.lineNo) || { ...evt, raw, msg: replaceIPsInLine(String(evt.msg || ''), opts), fields: {} };
}
// QNAP 勒索前兆（XN111）：有人手動刪除快照（自動輪替的 Users 為 ---，不算）；同一帳號＋來源 QNAP_MASS_WINDOW_MS 內刪除或改名
// 達 QNAP_MASS_MIN 次（用戶端中毒後加密共享資料夾時會出現；正常整理也可能），皆為需人工確認
const QNAP_MASS_WINDOW_MS = 10 * 60 * 1000, QNAP_MASS_MIN = 200;
function detectQnap(events) {
  const issues = [], snap = [], mass = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (e.netVendor !== 'qnap' || !f) return;
    if (f.qnap === 'event' && /^\[Storage & Snapshots\] Deleted snapshot/.test(f.content || '') && f.user && !/^system$/i.test(f.user)) snap.push(e);
    if (f.qnap === 'conn' && /^(?:Delete|Rename)$/i.test(f.qnapAction || '')) {
      const k = (e.host || '-') + '|' + (f.user || '-') + '|' + (f.srcip || '-');
      if (!mass.has(k)) mass.set(k, []);
      mass.get(k).push(e);
    }
  });
  const byU = new Map();
  snap.forEach(e => { const k = (e.host || '-') + '|' + e.fields.user; if (!byU.has(k)) byU.set(k, []); byU.get(k).push(e); });
  for (const list of byU.values()) {
    const e0 = list[0];
    issues.push({ category: 'qnapSnapshotDelete', severityNorm: 'High', count: list.length,
      firstSeen: e0.timestamp || null, lastSeen: list[list.length - 1].timestamp || null,
      ...sampleOf('sample.qnapSnapshotDelete', { host: e0.host || '-', user: e0.fields.user, src: e0.fields.srcip || '-', n: list.length }),
      relatedHosts: [e0.fields.user, e0.fields.srcip].filter(Boolean), relatedEvents: list, confidence: 'heuristic' });
  }
  for (const list of mass.values()) {
    const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    let best = null;
    for (let i = 0, j = 0; j < sorted.length; j++) {
      while (effectiveTime(sorted[j]) - effectiveTime(sorted[i]) > QNAP_MASS_WINDOW_MS) i++;
      if (j - i + 1 >= QNAP_MASS_MIN && (!best || j - i + 1 > best.length)) best = sorted.slice(i, j + 1);
    }
    if (!best) continue;
    const f = best[0].fields;
    issues.push({ category: 'qnapMassFileChange', severityNorm: 'Medium', count: best.length,
      firstSeen: best[0].timestamp || null, lastSeen: best[best.length - 1].timestamp || null,
      ...sampleOf('sample.qnapMassFileChange', { host: best[0].host || '-', user: f.user || '-', src: f.srcip || '-', n: best.length, conn: f.conntype || '-' }),
      relatedHosts: [f.user, f.srcip].filter(Boolean), relatedEvents: best, confidence: 'heuristic' });
  }
  return issues;
}
// Veeam Backup & Replication Event Forwarding（XN112）：RFC 5424，內容在「[categoryId=N instanceId=N 鍵="值" … Description="…"]」，
// 依 Elastic integrations veeam ingest pipeline（default.yml 取最後一段中括號的 key=value）。同一事件編號在文件與測試資料的說明不一致，
// 判斷一律以 Description 原文（同套件測試 log 的句型），不依編號
const VEEAM_SD_RE = /\[categoryId=(\d+) instanceId=(\d+)\s*([\s\S]*)\]\s*$/;
// 值裡可能有沒跳脫的雙引號（Description="… from "位址"."），依「空白＋鍵="」的位置切出每個值，再去掉結尾的雙引號
function veeamKv(text) {
  const out = Object.create(null), t = String(text || ''), re = /(?:^|\s)([A-Za-z][\w.]*)="/g, hits = [];
  let m;
  while ((m = re.exec(t))) hits.push({ k: m[1], s: m.index + m[0].length, at: m.index });
  hits.forEach((h, i) => { const end = i + 1 < hits.length ? hits[i + 1].at : t.length; out[h.k] = t.slice(h.s, end).replace(/"\s*$/, ''); });
  return out;
}
const VEEAM_RULES = [
  ['malware', /Potential malware activity detected|Malware detected by Veeam Threat Hunter|Restore point has been marked as infected/],
  ['defense', /^Disable four-eyes authorization event .* has been approved|objects have been added into the malware detection exclusions list|^Malware detection settings have been changed|^Security & Compliance Analyzer validation .* has been suppressed|^Recovery token has been removed/],
  ['delete', /^Failed attempt to delete backup from/],
  ['authFail', /^Invalid MFA code has been entered|^(?:Authorization|Token) request was denied: an authentication has failed/],
  ['change', /^(?:User or group|Credentials|Custom user role|Encryption password) .* ha(?:s|ve) been (?:added|deleted|modified|updated|created)|^Multi-factor authentication has been (?:enabled|disabled)|^Four-eyes authorization has been (?:enabled|disabled)/],
];
function parseVeeamMsg(rest) {
  const m = String(rest || '').match(VEEAM_SD_RE);
  if (!m) return null;
  const kv = veeamKv(m[3]);
  const f = { veeam: m[2], veeamCat: m[1] };
  ['UserName', 'VbrHostName', 'VbrVersion', 'SourceIpAddress', 'LastKnownHostName', 'BackupName', 'JobName'].forEach(k => { if (kv[k]) f[k] = kv[k]; });
  if (kv.UserName) { const d = String(kv.UserName).match(/^([^\\]+)\\(.+)$/); f.user = d ? d[2] : kv.UserName; }
  if (kv.SourceIpAddress) f.srcip = kv.SourceIpAddress;
  const desc = String(kv.Description || '').trim();
  const r = VEEAM_RULES.find(([, re]) => re.test(desc));
  if (r) f.veeamKind = r[0];
  return { vendor: 'veeam', fields: f, msg: desc };
}
// Veeam（XN112）：帳號（含 Description 內的網域\帳號）、主機名稱、位址換掉後重新解析
function anonymizeVeeamEvent(evt, opts) {
  const f = evt.fields || {};
  let raw = evt.raw;
  if (evt.host && !isValidIPv4(evt.host)) raw = raw.split(' ' + evt.host + ' ').join(' ' + anonHostname(evt.host) + ' ');
  // 帳號：UserName／FriendlyName／InitiatorName／Subject 的值（去掉網域與 .\ 前綴），整行同名一起換；網域\帳號寫法另外處理
  const sd = String(raw).match(VEEAM_SD_RE), kv = sd ? veeamKv(sd[3]) : {};
  const names = new Set();
  ['UserName', 'FriendlyName', 'InitiatorName', 'Subject'].forEach(k => { const v = String(kv[k] || '').replace(/^(?:\.|[^\\]+)\\/, '').trim(); if (v && v !== '-' && !/^SYSTEM$/i.test(v)) names.add(v); });
  [...names].sort((a, b) => b.length - a.length).forEach(n => { raw = raw.split(n).join(anonUser(n)); });
  raw = raw.replace(/\b([A-Za-z][A-Za-z0-9-]*)\\\\?(?=user-\d{3}\b)/g, (m, d) => /^(?:NT AUTHORITY|BUILTIN|user)$/i.test(d) ? m : anonHostname(d) + '\\');
  // 只出現在說明文字裡的「網域\帳號」（Backup job … started by user EXAMPLE\alice）；路徑片段也可能被換掉，寧可多遮
  raw = raw.replace(/\b([A-Za-z][A-Za-z0-9-]*)\\\\?((?!user-\d{3}\b)[A-Za-z0-9][A-Za-z0-9._-]*)/g, (m, d, u) => /^(?:NT AUTHORITY|BUILTIN)$/i.test(d) || /^(?:host|fw|dom)-device-\d{3}$/.test(d) ? m : anonHostname(d) + '\\' + anonUser(u));
  ['VbrHostName', 'LastKnownHostName'].forEach(k => { if (f[k] && !isValidIPv4(f[k])) raw = raw.split(f[k]).join(anonHostname(f[k])); });
  raw = replaceMACsInLine(replaceIPsInLine(raw, opts));
  return parseRFC5424Line(raw, evt.lineNo) || { ...evt, raw, msg: replaceIPsInLine(String(evt.msg || ''), opts), fields: {} };
}
// Veeam 勒索前兆（XN112）：備份中偵測到惡意活動 veeamMalware、防護被關閉 veeamDefenseOff（停用四眼授權、加入惡意偵測排除、抑制合規檢查、
// 移除復原權杖）、刪除備份的嘗試被擋下 veeamDeleteAttempt；依主機＋類別合併，皆為需人工確認
const VEEAM_ISSUE = { malware: ['veeamMalware', 'High'], defense: ['veeamDefenseOff', 'High'], delete: ['veeamDeleteAttempt', 'High'] };
function detectVeeam(events) {
  const groups = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (e.netVendor !== 'veeam' || !f || !VEEAM_ISSUE[f.veeamKind]) return;
    const k = (e.host || '-') + '|' + f.veeamKind;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(e);
  });
  const issues = [];
  for (const list of groups.values()) {
    const e0 = list[0], [cat, sev] = VEEAM_ISSUE[e0.fields.veeamKind];
    const items = [...new Set(list.map(e => String(e.msg || '').slice(0, 80)))].slice(0, 3).join('；');
    const users = [...new Set(list.map(e => e.fields.user).filter(Boolean))];
    issues.push({ category: cat, severityNorm: sev, count: list.length,
      firstSeen: e0.timestamp || null, lastSeen: list[list.length - 1].timestamp || null,
      ...sampleOf('sample.' + cat, { host: e0.host || '-', n: list.length, items, users: users.join(', ') || '-' }),
      relatedHosts: [e0.host, ...users].filter(Boolean), relatedEvents: list, confidence: 'heuristic' });
  }
  return issues;
}
// Vault 防護與特權（XN117）：停用稽核裝置 vaultAuditDisabled（delete sys/audit/<名稱>，停用後的操作不再留下紀錄，High，T1562.008）、
// root token 的使用與產生 vaultRootUse（auth.policies 含 root 或 sys/generate-root 的 update；HashiCorp 建議 root token 只在緊急時產生、
// 用完立即撤銷，Medium，T1078.003）。只看 response、成功的操作；依帳號＋類別合併，皆為需人工確認
function detectVault(events) {
  const tsOf = list => { const t = list.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b); return [t[0] || null, t[t.length - 1] || null]; };
  const groups = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (e.netVendor !== 'vault' || !f || f.vault !== 'response' || f.error) return;
    const kind = f.op === 'delete' && /^sys\/audit\/[^\/]+$/.test(f.path || '') ? 'vaultAuditDisabled'
      : (f.root || (/^sys\/generate-root\b/.test(f.path || '') && f.op === 'update')) ? 'vaultRootUse' : '';
    if (!kind) return;
    const k = kind + '|' + (kind === 'vaultRootUse' ? (f.srcip || '-') : (f.user || '-'));
    if (!groups.has(k)) groups.set(k, { kind, list: [] });
    groups.get(k).list.push(e);
  });
  const issues = [];
  for (const g of groups.values()) {
    const l = g.list, f0 = l[0].fields, [first, last] = tsOf(l);
    const ips = [...new Set(l.map(e => e.fields.srcip).filter(Boolean))], paths = [...new Set(l.map(e => e.fields.path))];
    issues.push({ category: g.kind, severityNorm: g.kind === 'vaultAuditDisabled' ? 'High' : 'Medium', count: l.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.' + g.kind, { who: f0.user || '-', ips: ips.slice(0, 3).join(', ') || '-', n: l.length, items: paths.slice(0, 3).join(', ') }),
      relatedHosts: [f0.user, ...ips.slice(0, 3)].filter(Boolean), relatedEvents: l, confidence: 'heuristic' });
  }
  return issues;
}
// RouterOS 入侵後常見的設定改動（XN129，需人工確認）：依 mikrotikCfgOf() 的物件名稱關鍵字判斷，依設備＋類別合併。
// 物件名稱除 filter／nat／mangle rule 外是依文件句型推得，查無逐字範例；規則被 changed 時看不出是否為停用，只寫「被變更」。
//  mtFwTamper：filter／raw／nat rule 被 removed／changed／moved（High，T1562.004）
//  mtUserChange：user（不含 user group）added／changed（High，T1136.001）
//  mtPersistence：script／scheduler added／changed（High，T1053.005）
//  mtProxyEnable：socks／proxy added／changed（Medium，T1090）
//  mtServiceChange：service changed，可能放寬管理來源（Medium，T1562.004）
// 同設備在第一筆改動前 24 小時內有外部位址登入管理介面成功時，以該來源為行為者（攻擊鏈才能與登入串在一起）
const MT_TAMPER_RULES = [
  ['mtFwTamper', /\b(?:filter|raw|nat) rule\b/i, /^(?:removed|changed|moved)$/, 'High'],
  ['mtUserChange', /^user\b(?!\s+group)/i, /^(?:added|changed)$/, 'High'],
  ['mtPersistence', /\b(?:script|scheduler)\b/i, /^(?:added|changed)$/, 'High'],
  ['mtProxyEnable', /\b(?:socks|proxy)\b/i, /^(?:added|changed)$/, 'Medium'],
  ['mtServiceChange', /\bservice\b/i, /^changed$/, 'Medium'],
];
const MT_TAMPER_LOGIN_WINDOW_MS = 24 * 3600 * 1000;
function detectMikroTikTamper(events) {
  const groups = new Map(), logins = [];
  events.forEach(e => {
    if (e.netVendor !== 'mikrotik') return;
    const a = adminLoginOf(e);
    if (a && a.ok && e.timestamp && !iocIsInternalIP(a.src)) logins.push({ host: e.host || '-', t: e.timestamp.getTime(), src: a.src });
    const c = mikrotikCfgOf(e);
    if (!c) return;
    const r = MT_TAMPER_RULES.find(([, objRe, opRe]) => objRe.test(c.obj) && opRe.test(c.op));
    if (!r) return;
    const k = r[0] + '|' + (e.host || '-');
    if (!groups.has(k)) groups.set(k, { kind: r[0], sev: r[3], list: [] });
    groups.get(k).list.push({ e, c });
  });
  const issues = [];
  for (const g of groups.values()) {
    const l = g.list, host = l[0].e.host || '-';
    const ts = l.map(x => x.e.timestamp).filter(Boolean).sort((a, b) => a - b);
    const t0 = ts.length ? ts[0].getTime() : null;
    const prior = t0 === null ? [] : logins.filter(x => x.host === host && x.t <= t0 && t0 - x.t <= MT_TAMPER_LOGIN_WINDOW_MS).sort((a, b) => b.t - a.t);
    const src = prior.length ? prior[0].src : '';
    const items = [...new Set(l.map(x => `${x.c.obj} ${x.c.op}`))];
    const who = [...new Set(l.map(x => x.c.user))];
    issues.push({ category: g.kind, severityNorm: g.sev, count: l.length, firstSeen: ts[0] || null, lastSeen: ts[ts.length - 1] || null,
      ...sampleOf('sample.' + g.kind, { host, n: l.length, items: items.slice(0, 4).join(', '), who: who.slice(0, 3).join(', '), src: src || '-' }),
      relatedHosts: [src || host, ...who.slice(0, 3)].filter(Boolean), relatedEvents: l.map(x => x.e), confidence: 'heuristic' });
  }
  return issues;
}
// 高風險服務埠的外部存取（XN129，不限廠牌）：有目的埠的流量事件、來源為外部位址，依 RISKY_PORTS 比對。
// 依 eventFwOutcome()：明確放行＝riskyPortAllowed（High，T1190，攻擊鏈 access）；拒絕或判斷不出＝探測，
// 同服務 ≥ RISKY_PROBE_MIN_SRC 個來源或 ≥ RISKY_PROBE_MIN_HITS 次才列 riskyPortProbe（Medium，T1595.001，recon）；
// 同一外部來源 1 小時內打 ≥ RISKY_SWEEP_MIN 種服務＝riskyPortSweep（High，T1595.001，recon）。
// cves 只收 CISA KEV 內的；設備只記錄部分放行流量時，沒有放行紀錄不代表沒放行
const RISKY_PORTS = [
  { port: 8291, proto: 'tcp', svc: 'MikroTik Winbox', cves: ['CVE-2018-14847'] },
  { port: 8728, proto: 'tcp', svc: 'RouterOS API', cves: [] },
  { port: 8729, proto: 'tcp', svc: 'RouterOS API-SSL', cves: [] },
  { port: 2000, proto: '', svc: 'MikroTik bandwidth-test', cves: [] },
  { port: 23, proto: 'tcp', svc: 'Telnet', cves: [] },
  { port: 2323, proto: 'tcp', svc: 'Telnet (alt)', cves: [] },
  { port: 445, proto: 'tcp', svc: 'SMB', cves: ['CVE-2017-0144'] },
  { port: 139, proto: 'tcp', svc: 'NetBIOS', cves: [] },
  { port: 3389, proto: '', svc: 'RDP', cves: ['CVE-2019-0708'] },
  { port: 5900, proto: 'tcp', svc: 'VNC', cves: [] },
  { port: 7547, proto: 'tcp', svc: 'TR-069', cves: [] },
  { port: 37215, proto: 'tcp', svc: 'Huawei HG532 UPnP', cves: [] },
  { port: 52869, proto: 'tcp', svc: 'Realtek SDK miniigd', cves: ['CVE-2014-8361'] },
  { port: 5555, proto: 'tcp', svc: 'Android ADB', cves: [] },
  { port: 6379, proto: 'tcp', svc: 'Redis', cves: [] },
  { port: 27017, proto: 'tcp', svc: 'MongoDB', cves: [] },
  { port: 9200, proto: 'tcp', svc: 'Elasticsearch', cves: [] },
  { port: 1433, proto: 'tcp', svc: 'MSSQL', cves: [] },
  { port: 3306, proto: 'tcp', svc: 'MySQL', cves: [] },
  { port: 161, proto: 'udp', svc: 'SNMP', cves: [] },
  { port: 1900, proto: 'udp', svc: 'SSDP', cves: [] },
  { port: 1080, proto: 'tcp', svc: 'SOCKS', cves: [] },
];
const RISKY_PROBE_MIN_SRC = 3, RISKY_PROBE_MIN_HITS = 10, RISKY_SWEEP_MIN = 3, RISKY_SWEEP_WINDOW_MS = 3600 * 1000;
function riskyPortOf(e) {
  const f = e && e.fields;
  if (!f || !f.srcip || !/^\d+$/.test(String(f.dstport || ''))) return null;
  if (e.format === 'weblog') return null;
  const port = +f.dstport, proto = String(f.proto || '').toLowerCase();
  return RISKY_PORTS.find(r => r.port === port && (!r.proto || !proto || proto.includes(r.proto))) || null;
}
function detectRiskyPortAccess(events) {
  const bySvc = new Map(), bySrc = new Map();
  events.forEach(e => {
    const r = riskyPortOf(e);
    if (!r || iocIsInternalIP(e.fields.srcip)) return;
    const out = eventFwOutcome(e);
    const k = r.svc + '|' + (out === 'accept' ? 'allowed' : 'probe');
    if (!bySvc.has(k)) bySvc.set(k, { r, allowed: out === 'accept', list: [] });
    bySvc.get(k).list.push(e);
    if (!bySrc.has(e.fields.srcip)) bySrc.set(e.fields.srcip, []);
    bySrc.get(e.fields.srcip).push({ e, r });
  });
  const issues = [];
  const span = list => { const t = list.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b); return [t[0] || null, t[t.length - 1] || null]; };
  for (const g of bySvc.values()) {
    const srcs = [...new Set(g.list.map(e => e.fields.srcip))], dsts = [...new Set(g.list.map(e => e.fields.dstip).filter(Boolean))];
    if (!g.allowed && srcs.length < RISKY_PROBE_MIN_SRC && g.list.length < RISKY_PROBE_MIN_HITS) continue;
    const kind = g.allowed ? 'riskyPortAllowed' : 'riskyPortProbe', [first, last] = span(g.list);
    issues.push({ category: kind, severityNorm: g.allowed ? 'High' : 'Medium', count: g.list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.' + kind, { svc: `${g.r.svc} (${g.r.port})`, n: g.list.length, srcs: srcs.length, ips: srcs.slice(0, 3).join(', '), dsts: dsts.slice(0, 3).join(', ') || '-', cves: g.r.cves.join(', ') || '-' }),
      cves: g.r.cves.slice(), relatedHosts: srcs.slice(0, 5), relatedEvents: g.list, confidence: 'heuristic' });
  }
  for (const [src, list] of bySrc) {
    list.sort((a, b) => (a.e.timestamp ? a.e.timestamp.getTime() : 0) - (b.e.timestamp ? b.e.timestamp.getTime() : 0));
    let best = null;
    for (let i = 0; i < list.length; i++) {
      const t0 = list[i].e.timestamp ? list[i].e.timestamp.getTime() : null;
      const win = list.slice(i).filter(x => t0 === null || !x.e.timestamp || x.e.timestamp.getTime() - t0 <= RISKY_SWEEP_WINDOW_MS);
      const svcs = new Set(win.map(x => x.r.svc));
      if (svcs.size >= RISKY_SWEEP_MIN && (!best || svcs.size > best.svcs.size)) best = { win, svcs };
    }
    if (!best) continue;
    const evs = best.win.map(x => x.e), [first, last] = span(evs);
    issues.push({ category: 'riskyPortSweep', severityNorm: 'High', count: evs.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.riskyPortSweep', { src, n: best.svcs.size, items: [...best.svcs].slice(0, 6).join(', ') }),
      relatedHosts: [src], relatedEvents: evs, confidence: 'heuristic' });
  }
  return issues;
}
// FortiMail／FortiManager（XN123）：欄位依 Elastic integrations fortinet_fortimail、fortinet_fortimanager 套件的真實測試 log。
//   FortiMail：「date=…,time=…,device_id=…,log_id=…,type=…,subtype=…」以逗號分隔（值可用 "…" 或 '…'），沒有時區（以本機時間解讀）；
//     kevent／admin 的 action=login＋status 接 adminLoginOf()（ui=方式(位址)），失敗＝authFail；kevent／config＝configChange；
//     webmail「Login for 'X' from 位址 failed」＝authFail；virus＝attack＋idsAlert；其餘（spam、statistics、system…）為一般事件
//   FortiManager：「date=… time=… tz="+hhmm" … log_id=… type=event subtype=…」以空白分隔；subtype system 的 operation login 接
//     adminLoginOf()（userfrom=方式(位址)，desc 含 failed＝authFail），objcfg／scrmgr／scply 與 dvm 的 Modify／Add device 由使用者（非 System）
//     執行＝configChange；未註冊設備被加入（msg「Unregistered device … add succeeded」，Fortinet FG-IR-24-423 公布的 CVE-2024-47575 跡象）
//     另列 fmgUnregDevice（High，需人工確認）
const FML_LINE_RE = /^(?:<\d{1,3}>)?date=(\d{4}-\d{2}-\d{2}),time=(\d{2}:\d{2}:\d{2})(?:\.(\d+))?,device_id=([^,]+),log_id=(\d+),/;
const FMG_LINE_RE = /^(?:<\d{1,3}>)?date=(\d{4}-\d{2}-\d{2}) time=(\d{2}:\d{2}:\d{2}) tz="?([+-])(\d{2})(\d{2})"?\s(?=[\s\S]*\blog_id="?\d{10}"?)/;
function fortiMgmtKv(s) {
  const kv = Object.create(null);
  String(s || '').replace(/([A-Za-z_][\w]*)=("(?:[^"\\]|\\.)*"|'[^']*'|[^,\s]*)/g, (m, k, v) => { if (!(k in kv)) kv[k] = /^["']/.test(v) ? v.slice(1, -1) : v; return m; });
  return kv;
}
const FORTI_UI_RE = /^([A-Za-z]+)\(([0-9a-f:.]+)\)$/i;
function parseFortiMgmtLine(line, lineNo) {
  const ml = line.match(FML_LINE_RE), mg = ml ? null : line.match(FMG_LINE_RE);
  if (!ml && !mg) return null;
  const vendor = ml ? 'fortimail' : 'fortimanager';
  const kv = fortiMgmtKv(line.replace(/^<\d{1,3}>/, ''));
  const ts = ml ? new Date(`${ml[1]}T${ml[2]}${ml[3] ? '.' + ml[3].slice(0, 3) : ''}`)
    : new Date(Date.parse(`${mg[1]}T${mg[2]}Z`) - (mg[3] === '-' ? -1 : 1) * (+mg[4] * 60 + +mg[5]) * 60000);
  const tsRaw = ml ? `${ml[1]} ${ml[2]}` : `${mg[1]} ${mg[2]} ${mg[3]}${mg[4]}${mg[5]}`;
  const f = { fm: vendor, fmType: kv.type || '', fmSub: kv.subtype || '', logid: kv.log_id || '' };
  const set = (k, v) => { if (v !== undefined && v !== null && v !== '' && v !== 'N/A') f[k] = String(v); };
  set('user', kv.user); set('fmAction', kv.action || kv.operation); set('fmStatus', kv.status); set('fmDesc', kv.desc); set('fmMsg', kv.msg); set('fmChanges', kv.changes);
  const ui = String(kv.ui || kv.userfrom || '').match(FORTI_UI_RE);
  if (ui) { f.method = ui[1]; f.srcip = ui[2]; }
  set('srcip', kv.client_ip || kv.src); set('dstip', kv.dst_ip); set('from', kv.from); set('to', kv.to); set('subject', kv.subject); set('device', kv.device || kv.performed_on);
  let x;
  if (vendor === 'fortimail' && f.fmType === 'event' && f.fmSub === 'webmail' && (x = String(kv.msg || '').match(/Login for '([^']+)' from (\S+) failed|User (\S+) from (\S+) logged in/))) {
    f.user = x[1] || x[3]; f.srcip = x[2] || x[4]; f.fmWebmail = x[1] ? 'fail' : 'ok';
  }
  if (vendor === 'fortimail' && f.fmType === 'virus' && (x = String(kv.msg || '').match(/is infected with (\S+?)\.?$/))) f.virus = x[1];
  const login = vendor === 'fortimail' ? f.fmType === 'kevent' && f.fmSub === 'admin' && /^login$/i.test(kv.action || '')
    : f.fmSub === 'system' && /^login$/i.test(kv.operation || '');
  if (login && f.srcip) f.fmLogin = /fail/i.test((kv.status || '') + ' ' + (kv.desc || '') + ' ' + (kv.msg || '')) ? 'fail' : 'ok';
  if (vendor === 'fortimanager' && /Unregistered device \S+ add succeeded/i.test((kv.msg || '') + ' ' + (kv.changes || ''))) f.fmgUnreg = true;
  const msg = [vendor === 'fortimail' ? 'FortiMail' : 'FortiManager', f.fmType + '/' + f.fmSub, f.user, f.srcip ? 'from ' + f.srcip : '', kv.msg || kv.desc || ''].filter(Boolean).join(' ');
  return { format: vendor, raw: line, lineNo, netFields: !!f.srcip, netVendor: vendor, timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: tsRaw,
    host: kv.devname || kv.device_id || '', appName: vendor, procid: '', msgid: f.logid, severityRaw: kv.pri || kv.level || '',
    severityNorm: f.virus || f.fmgUnreg ? 'High' : normSyslogSeverity(kv.pri || kv.level || ''), facility: null, facilityAuth: false, url: '', httpMethod: '', msg, fields: f };
}
// 去識別化：主機名稱（devname、client_name）、Fortinet 序號、帳號（user 與訊息內的帳號）、主旨遮蔽，其餘換位址、MAC、Email 後重新解析
const FORTI_SN_RE = /\b(?:FG|FM|FA|FE|FW|FS|FC)[A-Z0-9-]{8,}\b/g;
const FORTI_KEEP_USERS = /^(?:system|System|fgfm|mail|webmail|ntpd|N\/A)$/;
function anonymizeFortiMgmtEvent(evt, opts) {
  const f = evt.fields || {};
  let raw = String(evt.raw || '');
  const names = new Set();
  if (f.user && !FORTI_KEEP_USERS.test(f.user)) names.add(f.user);
  raw.replace(/\buser(?:name)? '([^']+)'/g, (m, u) => { if (!FORTI_KEEP_USERS.test(u)) names.add(u); return m; });
  raw = raw.replace(/\b(subject|hsubject)=("(?:[^"\\]|\\.)*"|'[^']*'|[^,\s]*)/g, (m, k) => k + '="REDACTED"')
    .replace(/\b(devname|client_name)=("(?:[^"\\]|\\.)*"|[^,\s]*)/g, (m, k, v) => { const q = v.startsWith('"') ? '"' : '', t = v.replace(/^"|"$/g, ''); return k + '=' + q + (t && !isValidIPv4(t) ? anonDnsName(t) : t) + q; });
  [...names].sort((a, b) => b.length - a.length).forEach(n => { raw = raw.split(n).join(anonUser(n)); });
  raw = raw.replace(FORTI_SN_RE, m => anonHostname(m));
  raw = anonEmails(replaceMACsInLine(replaceIPsInLine(raw, opts)));
  return parseFortiMgmtLine(raw, evt.lineNo) || { ...evt, raw, fields: {} };
}
// FortiManager 未註冊設備被加入（XN123）：依設備合併
function detectFortiMgmt(events) {
  const groups = new Map();
  events.forEach(e => { if (e.netVendor === 'fortimanager' && e.fields && e.fields.fmgUnreg) { const k = e.host || '-'; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(e); } });
  return [...groups.values()].map(list => ({ category: 'fmgUnregDevice', severityNorm: 'High', count: list.length,
    firstSeen: list[0].timestamp || null, lastSeen: list[list.length - 1].timestamp || null,
    ...sampleOf('sample.fmgUnregDevice', { host: list[0].host || '-', n: list.length, items: [...new Set(list.map(e => e.fields.device || '-'))].slice(0, 3).join(', ') }),
    relatedHosts: [list[0].host].filter(Boolean), relatedEvents: list, confidence: 'heuristic', cves: ['CVE-2024-47575'] }));
}
// Stormshield SNS（XN122）：key=value log，每行以 id=firewall time="…" fw="…" tz=±hhmm 開頭，依 logtype 區分；欄位依 Elastic integrations
// stormshield 套件的真實測試 log：connection／filter／plugin（src、dst、srcport、dstport、ipproto、proto、ruleid／rulename、action pass／block）
// 為流量事件；web（op、result、arg、dstname、cat_site、action）為 weblog；alarm 的 class 不是 system 時＝attack＋idsAlert（alarmid、pri、msg）；
// auth 有 error 或「failed」＝authFail；xvpn 為 SSL VPN（error=0 的 tunnel opened 接 vpnLoginSuccessOf()，否則 authFail）；
// server 為管理指令（user、address、msg 指令），非查詢類且 error=0＝configChange；其他（system、monitor、count、vpn…）為一般事件
const SNS_LINE_RE = /^(?:<\d{1,3}>)?id=firewall time="(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})" fw="([^"]*)" tz=([+-])(\d{2})(\d{2})\s/;
const SNS_READONLY_CMD_RE = /\b(?:SHOW|LIST|SEARCH|GET|IDENT|LANGUAGE|INFO|QUIT|EXIT|MONITOR|STATUS|VERSION|HELP|CHECK|DOWNLOAD|LOGDISK)\b/;
function snsKv(s) {
  const kv = Object.create(null);
  String(s || '').replace(/([A-Za-z_][\w:]*)=(?:"((?:[^"\\]|\\.)*)"|(\S*))/g, (m, k, q, v) => { if (!(k in kv)) kv[k] = q !== undefined ? q : v; return m; });
  return kv;
}
function parseStormshieldLine(line, lineNo) {
  const m = line.match(SNS_LINE_RE);
  if (!m) return null;
  const [, d, t, fw, sg, hh, mm] = m;
  const ts = new Date(Date.parse(`${d}T${t}Z`) - (sg === '-' ? -1 : 1) * (+hh * 60 + +mm) * 60000);
  const kv = snsKv(line.slice(line.indexOf('id=firewall')));
  const lt = kv.logtype || '';
  const ip = v => (/^[0-9a-f:.]+$/i.test(v || '') && /[.:]/.test(v || '') ? v : '');
  const f = { sns: lt, srcip: ip(kv.src), dstip: ip(kv.dst) };
  const set = (k, v) => { if (v !== undefined && v !== null && v !== '') f[k] = String(v); };
  set('srcport', kv.srcport); set('dstport', kv.dstport); set('proto', kv.ipproto); set('app', kv.proto); set('rule', kv.rulename || kv.ruleid);
  set('user', kv.user); set('srcName', kv.srcname); set('dstName', kv.dstname); set('snsMsg', kv.msg); set('snsError', kv.error);
  const act = String(kv.action || '').toLowerCase();
  if (act) f.action = /^pass/.test(act) ? 'accept' : /^block/.test(act) ? 'deny' : act;
  if (lt === 'alarm') { set('alarmId', kv.alarmid); set('alarmClass', kv.class); set('pri', kv.pri); }
  if (lt === 'server') { set('srcip', ip(kv.address)); }
  const tsRaw = `${d} ${t} ${sg}${hh}${mm}`;
  if (lt === 'web') {
    Object.assign(f, { method: kv.op || '', url: kv.arg || '/', status: kv.result || '', bytes: kv.rcvd || '0', domain: kv.dstname || '' });
    set('urlCat', kv.cat_site);
    const ev = webEvent('weblog', line, lineNo, ts, tsRaw, fw, f);
    Object.assign(ev, { netVendor: 'stormshield', appName: 'stormshield-web' });
    ev.msg = `${f.method || '-'} ${f.domain}${f.url} ${f.status || '-'}${f.action ? ' action=' + kv.action : ''}${f.urlCat ? ' ' + f.urlCat : ''}`;
    return ev;
  }
  if (/^(?:connection|filter|plugin)$/.test(lt)) {
    const ev = flowEvent('stormshield', line, lineNo, ts, tsRaw, fw, f, { format: 'stormshield', appName: 'stormshield-' + lt });
    return ev;
  }
  const isAlert = lt === 'alarm' && f.alarmClass && f.alarmClass !== 'system';
  return { format: 'stormshield', raw: line, lineNo, netFields: !!f.srcip, netVendor: 'stormshield', timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: tsRaw,
    host: fw, appName: 'stormshield-' + (lt || 'log'), procid: '', msgid: lt, severityRaw: kv.pri || '', severityNorm: isAlert ? (+kv.pri <= 2 ? 'High' : 'Medium') : 'Info',
    facility: null, facilityAuth: false, url: '', httpMethod: '',
    msg: [lt, f.user, f.srcip ? 'from ' + f.srcip : '', kv.msg].filter(Boolean).join(' '), fields: f };
}
// 去識別化：防火牆名稱、物件名稱（srcname／dstname）、驗證網域換主機名稱對照，帳號換假帳號，再換位址與 MAC 後重新解析
function anonymizeStormshieldEvent(evt, opts) {
  let raw = String(evt.raw || '');
  raw = raw.replace(/\b(fw|srcname|dstname|domain)="([^"]*)"/g, (m, k, v) => k + '="' + (v && !isValidIPv4(v) ? (k === 'dstname' ? anonDnsName(v) : anonHostname(v)) : v) + '"')
    .replace(/\b(srcname|dstname)=([^"\s]+)/g, (m, k, v) => k + '=' + (isValidIPv4(v) ? v : k === 'dstname' ? anonDnsName(v) : anonHostname(v)))
    .replace(/\buser="([^"]*)"/g, (m, v) => 'user="' + (v ? anonUser(v) : v) + '"');
  raw = replaceMACsInLine(replaceIPsInLine(raw, opts));
  return parseStormshieldLine(raw, evt.lineNo) || { ...evt, raw, fields: {} };
}
// Cisco Meraki syslog（XN120）：「<pri>1 epoch秒.奈秒 設備名稱 類型 內容」，格式與欄位依 Elastic integrations cisco_meraki 套件的真實測試 log：
//   flows／firewall／vpn_firewall／cellular_firewall／bridge_anyconnect_client_vpn_firewall：[allow|deny] src= dst= mac= protocol= sport= dport= pattern: 規則
//     （pattern 以 allow／deny 或 1／0 開頭；Group Policy Allow／Deny）→ 流量事件，deny＝denyBlock；ip_flow_start／end 為一般流量
//   urls：src=位址:埠 dst=位址:埠 mac= [agent='…'] request: 方法 網址 → weblog 事件
//   security_event ids_alerted／ids-alerts：signature= priority= src= dst= decision= message: 名稱 → attack＋idsAlert
//   security_event security_filtering_file_scanned／disposition_change：disposition=malicious → attack＋idsAlert（AMP 檔案名稱、sha256）
//   events：8021x_eap_failure＝authFail（identity）、anyconnect_vpn_auth_success 接 vpnLoginSuccessOf()、AnyConnect 拒絕＝authFail、
//     anyconnect_vpn_session_manager 的 Sess-ID 接 SESSION_SOURCES（同工作階段多位址）
//   airmarshal_events：ssid_spoofing_detected（偽冒本機 SSID）＝attack＋idsAlert；rogue_ssid_detected 為一般事件（多為鄰近網路）
const MERAKI_LINE_RE = /^<(\d{1,3})>1 (\d{9,11})\.(\d+) (\S+) ([a-z][\w-]*)(?: ([\s\S]*))?$/;
const MERAKI_FLOW_TYPES = /^(?:flows|firewall|vpn_firewall|cellular_firewall|bridge_anyconnect_client_vpn_firewall|ip_flow_start|ip_flow_end)$/;
function merakiKv(s) {
  const kv = Object.create(null);
  // AnyConnect 的 msg= 後面先有一個空白再接引號值
  String(s || '').replace(/([A-Za-z_][\w.]*)=(?: (?='))?(?:'([^']*)'|(\S*))/g, (m, k, q, v) => { if (!(k in kv)) kv[k] = q !== undefined ? q : v; return m; });
  return kv;
}
const merakiAddr = v => {
  const t = String(v || ''), m4 = t.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?$/), m6 = t.match(/^\[([0-9a-f:.]+)\](?::(\d+))?$/i);
  return m4 ? [m4[1], m4[2] || ''] : m6 ? [m6[1], m6[2] || ''] : [t, ''];
};
function parseMerakiLine(line, lineNo) {
  const m = line.match(MERAKI_LINE_RE);
  if (!m) return null;
  const [, pri, sec, frac, host, type, body0] = m, body = body0 || '';
  const ts = new Date(Number(sec) * 1000 + Math.floor(Number('0.' + frac) * 1000));
  const tsRaw = `${sec}.${frac}`;
  const head = body.split(/\s(?:pattern|message|request):\s/)[0];
  const kv = merakiKv(head);
  const tail = k => (body.match(new RegExp('\\s?' + k + ':\\s([\\s\\S]*)$')) || [])[1] || '';
  const base = { format: 'meraki', raw: line, lineNo, netFields: false, netVendor: 'meraki', timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: tsRaw,
    host, appName: type, procid: '', msgid: type, severityRaw: pri, severityNorm: 'Info', facility: null, facilityAuth: false, url: '', httpMethod: '' };
  if (MERAKI_FLOW_TYPES.test(type)) {
    const pat = tail('pattern').trim(), lead = (head.match(/^(allow|deny)\b/) || [])[1] || '';
    const act = lead || (/^(?:allow|1)\b/i.test(pat) || /\bAllow$/.test(pat) ? 'allow' : /^(?:deny|0)\b/i.test(pat) || /\bDeny$/.test(pat) ? 'deny' : '');
    const f = { merakiType: type, srcip: kv.src || '', dstip: kv.dst || '', proto: kv.protocol || '' };
    if (kv.sport) f.srcport = kv.sport; if (kv.dport) f.dstport = kv.dport; if (kv.mac) f.mac = kv.mac;
    if (act) f.action = act === 'allow' ? 'accept' : 'deny';
    if (pat) f.rule = pat;
    if (kv.translated_src_ip) f.natsrcip = kv.translated_src_ip; if (kv.translated_dst_ip) f.natdstip = kv.translated_dst_ip;
    const ev = flowEvent('meraki', line, lineNo, ts, tsRaw, host, f, { format: 'meraki', appName: type });
    return ev;
  }
  if (type === 'urls') {
    const rq = tail('request').trim().match(/^(\S+)\s+(\S+)/) || [];
    const [sip, sport] = merakiAddr(kv.src), [dip] = merakiAddr(kv.dst);
    const um = String(rq[2] || '').match(/^[a-z][\w+.-]*:\/\/([^\/:?#]+)(?::\d+)?([^\s]*)$/i) || [];
    const f = { merakiType: type, srcip: sip, srcport: sport, dstip: dip, method: rq[1] && rq[1] !== 'UNKNOWN' ? rq[1] : '', url: um[2] || '/', status: '', bytes: '0', domain: um[1] || '' };
    if (kv.mac) f.mac = kv.mac; if (kv.agent) f.ua = kv.agent;
    const ev = webEvent('weblog', line, lineNo, ts, tsRaw, host, f);
    Object.assign(ev, { netVendor: 'meraki', appName: type });
    ev.msg = `${f.method || '-'} ${f.domain}${f.url} from ${f.srcip || '-'}`;
    return ev;
  }
  const f = { merakiType: type };
  const sub = (head.match(/^([a-z][\w-]*)(?:\s|$)/) || [])[1] || '';
  let msg = body;
  if (type === 'security_event' || type === 'ids-alerts') {
    const [sip, sport] = merakiAddr(kv.src), [dip, dport] = merakiAddr(kv.dst);
    Object.assign(f, { merakiEvent: type === 'ids-alerts' ? 'ids_alerted' : sub, srcip: sip, dstip: dip });
    if (sport) f.srcport = sport; if (dport) f.dstport = dport;
    if (f.merakiEvent === 'ids_alerted') { f.signature = kv.signature || ''; f.priority = kv.priority || ''; f.decision = kv.decision || ''; f.alertName = tail('message').trim(); }
    else { f.disposition = kv.disposition || ''; f.fileName = kv.name || ''; f.sha256 = kv.sha256 || ''; f.fileUrl = kv.url || ''; f.decision = kv.action || ''; }
    msg = f.alertName ? `IDS ${f.signature} ${f.alertName} ${f.srcip} -> ${f.dstip} (${f.decision || '-'})` : `${sub} ${f.fileName} ${f.disposition}`.trim();
  } else if (type === 'events' || type === 'airmarshal_events') {
    const et = kv.type || '';
    f.merakiEvent = et;
    if (kv.client_mac) f.mac = kv.client_mac;
    if (kv.identity) f.user = kv.identity;
    if (kv.ssid !== undefined) f.ssid = kv.ssid;
    if (kv.bssid) f.bssid = kv.bssid;
    const am = String(kv.msg || '');
    const peer = (am.match(/Peer IP=([0-9a-f:.]+)/i) || [])[1], user = (am.match(/User\[([^\]]+)\]/) || am.match(/User=([^:\s]+)/) || [])[1], sess = (am.match(/Sess-ID\[(\d+)\]/) || [])[1];
    if (peer) f.srcip = peer; if (user) f.user = user; if (sess) f.merakiSess = sess;
    if (/^anyconnect_vpn_auth/.test(et)) f.vpnAuth = /accepted/i.test(am) || /success/.test(et) ? 'ok' : /reject|fail/i.test(am) || /fail/.test(et) ? 'fail' : '';
    msg = `${et}${f.user ? ' ' + f.user : ''}${f.srcip ? ' from ' + f.srcip : ''}${f.ssid ? " ssid='" + f.ssid + "'" : ''}${am ? ' ' + am.trim() : ''}`;
  }
  return Object.assign(base, { netFields: !!f.srcip, msg: msg.trim() || type, fields: f,
    severityNorm: f.alertName || /malicious/i.test(f.disposition || '') || f.merakiEvent === 'ssid_spoofing_detected' ? (+f.priority === 1 || /malicious/i.test(f.disposition || '') ? 'High' : 'Medium') : 'Info' });
}
// Meraki 去識別化：設備名稱換主機名稱、帳號（identity、User[…]、User=）換假帳號、SSID 遮蔽、網址主機換主機名稱，再換位址與 MAC 後重新解析
function anonymizeMerakiEvent(evt, opts) {
  const f = evt.fields || {};
  let raw = evt.raw;
  if (evt.host) raw = raw.replace(/^(<\d{1,3}>1 \S+ )(\S+)/, (m, p, h) => p + anonHostname(h));
  raw = raw.replace(/\bidentity='([^']*)'/g, (m, v) => "identity='" + (v ? anonUser(v) : v) + "'")
    .replace(/User\[([^\]]+)\]/g, (m, v) => 'User[' + anonUser(v) + ']').replace(/User=([^:\s]+)/g, (m, v) => 'User=' + anonUser(v))
    .replace(/\bssid='([^']+)'/g, "ssid='REDACTED'")
    .replace(/\b([a-z][\w+.-]*:\/\/)([^\/:?#\s']+)/gi, (m, p, h) => p + (isValidIPv4(h) ? h : anonDnsName(h)));
  raw = replaceMACsInLine(replaceIPsInLine(raw, opts));
  return parseMerakiLine(raw, evt.lineNo) || { ...evt, raw, fields: {} };
}
// Citrix NetScaler ADC／Gateway 原生 syslog（XN109）：「<pri> 日期:時間 [時區] 主機 PPE : default [模組] 事件 序號 嚴重度 : 內容」，
// 表頭與內容欄位依 Elastic integrations citrix_adc ingest pipeline（native.yml、sslvpn_and_aaatm_feature.yml）與同套件測試 log：
// 內容以「 - 」分隔「鍵 值」（User、Client_ip、X-Forwarded-For_ip、Context 帳號@位址、SessionId:、Vserver 位址:埠、Remote_ip、Command、Status）。
// 日期為 MM/DD/YYYY，第一段大於 12 時視為 DD/MM/YYYY（設備可設定）；時區 GMT 視為 UTC，沒有時區視為本機時間
// 經 syslog 伺服器轉存時前面多「BSD 時間 [<facility.level>] [轉送位址]」，舊版沒有 default（同 pipeline default.yml），此時必須有「N-PPE-N :」表頭
const NS_LINE_RE = /^(?:<(\d{1,3})>\s*|[A-Z][a-z]{2,8}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?:<[\w.]+>\s+)?(?:\S+\s+)?)(?:(\d{2})\/(\d{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([A-Z]{2,5}))?\s+(\S+)\s+(\d+-PPE-\d+)\s+:\s+(?:default\s+)?|default\s+)(?:([A-Z][A-Z0-9]+)\s+)?([A-Za-z][\w-]*)\s+(\d+)\s+(\d+)\s*:\s?([\s\S]*)$/;
// RFC5424 外殼（pipeline native.yml 第 4 種樣式）：<pri>1 ISO 時間 主機 模組 N-PPE-N 結構化資料兩欄 [default] 事件 序號 嚴重度 : 內容
const NS5424_RE = /^<(\d{1,3})>1 (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) (\S+) ([A-Z][A-Z0-9]+) (\d+-PPE-\d+) \S+ \S+ (?:default\s+)?([A-Za-z][\w-]*)\s+(\d+)\s+(\d+)\s*:\s?([\s\S]*)$/;
const NS_IP_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+)$/;
function parseNetScalerBody(body) {
  const f = {};
  String(body || '').replace(/^Logout handler : /, '').split(/\s+-\s+/).forEach(seg => {
    const t = seg.trim();
    let m;
    if ((m = t.match(/^Context (.+)@([^@\s]+)$/))) { if (!f.user) f.user = m[1]; return; }
    if ((m = t.match(/^SessionId:\s*(\d+)$/))) { f.nsSession = m[1]; return; }
    if (!(m = t.match(/^([A-Za-z][\w()-]*?)\s+([\s\S]*)$/))) return;
    const k = m[1], v = m[2].replace(/^"|"\s*$/g, '').trim();
    if (k === 'User') f.user = v;
    else if ((k === 'Client_ip' || k === 'Remote_ip') && NS_IP_RE.test(v) && v !== '0.0.0.0') f.srcip = v;
    else if (k === 'X-Forwarded-For_ip' && v !== 'unknown') f.xff = v;
    else if (k === 'Vserver') f.vserver = v;
    else if (k === 'Command') f.command = v;
    else if (k === 'Status') f.status = v;
  });
  return f;
}
function parseNetScalerLine(line, lineNo) {
  let m = line.match(NS_LINE_RE), iso = null;
  if (!m) {
    const r = line.match(NS5424_RE);
    if (!r) return null;
    iso = r[2];
    m = [r[0], r[1], '', '', '', '', '', '', '', r[3], r[5], r[4], r[6], r[7], r[8], r[9]];
  }
  const [, pri, a, b, y, hh, mi, ss, tz, host, ppe, mod, ev, seq, sev, body] = m;
  let ts = iso ? new Date(iso) : null;
  if (y) {
    const dmy = Number(a) > 12;
    const mo = (dmy ? Number(b) : Number(a)) - 1, d = dmy ? Number(a) : Number(b);
    ts = tz === 'GMT' || tz === 'UTC' ? new Date(Date.UTC(+y, mo, d, +hh, +mi, +ss)) : new Date(+y, mo, d, +hh, +mi, +ss);
    if (isNaN(ts.getTime())) ts = null;
  }
  const f = Object.assign({ nsModule: mod || '', nsEvent: ev }, parseNetScalerBody(body));
  if (ev === 'LOGIN_FAILED') f.nsAuth = 'fail';
  else if (ev === 'LOGIN' && !/^Logout handler/.test(body) && /^(?:SSLVPN|AAATM|AAA|)$/.test(mod || '')) f.nsAuth = 'ok';
  else if (ev === 'LOGOUT') f.nsLogout = true;
  const priNum = pri === undefined ? null : Number(pri), sevNum = priNum === null ? 6 : priNum % 8;
  return {
    format: 'netscaler', raw: line, lineNo, netFields: true, netVendor: 'netscaler',
    timestamp: ts, timestampRaw: iso || (y ? `${a}/${b}/${y}:${hh}:${mi}:${ss}${tz ? ' ' + tz : ''}` : ''),
    host: host || '', appName: mod || '', procid: ppe || '', msgid: ev,
    severityRaw: String(sevNum), severityNorm: normSyslogSeverity(sevNum),
    facility: priNum === null ? null : Math.floor(priNum / 8), facilityAuth: false,
    msg: `${mod ? mod + ' ' : ''}${ev} : ${String(body).trim()}`, fields: f
  };
}
// NetScaler（XN109）：主機名稱與帳號換掉、位址與 MAC 通用替換後重新解析（工作階段編號為設備內部流水號，保留以便關聯）
function anonymizeNetScalerEvent(evt, opts) {
  const f = evt.fields || {};
  let raw = evt.raw;
  if (evt.host && !isValidIPv4(evt.host)) raw = raw.split(' ' + evt.host + ' ').join(' ' + anonHostname(evt.host) + ' ');
  if (f.user) raw = raw.split(f.user).join(anonUser(f.user));
  raw = raw.replace(/(Context )([^@\s]+)(@)/g, (m, p, u, q) => p + anonUser(u) + q);
  raw = replaceMACsInLine(replaceIPsInLine(raw, opts));
  return parseNetScalerLine(raw, evt.lineNo) || { ...evt, raw, msg: replaceIPsInLine(String(evt.msg || ''), opts), fields: {} };
}
// 同一個 NetScaler 工作階段在 NS_SESSION_WINDOW_MS 內出現兩個以上的用戶端位址（XN109）：CitrixBleed 類漏洞外洩的工作階段
// 被他人重用時會出現這種情形；用戶端換網路（手機切換 Wi-Fi／行動網路）也會，故為需人工確認。依主機＋工作階段分組
// XN115：同樣適用其他有工作階段 ID 與用戶端位址的 VPN 來源（Ivanti／Pulse Connect Secure 的 session:，另列 vpnSessionMultiIp）；
// GlobalProtect、FortiGate 的 log 沒有可對應的網頁工作階段 ID（FortiGate tunnelid 每條通道只有一個來源），不納入
const NS_SESSION_WINDOW_MS = 60 * 60 * 1000;
const SESSION_SOURCES = { netscaler: ['nsSession', 'nsSessionMultiIp', 'NetScaler'], pcs: ['pcsSession', 'vpnSessionMultiIp', 'Ivanti Connect Secure'], meraki: ['merakiSess', 'vpnSessionMultiIp', 'Cisco Meraki AnyConnect'] };
function detectNsSessionMultiIp(events) {
  const groups = new Map();
  events.forEach(e => {
    const f = e.fields, src = SESSION_SOURCES[e.netVendor];
    // 去識別化後的工作階段一律是 REDACTED，不能當成同一個工作階段
    if (!src || !f || !f[src[0]] || !f.srcip || /^REDACTED/.test(f[src[0]])) return;
    const k = e.netVendor + '|' + (e.host || '-') + '|' + f[src[0]];
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(e);
  });
  const issues = [];
  for (const list of groups.values()) {
    const sorted = [...list].sort((x, y) => effectiveTime(x) - effectiveTime(y));
    let best = null;
    for (let i = 0, j = 0; j < sorted.length; j++) {
      while (effectiveTime(sorted[j]) - effectiveTime(sorted[i]) > NS_SESSION_WINDOW_MS) i++;
      const ips = new Set(sorted.slice(i, j + 1).map(e => e.fields.srcip));
      if (ips.size >= 2 && (!best || ips.size > best.ips.size)) best = { evs: sorted.slice(i, j + 1), ips };
    }
    if (!best) continue;
    const ips = [...best.ips], ext = ips.filter(ip => !iocIsInternalIP(ip));
    const e0 = best.evs[0], user = (best.evs.find(e => e.fields.user) || e0).fields.user || '-', src = SESSION_SOURCES[e0.netVendor];
    issues.push({
      category: src[1], severityNorm: ext.length >= 2 ? 'High' : 'Medium', count: best.evs.length,
      firstSeen: e0.timestamp || null, lastSeen: best.evs[best.evs.length - 1].timestamp || null,
      ...sampleOf('sample.' + src[1], { host: e0.host || '-', session: e0.fields[src[0]], user, n: ips.length, ips: ips.slice(0, 5).join(', '), vendor: src[2] }),
      relatedHosts: [...ips.slice(0, 5), user], relatedEvents: best.evs, confidence: 'heuristic'
    });
  }
  return issues;
}
// WatchGuard（XN108）：表頭主機名稱與序號、帳號、位址與 MAC、代理紀錄的目的主機名稱換掉後重新解析
function anonymizeWatchGuardEvent(evt, opts) {
  const f = evt.fields || {};
  const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  let raw = evt.raw;
  if (evt.host && !isValidIPv4(evt.host)) raw = raw.replace(new RegExp('(\\d{2}:\\d{2}:\\d{2}\\s+)' + esc(evt.host) + '(?=\\s)'), (m, p) => p + anonHostname(evt.host));
  if (f.wgSerial) raw = raw.split(' ' + f.wgSerial + ' ').join(' REDACTED ');
  [f.user, f.src_user, f.dst_user].filter(Boolean).forEach(u => { raw = raw.split(u).join(anonUser(u)); });
  raw = raw.replace(/\b(dstname|host)="([^"]*)"/g, (m, k, v) => k + '="' + (isValidIPv4(v) ? v : anonHostname(v)) + '"');
  raw = replaceMACsInLine(replaceIPsInLine(raw, opts));
  return parseRFC3164Line(raw, evt.lineNo) || { ...evt, raw, msg: replaceIPsInLine(String(evt.msg || ''), opts), fields: {} };
}
// ── 資料庫連線與認證 log（XN90）──
// PostgreSQL 伺服器 log：時間 時區 [pid]、選填 [行號-子號]（%l 或 syslog 序號）、log_line_prefix 其餘內容、嚴重度: 選填 SQLSTATE、訊息；
// 格式依 Elastic integrations postgresql 測試 log（'%m [%p] '、'%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '、'%u@%d '）。
// 句型依 postgres 原始碼：backend_startup.c「connection received: host=%s port=%s」（需 log_connections）、postinit.c「connection authorized:
// user=%s database=%s」、libpq/auth.c「password authentication failed for user "%s"」（Ident／Peer／LDAP／RADIUS／certificate… 同句型）與
// 「no pg_hba.conf entry for host "%s", user "%s", database "%s"」
const PG_SEV_SRC = '(LOG|FATAL|ERROR|WARNING|NOTICE|INFO|PANIC|DETAIL|HINT|STATEMENT|LOCATION|CONTEXT|DEBUG[1-5]?):\\s+(?:[0-9A-Z]{5}: )?([\\s\\S]*)$';
const PG_FILE_RE = new RegExp('^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?) ([A-Z]{2,5}|[+-]\\d{2}(?::?\\d{2})?) \\[(\\d+)\\]:?(.*?)\\b' + PG_SEV_SRC);
const PG_SYSLOG_RE = new RegExp('^(.*?)\\b' + PG_SEV_SRC);
// MySQL 錯誤 log（8.0：時間 執行緒 [等級] [MY-代碼] [子系統] 訊息；5.7 沒有代碼與子系統），依 Elastic Beats mysql 模組測試 log；
// 登入失敗「Access denied for user 'u'@'h' (using password: YES)」只在 log_error_verbosity=3 時寫入（sql_authentication.cc）
const MYSQL_ERR_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) +(\d+) \[(System|Warning|Note|ERROR|Error)\](?: \[(MY-\d+)\] \[(\w+)\])? ([\s\S]*)$/;
// MySQL general query log：時間\t%5u 指令\t內容（log.cc File_query_log::write_general）；Connect 內容為「帳號@主機 on 資料庫 using 連線方式」
// （sql_authentication.cc，代理帳號為「帳號@主機 as 實際帳號 on …」）或 Access denied
const MYSQL_GEN_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\t\s*(\d+) ([A-Z][A-Za-z ]*?)\t([\s\S]*)$/;
const MYSQL_DENIED_RE = /Access denied for user '(.*?)'@'(.*?)'(?: \(using password: (YES|NO)\))?/;
const MYSQL_CONNECT_RE = /^(\S*?)@(\S*?)(?: as \S+)? on (\S*) using (.+)$/;
const DB_SEV = { PANIC: 'Critical', FATAL: 'Medium', ERROR: 'Low', Error: 'Low', WARNING: 'Low', Warning: 'Low' };
function dbTime(dt, tz) {
  let suf = '';
  if (/^(?:UTC|GMT|Z)$/.test(tz || '')) suf = 'Z';
  else { const z = String(tz || '').match(/^([+-]\d{2}):?(\d{2})?$/); if (z) suf = z[1] + ':' + (z[2] || '00'); }
  const t = new Date(dt + suf);
  return isNaN(t.getTime()) ? null : t;
}
// log_line_prefix 的 user=／db=／client=（或 host=）與 %u@%d 寫法
function dbPrefixFields(prefix) {
  const f = {}, p = String(prefix || '').replace(/^\s*\[\d+-\d+\]\s*/, '').trim();
  const re = /(?:^|[,\s])(user|db|client|host)=([^,\s]*)/g;
  let m;
  while ((m = re.exec(p))) {
    if (!m[2] || m[2] === '[unknown]') continue;
    if (m[1] === 'user') f.user = m[2]; else if (m[1] === 'db') f.database = m[2]; else f.dbClient = m[2];
  }
  if (!f.user && (m = p.match(/^([^\s@=,]+)@([^\s@=,]+)$/))) { if (m[1] !== '[unknown]') f.user = m[1]; if (m[2] !== '[unknown]') f.database = m[2]; }
  return f;
}
// 用戶端字串轉位址：[local]（Unix socket）與 localhost 為本機，host(port) 去掉埠；主機名稱不當作位址
function dbClientAddr(f) {
  const c = String(f.dbClient || '').replace(/\(\d+\)$/, '');
  if (!c) return f;
  if (c === '[local]' || /^localhost$/i.test(c)) f.dbLocal = true;
  else if (isValidIPv4(c) || (c.includes(':') && /^[0-9a-f:.]+$/i.test(c))) f.srcip = c;
  return f;
}
function parsePgBody(sev, body, prefix) {
  const f = dbPrefixFields(prefix), s = String(body || '').trim();
  let m;
  if ((m = s.match(/^connection received: host=(\S+?)(?: port=(\d+))?$/))) { f.dbAuth = 'recv'; f.dbClient = m[1]; if (m[2]) f.srcport = m[2]; }
  else if ((m = s.match(/^(?:replication )?connection authorized: user=(\S+)(?: database=(\S+))?/))) { f.dbAuth = 'ok'; f.user = m[1]; if (m[2]) f.database = m[2]; }
  else if (sev === 'FATAL' && (m = s.match(/^(?:"?\w+"? )?authentication failed for user "(.*?)"/))) { f.dbAuth = 'fail'; f.user = m[1]; f.dbReason = 'auth'; }
  else if (sev === 'FATAL' && (m = s.match(/^no pg_hba\.conf entry for (?:replication connection from )?host "(.*?)", user "(.*?)"(?:, database "(.*?)")?/))) { f.dbAuth = 'fail'; f.dbClient = m[1]; f.user = m[2]; if (m[3]) f.database = m[3]; f.dbReason = 'hba'; }
  else if (sev === 'FATAL' && (m = s.match(/^role "(.*?)" does not exist/))) { f.dbAuth = 'fail'; f.user = m[1]; f.dbReason = 'norole'; }
  else return null;
  f.dbKind = 'postgres';
  return dbClientAddr(f);
}
function parseMysqlBody(s) {
  const m = String(s || '').match(MYSQL_DENIED_RE);
  if (!m) return null;
  return dbClientAddr({ dbKind: 'mysql', dbAuth: 'fail', user: m[1], dbClient: m[2], dbReason: 'auth', ...(m[3] ? { dbPassword: m[3] } : {}) });
}
function parseMysqlConnect(arg) {
  const m = String(arg || '').match(MYSQL_CONNECT_RE);
  if (!m) return parseMysqlBody(arg);
  return dbClientAddr({ dbKind: 'mysql', dbAuth: 'ok', user: m[1], dbClient: m[2], dbVia: m[4].trim(), ...(m[3] ? { database: m[3] } : {}) });
}
function parseDbFileLine(line, lineNo) {
  let m, f, ts, tsRaw, app, sev = '', msg;
  if ((m = line.match(PG_FILE_RE))) {
    tsRaw = m[1] + ' ' + m[2]; ts = dbTime(m[1].replace(' ', 'T'), m[2]); sev = m[5]; msg = m[6]; app = 'postgres';
    f = parsePgBody(sev, msg, m[4]) || Object.assign(dbPrefixFields(m[4]), { dbKind: 'postgres' });
  } else if ((m = line.match(MYSQL_GEN_RE))) {
    tsRaw = m[1]; ts = dbTime(m[1], ''); msg = m[4]; app = 'mysqld';
    f = (m[3] === 'Connect' && parseMysqlConnect(m[4])) || { dbKind: 'mysql' };
    f.dbCmd = m[3];
  } else if ((m = line.match(MYSQL_ERR_RE))) {
    tsRaw = m[1]; ts = dbTime(m[1], ''); sev = m[3]; msg = m[6]; app = 'mysqld';
    f = parseMysqlBody(msg) || { dbKind: 'mysql' };
  } else return null;
  f.dbPid = m[3] && app === 'postgres' ? m[3] : m[2];
  return {
    format: 'dbfile', raw: line, lineNo, netFields: !!f.dbAuth, netVendor: f.dbKind,
    timestamp: ts, timestampRaw: tsRaw, host: '', appName: app, procid: f.dbPid, msgid: '',
    severityRaw: sev, severityNorm: DB_SEV[sev] || 'Info', facility: null, facilityAuth: false, msg, rawPrefix: line.slice(0, line.length - msg.length), fields: f
  };
}
// syslog 送出的 postgres／mysqld 訊息（appName 判斷）
function parseDbMsg(appName, msg) {
  const a = String(appName || ''), s = String(msg || '');
  if (/^(?:postgres|postmaster)$/i.test(a)) {
    const m = s.match(PG_SYSLOG_RE), f = m && parsePgBody(m[2], m[3], m[1]);
    return f ? { vendor: 'postgres', fields: f } : null;
  }
  if (/^mysqld$/i.test(a)) { const f = parseMysqlBody(s); return f ? { vendor: 'mysql', fields: f } : null; }
  return null;
}
// MySQL Enterprise Audit JSON（XN90）：欄位依 Elastic integrations mysql_enterprise 測試 log——class connection、event connect／change_user、
// connection_id、account.user／host、login.user／ip、connection_data.status（0＝成功，其他為錯誤碼）／db／connection_type；timestamp 為 UTC
function isMysqlAuditEvent(o) { return !!o && typeof o === 'object' && typeof o.class === 'string' && typeof o.event === 'string' && 'connection_id' in o && !!o.account && typeof o.account === 'object'; }
function mysqlAuditEvent(o, lineNo) {
  const acc = o.account || {}, lg = o.login || {}, cd = o.connection_data || {}, gd = o.general_data || {};
  const f = { dbKind: 'mysql', dbPid: String(o.connection_id), dbAuditClass: o.class, dbAuditEvent: o.event };
  if (o.class === 'connection' && /^(?:connect|change_user)$/.test(o.event)) {
    f.dbAuth = Number(cd.status) === 0 ? 'ok' : 'fail';
    if (Number(cd.status)) f.dbStatus = String(cd.status);
    f.user = String(lg.user || acc.user || '');
    f.dbClient = String(lg.ip || acc.host || '');
    if (cd.db) f.database = String(cd.db);
    if (cd.connection_type) f.dbVia = String(cd.connection_type);
    dbClientAddr(f);
  } else if (acc.user) f.dbAccount = String(acc.user);
  const tsRaw = String(o.timestamp || '');
  const ts = dbTime(tsRaw.replace(' ', 'T'), /[zZ]$|[+-]\d{2}:?\d{2}$/.test(tsRaw) ? '' : 'Z');
  const who = f.user ? `${f.user}@${f.dbClient || '-'}` : (f.dbAccount || '');
  const msg = [`${o.class}/${o.event}`, who, f.database ? 'db=' + f.database : '', f.dbStatus ? 'status=' + f.dbStatus : '', gd.sql_command || ''].filter(Boolean).join(' ');
  return {
    format: 'json', raw: JSON.stringify(o), lineNo, netFields: !!f.dbAuth, netVendor: 'mysql', dbRaw: o,
    timestamp: ts, timestampRaw: tsRaw, host: '', appName: 'mysql-audit', procid: f.dbPid, msgid: o.event,
    severityRaw: '', severityNorm: 'Info', facility: null, facilityAuth: false, url: '', httpMethod: '', msg, fields: f
  };
}
// PostgreSQL「connection received」才有來源位址，同一台同一個後端程序（pid）接著的認證成功／失敗行補上來源（XN90）；可重複執行
function linkDbConns(events) {
  const last = new Map();
  for (const e of events) {
    const f = e.fields;
    if (!f || f.dbKind !== 'postgres' || !f.dbAuth) continue;
    const k = (e.host || '') + '|' + (f.dbPid || e.procid || '');
    if (f.dbAuth === 'recv') { last.set(k, f); continue; }
    const r = last.get(k);
    last.delete(k);
    if (!r || f.dbClient || !r.dbClient) continue;
    f.dbClient = r.dbClient; f.dbLinked = true;
    if (r.srcip) f.srcip = r.srcip;
    if (r.dbLocal) f.dbLocal = true;
  }
  return events;
}
// 去識別化：帳號、資料庫名稱、主機名稱換假值、位址換假位址後重新拆欄位；audit JSON 的查詢內容與連線屬性一律遮蔽
function anonDbText(s, f, opts) {
  let out = String(s || '');
  [[f.user, anonUser], [f.dbAccount, anonUser], [f.database, anonHostname]].forEach(([v, fn]) => {
    if (!v || v === '[local]' || DB_KEEP_NAMES.has(String(v).toLowerCase())) return;
    out = out.replace(new RegExp('(^|[^\\w.-])' + v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![\\w-])', 'g'), '$1' + fn(v));
  });
  if (f.dbClient && !f.srcip && !f.dbLocal) out = out.split(f.dbClient).join(anonHostname(f.dbClient));
  return anonFreeText(out, opts);
}
// 內建管理帳號與系統資料庫名稱不具識別性，保留以便去識別化後仍能判斷管理帳號登入
const DB_KEEP_NAMES = new Set(['postgres', 'root', 'mysql', 'template0', 'template1', 'information_schema', 'performance_schema', 'sys']);
// SQL 內容可能含資料本身，去識別化時整段遮蔽
const DB_SQL_SEV = new Set(['STATEMENT', 'DETAIL', 'CONTEXT', 'QUERY']), DB_SQL_CMD = new Set(['Query', 'Execute', 'Prepare']);
function anonymizeDbEvent(evt, opts) {
  if (evt.dbRaw) {
    const o = JSON.parse(JSON.stringify(evt.dbRaw)), au = v => (v && !DB_KEEP_NAMES.has(String(v).toLowerCase()) ? anonUser(String(v)) : v);
    const ah = v => (!v || v === 'localhost' ? v : (isValidIPv4(v) || String(v).includes(':') ? replaceIPsInLine(String(v), opts) : anonHostname(String(v))));
    if (o.account) { o.account.user = au(o.account.user); o.account.host = ah(o.account.host); }
    if (o.login) { o.login.user = au(o.login.user); o.login.os = au(o.login.os); o.login.ip = ah(o.login.ip); o.login.proxy = au(o.login.proxy); }
    if (o.connection_data) { if (o.connection_data.db) o.connection_data.db = anonHostname(String(o.connection_data.db)); if (o.connection_data.connection_attributes) o.connection_data.connection_attributes = 'REDACTED'; }
    if (o.general_data && o.general_data.query) o.general_data.query = 'REDACTED';
    if (o.startup_data && o.startup_data.args) o.startup_data.args = 'REDACTED';
    return mysqlAuditEvent(o, evt.lineNo);
  }
  const f = evt.fields || {};
  const c = { ...evt, fields: { ...f } };
  if (c.host) c.host = anonHostname(c.host);
  if (evt.format === 'dbfile') {
    const body = DB_SQL_SEV.has(evt.severityRaw) || DB_SQL_CMD.has(f.dbCmd) ? 'REDACTED' : anonDbText(evt.msg, f, opts);
    const re = parseDbFileLine(anonDbText(evt.rawPrefix || '', f, opts) + body, evt.lineNo);
    if (re) return re;
  }
  c.msg = anonDbText(evt.msg, f, opts);
  const re = parseDbMsg(c.appName, c.msg);
  c.fields = re ? re.fields : {};
  c.raw = rebuildSyslogRaw(c);
  return c;
}
// 389 Directory Server access log 檔案：[20/Oct/2026:10:00:00.123456789 +0800] conn=…
const DS389_LINE_RE = /^\[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*(?:([+-]\d{2})(\d{2}))?\] (conn=\d+ [\s\S]*)$/;
// OpenLDAP 2.6 logfile：十六進位 Unix 秒.微秒 [0x執行緒] conn=…
const OPENLDAP26_LINE_RE = /^([0-9a-f]{8})\.[0-9a-f]{8} (?:0x[0-9a-f]+ )?(conn=\d+ [\s\S]*)$/;
// XN16：OpenLDAP 2.6 logfile 的非連線訊息（slapd starting、資料庫錯誤…）與 389 errors log「[時間] - 嚴重度 - 子系統 - 訊息」
const OPENLDAP26_ANY_RE = /^([0-9a-f]{8})\.[0-9a-f]{8} (?:0x[0-9a-f]+ )?(\S[\s\S]*)$/;
const DS389_ERR_RE = /^\[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*(?:([+-]\d{2})(\d{2}))?\] - (EMERG|ALERT|CRIT|ERR|WARN|NOTICE|INFO|DEBUG) - (?:(\S+) - )?([\s\S]*)$/;
const DS389_SEV = { EMERG: 'Critical', ALERT: 'Critical', CRIT: 'Critical', ERR: 'High', WARN: 'Medium', NOTICE: 'Info', INFO: 'Info', DEBUG: 'Info' };
function isOpenLdap26SvcLine(line) { const o = line.match(OPENLDAP26_ANY_RE); return !!(o && !/^conn=/.test(o[2]) && parseLdapSvc('openldap', o[2])); }
function parseDs389Line(line, lineNo) {
  const ea = line.match(DS389_ERR_RE);
  if (ea && WEB_MONTHS[ea[2]]) {
    const sv = parseLdapSvc('389ds', ea[9].trim());
    const ts = new Date(`${ea[3]}-${WEB_MONTHS[ea[2]]}-${ea[1]}T${ea[4]}${ea[5] ? ea[5] + ':' + ea[6] : 'Z'}`);
    return {
      format: 'ldap', raw: line, lineNo, netFields: !!sv, netVendor: 'ldap',
      timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: line.slice(1, line.indexOf(']')), host: '', appName: 'ns-slapd', procid: '', msgid: '',
      severityRaw: ea[7], severityNorm: DS389_SEV[ea[7]] || 'Info', facility: null, facilityAuth: false, msg: ea[9], rawPrefix: line.slice(0, line.length - ea[9].length),
      fields: Object.assign({ ds389Sev: ea[7], ...(ea[8] ? { ds389Sub: ea[8] } : {}) }, sv ? sv.fields : {})
    };
  }
  const oa = line.match(OPENLDAP26_ANY_RE);
  if (oa && !/^conn=/.test(oa[2])) {
    const sv = parseLdapSvc('openldap', oa[2].trim());
    if (!sv) return null;
    return {
      format: 'ldap', raw: line, lineNo, netFields: true, netVendor: 'ldap',
      timestamp: new Date(parseInt(oa[1], 16) * 1000), timestampRaw: line.slice(0, 17), host: '', appName: 'slapd', procid: '', msgid: '',
      severityRaw: '', severityNorm: 'Info', facility: null, facilityAuth: false, msg: oa[2], rawPrefix: line.slice(0, line.length - oa[2].length), fields: sv.fields
    };
  }
  const o = line.match(OPENLDAP26_LINE_RE);
  if (o) {
    const f = parseLdapBody(o[2]);
    if (!f) return null;
    return {
      format: 'ldap', raw: line, lineNo, netFields: true, netVendor: 'ldap',
      timestamp: new Date(parseInt(o[1], 16) * 1000), timestampRaw: line.slice(0, 17), host: '', appName: 'slapd', procid: '', msgid: '',
      severityRaw: '', severityNorm: 'Info', facility: null, facilityAuth: false, msg: o[2], rawPrefix: line.slice(0, line.length - o[2].length), fields: f
    };
  }
  const m = line.match(DS389_LINE_RE);
  const f = m && WEB_MONTHS[m[2]] && parseLdapBody(m[7]);
  if (!f) return null;
  const ts = new Date(`${m[3]}-${WEB_MONTHS[m[2]]}-${m[1]}T${m[4]}${m[5] ? m[5] + ':' + m[6] : 'Z'}`);
  return {
    format: 'ldap', raw: line, lineNo, netFields: true, netVendor: 'ldap',
    timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: line.slice(1, line.indexOf(']')), host: '', appName: 'ns-slapd', procid: '', msgid: '',
    severityRaw: '', severityNorm: 'Info', facility: null, facilityAuth: false, msg: m[7], rawPrefix: line.slice(0, line.length - m[7].length), fields: f
  };
}
// DN 第一段的值當作帳號（uid／cn／sAMAccountName／mail…），空 DN 為匿名繫結
function ldapDnUser(dn) {
  const m = String(dn || '').match(/^\s*(?:uid|cn|samaccountname|userprincipalname|mail|krbprincipalname)=((?:\\.|[^,+])+)/i);
  return m ? m[1].replace(/\\(.)/g, '$1').trim() : String(dn || '').trim();
}
// LDAPS（636）或 STARTTLS／TLS established 之後才算加密連線；method=128 且有 DN 的簡單繫結在未加密連線上為明碼密碼
function linkLdapConns(events) {
  const conns = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (!f || !f.ldap) return;
    const k = `${e.host}|${f.conn}`;
    let c = conns.get(k);
    if (f.ldap === 'accept' || !c) { c = { ops: new Map(), tls: !!f.ldapTls || !!f.ldapLocal || f.dstport === '636' }; conns.set(k, c); }
    if (f.ldap === 'accept') { c.srcip = f.srcip; c.srcport = f.srcport; return; }
    if (c.srcip && !f.srcip) { f.srcip = c.srcip; if (c.srcport) f.srcport = c.srcport; }
    if (f.ldap === 'tls') { c.tls = true; return; }
    if (f.ldap === 'bind' || f.ldap === 'search') { c.ops.set(f.op, { ...f, tls: c.tls }); if (f.ldap === 'bind' && f.dn) f.user = ldapDnUser(f.dn); return; }
    const req = f.op !== undefined ? c.ops.get(f.op) : null;
    if (!req) return;
    // OpenLDAP SASL 繫結：BIND dn="" method=163 之後的 BIND dn="實際身分" mech=… 行補上身分
    if (f.ldap === 'bindmech' && req.ldap === 'bind') { if (f.dn && !req.dn) req.dn = f.dn; req.mech = req.mech || f.mech; return; }
    // err=14（SASL 繫結進行中）為中間步驟，等下一個 op 的結果
    if (f.ldap === 'result' && req.ldap === 'bind' && f.err === '14') { c.ops.delete(f.op); return; }
    if (f.ldap === 'result' && req.ldap === 'bind' && (f.tag === '97' || !f.tag)) {
      f.ldap = f.err === '0' ? 'bindok' : 'bindfail';
      const dn = req.dn || f.resultDn || '';
      const sasl = req.method === '163' || /^sasl$/i.test(req.method || '') || !!req.mech;
      f.dn = dn; f.method = req.method;
      if (req.mech) f.mech = req.mech;
      if (dn) f.user = ldapDnUser(dn); else if (!sasl) f.ldapAnon = true;
      if (req.method === '128' && req.dn && !req.tls) f.ldapPlain = true;
      c.ops.delete(f.op);
    } else if ((f.ldap === 'searchres' || f.ldap === 'result') && req.ldap === 'search') {
      f.ldap = 'searchres';
      Object.assign(f, { base: req.base, scope: req.scope, filter: req.filter });
      c.ops.delete(f.op);
    }
  });
  return events;
}
const ldapBindFailed = f => !!f && f.ldap === 'bindfail' && f.err === '49';
// LDAP 偵測（第三十輪 LD4）：
//   ldapBruteForce：同一來源 1 小時內繫結失敗（err=49）5 次以上，之後同來源繫結成功時升為 High
//   ldapPlainBind：未加密連線上帶 DN 的簡單繫結（密碼以明碼傳送），依來源＋帳號彙整
//   ldapAnonBind：匿名繫結成功，依來源彙整（Low）
//   ldapEnum：整個子樹（scope=2）以 (objectClass=*) 等全取條件搜尋，或單次回傳 1000 筆以上
const LDAP_BRUTE_MIN = 5, LDAP_BRUTE_WINDOW_MS = 60 * 60 * 1000, LDAP_ENUM_ENTRIES = 1000;
const LDAP_ALL_FILTER_RE = /^\(?\s*objectclass\s*=\s*\*\s*\)?$/i;
function detectLdapIssues(events) {
  const issues = [];
  const ld = events.filter(e => e.fields && e.fields.ldap);
  if (!ld.length) return issues;
  const time = (a, b) => effectiveTime(a) - effectiveTime(b);
  const group = (list, keyOf) => { const m = new Map(); list.forEach(e => { const k = keyOf(e); if (!k) return; if (!m.has(k)) m.set(k, []); m.get(k).push(e); }); return m; };
  // 暴力破解
  for (const [src, list] of group(ld.filter(e => e.fields.srcip && (ldapBindFailed(e.fields) || e.fields.ldap === 'bindok')), e => e.fields.srcip)) {
    const sorted = [...list].sort(time);
    let fails = [];
    const flush = (succ) => {
      if (fails.length < LDAP_BRUTE_MIN) { fails = []; return; }
      const users = [...new Set(fails.map(x => x.fields.user).filter(Boolean))];
      const rel = succ ? [...fails, succ] : fails;
      issues.push({ category: 'ldapBruteForce', severityNorm: succ ? 'High' : 'Medium', count: rel.length,
        firstSeen: fails[0].timestamp || null, lastSeen: rel[rel.length - 1].timestamp || null,
        ...sampleOf(succ ? 'sample.ldapBruteOk' : 'sample.ldapBrute', { src, n: fails.length, users: users.slice(0, 5).join(', ') || '-', user: succ ? succ.fields.user || '-' : '' }),
        relatedHosts: [src, ...users.slice(0, 5)], relatedEvents: rel, confidence: 'heuristic' });
      fails = [];
    };
    sorted.forEach(e => {
      const t = effectiveTime(e);
      // 視窗滑出前已達門檻的一波先列出，之後的失敗另算
      if (fails.length && t - effectiveTime(fails[0]) > LDAP_BRUTE_WINDOW_MS) {
        if (fails.length >= LDAP_BRUTE_MIN) flush(null);
        else fails = fails.filter(x => t - effectiveTime(x) <= LDAP_BRUTE_WINDOW_MS);
      }
      if (ldapBindFailed(e.fields)) fails.push(e);
      else if (!e.fields.ldapAnon) flush(e);
    });
    flush(null);
  }
  // 明碼繫結、匿名繫結
  const summary = (cat, sev, list, key) => {
    for (const [k, l] of group(list, e => (e.fields.srcip || e.host || '-') + '|' + (e.fields.user || ''))) {
      const sorted = [...l].sort(time);
      const [src, user] = k.split('|');
      issues.push({ category: cat, severityNorm: sev, count: sorted.length,
        firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
        ...sampleOf(key, { src, user: user || '-', n: sorted.length }),
        relatedHosts: [src, user].filter(x => x && x !== '-'), relatedEvents: sorted, confidence: 'confirmed' });
    }
  };
  summary('ldapPlainBind', 'Medium', ld.filter(e => e.fields.ldapPlain && e.fields.ldap === 'bindok'), 'sample.ldapPlainBind');
  summary('ldapAnonBind', 'Low', ld.filter(e => e.fields.ldapAnon && e.fields.ldap === 'bindok'), 'sample.ldapAnonBind');
  // 目錄列舉
  const enumList = ld.filter(e => e.fields.ldap === 'searchres' && ((e.fields.scope === '2' && LDAP_ALL_FILTER_RE.test(e.fields.filter || '')) || Number(e.fields.nentries) >= LDAP_ENUM_ENTRIES));
  for (const [src, l] of group(enumList, e => e.fields.srcip || e.host || '-')) {
    const sorted = [...l].sort(time);
    const total = sorted.reduce((a, e) => a + (Number(e.fields.nentries) || 0), 0);
    issues.push({ category: 'ldapEnum', severityNorm: 'Medium', count: sorted.length,
      firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf('sample.ldapEnum', { src, n: sorted.length, entries: total, base: sorted[0].fields.base || '-' }),
      relatedHosts: [src], relatedEvents: sorted, confidence: 'heuristic' });
  }
  return issues;
}
// LDAP 去識別化（第三十輪 LD5）：DN 與搜尋條件中的帳號類屬性值（uid／cn／sAMAccountName／userPrincipalName／
// krbPrincipalName）換假帳號、mail 換假 email、dc 連續段以主機名稱對照換成假網域、ou／o 依「備註」以外的固定規則換成 ou-N；
// objectClass 等其他屬性值保留
const LDAP_USER_ATTRS = /^(?:uid|cn|samaccountname|userprincipalname|krbprincipalname|displayname|givenname|sn|memberuid)$/i;
// OpenLDAP 內建 DN（cn=auth、cn=external、cn=peercred、cn=config、cn=monitor…）不是帳號
const LDAP_BUILTIN_CN_RE = /^(?:auth|external|peercred|gssapi|digest-md5|plain|config|monitor|schema|subschema)$/i;
function anonLdapDn(dn) {
  if (!dn) return dn;
  const parts = String(dn).split(/,(?=\s*[A-Za-z][\w-]*=)/);
  const dcs = parts.filter(p => /^\s*dc=/i.test(p)).map(p => p.split('=')[1].trim());
  const fakeDc = dcs.length ? anonDnsName(dcs.join('.')).split('.') : [];
  let di = 0;
  return parts.map(p => {
    const m = p.match(/^(\s*)([A-Za-z][\w-]*)=(.*)$/);
    if (!m) return p;
    const [, sp, attr, val] = m;
    if (/^dc$/i.test(attr)) return `${sp}${attr}=${fakeDc[di++] || val}`;
    if (LDAP_USER_ATTRS.test(attr) && !LDAP_BUILTIN_CN_RE.test(val)) return `${sp}${attr}=${anonUser(val.replace(/\\(.)/g, '$1'))}`;
    if (/^mail$/i.test(attr)) return `${sp}${attr}=${anonEmails(val)}`;
    if (/^(?:ou|o|l)$/i.test(attr)) return `${sp}${attr}=${anonHostname(val)}`;
    return p;
  }).join(',');
}
function anonLdapFilter(flt) {
  return String(flt || '').replace(/\(([A-Za-z][\w-]*)(~=|>=|<=|=)([^()]*)\)/g, (m, attr, op, val) => {
    if (val === '*' || !val) return m;
    if (LDAP_USER_ATTRS.test(attr)) return `(${attr}${op}${val.split('*').map(x => (x ? anonUser(x) : x)).join('*')})`;
    if (/^mail$/i.test(attr)) return `(${attr}${op}${anonEmails(val)})`;
    if (/^(?:distinguishedname|member|memberof|manager)$/i.test(attr)) return `(${attr}${op}${anonLdapDn(val)})`;
    return m;
  });
}
// SASL 身分（authcid／authzid）：dn: 或含 = 的為 DN，u: 或其他為帳號
function anonLdapId(v) {
  const m = String(v).match(/^(dn:|u:)?([\s\S]*)$/i);
  if (!m[2]) return v;
  return (m[1] || '') + (/^dn:/i.test(m[1] || '') || m[2].includes('=') ? anonLdapDn(m[2]) : anonUser(m[2]));
}
function anonymizeLdapEvent(clone, opts) {
  if (clone.host) clone.host = anonHostname(clone.host);
  const f0 = clone.fields;
  clone.msg = replaceIPsInLine(String(clone.msg || '')
    .replace(/\b(dn|base|id|newrdn|newSuperior)="(.*?)"/g, (m, k, v) => `${k}="${anonLdapDn(v)}"`)
    .replace(/\b(authcid|authzid)="(.*?)"/g, (m, k, v) => `${k}="${anonLdapId(v)}"`)
    .replace(/\bslapd-([^/\s.]+)\.socket/g, (m, v) => `slapd-${anonHostname(v)}.socket`)
    .replace(/\bfilter="(.*?)"(?=\s|$)/, (m, v) => `filter="${anonLdapFilter(v)}"`), opts);
  const re = parseLdapBody(clone.msg);
  const f = re || {};
  ['srcip', 'dstip'].forEach(k => { if (f0[k] && !f[k]) f[k] = replaceIPsInLine(String(f0[k]), opts); });
  if (f0.srcport && !f.srcport) f.srcport = f0.srcport;
  ['dn', 'base'].forEach(k => { if (f0[k] !== undefined && f[k] === undefined) f[k] = anonLdapDn(f0[k]); });
  if (f0.filter !== undefined && f.filter === undefined) f.filter = anonLdapFilter(f0.filter);
  if (f0.user) f.user = anonUser(f0.user);
  ['ldap', 'method', 'mech', 'scope', 'ldapAnon', 'ldapPlain', 'ldapTls', 'ldapLocal'].forEach(k => { if (f0[k] !== undefined) f[k] = f0[k]; });
  clone.fields = f;
  clone.raw = clone.format === 'ldap' ? `${clone.rawPrefix || ''}${clone.msg}` : rebuildSyslogRaw(clone);
}
// ── HAProxy（第二十三輪 IE，依 HAProxy 官方 doc/configuration.txt 第 8.2.2／8.2.3 節）──
// option httplog：用戶端:埠 [請求時間] 前端 後端/伺服器 TR/Tw/Tc/Tr/Ta 狀態 位元組 請求cookie 回應cookie 終止狀態
//   actconn/feconn/beconn/srv_conn/retries 伺服器佇列/後端佇列[ {擷取請求標頭}][ {擷取回應標頭}] "請求行"
// option tcplog：用戶端:埠 [時間] 前端 後端/伺服器 Tw/Tc/Tt 位元組 終止狀態 actconn/…/retries 佇列/佇列
// 終止狀態第一字 P 表示由 HAProxy 擋下（如 http-request deny），與 403／429 同列為拒絕；欄位 haproxy（http／tcp）、srcip、srcport、
// frontend、backend、server、status、bytes、termState、method、url
// 第二十三輪功能驗證（依 Elastic integrations haproxy 套件的 grok 與真實測試 log）：用戶端位址可為 -、伺服器與計時欄之間可多一個
// 目的位址或主機欄（自訂格式，存 dstip 或 dsthost）、請求行可能被截斷沒有結尾引號
const HAPROXY_HTTP_RE = /^(\S+):(\d+) \[(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}\.\d{3})\] (\S+) ([^\s/]+)\/(\S+) (?:(\S+) )?-?\d+\/-?\d+\/-?\d+\/-?\d+\/\+?-?\d+ (-?\d+) \+?(\d+) \S+ \S+ ([-A-Za-z]{4}) \d+\/\d+\/\d+\/\d+\/\+?\d+ \d+\/\d+(?: \{[^}]*\}){0,2}(?: "([^"]*)"?)?\s*$/;
const HAPROXY_TCP_RE = /^(\S+):(\d+) \[(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}\.\d{3})\] (\S+) ([^\s/]+)\/(\S+) (?:(\S+) )?-?\d+\/-?\d+\/\+?-?\d+ \+?(\d+) ([-A-Za-z]{2}) \d+\/\d+\/\d+\/\d+\/\+?\d+ \d+\/\d+\s*$/;
function haproxyBase(m) {
  const f = { srcport: m[2], frontend: m[4], backend: m[5], server: m[6] };
  if (m[1] !== '-') f.srcip = m[1];
  if (m[7]) { if (/^[\d.]+$|:/.test(m[7])) f.dstip = m[7]; else f.dsthost = m[7]; }
  return f;
}
function parseHaproxyMsg(appName, msg) {
  if (!/^haproxy/i.test(appName || '')) return null;
  const s = String(msg || '').trim();
  let m = s.match(HAPROXY_HTTP_RE);
  if (m) {
    const f = { haproxy: 'http', ...haproxyBase(m), status: m[8], bytes: m[9], termState: m[10] };
    const rq = (m[11] || '').match(/^(\S+) (\S+)/);
    if (rq) { f.method = rq[1]; f.url = rq[2]; }
    return { vendor: 'haproxy', fields: f };
  }
  if ((m = s.match(HAPROXY_TCP_RE))) return { vendor: 'haproxy', fields: { haproxy: 'tcp', ...haproxyBase(m), bytes: m[8], termState: m[9] } };
  return null;
}
// 不經 syslog 的原始行（log stdout format raw，容器常見）或只有「haproxy[pid]: 」前綴的行，格式 haproxy
const HAPROXY_RAW_RE = /^((?:haproxy\[\d+\]: )?)(\S+:\d+ \[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}\.\d{3}\] [\s\S]*)$/;
function parseHaproxyLine(line, lineNo) {
  const m = line.match(HAPROXY_RAW_RE);
  const vf = m && parseHaproxyMsg('haproxy', m[2]);
  if (!vf) return null;
  const d = m[2].match(/\[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})\.(\d{3})\]/);
  const ts = d && DNS_MONTHS[d[2]] ? new Date(`${d[3]}-${DNS_MONTHS[d[2]]}-${d[1]}T${d[4]}.${d[5]}`) : null;
  return {
    format: 'haproxy', raw: line, lineNo, netFields: true, netVendor: 'haproxy',
    timestamp: ts && !isNaN(ts.getTime()) ? ts : null, timestampRaw: d ? d[0].slice(1, -1) : '',
    host: '', appName: 'haproxy', procid: '', msgid: '', severityRaw: '', severityNorm: 'Info',
    facility: null, facilityAuth: false, msg: m[2], rawPrefix: m[1], fields: vf.fields
  };
}
const haproxyDenied = f => !!f && !!f.haproxy && (/^P/.test(f.termState || '') || f.status === '403' || f.status === '429');
// ── Cisco ISE 認證紀錄（第二十一輪 GE，依 Elastic integrations cisco_ise 套件的真實測試 log）──
// syslog 訊息：CISE_類別 訊息編號 總段數 段序 [日期 時間 時區 序號 代碼 嚴重度 訊息類別: 說明, ]鍵=值, 鍵=值, …
//   第一段（段序 0）帶時間與代碼，後續段只有「鍵=值」；鍵名可含空白（Device IP Address），同名鍵（Step 等）只取第一個
// 欄位：ise（類別，如 Failed_Attempts）、iseCode、iseClass（Failed-Attempt／Passed-Authentication…）、user、mac（Calling-Station-ID）、
//   netHost（NetworkDeviceName）、nasPort（NAS-Port-Id）、nasIp、failReason；認證失敗（Failed_Attempts 的 Failed-Attempt）歸 authFail
const ISE_RE = /^CISE_(\w+) (\d+) (\d+) (\d+) ?(?:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-]\d{2}:\d{2}) (\d+) (\d+) (\w+) ([^:,]+): ([^,]*),?)?\s*([\s\S]*)$/;
const ISE_KV_RE = /(?:^|,\s*)([A-Za-z][\w .-]*?)=([^,]*)/g;
function parseIseMsg(msg) {
  const m = String(msg || '').match(ISE_RE);
  if (!m) return null;
  const kv = {};
  for (const x of m[12].matchAll(ISE_KV_RE)) if (kv[x[1]] === undefined) kv[x[1]] = x[2].trim();
  const f = { ise: m[1], iseMsgId: m[2], iseSeg: m[4] };
  if (m[5]) Object.assign(f, { iseTime: `${m[5]} ${m[6]}`, iseCode: m[8], iseSev: m[9], iseClass: m[10], iseText: m[11].trim() });
  const pick = (k, ...names) => { const n = names.find(x => kv[x]); if (n) f[k] = kv[n]; };
  pick('user', 'UserName', 'User-Name');
  pick('mac', 'Calling-Station-ID');
  pick('netHost', 'NetworkDeviceName');
  pick('nasPort', 'NAS-Port-Id');
  pick('nasIp', 'NAS-IP-Address', 'Device IP Address');
  pick('srcip', 'Framed-IP-Address');
  pick('failReason', 'FailureReason');
  pick('authMethod', 'AuthenticationMethod');
  pick('radiusFlow', 'RadiusFlowType');
  f.iseKv = kv;
  return { vendor: 'ciscoise', fields: f };
}
// 事件時間改用第一段本文的完整時間（syslog 表頭沒有年份）；多段訊息後續段的使用者／MAC／設備／埠補回第一段
// （第一段才有代碼與類別，偵測只看第一段），後續段沿用第一段時間
function linkIseSegments(events) {
  const first = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (!f || !f.ise) return;
    const k = `${e.host}|${f.ise}|${f.iseMsgId}`;
    if (f.iseTime) { const t = new Date(f.iseTime.replace(' ', 'T').replace(' ', '')); if (!isNaN(t.getTime())) e.timestamp = t; }
    if (f.iseSeg === '0') first.set(k, e);
    else if (first.has(k)) {
      const fe = first.get(k), ff = fe.fields;
      if (fe.timestamp) e.timestamp = fe.timestamp;
      ['user', 'mac', 'netHost', 'nasPort', 'nasIp', 'srcip', 'failReason'].forEach(x => { if (f[x] && !ff[x]) ff[x] = f[x]; });
    }
  });
  return events;
}
// Failed_Attempts 第一段中，RADIUS 類別為伺服器端丟棄／過載通知，不算認證失敗
const iseAuthFailed = f => !!(f && f.ise === 'Failed_Attempts' && f.iseSeg === '0' && f.iseClass && f.iseClass !== 'RADIUS');
// 同一網路設備＋埠（NAS-Port-Id）的 802.1X／MAB 認證失敗彙整（第二十一輪 GE）：帶 netHost／netIface 供 🔌 交換器介面對照
const NAC_FAIL_MIN = 3;
function detectNacAuthFail(events) {
  const groups = new Map();
  events.forEach(e => {
    const f = e.fields;
    if (!iseAuthFailed(f) || !f.netHost || !f.nasPort) return;
    const k = `${f.netHost}|${f.nasPort}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(e);
  });
  const issues = [];
  for (const [k, list] of groups) {
    if (list.length < NAC_FAIL_MIN) continue;
    const [dev, port] = k.split('|');
    const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    const cnt = new Map();
    sorted.forEach(e => { const mac = e.fields.mac || ''; if (mac) cnt.set(mac, (cnt.get(mac) || 0) + 1); });
    const macs = [...cnt.keys()].sort((a, b) => cnt.get(b) - cnt.get(a));
    const users = [...new Set(sorted.map(e => e.fields.user).filter(Boolean))];
    const last = sorted[sorted.length - 1];
    issues.push({
      category: 'nacAuthFail', severityNorm: 'Medium', count: sorted.length,
      firstSeen: sorted[0].timestamp || null, lastSeen: last.timestamp || null,
      sampleRaw: `${dev} ${port}：${[...macs, ...users.filter(u => !macs.includes(u))].slice(0, 3).join(', ') || '-'}${last.fields.failReason ? '（' + last.fields.failReason + '）' : ''}`,
      relatedHosts: [dev, port], relatedEvents: sorted, confidence: 'confirmed',
      netHost: dev, netIface: port, ...(macs[0] ? { netMac: macs[0] } : {})
    });
  }
  return issues;
}
// ── DHCP 租約紀錄（第二十一輪 GC）──
// 共用欄位：dhcp（動作小寫，如 ack／release／decline／new／renew）、srcip（用戶端位址）、mac、dhcpHost（用戶端主機名稱）、iface
//   dnsmasq（依 dnsmasq src/rfc2131.c log_packet()，程式名稱 dnsmasq-dhcp）：[交易編號 ]類型(介面) [IP ][MAC ][主機名稱或訊息]
//   ISC dhcpd（依 ISC DHCP server/dhcp.c）：DHCPACK on IP to MAC (主機) via 介面、DHCPRELEASE of IP from MAC (主機) via 介面 (found)、
//     DHCPDISCOVER from MAC (主機) via 介面、DHCPREQUEST for IP (伺服器) from MAC (主機) via 介面
//   Windows DHCP Server 稽核 log（依 Microsoft 文件 DhcpSrvLog-<星期>.log）：ID,Date,Time,Description,IP Address,Host Name,MAC Address,…
//     日期為 MM/DD/YY；表頭說明行（到 ID,Date,Time 那行為止）略過
const DNSMASQ_DHCP_RE = /^(?:\d+ )?(DHCP[A-Z]+)\(([^)]*)\)(?: ((?:\d{1,3}\.){3}\d{1,3}))?(?: ([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5,}))?(?: (.*))?$/;
const ISC_DHCP_RE = /^(DHCP[A-Z]+) (?:(?:on|of|for) ((?:\d{1,3}\.){3}\d{1,3})(?: \([^)]*\))? (?:to|from) )?(?:from )?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})(?: \(([^)]*)\))? via (\S+)/;
const WINDHCP_ROW_RE = /^(\d{2}),(\d{2})\/(\d{2})\/(\d{2}),(\d{2}:\d{2}:\d{2}),/;
const WINDHCP_HEAD_RE = /^ID,Date,Time,Description,IP Address,Host Name,MAC Address/;
const WINDHCP_ACTION = { '10': 'new', '11': 'renew', '12': 'release', '13': 'inuse', '14': 'exhausted', '15': 'denied', '16': 'deleted', '17': 'expired', '18': 'expired', '20': 'new' };
const normMac = m => String(m || '').replace(/-/g, ':').toLowerCase();
function parseDhcpInMsg(appName, msg) {
  const s = String(msg || '');
  let m;
  if (/dnsmasq/i.test(appName || '') && (m = s.match(DNSMASQ_DHCP_RE))) {
    const f = { dhcp: m[1].slice(4).toLowerCase(), iface: m[2] };
    if (m[3]) f.srcip = m[3];
    if (m[4]) f.mac = normMac(m[4]);
    if (m[5]) { if (/^[\w.-]+$/.test(m[5])) f.dhcpHost = m[5]; else f.dhcpMsg = m[5]; }
    return { vendor: 'dnsmasq', fields: f };
  }
  if ((m = s.match(ISC_DHCP_RE))) {
    const f = { dhcp: m[1].slice(4).toLowerCase(), mac: normMac(m[3]), iface: m[5] };
    if (m[2]) f.srcip = m[2];
    if (m[4]) f.dhcpHost = m[4];
    return { vendor: 'iscdhcp', fields: f };
  }
  return null;
}
// ── Windows NPS（網路原則伺服器）DTS XML 記錄檔（XN65）──
// 每行一筆 <Event>…</Event>，每個屬性為 <名稱 data_type="N">值</名稱>（依 GitHub eenest/nps-logview 附的去識別化真實擷取）；
// 預設在 C:\Windows\System32\LogFiles\IN*.log。Packet-Type：1 Access-Request、2 Access-Accept、3 Access-Reject、
// 4 Accounting-Request、5 Accounting-Response；Reason-Code 名稱依 IAS_* 常數（verbosemode/nps-dts-radius-logparser）。
// RADIUS 用戶端（Client-IP-Address）是 AP／交換器，不是使用者電腦，故不設 srcip（避免同一台 AP 被當成密碼噴灑來源）
const NPS_DTS_RE = /^<Event><Timestamp data_type="\d+">[^<]*<\/Timestamp>[\s\S]*<(?:Packet-Type|Event-Source) data_type=/;
const NPS_PACKET = { 1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 4: 'Accounting-Request', 5: 'Accounting-Response' };
const NPS_REASON = { 0: 'IAS_SUCCESS', 1: 'IAS_INTERNAL_ERROR', 2: 'IAS_ACCESS_DENIED', 3: 'IAS_MALFORMED_REQUEST', 4: 'IAS_GLOBAL_CATALOG_UNAVAILABLE',
  5: 'IAS_DOMAIN_UNAVAILABLE', 6: 'IAS_SERVER_UNAVAILABLE', 7: 'IAS_NO_SUCH_DOMAIN', 8: 'IAS_NO_SUCH_USER', 16: 'IAS_AUTH_FAILURE',
  17: 'IAS_CHANGE_PASSWORD_FAILURE', 18: 'IAS_UNSUPPORTED_AUTH_TYPE', 32: 'IAS_LOCAL_USERS_ONLY', 33: 'IAS_PASSWORD_MUST_CHANGE',
  34: 'IAS_ACCOUNT_DISABLED', 35: 'IAS_ACCOUNT_EXPIRED', 36: 'IAS_ACCOUNT_LOCKED_OUT', 37: 'IAS_INVALID_LOGON_HOURS', 38: 'IAS_ACCOUNT_RESTRICTION',
  48: 'IAS_NO_POLICY_MATCH', 64: 'IAS_DIALIN_LOCKED_OUT', 65: 'IAS_DIALIN_DISABLED', 66: 'IAS_INVALID_AUTH_TYPE', 67: 'IAS_INVALID_CALLING_STATION',
  68: 'IAS_INVALID_DIALIN_HOURS', 69: 'IAS_INVALID_CALLED_STATION', 70: 'IAS_INVALID_PORT_TYPE', 71: 'IAS_INVALID_RESTRICTION', 80: 'IAS_NO_RECORD',
  96: 'IAS_SESSION_TIMEOUT', 97: 'IAS_UNEXPECTED_REQUEST' };
// 原則或設定不符（不是密碼錯誤）的原因碼：沒有符合的網路原則、撥入權限、驗證方法、來電／被叫站、時段、埠類型等限制
const NPS_POLICY_REASONS = new Set([48, 64, 65, 66, 67, 68, 69, 70, 71]);
// MAC 比對鍵：去掉 : - . 分隔符的 12 碼小寫，不是 MAC 時回傳空字串
const macKey = m => { const k = String(m || '').replace(/[:.-]/g, '').toLowerCase(); return /^[0-9a-f]{12}$/.test(k) ? k : ''; };
function npsTags(line) {
  const out = Object.create(null), seen = new Set();
  const re = /<([A-Za-z][\w-]*) data_type="\d+">([^<]*)<\/\1>/g;
  let m;
  while ((m = re.exec(line)) !== null) {
    if (seen.has(m[1])) { delete out[m[1]]; continue; }  // 同名多個（Vendor-Specific 等）不收
    seen.add(m[1]); out[m[1]] = m[2];
  }
  return out;
}
function parseNpsLine(line, lineNo) {
  if (!NPS_DTS_RE.test(line)) return null;
  const t = npsTags(line);
  const pk = parseInt(t['Packet-Type'], 10), rc = t['Reason-Code'] !== undefined ? parseInt(t['Reason-Code'], 10) : null;
  const f = { nps: 1 };
  if (!isNaN(pk)) { f.npsPacket = pk; f.npsPacketName = NPS_PACKET[pk] || String(pk); }
  if (rc !== null && !isNaN(rc)) { f.npsReason = rc; f.npsReasonName = NPS_REASON[rc] || 'IAS_' + rc; }
  const user = t['SAM-Account-Name'] || t['User-Name'] || t['Fully-Qualifed-User-Name'] || '';
  if (user) f.user = user;
  if (t['Client-IP-Address']) f.nasIp = t['Client-IP-Address'];
  if (t['Client-Friendly-Name']) f.nasName = t['Client-Friendly-Name'];
  if (t['Calling-Station-Id']) f.mac = t['Calling-Station-Id'];
  if (t['NP-Policy-Name']) f.policy = t['NP-Policy-Name'];
  // 時間為 NPS 主機的本地時間「月/日/年 時:分:秒.毫秒」，比照 Windows DHCP 以本地時間解析
  const tm = String(t.Timestamp || '').match(/^(\d{2})\/(\d{2})\/(\d{4}) (\d{2}:\d{2}:\d{2})(\.\d+)?$/);
  const ts = tm ? new Date(`${tm[3]}-${tm[1]}-${tm[2]}T${tm[4]}${tm[5] || ''}`) : null;
  const reject = pk === 3;
  const msg = [f.npsPacketName || 'NPS', user, f.npsReasonName && (reject || rc) ? `(${f.npsReasonName})` : '', f.nasName ? `via ${f.nasName}` : (f.nasIp ? `via ${f.nasIp}` : '')].filter(Boolean).join(' ');
  return {
    format: 'nps', raw: line, lineNo, netFields: false, netVendor: 'nps',
    timestamp: ts && !isNaN(ts.getTime()) ? ts : null, timestampRaw: t.Timestamp || '',
    host: t['Computer-Name'] || '', appName: 'nps', procid: '', msgid: String(isNaN(pk) ? '' : pk), severityRaw: String(isNaN(pk) ? '' : pk),
    severityNorm: reject ? 'Medium' : 'Info', facility: null, facilityAuth: true, msg, fields: f
  };
}
// Aruba ClearPass Policy Manager（XN134）：Syslog Export Filter 的輸出。格式依 splunk-connect-for-syslog 測試資料的實際輸出行：
// 標準格式「<PRI>年-月-日 時:分:秒,毫秒 主機 篩選器名稱 序號 1 0 鍵=值,鍵=值…」（篩選器名稱由管理者自訂、可含空白；值本身可含逗號），
// 6.11 起另有 RFC5424「… ClearPass 行程 編號 [timeQuality…][origin…][clearPass@14823 eventId="…" 鍵="值" …]」。
// 鍵依範本而定：Session Logs（Common.*／RADIUS.*／WEBAUTH.*）、Audit Records（Timestamp／Source／Category／Action／User）、
// System Events（event_source／level／category／description 或 Timestamp／Source／Level／Category／Action／Description）、
// CPPM_Alert（session_id／service_name／alert）、端點清單（mac_address／ip_address／hostname…）。只解析範例出現過的鍵
const CPPM_KEY_SRC = '(?:(?:Common|RADIUS|TACACS|WEBAUTH|CppmNode)\\.[A-Za-z][\\w\\- ]*|event_source|session_id|mac_address|Timestamp)';
const CPPM_STD_RE = new RegExp('^(?:<\\d{1,3}>)?\\s*(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})(?:,(\\d{3}))? (\\S+) (.+?) \\d+ \\d+ \\d+ (' + CPPM_KEY_SRC + '=.*)$');
const CPPM_5424_RE = /^<\d{1,3}>1 (\S+) (\S+) ClearPass \S+ \S+ .*\[clearPass@14823 ([^\n]*)\]\s*$/;
const CPPM_SPLIT_RE = /,(?=(?:[A-Za-z]+\.)?[A-Za-z][A-Za-z_\- ]*=)/;
function cppmKv(body) {
  const o = Object.create(null);
  String(body || '').split(CPPM_SPLIT_RE).forEach(p => {
    const i = p.indexOf('=');
    if (i <= 0) return;
    // 文件轉貼的輸出行會在鍵中間斷行留下空白（Common.Host-MAC-   Address），帶點號的鍵去掉空白
    const k = p.slice(0, i).trim(), key = k.includes('.') ? k.replace(/\s+/g, '') : k;
    if (!(key in o)) o[key] = p.slice(i + 1).replace(/,\s*$/, '').trim();
  });
  return o;
}
function cppmSd(sd) {
  const o = Object.create(null);
  const re = /([A-Za-z][\w.\-]*)="((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(sd))) if (!(m[1] in o)) o[m[1]] = m[2].replace(/\\([\]"\\])/g, '$1');
  return o;
}
function cppmTime(v) {
  const m = String(v || '').replace(/\s+/g, ' ').match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+-]\d{2})(?::?(\d{2}))?$/);
  if (!m) return null;
  const d = new Date(`${m[1]}T${m[2]}${m[3]}:${m[4] || '00'}`);
  return isNaN(d.getTime()) ? null : d;
}
function parseClearPassLine(line, lineNo) {
  let kv, host, hdrTime, filter = '';
  const s = line.match(CPPM_STD_RE), r = s ? null : line.match(CPPM_5424_RE);
  if (s) { kv = cppmKv(s[5]); host = s[3]; filter = s[4]; hdrTime = new Date(`${s[1].replace(' ', 'T')}${s[2] ? '.' + s[2] : ''}`); }
  else if (r) { kv = cppmSd(r[3]); host = r[2]; hdrTime = new Date(r[1]); }
  else return null;
  const g = k => kv[k] || '';
  const f = { cppm: 'other' };
  if (filter) f.cppmFilter = filter;
  const status = g('Common.Login-Status').toUpperCase();
  let sev = 'Info', msg = '';
  if (status || g('Common.Error-Code') || g('Common.Username')) {
    f.cppm = 'session';
    if (status) f.cppmStatus = status;
    if (g('Common.Username')) f.user = g('Common.Username');
    if (g('Common.Host-MAC-Address')) f.mac = g('Common.Host-MAC-Address');
    // NAS（AP／交換器）不當成來源位址，避免同一台設備被當成密碼噴灑來源（與 NPS 相同）
    if (g('Common.NAS-IP-Address')) f.nasIp = g('Common.NAS-IP-Address');
    if (g('Common.NAS-Name')) f.nasName = g('Common.NAS-Name');
    if (g('Common.Error-Code')) f.cppmError = g('Common.Error-Code');
    if (g('Common.Service')) f.policy = g('Common.Service');
    if (g('Common.Source')) f.cppmSource = g('Common.Source');
    if (g('RADIUS.Auth-Method')) f.authMethod = g('RADIUS.Auth-Method');
    if (g('Common.Alerts')) f.failReason = g('Common.Alerts');
    // 網頁登入（WEBAUTH）的用戶端位址；本機 127.0.0.1 不算來源
    const wip = g('WEBAUTH.Host-IP-Address').replace(/\s+/g, '');
    if (wip && wip !== '127.0.0.1' && wip !== '::1') f.srcip = wip;
    if (status === 'REJECT') sev = 'Medium';
    msg = ['ClearPass', status || 'session', f.user || '', f.cppmError && f.cppmError !== '0' ? `(error ${f.cppmError})` : '', f.policy ? `service ${f.policy}` : '', f.nasName ? `via ${f.nasName}` : (f.nasIp ? `via ${f.nasIp}` : ''),
      status === 'REJECT' && f.failReason ? '- ' + f.failReason : ''].filter(Boolean).join(' ');
  } else if (g('Action') && g('User') && !g('Level')) {
    f.cppm = 'audit'; f.user = g('User'); f.cppmAction = g('Action'); f.cppmCategory = g('Category');
    msg = `ClearPass audit: ${g('Action')} ${g('Category')} by ${g('User')}`;
  } else if (g('level') || g('Level')) {
    f.cppm = 'system';
    const lv = (g('level') || g('Level')).toUpperCase();
    sev = lv === 'ERROR' ? 'Medium' : lv === 'WARN' || lv === 'WARNING' ? 'Low' : 'Info';
    msg = ['ClearPass', g('event_source') || g('Source'), lv, g('category') || g('Category'), g('action_key') || g('Action'), g('description') || g('Description')].filter(Boolean).join(' | ');
  } else if (g('alert')) {
    f.cppm = 'alert';
    msg = `ClearPass alert: ${g('service_name')} ${g('alert')}`.replace(/\s+/g, ' ');
  } else if (g('mac_address')) {
    f.cppm = 'endpoint';
    msg = ['ClearPass endpoint', g('mac_address'), g('ip_address'), g('hostname'), g('device_category'), g('device_name')].filter(Boolean).join(' ');
  } else msg = 'ClearPass ' + (filter || 'event');
  const ts = cppmTime(g('Common.Request-Timestamp')) || cppmTime(g('timestamp')) || cppmTime(g('updated_at').replace(/(\.\d{3})\d+/, '$1')) || (hdrTime && !isNaN(hdrTime.getTime()) ? hdrTime : null);
  return {
    format: 'clearpass', raw: line, lineNo, netFields: false, netVendor: 'clearpass',
    timestamp: ts, timestampRaw: g('Common.Request-Timestamp') || g('timestamp') || (s ? s[1] : r ? r[1] : ''),
    host: host || '', appName: 'clearpass', procid: '', msgid: g('eventId'), severityRaw: status || g('level') || g('Level') || '',
    severityNorm: sev, facility: null, facilityAuth: f.cppm === 'session', msg, fields: f
  };
}
function parseWinDhcpLine(line, lineNo) {
  const m = line.match(WINDHCP_ROW_RE);
  if (!m) return null;
  const c = splitCSVSimple(line);
  const f = { dhcp: WINDHCP_ACTION[m[1]] || 'event', dhcpId: m[1], dhcpDesc: c[3] || '' };
  if (c[4]) f.srcip = c[4];
  if (c[5]) f.dhcpHost = c[5];
  if (c[6]) f.mac = /^[0-9a-fA-F]{12}$/.test(c[6]) ? c[6].toLowerCase().match(/../g).join(':') : c[6];
  const ts = new Date(`20${m[4]}-${m[2]}-${m[3]}T${m[5]}`);
  const warn = /^1[345]$/.test(m[1]);
  return {
    format: 'dhcp', raw: line, lineNo, netFields: false, netVendor: 'windhcp',
    timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: `${m[2]}/${m[3]}/${m[4]} ${m[5]}`,
    host: '', appName: 'windhcp', procid: '', msgid: m[1], severityRaw: m[1], severityNorm: warn ? 'Medium' : 'Info',
    facility: null, facilityAuth: false,
    msg: `${f.dhcpDesc} ${f.srcip || ''} ${f.mac || ''} ${f.dhcpHost || ''}`.replace(/\s+/g, ' ').trim(), fields: f
  };
}
// 位址歸屬（GD／第二十一輪、HA／第二十二輪）：依事件時間找出某個 IP 當時是哪台主機、哪個帳號——
//   主機（kind host）：DHCP 取得租約（ack／new／renew）起算，到釋放／刪除／到期為止，名稱為主機名稱（沒有時為 MAC）
//   帳號（kind user）：Cisco ISE RADIUS Accounting（Framed-IP-Address，Start／Interim-Update 起、Stop 止）、
//     FortiGate VPN 事件（action tunnel-up／tunnel-down 的 tunnelip 與 user，依 Elastic Beats fortinet 模組真實測試 log）、
//     Cisco ASA AnyConnect 722051（User <帳號> IP <公網> IPv4 Address <指派位址> … assigned to session，同上 cisco 模組）
// 其他事件的 srcip／dstip 補上 fields.srcName／dstName 與 srcUser／dstUser；沒有時間的事件不補
const DHCP_LEASE_START = new Set(['ack', 'new', 'renew']);
const DHCP_LEASE_END = new Set(['release', 'deleted', 'expired', 'decline']);
const ASA_VPN_ASSIGN_RE = /\bUser <([^>]+)> IP <[^>]*> IPv4 Address <(\d{1,3}(?:\.\d{1,3}){3})>/;
const usableIp = ip => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip || '') && ip !== '0.0.0.0';
function addrAssignOf(e) {
  const f = e.fields;
  if (!f) return null;
  if (f.dhcp) {
    if (!f.srcip) return null;
    if (DHCP_LEASE_START.has(f.dhcp)) { const name = f.dhcpHost || f.mac || ''; return name ? { ip: f.srcip, act: 'start', kind: 'host', name } : null; }
    return DHCP_LEASE_END.has(f.dhcp) ? { ip: f.srcip, act: 'end', kind: 'host' } : null;
  }
  if (f.radacct && usableIp(f.assignIp)) {
    if ((f.radacct === 'start' || f.radacct === 'interim') && f.user) return { ip: f.assignIp, act: 'start', kind: 'user', name: f.user };
    return f.radacct === 'stop' ? { ip: f.assignIp, act: 'end', kind: 'user' } : null;
  }
  if (f.ise === 'RADIUS_Accounting' && f.iseSeg === '0' && usableIp(f.srcip)) {
    const st = String((f.iseKv && f.iseKv['Acct-Status-Type']) || '');
    if (/^(?:Start|Interim-Update)$/i.test(st) && f.user) return { ip: f.srcip, act: 'start', kind: 'user', name: f.user };
    return /^Stop$/i.test(st) ? { ip: f.srcip, act: 'end', kind: 'user' } : null;
  }
  if (usableIp(f.tunnelip) && /^tunnel-(?:up|down)$/i.test(f.action || '')) {
    if (/up$/i.test(f.action)) return f.user ? { ip: f.tunnelip, act: 'start', kind: 'user', name: f.user } : null;
    return { ip: f.tunnelip, act: 'end', kind: 'user' };
  }
  if (f.ovpn || f.ipsec) {
    const k = f.ovpn || f.ipsec;
    if (!usableIp(f.assignIp)) return null;
    if (k === 'assign' || k === 'learn') return f.user ? { ip: f.assignIp, act: 'start', kind: 'user', name: f.user } : null;
    return (k === 'exit' || k === 'down') ? { ip: f.assignIp, act: 'end', kind: 'user' } : null;
  }
  if (/722051/.test(e.msgid || e.raw || '')) {
    const m = String(e.msg || '').match(ASA_VPN_ASSIGN_RE);
    if (m) return { ip: m[2], act: 'start', kind: 'user', name: m[1] };
  }
  return null;
}
// NPS 帳號歸屬到位址（XN71）：NPS Access-Accept 給「終端 MAC→帳號」，DHCP 租約給「MAC→IP」；
// 租約開始時取同一 MAC 在租約前 12 小時內（容許租約後 60 秒，DHCP 與 NPS 主機時鐘可能略有差距）最近一次 Accept 的帳號
const NPS_MAC_USER_MAX_MS = 12 * 3600 * 1000, NPS_MAC_USER_SKEW_MS = 60 * 1000;
function npsMacUsers(events) {
  const m = new Map();
  events.forEach(e => {
    const f = e.fields;
    // ClearPass 的 ACCEPT 同樣給「終端 MAC→帳號」（XN134）
    const ok = e.format === 'nps' ? f && f.npsPacket === 2 : e.format === 'clearpass' && f && f.cppmStatus === 'ACCEPT';
    if (!ok || !e.timestamp || !f.user) return;
    const k = macKey(f.mac);
    if (!k) return;
    if (!m.has(k)) m.set(k, []);
    m.get(k).push({ t: e.timestamp.getTime(), user: f.user });
  });
  m.forEach(l => l.sort((a, b) => a.t - b.t));
  return m;
}
function npsUserForLease(macUsers, mac, t) {
  const l = macUsers.get(macKey(mac));
  if (!l) return '';
  for (let i = l.length - 1; i >= 0; i--) {
    if (l[i].t > t + NPS_MAC_USER_SKEW_MS) continue;
    return t - l[i].t <= NPS_MAC_USER_MAX_MS ? l[i].user : '';
  }
  return '';
}
function buildAddrMaps(events) {
  const maps = { host: new Map(), user: new Map() };
  const macUsers = npsMacUsers(events);
  const assigns = [];
  events.filter(e => e.timestamp).forEach(e => {
    const a = addrAssignOf(e);
    if (!a) return;
    assigns.push({ e, a });
    // DHCP 租約也依 NPS 帳號產生使用者歸屬；租約結束同時結束使用者區間
    if (macUsers.size && e.fields.dhcp && a.kind === 'host') {
      if (a.act === 'start') { const user = e.fields.mac ? npsUserForLease(macUsers, e.fields.mac, e.timestamp.getTime()) : ''; if (user) assigns.push({ e, a: { ip: a.ip, act: 'start', kind: 'user', name: user } }); }
      else assigns.push({ e, a: { ip: a.ip, act: 'end', kind: 'user' } });
    }
  });
  assigns
    .sort((x, y) => x.e.timestamp - y.e.timestamp)
    .forEach(({ e, a }) => {
      const map = maps[a.kind], t = e.timestamp.getTime();
      const list = map.get(a.ip) || [];
      const last = list[list.length - 1];
      if (a.act === 'start') {
        if (last && last.end === null && last.name === a.name) return;
        if (last && last.end === null) last.end = t;
        list.push({ from: t, end: null, name: a.name });
        map.set(a.ip, list);
      } else if (last && last.end === null) last.end = t;
    });
  return maps;
}
function addrOwnerAt(map, ip, t) {
  const list = map.get(ip);
  if (!list) return '';
  for (let i = list.length - 1; i >= 0; i--) {
    const l = list[i];
    if (l.from <= t) return (l.end === null || t < l.end) ? l.name : '';
  }
  return '';
}
function annotateAddrOwners(events) {
  const maps = buildAddrMaps(events);
  if (!maps.host.size && !maps.user.size) return events;
  events.forEach(e => {
    if (!e.timestamp || !e.fields || addrAssignOf(e)) return;
    const tuple = getEventNetTuple(e), t = e.timestamp.getTime();
    [['src', tuple.src], ['dst', tuple.dst]].forEach(([k, ip]) => {
      if (ip === '-') return;
      const name = addrOwnerAt(maps.host, ip, t), user = addrOwnerAt(maps.user, ip, t);
      if (name) e.fields[k + 'Name'] = name;
      if (user) e.fields[k + 'User'] = user;
    });
  });
  return events;
}
const ipWithName = (ip, name, user) => ((name || user) && ip && ip !== '-') ? `${ip} (${[user, name].filter(Boolean).join(' / ')})` : ip;
// Squid 原生 access.log（第二十二輪 HD，依 Squid 原始碼 src/cf.data.pre 的 logformat squid：
//   %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt，耗時欄靠右補空白）
// 以 weblog 事件輸出：結果碼 squid（TCP_MISS／TCP_DENIED…）、status、bytes、method、url、user、hier（DIRECT…）、dstip（上游位址）、ctype；
// 結果碼含 DENIED 為拒絕（407 代理認證要求除外）
const SQUID_LINE_RE = /^(\d{9,11})\.(\d{3})\s+(\d+)\s+(\S+)\s+([A-Z_]+)\/(\d{3})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([A-Z_]+)\/(\S+)\s+(\S+)\s*$/;
function parseSquidLine(line, lineNo) {
  const m = line.match(SQUID_LINE_RE);
  if (!m) return null;
  const [, sec, ms, elapsed, client, code, status, bytes, method, url, user, hier, peer, ctype] = m;
  const fields = { squid: code, srcip: client, status, bytes, method, url, hier, elapsed };
  if (user !== '-') fields.user = user;
  if (peer !== '-' && /^[\d.:a-fA-F]+$/.test(peer) && /[.:]/.test(peer)) fields.dstip = peer;
  if (ctype !== '-') fields.ctype = ctype;
  const ts = new Date(Number(sec) * 1000 + Number(ms));
  const evt = webEvent('weblog', line, lineNo, ts, `${sec}.${ms}`, '', fields);
  evt.netVendor = 'squid';
  evt.msg = `${code}/${status} ${method} ${url}${fields.user ? ' ' + fields.user : ''}`;
  return evt;
}
// combined 格式之後自行加上的請求標頭欄位（XN78）：只收 origin=／http_origin=（Origin 標頭）與 host=／http_host=（Host 標頭），
// 值可加雙引號；例 nginx log_format 結尾加 origin="$http_origin" host="$host"。其他鍵不收，空值與 - 略過
function webExtraFields(rest) {
  const out = {};
  const re = /(?:^|\s)(origin|http_origin|host|http_host)=("((?:[^"\\]|\\.)*)"|(\S+))/gi;
  let m;
  while ((m = re.exec(String(rest || '')))) {
    const v = (m[3] !== undefined ? m[3].replace(/\\"/g, '"') : m[4]).trim();
    if (!v || v === '-') continue;
    out[/origin/i.test(m[1]) ? 'origin' : 'vhost'] = v;
  }
  return out;
}
function parseWebAccessLine(line, lineNo) {
  const m = line.match(WEB_ACCESS_RE);
  if (!m || !WEB_MONTHS[m[5]]) return null;
  const [, ip, , user, dd, mon, yyyy, hms, tzh, tzm, request, status, bytes, referer, ua] = m;
  const req = request.replace(/\\"/g, '"').split(' ');
  const fields = { srcip: ip, method: req.length >= 2 ? req[0] : '', url: req.length >= 2 ? req[1] : request, httpver: req[2] || '',
    status, bytes: bytes === '-' ? '0' : bytes };
  if (user !== '-') fields.user = user;
  if (referer !== undefined && referer !== '-') fields.referer = referer.replace(/\\"/g, '"');
  if (ua !== undefined && ua !== '-') fields.ua = ua.replace(/\\"/g, '"');
  Object.assign(fields, webExtraFields(line.slice(m[0].length)));
  const ts = new Date(`${yyyy}-${WEB_MONTHS[mon]}-${dd}T${hms}${tzh}:${tzm}`);
  return webEvent('weblog', line, lineNo, ts, `${dd}/${mon}/${yyyy}:${hms} ${tzh}${tzm}`, '', fields);
}
// Windows Defender 防火牆 log（pfirewall.log，第二十二輪 HC）：與 IIS 同為 W3C 風格，表頭 `#Software: Microsoft Windows Firewall`，
// 欄位依 #Fields（1.5 版：date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path，
// 新版另有 pid），空值為 -；`#Time Format: Local` 為本機時間。格式依 Plaso 開源鑑識工具的 winfirewall 解析器（同樣依 #Fields 動態對應）；
// Microsoft 文件站被網路政策擋下，只取得搜尋摘要。動作 DROP 為拒絕、ALLOW 為放行，另有 OPEN／CLOSE／INFO-EVENTS-LOST
function winFwEvent(cols, line, lineNo, utc) {
  const parts = line.trim().split(' ');
  if (parts.length !== cols.length) return null;
  const w = {};
  cols.forEach((c, i) => { w[c] = parts[i] === '-' ? '' : parts[i]; });
  const act = String(w.action || '').toUpperCase();
  const fields = { winfw: act, action: act === 'DROP' ? 'deny' : (act === 'ALLOW' ? 'accept' : ''), proto: w.protocol || '' };
  [['srcip', 'src-ip'], ['dstip', 'dst-ip'], ['srcport', 'src-port'], ['dstport', 'dst-port'], ['size', 'size'], ['tcpflags', 'tcpflags'],
    ['icmptype', 'icmptype'], ['icmpcode', 'icmpcode'], ['direction', 'path'], ['pid', 'pid'], ['info', 'info']].forEach(([k, c]) => { if (w[c]) fields[k] = w[c]; });
  const tsRaw = [w.date, w.time].filter(Boolean).join(' ');
  const ts = w.date && w.time ? new Date(`${w.date}T${w.time}${utc ? 'Z' : ''}`) : null;
  return {
    format: 'w3c', raw: line, lineNo, netFields: true, netVendor: 'winfw', w3cCols: cols, winfwUtc: !!utc,
    timestamp: ts && !isNaN(ts.getTime()) ? ts : null, timestampRaw: tsRaw,
    host: '', appName: 'Windows Firewall', procid: w.pid || '', msgid: '', severityRaw: act, severityNorm: act === 'DROP' ? 'Low' : 'Info',
    facility: null, facilityAuth: false,
    msg: `${act} ${fields.proto} ${fields.srcip || '-'}${fields.srcport ? ':' + fields.srcport : ''} -> ${fields.dstip || '-'}${fields.dstport ? ':' + fields.dstport : ''}${fields.direction ? ' ' + fields.direction : ''}`, fields
  };
}
// IIS W3C：回傳 null 表示文字中沒有 #Fields 指令（交給其他解析器）；欄位數不符的行交給逐行解析器
function parseW3CLogEvents(text) {
  if (!/^#Fields:/m.test(text)) return null;
  const events = [], unparsed = [];
  let cols = null, winfw = false, utc = false;
  text.split('\n').forEach((line, idx) => {
    if (!line.trim()) return;
    if (line.startsWith('#')) {
      const fm = line.match(/^#Fields:\s*(.+)$/);
      if (fm) cols = fm[1].trim().split(/\s+/);
      if (/^#Software:/.test(line)) winfw = /Microsoft Windows Firewall/i.test(line);
      if (/^#Time Format:/.test(line)) utc = /UTC/i.test(line);
      return;
    }
    if (winfw && cols) {
      const evt = winFwEvent(cols, line, idx + 1, utc);
      if (evt) events.push(evt); else unparsed.push({ lineNo: idx + 1, raw: line });
      return;
    }
    const parts = line.trim().split(' ');
    if (!cols || parts.length !== cols.length) {
      const evt = parseLogLine(line, idx + 1);
      if (evt) events.push(evt); else unparsed.push({ lineNo: idx + 1, raw: line });
      return;
    }
    const w = {};
    cols.forEach((c, i) => { w[c] = parts[i]; });
    const v = k => (w[k] && w[k] !== '-' ? w[k] : '');
    const fields = { ...w, srcip: v('c-ip'), method: v('cs-method'), status: v('sc-status'), bytes: v('sc-bytes') || '0',
      url: v('cs-uri-stem') + (v('cs-uri-query') ? '?' + v('cs-uri-query') : '') };
    if (v('s-ip')) fields.dstip = v('s-ip');
    if (v('s-port')) fields.dstport = v('s-port');
    if (v('cs-username')) fields.user = v('cs-username');
    if (v('cs(User-Agent)')) fields.ua = v('cs(User-Agent)').replace(/\+/g, ' ');
    // Origin／Host 標頭（XN78）：IIS 標準欄位 cs-host，自訂欄位常見寫法 cs(Origin)／Origin
    const w3cOrigin = v('cs(Origin)') || v('Origin') || v('origin');
    if (w3cOrigin) fields.origin = w3cOrigin;
    if (v('cs-host') || v('cs(Host)')) fields.vhost = v('cs-host') || v('cs(Host)');
    const tsRaw = [v('date'), v('time')].filter(Boolean).join(' ');
    const ts = v('date') && v('time') ? new Date(`${v('date')}T${v('time')}Z`) : null;
    const evt = webEvent('w3c', line, idx + 1, ts, tsRaw, v('s-computername'), fields);
    evt.w3cCols = cols;
    events.push(evt);
  });
  return events.length ? { events, unparsed } : null;
}
// Web 掃描：同一來源 IP 對大量不同路徑得到 404（路徑探測／目錄掃描的典型特徵）
const WEB_SCAN_MIN_404 = 10;
// Suricata 告警依 signature_id 彙整成問題（第十四輪 OG），等級取該特徵碼最嚴重的 severity
// Juniper IDP 的 threat-severity 換算成 Suricata 的 1～3（第十五輪 VF）；IDS 螢幕告警沒有等級，視為 2
const JUNOS_THREAT_SEV = { CRITICAL: 1, HIGH: 1, MAJOR: 1, MEDIUM: 2, MINOR: 3, LOW: 3, INFO: 3 };
function _idsAlertOf(e) {
  const f = e.fields || {};
  if (e.netVendor === 'suricata' && f.alert) return { key: 's:' + String(f.alert.signature_id || f.alert.signature || ''), sig: f.alert.signature_id || '-', name: f.alert.signature || '', sev: Number(f.alert.severity) || 3, src: f.src_ip, dst: f.dest_ip, dpt: f.dest_port };
  if (e.netVendor === 'amp' && (f.detection || /threat|malware|ioc|dropper|infect/i.test(f.ampType || ''))) return { key: 'a:' + (f.detection || f.ampType), sig: 'AMP', name: [f.ampType, f.detection].filter(Boolean).join(' '), sev: { Critical: 1, High: 1, Medium: 2, Low: 3 }[e.severityRaw] || 2, src: f.computer || f.srcip, dst: f.dstip, dpt: f.dstport };
  if (e.format === 'asa' && f.fpEvent === '430001' && f.signature) return { key: 'f:' + (f.sid || f.signature), sig: 'FTD ' + (f.sid || ''), name: f.signature, sev: Math.min(3, Number(f.priority) || 2), src: f.srcip, dst: f.dstip, dpt: f.dstport };
  if (e.netVendor === 'defender' && classifyByKeyword(e) === 'attack') return { key: 'd:' + f.title, sig: f.defType === 'm365' ? 'M365 Defender' : 'Defender', name: f.title + (f.category ? ' [' + f.category + ']' : ''), sev: { Critical: 1, High: 1, Medium: 2 }[e.severityNorm] || 3, src: f.computer || f.srcip, dst: '', dpt: '' };
  if (e.netVendor === 'falcon' && f.falconType === 'DetectionSummaryEvent') return { key: 'c:' + (f.detection || '') + '|' + (f.technique || ''), sig: 'Falcon', name: [f.detection, f.tactic, f.technique].filter(Boolean).join(' / '), sev: { Critical: 1, High: 1, Medium: 2 }[e.severityNorm] || 3, src: f.computer || f.srcip, dst: f.dstip, dpt: f.dstport };
  if (e.netVendor === 'zeek' && (f.zeekType === 'notice' || f.zeekType === 'intel')) return { key: 'z:' + (f.note || 'Intel ' + (f.indicator || '')), sig: f.zeekType === 'intel' ? 'Zeek Intel' : 'Zeek', name: f.note || ('Intel ' + (f.indicator || '')), sev: f.zeekType === 'intel' ? 1 : 2, src: f.srcip, dst: f.dstip, dpt: f.dstport };
  if (e.netVendor === 'paloalto' && f.logtype === 'THREAT' && PAN_IDS_SUBTYPES.has(f.subtype) && f.threat) return { key: 'p:' + (f.threatid || f.threat), sig: 'PAN-OS ' + (f.threatid || f.subtype), name: f.threat + ' [' + f.subtype + ']', sev: PAN_THREAT_SEV[String(f.threatsev || '').toLowerCase()] || 2, src: f.srcip, dst: f.dstip, dpt: f.dstport };
  if (e.netVendor === 'azfw' && f.threatIntel) return { key: 'az:' + f.threatIntel, sig: 'Azure Firewall TI', name: f.threatIntel, sev: 1, src: f.srcip, dst: f.fqdn || f.dstip, dpt: f.dstport };
  if (e.netVendor === 'fortimail' && f.virus) return { key: 'fml:' + f.virus, sig: 'FortiMail AV', name: f.virus + (f.from ? ' from ' + f.from : ''), sev: 1, src: f.srcip || '', dst: f.to || '', dpt: '' };
  if (e.netVendor === 'stormshield' && f.sns === 'alarm' && f.alarmClass && f.alarmClass !== 'system') return { key: 'sns:' + (f.alarmId || f.snsMsg), sig: 'Stormshield ' + (f.alarmId || ''), name: (f.snsMsg || '') + (f.action === 'deny' ? '' : ' [' + (f.action || 'not blocked') + ']'), sev: +f.pri <= 2 ? 1 : +f.pri <= 4 ? 2 : 3, src: f.srcip, dst: f.dstip, dpt: f.dstport || '' };
  if (e.netVendor === 'meraki' && f.alertName) return { key: 'mk:' + (f.signature || f.alertName), sig: 'Meraki IDS ' + (f.signature || ''), name: f.alertName + (/blocked/i.test(f.decision || '') ? '' : ' [' + (f.decision || 'allowed') + ']'), sev: Math.min(3, Number(f.priority) || 2), src: f.srcip, dst: f.dstip, dpt: f.dstport || '' };
  if (e.netVendor === 'meraki' && /malicious/i.test(f.disposition || '')) return { key: 'mka:' + (f.sha256 || f.fileName), sig: 'Meraki AMP', name: (f.fileName || f.sha256) + ' [' + (f.decision || '-') + ']', sev: 1, src: f.srcip || '', dst: f.dstip || '', dpt: f.dstport || '' };
  if (e.netVendor === 'meraki' && f.merakiEvent === 'ssid_spoofing_detected') return { key: 'mks:' + (f.ssid || '') + '|' + (f.bssid || ''), sig: 'Meraki Air Marshal', name: 'SSID spoofing ' + (f.ssid || '') + ' (' + (f.bssid || '-') + ')', sev: 2, src: f.bssid || '', dst: e.host || '', dpt: '' };
  if (e.netVendor === 'f5' && f.asmAttack) return { key: 'f5:' + f.asmAttack + '|' + (f.asmViolations || ''), sig: 'F5 ASM', name: [f.asmAttack, f.asmViolations !== f.asmAttack ? f.asmViolations : '', f.asmSigs].filter(Boolean).join(' / ') + (/^blocked$/i.test(f.asmStatus || '') ? '' : ' [' + (f.asmStatus || 'not blocked') + ']'),
    sev: /^Critical$/i.test(f.asmSev || '') ? 1 : /^(?:Error|Warning)$/i.test(f.asmSev || '') ? 2 : 3, src: f.srcip, dst: f.domain || f.vs || '', dpt: '' };
  if (e.netVendor === 'modsec' && f.waf && f.waf.length) { const r = f.waf.slice().sort((a, b) => (a.sev ?? 9) - (b.sev ?? 9))[0];
    return { key: 'm:' + r.id, sig: 'ModSecurity ' + r.id, name: (r.msg || r.id) + (f.wafBlocked ? '' : ' [not blocked]'), sev: r.sev === undefined ? 2 : r.sev <= 2 ? 1 : r.sev <= 4 ? 2 : 3, src: f.srcip, dst: f.domain, dpt: '' }; }
  if (e.netVendor === 'zscaler' && f.threat) return { key: 'zs:' + f.threat, sig: 'Zscaler', name: f.threat + (f.threatcat ? ' [' + f.threatcat + ']' : ''), sev: zsThreatSev(f.threatsev), src: f.srcip, dst: f.domain || f.dstip, dpt: f.dstport };
  if (e.netVendor === 'watchguard' && f.signature_name) return { key: 'w:' + (f.signature_id || f.signature_name), sig: 'WatchGuard IPS ' + (f.signature_id || ''), name: f.signature_name, sev: 2, src: f.srcip, dst: f.dstip, dpt: f.dstport };
  if (e.netVendor === 'junos' && (f.jsec === 'idp' || f.jsec === 'ids') && f.attack) return { key: 'j:' + f.attack, sig: f.jsec.toUpperCase(), name: f.attack, sev: JUNOS_THREAT_SEV[String(f.threatsev || '').toUpperCase()] || 2, src: f.srcip, dst: f.dstip, dpt: f.dstport };
  return null;
}
function detectIdsAlerts(events) {
  const bySig = new Map();
  events.forEach(e => {
    const a = _idsAlertOf(e);
    if (!a) return;
    if (!bySig.has(a.key)) bySig.set(a.key, { a, events: [], hosts: new Set(), sev: 9 });
    const g = bySig.get(a.key);
    g.events.push(e);
    if (a.src) g.hosts.add(a.src);
    g.sev = Math.min(g.sev, a.sev);
  });
  const issues = [];
  for (const [, g] of bySig) {
    const ts = g.events.map(e => e.timestamp).filter(Boolean).sort((x, y) => x - y);
    issues.push({
      category: 'idsAlert', severityNorm: SURICATA_SEV[g.sev] || 'Low', count: g.events.length,
      firstSeen: ts[0] || null, lastSeen: ts[ts.length - 1] || null,
      sampleRaw: `[${g.a.sig}] ${g.a.name} ${g.a.src || ''} -> ${g.a.dst || ''}${g.a.dpt ? ':' + g.a.dpt : ''}`.trim(),
      relatedHosts: [...g.hosts], relatedEvents: g.events, confidence: 'confirmed',
      cves: [...new Set((String(g.a.name || '').match(CVE_ID_RE) || []).map(c => c.toUpperCase()))]
    });
  }
  return issues;
}
// ── 已知漏洞利用嘗試（2026-10-24，XN17）──
// web 存取紀錄（Apache／Nginx／IIS／HAProxy／ELB／Cloudflare 等有 url 欄位者）比對公開漏洞的利用請求樣式。
// 每條樣式的請求路徑依 projectdiscovery/nuclei-templates 對應 CVE 範本（http/cves/<年>/<CVE>.yaml），CVE 皆在 CISA KEV
// （已知遭利用漏洞，2026-10-23 版核對）。只靠 Cookie／Host 等標頭才看得出的利用（例如 PAN-OS CVE-2024-3400、
// Citrix Bleed）存取紀錄看不到，不收。比對原始 URL 與解碼一次、兩次的結果（雙重編碼繞過）。
// name 用產品名稱（不分語言）；ua：需同時符合 User-Agent 的樣式
const EXPLOIT_SIGS = [
  { id: 'php-cgi-4577', name: 'PHP-CGI', cve: ['CVE-2024-4577'], re: /(?:%ad|\xad)[ds](?:\+|%20|\s)*[a-z_.]+(?:%3d|=)/i },
  { id: 'php-cgi-1823', name: 'PHP-CGI', cve: ['CVE-2012-1823'], re: /\?-[ds](?:\+|%20|\s)+(?:allow_url_include|auto_prepend_file|cgi\.force_redirect|safe_mode|disable_functions|open_basedir)/i },
  { id: 'phpunit', name: 'PHPUnit eval-stdin', cve: ['CVE-2017-9841'], re: /\/phpunit\/(?:[\w.-]+\/)*util\/php\/eval-stdin\.php/i },
  { id: 'thinkphp', name: 'ThinkPHP', cve: ['CVE-2018-20062', 'CVE-2019-9082'], re: /\\{1,2}think\\{1,2}(?:app|container)\/invokefunction|invokefunction&function=call_user_func_array/i },
  { id: 'log4shell', name: 'Log4j (Log4Shell)', cve: ['CVE-2021-44228'], re: /\$\{\s*jndi\s*:|\$\{(?:\$\{(?:lower|upper|::-|env:[^}]*:-)[^}]*\})+[^}]*:/i, field: 'any' },
  { id: 'spring4shell', name: 'Spring Framework (Spring4Shell)', cve: ['CVE-2022-22965'], re: /class\.module\.classloader/i },
  { id: 'apache-traversal', name: 'Apache HTTP Server', cve: ['CVE-2021-41773', 'CVE-2021-42013'], re: /\/(?:icons|cgi-bin)\/(?:[^/?\s]*\/)*?(?:\.%2e|%2e%2e|%2e\.|%%32%65|\.%%32%65)/i, raw: true },
  { id: 'fortios-sslvpn-traversal', name: 'FortiOS SSL-VPN', cve: ['CVE-2018-13379'], re: /\/remote\/fgt_lang\?lang=[^&\s]*\.\./i },
  { id: 'ivanti-ics', name: 'Ivanti Connect Secure', cve: ['CVE-2023-46805', 'CVE-2024-21887'], re: /\/api\/v1\/(?:totp\/user-backup-code|cav\/client\/status)\/\.\.\//i },
  { id: 'citrix-traversal', name: 'Citrix ADC/Gateway', cve: ['CVE-2019-19781'], re: /\/vpns?\/\.\.\/vpns\//i },
  { id: 'f5-icontrol-bash', name: 'F5 BIG-IP iControl REST', cve: ['CVE-2022-1388', 'CVE-2021-22986'], re: /\/mgmt\/tm\/util\/bash\b/i },
  { id: 'f5-tmui', name: 'F5 BIG-IP TMUI', cve: ['CVE-2020-5902'], re: /\/tmui\/login\.jsp\/\.\.;\//i },
  { id: 'proxyshell', name: 'Microsoft Exchange (ProxyShell)', cve: ['CVE-2021-34473'], re: /\/autodiscover\/autodiscover\.json\?[^\s]*@/i },
  { id: 'confluence-ognl', name: 'Atlassian Confluence', cve: ['CVE-2022-26134'], re: /\$\{[^}]*(?:@java\.lang\.|getRuntime|ProcessBuilder|#[a-z_]+\s*=)/i },
  { id: 'confluence-setup', name: 'Atlassian Confluence', cve: ['CVE-2023-22515'], re: /server-info\.action\?bootstrapStatusProvider\.applicationConfig\.setupComplete/i },
  { id: 'moveit', name: 'MOVEit Transfer', cve: ['CVE-2023-34362'], re: /\/moveitisapi\/moveitisapi\.dll\?action=m2/i },
  { id: 'asa-traversal', name: 'Cisco ASA/FTD', cve: ['CVE-2020-3452'], re: /\/\+CSCOT\+\/(?:translation-table|oem-customization)\?[^\s]*\.\./i },
  { id: 'fortios-auth-bypass', name: 'FortiOS', cve: ['CVE-2022-40684'], re: /\/api\/v2\/cmdb\/system\/admin\b/i, ua: /^(?:Report Runner|Node\.js)$/i },
  { id: 'iosxe-webui', name: 'Cisco IOS XE Web UI', cve: ['CVE-2023-20198'], re: /\/(?:%2577eb%2575i|%77eb%75i)_(?:%2577|%77)sma_https?\b/i, raw: true },
  { id: 'junos-phprc', name: 'Juniper J-Web', cve: ['CVE-2023-36845'], re: /[?&]PHPRC=/i },
  // ── 2025～2026 KEV（XN60，2026-10-30 依 nuclei-templates 與 KEV 2026.10.28 版核對）：只收 URL 本身看得出利用的樣式 ──
  { id: 'panos-unauth-traversal', name: 'PAN-OS', cve: ['CVE-2025-0108'], re: /\/unauth\/(?:[^/?\s]*\/)*\.\.\/(?:[^?\s]*\/)?php\//i },
  { id: 'asa-webvpn-traversal', name: 'Cisco ASA/FTD WebVPN', cve: ['CVE-2025-20362'], re: /\/\+CSCOU\+\/+\.\.\/\+CSCOE\+\/files\/file_action\.html/i },
  { id: 'fortiweb-fwbcgi', name: 'FortiWeb', cve: ['CVE-2025-64446'], re: /\/api\/v2\.0\/cmdb\/[^\s]*\.\.\/[^\s]*cgi-bin\/fwbcgi/i },
  { id: 'unifi-validate-sso', name: 'UniFi OS', cve: ['CVE-2026-34908', 'CVE-2026-34910'], re: /\/api\/auth\/validate-sso\/(?:\.\.\/)+proxy\//i },
  { id: 'fortisandbox-jid', name: 'FortiSandbox', cve: ['CVE-2026-39808'], re: /\/job-detail\/tracer-behavior\?(?:[^\s]*&)?jid=[^&\s]*(?:[|;`]|\$\()/i },
  { id: 'ivanti-epmm-el', name: 'Ivanti EPMM', cve: ['CVE-2025-4427'], re: /\/api\/v2\/featureusage(?:_history)?\?(?:[^\s]*&)?format=[^&\s]*\$\{/i },
  { id: 'sharepoint-toolshell', name: 'Microsoft SharePoint (ToolShell)', cve: ['CVE-2025-49706', 'CVE-2025-53770'], re: /\/_layouts\/1[56]\/ToolPane\.aspx\/?\?(?=[^\s]*DisplayMode=Edit)(?=[^\s]*[?&]a=\/ToolPane\.aspx)/i },
  { id: 'sap-metadatauploader', name: 'SAP NetWeaver Visual Composer', cve: ['CVE-2025-31324'], re: /\/developmentserver\/metadatauploader\b/i },
  { id: 'xwiki-solr-groovy', name: 'XWiki', cve: ['CVE-2025-24893'], re: /\/SolrSearch\?.*\{\{(?:groovy|python)\}\}/i },
  { id: 'freepbx-endpoint-sqli', name: 'FreePBX', cve: ['CVE-2025-57819'], re: /\/admin\/ajax\.php\?(?=[^\s]*module=FreePBX\\modules\\endpoint\\ajax)[^\s]*=[^&\s]*'/i },
  { id: 'freepbx-filestore-cmd', name: 'FreePBX', cve: ['CVE-2025-64328'], re: /\/admin\/ajax\.php\?(?=[^\s]*module=filestore)(?=[^\s]*command=testconnection)[^\s]*`/i },
  { id: 'oracle-ebs-traversal', name: 'Oracle E-Business Suite', cve: ['CVE-2025-61882'], re: /\/OA_HTML\/[^\s?]*\.\.\/ieshostedsurvey\.jsp/i },
  { id: 'vite-fs', name: 'Vite', cve: ['CVE-2025-31125'], re: /\/@fs\/[^\s]*\?import&\?inline=1\.wasm\?init/i },
  { id: 'gladinet-tdn', name: 'Gladinet CentreStack/Triofox', cve: ['CVE-2025-11371'], re: /\/storage\/t\.dn\?(?:[^\s]*&)?s=(?:\.\.[\\/])+/i },
  { id: 'magicinfo-upload', name: 'Samsung MagicINFO', cve: ['CVE-2025-4632'], re: /\/SWUpdateFileUploader\?(?:[^\s]*&)?fileName=[^&\s]*\.\.[\\/]/i },
  { id: 'atlassian-resources-traversal', name: 'Atlassian (Jira/Confluence/Bitbucket)', cve: ['CVE-2026-21589'], re: /\/download\/resources\/[^\s]*\.\.::\.\.::/i },
  { id: 'goanywhere-license', name: 'GoAnywhere MFT', cve: ['CVE-2025-10035'], re: /\/license\/Unlicensed\.xhtml\/[^\s?/]+\?[^\s]*GARequestAction=activate/i },
  { id: 'collabora-proxy-cmd', name: 'Collabora Online (CODE)', cve: ['CVE-2026-110447'], re: /\$\([^)]*\)[^\s]*\/apps\/richdocumentscode(?:_arm64)?\/proxy\.php/i },
  { id: 'meteobridge-template', name: 'Meteobridge', cve: ['CVE-2025-4008'], re: /\/public\/template\.cgi\?(?:[^\s]*&)?templatefile=[^&\s]*(?:\$\(|[`;|])/i },
];
const EXPLOIT_SIG_IDS = new Set(EXPLOIT_SIGS.map(s => s.id));
// %XX 逐一換成字元（不經 UTF-8 解碼，%AD 這類單一位元組也保留），不會因無效編碼拋錯
const exploitDecode = s => String(s || '').replace(/%([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)));
function exploitSigsOf(e) {
  const f = e.fields || {};
  const raw = String(f.url || ''), d1 = exploitDecode(raw), d2 = exploitDecode(d1), ua = String(f.ua || '');
  return EXPLOIT_SIGS.filter(s => {
    const hitUrl = s.raw ? s.re.test(raw) : (s.re.test(raw) || s.re.test(d1) || s.re.test(d2));
    if (s.ua) return hitUrl && s.ua.test(ua.trim());
    return hitUrl || (s.field === 'any' && (s.re.test(ua) || s.re.test(exploitDecode(ua))));
  });
}
// Appsmith 帳號接管（XN78）：CVE-2026-22794——1.93 前的忘記密碼與驗證信以請求的 Origin 標頭組連結網址，攻擊者改 Origin
// 就能把重設 token 導到自己的網域。路徑依 Appsmith 原始碼 UserControllerCE（Url.USER_URL＝/api/v1/users）：
// POST forgotPassword、POST resendEmailVerification、PUT resetPassword；管理 API 在 /api/v1/admin/
// (1) 有 Origin 欄位時：Origin 主機與本站（Host 欄位，沒有則取同一份 log 其他 Appsmith API 請求最常見的 Origin）不同 → appsmithOriginReset
// (2) 不需 Origin：外部位址申請重設後 1 小時內同位址改密碼成功 → appsmithResetFlow（之後 30 分鐘內打管理 API 升 High）；
//     同位址 1 小時內申請重設 ≥5 次 → appsmithResetBurst。正常使用者也可能這樣操作，皆列為需人工確認
const APPSMITH_RESET_REQ_RE = /\/api\/v1\/users\/(?:forgotPassword|resendEmailVerification)(?:[?#]|$)/;
const APPSMITH_RESET_DONE_RE = /\/api\/v1\/users\/resetPassword(?:[?#]|$)/;
const APPSMITH_ADMIN_RE = /\/api\/v1\/admin\//;
const APPSMITH_API_RE = /\/api\/v1\//;
const APPSMITH_FLOW_MS = 60 * 60 * 1000, APPSMITH_ADMIN_MS = 30 * 60 * 1000, APPSMITH_BURST_MS = 60 * 60 * 1000, APPSMITH_BURST_MIN = 5;
const APPSMITH_CVE = 'CVE-2026-22794';
// 有 Appsmith 問題時建議再匯入的 log（comp.*）：CI 主機登入、對外連線，GitLab 與資料庫稽核本工具不分析但需保全
const APPSMITH_COMPANIONS = ['ssh', 'firewall', 'gitlab', 'dbAudit'];
function urlHostOf(u) { const m = String(u || '').match(/^[a-z][\w+.-]*:\/\/([^\/:?#\s"]+)/i); return m ? m[1].toLowerCase() : ''; }
function isWebEvent(e) { return !!(e.fields && e.fields.url) && (e.netVendor === 'web' || e.netVendor === 'haproxy' || e.netVendor === 'cloudflare' || e.format === 'weblog' || e.format === 'w3c'); }
function detectAppsmithReset(events) {
  const web = events.filter(e => isWebEvent(e) && APPSMITH_API_RE.test(e.fields.url)).sort((a, b) => effectiveTime(a) - effectiveTime(b));
  const ok = e => /^2\d\d$/.test(String(e.fields.status || ''));
  const isReq = e => APPSMITH_RESET_REQ_RE.test(e.fields.url), isDone = e => APPSMITH_RESET_DONE_RE.test(e.fields.url);
  const tsOf = list => { const t = list.map(e => e.timestamp).filter(Boolean); return [t[0] || null, t[t.length - 1] || null]; };
  const issues = [];
  // (1) Origin 與本站不同
  const cnt = new Map();
  web.forEach(e => { if (!isReq(e)) { const h = urlHostOf(e.fields.origin); if (h) cnt.set(h, (cnt.get(h) || 0) + 1); } });
  const usual = [...cnt.entries()].sort((a, b) => b[1] - a[1]).map(x => x[0])[0] || '';
  const bad = new Map();
  web.forEach(e => {
    const f = e.fields; if (!isReq(e)) return;
    const oh = urlHostOf(f.origin), site = String(f.vhost || '').replace(/:\d+$/, '').toLowerCase() || usual;
    if (!oh || !site || oh === site) return;
    const k = (f.srcip || '-') + '|' + oh;
    if (!bad.has(k)) bad.set(k, { src: f.srcip || '-', origin: oh, site, list: [] });
    bad.get(k).list.push(e);
  });
  for (const g of bad.values()) {
    const n2 = g.list.filter(ok).length, [first, last] = tsOf(g.list);
    issues.push({
      category: 'appsmithOriginReset', severityNorm: n2 ? 'High' : 'Medium', count: g.list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.appsmithOriginReset', { src: g.src, n: g.list.length, ok: n2, origin: g.origin, site: g.site }),
      relatedHosts: [g.src, g.origin].filter(x => x && x !== '-'), relatedEvents: g.list, confidence: 'heuristic',
      cves: [APPSMITH_CVE], appsmithOrigin: g.origin, appsmithSite: g.site, companions: APPSMITH_COMPANIONS
    });
  }
  // (2) 依來源位址看申請重設 → 改密碼 → 管理 API
  const bySrc = new Map();
  web.forEach(e => { const s = e.fields.srcip; if (!s) return; if (!bySrc.has(s)) bySrc.set(s, []); bySrc.get(s).push(e); });
  for (const [src, list] of bySrc) {
    const reqs = list.filter(isReq);
    if (!reqs.length) continue;
    if (!iocIsInternalIP(src)) {
      const done = list.filter(e => isDone(e) && ok(e) && reqs.some(r => effectiveTime(r) <= effectiveTime(e) && effectiveTime(e) - effectiveTime(r) <= APPSMITH_FLOW_MS));
      if (done.length) {
        const t0 = effectiveTime(done[0]);
        const admin = list.filter(e => APPSMITH_ADMIN_RE.test(e.fields.url) && effectiveTime(e) >= t0 && effectiveTime(e) - t0 <= APPSMITH_ADMIN_MS);
        const rel = list.filter(e => reqs.includes(e) || done.includes(e) || admin.includes(e)), [first, last] = tsOf(rel);
        issues.push({
          category: 'appsmithResetFlow', severityNorm: admin.length ? 'High' : 'Medium', count: done.length, firstSeen: first, lastSeen: last,
          ...sampleOf(admin.length ? 'sample.appsmithResetFlowAdmin' : 'sample.appsmithResetFlow', { src, req: reqs.length, done: done.length, admin: admin.length }),
          relatedHosts: [src], relatedEvents: rel, confidence: 'heuristic', companions: APPSMITH_COMPANIONS
        });
      }
    }
    let best = null;
    for (let i = 0, j = 0; j < reqs.length; j++) {
      while (effectiveTime(reqs[j]) - effectiveTime(reqs[i]) > APPSMITH_BURST_MS) i++;
      if (j - i + 1 >= APPSMITH_BURST_MIN && (!best || j - i + 1 > best.length)) best = reqs.slice(i, j + 1);
    }
    if (best) {
      const [first, last] = tsOf(best);
      issues.push({
        category: 'appsmithResetBurst', severityNorm: 'Medium', count: best.length, firstSeen: first, lastSeen: last,
        ...sampleOf('sample.appsmithResetBurst', { src, n: best.length }),
        relatedHosts: [src], relatedEvents: best, confidence: 'heuristic', companions: APPSMITH_COMPANIONS
      });
    }
  }
  return issues;
}
// Appsmith 入侵線索（XN79，不依特定漏洞）：未修補的內部 Appsmith 被當成入口、再往 CI 主機與 GitLab 移動的事件裡，
// 攻擊工具多半直接呼叫 API。路徑依 Appsmith 原始碼 UrlCE 與各 ControllerCE。只看建立／修改資料來源、查詢、管理設定、
// 匯入與 Git 金鑰這類高風險操作（APPSMITH_RISKY），不看一般使用者也會呼叫的 /actions/execute
const APPSMITH_PATH_RE = /\/api\/v1\/(?:datasources|actions|admin|applications\/(?:import|ssh-keypair)|git|consolidated-api|users\/me)(?:[\/?#]|$)/;
const APPSMITH_UI_RE = /\/api\/v1\/(?:consolidated-api|users\/me)(?:[\/?#]|$)/;
const APPSMITH_RISKY = [
  ['datasource', /^(POST|PUT)$/, /\/api\/v1\/datasources(?:\/(?:test|[^\/?#]+(?:\/trigger)?))?(?:[?#]|$)/],
  ['query', /^(POST|PUT)$/, /\/api\/v1\/actions(?:\/(?!execute|move|refactor|view|runBehaviour|executeOnLoad)[^\/?#]+)?(?:[?#]|$)/],
  ['adminEnv', /^(GET|PUT|POST)$/, /\/api\/v1\/admin\/(?:env|restart)(?:[\/?#]|$)/],
  ['appImport', /^POST$/, /\/api\/v1\/applications\/import\//],
  ['gitKey', /^(GET|POST|PUT)$/, /\/api\/v1\/(?:applications\/ssh-keypair\/|git\/)/],
];
const APPSMITH_TOOL_UA = /python-requests|python-httpx|aiohttp|go-http-client|^curl\/|node-fetch|axios\/|okhttp|^java\/|libwww-perl|python-urllib/i;
function appsmithRiskOf(e) {
  const m = String(e.fields.method || '').toUpperCase(), u = e.fields.url;
  const hit = APPSMITH_RISKY.find(([, mr, ur]) => mr.test(m) && ur.test(u));
  return hit ? hit[0] : '';
}
function detectAppsmithIntrusion(events) {
  const web = events.filter(e => isWebEvent(e) && e.fields.srcip && APPSMITH_PATH_RE.test(e.fields.url)).sort((a, b) => effectiveTime(a) - effectiveTime(b));
  const ok = e => /^2\d\d$/.test(String(e.fields.status || ''));
  const tsOf = list => { const t = list.map(e => e.timestamp).filter(Boolean); return [t[0] || null, t[t.length - 1] || null]; };
  const bySrc = new Map();
  web.forEach(e => { const s = e.fields.srcip; if (!bySrc.has(s)) bySrc.set(s, []); bySrc.get(s).push(e); });
  const issues = [], extOk = [];
  for (const [src, list] of bySrc) {
    const ext = !iocIsInternalIP(src);
    if (ext && list.some(ok)) extOk.push(src);
    const risky = list.filter(e => appsmithRiskOf(e));
    if (!risky.length) continue;
    const kinds = [...new Set(risky.map(appsmithRiskOf))], n2 = risky.filter(ok).length, [first, last] = tsOf(risky);
    const base = { count: risky.length, firstSeen: first, lastSeen: last, relatedHosts: [src], relatedEvents: risky, confidence: 'heuristic',
      appsmithKinds: kinds, companions: APPSMITH_COMPANIONS };
    const p = { src, n: risky.length, ok: n2, kinds: kinds.join(', ') };
    if (ext) {
      issues.push({ category: 'appsmithExternalRisky', severityNorm: n2 ? 'High' : 'Medium', ...base, ...sampleOf('sample.appsmithExternalRisky', p) });
      continue;
    }
    // 只打 API：同來源沒有一般網頁會呼叫的 consolidated-api／users/me，或 User-Agent 是程式庫
    const ua = (risky.find(e => APPSMITH_TOOL_UA.test(e.fields.ua || '')) || {}).fields;
    const noUi = !list.some(e => APPSMITH_UI_RE.test(e.fields.url));
    if (!ua && !noUi) continue;
    issues.push({ category: 'appsmithScriptedApi', severityNorm: n2 ? 'High' : 'Medium', ...base, appsmithUa: ua ? ua.ua : '',
      ...sampleOf(ua ? 'sample.appsmithScriptedUa' : 'sample.appsmithScriptedNoUi', { ...p, ua: ua ? ua.ua : '' }) });
  }
  if (extOk.length) {
    const ev = web.filter(e => extOk.includes(e.fields.srcip) && ok(e)), [first, last] = tsOf(ev);
    issues.push({ category: 'appsmithExposed', severityNorm: 'Medium', count: ev.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.appsmithExposed', { n: extOk.length, srcs: extOk.slice(0, 5).join(', ') }),
      relatedHosts: extOk.slice(0, 5), relatedEvents: ev.slice(0, 200), confidence: 'heuristic', appsmithSrcs: extOk.slice(0, 5).join(', '), companions: APPSMITH_COMPANIONS });
  }
  return issues;
}
// 憑證／密鑰外洩跡象（XN80）：只用查證過的路徑、事件名稱與 log 格式，全部為需人工確認
// (1) web 下載密鑰檔：路徑依 nuclei-templates http/exposures（laravel-env、git-config、git-credentials-disclosure、aws-credentials、htpasswd-detection），
//     只列 2xx 且回應位元組大於 0（檔案確實被讀走）；.env.example 是範本檔不算；404／403 交給 Web 路徑探測
const CRED_FILE_RE = /\/(\.env(?:\.(?!example\b)[\w.-]+)?|\.git\/config|\.git-credentials|\.aws\/credentials|\.htpasswd)(?:[?#]|$)/;
// (2) 雲端機密讀取：CloudTrail Secrets Manager 與 SSM（WithDecryption），GCP Secret Manager（DATA_READ 稽核，預設未開啟）
const SECRET_READ_CT = new Set(['GetSecretValue', 'BatchGetSecretValue']);
const SECRET_READ_SSM = new Set(['GetParameter', 'GetParameters', 'GetParametersByPath']);
const SECRET_BULK_MS = 60 * 60 * 1000, SECRET_BULK_MIN = 5;
// (3) 同一把 AWS 長期金鑰（AKIA）24 小時內 ≥3 個 IP 且含外部位址；(5) 同一 SSH 金鑰指紋同條件
const KEY_MULTI_MS = 24 * 60 * 60 * 1000, KEY_MULTI_MIN = 3;
// (4) Entra 應用程式被加上憑證或密碼：activity 名稱依 SigmaHQ azure_app_credential_added 與 Microsoft 稽核活動名稱（en dash 與連字號皆接受）
const APP_CRED_ACTIVITY_RE = /^(?:Add service principal credentials|Update application [–-] Certificates and secrets management)$/i;
const CRED_COMP_WEB = ['fileAudit', 'gitlab'], CRED_COMP_CLOUD = ['cloudAudit'], CRED_COMP_SSH = ['journal'];
function secretReadOf(e) {
  // Vault（XN117）：kv 掛載點的讀取成功（KV v2 路徑含 data/，去掉後為機密名稱）
  if (e.netVendor === 'vault') {
    const f = e.fields || {};
    if (f.vault !== 'response' || f.error || f.op !== 'read' || f.mount !== 'kv') return null;
    return { who: f.user || '', ip: f.srcip || '', names: [String(f.path).replace(/^([^\/]+)\/data\//, '$1/')] };
  }
  const o = e.cloudRaw; if (!o) return null;
  const ci = cloudAuthInfo(o); if (!ci || !ci.ok) return null;
  if (ci.vendor === 'cloudtrail') {
    const rp = o.requestParameters || {};
    if (SECRET_READ_CT.has(o.eventName)) return { who: ci.user, ip: ci.ip, names: [].concat(rp.secretId || rp.secretIdList || rp.filters || '-').map(String) };
    if (SECRET_READ_SSM.has(o.eventName) && rp.withDecryption === true) return { who: ci.user, ip: ci.ip, names: [].concat(rp.name || rp.names || rp.path || '-').map(String) };
  }
  if (ci.vendor === 'gcpaudit' && /SecretManagerService\.AccessSecretVersion$/.test(ci.event)) {
    const rn = (o.protoPayload && (o.protoPayload.resourceName || (o.protoPayload.request || {}).name)) || '-';
    return { who: ci.user, ip: ci.ip, names: [String(rn).replace(/\/versions\/[^\/]+$/, '')] };
  }
  return null;
}
// 同一把金鑰在視窗內的不同來源位址；回傳最多來源的那個視窗
function multiSourceWindow(list) {
  const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
  let best = null;
  for (let i = 0, j = 0; j < sorted.length; j++) {
    while (effectiveTime(sorted[j]) - effectiveTime(sorted[i]) > KEY_MULTI_MS) i++;
    const win = sorted.slice(i, j + 1), ips = [...new Set(win.map(e => e._ip))];
    if (ips.length >= KEY_MULTI_MIN && ips.some(ip => !iocIsInternalIP(ip)) && (!best || ips.length > best.ips.length)) best = { win, ips };
  }
  return best;
}
// webshell 存取跡象（XN96，不依特定 CVE），全部為需人工確認、T1505.003：
// webshellCmd：GET 查詢字串帶系統指令（關鍵字依 SigmaHQ web_win_webshells_in_access_logs），或 POST、沒有 Referer 與 User-Agent
//   且查詢字串為 reGeorg 通道參數（依 SigmaHQ web_webshell_regeorg）；2xx 為 High
// webshellUpload：上傳／靜態檔目錄（WordPress wp-content/uploads、Magento pub/media 等）下的可執行腳本回 2xx（High），
//   這些目錄正常只放圖片與附件，不應執行程式
// webshellNewScript：同一個腳本只被 1～2 個來源以 POST 存取 ≥ WEBSHELL_POST_MIN 次且都成功、沒有其他來源以 GET 開過，
//   常見程式進入點（index.php、wp-login.php、xmlrpc.php 等）除外（Medium）
const WEBSHELL_CMD_KW = ['=whoami', '=net%20user', '=net+user', '=net%2Buser', '=cmd%20/c%', '=cmd+/c+', '=cmd%2B/c%', '=cmd%20/r%', '=cmd+/r+', '=cmd%2B/r%',
  '=cmd%20/k%', '=cmd+/k+', '=cmd%2B/k%', '=powershell%', '=powershell+', '=tasklist%', '=tasklist+', '=wmic%', '=wmic+', '=ssh%', '=ssh+', '=python%', '=python+',
  '=python3%', '=python3+', '=ipconfig', '=wget%', '=wget+', '=curl%', '=curl+', '=certutil', '=copy%20%5C%5C', '=dsquery%', '=dsquery+', '=nltest%', '=nltest+'];
const WEBSHELL_REGEORG_KW = ['cmd=read', 'connect&target', 'cmd=connect', 'cmd=disconnect', 'cmd=forward'];
const WEBSHELL_SCRIPT_RE = /\.(?:php[3-8]?|phtml|phar|jspx?|aspx?|ashx|cfm)$/i;
const WEBSHELL_UPLOAD_DIR_RE = /\/(?:wp-content\/uploads|pub\/media|media\/catalog|media\/wysiwyg|uploads?|images?|img|static|assets|files|attachments?)\//i;
const WEBSHELL_ENTRY_RE = /\/(?:index|wp-login|wp-cron|xmlrpc|admin-ajax|wp-comments-post|login|default)\.(?:php|aspx?|jsp)$/i;
const WEBSHELL_POST_MIN = 5;
const WEBSHELL_COMPANIONS = ['fileAudit', 'edr'];
function detectWebshell(events) {
  const issues = [];
  const tsOf = list => { const t = list.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b); return [t[0] || null, t[t.length - 1] || null]; };
  const ok = e => /^2\d\d$/.test(String(e.fields.status || ''));
  const pathOf = u => String(u || '').split('?')[0];
  const queryOf = u => { const i = String(u || '').indexOf('?'); return i < 0 ? '' : String(u).slice(i + 1); };
  const empty = v => !v || v === '-' || v === '""';
  const web = events.filter(isWebEvent);
  const group = (list, keyFn) => { const m = new Map(); list.forEach(e => { const k = keyFn(e); if (!m.has(k)) m.set(k, []); m.get(k).push(e); }); return m; };
  // (1) 查詢字串帶系統指令或 reGeorg 通道參數
  const cmd = web.filter(e => {
    const f = e.fields, q = '?' + queryOf(f.url), m = String(f.method || '').toUpperCase();
    if (m === 'GET' && WEBSHELL_CMD_KW.some(k => q.includes(k))) return true;
    return m === 'POST' && empty(f.referer) && empty(f.ua) && WEBSHELL_REGEORG_KW.some(k => q.includes(k));
  });
  for (const [path, list] of group(cmd, e => pathOf(e.fields.url))) {
    const [first, last] = tsOf(list), srcs = [...new Set(list.map(e => e.fields.srcip).filter(Boolean))];
    issues.push({ category: 'webshellCmd', severityNorm: list.some(ok) ? 'High' : 'Medium', count: list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.webshellCmd', { path, n: list.length, srcs: srcs.slice(0, 3).join(', ') || '-' }),
      relatedHosts: srcs.slice(0, 3), relatedEvents: list, confidence: 'heuristic', companions: WEBSHELL_COMPANIONS });
  }
  // (2) 上傳／靜態檔目錄下的腳本被成功執行
  const up = web.filter(e => { const p = pathOf(e.fields.url); return ok(e) && WEBSHELL_SCRIPT_RE.test(p) && WEBSHELL_UPLOAD_DIR_RE.test(p); });
  for (const [path, list] of group(up, e => pathOf(e.fields.url))) {
    const [first, last] = tsOf(list), srcs = [...new Set(list.map(e => e.fields.srcip).filter(Boolean))];
    issues.push({ category: 'webshellUpload', severityNorm: 'High', count: list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.webshellUpload', { path, n: list.length, srcs: srcs.slice(0, 3).join(', ') || '-' }),
      relatedHosts: srcs.slice(0, 3), relatedEvents: list, confidence: 'heuristic', companions: WEBSHELL_COMPANIONS });
  }
  // (3) 只被少數來源以 POST 使用的腳本（已列在 (1)(2) 的路徑不重複）
  const listed = new Set(issues.map(i => pathOf(i.relatedEvents[0].fields.url)));
  for (const [path, list] of group(web.filter(e => WEBSHELL_SCRIPT_RE.test(pathOf(e.fields.url))), e => pathOf(e.fields.url))) {
    if (listed.has(path) || WEBSHELL_ENTRY_RE.test(path)) continue;
    const posts = list.filter(e => String(e.fields.method || '').toUpperCase() === 'POST');
    const srcs = [...new Set(posts.map(e => e.fields.srcip).filter(Boolean))];
    const otherGet = list.some(e => String(e.fields.method || '').toUpperCase() === 'GET' && !srcs.includes(e.fields.srcip));
    if (posts.length < WEBSHELL_POST_MIN || !posts.every(ok) || srcs.length < 1 || srcs.length > 2 || otherGet) continue;
    const [first, last] = tsOf(posts);
    issues.push({ category: 'webshellNewScript', severityNorm: 'Medium', count: posts.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.webshellNewScript', { path, n: posts.length, srcs: srcs.join(', ') }),
      relatedHosts: srcs, relatedEvents: posts, confidence: 'heuristic', companions: WEBSHELL_COMPANIONS });
  }
  return issues;
}
// VMware ESXi（XN98）：比對字串依 Elastic detection-rules 的 rules/integrations/vsphere（vsphere.log 訊息），只收字串夠明確、
// 不會在一般 Linux log 誤判的規則（curl／chmod／rm 等泛用指令不收）。分四類、需人工確認，依主機合併：
// esxiRemoteAccess：SSH 被啟用、vpxuser 開 SSH 工作階段（High）、root 以密碼從非本機登入
// esxiDefenseOff：lockdown 模式關閉、防火牆關閉、syslog 遠端主機被重設、稽核紀錄關閉、execInstalledOnly 關閉、強制安裝未簽章 VIB（High）
// esxiAccountChange：新增帳號、指派 Admin 角色、root 密碼被改（High）
// esxiVmImpact：VM 關機、刪除全部快照、強制結束 VM 程序（勒索軟體加密前的典型步驟；快照或強制結束、或關機 ≥ ESXI_POWEROFF_MIN 次為 High）
const ESXI_RULES = [
  ['esxiRemoteAccess', 'SSH enabled', m => m.includes('SSH access has been enabled') || m.includes('hostsvc/enable_ssh')],
  ['esxiRemoteAccess', 'vpxuser SSH', m => m.includes('SSH session was opened for') && m.includes('vpxuser'), true],
  ['esxiRemoteAccess', 'root password login', m => m.includes('Accepted password for user root') && !m.includes('from 127.0.0.1')],
  ['esxiDefenseOff', 'lockdown disabled', m => m.includes('esx.audit.lockdownmode.disabled') || m.includes('lockdown_mode_exit')],
  ['esxiDefenseOff', 'firewall disabled', m => m.includes('Firewall has been disabled') || (m.includes('network firewall set') && /--default-action[= ]true|--enabled[= ]false/.test(m))],
  ['esxiDefenseOff', 'syslog loghost reset', m => m.includes('syslog config set') && /--reset[= ]loghost|reset=loghost/.test(m)],
  ['esxiDefenseOff', 'audit records disabled', m => m.includes('auditrecords') && /--enabled[= ]false|local disable|remote disable/.test(m)],
  ['esxiDefenseOff', 'execInstalledOnly disabled', m => m.includes('execInstalledOnly') && /-i 0|-v 0|FALSE/.test(m)],
  ['esxiDefenseOff', 'forced VIB install', m => m.includes('vib install') && /--force|\s-f\b|--no-sig-check/.test(m)],
  ['esxiAccountChange', 'account created', m => m.includes('esxcli system account add') || (m.includes('Account ') && m.includes('was created on host'))],
  ['esxiAccountChange', 'Admin role assigned', m => (m.includes('system permission set') && /--role[= ]Admin\b/.test(m)) || (m.includes('Permission created') && m.includes('role is Administrator'))],
  ['esxiAccountChange', 'root password changed', m => m.includes('Password was changed for account root') || (m.includes('esxcli system account set') && m.includes('-i root'))],
  ['esxiVmImpact', 'VM power off', m => m.includes('vmsvc/power.off')],
  ['esxiVmImpact', 'snapshots removed', m => m.includes('snapshot.removeall'), true],
  ['esxiVmImpact', 'VM process killed', m => m.includes('vm process kill') || (m.includes('pkill') && m.includes('vmx')) || (m.includes('suspend_v') && m.includes('vmdumper')), true],
];
const ESXI_POWEROFF_MIN = 5;
const ESXI_BASE_SEV = { esxiRemoteAccess: 'Medium', esxiDefenseOff: 'High', esxiAccountChange: 'High', esxiVmImpact: 'Medium' };
function detectEsxi(events) {
  const groups = new Map();
  events.forEach(e => {
    if (isWebEvent(e)) return;
    const m = String(e.msg || e.raw || '');
    ESXI_RULES.forEach(([cat, label, test, high]) => {
      if (!test(m)) return;
      const k = cat + '|' + (e.host || '-');
      if (!groups.has(k)) groups.set(k, { cat, host: e.host || '-', list: [], labels: new Map(), high: false });
      const g = groups.get(k);
      if (!g.list.includes(e)) g.list.push(e);
      g.labels.set(label, (g.labels.get(label) || 0) + 1);
      if (high) g.high = true;
    });
  });
  const issues = [];
  for (const g of groups.values()) {
    const t = g.list.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b);
    const high = g.high || (g.cat === 'esxiVmImpact' && (g.labels.get('VM power off') || 0) >= ESXI_POWEROFF_MIN);
    const items = [...g.labels].map(([l, n]) => `${l} ×${n}`).join(', ');
    issues.push({ category: g.cat, severityNorm: high ? 'High' : ESXI_BASE_SEV[g.cat], count: g.list.length, firstSeen: t[0] || null, lastSeen: t[t.length - 1] || null,
      ...sampleOf('sample.' + g.cat, { host: g.host, items }), relatedHosts: g.host !== '-' ? [g.host] : [], relatedEvents: g.list, confidence: 'heuristic', companions: ['firewall', 'edr'] });
  }
  return issues;
}
function detectCredTheft(events) {
  const issues = [];
  const tsOf = list => { const t = list.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b); return [t[0] || null, t[t.length - 1] || null]; };
  // (1) 密鑰檔被下載
  const files = new Map();
  events.forEach(e => {
    if (!isWebEvent(e)) return;
    const f = e.fields, m = String(f.url).match(CRED_FILE_RE);
    if (!m || !/^2\d\d$/.test(String(f.status || '')) || !(Number(f.bytes) > 0)) return;
    const src = f.srcip || '-';
    if (!files.has(src)) files.set(src, { list: [], names: new Set() });
    files.get(src).list.push(e); files.get(src).names.add(m[1]);
  });
  for (const [src, g] of files) {
    const [first, last] = tsOf(g.list), names = [...g.names];
    issues.push({ category: 'credFileExposed', severityNorm: 'High', count: g.list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.credFileExposed', { src, n: g.list.length, files: names.join(', ') }),
      relatedHosts: src !== '-' ? [src] : [], relatedEvents: g.list, confidence: 'heuristic', credFiles: names, companions: CRED_COMP_WEB });
  }
  // (2) 雲端機密被大量讀取
  const reads = new Map();
  events.forEach(e => { const r = secretReadOf(e); if (!r || !r.who) return; const k = e.netVendor + '|' + r.who; if (!reads.has(k)) reads.set(k, []); reads.get(k).push({ e, r }); });
  for (const list of reads.values()) {
    const sorted = list.sort((a, b) => effectiveTime(a.e) - effectiveTime(b.e));
    let best = null;
    for (let i = 0, j = 0; j < sorted.length; j++) {
      while (effectiveTime(sorted[j].e) - effectiveTime(sorted[i].e) > SECRET_BULK_MS) i++;
      const names = new Set(sorted.slice(i, j + 1).flatMap(x => x.r.names));
      if (names.size >= SECRET_BULK_MIN && (!best || names.size > best.names.size)) best = { win: sorted.slice(i, j + 1), names };
    }
    if (!best) continue;
    const ips = [...new Set(best.win.map(x => x.r.ip).filter(Boolean))], ext = ips.some(ip => /^[0-9a-f:.]+$/i.test(ip) && !iocIsInternalIP(ip));
    const ev = best.win.map(x => x.e), [first, last] = tsOf(ev), who = best.win[0].r.who;
    issues.push({ category: 'secretBulkRead', severityNorm: ext ? 'High' : 'Medium', count: ev.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.secretBulkRead', { who, n: best.names.size, ips: ips.slice(0, 3).join(', ') || '-', app: CLOUD_AUTH_APP[ev[0].netVendor] || ev[0].netVendor }),
      relatedHosts: [who, ...ips.slice(0, 3)], relatedEvents: ev, confidence: 'heuristic', credSecrets: [...best.names].slice(0, 10), companions: CRED_COMP_CLOUD });
  }
  // (3) 同一把 AWS 長期金鑰從多個位址使用；(5) 同一 SSH 金鑰指紋從多個來源登入
  const byKey = new Map();
  const add = (k, e, ip) => { if (!byKey.has(k)) byKey.set(k, []); byKey.get(k).push(Object.assign(Object.create(e), { _ip: ip, _e: e })); };
  events.forEach(e => {
    if (e.netVendor === 'cloudtrail' && e.cloudRaw) {
      const id = String((e.cloudRaw.userIdentity || {}).accessKeyId || ''), ip = String(e.cloudRaw.sourceIPAddress || '');
      if (/^AKIA[A-Z0-9]{12,}$/.test(id) && (isValidIPv4(ip) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(ip))) add('aws|' + id, e, ip);
    }
    const f = e.fields;
    if (e.netVendor === 'linuxauth' && f && f.ssh === 'accepted' && f.keyfp && f.srcip) add('ssh|' + f.keyfp, e, f.srcip);
  });
  for (const [k, list] of byKey) {
    const best = multiSourceWindow(list);
    if (!best) continue;
    const ssh = k.startsWith('ssh|'), key = k.slice(4), ev = best.win.map(x => x._e), [first, last] = tsOf(ev);
    const users = [...new Set(ev.map(e => e.fields && e.fields.user).filter(Boolean))];
    issues.push({ category: ssh ? 'sshKeyMultiSource' : 'cloudKeyMultiSource', severityNorm: 'Medium', count: ev.length, firstSeen: first, lastSeen: last,
      ...sampleOf(ssh ? 'sample.sshKeyMultiSource' : 'sample.cloudKeyMultiSource', { key: ssh ? key : key.slice(0, 8) + '…', n: best.ips.length, ips: best.ips.slice(0, 5).join(', '), user: users.slice(0, 3).join(', ') || '-' }),
      relatedHosts: best.ips.slice(0, 5), relatedEvents: ev, confidence: 'heuristic', credKey: ssh ? key : key.slice(0, 8) + '…', companions: ssh ? CRED_COMP_SSH : CRED_COMP_CLOUD });
  }
  // (4) Entra 應用程式被加上憑證或密碼
  const apps = new Map();
  events.forEach(e => {
    if (e.netVendor !== 'entraaudit' || !e.cloudRaw) return;
    const ci = cloudAuthInfo(e.cloudRaw);
    if (!ci || !ci.ok || !APP_CRED_ACTIVITY_RE.test(String(ci.event).trim())) return;
    const tgt = [].concat((e.cloudRaw.properties || {}).targetResources || []).map(t => t && t.displayName).filter(Boolean)[0] || '-';
    const k = tgt + '|' + ci.user;
    if (!apps.has(k)) apps.set(k, { app: tgt, who: ci.user || '-', list: [] });
    apps.get(k).list.push(e);
  });
  for (const g of apps.values()) {
    const [first, last] = tsOf(g.list);
    issues.push({ category: 'appCredentialAdded', severityNorm: 'High', count: g.list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.appCredentialAdded', { app: g.app, who: g.who, n: g.list.length }),
      relatedHosts: [g.who, g.app].filter(x => x && x !== '-'), relatedEvents: g.list, confidence: 'heuristic', credApp: g.app, companions: CRED_COMP_CLOUD });
  }
  return issues;
}
// GitLab 權杖與程式庫存取（XN81），全部為需人工確認：路徑依 GitLab 原始碼 lib/api/ci/variables.rb、lib/api/group_variables.rb、
// lib/api/admin/ci/variables.rb、lib/api/repositories.rb；建立權杖的訊息依 app/services/personal_access_tokens/create_service.rb（log_info）
const GL_VAR_RE = /^\/api\/v4\/(?:(projects|groups)\/([^\/?#]+)\/variables|admin\/ci\/variables)(?:[\/?#]|$)/;
const GL_ARCHIVE_RE = /^\/api\/v4\/projects\/([^\/?#]+)\/repository\/archive/;
const GL_PAT_RE = /^PAT CREATION: created_by: '([^']*)', created_for: '([^']*)', token_id: '(\d+)'/;
const GL_VAR_BULK = 5, GL_CLONE_MIN = 10, GL_WINDOW_MS = 60 * 60 * 1000;
const GL_COMPANIONS = ['ssh', 'firewall', 'dbAudit'];
function detectGitlab(events) {
  const issues = [], gl = events.filter(e => e.netVendor === 'gitlab' && e.fields);
  if (!gl.length) return issues;
  const tsOf = list => { const t = list.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b); return [t[0] || null, t[t.length - 1] || null]; };
  const ok = e => /^2\d\d$/.test(String(e.fields.status || ''));
  const ext = ip => !!ip && /^[0-9a-f:.]+$/i.test(ip) && !iocIsInternalIP(ip);
  // 視窗內不同「對象」數最多的一段
  const bestWindow = (list, keyOf) => {
    const sorted = [...list].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    let best = null;
    for (let i = 0, j = 0; j < sorted.length; j++) {
      while (effectiveTime(sorted[j]) - effectiveTime(sorted[i]) > GL_WINDOW_MS) i++;
      const objs = new Set(sorted.slice(i, j + 1).map(keyOf));
      if (!best || objs.size > best.objs.size) best = { win: sorted.slice(i, j + 1), objs };
    }
    return best;
  };
  const groupBy = (list, keyOf) => { const m = new Map(); list.forEach(e => { const k = keyOf(e); if (!m.has(k)) m.set(k, []); m.get(k).push(e); }); return m; };
  // (1) 讀取 CI/CD 變數
  const vars = gl.filter(e => e.fields.glKind === 'request' && String(e.fields.method).toUpperCase() === 'GET' && ok(e) && GL_VAR_RE.test(e.fields.url));
  for (const [k, list] of groupBy(vars, e => (e.fields.user || '-') + '|' + (e.fields.srcip || '-'))) {
    const b = bestWindow(list, e => { const m = e.fields.url.match(GL_VAR_RE); return m[1] ? m[1] + '/' + m[2] : 'admin'; });
    const [user, src] = k.split('|'), [first, last] = tsOf(b.win);
    issues.push({ category: 'gitlabCiVarRead', severityNorm: ext(src) || b.objs.size >= GL_VAR_BULK ? 'High' : 'Medium', count: list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.gitlabCiVarRead', { user, src, n: b.objs.size, targets: [...b.objs].slice(0, 5).join(', ') }),
      relatedHosts: [src, user].filter(x => x && x !== '-'), relatedEvents: list, confidence: 'heuristic', glTargets: [...b.objs].slice(0, 10), companions: GL_COMPANIONS });
  }
  // (2) 同一個權杖從多個位址使用（沿用 XN80 的多來源視窗）
  const byTok = new Map();
  gl.forEach(e => { const f = e.fields; if (f.glTokenId && f.srcip) { const k = (f.glTokenType || 'token') + '#' + f.glTokenId; if (!byTok.has(k)) byTok.set(k, []); byTok.get(k).push(Object.assign(Object.create(e), { _ip: f.srcip, _e: e })); } });
  for (const [k, list] of byTok) {
    const best = multiSourceWindow(list);
    if (!best) continue;
    const ev = best.win.map(x => x._e), [first, last] = tsOf(ev), users = [...new Set(ev.map(e => e.fields.user).filter(Boolean))];
    issues.push({ category: 'gitlabTokenMultiSource', severityNorm: 'Medium', count: ev.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.gitlabTokenMultiSource', { key: k, user: users.join(', ') || '-', n: best.ips.length, ips: best.ips.slice(0, 5).join(', ') }),
      relatedHosts: best.ips.slice(0, 5), relatedEvents: ev, confidence: 'heuristic', credKey: k, companions: GL_COMPANIONS });
  }
  // (3) 短時間下載大量程式庫：audit 的 git-upload-pack（clone／fetch）與 API 封存下載
  const pulls = gl.filter(e => (e.fields.glKind === 'audit' && e.fields.glAction === 'git-upload-pack' && e.fields.glTarget)
    || (e.fields.glKind === 'request' && ok(e) && GL_ARCHIVE_RE.test(e.fields.url)));
  const projOf = e => e.fields.glTarget || (e.fields.url.match(GL_ARCHIVE_RE) || [])[1];
  for (const [k, list] of groupBy(pulls, e => (e.fields.user || '-') + '|' + (e.fields.srcip || '-'))) {
    const b = bestWindow(list, projOf);
    if (b.objs.size < GL_CLONE_MIN) continue;
    const [user, src] = k.split('|'), [first, last] = tsOf(b.win);
    issues.push({ category: 'gitlabMassClone', severityNorm: ext(src) ? 'High' : 'Medium', count: b.win.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.gitlabMassClone', { user, src, n: b.objs.size }),
      relatedHosts: [src, user].filter(x => x && x !== '-'), relatedEvents: b.win, confidence: 'heuristic', glTargets: [...b.objs].slice(0, 10), companions: GL_COMPANIONS });
  }
  // (4) 建立個人存取權杖：替其他帳號建立為 High，替自己建立為 Low
  gl.forEach(e => {
    const m = String(e.fields.glMsg || '').match(GL_PAT_RE);
    if (!m) return;
    const other = m[1] !== m[2];
    issues.push({ category: 'gitlabTokenCreated', severityNorm: other ? 'High' : 'Low', count: 1, firstSeen: e.timestamp, lastSeen: e.timestamp,
      ...sampleOf(other ? 'sample.gitlabTokenCreatedOther' : 'sample.gitlabTokenCreated', { by: m[1], for: m[2], id: m[3], src: e.fields.srcip || '-' }),
      relatedHosts: [m[1], e.fields.srcip].filter(Boolean), relatedEvents: [e], confidence: 'confirmed', companions: GL_COMPANIONS, credKey: 'PersonalAccessToken#' + m[3], glTokenFor: m[2], glTokenOther: other });
  });
  return issues;
}
// AWS 帳號使用風險（XN83）：root 使用依 SigmaHQ aws_root_account_usage（userIdentity.type Root，排除 eventType AwsServiceEvent）；
// 主控台登入未用 MFA 依 additionalEventData.MFAUsed（Elastic integrations aws cloudtrail 真實測試 log），只看 IAMUser／Root
// （AssumedRole 等經 SSO 或聯合登入的 MFA 在身分提供者端）
function detectAwsAccount(events) {
  const issues = [];
  const ct = events.filter(e => e.netVendor === 'cloudtrail' && e.cloudRaw && !e.cloudRaw.errorCode);
  const tsOf = list => { const t = list.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b); return [t[0] || null, t[t.length - 1] || null]; };
  const loginOk = o => o.eventName === 'ConsoleLogin' && (o.responseElements || {}).ConsoleLogin === 'Success';
  const root = ct.filter(e => (e.cloudRaw.userIdentity || {}).type === 'Root' && e.cloudRaw.eventType !== 'AwsServiceEvent');
  const bySrc = new Map();
  root.forEach(e => { const k = e.cloudRaw.sourceIPAddress || '-'; if (!bySrc.has(k)) bySrc.set(k, []); bySrc.get(k).push(e); });
  for (const [src, list] of bySrc) {
    const login = list.some(e => loginOk(e.cloudRaw)), [first, last] = tsOf(list);
    const names = [...new Set(list.map(e => e.cloudRaw.eventName))];
    issues.push({ category: 'awsRootUsage', severityNorm: login ? 'High' : 'Medium', count: list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.awsRootUsage', { src, n: list.length, events: names.slice(0, 5).join(', ') }),
      relatedHosts: [src].filter(x => x !== '-'), relatedEvents: list, confidence: 'confirmed', companions: CRED_COMP_CLOUD });
  }
  const noMfa = ct.filter(e => loginOk(e.cloudRaw) && (e.cloudRaw.additionalEventData || {}).MFAUsed === 'No' && /^(?:IAMUser|Root)$/.test((e.cloudRaw.userIdentity || {}).type || ''));
  const byUser = new Map();
  noMfa.forEach(e => { const k = e.fields.user || '-'; if (!byUser.has(k)) byUser.set(k, []); byUser.get(k).push(e); });
  for (const [user, list] of byUser) {
    const isRoot = list.some(e => e.cloudRaw.userIdentity.type === 'Root'), [first, last] = tsOf(list);
    const ips = [...new Set(list.map(e => e.cloudRaw.sourceIPAddress).filter(Boolean))];
    issues.push({ category: 'awsConsoleNoMfa', severityNorm: isRoot ? 'High' : 'Medium', count: list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.awsConsoleNoMfa', { user, n: list.length, ips: ips.slice(0, 3).join(', ') || '-' }),
      relatedHosts: [user, ...ips.slice(0, 3)].filter(x => x !== '-'), relatedEvents: list, confidence: 'confirmed', companions: CRED_COMP_CLOUD });
  }
  return issues;
}
// 資料庫登入（XN90），全部為需人工確認：
// dbAdminRemote：postgres／root 等內建管理帳號從其他主機登入成功（外部位址 High，內部 Medium）；本機 socket／localhost／loopback 不列
// dbExternalLogin：其他帳號從外部位址登入成功（Medium）
// dbNewSource：帳號已從固定來源登入 DB_NEW_SRC_BASE 次以上、跨 1 小時以上後，出現沒見過的內部來源（Low）
// dbAuthFailBurst：同帳號 1 小時內認證失敗 ≥ DB_FAIL_MIN 次（Medium）；之後 1 小時內同帳號登入成功（來源相同或不明）為 High
const DB_ADMIN_USERS = new Set(['postgres', 'root']);
const DB_FAIL_MIN = 5, DB_FAIL_WINDOW_MS = 60 * 60 * 1000, DB_NEW_SRC_BASE = 10, DB_NEW_SRC_SPAN_MS = 60 * 60 * 1000;
const DB_COMPANIONS = ['firewall', 'ssh', 'gitlab'];
const dbIsLocal = f => !!f.dbLocal || /^127\./.test(f.srcip || '') || f.srcip === '::1';
const dbSrcOf = f => f.srcip || f.dbClient || '';
const dbKindLabel = k => (k === 'postgres' ? 'PostgreSQL' : 'MySQL');
function detectDbAuth(events) {
  const issues = [];
  const db = events.filter(e => e.fields && e.fields.dbKind && (e.fields.dbAuth === 'ok' || e.fields.dbAuth === 'fail') && e.fields.user);
  if (!db.length) return issues;
  const tsOf = list => { const t = list.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b); return [t[0] || null, t[t.length - 1] || null]; };
  const group = (list, keyFn) => { const m = new Map(); list.forEach(e => { const k = keyFn(e); if (k === null) return; if (!m.has(k)) m.set(k, []); m.get(k).push(e); }); return m; };
  const ok = db.filter(e => e.fields.dbAuth === 'ok');
  const remote = ok.filter(e => !dbIsLocal(e.fields) && dbSrcOf(e.fields));
  const isAdmin = f => DB_ADMIN_USERS.has(String(f.user).toLowerCase());
  const ext = f => !!f.srcip && !iocIsInternalIP(f.srcip);
  // 管理帳號遠端登入
  for (const [, list] of group(remote.filter(e => isAdmin(e.fields)), e => `${e.fields.dbKind}|${e.fields.user}|${dbSrcOf(e.fields)}`)) {
    const f = list[0].fields, src = dbSrcOf(f), [first, last] = tsOf(list);
    const dbs = [...new Set(list.map(e => e.fields.database).filter(Boolean))];
    issues.push({ category: 'dbAdminRemote', severityNorm: ext(f) ? 'High' : 'Medium', count: list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.dbAdminRemote', { kind: dbKindLabel(f.dbKind), user: f.user, src, n: list.length, dbs: dbs.slice(0, 3).join(', ') || '-' }),
      relatedHosts: [src, f.user], relatedEvents: list, confidence: 'heuristic', dbUser: f.user, dbKind: f.dbKind, companions: DB_COMPANIONS });
  }
  // 一般帳號從外部位址登入
  for (const [, list] of group(remote.filter(e => !isAdmin(e.fields) && ext(e.fields)), e => `${e.fields.dbKind}|${e.fields.user}|${e.fields.srcip}`)) {
    const f = list[0].fields, [first, last] = tsOf(list);
    issues.push({ category: 'dbExternalLogin', severityNorm: 'Medium', count: list.length, firstSeen: first, lastSeen: last,
      ...sampleOf('sample.dbExternalLogin', { kind: dbKindLabel(f.dbKind), user: f.user, src: f.srcip, n: list.length }),
      relatedHosts: [f.srcip, f.user], relatedEvents: list, confidence: 'heuristic', dbUser: f.user, dbKind: f.dbKind, companions: DB_COMPANIONS });
  }
  // 帳號出現新的內部來源（外部來源已由上面兩類列出）
  for (const [, list] of group(remote.filter(e => e.timestamp && !isAdmin(e.fields)), e => `${e.fields.dbKind}|${e.fields.user}`)) {
    const sorted = [...list].sort((a, b) => a.timestamp - b.timestamp), seen = new Set(), flagged = new Map();
    let n = 0;
    for (const e of sorted) {
      const src = dbSrcOf(e.fields);
      if (!seen.has(src) && n >= DB_NEW_SRC_BASE && e.timestamp - sorted[0].timestamp >= DB_NEW_SRC_SPAN_MS && !ext(e.fields)) flagged.set(src, { first: e, prev: [...seen] });
      if (flagged.has(src)) { const x = flagged.get(src); (x.list = x.list || []).push(e); }
      seen.add(src); n++;
    }
    for (const [src, x] of flagged) {
      const f = x.first.fields, [first, last] = tsOf(x.list);
      issues.push({ category: 'dbNewSource', severityNorm: 'Low', count: x.list.length, firstSeen: first, lastSeen: last,
        ...sampleOf('sample.dbNewSource', { kind: dbKindLabel(f.dbKind), user: f.user, src, base: x.prev.slice(0, 3).join(', ') }),
        relatedHosts: [src, f.user], relatedEvents: x.list, confidence: 'heuristic', dbUser: f.user, dbKind: f.dbKind, companions: DB_COMPANIONS });
    }
  }
  // 認證失敗暴增
  const fails = db.filter(e => e.fields.dbAuth === 'fail' && e.timestamp);
  for (const [, list] of group(fails, e => `${e.fields.dbKind}|${e.fields.user}`)) {
    if (list.length < DB_FAIL_MIN) continue;
    const sorted = [...list].sort((a, b) => a.timestamp - b.timestamp);
    let best = 0, end = null;
    for (let i = 0, j = 0; j < sorted.length; j++) {
      while (sorted[j].timestamp - sorted[i].timestamp > DB_FAIL_WINDOW_MS) i++;
      if (j - i + 1 > best) { best = j - i + 1; end = sorted[j].timestamp; }
    }
    if (best < DB_FAIL_MIN) continue;
    const f = sorted[0].fields, srcs = [...new Set(sorted.map(e => dbSrcOf(e.fields)).filter(Boolean))];
    const after = ok.find(e => e.fields.dbKind === f.dbKind && e.fields.user === f.user && e.timestamp && e.timestamp > end && e.timestamp - end <= DB_FAIL_WINDOW_MS
      && (!srcs.length || !dbSrcOf(e.fields) || srcs.includes(dbSrcOf(e.fields))));
    const [first, last] = tsOf(sorted);
    issues.push({ category: 'dbAuthFailBurst', severityNorm: after ? 'High' : 'Medium', count: sorted.length, firstSeen: first, lastSeen: after ? after.timestamp : last,
      ...sampleOf(after ? 'sample.dbAuthFailThenOk' : 'sample.dbAuthFailBurst', { kind: dbKindLabel(f.dbKind), user: f.user, n: best, srcs: srcs.slice(0, 3).join(', ') || '-' }),
      relatedHosts: [f.user, ...srcs.slice(0, 3)], relatedEvents: after ? [...sorted, after] : sorted, confidence: 'heuristic', dbUser: f.user, dbKind: f.dbKind, companions: DB_COMPANIONS });
  }
  return issues;
}
// 針對 AI 分析的提示注入字串（XN84）：攻擊者可控制的 log 欄位（網址、User-Agent、帳號、Referer、訊息）出現要求忽略指示、
// 冒充系統提示或對話標記的字串時提示（Low、風險標記類，不標 MITRE、不進攻擊鏈）。只收語意明確的片語，避免一般文字誤判；
// 把 log、報告或案件包交給 AI 摘要時，這類字串可能讓 AI 改變行為
const PROMPT_INJ_RE = [
  /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules|directions)\b/i,
  /\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted)\b/i,
  /\b(?:new|updated|override)\s+system\s+(?:prompt|instructions?)\b/i,
  /<\|im_start\|>|<\|im_end\|>|\[\/?INST\]|<<\/?SYS>>/,
  /忽略(?:之前|先前|以上|前面|上述)(?:的)?(?:所有)?(?:指示|指令|規則|提示)/,
  /(?:前の|以前の|上記の)(?:指示|命令)を(?:すべて)?無視/,
];
const PROMPT_INJ_FIELDS = ['url', 'ua', 'user', 'referer', 'origin', 'query', 'domain'];
function promptInjOf(e) {
  const f = e.fields || {};
  const parts = PROMPT_INJ_FIELDS.map(k => f[k]).filter(v => typeof v === 'string');
  if (e.msg) parts.push(String(e.msg).slice(0, 2000));
  for (const p of parts) {
    let t = p;
    try { t = decodeURIComponent(p.replace(/\+/g, ' ')); } catch (x) { /* 解碼失敗沿用原文 */ }
    const re = PROMPT_INJ_RE.find(r => r.test(t));
    if (re) return (t.match(re) || [''])[0].slice(0, 80);
  }
  return '';
}
function detectPromptInjection(events) {
  const groups = new Map();
  events.forEach(e => {
    const hit = promptInjOf(e);
    if (!hit) return;
    const src = (e.fields && e.fields.srcip) || '-';
    if (!groups.has(src)) groups.set(src, { list: [], hits: new Set() });
    groups.get(src).list.push(e); groups.get(src).hits.add(hit);
  });
  const issues = [];
  for (const [src, g] of groups) {
    const t = g.list.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b);
    issues.push({ category: 'promptInjection', severityNorm: 'Low', count: g.list.length, firstSeen: t[0] || null, lastSeen: t[t.length - 1] || null,
      ...sampleOf('sample.promptInjection', { src, n: g.list.length, text: [...g.hits].slice(0, 2).join(' / ') }),
      relatedHosts: src !== '-' ? [src] : [], relatedEvents: g.list, confidence: 'heuristic', promptInjText: [...g.hits].slice(0, 3) });
  }
  return issues;
}
// 憑證處置清單（XN91）：依憑證類問題列出需更換或撤銷的憑證，只列識別碼（金鑰前 8 碼、權杖編號、指紋、應用程式與檔名），不含機密值。
// 每項 {kind, id, cat}；怎麼處理的說明由畫面以 rot.where_<kind> 顯示。同一 kind＋id 只列一次
function buildRotationList(issues) {
  const out = [], seen = new Set();
  const add = (kind, id, cat) => { const k = kind + '|' + id; if (!id || seen.has(k)) return; seen.add(k); out.push({ kind, id: String(id), cat }); };
  (issues || []).forEach(is => {
    const c = is.category;
    if (c === 'cloudKeyMultiSource') add('awsKey', is.credKey, c);
    else if (c === 'secretBulkRead') (is.credSecrets || []).forEach(n => add('cloudSecret', n, c));
    else if (c === 'sshKeyMultiSource') add('sshKey', is.credKey, c);
    else if (c === 'appCredentialAdded') add('entraApp', is.credApp, c);
    else if (c === 'credFileExposed') {
      const site = [...new Set((is.relatedEvents || []).map(e => (e.fields && e.fields.vhost) || e.host).filter(Boolean))].join(', ');
      (is.credFiles || []).forEach(f => add('secretFile', site ? `${f} @ ${site}` : f, c));
    } else if (c === 'gitlabTokenMultiSource') add('gitlabToken', is.credKey, c);
    else if (c === 'gitlabTokenCreated' && is.glTokenOther) add('gitlabToken', is.credKey, c);
    else if (c === 'gitlabCiVarRead') (is.glTargets || []).forEach(t => add('ciVars', t, c));
    else if (c === 'awsRootUsage') add('awsRoot', 'root', c);
    else if (c === 'awsConsoleNoMfa') add('awsUser', is.relatedHosts && is.relatedHosts[0], c);
    else if ((c === 'appsmithExternalRisky' || c === 'appsmithScriptedApi') && (is.appsmithKinds || []).some(k => k === 'adminEnv' || k === 'datasource')) add('appsmithEnv', 'Appsmith', c);
    else if (c === 'appsmithOriginReset' || c === 'appsmithResetFlow') add('appsmithAccount', 'Appsmith', c);
    else if ((c === 'dbAdminRemote' || c === 'dbExternalLogin' || c === 'dbAuthFailBurst') && is.severityNorm === 'High') add('dbAccount', `${dbKindLabel(is.dbKind)} ${is.dbUser}`, c);
  });
  return out;
}
function detectExploitAttempts(events) {
  const groups = new Map();
  events.forEach(e => {
    const f = e.fields || {};
    if (!f.url || !(e.netVendor === 'web' || e.netVendor === 'haproxy' || e.netVendor === 'cloudflare' || e.format === 'weblog' || e.format === 'w3c')) return;
    exploitSigsOf(e).forEach(sig => {
      const src = f.srcip || '-', key = sig.id + '|' + src;
      if (!groups.has(key)) groups.set(key, { sig, src, events: [], ok: 0, hosts: new Set() });
      const g = groups.get(key);
      g.events.push(e);
      if (/^2\d\d$/.test(String(f.status || ''))) g.ok++;
      if (e.host) g.hosts.add(e.host);
    });
  });
  const issues = [];
  for (const g of groups.values()) {
    const ts = g.events.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b);
    const p = { src: g.src, name: g.sig.name, cve: g.sig.cve.join(', '), n: g.events.length, ok: g.ok, host: [...g.hosts].slice(0, 3).join(', ') || '-' };
    issues.push({
      category: 'exploitAttempt', severityNorm: g.ok ? 'High' : 'Medium', count: g.events.length,
      firstSeen: ts[0] || null, lastSeen: ts[ts.length - 1] || null,
      ...sampleOf(g.ok ? 'sample.exploitAttemptOk' : 'sample.exploitAttempt', p),
      relatedHosts: g.src !== '-' ? [g.src] : [], relatedEvents: g.events, confidence: 'heuristic',
      cves: g.sig.cve.slice(), exploitSig: g.sig.id, exploitOk: g.ok
    });
  }
  return issues;
}
// IDS 告警的簽章名稱常帶 CVE 編號（Suricata ET 規則等），抽出後附在 idsAlert 問題的 cves 欄位
const CVE_ID_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
function detectWebScan(events) {
  const bySrc = new Map();
  events.filter(e => (e.format === 'weblog' || e.format === 'w3c') && e.fields.srcip && e.fields.status === '404').forEach(e => {
    const src = e.fields.srcip;
    if (!bySrc.has(src)) bySrc.set(src, { paths: new Set(), events: [] });
    const g = bySrc.get(src);
    g.paths.add(String(e.fields.url || '').split('?')[0]);
    g.events.push(e);
  });
  const issues = [];
  for (const [src, g] of bySrc) {
    if (g.paths.size < WEB_SCAN_MIN_404) continue;
    const ts = g.events.map(e => e.timestamp).filter(Boolean).sort((a, b) => a - b);
    issues.push({
      category: 'possibleScan', severityNorm: 'Medium', count: g.paths.size,
      firstSeen: ts[0] || null, lastSeen: ts[ts.length - 1] || null,
      ...sampleOf('sample.webProbe', { src, n: g.paths.size }),
      relatedHosts: [src], relatedEvents: g.events, confidence: 'heuristic'
    });
  }
  return issues;
}
// ── DNS 異常偵測（第二十一輪 GB）──
// 來源：DNS 伺服器紀錄（fields.dns）、Zeek dns.log、Cisco Umbrella DNS、Sysmon EventID 22（QueryStatus 9003 為名稱不存在）
// 註冊網域以「最後兩段；頂層為兩字母且第二段為 co／com／net／org／gov／edu／ac 等時取三段」簡化判斷，不內建公開後綴清單
// 內部名稱（.local／.arpa／.lan／.internal／.home 等）不列入：Kubernetes 搜尋網域等會產生大量 NXDOMAIN
const DNS_DGA_MIN = 5, DNS_NX_MIN = 20, DNS_TUNNEL_SUBS = 50;
const DNS_INTERNAL_RE = /(?:^|\.)(?:local|localdomain|lan|internal|intranet|home|corp|arpa|localhost|svc|cluster\.local)$/i;
function dnsQueryOf(e) {
  const f = e.fields || {};
  if (f.dns && f.domain && f.dns !== 'upstream') return { client: f.srcip || '', name: f.domain, rcode: String(f.rcode || '').toUpperCase() };
  if (e.netVendor === 'zeek' && e.zeekRaw && e.zeekRaw.query) return { client: f.srcip || '', name: dnsName(e.zeekRaw.query), rcode: String(e.zeekRaw.rcode_name || '').toUpperCase() };
  if (f.umbrellaType === 'dns' && f.domain) return { client: f.srcip || f.ident || '', name: f.domain, rcode: String(f.rcode || '').toUpperCase() };
  if (e.format === 'winevent' && f.Channel === SYSMON_CHANNEL && f.EventID === '22' && f.QueryName) return { client: e.host || '', name: dnsName(f.QueryName), rcode: f.QueryStatus === '9003' ? 'NXDOMAIN' : '' };
  return null;
}
function dnsRegDomain(name) {
  const l = String(name).toLowerCase().split('.').filter(Boolean);
  if (l.length <= 2) return l.join('.');
  const n = l[l.length - 1].length === 2 && /^(?:co|com|net|org|gov|edu|ac|or|ne|go|mil)$/.test(l[l.length - 2]) ? 3 : 2;
  return l.slice(-n).join('.');
}
function dnsEntropy(s) {
  const c = {}; for (const ch of s) c[ch] = (c[ch] || 0) + 1;
  return Object.values(c).reduce((h, n) => h - (n / s.length) * Math.log2(n / s.length), 0);
}
// 疑似演算法產生的網域：註冊網域的名稱段 12 字元以上、亂度高，且母音很少或數字比例高（punycode 不算）
function dnsDgaLike(name) {
  const lab = dnsRegDomain(name).split('.')[0];
  if (lab.length < 12 || /^xn--/.test(lab) || !/^[a-z0-9-]+$/.test(lab)) return false;
  const vowels = (lab.match(/[aeiou]/g) || []).length / lab.length, digits = (lab.match(/\d/g) || []).length / lab.length;
  return dnsEntropy(lab) >= 3.5 && (vowels < 0.3 || digits >= 0.2);
}
function detectDnsAnomalies(events) {
  const byClient = new Map();
  events.forEach(e => {
    const q = dnsQueryOf(e);
    if (!q || !q.client || !q.name || DNS_INTERNAL_RE.test(q.name)) return;
    if (!byClient.has(q.client)) byClient.set(q.client, { dga: new Map(), nx: new Map(), long: new Map(), subs: new Map() });
    const g = byClient.get(q.client), name = q.name.toLowerCase(), reg = dnsRegDomain(name);
    const add = (m, k, v) => { if (!m.has(k)) m.set(k, { names: new Set(), events: [] }); const x = m.get(k); x.names.add(v); x.events.push(e); };
    if (dnsDgaLike(name)) add(g.dga, 'all', reg);
    if (q.rcode === 'NXDOMAIN') add(g.nx, 'all', name);
    const labels = name.split('.');
    if (labels.some(l => l.length >= 40) || name.length >= 100) add(g.long, reg, name);
    if (name !== reg) add(g.subs, reg, name);
  });
  const issues = [];
  const mk = (category, severityNorm, client, names, evs, text) => {
    const ts = evs.map(x => x.timestamp).filter(Boolean).sort((a, b) => a - b);
    issues.push({ category, severityNorm, count: names.size, firstSeen: ts[0] || null, lastSeen: ts[ts.length - 1] || null,
      ...sampleOf('sample.dns', { client, text, names: [...names].slice(0, 5).join(', ') }), relatedHosts: [client], relatedEvents: evs, confidence: 'heuristic', dnsNames: [...names].slice(0, 20) });
  };
  for (const [client, g] of byClient) {
    const dga = g.dga.get('all');
    if (dga && dga.names.size >= DNS_DGA_MIN) mk('dnsDga', 'High', client, dga.names, dga.events, { key: 'sample.dnsDga', p: { n: dga.names.size } });
    const nx = g.nx.get('all');
    if (nx && nx.names.size >= DNS_NX_MIN) mk('dnsNxBurst', 'Medium', client, nx.names, nx.events, { key: 'sample.dnsNx', p: { n: nx.names.size } });
    const tun = new Map(g.long);
    for (const [reg, x] of g.subs) {
      // 大量不同子網域且子網域本身很長才算（CDN、DNSBL 也會有大量子網域，但多半是短名稱或反轉 IP）
      const avg = [...x.names].reduce((n, v) => n + v.length - reg.length, 0) / x.names.size;
      if (x.names.size >= DNS_TUNNEL_SUBS && avg >= 20 && !tun.has(reg)) tun.set(reg, x);
    }
    for (const [reg, x] of tun) mk('dnsTunnel', 'High', client, x.names, x.events, { key: 'sample.dnsTunnel', p: { reg, n: x.names.size } });
  }
  return issues;
}
const MIKROTIK_SEV_WORDS = ['critical', 'error', 'warning', 'info', 'debug'];
function splitMikroTikTopics(text) {
  const m = String(text || '').match(/^([a-z][a-z0-9-]*(?:,[a-z][a-z0-9-]*)*)\s+([\s\S]*)$/);
  if (!m) return null;
  const topics = m[1].split(',');
  if (!topics.some(t => MIKROTIK_SEV_WORDS.includes(t))) return null;
  return { topics, body: m[2] };
}
// 端點：IPv4 可帶 :埠；IPv6 帶埠時以 [位址]:埠 表示；ICMP 等無埠時只有位址
function splitMikroTikEndpoint(s) {
  let m = s.match(/^\[([0-9A-Fa-f:.]+)\]:(\d+)$/);
  if (m) return { ip: m[1], port: m[2] };
  m = s.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/);
  if (m) return { ip: m[1], port: m[2] };
  return { ip: s, port: '' };
}
function parseMikroTikMsg(text) {
  const t = splitMikroTikTopics(text);
  const body = t ? t.body : String(text || '');
  const fields = {};
  const fw = body.match(/^(?:(.*?)\s+)?([\w-]+): in:(\S+) out:([^,]+),/);
  const proto = body.match(/\bproto (\w+)(?: \(([^)]*)\))?/);
  if (fw && proto) {
    if (fw[1]) fields.logprefix = fw[1];
    fields.chain = fw[2]; fields.inintf = fw[3]; fields.outintf = fw[4].trim();
    fields.proto = proto[1];
    if (proto[2]) fields.protoflags = proto[2];
    const mac = body.match(/\bsrc-mac ((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})/);
    if (mac) fields.srcmac = mac[1];
    // 位址對一律取 proto 之後第一組「, A->B,」（NAT 段落在其後，不會先命中）
    const addr = body.slice(proto.index).match(/,\s*(\S+?)->(\S+?),/);
    if (addr) {
      const a = splitMikroTikEndpoint(addr[1]), b = splitMikroTikEndpoint(addr[2]);
      fields.srcip = a.ip; if (a.port) fields.srcport = a.port;
      fields.dstip = b.ip; if (b.port) fields.dstport = b.port;
    }
    const len = body.match(/,\s*len (\d+)/);
    if (len) fields.len = len[1];
  }
  let m = body.match(/\blogin failure for user (\S*) from (\S+) via (\S+)/);
  if (m) { if (m[1]) fields.user = m[1]; fields.srcip = m[2]; fields.method = m[3]; }
  else if ((m = body.match(/\buser (\S+) logged (in|out) from (\S+) via (\S+)/))) {
    fields.user = m[1]; fields.loginaction = 'logged ' + m[2]; fields.srcip = m[3]; fields.method = m[4];
  }
  if (!t && !Object.keys(fields).length) return null;
  if (t) fields.topics = t.topics.join(',');
  return { topics: t ? t.topics : [], body, fields };
}
// topics 內嚴重度字取最嚴重者，沿用 normGenericSeverity() 既有詞彙對照（critical→Critical、
// error→High、warning→Medium、info→Low、debug→Info）；僅在沒有 <PRI> 可用時使用
function mikrotikTopicSeverity(topics) {
  const w = MIKROTIK_SEV_WORDS.find(s => topics.includes(s));
  return w ? normGenericSeverity(w) : 'Info';
}
// 本機 /log print 匯出的時間欄位：當天只有 HH:MM:SS；今年為 mmm/dd；較舊為 mmm/dd/yyyy；
// RouterOS 7.10 起改為 MM-DD／YYYY-MM-DD（官方論壇 7.10 日期格式變更公告）。缺年份或日期時
// 以目前日期補上（比照 parseSyslogTimestamp('bsd') 補目前年份的既有做法），以本機時區解讀
const MIKROTIK_MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
const MIKROTIK_LINE_RE = /^(?:<(\d{1,3})>)?(?:(?:(\d{4}-\d{2}-\d{2}|\d{2}-\d{2}|[A-Za-z]{3}\/\d{2}(?:\/\d{4})?)\s+)?(\d{2}:\d{2}:\d{2})\s+)?([a-z][\s\S]*)$/;
function parseMikroTikTimestamp(date, time, now) {
  if (!time) return null;
  const [hh, mi, ss] = time.split(':').map(Number);
  const ref = now || new Date();
  let y = ref.getFullYear(), mo = ref.getMonth(), d = ref.getDate(), m, hasYear = false;
  if (date) {
    if ((m = date.match(/^(\d{4})-(\d{2})-(\d{2})$/))) { y = +m[1]; mo = +m[2] - 1; d = +m[3]; hasYear = true; }
    else if ((m = date.match(/^(\d{2})-(\d{2})$/))) { mo = +m[1] - 1; d = +m[2]; }
    else if ((m = date.match(/^([A-Za-z]{3})\/(\d{2})(?:\/(\d{4}))?$/))) {
      const k = MIKROTIK_MONTHS[m[1].toLowerCase()];
      if (k === undefined) return null;
      mo = k; d = +m[2]; if (m[3]) { y = +m[3]; hasYear = true; }
    } else return null;
  }
  const r = new Date(y, mo, d, hh, mi, ss);
  if (isNaN(r.getTime())) return null;
  // 只有日期沒有年份時比照 parseSyslogTimestamp() 的跨年推算；只有時間（當天）不處理
  return date && !hasYear ? fixFutureYear(r, ref) : r;
}
function parseMikroTikLine(line, lineNo) {
  const m = line.match(MIKROTIK_LINE_RE);
  if (!m) return null;
  const [, pri, date, time, rest] = m;
  if (pri === undefined && !time) return null;
  const mt = parseMikroTikMsg(rest);
  if (!mt || !mt.topics.length) return null;
  const hasPri = pri !== undefined;
  const priNum = hasPri ? Number(pri) : null;
  const facility = hasPri ? Math.floor(priNum / 8) : null;
  const severityRaw = hasPri ? priNum % 8 : null;
  return {
    format: 'mikrotik', raw: line, lineNo, mikrotik: true, netFields: true, netVendor: 'mikrotik',
    timestamp: parseMikroTikTimestamp(date, time), timestampRaw: [date, time].filter(Boolean).join(' '),
    host: '', appName: '', procid: '', msgid: '',
    severityRaw, severityNorm: hasPri ? normSyslogSeverity(severityRaw) : mikrotikTopicSeverity(mt.topics),
    facility, facilityAuth: hasPri && (facility === 4 || facility === 10),
    msg: rest, fields: mt.fields
  };
}
function parseLogLine(line, lineNo) {
  line = line.replace(OCTET_COUNT_RE, '');
  const fmt = detectLineFormat(line);
  if (fmt === 'pancsv') return parsePanCSVLine(line, lineNo);
  if (fmt === 'umbrella') return parseUmbrellaLine(line, lineNo);
  if (fmt === 'rfc5424') return parseRFC5424Line(line, lineNo);
  if (fmt === 'cef') return parseCEFLine(line, lineNo);
  if (fmt === 'cef-syslog') return parseCEFInSyslogLine(line, lineNo);
  if (fmt === 'asa') return parseASALine(line, lineNo);
  if (fmt === 'ciscoios') return parseCiscoIOSLine(line, lineNo);
  if (fmt === 'comware') return parseComwareLine(line, lineNo);
  if (fmt === 'leef') return parseLEEFLine(line, lineNo);
  if (fmt === 'rfc3164') return parseRFC3164Line(line, lineNo);
  if (fmt === 'fortigate') return parseFortiGateLine(line, lineNo);
  if (fmt === 'kvfw') return parseKvFwLine(line, lineNo);
  if (fmt === 'mikrotik') return parseMikroTikLine(line, lineNo);
  if (fmt === 'weblog') return parseWebAccessLine(line, lineNo);
  if (fmt === 'squid') return parseSquidLine(line, lineNo);
  if (fmt === 'meraki') return parseMerakiLine(line, lineNo);
  if (fmt === 'stormshield') return parseStormshieldLine(line, lineNo);
  if (fmt === 'fortimail' || fmt === 'fortimanager') return parseFortiMgmtLine(line, lineNo);
  if (fmt === 'vpnauth') return parseVpnFileLine(line, lineNo);
  if (fmt === 'haproxy') return parseHaproxyLine(line, lineNo);
  if (fmt === 'elb') return parseElbLine(line, lineNo);
  if (fmt === 's3') return parseS3AccessLine(line, lineNo);
  if (fmt === 'dns') return parseDnsServerLine(line, lineNo);
  if (fmt === 'dhcp') return parseWinDhcpLine(line, lineNo);
  if (fmt === 'nps') return parseNpsLine(line, lineNo);
  if (fmt === 'clearpass') return parseClearPassLine(line, lineNo);
  if (fmt === 'ldap') return parseDs389Line(line, lineNo);
  if (fmt === 'dbfile') return parseDbFileLine(line, lineNo);
  if (fmt === 'pcs') return parsePcsLine(line, lineNo);
  if (fmt === 'netscaler') return parseNetScalerLine(line, lineNo);
  return null;
}
// JSON log 沒有統一欄位規格，依常見別名（TS_KEYS/SEV_KEYS/HOST_KEYS/MSG_KEYS/APP_KEYS，定義於
// 下方情資/可選欄位模組附近，供全檔共用）best-effort 對應到既有事件 schema；分類判定沿用既有
// classifyByKeyword()（只看 msg/appName 文字），不額外針對 JSON 欄位擴充比對來源，維持單一判定
// 邏輯來源，且大多數 JSON log 的語意本就會落在 message 欄位而非另一組動作欄位
function looksLikeLogRecord(obj) {
  if (isZeekLog(obj)) return true;
  return !!(pickField(obj, TS_KEYS) || pickField(obj, SEV_KEYS) || pickField(obj, MSG_KEYS) || pickField(obj, HOST_KEYS));
}
// Cisco Secure Endpoint（AMP for Endpoints）事件（第十五輪 VH）：欄位依 Elastic Beats cisco amp 模組的真實測試資料——
// event_type（Threat Detected／Threat Quarantined／Retrospective Detection／Quarantine Failure／Cloud IOC…）、severity（Low～Critical）、
// detection、computer.hostname／external_ip／network_addresses[].ip／mac、file.disposition／file_name／file_path／identity.sha256、
// network_info.local_ip／local_port／remote_ip／remote_port／nfm.protocol。原始事件另存 ampRaw 供去識別化後重建
const AMP_SEV = { Critical: 'Critical', High: 'High', Medium: 'Medium', Low: 'Low' };
function isCiscoAmpEvent(o) { return !!o && typeof o === 'object' && typeof o.event_type === 'string' && !!o.computer && o.connector_guid !== undefined; }
function ampFields(a) {
  const c = a.computer || {}, file = a.file || {}, n = a.network_info || {};
  const f = { ampType: a.event_type };
  if (a.detection) f.detection = a.detection;
  if (c.hostname) f.computer = c.hostname;
  const ip = n.local_ip || ((c.network_addresses || [])[0] || {}).ip;
  if (ip) f.srcip = ip;
  if (n.local_port) f.srcport = String(n.local_port);
  if (n.remote_ip) f.dstip = n.remote_ip;
  if (n.remote_port) f.dstport = String(n.remote_port);
  if (n.nfm && n.nfm.protocol) f.proto = String(n.nfm.protocol).toLowerCase();
  if (c.external_ip) f.natsrcip = c.external_ip;
  if (file.disposition) f.disposition = file.disposition;
  if (file.file_name) f.filename = file.file_name;
  if (file.file_path) f.filepath = file.file_path;
  if (file.identity && file.identity.sha256) f.sha256 = file.identity.sha256;
  return f;
}
function ampEvent(a, lineNo) {
  const t = new Date(a.date || (a.timestamp ? a.timestamp * 1000 : NaN));
  const f = ampFields(a);
  return {
    format: 'json', raw: JSON.stringify(a), lineNo, netFields: !!f.srcip, netVendor: 'amp', ampRaw: a,
    timestamp: isNaN(t.getTime()) ? null : t, timestampRaw: a.date || String(a.timestamp || ''),
    host: f.computer || '', appName: 'secure-endpoint', procid: '', msgid: a.event_type,
    severityRaw: a.severity || '', severityNorm: AMP_SEV[a.severity] || 'Info', facility: null, facilityAuth: false,
    url: '', httpMethod: '',
    msg: [a.event_type, a.detection, f.filename].filter(Boolean).join(' — '), fields: f
  };
}
// 威脅類事件（偵測、隔離、隔離失敗、雲端 IOC、惡意程式執行…）
const AMP_THREAT_RE = /threat|detection|malware|malicious|quarantine|ioc|dropper|infect|vulnerab/i;
// Zeek（第十八輪 TI）：JSON log 每行一個物件，ts（Unix 秒或 ISO）、uid、id.orig_h／id.orig_p／id.resp_h／id.resp_p 為共同欄位，
// log 種類由 _path（有設定時）或欄位形狀判斷——conn（conn_state）、dns（query＋qtype／rcode）、http（method＋uri／host）、
// ssh（auth_success）、notice（note）、intel（seen.indicator）、ssl（server_name／ja3）、files（fuid＋mime_type）、weird（name＋notice）。
// 欄位依 Zeek 官方 log 說明與 Elastic Beats zeek 模組的真實測試 log。TSV 格式（#separator／#fields 表頭）另由 parseZeekTsv() 轉成同樣的物件
function zeekGet(o, k) { if (k in o) return o[k]; return k.split('.').reduce((v, p) => (v && typeof v === 'object' ? v[p] : undefined), o); }
function isZeekLog(o) {
  if (!o || typeof o !== 'object' || o.ts === undefined) return false;
  if (zeekGet(o, 'id.orig_h') !== undefined || typeof o.uid === 'string' || typeof o.fuid === 'string' || typeof o._path === 'string') return true;
  // 沒有 uid 的種類：stats／capture_loss（peer）、notice（peer_descr）、dhcp（uids）、x509（certificate.*）、pe（id 為檔案 ID）、traceroute（src＋dst）
  return typeof o.ts === 'number' && (typeof o.peer === 'string' || 'peer_descr' in o || Array.isArray(o.uids) || 'certificate.version' in o || (typeof o.id === 'string' && /^F[A-Za-z0-9]{10,}$/.test(o.id)) || (typeof o.src === 'string' && typeof o.dst === 'string'));
}
function zeekType(o) {
  if (typeof o._path === 'string' && o._path) return o._path;
  if ('conn_state' in o) return 'conn';
  if ('query' in o && ('qtype' in o || 'rcode' in o || 'trans_id' in o)) return 'dns';
  if ('method' in o && ('uri' in o || 'host' in o)) return 'http';
  if ('auth_success' in o || ('kex_alg' in o && 'client' in o)) return 'ssh';
  if ('note' in o) return 'notice';
  if (zeekGet(o, 'seen.indicator') !== undefined) return 'intel';
  if ('server_name' in o || 'ja3' in o || ('cipher' in o && 'version' in o)) return 'ssl';
  if ('fuid' in o && 'mime_type' in o) return 'files';
  if ('name' in o && 'notice' in o) return 'weird';
  return 'zeek';
}
function zeekFields(o) {
  const f = { zeekType: zeekType(o) };
  const map = { srcip: 'id.orig_h', srcport: 'id.orig_p', dstip: 'id.resp_h', dstport: 'id.resp_p' };
  for (const [k, z] of Object.entries(map)) { const v = zeekGet(o, z); if (v !== undefined && v !== null && v !== '-') f[k] = String(v); }
  if (!f.srcip && o.src) f.srcip = String(o.src);
  if (!f.dstip && o.dst) f.dstip = String(o.dst);
  if (o.proto) f.proto = String(o.proto).toLowerCase();
  if (o.service) f.service = Array.isArray(o.service) ? o.service.join(',') : String(o.service);
  if (o.conn_state) f.connState = o.conn_state;
  if (f.zeekType === 'ssh' && o.auth_success !== undefined) f.authSuccess = String(o.auth_success);
  if (o.note) f.note = o.note;
  const ind = zeekGet(o, 'seen.indicator');
  if (ind !== undefined) f.indicator = String(ind);
  if (o.uid) f.uid = o.uid;
  ['md5', 'sha1', 'sha256'].forEach(k => { if (typeof o[k] === 'string') f[k] = o[k]; });   // files.log（第十九輪 EC）
  return f;
}
const ZEEK_DENY_STATES = new Set(['REJ', 'S0']);
function zeekMsg(o, f) {
  const tup = `${f.srcip || '-'}${f.srcport ? ':' + f.srcport : ''} -> ${f.dstip || '-'}${f.dstport ? ':' + f.dstport : ''}`;
  switch (f.zeekType) {
    case 'conn': return `${(f.proto || '').toUpperCase()} ${tup}${f.service ? ' ' + f.service : ''} ${o.conn_state || ''}`.trim();
    case 'dns': return `DNS ${o.query || ''} ${o.qtype_name || ''} ${o.rcode_name || ''} ${tup}`.replace(/\s+/g, ' ').trim();
    case 'http': return `${o.method || ''} ${o.host || ''}${o.uri || ''} ${o.status_code || ''} ${tup}`.replace(/\s+/g, ' ').trim();
    case 'ssh': return `SSH ${o.auth_success === false ? 'auth failed' : o.auth_success === true ? 'auth ok' : ''}${o.auth_attempts ? ' attempts=' + o.auth_attempts : ''} ${tup}`.replace(/\s+/g, ' ').trim();
    case 'notice': return `${o.note || 'Notice'}: ${o.msg || ''}${o.sub ? ' (' + o.sub + ')' : ''}`;
    case 'intel': return `Intel ${f.indicator || ''} [${zeekGet(o, 'seen.indicator_type') || ''}] ${(o.sources || []).join(', ')} ${tup}`.replace(/\s+/g, ' ').trim();
    case 'ssl': return `TLS ${o.server_name || ''} ${o.version || ''} ${tup}`.replace(/\s+/g, ' ').trim();
    case 'weird': return `weird ${o.name || ''} ${tup}`;
    default: return `${f.zeekType} ${tup}`;
  }
}
function zeekEvent(o, lineNo) {
  const f = zeekFields(o);
  const t = typeof o.ts === 'number' ? new Date(o.ts * 1000) : new Date(o.ts);
  if (f.zeekType === 'conn' && ZEEK_DENY_STATES.has(o.conn_state)) f.action = 'deny';
  const sev = f.zeekType === 'intel' ? 'High' : f.zeekType === 'notice' || (f.zeekType === 'ssh' && o.auth_success === false) ? 'Medium' : 'Info';
  return {
    format: 'json', raw: JSON.stringify(o), lineNo, netFields: !!(f.srcip && f.dstip), netVendor: 'zeek', zeekRaw: o,
    timestamp: isNaN(t.getTime()) ? null : t, timestampRaw: String(o.ts),
    host: '', appName: 'zeek', procid: '', msgid: f.zeekType,
    severityRaw: '', severityNorm: sev, facility: null, facilityAuth: false,
    url: '', httpMethod: o.method || '',
    msg: zeekMsg(o, f), fields: f
  };
}
// Zeek TSV：#separator \x09、#path、#fields 欄位名稱、#types；'-' 為未設定、'(empty)' 為空集合，set／vector 以 , 分隔
function parseZeekTsv(text) {
  if (!/^#separator\s/m.test(text) || !/^#fields\t/m.test(text)) return null;
  const events = [], unparsed = [];
  let cols = null, path = '';
  text.split('\n').forEach((line, i) => {
    if (!line.trim()) return;
    if (line.startsWith('#')) {
      if (line.startsWith('#fields\t')) cols = line.split('\t').slice(1);
      else if (line.startsWith('#path\t')) path = line.split('\t')[1];
      return;
    }
    const parts = line.split('\t');
    if (!cols || parts.length !== cols.length) { unparsed.push({ lineNo: i + 1, raw: line }); return; }
    const o = { _path: path };
    cols.forEach((c, k) => {
      const v = parts[k];
      if (v === '-' || v === undefined) return;
      if (v === '(empty)') { o[c] = []; return; }
      o[c] = c === 'ts' ? Number(v) : /^(?:T|F)$/.test(v) && /^(?:auth_success|local_orig|local_resp|AA|TC|RD|RA|rejected)$/.test(c) ? v === 'T' : /^(?:id\.orig_p|id\.resp_p|status_code|auth_attempts)$/.test(c) ? Number(v) : v;
    });
    events.push(zeekEvent(o, i + 1));
  });
  return events.length ? { events, unparsed } : null;
}
// CrowdStrike Falcon Streaming API 事件（第十八輪 TJ）：{metadata:{eventType, eventCreationTime(毫秒)…}, event:{…}}，常見匯出為
// 多個縮排 JSON 物件前後相接。欄位依 Elastic Beats crowdstrike 模組的真實測試資料——DetectionSummaryEvent（ComputerName、UserName、
// LocalIP、DetectName、DetectDescription、Severity 1～5／SeverityName、FileName、FilePath、CommandLine、SHA256String、Tactic、Technique、
// PatternDispositionDescription）、IncidentSummaryEvent（State、FineScore）、AuthActivityAuditEvent（UserId、UserIp、OperationName、Success）、
// UserActivityAuditEvent、RemoteResponseSession*、FirewallMatchEvent（ConnectionDirection "1" 為入站：來源為 RemoteAddress，否則來源為
// LocalAddress；RuleAction 數值意義未查證，不判斷允許／阻擋）。原始事件存 falconRaw 供去識別化重建
const FALCON_SEV = { 1: 'Info', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical' };
function isFalconEvent(o) { return !!o && typeof o === 'object' && !!o.metadata && typeof o.metadata.eventType === 'string' && !!o.event && typeof o.event === 'object'; }
function splitConcatJson(text) {
  const docs = []; let depth = 0, start = -1, inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) { if (esc) esc = false; else if (ch === '\\') esc = true; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') inStr = true;
    else if (ch === '{') { if (depth++ === 0) start = i; }
    else if (ch === '}') { if (depth > 0 && --depth === 0 && start >= 0) { try { docs.push(JSON.parse(text.slice(start, i + 1))); } catch (e) { /* 壞物件跳過 */ } start = -1; } }
  }
  return docs;
}
function falconFields(o) {
  const e = o.event, t = o.metadata.eventType, f = { falconType: t };
  const set = (k, v) => { if (v !== undefined && v !== null && v !== '') f[k] = String(v); };
  if (t === 'FirewallMatchEvent') {
    const inbound = String(e.ConnectionDirection) === '1';
    set('srcip', inbound ? e.RemoteAddress : e.LocalAddress); set('srcport', inbound ? e.RemotePort : e.LocalPort);
    set('dstip', inbound ? e.LocalAddress : e.RemoteAddress); set('dstport', inbound ? e.LocalPort : e.RemotePort);
    set('proto', FLOW_PROTO[String(e.Protocol)] || e.Protocol); set('rule', e.RuleName); set('policy', e.PolicyName); set('computer', e.HostName);
    set('direction', inbound ? 'inbound' : 'outbound');
  } else {
    set('computer', e.ComputerName || e.HostnameField || e.HostName);
    set('user', e.UserName || e.UserId);
    set('srcip', e.LocalIP || e.UserIp);
    set('detection', e.DetectName); set('tactic', e.Tactic); set('technique', e.Technique);
    set('filename', e.FileName); set('filepath', e.FilePath); set('sha256', e.SHA256String); set('md5', e.MD5String);
    set('disposition', e.PatternDispositionDescription); set('operation', e.OperationName);
    if (typeof e.Success === 'boolean') f.success = String(e.Success);
    set('state', e.State); set('score', e.FineScore);
  }
  return f;
}
function falconMsg(o, f) {
  const e = o.event;
  switch (f.falconType) {
    case 'DetectionSummaryEvent': return `${e.DetectName || 'Detection'}: ${e.DetectDescription || ''}${e.FileName ? ' (' + e.FileName + ')' : ''}${e.Tactic ? ' [' + e.Tactic + (e.Technique ? ' / ' + e.Technique : '') + ']' : ''}`;
    case 'IncidentSummaryEvent': return `Incident ${e.State || ''} score=${e.FineScore !== undefined ? e.FineScore : '-'}`;
    case 'AuthActivityAuditEvent': return `${e.OperationName || 'auth'} ${e.Success === false ? 'FAILURE' : 'success'} ${e.UserId || ''}${e.UserIp ? ' from ' + e.UserIp : ''}`.trim();
    case 'UserActivityAuditEvent': return `${e.OperationName || ''} ${e.ServiceName || ''} ${e.UserId || ''}${e.UserIp ? ' from ' + e.UserIp : ''}`.replace(/\s+/g, ' ').trim();
    case 'FirewallMatchEvent': return `FW ${f.direction} ${(f.proto || '').toUpperCase()} ${f.srcip || '-'}${f.srcport ? ':' + f.srcport : ''} -> ${f.dstip || '-'}${f.dstport ? ':' + f.dstport : ''}${f.rule ? ' rule=' + f.rule : ''}`;
    default: return `${f.falconType} ${f.user || ''} ${f.computer || ''}`.trim();
  }
}
function falconEvent(o, lineNo) {
  const f = falconFields(o), e = o.event;
  const t = new Date(Number(o.metadata.eventCreationTime));
  let sev = 'Info';
  if (f.falconType === 'DetectionSummaryEvent') sev = FALCON_SEV[e.Severity] || (['Critical', 'High', 'Medium', 'Low'].includes(e.SeverityName) ? e.SeverityName : 'Medium');
  else if (f.falconType === 'IncidentSummaryEvent') sev = 'Medium';
  else if (f.success === 'false') sev = 'Medium';
  return {
    format: 'json', raw: JSON.stringify(o), lineNo, netFields: !!(f.srcip && f.dstip), netVendor: 'falcon', falconRaw: o,
    timestamp: isNaN(t.getTime()) ? null : t, timestampRaw: String(o.metadata.eventCreationTime || ''),
    host: f.computer || '', appName: 'crowdstrike', procid: '', msgid: f.falconType,
    severityRaw: String(e.Severity || e.SeverityName || ''), severityNorm: sev, facility: null, facilityAuth: false,
    url: '', httpMethod: '', msg: falconMsg(o, f), fields: f
  };
}
// Microsoft Defender for Endpoint 告警與 Microsoft 365 Defender 事件（第十八輪 TK）：欄位依 Elastic Beats microsoft 模組的真實測試資料——
// MDE 告警（alerts API）：title、category、severity（Informational／Low／Medium／High）、status、determination、classification、
// alertCreationTime、detectionSource、computerDnsName、relatedUser.userName／domainName、evidence（ipAddress、fileName、sha256、
// accountName、userPrincipalName、url）、mitreTechniques；365 Defender 事件（incidents API）：incidentId、incidentName、severity、status、
// createdTime、alerts（陣列或單筆，欄位同上，主機在 devices[].deviceDnsName、實體在 entities）。每筆告警一筆事件，原始物件存 defRaw
const DEFENDER_SEV = { High: 'High', Medium: 'Medium', Low: 'Low', Informational: 'Info', Critical: 'Critical' };
function isDefenderAlert(o) { return !!o && typeof o === 'object' && typeof o.title === 'string' && ('alertCreationTime' in o || 'creationTime' in o) && 'detectionSource' in o; }
function isM365Incident(o) { return !!o && typeof o === 'object' && 'incidentId' in o && 'incidentName' in o && !!o.alerts && typeof o.alerts === 'object'; }
function defenderFields(a, inc) {
  const list = v => (Array.isArray(v) ? v : v && typeof v === 'object' ? [v] : []);
  const ents = [...list(a.evidence), ...list(a.entities)];
  const pick = k => { const e = ents.find(x => x && x[k]); return e ? String(e[k]) : ''; };
  const f = { defType: inc ? 'm365' : 'mde', title: a.title };
  const set = (k, v) => { if (v !== undefined && v !== null && v !== '') f[k] = String(v); };
  set('category', a.category); set('severity', a.severity); set('status', a.status);
  set('determination', a.determination || a.classification); set('detectionSource', a.detectionSource);
  set('computer', a.computerDnsName || (list(a.devices)[0] || {}).deviceDnsName);
  set('user', (a.relatedUser && a.relatedUser.userName) || pick('accountName') || pick('userPrincipalName'));
  set('srcip', pick('ipAddress'));
  set('filename', pick('fileName')); set('sha256', pick('sha256')); set('url', pick('url'));
  const mt = list(a.mitreTechniques).filter(x => typeof x === 'string');
  if (mt.length) f.mitre = mt.join(',');
  if (inc) { set('incidentId', inc.incidentId); set('incidentName', inc.incidentName); }
  return f;
}
function defenderEvent(a, inc, lineNo, raw) {
  const f = defenderFields(a, inc);
  const t = new Date(a.alertCreationTime || a.creationTime || (inc && inc.createdTime) || '');
  return {
    format: 'json', raw: JSON.stringify(raw), lineNo, netFields: false, netVendor: 'defender', defRaw: raw, defInc: !!inc,
    timestamp: isNaN(t.getTime()) ? null : t, timestampRaw: a.alertCreationTime || a.creationTime || '',
    host: f.computer || '', appName: inc ? 'm365-defender' : 'defender-endpoint', procid: '', msgid: f.category || '',
    severityRaw: a.severity || '', severityNorm: DEFENDER_SEV[a.severity] || 'Medium', facility: null, facilityAuth: false,
    url: f.url || '', httpMethod: '',
    msg: `${a.title}${f.category ? ' [' + f.category + ']' : ''}${f.status ? ' ' + f.status : ''}${f.mitre ? ' ' + f.mitre : ''}`, fields: f
  };
}
function defenderEvents(o, lineNo) {
  if (isDefenderAlert(o)) return [defenderEvent(o, null, lineNo, o)];
  const alerts = Array.isArray(o.alerts) ? o.alerts : [o.alerts];
  return alerts.filter(a => a && typeof a.title === 'string').map(a => defenderEvent(a, o, lineNo, o));
}
// Suricata EVE JSON（第十四輪 OG）：每行一個物件，event_type 為 alert／flow／dns／http…，src_ip／src_port／dest_ip／
// dest_port／proto 在頂層，alert 物件含 action（allowed／blocked）、signature_id、signature、category、severity（1 最高、3 最低）。
// 欄位依 Elastic Beats suricata 模組的真實 eve 測試 log。alert 以 signature 為訊息、severity 換算等級，IPS 模式 blocked 視為拒絕
const SURICATA_SEV = { 1: 'High', 2: 'Medium', 3: 'Low' };
function isSuricataEve(obj) { return !!obj && typeof obj.event_type === 'string' && obj.timestamp !== undefined && ('src_ip' in obj || 'flow_id' in obj); }
// 雲端身分／稽核平台登入紀錄（第十六輪 PF）：欄位依 Elastic Beats 各模組的真實測試 log 與 ingest 規則——
// Microsoft Entra ID（Azure AD）sign-in logs：category 以 SignInLogs 結尾，resultType 為錯誤碼、"0" 為成功（Beats 以
//   properties.status.errorCode 非 0 判為失敗），帳號 properties.userPrincipalName、來源 properties.ipAddress／callerIpAddress
// Okta System Log：eventType＋outcome.result（SUCCESS／FAILURE／ALLOW／DENY…），帳號 actor.alternateId、來源 client.ipAddress；
//   只把 user.session.start 與 user.authentication.* 的 FAILURE 當登入失敗
// Microsoft 365 稽核：Operation UserLoggedIn／UserLoginFailed，帳號 UserId、來源 ClientIP
// Google Workspace Reports API（applicationName login）：events.name login_success／login_failure，帳號 actor.email、來源 ipAddress
// AWS CloudTrail：eventName ConsoleLogin，responseElements.ConsoleLogin Success／Failure，帳號 userIdentity.userName、來源 sourceIPAddress
function cloudAuthInfo(o) {
  if (!o || typeof o !== 'object') return null;
  const g = (...path) => path.reduce((v, k) => (v && typeof v === 'object') ? v[k] : undefined, o);
  if (/SignInLogs$/.test(String(o.category || '')) && o.resultType !== undefined) {
    return { vendor: 'entra', event: o.operationName || 'Sign-in activity', user: g('properties', 'userPrincipalName') || o.identity || '',
      ip: g('properties', 'ipAddress') || o.callerIpAddress || '', login: true, ok: String(o.resultType) === '0', reason: o.resultDescription || '', ts: o.time };
  }
  // Entra ID 稽核 log（XN80）：category AuditLogs，欄位依 Elastic integrations azure auditlogs 的真實測試 log（properties.activityDisplayName、
  // initiatedBy.user.userPrincipalName 或 initiatedBy.app.displayName、result）；vendor 與登入紀錄分開，不影響登入類判斷
  if (o.category === 'AuditLogs' && g('properties', 'activityDisplayName')) {
    return { vendor: 'entraaudit', event: g('properties', 'activityDisplayName'), user: g('properties', 'initiatedBy', 'user', 'userPrincipalName') || g('properties', 'initiatedBy', 'app', 'displayName') || '',
      ip: g('properties', 'initiatedBy', 'user', 'ipAddress') || '', login: false, ok: String(g('properties', 'result') || '').toLowerCase() === 'success', reason: g('properties', 'resultReason') || '', ts: o.time };
  }
  if (typeof o.eventType === 'string' && o.outcome && o.actor && o.published) {
    const res = String(g('outcome', 'result') || '').toUpperCase();
    return { vendor: 'okta', event: o.eventType, user: g('actor', 'alternateId') || '', ip: g('client', 'ipAddress') || '',
      login: /^user\.(?:session\.start|authentication\.)/.test(o.eventType), ok: res !== 'FAILURE', reason: g('outcome', 'reason') || '', ts: o.published };
  }
  if (typeof o.Operation === 'string' && o.Workload && o.CreationTime) {
    return { vendor: 'm365', event: o.Operation, user: o.UserId || '', ip: o.ClientIP || o.ActorIpAddress || '',
      login: /^UserLog(?:gedIn|inFailed)$/.test(o.Operation), ok: o.Operation !== 'UserLoginFailed', reason: o.LogonError || '', ts: o.CreationTime + (/Z|[+-]\d\d:?\d\d$/.test(o.CreationTime) ? '' : 'Z') };
  }
  if (o.kind === 'admin#reports#activity' && o.id) {
    const evs = [].concat(o.events || []);
    const names = evs.map(e => e && e.name).filter(Boolean);
    const isLogin = g('id', 'applicationName') === 'login';
    return { vendor: 'gws', event: names.join(',') || g('id', 'applicationName') || '', user: g('actor', 'email') || '', ip: o.ipAddress || '',
      login: isLogin && names.some(n => /^login_(?:success|failure)$/.test(n)), ok: !names.includes('login_failure'), reason: '', ts: g('id', 'time') };
  }
  // Azure Activity Log（第二十輪 FE）：Event Hub／儲存體匯出的 resource log 形狀——time、resourceId、operationName、category
  // （Administrative／Action／Write…）、resultType（Success／Failure／Start…）、callerIpAddress、identity.claims（帳號在 upn 或 name 宣告）
  // 欄位依 Microsoft activity log schema 與 Elastic Beats azure activitylogs 測試 log；SignInLogs 已在上方處理
  if (typeof o.operationName === 'string' && typeof o.resourceId === 'string' && o.time && 'resultType' in o && /^(?:Administrative|Action|Write|Delete|Policy|Security|ResourceHealth|ServiceHealth|Alert|Autoscale|Recommendation)$/i.test(String(o.category || ''))) {
    const cl = g('identity', 'claims') || {};
    const claim = suf => { const k = Object.keys(cl).find(x => x === suf || x.endsWith('/' + suf)); return k ? cl[k] : ''; };
    return { vendor: 'azact', event: o.operationName, user: claim('upn') || claim('name') || o.caller || '', ip: o.callerIpAddress || '',
      login: false, ok: !/^fail/i.test(String(o.resultType)), pending: /^(?:start|accept(?:ed)?)$/i.test(String(o.resultType)), reason: o.resultSignature || '', ts: o.time };
  }
  // GCP Cloud Audit Logs（第二十輪 FE）：protoPayload 為 type.googleapis.com/google.cloud.audit.AuditLog，methodName、
  // authenticationInfo.principalEmail、requestMetadata.callerIp、status.code（非 0 為失敗）；欄位依 Google 官方 AuditLog 結構與 Beats gcp audit 測試 log
  if (o.protoPayload && /google\.cloud\.audit\.AuditLog$/.test(String(g('protoPayload', '@type') || '')) && o.timestamp) {
    const code = g('protoPayload', 'status', 'code');
    return { vendor: 'gcpaudit', event: g('protoPayload', 'methodName') || '', user: g('protoPayload', 'authenticationInfo', 'principalEmail') || '',
      ip: g('protoPayload', 'requestMetadata', 'callerIp') || '', login: false, ok: !code, reason: g('protoPayload', 'status', 'message') || '', ts: o.timestamp };
  }
  // Duo 驗證 log（第二十三輪 IF，Admin API v2 /admin/v2/logs/authentication 的 response.authlogs 項目，欄位依 Elastic integrations
  // cisco_duo 套件的真實測試資料）：txid、event_type（authentication／enrollment）、result（success／denied／fraud…）、reason、factor、
  // user.name、access_device.ip（可能帶埠）、application.name、isotimestamp（或 Unix 秒 timestamp）
  if (typeof o.txid === 'string' && typeof o.result === 'string' && typeof o.event_type === 'string' && (o.access_device || o.user)) {
    const ipRaw = String(g('access_device', 'ip') || '');
    const ip = (ipRaw.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/) || ipRaw.match(/^\[([0-9A-Fa-f:]+)\](?::\d+)?$/) || ipRaw.match(/^([0-9A-Fa-f:]+)$/) || [])[1] || '';  // IPv6 只有加方括號時才可能接埠號
    return { vendor: 'duo', event: `${o.event_type} ${o.result}`, user: g('user', 'name') || o.email || '', ip, login: o.event_type === 'authentication', ok: o.result === 'success',
      fraud: o.result === 'fraud', reason: [o.reason, o.factor, g('application', 'name')].filter(Boolean).join(' '),
      ts: o.isotimestamp || (typeof o.timestamp === 'number' ? new Date(o.timestamp * 1000).toISOString() : '') };
  }
  // Kubernetes 稽核 log（第二十三輪 ID，欄位依 kubernetes staging/src/k8s.io/apiserver/pkg/apis/audit/v1/types.go）：kind Event、
  // apiVersion audit.k8s.io/v1、verb、user.username、sourceIPs、objectRef.resource／subresource／namespace／name、responseStatus.code、
  // stage（RequestReceived／ResponseStarted／ResponseComplete／Panic，同一請求可能記多筆，只有 ResponseComplete／Panic 算完成）
  if (o.kind === 'Event' && /^audit\.k8s\.io\//.test(String(o.apiVersion || '')) && typeof o.verb === 'string') {
    const ref = o.objectRef || {};
    const code = Number(g('responseStatus', 'code')) || 0;
    const res = [ref.resource, ref.subresource].filter(Boolean).join('/');
    return { vendor: 'k8s', event: `${o.verb} ${res || o.requestURI || ''}`.trim(), verb: o.verb, resource: res, ns: ref.namespace || '', objName: ref.name || '', status: code,
      user: g('user', 'username') || '', ip: [].concat(o.sourceIPs || [])[0] || '', login: code === 401, ok: !(code >= 400),
      pending: !!o.stage && !/^(?:ResponseComplete|Panic)$/.test(o.stage), reason: g('responseStatus', 'reason') || g('responseStatus', 'message') || '', ts: o.stageTimestamp || o.requestReceivedTimestamp };
  }
  if (o.eventSource && o.eventName && o.eventTime && o.userIdentity) {
    const arn = String(g('userIdentity', 'arn') || '');
    return { vendor: 'cloudtrail', event: o.eventName, user: g('userIdentity', 'userName') || (arn.includes('/') ? arn.split('/').pop() : '') || g('userIdentity', 'type') || '',
      ip: o.sourceIPAddress || '', login: o.eventName === 'ConsoleLogin', ok: !(o.eventName === 'ConsoleLogin' && g('responseElements', 'ConsoleLogin') === 'Failure') && !o.errorCode,
      reason: o.errorMessage || o.errorCode || '', ts: o.eventTime };
  }
  return null;
}
const CLOUD_AUTH_APP = { vault: 'HashiCorp Vault', entra: 'Entra ID', entraaudit: 'Entra ID Audit', okta: 'Okta', m365: 'Microsoft 365', gws: 'Google Workspace', cloudtrail: 'CloudTrail', azact: 'Azure Activity Log', gcpaudit: 'GCP Cloud Audit Logs', k8s: 'Kubernetes Audit', duo: 'Duo' };
function cloudAuthEvent(o, ci, lineNo) {
  const t = new Date(ci.ts || '');
  const f = Object.assign({}, o, { cloudEvent: ci.event, cloudOutcome: ci.ok ? 'success' : 'failure' });
  // 原始事件的 user 可能是物件（Kubernetes 未通過驗證時為 {}），沒有帳號時不留物件，畫面才不會出現 [object Object]
  if (ci.user) f.user = ci.user; else if (f.user && typeof f.user === 'object') delete f.user;
  if (ci.ip && /^[0-9A-Fa-f:.]+$/.test(ci.ip)) f.srcip = ci.ip;
  return {
    format: 'json', raw: JSON.stringify(o), lineNo, netFields: !!f.srcip, netVendor: ci.vendor, cloudRaw: o,
    timestamp: isNaN(t.getTime()) ? null : t, timestampRaw: ci.ts || '',
    host: '', appName: CLOUD_AUTH_APP[ci.vendor], procid: '', msgid: ci.event,
    severityRaw: '', severityNorm: ci.login && !ci.ok ? 'Medium' : 'Info', facility: null, facilityAuth: false,
    url: '', httpMethod: '',
    msg: [ci.event, ci.ok ? '' : 'FAILURE', ci.user, ci.ip ? 'from ' + ci.ip : '', ci.reason].filter(Boolean).join(' '), fields: f
  };
}
// ── 雲端防火牆 log（第二十二輪 HE，格式依 Elastic integrations aws／azure firewall_logs 的真實測試 log）──
// AWS Network Firewall：{firewall_name, availability_zone, event_timestamp, event:{Suricata EVE（alert／netflow／tls…）}}，
//   內層沿用 Suricata 處理（告警進 idsAlert、blocked 為拒絕），主機為防火牆名稱
// Azure Firewall 診斷 log：舊版 category AzureFirewallNetworkRule／ApplicationRule（properties.msg 字串
//   「協定[ Type=N] request from 來源[:埠] to 目的[:埠]. Action: 動作. …」，operationName 含 ThreatIntel 為威脅情資）
//   與結構化 AZFWNetworkRule／AZFWApplicationRule／AZFWNatRule／AZFWThreatIntel 等（SourceIp／DestinationIp／Fqdn／Action／Rule…）；
//   可為逐行 JSON 或 {"records":[…]}；Deny 為拒絕、威脅情資為 attack
const isAwsNfwLog = o => !!o && typeof o.firewall_name === 'string' && !!o.event && isSuricataEve(o.event);
const isAzureFwLog = o => !!o && typeof o.category === 'string' && /^(?:AzureFirewall\w+|AZFW\w+)$/.test(o.category) && !!o.properties && typeof o.properties === 'object';
const AZFW_MSG_RE = /^(\w+)(?: Type=(\d+))?\s+request from (\S+?)(?::(\d+))?(?: to (\S+?)(?::(\d+))?)?\.(?: Url: (\S+)\.)? Action: (\w+)\.?\s*(.*)$/;
// DNS Proxy 舊版 msg 為 CoreDNS 格式：DNS Request: 用戶端:埠 - 編號 類型 類別 名稱 協定 大小 do 緩衝 RCODE …；新版 AZFWDnsQuery 為結構化欄位
// 舊版 NAT 規則 msg：TCP request from A:P to B:Q was DNAT'ed to C:R（Microsoft Azure Firewall 記錄文件）
const AZFW_DNAT_RE = /^(\w+) request from (\S+?):(\d+) to (\S+?):(\d+) was DNAT'ed to (\S+?):(\d+)/;
const AZFW_DNS_RE = /^DNS Request: (\S+):(\d+) - \d+ (\S+) \S+ (\S+) \w+ \d+ \w+ \d+ ([A-Z]+)/;
function nfwEvent(obj, lineNo) {
  const e = eventFromJSONObject(obj.event, lineNo);
  return Object.assign(e, { raw: JSON.stringify(obj), host: obj.firewall_name, nfwRaw: obj, appName: 'aws-network-firewall' });
}
function azfwEvent(obj, lineNo) {
  const p = obj.properties, f = { azfw: obj.category };
  const isIp = v => /^[\d.]+$|:/.test(String(v || ''));
  const dm = typeof p.msg === 'string' ? p.msg.match(AZFW_DNS_RE) : null;
  if (dm) Object.assign(f, { dns: 'reply', srcip: dm[1], srcport: dm[2], qtype: dm[3], domain: dnsName(dm[4]), rcode: dm[5] });
  else if (p.QueryName) Object.assign(f, { dns: 'reply', srcip: String(p.SourceIp || ''), srcport: String(p.SourcePort || ''), qtype: String(p.QueryType || ''), domain: dnsName(p.QueryName), rcode: String(p.ResponseCode || '') });
  else if (typeof p.msg === 'string') {
    const m = p.msg.match(AZFW_MSG_RE);
    if (m) {
      Object.assign(f, { proto: m[1], srcip: m[3], actionRaw: m[8] });
      if (m[6]) f.dstport = m[6];
      if (m[2]) f.icmptype = m[2];
      if (m[4]) f.srcport = m[4];
      if (m[5]) { if (isIp(m[5])) f.dstip = m[5]; else f.fqdn = m[5]; }
      if (m[7]) f.url = m[7];
      const ti = m[9].match(/ThreatIntel:\s*([^.]+)/);
      if (ti || /ThreatIntel/i.test(obj.operationName || '')) f.threatIntel = ti ? ti[1].trim() : 'ThreatIntel';
      const r = m[9].match(/Rule Collection: ([^.]+)\. Rule: ([^.,]+)/);
      if (r) { f.ruleCollection = r[1]; f.rule = r[2]; }
      const pol = m[9].match(/Policy: ([^.]+)\./);
      if (pol) f.policy = pol[1];
    } else {
      const d = p.msg.match(AZFW_DNAT_RE);
      if (d) Object.assign(f, { proto: d[1], srcip: d[2], srcport: d[3], dstip: d[4], dstport: d[5], natip: d[6], natport: d[7], actionRaw: 'Dnat' });
    }
  } else {
    const g = k => (p[k] === undefined || p[k] === null || p[k] === '' ? '' : String(p[k]));
    Object.assign(f, { proto: g('Protocol'), srcip: g('SourceIp'), srcport: g('SourcePort'), dstip: g('DestinationIp'), dstport: g('DestinationPort'),
      actionRaw: g('Action'), rule: g('Rule'), ruleCollection: g('RuleCollection'), policy: g('Policy') });
    if (g('Fqdn')) f.fqdn = g('Fqdn');
    if (g('TargetUrl')) f.url = g('TargetUrl');
    if (g('TranslatedIp')) { f.natip = g('TranslatedIp'); f.natport = g('TranslatedPort'); }
    if (/ThreatIntel/i.test(obj.category)) f.threatIntel = g('ThreatDescription') || 'ThreatIntel';
    Object.keys(f).forEach(k => { if (f[k] === '') delete f[k]; });
  }
  f.action = /^(?:deny|drop)$/i.test(f.actionRaw || '') ? 'deny' : (/^(?:allow|dnat)$/i.test(f.actionRaw || '') ? 'accept' : (f.actionRaw || '').toLowerCase());
  const ts = new Date(obj.time || '');
  const host = String(obj.resourceId || '').split('/').pop() || '';
  return {
    format: 'json', raw: JSON.stringify(obj), lineNo, netFields: true, netVendor: 'azfw', azfwRaw: obj,
    timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: String(obj.time || ''),
    host, appName: 'azure-firewall', procid: '', msgid: obj.category, severityRaw: f.actionRaw || '',
    severityNorm: f.threatIntel ? 'High' : (f.action === 'deny' ? 'Low' : 'Info'), facility: null, facilityAuth: false, url: f.url || '', httpMethod: '',
    msg: f.dns ? `DNS ${f.qtype} ${f.domain} ${f.rcode} from ${f.srcip}` : `${(f.actionRaw || '').toUpperCase()} ${f.proto || ''} ${f.srcip || '-'}${f.srcport ? ':' + f.srcport : ''} -> ${f.fqdn || f.dstip || '-'}${f.dstport ? ':' + f.dstport : ''}${f.rule ? ' rule=' + f.rule : ''}${f.threatIntel ? ' ThreatIntel: ' + f.threatIntel : ''}`.replace(/\s+/g, ' ').trim(),
    fields: f
  };
}
// Cloudflare Logpush（第二十六輪 SE）：欄位依 Elastic integrations cloudflare_logpush 套件的真實測試 log——
// http_requests（EdgeStartTimestamp、ClientRequestHost／URI、EdgeResponseStatus、SecurityAction／WAFAction、OriginIP）
// 與 firewall_events（Datetime、Action、Kind、Source、RuleID、Description）。時間可為 ISO、Unix 秒、毫秒或奈秒字串。
// 以 weblog 事件輸出（可觸發 Web 路徑探測），封鎖／質詢類動作歸 denyBlock；原物件存 cfRaw 供去識別化重建
const CF_DENY_RE = /^(?:block|drop|challenge|jschallenge|js_challenge|managed_challenge|challenge_failed|jschallenge_failed|connection_close|ban)$/i;
function isCloudflareEvent(o) { return !!o && typeof o === 'object' && typeof o.RayID === 'string' && typeof o.ClientIP === 'string' && ('EdgeStartTimestamp' in o || 'Datetime' in o); }
function cfTime(v) {
  const t = String(v == null ? '' : v).trim();
  if (/^\d+$/.test(t)) return new Date(t.length >= 18 ? Number(t.slice(0, 13)) : t.length >= 13 ? Number(t) : Number(t) * 1000);
  return new Date(t);
}
function cloudflareEvent(o, lineNo) {
  const isFw = 'Datetime' in o && ('Action' in o || 'Kind' in o) && !('EdgeStartTimestamp' in o);
  const tsRaw = String(isFw ? o.Datetime : (o.EdgeStartTimestamp != null ? o.EdgeStartTimestamp : o.Datetime));
  const act = String((isFw ? o.Action : (o.SecurityAction || o.WAFAction || o.Action)) || '');
  const action = /^(?:unknown|)$/i.test(act) ? '' : act;
  const f = { cf: isFw ? 'firewall' : 'http', srcip: o.ClientIP, method: o.ClientRequestMethod || '', url: o.ClientRequestURI || o.ClientRequestPath || '',
    status: o.EdgeResponseStatus != null ? String(o.EdgeResponseStatus) : '', domain: o.ClientRequestHost || '' };
  const set = (k, v) => { if (v !== undefined && v !== null && v !== '') f[k] = String(v); };
  set('dstip', o.OriginIP); set('country', o.ClientCountry); set('asn', o.ClientASN);
  if (action) {
    set('action', action);
    set('rule', isFw ? o.RuleID : (o.SecurityRuleID || o.WAFRuleID));
    set('ruleDesc', isFw ? o.Description : (o.SecurityRuleDescription || o.WAFRuleMessage));
    set('cfSource', o.Source);
  }
  const evt = webEvent('weblog', JSON.stringify(o), lineNo, cfTime(tsRaw), tsRaw, f.domain, f);
  evt.netVendor = 'cloudflare'; evt.cfRaw = o; evt.appName = 'cloudflare';
  if (action && CF_DENY_RE.test(action) && evt.severityNorm === 'Info') evt.severityNorm = 'Low';
  evt.msg = `${f.method || '-'} ${f.domain}${f.url || ''} ${f.status || '-'}${action ? ' action=' + action : ''}${f.rule ? ' rule=' + f.rule : ''}${f.ruleDesc ? ' (' + f.ruleDesc + ')' : ''}`;
  return evt;
}
// Zscaler Internet Access NSS（XN113）：欄位依 Elastic integrations zscaler_zia 套件的真實測試 log，
// 外層 {"sourcetype":"zscalernss-web|fw|dns|audit","event":{…}}（NSS feed 的 JSON 輸出格式）。
// web：host、url／eurl（URL 編碼）／b64url（base64，「主機/路徑」）、reqmethod、respcode、action（Allowed／Blocked／Cautioned）、
//   login、cltintip（內部位址，優先）／cltip、threatname（None＝沒有）、threatseverity「High (70–89)」；
// fw：csip／csport → cdip／cdport、proto、nwapp、rule、action；dns：dns_req、clt_sip、dns_reqtype、reqaction／resaction；
// audit（管理入口網站稽核）：adminid、clientip、action（SIGN_IN／SIGN_OUT／CREATE…）、category、result。
// 時間取 time／datetime：tz 為 GMT／UTC 或空白時以 UTC 解讀，其他時區改用 epochtime（秒）
const ZS_TYPES = { 'zscalernss-web': 'web', 'zscalernss-fw': 'fw', 'zscalernss-dns': 'dns', 'zscalernss-audit': 'audit' };
const ZS_MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
// 管理稽核中不改變設定的動作
const ZS_READONLY_ACTION_RE = /^(?:SIGN_IN|SIGN_OUT|LOGIN|LOGOUT|DOWNLOAD|EXPORT|READ|VIEW|SEARCH|GET)$/i;
function isZscalerNss(o) { return !!o && typeof o === 'object' && typeof o.sourcetype === 'string' && !!ZS_TYPES[o.sourcetype.toLowerCase()] && !!o.event && typeof o.event === 'object'; }
function zsTime(ev) {
  const t = String(ev.time || ev.datetime || '').trim(), tz = String(ev.tz || ev.timezone || '').trim();
  const utc = !tz || /^(?:GMT|UTC|Z)$/i.test(tz);
  let m = t.match(/^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/);
  if (m && ZS_MONTHS[m[1]] !== undefined) {
    if (utc) return new Date(Date.UTC(+m[6], ZS_MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]));
  } else if ((m = t.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/)) && utc) {
    return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  }
  if (/^\d{9,11}$/.test(String(ev.epochtime || ''))) return new Date(Number(ev.epochtime) * 1000);
  return new Date(t);
}
function zsVal(v) { const s = v == null ? '' : String(v).trim(); return /^(?:|None|NA|N\/A|Unknown|-|0\.0\.0\.0)$/i.test(s) ? '' : s; }
// web 的網址：url／eurl 為完整網址或「主機/路徑」，b64url 為 base64；回傳 [主機, 路徑＋查詢字串]
function zsUrl(ev) {
  let u = zsVal(ev.url);
  if (!u && zsVal(ev.eurl)) { try { u = decodeURIComponent(ev.eurl); } catch (e) { u = String(ev.eurl); } }
  if (!u && zsVal(ev.b64url)) { try { u = atob(String(ev.b64url)); } catch (e) { u = ''; } }
  u = u.replace(/^[a-z][\w+.-]*:\/\//i, '');
  const i = u.indexOf('/');
  return i < 0 ? [u, '/'] : [u.slice(0, i), u.slice(i)];
}
function zsThreatSev(s) { const m = String(s || '').match(/^(Critical|High|Medium|Low)\b/i); return m ? { critical: 1, high: 1, medium: 2, low: 3 }[m[1].toLowerCase()] : 2; }
function zscalerEvent(o, lineNo) {
  const ev = o.event, type = ZS_TYPES[o.sourcetype.toLowerCase()];
  const ts = zsTime(ev), tsRaw = String(ev.time || ev.datetime || '');
  const f = { zs: type };
  const set = (k, v) => { const x = zsVal(v); if (x) f[k] = x; };
  const user = zsVal(ev.login) || zsVal(ev.user) || zsVal(ev.adminid);
  if (user) { try { f.user = decodeURIComponent(user); } catch (e) { f.user = user; } }
  set('action', ev.action);
  const threat = type === 'web' || type === 'fw' ? zsVal(ev.threatname) : '';
  if (threat) { f.threat = threat; set('threatcat', ev.threatcat || ev.malwarecat); set('threatsev', ev.threatseverity); }
  const base = { format: 'json', raw: JSON.stringify(o), lineNo, netFields: true, netVendor: 'zscaler', zsRaw: o,
    timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: tsRaw, host: '', appName: 'zscaler', procid: '', msgid: o.sourcetype,
    severityRaw: f.threatsev || '', severityNorm: threat ? (zsThreatSev(f.threatsev) === 1 ? 'High' : 'Medium') : (/^Block/i.test(f.action || '') ? 'Low' : 'Info'),
    facility: null, facilityAuth: false, url: '', httpMethod: '', fields: f };
  if (type === 'web') {
    const [h, path] = zsUrl(ev);
    set('srcip', zsVal(ev.cltintip) || ev.cltip); set('cltip', ev.cltip);
    set('domain', ev.host || h); set('dstip', ev.serverip);
    f.method = zsVal(ev.reqmethod).toUpperCase(); f.url = path; f.status = zsVal(ev.respcode); f.bytes = zsVal(ev.respsize) || '0';
    set('ua', ev.useragent); set('urlcat', ev.urlcat || ev.urlcategory); set('rule', ev.rulelabel || ev.urlfilterrulelabel);
    const evt = webEvent('weblog', base.raw, lineNo, base.timestamp, tsRaw, '', f);
    Object.assign(evt, { netVendor: 'zscaler', zsRaw: o, appName: 'zscaler', msgid: o.sourcetype, severityNorm: base.severityNorm === 'Info' ? evt.severityNorm : base.severityNorm });
    evt.msg = `${f.action || '-'} ${f.method || '-'} ${f.domain || ''}${f.url} ${f.status || '-'}${f.user ? ' ' + f.user : ''}${threat ? ' threat=' + threat : ''}`;
    return evt;
  }
  if (type === 'fw') {
    set('srcip', ev.csip); set('srcport', ev.csport); set('dstip', ev.cdip); set('dstport', ev.cdport);
    set('proto', ev.proto); set('app', ev.nwapp); set('svc', ev.nwsvc); set('rule', ev.rulelabel || ev.rule); set('domain', ev.cltdomain);
    base.msg = `${f.action || '-'} ${f.proto || ''} ${f.srcip || '-'}${f.srcport ? ':' + f.srcport : ''} -> ${f.dstip || '-'}${f.dstport ? ':' + f.dstport : ''}${f.rule ? ' rule=' + f.rule : ''}${threat ? ' threat=' + threat : ''}`.replace(/\s+/g, ' ').trim();
    return base;
  }
  if (type === 'dns') {
    f.dns = 'query'; set('domain', ev.dns_req); set('srcip', ev.clt_sip); set('qtype', ev.dns_reqtype); set('answer', ev.dns_resp);
    const act = zsVal(ev.reqaction) || zsVal(ev.resaction);
    if (act) f.action = act;
    base.msg = `DNS ${f.qtype || ''} ${f.domain || '-'} from ${f.srcip || '-'}${f.action ? ' ' + f.action : ''}`.replace(/\s+/g, ' ').trim();
    return base;
  }
  set('srcip', isValidIPv4(String(ev.clientip || '')) || String(ev.clientip || '').includes(':') ? ev.clientip : '');
  set('zsCat', ev.category); set('zsSub', ev.subcategory); set('resource', ev.resource); set('iface', ev.interface); set('result', ev.result); set('errorcode', ev.errorcode);
  base.netFields = !!f.srcip;
  base.msg = [f.user, f.action, [f.zsCat, f.zsSub].filter(Boolean).join('/'), f.resource, f.result].filter(Boolean).join(' ');
  return base;
}
function zsAuditFailed(f) { return f.zs === 'audit' && /^LOGIN$/i.test(f.zsCat || '') && /^(?:SIGN_IN|LOGIN)$/i.test(f.action || '') && !/^SUCCESS$/i.test(f.result || ''); }
// HashiCorp Vault 稽核 log（XN117）：欄位依 Elastic integrations hashicorp_vault 套件的真實測試 log 與 Vault 文件——
// 每行 JSON {time, type:request|response, auth:{display_name, policies, metadata}, request:{id, operation, path, mount_type, remote_address}, error}；
// 同一請求有 request 與 response 兩行，分類與偵測只看 response（結果與錯誤在 response），request 行列為一般事件。
// 登入（auth/<方法>/login…）有錯誤＝authFail，其他 permission denied＝denyBlock；kv 讀取接 secretReadOf()（XN80 機密大量讀取）；
// sys/ 底下的政策、認證方式、稽核裝置、掛載點等的建立／修改／刪除＝configChange（netOpsInfo）
function isVaultAudit(o) { return !!o && typeof o === 'object' && (o.type === 'request' || o.type === 'response') && !!o.request && typeof o.request.path === 'string' && 'auth' in o && !!o.time; }
const VAULT_CHANGE_RE = /^sys\/(?:policy|policies|auth|audit|mounts|generate-root|rekey|seal|config|namespaces|plugins|raw|replication|quotas)\b/;
const VAULT_LOGIN_RE = /^auth\/[^\/]+\/login\b/;
function vaultEvent(o, lineNo) {
  const a = o.auth || {}, r = o.request || {}, md = a.metadata || {};
  const loginUser = (String(r.path).match(/^auth\/[^\/]+\/login\/([^\/]+)$/) || [])[1];
  const user = md.username || md.email || loginUser || a.display_name || '';
  const err = typeof o.error === 'string' ? o.error.replace(/\s+/g, ' ').trim() : '';
  const f = { vault: o.type, srcip: r.remote_address || '', op: r.operation || '', path: r.path, mount: r.mount_type || '' };
  if (user) f.user = String(user);
  if (err) f.error = err;
  if (Array.isArray(a.policies) && a.policies.includes('root')) f.root = true;
  const t = new Date(o.time);
  return { format: 'json', raw: JSON.stringify(o), lineNo, netFields: !!f.srcip, netVendor: 'vault', vaultRaw: o,
    timestamp: isNaN(t.getTime()) ? null : t, timestampRaw: o.time, host: '', appName: 'vault', procid: '', msgid: o.type,
    severityRaw: '', severityNorm: err && o.type === 'response' ? 'Low' : 'Info', facility: null, facilityAuth: false, url: '', httpMethod: '',
    msg: `${o.type} ${f.op} ${f.path}${f.user ? ' ' + f.user : ''}${f.srcip ? ' from ' + f.srcip : ''}${err ? ' error=' + err.slice(0, 120) : ''}`, fields: f };
}
// ModSecurity 稽核 log（XN118）：欄位依 Elastic integrations modsecurity 套件的真實測試 log，兩種 JSON：
//   v3（libmodsecurity，nginx）{transaction:{client_ip, time_stamp, host_ip, host_port, request:{method, uri, headers}, response:{http_code},
//     messages:[{message, details:{ruleId, severity(0～7), data, tags}}]}}
//   v2（mod_security2 Apache JSON）{transaction:{time, remote_address}, request:{request_line, headers}, response:{status},
//     audit_data:{messages:["… [id \"932160\"] [msg \"…\"] [severity \"CRITICAL\"] …"], action:{intercepted}}}
// 以 weblog 事件輸出（漏洞利用、webshell 等 web 類偵測照常適用），命中的規則放 fields.waf（CRS 的計分與彙總規則 949／959／980 不列）；
// 有規則命中＝attack＋idsAlert，被攔截（v2 action.intercepted 或「Access denied」訊息、v3 回應 403）註明
const MODSEC_SEV = { EMERGENCY: 0, ALERT: 1, CRITICAL: 2, ERROR: 3, WARNING: 4, NOTICE: 5, INFO: 6, DEBUG: 7 };
const MODSEC_SKIP_RULE = /^(?:949|959|980)\d{3}$/;
function isModsecAudit(o) {
  const t = o && typeof o === 'object' && o.transaction;
  return !!t && typeof t === 'object' && ((t.request && 'messages' in t && ('client_ip' in t || 'time_stamp' in t)) || (o.audit_data && o.request && 'request_line' in o.request));
}
function modsecTime(s) {
  const m = String(s || '').match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*([+-])(\d{2})(\d{2})$/);
  if (m && ZS_MONTHS[m[2]] !== undefined) return new Date(Date.UTC(+m[3], ZS_MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]) - (m[7] === '-' ? -1 : 1) * (+m[8] * 60 + +m[9]) * 60000);
  return new Date(s);
}
function modsecEvent(o, lineNo) {
  const t = o.transaction, v2 = !!o.audit_data;
  const req = v2 ? o.request : t.request || {}, hdr = req.headers || {};
  const rl = v2 ? String(req.request_line || '').match(/^(\S+)\s+(\S+)/) : null;
  const rules = [];
  if (v2) (o.audit_data.messages || []).forEach(msg => {
    const g = k => (String(msg).match(new RegExp('\\[' + k + ' "([^"]*)"\\]')) || [])[1];
    if (g('id')) rules.push({ id: g('id'), msg: g('msg') || '', sev: MODSEC_SEV[String(g('severity') || '').toUpperCase()] });
  });
  else (t.messages || []).forEach(m => { const d = m.details || {}; if (d.ruleId) rules.push({ id: String(d.ruleId), msg: m.message || '', sev: d.severity !== undefined && d.severity !== '' ? +d.severity : undefined }); });
  const status = String(v2 ? (o.response || {}).status : (t.response || {}).http_code || '');
  const blocked = v2 ? !!(o.audit_data.action && o.audit_data.action.intercepted) || (o.audit_data.messages || []).some(x => /^Access denied/.test(x)) : status === '403';
  const f = { srcip: v2 ? t.remote_address : t.client_ip, method: v2 ? (rl ? rl[1] : '') : req.method || '', url: v2 ? (rl ? rl[2] : '') : req.uri || '', status, bytes: '0',
    domain: hdr.Host || hdr.host || '', waf: rules.filter(r => !MODSEC_SKIP_RULE.test(r.id)), wafBlocked: blocked };
  const ua = hdr['User-Agent'] || hdr['user-agent']; if (ua) f.ua = ua;
  const ts = v2 ? modsecTime(t.time) : new Date(t.time_stamp);
  const raw = JSON.stringify(o);
  const evt = webEvent('weblog', raw, lineNo, ts, String(v2 ? t.time : t.time_stamp), '', f);
  Object.assign(evt, { netVendor: 'modsec', modsecRaw: o, appName: 'modsecurity' });
  if (f.waf.length) evt.severityNorm = f.waf.some(r => r.sev !== undefined && r.sev <= 2) ? 'High' : 'Medium';
  evt.msg = `${f.method || '-'} ${f.url || '-'} ${status || '-'}${f.waf.length ? ' WAF ' + f.waf.map(r => r.id + (r.msg ? ' ' + r.msg : '')).join('; ').slice(0, 200) : ''}${blocked ? ' (blocked)' : ''}`;
  return evt;
}
// F5 BIG-IP Telemetry Streaming（XN119）：欄位依 Elastic integrations f5_bigip 套件的真實測試 log，每行 JSON 帶 telemetryEventCategory：
//   LTM（請求紀錄：src_ip／client_ip、vip／virtual_name、http_method、http_uri、http_status、http_host）→ weblog 事件；
//   ASM（WAF：ip_client、method、uri、query_string、response_code、request_status blocked／alerted／passed、attack_type、violations、sig_names、severity）
//     → weblog 事件，attack_type 或 violations 不是 N/A 時＝attack＋idsAlert；
//   AFM（source_ip:port → dest_ip:port、ip_protocol、action Accept／Drop／Reject、acl_rule_name、acl_policy_name）→ 流量事件，Drop／Reject＝denyBlock；
//   APM（Access_Policy_Result Logon_Deny＝authFail，Client_IP）。AVR、system、iHealth 等統計類不處理（交回一般 JSON）
const F5TS_CATS = /^(?:LTM|ASM|AFM|APM)$/;
function isF5Telemetry(o) { return !!o && typeof o === 'object' && typeof o.telemetryEventCategory === 'string' && F5TS_CATS.test(o.telemetryEventCategory); }
const f5na = v => { const s = v == null ? '' : String(v).trim(); return /^(?:|N\/A|NA|-|0\.0\.0\.0)$/i.test(s) ? '' : s; };
function f5tsEvent(o, lineNo) {
  const cat = o.telemetryEventCategory;
  const tsRaw = String(o.f5telemetry_timestamp || o.event_timestamp || o.date_time || o.req_start_time || '');
  const ts = new Date(tsRaw.replace(/^(\d{4})\/(\d{2})\/(\d{2})/, '$1-$2-$3T').replace(/T\s+/, 'T'));
  const raw = JSON.stringify(o);
  if (cat === 'LTM' || cat === 'ASM') {
    const host = (String(o.request || '').match(/\r?\nHost:\s*([^\r\n]+)/i) || [])[1] || o.http_host || '';
    const f = { f5: cat, srcip: f5na(o.ip_client || o.src_ip || o.client_ip), method: f5na(o.method || o.http_method), url: f5na(o.uri || o.http_uri) + (f5na(o.query_string) ? '?' + o.query_string : ''),
      status: f5na(o.response_code || o.http_status).replace(/^0$/, ''), bytes: '0',
      domain: /^\[/.test(host.trim()) ? host.trim().replace(/^\[([^\]]*)\].*$/, '$1') : host.trim().replace(/:\d+$/, '') };
    const vs = f5na(o.virtual_name || o.vip); if (vs) f.vs = vs;
    const ua = f5na(o.http_user_agent); if (ua) f.ua = ua;
    const user = f5na(o.username || o.user); if (user) f.user = user;
    if (cat === 'ASM') {
      f.asmStatus = f5na(o.request_status);
      const at = f5na(o.attack_type), vio = f5na(o.violations);
      if (at || vio) { f.asmAttack = at || vio; f.asmViolations = vio; f.asmSigs = f5na(o.sig_names); f.asmSev = f5na(o.severity); }
    }
    const evt = webEvent('weblog', raw, lineNo, ts, tsRaw, f5na(o.hostname), f);
    Object.assign(evt, { netVendor: 'f5', f5Raw: o, appName: 'f5-' + cat.toLowerCase() });
    if (f.asmAttack) evt.severityNorm = /^Critical$/i.test(f.asmSev) ? 'High' : 'Medium';
    evt.msg = `${cat} ${f.method || '-'} ${f.domain || ''}${f.url || '-'} ${f.status || '-'}${f.asmAttack ? ' attack=' + f.asmAttack + (f.asmStatus ? ' (' + f.asmStatus + ')' : '') : ''}`;
    return evt;
  }
  const f = { f5: cat };
  const set = (k, v) => { const x = f5na(v); if (x) f[k] = x; };
  let msg;
  if (cat === 'AFM') {
    set('srcip', o.source_ip); set('srcport', o.source_port); set('dstip', o.dest_ip); set('dstport', o.dest_port); set('proto', o.ip_protocol);
    set('rule', o.acl_rule_name); set('policy', o.acl_policy_name); set('user', o.source_user);
    f.action = String(o.action || '').toLowerCase();
    msg = `AFM ${o.action || '-'} ${f.proto || ''} ${f.srcip || '-'}${f.srcport ? ':' + f.srcport : ''} -> ${f.dstip || '-'}${f.dstport ? ':' + f.dstport : ''}${f.rule ? ' rule=' + f.rule : ''}`.replace(/\s+/g, ' ');
  } else {
    set('srcip', o.Client_IP || o.client_ip); set('user', o.Username || o.username || o.User_Name || o.user);
    set('apmResult', o.Access_Policy_Result); set('session', o.Session_Id || o.session_id || o.Session_ID);
    msg = `APM ${f.apmResult || o.errdefs_msgno || ''}${f.user ? ' ' + f.user : ''}${f.srcip ? ' from ' + f.srcip : ''}`.trim();
  }
  return { format: 'json', raw, lineNo, netFields: !!f.srcip, netVendor: 'f5', f5Raw: o,
    timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: tsRaw, host: f5na(o.hostname), appName: 'f5-' + cat.toLowerCase(), procid: '', msgid: cat,
    severityRaw: String(o.severity || ''), severityNorm: /^(?:drop|reject)$/.test(f.action || '') || /deny/i.test(f.apmResult || '') ? 'Low' : 'Info',
    facility: null, facilityAuth: false, url: '', httpMethod: '', msg, fields: f };
}
// GitLab 結構化 log（XN81）：api_json.log／production_json.log（請求）、audit_json.log（稽核）、application_json.log（訊息），
// 欄位依 Elastic integrations gitlab 套件的真實測試 log：remote_ip（可能為「用戶端, 代理」清單，取第一個）、method、path、route、status、
// username／meta.user、ua、token_type、token_id；稽核 author_name、meta.remote_ip、entity_type、target_details、details.custom_message
function isGitlabLog(o) {
  if (!o || typeof o !== 'object' || !o.time) return false;
  if (typeof o.route === 'string' && /^\/api\/:version\//.test(o.route)) return true;
  // 舊版 audit_json.log 沒有 correlation_id；auth_json.log 的 Rack_Attack（封鎖或限流）訊息
  if ('author_name' in o && 'entity_type' in o && 'target_type' in o) return true;
  if (o.message === 'Rack_Attack' && o.remote_ip && o.path) return true;
  return typeof o.correlation_id === 'string' && ('meta.caller_id' in o || 'controller' in o || 'author_name' in o);
}
function gitlabEvent(o, lineNo) {
  const ip = String(o.remote_ip || o['meta.remote_ip'] || '').split(',')[0].trim();
  const user = o.username || o['meta.user'] || o.author_name || '';
  const t = new Date(o.time);
  if (o.method && o.path && o.status !== undefined) {
    const f = { srcip: ip, method: o.method, url: o.path, status: String(o.status), bytes: '0', glKind: 'request' };
    if (user) f.user = user; if (o.ua) f.ua = o.ua; if (o.route) f.glRoute = o.route;
    if (o.token_type) f.glTokenType = o.token_type; if (o.token_id !== undefined && o.token_id !== null) f.glTokenId = String(o.token_id);
    const evt = webEvent('weblog', JSON.stringify(o), lineNo, t, o.time, o.host || '', f);
    evt.netVendor = 'gitlab'; evt.appName = 'gitlab'; evt.glRaw = o;
    return evt;
  }
  const cm = o.details && o.details.custom_message;
  const f = { glKind: o.author_name !== undefined ? 'audit' : 'app' };
  if (ip) f.srcip = ip; if (user) f.user = user;
  if (o.target_details) f.glTarget = String(o.target_details);
  if (cm && typeof cm === 'object' && cm.action) f.glAction = String(cm.action);
  if (o.change) f.glChange = `${o.change}: ${o.from || ''} → ${o.to || ''}`;
  const msg = typeof cm === 'string' ? cm : (o.message || f.glChange || [o['meta.caller_id'], f.glAction, f.glTarget].filter(Boolean).join(' '));
  if (typeof o.message === 'string') f.glMsg = o.message;
  if (o.message === 'Rack_Attack') { f.glRack = o.env || ''; f.url = o.path; f.method = o.request_method || ''; }
  return {
    format: 'json', raw: JSON.stringify(o), lineNo, netFields: !!ip, netVendor: 'gitlab', glRaw: o,
    timestamp: isNaN(t.getTime()) ? null : t, timestampRaw: o.time, host: '', appName: 'gitlab', procid: '', msgid: o['meta.caller_id'] || '',
    severityRaw: o.severity || '', severityNorm: 'Info', facility: null, facilityAuth: false, url: '', httpMethod: '',
    msg: [user, msg].filter(Boolean).join(' '), fields: f
  };
}
function eventFromJSONObject(obj, lineNo) {
  if (isCloudflareEvent(obj)) return cloudflareEvent(obj, lineNo);
  if (isZscalerNss(obj)) return zscalerEvent(obj, lineNo);
  if (isVaultAudit(obj)) return vaultEvent(obj, lineNo);
  if (isModsecAudit(obj)) return modsecEvent(obj, lineNo);
  if (isF5Telemetry(obj)) return f5tsEvent(obj, lineNo);
  if (isAwsNfwLog(obj)) return nfwEvent(obj, lineNo);
  if (isAzureFwLog(obj)) return azfwEvent(obj, lineNo);
  if (isGitlabLog(obj)) return gitlabEvent(obj, lineNo);
  if (isMysqlAuditEvent(obj)) return mysqlAuditEvent(obj, lineNo);
  const ci = cloudAuthInfo(obj);
  if (ci) return cloudAuthEvent(obj, ci, lineNo);
  if (isZeekLog(obj)) return zeekEvent(obj, lineNo);
  if (isFalconEvent(obj)) return falconEvent(obj, lineNo);
  if (isSuricataEve(obj)) {
    const ts = new Date(String(obj.timestamp).replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
    const al = obj.alert && typeof obj.alert === 'object' ? obj.alert : null;
    const sev = al ? (SURICATA_SEV[al.severity] || 'Low') : 'Info';
    return {
      format: 'json', raw: JSON.stringify(obj), lineNo, netFields: true, netVendor: 'suricata',
      timestamp: isNaN(ts.getTime()) ? null : ts, timestampRaw: String(obj.timestamp),
      host: obj.host || '', appName: 'suricata', procid: '', msgid: obj.event_type,
      severityRaw: al ? String(al.severity) : '', severityNorm: sev, facility: null, facilityAuth: false,
      url: '', httpMethod: '',
      msg: al ? `${al.signature || ''}${al.category ? ' [' + al.category + ']' : ''}` : `${obj.event_type} ${obj.proto || ''} ${obj.src_ip || ''}${obj.src_port ? ':' + obj.src_port : ''} -> ${obj.dest_ip || ''}${obj.dest_port ? ':' + obj.dest_port : ''}`.trim(),
      fields: obj
    };
  }
  const tsRaw = pickField(obj, TS_KEYS);
  const ts = tsRaw ? new Date(tsRaw) : null;
  const timestamp = ts && !isNaN(ts.getTime()) ? ts : null;
  const sevRaw = pickField(obj, SEV_KEYS);
  return {
    format: 'json', raw: JSON.stringify(obj), lineNo,
    timestamp, timestampRaw: tsRaw || '',
    host: pickField(obj, HOST_KEYS) || '',
    appName: pickField(obj, APP_KEYS) || '', procid: '', msgid: '',
    severityRaw: sevRaw, severityNorm: normGenericSeverity(sevRaw),
    facility: null, facilityAuth: false,
    url: pickField(obj, URL_KEYS) || '', httpMethod: pickField(obj, HTTP_METHOD_KEYS) || '',
    msg: pickField(obj, MSG_KEYS) || '', fields: obj
  };
}
// Windows Event Log（wevtutil qe .../f:xml、PowerShell Get-WinEvent|ForEach{$_.ToXml()}、
// Event Viewer「另存所有事件為...」的 XML 匯出）：2026-08-24 新增。真實匯出常見多筆
// <Event>...</Event> 片段直接串接、沒有共同的根元素包裹（整檔非合法 XML，但每個片段本身
// 各自合法），故無法整檔 DOMParser 一次解析；比照 parseJSONLogEvents() 既有先例——判定與
// 解析皆在文字層級（非逐行），由 parseLogText() 呼叫，非 WEL 內容時回傳 null 交給既有邏輯處理。
// 明確排除範圍：原生二進位 .evtx（瀏覽器端 JS 無法解析，且會違反本工具純前端無外部依賴慣例，
// 不引入外部 EVTX 解析函式庫）；Sysmon 等廠牌特有 EventData 欄位語意對照（本輪僅做通用
// System/EventData 欄位擷取，不臆測特定 Provider 的欄位語意）
function normWinEventLevel(level) {
  // 官方 Windows Event Level 數值：0=LogAlways/Info, 1=Critical, 2=Error, 3=Warning,
  // 4=Informational, 5=Verbose（來源：Microsoft Event Schema 文件），對應到既有
  // severityNorm 五級（Critical/High/Medium/Low/Info），Error 對應 High、Warning 對應 Medium
  const n = parseInt(level, 10);
  if (n === 1) return 'Critical';
  if (n === 2) return 'High';
  if (n === 3) return 'Medium';
  if (n === 5) return 'Low';
  return 'Info'; // 0/4 或無法辨識的數值，比照官方定義的預設層級
}
// 常見 Windows Security 事件（4624/4625/4648 等登入相關）帶遠端來源 IP 的 Data 欄位名稱；
// 對映進通用的 srcip key，讓既有 getEventNetTuple()/extractCandidateIPs() 的
// pickField(fields, SRC_IP_KEYS) 機制免修改即可命中（SRC_IP_KEYS 定義於上方 [2] 模組）。
// WEL 事件無明確的「目的 IP」連線元組概念，不臆測 dst 欄位對應。
const WINEVENT_SRCIP_KEYS = ['IpAddress', 'ClientAddress', 'SourceAddress'];
// 常見 Windows Security 登入/帳號變更事件的使用者帳號 Data 欄位名稱（4624/4625/4648/4720 等）
const WINEVENT_USER_KEYS = ['SubjectUserName', 'TargetUserName', 'SubjectAccountName', 'TargetAccountName'];
// 登入失敗原因（第三十輪 WN2）：4625 的 SubStatus（為 0x0 時用 Status）、4776 的 Status（NTSTATUS）與
// 4771／4772／4768／4769／4773 的 Kerberos 錯誤碼（Status 或描述文字的 Result Code），依 Microsoft 事件說明文件；
// failKind 供彙整：badPassword／unknownUser／locked／disabled／expired／restricted／clock／other
const WIN_NTSTATUS_REASON = {
  '0xc000006a': ['bad password', 'badPassword'], '0xc0000064': ['unknown user name', 'unknownUser'],
  '0xc0000234': ['account locked out', 'locked'], '0xc0000072': ['account disabled', 'disabled'],
  '0xc0000193': ['account expired', 'expired'], '0xc0000071': ['password expired', 'expired'],
  '0xc0000224': ['password must change at next logon', 'expired'], '0xc000006f': ['outside allowed logon hours', 'restricted'],
  '0xc0000070': ['workstation restriction', 'restricted'], '0xc000006e': ['account restriction', 'restricted'],
  '0xc000015b': ['logon type not granted', 'restricted'], '0xc0000413': ['authentication firewall', 'restricted'],
  '0xc0000133': ['clock skew with domain controller', 'clock'], '0xc000006d': ['bad user name or password', 'other'],
  '0xc00000dc': ['server in wrong state', 'other'], '0xc000005e': ['no logon servers available', 'other']
};
const WIN_KRB_REASON = {
  '0x6': ['client not found in Kerberos database (unknown user)', 'unknownUser'], '0x7': ['server not found in Kerberos database', 'other'],
  '0x12': ['client credentials revoked (disabled, locked out or expired)', 'locked'], '0x17': ['password expired', 'expired'],
  '0x18': ['pre-authentication failed (bad password)', 'badPassword'], '0x25': ['clock skew too great', 'clock'],
  '0x1f': ['integrity check on decrypted field failed', 'other'], '0xc': ['KDC policy rejects request', 'restricted'],
  '0xe': ['encryption type not supported', 'other'], '0x20': ['ticket expired', 'other'], '0x9': ['key not found (password not set)', 'other']
};
const WIN_FAIL_EVENT_IDS = new Set(['4625', '4776', '4771', '4772', '4768', '4769', '4773']);
function annotateWinFailReason(f) {
  if (!f || !WIN_FAIL_EVENT_IDS.has(f.EventID)) return;
  const low = v => String(v || '').trim().toLowerCase();
  let code = '', hit = null;
  if (f.EventID === '4625' || f.EventID === '4776') {
    code = f.EventID === '4625' && low(f.SubStatus) && low(f.SubStatus) !== '0x0' ? low(f.SubStatus) : low(f.Status);
    if (/^0x0*$/.test(code)) return;
    code = code.replace(/^0x0*(?=[0-9a-f]{8}$)/, '0x');
    hit = WIN_NTSTATUS_REASON[code];
  } else {
    code = low(f.Status || f['Result Code'] || f['Failure Code']).replace(/^0x0+(?=[0-9a-f])/, '0x');
    if (!code || code === '0x0') return;
    hit = WIN_KRB_REASON[code];
  }
  f.failCode = code;
  f.failReason = hit ? hit[0] : code;
  f.failKind = hit ? hit[1] : 'other';
}
// 遠端桌面與登入類型（第三十輪 WN3）：TerminalServices-RemoteConnectionManager 1149（網路驗證成功，UserData 的 Param1 帳號、
// Param2 網域、Param3 來源位址）、TerminalServices-LocalSessionManager 21／22／24／25（工作階段登入、殼層啟動、中斷、重新連線，
// User 為「網域\帳號」、Address 為來源位址，本機登入為 LOCAL）轉成 TargetUserName／IpAddress；4624／4625 的 LogonType 加上名稱
const WIN_RCM_CHANNEL = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational';
const WIN_LSM_CHANNEL = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';
const WIN_LOGON_TYPES = { '2': 'Interactive', '3': 'Network', '4': 'Batch', '5': 'Service', '7': 'Unlock', '8': 'NetworkCleartext', '9': 'NewCredentials', '10': 'RemoteInteractive', '11': 'CachedInteractive', '12': 'CachedRemoteInteractive', '13': 'CachedUnlock' };
function normalizeWinRdpFields(f) {
  if (f.Channel === WIN_RCM_CHANNEL && f.EventID === '1149') {
    if (!f.Param1 && f.User) f.Param1 = f.User;
    if (f.Param1 && !f.TargetUserName) f.TargetUserName = f.Param1;
    if (f.Param2 && !f.TargetDomainName) f.TargetDomainName = f.Param2;
    if (f.Param3 && !f.IpAddress) f.IpAddress = f.Param3;
    f.rdp = 'auth';
  } else if (f.Channel === WIN_LSM_CHANNEL && /^(?:21|22|24|25)$/.test(f.EventID)) {
    const m = String(f.User || '').match(/^([^\\]*)\\(.+)$/);
    if (f.User && !f.TargetUserName) { f.TargetUserName = m ? m[2] : f.User; if (m) f.TargetDomainName = m[1]; }
    if (f.Address && f.Address !== 'LOCAL' && !f.IpAddress) f.IpAddress = f.Address;
    f.rdp = { '21': 'logon', '22': 'shell', '24': 'disconnect', '25': 'reconnect' }[f.EventID];
  } else if (f.Channel === 'Directory Service' && f.EventID === '2889') {
    // 2889 的未具名 Data：位址:埠、帳號、繫結類型（0 未簽章 SASL、1 未加密簡單繫結），見 detectLdapSigning()
    // Winlogbeat 把未具名 Data 命名為 param1～3
    const d0 = f.Data0 || f.param1, d1 = f.Data1 || f.param2, d2 = f.Data2 || f.param3;
    const addr = String(d0 || ''), i = addr.lastIndexOf(':');
    const ip = (i > 0 ? addr.slice(0, i) : addr).replace(/^\[|\]$/g, '');
    if (ip && !f.IpAddress) f.IpAddress = ip;
    if (d1 && !f.TargetUserName) f.TargetUserName = d1;
    f.ldapBindType = d2 === '1' ? 'simple' : 'unsigned';
  } else if ((f.EventID === '4624' || f.EventID === '4625') && WIN_LOGON_TYPES[f.LogonType]) {
    f.logonTypeName = WIN_LOGON_TYPES[f.LogonType];
    if (f.EventID === '4624' && f.LogonType === '10') f.rdp = 'logon';
  }
}
// 遠端桌面登入彙整（第三十輪 WN3）：成功的遠端桌面登入（4624 類型 10、1149、21、25）依來源位址列出登入的帳號與主機；
// 來源為公用位址時 Medium，其餘 Low。同一次連線常同時有 1149、4624、21，只計 4624／21／25（沒有時才計 1149）
// 明碼網路登入（4624 類型 8，密碼以明碼送到伺服器，如 IIS 基本驗證）依帳號列 Medium
// 公用位址：IPv4 排除私有、迴路、連結本機、CGNAT、多播與保留段；IPv6 排除 fc00::/7、fe80::/10、::1
function isPublicAddr(ip) {
  const v = String(ip || '').replace(/^::ffff:/i, '');
  if (v.includes(':')) return !/^(?:f[cd]|fe[89ab])/i.test(v) && v !== '::1';
  const p = v.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !(n >= 0 && n <= 255))) return false;
  const [a, b] = p;
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127));
}
function detectRdpAndCleartext(events) {
  const issues = [];
  const win = events.filter(e => e.format === 'winevent' && e.fields);
  // 依主機判斷：有 4624／21／25 的主機不計 1149，只有 1149 的主機（未上傳 Security log）才計
  const rdp = win.filter(e => e.fields.rdp === 'logon' || e.fields.rdp === 'reconnect');
  const rdpHosts = new Set(rdp.map(e => hostShort(e.host)));
  const auth1149 = win.filter(e => e.fields.rdp === 'auth' && !rdpHosts.has(hostShort(e.host)));
  const list = [...rdp, ...auth1149].filter(e => e.fields.srcip && e.fields.srcip !== '-' && e.fields.srcip !== '127.0.0.1' && e.fields.srcip !== '::1');
  const bySrc = new Map();
  list.forEach(e => { const k = String(e.fields.srcip).replace(/^::ffff:/i, ''); if (!bySrc.has(k)) bySrc.set(k, []); bySrc.get(k).push(e); });
  for (const [src, l] of bySrc) {
    const sorted = [...l].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    const users = [...new Set(sorted.map(e => e.fields.TargetUserName).filter(Boolean))];
    const hosts = [...new Set(sorted.map(e => e.host).filter(Boolean))];
    const pub = isPublicAddr(src);
    issues.push({ category: 'rdpLogon', severityNorm: pub ? 'Medium' : 'Low', count: sorted.length,
      firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf('sample.rdpLogon', { src, n: sorted.length, users: users.slice(0, 5).join(', ') || '-', hosts: hosts.slice(0, 3).join(', ') || '-' }),
      relatedHosts: [src, ...users.slice(0, 5), ...hosts.slice(0, 3)], relatedEvents: sorted, confidence: 'confirmed' });
  }
  const clear = win.filter(e => e.fields.EventID === '4624' && e.fields.LogonType === '8');
  const byUser = new Map();
  clear.forEach(e => { const k = e.fields.TargetUserName || '-'; if (!byUser.has(k)) byUser.set(k, []); byUser.get(k).push(e); });
  for (const [user, l] of byUser) {
    const sorted = [...l].sort((a, b) => effectiveTime(a) - effectiveTime(b));
    const procs = [...new Set(sorted.map(e => e.fields.ProcessName || e.fields.LogonProcessName).filter(x => x && x !== '-'))];
    issues.push({ category: 'cleartextLogon', severityNorm: 'Medium', count: sorted.length,
      firstSeen: sorted[0].timestamp || null, lastSeen: sorted[sorted.length - 1].timestamp || null,
      ...sampleOf('sample.cleartextLogon', { user, n: sorted.length, procs: procs.slice(0, 3).join(', ') || '-' }),
      relatedHosts: [user, ...new Set(sorted.map(e => e.host).filter(Boolean))], relatedEvents: sorted, confidence: 'confirmed' });
  }
  return issues;
}
function parseWinEventFragment(fragment, lineNo) {
  let doc;
  try { doc = new DOMParser().parseFromString(fragment, 'text/xml'); }
  catch (e) { return null; }
  if (!doc || doc.getElementsByTagName('parsererror').length) return null;
  const evtEl = doc.documentElement;
  if (!evtEl || evtEl.tagName !== 'Event') return null;
  const sys = evtEl.getElementsByTagName('System')[0];
  if (!sys) return null;
  const g = tag => { const el = sys.getElementsByTagName(tag)[0]; return el ? el.textContent.trim() : ''; };
  const providerEl = sys.getElementsByTagName('Provider')[0];
  const provider = providerEl ? (providerEl.getAttribute('Name') || '') : '';
  const eventId = g('EventID');
  const level = g('Level');
  const timeCreatedEl = sys.getElementsByTagName('TimeCreated')[0];
  const timeRaw = timeCreatedEl ? (timeCreatedEl.getAttribute('SystemTime') || '') : '';
  const ts = timeRaw ? new Date(timeRaw) : null;
  const timestamp = ts && !isNaN(ts.getTime()) ? ts : null;
  const recordId = g('EventRecordID');
  const channel = g('Channel');
  const computer = g('Computer');
  const fields = { EventID: eventId, Level: level, Channel: channel, Computer: computer, EventRecordID: recordId, Provider: provider };
  const dataEls = evtEl.getElementsByTagName('Data');
  for (let i = 0; i < dataEls.length; i++) {
    const nameAttr = dataEls[i].getAttribute('Name') || ('Data' + i);
    fields[nameAttr] = dataEls[i].textContent || '';
  }
  // UserData（1102 稽核清除、遠端桌面 1149／21～25 等）：最內層元素名稱當欄位名稱
  const ud = evtEl.getElementsByTagName('UserData')[0];
  if (ud) {
    const leaves = ud.getElementsByTagName('*');
    for (let i = 0; i < leaves.length; i++) {
      const el = leaves[i];
      if (el.getElementsByTagName('*').length) continue;
      const k = el.localName || el.tagName;
      if (k && fields[k] === undefined) fields[k] = el.textContent || '';
    }
  }
  normalizeWinRdpFields(fields);
  const srcVal = WINEVENT_SRCIP_KEYS.map(k => fields[k]).find(v => v && v !== '-');
  if (srcVal) fields.srcip = srcVal;
  annotateWinFailReason(fields);
  // WEL 原始 XML（wevtutil 預設 /f:xml）通常不含 rendered message（需查表對照 Provider 的
  // message table 才能還原，本工具不內建該資料庫，不臆測）；但 wevtutil /f:renderedxml 或
  // PowerShell 匯出時常見會多帶 <RenderingInfo><Message> 區塊（系統本身已查表解析好的文字，
  // 非本工具臆測），存在時優先採用，取不到才退回組合 EventID+Provider
  const renderingInfo = evtEl.getElementsByTagName('RenderingInfo')[0];
  const messageEl = renderingInfo ? renderingInfo.getElementsByTagName('Message')[0] : null;
  const renderedMsg = messageEl ? messageEl.textContent.trim() : '';
  const msg = renderedMsg || (provider ? `EventID ${eventId} (${provider})` : `EventID ${eventId}`) + (fields.failReason ? ' — ' + fields.failReason : '');
  return {
    format: 'winevent', raw: fragment, lineNo,
    timestamp, timestampRaw: timeRaw,
    host: computer, appName: provider, procid: '', msgid: eventId,
    severityRaw: level, severityNorm: normWinEventLevel(level),
    facility: null, facilityAuth: false,
    url: '', httpMethod: '',
    msg, fields
  };
}
function parseWinEventLogEvents(text) {
  if (!/<Event[\s>][\s\S]*?xmlns=["']http:\/\/schemas\.microsoft\.com\/win\/2004\/08\/events\/event["']/.test(text)) return null;
  const matches = text.match(/<Event[\s>][\s\S]*?<\/Event>/g);
  if (!matches || !matches.length) return null;
  const events = [];
  matches.forEach((frag, idx) => {
    const evt = parseWinEventFragment(frag, idx + 1);
    if (evt) events.push(evt);
  });
  return events.length ? events : null;
}
// ── Windows 事件的 JSON／CSV 匯出（第三十輪 WN1）──
// 轉成與 XML 相同的 winevent 事件形狀（fields 為 EventID／Channel／Computer／Provider＋EventData 欄位），
// 既有 Windows 偵測直接適用；去識別化後一律以 rebuildWinEventXML() 輸出 XML。
// Winlogbeat／Elastic Agent：winlog.event_id、channel、computer_name、provider_name、record_id、event_data、user_data，
// 等級在 log.level（information／warning／error／critical／verbose）。NXLog im_msvistalog 的 to_json：EventID、
// SourceName、Channel、Hostname、EventTime（本地時間「YYYY-MM-DD hh:mm:ss」）、RecordNumber、SeverityValue，
// EventData 欄位攤平在最上層
const WIN_LEVEL_NAME = { critical: '1', error: '2', warning: '3', information: '4', info: '4', verbose: '5' };
const NXLOG_SYSTEM_KEYS = new Set(['EventTime', 'EventReceivedTime', 'Hostname', 'Keywords', 'EventType', 'SeverityValue', 'Severity', 'EventID', 'SourceName', 'ProviderGuid', 'Version', 'Task', 'OpcodeValue', 'RecordNumber', 'ActivityID', 'RelatedActivityID', 'ProcessID', 'ThreadID', 'Channel', 'Message', 'Category', 'Opcode', 'Domain', 'AccountName', 'UserID', 'AccountType', 'SourceModuleName', 'SourceModuleType', 'ERRORLEVEL', 'Level']);
const isWinlogbeatEvent = o => !!o && !!o.winlog && typeof o.winlog === 'object' && o.winlog.event_id !== undefined;
const isNxlogWinEvent = o => !!o && o.EventID !== undefined && typeof o.Channel === 'string' && (o.SourceName !== undefined || o.ProviderGuid !== undefined) && (o.EventTime !== undefined || o.Hostname !== undefined);
// 沒有描述文字的 Windows 事件（訊息只有「EventID N (Provider)」）在畫面上補一句摘要：帳號 ← 來源位址（工作站）與幾個常用欄位，
// 只供顯示（事件清單、行為者檢視、匯出），不改 e.msg；欄位名稱沿用 Windows 原名，與介面語言無關
const WIN_BRIEF_KEYS = ['LogonType', 'TargetServerName', 'ServiceName', 'ShareName', 'ObjectDN', 'AttributeLDAPDisplayName', 'MemberName', 'NewProcessName', 'Image', 'TargetObject', 'TaskName', 'ImagePath'];
function winEventBrief(f) {
  const ok = v => v && v !== '-' && v !== '::1';
  const acct = (d, u) => (ok(u) ? (ok(d) && !/[@\\]/.test(u) ? d + '\\' : '') + u : '');
  const who = acct(f.TargetDomainName, f.TargetUserName) || acct(f.SubjectDomainName, f.SubjectUserName);
  const ip = ok(f.IpAddress) ? String(f.IpAddress).replace(/^::ffff:/i, '') : '';
  const ws = ok(f.WorkstationName) ? f.WorkstationName : '';
  const from = ip || ws ? ` ← ${ip || ws}${ip && ws ? ` (${ws})` : ''}` : '';
  const extra = WIN_BRIEF_KEYS.filter(k => ok(f[k])).slice(0, 3)
    .map(k => `${k}=${f[k]}${k === 'LogonType' && f.logonTypeName ? ' ' + f.logonTypeName : ''}`);
  return [who + from, ...extra].filter(Boolean).join(' | ');
}
function eventDisplayMsg(e) {
  if (e.format !== 'winevent' || !e.fields || !/^EventID \d+( \(|$)/.test(e.msg || '')) return e.msg;
  const b = winEventBrief(e.fields);
  return b ? `${e.msg} — ${b}` : e.msg;
}
function winEventFromFields(fields, tsRaw, msg, raw, lineNo, src) {
  normalizeWinRdpFields(fields);
  const ts = tsRaw ? new Date(tsRaw) : null;
  const timestamp = ts && !isNaN(ts.getTime()) ? ts : null;
  const srcVal = WINEVENT_SRCIP_KEYS.map(k => fields[k]).find(v => v && v !== '-');
  if (srcVal) fields.srcip = srcVal;
  annotateWinFailReason(fields);
  return {
    format: 'winevent', raw, lineNo, winSrc: src,
    timestamp, timestampRaw: timestamp ? timestamp.toISOString() : (tsRaw || ''),
    host: fields.Computer || '', appName: fields.Provider || '', procid: '', msgid: fields.EventID,
    severityRaw: fields.Level, severityNorm: normWinEventLevel(fields.Level),
    facility: null, facilityAuth: false, url: '', httpMethod: '',
    msg: msg || (fields.Provider ? `EventID ${fields.EventID} (${fields.Provider})` : `EventID ${fields.EventID}`) + (fields.failReason ? ' — ' + fields.failReason : ''), fields
  };
}
function winlogbeatEvent(o, lineNo) {
  const w = o.winlog;
  const lvl = String((o.log && o.log.level) || w.level || '').toLowerCase();
  const fields = { EventID: String(w.event_id), Level: WIN_LEVEL_NAME[lvl] || '', Channel: w.channel || '', Computer: w.computer_name || (o.host && o.host.name) || '', EventRecordID: w.record_id !== undefined ? String(w.record_id) : '', Provider: w.provider_name || '' };
  [w.event_data, w.user_data].forEach(d => { if (d && typeof d === 'object') Object.keys(d).forEach(k => { if (d[k] !== null && typeof d[k] !== 'object') fields[k] = String(d[k]); }); });
  return winEventFromFields(fields, o['@timestamp'] || '', typeof o.message === 'string' ? o.message.split('\n')[0].trim() : '', JSON.stringify(o), lineNo, 'winlogbeat');
}
function nxlogWinEvent(o, lineNo) {
  const sv = Number(o.SeverityValue);
  // NXLog SeverityValue：1 DEBUG、2 INFO、3 WARNING、4 ERROR、5 CRITICAL
  const lvl = { 1: '5', 2: '4', 3: '3', 4: '2', 5: '1' }[sv] || '';
  const fields = { EventID: String(o.EventID), Level: lvl, Channel: o.Channel || '', Computer: o.Hostname || '', EventRecordID: o.RecordNumber !== undefined ? String(o.RecordNumber) : '', Provider: o.SourceName || '' };
  Object.keys(o).forEach(k => { if (!NXLOG_SYSTEM_KEYS.has(k) && o[k] !== null && typeof o[k] !== 'object') fields[k] = String(o[k]); });
  if (o.EventType === 'AUDIT_FAILURE') fields.Keywords = 'Audit Failure';
  // UserData（遠端桌面 1149、21～25 等）不會攤平，只在 Message 內（OTRF Security-Datasets 的真實 NXLog 紀錄），由描述文字補上
  if (typeof o.Message === 'string') { const d = parseWinEventDescription(o.Message); Object.keys(d).forEach(k => { if (fields[k] === undefined) fields[k] = d[k]; }); }
  const t = String(o.EventTime || '');
  const tsRaw = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(t) ? t.replace(' ', 'T') : t;
  return winEventFromFields(fields, tsRaw, typeof o.Message === 'string' ? o.Message.split(/\r?\n/)[0].trim() : '', JSON.stringify(o), lineNo, 'nxlog');
}
// 事件檢視器「另存所有事件」CSV：表頭「Level,Date and Time,Source,Event ID,Task Category」（中文版「層級,日期和時間,來源,事件識別碼,工作類別」），
// 每列第 6 欄為描述文字（多行、加引號）；PowerShell Get-WinEvent | Export-Csv 的欄位名稱為 Id／ProviderName／LogName／MachineName／TimeCreated／Message。
// 描述文字依英文標籤取欄位（「Subject:」段為 Subject*，其他帳號段為 Target*）
function parseCsvRecords(text) {
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; }
    else if (c !== '\r') cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}
const WIN_DESC_LABELS = {
  'Account Name': 'UserName', 'Account Domain': 'DomainName', 'Security ID': 'UserSid', 'Logon ID': 'LogonId',
  'Source Network Address': 'IpAddress', 'Client Address': 'IpAddress', 'Source Port': 'IpPort', 'Client Port': 'IpPort',
  'Workstation Name': 'WorkstationName', 'Logon Type': 'LogonType', 'Status': 'Status', 'Sub Status': 'SubStatus',
  'Failure Reason': 'FailureReason', 'Failure Code': 'Status', 'Result Code': 'Result Code', 'Error Code': 'Status',
  'Ticket Encryption Type': 'TicketEncryptionType', 'Pre-Authentication Type': 'PreAuthType', 'Service Name': 'ServiceName',
  'Logon Process': 'LogonProcessName', 'Authentication Package': 'AuthenticationPackageName', 'Process Name': 'ProcessName',
  'New Process Name': 'NewProcessName', 'Process Command Line': 'CommandLine', 'Share Name': 'ShareName', 'Object Name': 'ObjectName',
  'Group Name': 'TargetUserName', 'Member Name': 'MemberName', 'User': 'User', 'Domain': 'Param2', 'Session ID': 'SessionID',
  'Logon Account': 'TargetUserName', 'Source Workstation': 'Workstation'
};
function parseWinEventDescription(desc) {
  const f = {}; let section = '';
  String(desc || '').split(/\r?\n/).forEach(line => {
    const m = line.match(/^\s*([A-Za-z][A-Za-z \-]*?):\s*(.*?)\s*$/);
    if (!m) return;
    if (!m[2]) { section = m[1]; return; }
    const key = WIN_DESC_LABELS[m[1]];
    if (!key) return;
    let name = key;
    if (/^(?:UserName|DomainName|UserSid|LogonId)$/.test(key)) name = (section === 'Subject' ? 'Subject' : 'Target') + key;
    // 群組成員事件（4728 等）的 Member 區段帳號為成員 DN，群組名稱才是 TargetUserName
    if (section === 'Member' && key === 'UserName') name = 'MemberName';
    if (section === 'Member' && key === 'UserSid') name = 'MemberSid';
    // LSM 21／25 本機主控台登入的來源為 LOCAL，不是位址
    if (key === 'IpAddress' && /^LOCAL$/i.test(m[2])) return;
    if (f[name] === undefined) f[name] = m[2];
  });
  return f;
}
// 事件檢視器 CSV 的日期：英文「10/20/2026 10:00:00 AM」或中文「2026/10/20 上午 10:00:00」，以本地時間解讀
function winCsvDate(s) {
  let m = String(s).trim().match(/^(\d{4})[\/-](\d{1,2})[\/-](\d{1,2})\s+(上午|下午)?\s*(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)?$/i);
  let y, mo, d;
  if (m) { [y, mo, d] = [m[1], m[2], m[3]]; }
  else {
    // 月/日/年（en-US）；第一段大於 12 或以點分隔（de-DE 20.10.2026）時為日/月/年
    m = String(s).trim().match(/^(\d{1,2})([\/.])(\d{1,2})[\/.](\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)?$/i);
    if (!m) return '';
    const dayFirst = m[2] === '.' || Number(m[1]) > 12;
    [mo, d, y] = dayFirst ? [m[3], m[1], m[4]] : [m[1], m[3], m[4]];
    m = [m[0], '', '', '', '', m[5], m[6], m[7], m[8]];
  }
  let h = Number(m[5]);
  const pm = /下午|PM/i.test((m[4] || '') + (m[8] || '')), am = /上午|AM/i.test((m[4] || '') + (m[8] || ''));
  if (pm && h < 12) h += 12;
  if (am && h === 12) h = 0;
  const p = n => String(n).padStart(2, '0');
  return `${y}-${p(mo)}-${p(d)}T${p(h)}:${m[6]}:${m[7]}`;
}
const WIN_CSV_LEVEL = { information: '4', '資訊': '4', warning: '3', '警告': '3', error: '2', '錯誤': '2', critical: '1', '重大': '1', verbose: '5', '詳細資訊': '5', 'audit success': '0', '稽核成功': '0', 'audit failure': '0', '稽核失敗': '0' };
function parseWinEventCsv(text) {
  // Windows PowerShell 5.1 的 Export-Csv 預設第一行為 #TYPE 型別名稱
  text = text.replace(/^\uFEFF?#TYPE [^\n]*\n/, '');
  const head = text.slice(0, 400);
  const viewer = /^(?:Level|Keywords|層級|關鍵字),(?:Date and Time|日期和時間),(?:Source|來源),(?:Event ID|事件識別碼),(?:Task Category|工作類別)/.test(head);
  const ps = /^"?(?:Message|Id)"?,/.test(head) && /"?ProviderName"?/.test(head.split('\n')[0]) && /"?TimeCreated"?/.test(head.split('\n')[0]);
  if (!viewer && !ps) return null;
  const rows = parseCsvRecords(text);
  const cols = rows.shift();
  const idx = n => cols.indexOf(n);
  const events = [];
  rows.forEach((r, i) => {
    if (r.length < 4) return;
    let fields, tsRaw, desc;
    if (viewer) {
      const lv = String(r[0] || '').trim().toLowerCase();
      fields = { EventID: r[3].trim(), Level: WIN_CSV_LEVEL[lv] || '', Channel: '', Computer: '', EventRecordID: '', Provider: r[2].trim() };
      if (/failure|失敗/.test(lv)) fields.Keywords = 'Audit Failure';
      tsRaw = winCsvDate(r[1]); desc = r[5] || '';
    } else {
      const g = n => (idx(n) >= 0 ? String(r[idx(n)] || '').trim() : '');
      fields = { EventID: g('Id'), Level: g('Level'), Channel: g('LogName'), Computer: g('MachineName'), EventRecordID: g('RecordId'), Provider: g('ProviderName') };
      tsRaw = winCsvDate(g('TimeCreated')) || g('TimeCreated'); desc = g('Message');
    }
    if (!/^\d+$/.test(fields.EventID)) return;
    if (!fields.Channel && /Security-Auditing/i.test(fields.Provider)) fields.Channel = 'Security';
    Object.assign(fields, parseWinEventDescription(desc));
    events.push(winEventFromFields(fields, tsRaw, desc.split(/\r?\n/)[0].trim(), r.join(','), i + 2, 'csv'));
  });
  return events.length ? events : null;
}
// 主要 log 匯入若整段文字可解析成 JSON/NDJSON，優先走這條路徑（格式判定在文字層級，非逐行）；
// 解析不到任何看起來像 log 事件的物件則回傳 null，交給既有逐行 CEF/Syslog dispatcher 處理，
// 兩者互不干擾——CEF/Syslog 每行都不是合法 JSON，JSON.parse 必定失敗，不會誤判
// AKS 診斷 log（category kube-audit／kube-audit-admin，properties.log 為 Kubernetes 稽核 Event 物件或 JSON 字串，依 Elastic integrations
// kubernetes audit_logs 的真實測試 log）：取出內層 Event，主機為資源 ID 最後一段（叢集名稱）
function aksAuditInner(o) {
  if (!o || !/^kube-audit(?:-admin)?$/i.test(String(o.category || '')) || !o.properties) return null;
  let ev = o.properties.log;
  if (typeof ev === 'string') { try { ev = JSON.parse(ev); } catch (e) { return null; } }
  return ev && ev.kind === 'Event' && /^audit\.k8s\.io\//.test(String(ev.apiVersion || '')) ? ev : null;
}
function aksAuditEvent(o, lineNo) {
  const e = eventFromJSONObject(aksAuditInner(o), lineNo);
  e.host = String(o.resourceId || '').split('/').pop() || '';
  return e;
}
const isDuoAuthResp = o => !!o && !!o.response && Array.isArray(o.response.authlogs);
const isK8sAuditList = o => !!o && o.kind === 'EventList' && /^audit\.k8s\.io\//.test(String(o.apiVersion || '')) && Array.isArray(o.items);
function parseJSONLogEvents(text) {
  const { arr, singleObj } = parseJSONOrNDJSON(text, true);
  let list = arr;
  if (!list && singleObj && ((Array.isArray(singleObj.records) && singleObj.records.some(isAzureFwLog)) || looksLikeLogRecord(singleObj) || isWinlogbeatEvent(singleObj) || isNxlogWinEvent(singleObj) || isCloudflareEvent(singleObj) || isFalconEvent(singleObj) || isDefenderAlert(singleObj) || isM365Incident(singleObj) || isK8sAuditList(singleObj) || isDuoAuthResp(singleObj) || aksAuditInner(singleObj) || (Array.isArray(singleObj.records) && singleObj.records.some(aksAuditInner)))) list = [singleObj];
  // 多個縮排 JSON 物件前後相接（CrowdStrike Falcon 串流匯出，第十八輪 TJ）
  if (!list && /^\s*\{/.test(text) && /"eventType"/.test(text)) { const docs = splitConcatJson(text); if (docs.length && docs.every(isFalconEvent)) list = docs; }
  if (!list) return null;
  const events = [];
  list.forEach((item, idx) => {
    if (!item || typeof item !== 'object') return;
    // Windows 事件（Winlogbeat／Elastic Agent、NXLog，第三十輪 WN1）
    if (isWinlogbeatEvent(item)) { events.push(winlogbeatEvent(item, idx + 1)); return; }
    if (isNxlogWinEvent(item)) { events.push(nxlogWinEvent(item, idx + 1)); return; }
    // Cisco Secure Endpoint（AMP）事件 API 回應：{version, metadata, data:[事件…]}（或逐筆 data:{事件}），展開成逐筆事件（第十五輪 VH）
    if (isCiscoAmpEvent(item)) { events.push(ampEvent(item, idx + 1)); return; }
    // Microsoft Defender 告警／365 Defender 事件（一個事件可含多筆告警，第十八輪 TK）
    if (isDefenderAlert(item) || isM365Incident(item)) { const d = defenderEvents(item, idx + 1); if (d.length) { events.push(...d); return; } }
    // Azure 診斷 log 匯出為 {"records":[…]}（第二十二輪 HE）
    if (Array.isArray(item.records) && item.records.length && item.records.every(isAzureFwLog)) { item.records.forEach(r => events.push(azfwEvent(r, idx + 1))); return; }
    // AKS 診斷 log 包裝的 Kubernetes 稽核（逐行或 {records:[…]}）
    if (aksAuditInner(item)) { events.push(aksAuditEvent(item, idx + 1)); return; }
    if (Array.isArray(item.records) && item.records.length && item.records.every(aksAuditInner)) { item.records.forEach(r => events.push(aksAuditEvent(r, idx + 1))); return; }
    // Duo Admin API 回應 {stat, response:{authlogs:[…], metadata}}（第二十三輪 IF）
    if (isDuoAuthResp(item)) { item.response.authlogs.forEach(r => events.push(eventFromJSONObject(r, idx + 1))); return; }
    // Kubernetes 稽核 EventList（kubectl 或 API 回應，第二十三輪 ID）
    if (isK8sAuditList(item)) { item.items.forEach(r => events.push(eventFromJSONObject(r, idx + 1))); return; }
    // CloudTrail 檔案（S3）為 {"Records":[事件…]}，逐行 NDJSON 時每行一個這種物件（第十六輪 PF）
    if (Array.isArray(item.Records) && item.Records.length && item.Records.every(r => r && r.eventSource && r.eventName)) { item.Records.forEach(r => events.push(eventFromJSONObject(r, idx + 1))); return; }
    const amp = item.data && (Array.isArray(item.data) ? item.data : [item.data]);
    if (amp && amp.length && amp.every(isCiscoAmpEvent)) { amp.forEach(a => events.push(ampEvent(a, idx + 1))); return; }
    // 容器 log 包裝（Kubernetes／Docker json-file：{"message"|"log": "CoreDNS 行", …}，第二十一輪 GA）
    const wrapped = typeof item.message === 'string' ? 'message' : (typeof item.log === 'string' ? 'log' : '');
    if (wrapped && COREDNS_RE.test(item[wrapped].trim())) { const d = parseDnsServerLine(item[wrapped].trim(), idx + 1); if (d) { d.raw = JSON.stringify(item); d.dnsWrap = { obj: item, key: wrapped }; events.push(d); return; } }
    events.push(eventFromJSONObject(item, idx + 1));
  });
  return events.length ? events : null;
}
// ── 雲端流量紀錄（2026-10-02，第十輪發想 ZM）──
// AWS VPC Flow Logs：依 AWS 官方 VPC 使用者指南（awsdocs/amazon-vpc-user-guide flow-logs.md／
// flow-logs-records-examples.md）——預設格式為 14 個 v2 欄位以空白分隔；自訂格式的欄位順序由使用者指定，
// 寫入 S3 的檔案第一行是欄位名稱（同一份文件的範例欄位清單），兩者皆接受。protocol 為 IANA 協定號碼，
// action 為 ACCEPT／REJECT，start／end 為 Unix 秒，NODATA／SKIPDATA 列只有時間與狀態。
// Azure：依 MicrosoftDocs azure-docs（network-watcher nsg-flow-logs-overview.md／vnet-flow-logs-overview.md）——
// {"records":[…]}；NSG flow logs（category NetworkSecurityGroupFlowEvent）的 flowTuples 為
// 「Unix 秒,來源,目的,來源埠,目的埠,T|U,I|O,A|D[,狀態,封包,位元組,封包,位元組]」；VNet flow logs
// （FlowLogFlowEvent）為「Unix 毫秒,來源,目的,來源埠,目的埠,協定號碼,I|O,B|C|E|D,加密狀態,封包,位元組,封包,位元組」，
// 狀態 D 表示拒絕。每個 tuple 一筆事件，規則名稱放在 fields.rule
const AWS_FLOW_V2 = ['version', 'account-id', 'interface-id', 'srcaddr', 'dstaddr', 'srcport', 'dstport', 'protocol', 'packets', 'bytes', 'start', 'end', 'action', 'log-status'];
const FLOW_PROTO = { '6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6', T: 'tcp', U: 'udp' };
function flowMsg(f) {
  if (f.status && !f.srcip) return f.status;
  return `${f.action === 'deny' ? 'DENY' : f.action === 'accept' ? 'ALLOW' : 'FLOW'} ${f.proto ? f.proto.toUpperCase() : ''} ${f.srcip || '-'}${f.srcport ? ':' + f.srcport : ''} -> ${f.dstip || '-'}${f.dstport ? ':' + f.dstport : ''}${f.rule ? ' rule=' + f.rule : ''}`;
}
function flowEvent(vendor, raw, lineNo, ts, tsRaw, host, f, extra) {
  const deny = f.action === 'deny';
  const msg = flowMsg(f);
  return {
    format: 'flowlog', raw, lineNo, netFields: true, netVendor: vendor,
    timestamp: ts && !isNaN(ts.getTime()) ? ts : null, timestampRaw: tsRaw,
    host: host || '', appName: vendor === 'aws' ? 'vpc-flow-logs' : 'flow-logs', procid: '', msgid: '',
    severityRaw: f.action || '', severityNorm: deny ? 'Low' : 'Info', facility: null, facilityAuth: false,
    msg, fields: f, ...(extra || {})
  };
}
function parseAwsFlowLogs(text) {
  const lines = text.split('\n');
  const first = lines.findIndex(l => l.trim());
  if (first < 0) return null;
  const head = lines[first].trim().split(/\s+/);
  let cols = null, start = first;
  if (head.every(c => /^[a-z][a-z0-9-]*$/.test(c)) && head.includes('srcaddr') && head.includes('dstaddr')) { cols = head; start = first + 1; }
  else if (/^\d+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \d+ \d+ (?:ACCEPT|REJECT|-) (?:OK|NODATA|SKIPDATA)\s*$/.test(lines[first].trim())) cols = AWS_FLOW_V2;
  if (!cols) return null;
  const events = [], unparsed = [];
  for (let i = start; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const parts = line.trim().split(/\s+/);
    if (parts.length !== cols.length) { unparsed.push({ lineNo: i + 1, raw: line }); continue; }
    const w = {};
    cols.forEach((c, k) => { if (parts[k] !== '-') w[c] = parts[k]; });
    const f = { ...w };
    if (w.srcaddr) f.srcip = w.srcaddr;
    if (w.dstaddr) f.dstip = w.dstaddr;
    if (w.srcport) f.srcport = w.srcport;
    if (w.dstport) f.dstport = w.dstport;
    if (w.protocol) f.proto = FLOW_PROTO[w.protocol] || w.protocol;
    if (w.action) f.action = w.action === 'REJECT' ? 'deny' : 'accept';
    if (w['interface-id']) f.interface = w['interface-id'];
    if (w['log-status'] && w['log-status'] !== 'OK') f.status = w['log-status'];
    const ts = w.start ? new Date(Number(w.start) * 1000) : null;
    events.push(flowEvent('aws', line, i + 1, ts, w.start || '', w['interface-id'] || w['instance-id'] || '', f, { flowCols: cols }));
  }
  return events.length ? { events, unparsed } : null;
}
function parseAzureFlowLogs(text) {
  if (!/"(?:NetworkSecurityGroupFlowEvent|FlowLogFlowEvent)"/.test(text) || !/"flowTuples"/.test(text)) return null;
  // 多個 blob 檔案串接上傳時是好幾份 JSON，逐份解析
  let docs = [];
  try { docs = [JSON.parse(text)]; } catch (e) {
    for (const chunk of text.split(/\n(?=\{)/)) { try { docs.push(JSON.parse(chunk)); } catch (e2) { /* 略過殘缺段落 */ } }
  }
  const events = [];
  const last = id => (id ? String(id).split('/').filter(Boolean).pop() : '');
  const push = (tuple, rule, host, mac, vnet) => {
    const t = String(tuple).split(',');
    if (t.length < 8) return;
    const tsNum = Number(t[0]);
    const f = { srcip: t[1], dstip: t[2], srcport: t[3], dstport: t[4], proto: FLOW_PROTO[t[5]] || t[5], direction: t[6] === 'I' ? 'inbound' : 'outbound', rule };
    if (vnet) { f.state = t[7]; f.action = t[7] === 'D' ? 'deny' : 'accept'; if (t[8]) f.encryption = t[8]; [f.packets, f.bytes, f.rpackets, f.rbytes] = t.slice(9, 13); }
    else { f.action = t[7] === 'D' ? 'deny' : 'accept'; if (t[8]) f.state = t[8]; [f.packets, f.bytes, f.rpackets, f.rbytes] = t.slice(9, 13); }
    Object.keys(f).forEach(k => { if (f[k] === undefined || f[k] === '') delete f[k]; });
    if (mac) f.srcmac = mac.replace(/(..)(?!$)/g, '$1:');
    const ts = isNaN(tsNum) ? null : new Date(vnet ? tsNum : tsNum * 1000);
    events.push(flowEvent('azure', String(tuple), events.length + 1, ts, t[0], host, f, { flowMac: mac || '' }));
  };
  docs.forEach(d => (d && Array.isArray(d.records) ? d.records : []).forEach(r => {
    if (r.category === 'NetworkSecurityGroupFlowEvent' && r.properties) {
      const host = last(r.resourceId || r.resourceid);
      (r.properties.flows || []).forEach(g => (g.flows || []).forEach(fl => (fl.flowTuples || []).forEach(tp => push(tp, g.rule || '', host, fl.mac || '', false))));
    } else if (r.category === 'FlowLogFlowEvent' && r.flowRecords) {
      const host = last(r.targetResourceID);
      (r.flowRecords.flows || []).forEach(fw => (fw.flowGroups || []).forEach(g => (g.flowTuples || []).forEach(tp => push(tp, g.rule || '', host, r.macAddress || '', true))));
    }
  }));
  return events.length ? { events, unparsed: [] } : null;
}
// GCP（第十六輪 PE）：Cloud Logging 匯出的 VPC Flow Logs（logName …compute.googleapis.com%2Fvpc_flows）與
// Firewall Rules Logging（…%2Ffirewall），逐行 JSON 或 gcloud logging read 的 JSON 陣列。欄位依 Elastic Beats gcp 模組
// 的真實測試 log：jsonPayload.connection.src_ip／dest_ip／src_port／dest_port／protocol（號碼），防火牆紀錄另有
// disposition ALLOWED／DENIED 與 rule_details.reference（network:網路/firewall:規則）／direction；VPC Flow Logs 沒有動作欄位，
// 依 reporter（SRC／DEST）取回報端 VM 名稱為主機
const GCP_FLOW_LOG_RE = /compute\.googleapis\.com%2F(vpc_flows|firewall)/;
function gcpFlowEvent(o, lineNo) {
  const p = o.jsonPayload || {}, c = p.connection || {};
  const kind = (String(o.logName || '').match(GCP_FLOW_LOG_RE) || [])[1];
  const f = { srcip: c.src_ip, dstip: c.dest_ip, srcport: c.src_port !== undefined ? String(c.src_port) : '', dstport: c.dest_port !== undefined ? String(c.dest_port) : '',
    proto: FLOW_PROTO[String(c.protocol)] || (c.protocol !== undefined ? String(c.protocol) : '') };
  if (kind === 'firewall') {
    f.action = p.disposition === 'DENIED' ? 'deny' : p.disposition === 'ALLOWED' ? 'accept' : '';
    const rd = p.rule_details || {};
    f.rule = (String(rd.reference || '').match(/firewall:(.+)$/) || [])[1] || '';
    if (rd.direction) f.direction = rd.direction === 'INGRESS' ? 'inbound' : 'outbound';
  } else {
    f.bytes = p.bytes_sent; f.packets = p.packets_sent;
    if (p.reporter) f.reporter = p.reporter;
  }
  Object.keys(f).forEach(k => { if (f[k] === undefined || f[k] === '') delete f[k]; });
  const inst = p.instance || (p.reporter === 'DEST' ? p.dest_instance : p.src_instance) || p.src_instance || p.dest_instance || {};
  const tsRaw = o.timestamp || p.end_time || '';
  return flowEvent('gcp', JSON.stringify(o), lineNo, tsRaw ? new Date(tsRaw) : null, tsRaw, inst.vm_name || '', f, { gcpRaw: o, flowKind: kind });
}
function parseGcpFlowLogs(text) {
  if (!GCP_FLOW_LOG_RE.test(text) || !/"jsonPayload"/.test(text)) return null;
  const { arr } = parseJSONOrNDJSON(text);
  const list = (arr || []).filter(o => o && o.jsonPayload && o.jsonPayload.connection && GCP_FLOW_LOG_RE.test(String(o.logName || '')));
  if (!list.length) return null;
  return { events: list.map((o, i) => gcpFlowEvent(o, i + 1)), unparsed: [] };
}
function parseFlowLogEvents(text) {
  return parseAzureFlowLogs(text) || parseAwsFlowLogs(text) || parseGcpFlowLogs(text);
}
// 解析分三段（UX26）：parseLogBegin() 先試整份格式（Windows XML／CSV、flow log、Zeek TSV、JSON、W3C），
// 是的話直接回傳 { done }；否則回傳逐行狀態，parseLogStep() 處理到指定行，parseLogFinish() 做跨行關聯。
// 同步的 parseLogText() 一次跑完（測試與比對前期 log 用）；parseLogTextAsync() 每 PARSE_CHUNK_LINES 行
// 讓出主執行緒並回報進度，只給 doAnalyze() 用，兩者結果相同
const PARSE_CHUNK_LINES = 5000;
function parseLogBegin(text) {
  // 貼上內容可能帶 UTF-8 BOM（檔案上傳時瀏覽器會自動去除），未去除會讓第一行解析失敗
  const norm = text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  const winEvents = parseWinEventLogEvents(norm);
  if (winEvents) return { done: { events: winEvents, unparsed: [] } };
  const winCsv = parseWinEventCsv(norm);
  if (winCsv) return { done: { events: winCsv, unparsed: [] } };
  const flow = parseFlowLogEvents(norm);
  if (flow) return { done: flow };
  const zeekTsv = parseZeekTsv(norm);
  if (zeekTsv) return { done: zeekTsv };
  const jsonEvents = parseJSONLogEvents(norm);
  if (jsonEvents) return { done: { events: jsonEvents, unparsed: [] } };
  const w3c = parseW3CLogEvents(norm);
  if (w3c) return { done: w3c };
  const lines = norm.split('\n');
  const rad = parseRadiusDetail(lines);
  // winDhcpHead：Windows DHCP 稽核 log 開頭的說明行（Microsoft DHCP Service Activity Log … 到 ID,Date,Time 表頭）不列為無法解析
  return { lines, rad, events: rad.events, unparsed: [], winDhcpHead: false, pos: 0 };
}
function parseLogStep(st, end) {
  const { lines, rad, events, unparsed } = st;
  const stop = Math.min(end, lines.length);
  for (let idx = st.pos; idx < stop; idx++) {
    const line = lines[idx];
    if (!line.trim() || rad.used.has(idx)) continue;
    if (/^\s*Microsoft DHCP Service Activity Log/i.test(line)) { st.winDhcpHead = true; continue; }
    if (WINDHCP_HEAD_RE.test(line)) { st.winDhcpHead = false; continue; }
    if (st.winDhcpHead) continue;
    const evt = parseLogLine(line, idx + 1);
    if (evt) events.push(evt); else unparsed.push({ lineNo: idx + 1, raw: line });
  }
  st.pos = stop;
}
function parseLogFinish(st) {
  const { events, unparsed } = st;
  if (st.rad.events.length) events.sort((a, b) => a.lineNo - b.lineNo);
  linkDnsReplies(events);
  linkIseSegments(events);
  linkVpnSessions(events);
  linkLdapConns(events);
  linkDbConns(events);
  annotateAddrOwners(events);
  return { events, unparsed };
}
function parseLogText(text) {
  const st = parseLogBegin(text);
  if (st.done) return st.done;
  parseLogStep(st, Infinity);
  return parseLogFinish(st);
}
// onProgress(已處理行數, 總行數)；shouldStop() 為真（已有更新的一次分析）時回傳 null
async function parseLogTextAsync(text, onProgress, shouldStop) {
  const st = parseLogBegin(text);
  if (st.done) return st.done;
  const total = st.lines.length;
  while (st.pos < total) {
    parseLogStep(st, st.pos + PARSE_CHUNK_LINES);
    if (st.pos < total) {
      if (onProgress) onProgress(st.pos, total);
      await yieldToUI();
      if (shouldStop && shouldStop()) return null;
    }
  }
  return parseLogFinish(st);
}
// 無法解析 log 回報觸發判斷（2026-09-29 新增，RC）：一筆事件都沒解析出來→'unknown_vendor'（格式
// 無法辨識，沿用 config_anonymizer 回報流程的觸發代號）；無法解析的行數佔一半以上且至少 3 行
// →'sparse'；其餘回傳 ''。回報內容只取無法解析的行（最多 REPORT_LOG_MAX_LINES 行），不送出整份 log
const REPORT_LOG_MAX_LINES = 200;
function logReportTrigger(eventCount, unparsedCount) {
  if (!eventCount && unparsedCount > 0) return 'unknown_vendor';
  if (unparsedCount >= 3 && unparsedCount / (eventCount + unparsedCount) >= 0.5) return 'sparse';
  return '';
}
function buildLogReportSample(unparsed) {
  return (unparsed || []).slice(0, REPORT_LOG_MAX_LINES).map(u => u.raw).join('\n');
}
// 事件清單分頁（2026-09-29 新增，PA）：5 萬列一次畫進表格會讓瀏覽器排版卡住約 28 秒，改為一次
// 顯示 RESULTS_PAGE_SIZE 筆、按「再顯示」增加；回傳本次要畫的筆數與尚未顯示的筆數
const RESULTS_PAGE_SIZE = 500;
function resultsPageInfo(total, limit) {
  const shown = Math.min(total, Math.max(RESULTS_PAGE_SIZE, limit || 0));
  return { shown, remaining: total - shown };
}

// 多檔上傳真正分組（2026-09 新增）：doUploadFile() 上傳多檔時沿用既有做法把各檔內容以 '\n'
// 串接成單一字串餵給上方 parseLogText()（不改動 parseLogText()/parseLogLine() 簽章），改在
// 上傳階段額外依各檔實際貢獻的行數建立「行號→來源檔名」對照表（fileBoundaries，
// [{name,startLine,endLine}]，1-indexed 皆含端點），事後用 event.lineNo 反查即可還原來源檔案。
// 僅對「逐行解析」路徑可靠——parseLogText() 逐行呼叫 parseLogLine(line, idx+1) 時，idx+1 本來
// 就是串接後文字裡的真實行號，與這裡的行號→檔案對照表天生一致；Windows Event Log／JSON
// 陣列這兩種一次解析整段文字的格式（parseWinEventLogEvents()/parseJSONLogEvents()），其
// event.lineNo 語意是「第幾筆事件/物件」而非文字行號，用行號回查會誤判來源檔案，故明確
// 排除（format==='winevent'||'json'），比照專案「不猜測」原則，寧可不標示來源檔也不要顯示
// 錯誤的檔名。
function resolveSourceFile(lineNo, fileBoundaries) {
  if (!fileBoundaries || fileBoundaries.length < 2) return null;
  const hit = fileBoundaries.find(b => lineNo >= b.startLine && lineNo <= b.endLine);
  return hit ? hit.name : null;
}
function annotateEventsWithSourceFile(events, fileBoundaries) {
  if (!fileBoundaries || fileBoundaries.length < 2) return events;
  events.forEach(e => {
    if (e.format === 'winevent' || e.format === 'json' || (e.format === 'flowlog' && e.netVendor === 'azure')) return;
    const name = resolveSourceFile(e.lineNo, fileBoundaries);
    if (name) e.sourceFile = name;
  });
  return events;
}
function getDistinctSourceFiles(events) {
  const set = new Set();
  events.forEach(e => { if (e.sourceFile) set.add(e.sourceFile); });
  return Array.from(set).sort();
}
function filterEventsBySourceFile(events, name) {
  if (!name) return events;
  return events.filter(e => e.sourceFile === name);
}

