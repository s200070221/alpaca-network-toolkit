// ══════════════════════════════════════════════════════════
//  CISCO ASA PARSER
// ══════════════════════════════════════════════════════════
const CiscoASAParser = (() => {

  function parseDeviceInfo(text) {
    const hostname = (text.match(/^hostname\s+(\S+)/m)||[])[1]||'-';
    const firmware  = (text.match(/^ASA Version\s+(\S+)/m)||[])[1]||'-';
    const model     = (text.match(/^Hardware:\s*(\S+)/m)||[])[1]||'-';
    const serial    = (text.match(/^Serial Number:\s*(\S+)/m)||[])[1]||'-';
    return { vendor:'Cisco ASA', hostname, firmware, model, serial, vdom:[] };
  }

  function parseInterfaces(text) {
    const ifaces = [];
    // 全域管理存取指令（2026-09-18 新增）：官方語法 "http <ip> <mask> <nameif>"／
    // "telnet <ip> <mask> <nameif>"，以 nameif（非實體介面名稱）定址、非逐介面區塊內宣告，
    // 故獨立於下方逐介面迴圈先掃描一次；三個 \S+ token 的要求天生不會誤判 "http server enable"
    // （僅 2 個 token）／"telnet timeout N"（僅 2 個 token）這類無關指令，不需額外排除條件
    const mgmtAccess = new Map(); // nameif -> Set of methods
    for (const l of text.split('\n')) {
      const t = l.trim();
      const mHttp = t.match(/^http\s+\S+\s+\S+\s+(\S+)/);
      if (mHttp) { if (!mgmtAccess.has(mHttp[1])) mgmtAccess.set(mHttp[1], new Set()); mgmtAccess.get(mHttp[1]).add('http'); }
      const mTelnet = t.match(/^telnet\s+\S+\s+\S+\s+(\S+)/);
      if (mTelnet) { if (!mgmtAccess.has(mTelnet[1])) mgmtAccess.set(mTelnet[1], new Set()); mgmtAccess.get(mTelnet[1]).add('telnet'); }
    }
    for (const block of text.split(/^(?=interface\s)/m)) {
      const mIf = block.match(/^interface\s+(.+)/);
      if (!mIf) continue;
      const name = mIf[1].trim();
      let ip='-', mask='-', ip6='-', nameif='', secLevel=-1, shutdown=false, desc='';
      for (const l of block.split('\n').slice(1)) {
        const t = l.trim();
        const mIp  = t.match(/^ip address\s+(\S+)\s+(\S+)/);
        if (mIp) { ip = mIp[1]; mask = mIp[2]; }
        // IPv6 介面位址（2026-09-18 新增）：官方單行語法 "ipv6 address <addr>/<prefix>"
        const mIp6 = t.match(/^ipv6 address\s+(\S+)/);
        if (mIp6) ip6 = mIp6[1];
        const mNif = t.match(/^nameif\s+(\S+)/);
        if (mNif) nameif = mNif[1];
        const mSec = t.match(/^security-level\s+(\d+)/);
        if (mSec) secLevel = parseInt(mSec[1]);
        if (/^shutdown/.test(t)) shutdown = true;
        const mD = t.match(/^description\s+(.+)/);
        if (mD) desc = mD[1];
      }
      let role = 'internal';
      if (secLevel === 0) role = 'external';
      else if (secLevel > 0 && secLevel < 100) role = 'dmz';
      const allowaccess = mgmtAccess.has(nameif) ? [...mgmtAccess.get(nameif)].join(' ') : '-';
      ifaces.push({ name, ip, ip6, mask, type:'physical', role, status:shutdown?'down':'up', desc, nameif, secLevel, allowaccess });
    }
    return ifaces;
  }

  // ASA 埠名稱（running-config 會把常見埠號寫成名稱，如 eq https、eq www）與 eq/gt/lt/neq/range 轉成埠範圍字串（2026-10-16）
  const ASA_PORTS = { 'aol':5190, 'bgp':179, 'biff':512, 'bootpc':68, 'bootps':67, 'chargen':19, 'cifs':3020, 'citrix-ica':1494, 'cmd':514, 'ctiqbe':2748, 'daytime':13,
    'discard':9, 'dnsix':195, 'domain':53, 'echo':7, 'exec':512, 'finger':79, 'ftp':21, 'ftp-data':20, 'gopher':70, 'h323':1720, 'hostname':101, 'http':80, 'https':443,
    'ident':113, 'imap4':143, 'irc':194, 'isakmp':500, 'kerberos':750, 'klogin':543, 'kshell':544, 'ldap':389, 'ldaps':636, 'login':513, 'lotusnotes':1352, 'lpd':515,
    'mobile-ip':434, 'nameserver':42, 'netbios-dgm':138, 'netbios-ns':137, 'netbios-ssn':139, 'nfs':2049, 'nntp':119, 'ntp':123, 'pcanywhere-data':5631,
    'pcanywhere-status':5632, 'pim-auto-rp':496, 'pop2':109, 'pop3':110, 'pptp':1723, 'radius':1645, 'radius-acct':1646, 'rip':520, 'rsh':514, 'rtsp':554,
    'secureid-udp':5510, 'sip':5060, 'smtp':25, 'snmp':161, 'snmptrap':162, 'sqlnet':1521, 'ssh':22, 'sunrpc':111, 'syslog':514, 'tacacs':49, 'talk':517,
    'telnet':23, 'tftp':69, 'time':37, 'uucp':540, 'vxlan':4789, 'who':513, 'whois':43, 'www':80, 'xdmcp':177 };
  const asaPort = v => (/^\d+$/.test(v) ? +v : ASA_PORTS[String(v).toLowerCase()]);
  // 回傳埠範圍字串（逗號分隔），無法辨識的埠名回傳 null
  function asaPortSpec(op, a, b) {
    const x = asaPort(a), y = asaPort(b);
    if (x === undefined) return null;
    if (op === 'eq') return String(x);
    if (op === 'range') return y === undefined ? null : `${x}-${y}`;
    if (op === 'gt') return x >= 65535 ? null : `${x + 1}-65535`;
    if (op === 'lt') return x <= 1 ? null : `1-${x - 1}`;
    if (op === 'neq') return [x > 1 ? `1-${x - 1}` : '', x < 65535 ? `${x + 1}-65535` : ''].filter(Boolean).join(',');
    return null;
  }
  const ASA_PORT_OPS = new Set(['eq', 'gt', 'lt', 'neq', 'range']);

  function parsePolicies(text, addrTypeMap) {
    const policies = [];
    let id = 1;
    // crypto map 引用的 ACL（crypto map NAME SEQ match address ACL）只用來定義 VPN 加密流量，
    // 不是介面上的存取控制規則，排除以免計入稽核與健康度（VPN 分頁另由 aclMap 讀取，不受影響）
    const cryptoAcls = new Set([...text.matchAll(/^crypto\s+map\s+\S+\s+\d+\s+match\s+address\s+(\S+)/gm)].map(x => x[1]));
    // ACL 套用的介面（2026-10-01，YA）：`access-group ACL {in|out} interface IF`、`access-group ACL global`。
    // in → 來源介面、out → 目的介面、global → any；沒有 access-group 的 ACL 維持 '-'（未套用到任何介面）
    const aclIn = {}, aclOut = {};
    for (const g of text.matchAll(/^access-group\s+(\S+)\s+(?:(in|out)\s+interface\s+(\S+)|global)/gm)) {
      const map = g[2] === 'out' ? aclOut : aclIn;
      (map[g[1]] = map[g[1]] || []).push(g[2] ? g[3] : 'any');
    }
    // ACL 內行號（2026-10-02，YI）：`show access-list` 的 line N 依 ACL 內順序編號，remark 也占一行，
    // 用來把命中數對回規則；每個 ACL 各自從 1 起算
    const aclLineNo = {};
    for (const line of text.split('\n')) {
      const am = line.match(/^access-list\s+(\S+)\s+(?:extended|standard|remark|webtype|ethertype)\b/);
      if (am) aclLineNo[am[1]] = (aclLineNo[am[1]] || 0) + 1;
      const m = line.match(/^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.+)/);
      if (!m) continue;
      const [, aclName, rawAction, proto, rest] = m;
      if (cryptoAcls.has(aclName)) continue;
      const action = rawAction === 'permit' ? 'accept' : 'deny';
      let parts = rest.trim().split(/\s+/);
      let src='any', dst='any', svc=proto, i=0;
      // 協定位置寫服務物件／群組（permit object-group SVC …、permit object SVC …）：名稱即服務
      if ((proto === 'object' || proto === 'object-group') && parts.length) { svc = parts[0]; parts = parts.slice(1); }
      // parse source
      if (parts[i]==='any'||parts[i]==='any4'||parts[i]==='any6') { src='any'; i++; }
      else if (parts[i]==='host') { src=parts[i+1]||'any'; i+=2; }
      else if (parts[i]==='object'||parts[i]==='object-group') { src=parts[i+1]||'any'; i+=2; }
      else if (/^\d+\.\d+\.\d+\.\d+$/.test(parts[i])&&/^\d+\.\d+\.\d+\.\d+$/.test(parts[i+1]||'')) { src=`${parts[i]} ${parts[i+1]}`; i+=2; }
      else { src=parts[i]||'any'; i++; }
      // parse dest
      if (i<parts.length) {
        if (parts[i]==='any'||parts[i]==='any4'||parts[i]==='any6') { dst='any'; i++; }
        else if (parts[i]==='host') { dst=parts[i+1]||'any'; i+=2; }
        else if (parts[i]==='object'||parts[i]==='object-group') { dst=parts[i+1]||'any'; i+=2; }
        else if (/^\d+\.\d+\.\d+\.\d+$/.test(parts[i])&&/^\d+\.\d+\.\d+\.\d+$/.test(parts[i+1]||'')) { dst=`${parts[i]} ${parts[i+1]}`; i+=2; }
        else { dst=parts[i]||'any'; i++; }
      }
      // 目的埠：eq／gt／lt／neq／range（埠名轉數字），或目的位址後接服務群組／物件（object-group SVC）
      if (ASA_PORT_OPS.has(parts[i]) && parts[i+1]) {
        const spec = asaPortSpec(parts[i], parts[i+1], parts[i+2]);
        // 無法辨識的埠名保留原文（查詢時回傳無法判斷），不可當成不限埠號
        svc = spec ? `${proto}/${spec}` : `${proto}/${parts[i+1]}`;
      } else if ((parts[i]==='object-group'||parts[i]==='object') && parts[i+1] && (proto==='tcp'||proto==='udp'||proto==='tcp-udp')) svc = parts[i+1];
      const srcAddrSplit = _splitAddr(src, addrTypeMap);
      const dstAddrSplit = _splitAddr(dst, addrTypeMap);
      // ASA 原生支援的 ACE 修飾字：行尾 `inactive` 停用該筆規則（不刪除）；`log disable`
      // 明確關閉該筆日誌（預設情況下 ASA 對每筆 ACE 皆會記錄，非顯式停用即視為有記錄）。
      // status/logtraffic 欄位值須與其餘廠牌 parser 共用慣例一致（'enable'/'disable'，全小寫），
      // 否則 analyzeCompliance()/analyzeRuleShadowing()/_runPolicyQuery()/computeFirewallHealth()
      // 等共用函式會誤判 ASA/FTD 規則永遠是「未停用」「無日誌」。utm 為固定佔位物件
      // （ASA 無 UTM profile 概念，比照 Juniper/MikroTik 等其餘無 UTM 廠牌既有慣例），
      // 避免 exportCSV('policies') 讀取 r.utm.av 時因 utm 為 undefined 而拋例外。
      const status = /\binactive\b/.test(rest) ? 'disable' : 'enable';
      const logtraffic = /\blog\s+disable\b/.test(rest) ? 'disable' : 'all';
      policies.push({ id:id++, name:aclName, aclLine:aclLineNo[aclName], srcIntf:(aclIn[aclName]||['-']).join(','), dstIntf:(aclOut[aclName]||['-']).join(','), srcAddr:src, dstAddr:dst, srcAddr4:srcAddrSplit.v4, srcAddr6:srcAddrSplit.v6, dstAddr4:dstAddrSplit.v4, dstAddr6:dstAddrSplit.v6, service:svc, action, schedule:'-', nat:'disable', ippool:'disable', poolname:'-', logtraffic, logstart:'-', utm:{av:'-',webfilter:'-',ips:'-',ssl:'-',appctrl:'-'}, status, comments:'-', users:'-', groups:'-', vdom:aclName, enabled: status==='enable', color:'0' });
    }
    return policies;
  }

  function parseAddressObjects(text) {
    const addrs = [];
    for (const block of text.split(/^(?=object(?:-group)?\s+network\s)/m)) {
      const mObj = block.match(/^object\s+network\s+(\S+)/);
      const mGrp = block.match(/^object-group\s+network\s+(\S+)/);
      const name = (mObj||mGrp)?.[1];
      if (!name) continue;
      const members = [];
      for (const l of block.split('\n').slice(1)) {
        const t = l.trim();
        if (!t||t.startsWith('!')) continue;
        const mH = t.match(/^host\s+(\S+)/);
        // 官方語法（Cisco Secure Firewall ASA CLI Configuration Guide）：
        // subnet {IPv4_address IPv4_mask | IPv6_address/IPv6_prefix} —— IPv6 是單一 token 的
        // 斜線 CIDR 寫法，與 IPv4 雙 token（位址+遮罩）不同，需分開比對，不能共用同一個正則
        const mS6 = t.match(/^subnet\s+(\S+\/\d+)$/);
        const mS4 = t.match(/^subnet\s+(\S+)\s+(\S+)/);
        const mR = t.match(/^range\s+(\S+)\s+(\S+)/);
        const mN = t.match(/^network-object\s+(.+)/);
        if (mH) members.push(mH[1]);
        else if (mS6) members.push(mS6[1]);
        else if (mS4) members.push(`${mS4[1]}/${mS4[2]}`);
        else if (mR) members.push(`${mR[1]}-${mR[2]}`);
        else if (mN) members.push(mN[1].trim());
      }
      // category：ASA 語法沒有獨立的 v4/v6 物件關鍵字（host/subnet 兩者共用，格式差異只在值
      // 本身），buildAddrTypeMap()/buildCiscoASAAddrTypeMap() 對 'address'/'address6' 一視
      // 同仁（用 colon 偵測值本身判斷型別），固定填 'address'/'address-group' 即可。
      // members 改存逗號分隔字串（比照專案既有慣例，UI 渲染與其他廠牌 parser 皆預期字串）
      addrs.push({ name, type:mGrp?'group':'host', category:mGrp?'address-group':'address', subnet:members[0]||'-', members:members.join(', '), color:'0' });
    }
    return addrs;
  }
  // ASA 的 group members 是原始片段字串（如 "host 2001:db8::1"／"192.168.1.0/24"／
  // "object WEB-SERVER"），不是共用 buildAddrTypeMap() 群組邏輯假設的「純名稱清單」，故先
  // 沿用共用函式處理好 host 型別物件的分類，再疊加一輪 ASA 專屬的 group 分類覆寫回 map
  function buildCiscoASAAddrTypeMap(addressObjects) {
    const map = buildAddrTypeMap(addressObjects);
    (addressObjects || []).forEach(o => {
      if (o.type !== 'group') return;
      const frags = (o.members || '').split(/\s*,\s*/).filter(Boolean);
      const types = new Set();
      // ASA 合法語法允許巢狀 group（network-object object-group NAME），先前只認得
      // "object "（結尾帶空格）前綴，"object-group NAME" 這種字面字串因第7個字元是 "-"
      // 比對不到，會落入 else 分支直接用 f.includes(':') 判斷整段 "object-group NAME"
      // 字串（天生不含冒號），永遠誤判為 v4，導致巢狀群組內真正是 IPv6 的內容從未被
      // 遞迴反查（2026-09 全功能審查發現）
      frags.forEach(f => {
        const mRef = f.match(/^object(?:-group)?\s+(.+)$/);
        if (mRef) types.add(map.get(mRef[1]) || 'v4');
        else types.add(f.includes(':') ? 'v6' : 'v4');
      });
      map.set(o.name, types.size > 1 ? 'mixed' : (types.values().next().value || 'v4'));
    });
    return map;
  }

  function parseServiceObjects(text) {
    const svcs = [];
    // 依協定累積埠範圍；tcp-udp 兩邊都加，icmp／ip 另記旗標（2026-10-16：原本只輸出 port，核心比對讀 tcpPorts／udpPorts，ASA 服務物件永遠比對不到）
    const add = (acc, proto, spec) => {
      const pr = String(proto || '').toLowerCase();
      if (pr === 'ip') { acc.ip = true; return; }
      if (pr === 'icmp' || pr === 'icmp6') { acc.icmp = true; return; }
      if (!spec) { if (pr === 'tcp' || pr === 'tcp-udp') acc.tcp.push('1-65535'); if (pr === 'udp' || pr === 'tcp-udp') acc.udp.push('1-65535'); return; }
      if (pr === 'tcp' || pr === 'tcp-udp') acc.tcp.push(spec);
      if (pr === 'udp' || pr === 'tcp-udp') acc.udp.push(spec);
    };
    const build = (name, acc, refs, display, type) => {
      const protos = [acc.tcp.length && 'TCP', acc.udp.length && 'UDP', acc.icmp && 'ICMP'].filter(Boolean);
      return { name, proto: acc.ip ? 'IP' : protos.join('/'), port: display.join(',') || '-', tcpPorts: acc.tcp.join(',') || '-', udpPorts: acc.udp.join(',') || '-',
        type, color: '0', members: refs.join(', ') || '-', refOnly: !acc.ip && !protos.length && refs.length > 0 };
    };
    for (const block of text.split(/^(?=object-group\s+service\s|object\s+service\s)/m)) {
      const g = block.match(/^object-group\s+service\s+(\S+)(?:\s+(\S+))?/);
      const o = !g && block.match(/^object\s+service\s+(\S+)/);
      if (!g && !o) continue;
      const acc = { tcp: [], udp: [], icmp: false, ip: false }, refs = [], display = [];
      const lines = block.split('\n').slice(1).filter(l => /^\s/.test(l)).map(l => l.trim());
      for (const t of lines) {
        // port-object eq/range（群組本身的協定）
        const mP = t.match(/^port-object\s+(eq|gt|lt|neq|range)\s+(\S+)(?:\s+(\S+))?/);
        if (mP && g) { const spec = asaPortSpec(mP[1], mP[2], mP[3]); add(acc, g[2] || '', spec); display.push(mP[3] ? `${mP[2]}-${mP[3]}` : mP[2]); continue; }
        // service-object PROTO [source …] [destination] OP 埠、或 object service 的 service PROTO … destination OP 埠
        const mS = t.match(/^(?:service-object|service)\s+(tcp-udp|tcp|udp|icmp6?|ip|\d+)\b(.*)$/);
        if (mS) {
          const d = mS[2].match(/destination\s+(eq|gt|lt|neq|range)\s+(\S+)(?:\s+(\S+))?/) || mS[2].match(/^\s*(eq|gt|lt|neq|range)\s+(\S+)(?:\s+(\S+))?/);
          const spec = d ? asaPortSpec(d[1], d[2], d[3]) : '';
          if (spec !== null) add(acc, mS[1], spec); else refs.push(`${mS[1]}/${d[2]}`);
          display.push(d ? `${mS[1]}/${d[3] ? d[2] + '-' + d[3] : d[2]}` : mS[1]);
          continue;
        }
        // 引用其他物件／群組（group-object NAME、service-object object NAME），供未使用物件稽核與查詢展開
        const mR = t.match(/^(?:group-object|service-object\s+object)\s+(\S+)/);
        if (mR) refs.push(mR[1]);
      }
      svcs.push(build(g ? g[1] : o[1], acc, refs, display, g ? 'group' : 'object'));
    }
    return svcs;
  }

  function parseNAT(text) {
    const nat = [];
    let id = 1;
    for (const line of text.split('\n')) {
      const mNew = line.match(/^nat\s+\(([^,]+),([^)]+)\)\s+(?:\d+\s+)?source\s+(static|dynamic)\s+(\S+)\s+(\S+)/);
      if (mNew) {
        // twiceDst：twice NAT 另帶 destination 條件（只對特定目的轉換），多台路徑查詢的來源 NAT 視為無法確定
        nat.push({ id:id++, type:mNew[3], srcIf:mNew[1].trim(), dstIf:mNew[2].trim(), origSrc:mNew[4], transSrc:mNew[5], twiceDst:/\sdestination\s+static\s/.test(line) });
        continue;
      }
      const mOld = line.match(/^nat\s+\((\S+)\)\s+(\d+)\s+(\S+)\s+(\S+)/);
      if (mOld) {
        nat.push({ id:id++, type:mOld[2]==='0'?'nonat':'dynamic', srcIf:mOld[1], dstIf:'outside', origSrc:`${mOld[3]}/${mOld[4]}`, transSrc:'interface' });
      }
    }
    // object NAT（auto NAT，2026-10-16）：object network X 底下縮排的
    // `nat (實際介面,對外介面) static|dynamic 對外位址 [service tcp|udp 實際埠 對外埠]`，實際位址即該物件
    for (const block of text.split(/^(?=object\s+network\s)/m)) {
      const ob = block.match(/^object\s+network\s+(\S+)/);
      if (!ob) continue;
      const m = block.match(/^\s+nat\s+\(([^,]+),([^)]+)\)\s+(static|dynamic)\s+(\S+)(?:\s+service\s+(tcp|udp)\s+(\S+)\s+(\S+))?/m);
      if (!m) continue;
      const e = { id:id++, name:ob[1], type:m[3], srcIf:m[1].trim(), dstIf:m[2].trim(), origSrc:ob[1], transSrc:m[4] };
      if (m[5]) { e.proto = m[5]; e.realPort = String(asaPort(m[6]) ?? m[6]); e.mappedPort = String(asaPort(m[7]) ?? m[7]); }
      nat.push(e);
    }
    return nat;
  }

  function parseRoutes(text) {
    const routes = [];
    let id = 1;
    for (const line of text.split('\n')) {
      const m = line.match(/^route\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?/);
      if (!m) continue;
      // 欄位形狀比照其餘廠牌 parser 共用 schema（id/dst/device/distance/status/blackhole/
      // comment），而非自成一格的 iface/mask/metric——2026-07-21 查核發現原本自成一格的欄位名稱
      // 導致 UI 路由表/HTML 報表/CSV 匯出/跨廠牌轉換全部讀不到值（讀 r.device 卻存的是 r.iface，
      // 讀 r.distance 卻存的是 r.metric），dst 沿用「網段 遮罩」空白分隔格式（netMaskOf() 既有
      // fallback 分支已支援此格式，不需另外改動下游轉換函式）
      routes.push({
        id: String(id++), type: m[2]==='0.0.0.0'?'default':'static',
        dst: `${m[2]} ${m[3]}`, device: m[1], gateway: m[4],
        distance: m[5]||'1', priority: m[5]||'1', status:'enable',
        blackhole:'disable', comment:'-', vrf:'global', vdom:'global'
      });
    }
    return routes;
  }

  function parseVPN(text) {
    const vpn = [];
    const lines = text.split('\n');

    // Parse best crypto isakmp policy (lowest seq = highest priority)
    let bestP1 = {auth:'psk', enc:'-', hash:'-', dhgrp:'-', lifetime:'86400'};
    let inP1 = false, p1seq = Infinity, curP1 = {};
    for (const line of lines) {
      const mP1 = line.match(/^crypto isakmp policy\s+(\d+)/);
      if (mP1) { inP1=true; const seq=parseInt(mP1[1]); if(seq<p1seq){p1seq=seq;curP1={};} else inP1=false; continue; }
      if (inP1) {
        if (/^\S/.test(line)){inP1=false;bestP1={auth:curP1.auth||'psk',enc:curP1.enc||'-',hash:curP1.hash||'-',dhgrp:curP1.grp||'-',lifetime:curP1.lt||'86400'};continue;}
        const mA=line.match(/^\s+authentication\s+(\S+)/); if(mA)curP1.auth=mA[1]==='pre-share'?'psk':mA[1];
        const mE=line.match(/^\s+encryption\s+(\S+)/); if(mE)curP1.enc=mE[1];
        const mH=line.match(/^\s+hash\s+(\S+)/); if(mH)curP1.hash=mH[1];
        const mG=line.match(/^\s+group\s+(\d+)/); if(mG)curP1.grp='group'+mG[1];
        const mL=line.match(/^\s+lifetime\s+(\d+)/); if(mL)curP1.lt=mL[1];
      }
    }
    // 收尾防呆：若 crypto isakmp policy 區塊剛好是檔案最後一段（沒有任何後續非縮排行觸發
    // inP1=false 分支），bestP1 會停留在函式開頭的預設值、curP1 蒐集到的真實設定值被丟棄
    // （2026-09 全功能審查發現，比照本專案既有「區塊收尾依賴下一行」風險模式的標準修法）
    if (inP1) bestP1 = {auth:curP1.auth||'psk',enc:curP1.enc||'-',hash:curP1.hash||'-',dhgrp:curP1.grp||'-',lifetime:curP1.lt||'86400'};

    // Parse global isakmp settings
    let natTraversal = '-', dpd = '-';
    for (const line of lines) {
      if (/^crypto isakmp nat-traversal\b/.test(line)) natTraversal = 'enable';
      if (/^isakmp keepalive threshold\b/.test(line)) dpd = 'enable';
    }

    // Parse transform-sets: name → esp algorithms
    const xformSets = {};
    for (const line of lines) {
      const mX = line.match(/^crypto ipsec transform-set\s+(\S+)\s+(.+)/);
      if (mX) xformSets[mX[1]] = mX[2].trim();
    }

    // Build aclMap: ACL name → {src, dst} from "access-list NAME permit ip SRC MASK DST MASK"
    const aclMap = {};
    for (const line of lines) {
      const mA = line.match(/^access-list\s+(\S+)\s+(?:extended\s+)?permit\s+ip\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/);
      if (mA) { aclMap[mA[1]] = aclMap[mA[1]] || { src: mA[2]+'/'+mA[3], dst: mA[4]+'/'+mA[5] }; }
    }

    // Parse crypto map entries: keyed by seq (mapName+seq) to avoid peer-collision overwrite
    const mapEntries = {};
    // 以「map 名稱-序號」為鍵，任一子指令先出現都建立項目：ASA running-config 慣例是
    // match address 排在 set peer 之前，原本只有 set peer 會建立項目，先出現的 match address
    // 找不到項目而被丟棄，VPN 加密網段一律顯示 "-"；另原本以 endsWith('-'+序號) 找項目，
    // 不同 map 名稱同序號時會對錯
    const entryOf = (name, seq) => { const k = `${name}-${seq}`; return mapEntries[k] = mapEntries[k] || { name, seq }; };
    for (const line of lines) {
      const mPeer = line.match(/^crypto map\s+(\S+)\s+(\d+)\s+set peer\s+(\S+)/);
      if (mPeer) { entryOf(mPeer[1], mPeer[2]).peer = mPeer[3]; continue; }
      const mMatch = line.match(/^crypto map\s+(\S+)\s+(\d+)\s+match address\s+(\S+)/);
      if (mMatch) { entryOf(mMatch[1], mMatch[2]).acl = mMatch[3]; continue; }
      const mXf = line.match(/^crypto map\s+(\S+)\s+(\d+)\s+set transform-set\s+(\S+)/);
      if (mXf) { entryOf(mXf[1], mXf[2]).xform = mXf[3]; continue; }
      const mLt = line.match(/^crypto map\s+(\S+)\s+(\d+)\s+set security-association lifetime seconds\s+(\d+)/);
      if (mLt) { entryOf(mLt[1], mLt[2]).p2lt = mLt[3]; continue; }
      const mIkev2 = line.match(/^crypto map\s+(\S+)\s+(\d+)\s+set ikev(\d)/);
      if (mIkev2) { entryOf(mIkev2[1], mIkev2[2]).ikever = mIkev2[3]; continue; }
    }

    // Parse tunnel-groups: peer → {hasPsk, type, defaultGroupPolicy}
    const tunnelGroups = {};
    let inTG = false, curTG = '';
    for (const line of lines) {
      const mTG = line.match(/^tunnel-group\s+(\S+)\s+type\s+(\S+)/);
      if (mTG) { curTG=mTG[1]; tunnelGroups[curTG]={type:mTG[2],hasPsk:false}; inTG=true; continue; }
      const mTGAttr = line.match(/^tunnel-group\s+(\S+)\s+ipsec-attributes/);
      if (mTGAttr) { curTG=mTGAttr[1]; inTG=true; continue; }
      if (inTG) {
        if (/^\S/.test(line)){inTG=false;continue;}
        if (/pre-shared-key/.test(line)&&tunnelGroups[curTG])tunnelGroups[curTG].hasPsk=true;
      }
    }

    // Parse tunnel-group ... general-attributes：peer/name → default-group-policy
    let inTGGen = false, curTGGen = '';
    for (const line of lines) {
      const mTGGen = line.match(/^tunnel-group\s+(\S+)\s+general-attributes/);
      if (mTGGen) { curTGGen=mTGGen[1]; inTGGen=true; continue; }
      if (inTGGen) {
        if (/^\S/.test(line)){inTGGen=false;continue;}
        const mDGP = line.match(/^\s+default-group-policy\s+(\S+)/);
        if (mDGP) { tunnelGroups[curTGGen] = tunnelGroups[curTGGen] || {}; tunnelGroups[curTGGen].defaultGroupPolicy = mDGP[1]; }
      }
    }

    // Build standardAclMap：ACL 名稱 → CIDR 清單，來自 "access-list NAME standard permit NETWORK MASK"
    // （split-tunnel-network-list 參照的是 standard ACL，跟既有 aclMap 認得的 "permit ip SRC MASK DST MASK" 兩段式語法不同，必須是 standard，extended 會被 ASA 靜默 fallback 成 tunnelall）
    const standardAclMap = {};
    for (const line of lines) {
      const mSA = line.match(/^access-list\s+(\S+)\s+standard\s+permit\s+(\S+)\s+(\S+)/);
      if (mSA) { (standardAclMap[mSA[1]] = standardAclMap[mSA[1]] || []).push(`${mSA[2]}/${mSA[3]}`); }
    }

    // Parse group-policy ... attributes：名稱 → {splitTunnelPolicy, aclName}
    const groupPolicies = {};
    let inGP = false, curGP = '';
    for (const line of lines) {
      const mGP = line.match(/^group-policy\s+(\S+)\s+attributes/);
      if (mGP) { curGP=mGP[1]; groupPolicies[curGP]=groupPolicies[curGP]||{}; inGP=true; continue; }
      if (inGP) {
        if (/^\S/.test(line)){inGP=false;continue;}
        const mSTP = line.match(/^\s+split-tunnel-policy\s+(\S+)/); if(mSTP) groupPolicies[curGP].splitTunnelPolicy=mSTP[1];
        const mSTL = line.match(/^\s+split-tunnel-network-list\s+value\s+(\S+)/); if(mSTL) groupPolicies[curGP].aclName=mSTL[1];
      }
    }

    // Build VPN entries — collect unique peers from mapEntries + tunnelGroups
    const peerMap = {}; // peer → best mapEntry
    for (const me of Object.values(mapEntries)) {
      if (me.peer && !peerMap[me.peer]) peerMap[me.peer] = me;
    }
    const allPeers = new Set([...Object.keys(peerMap),...Object.keys(tunnelGroups)]);
    let id = 1;
    for (const peer of allPeers) {
      const me = peerMap[peer] || {};
      const tg = tunnelGroups[peer] || {};
      if (tg.type && !tg.type.includes('ipsec')) continue;
      const xformDesc = me.xform ? (xformSets[me.xform]||me.xform) : '-';
      const p2Proposal = xformDesc !== '-' ? xformDesc : 'esp-aes-256 esp-sha256-hmac';
      const proposal = bestP1.enc!=='-' ? bestP1.enc+'-'+bestP1.hash : '-';
      const acl = me.acl ? (aclMap[me.acl]||null) : null;
      vpn.push({
        id: id++,
        name:  me.name ? `${me.name}@${peer}` : `TG_${peer}`,
        type:  'ipsec-p1',
        remote: peer,
        iface: 'outside',
        ikeVer: me.ikever||'1',
        authMethod: (tg.hasPsk||true) ? 'psk' : 'certificate',
        proposal, dhgrp: bestP1.dhgrp, lifetime: bestP1.lifetime,
        natTraversal, dpd,
        status: 'enable',
        phase2: me.xform ? [{
          name: (me.name||'MAP')+'-P2',
          phase1: peer,
          proposal: p2Proposal,
          lifetime: me.p2lt||'3600',
          pfs: '-', dhgrp: '-',
          localSub:  acl ? acl.src : '-',
          remoteSub: acl ? acl.dst : '-',
          localAddr:'-', remoteAddr:'-', autoNeg:'-', comment:'-',
        }] : [],
      });
    }

    // Build SSL-VPN（AnyConnect remote-access）entries：tunnel-group type remote-access/webvpn → default-group-policy → split-tunnel-network-list → standard ACL CIDR 清單
    for (const [tgName, tg] of Object.entries(tunnelGroups)) {
      if (!tg.type || !/remote-access|webvpn/.test(tg.type)) continue;
      const gp = tg.defaultGroupPolicy ? (groupPolicies[tg.defaultGroupPolicy] || {}) : {};
      const cidrs = gp.aclName ? (standardAclMap[gp.aclName] || []) : [];
      vpn.push({
        id: id++,
        name: `AnyConnect: ${tgName}`,
        type: 'ssl-vpn',
        remote: '-', iface: 'outside', ikeVer: '-', authMethod: 'ssl',
        proposal: '-', dhgrp: '-', lifetime: '-', natTraversal: '-', dpd: '-',
        status: 'enable',
        splitTunnel: cidrs.length ? 'enable' : 'disable',
        splitTunnelRoutingAddr: cidrs.join(', ') || '-',
        phase2: [],
      });
    }
    return vpn;
  }

  function parseUsers(text) {
    const users = [];
    for (const line of text.split('\n')) {
      const m = line.match(/^username\s+(\S+)\s+password\s+\S+(?:\s+encrypted)?\s*(?:privilege\s+(\d+))?/);
      if (!m) continue;
      const priv = parseInt(m[2]||'0');
      users.push({ name:m[1], role:priv>=15?'admin':priv>=5?'operator':'readonly', type:'local', groups:[] });
    }
    return users;
  }

  function parseDhcp(text) {
    const pools = {};
    for (const line of text.split('\n')) {
      const mA = line.match(/^dhcpd address\s+(\S+)-(\S+)\s+(\S+)/);
      if (mA) pools[mA[3]] = { iface:mA[3], start:mA[1], end:mA[2], dns:[] };
      const mD = line.match(/^dhcpd dns\s+(.+)/);
      if (mD) Object.values(pools).forEach(p=>{ p.dns=mD[1].trim().split(/\s+/); });
    }
    return { servers: Object.values(pools).map(p=>({ name:p.iface, iface:p.iface, start:p.start, end:p.end, dns:p.dns.join(','), gateway:'' })), relays: [] };
  }

  function parseDns(text) {
    const servers = [];
    let inGroup = false;
    for (const line of text.split('\n')) {
      if (/^dns server-group/.test(line)) { inGroup=true; continue; }
      if (inGroup && /^\S/.test(line)) inGroup=false;
      if (inGroup) { const m=line.match(/^\s+name-server\s+(\S+)/); if(m) servers.push(m[1]); }
    }
    return { servers, secondaries:[], domain:(text.match(/^dns domain-lookup\s+(\S+)/m)||[])[1]||'',
      proxy:false, proxyRules:[], dnsOverTls:false, cacheSize:'-', static:[] };
  }

  function parseSnmp(text) {
    const hosts = [];
    for (const line of text.split('\n')) {
      const m = line.match(/^snmp-server host\s+(\S+)\s+(\S+)\s+(?:community\s+)?(\S+)/);
      if (m) hosts.push({ host:m[2], iface:m[1], community:m[3], version:'v2c' });
    }
    const globalCommunity = (text.match(/^snmp-server community\s+(\S+)/m)||[])[1]||'';
    const location = (text.match(/^snmp-server location\s+(.+)/m)||[])[1]?.trim()||'';
    const contact = (text.match(/^snmp-server contact\s+(.+)/m)||[])[1]?.trim()||'';
    const commNames = new Set(hosts.map(h=>h.community));
    if (globalCommunity) commNames.add(globalCommunity);
    const communities = [...commNames].map(name => ({ name, permission:'ro', allowedHosts:[], events:'-', status:'enable' }));
    return {
      enabled: communities.length>0,
      agent: { name:'-', description:'-', location, contact, version: hosts.length?['v2c']:[] },
      communities,
      v3users: [],
      trapServers: hosts.map(h=>({ ip:h.host, port:'162', community:h.community, version:h.version }))
    };
  }

  function parseLogServers(text) {
    // 2026-08-20 修正：原本回傳純陣列＋鍵名 logServers（大寫S），但其餘 12 家 parser 與所有
    // 消費端（converter/reporter/app.js）一律讀 logservers（全小寫）＋{syslog,fortianalyzer,
    // netflow,logForward} 物件形狀，鍵名不符導致 ASA/FTD 的 log server 資料永遠不會出現在
    // 報表/CSV/converter，屬純粹的死欄位。改為對齊共用形狀；level 取自官方語法本來就是
    // 全域（非逐 host）的 `logging trap <level>`
    const syslog = [];
    const level = (text.match(/^logging trap\s+(\S+)/m)||[])[1] || '-';
    for (const line of text.split('\n')) {
      const m = line.match(/^logging host\s+(\S+)\s+(\S+)(?:\s+(\d+))?/);
      if (m) syslog.push({ server:m[2], iface:m[1], port:m[3]||'514', facility:'-', level, protocol:'UDP', status:'enable' });
    }
    return { syslog, fortianalyzer:[], netflow:[], logForward:[] };
  }

  // HA/Cluster：已查證官方 Failover 語法——`failover` 單獨一行代表啟用，`failover lan unit
  // primary/secondary` 決定角色，`failover lan interface NAME IFACE` 指定 LAN failover 介面，
  // `failover interface ip NAME PRIMARY_IP MASK standby STANDBY_IP` 指定雙機 IP，
  // `failover group N` 決定 Active/Active 群組（ASA 5500 Active/Active 模式才有）
  function parseHa(text) {
    const result = { enabled:false, mode:'-', groupId:'-', priority:'-', peerIp:'-', syncInterface:'-', vip:'-' };
    if (!/^failover\s*$/m.test(text)) return result;
    result.enabled = true;
    result.mode = /^failover\s+lan\s+unit\s+primary/m.test(text) ? 'primary'
      : /^failover\s+lan\s+unit\s+secondary/m.test(text) ? 'secondary' : '-';
    const lanIfaceM = text.match(/^failover\s+lan\s+interface\s+(\S+)\s+(\S+)/m);
    result.syncInterface = lanIfaceM ? `${lanIfaceM[1]} (${lanIfaceM[2]})` : '-';
    const ifIpM = text.match(/^failover\s+interface\s+ip\s+\S+\s+(\S+)\s+\S+\s+standby\s+(\S+)/m);
    if (ifIpM) { result.vip = ifIpM[1]; result.peerIp = ifIpM[2]; }
    const groupM = text.match(/^failover\s+group\s+(\d+)/m);
    result.groupId = groupM ? groupM[1] : '-';
    return result;
  }

  function parse(text) {
    const addresses = parseAddressObjects(text);
    const addrTypeMap = buildCiscoASAAddrTypeMap(addresses);
    return {
      vendor: 'Cisco ASA',
      deviceInfo:  parseDeviceInfo(text),
      interfaces:  parseInterfaces(text),
      policies:    parsePolicies(text, addrTypeMap),
      // same-security-traffic permit inter-interface|intra-interface（第十八輪 TF，查詢的 security-level 判斷用）
      sameSecurity: { inter: /^same-security-traffic\s+permit\s+inter-interface/m.test(text), intra: /^same-security-traffic\s+permit\s+intra-interface/m.test(text) },
      addresses,
      services:    parseServiceObjects(text),
      nat:         parseNAT(text),
      routes:      parseRoutes(text),
      vpn:         parseVPN(text),
      users:       parseUsers(text),
      schedules:   [],
      dhcp:        parseDhcp(text),
      dns:         parseDns(text),
      snmp:        parseSnmp(text),
      logservers:  parseLogServers(text),
      sdwan:       null,
      ha:          parseHa(text),
      wwan:        null,
    };
  }

  return { parse };
})();

// ═══ Cisco Firepower/FTD Parser ═══
// FTD 的 show running-config（Lina 引擎）大量重用 ASA 語法（介面/路由/基礎 NAT），
// 故直接重用 CiscoASAParser 既有解析邏輯，僅覆寫 vendor 標籤與韌體版本判斷方式
// （banner 為 "NGFW Version X.X.X"，非 ASA 的 "ASA Version X.X"）。
// ACP（Access Control Policy）/IPS(Snort)/大部分規則由 FMC 或 FDM 圖形化管理，
// 不會出現在 show running-config 裡，故 policies 僅涵蓋 CLI 可見的基礎規則
// （與 ASA 邏輯相同，屬既有 graceful degradation 慣例，非本解析器缺口）。
// 僅支援 show running-config（Lina CLI）格式，不支援 FMC 匯出的 ACP JSON/YAML 格式。
const CiscoFTDParser = (() => {
  function parse(text) {
    const r = CiscoASAParser.parse(text);
    r.vendor = 'Cisco FTD';
    r.deviceInfo.vendor = 'Cisco FTD';
    const fw = (text.match(/^NGFW Version\s+(\S+)/m)||[])[1];
    if (fw) r.deviceInfo.firmware = fw;
    return r;
  }
  return { parse };
})();

