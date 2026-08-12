// ══════════════════════════════════════════════════════════
//  ZYXEL USG/ATP (ZLD 韌體) PARSER
// ══════════════════════════════════════════════════════════
// 2026-07-30 對外查證官方 ZyWALL/USG (ZLD) CLI Reference Guide（v4.15，
// download.from.zyxel.ru 鏡像）後新增。ZLD 是傳統 flat CLI（configure terminal 進入
// Global Config 模式，非 Juniper 式 edit-commit），確認語法：
//   secure-policy insert <N> 進入 sub-command 模式，內含 from/to/sourceip/
//   destinationip/service/action/name/description/log 等逐行子指令；
//   address-object <name> <value>（value 本身格式即代表類型：單一 IP=host、
//   "X-Y"=range、"X/N"=subnet，無需額外類型關鍵字）；
//   service-object <name> {tcp|udp} {eq <port>|range <p1> <p2>}；
//   interface <name> 進入 sub-command 模式，內含 ip address <ip> <mask>／
//   ip gateway <ip>／description；zone <name> 進入 sub-command 模式，內含
//   interface <name> 逐行宣告成員（區域歸屬是從 zone 區塊反查回 interface，
//   非 interface 自己宣告）；ip route <dest> <mask> {interface|nexthop} [metric]；
//   hostname <name>。
// 無真實裝置匯出檔可比對校正，信心度比照 2026-07-29 Ruijie 先例（純官方文件組出）。
// VPN／NAT／DHCP／Users／Schedules 因查無足夠把握的完整語法佐證不實作，維持空值，
// 不猜測（比照 MikroTik ha/nat/vpn 等既有慣例，讓 getConversionLoss() 透明告知）。
const ZyxelParser = (() => {
  // interface/zone/secure-policy 皆為 "關鍵字 名稱/編號" 開啟 sub-command 模式、
  // 裸行 "exit" 關閉，三者不會互相巢狀（官方文件範例確認 sub-command 內容皆是平鋪
  // key-value/關鍵字行，無進一步巢狀子模式），故用單一狀態機一次掃描即可正確歸屬
  function splitBlocks(text) {
    const interfaces = {}, zones = {}, policies = [];
    let mode = null; // {type:'interface'|'zone'|'secure-policy', key, rule}
    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line) continue;
      if (mode) {
        if (/^exit\s*$/.test(line)) { mode = null; continue; }
        if (mode.type === 'interface') interfaces[mode.key].push(line);
        else if (mode.type === 'zone') zones[mode.key].push(line);
        else if (mode.type === 'secure-policy') mode.rule.lines.push(line);
        continue;
      }
      let m;
      if ((m = line.match(/^interface\s+(\S+)/))) { interfaces[m[1]] = interfaces[m[1]] || []; mode = { type: 'interface', key: m[1] }; continue; }
      if ((m = line.match(/^zone\s+(\S+)/))) { zones[m[1]] = zones[m[1]] || []; mode = { type: 'zone', key: m[1] }; continue; }
      if ((m = line.match(/^secure-policy\s+(?:insert\s+)?(\d+)/))) { const rule = { num: m[1], lines: [] }; policies.push(rule); mode = { type: 'secure-policy', rule }; continue; }
    }
    return { interfaces, zones, policies };
  }

  function parseDeviceInfo(text) {
    const hostname = (text.match(/^hostname\s+(\S+)/m) || [])[1] || '-';
    return { vendor: 'Zyxel', hostname, firmware: '-', model: '-', serial: '-', vdom: [] };
  }

  function parseInterfaces(blocks) {
    const ifaceZone = {};
    Object.entries(blocks.zones).forEach(([zname, lines]) => {
      lines.forEach(l => { const m = l.match(/^interface\s+(\S+)/); if (m) ifaceZone[m[1]] = zname; });
    });
    return Object.entries(blocks.interfaces).map(([name, lines]) => {
      const body = lines.join('\n');
      const ipM = body.match(/^ip address\s+([\d.]+)\s+([\d.]+)/m);
      const descM = body.match(/^description\s+(.+)/m);
      const zone = ifaceZone[name] || '-';
      const role = /^WAN/i.test(zone) ? 'WAN' : /^DMZ/i.test(zone) ? 'DMZ' : /^LAN/i.test(zone) ? 'LAN' : 'LAN';
      return {
        name, ip: ipM ? ipM[1] : '-', mask: ipM ? ipM[2] : '-', type: 'physical',
        vlanId: '-', alias: name, desc: descM ? descM[1].trim() : '',
        status: /^shutdown\s*$/m.test(body) ? 'down' : 'up',
        mtu: '-', speed: '-', mode: ipM ? 'static' : 'dhcp',
        vdom: '-', role, allowaccess: '-', _zone: zone,
      };
    });
  }

  function parseAddressObjects(text) {
    const out = [];
    const re = /^address-object\s+(\S+)\s+(\S+)/gm;
    let m;
    while ((m = re.exec(text)) !== null) {
      const name = m[1], val = m[2];
      // 2026-08-09 稽核修復：原判斷順序 "/" → "-" → 字母，含連字號的 FQDN（如
      // backup-server.corp.com，網域命名極常見）會被 "-" 判斷式先攔截誤判為 iprange，
      // 再被 split('-') 切成無意義字串；改為字母判斷優先於連字號判斷
      const type = val.includes('/') ? 'ipmask' : /[a-zA-Z]/.test(val) ? 'fqdn' : val.includes('-') ? 'iprange' : 'ipmask';
      const [startIp, endIp] = val.includes('-') && type === 'iprange' ? val.split('-') : ['-', '-'];
      out.push({
        category: 'address', name, type,
        subnet: type === 'ipmask' ? val : '-',
        fqdn: type === 'fqdn' ? val : '-',
        startIp, endIp, iface: '-', members: '-', comment: '',
      });
    }
    // 官方 CLI Reference Guide（ZLD 27.2.1，Address Object Commands）確認 IPv6 位址物件
    // 使用獨立關鍵字 address6-object（非 address-object 加冒號值），語法：
    // address6-object object_name {ipv6_address | ipv6_range | ipv6_subnet}
    // 先前完全沒有對應解析路徑，這批物件從未被解析出來（非型別判斷順序錯誤）
    const re6 = /^address6-object\s+(\S+)\s+(\S+)/gm;
    let m6;
    while ((m6 = re6.exec(text)) !== null) {
      const name = m6[1], val = m6[2];
      const type = val.includes('/') ? 'ipmask' : val.includes('-') ? 'iprange' : 'ipmask';
      const [startIp, endIp] = val.includes('-') && type === 'iprange' ? val.split('-') : ['-', '-'];
      out.push({
        category: 'address6', name, type,
        subnet: type === 'ipmask' ? val : '-',
        fqdn: '-',
        startIp, endIp, iface: '-', members: '-', comment: '',
      });
    }
    return out;
  }

  function parseServiceObjects(text) {
    const out = [];
    const re = /^service-object\s+(\S+)\s+(tcp|udp)\s+(?:eq\s+(\d+)|range\s+(\d+)\s+(\d+))/gim;
    let m;
    while ((m = re.exec(text)) !== null) {
      const name = m[1], proto = m[2].toUpperCase();
      const port = m[3] ? m[3] : `${m[4]}-${m[5]}`;
      out.push({
        category: 'service', name, proto,
        tcpPorts: proto === 'TCP' ? port : '-',
        udpPorts: proto === 'UDP' ? port : '-',
        icmpType: '-', members: '-', comment: '',
      });
    }
    return out;
  }

  function parsePolicies(blocks, addrTypeMap) {
    return blocks.policies.map(rule => {
      const body = rule.lines.join('\n');
      const from = (body.match(/^from\s+(\S+)/m) || [])[1] || 'any';
      const to = (body.match(/^to\s+(\S+)/m) || [])[1] || 'any';
      const srcAddr = (body.match(/^sourceip\s+(\S+)/m) || [])[1] || 'any';
      const dstAddr = (body.match(/^destinationip\s+(\S+)/m) || [])[1] || 'any';
      const service = (body.match(/^service\s+(\S+)/m) || [])[1] || 'any';
      const actionRaw = (body.match(/^action\s+(\S+)/m) || [])[1] || 'deny';
      const name = (body.match(/^name\s+(\S+)/m) || [])[1] || `Rule-${rule.num}`;
      const desc = (body.match(/^description\s+(.+)/m) || [])[1] || '';
      const noActivate = /^no\s+activate\s*$/m.test(body);
      const srcAddrSplit = _splitAddr(srcAddr, addrTypeMap);
      const dstAddrSplit = _splitAddr(dstAddr, addrTypeMap);
      return {
        id: parseInt(rule.num, 10) || 0, name,
        srcIntf: from, dstIntf: to, srcAddr, dstAddr,
        srcAddr4: srcAddrSplit.v4, srcAddr6: srcAddrSplit.v6, dstAddr4: dstAddrSplit.v4, dstAddr6: dstAddrSplit.v6,
        service, schedule: 'always',
        action: /^(allow)$/i.test(actionRaw) ? 'accept' : actionRaw.toLowerCase(),
        nat: 'disable', ippool: 'disable', poolname: '-',
        logtraffic: /^log\b/m.test(body) ? 'all' : 'disable',
        utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
        status: noActivate ? 'disable' : 'enable',
        users: '-', groups: '-', comments: desc,
        _vdom: '',
      };
    });
  }

  function parseRoutes(text) {
    const out = [];
    let seq = 1;
    const re = /^ip route\s+([\d.]+)\s+([\d.]+)\s+(\S+)(?:\s+(\d+))?/gm;
    let m;
    while ((m = re.exec(text)) !== null) {
      const net = m[1], mask = m[2], nh = m[3], metric = m[4] || '0';
      const isIface = !/^\d+\.\d+\.\d+\.\d+$/.test(nh);
      const maskBits = mask.split('.').reduce((n, o) => n + (parseInt(o, 10) >>> 0).toString(2).split('1').length - 1, 0);
      const dst = `${net}/${maskBits}`;
      out.push({
        type: dst === '0.0.0.0/0' ? 'default' : 'static', id: String(seq++),
        dst, gateway: isIface ? '-' : nh, device: isIface ? nh : '-',
        distance: metric, priority: metric,
        blackhole: 'disable', vrf: 'main', status: 'enable', comment: '',
        protocol_detail: '-', _vdom: '',
      });
    }
    return out;
  }

  // "ip gateway <ip> [metric <n>]" 巢狀於 interface 子模式內，官方文件確認為介面專屬預設
  // 閘道宣告（與頂層 "ip route" 是不同語法但同義，2026-08-01 對外查證官方 CLI Reference
  // Guide 真實 running-config 範例後補上，先前版本完全沒擷取這行）；比照 parseRoutes()
  // 既有輸出形狀合成一筆 default route，seq 從 parseRoutes() 之後接續避免 id 重複
  function parseInterfaceGateways(blocks, startSeq) {
    const out = [];
    let seq = startSeq;
    Object.entries(blocks.interfaces).forEach(([name, lines]) => {
      const body = lines.join('\n');
      const m = body.match(/^ip gateway\s+([\d.]+)(?:\s+metric\s+(\d+))?/m);
      if (!m) return;
      out.push({
        type: 'default', id: String(seq++),
        dst: '0.0.0.0/0', gateway: m[1], device: name,
        distance: m[2] || '1', priority: m[2] || '1',
        blackhole: 'disable', vrf: 'main', status: 'enable', comment: '',
        protocol_detail: '-', _vdom: '',
      });
    });
    return out;
  }

  function detect(text) {
    return /^secure-policy\s+(?:insert\s+)?\d+/m.test(text)
        && (/^address-object\s+\S+\s+\S+/m.test(text) || /^service-object\s+\S+\s+(tcp|udp)/im.test(text) || /ZyWALL|USG FLEX|Zyxel/i.test(text));
  }

  function parse(text) {
    const blocks = splitBlocks(text);
    const staticRoutes = parseRoutes(text);
    const addresses = parseAddressObjects(text);
    const addrTypeMap = buildAddrTypeMap(addresses);
    return {
      vendor: 'Zyxel',
      deviceInfo: parseDeviceInfo(text),
      interfaces: parseInterfaces(blocks),
      policies: parsePolicies(blocks, addrTypeMap),
      routes: staticRoutes.concat(parseInterfaceGateways(blocks, staticRoutes.length + 1)),
      ha: null, nat: [], vpn: [],
      addresses,
      services: parseServiceObjects(text),
      users: [], schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      // 2026-08-01 瀏覽器端到端測試意外抓到既有的「新增廠牌未同步 onParsed() 資料形狀」bug：
      // onParsed()（App.js）對 d.dhcp/d.dns/d.snmp/d.logservers 只做單層 truthy 判斷（如
      // `d.dhcp&&(d.dhcp.servers.length>0...)`），未用 optional chaining，若此處給空陣列/
      // 空物件（truthy 但缺欄位）會在讀取 .servers/.communities 等子欄位時對 undefined 呼叫
      // .length 直接拋錯，導致單獨上傳本廠牌（未與其他廠牌合併）分析時整頁崩潰。比照 `ha:
      // null` 既有慣例改用 null（onParsed()/exportHTML()/merge() 對這些欄位的 guard 皆已是
      // `d.xxx&&...`，null 可安全短路），非新增規則、只是修正型別
      dhcp: null, dns: null, snmp: null, logservers: null,
      wwan: null, wlan: null,
    };
  }

  return { parse, detect };
})();

