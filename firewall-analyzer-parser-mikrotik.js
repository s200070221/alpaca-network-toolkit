// ═══ parser-mikrotik.js ═══
/**
 * MikroTik RouterOS Parser v1.0
 * Supports: /export output (RouterOS 6.x / 7.x)
 * Sections: interfaces, addresses, firewall filter/nat/address-list,
 *           routes, IPsec VPN, users, services
 */
const MikrotikParser = (() => {

  // ── Core line parser ───────────────────────────────────────────────────────
  // Splits a MikroTik 'add'/'set' line into {key: value} pairs
  // Handles: key=value, key="quoted value", key=val1,val2, !negated, bare flags
  function parseLine(line) {
    const result = {};
    // strip leading command word (add/set)
    let rest = line.trim();
    if (/^(add|set)\s+/.test(rest)) rest = rest.replace(/^(add|set)\s+/, '');

    let i = 0;
    while (i < rest.length) {
      // skip spaces
      while (i < rest.length && rest[i] === ' ') i++;
      if (i >= rest.length) break;

      // read key
      const keyStart = i;
      while (i < rest.length && rest[i] !== '=' && rest[i] !== ' ') i++;
      const key = rest.slice(keyStart, i);
      if (!key) { i++; continue; }

      if (i >= rest.length || rest[i] !== '=') {
        result[key] = 'yes'; // bare flag
        continue;
      }
      i++; // skip =

      // read value
      let val = '';
      if (i < rest.length && rest[i] === '"') {
        i++; // skip opening quote
        while (i < rest.length && rest[i] !== '"') {
          if (rest[i] === '\\') i++; // skip escape
          val += rest[i++];
        }
        if (i < rest.length) i++; // skip closing quote
      } else {
        while (i < rest.length && rest[i] !== ' ') val += rest[i++];
      }
      result[key] = val;
    }
    return result;
  }

  // Split the full export text into sections keyed by '/section/path'
  function splitSections(text) {
    const sections = {};
    let currentSection = null;
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trimEnd();
      if (/^\/[\w\-]/.test(line.trim())) {
        // New section header — normalise to lowercase trimmed
        currentSection = line.trim().toLowerCase();
        if (!sections[currentSection]) sections[currentSection] = [];
      } else if (currentSection && /^\s*(add|set)\s/.test(line)) {
        sections[currentSection].push(line.trim());
      }
    }
    return sections;
  }

  // ── Device info ─────────────────────────────────────────────────────────────
  function parseDeviceInfo(text) {
    const hostnameM = text.match(/^\/system identity\s*[\r\n]+set name=([\w\-\.]+)/im)
                    || text.match(/set name=([\w\-\.]+)/i);
    const hostname  = hostnameM ? hostnameM[1] : '-';
    // RouterOS version from comment header: "# RouterOS 7.12.1"
    const verM      = text.match(/#\s*RouterOS\s+([\d\.]+)/i)
                    || text.match(/#\s*software id\s*=\s*([\w\-]+)/i);
    const firmware  = verM ? `RouterOS ${verM[1]}` : '-';
    const modelM    = text.match(/#\s*model\s*=\s*(.+)/i);
    const model     = modelM ? modelM[1].trim() : '-';
    const serialM   = text.match(/#\s*serial number\s*=\s*([\w\-]+)/i);
    const serial    = serialM ? serialM[1] : '-';
    return { vendor: 'MikroTik', hostname, firmware, model, serial, vdom: [] };
  }

  // ── Interfaces ──────────────────────────────────────────────────────────────
  // MikroTik: interface declarations are in multiple sections;
  // IP addresses are in /ip address with interface=X
  function parseInterfaces(sections) {
    const ifaces = {};

    // Collect all known interfaces from /interface* sections
    for (const [sec, lines] of Object.entries(sections)) {
      if (!sec.startsWith('/interface')) continue;
      const type = sec.replace('/interface', '').trim() || 'physical';
      lines.forEach(line => {
        const p = parseLine(line);
        const name = p['name'] || p['interface'] || '';
        if (!name) return;
        ifaces[name] = ifaces[name] || {
          name, ip: '-', mask: '-', secondaryIps: [], type: type || 'physical',
          vlanId: p['vlan-id'] || '-',
          alias: p['name'] || '',
          desc:  p['comment'] || '',
          status: p['disabled'] === 'yes' ? 'down' : 'up',
          mtu: p['mtu'] || '-', speed: '-', mode: 'static',
          vdom: '-', role: 'LAN', allowaccess: '-',
        };
        if (type === 'vlan') {
          ifaces[name].vlanId = p['vlan-id'] || '-';
          ifaces[name].type = 'vlan';
        }
        if (type === 'bridge') ifaces[name].type = 'bridge';
        if (type === 'eoip' || type === 'gre') ifaces[name].type = 'tunnel';
        if (type === 'pppoe-client' || type === 'lte') ifaces[name].type = 'pppoe';
      });
    }

    // Assign IPs from /ip address
    (sections['/ip address'] || []).forEach(line => {
      const p = parseLine(line);
      const iface = p['interface'] || '';
      const addr  = p['address'] || '';  // CIDR: 192.168.1.1/24
      if (!iface || !addr) return;

      // Ensure interface exists
      ifaces[iface] = ifaces[iface] || {
        name: iface, ip: '-', mask: '-', secondaryIps: [], type: 'physical',
        vlanId: '-', alias: '', desc: p['comment']||'',
        status: 'up', mtu: '-', speed: '-', mode: 'static',
        vdom: '-', role: 'LAN', allowaccess: '-',
      };

      const [ip, prefix] = addr.split('/');
      const prefixN = parseInt(prefix) || 24;
      // Convert prefix to mask
      const maskN = prefixN === 0 ? 0 : (0xFFFFFFFF << (32 - prefixN)) >>> 0;
      const mask = [(maskN>>>24)&0xFF,(maskN>>>16)&0xFF,(maskN>>>8)&0xFF,maskN&0xFF].join('.');

      // 資料遺失 bug 修復（非新功能）：原本對同一介面的第二筆 `/ip address add` 直接覆寫，
      // 靜默遺失第一筆資料——RouterOS 官方文件確認同一介面可綁定多筆位址（`/ip address
      // add address=X interface=Y` 重複執行即附加，無 secondary 關鍵字）。改為第一筆寫入
      // ip/mask，第二筆以後（2026-08-17 從「僅保留第一筆」擴大為完整收集）皆推進
      // secondaryIps 陣列
      if (ifaces[iface].ip === '-') {
        ifaces[iface].ip   = ip;
        ifaces[iface].mask = mask;
      } else {
        ifaces[iface].secondaryIps.push({ ip, mask });
      }
      if (p['comment']) ifaces[iface].desc = p['comment'];
    });

    // Guess roles from interface name and IP
    Object.values(ifaces).forEach(i => {
      const n = i.name.toLowerCase();
      if (/wan|pppoe|lte|4g|5g|dialer|sfp-sfpplus|ether1$/.test(n)) i.role = 'WAN';
      else if (/dmz|srv|server/.test(n)) i.role = 'DMZ';
      else if (/mgmt|manage|oob/.test(n)) i.role = 'MGMT';
      else if (/vpn|ipsec|l2tp|pptp|ovpn/.test(n)) i.role = 'VPN';
      else if (/vlan10[05]|vlan20[05]|management/.test(n)) i.role = 'MGMT';
      else if (/guest|wifi-guest/.test(n)) i.role = 'DMZ';

      // Classify WAN by typical IP ranges
      if (i.ip !== '-') {
        const firstOctet = parseInt(i.ip.split('.')[0]);
        const isPublic = !(
          (firstOctet === 10) ||
          (firstOctet === 172 && parseInt(i.ip.split('.')[1]) >= 16 && parseInt(i.ip.split('.')[1]) <= 31) ||
          (firstOctet === 192 && i.ip.split('.')[1] === '168')
        );
        if (isPublic && i.role === 'LAN') i.role = 'WAN';
      }
    });

    return Object.values(ifaces);
  }

  // ── Address lists (address objects) ─────────────────────────────────────────
  function parseAddressObjects(sections) {
    const lists = {};
    (sections['/ip firewall address-list'] || []).forEach(line => {
      const p = parseLine(line);
      const list = p['list'] || 'unnamed';
      const addr = p['address'] || '-';
      if (!lists[list]) lists[list] = { name: list, members: [], comment: '' };
      lists[list].members.push(addr);
      if (p['comment'] && !lists[list].comment) lists[list].comment = p['comment'];
    });

    const out = [];
    Object.values(lists).forEach(l => {
      // If single member: create address entry; else create group
      if (l.members.length === 1) {
        const addr = l.members[0];
        const type = addr.includes('/') ? 'ipmask'
                   : addr.includes('-') ? 'iprange'
                   : addr.match(/[a-zA-Z]/) ? 'fqdn' : 'ipmask';
        const [startIp, endIp] = addr.includes('-') ? addr.split('-') : ['-','-'];
        out.push({
          category: 'address', name: l.name, type,
          subnet: type === 'ipmask' ? addr : '-',
          fqdn: type === 'fqdn' ? addr : '-',
          startIp, endIp, iface: '-',
          members: '-', comment: l.comment,
        });
      } else {
        // multiple entries = group
        l.members.forEach((addr, idx) => {
          const type = addr.includes('/') ? 'ipmask'
                     : addr.includes('-') ? 'iprange'
                     : addr.match(/[a-zA-Z]/) ? 'fqdn' : 'ipmask';
          out.push({
            category: 'address', name: `${l.name}_${idx+1}`,
            type, subnet: type==='ipmask'?addr:'-',
            fqdn: type==='fqdn'?addr:'-',
            startIp: '-', endIp: '-', iface: '-',
            members: '-', comment: idx===0 ? l.comment : '',
          });
        });
        out.push({
          category: 'address-group', name: l.name, type: 'group',
          subnet: '-', fqdn: '-', startIp: '-', endIp: '-', iface: '-',
          members: l.members.join(', '), comment: l.comment,
        });
      }
    });
    return out;
  }

  // 規則的 src/dst-address-list 引用的是「原始清單名稱」，但上面 parseAddressObjects() 為了
  // 讓 Address Objects 表格顯示每個成員，會把多筆成員的清單展開成 `${l.name}_${idx+1}` 這種
  // 合成名稱——原始名稱反而不在展開後的物件清單裡，無法直接用 buildAddrTypeMap() 反查。故另
  // 寫這支獨立小函式，直接依「未展開前」的原始清單名稱分類 v4/v6/mixed，只供 _splitAddr 用，
  // 不影響 Address Objects 表格既有的展開顯示邏輯。同時這裡把 `/ipv6 firewall address-list`
  // 一併讀入——parseAddressObjects() 目前只讀 `/ip firewall address-list`，IPv6 清單完全沒被
  // 讀取，是比其他廠牌更深一層的既有缺口，但只在此處補上型別判斷用途，物件瀏覽表格本身沿用
  // 現狀不擴大處理
  function buildMikrotikAddrTypeMap(sections) {
    const listTypes = {};
    const scan = (sectionKey, fam) => {
      (sections[sectionKey] || []).forEach(line => {
        const p = parseLine(line);
        const list = p['list'] || 'unnamed';
        if (!p['address']) return;
        if (!listTypes[list]) listTypes[list] = new Set();
        listTypes[list].add(fam);
      });
    };
    scan('/ip firewall address-list', 'v4');
    scan('/ipv6 firewall address-list', 'v6');
    const map = new Map();
    Object.entries(listTypes).forEach(([name, fams]) => {
      map.set(name, fams.size > 1 ? 'mixed' : fams.values().next().value);
    });
    return map;
  }

  // ── Service objects ─────────────────────────────────────────────────────────
  function parseServiceObjects(sections) {
    // MikroTik doesn't have named service objects like FortiGate
    // We synthesise them from common port/protocol patterns found in filter rules
    const svcs = {};
    const knownPorts = {
      '20-21':'FTP','22':'SSH','23':'Telnet','25':'SMTP','53':'DNS',
      '80':'HTTP','110':'POP3','143':'IMAP','443':'HTTPS','465':'SMTPS',
      '587':'SMTP-Submit','993':'IMAPS','995':'POP3S','3389':'RDP',
      '8080':'HTTP-Alt','8443':'HTTPS-Alt','3306':'MySQL','5432':'PostgreSQL',
      '1433':'MSSQL','27017':'MongoDB',
    };
    (sections['/ip firewall filter'] || []).concat(sections['/ip firewall nat'] || []).forEach(line => {
      const p = parseLine(line);
      const proto = (p['protocol'] || '').toLowerCase();
      const dport = p['dst-port'] || '';
      const sport = p['src-port'] || '';
      if (!dport && !sport) return;
      const key = `${proto}:${dport||sport}`;
      if (svcs[key]) return;
      const port = dport || sport;
      const name = knownPorts[port] || `${proto.toUpperCase()}_${port.replace(',','-')}`;
      svcs[key] = {
        category: 'service', name,
        proto: proto === 'udp' ? 'UDP' : proto === 'tcp' ? 'TCP' : proto.toUpperCase(),
        tcpPorts: proto === 'tcp' ? port : '-',
        udpPorts: proto === 'udp' ? port : '-',
        icmpType: '-', members: '-', comment: '',
      };
    });
    return Object.values(svcs);
  }

  // ── Firewall filter rules → policies ────────────────────────────────────────
  // Chain mapping: input/output = firewall self; forward = transit traffic
  // We map to srcIntf/dstIntf using chain name as context
  // srcAddr/dstAddr 的清單引用是 `@listname` 前綴格式（與其他廠牌直接用物件名稱不同），故不
  // 沿用共用 _splitAddr()，改用 addrTypeMap（buildMikrotikAddrTypeMap() 產出，key 是不含 @
  // 的原始清單名稱）逐一 token 分類，`@` 前綴本身在輸出的 v4/v6 欄位中原樣保留
  function _splitAddrMikrotik(addrStr, addrTypeMap) {
    const addrs = (addrStr || '').split(/\s*,\s*/).filter(a => a.trim());
    const v4 = [], v6 = [];
    addrs.forEach(a => {
      if (a.includes(':')) { v6.push(a); return; }
      const key = a.startsWith('@') ? a.slice(1) : a;
      const t = addrTypeMap && addrTypeMap.get(key);
      if (t === 'v6') v6.push(a);
      else if (t === 'mixed') { v4.push(a); v6.push(a); }
      else v4.push(a);
    });
    return { v4: v4.join(', ') || '-', v6: v6.join(', ') || '-' };
  }
  function parsePolicies(sections, addrTypeMap) {
    const rules = [];
    let seq = 1;

    // Build interface-to-zone map for richer srcIntf/dstIntf
    const chainZone = {
      'input':   { src: 'any', dst: 'local' },
      'output':  { src: 'local', dst: 'any' },
      'forward': { src: 'any',   dst: 'any' },
    };

    (sections['/ip firewall filter'] || []).forEach(line => {
      const p = parseLine(line);
      const chain  = p['chain']  || 'forward';
      const action = p['action'] || 'drop';

      // Map action to accept/deny
      const normAction = (action === 'accept' || action === 'passthrough') ? 'accept' : 'deny';

      // Build source/destination strings
      const srcAddr = [
        p['src-address']     ? p['src-address']      : '',
        p['src-address-list']? `@${p['src-address-list']}` : '',
      ].filter(Boolean).join(', ') || 'any';

      const dstAddr = [
        p['dst-address']     ? p['dst-address']      : '',
        p['dst-address-list']? `@${p['dst-address-list']}` : '',
      ].filter(Boolean).join(', ') || 'any';

      // IPv4/IPv6 separation
      const srcAddrSplit = _splitAddrMikrotik(srcAddr, addrTypeMap);
      const dstAddrSplit = _splitAddrMikrotik(dstAddr, addrTypeMap);

      // Interface fields
      const srcIntf = p['in-interface']  || p['in-interface-list']  || chain;
      const dstIntf = p['out-interface'] || p['out-interface-list'] || chain;

      // Service
      const proto   = p['protocol']  || '';
      const dport   = p['dst-port']  || '';
      const sport   = p['src-port']  || '';
      const connState = p['connection-state'] || '';
      let service = 'any';
      if (proto && dport) service = `${proto}/${dport}`;
      else if (proto)     service = proto;
      else if (connState) service = `state:${connState}`;

      // UTM / extra features
      const log = p['log'] === 'yes' || p['log-prefix'] ? 'all' : 'disable';

      rules.push({
        id: seq++, name: p['comment'] || `Rule-${seq-1}`,
        srcIntf, dstIntf, srcAddr, dstAddr,
        srcAddr4: srcAddrSplit.v4, srcAddr6: srcAddrSplit.v6,
        dstAddr4: dstAddrSplit.v4, dstAddr6: dstAddrSplit.v6,
        service, schedule: 'always',
        action: normAction,
        nat: 'disable', ippool: 'disable', poolname: '-',
        logtraffic: log,
        utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
        status: p['disabled'] === 'yes' ? 'disable' : 'enable',
        users: '-', groups: '-',
        comments: p['comment'] || '',
        // MikroTik-specific extras
        _chain: chain, _connState: connState,
        _proto: proto, _dport: dport,
        _vdom: '',
      });
    });
    return rules;
  }

  // ── Routes ──────────────────────────────────────────────────────────────────
  function parseRoutes(sections) {
    const routes = [];
    let seq = 1;
    (sections['/ip route'] || []).forEach(line => {
      const p = parseLine(line);
      const dst     = p['dst-address'] || '0.0.0.0/0';
      const gw      = p['gateway']     || '-';
      const dist    = p['distance']    || '1';
      const comment = p['comment']     || '';
      const status  = p['disabled'] === 'yes' ? 'disable' : 'enable';
      const isBlackhole = !p['gateway'] || p['type'] === 'blackhole' || line.includes('blackhole');
      const iface   = p['routing-table'] || (gw.match(/^[\d\.]+$/) ? '-' : gw);
      const type    = dst === '0.0.0.0/0' || dst === '0.0.0.0 0.0.0.0' ? 'default' : 'static';
      routes.push({
        type, id: String(seq++),
        dst, gateway: isBlackhole ? 'blackhole' : gw,
        device: p['interface'] || '-',
        distance: dist, priority: dist,
        blackhole: isBlackhole ? 'enable' : 'disable',
        vrf: p['routing-table'] || 'main',
        status, comment,
        protocol_detail: '-', _vdom: '',
      });
    });
    return routes;
  }

  // ── HA/VRRP ─────────────────────────────────────────────────────────────────
  // 已查證 MikroTik RouterOS 官方文件（help.mikrotik.com）真實語法：
  // /interface vrrp 底下 add 一行含 name/interface/vrid/priority 等參數；虛擬 IP 另外在
  // /ip address 用 add address=X interface=<vrrp name> 反向關聯回 vrrp 邏輯介面。
  // 比照既有 CiscoASA parseHa() 的「文字逐行解析＋找不到填 '-'」慣例組成共用 ha 形狀。
  function parseMikrotikHa(sections) {
    const result = { enabled: false, mode: '-', groupId: '-', priority: '-', peerIp: '-', syncInterface: '-', vip: '-' };
    const vrrpLines = sections['/interface vrrp'] || [];
    if (!vrrpLines.length) return result;
    const first = parseLine(vrrpLines[0]);
    result.enabled = true;
    result.mode = 'VRRP';
    result.groupId = first['vrid'] || '-';
    result.priority = first['priority'] || '-';
    result.syncInterface = first['interface'] || '-';
    const vrrpName = first['name'] || '';
    const addrLines = sections['/ip address'] || [];
    for (const line of addrLines) {
      const p = parseLine(line);
      if (p['interface'] === vrrpName) { result.vip = p['address'] || '-'; break; }
    }
    return result;
  }

  // ── NAT ─────────────────────────────────────────────────────────────────────
  function parseNAT(sections) {
    const nat = [];
    (sections['/ip firewall nat'] || []).forEach(line => {
      const p      = parseLine(line);
      const chain  = p['chain']  || 'srcnat';
      const action = p['action'] || '-';
      const name   = p['comment'] || `NAT-${nat.length+1}`;

      // Classify type
      let type = 'ippool'; // SNAT default
      let extIp = '-', mapIp = '-', extPort = '-', mapPort = '-';

      if (chain === 'dstnat') {
        type   = 'vip';
        extIp  = p['dst-address'] || p['in-interface'] || '-';
        mapIp  = p['to-addresses'] || '-';
        extPort= p['dst-port'] || '-';
        mapPort= p['to-ports'] || '-';
      } else {
        // srcnat
        extIp  = p['src-address'] || p['src-address-list'] || 'any';
        mapIp  = action === 'masquerade' ? 'masquerade' : (p['to-addresses'] || '-');
        extPort= p['src-port'] || '-';
        mapPort= p['to-ports'] || '-';
      }

      nat.push({
        type, name, vipType: type === 'vip' ? 'static' : 'overload',
        poolType: action,
        extIp, mapIp,
        extIntf: p['in-interface'] || p['out-interface'] || '-',
        srcIntf: p['in-interface'] || '-',
        startIp: '-', endIp: '-',
        portFwd: mapPort !== '-' ? 'enable' : 'disable',
        extPort, mapPort,
        proto: p['protocol'] || '-',
        status: p['disabled'] === 'yes' ? 'disable' : 'enable',
        comment: p['comment'] || '',
      });
    });
    return nat;
  }

  // ── VPN (IPsec) ─────────────────────────────────────────────────────────────
  function parseVPN(sections) {
    const vpns = [];
    const peers = {};

    // Build proposalMap from /ip ipsec proposal
    const proposalMap = {};
    (sections['/ip ipsec proposal'] || []).forEach(line => {
      const p = parseLine(line);
      const pname = p['name'] || 'default';
      proposalMap[pname] = {
        enc:      p['enc-algorithms'] || p['encryption-algorithm'] || '-',
        auth:     p['auth-algorithms'] || p['authentication-algorithm'] || '-',
        lifetime: p['lifetime'] || '30m',
        pfsGroup: p['pfs-group'] || 'none',
      };
    });

    (sections['/ip ipsec peer'] || []).forEach(line => {
      const p = parseLine(line);
      const name = p['name'] || p['address'] || `peer-${Object.keys(peers).length+1}`;
      const natRaw = p['nat-traversal'] || '';
      const dpdRaw = p['dpd-interval'] || p['dpd-maximum-failures'] || '';
      peers[name] = {
        name, remote: p['address'] || '-',
        iface: p['interface'] || '-',
        ikeVer: p['exchange-mode'] === 'ike2' ? '2' : '1',
        authMethod: p['auth-method'] === 'rsa-signature' ? 'certificate' : 'psk',
        dhgrp: p['dh-group'] || p['dh-groups'] || '-',
        natTraversal: /yes|true|enable/i.test(natRaw) ? 'enable' : natRaw ? 'disable' : '-',
        dpd: dpdRaw ? 'enable' : '-',
        comment: p['comment'] || '',
        status: p['disabled'] === 'yes' ? 'disable' : 'enable',
      };
    });

    (sections['/ip ipsec policy'] || []).forEach(line => {
      const p = parseLine(line);
      const peerName = p['peer'] || p['tunnel'] || '';
      const peer = peers[peerName] || { name: peerName, remote: '-', iface: '-', ikeVer: '2', authMethod: 'psk', dhgrp: '-', natTraversal: '-', dpd: '-', comment: '', status: 'enable' };
      const propName = p['proposal'] || 'default';
      const prop = proposalMap[propName] || { enc: propName, auth: '-', lifetime: '30m', pfsGroup: 'none' };
      const localSub  = p['src-address'] || '-';
      const remoteSub = p['dst-address'] || '-';
      const phase2 = [{
        name: `P2-${vpns.length+1}`, phase1: peer.name,
        proposal: `${prop.enc}-${prop.auth}`,
        pfs: prop.pfsGroup !== 'none' ? 'enable' : 'disable',
        dhgrp: prop.pfsGroup !== 'none' ? prop.pfsGroup : peer.dhgrp,
        lifetime: prop.lifetime, replay: 'enable',
        localSub, remoteSub, autoNeg: '-', comment: '-',
      }];
      vpns.push({
        name: p['comment'] || peer.name || `ipsec-${vpns.length+1}`,
        type: 'ipsec', mode: 'main',
        remotegw: peer.remote, remote: peer.remote,
        iface: peer.iface, ikeVer: peer.ikeVer,
        localnet: localSub, remotenet: remoteSub,
        localId: '-', peerId: peer.remote, cert: '-',
        authMethod: peer.authMethod,
        proposal: `${prop.enc}-${prop.auth}`,
        dhgrp: peer.dhgrp, lifetime: prop.lifetime,
        natTraversal: peer.natTraversal, dpd: peer.dpd,
        status: p['disabled'] === 'yes' ? 'disable' : peer.status,
        phase2, comment: p['comment'] || peer.comment,
      });
    });

    // If no policies but peers exist, create one entry per peer
    if (vpns.length === 0) {
      Object.values(peers).forEach(peer => {
        const prop = proposalMap['default'] || { enc: '-', auth: '-', lifetime: '30m', pfsGroup: 'none' };
        vpns.push({
          name: peer.name, type: 'ipsec', mode: 'main',
          remotegw: peer.remote, remote: peer.remote,
          iface: peer.iface, ikeVer: peer.ikeVer,
          localnet: '-', remotenet: '-',
          localId: '-', peerId: peer.remote, cert: '-',
          authMethod: peer.authMethod, proposal: `${prop.enc}-${prop.auth}`,
          dhgrp: peer.dhgrp, lifetime: prop.lifetime,
          natTraversal: peer.natTraversal, dpd: peer.dpd,
          status: peer.status, phase2: [], comment: peer.comment,
        });
      });
    }
    return vpns;
  }

  // ── Users ───────────────────────────────────────────────────────────────────
  function parseUsers(sections) {
    const out = [];
    (sections['/user'] || []).forEach(line => {
      const p = parseLine(line);
      const name  = p['name'] || '-';
      if (name === '-') return;
      const group = (p['group'] || 'read').toLowerCase();
      const type  = (group === 'full' || group === 'write') ? 'admin' : 'local';
      const level = group === 'full' ? 'super-admin'
                  : group === 'write' ? 'admin'
                  : 'read-only';
      out.push({
        type, name,
        status: p['disabled'] === 'yes' ? 'disable' : 'enable',
        accessLevel: level,
        authType: 'local',
        email: p['email'] || '-',
        twoFactor: '-',
        roles: [group], permissions: {},
        members: '-', comment: p['comment'] || '',
      });
    });
    // User groups (RouterOS groups: full, write, read, policy)
    const groups = new Set();
    out.forEach(u => u.roles.forEach(r => groups.add(r)));
    groups.forEach(g => {
      const members = out.filter(u => u.roles.includes(g)).map(u => u.name).join(', ');
      out.push({
        type: 'group', name: g,
        status: 'enable', accessLevel: g,
        authType: 'local', email: '-',
        twoFactor: '-', roles: [], permissions: {},
        members: members || '-', comment: '',
      });
    });
    return out;
  }

  // ── Schedules ───────────────────────────────────────────────────────────────
  function parseSchedules(sections) {
    const out = [];
    (sections['/system scheduler'] || []).forEach(line => {
      const p = parseLine(line);
      const name = p['name'] || `sched-${out.length+1}`;
      out.push({
        type: p['interval'] ? 'recurring' : 'onetime',
        name,
        start: p['start-time'] || p['start-date'] || '-',
        end:   p['interval']   || '-',
        day:   p['start-date'] || '-',
        color: '0',
      });
    });
    return out;
  }

  // ── Vendor detection ────────────────────────────────────────────────────────
  // Returns true if text looks like a MikroTik /export file

  // ── DHCP Server & Relay ──────────────────────────────────────────────────
  function parseDhcp(sections) {
    const servers=[], relays=[];
    const pools={};
    (sections['/ip pool']||[]).forEach(line=>{const p=parseLine(line);if(p['name']&&p['ranges'])pools[p['name']]=p['ranges'];});
    const nets={};
    (sections['/ip dhcp-server network']||[]).forEach(line=>{
      const p=parseLine(line);
      if(p['address'])nets[p['address']]={gateway:p['gateway']||'-',domain:p['domain']||'-',dns:p['dns-server']||'-'};
    });
    (sections['/ip dhcp-server']||[]).forEach(line=>{
      const p=parseLine(line);
      const name=p['name']||`dhcp-${servers.length+1}`;
      const pool=p['address-pool']||'-';
      const ranges=(pools[pool]||'').split('-');
      const netInfo=Object.values(nets)[0]||{gateway:'-',domain:'-',dns:'-'};
      const dnsArr=netInfo.dns.split(',');
      servers.push({name,iface:p['interface']||'-',
        startIp:ranges[0]?.trim()||'-',endIp:ranges[1]?.trim()||'-',
        gateway:netInfo.gateway,mask:'-',dns1:dnsArr[0]?.trim()||'-',dns2:dnsArr[1]?.trim()||'-',
        domain:netInfo.domain,lease:p['lease-time']||'00:10:00',
        status:p['disabled']==='yes'?'disable':'enable',comment:p['comment']||''});
    });
    (sections['/ip dhcp-relay']||[]).forEach(line=>{
      const p=parseLine(line);
      relays.push({name:p['name']||'-',iface:p['interface']||'-',
        serverIp:p['dhcp-server']||'-',status:p['disabled']==='yes'?'disable':'enable',comment:p['comment']||''});
    });
    return {servers,relays};
  }
  // ── DNS ─────────────────────────────────────────────────────────────────
  function parseDns(sections) {
    const result={servers:[],secondaries:[],domain:'-',proxy:false,proxyRules:[],dnsOverTls:false,cacheSize:'-',static:[]};
    (sections['/ip dns']||[]).forEach(line=>{
      const p=parseLine(line);
      if(p['servers']){const list=p['servers'].split(',').map(s=>s.trim());result.servers=list.slice(0,1);result.secondaries=list.slice(1);}
      if(p['allow-remote-requests']==='yes')result.proxy=true;
      if(p['cache-size'])result.cacheSize=p['cache-size'];
    });
    (sections['/ip dns static']||[]).forEach(line=>{
      const p=parseLine(line);
      if(p['name']&&(p['address']||p['cname']))
        result.static.push({name:p['name'],type:p['type']||(p['cname']?'CNAME':'A'),ip:p['address']||p['cname']||'-',zone:p['name'].split('.').slice(1).join('.')||'.'});
    });
    (sections['/ip dns forwarder']||[]).forEach(line=>{
      const p=parseLine(line);if(p['domain']&&p['servers'])result.proxyRules.push({domain:p['domain'],target:p['servers']});
    });
    return result;
  }


  // ── SNMP ────────────────────────────────────────────────────────────────────
  function parseSnmp(sections) {
    const result={enabled:false,agent:{name:'-',description:'-',location:'-',contact:'-',version:[]},communities:[],v3users:[],trapServers:[]};
    (sections['/snmp']||[]).forEach(line=>{
      const p=parseLine(line);
      if(p['enabled']==='yes'||p['enabled']===undefined) result.enabled=true;
      if(p['contact'])  result.agent.contact=p['contact'];
      if(p['location']) result.agent.location=p['location'];
      if(p['name'])     result.agent.name=p['name'];
      const ver=p['trap-version']||'2'; result.agent.version=ver==='1'?['v1']:ver==='3'?['v2c','v3']:['v2c'];
    });
    (sections['/snmp community']||[]).forEach(line=>{
      const p=parseLine(line);
      const name=p['name']||'public';
      const sec=p['security']||'none';
      const perm=sec==='private'||sec==='write'?'rw':'ro';
      const hosts=(p['addresses']||'').split(',').map(s=>s.trim()).filter(Boolean);
      if(sec==='private'||p['authentication-password']){
        result.v3users.push({name,authProto:p['authentication-protocol']||'sha1',privProto:p['encryption-protocol']||'aes',secLevel:'auth-priv',notifyHost:'-',status:'enable'});
        if(!result.agent.version.includes('v3')) result.agent.version.push('v3');
      } else {
        result.communities.push({name,permission:perm,allowedHosts:hosts,events:'-',status:'enable'});
      }
    });
    // Trap targets from /snmp trap or set trap-target
    (sections['/snmp trap']||sections['/snmp']||[]).forEach(line=>{
      const p=parseLine(line);
      const target=p['trap-target']||p['trap-receiver'];
      if(target) target.split(',').forEach(ip=>result.trapServers.push({ip:ip.trim(),port:'162',community:result.communities[0]?.name||'public',version:'v2c'}));
    });
    return result;
  }

  // ── Log Servers ──────────────────────────────────────────────────────────────
  function parseLogServers(sections) {
    const result={syslog:[],fortianalyzer:[],netflow:[],logForward:[]};
    (sections['/system logging action']||[]).forEach(line=>{
      const p=parseLine(line);
      if((p['target']||'')!=='remote') return;
      const srv=p['remote']||'-';
      if(srv==='-') return;
      result.syslog.push({name:p['name']||`Syslog-${result.syslog.length+1}`,server:srv,port:p['remote-port']||'514',facility:p['syslog-facility']||'local7',format:p['bsd-syslog']==='yes'?'BSD':'default',protocol:'UDP',level:p['syslog-severity']||'info',status:'enable'});
    });
    return result;
  }

  function detect(text) {
    return /^#\s*RouterOS\b/im.test(text)
        || /^\/ip\s+firewall\s+filter/im.test(text)
        || /^\/interface\s+(bridge|vlan|ether)\b/im.test(text)
        || (text.includes('/ip address') && text.includes('/ip route') && text.includes('add '));
  }

  // ── LTE（行動網路）────────────────────────────────────────────────────────────
  function parseMikrotikLte(sections) {
    const lteInterfaces = (sections['/interface lte'] || []).map(l => {
      const p = parseLine(l);
      return {
        name:        p['name'] || '-',
        apnProfile:  p['apn'] || '-',
        allowRoaming:p['allow-roaming'] || 'no',
        disabled:    p['disabled'] || 'no',
        comment:     p['comment'] || '-',
      };
    });
    const apnProfiles = (sections['/interface lte apn'] || []).map(l => {
      const p = parseLine(l);
      const pw = p['password'];
      return {
        name:     p['name'] || '-',
        apn:      p['apn'] || '-',
        authType: p['authentication'] || 'none',
        username: p['user'] || '-',
        passwd:   pw && pw !== '' ? 'set' : '-',
        ipType:   p['ip-type'] || 'ipv4',
        distance: p['default-route-distance'] || '2',
      };
    });
    return { lteInterfaces, apnProfiles };
  }

  // ── 無線 AP（本機 + CAPsMAN）──────────────────────────────────────────────────
  function parseMikrotikWireless(sections) {
    // Security profiles
    const secProfiles = {};
    (sections['/interface wireless security-profiles'] || []).forEach(l => {
      const p = parseLine(l);
      const name = p['name'] || 'default';
      secProfiles[name] = {
        name,
        authTypes: p['authentication-types'] || 'none',
        mode:      p['mode'] || 'none',
        hasKey:    !!(p['wpa2-pre-shared-key'] || p['wpa-pre-shared-key']),
      };
    });
    // Wireless interfaces
    const interfaces = (sections['/interface wireless'] || []).map(l => {
      const p = parseLine(l);
      const profName = p['security-profile'] || 'default';
      const sec = secProfiles[profName] || {};
      return {
        name:        p['name'] || '-',
        ssid:        p['ssid'] || '-',
        band:        p['band'] || '-',
        mode:        p['mode'] || '-',
        frequency:   p['frequency'] || 'auto',
        channelWidth:p['channel-width'] || '-',
        country:     p['country'] || '-',
        secProfile:  profName,
        authTypes:   sec.authTypes || '-',
        hasKey:      sec.hasKey || false,
        disabled:    p['disabled'] || 'no',
        comment:     p['comment'] || '-',
      };
    });
    // CAPsMAN
    const capsmanEnabled = (sections['/caps-man manager'] || []).some(l => /enabled=yes/i.test(l));
    const capsmanConfigs = (sections['/caps-man configuration'] || []).map(l => {
      const p = parseLine(l);
      return {
        name:     p['name'] || '-',
        ssid:     p['ssid'] || p['channel.ssid'] || '-',
        band:     p['channel.band'] || '-',
        authTypes:p['security.authentication-types'] || '-',
        hasKey:   !!(p['security.passphrase'] || p['security.wpa2-pre-shared-key']),
      };
    });
    return { interfaces, secProfileList: Object.values(secProfiles), capsmanEnabled, capsmanConfigs };
  }

  // ── Main parse ───────────────────────────────────────────────────────────────
  function parse(text) {
    const sections = splitSections(text);
    return {
      vendor:     'MikroTik',
      deviceInfo: parseDeviceInfo(text),
      interfaces: parseInterfaces(sections),
      policies:   parsePolicies(sections, buildMikrotikAddrTypeMap(sections)),
      routes:     parseRoutes(sections),
      ha:         parseMikrotikHa(sections),
      nat:        parseNAT(sections),
      vpn:        parseVPN(sections),
      addresses:  parseAddressObjects(sections),
      services:   parseServiceObjects(sections),
      users:      parseUsers(sections),
      schedules:  parseSchedules(sections),
      sdwan:      parseSdwan(sections),
      dhcp:       parseDhcp(sections),
      dns:        parseDns(sections),
      snmp:       parseSnmp(sections),
      logservers: parseLogServers(sections),
      wwan:       parseMikrotikLte(sections),
      wlan:       parseMikrotikWireless(sections),
    };
  }


  // ── MikroTik Multi-WAN: distance-based failover + ECMP + Netwatch ──────────
  function parseSdwan(sections) {
    const result = { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] };

    // Detect multi-WAN: multiple default routes (dst=0.0.0.0/0) with check-gateway=ping
    const routes = sections['/ip route'] || [];
    const defaultRoutes = routes.filter(l => {
      const p = parseLine(l);
      return p['dst-address'] === '0.0.0.0/0' || p['dst-address'] === '0.0.0.0';
    });
    if (defaultRoutes.length < 1) return result;

    // One default = possible failover; two+ = multi-WAN
    const hasMulti = defaultRoutes.length > 1;
    const hasCheckGw = defaultRoutes.some(l => /check-gateway=ping/i.test(l));
    if (!hasMulti && !hasCheckGw) return result;
    result.enabled = true;

    // Determine LB mode from routing-options
    const routingRules = sections['/routing rule'] || sections['/ip route rule'] || [];
    const hasECMP = (sections['/routing settings'] || []).some(l => /ecmp/i.test(l));
    const hasLB   = (sections['/ip route'] || []).some(l => /ecmp|load-balance/i.test(l));
    result.lbMode = hasECMP || hasLB ? 'load-balance' : 'priority';

    // Routing tables = zones
    const tables = new Set(defaultRoutes.map(l => { const p = parseLine(l); return p['routing-table'] || p['table'] || 'main'; }));
    tables.forEach(t => result.zones.push({ name: t }));

    // Build members from default routes
    defaultRoutes.forEach((line, idx) => {
      const p = parseLine(line);
      const gw       = p['gateway'] || '-';
      const dist     = parseInt(p['distance'] || '1');
      const comment  = p['comment'] || `WAN${idx+1}`;
      const table    = p['routing-table'] || 'main';
      const iface    = p['interface'] || '-';
      // Try to find the interface associated with this gateway from /ip address
      let matchIface = iface;
      if (matchIface === '-') {
        (sections['/ip address'] || []).forEach(al => {
          const ap = parseLine(al);
          if (ap['address'] && gw.startsWith(ap['address'].split('/')[0].split('.').slice(0,3).join('.'))) {
            matchIface = ap['interface'] || matchIface;
          }
        });
      }
      result.members.push({
        id: String(idx+1),
        iface: matchIface,
        zone: table,
        gateway: gw, gateway6: '-',
        priority: dist, weight: 1, cost: dist,
        spillover: 0, volumeRatio: 1,
        status: p['disabled'] === 'yes' ? 'disable' : 'enable',
        comment,
      });
    });

    // Netwatch = health checks
    (sections['/tool netwatch'] || []).forEach((line, idx) => {
      const p = parseLine(line);
      const host = p['host'] || '-';
      if (!host || host === '-') return;
      result.healthChecks.push({
        name:         p['comment'] || `Netwatch_${idx+1}`,
        server:       host,
        protocol:     p['type'] || 'ping',
        port:         p['port'] || '-',
        interval:     p['interval'] ? p['interval'].replace('s','000').replace('m','0000') : '10000',
        timeout:      p['timeout']  ? p['timeout'].replace('s','000') : '1000',
        failtime:     '-', recoverytime: '-',
        probePackets: '3', http200Only: 'disable',
        members:      'all',
        slaThresholds: [],
      });
    });

    // Routing rules (PBR) = SD-WAN service rules
    routingRules.forEach((line, idx) => {
      const p = parseLine(line);
      result.services.push({
        id: String(idx+1),
        name: p['comment'] || `Route_Rule_${idx+1}`,
        mode: result.lbMode,
        src: p['src-address'] || p['src-address-list'] || 'all',
        dst: p['dst-address'] || p['dst-address-list'] || 'all',
        srcNegate: 'disable', dstNegate: 'disable', users: '-',
        protocol: '0', startPort: '-', endPort: '-',
        priorityMembers: result.members.map(m=>m.iface).join(', ') || '-',
        priorityZone: p['routing-mark'] || p['table'] || '-',
        preferredUplink: '-', slaCompare: 'order', tie: 'zone',
        slaRefs: [], inputDevice: p['in-interface'] || '-',
        status: p['disabled'] === 'yes' ? 'disable' : 'enable',
        comment: p['comment'] || '',
      });
    });

    // If no explicit rules, synthesise from number of default routes
    if (result.services.length === 0 && result.members.length > 0) {
      result.services.push({
        id:'1', name: result.lbMode === 'load-balance' ? 'ECMP_Default' : 'WAN_Failover_Default',
        mode: result.lbMode,
        src:'all', dst:'all', srcNegate:'disable', dstNegate:'disable', users:'-',
        protocol:'0', startPort:'-', endPort:'-',
        priorityMembers: result.members.map(m=>`${m.iface}(dist:${m.priority})`).join(', '),
        priorityZone:'-', preferredUplink: result.members.sort((a,b)=>a.priority-b.priority)[0]?.iface||'-',
        slaCompare:'order', tie:'zone', slaRefs:[], inputDevice:'-', status:'enable',
        comment:`check-gateway=ping on ${defaultRoutes.length} default routes`,
      });
    }

    return result;
  }

  return { parse, detect };
})();

