// ═══ parser-sonicwall.js ═══
/**
 * SonicWall SonicOS Parser v1.0
 * Supports: .exp XML export（僅 SonicOS <6.2；6.2+ 已停用 XML 匯出，非本解析器支援範圍）
 * Sections: Interfaces, Access Rules, Address Objects/Groups,
 *           Service Objects/Groups, Routes, NAT Policies,
 *           VPN (Site-to-Site), Users/Groups, Schedules
 */
const SonicWallParser = (() => {

  // ── XML helpers ────────────────────────────────────────────────────────────
  function parseXML(text) {
    // Strip BOM and leading whitespace
    const clean = text.replace(/^\uFEFF/, '').trim();
    try {
      return new DOMParser().parseFromString(clean, 'application/xml');
    } catch(e) {
      return new DOMParser().parseFromString(clean, 'text/xml');
    }
  }

  // Get text content of first matching child tag (case-insensitive)
  function gv(el, tag) {
    if (!el) return '';
    // Use childNodes (works in xmldom) instead of children
    const nodes = el.childNodes || [];
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (n.nodeType === 1 && n.tagName && n.tagName.toLowerCase() === tag.toLowerCase()) {
        return (n.textContent || '').trim();
      }
    }
    // Deep search via getElementsByTagName for nested elements
    try {
      const found = el.getElementsByTagName(tag);
      if (found && found.length > 0) return (found[0].textContent || '').trim();
    } catch(e) {}
    return '';
  }

  // Get attribute, case-insensitive
  function ga(el, attr) {
    if (!el || !el.attributes) return '';
    for (let i = 0; i < el.attributes.length; i++) {
      if (el.attributes[i].name.toLowerCase() === attr.toLowerCase())
        return el.attributes[i].value || '';
    }
    return '';
  }

  // Get all direct children with tagName
  function children(el, tag) {
    if (!el) return [];
    const out = [];
    for (let i = 0; i < el.children.length; i++) {
      if (el.children[i].tagName.toLowerCase() === tag.toLowerCase())
        out.push(el.children[i]);
    }
    return out;
  }

  // querySelectorAll with fallback
  // Multi-tag search using getElementsByTagName (compatible with xmldom)
  function qsa(root, sel) {
    const tags = sel.split(',').map(s => s.trim()).filter(Boolean);
    const seen = new WeakSet ? new WeakSet() : new Set();
    const useWeak = typeof WeakSet !== 'undefined';
    const results = [];
    for (const tag of tags) {
      try {
        const els = root.getElementsByTagName(tag);
        for (let j = 0; j < els.length; j++) {
          const el = els[j];
          if (useWeak ? !seen.has(el) : !results.includes(el)) {
            if (useWeak) seen.add(el);
            results.push(el);
          }
        }
      } catch(e) {}
    }
    return results;
  }

  // Normalise boolean strings
  function bool(v) { return /^(true|yes|enable|1)$/i.test(v || ''); }

  // ── Device info ─────────────────────────────────────────────────────────────
  function parseDeviceInfo(doc) {
    // SonicWall EXP: <SonicWALLconfig> or root element has attributes
    const root = doc.documentElement;
    const fw = qsa(doc, 'FirmwareVersion, FwVersion, Version')[0];
    const mn = qsa(doc, 'ModelName, Model, ProductName')[0];
    const sn = qsa(doc, 'SerialNumber, Serial')[0];
    const hn = qsa(doc, 'DeviceName, HostName, Hostname')[0];
    return {
      vendor:   'SonicWall',
      hostname: hn ? hn.textContent.trim() : (ga(root, 'deviceName') || '-'),
      firmware: fw ? fw.textContent.trim() : (ga(root, 'firmwareVersion') || ga(root, 'version') || '-'),
      model:    mn ? mn.textContent.trim() : (ga(root, 'model') || '-'),
      serial:   sn ? sn.textContent.trim() : '-',
      vdom:     [],
    };
  }

  // ── Interfaces ──────────────────────────────────────────────────────────────
  function parseInterfaces(doc) {
    const ifaces = [];
    // 主要標籤：<InterfaceSettings><InterfaceEntry>
    // 另保留 <Interfaces><Interface> 作為未證實對應版本的欄位命名容錯
    // （XML 匯出僅存在於 SonicOS <6.2，並無 7.x 對照樣本可查證此別名的真實來源）
    const selectors = ['InterfaceEntry', 'Interface', 'NetworkInterface'];
    for (const sel of selectors) {
      const els = qsa(doc, sel);
      if (!els.length) continue;
      for (const el of els) {
        const name  = gv(el,'Name') || gv(el,'IfName') || ga(el,'name') || '-';
        const ip    = gv(el,'IPAddress') || gv(el,'IpAddress') || gv(el,'IP') || '-';
        const mask  = gv(el,'SubnetMask') || gv(el,'Netmask') || gv(el,'Mask') || '-';
        const zone  = gv(el,'Zone') || gv(el,'ZoneName') || '-';
        const mode  = gv(el,'IPAssignment') || gv(el,'Mode') || 'static';
        const comment = gv(el,'Comment') || gv(el,'Note') || '';
        const status  = bool(gv(el,'Enabled') || gv(el,'Enable') || 'true') ? 'up' : 'down';
        const vlanId  = gv(el,'VLANID') || gv(el,'VlanId') || '-';
        const speed   = gv(el,'Speed') || '-';
        // Derive role from zone name
        const zl = zone.toLowerCase();
        const role = /wan|internet|ext/i.test(zl) ? 'WAN'
                   : /dmz|server/i.test(zl)       ? 'DMZ'
                   : /vpn/i.test(zl)              ? 'VPN'
                   : /mgmt|manage/i.test(zl)      ? 'MGMT'
                   : 'LAN';
        const type  = vlanId && vlanId !== '-' ? 'vlan'
                    : /ppp|dhcp|l2tp/i.test(mode) ? 'dhcp'
                    : 'physical';
        if (name === '-') continue;
        ifaces.push({ name, ip, mask, type, vlanId, vdom: zone, role, mtu: '-', speed, mode, status, allowaccess: '-', alias: '', desc: comment });
      }
      if (ifaces.length) break;
    }
    return ifaces;
  }

  // ── Address Objects ─────────────────────────────────────────────────────────
  function parseAddressObjects(doc) {
    const out = [];
    // Address Objects
    for (const el of qsa(doc, 'AddressObject, AddressEntry')) {
      const name    = gv(el,'Name') || ga(el,'name') || '-';
      const type    = (gv(el,'Type') || gv(el,'ObjType') || 'host').toLowerCase();
      const ip      = gv(el,'IPAddress') || gv(el,'Host') || gv(el,'Network') || '-';
      const mask    = gv(el,'SubnetMask') || gv(el,'Netmask') || '-';
      const start   = gv(el,'StartIP') || gv(el,'StartIp') || '-';
      const end     = gv(el,'EndIP')   || gv(el,'EndIp')   || '-';
      const fqdn    = gv(el,'FQDN')    || gv(el,'DomainName') || '-';
      const zone    = gv(el,'Zone')    || '-';
      const comment = gv(el,'Comment') || '';
      if (name === '-') continue;
      const ntype = /range/i.test(type) ? 'iprange'
                  : /fqdn|domain/i.test(type) ? 'fqdn'
                  : /network|subnet/i.test(type) ? 'ipmask'
                  : /mac/i.test(type) ? 'mac'
                  : 'ipmask';
      out.push({ category:'address', name, type: ntype, subnet: ip && mask !== '-' ? `${ip}/${mask}` : (ip !== '-' ? ip : '-'), fqdn, startIp: start, endIp: end, iface: zone, members: '-', comment });
    }
    // Address Groups
    for (const el of qsa(doc, 'AddressGroup, AddressGroupEntry')) {
      const name    = gv(el,'Name') || ga(el,'name') || '-';
      const comment = gv(el,'Comment') || '';
      const members = [...qsa(el, 'Member, MemberName')].map(m => m.textContent.trim()).filter(Boolean).join(', ');
      if (name === '-') continue;
      out.push({ category:'address-group', name, type:'group', subnet:'-', fqdn:'-', startIp:'-', endIp:'-', iface:'-', members: members || '-', comment });
    }
    return out;
  }

  // ── Service Objects ─────────────────────────────────────────────────────────
  function parseServiceObjects(doc) {
    const out = [];
    // Service Objects
    for (const el of qsa(doc, 'ServiceObject, ServiceEntry')) {
      const name    = gv(el,'Name') || ga(el,'name') || '-';
      const proto   = (gv(el,'Protocol') || gv(el,'IpType') || 'TCP').toUpperCase();
      const tcp     = gv(el,'Port') || gv(el,'TcpPort') || gv(el,'PortRange') || '-';
      const udp     = gv(el,'UdpPort') || '-';
      const comment = gv(el,'Comment') || '';
      if (name === '-') continue;
      const nproto = /6|tcp/i.test(proto) ? 'TCP'
                   : /17|udp/i.test(proto) ? 'UDP'
                   : /tcp.*udp|both/i.test(proto) ? 'TCP/UDP'
                   : /1|icmp/i.test(proto) ? 'ICMP'
                   : proto;
      out.push({ category:'service', name, proto: nproto, tcpPorts: nproto.includes('TCP') ? tcp : '-', udpPorts: nproto.includes('UDP') ? (udp !== '-' ? udp : tcp) : '-', icmpType: nproto === 'ICMP' ? tcp : '-', members: '-', comment });
    }
    // Service Groups
    for (const el of qsa(doc, 'ServiceGroup, ServiceGroupEntry')) {
      const name    = gv(el,'Name') || ga(el,'name') || '-';
      const comment = gv(el,'Comment') || '';
      const members = [...qsa(el, 'Member, MemberName')].map(m => m.textContent.trim()).filter(Boolean).join(', ');
      if (name === '-') continue;
      out.push({ category:'group', name, proto:'-', tcpPorts:'-', udpPorts:'-', icmpType:'-', members: members || '-', comment });
    }
    return out;
  }

  // ── Access Rules (Policies) ─────────────────────────────────────────────────
  function parsePolicies(doc, addrTypeMap) {
    const out = [];
    let seq = 1;
    // 主要標籤：<AccessRules><Rule>；另保留 <AccessRules><AccessRule> 作為未證實對應版本的欄位命名容錯（同上，7.x 無 XML 對照樣本）
    for (const el of qsa(doc, 'Rule, AccessRule')) {
      // Skip if this is a child of something else (e.g. VPN rule container)
      const parent = el.parentElement;
      if (parent && !/accessrules/i.test(parent.tagName)) continue;

      const enabled = bool(gv(el,'Enabled') || gv(el,'Enable') || 'true');
      const action  = (gv(el,'Action') || 'deny').toLowerCase();
      const name    = gv(el,'Name') || gv(el,'Comment') || `Rule-${seq}`;
      const srcZone = gv(el,'SourceZone') || gv(el,'SrcZone') || gv(el,'FromZone') || 'any';
      const dstZone = gv(el,'DestinationZone') || gv(el,'DstZone') || gv(el,'ToZone') || 'any';
      const srcAddr = gv(el,'Source') || gv(el,'SourceAddress') || gv(el,'SrcAddress') || 'any';
      const dstAddr = gv(el,'Destination') || gv(el,'DestinationAddress') || gv(el,'DstAddress') || 'any';
      const srcAddrSplit = _splitAddr(srcAddr, addrTypeMap);
      const dstAddrSplit = _splitAddr(dstAddr, addrTypeMap);
      const service = gv(el,'Service') || gv(el,'ServiceObject') || 'any';
      const schedule = gv(el,'Schedule') || gv(el,'ScheduleName') || '-';
      const comment  = gv(el,'Comment') || gv(el,'Note') || '';
      const log      = bool(gv(el,'LogEnabled') || gv(el,'Log') || 'false');
      // UTM fields
      const ips  = gv(el,'IPSPolicy') || gv(el,'IPS') || '';
      const av   = gv(el,'AVPolicy')  || gv(el,'AntiVirus') || '';
      const hasUTM = !!(ips || av);

      out.push({
        id: seq++, name,
        // Use same camelCase field names as all other parsers (Sophos/CP/PA/Juniper/pfSense)
        srcIntf: srcZone, dstIntf: dstZone,
        srcAddr: srcAddr, dstAddr: dstAddr,
        srcAddr4: srcAddrSplit.v4, srcAddr6: srcAddrSplit.v6,
        dstAddr4: dstAddrSplit.v4, dstAddr6: dstAddrSplit.v6,
        service, schedule,
        action: /allow|permit|accept/i.test(action) ? 'accept' : 'deny',
        nat:    'disable',
        ippool: 'disable', poolname: '-',
        logtraffic: log ? 'all' : 'disable',
        utm: {
          av:        av  ? av  : '-',
          ips:       ips ? ips : '-',
          webfilter: '-',
          appctrl:   '-',
        },
        status: enabled ? 'enable' : 'disable',
        users: '-', groups: '-',
        comments: comment,
        hasUTM,
        _vdom: '',
      });
    }
    return out;
  }

  // ── Routes ──────────────────────────────────────────────────────────────────
  function parseRoutes(doc) {
    const out = [];
    for (const el of qsa(doc, 'Route, RouteEntry, StaticRoute')) {
      const dest    = gv(el,'Destination') || gv(el,'Network') || gv(el,'DestNetwork') || '-';
      const mask    = gv(el,'SubnetMask') || gv(el,'Mask') || gv(el,'Netmask') || '-';
      const gw      = gv(el,'Gateway')     || gv(el,'NextHop') || '-';
      const iface   = gv(el,'Interface')   || gv(el,'IfName')  || '-';
      const metric  = gv(el,'Metric')      || '1';
      const comment = gv(el,'Comment')     || '';
      const enabled = bool(gv(el,'Enabled') || gv(el,'Enable') || 'true');
      if (dest === '-') continue;
      const subnet = mask !== '-' ? `${dest}/${mask}` : dest;
      const type   = /^0\.0\.0\.0/.test(dest) ? 'default' : 'static';
      out.push({ type, dst: subnet, gateway: gw, iface, device: iface, id: String(out.length+1), metric, distance: '-', priority: metric, status: enabled ? 'enable' : 'disable', blackhole: '-', comment, _vdom: '' });
    }
    return out;
  }

  // ── NAT Policies ────────────────────────────────────────────────────────────
  function parseNAT(doc) {
    const out = [];
    // Container-scoped to avoid cross-contamination; 標籤別名同上，未證實對應版本，僅為欄位命名容錯
    const containers = qsa(doc, 'NATPolicies, NATSettings, NATRules');
    const natEls = containers.length
      ? Array.from(containers[0].childNodes).filter(n=>n.nodeType===1)
      : qsa(doc, 'NATPolicy, NatEntry, NATEntry, NATRule, OneToOneNATEntry');
    for (const el of natEls) {
      const name    = gv(el,'Name') || gv(el,'Comment') || '-';
      if (name === '-') continue;
      const origSrc = gv(el,'OriginalSource') || gv(el,'InboundInterface') || '-';
      const tranSrc = gv(el,'TranslatedSource') || gv(el,'PublicIP') || gv(el,'MappedIP') || '-';
      const origDst = gv(el,'OriginalDestination') || '-';
      const tranDst = gv(el,'TranslatedDestination') || '-';
      const iface   = gv(el,'Interface') || gv(el,'InboundInterface') || '-';
      const enabled = bool(gv(el,'Enabled') || gv(el,'Enable') || 'true');
      const comment = gv(el,'Comment') || gv(el,'Note') || '';
      const isDnat  = tranDst && tranDst !== '-' && tranDst !== origDst;
      out.push({
        type: isDnat ? 'vip' : 'ippool',
        name, vipType: 'static', poolType: 'overload',
        extIp: isDnat ? origDst : origSrc,
        mapIp: isDnat ? tranDst : tranSrc,
        extIntf: iface, srcIntf: iface,
        startIp: '-', endIp: '-',
        portFwd: '-', extPort: '-', mapPort: '-', proto: '-',
        status: enabled ? 'enable' : 'disable',
        comment,
      });
    }
    return out;
  }

  // ── VPN (Site-to-Site) ──────────────────────────────────────────────────────
  function parseVPN(doc) {
    const out = [];
    for (const el of qsa(doc, 'VPNPolicy, VPNTunnel, VpnPolicy, SiteToSiteVPN')) {
      const name    = gv(el,'Name') || gv(el,'TunnelName') || '-';
      const peer    = gv(el,'PrimaryGateway') || gv(el,'PrimaryPeer') || gv(el,'RemoteGateway') || gv(el,'PeerIP') || '-';
      const local   = gv(el,'LocalNetwork') || gv(el,'LocalSubnet') || 'any';
      const remote  = gv(el,'RemoteNetwork') || gv(el,'RemoteSubnet') || 'any';
      const auth    = gv(el,'AuthMethod') || gv(el,'Authentication') || 'psk';
      const enc     = gv(el,'Encryption') || gv(el,'EncryptionAlgorithm') || '-';
      const enabled = bool(gv(el,'Enabled') || gv(el,'Enable') || 'true');
      const comment = gv(el,'Comment') || '';
      if (name === '-') continue;
      const dhgrp        = gv(el,'DHGroup') || gv(el,'Phase1DHGroup') || gv(el,'IKEDHGroup') || '-';
      const lifetime     = gv(el,'Phase1Life') || gv(el,'SALifetime') || gv(el,'KeyLife') || '-';
      const natRaw       = gv(el,'NATTraversal') || gv(el,'EnableNatTraversal') || gv(el,'NatTraversal') || '';
      const natTraversal = /true|enable|yes|1/i.test(natRaw) ? 'enable' : natRaw ? 'disable' : '-';
      const dpdRaw       = gv(el,'DPD') || gv(el,'EnableDPD') || gv(el,'DPDEnable') || '';
      const dpd          = /true|enable|yes|1/i.test(dpdRaw) ? 'enable' : dpdRaw ? 'disable' : '-';
      const phase2 = [];
      for (const p2 of qsa(el, 'Phase2, IPSecPhase2, Phase2Policy, Phase2Config')) {
        const p2enc  = gv(p2,'Encryption') || gv(p2,'Phase2Encryption') || enc;
        const p2auth = gv(p2,'Authentication') || gv(p2,'Phase2Authentication') || '-';
        const p2dh   = gv(p2,'DHGroup') || gv(p2,'PFS') || dhgrp;
        const p2life = gv(p2,'KeyLife') || gv(p2,'Phase2Life') || gv(p2,'SALifetime') || '28800';
        const lsub   = gv(p2,'LocalNetwork') || gv(p2,'LocalSubnet') || local;
        const rsub   = gv(p2,'RemoteNetwork') || gv(p2,'RemoteSubnet') || remote;
        phase2.push({name:`P2-${phase2.length+1}`,phase1:name,proposal:`${p2enc}-${p2auth}`,pfs:p2dh!=='-'?'enable':'disable',dhgrp:p2dh,lifetime:p2life,replay:'enable',localSub:lsub,remoteSub:rsub,autoNeg:'-',comment:'-'});
      }
      if (!phase2.length) {
        const p2enc  = gv(el,'Phase2Encryption') || enc;
        const p2auth = gv(el,'Phase2Authentication') || '-';
        const p2life = gv(el,'Phase2Life') || gv(el,'Phase2SALife') || '28800';
        phase2.push({name:'P2-1',phase1:name,proposal:`${p2enc}-${p2auth}`,pfs:dhgrp!=='-'?'enable':'disable',dhgrp,lifetime:p2life,replay:'enable',localSub:local,remoteSub:remote,autoNeg:'-',comment:'-'});
      }
      out.push({
        name, type: 'ipsec', mode: 'main',
        remotegw: peer, remote: peer,
        iface: '-', ikeVer: gv(el,'IKEVersion') || '2',
        localnet: local, remotenet: remote,
        localId: '-', peerId: peer, cert: '-',
        authMethod: auth, proposal: enc,
        dhgrp, lifetime, natTraversal, dpd,
        status: enabled ? 'enable' : 'disable',
        phase2, comment,
      });
    }
    return out;
  }

  // ── Users / Groups ──────────────────────────────────────────────────────────
  function parseUsers(doc) {
    const out = [];
    // Local users
    for (const el of qsa(doc, 'User, LocalUser, UserEntry')) {
      const name   = gv(el,'Name') || gv(el,'UserName') || ga(el,'name') || '-';
      const status = bool(gv(el,'Enabled') || gv(el,'Enable') || 'true') ? 'enable' : 'disable';
      const email  = gv(el,'Email') || gv(el,'EmailAddress') || '-';
      const role   = gv(el,'Role') || gv(el,'AccessType') || 'user';
      if (name === '-') continue;
      out.push({ type: /admin|administrator/i.test(role) ? 'admin' : 'local', name, status, accessLevel: role, authType: 'local', email, twoFactor: '-', roles: [], permissions: {}, members: '-', comment: '' });
    }
    // Groups
    for (const el of qsa(doc, 'UserGroup, UserGroupEntry')) {
      const name    = gv(el,'Name') || ga(el,'name') || '-';
      const members = [...qsa(el, 'Member, MemberName')].map(m => m.textContent.trim()).filter(Boolean).join(', ');
      if (name === '-') continue;
      out.push({ type: 'group', name, status: 'enable', accessLevel: '-', authType: 'local', email: '-', twoFactor: '-', roles: [], permissions: {}, members: members || '-', comment: '' });
    }
    return out;
  }

  // ── Schedules ───────────────────────────────────────────────────────────────
  // Fix: scope to <Schedules> container to avoid matching <Schedule> child refs in <Rule> elements
  function parseSchedules(doc) {
    const out = [];
    const containers = qsa(doc, 'Schedules');
    const els = containers.length
      ? Array.from(containers[0].children)
      : qsa(doc, 'ScheduleEntry');
    for (const el of els) {
      const name  = gv(el,'Name') || ga(el,'name') || '-';
      if (name === '-') continue;
      const type  = /once|onetime/i.test(gv(el,'Type') || '') ? 'onetime' : 'recurring';
      const start = gv(el,'StartTime') || gv(el,'Start') || '-';
      const end   = gv(el,'EndTime')   || gv(el,'End')   || '-';
      const day   = gv(el,'Days')      || gv(el,'Day')   || '-';
      out.push({ type, name, start, end, day, color: '0' });
    }
    return out;
  }

  // ── Main parse entry ────────────────────────────────────────────────────────
  function parse(text) {
    const doc = parseXML(text);
    // Validate: must have SonicWall-like root
    const root = doc.documentElement;
    if (!root || root.tagName === 'parsererror') throw new Error('SonicWall: XML 解析失敗，請確認匯出格式正確');

    const deviceInfo  = parseDeviceInfo(doc);
    const interfaces  = parseInterfaces(doc);
    // 位址物件需先解析出來，才能建 addrTypeMap 供 policies 的 Source/Destination 名稱反查
    // v4/v6 型別（見 _splitAddr() 上方註解）
    const addresses   = parseAddressObjects(doc);
    const policies    = parsePolicies(doc, buildAddrTypeMap(addresses));
    const routes      = parseRoutes(doc);
    const nat         = parseNAT(doc);
    const vpn         = parseVPN(doc);
    const services    = parseServiceObjects(doc);
    const users       = parseUsers(doc);
    const schedules   = parseSchedules(doc);

    const sdwan = parseSdwan(doc);
    const dhcp  = parseDhcp(doc);
    const dns   = parseDns(doc);
    const snmp  = parseSnmp(doc);
    const logservers = parseLogServers(doc);
    return { vendor: 'SonicWall', deviceInfo, interfaces, policies, routes, nat, vpn, addresses, services, users, schedules, sdwan, dhcp, dns, snmp, logservers };
  }


  // ── SonicWall WAN Failover / Load Balancing ────────────────────────────────

  // ── DHCP Server & Relay ──────────────────────────────────────────────────
  function parseDhcp(doc) {
    const servers=[], relays=[];
    const _bT=(root,tag)=>Array.from(root.getElementsByTagName(tag));
    _bT(doc,'DHCPServerEntry').forEach(el=>{
      servers.push({name:gv(el,'Name')||'-',iface:gv(el,'Interface')||'-',
        startIp:gv(el,'StartIP')||'-',endIp:gv(el,'EndIP')||'-',
        gateway:gv(el,'Gateway')||'-',mask:gv(el,'SubnetMask')||gv(el,'Netmask')||'-',
        dns1:gv(el,'DNS1')||gv(el,'PrimaryDNS')||'-',dns2:gv(el,'DNS2')||gv(el,'SecondaryDNS')||'-',
        domain:gv(el,'Domain')||gv(el,'DomainName')||'-',lease:gv(el,'LeaseTime')||'86400',
        status:bool(gv(el,'Enabled')||'true')?'enable':'disable',comment:gv(el,'Comment')||''});
    });
    _bT(doc,'DHCPRelay').forEach(el=>{
      relays.push({name:gv(el,'Name')||'-',iface:gv(el,'Interface')||'-',
        serverIp:gv(el,'Server')||gv(el,'ServerIP')||'-',status:'enable',comment:''});
    });
    return {servers,relays};
  }
  // ── DNS ─────────────────────────────────────────────────────────────────
  function parseDns(doc) {
    const result={servers:[],secondaries:[],domain:'-',proxy:false,proxyRules:[],dnsOverTls:false,cacheSize:'-',static:[]};
    const _bT=(root,tag)=>Array.from(root.getElementsByTagName(tag));
    [..._bT(doc,'DNSSettings'),..._bT(doc,'DNS')].forEach(el=>{
      const pri=gv(el,'PrimaryDNS')||gv(el,'Primary');if(pri&&pri!=='-')result.servers.push(pri);
      const sec=gv(el,'SecondaryDNS')||gv(el,'Secondary');if(sec&&sec!=='-')result.secondaries.push(sec);
      const dom=gv(el,'Domain')||gv(el,'DomainName');if(dom)result.domain=dom;
    });
    return result;
  }


  // ── SNMP ────────────────────────────────────────────────────────────────────
  function parseSnmp(doc) {
    const result={enabled:false,agent:{name:'-',description:'-',location:'-',contact:'-',version:[]},communities:[],v3users:[],trapServers:[]};
    const _bT=(root,tag)=>Array.from(root.getElementsByTagName(tag));
    const snmpEls=[..._bT(doc,'SNMP'),..._bT(doc,'SNMPSettings')];
    if(!snmpEls.length) return result;
    const el=snmpEls[0];
    const status=gv(el,'Status')||gv(el,'Enabled')||'';
    result.enabled=bool(status)||status.toLowerCase()==='enabled';
    result.agent.name     =gv(el,'SystemName')||gv(el,'Name')||'-';
    result.agent.contact  =gv(el,'Contact')||'-';
    result.agent.location =gv(el,'Location')||'-';
    const comm=gv(el,'Community')||gv(el,'ROCommunity')||'-';
    if(comm!=='-'){ result.communities.push({name:comm,permission:'ro',allowedHosts:[gv(el,'AcceptedHost')||'-'].filter(h=>h!=='-'),events:'-',status:'enable'}); result.agent.version.push('v2c'); }
    const trapComm=gv(el,'TrapCommunity')||comm;
    ['TrapServer1','TrapServer2','TrapServer3','TrapServer'].forEach(key=>{ const ip=gv(el,key); if(ip&&ip!=='-') result.trapServers.push({ip,port:'162',community:trapComm,version:'v2c'}); });
    return result;
  }

  // ── Log Servers ──────────────────────────────────────────────────────────────
  function parseLogServers(doc) {
    const result={syslog:[],fortianalyzer:[],netflow:[],logForward:[]};
    const _bT=(root,tag)=>Array.from(root.getElementsByTagName(tag));
    // SonicWall uses SyslogSettings, SyslogSettings2, SyslogSettings3 for multiple servers
    const swSyslogs=[..._bT(doc,'SyslogSettings'),..._bT(doc,'SyslogSettings2'),..._bT(doc,'SyslogSettings3'),..._bT(doc,'Syslog')];
    swSyslogs.forEach((el,i)=>{
      const srv=gv(el,'Server')||gv(el,'IPAddress')||'-';
      if(srv==='-') return;
      const enabled=bool(gv(el,'Enabled')||'true');
      if(!enabled) return;
      result.syslog.push({name:`Syslog${i+1}`,server:srv,port:gv(el,'Port')||'514',facility:gv(el,'Facility')||'local7',format:gv(el,'Format')||'default',protocol:'UDP',level:'information',status:'enable'});
    });
    return result;
  }

  function parseSdwan(doc) {
    const result = { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] };

    // WANFailover section — use getElementsByTagName (works in browser + xmldom)
    const _byTag = (root, tag) => Array.from(root.getElementsByTagName(tag));
    const _firstOf = (root, tags) => { for(const t of tags){ const els=_byTag(root,t); if(els.length) return els; } return []; };
    const wfRoots = _firstOf(doc, ['WANFailover','WANLoadBalancing','LoadBalancing','MultiWAN']);
    if (!wfRoots.length) return result;
    result.enabled = true;
    const wfScope = wfRoots[0];

    // WAN Groups = member groupings (nested in WANFailover)
    _firstOf(wfScope, ['WANGroup','WANInterface','WANMember']).forEach((el, idx) => {
      const name    = gv(el,'Name')       || gv(el,'Interface') || `WAN${idx+1}`;
      const iface   = gv(el,'Interface')  || name;
      const gw      = gv(el,'Gateway')    || '-';
      const method  = gv(el,'FailoverMethod') || gv(el,'Method') || 'LinkState';
      result.lbMode = method.toLowerCase().includes('round') ? 'source-ip-based'
                    : method.toLowerCase().includes('weight') ? 'weight-based'
                    : 'priority';
      result.members.push({
        id: String(idx+1), iface, zone: 'WAN',
        gateway: gw, gateway6: '-',
        priority: parseInt(gv(el,'Priority')||String(idx+1))||idx+1,
        weight:   parseInt(gv(el,'Weight') ||'1')||1,
        cost: 0, spillover: 0, volumeRatio: 1,
        status: bool(gv(el,'Enabled')||'true') ? 'enable' : 'disable',
        comment: gv(el,'Comment') || '',
      });
    });

    // Link probes = health checks
    _firstOf(wfScope, ['LinkProbe','WANProbe','HealthCheck']).forEach((el, idx) => {
      const iface    = gv(el,'Interface') || '-';
      const target   = gv(el,'Target')    || gv(el,'Host') || gv(el,'Server') || '8.8.8.8';
      const interval = gv(el,'Interval')  || gv(el,'ProbeInterval') || '30';
      const failCnt  = gv(el,'FailCount') || gv(el,'FailThreshold') || '3';
      result.healthChecks.push({
        name:         iface !== '-' ? `${iface}_probe` : `probe_${idx+1}`,
        server:       target,
        protocol:     (gv(el,'Type') || gv(el,'Protocol') || 'Ping').toLowerCase(),
        port:         gv(el,'Port') || '-',
        interval,
        timeout:      gv(el,'Timeout') || '10',
        failtime:     failCnt,
        recoverytime: gv(el,'RecoverCount') || failCnt,
        probePackets: '3', http200Only: 'disable',
        members:      iface !== '-' ? iface : 'all',
        slaThresholds: [],
      });
    });

    // Overall WAN policy = one service rule summarising the policy
    if (result.members.length > 0) {
      result.services.push({
        id:'1', name:'WAN_Failover_Policy',
        mode: result.lbMode || 'priority',
        src:'all', dst:'all', srcNegate:'disable', dstNegate:'disable', users:'-',
        protocol:'0', startPort:'-', endPort:'-',
        priorityMembers: result.members.map(m=>m.iface).join(', '),
        priorityZone:'-', preferredUplink: result.members[0]?.iface||'-',
        slaCompare:'order', tie:'zone', slaRefs:[], inputDevice:'-',
        status:'enable', comment: `Method: ${result.lbMode}`,
      });
    }

    return result;
  }

  return { parse };
})();



