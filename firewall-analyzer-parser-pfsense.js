// ═══ parser-pfsense.js ═══
/**
 * pfSense / OPNsense Configuration Parser
 * Supports: config.xml (exported from Diagnostics > Backup & Restore)
 * Covers: interfaces, firewall rules, NAT, routing, VPN (IPSec/OpenVPN),
 *         aliases (address/service objects), users/groups, schedules
 */
const PfsenseParser = (() => {

  // ── XML helpers ───────────────────────────────────────────────────────────
  // 這份也有巢狀同名標籤防護，但做法與 SophosParser 不同：直接剝除內容中「所有」子標籤
  // （`.replace(/<[^>]+>/g,'')`），不只是同名標籤；無 HTML 實體解碼（見 SophosParser
  // 開頭註解說明整體差異背景，三份刻意不合併）。
  function xv(xml, tag) {
    // Fix: 嚴格 scope — 只匹配直接子節點，不讓子節點的同名標籤污染結果
    const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i');
    const m = xml.match(re);
    if (!m) return '';
    const inner = m[1];
    // 若內含同名巢狀標籤，取第一層文字（去除子標籤）
    if (new RegExp(`<${tag}[\\s>]`, 'i').test(inner)) {
      return inner.replace(new RegExp(`<${tag}[\\s\\S]*?<\\/${tag}>`, 'gi'), '')
                  .replace(/<[^>]+>/g, '').trim()
                  .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim();
    }
    return inner.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim();
  }
  function xva(xml, tag) {
    const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'gi');
    const r = []; let m;
    while ((m = re.exec(xml)) !== null)
      r.push(m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1').trim());
    return r;
  }
  function xblks(xml, tag) {
    const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'gi');
    const r = []; let m;
    while ((m = re.exec(xml)) !== null)
      r.push({ _outer: m[0], _inner: m[1] });
    return r;
  }
  function hasTag(xml, tag) {
    return new RegExp(`<${tag}(?:\\s[^>]*)?/?>`, 'i').test(xml);
  }
  function prefixToMask(bits) {
    if (!bits || isNaN(bits)) return '255.255.255.0';
    const n = (0xFFFFFFFF << (32 - parseInt(bits))) >>> 0;
    return [(n>>>24)&0xFF,(n>>>16)&0xFF,(n>>>8)&0xFF,n&0xFF].join('.');
  }
  function subnetToIp(sub) {
    // "192.168.1.0/24" → {ip, mask}
    if (!sub) return {ip:'-',mask:'-'};
    const p = sub.split('/');
    return { ip: p[0], mask: p[1] ? prefixToMask(parseInt(p[1])) : '255.255.255.255' };
  }

  // ── Interface name resolution ─────────────────────────────────────────────
  // pfSense uses internal names (wan, lan, opt1...) that map to real if names
  function buildIfMap(ifXml) {
    // Returns {internalName: {realif, descr, ipaddr, subnet, type}}
    const map = {};
    // Extract all child elements of <interfaces>
    const re = /<(\w+)>([\s\S]*?)<\/\1>/gi;
    let m;
    const seen = new Set(['vlanif','vip','wireless']);
    while ((m = re.exec(ifXml)) !== null) {
      const key = m[1].toLowerCase();
      if (seen.has(key) || key === 'interfaces') continue;
      const inner = m[2];
      map[key] = {
        realif:  xv(inner,'if') || key,
        descr:   xv(inner,'descr') || key.toUpperCase(),
        ipaddr:  xv(inner,'ipaddr') || '-',
        subnet:  xv(inner,'subnet') || '-',
        ip6:     xv(inner,'ipaddrv6') || '-',
        type:    xv(inner,'ipaddr') === 'dhcp' ? 'dhcp' : xv(inner,'type') || 'static',
        enable:  hasTag(inner,'enable'),
        spoofmac:xv(inner,'spoofmac')||'-',
        mtu:     xv(inner,'mtu')||'1500',
        media:   xv(inner,'media')||'-',
        gateway: xv(inner,'gateway')||'-',
        track6if:xv(inner,'track6-interface')||'-',
      };
    }
    return map;
  }

  // Map internal interface name to display name
  function resolveIf(ifMap, name) {
    const n = (name||'').toLowerCase().trim();
    if (ifMap[n]) return ifMap[n].descr || n.toUpperCase();
    // Fallback: opt1→OPT1, etc.
    return n.toUpperCase();
  }

  // ── Device info ───────────────────────────────────────────────────────────
  function parseDeviceInfo(xml) {
    const sys = xv(xml, 'system');
    return {
      vendor:   'pfSense',
      hostname: xv(sys||xml,'hostname') || xv(xml,'hostname') || '-',
      firmware: xv(sys||xml,'version') || xv(xml,'version') ||
                (xml.match(/pfSense[\s\-]+([\d\.]+)/i)||[])[1] || '-',
      model:    xv(sys||xml,'platform') || xv(xml,'platform') ||
                (xml.includes('opnsense')||xml.includes('OPNsense') ? 'OPNsense' : 'pfSense'),
      serial:   '-',
      vdom:     [], vdomNames:[], isMultiVdom: false,
    };
  }

  // ── Interfaces ────────────────────────────────────────────────────────────
  function parseInterfaces(xml) {
    const ifaces = [];
    const ifXml = xv(xml,'interfaces');
    if (!ifXml) return ifaces;

    const ifMap = buildIfMap(ifXml);

    Object.entries(ifMap).forEach(([key, ifc]) => {
      const ip   = ifc.ipaddr === 'dhcp' ? 'DHCP' : ifc.ipaddr;
      const mask = ip && ip !== 'DHCP' && ip !== '-' ? prefixToMask(parseInt(ifc.subnet)) : '-';
      const role = key==='wan' ? 'WAN' : key==='lan' ? 'LAN' : key.startsWith('opt') ? 'DMZ' : 'Unknown';
      ifaces.push({
        name:    ifc.realif || key,
        alias:   ifc.descr  || key.toUpperCase(),
        ip:      ip !== '-' ? ip : '-',
        mask,
        type:    ifc.realif && ifc.realif.includes('vlan') ? 'vlan' : 'physical',
        vlanId:  '-',
        vdom:    key,
        role,
        status:  ifc.enable ? 'up' : 'down',
        speed:   ifc.media || '-',
        mtu:     ifc.mtu   || '1500',
        macaddr: ifc.spoofmac || '-',
        mode:    ifc.ipaddr === 'dhcp' ? 'dhcp' : 'static',
        gwdetect:'-',
        desc:    ifc.descr || '-',
        allowaccess: '-',
        interface:   ifc.realif || '-',
        gateway:     ifc.gateway || '-',
        _vdom: key,
      });
    });

    // VLANs
    const vlansXml = xv(xml,'vlans');
    xblks(vlansXml||xml,'vlan').forEach(b => {
      const inner = b._inner;
      const tag   = xv(inner,'tag');
      const iface = xv(inner,'if');
      const descr = xv(inner,'descr') || `VLAN${tag}`;
      ifaces.push({
        name:    `${iface}.${tag}`,
        alias:   descr,
        ip:      '-', mask: '-',
        type:    'vlan', vlanId: tag,
        vdom:    `vlan${tag}`, role: 'VLAN',
        status:  'up', speed: '-', mtu: '1500',
        macaddr: '-', mode: 'static', gwdetect: '-',
        desc:    descr, allowaccess: '-',
        interface: iface, gateway: '-',
        _vdom: `vlan${tag}`,
      });
    });

    return ifaces;
  }

  // ── Firewall rules ────────────────────────────────────────────────────────
  // "ip:port" 只有剛好一個冒號、左側本身不含冒號時才安全砍掉 port；IPv6 字面值含多個冒號，
  // 原樣保留（不猜測，交給下面 _splitAddr 的冒號判斷處理）
  function _pfsenseStripPort(addr) {
    const m = addr.match(/^(.*):(\d+)$/);
    if (!m) return addr;
    return m[1].split(':').length === 1 ? m[1] : addr;
  }
  // pfSense srcaddr/dstaddr 可能帶 "!" 否定前綴（規則排除），查表前需剝除（addrTypeMap 的 key
  // 是不含 "!" 的原始物件名稱），分類完再把前綴補回輸出值，維持與主欄位一致的顯示格式
  function _splitAddrNeg(addr, addrTypeMap) {
    const neg = addr.startsWith('!');
    const r = _splitAddr(neg ? addr.slice(1) : addr, addrTypeMap);
    if (neg) { if (r.v4 !== '-') r.v4 = '!' + r.v4; if (r.v6 !== '-') r.v6 = '!' + r.v6; }
    return r;
  }
  function parsePolicies(xml, ifMap, addrTypeMap) {
    const policies = [];
    const filterXml = xv(xml,'filter');
    if (!filterXml) return policies;

    xblks(filterXml,'rule').forEach((b, idx) => {
      const inner = b._inner;
      const type  = xv(inner,'type') || 'pass';
      const disabled = hasTag(inner,'disabled');
      const iface = xv(inner,'interface') || '-';

      // Source
      const srcXml = xv(inner,'source');
      let srcAddr = 'any';
      if (srcXml) {
        if (hasTag(srcXml,'any')) srcAddr = 'any';
        else {
          const net = xv(srcXml,'network');
          const addr = xv(srcXml,'address');
          const sub  = xv(srcXml,'subnet');
          if (net) srcAddr = net;
          else if (addr && sub) srcAddr = `${addr}/${sub}`;
          else if (addr) srcAddr = addr;
        }
        if (xv(srcXml,'not') === '' && hasTag(srcXml,'not')) srcAddr = `!${srcAddr}`;
      }

      // Destination
      const dstXml = xv(inner,'destination');
      let dstAddr = 'any';
      if (dstXml) {
        if (hasTag(dstXml,'any')) dstAddr = 'any';
        else {
          const net = xv(dstXml,'network');
          const addr = xv(dstXml,'address');
          const sub  = xv(dstXml,'subnet');
          if (net) dstAddr = net;
          else if (addr && sub) dstAddr = `${addr}/${sub}`;
          else if (addr) dstAddr = addr;
        }
        const dport = xv(dstXml,'port');
        if (dport) dstAddr += `:${dport}`;
      }

      // Service/Protocol
      const proto  = xv(inner,'protocol') || 'any';
      const dport  = xv(inner,'destination') ? xv(xv(inner,'destination'),'port')||'' : '';
      const sport  = xv(inner,'source')      ? xv(xv(inner,'source'),'port')||'' : '';
      let service = proto !== 'any' ? proto.toUpperCase() : 'ANY';
      if (dport) service += `:${dport}`;

      const action = type === 'pass' ? 'accept' : 'deny';
      const log    = hasTag(inner,'log') ? 'enable' : 'disable';
      const nat    = xv(inner,'associated-rule-id') ? 'enable' : 'disable';

      // IPv4/IPv6 separation：strip port 改用 _pfsenseStripPort（避免把 IPv6 字面值從第一個
      // 冒號腰斬）；"!" 否定前綴用 _splitAddrNeg 處理
      const srcAddrBase = _pfsenseStripPort(srcAddr);
      const dstAddrBase = _pfsenseStripPort(dstAddr);
      const srcAddrSplit = _splitAddrNeg(srcAddrBase, addrTypeMap);
      const dstAddrSplit = _splitAddrNeg(dstAddrBase, addrTypeMap);

      policies.push({
        id:       String(idx+1),
        name:     xv(inner,'descr') || xv(inner,'label') || `Rule-${idx+1}`,
        srcIntf:  resolveIf(ifMap, iface),
        dstIntf:  xv(inner,'destination-interface') ? resolveIf(ifMap, xv(inner,'destination-interface')) : 'any',
        srcAddr, dstAddr,
        srcAddr4: srcAddrSplit.v4, srcAddr6: srcAddrSplit.v6,
        dstAddr4: dstAddrSplit.v4, dstAddr6: dstAddrSplit.v6,
        service,
        schedule: xv(inner,'sched') || 'always',
        action, nat, ippool:'disable', poolname:'-',
        logtraffic: log, logstart:'-',
        utm:{ av:'-', webfilter:'-', ips:'-', ssl:'-', appctrl:'-' },
        status:   disabled ? 'disable' : 'enable',
        comments: xv(inner,'descr')||'-',
        users:    xv(inner,'username')||'-', groups:'-',
        _vdom:    resolveIf(ifMap,iface)||iface,
      });
    });

    return policies;
  }

  // ── Aliases (address + service objects) ───────────────────────────────────
  function parseAddressObjects(xml) {
    const objs = [];
    const aliasesXml = xv(xml,'aliases');
    xblks(aliasesXml||xml,'alias').forEach(b => {
      const inner = b._inner;
      const name  = xv(inner,'name');
      const type  = xv(inner,'type');  // host/network/port/url
      const addr  = xv(inner,'address');
      const detail= xv(inner,'detail');
      const descr = xv(inner,'descr');

      if (!name) return;

      if (type === 'host' || type === 'network' || type === 'url' || type === 'urltable') {
        // Address alias
        const addrs = addr.split(/\s+/).filter(Boolean);
        if (addrs.length === 1) {
          const isRange = addrs[0].includes('-');
          const isNet   = addrs[0].includes('/');
          objs.push({
            category: 'address', name, type: isRange?'iprange':isNet?'ipmask':'ipmask',
            subnet:   isNet ? addrs[0] : isRange ? '-' : `${addrs[0]}/32`,
            fqdn:     type==='url'||type==='urltable' ? addrs[0] : '-',
            startIp:  isRange ? addrs[0].split('-')[0] : addrs[0].split('/')[0],
            endIp:    isRange ? addrs[0].split('-')[1]||'-' : '-',
            wildcard: '-', iface: '-', color: '0',
            comment:  descr || '-', members: '-', _vdom: 'global',
          });
        } else {
          // Multiple → group
          objs.push({
            category: 'address-group', name, type: 'group',
            subnet: '-', fqdn: '-', startIp:'-', endIp:'-', wildcard:'-',
            iface:'-', color:'0', comment: descr||'-',
            members: addrs.join(', '), _vdom:'global',
          });
        }
      } else if (type === 'port') {
        // Port alias → service object
        const ports = addr.split(/\s+/).filter(Boolean);
        objs.push({
          category: 'custom', name, proto: 'TCP/UDP',
          tcpPorts: ports.join(', '), udpPorts: ports.join(', '),
          icmpType: '-', icmpCode: '-',
          comment: descr||'-', color:'0', category_name:'-', members:'-',
          _isService: true,
        });
      }
    });
    return objs;
  }

  // Split address vs service aliases
  function parseServiceObjects(xml) {
    const all = parseAddressObjects(xml);
    return all.filter(o => o._isService).map(o => {
      const { _isService, ...svc } = o;
      svc.category = 'custom';
      return svc;
    });
  }
  function parseAddressObjectsOnly(xml) {
    return parseAddressObjects(xml).filter(o => !o._isService);
  }

  // ── Routes ────────────────────────────────────────────────────────────────
  function parseRoutes(xml) {
    const routes = [];
    const gwsXml  = xv(xml,'gateways');
    const gwMap   = {};
    if (gwsXml) {
      xblks(gwsXml,'gateway_item').forEach(b => {
        const name = xv(b._inner,'name');
        const gw   = xv(b._inner,'gateway');
        const ifc  = xv(b._inner,'interface');
        if (name) gwMap[name] = { gw, ifc };
      });
    }

    const routesXml = xv(xml,'staticroutes');
    xblks(routesXml||xml,'route').forEach((b,i) => {
      const inner = b._inner;
      const network = xv(inner,'network');
      const gwName  = xv(inner,'gateway');
      const gwInfo  = gwMap[gwName] || { gw: gwName, ifc: '-' };
      routes.push({ type:'static', id:String(i+1),
        dst: network || '0.0.0.0/0',
        gateway: gwInfo.gw || gwName || '-',
        device:  gwInfo.ifc || '-',
        distance: '1', priority:'0', weight:'0',
        comment: xv(inner,'descr')||'-',
        status: hasTag(inner,'disabled') ? 'disable' : 'enable',
        blackhole: 'disable', vrf: '0' });
    });

    // Add default gateway route
    const sys = xv(xml,'system');
    const defGw = xv(sys||xml,'defaultgw');
    if (defGw && !routes.find(r=>r.dst==='0.0.0.0/0')) {
      routes.push({ type:'static', id:'gw', dst:'0.0.0.0/0',
        gateway:defGw, device:'-', distance:'1', priority:'0', weight:'0',
        comment:'Default gateway', status:'enable', blackhole:'disable', vrf:'0' });
    }

    return routes;
  }

  // ── VPN ───────────────────────────────────────────────────────────────────
  function parseVPN(xml) {
    const vpns = [];

    // IPSec
    const ipsecXml = xv(xml,'ipsec');
    if (ipsecXml) {
      // Phase 1 entries
      xblks(ipsecXml,'phase1').forEach((b,i) => {
        const inner = b._inner;
        const p1id  = xv(inner,'ikeid') || String(i+1);
        const enc   = xv(inner,'encryption-algorithm') || xv(xv(inner,'encryption-algorithm-option')||inner,'name') || 'aes256';
        const hash  = xv(inner,'hash-algorithm') || 'sha256';
        const dhgrp = xv(inner,'dhgroup') || '14';
        const ikeVer= xv(inner,'iketype') === 'ikev2' ? '2' : '1';

        // Phase 2s belonging to this P1
        const phase2 = [];
        xblks(ipsecXml,'phase2').forEach(p2b => {
          if (xv(p2b._inner,'ikeid') !== p1id) return;
          const p2e = xv(p2b._inner,'encryption-algorithm') || enc;
          const p2h = xv(p2b._inner,'hash-algorithm') || hash;
          const p2d = xv(p2b._inner,'pfsgroup') || dhgrp;
          const locNet = xv(p2b._inner,'localid');
          const remNet = xv(p2b._inner,'remoteid');
          const locSub = xv(locNet||p2b._inner,'network') || xv(locNet||p2b._inner,'address')||'-';
          const remSub = xv(remNet||p2b._inner,'network') || xv(remNet||p2b._inner,'address')||'-';
          phase2.push({
            name: `P2-${p1id}-${phase2.length+1}`, phase1: `P1-${p1id}`,
            proposal: `${p2e}-${p2h}`,
            pfs: p2d !== '0' ? 'enable' : 'disable',
            dhgrp: p2d, lifetime: xv(p2b._inner,'lifetime')||'3600',
            replay:'enable', localSub: locSub, remoteSub: remSub,
            autoNeg:'-', comment:'-',
          });
        });

        const authMethod = xv(inner,'authentication_method') || 'pre_shared_key';
        vpns.push({ type:'ipsec-p1', name:`P1-${p1id}`,
          mode: xv(inner,'mode')||'main',
          remote:  xv(inner,'remote-gateway')||xv(inner,'peer')||'-',
          iface:   xv(inner,'interface')||'-',
          ikeVer, authMethod: authMethod.includes('psk')||authMethod.includes('pre_shared') ? 'psk' : 'certificate',
          peertype:'-',
          proposal: `${enc}-${hash}`,
          dhgrp, lifetime: xv(inner,'lifetime')||'28800',
          natTraversal: xv(inner,'nat_traversal')||'enable',
          dpd: xv(inner,'dpd_enable')||'disable',
          dpdInterval: xv(inner,'dpd_delay')||'-',
          localId: xv(inner,'myid_data')||'-', peerId: xv(inner,'peerid_data')||'-',
          xauthType:'-', cert: xv(inner,'certref')||'-',
          monitorConn:'-', autoNeg:'-', status:'enable',
          phase2, _vdom:'default' });
      });
    }

    // OpenVPN (Server)
    const ovpnXml = xv(xml,'openvpn');
    if (ovpnXml) {
      xblks(ovpnXml,'openvpn-server').forEach((b,i) => {
        const inner = b._inner;
        const vpnid = xv(inner,'vpnid') || String(i+1);
        const mode  = xv(inner,'mode') || 'server_tls';
        const desc  = xv(inner,'description') || `OpenVPN-${vpnid}`;
        const pool  = xv(inner,'tunnel_network')||'-';
        const ifnet = xv(inner,'interface')||'wan';
        const port  = xv(inner,'local_port')||'1194';
        const proto = xv(inner,'protocol')||'UDP';
        const enc   = xv(inner,'crypto')||'AES-256-CBC';
        // local_network（IPv4）是 pfSense 官方原始碼 openvpn.inc 用來組 push route 的欄位，
        // 逗號分隔的 CIDR 清單，語意等同「split tunnel 時實際推送給 client 的路由」
        const splitTunnelRoutingAddr = xv(inner,'local_network') || '-';
        vpns.push({ type:'ssl-vpn', name: desc,
          iface: ifnet, remote:'-', port,
          tunPort:'-', addr: pool, dns1: xv(inner,'dns_server1')||'-',
          dns2: xv(inner,'dns_server2')||'-', wins1:'-', ipPool:pool,
          algorithm: enc, dtls: proto==='UDP'?'enable':'disable',
          authTimeout:'-', ikeVer:'-', authMethod:'certificate',
          proposal:enc, dhgrp:'-', phase2:[], status:'enable', _vdom:'default',
          splitTunnel: splitTunnelRoutingAddr!=='-'?'enable':'-', splitTunnelRoutingAddr });
      });
      // OpenVPN client instances
      xblks(ovpnXml,'openvpn-client').forEach((b,i) => {
        const inner = b._inner;
        const desc  = xv(inner,'description') || `OpenVPN-Client-${i+1}`;
        vpns.push({ type:'ssl-vpn', name:desc,
          iface: xv(inner,'interface')||'wan',
          remote: xv(inner,'server_addr')||'-',
          port: xv(inner,'server_port')||'1194',
          tunPort:'-', addr:'-', dns1:'-', dns2:'-', wins1:'-', ipPool:'-',
          algorithm: xv(inner,'crypto')||'AES-256-CBC',
          dtls:'disable', authTimeout:'-', ikeVer:'-', authMethod:'certificate',
          proposal: xv(inner,'crypto')||'-', dhgrp:'-', phase2:[],
          status:'enable', _vdom:'default' });
      });
    }

    return vpns;
  }

  // ── NAT ───────────────────────────────────────────────────────────────────
  function parseNAT(xml, ifMap) {
    const nats = [];
    const natXml = xv(xml,'nat');
    if (!natXml) return nats;

    // Outbound NAT rules
    xblks(natXml,'rule').forEach((b,i) => {
      const inner = b._inner;
      const ifname = xv(inner,'interface')||'wan';
      const src = xv(inner,'source');
      const srcNet = src ? xv(src,'network')||xv(src,'address')||'-' : '-';
      const target = xv(inner,'target');
      const nat2   = xv(inner,'nataddr')||'-';
      const isManual = xv(inner,'associated-rule-id')==='' ? false : true;
      if (target || nat2) {
        nats.push({ type:'ippool', name: xv(inner,'descr')||`Outbound-NAT-${i+1}`,
          poolType:'overload', startIp: target||nat2||'-', endIp:'-',
          srcIntf: resolveIf(ifMap,ifname), arpReply:'enable',
          comment: xv(inner,'descr')||'-', _vdom:'default' });
      }
    });

    // Port-forward (DNAT) rules
    xblks(natXml,'servernat').concat(xblks(natXml,'forward')).forEach((b,i) => {
      const inner = b._inner;
      const extIface = xv(inner,'interface')||'wan';
      const extPort  = xv(inner,'local-port') || xv(inner,'dstport')||'-';
      const intIp    = xv(inner,'target')||xv(inner,'local-ip')||'-';
      const intPort  = xv(inner,'local-port')||xv(inner,'targetport')||extPort;
      const proto    = xv(inner,'protocol')||'tcp';
      nats.push({ type:'vip', name: xv(inner,'descr')||`PortFwd-${i+1}`,
        vipType:'static-nat',
        extIp:   '-',
        extIntf: resolveIf(ifMap,extIface),
        mapIp:   intIp,
        portFwd: 'enable', extPort, mapPort: intPort, proto,
        comment: xv(inner,'descr')||'-', status:'enable', _vdom:'default' });
    });

    return nats;
  }

  // ── Schedules ─────────────────────────────────────────────────────────────
  function parseSchedules(xml) {
    const scheds = [];
    const schedXml = xv(xml,'schedules');
    xblks(schedXml||xml,'schedule').forEach(b => {
      const inner = b._inner;
      const name  = xv(inner,'name');
      if (!name) return;
      xblks(inner,'timerange').forEach((tr,i) => {
        scheds.push({ type:'recurring', name: i===0?name:`${name}-${i+1}`,
          start: xv(tr._inner,'from')||'-',
          end:   xv(tr._inner,'to')||'-',
          day:   xv(tr._inner,'day')||'-', color:'0', _vdom:'default' });
      });
      if (!xblks(inner,'timerange').length) {
        scheds.push({ type:'recurring', name,
          start:'-', end:'-', day:'-', color:'0', _vdom:'default' });
      }
    });
    return scheds;
  }

  // ── Users ─────────────────────────────────────────────────────────────────
  function parseUsers(xml) {
    const users = [];
    const sysXml = xv(xml,'system');

    // Local users
    xblks(sysXml||xml,'user').forEach(b => {
      const inner = b._inner;
      const name  = xv(inner,'name');
      if (!name) return;
      const priv  = xva(inner,'priv').concat(xva(inner,'scope'));
      const isAdmin = priv.some(p=>p.includes('page-all')||p.includes('admin')) ||
                      xv(inner,'scope')==='system';
      users.push({ type: isAdmin ? 'admin' : 'local', name,
        status:   xv(inner,'disabled') ? 'disable' : 'enable',
        authType: xv(inner,'ipsecpsk') ? 'psk' : xv(inner,'cert') ? 'certificate' : 'password',
        email:    xv(inner,'email') || '-',
        twoFactor:'disable', twoFType:'-',
        ldapServer:'-', radiusServer:'-',
        comment:  xv(inner,'fullname').replace(/^<!\[CDATA\[|\]\]>$/g,'')||'-',
        members:  '-',
        permissions: isAdmin ? [{resource:'All',access:'read-write'}] : [{resource:'WebGUI',access:'read-write'}],
        roles:    [xv(inner,'scope')||'user'],
        accessLevel: isAdmin ? 'super-admin' : 'user',
        _vdom: 'default' });
    });

    // Groups
    xblks(sysXml||xml,'group').forEach(b => {
      const inner = b._inner;
      const name = xv(inner,'name');
      if (!name) return;
      const members = xva(inner,'member').join(', ');
      users.push({ type:'group', name,
        groupType: xv(inner,'scope')||'local',
        members, match:'-', authTimeout:'-',
        comment: xv(inner,'description')||'-', status:'enable',
        permissions:[], roles:[], accessLevel:'group', _vdom:'default' });
    });

    // RADIUS
    const radiusXml = xv(sysXml||xml,'radiusserver') || xv(xml,'radiusserver');
    if (radiusXml) {
      xblks(radiusXml,'server').concat(xblks(sysXml||xml,'radius')).forEach((b,i)=>{
        const inner = b._inner;
        const ip = xv(inner,'ipaddr')||xv(inner,'ip')||'-';
        if (ip==='-') return;
        users.push({ type:'radius-server', name:`RADIUS-${i+1}`,
          server:ip, port:xv(inner,'port')||xv(inner,'auth_port')||'1812',
          authType:xv(inner,'protocol')||'auto', nasIp:'-',
          comment:xv(inner,'name')||'-', status:'enable',
          members:'-', permissions:[], roles:[], accessLevel:'auth-server', _vdom:'default' });
      });
    }

    // LDAP / Active Directory
    const ldapBlks = xblks(sysXml||xml,'authserver');
    ldapBlks.forEach(b => {
      const inner = b._inner;
      const stype = xv(inner,'type');
      if (!stype) return;
      const name  = xv(inner,'name')||`Auth-${stype}`;
      if (stype === 'ldap') {
        users.push({ type:'ldap-server', name,
          server:  xv(inner,'host')||'-', port:xv(inner,'port')||'389',
          dn:      xv(inner,'search_scope')||xv(inner,'base_dn')||'-',
          bindType:xv(inner,'binddn')?'regular':'anonymous',
          bindDn:  xv(inner,'binddn')||'-', cnid:xv(inner,'attr_user')||'uid',
          groupFilter:xv(inner,'attr_groups_member')||'-',
          ssl:     xv(inner,'transport')||'disable',
          comment: name, status:'enable', members:'-',
          permissions:[], roles:[], accessLevel:'auth-server', _vdom:'default' });
      } else if (stype === 'radius') {
        users.push({ type:'radius-server', name,
          server:  xv(inner,'host')||'-', port:xv(inner,'radius_auth_port')||'1812',
          authType:xv(inner,'radius_protocol')||'auto', nasIp:'-',
          comment: name, status:'enable', members:'-',
          permissions:[], roles:[], accessLevel:'auth-server', _vdom:'default' });
      }
    });

    return users;
  }

  // HA/Cluster：已查證官方文件與 GitHub 原始碼（pfsense/xmlrpc.php）確認 config.xml 語法：
  //   <hasync><pfsyncenabled>on</pfsyncenabled><pfsyncinterface>opt1</pfsyncinterface>
  //     <synchronizetoip>192.168.200.2</synchronizetoip></hasync>
  // CARP VIP（<virtualip><vip><mode>carp</mode>...</vip></virtualip>）為 pfSense 標準既有語法，
  // vhid/advskew 對應 groupId/priority 概念
  function parseHa(xml) {
    const result = { enabled:false, mode:'-', groupId:'-', priority:'-', peerIp:'-', syncInterface:'-', vip:'-' };
    const hasyncBlock = xv(xml, 'hasync');
    const carpVips = xblks(xv(xml,'virtualip')||'', 'vip').filter(b => /<mode>\s*carp\s*<\/mode>/i.test(b._inner));
    result.enabled = (!!hasyncBlock && /^(on|yes|1)$/i.test(xv(hasyncBlock,'pfsyncenabled'))) || carpVips.length>0;
    if (!result.enabled) return result;
    result.mode = 'CARP';
    if (hasyncBlock) {
      result.syncInterface = xv(hasyncBlock, 'pfsyncinterface') || '-';
      result.peerIp = xv(hasyncBlock, 'synchronizetoip') || '-';
    }
    if (carpVips.length) {
      const first = carpVips[0]._inner;
      const subnet = xv(first, 'subnet');
      const bits = xv(first, 'subnet_bits');
      result.vip = subnet ? (bits ? `${subnet}/${bits}` : subnet) : '-';
      result.groupId = xv(first, 'vhid') || '-';
      result.priority = xv(first, 'advskew') || '-';
    }
    return result;
  }

  // ── Main parse ────────────────────────────────────────────────────────────
  function parse(text) {
    // Fix: 前處理 — 移除 XML 註解，避免被解析為有效規則
    const xml = text.replace(/<!--[\s\S]*?-->/g, '');
    const ifXml = xv(xml,'interfaces');
    const ifMap = ifXml ? buildIfMap(ifXml) : {};
    // 位址物件需先解析出來，才能建 addrTypeMap 供 policies 的 source/destination 名稱反查
    // v4/v6 型別（見 _splitAddr() 定義處註解）
    const addresses = parseAddressObjectsOnly(xml);

    return {
      vendor:     'pfSense',
      deviceInfo: parseDeviceInfo(xml),
      interfaces: parseInterfaces(xml),
      policies:   parsePolicies(xml, ifMap, buildAddrTypeMap(addresses)),
      routes:     parseRoutes(xml),
      vpn:        parseVPN(xml),
      addresses,
      services:   parseServiceObjects(xml),
      schedules:  parseSchedules(xml),
      nat:        parseNAT(xml, ifMap),
      users:      parseUsers(xml),
      sdwan:      parseSdwan(xml),
      ha:         parseHa(xml),
      dhcp:       parseDhcp(xml),
      dns:        parseDns(xml),
      snmp:       parseSnmp(xml),
      logservers: parseLogServers(xml),
      _vdomNames: [],
      _isMultiVdom: false,
    };
  }


  // ── pfSense/OPNsense Multi-WAN / Gateway Groups ────────────────────────────

  // ── DHCP Server & Relay ──────────────────────────────────────────────────
  function parseDhcp(xml) {
    const servers=[], relays=[];
    const dhcpdBlks=xblks(xml,'dhcpd');
    if(dhcpdBlks.length){
      const raw=dhcpdBlks[0]._inner||'';
      for(const m of raw.matchAll(/<(\w+)>([\s\S]*?)<\/\1>/g)){
        const[,ifName,body]=m;
        if(!body.includes('<enable')) continue;
        const xg=(tag)=>{const mm=body.match(new RegExp(`<${tag}>([^<]+)<\\/${tag}>`,'i'));return mm?mm[1].trim():'-';};
        servers.push({name:ifName+'_dhcp',iface:ifName,startIp:xg('from'),endIp:xg('to'),
          gateway:xg('gateway'),mask:'-',dns1:xg('dnsserver'),dns2:'-',domain:xg('domain'),
          lease:xg('defaultleasetime')||'86400',status:'enable',comment:xg('description')||''});
      }
    }
    xblks(xml,'dhcrelay').forEach(blk=>{
      const t=blk._inner;
      relays.push({name:'dhcrelay',iface:xv(t,'interface')||'-',serverIp:xv(t,'server')||'-',status:'enable',comment:''});
    });
    return {servers,relays};
  }
  // ── DNS ─────────────────────────────────────────────────────────────────
  function parseDns(xml) {
    const result={servers:[],secondaries:[],domain:'-',proxy:false,proxyRules:[],dnsOverTls:false,cacheSize:'-',static:[]};
    xblks(xml,'system').forEach(blk=>{
      const t=blk._inner;
      for(const m of t.matchAll(/<dnsserver>([^<]+)<\/dnsserver>/gi))result.servers.push(m[1].trim());
      const dom=xv(t,'domain');if(dom)result.domain=dom;
    });
    if(xblks(xml,'dnsmasq').length)result.proxy=true;
    xblks(xml,'unbound').forEach(blk=>{
      result.proxy=true; const t=blk._inner;
      for(const m of t.matchAll(/<hosts>([\s\S]*?)<\/hosts>/gi)){
        const hb=m[1];const host=xv(hb,'host'),domain=xv(hb,'domain'),ip=xv(hb,'ip');
        if(host&&ip)result.static.push({name:`${host}.${domain}`,type:'A',ip,zone:domain});
      }
      for(const m of t.matchAll(/<domainoverrides>([\s\S]*?)<\/domainoverrides>/gi)){
        const db=m[1];result.proxyRules.push({domain:xv(db,'domain')||'-',target:xv(db,'ip')||'-'});
      }
    });
    return result;
  }


  // ── SNMP ────────────────────────────────────────────────────────────────────
  function parseSnmp(xml) {
    const result={enabled:false,agent:{name:'-',description:'-',location:'-',contact:'-',version:[]},communities:[],v3users:[],trapServers:[]};
    const snmpBlks=[...xblks(xml,'snmpd'),...xblks(xml,'snmp')];
    if(!snmpBlks.length) return result;
    const t=snmpBlks[0]._inner;
    result.enabled=xv(t,'enable')||t.includes('<enable')!==false;
    result.agent.location=xv(t,'syslocation')||xv(t,'location')||'-';
    result.agent.contact =xv(t,'syscontact') ||xv(t,'contact') ||'-';
    const comm=xv(t,'rocommunity')||xv(t,'community')||'-';
    if(comm!=='-'){ result.communities.push({name:comm,permission:'ro',allowedHosts:[],events:'-',status:'enable'}); result.agent.version.push('v2c'); }
    const rwComm=xv(t,'rwcommunity');
    if(rwComm) result.communities.push({name:rwComm,permission:'rw',allowedHosts:[],events:'-',status:'enable'});
    const trapSrv=xv(t,'trapserver')||xv(t,'traphost');
    if(trapSrv) result.trapServers.push({ip:trapSrv,port:xv(t,'trapserverport')||'162',community:xv(t,'trapcommunity')||comm,version:'v2c'});
    return result;
  }

  // ── Log Servers ──────────────────────────────────────────────────────────────
  function parseLogServers(xml) {
    const result={syslog:[],fortianalyzer:[],netflow:[],logForward:[]};
    xblks(xml,'syslog').forEach(blk=>{
      const t=blk._inner;
      if(!t.includes('<enable')) return;
      ['remoteserver','remoteserver2','remoteserver3'].forEach((key,i)=>{
        const srv=xv(t,key)||xv(t,'server');
        if(!srv||srv==='-') return;
        result.syslog.push({name:`Syslog${i+1}`,server:srv,port:xv(t,'remoteport')||xv(t,'port')||'514',facility:xv(t,'facility')||'local7',format:'BSD',protocol:'UDP',level:xv(t,'severity')||'notice',status:'enable'});
      });
    });
    return result;
  }

  function parseSdwan(xml) {
    const result = { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] };

    // Gateway items = WAN members
    const gwItems = xblks(xml, 'gateway_item') || [];
    gwItems.forEach((gw, idx) => {
      const t = gw._inner;
      const name    = xv(t,'name')       || `GW${idx+1}`;
      const iface   = xv(t,'interface')  || '-';
      const gateway = xv(t,'gateway')    || '-';
      const monitor = xv(t,'monitor')    || gateway;
      const weight  = parseInt(xv(t,'weight') || '1');
      const isDef   = hasTag(t,'defaultgw') || xv(t,'defaultgw') === 'true';
      if (!iface || iface === '-') return;
      result.enabled = true;
      result.members.push({
        id: String(idx+1), iface, zone: xv(t,'descr') || iface,
        gateway, gateway6: '-',
        priority: isDef ? 1 : idx+2,
        weight, cost: 0, spillover: 0, volumeRatio: weight,
        status: hasTag(t,'disabled') ? 'disable' : 'enable',
        comment: xv(t,'descr') || '',
      });
      // Each gateway has a monitor (dpinger probe)
      result.healthChecks.push({
        name: `${name}_probe`,
        server: monitor !== '-' ? monitor : '8.8.8.8',
        protocol: 'ping', port: '-',
        interval:     xv(t,'interval')          || '500',
        timeout:      xv(t,'time_period')        || '2000',
        failtime:     xv(t,'loss_interval')      || '2000',
        recoverytime: '750',
        probePackets: xv(t,'probe_count')        || '3',
        http200Only: 'disable',
        members: String(idx+1),
        slaThresholds: [{
          id: '1',
          latency:    xv(t,'latencylow')    || '200',
          jitter:     xv(t,'jitterlow')     || '100',
          packetLoss: xv(t,'losslow')       || '10',
        }],
      });
    });

    // Gateway groups = SD-WAN rules / failover tiers
    const gwGroups = xblks(xml, 'gateway_group') || [];
    gwGroups.forEach((gg, idx) => {
      const t = gg._inner;
      const name    = xv(t, 'name')    || `GW_Group${idx+1}`;
      const trigger = xv(t, 'trigger') || xv(t,'triggerdown') || 'member_down';
      // Items with tier info
      const items = xblks(t, 'item') || [];
      const tiered = items.map(it => {
        const inner = it._inner;
        return { gw: xv(inner,'gateway')||'-', tier: parseInt(xv(inner,'tier')||'1'), pri: parseInt(xv(inner,'priority')||'0') };
      }).sort((a,b)=>a.tier-b.tier);
      const isLB = tiered.length > 1 && tiered.every(t2=>t2.tier===tiered[0].tier);
      const mode = isLB ? 'load-balance' : 'priority';
      result.lbMode = mode;
      result.services.push({
        id: String(idx+1), name,
        mode,
        src: 'all', dst: 'all', srcNegate: 'disable', dstNegate: 'disable', users: '-',
        protocol: '0', startPort: '-', endPort: '-',
        priorityMembers: tiered.map(t2=>t2.gw).join(', '),
        priorityZone: '-',
        preferredUplink: tiered[0]?.gw || '-',
        slaCompare: 'order', tie: 'zone',
        slaRefs: [],
        inputDevice: '-',
        status: 'enable',
        comment: `Trigger: ${trigger} | Tiers: ${[...new Set(tiered.map(t2=>t2.tier))].join(',')}`,
      });
    });

    if (!result.enabled && result.services.length > 0) result.enabled = true;
    return result;
  }

  return { parse };
})();


