// ══════════════════════════════════════════════════════════
//  VYOS PARSER（2026-10-02 新增，第十輪發想 ZA）
// ══════════════════════════════════════════════════════════
// VyOS 與 EdgeOS 同為 Vyatta 語系，config.boot 都是換行斷句的大括號樹，共用 EdgeRouterParser._lib 的
// 樹狀解析與查詢函式。語法依 vyos/vyos-1x 原始碼內官方 smoketest（configs/*.boot 真實設定檔與
// scripts/cli/test_firewall.py、test_nat.py、test_vpn_ipsec.py、test_high-availability_vrrp.py 的 set 指令）確認：
// - 1.3（equuleus）：firewall name X／ipv6-name X 具名規則集，由 interfaces <型別> <名稱> firewall {in|out|local} name X
//   綁定；state { established enable }；NAT 為 nat source|destination rule N（inbound/outbound-interface 單值）
// - 1.4 起（sagitta）：firewall ipv4|ipv6 {forward|input|output} filter 基本鏈＋firewall ipv4|ipv6 name X 自訂鏈，
//   以 action jump／jump-target 從基本鏈跳入；規則內 inbound-interface／outbound-interface { name X | group X }；
//   state 改為葉節點（state established）；NAT 的介面改為 outbound-interface { name eth0 }
// - 兩版共通：firewall group（address-group／network-group／port-group 與 ipv6- 版本）、protocols static route、
//   system login user、vpn ipsec site-to-site peer、high-availability vrrp group
// 也接受 `show configuration commands` 的 set 指令格式（值以單引號包住），先轉回大括號樹再解析。
// 未涵蓋：1.3 zone-policy／1.4 firewall zone、DHCP／DNS／SNMP、規則集 default-action（比照 EdgeRouter 不列成規則）
const VyOSParser = (() => {
  const L = EdgeRouterParser._lib;
  const { child, val, vals, hasFlag, childrenPrefixed, cidrSplit, unquote } = L;

  // ── set 指令格式 → 大括號樹 ───────────────────────────────
  // 標籤節點（後面接名稱）合成一個節點；最後一個詞帶引號是值，不帶引號則為無值旗標（log、disable…）。
  // 標籤名稱在指令輸出中不加引號，所以「關鍵字＋最後一個帶引號的詞」一律是值（如 inbound-interface name 'eth0'、
  // vrrp 的 interface 'eth1'）；group 只有在 vrrp 底下是標籤，firewall group／source group 是容器
  const VYOS_TAG = new Set(['rule', 'name', 'ipv6-name', 'address-group', 'network-group', 'port-group', 'interface-group', 'domain-group',
    'mac-group', 'ipv6-address-group', 'ipv6-network-group', 'ethernet', 'vif', 'vif-s', 'vif-c', 'bonding', 'bridge', 'dummy', 'loopback',
    'pppoe', 'wireguard', 'vti', 'tunnel', 'openvpn', 'wireless', 'user', 'route', 'route6', 'next-hop', 'interface', 'shared-network-name',
    'subnet', 'static-mapping', 'peer', 'neighbor', 'area', 'server', 'community', 'host', 'ike-group', 'esp-group', 'proposal', 'zone',
    'from', 'route-map', 'prefix-list', 'access-list', 'psk', 'ca', 'certificate', 'virtual-server', 'table', 'instance']);
  const VYOS_SET_TOP = /^set\s+(?:firewall|interfaces|nat|system|protocols|service|vpn|policy|high-availability|container|pki|qos|vrf|load-balancing)\s/;
  function isSetFormat(text) {
    if (/\{/.test(text)) return false;
    const lines = String(text).match(/^set\s+\S.*$/gm) || [];
    return lines.filter(l => VYOS_SET_TOP.test(l)).length >= 3;
  }
  function setToCurly(text) {
    const root = { vals: [], kids: new Map() };
    for (const raw of String(text).split('\n')) {
      if (!/^set\s/.test(raw.trim())) continue;
      const t = (raw.trim().match(/'[^']*'|"[^"]*"|\S+/g) || []).slice(1);
      let node = root;
      for (let i = 0; i < t.length; i++) {
        const last = i === t.length - 1;
        if (last) { node.vals.push(t[i]); break; }
        if (i === t.length - 2 && /^['"]/.test(t[i + 1])) { node.vals.push(t[i] + ' ' + t[i + 1]); break; }
        let key = t[i];
        if (VYOS_TAG.has(key) || (key === 'group' && t[i - 1] === 'vrrp')) key += ' ' + unquote(t[++i]);
        if (!node.kids.has(key)) node.kids.set(key, { vals: [], kids: new Map() });
        node = node.kids.get(key);
        if (i === t.length - 1) break;
      }
    }
    const out = [];
    const emit = (n, d) => {
      const pad = '    '.repeat(d);
      n.vals.forEach(v => out.push(pad + v));
      for (const [k, c] of n.kids) { out.push(`${pad}${k} {`); emit(c, d + 1); out.push(`${pad}}`); }
    };
    emit(root, 0);
    return out.join('\n') + '\n';
  }

  function parseDeviceInfo(tree, text) {
    const sys = child(tree, 'system');
    const fw = (text.match(/^\/\/ Release version:\s*(\S+)/m) || text.match(/\bVyOS\s+(\d[\w.\-]*)/) || [])[1] || '-';
    return { vendor: 'VyOS', hostname: val(sys, 'host-name') || '-', firmware: fw, model: '-', serial: '-', vdom: [] };
  }

  // ── 介面 ───────────────────────────────────────────────────
  const IF_TYPES = ['ethernet', 'bonding', 'bridge', 'dummy', 'loopback', 'pppoe', 'wireguard', 'vti', 'tunnel', 'openvpn'];
  function ifFirewallNames(node) {
    const fw = child(node, 'firewall');
    return fw ? ['in', 'out', 'local'].map(d => val(child(fw, d), 'name')).filter(Boolean) : [];
  }
  function inferRole(text) {
    const s = text.toUpperCase();
    if (/WAN|PPPOE|INTERNET|UPLINK/.test(s)) return 'WAN';
    if (/DMZ/.test(s)) return 'DMZ';
    return 'LAN';
  }
  function ifRow(name, node, type, vlanId) {
    const addrs = vals(node, 'address').filter(a => a.includes('/'));
    const v4 = addrs.filter(a => !a.includes(':')), v6 = addrs.filter(a => a.includes(':'));
    const [ip, mask] = v4[0] ? cidrSplit(v4[0]) : ['-', '-'];
    const desc = val(node, 'description') || '';
    return {
      name, ip, mask, ip6: v6[0] || '-', secondaryIps: v4.slice(1).map(a => { const [i, m] = cidrSplit(a); return { ip: i, mask: m }; }),
      type: type === 'loopback' || type === 'dummy' ? 'loopback' : type === 'ethernet' ? 'physical' : type === 'bonding' ? 'aggregate' : type === 'pppoe' ? 'pppoe' : type === 'bridge' ? 'bridge' : 'tunnel',
      vlanId: vlanId || '-', alias: name, desc, status: hasFlag(node, 'disable') ? 'down' : 'up',
      mtu: val(node, 'mtu') || '-', speed: val(node, 'speed') || '-', mode: vals(node, 'address').includes('dhcp') ? 'dhcp' : addrs.length ? 'static' : '-',
      vdom: '-', role: inferRole(`${type} ${name} ${desc} ${ifFirewallNames(node).join(' ')}`), allowaccess: '-',
    };
  }
  function parseInterfaces(tree) {
    const out = [];
    const ifs = child(tree, 'interfaces');
    IF_TYPES.forEach(type => {
      Object.entries(childrenPrefixed(ifs, type)).forEach(([key, node]) => {
        const name = key.slice(type.length).trim();
        if (!name) return;
        out.push(ifRow(name, node, type));
        Object.entries(childrenPrefixed(node, 'vif')).forEach(([vk, vn]) => {
          const id = vk.replace(/^vif\s+/, '');
          out.push(ifRow(`${name}.${id}`, vn, type, id));
        });
      });
    });
    return out;
  }

  // ── 規則集綁定：1.3 介面 firewall in/out/local；1.4 基本鏈的 jump 規則 ─────────
  function buildBinding(tree, chains) {
    const bind = {};
    const add = (rs, intf) => { (bind[rs] = bind[rs] || []); if (!bind[rs].includes(intf)) bind[rs].push(intf); };
    const ifs = child(tree, 'interfaces');
    IF_TYPES.forEach(type => {
      Object.entries(childrenPrefixed(ifs, type)).forEach(([key, node]) => {
        const name = key.slice(type.length).trim();
        ifFirewallNames(node).forEach(rs => add(rs, name));
        Object.entries(childrenPrefixed(node, 'vif')).forEach(([vk, vn]) => ifFirewallNames(vn).forEach(rs => add(rs, `${name}.${vk.replace(/^vif\s+/, '')}`)));
      });
    });
    chains.filter(c => c.base).forEach(c => c.rules.forEach(([, r]) => {
      if (val(r, 'action') !== 'jump' || !val(r, 'jump-target')) return;
      add(val(r, 'jump-target'), ifRef(r, 'inbound-interface') || 'any');
    }));
    return bind;
  }
  // 1.4 介面條件 inbound-interface { name X | group X }；1.3 NAT 為單值 inbound-interface X
  function ifRef(node, key) {
    const c = child(node, key);
    if (c) return val(c, 'name') || (val(c, 'group') ? '@' + val(c, 'group') : '');
    return val(node, key);
  }

  // 所有規則鏈：1.3 name／ipv6-name；1.4 ipv4|ipv6 下的 forward／input／output filter 與 name
  function collectChains(tree) {
    const fw = child(tree, 'firewall');
    const chains = [];
    const rulesOf = n => Object.entries(childrenPrefixed(n, 'rule'));
    Object.entries(childrenPrefixed(fw, 'name')).forEach(([k, n]) => chains.push({ name: k.replace(/^name\s+/, ''), fam: 4, base: false, rules: rulesOf(n) }));
    Object.entries(childrenPrefixed(fw, 'ipv6-name')).forEach(([k, n]) => chains.push({ name: k.replace(/^ipv6-name\s+/, ''), fam: 6, base: false, rules: rulesOf(n) }));
    [['ipv4', 4], ['ipv6', 6]].forEach(([fk, fam]) => {
      const f = child(fw, fk);
      if (!f) return;
      ['forward', 'input', 'output'].forEach(hook => {
        const flt = child(child(f, hook), 'filter');
        if (flt) chains.push({ name: `${fk}-${hook}`, fam, base: true, hook, rules: rulesOf(flt) });
      });
      Object.entries(childrenPrefixed(f, 'name')).forEach(([k, n]) => chains.push({ name: k.replace(/^name\s+/, ''), fam, base: false, rules: rulesOf(n) }));
    });
    return chains;
  }

  function parsePolicies(tree, addrTypeMap, portGroupMap) {
    const chains = collectChains(tree);
    const bind = buildBinding(tree, chains);
    // 自訂鏈只有一個 jump 來源時，鏈內規則未指定的位址、協定、埠沿用 jump 規則的條件（比照 netfilter 解析器）
    const jumps = {};
    chains.filter(c => c.base).forEach(c => c.rules.forEach(([, r]) => { if (val(r, 'action') === 'jump' && val(r, 'jump-target')) (jumps[val(r, 'jump-target')] = jumps[val(r, 'jump-target')] || []).push(r); }));
    const out = [];
    let idx = 0;
    chains.forEach(c => c.rules.forEach(([rk, r]) => {
      const actionRaw = (val(r, 'action') || 'drop').toLowerCase();
      // jump／return／continue 只是流程控制，跳入的自訂鏈規則另外列出（srcIntf 取自 jump 規則的介面條件）
      if (['jump', 'return', 'continue', 'goto'].includes(actionRaw)) return;
      const num = rk.replace(/^rule\s+/, '');
      const js = jumps[c.name] || [];
      const j = js.length === 1 ? js[0] : null;
      const src = L.parseAddrOrPort(child(r, 'source'), portGroupMap);
      const dst = L.parseAddrOrPort(child(r, 'destination'), portGroupMap);
      if (j) {
        const js_ = L.parseAddrOrPort(child(j, 'source'), portGroupMap), jd = L.parseAddrOrPort(child(j, 'destination'), portGroupMap);
        if (src.addr === 'any') src.addr = js_.addr;
        if (dst.addr === 'any') dst.addr = jd.addr;
        if (!dst.port) dst.port = jd.port;
      }
      const protocol = val(r, 'protocol') || (j && val(j, 'protocol')) || 'all';
      const desc = val(r, 'description') || '';
      const stNode = child(r, 'state');
      const connState = [...new Set([...vals(r, 'state'), ...(stNode ? ['new', 'established', 'related', 'invalid'].filter(k => val(stNode, k) === 'enable') : [])])];
      const srcIntf = ifRef(r, 'inbound-interface') || (bind[c.name] || []).join(',') || (c.hook === 'output' ? 'local' : '-');
      const dstIntf = ifRef(r, 'outbound-interface') || (c.hook === 'input' ? 'local' : '-');
      const sa = _splitAddr(src.addr, addrTypeMap), da = _splitAddr(dst.addr, addrTypeMap);
      idx++;
      out.push({
        id: idx, name: desc || `${c.name}-${num}`,
        srcIntf, dstIntf, srcAddr: src.addr, dstAddr: dst.addr,
        srcAddr4: sa.v4, srcAddr6: sa.v6, dstAddr4: da.v4, dstAddr6: da.v6,
        service: dst.port ? `${protocol}/${dst.port}` : protocol, schedule: 'always',
        action: actionRaw === 'accept' ? 'accept' : 'deny', actionRaw,
        nat: 'disable', ippool: 'disable', poolname: '-',
        logtraffic: hasFlag(r, 'log') || val(r, 'log') === 'enable' ? 'all' : 'disable',
        utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
        status: hasFlag(r, 'disable') ? 'disable' : 'enable',
        users: '-', groups: '-', comments: desc, _vdom: '', connState, chain: c.name, ruleNum: num,
      });
    }));
    return out;
  }

  // ── 物件：位址群組（含 ipv6- 版本，include 的群組名稱一併列入成員）與埠群組 ─────
  function parseAddressObjects(tree) {
    const grp = child(child(tree, 'firewall'), 'group');
    const out = [];
    [['address-group', 'address'], ['network-group', 'network'], ['ipv6-address-group', 'address'], ['ipv6-network-group', 'network'], ['domain-group', 'address']].forEach(([kind, leaf]) => {
      Object.entries(childrenPrefixed(grp, kind)).forEach(([k, n]) => {
        const members = [...vals(n, leaf), ...vals(n, 'include')];
        out.push({ category: 'address-group', name: k.slice(kind.length).trim(), type: kind === 'domain-group' ? 'fqdn-group' : 'group', subnet: '-', fqdn: '-',
          startIp: '-', endIp: '-', wildcard: '-', iface: '-', color: '0', comment: val(n, 'description') || '', members: members.join(', ') || '-', _vdom: '' });
      });
    });
    return out;
  }
  function buildAddrTypeMap(addrs) {
    const map = new Map();
    addrs.forEach(o => {
      const ms = (o.members || '').split(/\s*,\s*/).filter(m => m && m !== '-');
      const fams = new Set(ms.map(m => m.includes(':') ? 'v6' : 'v4'));
      map.set(o.name, fams.size > 1 ? 'mixed' : (fams.values().next().value || 'v4'));
    });
    return map;
  }
  function parseServiceObjects(tree) {
    const grp = child(child(tree, 'firewall'), 'group');
    return Object.entries(childrenPrefixed(grp, 'port-group')).map(([k, n]) => {
      const ports = [...vals(n, 'port'), ...vals(n, 'include')].join(', ') || '-';
      return { category: 'service', name: k.replace(/^port-group\s+/, ''), proto: '-', tcpPorts: ports, udpPorts: ports, icmpType: '-', members: '-', comment: val(n, 'description') || '' };
    });
  }

  // ── 靜態路由（route 與 route6；blackhole 與 interface 型下一跳）──────────────
  function parseRoutes(tree) {
    const st = child(child(tree, 'protocols'), 'static');
    const out = [];
    let seq = 1;
    ['route', 'route6'].forEach(kind => Object.entries(childrenPrefixed(st, kind)).forEach(([k, n]) => {
      const dst = k.slice(kind.length).trim();
      const base = { type: dst === '0.0.0.0/0' || dst === '::/0' ? 'default' : 'static', dst, vrf: 'main', status: hasFlag(n, 'disable') ? 'disable' : 'enable', protocol_detail: '-', _vdom: '' };
      const nhs = Object.entries(childrenPrefixed(n, 'next-hop'));
      const ifs = Object.entries(childrenPrefixed(n, 'interface'));
      nhs.forEach(([nk, nn]) => out.push({ ...base, id: String(seq++), gateway: nk.replace(/^next-hop\s+/, ''), device: val(nn, 'interface') || '-', distance: val(nn, 'distance') || '1', priority: val(nn, 'distance') || '1', blackhole: 'disable', comment: val(n, 'description') || '' }));
      ifs.forEach(([ik, inode]) => out.push({ ...base, id: String(seq++), gateway: '-', device: ik.replace(/^interface\s+/, ''), distance: val(inode, 'distance') || '1', priority: val(inode, 'distance') || '1', blackhole: 'disable', comment: val(n, 'description') || '' }));
      if (child(n, 'blackhole') || hasFlag(n, 'blackhole')) out.push({ ...base, id: String(seq++), gateway: '-', device: '-', distance: val(child(n, 'blackhole'), 'distance') || '1', priority: '1', blackhole: 'enable', comment: val(n, 'description') || '' });
    }));
    return out;
  }

  // ── NAT：nat source／destination rule N（1.3 介面單值、1.4 介面為 { name X }）─────
  function parseNAT(tree) {
    const nat = child(tree, 'nat');
    const out = [];
    ['source', 'destination'].forEach(kind => Object.entries(childrenPrefixed(child(nat, kind), 'rule')).forEach(([k, n]) => {
      const num = k.replace(/^rule\s+/, '');
      const tr = child(n, 'translation'), src = child(n, 'source'), dst = child(n, 'destination');
      const proto = val(n, 'protocol') || '-', status = hasFlag(n, 'disable') ? 'disable' : 'enable', comment = val(n, 'description') || '';
      if (kind === 'destination') {
        out.push({ type: 'vip', name: `DNAT-${num}`, vipType: 'static', poolType: 'destination', extIp: val(dst, 'address') || '-', mapIp: val(tr, 'address') || '-',
          extIntf: ifRef(n, 'inbound-interface') || '-', srcIntf: '-', startIp: '-', endIp: '-',
          portFwd: val(dst, 'port') || val(tr, 'port') ? 'enable' : 'disable', extPort: val(dst, 'port') || '-', mapPort: val(tr, 'port') || '-', proto, status, comment });
      } else {
        const t = val(tr, 'address') || '-';
        out.push({ type: 'ippool', name: `SNAT-${num}`, vipType: 'overload', poolType: t === 'masquerade' ? 'masquerade' : 'source', extIp: val(src, 'address') || '-', mapIp: t,
          extIntf: ifRef(n, 'outbound-interface') || '-', srcIntf: ifRef(n, 'outbound-interface') || '-', startIp: '-', endIp: '-',
          portFwd: 'disable', extPort: '-', mapPort: '-', proto, status, comment });
      }
    }));
    return out;
  }

  // ── IPsec site-to-site：peer（1.3 名稱即對端 IP；1.4 為自訂名稱＋remote-address）────────
  function parseVPN(tree) {
    const ipsec = child(child(tree, 'vpn'), 'ipsec');
    if (!ipsec) return [];
    const ike = {}, esp = {};
    const propStr = g => {
      const p = Object.values(childrenPrefixed(g, 'proposal'))[0];
      return p ? { enc: val(p, 'encryption') || '-', hash: val(p, 'hash') || '-', dh: val(p, 'dh-group') || '-' } : { enc: '-', hash: '-', dh: '-' };
    };
    Object.entries(childrenPrefixed(ipsec, 'ike-group')).forEach(([k, g]) => { ike[k.replace(/^ike-group\s+/, '')] = { ...propStr(g), ver: (val(g, 'key-exchange') || 'ikev1').replace('ikev', ''), life: val(g, 'lifetime') || '28800' }; });
    Object.entries(childrenPrefixed(ipsec, 'esp-group')).forEach(([k, g]) => { esp[k.replace(/^esp-group\s+/, '')] = { ...propStr(g), pfs: val(g, 'pfs') || 'enable', life: val(g, 'lifetime') || '3600' }; });
    return Object.entries(childrenPrefixed(child(ipsec, 'site-to-site'), 'peer')).map(([k, p]) => {
      const name = k.replace(/^peer\s+/, '');
      const ig = ike[val(p, 'ike-group')] || { enc: '-', hash: '-', dh: '-', ver: '1', life: '28800' };
      const mode = val(child(p, 'authentication'), 'mode') || 'pre-shared-secret';
      const phase2 = Object.entries(childrenPrefixed(p, 'tunnel')).map(([tk, t]) => {
        const eg = esp[val(t, 'esp-group') || val(p, 'default-esp-group')] || { enc: '-', hash: '-', dh: '-', pfs: '-', life: '3600' };
        return { name: `${name}-${tk.replace(/^tunnel\s+/, '')}`, phase1: name, proposal: eg.enc !== '-' ? `${eg.enc}-${eg.hash}` : '-',
          pfs: eg.pfs === 'disable' ? 'disable' : 'enable', dhgrp: eg.dh, lifetime: eg.life, replay: 'enable',
          localSub: vals(child(t, 'local'), 'prefix').join(', ') || '-', remoteSub: vals(child(t, 'remote'), 'prefix').join(', ') || '-', autoNeg: '-', comment: '-' };
      });
      return { type: 'ipsec-p1', name, mode: 'tunnel', remote: val(p, 'remote-address') || (/^[\d.:a-f]+$/i.test(name) ? name : '-'),
        iface: val(p, 'local-address') || val(p, 'dhcp-interface') || '-', ikeVer: ig.ver, authMethod: /rsa|x509/.test(mode) ? 'certificate' : 'psk', peertype: '-',
        proposal: ig.enc !== '-' ? `${ig.enc}-${ig.hash}` : '-', dhgrp: ig.dh, lifetime: ig.life, natTraversal: 'enable', dpd: child(child(ipsec, 'ike-group ' + val(p, 'ike-group')), 'dead-peer-detection') ? 'enable' : '-', dpdInterval: '-',
        localId: val(child(p, 'authentication'), 'local-id') || '-', peerId: val(child(p, 'authentication'), 'remote-id') || '-', xauthType: '-', cert: '-', monitorConn: '-', autoNeg: '-',
        status: hasFlag(p, 'disable') ? 'disable' : 'enable', phase2, _vdom: '' };
    });
  }

  // ── VRRP（high-availability vrrp group，取第一個群組）─────────────
  function parseHa(tree) {
    const groups = Object.entries(childrenPrefixed(child(child(tree, 'high-availability'), 'vrrp'), 'group'));
    if (!groups.length) return null;
    const [, g] = groups[0];
    return { enabled: true, mode: 'vrrp', groupId: val(g, 'vrid') || '-', priority: val(g, 'priority') || '100', peerIp: val(g, 'peer-address') || '-',
      syncInterface: val(g, 'interface') || '-', vip: vals(g, 'address').concat(vals(g, 'virtual-address')).join(', ') || '-' };
  }

  function detect(text) {
    return /vyos-config-version|\bVyOS\b/.test(text) || /^set firewall ipv[46] (?:forward|input|output|name) /m.test(text) ||
      (/^firewall\s*\{/m.test(text) && /^\s+ipv[46]\s*\{\s*\n\s+(?:forward|input|output|name)\b/m.test(text));
  }

  function parse(text) {
    text = String(text || '').replace(/^\uFEFF/, '');
    const orig = text;
    if (isSetFormat(text)) text = setToCurly(text);
    const tree = L.parseTree(text.replace(/^\s*\/\/.*$/gm, ''));
    const addresses = parseAddressObjects(tree);
    const services = parseServiceObjects(tree);
    const portGroupMap = {};
    services.forEach(s => { portGroupMap[s.name] = s.tcpPorts; });
    return {
      vendor: 'VyOS',
      deviceInfo: parseDeviceInfo(tree, orig),
      interfaces: parseInterfaces(tree),
      policies: parsePolicies(tree, buildAddrTypeMap(addresses), portGroupMap),
      routes: parseRoutes(tree),
      ha: parseHa(tree), nat: parseNAT(tree), vpn: parseVPN(tree),
      addresses, services, users: L.parseUsers(tree), schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      // 比照 EdgeRouter：onParsed() 對這些欄位只做 truthy 判斷，未解析一律給 null
      dhcp: null, dns: null, snmp: null, logservers: null, wwan: null, wlan: null,
    };
  }

  return { parse, detect, _setToCurly: setToCurly, _isSetFormat: isSetFormat };
})();
