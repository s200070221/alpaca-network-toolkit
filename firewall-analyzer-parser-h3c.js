// ══════════════════════════════════════════════════════════
//  H3C SecPath（Comware V7 防火牆）PARSER
// ══════════════════════════════════════════════════════════
// 2026-10-05（第十一輪 KB）新增。h3c.com 被網路政策擋下無法直接讀取，語法依 H3C 官方
// Security Policy／Security Zone／Object Group／NAT／IPsec 命令參考與設定範例的搜尋索引摘要
// 交叉確認（信心度中等，無真實裝置匯出檔比對）：
//   security-zone name Trust ＋ 子行 import interface GigabitEthernet1/0/2
//   security-policy {ip|ipv6} ＋ rule <id> name <名稱> ＋ 規則子行：action {pass|drop}（預設 drop）、
//     source-zone／destination-zone、source-ip-host／-subnet／-range（destination 同）、
//     source-ip／destination-ip <位址物件群組>、service <服務物件群組>、
//     service-port <協定> [destination {eq|lt|gt N | range A B}]、description、disable、logging enable
//   object-group ip address <名稱> ＋ [序號] network {host address A | subnet A {M|長度} | range A B | group-object G}
//   object-group service <名稱> ＋ [序號] service <協定> [source …] [destination {eq|lt|gt N | range A B}]
//   介面視圖 nat server protocol <協定> global <位址> [埠] inside <位址> [埠]、
//     nat outbound [ACL] [address-group N] [no-pat]；nat address-group N ＋ address A B
//   ipsec policy <名稱> <序號> isakmp ＋ remote-address／security acl／ike-profile；介面 ipsec apply policy <名稱>
//   ip route-static <目的> {長度|遮罩} [介面] <下一跳> [preference N]；sysname；local-user
// 設定檔的層級以行首空格表示（頂層 0 格、子視圖 1 格、規則內容 2 格），# 為分隔行（之後回到頂層）。
// 未涵蓋：Comware 5 舊版 SecPath（firewall zone／interzone policy）、nat static、nat global-policy、
// IPsec 轉換集與 IKE 提議細節、應用層與使用者條件、預先定義服務名稱（如 http）的埠號展開。
const H3CSecPathParser = (() => {
  const V4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

  // 依縮排切成樹：每個節點 {text, kids}
  function buildTree(text) {
    const root = { text: '', kids: [] };
    const stack = [{ depth: -1, node: root }];
    for (const raw of text.split('\n')) {
      // # 分隔行代表回到頂層：全域指令在顯示輸出中也縮排一格（如 " sysname X"、" ip route-static …"）
      if (/^\s*#\s*$/.test(raw)) { stack.length = 1; continue; }
      if (!raw.trim() || /^\s*return\s*$/.test(raw)) continue;
      const depth = raw.match(/^ */)[0].length;
      const node = { text: raw.trim(), kids: [] };
      while (stack.length > 1 && stack[stack.length - 1].depth >= depth) stack.pop();
      stack[stack.length - 1].node.kids.push(node);
      stack.push({ depth, node });
    }
    return root;
  }
  const tops = (tree, re) => tree.kids.filter(k => re.test(k.text));

  function maskToLen(m) {
    if (/^\d{1,3}$/.test(m)) return m;
    if (!V4.test(m)) return null;
    return String(m.split('.').reduce((n, o) => n + ((parseInt(o, 10) >>> 0).toString(2).match(/1/g) || []).length, 0));
  }
  function lenToMask(len) {
    const n = parseInt(len, 10);
    if (!(n >= 0 && n <= 32)) return '-';
    const v = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0;
    return [24, 16, 8, 0].map(s => (v >>> s) & 255).join('.');
  }
  // 埠號條件 → "80"、"30-40"；無條件回傳 ''
  function portCond(op, a, b) {
    if (op === 'eq') return a;
    if (op === 'range') return `${a}-${b}`;
    if (op === 'lt') return `0-${Math.max(0, parseInt(a, 10) - 1)}`;
    if (op === 'gt') return `${parseInt(a, 10) + 1}-65535`;
    return '';
  }
  // "tcp destination eq 80" 之類 → 'tcp/80'、'icmp'、'tcp/0-65535'
  function svcLiteral(s) {
    const t = s.trim().split(/\s+/);
    const proto = (t[0] || '').toLowerCase();
    if (!proto) return '';
    if (proto !== 'tcp' && proto !== 'udp') return proto === 'icmp' || proto === 'icmpv6' ? proto : (/^\d+$/.test(proto) ? `proto-${proto}` : proto);
    const di = t.indexOf('destination');
    const port = di >= 0 ? portCond(t[di + 1], t[di + 2], t[di + 3]) : '';
    return `${proto}/${port || '0-65535'}`;
  }

  function parseDeviceInfo(text) {
    const hostname = (text.match(/^\s*sysname\s+(\S+)/m) || [])[1] || '-';
    const ver = text.match(/^\s*version\s+(\d+[\d.]*,\s*(?:Release|ESS)\s+\S+)/m);
    return { vendor: 'H3C SecPath', hostname, firmware: ver ? ver[1] : '-', model: '-', serial: '-', vdom: [] };
  }

  function zoneMap(tree) {
    const map = {};
    tops(tree, /^security-zone\s+name\s+\S+/).forEach(z => {
      const zn = z.text.split(/\s+/)[2];
      z.kids.forEach(k => {
        const m = k.text.match(/^import\s+interface\s+(\S+)/);
        if (m) map[m[1]] = zn;
      });
    });
    return map;
  }

  function parseInterfaces(tree, zones) {
    return tops(tree, /^interface\s+\S+/).map(n => {
      const name = n.text.split(/\s+/)[1];
      const lines = n.kids.map(k => k.text);
      const ips = lines.map(l => l.match(/^ip address\s+(\S+)\s+(\S+)(\s+sub)?/)).filter(Boolean);
      const pri = ips.find(m => !m[3]);
      const sec = ips.filter(m => m[3]);
      const desc = (lines.find(l => /^description\s/.test(l)) || '').replace(/^description\s+/, '');
      const zone = zones[name] || '-';
      const z = zone.toLowerCase();
      const vlan = (name.match(/^Vlan-interface(\d+)$/i) || [])[1] || (name.match(/\.(\d+)$/) || [])[1] || '-';
      return {
        name, ip: pri ? pri[1] : '-', mask: pri ? (V4.test(pri[2]) ? pri[2] : lenToMask(pri[2])) : '-',
        secondaryIps: sec.map(m => ({ ip: m[1], mask: V4.test(m[2]) ? m[2] : lenToMask(m[2]) })),
        type: /^Vlan-interface/i.test(name) ? 'vlan' : /^LoopBack/i.test(name) ? 'loopback' : /^(?:Route-Aggregation|Bridge-Aggregation)/i.test(name) ? 'aggregate' : 'physical',
        vlanId: vlan, alias: name, desc,
        status: lines.includes('shutdown') ? 'down' : 'up',
        mtu: (lines.map(l => l.match(/^mtu\s+(\d+)/)).find(Boolean) || [])[1] || '-',
        speed: '-', mode: pri ? 'static' : lines.some(l => /^ip address dhcp-alloc/.test(l)) ? 'dhcp' : '-',
        vdom: '-', role: z === 'untrust' ? 'WAN' : z === 'dmz' ? 'DMZ' : z === 'management' ? 'MGMT' : 'LAN',
        allowaccess: '-', _zone: zone,
      };
    });
  }

  // object-group ip address／ipv6 address：成員為字面位址（查詢引擎找不到同名物件時當字面值比對）
  function parseAddressObjects(tree) {
    const out = [];
    tops(tree, /^object-group\s+ipv?6?\s+address\s+\S+/).forEach(n => {
      const v6 = /^object-group\s+ipv6/.test(n.text);
      const name = n.text.split(/\s+/)[3];
      const desc = (n.kids.map(k => k.text).find(l => /^description\s/.test(l)) || '').replace(/^description\s+/, '');
      const mems = [];
      n.kids.forEach(k => {
        const l = k.text.replace(/^\d+\s+/, '');
        let m;
        if ((m = l.match(/^network\s+host\s+address\s+(\S+)/))) mems.push(m[1]);
        else if ((m = l.match(/^network\s+subnet\s+(\S+)\s+(\S+)/))) { const len = maskToLen(m[2]); mems.push(len ? `${m[1]}/${len}` : m[1]); }
        else if ((m = l.match(/^network\s+range\s+(\S+)\s+(\S+)/))) mems.push(`${m[1]}-${m[2]}`);
        else if ((m = l.match(/^network\s+group-object\s+(\S+)/))) mems.push(m[1]);
      });
      out.push({
        category: v6 ? 'address-group6' : 'address-group', name, type: 'group',
        subnet: '-', fqdn: '-', startIp: '-', endIp: '-', iface: '-',
        members: mems.join(', ') || '-', comment: desc,
      });
    });
    return out;
  }

  function parseServiceObjects(tree) {
    return tops(tree, /^object-group\s+service\s+\S+/).map(n => {
      const name = n.text.split(/\s+/)[2];
      const desc = (n.kids.map(k => k.text).find(l => /^description\s/.test(l)) || '').replace(/^description\s+/, '');
      const mems = [];
      n.kids.forEach(k => {
        const l = k.text.replace(/^\d+\s+/, '');
        let m;
        if ((m = l.match(/^service\s+group-object\s+(\S+)/))) mems.push(m[1]);
        else if ((m = l.match(/^service\s+(.+)/))) { const s = svcLiteral(m[1]); if (s) mems.push(s); }
      });
      return { category: 'group', name, proto: 'GROUP', tcpPorts: '-', udpPorts: '-', icmpType: '-', members: mems.join(', ') || '-', comment: desc };
    });
  }

  function parsePolicies(tree, addrTypeMap) {
    const out = [];
    tops(tree, /^security-policy\s+ipv?6?\s*$/).forEach(sp => {
      const v6 = /ipv6/.test(sp.text);
      sp.kids.forEach(r => {
        const h = r.text.match(/^rule\s+(?:(\d+)\s*)?(?:name\s+(\S+))?/);
        if (!h || (!h[1] && !h[2])) return;
        const lines = r.kids.map(k => k.text);
        const pick = re => lines.map(l => l.match(re)).filter(Boolean);
        const addrs = dir => {
          const a = [];
          pick(new RegExp(`^${dir}-ip-host\\s+(\\S+)`)).forEach(m => a.push(m[1]));
          pick(new RegExp(`^${dir}-ip-subnet\\s+(\\S+)\\s+(\\S+)`)).forEach(m => { const len = maskToLen(m[2]); a.push(len ? `${m[1]}/${len}` : m[1]); });
          pick(new RegExp(`^${dir}-ip-range\\s+(\\S+)\\s+(\\S+)`)).forEach(m => a.push(`${m[1]}-${m[2]}`));
          pick(new RegExp(`^${dir}-ip\\s+(\\S+)`)).forEach(m => a.push(m[1]));
          return a.join(', ') || 'any';
        };
        const zones = dir => pick(new RegExp(`^${dir}-zone\\s+(\\S+)`)).map(m => m[1]).join(', ') || 'any';
        const svcs = [];
        pick(/^service\s+(\S+)/).forEach(m => svcs.push(m[1]));
        pick(/^service-port\s+(.+)/).forEach(m => { const s = svcLiteral(m[1]); if (s) svcs.push(s); });
        const actionRaw = (pick(/^action\s+(\S+)/)[0] || [])[1] || 'drop';
        const srcAddr = addrs('source'), dstAddr = addrs('destination');
        const sSplit = _splitAddr(srcAddr, addrTypeMap), dSplit = _splitAddr(dstAddr, addrTypeMap);
        const id = h[1] !== undefined ? h[1] : String(out.length);
        out.push({
          id: v6 ? `v6/${id}` : (parseInt(id, 10) || 0), name: h[2] || `Rule-${id}`,
          srcIntf: zones('source'), dstIntf: zones('destination'), srcAddr, dstAddr,
          srcAddr4: v6 ? '-' : sSplit.v4, srcAddr6: v6 ? srcAddr : sSplit.v6,
          dstAddr4: v6 ? '-' : dSplit.v4, dstAddr6: v6 ? dstAddr : dSplit.v6,
          service: svcs.join(', ') || 'any', schedule: (pick(/^time-range\s+(\S+)/)[0] || [])[1] || 'always',
          action: /^pass$/i.test(actionRaw) ? 'accept' : 'deny', actionRaw: actionRaw.toLowerCase(),
          nat: 'disable', ippool: 'disable', poolname: '-',
          logtraffic: lines.some(l => /^logging\s+enable/.test(l)) ? 'all' : 'disable',
          utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
          status: lines.includes('disable') ? 'disable' : 'enable',
          users: '-', groups: '-', comments: (pick(/^description\s+(.+)/)[0] || [])[1] || '',
          _vdom: '', _family: v6 ? 'v6' : 'v4',
        });
      });
    });
    return out;
  }

  function parseNAT(tree, ifaces) {
    const out = [];
    const groups = {};
    tops(tree, /^nat\s+address-group\s+\S+/).forEach(g => {
      const id = g.text.split(/\s+/)[2];
      groups[id] = g.kids.map(k => k.text.match(/^address\s+(\S+)\s+(\S+)/)).filter(Boolean).map(m => m[1] === m[2] ? m[1] : `${m[1]}-${m[2]}`).join(', ') || '-';
    });
    let seq = 1;
    tops(tree, /^interface\s+\S+/).forEach(n => {
      const name = n.text.split(/\s+/)[1];
      const ifIp = (ifaces.find(i => i.name === name) || {}).ip || '-';
      n.kids.forEach(k => {
        const l = k.text;
        let m;
        if ((m = l.match(/^nat\s+server\s+(?:protocol\s+(\S+)\s+)?global\s+(current-interface|interface\s+\S+|\S+)(?:\s+(?!inside\b)(\S+))?\s+inside\s+(\S+)(?:\s+(?!vpn-instance\b|acl\b|rule\b|disable\b|description\b|counting\b|reversible\b)(\S+))?/))) {
          const ext = /^(?:current-)?interface/.test(m[2]) ? ifIp : m[2];
          out.push({ type: 'vip', name: `NAT-SERVER-${seq++}`, vipType: 'static', poolType: 'destination', extIp: ext, mapIp: m[4],
            extIntf: name, srcIntf: '-', startIp: '-', endIp: '-',
            portFwd: m[3] ? 'enable' : 'disable', extPort: m[3] || '-', mapPort: m[5] || m[3] || '-',
            proto: m[1] || 'any', status: /\sdisable\b/.test(l) ? 'disable' : 'enable', comment: '' });
        } else if ((m = l.match(/^nat\s+outbound(?:\s+(?:name\s+)?(?!address-group\b|no-pat\b)(\S+))?(?:\s+address-group\s+(?:name\s+)?(\S+))?/))) {
          const pool = m[2] ? (groups[m[2]] || m[2]) : ifIp;
          out.push({ type: 'ippool', name: `NAT-OUTBOUND-${seq++}`, vipType: /\bno-pat\b/.test(l) ? 'one-to-one' : 'overload',
            poolType: m[2] ? 'source' : 'masquerade', extIp: m[1] ? `ACL ${m[1]}` : 'any', mapIp: pool,
            extIntf: name, srcIntf: name, startIp: '-', endIp: '-', portFwd: 'disable', extPort: '-', mapPort: '-',
            proto: 'any', status: /\sdisable\b/.test(l) ? 'disable' : 'enable', comment: '' });
        }
      });
    });
    return out;
  }

  function parseVPN(tree) {
    const applied = {};
    tops(tree, /^interface\s+\S+/).forEach(n => n.kids.forEach(k => {
      const m = k.text.match(/^ipsec\s+apply\s+policy\s+(\S+)/);
      if (m) applied[m[1]] = n.text.split(/\s+/)[1];
    }));
    return tops(tree, /^ipsec\s+policy\s+\S+\s+\d+\s+isakmp/).map(n => {
      const [, , pname, seq] = n.text.split(/\s+/);
      const val = re => (n.kids.map(k => k.text.match(re)).find(Boolean) || [])[1];
      const acl = val(/^security\s+acl\s+(?:name\s+)?(\S+)/);
      return { type: 'ipsec-p1', name: `${pname}-${seq}`, mode: 'tunnel', remote: val(/^remote-address\s+(\S+)/) || '-',
        iface: applied[pname] || '-', ikeVer: '-', authMethod: '-', peertype: '-', proposal: '-', dhgrp: '-', lifetime: '-',
        natTraversal: '-', dpd: '-', dpdInterval: '-', localId: '-', peerId: val(/^ike-profile\s+(\S+)/) ? `ike-profile ${val(/^ike-profile\s+(\S+)/)}` : '-',
        xauthType: '-', cert: '-', monitorConn: '-', autoNeg: '-', status: 'enable',
        phase2: [{ name: `${pname}-${seq}`, phase1: `${pname}-${seq}`, proposal: val(/^transform-set\s+(\S+)/) || '-', pfs: '-', dhgrp: '-', lifetime: '-', replay: '-',
          localSub: acl ? `ACL ${acl}` : '-', remoteSub: '-', autoNeg: '-', comment: '-' }],
        _vdom: '' };
    });
  }

  function parseRoutes(text) {
    const out = [];
    let seq = 1;
    const re = /^\s*ip route-static\s+(?:vpn-instance\s+(\S+)\s+)?(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s+(.+)$/gm;
    let m;
    while ((m = re.exec(text)) !== null) {
      const len = maskToLen(m[3]);
      const t = m[4].trim().split(/\s+/);
      let device = '-', gateway = '-';
      if (V4.test(t[0])) gateway = t[0];
      else if (t[0] === 'vpn-instance') gateway = t[2] || '-';
      else { device = t[0]; if (t[1] && V4.test(t[1])) gateway = t[1]; }
      const pref = (m[4].match(/\bpreference\s+(\d+)/) || [])[1] || '60';
      const dst = `${m[2]}/${len === null ? m[3] : len}`;
      out.push({ type: dst === '0.0.0.0/0' ? 'default' : 'static', id: String(seq++), dst, gateway, device,
        distance: pref, priority: pref, blackhole: device === 'NULL0' ? 'enable' : 'disable', vrf: m[1] || 'main', status: 'enable',
        comment: (m[4].match(/\bdescription\s+(.+)$/) || [])[1] || '', protocol_detail: '-', _vdom: '' });
    }
    return out;
  }

  function parseUsers(tree) {
    return tops(tree, /^local-user\s+\S+/).map(n => {
      const name = n.text.split(/\s+/)[1];
      const roles = n.kids.map(k => k.text.match(/^authorization-attribute\s+user-role\s+(\S+)/)).filter(Boolean).map(m => m[1]);
      const manage = /\bclass\s+manage\b/.test(n.text) || !/\bclass\s+network\b/.test(n.text);
      return { name, role: roles.join(', ') || '-', type: manage && roles.some(r => /^(?:network-admin|level-15|security-audit)$/.test(r)) ? 'admin' : 'local' };
    });
  }

  function detect(text) {
    return /^security-policy\s+ipv?6?\s*$/m.test(text) && /^security-zone\s+name\s+\S+/m.test(text);
  }

  function parse(text) {
    const tree = buildTree(text);
    const zones = zoneMap(tree);
    const interfaces = parseInterfaces(tree, zones);
    const addresses = parseAddressObjects(tree);
    const addrTypeMap = buildAddrTypeMap(addresses);
    return {
      vendor: 'H3C SecPath',
      deviceInfo: parseDeviceInfo(text),
      interfaces,
      policies: parsePolicies(tree, addrTypeMap),
      routes: parseRoutes(text),
      ha: null, nat: parseNAT(tree, interfaces), vpn: parseVPN(tree),
      addresses, services: parseServiceObjects(tree),
      users: parseUsers(tree), schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      dhcp: null, dns: null, snmp: null, logservers: null,
      wwan: null, wlan: null,
    };
  }

  return { parse, detect };
})();
