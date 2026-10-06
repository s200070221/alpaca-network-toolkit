// ══════════════════════════════════════════════════════════
//  Netgate TNSR PARSER
// ══════════════════════════════════════════════════════════
// 2026-10-06（第十二輪 ML）新增。輸入為 `show configuration running cli` 的輸出：每個區塊以縮排
// 表示層級、以 exit 收尾（格式依 Oxidized 的 5 份真實錄製 tnsr#TNSR_23.02～25.02，介面、
// ip address、route table／route／next-hop、system name、auth user 皆取自錄製）。錄製皆為 BGP
// 路由器、沒有 ACL／NAT／VPF 規則，這三者的語法依 Netgate 官方 TNSR 文件的搜尋摘要
// （docs.netgate.com 被網路政策擋下，信心度中等）：
//   acl <名稱> ＋ rule <序號> ＋ action {deny|permit|reflect}、ip-version {ipv4|ipv6}、
//     source／destination address <前綴>、source／destination port <起> [<迄>]、protocol、description
//   介面內 access-list {input|output} acl <名稱> sequence <N>（同一介面依 sequence 先後套用；
//     VPP ACL 套用後未命中即拒絕）
//   vpf filter ruleset <名稱> ＋ rule <序號> ＋ pass|block、direction {in|out}、stateful、
//     ip-version、protocol、from／to {ipv4-prefix|ipv6-prefix} <前綴>、from／to port <起> [<迄>]、description
//   vpf options ＋ interface <介面> filter-ruleset <名稱>（綁定後未放行即封鎖；依序號先命中者生效，
//     標 tentative 的規則改為後面有命中時讓位，查詢無法模擬，於備註標示）
//   nat pool addresses <位址>、nat static mapping [tcp|udp|icmp|any] local <位址> [埠] external <位址|介面> [埠]、
//     介面 ip nat {inside|outside}
// 未涵蓋：VPF NAT ruleset、IPsec／WireGuard、MACIP ACL、dynamic routing（BGP／OSPF）、
// ACL 規則的來源埠（查詢引擎只比對目的埠，不列入服務）。
const TNSRParser = (() => {
  const V4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

  // 依縮排切成樹（exit 行與 ! 註解行略過）：每個節點 {text, kids}
  function buildTree(text) {
    const root = { text: '', kids: [] };
    const stack = [{ depth: -1, node: root }];
    for (const raw of text.split('\n')) {
      const t = raw.trim();
      if (!t || t === 'exit' || t.startsWith('!')) continue;
      const depth = raw.match(/^ */)[0].length;
      const node = { text: t, kids: [] };
      while (stack.length > 1 && stack[stack.length - 1].depth >= depth) stack.pop();
      stack[stack.length - 1].node.kids.push(node);
      stack.push({ depth, node });
    }
    return root;
  }
  const tops = (tree, re) => tree.kids.filter(k => re.test(k.text));
  const kidVals = (n, re) => n.kids.map(k => k.text.match(re)).filter(Boolean);
  const kidVal = (n, re) => (kidVals(n, re)[0] || [])[1];

  function lenToMask(len) {
    const n = parseInt(len, 10);
    if (!(n >= 0 && n <= 32)) return '-';
    const v = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0;
    return [24, 16, 8, 0].map(s => (v >>> s) & 255).join('.');
  }
  const portStr = (a, b) => (b && b !== a ? `${a}-${b}` : a);
  // 協定＋目的埠 → 服務字面值（tcp/22、udp/1024-65535、icmp、any）
  function svcOf(proto, dport) {
    const p = (proto || '').toLowerCase();
    if (!p || p === 'any') return dport ? `tcp/${dport}, udp/${dport}` : 'any';
    if (p === 'tcp' || p === 'udp') return `${p}/${dport || '0-65535'}`;
    return /^\d+$/.test(p) ? ({ '6': `tcp/${dport || '0-65535'}`, '17': `udp/${dport || '0-65535'}`, '1': 'icmp', '58': 'icmpv6' }[p] || `proto-${p}`) : p;
  }

  function parseDeviceInfo(text) {
    const hostname = (text.match(/^system\s+name\s+(\S+)/m) || [])[1] || '-';
    const ver = (text.match(/^!\s*Version:\s*(\S+)/m) || text.match(/^!\s+tnsr\s+(\S+)\s*$/m) || [])[1];
    return { vendor: 'Netgate TNSR', hostname, firmware: ver ? ver.replace(/\+.*$/, '') : '-', model: '-', serial: '-', vdom: [] };
  }

  // 資料平面介面（interface <名稱> 兩段式；interface bond／subif／loopback 等為建立物件的指令）與 host 管理介面
  function parseInterfaces(tree) {
    const out = [];
    // 同一介面可能出現多個區塊（真實錄製在設定尾端另有只含 exit 的空區塊），依名稱合併
    const merged = new Map();
    tops(tree, /^interface\s+\S+\s*$/).forEach(n => {
      const name = n.text.split(/\s+/)[1];
      if (merged.has(name)) merged.get(name).kids.push(...n.kids);
      else merged.set(name, { text: n.text, kids: [...n.kids] });
    });
    merged.forEach(n => {
      const name = n.text.split(/\s+/)[1];
      const lines = n.kids.map(k => k.text);
      const ips = lines.map(l => l.match(/^ip address\s+(\d[\d.]*)\/(\d+)/)).filter(Boolean);
      const nat = (lines.find(l => /^ip nat\s+(?:inside|outside)/.test(l)) || '').split(/\s+/)[2] || '';
      const vlan = (name.match(/\.(\d+)$/) || [])[1] || '-';
      out.push({
        name, ip: ips[0] ? ips[0][1] : '-', mask: ips[0] ? lenToMask(ips[0][2]) : '-',
        secondaryIps: ips.slice(1).map(m => ({ ip: m[1], mask: lenToMask(m[2]) })),
        type: /^loop/i.test(name) ? 'loopback' : /^BondEthernet\d+$/i.test(name) ? 'aggregate' : vlan !== '-' ? 'vlan' : 'physical',
        vlanId: vlan, alias: name, desc: kidVal(n, /^description\s+(.+)/) || '',
        status: lines.includes('enable') ? 'up' : 'down',
        mtu: kidVal(n, /^mtu\s+(\d+)/) || '-', speed: '-',
        mode: ips.length ? 'static' : lines.some(l => /^ip dhcp-client enable/.test(l)) ? 'dhcp' : '-',
        vdom: '-', role: nat === 'outside' ? 'WAN' : 'LAN', allowaccess: '-', _natSide: nat,
      });
    });
    tops(tree, /^host\s+interface\s+\S+/).forEach(n => {
      const name = n.text.split(/\s+/)[2];
      const lines = n.kids.map(k => k.text);
      const ips = lines.map(l => l.match(/^ip address\s+(\d[\d.]*)\/(\d+)/)).filter(Boolean);
      out.push({ name, ip: ips[0] ? ips[0][1] : '-', mask: ips[0] ? lenToMask(ips[0][2]) : '-', secondaryIps: [],
        type: 'physical', vlanId: '-', alias: `host ${name}`, desc: kidVal(n, /^description\s+(.+)/) || '',
        status: lines.includes('enable') ? 'up' : 'down', mtu: '-', speed: '-',
        mode: ips.length ? 'static' : lines.some(l => /^ip dhcp-client enable/.test(l)) ? 'dhcp' : '-',
        vdom: '-', role: 'MGMT', allowaccess: '-', _natSide: '' });
    });
    return out;
  }

  function mkPolicy(o) {
    const addrs = v => (v || 'any');
    const srcAddr = addrs(o.src), dstAddr = addrs(o.dst);
    const fam = o.family === 'ipv6' ? 'v6' : o.family === 'ipv4' ? 'v4' : (/:/.test(srcAddr + dstAddr) ? 'v6' : (/\d+\.\d+/.test(srcAddr + dstAddr) ? 'v4' : undefined));
    const p = {
      id: o.id, name: o.name, srcIntf: o.srcIntf, dstIntf: o.dstIntf, srcAddr, dstAddr,
      srcAddr4: fam === 'v6' ? '-' : srcAddr, srcAddr6: fam === 'v6' ? srcAddr : (srcAddr === 'any' ? 'any' : '-'),
      dstAddr4: fam === 'v6' ? '-' : dstAddr, dstAddr6: fam === 'v6' ? dstAddr : (dstAddr === 'any' ? 'any' : '-'),
      service: o.service, schedule: 'always', action: o.action, actionRaw: o.actionRaw,
      nat: 'disable', ippool: 'disable', poolname: '-', logtraffic: 'disable',
      utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
      status: o.status || 'enable', users: '-', groups: '-', comments: o.comments || '', _vdom: '',
    };
    if (fam) p._family = fam;
    return p;
  }

  // ACL：依介面綁定展開（input → 來源介面、output → 目的介面），同一介面依 sequence 排序；
  // 未綁定任何介面的 ACL 不會過濾流量，列為停用
  function parseACLPolicies(tree) {
    const acls = {};
    tops(tree, /^acl\s+\S+\s*$/).forEach(n => {
      const name = n.text.split(/\s+/)[1];
      acls[name] = n.kids.filter(k => /^rule\s+\d+/.test(k.text)).map(r => {
        const v = re => kidVal(r, re);
        const sp = r.kids.map(k => k.text.match(/^destination port\s+(\d+)(?:\s+(\d+))?/)).find(Boolean);
        const act = (v(/^action\s+(\S+)/) || 'deny').toLowerCase();
        return { seq: r.text.split(/\s+/)[1], act, family: v(/^ip-version\s+(\S+)/), src: v(/^source address\s+(\S+)/), dst: v(/^destination address\s+(\S+)/),
          proto: v(/^protocol\s+(\S+)/), dport: sp ? portStr(sp[1], sp[2]) : '', desc: v(/^description\s+(.+)/) || '' };
      });
    });
    const out = [], used = new Set();
    tops(tree, /^interface\s+\S+\s*$/).forEach(n => {
      const iface = n.text.split(/\s+/)[1];
      kidVals(n, /^access-list\s+(input|output)\s+acl\s+(\S+)(?:\s+sequence\s+(\d+))?/)
        .sort((a, b) => (a[1] === b[1] ? 0 : a[1] === 'input' ? -1 : 1) || (parseInt(a[3] || '0', 10) - parseInt(b[3] || '0', 10)))
        .forEach(m => {
          const [, dir, acl] = m;
          used.add(acl);
          (acls[acl] || []).forEach(r => out.push(mkPolicy({
            id: `${iface}/${dir === 'input' ? 'in' : 'out'}/${acl}/${r.seq}`, name: acl,
            srcIntf: dir === 'input' ? iface : 'any', dstIntf: dir === 'output' ? iface : 'any',
            src: r.src, dst: r.dst, family: r.family, service: svcOf(r.proto, r.dport),
            action: r.act === 'deny' ? 'deny' : 'accept', actionRaw: r.act, comments: r.desc,
          })));
        });
    });
    Object.keys(acls).filter(a => !used.has(a)).forEach(acl => acls[acl].forEach(r => out.push(mkPolicy({
      id: `-/${acl}/${r.seq}`, name: acl, srcIntf: '-', dstIntf: '-', src: r.src, dst: r.dst, family: r.family,
      service: svcOf(r.proto, r.dport), action: r.act === 'deny' ? 'deny' : 'accept', actionRaw: r.act, comments: r.desc, status: 'disable',
    }))));
    return out;
  }

  // VPF 篩選規則：依 vpf options 的 interface … filter-ruleset 綁定展開（direction in → 來源介面、
  // out → 目的介面、未指定 → 兩個方向各一條）
  function parseVPFPolicies(tree) {
    const sets = {};
    tops(tree, /^vpf\s+filter\s+ruleset\s+\S+/).forEach(n => {
      const name = n.text.split(/\s+/)[3];
      sets[name] = n.kids.filter(k => /^rule\s+\d+/.test(k.text)).map(r => {
        const lines = r.kids.map(k => k.text);
        const side = w => {
          const a = [], ports = [];
          lines.forEach(l => {
            const m = l.match(new RegExp(`^${w}\\s+(\\S+)(?:\\s+(\\S+))?(?:\\s+(\\S+))?`));
            if (!m) return;
            if (m[1] === 'port') ports.push(portStr(m[2], m[3]));
            else if (/^ipv[46]-prefix$/.test(m[1])) a.push(m[2]);
            else a.push([m[1], m[2], m[3]].filter(Boolean).join(' '));
          });
          return { addr: a.join(', '), port: ports.join(',') };
        };
        const act = (lines.find(l => /^(?:pass|block)\b/.test(l)) || 'block').split(/\s+/)[0];
        const from = side('from'), to = side('to');
        const desc = kidVal(r, /^description\s+(.+)/) || '';
        return { seq: r.text.split(/\s+/)[1], act, dir: kidVal(r, /^direction\s+(\S+)/) || '', family: kidVal(r, /^ip-version\s+(\S+)/),
          proto: kidVal(r, /^protocol\s+(\S+)/), src: from.addr, dst: to.addr, dport: to.port,
          desc: lines.includes('tentative') ? (desc ? desc + ' ' : '') + '[tentative]' : desc };
      });
    });
    const out = [];
    tops(tree, /^vpf\s+options\s*$/).forEach(o => kidVals(o, /^interface\s+(\S+)\s+filter-ruleset\s+(\S+)/).forEach(m => {
      const [, iface, rs] = m;
      (sets[rs] || []).forEach(r => (r.dir === 'in' || r.dir === 'out' ? [r.dir] : ['in', 'out']).forEach(d => out.push(mkPolicy({
        id: `${iface}/vpf/${rs}/${r.seq}${r.dir ? '' : '/' + d}`, name: rs,
        srcIntf: d === 'in' ? iface : 'any', dstIntf: d === 'out' ? iface : 'any',
        src: r.src, dst: r.dst, family: r.family, service: svcOf(r.proto, r.dport),
        action: r.act === 'pass' ? 'accept' : 'deny', actionRaw: r.act, comments: r.desc,
      }))));
    }));
    return out;
  }

  // NAT：nat static mapping（埠轉送／1:1）列為 vip；有 ip nat inside／outside 時的動態 NAT 以 nat pool addresses 為轉換位址
  function parseNAT(tree, ifaces) {
    const out = [];
    let seq = 1;
    tree.kids.forEach(k => {
      const m = k.text.match(/^nat\s+static\s+mapping\s+(?:(icmp|tcp|udp|any)\s+)?local\s+(\S+)(?:\s+(?!external\b)(\S+))?\s+external\s+(\S+)(?:\s+(?!twice-nat\b|out2in-only\b|route-table\b)(\S+))?/);
      if (!m) return;
      const [, proto, local, lport, ext, eport] = m;
      const extIf = V4.test(ext) ? '-' : ext;
      const extIp = V4.test(ext) ? ext : ((ifaces.find(i => i.name === ext) || {}).ip || '-');
      const pf = !!(eport && eport !== 'any');
      out.push({ type: 'vip', name: `STATIC-MAP-${seq++}`, vipType: 'static', poolType: 'destination', extIp, mapIp: local,
        extIntf: extIf, srcIntf: '-', startIp: '-', endIp: '-', portFwd: pf ? 'enable' : 'disable',
        extPort: pf ? eport : '-', mapPort: pf ? (lport && lport !== 'any' ? lport : eport) : '-',
        proto: proto || 'any', status: 'enable', comment: /\btwice-nat\b/.test(k.text) ? 'twice-nat' : '' });
    });
    const pools = tree.kids.map(k => k.text.match(/^nat\s+pool\s+addresses\s+(\S+)(?:\s+-\s+(\S+))?/)).filter(Boolean).map(m => (m[2] ? `${m[1]}-${m[2]}` : m[1]));
    const outside = ifaces.filter(i => i._natSide === 'outside').map(i => i.name);
    const inside = ifaces.filter(i => i._natSide === 'inside').map(i => i.name);
    if (outside.length && inside.length) out.push({ type: 'ippool', name: 'NAT44-DYNAMIC', vipType: 'overload', poolType: 'source',
      extIp: 'any', mapIp: pools.join(', ') || '-', extIntf: outside.join(', '), srcIntf: inside.join(', '),
      startIp: '-', endIp: '-', portFwd: 'disable', extPort: '-', mapPort: '-', proto: 'any', status: 'enable', comment: '' });
    return out;
  }

  // route table <名稱> ＋ route <前綴> ＋ next-hop <N> via {<位址> [<介面>] | null-send-unreach | drop …}
  function parseRoutes(tree) {
    const out = [];
    let seq = 1;
    tops(tree, /^route\s+table\s+\S+\s*$/).forEach(t => {
      const vrf = t.text.split(/\s+/)[2];
      t.kids.filter(k => /^route\s+\S+/.test(k.text)).forEach(r => {
        const dst = r.text.split(/\s+/)[1];
        kidVals(r, /^next-hop\s+\d+\s+via\s+(\S+)(?:\s+(\S+))?/).forEach(m => {
          const isAddr = /^[\d.]+$|:/.test(m[1]);
          const bh = !isAddr && /^(?:null|drop|local|prohibit)/.test(m[1]);
          out.push({ type: dst === '0.0.0.0/0' || dst === '::/0' ? 'default' : 'static', id: String(seq++), dst,
            gateway: isAddr ? m[1] : '-', device: isAddr ? (m[2] || '-') : (bh ? 'Null' : m[1]),
            distance: '-', priority: '-', blackhole: bh ? 'enable' : 'disable', vrf, status: 'enable',
            comment: kidVal(r, /^description\s+(.+)/) || '', protocol_detail: '-', _vdom: '' });
        });
      });
    });
    return out;
  }

  // auth user <名稱>；nacm group admin 的成員視為管理員
  function parseUsers(tree) {
    const admins = new Set();
    tops(tree, /^nacm\s+group\s+admin\s*$/).forEach(g => kidVals(g, /^member\s+(\S+)/).forEach(m => admins.add(m[1])));
    return tops(tree, /^auth\s+user\s+\S+/).map(n => {
      const name = n.text.split(/\s+/)[2];
      return { name, role: admins.has(name) ? 'admin' : '-', type: admins.has(name) ? 'admin' : 'local' };
    });
  }

  // 錄製皆含 nacm 與 dataplane 設定；只貼部分設定時以 TNSR 特有的 ACL 套用（sequence）、VPF、
  // route table 的 next-hop <N> via 判斷（與 app.js FW_VENDOR_SIGS.tnsr 一致）
  const SIGS = [/^nacm\s+(?:enable|disable|group\s)[\s\S]*^dataplane\s|^dataplane\s[\s\S]*^nacm\s+(?:enable|disable|group\s)/m,
    /^[ \t]+access-list\s+(?:input|output)\s+acl\s+\S+\s+sequence\s+\d+/m, /^vpf\s+(?:filter\s+ruleset|options)\b/m, /^[ \t]+next-hop\s+\d+\s+via\s/m];
  function detect(text) { return SIGS.some(re => re.test(text)); }

  function parse(text) {
    const tree = buildTree(String(text || '').replace(/\r\n/g, '\n'));
    const interfaces = parseInterfaces(tree);
    return {
      vendor: 'Netgate TNSR',
      deviceInfo: parseDeviceInfo(text),
      interfaces,
      policies: parseACLPolicies(tree).concat(parseVPFPolicies(tree)),
      routes: parseRoutes(tree),
      ha: null, nat: parseNAT(tree, interfaces), vpn: [],
      addresses: [], services: [],
      users: parseUsers(tree), schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      dhcp: null, dns: null, snmp: null, logservers: null,
      wwan: null, wlan: null,
    };
  }

  return { parse, detect };
})();
