// ══════════════════════════════════════════════════════════
//  雲端安全群組 PARSER（AWS Security Group／Azure NSG，2026-10-02 新增，第十輪發想 ZC）
// ══════════════════════════════════════════════════════════
// 格式來源：
// - AWS：`aws ec2 describe-security-groups` JSON，依 aws/aws-cli 官方範例（awscli/examples/ec2/
//   describe-security-groups.rst）：SecurityGroups[].{GroupId, GroupName, Description, VpcId, Tags,
//   IpPermissions[], IpPermissionsEgress[]}，每筆權限 {IpProtocol, FromPort, ToPort, IpRanges[{CidrIp,
//   Description}], Ipv6Ranges[{CidrIpv6}], PrefixListIds[{PrefixListId}], UserIdGroupPairs[{GroupId}]}；
//   IpProtocol "-1" 為全部協定，ICMP 的 FromPort／ToPort 是類型／代碼（-1 為全部）。
//   官方範例本身帶尾端逗號（非合法 JSON），解析前先去除。
// - Azure：NSG 資源 JSON，依 Azure/azure-cli 官方測試錄製的 REST 回應：{name, properties:{securityRules[],
//   defaultSecurityRules[]}}，規則 {name, properties:{protocol, sourcePortRange(s), destinationPortRange(s),
//   sourceAddressPrefix(es), destinationAddressPrefix(es), access, priority, direction, description}}；
//   `az network nsg show` 輸出沒有 properties 外層，兩種都接受，也接受 nsg list 的陣列與 ARM 範本的 resources。
// - Cisco Meraki MX（2026-10-02，第十輪發想 ZD）：Dashboard API 回應 JSON，依官方 OpenAPI 規格
//   （github.com/meraki/openapi spec3.json 的範例與欄位說明）：
//   l3FirewallRules {rules:[{comment, policy allow|deny, protocol any|tcp|udp|icmp|icmp6, srcPort, srcCidr,
//   destPort, destCidr, syslogEnabled}]}（埠與位址為逗號清單或 Any，目的可為 FQDN）、
//   portForwardingRules {rules:[{name, lanIp, uplink, publicPort, localPort, allowedIps[], protocol}]}、
//   oneToOneNatRules {rules:[{name, publicIp, lanIp, uplink, allowedInbound[{protocol, destinationPorts[], allowedIps[]}]}]}、
//   vlans [{id, name, subnet, applianceIp}]、staticRoutes [{name, subnet, gatewayIp, enabled}]。
//   設定分散在多個 API，可貼單一回應、多個回應前後相接，或以端點名稱為鍵的物件；依欄位形狀辨識各段。
//   L3 規則為 LAN 往外（WAN／VPN）由上而下比對，介面列為 any。
// 對應方式：每個安全群組／NSG 當成一個 VDOM（可用上方 VDOM 列切換）；入站規則目的介面為群組名稱、
// 出站規則來源介面為群組名稱。AWS 只有允許規則，未列出的流量一律拒絕（不另列規則，比照預設政策）；
// Azure 依方向、priority 排序，預設規則（65000 起）一併列出並標註。
// 服務標籤（VirtualNetwork、Internet…）、AWS 前綴清單與安全群組參照列為位址物件，但成員不在檔案內，
// IP 查詢不會命中這些名稱（不猜測其範圍）。
const CloudSGParser = (() => {
  const PROTO_NUM = { '6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6' };

  function loadJson(text) {
    const t = String(text || '').replace(/^﻿/, '').trim();
    try { return JSON.parse(t); } catch { /* 官方範例的尾端逗號 */ }
    try { return JSON.parse(t.replace(/,(\s*[}\]])/g, '$1')); } catch { return null; }
  }
  const isAwsGroup = o => o && typeof o === 'object' && Array.isArray(o.IpPermissions) && ('GroupId' in o || 'GroupName' in o);
  const nsgProps = o => (o && o.properties && (o.properties.securityRules || o.properties.defaultSecurityRules)) ? o.properties : o;
  const isAzureNsg = o => { const p = nsgProps(o); return !!p && typeof p === 'object' && (Array.isArray(p.securityRules) || Array.isArray(p.defaultSecurityRules)); };

  // 從任意 JSON 結構中找出 AWS 安全群組與 Azure NSG（describe 輸出、nsg list 陣列、ARM 範本 resources）
  function collect(root) {
    const aws = [], az = [], seen = new Set();
    (function walk(o, depth) {
      if (!o || typeof o !== 'object' || depth > 6 || seen.has(o)) return;
      seen.add(o);
      if (isAwsGroup(o)) { aws.push(o); return; }
      if (isAzureNsg(o)) { az.push(o); return; }
      (Array.isArray(o) ? o : Object.values(o)).forEach(v => walk(v, depth + 1));
    })(root, 0);
    return { aws, az };
  }

  // Meraki：依欄位形狀找出各 API 回應的項目陣列（規則陣列保留原順序）
  const has = (o, a, b) => !!o && typeof o === 'object' && !Array.isArray(o) && a in o && b in o;
  const MK = {
    l3: o => has(o, 'policy', 'destCidr'),
    pf: o => has(o, 'lanIp', 'publicPort'),
    nat11: o => has(o, 'lanIp', 'publicIp'),
    vlan: o => has(o, 'applianceIp', 'subnet'),
    route: o => has(o, 'gatewayIp', 'subnet'),
  };
  function collectMeraki(root) {
    const res = { l3: [], pf: [], nat11: [], vlan: [], route: [] }, seen = new Set();
    (function walk(o, depth) {
      if (!o || typeof o !== 'object' || depth > 5 || seen.has(o)) return;
      seen.add(o);
      if (Array.isArray(o)) {
        const k = Object.keys(MK).find(k => o.length && o.every(x => MK[k](x)));
        if (k) { res[k].push(...o); return; }
      }
      (Array.isArray(o) ? o : Object.values(o)).forEach(v => walk(v, depth + 1));
    })(root, 0);
    return res;
  }
  const merakiCount = m => m.l3.length + m.pf.length + m.nat11.length + m.vlan.length + m.route.length;
  // 多個 API 回應前後相接時逐段解析（每段由行首的 { 或 [ 開始）
  function loadAll(text) {
    const one = loadJson(text);
    if (one) return one;
    const parts = String(text || '').split(/\n(?=[{[])/).map(loadJson).filter(Boolean);
    return parts.length ? parts : null;
  }

  function detect(text) {
    const s = String(text || '');
    if (!/"(?:IpPermissions|securityRules|defaultSecurityRules|destCidr|publicPort|publicIp|applianceIp)"/.test(s)) return false;
    const d = loadAll(s);
    if (!d) return false;
    const { aws, az } = collect(d);
    return aws.length + az.length + merakiCount(collectMeraki(d)) > 0;
  }

  function basePolicy(o) {
    const sa = _splitAddr(o.src), da = _splitAddr(o.dst);
    return {
      id: o.id, name: o.name, srcIntf: o.srcIntf, dstIntf: o.dstIntf,
      srcAddr: o.src, dstAddr: o.dst, srcAddr4: sa.v4, srcAddr6: sa.v6, dstAddr4: da.v4, dstAddr6: da.v6,
      service: o.service, schedule: 'always', action: o.action, actionRaw: o.actionRaw,
      nat: 'disable', ippool: 'disable', poolname: '-', logtraffic: 'disable',
      utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' }, status: 'enable',
      users: '-', groups: '-', comments: o.comment || '', _vdom: o.vdom, chain: o.chain, ruleNum: String(o.ruleNum),
      srcPort: o.srcPort || '',
    };
  }
  const refObj = (name, comment, vdom) => ({ category: 'address-group', name, type: 'group', subnet: '-', fqdn: '-', startIp: '-', endIp: '-',
    wildcard: '-', iface: '-', color: '0', comment, members: '-', _vdom: vdom });

  // ── AWS ──────────────────────────────────────────────────
  function awsService(p) {
    const proto = String(p.IpProtocol == null ? '-1' : p.IpProtocol).toLowerCase();
    if (proto === '-1' || proto === 'all') return 'ALL';
    const name = PROTO_NUM[proto] || proto;
    const from = p.FromPort, to = p.ToPort;
    if (name === 'icmp' || name === 'icmpv6') return from == null || from === -1 ? name : `${name}/${from}`;
    if (name !== 'tcp' && name !== 'udp') return /^\d+$/.test(name) ? `proto-${name}` : name;
    if (from == null || from === -1) return `${name}/0-65535`;
    return from === to || to == null ? `${name}/${from}` : `${name}/${from}-${to}`;
  }
  function parseAws(groups, out) {
    groups.forEach(g => {
      const nameTag = (g.Tags || []).find(t => t && t.Key === 'Name');
      const vdom = g.GroupName || g.GroupId || 'sg';
      out.vdoms.push(vdom);
      [['IpPermissions', 'inbound'], ['IpPermissionsEgress', 'outbound']].forEach(([key, dir]) => {
        (g[key] || []).forEach((p, i) => {
          const peers = [], notes = [];
          (p.IpRanges || []).forEach(r => { if (r && r.CidrIp) { peers.push(r.CidrIp); if (r.Description) notes.push(r.Description); } });
          (p.Ipv6Ranges || []).forEach(r => { if (r && r.CidrIpv6) { peers.push(r.CidrIpv6); if (r.Description) notes.push(r.Description); } });
          (p.PrefixListIds || []).forEach(r => {
            if (!r || !r.PrefixListId) return;
            peers.push(r.PrefixListId); if (r.Description) notes.push(r.Description);
            out.refs.set(vdom + '/' + r.PrefixListId, refObj(r.PrefixListId, 'AWS 前綴清單（成員不在此檔）', vdom));
          });
          (p.UserIdGroupPairs || []).forEach(r => {
            const id = r && (r.GroupId || r.GroupName);
            if (!id) return;
            peers.push(id); if (r.Description) notes.push(r.Description);
            out.refs.set(vdom + '/' + id, refObj(id, '安全群組參照（成員為套用該群組的執行個體）', vdom));
          });
          if (!peers.length) return;
          const peer = peers.join(', ');
          out.policies.push(basePolicy({
            id: out.policies.length + 1, name: `${vdom}-${dir === 'inbound' ? 'in' : 'out'}-${i + 1}`, vdom, chain: dir, ruleNum: i + 1,
            srcIntf: dir === 'inbound' ? 'any' : vdom, dstIntf: dir === 'inbound' ? vdom : 'any',
            src: dir === 'inbound' ? peer : 'any', dst: dir === 'inbound' ? 'any' : peer,
            service: awsService(p), action: 'accept', actionRaw: 'allow', comment: [...new Set(notes)].join('; '),
          }));
        });
      });
      out.groups.push({ name: vdom, id: g.GroupId || '-', vpc: g.VpcId || '-', desc: g.Description || '', tag: nameTag ? nameTag.Value : '' });
    });
  }

  // ── Azure ────────────────────────────────────────────────
  const list = (one, many) => (Array.isArray(many) && many.length ? many : (one != null && one !== '' ? [one] : [])).map(String);
  function azAddr(one, many, asgs, vdom, out) {
    const vals = list(one, many);
    (asgs || []).forEach(a => { const id = a && a.id ? String(a.id).split('/').pop() : ''; if (id) vals.push(id); });
    if (!vals.length || vals.includes('*')) return 'any';
    vals.forEach(v => {
      if (/^[\d.:a-fA-F/]+$/.test(v) && /\d/.test(v)) return;
      // AzureLoadBalancer 官方定義即主機虛擬 IP 168.63.129.16（service-tags-overview）；其餘服務標籤與
      // 應用程式安全性群組範圍由 Azure 或使用者環境決定，列為位址物件但不展開
      if (v === 'AzureLoadBalancer') out.refs.set(vdom + '/' + v, { ...refObj(v, 'Azure 服務標籤：主機虛擬 IP（健康探查來源）', vdom), category: 'address', type: 'ipmask', subnet: '168.63.129.16/32' });
      else out.refs.set(vdom + '/' + v, refObj(v, 'Azure 服務標籤／應用程式安全性群組（範圍由 Azure 決定）', vdom));
    });
    return vals.join(', ');
  }
  function azService(r) {
    const proto = String(r.protocol || '*').toLowerCase();
    const ports = list(r.destinationPortRange, r.destinationPortRanges);
    const anyPort = !ports.length || ports.includes('*');
    if (proto === '*' || proto === 'any') {
      if (anyPort) return 'ALL';
      return ports.flatMap(p => [`tcp/${p}`, `udp/${p}`]).join(', ');
    }
    if (proto === 'icmp') return 'icmp';
    if (proto === 'tcp' || proto === 'udp') return anyPort ? `${proto}/0-65535` : ports.map(p => `${proto}/${p}`).join(', ');
    return proto;
  }
  function parseAzure(nsgs, out) {
    nsgs.forEach(n => {
      const p = nsgProps(n);
      const vdom = n.name || (n.id ? String(n.id).split('/').pop() : 'nsg');
      out.vdoms.push(vdom);
      const rules = [];
      (p.securityRules || []).forEach(r => rules.push({ r, def: false }));
      (p.defaultSecurityRules || []).forEach(r => rules.push({ r, def: true }));
      const norm = rules.map(({ r, def }) => ({ name: r.name, def, ...(r.properties || r) }));
      const dirRank = d => /^in/i.test(d || '') ? 0 : 1;
      norm.sort((a, b) => dirRank(a.direction) - dirRank(b.direction) || (+a.priority || 0) - (+b.priority || 0));
      norm.forEach(r => {
        const inbound = dirRank(r.direction) === 0;
        const srcPorts = list(r.sourcePortRange, r.sourcePortRanges).filter(x => x !== '*');
        const allow = /^allow$/i.test(r.access || '');
        out.policies.push(basePolicy({
          id: out.policies.length + 1, name: r.name || `${vdom}-${r.priority}`, vdom, chain: inbound ? 'Inbound' : 'Outbound', ruleNum: r.priority != null ? r.priority : '-',
          srcIntf: inbound ? 'any' : vdom, dstIntf: inbound ? vdom : 'any',
          src: azAddr(r.sourceAddressPrefix, r.sourceAddressPrefixes, r.sourceApplicationSecurityGroups, vdom, out),
          dst: azAddr(r.destinationAddressPrefix, r.destinationAddressPrefixes, r.destinationApplicationSecurityGroups, vdom, out),
          service: azService(r), action: allow ? 'accept' : 'deny', actionRaw: r.access || '',
          comment: [r.def ? '預設規則' : '', r.description || ''].filter(Boolean).join('：'), srcPort: srcPorts.join(','),
        }));
      });
      out.groups.push({ name: vdom, id: n.id || '-', vpc: n.location || '-', desc: '', tag: '' });
    });
  }

  // ── Meraki ───────────────────────────────────────────────
  const csv = v => String(v == null ? '' : v).split(',').map(x => x.trim()).filter(Boolean);
  const isAny = v => !csv(v).length || csv(v).some(x => /^any$/i.test(x));
  function mkAddr(v, out) {
    if (isAny(v)) return 'any';
    const vals = csv(v);
    vals.forEach(x => {
      if (/^[\d.:a-fA-F/]+$/.test(x) && /\d/.test(x)) return;
      out.refs.set('/' + x, { ...refObj(x, 'Meraki 目的 FQDN', ''), category: 'address', type: 'fqdn', fqdn: x });
    });
    return vals.join(', ');
  }
  function mkService(proto, ports) {
    const p = String(proto || 'any').toLowerCase();
    const list = isAny(ports) ? [] : csv(ports);
    if (p === 'any') return list.length ? list.flatMap(x => [`tcp/${x}`, `udp/${x}`]).join(', ') : 'ALL';
    if (p === 'tcp' || p === 'udp') return list.length ? list.map(x => `${p}/${x}`).join(', ') : `${p}/0-65535`;
    return p === 'icmp6' ? 'icmpv6' : p;
  }
  function parseMeraki(m, out) {
    m.l3.forEach((r, i) => {
      const pol = basePolicy({
        id: out.policies.length + 1, name: r.comment || `L3-${i + 1}`, chain: 'L3', ruleNum: i + 1,
        srcIntf: 'any', dstIntf: 'any', src: mkAddr(r.srcCidr, out), dst: mkAddr(r.destCidr, out),
        service: mkService(r.protocol, r.destPort), action: /^allow$/i.test(r.policy || '') ? 'accept' : 'deny', actionRaw: r.policy || '',
        comment: r.comment || '', srcPort: isAny(r.srcPort) ? '' : csv(r.srcPort).join(','),
      });
      if (r.syslogEnabled) pol.logtraffic = 'all';
      out.policies.push(pol);
    });
    const allowed = a => (Array.isArray(a) && a.length ? a : ['any']).join(', ');
    m.pf.forEach((r, i) => out.nat.push({
      type: 'vip', name: r.name || `PF-${i + 1}`, vipType: 'port-forward', poolType: 'destination', extIp: r.uplink || '-', mapIp: r.lanIp || '-',
      extIntf: r.uplink || '-', srcIntf: '-', startIp: '-', endIp: '-', portFwd: 'enable', extPort: r.publicPort || '-', mapPort: r.localPort || '-',
      proto: r.protocol || '-', status: 'enable', comment: '允許來源：' + allowed(r.allowedIps),
    }));
    m.nat11.forEach((r, i) => {
      const inb = Array.isArray(r.allowedInbound) ? r.allowedInbound : [];
      out.nat.push({
        type: 'vip', name: r.name || `1to1-${i + 1}`, vipType: 'static', poolType: 'destination', extIp: r.publicIp || '-', mapIp: r.lanIp || '-',
        extIntf: r.uplink || '-', srcIntf: '-', startIp: '-', endIp: '-', portFwd: 'disable', extPort: inb.flatMap(a => a.destinationPorts || []).join(',') || '-', mapPort: '-',
        proto: [...new Set(inb.map(a => a.protocol).filter(Boolean))].join(',') || '-', status: 'enable',
        comment: inb.length ? '允許來源：' + [...new Set(inb.flatMap(a => a.allowedIps || []))].join(', ') : '',
      });
    });
    m.vlan.forEach(v => {
      const bits = parseInt(String(v.subnet || '').split('/')[1], 10);
      const mask = Number.isFinite(bits) ? [24, 16, 8, 0].map(sh => ((bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0) >>> sh) & 255).join('.') : '-';
      const v6 = ((v.ipv6 && v.ipv6.prefixAssignments) || []).map(p => p.staticApplianceIp6).filter(Boolean);
      out.ifaces.push({ name: `VLAN ${v.id}`, ip: v.applianceIp || '-', mask, ip6: v6[0] || '-', secondaryIps: [], type: 'vlan', vlanId: String(v.id || '-'),
        alias: v.name || '', desc: v.dhcpHandling || '', status: 'up', mtu: '-', speed: '-', mode: '-', vdom: '', role: 'lan', allowaccess: '-' });
    });
    m.route.forEach((r, i) => out.routes.push({
      type: r.subnet === '0.0.0.0/0' ? 'default' : 'static', id: String(i + 1), dst: r.subnet || '-', gateway: r.gatewayIp || '-', device: '-',
      distance: '-', priority: '-', blackhole: 'disable', vrf: 'main', status: r.enabled === false ? 'disable' : 'enable', comment: r.name || '',
      protocol_detail: '-', _vdom: '',
    }));
  }

  function parse(text) {
    const d = loadAll(text);
    const { aws, az } = collect(d || {});
    const mk = collectMeraki(d || {});
    const out = { policies: [], refs: new Map(), vdoms: [], groups: [], nat: [], ifaces: [], routes: [] };
    parseAws(aws, out);
    parseAzure(az, out);
    parseMeraki(mk, out);
    const kinds = [aws.length && 'AWS Security Group', az.length && 'Azure NSG', merakiCount(mk) && 'Cisco Meraki MX'].filter(Boolean);
    const vendor = kinds.length === 1 ? kinds[0] : 'Cloud Security Group';
    const vpcs = [...new Set(out.groups.map(g => g.vpc).filter(v => v && v !== '-'))];
    return {
      vendor,
      deviceInfo: { vendor, hostname: '-', firmware: '-', model: vpcs.join(', ') || '-', serial: '-', vdom: out.vdoms },
      // 安全群組沒有介面；以群組本身列在介面頁，方便看出各群組套用範圍與說明
      interfaces: out.groups.map(g => ({ name: g.name, ip: '-', mask: '-', secondaryIps: [], type: 'security-group', vlanId: '-', alias: g.tag || g.id,
        desc: g.desc, status: 'up', mtu: '-', speed: '-', mode: '-', vdom: g.name, role: '-', allowaccess: '-' })).concat(out.ifaces),
      policies: out.policies, routes: out.routes, ha: null, nat: out.nat, vpn: [], addresses: [...out.refs.values()], services: [], users: [], schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      dhcp: null, dns: null, snmp: null, logservers: null, wwan: null, wlan: null,
    };
  }

  return { parse, detect, _loadJson: loadJson, _loadAll: loadAll };
})();
