// ════════════════════════════════════════════════════
//  EXTREME VOSS / FABRIC ENGINE（VSP 系列）PARSER（2026-10-05 新增，第十一輪 KG）
// ════════════════════════════════════════════════════
// 與 ExtremeXOS（parser-extreme.js）是不同系統，vendor 為 voss。show running-config／config.cfg 依：
// - Ansible 官方 VOSS 模組的單元測試錄製（community.network／extremenetworks/ansible_collections.extreme.voss
//   的 voss_facts_show_running-config，VSP-8284XSQ 7.0）：檔頭 `# box type`／`# software version`、
//   `#` 段落標題、區塊以 exit 收尾、`interface Vlan 1`＋`ip address A 遮罩 0`、`vlan create 3 type
//   port-mstprstp 0`、`interface GigabitEthernet 1/1`＋`name "…"`、`interface loopback 1`＋
//   `ip address 1 A/遮罩 [vrf X]`、`ip vrf dmz vrfid 1`、`prompt "…"`
// - Extreme 官方 XMC 腳本（extremenetworks/ExtremeScripting 的 oneview_CLI_scripts）中的 VOSS 指令範本：
//   `vlan create N name "X" type port-mstprstp 0`、`vlan i-sid V I`、`vlan members add|remove V 埠`、
//   `vlan mlt V M`、`mlt N enable name "X"`、`mlt N member 埠`、`mlt N encapsulation dot1q`、`interface mlt N`、
//   `interface gigabitEthernet P`＋`encapsulation dot1q`、`interface Vlan N`＋`vrf X`＋`ip address A/長度`、
//   `snmp-server name`、`router isis`／`spbm 1 …`、`i-sid N` 區塊的 `c-vid V port P`／`untagged-traffic port P`
// - 官方文件與知識庫的搜尋摘要（documentation.extremenetworks.com 被網路政策擋下）：`vlan members V 埠 portmember`、
//   `default-vlan-id`、`untag-port-default-vlan`、`interface mlt N`＋`lacp enable key K`、`ip route A 遮罩 B weight N`
// 未涵蓋：OSPF／BGP／VRRP 細節、使用者帳號、ACL／QoS、SMLT／vIST 叢集（只記錄 virtual-ist 對端）

function isVOSS(cfg) {
  return /^#\s*box type\s*:\s*(?:VSP|XA|\d{4})/m.test(cfg) || /^vlan\s+create\s+[\d,\-]+(?:\s+name\s+"[^"]*")?\s+type\s+port-mstprstp\s+\d+/m.test(cfg) ||
    (/^boot config flags\s/m.test(cfg) && /^#\s*cli mode\s*:/m.test(cfg));
}

// 埠清單：1/1-1/4,1/20,2/3/1（slot/port[/subport]）；範圍也接受 1/1-4
function vossPorts(s) {
  const out = [];
  String(s || '').split(',').map(x => x.trim()).filter(Boolean).forEach(tok => {
    const m = /^(\d+)\/(\d+)(?:\/(\d+))?-(?:(\d+)\/)?(\d+)(?:\/(\d+))?$/.exec(tok);
    if (!m) { out.push(tok); return; }
    if (m[3] !== undefined || m[6] !== undefined) {
      const slot = m[1], port = m[2], a = +(m[3] || 0), b = +(m[6] || m[5]);
      for (let i = a; i <= b && i - a < 512; i++) out.push(`${slot}/${port}/${i}`);
      return;
    }
    const slot = m[1], a = +m[2], b = +m[5];
    if (m[4] !== undefined && m[4] !== slot) { out.push(tok); return; }
    for (let i = a; i <= b && i - a < 512; i++) out.push(`${slot}/${i}`);
  });
  return out;
}
function vossVlanIds(s) {
  const out = [];
  String(s || '').split(',').forEach(tok => {
    const m = /^(\d+)(?:-(\d+))?$/.exec(tok.trim());
    if (!m) return;
    const a = +m[1], b = +(m[2] || m[1]);
    for (let i = a; i <= b && i - a < 4096; i++) out.push(String(i));
  });
  return out;
}
function vossCidr(a, m) {
  if (!a) return '';
  if (a.includes('/')) {
    const [ip, mk] = a.split('/');
    return ip + '/' + (/^\d+$/.test(mk) ? mk : maskToCIDR(mk));
  }
  return m ? a + '/' + maskToCIDR(m) : a;
}

function parseVOSS(cfg) {
  const lines = cfg.replace(/\r\n/g, '\n').split('\n');
  const head = k => { const m = new RegExp('^#\\s*' + k + '\\s*:\\s*(.+?)\\s*$', 'm').exec(cfg); return m ? m[1] : ''; };
  const q = s => (s || '').trim().replace(/^"|"$/g, '');
  const hostname = q((/^prompt\s+(.+)$/m.exec(cfg) || /^snmp-server\s+name\s+(.+)$/m.exec(cfg) || [])[1]) || 'unknown';

  // 區塊：interface …／router …／i-sid … 到 exit；其餘為全域單行
  const blocks = [], globals = [];
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (!t || t.startsWith('#')) continue;
    if (/^(?:interface\s+\S+|router\s+\S+(?:\s+vrf\s+\S+)?|i-sid\s+\d+(?:\s+\S+)?)$/i.test(t) || /^interface\s+\S+\s+\S+$/i.test(t)) {
      const body = [];
      let j = i + 1;
      for (; j < lines.length; j++) {
        const u = lines[j].trim();
        if (u === 'exit') break;
        if (/^(?:interface|router|i-sid)\s/i.test(u) || /^#/.test(u)) { j--; break; }
        if (u) body.push(u);
      }
      blocks.push({ head: t, body });
      i = j;
      continue;
    }
    globals.push(t);
  }

  // VLAN、成員、I-SID、MLT
  const vlanMap = {}, portVlans = {}, mlts = {};
  const vlan = id => (vlanMap[id] = vlanMap[id] || { id, name: '', isid: '', ipSubnets: [], vrf: '' });
  const addMember = (vid, port) => { (portVlans[port] = portVlans[port] || new Set()).add(vid); };
  const delMember = (vid, port) => { if (portVlans[port]) portVlans[port].delete(vid); };
  const mlt = id => (mlts[id] = mlts[id] || { id, name: '', members: [], tagged: false, lacpKey: '', vlans: new Set() });
  let vist = null;
  const routes = [], vrfs = [], ntp = [];
  globals.forEach(t => {
    let m;
    if ((m = /^vlan\s+create\s+([\d,\-]+)(?:\s+name\s+("[^"]*"|\S+))?\s+type\s+/.exec(t))) vossVlanIds(m[1]).forEach(id => { const v = vlan(id); if (m[2]) v.name = q(m[2]); });
    else if ((m = /^vlan\s+name\s+(\d+)\s+(.+)$/.exec(t))) vlan(m[1]).name = q(m[2]);
    else if ((m = /^vlan\s+i-sid\s+(\d+)\s+(\d+)/.exec(t))) vlan(m[1]).isid = m[2];
    else if ((m = /^vlan\s+members\s+remove\s+([\d,\-]+)\s+(\S+)/.exec(t))) vossVlanIds(m[1]).forEach(v => vossPorts(m[2]).forEach(p => delMember(v, p)));
    else if ((m = /^vlan\s+members\s+(?:add\s+)?([\d,\-]+)\s+(\S+)(?:\s+portmember)?\s*$/.exec(t))) vossVlanIds(m[1]).forEach(v => { vlan(v); vossPorts(m[2]).forEach(p => addMember(v, p)); });
    else if ((m = /^vlan\s+mlt\s+(\d+)\s+(\d+)/.exec(t))) { vlan(m[1]); mlt(m[2]).vlans.add(m[1]); }
    else if ((m = /^mlt\s+(\d+)\s+enable(?:\s+name\s+("[^"]*"|\S+))?/.exec(t))) { const x = mlt(m[1]); if (m[2]) x.name = q(m[2]); }
    else if ((m = /^mlt\s+(\d+)\s+member\s+(\S+)/.exec(t))) mlt(m[1]).members.push(...vossPorts(m[2]));
    else if ((m = /^mlt\s+(\d+)\s+encapsulation\s+dot1q/.exec(t))) mlt(m[1]).tagged = true;
    else if ((m = /^mlt\s+(\d+)\s+name\s+(.+)$/.exec(t))) mlt(m[1]).name = q(m[2]);
    else if ((m = /^mlt\s+(\d+)\s*$/.exec(t))) mlt(m[1]);
    else if ((m = /^ip\s+vrf\s+(\S+)(?:\s+vrfid\s+(\d+))?/.exec(t))) vrfs.push({ name: m[1], rd: '', importRoute: '', vrfId: m[2] || '' });
    else if ((m = /^ip\s+route(?:\s+vrf\s+(\S+))?\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)/.exec(t)))
      routes.push({ dst: vossCidr(m[2], m[3]), gw: m[4], vrf: m[1] || '', gwIsInterface: !/^\d+\.\d+\.\d+\.\d+$/.test(m[4]) });
    else if ((m = /^virtual-ist\s+peer-ip\s+(\S+)\s+vlan\s+(\d+)/.exec(t))) vist = { peer: m[1], vlan: m[2] };
    else if ((m = /^ntp\s+server\s+(\S+)/.exec(t))) ntp.push(m[1]);
  });

  // 介面區塊
  const ports = {}, interfaces = [], isids = [];
  const portOf = n => (ports[n] = ports[n] || { name: n, desc: '', tagged: null, pvid: '', untagDefault: false, shutdown: false, lacpKey: '' });
  let spbm = null;
  blocks.forEach(b => {
    let m;
    const val = re => { const x = b.body.map(l => re.exec(l)).find(Boolean); return x ? x[1] : ''; };
    if ((m = /^interface\s+(?:gigabitEthernet|fastEthernet|GigabitEthernet|FastEthernet)\s+(\S+)$/i.exec(b.head))) {
      vossPorts(m[1]).forEach(pn => {
        const p = portOf(pn);
        b.body.forEach(l => {
          let x;
          if ((x = /^name\s+(.+)$/.exec(l))) p.desc = q(x[1]);
          else if (/^encapsulation\s+dot1q$/.test(l)) p.tagged = true;
          else if (/^no\s+encapsulation\s+dot1q$/.test(l)) p.tagged = false;
          else if ((x = /^default-vlan-id(?:\s+\S+\/\S+)?\s+(\d+)$/.exec(l))) p.pvid = x[1];
          else if (/^untag-port-default-vlan(?:\s+enable)?$/.test(l)) p.untagDefault = true;
          else if (/^shutdown$/.test(l)) p.shutdown = true;
          else if (/^no\s+shutdown$/.test(l)) p.shutdown = false;
          else if ((x = /^lacp\s+(?:enable\s+)?key\s+(\d+)/.exec(l))) p.lacpKey = x[1];
        });
      });
    } else if ((m = /^interface\s+mlt\s+(\d+)$/i.exec(b.head))) {
      const k = val(/^lacp\s+(?:enable\s+)?key\s+(\d+)/);
      if (k || b.body.some(l => /^lacp\s+enable/.test(l))) mlt(m[1]).lacpKey = k || 'lacp';
    } else if ((m = /^interface\s+vlan\s+(\d+)$/i.exec(b.head))) {
      const v = vlan(m[1]);
      v.vrf = val(/^vrf\s+(\S+)/);
      b.body.forEach(l => { const x = /^ip\s+address\s+(\S+)(?:\s+(\d+\.\d+\.\d+\.\d+))?/.exec(l); if (x) v.ipSubnets.push({ cidr: vossCidr(x[1], x[2]) }); });
      const v6 = b.body.map(l => /^ipv6\s+interface\s+address\s+(\S+)/.exec(l)).filter(Boolean).map(x => x[1]);
      interfaces.push({ name: 'Vlan' + m[1], type: 'svi', desc: v.name, ip: v.ipSubnets.length ? v.ipSubnets[0].cidr : '', ip6: v6[0] || '',
        secondaryIps: v.ipSubnets.slice(1).map(s => s.cidr), mode: '', vlans: '', nativeVlan: '', vrf: v.vrf, shutdown: false, member: '1', hybrid: null, vrrp: [] });
    } else if ((m = /^interface\s+loopback\s+(\d+)$/i.exec(b.head))) {
      const ips = b.body.map(l => /^ip\s+address\s+\d+\s+(\S+)(?:\s+vrf\s+(\S+))?/.exec(l)).filter(Boolean);
      const v6 = b.body.map(l => /^ipv6\s+interface\s+address\s+(\S+)/.exec(l)).filter(Boolean).map(x => x[1]);
      const ex = interfaces.find(i => i.name === 'Loopback' + m[1]);
      if (ex) { if (!ex.ip && ips[0]) { ex.ip = vossCidr(ips[0][1]); ex.vrf = ips[0][2] || ''; } if (!ex.ip6 && v6[0]) ex.ip6 = v6[0]; return; }
      interfaces.push({ name: 'Loopback' + m[1], type: 'loopback', desc: '', ip: ips[0] ? vossCidr(ips[0][1]) : '', ip6: v6[0] || '', secondaryIps: [],
        mode: 'routed', vlans: '', nativeVlan: '', vrf: ips[0] && ips[0][2] || '', shutdown: false, member: '1', hybrid: null, vrrp: [] });
    } else if ((m = /^interface\s+mgmtEthernet\s+(\S+)$/i.exec(b.head))) {
      const x = b.body.map(l => /^ip\s+address\s+(\S+)(?:\s+(\d+\.\d+\.\d+\.\d+))?/.exec(l)).find(Boolean);
      interfaces.push({ name: 'mgmt', type: 'mgmt', desc: '', ip: x ? vossCidr(x[1], x[2]) : '', ip6: '', secondaryIps: [], mode: 'routed', vlans: '', nativeVlan: '',
        vrf: 'MgmtRouter', shutdown: false, member: '1', hybrid: null, vrrp: [] });
    } else if ((m = /^router\s+isis$/i.exec(b.head))) {
      spbm = { nickname: val(/^spbm\s+\d+\s+nick-name\s+(\S+)/) || '' };
    } else if ((m = /^i-sid\s+(\d+)(?:\s+(\S+))?$/i.exec(b.head))) {
      const uni = [];
      b.body.forEach(l => {
        const x = /^c-vid\s+(\d+)\s+(port|mlt)\s+(\S+)/.exec(l), y = /^untagged-traffic\s+(port|mlt)\s+(\S+)/.exec(l);
        if (x) uni.push({ cvid: x[1], kind: x[2], ports: x[2] === 'port' ? vossPorts(x[3]) : [x[3]] });
        if (y) uni.push({ cvid: '', kind: y[1], ports: y[1] === 'port' ? vossPorts(y[2]) : [y[2]] });
      });
      isids.push({ isid: m[1], type: m[2] || '', uni });
    }
  });

  // 埠：VLAN 成員來自 vlan members，MLT 成員另以 MLT 的 VLAN 為準
  const memberOfMlt = {};
  Object.values(mlts).forEach(x => x.members.forEach(p => { memberOfMlt[p] = x; }));
  const allPorts = [...new Set([...Object.keys(ports), ...Object.keys(portVlans), ...Object.keys(memberOfMlt)])]
    .filter(p => /^\d+\/\d+(?:\/\d+)?$/.test(p))
    .sort((a, b) => a.split('/').map(Number).reduce((s, n, i) => s || n - (b.split('/').map(Number)[i] || 0), 0));
  allPorts.forEach(pn => {
    const p = portOf(pn), ml = memberOfMlt[pn];
    const vids = [...(ml ? ml.vlans : (portVlans[pn] || []))].sort((a, b) => a - b);
    const tagged = ml ? ml.tagged : p.tagged === true;
    let mode = '', vl = '', native = '';
    if (tagged) { mode = 'trunk'; vl = vids.join(' '); native = p.untagDefault && p.pvid ? p.pvid : ''; }
    else if (vids.length) { mode = 'access'; vl = p.pvid && vids.includes(p.pvid) ? p.pvid : vids[0]; }
    interfaces.push({ name: pn, type: 'physical', desc: p.desc, ip: '', ip6: '', secondaryIps: [], mode, vlans: vl, nativeVlan: native, vrf: '',
      shutdown: p.shutdown, member: '1', hybrid: null, vrrp: [], channelGroup: ml ? 'MLT' + ml.id : '' });
  });
  Object.values(mlts).forEach(x => {
    interfaces.push({ name: 'MLT' + x.id, type: 'aggregate', desc: x.name, ip: '', ip6: '', secondaryIps: [], mode: x.tagged ? 'trunk' : (x.vlans.size ? 'access' : ''),
      vlans: [...x.vlans].sort((a, b) => a - b).join(' '), nativeVlan: '', vrf: '', shutdown: false, member: '1', hybrid: null, vrrp: [] });
  });
  const lacp = Object.values(mlts).filter(x => x.members.length).map(x => ({
    name: 'MLT' + x.id, mode: x.lacpKey ? 'Active' : 'Static', desc: x.name,
    members: x.members.map(m => ({ name: m, lacpMode: x.lacpKey ? 'Active' : null })),
  }));

  const vlans = Object.values(vlanMap).sort((a, b) => a.id - b.id);
  const snmpVal = k => q((new RegExp('^snmp-server\\s+' + k + '\\s+(.+)$', 'm').exec(cfg) || [])[1]);
  return {
    sys: { hostname, version: head('software version'), platform: head('box type') }, irf: null,
    stack: vist ? { type: 'vIST', domain: '-', peerLink: 'VLAN ' + vist.vlan, peerAddr: vist.peer, localIntf: '-',
      members: [{ id: '1', model: '', priority: null, role: 'primary' }, { id: '2', model: '', priority: null, role: 'secondary' }] } : null,
    vlans, interfaces, routes, lacp, vrfs, users: [],
    ospf: [], bgp: [], rip: [], vrrp: [], vxlan: null, vendor: 'voss', breakouts: [], dns: [],
    syslog: { servers: [] }, snmp: { communities: [], v3Users: [], hosts: [], location: snmpVal('location'), contact: snmpVal('contact') },
    stp: { mode: null, rootMode: null, timers: { hello: null, forwardDelay: null, maxAge: null }, instances: [], ports: [] },
    dhcp: [], qos: [], ntp, spbm: spbm ? { ...spbm, isids } : (isids.length ? { nickname: '', isids } : null),
  };
}
