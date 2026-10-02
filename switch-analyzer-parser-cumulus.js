// ════════════════════════════════════════════════════
//  NVIDIA CUMULUS LINUX（NVUE）PARSER（2026-10-02 新增，第十輪發想 ZI）
// ════════════════════════════════════════════════════
// 支援兩種 NVUE 輸出：`nv config show`／/etc/nvue.d/startup.yaml 的 YAML（`- header:` 與 `- set:` 兩段），
// 以及 `nv config show -o commands` 的 `nv set …` 指令。格式依：
// - Oxidized 專案的真實裝置錄製（spec/model/data/cumulus#MSN2010_5.9.2_nvue：interface 鍵可為範圍 swp1-18
//   或逗號清單 eth0,swp19-22、router bgp、system hostname／aaa user、service snmp-server／syslog）
// - NVIDIA 官方文件原始檔（github.com/CumulusNetworks/docs，cumulus-linux-59）的 startup.yaml 範例：
//   bridge domain br_default vlan（鍵可為 '310' 或 10,20,30）、untagged、介面 bridge domain br_default access／vlan、
//   stp admin-edge／bpdu-guard、bond member／mode／mlag、type svi＋vlan、vrf <名稱> router static <前綴> via <下一跳>
// 兩種輸出都轉成同一棵樹：YAML 的「key: 值」與指令最後一個字都成為子鍵，讀取葉值時取第一個子鍵（leaf()），
// 因此 `access: 310` 與 `nv set … access 310` 結果相同。未涵蓋：舊版 /etc/network/interfaces（ifupdown2）與 frr.conf
const CumulusNVUE = (() => {
  const unq = s => String(s).trim().replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1');
  function setPath(root, path) {
    let n = root;
    for (const k of path) { if (!n[k] || typeof n[k] !== 'object') n[k] = {}; n = n[k]; }
    return n;
  }
  // YAML（NVUE 輸出用到的子集）：區塊對應、`key: {}`、`key: 純值`、`key: |` 區塊字串（略過內容）、引號鍵與值
  function parseYaml(text) {
    const out = { header: {}, set: {} };
    let section = null;
    const stack = [];   // [{indent, node}]
    let skipIndent = -1;
    for (const raw of text.split('\n')) {
      if (!raw.trim() || /^\s*#/.test(raw)) continue;
      const indent = raw.match(/^\s*/)[0].length;
      if (skipIndent >= 0) { if (indent > skipIndent) continue; skipIndent = -1; }
      const top = raw.match(/^\s*-\s+(header|set|unset):\s*$/);
      if (top) { section = top[1] === 'unset' ? null : out[top[1]]; stack.length = 0; stack.push({ indent, node: section }); continue; }
      if (!section) continue;
      // 鍵到「後面接空白或行尾的冒號」為止：IPv6 位址鍵（2001:db8::1/32: {}）本身含冒號
      const m = raw.match(/^(\s*)('[^']*'|"[^"]*"|\S.*?):(?:\s+(.*)|$)/);
      if (!m) continue;
      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
      const parent = stack[stack.length - 1].node;
      const key = unq(m[2]);
      const val = m[3] === undefined ? '' : m[3].trim();
      if (val === '' ) { const child = parent[key] && typeof parent[key] === 'object' ? parent[key] : (parent[key] = {}); stack.push({ indent, node: child }); }
      else if (val === '{}') { if (!parent[key] || typeof parent[key] !== 'object') parent[key] = {}; }
      else if (/^[|>][-+]?$/.test(val)) { parent[key] = ''; skipIndent = indent; }
      else parent[key] = unq(val);
    }
    return out;
  }
  // `nv set a b c` → a.b.c = {}（值也是子鍵，與 YAML 一致由 leaf() 讀取）
  function parseCommands(text) {
    const set = {};
    for (const raw of text.split('\n')) {
      const m = raw.trim().match(/^nv set\s+(.+)$/);
      if (!m) continue;
      const toks = m[1].match(/'[^']*'|"[^"]*"|\S+/g).map(unq);
      setPath(set, toks);
    }
    return { header: {}, set };
  }
  const leaf = n => (n && typeof n === 'object' ? (Object.keys(n)[0] || '') : (n === undefined || n === null ? '' : String(n)));
  const keys = n => (n && typeof n === 'object' ? Object.keys(n) : (n ? [String(n)] : []));
  // swp1-4 → swp1..swp4；eth0,swp19-22 → eth0, swp19..swp22（只展開「前綴＋數字-數字」）
  function expandNames(key) {
    const out = [];
    for (const part of String(key).split(',')) {
      const m = part.match(/^(.*?)(\d+)-(\d+)$/);
      if (m && +m[3] >= +m[2] && +m[3] - +m[2] < 512) for (let i = +m[2]; i <= +m[3]; i++) out.push(m[1] + i);
      else if (part) out.push(part);
    }
    return out;
  }
  function deepMerge(a, b) {
    for (const k of Object.keys(b)) {
      if (b[k] && typeof b[k] === 'object' && a[k] && typeof a[k] === 'object') deepMerge(a[k], b[k]);
      else if (b[k] && typeof b[k] === 'object') a[k] = deepMerge({}, b[k]);
      else a[k] = b[k];
    }
    return a;
  }
  // VLAN 鍵：'310'、10,20,30、100-110
  const vlanList = n => [...new Set(keys(n).flatMap(k => expandNames(k)).filter(v => /^\d+$/.test(v)))].sort((a, b) => a - b);
  const ifSort = (a, b) => a.localeCompare(b, undefined, { numeric: true });
  return { parseYaml, parseCommands, leaf, keys, expandNames, deepMerge, vlanList, ifSort };
})();

function isCumulusNVUE(cfg) {
  return (/^\s*-\s+set:\s*$/m.test(cfg) && (/nvue-api-version/.test(cfg) || /^\s+(?:interface|bridge|system|router|vrf):\s*$/m.test(cfg))) ||
    /^nv set (?:interface|bridge|system|router|vrf|service) /m.test(cfg);
}

function parseCumulus(cfg) {
  const L = CumulusNVUE;
  const doc = /^nv set /m.test(cfg) && !/^\s*-\s+set:\s*$/m.test(cfg) ? L.parseCommands(cfg) : L.parseYaml(cfg);
  const S = doc.set || {}, H = doc.header || {};
  const sys = S.system || {};
  const hostname = L.leaf(sys.hostname) || 'unknown';
  const version = (L.leaf(H.version).match(/(\d+(?:\.\d+)+)/) || [])[1] || '';

  // 介面：展開範圍與逗號清單後合併同名設定
  const ifs = {};
  Object.entries(S.interface || {}).forEach(([k, v]) => {
    L.expandNames(k).forEach(n => { ifs[n] = L.deepMerge(ifs[n] || {}, v && typeof v === 'object' ? v : {}); });
  });

  // 橋接器 VLAN 與預設原生 VLAN（NVUE 預設 untagged 1）
  const domains = (S.bridge && S.bridge.domain) || {};
  const domVlans = {}, domUntagged = {};
  Object.entries(domains).forEach(([d, v]) => {
    domVlans[d] = L.vlanList(v && v.vlan);
    const u = L.leaf(v && v.untagged);
    domUntagged[d] = u === 'none' ? '' : (u || '1');
  });
  const vlanIds = new Set(Object.values(domVlans).flat());

  const interfaces = [], lacp = [], stpPorts = [];
  const sviIp = {};
  Object.keys(ifs).sort(L.ifSort).forEach(name => {
    const v = ifs[name];
    const type = L.leaf(v.type) || (/^swp/.test(name) ? 'swp' : '');
    const addrs = L.keys(v.ip && v.ip.address).filter(a => a !== 'dhcp');
    const v4 = addrs.filter(a => !a.includes(':')), v6 = addrs.filter(a => a.includes(':'));
    const vrf = L.leaf(v.ip && v.ip.vrf);
    const desc = L.leaf(v.description);
    const shutdown = !!(v.link && v.link.state && 'down' in (typeof v.link.state === 'object' ? v.link.state : { [v.link.state]: 1 }));
    const br = v.bridge && v.bridge.domain ? Object.keys(v.bridge.domain)[0] : '';
    const bd = br ? v.bridge.domain[br] || {} : null;
    let mode = '', vlans = '', nativeVlan = '';
    if (bd) {
      const acc = L.leaf(bd.access);
      if (acc) { mode = 'access'; vlans = acc; }
      else {
        mode = 'trunk';
        const own = L.vlanList(bd.vlan);
        vlans = (own.length ? own : (domVlans[br] || [])).join(' ');
        const u = L.leaf(bd.untagged);
        nativeVlan = u === 'none' ? '' : (u || domUntagged[br] || '');
      }
      if (bd.stp) stpPorts.push({ port: name, portfast: 'admin-edge' in bd.stp && L.leaf(bd.stp['admin-edge']) !== 'off', bpduguard: 'bpdu-guard' in bd.stp && L.leaf(bd.stp['bpdu-guard']) !== 'off', guardRoot: false, cost: '', priority: '' });
    }
    if (type === 'svi' || /^vlan\d+$/.test(name)) {
      const id = L.leaf(v.vlan) || (name.match(/(\d+)$/) || [])[1] || '';
      if (id) sviIp[id] = v4;
      interfaces.push({ name, type: 'svi', desc, ip: v4[0] || '', ip6: v6[0] || '', secondaryIps: v4.slice(1), mode: '', vlans: '', nativeVlan: '', vrf, shutdown, member: '1', hybrid: null, vrrp: [] });
      return;
    }
    if (v.bond && v.bond.member) {
      const bmode = L.leaf(v.bond.mode) || 'lacp';
      lacp.push({ name, mode: bmode === 'static' ? 'Static' : 'Active', members: L.keys(v.bond.member).flatMap(L.expandNames).map(m => ({ name: m, lacpMode: bmode === 'static' ? null : 'Active' })),
        mlag: v.bond.mlag ? L.leaf(v.bond.mlag.id) : '' });
    }
    const t = type === 'loopback' ? 'loopback' : type === 'bond' || type === 'peerlink' ? 'aggregate' : type === 'eth' ? 'mgmt' : type === 'sub' ? 'subinterface' : 'physical';
    interfaces.push({ name, type: t, desc, ip: v4[0] || '', ip6: v6[0] || '', secondaryIps: v4.slice(1),
      mode: mode || (v4.length || v6.length ? 'routed' : ''), vlans, nativeVlan, vrf, shutdown, member: '1', hybrid: null, vrrp: [] });
  });

  const vlans = [...new Set([...vlanIds, ...Object.keys(sviIp)])].sort((a, b) => a - b)
    .map(id => ({ id, name: '', ipSubnets: (sviIp[id] || []).map(cidr => ({ cidr })) }));

  // 靜態路由與 VRF
  const routes = [], vrfs = [];
  Object.entries(S.vrf || {}).forEach(([vn, v]) => {
    if (vn !== 'default') vrfs.push({ name: vn, rd: '', importRoute: '' });
    Object.entries((v && v.router && v.router.static) || {}).forEach(([dst, r]) => {
      L.keys(r && r.via).forEach(gw => routes.push({ dst, gw, vrf: vn === 'default' ? '' : vn, gwIsInterface: !/^[\d.:]+$/.test(gw) && gw !== 'blackhole' }));
    });
  });

  // BGP：本機 AS 與 router-id 在 router bgp，鄰居在 vrf <名稱> router bgp neighbor
  const bgp = [];
  const rb = (S.router && S.router.bgp) || {};
  const asn = L.leaf(rb['autonomous-system']);
  if (asn) {
    const peers = [];
    Object.values(S.vrf || {}).forEach(v => {
      const b = v && v.router && v.router.bgp;
      if (!b) return;
      const groups = b['peer-group'] || {};
      Object.entries(b.neighbor || {}).forEach(([ip, n]) => {
        const g = groups[L.leaf(n && n['peer-group'])] || {};
        const ras = L.leaf(n && n['remote-as']) || L.leaf(g['remote-as']);
        peers.push({ ip, as: ras, desc: L.leaf(n && n.description) || L.leaf(n && n['peer-group']),
          type: ras === 'internal' || ras === asn ? 'iBGP' : 'eBGP' });
      });
    });
    bgp.push({ asn, routerId: L.leaf(rb['router-id']), peers, networks: [] });
  }

  // 本機帳號（hashed-password '*' 代表未設密碼）
  const users = Object.entries((sys.aaa && sys.aaa.user) || {}).map(([name, u]) => {
    const pw = L.leaf(u && u['hashed-password']);
    return { name, role: L.leaf(u && u.role) || '', service: 'ssh/console', privilege: '', hasPwd: !!pw && pw !== '*',
      pwdType: pw && pw !== '*' ? (pw.startsWith('$6$') ? 'sha512' : pw.startsWith('$5$') ? 'sha256' : 'set') : 'none' };
  });

  // 服務：syslog／DNS 伺服器（依 VRF 分組，伺服器為子鍵）、SNMP v3 帳號
  const svc = S.service || {};
  const serversOf = n => Object.values(n || {}).flatMap(v => L.keys(v && v.server));
  const syslog = { servers: serversOf(svc.syslog).map(host => ({ host, facility: '' })) };
  const dns = serversOf(svc.dns).filter(h => /^[\d.:a-fA-F]+$/.test(h));
  const snmpSrv = svc['snmp-server'] || {};
  const snmp = { communities: L.keys(snmpSrv['readonly-community']).map(name => ({ name })), v3Users: L.keys(snmpSrv.username).map(name => ({ name })), hosts: [] };

  // MLAG：形狀比照 Arista（parseAristaMlag），peerlink 為 type peerlink 的 bond，backup 為備援 IP
  const peerlink = Object.keys(ifs).find(n => L.leaf(ifs[n].type) === 'peerlink') || '-';
  const mlag = S.mlag && L.leaf(S.mlag.enable) === 'on'
    ? { type: 'MLAG', domain: '-', peerLink: peerlink, peerAddr: L.leaf(S.mlag['peer-ip']) || '-', localIntf: L.keys(S.mlag.backup).join(', ') || '-',
        members: [{ id: '1', model: '', priority: null, role: 'primary' }, { id: '2', model: '', priority: null, role: 'secondary' }] } : null;

  return {
    sys: { hostname, version, platform: L.leaf(H.model) || '' }, irf: null, stack: mlag, vlans, interfaces, routes, lacp, vrfs, users,
    ospf: [], bgp, rip: [], vrrp: [], vxlan: null, vendor: 'cumulus', breakouts: [], dns, syslog, snmp,
    stp: { mode: null, rootMode: null, timers: { hello: null, forwardDelay: null, maxAge: null }, instances: [], ports: stpPorts },
    dhcp: [], qos: [],
  };
}
