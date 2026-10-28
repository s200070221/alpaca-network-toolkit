// ── 防火牆轉換：目標型號埠對應與轉換驗證（XN38／XN40）──────────────────────────────
// 純函式，全域 FwPortMap；型號資料 window.FW_MODELS 由 firewall-analyzer-models.js 提供（scripts/build_fw_models.py 產生）。
// 對應只改介面欄位（白名單），位址物件等名稱欄位不動；一律產生副本，不修改原 parsed（稽核的快取以物件身分為鍵）。
(function () {
  'use strict';

  const MODELS = () => (typeof window !== 'undefined' && window.FW_MODELS) || {};
  // parser 的 vendor 字串 → 型號資料的廠牌鍵
  const VENDOR_KEY = { 'fortigate': 'fortigate', 'paloalto': 'paloalto', 'cisco asa': 'ciscoasa', 'cisco ftd': 'ciscoftd', 'juniper': 'juniper', 'mikrotik': 'mikrotik',
    'checkpoint': 'checkpoint', 'sonicwall': 'sonicwall', 'sophos': 'sophos', 'zyxel': 'zyxel', 'edgerouter': 'edgerouter' };
  // 各廠牌出廠慣用的 WAN 埠（沒有名稱含 wan 的埠時優先使用）：SonicWall X1、EdgeRouter eth0、MikroTik ether1、SRX ge-0/0/0、Zyxel ge1、Palo Alto ethernet1/1
  const WAN_HINT = { sonicwall: ['X1'], edgerouter: ['eth0'], mikrotik: ['ether1'], juniper: ['ge-0/0/0'], zyxel: ['ge1'], paloalto: ['ethernet1/1'] };
  const vendorKey = parsed => VENDOR_KEY[String((parsed && parsed.vendor) || '').toLowerCase()] || null;

  function modelsOf(target) { return MODELS()[target] || []; }
  function getModel(target, id) { return modelsOf(target).find(m => m.id === id) || null; }

  // 不是實體埠的介面類型（邏輯介面、通道、無線、撥接等）；聚合／交換器另取成員
  const LOGICAL_RE = /^(vlan|tunnel|loopback|aggregate|redundant|zone|switch|hard-switch|vap-switch|wl-mesh|pppoe|pppoa|wireless|wifi|wlan|lte|wwan|vrrp|gre|vti|bridge|virtual|ipsec|l2tp|ovpn|sstp|pptp|bond|bonding|tun|ssl|emac-vlan|vxlan|vdom-link|npu-vlink|geneve|eoip|veth|wireguard)/i;
  const GROUP_RE = /^(aggregate|redundant|switch|hard-switch|bond|bonding|bridge)$/i;
  const MGMT_NAME_RE = /^(mgmt\d*|management\d*(\/\d+)*|fxp0|em0|me0|mgt)$/i;
  const HA_NAME_RE = /^(ha\d*|dedicated-ha\d*|hsci\d*|ha\d-[ab])$/i;
  const WAN_RE = /^(wan|external|untrust|outside|internet)$/i;

  const dash = v => v == null || v === '' || v === '-';
  // 子介面的實體基底：VLAN 類型取父介面，名稱帶 .N 單元或 VLAN 編號者取點前名稱
  // FortiOS 匯出的 VLAN 介面不寫 set type vlan，以 vlanid＋interface 判斷
  const isVlan = i => !dash(i.interface) && (/^vlan/i.test(i.type || '') || !dash(i.vlanId));
  function baseOf(i) {
    if (isVlan(i)) return String(i.interface);
    if (!dash(i.interface) && String(i.name).startsWith(String(i.interface) + '.')) return String(i.interface);
    const m = String(i.name).match(/^(.+?)\.\d+$/);
    return m ? m[1] : String(i.name);
  }

  // 來源實體埠：[{name, role:'wan'|'mgmt'|'ha'|'', fortilink, group, groupKind, ifaces:[使用此埠的介面名稱]}]
  function sourcePorts(parsed) {
    const ifs = (parsed && parsed.interfaces) || [];
    const groups = (parsed && parsed.switchGroups) || [];
    const logical = new Set(ifs.filter(i => LOGICAL_RE.test(i.type || '')).map(i => i.name).concat(groups.map(g => g.name)));
    const out = [], byName = Object.create(null);
    const add = (name, extra) => {
      if (!name || name === '__proto__' || logical.has(name)) return null;
      let p = byName[name];
      if (!p) { p = byName[name] = { name, role: '', fortilink: false, group: '', groupKind: '', ifaces: [] }; out.push(p); }
      if (extra) Object.keys(extra).forEach(k => { if (extra[k]) p[k] = extra[k]; });
      return p;
    };
    ifs.forEach(i => {
      const t = String(i.type || '');
      if (LOGICAL_RE.test(t) || isVlan(i)) {
        // 聚合／交換器：成員才是實體埠（FortiLink 聚合的成員標為交換器管理專用）
        if (GROUP_RE.test(t) || i.fortilink) (i.members || []).forEach(m => add(m, i.fortilink ? { fortilink: true } : { group: i.name, groupKind: t }));
        // VLAN 子介面掛在實體埠上：記到該埠，角色沿用
        if (isVlan(i)) { const p = add(baseOf(i)); if (p) { p.ifaces.push(i.name); if (!p.role && WAN_RE.test(i.role || '')) p.role = 'wan'; } }
        return;
      }
      const p = add(baseOf(i));
      if (!p) return;
      p.ifaces.push(i.name);
      const nm = String(i.name);
      if (!p.role) {
        if (MGMT_NAME_RE.test(p.name) || /^(mgmt|management)$/i.test(i.nameif || '') || /^mgmt$/i.test(i.role || '')) p.role = 'mgmt';
        else if (HA_NAME_RE.test(p.name)) p.role = 'ha';
        else if (WAN_RE.test(i.role || '') || WAN_RE.test(i.nameif || '') || WAN_RE.test(i.zone || '') || /^wan\d*$/i.test(nm)) p.role = 'wan';
      }
    });
    groups.forEach(g => (g.members || []).forEach(m => add(m, { group: g.name, groupKind: g.kind })));
    return out;
  }

  // 各實體埠的用途（XN46）：{埠: {ips, alias, zones, refs:{policy,nat,route,vpn}, used}}
  // 只靠名稱推得的 WAN 角色（如 wan2）不算使用中；DHCP／PPPoE 取得位址的介面視為有位址
  // 名稱標籤＝埠上各介面（含 VLAN 子介面）的名稱／nameif／區域（Juniper 以 _vdom 為區域）＋所屬群組，
  // 規則／NAT／路由／VPN 的介面欄位以 token 不分大小寫比對標籤
  const REF_KEYS = {
    policy: ['srcIntf', 'dstIntf', 'srcIntfMembers', 'dstIntfMembers'],
    nat: ['extIntf', 'srcIntf', 'dstIntf', 'outIntf', 'inIntf', 'srcIf', 'dstIf'],
    route: ['device', 'iface', 'interface'],
    vpn: ['iface'],
  };
  const tokensOf = v => (Array.isArray(v) ? v : String(v == null ? '' : v).split(/[\s,]+/)).map(s => String(s).trim().toLowerCase()).filter(s => s && s !== '-');
  function portUsage(parsed) {
    const ifs = (parsed && parsed.interfaces) || [];
    const juniper = /juniper/i.test((parsed && parsed.vendor) || '');
    const ifByName = Object.create(null);
    ifs.forEach(i => { if (i && i.name && i.name !== '__proto__') ifByName[i.name] = i; });
    const out = Object.create(null);
    sourcePorts(parsed).forEach(sp => {
      const labels = new Set(), ips = [], zones = [], alias = [];
      const addZone = z => { if (!dash(z) && !zones.includes(String(z))) zones.push(String(z)); };
      new Set([sp.name].concat(sp.ifaces)).forEach(n => {
        labels.add(String(n).toLowerCase());
        const i = ifByName[n];
        if (!i) return;
        [i.nameif, i.zone, i._zone].forEach(x => { if (!dash(x)) labels.add(String(x).toLowerCase()); });
        addZone(i.zone); addZone(i._zone); addZone(i.nameif);
        if (juniper && !dash(i._vdom)) { labels.add(String(i._vdom).toLowerCase()); addZone(i._vdom); }
        if (!dash(i.ip) && i.ip !== '0.0.0.0') ips.push(i.ip + (dash(i.mask) ? '' : '/' + i.mask));
        else if (/^(dhcp|pppoe)$/i.test(i.mode || '')) ips.push(String(i.mode).toUpperCase());
        const a = !dash(i.alias) && i.alias !== i.name ? i.alias : !dash(i.desc) ? i.desc : '';
        if (a && !alias.includes(a)) alias.push(String(a));
      });
      if (sp.group) labels.add(sp.group.toLowerCase());
      const refs = {};
      Object.keys(REF_KEYS).forEach(k => {
        const arr = k === 'policy' ? parsed.policies : k === 'route' ? parsed.routes : parsed[k];
        refs[k] = (arr || []).filter(o => o && REF_KEYS[k].some(f => tokensOf(o[f]).some(t => labels.has(t)))).length;
      });
      const used = ips.length > 0 || refs.policy + refs.nat + refs.route + refs.vpn > 0 || !!sp.group || sp.fortilink || sp.role === 'mgmt' || sp.role === 'ha';
      out[sp.name] = { ips, alias: alias.join(' / '), zones, refs, used };
    });
    return out;
  }

  // 來源型號：deviceInfo.model 與型號資料比對（FGT100F → FG-100F；完全相同優先，其次唯一的前綴相符）
  const norm = s => String(s || '').toUpperCase().replace(/^FORTIGATE/, 'FG').replace(/^FGT/, 'FG').replace(/[^A-Z0-9]/g, '');
  function detectSourceModel(parsed) {
    const v = vendorKey(parsed);
    const raw = parsed && parsed.deviceInfo && parsed.deviceInfo.model;
    if (!v || dash(raw)) return null;
    const n = norm(raw);
    if (!n) return null;
    const list = modelsOf(v);
    const exact = list.find(m => norm(m.id) === n || norm(m.label) === n);
    if (exact) return { vendor: v, id: exact.id, raw };
    const pre = list.filter(m => norm(m.id).startsWith(n) || norm(m.label).startsWith(n));
    return pre.length === 1 ? { vendor: v, id: pre[0].id, raw } : null;
  }

  // 目標型號的保留埠：管理、HA、出廠 FortiLink 成員、出廠硬體交換器成員
  function reservedOf(model) {
    const r = Object.create(null);
    const f = model.factory || {};
    (f.fortilink || []).forEach(n => { r[n] = 'fortilink'; });
    Object.keys(f.hwswitch || {}).forEach(sw => f.hwswitch[sw].forEach(n => { if (!r[n]) r[n] = 'hwswitch:' + sw; }));
    model.ports.forEach(p => { if (p.mgmt) r[p.name] = 'mgmt'; else if (p.ha && !r[p.name]) r[p.name] = 'ha'; });
    return r;
  }

  // 自動對應：管理→管理埠；WAN→名稱含 wan 的埠，其次第一個一般埠；其餘依序對到同媒介（來源型號已知時）的一般埠；
  // 一般埠用完才用出廠 FortiLink／硬體交換器成員；來源 FortiLink 成員只在目標也是有出廠 FortiLink 的 FortiGate 時對過去
  function suggestMap(parsed, target, modelId) {
    const model = getModel(target, modelId);
    if (!model) return null;
    // 設定中沒有 IP、也沒有任何參照的埠（XN46）不自動對應，使用者仍可手動選
    const usage = portUsage(parsed);
    const src = sourcePorts(parsed).filter(s => !usage[s.name] || usage[s.name].used);
    const srcModel = detectSourceModel(parsed);
    const srcModelObj = srcModel ? getModel(srcModel.vendor, srcModel.id) : null;
    const srcMedia = n => { const p = srcModelObj && srcModelObj.ports.find(x => x.name === n); return p ? p.media : ''; };
    const res = reservedOf(model);
    const used = new Set();
    const map = Object.create(null);
    const take = p => { used.add(p.name); return p.name; };
    const free = pred => model.ports.find(p => !used.has(p.name) && pred(p));
    const general = p => !res[p.name];
    // 管理
    src.filter(s => s.role === 'mgmt').forEach(s => { const t = free(p => p.mgmt); if (t) map[s.name] = take(t); });
    // FortiLink → 目標出廠 FortiLink 埠（FortiGate 轉 FortiGate）
    const tFl = (model.factory && model.factory.fortilink) || [];
    src.filter(s => s.fortilink).forEach(s => { if (target !== 'fortigate') return; const t = free(p => tFl.includes(p.name)); if (t) map[s.name] = take(t); });
    // 目標有同名一般埠（同廠牌換型號）時直接沿用
    src.filter(s => !map[s.name] && !s.fortilink && s.role !== 'mgmt').forEach(s => { const t = free(p => p.name === s.name && !p.mgmt && !p.ha && res[p.name] !== 'fortilink'); if (t) map[s.name] = take(t); });
    // WAN
    src.filter(s => !map[s.name] && s.role === 'wan' && !s.fortilink).forEach(s => {
      const hint = WAN_HINT[target] || [];
      const t = free(p => general(p) && /wan/i.test(p.name)) || free(p => general(p) && hint.includes(p.name)) ||
        free(p => general(p) && (!srcMedia(s.name) || p.media === srcMedia(s.name))) || free(general);
      if (t) map[s.name] = take(t);
    });
    // 其餘
    src.filter(s => !map[s.name] && !s.fortilink && s.role !== 'mgmt' && s.role !== 'ha').forEach(s => {
      const m = srcMedia(s.name);
      // 非 WAN 的埠先避開 WAN 名稱與慣用 WAN 埠
      const lan = p => general(p) && !/wan/i.test(p.name) && !(WAN_HINT[target] || []).includes(p.name);
      const hw = p => !p.mgmt && !p.ha && /^hwswitch:/.test(res[p.name] || '');
      const t = (m && free(p => lan(p) && p.media === m)) || free(lan) || free(hw) || (m && free(p => general(p) && p.media === m)) || free(general) || free(p => !p.mgmt && !p.ha);
      if (t) map[s.name] = take(t);
    });
    // HA 埠只對到目標 HA 埠
    src.filter(s => s.role === 'ha').forEach(s => { const t = free(p => p.ha && !p.mgmt); if (t) map[s.name] = take(t); });
    return { model, ports: sourcePorts(parsed), usage, map, warnings: portMapWarnings(parsed, target, model, map) };
  }

  const mbps = s => { const m = String(s || '').match(/^([\d.]+)([GM])$/); return m ? parseFloat(m[1]) * (m[2] === 'G' ? 1000 : 1) : 0; };
  // 警示：{code, port?, dst?, ...}，文字由畫面依 code 翻譯
  function portMapWarnings(parsed, target, model, map) {
    const src = sourcePorts(parsed);
    const res = model ? reservedOf(model) : Object.create(null);
    const tPort = n => model && model.ports.find(p => p.name === n);
    const srcModel = detectSourceModel(parsed);
    const srcModelObj = srcModel ? getModel(srcModel.vendor, srcModel.id) : null;
    const usage = portUsage(parsed);
    const W = [];
    const seen = Object.create(null);
    src.forEach(s => {
      const d = map[s.name];
      if (s.fortilink && !d) { W.push({ code: 'fortilinkSrc', port: s.name }); return; }
      if (!d) { W.push({ code: usage[s.name] && !usage[s.name].used ? 'unusedSrc' : 'unmapped', port: s.name }); return; }
      if (seen[d]) W.push({ code: 'dupTarget', port: s.name, dst: d, other: seen[d] }); else seen[d] = s.name;
      const r = res[d];
      if (r === 'fortilink' && !s.fortilink) W.push({ code: 'fortilinkDst', port: s.name, dst: d });
      else if (r && r.startsWith('hwswitch:') && s.group !== r.slice(9)) W.push({ code: 'hwswitchDst', port: s.name, dst: d, sw: r.slice(9) });
      else if (r === 'mgmt' && s.role !== 'mgmt') W.push({ code: 'mgmtUsed', port: s.name, dst: d });
      else if (r === 'ha' && s.role !== 'ha') W.push({ code: 'haUsed', port: s.name, dst: d });
      const sp = srcModelObj && srcModelObj.ports.find(x => x.name === s.name), tp = tPort(d);
      // 媒介不同（電口／光口）或目標速度較低才提示；速度提高不提示
      if (sp && tp && (sp.media !== tp.media || mbps(tp.speed) < mbps(sp.speed))) W.push({ code: 'media', port: s.name, dst: d, from: sp.speed + ' ' + sp.media, to: tp.speed + ' ' + tp.media });
    });
    // 來源的交換器（有 IP 的邏輯介面）：其他廠牌要改用 VLAN／bridge 等方式手動建立
    const groups = new Set();
    src.forEach(s => { if (s.group) groups.add(s.group + '|' + s.groupKind); });
    groups.forEach(g => { const [name, kind] = g.split('|'); if (target !== 'fortigate' || kind === 'hardware' || kind === 'hard-switch') W.push({ code: 'switchSrc', port: name, kind }); });
    const fl = ((parsed && parsed.interfaces) || []).find(i => i.fortilink);
    if (fl && target !== 'fortigate') W.push({ code: 'fortilinkIface', port: fl.name });
    return W;
  }

  // ── 套用對應 ─────────────────────────────────────────────────────────────────
  // 介面欄位白名單：值可為字串（逗號或空白分隔多個）或字串陣列
  const IFACE_KEYS = ['name', 'interface', 'members', 'device', 'iface', 'srcIntf', 'dstIntf', 'srcIntfMembers', 'dstIntfMembers',
    'extIntf', 'outIntf', 'inIntf', 'srcIf', 'dstIf', 'intf', 'parent', 'preferredUplink', 'interfaces'];
  const ARRAYS = ['interfaces', 'policies', 'routes', 'nat', 'vpn', 'zones', 'switchGroups'];

  function renameToken(tok, map, target) {
    if (map[tok]) return map[tok];
    const m = tok.match(/^(.+?)(\.\d+)$/);
    // 子介面後綴保留；Juniper 的 .0（未標記單元）轉到其他廠牌時去掉
    if (m && map[m[1]]) return map[m[1]] + (target !== 'juniper' && m[2] === '.0' ? '' : m[2]);
    return tok;
  }
  function renameVal(v, map, target) {
    if (Array.isArray(v)) return v.map(x => typeof x === 'string' ? renameToken(x, map, target) : x);
    if (typeof v !== 'string' || v === '-') return v;
    return v.replace(/[^\s,]+/g, t => renameToken(t, map, target));
  }
  function renameObj(o, map, target, arrName) {
    if (!o || typeof o !== 'object') return o;
    const c = Object.assign({}, o);
    IFACE_KEYS.forEach(k => {
      if (!(k in c)) return;
      // name 只在介面陣列改；zones 的 name 是區域名稱、interfaces 才是成員
      if (k === 'name' && arrName !== 'interfaces') return;
      c[k] = renameVal(c[k], map, target);
    });
    return c;
  }
  function renameParsed(p, map, target) {
    const c = Object.assign({}, p);
    ARRAYS.forEach(a => { if (Array.isArray(p[a])) c[a] = p[a].map(o => renameObj(o, map, target, a)); });
    return c;
  }
  // map：{來源埠: 目標埠}；空值代表不對應（保留原名）
  function applyMap(parsed, map, target) {
    const m = Object.create(null);
    Object.keys(map || {}).forEach(k => { if (map[k] && k !== '__proto__' && k !== 'constructor' && k !== 'prototype') m[k] = String(map[k]); });
    if (!parsed || !Object.keys(m).length) return parsed;
    const out = renameParsed(parsed, m, target);
    if (Array.isArray(parsed._perVdom)) out._perVdom = parsed._perVdom.map(v => renameParsed(v, m, target));
    return out;
  }

  // ── 轉換驗證（XN40）────────────────────────────────────────────────────────────
  const intToIp = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  const REP_SRC = '198.51.100.10', REP_DST = '203.0.113.10';
  // 位址名稱 → 一個具體 IPv4（網段取第一個主機）；any → 代表位址；無法解析（FQDN、地理、使用者）回傳 null
  function sampleIp(name, addrs, vdom, rep, depth) {
    const raw = String(name || '').trim(), nm = raw.toLowerCase();
    if (!raw || nm === 'any' || nm === 'all' || nm === 'any4' || nm === '0.0.0.0/0') return rep;
    if ((depth || 0) > 8) return null;
    const lit = cidrHost(raw);
    const o = _objByName(addrs, nm, vdom);
    if (!o) return lit;
    if ((o.type === 'ipmask' || o.type === 'ipprefix') && !dash(o.subnet)) return cidrHost(o.subnet);
    if (o.type === 'iprange' && o.startIp) return _ipToInt(o.startIp) !== null ? o.startIp : null;
    if (o.type === 'group' || o.category === 'address-group') {
      for (const m of String(o.members || '').split(',').map(s => s.trim()).filter(Boolean)) { const r = sampleIp(m, addrs, vdom, rep, (depth || 0) + 1); if (r) return r; }
    }
    return null;
  }
  function cidrHost(s) {
    const m = String(s).trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\s*\/\s*(\d{1,2})|\s+(\d{1,3}(?:\.\d{1,3}){3}))?$/);
    if (!m) return null;
    const ip = _ipToInt(m[1]); if (ip === null) return null;
    const len = m[2] !== undefined ? +m[2] : m[3] ? _cidrPrefixLen(m[3]) : 32;
    if (len === null || len > 32) return null;
    if (len === 0) return null;
    const mask = len === 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - len)) >>> 0;
    const net = (ip & mask) >>> 0;
    return intToIp(len >= 31 ? ip : (net + 1) >>> 0);
  }
  // 服務名稱 → {proto, port}；ALL／any → tcp 443；無法解析回傳 null
  function sampleSvc(name, svcs, vdom, depth) {
    const raw = String(name || '').trim(), nm = raw.toLowerCase();
    if (!raw || nm === 'all' || nm === 'any' || nm === 'ip') return { proto: 'tcp', port: '443' };
    if ((depth || 0) > 8) return null;
    const lit = t => {
      t = (_BUILTIN_SVC[t] || t).toLowerCase();
      if (/^icmp/.test(t) || t === 'ping') return { proto: 'icmp', port: '' };
      const m = t.match(/^(tcp|udp|tcp-udp|tcp\/udp)\/(\d+)/);
      if (m) return { proto: m[1] === 'udp' ? 'udp' : 'tcp', port: m[2] };
      if (/^\d+$/.test(t)) return { proto: 'tcp', port: t };
      if (t === 'tcp' || t === 'udp') return { proto: t, port: '' };
      return null;
    };
    const o = _objByName(svcs, nm, vdom);
    if (!o) return lit(nm);
    if (o.category === 'group' || o.refOnly) {
      for (const m of String(o.members || '').split(',').map(s => s.trim()).filter(m => m && m !== '-')) { const r = sampleSvc(m, svcs, vdom, (depth || 0) + 1); if (r) return r; }
      return null;
    }
    const pr = String(o.proto || '').toUpperCase();
    const first = r => { const m = String(r || '').match(/\d+/); return m ? m[0] : ''; };
    if (/ICMP/.test(pr)) return { proto: 'icmp', port: '' };
    if (pr.includes('TCP') && !dash(o.tcpPorts)) return { proto: 'tcp', port: first(o.tcpPorts) };
    if (pr.includes('UDP') && !dash(o.udpPorts)) return { proto: 'udp', port: first(o.udpPorts) };
    if (!pr || pr === '-') { if (!dash(o.tcpPorts)) return { proto: 'tcp', port: first(o.tcpPorts) }; if (!dash(o.udpPorts)) return { proto: 'udp', port: first(o.udpPorts) }; }
    return null;
  }
  const firstName = s => String(s || '').split(',').map(x => x.trim()).filter(Boolean)[0] || 'any';
  const actOf = r => !r || r.error ? 'error' : r.action === 'accept' ? 'accept' : 'deny';
  const cnt = (p, k) => Array.isArray(p && p[k]) ? p[k].length : 0;
  const VERIFY_MAX = 300;

  // 以來源規則產生代表性查詢（每條啟用中、IPv4 的規則一組），在來源與轉換結果各跑一次比對動作
  function verifyConversion(srcParsed, dstParsed, opts) {
    const max = (opts && opts.max) || VERIFY_MAX;
    const counts = ['policies', 'addresses', 'services', 'routes', 'nat', 'vpn', 'interfaces'].map(k => ({ key: k, src: cnt(srcParsed, k), dst: cnt(dstParsed, k) }));
    const sAddrs = _addrsWithVips(srcParsed), sSvcs = srcParsed.services || [];
    const queries = [], skipped = [];
    for (const p of srcParsed.policies || []) {
      if (queries.length >= max) break;
      if (p.status === 'disable' || p.enabled === false || p._family === 'v6' || p._default) continue;
      const src = sampleIp(firstName(p.srcAddr), sAddrs, p._vdom, REP_SRC);
      const dst = sampleIp(firstName(p.dstAddr), sAddrs, p._vdom, REP_DST);
      const svc = sampleSvc(firstName(p.service), sSvcs, p._vdom);
      if (!src || !dst || !svc) { skipped.push({ policy: p, why: !src ? 'src' : !dst ? 'dst' : 'svc' }); continue; }
      queries.push({ policy: p, src, dst, proto: svc.proto, port: svc.port });
    }
    let same = 0, unsure = 0;
    const diffs = [];
    queries.forEach(q => {
      const a = _runPolicyQuery(q.src, q.dst, q.proto, q.port, null, srcParsed, {});
      const b = _runPolicyQuery(q.src, q.dst, q.proto, q.port, null, dstParsed, {});
      const fq = r => !!(r && (r.trace || []).some(t => t.result === 'match' && t.hasFqdn));
      if (actOf(a) === actOf(b)) { same++; if (fq(a) || fq(b)) unsure++; return; }
      diffs.push({ q, src: { action: actOf(a), rule: a && a.matched ? (a.matched.name || a.matched.id) : '' },
        dst: { action: actOf(b), rule: b && b.matched ? (b.matched.name || b.matched.id) : '' } });
    });
    return { counts, total: queries.length, same, unsure, diffs, skipped, truncated: queries.length >= max };
  }

  // ── 埠對應表 CSV（XN44）：匯出給現場接線、同型號換多台時匯入重用 ─────────────────────────
  // 第一行為 `# target_vendor=…,target_model=…` 註解；值以 =+-@ 開頭時前綴單引號（防公式注入），匯入時去掉
  const MAP_SRC_HEADS = ['source_port', 'source', 'old_port', '來源埠', '舊埠'];
  const MAP_DST_HEADS = ['target_port', 'target', 'new_port', '目標埠', '新埠'];
  const csvQ = v => {
    let s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) || s !== s.trim() ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  // meta：{target_vendor, target_model, …}；cols：欄位名稱；rows：以欄位名稱為鍵的物件
  function buildMapCsv(meta, cols, rows) {
    const head = '# ' + Object.keys(meta || {}).map(k => k + '=' + String(meta[k] == null ? '' : meta[k]).replace(/[,\r\n]/g, ' ')).join(',');
    return [head, cols.join(','), ...(rows || []).map(r => cols.map(c => csvQ(r[c])).join(','))].join('\r\n') + '\r\n';
  }
  // 引號內可含逗號與換行，故整段解析不逐行切；回傳 [{line, cells}]
  function csvRecords(text) {
    const out = []; let row = [], cur = '', q = false, line = 1, start = 1;
    const push = () => { row.push(cur); if (row.some(x => x.trim())) out.push({ line: start, cells: row }); row = []; cur = ''; };
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '"' && text[i + 1] === '"') { cur += '"'; i++; }
        else if (c === '"') q = false;
        else { if (c === '\n') line++; cur += c; }
      } else if (c === '"') q = true;
      else if (c === ',') { row.push(cur); cur = ''; }
      else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; push(); line++; start = line; }
      else cur += c;
    }
    if (cur || row.length) push();
    return out;
  }
  const unq = s => String(s == null ? '' : s).trim().replace(/^'(?=[=+\-@\t\r])/, '');
  // 回傳 {meta, rows:[{line, source, target}], errors:[{code, line}]}
  function parseMapCsv(text) {
    const meta = Object.create(null), errors = [];
    const t = String(text || '').replace(/^﻿/, '');
    const body = t.split(/\r?\n/).map(l => {
      const m = l.match(/^\s*#(.*)$/);
      if (!m) return l;
      m[1].split(',').forEach(kv => { const i = kv.indexOf('='); if (i > 0) { const k = kv.slice(0, i).trim(); if (k && k !== '__proto__') meta[k] = kv.slice(i + 1).trim(); } });
      return '';  // 保留空行讓行號對得上
    }).join('\n');
    const recs = csvRecords(body);
    if (!recs.length) return { meta, rows: [], errors: [{ code: 'empty', line: 0 }] };
    const head = recs[0].cells.map(h => unq(h).toLowerCase().replace(/\s+/g, '_'));
    const si = head.findIndex(h => MAP_SRC_HEADS.includes(h)), di = head.findIndex(h => MAP_DST_HEADS.includes(h));
    if (si < 0 || di < 0) return { meta, rows: [], errors: [{ code: 'noHeader', line: recs[0].line }] };
    const rows = recs.slice(1).map(r => ({ line: r.line, source: unq(r.cells[si]), target: unq(r.cells[di]) }));
    return { meta, rows, errors };
  }
  // 只套用來源埠存在、目標埠屬於目前型號（或留空＝不對應）的列；回傳 {map, applied, skipped:[{line, port, code}]}
  function applyMapRows(rows, sourceNames, targetNames) {
    const src = new Set(sourceNames || []), dst = new Set(targetNames || []);
    const map = Object.create(null), usedDst = Object.create(null), seen = Object.create(null), skipped = [];
    let applied = 0;
    (rows || []).forEach(r => {
      const s = r.source, d = r.target;
      const skip = code => skipped.push({ line: r.line, port: s || d || '', code });
      if (!s) return skip('noSource');
      if (s === '__proto__' || s === 'constructor' || s === 'prototype' || !src.has(s)) return skip('unknownSource');
      if (seen[s]) return skip('dupSource');
      if (d && !dst.has(d)) return skip('unknownTarget');
      if (d && usedDst[d]) return skip('dupTarget');
      seen[s] = true;
      if (d) usedDst[d] = s;
      map[s] = d;
      applied++;
    });
    return { map, applied, skipped };
  }

  // ── 轉換前後安全稽核比對（XN45）────────────────────────────────────────────────
  // before／after：{health:{score,grade}, findings:[{id,label,risk,value}]}；findings 只含該廠牌評估過的項目（不評估的不出現）。
  // 只列有變化的項目；減少或消失常是轉換器沒帶過該設定（管理介面、帳號等），狀態標 less／gone，畫面不可說成改善
  const AUDIT_RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const AUDIT_STATUS_ORDER = { new: 0, worse: 1, noeval: 2, less: 3, gone: 4 };
  function compareAudit(before, after) {
    const idx = list => { const m = Object.create(null); (list || []).forEach(f => { if (f && f.id && f.id !== '__proto__') m[f.id] = f; }); return m; };
    const b = idx(before && before.findings), a = idx(after && after.findings);
    const rows = []; let same = 0;
    [...new Set([...Object.keys(b), ...Object.keys(a)])].forEach(id => {
      const x = b[id], y = a[id];
      const bv = x ? +x.value || 0 : 0, av = y ? +y.value || 0 : 0;
      if (!bv && !av) return;
      let status;
      if (!y) status = 'noeval';
      else if (!bv) status = 'new';
      else if (av > bv) status = 'worse';
      else if (!av) status = 'gone';
      else if (av < bv) status = 'less';
      else { same++; return; }
      rows.push({ id, label: (y && y.label) || (x && x.label) || id, risk: (y && y.risk) || (x && x.risk) || '', before: x ? bv : null, after: y ? av : null, status });
    });
    rows.sort((p, q) => AUDIT_STATUS_ORDER[p.status] - AUDIT_STATUS_ORDER[q.status] || (AUDIT_RISK_ORDER[p.risk] ?? 9) - (AUDIT_RISK_ORDER[q.risk] ?? 9) || p.id.localeCompare(q.id));
    return { health: { before: before && before.health || null, after: after && after.health || null }, rows, same };
  }

  const api = { vendorKey, modelsOf, getModel, sourcePorts, portUsage, detectSourceModel, reservedOf, suggestMap, portMapWarnings, applyMap, verifyConversion, sampleIp, sampleSvc, VERIFY_MAX, buildMapCsv, parseMapCsv, applyMapRows, compareAudit };
  if (typeof window !== 'undefined') window.FwPortMap = api;
  return api;
})();
