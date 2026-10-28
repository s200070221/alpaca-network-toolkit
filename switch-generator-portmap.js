// ── 交換器跨廠牌轉換：目標型號埠對應（XN39）與轉換摘要（XN40 交換器部分）────────────────
// 純函式，全域 SwPortMap。輸入為產生器 collectModel() 的 model；型號資料由呼叫端傳入
// （findDeviceModel()／expandDeviceModelPorts()，switch-generator-validate.js）。
// 改名只改白名單欄位（PORT_KEYS），VLAN 編號等數字字串不會被誤換（Extreme／ProCurve 的埠名稱就是數字）。
(function () {
  'use strict';

  const SPEED_MBPS = s => { const m = String(s || '').match(/^([\d.]+)\s*([GM])/i); return m ? parseFloat(m[1]) * (/g/i.test(m[2]) ? 1000 : 1) : 1000; };
  // 介面名稱可判斷速度時以名稱為準（Cisco／Comware／Juniper 命名）
  function speedFromName(name) {
    const n = String(name || '');
    if (/^(Hundred|HundredGig|Hu\d)/i.test(n)) return '100G';
    if (/^(Forty|Fo\d)|^et-/i.test(n)) return '40G';
    if (/^(TwentyFive|Twe\d)/i.test(n)) return '25G';
    if (/^(Ten-?Gig|TenGig|Te\d|XGE|xe-)/i.test(n)) return '10G';
    if (/^(FiveGig)/i.test(n)) return '5G';
    if (/^(TwoGig|mge-)/i.test(n)) return '2.5G';
    if (/^(Gigabit|GE\d|Gi\d|ge-|FastEthernet|Fa\d)/i.test(n)) return '1G';
    return '';
  }
  const MGMT_RE = /^(M-Gigabit|M-GE|mgmt|Management|me0|em0|vme|fxp0|oobm)/i;
  const isMgmtName = n => MGMT_RE.test(n) || /^(GigabitEthernet0\/0|FastEthernet0)$/.test(n);
  // 堆疊成員編號：只認三段式（a/b/c、ge-a/b/c）或 Extreme 的 n:m；兩段式（Gi0/1、Arista Ethernet5/1）不視為堆疊
  function memberOf(name) {
    const n = String(name || '');
    let m = n.match(/^\D*?(\d+)\/\d+\/\d+$/);
    if (m) return +m[1];
    m = n.match(/^(\d+):\d+$/);
    return m ? +m[1] : null;
  }
  // 把名稱的成員編號換成 member
  function withMember(name, member) {
    const n = String(name);
    if (/^\D*?\d+\/\d+\/\d+$/.test(n)) return n.replace(/^(\D*?)\d+/, '$1' + member);
    if (/^\d+:\d+$/.test(n)) return n.replace(/^\d+/, String(member));
    return null;
  }

  // 來源實體埠：介面表＋LACP 成員（未列在介面表者）
  function sourcePortsOf(model) {
    const out = [], seen = new Set();
    const lacpOf = Object.create(null);
    (model.lacp || []).forEach(g => (g.members || []).forEach(m => { lacpOf[m] = g.id; }));
    const add = (name, i) => {
      if (!name || seen.has(name)) return;
      seen.add(name);
      const speed = speedFromName(name) || (i && i.speed) || '1G';
      const use = [];
      if (i) {
        if (i.mode === 'trunk') use.push('trunk' + (i.trunkVlans ? ' ' + i.trunkVlans : ''));
        else if (i.mode === 'hybrid') use.push('hybrid');
        else if (i.accessVlan) use.push('access ' + i.accessVlan);
      }
      if (lacpOf[name]) use.push('LAG ' + lacpOf[name]);
      out.push({ name, speed, mgmt: isMgmtName(name), member: memberOf(name), use: use.join('; ') });
    };
    (model.interfaces || []).forEach(i => add(i.name, i));
    Object.keys(lacpOf).forEach(n => add(n, null));
    return out;
  }

  // 目標埠清單（含堆疊複製）：targetPorts 為 expandDeviceModelPorts() 結果；members 為來源成員數
  function targetPortsFor(targetPorts, members) {
    const base = targetPorts.map(p => memberOf(p.name)).find(x => x !== null);
    const list = targetPorts.map(p => Object.assign({}, p, { member: 0 }));
    if (members <= 1) return { ports: list, replicated: true };
    if (base === undefined) return { ports: list, replicated: false };
    for (let k = 1; k < members; k++) {
      targetPorts.forEach(p => {
        if (p.mgmt) return;
        const nm = withMember(p.name, base + k);
        if (nm) list.push(Object.assign({}, p, { name: nm, member: k }));
      });
    }
    return { ports: list, replicated: true };
  }

  // 建議對應：管理→管理；每個堆疊成員內，高速埠先挑（上行不被 1G 埠占走），同速度優先、其次較高速度
  function suggestSwitchMap(model, targetPorts) {
    const src = sourcePortsOf(model);
    const memberIds = [...new Set(src.filter(s => !s.mgmt && s.member !== null).map(s => s.member))].sort((a, b) => a - b);
    const idx = s => s.member === null ? 0 : Math.max(0, memberIds.indexOf(s.member));
    const tp = targetPortsFor(targetPorts, Math.max(1, memberIds.length));
    const used = new Set(), map = Object.create(null);
    const take = p => { used.add(p.name); return p.name; };
    src.filter(s => s.mgmt).forEach(s => { const t = tp.ports.find(p => p.mgmt && !used.has(p.name)); if (t) map[s.name] = take(t); });
    const data = src.filter(s => !s.mgmt).map((s, i) => ({ s, i })).sort((a, b) => SPEED_MBPS(b.s.speed) - SPEED_MBPS(a.s.speed) || a.i - b.i);
    data.forEach(({ s }) => {
      const k = idx(s);
      const pool = tp.ports.filter(p => !p.mgmt && !used.has(p.name) && p.member === k);
      const t = pool.find(p => SPEED_MBPS(p.speed) === SPEED_MBPS(s.speed)) || pool.find(p => SPEED_MBPS(p.speed) > SPEED_MBPS(s.speed));
      if (t) map[s.name] = take(t);
    });
    const info = { replicated: tp.replicated, members: memberIds.length };
    return { map, ports: src, targets: tp.ports, info, warnings: switchMapWarnings(model, tp.ports, map, info) };
  }

  function switchMapWarnings(model, targets, map, info) {
    const W = [], seen = Object.create(null);
    const tByName = Object.create(null);
    targets.forEach(p => { tByName[p.name] = p; });
    sourcePortsOf(model).forEach(s => {
      const d = map[s.name];
      if (!d) { W.push({ code: 'unmapped', port: s.name }); return; }
      if (seen[d]) W.push({ code: 'dupTarget', port: s.name, dst: d, other: seen[d] }); else seen[d] = s.name;
      const t = tByName[d];
      if (t && t.mgmt && !s.mgmt) W.push({ code: 'mgmtUsed', port: s.name, dst: d });
      if (t && SPEED_MBPS(t.speed) < SPEED_MBPS(s.speed)) W.push({ code: 'speedDown', port: s.name, dst: d, from: s.speed, to: t.speed });
    });
    if (info && info.members > 1 && !info.replicated) W.push({ code: 'stackNoReplicate', n: info.members });
    return W;
  }

  // ── 改名 ───────────────────────────────────────────────────────────────────
  // 值為埠名稱（字串或字串陣列）的欄位；name 只在 interfaces／sonicL3Interfaces 底下才是埠
  const PORT_KEYS = new Set(['members', 'port', 'ports', 'interface', 'interfaces', 'inInterface', 'trackIf', 'vslPorts', 'peerLink', 'localIntf', 'parentPort', 'target']);
  const NAME_PARENTS = new Set(['interfaces', 'sonicL3Interfaces']);
  function renameToken(v, map) {
    if (typeof v !== 'string' || !v) return v;
    if (map[v]) return map[v];
    const m = v.match(/^(.+?)([.:/]\d+)$/);  // 子埠／breakout（Gi1/0/49:1、port1.2、Et45/1）
    return m && map[m[1]] ? map[m[1]] + m[2] : v;
  }
  function walk(o, map, parentKey) {
    if (Array.isArray(o)) return o.map(x => walk(x, map, parentKey));
    if (!o || typeof o !== 'object') return o;
    const c = {};
    Object.keys(o).forEach(k => {
      const v = o[k];
      const isPort = PORT_KEYS.has(k) || (k === 'name' && NAME_PARENTS.has(parentKey));
      if (isPort && typeof v === 'string') c[k] = renameToken(v, map);
      else if (isPort && Array.isArray(v) && v.every(x => typeof x === 'string')) c[k] = v.map(x => renameToken(x, map));
      else c[k] = walk(v, map, k);
    });
    return c;
  }
  function renameSwitchModel(model, map) {
    const m = Object.create(null);
    Object.keys(map || {}).forEach(k => { if (map[k] && k !== '__proto__' && k !== 'constructor' && k !== 'prototype') m[k] = String(map[k]); });
    return walk(model, m, '');
  }

  // ── 換廠牌 ─────────────────────────────────────────────────────────────────
  const HYBRID_VENDORS = new Set(['comware', 'ruijie', 'planet']);
  // 只有單一廠牌會輸出的欄位（model 鍵 → 該廠牌）
  const VENDOR_ONLY = { mlag: 'arista', vpc: 'cisco_nxos', brocadeQos: 'brocade', extremeQos: 'extreme', routerosAcl: 'routeros', routerosQos: 'routeros',
    stack: 'ruijie', sonicL3Interfaces: 'sonic', sonicQos: 'sonic', sonicStpVlanIntf: 'sonic', planetMacAcl: 'planet', comwareIrf: 'comware',
    ciscoStack: 'cisco', brocadeStack: 'brocade', alcatelStack: 'alcatel', arubaVsf: 'aruba', dellVlt: 'dell-os10', procurveVsf: 'procurve' };
  const VXLAN_VENDORS = new Set(['comware', 'aruba']);
  function hasData(v) {
    if (v == null) return false;
    if (Array.isArray(v)) return v.some(hasData);
    if (typeof v === 'object') return Object.keys(v).some(k => k !== 'domain' && k !== 'mode' && hasData(v[k]));
    if (typeof v === 'boolean') return v;
    return String(v).trim() !== '';
  }
  // target：產生器 vendor 下拉值（h3c 視為 comware＋brand h3c）
  function adaptModelForVendor(model, target) {
    const notes = [];
    const vendor = target === 'h3c' ? 'comware' : target;
    const out = Object.assign({}, model, { vendor, brand: target === 'h3c' ? 'h3c' : '' });
    if (!HYBRID_VENDORS.has(vendor)) {
      out.interfaces = (model.interfaces || []).map(i => {
        if (i.mode !== 'hybrid') return i;
        const h = i.hybrid || {};
        const vl = [...new Set([...(h.untagged || []), ...(h.tagged || [])].filter(Boolean))];
        notes.push({ code: 'hybridToTrunk', port: i.name, pvid: h.pvid || '' });
        return Object.assign({}, i, { mode: 'trunk', nativeVlan: h.pvid || '', trunkVlans: vl.join(','), hybrid: { pvid: '', untagged: [], tagged: [] } });
      });
    }
    if ((model.breakouts || []).length && model.vendor !== vendor) { notes.push({ code: 'breakoutDropped', n: model.breakouts.length }); out.breakouts = []; }
    return { model: out, notes };
  }

  // ── 轉換摘要（XN40 交換器部分）──────────────────────────────────────────────
  // unsupported／incapable：VENDOR_UNSUPPORTED／VENDOR_INCAPABLE 的目標廠牌清單
  function conversionSummary(before, after, unsupported, incapable) {
    const un = new Set([...(unsupported || []), ...(incapable || [])]);
    const dh = m => (m.dhcp || []);
    const ifMode = (m, md) => (m.interfaces || []).filter(i => (i.mode || 'access') === md).length;
    const rows = [
      ['vlans', m => (m.vlans || []).length],
      ['ifAccess', m => ifMode(m, 'access')], ['ifTrunk', m => ifMode(m, 'trunk')], ['ifHybrid', m => ifMode(m, 'hybrid')],
      ['lacp', m => (m.lacp || []).length], ['lacpMembers', m => (m.lacp || []).reduce((a, g) => a + (g.members || []).length, 0)],
      ['routes', m => (m.routes || []).length, 'routes'], ['ospf', m => (m.ospf || []).reduce((a, o) => a + (o.areas || []).length, 0)],
      ['bgp', m => (m.bgp || []).reduce((a, b) => a + (b.peers || []).length, 0), 'bgp'], ['rip', m => (m.rip || []).length, 'rip'],
      ['vrrp', m => (m.vrrp || []).length, 'vrrp'], ['dhcpServer', m => dh(m).filter(d => d.type === 'server').length, 'dhcpServer'],
      ['dhcpRelay', m => dh(m).filter(d => d.type === 'relay').length, 'dhcpRelay'], ['acl', m => (m.acl || []).length, 'acl'],
      ['qos', m => (m.qos || []).length, 'qos'], ['security', m => (m.security || []).length, 'security'],
      ['stpPorts', m => ((m.stp || {}).ports || []).length, 'stp'], ['users', m => (m.users || []).length],
    ].map(([key, fn, flag]) => {
      const b = fn(before), a = fn(after);
      return { key, before: b, after: a, dropped: !!(flag && un.has(flag) && a > 0) };
    }).filter(r => r.before || r.after);
    const vendorOnly = Object.keys(VENDOR_ONLY).filter(k => VENDOR_ONLY[k] !== after.vendor && hasData(before[k])).map(k => ({ key: k, vendor: VENDOR_ONLY[k] }));
    if (hasData(before.vxlan && before.vxlan.vnis) && !VXLAN_VENDORS.has(after.vendor)) vendorOnly.push({ key: 'vxlan', vendor: 'comware/aruba' });
    return { rows, vendorOnly };
  }

  // round-trip（使用者已上傳合併版交換器分析頁時）：parsed 為目標文字讀回的結果；比對 VLAN 與已對應埠的模式
  function roundTripCheck(after, parsed) {
    const vl = new Set((parsed.vlans || []).map(v => String(v.id)));
    const missingVlans = (after.vlans || []).map(v => String(v.id)).filter(id => !vl.has(id));
    const pIf = Object.create(null);
    (parsed.interfaces || []).forEach(i => { pIf[i.name] = i; });
    const ifaceDiffs = [];
    (after.interfaces || []).forEach(i => {
      const p = pIf[i.name];
      if (!p) { ifaceDiffs.push({ port: i.name, why: 'missing' }); return; }
      const mode = i.mode || 'access';
      if (p.mode && p.mode !== mode) ifaceDiffs.push({ port: i.name, why: 'mode', want: mode, got: p.mode });
    });
    return { missingVlans, ifaceDiffs, checked: (after.interfaces || []).length };
  }

  const api = { speedFromName, memberOf, withMember, sourcePortsOf, targetPortsFor, suggestSwitchMap, switchMapWarnings, renameSwitchModel, adaptModelForVendor, conversionSummary, roundTripCheck, HYBRID_VENDORS, VENDOR_ONLY };
  if (typeof window !== 'undefined') window.SwPortMap = api;
  return api;
})();
