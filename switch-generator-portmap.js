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

  const api = { speedFromName, memberOf, withMember, sourcePortsOf, targetPortsFor, suggestSwitchMap, switchMapWarnings, renameSwitchModel, adaptModelForVendor, conversionSummary, roundTripCheck, HYBRID_VENDORS, VENDOR_ONLY, buildMapCsv, parseMapCsv, applyMapRows, compareAudit };
  if (typeof window !== 'undefined') window.SwPortMap = api;
  return api;
})();
