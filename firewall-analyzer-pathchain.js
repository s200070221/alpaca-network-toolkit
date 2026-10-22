// ═══════════════════════════════════════════════════════════════════════════
// firewall-analyzer-pathchain.js — 多台防火牆路徑查詢（2026-10-22，第三十三輪 XN7）
// 純函式，依賴 core.js 的 _runPolicyQuery()／_findDestNat()／_natStage()（頂層全域），不碰 DOM。
// 每台的處理順序：決定進入介面 → 目的 NAT → 以轉換後目的查路由（靜態＋介面直連網段，最長前綴）得出口介面與
// 下一跳 → 規則比對（同時帶進入與出口介面）→ 下一跳等於另一台已載入設備的介面位址（含次要位址）就接到那一台。
// 第一階段只做 IPv4；路由只有設定檔內的靜態路由與直連網段（動態路由學到的不在設定檔）；來源 NAT 只標記不轉換；
// 只做自動串接（HA 虛擬 IP、IPsec 通道、經交換器轉送等串不起來）。這些限制由畫面以警語說明。
// 以單一全域物件 FwPath 對外，避免與其他模組的頂層識別字衝突
// ═══════════════════════════════════════════════════════════════════════════
const FwPath = (function () {
  const MAX_HOPS = 16;
  const ipInt = s => {
    const m = String(s || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m || m.slice(1).some(x => +x > 255)) return null;
    return ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + (+m[4]);
  };
  const maskLen = m => {
    const s = String(m || '').trim();
    if (/^\d{1,2}$/.test(s)) return +s <= 32 ? +s : null;
    const n = ipInt(s);
    if (n === null) return null;
    const bits = n.toString(2).padStart(32, '0');
    return /^1*0*$/.test(bits) ? bits.indexOf('0') < 0 ? 32 : bits.indexOf('0') : null;
  };
  const inNet = (ip, net, len) => {
    if (ip === null || net === null || len === null) return false;
    const mask = len === 0 ? 0 : (0xFFFFFFFF << (32 - len)) >>> 0;
    return ((ip & mask) >>> 0) === ((net & mask) >>> 0);
  };
  // 路由 dst：「位址/前綴」或「位址 點分遮罩」（FortiGate／ASA），回傳 {net, len}
  const parseDst = d => {
    const parts = String(d || '').trim().split(/\s*\/\s*|\s+/);
    const net = ipInt(parts[0]);
    const len = parts[1] === undefined ? 32 : maskLen(parts[1]);
    return net === null || len === null ? null : { net, len };
  };
  // 介面的位址清單（主要＋次要），只取 IPv4 且遮罩可解析者
  function ifaceAddrs(i) {
    return [{ ip: i.ip, mask: i.mask }].concat(i.secondaryIps || [])
      .map(a => ({ ip: ipInt(a && a.ip), len: maskLen(a && a.mask) }))
      .filter(a => a.ip !== null && a.len !== null);
  }
  function ifaceByIp(parsed, ip) {
    const n = ipInt(ip);
    if (n === null) return null;
    return (parsed.interfaces || []).find(i => ifaceAddrs(i).some(a => a.ip === n)) || null;
  }
  // 依目的位址查路由：靜態／預設路由與介面直連網段一起做最長前綴比對，同長度時直連優先
  // vdom（選填）：只看該 VDOM 的路由與介面（FortiGate 多 VDOM）
  function lookupRoute(parsed, dst, vdom) {
    const d = ipInt(dst);
    if (d === null) return null;
    const inV = x => !vdom || !x._vdom || x._vdom === vdom;
    let best = null;
    const consider = (len, cand) => { if (!best || len > best.len || (len === best.len && cand.connected && !best.connected)) best = Object.assign({ len }, cand); };
    (parsed.interfaces || []).filter(inV).forEach(i => ifaceAddrs(i).forEach(a => {
      if (a.len < 32 && inNet(d, a.ip, a.len)) consider(a.len, { connected: true, iface: i, gateway: '', route: null });
    }));
    (parsed.routes || []).filter(r => inV(r) && ['static', 'default', 'connected'].includes(r.type)).forEach(r => {
      const p = parseDst(r.dst);
      if (p && inNet(d, p.net, p.len)) consider(p.len, { connected: false, iface: null, gateway: r.gateway && r.gateway !== '-' ? r.gateway : '', route: r });
    });
    if (best && !best.connected) best.iface = egressIface(parsed, best.route, vdom);
    return best;
  }
  // 路由的出口介面：route.device 對應介面名稱或 ASA nameif；沒有時用下一跳所在的直連網段
  function egressIface(parsed, route, vdom) {
    const ifs = (parsed.interfaces || []).filter(i => !vdom || !i._vdom || i._vdom === vdom);
    const dev = String((route && route.device) || '').trim().toLowerCase();
    if (dev && dev !== '-') {
      const byName = ifs.find(i => String(i.name || '').toLowerCase() === dev || String(i.nameif || '').toLowerCase() === dev);
      if (byName) return byName;
    }
    const g = ipInt(route && route.gateway);
    if (g === null) return null;
    let best = null, bl = -1;
    ifs.forEach(i => ifaceAddrs(i).forEach(a => { if (a.len > bl && inNet(g, a.ip, a.len)) { best = i; bl = a.len; } }));
    return best;
  }
  // 規則比對用的介面名稱：規則可能以介面、區域（Juniper／Palo Alto／H3C）或 nameif（ASA）表示。
  // 依序取 nameif、zone、_zone、（Juniper 介面的 _vdom 存的是區域）、介面名稱，選第一個出現在規則該欄位的值
  function intfLabel(parsed, iface, field) {
    if (!iface) return '';
    const cands = [iface.nameif, iface.zone, iface._zone, /juniper/i.test(parsed.vendor || '') ? iface._vdom : '', iface.name].filter(Boolean).map(String);
    const used = new Set();
    (parsed.policies || []).forEach(p => String(p[field] || '').split(/\s*,\s*/).forEach(s => used.add(s.trim().toLowerCase())));
    return cands.find(c => used.has(c.toLowerCase())) || iface.name || '';
  }
  const isMultiVdom = parsed => /fortigate/i.test(parsed.vendor || '') && !!(parsed.deviceInfo && parsed.deviceInfo.isMultiVdom);
  const natOn = p => !!p && /^(enable|enabled|yes|true)$/i.test(String(p.nat || ''));
  // 起點設備：直連網段包含來源位址的第一台
  function findStart(devices, src) {
    const s = ipInt(src);
    return devices.findIndex(d => (d.parsed.interfaces || []).some(i => ifaceAddrs(i).some(a => a.len < 32 && inNet(s, a.ip, a.len))));
  }
  // devices：[{name, parsed}]；q：{src, dst, proto, port, start（選填，設備索引）}
  // 回傳 {error} 或 {start, hops:[…], result:{kind, …}}；kind：reached｜reachedDevice｜denied｜noRoute｜left｜loop｜unknown
  function trace(devices, q) {
    if (ipInt(q.src) === null || ipInt(q.dst) === null) return { error: 'invalid_ip' };
    let cur = q.start !== undefined && q.start !== null && q.start !== '' ? +q.start : findStart(devices, q.src);
    if (!(cur >= 0 && cur < devices.length)) return { error: 'no_start' };
    let dst = String(q.dst).trim(), port = q.port || '';
    const proto = q.proto || 'any', src = String(q.src).trim();
    // 第一台的進入介面：朝向來源位址的那個介面（來源的路由出口）
    let ingress = (lookupRoute(devices[cur].parsed, src) || {}).iface || null;
    const hops = [], seen = new Set();
    const startIdx = cur;
    const done = (kind, extra) => ({ start: startIdx, hops, result: Object.assign({ kind }, extra || {}) });
    for (let n = 0; n < MAX_HOPS; n++) {
      const dev = devices[cur], parsed = dev.parsed;
      const key = cur + '|' + (ingress ? ingress.name : '');
      if (seen.has(key)) return done('loop', { device: dev.name });
      seen.add(key);
      const vdom = isMultiVdom(parsed) && ingress && ingress._vdom ? ingress._vdom : null;
      const dnat = _findDestNat(dst, proto, port, parsed, { srcIntf: ingress ? ingress.name : '' });
      const stage = _natStage(parsed.vendor);
      const fwdDst = dnat ? dnat.toIp : dst, fwdPort = dnat && dnat.toPort ? dnat.toPort : port;
      const route = lookupRoute(parsed, fwdDst, vdom);
      const hop = { device: dev.name, vendor: parsed.vendor, ingress: ingress ? ingress.name : '', dst, dnat: dnat ? { toIp: dnat.toIp, toPort: dnat.toPort || '' } : null,
        natStage: stage, route: route ? { connected: route.connected, dst: route.route ? route.route.dst : '', gateway: route.gateway } : null, egress: route && route.iface ? route.iface.name : '' };
      hops.push(hop);
      if (!route) { hop.action = 'noRoute'; return done('noRoute', { device: dev.name, dst: fwdDst }); }
      // NAT 在規則比對之前（post）以轉換後位址比對，之前或不確定（pre／unknown）以原位址比對
      const qDst = dnat && stage === 'post' ? fwdDst : dst, qPort = dnat && stage === 'post' ? fwdPort : port;
      const res = _runPolicyQuery(src, qDst, proto, qPort, vdom, parsed, {
        srcIntf: intfLabel(parsed, ingress, 'srcIntf'), dstIntf: intfLabel(parsed, route.iface, 'dstIntf') }) || { action: 'implicit_deny', matched: null, trace: [] };
      const last = (res.trace || []).filter(t => t.result === 'match').pop();
      hop.rule = res.matched ? { id: res.matched.id, name: res.matched.name || '', vdom: res.matched._vdom || '', defaultRule: !!res.defaultRule } : null;
      hop.action = res.action === 'accept' ? 'accept' : (res.action === 'goto_next' ? 'unknown' : 'deny');
      hop.uncertain = !!(last && last.hasFqdn) || (!!dnat && stage === 'unknown');
      hop.snat = natOn(res.matched);
      if (hop.action === 'deny') return done('denied', { device: dev.name, rule: hop.rule });
      if (hop.action === 'unknown') return done('unknown', { device: dev.name, rule: hop.rule });
      dst = fwdDst; port = fwdPort;
      if (route.connected) {
        // 目的就是另一台已載入設備的介面位址時，標出是哪一台
        const owner = devices.findIndex((d, i) => i !== cur && ifaceByIp(d.parsed, dst));
        return done(owner >= 0 ? 'reachedDevice' : 'reached', { device: dev.name, egress: hop.egress, owner: owner >= 0 ? devices[owner].name : '' });
      }
      if (!route.gateway) return done('left', { device: dev.name, egress: hop.egress, nextHop: '' });
      const next = devices.findIndex((d, i) => i !== cur && ifaceByIp(d.parsed, route.gateway));
      if (next < 0) return done('left', { device: dev.name, egress: hop.egress, nextHop: route.gateway });
      hop.nextDevice = devices[next].name;
      ingress = ifaceByIp(devices[next].parsed, route.gateway);
      cur = next;
    }
    return done('loop', { device: devices[cur].name });
  }
  return { trace, lookupRoute, egressIface, intfLabel, ifaceByIp, findStart, MAX_HOPS };
})();
