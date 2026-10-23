// ═══════════════════════════════════════════════════════════════════════════
// firewall-analyzer-pathchain.js — 多台防火牆路徑查詢（2026-10-22 第一階段、2026-10-23 第二階段，XN7）
// 純函式，依賴 core.js 的 _runPolicyQuery()／_findDestNat()／_natStage()（頂層全域），不碰 DOM。
// 每台的處理順序：決定進入介面 → 目的 NAT → 以轉換後目的查路由（設定檔靜態＋介面直連網段，或使用者貼上的路由表；
// 最長前綴）得出口介面與下一跳 → 規則比對（同時帶進入與出口介面）→ 來源 NAT（FortiGate／ASA／netfilter／MikroTik 轉換，
// 其餘只標記）→ 下一跳等於另一台已載入設備的介面位址（含次要位址）就接到那一台，否則查手動串接對應表。
// 只做 IPv4；HA 虛擬 IP、IPsec 通道、經 L3 交換器轉送等由使用者以對應表串接。限制由畫面以警語說明。
// 以單一全域物件 FwPath 對外，避免與其他模組的頂層識別字衝突
// ═══════════════════════════════════════════════════════════════════════════
const FwPath = (function () {
  const MAX_HOPS = 16;
  const ipInt = s => {
    const m = String(s || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m || m.slice(1).some(x => +x > 255)) return null;
    return ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + (+m[4]);
  };
  const intIp = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
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
  function ifaceByName(parsed, name) {
    const n = String(name || '').trim().toLowerCase();
    if (!n) return null;
    return (parsed.interfaces || []).find(i => String(i.name || '').toLowerCase() === n || String(i.nameif || '').toLowerCase() === n) || null;
  }
  const isBlackhole = r => r.type === 'blackhole' || r.blackhole === 'enable' || r.gateway === 'blackhole';
  const distOf = r => { const d = parseFloat(r && r.distance); return Number.isFinite(d) ? d : null; };
  // 依目的位址查路由：靜態／預設路由與介面直連網段一起做最長前綴比對；同長度時直連優先，其次 distance 小者。
  // vdom（選填）：只看該 VDOM 的路由與介面（FortiGate 多 VDOM）。
  // pasted（選填）：使用者貼上的路由表（parseRouteTable() 的 routes），有的話取代設定檔內的路由，介面直連網段仍保留
  function lookupRoute(parsed, dst, vdom, pasted) {
    const d = ipInt(dst);
    if (d === null) return null;
    const inV = x => !vdom || !x._vdom || x._vdom === vdom;
    let best = null;
    const consider = (len, cand) => {
      if (best && len < best.len) return;
      if (best && len === best.len) {
        if (best.connected && !cand.connected) return;
        if (best.connected === cand.connected) { const a = distOf(cand.route), b = distOf(best.route); if (a === null || b === null || a >= b) return; }
      }
      best = Object.assign({ len }, cand);
    };
    (parsed.interfaces || []).filter(inV).forEach(i => ifaceAddrs(i).forEach(a => {
      if (a.len < 32 && inNet(d, a.ip, a.len)) consider(a.len, { connected: true, iface: i, gateway: '', route: null });
    }));
    const list = pasted ? pasted.filter(r => ['static', 'default', 'connected', 'dynamic', 'blackhole'].includes(r.type))
      : (parsed.routes || []).filter(r => inV(r) && ['static', 'default', 'connected'].includes(r.type) && r.status !== 'disable');
    list.forEach(r => {
      const p = parseDst(r.dst);
      if (!p || !inNet(d, p.net, p.len)) return;
      const bh = isBlackhole(r), conn = !!pasted && r.type === 'connected';
      consider(p.len, { connected: conn, blackhole: bh, iface: null, gateway: !bh && r.gateway && r.gateway !== '-' ? r.gateway : '', route: r, pasted: !!pasted });
    });
    if (best && best.route && !best.blackhole) {
      best.iface = egressIface(parsed, best.route, vdom);
      // 貼上的路由表的介面名稱在設定檔找不到時（例如路由表顯示 Vlan40、設定檔沒有），以名稱建立暫代的介面，讓規則比對仍可用名稱
      if (!best.iface && best.route.device && best.route.device !== '-') best.iface = { name: best.route.device, _pseudo: true };
    }
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

  // ── 貼上的路由表（2026-10-23，XN7 第二階段）──────────────────────────────
  // 格式依 networktocode/ntc-templates tests 的真實輸出（副本在 test_config/ntc_*.txt）：
  // cisco：FortiGate get router info routing-table all、Cisco ASA show route、Cisco IOS show ip route、
  //        VyOS／EdgeRouter show ip route、Check Point Gaia show route（代碼＋前綴＋via 下一跳, 介面／is directly connected, 介面）
  // panos：Palo Alto show routing route；comware：H3C／HPE display ip routing-table；linux：ip route；
  // mikrotik：/ip route print detail。Juniper show route、pfSense netstat -rn 沒有可查證的範例，不支援。
  // 回傳 {format, routes:[{type, dst:'網段/長度', gateway, device, distance, ecmp, vr}], skipped}；
  // type：connected｜static｜dynamic｜blackhole。本機位址（L、H、/32 Direct）與迴路位址不收
  const IP_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
  const cidrOf = (ip, len) => { const n = ipInt(ip); return n === null || len === null || len === undefined ? null : intIp(len === 0 ? 0 : (n & ((0xFFFFFFFF << (32 - len)) >>> 0)) >>> 0) + '/' + len; };
  function detectRouteFormat(text) {
    if (/^\s*destination\s+nexthop\s+metric\s+flags/im.test(text)) return 'panos';
    if (/Destination\/Mask\s+Proto\s+Pre\s+Cost/i.test(text)) return 'comware';
    if (/dst-address=/.test(text)) return 'mikrotik';
    if (/^(?:default|\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)\s+(?:via\s+\S+\s+)?dev\s+\S+/m.test(text)) return 'linux';
    if (/via\s+\d{1,3}(?:\.\d{1,3}){3}|is directly connected/.test(text)) return 'cisco';
    return '';
  }
  function parseRouteTable(text, parsed) {
    const t = String(text || '').replace(/\r\n?/g, '\n');
    const format = detectRouteFormat(t);
    const out = { format, routes: [], skipped: 0 };
    if (format === 'cisco') parseCiscoStyle(t, parsed, out);
    else if (format === 'panos') parsePanos(t, out);
    else if (format === 'comware') parseComware(t, out);
    else if (format === 'linux') parseLinux(t, out);
    else if (format === 'mikrotik') parseMikrotik(t, out);
    return out;
  }
  // via 之後的「下一跳, 介面, 時間…」：介面取第一個以英文字母開頭、不是 cost／age 的欄位；EdgeRouter 的 (recursive is directly connected, 介面)
  function ciscoVia(rest) {
    const m = rest.match(/via\s+(\d{1,3}(?:\.\d{1,3}){3})(.*)$/);
    if (!m) return null;
    const rec = m[2].match(/recursive (?:is directly connected|via \S+),?\s*([^\s,)]+)/);
    const dev = rec ? rec[1] : (m[2].split(',').map(x => x.trim()).find(x => /^[A-Za-z]/.test(x) && !/^(cost|age|recursive)\b/i.test(x)) || '');
    return { gateway: m[1], device: dev.split(/\s/)[0] };
  }
  function parseCiscoStyle(t, parsed, out) {
    const addrs = (parsed && parsed.addresses) || [];
    let subLen = null, pending = null;
    // 路由代碼（S、O*E2、O IA、D EX、i L2、*> …）：1～4 字元且含英文字母或 * >
    const CODE_RE = /^(?=.*[A-Za-z*>])[A-Za-z0-9*>+%]{1,4}$/;
    const finish = (r, rest) => {
      // rest：前綴之後的文字；回傳 true 表示已確定下一跳
      const dist = (rest.match(/\[(\d+)\/\d+\]/) || [])[1];
      if (dist !== undefined) r.distance = dist;
      if (/\bis a summary\b|\bdiscard\b|\bNull0\b/i.test(rest)) { r.type = 'blackhole'; return true; }
      const v = ciscoVia(rest);
      if (v) { r.gateway = v.gateway; r.device = v.device; return true; }
      const dc = rest.match(/is directly connected,?\s*([^\s,)]+)?/);
      if (dc) { r.device = dc[1] || ''; if (r.type !== 'static') r.type = 'connected'; return !!r.device; }
      return false;
    };
    for (const line of t.split('\n')) {
      if (!line.trim()) { pending = null; continue; }
      const hdr = line.match(/^\s+(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2}) is (variably )?subnetted/);
      if (hdr) { subLen = hdr[3] ? null : +hdr[2]; continue; }
      if (/^\s/.test(line)) {
        // 續行：前一筆還沒有下一跳時補上，已有則是等價多路徑（ECMP），只標記不另列
        if (pending && !pending.done) pending.done = finish(pending.r, line);
        else if (pending && /via\s|directly connected/.test(line)) pending.r.ecmp = true;
        continue;
      }
      if (/^(Codes|Flags|Gateway of last resort|Routing table for|IP Route Table)\b/i.test(line)) continue;
      const tok = line.trim().split(/\s+/);
      let k = 0;
      while (k < tok.length && k < 4 && CODE_RE.test(tok[k]) && !IP_RE.test(tok[k])) k++;
      // ASA 物件名稱（如 SRV1）也可能符合代碼格式：後面緊接遮罩時把它退回當目的
      if (k >= 2 && /^255\./.test(tok[k] || '')) k--;
      if (k === 0 || k >= tok.length) continue;
      const code = tok.slice(0, k).join(' ').replace(/[*>]/g, '').trim();
      let ip = tok[k], len = null, consumed = 1;
      const cm = ip.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
      if (cm) { ip = cm[1]; len = +cm[2]; }
      else if (IP_RE.test(ip)) {
        if (tok[k + 1] && IP_RE.test(tok[k + 1]) && maskLen(tok[k + 1]) !== null && /^255\.|^0\.0\.0\.0$/.test(tok[k + 1])) { len = maskLen(tok[k + 1]); consumed = 2; }
        else len = subLen;
      } else if (tok[k + 1] && maskLen(tok[k + 1]) !== null && IP_RE.test(tok[k + 1])) {
        // ASA 以物件名稱顯示目的（names／object）：以設定檔的位址物件換回位址，查不到就略過
        const o = addrs.find(a => String(a.name) === ip);
        const sub = o ? String(o.subnet || '').split(/[\/\s]/)[0] : '';
        if (!IP_RE.test(sub)) { out.skipped++; continue; }
        ip = sub; len = maskLen(tok[k + 1]); consumed = 2;
      } else continue;
      if (len === null) { out.skipped++; continue; }
      // L（ASA／IOS 本機位址）不收
      if (/^L$/.test(code)) { out.skipped++; pending = null; continue; }
      const type = /^C/.test(code) ? 'connected' : /^S/.test(code) ? 'static' : 'dynamic';
      const r = { type, dst: cidrOf(ip, len), gateway: '', device: '', code };
      const rest = tok.slice(k + consumed).join(' ');
      const done = finish(r, rest);
      if (r.type === 'connected' && /^lo/i.test(r.device)) { out.skipped++; pending = null; continue; }
      out.routes.push(r);
      pending = { r, done };
    }
  }
  function parsePanos(t, out) {
    let cols = null, vr = '';
    for (const line of t.split('\n')) {
      const v = line.match(/^\s*VIRTUAL ROUTER:\s*(\S+)/i);
      if (v) { vr = v[1]; continue; }
      if (/^\s*destination\s+nexthop\s+metric\s+flags/i.test(line)) {
        cols = ['nexthop', 'metric', 'flags', 'age', 'interface', 'next-AS'].map(c => line.indexOf(c));
        continue;
      }
      if (!cols || !/^\s*\d{1,3}(?:\.\d{1,3}){3}\/\d/.test(line)) continue;
      const cut = (a, b) => line.slice(cols[a], b === undefined ? undefined : cols[b]).trim();
      const dst = line.slice(0, cols[0]).trim(), nh = cut(0, 1), flags = cut(2, 3), dev = cut(4, 5);
      if (!/A/.test(flags) || /H/.test(flags)) { out.skipped++; continue; }
      const m = dst.match(/^(\S+)\/(\d+)$/);
      const r = { type: nh === 'discard' ? 'blackhole' : /C/.test(flags) ? 'connected' : /S/.test(flags) ? 'static' : 'dynamic',
        dst: cidrOf(m[1], +m[2]), gateway: /C/.test(flags) || nh === 'discard' || !IP_RE.test(nh) ? '' : nh, device: dev, vr };
      if (r.dst) out.routes.push(r);
    }
  }
  function parseComware(t, out) {
    let last = null;
    for (const line of t.split('\n')) {
      const tok = line.trim().split(/\s+/);
      const m = tok[0] && tok[0].match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
      let proto, nh, dev;
      if (m && tok.length >= 6) { proto = tok[1]; nh = tok[4]; dev = tok[5]; }
      else if (!m && /^\s/.test(line) && last && tok.length >= 2 && IP_RE.test(tok[tok.length - 2])) { last.ecmp = true; continue; }
      else continue;
      const len = +m[2];
      if (/^InLoop/i.test(dev) || (/^Direct$/i.test(proto) && len === 32)) { out.skipped++; last = null; continue; }
      const r = { type: /^NULL/i.test(dev) ? 'blackhole' : /^Direct$/i.test(proto) ? 'connected' : /^Static$/i.test(proto) ? 'static' : 'dynamic',
        dst: cidrOf(m[1], len), gateway: '', device: dev, distance: tok[2] };
      if (r.type === 'static' || r.type === 'dynamic') r.gateway = IP_RE.test(nh) && nh !== '0.0.0.0' ? nh : '';
      out.routes.push(r); last = r;
    }
  }
  function parseLinux(t, out) {
    let last = null;
    for (const line of t.split('\n')) {
      if (/^\s+nexthop\s/.test(line)) { if (last) last.ecmp = true; continue; }
      const tok = line.trim().split(/\s+/);
      if (!tok[0]) continue;
      let i = 0, type = '';
      if (/^(broadcast|local|unreachable|prohibit|throw|multicast|anycast|nat)$/.test(tok[0])) { out.skipped++; continue; }
      if (tok[0] === 'blackhole') { type = 'blackhole'; i = 1; }
      const dstTok = tok[i] === 'default' ? '0.0.0.0/0' : tok[i];
      const m = String(dstTok || '').match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
      if (!m) continue;
      if (/\blinkdown\b/.test(line)) { out.skipped++; continue; }
      const kv = k => { const j = tok.indexOf(k); return j >= 0 ? tok[j + 1] || '' : ''; };
      const via = kv('via'), dev = kv('dev'), metric = kv('metric');
      const r = { type: type || (via ? 'static' : 'connected'), dst: cidrOf(m[1], m[2] === undefined ? 32 : +m[2]), gateway: type ? '' : via, device: dev };
      if (metric) r.distance = metric;
      if (/^lo$/.test(dev)) { out.skipped++; continue; }
      out.routes.push(r); last = r;
    }
  }
  function parseMikrotik(t, out) {
    // 每筆以「序號 旗標」開頭，key=value 可能續到下一行；旗標 A＝使用中、X＝停用、C＝直連、B＝黑洞
    const entries = t.split(/\n(?=\s*\d+\s)/);
    for (const e of entries) {
      const head = e.match(/^\s*\d+\s+([A-Za-z ]*?)\s*(?:;;;|dst-address=)/);
      if (!head) continue;
      const flags = head[1].replace(/\s/g, '');
      const kv = k => { const m = e.match(new RegExp('(?:^|\\s)' + k + '=(\\S+)')); return m ? m[1] : ''; };
      if (/X/.test(flags) || !/A/.test(flags) || kv('routing-mark') || kv('routing-table') && kv('routing-table') !== 'main') { out.skipped++; continue; }
      const m = kv('dst-address').match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
      if (!m) continue;
      const gw = kv('gateway').replace(/%.*$/, ''), tp = kv('type');
      const r = { type: /^(blackhole|unreachable|prohibit)$/.test(tp) || /B/.test(flags) ? 'blackhole' : /C/.test(flags) ? 'connected' : /S/.test(flags) ? 'static' : 'dynamic',
        dst: cidrOf(m[1], +m[2]), gateway: '', device: kv('vrf-interface'), distance: kv('distance') };
      if (r.type !== 'blackhole') {
        if (IP_RE.test(gw)) { r.gateway = r.type === 'connected' ? '' : gw; const via = e.match(/(?:reachable|recursive) via\s+(?:\d{1,3}(?:\.\d{1,3}){3}\s+)?([A-Za-z][\w.-]*)/); if (via) r.device = r.device || via[1]; }
        else r.device = gw;
      }
      out.routes.push(r);
    }
  }

  // ── 手動串接對應表（2026-10-23，XN7 第二階段）─────────────────────────────
  // 每行「來源設備, 下一跳位址或出口介面, 目的設備, 進入介面」（逗號或 Tab 分隔；設備可寫名稱或 #序號；# 開頭的行為註解）。
  // names：設備名稱陣列（#序號對應其順序）。回傳 {links:[{from, via, to, ingress, line}], errors:[{line, reason}]}，
  // reason：fields｜from_device｜to_device｜self
  function parseLinkMap(text, names) {
    const links = [], errors = [];
    const dev = s => {
      const v = String(s || '').trim(), m = v.match(/^#(\d+)$/);
      if (m) return +m[1] >= 1 && +m[1] <= names.length ? +m[1] - 1 : -1;
      return names.findIndex(n => String(n).toLowerCase() === v.toLowerCase());
    };
    String(text || '').replace(/\r\n?/g, '\n').split('\n').forEach((raw, i) => {
      const line = raw.trim();
      if (!line || (line.startsWith('#') && !/^#\d+\s*[,\t]/.test(line))) return;
      const p = line.split(/\s*[,\t]\s*/);
      if (p.length < 4 || p.slice(0, 4).some(x => !x)) { errors.push({ line: i + 1, reason: 'fields' }); return; }
      const from = dev(p[0]), to = dev(p[2]);
      if (from < 0) { errors.push({ line: i + 1, reason: 'from_device' }); return; }
      if (to < 0) { errors.push({ line: i + 1, reason: 'to_device' }); return; }
      if (from === to) { errors.push({ line: i + 1, reason: 'self' }); return; }
      links.push({ from, via: p[1].toLowerCase(), to, ingress: p[3], line: i + 1 });
    });
    return { links, errors };
  }

  // ── 來源 NAT（2026-10-23，XN7 第二階段）─────────────────────────────────
  // 只轉換 NAT 資料含比對條件的廠牌：FortiGate（規則 nat enable＋ippool）、Cisco ASA（twice／object NAT）、
  // Linux netfilter（SNAT／MASQUERADE）、MikroTik（srcnat）。回傳 null（不做來源 NAT）、
  // {exempt:true}（命中免轉換規則）或 {toIp, how, name, note}；note：range（位址池取第一個）｜noIp（出口介面沒有位址）｜
  // cond（比對條件無法判斷，toIp 為空）
  const SNAT_VENDOR_RE = /^(FortiGate|Cisco ASA|Cisco FTD|Linux netfilter|MikroTik)$/;
  const snatSupported = vendor => String(vendor || '').split(' + ').every(v => SNAT_VENDOR_RE.test(v.trim()));
  // 位址條件（any、單一位址、網段、範圍或位址物件）是否包含 ip；無法判斷回傳 null
  function addrHas(v, ip, addrs) {
    const s = String(v || '').trim(), n = ipInt(ip);
    if (!s || s === '-' || /^(any|any4|all|0\.0\.0\.0\/0)$/i.test(s)) return true;
    const rg = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (rg) return n >= ipInt(rg[1]) && n <= ipInt(rg[2]);
    const p = parseDst(s);
    if (p) return inNet(n, p.net, p.len);
    const o = (addrs || []).find(a => String(a.name) === s);
    if (o && o.type !== 'group') return addrHas(o.subnet, ip, []);
    return null;
  }
  const firstIp = v => (String(v || '').match(/\d{1,3}(?:\.\d{1,3}){3}/) || [''])[0];
  const ifaceIp = i => (i && i.ip && ipInt(i.ip) !== null ? i.ip : '');
  const sameIf = (a, iface) => { const s = String(a || '').trim().toLowerCase(); return !s || s === '-' || s === 'any' || (!!iface && [iface.name, iface.nameif].filter(Boolean).some(x => String(x).toLowerCase() === s)); };
  function findSourceNat(parsed, ctx) {
    const vendor = String(parsed.vendor || ''), nat = (parsed.nat || []).filter(n => n && n.status !== 'disable');
    const addrs = parsed.addresses || [], eg = ctx.egress;
    const viaIface = (how, name) => { const ip = ifaceIp(eg); return { toIp: ip, how, name: name || '', note: ip ? '' : 'noIp' }; };
    if (/^FortiGate$/.test(vendor)) {
      const r = ctx.rule;
      if (!natOn(r)) return null;
      if (r.ippool === 'enable' && r.poolname && r.poolname !== '-') {
        const pn = String(r.poolname).split(/\s*,\s*/)[0].replace(/^"|"$/g, '');
        const pool = nat.find(n => n.type === 'ippool' && n.name === pn && (!r._vdom || !n._vdom || n._vdom === r._vdom));
        if (pool && ipInt(pool.startIp) !== null) return { toIp: pool.startIp, how: 'ippool', name: pn, note: pool.endIp && pool.endIp !== '-' && pool.endIp !== pool.startIp ? 'range' : '' };
        return { toIp: '', how: 'ippool', name: pn, note: 'noIp' };
      }
      return viaIface('iface');
    }
    if (/^Cisco (ASA|FTD)$/.test(vendor)) {
      for (const n of nat) {
        if (!['static', 'dynamic', 'nonat'].includes(n.type) || !n.origSrc) continue;
        if (!sameIf(n.srcIf, ctx.ingress) || !sameIf(n.dstIf, eg)) continue;
        const has = addrHas(n.origSrc, ctx.src, addrs);
        if (has === false) continue;
        // 條件無法判斷（位址群組等）或 twice NAT 另帶 destination 條件：視為可能轉換、位址不確定
        if (has === null || n.twiceDst) return { toIp: '', how: 'nat', name: n.name || `NAT #${n.id}`, note: 'cond' };
        if (n.type === 'nonat') return { exempt: true };
        const ts = String(n.transSrc || '').trim();
        if (/^interface$/i.test(ts)) return viaIface('iface', n.name);
        if (ts === n.origSrc) return { exempt: true };
        // 網段對網段的 static：保留主機位移（10.1.1.5 → 192.0.2.5）
        const o1 = parseDst((addrs.find(a => a.name === n.origSrc) || {}).subnet || n.origSrc), o2 = parseDst((addrs.find(a => a.name === ts) || {}).subnet || ts);
        if (n.type === 'static' && o1 && o2 && o1.len === o2.len && o1.len < 32) {
          const mask = o1.len === 0 ? 0 : (0xFFFFFFFF << (32 - o1.len)) >>> 0;
          return { toIp: intIp(((o2.net & mask) | (ipInt(ctx.src) & ~mask)) >>> 0), how: 'nat', name: n.name || `NAT #${n.id}`, note: '' };
        }
        const single = _natSingleIp(ts, addrs);
        if (single) return { toIp: single, how: 'nat', name: n.name || `NAT #${n.id}`, note: '' };
        const o = addrs.find(a => a.name === ts), f = firstIp(o ? o.subnet : ts);
        return { toIp: f, how: 'nat', name: n.name || `NAT #${n.id}`, note: f ? 'range' : 'noIp' };
      }
      return null;
    }
    if (/^(Linux netfilter|MikroTik)$/.test(vendor)) {
      const mk = vendor === 'MikroTik';
      for (const n of nat) {
        if (n.type !== 'ippool') continue;
        const out = mk ? n.outIntf : n.extIntf;
        if (!sameIf(out, eg) || (mk && !sameIf(n.srcIntf, ctx.ingress))) continue;
        const hs = addrHas(n.extIp, ctx.src, []), hd = n.matchDst ? addrHas(n.matchDst, ctx.dst, []) : true;
        if (hs === false || hd === false) continue;
        if (hs === null || hd === null) return { toIp: '', how: 'nat', name: n.name, note: 'cond' };
        if (mk && n.poolType === 'accept') return { exempt: true };
        if (n.mapIp === 'masquerade') return viaIface('masquerade', n.name);
        const f = firstIp(n.mapIp);
        if (!f) return { toIp: '', how: 'nat', name: n.name, note: 'noIp' };
        return { toIp: f, how: 'nat', name: n.name, note: /-/.test(n.mapIp) || /\/(?!32)\d/.test(n.mapIp) ? 'range' : '' };
      }
      return null;
    }
    return null;
  }

  // devices：[{name, parsed, routes（選填，貼上的路由表）}]；q：{src, dst, proto, port, start（選填，設備索引）}；
  // opts：{links（parseLinkMap() 的 links，索引對應 devices）}
  // 回傳 {error} 或 {start, hops:[…], result:{kind, …}}；kind：reached｜reachedDevice｜denied｜noRoute｜blackhole｜left｜loop｜unknown
  function trace(devices, q, opts) {
    if (ipInt(q.src) === null || ipInt(q.dst) === null) return { error: 'invalid_ip' };
    let cur = q.start !== undefined && q.start !== null && q.start !== '' ? +q.start : findStart(devices, q.src);
    if (!(cur >= 0 && cur < devices.length)) return { error: 'no_start' };
    const links = (opts && opts.links) || [];
    let dst = String(q.dst).trim(), port = q.port || '', src = String(q.src).trim();
    const proto = q.proto || 'any';
    // 第一台的進入介面：朝向來源位址的那個介面（來源的路由出口）
    let ingress = (lookupRoute(devices[cur].parsed, src, null, devices[cur].routes) || {}).iface || null;
    const hops = [], seen = new Set();
    const startIdx = cur;
    const done = (kind, extra) => ({ start: startIdx, hops, result: Object.assign({ kind }, extra || {}) });
    const linkFor = (from, keys) => { for (const k of keys) { const l = k && links.find(x => x.from === from && x.via === String(k).toLowerCase()); if (l) return l; } return null; };
    for (let n = 0; n < MAX_HOPS; n++) {
      const dev = devices[cur], parsed = dev.parsed;
      const key = cur + '|' + (ingress ? ingress.name : '');
      if (seen.has(key)) return done('loop', { device: dev.name, count: n });
      seen.add(key);
      const vdom = isMultiVdom(parsed) && ingress && ingress._vdom ? ingress._vdom : null;
      const dnat = _findDestNat(dst, proto, port, parsed, { srcIntf: ingress ? ingress.name : '' });
      const stage = _natStage(parsed.vendor);
      const fwdDst = dnat ? dnat.toIp : dst, fwdPort = dnat && dnat.toPort ? dnat.toPort : port;
      const route = lookupRoute(parsed, fwdDst, vdom, dev.routes);
      const hop = { device: dev.name, vendor: parsed.vendor, ingress: ingress ? ingress.name : '', src, dst, dnat: dnat ? { toIp: dnat.toIp, toPort: dnat.toPort || '' } : null,
        natStage: stage, route: route ? { connected: route.connected, dst: route.route ? route.route.dst : '', gateway: route.gateway, pasted: !!route.pasted } : null,
        egress: route && route.iface ? route.iface.name : '' };
      hops.push(hop);
      if (!route) { hop.action = 'noRoute'; return done('noRoute', { device: dev.name, dst: fwdDst }); }
      if (route.blackhole) { hop.action = 'blackhole'; return done('blackhole', { device: dev.name, dst: fwdDst }); }
      // NAT 在規則比對之前（post）以轉換後位址比對，之前或不確定（pre／unknown）以原位址比對
      const qDst = dnat && stage === 'post' ? fwdDst : dst, qPort = dnat && stage === 'post' ? fwdPort : port;
      const res = _runPolicyQuery(src, qDst, proto, qPort, vdom, parsed, {
        srcIntf: intfLabel(parsed, ingress, 'srcIntf'), dstIntf: intfLabel(parsed, route.iface, 'dstIntf') }) || { action: 'implicit_deny', matched: null, trace: [] };
      const last = (res.trace || []).filter(t => t.result === 'match').pop();
      hop.rule = res.matched ? { id: res.matched.id, name: res.matched.name || '', vdom: res.matched._vdom || '', defaultRule: !!res.defaultRule } : null;
      hop.action = res.action === 'accept' ? 'accept' : (res.action === 'goto_next' ? 'unknown' : 'deny');
      hop.uncertain = !!(last && last.hasFqdn) || (!!dnat && stage === 'unknown');
      if (hop.action === 'deny') return done('denied', { device: dev.name, rule: hop.rule });
      if (hop.action === 'unknown') return done('unknown', { device: dev.name, rule: hop.rule });
      // 來源 NAT：支援的廠牌換算轉換後位址，之後各跳以新來源比對；其餘廠牌只在規則啟用 NAT 時標記
      hop.snat = false; hop.snatTo = '';
      if (snatSupported(parsed.vendor)) {
        const sn = findSourceNat(parsed, { src, dst: fwdDst, ingress, egress: route.iface, rule: res.matched });
        if (sn && !sn.exempt) {
          hop.snat = true; hop.snatTo = sn.toIp; hop.snatHow = sn.how; hop.snatName = sn.name || ''; hop.snatNote = sn.note || '';
          if (sn.toIp) src = sn.toIp;
        }
      } else hop.snat = natOn(res.matched);
      dst = fwdDst; port = fwdPort;
      if (route.connected) {
        // 目的就是另一台已載入設備的介面位址時，標出是哪一台
        const owner = devices.findIndex((d, i) => i !== cur && ifaceByIp(d.parsed, dst));
        return done(owner >= 0 ? 'reachedDevice' : 'reached', { device: dev.name, egress: hop.egress, owner: owner >= 0 ? devices[owner].name : '' });
      }
      let next = route.gateway ? devices.findIndex((d, i) => i !== cur && ifaceByIp(d.parsed, route.gateway)) : -1, nextIngress = null;
      if (next >= 0) nextIngress = ifaceByIp(devices[next].parsed, route.gateway);
      else {
        // 自動串接失敗：依下一跳、再依出口介面查手動對應表（HA 虛擬 IP、IPsec 通道、中間經 L3 交換器）
        const l = linkFor(cur, [route.gateway, hop.egress]);
        if (!l || !devices[l.to]) return done('left', { device: dev.name, egress: hop.egress, nextHop: route.gateway });
        next = l.to; hop.link = 'manual';
        nextIngress = ifaceByName(devices[next].parsed, l.ingress) || { name: l.ingress, _pseudo: true };
      }
      hop.nextDevice = devices[next].name;
      ingress = nextIngress;
      cur = next;
    }
    return done('loop', { device: devices[cur].name, count: MAX_HOPS });
  }
  return { trace, lookupRoute, egressIface, intfLabel, ifaceByIp, findStart, parseRouteTable, parseLinkMap, findSourceNat, snatSupported, MAX_HOPS };
})();
