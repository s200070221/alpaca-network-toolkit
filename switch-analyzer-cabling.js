// ── 多台設備實體接線拓樸（XN192）──────────────────────────────────────────────
// 資產清冊載入的每台設備各畫一個前面板示意（沿用 SwPanel.buildPanel()，型號可在卡片逐台選、含自訂型號），
// 再依各台的 LLDP／CDP 鄰居把埠與埠連起來；鄰居不在清冊內的列為「外部鄰居」。使用者另可自己寫接線（自訂串線），
// 與 LLDP 相同的接線標為已確認。介面描述只當補充：提到其他已載入設備名稱、卻沒有接線的埠列成提示，不畫線。
// 埠名稱比對以 portKey() 把常見縮寫（Gi／Te／XGE／Eth…）換成同一種寫法；設備名稱以 hostKey() 去網域與 CDP 序號。
// 純資料函式 buildCabling() 不碰 DOM；cablingHtml() 產生字串，所有設定檔內容一律跳脫。
(function () {
  'use strict';
  const lc = s => String(s || '').toLowerCase();
  const T = (k, p) => { let s = typeof tr === 'function' ? tr(k) : k; Object.keys(p || {}).forEach(n => { s = s.split('{' + n + '}').join(String(p[n])); }); return s; };
  const xesc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const esc2 = s => (typeof esc === 'function' ? esc(s) : xesc(s));
  const SP = () => (typeof window !== 'undefined' && window.SwPanel) || null;
  const PS = () => (typeof window !== 'undefined' && window.PanelSvg) || null;
  const EXT_MAX = 20, LINK_LINES_MAX = 500;

  // 介面名稱縮寫（依各廠牌 show 指令常見寫法：Cisco Gi／Te／Twe／Fo／Hu、Comware GE／XGE／WGE／FGE／HGE、Juniper ge-／xe-、NX-OS／Arista Eth／Et）
  const PREFIX = [
    [/^(gigabitethernet|gigabit|gige|gig|gi|ge)$/, 'gi'],
    [/^(tengigabitethernet|ten-gigabitethernet|tengige|tengig|te|xge|xe)$/, 'te'],
    [/^(twentyfivegigabitethernet|twentyfivegige|twenty-fivegige|twe|wge)$/, 'twe'],
    [/^(fortygigabitethernet|fortygige|fo|fge)$/, 'fo'],
    [/^(hundredgigabitethernet|hundredgige|hu|hge)$/, 'hu'],
    [/^(fastethernet|fa|fe)$/, 'fa'],
    [/^(ethernet|eth|et)$/, 'eth'],
    [/^(port-channel|portchannel|po)$/, 'po'],
    [/^(management|mgmt|ma)$/, 'mgmt'],
  ];
  function portKey(name) {
    const s = lc(name).trim().replace(/\s+/g, '');
    const m = s.match(/^([a-z][a-z-]*?)-?(\d.*)$/);
    if (!m) return s;
    let p = m[1];
    for (const [re, c] of PREFIX) if (re.test(p)) { p = c; break; }
    return p + m[2];
  }
  // 設備名稱：去網域（IPv4 不處理）與 CDP Device ID 結尾的序號括號
  function hostKey(h) {
    const s = lc(h).trim().replace(/\([^)]*\)$/, '');
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) ? s : s.split('.')[0];
  }

  // 自訂串線：每行「設備A 埠A <-> 設備B 埠B」（也接受 -- 或 ->），名稱含空白時改用逗號分隔「設備A,埠A,設備B,埠B」；# 之後為註解
  function parseCustomLinks(text) {
    const links = [], errors = [];
    String(text || '').replace(/\r\n?/g, '\n').split('\n').slice(0, LINK_LINES_MAX).forEach((raw, i) => {
      const line = raw.replace(/#.*$/, '').trim();
      if (!line) return;
      let f = null;
      if (line.includes(',')) { const a = line.split(',').map(x => x.trim()); if (a.length === 4 && a.every(Boolean)) f = a; }
      else { const m = line.match(/^(\S+)\s+(\S+)\s*(?:<->|<=>|--|->)\s*(\S+)\s+(\S+)$/); if (m) f = m.slice(1); }
      if (!f) { errors.push({ line: i + 1, code: 'syntax', tok: '' }); return; }
      links.push({ line: i + 1, a: { host: f[0], port: f[1] }, b: { host: f[2], port: f[3] } });
    });
    return { links, errors };
  }

  // 設定檔後面附上 show lldp／cdp neighbors detail 輸出時（Oxidized、RANCID 或手動收集常見），從同一份文字讀出鄰居。
  // 只在看到鄰居輸出專屬的欄位標題時才解析，避免把設定檔內容當成鄰居資料
  const LLDP_MARK = /^\s*(Device ID:|Local Intf:|Chassis id:|LLDP neighbor-information of port|Remote Identifier:|NeighborIndex:|LLDP Information from Neighbor:|Neighbor's chassis id:|Local Interface\s*:)/im;
  function lldpFromText(text, vendor) {
    if (typeof LLDPParser === 'undefined' || !LLDP_MARK.test(String(text || ''))) return [];
    try { return (LLDPParser.parse(String(text), vendor) || []).filter(n => n && n.localPort && n.neighbor); } catch (e) { return []; }
  }
  // 防火牆分析匯出的前面板（FwPanel.panelExport，format alpaca-panel）：逐欄檢查型別與長度，不合格整份拒絕；
  // 顏色只接受 #rrggbb，其餘欄位一律當文字（畫面與 SVG 都會跳脫）
  const IMPORT_PORT_MAX = 512, IMPORT_GROUP_MAX = 64;
  const str = (v, n) => (typeof v === 'string' && v.length <= n ? v : null);
  const color = v => (typeof v === 'string' && /^#[0-9a-f]{6}$/i.test(v) ? v : '#6b7280');
  function parsePanelExport(text) {
    let o;
    try { o = JSON.parse(String(text || '')); } catch (e) { return { ok: false, code: 'json' }; }
    if (!o || typeof o !== 'object' || o.format !== 'alpaca-panel' || o.version !== 1) return { ok: false, code: 'format' };
    const host = str(o.hostname, 64);
    if (!host || !host.trim()) return { ok: false, code: 'host' };
    if (!Array.isArray(o.ports) || !o.ports.length || o.ports.length > IMPORT_PORT_MAX) return { ok: false, code: 'ports' };
    const ports = [], seen = new Set();
    for (const p of o.ports) {
      const name = p && str(p.name, 64);
      if (!name || seen.has(lc(name))) return { ok: false, code: 'ports' };
      seen.add(lc(name));
      ports.push({ name, color: color(p.color), dim: p.dim === true, fiber: p.fiber === true, text: str(p.text, 16) || '', tip: str(p.tip, 400) || name });
    }
    const groups = (Array.isArray(o.groups) ? o.groups : []).slice(0, IMPORT_GROUP_MAX).filter(g => g && Array.isArray(g.members))
      .map(g => ({ label: str(g.label, 64) || '', color: color(g.color), dashed: g.dashed === true, members: g.members.filter(m => typeof m === 'string' && seen.has(lc(m))) }))
      .filter(g => g.members.length);
    return { ok: true, dev: { kind: o.kind === 'firewall' ? 'firewall' : 'other', hostname: host.trim(), vendor: str(o.vendor, 40) || '', model: str(o.model, 64) || '', ports, groups } };
  }
  // entries：[{hostname, parsed}]（交換器設定）或 [{imported}]（parsePanelExport 的 dev）；opts.linksText＝自訂串線；opts.modelOf(parsed)＝使用者選的型號 value；opts.lldpOf(parsed)＝使用者另外貼上的鄰居（取代設定檔內的）
  function buildCabling(entries, opts) {
    const o = opts || {}, sp = SP();
    if (!sp) return null;
    const devices = (entries || []).filter(e => e && (e.parsed || e.imported)).map((e, di) => {
      const byKey = Object.create(null);
      const keyOf = ports => ports.forEach(pt => { const k = portKey(pt.name); if (!(k in byKey)) byKey[k] = pt.name; });
      if (e.imported) { keyOf(e.imported.ports); return { idx: di, hostname: e.imported.hostname, key: hostKey(e.imported.hostname), parsed: null, imp: e.imported, src: e.imported, pn: null, byKey }; }
      const p = e.parsed, hostname = String((p.sys && p.sys.hostname) || e.hostname || ('#' + (di + 1)));
      const pn = sp.buildPanel(p, { modelValue: (o.modelOf && o.modelOf(p)) || '' });
      keyOf(pn ? pn.rows.flatMap(r => r.ports).concat(pn.extra) : []);
      return { idx: di, hostname, key: hostKey(hostname), parsed: p, imp: null, src: p, pn, byKey };
    });
    const devBy = Object.create(null), dupHosts = [];
    devices.forEach(d => { if (!(d.key in devBy)) devBy[d.key] = d; else if (!dupHosts.includes(d.hostname)) dupHosts.push(d.hostname); });
    const external = [], extBy = Object.create(null), unmatched = [], errors = [];
    const extPort = (name, port) => {
      const k = hostKey(name);
      let x = extBy[k];
      if (!x) { if (external.length >= EXT_MAX) return null; x = extBy[k] = { idx: external.length, name: String(name), ports: [], byKey: Object.create(null) }; external.push(x); }
      const pk = portKey(port || '?');
      if (!(pk in x.byKey)) { x.byKey[pk] = String(port || '?'); x.ports.push(String(port || '?')); }
      return { ext: x.idx, port: x.byKey[pk] };
    };
    const links = [], linkBy = new Map();
    const endId = e => (e.ext != null ? 'x' + e.ext : 'd' + e.dev) + '|' + lc(e.port);
    const addLink = (a, b, src, info) => {
      const ka = endId(a), kb = endId(b), key = ka < kb ? ka + '#' + kb : kb + '#' + ka;
      let l = linkBy.get(key);
      if (!l) { l = { a, b, lldp: 0, custom: false, protocols: [] }; linkBy.set(key, l); links.push(l); }
      if (src === 'lldp') { l.lldp++; if (info && info.protocol && !l.protocols.includes(info.protocol)) l.protocols.push(info.protocol); }
      else l.custom = true;
      return l;
    };
    // LLDP／CDP：本機埠以 portKey 對到面板上的埠（LLDP 表常用縮寫），鄰居名稱對到清冊內的設備
    devices.forEach(d => (((o.lldpOf && o.lldpOf(d.src)) || (d.parsed && d.parsed.lldp)) || []).forEach(n => {
      if (!n || !n.localPort || !n.neighbor) return;
      const lp = d.byKey[portKey(n.localPort)];
      if (!lp) { unmatched.push({ host: d.hostname, port: n.localPort, neighbor: n.neighbor, remotePort: n.remotePort || '', reason: 'local' }); return; }
      const peer = devBy[hostKey(n.neighbor)];
      if (peer && peer !== d) {
        const rp = peer.byKey[portKey(n.remotePort)];
        if (!rp) { unmatched.push({ host: d.hostname, port: lp, neighbor: peer.hostname, remotePort: n.remotePort || '', reason: 'remote' }); return; }
        addLink({ dev: d.idx, port: lp }, { dev: peer.idx, port: rp }, 'lldp', n);
      } else if (!peer) {
        const x = extPort(n.neighbor, n.remotePort);
        if (!x) { unmatched.push({ host: d.hostname, port: lp, neighbor: n.neighbor, remotePort: n.remotePort || '', reason: 'extmax' }); return; }
        addLink({ dev: d.idx, port: lp }, x, 'lldp', n);
      }
    }));
    // 自訂串線：設備 A 必須在清冊內；設備 B 不在清冊時列為外部鄰居
    const cl = parseCustomLinks(o.linksText);
    errors.push(...cl.errors);
    cl.links.forEach(c => {
      const da = devBy[hostKey(c.a.host)], db = devBy[hostKey(c.b.host)];
      const end = (dv, side) => { if (!dv) return null; const pn = dv.byKey[portKey(side.port)]; return pn ? { dev: dv.idx, port: pn } : false; };
      let a = end(da, c.a), b = end(db, c.b);
      if (!da && db) { const t = c.a; c.a = c.b; c.b = t; a = b; b = null; }
      if (!da && !db) { errors.push({ line: c.line, code: 'host', tok: c.a.host }); return; }
      if (a === false) { errors.push({ line: c.line, code: 'port', tok: c.a.host + ' ' + c.a.port }); return; }
      if (b === false) { errors.push({ line: c.line, code: 'port', tok: c.b.host + ' ' + c.b.port }); return; }
      if (b === null) { b = extPort(c.b.host, c.b.port); if (!b) { errors.push({ line: c.line, code: 'extmax', tok: c.b.host }); return; } }
      addLink(a, b, 'custom');
    });
    // 同一個埠出現在兩條以上的接線：中間可能有未管理的設備，或 LLDP／自訂串線有誤
    const useCnt = Object.create(null);
    links.forEach(l => [l.a, l.b].forEach(e => { const k = endId(e); useCnt[k] = (useCnt[k] || 0) + 1; }));
    const seenC = new Set(), conflicts = [];
    links.forEach(l => [l.a, l.b].forEach(e => {
      const k = endId(e);
      if (useCnt[k] > 1 && !seenC.has(k)) { seenC.add(k); conflicts.push({ host: e.ext != null ? external[e.ext].name : devices[e.dev].hostname, port: e.port }); }
    }));
    // 介面描述提到其他已載入設備的名稱（完整詞）、但這個埠沒有接線：只列提示
    const linked = new Set(links.flatMap(l => [endId(l.a), endId(l.b)]));
    const descHints = [];
    devices.forEach(d => (d.pn ? d.pn.rows.flatMap(r => r.ports).concat(d.pn.extra) : []).forEach(pt => {
      if (!pt.desc || linked.has('d' + d.idx + '|' + lc(pt.name))) return;
      const words = lc(pt.desc).split(/[^a-z0-9_.-]+/).map(w => w.replace(/^[.-]+|[.-]+$/g, '')).filter(Boolean).map(hostKey);
      const hit = devices.find(o2 => o2 !== d && o2.key && words.includes(o2.key));
      if (hit) descHints.push({ host: d.hostname, port: pt.name, desc: pt.desc, mention: hit.hostname });
    }));
    linkIssues(devices, links);
    return { devices, external, links, unmatched, conflicts, descHints, errors, dupHosts };
  }
  // 兩端都是清冊內交換器的線（LLDP 或自訂串線）：沿用 topology.js 的 checkLinkConsistency()（access／trunk、native、允許 VLAN、
  // hybrid、LACP 成員），結果放在 link.issues；設備名稱改用內部代號，避免同名或含網域時對錯設備
  function linkIssues(devices, links) {
    links.forEach(l => { l.issues = []; });
    if (typeof checkLinkConsistency !== 'function' || typeof _ljDevice !== 'function') return;
    const sw = links.filter(l => l.a.dev != null && l.b.dev != null && devices[l.a.dev].parsed && devices[l.b.dev].parsed);
    if (!sw.length) return;
    const dv = Object.create(null);
    const devOf = i => { if (!dv[i]) { const x = _ljDevice(devices[i].parsed); x.hostname = 'dev' + i; x.lldp = []; dv[i] = x; } return dv[i]; };
    sw.forEach(l => { devOf(l.b.dev); devOf(l.a.dev).lldp.push({ localPort: l.a.port, neighbor: 'dev' + l.b.dev, remotePort: l.b.port }); });
    let r;
    try { r = checkLinkConsistency(Object.keys(dv).map(k => dv[k])); } catch (e) { return; }
    const key = (h, p) => h + '|' + lc(p);
    const by = new Map();
    r.links.forEach(x => { by.set(key(x.a, x.aPort) + '#' + key(x.b, x.bPort), x.issues); by.set(key(x.b, x.bPort) + '#' + key(x.a, x.aPort), x.issues); });
    sw.forEach(l => { const iss = by.get(key('dev' + l.a.dev, l.a.port) + '#' + key('dev' + l.b.dev, l.b.port)); if (iss && iss.length) l.issues = iss; });
  }

  const LINK_COLORS = { lldp: '#22c55e', confirmed: '#16a34a', custom: '#a855f7', ext: '#94a3b8', mismatch: '#ef4444' };
  const issueText = i => T('lldp.ljissue_' + i.type).replace('{a}', i.a || '-').replace('{b}', i.b || '-');
  const linkKind = l => (l.custom && l.lldp ? 'confirmed' : l.custom ? 'custom' : l.b.ext != null || l.a.ext != null ? 'ext' : 'lldp');
  const endName = (cb, e) => (e.ext != null ? cb.external[e.ext].name : cb.devices[e.dev].hostname);
  function cablingSvg(cb, opts) {
    const sp = SP(), ps = PS(), show = s => (opts && opts.mask ? ps.maskIp(s) : String(s));
    const peerOf = Object.create(null);
    cb.links.forEach(l => {
      const ia = (l.a.ext != null ? 'x' + l.a.ext : 'd' + l.a.dev) + '|' + lc(l.a.port), ib = (l.b.ext != null ? 'x' + l.b.ext : 'd' + l.b.dev) + '|' + lc(l.b.port);
      (peerOf[ia] = peerOf[ia] || []).push(endName(cb, l.b) + ' ' + l.b.port);
      (peerOf[ib] = peerOf[ib] || []).push(endName(cb, l.a) + ' ' + l.a.port);
    });
    const rows = [], groups = [], ep = opts && opts.ep;
    let anyOv = false;
    cb.devices.forEach(d => {
      const ov = d.parsed && sp.overlayFor ? sp.overlayFor(d.parsed, ep, { strict: true }) : null;
      if (ov) anyOv = true;
      if (d.imp) {
        const ips = opts && opts.compact ? d.imp.ports.filter(p => !p.dim || peerOf['d' + d.idx + '|' + lc(p.name)]) : d.imp.ports;
        rows.push({ label: d.hostname + (d.imp.model ? ' · ' + d.imp.model : '') + ' · ' + T('ptopo.kind_' + (d.imp.kind === 'firewall' ? 'firewall' : 'other')), ports: ips.map((p, pi) => {
          const id = 'd' + d.idx + '|' + lc(p.name);
          return { id, name: p.name, label: p.name, color: p.color, dim: p.dim && !peerOf[id], fiber: p.fiber, text: p.text, tip: [show(p.tip), (peerOf[id] || []).map(x => '↔ ' + x).join(' ')].filter(Boolean).join(' · ') };
        }) });
        d.imp.groups.forEach(g => groups.push({ members: g.members.map(m => 'd' + d.idx + '|' + lc(m)), color: g.color, dashed: g.dashed, label: g.label }));
        return;
      }
      if (!d.pn) return;
      const sets = d.pn.rows.concat(d.pn.extra.length ? [{ member: '', extra: true, ports: d.pn.extra }] : []);
      sets.forEach(r0 => {
        // 精簡顯示（XN200）：只留使用中或有接線的埠
        const r = opts && opts.compact ? Object.assign({}, r0, { ports: r0.ports.filter(p => peerOf['d' + d.idx + '|' + lc(p.name)] || (sp.kindOf(p) !== 'unused' && sp.kindOf(p) !== 'shutdown')) }) : r0;
        if (!r.ports.length) return;
        const lbl = sp.shortLabels(r.ports);
        const head = d.hostname + (d.pn.model ? ' · ' + d.pn.model : '') + (r.member ? ' · ' + T('swp.member', { n: r.member }) : '') + (r.extra ? ' · ' + T('ptopo.extra_row') : '');
        rows.push({ label: head, ports: r.ports.map((p, pi) => {
          const k = sp.kindOf(p), id = 'd' + d.idx + '|' + lc(p.name);
          const tip = [d.hostname + ' ' + p.name, p.desc, p.ip ? show(p.ip) : '', (peerOf[id] || []).map(x => '↔ ' + x).join(' ')].filter(Boolean).join(' · ');
          return sp.overlayPort({ id, name: p.name, label: lbl[pi], color: sp.COLORS[k], dim: (k === 'unused' || k === 'shutdown') && !peerOf[id], text: k === 'access' ? (p.vlans || '1') : k === 'trunk' ? 'T' : k === 'routed' ? 'L3' : k === 'hybrid' ? 'H' : '', badge: p.stack ? 'S' : p.poe ? 'P' : '', tip }, ov, p.name);
        }) });
      });
    });
    cb.external.forEach(x => rows.push({ label: T('ptopo.ext_row', { name: x.name }), ports: x.ports.map(p => ({ id: 'x' + x.idx + '|' + lc(p), name: p, label: p, color: '#6b7280', text: '', tip: x.name + ' ' + p })) }));
    const links = cb.links.map(l => {
      const k = linkKind(l);
      const tip = endName(cb, l.a) + ' ' + l.a.port + ' ↔ ' + endName(cb, l.b) + ' ' + l.b.port + ' · ' + T('ptopo.src_' + k) + (l.protocols.length ? ' (' + l.protocols.join('/') + ')' : '');
      const bad = l.issues && l.issues.length;
      return { a: (l.a.ext != null ? 'x' + l.a.ext : 'd' + l.a.dev) + '|' + lc(l.a.port), b: (l.b.ext != null ? 'x' + l.b.ext : 'd' + l.b.dev) + '|' + lc(l.b.port), color: bad ? LINK_COLORS.mismatch : LINK_COLORS[k], dashed: k === 'custom', tip: bad ? tip + ' · ⚠ ' + l.issues.map(issueText).join('；') : tip };
    });
    const svg = ps.render({ rows, groups, links, separate: true });
    return opts && opts.withFlag ? { svg, overlay: anyOv } : svg;
  }

  // ── 埠層級匯出（XN195）：draw.io（每台一個容器、埠為子節點、接線連到埠）與 Mermaid（每台一個 subgraph，只列有接線的埠）──
  // 只含設備名稱、型號、埠名稱與接線來源，不含位址與描述
  // draw.io 標籤樣式為 html=1：XML 解開後會當 HTML 解讀，名稱先做 HTML 跳脫再做 XML 跳脫（與 graphToDrawio 相同，RV13）
  const xh = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const xa = s => xh(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
  // Mermaid 標籤：引號、角括號換實體碼，換行換空白、反引號換實體碼（避免成為 markdown 字串）
  const mm = s => String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').replace(/"/g, '#quot;').replace(/</g, '#lt;').replace(/>/g, '#gt;').replace(/`/g, '#96;');
  function exportGroups(cb) {
    // 依畫面相同的順序列出每台（含外部鄰居）的埠：[{title, kind, ports:[{key, name}]}]
    const out = [];
    cb.devices.forEach(d => {
      const ports = d.imp ? d.imp.ports.map(p => p.name) : d.pn ? d.pn.rows.flatMap(r => r.ports).concat(d.pn.extra).map(p => p.name) : [];
      out.push({ title: d.hostname + (d.imp ? (d.imp.model ? ' · ' + d.imp.model : '') : d.pn && d.pn.model ? ' · ' + d.pn.model : ''), kind: d.imp ? 'firewall' : 'switch', ports: ports.map(n => ({ key: 'd' + d.idx + '|' + lc(n), name: n })) });
    });
    cb.external.forEach(x => out.push({ title: x.name, kind: 'ext', ports: x.ports.map(n => ({ key: 'x' + x.idx + '|' + lc(n), name: n })) }));
    return out;
  }
  const endKey = e => (e.ext != null ? 'x' + e.ext : 'd' + e.dev) + '|' + lc(e.port);
  function cablingToDrawio(cb) {
    const PW = 56, PH = 28, G = 6, PER = 16, HEAD = 26, PADX = 10, GAPY = 60;
    const STYLE = { switch: 'fillColor=#dae8fc;strokeColor=#6c8ebf;', firewall: 'fillColor=#fff2cc;strokeColor=#d6b656;', ext: 'fillColor=#f5f5f5;strokeColor=#999999;dashed=1;' };
    const cells = [], idOf = Object.create(null);
    let y = 20, n = 0;
    exportGroups(cb).forEach((g, gi) => {
      const cols = Math.min(PER, Math.max(1, g.ports.length)), lines = Math.max(1, Math.ceil(g.ports.length / PER));
      const w = PADX * 2 + cols * (PW + G) - G, h = HEAD + lines * (PH + G) + PADX;
      const gid = 'g' + gi;
      cells.push(`<mxCell id="${gid}" value="${xa(g.title)}" style="swimlane;startSize=${HEAD};html=1;whiteSpace=wrap;${STYLE[g.kind]}" vertex="1" parent="1"><mxGeometry x="20" y="${y}" width="${w}" height="${h}" as="geometry"/></mxCell>`);
      g.ports.forEach((p, i) => {
        const id = 'p' + (n++);
        idOf[p.key] = id;
        cells.push(`<mxCell id="${id}" value="${xa(p.name)}" style="rounded=1;html=1;whiteSpace=wrap;fontSize=8;fillColor=#ffffff;" vertex="1" parent="${gid}"><mxGeometry x="${PADX + (i % PER) * (PW + G)}" y="${HEAD + Math.floor(i / PER) * (PH + G) + 4}" width="${PW}" height="${PH}" as="geometry"/></mxCell>`);
      });
      y += h + GAPY;
    });
    cb.links.forEach((l, i) => {
      const a = idOf[endKey(l.a)], b = idOf[endKey(l.b)];
      if (!a || !b) return;
      const k = linkKind(l), bad = l.issues && l.issues.length;
      const color = bad ? LINK_COLORS.mismatch : LINK_COLORS[k];
      cells.push(`<mxCell id="e${i}" value="${xa(T('ptopo.src_' + k))}" style="endArrow=none;html=1;fontSize=8;strokeWidth=2;strokeColor=${color};${k === 'custom' ? 'dashed=1;' : ''}" edge="1" parent="1" source="${a}" target="${b}"><mxGeometry relative="1" as="geometry"/></mxCell>`);
    });
    return `<mxfile host="app.diagrams.net"><diagram id="cabling" name="cabling"><mxGraphModel grid="1" gridSize="10" page="1" pageWidth="1169" pageHeight="${Math.max(827, y + 20)}"><root><mxCell id="0"/><mxCell id="1" parent="0"/>${cells.join('')}</root></mxGraphModel></diagram></mxfile>\n`;
  }
  function cablingToMermaid(cb) {
    const used = new Set(cb.links.flatMap(l => [endKey(l.a), endKey(l.b)]));
    const out = ['flowchart LR'], idOf = Object.create(null);
    let n = 0;
    exportGroups(cb).forEach((g, gi) => {
      const ps = g.ports.filter(p => used.has(p.key));
      if (!ps.length) return;
      out.push(`  subgraph g${gi}["${mm(g.title)}"]`);
      ps.forEach(p => { const id = 'p' + (n++); idOf[p.key] = id; out.push(`    ${id}["${mm(p.name)}"]`); });
      out.push('  end');
    });
    cb.links.forEach(l => {
      const a = idOf[endKey(l.a)], b = idOf[endKey(l.b)];
      if (a && b) out.push(`  ${a} ${linkKind(l) === 'custom' ? '-.-' : '---'}|"${mm(T('ptopo.src_' + linkKind(l)) + (l.issues && l.issues.length ? ' ⚠' : ''))}"| ${b}`);
    });
    return out.join('\n') + '\n';
  }

  // ── 卡片（資產清冊頁）──
  let _entries = [], _linksText = '', _lldpMsg = '', _importMsg = '', _projMsg = '', _compact = false;
  const _imported = [];   // 匯入的防火牆前面板 [{imported}]（只存記憶體）
  const IMPORT_MAX = 20;
  const _all = () => _entries.filter(x => x && x.parsed).concat(_imported);
  const _lldpOv = new WeakMap();   // parsed → 使用者貼上的鄰居（只存記憶體）
  const modelOf = p => { const sp = SP(); return (sp && sp.chosen.get(p)) || ''; };
  const lldpOf = p => _lldpOv.get(p) || null;
  const LINK_KINDS = ['lldp', 'confirmed', 'custom', 'ext'];
  const REASONS = ['local', 'remote', 'extmax'];
  function cablingHtml(entries, editorOpen) {
    const sp = SP(), ps = PS();
    if (!sp || !ps) return '';
    _entries = entries || [];
    const cb = buildCabling(_all(), { linksText: _linksText, modelOf, lldpOf });
    if (!cb || !cb.devices.length) return '';
    const box = 'background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;margin-top:16px';
    const btn = 'background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 14px;font-size:12px;cursor:pointer';
    let h = `<div id="ptopo-card" style="${box}"><div style="font-size:14px;font-weight:600;margin-bottom:4px">🔗 ${esc2(T('ptopo.title'))}</div>`
      + `<div style="font-size:12px;color:var(--text-dim);margin-bottom:6px">${esc2(T('ptopo.hint'))}</div>`;
    // 逐台型號（大多數設定檔沒有型號，讀不出時可手動選或用自訂型號）
    h += `<details data-ptopo-sec="models" style="margin-bottom:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.models', { n: cb.devices.length }))}</summary><div style="font-size:12px">`
      + cb.devices.map(d => `<div style="margin:3px 0"><b>${esc2(d.hostname)}</b>：${esc2(d.imp ? (d.imp.model || '') + ' · ' + T('ptopo.imported') : d.pn && d.pn.source === 'model' ? d.pn.model : T('ptopo.from_config'))} ${d.pn ? sp.modelSelectHtml(d.pn, !!modelOf(d.parsed), 'data-ptopo-model="' + d.idx + '"') : ''}</div>`).join('')
      + ps.customEditorHtml('ptopo', editorOpen) + '</div></details>';
    // 逐台貼上 LLDP／CDP 鄰居（資產清冊只讀設定檔；設定檔後面沒附鄰居輸出時在這裡補）
    h += `<details data-ptopo-sec="lldp" style="margin-bottom:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.lldp_title'))}</summary><div style="font-size:11px;color:var(--text-dim);margin:4px 0">${esc2(T('ptopo.lldp_hint'))}</div>`
      + `<select data-ptopo-lldp-dev style="width:auto;max-width:280px">${cb.devices.map(d => `<option value="${d.idx}">${esc2(d.hostname)}（${esc2(T('ptopo.lldp_count', { n: (lldpOf(d.src) || (d.parsed && d.parsed.lldp) || []).length }))}）</option>`).join('')}</select><br>`
      + `<textarea id="ptopo-lldp" rows="4" spellcheck="false" style="width:100%;max-width:560px;font-family:monospace;font-size:11px" placeholder="show lldp neighbors detail / show cdp neighbors detail"></textarea><br>`
      + `<button style="${btn}" data-ptopo-lldp-apply>${esc2(T('ptopo.lldp_apply'))}</button> <span style="font-size:11px">${esc2(_lldpMsg)}</span></details>`;
    // 加入防火牆：防火牆分析前面板卡片匯出的 JSON（交換器分析頁不載入防火牆解析器，改用匯出檔）
    h += `<details data-ptopo-sec="fw" style="margin-bottom:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.fw_title', { n: _imported.length }))}</summary><div style="font-size:11px;color:var(--text-dim);margin:4px 0">${esc2(T('ptopo.fw_hint'))}</div>`
      + `<input type="file" accept=".json,application/json" multiple data-ptopo-import> <span data-ptopo-import-msg style="font-size:11px">${esc2(_importMsg)}</span>`
      + _imported.map((x, i) => `<div style="font-size:12px;margin:3px 0"><b>${esc2(x.imported.hostname)}</b> ${esc2([x.imported.vendor, x.imported.model].filter(Boolean).join(' '))}（${esc2(T('pcu.ports', { n: x.imported.ports.length }))}） <button style="${btn};padding:2px 10px" data-ptopo-rm="${i}">${esc2(T('pcu.del'))}</button></div>`).join('') + '</details>';
    h += `<label style="font-size:12px"><input type="checkbox" data-ptopo-compact${_compact ? ' checked' : ''}> ${esc2(T('swp.compact'))}</label>`;
    const drawn = cablingSvg(cb, { withFlag: true, compact: _compact });
    h += `<div style="overflow-x:auto" data-ptopo-svg>${drawn.svg}</div>`;
    if (drawn.overlay) h += `<div style="font-size:11px;color:var(--text-dim)" data-ptopo-ov>${esc2(T('swp.ov_note'))}</div>`;
    const nBad = cb.links.filter(l => l.issues && l.issues.length).length;
    if (nBad) h += `<div style="font-size:12px;color:var(--red,#ef4444);margin:4px 0" data-ptopo-mismatch="${nBad}">⚠ ${esc2(T('ptopo.mismatch_n', { n: nBad }))}</div>`;
    h += `<div style="font-size:11px;margin:6px 0">${ps.legend(LINK_KINDS.map(k => [LINK_COLORS[k], T('ptopo.src_' + k)]).concat([[LINK_COLORS.mismatch, T('ptopo.lg_mismatch')]]), esc2)}<span style="color:var(--text-dim)">${esc2(T('ptopo.lg_note'))}</span></div>`;
    h += `<div style="font-size:12px;margin-top:8px">${esc2(T('ptopo.custom_title'))}</div><div style="font-size:11px;color:var(--text-dim)">${esc2(T('ptopo.custom_hint'))}</div>`
      + `<textarea id="ptopo-links" rows="4" spellcheck="false" style="width:100%;max-width:560px;font-family:monospace;font-size:11px" placeholder="CORE-SW Te1/1/1 &lt;-&gt; ACCESS-SW1 Te1/1/2">${xesc(_linksText)}</textarea><br>`
      + `<button style="${btn}" data-ptopo-apply>${esc2(T('ptopo.apply'))}</button>`;
    if (cb.errors.length) h += `<div style="font-size:11px;color:var(--red,#ef4444);margin-top:4px">${cb.errors.slice(0, 10).map(e => esc2(T('pcu.line', { n: e.line }) + ' ' + T('ptopo.err_' + e.code, { tok: e.tok }))).join('<br>')}</div>`;
    if (cb.links.length) h += `<details data-ptopo-sec="links" style="margin-top:6px" open><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.links', { n: cb.links.length }))}</summary><div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>${esc2(T('ptopo.col_dev'))}</th><th>${esc2(T('ptopo.col_port'))}</th><th>${esc2(T('ptopo.col_dev'))}</th><th>${esc2(T('ptopo.col_port'))}</th><th>${esc2(T('ptopo.col_src'))}</th><th>${esc2(T('ptopo.col_issue'))}</th></tr></thead><tbody>`
      + cb.links.map(l => `<tr${l.issues && l.issues.length ? ' data-ptopo-bad' : ''}><td>${esc2(endName(cb, l.a))}</td><td class="mono">${esc2(l.a.port)}</td><td>${esc2(endName(cb, l.b))}</td><td class="mono">${esc2(l.b.port)}</td><td>${esc2(T('ptopo.src_' + linkKind(l)) + (l.protocols.length ? ' (' + l.protocols.join('/') + ')' : ''))}</td><td style="color:var(--red,#ef4444)">${(l.issues || []).map(i => esc2(issueText(i))).join('<br>')}</td></tr>`).join('') + '</tbody></table></div></details>';
    else h += `<div class="nodata" style="font-size:12px">${esc2(T('ptopo.no_links'))}</div>`;
    if (cb.dupHosts.length) h += `<div style="font-size:11px;color:var(--orange,#f59e0b);margin-top:4px">${esc2(T('ptopo.dup_host', { list: cb.dupHosts.join('、') }))}</div>`;
    if (cb.conflicts.length) h += `<div style="font-size:11px;color:var(--orange,#f59e0b);margin-top:4px">${esc2(T('ptopo.conflict', { list: cb.conflicts.map(c => c.host + ' ' + c.port).join('、') }))}</div>`;
    if (cb.unmatched.length) h += `<details data-ptopo-sec="unmatched" style="margin-top:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.unmatched', { n: cb.unmatched.length }))}</summary><div style="font-size:11px">`
      + cb.unmatched.map(u => esc2(`${u.host} ${u.port} → ${u.neighbor} ${u.remotePort}：${T('ptopo.reason_' + (REASONS.includes(u.reason) ? u.reason : 'local'))}`)).join('<br>') + '</div></details>';
    if (cb.descHints.length) h += `<details data-ptopo-sec="hints" style="margin-top:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.desc_hints', { n: cb.descHints.length }))}</summary><div style="font-size:11px">`
      + cb.descHints.map(x => esc2(`${x.host} ${x.port}「${x.desc}」→ ${x.mention}`)).join('<br>') + '</div></details>';
    h += `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px"><button style="${btn}" data-ptopo-dl>${esc2(T('swp.download'))}</button>`
      + `<button style="${btn}" data-ptopo-exp="drawio" title="${xesc(T('ptopo.exp_tip'))}">⬇ draw.io</button><button style="${btn}" data-ptopo-exp="mermaid" title="${xesc(T('ptopo.exp_tip'))}">⬇ Mermaid</button>`
      + `<label style="font-size:11px"><input type="checkbox" id="ptopo-mask" checked> ${esc2(T('swp.mask'))}</label></div>`
      + `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px"><button style="${btn}" data-ptopo-save title="${xesc(T('ptopo.save_hint'))}">${esc2(T('ptopo.save'))}</button>`
      + `<label style="font-size:12px">${esc2(T('ptopo.load'))} <input type="file" accept=".json,application/json" data-ptopo-load></label> <span style="font-size:11px" data-ptopo-proj-msg>${esc2(_projMsg)}</span></div></div>`;
    return h;
  }
  function cablingDownloadSvg(mask) {
    const cb = buildCabling(_all(), { linksText: _linksText, modelOf, lldpOf });
    return cb && cb.devices.length ? '<?xml version="1.0" encoding="UTF-8"?>\n' + cablingSvg(cb, { mask }) : '';
  }
  // 重繪時保留各折疊區的開合狀態（依 data-ptopo-sec；自訂型號存檔後編輯區保持展開）
  const secKey = d => d.getAttribute('data-ptopo-sec') || (d.hasAttribute('data-pnl-cu') ? 'cu' : '');
  const redraw = open => {
    const c = document.getElementById('ptopo-card');
    if (!c) return;
    const st = Object.create(null);
    c.querySelectorAll('details').forEach(d => { if (secKey(d)) st[secKey(d)] = d.open; });
    c.outerHTML = cablingHtml(_entries, open);
    const n = document.getElementById('ptopo-card');
    if (n) n.querySelectorAll('details').forEach(d => { const k = secKey(d); if (k in st) d.open = st[k] || (open && k === 'cu'); });
  };
  if (typeof document !== 'undefined' && document.addEventListener) {
    document.addEventListener('change', e => {
      const cc = e.target && e.target.closest ? e.target.closest('input[data-ptopo-compact]') : null;
      if (cc) { _compact = cc.checked; redraw(false); return; }
      const sel = e.target && e.target.closest ? e.target.closest('select[data-ptopo-model]') : null;
      if (!sel) return;
      const d = _all()[+sel.getAttribute('data-ptopo-model')], sp = SP();
      if (!d || !d.parsed || !sp) return;
      const v = sel.value;
      if (v && !sp.choicesFor(sp.buildPanel(d.parsed, {}).vendor).some(m => m.value === v)) return;
      if (v) sp.chosen.set(d.parsed, v); else sp.chosen.delete(d.parsed);
      redraw(false);
    });
    document.addEventListener('click', e => {
      const t = e.target && e.target.closest ? e.target : null;
      if (!t) return;
      if (t.closest('[data-ptopo-lldp-apply]')) {
        const sel = document.querySelector('select[data-ptopo-lldp-dev]'), ta = document.getElementById('ptopo-lldp');
        const d = sel ? _all()[+sel.value] : null;
        if (!d || !ta) return;
        const key = d.parsed || d.imported, vendor = d.parsed ? d.parsed.vendor : '';
        const txt = String(ta.value).slice(0, 2000000).replace(/\r\n?/g, '\n');
        let list = [];
        try { list = typeof LLDPParser !== 'undefined' && txt.trim() ? (LLDPParser.parse(txt, vendor) || []).filter(n => n && n.localPort && n.neighbor) : []; } catch (er) { list = []; }
        if (txt.trim()) _lldpOv.set(key, list); else _lldpOv.delete(key);
        _lldpMsg = T('ptopo.lldp_done', { host: d.imported ? d.imported.hostname : String((d.parsed.sys && d.parsed.sys.hostname) || d.hostname || ''), n: list.length });
        redraw(false);
        return;
      }
      if (t.closest('[data-ptopo-exp]')) {
        const fmt = t.closest('[data-ptopo-exp]').getAttribute('data-ptopo-exp');
        const cb = buildCabling(_all(), { linksText: _linksText, modelOf, lldpOf });
        if (!cb || !cb.devices.length) return;
        const drawio = fmt === 'drawio';
        const url = URL.createObjectURL(new Blob([drawio ? cablingToDrawio(cb) : cablingToMermaid(cb)], { type: drawio ? 'application/xml' : 'text/plain' }));
        const a = document.createElement('a');
        a.href = url; a.download = drawio ? 'cabling_topology.drawio' : 'cabling_topology.mmd'; a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        return;
      }
      if (t.closest('[data-ptopo-save]')) {
        const obj = buildProject(_all(), { linksText: _linksText, modelOf, lldpOf });
        const url = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 1)], { type: 'application/json' }));
        const a = document.createElement('a');
        a.href = url; a.download = 'cabling_project.json'; a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        return;
      }
      if (t.closest('[data-ptopo-rm]')) { const i = +t.closest('[data-ptopo-rm]').getAttribute('data-ptopo-rm'); if (i >= 0 && i < _imported.length) _imported.splice(i, 1); _importMsg = ''; redraw(false); return; }
      if (t.closest('[data-ptopo-apply]')) { const ta = document.getElementById('ptopo-links'); _linksText = ta ? String(ta.value).slice(0, 50000) : ''; redraw(false); }
      else if (t.closest('[data-ptopo-dl]')) {
        const m = document.getElementById('ptopo-mask'), svg = cablingDownloadSvg(!m || m.checked);
        if (!svg) return;
        const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
        const a = document.createElement('a');
        a.href = url; a.download = 'cabling_topology.svg'; a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
    });
    // 載入接線專案（每份 5 MB 以內）
    document.addEventListener('change', e => {
      const inp = e.target && e.target.closest ? e.target.closest('input[data-ptopo-load]') : null;
      if (!inp || !inp.files || !inp.files[0]) return;
      const f = inp.files[0];
      (f.size > 5000000 ? Promise.resolve(null) : f.text().catch(() => null)).then(t => {
        const r = t == null ? { ok: false, code: 'size' } : parseProject(t);
        if (!r.ok) _projMsg = T('ptopo.proj_' + (PROJ_ERR_CODES.includes(r.code) ? r.code : 'format'));
        else { const x = applyProject(r.proj); _projMsg = T('ptopo.proj_done', { n: x.applied, m: x.missing }); }
        redraw(false);
      });
    });
    // 匯入防火牆前面板 JSON：同主機名稱覆蓋，最多 IMPORT_MAX 台；每份 2 MB 以內
    document.addEventListener('change', e => {
      const inp = e.target && e.target.closest ? e.target.closest('input[data-ptopo-import]') : null;
      if (!inp || !inp.files) return;
      const files = [...inp.files];
      Promise.all(files.map(f => (f.size > 2000000 ? Promise.resolve(null) : f.text().catch(() => null)))).then(texts => {
        const bad = [];
        texts.forEach((t, i) => {
          const r = t == null ? { ok: false, code: 'size' } : parsePanelExport(t);
          if (!r.ok) { bad.push(files[i].name + '：' + T('ptopo.imp_' + (IMPORT_ERR_CODES.includes(r.code) ? r.code : 'format'))); return; }
          const at = _imported.findIndex(x => hostKey(x.imported.hostname) === hostKey(r.dev.hostname));
          if (at >= 0) _imported[at] = { imported: r.dev };
          else if (_imported.length < IMPORT_MAX) _imported.push({ imported: r.dev });
          else bad.push(files[i].name + '：' + T('ptopo.imp_full', { n: IMPORT_MAX }));
        });
        _importMsg = bad.join('；');
        redraw(false);
      });
    });
    window.addEventListener('pnl-custom', e => { if (e && e.detail && e.detail.scope === 'ptopo') redraw(true); });
  }


  // ── 範例（?demo=cabling 與資產清冊「載入接線範例」）：合成設定，位址一律用文件用網段 ──
  // 核心交換器附 LLDP 輸出（對到兩台存取交換器之一、防火牆與一台 AP）；ACC-SW1 附 LLDP 回報核心；
  // ACC-SW2 沒有鄰居輸出、只有介面描述（示範描述提示與自訂串線）；防火牆為防火牆分析匯出的前面板格式
  const DEMO_CORE = [
    '! Sample config - RFC 5737 documentation IPs only, not a real device',
    'hostname CORE-SW', '!',
    'interface GigabitEthernet1/0/1', ' description to ACC-SW1', ' switchport mode trunk', '!',
    'interface GigabitEthernet1/0/2', ' description to ACC-SW2', ' switchport mode trunk', '!',
    'interface GigabitEthernet1/0/3', ' description FG-EDGE port2', ' switchport mode access', ' switchport access vlan 100', '!',
    'interface GigabitEthernet1/0/10', ' description server rack A', ' switchport mode access', ' switchport access vlan 20', '!',
    'interface TenGigabitEthernet1/1/1', ' description AP-LOBBY', ' switchport mode trunk', '!',
    'interface Vlan100', ' ip address 192.0.2.1 255.255.255.0', '!', 'end',
    'CORE-SW#show lldp neighbors detail',
    'Local Intf: Gi1/0/1', '  Chassis id: 0200.5e00.0011', '  Port id: Gi1/0/24', '  System Name: ACC-SW1', '  Management Addresses:', '    IP: 192.0.2.11', '',
    'Local Intf: Gi1/0/3', '  Chassis id: 0200.5e00.0021', '  Port id: port2', '  System Name: FG-EDGE', '  Management Addresses:', '    IP: 192.0.2.254', '',
    'Local Intf: Te1/1/1', '  Chassis id: 0200.5e00.0031', '  Port id: eth0', '  System Name: AP-LOBBY', '  Management Addresses:', '    IP: 192.0.2.50', ''].join('\n');
  const DEMO_ACC1 = [
    '! Sample config - RFC 5737 documentation IPs only, not a real device',
    'hostname ACC-SW1', '!',
    'interface GigabitEthernet1/0/1', ' description PC-101', ' switchport mode access', ' switchport access vlan 20', '!',
    'interface GigabitEthernet1/0/2', ' description PRINTER-01', ' switchport mode access', ' switchport access vlan 30', '!',
    'interface GigabitEthernet1/0/24', ' description uplink CORE-SW', ' switchport mode trunk', '!', 'end',
    'ACC-SW1#show lldp neighbors detail',
    'Local Intf: Gi1/0/24', '  Chassis id: 0200.5e00.0001', '  Port id: Gi1/0/1', '  System Name: CORE-SW', '  Management Addresses:', '    IP: 192.0.2.1', ''].join('\n');
  const DEMO_ACC2 = [
    '! Sample config - RFC 5737 documentation IPs only, not a real device',
    'hostname ACC-SW2', '!',
    'interface GigabitEthernet1/0/1', ' description PC-201', ' switchport mode access', ' switchport access vlan 20', '!',
    'interface GigabitEthernet1/0/24', ' description uplink CORE-SW', ' switchport mode trunk', '!', 'end'].join('\n');
  const fwPort = (name, color, text, tip, dim) => ({ name, color, dim: !!dim, fiber: false, text, tip });
  const DEMO_FW = { format: 'alpaca-panel', version: 1, kind: 'firewall', hostname: 'FG-EDGE', vendor: 'FortiGate', model: 'FG-60F',
    ports: ['internal1', 'internal2', 'internal3', 'internal4', 'internal5'].map((n, i) => fwPort(n, i < 2 ? '#3b82f6' : '#9ca3af', '', n + (i < 2 ? ' [lan]' : ''), i >= 2))
      .concat([fwPort('a', '#9ca3af', '', 'a', true), fwPort('b', '#9ca3af', '', 'b', true), fwPort('dmz', '#3b82f6', '', 'dmz 198.51.100.1/24'),
        fwPort('wan1', '#f59e0b', '', 'wan1 203.0.113.2/30'), fwPort('wan2', '#9ca3af', '', 'wan2', true)]),
    groups: [{ label: 'lan', color: '#ef4444', dashed: false, members: ['internal1', 'internal2'] }] };
  // 核心 Gi1/0/3 在 LLDP 對到防火牆 port2，但範例防火牆沒有 port2：示範「對端埠名稱對不上」，改用自訂串線接到 internal1
  // 第一行註解依目前語言（ptopo.demo_comment），其餘為範例接線
  const DEMO_LINKS = ['# CORE-SW Gi1/0/2 <-> ACC-SW2 Gi1/0/24',
    'CORE-SW Gi1/0/3 <-> FG-EDGE internal1',
    'FG-EDGE wan1 <-> ISP-ROUTER ge-0/0/0'].join('\n');
  const DEMO = { configs: [{ file: 'demo_CORE-SW.cfg', text: DEMO_CORE }, { file: 'demo_ACC-SW1.cfg', text: DEMO_ACC1 }, { file: 'demo_ACC-SW2.cfg', text: DEMO_ACC2 }], firewall: DEMO_FW, links: DEMO_LINKS };
  // 範例的防火牆與自訂串線帶進卡片狀態（交換器設定由 app 的 invAddTexts() 加入清冊）
  function loadDemoExtras() {
    const r = parsePanelExport(JSON.stringify(DEMO_FW));
    if (r.ok) { const at = _imported.findIndex(x => hostKey(x.imported.hostname) === hostKey(r.dev.hostname)); if (at >= 0) _imported[at] = { imported: r.dev }; else _imported.push({ imported: r.dev }); }
    _linksText = '# ' + String(T('ptopo.demo_comment')).replace(/[\r\n]+/g, ' ') + '\n' + DEMO_LINKS;
    _importMsg = '';
  }

  // ── 接線專案（XN194）：自訂串線、逐台型號、貼上的鄰居、匯入的防火牆前面板存成一個 JSON（不含設定檔原文、不存 localStorage）──
  // 自訂型號以名稱記錄（id 只在本機有效），載入時對到同名的本機自訂型號；鄰居只存埠與名稱，不存位址
  const PROJ_MAX_LLDP = 2000;
  function buildProject(entries, state) {
    const sp = SP(), st = state || {}, devs = (entries || []).filter(e => e && (e.parsed || e.imported));
    const hostOf = e => (e.imported ? e.imported.hostname : String((e.parsed.sys && e.parsed.sys.hostname) || e.hostname || ''));
    const customs = PS() ? PS().customModels() : [];
    const models = [], lldp = [];
    devs.forEach(e => {
      if (e.parsed && st.modelOf) {
        const v = st.modelOf(e.parsed);
        if (v) { const cu = customs.find(m => m.value === v); models.push(cu ? { host: hostOf(e), custom: cu.label } : { host: hostOf(e), value: v }); }
      }
      const ov = st.lldpOf ? st.lldpOf(e.parsed || e.imported) : null;
      if (ov) lldp.push({ host: hostOf(e), neighbors: ov.slice(0, PROJ_MAX_LLDP).map(n => ({ localPort: String(n.localPort), neighbor: String(n.neighbor), remotePort: String(n.remotePort || ''), protocol: String(n.protocol || '') })) });
    });
    return { format: 'alpaca-cabling', version: 1, links: String(st.linksText || ''), models, lldp, firewalls: devs.filter(e => e.imported).map(e => Object.assign({ format: 'alpaca-panel', version: 1 }, e.imported)) };
  }
  // 逐欄檢查；不合格的項目整份拒絕（回傳 code），合格時回傳整理後的資料
  function parseProject(text) {
    let o;
    try { o = JSON.parse(String(text || '')); } catch (e) { return { ok: false, code: 'json' }; }
    if (!o || typeof o !== 'object' || o.format !== 'alpaca-cabling' || o.version !== 1) return { ok: false, code: 'format' };
    const links = o.links == null ? '' : str(o.links, 50000);
    if (links == null) return { ok: false, code: 'format' };
    const arr = v => (v == null ? [] : Array.isArray(v) ? v : null);
    const ms = arr(o.models), ls = arr(o.lldp), fs = arr(o.firewalls);
    if (!ms || !ls || !fs || ms.length > 200 || ls.length > 200 || fs.length > IMPORT_MAX) return { ok: false, code: 'format' };
    const models = [];
    for (const m of ms) {
      const host = m && str(m.host, 64), v = m && (m.value != null ? str(m.value, 120) : null), cu = m && (m.custom != null ? str(m.custom, 40) : null);
      if (!host || (!v && !cu)) return { ok: false, code: 'format' };
      models.push({ host, value: v || '', custom: cu || '' });
    }
    const lldp = [];
    for (const g of ls) {
      const host = g && str(g.host, 64);
      if (!host || !Array.isArray(g.neighbors) || g.neighbors.length > PROJ_MAX_LLDP) return { ok: false, code: 'format' };
      const nb = [];
      for (const n of g.neighbors) {
        const lp = n && str(n.localPort, 128), ne = n && str(n.neighbor, 128);
        if (!lp || !ne) return { ok: false, code: 'format' };
        nb.push({ localPort: lp, neighbor: ne, remotePort: str(n.remotePort, 128) || '', protocol: str(n.protocol, 16) || '' });
      }
      lldp.push({ host, neighbors: nb });
    }
    const firewalls = [];
    for (const f of fs) { const r = parsePanelExport(JSON.stringify(f)); if (!r.ok) return { ok: false, code: 'firewall' }; firewalls.push(r.dev); }
    return { ok: true, proj: { links, models, lldp, firewalls } };
  }
  // 套用到目前清冊：主機名稱對不上的項目略過並計數；型號只接受該設備可選清單內的值
  function applyProject(proj) {
    const sp = SP(), ps = PS();
    _imported.length = 0;
    proj.firewalls.slice(0, IMPORT_MAX).forEach(d => _imported.push({ imported: d }));
    _linksText = proj.links;
    const all = _all(), byHost = Object.create(null);
    all.forEach(e => { const h = hostKey(e.imported ? e.imported.hostname : (e.parsed.sys && e.parsed.sys.hostname) || e.hostname || ''); if (h && !(h in byHost)) byHost[h] = e; });
    let applied = 0, missing = 0;
    proj.models.forEach(m => {
      const e = byHost[hostKey(m.host)];
      if (!e || !e.parsed || !sp) { missing++; return; }
      const choices = sp.choicesFor(sp.buildPanel(e.parsed, {}).vendor);
      const v = m.custom ? ((ps ? ps.customModels() : []).find(c => c.label === m.custom) || {}).value : m.value;
      if (v && choices.some(c => c.value === v)) { sp.chosen.set(e.parsed, v); applied++; } else missing++;
    });
    proj.lldp.forEach(g => { const e = byHost[hostKey(g.host)]; if (!e) { missing++; return; } _lldpOv.set(e.parsed || e.imported, g.neighbors); applied++; });
    return { applied, missing };
  }
  // 清冊清除時一併清掉（RV12：原本匯入的防火牆與串線留在記憶體，下次載入設定檔又出現）
  function reset() { _imported.length = 0; _linksText = ''; _lldpMsg = ''; _importMsg = ''; _projMsg = ''; }

  const IMPORT_ERR_CODES = ['json', 'format', 'host', 'ports', 'size'];
  const PROJ_ERR_CODES = ['json', 'format', 'firewall', 'size'];
  const api = { cablingToDrawio, cablingToMermaid, buildProject, parseProject, applyProject, reset, PROJ_ERR_CODES, linkIssues, DEMO, loadDemoExtras, parsePanelExport, IMPORT_ERR_CODES, lldpFromText, portKey, hostKey, parseCustomLinks, buildCabling, cablingSvg, cablingHtml, cablingDownloadSvg, LINK_KINDS, REASONS, LINK_ERR_CODES: ['syntax', 'host', 'port', 'extmax'], setLinksText: t => { _linksText = String(t || ''); } };
  if (typeof window !== 'undefined') window.SwCabling = api;
  return api;
})();
