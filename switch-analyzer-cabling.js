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
  // entries：[{hostname, parsed}]；opts.linksText＝自訂串線；opts.modelOf(parsed)＝使用者選的型號 value；opts.lldpOf(parsed)＝使用者另外貼上的鄰居（取代設定檔內的）
  function buildCabling(entries, opts) {
    const o = opts || {}, sp = SP();
    if (!sp) return null;
    const devices = (entries || []).filter(e => e && e.parsed).map((e, di) => {
      const p = e.parsed, hostname = String((p.sys && p.sys.hostname) || e.hostname || ('#' + (di + 1)));
      const pn = sp.buildPanel(p, { modelValue: (o.modelOf && o.modelOf(p)) || '' });
      const ports = pn ? pn.rows.flatMap(r => r.ports).concat(pn.extra) : [];
      const byKey = Object.create(null);
      ports.forEach(pt => { const k = portKey(pt.name); if (!(k in byKey)) byKey[k] = pt.name; });
      return { idx: di, hostname, key: hostKey(hostname), parsed: p, pn, byKey };
    });
    const devBy = Object.create(null);
    devices.forEach(d => { if (!(d.key in devBy)) devBy[d.key] = d; });
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
    devices.forEach(d => (((o.lldpOf && o.lldpOf(d.parsed)) || d.parsed.lldp) || []).forEach(n => {
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
    return { devices, external, links, unmatched, conflicts, descHints, errors };
  }

  const LINK_COLORS = { lldp: '#22c55e', confirmed: '#16a34a', custom: '#a855f7', ext: '#94a3b8' };
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
    const rows = [];
    cb.devices.forEach(d => {
      if (!d.pn) return;
      const groups = d.pn.rows.concat(d.pn.extra.length ? [{ member: '', extra: true, ports: d.pn.extra }] : []);
      groups.forEach(r => {
        const lbl = sp.shortLabels(r.ports);
        const head = d.hostname + (d.pn.model ? ' · ' + d.pn.model : '') + (r.member ? ' · ' + T('swp.member', { n: r.member }) : '') + (r.extra ? ' · ' + T('ptopo.extra_row') : '');
        rows.push({ label: head, ports: r.ports.map((p, pi) => {
          const k = sp.kindOf(p), id = 'd' + d.idx + '|' + lc(p.name);
          const tip = [d.hostname + ' ' + p.name, p.desc, p.ip ? show(p.ip) : '', (peerOf[id] || []).map(x => '↔ ' + x).join(' ')].filter(Boolean).join(' · ');
          return { id, name: p.name, label: lbl[pi], color: sp.COLORS[k], dim: (k === 'unused' || k === 'shutdown') && !peerOf[id], text: k === 'access' ? (p.vlans || '1') : k === 'trunk' ? 'T' : k === 'routed' ? 'L3' : k === 'hybrid' ? 'H' : '', badge: p.stack ? 'S' : p.poe ? 'P' : '', tip };
        }) });
      });
    });
    cb.external.forEach(x => rows.push({ label: T('ptopo.ext_row', { name: x.name }), ports: x.ports.map(p => ({ id: 'x' + x.idx + '|' + lc(p), name: p, label: p, color: '#6b7280', text: '', tip: x.name + ' ' + p })) }));
    const links = cb.links.map(l => {
      const k = linkKind(l);
      const tip = endName(cb, l.a) + ' ' + l.a.port + ' ↔ ' + endName(cb, l.b) + ' ' + l.b.port + ' · ' + T('ptopo.src_' + k) + (l.protocols.length ? ' (' + l.protocols.join('/') + ')' : '');
      return { a: (l.a.ext != null ? 'x' + l.a.ext : 'd' + l.a.dev) + '|' + lc(l.a.port), b: (l.b.ext != null ? 'x' + l.b.ext : 'd' + l.b.dev) + '|' + lc(l.b.port), color: LINK_COLORS[k], dashed: k === 'custom', tip };
    });
    return ps.render({ rows, links, separate: true });
  }

  // ── 卡片（資產清冊頁）──
  let _entries = [], _linksText = '', _lldpMsg = '';
  const _lldpOv = new WeakMap();   // parsed → 使用者貼上的鄰居（只存記憶體）
  const modelOf = p => { const sp = SP(); return (sp && sp.chosen.get(p)) || ''; };
  const lldpOf = p => _lldpOv.get(p) || null;
  const LINK_KINDS = ['lldp', 'confirmed', 'custom', 'ext'];
  const REASONS = ['local', 'remote', 'extmax'];
  function cablingHtml(entries, editorOpen) {
    const sp = SP(), ps = PS();
    if (!sp || !ps) return '';
    _entries = entries || [];
    const cb = buildCabling(_entries, { linksText: _linksText, modelOf, lldpOf });
    if (!cb || !cb.devices.length) return '';
    const box = 'background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;margin-top:16px';
    const btn = 'background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 14px;font-size:12px;cursor:pointer';
    let h = `<div id="ptopo-card" style="${box}"><div style="font-size:14px;font-weight:600;margin-bottom:4px">🔗 ${esc2(T('ptopo.title'))}</div>`
      + `<div style="font-size:12px;color:var(--text-dim);margin-bottom:6px">${esc2(T('ptopo.hint'))}</div>`;
    // 逐台型號（大多數設定檔沒有型號，讀不出時可手動選或用自訂型號）
    h += `<details data-ptopo-sec="models" style="margin-bottom:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.models', { n: cb.devices.length }))}</summary><div style="font-size:12px">`
      + cb.devices.map(d => `<div style="margin:3px 0"><b>${esc2(d.hostname)}</b>：${esc2(d.pn && d.pn.source === 'model' ? d.pn.model : T('ptopo.from_config'))} ${d.pn ? sp.modelSelectHtml(d.pn, !!modelOf(d.parsed), 'data-ptopo-model="' + d.idx + '"') : ''}</div>`).join('')
      + ps.customEditorHtml('ptopo', editorOpen) + '</div></details>';
    // 逐台貼上 LLDP／CDP 鄰居（資產清冊只讀設定檔；設定檔後面沒附鄰居輸出時在這裡補）
    h += `<details data-ptopo-sec="lldp" style="margin-bottom:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.lldp_title'))}</summary><div style="font-size:11px;color:var(--text-dim);margin:4px 0">${esc2(T('ptopo.lldp_hint'))}</div>`
      + `<select data-ptopo-lldp-dev style="width:auto;max-width:280px">${cb.devices.map(d => `<option value="${d.idx}">${esc2(d.hostname)}（${esc2(T('ptopo.lldp_count', { n: (lldpOf(d.parsed) || d.parsed.lldp || []).length }))}）</option>`).join('')}</select><br>`
      + `<textarea id="ptopo-lldp" rows="4" spellcheck="false" style="width:100%;max-width:560px;font-family:monospace;font-size:11px" placeholder="show lldp neighbors detail / show cdp neighbors detail"></textarea><br>`
      + `<button style="${btn}" data-ptopo-lldp-apply>${esc2(T('ptopo.lldp_apply'))}</button> <span style="font-size:11px">${esc2(_lldpMsg)}</span></details>`;
    h += `<div style="overflow-x:auto" data-ptopo-svg>${cablingSvg(cb)}</div>`;
    h += `<div style="font-size:11px;margin:6px 0">${ps.legend(LINK_KINDS.map(k => [LINK_COLORS[k], T('ptopo.src_' + k)]), esc2)}<span style="color:var(--text-dim)">${esc2(T('ptopo.lg_note'))}</span></div>`;
    h += `<div style="font-size:12px;margin-top:8px">${esc2(T('ptopo.custom_title'))}</div><div style="font-size:11px;color:var(--text-dim)">${esc2(T('ptopo.custom_hint'))}</div>`
      + `<textarea id="ptopo-links" rows="4" spellcheck="false" style="width:100%;max-width:560px;font-family:monospace;font-size:11px" placeholder="CORE-SW Te1/1/1 &lt;-&gt; ACCESS-SW1 Te1/1/2">${xesc(_linksText)}</textarea><br>`
      + `<button style="${btn}" data-ptopo-apply>${esc2(T('ptopo.apply'))}</button>`;
    if (cb.errors.length) h += `<div style="font-size:11px;color:var(--red,#ef4444);margin-top:4px">${cb.errors.slice(0, 10).map(e => esc2(T('pcu.line', { n: e.line }) + ' ' + T('ptopo.err_' + e.code, { tok: e.tok }))).join('<br>')}</div>`;
    if (cb.links.length) h += `<details data-ptopo-sec="links" style="margin-top:6px" open><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.links', { n: cb.links.length }))}</summary><div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>${esc2(T('ptopo.col_dev'))}</th><th>${esc2(T('ptopo.col_port'))}</th><th>${esc2(T('ptopo.col_dev'))}</th><th>${esc2(T('ptopo.col_port'))}</th><th>${esc2(T('ptopo.col_src'))}</th></tr></thead><tbody>`
      + cb.links.map(l => `<tr><td>${esc2(endName(cb, l.a))}</td><td class="mono">${esc2(l.a.port)}</td><td>${esc2(endName(cb, l.b))}</td><td class="mono">${esc2(l.b.port)}</td><td>${esc2(T('ptopo.src_' + linkKind(l)) + (l.protocols.length ? ' (' + l.protocols.join('/') + ')' : ''))}</td></tr>`).join('') + '</tbody></table></div></details>';
    else h += `<div class="nodata" style="font-size:12px">${esc2(T('ptopo.no_links'))}</div>`;
    if (cb.conflicts.length) h += `<div style="font-size:11px;color:var(--orange,#f59e0b);margin-top:4px">${esc2(T('ptopo.conflict', { list: cb.conflicts.map(c => c.host + ' ' + c.port).join('、') }))}</div>`;
    if (cb.unmatched.length) h += `<details data-ptopo-sec="unmatched" style="margin-top:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.unmatched', { n: cb.unmatched.length }))}</summary><div style="font-size:11px">`
      + cb.unmatched.map(u => esc2(`${u.host} ${u.port} → ${u.neighbor} ${u.remotePort}：${T('ptopo.reason_' + (REASONS.includes(u.reason) ? u.reason : 'local'))}`)).join('<br>') + '</div></details>';
    if (cb.descHints.length) h += `<details data-ptopo-sec="hints" style="margin-top:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('ptopo.desc_hints', { n: cb.descHints.length }))}</summary><div style="font-size:11px">`
      + cb.descHints.map(x => esc2(`${x.host} ${x.port}「${x.desc}」→ ${x.mention}`)).join('<br>') + '</div></details>';
    h += `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px"><button style="${btn}" data-ptopo-dl>${esc2(T('swp.download'))}</button>`
      + `<label style="font-size:11px"><input type="checkbox" id="ptopo-mask" checked> ${esc2(T('swp.mask'))}</label></div></div>`;
    return h;
  }
  function cablingDownloadSvg(mask) {
    const cb = buildCabling(_entries, { linksText: _linksText, modelOf, lldpOf });
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
      const sel = e.target && e.target.closest ? e.target.closest('select[data-ptopo-model]') : null;
      if (!sel) return;
      const d = _entries.filter(x => x && x.parsed)[+sel.getAttribute('data-ptopo-model')], sp = SP();
      if (!d || !sp) return;
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
        const d = sel ? _entries.filter(x => x && x.parsed)[+sel.value] : null;
        if (!d || !ta) return;
        const txt = String(ta.value).slice(0, 2000000).replace(/\r\n?/g, '\n');
        let list = [];
        try { list = typeof LLDPParser !== 'undefined' && txt.trim() ? (LLDPParser.parse(txt, d.parsed.vendor) || []).filter(n => n && n.localPort && n.neighbor) : []; } catch (er) { list = []; }
        if (txt.trim()) _lldpOv.set(d.parsed, list); else _lldpOv.delete(d.parsed);
        _lldpMsg = T('ptopo.lldp_done', { host: String((d.parsed.sys && d.parsed.sys.hostname) || d.hostname || ''), n: list.length });
        redraw(false);
        return;
      }
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
    window.addEventListener('pnl-custom', e => { if (e && e.detail && e.detail.scope === 'ptopo') redraw(true); });
  }

  const api = { lldpFromText, portKey, hostKey, parseCustomLinks, buildCabling, cablingSvg, cablingHtml, cablingDownloadSvg, LINK_KINDS, REASONS, LINK_ERR_CODES: ['syntax', 'host', 'port', 'extmax'], setLinksText: t => { _linksText = String(t || ''); } };
  if (typeof window !== 'undefined') window.SwCabling = api;
  return api;
})();
