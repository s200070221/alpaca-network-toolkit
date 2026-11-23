// ── 防火牆實體接線示意圖（XN190）──────────────────────────────────────────────
// 依型號資料（window.FW_MODELS，NetBox devicetype-library 的埠清單）畫出前面板示意，標出各埠用途：
// WAN 埠拉出外框列對外位址／PPPoE／DHCP、預設路由下一跳、綁在該埠的 VPN 對端與開在該埠的曝險服務；
// 其他埠標位址、區域、VLAN 子介面；hardware／software switch、聚合（aggregate／redundant）的成員以外框圈起來。
// 型號資料只有埠清單、沒有面板上的實際位置，排列一律是示意（依資料順序排成一列、每列 PANEL_PER_ROW 埠）。
// 讀不出型號時改用設定檔的實體埠。之後搭配 LLDP 畫實體接線拓樸時，埠物件的 neighbors 欄位留給鄰居資料。
// 純資料函式 buildPanel() 不碰 DOM；panelSvg()／panelHtml() 產生字串，所有設定檔內容一律跳脫。
(function () {
  'use strict';
  const PANEL_PER_ROW = 16;
  
  const dash = v => v == null || v === '' || v === '-';
  const lc = s => String(s || '').toLowerCase();
  const xesc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const T = (k, p) => { let s = typeof tr === 'function' ? tr(k) : k; Object.keys(p || {}).forEach(n => { s = s.split('{' + n + '}').join(String(p[n])); }); return s; };
  const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}/;
  const maskIp = s => (window.PanelSvg ? window.PanelSvg.maskIp(s) : String(s));

  // 預設路由：0.0.0.0/0 或 0.0.0.0 0.0.0.0（FortiGate）
  const isDefault = r => { const d = String((r && (r.dst || r.dest || r.prefix)) || '').trim(); return /^0\.0\.0\.0(?:\/0|\s+0\.0\.0\.0)$/.test(d) || d === 'default'; };

  // parsed → {model, source, ports:[...], extra:[...], groups:[...], wan:[...]}
  function buildPanel(parsed) {
    const PM = typeof window !== 'undefined' && window.FwPortMap;
    if (!PM || !parsed) return null;
    const det = PM.detectSourceModel(parsed);
    const model = det ? PM.getModel(det.vendor, det.id) : null;
    const sps = PM.sourcePorts(parsed), use = PM.portUsage(parsed);
    const spBy = Object.create(null), ifBy = Object.create(null);
    sps.forEach(p => { spBy[lc(p.name)] = p; });
    (parsed.interfaces || []).forEach(i => { if (i && i.name) ifBy[lc(i.name)] = i; });
    const transVdoms = new Set((parsed.transparentVdoms || []).map(lc));
    // 埠所屬 VDOM：實體埠介面的 vdom（沒有 VDOM 概念的廠牌為空）
    const vdomOf = name => { const i = ifBy[lc(name)]; const v = i && (i._vdom || i.vdom); return parsed._isMultiVdom && !dash(v) ? String(v) : ''; };
    const mk = (name, mp) => {
      const sp = spBy[lc(name)] || null, u = sp ? use[sp.name] : null;
      const role = sp && sp.role ? sp.role : mp && mp.mgmt ? 'mgmt' : mp && mp.ha ? 'ha' : '';
      return { name: sp ? sp.name : name, speed: (mp && mp.speed) || '', media: (mp && mp.media) || '', role, fortilink: !!(sp && sp.fortilink),
        group: (sp && sp.group) || '', groupKind: (sp && sp.groupKind) || '', vlans: sp ? sp.ifaces.filter(n => lc(n) !== lc(sp.name)) : [],
        ips: u ? u.ips : [], alias: u ? u.alias : '', zones: u ? u.zones : [], refs: u ? u.refs : { policy: 0, nat: 0, route: 0, vpn: 0 },
        used: !!(u && u.used), inConfig: !!sp, vdom: vdomOf(name), transparent: transVdoms.has(lc(vdomOf(name)) || (parsed._isMultiVdom ? '' : 'root')), neighbors: [] };
    };
    let ports, extra = [];
    if (model) {
      ports = model.ports.map(mp => mk(mp.name, mp));
      const known = new Set(model.ports.map(mp => lc(mp.name)));
      extra = sps.filter(p => !known.has(lc(p.name))).map(p => mk(p.name, null));
    } else ports = sps.map(p => mk(p.name, null));
    // 群組：設定檔的 hardware／software switch，與聚合介面（成員來自 sourcePorts 的 group）
    const groups = [], gBy = Object.create(null);
    ports.concat(extra).forEach(p => {
      if (!p.group) return;
      const k = lc(p.group);
      if (!gBy[k]) { gBy[k] = { name: p.group, kind: String(p.groupKind || '').toLowerCase(), members: [] }; groups.push(gBy[k]); }
      gBy[k].members.push(p.name);
    });
    // 透通（XN190）：hardware／software switch 與 bridge 成員之間是二層透通；透通模式（transparent）VDOM 的埠另成一組
    groups.forEach(g => { g.bridged = /^(hardware|software|hard-switch|switch|bridge)$/.test(g.kind); });
    const tv = Object.create(null);
    ports.concat(extra).forEach(p => { if (p.transparent) { const k = p.vdom || 'root'; (tv[k] = tv[k] || []).push(p.name); } });
    Object.keys(tv).forEach(k => groups.push({ name: 'VDOM ' + k, kind: 'transparent', members: tv[k], bridged: true }));
    // WAN 外框：角色為 wan 的埠，或有對外曝險服務的埠
    const exposed = typeof analyzeExposedServices === 'function' ? (analyzeExposedServices(parsed).items || []).filter(x => x.ext === true) : [];
    const routes = (parsed.routes || []).filter(isDefault);
    const vpns = parsed.vpn || [];
    const wan = [];
    ports.concat(extra).forEach(p => {
      const labels = new Set([lc(p.name)].concat(p.vlans.map(lc)).concat(p.group ? [lc(p.group)] : []).concat(p.zones.map(lc)));
      const hit = v => String(v == null ? '' : v).replace(/"/g, '').split(/[\s,]+/).some(t => t && labels.has(lc(t)));
      const ex = exposed.filter(x => hit(x.iface));
      if (p.role !== 'wan' && !ex.length) return;
      p.wan = true;
      const gw = routes.filter(r => hit(r.device) || hit(r.iface) || hit(r.interface)).map(r => r.gateway || r.gw || r.nexthop).filter(g => !dash(g) && g !== '0.0.0.0');
      const vp = vpns.filter(v => hit(v.iface) && !dash(v.remote) && v.remote !== '0.0.0.0').map(v => ({ name: v.name || '', remote: String(v.remote) }));
      wan.push({ port: p.name, ips: p.ips, gw: [...new Set(gw)], vpns: vp, exposed: [...new Set(ex.map(x => x.svc))] });
    });
    const vdoms = [...new Set(ports.concat(extra).map(p => p.vdom).filter(Boolean))];
    return { model: model ? model.id : '', modelRaw: (parsed.deviceInfo && parsed.deviceInfo.model) || '', source: model ? 'model' : 'config', ports, extra, groups, wan, vdoms };
  }

  const COLORS = { wan: '#f59e0b', used: '#3b82f6', unused: '#9ca3af', mgmt: '#8b5cf6', ha: '#8b5cf6', fortilink: '#10b981' };
  const GROUP_COLORS = ['#ef4444', '#14b8a6', '#eab308', '#ec4899', '#6366f1', '#84cc16'];
  // 群組種類（i18n pnl.kind_*；qa test_i18n_dynamic 依此列舉）
  const GROUP_KINDS = ['hardware', 'software', 'aggregate', 'redundant', 'bridge', 'transparent', 'other'];
  const VDOM_COLORS = ['#22d3ee', '#f472b6', '#a3e635', '#fb923c', '#c084fc', '#facc15'];
  const colorOf = p => (p.wan || p.role === 'wan' ? COLORS.wan : p.role === 'mgmt' || p.role === 'ha' ? COLORS.mgmt : p.fortilink ? COLORS.fortilink : p.used ? COLORS.used : COLORS.unused);

  // 前面板 SVG：opts.mask＝遮蔽位址（下載給他人時）。繪圖交給共用的 PanelSvg（panel-svg.js）
  function panelSvg(pn, opts) {
    const o = opts || {}, show = s => (o.mask ? maskIp(s) : String(s));
    const multi = pn.vdoms.length > 1;
    const ports = pn.ports.map(p => ({ id: lc(p.name), name: p.name, color: colorOf(p), dim: !(p.used || p.wan), fiber: /fiber|sfp|qsfp/i.test(p.media), text: p.speed,
      tip: p.name + (p.ips.length ? ' ' + show(p.ips.join(', ')) : '') + (p.zones.length ? ' [' + p.zones.join(', ') + ']' : ''),
      stripe: multi && p.vdom ? { color: VDOM_COLORS[pn.vdoms.indexOf(p.vdom) % VDOM_COLORS.length], tip: 'VDOM ' + p.vdom } : null }));
    const groups = pn.groups.map((g, gi) => ({ members: g.members.map(lc), color: GROUP_COLORS[gi % GROUP_COLORS.length], dashed: !g.bridged, label: g.name }));
    const callouts = pn.wan.map(w => {
      const lines = [w.port + (w.ips.length ? '  ' + show(w.ips.join(', ')) : '')];
      if (w.gw.length) lines.push(T('pnl.gw') + ' ' + show(w.gw.join(', ')));
      w.vpns.slice(0, 2).forEach(v => lines.push('VPN ' + v.name + ' → ' + show(v.remote)));
      if (w.vpns.length > 2) lines.push(T('pnl.more', { n: w.vpns.length - 2 }));
      if (w.exposed.length) lines.push('⚠ ' + w.exposed.map(x => T('expose.svc_' + x)).join(', '));
      return { port: lc(w.port), lines, color: COLORS.wan };
    });
    return window.PanelSvg.render({ title: pn.model || pn.modelRaw || '', rows: [{ ports }], groups, callouts });
  }


  const esc2 = s => (typeof esc === 'function' ? esc(s) : xesc(s));
  function legendHtml(pn) {
    const sw = (c, label) => `<span style="display:inline-flex;align-items:center;gap:4px;margin-right:10px"><span style="width:12px;height:12px;border-radius:2px;background:${c};display:inline-block"></span>${esc2(label)}</span>`;
    let h = `<div style="font-size:11px;margin:6px 0">${sw(COLORS.wan, T('pnl.lg_wan'))}${sw(COLORS.used, T('pnl.lg_used'))}${sw(COLORS.unused, T('pnl.lg_unused'))}${sw(COLORS.mgmt, T('pnl.lg_mgmt'))}${sw(COLORS.fortilink, T('pnl.lg_fortilink'))}`
      + `<span style="color:var(--text-dim)">${esc2(T('pnl.lg_fiber'))}　${esc2(T('pnl.lg_frame'))}</span>`;
    if (pn.vdoms.length > 1) h += '<br>' + pn.vdoms.map((v, i) => sw(VDOM_COLORS[i % VDOM_COLORS.length], 'VDOM ' + v)).join('');
    return h + '</div>';
  }

  // 摘要頁卡片：SVG＋埠明細表＋下載按鈕
  function panelHtml(parsed) {
    const pn = buildPanel(parsed);
    if (!pn || !pn.ports.length) return '';
    const box = 'background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin-bottom:12px';
    let h = `<div id="fw-panel-card" style="${box}"><div style="font-weight:600;font-size:13px;margin-bottom:4px">🔌 ${esc2(T('pnl.title'))}</div>`;
    h += `<div style="font-size:11px;color:var(--text-dim);margin-bottom:6px">${esc2(T(pn.source === 'model' ? 'pnl.hint_model' : 'pnl.hint_config', { m: pn.model }))}</div>`;
    h += `<div style="overflow-x:auto" data-fw-panel="${pn.source}">${panelSvg(pn)}</div>${legendHtml(pn)}`;
    const kindTxt = k => T('pnl.kind_' + (GROUP_KINDS.includes(k) ? k : 'other'));
    if (pn.groups.length) h += `<div style="font-size:11px;margin:4px 0">${pn.groups.map(g => `<b>${esc2(g.name)}</b>（${esc2(kindTxt(g.kind))}${g.bridged ? '，' + esc2(T('pnl.bridged')) : ''}）：${esc2(g.members.join(', '))}`).join('<br>')}</div>`;
    if (pn.extra.length) h += `<div style="font-size:11px;color:var(--orange,#f59e0b);margin:4px 0">${esc2(T('pnl.extra', { list: pn.extra.map(p => p.name).join(', ') }))}</div>`;
    const rowsHtml = pn.ports.concat(pn.extra).filter(p => p.used || p.wan || p.role).map(p => {
      const role = p.wan ? 'WAN' : p.role ? p.role.toUpperCase() : p.fortilink ? 'FortiLink' : '';
      const refs = Object.keys(p.refs).filter(k => p.refs[k]).map(k => T('pnl.ref_' + k) + ' ' + p.refs[k]).join('、');
      return `<tr><td class="mono">${esc2(p.name)}</td><td>${esc2(role)}</td><td class="mono">${esc2(p.ips.join(', '))}</td><td>${esc2(p.zones.join(', '))}</td>${pn.vdoms.length ? `<td>${esc2(p.vdom)}</td>` : ''}<td>${esc2(p.group)}</td><td class="mono">${esc2(p.vlans.join(', '))}</td><td>${esc2(refs)}</td></tr>`;
    }).join('');
    if (rowsHtml) h += `<details style="margin-top:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('pnl.detail'))}</summary><div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>${esc2(T('pnl.col_port'))}</th><th>${esc2(T('pnl.col_role'))}</th><th>${esc2(T('pnl.col_addr'))}</th><th>${esc2(T('pnl.col_zone'))}</th>${pn.vdoms.length ? '<th>VDOM</th>' : ''}<th>${esc2(T('pnl.col_group'))}</th><th>${esc2(T('pnl.col_vlan'))}</th><th>${esc2(T('pnl.col_refs'))}</th></tr></thead><tbody>${rowsHtml}</tbody></table></div></details>`;
    h += `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px"><button class="btn btn-ghost btn-sm" data-fw-panel-dl>${esc2(T('pnl.download'))}</button>`
      + `<label style="font-size:11px"><input type="checkbox" id="fw-panel-mask" checked> ${esc2(T('pnl.mask'))}</label></div></div>`;
    return h;
  }
  // 下載 SVG（預設遮蔽位址）；由 app 的事件代理呼叫
  function panelDownloadSvg(parsed, mask) {
    const pn = buildPanel(parsed);
    return pn ? '<?xml version="1.0" encoding="UTF-8"?>\n' + panelSvg(pn, { mask }) : '';
  }

  const api = { buildPanel, panelSvg, panelHtml, panelDownloadSvg, maskIp, PANEL_PER_ROW };
  if (typeof window !== 'undefined') window.FwPanel = api;
  return api;
})();
