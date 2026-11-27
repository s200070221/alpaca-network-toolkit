// ── 交換器實體接線示意圖（XN191）──────────────────────────────────────────────
// 依型號資料（產生器的 DEVICE_MODELS＋NetBox 型號 NETBOX_SW_MODELS）畫前面板示意，標出各埠的 access VLAN／trunk／
// routed／hybrid、shutdown、LACP 成員（虛線框）、堆疊埠、型號標明支援 PoE 的埠，以及 LLDP／CDP 鄰居（滑鼠提示與明細表）。
// 堆疊時每個成員各畫一排（型號的埠名稱依成員編號換算）。讀不出型號時可在卡片選型號，或改用設定檔的實體埠。
// 埠的排列一律是示意；型號資料沒有面板上的實際位置。埠物件 neighbors 供之後多台接線拓樸（XN192）使用。
// 繪圖交給共用的 PanelSvg（panel-svg.js）；純資料函式 buildPanel() 不碰 DOM。
(function () {
  'use strict';
  const lc = s => String(s || '').toLowerCase();
  const norm = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const T = (k, p) => { let s = typeof tr === 'function' ? tr(k) : k; Object.keys(p || {}).forEach(n => { s = s.split('{' + n + '}').join(String(p[n])); }); return s; };
  const xesc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const esc2 = s => (typeof esc === 'function' ? esc(s) : xesc(s));
  const maskIp = s => (typeof window !== 'undefined' && window.PanelSvg ? window.PanelSvg.maskIp(s) : String(s));
  // 交換器分析的 vendor 代碼 → 型號資料的廠牌鍵（其餘同名）
  const VENDOR_KEY = { nxos: 'cisco_nxos' };
  const MODELS = () => (typeof DEVICE_MODELS !== 'undefined' ? DEVICE_MODELS : {});
  const NB = () => (typeof window !== 'undefined' && window.NETBOX_SW_MODELS) || {};
  const vendorKey = parsed => VENDOR_KEY[(parsed && parsed.vendor) || ''] || (parsed && parsed.vendor) || '';
  // 型號鍵：與產生器 validate.js 的 _modelKey() 同規則（去括號說明、廠牌字樣）
  const modelKey = label => String(label || '').replace(/\(.*$/, '').toUpperCase().replace(/[^A-Z0-9]/g, '')
    .replace(/^(CISCO|CATALYST|ARISTA|DCS|JUNIPER|ARUBACX|ARUBA|HPE|FLEXNETWORK|FLEXFABRIC|FORTISWITCH|EXTREMESWITCHING|EXTREME|SUMMIT|NETGEAR)+/, '');
  // 某廠牌可選的型號：人工整理在前，NetBox 型號中型號鍵相同者略過（與產生器 netboxModelsFor() 同規則）
  function modelsFor(vk) {
    const own = MODELS()[vk] || [], seen = new Set(own.map(m => modelKey(m.label)));
    return own.concat((NB()[vk] || []).filter(m => !seen.has(modelKey(m.label))));
  }
  // 可選型號＝型號資料＋使用者自訂型號（panel-svg.js，各廠牌共用）
  const customs = () => (typeof window !== 'undefined' && window.PanelSvg ? window.PanelSvg.customModels() : []);
  const choicesFor = vk => modelsFor(vk).concat(customs());
  // 型號埠展開（與產生器 validate.js 的 expandDeviceModelPorts() 同規則，qa 測試比對兩者結果一致）
  function expandPorts(model) {
    const out = [];
    (model && model.ports || []).forEach(p => {
      if (p.name) out.push({ name: p.name, speed: p.speed || '1G', mgmt: !!p.mgmt });
      else for (let n = p.from; n <= p.to; n++) out.push({ name: p.prefix + n + (p.suffix || ''), speed: p.speed || '1G', mgmt: false });
    });
    return out;
  }
  // 型號的 PoE 埠（與產生器 poePortNames() 同規則：poeRange 為存取埠號，從第一個埠群組依序取到迄號）；以型號原始埠名比對（堆疊成員換算前）
  function poePorts(model) {
    if (model && model.custom) return new Set(model.ports.filter(p => p.poe).map(p => lc(p.name)));
    if (!model || model.poe !== true || !Array.isArray(model.poeRange)) return new Set();
    const a = model.poeRange[0], b = model.poeRange[1], out = new Set();
    for (const p of model.ports || []) {
      if (p.name || p.from == null) continue;
      let hit = false;
      for (let n = p.from; n <= p.to; n++) if (n >= a && n <= b) { out.add(lc(p.prefix + n + (p.suffix || ''))); hit = true; if (n === b) return out; }
      if (!hit) break;
    }
    return out;
  }
  // 設定檔型號（sys.model／platform 或堆疊成員型號）比對型號資料：標籤、value 或括號內料號完全相同
  function matchModel(parsed) {
    const vk = vendorKey(parsed), s = (parsed && parsed.sys) || {};
    // 設定檔多半寫料號（c9300-48p），型號資料是名稱（Catalyst 9300-48P）：兩邊都轉成型號鍵，料號開頭的 C 可省略
    const raws = [s.model, s.platform].concat(((parsed && parsed.stack && parsed.stack.members) || []).map(m => m.model)).map(modelKey).filter(x => x.length >= 4)
      .flatMap(k => [k, k.replace(/^C(?=\d)/, '')]);
    if (!raws.length) return null;
    for (const m of choicesFor(vk)) {
      const keys = new Set([norm(m.label), norm(m.value), modelKey(m.label), modelKey(m.value)]);
      (String(m.label).match(/\(([^)]+)\)/g) || []).forEach(x => x.replace(/[()]/g, '').split(/[，,、\s]+/).forEach(t => { if (norm(t).length >= 4) keys.add(norm(t)); }));
      if (raws.some(r => keys.has(r))) return m;
    }
    return null;
  }
  // 混型號堆疊（XN215）：成員 k 的料號（例如 switch 2 provision c9300-48p）比對到的型號；比對不到為 null
  function memberModel(parsed, k) {
    const m = ((parsed && parsed.stack && parsed.stack.members) || []).find(x => String(x.id) === String(k) && x.model);
    return m ? matchModel({ vendor: parsed.vendor, sys: { brand: parsed.sys && parsed.sys.brand }, stack: { members: [m] } }) : null;
  }
  // 堆疊成員 k 的埠名稱：三段式名稱第一段為成員編號（GigabitEthernet1/0/1、1/1/1）才換算；管理埠只在成員 1
  const memberName = (name, k) => { const m = String(name).match(/^(\D*)1(\/\d+\/\d+)$/); return m ? m[1] + k + m[2] : (k === '1' ? name : null); };

  // 聚合等邏輯介面（部分 parser 的 type 仍是 physical），依名稱排除
  const LOGICAL_NAME = /^(lag\s*\d|bridge-aggregation|route-aggregation|port-channel|po\d|ae\d|bond|trk\d|vlan|vlan-interface|loopback|tunnel|null|mgmt-vrf|nve|vxlan)/i;
  function buildPanel(parsed, opts) {
    if (!parsed) return null;
    const o = opts || {}, vk = vendorKey(parsed);
    const picked = o.modelValue ? (choicesFor(vk).find(m => m.value === o.modelValue) || null) : null;
    const auto = picked || o.noAuto ? null : matchModel(parsed);
    const pn = _build(parsed, vk, picked || auto, !picked);
    // 自動比對到的型號若對不上大部分設定檔的實體埠（例如同廠牌不同作業系統的命名），改依設定檔繪製；手動選的照用
    if (auto && pn.extra.length > pn.rows.reduce((n, r) => n + r.ports.filter(p => p.inConfig).length, 0)) {
      const fb = _build(parsed, vk, null);
      fb.autoMismatch = auto.label;
      return fb;
    }
    return pn;
  }
  function _build(parsed, vk, model, perMember) {
    const ifBy = Object.create(null);
    (parsed.interfaces || []).forEach(i => { if (i && i.name) ifBy[lc(i.name)] = i; });
    const lag = Object.create(null);
    (parsed.lacp || []).forEach(l => {
      const ms = Array.isArray(l.members) ? l.members.map(m => (m && typeof m === 'object' ? m.name : m)) : String(l.members || '').split(/[\s,]+/);
      ms.filter(Boolean).forEach(m => { lag[lc(m)] = l.name; });
    });
    const stackPorts = new Set();
    ((parsed.stack && parsed.stack.links) || []).forEach(l => (l.ports || []).forEach(p => stackPorts.add(lc(p))));
    const nbBy = Object.create(null);
    (parsed.lldp || []).forEach(n => { if (n && n.localPort) (nbBy[lc(n.localPort)] = nbBy[lc(n.localPort)] || []).push({ neighbor: n.neighbor || '', remotePort: n.remotePort || '', ip: n.ip || '' }); });
    const poe = poePorts(model);
    const mk = (name, mp) => {
      const i = ifBy[lc(name)] || null;
      // LACP 成員的 VLAN 設定寫在聚合介面上：成員沒有模式時沿用所屬聚合介面
      const agg = !(i && i.mode) && lag[lc(name)] ? ifBy[lc(lag[lc(name)])] : null;
      const mode = i && i.mode ? String(i.mode) : agg ? String(agg.mode || '') : '';
      const vlans = i && i.mode ? String(i.vlans || '') : agg ? String(agg.vlans || '') : '';
      const cfg = !!i && (!!i.desc && i.desc !== '-' || /^(trunk|routed|hybrid)$/i.test(mode) || (vlans && vlans !== '1') || !!i.ip);
      return { name: i ? i.name : name, speed: (mp && mp.speed) || (i && i.speed) || '', mgmt: !!(mp && mp.mgmt), mode, vlans, nativeVlan: i && i.mode ? String(i.nativeVlan || '') : agg ? String(agg.nativeVlan || '') : '',
        desc: i && i.desc && i.desc !== '-' ? String(i.desc) : '', ip: i && i.ip ? String(i.ip) : '', shutdown: !!(i && i.shutdown), lag: lag[lc(name)] || '',
        stack: stackPorts.has(lc(name)), poe: !!mp && poe.has(lc(mp.name)), neighbors: nbBy[lc(name)] || [], inConfig: !!i,
        used: !!i && !i.shutdown && (cfg || !!lag[lc(name)] || stackPorts.has(lc(name)) || !!(nbBy[lc(name)] || []).length) };
    };
    const mems = ((parsed.stack && parsed.stack.members) || []).map(m => String(m.id)).filter(Boolean);
    const rows = [];
    let extra = [];
    if (model) {
      const ids = mems.length > 1 ? mems : ['1'];
      ids.forEach(k => {
        // 自動比對時，成員有自己的料號就依該型號展開（混型號堆疊），否則用整台型號；手動選型號時一律用選的
        const base = expandPorts((perMember && ids.length > 1 && memberModel(parsed, k)) || model);
        const ports = base.map(p => ({ p, n: memberName(p.name, k) })).filter(x => x.n).map(x => mk(x.n, x.p));
        rows.push({ member: mems.length > 1 ? k : '', ports });
      });
      const known = new Set(rows.flatMap(r => r.ports.map(p => lc(p.name))));
      extra = (parsed.interfaces || []).filter(i => (i.type === 'physical' || i.type === 'stack') && !LOGICAL_NAME.test(i.name || '') && !known.has(lc(i.name))).map(i => mk(i.name, null));
    } else {
      const phys = (parsed.interfaces || []).filter(i => (i.type === 'physical' || i.type === 'stack') && !LOGICAL_NAME.test(i.name || ''));
      const by = new Map();
      phys.forEach(i => { const k = mems.length > 1 ? String(i.member || '') : ''; if (!by.has(k)) by.set(k, []); by.get(k).push(mk(i.name, null)); });
      by.forEach((ports, k) => rows.push({ member: k, ports }));
    }
    const lags = Object.create(null), groups = [];
    rows.concat([{ ports: extra }]).forEach(r => r.ports.forEach(p => { if (p.lag) { if (!lags[lc(p.lag)]) { lags[lc(p.lag)] = { name: p.lag, members: [] }; groups.push(lags[lc(p.lag)]); } lags[lc(p.lag)].members.push(p.name); } }));
    return { vendor: vk, model: model ? model.label : '', modelValue: model ? model.value : '', modelRaw: (parsed.sys && (parsed.sys.model || parsed.sys.platform)) || '', source: model ? 'model' : 'config', rows, extra, groups, models: choicesFor(vk) };
  }

  // 終端定位頁貼上的輸出（XN196）：介面錯誤計數器、光模組告警、MAC 表每埠終端數，依設備名稱對到這台；
  // ep 未給時讀 app 的全域 epModel，只有一台時不比對名稱。回傳 Map（埠正規化名稱 → {sev, phy, opt, macs}）
  const hostKeyOf = h => { const s = lc(h).trim().replace(/\([^)]*\)$/, ''); return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) ? s : s.split('.')[0]; };
  // opts.strict：只依設備名稱對應（多台接線拓樸用；只有一台終端定位資料時也不套到名稱不同的設備）
  function overlayFor(parsed, ep, opts) {
    const model = ep !== undefined ? ep : (typeof epModel !== 'undefined' ? epModel : null);
    const devs = (model && model.devices) || [];
    if (!devs.length || typeof epNormIface !== 'function') return null;
    const host = hostKeyOf(parsed && parsed.sys && parsed.sys.hostname);
    const d = devs.find(x => host && hostKeyOf(x.name) === host) || (devs.length === 1 && !(opts && opts.strict) ? devs[0] : null);
    if (!d) return null;
    const out = new Map(), at = k => { if (!out.has(k)) out.set(k, { sev: '', phy: [], opt: [], macs: 0 }); return out.get(k); };
    const bump = (o, sev) => { if (sev === 'high' || (sev === 'medium' && o.sev !== 'high')) o.sev = sev; };
    if (typeof epPhyIssues === 'function') epPhyIssues({ devices: [d] }).forEach(r => { const o = at(epNormIface(r.port)); o.phy = r.findings; bump(o, r.severity); });
    if (typeof epOpticsIssues === 'function') epOpticsIssues({ devices: [d] }).forEach(r => { const o = at(epNormIface(r.port)); o.opt = r.findings.map(f => f.metric); bump(o, r.severity); });
    const seen = new Map();
    (d.macs || []).forEach(m => { const k = epNormIface(m.port); if (!seen.has(k)) seen.set(k, new Set()); seen.get(k).add(m.mac); });
    seen.forEach((v, k) => { at(k).macs = v.size; });
    return out.size ? out : null;
  }
  // 疊加到繪圖用的埠：警示點、終端數與提示文字（低嚴重度只有 drops 時不加警示點）
  function overlayPort(spec, ov, name) {
    const o = ov && typeof epNormIface === 'function' ? ov.get(epNormIface(name)) : null;
    if (!o) return spec;
    const extra = [];
    if (o.phy.length) extra.push(T('swp.ov_phy', { list: o.phy.map(f => T('ep.phy_' + f)).join('、') }));
    if (o.opt.length) extra.push(T('swp.ov_opt', { list: o.opt.map(m => T('ep.opt_m_' + m)).join('、') }));
    if (o.macs) extra.push(T('swp.ov_macs', { n: o.macs }));
    return Object.assign(spec, { alert: o.sev === 'high' || o.sev === 'medium' ? o.sev : '', count: o.macs || '', tip: [spec.tip].concat(extra).join(' · ') });
  }
  const COLORS = { access: '#3b82f6', trunk: '#f59e0b', routed: '#10b981', hybrid: '#ec4899', shutdown: '#4b5563', unused: '#9ca3af', mgmt: '#8b5cf6' };
  const GROUP_COLORS = ['#ef4444', '#14b8a6', '#eab308', '#ec4899', '#6366f1', '#84cc16'];
  const kindOf = p => (p.mgmt ? 'mgmt' : p.shutdown ? 'shutdown' : !p.used ? 'unused' : /trunk/i.test(p.mode) ? 'trunk' : /routed/i.test(p.mode) || (p.ip && !p.mode) ? 'routed' : /hybrid/i.test(p.mode) ? 'hybrid' : 'access');
  // 圖上的精簡埠標籤：GigabitEthernet1/0/12 → 12；該排最常見的類型只標最後一段數字，其他類型加兩字縮寫（Te1）
  const typeOf = n => (String(n).match(/^[A-Za-z-]+/) || [''])[0];
  const lastNum = n => (String(n).match(/(\d+)(?!.*\d)/) || ['', n])[1];
  function shortLabels(ports) {
    const cnt = Object.create(null);
    ports.forEach(p => { const t = typeOf(p.name); cnt[t] = (cnt[t] || 0) + 1; });
    const main = Object.keys(cnt).sort((a, b) => cnt[b] - cnt[a])[0];
    return ports.map(p => { const t = typeOf(p.name); return t === main ? lastNum(p.name) : (t.slice(0, 2) || '') + lastNum(p.name); });
  }
  // 精簡顯示（XN200）：只留使用中或有 LLDP 鄰居的埠（管理埠一併保留），手機寬度少捲動；下載的 SVG 一律完整
  const keepCompact = p => p.used || p.mgmt || (p.neighbors && p.neighbors.length);
  function panelSvg(pn, opts) {
    const show = s => (opts && opts.mask ? maskIp(s) : String(s));
    const rows = pn.rows.map(r => { const ports = opts && opts.compact ? r.ports.filter(keepCompact) : r.ports, lbl = shortLabels(ports); return { label: r.member ? T('swp.member', { n: r.member }) : '', ports: ports.map((p, pi) => {
      const k = kindOf(p);
      const text = k === 'access' ? (p.vlans || '1') : k === 'trunk' ? 'T' : k === 'routed' ? 'L3' : k === 'hybrid' ? 'H' : '';
      const nb = p.neighbors.map(n => '→ ' + n.neighbor + (n.remotePort ? ' ' + n.remotePort : '')).join(' ');
      const tip = [p.name, p.speed, p.desc, k === 'trunk' ? 'trunk ' + (p.vlans || 'all') + (p.nativeVlan ? ' native ' + p.nativeVlan : '') : k === 'access' ? 'VLAN ' + (p.vlans || '1') : '', p.ip ? show(p.ip) : '', p.lag, nb].filter(Boolean).join(' · ');
      return overlayPort({ id: lc(p.name), name: p.name, label: lbl[pi], color: COLORS[k], dim: k === 'unused' || k === 'shutdown', fiber: false, text, tip, badge: p.stack ? 'S' : p.poe ? 'P' : '' }, opts && opts.overlay, p.name);
    }) }; });
    const groups = pn.groups.map((g, i) => ({ members: g.members.map(lc), color: GROUP_COLORS[i % GROUP_COLORS.length], dashed: true, label: g.name }));
    return window.PanelSvg.render({ title: pn.model || pn.modelRaw || '', rows, groups, callouts: [] });
  }

  const _chosen = new WeakMap();   // parsed → 使用者在卡片選的型號（只存記憶體）
  let _last = null, _compact = false;
  function panelHtml(parsed, editorOpen) {
    if (!parsed || typeof window === 'undefined' || !window.PanelSvg) return '';
    _last = parsed;
    const pn = buildPanel(parsed, { modelValue: _chosen.get(parsed) || '' });
    if (!pn) return '';
    const box = 'background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;margin-top:16px';
    let h = `<div id="sw-panel-card" style="${box}"><div style="font-size:14px;font-weight:600;margin-bottom:4px">🔌 ${esc2(T('swp.title'))}</div>`;
    h += `<div style="font-size:12px;color:var(--text-dim);margin-bottom:6px">${esc2(T(pn.source === 'model' ? 'swp.hint_model' : 'swp.hint_config', { m: pn.model }))}</div>`;
    if (pn.autoMismatch) h += `<div style="font-size:12px;color:var(--orange,#f59e0b);margin-bottom:6px">${esc2(T('swp.mismatch', { m: pn.autoMismatch }))}</div>`;
    h += modelSelectHtml(pn, !!_chosen.get(parsed), 'data-sw-panel-model');
    const editor = window.PanelSvg.customEditorHtml('sw', editorOpen);
    if (!pn.rows.some(r => r.ports.length)) return h + `<div class="nodata">${esc2(T('swp.none'))}</div>${editor}</div>`;
    const ov = overlayFor(parsed);
    h += ` <label style="font-size:12px;white-space:nowrap"><input type="checkbox" data-sw-panel-compact${_compact ? ' checked' : ''}> ${esc2(T('swp.compact'))}</label>`;
    h += `<div style="overflow-x:auto;margin-top:6px" data-sw-panel="${pn.source}">${panelSvg(pn, { overlay: ov, compact: _compact })}</div>`;
    const L = [[COLORS.access, T('swp.lg_access')], [COLORS.trunk, T('swp.lg_trunk')], [COLORS.routed, T('swp.lg_routed')], [COLORS.hybrid, T('swp.lg_hybrid')], [COLORS.shutdown, T('swp.lg_shutdown')], [COLORS.unused, T('swp.lg_unused')], [COLORS.mgmt, T('swp.lg_mgmt')]];
    h += `<div style="font-size:11px;margin:6px 0">${window.PanelSvg.legend(L, esc2)}<span style="color:var(--text-dim)">${esc2(T('swp.lg_marks'))}</span>${ov ? `<br><span style="color:var(--text-dim)" data-sw-panel-ov>${esc2(T('swp.ov_note'))}</span>` : ''}</div>`;
    if (pn.groups.length) h += `<div style="font-size:11px;margin:4px 0">${pn.groups.map(g => `<b>${esc2(g.name)}</b>（LACP）：${esc2(g.members.join(', '))}`).join('<br>')}</div>`;
    if (pn.extra.length) h += `<div style="font-size:11px;color:var(--orange,#f59e0b);margin:4px 0">${esc2(T('swp.extra', { list: pn.extra.map(p => p.name).join(', ') }))}</div>`;
    const all = pn.rows.flatMap(r => r.ports).concat(pn.extra).filter(p => p.used || p.shutdown && p.inConfig || p.neighbors.length);
    if (all.length) h += `<details style="margin-top:6px"><summary style="cursor:pointer;font-size:12px">${esc2(T('swp.detail'))}</summary><div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>${esc2(T('swp.col_port'))}</th><th>${esc2(T('swp.col_mode'))}</th><th>VLAN</th><th>${esc2(T('swp.col_desc'))}</th><th>LACP</th><th>${esc2(T('swp.col_nb'))}</th></tr></thead><tbody>`
      + all.map(p => `<tr><td class="mono">${esc2(p.name)}</td><td>${esc2(p.shutdown ? 'shutdown' : p.mode || (p.ip ? 'routed' : ''))}</td><td class="mono">${esc2(p.vlans + (p.nativeVlan && /trunk/i.test(p.mode) ? ' (native ' + p.nativeVlan + ')' : ''))}</td><td>${esc2(p.desc)}</td><td>${esc2(p.lag)}</td><td>${esc2(p.neighbors.map(n => n.neighbor + (n.remotePort ? ' ' + n.remotePort : '')).join(', '))}</td></tr>`).join('') + '</tbody></table></div></details>';
    h += `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px"><button style="background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 14px;font-size:12px;cursor:pointer" data-sw-panel-dl>${esc2(T('swp.download'))}</button>`
      + `<label style="font-size:11px"><input type="checkbox" id="sw-panel-mask" checked> ${esc2(T('swp.mask'))}</label></div>${editor}</div>`;
    return h;
  }
  // 型號選單（型號資料在前，自訂型號另成一組）；attr 為選單的 data 屬性（總覽卡片與接線拓樸共用）
  function modelSelectHtml(pn, chosen, attr, extra) {
    const opt = m => `<option value="${xesc(m.value)}"${chosen && m.value === pn.modelValue ? ' selected' : ''}>${esc2(m.label)}</option>`;
    const own = pn.models.filter(m => !m.custom), cu = pn.models.filter(m => m.custom);
    if (!own.length && !cu.length) return '';
    return `<label style="font-size:12px">${esc2(T('swp.pick'))} <select ${attr}${extra || ''} style="width:auto;max-width:280px"><option value="">${esc2(T('swp.pick_auto'))}</option>${own.map(opt).join('')}`
      + (cu.length ? `<optgroup label="${xesc(T('pcu.group'))}">${cu.map(opt).join('')}</optgroup>` : '') + '</select></label>';
  }
  function panelDownloadSvg(parsed, mask) {
    const pn = buildPanel(parsed, { modelValue: _chosen.get(parsed) || '' });
    return pn && window.PanelSvg ? '<?xml version="1.0" encoding="UTF-8"?>\n' + panelSvg(pn, { mask, overlay: overlayFor(parsed) }) : '';
  }
  // 卡片上的型號選單與下載（事件代理；型號只接受該廠牌清單內的 value）
  if (typeof document !== 'undefined' && document.addEventListener) {
    document.addEventListener('change', e => {
      const cb = e.target && e.target.closest ? e.target.closest('input[data-sw-panel-compact]') : null;
      if (cb && _last) { _compact = cb.checked; const card = document.getElementById('sw-panel-card'); if (card) card.outerHTML = panelHtml(_last); return; }
      const sel = e.target && e.target.closest ? e.target.closest('select[data-sw-panel-model]') : null;
      if (!sel || !_last) return;
      const v = sel.value, ok = !v || choicesFor(vendorKey(_last)).some(m => m.value === v);
      if (!ok) return;
      if (v) _chosen.set(_last, v); else _chosen.delete(_last);
      const card = document.getElementById('sw-panel-card');
      if (card) card.outerHTML = panelHtml(_last);
    });
    // 自訂型號存檔或刪除後：存檔的型號直接套用到目前這台，重繪卡片並保持編輯區展開
    window.addEventListener('pnl-custom', e => {
      const d = (e && e.detail) || {};
      if (d.scope !== 'sw' || !_last) return;
      if (d.value) _chosen.set(_last, d.value);
      else if (_chosen.get(_last) && !customs().some(m => m.value === _chosen.get(_last))) _chosen.delete(_last);
      const card = document.getElementById('sw-panel-card');
      if (card) card.outerHTML = panelHtml(_last, true);
    });
    document.addEventListener('click', e => {
      const b = e.target && e.target.closest ? e.target.closest('[data-sw-panel-dl]') : null;
      if (!b || !_last) return;
      const m = document.getElementById('sw-panel-mask');
      const svg = panelDownloadSvg(_last, !m || m.checked);
      if (!svg) return;
      const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
      const a = document.createElement('a');
      a.href = url; a.download = String((_last.sys && _last.sys.hostname) || 'switch').replace(/[^\w.\-]/g, '_') + '_panel.svg'; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }

  const api = { overlayFor, overlayPort, buildPanel, panelSvg, panelHtml, panelDownloadSvg, matchModel, memberModel, modelsFor, choicesFor, expandPorts, poePorts, memberName, modelSelectHtml, shortLabels, kindOf, COLORS, chosen: _chosen };
  if (typeof window !== 'undefined') window.SwPanel = api;
  return api;
})();
