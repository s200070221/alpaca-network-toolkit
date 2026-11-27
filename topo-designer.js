// ── 拓樸設計頁（XN202，第一步）──────────────────────────────────────────────────
// 在畫布上放交換器（廠牌＋型號，型號資料沿用產生器的 DEVICE_MODELS／NetBox 與自訂型號）、拖拉位置、
// 選兩台設備與各自的埠連線，存成設計檔（format alpaca-design）。這一步不產生設定檔。
// 純函式（addDevice／addLink／buildDesign／parseDesign 等）不碰 DOM，測試以沙箱載入；畫面部分只在有 document 時啟動。
// 資料只存記憶體（不寫 localStorage）；設備名稱只當值、不當物件鍵（原型污染），內部以程式產生的 d1、d2… 為 ID。
(function () {
  'use strict';
  const lc = s => String(s || '').toLowerCase();
  // 與產生器 #vendor 選單相同的值；h3c 的型號沿用 comware
  const VENDORS = [
    ['comware', 'HPE Comware'], ['h3c', 'H3C Comware'], ['fortiswitch', 'FortiSwitch'], ['aruba', 'Aruba CX'],
    ['cisco', 'Cisco IOS/IOS-XE'], ['cisco_nxos', 'Cisco NX-OS'], ['juniper', 'Juniper (Junos)'], ['dell-os10', 'Dell OS10'],
    ['arista', 'Arista EOS'], ['brocade', 'Ruckus/Brocade ICX'], ['alcatel', 'Alcatel OmniSwitch'], ['extreme', 'Extreme EXOS'],
    ['procurve', 'Aruba ProCurve / ArubaOS-Switch'], ['routeros', 'MikroTik RouterOS'], ['ruijie', 'Ruijie RGOS'],
    ['netgear', 'Netgear M4300'], ['edgeswitch', 'Ubiquiti EdgeSwitch'], ['sonic', 'SONiC'], ['planet', 'Planet'],
  ];
  const VENDOR_IDS = VENDORS.map(v => v[0]);
  const vendorName = id => (VENDORS.find(v => v[0] === id) || [id, id])[1];
  const modelVendor = id => (id === 'h3c' ? 'comware' : id);
  const MAX_DEVICES = 64, MAX_LINKS = 512, MAX_VLANS = 512;
  // 畫布寬度固定；高度至少 CANVAS_H，設備多時往下長（最多 MAX_H，放得下 MAX_DEVICES 台的格狀位置）
  const CANVAS_W = 1000, CANVAS_H = 560, BOX_W = 180, BOX_H = 58, GAP_X = 30, GAP_Y = 60;
  const COLS = Math.floor(CANVAS_W / (BOX_W + GAP_X)), MAX_H = 20 + Math.ceil(MAX_DEVICES / COLS) * (BOX_H + GAP_Y);
  const HOST_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/;
  const VLAN_NAME_RE = /^[^\x00-\x1f\x7f]{0,32}$/;
  // 錯誤代碼（td.err_*）；設計檔讀入只會出現 DESIGN_ERR_CODES
  const DESIGN_ERR_CODES = ['json', 'format', 'device', 'link', 'max', 'vlan', 'lag'];
  const ERR_CODES = DESIGN_ERR_CODES.concat(['host', 'dup', 'vendor', 'model', 'self', 'port', 'used', 'vlan_id', 'vlan_dup', 'vlan_name', 'vlan_used', 'vlan_missing', 'vlan_syntax', 'native', 'lag_links', 'lag_num', 'lag_num_dup', 'lag_mode']);
  // 連線兩端不一致的類型（td.li_*）與等級：high＝VLAN 混接或中斷、medium＝只有部分 VLAN 通、info＝無法比對
  // 聚合（XN204）：lag_cfg＝同一聚合成員設定不一致（成員無法加入聚合）、parallel＝同一對設備有多條獨立連線（STP 會擋掉多出來的）
  const LINK_ISSUE_TYPES = ['undef', 'mode', 'access_vlan', 'native', 'allowed', 'native_not_allowed', 'lag_cfg', 'parallel'];
  const ISSUE_LEVEL = { undef: 'info', mode: 'high', access_vlan: 'high', native: 'high', allowed: 'medium', native_not_allowed: 'medium', lag_cfg: 'high', parallel: 'medium' };
  const LAG_MODES = ['active', 'static'], LAG_NUM_MAX = 4096;

  const SP = () => (typeof window !== 'undefined' && window.SwPanel) || null;
  // 某廠牌可選的型號：型號資料＋自訂型號（SwPanel.choicesFor）
  const modelChoices = vendor => { const sp = SP(); return sp ? sp.choicesFor(modelVendor(vendor)) : []; };
  const findModel = (vendor, value) => (value ? modelChoices(vendor).find(m => m.value === value) || null : null);
  const portsOf = (vendor, value) => { const m = findModel(vendor, value), sp = SP(); return m && sp ? sp.expandPorts(m).map(p => p.name) : []; };
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, Math.round(v)));

  function newDesign() { return { devices: [], links: [], vlans: [], lags: [], seq: 0, lagSeq: 0 }; }
  const devById = (d, id) => d.devices.find(x => x.id === id) || null;
  // 已接線的埠（小寫埠名集合）
  function usedPorts(d, id) {
    const s = new Set();
    d.links.forEach(l => [l.a, l.b].forEach(e => { if (e.dev === id) s.add(lc(e.port)); }));
    return s;
  }
  // 新設備放在第一個沒有與其他方塊重疊的格狀位置，之後再拖拉
  function nextSlot(d) {
    const free = (x, y) => !d.devices.some(o => Math.abs(o.x - x) < BOX_W && Math.abs(o.y - y) < BOX_H);
    for (let k = 0; k < COLS * Math.ceil(MAX_DEVICES / COLS); k++) {
      const x = 20 + (k % COLS) * (BOX_W + GAP_X), y = 20 + Math.floor(k / COLS) * (BOX_H + GAP_Y);
      if (free(x, y)) return { x, y };
    }
    return { x: 20, y: 20 };
  }
  // 目前畫布高度：容納最下面的設備
  const canvasH = d => Math.max(CANVAS_H, ...d.devices.map(x => x.y + BOX_H + 20));
  function addDevice(d, o) {
    const hostname = String((o && o.hostname) || '').trim(), vendor = String((o && o.vendor) || ''), model = String((o && o.model) || '');
    if (d.devices.length >= MAX_DEVICES) return { ok: false, code: 'max' };
    if (!HOST_RE.test(hostname)) return { ok: false, code: 'host' };
    if (d.devices.some(x => lc(x.hostname) === lc(hostname))) return { ok: false, code: 'dup' };
    if (!VENDOR_IDS.includes(vendor)) return { ok: false, code: 'vendor' };
    if (!findModel(vendor, model)) return { ok: false, code: 'model' };
    const pos = o.x != null && o.y != null ? { x: o.x, y: o.y } : nextSlot(d);
    const dev = { id: 'd' + (++d.seq), hostname, vendor, model, x: clamp(pos.x, 0, CANVAS_W - BOX_W), y: clamp(pos.y, 0, MAX_H - BOX_H) };
    d.devices.push(dev);
    return { ok: true, dev };
  }
  function removeDevice(d, id) {
    d.devices = d.devices.filter(x => x.id !== id);
    d.links = d.links.filter(l => l.a.dev !== id && l.b.dev !== id);
    pruneLags(d);
  }
  function moveDevice(d, id, x, y) {
    const dev = devById(d, id);
    if (dev) { dev.x = clamp(x, 0, CANVAS_W - BOX_W); dev.y = clamp(y, 0, MAX_H - BOX_H); }
  }
  // 編輯設備（XN203）：改名、換廠牌或型號。新型號沒有的埠，連到該埠的線列在 drop（連線索引）；
  // opts.dryRun 只回報不修改，正式套用時刪除這些線，其餘線的埠名稱換成新型號的寫法
  function changeDevice(d, id, o, opts) {
    const dev = devById(d, id);
    if (!dev) return { ok: false, code: 'device' };
    const hostname = String((o && o.hostname) || '').trim(), vendor = String((o && o.vendor) || ''), model = String((o && o.model) || '');
    if (!HOST_RE.test(hostname)) return { ok: false, code: 'host' };
    if (d.devices.some(x => x !== dev && lc(x.hostname) === lc(hostname))) return { ok: false, code: 'dup' };
    if (!VENDOR_IDS.includes(vendor)) return { ok: false, code: 'vendor' };
    if (!findModel(vendor, model)) return { ok: false, code: 'model' };
    const byLc = new Map(portsOf(vendor, model).map(p => [lc(p), p]));
    const drop = [];
    d.links.forEach((l, i) => { if ([l.a, l.b].some(e => e.dev === id && !byLc.has(lc(e.port)))) drop.push(i); });
    if (opts && opts.dryRun) return { ok: true, drop };
    for (let k = drop.length - 1; k >= 0; k--) removeLink(d, drop[k]);
    Object.assign(dev, { hostname, vendor, model });
    d.links.forEach(l => [l.a, l.b].forEach(e => { if (e.dev === id) e.port = byLc.get(lc(e.port)); }));
    return { ok: true, drop };
  }

  // ── VLAN ──
  // VLAN 清單寫法：與產生器 parseVlanRangeSpec()（switch-generator-validate.js）同規則，另外接受單獨的 all
  function parseVlanList(spec) {
    const s = String(spec || '').trim();
    if (/^all$/i.test(s)) return { ids: [], all: true, invalid: [] };
    const ids = new Set(), invalid = [];
    s.split(/[,\s]+/).filter(Boolean).forEach(tok => {
      const m = tok.match(/^(\d+)(?:-(\d+))?$/);
      if (!m) { invalid.push(tok); return; }
      const a = Number(m[1]), b = m[2] === undefined ? a : Number(m[2]);
      if (a < 1 || b > 4094 || a > b) { invalid.push(tok); return; }
      for (let i = a; i <= b; i++) ids.add(i);
    });
    return { ids: [...ids].sort((x, y) => x - y), all: false, invalid };
  }
  // 編號陣列壓縮成「10,20-30」
  function vlanText(ids) {
    const a = [...new Set(ids)].sort((x, y) => x - y), out = [];
    for (let i = 0; i < a.length; i++) {
      let j = i;
      while (j + 1 < a.length && a[j + 1] === a[j] + 1) j++;
      out.push(j > i ? a[i] + '-' + a[j] : String(a[i]));
      i = j;
    }
    return out.join(',');
  }
  const vlanIdOf = v => { const s = String(v == null ? '' : v).trim(); return /^\d{1,4}$/.test(s) && +s >= 1 && +s <= 4094 ? +s : null; };
  const hasVlan = (d, id) => d.vlans.some(v => v.id === id);
  function addVlan(d, o) {
    const id = vlanIdOf(o && o.id), name = String((o && o.name) || '').trim();
    if (id == null) return { ok: false, code: 'vlan_id' };
    if (hasVlan(d, id)) return { ok: false, code: 'vlan_dup' };
    if (!VLAN_NAME_RE.test(name)) return { ok: false, code: 'vlan_name' };
    if (d.vlans.length >= MAX_VLANS) return { ok: false, code: 'max' };
    d.vlans.push({ id, name });
    d.vlans.sort((x, y) => x.id - y.id);
    return { ok: true, vlan: { id, name } };
  }
  // 某一端設定用到的 VLAN（trunk all 不列）
  function cfgVlans(c) {
    if (!c) return [];
    const out = c.mode === 'access' ? [+c.vlans] : (parseVlanList(c.vlans).ids);
    if (c.mode === 'trunk' && c.nativeVlan) out.push(+c.nativeVlan);
    return out;
  }
  function removeVlan(d, id) {
    if (d.links.some(l => [l.a.cfg, l.b.cfg].some(c => cfgVlans(c).includes(id)))) return { ok: false, code: 'vlan_used' };
    d.vlans = d.vlans.filter(v => v.id !== id);
    return { ok: true };
  }
  // 檢查並正規化一端的設定：access 單一 VLAN、trunk 允許清單（all 或清單內的 VLAN）＋選填 native；null＝未設定
  function normCfg(d, c) {
    if (c == null || c.mode == null || c.mode === '') return { ok: true, cfg: null };
    if (c.mode === 'access') {
      const id = vlanIdOf(c.vlans);
      // 共用清單還沒有任何 VLAN 時，提示先新增（選單是空的，不是寫法錯）
      if (id == null) return { ok: false, code: d.vlans.length ? 'vlan_syntax' : 'vlan_missing' };
      if (!hasVlan(d, id)) return { ok: false, code: 'vlan_missing' };
      return { ok: true, cfg: { mode: 'access', vlans: String(id), nativeVlan: '' } };
    }
    if (c.mode !== 'trunk') return { ok: false, code: 'vlan_syntax' };
    const p = parseVlanList(c.vlans);
    if (!p.invalid.length && !p.all && !p.ids.length && !d.vlans.length) return { ok: false, code: 'vlan_missing' };
    if (p.invalid.length || (!p.all && !p.ids.length)) return { ok: false, code: 'vlan_syntax' };
    if (p.ids.some(id => !hasVlan(d, id))) return { ok: false, code: 'vlan_missing' };
    let nat = '';
    if (c.nativeVlan != null && String(c.nativeVlan).trim() !== '') {
      const n = vlanIdOf(c.nativeVlan);
      if (n == null || !hasVlan(d, n)) return { ok: false, code: 'native' };
      nat = String(n);
    }
    return { ok: true, cfg: { mode: 'trunk', vlans: p.all ? 'all' : vlanText(p.ids), nativeVlan: nat } };
  }
  function addLink(d, a, b, cfg) {
    if (d.links.length >= MAX_LINKS) return { ok: false, code: 'max' };
    const da = a && devById(d, a.dev), db = b && devById(d, b.dev);
    if (!da || !db || !a.port || !b.port) return { ok: false, code: 'port' };
    if (da === db) return { ok: false, code: 'self' };
    const pa = portsOf(da.vendor, da.model).find(p => lc(p) === lc(a.port)), pb = portsOf(db.vendor, db.model).find(p => lc(p) === lc(b.port));
    if (!pa || !pb) return { ok: false, code: 'port' };
    if (usedPorts(d, da.id).has(lc(pa)) || usedPorts(d, db.id).has(lc(pb))) return { ok: false, code: 'used' };
    // 建立時的設定預設同時套到兩端，之後每端可分別修改
    const n = normCfg(d, cfg);
    if (!n.ok) return n;
    const link = { a: { dev: da.id, port: pa, cfg: n.cfg && Object.assign({}, n.cfg) }, b: { dev: db.id, port: pb, cfg: n.cfg && Object.assign({}, n.cfg) } };
    d.links.push(link);
    return { ok: true, link };
  }
  function removeLink(d, i) { if (i >= 0 && i < d.links.length) { d.links.splice(i, 1); pruneLags(d); } }

  // ── 鏈路聚合（XN204）──
  // d.lags：[{id, a:{dev,num}, b:{dev,num}, mode}]，成員為 link.lag === id 的線；a／b 依建立時第一條線的兩端
  const lagById = (d, id) => (d.lags || []).find(g => g.id === id) || null;
  const lagMembers = (d, id) => d.links.filter(l => l.lag === id);
  // 刪除線或設備後：沒有成員的聚合一併移除
  function pruneLags(d) {
    if (!d.lags) d.lags = [];
    d.lags = d.lags.filter(g => d.links.some(l => l.lag === g.id));
    d.links.forEach(l => { if (l.lag && !lagById(d, l.lag)) delete l.lag; });
  }
  const lagNumOf = v => { const s = String(v == null ? '' : v).trim(); return /^\d{1,4}$/.test(s) && +s >= 1 && +s <= LAG_NUM_MAX ? +s : null; };
  // 某台設備上已用的群組編號
  const usedLagNums = (d, dev, except) => new Set((d.lags || []).filter(g => g.id !== except).flatMap(g => [g.a, g.b]).filter(e => e.dev === dev).map(e => e.num));
  // 所選的線（連線索引）合成一組：須是同一對設備、都還沒加入聚合；兩端群組編號 1～4096 且該設備上不重複
  function addLag(d, idxs, o) {
    if (!d.lags) d.lags = [];
    const list = [...new Set((idxs || []).map(Number))];
    const ls = list.map(i => d.links[i]);
    if (!list.length || ls.some(l => !l || l.lag)) return { ok: false, code: 'lag_links' };
    const a = ls[0].a.dev, b = ls[0].b.dev;
    if (ls.some(l => !((l.a.dev === a && l.b.dev === b) || (l.a.dev === b && l.b.dev === a)))) return { ok: false, code: 'lag_links' };
    const aNum = lagNumOf(o && o.aNum), bNum = lagNumOf(o && o.bNum), mode = String((o && o.mode) || 'active');
    if (aNum == null || bNum == null) return { ok: false, code: 'lag_num' };
    if (usedLagNums(d, a).has(aNum) || usedLagNums(d, b).has(bNum)) return { ok: false, code: 'lag_num_dup' };
    if (!LAG_MODES.includes(mode)) return { ok: false, code: 'lag_mode' };
    const g = { id: 'g' + (++d.lagSeq), a: { dev: a, num: aNum }, b: { dev: b, num: bNum }, mode };
    d.lags.push(g);
    ls.forEach(l => { l.lag = g.id; });
    return { ok: true, lag: g };
  }
  function removeLag(d, id) {
    if (!lagById(d, id)) return { ok: false, code: 'lag_links' };
    d.lags = d.lags.filter(g => g.id !== id);
    d.links.forEach(l => { if (l.lag === id) delete l.lag; });
    return { ok: true };
  }
  // 聚合在某台設備上的成員埠
  const lagPortsOn = (d, g, dev) => lagMembers(d, g.id).map(l => (l.a.dev === dev ? l.a : l.b).port);
  function setEndCfg(d, i, end, cfg) {
    const l = d.links[i];
    if (!l || (end !== 'a' && end !== 'b')) return { ok: false, code: 'link' };
    const n = normCfg(d, cfg);
    if (!n.ok) return n;
    l[end].cfg = n.cfg;
    return { ok: true, cfg: n.cfg };
  }

  // 兩端比對：依實際影響分級（native／模式／access VLAN 不同會讓 VLAN 混接或中斷；允許清單不同只有部分 VLAN 通）
  function linkIssues(d, l) {
    const out = cfgIssues(d, l);
    const add = (type, p) => out.push({ type, level: ISSUE_LEVEL[type], p: p || {} });
    // 同一聚合的成員：每一端的設定都要相同（不同時成員無法加入聚合）
    if (l.lag) {
      const ms = lagMembers(d, l.lag), cfgOf = (x, dev) => JSON.stringify((x.a.dev === dev ? x.a : x.b).cfg || null);
      [l.a.dev, l.b.dev].forEach(dev => { if (new Set(ms.map(x => cfgOf(x, dev))).size > 1) add('lag_cfg', { host: (devById(d, dev) || {}).hostname || '' }); });
    }
    // 同一對設備有兩條以上的邏輯連線（每個聚合算一條）：沒有聚合時 STP 只留一條
    const same = d.links.filter(x => (x.a.dev === l.a.dev && x.b.dev === l.b.dev) || (x.a.dev === l.b.dev && x.b.dev === l.a.dev));
    const logical = new Set(same.map((x, i) => x.lag || 'l' + i)).size;
    if (logical > 1) add('parallel', { n: logical });
    return out;
  }
  function cfgIssues(d, l) {
    const ca = l.a.cfg, cb = l.b.cfg, out = [];
    const add = (type, p) => out.push({ type, level: ISSUE_LEVEL[type], p: p || {} });
    if (!ca || !cb) { add('undef'); return out; }
    if (ca.mode !== cb.mode) { add('mode'); return out; }
    if (ca.mode === 'access') { if (ca.vlans !== cb.vlans) add('access_vlan', { a: ca.vlans, b: cb.vlans }); return out; }
    const na = ca.nativeVlan || '1', nb = cb.nativeVlan || '1';
    if (na !== nb) add('native', { a: na, b: nb });
    const pa = parseVlanList(ca.vlans), pb = parseVlanList(cb.vlans);
    if (!(pa.all && pb.all)) {
      // all 對清單時，以共用 VLAN 清單內的編號計算
      const known = d.vlans.map(v => v.id), sa = new Set(pa.all ? known : pa.ids), sb = new Set(pb.all ? known : pb.ids);
      const common = [...sa].filter(x => sb.has(x)), onlyA = [...sa].filter(x => !sb.has(x)), onlyB = [...sb].filter(x => !sa.has(x));
      if (onlyA.length || onlyB.length) add('allowed', { common: vlanText(common), onlyA: vlanText(onlyA), onlyB: vlanText(onlyB) });
    }
    [['A', ca, pa], ['B', cb, pb]].forEach(([end, c, p]) => {
      if (c.nativeVlan && !p.all && !p.ids.includes(+c.nativeVlan)) add('native_not_allowed', { end, v: c.nativeVlan });
    });
    return out;
  }
  // 整條線的狀態：high／medium／undef（有一端未設定）／ok-trunk／ok-access
  function linkState(d, l) {
    const is = linkIssues(d, l);
    if (is.some(x => x.level === 'high')) return 'high';
    if (is.some(x => x.level === 'medium')) return 'medium';
    if (is.some(x => x.type === 'undef')) return 'undef';
    return l.a.cfg.mode === 'access' ? 'access' : 'trunk';
  }

  // 交給交換器設定產生器：組成交換器分析 parser 的形狀（applyParsedConfigToForm 讀 sys／vlans／interfaces），
  // 型號的全部資料埠（不含管理埠）都列入；串接埠依該端設定並自動寫描述，其餘為 access、VLAN 空白
  const GEN_VENDOR = { cisco_nxos: 'nxos', h3c: 'comware' };
  function generatorModel(d, id) {
    const dev = devById(d, id), sp = SP();
    if (!dev || !sp) return null;
    const m = findModel(dev.vendor, dev.model), ends = new Map();
    d.links.forEach(l => {
      if (l.a.dev === id) ends.set(lc(l.a.port), { cfg: l.a.cfg, peer: l.b });
      if (l.b.dev === id) ends.set(lc(l.b.port), { cfg: l.b.cfg, peer: l.a });
    });
    const interfaces = (m ? sp.expandPorts(m) : []).filter(p => !p.mgmt).map(p => {
      const e = ends.get(lc(p.name)), c = e && e.cfg, peer = e && devById(d, e.peer.dev);
      // vlan 與 vlans 同值：產生器對 NX-OS 交接會以 vlan 欄位覆寫 vlans（normalizeNXOSInterfaceVlans）
      return { name: p.name, type: 'physical', speed: p.speed, mode: c ? c.mode : 'access', vlans: c ? c.vlans : '', vlan: c ? c.vlans : '', nativeVlan: c && c.mode === 'trunk' ? c.nativeVlan : '',
        desc: peer ? ('to ' + peer.hostname + ' ' + e.peer.port).slice(0, 80) : '', shutdown: false };
    });
    const sys = { hostname: dev.hostname };
    if (dev.vendor === 'h3c') sys.brand = 'h3c';
    // 聚合（XN204）：交換器分析 parser 的 lacp 形狀，產生器 applyParsedConfigToForm() 讀名稱中的數字、mode 與成員陣列
    const lacp = (d.lags || []).filter(g => g.a.dev === id || g.b.dev === id).map(g => ({ name: 'Port-channel' + (g.a.dev === id ? g.a.num : g.b.num), mode: g.mode, members: lagPortsOn(d, g, id) }));
    return { vendor: GEN_VENDOR[dev.vendor] || dev.vendor, sys, vlans: d.vlans.map(v => ({ id: String(v.id), name: v.name })), interfaces, lacp };
  }

  // 設計檔：設備以名稱互相參照（ID 每次讀入重新產生）；自訂型號只存名稱（value 是本機 localStorage 的編號）
  function buildDesign(d) {
    const hostOf = id => (devById(d, id) || {}).hostname || '';
    const end = e => (e.cfg ? { host: hostOf(e.dev), port: e.port, cfg: Object.assign({}, e.cfg) } : { host: hostOf(e.dev), port: e.port });
    const lags = (d.lags || []).filter(g => lagMembers(d, g.id).length), lagIdx = new Map(lags.map((g, i) => [g.id, i]));
    return {
      format: 'alpaca-design', version: 3,
      lags: lags.map(g => ({ a: { host: hostOf(g.a.dev), num: g.a.num }, b: { host: hostOf(g.b.dev), num: g.b.num }, mode: g.mode })),
      vlans: d.vlans.map(v => ({ id: v.id, name: v.name })),
      devices: d.devices.map(x => {
        const m = findModel(x.vendor, x.model);
        return m && m.custom ? { hostname: x.hostname, vendor: x.vendor, model: '', custom: m.label, x: x.x, y: x.y } : { hostname: x.hostname, vendor: x.vendor, model: x.model, x: x.x, y: x.y };
      }),
      links: d.links.map(l => Object.assign({ a: end(l.a), b: end(l.b) }, l.lag && lagIdx.has(l.lag) ? { lag: lagIdx.get(l.lag) } : {})),
    };
  }
  const str = (v, n) => (typeof v === 'string' && v.length <= n ? v : null);
  const num = v => (typeof v === 'number' && isFinite(v) ? v : null);
  // 設計檔裡一端的設定：只接受字串欄位，交給 normCfg() 檢查 VLAN
  const fileCfg = c => (c == null ? null : (c && typeof c === 'object' && str(c.mode, 8) != null && str(c.vlans, 200) != null && (c.nativeVlan == null || str(c.nativeVlan, 4) != null)
    ? { mode: c.mode, vlans: c.vlans, nativeVlan: c.nativeVlan || '' } : undefined));
  // 讀入設計檔（第 1、2 版）：結構或 VLAN 不合格整份拒絕；本機找不到的型號清空並計數（missing），埠對不上的線略過並計數（dropped）
  function parseDesign(text) {
    let o;
    try { o = JSON.parse(String(text || '')); } catch (e) { return { ok: false, code: 'json' }; }
    if (!o || typeof o !== 'object' || o.format !== 'alpaca-design' || (o.version !== 1 && o.version !== 2 && o.version !== 3) || !Array.isArray(o.devices) || !Array.isArray(o.links)) return { ok: false, code: 'format' };
    if ((o.vlans != null && !Array.isArray(o.vlans)) || (o.lags != null && !Array.isArray(o.lags))) return { ok: false, code: 'format' };
    if (o.devices.length > MAX_DEVICES || o.links.length > MAX_LINKS || (o.vlans || []).length > MAX_VLANS) return { ok: false, code: 'max' };
    const d = newDesign(), byHost = new Map();
    let missing = 0, dropped = 0;
    const lagLinks = (o.lags || []).map(() => []);   // 每個聚合讀入後的連線索引
    for (const v of o.vlans || []) {
      if (!v || typeof v !== 'object' || num(v.id) == null || (v.name != null && str(v.name, 32) == null) || !addVlan(d, { id: v.id, name: v.name || '' }).ok) return { ok: false, code: 'vlan' };
    }
    for (const x of o.devices) {
      const hostname = x && str(x.hostname, 32), vendor = x && str(x.vendor, 32), model = x && x.model != null ? str(x.model, 200) : '', custom = x && x.custom != null ? str(x.custom, 200) : '';
      if (!hostname || !HOST_RE.test(hostname) || byHost.has(lc(hostname)) || !vendor || !VENDOR_IDS.includes(vendor) || model == null || custom == null || num(x.x) == null || num(x.y) == null) return { ok: false, code: 'device' };
      let value = model;
      if (custom) { const m = modelChoices(vendor).find(c => c.custom && c.label === custom); value = m ? m.value : ''; }
      if (!findModel(vendor, value)) { value = ''; missing++; }
      const dev = { id: 'd' + (++d.seq), hostname, vendor, model: value, x: clamp(x.x, 0, CANVAS_W - BOX_W), y: clamp(x.y, 0, MAX_H - BOX_H) };
      d.devices.push(dev);
      byHost.set(lc(hostname), dev);
    }
    for (const l of o.links) {
      const ah = l && l.a && str(l.a.host, 32), ap = l && l.a && str(l.a.port, 128), bh = l && l.b && str(l.b.host, 32), bp = l && l.b && str(l.b.port, 128);
      if (!ah || !ap || !bh || !bp || !byHost.has(lc(ah)) || !byHost.has(lc(bh))) return { ok: false, code: 'link' };
      const fa = fileCfg(l.a.cfg), fb = fileCfg(l.b.cfg);
      if (fa === undefined || fb === undefined) return { ok: false, code: 'vlan' };
      if (l.lag != null && !(Number.isInteger(l.lag) && l.lag >= 0 && l.lag < lagLinks.length)) return { ok: false, code: 'lag' };
      const r = addLink(d, { dev: byHost.get(lc(ah)).id, port: ap }, { dev: byHost.get(lc(bh)).id, port: bp });
      if (!r.ok) { dropped++; continue; }
      const i = d.links.length - 1;
      if (!setEndCfg(d, i, 'a', fa).ok || !setEndCfg(d, i, 'b', fb).ok) return { ok: false, code: 'vlan' };
      if (l.lag != null) lagLinks[l.lag].push(i);
    }
    // 聚合：成員都讀得到時重建；兩端名稱與編號須對得上第一條成員，否則整份拒絕；成員全部被略過的聚合跟著略過
    for (let k = 0; k < lagLinks.length; k++) {
      const g = o.lags[k], ah = g && g.a && str(g.a.host, 32), bh = g && g.b && str(g.b.host, 32);
      if (!ah || !bh || !byHost.has(lc(ah)) || !byHost.has(lc(bh))) return { ok: false, code: 'lag' };
      if (!lagLinks[k].length) continue;
      const first = d.links[lagLinks[k][0]], da = byHost.get(lc(ah)).id, db = byHost.get(lc(bh)).id;
      if (!((first.a.dev === da && first.b.dev === db) || (first.a.dev === db && first.b.dev === da))) return { ok: false, code: 'lag' };
      const flip = first.a.dev !== da;
      const r = addLag(d, lagLinks[k], { aNum: flip ? g.b.num : g.a.num, bNum: flip ? g.a.num : g.b.num, mode: g.mode });
      if (!r.ok) return { ok: false, code: 'lag' };
    }
    return { ok: true, design: d, missing, dropped };
  }

  // 只做結構檢查的讀法（XN205，交換器分析比對實際接線用）：不依本機型號資料，別台瀏覽器的自訂型號也不會讓線被略過
  function readDesignRaw(text) {
    let o;
    try { o = JSON.parse(String(text || '')); } catch (e) { return { ok: false, code: 'json' }; }
    if (!o || typeof o !== 'object' || o.format !== 'alpaca-design' || ![1, 2, 3].includes(o.version) || !Array.isArray(o.devices) || !Array.isArray(o.links)) return { ok: false, code: 'format' };
    if (o.devices.length > MAX_DEVICES || o.links.length > MAX_LINKS) return { ok: false, code: 'max' };
    const devices = [], hosts = new Set();
    for (const x of o.devices) {
      const h = x && str(x.hostname, 32), v = x && str(x.vendor, 32);
      if (!h || !HOST_RE.test(h) || hosts.has(lc(h)) || !v) return { ok: false, code: 'device' };
      hosts.add(lc(h));
      devices.push({ hostname: h, vendor: v });
    }
    const end = e => {
      const h = e && str(e.host, 32), pt = e && str(e.port, 128);
      if (!h || !pt || !hosts.has(lc(h))) return null;
      const c = fileCfg(e.cfg);
      return c === undefined ? null : { host: h, port: pt, cfg: c };
    };
    const links = [];
    for (const l of o.links) {
      const a = end(l && l.a), b = end(l && l.b);
      if (!a || !b) return { ok: false, code: 'link' };
      links.push({ a, b });
    }
    return { ok: true, devices, links };
  }

  // ── SVG 畫布 ──
  const xesc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const cut = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1) + '…' : String(s));
  const center = dev => ({ x: dev.x + BOX_W / 2, y: dev.y + BOX_H / 2 });
  // 畫布上的埠名縮寫（只影響顯示）：長名稱的介面型別換成常見縮寫
  const SHORT = [[/^HundredGigE/i, 'Hu'], [/^FortyGigabitEthernet/i, 'Fo'], [/^TwentyFiveGigE/i, 'Twe'], [/^TenGigabitEthernet/i, 'Te'],
    [/^Ten-GigabitEthernet/i, 'XGE'], [/^GigabitEthernet/i, 'Gi'], [/^FastEthernet/i, 'Fa'], [/^Ethernet/i, 'Et']];
  const shortPort = p => { for (const [re, r] of SHORT) if (re.test(p)) return String(p).replace(re, r); return String(p); };
  // 線的顏色：一致的 trunk 綠、access 藍；有 high 紅、只有 medium 黃；有一端未設定灰
  const STATE_COLOR = { trunk: '#22c55e', access: '#3b82f6', high: '#ef4444', medium: '#eab308', undef: '#94a3b8' };
  const cfgShort = c => (!c ? '' : c.mode === 'access' ? 'A ' + c.vlans : 'T ' + c.vlans);
  // 同一對設備的多條線（XN203）：依序往線的垂直方向位移，不疊在一起；方向以 ID 較小的設備為準，兩端順序不同也一致
  const PAR_GAP = 16;
  function parallelOffsets(d) {
    const pair = l => (l.a.dev < l.b.dev ? l.a.dev + '|' + l.b.dev : l.b.dev + '|' + l.a.dev);
    const groups = new Map(), out = [];
    d.links.forEach((l, i) => { const k = pair(l); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(i); });
    groups.forEach(idx => idx.forEach((li, k) => { out[li] = (k - (idx.length - 1) / 2) * PAR_GAP; }));
    return out;
  }
  function linksSvg(d) {
    const offs = parallelOffsets(d), mids = [];
    const lines = d.links.map((l, i) => {
      const a = devById(d, l.a.dev), b = devById(d, l.b.dev);
      if (!a || !b) return '';
      const st = linkState(d, l), col = STATE_COLOR[st];
      const p0 = center(a), q0 = center(b), flip = l.a.dev < l.b.dev ? 1 : -1;
      const dx = q0.x - p0.x, dy = q0.y - p0.y, len = Math.hypot(dx, dy) || 1, ox = -dy / len * offs[i] * flip, oy = dx / len * offs[i] * flip;
      const p = { x: +(p0.x + ox).toFixed(1), y: +(p0.y + oy).toFixed(1) }, q = { x: +(q0.x + ox).toFixed(1), y: +(q0.y + oy).toFixed(1) };
      const at = t => ({ x: p.x + (q.x - p.x) * t, y: p.y + (q.y - p.y) * t });
      mids[i] = at(0.4);
      const lbl = (pt, txt, full, extra) => `<text x="${pt.x.toFixed(1)}" y="${pt.y.toFixed(1)}" text-anchor="middle" font-size="10" fill="${extra || 'currentColor'}" stroke="var(--card)" stroke-width="3" paint-order="stroke"><title>${xesc(full)}</title>${xesc(txt)}</text>`;
      // 線中間：兩端設定相同時只寫一次，不同時寫「A 端｜B 端」
      const sa = cfgShort(l.a.cfg), sb = cfgShort(l.b.cfg), mid = sa === sb ? sa : (sa || '?') + ' | ' + (sb || '?');
      const midTxt = (st === 'high' || st === 'medium' ? '⚠ ' : '') + mid;
      return `<g data-td-link="${i}" data-td-state="${st}"><line x1="${p.x}" y1="${p.y}" x2="${q.x}" y2="${q.y}" stroke="${col}" stroke-width="${st === 'high' ? 3 : 2}"${st === 'undef' ? ' stroke-dasharray="5 4"' : ''}/>`
        + lbl(at(0.25), cut(shortPort(l.a.port), 22), l.a.port) + lbl(at(0.75), cut(shortPort(l.b.port), 22), l.b.port)
        + (mid ? lbl(at(0.5), cut(midTxt, 30), midTxt, col) : '') + '</g>';
    }).join('');
    // 聚合（XN204）：成員線段外圍一個虛線框，標「Po 兩端編號 ×成員數」
    const lagBoxes = (d.lags || []).map(g => {
      const pts = d.links.map((l, i) => (l.lag === g.id ? mids[i] : null)).filter(Boolean);
      if (!pts.length) return '';
      const xs = pts.map(p => p.x), ys = pts.map(p => p.y), x0 = Math.min(...xs) - 10, y0 = Math.min(...ys) - 10, x1 = Math.max(...xs) + 10, y1 = Math.max(...ys) + 10;
      const txt = 'Po' + g.a.num + (g.a.num === g.b.num ? '' : '/' + g.b.num) + ' ×' + pts.length;
      return `<g data-td-lag="${xesc(g.id)}"><rect x="${x0.toFixed(1)}" y="${y0.toFixed(1)}" width="${(x1 - x0).toFixed(1)}" height="${(y1 - y0).toFixed(1)}" rx="8" fill="none" stroke="#a855f7" stroke-width="1.5" stroke-dasharray="4 3"/>`
        + `<text x="${((x0 + x1) / 2).toFixed(1)}" y="${(y0 - 3).toFixed(1)}" text-anchor="middle" font-size="10" font-weight="600" fill="#a855f7" stroke="var(--card)" stroke-width="3" paint-order="stroke">${xesc(txt)}</text></g>`;
    }).join('');
    return lines + lagBoxes;
  }
  function deviceSvg(d, dev, sel, T) {
    const m = findModel(dev.vendor, dev.model), total = portsOf(dev.vendor, dev.model).length, used = usedPorts(d, dev.id).size;
    const stroke = sel === dev.id ? 'var(--accent)' : 'var(--border)';
    return `<g data-td-dev="${xesc(dev.id)}" transform="translate(${dev.x},${dev.y})" style="cursor:grab">`
      + `<title>${xesc(dev.hostname + ' · ' + vendorName(dev.vendor) + ' · ' + (m ? m.label : '?'))}</title><rect width="${BOX_W}" height="${BOX_H}" rx="6" fill="var(--chip)" stroke="${stroke}" stroke-width="${sel === dev.id ? 2.5 : 1.5}"/>`
      + `<text x="8" y="18" font-size="13" font-weight="600" fill="currentColor">${xesc(cut(dev.hostname, 24))}</text>`
      + `<text x="8" y="34" font-size="10" fill="var(--dim)">${xesc(cut(vendorName(dev.vendor) + ' · ' + (m ? m.label : '?'), 34))}</text>`
      + `<text x="8" y="49" font-size="10" fill="var(--dim)">${xesc(T('td.ports_used', { used, total }))}</text></g>`;
  }
  function canvasSvg(d, sel, T) {
    const H = canvasH(d);
    return `<svg data-td-svg viewBox="0 0 ${CANVAS_W} ${H}" width="100%" style="display:block;max-width:${CANVAS_W}px;min-width:720px;aspect-ratio:${CANVAS_W}/${H};touch-action:none;user-select:none;color:var(--text)" role="img">`
      + `<rect width="${CANVAS_W}" height="${H}" fill="var(--bg)" stroke="var(--border)"/>`
      + `<g data-td-links>${linksSvg(d)}</g>${d.devices.map(x => deviceSvg(d, x, sel, T)).join('')}</svg>`;
  }

  // ── 匯出（XN203）：只含名稱、廠牌、型號、埠與模式／VLAN，不含位址 ──
  // 獨立 SVG：畫布的 CSS 變數換成固定的淺色配色，下載後直接開啟也正確
  const FILE_COLORS = { bg: '#ffffff', card: '#ffffff', text: '#1f2328', dim: '#59636e', border: '#d0d7de', accent: '#0969da', chip: '#eef1f4' };
  function designToSvg(d, T) {
    const H = canvasH(d);
    const body = canvasSvg(d, null, T || (k => k)).replace(/^<svg[^>]*>/, '');
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${CANVAS_W} ${H}" width="${CANVAS_W}" height="${H}" font-family="sans-serif" color="${FILE_COLORS.text}">`
      + body.replace(/var\(--([a-z]+)\)/g, (m, k) => FILE_COLORS[k] || FILE_COLORS.text).replace(/currentColor/g, FILE_COLORS.text).replace(/ style="cursor:grab"/g, '') + '\n';
  }
  // draw.io：標籤樣式 html=1，XML 解開後會當 HTML 解讀，名稱先 HTML 再 XML 兩層跳脫（與接線拓樸 cablingToDrawio 相同）
  const xh = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const xml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
  const xa = s => xml(xh(s));
  const devLabel = dev => { const m = findModel(dev.vendor, dev.model); return vendorName(dev.vendor) + ' · ' + (m ? m.label : '?'); };
  const linkLabel = l => { const sa = cfgShort(l.a.cfg), sb = cfgShort(l.b.cfg); return l.a.port + ' ↔ ' + l.b.port + (sa || sb ? ' · ' + (sa === sb ? sa : (sa || '?') + ' | ' + (sb || '?')) : ''); };
  function designToDrawio(d) {
    const cells = [];
    d.devices.forEach(x => cells.push(`<mxCell id="${xml(x.id)}" value="${xml(xh(x.hostname) + '<br>' + xh(devLabel(x)))}" style="rounded=1;html=1;whiteSpace=wrap;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1"><mxGeometry x="${x.x}" y="${x.y}" width="${BOX_W}" height="${BOX_H}" as="geometry"/></mxCell>`));
    d.links.forEach((l, i) => {
      const st = linkState(d, l);
      cells.push(`<mxCell id="e${i}" value="${xa(linkLabel(l))}" style="endArrow=none;html=1;fontSize=9;strokeWidth=2;strokeColor=${STATE_COLOR[st]};${st === 'undef' ? 'dashed=1;' : ''}" edge="1" parent="1" source="${xml(l.a.dev)}" target="${xml(l.b.dev)}"><mxGeometry relative="1" as="geometry"/></mxCell>`);
    });
    return `<mxfile host="app.diagrams.net"><diagram id="design" name="design"><mxGraphModel grid="1" gridSize="10" page="1" pageWidth="1169" pageHeight="${Math.max(827, canvasH(d) + 20)}"><root><mxCell id="0"/><mxCell id="1" parent="0"/>${cells.join('')}</root></mxGraphModel></diagram></mxfile>\n`;
  }
  // Mermaid：引號、角括號換實體碼，換行換空白、反引號換實體碼（與 cablingToMermaid 相同）
  const mm = s => String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').replace(/"/g, '#quot;').replace(/</g, '#lt;').replace(/>/g, '#gt;').replace(/`/g, '#96;');
  function designToMermaid(d) {
    const out = ['flowchart LR'];
    d.devices.forEach(x => out.push(`  ${x.id}["${mm(x.hostname)}<br/>${mm(devLabel(x))}"]`));
    d.links.forEach(l => out.push(`  ${l.a.dev} ${linkState(d, l) === 'undef' ? '-.-' : '---'}|"${mm(linkLabel(l) + (/^(high|medium)$/.test(linkState(d, l)) ? ' ⚠' : ''))}"| ${l.b.dev}`));
    return out.join('\n') + '\n';
  }

  const api = {
    readDesignRaw, changeDevice, parallelOffsets, designToSvg, designToDrawio, designToMermaid,
    VENDORS, VENDOR_IDS, vendorName, shortPort, modelChoices, findModel, portsOf, newDesign, addDevice, removeDevice, moveDevice, addLink, removeLink,
    usedPorts, buildDesign, parseDesign, canvasSvg, canvasH, DESIGN_ERR_CODES, ERR_CODES, MAX_DEVICES, MAX_LINKS, MAX_VLANS, CANVAS_W, CANVAS_H, MAX_H, BOX_W, BOX_H,
    addLag, removeLag, LAG_MODES, LAG_NUM_MAX,
    parseVlanList, vlanText, addVlan, removeVlan, normCfg, setEndCfg, linkIssues, linkState, LINK_ISSUE_TYPES, ISSUE_LEVEL, generatorModel,
  };
  if (typeof window !== 'undefined') window.TopoDesigner = api;
  if (typeof document === 'undefined' || typeof LANG_TD === 'undefined') return;

  // ── 畫面 ──
  const FORMAL = ['zhTW', 'en', 'ja'], LANG_ORDER = ['zhTW', 'en', 'ja', 'tlh', 'pirate', 'emoji', 'bureau', 'cat', 'bean', 'alpaca', 'yanse', 'wuxia'];
  const LANG_NAME = { zhTW: '繁體中文', en: 'English', ja: '日本語', tlh: 'tlhIngan Hol', pirate: 'Pirate', emoji: 'Emoji', bureau: '公文體', cat: '喵語', bean: '豆語', alpaca: '羊駝語', yanse: '厭世語', wuxia: '武俠' };
  // 語言：正式語言與其他工具共用 cw_lang，沒存過時依瀏覽器語言；本頁選的彩蛋語言另存 topo_designer_lang
  function loadLang() {
    try { const egg = localStorage.getItem('topo_designer_lang'); if (LANG_TD[egg] && FORMAL.indexOf(egg) < 0) return egg; } catch (e) { /* 略過 */ }
    try { const v = localStorage.getItem('cw_lang'); if (FORMAL.indexOf(v) >= 0) return v; } catch (e) { /* 略過 */ }
    const n = lc(navigator.language);
    return n.indexOf('ja') === 0 ? 'ja' : (n.indexOf('zh') === 0 || !n ? 'zhTW' : 'en');
  }
  function saveLang(l) {
    try {
      if (FORMAL.indexOf(l) >= 0) { localStorage.setItem('cw_lang', l); localStorage.removeItem('topo_designer_lang'); }
      else localStorage.setItem('topo_designer_lang', l);
    } catch (e) { /* 略過 */ }
  }
  let lang = loadLang();
  const tr = k => (LANG_TD[lang] && LANG_TD[lang][k]) || LANG_TD.zhTW[k] || k;
  window.tr = window.tr || tr;   // 共用模組（panel-svg 等）以 typeof tr 取得翻譯
  const T = (k, p) => { let s = tr(k); Object.keys(p || {}).forEach(n => { s = s.split('{' + n + '}').join(String(p[n])); }); return s; };
  const esc = xesc;
  const $ = id => document.getElementById(id);
  let D = newDesign(), sel = null, pickNext = 'a', msg = '', msgBad = false;
  const say = (text, bad) => { msg = text; msgBad = !!bad; const el = $('td-msg'); if (el) { el.textContent = msg; el.className = bad ? 'msg bad' : 'msg'; } };

  function fillStatic() {
    document.documentElement.lang = lang === 'zhTW' ? 'zh-Hant' : lang === 'ja' ? 'ja' : 'en';
    document.title = tr('td.title');
    document.querySelectorAll('[data-td-i18n]').forEach(el => { el.textContent = tr(el.getAttribute('data-td-i18n')); });
    document.querySelectorAll('[data-td-i18n-ph]').forEach(el => { el.placeholder = tr(el.getAttribute('data-td-i18n-ph')); });
    const ls = $('td-lang-sel');
    ls.innerHTML = LANG_ORDER.map(l => `<option value="${l}"${l === lang ? ' selected' : ''}>${esc(LANG_NAME[l])}</option>`).join('');
    const vs = $('td-vendor'), cur = vs.value || 'cisco';
    vs.innerHTML = VENDORS.map(v => `<option value="${esc(v[0])}"${v[0] === cur ? ' selected' : ''}>${esc(v[1])}</option>`).join('');
    const dv = $('td-de-vendor'), dcur = dv.value || cur;
    dv.innerHTML = VENDORS.map(v => `<option value="${esc(v[0])}"${v[0] === dcur ? ' selected' : ''}>${esc(v[1])}</option>`).join('');
    const lm = $('td-lag-mode'), lkeep = lm.value || 'active';
    lm.innerHTML = LAG_MODES.map(v => `<option value="${v}"${v === lkeep ? ' selected' : ''}>${esc(tr('td.lag_mode_' + v))}</option>`).join('');
    ['l', 'e'].forEach(pfx => { const m = $('td-' + pfx + '-mode'), keep = m.value; m.innerHTML = ['', 'access', 'trunk'].map(v => `<option value="${v}"${v === keep ? ' selected' : ''}>${esc(tr(v ? 'td.mode_' + v : 'td.mode_none'))}</option>`).join(''); });
    fillModels();
    fillCustom();
    fillDevEditModels();
    if (window.renderToolkitVersion) window.renderToolkitVersion(lang);
  }
  function fillModels() {
    const ms = $('td-model'), keep = ms.value, list = modelChoices($('td-vendor').value);
    ms.innerHTML = `<option value="">${esc(tr('td.pick'))}</option>` + list.map(m => `<option value="${esc(m.value)}"${m.value === keep ? ' selected' : ''}>${esc(m.label)}${m.custom ? ' (' + esc(tr('td.custom')) + ')' : ''}</option>`).join('');
    const hint = $('td-model-hint');
    if (hint) { hint.hidden = list.length > 0; hint.textContent = tr('td.no_models'); }
  }
  // 自訂型號編輯區（panel-svg.js，與交換器分析、防火牆共用同一份 localStorage）；沒有內建型號時預設展開
  function fillCustom() {
    const box = $('td-custom'), ps = window.PanelSvg;
    if (!box || !ps) return;
    const open = box.querySelector('details[open]') || !modelChoices($('td-vendor').value).length;
    box.innerHTML = ps.customEditorHtml('td', !!open);
  }
  function fillEnd(end) {
    const dsel = $('td-' + end + '-dev'), psel = $('td-' + end + '-port'), keepD = dsel.value, keepP = psel.value;
    dsel.innerHTML = `<option value="">${esc(tr('td.pick'))}</option>` + D.devices.map(x => `<option value="${esc(x.id)}"${x.id === keepD ? ' selected' : ''}>${esc(x.hostname)}</option>`).join('');
    const dev = devById(D, dsel.value), used = dev ? usedPorts(D, dev.id) : new Set();
    const ports = dev ? portsOf(dev.vendor, dev.model).filter(p => !used.has(lc(p))) : [];
    psel.innerHTML = `<option value="">${esc(tr('td.pick'))}</option>` + ports.map(p => `<option value="${esc(p)}"${p === keepP ? ' selected' : ''}>${esc(p)}</option>`).join('');
  }
  // 連線模式表單（建立連線 l、編輯一端 e 共用同一組欄位）
  const vlanOpt = (v, keep) => `<option value="${v.id}"${String(v.id) === String(keep) ? ' selected' : ''}>${v.id}${v.name ? ' ' + esc(v.name) : ''}</option>`;
  function fillCfgForm(pfx, cfg) {
    const mode = $('td-' + pfx + '-mode'), vsel = $('td-' + pfx + '-vlan'), allowed = $('td-' + pfx + '-allowed'), nat = $('td-' + pfx + '-native');
    if (cfg !== undefined) {
      mode.value = cfg ? cfg.mode : '';
      allowed.value = cfg && cfg.mode === 'trunk' ? cfg.vlans : '';
    }
    const keepV = cfg !== undefined ? (cfg && cfg.mode === 'access' ? cfg.vlans : '') : vsel.value;
    const keepN = cfg !== undefined ? (cfg && cfg.mode === 'trunk' ? cfg.nativeVlan : '') : nat.value;
    vsel.innerHTML = D.vlans.map(v => vlanOpt(v, keepV)).join('');
    nat.innerHTML = `<option value="">${esc(tr('td.native_default'))}</option>` + D.vlans.map(v => vlanOpt(v, keepN)).join('');
    document.querySelectorAll(`[data-td-show^="${pfx}-"]`).forEach(el => { el.hidden = el.getAttribute('data-td-show') !== pfx + '-' + mode.value; });
  }
  const readCfgForm = pfx => {
    const mode = $('td-' + pfx + '-mode').value;
    if (!mode) return null;
    return mode === 'access' ? { mode, vlans: $('td-' + pfx + '-vlan').value } : { mode, vlans: $('td-' + pfx + '-allowed').value, nativeVlan: $('td-' + pfx + '-native').value };
  };
  const cfgText = c => (!c ? tr('td.cfg_none') : c.mode === 'access' ? T('td.cfg_access', { v: c.vlans }) : T('td.cfg_trunk', { v: c.vlans }) + (c.nativeVlan ? ' · ' + T('td.cfg_native', { v: c.nativeVlan }) : ''));
  const issueText = is => T('td.li_' + is.type, Object.assign({ none: tr('td.none') }, is.p, { onlyA: is.p.onlyA || tr('td.none'), onlyB: is.p.onlyB || tr('td.none'), common: is.p.common || tr('td.none') }));
  let editing = null;   // 正在編輯的一端 {i, end}
  let devEdit = null;   // 正在編輯的設備 {id, pending}（pending＝已確認要刪除的線，等使用者按確認）
  function fillDevEditModels(keep) {
    const ms = $('td-de-model'), list = modelChoices($('td-de-vendor').value), k = keep !== undefined ? keep : ms.value;
    ms.innerHTML = `<option value="">${esc(tr('td.pick'))}</option>` + list.map(m => `<option value="${esc(m.value)}"${m.value === k ? ' selected' : ''}>${esc(m.label)}${m.custom ? ' (' + esc(tr('td.custom')) + ')' : ''}</option>`).join('');
  }
  function openDevEdit(id) {
    const dev = devById(D, id);
    if (!dev) return;
    devEdit = { id, pending: null };
    $('td-de-host').value = dev.hostname;
    $('td-de-vendor').value = dev.vendor;
    fillDevEditModels(dev.model);
    render();
    const box = $('td-dev-edit');
    if (box.scrollIntoView) box.scrollIntoView({ block: 'nearest' });
  }
  const readDevEdit = () => ({ hostname: $('td-de-host').value, vendor: $('td-de-vendor').value, model: $('td-de-model').value });
  function applyDevEdit(confirmed) {
    if (!devEdit) return;
    const o = readDevEdit();
    const dry = changeDevice(D, devEdit.id, o, { dryRun: true });
    if (!dry.ok) { say(tr('td.err_' + dry.code), true); return; }
    if (dry.drop.length && !confirmed) {
      const hostOf = id => (devById(D, id) || {}).hostname || '';
      devEdit.pending = dry.drop.slice();
      $('td-de-drop').textContent = T('td.dev_drop', { n: dry.drop.length, links: dry.drop.map(i => { const l = D.links[i]; return hostOf(l.a.dev) + ' ' + l.a.port + ' ↔ ' + hostOf(l.b.dev) + ' ' + l.b.port; }).join('；') });
      $('td-de-drop').hidden = false; $('td-de-confirm').hidden = false;
      return;
    }
    changeDevice(D, devEdit.id, o);
    devEdit = null; editing = null; lagPick = new Set();
    render();
    say(T('td.dev_saved', { host: o.hostname.trim() }));
  }
  function render() {
    $('td-canvas').innerHTML = D.devices.length ? canvasSvg(D, sel, T) : `<div class="hint">${esc(tr('td.empty_canvas'))}</div>`;
    fillEnd('a'); fillEnd('b');
    fillCfgForm('l');
    if (editing && !D.links[editing.i]) editing = null;
    if (devEdit && !devById(D, devEdit.id)) devEdit = null;
    $('td-dev-edit').hidden = !devEdit;
    if (devEdit) $('td-de-title').textContent = T('td.dev_edit_title', { host: devById(D, devEdit.id).hostname });
    else { $('td-de-drop').hidden = true; $('td-de-confirm').hidden = true; }
    $('td-end-edit').hidden = !editing;
    if (editing) { const l = D.links[editing.i], e = l[editing.end]; $('td-end-title').textContent = T('td.end_edit_title', { host: (devById(D, e.dev) || {}).hostname || '', port: e.port }); fillCfgForm('e'); }
    $('td-vlan-list').innerHTML = D.vlans.length
      ? `<table><thead><tr><th>${esc(tr('td.col_vlan_id'))}</th><th>${esc(tr('td.col_vlan_name'))}</th><th></th></tr></thead><tbody>`
        + D.vlans.map(v => `<tr><td>${v.id}</td><td>${esc(v.name)}</td><td><button class="btn btn-sm" data-td-rm-vlan="${v.id}">${esc(tr('td.rm'))}</button></td></tr>`).join('') + '</tbody></table>'
      : `<div class="hint">${esc(tr('td.no_vlans'))}</div>`;
    const hostOf = id => (devById(D, id) || {}).hostname || '';
    $('td-dev-list').innerHTML = D.devices.length
      ? `<table><thead><tr><th>${esc(tr('td.col_host'))}</th><th>${esc(tr('td.col_vendor'))}</th><th>${esc(tr('td.col_model'))}</th><th>${esc(tr('td.col_ports'))}</th><th></th></tr></thead><tbody>`
        + D.devices.map(x => { const m = findModel(x.vendor, x.model); return `<tr><td>${esc(x.hostname)}</td><td>${esc(vendorName(x.vendor))}</td><td>${esc(m ? m.label : '?')}</td><td>${usedPorts(D, x.id).size}／${portsOf(x.vendor, x.model).length}</td><td style="white-space:nowrap"><button class="btn btn-sm" data-td-send="${esc(x.id)}">${esc(tr('td.send'))}</button> <button class="btn btn-sm" data-td-edit-dev="${esc(x.id)}">${esc(tr('td.edit_dev'))}</button> <button class="btn btn-sm" data-td-rm-dev="${esc(x.id)}">${esc(tr('td.rm'))}</button></td></tr>`; }).join('') + '</tbody></table>'
      : `<div class="hint">${esc(tr('td.no_devices'))}</div>`;
    const color = { high: 'var(--red)', medium: 'var(--yellow)', info: 'var(--dim)' };
    $('td-link-list').innerHTML = D.links.length
      ? `<table><thead><tr><th></th><th>${esc(tr('td.col_a'))}</th><th>${esc(tr('td.col_cfg_a'))}</th><th>${esc(tr('td.col_b'))}</th><th>${esc(tr('td.col_cfg_b'))}</th><th>${esc(tr('td.col_status'))}</th><th></th></tr></thead><tbody>`
        + D.links.map((l, i) => {
          const is = linkIssues(D, l);
          const st = is.length ? is.map(x => `<div data-td-issue="${x.type}" style="color:${color[x.level]}">${esc(issueText(x))}</div>`).join('') : `<span style="color:var(--green)">${esc(tr('td.st_ok'))}</span>`;
          const g = l.lag && lagById(D, l.lag);
          const pick = g ? `<span class="mono" style="color:#a855f7">${esc(lagName(g))}</span>` : `<input type="checkbox" data-td-lag-pick="${i}"${lagPick.has(i) ? ' checked' : ''} aria-label="${esc(tr('td.lag_add'))}">`;
          return `<tr data-td-link-row="${i}"><td>${pick}</td><td>${esc(hostOf(l.a.dev))} <span class="mono">${esc(l.a.port)}</span></td><td>${esc(cfgText(l.a.cfg))} <button class="btn btn-sm" data-td-edit="${i}:a">${esc(tr('td.edit'))}</button></td>`
            + `<td>${esc(hostOf(l.b.dev))} <span class="mono">${esc(l.b.port)}</span></td><td>${esc(cfgText(l.b.cfg))} <button class="btn btn-sm" data-td-edit="${i}:b">${esc(tr('td.edit'))}</button></td>`
            + `<td>${st}</td><td><button class="btn btn-sm" data-td-rm-link="${i}">${esc(tr('td.rm'))}</button></td></tr>`;
        }).join('') + '</tbody></table>'
      : `<div class="hint">${esc(tr('td.no_links'))}</div>`;
    renderLagBox();
  }
  // 聚合區（XN204）：勾選的線、兩端編號欄位標示設備名稱、已建立的聚合清單
  const lagName = g => 'Po' + g.a.num + (g.a.num === g.b.num ? '' : '/' + g.b.num);
  let lagPick = new Set();
  function renderLagBox() {
    lagPick = new Set([...lagPick].filter(i => D.links[i] && !D.links[i].lag));
    const first = D.links[[...lagPick][0]], hostOf = id => (devById(D, id) || {}).hostname || '';
    $('td-lag-a-lbl').textContent = first ? T('td.lag_num', { host: hostOf(first.a.dev) }) : T('td.lag_num', { host: 'A' });
    $('td-lag-b-lbl').textContent = first ? T('td.lag_num', { host: hostOf(first.b.dev) }) : T('td.lag_num', { host: 'B' });
    $('td-lag-list').innerHTML = (D.lags || []).length
      ? `<table><thead><tr><th>${esc(tr('td.col_lag'))}</th><th>${esc(tr('td.col_a'))}</th><th>${esc(tr('td.col_b'))}</th><th>${esc(tr('td.lag_mode'))}</th><th>${esc(tr('td.col_members'))}</th><th></th></tr></thead><tbody>`
        + D.lags.map(g => `<tr data-td-lag-row="${esc(g.id)}"><td class="mono">${esc(lagName(g))}</td><td>${esc(hostOf(g.a.dev))} Po${g.a.num}</td><td>${esc(hostOf(g.b.dev))} Po${g.b.num}</td><td>${esc(tr('td.lag_mode_' + g.mode))}</td>`
          + `<td class="mono">${esc(lagPortsOn(D, g, g.a.dev).join(', '))}</td><td><button class="btn btn-sm" data-td-rm-lag="${esc(g.id)}">${esc(tr('td.lag_rm'))}</button></td></tr>`).join('') + '</tbody></table>'
      : `<div class="hint">${esc(tr('td.lag_none'))}</div>`;
  }

  // 拖拉：畫布上抓住設備方塊；移動距離很小時視為點選（依序填入 A 端、B 端）
  let drag = null;
  const svgPoint = (svg, ev) => { const m = svg.getScreenCTM(); if (!m) return { x: 0, y: 0 }; const p = new DOMPoint(ev.clientX, ev.clientY).matrixTransform(m.inverse()); return { x: p.x, y: p.y }; };
  function onDown(ev) {
    const g = ev.target.closest && ev.target.closest('[data-td-dev]'), svg = ev.target.closest && ev.target.closest('[data-td-svg]');
    if (!g || !svg) return;
    const dev = devById(D, g.getAttribute('data-td-dev'));
    if (!dev) return;
    const p = svgPoint(svg, ev);
    drag = { dev, svg, g, dx: p.x - dev.x, dy: p.y - dev.y, sx: ev.clientX, sy: ev.clientY, moved: false };
    try { svg.setPointerCapture(ev.pointerId); } catch (e) { /* 略過 */ }
    ev.preventDefault();
  }
  function onMove(ev) {
    if (!drag) return;
    if (Math.abs(ev.clientX - drag.sx) + Math.abs(ev.clientY - drag.sy) > 4) drag.moved = true;
    if (!drag.moved) return;
    const p = svgPoint(drag.svg, ev);
    moveDevice(D, drag.dev.id, p.x - drag.dx, p.y - drag.dy);
    drag.g.setAttribute('transform', `translate(${drag.dev.x},${drag.dev.y})`);
    const lk = drag.svg.querySelector('[data-td-links]');
    if (lk) lk.innerHTML = linksSvg(D);
  }
  function onUp() {
    if (!drag) return;
    const d = drag;
    drag = null;
    // 拖到最下面時畫布要長高；其他情況方塊已在原位，不必重畫
    if (d.moved) { if (canvasH(D) !== +String(d.svg.getAttribute('viewBox')).split(' ')[3]) render(); return; }
    // 點選：依序填入 A 端、B 端
    $('td-' + pickNext + '-dev').value = d.dev.id;
    sel = d.dev.id;
    const end = pickNext;
    pickNext = pickNext === 'a' ? 'b' : 'a';
    render();
    say(T(end === 'a' ? 'td.picked_a' : 'td.picked_b', { host: d.dev.hostname }));
  }

  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type: type || 'application/json' }));
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function loadText(text) {
    const r = parseDesign(text);
    if (!r.ok) { say(tr('td.err_' + r.code), true); return r; }
    D = r.design; sel = null; pickNext = 'a'; editing = null; devEdit = null; lagPick = new Set();
    render();
    const parts = [T('td.loaded', { d: D.devices.length, l: D.links.length })];
    if (r.missing) parts.push(T('td.loaded_missing', { n: r.missing }));
    if (r.dropped) parts.push(T('td.loaded_dropped', { n: r.dropped }));
    say(parts.join(' '), !!(r.missing || r.dropped));
    return r;
  }
  // 送到交換器設定產生器：一次性交接 key（產生器開頁時讀取並清除，TTL 30 秒）；新分頁被擋下時立刻清掉
  const HANDOFF_KEY = '_netAnalyzer_swParsedModel';
  function sendToGenerator(id) {
    const dev = devById(D, id), parsed = generatorModel(D, id);
    if (!dev || !parsed) return false;
    const m = findModel(dev.vendor, dev.model);
    try { localStorage.setItem(HANDOFF_KEY, JSON.stringify({ ts: Date.now(), parsed, vendor: parsed.vendor, name: dev.hostname, deviceModel: m && !m.custom ? dev.model : '' })); } catch (e) { return false; }
    const w = window.open('switch-config-generator.html', '_blank');
    if (!w) { try { localStorage.removeItem(HANDOFF_KEY); } catch (e) { /* 略過 */ } say(tr('td.send_blocked'), true); return false; }
    try { w.opener = null; } catch (e) { /* 略過 */ }
    say(T('td.sent', { host: dev.hostname }));
    return true;
  }

  function init() {
    fillStatic();
    render();
    $('td-lang-sel').addEventListener('change', e => { lang = e.target.value; saveLang(lang); fillStatic(); render(); });
    $('td-vendor').addEventListener('change', () => { fillModels(); fillCustom(); });
    // 存檔／刪除自訂型號後：重填型號選單（剛存的直接選取），已放在畫布上的設備重畫
    window.addEventListener('pnl-custom', e => {
      if (!e.detail || e.detail.scope !== 'td') return;
      fillModels();
      if (e.detail.value) $('td-model').value = e.detail.value;
      fillCustom();
      fillDevEditModels();
      render();
    });
    ['a', 'b'].forEach(end => $('td-' + end + '-dev').addEventListener('change', () => fillEnd(end)));
    ['l', 'e'].forEach(pfx => $('td-' + pfx + '-mode').addEventListener('change', () => fillCfgForm(pfx)));
    $('td-dev-add').addEventListener('click', () => {
      const r = addDevice(D, { hostname: $('td-host').value, vendor: $('td-vendor').value, model: $('td-model').value });
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      $('td-host').value = '';
      render();
      say(T('td.added_dev', { host: r.dev.hostname }));
    });
    $('td-vlan-add').addEventListener('click', () => {
      const r = addVlan(D, { id: $('td-vlan-id').value, name: $('td-vlan-name').value });
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      $('td-vlan-id').value = ''; $('td-vlan-name').value = '';
      render();
      say(T('td.added_vlan', { id: r.vlan.id }));
    });
    $('td-link-add').addEventListener('click', () => {
      const r = addLink(D, { dev: $('td-a-dev').value, port: $('td-a-port').value }, { dev: $('td-b-dev').value, port: $('td-b-port').value }, readCfgForm('l'));
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      const h = id => devById(D, id).hostname;
      render();
      say(T('td.added_link', { a: h(r.link.a.dev), pa: r.link.a.port, b: h(r.link.b.dev), pb: r.link.b.port }));
    });
    $('td-e-save').addEventListener('click', () => {
      if (!editing) return;
      const r = setEndCfg(D, editing.i, editing.end, readCfgForm('e'));
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      const e = D.links[editing.i][editing.end];
      editing = null;
      render();
      say(T('td.saved_end', { host: (devById(D, e.dev) || {}).hostname || '', port: e.port }));
    });
    $('td-e-cancel').addEventListener('click', () => { editing = null; render(); });
    // 編輯設備：改了表單就要重新確認要刪除的線
    const resetDrop = () => { if (devEdit) devEdit.pending = null; $('td-de-drop').hidden = true; $('td-de-confirm').hidden = true; };
    $('td-de-vendor').addEventListener('change', () => { fillDevEditModels(); resetDrop(); });
    $('td-de-model').addEventListener('change', resetDrop);
    $('td-de-host').addEventListener('input', resetDrop);
    $('td-de-apply').addEventListener('click', () => applyDevEdit(false));
    $('td-de-confirm').addEventListener('click', () => applyDevEdit(true));
    $('td-de-cancel').addEventListener('click', () => { devEdit = null; render(); });
    document.addEventListener('change', e => {
      const t = e.target;
      if (!t || !t.matches || !t.matches('[data-td-lag-pick]')) return;
      const i = +t.getAttribute('data-td-lag-pick');
      if (t.checked) lagPick.add(i); else lagPick.delete(i);
      renderLagBox();
    });
    $('td-lag-add').addEventListener('click', () => {
      if (!lagPick.size) { say(tr('td.lag_pick_none'), true); return; }
      const r = addLag(D, [...lagPick].sort((x, y) => x - y), { aNum: $('td-lag-a').value, bNum: $('td-lag-b').value, mode: $('td-lag-mode').value });
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      lagPick = new Set(); $('td-lag-a').value = ''; $('td-lag-b').value = '';
      render();
      say(T('td.lag_added', { name: lagName(r.lag), n: lagMembers(D, r.lag.id).length }));
    });
    $('td-exp-svg').addEventListener('click', () => download('topology-design.svg', designToSvg(D, T), 'image/svg+xml'));
    $('td-exp-drawio').addEventListener('click', () => download('topology-design.drawio', designToDrawio(D), 'application/xml'));
    $('td-exp-mmd').addEventListener('click', () => download('topology-design.mmd', designToMermaid(D), 'text/plain'));
    document.addEventListener('click', e => {
      const t = e.target && e.target.closest ? e.target : null;
      if (!t) return;
      const de = t.closest('[data-td-edit-dev]');
      if (de) { openDevEdit(de.getAttribute('data-td-edit-dev')); return; }
      const rg = t.closest('[data-td-rm-lag]');
      if (rg) { removeLag(D, rg.getAttribute('data-td-rm-lag')); render(); return; }
      const rd = t.closest('[data-td-rm-dev]'), rl = t.closest('[data-td-rm-link]'), rv = t.closest('[data-td-rm-vlan]'), ed = t.closest('[data-td-edit]'), sd = t.closest('[data-td-send]');
      if (rd || rl) lagPick = new Set();
      if (rd) { removeDevice(D, rd.getAttribute('data-td-rm-dev')); if (!devById(D, sel)) sel = null; editing = null; render(); }
      else if (rl) { removeLink(D, +rl.getAttribute('data-td-rm-link')); editing = null; render(); }
      else if (rv) { const r = removeVlan(D, +rv.getAttribute('data-td-rm-vlan')); if (!r.ok) say(tr('td.err_' + r.code), true); render(); }
      else if (ed) {
        const [i, end] = ed.getAttribute('data-td-edit').split(':');
        if (!D.links[+i] || (end !== 'a' && end !== 'b')) return;
        editing = { i: +i, end };
        render();
        fillCfgForm('e', D.links[+i][end].cfg);
        const box = $('td-end-edit');
        if (box.scrollIntoView) box.scrollIntoView({ block: 'nearest' });
      }
      else if (sd) sendToGenerator(sd.getAttribute('data-td-send'));
    });
    $('td-save').addEventListener('click', () => download('topology-design.json', JSON.stringify(buildDesign(D), null, 2)));
    $('td-load').addEventListener('change', e => {
      const f = e.target.files && e.target.files[0];
      if (!f) return;
      f.text().then(loadText).finally(() => { e.target.value = ''; });
    });
    $('td-clear').addEventListener('click', () => { D = newDesign(); sel = null; pickNext = 'a'; editing = null; devEdit = null; lagPick = new Set(); render(); say(tr('td.cleared')); });
    const cv = $('td-canvas');
    cv.addEventListener('pointerdown', onDown);
    cv.addEventListener('pointermove', onMove);
    cv.addEventListener('pointerup', onUp);
    cv.addEventListener('pointercancel', () => { drag = null; });
  }
  // 頁面與測試用：直接操作目前的設計
  api.state = () => D;
  api.render = () => render();
  api.loadText = loadText;
  api.send = sendToGenerator;
  api.add = o => { const r = addDevice(D, o); if (r.ok) render(); return r; };
  api.addVlan = o => { const r = addVlan(D, o); if (r.ok) render(); return r; };
  api.link = (a, b, cfg) => { const r = addLink(D, a, b, cfg); if (r.ok) render(); return r; };
  api.lag = (idxs, o) => { const r = addLag(D, idxs, o); if (r.ok) render(); return r; };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
