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
  const CANVAS_W = 1000, CANVAS_H = 260, BOX_W = 180, BOX_H = 58, GAP_X = 30, GAP_Y = 60;
  const COLS = Math.floor(CANVAS_W / (BOX_W + GAP_X)), MAX_H = 20 + Math.ceil(MAX_DEVICES / COLS) * (BOX_H + GAP_Y);
  const HOST_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/;
  const VLAN_NAME_RE = /^[^\x00-\x1f\x7f]{0,32}$/;
  // 錯誤代碼（td.err_*）；設計檔讀入只會出現 DESIGN_ERR_CODES
  const DESIGN_ERR_CODES = ['json', 'format', 'device', 'link', 'max', 'vlan', 'lag', 'pair'];
  const ERR_CODES = DESIGN_ERR_CODES.concat(['stack_unsupported', 'stack_n', 'pair_dev', 'pair_self', 'pair_vendor', 'pair_dup', 'pair_domain', 'pair_lag', 'peer_link', 'host', 'dup', 'vendor', 'model', 'self', 'port', 'used', 'vlan_id', 'vlan_dup', 'vlan_name', 'vlan_used', 'vlan_missing', 'vlan_syntax', 'native', 'lag_links', 'lag_num', 'lag_num_dup', 'lag_mode', 'stp_pri', 'stack_model']);
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
  // ── 堆疊（XN211）：產生器能帶入堆疊設定的廠牌；型號的資料埠須能依成員展開（SwPanel.memberName，「前綴 1/x/y」三段式）──
  const STACK_VENDORS = ['comware', 'h3c', 'cisco', 'brocade', 'alcatel', 'aruba'], MAX_MEMBERS = 9;
  function canStack(vendor, value) {
    const m = findModel(vendor, value), sp = SP();
    if (!STACK_VENDORS.includes(vendor) || !m || !sp) return false;
    const data = sp.expandPorts(m).filter(p => !p.mgmt);
    return data.length > 0 && data.every(p => sp.memberName(p.name, '2'));
  }
  // 依成員展開的埠物件（管理埠只在成員 1，與 SwPanel.buildPanel 相同）；混型號堆疊（XN215）成員 k 用 memberModels[k-1]（空＝與成員 1 相同）
  function devPortObjs(vendor, value, members, memberModels) {
    const m = findModel(vendor, value), sp = SP(), n = members > 1 ? members : 1;
    if (!m || !sp) return [];
    if (n === 1) return sp.expandPorts(m);
    const out = [];
    for (let k = 1; k <= n; k++) {
      const mk = (k > 1 && memberModels && memberModels[k - 1] && findModel(vendor, memberModels[k - 1])) || m;
      sp.expandPorts(mk).forEach(p => { if (p.mgmt && k > 1) return; const nm = k === 1 ? p.name : sp.memberName(p.name, String(k)); if (nm) out.push(Object.assign({}, p, { name: nm, member: k })); });
    }
    return out;
  }
  const portObjsOf = dev => devPortObjs(dev.vendor, dev.model, dev.members, dev.memberModels);
  const devPorts = dev => portObjsOf(dev).map(p => p.name);
  // 成員型號檢查與正規化（XN215）：截到成員數、與成員 1 相同的改空字串、全部相同回 undefined；
  // 不同的型號須同廠牌找得到且可堆疊，否則 null（stack_model）。型號能否互疊依各廠牌文件，這裡不判斷
  function normMemberModels(vendor, model, members, arr) {
    if (!Array.isArray(arr) || members < 2) return undefined;
    const out = [''];
    for (let k = 1; k < members; k++) {
      const v = arr[k] == null ? '' : String(arr[k]);
      if (!v || v === model) { out.push(''); continue; }
      if (!findModel(vendor, v) || !canStack(vendor, v)) return null;
      out.push(v);
    }
    return out.some(Boolean) ? out : undefined;
  }
  const isMixedStack = dev => !!(dev && dev.members > 1 && Array.isArray(dev.memberModels) && dev.memberModels.some(Boolean));
  const membersOf = v => { const n = v == null || v === '' ? 1 : Number(v); return Number.isInteger(n) && n >= 1 && n <= MAX_MEMBERS ? n : null; };
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, Math.round(v)));

  function newDesign() { return { devices: [], links: [], vlans: [], lags: [], pairs: [], seq: 0, lagSeq: 0, pairSeq: 0 }; }
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
  // 畫布高度依內容（UX40）：最低的設備下方再留一格給拖拉與新增，下限 CANVAS_H
  const canvasH = d => Math.max(CANVAS_H, ...d.devices.map(x => x.y + BOX_H + GAP_Y + BOX_H));
  function addDevice(d, o) {
    const hostname = String((o && o.hostname) || '').trim(), vendor = String((o && o.vendor) || ''), model = String((o && o.model) || '');
    if (d.devices.length >= MAX_DEVICES) return { ok: false, code: 'max' };
    if (!HOST_RE.test(hostname)) return { ok: false, code: 'host' };
    if (d.devices.some(x => lc(x.hostname) === lc(hostname))) return { ok: false, code: 'dup' };
    if (!VENDOR_IDS.includes(vendor)) return { ok: false, code: 'vendor' };
    if (!findModel(vendor, model)) return { ok: false, code: 'model' };
    const members = membersOf(o.members);
    if (members == null) return { ok: false, code: 'stack_n' };
    if (members > 1 && !canStack(vendor, model)) return { ok: false, code: 'stack_unsupported' };
    const mm = normMemberModels(vendor, model, members, o.memberModels);
    if (mm === null) return { ok: false, code: 'stack_model' };
    const pos = o.x != null && o.y != null ? { x: o.x, y: o.y } : nextSlot(d);
    const dev = { id: 'd' + (++d.seq), hostname, vendor, model, members, x: clamp(pos.x, 0, CANVAS_W - BOX_W), y: clamp(pos.y, 0, MAX_H - BOX_H) };
    if (mm) dev.memberModels = mm;
    d.devices.push(dev);
    return { ok: true, dev };
  }
  function removeDevice(d, id) {
    d.devices = d.devices.filter(x => x.id !== id);
    d.links = d.links.filter(l => l.a.dev !== id && l.b.dev !== id);
    // 刪除 pair 的一台時解散 pair
    const p = pairOfDev(d, id);
    if (p) removePair(d, p.id);
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
    const members = membersOf(o.members === undefined ? dev.members : o.members);
    if (members == null) return { ok: false, code: 'stack_n' };
    if (members > 1 && !canStack(vendor, model)) return { ok: false, code: 'stack_unsupported' };
    // 沒帶 memberModels 時沿用原本的成員型號（廠牌或型號換了而原本的成員型號不合格時清掉）
    let mm = normMemberModels(vendor, model, members, o.memberModels === undefined ? dev.memberModels : o.memberModels);
    if (mm === null && o.memberModels === undefined) mm = undefined;
    if (mm === null) return { ok: false, code: 'stack_model' };
    const byLc = new Map(devPortObjs(vendor, model, members, mm).map(p => [lc(p.name), p.name]));
    const drop = [];
    d.links.forEach((l, i) => { if ([l.a, l.b].some(e => e.dev === id && !byLc.has(lc(e.port)))) drop.push(i); });
    // 換廠牌時跨機聚合 pair 兩台不再同廠牌：解散 pair（peer link 標記與跨機聚合一併拆掉），否則存出的設計檔讀不回來
    const pr = pairOfDev(d, id), unpair = !!(pr && vendor !== dev.vendor);
    if (opts && opts.dryRun) return { ok: true, drop, unpair };
    if (unpair) removePair(d, pr.id);
    for (let k = drop.length - 1; k >= 0; k--) removeLink(d, drop[k]);
    Object.assign(dev, { hostname, vendor, model, members });
    if (mm) dev.memberModels = mm; else delete dev.memberModels;
    d.links.forEach(l => [l.a, l.b].forEach(e => { if (e.dev === id) e.port = byLc.get(lc(e.port)); }));
    return { ok: true, drop, unpair };
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
    const pa = devPorts(da).find(p => lc(p) === lc(a.port)), pb = devPorts(db).find(p => lc(p) === lc(b.port));
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
  // 已用的群組編號：pair 的編號與兩台各自的編號共用同一組（同一台設備上不可重複）
  const unitDevs = (d, u) => { const p = (d.pairs || []).find(x => x.id === u); return p ? [p.a, p.b] : [u]; };
  const usedLagNums = (d, unit, except) => {
    const devs = unitDevs(d, unit), p = pairOfDev(d, unit), keys = new Set(devs.concat(p ? [p.id] : []).concat(devs.map(x => (pairOfDev(d, x) || {}).id).filter(Boolean)));
    return new Set((d.lags || []).filter(g => g.id !== except).flatMap(g => [g.a, g.b]).filter(e => keys.has(e.dev)).map(e => e.num));
  };
  // 所選的線（連線索引）合成一組：須是同一對設備、都還沒加入聚合；兩端群組編號 1～4096 且該設備上不重複
  function addLag(d, idxs, o) {
    if (!d.lags) d.lags = [];
    const list = [...new Set((idxs || []).map(Number))];
    const ls = list.map(i => d.links[i]);
    if (!list.length || ls.some(l => !l || l.lag)) return { ok: false, code: 'lag_links' };
    // 兩端以「單位」比對：pair 的兩台算同一端（XN212 跨機聚合），其餘為設備本身；兩端不可是同一單位
    // 同一 pair 兩台之間的線（peer link 的 port-channel）：以兩台實體設備為兩端
    const intra = unitOf(d, ls[0].a.dev) === unitOf(d, ls[0].b.dev) && ls[0].a.dev !== ls[0].b.dev;
    const U = dev => (intra ? dev : unitOf(d, dev));
    const a = U(ls[0].a.dev), b = U(ls[0].b.dev);
    if (a === b || ls.some(l => { const x = U(l.a.dev), y = U(l.b.dev); return !((x === a && y === b) || (x === b && y === a)); })) return { ok: false, code: 'lag_links' };
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
  const lagPortsOn = (d, g, dev) => lagMembers(d, g.id).filter(l => l.a.dev === dev || l.b.dev === dev).map(l => (l.a.dev === dev ? l.a : l.b).port);

  // ── 跨機聚合 pair（XN212，MLAG／vPC／VLT）：同廠牌兩台，之間的線可標 peer link；peer link 與兩台之間的其他線不列入二層分析 ──
  const PAIR_VENDORS = ['arista', 'cisco_nxos', 'dell-os10'];
  const pairOfDev = (d, dev) => (d.pairs || []).find(p => p.a === dev || p.b === dev) || null;
  const unitOf = (d, dev) => { const p = pairOfDev(d, dev); return p ? p.id : dev; };
  const domainOf = v => { const s = String(v == null || v === '' ? '1' : v).trim(); return /^\d{1,4}$/.test(s) && +s >= 1 && +s <= 1000 ? s : null; };
  function addPair(d, aId, bId, o) {
    if (!d.pairs) d.pairs = [];
    const a = devById(d, aId), b = devById(d, bId);
    if (!a || !b) return { ok: false, code: 'pair_dev' };
    if (a === b) return { ok: false, code: 'pair_self' };
    if (a.vendor !== b.vendor || !PAIR_VENDORS.includes(a.vendor)) return { ok: false, code: 'pair_vendor' };
    if (pairOfDev(d, a.id) || pairOfDev(d, b.id)) return { ok: false, code: 'pair_dup' };
    const domain = domainOf(o && o.domain);
    if (domain == null) return { ok: false, code: 'pair_domain' };
    // 已有的聚合兩端不可跨到這兩台（避免既有聚合的單位改變）
    if ((d.lags || []).some(g => [g.a.dev, g.b.dev].includes(a.id) && [g.a.dev, g.b.dev].includes(b.id))) return { ok: false, code: 'pair_lag' };
    const p = { id: 'p' + (++d.pairSeq), a: a.id, b: b.id, domain };
    d.pairs.push(p);
    return { ok: true, pair: p };
  }
  function removePair(d, id) {
    const p = (d.pairs || []).find(x => x.id === id);
    if (!p) return { ok: false, code: 'pair_dev' };
    d.pairs = d.pairs.filter(x => x !== p);
    d.links.forEach(l => { if ((l.a.dev === p.a || l.a.dev === p.b) && (l.b.dev === p.a || l.b.dev === p.b)) delete l.peer; });
    // 跨機聚合拆回一般線
    (d.lags || []).filter(g => g.a.dev === p.id || g.b.dev === p.id).forEach(g => removeLag(d, g.id));
    return { ok: true };
  }
  // 標記／取消 peer link：只能是同一 pair 兩台之間的線
  function setPeer(d, i, on) {
    const l = d.links[i], p = l && pairOfDev(d, l.a.dev);
    if (!l || !p || pairOfDev(d, l.b.dev) !== p) return { ok: false, code: 'peer_link' };
    if (on) l.peer = true; else delete l.peer;
    return { ok: true };
  }
  // pair 的檢查：沒有 peer link（high）、下游設備只接到其中一台（info，沒有雙上行）
  function pairIssues(d) {
    const out = [];
    (d.pairs || []).forEach(p => {
      const name = (devById(d, p.a) || {}).hostname + '＋' + (devById(d, p.b) || {}).hostname;
      if (!d.links.some(l => l.peer && [l.a.dev, l.b.dev].includes(p.a) && [l.a.dev, l.b.dev].includes(p.b))) out.push({ type: 'pair_nopeer', level: 'high', pair: p.id, p: { pair: name } });
      const peersOf = new Map();
      d.links.forEach(l => [[l.a, l.b], [l.b, l.a]].forEach(([x, y]) => { if ((x.dev === p.a || x.dev === p.b) && y.dev !== p.a && y.dev !== p.b) { if (!peersOf.has(y.dev)) peersOf.set(y.dev, new Set()); peersOf.get(y.dev).add(x.dev); } }));
      peersOf.forEach((set, dev) => { if (set.size === 1) out.push({ type: 'pair_single', level: 'info', pair: p.id, p: { pair: name, host: (devById(d, dev) || {}).hostname || '' } }); });
    });
    return out;
  }
  const PAIR_ISSUE_TYPES = ['pair_nopeer', 'pair_single'];
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
      // 以單位比對：跨機聚合在 pair 兩台的成員也要一致
      const ms = lagMembers(d, l.lag), cfgOf = (x, u) => JSON.stringify((x.a.dev === u || (x.b.dev !== u && unitOf(d, x.a.dev) === u) ? x.a : x.b).cfg || null);
      const unitName = u => { const p = (d.pairs || []).find(x => x.id === u); return p ? (devById(d, p.a) || {}).hostname + '＋' + (devById(d, p.b) || {}).hostname : (devById(d, u) || {}).hostname || ''; };
      const lg = lagById(d, l.lag);
      (lg ? [lg.a.dev, lg.b.dev] : [unitOf(d, l.a.dev), unitOf(d, l.b.dev)]).forEach(u => { if (new Set(ms.map(x => cfgOf(x, u))).size > 1) add('lag_cfg', { host: unitName(u) }); });
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
    const interfaces = portObjsOf(dev).filter(p => !p.mgmt).map(p => {
      const e = ends.get(lc(p.name)), c = e && e.cfg, peer = e && devById(d, e.peer.dev);
      // vlan 與 vlans 同值：產生器對 NX-OS 交接會以 vlan 欄位覆寫 vlans（normalizeNXOSInterfaceVlans）
      return { name: p.name, type: 'physical', speed: p.speed, mode: c ? c.mode : 'access', vlans: c ? c.vlans : '', vlan: c ? c.vlans : '', nativeVlan: c && c.mode === 'trunk' ? c.nativeVlan : '',
        desc: peer ? ('to ' + peer.hostname + ' ' + e.peer.port).slice(0, 80) : '', shutdown: false };
    });
    const sys = { hostname: dev.hostname };
    if (dev.vendor === 'h3c') sys.brand = 'h3c';
    // 聚合（XN204）：交換器分析 parser 的 lacp 形狀，產生器 applyParsedConfigToForm() 讀名稱中的數字、mode 與成員陣列
    const unit = unitOf(d, id);
    const mine = e => e.dev === id || e.dev === unit;
    const lacp = (d.lags || []).filter(g => (mine(g.a) || mine(g.b)) && lagPortsOn(d, g, id).length).map(g => {
      const side = g.a.dev === id ? g.a : g.b.dev === id ? g.b : g.a.dev === unit ? g.a : g.b;
      const num = side.num, item = { name: 'Port-channel' + num, mode: g.mode, members: lagPortsOn(d, g, id) };
      // 跨機聚合（XN212）：pair 端的 port-channel 帶跨機序號（與編號相同）；peer link 的 port-channel 不帶
      if (side.dev !== id) item.mlagId = String(num);
      return item;
    });
    const out = { vendor: GEN_VENDOR[dev.vendor] || dev.vendor, sys, vlans: d.vlans.map(v => ({ id: String(v.id), name: v.name })), interfaces, lacp };
    // 跨機聚合 pair（XN212）：產生器 applyParsedConfigToForm 依廠牌讀入的形狀；peer link 為 peer 線所在的 port-channel（沒有聚合時為第一條 peer 線的埠）
    const pr = pairOfDev(d, id);
    if (pr) {
      const peers = d.links.filter(l => l.peer && (l.a.dev === id || l.b.dev === id));
      const pl = peers.length && peers.every(l => l.lag && l.lag === peers[0].lag) ? lagById(d, peers[0].lag) : null;
      const plNum = pl ? (pl.a.dev === id ? pl.a.num : pl.b.num) : null;
      const firstPort = peers.length ? (peers[0].a.dev === id ? peers[0].a.port : peers[0].b.port) : '';
      const pcName = n => (dev.vendor === 'arista' ? 'Port-Channel' : 'port-channel') + n;
      const peerLink = plNum != null ? pcName(plNum) : firstPort;
      if (dev.vendor === 'arista') out.stack = { domain: pr.domain, localIntf: '', peerAddr: '', peerLink };
      else if (dev.vendor === 'cisco_nxos') out.stack = { type: 'VPC', domain: pr.domain, peerKeepalive: '', peerLink, peerGateway: false };
      else if (dev.vendor === 'dell-os10') out.stack = { type: 'VLT', domain: pr.domain, members: [{ id: pr.a === id ? '1' : '2', priority: '' }], peerLink };
    }
    // 堆疊（XN211）：交換器分析 parser 的堆疊形狀（產生器 applyParsedConfigToForm 依廠牌讀入）；堆疊埠（IRF／VSF 實體埠）不帶，在產生器補填
    if (dev.members > 1) {
      const ids = Array.from({ length: dev.members }, (_, i) => String(i + 1));
      if (dev.vendor === 'comware' || dev.vendor === 'h3c') out.irf = { domain: '1', members: ids.map(id => ({ id, priority: '' })), links: [] };
      else out.stack = { type: STACK_TYPE[dev.vendor], members: ids.map(id => ({ id, model: '', priority: '' })) };
    }
    return out;
  }
  const STACK_TYPE = { cisco: 'StackWise', brocade: 'ICX-Stack', alcatel: 'Stack', aruba: 'VSF' };

  // 設計檔：設備以名稱互相參照（ID 每次讀入重新產生）；自訂型號只存名稱（value 是本機 localStorage 的編號）
  function buildDesign(d) {
    const hostOf = id => (devById(d, id) || {}).hostname || '';
    const end = e => (e.cfg ? { host: hostOf(e.dev), port: e.port, cfg: Object.assign({}, e.cfg) } : { host: hostOf(e.dev), port: e.port });
    const lags = (d.lags || []).filter(g => lagMembers(d, g.id).length), lagIdx = new Map(lags.map((g, i) => [g.id, i]));
    const pairs = d.pairs || [], pairIdx = new Map(pairs.map((p, i) => [p.id, i]));
    // 聚合的一端是 pair 時記 pair 索引，否則記主機名稱
    const side = e => (pairIdx.has(e.dev) ? { pair: pairIdx.get(e.dev), num: e.num } : { host: hostOf(e.dev), num: e.num });
    return {
      format: 'alpaca-design', version: 5,
      pairs: pairs.map(p => ({ a: hostOf(p.a), b: hostOf(p.b), domain: p.domain })),
      lags: lags.map(g => ({ a: side(g.a), b: side(g.b), mode: g.mode })),
      vlans: d.vlans.map(v => ({ id: v.id, name: v.name })),
      devices: d.devices.map(x => {
        const m = findModel(x.vendor, x.model);
        const base = m && m.custom ? { hostname: x.hostname, vendor: x.vendor, model: '', custom: m.label, x: x.x, y: x.y } : { hostname: x.hostname, vendor: x.vendor, model: x.model, x: x.x, y: x.y };
        if (x.members > 1) base.members = x.members;
        // 成員型號（第 5 版）：與成員 1 相同為空字串，自訂型號存名稱
        if (isMixedStack(x)) base.memberModels = x.memberModels.map(v => { if (!v) return ''; const mm = findModel(x.vendor, v); return mm && mm.custom ? { custom: mm.label } : v; });
        if (stpPriOk(x.stpPri)) base.stpPri = x.stpPri;
        return base;
      }),
      links: d.links.map(l => Object.assign({ a: end(l.a), b: end(l.b) }, l.lag && lagIdx.has(l.lag) ? { lag: lagIdx.get(l.lag) } : {}, l.peer ? { peer: true } : {})),
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
    if (!o || typeof o !== 'object' || o.format !== 'alpaca-design' || ![1, 2, 3, 4, 5].includes(o.version) || !Array.isArray(o.devices) || !Array.isArray(o.links)) return { ok: false, code: 'format' };
    if ((o.vlans != null && !Array.isArray(o.vlans)) || (o.lags != null && !Array.isArray(o.lags)) || (o.pairs != null && !Array.isArray(o.pairs))) return { ok: false, code: 'format' };
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
      // 堆疊成員數（第 4 版）：不合格整份拒絕；本機型號不能依成員展開時退回 1 台並計入 missing
      let members = membersOf(x.members == null ? 1 : x.members);
      if (members == null || (x.members != null && typeof x.members !== 'number')) return { ok: false, code: 'device' };
      if (members > 1 && !canStack(vendor, value)) { if (value) missing++; members = 1; }
      // 成員型號（第 5 版）：陣列，每格為空字串、型號 value 或 {custom: 名稱}；本機找不到或不可堆疊的成員改為與成員 1 相同並計入 missing
      let mm;
      if (x.memberModels != null) {
        if (!Array.isArray(x.memberModels) || x.memberModels.length > MAX_MEMBERS) return { ok: false, code: 'device' };
        const arr = [];
        for (const e of x.memberModels) {
          let v = '';
          if (typeof e === 'string') v = str(e, 200) || '';
          else if (e && typeof e === 'object' && typeof e.custom === 'string') { const c = modelChoices(vendor).find(q => q.custom && q.label === e.custom); v = c ? c.value : '?'; }
          else if (e !== null && e !== '') return { ok: false, code: 'device' };
          if (v && (!findModel(vendor, v) || !canStack(vendor, v))) { missing++; v = ''; }
          arr.push(v);
        }
        mm = value && members > 1 ? normMemberModels(vendor, value, members, arr) || undefined : undefined;
      }
      const dev = { id: 'd' + (++d.seq), hostname, vendor, model: value, members, x: clamp(x.x, 0, CANVAS_W - BOX_W), y: clamp(x.y, 0, MAX_H - BOX_H) };
      if (mm) dev.memberModels = mm;
      // STP 優先權（XN214，選填）：不合格整份拒絕
      if (x.stpPri != null) { if (!stpPriOk(x.stpPri)) return { ok: false, code: 'device' }; dev.stpPri = x.stpPri; }
      d.devices.push(dev);
      byHost.set(lc(hostname), dev);
    }
    // 跨機聚合 pair（第 4 版）：兩台名稱須在設計中、廠牌與條件同 addPair()，不合格整份拒絕
    const pairIds = [];
    for (const p of o.pairs || []) {
      const ah = p && str(p.a, 32), bh = p && str(p.b, 32), dom = p && p.domain != null ? str(String(p.domain), 4) : '1';
      if (!ah || !bh || !byHost.has(lc(ah)) || !byHost.has(lc(bh)) || dom == null) return { ok: false, code: 'pair' };
      const r = addPair(d, byHost.get(lc(ah)).id, byHost.get(lc(bh)).id, { domain: dom });
      if (!r.ok) return { ok: false, code: 'pair' };
      pairIds.push(r.pair.id);
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
      if (l.peer === true && !setPeer(d, i, true).ok) return { ok: false, code: 'pair' };
    }
    // 聚合：成員都讀得到時重建；兩端名稱與編號須對得上第一條成員，否則整份拒絕；成員全部被略過的聚合跟著略過
    // 聚合的一端：{host} 為該設備所屬的單位、{pair} 為 pair 索引
    const sideUnit = e => {
      if (!e || typeof e !== 'object') return null;
      if (e.pair != null) return Number.isInteger(e.pair) && e.pair >= 0 && e.pair < pairIds.length ? pairIds[e.pair] : null;
      const h = str(e.host, 32);
      return h && byHost.has(lc(h)) ? byHost.get(lc(h)).id : null;
    };
    for (let k = 0; k < lagLinks.length; k++) {
      const g = o.lags[k];
      let ua = g && sideUnit(g.a), ub = g && sideUnit(g.b);
      if (!ua || !ub) return { ok: false, code: 'lag' };
      if (!lagLinks[k].length) continue;
      const first = d.links[lagLinks[k][0]];
      // 同一 pair 兩台之間的聚合（peer link）兩端是實體設備，其餘以所屬單位比對
      const intra = unitOf(d, first.a.dev) === unitOf(d, first.b.dev) && first.a.dev !== first.b.dev;
      const U = x => (intra || pairIds.includes(x) ? x : unitOf(d, x));
      ua = U(ua); ub = U(ub);
      const fa = intra ? first.a.dev : unitOf(d, first.a.dev), fb = intra ? first.b.dev : unitOf(d, first.b.dev);
      if (!((fa === ua && fb === ub) || (fa === ub && fb === ua))) return { ok: false, code: 'lag' };
      const flip = fa !== ua;
      const r = addLag(d, lagLinks[k], { aNum: flip ? g.b.num : g.a.num, bNum: flip ? g.a.num : g.b.num, mode: g.mode });
      if (!r.ok) return { ok: false, code: 'lag' };
    }
    return { ok: true, design: d, missing, dropped };
  }

  // ── 二層分析（XN207／XN210）：設計與接線拓樸共用的圖 ──
  // 圖：{nodes:[{id,name}], edges:[{id, a:{node,port,cfg}, b:{node,port,cfg}, refs:[連線索引], lag}]}；同一聚合的成員合成一條邊（設定取第一條）
  // opts.physical：不合併 pair、包含 pair 兩台之間的線（自動排版、單點故障用實體圖）
  function l2Graph(d, opts) {
    const phys = !!(opts && opts.physical), U = dev => (phys ? dev : unitOf(d, dev));
    // pair 合成一個節點（名稱「A＋B」）；兩台之間的線（peer link 等）是 pair 內部，不列入
    const pairNodes = phys ? [] : (d.pairs || []).map(p => ({ id: p.id, name: (devById(d, p.a) || {}).hostname + '＋' + (devById(d, p.b) || {}).hostname, devs: [p.a, p.b] }));
    const nodes = d.devices.filter(x => phys || !pairOfDev(d, x.id)).map(x => ({ id: x.id, name: x.hostname })).concat(pairNodes), edges = [], byLag = new Map();
    d.links.forEach((l, i) => {
      if (U(l.a.dev) === U(l.b.dev)) return;
      if (l.lag && byLag.has(l.lag)) { byLag.get(l.lag).refs.push(i); return; }
      const e = { id: edges.length, a: { node: U(l.a.dev), port: l.a.port, cfg: l.a.cfg || null }, b: { node: U(l.b.dev), port: l.b.port, cfg: l.b.cfg || null }, refs: [i], lag: !!l.lag };
      if (l.lag) { const g = lagById(d, l.lag); if (g) e.lagName = 'Po' + g.a.num + (g.a.num === g.b.num ? '' : '/' + g.b.num); byLag.set(l.lag, e); }
      edges.push(e);
    });
    return { nodes, edges };
  }
  // 某一端是否帶這個 VLAN：access 相同才帶、trunk 允許清單 all 或包含；沒有設定為 null（無法判斷）
  function carries(cfg, v) {
    if (!cfg || !cfg.mode) return null;
    if (cfg.mode === 'access') return +cfg.vlans === +v;
    if (cfg.mode !== 'trunk') return null;
    const p = parseVlanList(cfg.vlans);
    return p.all || p.ids.includes(+v);
  }
  // 一條邊兩端都帶才帶；任一端無法判斷為 null
  const edgeCarries = (e, v) => { const x = carries(e.a.cfg, v), y = carries(e.b.cfg, v); return x === null || y === null ? null : x && y; };
  function adjOf(g, ok) {
    const adj = new Map(g.nodes.map(n => [n.id, []]));
    g.edges.forEach(e => { if (adj.has(e.a.node) && adj.has(e.b.node) && (!ok || ok(e))) { adj.get(e.a.node).push({ to: e.b.node, e, from: 'a' }); adj.get(e.b.node).push({ to: e.a.node, e, from: 'b' }); } });
    return adj;
  }
  // 連通塊：node id → 塊編號
  function compsOf(g, ok) {
    const adj = adjOf(g, ok), comp = new Map();
    let n = 0;
    g.nodes.forEach(s => {
      if (comp.has(s.id)) return;
      const q = [s.id]; comp.set(s.id, n);
      while (q.length) { const u = q.shift(); adj.get(u).forEach(x => { if (!comp.has(x.to)) { comp.set(x.to, n); q.push(x.to); } }); }
      n++;
    });
    return { comp, n };
  }
  // 橋（不在任何環上的邊）：Tarjan，依邊編號區分平行邊
  function bridgesOf(g) {
    const adj = adjOf(g), disc = new Map(), low = new Map(), out = new Set();
    let t = 0;
    const dfs = (u, viaEdge) => {
      disc.set(u, t); low.set(u, t); t++;
      adj.get(u).forEach(x => {
        if (x.e.id === viaEdge) return;
        if (!disc.has(x.to)) { dfs(x.to, x.e.id); low.set(u, Math.min(low.get(u), low.get(x.to))); if (low.get(x.to) > disc.get(u)) out.add(x.e.id); }
        else low.set(u, Math.min(low.get(u), disc.get(x.to)));
      });
    };
    g.nodes.forEach(n => { if (!disc.has(n.id)) dfs(n.id, -1); });
    return out;
  }
  // 從某設備出發的跳數
  function hopsFrom(adj, s) { const dist = new Map([[s, 0]]), q = [s]; while (q.length) { const u = q.shift(); adj.get(u).forEach(x => { if (!dist.has(x.to)) { dist.set(x.to, dist.get(u) + 1); q.push(x.to); } }); } return dist; }
  // 分析：VLAN 分塊（splits）、環（loops）、根橋建議（roots，每個有連線的連通塊取中心）、未設定而排除的邊（undef）
  function l2Analyze(g, vlans) {
    const nameOf = id => (g.nodes.find(n => n.id === id) || {}).name || String(id);
    const phys = compsOf(g), bridges = bridgesOf(g), adj = adjOf(g);
    const loops = [], roots = [];
    for (let c = 0; c < phys.n; c++) {
      const ids = g.nodes.filter(n => phys.comp.get(n.id) === c).map(n => n.id);
      if (ids.length < 2) continue;
      const onCycle = g.edges.filter(e => phys.comp.get(e.a.node) === c && !bridges.has(e.id));
      if (onCycle.length) loops.push({ nodes: [...new Set(onCycle.flatMap(e => [e.a.node, e.b.node]))].map(nameOf), edges: onCycle.map(e => e.id) });
      // 中心：離最遠設備跳數最小，同分取連線數多、再依名稱
      const best = ids.map(id => ({ id, ecc: Math.max(...hopsFrom(adj, id).values()), deg: adj.get(id).length, name: nameOf(id) }))
        .sort((x, y) => x.ecc - y.ecc || y.deg - x.deg || (x.name < y.name ? -1 : 1))[0];
      roots.push({ node: best.id, name: best.name, nodes: ids.length });
    }
    const undef = g.edges.filter(e => !e.a.cfg || !e.b.cfg).map(e => e.id);
    const splits = [];
    (vlans || []).forEach(v => {
      const users = new Set();
      g.edges.forEach(e => { if (carries(e.a.cfg, v)) users.add(e.a.node); if (carries(e.b.cfg, v)) users.add(e.b.node); });
      if (users.size < 2) return;
      const vc = compsOf(g, e => edgeCarries(e, v) === true), groups = new Map();
      users.forEach(id => { const k = vc.comp.get(id); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(nameOf(id)); });
      if (groups.size < 2) return;
      // 斷在哪：一端放行、另一端沒放行的線
      const breaks = g.edges.filter(e => edgeCarries(e, v) === false && (carries(e.a.cfg, v) || carries(e.b.cfg, v)))
        .map(e => { const bad = carries(e.a.cfg, v) ? e.b : e.a; return { edge: e.id, node: nameOf(bad.node), port: bad.port }; });
      splits.push({ vlan: +v, groups: [...groups.values()].map(x => x.sort()), breaks });
    });
    return { components: phys.n, loops, roots, undef, splits };
  }
  // 兩台設備之間某個 VLAN 的二層路徑：走帶該 VLAN 的邊（BFS 最短）；走不到時沿實體最短路徑找第一條不帶的邊
  function bfsPath(g, from, to, ok) {
    const adj = adjOf(g, ok), prev = new Map([[from, null]]), q = [from];
    while (q.length) { const u = q.shift(); if (u === to) break; adj.get(u).forEach(x => { if (!prev.has(x.to)) { prev.set(x.to, { u, x }); q.push(x.to); } }); }
    if (!prev.has(to)) return null;
    const hops = [];
    for (let v = to; prev.get(v); v = prev.get(v).u) { const { u, x } = prev.get(v); const near = x.from === 'a' ? x.e.a : x.e.b, far = x.from === 'a' ? x.e.b : x.e.a; hops.unshift({ edge: x.e.id, from: u, fromPort: near.port, to: v, toPort: far.port }); }
    return hops;
  }
  // 走不到的原因（td.l2p_*）
  const L2P_REASONS = ['blocked', 'undef', 'nolink', 'same', 'nodev'];
  // opts.allow(edge)：只走允許的邊（依 STP 計算時排除被擋的線，XN214）
  function l2Path(g, from, to, v, opts) {
    if (!g.nodes.some(n => n.id === from) || !g.nodes.some(n => n.id === to)) return { ok: false, reason: 'nodev' };
    if (from === to) return { ok: false, reason: 'same' };
    const allow = (opts && opts.allow) || (() => true);
    const hops = bfsPath(g, from, to, e => allow(e) && edgeCarries(e, v) === true);
    if (hops) return { ok: true, hops };
    const phys = bfsPath(g, from, to, allow);
    if (!phys) return { ok: false, reason: 'nolink' };
    const h = phys.find(x => edgeCarries(g.edges[x.edge], v) !== true), e = g.edges[h.edge];
    const ca = carries(e.a.cfg, v), cb = carries(e.b.cfg, v);
    const bad = ca === null || ca === false ? e.a : e.b, nameOf = id => (g.nodes.find(n => n.id === id) || {}).name || String(id);
    return { ok: false, reason: ca === null || cb === null ? 'undef' : 'blocked', edge: e.id, node: nameOf(bad.node), port: bad.port, hops: phys };
  }

  // ── STP 模擬（XN214）：單一生成樹（RSTP／MST 的 CIST），PVST 每個 VLAN 一棵樹不模擬 ──
  const STP_PRI_DEFAULT = 32768, STP_PRI_MAX = 61440, STP_PRI_STEP = 4096;
  const stpPriOk = v => Number.isInteger(v) && v >= 0 && v <= STP_PRI_MAX && v % STP_PRI_STEP === 0;
  // 空白＝預設（刪除欄位）
  function setStpPri(d, id, v) {
    const dev = devById(d, id);
    if (!dev) return { ok: false, code: 'stp_pri' };
    if (v === '' || v == null) { delete dev.stpPri; return { ok: true }; }
    const n = typeof v === 'number' ? v : /^\d+$/.test(String(v).trim()) ? +v : NaN;
    if (!stpPriOk(n)) return { ok: false, code: 'stp_pri' };
    dev.stpPri = n;
    return { ok: true };
  }
  // 速率字串（1G、25G、100M）→ bps；看不出來為 null
  const speedBps = s => { const m = String(s || '').match(/^(\d+(?:\.\d+)?)\s*([MGT])/i); return m ? +m[1] * { m: 1e6, g: 1e9, t: 1e12 }[m[2].toLowerCase()] : null; };
  // IEEE 802.1D-2004 建議的路徑成本（20 Tb/s ÷ 速率，1～200000000）：1G＝20000、10G＝2000、100G＝200
  const stpCost = bps => Math.max(1, Math.min(200000000, Math.round(2e13 / bps)));
  // g：l2Graph() 的圖；priOf(node)→優先權；costOf(edge)→成本
  // 橋 ID 以（優先權、名稱）比較；根埠依（到根成本、對方橋 ID、對方埠名、本機埠名）；不是任何一端根埠的邊為被擋，擋在優先向量較差的一端
  function stpTree(g, priOf, costOf) {
    const name = id => (g.nodes.find(n => n.id === id) || {}).name || String(id), pri = new Map(g.nodes.map(n => [n.id, priOf(n)]));
    const cmpB = (x, y) => pri.get(x) - pri.get(y) || (name(x) < name(y) ? -1 : name(x) > name(y) ? 1 : 0);
    const adj = adjOf(g), comps = compsOf(g), cost = new Map(g.edges.map(e => [e.id, costOf(e)]));
    const roots = [], dist = new Map();
    for (let c = 0; c < comps.n; c++) {
      const ids = g.nodes.map(n => n.id).filter(id => comps.comp.get(id) === c);
      if (!ids.some(id => adj.get(id).some(x => x.to !== id))) continue;   // 沒有連線的設備不算
      const root = ids.slice().sort(cmpB)[0], done = new Set();
      roots.push(root); dist.set(root, 0);
      for (;;) {
        let u = null;
        ids.forEach(id => { if (!done.has(id) && dist.has(id) && (u == null || dist.get(id) < dist.get(u))) u = id; });
        if (u == null) break;
        done.add(u);
        adj.get(u).forEach(x => { const nd = dist.get(u) + cost.get(x.e.id); if (x.to !== u && (!dist.has(x.to) || nd < dist.get(x.to))) dist.set(x.to, nd); });
      }
    }
    const rootPort = new Map(), isRoot = new Set(roots);
    g.nodes.forEach(n => {
      if (isRoot.has(n.id) || !dist.has(n.id)) return;
      let best = null;
      adj.get(n.id).forEach(x => {
        if (x.to === n.id || !dist.has(x.to)) return;
        const near = x.from === 'a' ? x.e.a : x.e.b, far = x.from === 'a' ? x.e.b : x.e.a;
        const c = { edge: x.e.id, cost: dist.get(x.to) + cost.get(x.e.id), via: x.to, viaPort: far.port, port: near.port };
        if (!best || c.cost - best.cost < 0 || (c.cost === best.cost && (cmpB(c.via, best.via) < 0 || (c.via === best.via && (c.viaPort < best.viaPort || (c.viaPort === best.viaPort && c.port < best.port)))))) best = c;
      });
      if (best) rootPort.set(n.id, best);
    });
    const fwd = new Set([...rootPort.values()].map(r => r.edge));
    // 被擋的一端：到根成本較大者，同分取橋 ID 較大者
    const blocked = g.edges.filter(e => e.a.node !== e.b.node && dist.has(e.a.node) && !fwd.has(e.id)).map(e => {
      const worseA = dist.get(e.a.node) > dist.get(e.b.node) || (dist.get(e.a.node) === dist.get(e.b.node) && cmpB(e.a.node, e.b.node) > 0);
      return { edge: e.id, node: worseA ? e.a.node : e.b.node, port: worseA ? e.a.port : e.b.port };
    });
    return { roots, rootPort, blocked, dist, pri };
  }
  // 設計頁：pair 以兩台中較小的優先權當一座橋；邊的成本依每條實體線兩端較慢的速率合計（聚合），速率不明以 1G 計
  function designStp(d) {
    const g = l2Graph(d), speeds = new Map();
    const speedOf = (dev, port) => {
      if (!speeds.has(dev)) { const x = devById(d, dev); speeds.set(dev, new Map(x ? portObjsOf(x).map(p => [p.name, speedBps(p.speed)]) : [])); }
      return speeds.get(dev).get(port) || null;
    };
    const priOfDev = id => { const x = devById(d, id); return x && stpPriOk(x.stpPri) ? x.stpPri : STP_PRI_DEFAULT; };
    const priOf = n => (n.devs ? Math.min(...n.devs.map(priOfDev)) : priOfDev(n.id));
    const costOf = e => {
      const bps = e.refs.reduce((sum, i) => { const l = d.links[i], sa = speedOf(l.a.dev, l.a.port), sb = speedOf(l.b.dev, l.b.port); return sum + (Math.min(sa || Infinity, sb || Infinity) === Infinity ? 1e9 : Math.min(sa || Infinity, sb || Infinity)); }, 0);
      return stpCost(bps);
    };
    return Object.assign({ g }, stpTree(g, priOf, costOf));
  }

  // 根橋建議（UX40）：每個連通塊的 STP 根橋不是拓樸中心（l2Analyze 的 roots）時，建議把中心的優先權設成 4096；
  // 中心已手動設過優先權（不論多少）時不再建議，交給使用者決定。回傳 [{root, suggest, devs}]（節點 id；devs 為要設定的設備）
  function stpAdvice(d) {
    const st = designStp(d), an = l2Analyze(st.g, []), comps = compsOf(st.g), out = [];
    an.roots.forEach(r => {
      const root = st.roots.find(x => comps.comp.get(x) === comps.comp.get(r.node));
      if (!root || root === r.node) return;
      const n = st.g.nodes.find(x => x.id === r.node), devs = n && n.devs ? n.devs : [r.node];
      if (devs.some(id => { const x = devById(d, id); return x && x.stpPri != null; })) return;
      out.push({ root, suggest: r.node, devs });
    });
    return out;
  }

  // ── 單點故障（XN213）：只依接線判斷（不含電源、控制平面等因素） ──
  // nodes:[{id,name}]、cables:[{a:{node,port},b:{node,port}}]（每條實體線一筆）、memberOf(node,port)→堆疊成員號（非堆疊為 null）
  // 逐一拿掉每台設備、每個堆疊成員（接在該成員埠上的線）、每條線，列出因此與其他設備斷開的設備：
  // 依原本的連通塊分組，拿掉後剩下設備中最大的一群視為留下（同數取設備順序在前者），其餘為斷開
  // 回傳 [{kind:'device'|'member'|'link', node, member, cable, cut:[node id]}]，依斷開台數由多到少
  const FAIL_KINDS = ['device', 'member', 'link'];
  function failureImpact(nodes, cables, memberOf) {
    const order = new Map(nodes.map((n, i) => [n.id, i]));
    const compsWithout = (skipNode, skipCable) => {
      const adj = new Map(nodes.filter(n => n.id !== skipNode).map(n => [n.id, []]));
      cables.forEach((c, i) => { if (!skipCable(i) && adj.has(c.a.node) && adj.has(c.b.node) && c.a.node !== c.b.node) { adj.get(c.a.node).push(c.b.node); adj.get(c.b.node).push(c.a.node); } });
      const comp = new Map();
      let n = 0;
      adj.forEach((_, s) => {
        if (comp.has(s)) return;
        const q = [s]; comp.set(s, n);
        while (q.length) adj.get(q.shift()).forEach(t => { if (!comp.has(t)) { comp.set(t, n); q.push(t); } });
        n++;
      });
      return comp;
    };
    const base = compsWithout(null, () => false);
    const cutOf = (skipNode, skipCable) => {
      const c = compsWithout(skipNode, skipCable), groups = new Map();
      c.forEach((nc, id) => {
        const b = base.get(id);
        if (!groups.has(b)) groups.set(b, new Map());
        const g = groups.get(b);
        if (!g.has(nc)) g.set(nc, []);
        g.get(nc).push(id);
      });
      const cut = [];
      groups.forEach(g => {
        if (g.size < 2) return;
        const parts = [...g.values()].sort((x, y) => y.length - x.length || Math.min(...x.map(i => order.get(i))) - Math.min(...y.map(i => order.get(i))));
        parts.slice(1).forEach(pt => cut.push(...pt));
      });
      return cut.sort((x, y) => order.get(x) - order.get(y));
    };
    const out = [], touched = new Set(), members = new Map();
    cables.forEach(c => ['a', 'b'].forEach(k => {
      touched.add(c[k].node);
      const m = memberOf ? memberOf(c[k].node, c[k].port) : null;
      if (m != null) members.set(c[k].node + '\u0000' + m, { node: c[k].node, member: m });
    }));
    nodes.forEach(n => { if (!touched.has(n.id)) return; const cut = cutOf(n.id, () => false); if (cut.length) out.push({ kind: 'device', node: n.id, cut }); });
    members.forEach(({ node, member }) => {
      const on = e => e.node === node && memberOf(e.node, e.port) === member;
      const cut = cutOf(null, i => on(cables[i].a) || on(cables[i].b));
      if (cut.length) out.push({ kind: 'member', node, member, cut });
    });
    cables.forEach((c, i) => { const cut = cutOf(null, j => j === i); if (cut.length) out.push({ kind: 'link', cable: i, cut }); });
    return out.sort((x, y) => y.cut.length - x.cut.length || FAIL_KINDS.indexOf(x.kind) - FAIL_KINDS.indexOf(y.kind));
  }
  // 設計頁：每條連線一筆，堆疊設備的成員號取自型號展開的埠（pair 兩台分開算）
  function designFailures(d) {
    const mem = new Map();
    d.devices.forEach(x => { if (x.members > 1) mem.set(x.id, new Map(portObjsOf(x).map(p => [p.name, p.member]))); });
    return failureImpact(d.devices.map(x => ({ id: x.id, name: x.hostname })), d.links.map(l => ({ a: { node: l.a.dev, port: l.a.port }, b: { node: l.b.dev, port: l.b.port } })),
      (node, port) => { const m = mem.get(node); return m && m.has(port) ? m.get(port) : null; });
  }

  // ── 自動排版（XN208）：每個連通塊以中心設備為第 0 層、依跳數分層，同層依上一層相鄰設備的平均位置排序 ──
  const LAYER_GAP = BOX_H + 90;
  // 跨機聚合 pair 以合併後的節點分層（UX40），pair 兩台在同一列並排、佔兩格；堆疊本來就是一個節點
  function autoLayout(d) {
    const g = l2Graph(d), adj = adjOf(g), an = l2Analyze(g, []), placed = new Map();
    const devsOf = id => { const n = g.nodes.find(x => x.id === id); return n && n.devs ? n.devs : [id]; };
    const slot = BOX_W + GAP_X, per = Math.max(1, Math.floor((CANVAS_W - 20) / slot)), overflow = [], PAIR_EXTRA = 50;
    let y = 20;
    const rowAt = (ids, yy) => {
      // 依格數切列：pair 佔 2 格，放不下就換到下一列
      const rows = [];
      let cur = [], used = 0;
      ids.forEach(id => { const w = devsOf(id).length; if (used + w > per && cur.length) { rows.push(cur); cur = []; used = 0; } cur.push(id); used += w; });
      if (cur.length) rows.push(cur);
      rows.forEach(row => {
        const cells = row.reduce((n, id) => n + devsOf(id).length, 0), pairs = row.filter(id => devsOf(id).length > 1).length;
        const x0 = Math.max(10, (CANVAS_W - (cells * slot - GAP_X + pairs * PAIR_EXTRA)) / 2);
        // 畫布高度放不下的設備最後再找空位
        if (yy > MAX_H - BOX_H) { row.forEach(id => { overflow.push(id); placed.set(id, CANVAS_W / 2); }); return; }
        let x = x0;
        row.forEach(id => {
          const ds = devsOf(id), w = ds.length > 1 ? slot + PAIR_EXTRA : 0;
          ds.forEach((dev, j) => moveDevice(d, dev, x + j * w, yy));
          placed.set(id, x + w / 2);
          x += ds.length > 1 ? 2 * slot + PAIR_EXTRA : slot;
        });
        yy += LAYER_GAP;
      });
      return yy;
    };
    an.roots.forEach(r => {
      const dist = hopsFrom(adj, r.node), layers = [];
      dist.forEach((k, id) => { (layers[k] = layers[k] || []).push(id); });
      layers.forEach(ids => {
        // 依上一層相鄰設備的平均位置排序，減少交叉；沒有上層鄰居時依名稱
        const key = id => { const xs = adj.get(id).filter(x => placed.has(x.to)).map(x => placed.get(x.to)); return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : Infinity; };
        const nm = id => (g.nodes.find(n => n.id === id) || {}).name || '';
        ids.sort((a, b) => key(a) - key(b) || (nm(a) < nm(b) ? -1 : 1));
        y = rowAt(ids, y);
      });
    });
    const lone = g.nodes.filter(n => !placed.has(n.id)).map(n => n.id);
    if (lone.length) y = rowAt(lone, y);
    // 層數多到畫布放不下（例如一長串）：改用一般格狀排列，順序沿用分層順序，pair 兩台仍相鄰
    if (overflow.length) [...placed.keys()].flatMap(devsOf).forEach((id, k) => moveDevice(d, id, 20 + (k % COLS) * slot, 20 + Math.floor(k / COLS) * (BOX_H + GAP_Y)));
    return d;
  }

  // ── 範例設計（UX40）：兩台 NX-OS 核心組 vPC（Eth1/47–48 為 peer link 聚合 Po100），三台兩成員 Catalyst 9300 堆疊以跨機聚合雙上行 ──
  function demoDesign() {
    const d = newDesign(), tk = { mode: 'trunk', vlans: '10,20,30' };
    [[10, 'USERS'], [20, 'VOICE'], [30, 'SERVERS']].forEach(([id, name]) => addVlan(d, { id, name }));
    const c1 = addDevice(d, { hostname: 'CORE-1', vendor: 'cisco_nxos', model: 'n9k-c9372px' }).dev, c2 = addDevice(d, { hostname: 'CORE-2', vendor: 'cisco_nxos', model: 'n9k-c9372px' }).dev;
    setStpPri(d, c1.id, 4096); setStpPri(d, c2.id, 4096);
    addPair(d, c1.id, c2.id, { domain: '1' });
    ['Ethernet1/47', 'Ethernet1/48'].forEach(p => { addLink(d, { dev: c1.id, port: p }, { dev: c2.id, port: p }, { mode: 'trunk', vlans: 'all' }); setPeer(d, d.links.length - 1, true); });
    addLag(d, [0, 1], { aNum: 100, bNum: 100 });
    [1, 2, 3].forEach(k => {
      const a = addDevice(d, { hostname: 'ACC-' + k, vendor: 'cisco', model: 'c9300-24', members: 2 }).dev;
      addLink(d, { dev: a.id, port: 'TenGigabitEthernet1/1/1' }, { dev: c1.id, port: 'Ethernet1/' + k }, tk);
      addLink(d, { dev: a.id, port: 'TenGigabitEthernet2/1/1' }, { dev: c2.id, port: 'Ethernet1/' + k }, tk);
      addLag(d, [d.links.length - 2, d.links.length - 1], { aNum: 1, bNum: 10 + k });
    });
    return autoLayout(d);
  }

  // ── 復原／重做（XN209）：快照為設計檔 JSON 字串，最多 max 份 ──
  function makeHistory(max) {
    const lim = max || 50;
    let list = [], at = -1;
    return {
      push(s) { if (list[at] === s) return false; list = list.slice(0, at + 1); list.push(s); if (list.length > lim) list.shift(); at = list.length - 1; return true; },
      undo() { if (at <= 0) return null; at--; return list[at]; },
      redo() { if (at >= list.length - 1) return null; at++; return list[at]; },
      canUndo: () => at > 0, canRedo: () => at < list.length - 1, size: () => list.length,
    };
  }

  // 只做結構檢查的讀法（XN205，交換器分析比對實際接線用）：不依本機型號資料，別台瀏覽器的自訂型號也不會讓線被略過
  function readDesignRaw(text) {
    let o;
    try { o = JSON.parse(String(text || '')); } catch (e) { return { ok: false, code: 'json' }; }
    if (!o || typeof o !== 'object' || o.format !== 'alpaca-design' || ![1, 2, 3, 4, 5].includes(o.version) || !Array.isArray(o.devices) || !Array.isArray(o.links)) return { ok: false, code: 'format' };
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
  function linksSvg(d, view) {
    const offs = parallelOffsets(d), mids = [], vw = view || {};
    const lines = d.links.map((l, i) => {
      const a = devById(d, l.a.dev), b = devById(d, l.b.dev);
      if (!a || !b) return '';
      // peer link（XN212）以紫色標示
      const st = linkState(d, l), col = l.peer ? '#a855f7' : STATE_COLOR[st];
      const p0 = center(a), q0 = center(b), flip = l.a.dev < l.b.dev ? 1 : -1;
      const dx = q0.x - p0.x, dy = q0.y - p0.y, len = Math.hypot(dx, dy) || 1, ox = -dy / len * offs[i] * flip, oy = dx / len * offs[i] * flip;
      const p = { x: +(p0.x + ox).toFixed(1), y: +(p0.y + oy).toFixed(1) }, q = { x: +(q0.x + ox).toFixed(1), y: +(q0.y + oy).toFixed(1) };
      const at = t => ({ x: p.x + (q.x - p.x) * t, y: p.y + (q.y - p.y) * t });
      mids[i] = at(0.4);
      const lbl = (pt, txt, full, extra) => `<text x="${pt.x.toFixed(1)}" y="${pt.y.toFixed(1)}" text-anchor="middle" font-size="10" fill="${extra || 'currentColor'}" stroke="var(--card)" stroke-width="3" paint-order="stroke"><title>${xesc(full)}</title>${xesc(txt)}</text>`;
      // 線中間：兩端設定相同時只寫一次，不同時寫「A 端｜B 端」
      const sa = cfgShort(l.a.cfg), sb = cfgShort(l.b.cfg), mid = sa === sb ? sa : (sa || '?') + ' | ' + (sb || '?');
      const midTxt = (st === 'high' || st === 'medium' ? '⚠ ' : '') + mid;
      // 二層分析標示（XN207／XN210）：選了 VLAN 時不帶它的線變淡；路徑底下加粗藍線、斷點加粗紅虛線
      const dimmed = vw.vlan != null && edgeCarries(l, vw.vlan) !== true;
      const under = vw.spof && vw.spof.links.has(i) ? `<line x1="${p.x}" y1="${p.y}" x2="${q.x}" y2="${q.y}" stroke="#ef4444" stroke-width="9" stroke-opacity="0.45" stroke-dasharray="8 5" data-td-spof-link/>`
        : vw.broken && vw.broken.has(i) ? `<line x1="${p.x}" y1="${p.y}" x2="${q.x}" y2="${q.y}" stroke="#ef4444" stroke-width="9" stroke-opacity="0.45" stroke-dasharray="8 5" data-td-broken/>`
        : vw.path && vw.path.has(i) ? `<line x1="${p.x}" y1="${p.y}" x2="${q.x}" y2="${q.y}" stroke="#0ea5e9" stroke-width="9" stroke-opacity="0.45" data-td-onpath/>` : '';
      // STP 被擋（XN214）：細虛線＋⊘
      const stpB = !!(vw.stp && vw.stp.has(i));
      return `<g data-td-link="${i}" data-td-state="${st}"${dimmed ? ' opacity="0.15" data-td-dim' : ''}${stpB ? ' data-td-stp-blocked' : ''}>${under}<line x1="${p.x}" y1="${p.y}" x2="${q.x}" y2="${q.y}" stroke="${col}" stroke-width="${st === 'high' ? 3 : 2}"${stpB ? ' stroke-dasharray="2 6" stroke-opacity="0.6"' : st === 'undef' ? ' stroke-dasharray="5 4"' : ''}/>`
        + (stpB ? lbl(at(0.62), '⊘', 'STP', '#ef4444') : '')
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
  function deviceSvg(d, dev, sel, T, view) {
    const m = findModel(dev.vendor, dev.model), total = devPorts(dev).length, used = usedPorts(d, dev.id).size, sp = view && view.spof;
    const failed = !!(sp && sp.dev === dev.id), cutOff = !!(sp && sp.cut.has(dev.id));
    const stroke = failed ? '#ef4444' : sel === dev.id ? 'var(--accent)' : 'var(--border)';
    return `<g data-td-dev="${xesc(dev.id)}" transform="translate(${dev.x},${dev.y})" style="cursor:grab"${failed ? ' data-td-spof-dev' : ''}${cutOff ? ' opacity="0.35" data-td-cut' : ''}>`
      + `<title>${xesc(dev.hostname + ' · ' + vendorName(dev.vendor) + ' · ' + (m ? m.label : '?'))}</title><rect width="${BOX_W}" height="${BOX_H}" rx="6" fill="var(--chip)" stroke="${stroke}" stroke-width="${failed || sel === dev.id ? 2.5 : 1.5}"${failed ? ' stroke-dasharray="6 3"' : ''}/>`
      + `<text x="8" y="18" font-size="13" font-weight="600" fill="currentColor">${xesc(cut(dev.hostname, 24))}</text>`
      + `<text x="8" y="34" font-size="10" fill="var(--dim)">${xesc(cut(vendorName(dev.vendor) + ' · ' + (m ? m.label : '?'), 34))}</text>`
      + `<text x="8" y="49" font-size="10" fill="var(--dim)">${xesc(T('td.ports_used', { used, total }) + (dev.members > 1 ? ' · ' + T(isMixedStack(dev) ? 'td.stack_mixed' : 'td.stack_badge', { n: dev.members }) : '') + (pairOfDev(d, dev.id) ? ' · ' + T('td.pair_badge') : ''))}</text></g>`;
  }
  function canvasSvg(d, sel, T, view) {
    const H = canvasH(d);
    return `<svg data-td-svg viewBox="0 0 ${CANVAS_W} ${H}" width="100%" style="display:block;max-width:${CANVAS_W}px;min-width:720px;aspect-ratio:${CANVAS_W}/${H};touch-action:none;user-select:none;color:var(--text)" role="img">`
      + `<rect width="${CANVAS_W}" height="${H}" fill="var(--bg)" stroke="var(--border)"/>`
      + `<g data-td-links>${linksSvg(d, view)}</g>${d.devices.map(x => deviceSvg(d, x, sel, T, view)).join('')}</svg>`;
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
    addPair, removePair, setPeer, pairIssues, PAIR_VENDORS, PAIR_ISSUE_TYPES, unitOf,
    readDesignRaw, changeDevice, canStack, devPortObjs, normMemberModels, isMixedStack, STACK_VENDORS, MAX_MEMBERS, parallelOffsets, l2Graph, carries, edgeCarries, l2Analyze, l2Path, L2P_REASONS, failureImpact, designFailures, FAIL_KINDS, setStpPri, stpTree, designStp, stpAdvice, demoDesign, stpCost, speedBps, STP_PRI_DEFAULT, autoLayout, makeHistory, designToSvg, designToDrawio, designToMermaid,
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
    const ports = dev ? devPorts(dev).filter(p => !used.has(lc(p))) : [];
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
  // 成員型號選單（XN215）：成員數 > 1 時列出成員 2～N，選項為同廠牌可堆疊的型號，第一項＝與成員 1 相同；保留原本的選擇
  function fillMemberModels(boxId, vendor, model, members, keep) {
    const box = $(boxId);
    if (!box) return;
    const n = membersOf(members) || 1, cur = keep || [...box.querySelectorAll('select[data-td-mm]')].reduce((a, el) => { a[+el.getAttribute('data-td-mm') - 1] = el.value; return a; }, []);
    if (n < 2 || !model || !canStack(vendor, model)) { box.innerHTML = ''; box.hidden = true; return; }
    const list = modelChoices(vendor).filter(m => canStack(vendor, m.value));
    box.hidden = false;
    box.innerHTML = Array.from({ length: n - 1 }, (_, i) => i + 2).map(k => {
      const v = cur[k - 1] && cur[k - 1] !== model ? cur[k - 1] : '';
      return `<label><span>${esc(T('td.member_model', { k }))}</span><select data-td-mm="${k}"><option value="">${esc(tr('td.same_as_m1'))}</option>`
        + list.filter(m => m.value !== model).map(m => `<option value="${esc(m.value)}"${m.value === v ? ' selected' : ''}>${esc(m.label)}</option>`).join('') + '</select></label>';
    }).join('');
  }
  const readMemberModels = boxId => { const out = ['']; ($(boxId) ? [...$(boxId).querySelectorAll('select[data-td-mm]')] : []).forEach(el => { out[+el.getAttribute('data-td-mm') - 1] = el.value; }); return out.length > 1 ? out : undefined; };
  const refreshAddMembers = () => fillMemberModels('td-member-models', $('td-vendor').value, $('td-model').value, $('td-members').value);
  const refreshEditMembers = keep => fillMemberModels('td-de-member-models', $('td-de-vendor').value, $('td-de-model').value, $('td-de-members').value, keep);
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
    $('td-de-members').value = String(dev.members || 1);
    fillDevEditModels(dev.model);
    refreshEditMembers(dev.memberModels || []);
    render();
    const box = $('td-dev-edit');
    if (box.scrollIntoView) box.scrollIntoView({ block: 'nearest' });
  }
  const readDevEdit = () => ({ hostname: $('td-de-host').value, vendor: $('td-de-vendor').value, model: $('td-de-model').value, members: $('td-de-members').value, memberModels: readMemberModels('td-de-member-models') || [] });
  function applyDevEdit(confirmed) {
    if (!devEdit) return;
    const o = readDevEdit();
    const dry = changeDevice(D, devEdit.id, o, { dryRun: true });
    if (!dry.ok) { say(tr('td.err_' + dry.code), true); return; }
    if ((dry.drop.length || dry.unpair) && !confirmed) {
      const hostOf = id => (devById(D, id) || {}).hostname || '';
      devEdit.pending = dry.drop.slice();
      const msgs = [];
      if (dry.drop.length) msgs.push(T('td.dev_drop', { n: dry.drop.length, links: dry.drop.map(i => { const l = D.links[i]; return hostOf(l.a.dev) + ' ' + l.a.port + ' ↔ ' + hostOf(l.b.dev) + ' ' + l.b.port; }).join('；') }));
      if (dry.unpair) msgs.push(T('td.dev_unpair', { pair: unitName(pairOfDev(D, devEdit.id).id) }));
      $('td-de-drop').textContent = msgs.join(' ');
      $('td-de-drop').hidden = false; $('td-de-confirm').hidden = false;
      return;
    }
    changeDevice(D, devEdit.id, o);
    devEdit = null; editing = null; lagPick = new Set();
    changed();
    say(T('td.dev_saved', { host: o.hostname.trim() }));
  }
  // ── 每次成功修改後（XN209）：清掉二層路徑結果、存復原快照、寫草稿（有勾選且已回應還原提示），再重畫 ──
  const DRAFT_KEY = 'topo_designer_draft';
  let hist = null, l2Res = null, l2Vlan = '', draftWait = false, spofSel = null, spofList = [], l2Tab = 'vlan', lagFold = new Set();
  const snapshot = () => JSON.stringify(buildDesign(D));
  const draftOn = () => !!$('td-draft-on') && $('td-draft-on').checked;
  function saveDraft() { if (!draftOn() || draftWait) return; try { localStorage.setItem(DRAFT_KEY, snapshot()); } catch (e) { /* 空間不足或停用時略過 */ } }
  function changed() {
    l2Res = null; spofSel = null;
    if (hist) hist.push(snapshot());
    saveDraft();
    render();
  }
  function restoreSnap(text) {
    const r = parseDesign(text);
    if (!r.ok) return false;
    D = r.design; sel = null; pickNext = 'a'; editing = null; devEdit = null; lagPick = new Set(); l2Res = null; spofSel = null;
    saveDraft();
    render();
    return true;
  }
  function undo() { const t = hist && hist.undo(); if (t != null && restoreSnap(t)) say(tr('td.undone')); }
  function redo() { const t = hist && hist.redo(); if (t != null && restoreSnap(t)) say(tr('td.redone')); }
  // 二層分析區（XN207）與兩點間路徑（XN210）
  const nameOfId = id => (devById(D, id) || {}).hostname || '';
  function renderL2() {
    const vs = $('td-l2-vlan'), keep = l2Vlan;
    vs.innerHTML = `<option value="">${esc(tr('td.l2_vlan_all'))}</option>` + D.vlans.map(v => `<option value="${v.id}"${String(v.id) === String(keep) ? ' selected' : ''}>${v.id}${v.name ? ' ' + esc(v.name) : ''}</option>`).join('');
    if (!D.vlans.some(v => String(v.id) === String(l2Vlan))) l2Vlan = '';
    ['from', 'to'].forEach(k => { const el = $('td-l2p-' + k), kv = el.value; el.innerHTML = D.devices.map(x => `<option value="${esc(x.id)}"${x.id === kv ? ' selected' : ''}>${esc(x.hostname)}</option>`).join(''); });
    const pv = $('td-l2p-vlan'), pk = pv.value;
    pv.innerHTML = D.vlans.map(v => `<option value="${v.id}"${String(v.id) === pk ? ' selected' : ''}>${v.id}${v.name ? ' ' + esc(v.name) : ''}</option>`).join('');
    const g = l2Graph(D), r = l2Analyze(g, D.vlans.map(v => v.id)), out = [];
    const linkTxt = id => { const e = g.edges[id]; return nameOfId(e.a.node) + ' ' + e.a.port + ' ↔ ' + nameOfId(e.b.node) + ' ' + e.b.port; };
    r.splits.forEach(x => out.push(`<div data-td-l2="split" style="color:var(--red)">${esc(T('td.l2_split', { vlan: x.vlan, groups: x.groups.map(gr => gr.join('、')).join(' ｜ ') }))}`
      + x.breaks.map(b => `<div style="margin-left:14px">${esc(T('td.l2_break', { node: b.node, port: b.port, link: linkTxt(b.edge) }))}</div>`).join('') + '</div>'));
    r.loops.forEach(x => out.push(`<div data-td-l2="loop" style="color:var(--yellow)">${esc(T('td.l2_loop', { nodes: x.nodes.join('、'), n: x.edges.length }))}</div>`));
    r.roots.forEach(x => out.push(`<div data-td-l2="root">${esc(T('td.l2_root', { name: x.name, n: x.nodes }))}</div>`));
    if (r.undef.length) out.push(`<div data-td-l2="undef" style="color:var(--dim)">${esc(T('td.l2_undef', { n: r.undef.length }))}</div>`);
    if (!r.splits.length && !r.loops.length && D.links.length) out.unshift(`<div data-td-l2="ok" style="color:var(--green)">${esc(tr('td.l2_ok'))}</div>`);
    $('td-l2-out').innerHTML = D.links.length ? out.join('') : `<div class="hint">${esc(tr('td.no_links'))}</div>`;
    // STP 模擬（XN214）
    const stp = designStp(D), stpNode = id => stp.g.nodes.find(n => n.id === id) || { id, name: '' };
    const priOpts = cur => `<option value=""${cur === '' ? ' selected' : ''}>${esc(tr('td.stp_default'))}</option>` + Array.from({ length: 16 }, (_, k) => k * 4096).map(n => `<option value="${n}"${String(cur) === String(n) ? ' selected' : ''}>${n}</option>`).join('');
    const devPri = id => { const x = devById(D, id); return x && x.stpPri != null ? x.stpPri : ''; };
    const linkOf = e => nameOfId2(e.a.node) + ' ' + e.a.port + ' ↔ ' + nameOfId2(e.b.node) + ' ' + e.b.port;
    function nameOfId2(id) { return stpNode(id).name || nameOfId(id); }
    const rpTxt = rp => { const e = stp.g.edges[rp.edge]; return e && e.lagName ? `<span title="${esc(rp.port)}">${esc(e.lagName)}</span>` : esc(rp.port); };
    const advice = stpAdvice(D).map(a => `<div data-td-stp="advice" style="color:var(--yellow)">${esc(T('td.stp_root_mismatch', { root: stpNode(a.root).name, suggest: stpNode(a.suggest).name }))} <button class="btn btn-sm" data-td-stp-fix="${esc(a.devs.join(','))}">${esc(T('td.stp_set_root', { name: stpNode(a.suggest).name }))}</button></div>`).join('');
    const stpRows = stp.g.nodes.filter(n => stp.dist.has(n.id)).sort((x, y) => stp.dist.get(x.id) - stp.dist.get(y.id) || (x.name < y.name ? -1 : 1)).map(n => {
      const ids = n.devs || [n.id], rp = stp.rootPort.get(n.id), cur = n.devs ? (devPri(n.devs[0]) === devPri(n.devs[1]) ? devPri(n.devs[0]) : '') : devPri(n.id);
      return `<tr data-td-stp-node="${esc(n.id)}"><td>${esc(n.name)}${stp.roots.includes(n.id) ? ' <b data-td-stp-root>★</b>' : ''}</td><td><select data-td-stp-pri="${esc(ids.join(','))}">${priOpts(cur)}</select></td><td>${stp.dist.get(n.id)}</td><td class="mono" style="font-size:12px">${rp ? rpTxt(rp) : '-'}</td></tr>`;
    });
    const so2 = $('td-stp-out');
    if (so2) so2.innerHTML = !D.links.length ? `<div class="hint">${esc(tr('td.no_links'))}</div>` : advice + stp.roots.map(r => `<div data-td-stp="root">${esc(T('td.stp_root', { name: stpNode(r).name, pri: stp.pri.get(r) }))}</div>`).join('')
      + (stp.blocked.length ? stp.blocked.map(b => `<div data-td-stp="blocked" style="color:var(--yellow)">${esc(T('td.stp_blocked', { link: linkOf(stp.g.edges[b.edge]), node: stpNode(b.node).name, port: b.port }))}</div>`).join('') : `<div data-td-stp="none" style="color:var(--green)">${esc(tr('td.stp_none_blocked'))}</div>`)
      + `<div style="overflow-x:auto"><table><thead><tr><th>${esc(tr('td.stp_col_bridge'))}</th><th>${esc(tr('td.stp_col_pri'))}</th><th>${esc(tr('td.stp_col_cost'))}</th><th>${esc(tr('td.stp_col_rootport'))}</th></tr></thead><tbody>${stpRows.join('')}</tbody></table></div>`;
    // 單點故障（XN213）
    spofList = designFailures(D);
    if (spofSel != null && !spofList[spofSel]) spofSel = null;
    const so = $('td-spof-out');
    if (so) so.innerHTML = !D.links.length ? `<div class="hint">${esc(tr('td.no_links'))}</div>` : spofList.length ? spofList.map((f, i) => {
      const name = nameOfId(f.node), cutTxt = f.cut.map(nameOfId).join('、');
      const l = f.kind === 'link' ? D.links[f.cable] : null, link = l ? nameOfId(l.a.dev) + ' ' + l.a.port + ' ↔ ' + nameOfId(l.b.dev) + ' ' + l.b.port : '';
      return `<div data-td-spof-item="${f.kind}" style="display:flex;gap:6px;align-items:baseline;flex-wrap:wrap"><span style="color:${f.cut.length > 1 ? 'var(--red)' : 'var(--yellow)'}">${esc(T('td.spof_' + f.kind, { name, member: f.member || '', link, cut: cutTxt, n: f.cut.length }))}</span>`
        + `<button class="btn btn-sm" data-td-spof="${i}">${esc(tr(spofSel === i ? 'td.spof_hide' : 'td.spof_show'))}</button></div>`;
    }).join('') : `<div data-td-spof-item="none" style="color:var(--green)">${esc(tr('td.spof_none'))}</div>`;
    // 分頁（UX40）：標籤帶數量，只顯示目前分頁
    const cnt = { vlan: r.splits.length + r.loops.length, stp: stp.blocked.length, spof: spofList.length, path: null };
    document.querySelectorAll('[data-td-tab]').forEach(b => {
      const k = b.getAttribute('data-td-tab'), n = cnt[k];
      b.textContent = tr('td.tab_' + k) + (n ? ' (' + n + ')' : '');
      b.setAttribute('aria-selected', k === l2Tab ? 'true' : 'false');
    });
    document.querySelectorAll('[data-td-pane]').forEach(el => { el.hidden = el.getAttribute('data-td-pane') !== l2Tab; });
    // 路徑結果
    const po = $('td-l2p-out');
    if (!l2Res) { po.innerHTML = ''; return; }
    const p = l2Res.r;
    if (p.ok) po.innerHTML = `<div data-td-l2p="ok" style="color:var(--green)">${esc(T('td.l2p_ok', { n: p.hops.length, vlan: l2Res.vlan }))}</div><ol style="margin:4px 0 0 18px;padding:0">`
      + p.hops.map(h => `<li class="mono" style="font-size:12px">${esc(nameOfId(h.from) + ' ' + h.fromPort + ' → ' + h.toPort + ' ' + nameOfId(h.to))}</li>`).join('') + `</ol><div class="hint">${esc(tr(l2Res.stp ? 'td.l2p_stp_on' : 'td.l2p_stp'))}</div>`;
    else po.innerHTML = `<div data-td-l2p="${esc(p.reason)}" style="color:var(--red)">${esc(T('td.l2p_' + p.reason, { node: p.node || '', port: p.port || '', vlan: l2Res.vlan }))}</div>`;
  }
  // 畫布標示：選了 VLAN 時只亮出帶它的線；有路徑結果時標出路徑（藍）或斷點（紅）
  function viewOpts() {
    // 畫布只畫目前分頁的標示（UX40）：vlan 變淡、stp 被擋的線、spof 故障項目、path 路徑（勾選依 STP 時也標被擋的線）
    const v = { vlan: l2Tab === 'vlan' && l2Vlan !== '' ? +l2Vlan : null, path: null, broken: null, spof: null, stp: null };
    // STP 被擋的線（XN214）
    if (l2Tab === 'stp' || (l2Tab === 'path' && stpOn())) { const st = designStp(D); v.stp = new Set(st.blocked.flatMap(b => st.g.edges[b.edge].refs)); }
    // 單點故障標示（XN213）：拿掉的設備與線標紅、斷開的設備變淡
    const f = l2Tab === 'spof' && spofSel != null && spofList[spofSel];
    if (f) {
      const on = e => (f.kind === 'device' && e.dev === f.node) || (f.kind === 'member' && e.dev === f.node && memberOfPort(e.dev, e.port) === f.member);
      v.spof = { dev: f.kind === 'device' ? f.node : null, cut: new Set(f.cut), links: new Set(D.links.map((l, i) => (f.kind === 'link' ? i === f.cable : on(l.a) || on(l.b)) ? i : -1).filter(i => i >= 0)) };
    }
    if (l2Res && l2Tab === 'path') {
      const g = l2Res.g, refs = ids => new Set(ids.flatMap(id => g.edges[id].refs));
      if (l2Res.r.ok) v.path = refs(l2Res.r.hops.map(h => h.edge));
      else if (l2Res.r.edge != null) { v.broken = refs([l2Res.r.edge]); if (l2Res.r.hops) v.path = refs(l2Res.r.hops.map(h => h.edge).filter(id => id !== l2Res.r.edge)); }
    }
    return v;
  }
  const stpOn = () => !!$('td-stp-on') && $('td-stp-on').checked;
  function memberOfPort(dev, port) {
    const x = devById(D, dev);
    if (!x || !(x.members > 1)) return null;
    const p = portObjsOf(x).find(q => q.name === port);
    return p ? p.member : null;
  }
  function render() {
    $('td-canvas').innerHTML = D.devices.length ? canvasSvg(D, sel, T, viewOpts()) : `<div class="hint">${esc(tr('td.empty_canvas'))}</div>`;
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
        + D.devices.map(x => { const m = findModel(x.vendor, x.model); return `<tr><td>${esc(x.hostname)}</td><td>${esc(vendorName(x.vendor))}</td><td>${esc(m ? m.label : '?')}${isMixedStack(x) ? x.memberModels.map((v, k) => (v ? `<div class="hint" style="margin:0">${esc(T('td.member_model', { k: k + 1 }))}: ${esc((findModel(x.vendor, v) || {}).label || v)}</div>` : '')).join('') : ''}</td><td>${usedPorts(D, x.id).size}／${devPorts(x).length}${x.members > 1 ? ' · ' + esc(T(isMixedStack(x) ? 'td.stack_mixed' : 'td.stack_badge', { n: x.members })) : ''}</td><td style="white-space:nowrap"><button class="btn btn-sm" data-td-send="${esc(x.id)}">${esc(tr('td.send'))}</button> <button class="btn btn-sm" data-td-edit-dev="${esc(x.id)}">${esc(tr('td.edit_dev'))}</button> <button class="btn btn-sm" data-td-rm-dev="${esc(x.id)}">${esc(tr('td.rm'))}</button></td></tr>`; }).join('') + '</tbody></table>'
      : `<div class="hint">${esc(tr('td.no_devices'))}</div>`;
    const color = { high: 'var(--red)', medium: 'var(--yellow)', info: 'var(--dim)' };
    $('td-link-list').innerHTML = D.links.length
      ? `<table><thead><tr><th></th><th>${esc(tr('td.col_a'))}</th><th>${esc(tr('td.col_cfg_a'))}</th><th>${esc(tr('td.col_b'))}</th><th>${esc(tr('td.col_cfg_b'))}</th><th>${esc(tr('td.col_status'))}</th><th></th></tr></thead><tbody>`
        + linkRowsGrouped((l, i) => {
          const is = linkIssues(D, l);
          const st = is.length ? is.map(x => `<div data-td-issue="${x.type}" style="color:${color[x.level]}">${esc(issueText(x))}</div>`).join('') : `<span style="color:var(--green)">${esc(tr('td.st_ok'))}</span>`;
          const g = l.lag && lagById(D, l.lag);
          const pr = pairOfDev(D, l.a.dev), intra = pr && pairOfDev(D, l.b.dev) === pr;
          const peerBtn = intra ? ` <button class="btn btn-sm" data-td-peer="${i}" aria-pressed="${l.peer ? 'true' : 'false'}">${esc(tr(l.peer ? 'td.peer_on' : 'td.peer_off'))}</button>` : '';
          const pick = (g || l.peer ? '' : `<input type="checkbox" data-td-lag-pick="${i}"${lagPick.has(i) ? ' checked' : ''} aria-label="${esc(tr('td.lag_add'))}">`) + peerBtn;
          return `<tr data-td-link-row="${i}"><td>${pick}</td><td>${esc(hostOf(l.a.dev))} <span class="mono">${esc(l.a.port)}</span></td><td>${esc(cfgText(l.a.cfg))} <button class="btn btn-sm" data-td-edit="${i}:a">${esc(tr('td.edit'))}</button></td>`
            + `<td>${esc(hostOf(l.b.dev))} <span class="mono">${esc(l.b.port)}</span></td><td>${esc(cfgText(l.b.cfg))} <button class="btn btn-sm" data-td-edit="${i}:b">${esc(tr('td.edit'))}</button></td>`
            + `<td>${st}</td><td><button class="btn btn-sm" data-td-rm-link="${i}">${esc(tr('td.rm'))}</button></td></tr>`;
        }, color) + '</tbody></table>'
      : `<div class="hint">${esc(tr('td.no_links'))}</div>`;
    renderLagBox();
    renderPairBox();
    renderL2();
    if ($('td-undo')) { $('td-undo').disabled = !(hist && hist.canUndo()); $('td-redo').disabled = !(hist && hist.canRedo()); }
  }
  // 連線清單依聚合分組（UX40）：同一聚合的成員連續排列，前面一列群組標題（名稱、兩端、條數、問題數），可收合
  function linkRowsGrouped(rowOf, color) {
    const done = new Set(), out = [];
    D.links.forEach((l, i) => {
      const g = l.lag && lagById(D, l.lag);
      if (!g) { out.push(rowOf(l, i)); return; }
      if (done.has(g.id)) return;
      done.add(g.id);
      const idx = D.links.map((x, k) => (x.lag === g.id ? k : -1)).filter(k => k >= 0), folded = lagFold.has(g.id);
      const iss = idx.flatMap(k => linkIssues(D, D.links[k])), worst = ['high', 'medium', 'info'].find(lv => iss.some(x => x.level === lv));
      const st = worst ? `<span style="color:${color[worst]}">⚠ ${iss.length}</span>` : `<span style="color:var(--green)">${esc(tr('td.st_ok'))}</span>`;
      out.push(`<tr data-td-lag-head="${esc(g.id)}"><td colspan="7"><button class="btn btn-sm" data-td-lag-fold="${esc(g.id)}" aria-expanded="${folded ? 'false' : 'true'}" title="${esc(tr(folded ? 'td.unfold' : 'td.fold'))}">${folded ? '▸' : '▾'}</button> `
        + `<b class="mono" style="color:#a855f7">${esc(lagName(g))}</b> ${esc(T('td.lag_group', { a: unitName(g.a.dev), b: unitName(g.b.dev), n: idx.length }))} · ${st}</td></tr>`);
      if (!folded) idx.forEach(k => out.push(rowOf(D.links[k], k)));
    });
    return out.join('');
  }
  // 聚合區（XN204）：勾選的線、兩端編號欄位標示設備名稱、已建立的聚合清單
  const lagName = g => 'Po' + g.a.num + (g.a.num === g.b.num ? '' : '/' + g.b.num);
  let lagPick = new Set(), pairOpened = false;
  // 跨機聚合 pair 區（XN212）：可選的設備只列支援的廠牌且還沒組成 pair 的
  function renderPairBox() {
    const cand = D.devices.filter(x => PAIR_VENDORS.includes(x.vendor) && !pairOfDev(D, x.id));
    if (!pairOpened && (cand.length >= 2 || (D.pairs || []).length)) { pairOpened = true; $('td-pair-sec').open = true; }
    ['a', 'b'].forEach(k => { const el = $('td-pair-' + k), kv = el.value; el.innerHTML = `<option value="">${esc(tr('td.pick'))}</option>` + cand.map(x => `<option value="${esc(x.id)}"${x.id === kv ? ' selected' : ''}>${esc(x.hostname)}</option>`).join(''); });
    const iss = pairIssues(D);
    $('td-pair-list').innerHTML = (D.pairs || []).length
      ? `<table><thead><tr><th>${esc(tr('td.pair_col'))}</th><th>${esc(tr('td.pair_domain'))}</th><th>${esc(tr('td.col_status'))}</th><th></th></tr></thead><tbody>`
        + D.pairs.map(p => { const is = iss.filter(x => x.pair === p.id);
          return `<tr data-td-pair-row="${esc(p.id)}"><td>${esc(unitName(p.id))}</td><td class="mono">${esc(p.domain)}</td><td>`
            + (is.length ? is.map(x => `<div data-td-pi="${x.type}" style="color:${x.level === 'high' ? 'var(--red)' : 'var(--dim)'}">${esc(T('td.pi_' + x.type, x.p))}</div>`).join('') : `<span style="color:var(--green)">${esc(tr('td.st_ok'))}</span>`)
            + `</td><td><button class="btn btn-sm" data-td-rm-pair="${esc(p.id)}">${esc(tr('td.pair_rm'))}</button></td></tr>`; }).join('') + '</tbody></table>'
      : `<div class="hint">${esc(tr('td.pair_none'))}</div>`;
  }
  // 單位名稱：pair 為「A＋B」，其餘為主機名稱
  const unitName = u => { const p = (D.pairs || []).find(x => x.id === u); return p ? (devById(D, p.a) || {}).hostname + '＋' + (devById(D, p.b) || {}).hostname : (devById(D, u) || {}).hostname || ''; };
  function renderLagBox() {
    lagPick = new Set([...lagPick].filter(i => D.links[i] && !D.links[i].lag && !D.links[i].peer));
    const first = D.links[[...lagPick][0]], hostOf = id => unitName(unitOf(D, id));
    $('td-lag-box').hidden = !lagPick.size;
    $('td-lag-picked').textContent = T('td.lag_picked', { n: lagPick.size });
    $('td-lag-a-lbl').textContent = first ? T('td.lag_num', { host: hostOf(first.a.dev) }) : T('td.lag_num', { host: 'A' });
    $('td-lag-b-lbl').textContent = first ? T('td.lag_num', { host: hostOf(first.b.dev) }) : T('td.lag_num', { host: 'B' });
    $('td-lag-list').innerHTML = (D.lags || []).length
      ? `<table><thead><tr><th>${esc(tr('td.col_lag'))}</th><th>${esc(tr('td.col_a'))}</th><th>${esc(tr('td.col_b'))}</th><th>${esc(tr('td.lag_mode'))}</th><th>${esc(tr('td.col_members'))}</th><th></th></tr></thead><tbody>`
        + D.lags.map(g => `<tr data-td-lag-row="${esc(g.id)}"><td class="mono">${esc(lagName(g))}</td><td>${esc(unitName(g.a.dev))} Po${g.a.num}</td><td>${esc(unitName(g.b.dev))} Po${g.b.num}</td><td>${esc(tr('td.lag_mode_' + g.mode))}</td>`
          + `<td class="mono">${esc(lagMembers(D, g.id).map(l => (unitOf(D, l.a.dev) === g.a.dev ? l.a : l.b)).map(e => (D.pairs || []).some(p => p.id === g.a.dev) ? (devById(D, e.dev) || {}).hostname + ' ' + e.port : e.port).join(', '))}</td><td><button class="btn btn-sm" data-td-rm-lag="${esc(g.id)}">${esc(tr('td.lag_rm'))}</button></td></tr>`).join('') + '</tbody></table>'
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
    if (lk) lk.innerHTML = linksSvg(D, viewOpts());
  }
  function onUp() {
    if (!drag) return;
    const d = drag;
    drag = null;
    // 拖到最下面時畫布要長高；其他情況方塊已在原位，不必重畫
    // 拖拉放開也算一次修改（復原快照、草稿）；畫布順便依新高度重畫
    if (d.moved) { changed(); return; }
    // 點選：依序填入 A 端、B 端
    $('td-' + pickNext + '-dev').value = d.dev.id;
    sel = d.dev.id;
    const end = pickNext;
    pickNext = pickNext === 'a' ? 'b' : 'a';
    render();
    say(T(end === 'a' ? 'td.picked_a' : 'td.picked_b', { host: d.dev.hostname }));
    // 兩端都選好時，連線表單不在視窗內（窄螢幕）就捲過去選埠（UX40）
    if (end === 'b') { const c = $('td-link-card'), r = c && c.getBoundingClientRect(); if (r && (r.top < 0 || r.bottom > innerHeight)) c.scrollIntoView({ block: 'nearest' }); }
  }

  // 範例設計（UX40）：目前設計非空時先確認；可復原
  function loadDemo() {
    if (D.devices.length && !confirm(tr('td.demo_confirm'))) return;
    D = demoDesign(); sel = null; pickNext = 'a'; editing = null; devEdit = null; lagPick = new Set(); lagFold = new Set();
    changed();
    say(T('td.demo_loaded', { d: D.devices.length, l: D.links.length }));
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
    changed();
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
    hist = makeHistory(50);
    hist.push(snapshot());
    // 草稿（XN209）：有暫存時勾選維持開啟，並詢問是否還原；回應前不覆蓋
    let draft = null;
    try { draft = localStorage.getItem(DRAFT_KEY); } catch (e) { draft = null; }
    if (draft) { $('td-draft-on').checked = true; draftWait = true; $('td-draft-bar').hidden = false; }
    render();
    if (/[?&]demo=1(&|$)/.test(location.search) && !draft) loadDemo();
    $('td-draft-restore').addEventListener('click', () => {
      draftWait = false; $('td-draft-bar').hidden = true;
      const r = loadText(draft || '');
      if (!r.ok) { try { localStorage.removeItem(DRAFT_KEY); } catch (e) { /* 略過 */ } }
    });
    $('td-draft-discard').addEventListener('click', () => {
      draftWait = false; $('td-draft-bar').hidden = true;
      try { localStorage.removeItem(DRAFT_KEY); } catch (e) { /* 略過 */ }
      $('td-draft-on').checked = false;
    });
    $('td-draft-on').addEventListener('change', e => {
      draftWait = false; $('td-draft-bar').hidden = true;
      if (e.target.checked) { saveDraft(); say(tr('td.draft_on')); }
      else { try { localStorage.removeItem(DRAFT_KEY); } catch (er) { /* 略過 */ } say(tr('td.draft_off')); }
    });
    $('td-undo').addEventListener('click', undo);
    $('td-redo').addEventListener('click', redo);
    // 快捷鍵：Ctrl+Z 復原、Ctrl+Y／Ctrl+Shift+Z 重做；在輸入框內交給瀏覽器
    document.addEventListener('keydown', e => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
      const t = e.target, tag = t && t.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (t && t.isContentEditable)) return;
      const k = String(e.key).toLowerCase();
      if (k === 'z' && !e.shiftKey) { e.preventDefault(); undo(); }
      else if (k === 'y' || (k === 'z' && e.shiftKey)) { e.preventDefault(); redo(); }
    });
    $('td-layout').addEventListener('click', () => { if (!D.devices.length) return; autoLayout(D); changed(); say(tr('td.layout_done')); });
    $('td-l2-vlan').addEventListener('change', e => { l2Vlan = e.target.value; render(); });
    $('td-stp-on').addEventListener('change', () => { l2Res = null; render(); });
    $('td-demo').addEventListener('click', loadDemo);
    $('td-l2p-run').addEventListener('click', () => {
      const v = $('td-l2p-vlan').value;
      if (!v) { say(tr('td.l2p_novlan'), true); return; }
      // 勾選依 STP 計算時只走沒被擋的線（XN214）
      const st = stpOn() ? designStp(D) : null, g = st ? st.g : l2Graph(D), bl = new Set(st ? st.blocked.map(b => b.edge) : []);
      l2Res = { g, vlan: +v, stp: !!st, r: l2Path(g, unitOf(D, $('td-l2p-from').value), unitOf(D, $('td-l2p-to').value), +v, { allow: e => !bl.has(e.id) }) };
      render();
    });
    $('td-l2p-clear').addEventListener('click', () => { l2Res = null; render(); });
    $('td-lang-sel').addEventListener('change', e => { lang = e.target.value; saveLang(lang); fillStatic(); refreshAddMembers(); if (devEdit) refreshEditMembers(); render(); });
    $('td-vendor').addEventListener('change', () => { fillModels(); fillCustom(); refreshAddMembers(); });
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
      const r = addDevice(D, { hostname: $('td-host').value, vendor: $('td-vendor').value, model: $('td-model').value, members: $('td-members').value, memberModels: readMemberModels('td-member-models') });
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      $('td-host').value = '';
      changed();
      say(T('td.added_dev', { host: r.dev.hostname }));
    });
    $('td-vlan-add').addEventListener('click', () => {
      const r = addVlan(D, { id: $('td-vlan-id').value, name: $('td-vlan-name').value });
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      $('td-vlan-id').value = ''; $('td-vlan-name').value = '';
      changed();
      say(T('td.added_vlan', { id: r.vlan.id }));
    });
    $('td-link-add').addEventListener('click', () => {
      const r = addLink(D, { dev: $('td-a-dev').value, port: $('td-a-port').value }, { dev: $('td-b-dev').value, port: $('td-b-port').value }, readCfgForm('l'));
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      const h = id => devById(D, id).hostname;
      changed();
      say(T('td.added_link', { a: h(r.link.a.dev), pa: r.link.a.port, b: h(r.link.b.dev), pb: r.link.b.port }));
    });
    $('td-e-save').addEventListener('click', () => {
      if (!editing) return;
      const r = setEndCfg(D, editing.i, editing.end, readCfgForm('e'));
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      const e = D.links[editing.i][editing.end];
      editing = null;
      changed();
      say(T('td.saved_end', { host: (devById(D, e.dev) || {}).hostname || '', port: e.port }));
    });
    $('td-e-cancel').addEventListener('click', () => { editing = null; render(); });
    // 編輯設備：改了表單就要重新確認要刪除的線
    const resetDrop = () => { if (devEdit) devEdit.pending = null; $('td-de-drop').hidden = true; $('td-de-confirm').hidden = true; };
    $('td-de-vendor').addEventListener('change', () => { fillDevEditModels(); refreshEditMembers(); resetDrop(); });
    $('td-de-model').addEventListener('change', () => { refreshEditMembers(); resetDrop(); });
    $('td-de-host').addEventListener('input', resetDrop);
    $('td-de-members').addEventListener('input', () => { refreshEditMembers(); resetDrop(); });
    $('td-de-member-models').addEventListener('change', resetDrop);
    $('td-model').addEventListener('change', refreshAddMembers);
    $('td-members').addEventListener('input', refreshAddMembers);
    $('td-de-apply').addEventListener('click', () => applyDevEdit(false));
    $('td-de-confirm').addEventListener('click', () => applyDevEdit(true));
    $('td-de-cancel').addEventListener('click', () => { devEdit = null; render(); });
    document.addEventListener('change', e => {
      const t = e.target;
      // STP 優先權（XN214）：pair 兩台一起改
      if (t && t.matches && t.matches('[data-td-stp-pri]')) {
        const ids = t.getAttribute('data-td-stp-pri').split(','), v = t.value;
        if (ids.every(id => setStpPri(D, id, v).ok)) changed(); else say(tr('td.err_stp_pri'), true);
        return;
      }
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
      changed();
      say(T('td.lag_added', { name: lagName(r.lag), n: lagMembers(D, r.lag.id).length }));
    });
    $('td-pair-add').addEventListener('click', () => {
      const r = addPair(D, $('td-pair-a').value, $('td-pair-b').value, { domain: $('td-pair-domain').value });
      if (!r.ok) { say(tr('td.err_' + r.code), true); return; }
      changed();
      say(T('td.pair_added', { pair: unitName(r.pair.id) }));
    });
    $('td-exp-svg').addEventListener('click', () => download('topology-design.svg', designToSvg(D, T), 'image/svg+xml'));
    $('td-exp-drawio').addEventListener('click', () => download('topology-design.drawio', designToDrawio(D), 'application/xml'));
    $('td-exp-mmd').addEventListener('click', () => download('topology-design.mmd', designToMermaid(D), 'text/plain'));
    document.addEventListener('click', e => {
      const t = e.target && e.target.closest ? e.target : null;
      if (!t) return;
      const de = t.closest('[data-td-edit-dev]');
      if (de) { openDevEdit(de.getAttribute('data-td-edit-dev')); return; }
      const tb = t.closest('[data-td-tab]');
      if (tb) { l2Tab = tb.getAttribute('data-td-tab'); render(); return; }
      const fx = t.closest('[data-td-stp-fix]');
      if (fx) { if (fx.getAttribute('data-td-stp-fix').split(',').every(id => setStpPri(D, id, 4096).ok)) changed(); return; }
      const lf = t.closest('[data-td-lag-fold]');
      if (lf) { const id = lf.getAttribute('data-td-lag-fold'); if (lagFold.has(id)) lagFold.delete(id); else lagFold.add(id); render(); return; }
      const sf = t.closest('[data-td-spof]');
      if (sf) { const i = +sf.getAttribute('data-td-spof'); spofSel = spofSel === i ? null : i; render(); return; }
      const pe = t.closest('[data-td-peer]');
      if (pe) { const i = +pe.getAttribute('data-td-peer'); if (D.links[i]) { setPeer(D, i, !D.links[i].peer); lagPick.delete(i); changed(); } return; }
      const rp = t.closest('[data-td-rm-pair]');
      if (rp) { removePair(D, rp.getAttribute('data-td-rm-pair')); changed(); return; }
      const rg = t.closest('[data-td-rm-lag]');
      if (rg) { removeLag(D, rg.getAttribute('data-td-rm-lag')); changed(); return; }
      const rd = t.closest('[data-td-rm-dev]'), rl = t.closest('[data-td-rm-link]'), rv = t.closest('[data-td-rm-vlan]'), ed = t.closest('[data-td-edit]'), sd = t.closest('[data-td-send]');
      if (rd || rl) lagPick = new Set();
      if (rd) { removeDevice(D, rd.getAttribute('data-td-rm-dev')); if (!devById(D, sel)) sel = null; editing = null; changed(); }
      else if (rl) { removeLink(D, +rl.getAttribute('data-td-rm-link')); editing = null; changed(); }
      else if (rv) { const r = removeVlan(D, +rv.getAttribute('data-td-rm-vlan')); if (!r.ok) say(tr('td.err_' + r.code), true); changed(); }
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
    $('td-clear').addEventListener('click', () => { D = newDesign(); sel = null; pickNext = 'a'; editing = null; devEdit = null; lagPick = new Set(); changed(); say(tr('td.cleared')); });
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
  api.add = o => { const r = addDevice(D, o); if (r.ok) changed(); return r; };
  api.addVlan = o => { const r = addVlan(D, o); if (r.ok) changed(); return r; };
  api.link = (a, b, cfg) => { const r = addLink(D, a, b, cfg); if (r.ok) changed(); return r; };
  api.lag = (idxs, o) => { const r = addLag(D, idxs, o); if (r.ok) changed(); return r; };
  api.pair = (a, b, o) => { const r = addPair(D, a, b, o); if (r.ok) changed(); return r; };
  api.peer = (i, on) => { const r = setPeer(D, i, on); if (r.ok) changed(); return r; };
  api.undo = () => undo();
  api.redo = () => redo();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
