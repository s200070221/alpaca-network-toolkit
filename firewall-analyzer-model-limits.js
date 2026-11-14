// ═══════════════════════════════════════════════════════════════════════════
// firewall-analyzer-model-limits.js — 型號＋版本限制（XN144）：FortiGate 小記憶體機種升版後被移除的功能
// 資料一律依 Fortinet 官方文件（docs.fortinet.com 的 FortiOS release notes／new features），每條附出處；
// 只依官方列出的系列判斷，不內建各型號的記憶體大小。FortiGate-Rugged 60F 有 2GB 與 4GB 兩種，設定檔分不出來，
// 標「需確認記憶體」並附官方確認指令。純函式，以 window.FwModelLimits 對外
// ═══════════════════════════════════════════════════════════════════════════
(function () {
  const ASOF = '2026-11-13';
  const RAM_CHECK_CMD = 'diagnose hardware sysinfo conserve';
  // 系列代碼（設定檔檔頭型號去掉 FG／FGT／FWF／FGR 前綴與 3G4G、POE 等後綴）
  // series：符合的系列；rugged2gb：FGR 的這些系列只有 2GB 版本受影響；all：所有機種
  const LIMITS = [
    { id: 'proxy-2gb', since: '7.4.4', series: ['40F', '60E', '61E', '60F', '61F', '80E', '81E', '90E', '91E'], rugged2gb: ['60F'],
      features: ['proxyInspect', 'proxyOnly', 'ztna', 'accessProxy', 'proxyPolicy', 'explicitProxy', 'l7Vip', 'wanopt'],
      src: 'https://docs.fortinet.com/document/fortigate/7.4.0/new-features/519079/proxy-related-features-no-longer-supported-on-fortigate-2gb-ram-models-7-4-4' },
    { id: 'sslvpn-2gb', since: '7.6.0', series: ['40F', '60F', '61F'], rugged2gb: ['60F'], features: ['sslTunnel', 'sslWeb'],
      src: 'https://docs.fortinet.com/document/fortigate/7.6.1/fortios-release-notes/877104/ssl-vpn-removed-from-2gb-ram-models-for-tunnel-and-web-mode' },
    { id: 'sslvpn-90g', since: '7.6.1', series: ['90G', '91G'], features: ['sslTunnel', 'sslWeb'],
      src: 'https://docs.fortinet.com/document/fortigate/7.6.1/fortios-release-notes/205987/ssl-vpn-not-supported-on-fortigate-90g-series-models' },
    { id: 'tunnel-all', since: '7.6.3', all: true, features: ['sslTunnel'],
      src: 'https://docs.fortinet.com/document/fortigate/7.6.6/fortios-release-notes/173430/ssl-vpn-tunnel-mode-replaced-with-ipsec-vpn' },
    { id: 'agentless-763', since: '7.6.3', series: ['40F', '60F', '61F', '90G', '91G'], rugged2gb: ['60F'], features: ['sslWeb'],
      src: 'https://docs.fortinet.com/document/fortigate/7.6.3/fortios-release-notes/877104/agentless-vpn-formerly-ssl-vpn-web-mode-not-supported-on-fortigate-40f-60f-and-90g-series-models' },
    { id: 'agentless-764', since: '7.6.4', series: ['50G', '70G'], features: ['sslWeb'],
      src: 'https://docs.fortinet.com/document/fortigate/7.6.4/fortios-release-notes/877104/agentless-vpn-formerly-ssl-vpn-web-mode-not-supported-on-some-fortigate-series-models' },
  ];

  // 檔頭型號 → { series, rugged }；FGVMK6、FG1K1E 等不符合 數字＋字母 寫法者回傳 null
  function modelSeries(model) {
    const m = String(model || '').toUpperCase().replace(/[^A-Z0-9]/g, '').match(/^(FGT|FGR|FWF|FG)(\d{2,4})([A-Z])/);
    return m ? { series: m[2] + m[3], rugged: m[1] === 'FGR', wifi: m[1] === 'FWF' } : null;
  }
  // 版本：完整（7.4.3）或只有主次版本（設定檔檔頭 7.04＝7.4）；回傳 { nums:[主,次,修補|null] } 或 null
  function parseVer(v) {
    const s = String(v || '');
    let m = s.match(/(\d+)\.(\d+)\.(\d+)/);
    if (m) return { nums: [+m[1], +m[2], +m[3]], full: true };
    m = s.match(/(\d+)\.(\d{1,2})\b/);
    return m ? { nums: [+m[1], +m[2], null], full: false } : null;
  }
  // 目前版本與限制起始版本的關係：active（已在範圍內）、upgrade（升級到 since 以後才受影響）、patch（主次版本相同、修補版不明）、unknown
  function relation(cur, since) {
    const c = parseVer(cur), s = parseVer(since);
    if (!c || !s) return 'unknown';
    for (let i = 0; i < 2; i++) if (c.nums[i] !== s.nums[i]) return c.nums[i] > s.nums[i] ? 'active' : 'upgrade';
    if (c.nums[2] === null) return 'patch';
    return c.nums[2] >= s.nums[2] ? 'active' : 'upgrade';
  }
  // 用到的功能（parser 的 deviceInfo.featureUse）→ 受影響設定清單 { kind: [參照] }
  function usedRefs(fu, kind) {
    if (!fu) return [];
    const sslOn = fu.sslvpn !== false;  // null（沒有 vpn ssl settings 區塊）時有 portal 設定仍列出，標為可能使用
    switch (kind) {
      case 'sslTunnel': return sslOn ? fu.portalTunnel || [] : [];
      case 'sslWeb': return sslOn ? fu.portalWeb || [] : [];
      case 'proxyOnly': return (fu.proxyOnly || []).map(x => x.id + ' (' + x.kinds.join(', ') + ')');
      case 'explicitProxy': return fu.explicitProxy ? ['web-proxy explicit'] : [];
      default: return fu[kind] || [];
    }
  }
  // parsed：FortiGate 解析結果；version：使用者補填的完整版本（沒有就用設定檔的 firmware）
  function assess(parsed, version) {
    const p = parsed || {}, info = p.deviceInfo || {};
    if (!/fortigate/i.test(p.vendor || '')) return { supported: false };
    const ms = modelSeries(info.model);
    const ver = String(version || '').trim() || String(info.firmware || '').replace(/^-$/, '');
    const fu = info.featureUse || null;
    const items = [];
    LIMITS.forEach(L => {
      let applies = !!L.all, ramCheck = false;
      if (!applies && ms) {
        if (ms.rugged) { applies = (L.rugged2gb || []).includes(ms.series); ramCheck = applies; }
        else applies = (L.series || []).includes(ms.series);
      }
      if (!applies) return;
      const uses = L.features.map(k => ({ kind: k, refs: usedRefs(fu, k) })).filter(u => u.refs.length);
      if (!uses.length) return;
      items.push({ id: L.id, since: L.since, src: L.src, status: relation(ver, L.since), ramCheck, uncertain: fu && fu.sslvpn === null && uses.some(u => /^ssl/.test(u.kind)), uses });
    });
    return { supported: true, model: info.model || '-', series: ms ? ms.series : '', rugged: !!(ms && ms.rugged), version: ver, versionFull: !!(parseVer(ver) || {}).full,
      known: !!ms, items, asof: ASOF, ramCmd: RAM_CHECK_CMD };
  }

  // ── 數量上限（XN145）：官方 Maximum Values 表（firewall-analyzer-fg-maxvalues.js，build_fg_max_values.py 產生）──
  // 官方語意：instance＝每個物件內的項目數、vdom＝每個 VDOM、global＝整台，三者同時生效；0＝只受記憶體限制
  const MV_NEAR = 0.8;
  const vdomOf = x => (x && x._vdom) || 'root';
  const memList = v => String(v || '').split(/,\s*/).map(x => x.trim()).filter(x => x && x !== '-');
  // 每項：obj＝官方表物件名稱；vd＝依 VDOM 分組的物件清單；inst＝每個物件內項目數（取最大者）
  const MV_ITEMS = [
    { obj: 'firewall.address', vd: p => (p.addresses || []).filter(a => a.category === 'address') },
    { obj: 'firewall.address6', vd: p => (p.addresses || []).filter(a => a.category === 'address6') },
    { obj: 'firewall.addrgrp', vd: p => (p.addresses || []).filter(a => a.category === 'address-group') },
    { obj: 'firewall.addrgrp6', vd: p => (p.addresses || []).filter(a => a.category === 'address-group6') },
    { obj: 'firewall.addrgrp:member', inst: p => (p.addresses || []).filter(a => a.category === 'address-group').map(g => ({ name: g.name, n: memList(g.members).length })) },
    { obj: 'firewall.policy', vd: p => (p.policies || []).filter(r => !r.platformRule && !r._implicit) },
    { obj: 'firewall.service.custom', vd: p => (p.services || []).filter(s => s.category === 'custom') },
    { obj: 'firewall.service.group', vd: p => (p.services || []).filter(s => s.category === 'group') },
    { obj: 'firewall.service.group:member', inst: p => (p.services || []).filter(s => s.category === 'group').map(g => ({ name: g.name, n: memList(g.members).length })) },
    { obj: 'firewall.vip', vd: p => (p.nat || []).filter(n => n.type === 'vip') },
    { obj: 'firewall.vipgrp', vd: p => (p.nat || []).filter(n => n.type === 'vipgrp') },
    { obj: 'firewall.ippool', vd: p => (p.nat || []).filter(n => n.type === 'ippool') },
    { obj: 'firewall.schedule.recurring', vd: p => (p.schedules || []).filter(s => s.type === 'recurring') },
    { obj: 'firewall.schedule.onetime', vd: p => (p.schedules || []).filter(s => s.type === 'onetime') },
    { obj: 'router.static', vd: p => (p.routes || []).filter(r => r.type === 'static' || r.type === 'default') },
    { obj: 'router.static6', vd: p => (p.routes || []).filter(r => r.type === 'static6') },
    { obj: 'system.interface', vd: p => p.interfaces || [] },
    { obj: 'system.zone', vd: p => (p._perVdom || []).flatMap(v => (v.zones || []).map(z => Object.assign({ _vdom: v.name }, z))) },
    { obj: 'system.admin', vd: p => (p.users || []).filter(u => u.type === 'admin') },
    { obj: 'user.local', vd: p => (p.users || []).filter(u => u.type === 'local'), key: true },
    { obj: 'user.group', vd: p => (p.users || []).filter(u => u.type === 'group') },
    { obj: 'user.group:member', inst: p => (p.users || []).filter(u => u.type === 'group').map(g => ({ name: g.name, n: memList(g.members).length })), key: true },
    { obj: 'user.ldap', vd: p => (p.users || []).filter(u => u.type === 'ldap-server') },
    { obj: 'user.radius', vd: p => (p.users || []).filter(u => u.type === 'radius-server') },
    { obj: 'vpn.ipsec.phase1-interface', vd: p => (p.vpn || []).filter(v => v.type === 'ipsec-p1') },
    { obj: 'vpn.ipsec.phase2-interface', vd: p => (p.vpn || []).flatMap(v => v.type === 'ipsec-p1' || v.type === 'ipsec-p2-orphan' ? (v.phase2 || []).map(x => Object.assign({ _vdom: v._vdom }, x)) : []) },
  ];
  const mvData = () => (typeof window !== 'undefined' && window.FG_MAX_VALUES) || null;
  const normCode = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  // 檔頭型號（FGT40F、FWF60F、FGR60F、FG40F3G4G、FGT60EPOE）或轉換型號（FG-40F）→ 官方表代碼（40F、WF60F、R60F、40F_3G4G、60E_POE）
  function mvModelCode(model, train) {
    const D = mvData(); if (!D) return null;
    const m = normCode(model).match(/^(FGT|FGR|FWF|FG)(\d.*)$/);
    if (!m || /^VM/.test(m[2])) return null;
    const want = (m[1] === 'FWF' ? 'WF' : m[1] === 'FGR' ? 'R' : '') + m[2];
    const t = D.trains[train]; if (!t) return null;
    const codes = Object.keys(t.models);
    const exact = codes.find(c => normCode(c) === want);
    if (exact) return { code: exact, exact: true };
    // 後綴（DSL、POE 等）官方表沒有時，以同系列基本型號近似
    const ms = modelSeries(model);
    const base = ms && codes.find(c => normCode(c) === (m[1] === 'FWF' ? 'WF' : m[1] === 'FGR' ? 'R' : '') + ms.series);
    return base ? { code: base, exact: false } : null;
  }
  // 選 train：與版本相同者；沒有就取最接近的較新 train（再沒有取最新）
  function mvTrain(version) {
    const D = mvData(); if (!D) return null;
    const keys = Object.keys(D.trains).sort((a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); return x[0] - y[0] || x[1] - y[1]; });
    const v = parseVer(version);
    if (!v) return { train: keys[keys.length - 1], exact: false };
    const want = v.nums[0] + '.' + v.nums[1];
    if (D.trains[want]) return { train: want, exact: true };
    const newer = keys.find(k => { const x = k.split('.').map(Number); return x[0] > v.nums[0] || (x[0] === v.nums[0] && x[1] > v.nums[1]); });
    return { train: newer || keys[keys.length - 1], exact: false };
  }
  // 計數：opts.singleVdom（轉換後全部放進 root）時不分 VDOM
  function mvCounts(parsed, opts) {
    const p = parsed || {}, single = !!(opts && opts.singleVdom);
    return MV_ITEMS.map(it => {
      if (it.inst) {
        const arr = it.inst(p);
        const top = arr.reduce((a, b) => (b.n > a.n ? b : a), { name: '', n: 0 });
        return { obj: it.obj, key: !!it.key, inst: top.n, instName: top.name, total: arr.length ? top.n : 0 };
      }
      const arr = it.vd(p), per = Object.create(null);
      arr.forEach(x => { const k = single ? 'root' : vdomOf(x); per[k] = (per[k] || 0) + 1; });
      let vmax = 0, vname = '';
      Object.keys(per).forEach(k => { if (per[k] > vmax) { vmax = per[k]; vname = k; } });
      return { obj: it.obj, key: !!it.key, total: arr.length, vdomMax: vmax, vdomName: vname };
    });
  }
  // parsed＋{model, version, singleVdom} → { supported, code, exact, train, trainExact, version, items:[{obj,key,count,limit,scope,where,ratio,level}] }
  // level：over（≥100%）、near（≥80%）、ok、nolimit（三層都是 0）、nodata（官方表沒有資料）
  function mvAssess(parsed, opts) {
    const o = opts || {}, D = mvData();
    if (!D) return { supported: false, reason: 'nodata' };
    const tr = mvTrain(o.version);
    const mc = mvModelCode(o.model, tr.train);
    if (!mc) return { supported: false, reason: 'model', model: o.model || '-' };
    const T = D.trains[tr.train], prof = T.profiles[T.models[mc.code]];
    const items = mvCounts(parsed, o).map(c => {
      const i = T.objects.indexOf(c.obj);
      if (i < 0) return Object.assign({}, c, { count: c.total, level: 'nodata' });
      const [li, lv, lg] = prof.slice(i * 3, i * 3 + 3);
      if (li === null && lv === null && lg === null) return Object.assign({}, c, { count: c.total, level: 'nodata' });
      const cands = [];
      if (c.inst !== undefined) { if (li) cands.push({ scope: 'instance', count: c.inst, limit: li, where: c.instName }); }
      else {
        if (lv) cands.push({ scope: 'vdom', count: c.vdomMax, limit: lv, where: c.vdomName });
        if (lg) cands.push({ scope: 'global', count: c.total, limit: lg, where: '' });
      }
      if (!cands.length) return Object.assign({}, c, { count: c.inst !== undefined ? c.inst : c.total, level: 'nolimit' });
      const worst = cands.reduce((a, b) => (b.count / b.limit > a.count / a.limit ? b : a));
      const ratio = worst.count / worst.limit;
      return Object.assign({ obj: c.obj, key: c.key }, worst, { ratio, level: ratio >= 1 ? 'over' : ratio >= MV_NEAR ? 'near' : 'ok' });
    });
    return { supported: true, code: mc.code, exact: mc.exact, train: tr.train, trainExact: tr.exact, version: T.version, asof: D.asof, src: D.src, items };
  }

  // ── Cisco ASA／FTD 型號上限（XN149）：VLAN 子介面數，依 cisco.com 設定指南的機型表（手工維護，每筆附出處）──
  //  asa：ASA 授權的 VLAN 上限（兩個值＝Base／Security Plus 授權）；ftd：Management Center 裝置設定指南的 VLAN 子介面上限
  const CISCO_SRC = {
    asaPak: 'https://www.cisco.com/c/en/us/td/docs/security/asa/asa912/configuration/general/asa-912-general-config/intro-license.html',
    asaSmart: 'https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/intro-license-smart.html',
    ftd: 'https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/720/management-center-device-config-72/interfaces-settings-ifcs-firewall.html',
  };
  const CISCO_FW_LIMITS = {
    'ASA5506-X': { asa: [5, 30] }, 'ASA5508-X': { asa: [50] }, 'ASA5512-X': { asa: [50, 100] }, 'ASA5515-X': { asa: [100] }, 'ASA5516-X': { asa: [150] },
    'ASA5525-X': { asa: [200] }, 'ASA5545-X': { asa: [300] }, 'ASA5555-X': { asa: [500] }, 'ASA5585-X': { asa: [1024] },
    FPR1010: { asa: [60], ftd: 60, switchPorts: true }, FPR1120: { asa: [1024], ftd: 512 }, FPR1140: { asa: [1024], ftd: 1024 }, FPR1150: { asa: [1024], ftd: 1024 },
    FPR2110: { asa: [1024], ftd: 1024 }, FPR2120: { asa: [1024], ftd: 1024 }, FPR2130: { asa: [1024], ftd: 1024 }, FPR2140: { asa: [1024], ftd: 1024 },
    FPR3110: { asa: [1024], ftd: 1024 }, FPR3120: { asa: [1024], ftd: 1024 }, FPR3140: { asa: [1024], ftd: 1024 },
  };
  // 型號字串（FW_MODELS id、show version 的 Hardware: ASA5516、FPR-1010 等）→ 表格鍵
  function ciscoModelKey(model) {
    const m = String(model || '').toUpperCase().replace(/[\s,]/g, '');
    let x = m.match(/^ASA-?(55\d\d)/); if (x) return 'ASA' + x[1] + '-X';
    x = m.match(/^(?:FPR|FIREPOWER)-?(\d{4})/); if (x) return 'FPR' + x[1];
    return null;
  }
  // 帶 VLAN 的介面（子介面）數：vlanId 有值或名稱為「介面.編號」
  function vlanIfCount(parsed) {
    return ((parsed && parsed.interfaces) || []).filter(i => (i.vlanId && i.vlanId !== '-') || /\.\d+$/.test(String(i.name || ''))).length;
  }
  // target：'ciscoasa'｜'ciscoftd'；回傳 { supported, key, kind, limit, base, count, level, needLicense, switchPorts, src }
  function ciscoAssess(parsed, opts) {
    const o = opts || {}, key = ciscoModelKey(o.model), row = key && CISCO_FW_LIMITS[key];
    if (!row) return { supported: false, model: o.model || '-' };
    const ftd = o.target === 'ciscoftd';
    const lim = ftd ? row.ftd : row.asa[row.asa.length - 1];
    if (!lim) return { supported: false, model: o.model || '-' };
    const base = !ftd && row.asa.length > 1 ? row.asa[0] : null;
    const count = vlanIfCount(parsed), r = count / lim;
    return { supported: true, key, kind: ftd ? 'ftd' : 'asa', limit: lim, base, count, level: r > 1 ? 'over' : r >= MV_NEAR ? 'near' : 'ok',
      needLicense: base !== null && count > base, switchPorts: !!(ftd && row.switchPorts), src: ftd ? CISCO_SRC.ftd : (/^ASA/.test(key) ? CISCO_SRC.asaPak : CISCO_SRC.asaSmart), asof: ASOF };
  }
  window.FwModelLimits = { LIMITS, ASOF, CISCO_FW_LIMITS, ciscoModelKey, ciscoAssess, RAM_CHECK_CMD, modelSeries, parseVer, relation, assess, MV_NEAR, mvModelCode, mvTrain, mvCounts, mvAssess };
})();
