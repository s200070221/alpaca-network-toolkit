// ═══════════════════════════════════════════════════════════════════════════
// switch-generator-model-limits.js — 交換器型號上限（XN149）：Cisco Catalyst 各系列規格表「規模」表格的數值
// 手工維護，每個系列附 cisco.com 規格表網址；只收表格內明列的數值，沒有的欄位不填（不推算）。
// 產生器 validateForm() 依所選型號比對表單內容（VLAN 數、SVI、STP 實例、ACL 項目、聚合埠），超過或接近時提示。
// 以 window.SwModelLimits 對外
// ═══════════════════════════════════════════════════════════════════════════
(function () {
  const ASOF = '2026-11-14';
  const NEAR = 0.8;
  const DS = {
    c1000: 'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-1000-series-switches/nb-06-cat1k-ser-switch-ds-cte-en.html',
    c1300: 'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-1300-series-switches/nb-06-cat1300-ser-data-sheet-cte-en.html',
    c2960x: 'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-x-series-switches/data_sheet_c78-728232.html',
    c3650: 'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3650-series-switches/data_sheet_c78-729449.html',
    c3850: 'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3850-series-switches/data_sheet_c78-720918.html',
    c9200: 'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html',
    c9300: 'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html',
    c9350: 'https://www.cisco.com/site/us/en/products/collateral/networking/switches/c9350-series-smart-switches/c9350-series-smart-switches-ds.html',
  };
  // 欄位：activeVlans（同時啟用 VLAN）、pvst（PVST 實例）、mst（MST 實例）、stp（STP 實例，不分模式）、svis、ipIfs（IP 介面）、
  // acl（安全 ACL 項目）、lagGroups（聚合埠組數）、lagMembers（每組成員）。re 比對正規化後的型號（例：C9200L-24P-4G）
  const FAMILIES = [
    { id: 'c1000', name: 'Catalyst 1000', re: /^C1000(FE)?-/, src: DS.c1000, activeVlans: 256, stp: 64, acl: 600 },
    { id: 'c1300x', name: 'Catalyst 1300X', re: /^C1300X-/, src: DS.c1300, pvst: 126, mst: 16, ipIfs: 256, acl: 3072, lagGroups: 8, lagMembers: 8 },
    { id: 'c1300-10g', name: 'Catalyst 1300（10G 機型）', re: /^C1300-(\d+X|.*-\d+X$)/, src: DS.c1300, pvst: 126, mst: 16, ipIfs: 256, acl: 2048, lagGroups: 8, lagMembers: 8 },
    { id: 'c1300', name: 'Catalyst 1300（1G 機型）', re: /^C1300-/, src: DS.c1300, pvst: 126, mst: 16, ipIfs: 128, acl: 1024, lagGroups: 8, lagMembers: 8 },
    { id: 'c2960xr', name: 'Catalyst 2960-XR IP Lite', re: /^C2960XR-/, src: DS.c2960x, activeVlans: 1023 },
    { id: 'c2960x-lanlite', name: 'Catalyst 2960-X LAN Lite', re: /^C2960X-.*-S$/, src: DS.c2960x, activeVlans: 64 },
    { id: 'c2960x', name: 'Catalyst 2960-X LAN Base', re: /^C2960X-/, src: DS.c2960x, activeVlans: 1023 },
    { id: 'c3650', name: 'Catalyst 3650', re: /^C3650-/, src: DS.c3650, svis: 1000 },
    { id: 'c3850', name: 'Catalyst 3850', re: /^C3850-/, src: DS.c3850, svis: 1000 },
    { id: 'c9200cx', name: 'Catalyst 9200CX', re: /^C9200CX-/, src: DS.c9200, pvst: 128, svis: 512, acl: 1600 },
    { id: 'c9200l', name: 'Catalyst 9200L', re: /^C9200L-/, src: DS.c9200, pvst: 128, svis: 512, acl: 1500 },
    { id: 'c9200', name: 'Catalyst 9200', re: /^C9200-/, src: DS.c9200, pvst: 128, svis: 512, acl: 1600 },
    { id: 'c9300x', name: 'Catalyst 9300X', re: /^C9300X-/, src: DS.c9300, pvst: 300, svis: 1000, acl: 8000 },
    { id: 'c9300l', name: 'Catalyst 9300L／LM', re: /^C9300LM?-/, src: DS.c9300, pvst: 300, svis: 1000, acl: 5120 },
    { id: 'c9300b', name: 'Catalyst 9300 高規格（B 機型）', re: /^C9300-\w+B$/, src: DS.c9300, pvst: 300, svis: 1000, acl: 18000 },
    { id: 'c9300', name: 'Catalyst 9300', re: /^C9300-/, src: DS.c9300, pvst: 300, svis: 1000, acl: 5120 },
    { id: 'c9350', name: 'Catalyst 9350', re: /^C9350-/, src: DS.c9350, activeVlans: 4000, svis: 4000, acl: 5000 },
  ];
  // 型號值（NetBox nb:SKU）或顯示名稱 → 正規化型號（C9200L-24P-4G）
  function normModel(value, label) {
    const v = String(value || '');
    let s = v.startsWith('nb:') ? v.slice(3) : String(label || v);
    s = s.toUpperCase().trim().replace(/^CATALYST\s+C?/, 'C').replace(/^WS-C/, 'C').split(/\s/)[0];
    return s;
  }
  function familyOf(value, label) {
    const m = normModel(value, label);
    return FAMILIES.find(f => f.re.test(m)) || null;
  }
  // model：產生器 collectModel() 的結果（vlans、lacp、acl、stp）
  function assess(value, label, model) {
    const f = familyOf(value, label);
    if (!f) return null;
    const m = model || {};
    const vlans = new Set((m.vlans || []).map(v => String(v.id)).filter(Boolean));
    const svis = (m.vlans || []).filter(v => v.ip && String(v.ip).trim()).length;
    const mode = String((m.stp && m.stp.mode) || '').toLowerCase();
    const mst = /mst/.test(mode), insts = ((m.stp && m.stp.instances) || []).length;
    const aclRules = (m.acl || []).reduce((n, a) => n + ((a.rules || []).length), 0);
    const lags = m.lacp || [], maxMem = lags.reduce((n, l) => Math.max(n, (l.members || []).length), 0);
    const items = [];
    const add = (key, count, limit) => { if (limit && count) { const r = count / limit; items.push({ key, count, limit, level: r > 1 ? 'over' : r >= NEAR ? 'near' : 'ok' }); } };
    add('vlans', vlans.size, f.activeVlans);
    add('svis', svis, f.svis || f.ipIfs);
    // Cisco 沒寫 STP 模式時預設 PVST 系列：每個 VLAN 一個實例；MST 比實例數
    if (mst) add('mst', insts, f.mst || f.stp); else add('pvst', vlans.size, f.pvst || f.stp);
    add('acl', aclRules, f.acl);
    add('lagGroups', lags.length, f.lagGroups);
    add('lagMembers', maxMem, f.lagMembers);
    return { family: f.id, name: f.name, src: f.src, model: normModel(value, label), items, asof: ASOF };
  }
  // 測試沙箱可能沒有 window（gen_test／qa round-trip 直接載入全部產生器模組）
  (typeof window !== 'undefined' ? window : globalThis).SwModelLimits = { ASOF, NEAR, FAMILIES, normModel, familyOf, assess };
})();
