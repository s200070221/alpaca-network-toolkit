// ============================================================
// switch_analyzer：結構化/廠牌感知設定比對（2026-08-26 新增）
// ============================================================
// 純函式，零 DOM／parsed／ST 全域依賴（比照 firewall-analyzer-audit.js 2026-08-17 拆分
// 先例）——switch-analyzer-app.js 本身頂層有多處立即執行的 DOM 綁定，純函式若寫進該檔會導致
// Node 測試沙箱一讀取整檔就因 document is not defined 拋錯。
//
// 動機：既有 performDiff()/computeDiff() 是純文字逐行 LCS 比對，兩份功能相同但區塊順序不同
// （典型案例：ACL 規則重排）的設定檔會顯示大量無意義的新增/刪除雜訊。本檔案提供以 parseAny()
// 解析後的結構化模型為基礎的比對，用 key 比對取代位置比對，天生不受陣列順序影響。

// diffArrayByKey — 逐字搬自 firewall-analyzer-audit.js（通用 Map 比對，vendor/domain 無關）
function diffArrayByKey(oldArr, newArr, keyFn, compareFields) {
  const oldMap = new Map((oldArr || []).map(o => [keyFn(o), o]));
  const newMap = new Map((newArr || []).map(n => [keyFn(n), n]));
  const added = [...newMap.keys()].filter(k => !oldMap.has(k)).map(k => newMap.get(k));
  const removed = [...oldMap.keys()].filter(k => !newMap.has(k)).map(k => oldMap.get(k));
  const changed = [];
  for (const [k, oldItem] of oldMap) {
    if (!newMap.has(k)) continue;
    const newItem = newMap.get(k);
    const diffFields = compareFields.filter(f => String(oldItem[f] ?? '') !== String(newItem[f] ?? ''));
    if (diffFields.length) changed.push({ key: k, old: oldItem, new: newItem, diffFields });
  }
  return { added, removed, changed };
}

// 巢狀資料（ACL rules、OSPF areas/networks、BGP peers 等）的通用比對外殼：先用 diffArrayByKey
// 比對外層純量欄位，attachFn(record) 對「外層已判定 changed」的項目掛上巢狀 diff 結果；接著
// 額外掃一遍「外層欄位完全沒變」但兩邊都存在的項目——若其巢狀內容其實有差異（如規則單純重排
// 但成員不變, key 比對後 added/removed/changed 皆為空, 但這正是我們要偵測的情境；反之若巢狀
// 內容真的有變, 外層卻因為只比較純量欄位而遺漏, hasNestedFn 用來補上這類項目), 用空 diffFields
// 補上一筆 changed 記錄, 讓使用者仍能展開看到巢狀內容, 但不會被誤判成「外層欄位變了」。
function _diffWithNested(oldArr, newArr, keyFn, outerFields, attachFn, hasNestedFn) {
  const outer = diffArrayByKey(oldArr, newArr, keyFn, outerFields);
  outer.changed.forEach(attachFn);
  const oldMap = new Map((oldArr || []).map(o => [keyFn(o), o]));
  const newMap = new Map((newArr || []).map(n => [keyFn(n), n]));
  for (const [k, oldItem] of oldMap) {
    const newItem = newMap.get(k);
    if (!newItem || outer.changed.find(c => c.key === k)) continue;
    const rec = { key: k, old: oldItem, new: newItem, diffFields: [] };
    attachFn(rec);
    if (hasNestedFn(rec)) outer.changed.push(rec);
  }
  return outer;
}
const _hasAny = (...results) => results.some(r => r && (r.added.length || r.removed.length || r.changed.length));

// ACL：兩層 key 比對。外層排除 rules/appliedOn（走巢狀 diff，避免規則重排被扁平字串比較
// 誤判成「整條 ACL 變了」）；rules 以語意內容（action+protocol+src+dst+dstPort）為 key，
// seq/remark 視為非識別性中繼資料，compareFields 刻意留空、完全不影響「規則是否相同」的判定。
function diffACLs(oldArr, newArr) {
  const aclKey = a => `${a.name}|${a.aclType}|${a.ipVersion}`;
  const ruleKey = r => `${r.action}|${r.protocol}|${r.src}|${r.dst}|${r.dstPort}`;
  const attach = c => {
    c.ruleDiff = diffArrayByKey(c.old.rules, c.new.rules, ruleKey, []);
    c.appliedOnDiff = diffArrayByKey(c.old.appliedOn, c.new.appliedOn, a => `${a.interface}|${a.direction}`, []);
  };
  const hasNested = c => _hasAny(c.ruleDiff, c.appliedOnDiff);
  return _diffWithNested(oldArr, newArr, aclKey, ['type', 'vendor'], attach, hasNested);
}

// OSPF：三層巢狀（pid → area → network），area 層與 pid 層皆需各自的巢狀重排偵測
function _diffOSPFAreas(oldAreas, newAreas) {
  const attach = ac => { ac.networkDiff = diffArrayByKey(ac.old.networks, ac.new.networks, n => `${n.network}|${n.wildcard}`, []); };
  const hasNested = ac => _hasAny(ac.networkDiff);
  return _diffWithNested(oldAreas, newAreas, a => a.area, ['type', 'noSummary'], attach, hasNested);
}
function diffOSPF(oldArr, newArr) {
  const attach = c => {
    c.areaDiff = _diffOSPFAreas(c.old.areas, c.new.areas);
    c.redistributeDiff = diffArrayByKey(c.old.redistributes, c.new.redistributes, r => r, []);
  };
  const hasNested = c => _hasAny(c.areaDiff, c.redistributeDiff);
  return _diffWithNested(oldArr, newArr, o => o.pid, ['routerId'], attach, hasNested);
}

// BGP：兩層巢狀（asn → peer），networks/networks6 為 flat CIDR 字串陣列
function diffBGP(oldArr, newArr) {
  const attach = c => {
    c.peerDiff = diffArrayByKey(c.old.peers, c.new.peers, p => p.ip, ['as', 'desc', 'type']);
    c.networkDiff = diffArrayByKey(c.old.networks, c.new.networks, n => n, []);
    c.network6Diff = diffArrayByKey(c.old.networks6, c.new.networks6, n => n, []);
  };
  const hasNested = c => _hasAny(c.peerDiff, c.networkDiff, c.network6Diff);
  return _diffWithNested(oldArr, newArr, b => b.asn, ['routerId'], attach, hasNested);
}

// RIP：process 物件清單（同 OSPF/BGP 慣例，非扁平網段清單），key=pid，巢狀 networks
function diffRIP(oldArr, newArr) {
  const attach = c => { c.networkDiff = diffArrayByKey(c.old.networks, c.new.networks, n => n, []); };
  const hasNested = c => _hasAny(c.networkDiff);
  return _diffWithNested(oldArr, newArr, r => r.pid, ['vrf', 'version', 'autoSummary', 'timers'], attach, hasNested);
}

// STP：單一巢狀物件（非清單），欄位逐一比對 + 兩個內部陣列各自 diffArrayByKey
function diffSTP(oldStp, newStp) {
  const o = oldStp || {}, n = newStp || {};
  const fieldDiff = ['mode', 'rootMode'].filter(f => String(o[f] ?? '') !== String(n[f] ?? ''));
  return {
    fieldDiff, old: o, new: n,
    instances: diffArrayByKey(o.instances, n.instances, i => i.id, ['vlan', 'priority']),
    ports: diffArrayByKey(o.ports, n.ports, p => p.port, ['portfast', 'bpduguard', 'guardRoot', 'cost', 'priority']),
  };
}

// computeStructuredDiff — 頂層編排，對 parseAny() 回傳模型逐欄位套用對應 diff
function computeStructuredDiff(oldParsed, newParsed) {
  return {
    vlans: diffArrayByKey(oldParsed.vlans, newParsed.vlans, v => v.id, ['name', 'ipSubnets']),
    interfaces: diffArrayByKey(oldParsed.interfaces, newParsed.interfaces, i => i.name,
      ['desc', 'ip', 'ip6', 'secondaryIps', 'mode', 'vlans', 'nativeVlan', 'vrf', 'shutdown']),
    acls: diffACLs(oldParsed.acls, newParsed.acls),
    ospf: diffOSPF(oldParsed.ospf, newParsed.ospf),
    bgp: diffBGP(oldParsed.bgp, newParsed.bgp),
    routes: diffArrayByKey(oldParsed.routes, newParsed.routes, r => `${r.dst}|${r.gw}`, ['vrf', 'gwIsInterface']),
    rip: diffRIP(oldParsed.rip, newParsed.rip),
    vrrp: diffArrayByKey(oldParsed.vrrp, newParsed.vrrp, v => `${v.interface}|${v.vrid}`,
      ['vip', 'vip6', 'priority', 'preempt', 'authMode', 'trackIf']),
    stp: diffSTP(oldParsed.stp, newParsed.stp),
  };
}
