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
  window.FwModelLimits = { LIMITS, ASOF, RAM_CHECK_CMD, modelSeries, parseVer, relation, assess };
})();
