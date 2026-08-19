// ════════════════════════════════════════════════════════════════════════
// firewall-analyzer-audit.js — 稽核／比對分析引擎（2026-08-17 從 firewall-analyzer-app.js
// 拆出）。涵蓋：規則遮蔽分析／未使用物件分析／合併建議／合規檢查／新舊設定檔結構化比對／
// 健康度評估，以及上述功能專用的 HTML 渲染 helper。此區塊在原檔案中皆為無巢狀、不依賴
// App 模組狀態變數（PARSED/ST/$ 等）的頂層函式，只靠參數與 tr()/esc()/pill()/tip()——
// tr()（i18n.js）／tip()（core.js）本來就是頂層宣告的全域函式；esc()/pill() 則比照本專案
// 既有慣例（firewall-analyzer-reporter.js／firewall-analyzer-converter.js 皆各自重複宣告
// 一份，非跨檔共用）在此另外宣告一份，故可安全獨立成檔案；
// `_jumpToPolicy()`（操作 DOM，需要留在觸發呼叫的 app.js 內）與 `onParsed()`/`renderSection()`
// （深度耦合 PARSED/ST，拆分無助於降低 merge 衝突機率）刻意不搬移，詳見 now.md 對應段落評估。
// ════════════════════════════════════════════════════════════════════════

  const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const pill=(t,c)=>`<span class="pill ${c}">${esc(t)}</span>`;

  // ── Audit Analysis ────────────────────────────────────────────
  // 共用比對邏輯：analyzeRuleShadowing()／buildShadowMap() 皆需要判斷「earlier 規則
  // 是否涵蓋 later 規則」，原本兩處各自定義一份逐字相同的 helper，抽到此處只定義一次
  // （2026-07-21 優化去重，行為完全不變）
  const _SHADOW_WILDCARD = new Set(['all','any','ALL','0.0.0.0/0','0.0.0.0 0.0.0.0']);
  function _shadowToSet(str) {
    if (!str || str === '-') return new Set();
    return new Set(str.split(/,\s*/).map(s => s.trim().toLowerCase()));
  }
  function _shadowIsWild(set) { return [...set].some(v => _SHADOW_WILDCARD.has(v)); }
  // 欄位涵蓋：earlier 是萬用字元，或與 later 完全相同
  function _shadowCovers(eSet, lSet) {
    return _shadowIsWild(eSet) || (eSet.size === lSet.size && [...eSet].every(v => lSet.has(v)));
  }
  // 介面涵蓋：支援多值介面（逗號分隔），earlier 需包含 later 的所有介面
  // 任一方為 '-'（未解析）→ 不阻擋比對
  function _shadowIntfCovers(eIntf, lIntf) {
    if (!eIntf || eIntf === '-' || !lIntf || lIntf === '-') return true;
    if (eIntf === 'any' || eIntf === 'all') return true;
    const eParts = new Set(eIntf.split(/,\s*/).map(s => s.trim().toLowerCase()));
    if (eParts.has('any') || eParts.has('all')) return true;
    return lIntf.split(/,\s*/).every(p => eParts.has(p.trim().toLowerCase()));
  }

  // ── 新舊設定檔結構化比對（單一設備）────────────────────────────
  // 通用 key-based 陣列比對：回傳新增/刪除/變更三類，changed 附上實際變更的欄位清單
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

  // Policy 主鍵是同 VDOM 內的 edit 序號，規則重排會漂移；先以 id 比對，
  // 再把「id 比對後落入 removed 且能在 added 中找到同名（同 VDOM）」的配對
  // 重新歸類為 changed（避免規則重排被誤判成刪除+新增）
  const _POLICY_COMPARE_FIELDS = ['name','srcIntf','dstIntf','srcAddr','dstAddr','service','schedule','action','nat','ippool','poolname','logtraffic','status','comments','users','groups'];
  function _flattenUtm(p) {
    const u = p.utm || {};
    return { ...p, 'utm.av': u.av, 'utm.webfilter': u.webfilter, 'utm.ips': u.ips, 'utm.appctrl': u.appctrl };
  }
  function diffPolicies(oldArr, newArr) {
    const keyFn = p => (p._vdom ? p._vdom + '/' : '') + p.id;
    const fields = [..._POLICY_COMPARE_FIELDS, 'utm.av', 'utm.webfilter', 'utm.ips', 'utm.appctrl'];
    const result = diffArrayByKey((oldArr || []).map(_flattenUtm), (newArr || []).map(_flattenUtm), keyFn, fields);
    const stillAdded = [];
    for (const a of result.added) {
      const match = a.name && result.removed.find(r => r.name === a.name && (r._vdom || null) === (a._vdom || null));
      if (match) {
        const diffFields = fields.filter(f => String(match[f] ?? '') !== String(a[f] ?? ''));
        if (!diffFields.includes('id')) diffFields.unshift('id');
        result.changed.push({ key: keyFn(a), old: match, new: a, diffFields });
        result.removed.splice(result.removed.indexOf(match), 1);
      } else stillAdded.push(a);
    }
    result.added = stillAdded;
    return result;
  }

  const _ADDRESS_COMPARE_FIELDS = ['type','subnet','fqdn','startIp','endIp','wildcard','iface','color','comment','members'];
  function diffAddresses(oldArr, newArr) {
    return diffArrayByKey(oldArr, newArr, a => (a._vdom ? a._vdom + '/' : '') + a.name, _ADDRESS_COMPARE_FIELDS);
  }

  const _SERVICE_COMPARE_FIELDS = ['proto','tcpPorts','udpPorts','icmpType','icmpCode','comment','color','members'];
  function diffServices(oldArr, newArr) {
    return diffArrayByKey(oldArr, newArr, s => (s._vdom ? s._vdom + '/' : '') + s.name, _SERVICE_COMPARE_FIELDS);
  }

  const _ROUTE_COMPARE_FIELDS = ['distance','priority','weight','comment','status','blackhole','vrf'];
  function diffRoutes(oldArr, newArr) {
    const keyFn = r => (r._vdom ? r._vdom + '/' : '') + r.dst + '|' + r.device + '|' + r.gateway;
    return diffArrayByKey(oldArr, newArr, keyFn, _ROUTE_COMPARE_FIELDS);
  }

  function diffConfigs(oldParsed, newParsed) {
    return {
      policies: diffPolicies(oldParsed.policies, newParsed.policies),
      addresses: diffAddresses(oldParsed.addresses, newParsed.addresses),
      services: diffServices(oldParsed.services, newParsed.services),
      routes: diffRoutes(oldParsed.routes, newParsed.routes),
    };
  }

  function analyzeRuleShadowing(policies) {
    const toSet = _shadowToSet, covers = _shadowCovers, intfCovers = _shadowIntfCovers;
    const results = [];
    const eq = (a, b) => a.size === b.size && [...a].every(v => b.has(v));
    const active = policies.filter(p => p.status !== 'disable');
    for (let i = 0; i < active.length; i++) {
      const later = active[i];
      const lSrc = toSet(later.srcAddr), lDst = toSet(later.dstAddr), lSvc = toSet(later.service);
      for (let j = 0; j < i; j++) {
        const earlier = active[j];
        if (earlier.action !== 'accept') continue;       // deny 規則不構成遮蔽
        if (earlier._vdom !== later._vdom) continue;     // 不同 VDOM 彼此獨立
        if (!intfCovers(earlier.srcIntf, later.srcIntf)) continue;
        if (!intfCovers(earlier.dstIntf, later.dstIntf)) continue;
        const eSrc = toSet(earlier.srcAddr), eDst = toSet(earlier.dstAddr), eSvc = toSet(earlier.service);
        if (!covers(eSrc, lSrc) || !covers(eDst, lDst) || !covers(eSvc, lSvc)) continue;
        // 判斷 tier：三欄位全相等 = 完全重複；否則為部分覆蓋
        const tier = (eq(eSrc,lSrc) && eq(eDst,lDst) && eq(eSvc,lSvc)) ? 1 : 2;
        const reason = tier === 1 ? 'audit.reason1_short' : 'audit.reason2_short';
        results.push({ shadowedId: later.id, shadowedName: later.name,
          shadowingId: earlier.id, shadowingName: earlier.name, tier, reason });
        break;
      }
    }
    return results;
  }

  function buildShadowMap(policies) {
    // 建立每個規則遮蔽的下游規則清單（用於流程排序顯示）
    const map = {};
    const toSet = _shadowToSet, covers = _shadowCovers, intfCovers = _shadowIntfCovers;
    const active = policies.filter(p => p.status !== 'disable');
    active.forEach(p => map[p.id] = []);
    for (let i = 0; i < active.length; i++) {
      const earlier = active[i];
      if (earlier.action !== 'accept') continue;
      const eSrc = toSet(earlier.srcAddr), eDst = toSet(earlier.dstAddr), eSvc = toSet(earlier.service);
      for (let j = i + 1; j < active.length; j++) {
        const later = active[j];
        if (earlier._vdom !== later._vdom) continue;
        if (!intfCovers(earlier.srcIntf, later.srcIntf)) continue;
        if (!intfCovers(earlier.dstIntf, later.dstIntf)) continue;
        const lSrc = toSet(later.srcAddr), lDst = toSet(later.dstAddr), lSvc = toSet(later.service);
        if (covers(eSrc, lSrc) && covers(eDst, lDst) && covers(eSvc, lSvc)) {
          map[earlier.id].push(later.id);
        }
      }
    }
    return map;
  }

  function analyzeUnusedObjects(parsed) {
    const BUILTINS = new Set([
      // 通用
      'all','any','ALL','none','NONE',
      // 預設地址物件
      'INTERNET','LAN_SUBNETS','SSLVPN_TUNNEL_ADDR1','SSLVPN_TUNNEL_ADDR1_IPV6',
      'FABRIC_DEVICE','FIREWALL_AUTH_PORTAL_ADDRESS',
      // 預設服務（FortiGate 出廠預設 + full-config 輸出常見）
      'PING','DNS','DNS-UDP','HTTP','HTTPS','SSH','FTP','SMTP','POP3','IMAP','IMAPS','SMTPS',
      'ALL_ICMP','ALL_ICMP6','ALL_TCP','ALL_UDP',
      'BGP','RIP','OSPF','NTP','SNMP','SNMP-TRAP',
      'TELNET','RDP','VNC','SMB','NetBIOS-DS','NetBIOS-NS','NetBIOS-SS',
      'LDAP','LDAPS','RADIUS','KERBEROS','KERBEROS-UDP',
      'SIP','H323','MGCP','SCCP',
      'IKE','PPTP','L2TP','GRE',
      'DHCP','TFTP','NFS','RSYNC','SAMBA',
      'IRC','QUAKE','PC-Anywhere-Data','Squid',
      'TRACEROUTE','SYSLOG','WCCP',
    ]);
    // type 為系統自動管理，不需出現在 policy 中即算「已使用」
    const AUTO_TYPES = new Set(['interface-subnet','dynamic','wildcard-fqdn','geography']);

    const usedAddr = new Set(), usedSvc = new Set();
    function addRefs(str, target) {
      if (!str || str === '-') return;
      str.split(/[,"\s]+/).forEach(n => { const t = n.trim(); if (t) target.add(t); });
    }

    // 1. Firewall policies
    for (const p of (parsed.policies || [])) {
      addRefs(p.srcAddr, usedAddr); addRefs(p.dstAddr, usedAddr); addRefs(p.service, usedSvc);
    }
    // 2. NAT：VIP/ippool 名稱、vipgrp members
    for (const n of (parsed.nat || [])) {
      usedAddr.add(n.name); // VIP/ippool 本身名稱（policy dstAddr 會直接引用）
      if (n.members) addRefs(n.members, usedAddr); // vipgrp members
    }
    // 3. SSL-VPN source-address / tunnel-ip-pools；SSL Portal ip-pools / split-tunneling-routing-address
    for (const v of (parsed.vpn || [])) {
      if (v.type === 'ssl-vpn') {
        addRefs(v.addr,   usedAddr);
        addRefs(v.ipPool, usedAddr);
        addRefs(v.splitTunnelRoutingAddr, usedAddr);
      }
      if (v.type === 'ssl-portal') {
        addRefs(v.ipPool, usedAddr);
        addRefs(v.splitTunnelRoutingAddr, usedAddr);
      }
    }
    // 4. 有 associated-interface 的地址物件：屬於介面子網（WiFi SSID / VLAN），系統隱式使用
    for (const a of (parsed.addresses || [])) {
      if (a.iface && a.iface !== '-') usedAddr.add(a.name);
    }

    // 展開 address/service groups（迭代直到穩定）
    let changed = true;
    while (changed) {
      changed = false;
      for (const a of (parsed.addresses || [])) {
        if (a.members && usedAddr.has(a.name)) {
          a.members.split(/,\s*/).forEach(m => { const t = m.trim(); if (t && !usedAddr.has(t)) { usedAddr.add(t); changed = true; } });
        }
      }
      for (const s of (parsed.services || [])) {
        if (s.members && usedSvc.has(s.name)) {
          s.members.split(/,\s*/).forEach(m => { const t = m.trim(); if (t && !usedSvc.has(t)) { usedSvc.add(t); changed = true; } });
        }
      }
    }

    const unusedAddrs = (parsed.addresses || []).filter(a =>
      !BUILTINS.has(a.name) &&
      !AUTO_TYPES.has(a.type) &&
      !usedAddr.has(a.name)
    );
    const unusedSvcs = (parsed.services || []).filter(s =>
      !BUILTINS.has(s.name) &&
      !usedSvc.has(s.name)
    );
    return { unusedAddrs, unusedSvcs };
  }

  // 相鄰規則合併建議：偵測「相鄰（consecutive，中間不能夾其他規則）」且除了
  // srcAddr/dstAddr/service 三者之一外，其餘關鍵欄位（action/介面/schedule/nat/
  // logtraffic/VDOM）皆完全相同的規則群組，建議合併為一條（差異欄位改用群組涵蓋多值）。
  // 若差異欄位任一方已是萬用字元（any/all 等），代表其中一條已完全涵蓋另一條，
  // 屬於 analyzeRuleShadowing() 的偵測範圍，本分析刻意排除避免重複提示。
  const _MERGE_FIELDS = ['srcAddr', 'dstAddr', 'service'];
  const _MERGE_SAME_KEYS = ['action', 'srcIntf', 'dstIntf', 'logtraffic', 'schedule', 'nat'];
  function analyzeMergeSuggestions(policies) {
    const isWild = v => _SHADOW_WILDCARD.has((v || '').trim().toLowerCase());
    const results = [];
    const active = (policies || []).filter(p => p.status !== 'disable');
    let i = 0;
    while (i < active.length) {
      const base = active[i];
      let diffField = null;
      const group = [base];
      let j = i + 1;
      while (j < active.length) {
        const cand = active[j];
        if (base._vdom !== cand._vdom) break;
        if (_MERGE_SAME_KEYS.some(k => (base[k] || '-') !== (cand[k] || '-'))) break;
        const diffs = _MERGE_FIELDS.filter(f => (base[f] || '-') !== (cand[f] || '-'));
        if (diffs.length !== 1) break;
        const f = diffs[0];
        if (diffField === null) {
          if (isWild(base[f]) || isWild(cand[f])) break;
          diffField = f;
        } else if (diffField !== f || isWild(cand[f])) break;
        group.push(cand);
        j++;
      }
      if (group.length >= 2) {
        results.push({
          field: diffField,
          ids: group.map(p => p.id),
          names: group.map(p => p.name),
          values: [...new Set(group.map(p => p[diffField]))],
          count: group.length,
        });
      }
      i = (j > i + 1) ? j : i + 1;
    }
    return results;
  }

  function analyzeCompliance(parsed) {
    const findings = [];
    // standards：僅供參考的常見資安標準關聯條號（業界廣泛公開引用的控制編號與主題，
    // 非逐字引用付費標準內容），純資訊性標籤，不代表通過此工具檢查即符合該標準認證。
    // PCI-DSS 4.0 條號已對照 PCI Security Standards Council 官方公開文件逐條查證（2026-07-22）；
    // ISO27001 條號已改為 2022 版 Annex A 編號（2022 版將 2013 版 114 條重整為 93 條，
    // 舊版 A.9/A.10/A.12/A.13 等編號已作廢），依 ISMS.online／High Table／Voragosecurity
    // 等公開次級來源交叉核對官方 2013→2022 對照表（2026-07-22，非直接核對付費原文，
    // 部分條號查證信心為中高非完全確定，詳見 now.md 對應段落）；
    // NIST 800-53/CIS v8 沿用既有引用（CIS v8 已於 2026-07-21 查證）。
    const f = (id, check, value, risk, detail, standards) => findings.push({ id, check, value, risk, detail, standards: standards||[] });
    const policies = parsed.policies || [];
    // 多 VDOM 時以 VDOM/ID 顯示，避免各 VDOM 重複的 ID 混淆
    const isMultiVdom = policies.some(p => p._vdom !== undefined && p._vdom !== null);
    const idLabel = p => (isMultiVdom && p._vdom) ? `${p._vdom}/${p.id}` : p.id;
    // 1. any-to-any 允許規則
    const anyAny = policies.filter(p => p.action === 'accept' && p.status !== 'disable' &&
      /\b(all|any)\b/i.test(p.srcAddr||'') && /\b(all|any)\b/i.test(p.dstAddr||'') && /\b(all|any|ALL)\b/i.test(p.service||''));
    f('any-any', tr('audit.check_any_any'), anyAny.length, 'high',
      anyAny.length ? tr('audit.id_prefix') + anyAny.map(p => idLabel(p)).slice(0,10).join(', ') + (anyAny.length > 10 ? '…' : '') : tr('audit.none'),
      ['ISO27001 A.8.20', 'PCI-DSS 4.0 1.3.1/1.3.2', 'NIST 800-53 SC-7', 'CIS v8 12.2']);
    // 2. 停用規則數量
    const disabled = policies.filter(p => p.status === 'disable');
    f('disabled-pol', tr('audit.check_disabled'), disabled.length, 'medium',
      disabled.length ? `${disabled.length}` + tr('audit.rec_disabled') : tr('audit.none'),
      ['ISO27001 A.8.9', 'PCI-DSS 4.0 1.2.7', 'NIST 800-53 CM-7', 'CIS v8 4.1']);
    // 3. 無日誌的允許規則
    const noLog = policies.filter(p => p.action === 'accept' && p.status !== 'disable' &&
      (!p.logtraffic || p.logtraffic === 'disable' || p.logtraffic === 'utm'));
    f('no-log', tr('audit.check_no_log'), noLog.length, 'medium',
      noLog.length ? `${noLog.length}` + tr('audit.rec_log') : tr('audit.all_logged'),
      ['ISO27001 A.8.15', 'PCI-DSS 4.0 10.2.1', 'NIST 800-53 AU-2', 'CIS v8 8.2']);
    // 4. SNMP v1/v2c
    const snmp = parsed.snmp;
    const hasV1v2 = snmp && snmp.communities && snmp.communities.length > 0;
    f('snmp-v1v2', tr('audit.check_snmp'), hasV1v2 ? snmp.communities.length : 0, 'high',
      hasV1v2 ? `Community: ${snmp.communities.length}` + tr('audit.rec_snmpv3') : tr('audit.none'),
      ['ISO27001 A.8.24', 'PCI-DSS 4.0 2.2.6', 'NIST 800-53 IA-5', 'CIS v8 4.8']);
    // 5. 管理員未啟用 2FA（2026-08-19 擴大涵蓋 type==='local' 但實際等同管理員權限的帳號：
    // CiscoASA 用單數 role 欄位、CheckPoint 用 roles/accessLevel、PaloAlto mgt-config users
    // 節點本身無角色欄位但本質即管理員帳號、Sophos accessLevel 可能是 admin/super-admin。
    // 刻意不用一律 type==='local' 的粗暴寫法——會誤觸 FortiGate SSL-VPN/portal 一般使用者
    // （accessLevel 固定 'user'）與 Sophos 一般權限使用者）
    const isPrivileged = u => u.status !== 'disable' && (
      u.type === 'admin' ||
      u.role === 'admin' ||
      (Array.isArray(u.roles) && u.roles.includes('admin')) ||
      u.accessLevel === 'admin' || u.accessLevel === 'super-admin' ||
      (u.type === 'local' && parsed.vendor === 'PaloAlto')
    );
    const admins = (parsed.users || []).filter(isPrivileged);
    const no2fa  = admins.filter(u => !u.twoFactor || u.twoFactor === 'disable');
    f('no-2fa', tr('audit.check_no_2fa'), no2fa.length, 'high',
      no2fa.length ? no2fa.map(u => u.name).slice(0,8).join(', ') + (no2fa.length > 8 ? '…' : '') : tr('audit.all_2fa'),
      ['ISO27001 A.8.5', 'PCI-DSS 4.0 8.4.1', 'NIST 800-53 IA-2(1)', 'CIS v8 6.5']);
    // 6. 外部介面允許 HTTP/Telnet
    const dangerAcc = ['http','telnet'];
    const riskyIntf = (parsed.interfaces || []).filter(i => {
      const acc = (i.allowaccess || '').toLowerCase();
      const isExt = i.role === 'WAN' || (i.name || '').toLowerCase().match(/^(wan|ext|outside|untrust)/);
      return isExt && dangerAcc.some(d => acc.includes(d));
    });
    f('http-mgmt', tr('audit.check_http_mgmt'), riskyIntf.length, 'high',
      riskyIntf.length ? riskyIntf.map(i => `${i.name}(${i.allowaccess})`).join(', ') : tr('audit.normal'),
      ['ISO27001 A.5.15', 'PCI-DSS 4.0 2.2.7', 'NIST 800-53 AC-17', 'CIS v8 12.3']);
    // 7. VPN 弱加密
    const WEAK = /\b(des\b|3des|md5|rc4|null)/i;
    const weakVpn = (parsed.vpn || []).filter(v => WEAK.test((v.proposal || '') + ' ' + (v.dhgrp || '')));
    f('weak-vpn', tr('audit.check_weak_vpn'), weakVpn.length, 'high',
      weakVpn.length ? weakVpn.map(v => v.name).slice(0,6).join(', ') : tr('audit.normal'),
      ['ISO27001 A.8.24', 'PCI-DSS 4.0 4.2.1', 'NIST 800-53 SC-13', 'CIS v8 3.10']);
    // 8. VPN Phase2 未啟用 PFS（新增：PCI-DSS 4.0 逐條擴充，Req 4.2.1 強加密延伸至完美前向保密）
    const noPfs = [];
    (parsed.vpn || []).forEach(v => {
      const legs = (v.phase2 && v.phase2.length) ? v.phase2 : [v];
      legs.forEach(p2 => {
        if (p2.pfs !== undefined && p2.pfs !== 'enable') noPfs.push(v.name + (p2.name && p2.name !== v.name ? '/' + p2.name : ''));
      });
    });
    f('vpn-no-pfs', tr('audit.check_vpn_no_pfs'), noPfs.length, 'medium',
      noPfs.length ? noPfs.slice(0,8).join(', ') + (noPfs.length > 8 ? '…' : '') : tr('audit.normal'),
      ['ISO27001 A.8.24', 'PCI-DSS 4.0 4.2.1']);
    // 9. 預設/通用管理員帳號名稱仍啟用（新增：PCI-DSS 4.0 逐條擴充，Req 2.2.2 預設帳號／8.2.2 共用帳號禁用）
    const DEFAULT_NAMES = /^(admin|administrator|root|guest|test|demo)$/i;
    const defaultAdmins = (parsed.users || []).filter(u =>
      (u.type === 'admin' || u.type === 'local') && u.status !== 'disable' && DEFAULT_NAMES.test((u.name || '').trim()));
    f('default-admin-name', tr('audit.check_default_admin'), defaultAdmins.length, 'medium',
      defaultAdmins.length ? defaultAdmins.map(u => u.name).slice(0,8).join(', ') + (defaultAdmins.length > 8 ? '…' : '') : tr('audit.none'),
      ['ISO27001 A.5.16', 'PCI-DSS 4.0 2.2.2/8.2.2']);
    // 10. SNMPv3 認證/加密強度不足（僅涵蓋有實際解析出 v3users 的 6 家：FortiGate/Juniper/PaloAlto/
    // Sophos/CheckPoint/MikroTik；CiscoASA/pfSense/SonicWall 固定空陣列、EdgeRouter/OpenWrt/Zyxel
    // 無 snmp 物件，皆非本檢查涵蓋範圍，非「查無弱設定」）
    const v3users = (snmp && snmp.v3users) || [];
    const WEAK_AUTH = ['md5'], WEAK_PRIV = ['des'];
    const weakV3 = v3users.filter(u =>
      (u.secLevel && u.secLevel !== 'auth-priv') ||
      (u.authProto && WEAK_AUTH.includes(String(u.authProto).toLowerCase())) ||
      (u.privProto && WEAK_PRIV.includes(String(u.privProto).toLowerCase())));
    f('snmpv3-weak', tr('audit.check_snmpv3_weak'), weakV3.length, weakV3.length ? 'medium' : 'low',
      weakV3.length ? weakV3.map(u => u.name).slice(0,8).join(', ') + (weakV3.length > 8 ? '…' : '') + tr('audit.rec_snmpv3_strong') : tr('audit.none'),
      ['NIST 800-53 IA-5', 'CIS v8 4.8']);
    return findings;
  }

  function buildZoneMatrixHtml(policies) {
    const pols=(policies||[]).filter(p=>p.srcIntf&&p.srcIntf!=='-'&&p.dstIntf&&p.dstIntf!=='-');
    if(!pols.length) return '';
    const zones=[...new Set([...pols.map(p=>p.srcIntf),...pols.map(p=>p.dstIntf)])].sort();
    if(zones.length>20) return '';
    const mx={};
    zones.forEach(z=>{mx[z]={};zones.forEach(d=>{mx[z][d]={a:0,n:0};});});
    pols.forEach(p=>{const s=p.srcIntf,d=p.dstIntf;if(mx[s]&&mx[s][d]!==undefined){if(p.action==='accept')mx[s][d].a++;else mx[s][d].n++;}});
    let h=`<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--teal);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">${tr('audit.zone_matrix')}</div>`;
    h+=`<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th style="font-size:10px">${tr('audit.zone_src')} \\ ${tr('audit.zone_dst')}</th>`;
    zones.forEach(d=>{h+=`<th style="text-align:center;font-size:10px;white-space:nowrap">${esc(d)}</th>`;});
    h+='</tr></thead><tbody>';
    zones.forEach(s=>{
      h+=`<tr><td style="font-weight:600;color:var(--accent);font-size:11px;white-space:nowrap">${esc(s)}</td>`;
      zones.forEach(d=>{
        const c=mx[s][d];
        if(!c||(!c.a&&!c.n)){h+=`<td style="text-align:center;color:var(--text-muted)">—</td>`;return;}
        const bg=c.a&&c.n?'var(--yellow)':c.a?'var(--green)':'var(--red)';
        h+=`<td style="text-align:center"><span title="${c.a} ${tr('audit.zone_allow')} / ${c.n} ${tr('audit.zone_deny')}" style="display:inline-block;min-width:28px;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:600;background:${bg}20;color:${bg}">${c.a+c.n}</span></td>`;
      });
      h+='</tr>';
    });
    h+='</tbody></table></div>';
    h+=`<div style="margin-top:6px;font-size:11px;color:var(--text-dim)"><span style="color:var(--green)">■</span> ${tr('audit.zone_allow')} &nbsp;<span style="color:var(--red)">■</span> ${tr('audit.zone_deny')} &nbsp;<span style="color:var(--yellow)">■</span> ${tr('audit.zone_mixed')}</div></div>`;
    return h;
  }

  // Zone 拓樸圖：重用 buildZoneMatrixHtml() 既有的 zone 推導與 mx[src][dst] accept/deny 計數，
  // 佈局套用既有 BGP peer 拓樸（case 'routes' 內的極座標圓周佈局）手法，多對多邊的畫法比照
  // switch_analyzer renderMultiTopo() 的去重概念（i<j 只畫一次，雙向流量合併計數）
  function buildZoneTopoHtml(policies) {
    const pols=(policies||[]).filter(p=>p.srcIntf&&p.srcIntf!=='-'&&p.dstIntf&&p.dstIntf!=='-');
    if(!pols.length) return '';
    const zones=[...new Set([...pols.map(p=>p.srcIntf),...pols.map(p=>p.dstIntf)])].sort();
    if(zones.length>20) return '';
    const mx={};
    zones.forEach(z=>{mx[z]={};zones.forEach(d=>{mx[z][d]={a:0,n:0};});});
    pols.forEach(p=>{const s=p.srcIntf,d=p.dstIntf;if(mx[s]&&mx[s][d]!==undefined){if(p.action==='accept')mx[s][d].a++;else mx[s][d].n++;}});
    const cnt=zones.length;
    const CX=380,CY=200,R=Math.min(160,60+cnt*18),nr=32,W=760,H=400;
    const pos=zones.map((_,i)=>{const a=(2*Math.PI*i/cnt)-Math.PI/2;return{x:CX+R*Math.cos(a),y:CY+R*Math.sin(a)};});
    let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" style="width:100%;max-height:400px"><defs><filter id="fwzt"><feGaussianBlur stdDeviation="2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
    for(let i=0;i<cnt;i++){
      for(let j=i+1;j<cnt;j++){
        const s=zones[i],dd=zones[j];
        const fwd=mx[s][dd],bwd=mx[dd][s];
        const a=fwd.a+bwd.a,n=fwd.n+bwd.n;
        if(!a&&!n) continue;
        const col=a&&n?'var(--yellow)':a?'var(--green)':'var(--red)';
        const p1=pos[i],p2=pos[j];
        const dx=p2.x-p1.x,dy=p2.y-p1.y,dist=Math.sqrt(dx*dx+dy*dy)||1;
        svg+=`<line x1="${p1.x+dx/dist*nr}" y1="${p1.y+dy/dist*nr}" x2="${p2.x-dx/dist*nr}" y2="${p2.y-dy/dist*nr}" stroke="${col}" stroke-width="1.5" stroke-opacity="0.6"/>`;
        svg+=`<text x="${(p1.x+p2.x)/2}" y="${(p1.y+p2.y)/2}" text-anchor="middle" font-size="9" fill="${col}" opacity="0.85">${a+n}</text>`;
      }
    }
    pos.forEach((p,i)=>{
      svg+=`<circle cx="${p.x}" cy="${p.y}" r="${nr}" fill="var(--surface2)" stroke="var(--accent)" stroke-width="1.5" filter="url(#fwzt)"/>`;
      svg+=`<text x="${p.x}" y="${p.y+4}" text-anchor="middle" font-size="9" font-weight="600" fill="var(--text)">${esc(zones[i])}</text>`;
    });
    svg+='</svg>';
    return `<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--teal);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">${tr('audit.zone_matrix')}</div>`
      +`<div style="background:var(--surface2);border-radius:6px;padding:8px">${svg}</div>`
      +`<div style="margin-top:6px;font-size:11px;color:var(--text-dim)"><span style="color:var(--green)">■</span> ${tr('audit.zone_allow')} &nbsp;<span style="color:var(--red)">■</span> ${tr('audit.zone_deny')} &nbsp;<span style="color:var(--yellow)">■</span> ${tr('audit.zone_mixed')}</div></div>`;
  }

  function buildShadowHtml(results) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--red);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + tip('tip.shadow', tr('audit.shadow_title')) + '</div>';
    if (!results.length) {
      h += '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('audit.shadow_none')) + '</div></div>';
      return h;
    }
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('audit.col_tier') + '</th><th>' + tr('audit.col_shadowed_id') + '</th><th>' + tr('audit.col_shadowed_name') + '</th><th>' + tr('audit.col_shadow_id') + '</th><th>' + tr('audit.col_shadow_name') + '</th><th>' + tr('audit.col_reason') + '</th></tr></thead><tbody>';
    results.forEach(r => {
      const tp = r.tier === 1 ? pill(tr('audit.tier1_label'),'p-deny') : pill(tr('audit.tier2_label'),'p-warn');
      const jh = tr('audit.jump_hint');
      const reasonTip = r.tier === 1
        ? tr('audit.reason_t1a') + esc(r.shadowingId) + tr('audit.reason_t1b')
        : tr('audit.reason_t2a') + esc(r.shadowingId) + tr('audit.reason_t2b');
      h += `<tr><td>${tp}</td><td class="mono"><span class="clickable-cell" style="color:var(--red)" onclick="window._jumpToPolicy('${esc(r.shadowedId)}')" title="${esc(jh)}">${esc(r.shadowedId)}</span></td><td>${esc(r.shadowedName||'-')}</td><td class="mono"><span class="clickable-cell" onclick="window._jumpToPolicy('${esc(r.shadowingId)}')" title="${esc(jh)}">${esc(r.shadowingId)}</span></td><td>${esc(r.shadowingName||'-')}</td><td style="color:var(--text-dim);font-size:11px"><span data-tip="${reasonTip.replace(/"/g,'&quot;')}">${esc(tr(r.reason))}<sup style="font-size:8px;opacity:.45;margin-left:2px;cursor:help">ⓘ</sup></span></td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  }

  const _MERGE_FIELD_LABEL = { srcAddr: 'col.src_addr', dstAddr: 'col.dst_addr', service: 'col.service' };
  function buildMergeHtml(results) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--teal);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + tip('tip.merge', tr('audit.merge_title')) + '</div>';
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:10px;padding:6px 10px;background:var(--bg2);border-radius:4px;border-left:3px solid var(--teal)">' + esc(tr('audit.merge_warn')) + '</div>';
    if (!results.length) {
      h += '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('audit.merge_none')) + '</div></div>';
      return h;
    }
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('audit.col_merge_field') + '</th><th>' + tr('audit.col_merge_ids') + '</th><th>' + tr('audit.col_merge_values') + '</th><th>' + tr('audit.col_merge_count') + '</th></tr></thead><tbody>';
    results.forEach(r => {
      const jh = tr('audit.jump_hint');
      const idCells = r.ids.map(id => `<span class="clickable-cell" onclick="window._jumpToPolicy('${esc(id)}')" title="${esc(jh)}" style="margin-right:6px">${esc(id)}</span>`).join('');
      h += `<tr><td>${pill(tr(_MERGE_FIELD_LABEL[r.field]), 'p-info')}</td><td class="mono">${idCells}</td><td style="font-size:11px">${esc(r.values.join(', '))}</td><td class="mono">${r.count}</td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  }

  function buildUnusedHtml({ unusedAddrs, unusedSvcs }) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--yellow);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + tip('tip.unused_obj', tr('audit.unused_title')) + '</div>';
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:10px;padding:6px 10px;background:var(--bg2);border-radius:4px;border-left:3px solid var(--yellow)">' + esc(tr('audit.unused_warn')) + '</div>';
    if (!unusedAddrs.length) {
      h += '<div style="font-size:12px;color:var(--green);padding:4px 0 8px">' + esc(tr('audit.unused_addr_none')) + '</div>';
    } else {
      h += `<div style="font-size:11px;color:var(--text-dim);margin-bottom:6px">${esc(tr('audit.unused_addr_header'))}（${unusedAddrs.length}）</div><div style="overflow-x:auto;margin-bottom:14px"><table class="data-tbl"><thead><tr><th>${tr('audit.col_name')}</th><th>${tr('audit.col_category')}</th><th>${tr('audit.col_type')}</th><th>${tr('audit.col_subnet')}</th></tr></thead><tbody>`;
      unusedAddrs.forEach(a => {
        h += `<tr><td class="mono" style="color:var(--accent)">${esc(a.name)}</td><td>${pill(a.category||'address','p-info')}</td><td style="color:var(--text-dim)">${esc(a.type||'-')}</td><td class="mono" style="color:var(--text-dim)">${esc(a.subnet||a.fqdn||'-')}</td></tr>`;
      });
      h += '</tbody></table></div>';
    }
    if (!unusedSvcs.length) {
      h += '<div style="font-size:12px;color:var(--green);padding:4px 0">' + esc(tr('audit.unused_svc_none')) + '</div>';
    } else {
      h += `<div style="font-size:11px;color:var(--text-dim);margin-bottom:6px">${esc(tr('audit.unused_svc_header'))}（${unusedSvcs.length}）</div><div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>${tr('audit.col_name')}</th><th>${tr('audit.col_category')}</th><th>${tr('audit.col_proto')}</th><th>${tr('audit.col_port')}</th></tr></thead><tbody>`;
      unusedSvcs.forEach(s => {
        h += `<tr><td class="mono" style="color:var(--accent)">${esc(s.name)}</td><td>${pill(s.category||'service','p-info')}</td><td style="color:var(--text-dim)">${esc(s.proto||'-')}</td><td class="mono" style="color:var(--text-dim)">${esc(s.tcpPorts||s.udpPorts||'-')}</td></tr>`;
      });
      h += '</tbody></table></div>';
    }
    h += '</div>';
    return h;
  }

  function buildComplianceHtml(findings) {
    const rp = r => r === 'high' ? pill(tr('audit.risk_high'),'p-deny') : r === 'medium' ? pill(tr('audit.risk_mid'),'p-warn') : pill(tr('audit.risk_low'),'p-allow');
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--purple);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + tip('tip.compliance', tr('audit.compliance_title')) + '</div>';
    h += `<div style="color:var(--text-dim);font-size:11px;margin-bottom:8px">${esc(tr('audit.standards_disclaimer'))}</div>`;
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('audit.col_check') + '</th><th>' + tr('audit.col_result') + '</th><th>' + tr('audit.col_risk') + '</th><th>' + tr('audit.col_detail') + '</th><th>' + tr('audit.col_standards') + '</th></tr></thead><tbody>';
    findings.forEach(f => {
      const ok = f.value === 0;
      const vc = (!ok && f.risk !== 'low') ? 'var(--red)' : 'var(--green)';
      const stdBadges = (f.standards||[]).map(s => `<span style="display:inline-block;margin:1px 3px 1px 0;padding:1px 6px;border-radius:3px;font-size:10px;background:var(--surface2);color:var(--text-dim);border:1px solid var(--border)">${esc(s)}</span>`).join('');
      h += `<tr><td>${esc(f.check)}</td><td class="mono" style="color:${vc};font-weight:600">${esc(String(f.value))}</td><td>${rp(f.risk)}</td><td style="color:var(--text-dim);font-size:11px">${esc(f.detail)}</td><td style="font-size:11px;white-space:normal;min-width:220px">${stdBadges || '-'}</td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  }

  // ── 新舊設定檔比對結果渲染 ─────────────────────────────────────
  function _diffItemLabel(item) {
    if (item.name) return item.name;
    if (item.dst !== undefined) return `${item.dst} → ${item.gateway || '-'} (${item.device || '-'})`;
    return item.id !== undefined ? String(item.id) : '-';
  }
  function _buildDiffSection(titleKey, result) {
    const total = result.added.length + result.removed.length + result.changed.length;
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--teal);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + esc(tr(titleKey)) + '</div>';
    if (!total) {
      h += '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('diff.none_found')) + '</div></div>';
      return h;
    }
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('diff.col_status') + '</th><th>' + tr('diff.col_key') + '</th><th>' + tr('diff.col_changed_fields') + '</th></tr></thead><tbody>';
    result.added.forEach(item => {
      h += `<tr><td>${pill(tr('diff.status_added'), 'p-allow')}</td><td class="mono" style="font-size:11px">${esc(_diffItemLabel(item))}</td><td>-</td></tr>`;
    });
    result.removed.forEach(item => {
      h += `<tr><td>${pill(tr('diff.status_removed'), 'p-deny')}</td><td class="mono" style="font-size:11px">${esc(_diffItemLabel(item))}</td><td>-</td></tr>`;
    });
    result.changed.forEach(c => {
      h += `<tr><td>${pill(tr('diff.status_changed'), 'p-warn')}</td><td class="mono" style="font-size:11px">${esc(_diffItemLabel(c.new))}</td><td style="font-size:11px;color:var(--text-dim)">${esc(c.diffFields.join(', '))}</td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  }
  function buildDiffHtml(diffResult) {
    const bar = `<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
      <button class="btn btn-ghost btn-sm" onclick="doExport('csv-diff-policies')">⬇ CSV: ${esc(tr('diff.title_policies'))}</button>
      <button class="btn btn-ghost btn-sm" onclick="doExport('csv-diff-addresses')">⬇ CSV: ${esc(tr('diff.title_addresses'))}</button>
      <button class="btn btn-ghost btn-sm" onclick="doExport('csv-diff-services')">⬇ CSV: ${esc(tr('diff.title_services'))}</button>
      <button class="btn btn-ghost btn-sm" onclick="doExport('csv-diff-routes')">⬇ CSV: ${esc(tr('diff.title_routes'))}</button>
    </div>`;
    return bar
      + _buildDiffSection('diff.title_policies', diffResult.policies)
      + _buildDiffSection('diff.title_addresses', diffResult.addresses)
      + _buildDiffSection('diff.title_services', diffResult.services)
      + _buildDiffSection('diff.title_routes', diffResult.routes);
  }

  // ── 健康度評估 ─────────────────────────────────────────────────
  function computeFirewallHealth(parsed) {
    const policies = parsed.policies || [];
    let score = 100;
    const issues = [];
    // T1: any-any accept
    const anyAny = policies.filter(p => p.action === 'accept' && /^(all|any)$/i.test((p.srcAddr||'').trim()) && /^(all|any)$/i.test((p.dstAddr||'').trim()));
    if (anyAny.length) { score -= anyAny.length * 20; issues.push({sev:'crit', label:tr('health.any_any'), count:anyAny.length}); }
    // T2: shadowed rules
    const shadowMap = buildShadowMap(policies);
    const shadowCount = Object.values(shadowMap).reduce((s, arr) => s + arr.length, 0);
    if (shadowCount) { score -= shadowCount * 5; issues.push({sev:'warn', label:tr('health.shadowed'), count:shadowCount}); }
    // T3: disabled rules（欄位值一律是 'disable'，非 'disabled'，見 _runPolicyQuery()/各 assemble 函式既有慣例）
    const disabled = policies.filter(p => p.status === 'disable' || p.enabled === false || p.enabled === 'disable');
    if (disabled.length > 3) { score -= (disabled.length - 3) * 2; issues.push({sev:'info', label:tr('health.disabled'), count:disabled.length}); }
    // T4: accept without log（欄位名稱是全小寫 logtraffic，非 logTraffic；判斷式比照 analyzeCompliance() 既有慣例）
    const noLog = policies.filter(p => p.action === 'accept' && (!p.logtraffic || p.logtraffic === 'disable' || p.logtraffic === 'utm'));
    if (noLog.length > 2) { score -= (noLog.length - 2) * 3; issues.push({sev:'warn', label:tr('health.no_log'), count:noLog.length}); }
    score = Math.max(0, Math.min(100, score));
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
    const gradeColor = grade === 'A' ? 'var(--green)' : grade === 'B' ? 'var(--teal)' : grade === 'C' ? 'var(--yellow)' : grade === 'D' ? 'var(--orange)' : 'var(--red)';
    return {score, grade, gradeColor, issues};
  }
