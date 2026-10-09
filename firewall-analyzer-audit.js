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

  const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const pill=(t,c)=>`<span class="pill ${c}">${esc(t)}</span>`;

  // ── Audit Analysis ────────────────────────────────────────────
  // 共用比對邏輯：analyzeRuleShadowing()／buildShadowMap() 皆需要判斷「earlier 規則
  // 是否涵蓋 later 規則」，原本兩處各自定義一份逐字相同的 helper，抽到此處只定義一次
  // （2026-07-21 優化去重，行為完全不變）
  const _SHADOW_WILDCARD = new Set(['all','any','ALL','0.0.0.0/0','0.0.0.0 0.0.0.0']);
  // 規則停用狀態判斷（2026-09-18 根因性修復）：部分廠牌 parser（如 Sophos）未正規化的原始值
  // 會是大寫開頭的 'Disable'，逐處各自寫 p.status!=='disable' 這種精確小寫比對會漏判。原本
  // 只有 analyzeCompliance() 內部定義了一份大小寫不敏感版本（區域變數，其餘函式各自看不到），
  // 導致 analyzeRuleShadowing()/buildShadowMap()/analyzeDenyBlocking()/analyzeMergeSuggestions()/
  // computeFirewallHealth() T3 仍是純小寫比對（漏判大寫來源）；提升為本檔案頂層共用 helper，
  // 全部改呼叫這一份，避免未來新增判斷式時重蹈覆轍
  const _isDisabledStatus = p => /^disable$/i.test(p.status || '');
  function _shadowToSet(str) {
    if (!str || str === '-') return new Set();
    return new Set(str.split(/,\s*/).map(s => s.trim().toLowerCase()));
  }
  function _shadowIsWild(set) { return [...set].some(v => _SHADOW_WILDCARD.has(v)); }
  // 每條規則的 src/dst/service 集合只算一次（2026-09-29 QE）：原本兩兩比對的內層迴圈每次都
  // 重新切字串建集合，3000 條規則約重算 450 萬次、耗時約 4.5 秒；比對邏輯本身不變
  // 介面欄位預先整理：null＝未解析（'-' 或空白，不阻擋比對）、'any'＝萬用、否則為小寫介面集合
  // （多值介面以逗號分隔，earlier 需包含 later 的所有介面）
  function _shadowIntfPrep(v) {
    if (!v || v === '-') return null;
    const parts = new Set(v.split(/,\s*/).map(x => x.trim().toLowerCase()));
    return (v === 'any' || v === 'all' || parts.has('any') || parts.has('all')) ? 'any' : parts;
  }
  // 位址欄位展開成範圍（2026-10-01，第九輪發想 YB）：物件（ipmask／ipprefix／iprange／群組遞迴）與字面位址
  // （IP、CIDR、IP＋點分遮罩、範圍、IPv6 前綴、host X、MikroTik @清單）轉成 {f:4|6, lo, hi}（BigInt），
  // 任一成員無法確定範圍（FQDN、介面型物件、! 反向、找不到的名稱）即回傳 null，該欄位退回原本的字串比對
  const _V4_FULL = { f: 4, lo: 0n, hi: 0xFFFFFFFFn }, _V6_FULL = { f: 6, lo: 0n, hi: (1n << 128n) - 1n };
  function _rangeOfLiteral(t) {
    const a = t.replace(/^host\s+/i, '').trim();
    let m = a.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (m) { const lo = _strictIpInt(m[1]), hi = _strictIpInt(m[2]); return lo === null || hi === null || lo > hi ? null : { f: 4, lo: BigInt(lo), hi: BigInt(hi) }; }
    m = a.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\s*\/\s*(\d{1,2})|\s+(\d{1,3}(?:\.\d{1,3}){3}))?$/);
    if (m) {
      const ip = _strictIpInt(m[1]); if (ip === null) return null;
      const bits = m[2] !== undefined ? +m[2] : (m[3] !== undefined ? _cidrPrefixLen(m[3]) : 32);
      if (bits === null || bits > 32) return null;
      const size = 1n << BigInt(32 - bits), lo = (BigInt(ip) / size) * size;
      return { f: 4, lo, hi: lo + size - 1n };
    }
    m = a.match(/^([0-9a-f:]+)(?:\/(\d{1,3}))?$/i);
    if (m && a.includes(':')) {
      const base = _ipv6ToBig(m[1]), bits = m[2] !== undefined ? +m[2] : 128;
      if (base === null || bits > 128) return null;
      const size = 1n << BigInt(128 - bits), lo = (base / size) * size;
      return { f: 6, lo, hi: lo + size - 1n };
    }
    return null;
  }
  function _rangesOfName(name, addrs, vdom, seen) {
    const raw = name.trim(), nm = raw.toLowerCase();
    if (nm === 'all' || nm === 'any' || nm === '0.0.0.0/0' || nm === '0.0.0.0 0.0.0.0') return [_V4_FULL, _V6_FULL];
    if (nm === 'any4') return [_V4_FULL];
    if (nm === 'any6') return [_V6_FULL];
    if (seen.has(nm)) return [];
    seen.add(nm);
    const obj = addrs.find(a => a.name && a.name.toLowerCase() === nm && (!vdom || !a._vdom || a._vdom === vdom)) || addrs.find(a => a.name && a.name.toLowerCase() === nm);
    if (obj) {
      if ((obj.type === 'ipmask' || obj.type === 'ipprefix') && obj.subnet && obj.subnet !== '-') { const r = _rangeOfLiteral(obj.subnet); return r ? [r] : null; }
      if (obj.type === 'iprange') { const r = _rangeOfLiteral(`${obj.startIp}-${obj.endIp}`) || _rangeOfLiteral(obj.startIp); return r ? [r] : null; }
      if (obj.type === 'group' || obj.category === 'address-group') {
        const out = [];
        for (const mem of String(obj.members || '').split(',').map(x => x.trim()).filter(x => x && x !== '-')) {
          const r = _rangesOfName(mem, addrs, vdom, seen); if (!r) return null; out.push(...r);
        }
        return out;
      }
      return null;
    }
    if (raw.startsWith('@')) return _rangesOfName(raw.slice(1), addrs, vdom, seen);
    const r = _rangeOfLiteral(raw);
    return r ? [r] : null;
  }
  function _shadowAddrRanges(str, addrs, vdom) {
    if (!addrs) return null;
    const toks = String(str || '').split(/,\s*/).map(x => x.trim()).filter(x => x && x !== '-');
    if (!toks.length) return null;
    const out = [];
    for (const t of toks) { const r = _rangesOfName(t, addrs, vdom, new Set()); if (!r) return null; out.push(...r); }
    // 同家族相鄰／重疊範圍合併，涵蓋判斷只需比對單一合併後區間
    const merged = [];
    out.sort((x, y) => (x.f - y.f) || (x.lo < y.lo ? -1 : x.lo > y.lo ? 1 : 0)).forEach(r => {
      const last = merged[merged.length - 1];
      if (last && last.f === r.f && r.lo <= last.hi + 1n) { if (r.hi > last.hi) last.hi = r.hi; }
      else merged.push({ f: r.f, lo: r.lo, hi: r.hi });
    });
    return merged;
  }
  const _rangesCover = (E, L) => !!(E && L && L.length && L.every(l => E.some(e => e.f === l.f && e.lo <= l.lo && l.hi <= e.hi)));
  // addresses（選填）：提供時位址欄位另以範圍包含判斷涵蓋；未提供時維持原本只比對字串相同或 any
  function _shadowPrep(active, addresses) {
    return active.map(p => {
      const src = _shadowToSet(p.srcAddr), dst = _shadowToSet(p.dstAddr), svc = _shadowToSet(p.service);
      return { src, dst, svc, srcW: _shadowIsWild(src), dstW: _shadowIsWild(dst), svcW: _shadowIsWild(svc),
        si: _shadowIntfPrep(p.srcIntf), di: _shadowIntfPrep(p.dstIntf),
        srcR: _shadowAddrRanges(p.srcAddr, addresses, p._vdom), dstR: _shadowAddrRanges(p.dstAddr, addresses, p._vdom) };
    });
  }
  // 以預先整理的資料判斷 e（較早規則）是否涵蓋 l（較晚規則）：介面涵蓋，且 src/dst/service
  // 各欄位 earlier 為萬用字元、與 later 完全相同，或（位址欄位）earlier 的範圍包含 later 的範圍
  function _shadowPrepCovers(e, l) {
    const intfOk = (ei, li) => ei === null || li === null || ei === 'any' || (li !== 'any' && [...li].every(x => ei.has(x)));
    const fieldOk = (eS, eW, lS, eR, lR) => eW || (eS.size === lS.size && [...eS].every(v => lS.has(v))) || _rangesCover(eR, lR);
    return intfOk(e.si, l.si) && intfOk(e.di, l.di) && fieldOk(e.src, e.srcW, l.src, e.srcR, l.srcR) && fieldOk(e.dst, e.dstW, l.dst, e.dstR, l.dstR) && fieldOk(e.svc, e.svcW, l.svc);
  }

  // ── 新舊設定檔結構化比對（單一設備）────────────────────────────
  // 通用 key-based 陣列比對：回傳新增/刪除/變更三類，changed 附上實際變更的欄位清單
  // excludeFields（選填，2026-09-01 新增，功能4 HA 降噪模式用）：從 compareFields 中排除
  // 指定欄位再比對，不影響 added/removed 判斷（僅影響 changed 的欄位差異偵測）
  function diffArrayByKey(oldArr, newArr, keyFn, compareFields, excludeFields) {
    const fields = excludeFields && excludeFields.length ? compareFields.filter(f => !excludeFields.includes(f)) : compareFields;
    const oldMap = new Map((oldArr || []).map(o => [keyFn(o), o]));
    const newMap = new Map((newArr || []).map(n => [keyFn(n), n]));
    const added = [...newMap.keys()].filter(k => !oldMap.has(k)).map(k => newMap.get(k));
    const removed = [...oldMap.keys()].filter(k => !newMap.has(k)).map(k => oldMap.get(k));
    const changed = [];
    for (const [k, oldItem] of oldMap) {
      if (!newMap.has(k)) continue;
      const newItem = newMap.get(k);
      const diffFields = fields.filter(f => String(oldItem[f] ?? '') !== String(newItem[f] ?? ''));
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
  function diffPolicies(oldArr, newArr, excludeFields) {
    const keyFn = p => (p._vdom ? p._vdom + '/' : '') + p.id;
    const allFields = [..._POLICY_COMPARE_FIELDS, 'utm.av', 'utm.webfilter', 'utm.ips', 'utm.appctrl'];
    const fields = excludeFields && excludeFields.length ? allFields.filter(f => !excludeFields.includes(f)) : allFields;
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
  function diffAddresses(oldArr, newArr, excludeFields) {
    return diffArrayByKey(oldArr, newArr, a => (a._vdom ? a._vdom + '/' : '') + a.name, _ADDRESS_COMPARE_FIELDS, excludeFields);
  }

  const _SERVICE_COMPARE_FIELDS = ['proto','tcpPorts','udpPorts','icmpType','icmpCode','comment','color','members'];
  function diffServices(oldArr, newArr, excludeFields) {
    return diffArrayByKey(oldArr, newArr, s => (s._vdom ? s._vdom + '/' : '') + s.name, _SERVICE_COMPARE_FIELDS, excludeFields);
  }

  const _ROUTE_COMPARE_FIELDS = ['distance','priority','weight','comment','status','blackhole','vrf'];
  function diffRoutes(oldArr, newArr, excludeFields) {
    const keyFn = r => (r._vdom ? r._vdom + '/' : '') + r.dst + '|' + r.device + '|' + r.gateway;
    return diffArrayByKey(oldArr, newArr, keyFn, _ROUTE_COMPARE_FIELDS, excludeFields);
  }

  // NAT 比對（2026-09-01 新增，功能4：HA 主備比對＋功能5 相關擴充）：欄位依 FortiGate
  // VIP/ippool 既有 parseNAT() 回傳形狀（其餘 vendor 若未輸出對應欄位則該欄位恆為
  // undefined，diffArrayByKey 的 String(undefined??'')==='' 兩邊相等不會誤判為變更）。
  // key 用 (vdom/)type/name 避免同名不同 type（如 vip 與 ippool 剛好同名）互相覆蓋。
  const _NAT_COMPARE_FIELDS = ['vipType','poolType','extIp','extIntf','mapIp','portFwd','extPort','mapPort','proto','startIp','endIp','status','comment','members'];
  function diffNAT(oldArr, newArr, excludeFields) {
    const keyFn = n => (n._vdom ? n._vdom + '/' : '') + n.type + '/' + n.name;
    return diffArrayByKey(oldArr, newArr, keyFn, _NAT_COMPARE_FIELDS, excludeFields);
  }

  // VPN／Interfaces 比對（2026-09-21 新增）：與上面 4 類同構的薄包裝，key 沿用既有 _vdom
  // 前綴慣例（Palo Alto 等多 vsys 廠牌對 interfaces 物件也會標記 _vdom）
  const _VPN_COMPARE_FIELDS = ['remote','iface','ikeVer','authMethod','proposal','dhgrp','lifetime','natTraversal','dpd','status'];
  function diffVpn(oldArr, newArr, excludeFields) {
    return diffArrayByKey(oldArr, newArr, v => (v._vdom ? v._vdom + '/' : '') + v.name, _VPN_COMPARE_FIELDS, excludeFields);
  }
  const _INTERFACE_COMPARE_FIELDS = ['ip','mask','ip6','type','vlanId','vdom','role','mtu','speed','mode','status','allowaccess','desc'];
  function diffInterfaces(oldArr, newArr, excludeFields) {
    return diffArrayByKey(oldArr, newArr, i => (i._vdom ? i._vdom + '/' : '') + i.name, _INTERFACE_COMPARE_FIELDS, excludeFields);
  }

  // haMode（2026-09-01 新增，功能4）：HA 主備正常應完全同步，此模式僅排除常見的裝置別
  // 註記（comment/comments）欄位差異，其餘欄位若仍有差異即代表兩台設定不同步——刻意只做
  // 這一個範圍明確、低風險的過濾，不臆測其他「裝置專屬」欄位有哪些
  const _HA_MODE_EXCLUDE_FIELDS = ['comment', 'comments'];
  function diffConfigs(oldParsed, newParsed, opts) {
    const excludeFields = opts && opts.haMode ? _HA_MODE_EXCLUDE_FIELDS : undefined;
    return {
      policies: diffPolicies(oldParsed.policies, newParsed.policies, excludeFields),
      addresses: diffAddresses(oldParsed.addresses, newParsed.addresses, excludeFields),
      services: diffServices(oldParsed.services, newParsed.services, excludeFields),
      routes: diffRoutes(oldParsed.routes, newParsed.routes, excludeFields),
      nat: diffNAT(oldParsed.nat, newParsed.nat, excludeFields),
      vpn: diffVpn(oldParsed.vpn, newParsed.vpn, excludeFields),
      interfaces: diffInterfaces(oldParsed.interfaces, newParsed.interfaces, excludeFields),
    };
  }

  function analyzeRuleShadowing(policies, addresses) {
    const results = [];
    const eq = (a, b) => a.size === b.size && [...a].every(v => b.has(v));
    const active = policies.filter(p => !_isDisabledStatus(p));
    const prep = _shadowPrep(active, addresses);
    for (let i = 0; i < active.length; i++) {
      const later = active[i];
      const { src: lSrc, dst: lDst, svc: lSvc } = prep[i];
      for (let j = 0; j < i; j++) {
        const earlier = active[j];
        if (earlier.action !== 'accept') continue;       // deny 規則不構成遮蔽
        if (earlier._vdom !== later._vdom) continue;     // 不同 VDOM 彼此獨立
        if (!_shadowPrepCovers(prep[j], prep[i])) continue;
        const { src: eSrc, dst: eDst, svc: eSvc } = prep[j];
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

  function buildShadowMap(policies, addresses) {
    // 建立每個規則遮蔽的下游規則清單（用於流程排序顯示）
    const map = {};
    const active = policies.filter(p => !_isDisabledStatus(p));
    const prep = _shadowPrep(active, addresses);
    active.forEach(p => map[p.id] = []);
    for (let i = 0; i < active.length; i++) {
      const earlier = active[i];
      if (earlier.action !== 'accept') continue;
      for (let j = i + 1; j < active.length; j++) {
        const later = active[j];
        if (earlier._vdom !== later._vdom) continue;
        if (_shadowPrepCovers(prep[i], prep[j])) {
          map[earlier.id].push(later.id);
        }
      }
    }
    return map;
  }

  // 較早的 deny 規則擋住較晚的 accept 規則：與 analyzeRuleShadowing()（較早 accept 遮蔽較晚 accept，
  // 屬於「規則冗餘可精簡」）是不同性質的問題——這裡是「規則被擋住形同虛設」，對安全稽核更關鍵
  // （使用者可能誤以為某條 accept 規則生效，實際上流量早被更前面的 deny 攔截）。獨立成一個函式，
  // 不與 analyzeRuleShadowing 合併，避免混淆兩種問題的語意與後續建議動作。全專案 12 家廠牌的
  // policies 正規化模型 action 欄位只有二元值 accept/deny（見 firewall-analyzer-parser-fortigate.js
  // 的 `gv(t,'action')||'deny'` 預設值慣例），不需處理 vendor 專屬的 drop/reject 同義詞。
  function analyzeDenyBlocking(policies, addresses) {
    const results = [];
    const active = policies.filter(p => !_isDisabledStatus(p));
    const prep = _shadowPrep(active, addresses);
    for (let i = 0; i < active.length; i++) {
      const later = active[i];
      if (later.action !== 'accept') continue;   // 只關心「本該生效的 accept 規則」被擋住的情境
      for (let j = 0; j < i; j++) {
        const earlier = active[j];
        if (earlier.action !== 'deny') continue;
        if (earlier._vdom !== later._vdom) continue;
        if (!_shadowPrepCovers(prep[j], prep[i])) continue;
        results.push({ blockedId: later.id, blockedName: later.name,
          blockingId: earlier.id, blockingName: earlier.name });
        break;
      }
    }
    return results;
  }

  // 跨廠牌都存在的通用萬用字元關鍵字，非任何特定廠牌命名，任何廠牌 fallback 皆套用
  const _COMMON_BUILTINS = ['all', 'any', 'ALL', 'none', 'NONE'];
  // parsed.vendor（各 parser 回傳的頂層 vendor 字串，如 'FortiGate'/'Cisco ASA'）→ 該廠牌出廠
  // 預設/內建位址、服務物件名稱清單。查無官方文件佐證的廠牌不列在此 Map，analyzeUnusedObjects()
  // 會 fallback 使用 _COMMON_BUILTINS，避免臆測名稱造成誤判「已使用」而漏掉真正未使用物件。
  const VENDOR_BUILTINS = new Map([
    // FortiGate 出廠預設地址/服務物件（既有清單，2026-08-25 前即已驗證，原樣保留）
    ['FortiGate', [
      ..._COMMON_BUILTINS,
      'INTERNET', 'LAN_SUBNETS', 'SSLVPN_TUNNEL_ADDR1', 'SSLVPN_TUNNEL_ADDR1_IPV6',
      'FABRIC_DEVICE', 'FIREWALL_AUTH_PORTAL_ADDRESS',
      'PING', 'DNS', 'DNS-UDP', 'HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP', 'POP3', 'IMAP', 'IMAPS', 'SMTPS',
      'ALL_ICMP', 'ALL_ICMP6', 'ALL_TCP', 'ALL_UDP',
      'BGP', 'RIP', 'OSPF', 'NTP', 'SNMP', 'SNMP-TRAP',
      'TELNET', 'RDP', 'VNC', 'SMB', 'NetBIOS-DS', 'NetBIOS-NS', 'NetBIOS-SS',
      'LDAP', 'LDAPS', 'RADIUS', 'KERBEROS', 'KERBEROS-UDP',
      'SIP', 'H323', 'MGCP', 'SCCP',
      'IKE', 'PPTP', 'L2TP', 'GRE',
      'DHCP', 'TFTP', 'NFS', 'RSYNC', 'SAMBA',
      'IRC', 'QUAKE', 'PC-Anywhere-Data', 'Squid',
      'TRACEROUTE', 'SYSLOG', 'WCCP',
    ]],
    // Cisco ASA/FTD 官方網路物件關鍵字（ASA Command Reference 明確定義，基礎且無爭議）
    ['Cisco ASA', [..._COMMON_BUILTINS, 'any4', 'any6']],
    // PaloAlto：PAN-OS 官方文件（Objects > Services, PAN-OS 11.1 Web Interface Help）明確記載
    // service-http／service-https 為 predefined service（不會出現在 `show service` 這類僅列出
    // 自訂物件的指令輸出），高信心度；PAN-OS 無出廠預設地址物件（"any" 僅為比對關鍵字非具名物件）
    ['PaloAlto', [..._COMMON_BUILTINS, 'service-http', 'service-https']],
    // pfSense：官方文件（docs.netgate.com「Alias Types」頁）列出的系統保留別名（system alias），
    // 高信心度；pfSense 無出廠預設服務物件（服務直接以埠號寫在規則內，無具名物件概念）
    ['pfSense', [..._COMMON_BUILTINS, 'bogons', 'sshguard', 'snort2c', 'virusprot', 'vpn_networks', 'negate_networks', 'tonatsubnets']],
    // Juniper SRX：Junos 官方文件（Junos Default Groups）明確記載 junos-defaults group 內建
    // 大量不可刪除/編輯的 predefined application，高信心度（第三方 majornetwork.net 逐一列表僅作
    // 輔助佐證非主要依據）；Junos 無出廠預設 address-book 物件（"any" 僅為 policy 比對關鍵字）
    ['Juniper', [
      ..._COMMON_BUILTINS,
      'junos-http', 'junos-https', 'junos-ftp', 'junos-ssh', 'junos-telnet',
      'junos-dns-udp', 'junos-dns-tcp', 'junos-dhcp-server', 'junos-dhcp-client',
      'junos-smtp', 'junos-ntp', 'junos-snmp', 'junos-ldap', 'junos-imap', 'junos-pop3',
      'junos-nfs', 'junos-tftp', 'junos-ping', 'junos-icmp-all',
    ]],
    // 以下廠牌已派研究 agent 查證（2026-08-25），皆因信心度不足未列入，fallback 套用
    // _COMMON_BUILTINS，比照專案「不猜測」原則：
    // - Check Point：官方文件僅查到 SMB Appliance 產品線（非本工具鎖定的 Gaia R8x）的 System
    //   Services 清單（HTTP/HTTPS/FTP/PPTP_TCP/SNMP/SSH/Citrix），產品線不符，不採用
    // - SonicWall：官方文件確認存在預設 Address/Service Object，但頁面未能取得逐一具名清單
    // - MikroTik／EdgeRouter：官方文件確認無出廠預設具名物件，本來就不需要清單（fallback 已足夠）
    // - Zyxel：僅論壇討論串佐證單一 service group 名稱（非官方 CLI Reference 逐條記載）
    // - Sophos：官方文件僅確認 Local Service ACL（設備管理存取控制）清單，與一般 Objects >
    //   Services（防火牆規則用）類別是否相同查無佐證，不確定是否適用
    // - OpenWrt：parser 本身 `addresses`/`services` 固定回傳空陣列（UCI 無對應物件概念），
    //   此函式對 OpenWrt 天生無作用，不需要清單
  ]);

  function analyzeUnusedObjects(parsed) {
    // merge()（跨檔案比對合併）會把 vendor 字串併成 "A + B" 這種形式，Map.get() 精確比對
    // 會查無結果、fallback 成只有 all/any/none 的 _COMMON_BUILTINS，導致合併分析時單一廠牌的
    // 出廠內建物件（如 FortiGate 的 INTERNET/SSLVPN_TUNNEL_ADDR1）全被誤判為「未使用」
    // （2026-09 全功能審查發現，比照同檔案 no-2fa/analyzeOrphanNAT 已採用的子字串比對慣例）
    const _vendorEntry = [...VENDOR_BUILTINS.entries()].find(([v]) => (parsed.vendor || '').includes(v));
    const BUILTINS = new Set(_vendorEntry ? _vendorEntry[1] : _COMMON_BUILTINS);
    // type 為系統自動管理，不需出現在 policy 中即算「已使用」
    const AUTO_TYPES = new Set(['interface-subnet','dynamic','wildcard-fqdn','geography']);

    // key 一律帶 vdom 前綴（比照 diffAddresses()/diffServices() 既有 `(x._vdom?x._vdom+'/':'')+name`
    // 慣例），避免多 VDOM 設定檔裡 VDOM A 的引用讓 VDOM B 同名孤兒物件被誤判為「已使用」而漏報
    // （2026-09-21 修復）
    const vk = (vdom, name) => (vdom ? vdom + '/' : '') + name;
    const usedAddr = new Set(), usedSvc = new Set();
    function addRefs(str, target, vdom) {
      if (!str || str === '-') return;
      str.split(/[,"\s]+/).forEach(n => { const t = n.trim(); if (t) target.add(vk(vdom, t)); });
    }

    // 1. Firewall policies
    for (const p of (parsed.policies || [])) {
      addRefs(p.srcAddr, usedAddr, p._vdom); addRefs(p.dstAddr, usedAddr, p._vdom); addRefs(p.service, usedSvc, p._vdom);
    }
    // 2. NAT：VIP/ippool 名稱、vipgrp members
    for (const n of (parsed.nat || [])) {
      usedAddr.add(vk(n._vdom, n.name)); // VIP/ippool 本身名稱（policy dstAddr 會直接引用）
      if (n.members) addRefs(n.members, usedAddr, n._vdom); // vipgrp members
    }
    // 3. SSL-VPN source-address / tunnel-ip-pools；SSL Portal ip-pools / split-tunneling-routing-address
    for (const v of (parsed.vpn || [])) {
      if (v.type === 'ssl-vpn') {
        addRefs(v.addr,   usedAddr, v._vdom);
        addRefs(v.ipPool, usedAddr, v._vdom);
        addRefs(v.splitTunnelRoutingAddr, usedAddr, v._vdom);
      }
      if (v.type === 'ssl-portal') {
        addRefs(v.ipPool, usedAddr, v._vdom);
        addRefs(v.splitTunnelRoutingAddr, usedAddr, v._vdom);
      }
    }
    // 4. 有 associated-interface 的地址物件：屬於介面子網（WiFi SSID / VLAN），系統隱式使用
    for (const a of (parsed.addresses || [])) {
      if (a.iface && a.iface !== '-') usedAddr.add(vk(a._vdom, a.name));
    }

    // 展開 address/service groups（迭代直到穩定）
    let changed = true;
    while (changed) {
      changed = false;
      for (const a of (parsed.addresses || [])) {
        if (a.members && usedAddr.has(vk(a._vdom, a.name))) {
          a.members.split(/,\s*/).forEach(m => { const t = m.trim(); if (t && !usedAddr.has(vk(a._vdom, t))) { usedAddr.add(vk(a._vdom, t)); changed = true; } });
        }
      }
      for (const s of (parsed.services || [])) {
        if (s.members && usedSvc.has(vk(s._vdom, s.name))) {
          s.members.split(/,\s*/).forEach(m => { const t = m.trim(); if (t && !usedSvc.has(vk(s._vdom, t))) { usedSvc.add(vk(s._vdom, t)); changed = true; } });
        }
      }
    }

    const unusedAddrs = (parsed.addresses || []).filter(a =>
      !BUILTINS.has(a.name) &&
      !AUTO_TYPES.has(a.type) &&
      !usedAddr.has(vk(a._vdom, a.name))
    );
    const unusedSvcs = (parsed.services || []).filter(s =>
      !BUILTINS.has(s.name) &&
      !usedSvc.has(vk(s._vdom, s.name))
    );
    return { unusedAddrs, unusedSvcs };
  }

  // ── NAT 規則健檢（2026-09-01 新增，功能5）─────────────────────
  // 重複 extIP／port 衝突偵測：原本是 firewall-analyzer-app.js 內的 UI-only 函式
  // （無測試覆蓋），本輪搬到這裡形式化＋補測試，邏輯完全不變。純粹依欄位形狀運作
  // （type==='vip' + extIp/portFwd/extPort/proto），非寫死 vendor 判斷——FortiGate／
  // EdgeRouter／OpenWrt／MikroTik 四家 NAT parser 皆輸出此形狀，故本來就會自然套用到
  // 這四家，非本輪新增查證範圍。
  function analyzeNAT(nat) {
    const warnings = [];
    const vips = (nat || []).filter(n => n.type === 'vip');
    // 先依 VDOM 分組再各自比對重複（比照 analyzeExactDuplicates() 既有分組慣例，2026-09-21 修復）：
    // 不同 VDOM 通常各自獨立 WAN，同 extIP/port 未必真衝突，不分組會漏報同 VDOM 內真正的衝突
    // 被跨 VDOM 湊出「>1 筆」的假象掩蓋掉方向不同的問題，也可能把不同 VDOM 的巧合同址誤判為衝突
    const byVdom = new Map();
    vips.forEach(v => {
      const vd = v._vdom || '';
      if (!byVdom.has(vd)) byVdom.set(vd, []);
      byVdom.get(vd).push(v);
    });
    byVdom.forEach(group => {
      const ipMap = {};
      group.filter(v => v.portFwd === 'disable' || !v.portFwd).forEach(v => {
        if (v.extIp && v.extIp !== '-') { (ipMap[v.extIp] = ipMap[v.extIp] || []).push(v.name); }
      });
      Object.entries(ipMap).filter(([, names]) => names.length > 1).forEach(([ip, names]) => warnings.push({ type: 'dup_ip', msg: `${tr('nat.dup_ip')}: ${ip}`, detail: names.join(', ') }));
      const portMap = {};
      group.filter(v => v.portFwd === 'enable').forEach(v => {
        const k = `${v.extIp}:${v.extPort}:${v.proto || 'tcp'}`;
        if (v.extIp && v.extIp !== '-' && v.extPort && v.extPort !== '-') { (portMap[k] = portMap[k] || []).push(v.name); }
      });
      Object.entries(portMap).filter(([, names]) => names.length > 1).forEach(([k, names]) => warnings.push({ type: 'port_conflict', msg: `${tr('nat.port_conflict')}: ${k}`, detail: names.join(', ') }));
    });
    return warnings;
  }

  // 孤兒 NAT 物件：具名可被 policy 引用的 NAT 物件（vip/ippool/vipgrp）從未被任何 policy 的
  // srcAddr/dstAddr 引用。**明確排除 Cisco ASA／SonicWall**——這兩家的 NAT 是自我完備規則
  // （ASA 甚至沒有 .name 欄位、SonicWall 規則不透過 policy 引用生效），對它們做「是否被
  // 引用」判斷沒有意義，會導致每筆都被誤判為孤兒；比照本專案既有 NAT_UNSUPPORTED／
  // VENDOR_INCAPABLE 白名單慣例明確排除、不猜測。
  // 排除比對改用不分大小寫的子字串（比照既有 no-2fa 的 .includes('PaloAlto') 修法），因為
  // parsed.vendor 實際值是 'Cisco ASA'／'SonicWall'（含空格/駝峰），且 merge() 合併多廠牌分析
  // 時會在後面加後綴，精確比對／小寫字面值比對兩者皆會恆為 false 導致排除清單完全失效。
  const ORPHAN_NAT_EXCLUDED_VENDOR_RE = /cisco\s*asa|sonicwall/i;
  const ORPHAN_NAT_TYPES = new Set(['vip', 'ippool', 'vipgrp']);
  function analyzeOrphanNAT(parsed) {
    if (ORPHAN_NAT_EXCLUDED_VENDOR_RE.test(parsed.vendor || '')) return [];
    const nat = parsed.nat || [];
    if (!nat.length) return [];
    // key 帶 vdom 前綴（比照 diffNAT() 既有慣例，2026-09-21 修復）：避免多 VDOM 設定檔裡 VDOM A
    // 的引用讓 VDOM B 同名孤兒 NAT 物件被誤判為「已使用」而漏報
    const vk = (vdom, name) => (vdom ? vdom + '/' : '') + name;
    const usedAddr = new Set();
    for (const p of (parsed.policies || [])) {
      // poolname 是 ippool（SNAT／來源位址轉換）的引用欄位，與 vip 用的 srcAddr/dstAddr 不同，
      // 遺漏這欄會讓所有正常在用的 ippool 被誤判為孤兒（outbound SNAT 用 IP Pool 是常見設定）。
      [p.srcAddr, p.dstAddr, p.poolname].forEach(str => {
        if (!str || str === '-') return;
        str.split(/[,"\s]+/).forEach(n => { const t = n.trim(); if (t) usedAddr.add(vk(p._vdom, t)); });
      });
    }
    return nat.filter(n => ORPHAN_NAT_TYPES.has(n.type) && n.name && !usedAddr.has(vk(n._vdom, n.name)));
  }

  // 孤兒 VPN 物件：IPSec Phase1 通道從未被任何 policy 的 srcIntf/dstIntf 引用，也從未出現在
  // SD-WAN member 的 interface 欄位（常見「IPsec 介面模式通道被加進 SD-WAN member」情境，
  // 不檢查會誤判）。**明確排除 Cisco ASA**——policy-based/crypto-map VPN 不透過介面名稱被規則
  // 引用，架構上不適用，比照上方 ORPHAN_NAT_EXCLUDED_VENDOR_RE 精神。僅涵蓋 ipsec-p1（排除
  // SSL-VPN/portal 類型，這些不透過介面被引用）。
  // **v.iface 欄位語意隨廠牌不同，不可一律當成「可被引用的通道介面」比對**：Palo Alto／
  // Juniper 的 v.iface 是真正的虛擬通道介面（tunnel.1／st0.0，規則直接引用）；但 FortiGate／
  // pfSense 的 v.iface 是該通道綁定的實體 WAN 埠（如 wan1，parser 直接讀 `set interface`），
  // 同一實體埠通常被大量無關規則引用，若同樣拿來比對會讓幾乎所有孤兒通道被誤判為「已使用」
  // （原始實作曾誤判，已用真實 FortiGate 設定檔測資復現並修正）。故僅對 v.iface 語意等同虛擬
  // 通道介面的廠牌白名單額外比對該欄位，其餘廠牌（含 FortiGate）僅比對 v.name（FortiGate 規則
  // 引用的是與通道同名的自動建立虛擬介面，即 v.name 本身）。
  const ORPHAN_VPN_EXCLUDED_VENDOR_RE = /cisco\s*asa/i;
  const ORPHAN_VPN_IFACE_IS_TUNNEL_VENDOR_RE = /palo\s*alto|juniper/i;
  function analyzeOrphanVPN(parsed) {
    if (ORPHAN_VPN_EXCLUDED_VENDOR_RE.test(parsed.vendor || '')) return [];
    const vpn = (parsed.vpn || []).filter(v => v.type === 'ipsec-p1');
    if (!vpn.length) return [];
    const ifaceIsTunnel = ORPHAN_VPN_IFACE_IS_TUNNEL_VENDOR_RE.test(parsed.vendor || '');
    // key 帶 vdom 前綴（比照 diffVpn() 既有慣例，2026-09-21 修復）：避免多 VDOM 設定檔裡 VDOM A
    // 的引用讓 VDOM B 同名孤兒通道被誤判為「已使用」而漏報
    const vk = (vdom, name) => (vdom ? vdom + '/' : '') + name;
    const usedIface = new Set();
    for (const p of (parsed.policies || [])) {
      [p.srcIntf, p.dstIntf].forEach(str => {
        if (!str || str === '-') return;
        str.split(/[,"\s]+/).forEach(n => { const t = n.trim(); if (t) usedIface.add(vk(p._vdom, t)); });
      });
    }
    ((parsed.sdwan && parsed.sdwan.members) || []).forEach(m => {
      if (m.iface && m.iface !== '-') usedIface.add(vk(m._vdom, m.iface));
    });
    return vpn.filter(v => {
      const refs = [v.name, ifaceIsTunnel ? v.iface : null].filter(x => x && x !== '-');
      return refs.length > 0 && !refs.some(r => usedIface.has(vk(v._vdom, r)));
    });
  }

  // 規則缺無備註稽核（2026-09-23 新增，使用者發想功能）：檢查每筆規則的 comments 欄位是否為
  // 空字串／未定義／各廠牌 parser 常見的無值佔位符 '-'（比照本檔案既有 _shadowToSet() 等函式
  // 「'-' 視為空」慣例統一判斷；各廠牌 parser 對 policies 的欄位名稱固定是 comments 複數形，
  // 見各 firewall-analyzer-parser-*.js 的 parsePolicies()）。回傳陣列比照 analyzeOrphanNAT()
  // 既有慣例，直接回傳命中的規則物件本身（非另包一層 warning 物件），供 computeFirewallHealth()
  // 計數與畫面渲染共用；不區分規則是否已停用——備註缺漏本身是「設定衛生」問題，即使規則目前
  // 停用，日後重新啟用時仍受益於清楚的備註說明。
  function analyzeMissingComments(parsed) {
    const policies = parsed.policies || [];
    return policies.filter(p => !p.comments || p.comments === '-');
  }

  // 停用規則清理清單（2026-09-24 新增）：analyzeCompliance() 的 'disabled-pol' 只給計數，
  // 此函式列出明細供清理／匯出 CSV。判斷式刻意沿用同一個 _isDisabledStatus()，確保清單筆數
  // 與合規檢查顯示的計數一致；不另外計入稽核總數／健康度（合規檢查已計過，避免重複扣分）
  function analyzeDisabledPolicies(parsed) {
    return (parsed.policies || []).filter(p => _isDisabledStatus(p));
  }

  // 過大／巢狀過深群組物件稽核（2026-09-23 新增，使用者發想功能）：檢查 addresses/services
  // 內具有 members 欄位的群組型物件（各廠牌 category 命名不一，如 address-group／group，
  // 統一以「members 欄位非空」判斷是否為群組，比照 analyzeUnusedObjects() 展開 group members
  // 時的既有判斷慣例）。門檻為簡單常數，未來若需調整只改這兩個常數即可，非對外查證數字。
  // 巢狀深度計算需防禦循環引用（正常設定不該出現，但群組互相引用的畸形資料理論上可能發生）：
  // 用 visiting 集合偵測，命中即視為已超過門檻不再往下展開，避免無窮迴圈卡住畫面；depthCache
  // 記錄每個物件算過的深度，避免同一物件被不同起點的群組重複展開造成效能問題。
  const OVERSIZED_GROUP_MEMBER_THRESHOLD = 50;
  const OVERSIZED_GROUP_DEPTH_THRESHOLD = 3;
  function analyzeOversizedGroups(parsed) {
    const results = [];
    const _check = (list, category) => {
      const items = list || [];
      const vk = (vdom, name) => (vdom ? vdom + '/' : '') + name;
      const byKey = new Map(items.map(o => [vk(o._vdom, o.name), o]));
      const depthCache = new Map();
      function depthOf(obj, visiting) {
        const key = vk(obj._vdom, obj.name);
        if (depthCache.has(key)) return depthCache.get(key);
        if (visiting.has(key)) return OVERSIZED_GROUP_DEPTH_THRESHOLD + 1; // 循環引用防禦：直接視為超標，不再往下展開
        visiting.add(key);
        const memberNames = (obj.members || '').split(/,\s*/).map(s => s.trim()).filter(Boolean);
        let maxChildDepth = 0;
        memberNames.forEach(m => {
          const child = byKey.get(vk(obj._vdom, m));
          if (child && child.members && child.members !== '-') {
            maxChildDepth = Math.max(maxChildDepth, depthOf(child, visiting));
          }
        });
        visiting.delete(key);
        const depth = 1 + maxChildDepth;
        depthCache.set(key, depth);
        return depth;
      }
      items.forEach(o => {
        if (!o.members || o.members === '-') return; // 非群組物件（一般 host/range/port 定義）
        const memberCount = o.members.split(/,\s*/).map(s => s.trim()).filter(Boolean).length;
        if (memberCount > OVERSIZED_GROUP_MEMBER_THRESHOLD) {
          results.push({ category, name: o.name, vdom: o._vdom || '', issue: 'members', value: memberCount });
        }
        const depth = depthOf(o, new Set());
        if (depth > OVERSIZED_GROUP_DEPTH_THRESHOLD) {
          results.push({ category, name: o.name, vdom: o._vdom || '', issue: 'depth', value: depth });
        }
      });
    };
    _check(parsed.addresses, 'address');
    _check(parsed.services, 'service');
    return results;
  }

  // 相鄰規則合併建議：偵測「相鄰（consecutive，中間不能夾其他規則）」且除了
  // srcAddr/dstAddr/service 三者之一外，其餘關鍵欄位（action/介面/schedule/nat/
  // logtraffic/VDOM）皆完全相同的規則群組，建議合併為一條（差異欄位改用群組涵蓋多值）。
  // 若差異欄位任一方已是萬用字元（any/all 等），代表其中一條已完全涵蓋另一條，
  // 屬於 analyzeRuleShadowing() 的偵測範圍，本分析刻意排除避免重複提示。
  const _MERGE_FIELDS = ['srcAddr', 'dstAddr', 'service'];
  // poolname：NAT Pool 身份（2026-08-19 新增）。原本只比對 nat enable/disable 旗標，兩條規則
  // 都開 NAT 但接不同 Pool 時仍會被誤判可合併；poolname/ippool 是全廠牌 parser 皆會回傳的共用
  // 欄位（僅 FortiGate 目前有真實值，其餘廠牌固定回傳 '-'/'disable' 佔位值，故此變更不影響
  // 其他廠牌既有行為）
  const _MERGE_SAME_KEYS = ['action', 'srcIntf', 'dstIntf', 'logtraffic', 'schedule', 'nat', 'poolname'];
  function analyzeMergeSuggestions(policies) {
    const isWild = v => _SHADOW_WILDCARD.has((v || '').trim().toLowerCase());
    const results = [];
    const active = (policies || []).filter(p => !_isDisabledStatus(p));
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

  // 全清單完全重複規則偵測（2026-09-14 新增）：與 analyzeMergeSuggestions() 不同——那個函式
  // 只掃描「相鄰」規則且要求恰好 1 個欄位不同（合併建議）；此函式用 Map 對「來源/目的/服務/動作」
  // 完全相同的規則全量分組（非相鄰亦會命中），找出的是真正的冗餘規則（可直接刪除其一），
  // 語意與合併建議互補、非重工
  function analyzeExactDuplicates(policies) {
    const active = (policies || []).filter(p => !_isDisabledStatus(p));
    const groups = new Map();
    active.forEach(p => {
      const key = `${p._vdom || ''}|${p.srcAddr || '-'}|${p.dstAddr || '-'}|${p.service || '-'}|${p.action || '-'}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(p);
    });
    const results = [];
    groups.forEach(group => {
      if (group.length < 2) return;
      const first = group[0];
      results.push({
        srcAddr: first.srcAddr, dstAddr: first.dstAddr, service: first.service, action: first.action,
        ids: group.map(p => p.id), count: group.length,
      });
    });
    return results;
  }

  // 本機 log 保留天數門檻（第十四輪 OK）：opts 優先，其次日誌頁設定（localStorage），預設 90 天
  const LOG_RETENTION_DEFAULT = 90;
  function logRetentionThreshold(opts) {
    let v = opts && opts.logRetentionDays;
    if (v == null) { try { v = localStorage.getItem('fw_log_retention_days'); } catch (e) { v = null; } }
    const n = parseInt(v, 10);
    return n > 0 ? n : LOG_RETENTION_DEFAULT;
  }
  function analyzeCompliance(parsed, opts) {
    const findings = [];
    // standards：僅供參考的常見資安標準關聯條號（業界廣泛公開引用的控制編號與主題，
    // 非逐字引用付費標準內容），純資訊性標籤，不代表通過此工具檢查即符合該標準認證。
    // PCI-DSS 4.0 條號已對照 PCI Security Standards Council 官方公開文件逐條查證（2026-07-22）；
    // ISO27001 條號已改為 2022 版 Annex A 編號（2022 版將 2013 版 114 條重整為 93 條，
    // 舊版 A.9/A.10/A.12/A.13 等編號已作廢），依 ISMS.online／High Table／Voragosecurity
    // 等公開次級來源交叉核對官方 2013→2022 對照表（2026-07-22，非直接核對付費原文，
    // 部分條號查證信心為中高非完全確定，詳見 now.md 對應段落）；
    // NIST 800-53/CIS v8 沿用既有引用（CIS v8 已於 2026-07-21 查證）。
    // items（2026-09-29 新增，AA）：完整命中對象 {kind, id?, name, vdom?}，供 buildFirewallAuditEvidence() 找原始設定行
    const f = (id, check, value, risk, detail, standards, items) => findings.push({ id, check, value, risk, detail, standards: standards||[], items: items||[] });
    const polItems = arr => arr.map(p => ({ kind: 'policy', id: p.id, name: p.name, vdom: p._vdom }));
    const policies = parsed.policies || [];
    // 多 VDOM 時以 VDOM/ID 顯示，避免各 VDOM 重複的 ID 混淆
    const isMultiVdom = policies.some(p => p._vdom !== undefined && p._vdom !== null);
    const idLabel = p => (isMultiVdom && p._vdom) ? `${p._vdom}/${p.id}` : p.id;
    // _isDisabledStatus 已提升為本檔案頂層共用 helper（見檔案開頭 27 行附近），此處不再
    // 重複定義
    // 1. any-to-any 允許規則
    const anyAny = policies.filter(p => p.action === 'accept' && !_isDisabledStatus(p) &&
      /\b(all|any)\b/i.test(p.srcAddr||'') && /\b(all|any)\b/i.test(p.dstAddr||'') && /\b(all|any|ALL)\b/i.test(p.service||''));
    f('any-any', tr('audit.check_any_any'), anyAny.length, 'high',
      anyAny.length ? tr('audit.id_prefix') + anyAny.map(p => idLabel(p)).slice(0,10).join(', ') + (anyAny.length > 10 ? '…' : '') : tr('audit.none'),
      ['ISO27001 A.8.20', 'PCI-DSS 4.0 1.3.1/1.3.2', 'NIST 800-53 SC-7', 'CIS v8 12.2'], polItems(anyAny));
    // 2. 停用規則數量
    const disabled = policies.filter(p => _isDisabledStatus(p));
    f('disabled-pol', tr('audit.check_disabled'), disabled.length, 'medium',
      disabled.length ? `${disabled.length}` + tr('audit.rec_disabled') : tr('audit.none'),
      ['ISO27001 A.8.9', 'PCI-DSS 4.0 1.2.7', 'NIST 800-53 CM-7', 'CIS v8 4.1'], polItems(disabled));
    // 3. 無日誌的允許規則
    const noLog = policies.filter(p => p.action === 'accept' && !_isDisabledStatus(p) &&
      (!p.logtraffic || p.logtraffic === 'disable' || p.logtraffic === 'utm'));
    f('no-log', tr('audit.check_no_log'), noLog.length, 'medium',
      noLog.length ? `${noLog.length}` + tr('audit.rec_log') : tr('audit.all_logged'),
      ['ISO27001 A.8.15', 'PCI-DSS 4.0 10.2.1', 'NIST 800-53 AU-2', 'CIS v8 8.2'], polItems(noLog));
    // 4. SNMP v1/v2c
    const snmp = parsed.snmp;
    const hasV1v2 = snmp && snmp.communities && snmp.communities.length > 0;
    f('snmp-v1v2', tr('audit.check_snmp'), hasV1v2 ? snmp.communities.length : 0, 'high',
      hasV1v2 ? `Community: ${snmp.communities.length}` + tr('audit.rec_snmpv3') : tr('audit.none'),
      ['ISO27001 A.8.24', 'PCI-DSS 4.0 2.2.6', 'NIST 800-53 IA-5', 'CIS v8 4.8'], hasV1v2 ? snmp.communities.map(c => ({ kind: 'snmp', name: c.name })) : []);
    // 5. 管理員未啟用 2FA（2026-08-19 擴大涵蓋 type==='local' 但實際等同管理員權限的帳號：
    // CiscoASA 用單數 role 欄位、CheckPoint 用 roles/accessLevel、PaloAlto mgt-config users
    // 節點本身無角色欄位但本質即管理員帳號、Sophos accessLevel 可能是 admin/super-admin。
    // 刻意不用一律 type==='local' 的粗暴寫法——會誤觸 FortiGate SSL-VPN/portal 一般使用者
    // （accessLevel 固定 'user'）與 Sophos 一般權限使用者）
    // 2026-08-27 稽核修復：parsed.vendor 精確比對 'PaloAlto' 在多廠牌合併分析時會失效——
    // merge()（firewall-analyzer-app.js）把兩份設定檔的 vendor 串接成 "FortiGate + PaloAlto"
    // 這類字串，精確比對從此恆為 false，PaloAlto 本機管理帳號的 2FA 缺口從此被靜默排除在
    // 稽核範圍外（單一廠牌上傳不受影響，僅合併分析時失效）。改用 includes()，vendor 串接
    // 語法固定用 " + " 分隔，不會有其他廠牌名稱意外包含 "PaloAlto" 子字串造成誤判
    const isPrivileged = u => u.status !== 'disable' && (
      u.type === 'admin' ||
      u.role === 'admin' ||
      (Array.isArray(u.roles) && u.roles.includes('admin')) ||
      u.accessLevel === 'admin' || u.accessLevel === 'super-admin' ||
      (u.type === 'local' && (parsed.vendor || '').includes('PaloAlto'))
    );
    const admins = (parsed.users || []).filter(isPrivileged);
    const no2fa  = admins.filter(u => !u.twoFactor || u.twoFactor === 'disable');
    f('no-2fa', tr('audit.check_no_2fa'), no2fa.length, 'high',
      no2fa.length ? no2fa.map(u => u.name).slice(0,8).join(', ') + (no2fa.length > 8 ? '…' : '') : tr('audit.all_2fa'),
      ['ISO27001 A.8.5', 'PCI-DSS 4.0 8.4.1', 'NIST 800-53 IA-2(1)', 'CIS v8 6.5'], no2fa.map(u => ({ kind: 'user', name: u.name, vdom: u._vdom })));
    // 6. 外部介面允許 HTTP/Telnet
    const dangerAcc = ['http','telnet'];
    const riskyIntf = (parsed.interfaces || []).filter(i => {
      const acc = (i.allowaccess || '').toLowerCase();
      // 2026-09-18 新增：i.role==='external' 涵蓋 Cisco ASA 專屬的小寫角色詞彙（其餘廠牌
      // guessRole() 皆回傳大寫 'WAN'/'LAN'/'DMZ'/...，僅 ASA 用 'external'/'internal'/'dmz'，
      // 兩者字面不同不會誤判彼此），i.nameif 比對涵蓋 ASA 的 nameif 命名慣例（如 outside）
      // 與 i.name（實體介面名稱如 GigabitEthernet0/0）分屬不同欄位，僅比對 i.name 永遠測不到
      const isExt = i.role === 'WAN' || i.role === 'external' ||
        (i.name || '').toLowerCase().match(/^(wan|ext|outside|untrust)/) ||
        (i.nameif || '').toLowerCase().match(/^(wan|ext|outside|untrust)/);
      return isExt && dangerAcc.some(d => acc.includes(d));
    });
    f('http-mgmt', tr('audit.check_http_mgmt'), riskyIntf.length, 'high',
      riskyIntf.length ? riskyIntf.map(i => `${i.name}(${i.allowaccess})`).join(', ') : tr('audit.normal'),
      ['ISO27001 A.5.15', 'PCI-DSS 4.0 2.2.7', 'NIST 800-53 AC-17', 'CIS v8 12.3'], riskyIntf.map(i => ({ kind: 'iface', name: i.name, vdom: i._vdom })));
    // 7. VPN 弱加密
    const WEAK = /\b(des\b|3des|md5|rc4|null)/i;
    const weakVpn = (parsed.vpn || []).filter(v => WEAK.test((v.proposal || '') + ' ' + (v.dhgrp || '')));
    f('weak-vpn', tr('audit.check_weak_vpn'), weakVpn.length, 'high',
      weakVpn.length ? weakVpn.map(v => v.name).slice(0,6).join(', ') : tr('audit.normal'),
      ['ISO27001 A.8.24', 'PCI-DSS 4.0 4.2.1', 'NIST 800-53 SC-13', 'CIS v8 3.10'], weakVpn.map(v => ({ kind: 'vpn', name: v.name, vdom: v._vdom })));
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
      ['ISO27001 A.8.24', 'PCI-DSS 4.0 4.2.1'], noPfs.map(n => ({ kind: 'vpn', name: String(n).split('/')[0] })));
    // 9. 預設/通用管理員帳號名稱仍啟用（新增：PCI-DSS 4.0 逐條擴充，Req 2.2.2 預設帳號／8.2.2 共用帳號禁用）
    const DEFAULT_NAMES = /^(admin|administrator|root|guest|test|demo)$/i;
    const defaultAdmins = (parsed.users || []).filter(u =>
      (u.type === 'admin' || u.type === 'local') && u.status !== 'disable' && DEFAULT_NAMES.test((u.name || '').trim()));
    f('default-admin-name', tr('audit.check_default_admin'), defaultAdmins.length, 'medium',
      defaultAdmins.length ? defaultAdmins.map(u => u.name).slice(0,8).join(', ') + (defaultAdmins.length > 8 ? '…' : '') : tr('audit.none'),
      ['ISO27001 A.5.16', 'PCI-DSS 4.0 2.2.2/8.2.2'], defaultAdmins.map(u => ({ kind: 'user', name: u.name, vdom: u._vdom })));
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
      ['NIST 800-53 IA-5', 'CIS v8 4.8'], weakV3.map(u => ({ kind: 'snmp', name: u.name })));
    // 11. 過寬規則：來源/目的為超大範圍網段（2026-08-29 新增，使用者發想 5 項新功能第 3 項）。
    // 上方第 1 項 any-any 檢查只用字面 all/any 文字比對，查證確認查無法命中字面 CIDR 寫法
    // （如 0.0.0.0/0、10.0.0.0/8），是既有真實缺口而非與 any-any 重工。僅評估能解析出明確
    // CIDR 前綴長度的來源/目的：欄位本身是字面 CIDR（如 MikroTik 慣例直接存 CIDR）、或具名
    // address 物件且 type==='ipmask' 時查其 subnet 欄位；address group／巢狀 group／FQDN
    // 物件因需遞迴展開且語意可能因物件成員而異，刻意不解析、不臆測，比照 any-any 檢查同樣
    // 謹慎的範圍；僅處理 IPv4（IPv6 前綴語意不同，本輪不評估）
    // key 帶 vdom 前綴（比照 diffAddresses() 等既有 `(x._vdom?x._vdom+'/':'')+name` 慣例），
    // 避免多 VDOM 環境下不同 VDOM 同名位址物件互相覆蓋、誤判過寬網段（2026-09-22 修復）
    const vk = (vdom, name) => (vdom ? vdom + '/' : '') + name;
    const addrByName = new Map((parsed.addresses || []).map(a => [vk(a._vdom, a.name), a]));
    const addrPrefixLen = (val, vdom) => {
      if (!val) return null;
      const literal = _extractLiteralCidrPrefixLen(val);
      if (literal !== null) return literal;
      const obj = addrByName.get(vk(vdom, val));
      return (obj && obj.type === 'ipmask' && obj.subnet) ? _extractLiteralCidrPrefixLen(obj.subnet) : null;
    };
    const isBroad = (val, vdom) => String(val || '').split(',').map(s => s.trim()).filter(Boolean)
      .some(p => { const len = addrPrefixLen(p, vdom); return len !== null && len <= 8; });
    const broadNetwork = policies.filter(p => p.action === 'accept' && !_isDisabledStatus(p) &&
      (isBroad(p.srcAddr, p._vdom) || isBroad(p.dstAddr, p._vdom)));
    f('broad-network', tr('audit.check_broad_network'), broadNetwork.length, 'medium',
      broadNetwork.length ? tr('audit.id_prefix') + broadNetwork.map(p => idLabel(p)).slice(0,10).join(', ') + (broadNetwork.length > 10 ? '…' : '') : tr('audit.none'),
      ['ISO27001 A.8.20', 'PCI-DSS 4.0 1.3.1/1.3.2', 'NIST 800-53 SC-7', 'CIS v8 12.2'], polItems(broadNetwork));
    // 12. 遠端管理埠對全網開放（2026-10-02 新增，第十輪 ZC）：來源為 any／0.0.0.0/0／::/0／Azure Internet
    // 服務標籤，且服務明確涵蓋 SSH(22)／Telnet(23)／RDP(3389) 的允許規則。服務為 ALL 的規則已由第 1 項
    // any-any 與第 11 項涵蓋，這裡只看有寫出服務的規則，避免重複計算
    const MGMT_PORTS = [22, 23, 3389];
    const anySrc = v => String(v || '').split(',').map(x => x.trim().toLowerCase()).some(x => ['all', 'any', '0.0.0.0/0', '::/0', 'internet', '0.0.0.0 0.0.0.0'].includes(x));
    const mgmtExposed = policies.filter(p => p.action === 'accept' && !_isDisabledStatus(p) && anySrc(p.srcAddr) &&
      !/^(all|any)$/i.test(String(p.service || 'ALL').trim()) &&
      MGMT_PORTS.some(port => _policySvcMatches(p.service, 'TCP', port, parsed.services || [])));
    f('mgmt-exposed', tr('audit.check_mgmt_exposed'), mgmtExposed.length, 'high',
      mgmtExposed.length ? tr('audit.id_prefix') + mgmtExposed.map(p => idLabel(p)).slice(0,10).join(', ') + (mgmtExposed.length > 10 ? '…' : '') : tr('audit.none'),
      ['PCI-DSS 4.0 1.3.1', 'NIST 800-53 SC-7', 'CIS v8 4.4'], polItems(mgmtExposed));
    // 12b. IPv6 防護缺口（2026-10-06，第十二輪 MC）
    // (a) ipv6-any-open：IPv6 部分來源與目的皆為全部（::/0、any6、all6 等字面值或值為 ::/0 的位址物件）、服務不限的允許規則。
    //     any-any 與過寬網段只看 IPv4／字面 any，`::/0` 這類 IPv6 全開寫法原本兩者都抓不到；已算進第 1 項的規則不重複列
    // (b) ipv6-unfiltered：未設定規則時 IPv6 預設放行的系統（MikroTik /ipv6 firewall filter 與 Linux netfilter 鏈預設接受、
    //     VyOS 基本鏈預設 accept、EdgeRouter 未綁定規則集即不過濾——依官方文件），有 IPv4 規則卻沒有任何適用 IPv6 的規則。只在單一廠牌上傳時判斷
    const V6_ANY = new Set(['::/0', '::0/0', '0::0/0', 'any6', 'all6', 'any-ipv6', 'ipv6-any', '::']);
    const v6AnyTok = (tok, vdom) => {
      const t = String(tok || '').trim().replace(/^"|"$/g, '');
      if (V6_ANY.has(t.toLowerCase())) return true;
      const o = addrByName.get(vk(vdom, t));
      return !!o && [o.subnet, o.ip6, o.value, o.ip].some(x => V6_ANY.has(String(x || '').trim().toLowerCase().replace(/\s+/g, '')));
    };
    const v6Side = (p, k) => {
      const six = p[k + '6'];
      if (six !== undefined && six !== '-' && six !== '') return String(six).split(/\s*,\s*/);
      if (p._family === 'v6' || /^v6\//.test(String(p.id))) return String(p[k] || '').split(/\s*,\s*/);
      return String(p[k] || '').split(/\s*,\s*/).filter(x => x.includes(':'));
    };
    const svcAny = p => /^(all|any|ALL)$/i.test(String(p.service || 'ALL').trim());
    const v6AnyOpen = policies.filter(p => p.action === 'accept' && !_isDisabledStatus(p) && !anyAny.includes(p) && svcAny(p) &&
      v6Side(p, 'srcAddr').some(x => v6AnyTok(x, p._vdom)) && v6Side(p, 'dstAddr').some(x => v6AnyTok(x, p._vdom)));
    f('ipv6-any-open', tr('audit.check_ipv6_any_open'), v6AnyOpen.length, 'high',
      v6AnyOpen.length ? tr('audit.id_prefix') + v6AnyOpen.map(p => idLabel(p)).slice(0,10).join(', ') + (v6AnyOpen.length > 10 ? '…' : '') : tr('audit.none'),
      ['ISO27001 A.8.20', 'PCI-DSS 4.0 1.3.1/1.3.2', 'NIST 800-53 SC-7', 'CIS v8 12.2'], polItems(v6AnyOpen));
    const vend = String(parsed.vendor || '');
    // EdgeRouter（第十三輪 NE）：規則集要綁到介面才生效，沒綁 ipv6-name 的介面 IPv6 不過濾（Ubiquiti 說明的搜尋摘要）
    if (/^(MikroTik|VyOS|Linux netfilter|EdgeRouter)$/.test(vend)) {
      const live = policies.filter(p => !_isDisabledStatus(p));
      const v6Rules = live.filter(p => p._family !== 'v4');
      const v4Rules = live.filter(p => p._family === 'v4');
      const gap = v4Rules.length > 0 && v6Rules.length === 0;
      f('ipv6-unfiltered', tr('audit.check_ipv6_unfiltered'), gap ? 1 : 0, 'medium',
        gap ? tr('audit.ipv6_unfiltered_detail').replace('{n}', v4Rules.length) : tr('audit.none'),
        ['ISO27001 A.8.20', 'PCI-DSS 4.0 1.3.1/1.3.2', 'NIST 800-53 SC-7', 'CIS v8 12.2'], []);
    }
    // 12c. 本機 log 保留天數過短（2026-10-09，第十四輪 OK）：FortiGate 有硬碟（或推測有）且寫入硬碟，
    // 保留天數低於門檻，又沒有任何 Syslog／FortiAnalyzer 外送。門檻預設 90 天（PCI-DSS 4.0 10.5.1：最近
    // 三個月須可立即分析），可由 opts.logRetentionDays 或日誌頁設定（localStorage fw_log_retention_days）調整
    const ll = parsed.localLog;
    if (ll && ll.hasDisk !== false && ll.disk && ll.disk.status !== 'disable') {
      const lg = parsed.logservers || {};
      const external = (lg.syslog || []).length + (lg.fortianalyzer || []).length;
      const minDays = logRetentionThreshold(opts);
      const age = Number(ll.disk.maxAge);
      const short = ll.hasDisk && !external && age > 0 && age < minDays;
      f('log-retention', tr('audit.check_log_retention'), short ? 1 : 0, 'low',
        short ? tr('audit.log_retention_detail').replace('{n}', age).replace('{min}', minDays) : tr('audit.none'),
        ['PCI-DSS 4.0 10.5.1', 'NIST 800-53 AU-11', 'CIS v8 8.10'], []);
    }
    // 13. 過寬服務物件（2026-09-14 新增）：與第 1 項 any-any 檢查角度不同——那項看的是「規則」
    // 層級的來源/目的/服務是否皆為 all，此項專門看「服務物件本身」定義是否在物件層級就已無任何
    // 埠限制（proto 為 ANY/IP，或 tcp/udp port-range 寬度達 65535 等同全埠開放），即使規則的
    // src/dst 收斂，用了這種服務物件仍形同無埠管制
    const overlyPermissiveSvc = (parsed.services || []).filter(s => {
      const proto = String(s.proto || '').toUpperCase();
      if (proto === 'ANY' || proto === 'IP') return true;
      return _maxPortRangeWidth(s.tcpPorts) >= 65535 || _maxPortRangeWidth(s.udpPorts) >= 65535;
    });
    f('overly-permissive-svc', tr('audit.check_overly_permissive_svc'), overlyPermissiveSvc.length, 'medium',
      overlyPermissiveSvc.length ? overlyPermissiveSvc.map(s => s.name).slice(0,10).join(', ') + (overlyPermissiveSvc.length > 10 ? '…' : '') : tr('audit.none'),
      ['ISO27001 A.8.20', 'PCI-DSS 4.0 1.3.1/1.3.2', 'NIST 800-53 SC-7', 'CIS v8 4.4'], overlyPermissiveSvc.map(x => ({ kind: 'svc', name: x.name, vdom: x._vdom })));
    return findings;
  }
  // 單一 port-range token（如 "1-65535" 或 "443"）換算涵蓋的埠數量，供過寬服務物件檢查使用；
  // 非數字/範圍格式（如具名巨集）一律回傳 0，不臆測
  function _portRangeWidth(token) {
    const m = /^(\d+)-(\d+)$/.exec(token.trim());
    if (m) return Math.max(0, Number(m[2]) - Number(m[1]) + 1);
    return /^\d+$/.test(token.trim()) ? 1 : 0;
  }
  // tcpPorts/udpPorts 欄位可能是逗號或空白分隔的多個 range（各廠牌慣例不同），取其中寬度最大
  // 的單一 token（而非加總全部 token），避免把「很多個小範圍」誤判成「單一極寬範圍」
  function _maxPortRangeWidth(portsStr) {
    if (!portsStr || portsStr === '-') return 0;
    return String(portsStr).split(/[\s,]+/).filter(Boolean)
      .reduce((max, tok) => Math.max(max, _portRangeWidth(tok)), 0);
  }

  // 跨 VDOM 同名物件不一致稽核（2026-09-14 新增）：只在多 VDOM 設定檔才有意義（沿用
  // buildVdomBar() 既有的 parsed._isMultiVdom 判斷），依 name 分組 addresses/services（皆已有
  // _vdom 欄位），同名但跨 VDOM 內容不同（addresses 比對 subnet/startIp/endIp/fqdn，services
  // 比對 proto/tcpPorts/udpPorts/icmpType/icmpCode）時命中——同名物件理應代表同一份定義，內容
  // 卻不同，容易讓管理者誤以為跨 VDOM 行為一致而誤判影響範圍
  const _CROSS_VDOM_ADDR_FIELDS = ['subnet', 'startIp', 'endIp', 'fqdn'];
  const _CROSS_VDOM_SVC_FIELDS = ['proto', 'tcpPorts', 'udpPorts', 'icmpType', 'icmpCode'];
  function analyzeCrossVdomInconsistency(parsed) {
    if (!parsed || !parsed._isMultiVdom) return [];
    const results = [];
    const _check = (list, fields, category) => {
      const groups = new Map();
      (list || []).forEach(o => {
        if (!o.name) return;
        if (!groups.has(o.name)) groups.set(o.name, []);
        groups.get(o.name).push(o);
      });
      groups.forEach((group, name) => {
        const vdoms = [...new Set(group.map(o => o._vdom))];
        if (vdoms.length < 2) return;
        const keyOf = o => fields.map(f => o[f] || '').join('|');
        const distinctKeys = new Set(group.map(keyOf));
        if (distinctKeys.size <= 1) return;
        results.push({
          category, name,
          sample: group.map(o => `${o._vdom || '-'}: ${fields.map(f => o[f]).filter(Boolean).join('/') || '-'}`),
        });
      });
    };
    _check(parsed.addresses, _CROSS_VDOM_ADDR_FIELDS, 'address');
    _check(parsed.services, _CROSS_VDOM_SVC_FIELDS, 'service');
    return results;
  }
  // SARIF（Static Analysis Results Interchange Format 2.1.0）稽核結果匯出（2026-09-14 新增）：
  // 彙整全部既有稽核函式的結果，轉換成業界標準 schema，供 CI/CD 或安全工具鏈匯入比對。純函式，
  // 即時重新呼叫 analyze* 系列（比照 CSV_SUBSECTION_GETTERS 型別匯出時才重算的既有慣例，不依賴
  // 使用者是否已切換過稽核分頁的渲染快取）
  // sources（選填，AA）：[{name,text}] 原始設定；有提供時合規檢查結果附上證據行（physicalLocation）
  function buildSarifAuditReport(parsed, sources) {
    const results = [];
    const push = (ruleId, level, message, properties) => results.push({ ruleId, level, message: { text: message }, properties: properties || {} });
    analyzeRuleShadowing(parsed.policies || [], parsed.addresses).forEach(r => {
      push('rule-shadowing', 'warning', `${tr('audit.shadow_title')}: ${r.shadowedId} ${tr(r.reason)} ${r.shadowingId}`, { shadowedId: r.shadowedId, shadowedName: r.shadowedName, shadowingId: r.shadowingId, shadowingName: r.shadowingName, tier: r.tier });
    });
    analyzeDenyBlocking(parsed.policies || [], parsed.addresses).forEach(r => {
      push('deny-blocking', 'warning', `${tr('audit.deny_block_title')}: ${r.blockedId} (${r.blockedName||'-'}) blocked by ${r.blockingId} (${r.blockingName||'-'})`, { blockedId: r.blockedId, blockingId: r.blockingId });
    });
    analyzeMergeSuggestions(parsed.policies || []).forEach(r => {
      push('merge-suggestion', 'note', `${tr('audit.merge_title')}: ${tr(_MERGE_FIELD_LABEL[r.field])} — ${r.values.join(', ')}`, { ids: r.ids, field: r.field, count: r.count });
    });
    analyzeExactDuplicates(parsed.policies || []).forEach(r => {
      push('exact-duplicate-rules', 'warning', `${tr('audit.duplicate_title')}: ${r.ids.join(', ')} (${r.srcAddr} -> ${r.dstAddr} / ${r.service} / ${r.action})`, { ids: r.ids, count: r.count });
    });
    const un = analyzeUnusedObjects(parsed);
    (un.unusedAddrs || []).forEach(a => push('unused-address-object', 'note', `${tr('audit.unused_addr_header')}: ${a.name}`, { name: a.name, category: a.category }));
    (un.unusedSvcs || []).forEach(s => push('unused-service-object', 'note', `${tr('audit.unused_svc_header')}: ${s.name}`, { name: s.name, category: s.category }));
    const _co = analyzeCompliance(parsed);
    const _ev = sources ? buildFirewallAuditEvidence(sources, _co) : {};
    _co.forEach(f => {
      if (f.value > 0) {
        push('compliance-' + f.id, f.risk === 'high' ? 'error' : f.risk === 'medium' ? 'warning' : 'note', `${f.check}: ${f.detail}`, { standards: f.standards, count: f.value });
        if ((_ev[f.id] || []).length) results[results.length - 1].locations = _ev[f.id].map(e => ({ physicalLocation: { artifactLocation: { uri: e.src || 'config' }, region: { startLine: e.line, snippet: { text: e.text } } } }));
      }
    });
    analyzeCrossVdomInconsistency(parsed).forEach(r => {
      push('cross-vdom-inconsistency', 'warning', `${tr('audit.cross_vdom_title')}: ${r.name} (${r.category}) — ${r.sample.join(' / ')}`, { category: r.category, name: r.name });
    });
    return {
      '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'firewall_analyzer', informationUri: 'https://github.com/s200070221/alpaca-network-toolkit', version: '1.0.0', rules: [] } },
        results,
      }],
    };
  }

  function buildCrossVdomHtml(results) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--orange);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + tip('tip.cross_vdom', tr('audit.cross_vdom_title')) + '</div>';
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:10px;padding:6px 10px;background:var(--bg2);border-radius:4px;border-left:3px solid var(--orange)">' + esc(tr('audit.cross_vdom_warn')) + '</div>';
    if (!results.length) {
      h += '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('audit.cross_vdom_none')) + '</div></div>';
      return h;
    }
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('audit.col_category') + '</th><th>' + tr('audit.col_name') + '</th><th>' + tr('audit.col_cross_vdom_values') + '</th></tr></thead><tbody>';
    results.forEach(r => {
      h += `<tr><td>${pill(r.category, 'p-info')}</td><td class="mono" style="color:var(--accent)">${esc(r.name)}</td><td style="font-size:11px">${esc(r.sample.join(' / '))}</td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
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
      h += `<tr><td>${tp}</td><td class="mono"><span class="clickable-cell" style="color:var(--red)" onclick="window._jumpToPolicy(${JSON.stringify(r.shadowedId).replace(/"/g,'&quot;')})" title="${esc(jh)}">${esc(r.shadowedId)}</span></td><td>${esc(r.shadowedName||'-')}</td><td class="mono"><span class="clickable-cell" onclick="window._jumpToPolicy(${JSON.stringify(r.shadowingId).replace(/"/g,'&quot;')})" title="${esc(jh)}">${esc(r.shadowingId)}</span></td><td>${esc(r.shadowingName||'-')}</td><td style="color:var(--text-dim);font-size:11px"><span data-tip="${reasonTip.replace(/"/g,'&quot;')}">${esc(tr(r.reason))}<sup style="font-size:8px;opacity:.45;margin-left:2px;cursor:help">ⓘ</sup></span></td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  }

  function buildDenyBlockHtml(results) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--red);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + tip('tip.deny_block', tr('audit.deny_block_title')) + '</div>';
    if (!results.length) {
      h += '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('audit.deny_block_none')) + '</div></div>';
      return h;
    }
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('audit.col_blocked_id') + '</th><th>' + tr('audit.col_blocked_name') + '</th><th>' + tr('audit.col_blocking_id') + '</th><th>' + tr('audit.col_blocking_name') + '</th></tr></thead><tbody>';
    results.forEach(r => {
      const jh = tr('audit.jump_hint');
      h += `<tr><td class="mono"><span class="clickable-cell" style="color:var(--red)" onclick="window._jumpToPolicy(${JSON.stringify(r.blockedId).replace(/"/g,'&quot;')})" title="${esc(jh)}">${esc(r.blockedId)}</span></td><td>${esc(r.blockedName||'-')}</td><td class="mono"><span class="clickable-cell" onclick="window._jumpToPolicy(${JSON.stringify(r.blockingId).replace(/"/g,'&quot;')})" title="${esc(jh)}">${esc(r.blockingId)}</span></td><td>${esc(r.blockingName||'-')}</td></tr>`;
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
      const idCells = r.ids.map(id => `<span class="clickable-cell" onclick="window._jumpToPolicy(${JSON.stringify(id).replace(/"/g,'&quot;')})" title="${esc(jh)}" style="margin-right:6px">${esc(id)}</span>`).join('');
      h += `<tr><td>${pill(tr(_MERGE_FIELD_LABEL[r.field]), 'p-info')}</td><td class="mono">${idCells}</td><td style="font-size:11px">${esc(r.values.join(', '))}</td><td class="mono">${r.count}</td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  }

  function buildDuplicateHtml(results) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--red);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + tip('tip.duplicate', tr('audit.duplicate_title')) + '</div>';
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:10px;padding:6px 10px;background:var(--bg2);border-radius:4px;border-left:3px solid var(--red)">' + esc(tr('audit.duplicate_warn')) + '</div>';
    if (!results.length) {
      h += '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('audit.duplicate_none')) + '</div></div>';
      return h;
    }
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('audit.col_merge_ids') + '</th><th>' + tr('col.src_addr') + '</th><th>' + tr('col.dst_addr') + '</th><th>' + tr('col.service') + '</th><th>' + tr('col.action') + '</th><th>' + tr('audit.col_merge_count') + '</th></tr></thead><tbody>';
    results.forEach(r => {
      const jh = tr('audit.jump_hint');
      const idCells = r.ids.map(id => `<span class="clickable-cell" onclick="window._jumpToPolicy(${JSON.stringify(id).replace(/"/g,'&quot;')})" title="${esc(jh)}" style="margin-right:6px">${esc(id)}</span>`).join('');
      h += `<tr><td class="mono">${idCells}</td><td class="mono" style="font-size:11px">${esc(r.srcAddr)}</td><td class="mono" style="font-size:11px">${esc(r.dstAddr)}</td><td class="mono" style="font-size:11px">${esc(r.service)}</td><td>${pill(r.action,'p-info')}</td><td class="mono">${r.count}</td></tr>`;
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

  // 規則缺無備註稽核渲染（2026-09-23 新增）：比照 buildDuplicateHtml() 既有樣式（警語橫幅＋
  // 表格＋可點擊跳轉），列出的是「命中的規則物件」本身（analyzeMissingComments() 回傳形狀）
  function buildMissingCommentsHtml(results) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--yellow);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + esc(tr('audit.missing_comments_title')) + '</div>';
    if (!results.length) {
      h += '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('audit.missing_comments_none')) + '</div></div>';
      return h;
    }
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:10px;padding:6px 10px;background:var(--bg2);border-radius:4px;border-left:3px solid var(--yellow)">' + esc(tr('audit.missing_comments_warn')) + '</div>';
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>ID</th><th>' + tr('audit.col_name') + '</th><th>' + tr('audit.col_vdom') + '</th></tr></thead><tbody>';
    results.forEach(p => {
      const jh = tr('audit.jump_hint');
      h += `<tr><td class="mono"><span class="clickable-cell" onclick="window._jumpToPolicy(${JSON.stringify(p.id).replace(/"/g,'&quot;')})" title="${esc(jh)}">${esc(p.id)}</span></td><td>${esc(p.name||'-')}</td><td style="color:var(--text-dim)">${esc(p._vdom||'-')}</td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  }

  // 停用規則清理清單渲染（2026-09-24 新增）：比照 buildMissingCommentsHtml() 樣式，
  // 多列出來源/目的/服務/備註，方便判斷該規則是否可直接刪除
  function buildDisabledPoliciesHtml(results) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--yellow);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + esc(tr('audit.disabled_title')) + '</div>';
    if (!results.length) {
      h += '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('audit.disabled_none')) + '</div></div>';
      return h;
    }
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:10px;padding:6px 10px;background:var(--bg2);border-radius:4px;border-left:3px solid var(--yellow)">' + esc(tr('audit.disabled_warn')) + '</div>';
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>ID</th><th>' + tr('audit.col_name') + '</th><th>' + tr('col.src_addr') + '</th><th>' + tr('col.dst_addr') + '</th><th>' + tr('col.service') + '</th><th>' + tr('col.action') + '</th><th>' + tr('audit.col_vdom') + '</th><th>' + tr('col.comments') + '</th></tr></thead><tbody>';
    results.forEach(p => {
      const jh = tr('audit.jump_hint');
      h += `<tr><td class="mono"><span class="clickable-cell" onclick="window._jumpToPolicy(${JSON.stringify(p.id).replace(/"/g,'&quot;')})" title="${esc(jh)}">${esc(p.id)}</span></td><td>${esc(p.name||'-')}</td><td class="mono">${esc(p.srcAddr||'-')}</td><td class="mono">${esc(p.dstAddr||'-')}</td><td class="mono">${esc(p.service||'-')}</td><td>${esc(p.action||'-')}</td><td style="color:var(--text-dim)">${esc(p._vdom||'-')}</td><td style="color:var(--text-dim)">${esc(p.comments||'-')}</td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  }

  // 過大／巢狀過深群組物件稽核渲染（2026-09-23 新增）：同一群組物件可能同時命中「成員過多」
  // 與「巢狀過深」兩種 issue，各自獨立一列顯示，不合併，避免單列塞兩種不同語意的數值
  const _OVERSIZED_GROUP_ISSUE_LABEL = { members: 'audit.issue_too_many_members', depth: 'audit.issue_too_deep' };
  // 重複物件（2026-10-07，第十三輪 NI）：同一 VDOM 內值相同但名稱不同的位址／服務物件，以及成員完全相同的群組，
  // 可合併成一個以簡化維護。各廠牌欄位寫法不同，比對前先正規化：位址取 subnet（「位址 遮罩」「位址/遮罩」
  // 「位址/長度」「單一位址」一律轉成 CIDR）、範圍取 startIp-endIp、FQDN 取小寫；服務取協定＋TCP／UDP 埠＋ICMP 類型
  // （ASA 為 proto＋port）；群組取排序後的成員清單。內建物件不列。值為空或 '-' 的物件不比對
  function _dupMaskLen(m) {
    if (/^\d+$/.test(m)) return +m;
    const p = m.split('.').map(Number);
    if (p.length !== 4 || p.some(x => isNaN(x) || x < 0 || x > 255)) return null;
    const bits = p.map(x => x.toString(2).padStart(8, '0')).join('');
    return /^1*0*$/.test(bits) ? bits.indexOf('0') < 0 ? 32 : bits.indexOf('0') : null;
  }
  function _dupNormSubnet(v) {
    const t = String(v || '').trim();
    if (!t || t === '-') return '';
    const m = t.match(/^(\S+?)(?:\s+|\/)(\S+)$/);
    const ip = (m ? m[1] : t).toLowerCase();
    if (ip.includes(':')) return ip + '/' + (m ? m[2] : '128');
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return '';
    const len = m ? _dupMaskLen(m[2]) : 32;
    return len === null ? '' : ip + '/' + len;
  }
  function analyzeDuplicateObjects(parsed) {
    const _vendorEntry = [...VENDOR_BUILTINS.entries()].find(([v]) => (parsed.vendor || '').includes(v));
    const BUILTINS = new Set(_vendorEntry ? _vendorEntry[1] : _COMMON_BUILTINS);
    const dash = v => { const t = String(v == null ? '' : v).trim(); return t === '-' ? '' : t; };
    const isGroup = o => /group/i.test(o.category || '') || o.type === 'group';
    const memberKey = o => { const m = dash(o.members).split(/[\s,]+/).filter(Boolean); return m.length ? [...new Set(m)].sort().join(',') : ''; };
    const addrKey = o => {
      if (isGroup(o)) { const k = memberKey(o); return k ? ['addrgroup', k] : null; }
      const fq = dash(o.fqdn); if (fq && /fqdn/i.test(o.type || '')) return ['address', 'fqdn:' + fq.toLowerCase()];
      const s = dash(o.startIp), e = dash(o.endIp); if (s && e) return ['address', 'range:' + s + '-' + e];
      const n = _dupNormSubnet(o.subnet); return n ? ['address', n] : null;
    };
    const svcKey = o => {
      if (isGroup(o) && !dash(o.port)) { const k = memberKey(o); return k ? ['svcgroup', k] : null; }
      const proto = dash(o.proto).toLowerCase();
      if (dash(o.port)) return ['service', proto + ':' + dash(o.port).replace(/\s+/g, '')];
      const parts = [dash(o.tcpPorts), dash(o.udpPorts), dash(o.icmpType)];
      if (!proto && !parts.some(Boolean)) return null;
      return ['service', [proto, ...parts].join('|').replace(/\s+/g, '')];
    };
    const groups = new Map();
    const add = (o, k) => {
      if (!k || !o.name || BUILTINS.has(o.name)) return;
      const key = (o._vdom || '') + '\u0000' + k[0] + '\u0000' + k[1];
      if (!groups.has(key)) groups.set(key, { kind: k[0], vdom: o._vdom || '', value: k[1], names: [] });
      const g = groups.get(key);
      if (!g.names.includes(o.name)) g.names.push(o.name);
    };
    (parsed.addresses || []).forEach(o => add(o, addrKey(o)));
    (parsed.services || []).forEach(o => add(o, svcKey(o)));
    return [...groups.values()].filter(g => g.names.length > 1);
  }
  function buildDuplicateObjectsHtml(results) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--yellow);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + esc(tr('audit.dup_obj_title')) + '</div>';
    if (!results.length) return h + '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('audit.dup_obj_none')) + '</div></div>';
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:10px;padding:6px 10px;background:var(--bg2);border-radius:4px;border-left:3px solid var(--yellow)">' + esc(tr('audit.dup_obj_warn')) + '</div>';
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('audit.col_category') + '</th><th>' + tr('audit.dup_obj_col_value') + '</th><th>' + tr('audit.col_vdom') + '</th><th>' + tr('audit.dup_obj_col_names') + '</th></tr></thead><tbody>';
    results.forEach(r => {
      h += `<tr><td>${pill(tr('audit.dup_kind_' + r.kind), 'p-info')}</td><td class="mono" style="word-break:break-all">${esc(r.value)}</td><td style="color:var(--text-dim)">${esc(r.vdom || '-')}</td><td class="mono" style="color:var(--accent)">${r.names.map(esc).join(', ')}</td></tr>`;
    });
    return h + '</tbody></table></div></div>';
  }

  function buildOversizedGroupsHtml(results) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--yellow);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + esc(tr('audit.oversized_group_title')) + '</div>';
    if (!results.length) {
      h += '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('audit.oversized_group_none')) + '</div></div>';
      return h;
    }
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:10px;padding:6px 10px;background:var(--bg2);border-radius:4px;border-left:3px solid var(--yellow)">' + esc(tr('audit.oversized_group_warn')) + '</div>';
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('audit.col_category') + '</th><th>' + tr('audit.col_name') + '</th><th>' + tr('audit.col_vdom') + '</th><th>' + tr('audit.col_issue_type') + '</th><th>' + tr('audit.col_count') + '</th></tr></thead><tbody>';
    results.forEach(r => {
      const issueLabel = tr(_OVERSIZED_GROUP_ISSUE_LABEL[r.issue]);
      h += `<tr><td>${pill(r.category,'p-info')}</td><td class="mono" style="color:var(--accent)">${esc(r.name)}</td><td style="color:var(--text-dim)">${esc(r.vdom||'-')}</td><td>${pill(issueLabel,'p-warn')}</td><td class="mono">${r.value}</td></tr>`;
    });
    h += '</tbody></table></div></div>';
    return h;
  }

  // 證據行（AA）：可展開的原始設定行清單（多檔時標示檔名）；有命中但找不到對應行時顯示說明
  function _buildEvidenceDetails(f, ev) {
    if (!f.value || !ev) return '';
    if (!ev.length) return `<div style="font-size:10px;color:var(--text-muted);margin-top:3px">${esc(tr('audit.evidence_none'))}</div>`;
    const multi = new Set(ev.map(e => e.src)).size > 1;
    return `<details style="margin-top:4px"><summary style="cursor:pointer;font-size:11px;color:var(--accent)">${esc(tr('audit.evidence').replace('{n}', ev.length))}</summary>`
      + `<pre style="margin:4px 0 0;padding:6px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;font-size:11px;line-height:1.5;white-space:pre-wrap;max-height:220px;overflow:auto">`
      + ev.map(e => `<span style="color:var(--text-muted)">${multi ? esc(e.src) + ' ' : ''}L${e.line}</span>  ${esc(e.text)}`).join('\n') + '</pre></details>';
  }
  // 為什麼重要／怎麼修（NB）：白話說明（i18n fix.<id>）＋ FortiGate 修正指令範例
  function _buildFixDetails(f, vendor) {
    if (!f.value) return '';
    const why = tr('fix.' + f.id);
    if (!why || why === 'fix.' + f.id) return '';
    const cmd = buildFirewallFixCommands(f, vendor);
    return `<details style="margin-top:4px"><summary style="cursor:pointer;font-size:11px;color:var(--accent)">${esc(tr('fix.title'))}</summary>`
      + `<div style="font-size:12px;color:var(--text);margin:4px 0;line-height:1.5">${esc(why)}</div>`
      + (cmd ? `<div style="font-size:11px;color:var(--text-dim);margin-top:4px">${esc(tr('fix.cmd_title').replace('{vendor}', 'FortiGate'))}</div>`
        + `<pre style="margin:4px 0 0;padding:6px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;font-size:11px;line-height:1.5;white-space:pre-wrap;max-height:220px;overflow:auto">${esc(cmd)}</pre>`
        + `<div style="font-size:10px;color:var(--text-muted);margin-top:3px">${esc(tr('fix.cmd_note'))}</div>` : '')
      + '</details>';
  }
  // marks（選填，AB）：{發現id:{status,note}}；有提供時多一欄處置狀態＋備註，並在表頭上方顯示審查者欄位與工作底稿匯出按鈕
  function _buildMarkCell(id, m) {
    const opt = st => `<option value="${st}"${(m.status || 'open') === st ? ' selected' : ''}>${esc(tr('wp.status_' + st))}</option>`;
    return `<select aria-label="${esc(tr('wp.col_status'))}" onchange="window._fwSetAuditMark('${id}','status',this.value)" style="font-size:11px;padding:2px 4px;margin-bottom:3px">${AUDIT_MARK_STATUSES.map(opt).join('')}</select>`
      + `<input value="${esc(m.note || '')}" placeholder="${esc(tr('wp.note_ph'))}" aria-label="${esc(tr('wp.col_note'))}" onchange="window._fwSetAuditMark('${id}','note',this.value)" style="font-size:11px;padding:2px 4px;width:120px;display:block">`;
  }
  function buildComplianceHtml(findings, evidence, vendor, marks, reviewer) {
    const rp = r => r === 'high' ? pill(tr('audit.risk_high'),'p-deny') : r === 'medium' ? pill(tr('audit.risk_mid'),'p-warn') : pill(tr('audit.risk_low'),'p-allow');
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--purple);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + tip('tip.compliance', tr('audit.compliance_title')) + '</div>';
    h += `<div style="color:var(--text-dim);font-size:11px;margin-bottom:8px">${esc(tr('audit.standards_disclaimer'))}</div>`;
    if (marks) h += `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:6px"><button class="btn btn-ghost btn-sm" onclick="window._fwExportWorkpaper()">📋 ${esc(tr('wp.export_btn'))}</button><input id="fw-audit-reviewer" value="${esc(reviewer || '')}" placeholder="${esc(tr('wp.reviewer_ph'))}" aria-label="${esc(tr('wp.col_reviewer'))}" onchange="window._fwSetAuditReviewer(this.value)" style="font-size:12px;padding:3px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg2);color:var(--text);width:140px"><span style="font-size:11px;color:var(--text-muted)">${esc(tr('wp.hint'))}</span></div>`;
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('audit.col_check') + '</th><th>' + tr('audit.col_result') + '</th><th>' + tr('audit.col_risk') + '</th><th>' + tr('audit.col_detail') + '</th><th>' + tr('audit.col_standards') + '</th>' + (marks ? '<th>' + tr('wp.col_status') + '</th>' : '') + '</tr></thead><tbody>';
    findings.forEach(f => {
      const ok = f.value === 0;
      const vc = (!ok && f.risk !== 'low') ? 'var(--red)' : 'var(--green)';
      const stdBadges = (f.standards||[]).map(s => `<span style="display:inline-block;margin:1px 3px 1px 0;padding:1px 6px;border-radius:3px;font-size:10px;background:var(--surface2);color:var(--text-dim);border:1px solid var(--border)">${esc(s)}</span>`).join('');
      h += `<tr><td>${esc(f.check)}</td><td class="mono" style="color:${vc};font-weight:600">${esc(String(f.value))}</td><td>${rp(f.risk)}</td><td style="color:var(--text-dim);font-size:11px">${esc(f.detail)}${_buildEvidenceDetails(f, evidence && evidence[f.id])}${_buildFixDetails(f, vendor)}</td><td style="font-size:11px;white-space:normal;min-width:220px">${stdBadges || '-'}</td>${marks ? `<td>${f.value ? _buildMarkCell(f.id, marks[f.id] || {}) : '-'}</td>` : ''}</tr>`;
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
      <button class="btn btn-ghost btn-sm" onclick="doExport('csv-diff-nat')">⬇ CSV: ${esc(tr('diff.title_nat'))}</button>
      <button class="btn btn-ghost btn-sm" onclick="doExport('csv-diff-vpn')">⬇ CSV: ${esc(tr('diff.title_vpn'))}</button>
      <button class="btn btn-ghost btn-sm" onclick="doExport('csv-diff-interfaces')">⬇ CSV: ${esc(tr('diff.title_interfaces'))}</button>
    </div>`;
    return bar
      + _buildDiffSection('diff.title_policies', diffResult.policies)
      + _buildDiffSection('diff.title_addresses', diffResult.addresses)
      + _buildDiffSection('diff.title_services', diffResult.services)
      + _buildDiffSection('diff.title_routes', diffResult.routes)
      + _buildDiffSection('diff.title_nat', diffResult.nat)
      + _buildDiffSection('diff.title_vpn', diffResult.vpn)
      + _buildDiffSection('diff.title_interfaces', diffResult.interfaces);
  }

  // ── 合規基準快照 + drift 比對（2026-09-15 新增）───────────────────────
  // 完整複用既有 diffArrayByKey()：analyzeCompliance() 每筆發現已有穩定短字串 id（'any-any'／
  // 'no-2fa'／'weak-vpn' 等固定集合），天生適合當 diff key；一行 wrapper 即可，不需要另外
  // 實作一套比對邏輯。與既有「上傳新舊設定檔比較」diffConfigs() 語意刻意區隔——那個比的是
  // 設定檔本身，這個比的是合規檢查「結果」（風險等級/命中數量隨時間的變化趨勢）。
  function diffCompliance(oldFindings, newFindings) {
    return diffArrayByKey(oldFindings, newFindings, f => f.id, ['value', 'risk', 'detail']);
  }
  // 渲染：不比照 _buildDiffSection() 的通用 diffFields 清單顯示（那是給「任意欄位變動」用的
  // 泛用格式），改為針對合規發現的語意客製——直接顯示 old.value→new.value 與風險等級本身，
  // 比通用 diffFields 陣列（如 "value, risk"）更能一眼看出「發生數從幾筆變幾筆」
  const _RISK_PILL_TYPE = { high: 'p-deny', medium: 'p-warn', low: 'p-info' };
  function _riskLabel(risk) {
    return risk === 'high' ? tr('audit.risk_high') : risk === 'medium' ? tr('audit.risk_mid') : tr('audit.risk_low');
  }
  function buildComplianceDiffHtml(diffResult) {
    const total = diffResult.added.length + diffResult.removed.length + diffResult.changed.length;
    if (!total) return `<div class="nodata" style="padding:14px 0;color:var(--green)">${esc(tr('diff.none_found'))}</div>`;
    // CSV 匯出按鈕（2026-09-21 新增），比照 buildDiffHtml() 既有 bar 樣式
    let h = `<div style="display:flex;gap:8px;margin-bottom:12px"><button class="btn btn-ghost btn-sm" onclick="doExport('csv-compliance-diff')">⬇ ${esc(tr('baseline.export_csv_btn'))}</button></div>`;
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('diff.col_status') + '</th><th>' + tr('audit.col_check') + '</th><th>' + tr('baseline.col_old') + '</th><th>' + tr('baseline.col_new') + '</th></tr></thead><tbody>';
    diffResult.added.forEach(f => {
      h += `<tr><td>${pill(tr('diff.status_added'), 'p-allow')}</td><td>${esc(f.check)}</td><td class="mono">-</td><td class="mono">${f.value} ${pill(_riskLabel(f.risk), _RISK_PILL_TYPE[f.risk] || 'p-info')}</td></tr>`;
    });
    diffResult.removed.forEach(f => {
      h += `<tr><td>${pill(tr('diff.status_removed'), 'p-deny')}</td><td>${esc(f.check)}</td><td class="mono">${f.value} ${pill(_riskLabel(f.risk), _RISK_PILL_TYPE[f.risk] || 'p-info')}</td><td class="mono">-</td></tr>`;
    });
    diffResult.changed.forEach(c => {
      h += `<tr><td>${pill(tr('diff.status_changed'), 'p-warn')}</td><td>${esc(c.new.check)}</td><td class="mono">${c.old.value} ${pill(_riskLabel(c.old.risk), _RISK_PILL_TYPE[c.old.risk] || 'p-info')}</td><td class="mono">${c.new.value} ${pill(_riskLabel(c.new.risk), _RISK_PILL_TYPE[c.new.risk] || 'p-info')}</td></tr>`;
    });
    h += '</tbody></table></div>';
    return h;
  }

  // ── 健康度評估 ─────────────────────────────────────────────────
  // opts.acceptedRisks（2026-09-24 新增）：已由使用者標記為「接受風險」的項目 key 清單
  // （Set 或陣列，key＝health.* i18n key 去掉前綴，如 'any_any'）。命中者不扣分，但仍保留在
  // issues 內並標 accepted:true，讓畫面／報表能顯示「已接受」而非讓問題憑空消失；未傳 opts
  // 時行為與先前完全相同
  function computeFirewallHealth(parsed, opts) {
    const policies = parsed.policies || [];
    let score = 100;
    const issues = [];
    const acceptedRisks = (opts && opts.acceptedRisks) ? new Set(opts.acceptedRisks) : new Set();
    // 每項扣分上限（2026-09-24 使用者決定）：逐筆扣分但單一檢查最多扣「每筆權重×3」，避免
    // 規則缺備註、孤兒物件等逐筆累加的項目在真實設定檔（數百條規則）把分數一律壓到 0 分，
    // 讓健康度失去區辨力；達上限者標 capped:true 供畫面提示實際數量比扣分反映的更多
    const HEALTH_CAP_MULTIPLIER = 3;
    const deduct = (labelKey, sev, count, amount, perItem) => {
      const key = labelKey.replace(/^health\./, '');
      if (acceptedRisks.has(key)) { issues.push({ key, sev, label: tr(labelKey), count, accepted: true }); return; }
      const cap = perItem * HEALTH_CAP_MULTIPLIER;
      const capped = amount > cap;
      score -= capped ? cap : amount;
      issues.push(capped ? { key, sev, label: tr(labelKey), count, capped: true } : { key, sev, label: tr(labelKey), count });
    };
    // T1: any-any accept（需排除已停用規則，比照下方 T1b/broad-network 既有慣例；
    // 先前漏了這道防呆，已停用的 any-any/no-log 規則從未真正生效卻仍被扣分，2026-09 全功能審查發現）
    const anyAny = policies.filter(p => p.action === 'accept' && !_isDisabledStatus(p) && /^(all|any)$/i.test((p.srcAddr||'').trim()) && /^(all|any)$/i.test((p.dstAddr||'').trim()));
    if (anyAny.length) deduct('health.any_any', 'crit', anyAny.length, anyAny.length * 20, 20);
    // T1b: broad-network（2026-08-29 新增，比照 analyzeCompliance() 的 broad-network 檢查同一套
    // 判斷邏輯，權重較 any-any 低——過寬網段風險低於完全開放，但仍值得扣分）
    // key 帶 vdom 前綴，理由與修法同 analyzeCompliance() 的 broad-network 檢查（2026-09-22 修復）
    const healthVk = (vdom, name) => (vdom ? vdom + '/' : '') + name;
    const healthAddrByName = new Map((parsed.addresses || []).map(a => [healthVk(a._vdom, a.name), a]));
    const healthAddrPrefixLen = (val, vdom) => {
      if (!val) return null;
      const literal = _extractLiteralCidrPrefixLen(val);
      if (literal !== null) return literal;
      const obj = healthAddrByName.get(healthVk(vdom, val));
      return (obj && obj.type === 'ipmask' && obj.subnet) ? _extractLiteralCidrPrefixLen(obj.subnet) : null;
    };
    const healthIsBroad = (val, vdom) => String(val || '').split(',').map(s => s.trim()).filter(Boolean)
      .some(p => { const len = healthAddrPrefixLen(p, vdom); return len !== null && len <= 8; });
    const broadNetwork = policies.filter(p => p.action === 'accept' && !_isDisabledStatus(p) && (healthIsBroad(p.srcAddr, p._vdom) || healthIsBroad(p.dstAddr, p._vdom)));
    if (broadNetwork.length) deduct('health.broad_network', 'warn', broadNetwork.length, broadNetwork.length * 10, 10);
    // T2: shadowed rules
    const shadowMap = buildShadowMap(policies, parsed.addresses);
    const shadowCount = Object.values(shadowMap).reduce((s, arr) => s + arr.length, 0);
    if (shadowCount) deduct('health.shadowed', 'warn', shadowCount, shadowCount * 5, 5);
    // T2b: rules blocked by an earlier deny rule（同 T2 權重，皆屬「規則永不生效」類問題）
    const denyBlockedCount = analyzeDenyBlocking(policies, parsed.addresses).length;
    if (denyBlockedCount) deduct('health.deny_blocked', 'warn', denyBlockedCount, denyBlockedCount * 5, 5);
    // T3: disabled rules（欄位值一律是 'disable'，非 'disabled'，見 _runPolicyQuery()/各 assemble 函式既有慣例；
    // 大小寫不敏感比對改用共用 _isDisabledStatus()，先前純小寫比對會 undercount Sophos 等大寫來源，
    // 2026-09-18 根因性修復，與 T1/T1b/T4 統一）
    const disabled = policies.filter(p => _isDisabledStatus(p) || p.enabled === false || p.enabled === 'disable');
    if (disabled.length > 3) deduct('health.disabled', 'info', disabled.length, (disabled.length - 3) * 2, 2);
    // T4: accept without log（欄位名稱是全小寫 logtraffic，非 logTraffic；判斷式比照 analyzeCompliance() 既有慣例，
    // 同樣需排除已停用規則，原因同 T1，2026-09 全功能審查發現）
    const noLog = policies.filter(p => p.action === 'accept' && !_isDisabledStatus(p) && (!p.logtraffic || p.logtraffic === 'disable' || p.logtraffic === 'utm'));
    if (noLog.length > 2) deduct('health.no_log', 'warn', noLog.length, (noLog.length - 2) * 3, 3);
    // T5-T11：其餘 7 項合規檢查納入健康度評分（2026-08-31 新增）。先前只有上方 4 項（any-any／
    // broad-network／disabled／no-log）會扣分，`analyzeCompliance()` 其餘 7 項發現完全不影響
    // 分數，是探勘功能4「弱加密VPN/預設帳號偵測」時發現的真實缺口（該兩項本身早已存在，缺口
    // 在於評分未涵蓋）。直接重用 `analyzeCompliance(parsed)` 已計算好的 findings，避免重新
    // implement 一次 isPrivileged/WEAK regex 等複雜判斷邏輯（risk 分級沿用該函式既有的
    // high/medium/low 標記，扣分權重比照既有 T1(-20,high)／T1b(-10,medium)／T4(-3) 的相對
    // 級距：high 比照 broad-network 定為 -10／medium 定為 -5／low 定為 -3）
    const complianceFindings = analyzeCompliance(parsed);
    const HEALTH_WEIGHT = { high: 10, medium: 5, low: 3 };
    const HEALTH_EXTRA_CHECKS = [
      ['snmp-v1v2', 'health.snmp_weak'],
      ['no-2fa', 'health.no_2fa'],
      ['http-mgmt', 'health.http_mgmt'],
      ['weak-vpn', 'health.weak_vpn'],
      ['vpn-no-pfs', 'health.vpn_no_pfs'],
      ['default-admin-name', 'health.default_admin'],
      ['snmpv3-weak', 'health.snmpv3_weak'],
      ['ipv6-any-open', 'health.ipv6_any_open'],
      ['ipv6-unfiltered', 'health.ipv6_unfiltered'],
    ];
    HEALTH_EXTRA_CHECKS.forEach(([id, labelKey]) => {
      const found = complianceFindings.find(f => f.id === id);
      if (found && found.value > 0) {
        const weight = HEALTH_WEIGHT[found.risk] || HEALTH_WEIGHT.low;
        deduct(labelKey, found.risk === 'high' ? 'crit' : found.risk === 'medium' ? 'warn' : 'info', found.value, found.value * weight, weight);
      }
    });
    // T12-T14：NAT 規則健檢納入健康度評分（2026-09-01 新增，功能5）。dup_ip／port_conflict
    // 沿用既有 T1b(broad-network,-10,medium) 同一相對級距的 medium 權重（-5）；孤兒 NAT 屬於
    // 「設定衛生」而非直接安全風險，權重比照既有 T3(disabled,-2)／HEALTH_WEIGHT.low(-3) 級距
    // 定為 low(-3)，且刻意不對 Cisco ASA／SonicWall 執行（見 analyzeOrphanNAT() 排除清單）。
    const natWarns = analyzeNAT(parsed.nat);
    const natDupIp = natWarns.filter(w => w.type === 'dup_ip').length;
    if (natDupIp) deduct('health.nat_dup_ip', 'warn', natDupIp, natDupIp * HEALTH_WEIGHT.medium, HEALTH_WEIGHT.medium);
    const natPortConflict = natWarns.filter(w => w.type === 'port_conflict').length;
    if (natPortConflict) deduct('health.nat_port_conflict', 'warn', natPortConflict, natPortConflict * HEALTH_WEIGHT.medium, HEALTH_WEIGHT.medium);
    const orphanNatCount = analyzeOrphanNAT(parsed).length;
    if (orphanNatCount) deduct('health.nat_orphan', 'info', orphanNatCount, orphanNatCount * HEALTH_WEIGHT.low, HEALTH_WEIGHT.low);
    // T15：孤兒 VPN 物件（2026-09-15 新增），權重比照孤兒 NAT 同屬「設定衛生」訊號，同為 low
    const orphanVpnCount = analyzeOrphanVPN(parsed).length;
    if (orphanVpnCount) deduct('health.vpn_orphan', 'info', orphanVpnCount, orphanVpnCount * HEALTH_WEIGHT.low, HEALTH_WEIGHT.low);
    // T16：規則缺無備註（2026-09-23 新增），權重比照孤兒 NAT/VPN 同屬「設定衛生」訊號，同為 low
    const missingCommentsCount = analyzeMissingComments(parsed).length;
    if (missingCommentsCount) deduct('health.missing_comments', 'info', missingCommentsCount, missingCommentsCount * HEALTH_WEIGHT.low, HEALTH_WEIGHT.low);
    // T17：過大／巢狀過深群組物件（2026-09-23 新增），權重同上
    const oversizedGroupCount = analyzeOversizedGroups(parsed).length;
    if (oversizedGroupCount) deduct('health.oversized_group', 'info', oversizedGroupCount, oversizedGroupCount * HEALTH_WEIGHT.low, HEALTH_WEIGHT.low);
    // T18：臨時規則到期（第十二輪 MF）——備註寫明到期卻仍啟用屬實際開放風險（medium）；
    // 單次排程已過期的規則已不放行流量，屬設定衛生（low）
    const expired = analyzeExpiredRules(parsed, { now: opts && opts.now, keywords: opts && opts.expiryKeywords }).results.filter(r => r.status === 'expired');
    const expComment = expired.filter(r => r.source === 'comment').length;
    if (expComment) deduct('health.rule_expired', 'warn', expComment, expComment * HEALTH_WEIGHT.medium, HEALTH_WEIGHT.medium);
    const expSched = expired.filter(r => r.source === 'schedule').length;
    if (expSched) deduct('health.schedule_expired', 'info', expSched, expSched * HEALTH_WEIGHT.low, HEALTH_WEIGHT.low);
    score = Math.max(0, Math.min(100, score));
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
    const gradeColor = grade === 'A' ? 'var(--green)' : grade === 'B' ? 'var(--teal)' : grade === 'C' ? 'var(--yellow)' : grade === 'D' ? 'var(--orange)' : 'var(--red)';
    return {score, grade, gradeColor, issues};
  }

  // 命名規範檢查（2026-09-24 新增）：rules = {address, service, policy} 三條使用者自訂正則字串
  // （空字串代表不檢查該類）。正則區分大小寫（命名規範通常大小寫有意義）；無效正則不拋錯，
  // 改回報在 errors 讓畫面提示。all/any/none 為多數廠牌內建位址名稱，不列入；沒有名稱或名稱
  // 為 '-' 的規則也略過（規則名稱在部分廠牌本來就是選填）。不計入健康度——命名規範屬團隊自訂
  // 標準而非安全風險
  const NAMING_BUILTIN_ADDR = new Set(['all', 'any', 'none']);
  function analyzeNamingConvention(parsed, rules) {
    const results = [], errors = [];
    const mk = (kind) => {
      const src = (rules && rules[kind]) || '';
      if (!src) return null;
      try { return new RegExp(src); } catch (e) { errors.push(kind); return null; }
    };
    const ra = mk('address'), rs = mk('service'), rp = mk('policy');
    if (ra) (parsed.addresses || []).forEach(a => {
      if (!a.name || NAMING_BUILTIN_ADDR.has(String(a.name).toLowerCase())) return;
      if (!ra.test(a.name)) results.push({ kind: 'address', id: '', name: a.name, vdom: a._vdom || '' });
    });
    if (rs) (parsed.services || []).forEach(sv => {
      if (!sv.name) return;
      if (!rs.test(sv.name)) results.push({ kind: 'service', id: '', name: sv.name, vdom: sv._vdom || '' });
    });
    if (rp) (parsed.policies || []).forEach(p => {
      if (!p.name || p.name === '-') return;
      if (!rp.test(p.name)) results.push({ kind: 'policy', id: p.id, name: p.name, vdom: p._vdom || '' });
    });
    return { results, errors };
  }
  function buildNamingConventionHtml(res, rules) {
    const kindLabel = { address: tr('naming.kind_address'), service: tr('naming.kind_service'), policy: tr('naming.kind_policy') };
    const inp = (kind) => `<label style="display:flex;flex-direction:column;gap:2px;font-size:11px;color:var(--text-dim)">${esc(kindLabel[kind])}<input id="naming-${kind}" class="mono" value="${esc((rules && rules[kind]) || '')}" placeholder="^[A-Z]" style="width:200px;padding:4px 6px;border:1px solid var(--border);border-radius:4px;background:var(--surface2);color:var(--text)"></label>`;
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--teal);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + esc(tr('naming.title')) + '</div>';
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:8px">' + esc(tr('naming.hint')) + '</div>';
    h += `<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px">${inp('address')}${inp('service')}${inp('policy')}<button class="btn btn-ghost btn-sm" onclick="window._applyNamingRules()">${esc(tr('naming.apply'))}</button></div>`;
    if (res.errors.length) h += `<div style="color:var(--red);font-size:12px;margin-bottom:8px">${esc(tr('naming.regex_error').replace('{items}', res.errors.map(k => kindLabel[k]).join(', ')))}</div>`;
    const anyRule = rules && (rules.address || rules.service || rules.policy);
    if (!anyRule) return h + '</div>';
    if (!res.results.length) return h + '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('naming.none')) + '</div></div>';
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>' + tr('naming.col_kind') + '</th><th>ID</th><th>' + tr('audit.col_name') + '</th><th>' + tr('audit.col_vdom') + '</th></tr></thead><tbody>';
    res.results.forEach(r => {
      const idCell = r.kind === 'policy' ? `<span class="clickable-cell" onclick="window._jumpToPolicy(${JSON.stringify(r.id).replace(/"/g,'&quot;')})" title="${esc(tr('audit.jump_hint'))}">${esc(r.id)}</span>` : '-';
      h += `<tr><td>${pill(kindLabel[r.kind], 'p-info')}</td><td class="mono">${idCell}</td><td class="mono" style="color:var(--accent)">${esc(r.name)}</td><td style="color:var(--text-dim)">${esc(r.vdom || '-')}</td></tr>`;
    });
    return h + '</tbody></table></div></div>';
  }

  // 臨時規則到期稽核（第十二輪 MF）：兩種來源——(1) 規則引用的單次排程已過期（FortiGate
  // `config firewall schedule onetime` 的 end「hh:mm yyyy/mm/dd」、Palo Alto non-recurring
  // 「YYYY/MM/DD@hh:mm-YYYY/MM/DD@hh:mm」，皆依官方格式）；(2) 規則名稱或備註在到期關鍵字後
  // 寫了日期（只認年在前的 YYYY-MM-DD／YYYY/MM/DD／YYYY.MM.DD／YYYYMMDD，DD/MM 與 MM/DD
  // 無法區分不判斷）。只看啟用中的規則；status 為 expired（已過期）或 soon（30 天內到期）。
  // keywords 為使用者自訂正則（空字串用預設），無效正則回報在 error 並改用預設
  const EXPIRY_DEFAULT_KEYWORDS = 'expire[sd]?|expiry|expiration|exp(?![a-z])|until|valid\\s+to|到期|期限|截止|有效';
  const EXPIRY_SOON_DAYS = 30;
  function _ymdDay(y, m, d) {
    y = +y; m = +m; d = +d;
    if (m < 1 || m > 12 || d < 1 || d > 31) return null;
    const t = Date.UTC(y, m - 1, d);
    const dt = new Date(t);
    if (dt.getUTCMonth() !== m - 1) return null; // 2月30日之類不存在的日期
    return Math.floor(t / 864e5);
  }
  function analyzeExpiredRules(parsed, opts) {
    opts = opts || {};
    const now = new Date(opts.now || Date.now());
    const today = Math.floor(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()) / 864e5);
    let kwSrc = (opts.keywords || '').trim(), error = false, re;
    try { re = new RegExp('(?:' + (kwSrc || EXPIRY_DEFAULT_KEYWORDS) + ')[^\\d\\n]{0,4}?\\d{4}(?:[-/.]\\d{1,2}[-/.]\\d{1,2}|\\d{4})(?!\\d)', 'gi'); }
    catch (e) { error = true; re = new RegExp('(?:' + EXPIRY_DEFAULT_KEYWORDS + ')[^\\d\\n]{0,4}?\\d{4}(?:[-/.]\\d{1,2}[-/.]\\d{1,2}|\\d{4})(?!\\d)', 'gi'); }
    const sched = new Map();
    (parsed.schedules || []).forEach(s => {
      if (s.type !== 'onetime') return;
      const m = String(s.end || '').match(/(\d{4})\/(\d{1,2})\/(\d{1,2})/);
      const day = m && _ymdDay(m[1], m[2], m[3]);
      if (day === null || day === undefined) return;
      const v = { day, raw: s.end };
      sched.set((s._vdom || '') + '\u0000' + s.name, v);
      if (!sched.has('\u0000' + s.name)) sched.set('\u0000' + s.name, v);
    });
    const fmt = day => new Date(day * 864e5).toISOString().slice(0, 10);
    const results = [];
    (parsed.policies || []).forEach(p => {
      if (_isDisabledStatus(p) || p.enabled === false) return;
      const push = (source, day, ref) => {
        const days = day - today;
        if (days > EXPIRY_SOON_DAYS) return;
        results.push({ id: p.id, name: p.name || '-', vdom: p._vdom || '', source, ref, date: fmt(day), days, status: days < 0 ? 'expired' : 'soon' });
      };
      const sn = p.schedule;
      if (sn && !/^(always|any|none|-)$/i.test(sn)) {
        const v = sched.get((p._vdom || '') + '\u0000' + sn) || sched.get('\u0000' + sn);
        if (v) push('schedule', v.day, sn);
      }
      const text = [p.name, p.comments].filter(x => x && x !== '-').join('\n');
      let best = null, m;
      re.lastIndex = 0;
      while ((m = re.exec(text)) !== null) {
        const d = m[0].match(/(\d{4})(?:[-/.](\d{1,2})[-/.](\d{1,2})|(\d{2})(\d{2}))$/);
        const day = d && _ymdDay(d[1], d[2] || d[4], d[3] || d[5]);
        if (day !== null && day !== undefined && (best === null || day > best.day)) best = { day, ref: m[0].trim() };
        if (m[0].length === 0) re.lastIndex++;
      }
      if (best) push('comment', best.day, best.ref);
    });
    results.sort((a, b) => a.days - b.days);
    return { results, error };
  }
  function buildExpiredRulesHtml(res, keywords) {
    let h = '<div style="margin-bottom:24px"><div style="font-size:13px;font-weight:600;color:var(--teal);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)">' + esc(tr('expiry.title')) + '</div>';
    h += '<div style="font-size:11px;color:var(--text-dim);margin-bottom:8px">' + esc(tr('expiry.hint')) + '</div>';
    h += `<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px"><label style="display:flex;flex-direction:column;gap:2px;font-size:11px;color:var(--text-dim)">${esc(tr('expiry.keywords'))}<input id="expiry-keywords" class="mono" value="${esc(keywords || '')}" placeholder="${esc(EXPIRY_DEFAULT_KEYWORDS)}" style="width:320px;max-width:100%;padding:4px 6px;border:1px solid var(--border);border-radius:4px;background:var(--surface2);color:var(--text)"></label><button class="btn btn-ghost btn-sm" onclick="window._applyExpiryKeywords()">${esc(tr('naming.apply'))}</button></div>`;
    if (res.error) h += `<div style="color:var(--red);font-size:12px;margin-bottom:8px">${esc(tr('expiry.regex_error'))}</div>`;
    if (!res.results.length) return h + '<div class="nodata" style="padding:14px 0;color:var(--green)">' + esc(tr('expiry.none')) + '</div></div>';
    const jh = tr('audit.jump_hint');
    h += '<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>ID</th><th>' + tr('audit.col_name') + '</th><th>' + tr('audit.col_vdom') + '</th><th>' + esc(tr('expiry.col_source')) + '</th><th>' + esc(tr('expiry.col_date')) + '</th><th>' + esc(tr('expiry.col_status')) + '</th></tr></thead><tbody>';
    res.results.forEach(r => {
      const st = r.status === 'expired'
        ? pill(tr('expiry.expired').replace('{n}', -r.days), 'p-deny')
        : pill(tr('expiry.soon').replace('{n}', r.days), 'p-warn');
      const src = (r.source === 'schedule' ? tr('expiry.src_schedule') : tr('expiry.src_comment')) + ': ' + r.ref;
      h += `<tr><td class="mono"><span class="clickable-cell" onclick="window._jumpToPolicy(${JSON.stringify(r.id).replace(/"/g,'&quot;')})" title="${esc(jh)}">${esc(r.id)}</span></td><td>${esc(r.name)}</td><td style="color:var(--text-dim)">${esc(r.vdom || '-')}</td><td style="font-size:11px">${esc(src)}</td><td class="mono">${esc(r.date)}</td><td>${st}</td></tr>`;
    });
    return h + '</tbody></table></div></div>';
  }

  // 健康度歷史折線圖（2026-09-24 新增）：比照 switch-analyzer-audit.js buildHealthSparklineSVG()
  // 同一套零依賴 inline SVG 寫法（各工具各自維護一份純函式的既有慣例）。entries 為「新到舊」，
  // 繪圖時反轉成由左至右的舊到新
  function buildHealthSparklineSVG(entries) {
    const w = 280, h = 60, pad = 6;
    const list = (entries || []).slice().reverse();
    if (!list.length) return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"></svg>`;
    const yOf = score => pad + (100 - score) / 100 * (h - 2 * pad);
    const titleOf = e => `${e.score} (${new Date(e.ts).toLocaleDateString()})`;
    if (list.length === 1) {
      const y = yOf(list[0].score);
      return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"><circle cx="${w / 2}" cy="${y.toFixed(1)}" r="3" fill="var(--accent)"><title>${titleOf(list[0])}</title></circle></svg>`;
    }
    const stepX = (w - 2 * pad) / (list.length - 1);
    const pts = list.map((e, i) => ({ x: pad + i * stepX, y: yOf(e.score), e }));
    const path = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    const dots = pts.map(p => `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.5" fill="var(--accent)"><title>${titleOf(p.e)}</title></circle>`).join('');
    return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"><path d="${path}" fill="none" stroke="var(--accent)" stroke-width="1.5"/>${dots}</svg>`;
  }

  // 無法解析設定檔回報觸發判斷（2026-09-29 新增）：unknownSlots 為上傳時未命中任何廠牌簽章的
  // 欄位廠牌清單（app.js 在 detectFwVendor() 檢查時收集）；有值即 'unknown_vendor'。否則若介面、
  // 規則、位址物件、路由四者皆為 0 視為 'sparse'（防火牆設定檔幾乎必定至少有介面或規則）；
  // 其餘回傳 ''。門檻刻意保守，避免精簡但正常的設定檔也跳出提示
  function fwReportTrigger(parsed, unknownSlots) {
    if (unknownSlots && unknownSlots.length) return 'unknown_vendor';
    const p = parsed || {};
    const n = k => (p[k] || []).length;
    if (!n('interfaces') && !n('policies') && !n('addresses') && !n('routes')) return 'sparse';
    return '';
  }
  function fwReportStats(parsed) {
    const p = parsed || {};
    return { interfaces: (p.interfaces || []).length, policies: (p.policies || []).length, addresses: (p.addresses || []).length, routes: (p.routes || []).length };
  }

  // ── 全域搜尋比對邏輯（2026-09-23 新增）─────────────────────────────────────
  // 抽出為純函式，供 app.js 的 doGlobalQuery()（負責讀寫 DOM）呼叫，也讓 Node 測試能在
  // 不碰 DOM 的情況下驗證比對邏輯本身。useRegex 開啟時以 try/catch 包住 new RegExp()，
  // 避免使用者輸入無效正則（如未閉合的括號）直接讓整頁報錯；正則建置失敗時退回一般子字串
  // 比對，並回傳 regexError 供呼叫端顯示提示。
  function _buildGlobalSearchMatcher(query, useRegex) {
    if (useRegex) {
      try {
        const re = new RegExp(query, 'i');
        return { test: v => re.test(String(v ?? '')), regexError: false };
      } catch (e) {
        // 無效正則：退回一般文字比對，不讓整頁報錯
      }
    }
    const ql = query.toLowerCase();
    return { test: v => String(v ?? '').toLowerCase().includes(ql), regexError: !!useRegex };
  }

  // 欄位範圍白名單：'all' 沿用既有全部 8 個資料表；其餘為單一資料表限定，供畫面的
  // 欄位範圍下拉選單使用（2026-09-23 新增）
  const GLOBAL_SEARCH_SCOPES = {
    all: ['interfaces', 'policies', 'routes', 'vpn', 'nat', 'addresses', 'services', 'users'],
    policies: ['policies'],
    addresses: ['addresses'],
    services: ['services'],
  };

  function runGlobalSearch(parsed, query, opts) {
    opts = opts || {};
    const q = (query || '').trim();
    if (!q || !parsed) return { results: [], regexError: false };
    const matcher = _buildGlobalSearchMatcher(q, !!opts.useRegex);
    const sections = GLOBAL_SEARCH_SCOPES[opts.scope] || GLOBAL_SEARCH_SCOPES.all;
    const results = sections.map(sec => {
      const arr = parsed[sec] || [];
      const hits = arr.filter(r => Object.values(r).some(v => matcher.test(v))).slice(0, 30);
      return { sec, count: hits.length, rows: hits };
    }).filter(r => r.count > 0);
    return { results, regexError: matcher.regexError };
  }

  // 稽核結果 Markdown 匯出（2026-09-24 新增）：供貼到工單／Wiki。內容重新呼叫 analyze* 系列
  // 即時計算（比照 buildSarifAuditReport() 慣例，不依賴稽核分頁渲染快取）；各區塊命中數與稽核頁
  // 摘要卡片同一組函式，合規檢查與健康度問題另列明細表
  function _mdCell(v) { return String(v == null ? '' : v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, ' '); }
  function buildFirewallExecSummary(host,health){
    // 主管摘要（2026-09-30 新增，第八輪 XG）：報表開頭一段白話文字，給不看細節的主管或客戶。
    // 只用 computeFirewallHealth() 已算好的結果（等級、各項扣分），不另外計算；已標記接受風險者不列入待改善，另行註明
    const active=health.issues.filter(i=>!i.accepted);
    const accepted=health.issues.length-active.length;
    const RANK={crit:0,warn:1,info:2};
    const lines=[tr('exec.grade').replace('{host}',host||'-').replace('{score}',health.score).replace('{grade}',health.grade)+tr('exec.grade_'+health.grade)];
    if(!active.length)lines.push(tr('exec.none'));
    else{
      lines.push(tr('exec.found').replace('{n}',active.length).replace('{crit}',active.filter(i=>i.sev==='crit').length).replace('{warn}',active.filter(i=>i.sev==='warn').length));
      const top=active.slice().sort((a,b)=>(RANK[a.sev]??3)-(RANK[b.sev]??3)||b.count-a.count).slice(0,3);
      lines.push(tr('exec.top').replace('{list}',top.map(i=>tr('exec.item').replace('{label}',i.label).replace('{count}',i.count)).join(tr('exec.sep'))));
    }
    if(accepted)lines.push(tr('exec.accepted').replace('{n}',accepted));
    return lines;
  }
  function buildFirewallAuditMarkdown(parsed, opts) {
    const pol = parsed.policies || [];
    const info = parsed.deviceInfo || {};
    const un = analyzeUnusedObjects(parsed);
    const co = analyzeCompliance(parsed);
    const health = computeFirewallHealth(parsed, opts);
    const riskLabel = { high: tr('audit.risk_high'), medium: tr('audit.risk_mid'), low: tr('audit.risk_low') };
    const summary = [
      [tr('audit.sum_shadow'), analyzeRuleShadowing(pol, parsed.addresses).length],
      [tr('audit.sum_deny_block'), analyzeDenyBlocking(pol, parsed.addresses).length],
      [tr('audit.sum_merge'), analyzeMergeSuggestions(pol).length],
      [tr('audit.sum_duplicate'), analyzeExactDuplicates(pol).length],
      [tr('audit.sum_unused_addr'), un.unusedAddrs.length],
      [tr('audit.sum_unused_svc'), un.unusedSvcs.length],
      [tr('audit.sum_cross_vdom'), analyzeCrossVdomInconsistency(parsed).length],
      [tr('audit.sum_missing_comments'), analyzeMissingComments(parsed).length],
      [tr('audit.sum_oversized_groups'), analyzeOversizedGroups(parsed).length],
      [tr('audit.sum_dup_objects'), analyzeDuplicateObjects(parsed).length],
      [tr('audit.disabled_title'), analyzeDisabledPolicies(parsed).length],
    ];
    const L = [
      `# ${tr('md.fw_title')} — ${info.hostname || '-'}`,
      '',
      `- ${tr('md.vendor')}: ${parsed.vendor || info.vendor || '-'}`,
      `- ${tr('md.generated')}: ${new Date().toISOString()}`,
      `- ${tr('md.health')}: ${health.score} (${health.grade})`,
      '',
      `## ${tr('exec.title')}`,
      '',
      ...buildFirewallExecSummary(info.hostname, health).map(x => '- ' + x),
      '',
      `## ${tr('md.summary')}`,
      '',
      `| ${tr('audit.col_check')} | ${tr('audit.col_result')} |`,
      '|---|---|',
    ];
    summary.forEach(([k, v]) => L.push(`| ${_mdCell(k)} | ${v} |`));
    L.push('', `## ${tr('audit.compliance_title')}`, '',
      `| ${tr('audit.col_check')} | ${tr('audit.col_result')} | ${tr('audit.col_risk')} | ${tr('audit.col_detail')} | ${tr('audit.col_standards')} |`,
      '|---|---|---|---|---|');
    co.forEach(f => L.push(`| ${_mdCell(f.check)} | ${f.value} | ${_mdCell(riskLabel[f.risk] || f.risk)} | ${_mdCell(f.detail)} | ${_mdCell((f.standards || []).join('; '))} |`));
    // 證據行（AA）：opts.sources 有原始設定時，逐項列出命中的設定行
    if (opts && opts.sources) {
      const ev = buildFirewallAuditEvidence(opts.sources, co);
      const hits = co.filter(f => f.value > 0);
      if (hits.length) {
        L.push('', `## ${tr('audit.evidence_title')}`, '');
        const multi = new Set(opts.sources.filter(x => x && x.text).map(x => x.name)).size > 1;
        hits.forEach(f => {
          L.push(`### ${f.check}`, '');
          const e = ev[f.id] || [];
          if (e.length) L.push('```', ...e.map(x => `${multi ? x.src + ' ' : ''}L${x.line}: ${x.text}`), '```', '');
          else L.push(tr('audit.evidence_none'), '');
          const why = tr('fix.' + f.id);
          if (why && why !== 'fix.' + f.id) L.push(`**${tr('fix.title')}**: ${why}`, '');
          const cmd = buildFirewallFixCommands(f, parsed.vendor);
          if (cmd) L.push('```', cmd, '```', '');
        });
      }
    }
    if (health.issues.length) {
      L.push('', `## ${tr('health.title')}`, '');
      health.issues.forEach(i => L.push(`- ${_mdCell(i.label)}: ${i.count}${i.accepted ? ` (${tr('health.accepted_mark')})` : ''}${i.capped ? ` (${tr('health.capped_mark')})` : ''}`));
    }
    L.push('', `> ${tr('audit.standards_disclaimer')}`, '');
    return L.join('\n');
  }

  // ── FortiGate 清理指令產生（2026-09-29 新增，第六輪 WJ）──────────────────
  // 把既有稽核找到的「停用規則／未使用物件／被上方 accept 規則完全涵蓋的規則」轉成可檢視後
  // 貼上執行的 FortiOS CLI 刪除指令（config <表格> → delete <項目> → end）。僅 FortiGate：
  // 表格名稱依 parser 的 category 對應（address／addrgrp／address6／addrgrp6、service custom／
  // group、policy／policy6〔id 帶 v6/ 前綴〕）；其他 category 不產生指令。
  // 順序：先刪規則（規則會引用物件），再刪群組、最後刪單一物件；同為未使用的巢狀群組，先刪
  // 引用別人的外層群組，避免「仍被群組引用」而刪除失敗。
  // 多 VDOM 時以 config vdom → edit <vdom> … next → end 包起來。遮蔽規則在各 VDOM 內各自分析
  // （規則編號只在 VDOM 內唯一）。
  const _FG_ADDR_TABLE = { 'address': 'firewall address', 'address-group': 'firewall addrgrp', 'address6': 'firewall address6', 'address-group6': 'firewall addrgrp6' };
  const _FG_SVC_TABLE = { 'custom': 'firewall service custom', 'group': 'firewall service group' };
  function _fgQuote(n) { return '"' + String(n).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }
  // 群組刪除順序：還被其他「待刪群組」引用的群組放後面
  function _fgGroupOrder(groups) {
    const left = groups.slice(), out = [];
    while (left.length) {
      let idx = left.findIndex(g => !left.some(o => o !== g && String(o.members || '').split(/,\s*/).map(s => s.trim()).includes(g.name)));
      if (idx < 0) idx = 0; // 循環引用（畸形資料）時照原順序，避免無窮迴圈
      out.push(left.splice(idx, 1)[0]);
    }
    return out;
  }
  function buildFortiGateCleanupScript(parsed, opts) {
    const o = Object.assign({ disabled: true, unused: true, shadowed: false }, opts || {});
    const pols = parsed.policies || [];
    const vdoms = [...new Set([...pols, ...(parsed.addresses || []), ...(parsed.services || [])].map(x => x._vdom || ''))];
    // 只有真正的多 VDOM 設定才包 config vdom（單一 VDOM 的 FortiGate 沒有此指令；parser 對單一 VDOM 也會把 _vdom 設為 root）
    const multi = !!(parsed.deviceInfo && parsed.deviceInfo.isMultiVdom);
    const counts = { disabled: 0, shadowed: 0, addresses: 0, services: 0 };
    const un = o.unused ? analyzeUnusedObjects(parsed) : { unusedAddrs: [], unusedSvcs: [] };
    const body = [];
    for (const vd of vdoms.sort()) {
      const blk = [];
      const table = (name, lines) => { if (lines.length) blk.push('config ' + name, ...lines.map(l => '    ' + l), 'end'); };
      const vp = pols.filter(p => (p._vdom || '') === vd);
      const delPol = new Map(); // id → 原因
      if (o.disabled) vp.filter(p => _isDisabledStatus(p)).forEach(p => { delPol.set(p.id, 'disabled'); });
      if (o.shadowed) analyzeRuleShadowing(vp, parsed.addresses).forEach(r => { if (!delPol.has(r.shadowedId)) delPol.set(r.shadowedId, 'shadowed'); });
      const v4 = [], v6 = [];
      delPol.forEach((why, id) => {
        counts[why]++;
        const s = String(id);
        (s.startsWith('v6/') ? v6 : v4).push('delete ' + s.replace(/^v6\//, ''));
      });
      table('firewall policy', v4);
      table('firewall policy6', v6);
      const addrs = un.unusedAddrs.filter(a => (a._vdom || '') === vd && _FG_ADDR_TABLE[a.category]);
      const svcs = un.unusedSvcs.filter(s => (s._vdom || '') === vd && _FG_SVC_TABLE[s.category]);
      counts.addresses += addrs.length; counts.services += svcs.length;
      ['address-group', 'address-group6'].forEach(c => table(_FG_ADDR_TABLE[c], _fgGroupOrder(addrs.filter(a => a.category === c)).map(a => 'delete ' + _fgQuote(a.name))));
      table(_FG_SVC_TABLE.group, _fgGroupOrder(svcs.filter(s => s.category === 'group')).map(s => 'delete ' + _fgQuote(s.name)));
      ['address', 'address6'].forEach(c => table(_FG_ADDR_TABLE[c], addrs.filter(a => a.category === c).map(a => 'delete ' + _fgQuote(a.name))));
      table(_FG_SVC_TABLE.custom, svcs.filter(s => s.category === 'custom').map(s => 'delete ' + _fgQuote(s.name)));
      if (!blk.length) continue;
      if (multi) body.push('edit ' + (vd || 'root'), ...blk, 'next');
      else body.push(...blk);
    }
    if (multi && body.length) { body.unshift('config vdom'); body.push('end'); }
    const total = counts.disabled + counts.shadowed + counts.addresses + counts.services;
    const head = String(tr('cleanup.script_header')).split('\n').map(l => '# ' + l);
    return { text: total ? [...head, '', ...body, ''].join('\n') : '', counts, total };
  }

  // ── FortiGate 開通指令產生（2026-09-29 新增，第六輪 WI）──────────────────
  // 在既有「IP/Policy 查詢」判定為未放行（明確 deny 或 implicit deny）時，產生新增放行規則的
  // FortiOS CLI：沿用同 VDOM 內已存在的主機位址物件（/32）與單一埠服務物件，沒有才新增；新規則
  // 編號取該 VDOM 現有最大編號 +1（明確指定編號，才能接著用 move 調整位置）；若被明確 deny 規則
  // 擋住，加上 move <新編號> before <deny 規則編號>，implicit deny 則不需移動。
  // 範圍：僅 IPv4（FortiOS 6.x 的 policy6 與 7.x 合併表格語法不同，不猜測）；不設定 NAT。
  function _fgIp4(s) { const p = String(s || '').trim().split('.'); if (p.length !== 4 || p.some(x => !/^\d{1,3}$/.test(x) || +x > 255)) return null; return p.reduce((a, b) => (a * 256) + (+b), 0); }
  function _fgMaskLen(m) {
    const t = String(m || '').trim();
    if (/^\d{1,2}$/.test(t)) return +t;
    const n = _fgIp4(t); if (n === null) return null;
    let len = 0; for (let b = 31; b >= 0; b--) { if (Math.floor(n / 2 ** b) % 2) len++; else break; }
    return len;
  }
  function _fgInNet(ip, net, len) { if (ip === null || net === null || len === null) return false; const size = 2 ** (32 - len); return Math.floor(ip / size) === Math.floor(net / size); }
  // 推測介面：先找直連網段（介面 IP／遮罩或次要 IP 涵蓋此位址），再找最長前綴的靜態路由出口介面
  function fgGuessInterface(parsed, ip, vdom) {
    const t = _fgIp4(ip); if (t === null) return '';
    const inVd = x => !vdom || !x._vdom || x._vdom === vdom;
    for (const i of (parsed.interfaces || []).filter(inVd)) {
      const cands = [{ ip: i.ip, mask: i.mask }, ...((i.secondaryIps || []))];
      if (cands.some(c => _fgInNet(t, _fgIp4(c.ip), _fgMaskLen(c.mask)))) return i.name;
    }
    let best = null, bestLen = -1;
    for (const r of (parsed.routes || []).filter(inVd)) {
      if (r.type !== 'static' || !r.device || r.device === '-') continue;
      const parts = String(r.dst || '').trim().split(/\s*\/\s*|\s+/);
      const len = parts[1] === undefined ? 32 : _fgMaskLen(parts[1]);
      if (_fgInNet(t, _fgIp4(parts[0]), len) && len > bestLen) { best = r; bestLen = len; }
    }
    return best ? best.device : '';
  }
  function buildFortiGateAllowCommand(parsed, req, queryRes) {
    const warnings = [];
    const src = String(req.src || '').trim(), dst = String(req.dst || '').trim();
    if (_fgIp4(src) === null || _fgIp4(dst) === null) return { error: 'ipv4_only' };
    if (queryRes && queryRes.action === 'accept') return { error: 'already_allowed' };
    const multi = !!(parsed.deviceInfo && parsed.deviceInfo.isMultiVdom);
    let vd = req.vdom && req.vdom !== '__all__' ? req.vdom : '';
    if (multi && !vd) return { error: 'need_vdom' };
    if (!vd) vd = (parsed.policies || [])[0]?._vdom || 'root';
    const inVd = x => (x._vdom || 'root') === vd;
    const addrs = (parsed.addresses || []).filter(inVd), svcs = (parsed.services || []).filter(inVd);
    const newObjs = { addr: [], svc: [] };
    const hostObj = ip => {
      const hit = addrs.find(a => a.category === 'address' && (a.type === 'ipmask' || !a.type) && (() => { const [n, m] = String(a.subnet || '').split(/\s*\/\s*|\s+/); return n === ip && _fgMaskLen(m) === 32; })());
      if (hit) return hit.name;
      let name = 'H_' + ip;
      if (addrs.some(a => a.name === name) || newObjs.addr.some(a => a.name === name)) name += '_REQ';
      if (!newObjs.addr.some(a => a.name === name)) newObjs.addr.push({ name, ip });
      return name;
    };
    const srcName = hostObj(src), dstName = hostObj(dst);
    const proto = String(req.proto || 'any').toLowerCase(), port = String(req.port || '').trim();
    let svcName;
    if (proto === 'any' || proto === '') svcName = 'ALL';
    else if (proto === 'icmp') svcName = 'ALL_ICMP';
    else if (!port) svcName = proto === 'tcp' ? 'ALL_TCP' : 'ALL_UDP';
    else {
      const key = proto === 'tcp' ? 'tcpPorts' : 'udpPorts', other = proto === 'tcp' ? 'udpPorts' : 'tcpPorts';
      const hit = svcs.find(s => s.category === 'custom' && String(s[key] || '').trim() === port && (!s[other] || s[other] === '-'));
      if (hit) svcName = hit.name;
      else {
        svcName = proto.toUpperCase() + '_' + port;
        if (svcs.some(s => s.name === svcName)) svcName += '_REQ';
        newObjs.svc.push({ name: svcName, key: proto + '-portrange', port });
      }
    }
    const nums = (parsed.policies || []).filter(inVd).filter(p => /^\d+$/.test(String(p.id))).map(p => parseInt(p.id, 10));
    const newId = (nums.length ? Math.max(...nums) : 0) + 1;
    const blocker = queryRes && queryRes.action === 'deny' && queryRes.matched && /^\d+$/.test(String(queryRes.matched.id)) ? queryRes.matched : null;
    const srcIntf = String(req.srcIntf || '').trim(), dstIntf = String(req.dstIntf || '').trim();
    if (!srcIntf || !dstIntf) warnings.push('intf');
    if (blocker) warnings.push('blocked');
    const q = _fgQuote;
    const body = [];
    if (newObjs.addr.length) body.push('config firewall address', ...newObjs.addr.flatMap(a => ['    edit ' + q(a.name), '        set subnet ' + a.ip + ' 255.255.255.255', '    next']), 'end');
    if (newObjs.svc.length) body.push('config firewall service custom', ...newObjs.svc.flatMap(s => ['    edit ' + q(s.name), '        set ' + s.key + ' ' + s.port, '    next']), 'end');
    const name = String(req.name || ('REQ_' + dst + (port ? '_' + port : ''))).slice(0, 35);
    body.push('config firewall policy', '    edit ' + newId,
      '        set name ' + q(name),
      '        set srcintf ' + q(srcIntf || 'CHANGE_ME'), '        set dstintf ' + q(dstIntf || 'CHANGE_ME'),
      '        set srcaddr ' + q(srcName), '        set dstaddr ' + q(dstName),
      '        set action accept', '        set schedule "always"', '        set service ' + q(svcName), '        set logtraffic all',
      '    next');
    if (blocker) body.push('    move ' + newId + ' before ' + blocker.id);
    body.push('end');
    const wrapped = multi ? ['config vdom', 'edit ' + vd, ...body, 'next', 'end'] : body;
    const head = String(tr('allow.script_header')).replace('{req}', `${src} → ${dst} ${proto.toUpperCase()}${port ? '/' + port : ''}`).split('\n').map(l => '# ' + l);
    return { text: [...head, '', ...wrapped, ''].join('\n'), newId, blockerId: blocker ? blocker.id : null, newAddrs: newObjs.addr.length, newSvcs: newObjs.svc.length, warnings, vdom: vd };
  }
  // 開通需求檢查：既有 IP/Policy 查詢只比對位址與服務、不看介面；FortiGate 規則是先依來源／目的
  // 介面篩選，只看位址會把「別的介面方向」的 all→all 規則誤當成已放行。這裡先推測（或使用者
  // 指定）來源／目的介面，只保留介面相符（含 any、未解析 -）的規則後，再交給既有 _runPolicyQuery()。
  // 介面屬於 zone／SD-WAN 時規則寫的是 zone 名稱，推測不到，需使用者直接填入規則使用的名稱。
  function _fgIntfMatch(list, name) {
    if (!name) return true;
    const items = String(list || '-').split(/\s*,\s*/).map(s => s.trim().toLowerCase());
    return items.some(s => s === 'any' || s === '-' || s === name.toLowerCase());
  }
  function fgCheckRequest(parsed, req) {
    const multi = !!(parsed.deviceInfo && parsed.deviceInfo.isMultiVdom);
    const vd = req.vdom && req.vdom !== '__all__' ? req.vdom : '';
    const guessedSrc = !String(req.srcIntf || '').trim(), guessedDst = !String(req.dstIntf || '').trim();
    const srcIntf = guessedSrc ? fgGuessInterface(parsed, req.src, vd) : String(req.srcIntf).trim();
    const dstIntf = guessedDst ? fgGuessInterface(parsed, req.dst, vd) : String(req.dstIntf).trim();
    const filtered = Object.assign({}, parsed, { policies: (parsed.policies || []).filter(p => _fgIntfMatch(p.srcIntf, srcIntf) && _fgIntfMatch(p.dstIntf, dstIntf)) });
    const res = _runPolicyQuery(String(req.src || '').trim(), String(req.dst || '').trim(), req.proto || 'any', req.port || '', vd || '__all__', filtered);
    if (!res || res.error) return { error: res ? res.error : 'no_policy' };
    const cmd = res.action === 'accept' ? null : buildFortiGateAllowCommand(parsed, Object.assign({}, req, { srcIntf, dstIntf, vdom: vd || (multi ? '' : req.vdom) }), res);
    return { res, srcIntf, dstIntf, guessedSrc, guessedDst, cmd };
  }

  // ── 合規檢查的證據行（2026-09-29 新增，第七輪 AA）──────────────────────────
  // sources：[{name: 檔名, text: 原始設定文字}]（多台同時分析時逐一搜尋）；依 analyzeCompliance()
  // 每項發現的 items 找出原始設定行，回傳 {發現id: [{src, line, text}]}（line 為 1 起算）。
  //   policy：FortiGate 在 config firewall policy／policy6 區段內找 edit <編號>（多 VDOM 依區段前最近的
  //           頂層 edit 判斷所屬 VDOM）；其他廠牌以規則名稱找宣告行。之後帶出區塊內與該項檢查相關的子行。
  //   user／iface／vpn／svc／snmp：以名稱找宣告行（edit／set／<entry name=…>／username 等）＋相關子行
  // 找不到時清單為空。密碼、金鑰、PSK 值一律遮成 ****。以縮排判斷區塊（FortiGate edit…next、
  // Palo Alto／Sophos 等 XML 縮排、Junos 大括號皆適用）。
  const _FW_EV_SUB = {
    'any-any': /srcaddr|dstaddr|service|action|source|destination|application|from|to\b|match/i,
    'broad-network': /srcaddr|dstaddr|source|destination|address/i,
    'no-log': /log|action/i,
    'disabled-pol': /status|disable/i,
    'no-2fa': /two-factor|2fa|otp|accprofile|trusthost/i,
    'default-admin-name': /accprofile|profile|level|user-type/i,
    'http-mgmt': /allowaccess|manage|http|telnet/i,
    'weak-vpn': /proposal|dhgrp|encrypt|hash|dh-group|authentication/i,
    'vpn-no-pfs': /pfs|dhgrp|dh-group/i,
    'snmpv3-weak': /auth|priv/i,
    'overly-permissive-svc': /port|protocol/i,
  };
  const _FW_EV_MAX = 30;
  function _fwEvEsc(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function _fwEvNameRe(name) { return new RegExp('(^|[\\s"\'>=])' + _fwEvEsc(name) + '($|[\\s"\'<;{,])', 'i'); }
  function _fwEvIndent(l) { return (l.match(/^[ \t]*/) || [''])[0].length; }
  function _fwEvBlock(lines, i) {
    const out = [], base = _fwEvIndent(lines[i]);
    for (let k = i + 1; k < lines.length; k++) {
      const l = lines[k];
      if (!l.trim()) continue;
      if (_fwEvIndent(l) <= base) break;
      out.push(k);
    }
    return out;
  }
  function _fwEvMask(l) {
    return l.replace(/\b(password|passwd|phash|secret|psksecret|pre-shared-key|pre-shared-secret|keystring|auth-pwd|priv-pwd|key)(\s+ENC)?(\s+)("?)[^\s"<]+\4/gi, (m, kw, enc, sp, q) => `${kw}${enc || ''}${sp}${q}****${q}`)
      .replace(/<(password|phash|psk|pre-shared-key|secret|key)>[^<]*<\//gi, '<$1>****</');
  }
  // FortiGate：每個 config firewall policy(6) 區段的起訖行與所屬 VDOM
  function _fgPolicySections(lines) {
    const secs = [];
    let vdom = '';
    lines.forEach((l, i) => {
      const top = l.match(/^edit\s+"?([^"\s]+)"?\s*$/);
      if (top) vdom = top[1];
      const m = l.match(/^(\s*)config firewall (policy6?)\s*$/);
      if (m) {
        let end = lines.length;
        for (let k = i + 1; k < lines.length; k++) if (_fwEvIndent(lines[k]) === m[1].length && /^\s*end\s*$/.test(lines[k])) { end = k; break; }
        secs.push({ start: i, end, vdom, six: m[2] === 'policy6' });
      }
    });
    return secs;
  }
  function buildFirewallAuditEvidence(sources, findings) {
    const res = {};
    const srcs = (sources || []).filter(s => s && s.text).map(s => ({ name: s.name || '', lines: String(s.text).replace(/^﻿/, '').replace(/\r\n?/g, '\n').split('\n') }));
    srcs.forEach(s => { s.fgSecs = /^\s*config firewall policy/m.test(s.lines.join('\n')) ? _fgPolicySections(s.lines) : null; });
    (findings || []).forEach(f => {
      const out = [];
      const seen = new Set();
      const sub = _FW_EV_SUB[f.id];
      if (!f.value) { res[f.id] = out; return; }
      srcs.forEach(src => {
        const L = src.lines;
        const add = k => { const key = src.name + ':' + k; if (out.length < _FW_EV_MAX && !seen.has(key)) { seen.add(key); out.push({ src: src.name, line: k + 1, text: _fwEvMask(L[k].replace(/\s+$/, '')) }); } };
        const addBlock = k => { add(k); if (sub) _fwEvBlock(L, k).forEach(b => { if (sub.test(L[b])) add(b); }); };
        (f.items || []).forEach(it => {
          if (it.kind === 'policy') {
            if (src.fgSecs) {
              const idStr = String(it.id), six = idStr.startsWith('v6/'), num = idStr.replace(/^v6\//, '');
              src.fgSecs.filter(sec => sec.six === six && (!it.vdom || !sec.vdom || sec.vdom === it.vdom)).forEach(sec => {
                for (let k = sec.start + 1; k < sec.end; k++) if (new RegExp('^\\s*edit\\s+"?' + _fwEvEsc(num) + '"?\\s*$').test(L[k])) { addBlock(k); break; }
              });
              return;
            }
            const re = it.name ? _fwEvNameRe(it.name) : _fwEvNameRe(it.id);
            // 2026-09-30：關鍵字補上 MikroTik 的 add／chain（規則行為 add action=… chain=… comment="…"）
            let k = L.findIndex(l => re.test(l) && /rule|policy|entry|edit|name|access-list|filter|term|set|chain|^\s*add\b/i.test(l));
            // EdgeRouter 合成名稱「規則集-序號」（如 WAN_LOCAL-10）：找 name WAN_LOCAL { 之後的 rule 10 {
            const er = it.name && String(it.name).match(/^(\S+)-(\d+)$/);
            if (k < 0 && er) {
              const n = L.findIndex(l => new RegExp('^\\s*name\\s+"?' + _fwEvEsc(er[1]) + '"?\\s*\\{').test(l));
              if (n >= 0) k = L.findIndex((l, i) => i > n && new RegExp('^\\s*rule\\s+' + er[2] + '\\s*\\{').test(l));
            }
            // 名稱只出現在說明文字（EdgeRouter description "…"）：往上找所屬的 rule N { 區塊開頭
            if (k < 0 && it.name) {
              const d = L.findIndex(l => l.includes(String(it.name)));
              if (d >= 0) { k = d; for (let u = d - 1; u >= Math.max(0, d - 15); u--) if (/^\s*rule\s+\d+\s*\{/.test(L[u])) { k = u; break; } }
            }
            if (k >= 0) addBlock(k);
            return;
          }
          if (!it.name) return;
          // Cisco ASA／FTD 的 VPN 名稱是合成的「crypto map 名稱@對端 IP」，設定檔只有 crypto map 名稱（2026-09-30）
          const re = _fwEvNameRe(it.kind === 'vpn' && /@/.test(it.name) ? String(it.name).split('@')[0] : it.name);
          // 先找物件宣告行（edit／<entry>），再找其他常見開頭，最後才是任何含此名稱的行
          let k = L.findIndex(l => re.test(l) && /^\s*(edit|<entry)\b/i.test(l));
          if (k < 0) k = L.findIndex(l => re.test(l) && /^\s*(set|username|user|<name>|interface|crypto|tunnel-group|community|snmp|add|\/)/i.test(l));
          if (k < 0) k = L.findIndex(l => re.test(l));
          if (k >= 0) addBlock(k);
        });
      });
      res[f.id] = out;
    });
    return res;
  }

  // ── 合規發現的修正指令範例（2026-09-29 新增，第七輪 NB）──────────────────────
  // 只提供 FortiGate（FortiOS）；其他廠牌只顯示白話說明（i18n fix.<發現id>）。以發現的 items 代入
  // （規則編號、帳號、介面、VPN、服務物件），每項最多 10 個對象，<...> 為需要自行填入的值；
  // 多 VDOM 設定需先 config vdom／edit <vdom>，此處不自動包覆（同一發現可能跨多個 VDOM）。
  const FW_FIX_MAX = 10;
  const _fgPol = (it, lines) => ['config firewall policy', ...(it || []).filter(x => !String(x.id).startsWith('v6/')).slice(0, FW_FIX_MAX).flatMap(x => [`    edit ${x.id}`, ...lines.map(l => '        ' + l), '    next']), 'end'];
  const _fgEdit = (table, it, lines) => [`config ${table}`, ...(it || []).slice(0, FW_FIX_MAX).flatMap(x => [`    edit ${_fgQuote(x.name)}`, ...lines.map(l => '        ' + l), '    next']), 'end'];
  const FW_FIX_CMDS_FORTIGATE = {
    'any-any': it => _fgPol(it, ['set srcaddr "<specific-source>"', 'set dstaddr "<specific-destination>"', 'set service "<specific-service>"']),
    'disabled-pol': it => ['config firewall policy', ...(it || []).filter(x => !String(x.id).startsWith('v6/')).slice(0, FW_FIX_MAX).map(x => `    delete ${x.id}`), 'end'],
    'no-log': it => _fgPol(it, ['set logtraffic all']),
    'snmp-v1v2': () => ['config system snmp community', '    delete <community-id>', 'end', 'config system snmp user', '    edit "<user>"', '        set security-level auth-priv', '        set auth-proto sha256', '        set auth-pwd <auth-password>', '        set priv-proto aes256', '        set priv-pwd <priv-password>', '    next', 'end'],
    'no-2fa': it => _fgEdit('system admin', it, ['set two-factor fortitoken', 'set fortitoken <token-serial>']),
    'http-mgmt': it => _fgEdit('system interface', it, ['set allowaccess ping https ssh']),
    'weak-vpn': it => _fgEdit('vpn ipsec phase1-interface', it, ['set proposal aes256-sha256', 'set dhgrp 14']),
    'vpn-no-pfs': () => ['config vpn ipsec phase2-interface', '    edit "<phase2-name>"', '        set pfs enable', '        set dhgrp 14', '    next', 'end'],
    'default-admin-name': it => ['config system admin', '    edit "<new-admin-name>"', '        set accprofile "super_admin"', '        set password <new-password>', '    next', ...(it || []).slice(0, FW_FIX_MAX).map(x => `    delete ${_fgQuote(x.name)}`), 'end'],
    'snmpv3-weak': it => ['config system snmp user', ...(it || []).slice(0, FW_FIX_MAX).flatMap(x => [`    edit ${_fgQuote(x.name)}`, '        set auth-proto sha256', '        set priv-proto aes256', '    next']), 'end'],
    'broad-network': it => _fgPol(it, ['set srcaddr "<narrower-source>"', 'set dstaddr "<narrower-destination>"']),
    'overly-permissive-svc': it => _fgEdit('firewall service custom', it, ['set tcp-portrange <specific-ports>']),
  };
  function buildFirewallFixCommands(finding, vendor) {
    if (!finding.value || !/FortiGate/i.test(vendor || '') || / \+ /.test(vendor || '')) return '';
    const fn = FW_FIX_CMDS_FORTIGATE[finding.id];
    return fn ? fn(finding.items || []).join('\n') : '';
  }

  // ── 稽核工作底稿（2026-09-29 新增，第七輪 AB）─────────────────────────────
  // 合規檢查每項一列：主機、檢查項目、風險、結果、詳細說明、相關標準、證據行、修正建議（說明＋指令）、
  // 處置狀態、審查者備註、審查者、更新時間。marks＝{發現id:{status,note,ts}}（畫面上由使用者填寫，存在
  // 瀏覽器）；與健康度的「接受風險」是兩套獨立標記（後者影響分數，此處只是底稿紀錄）。
  const AUDIT_MARK_STATUSES = ['open', 'todo', 'fixed', 'accepted'];
  function auditStatusLabel(st) { return tr('wp.status_' + (AUDIT_MARK_STATUSES.includes(st) ? st : 'open')); }
  function buildFirewallWorkpaper(parsed, sources, marks, reviewer) {
    const co = analyzeCompliance(parsed);
    const ev = sources ? buildFirewallAuditEvidence(sources, co) : {};
    const host = (parsed.deviceInfo && parsed.deviceInfo.hostname) || '-';
    const riskLabel = { high: tr('audit.risk_high'), medium: tr('audit.risk_mid'), low: tr('audit.risk_low') };
    const headers = [tr('wp.col_host'), tr('audit.col_check'), tr('audit.col_risk'), tr('audit.col_result'), tr('audit.col_detail'), tr('audit.col_standards'), tr('audit.col_evidence'), tr('wp.col_fix'), tr('wp.col_status'), tr('wp.col_note'), tr('wp.col_reviewer'), tr('wp.col_updated')];
    const multi = new Set((sources || []).filter(s => s && s.text).map(s => s.name)).size > 1;
    const rows = co.map(f => {
      const m = (marks && marks[f.id]) || {};
      const why = tr('fix.' + f.id);
      const fix = f.value ? [why !== 'fix.' + f.id ? why : '', buildFirewallFixCommands(f, parsed.vendor)].filter(Boolean).join('\n') : '';
      return [host, f.check, riskLabel[f.risk] || f.risk, f.value, f.detail, (f.standards || []).join('; '),
        (ev[f.id] || []).map(e => `${multi ? e.src + ' ' : ''}L${e.line}: ${e.text}`).join('\n'), fix,
        f.value ? auditStatusLabel(m.status) : '-', m.note || '', reviewer || '', m.ts ? new Date(m.ts).toISOString() : ''];
    });
    return { headers, rows };
  }

  // ── 規則命中數匯入（FortiGate，2026-09-30 新增，第八輪 XF）──────────────────
  // 設定檔本身沒有命中統計，需另外從設備取得後貼上，支援兩種來源（皆依 Fortinet 官方文件／KB 的欄位名稱）：
  //   1. REST API：GET /api/v2/monitor/firewall/policy 的 JSON 回應——{vdom?, results:[{policyid, hit_count,
  //      last_used(Unix 秒), first_used, bytes, ...}]}；也接受直接貼 results 陣列或多個回應物件的陣列
  //   2. CLI：diagnose firewall iprope show 00100004 <policy id...> 的輸出，新版多行（idx:1／hit count:N (...)／
  //      first hit:YYYY-MM-DD hh:mm:ss last hit:...）與舊版單行（idx=1 pkts/bytes=... hit count:N、first:... last:...）
  //      皆以寬鬆比對讀取；CLI 輸出不含 VDOM 資訊，時間以瀏覽器本地時區解讀
  // 回傳 {format:'json'|'cli'|'', vdom:'', items:[{id, hits, lastUsed(ms|null), firstUsed(ms|null), bytes|null}]}
  function parseFortiHitCounts(text) {
    const t = String(text || '').trim();
    const res = { format: '', vdom: '', items: [] };
    if (!t) return res;
    if (/^[\[{]/.test(t)) {
      let data = null;
      try { data = JSON.parse(t); } catch (e) { return res; }
      const resps = Array.isArray(data) && data.length && data[0] && Array.isArray(data[0].results) ? data : [data];
      resps.forEach(r => {
        const list = Array.isArray(r) ? r : (r && Array.isArray(r.results) ? r.results : []);
        if (r && typeof r.vdom === 'string' && !res.vdom) res.vdom = r.vdom;
        list.forEach(x => {
          if (!x || x.policyid === undefined || x.hit_count === undefined) return;
          const sec = v => (Number(v) > 0 ? Number(v) * 1000 : null);
          res.items.push({ id: String(x.policyid), hits: Number(x.hit_count) || 0, lastUsed: sec(x.last_used), firstUsed: sec(x.first_used),
            bytes: x.bytes !== undefined ? Number(x.bytes) : null });
        });
      });
      if (res.items.length) res.format = 'json';
      return res;
    }
    const toMs = s => { const m = String(s || '').match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/); return m ? new Date(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime() : null; };
    // 以 idx 切段，每段取 hit count 與首／末次命中時間
    const parts = t.split(/(?=^\s*idx\s*[:=]\s*\d+)/m);
    parts.forEach(p => {
      const im = p.match(/^\s*idx\s*[:=]\s*(\d+)/m);
      const hm = p.match(/hit count\s*:\s*(\d+)/i);
      if (!im || !hm) return;
      const lm = p.match(/last(?: hit)?\s*:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
      const fm = p.match(/first(?: hit)?\s*:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
      const bm = p.match(/pkts\/bytes\s*=\s*\d+\/(\d+)/) || p.match(/^\s*bytes\s*:\s*(\d+)/m);
      res.items.push({ id: im[1], hits: Number(hm[1]), lastUsed: lm ? toMs(lm[1]) : null, firstUsed: fm ? toMs(fm[1]) : null, bytes: bm ? Number(bm[1]) : null });
    });
    if (res.items.length) res.format = 'cli';
    return res;
  }
  // 依 policy ID 對上已解析的 FortiGate 規則（只看啟用中的規則）：命中 0 次、或最後命中超過 days 天。
  // 多 VDOM 設定：命中資料有 vdom（REST API）時只比對該 VDOM；沒有時，ID 在多個 VDOM 重複的規則無法判斷，列入 ambiguous 不下結論。
  // opts: {days=90, now=Date.now()}；回傳 {rows:[{id,name,vdom,action,hits,lastUsed,kind:'zero'|'stale'|'ok'}], zero, stale, missing:[沒有命中資料的啟用規則 ID], ambiguous:[ID], unknown:[命中資料有但設定檔沒有的 ID]}
  function analyzeFortiHitCounts(parsed, hc, opts) {
    // 只比對 IPv4 規則：REST /firewall/policy 與 iprope 00100004 皆為 IPv4 規則表，IPv6（parser 以 v6/ 前綴區分）不列入
    const pols = (parsed.policies || []).filter(p => !_isDisabledStatus(p) && !/^v6\//.test(String(p.id)) && (!hc.vdom || !p._vdom || p._vdom === hc.vdom));
    return _analyzeHitCountsByKey(pols, hc, p => String(p.id), opts);
  }
  // ── 規則命中數匯入：Cisco ASA／FTD 與 Palo Alto（2026-10-02，第九輪發想 YI）──
  // ASA：`show access-list` 輸出，頂層 ACE 行 `access-list NAME line N extended permit|deny … (hitcnt=N) 0x…`
  //   （Cisco 官方指令參考與社群範例交叉確認）；縮排的子行是 object-group 展開明細，加總已在頂層行，略過；
  //   remark 行沒有 hitcnt 也略過。輸出不含最後命中時間，只能判斷「從未命中」。id 為「ACL#行號」
  // Palo Alto：CLI `show rule-hit-count vsys vsys-name X rule-base security rules all` 的表格
  //   （Rule Name／Hit Count／Last Hit Timestamp…，欄位以多個空白分隔，名稱可含空白，時間如 `Wed Nov 20 11:31:07 2019`
  //   或 `-`），或 XML API 回應（rules 下 `<entry name="規則">` 內 `<hit-count>`、`<last-hit-timestamp>` Unix 秒）。id 為規則名稱
  function parseAsaHitCounts(text) {
    const res = { format: '', vdom: '', items: [] };
    for (const line of String(text || '').split(/\r?\n/)) {
      const m = line.match(/^access-list\s+(\S+)\s+line\s+(\d+)\s+(?:extended|standard)\s+(permit|deny)\b.*\(hitcnt=(\d+)\)/);
      if (!m) continue;
      res.items.push({ id: m[1] + '#' + m[2], label: `${m[1]} line ${m[2]}`, hits: Number(m[4]), lastUsed: null, firstUsed: null, bytes: null, action: m[3] === 'permit' ? 'accept' : 'deny' });
    }
    if (res.items.length) res.format = 'asa';
    return res;
  }
  function parsePaloAltoHitCounts(text) {
    const t = String(text || '');
    const res = { format: '', vdom: '', items: [] };
    if (/<hit-count>/.test(t)) {
      // 每個 <entry name="…"> 到下一個 <entry 或 </entry> 為一段，有 <hit-count> 的才是規則
      for (const seg of t.split(/(?=<entry\s+name=")/)) {
        const nm = seg.match(/^<entry\s+name="([^"]*)"/), hm = seg.match(/<hit-count>(\d*)<\/hit-count>/);
        if (!nm || !hm) continue;
        const body = seg.split(/<\/entry>/)[0];
        if (!/<hit-count>/.test(body)) continue;
        const ts = tag => { const x = body.match(new RegExp('<' + tag + '>(\\d+)</' + tag + '>')); return x && Number(x[1]) > 0 ? Number(x[1]) * 1000 : null; };
        const name = nm[1].replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"');
        res.items.push({ id: name, hits: Number(hm[1]) || 0, lastUsed: ts('last-hit-timestamp'), firstUsed: ts('first-hit-timestamp'), bytes: null });
      }
      if (res.items.length) res.format = 'paxml';
      return res;
    }
    const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
    const TS = '(?:[A-Z][a-z]{2}\\s+[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\d{4}|-)';
    const toMs = s => { const m = String(s).match(/^[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/); return m && MON[m[1]] !== undefined ? new Date(+m[6], MON[m[1]], +m[2], +m[3], +m[4], +m[5]).getTime() : null; };
    const rowRe = new RegExp('^(\\S.*?)\\s{2,}(\\d+)\\s+(' + TS + ')\\s+(' + TS + ')\\s+(' + TS + ')');
    if (!/Rule Name\s+Hit Count/.test(t)) return res;
    for (const line of t.split(/\r?\n/)) {
      const m = line.match(rowRe);
      if (!m || /^Rule Name\b/.test(m[1]) || /^-+$/.test(m[1])) continue;
      res.items.push({ id: m[1].trim(), hits: Number(m[2]), lastUsed: toMs(m[3]), firstUsed: toMs(m[5]), bytes: null });
    }
    if (res.items.length) res.format = 'pacli';
    return res;
  }
  // Juniper SRX（2026-10-02，第十輪發想 ZP）：`show security policies hit-count` 表格，欄位為 Index／From zone／To zone／
  //   Name／Policy count（Juniper 官方指令文件的欄位與範例列，原文頁被網路政策擋下，以搜尋索引摘要確認）。以表頭定位，
  //   之後每列 5 欄；政策名稱不含空白。只有累計次數、沒有最後命中時間，只能判斷「從未命中」。id 為「來源區域|目的區域|名稱」
  function parseJuniperHitCounts(text) {
    const res = { format: '', vdom: '', items: [] };
    let inTable = false;
    for (const line of String(text || '').split(/\r?\n/)) {
      if (/From zone\s+To zone\s+Name\s+Policy count/i.test(line)) { inTable = true; continue; }
      if (!inTable) continue;
      const m = line.match(/^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$/);
      if (m) res.items.push({ id: `${m[2]}|${m[3]}|${m[4]}`, label: `${m[2]} → ${m[3]} ${m[4]}`, hits: Number(m[5]), lastUsed: null, firstUsed: null, bytes: null });
    }
    if (res.items.length) res.format = 'junos';
    return res;
  }
  // 依廠牌分派：回傳 {hc, res}；不支援的廠牌 hc 為 null
  function parseRuleHitCounts(text, vendor) {
    if (vendor === 'Juniper') return parseJuniperHitCounts(text);
    if (vendor === 'FortiGate') return parseFortiHitCounts(text);
    if (vendor === 'Cisco ASA' || vendor === 'Cisco FTD') return parseAsaHitCounts(text);
    if (vendor === 'PaloAlto') return parsePaloAltoHitCounts(text);
    return null;
  }
  function analyzeRuleHitCounts(parsed, hc, opts) {
    if (parsed.vendor === 'FortiGate') return analyzeFortiHitCounts(parsed, hc, opts);
    const pols = (parsed.policies || []).filter(p => !_isDisabledStatus(p));
    if (parsed.vendor === 'PaloAlto') return _analyzeHitCountsByKey(pols, hc, p => String(p.name || ''), opts);
    if (parsed.vendor === 'Juniper') return _analyzeHitCountsByKey(pols, hc, p => `${p.srcIntf}|${p.dstIntf}|${p.name}`, opts);
    return _analyzeHitCountsByKey(pols.filter(p => p.aclLine), hc, p => p.name + '#' + p.aclLine, opts);
  }
  // 共用比對（2026-10-02 自 analyzeFortiHitCounts 抽出，供 ASA／Palo Alto 共用）：keyOf(policy) 與命中資料的 id 對應；
  // 同一 key 對到多條規則列入 ambiguous；item.action（選填）與規則動作不同時也視為無法判斷（ASA 行號錯位的保護）
  function _analyzeHitCountsByKey(pols, hc, keyOf, opts) {
    const days = (opts && opts.days) || 90, now = (opts && opts.now) || Date.now();
    const byId = {};
    pols.forEach(p => { (byId[keyOf(p)] = byId[keyOf(p)] || []).push(p); });
    const out = { rows: [], zero: 0, stale: 0, missing: [], ambiguous: [], unknown: [] };
    const seen = new Set();
    hc.items.forEach(it => {
      const ps = byId[it.id];
      if (!ps) { if (!out.unknown.includes(it.id)) out.unknown.push(it.id); return; }
      seen.add(it.id);
      if (ps.length > 1 || (it.action && ps[0].action && it.action !== ps[0].action)) { if (!out.ambiguous.includes(it.id)) out.ambiguous.push(it.id); return; }
      const p = ps[0];
      const kind = it.hits === 0 ? 'zero' : (it.lastUsed && now - it.lastUsed > days * 86400000 ? 'stale' : 'ok');
      if (kind === 'zero') out.zero++; else if (kind === 'stale') out.stale++;
      out.rows.push({ id: it.label || String(p.id), name: p.name || '', vdom: p._vdom || '', action: p.action || '', hits: it.hits, lastUsed: it.lastUsed, kind });
    });
    Object.keys(byId).forEach(id => { if (!seen.has(id)) out.missing.push(id); });
    const rank = { zero: 0, stale: 1, ok: 2 };
    out.rows.sort((a, b) => rank[a.kind] - rank[b.kind] || (a.lastUsed || 0) - (b.lastUsed || 0));
    return out;
  }
