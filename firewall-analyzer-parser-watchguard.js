// ══════════════════════════════════════════════════════════
//  WATCHGUARD FIREBOX PARSER（MVP，2026-08-26 新增）
// ══════════════════════════════════════════════════════════
// 查證來源：GitHub 真實社群 Python parser ins1gn1a/WatchGuard-Config-Parser（watchparse.py，
// xml.etree.ElementTree 逐段解析，非猜測）；直接 fetch 該檔內容確認以下標籤結構後才動手實作：
// from-alias-list／to-alias-list／alias-member-list／addr-group-member／service-item／
// if-item-list 這幾個「清單容器」底下一律用泛用 <item> 當重複子節點包裝（WatchGuard XML
// 匯出檔慣例，非本專案臆測——watchparse.py 對這些容器一律寫 `for a in x:`，不指定特定子標籤
// 名稱，代表容器內每個子元素都是同一個泛用包裝標籤）。另有第三方合規稽核工具 Titania 官方
// 文件交叉佐證此 XML 格式確實用於業界文字解析。
//
// MVP 範圍（僅本次查證到有明確 XML tag 佐證的 5 個資料形狀）：interfaces／policies／
// addresses／services／routes。
//
// 明確排除、非查證不足（查無任何 XML tag 佐證，不猜測實作）：
// - NAT 詳細結構：abs-policy 內只有 <policy-nat> 一個文字欄位（如 "1-to-1 NAT"／"None"），
//   非獨立 NAT 物件清單，無法比照 FortiGate VIP/IP Pool 那種結構化欄位還原；本檔改把
//   policy-nat 文字併入每筆 policy 自己的 nat/poolname 欄位（policy 本來就有這兩個欄位），
//   頂層 `nat` 陣列維持 []（不生出假的 NAT 物件），由 NAT 分頁的 vendor-unsupported 警語
//   說明「僅有政策內文字欄位，非結構化 NAT」。
// - VPN（BOVPN/Mobile VPN）：社群 parser 完全沒碰，多輪關鍵字搜尋皆查無標籤，vpn:[]。
// - Users：查無本機帳號設定標籤，users:[]。
// - 裝置資訊（hostname/firmware/model/serial）：查無對應 tag，僅知檔名慣例是
//   <device-friendly-name>.xml，非 XML 內容本身可解析，deviceInfo 除 vendor 外皆留白。
// - interfaces 的 vlanId／role／mtu／type：查無對應標籤，欄位留白 '-'（非集合型缺口，
//   不需要警語 UI，比照其他廠牌「查無此欄位」慣例）。
// - if-item-list 的 ip-node-type 語意不明（疑似 static/dhcp），不臆測，不對應到 mode 欄位。
//
// 頂層 nat/vpn/users 為何回傳 [] 而非 null：merge()（app.js）對這三個欄位是
// `[...a.nat,...b.nat]` 陣列展開，counts/renderSection 也都是 `d.nat.length` 直接存取，
// 全部沒有 optional chaining／truthy guard（與 ha/dhcp/dns/snmp/logservers 那組「有 guard
// 才能安全塞 null」的欄位不同）。若這三個回傳 null，單一廠牌上傳時(parsedAll.length===1)
// 沒事，但只要與其他廠牌合併分析（merge()）就會對 null 做 spread 直接拋錯，或
// renderSection 對 null.length 拋錯導致整頁崩潰。故改用「陣列維持 []＋ NAT_UNSUPPORTED/
// VPN_UNSUPPORTED/USERS_UNSUPPORTED 廠牌白名單」機制（app.js 新增，比照既有 WIFI_UNSUPPORTED
// 精神：分頁不隱藏，但用 ST.raw 該廠牌 slot 是否有上傳來決定顯示「查無佐證」警語還是
// 「無資料」，純粹是顯示層判斷，不影響底層資料一律是安全的空陣列）。
const WatchGuardParser = (() => {

  // ── XML helpers（沿用 PfsenseParser 同款正則式寫法，各檔各自宣告一份，不跨檔共用）──
  function xv(xml, tag) {
    const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i');
    const m = xml.match(re);
    if (!m) return '';
    const inner = m[1];
    if (new RegExp(`<${tag}[\\s>]`, 'i').test(inner)) {
      return inner.replace(new RegExp(`<${tag}[\\s\\S]*?<\\/${tag}>`, 'gi'), '')
                  .replace(/<[^>]+>/g, '').trim()
                  .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim();
    }
    return inner.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim();
  }
  function xva(xml, tag) {
    const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'gi');
    const r = []; let m;
    while ((m = re.exec(xml)) !== null)
      r.push(m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1').trim());
    return r;
  }
  function xblks(xml, tag) {
    const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'gi');
    const r = []; let m;
    while ((m = re.exec(xml)) !== null)
      r.push({ _outer: m[0], _inner: m[1] });
    return r;
  }
  function hasTag(xml, tag) {
    return new RegExp(`<${tag}(?:\\s[^>]*)?/?>`, 'i').test(xml);
  }
  function isTrue(s) {
    const v = (s||'').trim().toLowerCase();
    return v==='true'||v==='1'||v==='yes'||v==='enabled'||v==='enable';
  }
  function maskToBits(mask) {
    if (!mask) return 32;
    if (/^\d{1,2}$/.test(mask.trim())) return parseInt(mask.trim(), 10);
    const parts = mask.trim().split('.').map(n=>parseInt(n,10));
    if (parts.length !== 4 || parts.some(n=>isNaN(n))) return 32;
    let bin = parts.map(n=>(n>>>0).toString(2).padStart(8,'0')).join('');
    return (bin.match(/1/g)||[]).length;
  }

  // ── 頂層容器直接抓子區塊，不假設外層 <configuration> 之類根標籤名稱（社群 parser 用
  //    root.findall("./xxx-list/xxx") 相對路徑，本檔用同一份文字全域搜尋等效，容錯度更高）──

  function parseDeviceInfo() {
    return { vendor: 'WatchGuard', hostname: '-', firmware: '-', model: '-', serial: '-',
      vdom: [], vdomNames: [], isMultiVdom: false };
  }

  // ── Interfaces ──────────────────────────────────────────────────────────────
  // 注意：必須先框在 <interface-list> 範圍內再抓 <interface> 區塊，不能對整份 xml 全域搜尋
  // ——alias-member-list 底下的 <interface>eth1</interface> 也是同名標籤（別名指向介面時的
  // 葉節點），對全文做 xblks(xml,'interface') 會把這些單行文字節點誤判成一筆空介面
  function parseInterfaces(xml) {
    const out = [];
    const listXml = xv(xml, 'interface-list');
    xblks(listXml || '', 'interface').forEach(b => {
      const inner = b._inner;
      const name = xv(inner, 'name') || '-';
      const desc = xv(inner, 'description') || '';
      const itemListXml = xv(inner, 'if-item-list');
      // if-item-list → item → physif → 欄位（watchparse.py 三層巢狀，見檔頭註解查證來源）
      const items = xblks(itemListXml, 'item');
      const physifBlk = items.length ? (xblks(items[0]._inner, 'physif')[0] || null) : null;
      const physif = physifBlk ? physifBlk._inner : itemListXml; // 找不到 physif 包裝時退化直接讀 item 內容，避免過度嚴格
      const ifDevName = xv(physif, 'if-dev-name') || name;
      const enabled = xva(physif, 'enabled')[0];
      const ip = xv(physif, 'ip') || '-';
      const netmask = xv(physif, 'netmask') || '-';
      const gateway = xv(physif, 'default-gateway') || '-';
      // 次要IP：secondary-ip-list/item/{ip,netmask}（比照本檔其餘清單容器的泛用 <item> 慣例）
      const secList = xv(physif, 'secondary-ip-list');
      const secondaryIps = xblks(secList, 'item').map(sb => ({
        ip: xv(sb._inner, 'ip') || '-', mask: xv(sb._inner, 'netmask') || '-',
      })).filter(s => s.ip !== '-');
      out.push({
        name: ifDevName, alias: desc || name, ip, mask: netmask, secondaryIps,
        type: '-', vlanId: '-', vdom: '-', role: '-',
        status: enabled === undefined ? 'up' : (isTrue(enabled) ? 'up' : 'down'),
        speed: '-', mtu: '-', macaddr: '-', mode: '-', gwdetect: '-',
        desc: desc || '-', allowaccess: '-', interface: ifDevName, gateway, _vdom: '',
      });
    });
    return out;
  }

  // ── Address Groups + Aliases ────────────────────────────────────────────────
  // addr-group-member → item → {host-ip-addr | ip-network-addr+ip-mask | start-ip-addr+end-ip-addr}
  function _addrGroupMembers(memberListXml) {
    return xblks(memberListXml, 'item').map(b => {
      const inner = b._inner;
      const host = xv(inner, 'host-ip-addr');
      if (host) return { display: host, subnet: `${host}/32`, startIp: host, endIp: '-', type: 'ipmask' };
      const net = xv(inner, 'ip-network-addr');
      const netMask = xv(inner, 'ip-mask');
      if (net) { const bits = maskToBits(netMask); return { display: `${net}/${bits}`, subnet: `${net}/${bits}`, startIp: net, endIp: '-', type: 'ipmask' }; }
      const s = xv(inner, 'start-ip-addr'), e = xv(inner, 'end-ip-addr');
      if (s) return { display: `${s}-${e||s}`, subnet: '-', startIp: s, endIp: e||s, type: 'iprange' };
      return null;
    }).filter(Boolean);
  }

  function parseAddressGroups(xml) {
    const out = [];
    xblks(xml, 'address-group').forEach(b => {
      const inner = b._inner;
      const name = xv(inner, 'name');
      if (!name) return;
      const comment = xv(inner, 'description') || '-';
      const memberListXml = xv(inner, 'addr-group-member');
      const members = _addrGroupMembers(memberListXml);
      if (members.length === 1) {
        const m = members[0];
        out.push({ category: 'address', name, type: m.type, subnet: m.subnet, fqdn: '-',
          startIp: m.startIp, endIp: m.endIp, wildcard: '-', iface: '-', color: '0',
          comment, members: '-', _vdom: '' });
      } else if (members.length > 1) {
        out.push({ category: 'address-group', name, type: 'group', subnet: '-', fqdn: '-',
          startIp: '-', endIp: '-', wildcard: '-', iface: '-', color: '0',
          comment, members: members.map(m=>m.display).join(', '), _vdom: '' });
      }
    });
    return out;
  }

  // alias-member-list → item → {aliasname | address | interface}（一個 item 僅含其中一種）
  function _aliasMembers(memberListXml) {
    return xblks(memberListXml, 'item').map(b => {
      const inner = b._inner;
      const an = xv(inner, 'aliasname');
      if (an) return { kind: 'aliasname', value: an };
      const ad = xv(inner, 'address');
      if (ad) return { kind: 'address', value: ad };
      const ifc = xv(inner, 'interface');
      if (ifc) return { kind: 'interface', value: ifc };
      return null;
    }).filter(Boolean);
  }

  // 回傳 { aliasMap: Map(name -> {hasInterface, intfNames:[], addrTokens:[]}), addressRows:[] }
  // addressRows：非純介面別名（含至少一個 aliasname/address 成員）一併展開進「位址物件」分頁，
  // 讓使用者能在 Addresses 分頁看到 alias 本身（members 欄位顯示其引用內容），比照
  // EdgeRouter/pfSense「group 型別物件也收進 addresses 陣列」的既有慣例
  function parseAliases(xml) {
    const aliasMap = new Map();
    const addressRows = [];
    xblks(xml, 'alias').forEach(b => {
      const inner = b._inner;
      const name = xv(inner, 'name');
      if (!name) return;
      const comment = xv(inner, 'description') || '-';
      const memberListXml = xv(inner, 'alias-member-list');
      const members = _aliasMembers(memberListXml);
      const intfNames = members.filter(m=>m.kind==='interface').map(m=>m.value);
      const addrTokens = members.filter(m=>m.kind!=='interface').map(m=>m.value);
      aliasMap.set(name, { hasInterface: intfNames.length>0, intfNames, addrTokens });
      if (addrTokens.length) {
        addressRows.push({ category: 'address-group', name, type: 'group', subnet: '-', fqdn: '-',
          startIp: '-', endIp: '-', wildcard: '-', iface: '-', color: '0',
          comment, members: addrTokens.join(', '), _vdom: '' });
      }
    });
    return { aliasMap, addressRows };
  }

  function parseAddressObjects(xml) {
    const groups = parseAddressGroups(xml);
    const { addressRows } = parseAliases(xml);
    return [...groups, ...addressRows];
  }

  // ── Services ─────────────────────────────────────────────────────────────────
  // protocol 數字碼對照：6=TCP, 17=UDP, 1=ICMP（標準 IANA protocol number，官方查證已確認）；
  // 其餘數字碼查無對照表佐證，不猜測，原樣以 "PROTO-<n>" 標示
  function protoName(code) {
    if (code === '6') return 'TCP';
    if (code === '17') return 'UDP';
    if (code === '1') return 'ICMP';
    return code ? `PROTO-${code}` : '-';
  }
  function parseServiceObjects(xml) {
    const out = [];
    xblks(xml, 'service').forEach(b => {
      const inner = b._inner;
      const name = xv(inner, 'name');
      if (!name) return;
      const comment = xv(inner, 'description') || '-';
      const itemListXml = xv(inner, 'service-item');
      const items = xblks(itemListXml, 'item').map(ib => ({
        proto: protoName(xv(ib._inner, 'protocol')),
        port: xv(ib._inner, 'server-port') || '-',
      }));
      const tcp = items.filter(i=>i.proto==='TCP').map(i=>i.port).filter(p=>p!=='-');
      const udp = items.filter(i=>i.proto==='UDP').map(i=>i.port).filter(p=>p!=='-');
      const icmp = items.filter(i=>i.proto==='ICMP').map(i=>i.port).filter(p=>p!=='-');
      const others = items.filter(i=>!['TCP','UDP','ICMP'].includes(i.proto));
      const protoSet = [...new Set(items.map(i=>i.proto).filter(p=>p!=='-'))];
      out.push({
        category: 'service', name,
        proto: protoSet.length > 1 ? protoSet.join('/') : (protoSet[0] || '-'),
        tcpPorts: tcp.join(', ') || '-',
        udpPorts: udp.join(', ') || '-',
        icmpType: icmp.join(', ') || '-',
        members: others.length ? others.map(o=>`${o.proto}:${o.port}`).join(', ') : '-',
        comment,
      });
    });
    return out;
  }

  // ── Policies ─────────────────────────────────────────────────────────────────
  // from-alias-list/to-alias-list → item（每個 item 文字內容本身就是引用的 alias 名稱，
  // 官方社群 parser `for a in x: rule_src = a.text` 已查證確認，非再巢狀一層）
  function _aliasListRefs(listXml) {
    return xva(listXml, 'item').map(t=>t.trim()).filter(Boolean);
  }
  // 依 aliasMap 把引用名稱分流成介面清單／位址清單（一個規則可能同時引用多個別名，
  // 其中有的指介面、有的指位址群組，兩者不互斥）。real-world WatchGuard 政策的 from/to
  // 引用值不保證一定是 alias-list 的名稱——也可能直接引用 address-group-list 的群組名稱
  // （社群 parser 對 from-alias-list/to-alias-list 只讀取文字內容比對，未強制要求該名稱
  // 必須先在 alias-list 定義過），故 aliasMap 查無結果時，退一步查 addrNames（address-group-list
  // ＋ alias-list 展開後的位址物件名稱集合）是否直接命中
  function _classifyRefs(refs, aliasMap, addrNames) {
    const intf = [], addr = [];
    refs.forEach(r => {
      const a = aliasMap.get(r);
      if (a) {
        if (a.intfNames.length) intf.push(...a.intfNames);
        if (a.addrTokens.length || !a.hasInterface) addr.push(r); // 位址型別別名以名稱引用（對應 addresses 分頁的展開項），保留可點擊查詢
      } else if (addrNames.has(r)) {
        addr.push(r); // 直接引用 address-group 名稱（未透過 alias-list 包一層）
      } else if (/^any(-.*)?$/i.test(r)) {
        addr.push('any');
      } else {
        addr.push(r); // 找不到定義（如系統內建別名），原樣視為位址型 token 傳遞
      }
    });
    return {
      intf: intf.length ? [...new Set(intf)].join(', ') : '-',
      addr: addr.length ? [...new Set(addr)].join(', ') : 'any',
    };
  }
  function parsePolicies(xml, aliasMap, addrNames, addrTypeMap) {
    const out = [];
    xblks(xml, 'abs-policy').forEach((b, idx) => {
      const inner = b._inner;
      const name = xv(inner, 'name') || `Policy-${idx+1}`;
      const srcRefs = _aliasListRefs(xv(inner, 'from-alias-list'));
      const dstRefs = _aliasListRefs(xv(inner, 'to-alias-list'));
      const srcCls = _classifyRefs(srcRefs, aliasMap, addrNames);
      const dstCls = _classifyRefs(dstRefs, aliasMap, addrNames);
      const service = xv(inner, 'service') || 'Any';
      const enabledRaw = xv(inner, 'enabled');
      const status = enabledRaw === '' && !hasTag(inner, 'enabled') ? 'enable' : (isTrue(enabledRaw) ? 'enable' : 'disable');
      // firewall（action）：官方確切字面值本輪未能自社群 parser 原始碼查得實際範例，依常見
      // WatchGuard System Manager 用語（Allowed/Denied）做大小寫不敏感的寬鬆比對，非窮舉字面
      // 值精確匹配；查無法辨識時預設從嚴歸為 deny（比照本專案「無法辨識時預設拒絕」慣例）
      const fw = (xv(inner, 'firewall') || '').toLowerCase();
      const action = /allow/.test(fw) ? 'accept' : 'deny';
      const policyNat = xv(inner, 'policy-nat') || '';
      const natEnabled = policyNat && !/^(none|no|disabled?|-)$/i.test(policyNat.trim());
      const desc = xv(inner, 'description') || '-';
      const settingsXml = xv(inner, 'settings');
      const schedule = xv(settingsXml, 'schedule') || 'always';
      const logEnabled = xv(settingsXml, 'log-enabled');
      const srcSplit = _splitAddr(srcCls.addr, addrTypeMap);
      const dstSplit = _splitAddr(dstCls.addr, addrTypeMap);
      out.push({
        id: String(idx+1), name,
        srcIntf: srcCls.intf, dstIntf: dstCls.intf,
        srcAddr: srcCls.addr, dstAddr: dstCls.addr,
        srcAddr4: srcSplit.v4, srcAddr6: srcSplit.v6,
        dstAddr4: dstSplit.v4, dstAddr6: dstSplit.v6,
        service, schedule, action,
        nat: natEnabled ? 'enable' : 'disable', ippool: 'disable', poolname: policyNat || '-',
        logtraffic: logEnabled === '' && !hasTag(settingsXml, 'log-enabled') ? 'disable' : (isTrue(logEnabled) ? 'all' : 'disable'),
        utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
        status, users: '-', groups: '-', comments: desc, _vdom: '',
      });
    });
    return out;
  }

  // ── Routes ───────────────────────────────────────────────────────────────────
  function parseRoutes(xml) {
    const out = [];
    const spXml = xv(xml, 'system-parameters');
    const routeXml = xv(spXml || xml, 'route');
    xblks(routeXml || xml, 'route-entry').forEach((b, idx) => {
      const inner = b._inner;
      const dest = xv(inner, 'dest-address') || '0.0.0.0';
      const mask = xv(inner, 'mask') || '0.0.0.0';
      const gw = xv(inner, 'gateway-ip') || '-';
      const bits = maskToBits(mask);
      out.push({
        type: (dest === '0.0.0.0' && bits === 0) ? 'default' : 'static',
        id: String(idx+1), dst: `${dest}/${bits}`, gateway: gw, device: '-',
        distance: '1', priority: '1', blackhole: 'disable', vrf: 'main',
        status: 'enable', comment: '-', protocol_detail: '-', _vdom: '',
      });
    });
    return out;
  }

  function detect(text) {
    return /<abs-policy-list/i.test(text) && /<interface-list/i.test(text) && /<address-group-list/i.test(text);
  }

  function parse(text) {
    const xml = (text || '').replace(/\r\n/g, '\n');
    const { aliasMap } = parseAliases(xml);
    const addresses = parseAddressObjects(xml);
    const addrNames = new Set(addresses.map(a => a.name));
    return {
      vendor: 'WatchGuard',
      deviceInfo: parseDeviceInfo(),
      interfaces: parseInterfaces(xml),
      policies: parsePolicies(xml, aliasMap, addrNames, buildAddrTypeMap(addresses)),
      routes: parseRoutes(xml),
      ha: null,
      // NAT/VPN/Users：查無官方 schema 佐證（見檔頭註解），維持空陣列而非 null——merge()/
      // renderSection() 對這三個欄位全部假設是陣列（無 optional chaining guard），null 會在
      // 跨廠牌合併分析或切換分頁時直接拋錯；改由 app.js 的 NAT_UNSUPPORTED/VPN_UNSUPPORTED/
      // USERS_UNSUPPORTED 白名單機制（比照既有 WIFI_UNSUPPORTED）在分頁顯示查無佐證警語
      nat: [], vpn: [], users: [], addresses,
      services: parseServiceObjects(xml),
      schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      // dhcp/dns/snmp/logservers/wwan/wlan：本輪查無對應標籤佐證，比照 EdgeRouter/OpenWrt
      // 既有慣例明確標示為 null（非空物件/空陣列），這些欄位在 app.js 皆用 truthy/optional
      // chaining guard 讀取，null 可安全短路
      dhcp: null, dns: null, snmp: null, logservers: null, wwan: null, wlan: null,
    };
  }

  return { parse, detect };
})();
