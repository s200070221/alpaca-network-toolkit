// ══════════════════════════════════════════════════════════
//  UBIQUITI EDGEROUTER (EdgeOS) PARSER
// ══════════════════════════════════════════════════════════
// config.boot 為巢狀大括號樹狀格式（VyOS/Vyatta 語系），非扁平 set 指令：set 只是互動式 CLI
// 輸入語法，存檔格式沒有 set／沒有分號，每個葉節點是單獨一行 "key value"，區塊用 {} 巢狀
// （2026-08-01 對外重新查證後修正 now.md 原始評估的誤判——原以為與 Juniper set path value
// 高度相似，實際上不能重用 JuniperParser 的 parseJunosTree()：Junos 是用分號斷句，EdgeOS
// 是用換行斷句，需另寫 tokenizer）。查證來源：真實裝置匯出檔
// github.com/stevejenkins/UBNT-EdgeRouter-Example-Configs 交叉比對官方 UISP Help Center
// 文件（Source/Destination NAT、Static Route、Firewall Group）。
// 已查證語法：system/host-name；interfaces/ethernet（含 vif 802.1Q 子介面）；firewall 具名
// 規則集（default-action／rule N／state／source／destination／log／group 引用）；firewall
// group（address-group／network-group／port-group）；service/nat（masquerade／source／
// destination 三種 type）；protocols/static/route。VPN(vpn ipsec)／DHCP Server／Users／
// Schedules 因本輪未查證完整屬性語法，維持空值不猜測（比照既有 Zyxel 慣例）。
// 已知信心度較低項目：各層級的 "disable" 裸旗標（停用該介面/規則）依 VyOS/Vyatta 語系通用
// 慣例支援，但本輪未找到 EdgeOS 官方逐字範例佐證此用法，非查無來源就不支援（該慣例在同語系
// 產品中極為標準），僅信心度略低於已逐字核對的其餘語法。
const EdgeRouterParser = (() => {

  // ── config.boot 大括號樹 tokenizer（換行斷句版，結構參考 JuniperParser 的
  // parseJunosTree() 但因分隔字元不同（換行 vs 分號）不共用程式碼）。字元級掃描（非逐行），
  // 因真實裝置匯出檔的簡短區塊常見單行緊湊寫法（如 "in { name WAN_IN }"），逐行判斷
  // 「這行是否以 { 結尾」會誤判成單一葉節點，必須不論 {/} 是否與其他內容同一行都能正確斷句
  function tokenizeEdgeOS(src) {
    const out = [];
    let buf = '';
    let inStr = false, strCh = '';
    for (let ci = 0; ci < src.length; ci++) {
      const ch = src[ci];
      if (inStr) {
        buf += ch;
        if (ch === strCh) inStr = false;
        continue;
      }
      if (ch === '"' || ch === "'") { inStr = true; strCh = ch; buf += ch; continue; }
      if (ch === '{') {
        const t = buf.trim();
        out.push(t ? t + ' {' : '{');
        buf = '';
      } else if (ch === '}') {
        const t = buf.trim();
        if (t) out.push(t);
        out.push('}');
        buf = '';
      } else if (ch === '\n' || ch === '\r') {
        const t = buf.trim();
        if (t) out.push(t);
        buf = '';
      } else {
        buf += ch;
      }
    }
    const t = buf.trim();
    if (t) out.push(t);
    return out;
  }

  function parseTree(text) {
    const lines = tokenizeEdgeOS(text).filter(l => l && !l.startsWith('/*') && !l.startsWith('*'));
    let i = 0;
    function readBlock() {
      const node = { _values: [], _children: {} };
      while (i < lines.length) {
        const line = lines[i]; i++;
        if (line === '}') break;
        if (line.endsWith('{')) {
          const key = line.slice(0, -1).trim();
          node._children[key] = readBlock();
        } else {
          node._values.push(line);
        }
      }
      return node;
    }
    const root = { _values: [], _children: {} };
    while (i < lines.length) {
      const line = lines[i]; i++;
      if (line === '}') continue;
      if (line.endsWith('{')) {
        const key = line.slice(0, -1).trim();
        root._children[key] = readBlock();
      } else {
        root._values.push(line);
      }
    }
    return root;
  }

  // ── Tree query helpers ──────────────────────────────────────────────────────
  function unquote(s) {
    if (s.length >= 2 && ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))) return s.slice(1, -1);
    return s;
  }
  function child(node, key) { return node ? node._children[key] : null; }
  function val(node, key) {
    if (!node) return '';
    const m = node._values.find(v => v === key || v.startsWith(key + ' '));
    return m ? unquote(m.slice(key.length).trim()) : '';
  }
  function vals(node, key) {
    if (!node) return [];
    return node._values.filter(v => v === key || v.startsWith(key + ' ')).map(v => unquote(v.slice(key.length).trim()));
  }
  function hasFlag(node, key) { return node ? node._values.includes(key) : false; }
  function childrenPrefixed(node, prefix) {
    if (!node) return {};
    return Object.fromEntries(Object.entries(node._children).filter(([k]) => k === prefix || k.startsWith(prefix + ' ')));
  }

  function maskFromBits(bits) {
    if (!Number.isFinite(bits)) return '-';
    const m = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    return [(m >>> 24) & 255, (m >>> 16) & 255, (m >>> 8) & 255, m & 255].join('.');
  }
  function cidrSplit(cidr) {
    const [ip, bits] = cidr.split('/');
    return [ip, maskFromBits(parseInt(bits, 10))];
  }

  function parseDeviceInfo(tree) {
    const sys = child(tree, 'system');
    return { vendor: 'EdgeRouter', hostname: val(sys, 'host-name') || '-', firmware: '-', model: '-', serial: '-', vdom: [] };
  }

  // ruleset 名稱 → 綁定介面清單（走訪 interfaces.ethernet.*.firewall.{in,out,local}，
  // EdgeOS 無 zone 概念，比照既有 MikroTik parsePolicies() 用 chain 名稱回填 srcIntf 的
  // 慣例，改用「規則集綁定的介面」回填 srcIntf，dstIntf 固定 '-'）
  function buildRulesetBinding(tree) {
    const bind = {};
    const eths = childrenPrefixed(child(tree, 'interfaces'), 'ethernet');
    Object.entries(eths).forEach(([key, node]) => {
      const name = key.replace(/^ethernet\s+/, '');
      const fw = child(node, 'firewall');
      if (!fw) return;
      ['in', 'out', 'local'].forEach(dir => {
        const rn = val(child(fw, dir), 'name');
        if (!rn) return;
        bind[rn] = bind[rn] || [];
        bind[rn].push(name);
      });
    });
    return bind;
  }

  function inferRole(desc, boundRulesets) {
    const text = (desc + ' ' + boundRulesets.join(' ')).toUpperCase();
    if (/WAN/.test(text)) return 'WAN';
    if (/DMZ/.test(text)) return 'DMZ';
    return 'LAN';
  }

  function parseInterfaces(tree, bind) {
    const out = [];
    const eths = childrenPrefixed(child(tree, 'interfaces'), 'ethernet');
    Object.entries(eths).forEach(([key, node]) => {
      const name = key.replace(/^ethernet\s+/, '');
      const addr = val(node, 'address');
      const [ip, mask] = addr && addr.includes('/') ? cidrSplit(addr) : ['-', '-'];
      // 次要IP（Secondary IP，官方 VyOS/EdgeOS 文件：同一介面可重複宣告多筆 `address`
      // statement，附加式非關鍵字機制，與 Junos 同款；2026-08-17 從「僅取第二筆」擴大為
      // 完整收集全部次要IP）
      const secondaryIps = vals(node, 'address').slice(1).map(a => {
        const [i, m] = a && a.includes('/') ? cidrSplit(a) : ['-', '-'];
        return { ip: i, mask: m };
      });
      const desc = val(node, 'description') || '';
      const fw = child(node, 'firewall');
      const boundRulesets = fw ? ['in', 'out', 'local'].map(d => val(child(fw, d), 'name')).filter(Boolean) : [];
      out.push({
        name, ip, mask, secondaryIps, type: 'physical', vlanId: '-', alias: name, desc,
        status: hasFlag(node, 'disable') ? 'down' : 'up',
        mtu: val(node, 'mtu') || '-', speed: '-', mode: addr ? 'static' : 'dhcp',
        vdom: '-', role: inferRole(desc, boundRulesets), allowaccess: '-',
      });
      // vif 子介面（802.1Q VLAN sub-interface）展開成獨立列
      const vifs = childrenPrefixed(node, 'vif');
      Object.entries(vifs).forEach(([vkey, vnode]) => {
        const vlanId = vkey.replace(/^vif\s+/, '');
        const vaddr = val(vnode, 'address');
        const [vip, vmask] = vaddr && vaddr.includes('/') ? cidrSplit(vaddr) : ['-', '-'];
        const vdesc = val(vnode, 'description') || '';
        out.push({
          name: `${name}.${vlanId}`, ip: vip, mask: vmask, secondaryIps: [], type: 'physical', vlanId, alias: `${name}.${vlanId}`,
          desc: vdesc, status: hasFlag(vnode, 'disable') ? 'down' : 'up',
          mtu: '-', speed: '-', mode: vaddr ? 'static' : 'dhcp', vdom: '-', role: inferRole(vdesc, []), allowaccess: '-',
        });
      });
    });
    return out;
  }

  function parseAddrOrPort(node) {
    // source/destination 子區塊：address／port／group{address-group|network-group|port-group}
    if (!node) return { addr: 'any', port: '' };
    const grp = child(node, 'group');
    if (grp) {
      const g = val(grp, 'address-group') || val(grp, 'network-group') || val(grp, 'port-group');
      if (g) return { addr: g, port: val(node, 'port') || '' };
    }
    return { addr: val(node, 'address') || 'any', port: val(node, 'port') || '' };
  }

  function parsePolicies(tree, bind, addrTypeMap) {
    const out = [];
    const rulesets = childrenPrefixed(child(tree, 'firewall'), 'name');
    let idx = 0;
    Object.entries(rulesets).forEach(([key, rsNode]) => {
      const rsName = key.replace(/^name\s+/, '');
      const rules = childrenPrefixed(rsNode, 'rule');
      Object.entries(rules).forEach(([rkey, rNode]) => {
        const ruleNum = rkey.replace(/^rule\s+/, '');
        const src = parseAddrOrPort(child(rNode, 'source'));
        const dst = parseAddrOrPort(child(rNode, 'destination'));
        const protocol = val(rNode, 'protocol') || 'all';
        const actionRaw = (val(rNode, 'action') || 'drop').toLowerCase();
        const desc = val(rNode, 'description') || '';
        idx++;
        // 2026-08-10 稽核修復：先前完全沒有呼叫 _splitAddr()，srcAddr6/dstAddr6 恆為 '-'，
        // 不論規則引用的 group 實際是否含 IPv6 成員
        const srcAddrSplit = _splitAddr(src.addr, addrTypeMap);
        const dstAddrSplit = _splitAddr(dst.addr, addrTypeMap);
        out.push({
          id: idx, name: desc || `${rsName}-${ruleNum}`,
          srcIntf: (bind[rsName] || []).join(',') || '-', dstIntf: '-',
          srcAddr: src.addr, dstAddr: dst.addr,
          srcAddr4: srcAddrSplit.v4, srcAddr6: srcAddrSplit.v6,
          dstAddr4: dstAddrSplit.v4, dstAddr6: dstAddrSplit.v6,
          service: dst.port ? `${protocol}/${dst.port}` : protocol,
          schedule: 'always',
          action: actionRaw === 'accept' ? 'accept' : 'deny',
          nat: 'disable', ippool: 'disable', poolname: '-',
          logtraffic: val(rNode, 'log') === 'enable' ? 'all' : 'disable',
          utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
          status: hasFlag(rNode, 'disable') ? 'disable' : 'enable',
          users: '-', groups: '-', comments: desc, _vdom: '',
        });
      });
    });
    return out;
  }

  function parseAddressObjects(tree) {
    const out = [];
    const grp = child(child(tree, 'firewall'), 'group');
    if (!grp) return out;
    const addrGroups = childrenPrefixed(grp, 'address-group');
    Object.entries(addrGroups).forEach(([key, node]) => {
      const name = key.replace(/^address-group\s+/, '');
      const members = vals(node, 'address');
      out.push({ category: 'address-group', name, type: 'group', subnet: '-', fqdn: '-', startIp: '-', endIp: '-',
        wildcard: '-', iface: '-', color: '0', comment: val(node, 'description') || '', members: members.join(', ') || '-', _vdom: '' });
    });
    const netGroups = childrenPrefixed(grp, 'network-group');
    Object.entries(netGroups).forEach(([key, node]) => {
      const name = key.replace(/^network-group\s+/, '');
      const members = vals(node, 'network');
      out.push({ category: 'address-group', name, type: 'group', subnet: '-', fqdn: '-', startIp: '-', endIp: '-',
        wildcard: '-', iface: '-', color: '0', comment: val(node, 'description') || '', members: members.join(', ') || '-', _vdom: '' });
    });
    return out;
  }

  // EdgeRouter 的 group（address-group/network-group）本身就是最終位址清單——members 存的是
  // 字面 IP/CIDR 值，不是其他物件的名稱引用，與共用 buildAddrTypeMap()「members 是名稱、需要
  // 二次查表」的假設不同（那套適用於 FortiGate/PaloAlto/Juniper/SonicWall），故另寫直接對
  // 字面值做冒號判斷的版本；直接沿用 parseAddressObjects() 已展開好的 members 字串，不重複
  // 走一次 tree（比照既有 buildMikrotikAddrTypeMap() 的做法精神一致，但 MikroTik 是從原始
  // section 直接建表，這裡因為 EdgeRouter 沒有「展開前/展開後名稱不同」的問題，可以直接讀
  // parseAddressObjects() 的輸出）
  function buildEdgeRouterAddrTypeMap(addressObjects) {
    const map = new Map();
    (addressObjects || []).forEach(o => {
      if (o.category !== 'address-group') return;
      const members = (o.members || '').split(/\s*,\s*/).filter(m => m && m !== '-');
      const fams = new Set(members.map(m => m.includes(':') ? 'v6' : 'v4'));
      map.set(o.name, fams.size > 1 ? 'mixed' : (fams.values().next().value || 'v4'));
    });
    return map;
  }

  function parseServiceObjects(tree) {
    const out = [];
    const grp = child(child(tree, 'firewall'), 'group');
    if (!grp) return out;
    const portGroups = childrenPrefixed(grp, 'port-group');
    Object.entries(portGroups).forEach(([key, node]) => {
      const name = key.replace(/^port-group\s+/, '');
      const portStr = vals(node, 'port').join(', ') || '-';
      out.push({ category: 'service', name, proto: '-', tcpPorts: portStr, udpPorts: portStr, icmpType: '-', members: '-', comment: val(node, 'description') || '' });
    });
    return out;
  }

  function parseRoutes(tree) {
    const out = [];
    const routes = childrenPrefixed(child(child(tree, 'protocols'), 'static'), 'route');
    let seq = 1;
    Object.entries(routes).forEach(([key, node]) => {
      const dst = key.replace(/^route\s+/, '');
      const nhs = childrenPrefixed(node, 'next-hop');
      Object.entries(nhs).forEach(([nkey, nnode]) => {
        const nh = nkey.replace(/^next-hop\s+/, '');
        out.push({
          type: dst === '0.0.0.0/0' ? 'default' : 'static', id: String(seq++),
          dst, gateway: nh, device: '-',
          distance: val(nnode, 'distance') || '1', priority: val(nnode, 'distance') || '1',
          blackhole: 'disable', vrf: 'main', status: 'enable', comment: val(nnode, 'description') || '',
          protocol_detail: '-', _vdom: '',
        });
      });
    });
    return out;
  }

  function parseNAT(tree) {
    const out = [];
    const rules = childrenPrefixed(child(child(tree, 'service'), 'nat'), 'rule');
    Object.entries(rules).forEach(([key, node]) => {
      const num = key.replace(/^rule\s+/, '');
      const type = (val(node, 'type') || 'masquerade').toLowerCase();
      const proto = val(node, 'protocol') || '-';
      const status = hasFlag(node, 'disable') ? 'disable' : 'enable';
      const comment = val(node, 'description') || '';
      if (type === 'destination') {
        const dst = child(node, 'destination');
        const inside = child(node, 'inside-address');
        out.push({
          type: 'vip', name: `Rule-${num}`, vipType: 'static', poolType: 'destination',
          extIp: val(dst, 'address') || '-', mapIp: val(inside, 'address') || '-',
          extIntf: val(node, 'inbound-interface') || '-', srcIntf: '-', startIp: '-', endIp: '-',
          portFwd: (val(dst, 'port') || val(inside, 'port')) ? 'enable' : 'disable',
          extPort: val(dst, 'port') || '-', mapPort: val(inside, 'port') || '-', proto, status, comment,
        });
      } else if (type === 'source') {
        const src = child(node, 'source');
        const outside = child(node, 'outside-address');
        out.push({
          type: 'ippool', name: `Rule-${num}`, vipType: 'overload', poolType: 'source',
          extIp: val(src, 'address') || '-', mapIp: val(outside, 'address') || '-',
          extIntf: val(node, 'outbound-interface') || '-', srcIntf: val(node, 'outbound-interface') || '-',
          startIp: '-', endIp: '-', portFwd: 'disable', extPort: '-', mapPort: '-', proto, status, comment,
        });
      } else {
        out.push({
          type: 'ippool', name: `Rule-${num}`, vipType: 'overload', poolType: 'masquerade',
          extIp: '-', mapIp: 'masquerade',
          extIntf: val(node, 'outbound-interface') || '-', srcIntf: val(node, 'outbound-interface') || '-',
          startIp: '-', endIp: '-', portFwd: 'disable', extPort: '-', mapPort: '-', proto, status, comment,
        });
      }
    });
    return out;
  }

  function detect(text) {
    return /ethernet\s+eth\d+\s*\{/.test(text) && /firewall\s*\{/.test(text);
  }

  function parse(text) {
    const tree = parseTree(text);
    const bind = buildRulesetBinding(tree);
    // 位址物件需先解析出來，才能建 addrTypeMap 供 policies 的 source/destination group 名稱
    // 反查 v4/v6 型別（見 buildEdgeRouterAddrTypeMap() 定義處註解）
    const addresses = parseAddressObjects(tree);
    return {
      vendor: 'EdgeRouter',
      deviceInfo: parseDeviceInfo(tree),
      interfaces: parseInterfaces(tree, bind),
      policies: parsePolicies(tree, bind, buildEdgeRouterAddrTypeMap(addresses)),
      routes: parseRoutes(tree),
      ha: null, nat: parseNAT(tree), vpn: [],
      addresses,
      services: parseServiceObjects(tree),
      users: [], schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      // 2026-08-01 瀏覽器端到端測試意外抓到既有的「新增廠牌未同步 onParsed() 資料形狀」bug：
      // onParsed()（App.js）對 d.dhcp/d.dns/d.snmp/d.logservers 只做單層 truthy 判斷（如
      // `d.dhcp&&(d.dhcp.servers.length>0...)`），未用 optional chaining，若此處給空陣列/
      // 空物件（truthy 但缺欄位）會在讀取 .servers/.communities 等子欄位時對 undefined 呼叫
      // .length 直接拋錯，導致單獨上傳本廠牌（未與其他廠牌合併）分析時整頁崩潰。比照 `ha:
      // null` 既有慣例改用 null（onParsed()/exportHTML()/merge() 對這些欄位的 guard 皆已是
      // `d.xxx&&...`，null 可安全短路），非新增規則、只是修正型別
      dhcp: null, dns: null, snmp: null, logservers: null,
      wwan: null, wlan: null,
    };
  }

  return { parse, detect };
})();

