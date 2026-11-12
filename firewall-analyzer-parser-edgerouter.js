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
// destination 三種 type）；protocols/static/route；system/login/user（本機帳號，2026-08-19
// 對外查證官方 VyOS 文件新增，EdgeOS 為同源 fork 語法一致）。VPN(vpn ipsec)／DHCP Server／
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

  function parseDeviceInfo(tree, text) {
    const sys = child(tree, 'system');
    // config.boot 檔尾「/* Release version: v2.0.9-hotfix.7.… */」（XN127）
    const rel = (String(text || '').match(/\/\*\s*Release version:\s*(v?\d[\w.\-]*)\s*\*\//) || [])[1];
    return { vendor: 'EdgeRouter', hostname: val(sys, 'host-name') || '-', firmware: rel ? `EdgeOS ${rel}` : '-', model: '-', serial: '-', vdom: [] };
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
      if (fw) {
        ['in', 'out', 'local'].forEach(dir => {
          // IPv6 規則集以 ipv6-name 綁定（第十三輪 NE），key 加 6: 前綴與 IPv4 的 name 區分
          [['name', ''], ['ipv6-name', '6:']].forEach(([k, pre]) => {
            const rn = val(child(fw, dir), k);
            if (!rn) return;
            bind[pre + rn] = bind[pre + rn] || [];
            bind[pre + rn].push(name);
          });
        });
      }
      // EdgeRouter 允許把 firewall 直接綁在 VLAN sub-interface（vif）上，而非只綁在
      // 實體介面本身，先前只掃 ethernet.*.firewall 會漏掉這種綁定，導致對應規則的
      // srcIntf 一律顯示 '-'（2026-09 全功能審查發現）
      const vifs = childrenPrefixed(node, 'vif');
      Object.entries(vifs).forEach(([vkey, vnode]) => {
        const vlanId = vkey.replace(/^vif\s+/, '');
        const vfw = child(vnode, 'firewall');
        if (!vfw) return;
        ['in', 'out', 'local'].forEach(dir => {
          [['name', ''], ['ipv6-name', '6:']].forEach(([k, pre]) => {
            const rn = val(child(vfw, dir), k);
            if (!rn) return;
            bind[pre + rn] = bind[pre + rn] || [];
            bind[pre + rn].push(`${name}.${vlanId}`);
          });
        });
      });
    });
    return bind;
  }

  // netfilter 式鏈評估資料（XN127，EdgeOS 與 VyOS 1.3 共用；見 core.js _nfQueryChain()）：
  // 介面 firewall in／out／local name X 綁定保留方向——in 進 fwd-in、out 進 fwd-out（以出口介面比對）、local 進 input，
  // 每個綁定合成一條 jump；規則集內的規則依序比對，結尾補上 default-action（沒寫＝drop）。
  // 轉送依序過 fwd-in 與 fwd-out（in 規則集放行後，出口介面的 out 規則集仍要判斷）；沒有綁定規則集的介面不過濾（鏈尾放行）。
  // 介面種類：ethernet（含 vif、pppoe）、switch、bonding、bridge、openvpn、wireguard、tunnel、l2tp-client／pptp-client
  const VYATTA_IF_TYPES = ['ethernet', 'switch', 'bonding', 'bridge', 'openvpn', 'wireguard', 'tunnel', 'l2tp-client', 'pptp-client', 'pseudo-ethernet', 'vti', 'pppoe', 'dummy'];
  function vyattaBindings(tree) {
    const out = [];
    const addFw = (name, node) => {
      const fw = child(node, 'firewall');
      if (!fw) return;
      ['in', 'out', 'local'].forEach(dir => [['name', 4], ['ipv6-name', 6]].forEach(([k, fam]) => {
        const rn = val(child(fw, dir), k);
        if (rn) out.push({ iface: name, dir, rs: rn, fam });
      }));
    };
    const ifs = child(tree, 'interfaces');
    VYATTA_IF_TYPES.forEach(t => Object.entries(childrenPrefixed(ifs, t)).forEach(([key, node]) => {
      const name = key.slice(t.length).trim();
      if (!name) return;
      addFw(name, node);
      Object.entries(childrenPrefixed(node, 'vif')).forEach(([vk, vn]) => addFw(`${name}.${vk.replace(/^vif\s+/, '')}`, vn));
      Object.entries(childrenPrefixed(node, 'pppoe')).forEach(([pk, pn]) => addFw(`pppoe${pk.replace(/^pppoe\s+/, '')}`, pn));
    }));
    return out;
  }
  function buildVyattaNf(tree, policies, dfltOf) {
    const anyRule = o => Object.assign({ srcIntf: '-', dstIntf: '-', srcAddr: 'any', dstAddr: 'any', srcAddr4: 'any', dstAddr4: 'any', srcAddr6: '-', dstAddr6: '-',
      service: 'all', schedule: 'always', nat: 'disable', ippool: 'disable', poolname: '-', logtraffic: 'disable', utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
      status: 'enable', users: '-', groups: '-', comments: '', _vdom: '', connState: [] }, o);
    const rsKey = (rs, fam) => `rs:${fam === 6 ? '6:' : ''}${rs}`;
    const rules = [];
    vyattaBindings(tree).forEach((b, i) => rules.push(anyRule({
      id: `bind/${i + 1}`, name: `${b.iface} firewall ${b.dir} → ${b.rs}`, action: 'deny', _family: b.fam === 6 ? 'v6' : 'v4',
      [b.dir === 'out' ? 'dstIntf' : 'srcIntf']: b.iface, _chain: b.dir === 'in' ? 'fwd-in' : b.dir === 'out' ? 'fwd-out' : 'input',
      _mtAct: 'jump', _jumpTarget: rsKey(b.rs, b.fam), _nonterminal: true, _mtHasMatch: true })));
    const seen = new Set();
    policies.forEach(p => {
      const fam = p._family === 'v6' ? 6 : 4, key = rsKey(p.chain, fam);
      rules.push(Object.assign({}, p, { srcIntf: '-', dstIntf: '-', _chain: key, _mtAct: p.action === 'accept' ? 'accept' : 'drop', _nonterminal: false }));
      seen.add(p.chain + '|' + fam);
    });
    // 規則集結尾的 default-action（沒有規則的規則集也要補，綁定後一律由它決定）
    (dfltOf || []).forEach(d => rules.push(anyRule({ id: `${rsKey(d.rs, d.fam)}/default`, name: `${d.rs} default-action ${d.act}`, action: d.act === 'accept' ? 'accept' : 'deny',
      _family: d.fam === 6 ? 'v6' : 'v4', _chain: rsKey(d.rs, d.fam), _mtAct: d.act === 'accept' ? 'accept' : 'drop', _nonterminal: false, _nfDefaultRule: true })));
    return { rules, defaults: {}, forward: ['fwd-in', 'fwd-out'], input: ['input'] };
  }
  // 路由器本身的服務（XN127，EdgeOS 與 VyOS 共用）：service 區塊有寫才算啟用（兩者的設定檔都會列出啟用中的服務）。
  //  EdgeOS：gui（https-port 預設 443、listen-address）、ssh（port 預設 22、listen-address）、telnet（port 預設 23）、
  //          dns forwarding（listen-on 介面）、upnp／upnp2
  //  VyOS：https（listen-address；API 也在這裡）、ssh（port、listen-address）、telnet、dns forwarding（listen-address、allow-from）、upnp
  function parseVyattaRouterPlane(tree) {
    const svc = child(tree, 'service');
    if (!svc) return null;
    const services = [];
    const add = (node, name, kind, dport, portKey) => {
      if (!node) return;
      const p = val(node, portKey || 'port') || dport;
      services.push({ name, kind, port: Number(p) || dport, enabled: !hasFlag(node, 'disable'), listenAddrs: vals(node, 'listen-address') });
    };
    add(child(svc, 'gui'), 'gui', 'rt-web', 443, 'https-port');
    add(child(svc, 'https'), 'https', 'rt-web', 443);
    add(child(svc, 'ssh'), 'ssh', 'admin-ssh', 22);
    add(child(svc, 'telnet'), 'telnet', 'admin-telnet', 23);
    const df = child(child(svc, 'dns'), 'forwarding');
    const dns = df ? { listenIfs: vals(df, 'listen-on'), listenAddrs: vals(df, 'listen-address'), allowFrom: vals(df, 'allow-from') } : null;
    const upnp = child(svc, 'upnp') || child(svc, 'upnp2') ? true : null;
    return { services, dns, upnp };
  }

  // 規則集的 default-action（EdgeOS／VyOS 1.3：firewall name X／ipv6-name X 的 default-action，沒寫＝drop）
  function vyattaRulesetDefaults(tree) {
    const fwNode = child(tree, 'firewall');
    return [...Object.entries(childrenPrefixed(fwNode, 'name')).map(([k, n]) => ({ rs: k.replace(/^name\s+/, ''), fam: 4, act: (val(n, 'default-action') || 'drop').toLowerCase() })),
      ...Object.entries(childrenPrefixed(fwNode, 'ipv6-name')).map(([k, n]) => ({ rs: k.replace(/^ipv6-name\s+/, ''), fam: 6, act: (val(n, 'default-action') || 'drop').toLowerCase() }))];
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
      // IPv4 與 IPv6 位址分開（XN143）：IPv6 位址原本會混進主要／次要位址被當成 IPv4，改收進 ip6s（多台路徑查詢用）
      const addr = val(node, 'address');  // 第一個 address（決定 mode）
      const addrs = vals(node, 'address').filter(a => a && a.includes('/'));
      const v4 = addrs.filter(a => !a.includes(':')), ip6s = addrs.filter(a => a.includes(':'));
      const [ip, mask] = v4[0] ? cidrSplit(v4[0]) : ['-', '-'];
      // 次要IP（Secondary IP，官方 VyOS/EdgeOS 文件：同一介面可重複宣告多筆 `address`
      // statement，附加式非關鍵字機制，與 Junos 同款；2026-08-17 從「僅取第二筆」擴大為
      // 完整收集全部次要IP）
      const secondaryIps = v4.slice(1).map(a => { const [i, m] = cidrSplit(a); return { ip: i, mask: m }; });
      const desc = val(node, 'description') || '';
      const fw = child(node, 'firewall');
      const boundRulesets = fw ? ['in', 'out', 'local'].map(d => val(child(fw, d), 'name')).filter(Boolean) : [];
      out.push({
        name, ip, mask, secondaryIps, ip6s, type: 'physical', vlanId: '-', alias: name, desc,
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
        const vfw = child(vnode, 'firewall');
        const vBoundRulesets = vfw ? ['in', 'out', 'local'].map(d => val(child(vfw, d), 'name')).filter(Boolean) : [];
        out.push({
          name: `${name}.${vlanId}`, ip: vip, mask: vmask, secondaryIps: [], type: 'physical', vlanId, alias: `${name}.${vlanId}`,
          desc: vdesc, status: hasFlag(vnode, 'disable') ? 'down' : 'up',
          mtu: '-', speed: '-', mode: vaddr ? 'static' : 'dhcp', vdom: '-', role: inferRole(vdesc, vBoundRulesets), allowaccess: '-',
        });
      });
    });
    return out;
  }

  function parseAddrOrPort(node, portGroupMap) {
    // source/destination 子區塊：address／port／group{address-group|network-group|port-group}
    // port-group 命中時，埠號定義在具名 firewall group port-group{} 區塊裡（見 parseServiceObjects()），
    // node 自己不會有 port 葉節點——需靠呼叫端傳入的 name→ports 查找表才能正確取得埠號，
    // 否則會靜默讀成空字串（既有 bug，2026-09-16 修復）
    if (!node) return { addr: 'any', port: '' };
    const grp = child(node, 'group');
    if (grp) {
      const addrGrp = val(grp, 'address-group') || val(grp, 'network-group') || val(grp, 'ipv6-address-group') || val(grp, 'ipv6-network-group');
      if (addrGrp) return { addr: addrGrp, port: val(node, 'port') || '' };
      const portGrp = val(grp, 'port-group');
      if (portGrp) {
        const port = (portGroupMap && portGroupMap[portGrp]) || val(node, 'port') || '';
        return { addr: portGrp, port };
      }
    }
    return { addr: val(node, 'address') || 'any', port: val(node, 'port') || '' };
  }

  function parsePolicies(tree, bind, addrTypeMap, portGroupMap) {
    const out = [];
    // firewall name X（IPv4）與 firewall ipv6-name X（IPv6，第十三輪 NE：語法依 Ubiquiti 官方說明與社群設定的
    // 搜尋摘要，介面以 firewall in|out|local ipv6-name X 綁定，與 VyOS 1.3 同源）；IPv6 規則 id 加 v6/ 前綴並標 _family
    const fwNode = child(tree, 'firewall');
    const rulesets = [...Object.entries(childrenPrefixed(fwNode, 'name')).map(([k, n]) => [k.replace(/^name\s+/, ''), n, 4]),
      ...Object.entries(childrenPrefixed(fwNode, 'ipv6-name')).map(([k, n]) => [k.replace(/^ipv6-name\s+/, ''), n, 6])];
    let idx = 0, idx6 = 0;
    rulesets.forEach(([rsName, rsNode, fam]) => {
      const rules = childrenPrefixed(rsNode, 'rule');
      Object.entries(rules).forEach(([rkey, rNode]) => {
        const ruleNum = rkey.replace(/^rule\s+/, '');
        const src = parseAddrOrPort(child(rNode, 'source'), portGroupMap);
        const dst = parseAddrOrPort(child(rNode, 'destination'), portGroupMap);
        const protocol = val(rNode, 'protocol') || 'all';
        const actionRaw = (val(rNode, 'action') || 'drop').toLowerCase();
        const desc = val(rNode, 'description') || '';
        // 連線狀態條件 `state { established enable; related enable; new enable; invalid enable }`（2026-10-01，
        // 供 IP/Policy 查詢「只看新連線」略過僅比對既有連線的規則）
        const stNode = child(rNode, 'state');
        const connState = stNode ? ['new', 'established', 'related', 'invalid'].filter(k => val(stNode, k) === 'enable') : [];
        if (fam === 6) idx6++; else idx++;
        // 2026-08-10 稽核修復：先前完全沒有呼叫 _splitAddr()，srcAddr6/dstAddr6 恆為 '-'，
        // 不論規則引用的 group 實際是否含 IPv6 成員
        const srcAddrSplit = _splitAddr(src.addr, addrTypeMap);
        const dstAddrSplit = _splitAddr(dst.addr, addrTypeMap);
        out.push({
          id: fam === 6 ? 'v6/' + idx6 : idx, name: desc || `${rsName}-${ruleNum}`,
          srcIntf: (bind[(fam === 6 ? '6:' : '') + rsName] || []).join(',') || '-', dstIntf: '-',
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
          users: '-', groups: '-', comments: desc, _vdom: '', connState, chain: rsName, ruleNum, _family: fam === 6 ? 'v6' : 'v4',
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
    // IPv6 群組（第十三輪 NE）：ipv6-address-group／ipv6-network-group，成員葉節點為 address／network（另見 ipv6-network 寫法）
    ['ipv6-address-group', 'ipv6-network-group'].forEach(kind => {
      Object.entries(childrenPrefixed(grp, kind)).forEach(([key, node]) => {
        const members = ['address', 'network', 'ipv6-address', 'ipv6-network'].flatMap(k => vals(node, k));
        out.push({ category: 'address-group', name: key.replace(new RegExp('^' + kind + '\\s+'), ''), type: 'group', subnet: '-', fqdn: '-', startIp: '-', endIp: '-',
          wildcard: '-', iface: '-', color: '0', comment: val(node, 'description') || '', members: members.join(', ') || '-', _vdom: '' });
      });
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
    // 只指定出口介面的靜態路由（set protocols static interface-route X next-hop-interface IF）
    const ifRoutes = childrenPrefixed(child(child(tree, 'protocols'), 'static'), 'interface-route');
    Object.entries(ifRoutes).forEach(([key, node]) => {
      const dst = key.replace(/^interface-route\s+/, '');
      Object.entries(childrenPrefixed(node, 'next-hop-interface')).forEach(([nkey, nnode]) => {
        out.push({
          type: dst === '0.0.0.0/0' ? 'default' : 'static', id: String(seq++),
          dst, gateway: '-', device: nkey.replace(/^next-hop-interface\s+/, ''),
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
          matchSrc: val(child(node, 'source'), 'address') || '',  // 來源條件（XN127 rt-dstnat-broad 判斷用）
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

  // system/login/user <name> {authentication{...} level admin|operator} —官方 VyOS 文件
  // 確認語法（EdgeOS 為同源 fork，語法一致），level 省略時文件明載預設視為 admin。欄位形狀
  // 比照既有 CiscoASA 最小化慣例，不硬湊查無官方佐證的 status/twoFactor 欄位
  function parseUsers(tree) {
    const out = [];
    const login = child(child(tree, 'system'), 'login');
    const users = childrenPrefixed(login, 'user');
    Object.entries(users).forEach(([key, node]) => {
      const name = key.replace(/^user\s+/, '');
      const level = val(node, 'level') || 'admin';
      out.push({ name, role: level, type: level === 'operator' ? 'local' : 'admin' });
    });
    return out;
  }

  function detect(text) {
    return /ethernet\s+eth\d+\s*\{/.test(text) && /firewall\s*\{/.test(text);
  }

  // ── SNMP／syslog／DNS／DHCP（2026-10-09，第十四輪 OC；VyOS 共用）──────────────────────
  // 語法依 vyos-1x smoketest 的真實 config.boot（1.3：syslog host、DHCP subnet 下 default-router／
  // dns-server、range N { start stop }）與遷移後的 set 指令（新版：syslog remote、option default-router／
  // name-server），EdgeOS 另以 Comcast 真實 config.boot 確認 DHCP `start A { stop B }` 與 DNS forwarding。
  // 形狀比照 FortiGate／MikroTik；沒有對應設定時回傳 null（onParsed() 只做 truthy 判斷）
  function tagName(k) { return unquote(k.slice(k.indexOf(' ') + 1).trim()); }
  function parseServicesVyatta(tree) {
    const svc = child(tree, 'service'), sys = child(tree, 'system');
    let snmp = null;
    const sn = child(svc, 'snmp');
    if (sn) {
      snmp = { enabled: true, agent: { name: '-', description: val(sn, 'description') || '-', location: val(sn, 'location') || '-', contact: val(sn, 'contact') || '-', version: [] }, communities: [], v3users: [], trapServers: [] };
      Object.entries(childrenPrefixed(sn, 'community')).forEach(([k, n]) => {
        snmp.communities.push({ name: tagName(k), permission: val(n, 'authorization') === 'rw' ? 'rw' : 'ro', allowedHosts: [...vals(n, 'network'), ...vals(n, 'client')], events: '-', status: 'enable' });
      });
      vals(sn, 'community').forEach(c => snmp.communities.push({ name: c, permission: 'ro', allowedHosts: [], events: '-', status: 'enable' }));
      const traps = (node, ver) => {
        Object.entries(childrenPrefixed(node, 'trap-target')).forEach(([k, n]) => snmp.trapServers.push({ ip: tagName(k), port: val(n, 'port') || '162', community: val(n, 'community') || '-', version: ver }));
        vals(node, 'trap-target').forEach(ip => snmp.trapServers.push({ ip, port: '162', community: '-', version: ver }));
      };
      traps(sn, 'v2c');
      const v3 = child(sn, 'v3');
      Object.entries(childrenPrefixed(v3, 'user')).forEach(([k, n]) => {
        snmp.v3users.push({ name: tagName(k), authProto: val(child(n, 'auth'), 'type') || '-', privProto: val(child(n, 'privacy'), 'type') || '-', secLevel: child(n, 'privacy') ? 'auth-priv' : (child(n, 'auth') ? 'auth-no-priv' : '-'), notifyHost: '-', status: 'enable' });
      });
      traps(v3, 'v3');
      if (snmp.communities.length) snmp.agent.version.push('v2c');
      if (snmp.v3users.length) snmp.agent.version.push('v3');
    }
    let logservers = null;
    const sl = child(sys, 'syslog');
    const hosts = Object.entries({ ...childrenPrefixed(sl, 'host'), ...childrenPrefixed(sl, 'remote') });
    if (hosts.length) {
      logservers = { syslog: [], fortianalyzer: [], netflow: [], logForward: [] };
      hosts.forEach(([k, n]) => {
        let server = tagName(k), port = val(n, 'port');
        const hp = server.match(/^([^:]+):(\d+)$/);   // 1.3 允許 host 名稱:埠
        if (hp) { server = hp[1]; port = port || hp[2]; }
        const fac = Object.entries(childrenPrefixed(n, 'facility'))[0];
        logservers.syslog.push({ name: server, server, port: port || '514', facility: fac ? tagName(fac[0]) : '-', format: 'default',
          protocol: (val(n, 'protocol') || 'udp').toUpperCase(), level: fac ? val(fac[1], 'level') || '-' : '-', status: 'enable' });
      });
    }
    let dns = null;
    const fw = child(child(svc, 'dns'), 'forwarding');
    const fwServers = [...vals(fw, 'name-server'), ...Object.keys(childrenPrefixed(fw, 'name-server')).map(tagName)];
    const sysServers = vals(sys, 'name-server');
    const list = sysServers.length ? sysServers : fwServers;
    if (list.length || fw) {
      dns = { servers: list.slice(0, 1), secondaries: list.slice(1), domain: val(sys, 'domain-name') || '-', proxy: !!fw,
        proxyRules: fw && sysServers.length ? fwServers.map(x => ({ domain: '*', target: x })) : [], dnsOverTls: false, cacheSize: val(fw, 'cache-size') || '-', static: [] };
    }
    let dhcp = null;
    const ds = child(svc, 'dhcp-server');
    const servers = [];
    Object.entries(childrenPrefixed(ds, 'shared-network-name')).forEach(([nk, net]) => {
      Object.entries(childrenPrefixed(net, 'subnet')).forEach(([sk, sub]) => {
        const opt = child(sub, 'option');
        const cidr = tagName(sk);
        const dnsList = vals(sub, 'dns-server').length ? vals(sub, 'dns-server') : vals(opt, 'name-server');
        const ranges = [...Object.entries(childrenPrefixed(sub, 'start')).map(([k, n]) => [tagName(k), val(n, 'stop')]),
          ...Object.values(childrenPrefixed(sub, 'range')).map(n => [val(n, 'start'), val(n, 'stop')])];
        (ranges.length ? ranges : [['-', '-']]).forEach(([a, b]) => servers.push({
          name: tagName(nk), iface: '-', startIp: a || '-', endIp: b || '-',
          gateway: val(sub, 'default-router') || val(opt, 'default-router') || '-', mask: cidr.includes('/') ? cidrSplit(cidr)[1] : '-',
          dns1: dnsList[0] || '-', dns2: dnsList[1] || '-', domain: val(sub, 'domain-name') || val(opt, 'domain-name') || '-',
          lease: val(sub, 'lease') || '-', status: /^(true|enable)$/.test(val(ds, 'disabled')) || hasFlag(ds, 'disable') ? 'disable' : 'enable', comment: cidr }));
      });
    });
    const dr = child(svc, 'dhcp-relay');
    const relays = vals(dr, 'server').map(ip => ({ name: '-', iface: [...vals(dr, 'interface'), ...vals(dr, 'listen-interface')].join(', ') || '-', serverIp: ip, status: 'enable', comment: '' }));
    if (servers.length || relays.length) dhcp = { servers, relays };
    return { snmp, logservers, dns, dhcp };
  }

  function parse(text) {
    const tree = parseTree(text);
    const bind = buildRulesetBinding(tree);
    // 位址物件需先解析出來，才能建 addrTypeMap 供 policies 的 source/destination group 名稱
    // 反查 v4/v6 型別（見 buildEdgeRouterAddrTypeMap() 定義處註解）
    const addresses = parseAddressObjects(tree);
    // 服務物件（含 port-group）同樣需先解析出來，才能建 name→ports 查找表供 policies 的
    // source/destination port-group 引用反查埠號（見 parseAddrOrPort() 定義處註解）
    const services = parseServiceObjects(tree);
    const portGroupMap = {};
    services.forEach(s => { portGroupMap[s.name] = s.tcpPorts; });
    return {
      vendor: 'EdgeRouter',
      deviceInfo: parseDeviceInfo(tree, text),
      interfaces: parseInterfaces(tree, bind),
      ...(pols => ({ policies: pols, nf: buildVyattaNf(tree, pols, vyattaRulesetDefaults(tree)) }))(parsePolicies(tree, bind, buildEdgeRouterAddrTypeMap(addresses), portGroupMap)),
      rtRouter: parseVyattaRouterPlane(tree),
      routes: parseRoutes(tree),
      ha: null, nat: parseNAT(tree), vpn: [],
      addresses,
      services,
      users: parseUsers(tree), schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      // 2026-08-01 瀏覽器端到端測試意外抓到既有的「新增廠牌未同步 onParsed() 資料形狀」bug：
      // onParsed()（App.js）對 d.dhcp/d.dns/d.snmp/d.logservers 只做單層 truthy 判斷（如
      // `d.dhcp&&(d.dhcp.servers.length>0...)`），未用 optional chaining，若此處給空陣列/
      // 空物件（truthy 但缺欄位）會在讀取 .servers/.communities 等子欄位時對 undefined 呼叫
      // .length 直接拋錯，導致單獨上傳本廠牌（未與其他廠牌合併）分析時整頁崩潰。比照 `ha:
      // null` 既有慣例改用 null（onParsed()/exportHTML()/merge() 對這些欄位的 guard 皆已是
      // `d.xxx&&...`，null 可安全短路），非新增規則、只是修正型別
      ...parseServicesVyatta(tree),
      wwan: null, wlan: null,
    };
  }

  // VyOS（同為 Vyatta 語系，2026-10-02 新增）共用樹狀解析與查詢函式，見 firewall-analyzer-parser-vyos.js
  return { parse, detect, _lib: { parseTree, unquote, child, val, vals, hasFlag, childrenPrefixed, cidrSplit, parseAddrOrPort, parseRoutes, parseUsers, parseServicesVyatta, buildVyattaNf, vyattaRulesetDefaults, vyattaBindings, parseVyattaRouterPlane } };
})();

