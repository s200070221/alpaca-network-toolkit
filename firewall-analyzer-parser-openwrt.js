// ══════════════════════════════════════════════════════════
//  OPENWRT (UCI) PARSER
// ══════════════════════════════════════════════════════════
// UCI（Unified Configuration Interface）是全新語法家族：`package`/`config`/`option`/`list`
// 的 stanza 格式，無巢狀大括號、無分號，與既有廠牌（攤平 CLI 逐行輸出或大括號巢狀樹狀）
// 皆不同，需要獨立 tokenizer。對外查證來源：OpenWrt 官方文件（openwrt.org firewall 設定
// 範例頁）＋ OpenWrt Wiki UCI 系統文件；規格十餘年幾乎未變，信心度中等（純文件組出，
// 本輪未逐字比對真實裝置匯出檔）。
// 已查證語法：network package `config interface`（`ifname`／`proto`／`ipaddr`／`netmask`）
// ／`config route`（`target`／`netmask`／`gateway`／`interface`）；firewall package
// `config zone`（`name`＋`list network`）／`config rule`（`src`／`dest`／`proto`／`src_ip`／
// `dest_ip`／`src_port`／`dest_port`／`target`／`enabled`）／`config redirect`（port
// forward，`target` 為 `DNAT`（預設）或 `SNAT` 兩種）；`config ipset`（`name`／`match`／
// `list entry`，2026-09-14 新增，對外查證 oldwiki.archive.openwrt.org/doc/uci/firewall 官方
// 選項表＋多筆真實社群範例確認靜態成員語法）＋ rule 的 `option ipset` 引用；dhcp package
// `config dhcp`（`interface`／`start`／`limit`／`leasetime`，`start`/`limit` 為相對網段的
// offset，非絕對 IP，本工具原樣呈現不臆測絕對範圍）。`uci export`（無參數）會把所有
// package 串接成一個檔案、每段以 `package <name>` 開頭分隔；個別 `/etc/config/X` 檔案
// 單獨上傳則不含 `package` 行，故 parser 對未出現過 `package` 行時依已知 config 類型名稱
// 歸類。VPN／WiFi／Users／Schedules／service-object（查無官方逐字語法佐證）與 FQDN 位址
// 物件（ipset 架構本身無法儲存主機名稱，非查證不足）因故維持空值不猜測。
const OpenWrtParser = (() => {

  function unquote(s) {
    s = s.trim();
    if (s.length >= 2 && ((s[0] === "'" && s[s.length - 1] === "'") || (s[0] === '"' && s[s.length - 1] === '"'))) return s.slice(1, -1);
    return s;
  }

  // 已知 config 類型 → package 名稱（單一檔案上傳、無 package 行時的分類依據）
  const TYPE_TO_PACKAGE = {
    interface: 'network', route: 'network', switch: 'network', device: 'network', globals: 'network',
    zone: 'firewall', rule: 'firewall', redirect: 'firewall', forwarding: 'firewall', defaults: 'firewall', ipset: 'firewall',
    dhcp: 'dhcp', dnsmasq: 'dhcp', host: 'dhcp',
  };

  // ── stanza tokenizer：package → sections[]（{type,name,options{},lists{}}）───────────
  function parseUCI(text) {
    const packages = {};
    let currentPkg = null, currentSection = null;
    for (const raw of text.replace(/\r\n/g, '\n').split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      let m;
      if ((m = line.match(/^package\s+(.+)$/))) {
        currentPkg = unquote(m[1]);
        packages[currentPkg] = packages[currentPkg] || [];
        currentSection = null;
        continue;
      }
      if ((m = line.match(/^config\s+(\S+)(?:\s+(.+))?$/))) {
        const type = unquote(m[1]);
        const name = m[2] ? unquote(m[2]) : null;
        const pkg = currentPkg || TYPE_TO_PACKAGE[type] || '_unknown';
        packages[pkg] = packages[pkg] || [];
        currentSection = { type, name, options: {}, lists: {} };
        packages[pkg].push(currentSection);
        continue;
      }
      if (!currentSection) continue;
      if ((m = line.match(/^option\s+(\S+)\s+(.+)$/))) {
        currentSection.options[unquote(m[1])] = unquote(m[2]);
        continue;
      }
      if ((m = line.match(/^list\s+(\S+)\s+(.+)$/))) {
        const key = unquote(m[1]);
        (currentSection.lists[key] = currentSection.lists[key] || []).push(unquote(m[2]));
        continue;
      }
    }
    return packages;
  }

  function val(section, key, dft) {
    const v = section.options[key];
    return v !== undefined ? v : (dft !== undefined ? dft : '');
  }

  function parseDeviceInfo(pkgs) {
    // system package 的 hostname 完整語法本輪未逐字查證，維持 '-' 不猜測
    return { vendor: 'OpenWrt', hostname: '-', firmware: '-', model: '-', serial: '-', vdom: [] };
  }

  function parseInterfaces(pkgs) {
    const out = [];
    (pkgs.network || []).filter(s => s.type === 'interface').forEach(s => {
      const name = s.name || '(anonymous)';
      const ip = val(s, 'ipaddr', '-');
      // 次要IP（2026-08-12 新增，2026-08-17 擴大為完整收集，官方 OpenWrt UCI 慣例確認主要
      // 位址用 `option ipaddr`，額外的次要位址用重複的 `list ipaddr 'A.B.C.D/N'` 行；通用
      // tokenizer parseUCI() 早就把重複的 list KEY VALUE 收集進 s.lists[key] 陣列，這裡只需
      // 消費，不用改字彙掃描層。list 形式的位址值本身是 CIDR（含 prefix），與 option ipaddr/
      // option netmask 分開兩欄不同，需拆解）
      const ipList = (s.lists && s.lists.ipaddr) || [];
      const secondaryIps = ipList.map(raw => {
        const [sip, sbits] = raw.split('/');
        return { ip: sip || '-', mask: sbits ? prefixToMask(parseInt(sbits)) : '255.255.255.255' };
      });
      out.push({
        name, ip, mask: val(s, 'netmask', '-'), type: 'physical', vlanId: '-',
        alias: val(s, 'ifname') || val(s, 'device') || name, desc: '',
        status: 'up', mtu: '-', speed: '-', mode: val(s, 'proto') === 'dhcp' ? 'dhcp' : 'static',
        vdom: '-', role: /^wan/i.test(name) ? 'WAN' : 'LAN', allowaccess: '-',
        secondaryIps,
      });
    });
    return out;
  }

  function bitsFromMask(mask) {
    if (!mask) return null;
    return mask.split('.').reduce((n, o) => { let b = parseInt(o, 10) >>> 0, c = 0; while (b) { b &= (b - 1); c++; } return n + c; }, 0);
  }
  function prefixToMask(bits) {
    if (bits === null || bits === undefined || isNaN(bits)) return '255.255.255.0';
    const bitsN = parseInt(bits);
    // JS 的 << 位移量會對 32 取模，bits=0 時 "32-0=32" 會變成 no-op（右邊不變），
    // 需特別處理 /0 才能正確得出 0.0.0.0（2026-09 全功能審查發現）
    const n = bitsN === 0 ? 0 : (0xFFFFFFFF << (32 - bitsN)) >>> 0;
    return [(n>>>24)&0xFF,(n>>>16)&0xFF,(n>>>8)&0xFF,n&0xFF].join('.');
  }

  function parseRoutes(pkgs) {
    const out = []; let seq = 1;
    (pkgs.network || []).filter(s => s.type === 'route').forEach(s => {
      const target = val(s, 'target', '');
      if (!target) return;
      const netmask = val(s, 'netmask', '');
      const dst = target.includes('/') ? target : (netmask ? `${target}/${bitsFromMask(netmask)}` : `${target}/32`);
      out.push({
        type: dst.startsWith('0.0.0.0/') ? 'default' : 'static', id: String(seq++),
        dst, gateway: val(s, 'gateway', '-'), device: val(s, 'interface', '-'),
        distance: '-', priority: '-', blackhole: 'disable', vrf: 'main', status: 'enable', comment: '',
        protocol_detail: '-', _vdom: '',
      });
    });
    return out;
  }

  // address-group（2026-09-14 新增）：`config ipset` + `list entry` 靜態成員語法已對外查證
  // （直接讀取 oldwiki.archive.openwrt.org/doc/uci/firewall 官方 `config ipset` 完整選項表＋
  // 多筆真實社群設定範例交叉確認），對稱 firewall-analyzer-converter.js 的 toOpenWrt() 攤平
  // 輸出完成 round-trip；FQDN 因 ipset 架構本身無法儲存主機名稱不支援，service-object 仍因
  // 查無官方逐字語法佐證維持空值
  function parseAddressGroups(pkgs) {
    return (pkgs.firewall || []).filter(s => s.type === 'ipset').map(s => ({
      category: 'address-group', name: val(s, 'name', s.name || ''), type: 'group',
      members: (s.lists.entry || []).join(', '), comment: '-',
    })).filter(g => g.name);
  }

  function parsePolicies(pkgs) {
    const out = []; let idx = 0;
    // ipset 的 match 方向（src_net/dest_net 等）在宣告時就固定，config rule 用
    // `option ipset 'NAME'` 引用時依此方向決定要落在 srcAddr 還是 dstAddr（見
    // toOpenWrt() 內對稱的輸出邏輯與其註解）
    const ipsetDir = {};
    (pkgs.firewall || []).filter(s => s.type === 'ipset').forEach(s => {
      const name = val(s, 'name', s.name || '');
      if (name) ipsetDir[name] = val(s, 'match', '').startsWith('dest') ? 'dest' : 'src';
    });
    (pkgs.firewall || []).filter(s => s.type === 'rule').forEach(s => {
      idx++;
      const name = val(s, 'name', '') || `Rule-${idx}`;
      const proto = val(s, 'proto', 'any');
      const dport = val(s, 'dest_port', '');
      const ipsetRef = val(s, 'ipset', '');
      const ipsetIsSrc = ipsetRef && ipsetDir[ipsetRef] === 'src';
      const ipsetIsDst = ipsetRef && ipsetDir[ipsetRef] === 'dest';
      const srcAddrVal = ipsetIsSrc ? ipsetRef : val(s, 'src_ip', 'any');
      const dstAddrVal = ipsetIsDst ? ipsetRef : val(s, 'dest_ip', 'any');
      // 官方文件與社群範例確認 UCI 的 src_ip/dest_ip 本身可直接承載 IPv4 或 IPv6 字面值/CIDR
      // （如 option src_ip 'fdca:f00:ba3::/64'），無獨立的 src_ip6/dest_ip6 欄位，family
      // 選項僅輔助宣告非必要；ipset 群組引用非字面 IP，不適用此冒號偵測，交由呼叫端另行處理
      const srcAddrSplit = ipsetIsSrc ? { v4: '-', v6: '-' } : _splitAddr(srcAddrVal);
      const dstAddrSplit = ipsetIsDst ? { v4: '-', v6: '-' } : _splitAddr(dstAddrVal);
      out.push({
        id: idx, name,
        srcIntf: val(s, 'src', 'any') || 'any', dstIntf: val(s, 'dest', 'any') || 'any',
        srcAddr: srcAddrVal, dstAddr: dstAddrVal,
        srcAddr4: srcAddrSplit.v4, srcAddr6: srcAddrSplit.v6, dstAddr4: dstAddrSplit.v4, dstAddr6: dstAddrSplit.v6,
        service: dport ? `${proto}/${dport}` : proto,
        schedule: 'always',
        action: val(s, 'target', 'REJECT').toUpperCase() === 'ACCEPT' ? 'accept' : 'deny',
        nat: 'disable', ippool: 'disable', poolname: '-',
        logtraffic: val(s, 'log', '') === '1' ? 'all' : 'disable',
        utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
        status: val(s, 'enabled', '1') === '0' ? 'disable' : 'enable',
        users: '-', groups: '-', comments: name, _vdom: '',
      });
    });
    return out;
  }

  function parseNAT(pkgs) {
    const out = [];
    (pkgs.firewall || []).filter(s => s.type === 'redirect').forEach((s, i) => {
      const isSnat = val(s, 'target', 'DNAT').toUpperCase() === 'SNAT';
      const proto = val(s, 'proto', '-');
      const comment = val(s, 'name', '') || `Redirect-${i + 1}`;
      if (isSnat) {
        out.push({
          type: 'ippool', name: comment, vipType: 'overload', poolType: 'source',
          extIp: val(s, 'src_ip', '-'), mapIp: val(s, 'src_dip', '-'),
          extIntf: val(s, 'src', '-'), srcIntf: val(s, 'src', '-'),
          startIp: '-', endIp: '-', portFwd: 'disable', extPort: '-', mapPort: '-',
          proto, status: 'enable', comment,
        });
      } else {
        out.push({
          type: 'vip', name: comment, vipType: 'static', poolType: 'destination',
          extIp: val(s, 'src_dip', '-'), mapIp: val(s, 'dest_ip', '-'),
          extIntf: val(s, 'src', '-'), srcIntf: '-', startIp: '-', endIp: '-',
          portFwd: val(s, 'dest_port') ? 'enable' : 'disable',
          extPort: val(s, 'src_dport', '-'), mapPort: val(s, 'dest_port', '-'),
          proto, status: 'enable', comment,
        });
      }
    });
    return out;
  }

  // dhcp package 的 start/limit 是相對網段的 offset（dnsmasq 語意）；透過 option interface／
  // stanza name 對應到 config interface 的 ipaddr+netmask 可還原絕對 IP，查無對應介面或缺
  // ipaddr/netmask 時退回僅顯示 offset 數值，不臆測
  function ipv4ToInt(ip) {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || '');
    if (!m) return null;
    return (((+m[1]) << 24) | ((+m[2]) << 16) | ((+m[3]) << 8) | (+m[4])) >>> 0;
  }
  function intToIPv4(n) {
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  function parseDHCP(pkgs) {
    const ifaceMap = {};
    (pkgs.network || []).filter(s => s.type === 'interface').forEach(s => {
      if (s.name) ifaceMap[s.name] = { ipaddr: val(s, 'ipaddr', ''), netmask: val(s, 'netmask', '') };
    });
    const servers = [];
    (pkgs.dhcp || []).filter(s => s.type === 'dhcp').forEach(s => {
      const iface = s.name || val(s, 'interface', '-');
      const start = val(s, 'start', '-');
      const limit = val(s, 'limit', '');
      let startIp = start, endIp = (start !== '-' && limit) ? String(parseInt(start, 10) + parseInt(limit, 10) - 1) : '-';
      let mask = '-';
      const ifName = val(s, 'interface', '') || s.name || '';
      const ifInfo = ifaceMap[ifName];
      if (ifInfo && start !== '-' && limit && ifInfo.ipaddr && ifInfo.netmask) {
        const base = ipv4ToInt(ifInfo.ipaddr), maskInt = ipv4ToInt(ifInfo.netmask);
        if (base !== null && maskInt !== null) {
          const netBase = (base & maskInt) >>> 0;
          startIp = intToIPv4((netBase + parseInt(start, 10)) >>> 0);
          endIp = intToIPv4((netBase + parseInt(start, 10) + parseInt(limit, 10) - 1) >>> 0);
          mask = ifInfo.netmask;
        }
      }
      servers.push({ name: iface, mask, iface, startIp, endIp, gateway: '-', dns: '-', lease: val(s, 'leasetime', '-') });
    });
    return servers.length ? { servers, relays: [] } : null;
  }

  function detect(text) {
    let hits = 0;
    if (/^config\s+interface(\s|$)/m.test(text)) hits++;
    if (/^\s*option\s+proto\s/m.test(text)) hits++;
    if (/^config\s+(zone|rule|redirect|forwarding)(\s|$)/m.test(text)) hits++;
    if (/^package\s+(network|firewall|dhcp)/m.test(text)) hits++;
    return hits >= 2;
  }

  // netfilter 式鏈評估資料（XN127，見 core.js _nfQueryChain()）：依 fw4 產生規則的方式推得（近似，非逐條比對實機 nft 輸出）
  //  - zone 的 list network／option network 為成員介面；policy 沒寫時沿用 config defaults，defaults 沒寫為拒絕
  //  - input：來自 zone Z → src＝Z（或 *）且沒有 dest 的 rule 依序比對 → Z 的 input 政策
  //  - forward：來自 zone Z → src＝Z（或 *）且有 dest 的 rule → config forwarding Z→D 放行 → 目的也在 Z 時套用 Z 的 forward 政策
  //    → config defaults 的 forward 政策
  //  - rule 的 target 只有 ACCEPT／REJECT／DROP 決定結果（MARK／NOTRACK 等不列）；沒有 src 的 rule 是 output，不列
  function buildNf(pkgs, policies) {
    const fw = pkgs.firewall || [];
    const pol = v => /^(REJECT|DROP)$/i.test(v || '') ? 'deny' : /^ACCEPT$/i.test(v || '') ? 'accept' : '';
    const defs = fw.find(s => s.type === 'defaults');
    const dIn = (defs && pol(val(defs, 'input'))) || 'deny', dFwd = (defs && pol(val(defs, 'forward'))) || 'deny';
    const zones = fw.filter(s => s.type === 'zone').map(s => ({
      name: val(s, 'name', s.name || ''), nets: [...((s.lists && s.lists.network) || []), ...String(val(s, 'network', '')).split(/\s+/)].filter(Boolean),
      input: pol(val(s, 'input')) || dIn, forward: pol(val(s, 'forward')) || dFwd })).filter(z => z.name);
    // 規則或 forwarding 引用、但這份檔案沒有定義的 zone（只上傳部分設定時常見）：以 defaults 的政策補上，
    // 否則這些規則不會出現在任何鏈，查詢與轉換都會被整批略過（RV1）
    const defined = new Set(zones.map(z => z.name));
    fw.filter(s => s.type === 'rule' || s.type === 'forwarding').forEach(s => ['src', 'dest'].forEach(k => {
      const zn = val(s, k, '');
      if (zn && zn !== '*' && !defined.has(zn)) { defined.add(zn); zones.push({ name: zn, nets: [], input: dIn, forward: dFwd, implicit: true }); }
    }));
    const zm = new Map(zones.map(z => [z.name, z]));
    const mem = zn => zn && zn !== '*' && zm.has(zn) ? (zm.get(zn).nets.join(', ') || undefined) : undefined;
    const base = o => Object.assign({ srcIntf: '-', dstIntf: '-', srcAddr: 'any', dstAddr: 'any', srcAddr4: 'any', dstAddr4: 'any', srcAddr6: '-', dstAddr6: '-',
      service: 'any', schedule: 'always', nat: 'disable', ippool: 'disable', poolname: '-', logtraffic: 'disable', utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
      status: 'enable', users: '-', groups: '-', comments: '', _vdom: '', connState: [], _nonterminal: false }, o);
    const rules = [];
    const ruleSecs = fw.filter(s => s.type === 'rule');
    zones.forEach(z => {
      const zIn = `in:${z.name}`, zFw = `fw:${z.name}`;
      rules.push(base({ id: `zone/${z.name}/in`, name: `zone ${z.name} → input`, action: 'deny', srcIntf: z.name, srcIntfMembers: mem(z.name), _chain: 'input', _mtAct: 'jump', _jumpTarget: zIn, _nonterminal: true, _mtHasMatch: true }));
      rules.push(base({ id: `zone/${z.name}/fwd`, name: `zone ${z.name} → forward`, action: 'deny', srcIntf: z.name, srcIntfMembers: mem(z.name), _chain: 'forward', _mtAct: 'jump', _jumpTarget: zFw, _nonterminal: true, _mtHasMatch: true }));
      ruleSecs.forEach((s, i) => {
        const p = policies[i], src = val(s, 'src', ''), dest = val(s, 'dest', '');
        if (!p || !src || (src !== '*' && src !== z.name)) return;
        const tgt = val(s, 'target', 'REJECT').toUpperCase();
        if (!['ACCEPT', 'REJECT', 'DROP'].includes(tgt)) return;
        rules.push(Object.assign({}, p, { id: `${p.id}@${z.name}`, srcIntf: '-', dstIntf: dest && dest !== '*' ? dest : '-', dstIntfMembers: dest && dest !== '*' ? mem(dest) : undefined,
          _chain: dest ? zFw : zIn, _mtAct: tgt === 'ACCEPT' ? 'accept' : 'drop', _nonterminal: false }));
      });
      fw.filter(s => s.type === 'forwarding' && val(s, 'src') === z.name && val(s, 'enabled', '1') !== '0').forEach(s => {
        const d = val(s, 'dest');
        rules.push(base({ id: `fwd/${z.name}/${d}`, name: `forwarding ${z.name} → ${d}`, action: 'accept', dstIntf: d, dstIntfMembers: mem(d), _chain: zFw, _mtAct: 'accept' }));
      });
      rules.push(base({ id: `zone/${z.name}/fwd-policy`, name: `zone ${z.name} forward ${z.forward.toUpperCase()}`, action: z.forward, dstIntf: z.name, dstIntfMembers: mem(z.name), _chain: zFw, _mtAct: z.forward === 'accept' ? 'accept' : 'drop', _nfDefaultRule: true }));
      rules.push(base({ id: `zone/${z.name}/in-policy`, name: `zone ${z.name} input ${z.input.toUpperCase()}`, action: z.input, _chain: zIn, _mtAct: z.input === 'accept' ? 'accept' : 'drop', _nfDefaultRule: true }));
    });
    return { rules, defaults: { input: dIn, forward: dFwd }, forward: ['forward'], input: ['input'], zones };
  }

  // 路由器本身的服務（XN127）：uci export 含 dropbear／uhttpd／upnpd 時才評估（只上傳 firewall 檔案時為 null）。
  //  dropbear：Port（預設 22）、Interface（限定的 network，沒寫＝全部）、enable '0'＝停用
  //  uhttpd（LuCI）：list listen_http／listen_https「位址:埠」，0.0.0.0／[::]＝全部介面
  //  upnpd：config upnpd 的 enabled '1'
  function parseRouterPlane(pkgs) {
    const all = Object.values(pkgs).flat();
    const drop = all.filter(s => s.type === 'dropbear'), uh = all.filter(s => s.type === 'uhttpd'), up = all.filter(s => s.type === 'upnpd');
    if (!drop.length && !uh.length && !up.length) return null;
    const services = [];
    drop.forEach(s => services.push({ name: 'dropbear', kind: 'admin-ssh', port: Number(val(s, 'Port', '22')) || 22, enabled: val(s, 'enable', '1') !== '0',
      listenIfs: val(s, 'Interface') ? [val(s, 'Interface')] : [], listenAddrs: [] }));
    uh.forEach(s => ['listen_https', 'listen_http'].forEach(k => ((s.lists && s.lists[k]) || (val(s, k) ? [val(s, k)] : [])).forEach(l => {
      const m = String(l).match(/^(.*):(\d+)$/);
      if (!m) return;
      const addr = m[1].replace(/^\[|\]$/g, '');
      services.push({ name: `uhttpd ${k === 'listen_https' ? 'https' : 'http'}`, kind: 'rt-web', port: Number(m[2]), enabled: true,
        listenIfs: [], listenAddrs: /^(0\.0\.0\.0|::|\*)?$/.test(addr) ? [] : [addr] });
    })));
    return { services, dns: null, upnp: up.length ? up.some(s => val(s, 'enabled', '0') === '1') : null };
  }

  function parse(text) {
    const pkgs = parseUCI(text);
    const policies = parsePolicies(pkgs);
    return {
      vendor: 'OpenWrt',
      deviceInfo: parseDeviceInfo(pkgs),
      interfaces: parseInterfaces(pkgs),
      policies, nf: buildNf(pkgs, policies), rtRouter: parseRouterPlane(pkgs),
      routes: parseRoutes(pkgs),
      ha: null, nat: parseNAT(pkgs), vpn: [],
      addresses: parseAddressGroups(pkgs), services: [],
      users: [], schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      dhcp: parseDHCP(pkgs), dns: null, snmp: null, logservers: null,
      wwan: null, wlan: null,
    };
  }

  return { parse, detect };
})();

