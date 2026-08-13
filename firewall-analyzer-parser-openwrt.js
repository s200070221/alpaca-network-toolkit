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
// forward，`target` 為 `DNAT`（預設）或 `SNAT` 兩種）；dhcp package `config dhcp`
// （`interface`／`start`／`limit`／`leasetime`，`start`/`limit` 為相對網段的 offset，非絕對
// IP，本工具原樣呈現不臆測絕對範圍）。`uci export`（無參數）會把所有 package 串接成一個
// 檔案、每段以 `package <name>` 開頭分隔；個別 `/etc/config/X` 檔案單獨上傳則不含
// `package` 行，故 parser 對未出現過 `package` 行時依已知 config 類型名稱歸類。VPN／
// WiFi／Users／Schedules／address-object／service-object（UCI 規則的 src_ip/dest_ip 是
// 直接內嵌值，無具名物件；`config ipset` 與 rule 的完整引用語法本輪未查證）因查無足夠
// 把握的語法佐證維持空值不猜測。
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
      // 次要IP（2026-08-12 新增，官方 OpenWrt UCI 慣例確認主要位址用 `option ipaddr`，額外的
      // 次要位址用重複的 `list ipaddr 'A.B.C.D/N'` 行；通用 tokenizer parseUCI() 早就把重複的
      // list KEY VALUE 收集進 s.lists[key] 陣列，這裡只需消費，不用改字彙掃描層。list 形式的
      // 位址值本身是 CIDR（含 prefix），與 option ipaddr/option netmask 分開兩欄不同，需拆解；
      // 僅取第一筆次要IP為 MVP 範圍，比照其餘廠牌既有限制）
      const ipList = (s.lists && s.lists.ipaddr) || [];
      let secondaryIp = '-', secondaryMask = '-';
      if (ipList[0]) {
        const [sip, sbits] = ipList[0].split('/');
        if (sip) { secondaryIp = sip; secondaryMask = sbits ? prefixToMask(parseInt(sbits)) : '255.255.255.255'; }
      }
      out.push({
        name, ip, mask: val(s, 'netmask', '-'), type: 'physical', vlanId: '-',
        alias: val(s, 'ifname') || val(s, 'device') || name, desc: '',
        status: 'up', mtu: '-', speed: '-', mode: val(s, 'proto') === 'dhcp' ? 'dhcp' : 'static',
        vdom: '-', role: /^wan/i.test(name) ? 'WAN' : 'LAN', allowaccess: '-',
        secondaryIp, secondaryMask,
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
    const n = (0xFFFFFFFF << (32 - parseInt(bits))) >>> 0;
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

  function parsePolicies(pkgs) {
    const out = []; let idx = 0;
    (pkgs.firewall || []).filter(s => s.type === 'rule').forEach(s => {
      idx++;
      const name = val(s, 'name', '') || `Rule-${idx}`;
      const proto = val(s, 'proto', 'any');
      const dport = val(s, 'dest_port', '');
      // 官方文件與社群範例確認 UCI 的 src_ip/dest_ip 本身可直接承載 IPv4 或 IPv6 字面值/CIDR
      // （如 option src_ip 'fdca:f00:ba3::/64'），無獨立的 src_ip6/dest_ip6 欄位，family
      // 選項僅輔助宣告非必要；沒有具名位址物件概念（既有範圍界定），故用免 map 版純冒號偵測
      const srcAddrSplit = _splitAddr(val(s, 'src_ip', 'any'));
      const dstAddrSplit = _splitAddr(val(s, 'dest_ip', 'any'));
      out.push({
        id: idx, name,
        srcIntf: val(s, 'src', 'any') || 'any', dstIntf: val(s, 'dest', 'any') || 'any',
        srcAddr: val(s, 'src_ip', 'any'), dstAddr: val(s, 'dest_ip', 'any'),
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

  function parse(text) {
    const pkgs = parseUCI(text);
    return {
      vendor: 'OpenWrt',
      deviceInfo: parseDeviceInfo(pkgs),
      interfaces: parseInterfaces(pkgs),
      policies: parsePolicies(pkgs),
      routes: parseRoutes(pkgs),
      ha: null, nat: parseNAT(pkgs), vpn: [],
      addresses: [], services: [],
      users: [], schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      dhcp: parseDHCP(pkgs), dns: null, snmp: null, logservers: null,
      wwan: null, wlan: null,
    };
  }

  return { parse, detect };
})();

