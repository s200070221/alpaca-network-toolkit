// ═══ parser-juniper.js ═══
/**
 * Juniper SRX / Junos Configuration Parser
 * Supports: "show configuration" CLI output (Junos hierarchical { } format)
 * Covers: interfaces, security zones/policies, routing-options, applications,
 *         vpn (ike+ipsec), address-book, user-management, nat
 */
const JuniperParser = (() => {

  // ── Junos { } block parser ────────────────────────────────────────────────
  // Returns a nested object tree from Junos "show configuration" output
  function parseJunosTree(text) {
    // Normalize: remove version header comments, collapse continuations
    // 2026-08-24 修正：先前這裡的說明自相矛盾（同時宣稱「compact 格式暫不支援」與
    // 「Handles both compact single-line and standard indented formats」）。實際情況：
    // tokenizeJunos() 是逐字元掃描（非逐行），對大括號階層格式（含刻意壓成單行的變體）
    // 天生就能正確處理，本來就支援。真正完全不支援的是另一種截然不同的語法家族——
    // `show configuration | display set` 扁平格式（裸 "set security policies ..." 行，
    // 無大括號階層），這種格式 tokenizeJunos()/parseJunosTree() 從未處理過；
    // firewall-analyzer-app.js 的 analyze() 已於本輪新增偵測與非阻塞 UI 警告
    // （msg.junos_display_set_unsupported），避免使用者誤以為解析結果完整。
    // Tokenize JunOS config into normalized lines (each ending with { ; or being } alone)
    function tokenizeJunos(src) {
      const out = [];
      let buf = '';
      let inStr = false;
      let strChar = '';
      for (let ci = 0; ci < src.length; ci++) {
        const ch = src[ci];
        // Handle string literals (don't split inside quotes)
        if (inStr) {
          buf += ch;
          if (ch === strChar) inStr = false;
          continue;
        }
        if (ch === '"' || ch === "'") { inStr = true; strChar = ch; buf += ch; continue; }
        // Token boundaries
        if (ch === '{') {
          const t = buf.trim();
          if (t) out.push(t + ' {');
          else    out.push('{');
          buf = '';
        } else if (ch === '}') {
          const t = buf.trim();
          if (t) out.push(t);  // trailing value before }
          out.push('}');
          buf = '';
        } else if (ch === ';') {
          const t = buf.trim();
          if (t) out.push(t + ';');
          buf = '';
        } else if (ch === '\n' || ch === '\r') {
          // Newline: flush buffer only if it ends a comment line (##)
          const t = buf.trim();
          if (t.startsWith('#') || t.startsWith('/*')) { buf = ''; }
          else if (t) buf += ' '; // merge continuation
          else buf = '';
        } else {
          buf += ch;
        }
      }
      const t = buf.trim();
      if (t) out.push(t);
      return out;
    }
    const lines = tokenizeJunos(text)
      .filter(l => l && !l.match(/^##|^version\s+\d|^\/\*|^\s*\*\//));

    let i = 0;

    function readBlock() {
      const node = { _values: [], _children: {} };
      while (i < lines.length) {
        const line = lines[i].trim(); i++;
        if (!line || line === '}') break;
        if (line.endsWith('{')) {
          // Named child block: "name {" or "name value {"
          const key = line.slice(0, -1).trim();
          node._children[key] = readBlock();
        } else if (line.endsWith(';')) {
          node._values.push(line.slice(0, -1).trim());
        }
      }
      return node;
    }

    const root = { _values: [], _children: {} };
    while (i < lines.length) {
      const line = lines[i].trim(); i++;
      if (!line) continue;
      if (line.endsWith('{')) {
        const key = line.slice(0, -1).trim();
        root._children[key] = readBlock();
      } else if (line.endsWith(';')) {
        root._values.push(line.slice(0, -1).trim());
      }
    }
    return root;
  }

  // ── Tree query helpers ────────────────────────────────────────────────────
  // Get child by path array: path(tree, ['interfaces','ge-0/0/0','unit 0'])
  function path(node, keys) {
    let cur = node;
    for (const k of keys) {
      if (!cur) return null;
      // Exact match first
      if (cur._children[k]) { cur = cur._children[k]; continue; }
      // Prefix match (Junos keys can have trailing value)
      const match = Object.keys(cur._children).find(ck => ck === k || ck.startsWith(k + ' '));
      if (match) { cur = cur._children[match]; continue; }
      return null;
    }
    return cur;
  }

  // Get value from node._values that starts with key
  function val(node, key) {
    if (!node) return '';
    const m = node._values.find(v => v === key || v.startsWith(key + ' '));
    return m ? m.slice(key.length).trim() : '';
  }

  // Get all children whose key starts with prefix
  function childrenPrefixed(node, prefix) {
    if (!node) return {};
    return Object.fromEntries(
      Object.entries(node._children)
        .filter(([k]) => k === prefix || k.startsWith(prefix + ' ') || k.startsWith(prefix + '-'))
    );
  }

  function childKeys(node) {
    return node ? Object.keys(node._children) : [];
  }

  // ── Device info ───────────────────────────────────────────────────────────
  function parseDeviceInfo(text, tree) {
    const info = { vendor:'Juniper', hostname:'-', firmware:'-', model:'-', serial:'-', vdom:[], vdomNames:[], isMultiVdom:false };

    // "version 22.3R1.12;" or "## Last commit:" comments
    const verM = text.match(/^version\s+([\d\w\-\.]+)/im)
               || text.match(/Junos[:\s]+([\d\w\-\.]+)/i);
    if (verM) info.firmware = verM[1];

    const modelM = text.match(/Model:\s*(\S+)/i) || text.match(/chassis\s+model\s+(\S+)/i);
    if (modelM) info.model = modelM[1];

    const snM = text.match(/Chassis\s+([A-Z0-9]{10,})/i) || text.match(/serial-number\s+(\S+)/i);
    if (snM) info.serial = snM[1];

    // hostname from system block
    const sys = path(tree, ['system']);
    if (sys) {
      const hn = val(sys, 'host-name') || val(sys, 'hostname');
      if (hn) info.hostname = hn;
      const fw = val(sys, 'version');
      if (fw && info.firmware === '-') info.firmware = fw;
    }

    // Also try regex for hostname
    if (info.hostname === '-') {
      const hm = text.match(/host-name\s+(\S+);/i);
      if (hm) info.hostname = hm[1];
    }

    return info;
  }

  // ── Interfaces ────────────────────────────────────────────────────────────
  // 次要IP（Secondary IP，官方 Junos family inet 文件：同一 family inet 區塊內可重複宣告
  // 多筆 `address` statement，附加式非關鍵字機制；2026-08-17 從「僅取第二筆」擴大為完整
  // 收集全部次要IP）
  function _addrListToSecondaryIps(addrList) {
    return addrList.slice(1).map(v => {
      const raw = v.slice('address'.length).trim();
      const parts = raw.split('/');
      return { ip: parts[0] || '-', mask: parts[1] ? prefixToMask(parseInt(parts[1])) : '-' };
    });
  }
  function parseInterfaces(tree) {
    const ifaces = [];
    const intfNode = path(tree, ['interfaces']);
    if (!intfNode) return ifaces;

    // Build zone map: interface → zone name
    const ifaceZoneMap = {};
    const secNode = path(tree, ['security']);
    if (secNode) {
      const zonesNode = path(secNode, ['zones']);
      if (zonesNode) {
        Object.entries(zonesNode._children).forEach(([zkey, znode]) => {
          const zoneName = zkey.replace(/^security-zone\s+/, '');
          const ifNode = path(znode, ['interfaces']);
          if (ifNode) {
            ifNode._values.forEach(ifv => {
              const ifname = ifv.split('.')[0]; // strip unit suffix
              ifaceZoneMap[ifv] = zoneName;
              ifaceZoneMap[ifname] = zoneName;
            });
          }
        });
      }
    }

    Object.entries(intfNode._children).forEach(([ifKey, ifNode]) => {
      const ifName = ifKey; // e.g. "ge-0/0/0", "ae0", "lo0"
      const ifType = ifName.startsWith('ge-') || ifName.startsWith('xe-') || ifName.startsWith('et-') ? 'physical'
                   : ifName.startsWith('ae') ? 'aggregate'
                   : ifName.startsWith('lo') ? 'loopback'
                   : ifName.startsWith('irb') ? 'irb'
                   : ifName.startsWith('vlan') ? 'vlan'
                   : ifName.startsWith('st0') ? 'tunnel'
                   : 'physical';

      const desc = val(ifNode, 'description').replace(/^"|"$/g, '');
      const mtu  = val(ifNode, 'mtu') || '1500';
      const link = ifNode._values.includes('disable') ? 'down' : 'up';

      // Process units
      const hasUnits = Object.keys(ifNode._children).some(k => k.startsWith('unit '));
      if (hasUnits) {
        Object.entries(ifNode._children).forEach(([ukey, unode]) => {
          if (!ukey.startsWith('unit ')) return;
          const unitNum = ukey.replace('unit ', '');
          const unitName = `${ifName}.${unitNum}`;
          const inetNode = path(unode, ['family inet']);
          const ip4 = inetNode ? val(inetNode, 'address') : '';
          const addrList = inetNode ? inetNode._values.filter(v => v === 'address' || v.startsWith('address ')) : [];
          const secondaryIps = _addrListToSecondaryIps(addrList);
          const vlanId = val(unode, 'vlan-id') || val(unode, 'vlan-tags outer') || '-';
          const udesc = val(unode, 'description').replace(/^"|"$/g,'') || desc;
          const zone = ifaceZoneMap[unitName] || ifaceZoneMap[ifName] || '';

          let ipAddr = '-', mask = '-';
          if (ip4) {
            const parts = ip4.split('/');
            ipAddr = parts[0];
            if (parts[1]) mask = prefixToMask(parseInt(parts[1]));
          }
          ifaces.push({
            name: unitName, alias: udesc || '-',
            ip: ipAddr, mask,
            secondaryIps,
            type: vlanId !== '-' ? 'vlan' : ifType,
            vlanId, vdom: zone || '-',
            role: zone ? mapZoneRole(zone) : guessRole(ifName),
            status: link, speed: val(ifNode,'speed')||'-',
            mtu, macaddr: '-', mode: ip4 ? 'static' : '-',
            gwdetect: '-', desc: udesc || desc || '-',
            allowaccess: val(path(unode,['family inet','rpf-check'])||unode,'filter input')||'-',
            interface: ifName, gateway: '-', _vdom: zone || 'default',
          });
        });
      } else {
        // Interface without units
        const inetNode = path(ifNode, ['family inet']);
        const ip4 = inetNode ? val(inetNode, 'address') : '';
        const addrList = inetNode ? inetNode._values.filter(v => v === 'address' || v.startsWith('address ')) : [];
        const secondaryIps = _addrListToSecondaryIps(addrList);
        const zone = ifaceZoneMap[ifName] || '';
        let ipAddr = '-', mask = '-';
        if (ip4) { const p = ip4.split('/'); ipAddr=p[0]; if(p[1])mask=prefixToMask(parseInt(p[1])); }
        ifaces.push({
          name: ifName, alias: desc||'-', ip: ipAddr, mask,
          secondaryIps,
          type: ifType, vlanId: '-', vdom: zone||'-',
          role: zone ? mapZoneRole(zone) : guessRole(ifName),
          status: link, speed: val(ifNode,'speed')||'-', mtu,
          macaddr: '-', mode: ip4?'static':'-', gwdetect: '-',
          desc: desc||'-', allowaccess: '-', interface: '-', gateway: '-',
          _vdom: zone||'default',
        });
      }
    });

    return ifaces;
  }

  // ── Security policies ─────────────────────────────────────────────────────
  function parsePolicies(tree, addrTypeMap) {
    const policies = [];
    const secNode = path(tree, ['security']);
    if (!secNode) return policies;
    const polsNode = path(secNode, ['policies']);
    if (!polsNode) return policies;

    let id = 1;
    Object.entries(polsNode._children).forEach(([zoneKey, zoneNode]) => {
      // Key format: "from-zone <src> to-zone <dst>"
      const zm = zoneKey.match(/from-zone\s+(\S+)\s+to-zone\s+(\S+)/);
      if (!zm) return;
      const srcZone = zm[1], dstZone = zm[2];

      Object.entries(zoneNode._children).forEach(([polKey, polNode]) => {
        const polName = polKey.replace(/^policy\s+/, '');
        const matchNode = path(polNode, ['match']);
        const thenNode  = path(polNode, ['then']);

        // Fix: compact + indented format — search both matchNode._values AND polNode._values
        function extractMatchVal(keyword) {
          const sources = [];
          if (matchNode && matchNode._values) {
            matchNode._values.filter(v=>v.startsWith(keyword)).forEach(v=>sources.push(v.replace(keyword+' ','').trim()));
          }
          // compact: "match { source-address any; }" stored in polNode._values
          if (!sources.length && polNode && polNode._values) {
            const inlinePol = polNode._values.join(' ');
            const mRe = new RegExp('match\\s*\\{[^}]*\\b'+keyword+'\\s+([^;\\}]+)','gi');
            let mm;
            while((mm=mRe.exec(inlinePol))!==null) sources.push(mm[1].trim());
          }
          return sources.length ? sources.join(', ') : 'any';
        }
        const srcAddr = extractMatchVal('source-address');
        const dstAddr = extractMatchVal('destination-address');
        const apps    = extractMatchVal('application');
        const srcAddrSplit = _splitAddr(srcAddr, addrTypeMap);
        const dstAddrSplit = _splitAddr(dstAddr, addrTypeMap);

        let action = 'deny';
        if (thenNode) {
          const thenVals = thenNode._values.join(' ').toLowerCase();
          if (thenVals.includes('permit') || thenNode._children['permit']) action = 'accept';
          else if (thenVals.includes('allow')) action = 'accept';
          else if (thenVals.includes('reject') || thenVals.includes('deny') || thenVals.includes('discard')) action = 'deny';
        }
        // Fix: compact format — "then { permit; }" stored in _values (not parsed as child block)
        // Search polNode._values for inline then-permit pattern
        if (action === 'deny' && polNode && polNode._values) {
          const inlineVals = polNode._values.join(' ').toLowerCase();
          if (/then\s*\{[^}]*\bpermit\b/.test(inlineVals) || inlineVals.includes('then permit')) {
            action = 'accept';
          }
        }

        const logNode = thenNode ? (path(thenNode,['permit','firewall-authentication']) || thenNode) : null;
        const logtraffic = thenNode && (thenNode._children['log'] || val(thenNode,'log') !== '') ? 'enable' : 'disable';

        // UTM profiles
        const utm = { av:'-', webfilter:'-', ips:'-', ssl:'-', appctrl:'-' };
        if (thenNode) {
          const permitNode = thenNode._children['permit'];
          if (permitNode) {
            utm.ips = val(path(permitNode,['application-services'])||permitNode,'idp-policy') || '-';
            utm.av  = val(path(permitNode,['application-services'])||permitNode,'utm-policy') || '-';
          }
        }

        const disabled = polNode._values.includes('inactive') || polNode._values.includes('deactivate');

        policies.push({
          id: String(id++), name: polName,
          srcIntf: srcZone, dstIntf: dstZone,
          srcAddr: srcAddr || 'any', dstAddr: dstAddr || 'any',
          srcAddr4: srcAddrSplit.v4, srcAddr6: srcAddrSplit.v6,
          dstAddr4: dstAddrSplit.v4, dstAddr6: dstAddrSplit.v6,
          service: apps || 'any', schedule: 'always',
          action, nat: 'disable', ippool: 'disable', poolname: '-',
          logtraffic, logstart: '-', utm,
          status: disabled ? 'disable' : 'enable',
          comments: val(polNode,'description').replace(/^"|"$/g,'')||'-',
          users: '-', groups: '-', _vdom: `${srcZone}-to-${dstZone}`,
        });
      });
    });
    return policies;
  }

  // ── Address objects ───────────────────────────────────────────────────────
  function parseAddressObjects(tree) {
    const objs = [];

    // Global address book (older Junos) or per-zone address-book
    function processAddrBook(bookNode, zoneName) {
      if (!bookNode) return;
      // Parse address SIMPLE values: "address NAME 1.2.3.4/24;" stored as _values
      if (bookNode._values) {
        bookNode._values.forEach(v => {
          const m = v.match(/^address\s+(\S+)\s+(\S+)$/);
          if (!m) return;
          const name=m[1], prefix=m[2];
          if (prefix.includes('.') || prefix.includes(':')) { // IPv4 or IPv6
            objs.push({ category:'address', name, type:'ipmask',
              subnet:prefix.includes('/')?prefix:prefix+'/32',
              fqdn:'-', startIp:prefix.split('/')[0], endIp:'-',
              wildcard:'-', iface:'-', color:'0', comment:zoneName||'-',
              members:'-', _vdom:zoneName||'global' });
          }
        });
      }
      Object.entries(bookNode._children).forEach(([akey, anode]) => {
        // Recurse into named sub-books (e.g. 'global' inside address-book)
        if (!akey.startsWith('address') && !akey.startsWith('address-set')) {
          processAddrBook(anode, akey === 'global' ? 'global' : (zoneName||akey));
          return;
        }
        if (akey.startsWith('address-set ')) {
          const name = akey.replace('address-set ','');
          const members = anode._values
            .filter(v=>v.startsWith('address ')||v.startsWith('address-set '))
            .map(v=>v.replace(/^address(-set)?\s+/,'').trim()).join(', ');
          objs.push({ category:'address-group', name, type:'group', subnet:'-', fqdn:'-',
            startIp:'-', endIp:'-', wildcard:'-', iface:'-', color:'0',
            comment:zoneName||'-', members, _vdom:zoneName||'global' });
        } else if (akey.startsWith('address ')) {
          const name = akey.replace('address ','');
          const ip4 = val(anode,'ip-prefix') || val(anode,'ip-address');
          const dns = val(anode,'dns-name');
          const range = val(anode,'range-address');
          let type='ipmask', subnet=ip4||'-', fqdn='-', startIp='-', endIp='-';
          if (dns) { type='fqdn'; fqdn=dns; subnet='-'; }
          else if (range) {
            const rp = range.match(/(\S+)\s+to\s+(\S+)/);
            if (rp) { type='iprange'; startIp=rp[1]; endIp=rp[2]; subnet='-'; }
          }
          objs.push({ category:'address', name, type, subnet, fqdn, startIp, endIp,
            wildcard:'-', iface:'-', color:'0',
            comment: val(anode,'description').replace(/^"|"$/g,'')||'-',
            members:'-', _vdom:zoneName||'global' });
        }
      });
    }

    // Check for global address-book (older Junos)
    const globalAB = path(tree, ['security','address-book']);
    if (globalAB) processAddrBook(globalAB, 'global');

    // Per-zone address-books (newer Junos)
    const zonesNode = path(tree, ['security','zones']);
    if (zonesNode) {
      Object.entries(zonesNode._children).forEach(([zkey, znode]) => {
        const zoneName = zkey.replace('security-zone ','');
        const ab = path(znode, ['address-book']);
        if (ab) processAddrBook(ab, zoneName);
      });
    }

    return objs;
  }

  // ── Applications (services) ───────────────────────────────────────────────
  function parseServiceObjects(tree) {
    const svcs = [];
    const appNode = path(tree, ['applications']);
    if (!appNode) return svcs;

    Object.entries(appNode._children).forEach(([akey, anode]) => {
      if (akey.startsWith('application ')) {
        const name = akey.replace('application ','');
        const proto = val(anode,'protocol').toUpperCase() || 'TCP';
        const dstPort = val(anode,'destination-port') || val(anode,'port') || '-';
        const srcPort = val(anode,'source-port') || '-';
        svcs.push({ category:'custom', name, proto,
          tcpPorts: proto==='TCP'?dstPort:'-',
          udpPorts: proto==='UDP'?dstPort:'-',
          icmpType: proto.includes('ICMP')?val(anode,'icmp-type')||'-':'-',
          icmpCode: proto.includes('ICMP')?val(anode,'icmp-code')||'-':'-',
          comment: val(anode,'description').replace(/^"|"$/g,'')||'-',
          color:'0', category_name: val(anode,'application-group')||'-', members:'-' });
      } else if (akey.startsWith('application-set ')) {
        const name = akey.replace('application-set ','');
        const members = anode._values
          .filter(v=>v.startsWith('application ')||v.startsWith('application-set '))
          .map(v=>v.replace(/^application(-set)?\s+/,'').trim()).join(', ');
        svcs.push({ category:'group', name, proto:'GROUP', members,
          tcpPorts:'-', udpPorts:'-', icmpType:'-', icmpCode:'-',
          comment:val(anode,'description').replace(/^"|"$/g,'')||'-' });
      }
    });
    return svcs;
  }

  // ── Routes ────────────────────────────────────────────────────────────────
  function parseRoutes(tree, text) {
    const routes = [];
    const rtNode = path(tree, ['routing-options']);
    if (!rtNode) return routes;

    // Static routes - parse from raw text for reliability
    let srtId = 1;
    const staticRe = /route\s+(\S+)\s+\{([^}]*)\}/g;
    const staticSection = text.match(/routing-options\s*\{[\s\S]*?\}\s*(?=\n\w|$)/);
    const staticText = staticSection ? staticSection[0] : text;
    let srm;
    while ((srm = staticRe.exec(staticText)) !== null) {
      const dst = srm[1];
      const body = srm[2];
      const nhM = body.match(/next-hop\s+(\S+);/);
      const nh = nhM ? nhM[1].replace(';','') : '-';
      const bh = /discard|reject/.test(body) ? 'enable' : 'disable';
      const prefM = body.match(/preference\s+(\d+);/);
      const metM  = body.match(/metric\s+(\d+);/);
      routes.push({ type:'static', id:String(srtId++), dst,
        gateway: bh==='enable' ? 'blackhole' : nh,
        device: '-', distance: prefM?prefM[1]:'5',
        priority: metM?metM[1]:'-', weight:'0',
        comment: (body.match(/description\s+"([^"]+)"/)||[])[1]||'-',
        status:'enable', blackhole:bh, vrf:'0' });
    }
    // Also try simple "route DST next-hop GW;" form
    const simpleRe = /route\s+(\S+)\s+next-hop\s+(\S+);/g;
    let sm2;
    while ((sm2 = simpleRe.exec(staticText)) !== null) {
      if (!routes.find(r=>r.dst===sm2[1])) {
        routes.push({ type:'static', id:String(srtId++), dst:sm2[1],
          gateway:sm2[2], device:'-', distance:'5', priority:'-', weight:'0',
          comment:'-', status:'enable', blackhole:'disable', vrf:'0' });
      }
    }
    const discardRe = /route\s+(\S+)\s+discard;/g;
    let dm;
    while ((dm = discardRe.exec(staticText)) !== null) {
      if (!routes.find(r=>r.dst===dm[1])) {
        routes.push({ type:'static', id:String(srtId++), dst:dm[1],
          gateway:'blackhole', device:'-', distance:'5', priority:'-', weight:'0',
          comment:'-', status:'enable', blackhole:'enable', vrf:'0' });
      }
    }

    // OSPF
    const ospfNode = path(rtNode,['ospf']) || path(tree,['protocols','ospf']);
    if (ospfNode) {
      routes.push({ type:'ospf', id:'ospf', dst:'dynamic', gateway:'-', device:'-',
        routerId: val(ospfNode,'router-id') || val(path(rtNode,['router-id'])||rtNode,'router-id') || '-',
        distance: val(ospfNode,'preference')||'10', priority:'-', weight:'-',
        comment:'OSPF', status:'enable', blackhole:'disable', vrf:'0',
        protocol_detail:`Router-ID: ${val(ospfNode,'router-id')||'-'}` });
    }

    // BGP
    const bgpNode = path(rtNode,['bgp']) || path(tree,['protocols','bgp']);
    if (bgpNode) {
      routes.push({ type:'bgp', id:'bgp', dst:'dynamic', gateway:'-', device:'-',
        as: val(bgpNode,'local-as') || val(rtNode,'autonomous-system') || '-',
        routerId: val(bgpNode,'router-id') || '-',
        distance: val(bgpNode,'preference')||'170', priority:'-', weight:'-',
        comment:'BGP', status:'enable', blackhole:'disable', vrf:'0',
        protocol_detail:`AS: ${val(rtNode,'autonomous-system')||'-'}` });
    }

    // RIP
    if (path(tree,['protocols','rip'])||path(rtNode,['rip'])) {
      routes.push({ type:'rip', id:'rip', dst:'dynamic', gateway:'-', device:'-',
        distance:'100', priority:'-', weight:'-', comment:'RIP',
        status:'enable', blackhole:'disable', vrf:'0', protocol_detail:'RIP' });
    }

    return routes;
  }

  // ── VPN ───────────────────────────────────────────────────────────────────
  function parseVPN(tree, text) {
    const vpns = [];
    const secNode = path(tree, ['security']);
    if (!secNode) return vpns;

    // IKE + IPSec
    const ikeNode  = path(secNode,['ike']);
    const ipsecNode = path(secNode,['ipsec']);

    // Collect IKE gateways
    const ikeGws = {};
    if (ikeNode) {
      Object.entries(ikeNode._children).forEach(([gkey, gnode]) => {
        if (!gkey.startsWith('gateway ')) return;
        const name = gkey.replace('gateway ','');
        const polName = val(gnode,'ike-policy') || val(gnode,'policy') || '-';
        const polNode = polName !== '-' ? path(ikeNode, [`policy ${polName}`]) : null;
        const proposal = polNode ? val(path(polNode,['proposal-set'])||polNode,'proposals')||val(polNode,'proposal-set')||'-' : '-';

        // Get encryption from proposal
        let enc = '-', hash = '-', dhgrp = '-';
        if (polNode) {
          // Check proposals
          const propsStr = val(polNode,'proposals');
          const propNode = propsStr ? path(ikeNode,[`proposal ${propsStr}`]) : null;
          if (propNode) {
            enc   = val(propNode,'encryption-algorithm') || '-';
            hash  = val(propNode,'authentication-algorithm') || '-';
            dhgrp = val(propNode,'dh-group') || '-';
          }
          if (enc==='-') enc = val(polNode,'proposal-set')||'-';
        }

        ikeGws[name] = {
          remote:  val(gnode,'address') || val(gnode,'remote-identity inet')||'-',
          iface:   val(gnode,'external-interface') || val(gnode,'interface') || '-',
          ikeVer:  val(gnode,'version') === 'v2-only' ? '2' : '1',
          authMethod: val(path(polNode||gnode,['pre-shared-key'])||gnode,'pre-shared-key ascii-text') !== '' ||
                      gnode._values.some(v=>v.includes('pre-shared-key')) ? 'psk' : 'certificate',
          proposal: enc !== '-' ? `${enc}-${hash}` : proposal,
          dhgrp, lifetime: val(polNode||gnode,'lifetime-seconds')||'28800',
          localId: val(gnode,'local-identity inet')||'-',
          peerId:  val(gnode,'remote-identity inet')||'-',
        };
      });
    }

    // IPSec VPN tunnels
    if (ipsecNode) {
      Object.entries(ipsecNode._children).forEach(([vkey, vnode]) => {
        if (!vkey.startsWith('vpn ')) return;
        const name = vkey.replace('vpn ','');
        const ikeGwName = val(vnode,'ike-gateway') || val(path(vnode,['ike'])||vnode,'gateway') || '-';
        const gwInfo = ikeGws[ikeGwName] || {};

        // Phase2 proposal
        const p2polName = val(vnode,'ipsec-policy') || val(path(vnode,['ipsec'])||vnode,'policy') || '-';
        const p2polNode = p2polName !== '-' && ipsecNode ? path(ipsecNode,[`policy ${p2polName}`]) : null;
        let p2enc='-', p2hash='-', p2dhgrp='-';
        if (p2polNode) {
          const p2propsStr = val(p2polNode,'proposals');
          const p2propNode = p2propsStr ? path(ipsecNode,[`proposal ${p2propsStr}`]) : null;
          if (p2propNode) {
            p2enc   = val(p2propNode,'encryption-algorithm')||'-';
            p2hash  = val(p2propNode,'authentication-algorithm')||'-';
            p2dhgrp = val(p2propNode,'perfect-forward-secrecy keys')||val(p2propNode,'dh-group')||'-';
          }
        }

        // Parse traffic-selectors from tree (vnode._children)
        const phase2 = [];
        // Try tree first
        const tsFromTree = Object.entries(vnode._children)
          .filter(([k]) => k.startsWith('traffic-selector '));
        let vpnBody = '';
        if (tsFromTree.length === 0) {
          // Fallback: scan text for this vpn block
          const ipsecTxt = text.slice(text.indexOf('ipsec {'));
          const vpnBlockM = ipsecTxt.match(new RegExp('vpn\\s+' + name.replace(/\./, '\\.') + '\\s*\\{'));
          if (vpnBlockM) {
            let di = vpnBlockM.index + vpnBlockM[0].length, depth2 = 1;
            while (di < ipsecTxt.length && depth2 > 0) {
              if (ipsecTxt[di]==='{') depth2++;
              else if (ipsecTxt[di]==='}') depth2--;
              if (depth2>0) vpnBody += ipsecTxt[di];
              di++;
            }
          }
        } else {
          tsFromTree.forEach(([tsKey, tsNode]) => {
            const lsM = tsNode._values.find(v=>v.startsWith('local-ip '));
            const rsM = tsNode._values.find(v=>v.startsWith('remote-ip '));
            phase2.push({
              name: name+'-'+tsKey.replace('traffic-selector ',''), phase1: name,
              proposal: p2enc!=='-'?p2enc+'-'+p2hash:p2polName,
              pfs: p2dhgrp!=='-'?'enable':'disable', dhgrp: p2dhgrp,
              lifetime: '3600', replay: 'enable',
              localSub:  lsM ? lsM.replace('local-ip ','')  : '-',
              remoteSub: rsM ? rsM.replace('remote-ip ','') : '-',
              autoNeg:'-', comment:'-',
            });
          });
        }
        const tsRe = /traffic-selector\s+(\S+)\s*\{([^}]*)\}/g;
        let tsm;
        while ((tsm = tsRe.exec(vpnBody)) !== null) {
          const tsBody = tsm[2];
          const lsM = tsBody.match(/local-ip\s+(\S+);/);
          const rsM = tsBody.match(/remote-ip\s+(\S+);/);
          phase2.push({
            name: name+'-'+tsm[1], phase1: name,
            proposal: p2enc!=='-' ? p2enc+'-'+p2hash : p2polName,
            pfs: p2dhgrp!=='-'?'enable':'disable', dhgrp:p2dhgrp,
            lifetime: '3600', replay:'enable',
            localSub:  lsM?lsM[1]:'-',
            remoteSub: rsM?rsM[1]:'-',
            autoNeg:'-', comment:'-',
          });
        }
        // If no traffic-selectors, add generic p2
        if (phase2.length===0 && p2polName!=='-') {
          phase2.push({ name:name+'-P2', phase1:name,
            proposal: p2enc!=='-'?p2enc+'-'+p2hash:p2polName,
            pfs:'enable', dhgrp:p2dhgrp, lifetime:'3600', replay:'enable',
            localSub:'-', remoteSub:'-', autoNeg:'-', comment:'-' });
        }

        const _gwRef = ikeNode ? path(ikeNode,[`gateway ${ikeGwName}`]) : null;
        const _dpdBlock = _gwRef ? path(_gwRef,['dead-peer-detection']) : null;
        const _dpdEnabled = _gwRef && (_dpdBlock || (_gwRef._values||[]).some(v=>v==='dead-peer-detection'));
        const _dpd = _dpdEnabled ? 'enable' : '-';
        const _dpdInterval = _dpdBlock ? (val(_dpdBlock,'interval')||'-') : '-';
        vpns.push({
          type:'ipsec-p1', name,
          mode: val(vnode,'mode')||'tunnel',
          remote:  gwInfo.remote||'-',
          iface:   gwInfo.iface || val(vnode,'bind-interface')||'-',
          ikeVer:  gwInfo.ikeVer||'1',
          authMethod: gwInfo.authMethod||'psk',
          peertype: '-',
          proposal: gwInfo.proposal||'-',
          dhgrp:    gwInfo.dhgrp||'-',
          lifetime: gwInfo.lifetime||'28800',
          natTraversal: ikeNode ? (val(path(ikeNode,[`gateway ${ikeGwName}`])||{_values:[]},'nat-keepalive')!==''?'enable':'disable') : 'enable',
          dpd: _dpd, dpdInterval: _dpdInterval,
          localId: gwInfo.localId||'-', peerId: gwInfo.peerId||'-',
          xauthType: '-', cert: '-', monitorConn: '-', autoNeg: '-',
          status: 'enable', phase2,
          _vdom: 'default',
        });
      });
    }

    // Remote access / SSL VPN (Junos SA / Pulse)
    const dynVpn = path(secNode,['dynamic-vpn']);
    if (dynVpn) {
      vpns.push({
        type:'ssl-vpn', name:'Dynamic-VPN',
        iface: val(dynVpn,'interface')||'-', remote:'-',
        port:'443', tunPort:'-', addr:'-', dns1:'-', dns2:'-', wins1:'-',
        ipPool: val(path(dynVpn,['access-profile'])||dynVpn,'address-pool')||'-',
        algorithm:'high', dtls:'-', authTimeout:'-',
        ikeVer:'-', authMethod:'certificate', proposal:'-', dhgrp:'-', phase2:[],
        status:'enable', _vdom:'default',
      });
    }

    return vpns;
  }

  // ── NAT ───────────────────────────────────────────────────────────────────
  function parseNAT(tree) {
    const nats = [];
    const secNode = path(tree,['security']);
    if (!secNode) return nats;
    const natNode = path(secNode,['nat']);
    if (!natNode) return nats;

    // Source NAT
    const srcNat = path(natNode,['source']);
    if (srcNat) {
      Object.entries(srcNat._children).forEach(([rkey,rnode]) => {
        if (!rkey.startsWith('rule-set ')) return;
        const rsName = rkey.replace('rule-set ','');
        Object.entries(rnode._children).forEach(([rrkey,rrnode]) => {
          if (!rrkey.startsWith('rule ')) return;
          const rname = rrkey.replace('rule ','');
          const thenNode = path(rrnode,['then','source-nat']);
          const poolName = thenNode ? val(thenNode,'pool')||'-' : '-';
          nats.push({ type:'ippool', name:`${rsName}-${rname}`,
            poolType:'overload', startIp: poolName, endIp:'-',
            srcIntf:val(rnode,'from zone')||val(rnode,'from interface')||'-',
            arpReply:'enable', comment:`Source NAT ruleset: ${rsName}` });
        });
      });
    }

    // Destination NAT
    const dstNat = path(natNode,['destination']);
    if (dstNat) {
      Object.entries(dstNat._children).forEach(([rkey,rnode]) => {
        if (!rkey.startsWith('rule-set ')) return;
        const rsName = rkey.replace('rule-set ','');
        Object.entries(rnode._children).forEach(([rrkey,rrnode]) => {
          if (!rrkey.startsWith('rule ')) return;
          const rname = rrkey.replace('rule ','');
          const matchNode = path(rrnode,['match']);
          const thenNode  = path(rrnode,['then','destination-nat','pool']);
          nats.push({ type:'vip', name:`${rsName}-${rname}`,
            vipType:'static-nat',
            extIp:   matchNode ? val(matchNode,'destination-address')||'-':'-',
            extIntf: val(rnode,'from interface')||'-',
            mapIp:   thenNode ? val(thenNode,'pool')||'-' : '-',
            portFwd: 'disable', extPort:'-', mapPort:'-', proto:'-',
            comment:`Destination NAT ruleset: ${rsName}`, status:'enable' });
        });
      });
    }

    // NAT pools
    const poolNode = path(natNode,['source','pool']) || path(natNode,['pool']);
    if (poolNode) {
      Object.entries(poolNode._children || {}).forEach(([pkey,pnode]) => {
        const pname = pkey.replace('pool ','');
        const addr = val(pnode,'address');
        if (addr && addr.includes('-')) {
          const parts = addr.split('-');
          nats.push({ type:'ippool', name:`Pool-${pname}`,
            poolType:'overload', startIp:parts[0], endIp:parts[1]||parts[0],
            srcIntf:'-', arpReply:'enable', comment:'NAT Pool' });
        }
      });
    }

    return nats;
  }

  // ── Schedules ─────────────────────────────────────────────────────────────
  function parseSchedules(tree) {
    const scheds = [];
    const schedNode = path(tree, ['schedulers']);
    if (!schedNode) return scheds;
    Object.entries(schedNode._children).forEach(([skey, snode]) => {
      const name = skey.replace('scheduler ','');
      scheds.push({ type:'recurring', name,
        start: val(snode,'start-time')||'-',
        end:   val(snode,'stop-time')||'-',
        day:   val(snode,'day-of-week')||'-', color:'0', _vdom:'default' });
    });
    return scheds;
  }

  // ── Users ─────────────────────────────────────────────────────────────────
  function parseUsers(tree, text) {
    const users = [];

    // System local users - parse from raw text for reliability
    // Parse all "user NAME { ... }" blocks inside login { }
    const loginSection = text.match(/login\s*\{([\s\S]*?)^\}/m);
    const loginText = loginSection ? loginSection[1] : '';
    // Extract each user block by scanning braces
    const adminBlocks = [];
    let aidx = 0;
    const uRe = /\buser\s+(\S+)\s*\{/g;
    let um2;
    while ((um2 = uRe.exec(loginText)) !== null) {
      const uname = um2[1];
      let depth = 1, start = um2.index + um2[0].length;
      let body = '';
      for (let ci = start; ci < loginText.length && depth > 0; ci++) {
        if (loginText[ci] === '{') depth++;
        else if (loginText[ci] === '}') { depth--; if (depth===0) break; }
        if (depth > 0) body += loginText[ci];
      }
      adminBlocks.push({ name: uname, body });
    }
    for (const { name, body } of adminBlocks) {
      const am = { 1: name, 2: body };  // compatibility alias
      const clsM  = body.match(/class\s+(\S+);/);
      const cls   = clsM ? clsM[1] : 'operator';
      const mailM = body.match(/full-name\s+"([^"]+)"/)||body.match(/full-name\s+(\S+)/);
      const hasSSH= body.includes('ssh-rsa')||body.includes('ssh-ecdsa');
      const has2fa= body.includes('otp')||body.includes('totp');
      const perms = cls==='super-user'?[{resource:'All',access:'read-write'}]:cls==='read-only'?[{resource:'All',access:'read'}]:[{resource:cls,access:'read-write'}];
      users.push({ type:'admin', name,
        status:'enable', authType:hasSSH?'ssh-key':'password',
        email:mailM?mailM[1]:'-',
        twoFactor:has2fa?'enable':'disable', twoFType:has2fa?'otp':'-',
        ldapServer:'-', radiusServer:'-',
        comment:mailM?mailM[1]:'-', members:'-', vdom:'default',
        permissions:perms, roles:[cls],
        accessLevel:cls==='super-user'?'super-admin':cls==='read-only'?'read-only':'admin',
        _vdom:'default' });
    }
    // RADIUS from raw text
    const radRe = /radius-server\s+(\S+)\s*\{([^}]*)\}/g;
    let radm;
    while ((radm = radRe.exec(text)) !== null) {
      const srv = radm[1]; const body = radm[2];
      const portM = body.match(/port\s+(\d+)/);
      if (!users.find(u=>u.type==='radius-server'&&u.server===srv)) {
        users.push({ type:'radius-server', name:`RADIUS-${srv}`,
          server:srv, port:portM?portM[1]:'1812',
          authType:'auto', nasIp:'-', comment:'-', status:'enable',
          members:'-', permissions:[], roles:[], accessLevel:'auth-server', _vdom:'default' });
      }
    }
    const sysNode = path(tree,['system']);
    if (false && sysNode) { // kept for reference, replaced above
      Object.entries(sysNode._children).forEach(([ukey, unode]) => {
        if (!ukey.startsWith('login user ')) return;
        const name = ukey.replace('login user ','');
        const cls  = val(unode,'class') || 'operator';
        const authNode = path(unode,['authentication']);
        const has2fa = authNode && (authNode._values.some(v=>v.includes('otp')||v.includes('totp')));
        const perms = cls === 'super-user' ? [{resource:'All',access:'read-write'}]
                    : cls === 'read-only'   ? [{resource:'All',access:'read'}]
                    : [{resource:cls,access:'read-write'}];
        users.push({ type:'admin', name,
          status: unode._values.includes('inactive') ? 'disable' : 'enable',
          authType: authNode && val(authNode,'encrypted-password') ? 'password' :
                    authNode && val(authNode,'ssh-rsa') ? 'ssh-key' : 'password',
          email: val(unode,'full-name').replace(/^"|"$/g,'')||'-',
          twoFactor: has2fa ? 'enable' : 'disable', twoFType: has2fa?'otp':'-',
          ldapServer:'-', radiusServer:'-',
          comment: val(unode,'full-name').replace(/^"|"$/g,'')||'-',
          members:'-', vdom:'default',
          permissions: perms, roles:[cls], accessLevel: cls==='super-user'?'super-admin':cls==='read-only'?'read-only':'admin',
          _vdom:'default' });
      });

      // RADIUS
      const radiusNode = path(sysNode,['radius-server']);
      if (radiusNode) {
        radiusNode._values.concat(Object.keys(radiusNode._children)).forEach((srv,i) => {
          if (!srv || srv.startsWith('_')) return;
          users.push({ type:'radius-server', name:`RADIUS-${i+1}`,
            server:srv, port: val(radiusNode,`${srv} port`)||'1812',
            authType:'auto', nasIp:'-', comment:'-', status:'enable',
            members:'-', permissions:[], roles:[], accessLevel:'auth-server', _vdom:'default' });
        });
        Object.entries(radiusNode._children).forEach(([rkey,rnode]) => {
          users.push({ type:'radius-server', name:rkey,
            server:rkey, port:val(rnode,'port')||'1812',
            authType:'auto', nasIp:'-', comment:'-', status:'enable',
            members:'-', permissions:[], roles:[], accessLevel:'auth-server', _vdom:'default' });
        });
      }

      // LDAP
      const ldapNode = path(sysNode,['ldap-server']) || path(sysNode,['authentication-order']);
      if (ldapNode) {
        Object.entries(ldapNode._children).forEach(([lkey,lnode]) => {
          users.push({ type:'ldap-server', name:lkey,
            server:val(lnode,'server')||lkey, port:val(lnode,'port')||'389',
            dn: val(lnode,'base')||val(lnode,'base-dn')||'-',
            bindType:'regular', bindDn:val(lnode,'search-name')||'-', cnid:'uid',
            groupFilter:'-', ssl:val(lnode,'ssl')||'disable',
            comment:'-', status:'enable', members:'-',
            permissions:[], roles:[], accessLevel:'auth-server', _vdom:'default' });
        });
      }
    }

    // Access profiles / groups (via access module)
    const accessNode = path(tree,['access']);
    if (accessNode) {
      Object.entries(accessNode._children).forEach(([gkey,gnode]) => {
        if (!gkey.startsWith('group ')) return;
        const name = gkey.replace('group ','');
        const members = gnode._values.filter(v=>v.startsWith('member ')).map(v=>v.replace('member ','')).join(', ');
        users.push({ type:'group', name, groupType:'access',
          members, match:'-', authTimeout:'-', comment:'-',
          status:'enable', permissions:[], roles:[], accessLevel:'group', _vdom:'default' });
      });
    }

    return users;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function prefixToMask(bits) {
    const n = (0xFFFFFFFF << (32-bits)) >>> 0;
    return [(n>>>24)&0xFF,(n>>>16)&0xFF,(n>>>8)&0xFF,n&0xFF].join('.');
  }
  function guessRole(name) {
    const n = (name||'').toLowerCase();
    if (/ge-0\/0\/0|xe-0\/0\/0|et-0\/0\/0|fe-0\/0\/0|em0|ext|wan|untrust/.test(n)) return 'WAN';
    if (/ge-0\/0\/1|em1|lan|trust|int/.test(n)) return 'LAN';
    if (/dmz|server|srv/.test(n)) return 'DMZ';
    if (/lo0|loopback|mgmt/.test(n)) return 'MGMT';
    if (/ae|bond|lag/.test(n)) return 'LAN';
    if (/st0|vpn|ipsec/.test(n)) return 'VPN';
    return 'Unknown';
  }
  function mapZoneRole(zone) {
    const z = (zone||'').toLowerCase();
    if (/untrust|outside|wan|internet/.test(z)) return 'WAN';
    if (/trust|inside|lan|internal/.test(z))    return 'LAN';
    if (/dmz|server/.test(z))                   return 'DMZ';
    if (/mgmt|manage/.test(z))                  return 'MGMT';
    if (/vpn/.test(z))                          return 'VPN';
    return 'Unknown';
  }

  // HA/Cluster：SRX chassis cluster，已查證官方文件語法 `chassis { cluster { reth-count N;
  // redundancy-group N { node 0 priority X; node 1 priority Y; } } }`（brace 格式；此檔案
  // Juniper parser 走 brace tree，不是 set-format，故用區塊擷取而非 setVal）。比照既有
  // parseDhcp() 內 _xb() 大括號計數輔助函式的寫法（未共用，各自函式內各自實作一份小工具）
  function parseHa(text) {
    const result = { enabled:false, mode:'-', groupId:'-', priority:'-', peerIp:'-', syncInterface:'-', vip:'-' };
    const _xb=(src,kw)=>{const re=new RegExp(`\\b${kw}[\\s\\w-]*\\s*\\{`);const m=re.exec(src);if(!m)return null;let d=0,i=m.index,s=-1;while(i<src.length){if(src[i]==='{'){if(d===0)s=i+1;d++;}else if(src[i]==='}'){d--;if(d===0)return src.slice(s,i);}i++;}return null;};
    const chassisBody = _xb(text, 'chassis');
    const clusterBody = chassisBody ? _xb(chassisBody, 'cluster') : null;
    if (!clusterBody) return result;
    result.enabled = true;
    result.mode = 'chassis-cluster';
    const rgMatch = clusterBody.match(/redundancy-group\s+(\d+)\s*\{/);
    result.groupId = rgMatch ? rgMatch[1] : '-';
    const prioM = clusterBody.match(/node\s+\d+\s+priority\s+(\d+)/);
    result.priority = prioM ? prioM[1] : '-';
    const rethM = clusterBody.match(/reth-count\s+(\d+)/);
    result.syncInterface = rethM ? `reth-count ${rethM[1]}` : '-';
    return result;
  }

  // ── Main parse ────────────────────────────────────────────────────────────
  function parse(text) {
    const tree = parseJunosTree(text);
    // 位址物件需先解析出來，才能建 addrTypeMap 供 policies 的 source/destination-address
    // 名稱反查 v4/v6 型別（見 _splitAddr() 上方註解）
    const addresses = parseAddressObjects(tree);
    return {
      vendor:     'Juniper',
      deviceInfo: parseDeviceInfo(text, tree),
      interfaces: parseInterfaces(tree),
      policies:   parsePolicies(tree, buildAddrTypeMap(addresses)),
      routes:     parseRoutes(tree, text),
      vpn:        parseVPN(tree, text),
      addresses,
      services:   parseServiceObjects(tree),
      schedules:  parseSchedules(tree),
      nat:        parseNAT(tree),
      users:      parseUsers(tree, text),
      sdwan:      parseSdwan(text, tree),
      ha:         parseHa(text),
      dhcp:       parseDhcp(text, tree),
      dns:        parseDns(text, tree),
      snmp:       parseSnmp(text, tree),
      logservers: parseLogServers(text, tree),
      _tree:      tree,
      _vdomNames: [],
      _isMultiVdom: false,
    };
  }


  // ── Juniper SRX AppQoE / Multi-WAN path selection ─────────────────────────
  // SRX uses CoS + policy routing; no native "SD-WAN" config block
  // We parse: interfaces with inet + routing-options static (multi-WAN)
  // + services rpm (probe) + class-of-service

  // ── DHCP Server & Relay ──────────────────────────────────────────────────
  function parseDhcp(text, tree) {
    const servers=[], relays=[];
    // Robust block extractor using brace counting
    const _xb=(src,kw)=>{const re=new RegExp(`\\b${kw}[\\s\\w-]*\\s*\\{`);const m=re.exec(src);if(!m)return null;let d=0,i=m.index,s=-1;while(i<src.length){if(src[i]==='{'){if(d===0)s=i+1;d++;}else if(src[i]==='}'){d--;if(d===0)return src.slice(s,i);}i++;}return null;};
    // address-assignment pools inside access block
    const accessBody=_xb(text,'access');
    if(accessBody){
      const poolRe=/pool\s+(\S+)\s*\{/g; let pm;
      while((pm=poolRe.exec(accessBody))!==null){
        const poolBody=_xb(accessBody.slice(pm.index),'pool');
        if(!poolBody) continue;
        const poolName=pm[1];
        const inetBody=_xb(poolBody,'inet')||poolBody;
        const rangeM=inetBody.match(/range\s+\S+\s*\{\s*low\s+([\d\.]+);\s*high\s+([\d\.]+)/);
        const gwM=inetBody.match(/router\s+([\d\.]+)/);
        const dnsM=inetBody.match(/name-server\s*\[\s*([\d\.\s]+?)\s*\]/);
        const domM=inetBody.match(/domain-name\s+([\w\.\-]+)/);
        const leaseM=inetBody.match(/maximum-lease-time\s+(\d+)/);
        const dnsArr=dnsM?dnsM[1].trim().split(/\s+/):[];
        servers.push({name:poolName,iface:'-',
          startIp:rangeM?rangeM[1]:'-',endIp:rangeM?rangeM[2]:'-',
          gateway:gwM?gwM[1]:'-',mask:'-',
          dns1:dnsArr[0]||'-',dns2:dnsArr[1]||'-',
          domain:domM?domM[1]:'-',lease:leaseM?leaseM[1]:'86400',status:'enable',comment:''});
      }
    }
    // DHCP relay: forwarding-options helpers
    const fwdBody=_xb(text,'forwarding-options');
    if(fwdBody){const helpBody=_xb(fwdBody,'helpers')||fwdBody;const sRe=/server\s+([\d\.]+)/g;let sm;
      while((sm=sRe.exec(helpBody))!==null)relays.push({name:'dhcp-relay',iface:'-',serverIp:sm[1],status:'enable',comment:''});}
    return {servers,relays};
  }
  // ── DNS ─────────────────────────────────────────────────────────────────
  function parseDns(text, tree) {
    const result={servers:[],secondaries:[],domain:'-',proxy:false,proxyRules:[],dnsOverTls:false,cacheSize:'-',static:[]};
    const sysM=text.match(/\bsystem\s*\{([\s\S]*?)\n\}/);
    if(sysM){
      const nsM=sysM[1].match(/name-server\s*\{([^}]+)\}/);
      if(nsM){for(const m of nsM[1].matchAll(/([\d\.]+);/g))result.servers.push(m[1]);}
      const domM=sysM[1].match(/domain-name\s+([\w\.\-]+)/);
      if(domM)result.domain=domM[1];
    }
    return result;
  }


  // ── SNMP ────────────────────────────────────────────────────────────────────
  function parseSnmp(text, tree) {
    const result={enabled:false,agent:{name:'-',description:'-',location:'-',contact:'-',version:[]},communities:[],v3users:[],trapServers:[]};
    const snmpM=text.match(/\bsnmp\s*\{([\s\S]*?)\n\}/);
    if(!snmpM) return result;
    result.enabled=true;
    const sb=snmpM[1];
    result.agent.name        = (sb.match(/name\s+"?([^";\n]+)"?/)||[])[1]?.trim()||'-';
    result.agent.description = (sb.match(/description\s+"?([^";\n]+)"?/)||[])[1]?.trim()||'-';
    result.agent.contact     = (sb.match(/contact\s+"?([^";\n]+)"?/)||[])[1]?.trim()||'-';
    result.agent.location    = (sb.match(/location\s+"?([^";\n]+)"?/)||[])[1]?.trim()||'-';
    // Communities
    const commRe=/community\s+(\S+)\s*\{([^}]+)\}/g; let cm;
    while((cm=commRe.exec(sb))!==null){
      const name=cm[1].replace(/"/g,''); const body=cm[2];
      const perm=/read-write/i.test(body)?'rw':'ro';
      const clients=[...body.matchAll(/clients\s*\{([^}]+)\}/g)].flatMap(m=>m[1].match(/[\d\.]+\/\d+/g)||[]);
      result.communities.push({name,permission:perm,allowedHosts:clients,events:'-',status:'enable'});
      if(!result.agent.version.includes('v2c')) result.agent.version.push('v2c');
    }
    // Trap targets
    // Extract trap-group blocks with brace counting (nested { } for targets)
    const _xbJn=(src,kw)=>{const re=new RegExp(`\\b${kw}[\\s\\S]{0,30}\\{`);const m=re.exec(src);if(!m)return null;let d=0,i=m.index,s=-1;while(i<src.length){if(src[i]==='{'){if(d===0)s=i+1;d++;}else if(src[i]==='}'){d--;if(d===0)return src.slice(s,i);}i++;}return null;};
    const tgRe=/trap-group\s+(\S+)\s*\{/g; let tg;
    while((tg=tgRe.exec(sb))!==null){
      const tgBody=_xbJn(sb.slice(tg.index),'trap-group');
      if(!tgBody) continue;
      const ver=/version\s+v?(\d+)/i.exec(tgBody);
      const tgtsBody=_xbJn(tgBody,'targets');
      const targets=(tgtsBody||'').match(/[\d.]+(?:\.[\d]+){3}/g)||[];
      targets.forEach(ip=>result.trapServers.push({ip,port:'162',community:result.communities[0]?.name||'-',version:ver?`v${ver[1]}`:'v2c'}));
    }
    // v3 users
    if(/usm\s*\{/i.test(sb)){
      const v3Re=/user\s+(\S+)\s*\{/g; let vm2;
      while((vm2=v3Re.exec(sb))!==null){ result.v3users.push({name:vm2[1],authProto:'sha',privProto:'aes',secLevel:'auth-priv',notifyHost:'-',status:'enable'}); if(!result.agent.version.includes('v3')) result.agent.version.push('v3'); }
    }
    return result;
  }

  // ── Log Servers ──────────────────────────────────────────────────────────────
  function parseLogServers(text, tree) {
    const result={syslog:[],fortianalyzer:[],netflow:[],logForward:[]};
    const sysM=text.match(/\bsyslog\s*\{([\s\S]*?)\n\s*\}/);
    if(!sysM) return result;
    const hostRe=/host\s+([\d\.]+)\s*\{([^}]+)\}/g; let hm;
    while((hm=hostRe.exec(sysM[1]))!==null){
      const ip=hm[1]; const body=hm[2];
      const portM=body.match(/port\s+(\d+)/); const facM=body.match(/facility-override\s+(\S+)/);
      result.syslog.push({name:`Syslog-${ip}`,server:ip,port:portM?portM[1]:'514',facility:facM?facM[1]:'local7',format:'BSD',protocol:'UDP',level:'notice',status:'enable'});
    }
    // Netflow
    const nfM=text.match(/flow\s*\{[\s\S]*?collector\s*\{([^}]+)\}/);
    if(nfM){ const ip=(nfM[1].match(/[\d\.]+/)||[])[0]; if(ip) result.netflow.push({collector:ip,port:'2055',activeTimeout:'60',status:'enable'}); }
    return result;
  }

  function parseSdwan(text, tree) {
    const result = { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] };

    // Detect multi-WAN via multiple default routes
    const defaultRoutes = [];
    const routeRe = /route\s+0\.0\.0\.0\/0\s+next-hop\s+([\d\.]+)/gi;
    let m;
    while ((m = routeRe.exec(text)) !== null) defaultRoutes.push(m[1]);
    // Also check routing-options static for multiple nexthops
    const staticBlock = text.match(/static\s*\{([\s\S]*?)\}/);
    if (staticBlock) {
      const nhRe = /route\s+0\.0\.0\.0\/0.*?next-hop\s+([\d\.]+)/gi;
      let nm; const seen = new Set();
      while ((nm = nhRe.exec(staticBlock[1])) !== null) {
        if (!seen.has(nm[1])) { seen.add(nm[1]); defaultRoutes.push(nm[1]); }
      }
    }
    if (defaultRoutes.length < 1) return result;
    result.enabled = defaultRoutes.length > 1 || /load-balance\s+per-packet|ecmp/i.test(text);
    if (!result.enabled) return result;
    result.lbMode = /load-balance\s+per-packet/i.test(text) ? 'load-balance' : 'priority';

    // WAN interfaces = inet interfaces connected to public IPs
    const ifBlocks = text.match(/interfaces\s*\{([\s\S]*?)\n\}/);
    if (ifBlocks) {
      const unitRe = /(\S+)\s*\{[\s\S]*?unit\s+\d+\s*\{[\s\S]*?inet\s*\{[\s\S]*?address\s+([\d\.\/]+)/gi;
      let im; let idx = 0;
      while ((im = unitRe.exec(ifBlocks[1])) !== null) {
        const [,iface,addr] = im;
        const ip = addr.split('/')[0];
        const firstOctet = parseInt(ip.split('.')[0]);
        const isPublic = !(firstOctet===10 || (firstOctet===172&&parseInt(ip.split('.')[1])>=16) || (firstOctet===192&&ip.split('.')[1]==='168'));
        if (isPublic || defaultRoutes.some(gw => gw.startsWith(ip.split('.').slice(0,3).join('.')))) {
          idx++;
          result.members.push({
            id: String(idx), iface, zone: 'untrust',
            gateway: defaultRoutes[idx-1] || '-', gateway6: '-',
            priority: idx, weight: 1, cost: 0, spillover: 0, volumeRatio: 1,
            status: 'enable', comment: `Public WAN: ${addr}`,
          });
        }
      }
    }

    // RPM probes = health checks
    const rpmBlock = text.match(/rpm\s*\{([\s\S]*?)\n\s*\}/);
    if (rpmBlock) {
      const probeRe = /probe\s+"?([\w\-]+)"?\s*\{[\s\S]*?test\s+"?([\w\-]+)"?\s*\{([\s\S]*?)\}/gi;
      let rm;
      while ((rm = probeRe.exec(rpmBlock[1])) !== null) {
        const [, probeName, testName, body] = rm;
        const targetM = body.match(/target\s+address\s+([\d\.]+)/i);
        const intervalM = body.match(/probe-interval\s+(\d+)/i);
        const threshM   = body.match(/thresholds\s*\{([\s\S]*?)\}/i);
        const latM = threshM ? threshM[1].match(/successive-loss\s+(\d+)/) : null;
        result.healthChecks.push({
          name: `${probeName}/${testName}`,
          server: targetM ? targetM[1] : '-',
          protocol: body.includes('icmp') ? 'ping' : 'http',
          port: '-', interval: intervalM ? intervalM[1] : '10',
          timeout: '-', failtime: '-', recoverytime: '-',
          probePackets: '5', http200Only: 'disable', members: 'all',
          slaThresholds: latM ? [{id:'1', latency:'200', jitter:'50', packetLoss:latM[1]}] : [],
        });
      }
    }

    // Load balance policy = service rule
    if (/load-balance\s+per-packet/i.test(text)) {
      result.services.push({
        id:'1', name:'ECMP_Load_Balance', mode:'load-balance',
        src:'all', dst:'all', srcNegate:'disable', dstNegate:'disable', users:'-',
        protocol:'0', startPort:'-', endPort:'-',
        priorityMembers: result.members.map(m=>m.iface).join(', ') || '-',
        priorityZone:'-', preferredUplink:'-', slaCompare:'order', tie:'zone',
        slaRefs:[], inputDevice:'-', status:'enable',
        comment:'ECMP per-packet load balance',
      });
    } else if (result.members.length > 1) {
      result.services.push({
        id:'1', name:'WAN_Failover_Policy', mode:'priority',
        src:'all', dst:'all', srcNegate:'disable', dstNegate:'disable', users:'-',
        protocol:'0', startPort:'-', endPort:'-',
        priorityMembers: result.members.map(m=>m.iface).join(', ') || '-',
        priorityZone:'-',
        preferredUplink: result.members[0]?.iface || '-',
        slaCompare:'order', tie:'zone', slaRefs:[], inputDevice:'-', status:'enable',
        comment:'Distance-based WAN failover',
      });
    }

    return result;
  }

  return { parse };
})();


