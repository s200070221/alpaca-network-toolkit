// ══════════════════════════════════════════════════════════
//  F5 BIG-IP PARSER（XN116）
// ══════════════════════════════════════════════════════════
// BIG-IP 是負載平衡器（ADC），本工具以防火牆／路由器的角度只分析下列項目（畫面與報告另有備註 f5.scope_*）：
//   介面（net vlan＋net self、管理位址）、路由（net route、sys management-route）、位址物件（ltm node、
//   security firewall address-list、ltm virtual-address）、virtual server（列在 NAT 頁，並合成一條允許規則
//   供查詢）、ltm nat／snat／snatpool、AFM 規則（security firewall policy／rule-list，若有授權與設定）、
//   本機帳號、SNMP、管理介面來源限制（sys httpd／sshd allow）、遠端 syslog。
// 不分析：iRule 內容、profile、APM／ASM／GTM、HA（device trust）、route domain 的隔離語意。
// 輸入：bigip.conf／bigip_base.conf、tmsh list 輸出或 Oxidized tmos 錄製（# 開頭的 show 輸出區段略過，只讀版本）。
// 格式依據：Oxidized tmos 真實錄製、f5devcentral/f5-corkscrew 測試用真實 bigip.conf（Apache-2.0，ltm 物件）；
// net self／vlan／route、sys httpd／sshd、AFM 語法依 F5 tmsh 參考文件，未以真實錄製驗證。
// 解析以縮排為準：tmsh 輸出頂層區塊在第 0 欄、結尾為第 0 欄的「}」，iRule 內容不展開（避免程式碼中的大括號）。
const BigipParser = (() => {
  const V4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
  // 服務名稱（destination 的 :https 等寫法）→ 埠號
  const PORT_NAMES = { any: '0', http: '80', https: '443', ssh: '22', telnet: '23', ftp: '21', smtp: '25', domain: '53', snmp: '161', ldap: '389', ldaps: '636',
    pop3: '110', imap: '143', imaps: '993', pop3s: '995', ntp: '123', radius: '1812', 'radius-acct': '1813', mysql: '3306', 'ms-sql-s': '1433', rdp: '3389', sip: '5060' };
  const strip = s => String(s || '').replace(/^"|"$/g, '').replace(/^\/Common\//, '');
  const noRd = s => String(s || '').replace(/%\d+/, '');

  // tmsh 樹：每個節點 {text, kids}；以「行尾 {」開啟子節點、單獨「}」結束；「x { }」與「x { a b }」視為葉節點
  function buildTree(text) {
    const root = { text: '', kids: [] };
    const stack = [root];
    let skipDepth = 0;   // iRule（ltm rule）等程式內容：只算大括號深度、不建節點
    for (const raw of text.split('\n')) {
      const line = raw.replace(/\s+$/, '');
      if (!line.trim() || (stack.length === 1 && !skipDepth && /^#/.test(line))) continue;
      const t = line.trim();
      if (skipDepth) {
        skipDepth += (t.match(/\{/g) || []).length - (t.match(/\}/g) || []).length;
        if (skipDepth <= 0) { skipDepth = 0; stack.pop(); }
        continue;
      }
      if (t === '}') { if (stack.length > 1) stack.pop(); continue; }
      const open = /\{$/.test(t);
      const node = { text: open ? t.replace(/\s*\{$/, '') : t, kids: [] };
      stack[stack.length - 1].kids.push(node);
      if (open) {
        stack.push(node);
        // 程式碼區塊：iRule、iApp 範本、tmsh script，內容不解析
        if (stack.length === 2 && /^(?:ltm rule|sys application template|cli script|gtm rule)\s/.test(node.text)) skipDepth = 1;
      }
    }
    return root;
  }
  const tops = (tree, re) => tree.kids.filter(k => re.test(k.text));
  const kid = (n, re) => n.kids.find(k => re.test(k.text));
  const kidVal = (n, re) => { const k = n.kids.find(x => re.test(x.text)); return k ? (k.text.match(re) || [])[1] : undefined; };
  // 「key { a b }」單行清單或子區塊的子項名稱
  function listOf(n, key) {
    if (!n) return [];
    const one = n.kids.find(k => new RegExp('^' + key + '\\s*\\{([^}]*)\\}$').test(k.text));
    if (one) return one.text.replace(/^[^{]*\{|\}$/g, '').trim().split(/\s+/).filter(Boolean);
    const blk = n.kids.find(k => k.text === key);
    return blk ? blk.kids.map(k => k.text.replace(/\s*\{\s*\}$/, '').trim()) : [];
  }
  function lenToMask(len) {
    const n = parseInt(len, 10);
    if (!(n >= 0 && n <= 32)) return '-';
    const v = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0;
    return [24, 16, 8, 0].map(s => (v >>> s) & 255).join('.');
  }
  const maskToLen = m => { if (!V4.test(m)) return null; const b = m.split('.').map(Number).map(x => x.toString(2).padStart(8, '0')).join(''); return /^1*0*$/.test(b) ? b.indexOf('0') < 0 ? 32 : b.indexOf('0') : null; };
  const portNum = p => (PORT_NAMES[String(p).toLowerCase()] !== undefined ? PORT_NAMES[String(p).toLowerCase()] : String(p));

  // destination：/Common/1.2.3.4:443、1.2.3.4%2:https、IPv6 為「位址.埠」、* 或 0.0.0.0:0 為任何
  function parseDest(d) {
    const s = noRd(strip(d));
    if (s === '*:*' || s === 'any') return { ip: 'any', port: '0' };
    let m = s.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\S+)$/);
    if (m) return { ip: m[1] === '0.0.0.0' ? 'any' : m[1], port: portNum(m[2]) };
    m = s.match(/^([0-9a-f:]+)\.(\S+)$/i);
    if (m && m[1].includes(':')) return { ip: m[1] === '::' ? 'any' : m[1], port: portNum(m[2]) };
    return { ip: s, port: '0' };
  }
  function svcOf(proto, ports) {
    const p = String(proto || 'any').toLowerCase();
    const list = (ports || []).filter(x => x && x !== '0');
    if (!list.length) return p === 'any' ? 'any' : p === 'tcp' || p === 'udp' ? `${p}/0-65535` : p;
    if (p === 'any') return list.map(x => `tcp/${x}, udp/${x}`).join(', ');
    if (p === 'tcp' || p === 'udp') return list.map(x => `${p}/${x}`).join(', ');
    return p;
  }

  // 版本只讀 show sys version 的 Version／Build 行（# 開頭的 Oxidized 區段也算）；#TMSH-VERSION 不採用
  function parseDeviceInfo(text, tree) {
    const vm = text.match(/^#?\s*Version\s+(\d+(?:\.\d+){2,3})\s*$/m);
    const g = tops(tree, /^sys global-settings$/)[0];
    const plat = (text.match(/^#?\s*marketing-name\s+(.+)$/m) || [])[1];
    return { vendor: 'F5 BIG-IP', hostname: (g && kidVal(g, /^hostname\s+(\S+)/)) || '-', firmware: vm ? vm[1] : '-', model: plat ? plat.trim() : '-', serial: '-', vdom: [] };
  }

  // 介面：每個 VLAN 一筆，self IP（非 floating 優先）為位址，其餘 self IP 為次要位址；allow-service 放 allowaccess
  function parseInterfaces(tree) {
    const out = [], byName = Object.create(null);
    const get = name => {
      if (!byName[name]) {
        byName[name] = { name, ip: '-', mask: '-', secondaryIps: [], type: 'vlan', vlanId: '-', alias: name, desc: '', status: 'up', mtu: '-', speed: '-',
          mode: '-', vdom: '-', role: 'LAN', allowaccess: '-', selfIps: [] };
        out.push(byName[name]);
      }
      return byName[name];
    };
    tops(tree, /^net vlan \S+$/).forEach(n => {
      const i = get(strip(n.text.split(/\s+/)[2]));
      i.vlanId = kidVal(n, /^tag\s+(\d+)/) || '-';
      i.desc = strip(kidVal(n, /^description\s+(.+)/) || '');
      i.mtu = kidVal(n, /^mtu\s+(\d+)/) || '-';
      i.members = listOf(n, 'interfaces').join(', ');
    });
    const selfs = tops(tree, /^net self \S+$/).map(n => {
      const addr = noRd(kidVal(n, /^address\s+(\S+)/) || '');
      const svc = kid(n, /^allow-service\b/);
      let allow = 'none';
      if (svc) allow = svc.kids.length ? svc.kids.map(k => k.text.replace(/\s*\{\s*\}$/, '')).join(' ') : svc.text.replace(/^allow-service\s*/, '').replace(/^\{|\}$/g, '').trim();
      return { name: strip(n.text.split(/\s+/)[2]), vlan: strip(kidVal(n, /^vlan\s+(\S+)/) || ''), addr, allow,
        floating: /traffic-group-local-only/.test(kidVal(n, /^traffic-group\s+(\S+)/) || 'traffic-group-local-only') ? false : true,
        policy: strip(kidVal(n, /^fw-enforced-policy\s+(\S+)/) || '') };
    });
    selfs.sort((a, b) => a.floating - b.floating).forEach(s => {
      const i = get(s.vlan || s.name);
      const [ip, len] = s.addr.split('/');
      const allowList = i.allowaccess === '-' ? [] : [i.allowaccess];
      if (s.allow !== 'none' && !allowList.includes(s.allow)) allowList.push(s.allow);
      i.allowaccess = allowList.join(' ') || '-';
      i.selfIps.push(s);
      if (!V4.test(ip) && !String(ip).includes(':')) return;
      if (i.ip === '-') { i.ip = ip; i.mask = String(ip).includes(':') ? (len || '128') : lenToMask(len); i.mode = 'static'; i.alias = s.name; }
      else i.secondaryIps.push({ ip, mask: String(ip).includes(':') ? (len || '128') : lenToMask(len) });
    });
    const mg = tree.kids.find(k => /^sys management-ip \S+/.test(k.text));
    if (mg) {
      const [ip, len] = mg.text.split(/\s+/)[2].split('/');
      out.push({ name: 'mgmt', ip, mask: lenToMask(len), secondaryIps: [], type: 'physical', vlanId: '-', alias: 'management-ip', desc: '', status: 'up',
        mtu: '-', speed: '-', mode: 'static', vdom: '-', role: 'MGMT', allowaccess: '-', selfIps: [] });
    }
    return { interfaces: out, selfs };
  }

  // 路由：net route（gw／interface／blackhole，network default）、sys management-route（管理介面）
  function parseRoutes(tree) {
    const out = [];
    let seq = 1;
    const add = (n, mgmt) => {
      const net = noRd(kidVal(n, /^network\s+(\S+)/) || '');
      const dst = /^default$/.test(net) ? '0.0.0.0/0' : /^default-inet6$/.test(net) ? '::/0' : net;
      const gw = noRd(kidVal(n, /^(?:gw|gateway)\s+(\S+)/) || '');
      const bh = n.kids.some(k => k.text === 'blackhole');
      out.push({ type: /^(?:0\.0\.0\.0\/0|::\/0)$/.test(dst) ? 'default' : 'static', id: String(seq++), dst, gateway: gw || '-',
        device: mgmt ? 'mgmt' : bh ? 'Null' : strip(kidVal(n, /^interface\s+(\S+)/) || '-'), distance: '-', priority: '-',
        blackhole: bh ? 'enable' : 'disable', status: 'enable', comment: strip(n.text.split(/\s+/)[2]) + (mgmt ? ' (management-route)' : ''),
        protocol_detail: '-', _vdom: '' });
    };
    tops(tree, /^net route \S+$/).forEach(n => add(n, false));
    tops(tree, /^sys management-route \S+$/).forEach(n => add(n, true));
    return out;
  }

  // 位址物件：ltm node（address／fqdn）、AFM address-list、virtual-address
  function parseAddresses(tree) {
    const out = [];
    const lit = a => { const s = noRd(strip(a)); if (/^any(?:4|6)?$/.test(s)) return null; return s; };
    const one = (name, a, comment) => {
      const s = lit(a); if (!s) return;
      if (/^\d+(?:\.\d+){3}-\d+(?:\.\d+){3}$/.test(s)) { const [x, y] = s.split('-'); out.push({ name, type: 'iprange', subnet: '-', fqdn: '-', startIp: x, endIp: y, iface: '-', members: '-', comment }); return; }
      const subnet = s.includes('/') ? s : s.includes(':') ? `${s}/128` : `${s}/32`;
      out.push({ name, type: 'ipmask', subnet, fqdn: '-', startIp: '-', endIp: '-', iface: '-', members: '-', comment });
    };
    tops(tree, /^ltm node \S+$/).forEach(n => {
      const name = strip(n.text.split(/\s+/)[2]);
      const a = kidVal(n, /^address\s+(\S+)/);
      const fq = kid(n, /^fqdn$/);
      if (a && a !== 'any6') one(name, a, 'ltm node');
      else if (fq) out.push({ name, type: 'fqdn', subnet: '-', fqdn: kidVal(fq, /^name\s+(\S+)/) || '-', startIp: '-', endIp: '-', iface: '-', members: '-', comment: 'ltm node' });
    });
    tops(tree, /^security firewall address-list \S+$/).forEach(n => {
      const name = strip(n.text.split(/\s+/)[3]);
      const mems = listOf(n, 'addresses').map(x => noRd(x)).concat(listOf(n, 'address-lists').map(strip), listOf(n, 'fqdns'));
      out.push({ category: 'address-group', name, type: 'group', subnet: '-', fqdn: '-', startIp: '-', endIp: '-', iface: '-', members: mems.join(', ') || '-', comment: 'AFM address-list' });
    });
    tops(tree, /^ltm virtual-address \S+$/).forEach(n => {
      const a = kidVal(n, /^address\s+(\S+)/);
      if (a && a !== 'any' && a !== 'any6') one(strip(n.text.split(/\s+/)[2]), a, 'ltm virtual-address');
    });
    return out;
  }
  function parsePortLists(tree) {
    const lists = Object.create(null);
    const services = tops(tree, /^security firewall port-list \S+$/).map(n => {
      const name = strip(n.text.split(/\s+/)[3]);
      lists[name] = listOf(n, 'ports');
      return { category: 'group', name, proto: 'GROUP', tcpPorts: lists[name].join(' ') || '-', udpPorts: '-', icmpType: '-', members: lists[name].join(', ') || '-', comment: 'AFM port-list' };
    });
    return { services, lists };
  }

  // pool：名稱 → [{address, port}]
  function parsePools(tree) {
    const pools = Object.create(null);
    tops(tree, /^ltm pool \S+$/).forEach(n => {
      const mems = [];
      const blk = kid(n, /^members$/);
      (blk ? blk.kids : []).forEach(m => {
        const hm = m.text.replace(/\s*\{\s*\}$/, '').match(/^(\S+?)[:.](\d+|[a-z-]+)$/);
        const addr = kidVal(m, /^address\s+(\S+)/) || (hm && /^[\d.]+$/.test(strip(hm[1])) ? strip(hm[1]) : '');
        mems.push({ name: hm ? strip(hm[1]) : strip(m.text).replace(/[:.]\d+$/, ''), address: noRd(addr) || (hm ? strip(hm[1]) : '-'), port: hm ? portNum(hm[2]) : '-' });
      });
      pools[strip(n.text.split(/\s+/)[2])] = mems;
    });
    return pools;
  }

  // virtual server：destination、source、ip-protocol、pool、vlans、snat、iRule、AFM 政策、停用
  function parseVirtuals(tree) {
    return tops(tree, /^ltm virtual \S+$/).map(n => {
      const dest = parseDest(kidVal(n, /^destination\s+(\S+)/) || '*:*');
      const sat = kid(n, /^source-address-translation$/);
      const satType = sat ? kidVal(sat, /^type\s+(\S+)/) : (n.kids.some(k => k.text === 'snatpool' || /^snatpool\s/.test(k.text)) ? 'snat' : '');
      const satPool = sat ? strip(kidVal(sat, /^pool\s+(\S+)/) || '') : strip(kidVal(n, /^snatpool\s+(\S+)/) || '');
      const vl = listOf(n, 'vlans').map(strip);
      return {
        name: strip(n.text.split(/\s+/)[2]), dest, src: noRd(kidVal(n, /^source\s+(\S+)/) || '0.0.0.0/0'),
        proto: kidVal(n, /^ip-protocol\s+(\S+)/) || 'any', pool: strip(kidVal(n, /^pool\s+(\S+)/) || ''),
        vlans: vl, vlansMode: n.kids.some(k => k.text === 'vlans-enabled') ? 'enabled' : vl.length ? 'disabled' : '',
        snat: satType && satType !== 'none' ? (satType === 'automap' ? 'automap' : `snatpool ${satPool}`) : '',
        rules: listOf(n, 'rules').map(strip), policy: strip(kidVal(n, /^fw-enforced-policy\s+(\S+)/) || ''),
        disabled: n.kids.some(k => k.text === 'disabled'), forward: n.kids.some(k => k.text === 'ip-forward' || k.text === 'l2-forward'),
        desc: strip(kidVal(n, /^description\s+(.+)/) || ''),
      };
    });
  }

  function mkPolicy(o) {
    const srcAddr = o.src || 'any', dstAddr = o.dst || 'any';
    const fam = /:/.test(srcAddr + dstAddr) ? 'v6' : (/\d+\.\d+/.test(srcAddr + dstAddr) ? 'v4' : undefined);
    const p = {
      id: o.id, name: o.name, srcIntf: o.srcIntf || 'any', dstIntf: 'any', srcAddr, dstAddr,
      srcAddr4: fam === 'v6' ? '-' : srcAddr, srcAddr6: fam === 'v6' ? srcAddr : (srcAddr === 'any' ? 'any' : '-'),
      dstAddr4: fam === 'v6' ? '-' : dstAddr, dstAddr6: fam === 'v6' ? dstAddr : (dstAddr === 'any' ? 'any' : '-'),
      service: o.service, schedule: 'always', action: o.action, actionRaw: o.actionRaw,
      nat: o.nat || 'disable', ippool: 'disable', poolname: '-', logtraffic: o.log,
      utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
      status: o.status || 'enable', users: '-', groups: '-', comments: o.comments || '', _vdom: '',
    };
    if (fam) p._family = fam;
    if (o.f5) p._f5 = o.f5;
    return p;
  }

  // AFM：policy 與 rule-list 的規則，rule-list 參照就地展開
  function parseAfm(tree, portLists) {
    const ruleLists = Object.create(null), policies = Object.create(null), portListRefs = new Set();
    const rulesOf = blk => (blk ? blk.kids : []).map(r => r);
    tops(tree, /^security firewall rule-list \S+$/).forEach(n => { ruleLists[strip(n.text.split(/\s+/)[3])] = rulesOf(kid(n, /^rules$/)); });
    tops(tree, /^security firewall policy \S+$/).forEach(n => { policies[strip(n.text.split(/\s+/)[3])] = rulesOf(kid(n, /^rules$/)); });
    const side = r => {
      if (!r) return { addrs: [], ports: [], vlans: [] };
      const addrs = listOf(r, 'addresses').map(noRd).concat(listOf(r, 'address-lists').map(strip), listOf(r, 'fqdns'));
      const ports = listOf(r, 'ports').concat(...listOf(r, 'port-lists').map(pl => { portListRefs.add(strip(pl)); return portLists[strip(pl)] || [strip(pl)]; }));
      return { addrs, ports, vlans: listOf(r, 'vlans').map(strip) };
    };
    // 回傳 {rules:[{name, action, proto, src, dst, log, disabled}]}
    const expand = (rules, prefix, seen) => {
      const out = [];
      rules.forEach(r => {
        const rl = kidVal(r, /^rule-list\s+(\S+)/);
        const name = strip(r.text.replace(/\s*\{\s*\}$/, ''));
        if (rl) {
          const key = strip(rl);
          if (!seen.has(key) && ruleLists[key]) { const s2 = new Set(seen); s2.add(key); out.push(...expand(ruleLists[key], `${prefix}${name}/`, s2)); }
          return;
        }
        out.push({ name: prefix + name, action: kidVal(r, /^action\s+(\S+)/) || 'drop', proto: kidVal(r, /^ip-protocol\s+(\S+)/) || 'any',
          src: side(kid(r, /^source$/)), dst: side(kid(r, /^destination$/)), log: kidVal(r, /^log\s+(\S+)/) === 'yes',
          disabled: /^disabled$/.test(kidVal(r, /^status\s+(\S+)/) || '') || r.kids.some(k => k.text === 'disabled'),
          desc: strip(kidVal(r, /^description\s+(.+)/) || '') });
      });
      return out;
    };
    const global = tops(tree, /^security firewall global-rules$/).map(n => strip(kidVal(n, /^enforced-policy\s+(\S+)/) || '')).filter(Boolean);
    const rd = [];
    tops(tree, /^net route-domain \S+$/).forEach(n => { const p = strip(kidVal(n, /^fw-enforced-policy\s+(\S+)/) || ''); if (p) rd.push({ rd: strip(n.text.split(/\s+/)[2]), policy: p }); });
    return { policies, expand, global, rd, portListRefs };
  }

  function buildPolicies(afm, virtuals, selfs) {
    const out = [];
    const act = a => (/^accept/.test(a) ? 'accept' : 'deny');
    // virtual 情境（vs 有 destination 埠時）：只有送到該埠的流量會進入此政策，規則沒寫埠就限定為該埠，
    // 規則的埠不含該埠則永遠不會命中、不列出
    const push = (ctx, ctxName, policyName, dstOverride, vs) => {
      afm.expand(afm.policies[policyName] || [], '', new Set()).forEach((r, i) => {
        if (vs && vs.dest.port !== '0' && r.dst.ports.length && !r.dst.ports.map(portNum).includes(vs.dest.port)) return;
        if (vs && vs.dest.port !== '0') { r = Object.assign({}, r, { proto: r.proto === 'any' ? vs.proto : r.proto, dst: Object.assign({}, r.dst, { ports: [vs.dest.port] }) }); }
        const dstAddr = r.dst.addrs.length ? r.dst.addrs.join(', ') : (dstOverride || 'any');
        out.push(mkPolicy({ id: `afm/${ctx}${ctxName ? '/' + ctxName : ''}/${i + 1}`, name: `${policyName}:${r.name}`,
          srcIntf: r.src.vlans.length ? r.src.vlans.join(', ') : 'any', src: r.src.addrs.join(', ') || 'any', dst: dstAddr,
          service: svcOf(r.proto, r.dst.ports), action: act(r.action), actionRaw: r.action, log: r.log ? 'all' : 'disable',
          status: r.disabled ? 'disable' : 'enable', comments: [`AFM ${ctx}${ctxName ? ' ' + ctxName : ''}`, r.desc].filter(Boolean).join(' · '), f5: 'afm' }));
      });
    };
    afm.global.forEach(p => push('global', '', p));
    afm.rd.forEach(x => push('route-domain', x.rd, x.policy));
    virtuals.filter(v => v.policy).forEach(v => push('virtual', v.name, v.policy, v.dest.ip, v));
    selfs.filter(s => s.policy).forEach(s => push('self', s.name, s.policy, s.addr.split('/')[0]));
    // virtual server 本身：BIG-IP 只處理送到 virtual server 或 self IP 的流量，因此每個 virtual 合成一條允許規則；
    // virtual 有自己的 AFM 政策時以政策規則為準，不另合成（避免與政策的拒絕規則互相判為遮蔽）
    virtuals.filter(v => !v.policy).forEach(v => out.push(mkPolicy({ id: `vs/${v.name}`, name: v.name,
      srcIntf: v.vlansMode === 'enabled' && v.vlans.length ? v.vlans.join(', ') : 'any',
      src: /^0\.0\.0\.0\/0$|^::\/0$/.test(v.src) ? 'any' : v.src, dst: v.dest.ip,
      service: svcOf(v.proto, v.dest.port === '0' ? [] : [v.dest.port]), action: 'accept', actionRaw: v.forward ? 'virtual server (forwarding)' : 'virtual server',
      log: '-', status: v.disabled ? 'disable' : 'enable', nat: v.snat ? 'enable' : 'disable',
      comments: ['virtual server', v.pool ? 'pool ' + v.pool : '', v.snat ? 'SNAT ' + v.snat : '', v.rules.length ? 'iRule ' + v.rules.join(', ') : ''].filter(Boolean).join(' · '), f5: 'virtual' })));
    return out;
  }

  // NAT 頁：virtual server（目的轉換到 pool）、ltm nat（1:1）、ltm snat（來源轉換）
  function parseNat(tree, virtuals, pools) {
    const out = [];
    virtuals.forEach(v => {
      const mems = pools[v.pool] || [];
      const mapPorts = [...new Set(mems.map(m => m.port).filter(p => p && p !== '-' && p !== '0'))];
      out.push({ type: 'vip', name: v.name, vipType: v.forward ? 'forwarding' : 'virtual-server', poolType: 'destination',
        extIp: v.dest.ip, mapIp: mems.map(m => m.address).join(', ') || '-', extIntf: v.vlansMode === 'enabled' ? v.vlans.join(', ') || '-' : '-',
        srcIntf: '-', startIp: '-', endIp: '-', portFwd: v.dest.port !== '0' ? 'enable' : 'disable', extPort: v.dest.port !== '0' ? v.dest.port : '-',
        mapPort: mapPorts.join(', ') || '-', proto: v.proto, status: v.disabled ? 'disable' : 'enable', poolMembers: mems.map(m => m.name).join(', ') || '-',
        comment: [v.pool ? 'pool ' + v.pool : '', v.snat ? 'SNAT ' + v.snat : '', v.rules.length ? 'iRule ' + v.rules.join(', ') : '', v.desc].filter(Boolean).join(' · ') });
    });
    tops(tree, /^ltm nat \S+$/).forEach(n => out.push({ type: 'vip', name: strip(n.text.split(/\s+/)[2]), vipType: 'static', poolType: 'destination',
      extIp: noRd(kidVal(n, /^translation-address\s+(\S+)/) || '-'), mapIp: noRd(kidVal(n, /^originating-address\s+(\S+)/) || '-'),
      extIntf: '-', srcIntf: '-', startIp: '-', endIp: '-', portFwd: 'disable', extPort: '-', mapPort: '-', proto: 'any', status: 'enable', comment: 'ltm nat' }));
    const snatPools = Object.create(null);
    tops(tree, /^ltm snatpool \S+$/).forEach(n => { snatPools[strip(n.text.split(/\s+/)[2])] = listOf(n, 'members').map(x => noRd(strip(x))); });
    tops(tree, /^ltm snat \S+$/).forEach(n => {
      const pool = strip(kidVal(n, /^snatpool\s+(\S+)/) || '');
      const trans = kidVal(n, /^translation\s+(\S+)/);
      out.push({ type: 'ippool', name: strip(n.text.split(/\s+/)[2]), vipType: 'overload', poolType: 'source',
        extIp: listOf(n, 'origins').map(noRd).join(', ') || '-', mapIp: trans ? noRd(strip(trans)) : n.kids.some(k => k.text === 'automap') ? 'automap' : (snatPools[pool] || []).join(', ') || '-',
        extIntf: '-', srcIntf: '-', startIp: '-', endIp: '-', portFwd: 'disable', extPort: '-', mapPort: '-', proto: 'any', status: 'enable', comment: pool ? 'snatpool ' + pool : 'ltm snat' });
    });
    Object.keys(snatPools).forEach(name => out.push({ type: 'ippool', name, vipType: 'overload', poolType: 'source', extIp: '-', mapIp: snatPools[name].join(', ') || '-',
      extIntf: '-', srcIntf: '-', startIp: '-', endIp: '-', portFwd: 'disable', extPort: '-', mapPort: '-', proto: 'any', status: 'enable', comment: 'ltm snatpool' }));
    return out;
  }

  // 本機帳號：partition-access 的 role、shell
  function parseUsers(tree) {
    return tops(tree, /^auth user \S+$/).map(n => {
      const roles = [];
      const pa = kid(n, /^partition-access$/);
      (pa ? pa.kids : []).forEach(k => { const r = kidVal(k, /^role\s+(\S+)/); if (r) roles.push(r); });
      const role = roles.includes('admin') ? 'admin' : roles[0] || (kidVal(n, /^role\s+(\S+)/) || '-');
      return { name: strip(n.text.split(/\s+/)[2]), role, type: role === 'admin' ? 'admin' : 'local', shell: kidVal(n, /^shell\s+(\S+)/) || '-',
        status: 'enable', desc: strip(kidVal(n, /^description\s+(.+)/) || '') };
    });
  }

  function parseSnmp(tree) {
    const s = tops(tree, /^sys snmp$/)[0];
    if (!s) return null;
    const comms = [], v3 = [];
    const cb = kid(s, /^communities$/);
    (cb ? cb.kids : []).forEach(c => { const nm = kidVal(c, /^community-name\s+(\S+)/); if (nm) comms.push({ name: strip(nm), permission: kidVal(c, /^access\s+(\S+)/) === 'rw' ? 'rw' : 'ro', allowedHosts: [kidVal(c, /^source\s+(\S+)/)].filter(x => x && x !== 'default'), events: '-', status: 'enable' }); });
    const ub = kid(s, /^users$/);
    (ub ? ub.kids : []).forEach(u => v3.push({ name: kidVal(u, /^username\s+(\S+)/) || strip(u.text), auth: kidVal(u, /^auth-protocol\s+(\S+)/) || '-', priv: kidVal(u, /^privacy-protocol\s+(\S+)/) || '-' }));
    return { enabled: true, agent: { name: '-', description: '-', location: kidVal(s, /^sys-location\s+(.+)/) || '-', contact: kidVal(s, /^sys-contact\s+(.+)/) || '-', version: comms.length ? ['v2c'] : v3.length ? ['v3'] : [] },
      communities: comms, v3users: v3, trapServers: [] };
  }

  // 管理介面來源限制：sys httpd／sshd 的 allow；沒有 allow 行時為 null（不評估）
  function parseMgmtPlane(tree) {
    const allowOf = re => { const n = tops(tree, re)[0]; if (!n) return null; const k = kid(n, /^allow\b/); return k ? listOf(n, 'allow').map(x => noRd(x)) : null; };
    return { httpdAllow: allowOf(/^sys httpd$/), sshdAllow: allowOf(/^sys sshd$/) };
  }
  function parseLogServers(tree) {
    const s = tops(tree, /^sys syslog$/)[0];
    const rs = s && kid(s, /^remote-servers$/);
    const syslog = (rs ? rs.kids : []).map(r => ({ server: kidVal(r, /^host\s+(\S+)/) || '-', iface: '-', port: kidVal(r, /^remote-port\s+(\d+)/) || '514',
      facility: '-', level: '-', protocol: 'UDP', status: 'enable' }));
    return { syslog, fortianalyzer: [], netflow: [], logForward: [] };
  }

  // 與入口頁 isBigipConf()、app.js FW_VENDOR_SIGS.bigip、去識別化 VENDOR_SIGS.bigip 相同（至少 2 項）
  const SIGS = [/^#TMSH-VERSION: /m, /^ltm (?:virtual|pool|node) \S+ \{/m, /^net self \S+ \{/m, /^net vlan \S+ \{/m, /^sys global-settings \{/m,
    /^auth user \S+ \{/m, /^sys (?:httpd|sshd|snmp) \{/m, /^sys management-ip /m, /Sys::Version/];
  function detect(text) { const t = String(text || ''); return SIGS.filter(re => re.test(t)).length >= 2; }

  function parse(text) {
    const t = String(text || '').replace(/\r\n/g, '\n');
    const tree = buildTree(t);
    const { interfaces, selfs } = parseInterfaces(tree);
    const { services, lists } = parsePortLists(tree);
    const virtuals = parseVirtuals(tree);
    const pools = parsePools(tree);
    const afm = parseAfm(tree, lists);
    const policies = buildPolicies(afm, virtuals, selfs);
    const nat = parseNat(tree, virtuals, pools);
    // 已使用（_inUse，analyzeUnusedObjects() 視為使用中）：pool 成員的 node、virtual 的 virtual-address、
    // 生效中 AFM 規則引用的 port-list（規則的服務已展開成埠號，名稱不會出現在規則欄位）
    const usedNodes = new Set(Object.keys(pools).flatMap(k => pools[k].map(m => m.name)));
    const vips = new Set(virtuals.map(v => v.dest.ip));
    const addresses = parseAddresses(tree);
    addresses.forEach(a => { if ((a.comment === 'ltm node' && usedNodes.has(a.name)) || (a.comment === 'ltm virtual-address' && vips.has(a.subnet.split('/')[0]))) a._inUse = true; });
    services.forEach(sv => { if (afm.portListRefs.has(sv.name)) sv._inUse = true; });
    return {
      vendor: 'F5 BIG-IP',
      deviceInfo: parseDeviceInfo(t, tree),
      interfaces,
      policies,
      routes: parseRoutes(tree),
      ha: null, nat, vpn: [],
      addresses, services,
      users: parseUsers(tree), schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      dhcp: null, dns: null, snmp: parseSnmp(tree), logservers: parseLogServers(tree),
      wwan: null, wlan: null,
      mgmtPlane: parseMgmtPlane(tree),
      f5: { afm: Object.keys(afm.policies).length > 0, virtuals: virtuals.length, pools: Object.keys(pools).length,
        irules: tops(tree, /^ltm rule \S+/).length },
    };
  }

  return { parse, detect, maskToLen };
})();
