// ═══════════════════════════════════════════════════════════════════════════
// Cisco IOS／IOS-XE 路由器當防火牆（XN139）
// 語法依 Batfish（Apache-2.0）projects/batfish/src/test/resources/org/batfish/grammar/cisco/testconfigs 的
// ios-acl*、ios-zone-security、ios-xe-zone-default-behavior、ios-policy-map-inspect、ios-class-map-inspect、ios-nat-* 等測試設定對照。
//
// 解析：介面（位址、secondary、ip access-group、zone-member security、ip nat inside／outside）、
//   ACL（編號與具名、standard／extended、object-group network／service、埠運算子、established）、
//   Zone-Based Firewall（zone-pair、policy-map type inspect、class-map type inspect）、
//   NAT（ip nat inside source list … interface／pool、static）、靜態路由、本機帳號、管理服務（http server、line vty）。
// 查詢語意（nf，與 EdgeRouter／VyOS 1.3 相同的鏈模型）：
//   forward＝介面 in ACL → ZBF → 出口介面 out ACL；input（目的是路由器自己）＝介面 in ACL。
//   綁定的 ACL 有內容時結尾為隱含拒絕；綁定但沒有定義或沒有任何項目的 ACL 等同全部放行（IOS 行為）。
//   ZBF：同區域互通；不同區域沒有 zone-pair、或區域成員與沒有區域的介面之間為拒絕；class-default 沒寫動作為 drop。
//   self zone（XN140，依 Cisco ZBF 設計指南 98628）：到路由器本身預設放行，只受「區域 → self」的 zone-pair 限制（input → zbf-self），
//   路由器自己發出的流量（self → 區域）不評估。class-map 的 match class-map 依序展開。
//   class-map 所引用 ACL 裡的 deny 項目代表「不屬於這個 class」，這裡以該 policy-map 的 class-default 動作近似
//   （只有一個 class 時相同；後面還有其他 class 會比對同一流量時可能不同，規則標 _zbfApprox）。
// 不解析：IPv6 ACL、反射式 ACL、時間條件、IPsec／DMVPN、route-map 條件的 NAT（條件標為無法判斷）。
// ═══════════════════════════════════════════════════════════════════════════
const CiscoIOSParser = (() => {
  // IOS ACL 可用的埠名稱（Cisco IOS 指令參考的 TCP／UDP 埠關鍵字）
  const PORT_NAMES = { bgp: 179, chargen: 19, cmd: 514, daytime: 13, discard: 9, domain: 53, echo: 7, exec: 512, finger: 79, ftp: 21, 'ftp-data': 20, gopher: 70,
    hostname: 101, ident: 113, irc: 194, klogin: 543, kshell: 544, login: 513, lpd: 515, msdp: 639, nntp: 119, 'pim-auto-rp': 496, pop2: 109, pop3: 110, smtp: 25,
    sunrpc: 111, syslog: 514, tacacs: 49, talk: 517, telnet: 23, time: 37, uucp: 540, whois: 43, www: 80, biff: 512, bootpc: 68, bootps: 67, dnsix: 195,
    isakmp: 500, 'non500-isakmp': 4500, 'mobile-ip': 434, nameserver: 42, 'netbios-dgm': 138, 'netbios-ns': 137, 'netbios-ss': 139, ntp: 123, rip: 520,
    snmp: 161, snmptrap: 162, tftp: 69, who: 513, xdmcp: 177, ssh: 22, https: 443, ldap: 389 };
  // class-map「match protocol」常見的應用名稱對應到協定／埠；其餘名稱原樣保留（查詢時無法判斷）
  const APP_SVC = { tcp: 'tcp', udp: 'udp', icmp: 'icmp', http: 'tcp/80', https: 'tcp/443', dns: 'tcp/53, udp/53', ssh: 'tcp/22', telnet: 'tcp/23', ftp: 'tcp/21',
    smtp: 'tcp/25', pop3: 'tcp/110', imap: 'tcp/143', ntp: 'udp/123', snmp: 'udp/161', tftp: 'udp/69', syslog: 'udp/514' };
  const IP_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
  const ipInt = s => { const p = String(s).split('.').map(Number); return IP_RE.test(String(s)) && p.every(n => n <= 255) ? ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0 : null; };
  const maskLen = m => { const n = ipInt(m); if (n === null) return null; const inv = (~n) >>> 0; return (inv & (inv + 1)) === 0 ? 32 - Math.round(Math.log2(inv + 1)) : null; };
  // 萬用遮罩（wildcard）：連續才換成前綴長度
  const wildLen = w => { const n = ipInt(w); return n !== null && (n & (n + 1)) === 0 ? 32 - Math.round(Math.log2(n + 1)) : null; };
  const port = p => /^\d+$/.test(p) ? p : (PORT_NAMES[String(p).toLowerCase()] !== undefined ? String(PORT_NAMES[String(p).toLowerCase()]) : null);

  // 依縮排把設定切成頂層區塊：[{head, body:[…]}]
  function blocks(text) {
    const out = [];
    let cur = null;
    String(text || '').replace(/\r\n?/g, '\n').split('\n').forEach(raw => {
      const line = raw.replace(/\s+$/, '');
      if (!line.trim() || /^\s*!/.test(line)) return;
      if (/^\s/.test(line)) { if (cur) cur.body.push(line.trim()); return; }
      cur = { head: line, body: [] };
      out.push(cur);
    });
    return out;
  }

  // 位址條件：any｜host A｜A W（extended 為萬用遮罩）｜object-group 名稱。回傳 {addr, n（用掉幾個詞）, unk}
  function addrSpec(t, i, std) {
    const w = t[i];
    if (w === undefined) return null;
    if (w === 'any' || w === 'any4') return { addr: 'any', n: 1 };
    if (w === 'host') return IP_RE.test(t[i + 1] || '') ? { addr: t[i + 1] + '/32', n: 2 } : null;
    if (w === 'object-group') return t[i + 1] ? { addr: t[i + 1], n: 2 } : null;
    if (!IP_RE.test(w)) return null;
    if (IP_RE.test(t[i + 1] || '')) {
      const l = wildLen(t[i + 1]);
      // 不連續的萬用遮罩無法換成網段：保留原文，查詢時為無法判斷
      return l === null ? { addr: `${w} wildcard ${t[i + 1]}`, n: 2, unk: true } : { addr: `${w}/${l}`, n: 2 };
    }
    return std ? { addr: w + '/32', n: 1 } : null;
  }
  // 埠條件：eq p [p…]｜range a b｜gt p｜lt p｜neq p。回傳 {ports:[…], n} 或 null
  function portSpec(t, i) {
    const op = t[i];
    if (op === 'eq' || op === 'neq') {
      const ps = [];
      let j = i + 1;
      while (t[j] !== undefined && port(t[j]) !== null && !['established', 'log', 'log-input'].includes(t[j])) ps.push(port(t[j++]));
      if (!ps.length) return null;
      if (op === 'eq') return { ports: ps, n: j - i };
      const p = +ps[0];
      return { ports: [p > 1 ? `1-${p - 1}` : '', p < 65535 ? `${p + 1}-65535` : ''].filter(Boolean), n: 2 };
    }
    if (op === 'range') { const a = port(t[i + 1]), b = port(t[i + 2]); return a !== null && b !== null ? { ports: [`${a}-${b}`], n: 3 } : null; }
    if (op === 'gt' || op === 'lt') { const p = port(t[i + 1]); if (p === null) return null; return { ports: [op === 'gt' ? `${+p + 1}-65535` : `1-${+p - 1}`], n: 2 }; }
    return null;
  }
  // 一條 ACL 項目（去掉行號後的詞）→ {action, proto, src, dst, service, established, unk} 或 null
  function aclEntry(words, std) {
    const t = words.slice();
    const action = t.shift();
    if (action !== 'permit' && action !== 'deny') return null;
    if (std) {
      const s = addrSpec(t, 0, true);
      return s ? { action, src: s.addr, dst: 'any', service: 'all', established: false, unk: !!s.unk } : null;
    }
    let proto = t.shift(), svcGroup = '';
    if (proto === 'object-group') { svcGroup = t.shift(); proto = 'ip'; }
    if (proto === undefined) return null;
    let i = 0;
    const s = addrSpec(t, i, false);
    if (!s) return null;
    i += s.n;
    const sp = portSpec(t, i);  // 來源埠條件只跳過不比對
    if (sp) i += sp.n;
    const d = addrSpec(t, i, false);
    if (!d) return null;
    i += d.n;
    const dp = portSpec(t, i);
    if (dp) i += dp.n;
    const rest = t.slice(i);
    const p = String(proto).toLowerCase();
    let service;
    if (svcGroup) service = svcGroup;
    else if (p === 'ip') service = 'all';
    else if (p === 'tcp' || p === 'udp') service = dp ? dp.ports.map(x => `${p}/${x}`).join(', ') : p;
    else if (p === 'icmp') service = 'icmp';
    else service = /^\d+$/.test(p) ? `proto-${p}` : p;
    return { action, src: s.addr, dst: d.addr, service, established: rest.includes('established'), log: rest.some(x => /^log/.test(x)),
      unk: !!(s.unk || d.unk || rest.includes('time-range') || rest.includes('reflect')), srcPort: !!sp };
  }

  function parse(text) {
    const bl = blocks(text);
    const first = re => { for (const b of bl) { const m = b.head.match(re); if (m) return m; } return null; };
    const hostname = (first(/^hostname\s+(\S+)/) || [])[1] || '-';
    const verM = String(text || '').match(/Cisco IOS(?:[ -]XE)? Software.*?Version\s+([^\s,]+)/i) || first(/^version\s+(\S+)/);
    const isXe = /IOS[ -]XE/i.test(String(text || '')) || (verM && /^(?:1[6-9]|[2-9]\d)\./.test(verM[1]));

    // ── 物件群組 ──
    const addresses = [], services = [];
    bl.forEach(b => {
      let m = b.head.match(/^object-group network (\S+)/);
      if (m) {
        const mem = [];
        b.body.forEach(l => {
          const t = l.split(/\s+/);
          if (t[0] === 'host' && IP_RE.test(t[1] || '')) mem.push(t[1] + '/32');
          else if (t[0] === 'group-object' && t[1]) mem.push(t[1]);
          else if (t[0] === 'range' && IP_RE.test(t[1] || '') && IP_RE.test(t[2] || '')) mem.push(`${t[1]}-${t[2]}`);
          else if (IP_RE.test(t[0]) && IP_RE.test(t[1] || '')) { const l2 = maskLen(t[1]); if (l2 !== null) mem.push(`${t[0]}/${l2}`); }
          else if (/^\d{1,3}(\.\d{1,3}){3}\/\d+$/.test(t[0])) mem.push(t[0]);
        });
        addresses.push({ name: m[1], type: 'group', category: 'group', subnet: '-', members: mem.join(', '), color: '0' });
        return;
      }
      m = b.head.match(/^object-group service (\S+)/);
      if (m) {
        const tcp = [], udp = [], other = [];
        b.body.forEach(l => {
          const t = l.split(/\s+/), p = t[0];
          if (p === 'tcp' || p === 'udp' || p === 'tcp-udp') {
            const ps = portSpec(t, 1), list = ps ? ps.ports : ['1-65535'];
            if (p !== 'udp') tcp.push(...list);
            if (p !== 'tcp') udp.push(...list);
          } else if (p && p !== 'description' && p !== 'group-object') other.push(p);
        });
        services.push({ name: m[1], proto: tcp.length && udp.length ? 'TCP/UDP' : tcp.length ? 'TCP' : udp.length ? 'UDP' : (other[0] || 'IP').toUpperCase(),
          port: tcp.concat(udp).join(',') || '-', tcpPorts: tcp.join(',') || '-', udpPorts: udp.join(',') || '-', type: 'group', color: '0', members: '-', refOnly: false });
      }
    });

    // ── ACL ──（Object.create(null)：名稱來自設定檔）
    const acls = Object.create(null);
    const aclAdd = (name, std, line) => {
      const t = line.trim().split(/\s+/);
      if (/^\d+$/.test(t[0])) t.shift();
      if (t[0] === 'remark') { (acls[name] = acls[name] || { std, entries: [], remark: '' }).remark = t.slice(1).join(' '); return; }
      const e = aclEntry(t, std);
      const a = acls[name] = acls[name] || { std, entries: [], remark: '' };
      if (e) { e.remark = a.remark; e.seq = a.entries.length + 1; a.entries.push(e); a.remark = ''; }
    };
    bl.forEach(b => {
      let m = b.head.match(/^ip access-list (standard|extended) (\S+)/);
      if (m) { acls[m[2]] = acls[m[2]] || { std: m[1] === 'standard', entries: [], remark: '' }; b.body.forEach(l => aclAdd(m[2], m[1] === 'standard', l)); return; }
      m = b.head.match(/^access-list (\d+) (.+)$/);
      if (m) { const n = +m[1]; aclAdd(m[1], (n >= 1 && n <= 99) || (n >= 1300 && n <= 1999), m[2]); }
    });

    // ── 介面 ──
    const interfaces = [], binds = [];
    bl.forEach(b => {
      const m = b.head.match(/^interface (\S+)/);
      if (!m) return;
      const name = m[1];
      const o = { name, ip: '-', mask: '-', secondaryIps: [], type: /^Loopback/i.test(name) ? 'loopback' : /^Tunnel/i.test(name) ? 'tunnel' : /^Vlan|^BVI|^BDI/i.test(name) ? 'vlan' : /\.\d+$/.test(name) ? 'vlan' : 'physical',
        vlanId: '-', alias: name, desc: '', status: 'up', mtu: '-', speed: '-', mode: 'static', vdom: '-', role: '-', allowaccess: '-', zone: '' };
      b.body.forEach(l => {
        let x;
        if ((x = l.match(/^ip address (\d{1,3}(?:\.\d{1,3}){3}) (\d{1,3}(?:\.\d{1,3}){3})( secondary)?/))) { if (x[3]) o.secondaryIps.push({ ip: x[1], mask: x[2] }); else { o.ip = x[1]; o.mask = x[2]; } }
        else if (/^ip address (dhcp|negotiated)/.test(l)) o.mode = 'dhcp';
        else if ((x = l.match(/^description (.+)$/))) o.desc = x[1];
        else if (l === 'shutdown') o.status = 'down';
        else if ((x = l.match(/^encapsulation dot1q (\d+)/i))) o.vlanId = x[1];
        else if ((x = l.match(/^ip access-group (\S+) (in|out)/))) binds.push({ iface: name, acl: x[1], dir: x[2] });
        else if ((x = l.match(/^zone-member security (\S+)/))) o.zone = x[1];
        else if ((x = l.match(/^ip nat (inside|outside)$/))) { o.natSide = x[1]; o.role = x[1] === 'outside' ? 'WAN' : 'LAN'; }
        else if ((x = l.match(/^(?:ip )?vrf forwarding (\S+)/))) o.vrf = x[1];
      });
      interfaces.push(o);
    });
    const ifByName = n => interfaces.find(i => i.name === n);

    // ── Zone-Based Firewall ──
    const classMaps = Object.create(null), policyMaps = Object.create(null), zonePairs = [];
    bl.forEach(b => {
      let m = b.head.match(/^class-map type inspect (?:(match-any|match-all) )?(\S+)/);
      if (m) {
        const cm = classMaps[m[2]] = { mode: m[1] || 'match-all', acls: [], protos: [], subs: [] };
        b.body.forEach(l => { let x; if ((x = l.match(/^match access-group (?:name )?(\S+)/))) cm.acls.push(x[1]); else if ((x = l.match(/^match protocol (\S+)/))) cm.protos.push(x[1]);
          else if ((x = l.match(/^match class-map (\S+)/))) cm.subs.push(x[1]); });
        return;
      }
      m = b.head.match(/^policy-map type inspect (\S+)/);
      if (m) {
        const pm = policyMaps[m[1]] = { classes: [] };
        let cur = null;
        b.body.forEach(l => {
          const x = l.match(/^class (?:type inspect )?(\S+)/);
          if (x) { cur = { name: x[1], action: '' }; pm.classes.push(cur); return; }
          if (cur && /^(inspect|pass|drop)\b/.test(l) && !cur.action) cur.action = l.split(/\s+/)[0];
        });
        return;
      }
      m = b.head.match(/^zone-pair security (\S+) source (\S+) destination (\S+)/);
      if (m) { const sp = b.body.map(l => l.match(/^service-policy type inspect (\S+)/)).find(Boolean); zonePairs.push({ name: m[1], src: m[2], dst: m[3], pm: sp ? sp[1] : '' }); }
    });
    const hasZbf = interfaces.some(i => i.zone);
    // 巢狀 class-map（match class-map X，Cisco ZBF 設計指南的 self zone 範例）：依序併入被引用者的 ACL 與協定，深度上限 4、防循環
    const cmFlat = (name, seen) => {
      const cm = classMaps[name];
      if (!cm) return null;
      const out = { mode: cm.mode, acls: cm.acls.slice(), protos: cm.protos.slice(), nested: cm.subs.length > 0 };
      cm.subs.forEach(sn => { if (seen.length >= 4 || seen.includes(sn)) return; const sub = cmFlat(sn, seen.concat([sn])); if (sub) { out.acls.push(...sub.acls); out.protos.push(...sub.protos); } });
      return out;
    };

    // ── 規則 ──
    const base = o => Object.assign({ srcIntf: '-', dstIntf: '-', srcAddr: 'any', dstAddr: 'any', srcAddr4: 'any', dstAddr4: 'any', srcAddr6: '-', dstAddr6: '-',
      service: 'all', schedule: 'always', nat: 'disable', ippool: 'disable', poolname: '-', logtraffic: 'disable', utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' },
      status: 'enable', users: '-', groups: '-', comments: '', _vdom: '', connState: [], _family: 'v4' }, o);
    const fromEntry = (e, o) => base(Object.assign({ srcAddr: e.src, dstAddr: e.dst, srcAddr4: e.src, dstAddr4: e.dst, service: e.service, logtraffic: e.log ? 'all' : 'disable',
      comments: [e.remark, e.srcPort ? '(source port condition not evaluated)' : ''].filter(Boolean).join(' '), connState: e.established ? ['established'] : [], _iosUnk: e.unk || undefined }, o));
    const policies = [], rules = [];
    let pid = 0;
    // 介面 ACL：只收有綁到介面的 ACL（NAT、vty、route-map 用的 ACL 不是過濾規則）
    const bound = [...new Set(binds.map(b => b.acl))];
    bound.forEach(name => {
      const a = acls[name];
      if (!a || !a.entries.length) return;  // 沒定義或空的 ACL＝全部放行，不建立鏈
      const key = 'acl:' + name;
      a.entries.forEach(e => {
        const p = fromEntry(e, { id: ++pid, name, chain: name, ruleNum: String(e.seq), action: e.action === 'permit' ? 'accept' : 'deny' });
        policies.push(p);
        rules.push(Object.assign({}, p, { _chain: key, _mtAct: p.action === 'accept' ? 'accept' : 'drop', _nonterminal: false }));
      });
      rules.push(base({ id: `${key}/implicit`, name: `${name} implicit deny`, action: 'deny', _chain: key, _mtAct: 'drop', _nonterminal: false, _nfDefaultRule: true }));
    });
    binds.forEach((b, i) => {
      const a = acls[b.acl];
      if (!a || !a.entries.length) return;
      const jump = chain => rules.push(base({ id: `bind/${i + 1}/${chain}`, name: `${b.iface} access-group ${b.acl} ${b.dir}`, action: 'deny', [b.dir === 'out' ? 'dstIntf' : 'srcIntf']: b.iface,
        _chain: chain, _mtAct: 'jump', _jumpTarget: 'acl:' + b.acl, _nonterminal: true, _mtHasMatch: true }));
      if (b.dir === 'in') { jump('fwd-in'); jump('input'); } else jump('fwd-out');
    });
    // ZBF：每個 zone-pair 一條鏈；zbf 鏈依「來源介面→目的介面」跳進去
    if (hasZbf) {
      const zoneIfs = z => interfaces.filter(i => i.zone === z).map(i => i.name);
      zonePairs.forEach(zp => {
        // 路由器自己發出的流量（source self）不評估；到路由器本身（destination self）由 zbf-self 鏈處理（XN140）
        if (zp.src === 'self') return;
        const pm = policyMaps[zp.pm], key = 'zp:' + zp.name;
        const act = a => (a === 'inspect' || a === 'pass') ? 'accept' : 'deny';
        const dflt = pm ? act((pm.classes.find(c => c.name === 'class-default') || {}).action || 'drop') : 'deny';
        const add = (o, e) => {
          const p = (e ? fromEntry(e, o) : base(o));
          Object.assign(p, { id: ++pid, name: zp.name, chain: `zone-pair ${zp.name}`, srcIntf: zp.src, dstIntf: zp.dst });
          policies.push(p);
          rules.push(Object.assign({}, p, { srcIntf: '-', dstIntf: '-', _chain: key, _mtAct: p.action === 'accept' ? 'accept' : 'drop', _nonterminal: false }));
        };
        (pm ? pm.classes : []).forEach(c => {
          if (c.name === 'class-default') return;
          const cm = cmFlat(c.name, [c.name]);
          if (!cm) return;
          const a = act(c.action || 'drop');
          cm.acls.forEach(an => ((acls[an] || {}).entries || []).forEach(e =>
            add({ ruleNum: `${c.name}/${an}/${e.seq}`, action: e.action === 'permit' ? a : dflt, _zbfApprox: e.action !== 'permit' || (cm.mode === 'match-all' && cm.acls.length + cm.protos.length > 1) || undefined }, e)));
          if (!cm.acls.length) cm.protos.forEach(pr => add({ ruleNum: `${c.name}/protocol ${pr}`, action: a, service: APP_SVC[pr.toLowerCase()] || pr }));
        });
        add({ ruleNum: 'class-default', action: dflt, comments: 'class-default' });
        // 到路由器本身（XN140）：來源區域的介面進來即跳到該 zone-pair；沒有 zone-pair 指向 self 的區域與沒有區域的介面落到鏈尾放行
        if (zp.dst === 'self') {
          zoneIfs(zp.src).forEach(si => rules.push(base({ id: `zbf-self/${zp.name}/${si}`, name: `zone-pair ${zp.name}`, action: 'deny', srcIntf: si,
            _chain: 'zbf-self', _mtAct: 'jump', _jumpTarget: key, _nonterminal: true, _mtHasMatch: true })));
          return;
        }
        zoneIfs(zp.src).forEach(si => zoneIfs(zp.dst).forEach(di => rules.push(base({ id: `zbf/${zp.name}/${si}/${di}`, name: `zone-pair ${zp.name}`, action: 'deny', srcIntf: si, dstIntf: di,
          _chain: 'zbf', _mtAct: 'jump', _jumpTarget: key, _nonterminal: true, _mtHasMatch: true }))));
      });
      // 不同區域之間沒有 zone-pair、或區域成員與沒有區域的介面之間：拒絕
      interfaces.forEach(si => interfaces.forEach(di => {
        if (si === di || si.zone === di.zone) return;
        if (si.zone && di.zone && zonePairs.some(z => z.src === si.zone && z.dst === di.zone)) return;
        rules.push(base({ id: `zbf/none/${si.name}/${di.name}`, name: si.zone && di.zone ? `no zone-pair ${si.zone} → ${di.zone}` : 'zone member ↔ non-zone interface', action: 'deny',
          srcIntf: si.name, dstIntf: di.name, _chain: 'zbf', _mtAct: 'drop', _nonterminal: false, _nfDefaultRule: true }));
      }));
    }

    // ── NAT ──
    const nat = [], pools = Object.create(null);
    bl.forEach(b => { const m = b.head.match(/^ip nat pool (\S+) (\d{1,3}(?:\.\d{1,3}){3}) (\d{1,3}(?:\.\d{1,3}){3})/); if (m) pools[m[1]] = { start: m[2], end: m[3] }; });
    bl.forEach(b => {
      let m = b.head.match(/^ip nat inside source (list|route-map) (\S+) (interface|pool) (\S+)( overload)?/);
      if (m) {
        const pool = m[3] === 'pool' ? pools[m[4]] : null;
        nat.push({ type: 'ippool', name: `inside source ${m[1]} ${m[2]}`, vipType: 'overload', poolType: m[5] ? 'overload' : 'one-to-one', extIp: '-', mapIp: m[3] === 'interface' ? 'interface' : (pool ? pool.start : m[4]),
          extIntf: m[3] === 'interface' ? m[4] : '-', srcIntf: '-', startIp: pool ? pool.start : '-', endIp: pool ? pool.end : '-', portFwd: 'disable', extPort: '-', mapPort: '-', proto: 'all', status: 'enable',
          comment: b.head, iosNat: { kind: m[3], acl: m[1] === 'list' ? m[2] : '', cond: m[1] === 'route-map', iface: m[3] === 'interface' ? m[4] : '', start: pool ? pool.start : '', end: pool ? pool.end : '',
            // NAT 用的 ACL 項目（多台路徑查詢判斷來源是否轉換）；ACL 沒有定義＝null（不轉換）
            entries: m[1] === 'list' && acls[m[2]] ? acls[m[2]].entries.map(e => ({ action: e.action, src: e.src, dst: e.dst, unk: !!e.unk })) : null } });
        return;
      }
      m = b.head.match(/^ip nat inside source static (?:(tcp|udp) )?(\d{1,3}(?:\.\d{1,3}){3})(?: (\d+))? (?:(\d{1,3}(?:\.\d{1,3}){3})|interface (\S+))(?: (\d+))?/);
      if (m) {
        // m[2] 內部位址、m[3] 內部埠、m[4] 外部位址或 m[5] 外部介面、m[6] 外部埠
        const gif = m[5] ? ifByName(m[5]) : null, global = m[4] || (gif && gif.ip !== '-' ? gif.ip : '');
        nat.push({ type: 'vip', name: `static ${m[2]}${m[3] ? ':' + m[3] : ''}`, vipType: 'static-nat', extIp: global || '-', mapIp: m[2], extIntf: m[5] || '-', portFwd: m[1] ? 'enable' : 'disable',
          extPort: m[6] || '-', mapPort: m[3] || '-', proto: m[1] || '-', status: 'enable', comment: b.head, iosNat: m[1] ? null : { kind: 'static', local: m[2], global } });
      }
    });

    // ── 路由 ──
    const routes = [];
    bl.forEach(b => {
      const m = b.head.match(/^ip route (?:vrf (\S+) )?(\d{1,3}(?:\.\d{1,3}){3}) (\d{1,3}(?:\.\d{1,3}){3}) (.+)$/);
      if (!m) return;
      const t = m[4].split(/\s+/);
      let device = '-', gateway = '-', i = 0;
      if (!IP_RE.test(t[0])) { device = t[0]; i = 1; }
      if (IP_RE.test(t[i] || '')) { gateway = t[i]; i++; }
      const dist = /^\d+$/.test(t[i] || '') ? t[i] : '1';
      routes.push({ id: String(routes.length + 1), type: m[2] === '0.0.0.0' && m[3] === '0.0.0.0' ? 'default' : 'static', dst: `${m[2]} ${m[3]}`, device, gateway, distance: dist, priority: '1',
        status: 'enable', blackhole: /^Null0$/i.test(device) ? 'enable' : 'disable', comment: '-', vrf: m[1] || 'global', vdom: 'global' });
    });

    // ── 帳號與管理服務 ──
    const users = [];
    bl.forEach(b => { const m = b.head.match(/^username (\S+)(.*)$/); if (m) { const pv = (m[2].match(/privilege (\d+)/) || [])[1]; users.push({ name: m[1], role: pv === '15' ? 'admin' : (pv ? 'privilege ' + pv : 'user'), type: 'local', groups: [] }); } });
    const has = re => bl.some(b => re.test(b.head));
    const vty = bl.filter(b => /^line vty\b/.test(b.head));
    // transport input 沒寫時依版本不同（舊版為全部），只在明寫時判斷；每一組 vty 都有 access-class in 才算已限制來源
    const tin = vty.map(b => (b.body.find(l => /^transport input\b/.test(l)) || '').replace(/^transport input\s*/, ''));
    const vtyAcl = vty.length > 0 && vty.every(b => b.body.some(l => /^access-class \S+ in\b/.test(l)));
    const svc = (name, kind, p, on, limited) => ({ name, kind, port: p, enabled: on, listenAddrs: [], limited: !!limited });
    const rtRouter = { services: [
      svc('ip http server', 'rt-web', 80, has(/^ip http server\b/), has(/^ip http access-class\b/)),
      svc('ip http secure-server', 'rt-web', 443, has(/^ip http secure-server\b/), has(/^ip http access-class\b/)),
      svc('vty ssh', 'admin-ssh', 22, tin.some(x => /\b(ssh|all)\b/.test(x)), vtyAcl),
      svc('vty telnet', 'admin-telnet', 23, tin.some(x => /\b(telnet|all)\b/.test(x)), vtyAcl),
    ].filter(s => s.enabled && !s.limited), dns: null, upnp: null };

    return {
      vendor: 'Cisco IOS',
      deviceInfo: { vendor: 'Cisco IOS', hostname, firmware: verM ? verM[1] : '-', model: '-', serial: '-', vdom: [], iosXe: !!isXe },
      interfaces, policies,
      nf: { rules, defaults: {}, forward: hasZbf ? ['fwd-in', 'zbf', 'fwd-out'] : ['fwd-in', 'fwd-out'], input: hasZbf && rules.some(r => r._chain === 'zbf-self') ? ['input', 'zbf-self'] : ['input'] },
      rtRouter, routes, ha: null, nat, vpn: [], addresses, services, users, schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      snmp: null, logservers: null, dns: null, dhcp: null, wwan: null, wlan: null,
      iosScope: { acls: Object.keys(acls).length, boundAcls: bound.length, zonePairs: zonePairs.length, zbf: hasZbf },
    };
  }

  // 路由器（不是交換器）且有過濾或 NAT 設定：沒有任何 switchport，並有 ZBF、ip nat inside source、ip inspect 或綁到介面的 ACL
  function detect(text) {
    const t = String(text || '');
    if (!/^interface \S+/m.test(t) || /^\s*switchport\b/m.test(t) || /^ASA Version|^: Saved/m.test(t)) return false;
    if (!/^(?:version \d|hostname \S|ip route |line vty)/m.test(t)) return false;
    return /^zone(?:-pair)? security \S+/m.test(t) || /^ip nat inside source /m.test(t) || /^ip inspect name /m.test(t) || /^\s+ip access-group \S+ (?:in|out)/m.test(t);
  }

  return { parse, detect };
})();
