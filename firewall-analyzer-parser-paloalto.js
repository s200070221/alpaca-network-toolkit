// ═══ parser-paloalto.js ═══
/**
 * Palo Alto Networks PAN-OS Configuration Parser
 * Supports:
 *   - XML running config (show config running / exported XML)
 *   - "set" CLI format (show config | match "set ")
 */
const PaloAltoParser = (() => {

  // ─── XML helpers ──────────────────────────────────────────────────────────
  // 這份是三個 parser module 中最簡化的版本：無巢狀同名標籤防護、無 HTML 實體解碼
  // （見 SophosParser 開頭註解說明整體差異背景）。維持原樣，未經真實 PaloAlto XML
  // 樣本驗證前不擅自加上其他兩份才有的防護邏輯。
  function xv(xml, tag) {
    const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i');
    return (xml.match(re) || [])[1]?.trim() || '';
  }

  function xva(xml, tag) {
    const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'gi');
    const results = []; let m;
    while ((m = re.exec(xml)) !== null) results.push(m[1].trim());
    return results;
  }

  function xblks(xml, tag) {
    const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'gi');
    const results = []; let m;
    while ((m = re.exec(xml)) !== null) results.push({ _outer: m[0], _inner: m[1] });
    return results;
  }

  // Depth-aware top-level entry extractor (handles nested <entry> tags correctly)
  // Also handles self-closing <entry name="..." /> which must not affect depth
  function xentriesTop(xml) {
    const results = [];
    // Pre-process: normalise self-closing <entry .../> so they don't interfere with depth counting
    const xmlNorm = xml.replace(/<entry\s+name="([^"]+)"([^>]*)\/>/gi,
      (m,n,attrs) => `<entry name="${n}"${attrs}></entry>`);
    const startRe = /<entry\s+name="([^"]+)"[^>]*>/gi;
    let sm;
    while ((sm = startRe.exec(xmlNorm)) !== null) {
      const name = sm[1];
      // Skip if this is an already-converted self-closing (immediately followed by </entry>)
      const immediate = xmlNorm.slice(sm.index + sm[0].length, sm.index + sm[0].length + 8);
      // Check if this is self-closing (converted: empty content)
      let depth = 1, pos = sm.index + sm[0].length;
      const nestedRe = /<\/?entry\b/gi;
      nestedRe.lastIndex = pos;
      let nm;
      while ((nm = nestedRe.exec(xmlNorm)) !== null && depth > 0) {
        if (!nm[0].startsWith('</')) depth++;
        else { depth--; if (depth === 0) break; }
      }
      if (depth > 0 || !nm) continue;
      const inner = xmlNorm.slice(pos, nm.index);
      // Skip truly empty entries (were self-closing) unless at top-level call
      const outerEnd = nm.index + nm[0].length + 1;
      results.push({ _outer: xmlNorm.slice(sm.index, outerEnd), _inner: inner, _name: name });
      startRe.lastIndex = outerEnd;
    }
    return results;
  }

  function xname(blk) {
    const m = blk._outer.match(/name="([^"]+)"/);
    return m ? m[1] : xv(blk._inner, 'name') || '';
  }

  function xlist(xml, tag) {
    // Returns all <member> inside <tag>
    const inner = xv(xml, tag);
    if (!inner) return [];
    return xva(inner, 'member').filter(Boolean);
  }

  // ─── Set-format helpers ───────────────────────────────────────────────────
  function setVal(text, key) {
    const re = new RegExp(`^set\\s+${key.replace(/\s+/g,'\\s+')}\\s+(.+)$`, 'im');
    return (text.match(re) || [])[1]?.trim() || '';
  }

  function setLines(text, prefix) {
    const re = new RegExp(`^set\\s+${prefix.replace(/\s+/g,'\\s+')}\\s+(.+)$`, 'gim');
    const results = []; let m;
    while ((m = re.exec(text)) !== null) results.push(m[1].trim());
    return results;
  }

  // Detect format
  function isXml(text) { return text.trimStart().startsWith('<'); }

  // ─── Device info ──────────────────────────────────────────────────────────
  function parseDeviceInfo(text) {
    const info = { vendor: 'PaloAlto', hostname: '-', firmware: '-', model: '-', serial: '-', vdom: [] };
    if (isXml(text)) {
      // <deviceconfig><system><hostname>
      const sys = xv(text, 'system');
      info.hostname = xv(sys || text, 'hostname') || '-';
      info.firmware  = xv(sys || text, 'sw-version') || xv(sys || text, 'version') || '-';
      info.model     = xv(sys || text, 'platform-family') || xv(sys || text, 'model') || '-';
      info.serial    = xv(sys || text, 'serial') || '-';
      // VSYSes
      const vsys = xblks(text, 'vsys');
      info.vdom = vsys.map(v => xname(v)).filter(Boolean);
    } else {
      info.hostname = setVal(text, 'deviceconfig system hostname') || '-';
      info.firmware  = (text.match(/sw-version\s+(\S+)/i) || [])[1] || '-';
      info.model     = (text.match(/platform-family\s+(\S+)/i) || [])[1] || '-';
    }
    return info;
  }

  // ─── Interfaces ───────────────────────────────────────────────────────────
  function parseInterfaces(text) {
    const ifaces = [];

    if (isXml(text)) {
      // Ethernet — look in <network> block to avoid matching vsys member refs
      const networkBlock = xv(text, 'network') || text;
      const ifnetBlock = xv(networkBlock, 'interface') || xv(text, 'interface');
      // In network/interface block, ethernet entries are <ethernet><entry name="X">...</entry></ethernet>
      // So we iterate entries within the ethernet container
      const ethContainer = xv(ifnetBlock || text, 'ethernet') || ifnetBlock || text;
      // Use depth-aware entry extraction to correctly capture all fields including <vsys>
      xentriesTop(ethContainer).forEach(eth => {
        const name = eth._name || xname(eth);
        const layer3 = xv(eth._inner, 'layer3');
        // Try <member> in <ip>, <ip-address> tag, or <entry name="IP/prefix"/> format
        const ipList = xlist(layer3 || eth._inner, 'ip');
        const ipFromTag = xv(xv(layer3||eth._inner,'ip'),'ip-address') || '';
        // Format: <ip><entry name="192.168.1.1/24"/></ip> — IP as entry name。官方 PAN-OS
        // 文件確認一個 L3 介面可有多筆 <entry name="X"/>（「A single Layer 3 interface
        // supports multiple static IPv4 and static IPv6 addresses」）；entry 為 self-closing
        // 標籤，xva()/xlist() 認得的是 <tag>...</tag> 配對格式抓不到，故直接對 <ip> 區塊
        // 內容做全域 name 屬性擷取，取得完整清單（官方 PAN-OS 文件確認一個 L3 介面可有
        // 多筆位址，2026-08-17 從「僅取第一筆次要IP」擴大為完整收集全部次要IP）
        const ipEntryAll = [...xv(layer3||eth._inner,'ip').matchAll(/<entry\s+name="([\d.]+\/\d+)"/g)].map(m=>m[1]);
        // Format: <ip><entry name="192.168.1.1/24"/></ip> — IP as entry name
        const ipEntryM = (layer3||eth._inner).match(/<ip>\s*<entry\s+name="([\d.]+\/\d+)"/);
        // 主要/次要IP 一律取自同一個來源清單（依既有優先序挑出第一個有命中的來源），
        // 避免混用不同 XML 格式變體的清單造成資料錯置
        const activeIpList = ipList.length ? ipList : (ipFromTag ? [ipFromTag] : (ipEntryAll.length ? ipEntryAll : (ipEntryM ? [ipEntryM[1]] : [])));
        const ipRaw = activeIpList[0] || '';
        const ip = ipRaw;
        const [ipAddr, prefix] = ip ? ip.split('/') : ['-', '-'];
        // 次要IP（2026-08-17 擴大為完整收集，非僅取第一筆）
        const secondaryIps = activeIpList.slice(1).map(raw => {
          const [a, p] = raw.split('/');
          return { ip: a || '-', mask: p ? prefixToMask(parseInt(p)) : '-' };
        });
        const mtu   = xv(eth._inner, 'mtu') || '1500';
        const link  = xv(eth._inner, 'link-state') || 'up';
        const itype = xv(eth._inner, 'layer3') ? 'physical' : xv(eth._inner, 'layer2') ? 'layer2' : xv(eth._inner, 'tap') ? 'tap' : 'physical';

        ifaces.push({
          name, alias: xv(eth._inner, 'comment') || '-',
          ip: ipAddr || '-',
          mask: prefix ? prefixToMask(parseInt(prefix)) : '-',
          secondaryIps,
          type: itype, vlanId: '-',
          vdom: xv(eth._inner, 'vsys') || 'vsys1',
          _vdom: xv(eth._inner, 'vsys') || 'vsys1',
          role: guessRole(name, xv(eth._inner, 'zone')),
          status: link, speed: xv(eth._inner, 'link-speed') || '-',
          mtu, macaddr: '-', mode: 'static',
          gwdetect: '-', desc: xv(eth._inner, 'comment') || '-',
          allowaccess: xv(eth._inner, 'interface-management-profile') || '-',
          interface: '-', gateway: '-',
        });

        // Sub-interfaces
        xblks(eth._inner, 'units').forEach(sub => {
          const sname = xname(sub) || `${name}.${xv(sub._inner,'tag')}`;
          const sipRaw = xlist(sub._inner, 'ip')[0] || xv(xv(sub._inner,'ip'),'ip-address') || '';
          const sip = sipRaw;
          const [sipAddr, spfx] = sip ? sip.split('/') : ['-','-'];
          ifaces.push({
            name: sname, alias: xv(sub._inner,'comment')||'-',
            ip: sipAddr||'-', mask: spfx?prefixToMask(parseInt(spfx)):'-',
            type:'vlan', vlanId: xv(sub._inner,'tag')||'-',
            vdom: xv(sub._inner,'vsys')||'vsys1',
            _vdom: xv(sub._inner,'vsys')||'vsys1',
            role: guessRole(sname, xv(sub._inner,'zone')),
            status:'up', speed:'-', mtu:'1500', macaddr:'-', mode:'static',
            gwdetect:'-', desc: xv(sub._inner,'comment')||'-',
            allowaccess: xv(sub._inner,'interface-management-profile')||'-',
            interface: name, gateway:'-',
          });
        });
      });

      // Loopback
      xblks(xv(text,'interface')||text, 'loopback').forEach(lo => {
        const name = xname(lo);
        const ip = xlist(lo._inner,'ip')[0]||'';
        const [ipA, pfx] = ip.split('/');
        ifaces.push({
          name, alias:'-', ip:ipA||'-', mask:pfx?prefixToMask(parseInt(pfx)):'-',
          type:'loopback', vlanId:'-', vdom:'vsys1',
          role:'MGMT', status:'up', speed:'-', mtu:'1500',
          macaddr:'-', mode:'static', gwdetect:'-', desc:'-',
          allowaccess:'-', interface:'-', gateway:'-',
        });
      });

      // Tunnel
      xblks(xv(text,'interface')||text, 'tunnel').forEach(tn => {
        const name = xname(tn);
        ifaces.push({
          name, alias:'-', ip:'-', mask:'-',
          type:'tunnel', vlanId:'-', vdom:'vsys1',
          role:'VPN', status:'up', speed:'-', mtu:'1500',
          macaddr:'-', mode:'static', gwdetect:'-', desc:'-',
          allowaccess:'-', interface:'-', gateway:'-',
        });
      });

      // VLAN interfaces
      xblks(xv(text,'interface')||text, 'vlan').forEach(vl => {
        const name = xname(vl);
        if (!name || ifaces.find(i=>i.name===name)) return;
        const ip = xlist(vl._inner,'ip')[0]||'';
        const [ipA, pfx] = ip.split('/');
        ifaces.push({
          name, alias:xv(vl._inner,'comment')||'-',
          ip:ipA||'-', mask:pfx?prefixToMask(parseInt(pfx)):'-',
          type:'vlan', vlanId:xv(vl._inner,'tag')||'-',
          vdom:'vsys1', role:guessRole(name),
          status:'up', speed:'-', mtu:'1500',
          macaddr:'-', mode:'static', gwdetect:'-',
          desc:xv(vl._inner,'comment')||'-',
          allowaccess:'-', interface:'-', gateway:'-',
        });
      });

    } else {
      // set format
      const ifNames = new Set();
      const ifRe = /^set\s+network\s+interface\s+(\S+)\s+(\S+)/gim;
      let m;
      while ((m = ifRe.exec(text)) !== null) ifNames.add(`${m[1]} ${m[2]}`);

      ifNames.forEach(key => {
        const [type, name] = key.split(' ');
        const prefix = `network interface ${type} ${name}`;
        const ip  = setVal(text, `${prefix} layer3 ip`) ||
                    setVal(text, `${prefix} ip`) || '-';
        const [ipA, pfx] = ip.includes('/') ? ip.split('/') : [ip, ''];
        ifaces.push({
          name, alias: setVal(text, `${prefix} comment`) || '-',
          ip: ipA || '-', mask: pfx ? prefixToMask(parseInt(pfx)) : '-',
          type: type === 'ethernet' ? 'physical' : type,
          vlanId: setVal(text, `${prefix} tag`) || '-',
          vdom: setVal(text, `${prefix} vsys`) || 'vsys1',
          role: guessRole(name),
          status: 'up', speed: setVal(text, `${prefix} link-speed`) || '-',
          mtu: setVal(text, `${prefix} mtu`) || '1500',
          macaddr:'-', mode:'static', gwdetect:'-',
          desc: setVal(text, `${prefix} comment`) || '-',
          allowaccess: setVal(text, `${prefix} interface-management-profile`) || '-',
          interface:'-', gateway:'-',
        });
      });
    }

    return ifaces;
  }

  // ─── Security policies ────────────────────────────────────────────────────
  function parsePolicies(text, vsysXml, vsysName, addrTypeMap) {
    const policies = [];

    if (isXml(text)) {
      // <security><rules><entry name="...">
      // Use vsysXml when provided (multi-vsys); fall back to full text for single-vsys
      const vsysContent = vsysXml !== undefined ? vsysXml : (xv(xv(text,'vsys')||'','entry') || text);
      const secBlock = xv(vsysContent, 'security') || (vsysXml!==undefined?'':xv(text, 'security')) || (vsysXml===undefined?text:'');
      xblks(secBlock, 'entry').forEach((entry, idx) => {
        const inner = entry._inner;
        const name  = xname(entry) || `Rule-${idx+1}`;
        const from  = xlist(inner,'from').join(', ') || 'any';
        const to    = xlist(inner,'to').join(', ')   || 'any';
        const src   = xlist(inner,'source').join(', ')      || 'any';
        const dst   = xlist(inner,'destination').join(', ') || 'any';
        const svc   = xlist(inner,'service').join(', ')     || 'any';
        const app   = xlist(inner,'application').join(', ') || 'any';
        const action= xv(inner,'action') || 'deny';
        const dis   = entry._outer.includes('disabled="yes"') || xv(inner,'disabled') === 'yes';
        const srcAddrSplit = _splitAddr(src, addrTypeMap);
        const dstAddrSplit = _splitAddr(dst, addrTypeMap);

        policies.push({
          id:       String(idx+1),
          name,
          srcIntf:  from,
          dstIntf:  to,
          srcAddr:  src,
          dstAddr:  dst,
          srcAddr4: srcAddrSplit.v4,
          srcAddr6: srcAddrSplit.v6,
          dstAddr4: dstAddrSplit.v4,
          dstAddr6: dstAddrSplit.v6,
          service:  svc,
          schedule: xv(inner,'schedule') || 'any',
          action:   action === 'allow' ? 'accept' : 'deny',
          nat:      xv(inner,'nat') || 'disable',
          ippool:   'disable',
          poolname: '-',
          logtraffic: xv(xv(inner,'log-setting')||inner,'log-end')||xv(inner,'log-end') === 'yes' ? 'enable' : 'disable',
          logstart:   xv(inner,'log-start') === 'yes' ? 'enable' : 'disable',
          utm: {
            av:        xv(inner,'virus') || xv(xv(inner,'profile-setting'),'virus') || '-',
            webfilter: xv(inner,'url-filtering') || xv(xv(inner,'profile-setting'),'url-filtering') || '-',
            ips:       xv(inner,'vulnerability') || xv(xv(inner,'profile-setting'),'vulnerability') || '-',
            ssl:       xv(inner,'file-blocking') || '-',
            appctrl:   app !== 'any' ? app.slice(0,40) : '-',
          },
          status:   dis ? 'disable' : 'enable',
          comments: xv(inner,'description') || '-',
          users:    xlist(inner,'user').join(', ') || '-',
          groups:   xlist(xv(inner,'source-user'),'entry').join(', ') || xva(inner,'source-user').join(', ') || '-',
          app,
          _vdom: vsysName || 'vsys1',
        });
      });
    } else {
      // set format: set security rules <name> ...
      const ruleNames = new Set();
      const ruleRe = /^set\s+security\s+rules\s+("?[^"\s]+"?)/gim;
      let m;
      while ((m = ruleRe.exec(text)) !== null) ruleNames.add(m[1].replace(/"/g,''));

      let idx = 1;
      ruleNames.forEach(name => {
        const p = `security rules "${name}"`;
        const p2 = `security rules ${name}`;
        const gv = k => setVal(text, `${p} ${k}`) || setVal(text, `${p2} ${k}`);
        const action = gv('action') || 'deny';
        const srcStr = gv('source') || 'any';
        const dstStr = gv('destination') || 'any';
        const srcAddrSplit = _splitAddr(srcStr, addrTypeMap);
        const dstAddrSplit = _splitAddr(dstStr, addrTypeMap);
        policies.push({
          id: String(idx++), name,
          srcIntf:  gv('from') || 'any',
          dstIntf:  gv('to')   || 'any',
          srcAddr:  srcStr,
          dstAddr:  dstStr,
          srcAddr4: srcAddrSplit.v4,
          srcAddr6: srcAddrSplit.v6,
          dstAddr4: dstAddrSplit.v4,
          dstAddr6: dstAddrSplit.v6,
          service:  gv('service')     || 'any',
          schedule: gv('schedule')    || 'any',
          action:   action === 'allow' ? 'accept' : 'deny',
          nat: 'disable', ippool:'disable', poolname:'-',
          logtraffic: gv('log-end') || 'yes',
          logstart:   gv('log-start') || 'no',
          utm: {
            av:        gv('profile-setting virus') || '-',
            webfilter: gv('profile-setting url-filtering') || '-',
            ips:       gv('profile-setting vulnerability') || '-',
            ssl:       '-',
            appctrl:   gv('application') || '-',
          },
          status:   gv('disabled') === 'yes' ? 'disable' : 'enable',
          comments: gv('description') || '-',
          users: gv('source-user') || '-', groups: '-',
        });
      });
    }
    return policies;
  }

  // ─── Routes ───────────────────────────────────────────────────────────────
  function parseRoutes(text) {
    const routes = [];

    if (isXml(text)) {
      // Virtual routers
      xblks(text, 'virtual-router').forEach(vr => {
        const vrName = xname(vr);
        // Static
        xblks(xv(vr._inner,'routing-table')||vr._inner, 'entry').forEach((e, i) => {
          const inner = e._inner;
          const dst = xv(inner,'destination') || '-';
          routes.push({
            type: 'static', id: `${vrName}-${i+1}`,
            dst, gateway: xv(inner,'nexthop')||xv(inner,'ip-address')||'-',
            device: xv(inner,'interface') || '-',
            distance: xv(inner,'admin-dist') || xv(inner,'metric') || '10',
            priority: xv(inner,'priority') || '0',
            weight: '0',
            comment: '-',
            status: e._outer.includes('disabled="yes"') ? 'disable' : 'enable',
            blackhole: xv(inner,'nexthop-type') === 'discard' ? 'enable' : 'disable',
            vrf: vrName,
          });
        });
        // OSPF
        const ospf = xv(vr._inner,'ospf');
        if (ospf && xv(ospf,'enable') !== 'no') {
          routes.push({
            type:'ospf', id:`${vrName}-ospf`, dst:'dynamic', gateway:'-', device:'-',
            routerId: xv(ospf,'router-id') || '-',
            ospfNetworks: xblks(ospf,'entry').map(a=>xname(a)).join('; ') || '-',
            distance: xv(ospf,'external-preference') || '110',
            priority:'-', weight:'-', comment:`VR: ${vrName}`, status:'enable',
            protocol_detail: `Router-ID: ${xv(ospf,'router-id')||'-'}  VR: ${vrName}`,
          });
        }
        // BGP
        const bgp = xv(vr._inner,'bgp');
        if (bgp && xv(bgp,'enable') !== 'no') {
          routes.push({
            type:'bgp', id:`${vrName}-bgp`, dst:'dynamic', gateway:'-', device:'-',
            as: xv(bgp,'local-as') || '-',
            routerId: xv(bgp,'router-id') || '-',
            distance:'20', priority:'-', weight:'-', comment:`VR: ${vrName}`, status:'enable',
            protocol_detail: `AS: ${xv(bgp,'local-as')||'-'}  Router-ID: ${xv(bgp,'router-id')||'-'}`,
          });
        }
        // RIP
        const rip = xv(vr._inner,'rip');
        if (rip && xv(rip,'enable') !== 'no') {
          routes.push({
            type:'rip', id:`${vrName}-rip`, dst:'dynamic', gateway:'-', device:'-',
            distance:'120', priority:'-', weight:'-', comment:`VR: ${vrName}`, status:'enable', protocol_detail:`RIP  VR: ${vrName}`,
          });
        }
      });
    } else {
      // set format
      const routeRe = /^set\s+network\s+virtual-router\s+(\S+)\s+routing-table\s+(?:ip\s+)?static-route\s+(\S+)\s+/gim;
      const seen = new Map(); let m, idx=1;
      while ((m = routeRe.exec(text)) !== null) {
        const key = `${m[1]}_${m[2]}`;
        if (seen.has(key)) continue; seen.set(key,true);
        const vr=m[1], rname=m[2];
        const p = `network virtual-router ${vr} routing-table ip static-route ${rname}`;
        const p2 = `network virtual-router ${vr} routing-table static-route ${rname}`;
        const gv = k => setVal(text,`${p} ${k}`) || setVal(text,`${p2} ${k}`);
        routes.push({
          type:'static', id:String(idx++),
          dst: gv('destination') || '-',
          gateway: gv('nexthop ip-address') || gv('nexthop') || '-',
          device:  gv('interface') || '-',
          distance:gv('admin-dist') || '10',
          priority:gv('priority')   || '0',
          weight:'0', comment:'-',
          status: gv('disabled') === 'yes' ? 'disable' : 'enable',
          blackhole: gv('nexthop-type') === 'discard' ? 'enable' : 'disable',
          vrf: vr,
        });
      }
    }
    return routes;
  }

  // ─── VPN ─────────────────────────────────────────────────────────────────
  function parseVPN(text) {
    const vpns = [];

    if (isXml(text)) {
      // IKE gateways
      const ikeGws = {};
      xblks(xv(text,'ike')||text, 'gateway').forEach(gw => {
        const name = xname(gw);
        ikeGws[name] = gw._inner;
      });

      // IPSec tunnels
      xblks(xv(text,'ipsec')||text, 'tunnel').forEach(tn => {
        const name  = xname(tn);
        const inner = tn._inner;
        const gwName = xv(xv(inner,'ike')||inner,'gateway') || xv(inner,'ike-gateway') || '-';
        const gwInner= ikeGws[gwName] || '';
        const cryptoP2 = xv(inner,'ike-crypto-profile') || xv(xv(inner,'esp')||inner,'ike-crypto-profile') || '-';
        const localSub  = xlist(xv(inner,'tunnel-interface')||inner,'ip')[0] || '-';

        vpns.push({
          type: 'ipsec-p1', name,
          mode:        xv(gwInner,'version') || 'ikev1',
          remote:      xv(gwInner,'peer-ip-value') || xv(gwInner,'peer-address') || '-',
          iface:       xv(gwInner,'interface') || xv(inner,'tunnel-interface') || '-',
          ikeVer:      xv(gwInner,'version') === 'ikev2' ? '2' : '1',
          authMethod:  xv(xv(gwInner,'authentication')||gwInner,'pre-shared-key') ? 'psk' : 'certificate',
          peertype:    xv(gwInner,'peer-id-type') || '-',
          proposal:    xv(gwInner,'ike-crypto-profile') || '-',
          dhgrp:       xv(gwInner,'dh-group') || '-',
          lifetime:    xv(gwInner,'lifetime') || '28800',
          natTraversal:xv(gwInner,'nat-traversal') === 'enable' ? 'enable' : 'disable',
          dpd:         xv(gwInner,'dead-peer-detection') ? 'enable' : '-',
          dpdInterval: xv(xv(gwInner,'dead-peer-detection')||'','interval') || '-',
          localId:     xv(xv(gwInner,'local-id')||gwInner,'id') || '-',
          peerId:      xv(xv(gwInner,'peer-id')||gwInner,'id') || '-',
          xauthType:   '-',
          cert:        xv(xv(gwInner,'authentication')||gwInner,'certificate') || '-',
          monitorConn: xv(inner,'tunnel-monitor') || '-',
          autoNeg:     xv(inner,'auto-key') ? 'enable' : '-',
          status:      'enable',
          phase2: [{
            name:      name+'-P2',
            phase1:    name,
            proposal:  cryptoP2,
            pfs:       xv(inner,'pfs') || 'enable',
            dhgrp:     xv(xv(inner,'pfs')||inner,'dh-group') || '-',
            lifetime:  xv(inner,'lifetime') || '3600',
            replay:    'enable',
            localSub,
            remoteSub: xv(inner,'remote-network') || '-',
            localAddr: '-', remoteAddr: '-', autoNeg: '-', comment: '-',
          }],
        });
      });

      // GlobalProtect (SSL VPN)
      const gp = xv(text,'global-protect');
      if (gp) {
        xblks(gp,'gateway').forEach(gwb => {
          const gname = xname(gwb);
          const inner = gwb._inner;
          // Split tunnel: client-config > configs > entry > split-tunneling > access-route（含多筆 <member>）
          // xlist()/xv() 是全文 regex 搜尋，不受巢狀深度影響，故不需逐層展開
          const splitRoutes = xlist(inner,'access-route');
          vpns.push({
            type: 'ssl-vpn',
            name: `GlobalProtect: ${gname}`,
            iface: xv(inner,'interface') || '-',
            remote: '-',
            port: xv(inner,'ssl-tls-service-profile') || '443',
            tunPort: '-',
            addr: xlist(inner,'ip-pool').join(', ') || '-',
            dns1: xv(inner,'dns-server-primary') || '-',
            dns2: xv(inner,'dns-server-secondary') || '-',
            wins1: '-',
            ipPool: xlist(inner,'ip-pool').join(', ') || '-',
            algorithm: xv(inner,'ssl-tls-service-profile') || 'tls-profile',
            dtls: xv(inner,'enable-udp-mode') || 'disable',
            authTimeout: '-',
            ikeVer: '-', authMethod: 'certificate',
            proposal: '-', dhgrp: '-', phase2: [], status: 'enable',
            splitTunnel: splitRoutes.length ? 'enable' : '-',
            splitTunnelRoutingAddr: splitRoutes.join(', ') || '-',
          });
        });
      }

    } else {
      // set format
      const ikeGwNames = new Set();
      const ikeRe = /^set\s+network\s+ike\s+gateway\s+("?[^"\s]+"?)/gim;
      let m;
      while ((m = ikeRe.exec(text)) !== null) ikeGwNames.add(m[1].replace(/"/g,''));

      const tunnelNames = new Set();
      const tnRe = /^set\s+network\s+ipsec\s+tunnel\s+("?[^"\s]+"?)/gim;
      while ((m = tnRe.exec(text)) !== null) tunnelNames.add(m[1].replace(/"/g,''));

      tunnelNames.forEach(name => {
        const p = `network ipsec tunnel "${name}"`;
        const p2 = `network ipsec tunnel ${name}`;
        const gv = k => setVal(text,`${p} ${k}`) || setVal(text,`${p2} ${k}`);
        const gwName = gv('auto-key ike-gateway entry') || gv('ike-gateway') || '-';
        const gp = `network ike gateway "${gwName}"`;
        const gp2 = `network ike gateway ${gwName}`;
        const ggv = k => setVal(text,`${gp} ${k}`) || setVal(text,`${gp2} ${k}`);

        vpns.push({
          type: 'ipsec-p1', name,
          mode:        ggv('version') === 'ikev2' ? 'ikev2' : 'main',
          remote:      ggv('peer-address ip') || ggv('peer-ip-value') || '-',
          iface:       ggv('interface') || gv('tunnel-interface') || '-',
          ikeVer:      ggv('version') === 'ikev2' ? '2' : '1',
          authMethod:  ggv('pre-shared-key key') ? 'psk' : 'certificate',
          peertype:    ggv('peer-id type') || '-',
          proposal:    ggv('ike-crypto-profile') || '-',
          dhgrp:       '-', lifetime: '-',
          natTraversal:ggv('nat-traversal enable') || '-',
          dpd: ggv('dead-peer-detection') || '-', dpdInterval: '-',
          localId: ggv('local-id id') || '-',
          peerId:  ggv('peer-id id') || '-',
          xauthType: '-', cert: ggv('certificate') || '-',
          monitorConn: gv('tunnel-monitor enable') || '-',
          autoNeg: 'enable', status: 'enable',
          phase2: [{
            name: name+'-P2', phase1: name,
            proposal: gv('auto-key ike-crypto-profile') || '-',
            pfs: 'enable', dhgrp: '-', lifetime: '-', replay: 'enable',
            localSub:  gv('auto-key proxy-id entry local') || '-',
            remoteSub: gv('auto-key proxy-id entry remote') || '-',
            localAddr:'-', remoteAddr:'-', autoNeg:'-', comment:'-',
          }],
        });
      });

      // GlobalProtect split-tunnel（set 格式，先前完全無解析路徑）
      // 已查證語法（Palo Alto 官方 KnowledgeBase kA10g000000ClTm）：
      // set [vsys <vsys>] global-protect global-protect-gateway "<Gateway>" remote-user-tunnel-configs "<Config>" split-tunneling access-route <CIDR>
      const gpGwNames = new Set();
      const gpGwRe = /^set\s+(?:vsys\s+\S+\s+)?global-protect\s+global-protect-gateway\s+("?[^"\s]+"?)/gim;
      while ((m = gpGwRe.exec(text)) !== null) gpGwNames.add(m[1].replace(/"/g,''));

      gpGwNames.forEach(gname => {
        const escName = gname.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const routeRe = new RegExp(`^set\\s+(?:vsys\\s+\\S+\\s+)?global-protect\\s+global-protect-gateway\\s+"?${escName}"?\\s+remote-user-tunnel-configs\\s+\\S+\\s+split-tunneling\\s+access-route\\s+(\\S+)`, 'gim');
        const routes = [];
        let rm;
        while ((rm = routeRe.exec(text)) !== null) routes.push(rm[1]);
        vpns.push({
          type: 'ssl-vpn',
          name: `GlobalProtect: ${gname}`,
          iface: '-', remote: '-', port: '443', tunPort: '-',
          addr: '-', dns1: '-', dns2: '-', wins1: '-', ipPool: '-',
          algorithm: '-', dtls: '-', authTimeout: '-',
          ikeVer: '-', authMethod: 'certificate',
          proposal: '-', dhgrp: '-', phase2: [], status: 'enable',
          splitTunnel: routes.length ? 'enable' : '-',
          splitTunnelRoutingAddr: routes.join(', ') || '-',
        });
      });
    }

    return vpns;
  }

  // ─── Address objects ──────────────────────────────────────────────────────
  function parseAddressObjects(text, vsysXml, vsysName) {
    const objs = [];

    if (isXml(text)) {
      const aoContent = vsysXml !== undefined ? vsysXml : text;
      xblks(xv(aoContent,'address')||xv(text,'address')||aoContent, 'entry').forEach(e => {
        const name  = xname(e);
        const inner = e._inner;
        const ip6   = xv(inner,'ip-netmask');
        const range = xv(inner,'ip-range');
        const fqdn  = xv(inner,'fqdn');
        const wild  = xv(inner,'ip-wildcard');
        let type='ipmask', subnet=ip6||'-', startIp='-', endIp='-';
        if (range) { type='iprange'; startIp=range.split('-')[0].trim(); endIp=range.split('-')[1]?.trim()||'-'; subnet='-'; }
        else if (fqdn) { type='fqdn'; subnet='-'; }
        else if (wild) { type='wildcard'; subnet=wild; }
        objs.push({
          category:'address', name, type, subnet, fqdn: fqdn||'-',
          startIp, endIp, wildcard: wild||'-', iface:'-', color:'0',
          comment: xv(inner,'description') || xv(inner,'tag') || '-',
          _vdom: vsysName || 'vsys1',
        });
      });

      // Address groups
      // When vsysXml is provided, don't fall back to full text (prevents vsys bleed-through)
      xblks(xv(aoContent,'address-group')||(vsysXml!==undefined?'':xv(text,'address-group'))||'', 'entry').forEach(e => {
        const name = xname(e);
        const mems = xlist(e._inner,'static').concat(xlist(e._inner,'dynamic-filter'));
        objs.push({
          category:'address-group', name, type:'group',
          members: mems.join(', ')||'-',
          comment: xv(e._inner,'description')||'-', color:'0',
          _vdom: vsysName || 'vsys1',
        });
      });

    } else {
      const addrNames = new Set();
      const re = /^set\s+address\s+("?[^"\s]+"?)\s+/gim;
      let m;
      while ((m = re.exec(text)) !== null) addrNames.add(m[1].replace(/"/g,''));
      addrNames.forEach(name => {
        const p = `address "${name}"`;
        const p2 = `address ${name}`;
        const gv = k => setVal(text,`${p} ${k}`) || setVal(text,`${p2} ${k}`);
        const ip = gv('ip-netmask'), rng = gv('ip-range'), fq = gv('fqdn');
        let type='ipmask', subnet=ip||'-', startIp='-', endIp='-';
        if (rng) { type='iprange'; startIp=rng.split('-')[0]?.trim(); endIp=rng.split('-')[1]?.trim(); subnet='-'; }
        else if (fq) { type='fqdn'; subnet='-'; }
        objs.push({
          category:'address', name, type, subnet, fqdn:fq||'-',
          startIp, endIp, wildcard:'-', iface:'-', color:'0',
          comment: gv('description') || '-',
        });
      });

      // Groups
      const grpNames = new Set();
      const grpRe = /^set\s+address-group\s+("?[^"\s]+"?)\s+/gim;
      while ((m = grpRe.exec(text)) !== null) grpNames.add(m[1].replace(/"/g,''));
      grpNames.forEach(name => {
        const p = `address-group "${name}"`;
        const p2 = `address-group ${name}`;
        const mems = (setVal(text,`${p} static`) || setVal(text,`${p2} static`)).split(/\s+/).filter(Boolean);
        objs.push({
          category:'address-group', name, type:'group',
          members: mems.join(', ')||'-',
          comment: setVal(text,`${p} description`) || '-', color:'0',
        });
      });
    }
    return objs;
  }

  // ─── Service objects ──────────────────────────────────────────────────────
  function parseServiceObjects(text, vsysXml, vsysName) {
    const svcs = [];

    if (isXml(text)) {
      const soContent = vsysXml !== undefined ? vsysXml : text;
      xblks(xv(soContent,'service')||xv(text,'service')||soContent, 'entry').forEach(e => {
        const name  = xname(e);
        const inner = e._inner;
        const proto = xv(inner,'protocol');
        const tcp   = xv(proto||inner,'tcp');
        const udp   = xv(proto||inner,'udp');
        const tcpPort = xv(tcp||inner,'port') || xv(tcp||inner,'destination-port');
        const udpPort = xv(udp||inner,'port') || xv(udp||inner,'destination-port');
        svcs.push({
          category:'custom', name,
          proto: tcp ? 'TCP' : udp ? 'UDP' : 'TCP/UDP',
          tcpPorts: tcpPort || '-', udpPorts: udpPort || '-',
          icmpType: '-', icmpCode: '-',
          comment: xv(inner,'description') || '-',
          color: '0', category_name: '-',
        });
      });

      // Service groups
      xblks(xv(soContent,'service-group')||(vsysXml!==undefined?'':xv(text,'service-group'))||'', 'entry').forEach(e => {
        const mems = xlist(e._inner,'members');
        svcs.push({
          category:'group', name:xname(e), proto:'GROUP',
          tcpPorts:'-', udpPorts:'-', icmpType:'-', icmpCode:'-',
          members: mems.join(', ')||'-',
          comment: xv(e._inner,'description')||'-',
        });
      });
    } else {
      const svcNames = new Set();
      const re = /^set\s+service\s+("?[^"\s]+"?)\s+/gim;
      let m;
      while ((m = re.exec(text)) !== null) svcNames.add(m[1].replace(/"/g,''));
      svcNames.forEach(name => {
        const p = `service "${name}"`;
        const p2 = `service ${name}`;
        const gv = k => setVal(text,`${p} ${k}`) || setVal(text,`${p2} ${k}`);
        const tcp = gv('protocol tcp port') || gv('protocol tcp destination-port');
        const udp = gv('protocol udp port') || gv('protocol udp destination-port');
        svcs.push({
          category:'custom', name,
          proto: tcp ? 'TCP' : udp ? 'UDP' : '-',
          tcpPorts: tcp||'-', udpPorts: udp||'-',
          icmpType:'-', icmpCode:'-',
          comment: gv('description')||'-', color:'0', category_name:'-',
        });
      });
    }
    return svcs;
  }

  // ─── Users & Groups ───────────────────────────────────────────────────────
  function parseUsers(text) {
    const users = [];

    if (isXml(text)) {
      // Local users (device users / admin)
      xblks(xv(text,'users')||xv(xv(text,'mgt-config')||text,'users')||text, 'entry').forEach(e => {
        const name = xname(e);
        users.push({
          type:'local', name,
          status: xv(e._inner,'disabled') === 'yes' ? 'disable' : 'enable',
          authType: xv(e._inner,'authentication-profile') || 'password',
          email: xv(e._inner,'email') || '-',
          twoFactor:'disable', twoFType:'-',
          ldapServer:'-', radiusServer:'-',
          comment: xv(e._inner,'comments') || '-',
        });
      });

      // Authentication profiles (LDAP/RADIUS)
      xblks(xv(text,'authentication-profile')||text, 'entry').forEach(e => {
        const name = xname(e);
        const inner = e._inner;
        const method= xv(inner,'method');
        const ldap  = xv(method||inner,'ldap');
        const radius= xv(method||inner,'radius');
        if (ldap || (xv(inner,'method') === 'ldap')) {
          users.push({
            type:'ldap-server', name,
            server:  xv(ldap||inner,'server') || xv(ldap||inner,'server-profile') || '-',
            port:    '389', dn: xv(ldap||inner,'base') || '-',
            bindType:'regular', bindDn:'-', cnid:'uid', groupMember:'-', groupFilter:'-',
            ssl: xv(ldap||inner,'ssl') || 'disable',
            comment:'-', status:'enable', members:'-',
          });
        } else if (radius || xv(inner,'method') === 'radius') {
          users.push({
            type:'radius-server', name,
            server: xv(radius||inner,'server') || xv(radius||inner,'server-profile') || '-',
            port: '1812', authType:'auto', nasIp:'-',
            comment:'-', status:'enable', members:'-',
          });
        }
      });

      // User groups
      xblks(xv(text,'groups')||xv(xv(text,'local-user-database')||text,'user-group')||text, 'entry').forEach(e => {
        const name = xname(e);
        const mems = xlist(e._inner,'user');
        users.push({
          type:'group', name, groupType:'local',
          members: mems.join(', ')||'-',
          match:'-', authTimeout:'-', httpDigest:'-', ssoAttrVal:'-',
          comment:'-', status:'enable',
          permissions:[{resource:'All',access:'read-write'}], roles:['group'], accessLevel:'group',
        });
      });

    } else {
      // set format
      const admNames = new Set();
      const admRe = /^set\s+mgt-config\s+users\s+(\S+)\s+/gim;
      let m;
      while ((m = admRe.exec(text)) !== null) admNames.add(m[1]);
      admNames.forEach(name => {
        const p = `mgt-config users ${name}`;
        users.push({
          type:'local', name,
          status: setVal(text,`${p} disabled`) === 'yes' ? 'disable' : 'enable',
          authType: setVal(text,`${p} authentication-profile`) || 'password',
          email:'-', twoFactor:'disable', twoFType:'-',
          ldapServer:'-', radiusServer:'-', comment:'-',
        });
      });
    }
    return users;
  }

  // ─── Schedules ────────────────────────────────────────────────────────────
  function parseSchedules(text, vsysXml, vsysName) {
    const scheds = [];
    if (isXml(text)) {
      const schContent = vsysXml !== undefined ? vsysXml : text;
      xblks(xv(schContent,'schedule')||(vsysXml!==undefined?'':xv(text,'schedule'))||schContent, 'entry').forEach(e => {
        const inner = e._inner;
        const recur = xv(inner,'recurring');
        const once  = xv(inner,'non-recurring');
        scheds.push({
          type: recur ? 'recurring' : 'onetime',
          name: xname(e),
          start: xv(once||recur||inner,'start') || xv(once||recur||inner,'first') || '-',
          end:   xv(once||recur||inner,'end')   || xv(once||recur||inner,'last')  || '-',
          day:   xva(recur||inner,'weekly').join(', ') || xva(recur||inner,'daily').join(', ') || '-',
          color:'0',
        });
      });
    } else {
      const schNames = new Set();
      const re = /^set\s+schedule\s+("?[^"\s]+"?)\s+/gim;
      let m;
      while ((m = re.exec(text)) !== null) schNames.add(m[1].replace(/"/g,''));
      schNames.forEach(name => {
        const p = `schedule "${name}"`;
        const p2 = `schedule ${name}`;
        const gv = k => setVal(text,`${p} ${k}`) || setVal(text,`${p2} ${k}`);
        scheds.push({
          type: 'recurring', name,
          start: gv('recurring start') || '-',
          end:   gv('recurring end')   || '-',
          day:   gv('recurring weekly') || '-', color:'0',
        });
      });
    }
    return scheds;
  }

  // ─── NAT policies ─────────────────────────────────────────────────────────
  function parseNAT(text, vsysXml, vsysName) {
    const nats = [];
    if (isXml(text)) {
      // PAN NAT rules under <nat><rules>
      const natContent = vsysXml !== undefined ? vsysXml : text;
      const natBlock = xv(natContent,'nat') || (vsysXml!==undefined?'':xv(text,'nat')) || natContent;
      xblks(natBlock, 'entry').forEach((e, i) => {
        const inner = e._inner;
        const name  = xname(e) || `NAT-${i+1}`;
        const dynSrc = xv(inner,'dynamic-ip-and-port') || xv(xv(inner,'source-translation')||inner,'dynamic-ip-and-port');
        const statSrc = xv(inner,'static-ip') || xv(xv(inner,'source-translation')||inner,'static-ip');
        const dstTr  = xv(inner,'destination-translation');
        const type   = dstTr ? 'vip' : 'ippool';
        nats.push({
          type, name,
          vipType: dstTr ? 'static-nat' : '-',
          poolType: dynSrc ? 'overload' : statSrc ? 'static' : '-',
          extIp:   xv(dstTr||inner,'translated-address') || xlist(inner,'destination')[0] || '-',
          extIntf: xlist(inner,'to')[0] || '-',
          mapIp:   xv(dstTr||inner,'translated-address') || xv(dynSrc||inner,'translated-address') || '-',
          startIp: xv(dynSrc||inner,'translated-address') || '-',
          endIp:   '-',
          portFwd: xv(dstTr||inner,'translated-port') ? 'enable' : 'disable',
          extPort: xv(dstTr||inner,'original-port') || '-',
          mapPort: xv(dstTr||inner,'translated-port') || '-',
          proto:   '-', comment: xv(inner,'description') || '-',
          status:  e._outer.includes('disabled="yes"') ? 'disable' : 'enable',
          srcIntf: xlist(inner,'from')[0] || '-', arpReply: 'enable',
          _vdom: vsysName || 'vsys1',
        });
      });
    } else {
      const natNames = new Set();
      const re = /^set\s+nat\s+rules\s+("?[^"\s]+"?)\s+/gim;
      let m;
      while ((m = re.exec(text)) !== null) natNames.add(m[1].replace(/"/g,''));
      let idx=1;
      natNames.forEach(name => {
        const p = `nat rules "${name}"`;
        const p2 = `nat rules ${name}`;
        const gv = k => setVal(text,`${p} ${k}`) || setVal(text,`${p2} ${k}`);
        const dst = gv('destination-translation translated-address');
        nats.push({
          type: dst ? 'vip' : 'ippool', name,
          vipType: dst ? 'static-nat' : '-',
          poolType: gv('source-translation dynamic-ip-and-port translated-address') ? 'overload' : '-',
          extIp:   gv('destination') || '-',
          extIntf: gv('to') || '-',
          mapIp:   dst || gv('source-translation dynamic-ip-and-port translated-address') || '-',
          startIp: '-', endIp:'-',
          portFwd: gv('destination-translation translated-port') ? 'enable' : 'disable',
          extPort: gv('destination-translation original-port') || '-',
          mapPort: gv('destination-translation translated-port') || '-',
          proto:'-', comment: gv('description')||'-', status:'enable',
          srcIntf: gv('from')||'-', arpReply:'enable',
        });
      });
    }
    return nats;
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────
  function guessRole(name, zone) {
    const z = (zone || '').toLowerCase();
    const n = (name || '').toLowerCase();
    if (z === 'untrust' || /wan|internet|ext|outside|uplink|untrust/.test(n)) return 'WAN';
    if (z === 'trust'   || /lan|inside|internal|trust|intra/.test(n)) return 'LAN';
    if (z === 'dmz'     || /dmz|server|srv/.test(n)) return 'DMZ';
    if (/mgmt|manage|oob|admin/.test(n)) return 'MGMT';
    if (/vpn|ipsec|ssl|tunnel/.test(n)) return 'VPN';
    if (/loopback|lo/.test(n)) return 'MGMT';
    return 'Unknown';
  }

  function prefixToMask(prefix) {
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return '-';
    const n = (0xFFFFFFFF << (32 - prefix)) >>> 0;
    return [(n>>>24)&0xFF,(n>>>16)&0xFF,(n>>>8)&0xFF,n&0xFF].join('.');
  }

  // ─── Main parse ───────────────────────────────────────────────────────────
  // ── vsys helper ──────────────────────────────────────────────────────────────
  // Extract list of {name, inner, displayName} for all vsys entries
  function extractVsysList(text) {
    if (!isXml(text)) return [];
    // Find <vsys>...</vsys> block — use depth tracking to handle nested XML correctly
    const vsysStart = text.search(/<vsys\b[^>]*>/i);
    if (vsysStart < 0) return [];
    // Extract vsys block content using tag depth
    let depth = 0, i = vsysStart, vsysInner = '';
    const vsysTagRe = /<\/?vsys\b/gi;
    vsysTagRe.lastIndex = vsysStart;
    let tm;
    while ((tm = vsysTagRe.exec(text)) !== null) {
      if (!tm[0].startsWith('</')) depth++;
      else { depth--; if (depth === 0) { vsysInner = text.slice(vsysStart, tm.index + tm[0].length + 1); break; } }
    }
    // Extract only TOP-LEVEL <entry name="vsysN"> elements from vsysInner
    // by tracking <entry>/<\/entry> depth to skip nested entries
    const result = [];
    const entryStartRe = /<entry\s+name="([^"]+)"[^>]*>/gi;
    let em;
    while ((em = entryStartRe.exec(vsysInner)) !== null) {
      const vsysName = em[1];
      let eDepth = 1, ePos = em.index + em[0].length;
      // Find matching </entry> by counting entry tags
      const nestedRe = /<\/?entry\b/gi;
      nestedRe.lastIndex = ePos;
      let nm;
      while ((nm = nestedRe.exec(vsysInner)) !== null && eDepth > 0) {
        if (!nm[0].startsWith('</')) eDepth++;
        else { eDepth--; if (eDepth === 0) { ePos = nm.index + nm[0].length + 1; break; } }
      }
      if (eDepth > 0) continue; // malformed XML
      const inner = vsysInner.slice(em.index + em[0].length, nm.index);
      const displayName = inner.match(/<display-name>([^<]+)<\/display-name>/i)?.[1]?.trim() || vsysName;
      result.push({ name: vsysName, inner, displayName });
      // Skip to end of this top-level entry
      entryStartRe.lastIndex = ePos;
    }
    return result;
  }

  // HA/Cluster：XML 走 <deviceconfig><high-availability>（xv() 全文搜尋不受巢狀深度影響）；
  // set-format 已查證官方 KB（kA10g000000ClGNCA0）語法：
  //   set deviceconfig high-availability group group-id 1 peer-ip 192.168.6.45
  //   set deviceconfig high-availability group group-id 1 mode active-passive ...
  // group-id 數值需先掃出來才能組出完整 setVal() key（不像其他固定 key 可直接查）
  function parseHa(text) {
    const result = { enabled:false, mode:'-', groupId:'-', priority:'-', peerIp:'-', syncInterface:'-', vip:'-' };
    if (isXml(text)) {
      const haBlock = xv(text, 'high-availability');
      if (!haBlock) return result;
      result.enabled = xv(haBlock, 'enabled') === 'yes';
      if (!result.enabled) return result;
      const groupBlock = xv(haBlock, 'group') || haBlock;
      result.groupId = xv(groupBlock, 'group-id') || '-';
      result.peerIp = xv(groupBlock, 'peer-ip') || '-';
      const modeBlock = xv(groupBlock, 'mode');
      result.mode = /active-passive/i.test(modeBlock) ? 'active-passive' : /active-active/i.test(modeBlock) ? 'active-active' : (modeBlock || '-');
    } else {
      const gidM = text.match(/^set\s+deviceconfig\s+high-availability\s+group\s+group-id\s+(\d+)/m);
      if (!gidM) return result;
      result.enabled = true;
      result.groupId = gidM[1];
      result.peerIp = setVal(text, `deviceconfig high-availability group group-id ${result.groupId} peer-ip`) || '-';
      const modeLine = setVal(text, `deviceconfig high-availability group group-id ${result.groupId} mode`);
      result.mode = modeLine ? modeLine.split(/\s+/)[0] : '-';
    }
    return result;
  }

  // ── Multi-vsys aware parse() ──────────────────────────────────────────────────
  function parse(text) {
    const deviceInfo = parseDeviceInfo(text);
    const vsysList   = extractVsysList(text);
    const isMultiVsys = vsysList.length > 1;
    const vsysNames   = vsysList.map(v => v.name);

    // Network-scoped (shared across all vsys): interfaces, routes, vpn, sdwan
    const interfaces = parseInterfaces(text);
    const routes     = parseRoutes(text);
    const vpn        = parseVPN(text);
    const sdwan      = parseSdwan(text);
    const ha         = parseHa(text);
    // Device-level: dhcp (in <network>), dns (in <deviceconfig>), users
    const dhcp       = parseDhcp(text);
    const dns        = parseDns(text);
    const users      = parseUsers(text);

    // vsys-scoped sections: parse per vsys and merge
    let policies  = [], addresses = [], services = [], schedules = [], nat = [];
    let _perVsys  = [];

    if (vsysList.length === 0) {
      // No explicit vsys — single-vsys device or CLI export: parse from full text
      // 位址物件需先解析出來，才能建 addrTypeMap 供 policies 的 source/destination 名稱反查
      // v4/v6 型別（見 _splitAddr() 上方註解）
      addresses = parseAddressObjects(text, text, 'vsys1');
      policies  = parsePolicies(text, text, 'vsys1', buildAddrTypeMap(addresses));
      services  = parseServiceObjects(text, text, 'vsys1');
      schedules = parseSchedules(text, text, 'vsys1');
      nat       = parseNAT(text, text, 'vsys1');
    } else {
      vsysList.forEach(vs => {
        const vsXml  = vs.inner;
        const vsName = vs.name;
        const vsAddresses = parseAddressObjects(text, vsXml, vsName);
        const vsPolicies  = parsePolicies(text, vsXml, vsName, buildAddrTypeMap(vsAddresses));
        const vsServices  = parseServiceObjects(text, vsXml, vsName);
        const vsSchedules = parseSchedules(text, vsXml, vsName);
        const vsNat       = parseNAT(text, vsXml, vsName);
        policies  = policies.concat(vsPolicies);
        addresses = addresses.concat(vsAddresses);
        services  = services.concat(vsServices);
        schedules = schedules.concat(vsSchedules);
        nat       = nat.concat(vsNat);
        _perVsys.push({
          name: vsName, displayName: vs.displayName,
          policies: vsPolicies, addresses: vsAddresses,
          services: vsServices, schedules: vsSchedules,
          nat: vsNat,
          // Tag interfaces belonging to this vsys
          interfaces: interfaces.filter(i => i._vdom === vsName || (!isMultiVsys && i._vdom === 'vsys1')),
          routes: routes.filter(r => !r._vsys || r._vsys === vsName),
        });
      });
    }

    return {
      vendor:       'PaloAlto',
      deviceInfo,
      interfaces,
      policies,
      routes,
      vpn,
      addresses,
      services,
      schedules,
      nat,
      users,
      sdwan,
      ha,
      dhcp,
      dns,
      snmp:       parseSnmp(text),
      logservers: parseLogServers(text),
      // VDOM-compatible metadata for UI filtering
      _vdomNames:   isMultiVsys ? vsysNames : [],
      _isMultiVdom: isMultiVsys,
      _perVdom:     _perVsys,   // named _perVdom for UI compatibility
    };
  }




  // ── Palo Alto SD-WAN (PAN-OS 10.1+) ───────────────────────────────────────

  // ── DHCP Server & Relay ──────────────────────────────────────────────────
  function parseDhcp(text) {
    const servers=[], relays=[];
    // DHCP lives in <network> block in multi-vsys configs
    const dhcpSrc = (xv(text,'network')||text);
    const dhcpM=(dhcpSrc).match(/<dhcp>([\s\S]*?)<\/dhcp>/i);
    if(!dhcpM) return {servers,relays};
    const dhcpXml=dhcpM[1];
    const xget=(x,tag)=>{const m=x.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`,'i'));return m?m[1].trim():'-';};
    const xgetAll=(x,tag)=>[...x.matchAll(new RegExp(`<${tag}>([^<]+)<\\/${tag}>`,'gi'))].map(m=>m[1].trim());
    // Iterate all <server> blocks, then all <entry> within each server block
    for(const sm of dhcpXml.matchAll(/<server>([\s\S]*?)<\/server>/gi)){
      const serverBody=sm[1];
      for(const m of serverBody.matchAll(/<entry\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/entry>/gi)){
        const[,name,body]=m;
        const pool=xgetAll(body,'member').join(', ');
        const parts=pool.split('-');
        servers.push({name,iface:xget(body,'interface'),
          startIp:parts[0]?.trim()||'-',endIp:parts[1]?.trim()||'-',
          gateway:xget(body,'gateway'),mask:xget(body,'subnet-mask'),
          dns1:xget(body,'primary-dns'),dns2:xget(body,'secondary-dns'),
          domain:xget(body,'domain'),lease:xget(body,'days')||'1',
          status:xget(body,'mode')==='disabled'?'disable':'enable',comment:''});
      }
    }
    // Iterate all <relay> blocks similarly
    for(const rm of dhcpXml.matchAll(/<relay>([\s\S]*?)<\/relay>/gi)){
      const relayBody=rm[1];
      for(const m of relayBody.matchAll(/<entry\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/entry>/gi)){
        const[,name,body]=m;
        relays.push({name,iface:xget(body,'interface'),serverIp:xgetAll(body,'member').join(', '),status:'enable',comment:''});
      }
    }
    return {servers,relays};
  }
  // ── DNS ─────────────────────────────────────────────────────────────────
  function parseDns(text) {
    const result={servers:[],secondaries:[],domain:'-',proxy:false,proxyRules:[],dnsOverTls:false,cacheSize:'-',static:[]};
    const xget=(x,tag)=>{const m=x.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`,'i'));return m?m[1].trim():'-';};
    const dsM=text.match(/<dns-setting>([\s\S]*?)<\/dns-setting>/i);
    if(dsM){const pri=xget(dsM[1],'primary');if(pri!=='-')result.servers.push(pri);const sec=xget(dsM[1],'secondary');if(sec!=='-')result.secondaries.push(sec);}
    const dpM=text.match(/<dns-proxy>([\s\S]*?)<\/dns-proxy>/i);
    if(dpM){
      result.proxy=true;
      for(const m of dpM[1].matchAll(/<entry name="([^"]+)">([\s\S]*?)<\/entry>/gi)){
        const[,name,body]=m;
        for(const dm of body.matchAll(/<domain>([\s\S]*?)<\/domain>/gi)){
          const dom=xget(dm[1],'name'),tgt=xget(dm[1],'dns-server');
          result.proxyRules.push({domain:dom,target:tgt});
        }
      }
    }
    return result;
  }


  // ── SNMP ────────────────────────────────────────────────────────────────────
  function parseSnmp(text) {
    const result = { enabled:false, agent:{name:'-',description:'-',location:'-',contact:'-',version:[]}, communities:[], v3users:[], trapServers:[] };

    // ── Format A: <snmp-setting> inside <deviceconfig><system> ──────────────
    const snmpM=text.match(/<snmp-setting>([\s\S]*?)<\/snmp-setting>/i);
    if(snmpM){
      result.enabled=true;
      const snmpXml=snmpM[1];
      const xget=(x,tag)=>{const m=x.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`,'i'));return m?m[1].trim():'-';};
      // v2c community (Format A: <snmp-community-string>X</snmp-community-string>)
      const v2M=snmpXml.match(/<v2c>([\s\S]*?)<\/v2c>/i);
      if(v2M){ const comm=xget(v2M[1],'snmp-community-string'); if(comm&&comm!=='-'){result.communities.push({name:comm,permission:'ro',allowedHosts:[],events:'-',status:'enable'}); result.agent.version.push('v2c');} }
      // v3 users
      const v3M=snmpXml.match(/<v3>([\s\S]*?)<\/v3>/i);
      if(v3M){
        result.agent.version.push('v3');
        const v3usersM=v3M[1].match(/<users>([\s\S]*?)<\/users>/i);
        const v3usersXml=v3usersM?v3usersM[1]:v3M[1];
        xentriesTop(v3usersXml).forEach(e=>{
          const b=e._inner;
          const hasPriv=/<privpwd>/i.test(b);
          const hasAuth=/<authpwd>/i.test(b);
          result.v3users.push({name:e._name,authProto:xget(b,'auth-type')||'sha',privProto:hasPriv?(xget(b,'priv-type')||'aes'):'-',secLevel:hasPriv?'auth-priv':hasAuth?'auth-no-priv':'no-auth-no-priv',notifyHost:'-',status:'enable'});
        });
      }
    }

    // ── Format B: <shared><snmp-setup> (PAN-OS older / Panorama style) ──────
    const sharedM=text.match(/<shared>([\s\S]*?)<\/shared>/i);
    const snmpSetupM=(sharedM?sharedM[1]:text).match(/<snmp-setup>([\s\S]*?)<\/snmp-setup>/i);
    if(snmpSetupM){
      result.enabled=true;
      const su=snmpSetupM[1];
      const xget=(x,tag)=>{const m=x.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`,'i'));return m?m[1].trim():'-';};
      // System info (agent metadata)
      const sysM=su.match(/<system>([\s\S]*?)<\/system>/i);
      if(sysM){
        result.agent.description=xget(sysM[1],'description');
        result.agent.location   =xget(sysM[1],'location');
        result.agent.contact    =xget(sysM[1],'contact');
      }
      // v2c communities: <snmp-community><entry name="CommName">
      const v2cM=su.match(/<v2c>([\s\S]*?)<\/v2c>/i);
      if(v2cM){
        result.agent.version.push('v2c');
        const commBlk=v2cM[1].match(/<snmp-community>([\s\S]*?)<\/snmp-community>/i);
        if(commBlk){
          xentriesTop(commBlk[1]).forEach(e=>{
            result.communities.push({name:e._name,permission:/rw|write|admin/i.test(e._name)?'rw':'ro',allowedHosts:[],events:'-',status:'enable'});
          });
        }
      }
      // v3 users
      const v3M=su.match(/<v3>([\s\S]*?)<\/v3>/i);
      if(v3M){
        if(!result.agent.version.includes('v3')) result.agent.version.push('v3');
        const v3usersM=v3M[1].match(/<users>([\s\S]*?)<\/users>/i);
        const v3usersXml=v3usersM?v3usersM[1]:v3M[1];
        xentriesTop(v3usersXml).forEach(e=>{
          const b=e._inner;
          const authT=xget(b,'auth-type')||'-';
          const privT=xget(b,'priv-type')||'-';
          const hasPriv=privT!=='-'&&privT!=='';
          const hasAuth=authT!=='-'&&authT!=='';
          result.v3users.push({name:e._name,authProto:hasAuth?authT:'sha',privProto:hasPriv?privT:'-',secLevel:hasPriv?'auth-priv':hasAuth?'auth-no-priv':'no-auth-no-priv',notifyHost:'-',status:'enable'});
        });
      }
    }

    // ── System contact/location from <deviceconfig><system> ─────────────────
    const sysM2=text.match(/<system>([\s\S]*?)<\/system>/i);
    if(sysM2){
      const xget=(x,tag)=>{const m=x.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`,'i'));return m?m[1].trim():'-';};
      const hn=xget(sysM2[1],'hostname'); if(hn&&hn!=='-') result.agent.name=hn;
      const co=xget(sysM2[1],'snmp-contact')||xget(sysM2[1],'contact'); if(co&&co!=='-'&&result.agent.contact==='-') result.agent.contact=co;
      const lo=xget(sysM2[1],'snmp-location')||xget(sysM2[1],'location'); if(lo&&lo!=='-'&&result.agent.location==='-') result.agent.location=lo;
    }
    return result;
  }

  // ── Log Servers ──────────────────────────────────────────────────────────────
  function parseLogServers(text) {
    const result={syslog:[],fortianalyzer:[],netflow:[],logForward:[]};
    const xget=(x,tag)=>{const m=x.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`,'i'));return m?m[1].trim():'-';};

    // ── A) Top-level <syslog> profile (standard format) ─────────────────────
    const topSyslogM=text.match(/<syslog>([\s\S]*?)<\/syslog>/i);
    if(topSyslogM){
      xentriesTop(topSyslogM[1]).forEach(prof=>{
        const profName=prof._name;
        xentriesTop(prof._inner).forEach(srv=>{
          const sb=srv._inner;
          result.syslog.push({name:`${profName}/${srv._name}`,server:xget(sb,'server'),port:xget(sb,'port')||'514',facility:xget(sb,'facility')||'LOG_USER',format:xget(sb,'format')||'BSD',protocol:xget(sb,'transport')||'UDP',level:'information',status:'enable'});
        });
      });
    }

    // ── B) Per-vsys <log-settings><syslog> (this config's format) ───────────
    // Search all <log-settings> blocks in the text (inside each vsys or device)
    const logSettingsRe=/<log-settings>([\s\S]*?)<\/log-settings>/gi;
    let lsm;
    while((lsm=logSettingsRe.exec(text))!==null){
      const lsBody=lsm[1];
      // Find <syslog> inside log-settings
      // Find syslog blocks that are SERVER DEFINITIONS (contain <entry> not just <member>)
      const lsAllSyslogs=[...lsBody.matchAll(/<syslog>([\s\S]*?)<\/syslog>/gi)];
      const lsSyslogDefs=lsAllSyslogs.filter(m=>/<entry\s+name=/i.test(m[1])&&!/<member>/i.test(m[1]));
      // Also accept syslog blocks that have <entry> mixed with <member>
      const lsSyslogAll=lsAllSyslogs.filter(m=>/<entry\s+name=/i.test(m[1]));
      (lsSyslogAll.length?lsSyslogAll:lsSyslogDefs).forEach(m=>{
        xentriesTop(m[1]).forEach(srv=>{
          const sb=srv._inner;
          const svr=xget(sb,'server');
          if(!svr||svr==='-') return;
          const key=`${svr}:${xget(sb,'port')||'514'}`;
          if(result.syslog.some(s=>`${s.server}:${s.port}`===key)) return;
          result.syslog.push({name:srv._name,server:svr,port:xget(sb,'port')||'514',facility:xget(sb,'facility')||'LOG_LOCAL7',format:xget(sb,'format')||'BSD',protocol:xget(sb,'transport')||'UDP',level:'information',status:'enable'});
        });
      });
      // Log forwarding profiles inside log-settings
      const profBlk=lsBody.match(/<profiles>([\s\S]*?)<\/profiles>/i);
      if(profBlk){
        xentriesTop(profBlk[1]).forEach(prof=>{
          // Only add if not already in logForward
          if(!result.logForward.some(lf=>lf.name===prof._name))
            result.logForward.push({name:prof._name,type:'log-forwarding',target:'-'});
        });
      }
    }

    // ── C) Panorama servers = FortiAnalyzer equivalent ───────────────────────
    // Search <panorama-server> directly — avoid matching the wrong <system> block
    const pano1M=text.match(/<panorama-server>([^<]+)<\/panorama-server>/i);
    const pano2M=text.match(/<panorama-server-2>([^<]+)<\/panorama-server-2>/i);
    if(pano1M) result.fortianalyzer.push({name:'Panorama-Primary',  server:pano1M[1].trim(),port:'3978',reliable:'enable',encAlgo:'high',status:'enable'});
    if(pano2M) result.fortianalyzer.push({name:'Panorama-Secondary',server:pano2M[1].trim(),port:'3978',reliable:'enable',encAlgo:'high',status:'enable'});

    // ── D) NetFlow ────────────────────────────────────────────────────────────
    const nfM=text.match(/<netflow>([\s\S]*?)<\/netflow>/i);
    if(nfM){ result.netflow.push({collector:xget(nfM[1],'server'),port:xget(nfM[1],'port')||'2055',activeTimeout:'60',status:'enable'}); }

    return result;
  }

  function parseSdwan(text) {
    const result = { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] };

    // Try to find <sdwan> block anywhere in the XML
    const sdwanMatch = text.match(/<sdwan>([\s\S]*?)<\/sdwan>/i);
    if (!sdwanMatch) return result;
    result.enabled = true;
    const sdxml = sdwanMatch[1];

    // Helper: get text content
    const xget = (xml, tag) => { const m = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`,'i')); return m ? m[1].trim() : '-'; };
    const xall = (xml, tag) => { const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`,'gi'); const r=[]; let m; while((m=re.exec(xml))!==null) r.push(m[1]); return r; };
    const xentries = (xml, tag) => { const re = new RegExp(`<entry name="([^"]+)"[^>]*>([\\s\\S]*?)<\\/entry>`,'gi'); const r=[]; let m; while((m=re.exec(xml))!==null){ const inner=m[2]; if(inner.includes(`<${tag}>`)|| tag==='*') r.push({name:m[1],inner}); } return r; };

    // Interfaces with SD-WAN tag
    const ifaceEntries = xentries(sdxml, 'link-tag');
    ifaceEntries.forEach((e, idx) => {
      const tag = xget(e.inner, 'link-tag');
      result.members.push({
        id: String(idx+1), iface: e.name,
        zone: tag !== '-' ? tag : 'WAN',
        gateway: '-', gateway6: '-',
        priority: 1, weight: 1, cost: 0, spillover: 0, volumeRatio: 1,
        status: 'enable', comment: tag !== '-' ? `Tag: ${tag}` : '',
      });
    });

    // Path quality profiles = health checks / SLA thresholds
    const pqpBlock = sdxml.match(/<path-quality-profile>([\s\S]*?)<\/path-quality-profile>/i);
    if (pqpBlock) {
      xentries(pqpBlock[1], '*').forEach((e, idx) => {
        const latency = xget(e.inner, 'latency');
        const jitter  = xget(e.inner, 'jitter');
        const loss    = xget(e.inner, 'packet-loss');
        result.healthChecks.push({
          name: e.name,
          server: '-', protocol: 'ping', port: '-',
          interval: xget(e.inner, 'probe-frequency') || '10',
          timeout: '-', failtime: '-', recoverytime: '-',
          probePackets: '5', http200Only: 'disable',
          members: 'all',
          slaThresholds: [{
            id: '1',
            latency: latency !== '-' ? latency : '150',
            jitter:  jitter  !== '-' ? jitter  : '30',
            packetLoss: loss !== '-' ? loss : '5',
          }],
        });
      });
    }

    // Traffic distribution profiles = lb mode
    const tdpBlock = sdxml.match(/<traffic-distribution-profile>([\s\S]*?)<\/traffic-distribution-profile>/i);
    if (tdpBlock) {
      const method = xget(tdpBlock[1], 'distribution-method');
      result.lbMode = method.includes('round') ? 'source-ip-based'
                    : method.includes('weight') ? 'weight-based'
                    : method.includes('priority') ? 'priority'
                    : 'load-balance';
    }

    // SD-WAN policy rules
    const ruleBlock = sdxml.match(/<sdwan-policy-rule>([\s\S]*?)<\/sdwan-policy-rule>/i);
    if (ruleBlock) {
      xentries(ruleBlock[1], '*').forEach((e, idx) => {
        const action = e.inner.match(/<path-selection>([\s\S]*?)<\/path-selection>/i);
        const actionInner = action ? action[1] : '';
        const pqpRef = xget(actionInner, 'path-quality-profile');
        const tdpRef = xget(actionInner, 'traffic-distribution-profile');
        const enforce = xget(actionInner, 'path-quality-enforcement') === 'yes';
        result.services.push({
          id: String(idx+1), name: e.name,
          mode: enforce ? 'sla' : 'load-balance',
          src: xget(e.inner, 'source') || 'any',
          dst: xget(e.inner, 'destination') || 'any',
          srcNegate: 'disable', dstNegate: 'disable', users: '-',
          protocol: '0', startPort: '-', endPort: '-',
          priorityMembers: tdpRef !== '-' ? tdpRef : '-',
          priorityZone: '-', preferredUplink: '-',
          slaCompare: 'order', tie: 'zone',
          slaRefs: pqpRef !== '-' ? [{healthCheck: pqpRef, id:'1'}] : [],
          inputDevice: '-',
          status: xget(e.inner,'disabled') === 'yes' ? 'disable' : 'enable',
          comment: '',
        });
      });
    }

    return result;
  }

  return { parse };
})();


