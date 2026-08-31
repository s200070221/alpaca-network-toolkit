// ═══ parser-checkpoint.js ═══
/**
 * Check Point Firewall Configuration Parser
 * Supports:
 *   - Gaia CLI: "show configuration" output (.txt / .conf)
 *   - SmartConsole policy export (objects_5_0.C / rulebases_5_0.fws)
 *   - Clish "show running-system" output
 */
const CheckpointParser = (() => {

  // ─── Gaia Clish helpers ───────────────────────────────────────────────────
  function clishVal(text, key) {
    const re = new RegExp(`^set\\s+${key.replace(/[-\s]/g, '[\\s\\-]')}\\s+(.+)$`, 'im');
    const raw = (text.match(re) || [])[1]?.trim() || '';
    // Fix: 轉義引號 \" 與首尾引號清除
    return raw.replace(/^"|"$/g,'').replace(/\\"/g,'"');
  }

  function clishLines(text, prefix) {
    const re = new RegExp(`^set\\s+${prefix.replace(/[-\s]/g, '[\\s\\-]')}\\s+(.+)$`, 'gim');
    const results = [];
    let m;
    while ((m = re.exec(text)) !== null) results.push(m[1].trim());
    return results;
  }

  // ─── objects_5_0.C / .W format helpers ───────────────────────────────────
  function parseObjectsC(text) {
    // Format: ( :Name (value) :Attr (value) )
    const objects = [];
    const re = /\(\s*:([\w\-]+)\s*\(([\s\S]*?)\)\s*\)/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      objects.push({ _type: m[1], _body: m[2] });
    }
    return objects;
  }

  function objVal(body, key) {
    const re = new RegExp(`:${key}\\s+\\(([^)]*?)\\)`, 'i');
    return (body.match(re) || [])[1]?.trim() || '';
  }

  function objVals(body, key) {
    const re = new RegExp(`:${key}\\s+\\(([^)]*)\\)`, 'gi');
    const results = [];
    let m;
    while ((m = re.exec(body)) !== null) results.push(m[1].trim());
    return results;
  }

  // ─── Device info ──────────────────────────────────────────────────────────
  function parseDeviceInfo(text) {
    const info = { vendor: 'CheckPoint', hostname: '-', firmware: '-', model: '-', serial: '-', vdom: [] };

    // Gaia clish
    info.hostname = clishVal(text, 'hostname') || '-';
    const verLine = text.match(/Check Point Gaia\s+(R?\d[\d\.]+)/i) ||
                    text.match(/version\s+(R?\d[\d\.]+)/i) ||
                    text.match(/Product version\s+(R?\d[\d\.]+)/i);
    if (verLine) info.firmware = verLine[1];

    const modelLine = text.match(/Product name:\s*(.+)/i) ||
                      text.match(/set edition\s+(\S+)/i);
    if (modelLine) info.model = modelLine[1].trim();

    const snLine = text.match(/Serial Number:\s*(\S+)/i);
    if (snLine) info.serial = snLine[1];

    return info;
  }

  // ─── Interfaces ───────────────────────────────────────────────────────────
  // 次要IP（Secondary IP，2026-08-31 新增，二次查證推翻先前記載）：官方 Check Point Gaia
  // Administration Guide「Aliases」章節（sc1.checkpoint.com R80.20/R80.30）直接 fetch 逐字
  // 確認真實指令為 `add interface <NAME> alias <IPv4>/<PREFIXLEN>`（Linux IP-aliasing
  // 機制，系統內部自動產生 eth1:1/eth1:2 等別名介面名稱，但設定檔文字本身只會出現對基礎
  // 介面名稱的 `add interface` 一行，不會出現 `set interface eth1:1 ...` 這種巢狀命名）。
  // 先前 2026-08-12 記載「查無任何佐證」係因當時搜尋只查到語意完全不同的 Proxy ARP `add`
  // 指令，本輪換關鍵字重新查證後找到官方 Aliases 頁面確認此語法真實存在，予以推翻並實作。
  function parseSecondaryIpsCheckpoint(text, name) {
    const nameEsc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp('^add\\s+interface\\s+' + nameEsc + '\\s+alias\\s+(\\S+)/(\\d+)', 'gim');
    const list = [];
    let am;
    while ((am = re.exec(text)) !== null) {
      const ml = parseInt(am[2]);
      let maskDot = '-';
      if (!isNaN(ml)) {
        const n = (0xFFFFFFFF << (32 - ml)) >>> 0;
        maskDot = [(n>>>24)&0xFF,(n>>>16)&0xFF,(n>>>8)&0xFF,n&0xFF].join('.');
      }
      list.push({ ip: am[1], mask: maskDot });
    }
    return list;
  }

  function parseInterfaces(text) {
    const ifaces = [];

    // Gaia clish: "set interface eth0 ipv4-address 10.0.0.1 mask-length 24"
    const ifNames = new Set();
    const ifRe = /^set\s+interface\s+(\S+)\s+/gim;
    let m;
    while ((m = ifRe.exec(text)) !== null) ifNames.add(m[1]);

    ifNames.forEach(name => {
      const ipv4  = clishVal(text, `interface ${name} ipv4-address`);
      const mask  = clishVal(text, `interface ${name} mask-length`);
      const state = clishVal(text, `interface ${name} state`) ||
                    clishVal(text, `interface ${name} link-speed`) ? 'up' : 'up';
      const mtu   = clishVal(text, `interface ${name} mtu`) || '1500';
      const comm  = clishVal(text, `interface ${name} comments`) || '-';
      const vlanId= name.match(/\.\d+$/) ? name.split('.').pop() : '-';
      const type  = name.includes('.') ? 'vlan' : name.startsWith('lo') ? 'loopback' : name.startsWith('bond') ? 'bond' : 'physical';

      // Convert mask-length to dotted notation
      let maskDot = '-';
      if (mask) {
        const ml = parseInt(mask);
        if (!isNaN(ml)) {
          const n = (0xFFFFFFFF << (32 - ml)) >>> 0;
          maskDot = [(n>>>24)&0xFF,(n>>>16)&0xFF,(n>>>8)&0xFF,n&0xFF].join('.');
        }
      }

      ifaces.push({
        name,
        alias:   clishVal(text, `interface ${name} alias`) || '-',
        ip:      ipv4 || '-',
        mask:    maskDot,
        secondaryIps: parseSecondaryIpsCheckpoint(text, name),
        type,
        vlanId,
        vdom:    '-',
        role:    guessRole(name),
        status:  state,
        speed:   clishVal(text, `interface ${name} link-speed`) || '-',
        mtu,
        macaddr: clishVal(text, `interface ${name} mac-addr`) || '-',
        mode:    'static',
        gwdetect:'-',
        desc:    comm,
        allowaccess: '-',
        interface: name.includes('.') ? name.split('.')[0] : '-',
        gateway: clishVal(text, `interface ${name} gateway`) || '-',
      });
    });

    // Also parse from objects_5_0.C format (: interface)
    const intfBlock = text.match(/\(\s*:interface\s*\(([\s\S]*?)\)\s*\)/g) || [];
    intfBlock.forEach(blk => {
      const body = blk.slice(blk.indexOf('(', 1) + 1, blk.lastIndexOf(')'));
      const name = objVal(body, 'Name');
      if (!name || ifNames.has(name)) return;
      const ip   = objVal(body, 'ipaddr') || objVal(body, 'subnets');
      const msk  = objVal(body, 'netmask') || objVal(body, 'mask');
      ifaces.push({
        name, alias: objVal(body, 'comments') || '-',
        ip: ip || '-', mask: msk || '-',
        type: 'physical', vlanId: '-', vdom: '-',
        role: guessRole(name), status: 'up',
        speed: '-', mtu: '1500', macaddr: '-', mode: 'static',
        gwdetect: '-', desc: objVal(body, 'comments') || '-', allowaccess: '-', interface: '-',
      });
      ifNames.add(name);
    });

    return ifaces;
  }

  // ─── Policies (rulebases) ─────────────────────────────────────────────────
  function parsePolicies(text, addrTypeMap) {
    const policies = [];

    // Gaia clish access-policy or "show access-policy" output
    // Format: set access-policy rule <n> ...
    const ruleNums = new Set();
    const ruleRe = /^set\s+access[\-\s]policy\s+rule\s+(\d+)\s+/gim;
    let m;
    while ((m = ruleRe.exec(text)) !== null) ruleNums.add(m[1]);

    ruleNums.forEach(n => {
      const prefix = `access-policy rule ${n}`;
      const srcStr = clishVal(text, `${prefix} source`) || 'Any';
      const dstStr = clishVal(text, `${prefix} destination`) || 'Any';
      const srcAddrSplit = _splitAddr(srcStr, addrTypeMap);
      const dstAddrSplit = _splitAddr(dstStr, addrTypeMap);
      policies.push({
        id:       n,
        name:     clishVal(text, `${prefix} name`) || `Rule-${n}`,
        srcIntf:  clishVal(text, `${prefix} from`) || 'Any',
        dstIntf:  clishVal(text, `${prefix} to`) || 'Any',
        srcAddr:  srcStr,
        dstAddr:  dstStr,
        srcAddr4: srcAddrSplit.v4,
        srcAddr6: srcAddrSplit.v6,
        dstAddr4: dstAddrSplit.v4,
        dstAddr6: dstAddrSplit.v6,
        service:  clishVal(text, `${prefix} service`) || 'Any',
        schedule: clishVal(text, `${prefix} time`) || 'Any',
        action:   mapCpAction(clishVal(text, `${prefix} action`) || 'drop'),
        nat:      clishVal(text, `${prefix} nat`) || 'disable',
        ippool:   'disable',
        poolname: '-',
        logtraffic: clishVal(text, `${prefix} track`) || 'disable',
        logstart:   '-',
        utm:      {
          av:        clishVal(text, `${prefix} av-profile`) || '-',
          webfilter: clishVal(text, `${prefix} urlf-profile`) || '-',
          ips:       clishVal(text, `${prefix} ips-profile`) || '-',
          ssl:       '-',
          appctrl:   clishVal(text, `${prefix} appi-profile`) || '-',
        },
        status:   clishVal(text, `${prefix} disabled`) === 'true' ? 'disable' : 'enable',
        comments: clishVal(text, `${prefix} comments`) || '-',
        users:    clishVal(text, `${prefix} user-group`) || '-',
        groups:   clishVal(text, `${prefix} identity-tag`) || '-',
      });
    });

    // Parse rulebases_5_0.fws / policy.W format
    // Format: :rules ( :(0) ( :src (...) :dst (...) :services (...) :action (...) ) )
    const ruleBaseRe = /:\((\d+)\)\s*\(([\s\S]*?)(?=:\(\d+\)\s*\(|:properties|\)$)/g;
    while ((m = ruleBaseRe.exec(text)) !== null) {
      const n = m[1], body = m[2];
      if (!body.includes(':src') && !body.includes(':dst')) continue;
      const src  = objVals(body, 'src').join(', ')  || 'Any';
      const dst  = objVals(body, 'dst').join(', ')  || 'Any';
      const svcs = objVals(body, 'services').join(', ') || 'Any';
      const act  = objVal(body, 'action') || 'drop';
      const trk  = objVal(body, 'track') || 'None';
      const dis  = objVal(body, 'disabled');
      // 2026-08-10 稽核修復：此格式先前完全沒有計算 srcAddr4/srcAddr6/dstAddr4/dstAddr6，
      // 這幾個欄位會是 undefined，UI 的 IPV4/IPV6 來源/目的欄位對這種規則格式一律顯示空白
      const srcAddrSplit = _splitAddr(src, addrTypeMap);
      const dstAddrSplit = _splitAddr(dst, addrTypeMap);
      policies.push({
        id: n, name: objVal(body, 'name') || `Rule-${n}`,
        srcIntf: objVal(body, 'from') || 'Any',
        dstIntf: objVal(body, 'to')   || 'Any',
        srcAddr: src, dstAddr: dst,
        srcAddr4: srcAddrSplit.v4, srcAddr6: srcAddrSplit.v6,
        dstAddr4: dstAddrSplit.v4, dstAddr6: dstAddrSplit.v6,
        service: svcs,
        schedule: objVal(body, 'time') || 'Any',
        action: mapCpAction(act), nat: 'disable',
        ippool: 'disable', poolname: '-',
        logtraffic: trk.toLowerCase() !== 'none' ? 'enable' : 'disable',
        logstart: '-',
        utm: { av: '-', webfilter: '-', ips: '-', ssl: '-', appctrl: objVal(body, 'applications') || '-' },
        status: dis === 'true' ? 'disable' : 'enable',
        comments: objVal(body, 'comments') || '-',
        users: objVals(body, 'user').join(', ') || '-',
        groups: objVals(body, 'identity-role').join(', ') || '-',
      });
    }

    return policies;
  }

  function mapCpAction(a) {
    const l = (a || '').toLowerCase();
    if (l === 'accept' || l === 'allow') return 'accept';
    if (l === 'drop'   || l === 'deny' || l === 'reject') return 'deny';
    return 'deny';
  }

  // ─── Routes ───────────────────────────────────────────────────────────────
  function parseRoutes(text) {
    const routes = [];

    let idx = 1;  // route ID counter
    // Static: "set static-route 10.0.0.0/8 nexthop gateway address 192.168.1.1 on"
    const staticRe = /^set\s+static-route\s+(\S+)\s+nexthop\s+(?:gateway\s+\S+\s+(\S+)|(?:blackhole))\s*/gim;
    // Also: "set route DST MASK nexthop gateway address IP on"
    const routeRe = /^set\s+route\s+([\d.]+)\s+([\d.]+)\s+nexthop\s+gateway\s+address\s+(\S+)/gim;
    let rm;
    while ((rm = routeRe.exec(text)) !== null) {
      const dst = rm[1], mask = rm[2], gw = rm[3];
      // Convert mask to prefix length
      const parts = mask.split('.').map(Number);
      const bits = parts.reduce((n,o)=>n+(o===255?8:o===254?7:o===252?6:o===248?5:o===240?4:o===224?3:o===192?2:o===128?1:0),0);
      const cidr = `${dst}/${bits||0}`;
      if (!routes.find(r=>r.dst===cidr)) {
        routes.push({ type:'static', id:String(++idx), dst:cidr, gateway:gw, iface:'-', device:'-', distance:'1', priority:'-', status:'enable', blackhole:'disable', comment:'' });
      }
    }
    let m;
    while ((m = staticRe.exec(text)) !== null) {
      routes.push({
        type: 'static', id: String(idx++),
        dst: m[1], gateway: m[2] || '-',
        device: '-',
        distance: clishVal(text, `static-route ${m[1]} nexthop gateway priority`) || '1',
        priority: '0', weight: '0',
        comment: '-', status: 'enable',
        blackhole: m[0].includes('blackhole') ? 'enable' : 'disable',
        vrf: '0',
      });
    }

    // OSPF
    if (/set ospf\s/im.test(text)) {
      routes.push({
        type: 'ospf', id: 'ospf', dst: 'dynamic', gateway: '-',
        device: '-',
        routerId: clishVal(text, 'ospf router-id') || '-',
        ospfNetworks: '-',
        distance: '110', priority: '-', weight: '-',
        comment: 'OSPF Dynamic Routing', status: 'enable',
        protocol_detail: `Router-ID: ${clishVal(text,'ospf router-id')||'-'}`,
      });
    }

    // BGP
    if (/set bgp\s/im.test(text)) {
      routes.push({
        type: 'bgp', id: 'bgp', dst: 'dynamic', gateway: '-', device: '-',
        as: clishVal(text, 'bgp as') || '-',
        routerId: clishVal(text, 'bgp router-id') || '-',
        distance: '20', priority: '-', weight: '-',
        comment: 'BGP Dynamic Routing', status: 'enable',
        protocol_detail: `AS: ${clishVal(text,'bgp as')||'-'}`,
      });
    }

    return routes;
  }

  // ─── VPN ─────────────────────────────────────────────────────────────────
  function parseVPN(text) {
    const vpns = [];

    // Site-to-site VPN communities (clish/objects)
    // "set vpn site-to-site community <name> ..."
    const commNames = new Set();
    const commRe = /^set\s+vpn\s+(?:site-to-site\s+community|ipsec-vpn)\s+(\S+)\s+/gim;
    // Also: "set vpn ike gateway NAME version|peer|interface ..."
    const ikeGwRe = /^set\s+vpn\s+ike\s+gateway\s+(\S+)\s+(\S+)\s+(\S+)/gim;
    const ikeGws = {};
    let igm;
    while ((igm = ikeGwRe.exec(text)) !== null) {
      const name=igm[1]; const key=igm[2]; const val=igm[3];
      if (!ikeGws[name]) ikeGws[name]={name, peer:'-', iface:'-', ver:'2'};
      if (key==='peer') ikeGws[name].peer=val;
      else if (key==='interface') ikeGws[name].iface=val;
      else if (key==='version') ikeGws[name].ver=val.replace('ikev','');
    }
    Object.values(ikeGws).forEach(gw => {
      if (!commNames.has(gw.name)) {
        commNames.add(gw.name);
        vpns.push({ name:gw.name, type:'ipsec', mode:'main', peer:gw.peer, remote:gw.peer, remotegw:gw.peer, iface:gw.iface, ikeVer:gw.ver, localnet:'-', remotenet:'-', authMethod:'psk', proposal:'-', dhgrp:'-', lifetime:'-', natTraversal:'-', dpd:'-', localId:'-', peerId:gw.peer, cert:'-', monitorConn:'-', autoNeg:'-', status:'enable', phase2:[] });
      }
    });
    let m;
    while ((m = commRe.exec(text)) !== null) commNames.add(m[1]);

    commNames.forEach(name => {
      const prefix = `vpn site-to-site community ${name}`;
      vpns.push({
        type: 'ipsec-p1', name,
        mode:       clishVal(text, `${prefix} type`) || 'star',
        remote:     clishVal(text, `${prefix} peer`) || '-',
        iface:      clishVal(text, `${prefix} interface`) || '-',
        ikeVer:     clishVal(text, `${prefix} ike-version`) || '1',
        authMethod: clishVal(text, `${prefix} auth-method`) || 'psk',
        peertype:   '-',
        proposal:   (clishVal(text,`${prefix} ike-p1-encryption`)||'aes-256') + '-' + (clishVal(text,`${prefix} ike-p1-integrity`)||'sha256'),
        dhgrp:      clishVal(text, `${prefix} ike-p1-dh-group`) || 'group14',
        lifetime:   clishVal(text, `${prefix} ike-p1-lifetime`) || '86400',
        natTraversal: clishVal(text, `${prefix} nat-traversal`) || 'enable',
        dpd:        clishVal(text, `${prefix} dpd`) || '-',
        dpdInterval:clishVal(text, `${prefix} dpd-interval`) || '-',
        localId:    clishVal(text, `${prefix} local-id`) || '-',
        peerId:     clishVal(text, `${prefix} peer-id`) || '-',
        xauthType:  '-',
        cert:       clishVal(text, `${prefix} certificate`) || '-',
        monitorConn:'-',
        autoNeg:    '-',
        status:     'enable',
        phase2: [{
          name:      `${name}-P2`,
          phase1:    name,
          proposal:  (clishVal(text,`${prefix} ike-p2-encryption`)||'aes-256') + '-' + (clishVal(text,`${prefix} ike-p2-integrity`)||'sha256'),
          pfs:       clishVal(text,`${prefix} ike-p2-pfs`) || 'enable',
          dhgrp:     clishVal(text,`${prefix} ike-p2-dh-group`) || 'group14',
          lifetime:  clishVal(text,`${prefix} ike-p2-lifetime`) || '3600',
          replay:    'enable',
          localSub:  clishVal(text,`${prefix} local-encryption-domain`) || '-',
          remoteSub: clishVal(text,`${prefix} peer-encryption-domain`) || '-',
          localAddr: '-', remoteAddr: '-', autoNeg: '-', comment: '-',
        }],
      });
    });

    // Objects .C format: :gateway_cluster or :gateway_plain with VPN
    // 修正：原本用 \Z（JS 正則不支援，等同字面 'Z' 字元）當字串結尾 fallback，
    // 若該物件剛好是檔案最後一段且內容不含字母 Z，會完全解析不到；改用既有慣例 (?![\s\S])
    const vpnGwRe = /:\w+\s*\(\s*([\s\S]*?)(?=:\w+\s*\(|(?![\s\S]))/g;
    while ((m = vpnGwRe.exec(text)) !== null) {
      const body = m[1];
      if (!body.includes(':vpn_') && !body.includes(':ike-')) continue;
      const name = objVal(body, 'Name') || objVal(body, 'name');
      if (!name || commNames.has(name)) continue;
      vpns.push({
        type: 'ipsec-p1', name,
        remote:     objVal(body, 'ipaddr') || '-',
        iface:      '-',
        ikeVer:     objVal(body, 'ike_version') || '1',
        authMethod: objVal(body, 'auth') || 'psk',
        peertype:   '-',
        proposal:   objVal(body, 'ike_p1_encryption') || '-',
        dhgrp:      objVal(body, 'ike_p1_dh_group') || '-',
        lifetime:   objVal(body, 'ike_p1_lifetime') || '86400',
        natTraversal: 'enable', dpd: '-', dpdInterval: '-',
        localId: '-', peerId: '-', xauthType: '-', cert: '-',
        monitorConn: '-', autoNeg: '-', mode: 'tunnel', status: 'enable', phase2: [],
      });
      commNames.add(name);
    }

    // Mobile Access (SSL VPN)
    if (/set mobile-access\s/im.test(text) || /mobile.access.portal/i.test(text)) {
      vpns.push({
        type: 'ssl-vpn',
        name: 'Mobile Access Portal',
        iface: clishVal(text, 'mobile-access interface') || '-',
        remote: '-',
        port: clishVal(text, 'mobile-access port') || '443',
        tunPort: '-',
        addr: clishVal(text, 'mobile-access ip-pool') || '-',
        dns1: '-', dns2: '-', wins1: '-', ipPool: '-',
        algorithm: 'high', dtls: '-', authTimeout: '-',
        ikeVer: '-', authMethod: 'certificate',
        proposal: 'aes-256-sha256', dhgrp: '-', phase2: [], status: 'enable',
      });
    }

    return vpns;
  }

  // ─── Address objects (network objects) ───────────────────────────────────
  function parseAddressObjects(text) {
    const objs = [];

    // Gaia clish: "set network-object host <name> ipaddr <ip>"
    const hostRe = /^set\s+network-object\s+host\s+(\S+)\s+ipaddr\s+(\S+)/gim;
    // Also: "set network NAME ip IP mask MASK" (simpler format)
    const netSimpleRe = /^set\s+network\s+(\S+)\s+ip\s+(\S+)\s+mask\s+(\S+)/gim;
    let nsm;
    while ((nsm = netSimpleRe.exec(text)) !== null) {
      const [,name,ip,mask]=nsm;
      const parts=mask.split('.').map(Number);
      const bits=parts.reduce((n,o)=>n+(o===255?8:o===254?7:o===252?6:o===248?5:o===240?4:o===224?3:o===192?2:o===128?1:0),0);
      if (!objs.find(o=>o.name===name))
        objs.push({category:'address',name,type:'ipmask',subnet:`${ip}/${bits}`,fqdn:'-',startIp:ip,endIp:'-',wildcard:'-',iface:'-',color:'0',comment:'',members:'-',_vdom:''});
    }
    // Also handle: set group NAME type network + set group NAME members X Y
    const addrGrpNames={}; const addrGrpMembers={};
    for (const ln of text.split(/\r?\n/)) {
      const gm=ln.match(/^set\s+group\s+(\S+)\s+type\s+network/i);
      if(gm) addrGrpNames[gm[1]]='network';
      const mm=ln.match(/^set\s+group\s+(\S+)\s+members?\s+(.+)/i);
      if(mm) addrGrpMembers[mm[1]]=(mm[2]||'').trim().split(/\s+/).join(', ');
    }
    Object.entries(addrGrpNames).forEach(([name])=>{
      if(!objs.find(o=>o.name===name))
        objs.push({category:'address-group',name,type:'group',subnet:'-',fqdn:'-',startIp:'-',endIp:'-',wildcard:'-',iface:'-',color:'0',comment:'',members:addrGrpMembers[name]||'-',_vdom:''});
    });
    let m;
    while ((m = hostRe.exec(text)) !== null) {
      objs.push({ category:'address', name:m[1], type:'ipmask',
        subnet:`${m[2]} 255.255.255.255`, fqdn:'-', startIp:m[2], endIp:'-',
        wildcard:'-', iface:'-', color:'0', comment:'-' });
    }

    // "set network-object network <name> ipaddr <ip> mask-length <ml>"
    const netRe = /^set\s+network-object\s+network\s+(\S+)\s+ipaddr\s+(\S+)\s+mask-length\s+(\d+)/gim;
    while ((m = netRe.exec(text)) !== null) {
      objs.push({ category:'address', name:m[1], type:'ipmask',
        subnet:`${m[2]}/${m[3]}`, fqdn:'-', startIp:m[2], endIp:'-',
        wildcard:'-', iface:'-', color:'0', comment:'-' });
    }

    // "set network-object ip-range <name> first-ip <ip> last-ip <ip>"
    const rangeRe = /^set\s+network-object\s+ip-range\s+(\S+)\s+first-ip\s+(\S+)\s+last-ip\s+(\S+)/gim;
    while ((m = rangeRe.exec(text)) !== null) {
      objs.push({ category:'address', name:m[1], type:'iprange',
        subnet:'-', fqdn:'-', startIp:m[2], endIp:m[3],
        wildcard:'-', iface:'-', color:'0', comment:'-' });
    }

    // "set network-object group <name> add <member>"
    const grpNames = new Set();
    const grpMemRe = /^set\s+network-object\s+group\s+(\S+)\s+add\s+(\S+)/gim;
    const grpMembers = {};
    while ((m = grpMemRe.exec(text)) !== null) {
      grpNames.add(m[1]);
      grpMembers[m[1]] = grpMembers[m[1]] || [];
      grpMembers[m[1]].push(m[2]);
    }
    grpNames.forEach(name => {
      objs.push({ category:'address-group', name, type:'group',
        members:(grpMembers[name]||[]).join(', '),
        comment:'-', color:'0' });
    });

    // objects_5_0.C format parsing
    // 修正：同上 \Z 字串結尾 fallback bug，改用 (?![\s\S])
    const cpObjRe = /:\(\s*([\s\S]*?)\)\s*(?=:\(|(?![\s\S]))/g;
    while ((m = cpObjRe.exec(text)) !== null) {
      const body = m[1];
      const cname = objVal(body, 'Name');
      if (!cname) continue;
      const ctype = objVal(body, 'type') || objVal(body, 'Class_Name') || '';
      if (/host_plain|network_object/.test(ctype)) {
        const ip = objVal(body, 'ipaddr');
        const msk = objVal(body, 'netmask');
        if (ip && !objs.find(o => o.name === cname)) {
          objs.push({ category:'address', name:cname, type:msk?'ipmask':'ipmask',
            subnet:`${ip} ${msk||'255.255.255.255'}`, fqdn:'-', startIp:ip, endIp:'-',
            wildcard:'-', iface:'-', color:'0', comment:objVal(body,'comments')||'-' });
        }
      } else if (/address_range/.test(ctype)) {
        if (!objs.find(o => o.name === cname)) {
          objs.push({ category:'address', name:cname, type:'iprange',
            subnet:'-', fqdn:'-',
            startIp:objVal(body,'ipaddr-first')||'-',
            endIp:objVal(body,'ipaddr-last')||'-',
            wildcard:'-', iface:'-', color:'0', comment:objVal(body,'comments')||'-' });
        }
      } else if (/group/.test(ctype)) {
        const mems = objVals(body, 'member');
        if (!objs.find(o => o.name === cname)) {
          objs.push({ category:'address-group', name:cname, type:'group',
            members:mems.join(', ')||'-', comment:objVal(body,'comments')||'-', color:'0' });
        }
      }
    }

    return objs;
  }

  // ─── Service objects ──────────────────────────────────────────────────────
  function parseServiceObjects(text) {
    const svcs = [];

    // Gaia: "set service tcp <name> port <port>"
    const tcpRe = /^set\s+service\s+tcp\s+(\S+)\s+port\s+(\S+)/gim;
    // Also: "set service NAME tcp dst-port PORT" (simpler format)
    const svcSimpleRe = /^set\s+service\s+(\S+)\s+(tcp|udp)\s+(?:dst-port|port)\s+(\S+)/gim;
    let ssm;
    while ((ssm = svcSimpleRe.exec(text)) !== null) {
      const [,name,proto,port]=ssm;
      const pr=proto.toUpperCase();
      if (!svcs.find(s=>s.name===name))
        svcs.push({category:'custom',name,proto:pr,tcpPorts:pr==='TCP'?port:'-',udpPorts:pr==='UDP'?port:'-',icmpType:'-',icmpCode:'-',comment:'',color:'0',category_name:'-',members:'-'});
    }
    let m;
    while ((m = tcpRe.exec(text)) !== null) {
      svcs.push({ category:'custom', name:m[1], proto:'TCP',
        tcpPorts:m[2], udpPorts:'-', icmpType:'-', icmpCode:'-',
        comment:'-', color:'0', category_name:'-' });
    }

    const udpRe = /^set\s+service\s+udp\s+(\S+)\s+port\s+(\S+)/gim;
    while ((m = udpRe.exec(text)) !== null) {
      svcs.push({ category:'custom', name:m[1], proto:'UDP',
        tcpPorts:'-', udpPorts:m[2], icmpType:'-', icmpCode:'-',
        comment:'-', color:'0', category_name:'-' });
    }

    // Service groups
    const svcGrpMems = {};
    const svcGrpRe = /^set\s+service\s+group\s+(\S+)\s+add\s+(\S+)/gim;
    while ((m = svcGrpRe.exec(text)) !== null) {
      svcGrpMems[m[1]] = svcGrpMems[m[1]] || [];
      svcGrpMems[m[1]].push(m[2]);
    }
    Object.keys(svcGrpMems).forEach(name => {
      svcs.push({ category:'group', name, proto:'GROUP',
        tcpPorts:'-', udpPorts:'-', icmpType:'-', icmpCode:'-',
        members:svcGrpMems[name].join(', '), comment:'-' });
    });

    return svcs;
  }

  // ─── Users & Groups ───────────────────────────────────────────────────────
  function parseUsers(text) {
    const users = [];

    // Local admin / users
    const admRe = /^set\s+user\s+(\S+)\s+(?:password|type)\s+(\S+)/gim;
    const seen = new Set();
    let m;
    while ((m = admRe.exec(text)) !== null) {
      if (seen.has(m[1])) continue;
      seen.add(m[1]);
      users.push({
        type: 'local', name: m[1], status: 'enable',
        authType: clishVal(text, `user ${m[1]} type`) || 'password',
        email:    clishVal(text, `user ${m[1]} email`) || '-',
        twoFactor:'disable', twoFType:'-',
        ldapServer:'-', radiusServer:'-',
        comment:  clishVal(text, `user ${m[1]} realname`) || '-',
        members:'-', permissions:[{resource:'All',access:'read-write'}], roles:['admin'], accessLevel:'admin',
      });
    }

    // LDAP account unit
    const ldapRe = /^set\s+ldap[- ]account[- ]unit\s+(\S+)\s+/gim;
    const ldapNames = new Set();
    while ((m = ldapRe.exec(text)) !== null) ldapNames.add(m[1]);
    ldapNames.forEach(name => {
      users.push({
        type: 'ldap-server', name,
        server:  clishVal(text, `ldap-account-unit ${name} server`) || '-',
        port:    clishVal(text, `ldap-account-unit ${name} port`) || '389',
        dn:      clishVal(text, `ldap-account-unit ${name} base-dn`) || '-',
        bindType:clishVal(text, `ldap-account-unit ${name} login-dn`) ? 'regular' : 'anonymous',
        bindDn:  clishVal(text, `ldap-account-unit ${name} login-dn`) || '-',
        cnid:    'cn', groupMember:'-', groupFilter:'-',
        ssl:     clishVal(text, `ldap-account-unit ${name} ssl`) || 'disable',
        comment: '-', status: 'enable', members: '-', permissions:[], roles:[], accessLevel:'auth-server',
      });
    });

    // RADIUS
    const radRe = /^set\s+radius[- ]server\s+(\S+)\s+/gim;
    const radNames = new Set();
    while ((m = radRe.exec(text)) !== null) radNames.add(m[1]);
    radNames.forEach(name => {
      users.push({
        type: 'radius-server', name,
        server:  clishVal(text, `radius-server ${name} server`) || '-',
        port:    clishVal(text, `radius-server ${name} port`) || '1812',
        authType:clishVal(text, `radius-server ${name} auth-type`) || 'auto',
        nasIp:   '-', comment: '-', status: 'enable', members: '-', permissions:[], roles:[], accessLevel:'auth-server',
      });
    });

    // User groups (access roles)
    const grpRe = /^set\s+access-role\s+(\S+)\s+/gim;
    const grpNames = new Set();
    while ((m = grpRe.exec(text)) !== null) grpNames.add(m[1]);
    grpNames.forEach(name => {
      users.push({
        type: 'group', name,
        groupType: 'access-role',
        members:   clishVal(text, `access-role ${name} users`) || '-',
        match: '-', authTimeout: '-', httpDigest: '-', ssoAttrVal: '-',
        comment: '-', status: 'enable',
        permissions:[{resource:'Network',access:'read-write'}], roles:['access-role'], accessLevel:'group',
      });
    });

    return users;
  }

  // ─── Schedules ────────────────────────────────────────────────────────────
  function parseSchedules(text) {
    const scheds = [];
    const re = /^set\s+time\s+(\S+)\s+/gim;
    const names = new Set();
    let m;
    while ((m = re.exec(text)) !== null) names.add(m[1]);
    names.forEach(name => {
      scheds.push({
        type:  clishVal(text, `time ${name} type`) || 'recurring',
        name,
        start: clishVal(text, `time ${name} start`) || '-',
        end:   clishVal(text, `time ${name} end`) || '-',
        day:   clishVal(text, `time ${name} day`) || '-',
        color: '0',
      });
    });
    return scheds;
  }

  // ─── NAT ─────────────────────────────────────────────────────────────────
  function parseNAT(text) {
    const nats = [];
    // "set nat rule <n> ..."
    const natNums = new Set();
    const natRe = /^set\s+nat\s+rule\s+(\d+)\s+/gim;
    let m, idx = 1;
    while ((m = natRe.exec(text)) !== null) natNums.add(m[1]);

    natNums.forEach(n => {
      const prefix = `nat rule ${n}`;
      const xorSrc = clishVal(text, `${prefix} translated-source`);
      const xorDst = clishVal(text, `${prefix} translated-destination`);
      const type   = xorDst ? 'vip' : 'ippool';
      nats.push({
        type,
        name:    `NAT-${n}`,
        vipType: xorDst ? 'static-nat' : 'overload',
        poolType:xorSrc ? 'overload' : '-',
        extIp:   clishVal(text, `${prefix} original-destination`) || '-',
        extIntf: clishVal(text, `${prefix} install-on`) || '-',
        mapIp:   xorDst || xorSrc || '-',
        startIp: xorSrc || '-', endIp: '-',
        portFwd: clishVal(text, `${prefix} translated-service`) ? 'enable' : 'disable',
        extPort: clishVal(text, `${prefix} original-service`) || '-',
        mapPort: clishVal(text, `${prefix} translated-service`) || '-',
        proto:   '-',
        comment: clishVal(text, `${prefix} comments`) || '-',
        status:  clishVal(text, `${prefix} disabled`) === 'true' ? 'disable' : 'enable',
        srcIntf: '-', arpReply: '-',
      });
    });
    return nats;
  }

  // ─── Helper ───────────────────────────────────────────────────────────────
  function guessRole(name) {
    const n = (name || '').toLowerCase();
    if (/eth0|wan|internet|ext|outside|uplink/.test(n)) return 'WAN';
    if (/eth1|lan|inside|internal|trust|intra/.test(n)) return 'LAN';
    if (/dmz|server|srv/.test(n)) return 'DMZ';
    if (/mgmt|manage|oob|admin/.test(n)) return 'MGMT';
    if (/sync|ha|heartbeat/.test(n)) return 'HA';
    if (/vpn|ipsec|ssl/.test(n)) return 'VPN';
    return 'Unknown';
  }

  // ─── Main parse ───────────────────────────────────────────────────────────
  function parse(text) {
    // 位址物件需先解析出來，才能建 addrTypeMap 供 policies 的 source/destination 名稱反查
    // v4/v6 型別（見 _splitAddr() 定義處註解）。注意：parseAddressObjects() 目前只認 IPv4
    // 專屬 Gaia clish 關鍵字（ipaddr/mask-length/first-ip/last-ip），沒有 IPv6 位址物件會被
    // 解析進來，故此反查表對 Check Point 目前仍只能正確分類 v4 物件（已知限制，非本次修法
    // 範圍——查無官方文件佐證 IPv6 對應關鍵字寫法，不可臆測 schema）
    const addresses = parseAddressObjects(text);
    return {
      vendor:     'CheckPoint',
      deviceInfo: parseDeviceInfo(text),
      interfaces: parseInterfaces(text),
      policies:   parsePolicies(text, buildAddrTypeMap(addresses)),
      routes:     parseRoutes(text),
      vpn:        parseVPN(text),
      addresses,
      services:   parseServiceObjects(text),
      schedules:  parseSchedules(text),
      nat:        parseNAT(text),
      users:      parseUsers(text),
      sdwan:      parseSdwan(text),
      dhcp:       parseDhcp(text),
      dns:        parseDns(text),
      snmp:       parseSnmp(text),
      logservers: parseLogServers(text),
    };
  }


  // ── Check Point Link Selection / SD-WAN ───────────────────────────────────

  // ── DHCP Server & Relay ──────────────────────────────────────────────────
  function parseDhcp(text) {
    const servers=[], relays=[], scopes={};
    for(const line of text.split(/\r?\n/)){
      const m=line.match(/^set\s+dhcp-server\s+scope\s+(\S+)\s+(\S+)\s+(.*)/i);
      if(!m) continue;
      const[,name,key,val]=m; if(!scopes[name]) scopes[name]={name};
      const kl=key.toLowerCase();
      if(kl==='ip'){const p=val.split(/\s*-\s*/);scopes[name].startIp=p[0]?.trim()||'-';scopes[name].endIp=p[1]?.trim()||'-';}
      else if(kl==='netmask') scopes[name].mask=val.trim();
      else if(kl==='default-gw'||kl==='gateway') scopes[name].gateway=val.trim();
      else if(kl==='dns') scopes[name].dns1=val.trim();
      else if(kl==='domain') scopes[name].domain=val.trim();
      else if(kl==='lease') scopes[name].lease=val.trim();
      else if(kl==='interface') scopes[name].iface=val.trim();
    }
    Object.values(scopes).forEach(s=>servers.push({name:s.name,iface:s.iface||'-',
      startIp:s.startIp||'-',endIp:s.endIp||'-',gateway:s.gateway||'-',mask:s.mask||'-',
      dns1:s.dns1||'-',dns2:'-',domain:s.domain||'-',lease:s.lease||'86400',status:'enable',comment:''}));
    for(const line of text.split(/\r?\n/)){
      const m=line.match(/^set\s+dhcp-relay\s+server\s+(\S+)(?:\s+interface\s+(\S+))?/i);
      if(m) relays.push({name:'dhcp-relay',iface:m[2]||'-',serverIp:m[1],status:'enable',comment:''});
    }
    return { servers, relays };
  }
  // ── DNS ─────────────────────────────────────────────────────────────────
  function parseDns(text) {
    const result={servers:[],secondaries:[],domain:'-',proxy:false,proxyRules:[],dnsOverTls:false,cacheSize:'-',static:[]};
    const gcp=(key)=>{const m=text.match(new RegExp(`^set\\s+dns\\s+${key}\\s+(\\S+)`,'im'));return m?m[1].trim():'-';};
    const pri=gcp('primary'); if(pri!=='-') result.servers.push(pri);
    const sec=gcp('secondary'); if(sec!=='-') result.secondaries.push(sec);
    const dom=gcp('suffix')||gcp('domain'); if(dom!=='-') result.domain=dom;
    if(/set\s+dns\s+over-https\s+enable/i.test(text)) result.dnsOverTls=true;
    for(const m of text.matchAll(/^set\s+dns\s+forwarder\s+(\S+)\s+(\S+)/gim))
      result.proxyRules.push({domain:m[1],target:m[2]});
    if(result.proxyRules.length) result.proxy=true;
    return result;
  }


  // ── SNMP ────────────────────────────────────────────────────────────────────
  function parseSnmp(text) {
    const result = { enabled:false, agent:{name:'-',description:'-',location:'-',contact:'-',version:[]}, communities:[], v3users:[], trapServers:[] };
    if (!/set\s+snmp\s+agent\s+on/i.test(text)) return result;
    result.enabled = true;
    const gcp = (key) => { const m=text.match(new RegExp(`^set\\s+snmp\\s+${key.replace(/[-]/g,'\\-')}\\s+(.+)`,'im')); return m?m[1].trim().replace(/^"|"$/g,''):'-'; };
    result.agent.contact  = gcp('contact');
    result.agent.location = gcp('location');
    result.agent.name     = gcp('hostname')||gcp('agent-name')||'-';
    const ver = gcp('agent-version')||'any';
    if (ver==='any'||ver.includes('2')) result.agent.version.push('v2c');
    if (ver==='any'||ver.includes('1')) result.agent.version.push('v1');
    // Communities
    const commRe=/^set\s+snmp\s+community\s+"?([^"\s]+)"?\s+(read-only|read-write)/gim;
    let cm; const seen=new Set();
    while((cm=commRe.exec(text))!==null){
      const name=cm[1]; if(seen.has(name))continue; seen.add(name);
      const hosts=[...text.matchAll(new RegExp(`set\\s+snmp\\s+community\\s+"?${name}"?\\s+allowed-client\\s+(\\S+)`,'gim'))].map(m=>m[1]);
      result.communities.push({ name, permission:cm[2]==='read-only'?'ro':'rw', allowedHosts:hosts, events:'-', status:'enable' });
    }
    // Trap servers
    const trapRe=/^set\s+snmp\s+traps\s+trap-usm\s+(.+)/im;
    // v3 users
    const v3Re=/^set\s+snmp\s+v3\s+user\s+"?([^"\s]+)"?/gim; let v3m;
    while((v3m=v3Re.exec(text))!==null){
      const uname=v3m[1];
      const auth=text.match(new RegExp(`snmp\\s+v3\\s+user\\s+"?${uname}"?\\s+auth-protocol\\s+(\\S+)`,'i'))?.[1]||'sha';
      const priv=text.match(new RegExp(`snmp\\s+v3\\s+user\\s+"?${uname}"?\\s+priv-protocol\\s+(\\S+)`,'i'))?.[1]||'aes';
      result.v3users.push({ name:uname, authProto:auth, privProto:priv, secLevel:'auth-priv', notifyHost:'-', status:'enable' });
      if(!result.agent.version.includes('v3')) result.agent.version.push('v3');
    }
    // Trap targets
    for(const m of text.matchAll(/^set\s+snmp\s+traps?\s+(?:trap-)?target\s+(\S+)/gim)) result.trapServers.push({ ip:m[1], port:'162', community:result.communities[0]?.name||'-', version:'v2c' });
    return result;
  }

  // ── Log Servers ──────────────────────────────────────────────────────────────
  function parseLogServers(text) {
    const result = { syslog:[], fortianalyzer:[], netflow:[], logForward:[] };
    if (!/set\s+syslog\s+on/i.test(text)) return result;
    const gcp=(key)=>{ const m=text.match(new RegExp(`^set\\s+syslog\\s+${key}\\s+(\\S+)`,'im')); return m?m[1].trim():'-'; };
    const server=gcp('server'); const port=gcp('port')||'514'; const fac=gcp('facility')||'local7';
    const proto=gcp('tcp')||gcp('udp'); const relProto=/tcp/i.test(proto)?'TCP':'UDP';
    if(server!=='-') result.syslog.push({ name:'Syslog1', server, port, facility:fac, format:'default', protocol:relProto, level:'information', status:'enable' });
    // Additional log-server lines
    for(const m of text.matchAll(/^set\s+log-server\s+(\S+)\s+(\d+)/gim)) result.syslog.push({ name:`LogServer`, server:m[1], port:m[2], facility:'local7', format:'default', protocol:'UDP', level:'information', status:'enable' });
    return result;
  }

  function parseSdwan(text) {
    const result = { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] };

    // Check Point link selection is in "set link-selection" CLI commands
    const lsLines = text.split(/\r?\n/).filter(l => /set\s+link-selection/i.test(l));
    if (!lsLines.length) return result;
    result.enabled = true;

    const gv2 = (lines, key) => {
      const re = new RegExp(`set\\s+link-selection\\s+${key}\\s+(\\S+)`, 'i');
      for (const l of lines) { const m = l.match(re); if (m) return m[1]; }
      return '-';
    };

    const method   = gv2(lsLines, 'probing-method') || gv2(lsLines, 'method') || 'icmp';
    const primary  = gv2(lsLines, 'primary-interface');
    const backup   = gv2(lsLines, 'backup-interface');
    const failover = gv2(lsLines, 'failover-condition');
    result.lbMode = backup !== '-' ? 'priority' : 'source-ip-based';

    // Extract interface entries
    [primary, backup].filter(i => i !== '-').forEach((iface, idx) => {
      result.members.push({
        id: String(idx + 1), iface, zone: idx === 0 ? 'primary' : 'backup',
        gateway: '-', gateway6: '-',
        priority: idx === 0 ? 1 : 10,
        weight: 1, cost: 0, spillover: 0, volumeRatio: 1,
        status: 'enable', comment: idx === 0 ? 'Primary link' : 'Backup link',
      });
    });

    // Probing = health check
    const probeTarget = gv2(lsLines, 'probing-target') || gv2(lsLines, 'probe-target');
    if (probeTarget !== '-' || method !== '-') {
      result.healthChecks.push({
        name: 'LinkProbe', server: probeTarget !== '-' ? probeTarget : '8.8.8.8',
        protocol: method, port: '-',
        interval: gv2(lsLines, 'interval') || '30',
        timeout:  gv2(lsLines, 'timeout')  || '10',
        failtime: gv2(lsLines, 'retries')  || '3',
        recoverytime: '3', probePackets: '3', http200Only: 'disable',
        members: 'all', slaThresholds: [],
      });
    }

    // Service rule: simple failover policy
    result.services.push({
      id: '1', name: 'Link_Selection_Policy',
      mode: backup !== '-' ? 'priority' : 'load-balance',
      src: 'all', dst: 'all',
      srcNegate: 'disable', dstNegate: 'disable', users: '-',
      protocol: '0', startPort: '-', endPort: '-',
      priorityMembers: [primary, backup].filter(i=>i!=='-').join(', ') || '-',
      priorityZone: '-', preferredUplink: primary !== '-' ? primary : '-',
      slaCompare: 'order', tie: 'zone', slaRefs: [], inputDevice: '-',
      status: 'enable',
      comment: `Failover condition: ${failover}`,
    });

    return result;
  }

  return { parse };
})();


