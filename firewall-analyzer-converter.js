// ═══ converter.js ═══
/**
 * Firewall Configuration Converter v4.0
 * Supports 6 vendors × 30 conversion paths:
 * FortiGate ↔ Sophos ↔ Check Point ↔ Palo Alto ↔ Juniper SRX ↔ pfSense
 */
const Converter = (() => {

  // ── Shared utilities ──────────────────────────────────────────────────────
  const esc = s => String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const sl  = str => (!str||str==='-'||/^(any|all)$/i.test(str.trim()))?[]:str.split(/,\s*/).map(s=>s.trim()).filter(Boolean);
  const now = () => new Date().toISOString().slice(0,19).replace('T',' ');
  const hdr = (f,t,h) => `Converted from ${f} to ${t} | Source: ${h} | ${now()}`;

  function bits(mask) {
    if (!mask||mask==='-') return 32;
    if (/^\d+$/.test(String(mask))) return parseInt(mask);
    return String(mask).split('.').reduce((n,o)=>{
      let b=parseInt(o)>>>0, c=0;
      while(b){b&=(b-1);c++;} return n+c;
    }, 0);
  }
  function maskOf(b) {
    const bi=parseInt(b);
    const n=bi<=0?0:(0xFFFFFFFF<<(32-bi))>>>0;
    return [(n>>>24)&0xFF,(n>>>16)&0xFF,(n>>>8)&0xFF,n&0xFF].join('.');
  }
  function cidr(ip,mask) {
    if (!ip||ip==='-'||ip==='DHCP') return '0.0.0.0/0';
    const b=mask?(mask.includes('.')?bits(mask):mask):32;
    return ip+'/'+b;
  }
  // 2026-07-24 新增：位址物件的 a.subnet 來源格式不一定是 CIDR，也可能是「IP 空白 遮罩」
  // 空格分隔格式；部分轉換函式（如原本的 toPaloAlto）曾直接對非 CIDR 字串尾端加 "/32"，
  // 產生「192.168.1.0 255.255.255.0/32」這種畸形值。統一用此 helper 正確判斷格式後轉真正 CIDR，
  // 保證回傳值必定是合法的 "ip/bits" 形式
  function addrCidr(a){
    const sub=a.subnet;
    if(sub){
      if(sub.includes('/')) return sub;
      if(sub.includes(' ')){ const p=sub.trim().split(/\s+/); return cidr(p[0],p[1]); }
      return sub+'/32';
    }
    return (a.ip&&a.ip!=='-'&&a.ip!=='DHCP')?a.ip+'/32':'0.0.0.0/0';
  }
  // 各廠牌路由的網段+遮罩來源形狀不一（CIDR「IP/prefix」、CIDR-with-dotted-mask「IP/255.x」、
  // 空白分隔「網段 遮罩」、獨立欄位 r.mask），統一還原成 {net,mask}（dotted mask）
  function netMaskOf(dst, maskField) {
    if (maskField && maskField !== '-') return { net: dst, mask: maskField.includes('.') ? maskField : maskOf(maskField) };
    const s = (dst || '0.0.0.0/0').trim();
    if (s.includes('/')) { const [net, pfx] = s.split('/'); return { net, mask: pfx.includes('.') ? pfx : maskOf(pfx) }; }
    const parts = s.split(/\s+/);
    return parts.length >= 2 ? { net: parts[0], mask: parts[1] } : { net: s, mask: '255.255.255.255' };
  }

  // Parse "aes256-sha256" / "aes-256-cbc" → [enc, hash]
  function splitProp(prop) {
    if (!prop||prop==='-') return ['aes256','sha256'];
    const p=prop.toLowerCase().replace(/[\s\-]/g,'');
    const h=(p.match(/(sha512|sha384|sha256|sha1|md5)/)||[])[1]||'sha256';
    const e=(p.match(/(aes256gcm|aes128gcm|aes256|aes192|aes128|3des|des)/)||[])[1]||'aes256';
    return [e,h];
  }

  // Normalize encryption/hash for each vendor
  const ENC = {
    fortigate: {aes256gcm:'aes256gcm',aes128gcm:'aes128gcm',aes256:'aes256',aes192:'aes192',aes128:'aes128','3des':'3des',des:'des'},
    sophos:    {aes256gcm:'AES256GCM', aes128gcm:'AES128GCM', aes256:'AES256',aes192:'AES192',aes128:'AES128','3des':'3DES',des:'DES'},
    checkpoint:{aes256gcm:'AES-256-GCM',aes128gcm:'AES-128-GCM',aes256:'AES-256',aes192:'AES-192',aes128:'AES-128','3des':'3DES',des:'DES'},
    paloalto:  {aes256gcm:'aes-256-gcm',aes128gcm:'aes-128-gcm',aes256:'aes-256-cbc',aes192:'aes-192-cbc',aes128:'aes-128-cbc','3des':'3des',des:'des'},
    juniper:   {aes256gcm:'aes-256-gcm',aes128gcm:'aes-128-gcm',aes256:'aes-256-cbc',aes192:'aes-192-cbc',aes128:'aes-128-cbc','3des':'3des-cbc',des:'des-cbc'},
    pfsense:   {aes256gcm:'aes256gcm',  aes128gcm:'aes128gcm',  aes256:'aes256',  aes192:'aes192', aes128:'aes128', '3des':'3des', des:'des'},
    ciscoasa:  {aes256gcm:'aes-gcm-256',aes128gcm:'aes-gcm',aes256:'aes-256',aes192:'aes-192',aes128:'aes',   '3des':'3des',des:'des'},
    sonicwall: {aes256gcm:'AES-256',    aes128gcm:'AES-128',aes256:'AES-256',aes192:'AES-192',aes128:'AES-128','3des':'3DES',des:'DES'},
    mikrotik:  {aes256gcm:'aes-256-gcm',aes128gcm:'aes-128-gcm',aes256:'aes-256-cbc',aes192:'aes-192-cbc',aes128:'aes-128-cbc','3des':'3des',des:'des-cbc'},
  };
  const HASH = {
    fortigate: {sha512:'sha512',sha384:'sha384',sha256:'sha256',sha1:'sha1',md5:'md5'},
    sophos:    {sha512:'SHA512',sha384:'SHA384',sha256:'SHA256',sha1:'SHA1',md5:'MD5'},
    checkpoint:{sha512:'SHA-512',sha384:'SHA-384',sha256:'SHA-256',sha1:'SHA-1',md5:'MD5'},
    paloalto:  {sha512:'sha512',sha384:'sha384',sha256:'sha256',sha1:'sha1',md5:'md5'},
    juniper:   {sha512:'sha-512',sha384:'sha-384',sha256:'sha-256',sha1:'sha-1',md5:'md5'},
    pfsense:   {sha512:'sha512',sha384:'sha384',sha256:'sha256',sha1:'sha1',md5:'md5'},
    ciscoasa:  {sha512:'sha-512',sha384:'sha-384',sha256:'sha-256',sha1:'sha',md5:'md5'},
    sonicwall: {sha512:'SHA512',sha384:'SHA384',sha256:'SHA256',sha1:'SHA1',md5:'MD5'},
    mikrotik:  {sha512:'sha512',sha384:'sha384',sha256:'sha256',sha1:'sha1',md5:'md5'},
  };
  const DH = {
    fortigate: {1:'1',2:'2',5:'5',14:'14',19:'19',20:'20',21:'21'},
    sophos:    {1:'Group1',2:'Group2',5:'Group5',14:'Group14',19:'Group19',20:'Group20',21:'Group21'},
    checkpoint:{1:'group1',2:'group2',5:'group5',14:'group14',19:'group19',20:'group20',21:'group21'},
    paloalto:  {1:'group1',2:'group2',5:'group5',14:'group14',19:'group19',20:'group20',21:'group21'},
    juniper:   {1:'group1',2:'group2',5:'group5',14:'group14',19:'group19',20:'group20',21:'group21'},
    pfsense:   {1:'1',2:'2',5:'5',14:'14',19:'19',20:'20',21:'21'},
    ciscoasa:  {1:'1',2:'2',5:'5',14:'14',19:'19',20:'20',21:'21'},
    sonicwall: {1:'Group1',2:'Group2',5:'Group5',14:'Group14',19:'Group19',20:'Group20',21:'Group21'},
    mikrotik:  {1:'modp768',2:'modp1024',5:'modp1536',14:'modp2048',19:'ecp256',20:'ecp384',21:'ecp521'},
  };

  function normEnc(enc, target) {
    const e=(enc||'aes256').toLowerCase().replace(/[\s\-_]/g,'');
    const map=ENC[target]||ENC.fortigate;
    for(const k of Object.keys(map)){if(e===k||e.includes(k))return map[k];}
    return map.aes256||'aes256';
  }
  function normHash(hash, target) {
    const h=(hash||'sha256').toLowerCase().replace(/[\s\-_]/g,'');
    const map=HASH[target]||HASH.fortigate;
    for(const k of Object.keys(map)){if(h===k||h.includes(k))return map[k];}
    return map.sha256||'sha256';
  }
  function normDH(dh, target) {
    let d=String(dh||'14').replace(/[^0-9]/g,'');
    // 2026-07-24 修復：來源值完全無法解析出數字時（如非標準命名）d 會變成空字串，導致輸出
    // "group "（後面空白），退回所有目標廠牌 DH 對照表皆有收錄的 group 2（業界最通用值）
    if(!d) d='2';
    return (DH[target]||DH.fortigate)[d]||d;
  }

  // Role → zone/interface mapping
  const ZONE = {
    juniper:   {WAN:'untrust',LAN:'trust',DMZ:'dmz',MGMT:'management',HA:'ha',VPN:'vpn',VLAN:'trust',Unknown:'trust'},
    pfsense:   {WAN:'wan',LAN:'lan',DMZ:'opt1',MGMT:'opt2',HA:'opt3',VPN:'opt4',VLAN:'opt5',Unknown:'opt9'},
    paloalto:  {WAN:'untrust',LAN:'trust',DMZ:'dmz',MGMT:'management',HA:'ha',VPN:'vpn',VLAN:'trust',Unknown:'trust'},
    checkpoint:{WAN:'External',LAN:'Internal',DMZ:'DMZ',MGMT:'Management',HA:'HA',VPN:'VPN',VLAN:'Internal',Unknown:'Internal'},
    sophos:    {WAN:'WAN',LAN:'LAN',DMZ:'DMZ',MGMT:'MGMT',HA:'HA',VPN:'VPN',VLAN:'LAN',Unknown:'LAN'},
    fortigate: {WAN:'wan',LAN:'lan',DMZ:'dmz',MGMT:'management',HA:'ha',VPN:'vpn',VLAN:'vlan',Unknown:'unknown'},
    ciscoasa:  {WAN:'outside',LAN:'inside',DMZ:'dmz',MGMT:'management',HA:'ha',VPN:'vpn',VLAN:'inside',Unknown:'inside'},
    sonicwall: {WAN:'WAN',LAN:'LAN',DMZ:'DMZ',MGMT:'MGMT',HA:'HA',VPN:'VPN',VLAN:'LAN',Unknown:'LAN'},
  };
  function mapZone(roleOrZone, target) {
    const r=(roleOrZone||'').toUpperCase();
    // Direct role lookup
    const byRole=(ZONE[target]||{})[r];
    if(byRole) return byRole;
    // Heuristic from zone name
    const z=(roleOrZone||'').toLowerCase();
    if(/wan|untrust|outside|ext|internet/.test(z)) return (ZONE[target]||{}).WAN||z;
    if(/lan|trust|inside|internal/.test(z))         return (ZONE[target]||{}).LAN||z;
    if(/dmz|server|srv/.test(z))                    return (ZONE[target]||{}).DMZ||z;
    if(/mgmt|manage|oob/.test(z))                   return (ZONE[target]||{}).MGMT||z;
    if(/vpn|ipsec/.test(z))                         return (ZONE[target]||{}).VPN||z;
    return roleOrZone||'any';
  }
  function mapAction(action, target) {
    const ok=(action||'').toLowerCase()==='accept'||(action||'').toLowerCase()==='allow';
    return {fortigate:ok?'accept':'deny',sophos:ok?'Accept':'Drop',checkpoint:ok?'accept':'drop',
            paloalto:ok?'allow':'deny',juniper:ok?'permit':'deny',pfsense:ok?'pass':'block',
            ciscoasa:ok?'permit':'deny',sonicwall:ok?'allow':'deny',mikrotik:ok?'accept':'drop',
            zyxel:ok?'allow':'deny',edgerouter:ok?'accept':'drop',openwrt:ok?'ACCEPT':'REJECT'}[target]||(ok?'accept':'deny');
  }

  const I = n => '    '.repeat(n);

  // ── XML block builder (for Sophos, Palo Alto, pfSense) ───────────────────
  function xml(tag, content, indent=0, attrs='') {
    const p=I(indent);
    if (typeof content === 'string' && !content.includes('\n'))
      return `${p}<${tag}${attrs}>${content}</${tag}>`;
    return `${p}<${tag}${attrs}>\n${content}\n${p}</${tag}>`;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → FortiGate
  // ══════════════════════════════════════════════════════════════════════════
  function toFortigate(parsed) {
    const L=[], d=parsed.deviceInfo;
    L.push(`#config-version=FGT100F-7.4.0-FW-build0001:opmode=0:vdom=0`);
    L.push(`## ${hdr(parsed.vendor||'?','FortiGate 7.4',d.hostname)}`);
    L.push('');
    L.push('config system global');
    L.push(`    set hostname "${d.hostname}"`);
    L.push('end');
    L.push('');

    // accprofile
    L.push('config system accprofile');
    L.push('    edit "prof_admin"');
    L.push('        set sysgrp read-write');
    L.push('        set netgrp read-write');
    L.push('        set fwgrp read-write');
    L.push('        set vpngrp read-write');
    L.push('        set loggrp read-write');
    L.push('    next');
    L.push('    edit "prof_readonly"');
    L.push('        set sysgrp read');
    L.push('        set netgrp read');
    L.push('        set fwgrp read');
    L.push('    next');
    L.push('end');
    L.push('');

    // admins
    const admins=parsed.users.filter(u=>u.type==='admin');
    if(admins.length) {
      L.push('config system admin');
      admins.forEach(u=>{
        L.push(`    edit "${u.name}"`);
        const prof=u.accessLevel==='read-only'?'prof_readonly':'prof_admin';
        L.push(`        set accprofile "${prof}"`);
        L.push('        set vdom "root"');
        if(u.email&&u.email!=='-') L.push(`        set email-to "${u.email}"`);
        if(u.twoFactor&&u.twoFactor!=='disable') L.push(`        set two-factor fortitoken`);
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    // local users
    const lusers=parsed.users.filter(u=>u.type==='local');
    if(lusers.length) {
      L.push('config user local');
      lusers.forEach(u=>{
        L.push(`    edit "${u.name}"`);
        L.push(`        set type password`);
        if(u.email&&u.email!=='-') L.push(`        set email-to "${u.email}"`);
        if(u.twoFactor&&u.twoFactor!=='disable') L.push(`        set two-factor fortitoken`);
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    // LDAP
    parsed.users.filter(u=>u.type==='ldap-server').forEach((u,i)=>{
      if(i===0) L.push('config user ldap');
      L.push(`    edit "${u.name}"`);
      L.push(`        set server "${u.server||'-'}"`);
      L.push(`        set port ${u.port||389}`);
      if(u.dn&&u.dn!=='-') L.push(`        set dn "${u.dn}"`);
      if(u.bindDn&&u.bindDn!=='-') { L.push(`        set bind-type regular`); L.push(`        set username "${u.bindDn}"`); }
      L.push('    next');
      if(i===parsed.users.filter(u=>u.type==='ldap-server').length-1) { L.push('end'); L.push(''); }
    });

    // RADIUS
    parsed.users.filter(u=>u.type==='radius-server').forEach((u,i)=>{
      if(i===0) L.push('config user radius');
      L.push(`    edit "${u.name}"`);
      L.push(`        set server "${u.server||'-'}"`);
      L.push(`        set auth-port ${u.port||1812}`);
      L.push('    next');
      if(i===parsed.users.filter(u=>u.type==='radius-server').length-1) { L.push('end'); L.push(''); }
    });

    // user groups
    const grps=parsed.users.filter(u=>u.type==='group');
    if(grps.length) {
      L.push('config user group');
      grps.forEach(g=>{
        L.push(`    edit "${g.name}"`);
        L.push(`        set group-type ${g.groupType==='access'?'firewall':g.groupType||'firewall'}`);
        if(g.members&&g.members!=='-') {
          const mems=sl(g.members).map(m=>`"${m}"`).join(' ');
          L.push(`        set member ${mems}`);
        }
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    // interfaces
    if(parsed.interfaces.length) {
      L.push('config system interface');
      parsed.interfaces.forEach(i=>{
        L.push(`    edit "${i.name}"`);
        L.push(`        set vdom "root"`);
        if(i.ip&&i.ip!=='-'&&i.ip!=='DHCP') L.push(`        set ip ${i.ip} ${i.mask&&i.mask!=='-'?i.mask:'255.255.255.0'}`);
        // 次要IP（2026-08-18 補上輸出端，官方 FortiOS CLI Reference 巢狀 config secondaryip／
        // edit N／set ip A B，與 firewall-analyzer-parser-fortigate.js 既有解析語法對稱）
        if(i.secondaryIps&&i.secondaryIps.length){
          L.push('        config secondaryip');
          i.secondaryIps.forEach((s,idx)=>{
            L.push(`            edit ${idx+1}`);
            L.push(`                set ip ${s.ip} ${s.mask&&s.mask!=='-'?s.mask:'255.255.255.0'}`);
            L.push('            next');
          });
          L.push('        end');
        }
        if(i.type==='vlan') { L.push(`        set type vlan`); if(i.vlanId&&i.vlanId!=='-') L.push(`        set vlanid ${i.vlanId}`); if(i.interface&&i.interface!=='-') L.push(`        set interface "${i.interface}"`); }
        else L.push(`        set type ${i.type||'physical'}`);
        if(i.alias&&i.alias!=='-') L.push(`        set alias "${i.alias}"`);
        if(i.desc&&i.desc!=='-'&&i.desc!==i.alias) L.push(`        set description "${i.desc}"`);
        if(i.mtu&&i.mtu!=='1500') L.push(`        set mtu ${i.mtu}`);
        const role=i.role||'Unknown';
        if(role==='WAN') L.push(`        set role wan`);
        else if(role==='LAN') L.push(`        set role lan`);
        else if(role==='DMZ') L.push(`        set role dmz`);
        if(i.status==='down'||i.status==='Disable') L.push('        set status down');
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    // address objects
    const addrs=parsed.addresses.filter(a=>a.category==='address');
    if(addrs.length) {
      L.push('config firewall address');
      addrs.forEach(a=>{
        L.push(`    edit "${a.name}"`);
        if(a.type==='fqdn') { L.push('        set type fqdn'); L.push(`        set fqdn "${a.fqdn}"`); }
        else if(a.type==='iprange') { L.push('        set type iprange'); L.push(`        set start-ip ${a.startIp}`); L.push(`        set end-ip ${a.endIp}`); }
        else {
          const sub=a.subnet||(a.ip&&a.mask?`${a.ip} ${a.mask}`:a.ip?`${a.ip} 255.255.255.255`:'0.0.0.0 0.0.0.0');
          const subFmt=sub.includes('/')?sub.replace('/',` ${maskOf(sub.split('/')[1])}`):sub;
          L.push(`        set type ipmask`); L.push(`        set subnet ${subFmt}`);
        }
        if(a.comment&&a.comment!=='-') L.push(`        set comment "${a.comment}"`);
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    // address groups
    const agrps=parsed.addresses.filter(a=>a.category==='address-group');
    if(agrps.length) {
      L.push('config firewall addrgrp');
      agrps.forEach(g=>{
        L.push(`    edit "${g.name}"`);
        const mems=sl(g.members).map(m=>`"${m}"`).join(' ');
        if(mems) L.push(`        set member ${mems}`);
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    // services
    const csvcs=parsed.services.filter(s=>s.category==='custom');
    if(csvcs.length) {
      L.push('config firewall service custom');
      csvcs.forEach(s=>{
        L.push(`    edit "${s.name}"`);
        const p=(s.proto||'TCP').toUpperCase();
        if(p.includes('ICMP')) { L.push('        set protocol ICMP'); if(s.icmpType&&s.icmpType!=='-') L.push(`        set icmptype ${s.icmpType}`); }
        else { L.push('        set protocol TCP/UDP'); if(s.tcpPorts&&s.tcpPorts!=='-') L.push(`        set tcp-portrange ${s.tcpPorts}`); if(s.udpPorts&&s.udpPorts!=='-') L.push(`        set udp-portrange ${s.udpPorts}`); }
        if(s.comment&&s.comment!=='-') L.push(`        set comment "${s.comment}"`);
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    const sgrps=parsed.services.filter(s=>s.category==='group');
    if(sgrps.length) {
      L.push('config firewall service group');
      sgrps.forEach(g=>{
        L.push(`    edit "${g.name}"`);
        const mems=sl(g.members).map(m=>`"${m}"`).join(' ');
        if(mems) L.push(`        set member ${mems}`);
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    // schedules
    const rscheds=parsed.schedules.filter(s=>s.type==='recurring');
    if(rscheds.length) {
      L.push('config firewall schedule recurring');
      rscheds.forEach(s=>{ L.push(`    edit "${s.name}"`); if(s.day&&s.day!=='-') L.push(`        set day ${s.day}`); if(s.start) L.push(`        set start ${s.start}`); if(s.end) L.push(`        set end ${s.end}`); L.push('    next'); });
      L.push('end'); L.push('');
    }

    // static routes
    const sroutes=parsed.routes.filter(r=>r.type==='static'||r.type==='default');
    if(sroutes.length) {
      L.push('config router static');
      sroutes.forEach((r,i)=>{
        L.push(`    edit ${i+1}`);
        const dst=r.dst.includes('/')?r.dst.replace('/',` ${maskOf(r.dst.split('/')[1])}`):r.dst;
        L.push(`        set dst ${dst}`);
        if(r.gateway&&r.gateway!=='-'&&r.gateway!=='blackhole') L.push(`        set gateway ${r.gateway}`);
        if(r.device&&r.device!=='-') L.push(`        set device "${r.device}"`);
        if(r.blackhole==='enable') L.push('        set blackhole enable');
        if(r.distance&&r.distance!=='-') L.push(`        set distance ${r.distance}`);
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    // static6 routes（IPv6，2026-08-20 新增；官方 CLI Reference 確認 dst 直接用 CIDR 表示，
    // 不像 IPv4 需轉換成點分遮罩，其餘欄位與 IPv4 static route 相同）
    const sroutes6=parsed.routes.filter(r=>r.type==='static6');
    if(sroutes6.length) {
      L.push('config router static6');
      sroutes6.forEach((r,i)=>{
        L.push(`    edit ${i+1}`);
        L.push(`        set dst ${r.dst}`);
        if(r.gateway&&r.gateway!=='-'&&r.gateway!=='blackhole') L.push(`        set gateway ${r.gateway}`);
        if(r.device&&r.device!=='-') L.push(`        set device "${r.device}"`);
        if(r.blackhole==='enable') L.push('        set blackhole enable');
        if(r.distance&&r.distance!=='-') L.push(`        set distance ${r.distance}`);
        L.push('    next');
      });
      L.push('end'); L.push('');
    }

    // OSPF
    const ospf=parsed.routes.find(r=>r.type==='ospf');
    if(ospf) { L.push('config router ospf'); if(ospf.routerId) L.push(`    set router-id ${ospf.routerId}`); L.push('end'); L.push(''); }

    // BGP
    const bgp=parsed.routes.find(r=>r.type==='bgp');
    if(bgp) { L.push('config router bgp'); L.push(`    set as ${bgp.as||65000}`); if(bgp.routerId) L.push(`    set router-id ${bgp.routerId}`); L.push('end'); L.push(''); }

    // NAT (IP pools)
    const ippools=parsed.nat.filter(n=>n.type==='ippool');
    if(ippools.length) {
      L.push('config firewall ippool');
      ippools.forEach(n=>{ L.push(`    edit "${n.name}"`); L.push(`        set type ${n.poolType||'overload'}`); if(n.startIp&&n.startIp!=='-') { L.push(`        set startip ${n.startIp}`); L.push(`        set endip ${n.endIp&&n.endIp!=='-'?n.endIp:n.startIp}`); } L.push('    next'); });
      L.push('end'); L.push('');
    }

    // VIPs
    const vips=parsed.nat.filter(n=>n.type==='vip');
    if(vips.length) {
      L.push('config firewall vip');
      vips.forEach(n=>{ L.push(`    edit "${n.name}"`); if(n.extIp&&n.extIp!=='-') L.push(`        set extip ${n.extIp}`); if(n.extIntf&&n.extIntf!=='-') L.push(`        set extintf "${n.extIntf}"`); if(n.mapIp&&n.mapIp!=='-') L.push(`        set mappedip ${n.mapIp}`); if(n.portFwd==='enable') { L.push('        set portforward enable'); if(n.extPort) L.push(`        set extport ${n.extPort}`); if(n.mapPort) L.push(`        set mappedport ${n.mapPort}`); if(n.proto) L.push(`        set protocol ${n.proto}`); } L.push('    next'); });
      L.push('end'); L.push('');
    }

    // VIP Group（vipgrp／vipgrp6，2026-08-21 新增；官方 Fortinet schema 確認欄位名稱
    // interface/member/comments，vipgrp6 無 interface 欄位）
    const vipgrps=parsed.nat.filter(n=>n.type==='vipgrp');
    if(vipgrps.length) {
      L.push('config firewall vipgrp');
      vipgrps.forEach(n=>{ L.push(`    edit "${n.name}"`); if(n.extIntf&&n.extIntf!=='-') L.push(`        set interface "${n.extIntf}"`); const ms=sl(n.members); if(ms.length) L.push(`        set member ${ms.map(m=>`"${m}"`).join(' ')}`); if(n.comment&&n.comment!=='-') L.push(`        set comments "${n.comment}"`); L.push('    next'); });
      L.push('end'); L.push('');
    }

    // IPv6 NAT66（ippool6/vip6/vipgrp6，官方 CLI Reference 確認欄位名稱與 IPv4 版本幾乎相同）
    const ippools6=parsed.nat.filter(n=>n.type==='ippool6');
    if(ippools6.length) {
      L.push('config firewall ippool6');
      ippools6.forEach(n=>{ L.push(`    edit "${n.name}"`); if(n.startIp&&n.startIp!=='-') { L.push(`        set startip ${n.startIp}`); L.push(`        set endip ${n.endIp&&n.endIp!=='-'?n.endIp:n.startIp}`); } L.push('    next'); });
      L.push('end'); L.push('');
    }
    const vips6=parsed.nat.filter(n=>n.type==='vip6');
    if(vips6.length) {
      L.push('config firewall vip6');
      vips6.forEach(n=>{ L.push(`    edit "${n.name}"`); if(n.extIp&&n.extIp!=='-') L.push(`        set extip ${n.extIp}`); if(n.extIntf&&n.extIntf!=='-') L.push(`        set extintf "${n.extIntf}"`); if(n.mapIp&&n.mapIp!=='-') L.push(`        set mappedip ${n.mapIp}`); if(n.portFwd==='enable') { L.push('        set portforward enable'); if(n.extPort) L.push(`        set extport ${n.extPort}`); if(n.mapPort) L.push(`        set mappedport ${n.mapPort}`); if(n.proto) L.push(`        set protocol ${n.proto}`); } L.push('    next'); });
      L.push('end'); L.push('');
    }
    const vipgrps6=parsed.nat.filter(n=>n.type==='vipgrp6');
    if(vipgrps6.length) {
      L.push('config firewall vipgrp6');
      vipgrps6.forEach(n=>{ L.push(`    edit "${n.name}"`); const ms=sl(n.members); if(ms.length) L.push(`        set member ${ms.map(m=>`"${m}"`).join(' ')}`); if(n.comment&&n.comment!=='-') L.push(`        set comments "${n.comment}"`); L.push('    next'); });
      L.push('end'); L.push('');
    }

    // IPSec VPN
    const ivpns=parsed.vpn.filter(v=>v.type==='ipsec-p1');
    if(ivpns.length) {
      L.push('config vpn ipsec phase1-interface');
      ivpns.forEach(v=>{
        const [e,h]=splitProp(v.proposal);
        L.push(`    edit "${v.name}"`);
        L.push(`        set interface "${v.iface||'port1'}"`);
        L.push(`        set ike-version ${v.ikeVer||'1'}`);
        if(v.remote&&v.remote!=='-') L.push(`        set remote-gw ${v.remote}`);
        L.push(`        set authmethod ${v.authMethod==='psk'?'psk':'signature'}`);
        L.push(`        set proposal ${normEnc(e,'fortigate')}-${normHash(h,'fortigate')}`);
        L.push(`        set dhgrp ${normDH(v.dhgrp,'fortigate')}`);
        if(v.lifetime&&v.lifetime!=='-') L.push(`        set keylife ${v.lifetime}`);
        if(v.natTraversal==='enable') L.push('        set nattraversal enable');
        if(v.dpd&&v.dpd!=='-') L.push(`        set dpd ${v.dpd}`);
        L.push('    next');
      });
      L.push('end'); L.push('');
      L.push('config vpn ipsec phase2-interface');
      ivpns.forEach(v=>{
        (v.phase2||[]).forEach((p2,pi)=>{
          const [pe,ph]=splitProp(p2.proposal||v.proposal);
          L.push(`    edit "${p2.name||v.name+'-P2-'+pi}"`);
          L.push(`        set phase1name "${v.name}"`);
          L.push(`        set proposal ${normEnc(pe,'fortigate')}-${normHash(ph,'fortigate')}`);
          L.push(`        set pfs ${p2.pfs==='enable'?'enable':'disable'}`);
          if(p2.dhgrp&&p2.dhgrp!=='-') L.push(`        set dhgrp ${normDH(p2.dhgrp,'fortigate')}`);
          if(p2.lifetime&&p2.lifetime!=='-') L.push(`        set keylifeseconds ${p2.lifetime}`);
          if(p2.localSub&&p2.localSub!=='-') { const s=p2.localSub.includes('/')?p2.localSub.replace('/',` ${maskOf(p2.localSub.split('/')[1])}`):p2.localSub; L.push(`        set src-subnet ${s}`); }
          if(p2.remoteSub&&p2.remoteSub!=='-') { const s=p2.remoteSub.includes('/')?p2.remoteSub.replace('/',` ${maskOf(p2.remoteSub.split('/')[1])}`):p2.remoteSub; L.push(`        set dst-subnet ${s}`); }
          L.push('    next');
        });
      });
      L.push('end'); L.push('');
    }

    // SSL-VPN
    const sslvpn=parsed.vpn.find(v=>v.type==='ssl-vpn');
    if(sslvpn) {
      L.push('config vpn ssl settings');
      if(sslvpn.iface&&sslvpn.iface!=='-') L.push(`    set source-interface "${sslvpn.iface}"`);
      L.push(`    set port ${sslvpn.port||443}`);
      if(sslvpn.ipPool&&sslvpn.ipPool!=='-') L.push(`    set tunnel-ip-pools "${sslvpn.ipPool}"`);
      if(sslvpn.dns1&&sslvpn.dns1!=='-') L.push(`    set dns-server1 ${sslvpn.dns1}`);
      L.push('end'); L.push('');
    }

    // Firewall policies
    if(parsed.policies.length) {
      L.push('config firewall policy');
      parsed.policies.forEach((p,idx)=>{
        L.push(`    edit ${idx+1}`);
        if(p.name) L.push(`        set name "${p.name}"`);
        const si=p.srcIntf&&p.srcIntf!=='-'?p.srcIntf:'any';
        const di=p.dstIntf&&p.dstIntf!=='-'?p.dstIntf:'any';
        L.push(`        set srcintf "${si}"`);
        L.push(`        set dstintf "${di}"`);
        const sa=sl(p.srcAddr).map(a=>`"${a}"`).join(' ')||'"all"';
        const da=sl(p.dstAddr).map(a=>`"${a}"`).join(' ')||'"all"';
        L.push(`        set srcaddr ${sa}`);
        L.push(`        set dstaddr ${da}`);
        const sv=sl(p.service).map(s=>`"${s}"`).join(' ')||'"ALL"';
        L.push(`        set service ${sv}`);
        L.push(`        set schedule "${p.schedule||'always'}"`);
        L.push(`        set action ${mapAction(p.action,'fortigate')}`);
        if(p.nat==='enable') L.push('        set nat enable');
        if(p.logtraffic&&p.logtraffic!=='disable') L.push(`        set logtraffic ${p.logtraffic}`);
        if(p.status==='disable') L.push('        set status disable');
        if(p.comments&&p.comments!=='-') L.push(`        set comments "${p.comments}"`);
        if(p.utm) { if(p.utm.av&&p.utm.av!=='-') L.push(`        set av-profile "${p.utm.av}"`); if(p.utm.webfilter&&p.utm.webfilter!=='-') L.push(`        set webfilter-profile "${p.utm.webfilter}"`); if(p.utm.ips&&p.utm.ips!=='-') L.push(`        set ips-sensor "${p.utm.ips}"`); }
        L.push('    next');
      });
      L.push('end');
    }

    // WWAN（2026-08-20 新增，LOSS_FIELDS 同廠牌自轉補齊）：wireless-controller wwan-profile／
    // system lte-modem／system modem／system 5g-modem 四種區塊，來源為 parseWwan()/
    // parseLteModem()/parseSystemModem()/parse5GModem() 已解析出的真實資料。密碼類欄位
    // 一律輸出 PLACEHOLDER（比照既有 IPSec secret 慣例），僅 'enc' 狀態需以 ENC 前綴
    // 保留可辨識性（parser 判定加密與否靠字面 "ENC" 前綴，非真的解密）
    if(parsed.wwan){
      const profiles=parsed.wwan.profiles||[];
      if(profiles.length){
        L.push(''); L.push('config wireless-controller wwan-profile');
        profiles.forEach(p=>{
          L.push(`    edit "${p.name}"`);
          if(p.apn&&p.apn!=='-')L.push(`        set apn "${p.apn}"`);
          if(p.authType&&p.authType!=='-')L.push(`        set auth-type ${p.authType}`);
          if(p.username&&p.username!=='-')L.push(`        set username "${p.username}"`);
          if(p.passwd&&p.passwd!=='-')L.push(`        set passwd ${p.passwd==='enc'?'ENC PLACEHOLDER':'PLACEHOLDER'}`);
          if(p.modemId&&p.modemId!=='-')L.push(`        set modem-id ${p.modemId}`);
          if(p.simPin==='set')L.push('        set sim-pin PLACEHOLDER');
          if(p.provider&&p.provider!=='-')L.push(`        set network-provider ${p.provider}`);
          if(p.dataplan&&p.dataplan!=='-')L.push(`        set dataplan ${p.dataplan}`);
          L.push('    next');
        });
        L.push('end');
      }
      if(parsed.wwan.lteModem){
        const m=parsed.wwan.lteModem;
        L.push(''); L.push('config system lte-modem');
        if(m.status)L.push(`    set status ${m.status}`);
        if(m.autoSwitch)L.push(`    set auto-switch ${m.autoSwitch}`);
        if(m.modemPort&&m.modemPort!=='-')L.push(`    set modem-port ${m.modemPort}`);
        if(m.apn&&m.apn!=='-')L.push(`    set apn ${m.apn}`);
        if(m.authType&&m.authType!=='-')L.push(`    set authtype ${m.authType}`);
        L.push('end');
      }
      if(parsed.wwan.systemModem){
        const m=parsed.wwan.systemModem;
        L.push(''); L.push('config system modem');
        if(m.status)L.push(`    set status ${m.status}`);
        if(m.altMode)L.push(`    set altmode ${m.altMode}`);
        if(m.pinInit&&m.pinInit!=='-')L.push(`    set pin-init ${m.pinInit}`);
        L.push('end');
      }
      if(parsed.wwan.modem5G&&(parsed.wwan.modem5G.modem1||parsed.wwan.modem5G.modem2)){
        L.push(''); L.push('config system 5g-modem');
        const pushModem=(key,m)=>{
          if(!m)return;
          L.push(`    config ${key}`);
          if(m.apn&&m.apn!=='-')L.push(`        set apn ${m.apn}`);
          if(m.apnProvider&&m.apnProvider!=='-')L.push(`        set apn-provider ${m.apnProvider}`);
          if(m.authType&&m.authType!=='-')L.push(`        set auth-type ${m.authType}`);
          if(m.username&&m.username!=='-')L.push(`        set username ${m.username}`);
          if(m.passwd&&m.passwd!=='-')L.push(`        set passwd ${m.passwd==='enc'?'ENCPLACEHOLDER':'PLACEHOLDER'}`);
          if(m.sim1Pin==='set')L.push('        set sim1-pin PLACEHOLDER');
          if(m.sim2Pin==='set')L.push('        set sim2-pin PLACEHOLDER');
          if(m.preferSim&&m.preferSim!=='sim1')L.push(`        set preferred-sim ${m.preferSim}`);
          if(m.interface&&m.interface!=='wwan')L.push(`        set interface ${m.interface}`);
          L.push('    end');
        };
        pushModem('modem1',parsed.wwan.modem5G.modem1);
        pushModem('modem2',parsed.wwan.modem5G.modem2);
        L.push('end');
      }
    }
    return L.join('\n');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → Sophos XG/XGS XML
  // ══════════════════════════════════════════════════════════════════════════
  function toSophos(parsed) {
    const L=[], d=parsed.deviceInfo;
    L.push('<?xml version="1.0" encoding="UTF-8"?>');
    L.push(`<!-- ${hdr(parsed.vendor||'?','Sophos XGS',d.hostname)} -->`);
    L.push('<Configuration>');
    L.push('  <DeviceInfo>');
    L.push(`    <DeviceName>${esc(d.hostname)}</DeviceName>`);
    L.push(`    <Version>${esc(d.firmware)}</Version>`);
    L.push(`    <Model>${esc(d.model||'XGS')}</Model>`);
    L.push('  </DeviceInfo>');

    // Interfaces
    if(parsed.interfaces.length) {
      L.push('  <Interfaces>');
      parsed.interfaces.forEach(i=>{
        const tag=i.type==='vlan'?'VLANInterface':'Interface';
        L.push(`    <${tag}>`);
        L.push(`      <Name>${esc(i.name)}</Name>`);
        if(i.ip&&i.ip!=='-'&&i.ip!=='DHCP') { L.push(`      <IPAddress>${esc(i.ip)}</IPAddress>`); L.push(`      <Netmask>${esc(i.mask&&i.mask!=='-'?i.mask:'255.255.255.0')}</Netmask>`); }
        L.push(`      <Zone>${esc(mapZone(i.role,'sophos'))}</Zone>`);
        L.push(`      <Status>${i.status==='down'||i.status==='Disable'?'Disable':'Enable'}</Status>`);
        if(i.mtu&&i.mtu!=='1500') L.push(`      <MTU>${esc(i.mtu)}</MTU>`);
        if(i.vlanId&&i.vlanId!=='-') L.push(`      <VLANTag>${esc(i.vlanId)}</VLANTag>`);
        if(i.alias&&i.alias!=='-') L.push(`      <Alias>${esc(i.alias)}</Alias>`);
        if(i.desc&&i.desc!=='-') L.push(`      <Description>${esc(i.desc)}</Description>`);
        L.push(`    </${tag}>`);
      });
      L.push('  </Interfaces>');
    }

    // Address objects
    const hasObjs=parsed.addresses.length||parsed.services.length;
    if(hasObjs) {
      L.push('  <HostsAndServices>');
      parsed.addresses.filter(a=>a.category==='address').forEach(a=>{
        if(a.type==='fqdn') { L.push(`    <FQDN><Name>${esc(a.name)}</Name><FQDN>${esc(a.fqdn)}</FQDN><Description>${esc(a.comment)}</Description></FQDN>`); }
        else if(a.type==='iprange') { L.push(`    <IPRange><Name>${esc(a.name)}</Name><StartIPAddress>${esc(a.startIp)}</StartIPAddress><EndIPAddress>${esc(a.endIp)}</EndIPAddress><Description>${esc(a.comment)}</Description></IPRange>`); }
        else {
          const sub=a.subnet||(a.ip?a.ip+'/32':'0.0.0.0/0');
          const ip=sub.split('/')[0]||sub.split(' ')[0];
          const nm=sub.includes('/')?maskOf(sub.split('/')[1]):sub.split(' ')[1]||'255.255.255.255';
          L.push(`    <Host><Name>${esc(a.name)}</Name><IPAddress>${esc(ip)}</IPAddress><Subnet>${esc(nm)}</Subnet><Description>${esc(a.comment)}</Description></Host>`);
        }
      });
      parsed.addresses.filter(a=>a.category==='address-group').forEach(g=>{
        L.push(`    <HostGroup><Name>${esc(g.name)}</Name>`);
        sl(g.members).forEach(m=>L.push(`      <Host>${esc(m)}</Host>`));
        L.push(`      <Description>${esc(g.comment)}</Description></HostGroup>`);
      });
      parsed.services.filter(s=>s.category==='custom').forEach(s=>{
        const p=(s.proto||'TCP').toUpperCase();
        const port=p.includes('UDP')?(s.udpPorts!=='-'?s.udpPorts:s.tcpPorts):(s.tcpPorts!=='-'?s.tcpPorts:s.udpPorts);
        L.push(`    <Service><Name>${esc(s.name)}</Name><Type>${p.includes('ICMP')?'ICMP':p.includes('UDP')?'UDP':'TCP'}</Type><DestinationPort>${esc(port||'-')}</DestinationPort><Description>${esc(s.comment)}</Description></Service>`);
      });
      parsed.services.filter(s=>s.category==='group').forEach(g=>{
        L.push(`    <ServiceGroup><Name>${esc(g.name)}</Name>`);
        sl(g.members).forEach(m=>L.push(`      <ServiceList>${esc(m)}</ServiceList>`));
        L.push('    </ServiceGroup>');
      });
      L.push('  </HostsAndServices>');
    }

    // Schedules
    if(parsed.schedules.length) {
      L.push('  <Schedules>');
      parsed.schedules.forEach(s=>{ L.push(`    <Schedule><Name>${esc(s.name)}</Name><Type>Recurring</Type><StartTime>${esc(s.start||'00:00')}</StartTime><EndTime>${esc(s.end||'23:59')}</EndTime><Days>${esc(s.day||'-')}</Days></Schedule>`); });
      L.push('  </Schedules>');
    }

    // Routes
    const sroutes=parsed.routes.filter(r=>r.type==='static'||r.type==='default');
    const ospf=parsed.routes.find(r=>r.type==='ospf');
    if(sroutes.length||ospf) {
      L.push('  <Routing>');
      sroutes.forEach(r=>{ const dst=r.dst.includes('/')?r.dst:r.dst.replace(/\s+/,'/'); L.push(`    <Unicast><DestinationIP>${esc(dst.split('/')[0]||dst.split(' ')[0])}</DestinationIP><Mask>${esc(dst.includes('/')?maskOf(dst.split('/')[1]):dst.split(' ')[1]||'0.0.0.0')}</Mask><Gateway>${esc(r.gateway)}</Gateway><Interface>${esc(r.device||'Port1')}</Interface><Distance>${esc(r.distance||'1')}</Distance><Description>${esc(r.comment)}</Description></Unicast>`); });
      if(ospf) L.push(`    <OSPF><RouterID>${esc(ospf.routerId||'-')}</RouterID><AdminDistance>${esc(ospf.distance||'110')}</AdminDistance></OSPF>`);
      L.push('  </Routing>');
    }

    // VPN
    const ivpns=parsed.vpn.filter(v=>v.type==='ipsec-p1');
    const sslvpn=parsed.vpn.find(v=>v.type==='ssl-vpn');
    if(ivpns.length||sslvpn) {
      L.push('  <VPNConfiguration>');
      ivpns.forEach(v=>{
        const [e,h]=splitProp(v.proposal);
        L.push('    <IPSec>');
        L.push(`      <Name>${esc(v.name)}</Name>`);
        L.push(`      <RemoteGateway>${esc(v.remote||'-')}</RemoteGateway>`);
        L.push(`      <Interface>${esc(v.iface||'Port1')}</Interface>`);
        L.push(`      <IKEVersion>${esc(v.ikeVer||'1')}</IKEVersion>`);
        L.push(`      <AuthenticationMode>${v.authMethod==='psk'?'PSK':'Certificate'}</AuthenticationMode>`);
        L.push(`      <Encryption>${normEnc(e,'sophos')}</Encryption>`);
        L.push(`      <Authentication>${normHash(h,'sophos')}</Authentication>`);
        L.push(`      <DHGroup>${normDH(v.dhgrp,'sophos')}</DHGroup>`);
        L.push(`      <KeyLife>${esc(v.lifetime||'86400')}</KeyLife>`);
        L.push(`      <NATTraversal>${esc(v.natTraversal||'enable')}</NATTraversal>`);
        L.push(`      <Status>Active</Status>`);
        (v.phase2||[]).forEach(p2=>{
          const [pe,ph]=splitProp(p2.proposal||v.proposal);
          L.push('      <Phase2>');
          L.push(`        <Name>${esc(p2.name||v.name+'-P2')}</Name>`);
          L.push(`        <Encryption>${normEnc(pe,'sophos')}</Encryption>`);
          L.push(`        <Authentication>${normHash(ph,'sophos')}</Authentication>`);
          L.push(`        <DHGroup>${normDH(p2.dhgrp||v.dhgrp,'sophos')}</DHGroup>`);
          if(p2.localSub&&p2.localSub!=='-') L.push(`        <LocalNetwork>${esc(p2.localSub.includes('/')?p2.localSub:p2.localSub.replace(/\s+/,'/'))}</LocalNetwork>`);
          if(p2.remoteSub&&p2.remoteSub!=='-') L.push(`        <RemoteNetwork>${esc(p2.remoteSub.includes('/')?p2.remoteSub:p2.remoteSub.replace(/\s+/,'/'))}</RemoteNetwork>`);
          L.push(`        <KeyLife>${esc(p2.lifetime||'3600')}</KeyLife>`);
          L.push(`        <PFS>${esc(p2.pfs==='enable'?'enable':'disable')}</PFS>`);
          L.push('      </Phase2>');
        });
        L.push('    </IPSec>');
      });
      if(sslvpn) {
        L.push('    <SSLVPNPolicy>');
        L.push(`      <Name>${esc(sslvpn.name)}</Name>`);
        L.push(`      <Port>${esc(sslvpn.port||'443')}</Port>`);
        L.push(`      <Interface>${esc(sslvpn.iface||'Port1')}</Interface>`);
        if(sslvpn.ipPool&&sslvpn.ipPool!=='-') L.push(`      <TunnelPool>${esc(sslvpn.ipPool)}</TunnelPool>`);
        if(sslvpn.dns1&&sslvpn.dns1!=='-') L.push(`      <PrimaryDNS>${esc(sslvpn.dns1)}</PrimaryDNS>`);
        L.push(`      <Status>Active</Status>`);
        L.push('    </SSLVPNPolicy>');
      }
      L.push('  </VPNConfiguration>');
    }

    // NAT
    const nats=parsed.nat;
    if(nats.length) {
      L.push('  <NATConfiguration>');
      nats.filter(n=>n.type==='vip').forEach(n=>{ L.push(`    <DNAT><Name>${esc(n.name)}</Name><ExternalIP>${esc(n.extIp||'-')}</ExternalIP><InboundInterface>${esc(n.extIntf||'Port1')}</InboundInterface><TranslatedDestination>${esc(n.mapIp||'-')}</TranslatedDestination><ExternalPort>${esc(n.extPort||'-')}</ExternalPort><TranslatedPort>${esc(n.mapPort||'-')}</TranslatedPort><Status>Enable</Status></DNAT>`); });
      nats.filter(n=>n.type==='ippool').forEach(n=>{ L.push(`    <SNAT><Name>${esc(n.name)}</Name><TranslatedSource>${esc(n.startIp||'-')}</TranslatedSource><OutboundInterface>${esc(n.srcIntf||'Port1')}</OutboundInterface></SNAT>`); });
      L.push('  </NATConfiguration>');
    }

    // Users
    const ulist=parsed.users.filter(u=>u.type==='admin'||u.type==='local');
    const glist=parsed.users.filter(u=>u.type==='group');
    const ldaps=parsed.users.filter(u=>u.type==='ldap-server');
    const radii=parsed.users.filter(u=>u.type==='radius-server');
    if(ulist.length||glist.length||ldaps.length||radii.length) {
      L.push('  <Users>');
      ulist.forEach(u=>{ L.push(`    <${u.type==='admin'?'Administrator':'User'}><Name>${esc(u.name)}</Name><Email>${esc(u.email||'-')}</Email><Status>Active</Status><Profile>${u.accessLevel==='super-admin'?'Administrator':u.accessLevel==='read-only'?'Read-Only':'User'}</Profile></${u.type==='admin'?'Administrator':'User'}>`); });
      glist.forEach(g=>{ L.push(`    <Group><Name>${esc(g.name)}</Name>`); sl(g.members).forEach(m=>L.push(`      <Member>${esc(m)}</Member>`)); L.push(`    </Group>`); });
      ldaps.forEach(u=>{ L.push(`    <LDAPServer><Name>${esc(u.name)}</Name><Server>${esc(u.server)}</Server><Port>${esc(u.port||'389')}</Port><BaseDN>${esc(u.dn||'-')}</BaseDN>${u.bindDn&&u.bindDn!=='-'?`<BindDN>${esc(u.bindDn)}</BindDN>`:''}</LDAPServer>`); });
      radii.forEach(u=>{ L.push(`    <RADIUSServer><Name>${esc(u.name)}</Name><Server>${esc(u.server)}</Server><Port>${esc(u.port||'1812')}</Port></RADIUSServer>`); });
      L.push('  </Users>');
    }

    // Firewall rules
    if(parsed.policies.length) {
      L.push('  <FirewallRules>');
      parsed.policies.forEach((p,i)=>{
        L.push('    <FirewallRule>');
        L.push(`      <Id>${i+1}</Id>`);
        L.push(`      <Name>${esc(p.name)}</Name>`);
        L.push(`      <SourceZone>${esc(mapZone(p.srcIntf,'sophos'))}</SourceZone>`);
        L.push(`      <DestinationZone>${esc(mapZone(p.dstIntf,'sophos'))}</DestinationZone>`);
        sl(p.srcAddr).forEach(a=>L.push(`      <SourceNetworks>${esc(a)}</SourceNetworks>`));
        if(!sl(p.srcAddr).length) L.push('      <SourceNetworks>Any</SourceNetworks>');
        sl(p.dstAddr).forEach(a=>L.push(`      <DestinationNetworks>${esc(a)}</DestinationNetworks>`));
        if(!sl(p.dstAddr).length) L.push('      <DestinationNetworks>Any</DestinationNetworks>');
        sl(p.service).forEach(s=>L.push(`      <Services>${esc(s)}</Services>`));
        if(!sl(p.service).length) L.push('      <Services>Any</Services>');
        L.push(`      <Action>${mapAction(p.action,'sophos')}</Action>`);
        if(p.schedule&&p.schedule!=='always'&&p.schedule!=='-') L.push(`      <Schedule>${esc(p.schedule)}</Schedule>`);
        if(p.logtraffic&&p.logtraffic!=='disable') L.push('      <LogTraffic>Enable</LogTraffic>');
        if(p.nat==='enable') L.push('      <OutboundNAT>Enable</OutboundNAT>');
        L.push(`      <Status>${p.status==='disable'?'Disable':'Enable'}</Status>`);
        if(p.utm) { if(p.utm.av&&p.utm.av!=='-') L.push(`      <AntiVirus>${esc(p.utm.av)}</AntiVirus>`); if(p.utm.webfilter&&p.utm.webfilter!=='-') L.push(`      <WebFilter>${esc(p.utm.webfilter)}</WebFilter>`); if(p.utm.ips&&p.utm.ips!=='-') L.push(`      <IPS>${esc(p.utm.ips)}</IPS>`); }
        if(p.comments&&p.comments!=='-') L.push(`      <Description>${esc(p.comments)}</Description>`);
        L.push('    </FirewallRule>');
      });
      L.push('  </FirewallRules>');
    }
    L.push('</Configuration>');
    return L.join('\n');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → Check Point Gaia Clish
  // ══════════════════════════════════════════════════════════════════════════
  function toCheckpoint(parsed) {
    const L=[], d=parsed.deviceInfo;
    L.push(`# ${hdr(parsed.vendor||'?','Check Point R81.20 Gaia',d.hostname)}`);
    L.push(`set hostname "${d.hostname}"`);
    L.push('');
    // Interfaces
    // 2026-07-24 修復：原本整個介面輸出包在 "if(i.ip...)" 底下，沒有 IP 的介面（如僅作為
    // L2/管理用途的埠）會整個消失、無任何提示。改為介面本身一律輸出，只有 ipv4-address
    // 這行才依 IP 是否存在決定要不要輸出
    parsed.interfaces.forEach(i=>{
      if(i.ip&&i.ip!=='-'&&i.ip!=='DHCP') {
        const pfx=bits(i.mask);
        L.push(`set interface ${i.name} ipv4-address ${i.ip} mask-length ${pfx}`);
      }
      if(i.desc&&i.desc!=='-') L.push(`set interface ${i.name} comments "${i.desc}"`);
      L.push(`set interface ${i.name} state ${i.status==='down'?'off':'on'}`);
    });
    L.push('');
    // Routes
    parsed.routes.filter(r=>r.type==='static'||r.type==='default').forEach(r=>{
      const dst=r.dst.includes('/')?r.dst:r.dst.replace(/\s+/,'/');
      if(r.blackhole==='enable') L.push(`set static-route ${dst} blackhole on`);
      else if(r.gateway&&r.gateway!=='-') L.push(`set static-route ${dst} nexthop gateway address ${r.gateway} on`);
    });
    const ospf=parsed.routes.find(r=>r.type==='ospf');
    if(ospf) { L.push(''); L.push('set ospf enabled on'); if(ospf.routerId) L.push(`set ospf router-id ${ospf.routerId}`); }
    const bgp=parsed.routes.find(r=>r.type==='bgp');
    if(bgp) { L.push(''); if(bgp.as) L.push(`set bgp local-as ${bgp.as}`); if(bgp.routerId) L.push(`set bgp router-id ${bgp.routerId}`); }
    L.push('');
    // Address objects
    parsed.addresses.filter(a=>a.category==='address').forEach(a=>{
      if(a.type==='fqdn') L.push(`set network-object fqdn "${a.name}" fqdn ${a.fqdn}`);
      else if(a.type==='iprange') L.push(`set network-object ip-range "${a.name}" first-ip ${a.startIp} last-ip ${a.endIp}`);
      else {
        const sub=a.subnet||(a.ip?a.ip+'/32':'0.0.0.0/0');
        const ip=sub.split(/[\/\s]/)[0]; const sfx=sub.includes('/')?sub.split('/')[1]:bits(sub.split(' ')[1]||'255.255.255.255');
        if(sfx==='32'||!sub.includes('/')) L.push(`set network-object host "${a.name}" ipaddr ${ip}`);
        else L.push(`set network-object network "${a.name}" ipaddr ${ip} mask-length ${sfx}`);
      }
    });
    parsed.addresses.filter(a=>a.category==='address-group').forEach(g=>{ sl(g.members).forEach(m=>L.push(`set network-object group "${g.name}" add "${m}"`)); });
    L.push('');
    // Services
    parsed.services.filter(s=>s.category==='custom').forEach(s=>{
      const p=(s.proto||'TCP').toLowerCase();
      if(p.includes('icmp')) L.push(`set service icmp "${s.name}" type ${s.icmpType||'0'}`);
      else if(p.includes('udp')) { const port=s.udpPorts!=='-'?s.udpPorts:s.tcpPorts; L.push(`set service udp "${s.name}" port ${port||'0'}`); }
      else { L.push(`set service tcp "${s.name}" port ${s.tcpPorts||'0'}`); }
    });
    parsed.services.filter(s=>s.category==='group').forEach(g=>{ sl(g.members).forEach(m=>L.push(`set service group "${g.name}" add "${m}"`)); });
    L.push('');
    // Schedules
    parsed.schedules.forEach(s=>{ L.push(`set time "${s.name}" type ${s.type||'recurring'}`); if(s.start) L.push(`set time "${s.name}" start ${s.start}`); if(s.end) L.push(`set time "${s.name}" end ${s.end}`); });
    // 2026-08-09 查證：規則庫（access-policy）／NAT／VPN site-to-site community 在真實 Check
    // Point Gaia clish 官方 `set` 指令清單（sc1.checkpoint.com Gaia Admin Guide）查無對應指令，
    // 這幾類物件在真實裝置只能透過 SmartConsole 或 Management API 管理，clish 僅管
    // OS 層級設定（hostname/interface/routing/DNS 等，已於上方輸出）。原本此處會輸出
    // `set access-policy rule`／`set nat rule`／`set vpn site-to-site community` 三類自創
    // 指令族群，`CheckpointParser.parsePolicies()` 又剛好解析同一套自創語法形成封閉迴圈，
    // 貼到真實裝置會被拒絕，故本輪移除，比照既有 ClusterXL／Mobile Access split-tunnel 因
    // 查無公開可信 schema 而排除的做法。VPN 僅保留 Mobile Access（SSL VPN）全域開關，因其
    // `set mobile-access` 為 Gaia clish 已存在的合法指令，不在本次移除範圍。
    const sslvpn=parsed.vpn.find(v=>v.type==='ssl-vpn');
    if(sslvpn) { L.push(''); L.push('set mobile-access on'); L.push(`set mobile-access port ${sslvpn.port||443}`); if(sslvpn.iface) L.push(`set mobile-access interface ${sslvpn.iface}`); }
    L.push('');
    // Users
    parsed.users.filter(u=>u.type==='admin'||u.type==='local').forEach(u=>{ L.push(`set user "${u.name}" password-hash PLACEHOLDER`); if(u.email&&u.email!=='-') L.push(`set user "${u.name}" email "${u.email}"`); });
    parsed.users.filter(u=>u.type==='ldap-server').forEach(u=>{ L.push(`set ldap-account-unit "${u.name}" server ${u.server}`); L.push(`set ldap-account-unit "${u.name}" port ${u.port||389}`); if(u.dn&&u.dn!=='-') L.push(`set ldap-account-unit "${u.name}" base-dn "${u.dn}"`); });
    L.push('');
    L.push('# 規則庫（Access Policy）／NAT／VPN site-to-site community 需透過 SmartConsole 或');
    L.push('# Management API 管理，非 Gaia clish 可設定範圍，本工具不產生對應指令。');
    return L.join('\n');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → Palo Alto PAN-OS XML
  // ══════════════════════════════════════════════════════════════════════════
  function toPaloAlto(parsed) {
    const L=[], d=parsed.deviceInfo;
    L.push('<?xml version="1.0"?>');
    L.push(`<!-- ${hdr(parsed.vendor||'?','Palo Alto PAN-OS 11',d.hostname)} -->`);
    L.push('<config version="11.0.0">');
    L.push('  <devices><entry name="localhost.localdomain">');
    L.push('    <deviceconfig><system>');
    L.push(`      <hostname>${esc(d.hostname)}</hostname>`);
    L.push('    </system>');
    // HA（2026-08-20 新增，LOSS_FIELDS 同廠牌自轉補齊）：<high-availability> 與 <system>
    // 同層皆在 <deviceconfig> 底下，比照 parseHa() 已查證的官方 KB kA10g000000ClGNCA0 語法
    if(parsed.ha&&parsed.ha.enabled){
      const ha=parsed.ha;
      L.push('    <high-availability>');
      L.push('      <enabled>yes</enabled>');
      L.push('      <group>');
      if(ha.groupId&&ha.groupId!=='-')L.push(`        <group-id>${esc(ha.groupId)}</group-id>`);
      if(ha.peerIp&&ha.peerIp!=='-')L.push(`        <peer-ip>${esc(ha.peerIp)}</peer-ip>`);
      if(ha.mode&&ha.mode!=='-')L.push(`        <mode>${esc(ha.mode)}</mode>`);
      L.push('      </group>');
      L.push('    </high-availability>');
    }
    L.push('    </deviceconfig>');
    L.push('    <network>');
    // Interfaces
    // 2026-07-24 修復：原本把 VLAN 子介面跟實體介面同層對待，直接產生 <entry name="port5.100">
    // 掛在 <ethernet> 底下，不符合 PAN-OS 真實子介面規範（必須巢狀在父介面 <layer3><units>
    // 底下＋帶 <tag>）。改為兩層迴圈：先跑實體介面，各自查詢屬於它的 VLAN 子介面巢狀輸出到
    // <units>；找不到對應父介面的孤兒子介面（來源資料不完整時）退回原本的扁平輸出，避免資料消失
    // 次要IP（2026-08-18 補上輸出端，官方 PAN-OS 真實匯出格式在 <ip> 標籤內用多筆
    // <entry name="CIDR"/> 清單表示，非 <member> 清單，與 parser 端既有 xlist() 讀取語法對稱）
    const ipEntries=ifc=>{
      const list=[];
      if(ifc.ip&&ifc.ip!=='-'&&ifc.ip!=='DHCP') list.push(cidr(ifc.ip,ifc.mask));
      (ifc.secondaryIps||[]).forEach(s=>list.push(cidr(s.ip,s.mask)));
      return list.map(c=>`<entry name="${esc(c)}"/>`).join('');
    };
    const hasAnyIp=ifc=>(ifc.ip&&ifc.ip!=='-'&&ifc.ip!=='DHCP')||(ifc.secondaryIps&&ifc.secondaryIps.length);
    if(parsed.interfaces.length) {
      L.push('      <interface><ethernet>');
      // 2026-08-20 修正：原本只認 type==='physical'/未設定，但 MikroTik parser 的介面
      // type 依 /interface 區段種類分得更細（ethernet/bridge/tunnel/pppoe...），非
      // 'physical' 字面值，導致這些介面被靜默排除、完全不輸出（跨廠牌 round-trip 測試
      // 揪出）。這裡真正的意圖只是「排除 VLAN 子介面」（子介面另外用 kids 巢狀輸出），
      // 其餘任何 type 都應視為頂層介面
      const physicals=parsed.interfaces.filter(i=>i.type!=='vlan');
      const vlans=parsed.interfaces.filter(i=>i.type==='vlan');
      physicals.forEach(i=>{
        L.push(`        <entry name="${esc(i.name)}">`);
        const kids=vlans.filter(v=>v.interface===i.name);
        if(hasAnyIp(i)||kids.length){
          L.push('          <layer3>');
          if(hasAnyIp(i)) L.push(`            <ip>${ipEntries(i)}</ip>`);
          if(kids.length){
            L.push('            <units>');
            kids.forEach(v=>{
              const vip=hasAnyIp(v)?`<ip>${ipEntries(v)}</ip>`:'';
              L.push(`              <entry name="${esc(v.name)}"><tag>${esc(v.vlanId)}</tag>${vip}</entry>`);
            });
            L.push('            </units>');
          }
          L.push('          </layer3>');
        }
        if(i.desc&&i.desc!=='-') L.push(`          <comment>${esc(i.desc)}</comment>`);
        L.push('        </entry>');
      });
      vlans.filter(v=>!physicals.some(i=>i.name===v.interface)).forEach(v=>{
        L.push(`        <entry name="${esc(v.name)}">`);
        if(hasAnyIp(v)) L.push(`          <layer3><ip>${ipEntries(v)}</ip></layer3>`);
        if(v.desc&&v.desc!=='-') L.push(`          <comment>${esc(v.desc)}</comment>`);
        L.push('        </entry>');
      });
      L.push('      </ethernet></interface>');
    }
    // Routes
    const sroutes=parsed.routes.filter(r=>r.type==='static'||r.type==='default');
    const ospf=parsed.routes.find(r=>r.type==='ospf');
    const bgp2=parsed.routes.find(r=>r.type==='bgp');
    L.push('      <virtual-router><entry name="default">');
    if(sroutes.length) {
      L.push('        <routing-table><ip><static-route>');
      sroutes.forEach(r=>{ const dst=r.dst.includes('/')?r.dst:r.dst.replace(/\s+/,'/'); L.push(`          <entry name="${esc(r.comment&&r.comment!=='-'?r.comment:'route-'+r.id)}"><destination>${esc(dst)}</destination>${r.gateway&&r.gateway!=='-'&&r.gateway!=='blackhole'?`<nexthop><ip-address>${esc(r.gateway)}</ip-address></nexthop>`:''}<admin-dist>${esc(r.distance||'10')}</admin-dist></entry>`); });
      L.push('        </static-route></ip></routing-table>');
    }
    if(ospf) L.push(`        <ospf><enable>yes</enable>${ospf.routerId?`<router-id>${esc(ospf.routerId)}</router-id>`:''}</ospf>`);
    if(bgp2) L.push(`        <bgp><enable>yes</enable><local-as>${esc(bgp2.as||'65000')}</local-as>${bgp2.routerId?`<router-id>${esc(bgp2.routerId)}</router-id>`:''}</bgp>`);
    L.push('      </entry></virtual-router>');
    // IKE gateways
    const ivpns=parsed.vpn.filter(v=>v.type==='ipsec-p1');
    if(ivpns.length) {
      L.push('      <ike><gateway>');
      ivpns.forEach(v=>{ const [e,h]=splitProp(v.proposal); L.push(`        <entry name="${esc('IKE-'+v.name)}"><peer-address><ip>${esc(v.remote||'0.0.0.0')}</ip></peer-address><interface>${esc(v.iface||'ethernet1/1')}</interface><authentication><pre-shared-key><key>CHANGE_ME</key></pre-shared-key></authentication><version>${v.ikeVer==='2'?'ikev2':'ikev1'}</version><nat-traversal><enable>${v.natTraversal==='enable'?'yes':'no'}</enable></nat-traversal></entry>`); });
      L.push('      </gateway></ike>');
      L.push('      <ipsec><tunnel>');
      ivpns.forEach(v=>{ L.push(`        <entry name="${esc(v.name)}"><auto-key><ike-gateway><entry name="${esc('IKE-'+v.name)}"/></ike-gateway>${v.phase2&&v.phase2.length?v.phase2.map(p2=>`<proxy-id><entry name="${esc(p2.name||'proxy1')}">${p2.localSub&&p2.localSub!=='-'?`<local>${esc(p2.localSub.replace(/\s+/,'/'))}</local>`:''}${p2.remoteSub&&p2.remoteSub!=='-'?`<remote>${esc(p2.remoteSub.replace(/\s+/,'/'))}</remote>`:''}</entry></proxy-id>`).join(''):''}</auto-key></entry>`); });
      L.push('      </tunnel></ipsec>');
    }
    L.push('    </network>');
    L.push('    <vsys><entry name="vsys1">');
    // Zones
    const zones=new Set(['untrust','trust','dmz']);
    parsed.interfaces.forEach(i=>{ const z=mapZone(i.role,'paloalto'); if(z) zones.add(z); });
    L.push('      <zone>');
    zones.forEach(z=>{ const zIfs=parsed.interfaces.filter(i=>mapZone(i.role,'paloalto')===z).map(i=>i.name); L.push(`        <entry name="${esc(z)}"><network><layer3>${zIfs.map(ii=>`<member>${esc(ii)}</member>`).join('')}</layer3></network></entry>`); });
    L.push('      </zone>');
    // Address objects
    if(parsed.addresses.length) {
      L.push('      <address>');
      parsed.addresses.filter(a=>a.category==='address').forEach(a=>{
        L.push(`        <entry name="${esc(a.name)}">`);
        if(a.type==='fqdn') L.push(`          <fqdn>${esc(a.fqdn)}</fqdn>`);
        else if(a.type==='iprange') L.push(`          <ip-range>${esc(a.startIp+'-'+a.endIp)}</ip-range>`);
        else { L.push(`          <ip-netmask>${esc(addrCidr(a))}</ip-netmask>`); }
        if(a.comment&&a.comment!=='-') L.push(`          <description>${esc(a.comment)}</description>`);
        L.push('        </entry>');
      });
      L.push('      </address>');
      if(parsed.addresses.filter(a=>a.category==='address-group').length) {
        L.push('      <address-group>');
        parsed.addresses.filter(a=>a.category==='address-group').forEach(g=>{ L.push(`        <entry name="${esc(g.name)}"><static>${sl(g.members).map(m=>`<member>${esc(m)}</member>`).join('')}</static></entry>`); });
        L.push('      </address-group>');
      }
    }
    // Services
    const csvcs=parsed.services.filter(s=>s.category==='custom');
    if(csvcs.length) {
      L.push('      <service>');
      csvcs.forEach(s=>{ const p=(s.proto||'TCP').toLowerCase(); const port=p.includes('udp')?(s.udpPorts!=='-'?s.udpPorts:s.tcpPorts):(s.tcpPorts!=='-'?s.tcpPorts:s.udpPorts); L.push(`        <entry name="${esc(s.name)}"><protocol><${p.includes('udp')?'udp':'tcp'}><port>${esc(port||'0')}</port></${p.includes('udp')?'udp':'tcp'}></protocol></entry>`); });
      L.push('      </service>');
    }
    const sgrps2=parsed.services.filter(s=>s.category==='group');
    if(sgrps2.length) { L.push('      <service-group>'); sgrps2.forEach(g=>L.push(`        <entry name="${esc(g.name)}"><members>${sl(g.members).map(m=>`<member>${esc(m)}</member>`).join('')}</members></entry>`)); L.push('      </service-group>'); }
    // Schedules
    if(parsed.schedules.length) { L.push('      <schedule>'); parsed.schedules.forEach(s=>{ L.push(`        <entry name="${esc(s.name)}"><recurring><weekly><monday><member>${esc(s.start||'08:00')}-${esc(s.end||'18:00')}</member></monday></weekly></recurring></entry>`); }); L.push('      </schedule>'); }
    // NAT
    const nats2=parsed.nat;
    if(nats2.length) { L.push('      <nat><rules>'); nats2.filter(n=>n.type==='ippool').forEach(n=>{ L.push(`        <entry name="${esc(n.name)}"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><source-translation><dynamic-ip-and-port><translated-address><member>${esc(n.startIp||'-')}</member></translated-address></dynamic-ip-and-port></source-translation></entry>`); }); nats2.filter(n=>n.type==='vip').forEach(n=>{ L.push(`        <entry name="${esc(n.name)}"><from><member>untrust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><destination-translation><translated-address>${esc(n.mapIp||'-')}</translated-address>${n.mapPort&&n.mapPort!=='-'?`<translated-port>${esc(n.mapPort)}</translated-port>`:''}</destination-translation></entry>`); }); L.push('      </rules></nat>'); }
    // Users
    const ulist2=parsed.users.filter(u=>u.type==='admin'||u.type==='local');
    if(ulist2.length) { L.push('      <local-user-database><user>'); ulist2.forEach(u=>L.push(`        <entry name="${esc(u.name)}"><phash>PLACEHOLDER</phash></entry>`)); L.push('      </user></local-user-database>'); }
    // GlobalProtect (SSL-VPN)
    const sslvpn2=parsed.vpn.find(v=>v.type==='ssl-vpn');
    if(sslvpn2) { L.push('      <global-protect><gateway><entry name="GP-Gateway">'); L.push(`        <interface>${esc(sslvpn2.iface||'ethernet1/1')}</interface>`); if(sslvpn2.ipPool&&sslvpn2.ipPool!=='-') L.push(`        <tunnel-settings><ip-pool><entry name="${esc(sslvpn2.ipPool)}"/></ip-pool></tunnel-settings>`); L.push('      </entry></gateway></global-protect>'); }
    // Security rules
    if(parsed.policies.length) {
      L.push('      <security><rules>');
      parsed.policies.forEach(p=>{ L.push(`        <entry name="${esc(p.name)}"${p.status==='disable'?' disabled="yes"':''}>`); const srcZ=typeof p.srcIntf==='string'?p.srcIntf.split(','):['trust']; const dstZ=typeof p.dstIntf==='string'?p.dstIntf.split(','):['untrust']; L.push(`          <from>${srcZ.map(z=>`<member>${esc(mapZone(z.trim(),'paloalto'))}</member>`).join('')||'<member>any</member>'}</from>`); L.push(`          <to>${dstZ.map(z=>`<member>${esc(mapZone(z.trim(),'paloalto'))}</member>`).join('')||'<member>any</member>'}</to>`); const sa2=sl(p.srcAddr); const da2=sl(p.dstAddr); const sv2=sl(p.service); L.push(`          <source>${sa2.length?sa2.map(a=>`<member>${esc(a)}</member>`).join(''):'<member>any</member>'}</source>`); L.push(`          <destination>${da2.length?da2.map(a=>`<member>${esc(a)}</member>`).join(''):'<member>any</member>'}</destination>`); L.push(`          <service>${sv2.length?sv2.map(s=>`<member>${esc(s)}</member>`).join(''):'<member>any</member>'}</service>`); L.push(`          <application><member>any</member></application>`); L.push(`          <action>${mapAction(p.action,'paloalto')}</action>`); if(p.logtraffic&&p.logtraffic!=='disable') L.push('          <log-end>yes</log-end>'); if(p.schedule&&p.schedule!=='always'&&p.schedule!=='-') L.push(`          <schedule>${esc(p.schedule)}</schedule>`); if(p.utm) { if(p.utm.av&&p.utm.av!=='-') L.push(`          <profile-setting><virus>${esc(p.utm.av)}</virus></profile-setting>`); } if(p.comments&&p.comments!=='-') L.push(`          <description>${esc(p.comments)}</description>`); L.push('        </entry>'); });
      L.push('      </rules></security>');
    }
    L.push('    </entry></vsys>');
    L.push('  </entry></devices>');
    L.push('</config>');
    return L.join('\n');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → Juniper SRX Junos
  // ══════════════════════════════════════════════════════════════════════════
  function toJuniper(parsed) {
    const L=[], d=parsed.deviceInfo;
    L.push(`## ${hdr(parsed.vendor||'?','Juniper SRX Junos',d.hostname)}`);
    L.push('');
    // system
    L.push('system {');
    L.push(`${I(1)}host-name ${d.hostname};`);
    L.push(`${I(1)}time-zone Asia/Taipei;`);
    parsed.users.filter(u=>u.type==='admin'||u.type==='local').forEach(u=>{
      const cls=u.accessLevel==='super-admin'?'super-user':u.accessLevel==='read-only'?'read-only':'operator';
      L.push(`${I(1)}login { user ${u.name} { class ${cls}; authentication { encrypted-password "CHANGE_ME"; } } }`);
    });
    parsed.users.filter(u=>u.type==='radius-server').forEach(u=>{
      L.push(`${I(1)}radius-server ${u.server||u.name} { port ${u.port||'1812'}; secret "CHANGE_ME"; }`);
    });
    L.push('}'); L.push('');

    // HA（2026-08-20 新增，LOSS_FIELDS 同廠牌自轉補齊）：chassis cluster，比照 parseHa()
    // 已查證的官方文件語法。mode 固定為 chassis-cluster（parser 端偵測到 cluster{} 區塊即
    // 視為啟用，非讀取自欄位值，故此處不輸出 mode 對應指令，parser 本就不依賴它）
    if(parsed.ha&&parsed.ha.enabled){
      const ha=parsed.ha;
      L.push('chassis {');
      L.push(`${I(1)}cluster {`);
      const rethM=ha.syncInterface&&ha.syncInterface!=='-'?ha.syncInterface.match(/reth-count\s+(\d+)/):null;
      if(rethM) L.push(`${I(2)}reth-count ${rethM[1]};`);
      if(ha.groupId&&ha.groupId!=='-'){
        L.push(`${I(2)}redundancy-group ${ha.groupId} {`);
        if(ha.priority&&ha.priority!=='-') L.push(`${I(3)}node 0 priority ${ha.priority};`);
        L.push(`${I(2)}}`);
      }
      L.push(`${I(1)}}`);
      L.push('}'); L.push('');
    }

    // interfaces
    if(parsed.interfaces.length) {
      L.push('interfaces {');
      const grp={};
      parsed.interfaces.forEach(i=>{ const b=i.name.includes('.')?i.name.split('.')[0]:i.name; const u2=i.name.includes('.')?i.name.split('.')[1]:'0'; (grp[b]=grp[b]||[]).push({...i,_u:u2}); });
      Object.entries(grp).forEach(([base,units])=>{
        const f=units[0];
        L.push(`${I(1)}${base} {`);
        if(f.desc&&f.desc!=='-') L.push(`${I(2)}description "${f.desc}";`);
        if(f.mtu&&f.mtu!=='1500') L.push(`${I(2)}mtu ${f.mtu};`);
        if(f.status==='down') L.push(`${I(2)}disable;`);
        units.forEach(u2=>{
          L.push(`${I(2)}unit ${u2._u} {`);
          if(u2.vlanId&&u2.vlanId!=='-') L.push(`${I(3)}vlan-id ${u2.vlanId};`);
          // 次要IP（2026-08-18 補上輸出端，官方 Junos "Protocol Family and Interface Address
          // Properties" 確認同一 family inet {} 區塊內重複宣告 address 陳述式即為附加式次要IP，
          // 無 secondary 關鍵字，與 parser 端既有 _addrListToSecondaryIps() 語法對稱）
          if(u2.secondaryIps&&u2.secondaryIps.length){
            L.push(`${I(3)}family inet {`);
            if(u2.ip&&u2.ip!=='-'&&u2.ip!=='DHCP') L.push(`${I(4)}address ${cidr(u2.ip,u2.mask)};`);
            u2.secondaryIps.forEach(s=>L.push(`${I(4)}address ${cidr(s.ip,s.mask)};`));
            L.push(`${I(3)}}`);
          } else if(u2.ip&&u2.ip!=='-'&&u2.ip!=='DHCP') L.push(`${I(3)}family inet { address ${cidr(u2.ip,u2.mask)}; }`);
          L.push(`${I(2)}}`);
        });
        L.push(`${I(1)}}`);
      });
      L.push('}'); L.push('');
    }

    // routing-options
    const sr2=parsed.routes.filter(r=>r.type==='static'||r.type==='default');
    const ospf2=parsed.routes.find(r=>r.type==='ospf');
    const bgp3=parsed.routes.find(r=>r.type==='bgp');
    if(sr2.length||ospf2||bgp3) {
      L.push('routing-options {');
      if(bgp3) { L.push(`${I(1)}autonomous-system ${bgp3.as||'65000'};`); if(bgp3.routerId) L.push(`${I(1)}router-id ${bgp3.routerId};`); }
      if(sr2.length) {
        L.push(`${I(1)}static {`);
        sr2.forEach(r=>{ const dst=r.dst.includes('/')?r.dst:r.dst.replace(/\s+/,'/'); L.push(r.blackhole==='enable'?`${I(2)}route ${dst} discard;`:`${I(2)}route ${dst} next-hop ${r.gateway};`); });
        L.push(`${I(1)}}`);
      }
      L.push('}'); L.push('');
    }

    // applications
    const cSvcs2=parsed.services.filter(s=>s.category==='custom');
    if(cSvcs2.length) {
      L.push('applications {');
      cSvcs2.forEach(s=>{
        L.push(`${I(1)}application ${s.name} {`);
        const p=(s.proto||'TCP').toLowerCase();
        if(p.includes('icmp')){ L.push(`${I(2)}protocol icmp;`); if(s.icmpType&&s.icmpType!=='-') L.push(`${I(2)}icmp-type ${s.icmpType};`); }
        else { L.push(`${I(2)}protocol ${p.includes('udp')?'udp':'tcp'};`); const port2=p.includes('udp')?(s.udpPorts!=='-'?s.udpPorts:s.tcpPorts):(s.tcpPorts!=='-'?s.tcpPorts:s.udpPorts); if(port2&&port2!=='-') L.push(`${I(2)}destination-port ${port2};`); }
        L.push(`${I(1)}}`);
      });
      parsed.services.filter(s=>s.category==='group').forEach(g=>{ L.push(`${I(1)}application-set ${g.name} {`); sl(g.members).forEach(m=>L.push(`${I(2)}application ${m};`)); L.push(`${I(1)}}`); });
      L.push('}'); L.push('');
    }

    // security
    L.push('security {');
    // zones + address-book
    const jZones=new Set(['trust','untrust','dmz']);
    parsed.interfaces.forEach(i=>jZones.add(mapZone(i.role,'juniper')));
    L.push(`${I(1)}zones {`);
    jZones.forEach(z=>{
      const zIfs=parsed.interfaces.filter(i=>mapZone(i.role,'juniper')===z&&i.ip&&i.ip!=='-'&&i.ip!=='DHCP').map(i=>i.name.includes('.')?i.name:i.name+'.0');
      L.push(`${I(2)}security-zone ${z} {`);
      L.push(`${I(3)}host-inbound-traffic { system-services { ping; ssh; } }`);
      if(zIfs.length){L.push(`${I(3)}interfaces {`); zIfs.forEach(ii=>L.push(`${I(4)}${ii};`)); L.push(`${I(3)}}`);}
      // address book
      const zA=parsed.addresses.filter(a=>a.category==='address'&&(mapZone(a._vdom||a.vdom||'','juniper')===z||(!a._vdom||a._vdom==='global')));
      const zG=z==='trust'?parsed.addresses.filter(a=>a.category==='address-group'):[];
      if(zA.length||zG.length){
        L.push(`${I(3)}address-book {`);
        zA.forEach(a=>{ if(a.type==='iprange') L.push(`${I(4)}address ${a.name} range-address ${a.startIp} to ${a.endIp};`); else if(a.type==='fqdn') L.push(`${I(4)}address ${a.name} dns-name ${a.fqdn};`); else { const s2=a.subnet||(a.ip?cidr(a.ip,a.mask):'0.0.0.0/0'); L.push(`${I(4)}address ${a.name} ${s2.includes('/')?s2:s2+'/32'};`); } });
        zG.forEach(g=>{L.push(`${I(4)}address-set ${g.name} {`); sl(g.members).forEach(m=>L.push(`${I(5)}address ${m};`)); L.push(`${I(4)}}`);});
        L.push(`${I(3)}}`);
      }
      L.push(`${I(2)}}`);
    });
    L.push(`${I(1)}}`);L.push('');

    // policies
    if(parsed.policies.length){
      const pg={};
      parsed.policies.forEach(p=>{ const s=mapZone(p.srcIntf,'juniper')||'trust', dt=mapZone(p.dstIntf,'juniper')||'untrust'; const k=`from-zone ${s} to-zone ${dt}`; (pg[k]=pg[k]||[]).push(p); });
      L.push(`${I(1)}policies {`);
      Object.entries(pg).forEach(([zk,pols])=>{
        L.push(`${I(2)}${zk} {`);
        pols.forEach(p=>{
          L.push(`${I(3)}policy ${p.name.replace(/[\s"]/g,'-')} {`);
          L.push(`${I(4)}match {`);
          (sl(p.srcAddr).length?sl(p.srcAddr):['any']).forEach(a=>L.push(`${I(5)}source-address ${a};`));
          (sl(p.dstAddr).length?sl(p.dstAddr):['any']).forEach(a=>L.push(`${I(5)}destination-address ${a};`));
          (sl(p.service).length?sl(p.service):['any']).forEach(s=>L.push(`${I(5)}application ${s};`));
          L.push(`${I(4)}}`);
          L.push(`${I(4)}then {`);
          if(p.action==='accept'){L.push(`${I(5)}permit;`);}else{L.push(`${I(5)}deny;`);}
          if(p.logtraffic&&p.logtraffic!=='disable') L.push(`${I(5)}log { session-close; }`);
          L.push(`${I(4)}}`);
          if(p.status==='disable') L.push(`${I(4)}inactive: true;`);
          L.push(`${I(3)}}`);
        });
        L.push(`${I(2)}}`);
      });
      L.push(`${I(1)}}`);L.push('');
    }

    // nat
    const dn=parsed.nat.filter(n=>n.type==='vip');
    const sn=parsed.nat.filter(n=>n.type==='ippool');
    if(dn.length||sn.length){
      L.push(`${I(1)}nat {`);
      if(dn.length){L.push(`${I(2)}destination { rule-set dnat-rs { from zone untrust;`); dn.forEach((n,i2)=>{L.push(`${I(3)}rule r${i2+1} { match { ${n.extIp&&n.extIp!=='-'?`destination-address ${n.extIp};`:''} } then { destination-nat { pool { dp${i2+1}; } } } }`); L.push(`${I(3)}pool dp${i2+1} { address ${n.mapIp||'0.0.0.0'}; }`); }); L.push(`${I(2)}} }`); }
      if(sn.length){L.push(`${I(2)}source { rule-set snat-rs { from zone trust; to zone untrust;`); sn.forEach((n,i2)=>{L.push(`${I(3)}rule r${i2+1} { match { source-address 0.0.0.0/0; } then { source-nat { ${n.startIp&&n.startIp!=='-'?`pool { sp${i2+1}; }`:'interface;'} } } }`); if(n.startIp&&n.startIp!=='-') L.push(`${I(3)}pool sp${i2+1} { address ${n.startIp}${n.endIp&&n.endIp!=='-'?' to '+n.endIp:''}; }`); }); L.push(`${I(2)}} }`); }
      L.push(`${I(1)}}`);L.push('');
    }

    // ike/ipsec
    const iv2=parsed.vpn.filter(v=>v.type==='ipsec-p1');
    if(iv2.length){
      L.push(`${I(1)}ike {`);
      iv2.forEach((v,vi)=>{
        const [e2,h2]=splitProp(v.proposal);
        L.push(`${I(2)}proposal ikp-${vi} { authentication-method ${v.authMethod==='psk'?'pre-shared-keys':'rsa-signatures'}; dh-group ${normDH(v.dhgrp,'juniper')}; authentication-algorithm ${normHash(h2,'juniper')}; encryption-algorithm ${normEnc(e2,'juniper')}; lifetime-seconds ${v.lifetime||'28800'}; }`);
        L.push(`${I(2)}policy ikpol-${vi} { mode main; proposals ikp-${vi}; ${v.authMethod==='psk'?'pre-shared-key ascii-text "CHANGE_ME_PSK";':''} }`);
        L.push(`${I(2)}gateway ikg-${vi} { address ${v.remote||'0.0.0.0'}; external-interface ${v.iface||'ge-0/0/0.0'}; ike-policy ikpol-${vi}; version ${v.ikeVer==='2'?'v2-only':'v1-only'}; }`);
      });
      L.push(`${I(1)}}`);
      L.push(`${I(1)}ipsec {`);
      iv2.forEach((v,vi)=>{
        const p2s=v.phase2&&v.phase2.length?v.phase2:[{name:v.name+'-P2',proposal:v.proposal,dhgrp:v.dhgrp,lifetime:'3600',localSub:'-',remoteSub:'-',pfs:'enable'}];
        p2s.forEach((p2,pi)=>{
          const [pe2,ph2]=splitProp(p2.proposal||v.proposal);
          L.push(`${I(2)}proposal isp-${vi}-${pi} { protocol esp; authentication-algorithm ${normHash(ph2,'juniper')}; encryption-algorithm ${normEnc(pe2,'juniper')}; lifetime-seconds ${p2.lifetime||'3600'}; }`);
          L.push(`${I(2)}policy isppol-${vi}-${pi} { perfect-forward-secrecy { keys ${normDH(p2.dhgrp||v.dhgrp,'juniper')}; } proposals isp-${vi}-${pi}; }`);
          L.push(`${I(2)}vpn ${v.name} { bind-interface st0.${vi}; ike { gateway ikg-${vi}; ipsec-policy isppol-${vi}-${pi}; }`);
          if(p2.localSub&&p2.localSub!=='-'){const ls=p2.localSub.replace(/\s+/,'/'); const rs=(p2.remoteSub||'').replace(/\s+/,'/'); L.push(`${I(3)}traffic-selector ts0 { local-ip ${ls}; remote-ip ${rs||'0.0.0.0/0'}; }`);}
          L.push(`${I(2)}}`);
        });
      });
      L.push(`${I(1)}}`);
    }
    L.push('}'); // close security
    L.push('');
    // protocols
    if(ospf2||bgp3){
      L.push('protocols {');
      if(ospf2) L.push(`${I(1)}ospf { ${ospf2.routerId?'router-id '+ospf2.routerId+';':''} area 0.0.0.0 { interface ge-0/0/1.0; } }`);
      if(bgp3) L.push(`${I(1)}bgp { local-as ${bgp3.as||'65000'}; ${bgp3.routerId?'router-id '+bgp3.routerId+';':''} }`);
      L.push('}');
    }
    return L.join('\n');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → pfSense config.xml
  // ══════════════════════════════════════════════════════════════════════════
  function toPfsense(parsed) {
    const L=[], d=parsed.deviceInfo;
    L.push('<?xml version="1.0"?>');
    L.push(`<!-- ${hdr(parsed.vendor||'?','pfSense config.xml',d.hostname)} -->`);
    L.push('<pfsense>');
    L.push('  <system>');
    L.push(`    <hostname>${esc(d.hostname)}</hostname>`);
    L.push('    <domain>local</domain><platform>pfSense</platform><version>2.7.2</version>');
    L.push('    <timeservers>pool.ntp.org</timeservers><timezone>Asia/Taipei</timezone>');
    // users
    parsed.users.filter(u=>u.type==='admin'||u.type==='local').forEach(u=>{
      L.push('    <user>');
      L.push(`      <name>${esc(u.name)}</name>`);
      L.push(`      <descr>${esc(u.comment&&u.comment!=='-'?u.comment:u.email&&u.email!=='-'?u.email:'')}</descr>`);
      L.push('      <bcrypt-hash>CHANGE_ME</bcrypt-hash>');
      if(u.email&&u.email!=='-') L.push(`      <email>${esc(u.email)}</email>`);
      if(u.accessLevel==='super-admin') L.push('      <scope>system</scope>\n      <priv>page-all</priv>');
      if(u.twoFactor&&u.twoFactor!=='disable') L.push('      <otp_seed>CHANGE_ME</otp_seed>');
      L.push('    </user>');
    });
    parsed.users.filter(u=>u.type==='group').forEach(g=>{
      L.push(`    <group><name>${esc(g.name)}</name><scope>local</scope>`);
      sl(g.members).forEach(m=>L.push(`      <member>${esc(m)}</member>`));
      L.push('    </group>');
    });
    parsed.users.filter(u=>u.type==='ldap-server').forEach(u=>{
      L.push(`    <authserver><type>ldap</type><name>${esc(u.name)}</name><host>${esc(u.server)}</host><port>${esc(u.port||'389')}</port><base_dn>${esc(u.dn||'-')}</base_dn>${u.bindDn&&u.bindDn!=='-'?`<binddn>${esc(u.bindDn)}</binddn>`:''}</authserver>`);
    });
    parsed.users.filter(u=>u.type==='radius-server').forEach(u=>{
      L.push(`    <authserver><type>radius</type><name>${esc(u.name)}</name><host>${esc(u.server)}</host><radius_auth_port>${esc(u.port||'1812')}</radius_auth_port></authserver>`);
    });
    L.push('  </system>');

    // interfaces
    // 2026-07-24 修復：原本 pfIfKeys 陣列只有 8 筆、.slice(0,8) 直接砍掉多餘介面，超過 8 個
    // 的介面（含其上的 VLAN 子介面）會靜默消失、無任何提示。pfSense 的 <interfaces> schema
    // 本身沒有數量上限（optN 可無限延伸），拿掉截斷；同時修正 key 產生公式的既有 off-by-one
    // （原本 fallback "opt${idx}" 在 idx=8 時會產生 "opt8"，直接跳過 "opt7"）
    const pfIfKey=idx=>idx===0?'wan':idx===1?'lan':`opt${idx-1}`;
    L.push('  <interfaces>');
    // 次要IP（2026-08-18 補上輸出端，累積各介面的內部代稱 key，供迴圈結束後組裝 <virtualip>
    // 區塊時引用；官方 docs.netgate.com "Virtual IP Addresses" 確認 IP Alias 是獨立於
    // <interfaces> 之外的頂層區塊，非巢狀在介面本身內，與 parser 端既有 parseSecondaryIps() 對稱）
    const pfSecondaryVips=[];
    parsed.interfaces.forEach((ifc,idx)=>{
      const key=pfIfKey(idx);
      L.push(`    <${key}>`);
      L.push(`      <if>${esc(ifc.name)}</if>`);
      L.push(`      <descr>${esc(ifc.alias&&ifc.alias!=='-'?ifc.alias:ifc.role||key.toUpperCase())}</descr>`);
      if(ifc.ip&&ifc.ip!=='-'&&ifc.ip!=='DHCP'){ L.push(`      <ipaddr>${esc(ifc.ip)}</ipaddr><subnet>${bits(ifc.mask)}</subnet>`); }
      else if(ifc.mode==='dhcp'||ifc.ip==='DHCP') L.push('      <ipaddr>dhcp</ipaddr>');
      if(ifc.status!=='down'&&ifc.status!=='Disable') L.push('      <enable></enable>');
      if(ifc.mtu&&ifc.mtu!=='1500') L.push(`      <mtu>${esc(ifc.mtu)}</mtu>`);
      L.push(`    </${key}>`);
      (ifc.secondaryIps||[]).forEach(s=>pfSecondaryVips.push({key,ip:s.ip,bits:bits(s.mask)}));
    });
    L.push('  </interfaces>');
    if(pfSecondaryVips.length){
      L.push('  <virtualip>');
      pfSecondaryVips.forEach(v=>{
        L.push('    <vip>');
        L.push('      <mode>ipalias</mode>');
        L.push(`      <interface>${esc(v.key)}</interface>`);
        L.push(`      <subnet>${esc(v.ip)}</subnet>`);
        L.push(`      <subnet_bits>${v.bits}</subnet_bits>`);
        L.push('    </vip>');
      });
      L.push('  </virtualip>');
    }

    // gateways
    const defRoute=parsed.routes.find(r=>(r.type==='static'||r.type==='default')&&(r.dst==='0.0.0.0/0'||r.dst.startsWith('0.0.0.0')));
    if(defRoute) L.push(`  <gateways><gateway_item><name>GW_WAN</name><gateway>${esc(defRoute.gateway)}</gateway><interface>wan</interface><defaultgw>yes</defaultgw></gateway_item></gateways>`);

    // static routes
    const sroutes2=parsed.routes.filter(r=>(r.type==='static'||r.type==='default')&&!r.dst.startsWith('0.0.0.0'));
    if(sroutes2.length){ L.push('  <staticroutes>'); sroutes2.forEach(r=>{ const dst2=r.dst.includes('/')?r.dst:r.dst.replace(/\s+/,'/'); L.push(`    <route><network>${esc(dst2)}</network><gateway>GW_WAN</gateway><descr>${esc(r.comment)}</descr>${r.status==='disable'?'<disabled></disabled>':''}</route>`); }); L.push('  </staticroutes>'); }

    // aliases
    const allAddrs2=parsed.addresses.filter(a=>a.category==='address');
    const allGrps2=parsed.addresses.filter(a=>a.category==='address-group');
    const allSvcs2=parsed.services.filter(s=>s.category==='custom');
    if(allAddrs2.length||allGrps2.length||allSvcs2.length){
      L.push('  <aliases>');
      allAddrs2.forEach(a=>{
        L.push(`    <alias><name>${esc(a.name)}</name>`);
        if(a.type==='fqdn') L.push(`      <type>url</type><address>${esc(a.fqdn)}</address>`);
        else if(a.type==='iprange') L.push(`      <type>host</type><address>${esc(a.startIp+'-'+a.endIp)}</address>`);
        else { const s3=addrCidr(a); L.push(`      <type>${s3.endsWith('/32')?'host':'network'}</type><address>${esc(s3)}</address>`); }
        L.push(`      <descr>${esc(a.comment&&a.comment!=='-'?a.comment:'')}</descr></alias>`);
      });
      allGrps2.forEach(g=>L.push(`    <alias><name>${esc(g.name)}</name><type>host</type><address>${esc(sl(g.members).join(' '))}</address><descr>${esc(g.comment&&g.comment!=='-'?g.comment:'')}</descr></alias>`));
      allSvcs2.forEach(s=>{ const ports2=(s.tcpPorts&&s.tcpPorts!=='-'?s.tcpPorts:s.udpPorts&&s.udpPorts!=='-'?s.udpPorts:'').replace(/,\s*/g,' '); L.push(`    <alias><name>${esc(s.name)}</name><type>port</type><address>${esc(ports2)}</address><descr>${esc(s.comment&&s.comment!=='-'?s.comment:'')}</descr></alias>`); });
      L.push('  </aliases>');
    }

    // firewall rules
    if(parsed.policies.length){
      L.push('  <filter>');
      parsed.policies.forEach(p=>{
        L.push('    <rule>');
        L.push(`      <type>${mapAction(p.action,'pfsense')}</type>`);
        L.push(`      <interface>${esc(mapZone(p.srcIntf,'pfsense'))}</interface>`);
        const proto3=(p.service&&p.service!=='ANY'&&p.service!=='any'&&p.service!=='-'&&p.service!=='-')?p.service.split(/[,\s:]/)[0].toLowerCase():'any';
        L.push(`      <protocol>${esc(proto3)}</protocol>`);
        L.push('      <source>');
        if(p.srcAddr&&p.srcAddr!=='any'&&p.srcAddr!=='-') L.push(`        <address>${esc(sl(p.srcAddr)[0]||p.srcAddr)}</address>`);
        else L.push('        <any/>');
        L.push('      </source>');
        L.push('      <destination>');
        if(p.dstAddr&&p.dstAddr!=='any'&&p.dstAddr!=='-') L.push(`        <address>${esc(sl(p.dstAddr)[0]||p.dstAddr)}</address>`);
        else L.push('        <any/>');
        L.push('      </destination>');
        L.push(`      <descr>${esc(p.name)}</descr>`);
        if(p.logtraffic&&p.logtraffic!=='disable') L.push('      <log></log>');
        if(p.status==='disable') L.push('      <disabled></disabled>');
        if(p.schedule&&p.schedule!=='always'&&p.schedule!=='-') L.push(`      <sched>${esc(p.schedule)}</sched>`);
        L.push('    </rule>');
      });
      L.push('  </filter>');
    }

    // nat
    const dnat2=parsed.nat.filter(n=>n.type==='vip');
    const snat2=parsed.nat.filter(n=>n.type==='ippool');
    if(dnat2.length||snat2.length){
      L.push('  <nat>');
      snat2.forEach(n=>L.push(`    <rule><interface>wan</interface><target>${esc(n.startIp||'-')}</target><descr>${esc(n.name)}</descr></rule>`));
      dnat2.forEach(n=>{ if(n.portFwd==='enable'||n.mapIp) L.push(`    <forward><interface>wan</interface><protocol>${esc(n.proto||'tcp')}</protocol><local-ip>${esc(n.mapIp||'-')}</local-ip><local-port>${esc(n.mapPort||n.extPort||'-')}</local-port><dstport>${esc(n.extPort||'-')}</dstport><descr>${esc(n.name)}</descr></forward>`); });
      L.push('  </nat>');
    }

    // ipsec vpn
    const iv3=parsed.vpn.filter(v=>v.type==='ipsec-p1');
    if(iv3.length){
      L.push('  <ipsec>');
      iv3.forEach((v,vi)=>{
        const [e3,h3]=splitProp(v.proposal);
        L.push(`    <phase1><ikeid>${vi+1}</ikeid><interface>wan</interface><remote-gateway>${esc(v.remote||'-')}</remote-gateway><authentication_method>${v.authMethod==='psk'?'pre_shared_key':'cert'}</authentication_method><encryption-algorithm>${normEnc(e3,'pfsense')}</encryption-algorithm><hash-algorithm>${normHash(h3,'pfsense')}</hash-algorithm><dhgroup>${normDH(v.dhgrp,'pfsense')}</dhgroup><lifetime>${v.lifetime||'28800'}</lifetime><iketype>${v.ikeVer==='2'?'ikev2':'ikev1'}</iketype><mode>${v.mode||'main'}</mode></phase1>`);
        (v.phase2||[]).forEach(p2=>{
          const [p2e,p2h]=splitProp(p2.proposal||v.proposal);
          const ls2=p2.localSub&&p2.localSub!=='-'?p2.localSub.split(/[\/\s]/):['0.0.0.0','24'];
          const rs2=p2.remoteSub&&p2.remoteSub!=='-'?p2.remoteSub.split(/[\/\s]/):['0.0.0.0','24'];
          L.push(`    <phase2><ikeid>${vi+1}</ikeid><encryption-algorithm>${normEnc(p2e,'pfsense')}</encryption-algorithm><hash-algorithm>${normHash(p2h,'pfsense')}</hash-algorithm><pfsgroup>${normDH(p2.dhgrp||v.dhgrp,'pfsense')}</pfsgroup><lifetime>${p2.lifetime||'3600'}</lifetime><localid><network>${ls2[0]}</network><subnet>${ls2[1]||'24'}</subnet></localid><remoteid><network>${rs2[0]}</network><subnet>${rs2[1]||'24'}</subnet></remoteid></phase2>`);
        });
      });
      L.push('  </ipsec>');
    }

    // openvpn
    const ssl3=parsed.vpn.filter(v=>v.type==='ssl-vpn');
    if(ssl3.length){ L.push('  <openvpn>'); ssl3.forEach((v,vi)=>L.push(`    <openvpn-server><vpnid>${vi+1}</vpnid><mode>server_tls</mode><interface>wan</interface><local_port>${v.port||'1194'}</local_port><tunnel_network>${esc(v.ipPool&&v.ipPool!=='-'?v.ipPool:'10.200.0.0/24')}</tunnel_network><description>${esc(v.name)}</description><crypto>${esc(v.algorithm||'AES-256-CBC')}</crypto>${v.dns1&&v.dns1!=='-'?`<dns_server1>${esc(v.dns1)}</dns_server1>`:''}</openvpn-server>`)); L.push('  </openvpn>'); }

    // schedules
    if(parsed.schedules.length){ L.push('  <schedules>'); parsed.schedules.forEach(s=>L.push(`    <schedule><name>${esc(s.name)}</name><timerange><from>${esc(s.start||'08:00')}</from><to>${esc(s.end||'18:00')}</to>${s.day&&s.day!=='-'?`<day>${esc(s.day)}</day>`:''}</timerange></schedule>`)); L.push('  </schedules>'); }

    L.push('</pfsense>');
    return L.join('\n');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → Cisco ASA
  // ══════════════════════════════════════════════════════════════════════════
  function toCiscoASA(parsed) {
    const L=[], d=parsed.deviceInfo;
    // Local helpers — turn a policy's service/address strings into ASA ACL syntax
    const svcOf = svc => {
      const first=(sl(svc)[0]||'any').toLowerCase();
      if(!first||first==='any'||first==='all'||first==='-') return {proto:'ip',port:null};
      const m=first.match(/^(tcp|udp|icmp)\/?(\d+)?$/);
      if(m) return {proto:m[1],port:m[2]||null};
      if(/^\d+$/.test(first)) return {proto:'tcp',port:first};
      return {proto:'tcp',port:null};
    };
    const addrOf = addr => {
      const first=sl(addr)[0]||'any';
      if(!first||/^(any|all|-)$/i.test(first)) return 'any';
      const ipMask=first.match(/^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$/);
      if(ipMask) return `${ipMask[1]} ${ipMask[2]}`;
      if(first.includes('/')) { const [ip,pfx]=first.split('/'); return pfx==='32'?`host ${ip}`:`${ip} ${maskOf(pfx)}`; }
      if(/^\d+\.\d+\.\d+\.\d+$/.test(first)) return `host ${first}`;
      return `object ${first}`;
    };
    // ASA ACL 沒有天然的「any」介面，找不到明確來源介面時退回 inside 而非 mapZone() 的通用 fallback 'any'
    const intfOf = role => { const z=mapZone(role,'ciscoasa'); return z==='any'?'inside':z; };
    // 2026-07-24 修復：來源若有兩個以上同角色介面（如 wan1+wan2-pppoe 皆對應 outside），
    // 原本會產生兩個介面同時 "nameif outside"，真實 ASA 上 nameif 必須唯一、會被拒絕。
    // 先算好一份計數表，重複時自動加編號區分（outside/outside2/outside3...）
    const nameifCounts={};
    const nameifOf=i=>{
      const base=i.nameif||intfOf(i.role);
      nameifCounts[base]=(nameifCounts[base]||0)+1;
      return nameifCounts[base]===1?base:`${base}${nameifCounts[base]}`;
    };

    L.push(`: ${hdr(parsed.vendor||'?','Cisco ASA 9.x',d.hostname)}`);
    L.push(`hostname ${d.hostname}`);
    L.push('');

    // Interfaces — 若原始資料本身就是 ASA（有 nameif/secLevel 欄位）直接沿用以利 round-trip，
    // 其餘廠牌來源用 role 概略對應
    parsed.interfaces.forEach(i=>{
      L.push(`interface ${i.name}`);
      L.push(` nameif ${nameifOf(i)}`);
      const sec = (typeof i.secLevel==='number'&&i.secLevel>=0) ? i.secLevel : (/wan|untrust|outside|external/i.test(i.role||'')?0:/dmz/i.test(i.role||'')?50:100);
      L.push(` security-level ${sec}`);
      // 2026-07-24 新增：VLAN 子介面需要 "vlan N" 子指令才能真正生效，原本完全沒有輸出
      if(i.type==='vlan'&&i.vlanId&&i.vlanId!=='-') L.push(` vlan ${i.vlanId}`);
      if(i.ip&&i.ip!=='-'&&i.ip!=='DHCP') {
        const mask=i.mask&&i.mask!=='-'?(i.mask.includes('.')?i.mask:maskOf(i.mask)):'255.255.255.0';
        L.push(` ip address ${i.ip} ${mask}`);
      }
      if(i.desc&&i.desc!=='-') L.push(` description ${i.desc}`);
      if(i.status==='down') L.push(' shutdown');
    });
    L.push('');

    // Routes — r.device 對 ASA 來源本身就是真實 nameif（如 outside/inside），對其餘廠牌則是
    // role 提示需經 intfOf() 概略對應；type 需同時涵蓋 static/default（2026-07-21 查核發現原本
    // 漏了 default，會把來源廠牌的預設路由靜默丟棄，比照其餘 8 個轉換函式一致的過濾條件補上）
    parsed.routes.filter(r=>r.type==='static'||r.type==='default').forEach(r=>{
      const {net,mask}=netMaskOf(r.dst, r.mask);
      L.push(`route ${intfOf(r.device)} ${net} ${mask} ${r.gateway||'0.0.0.0'}${r.distance&&r.distance!=='-'?' '+r.distance:''}`);
    });
    L.push('');

    // Address / service objects
    parsed.addresses.filter(a=>a.category==='address').forEach(a=>{
      L.push(`object network ${a.name}`);
      if(a.type==='fqdn') L.push(` fqdn ${a.fqdn}`);
      else if(a.type==='iprange') L.push(` range ${a.startIp} ${a.endIp}`);
      else {
        const sub=a.subnet||(a.ip?a.ip+'/32':'0.0.0.0/0');
        const ip=sub.split(/[\/\s]/)[0]; const sfx=sub.includes('/')?sub.split('/')[1]:bits(sub.split(' ')[1]||'255.255.255.255');
        if(String(sfx)==='32'||!sub.includes('/')) L.push(` host ${ip}`);
        else L.push(` subnet ${ip} ${maskOf(sfx)}`);
      }
    });
    parsed.addresses.filter(a=>a.category==='address-group').forEach(g=>{
      L.push(`object-group network ${g.name}`);
      sl(g.members).forEach(m=>L.push(` network-object object ${m}`));
    });
    parsed.services.filter(s=>s.category==='custom').forEach(s=>{
      const p=(s.proto||'tcp').toLowerCase();
      L.push(`object service ${s.name}`);
      if(p.includes('icmp')) L.push(' service icmp');
      else { const port=p.includes('udp')?(s.udpPorts!=='-'?s.udpPorts:s.tcpPorts):(s.tcpPorts!=='-'?s.tcpPorts:s.udpPorts); L.push(` service ${p.includes('udp')?'udp':'tcp'} destination eq ${port||'0'}`); }
    });
    parsed.services.filter(s=>s.category==='group').forEach(g=>{
      L.push(`object-group service ${g.name}`);
      sl(g.members).forEach(m=>L.push(` service-object object ${m}`));
    });
    L.push('');

    // VPN — site-to-site IPsec only (AnyConnect/SSL-VPN 無明確可還原欄位，略過)
    const ivpns=parsed.vpn.filter(v=>v.type==='ipsec-p1');
    ivpns.forEach((v,vi)=>{
      const [e,h]=splitProp(v.proposal);
      const polNum=10+vi;
      L.push(`crypto isakmp policy ${polNum}`);
      L.push(` authentication ${v.authMethod==='psk'?'pre-share':'rsa-sig'}`);
      L.push(` encryption ${normEnc(e,'ciscoasa')}`);
      L.push(` hash ${normHash(h,'ciscoasa')}`);
      L.push(` group ${normDH(v.dhgrp,'ciscoasa')}`);
      L.push(` lifetime ${v.lifetime||'86400'}`);
      const p2=(v.phase2||[])[0];
      const [pe,ph]=splitProp(p2?(p2.proposal||v.proposal):v.proposal);
      const xform=`TS-${v.name}`;
      L.push(`crypto ipsec transform-set ${xform} esp-${normEnc(pe,'ciscoasa')} esp-${normHash(ph,'ciscoasa')}-hmac`);
      const aclName=`${v.name}-acl`;
      if(p2&&p2.localSub&&p2.localSub!=='-'&&p2.remoteSub&&p2.remoteSub!=='-') {
        const [lnet,lpfx]=p2.localSub.includes('/')?p2.localSub.split('/'):p2.localSub.split(/\s+/);
        const [rnet,rpfx]=p2.remoteSub.includes('/')?p2.remoteSub.split('/'):p2.remoteSub.split(/\s+/);
        L.push(`access-list ${aclName} extended permit ip ${lnet} ${maskOf(lpfx||'24')} ${rnet} ${maskOf(rpfx||'24')}`);
      }
      const mapName='OUTSIDE-MAP';
      L.push(`crypto map ${mapName} ${polNum} match address ${aclName}`);
      L.push(`crypto map ${mapName} ${polNum} set peer ${v.remote||'0.0.0.0'}`);
      L.push(`crypto map ${mapName} ${polNum} set transform-set ${xform}`);
      if(p2&&p2.lifetime&&p2.lifetime!=='-') L.push(`crypto map ${mapName} ${polNum} set security-association lifetime seconds ${p2.lifetime}`);
      if(v.ikeVer==='2') L.push(`crypto map ${mapName} ${polNum} set ikev2 ipsec-proposal ${xform}`);
      L.push(`tunnel-group ${v.remote||'0.0.0.0'} type ipsec-l2l`);
      L.push(`tunnel-group ${v.remote||'0.0.0.0'} ipsec-attributes`);
      L.push(' pre-shared-key PLACEHOLDER');
    });
    if(ivpns.length) L.push(`crypto map OUTSIDE-MAP interface ${mapZone('WAN','ciscoasa')}`);
    L.push('');

    // NAT
    parsed.nat.forEach(n=>{
      const inIf=n.srcIf||intfOf(n.srcIntf||'LAN'), outIf=n.dstIf||intfOf(n.extIntf||'WAN');
      if(n.type==='static'||n.type==='vip') L.push(`nat (${inIf},${outIf}) source static ${n.mapIp||n.origSrc||'any'} ${n.extIp||n.transSrc||'interface'}`);
      else L.push(`nat (${inIf},${outIf}) source dynamic ${n.origSrc||'any'} ${n.transSrc||'interface'}`);
    });
    L.push('');

    // ACL policies + access-group binding
    const boundIntf=new Set();
    parsed.policies.forEach(p=>{
      const intf=intfOf(p.srcIntf);
      const aclName=`${intf}_access_in`;
      const {proto,port}=svcOf(p.service);
      let line=`access-list ${aclName} extended ${mapAction(p.action,'ciscoasa')} ${proto} ${addrOf(p.srcAddr)} ${addrOf(p.dstAddr)}`;
      if(port) line+=` eq ${port}`;
      if(p.status==='disable') line+=' inactive';
      L.push(line);
      boundIntf.add(intf);
    });
    boundIntf.forEach(intf=>L.push(`access-group ${intf}_access_in in interface ${intf}`));
    L.push('');

    // Users
    parsed.users.filter(u=>u.type==='admin'||u.type==='local').forEach(u=>{
      L.push(`username ${u.name} password PLACEHOLDER ${u.accessLevel==='read-only'?'privilege 5':'privilege 15'}`);
    });

    // HA（2026-08-20 新增，LOSS_FIELDS 同廠牌自轉補齊，FTD 委派同一套邏輯一併受益）：
    // 比照 parseHa() 已查證的官方 Failover 語法。syncInterface 存的是 "LOGICAL (PHYSICAL)"
    // 組合字串（parser 端 `failover lan interface <logical> <physical>` 兩個 token 各自
    // 存的位置），輸出時需拆解還原成兩個獨立 token；mask 因 parseHa() 本身未擷取保留、
    // 不影響 groupId/mode/priority/peerIp/vip 的 round-trip，固定輸出常見 /24
    if(parsed.ha&&parsed.ha.enabled){
      const ha=parsed.ha;
      L.push('');
      L.push('failover');
      if(ha.mode==='primary')L.push('failover lan unit primary');
      else if(ha.mode==='secondary')L.push('failover lan unit secondary');
      const syncM=ha.syncInterface&&ha.syncInterface!=='-'?ha.syncInterface.match(/^(\S+)\s+\(([^)]+)\)$/):null;
      const logicalName=syncM?syncM[1]:'state';
      const physIface=syncM?syncM[2]:'GigabitEthernet0/3';
      L.push(`failover lan interface ${logicalName} ${physIface}`);
      if(ha.vip&&ha.vip!=='-'&&ha.peerIp&&ha.peerIp!=='-')L.push(`failover interface ip ${logicalName} ${ha.vip} 255.255.255.0 standby ${ha.peerIp}`);
      if(ha.groupId&&ha.groupId!=='-')L.push(`failover group ${ha.groupId}`);
    }

    return L.join('\n');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → Cisco FTD（沿用 ASA Lina CLI 語法，比照 CiscoFTDParser 委派同一套解析邏輯）
  // ══════════════════════════════════════════════════════════════════════════
  function toCiscoFTD(parsed) {
    const out=toCiscoASA(parsed);
    return out.replace(/^: .*$/m, `: ${hdr(parsed.vendor||'?','Cisco Firepower/FTD',parsed.deviceInfo.hostname)}\n: NGFW Version 7.4`);
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → SonicWall SonicOS
  // ══════════════════════════════════════════════════════════════════════════
  function toSonicWall(parsed) {
    const L=[], d=parsed.deviceInfo;
    L.push('<?xml version="1.0" encoding="UTF-8"?>');
    L.push(`<!-- ${hdr(parsed.vendor||'?','SonicOS <6.2',d.hostname)} -->`);
    L.push('<SonicWALLConfig>');
    L.push('  <DeviceInfo>');
    // 2026-08-09 修復：原本用 <Name> 標籤，但 SonicWallParser.parseDeviceInfo() 只認
    // DeviceName/HostName/Hostname 三種標籤，<Name> 打不中導致轉換後讀不回 hostname
    // （round-trip 測試 CV42b 發現，用 Node 實測確認修復前必定回傳 "-"）
    L.push(`    <DeviceName>${esc(d.hostname)}</DeviceName>`);
    L.push(`    <FirmwareVersion>${esc(d.firmware)}</FirmwareVersion>`);
    L.push(`    <Model>${esc(d.model||'TZ')}</Model>`);
    L.push('  </DeviceInfo>');

    if(parsed.interfaces.length) {
      // 2026-08-09 修正：改用 SonicWallParser 註明「主要（已驗證）」的標籤
      // <InterfaceSettings><InterfaceEntry>，原本用的 <Interfaces><Interface> 是該 parser
      // 自己標註「未證實對應版本」的欄位命名容錯別名
      L.push('  <InterfaceSettings>');
      parsed.interfaces.forEach(i=>{
        L.push('    <InterfaceEntry>');
        L.push(`      <Name>${esc(i.name)}</Name>`);
        if(i.ip&&i.ip!=='-'&&i.ip!=='DHCP') { L.push(`      <IPAddress>${esc(i.ip)}</IPAddress>`); L.push(`      <Netmask>${esc(i.mask&&i.mask!=='-'?i.mask:'255.255.255.0')}</Netmask>`); }
        L.push(`      <Zone>${esc(mapZone(i.role,'sonicwall'))}</Zone>`);
        if(i.desc&&i.desc!=='-') L.push(`      <Comment>${esc(i.desc)}</Comment>`);
        L.push('    </InterfaceEntry>');
      });
      L.push('  </InterfaceSettings>');
    }

    const sroutes=parsed.routes.filter(r=>r.type==='static'||r.type==='default');
    if(sroutes.length) {
      L.push('  <Routes>');
      sroutes.forEach(r=>{ const {net,mask}=netMaskOf(r.dst,r.mask); L.push(`    <Route><Destination>${esc(net)}</Destination><Netmask>${esc(mask)}</Netmask><Gateway>${esc(r.gateway||'-')}</Gateway><Metric>${esc(r.distance!=='-'&&r.distance?r.distance:(r.metric||'1'))}</Metric></Route>`); });
      L.push('  </Routes>');
    }

    const ivpns=parsed.vpn.filter(v=>v.type==='ipsec-p1');
    if(ivpns.length) {
      L.push('  <VPNPolicies>');
      ivpns.forEach(v=>{
        const [e,h]=splitProp(v.proposal);
        L.push('    <VpnPolicy>');
        L.push(`      <Name>${esc(v.name)}</Name>`);
        L.push(`      <GatewayAddress>${esc(v.remote||'-')}</GatewayAddress>`);
        L.push(`      <IKEVersion>${esc(v.ikeVer||'1')}</IKEVersion>`);
        L.push(`      <Encryption>${normEnc(e,'sonicwall')}</Encryption>`);
        L.push(`      <Authentication>${normHash(h,'sonicwall')}</Authentication>`);
        L.push(`      <DHGroup>${normDH(v.dhgrp,'sonicwall')}</DHGroup>`);
        L.push(`      <Lifetime>${esc(v.lifetime||'28800')}</Lifetime>`);
        L.push('    </VpnPolicy>');
      });
      L.push('  </VPNPolicies>');
    }

    if(parsed.nat.length) {
      // 2026-08-09 查證：NAT 標籤與 Interface/AccessRule 不同，SonicWallParser 對 NAT 容器/
      // 元素命名（NatEntry/NATEntry/NATRule/OneToOneNATEntry）並未標註任何一個是「主要
      // （已驗證）」標籤，全部都是「未證實對應版本」的欄位命名容錯，故無可換用的已驗證
      // 標籤，維持現狀，待未來取得真實 SonicOS <6.2 XML 範例才能確認
      L.push('  <NATPolicies>');
      parsed.nat.forEach(n=>{
        L.push('    <NatEntry>');
        L.push(`      <Name>${esc(n.name)}</Name>`);
        L.push(`      <OriginalSource>${esc(n.origSrc||n.startIp||'-')}</OriginalSource>`);
        L.push(`      <TranslatedSource>${esc(n.transSrc||n.mapIp||'-')}</TranslatedSource>`);
        L.push('    </NatEntry>');
      });
      L.push('  </NATPolicies>');
    }

    if(parsed.policies.length) {
      // 2026-08-09 修正：改用 SonicWallParser 註明「主要（已驗證）」的標籤 <Rule>，原本用
      // 的 <AccessRule> 是該 parser 自己標註「未證實對應版本」的欄位命名容錯別名
      L.push('  <AccessRules>');
      parsed.policies.forEach(p=>{
        L.push('    <Rule>');
        L.push(`      <Name>${esc(p.name)}</Name>`);
        L.push(`      <SourceZone>${esc(mapZone(p.srcIntf,'sonicwall'))}</SourceZone>`);
        L.push(`      <DestinationZone>${esc(mapZone(p.dstIntf,'sonicwall'))}</DestinationZone>`);
        L.push(`      <Source>${esc(sl(p.srcAddr)[0]||'any')}</Source>`);
        L.push(`      <Destination>${esc(sl(p.dstAddr)[0]||'any')}</Destination>`);
        L.push(`      <Service>${esc(sl(p.service)[0]||'any')}</Service>`);
        L.push(`      <Action>${mapAction(p.action,'sonicwall')}</Action>`);
        L.push(`      <Enabled>${p.status==='disable'?'false':'true'}</Enabled>`);
        L.push('    </Rule>');
      });
      L.push('  </AccessRules>');
    }

    L.push('</SonicWALLConfig>');
    return L.join('\n');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  → MikroTik RouterOS
  // ══════════════════════════════════════════════════════════════════════════
  // ══════════════════════════════════════════════════════════════════════════
  //  → Zyxel USG/ATP (ZLD)
  // ══════════════════════════════════════════════════════════════════════════
  function toZyxel(parsed) {
    const L=[], d=parsed.deviceInfo;
    L.push(`! ${hdr(parsed.vendor||'?','ZLD (USG FLEX/ATP)',d.hostname)}`);
    L.push(`hostname ${d.hostname||'Zyxel'}`);
    L.push('');

    parsed.interfaces.forEach(i=>{
      if(!i.ip||i.ip==='-'||i.ip==='DHCP')return;
      L.push(`interface ${i.name}`);
      if(i.desc&&i.desc!=='-')L.push(` description ${i.desc}`);
      const mask=i.mask&&i.mask!=='-'?i.mask:'255.255.255.0';
      L.push(` ip address ${i.ip} ${mask}`);
      L.push('exit');
    });
    if(parsed.interfaces.some(i=>i.ip&&i.ip!=='-'&&i.ip!=='DHCP'))L.push('');

    const sroutes=parsed.routes.filter(r=>r.type==='static'||r.type==='default');
    sroutes.forEach(r=>{
      const {net,mask}=netMaskOf(r.dst,r.mask);
      L.push(`ip route ${net} ${mask} ${r.gateway&&r.gateway!=='-'?r.gateway:(r.device||'0.0.0.0')}${r.distance&&r.distance!=='-'&&r.distance!=='0'?' '+r.distance:''}`);
    });
    if(sroutes.length)L.push('');

    // address-object/service-object 皆需在 secure-policy 之前先宣告（ZLD 語法要求物件
    // 先建立才能被規則引用），逐規則依 srcAddr/dstAddr/service 動態合成物件名稱
    const addrNames={};
    const svcNames={};
    let addrSeq=1, svcSeq=1;
    const addrObjLines=[], svcObjLines=[];
    const nz=(v,fb)=>(v&&v!=='-'&&!/^(any|all)$/i.test(v))?v:fb;
    function addrObjFor(val){
      if(!val||/^(any|all|-)$/i.test(val))return null;
      const first=sl(val)[0]||val;
      if(addrNames[first])return addrNames[first];
      const name=`ADDR_${addrSeq++}`;
      addrNames[first]=name;
      addrObjLines.push(`address-object ${name} ${first}`);
      return name;
    }
    function svcObjFor(val){
      if(!val||/^(any|all|-)$/i.test(val))return null;
      const svc=sl(val)[0]||val;
      const m=svc.match(/^(tcp|udp)\/(\d+)$/i);
      if(!m)return null;
      const key=svc.toLowerCase();
      if(svcNames[key])return svcNames[key];
      const name=`SVC_${svcSeq++}`;
      svcNames[key]=name;
      svcObjLines.push(`service-object ${name} ${m[1].toLowerCase()} eq ${m[2]}`);
      return name;
    }
    const ruleBlocks=[];
    parsed.policies.forEach((p,idx)=>{
      const srcObj=addrObjFor(p.srcAddr);
      const dstObj=addrObjFor(p.dstAddr);
      const svcObj=svcObjFor(p.service);
      const lines=[`secure-policy insert ${idx+1}`];
      lines.push(` from ${nz(p.srcIntf,'any')}`);
      lines.push(` to ${nz(p.dstIntf,'any')}`);
      if(srcObj)lines.push(` sourceip ${srcObj}`);
      if(dstObj)lines.push(` destinationip ${dstObj}`);
      if(svcObj)lines.push(` service ${svcObj}`);
      lines.push(` action ${mapAction(p.action,'zyxel')}`);
      if(p.name)lines.push(` name ${p.name.replace(/\s+/g,'_')}`);
      if(p.status==='disable')lines.push(' no activate');
      lines.push('exit');
      ruleBlocks.push(lines.join('\n'));
    });
    if(addrObjLines.length){L.push(...addrObjLines);L.push('');}
    if(svcObjLines.length){L.push(...svcObjLines);L.push('');}
    if(ruleBlocks.length){L.push(...ruleBlocks);L.push('');}

    return L.join('\n');
  }

  function toEdgeRouter(parsed) {
    // EdgeOS config.boot 是巢狀大括號樹狀格式（非扁平 CLI），與其餘轉換函式輸出風格不同，
    // 需注意縮排與 } 收尾正確性。來源 parsed.policies 是扁平清單、無「具名規則集綁定介面」
    // 概念，轉換時無法得知原始規則該歸屬哪個介面方向，故統一併入單一規則集 CONVERTED_IN
    // （不綁定任何介面，需使用者手動 attach），已於 getConversionCaveats() 提醒此限制
    const L=[], d=parsed.deviceInfo;
    L.push(`/* ${hdr(parsed.vendor||'?','EdgeOS',d.hostname)} */`);
    L.push('system {');
    L.push(`    host-name ${d.hostname||'ubnt'}`);
    L.push('}');

    const ifaceLines=[];
    parsed.interfaces.forEach(i=>{
      const hasIp=i.ip&&i.ip!=='-'&&i.ip!=='DHCP';
      const hasSecondary=i.secondaryIps&&i.secondaryIps.length;
      if(!hasIp&&!hasSecondary)return;
      ifaceLines.push(`    ethernet ${i.name} {`);
      if(hasIp)ifaceLines.push(`        address ${i.ip}/${bits(i.mask||'255.255.255.0')}`);
      // 次要IP（2026-08-18 補上輸出端，官方 VyOS/EdgeOS 文件確認同一介面可重複宣告多筆
      // address statement 即為附加式次要IP，無 secondary 關鍵字，與 parser 端既有
      // vals(node,'address').slice(1) 語法對稱）
      (i.secondaryIps||[]).forEach(s=>ifaceLines.push(`        address ${s.ip}/${bits(s.mask||'255.255.255.0')}`));
      if(i.desc&&i.desc!=='-')ifaceLines.push(`        description ${i.desc}`);
      ifaceLines.push('    }');
    });
    if(ifaceLines.length){L.push('interfaces {');L.push(...ifaceLines);L.push('}');}

    const rules=parsed.policies||[];
    if(rules.length){
      L.push('firewall {');
      L.push('    name CONVERTED_IN {');
      L.push('        default-action drop');
      rules.forEach((p,idx)=>{
        const num=(idx+1)*10;
        const [svcProto,svcPort]=(p.service&&p.service.includes('/'))?p.service.split('/'):[p.service||'all',''];
        L.push(`        rule ${num} {`);
        L.push(`            action ${p.action==='accept'?'accept':'drop'}`);
        if(p.comments)L.push(`            description "${p.comments.replace(/"/g,"'")}"`);
        if(svcProto&&!/^(any|all)$/i.test(svcProto))L.push(`            protocol ${svcProto}`);
        if(p.srcAddr&&!/^(any|-)$/.test(p.srcAddr)){
          L.push('            source {');
          L.push(`                address ${p.srcAddr}`);
          L.push('            }');
        }
        if((p.dstAddr&&!/^(any|-)$/.test(p.dstAddr))||svcPort){
          L.push('            destination {');
          if(p.dstAddr&&!/^(any|-)$/.test(p.dstAddr))L.push(`                address ${p.dstAddr}`);
          if(svcPort)L.push(`                port ${svcPort}`);
          L.push('            }');
        }
        if(p.logtraffic==='all')L.push('            log enable');
        if(p.status==='disable')L.push('            disable');
        L.push('        }');
      });
      L.push('    }');
      L.push('}');
    }

    const natRules=parsed.nat||[];
    if(natRules.length){
      L.push('service {');
      L.push('    nat {');
      natRules.forEach((n,idx)=>{
        const num=5000+idx*10;
        L.push(`        rule ${num} {`);
        if(n.comment)L.push(`            description "${n.comment.replace(/"/g,"'")}"`);
        if(n.type==='vip'){
          L.push('            type destination');
          if(n.extIntf&&n.extIntf!=='-')L.push(`            inbound-interface ${n.extIntf}`);
          L.push('            destination {');
          if(n.extIp&&n.extIp!=='-')L.push(`                address ${n.extIp}`);
          if(n.extPort&&n.extPort!=='-')L.push(`                port ${n.extPort}`);
          L.push('            }');
          L.push('            inside-address {');
          if(n.mapIp&&n.mapIp!=='-')L.push(`                address ${n.mapIp}`);
          if(n.mapPort&&n.mapPort!=='-')L.push(`                port ${n.mapPort}`);
          L.push('            }');
        }else if(n.mapIp==='masquerade'||n.poolType==='masquerade'){
          L.push('            type masquerade');
          if(n.extIntf&&n.extIntf!=='-')L.push(`            outbound-interface ${n.extIntf}`);
        }else{
          L.push('            type source');
          if(n.extIntf&&n.extIntf!=='-')L.push(`            outbound-interface ${n.extIntf}`);
          if(n.extIp&&n.extIp!=='-'){
            L.push('            source {');
            L.push(`                address ${n.extIp}`);
            L.push('            }');
          }
          if(n.mapIp&&n.mapIp!=='-'&&n.mapIp!=='masquerade'){
            L.push('            outside-address {');
            L.push(`                address ${n.mapIp}`);
            L.push('            }');
          }
        }
        if(n.proto&&n.proto!=='-')L.push(`            protocol ${n.proto}`);
        L.push('        }');
      });
      L.push('    }');
      L.push('}');
    }

    const routes=(parsed.routes||[]).filter(r=>r.type==='static'||r.type==='default');
    if(routes.length){
      L.push('protocols {');
      L.push('    static {');
      routes.forEach(r=>{
        L.push(`        route ${r.dst} {`);
        const nh=r.gateway&&r.gateway!=='-'?r.gateway:(r.device||'0.0.0.0');
        L.push(`            next-hop ${nh} {`);
        if(r.distance&&r.distance!=='-'&&r.distance!=='0')L.push(`                distance ${r.distance}`);
        L.push('            }');
        L.push('        }');
      });
      L.push('    }');
      L.push('}');
    }

    return L.join('\n');
  }

  function toOpenWrt(parsed) {
    // UCI stanza 格式（package/config/option/list），與其餘多數轉換函式的扁平 CLI／巢狀
    // 大括號風格皆不同。來源 parsed.policies 的 srcIntf/dstIntf 未必是 UCI 慣用的 zone
    // 名稱，此處直接沿用其值當 zone 名稱並自動合成對應 config zone 區塊（list network 用
    // 同名），讓輸出至少能自我一致（zone 有定義），已於 getConversionCaveats() 提醒人工
    // 核對這組自動合成的 zone／network 對應是否符合實際拓樸
    const L=[], d=parsed.deviceInfo;
    const maskFromBits=(bits)=>{if(!Number.isFinite(bits))return '255.255.255.0';const m=bits===0?0:(0xFFFFFFFF<<(32-bits))>>>0;return [(m>>>24)&255,(m>>>16)&255,(m>>>8)&255,m&255].join('.');};
    L.push(`# ${hdr(parsed.vendor||'?','OpenWrt (UCI)',d.hostname)}`);
    L.push('');
    L.push(`package network`);
    L.push('');
    parsed.interfaces.forEach(i=>{
      if(!i.ip||i.ip==='-'||i.ip==='DHCP')return;
      L.push(`config interface '${i.name}'`);
      L.push(`\toption ifname '${i.name}'`);
      L.push(`\toption proto 'static'`);
      L.push(`\toption ipaddr '${i.ip}'`);
      if(i.mask&&i.mask!=='-')L.push(`\toption netmask '${i.mask}'`);
      // 次要IP（2026-08-18 補上輸出端，官方 OpenWrt UCI 慣例確認額外位址用重複的
      // list ipaddr 'A.B.C.D/N' 行（CIDR 格式，與主要位址 option ipaddr/option netmask
      // 分開兩欄不同），與 parser 端既有 s.lists.ipaddr 語法對稱）
      (i.secondaryIps||[]).forEach(s=>L.push(`\tlist ipaddr '${cidr(s.ip,s.mask)}'`));
      L.push('');
    });
    const routes=(parsed.routes||[]).filter(r=>r.type==='static'||r.type==='default');
    routes.forEach(r=>{
      const [net,bitsStr]=r.dst.split('/');
      L.push(`config route`);
      L.push(`\toption target '${net}'`);
      if(bitsStr)L.push(`\toption netmask '${maskFromBits(parseInt(bitsStr,10))}'`);
      if(r.gateway&&r.gateway!=='-')L.push(`\toption gateway '${r.gateway}'`);
      if(r.device&&r.device!=='-')L.push(`\toption interface '${r.device}'`);
      L.push('');
    });
    L.push(`package firewall`);
    L.push('');
    const zones=new Set();
    (parsed.policies||[]).forEach(p=>{
      if(p.srcIntf&&p.srcIntf!=='any')zones.add(p.srcIntf);
      if(p.dstIntf&&p.dstIntf!=='any')zones.add(p.dstIntf);
    });
    zones.forEach(z=>{
      L.push(`config zone`);
      L.push(`\toption name '${z}'`);
      L.push(`\tlist network '${z}'`);
      L.push(`\toption input 'ACCEPT'`);
      L.push(`\toption output 'ACCEPT'`);
      L.push(`\toption forward 'REJECT'`);
      L.push('');
    });
    (parsed.policies||[]).forEach(p=>{
      L.push(`config rule`);
      if(p.name)L.push(`\toption name '${p.name}'`);
      if(p.srcIntf&&p.srcIntf!=='any')L.push(`\toption src '${p.srcIntf}'`);
      if(p.dstIntf&&p.dstIntf!=='any')L.push(`\toption dest '${p.dstIntf}'`);
      const [svcProto,svcPort]=(p.service&&p.service.includes('/'))?p.service.split('/'):[p.service||'any',''];
      if(svcProto&&!/^(any|all)$/i.test(svcProto))L.push(`\toption proto '${svcProto}'`);
      if(svcPort)L.push(`\toption dest_port '${svcPort}'`);
      if(p.srcAddr&&!/^(any|-)$/.test(p.srcAddr))L.push(`\toption src_ip '${p.srcAddr}'`);
      if(p.dstAddr&&!/^(any|-)$/.test(p.dstAddr))L.push(`\toption dest_ip '${p.dstAddr}'`);
      L.push(`\toption target '${p.action==='accept'?'ACCEPT':'REJECT'}'`);
      if(p.status==='disable')L.push(`\toption enabled '0'`);
      L.push('');
    });
    (parsed.nat||[]).forEach(n=>{
      L.push(`config redirect`);
      if(n.comment)L.push(`\toption name '${n.comment}'`);
      if(n.type==='vip'){
        if(n.extIntf&&n.extIntf!=='-')L.push(`\toption src '${n.extIntf}'`);
        if(n.extPort&&n.extPort!=='-')L.push(`\toption src_dport '${n.extPort}'`);
        if(n.mapIp&&n.mapIp!=='-')L.push(`\toption dest_ip '${n.mapIp}'`);
        if(n.mapPort&&n.mapPort!=='-')L.push(`\toption dest_port '${n.mapPort}'`);
      }else{
        L.push(`\toption target 'SNAT'`);
        if(n.extIntf&&n.extIntf!=='-')L.push(`\toption src '${n.extIntf}'`);
        if(n.extIp&&n.extIp!=='-')L.push(`\toption src_ip '${n.extIp}'`);
        if(n.mapIp&&n.mapIp!=='-'&&n.mapIp!=='masquerade')L.push(`\toption src_dip '${n.mapIp}'`);
      }
      if(n.proto&&n.proto!=='-')L.push(`\toption proto '${n.proto}'`);
      L.push('');
    });
    return L.join('\n').replace(/\n+$/,'\n');
  }

  function toMikrotik(parsed) {
    const L=[], d=parsed.deviceInfo;
    L.push(`# ${hdr(parsed.vendor||'?','RouterOS 7',d.hostname)}`);
    L.push(`/system identity set name=${d.hostname}`);
    L.push('');

    // 2026-07-24 修復：原本直接把 "port5.100" 這種點號子介面名稱塞進 interface= 參數，
    // RouterOS 完全沒有這種命名慣例（會被當成一個不存在的介面字面字串，語意錯誤）。
    // 改為先產生原生的 /interface vlan 區塊，/ip address 的 VLAN 介面改引用這個新名稱
    const vlanIfs=parsed.interfaces.filter(i=>i.type==='vlan'&&i.vlanId&&i.vlanId!=='-'&&i.interface);
    if(vlanIfs.length){
      L.push('/interface vlan');
      vlanIfs.forEach(v=>L.push(`add name=vlan${v.vlanId} vlan-id=${v.vlanId} interface=${v.interface}`));
      L.push('');
    }
    if(parsed.interfaces.length) {
      L.push('/ip address');
      parsed.interfaces.forEach(i=>{
        const ifName=(i.type==='vlan'&&i.vlanId&&i.vlanId!=='-'&&i.interface)?`vlan${i.vlanId}`:i.name;
        if(i.ip&&i.ip!=='-'&&i.ip!=='DHCP') {
          const pfx=i.mask&&i.mask!=='-'?(i.mask.includes('.')?bits(i.mask):i.mask):'24';
          L.push(`add address=${i.ip}/${pfx} interface=${ifName}${i.desc&&i.desc!=='-'?' comment="'+i.desc+'"':''}`);
        }
        // 次要IP（2026-08-18 補上輸出端，官方文件確認同一介面重複 /ip address add 即為附加式
        // 次要IP，無 secondary 關鍵字，與 parser 端既有「第一筆進 ip/mask、後續進
        // secondaryIps」邏輯對稱）
        (i.secondaryIps||[]).forEach(s=>{
          const spfx=s.mask&&s.mask!=='-'?(s.mask.includes('.')?bits(s.mask):s.mask):'24';
          L.push(`add address=${s.ip}/${spfx} interface=${ifName}`);
        });
      });
      L.push('');
    }

    // 2026-08-09 修復：round-trip 測試（CV46b）發現既有 bug——上方 /ip address 對 VRRP
    // 虛擬介面（如 vrrp1）只輸出位址綁定，卻從未輸出 /interface vrrp add name=vrrp1 ...
    // 本體，貼到真實裝置會因該介面不存在而被拒絕；比照 MikrotikParser.parseMikrotikHa()
    // 已查證的真實語法（/interface vrrp 底下 add 一行含 name/interface/vrid/priority）補回
    const vrrpIf=parsed.interfaces.find(i=>i.type==='vrrp');
    if(vrrpIf&&parsed.ha&&parsed.ha.enabled&&parsed.ha.mode==='VRRP'){
      L.push('/interface vrrp');
      L.push(`add name=${vrrpIf.name} interface=${parsed.ha.syncInterface&&parsed.ha.syncInterface!=='-'?parsed.ha.syncInterface:'ether1'} vrid=${parsed.ha.groupId&&parsed.ha.groupId!=='-'?parsed.ha.groupId:'1'} priority=${parsed.ha.priority&&parsed.ha.priority!=='-'?parsed.ha.priority:'100'}`);
      L.push('');
    }

    const sroutes=parsed.routes.filter(r=>r.type==='static'||r.type==='default');
    if(sroutes.length) {
      L.push('/ip route');
      sroutes.forEach(r=>{ const {net,mask}=netMaskOf(r.dst,r.mask); L.push(`add dst-address=${net}/${bits(mask)} gateway=${r.gateway||'0.0.0.0'}${r.distance&&r.distance!=='-'?' distance='+r.distance:''}`); });
      L.push('');
    }

    const ivpns=parsed.vpn.filter(v=>v.type==='ipsec-p1');
    if(ivpns.length) {
      L.push('/ip ipsec proposal');
      ivpns.forEach(v=>{
        const [e,h]=splitProp(v.proposal);
        L.push(`add name=${v.name}-proposal enc-algorithms=${normEnc(e,'mikrotik')} auth-algorithms=${normHash(h,'mikrotik')} lifetime=${v.lifetime||'30m'}`);
      });
      L.push('');
      L.push('/ip ipsec peer');
      ivpns.forEach(v=>L.push(`add name=${v.name}-peer address=${v.remote||'0.0.0.0/32'} exchange-mode=${v.ikeVer==='2'?'ike2':'main'}`));
      L.push('');
      L.push('/ip ipsec identity');
      ivpns.forEach(v=>L.push(`add peer=${v.name}-peer auth-method=${v.authMethod==='psk'?'pre-shared-key':'rsa-signature'} secret=PLACEHOLDER`));
      L.push('');
    }

    if(parsed.nat.length) {
      L.push('/ip firewall nat');
      const nz=(v,fb)=>(v&&v!=='-')?v:fb;
      parsed.nat.forEach(n=>{
        if(n.type==='vip'||n.type==='static') L.push(`add chain=dstnat dst-address=${nz(n.extIp,'0.0.0.0')} action=dst-nat to-addresses=${nz(n.mapIp,'0.0.0.0')} comment="${n.name}"`);
        else L.push(`add chain=srcnat out-interface=${nz(n.srcIntf,nz(n.extIntf,'ether1'))} action=masquerade comment="${n.name}"`);
      });
      L.push('');
    }

    // WLAN（2026-08-20 新增，LOSS_FIELDS 同廠牌自轉補齊）：/interface wireless
    // security-profiles + /interface wireless，來源為 parseMikrotikWireless() 已解析出的
    // 真實資料。CAPsMAN（parsed.wlan.capsmanEnabled/capsmanConfigs）不在本輪範圍
    if(parsed.wlan){
      const secProfileList=parsed.wlan.secProfileList||[];
      if(secProfileList.length){
        L.push('/interface wireless security-profiles');
        secProfileList.forEach(s=>{
          let line=`add name=${s.name}`;
          if(s.authTypes&&s.authTypes!=='none')line+=` authentication-types=${s.authTypes}`;
          if(s.mode&&s.mode!=='none')line+=` mode=${s.mode}`;
          if(s.hasKey)line+=' wpa2-pre-shared-key=PLACEHOLDER';
          L.push(line);
        });
        L.push('');
      }
      const wlanIfs=parsed.wlan.interfaces||[];
      if(wlanIfs.length){
        L.push('/interface wireless');
        wlanIfs.forEach(w=>{
          let line=`add name=${w.name}`;
          if(w.ssid&&w.ssid!=='-')line+=` ssid=${w.ssid}`;
          if(w.band&&w.band!=='-')line+=` band=${w.band}`;
          if(w.mode&&w.mode!=='-')line+=` mode=${w.mode}`;
          if(w.frequency&&w.frequency!=='auto')line+=` frequency=${w.frequency}`;
          if(w.channelWidth&&w.channelWidth!=='-')line+=` channel-width=${w.channelWidth}`;
          if(w.country&&w.country!=='-')line+=` country=${w.country}`;
          if(w.secProfile&&w.secProfile!=='default')line+=` security-profile=${w.secProfile}`;
          if(w.disabled==='yes')line+=' disabled=yes';
          if(w.comment&&w.comment!=='-')line+=` comment="${w.comment}"`;
          L.push(line);
        });
        L.push('');
      }
    }

    // WWAN（2026-08-20 新增，LOSS_FIELDS 同廠牌自轉補齊）：/interface lte apn（APN 設定檔）
    // + /interface lte（介面本體，其 apn= 參數引用的是 APN 設定檔名稱，非介面自己的 APN
    // 字面值），來源為 parseMikrotikLte() 已解析出的真實資料
    if(parsed.wwan){
      const apnProfiles=parsed.wwan.apnProfiles||[];
      if(apnProfiles.length){
        L.push('/interface lte apn');
        apnProfiles.forEach(a=>{
          let line=`add name=${a.name} apn=${a.apn}`;
          if(a.authType&&a.authType!=='none')line+=` authentication=${a.authType}`;
          if(a.username&&a.username!=='-')line+=` user=${a.username}`;
          if(a.passwd==='set')line+=' password=PLACEHOLDER';
          if(a.ipType&&a.ipType!=='ipv4')line+=` ip-type=${a.ipType}`;
          if(a.distance&&a.distance!=='2')line+=` default-route-distance=${a.distance}`;
          L.push(line);
        });
        L.push('');
      }
      const lteInterfaces=parsed.wwan.lteInterfaces||[];
      if(lteInterfaces.length){
        L.push('/interface lte');
        lteInterfaces.forEach(l=>{
          let line=`add name=${l.name}`;
          if(l.apnProfile&&l.apnProfile!=='-')line+=` apn=${l.apnProfile}`;
          if(l.allowRoaming==='yes')line+=' allow-roaming=yes';
          if(l.disabled==='yes')line+=' disabled=yes';
          if(l.comment&&l.comment!=='-')line+=` comment="${l.comment}"`;
          L.push(line);
        });
        L.push('');
      }
    }

    // Log Servers（2026-08-20 新增，LOSS_FIELDS 同廠牌自轉補齊）：/system logging action，
    // 來源為 parseLogServers() 已解析出的真實資料，name 為 parser 反查用的識別鍵須無條件輸出
    if(parsed.logservers&&parsed.logservers.syslog&&parsed.logservers.syslog.length){
      L.push('/system logging action');
      parsed.logservers.syslog.forEach(s=>{
        let line=`add name=${s.name} target=remote remote=${s.server}`;
        if(s.port&&s.port!=='514')line+=` remote-port=${s.port}`;
        if(s.facility&&s.facility!=='local7')line+=` syslog-facility=${s.facility}`;
        if(s.format==='BSD')line+=' bsd-syslog=yes';
        if(s.level&&s.level!=='info')line+=` syslog-severity=${s.level}`;
        L.push(line);
      });
      L.push('');
    }

    // SNMP（2026-08-20 新增，LOSS_FIELDS 同廠牌自轉補齊）：/snmp（enable/agent）+
    // /snmp community，來源為 parseSnmp() 已解析出的真實資料。v3 使用者（parsed.snmp.v3users）
    // 不在本輪範圍——parser 端判定 v3 的依據是 security=private 或 authentication-password
    // 存在，與一般 community 共用同一個 /snmp community 區塊語法，本輪僅輸出一般 community
    if(parsed.snmp&&parsed.snmp.enabled){
      const agent=parsed.snmp.agent||{};
      // splitSections() 要求區段標頭（/snmp）獨立一行，隨後的 set/add 才會被收進該區段，
      // 不能寫成 "/snmp set enabled=yes ..." 單行（那樣整行會被誤判成一個不存在的區段名）
      let line='set enabled=yes';
      if(agent.contact&&agent.contact!=='-')line+=` contact="${agent.contact}"`;
      if(agent.location&&agent.location!=='-')line+=` location="${agent.location}"`;
      if(agent.name&&agent.name!=='-')line+=` name=${agent.name}`;
      if(agent.version){
        if(agent.version.includes('v1'))line+=' trap-version=1';
        else if(agent.version.includes('v3'))line+=' trap-version=3';
      }
      const trapIps=(parsed.snmp.trapServers||[]).map(t=>t.ip).filter(Boolean).join(',');
      if(trapIps)line+=` trap-target=${trapIps}`;
      L.push('/snmp');
      L.push(line);
      L.push('');
      const communities=(parsed.snmp.communities||[]);
      if(communities.length){
        L.push('/snmp community');
        communities.forEach(c=>{
          let cline=`add name=${c.name}`;
          if(c.permission==='rw')cline+=' security=write';
          if(c.allowedHosts&&c.allowedHosts.length)cline+=` addresses=${c.allowedHosts.join(',')}`;
          L.push(cline);
        });
        L.push('');
      }
    }

    if(parsed.policies.length) {
      L.push('/ip firewall filter');
      parsed.policies.forEach(p=>{
        const svc=(sl(p.service)[0]||'').toLowerCase();
        const proto=/udp/.test(svc)?'udp':/icmp/.test(svc)?'icmp':/tcp|^\d/.test(svc)?'tcp':'';
        let line=`add chain=forward action=${mapAction(p.action,'mikrotik')}`;
        const srcAddr=sl(p.srcAddr)[0], dstAddr=sl(p.dstAddr)[0];
        if(srcAddr&&!/^(any|all|-)$/i.test(srcAddr)) line+=` src-address=${srcAddr}`;
        if(dstAddr&&!/^(any|all|-)$/i.test(dstAddr)) line+=` dst-address=${dstAddr}`;
        if(proto) line+=` protocol=${proto}`;
        const portM=svc.match(/(\d+)$/);
        if(proto&&proto!=='icmp'&&portM) line+=` dst-port=${portM[1]}`;
        line+=` comment="${p.name}"`;
        if(p.status==='disable') line+=' disabled=yes';
        L.push(line);
      });
      L.push('');
    }

    return L.join('\n');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  DISPATCHER — 10 廠牌互轉
  // ══════════════════════════════════════════════════════════════════════════
  function convert(parsed, targetVendor) {
    switch(targetVendor) {
      case 'fortigate':  return toFortigate(parsed);
      case 'sophos':     return toSophos(parsed);
      case 'checkpoint': return toCheckpoint(parsed);
      case 'paloalto':   return toPaloAlto(parsed);
      case 'juniper':    return toJuniper(parsed);
      case 'pfsense':    return toPfsense(parsed);
      case 'ciscoasa':   return toCiscoASA(parsed);
      case 'ciscoftd':   return toCiscoFTD(parsed);
      case 'sonicwall':  return toSonicWall(parsed);
      case 'mikrotik':   return toMikrotik(parsed);
      case 'zyxel':      return toZyxel(parsed);
      case 'edgerouter': return toEdgeRouter(parsed);
      case 'openwrt':    return toOpenWrt(parsed);
      default: throw new Error(`未知目標廠牌: ${targetVendor}`);
    }
  }

  // ── 轉換遺失提示：10 個 to*() 皆只讀取 policies/routes/addresses/services/vpn/nat/
  // users/schedules，完全不碰以下 8 類欄位，來源設定檔若有值會被靜默丟棄，改為透明告知 ──
  const LOSS_FIELDS=[{key:'dhcp',label:'DHCP'},{key:'dns',label:'DNS'},{key:'snmp',label:'SNMP'},{key:'logservers',label:'Log Server'},{key:'sdwan',label:'SD-WAN'},{key:'ha',label:'HA/Cluster'},{key:'wwan',label:'WWAN'},{key:'wlan',label:'WLAN'}];
  function hasAnyData(v){
    if(!v)return false;
    if(Array.isArray(v))return v.length>0;
    if(typeof v==='object')return Object.values(v).some(x=>Array.isArray(x)?x.length>0:(x&&typeof x==='object'?hasAnyData(x):!!x));
    return !!v;
  }
  // 2026-08-20 新增 targetVendor 參數：MikroTik→MikroTik（wlan/wwan/logservers/snmp）、
  // FortiGate→FortiGate（wwan）、CiscoASA/FTD→CiscoASA/FTD（ha）、PaloAlto→PaloAlto（ha）、
  // Juniper→Juniper（ha）皆已補上真正輸出（見 toMikrotik()/toFortigate()/toCiscoASA()/
  // toPaloAlto()/toJuniper() 對應區塊），這些組合不再算「轉換會遺失」，其餘組合維持原判定不變
  function getConversionLoss(parsed,targetVendor){
    return LOSS_FIELDS.filter(f=>{
      if(!hasAnyData(parsed[f.key]))return false;
      if(parsed.vendor==='MikroTik'&&targetVendor==='mikrotik'&&['wlan','wwan','logservers','snmp'].includes(f.key))return false;
      if(parsed.vendor==='FortiGate'&&targetVendor==='fortigate'&&f.key==='wwan')return false;
      if((parsed.vendor==='Cisco ASA'||parsed.vendor==='Cisco FTD')&&(targetVendor==='ciscoasa'||targetVendor==='ciscoftd')&&f.key==='ha')return false;
      if(parsed.vendor==='PaloAlto'&&targetVendor==='paloalto'&&f.key==='ha')return false;
      if(parsed.vendor==='Juniper'&&targetVendor==='juniper'&&f.key==='ha')return false;
      return true;
    }).map(f=>f.label);
  }

  // 2026-07-24 新增：轉換警語——回答「不同 port 數量/型號能否轉換」的疑慮：能跑，但介面
  // 實體命名/埠位對應本質上無法從來源設定檔自動判斷目標設備的真實硬體規格，10 個 to*()
  // 全部直接沿用來源介面名稱，不做（也不應該做）猜測性的命名轉換。比起假裝能自動判斷正確，
  // 統一在此集中偵測並誠實告知使用者需要人工核對的項目，與 getConversionLoss()（資料真的
  // 被拿掉）區分開來——這裡回報的是「資料還在，但正確性需要人工複核」
  function getConversionCaveats(parsed, targetVendor){
    const notes=['介面實體名稱／埠位對應皆直接沿用來源設定，未轉換為目標設備慣用命名，請依目標設備實際型號與埠數量人工核對介面清單'];
    const ifs=parsed.interfaces||[];
    if(targetVendor==='ciscoasa'||targetVendor==='ciscoftd'){
      const intfOf=role=>{const z=mapZone(role,'ciscoasa');return z==='any'?'inside':z;};
      const counts={};
      ifs.forEach(i=>{const base=i.nameif||intfOf(i.role);counts[base]=(counts[base]||0)+1;});
      if(Object.values(counts).some(n=>n>1)) notes.push('偵測到多個相同角色介面，已自動編號區分 nameif 避免命名衝突，靜態路由的介面對應為概略猜測，請人工核對');
    }
    if(targetVendor==='mikrotik'){
      const noIp=ifs.filter(i=>!i.ip||i.ip==='-'||i.ip==='DHCP').length;
      if(noIp) notes.push(`${noIp} 個無 IP 位址的介面未輸出於 /ip address（RouterOS 此區塊僅列出已指派 IP 的介面）`);
    }
    if(ifs.some(i=>i.type==='vlan')) notes.push('VLAN 子介面語法為近似對應，實機匯入前請人工確認子介面設定是否完整');
    if(targetVendor==='sonicwall') notes.push('SonicWall 僅支援 SonicOS 6.2 之前版本的 XML 匯入格式（6.2+ 已停用 XML 匯出），本輸出僅適用於舊版韌體裝置');
    if(targetVendor==='zyxel') notes.push('Zyxel ZLD 語法純依官方 CLI Reference Guide 組出，無真實裝置匯出檔比對校正，信心度低於已用真實範例驗證過的廠牌；VPN／NAT／DHCP 等欄位本轉換器不支援輸出，請人工於裝置上另行設定');
    if(targetVendor==='edgerouter') notes.push('EdgeRouter 規則來源設定檔通常已按介面方向分別建立具名規則集，本轉換器無法得知原始規則應歸屬哪個介面，統一併入單一規則集 CONVERTED_IN 且未綁定任何介面，請人工在裝置上用 firewall in/out/local name 指令綁定至正確介面方向後才會生效');
    if(targetVendor==='openwrt') notes.push('OpenWrt (UCI) 語法純依官方文件組出，無真實裝置匯出檔比對校正；來源規則的介面欄位未必是 UCI 慣用的 zone 名稱，本轉換器已自動合成對應 config zone 區塊讓輸出自我一致，但實際 zone／network 對應請人工依裝置真實拓樸核對');
    if(targetVendor==='checkpoint') notes.push('查證官方 Gaia Admin Guide 確認規則庫（Access Policy）／NAT／VPN site-to-site community 並無對應的 clish "set" 指令，這幾類物件僅能透過 SmartConsole 或 Management API 管理，本轉換器不產生對應輸出，僅轉換 OS 層級設定（介面/路由/hostname 等）');
    return notes;
  }

  return { convert, getConversionLoss, getConversionCaveats, toFortigate, toSophos, toCheckpoint, toPaloAlto, toJuniper, toPfsense, toCiscoASA, toCiscoFTD, toSonicWall, toMikrotik, toZyxel, toEdgeRouter, toOpenWrt };
})();


