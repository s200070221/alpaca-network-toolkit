// ═══ parser-sophos.js ═══
/**
 * Sophos XG/XGS Configuration Parser (XML format)
 * Adds: admin users, access profiles, permissions
 */
const SophosParser = (() => {
  // 【與 PaloAltoParser／PfsenseParser 各自的 xv/xva/xblks 差異說明，2026-07-21 優化稽核時發現】
  // 三個 parser module 各自定義一份幾乎相同但不完全相同的 xv/xva/xblks，並非單純意外重複：
  // Sophos 這份多了 decodeXml() HTML 實體解碼（真實 Sophos XML 匯出值常含 &amp; 等實體，
  // 其他兩廠牌未觀察到此現象）＋巢狀同名標籤防護（取第一層文字，遇到子標籤同名時裁切）。
  // 在沒有真實 PaloAlto／Pfsense 樣本驗證各自是否也需要這些防護前，貿然合併成一份共用實作
  // 有變更既有正確行為的風險，故刻意保留三份獨立版本，不做去重合併。
  // HTML 實體解碼（&amp; &lt; &gt; &quot; &apos; &#nn;）
  function decodeXml(s){return(s||'').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&#(\d+);/g,(_,n)=>String.fromCharCode(+n));}
  function xv(xml,tag){
    const re=new RegExp('<'+tag+'(?:\\s[^>]*)?>([\\s\\S]*?)</'+tag+'>','i');
    const m=xml.match(re);
    if(!m) return '';
    const inner=m[1];
    // Fix: 防護巢狀同名標籤 - 若內有同名子標籤，取第一層文字
    const childRe=new RegExp('<'+tag+'[\\s>]','i');
    if(childRe.test(inner)){
      const stripped=inner.replace(new RegExp('<'+tag+'[\\s\\S]*?</'+tag+'>','gi'),'').trim();
      if(stripped) return decodeXml(stripped.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1').trim());
    }
    return decodeXml(inner.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1').trim());
  }
  function xva(xml,tag){const re=new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`,'gi');const r=[];let m;while((m=re.exec(xml))!==null)r.push(decodeXml(m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1').trim()));return r;}
  function xblks(xml,tag){const re=new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`,'gi');const r=[];let m;while((m=re.exec(xml))!==null)r.push({_outer:m[0],_inner:m[1]});return r;}
  function plist(xml,tag){return xva(xml,tag).filter(Boolean);}
  function dedup(arr,key){const s=new Set();return arr.filter(i=>{const k=i[key];if(!k||k==='-'||s.has(k))return false;s.add(k);return true;});}

  function guessRole(name){const n=(name||'').toLowerCase();if(/wan|internet|ext|outside|uplink/.test(n))return'WAN';if(/lan|inside|internal|trust/.test(n))return'LAN';if(/dmz|server|srv/.test(n))return'DMZ';if(/mgmt|manage|oob/.test(n))return'MGMT';if(/vpn|ipsec|ssl/.test(n))return'VPN';return'Unknown';}

  function parseDeviceInfo(xml){return{vendor:'Sophos',hostname:xv(xml,'DeviceName')||xv(xml,'HostName')||'-',firmware:xv(xml,'Version')||'-',model:xv(xml,'Model')||'-',serial:xv(xml,'SerialNumber')||'-',vdom:[]};}

  function parseInterfaces(xml){
    const ifaces=[];
    const tags=['Interface','PhysicalInterface','LAGInterface','VLANInterface','LoopbackInterface','TunnelInterface','NetworkInterface','InterfaceSettings'];
    tags.forEach(tag=>xblks(xml,tag).forEach(b=>{
      const inner=b._inner;
      const name=xv(inner,'Name')||xv(inner,'InterfaceName')||'-';
      ifaces.push({name,alias:xv(inner,'Alias')||xv(inner,'Description')||'-',ip:xv(inner,'IPAddress')||xv(inner,'Network')||'-',mask:xv(inner,'Netmask')||xv(inner,'SubnetMask')||'-',type:tag.replace('Interface','').toLowerCase()||'physical',vlanId:xv(inner,'VlanId')||xv(inner,'VLANID')||'-',vdom:xv(inner,'Zone')||'-',role:xv(inner,'Zone')||xv(inner,'NetworkZone')||guessRole(name),status:xv(inner,'Status')||'Active',speed:xv(inner,'Speed')||'-',mtu:xv(inner,'MTU')||'1500',macaddr:xv(inner,'MACAddress')||'-',mode:xv(inner,'Mode')||'static',gwdetect:'-',desc:xv(inner,'Description')||'-',allowaccess:'-',interface:xv(inner,'PhysicalInterface')||'-',gateway:xv(inner,'Gateway')||'-'});
    }));
    return dedup(ifaces,'name');
  }

  function parsePolicies(xml,addrTypeMap){
    const policies=[];const seen=new Set();
    // 只解析防火牆規則標籤，排除 Web Filter/App Control 的 <Rule>（避免分類被誤認為規則）
    ['FirewallRule','SecurityPolicy'].forEach(tag=>xblks(xml,tag).forEach((b,idx)=>{
      const inner=b._inner;const name=xv(inner,'Name')||`Rule-${idx+1}`;if(seen.has(name))return;seen.add(name);
      const action=(xv(inner,'Action')||xv(inner,'PolicyAction')||'Accept').toLowerCase();
      const srcNets=plist(inner,'SourceNetworks').concat(plist(inner,'Source')).concat(plist(inner,'SourceNetwork'));
      const dstNets=plist(inner,'DestinationNetworks').concat(plist(inner,'Destination')).concat(plist(inner,'DestinationNetwork'));
      const svcs=plist(inner,'Services').concat(plist(inner,'Service')).concat(plist(inner,'ServiceList'));
      const srcAddrStr=srcNets.join(', ')||'Any';
      const dstAddrStr=dstNets.join(', ')||'Any';
      const srcAddrSplit=_splitAddr(srcAddrStr,addrTypeMap);
      const dstAddrSplit=_splitAddr(dstAddrStr,addrTypeMap);
      policies.push({id:xv(inner,'Id')||String(idx+1),name,srcIntf:xv(inner,'SourceZone')||xv(inner,'FromZone')||'-',dstIntf:xv(inner,'DestinationZone')||xv(inner,'ToZone')||'-',srcAddr:srcAddrStr,dstAddr:dstAddrStr,srcAddr4:srcAddrSplit.v4,srcAddr6:srcAddrSplit.v6,dstAddr4:dstAddrSplit.v4,dstAddr6:dstAddrSplit.v6,service:svcs.join(', ')||'Any',schedule:xv(inner,'Schedule')||'All the time',action:action.includes('accept')||action.includes('allow')||action.includes('permit')?'accept':'deny',nat:xv(inner,'OutboundNAT')||(xv(inner,'NATRule')?'enable':'disable'),ippool:'disable',poolname:xv(inner,'NATRule')||'-',logtraffic:xv(inner,'LogTraffic')||xv(inner,'Log')||'disable',logstart:'-',utm:{av:xv(inner,'AntiVirus')||xv(inner,'AVProfile')||'-',webfilter:xv(inner,'WebFilter')||xv(inner,'WebPolicy')||'-',ips:xv(inner,'IPS')||xv(inner,'IPSPolicy')||'-',ssl:xv(inner,'SSLInspection')||'-',appctrl:xv(inner,'ApplicationControl')||xv(inner,'AppPolicy')||'-'},status:xv(inner,'Status')||xv(inner,'Active')||'Enable',comments:xv(inner,'Description')||xv(inner,'Comments')||'-',users:plist(inner,'Users').join(', ')||'-',groups:plist(inner,'Groups').join(', ')||'-'});
    }));
    return policies;
  }

  function parseAddressObjects(xml){
    const objs=[];
    // ── IPHost 物件（Sophos v18+ 主要格式，依 HostType 分類）──────────────
    xblks(xml,'IPHost').forEach(b=>{
      const inner=b._inner; const name=xv(inner,'Name')||'-'; if(name==='-')return;
      const hostType=(xv(inner,'HostType')||'IP').toLowerCase();
      if(hostType==='iprange'){
        // IP 範圍：StartIPAddress / EndIPAddress
        objs.push({category:'address',name,type:'iprange',subnet:'-',fqdn:'-',
          startIp:xv(inner,'StartIPAddress')||xv(inner,'StartIP')||'-',
          endIp:xv(inner,'EndIPAddress')||xv(inner,'EndIP')||'-',
          wildcard:'-',iface:'-',color:'0',comment:xv(inner,'Description')||'-',members:'-'});
      } else {
        // IP / Network / System / MAC → 取 IPAddress + Subnet
        const ip=xv(inner,'IPAddress')||'-';
        const mask=xv(inner,'Subnet')||xv(inner,'SubnetMask')||'';
        objs.push({category:'address',name,type:'ipmask',
          subnet:ip!=='-'&&mask?ip+' '+mask:ip,fqdn:'-',startIp:ip,endIp:'-',
          wildcard:'-',iface:xv(inner,'Interface')||'-',color:'0',
          comment:xv(inner,'Description')||'-',members:'-'});
      }
    });
    // ── 舊式 Host 物件（需含 <IPAddress> 子標籤，排除 HostGroup 內的純引用）──
    xblks(xml,'Host').forEach(b=>{
      const inner=b._inner; const name=xv(inner,'Name')||'-';
      if(name==='-'||!/<IPAddress[\s>]/i.test(inner))return;
      const ip=xv(inner,'IPAddress')||'-';
      const mask=xv(inner,'Subnet')||xv(inner,'SubnetMask')||'255.255.255.255';
      objs.push({category:'address',name,type:'ipmask',
        subnet:ip+' '+mask,fqdn:'-',startIp:ip,endIp:'-',
        wildcard:'-',iface:xv(inner,'Interface')||'-',color:'0',
        comment:xv(inner,'Description')||'-',members:'-'});
    });
    // ── 獨立 Network 物件（需含 <Name> 且有 IP 欄位，避免抓到路由/介面的 <Network>）──
    xblks(xml,'Network').forEach(b=>{
      const inner=b._inner; const name=xv(inner,'Name')||'-';
      const ip=xv(inner,'IPAddress')||xv(inner,'Network')||'-';
      if(name==='-'||ip==='-'||!/<Name[\s>]/i.test(inner))return;
      objs.push({category:'address',name,type:'ipmask',
        subnet:ip+'/'+(xv(inner,'Subnet')||xv(inner,'Prefix')||'24'),
        fqdn:'-',startIp:xv(inner,'StartIPAddress')||'-',endIp:xv(inner,'EndIPAddress')||'-',
        wildcard:'-',iface:'-',color:'0',comment:xv(inner,'Description')||'-',members:'-'});
    });
    xblks(xml,'IPRange').forEach(b=>{
      const inner=b._inner; const name=xv(inner,'Name')||'-'; if(name==='-')return;
      objs.push({category:'address',name,type:'iprange',subnet:'-',fqdn:'-',
        startIp:xv(inner,'StartIPAddress')||xv(inner,'StartIP')||'-',
        endIp:xv(inner,'EndIPAddress')||xv(inner,'EndIP')||'-',
        wildcard:'-',iface:'-',color:'0',comment:xv(inner,'Description')||'-',members:'-'});
    });
    xblks(xml,'FQDN').forEach(b=>{
      const inner=b._inner; const name=xv(inner,'Name')||'-'; if(name==='-')return;
      objs.push({category:'address',name,type:'fqdn',subnet:'-',
        fqdn:xv(inner,'FQDN')||xv(inner,'DomainName')||'-',
        startIp:'-',endIp:'-',wildcard:'-',iface:'-',color:'0',comment:'-',members:'-'});
    });
    xblks(xml,'IPList').concat(xblks(xml,'HostGroup')).concat(xblks(xml,'IPHostGroup')).forEach(b=>{
      const inner=b._inner; const name=xv(inner,'Name')||'-'; if(name==='-')return;
      const mems=plist(inner,'Host').concat(plist(inner,'Network')).concat(plist(inner,'IPRange'));
      objs.push({category:'address-group',name,type:'group',
        members:mems.join(', ')||'-',comment:xv(inner,'Description')||'-',
        color:'0',subnet:'-',fqdn:'-',startIp:'-',endIp:'-',wildcard:'-',iface:'-'});
    });
    return dedup(objs,'name');
  }

  function parseServiceObjects(xml){
    const svcs=[];
    xblks(xml,'Service').forEach(b=>{const inner=b._inner;const name=xv(inner,'Name');if(!name)return;const proto=(xv(inner,'Type')||xv(inner,'Protocol')||'TCP').toUpperCase();const dst=xv(inner,'DestinationPort')||xv(inner,'DstPort')||xv(inner,'Port')||'-';svcs.push({category:'custom',name,proto,tcpPorts:proto.includes('TCP')?dst:'-',udpPorts:proto.includes('UDP')?dst:'-',srcPort:xv(inner,'SourcePort')||'-',icmpType:xv(inner,'ICMPType')||'-',icmpCode:xv(inner,'ICMPCode')||'-',comment:xv(inner,'Description')||'-',color:'0',category_name:xv(inner,'ServiceGroup')||'-',members:'-'});});
    xblks(xml,'ServiceGroup').forEach(b=>{const inner=b._inner;const mems=plist(inner,'ServiceList').concat(plist(inner,'Service'));svcs.push({category:'group',name:xv(inner,'Name')||'-',proto:'GROUP',tcpPorts:'-',udpPorts:'-',icmpType:'-',icmpCode:'-',members:mems.join(', ')||'-',comment:xv(inner,'Description')||'-'});});
    return svcs;
  }

  function parseRoutes(xml){
    const routes=[];
    xblks(xml,'Unicast').concat(xblks(xml,'StaticRoute')).concat(xblks(xml,'Route')).forEach((b,i)=>{const inner=b._inner;routes.push({type:'static',id:String(i+1),dst:(xv(inner,'DestinationIP')||'0.0.0.0')+'/'+(xv(inner,'Mask')||xv(inner,'Netmask')||'0'),gateway:xv(inner,'Gateway')||xv(inner,'GatewayIP')||'-',device:xv(inner,'Interface')||xv(inner,'OutInterface')||'-',distance:xv(inner,'Distance')||xv(inner,'Metric')||'1',priority:xv(inner,'Priority')||'0',weight:'0',comment:xv(inner,'Description')||'-',status:xv(inner,'Status')||'Enable',blackhole:'disable',vrf:'0'});});
    xblks(xml,'OSPF').forEach(b=>{routes.push({type:'ospf',id:'ospf',dst:'dynamic',gateway:'-',device:'-',routerId:xv(b._inner,'RouterID')||'-',distance:xv(b._inner,'AdminDistance')||'110',priority:'-',weight:'-',comment:'OSPF',status:'Enable',blackhole:'disable',vrf:'0',protocol_detail:`Router-ID: ${xv(b._inner,'RouterID')||'-'}`});});
    xblks(xml,'BGP').forEach(b=>{routes.push({type:'bgp',id:'bgp',dst:'dynamic',gateway:'-',device:'-',as:xv(b._inner,'LocalAS')||'-',routerId:xv(b._inner,'RouterID')||'-',distance:'20',priority:'-',weight:'-',comment:'BGP',status:'Enable',blackhole:'disable',vrf:'0',protocol_detail:`AS: ${xv(b._inner,'LocalAS')||'-'}`});});
    return routes;
  }

  function parseVPN(xml){
    const vpns=[];
    xblks(xml,'IPSec').concat(xblks(xml,'VPNPolicy')).concat(xblks(xml,'IPsecPolicy')).forEach((b,i)=>{
      const inner=b._inner;const name=xv(inner,'Name')||xv(inner,'PolicyName')||`IPSec-${i+1}`;
      const ph2=[];xblks(inner,'Phase2').forEach(p2=>{ph2.push({name:xv(p2._inner,'Name')||`P2-${i}`,phase1:name,proposal:(xv(p2._inner,'Encryption')||'-')+'-'+(xv(p2._inner,'Authentication')||'-'),pfs:xv(p2._inner,'PFS')||'enable',dhgrp:xv(p2._inner,'DHGroup')||'-',lifetime:xv(p2._inner,'KeyLife')||'28800',replay:'enable',localSub:xv(p2._inner,'LocalSubnet')||xv(p2._inner,'LocalNetwork')||'-',remoteSub:xv(p2._inner,'RemoteSubnet')||xv(p2._inner,'RemoteNetwork')||'-',autoNeg:'-',comment:'-'});});
      vpns.push({type:'ipsec-p1',name,mode:xv(inner,'ConnectionType')||xv(inner,'Mode')||'tunnel',remote:xv(inner,'RemoteGateway')||xv(inner,'RemoteIP')||'-',iface:xv(inner,'Interface')||xv(inner,'LocalInterface')||'-',ikeVer:xv(inner,'IKEVersion')||'1',authMethod:xv(inner,'AuthenticationMode')||xv(inner,'AuthBy')||'PSK',peertype:'-',proposal:(xv(inner,'Encryption')||'-')+'-'+(xv(inner,'Authentication')||'-'),dhgrp:xv(inner,'DHGroup')||'-',lifetime:xv(inner,'KeyLife')||'86400',natTraversal:xv(inner,'NATTraversal')||'enable',dpd:xv(inner,'DPD')||'-',dpdInterval:xv(inner,'DPDTimeout')||'-',localId:xv(inner,'LocalID')||'-',peerId:xv(inner,'RemoteID')||'-',cert:xv(inner,'DigitalCertificate')||'-',status:xv(inner,'Status')||'Active',phase2:ph2});
    });
    xblks(xml,'SSLVPNPolicy').concat(xblks(xml,'SSLVPN')).forEach((b,i)=>{const inner=b._inner;vpns.push({type:'ssl-vpn',name:xv(inner,'Name')||`SSL-VPN-${i+1}`,iface:xv(inner,'Interface')||'-',remote:'-',port:xv(inner,'Port')||'443',tunPort:'-',addr:xv(inner,'IPRange')||xv(inner,'TunnelIPRange')||'-',dns1:xv(inner,'PrimaryDNS')||'-',dns2:xv(inner,'SecondaryDNS')||'-',wins1:'-',ipPool:xv(inner,'TunnelPool')||'-',algorithm:xv(inner,'Encryption')||'-',dtls:'-',authTimeout:xv(inner,'AuthTimeout')||'-',ikeVer:'-',authMethod:'ssl',proposal:xv(inner,'Encryption')||'-',dhgrp:'-',phase2:[],status:xv(inner,'Status')||'Active'});});
    return vpns;
  }

  function parseUsers(xml){
    const users=[];
    // local users
    xblks(xml,'User').forEach(b=>{const inner=b._inner;const name=xv(inner,'Name')||xv(inner,'Username')||'-';const prof=xv(inner,'Profile')||xv(inner,'AccessProfile')||'User';users.push({type:'local',name,status:xv(inner,'Status')||'Active',authType:xv(inner,'Type')||'password',email:xv(inner,'Email')||xv(inner,'EmailAddress')||'-',twoFactor:xv(inner,'TwoFactorAuth')||'disable',twoFType:'-',ldapServer:xv(inner,'LDAPServer')||'-',radiusServer:xv(inner,'RADIUSServer')||'-',comment:xv(inner,'Description')||'-',members:'-',permissions:mapSophosProfilePermissions(prof),roles:[prof],accessLevel:mapSophosAccessLevel(prof)});});
    // admin users
    xblks(xml,'Administrator').concat(xblks(xml,'AdminUser')).forEach(b=>{const inner=b._inner;const name=xv(inner,'Name')||xv(inner,'Username')||'-';if(users.find(u=>u.name===name&&u.type==='local'))return;const prof=xv(inner,'Profile')||xv(inner,'Role')||'Administrator';users.push({type:'admin',name,status:xv(inner,'Status')||'Active',authType:xv(inner,'AuthType')||'password',email:xv(inner,'Email')||'-',twoFactor:xv(inner,'TwoFactor')||'disable',twoFType:'-',ldapServer:'-',radiusServer:'-',comment:xv(inner,'Description')||'-',members:'-',permissions:mapSophosProfilePermissions(prof),roles:[prof],accessLevel:mapSophosAccessLevel(prof)});});
    // groups
    xblks(xml,'Group').concat(xblks(xml,'UserGroup')).forEach(b=>{const inner=b._inner;const mems=plist(inner,'Member').concat(plist(inner,'User'));const prof=xv(inner,'AccessProfile')||'-';users.push({type:'group',name:xv(inner,'Name')||'-',groupType:xv(inner,'Type')||'normal',members:mems.join(', ')||'-',match:'-',authTimeout:xv(inner,'AuthTimeout')||'-',comment:xv(inner,'Description')||'-',status:'Active',permissions:mapSophosProfilePermissions(prof),roles:[prof],accessLevel:'group'});});
    // LDAP
    xblks(xml,'LDAPServer').concat(xblks(xml,'AuthenticationServer')).forEach(b=>{const inner=b._inner;if((xv(inner,'Type')||'').toLowerCase()==='radius')return;users.push({type:'ldap-server',name:xv(inner,'Name')||'-',server:xv(inner,'Server')||xv(inner,'ServerIP')||'-',port:xv(inner,'Port')||'389',dn:xv(inner,'BaseDN')||xv(inner,'SearchBase')||'-',bindType:xv(inner,'BindDN')?'regular':'anonymous',bindDn:xv(inner,'BindDN')||'-',cnid:xv(inner,'UserNameAttribute')||'cn',groupFilter:xv(inner,'GroupSearchFilter')||'-',ssl:xv(inner,'UseSSL')||xv(inner,'Encryption')||'disable',comment:'-',status:'Active',members:'-',permissions:[],roles:[],accessLevel:'auth-server'});});
    // RADIUS
    xblks(xml,'RADIUSServer').forEach(b=>{const inner=b._inner;users.push({type:'radius-server',name:xv(inner,'Name')||'-',server:xv(inner,'Server')||xv(inner,'ServerIP')||'-',port:xv(inner,'Port')||'1812',authType:xv(inner,'AuthMethod')||'auto',nasIp:xv(inner,'NASIP')||'-',comment:'-',status:'Active',members:'-',permissions:[],roles:[],accessLevel:'auth-server'});});
    return dedup(users,'name');
  }

  function mapSophosProfilePermissions(prof){
    const p=(prof||'').toLowerCase();
    if(p==='administrator'||p==='superadmin'||p==='full access')return[{resource:'All',access:'read-write'}];
    if(p.includes('read only')||p.includes('readonly'))return[{resource:'All',access:'read'}];
    if(p.includes('network'))return[{resource:'Network',access:'read-write'},{resource:'Firewall',access:'read-write'}];
    if(p.includes('vpn'))return[{resource:'VPN',access:'read-write'}];
    if(p.includes('log')||p.includes('report'))return[{resource:'Logging',access:'read-write'},{resource:'Reports',access:'read-write'}];
    if(p==='user'||p==='')return[{resource:'User Portal',access:'read-write'}];
    return[{resource:prof||'User',access:'read-write'}];
  }

  function mapSophosAccessLevel(prof){
    const p=(prof||'').toLowerCase();
    if(p==='administrator'||p==='superadmin'||p.includes('full'))return'super-admin';
    if(p.includes('read'))return'read-only';
    if(p.includes('vpn'))return'vpn-only';
    if(p.includes('log')||p.includes('report'))return'log-viewer';
    if(p==='user'||p==='')return'user';
    return'admin';
  }

  function parseSchedules(xml){const s=[];xblks(xml,'Schedule').forEach(b=>{const inner=b._inner;s.push({type:xv(inner,'Type')||'recurring',name:xv(inner,'Name')||'-',start:xv(inner,'StartTime')||xv(inner,'Start')||'-',end:xv(inner,'EndTime')||xv(inner,'End')||'-',day:xv(inner,'Days')||xv(inner,'Day')||'-',color:'0'});});return s;}

  function parseNAT(xml){
    const nats=[];
    [...xblks(xml,'DNAT'),...xblks(xml,'DNATRule'),...xblks(xml,'NATRule')].forEach((b,i)=>{const inner=b._inner;nats.push({type:'vip',name:xv(inner,'Name')||`DNAT-${i+1}`,vipType:'static-nat',extIp:xv(inner,'ExternalIP')||xv(inner,'OriginalDestination')||'-',extIntf:xv(inner,'InboundInterface')||'-',mapIp:xv(inner,'TranslatedDestination')||xv(inner,'MappedIP')||'-',portFwd:xv(inner,'PortForwarding')||'disable',extPort:xv(inner,'ExternalPort')||xv(inner,'OriginalPort')||'-',mapPort:xv(inner,'TranslatedPort')||xv(inner,'MappedPort')||'-',proto:xv(inner,'Protocol')||'-',comment:xv(inner,'Description')||'-',status:xv(inner,'Status')||'Enable'});});
    [...xblks(xml,'SNAT'),...xblks(xml,'SNATRule'),...xblks(xml,'MasqueradeRule')].forEach((b,i)=>{const inner=b._inner;nats.push({type:'ippool',name:xv(inner,'Name')||`SNAT-${i+1}`,poolType:'overload',startIp:xv(inner,'TranslatedSource')||xv(inner,'MappedIP')||'-',endIp:'-',srcIntf:xv(inner,'OutboundInterface')||'-',arpReply:'enable',comment:xv(inner,'Description')||'-'});});
    return nats;
  }

  // Fix: 移除 XML 註解，避免被解析為有效規則
  function stripXmlComments(xml){return xml.replace(/<!--[\s\S]*?-->/g,'');}
  function parse(text){
    const xml=stripXmlComments(text);
    // 位址物件需先解析出來，才能建 addrTypeMap 供 policies 的 SourceNetworks/DestinationNetworks
    // 名稱反查 v4/v6 型別（見 _splitAddr() 定義處註解）
    const addresses=parseAddressObjects(xml);
    return{vendor:'Sophos',deviceInfo:parseDeviceInfo(xml),interfaces:parseInterfaces(xml),policies:parsePolicies(xml,buildAddrTypeMap(addresses)),routes:parseRoutes(xml),vpn:parseVPN(xml),addresses,services:parseServiceObjects(xml),schedules:parseSchedules(xml),nat:parseNAT(xml),users:parseUsers(xml),sdwan:parseSdwan(xml),dhcp:parseDhcp(xml),dns:parseDns(xml),snmp:parseSnmp(xml),logservers:parseLogServers(xml)};
  }

  // ── Sophos SD-WAN / Link Balancing ────────────────────────────────────────

  // ── DHCP Server & Relay ──────────────────────────────────────────────────
  function parseDhcp(xml) {
    const servers=[], relays=[];
    xblks(xml,'DHCPServer').forEach(blk => {
      const t=blk._inner;
      // IP 範圍：支援平坦 StartIP/EndIP 及巢狀 IPRange/From/To
      const startIp=xv(t,'StartIP')||xv(t,'StartAddress')||xv(t,'FromIP')||xv(t,'From')||'-';
      const endIp  =xv(t,'EndIP')||xv(t,'EndAddress')||xv(t,'ToIP')||xv(t,'To')||'-';
      // 閘道
      const gateway=xv(t,'Gateway')||xv(t,'DefaultGateway')||'-';
      // 子網路遮罩（xv 使用 case-insensitive，Netmask/NetMask 均可）
      const mask=xv(t,'Netmask')||xv(t,'SubnetMask')||xv(t,'Mask')||'-';
      // DNS：平坦 DNS1/PrimaryDNS 或巢狀 DNSServer 列表
      const dnsArr=xva(t,'DNSServer');
      const dns1=xv(t,'DNS1')||xv(t,'PrimaryDNS')||dnsArr[0]||'-';
      const dns2=xv(t,'DNS2')||xv(t,'SecondaryDNS')||dnsArr[1]||'-';
      // 租約時間：LeaseTime 或 Lease
      const lease=xv(t,'LeaseTime')||xv(t,'Lease')||'86400';
      // 啟用狀態：Enable (0/1) 或 Status (Enable/Disable)
      const enableVal=xv(t,'Enable'), statusVal=xv(t,'Status');
      let status='enable';
      if(enableVal!=='') status=enableVal==='0'?'disable':'enable';
      else if(statusVal!=='') status=statusVal.toLowerCase()==='disable'?'disable':'enable';
      servers.push({ name:xv(t,'Name')||'-', iface:xv(t,'Interface')||'-',
        startIp, endIp, gateway, mask, dns1, dns2,
        domain:xv(t,'Domain')||xv(t,'DomainName')||'-', lease, status,
        comment:xv(t,'Description')||'' });
    });
    xblks(xml,'DHCPRelay').forEach(blk => {
      const t=blk._inner;
      relays.push({ name:xv(t,'Name')||'-', iface:xv(t,'Interface')||'-',
        serverIp:xv(t,'ServerIP')||xv(t,'Server')||xv(t,'RelayServer')||'-',
        status:'enable', comment:'' });
    });
    return { servers, relays };
  }
  // ── DNS ─────────────────────────────────────────────────────────────────
  function parseDns(xml) {
    const result={servers:[],secondaries:[],domain:'-',proxy:false,proxyRules:[],dnsOverTls:false,cacheSize:'-',static:[]};
    [...xblks(xml,'DNS'),...xblks(xml,'DNSSettings')].forEach(blk=>{
      const t=blk._inner;
      const pri=xv(t,'PrimaryDNS')||xv(t,'DNS1'); if(pri&&pri!=='-') result.servers.push(pri);
      const sec=xv(t,'SecondaryDNS')||xv(t,'DNS2'); if(sec&&sec!=='-') result.secondaries.push(sec);
      if(xv(t,'Domain')) result.domain=xv(t,'Domain');
    });
    [...xblks(xml,'DNSProxyRule'),...xblks(xml,'ConditionalForwarder')].forEach(blk=>{
      const t=blk._inner;
      result.proxyRules.push({domain:xv(t,'Domain')||xv(t,'ForwardingDomain')||'-',target:xv(t,'TargetDNS')||xv(t,'ForwardingServer')||'-'});
      result.proxy=true;
    });
    return result;
  }


  // ── SNMP ────────────────────────────────────────────────────────────────────
  function parseSnmp(xml) {
    const result = { enabled:false, agent:{name:'-',description:'-',location:'-',contact:'-',version:[]}, communities:[], v3users:[], trapServers:[] };
    const agents = [...xblks(xml,'SNMPAgent'),...xblks(xml,'SNMP')];
    if (!agents.length) return result;
    result.enabled = true;
    const blk = agents[0]._inner;
    result.agent.name        = xv(blk,'Name')||xv(blk,'SystemName')||'-';
    result.agent.description = xv(blk,'Description')||'-';
    result.agent.contact     = xv(blk,'Contact')||'-';
    result.agent.location    = xv(blk,'Location')||'-';
    const ver = (xv(blk,'Version')||'v2c').toLowerCase();
    if (!result.agent.version.includes(ver)) result.agent.version.push(ver);
    // Community
    const comm = xv(blk,'Community')||xv(blk,'ROCommunity')||'-';
    const hosts = [...xblks(blk,'Host')].map(h=>h._inner.trim()).filter(Boolean);
    if (comm!=='-') result.communities.push({ name:comm, permission:'ro', allowedHosts:hosts, events:'-', status:'enable' });
    // Trap servers
    xblks(blk,'TrapServer').forEach(ts => { const ti=ts._inner; result.trapServers.push({ ip:xv(ti,'IP')||xv(ti,'Address')||'-', port:xv(ti,'Port')||'162', community:xv(ti,'Community')||comm, version:'v2c' }); });
    const trapSrv = xv(blk,'TrapServer')||xv(blk,'TrapTarget');
    if (trapSrv&&trapSrv!=='-'&&!result.trapServers.length) result.trapServers.push({ ip:trapSrv, port:'162', community:comm, version:'v2c' });
    // v3 users
    xblks(xml,'SNMPv3').forEach(blk3 => {
      xblks(blk3._inner,'User').forEach(u => { const ui=u._inner; result.v3users.push({ name:xv(ui,'Name')||'-', authProto:xv(ui,'AuthProtocol')||'sha', privProto:xv(ui,'PrivProtocol')||'aes', secLevel:'auth-priv', notifyHost:'-', status:'enable' }); if(!result.agent.version.includes('v3')) result.agent.version.push('v3'); });
    });
    return result;
  }

  // ── Log Servers ──────────────────────────────────────────────────────────────
  function parseLogServers(xml) {
    const result = { syslog:[], fortianalyzer:[], netflow:[], logForward:[] };
    xblks(xml,'Syslog').forEach(blk => {
      const b=blk._inner;
      const enabled=(xv(b,'Status')||xv(b,'Enabled')||'').toLowerCase();
      if (enabled==='disable'||enabled==='no') return;
      result.syslog.push({ name:xv(b,'Name')||'Syslog', server:xv(b,'Server')||xv(b,'IPAddress')||'-', port:xv(b,'Port')||'514', facility:xv(b,'Facility')||'local7', format:xv(b,'LogFormat')||'standard', protocol:'UDP', level:xv(b,'LogLevel')||'information', status:'enable' });
    });
    xblks(xml,'CentralReporting').forEach(blk => {
      const b=blk._inner;
      if ((xv(b,'Status')||'').toLowerCase()==='enable') result.fortianalyzer.push({ name:'CentralReporting', server:xv(b,'Server')||'-', port:xv(b,'Port')||'8888', reliable:'enable', encAlgo:'-', status:'enable' });
    });
    return result;
  }

  function parseSdwan(xml) {
    const result = { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] };

    // WANLink = member (WAN interface + gateway + health check)
    const wanLinks = xblks(xml, 'WANLink');
    if (!wanLinks.length) return result;
    result.enabled = true;

    wanLinks.forEach((lk, idx) => {
      const t = lk._inner;
      // Health check nested in WANLink
      const hcBlk = xblks(t, 'HealthCheck');
      let hc = null;
      if (hcBlk.length) {
        const ht = hcBlk[0]._inner;
        hc = {
          name:         xv(t,'Name') + '_HC',
          server:       xv(ht,'Host')     || xv(ht,'Server') || '-',
          protocol:     (xv(ht,'Type')    || 'Ping').toLowerCase(),
          port:         xv(ht,'Port')     || '-',
          interval:     xv(ht,'Interval') || '30',
          timeout:      xv(ht,'Timeout')  || '5',
          failtime:     xv(ht,'FailCount')|| '3',
          recoverytime: xv(ht,'RecoverCount') || '3',
          probePackets: '3',
          http200Only:  'disable',
          members:      String(idx + 1),
          slaThresholds: [],
        };
        result.healthChecks.push(hc);
      }
      result.members.push({
        id:       String(idx + 1),
        iface:    xv(t, 'Interface') || xv(t, 'Name') || '-',
        zone:     xv(t, 'Zone') || 'WAN',
        gateway:  xv(t, 'Gateway') || '-',
        gateway6: '-',
        priority: parseInt(xv(t,'Priority')||'1') || 1,
        weight:   parseInt(xv(t,'Weight')||'1') || 1,
        cost:     0, spillover: 0, volumeRatio: 1,
        status:   xv(t,'Status')||xv(t,'Active')||'enable',
        comment:  xv(t,'Description') || '',
      });
    });

    // SDWANProfile = load-balance group
    xblks(xml, 'SDWANProfile').forEach((pb, idx) => {
      const t = pb._inner;
      const policy = (xv(t,'Policy') || xv(t,'LoadBalancePolicy') || 'LoadBalance').toLowerCase();
      const lbMode = policy.includes('failover') ? 'priority'
                   : policy.includes('round')    ? 'source-ip-based'
                   : policy.includes('weight')   ? 'weight-based'
                   : 'load-balance';
      if (idx === 0) { result.lbMode = lbMode; result.enabled = true; }
      const memberNames = xva(t, 'Member');
      result.services.push({
        id:              String(idx + 1),
        name:            xv(t,'Name') || `Profile-${idx+1}`,
        mode:            lbMode,
        src: 'all', dst: 'all',
        srcNegate: 'disable', dstNegate: 'disable',
        users: '-', protocol: '0', startPort: '-', endPort: '-',
        priorityMembers: '-',
        priorityZone:    memberNames.join(', ') || '-',
        preferredUplink: '-', slaCompare: 'order', tie: 'zone',
        slaRefs: [], inputDevice: '-',
        status: 'enable',
        comment: xv(t,'Description') || '',
      });
    });

    // SDWANPolicy rules (Traffic Selectors)
    xblks(xml, 'SDWANPolicy').forEach((pb, idx) => {
      const t = pb._inner;
      result.services.push({
        id:              String(result.services.length + 1),
        name:            xv(t,'Name') || `Policy-${idx+1}`,
        mode:            'sla',
        src:             xv(t,'Source') || xv(t,'SourceNetwork') || 'all',
        dst:             xv(t,'Destination') || xv(t,'DestinationNetwork') || 'all',
        srcNegate: 'disable', dstNegate: 'disable', users: '-',
        protocol:        xv(t,'Protocol') || '0',
        startPort:       xv(t,'DestPort') || '-', endPort: '-',
        priorityMembers: '-',
        priorityZone:    xv(t,'Profile') || xv(t,'WANProfile') || '-',
        preferredUplink: '-', slaCompare: 'order', tie: 'zone',
        slaRefs: [], inputDevice: '-',
        status: xv(t,'Status') === 'Disable' ? 'disable' : 'enable',
        comment: xv(t,'Description') || '',
      });
    });

    return result;
  }

  return{parse};
})();


