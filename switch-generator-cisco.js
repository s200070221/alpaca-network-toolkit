function renderCiscoVLAN(v){
  const lines=[`vlan ${v.id}`];
  if(v.name)lines.push(` name ${v.name}`);
  return lines.join('\n');
}
function renderCiscoVLANs(vlans){return vlans.map(renderCiscoVLAN).join('\n!\n');}

// switchport trunk/access（VLAN 屬性）render，Cisco IOS-XE 專用；抽成獨立函式供
// renderCiscoInterface() 與 renderCiscoLACPExtra() 共用。屬性不一致時 Cisco 不會擋設定匯入，
// 但該實體埠會被判定為 suspended（"vlan mask is different"）而被排除在聚合之外，等同該埠沒
// 加入 EtherChannel；為確保「能夠成功聚合」，member port 一律不輸出這組屬性，改由
// renderCiscoLACPExtra() 統一輸出在 Port-channel 介面上（member 個別填的設定被忽略，見
// lacpMemberAttrWarnings() 的非阻擋性提示）
function ciscoSwitchportLines(iface){
  const lines=[];
  if(!iface)return lines;
  if(iface.mode==='trunk'){
    lines.push(' switchport mode trunk');
    if(iface.trunkVlans)lines.push(` switchport trunk allowed vlan ${iface.trunkVlans}`);
    if(iface.nativeVlan)lines.push(` switchport trunk native vlan ${iface.nativeVlan}`);
  }else if(iface.mode==='access'){
    lines.push(' switchport mode access');
    if(iface.accessVlan)lines.push(` switchport access vlan ${iface.accessVlan}`);
  }
  return lines;
}
// OSPFv3（2026-08-23 新增，Cisco/Arista/Ruijie 共用）：官方 Cisco IPv6 Routing Protocols
// Configuration Guide 確認真正的介面成員關係在介面視圖 "ipv6 ospf PID area AREA"，process
// 層級的 "ipv6 router ospf PID" 區塊本身不巢狀 network 陳述式
function ciscoOspf6IfaceLines(ospf6List,ifaceName){
  const lines=[];
  (ospf6List||[]).forEach(o=>{
    (o.areas||[]).forEach(a=>{
      if((a.interfaces||[]).includes(ifaceName))lines.push(` ipv6 ospf ${o.pid} area ${a.area}`);
    });
  });
  return lines;
}
function renderCiscoInterface(iface,lacpList,dhcpList,aclList,securityList,stp,ospf6List,qosApplyList){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(` description ${iface.desc}`);
  // L3 欄位（ip/vrf，2026-07-27 補上）：parseCiscoInterfaces() 對 SVI／Loopback／routed
  // 實體埠皆有解析 ip/vrf，但 render 端從未輸出過。SVI 的 ip 欄位在解析時已轉成 CIDR
  // 格式，Loopback／routed 實體埠則保留原始「IP MASK」字串；vrf forwarding 須在
  // ip address 之前宣告（真實語法要求，變更 VRF 會清空既有 IP）。Management 介面的
  // vrf 欄位是解析器固定塞入的 'MGMT' 標記（非真實解析到的關鍵字），不在此處理範圍。
  // IPv6（試點 5 廠牌之一，標準 Cisco IOS 語法 `ipv6 address ADDR/PREFIXLEN`，不需遮罩換算）
  // 次要IP（Secondary IP，官方 IP Addressing Services Command Reference：`ip
  // address A B secondary`，IPv4 專屬機制；2026-08-23 陣列化：parser 端 2026-08-17 已
  // 從「僅取第一筆」擴充為完整陣列 secondaryIps，render 端同步逐筆輸出）
  const secLines=(iface.secondaryIps||[]).filter(s=>!s.includes(':')).map(s=>{
    const [sip,slen]=s.split('/');
    return sip&&slen?` ip address ${sip} ${maskFromCidr(slen)} secondary`:'';
  }).filter(Boolean);
  if(iface.type==='svi'){
    if(iface.vrf)lines.push(` ip vrf forwarding ${iface.vrf}`);
    if(iface.ip){
      if(iface.ip.includes(':')){
        lines.push(` ipv6 address ${iface.ip}`);
      }else{
        const [ip,len]=iface.ip.split('/');
        lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
        secLines.forEach(l=>lines.push(l));
      }
    }
  }else if(iface.type==='loopback'){
    if(iface.ip){
      lines.push(` ${iface.ip.includes(':')?'ipv6':'ip'} address ${iface.ip}`);
      if(!iface.ip.includes(':'))secLines.forEach(l=>lines.push(l));
    }
  }else if(iface.type==='physical'&&iface.mode==='routed'){
    lines.push(' no switchport');
    if(iface.vrf)lines.push(` ip vrf forwarding ${iface.vrf}`);
    if(iface.ip){
      lines.push(` ${iface.ip.includes(':')?'ipv6':'ip'} address ${iface.ip}`);
      if(!iface.ip.includes(':'))secLines.forEach(l=>lines.push(l));
    }
  }
  // OSPFv3（2026-08-23 新增）：真正的介面成員關係看介面視圖的 "ipv6 ospf PID area AREA"
  // 指令（比照 v4 network 陳述式在 process 層級的位置差異），須在此反查 model.ospf6
  ciscoOspf6IfaceLines(ospf6List,iface.name).forEach(l=>lines.push(l));
  const lg=findLacpGroup(lacpList,iface.name);
  if(!lg)lines.push(...ciscoSwitchportLines(iface));
  if(lg){
    const modeWord=lg.mode==='active'?'active':lg.mode==='passive'?'passive':'on';
    lines.push(` channel-group ${lg.id} mode ${modeWord}`);
  }
  if(iface.jumbo&&iface.jumbo.enabled&&iface.jumbo.mtu)lines.push(` mtu ${iface.jumbo.mtu}`);
  if(iface.shutdown)lines.push(' shutdown');
  findDhcpRelays(dhcpList,iface.name).forEach(rel=>lines.push(` ip helper-address ${rel.relayServer}`));
  findAclApplications(aclList,iface.name).forEach(ap=>lines.push(` ip access-group ${ap.name} ${ap.direction}`));
  // service-policy 介面套用（2026-08-28（續4）新增，見 findQosApplications() 註解）
  findQosApplications(qosApplyList,iface.name).forEach(ap=>lines.push(` service-policy ${ap.direction} ${ap.policy}`));
  const sec=findSecurityForPort(securityList,iface.name);
  if(sec){
    if(sec.dot1x==='auth')lines.push(' dot1x pae authenticator');
    else if(sec.dot1x==='supp')lines.push(' dot1x pae supplicant');
    if(sec.portSec){
      lines.push(' switchport port-security');
      if(sec.maxMac)lines.push(` switchport port-security maximum ${sec.maxMac}`);
      if(sec.violation)lines.push(` switchport port-security violation ${sec.violation}`);
    }
    if(sec.guestVlan)lines.push(` dot1x guest-vlan ${sec.guestVlan}`);
  }
  const sp=findStpForPort(stp,iface.name);
  if(sp){
    if(sp.portfast)lines.push(' spanning-tree portfast');
    if(sp.bpduguard)lines.push(' spanning-tree bpduguard enable');
    if(sp.guardRoot)lines.push(' spanning-tree guard root');
    if(sp.cost)lines.push(` spanning-tree cost ${sp.cost}`);
    if(sp.priority)lines.push(` spanning-tree port-priority ${sp.priority}`);
  }
  // PoE 配置（Cisco）
  if(iface.poeMode&&iface.poeMode!=='none'){
    const poeMap={'auto':'auto','never':'never','static-max':'static','static-high':'static'};
    const poeCmd=poeMap[iface.poeMode];
    if(poeCmd)lines.push(` power inline ${poeCmd}`);
  }
  return lines.join('\n');
}
function renderCiscoInterfaces(ifaces,lacpList,dhcpList,aclList,securityList,stp,ospf6List,qosApplyList){return ifaces.map(i=>renderCiscoInterface(i,lacpList,dhcpList,aclList,securityList,stp,ospf6List,qosApplyList)).join('\n!\n');}

function renderCiscoLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    blocks.push([`interface Port-channel${l.id}`,...ciscoSwitchportLines(refIface)].join('\n'));
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return;
      const modeWord=l.mode==='active'?'active':l.mode==='passive'?'passive':'on';
      blocks.push(`interface ${mem}\n channel-group ${l.id} mode ${modeWord}`);
    });
  });
  return blocks.join('\n!\n');
}

function renderCiscoVRRPGroup(g){
  const lines=[`interface Vlan${g.vlanId}`];
  if(g.ip){
    const [ip,len]=g.ip.split('/');
    lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
  }
  g.entries.forEach(v=>{
    // version（2026-07-27 補上）：parseVRRP(cfg,'cisco') 已解析 "standby N version N"，
    // 預設值是解析器內部使用的 'HSRP' 佔位字串（代表設定檔原本沒有這行），非真實版本號，
    // 只有解析到實際數字才輸出
    if(v.version&&/^\d+$/.test(v.version))lines.push(` standby ${v.vrid} version ${v.version}`);
    if(v.vip)lines.push(` standby ${v.vrid} ip ${v.vip}`);
    // IPv6（2026-08-23 新增）：官方語法 "standby N ipv6 ADDR"／"standby N ipv6 autoconfig"，
    // 前提須先宣告 "standby version 2"（HSRP for IPv6 僅 v2 支援），本工具沿用既有慣例
    // 只輸出欄位值，不驗證裝置端前提條件是否成立
    if(v.vip6)lines.push(` standby ${v.vrid} ipv6 ${v.vip6}`);
    lines.push(` standby ${v.vrid} priority ${v.priority}`);
    if(v.preempt)lines.push(` standby ${v.vrid} preempt`);
    // trackIf（2026-07-27 補上）：parseVRRP(cfg,'cisco') 已解析 "standby N track IFACE"，
    // render 端從未輸出過
    if(v.trackIf)lines.push(` standby ${v.vrid} track ${v.trackIf}`);
  });
  return lines.join('\n');
}
function renderCiscoVRRP(list){return groupVrrpByVlan(list).map(renderCiscoVRRPGroup).join('\n!\n');}

function renderCiscoOSPFProcess(o){
  const lines=[`router ospf ${o.pid}`];
  if(o.routerId)lines.push(` router-id ${o.routerId}`);
  (o.areas||[]).forEach(a=>{
    (a.networks||[]).forEach(n=>lines.push(` network ${n.network} ${n.wildcard} area ${a.area}`));
  });
  return lines.join('\n');
}
function renderCiscoOSPF(list){return (list||[]).map(renderCiscoOSPFProcess).join('\n!\n');}

// OSPFv3（2026-08-23 新增，Cisco/Arista/Ruijie 共用）：process 層級只宣告 "ipv6 router
// ospf PID"／router-id，真正的介面成員關係由 ciscoOspf6IfaceLines() 在逐介面 render 時輸出
function renderCiscoOSPFv3Process(o){
  const lines=[`ipv6 router ospf ${o.pid}`];
  if(o.routerId)lines.push(` router-id ${o.routerId}`);
  return lines.join('\n');
}
function renderCiscoOSPFv3(list){return (list||[]).map(renderCiscoOSPFv3Process).join('\n!\n');}

function renderCiscoBGP(b){
  const lines=[`router bgp ${b.asn}`];
  if(b.routerId)lines.push(` bgp router-id ${b.routerId}`);
  (b.peers||[]).forEach(p=>{
    lines.push(` neighbor ${p.ip} remote-as ${p.as}`);
    if(p.desc)lines.push(` neighbor ${p.ip} description ${p.desc}`);
  });
  // Cisco 的 network 陳述式只接受純 IP + 可選 dotted mask，不接受 CIDR 斜線寫法
  (b.networks||[]).forEach(n=>{
    const [ip,len]=n.split('/');
    lines.push(len?` network ${ip} mask ${maskFromCidr(len)}`:` network ${ip}`);
  });
  // IPv6（2026-08-23 新增，Cisco/Arista/Ruijie 共用）：官方 Cisco BGP Configuration Guide
  // 確認 network 巢狀在獨立的 address-family ipv6 [unicast] 子模式內，slash-CIDR 直接輸出
  // （不需 mask 換算），子模式以官方 exit-address-family 關鍵字結尾
  if(b.networks6&&b.networks6.length){
    lines.push(' address-family ipv6');
    b.networks6.forEach(n=>lines.push(`  network ${n}`));
    lines.push(' exit-address-family');
  }
  return lines.join('\n');
}
function renderCiscoBGPList(list){return (list||[]).map(renderCiscoBGP).join('\n!\n');}

function renderCiscoRIP(r){
  const lines=['router rip'];
  if(r.version)lines.push(` version ${r.version}`);
  (r.networks||[]).forEach(n=>lines.push(` network ${n}`));
  (r.redistribute||[]).forEach(x=>lines.push(` redistribute ${x}`));
  // passive／peers／timers／autoSummary／defaultMetric（2026-07-27 補上）：parseRIPBlock()
  // 共用邏輯已解析這些欄位，Cisco render 端從未輸出過。peer 關鍵字 Cisco 真實用詞是
  // neighbor（parseRIPBlock 的 peer/neighbor 共用正則相容兩者）
  (r.passive||[]).forEach(i=>lines.push(` passive-interface ${i}`));
  (r.peers||[]).forEach(p=>lines.push(` neighbor ${p}`));
  if(r.timers)lines.push(` timers basic ${r.timers}`);
  if(r.autoSummary)lines.push(` auto-summary`);
  if(r.defaultMetric)lines.push(` default-metric ${r.defaultMetric}`);
  return lines.join('\n');
}
function renderCiscoRIPList(list){return (list||[]).map(renderCiscoRIP).join('\n!\n');}

function renderCiscoRoute(r){
  // 2026-07-22 對外查證官方 Cisco IOS-XE 文件後修正：ip route 的遮罩欄位必須是點分
  // 遮罩（255.255.255.0），不接受 CIDR 前綴長度整數，原本直接輸出前綴長度數字在
  // 真實裝置上會被拒絕
  const [net,len]=r.dst.split('/');
  // vrf（2026-07-27 補上）：parseCiscoRoutes() 支援 "ip route vrf NAME ..." 語法，
  // render 端從未輸出過
  // IPv6（2026-08-23 新增，Cisco/Arista/Ruijie 共用）：官方語法 "ipv6 route [vrf VRF]
  // PREFIX/LEN NEXTHOP"，prefix/length 已是單一 slash-CIDR token，不需 mask 換算
  if(r.dst.includes(':'))return `ipv6 route${r.vrf?' vrf '+r.vrf:''} ${r.dst} ${r.gw}`;
  return `ip route${r.vrf?' vrf '+r.vrf:''} ${net} ${maskFromCidr(len)} ${r.gw}`;
}
function renderCiscoRoutes(list){return (list||[]).map(renderCiscoRoute).join('\n!\n');}

// DHCP server pool；relay（ip helper-address）內嵌進 renderCiscoInterface，不在此輸出
function renderCiscoDHCPPool(d){
  const lines=[`ip dhcp pool ${d.name}`];
  if(d.network)lines.push(` network ${d.network}`);
  if(d.gateway)lines.push(` default-router ${d.gateway}`);
  if(d.dns)lines.push(` dns-server ${d.dns}`);
  if(d.lease)lines.push(` lease ${d.lease}`);
  if(d.excluded)lines.push(` excluded-address ${d.excluded}`);
  // bootFile／nextServer／ntpServer（2026-07-27 補上）：parseDHCP() cisco 分支已解析
  // bootfile(Option67)／next-server（備援 option 150 ip）／option 42 ip(NTP)，render 端
  // 從未輸出過
  if(d.bootFile)lines.push(` bootfile ${d.bootFile}`);
  if(d.nextServer)lines.push(` next-server ${d.nextServer}`);
  if(d.ntpServer)lines.push(` option 42 ip ${d.ntpServer}`);
  return lines.join('\n');
}
function renderCiscoDHCP(list){return (list||[]).filter(d=>d.type==='server').map(renderCiscoDHCPPool).join('\n!\n');}

// ACL：ip access-list extended/standard NAME 區塊；套用（ip access-group）內嵌進
// renderCiscoInterface。_parseACLCisco 的區塊擷取正則只認得下一個 "ip access-list "
// 或字串結尾當終止字元（不認得 "!"／"interface " 等其他分隔符），若後面還接其他區塊，
// 會被整段吃進 ACL 的 body 裡，故比照 assembleXXXConfig 既有的 BGP「放最後」慣例，
// ACL 一定要放在組裝順序的最後一項
function renderCiscoACLEntry(a){
  const lines=[`ip access-list ${a.type||'extended'} ${a.name}`];
  (a.rules||[]).forEach(r=>{
    let line=` ${r.action||'permit'}`;
    if(a.type==='standard')line+=` ${r.src||'any'}`;
    else line+=` ${r.protocol||'ip'} ${r.src||'any'} ${r.dst||'any'}${r.dstPort?' eq '+r.dstPort:''}`;
    lines.push(line);
    if(r.remark)lines.push(` remark ${r.remark}`);
  });
  return lines.join('\n');
}
function renderCiscoACL(list){return (list||[]).map(renderCiscoACLEntry).join('\n!\n');}

// Breakout：IOS-XE 兩種已查證模式——pattern A（9300X+NM-4C 模組換位編號）
// `hw-module breakout module <slot> port <port> switch <num>`；pattern B（9500-32C 後綴編號）
// `hw-module breakout <port>`，直接沿用母埠名稱
function renderCiscoBreakoutBlock(breakouts){
  const ciBreakouts=(breakouts||[]).filter(b=>b.vendor==='cisco');
  if(!ciBreakouts.length)return '';
  const lines=[];
  ciBreakouts.forEach(b=>{
    if(b.scheme==='renumber'){
      // 2026-07-22 修正資料模型不一致 bug：解析器產生的 breakout 物件沒有頂層 slot
      // 欄位（只內嵌在 parentPort 字串裡，格式 "module<slot>/port<portNum>"），原本
      // 直接讀 b.slot 永遠是 undefined，造成「匯入既有設定檔 → 重新產生」時這類
      // breakout 設定會靜默消失
      const pm=b.parentPort.match(/^module(\d+)\/port(\d+)$/);
      if(!pm||!b.switchNum)return;
      const [,slot,portNum]=pm;
      lines.push(`hw-module breakout module ${slot} port ${portNum} switch ${b.switchNum}`);
    }else{
      lines.push(`hw-module breakout ${b.parentPort}`);
    }
  });
  return lines.join('\n');
}

function assembleCiscoConfig(model){
  const blocks=[`! ${tr('notice.disclaimer')}`,`hostname ${model.sysname||'Switch'}`];
  // DHCP Relay option82（2026-07-27 補上）：parseDHCP() cisco 分支解析的是全域指令
  // "ip dhcp snooping information option"（非逐 interface），套用到全部 relay 條目，
  // 先前 render 端全檔案完全沒有任何輸出路徑
  if((model.dhcp||[]).some(d=>d.type==='relay'&&d.option82))blocks.push('ip dhcp snooping information option');
  const ciscoBreakoutBlock=renderCiscoBreakoutBlock(model.breakouts);
  if(ciscoBreakoutBlock)blocks.push(ciscoBreakoutBlock);
  if(model.vlans&&model.vlans.length)blocks.push(renderCiscoVLANs(model.vlans));
  // VRF：官方文件確認舊式 `ip vrf forwarding NAME`（本工具介面上已使用的語法）要求該 VRF
  // 已用 `ip vrf NAME` 建立，排在 Interfaces 之前輸出
  const ciscoVrfNames=collectVrfNames(model.interfaces);
  if(ciscoVrfNames.length)blocks.push(ciscoVrfNames.map(n=>`ip vrf ${n}`).join('\n!\n'));
  if(model.interfaces&&model.interfaces.length)blocks.push(renderCiscoInterfaces(model.interfaces,model.lacp,model.dhcp,model.acl,model.security,model.stp,model.ospf6,model.qosApply));
  const ciscoLacpExtra=renderCiscoLACPExtra(model.lacp,model.interfaces);
  if(ciscoLacpExtra)blocks.push(ciscoLacpExtra);
  if(model.vrrp&&model.vrrp.length)blocks.push(renderCiscoVRRP(model.vrrp));
  if(model.dhcp&&model.dhcp.some(d=>d.type==='server'))blocks.push(renderCiscoDHCP(model.dhcp));
  const stpBlockCi=renderSpanningTreeGlobal(model.stp);
  if(stpBlockCi)blocks.push(stpBlockCi);
  if(model.ospf&&model.ospf.length)blocks.push(renderCiscoOSPF(model.ospf));
  if(model.ospf6&&model.ospf6.length)blocks.push(renderCiscoOSPFv3(model.ospf6));
  if(model.rip&&model.rip.length)blocks.push(renderCiscoRIPList(model.rip));
  if(model.routes&&model.routes.length)blocks.push(renderCiscoRoutes(model.routes));
  if(model.bgp&&model.bgp.length)blocks.push(renderCiscoBGPList(model.bgp));
  if(model.acl&&model.acl.length)blocks.push(renderCiscoACL(model.acl));
  // class-map 必須先於引用它的 policy-map 定義，且其收尾正則同時認 policy-map 邊界，順序
  // 不能顛倒（2026-08-28（續4）新增）
  if(model.classMaps&&model.classMaps.length)blocks.push(renderClassMapQoS(model.classMaps));
  // QoS 放最後（同一個原因：policy-map 區塊擷取正則只認得下一個 "policy-map " 或字串
  // 結尾，沒有其他終止字元，比照 ACL/BGP 慣例排在組裝順序最後）
  if(model.qos&&model.qos.length)blocks.push(renderPolicyMapQoS(model.qos));
  const ciscoUsersBlock=renderCiscoUsers(model.users);
  if(ciscoUsersBlock)blocks.push(ciscoUsersBlock);
  if(model.snmpTrapHost)blocks.push(`snmp-server host ${model.snmpTrapHost}`);
  if(model.syslogServer)blocks.push(`logging host ${model.syslogServer}`);
  // 結尾補換行，理由同 assembleArubaConfig
  return blocks.join('\n!\n')+'\n';
}

// 本機帳號：switch_analyzer 的 parseCiscoUsers()（Cisco IOS/IOS-XE 共用，Arista/Ruijie 重用
// 同一套 parser 與此 render 函式）僅支援 "username NAME privilege N secret|password N HASH"
// 語法，role 欄位格式固定為 "privilege-N"；密碼固定輸出等級 0（plaintext marker，parser
// 本身不驗證雜湊格式是否吻合宣告等級），使用者需自行貼上已產生的雜湊/密碼字串
function renderCiscoUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>{
    const m=/^privilege-(\d+)$/.exec(u.role||'');
    const priv=m?m[1]:'15';
    return `username ${u.name} privilege ${priv} secret 0 ${u.password}`;
  }).join('\n');
}

// ══════════════════════════════════════════════════════════════════
// Dell OS10 render 函式（switch_analyzer parser 範圍：VLAN/Interface(access/trunk)/
// OSPF/BGP/靜態路由/LACP/VRRP/DHCP server/ACL/QoS/Port Security-802.1X/STP；無 RIP，故不產生。
// ACL/QoS/Security/STP 直接沿用 Cisco 語法與 renderCiscoACL/renderPolicyMapQoS/
// renderSpanningTreeGlobal/findAclApplications/findSecurityForPort/findStpForPort 既有函式，
// 因為 switch_analyzer 的 parseACL/parseQoS/parseSecurity/parseSTP 對沒有明確列出分支的廠牌
// （含 dell-os10）本來就會 fallback 到這套 Cisco-style 通用邏輯，round-trip 可直接驗證，不需要
// 新寫 switch_analyzer 的 dell-os10 專屬分支。RIP 則是 parseDellOS10() 寫死回傳 rip:[]，
// switch_analyzer 完全沒有對應解析路徑，維持排除）
// ══════════════════════════════════════════════════════════════════

// Dell OS10 沒有獨立的 vlan 資料庫語法，VLAN 名稱只能透過 interface vlanN 的
// description 設定；VRRP 又需要在同一個 interface vlanN 底下加 ip address +
// vrrp-group，故同一 VLAN ID 若同時有名稱與 VRRP 資料，必須合併進同一個區塊
// 輸出（比照 Juniper 頂層區塊必須合併的既有原則），不能像 Cisco 一樣分開兩個
// 獨立 interface Vlan10 區塊（重新解析時會產生兩筆同名 interface，無法正確對應）
// 2026-07-27 補上 interfaces 參數：parseDellOS10Interfaces() 的 SVI 分支本來就有解析
// iface.ip/iface.vrf（`interface vlanN` 底下的 `ip address`/`ip vrf forwarding`），但原本
// 這裡只從 vrrpList 的 g.ip 重建位址，沒有 VRRP 的純 SVI（只設 ip、不掛 VRRP）的位址會消失，
// vrf 更是完全沒有對應輸出路徑。改為優先讀 interfaces 裡對應 SVI 自己的 ip/vrf，VRRP 分組
// 的 g.ip 僅作為退回來源（理論上兩者同值，SVI 找不到時才會用到）
