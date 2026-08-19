function renderNXOSVLAN(v){
  const lines=[`vlan ${v.id}`];
  if(v.name)lines.push(` name ${v.name}`);
  return lines.join('\n');
}
function renderNXOSVLANs(vlans){return vlans.map(renderNXOSVLAN).join('\n!\n');}

// switchport trunk/access（VLAN 屬性）render，NX-OS 專用；抽成獨立函式供
// renderNXOSInterface() 與 renderNXOSLACPExtra() 共用。屬性不一致時 NX-OS（Cisco EtherChannel
// 語系）不會擋設定匯入，但該實體埠會被判定 suspended 排除在聚合之外；為確保「能夠成功聚合」，
// member port 一律不輸出這組屬性，改由 renderNXOSLACPExtra() 統一輸出在 port-channel 介面上
function nxosSwitchportLines(iface){
  const lines=[];
  if(!iface)return lines;
  if(iface.mode==='trunk'){
    lines.push(' switchport mode trunk');
    if(iface.trunkVlans)lines.push(` switchport trunk allowed vlan ${iface.trunkVlans}`);
  }else if(iface.mode==='access'){
    lines.push(' switchport mode access');
    if(iface.accessVlan)lines.push(` switchport access vlan ${iface.accessVlan}`);
  }
  return lines;
}
function renderNXOSInterface(iface,lacpList,dhcpList,aclList,securityList,stp,vpc){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(` description ${iface.desc}`);
  const lacpGroup=lacpList?.find(l=>l.members?.some(m=>m===iface.name));
  if(!lacpGroup)lines.push(...nxosSwitchportLines(iface));
  // ip/vrf（2026-07-27 補上，parseInterfaces() 早就有解析：`mIp`/`mVrf`，但這裡從未輸出過）：
  // parser 找不到 ip 時預設回填字面 '-'（非空字串，見 parseInterfaces() 的 `ip=mIp?...:'-'`），
  // 故判斷須排除 '-'；Loopback 未被 parseInterfaces() 特別分類，type 落在 'physical'，須靠
  // 名稱另外判斷是否要輸出 `no switchport`（Loopback 原生即 L3，沒有這個指令）
  const isLoopback=/^loopback/i.test(iface.name);
  if(iface.ip&&iface.ip!=='-'){
    if(iface.type!=='svi'&&!isLoopback)lines.push(' no switchport');
    lines.push(` ip address ${iface.ip}`);
    // 次要IP（2026-08-12 新增）：官方 `ip address A/N secondary`，僅取第一筆為 MVP 範圍
    if(iface.secondaryIp)lines.push(` ip address ${iface.secondaryIp} secondary`);
  }
  if(iface.vrf)lines.push(` vrf member ${iface.vrf}`);
  if(iface.mtu)lines.push(` mtu ${iface.mtu}`);
  if(iface.jumbo)lines.push(` mtu 9216`);
  if(iface.shutdown)lines.push(' shutdown');
  // DHCP Relay（2026-07-24 新增解析，一直未接線）：真實語法是逐介面 `ip dhcp relay address IP`
  // （非 Cisco IOS 式 ip helper-address），信任旗標簡化為逐介面輸出 `ip dhcp relay information
  // trusted`（parser 端 option82 是「全域 trust 旗標 OR 逐介面 trusted」任一成立即真，逐介面
  // 輸出必定能被兩種判斷式其中之一偵測到，不需要額外處理全域旗標）
  findDhcpRelays(dhcpList,iface.name).forEach(rel=>{
    lines.push(` ip dhcp relay address ${rel.relayServer}`);
    if(rel.option82)lines.push(' ip dhcp relay information trusted');
  });
  if(lacpGroup){
    // 2026-07-22 修正：未比照 Cisco/Arista/Aruba CX 共用的 mode 轉換邏輯，UI 預設值
    // 'static' 會直接原樣輸出，但 channel-group mode 合法值僅 on/active/passive，
    // 'static' 不是合法關鍵字
    const modeWord=lacpGroup.mode==='active'?'active':lacpGroup.mode==='passive'?'passive':'on';
    lines.push(` channel-group ${lacpGroup.id} mode ${modeWord}`);
  }
  // VPC peer-link：真實語法內嵌在該 port-channel 自己的 interface 區塊（"vpc peer-link"），
  // 對應 switch_analyzer parseNxosVpc() 掃描 interface 區塊找此標記的既有邏輯
  if(vpc&&vpc.peerLink&&iface.name.toLowerCase()===vpc.peerLink.toLowerCase()){
    lines.push(' vpc peer-link');
  }
  // ACL 套用／Port Security-802.1X／STP 逐 port：NX-OS 與 Cisco IOS 共用同一套 Cisco-style
  // 通用解析分支（parseACL/parseSecurity/parseSTP 對 nxos 走的正是這條），語法與
  // renderDellOS10Interface 完全相同，直接沿用同一套內嵌邏輯與輸出行
  findAclApplications(aclList,iface.name).forEach(ap=>lines.push(` ip access-group ${ap.name} ${ap.direction}`));
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
  return lines.join('\n');
}
function renderNXOSInterfaces(ifaces,lacpList,dhcpList,aclList,securityList,stp,vpc){return ifaces.map(i=>renderNXOSInterface(i,lacpList,dhcpList,aclList,securityList,stp,vpc)).join('\n!\n');}

function renderNXOSLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const portChanName=`port-channel${l.id}`;
    if(!existingNames.has(portChanName)){
      const lines=[`interface ${portChanName}`];
      if(l.desc)lines.push(` description ${l.desc}`);
      const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
      lines.push(...nxosSwitchportLines(refIface));
      blocks.push(lines.join('\n'));
    }
  });
  return blocks.length?blocks.join('\n!\n'):'';
}

function renderNXOSRoute(r){
  // 2026-07-22 修正欄位名稱不符 bug：原本讀 r.destination/r.prefixLength/r.gateway，
  // 但共用路由模型（collectModel()/addRouteRow() 產生）是 {dst,gw}，三個欄位全部讀不到值，
  // 每條 NX-OS 靜態路由都會輸出成 "ip route undefined/undefined undefined"
  return `ip route ${r.dst} ${r.gw}`;
}
function renderNXOSRoutes(routes){return (routes||[]).map(renderNXOSRoute).join('\n');}

function renderNXOSBGPPeer(p){
  const lines=[` neighbor ${p.ip}`];
  if(p.as)lines.push(`  remote-as ${p.as}`);
  if(p.desc)lines.push(`  description ${p.desc}`);
  return lines.join('\n');
}
// Networks（2026-07-17 對外查證官方 NX-OS Unicast Routing Configuration Guide 確認）：
// `network A.B.C.D/N [route-map NAME]` 須巢狀在 `address-family ipv4 unicast` 子區塊內，
// 與 neighbor（全域層級）不同層，故獨立成自己的子區塊而非塞進既有 neighbor 迴圈
function renderNXOSBGPList(bgps){
  if(!bgps||!bgps.length)return '';
  const blocks=bgps.map(b=>{
    const lines=[`router bgp ${b.asn}`];
    if(b.routerId)lines.push(` router-id ${b.routerId}`);
    if(b.networks&&b.networks.length){
      lines.push(' address-family ipv4 unicast');
      b.networks.forEach(n=>lines.push(`  network ${n}`));
    }
    if(b.peers&&b.peers.length){
      b.peers.forEach(p=>{
        lines.push(renderNXOSBGPPeer(p));
      });
    }
    return lines.join('\n');
  });
  return blocks.join('\n!\n');
}

// 2026-07-22 對外查證官方 NX-OS Unicast Routing Configuration Guide 後修正：
// 原本輸出的 `network X area Y`（router ospf 底下的網段陳述式）確認錯誤——現代 NX-OS
// 完全沒有這個語法，area 指派只能透過逐介面 `ip router ospf <tag> area <area-id>`
// 指定（NX-OS 8.4+/9.3+ 起舊版 network 指令已被移除，改用會直接報錯）；同時原本無條件
// 輸出 `area X authentication simple` 也是錯的——這行語法本身真實存在，但強制對每個
// area 開啟認證卻沒有對應金鑰設定，會直接讓真實裝置的 OSPF 鄰居關係失敗。兩者皆先移除，
// 逐介面 area 指派需要 IP/CIDR 比對邏輯（比照 Comware/Aruba 既有慣例），屬於新功能而非
// 語法修正，留待未來規劃
function renderNXOSOSPF(ospfs){
  if(!ospfs||!ospfs.length)return '';
  const blocks=ospfs.map(o=>{
    const lines=[`router ospf ${o.processId||1}`];
    if(o.routerId)lines.push(` router-id ${o.routerId}`);
    return lines.join('\n');
  });
  return blocks.join('\n!\n');
}

// Breakout：獨立頂層指令 `interface breakout module M port P map ratio`，
// 執行後該模組會 reload 並清除既有設定，assembleNXOSConfig 會在有使用此功能時額外輸出警告註解
function renderNXOSBreakoutBlock(breakouts){
  const nxBreakouts=(breakouts||[]).filter(b=>b.vendor==='cisco_nxos');
  if(!nxBreakouts.length)return '';
  const modeMap={'4x10G':'10g-4x','4x25G':'25g-4x'};
  const lines=nxBreakouts.map(b=>{
    const map=modeMap[b.mode];
    const m=b.parentPort.match(/^Ethernet(\d+)\/(\d+)$/i);
    if(!map||!m)return ''; // 2x50G 未查證官方語法，或母埠名稱格式不符，不輸出
    return `interface breakout module ${m[1]} port ${m[2]} map ${map}`;
  }).filter(Boolean);
  return lines.join('\n');
}

// NX-OS HSRP（充當 VRRP）：巢狀在 interface Vlan<N> 區塊內的 "hsrp <group>" 子區塊，
// 子指令縮排務必比 "hsrp N" 這行本身更深一層——對應 switch_analyzer parseVRRP() 的
// nxos 分支用縮排深度判斷子區塊邊界（非其他廠牌那種同層級的 "standby N ip X"）；
// preempt 預設關閉，需顯式輸出 "preempt" 才代表開啟（比照傳統 Cisco HSRP，與 Arista 相反）
function renderNXOSVRRPGroup(g){
  const lines=[`interface Vlan${g.vlanId}`];
  if(g.ip){
    const [ip,len]=g.ip.split('/');
    lines.push(`  ip address ${ip}/${len}`);
  }
  g.entries.forEach(v=>{
    lines.push(`  hsrp ${v.vrid}`);
    if(v.preempt)lines.push(`    preempt`);
    lines.push(`    priority ${v.priority}`);
    lines.push(`    ip ${v.vip}`);
  });
  return lines.join('\n');
}
function renderNXOSVRRP(list){return groupVrrpByVlan(list).map(renderNXOSVRRPGroup).join('\n!\n');}

// NX-OS VPC（Virtual Port Channel）：獨立頂層 "vpc domain N" 區塊，peer-link 則內嵌在
// 對應 port-channel 自己的 interface 區塊（見 renderNXOSInterface 的 vpc 參數），已查證
// 官方 Cisco Nexus 文件語法（feature vpc / vpc domain N / peer-keepalive destination / peer-gateway）
function renderNXOSVpc(vpc){
  if(!vpc||!vpc.domain)return '';
  const lines=[`vpc domain ${vpc.domain}`];
  if(vpc.peerKeepalive)lines.push(` peer-keepalive destination ${vpc.peerKeepalive}`);
  if(vpc.peerGateway)lines.push(' peer-gateway');
  return lines.join('\n');
}

function assembleNXOSConfig(model){
  // 真實 Nexus "show running-config" 開頭固定帶這類自我描述註解行，switch_analyzer 的
  // detectVendor() 以 "feature X" + "Cisco Nexus" 字樣作為 nxos 判定依據之一；先前產生器
  // 從未輸出這行，導致產生的設定檔匯入時無法被自動偵測為 nxos（既有缺口，隨匯入功能一併修正）
  const blocks=[`! Cisco Nexus Operating System (NX-OS) Software`,`! ${tr('notice.disclaimer')}`];
  if(model.breakouts&&model.breakouts.some(b=>b.vendor==='cisco_nxos'))blocks.push(`! ${tr('notice.nxosBreakoutWarning')}`);
  const hasVpc=model.vpc&&model.vpc.domain;
  if(model.ospf&&model.ospf.length)blocks.push('feature ospf');
  if(model.bgp&&model.bgp.length)blocks.push('feature bgp');
  if(hasVpc)blocks.push('feature vpc');
  // VRRP 在 NX-OS 是掛在 "interface Vlan N" SVI 底下的 HSRP 區塊，真實設備上需要先啟用
  // feature interface-vlan 才能建立 SVI，否則 interface Vlan 指令本身就會被拒絕
  if(model.vrrp&&model.vrrp.length)blocks.push('feature interface-vlan');
  // 2026-07-22 對外查證官方 NX-OS Security Configuration Guide 後新增：802.1X／
  // port-security 指令在 NX-OS 上同樣需要先啟用對應 feature，否則逐介面的
  // dot1x pae authenticator／switchport port-security 系列指令會被拒絕（IOS-XE 不需要
  // 這個前置步驟，先前沿用共用邏輯時漏了這點）
  if((model.security||[]).some(s=>s.dot1x==='auth'||s.dot1x==='supp'))blocks.push('feature dot1x');
  if((model.security||[]).some(s=>s.portSec))blocks.push('feature port-security');
  // 2026-07-27 補上：switch_analyzer 的 parseDHCP() 已於 2026-07-24 新增 nxos 分支（Relay
  // Agent，`ip dhcp relay address`），上面那則「完全沒有對應分支」的說明已過時；DHCP Relay
  // 指令同樣需要先啟用對應 feature 才會被真機接受
  const hasNxosDhcpRelay=(model.dhcp||[]).some(d=>d.type==='relay');
  if(hasNxosDhcpRelay)blocks.push('feature dhcp');
  blocks.push(`hostname ${model.sysname||'Switch'}`);
  const nxosBreakoutBlock=renderNXOSBreakoutBlock(model.breakouts);
  if(nxosBreakoutBlock)blocks.push(nxosBreakoutBlock);
  if(model.vlans&&model.vlans.length)blocks.push(renderNXOSVLANs(model.vlans));
  // VRF：官方文件確認 `vrf member NAME` 要求該 VRF 已用 `vrf context NAME` 建立，否則介面
  // 會停留在 down 狀態直到 VRF 建立為止，排在 Interfaces 之前輸出
  const nxosVrfNames=collectVrfNames(model.interfaces);
  if(nxosVrfNames.length)blocks.push(nxosVrfNames.map(n=>`vrf context ${n}`).join('\n!\n'));
  // vpc domain 必須排在「把 port-channel 指派為 peer-link」之前輸出：真實 NX-OS 要求
  // vpc domain 物件已存在，才能在 interface/port-channel 區塊內宣告 vpc peer-link，
  // 否則會被拒絕（"Please configure the vpc domain first" 一類訊息，已對外查證官方
  // Configuring vPCs 文件），結構與已修復的 Comware Bridge-Aggregation 問題相同
  const nxosVpcBlock=renderNXOSVpc(model.vpc);
  if(nxosVpcBlock)blocks.push(nxosVpcBlock);
  if(model.interfaces&&model.interfaces.length)blocks.push(renderNXOSInterfaces(model.interfaces,model.lacp,model.dhcp,model.acl,model.security,model.stp,model.vpc));
  const nxosLacpExtra=renderNXOSLACPExtra(model.lacp,model.interfaces);
  if(nxosLacpExtra)blocks.push(nxosLacpExtra);
  if(model.vrrp&&model.vrrp.length)blocks.push(renderNXOSVRRP(model.vrrp));
  // STP 全域：直接重用 Cisco/Dell OS10 共用的 renderSpanningTreeGlobal（parseSTP 對 nxos
  // 走同一套 Cisco-style generic 分支，語法沿用即可）
  const stpBlockNx=renderSpanningTreeGlobal(model.stp);
  if(stpBlockNx)blocks.push(stpBlockNx);
  if(model.ospf&&model.ospf.length)blocks.push(renderNXOSOSPF(model.ospf));
  if(model.routes&&model.routes.length)blocks.push(renderNXOSRoutes(model.routes));
  if(model.bgp&&model.bgp.length)blocks.push(renderNXOSBGPList(model.bgp));
  // ACL 定義本身（規則清單）：2026-07-22 對外查證官方 NX-OS Security Configuration
  // Guide 後改用專屬 renderNXOSACL()——原本沿用 renderCiscoACL()（IOS-XE 語法），但真實
  // NX-OS 容器是裸 "ip access-list NAME"（無 standard/extended 關鍵字），規則列格式也
  // 不同（序號在最前面，無 rule/seq 關鍵字），與 IOS-XE 完全不相容，對應的
  // _parseACLNXOS() 已同步新增。必須放在組裝順序最後——理由與 assembleDellOS10Config/
  // assembleCiscoConfig 相同：區塊擷取 regex 只認得下一個同關鍵字區塊或字串結尾
  if(model.acl&&model.acl.length)blocks.push(renderNXOSACL(model.acl));
  const nxosUsersBlock=renderNXOSUsers(model.users);
  if(nxosUsersBlock)blocks.push(nxosUsersBlock);
  return blocks.join('\n!\n')+'\n';
}
// 本機帳號：switch_analyzer 的 parseUsers()（NX-OS 分支）語法為
// "username NAME password N HASH role ROLE"，role 是直接字面值（非 Cisco IOS 式
// privilege-N 換算），密碼固定輸出等級 0（plaintext marker）
function renderNXOSUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>`username ${u.name} password 0 ${u.password} role ${u.role||'network-admin'}`).join('\n');
}
function renderNXOSACLEntry(a){
  const lines=[`ip access-list ${a.name}`];
  (a.rules||[]).forEach((r,idx)=>{
    const seq=r.seq||String((idx+1)*10);
    lines.push(` ${seq} ${r.action||'permit'} ${r.protocol||'ip'} ${r.src||'any'} ${r.dst||'any'}${r.dstPort?' eq '+r.dstPort:''}`);
  });
  return lines.join('\n');
}
function renderNXOSACL(list){return (list||[]).map(renderNXOSACLEntry).join('\n!\n');}

// ══════════════════════════════════════════════════════════════════
// Juniper（Junos）render 函式：階層式大括號設定，非逐行指令。
// switch_analyzer 用 junosBlock/junosSubBlocks 以大括號深度計數取區塊內容
// （而非其他 4 廠牌那種「下一個關鍵字或字串結尾」的 lookahead），組裝順序因此
// 不用像 Cisco ACL/QoS 或 Comware BGP 那樣「刻意排最後」；但代價是「同名頂層
// 區塊只能出現一次」——junosBlock 用非 global 比對，若同一份設定文字出現兩個
// 獨立的 "interfaces { }"，第二個會被完全忽略。故 assembleJuniperConfig 務必把
// 一般 interface 與 LACP 產生的 aeN 介面合併進同一個 interfaces{}，OSPF/BGP
// 合併進同一個 protocols{}，router-id/AS/靜態路由合併進同一個 routing-options{}。
//
// 核心功能範圍（比照當初 Comware/Cisco MVP）：Hostname/VLAN/Interface(access/
// trunk，無 hybrid)/OSPF/BGP/靜態路由/LACP。不含 RIP/VRRP/QoS/Security（switch_
// analyzer 目前也還沒有這些項目的 Junos parser）。
//
// OSPF 語意差異：Junos area 底下宣告的是「介面名稱」而非 network+wildcard CIDR，
// 沿用既有 Area 表格 UI，但 render 把「Network」欄位的值當成介面名稱使用（
// wildcard/type 欄位忽略）。
// BGP 語意差異：Junos 需要 group 名稱，依 peer.as===asn 自動分成 internal-peers/
// external-peers 兩組（跟 parser 自己推斷 iBGP/eBGP 的邏輯一致），不新增 UI 欄位。
// ══════════════════════════════════════════════════════════════════

