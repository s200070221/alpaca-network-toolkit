function renderAristaVLAN(v){
  const lines=[`vlan ${v.id}`];
  if(v.name)lines.push(` name ${v.name}`);
  return lines.join('\n');
}
function renderAristaVLANs(vlans){return (vlans||[]).map(renderAristaVLAN).join('\n!\n');}

// switchport trunk/access（VLAN 屬性）render，Arista EOS 專用（與 Cisco 相同語法，但獨立
// render 函式，故獨立抽一份輔助函式，比照既有慣例避免未來語法分歧時互相牽動）；抽成獨立
// 函式供 renderAristaInterface() 與 renderAristaLACPExtra() 共用。屬性不一致時不會擋設定
// 匯入，但該實體埠會被判定 suspended 排除在聚合之外；為確保「能夠成功聚合」，member port
// 一律不輸出這組屬性，改由 renderAristaLACPExtra() 統一輸出在 Port-Channel 介面上
function aristaSwitchportLines(iface){
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
function renderAristaInterface(iface,lacpList,dhcpList,aclList,securityList,stp,breakouts,ospf6List,qosApplyList){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(` description ${iface.desc}`);
  // Breakout：官方語法內嵌於母埠自己的 interface 區塊（比照 Comware/Aruba CX 既有慣例），
  // 已查證支援 4x10G/4x25G/2x50G 三種拆分比例（Arista Community "Understanding interface
  // breakout modes on Arista switches"）
  const bk=findBreakoutForPort(breakouts,iface.name);
  if(bk)lines.push(` breakout mode ${bk.mode}`);
  const lg=findLacpGroup(lacpList,iface.name);
  if(!lg)lines.push(...aristaSwitchportLines(iface));
  // ip/vrf（2026-07-27 補上，parseCiscoInterfaces() 早就有解析，renderAristaInterface() 從未
  // 輸出過）：SVI（Vlan）的 iface.ip 是 parser 轉換過的 CIDR 字串，需還原成點分遮罩才符合
  // "ip address IP MASK" 語法；Loopback／Management／routed 實體埠的 iface.ip 則是 parser
  // 直接原樣擷取的「IP 遮罩」字串（未轉 CIDR），直接輸出即可。Loopback 在整份 generator
  // 先前完全沒有輸出路徑，也是靠這裡補上（比照 Aruba CX renderArubaInterface() 的既有寫法）
  const isMgmt=/^Management/i.test(iface.name);
  // 次要IP（2026-08-12 新增）：parseCiscoInterfaces() 早就會透過共用函式解析出 Arista 的
  // secondaryIp（官方語法與 Cisco 相同 `ip address A B secondary`），但 renderAristaInterface()
  // 從未輸出過，比照 switch-generator-cisco.js:38 的 secLine 寫法補上；secondaryIp 一律是
  // CIDR 字串（不分介面類型），IPv6 無次要位址機制故排除
  // 2026-08-23 陣列化：parser 端 2026-08-17 已從「僅取第一筆」擴充為完整陣列 secondaryIps
  const secLines=(iface.secondaryIps||[]).filter(s=>!s.includes(':')).map(s=>{
    const [sip,slen]=s.split('/');
    return sip&&slen?` ip address ${sip} ${maskFromCidr(slen)} secondary`:'';
  }).filter(Boolean);
  // IPv6（試點 5 廠牌之一，官方 EOS User Manual 確認 interface 模式下 `ipv6 address ADDR/PREFIXLEN`
  // 與 Cisco 語法一致，不需遮罩換算）
  if(iface.type==='svi'){
    if(iface.ip){
      if(iface.ip.includes(':')){
        lines.push(` ipv6 address ${iface.ip}`);
      }else{
        const [ip,len]=iface.ip.split('/');
        lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
        secLines.forEach(l=>lines.push(l));
      }
    }
  }else if(iface.type==='loopback'||isMgmt){
    if(iface.ip){
      lines.push(` ${iface.ip.includes(':')?'ipv6':'ip'} address ${iface.ip}`);
      if(!iface.ip.includes(':'))secLines.forEach(l=>lines.push(l));
    }
  }else if(iface.mode==='routed'&&iface.ip){
    lines.push(' no switchport');
    lines.push(` ${iface.ip.includes(':')?'ipv6':'ip'} address ${iface.ip}`);
    if(!iface.ip.includes(':'))secLines.forEach(l=>lines.push(l));
  }
  // OSPFv3（2026-08-23 新增）：與 Cisco 共用同一份 ciscoOspf6IfaceLines()（switch-generator-
  // cisco.js），反查 model.ospf6 輸出 "ipv6 ospf PID area AREA"
  ciscoOspf6IfaceLines(ospf6List,iface.name).forEach(l=>lines.push(l));
  // vrf（2026-08-08 查證修正）：官方 EOS 4.23+ 語法為裸 "vrf NAME"（"vrf forwarding" 已廢棄），
  // parseCiscoInterfaces() 已同步改用 vendor 分流偵測；management 介面固定為 MGMT，是 parser
  // 端寫死賦值非反查而來，不存在對應真實指令
  if(iface.vrf&&!isMgmt)lines.push(` vrf ${iface.vrf}`);
  if(lg){
    const modeWord=lg.mode==='active'?'active':lg.mode==='passive'?'passive':'on';
    lines.push(` channel-group ${lg.id} mode ${modeWord}`);
  }
  if(iface.jumbo&&iface.jumbo.enabled&&iface.jumbo.mtu)lines.push(` mtu ${iface.jumbo.mtu}`);
  if(iface.shutdown)lines.push(' shutdown');
  findDhcpRelays(dhcpList,iface.name).forEach(rel=>lines.push(` ip helper-address ${rel.relayServer}`));
  // ipv6 traffic-filter（2026-09-03 新增，Arista 與 Cisco IOS-XE 共用同一套官方關鍵字，
  // 與 IPv4 的 ip access-group 不同字面），比對 _parseACLCisco() 的 ag6Re 分支
  findAclApplications(aclList,iface.name).forEach(ap=>lines.push(ap.ipVersion==='v6'?` ipv6 traffic-filter ${ap.name} ${ap.direction}`:` ip access-group ${ap.name} ${ap.direction}`));
  // service-policy 介面套用（2026-08-28（續5）新增，見 parseAristaServicePolicy() 註解）：
  // 官方語法多一段 "type qos" 限定詞在 direction 之前，與 Dell OS10 語序相反
  findQosApplications(qosApplyList,iface.name).forEach(ap=>lines.push(` service-policy type qos ${ap.direction} ${ap.policy}`));
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
function renderAristaInterfaces(ifaces,lacpList,dhcpList,aclList,securityList,stp,breakouts,ospf6List,qosApplyList){return (ifaces||[]).map(i=>renderAristaInterface(i,lacpList,dhcpList,aclList,securityList,stp,breakouts,ospf6List,qosApplyList)).join('\n!\n');}

function renderAristaLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    blocks.push([`interface Port-Channel${l.id}`,...aristaSwitchportLines(refIface)].join('\n'));
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return;
      const modeWord=l.mode==='active'?'active':l.mode==='passive'?'passive':'on';
      blocks.push(`interface ${mem}\n channel-group ${l.id} mode ${modeWord}`);
    });
  });
  return blocks.join('\n!\n');
}

// MLAG：Arista 的 stack 對應功能（switch_analyzer parseAristaMlag() 既有 stub 形狀
// {domain,peerLink,peerAddr,localIntf}），generator 端全新 UI 領域、無既有模板可抄
function renderAristaMlagBlock(mlag){
  if(!mlag||!(mlag.domain||mlag.peerLink||mlag.peerAddr||mlag.localIntf))return '';
  const lines=['mlag configuration'];
  if(mlag.domain)lines.push(` domain-id ${mlag.domain}`);
  if(mlag.localIntf)lines.push(` local-interface ${mlag.localIntf}`);
  if(mlag.peerAddr)lines.push(` peer-address ${mlag.peerAddr}`);
  if(mlag.peerLink)lines.push(` peer-link ${mlag.peerLink}`);
  return lines.join('\n');
}

// VRRP：真實 EOS 語法（vrrp N ipv4 VIP / vrrp N priority-level P），並非其他廠牌沿用的
// Cisco HSRP standby 語法。preempt 語意與其他廠牌相反——EOS 預設啟用，只有明確
// preempt===false 才輸出 "no vrrp N preempt"（對應 parseVRRP 的 'arista' 分支）
function renderAristaVRRPGroup(g){
  const lines=[`interface Vlan${g.vlanId}`];
  if(g.ip){
    const [ip,len]=g.ip.split('/');
    lines.push(` ip address ${ip}/${len}`);
  }
  g.entries.forEach(v=>{
    if(v.vip)lines.push(` vrrp ${v.vrid} ipv4 ${v.vip}`);
    // IPv6（2026-08-23 新增）：官方 Arista EOS User Manual 確認獨立的 "vrrp N ipv6 ADDR"
    // 宣告，前提須先在某個 vrid 上宣告 "vrrp N ipv4 version 3"（本工具不驗證此前提）
    if(v.vip6)lines.push(` vrrp ${v.vrid} ipv6 ${v.vip6}`);
    lines.push(` vrrp ${v.vrid} priority-level ${v.priority}`);
    if(v.preempt===false)lines.push(` no vrrp ${v.vrid} preempt`);
  });
  return lines.join('\n');
}
function renderAristaVRRP(list){return groupVrrpByVlan(list).map(renderAristaVRRPGroup).join('\n!\n');}

function assembleAristaConfig(model){
  // 真實 EOS "show running-config" 輸出固定帶有此類版本自我描述註解行，switch_analyzer 的
  // detectVendor() 以此作為 arista 判定依據之一（另一依據是 interface Ethernet+ip routing 組合），
  // 缺這行會導致 round-trip 時無法被自動辨識為 arista
  const blocks=[`! ${tr('notice.disclaimer')}`,'! Software image version: EOS',`hostname ${model.sysname||'Switch'}`];
  if(model.vlans&&model.vlans.length)blocks.push(renderAristaVLANs(model.vlans));
  // VRF（2026-08-08 查證修正）：Arista 官方社群確認 EOS 4.23 train（2019-08 起）廢棄
  // `vrf definition`／介面 `vrf forwarding NAME`，改用 `vrf instance NAME`（建立）＋介面裸
  // `vrf NAME`（綁定，見 renderAristaInterface()）；parseCiscoInterfaces() 已同步改用
  // vendor==='arista' 分流偵測裸 vrf 語法，round-trip 不再依賴 Cisco 式語法
  const aristaVrfNames=collectVrfNames(model.interfaces);
  if(aristaVrfNames.length)blocks.push(aristaVrfNames.map(n=>`vrf instance ${n}`).join('\n!\n'));
  if(model.interfaces&&model.interfaces.length)blocks.push(renderAristaInterfaces(model.interfaces,model.lacp,model.dhcp,model.acl,model.security,model.stp,model.breakouts,model.ospf6,model.qosApply));
  // DHCP Relay Option82（2026-07-24 新增解析，一直未接線）：真實語法是不含任何後綴參數的
  // 裸全域指令 "ip dhcp relay information option"（非逐介面），parser 端也是用行首錨點比對
  // 這一整行是否存在，故只要任一 relay 項目要求 option82，輸出一行全域指令即可
  if((model.dhcp||[]).some(d=>d.type==='relay'&&d.option82))blocks.push('ip dhcp relay information option');
  const aristaLacpExtra=renderAristaLACPExtra(model.lacp,model.interfaces);
  if(aristaLacpExtra)blocks.push(aristaLacpExtra);
  if(model.vrrp&&model.vrrp.length)blocks.push(renderAristaVRRP(model.vrrp));
  const mlagBlock=renderAristaMlagBlock(model.mlag);
  if(mlagBlock)blocks.push(mlagBlock);
  const stpBlockAr=renderSpanningTreeGlobal(model.stp);
  if(stpBlockAr)blocks.push(stpBlockAr);
  if(model.ospf&&model.ospf.length)blocks.push(renderCiscoOSPF(model.ospf));
  if(model.ospf6&&model.ospf6.length)blocks.push(renderCiscoOSPFv3(model.ospf6));
  if(model.rip&&model.rip.length)blocks.push(renderCiscoRIPList(model.rip));
  if(model.routes&&model.routes.length)blocks.push(renderCiscoRoutes(model.routes));
  if(model.bgp&&model.bgp.length)blocks.push(renderCiscoBGPList(model.bgp));
  // ACL：已查證官方 Arista EOS User Manual 後確認與 Cisco 語法相符，沿用 renderCiscoACL
  // 不需改動。QoS 已查證確認不相符，改用 renderAristaQoS()。放最後：理由同
  // assembleCiscoConfig/assembleDellOS10Config（區塊擷取正則只認得下一個同關鍵字區塊或字串結尾）
  if(model.acl&&model.acl.length)blocks.push(renderCiscoACL(model.acl));
  // class-map 必須先於引用它的 policy-map 定義，且其收尾正則同時認 policy-map 邊界，順序
  // 不能顛倒（2026-08-28（續5）新增）
  if(model.classMaps&&model.classMaps.length)blocks.push(renderAristaClassMapQoS(model.classMaps));
  if(model.qos&&model.qos.length)blocks.push(renderAristaQoS(model.qos));
  // 本機帳號：與 Cisco IOS 共用同一套 parseCiscoUsers()/renderCiscoUsers()，語法相符
  const aristaUsersBlock=renderCiscoUsers(model.users);
  if(aristaUsersBlock)blocks.push(aristaUsersBlock);
  if(model.snmpTrapHost)blocks.push(`snmp-server host ${model.snmpTrapHost}`);
  if(model.syslogServer)blocks.push(`logging host ${model.syslogServer}`);
  return blocks.join('\n!\n')+'\n';
}

// class-map/match（2026-08-28（續5）新增）：官方 EOS Quality of Service/Traffic Management
// 文件確認語法比 Cisco 家族多一段 "type qos" 限定詞，見 switch-analyzer-parser-arista.js
// 的 parseAristaClassMaps() 對應註解。本輪僅輸出已確認的 "match ip access-group" 這一種
// match 條件，即使使用者在共用表單選了 dscp/protocol/cos/ip-precedence/vlan 也不輸出
// （不臆測，官方逐字語法未查得）
function renderAristaClassMapQoS(list){
  const blocks=[];
  groupClassMapMatches(list).forEach((grp,name)=>{
    const lines=[`class-map type qos ${grp.matchType} ${name}`];
    grp.matches.forEach(mt=>{
      if(mt.type==='access-group'&&mt.value)lines.push(` match ip access-group ${mt.value}`);
    });
    blocks.push(lines.join('\n'));
  });
  return blocks.join('\n!\n');
}
// QoS：已查證官方 Arista EOS User Manual 後新增，真實語法 policy-map 標頭多一段
// "type quality-of-service"，bandwidth/shape 動作多一個單位關鍵字 "kbps"（與 Cisco
// 裸數字寫法不同）；police/priority 本輪未查證，維持沿用既有 Cisco 假設（不在本輪
// 查證修正範圍內，非新引入的假設）
function renderAristaQoS(list){
  const blocks=[];
  groupQosByPolicy(list).forEach((items,policy)=>{
    const lines=[`policy-map type quality-of-service ${policy}`];
    items.forEach(q=>{
      lines.push(` class ${q.cls}`);
      // 2026-07-22 對外查證官方 EOS User Manual/Traffic Management 文件後修正：
      // (1) police 子動詞真實語法是 "police cir N bc M"（cir/bc 關鍵字），原本的
      // "police rate N" 從未真實存在；(2) class 子模式下沒有 priority 這個指令，
      // EOS 的嚴格優先權是在 interface 的 tx-queue 層級設定（interface X / tx-queue N /
      // priority strict），與目前 QoS 表單資料結構（policy/class 導向）完全不同層級，
      // 本輪先移除捏造輸出，不臆測；真要支援需新增 tx-queue 專屬表單，留待未來規劃
      if(q.action==='police')lines.push(`  police cir ${q.rate||'1000000'}${q.burst?' bc '+q.burst:''}`);
      else if(q.action==='shape')lines.push(`  shape kbps ${q.rate||'1000000'}`);
      else if(q.action==='bandwidth')lines.push(`  bandwidth kbps ${q.rate||'1000'}`);
    });
    blocks.push(lines.join('\n'));
  });
  return blocks.join('\n!\n');
}

// ══════════════════════════════════════════════════════════════════
// Ruijie (RGOS) render 函式（2026-07-29 新增第 14 個廠牌）
// switch_analyzer parseRuijie() 對應範圍：VLAN(與 Cisco 相同，重用 renderCiscoVLANs)/
// Interface(access/trunk/hybrid)/OSPF/BGP/RIP/靜態路由(與 Cisco 語法相同，重用對應
// renderCiscoXxx)/LACP(AggregatePort+port-group，非 channel-group)/VRRP(vrrp N ip VIP，
// 非 HSRP)/VSU 堆疊(switch virtual domain+逐成員 switch N priority P+VSL 鏈路埠巢狀於
// 介面自己的區塊內宣告 port-member interface X)。尚無真實裝置匯出檔完整驗證 generator
// 產生的設定檔本身（analyzer 端已用兩份使用者提供的真實風格範例驗證過 parser 方向），
// 信心度沿用 analyzer 端註記。
// ══════════════════════════════════════════════════════════════════

// VLAN ID 陣列 → 範圍壓縮字串（如 [10,11,12,20] → "10-12,20"），僅供 hybrid render 使用
// （官方 "switchport hybrid allowed vlan tagged|untagged X-Y" 接受範圍格式，Comware 對應
// 的 "port hybrid vlan X tagged/untagged" 是空白分隔離散清單，兩者輸出格式不同，不可沿用
// Comware 既有的 .join(' ')）
