function compressVlanList(ids){
  const nums=[...new Set((ids||[]).map(Number))].filter(n=>!isNaN(n)).sort((a,b)=>a-b);
  const ranges=[]; let start=null,prev=null;
  nums.forEach(n=>{
    if(start===null){start=n;prev=n;return;}
    if(n===prev+1){prev=n;return;}
    ranges.push(start===prev?String(start):`${start}-${prev}`);
    start=n;prev=n;
  });
  if(start!==null)ranges.push(start===prev?String(start):`${start}-${prev}`);
  return ranges.join(',');
}

// switchport trunk/access/hybrid（VLAN 屬性）render，Ruijie 專用；抽成獨立函式供
// renderRuijieInterface() 與 renderRuijieLACPExtra() 共用。屬性不一致時不會擋設定匯入，
// 但該實體埠會被判定 suspended 排除在聚合之外；為確保「能夠成功聚合」，member port 一律
// 不輸出這組屬性，改由 renderRuijieLACPExtra() 統一輸出在 AggregatePort 介面上
function ruijieSwitchportLines(iface){
  const lines=[];
  if(!iface)return lines;
  if(iface.mode==='trunk'){
    lines.push(' switchport mode trunk');
    // 官方真實輸出常見用 "only" 關鍵字整批宣告完整清單（2026-07-29 使用者提供真實風格
    // 範例確認：switchport trunk allowed vlan only X,Y），比照 analyzer 端
    // parseRuijieInterfaces() 偏好判斷邏輯（only/all/裸清單優先），確保 round-trip 不失真
    if(iface.trunkVlans)lines.push(` switchport trunk allowed vlan only ${iface.trunkVlans}`);
    if(iface.nativeVlan)lines.push(` switchport trunk native vlan ${iface.nativeVlan}`);
  }else if(iface.mode==='access'){
    lines.push(' switchport mode access');
    if(iface.accessVlan)lines.push(` switchport access vlan ${iface.accessVlan}`);
  }else if(iface.mode==='hybrid'){
    lines.push(' switchport mode hybrid');
    const h=iface.hybrid||{};
    if(h.pvid)lines.push(` switchport hybrid native vlan ${h.pvid}`);
    if(h.untagged&&h.untagged.length)lines.push(` switchport hybrid allowed vlan untagged ${compressVlanList(h.untagged)}`);
    if(h.tagged&&h.tagged.length)lines.push(` switchport hybrid allowed vlan tagged ${compressVlanList(h.tagged)}`);
  }
  return lines;
}
function renderRuijieInterface(iface,lacpList,dhcpList,aclList,securityList,stp){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(` description ${iface.desc}`);
  const lg=findLacpGroup(lacpList,iface.name);
  if(!lg)lines.push(...ruijieSwitchportLines(iface));
  const isMgmt=/^Management/i.test(iface.name);
  if(iface.type==='svi'){
    if(iface.ip){
      if(iface.ip.includes(':')){
        lines.push(` ipv6 address ${iface.ip}`);
      }else{
        const [ip,len]=iface.ip.split('/');
        lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
      }
    }
  }else if(iface.type==='loopback'||isMgmt){
    if(iface.ip)lines.push(` ${iface.ip.includes(':')?'ipv6':'ip'} address ${iface.ip}`);
  }else if(iface.mode==='routed'&&iface.ip){
    lines.push(' no switchport');
    lines.push(` ${iface.ip.includes(':')?'ipv6':'ip'} address ${iface.ip}`);
  }
  if(iface.vrf&&!isMgmt)lines.push(` ip vrf forwarding ${iface.vrf}`);
  if(lg){
    const modeWord=lg.mode==='passive'?'passive':'active';
    lines.push(` port-group ${lg.id} mode ${modeWord}`);
  }
  if(iface.jumbo&&iface.jumbo.enabled&&iface.jumbo.mtu)lines.push(` mtu ${iface.jumbo.mtu}`);
  if(iface.shutdown)lines.push(' shutdown');
  findDhcpRelays(dhcpList,iface.name).forEach(rel=>lines.push(` ip helper-address ${rel.relayServer}`));
  findAclApplications(aclList,iface.name).forEach(ap=>lines.push(` ip access-group ${ap.name} ${ap.direction}`));
  const sec=findSecurityForPort(securityList,iface.name);
  if(sec){
    if(sec.dot1x==='auth')lines.push(' dot1x port-control auto');
    if(sec.portSec){
      lines.push(' switchport port-security');
      if(sec.maxMac)lines.push(` switchport port-security maximum ${sec.maxMac}`);
      if(sec.violation)lines.push(` switchport port-security violation ${sec.violation}`);
    }
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
function renderRuijieInterfaces(ifaces,lacpList,dhcpList,aclList,securityList,stp){
  return (ifaces||[]).map(i=>renderRuijieInterface(i,lacpList,dhcpList,aclList,securityList,stp)).join('\n!\n');
}

// LACP：Ruijie 稱聚合介面為 AggregatePort（AP），成員埠語法是 "port-group N mode
// {active|passive}"，與 Cisco channel-group 完全不同關鍵字（查證來源：官方 RG-S2600E
// CLI Reference Manual）
function renderRuijieLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    blocks.push([`interface AggregatePort ${l.id}`,...ruijieSwitchportLines(refIface)].join('\n'));
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return;
      const modeWord=l.mode==='passive'?'passive':'active';
      blocks.push(`interface ${mem}\n port-group ${l.id} mode ${modeWord}`);
    });
  });
  return blocks.join('\n!\n');
}

// VRRP：真實 RGOS 語法 "vrrp N ip VIP"／"vrrp N priority P"／"vrrp N preempt"，非其他
// 廠牌沿用的 Cisco HSRP standby 語法，比照 Aruba CX renderArubaVRRPGroup 模板改寫關鍵字
// （vip→ip）
function renderRuijieVRRPGroup(g){
  const lines=[`interface VLAN ${g.vlanId}`];
  if(g.ip){
    const [ip,len]=g.ip.split('/');
    lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
  }
  g.entries.forEach(v=>{
    lines.push(` vrrp ${v.vrid} ip ${v.vip}`);
    lines.push(` vrrp ${v.vrid} priority ${v.priority}`);
    if(v.preempt)lines.push(` vrrp ${v.vrid} preempt`);
  });
  return lines.join('\n');
}
function renderRuijieVRRP(list){return groupVrrpByVlan(list).map(renderRuijieVRRPGroup).join('\n!\n');}

// VSU 堆疊（Virtual Switch Unit）：全域 "switch virtual domain <id>" + 逐成員
// "switch <n> priority <p>"，查證來源官方 VSU 技術文檔 https://www.ruijie.com.cn/fw/wt/90872/ 。
// 2026-08-07 對外查證 VSL 鏈路埠語法（Medium／CloudAja 兩份獨立教學文件交叉確認命令序列一致）
// 修正：port-member interface 是獨立的 "vsl-port" 子模式（vsl-port/逐行 port-member interface/
// exit），並非巢狀在各實體介面自己的 interface 區塊裡——舊版巢狀寫法已證實是結構性錯誤，
// switch_analyzer 的 parseRuijieStack() 已同步修正解析來源。信心度note：教學文件展示的是兩台
// 實體裝置合併前各自的初始設定指令，與 show running-config 是否逐字相同尚無法 100% 排除落差，
// 仍是次於「已用真實裝置匯出檔校正過」的廠牌之信心度
function renderRuijieStack(stack){
  const vslSet=new Set();
  if(!stack||!stack.domain||!(stack.members||[]).length)return{block:'',vslSet};
  const lines=[`switch virtual domain ${stack.domain}`];
  const vslLines=[];
  (stack.members||[]).forEach(m=>{
    if(m.id&&m.priority)lines.push(`switch ${m.id} priority ${m.priority}`);
    (m.vslPorts||[]).forEach(p=>{if(p){vslSet.add(p);vslLines.push(`port-member interface ${p}`);}});
  });
  if(vslLines.length){
    lines.push('vsl-port');
    lines.push(...vslLines);
    lines.push('exit');
  }
  return{block:lines.join('\n'),vslSet};
}

function assembleRuijieConfig(model){
  // 真實 RGOS "show running-config" 韌體版本字串固定含 "RGOS" 字樣，switch_analyzer 的
  // detectVendor() 以此作為 ruijie 判定依據之一，缺這行會導致 round-trip 時無法被自動
  // 辨識為 ruijie（比照 Arista EOS 版本註解行的既有慣例）
  const blocks=[`! ${tr('notice.disclaimer')}`,'! version RGOS 11.4(1)B1',`hostname ${model.sysname||'Switch'}`];
  if(model.vlans&&model.vlans.length)blocks.push(renderCiscoVLANs(model.vlans));
  // VRF：2026-08-09 查證官方 Ruijie RG-S6120 Series RGOS Command Reference（Release
  // 12.1(2)B0102）第 7.4 節「ip vrf」確認 `ip vrf vrf-name` 為 Global configuration mode
  // 建立 VRF 的指令（"Use this command to create a VRF"），與 Cisco classic IOS 語法相同，
  // 非單純類推；介面綁定 `ip vrf forwarding NAME`（第 7.5 節）語法亦一併確認
  const ruijieVrfNames=collectVrfNames(model.interfaces);
  if(ruijieVrfNames.length)blocks.push(ruijieVrfNames.map(n=>`ip vrf ${n}`).join('\n!\n'));
  const stackInfo=renderRuijieStack(model.stack);
  if(model.interfaces&&model.interfaces.length)blocks.push(renderRuijieInterfaces(model.interfaces,model.lacp,model.dhcp,model.acl,model.security,model.stp));
  // DHCP Relay Option82：與 Cisco 共用同一套 "ip dhcp snooping information option" 全域旗標
  // （parseDHCP 的 cisco/ruijie 共用分支已確認此關鍵字），比照 Arista 既有寫法
  if((model.dhcp||[]).some(d=>d.type==='relay'&&d.option82))blocks.push('ip dhcp snooping information option');
  const ruijieLacpExtra=renderRuijieLACPExtra(model.lacp,model.interfaces);
  if(ruijieLacpExtra)blocks.push(ruijieLacpExtra);
  if(model.vrrp&&model.vrrp.length)blocks.push(renderRuijieVRRP(model.vrrp));
  // vsl-port 是獨立子模式，與 model.interfaces 表單完全無關，VSL 埠一律由 renderRuijieStack()
  // 的 stackInfo.block 一併輸出，不需要像舊版那樣為「不在 Interface 表單內的埠」另外補區塊
  if(stackInfo.block)blocks.push(stackInfo.block);
  const stpBlockRj=renderSpanningTreeGlobal(model.stp);
  if(stpBlockRj)blocks.push(stpBlockRj);
  // OSPF/BGP/RIP/靜態路由/ACL：已查證與 Cisco IOS 語法相符，直接重用對應 renderCiscoXxx，
  // 沿用既有慣例排在 blocks 陣列最後（區塊擷取正則只認得下一個同關鍵字區塊或字串結尾）
  if(model.ospf&&model.ospf.length)blocks.push(renderCiscoOSPF(model.ospf));
  if(model.rip&&model.rip.length)blocks.push(renderCiscoRIPList(model.rip));
  if(model.routes&&model.routes.length)blocks.push(renderCiscoRoutes(model.routes));
  if(model.bgp&&model.bgp.length)blocks.push(renderCiscoBGPList(model.bgp));
  if(model.acl&&model.acl.length)blocks.push(renderCiscoACL(model.acl));
  // QoS：RGOS 語法未查得與 Cisco 有落差佐證，重用共用的 Cisco-style policy-map render
  // （renderPolicyMapQoS，非 Arista 專屬的 renderAristaQoS，後者已查證的 EOS 差異
  // "type quality-of-service"/kbps 單位詞對 Ruijie 而言查無對應佐證，不應套用）；放最後
  // 理由同 ACL/BGP（policy-map 區塊擷取正則只認得下一個同關鍵字區塊或字串結尾）
  if(model.qos&&model.qos.length)blocks.push(renderPolicyMapQoS(model.qos));
  // 本機帳號：與 Cisco IOS 共用同一套 parseCiscoUsers()/renderCiscoUsers()，語法相符
  const ruijieUsersBlock=renderCiscoUsers(model.users);
  if(ruijieUsersBlock)blocks.push(ruijieUsersBlock);
  return blocks.join('\n!\n')+'\n';
}

// ══════════════════════════════════════════════════════════════════
// Netgear M4300 (Intelligent Edge, ICOS) render 函式（2026-07-30 新增第 15 個廠牌）
// switch_analyzer parser 範圍：VLAN(vlan database)/Interface(switchport mode
// access/trunk，Cisco 相容別名)/LACP(addport lag N，ICOS 語系)/VRRP(ip vrrp N，ICOS
// 語系)/OSPF(bare "router ospf"，無 process-id)/RIP(bare "router rip")/靜態路由(nexthop
// 可為 interface vlan N)。OSPF/RIP/靜態路由與 Cisco 語法相近但 bare router ospf 無
// process-id、ip route 可用 interface 當 nexthop，故不重用 renderCiscoOSPF/
// renderCiscoRoutes，自行輸出；RIP 本身無可設定欄位，重用 renderCiscoRIPList 會多印出
// process-id 造成 round-trip 失真，一併自寫。ACL/QoS/Security/DHCP Server 因查無足夠
// 把握的官方語法佐證不輸出；BGP 官方 202-11997-08 版本更新記錄明確寫「已移除 BGP 相關
// 敘述、此協定不支援」，裝置真不支援已列入 VENDOR_INCAPABLE 卡片隱藏，非查無語法。
// switchport trunk/access（VLAN 屬性）render，Netgear M4300 專用；抽成獨立函式供
// renderNetgearInterface() 與 renderNetgearLACPExtra() 共用。屬性不一致時不會擋設定匯入，
// 但該實體埠會被判定 suspended 排除在聚合之外；為確保「能夠成功聚合」，member port 一律
// 不輸出這組屬性，改由 renderNetgearLACPExtra() 統一輸出在 lag 介面上
