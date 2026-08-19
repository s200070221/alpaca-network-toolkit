function renderDellOS10VLANs(vlans,vrrpList,interfaces){
  const vrrpByVlan=new Map(groupVrrpByVlan(vrrpList).map(g=>[String(g.vlanId),g]));
  const sviByVlan=new Map((interfaces||[]).filter(i=>i.type==='svi')
    .map(i=>[String((i.name.match(/(\d+)/)||[])[1]||''),i]));
  const ids=new Set([...(vlans||[]).map(v=>String(v.id)),...vrrpByVlan.keys(),...sviByVlan.keys()]);
  const blocks=[...ids].sort((a,b)=>parseInt(a)-parseInt(b)).map(id=>{
    const v=(vlans||[]).find(x=>String(x.id)===id);
    const g=vrrpByVlan.get(id);
    const svi=sviByVlan.get(id);
    const lines=[`interface vlan${id}`];
    if(v&&v.name)lines.push(` description ${v.name}`);
    const ip=(svi&&svi.ip)||(g&&g.ip)||'';
    // 官方 SmartFabric OS10 User Guide 確認 IPv6 語法 `ipv6 address ADDR/PREFIXLEN`
    if(ip)lines.push(` ${ip.includes(':')?'ipv6':'ip'} address ${ip}`);
    // 次要IP（2026-08-12 新增）：官方 `ip address A/N secondary`，僅取第一筆為 MVP 範圍
    if(svi&&svi.secondaryIp&&!svi.secondaryIp.includes(':'))lines.push(` ip address ${svi.secondaryIp} secondary`);
    if(svi&&svi.vrf)lines.push(` ip vrf forwarding ${svi.vrf}`);
    if(g)g.entries.forEach(e=>{
      lines.push(` vrrp-group ${e.vrid}`);
      lines.push(`  virtual-address ${e.vip}`);
      lines.push(`  priority ${e.priority}`);
    });
    return lines.join('\n');
  });
  return blocks.join('\n!\n');
}

// switchport trunk/access（VLAN 屬性）render，Dell OS10 專用；抽成獨立函式供
// renderDellOS10Interface() 與 renderDellOS10LACPExtra() 共用。屬性不一致時 Dell OS10
// （Cisco EtherChannel 語系）不會擋設定匯入，但該實體埠會被判定 suspended 排除在聚合之外；
// 為確保「能夠成功聚合」，member port 一律不輸出這組屬性，改由 renderDellOS10LACPExtra()
// 統一輸出在 Port-channel 介面上（member 個別填的設定被忽略，見 lacpMemberAttrWarnings()
// 的非阻擋性提示）
function dellOS10SwitchportLines(iface){
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
function renderDellOS10Interface(iface,lacpList,aclList,securityList,stp){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(` description ${iface.desc}`);
  // management 介面天生為 L3，vrf 固定為 MGMT（parseDellOS10Interfaces() 對此欄位是寫死
  // 賦值，非從設定文字反查而來，故不存在對應可輸出的真實指令，不臆測語法）
  const isMgmt=/^management/i.test(iface.name);
  const lg=findLacpGroup(lacpList,iface.name);
  if(!lg)lines.push(...dellOS10SwitchportLines(iface));
  if(iface.mode==='routed'){
    // routed 實體埠/Port-channel：parseDellOS10Interfaces() 靠 body 內是否含 "no switchport"
    // 判斷才會解析 ip/vrf，故要 round-trip 必須先輸出這行（2026-07-27 補上，先前完全沒有
    // 輸出過，routed 埠的 ip/vrf 從未寫回設定文字）
    lines.push(' no switchport');
  }
  // 官方 SmartFabric OS10 User Guide 確認 IPv6 語法 `ipv6 address ADDR/PREFIXLEN`，iface.ip
  // 本來就直接存完整 CIDR 字串輸出（無遮罩換算），只需依冒號判斷切換關鍵字
  if(iface.ip)lines.push(` ${iface.ip.includes(':')?'ipv6':'ip'} address ${iface.ip}`);
  // 次要IP（2026-08-12 新增）：官方 `ip address A/N secondary`，僅取第一筆為 MVP 範圍
  if(iface.secondaryIp&&!iface.secondaryIp.includes(':'))lines.push(` ip address ${iface.secondaryIp} secondary`);
  if(iface.vrf&&!isMgmt)lines.push(` ip vrf forwarding ${iface.vrf}`);
  if(lg){
    const modeWord=lg.mode==='active'?'active':lg.mode==='passive'?'passive':'on';
    lines.push(` channel-group ${lg.id} mode ${modeWord}`);
  }
  if(iface.jumbo&&iface.jumbo.enabled&&iface.jumbo.mtu)lines.push(` mtu ${iface.jumbo.mtu}`);
  if(iface.shutdown)lines.push(' shutdown');
  // ACL 套用：已查證真實語法規則列帶 seq 前綴，套用指令 ip access-group 與 Cisco 相同不需改動
  findAclApplications(aclList,iface.name).forEach(ap=>lines.push(` ip access-group ${ap.name} ${ap.direction}`));
  // Port Security-802.1X：已查證官方 SmartFabric OS10 User Guide 後修正——802.1X 改輸出
  // "dot1x port-control auto"（真實最小可用設定，非原本沿用 Cisco 的 dot1x pae
  // authenticator；全域 dot1x system-auth-control 因不影響本表單 round-trip 判斷、
  // 且會牽動 Cisco 共用 assemble 函式，本輪不輸出，記為已知限制）；port-security 改為
  // 巢狀 "switchport port-security" 子模式下的 "mac-learn limit N"/"mac-learn limit
  // violation X"，非原本假想的攤平 Cisco 寫法
  const sec=findSecurityForPort(securityList,iface.name);
  if(sec){
    if(sec.dot1x==='auth')lines.push(' dot1x port-control auto');
    else if(sec.dot1x==='supp')lines.push(' dot1x pae supplicant');
    if(sec.portSec){
      lines.push(' switchport port-security');
      if(sec.maxMac)lines.push(`  mac-learn limit ${sec.maxMac}`);
      if(sec.violation)lines.push(`  mac-learn limit violation ${sec.violation}`);
    }
    // guest-vlan：2026-07-22 對外查證官方 SmartFabric OS10 User Guide 後移除——
    // `dot1x guest-vlan` 只存在於舊版 OS9/Force10 CLI（S3048-ON 等機型），OS10 官方
    // 文件站內搜尋查無任何對應指令，屬於真實功能缺口非命名差異，先移除捏造輸出不臆測
  }
  // STP：spanning-tree bpduguard enable/guard root 已查證與 Cisco 相符，不需改動
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
function renderDellOS10Interfaces(ifaces,lacpList,aclList,securityList,stp){return ifaces.map(i=>renderDellOS10Interface(i,lacpList,aclList,securityList,stp)).join('\n!\n');}

function renderDellOS10LACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    blocks.push([`interface Port-channel${l.id}`,...dellOS10SwitchportLines(refIface)].join('\n'));
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return;
      const modeWord=l.mode==='active'?'active':l.mode==='passive'?'passive':'on';
      blocks.push(`interface ${mem}\n channel-group ${l.id} mode ${modeWord}`);
    });
  });
  return blocks.join('\n!\n');
}

// OSPF/BGP/靜態路由皆為 CIDR 格式（network X/Y area Z、network X/Y、ip route X/Y GW），
// 跟 Cisco 的 dotted-mask 格式不同，共用 UI 欄位本來就存 CIDR 字串，不需要 maskFromCidr 轉換
function renderDellOS10OSPFProcess(o){
  const lines=[`router ospf ${o.pid}`];
  if(o.routerId)lines.push(` router-id ${o.routerId}`);
  (o.areas||[]).forEach(a=>{
    (a.networks||[]).forEach(n=>lines.push(` network ${n.network} area ${a.area}`));
  });
  return lines.join('\n');
}
function renderDellOS10OSPF(list){return (list||[]).map(renderDellOS10OSPFProcess).join('\n!\n');}

function renderDellOS10BGP(b){
  const lines=[`router bgp ${b.asn}`];
  if(b.routerId)lines.push(` bgp router-id ${b.routerId}`);
  (b.peers||[]).forEach(p=>{
    lines.push(` neighbor ${p.ip} remote-as ${p.as}`);
    if(p.desc)lines.push(` neighbor ${p.ip} description ${p.desc}`);
  });
  (b.networks||[]).forEach(n=>lines.push(` network ${n}`));
  return lines.join('\n');
}
function renderDellOS10BGPList(list){return (list||[]).map(renderDellOS10BGP).join('\n!\n');}

// vrf==='MGMT'（2026-07-27 補上）：parseDellOS10Routes() 的 management VRF 路由是完全
// 獨立的關鍵字 `management route DST/LEN GW`（非 Cisco 式 `ip route vrf VRF ...`），先前
// 一律走 renderArubaRoute() 輸出成一般 `ip route`，MGMT VRF 路由會被誤植成一般路由
function renderDellOS10Route(r){
  if(r.vrf==='MGMT')return `management route ${r.dst} ${r.gw}`;
  return renderArubaRoute(r);
}
function renderDellOS10Routes(list){return (list||[]).map(renderDellOS10Route).join('\n!\n');}

// DHCP：僅 server pool，parser 無 relay/range/excluded 分支
function renderDellOS10DHCPPool(d){
  const lines=[`ip dhcp pool ${d.name}`];
  if(d.network)lines.push(` subnet ${d.network}`);
  if(d.gateway)lines.push(` default-router ${d.gateway}`);
  if(d.dns)lines.push(` dns-server ${d.dns}`);
  if(d.lease)lines.push(` lease ${d.lease}`);
  return lines.join('\n');
}
function renderDellOS10DHCP(list){return (list||[]).filter(d=>d.type==='server').map(renderDellOS10DHCPPool).join('\n!\n');}

// Breakout：獨立頂層 `port-group X` 區塊 → `mode Eth ratio`，子埠命名 ethernetX:1~4（冒號）
function renderDellOS10BreakoutBlock(breakouts){
  const dellBreakouts=(breakouts||[]).filter(b=>b.vendor==='dell-os10');
  if(!dellBreakouts.length)return '';
  const modeMap={'4x10G':'10g-4x','4x25G':'25g-4x'};
  const blocks=dellBreakouts.map(b=>{
    const eth=modeMap[b.mode];
    if(!eth)return ''; // 2x50G 未查證官方語法，不輸出
    const pgId=b.parentPort.replace(/^ethernet/i,'');
    return `port-group ${pgId}\n mode Eth ${eth}`;
  }).filter(Boolean);
  return blocks.join('\n!\n');
}

function assembleDellOS10Config(model){
  const blocks=[`! ${tr('notice.disclaimer')}`,`hostname ${model.sysname||'Switch'}`];
  const breakoutBlockDell=renderDellOS10BreakoutBlock(model.breakouts);
  if(breakoutBlockDell)blocks.push(breakoutBlockDell);
  // VRF：官方文件確認 `ip vrf forwarding NAME` 要求該 VRF 已用 `ip vrf NAME` 建立；SVI 的
  // vrf 欄位巢狀在 renderDellOS10VLANs() 輸出的 interface vlanN 區塊內，故排在該區塊之前
  const dellVrfNames=collectVrfNames(model.interfaces);
  if(dellVrfNames.length)blocks.push(dellVrfNames.map(n=>`ip vrf ${n}`).join('\n!\n'));
  const vlanBlock=renderDellOS10VLANs(model.vlans,model.vrrp,model.interfaces);
  if(vlanBlock)blocks.push(vlanBlock);
  // SVI（type:'svi'）已由 renderDellOS10VLANs() 合併輸出進 interface vlanN 區塊，
  // 這裡只處理其餘實體埠/Port-channel/management，避免同一個 vlanN 被輸出成兩個區塊
  const dellPhysicalIfaces=(model.interfaces||[]).filter(i=>i.type!=='svi');
  if(dellPhysicalIfaces.length)blocks.push(renderDellOS10Interfaces(dellPhysicalIfaces,model.lacp,model.acl,model.security,model.stp));
  const dellLacpExtra=renderDellOS10LACPExtra(model.lacp,model.interfaces);
  if(dellLacpExtra)blocks.push(dellLacpExtra);
  if(model.dhcp&&model.dhcp.some(d=>d.type==='server'))blocks.push(renderDellOS10DHCP(model.dhcp));
  // STP 全域：直接重用 Cisco/Aruba CX 共用的 renderSpanningTreeGlobal（parseSTP 對 dell-os10
  // 走同一套 generic 邏輯，語法沿用即可）
  const stpBlockDell=renderSpanningTreeGlobal(model.stp);
  if(stpBlockDell)blocks.push(stpBlockDell);
  if(model.ospf&&model.ospf.length)blocks.push(renderDellOS10OSPF(model.ospf));
  if(model.routes&&model.routes.length)blocks.push(renderDellOS10Routes(model.routes));
  if(model.bgp&&model.bgp.length)blocks.push(renderDellOS10BGPList(model.bgp));
  // ACL：已查證官方 SmartFabric OS10 User Guide 後改用 renderDellOS10ACL()（規則列帶
  // seq 前綴，非 Cisco 裸數字寫法）；QoS 同批查證後改用 renderDellOS10QoS()（police
  // cir/pir、bandwidth percent，與 Cisco 裸數字寫法不同）。必須放在組裝順序最後——
  // 理由與 assembleCiscoConfig 相同：兩者的區塊擷取 regex 只認得下一個同關鍵字區塊或字串結尾
  if(model.acl&&model.acl.length)blocks.push(renderDellOS10ACL(model.acl));
  if(model.qos&&model.qos.length)blocks.push(renderDellOS10QoS(model.qos));
  const dellUsersBlock=renderDellOS10Users(model.users);
  if(dellUsersBlock)blocks.push(dellUsersBlock);
  return blocks.join('\n!\n')+'\n';
}
// 本機帳號：switch_analyzer 的 parseDellOS10Users() OS10 語法為
// "username NAME password N HASH role ROLE"（產生器一律輸出此新式語法，非 OS9 的
// privilege 寫法），密碼固定輸出等級 0（plaintext marker）
function renderDellOS10Users(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>`username ${u.name} password 0 ${u.password} role ${u.role||'sysadmin'}`).join('\n');
}

// ACL：已查證官方 SmartFabric OS10 User Guide 後新增，真實規則列帶 "seq N" 字面前綴
// （如 "seq 10 permit ip host X host Y"），非原本沿用 Cisco 的裸數字前綴寫法
function renderDellOS10ACLEntry(a){
  const lines=[`ip access-list ${a.type||'extended'} ${a.name}`];
  (a.rules||[]).forEach(r=>{
    let line=r.seq?` seq ${r.seq} `:' ';
    line+=`${r.action||'permit'}`;
    if(a.type==='standard')line+=` ${r.src||'any'}`;
    else line+=` ${r.protocol||'ip'} ${r.src||'any'} ${r.dst||'any'}${r.dstPort?' eq '+r.dstPort:''}`;
    lines.push(line);
    if(r.remark)lines.push(` remark ${r.remark}`);
  });
  return lines.join('\n');
}
function renderDellOS10ACL(list){return (list||[]).map(renderDellOS10ACLEntry).join('\n!\n');}

// QoS：已查證官方 SmartFabric OS10 User Guide 後新增，真實語法 police 帶 cir/pir 雙值
// （committed+peak information rate，共用形狀僅有單一 rate 欄位，pir 沿用同一值，已知
// 簡化）；bandwidth 為百分比制 "bandwidth percent N"，與 Cisco 裸數字寫法不同；比照
// renderPolicyMapQoS 用 groupQosByPolicy 依 policy 分組，避免同一 policy 多個 class
// 被拆成重複的 policy-map 標頭
function renderDellOS10QoS(list){
  const blocks=[];
  groupQosByPolicy(list).forEach((items,policy)=>{
    const lines=[`policy-map ${policy}`];
    items.forEach(q=>{
      lines.push(` class ${q.cls}`);
      if(q.action==='police')lines.push(`  police cir ${q.rate||0} pir ${q.rate||0}`);
      else if(q.action==='priority')lines.push('  priority');
      // 2026-07-22 對外查證官方 SmartFabric OS10 User Guide 後修正：shape 沒有 average
      // 關鍵字，真實語法是 `shape min kbps N max kbps N`；burst 不是 shape 底下的獨立
      // 子動詞（burst 語意屬於 police，OS10 用 cir/pir 雙值表示，本工具目前 QoS 表單
      // 沒有獨立 burst 欄位對應 police，故此處直接不輸出，不臆測）
      else if(q.action==='shape')lines.push(`  shape min kbps ${q.rate||0} max kbps ${q.rate||0}`);
      else if(q.action==='bandwidth')lines.push(`  bandwidth percent ${q.rate||0}`);
    });
    blocks.push(lines.join('\n'));
  });
  return blocks.join('\n!\n');
}

// ══════════════════════════════════════════════════════════════════
// Arista EOS render 函式（switch_analyzer parser 範圍：VLAN/Interface(access/trunk)/
// MLAG(stack)/OSPF/BGP/RIP/靜態路由/LACP/VRRP(真實 EOS 語法)/DHCP Relay(ip helper-address)/
// ACL/QoS/Port Security-802.1X/STP。OSPF/BGP/RIP/靜態路由/ACL/QoS/Security/STP 直接沿用
// Cisco 既有 renderCiscoOSPF/renderCiscoBGPList/renderCiscoRIPList/renderCiscoRoutes/
// renderCiscoACL/renderPolicyMapQoS/renderSpanningTreeGlobal，因為 switch_analyzer 的
// parseArista() 本身就是直接呼叫 parseCiscoOSPF/parseCiscoBGP/parseCiscoRIP/parseCiscoRoutes，
// parseACL/parseQoS/parseSecurity/parseSTP 對 arista 也是走 Cisco-style 通用 fallback 分支，
// 語法必須一致才能 round-trip。DHCP Server pool（EOS 4.22.1+ 的 "dhcp server" 區塊，Kea
// backend）語法未查證到可信來源，本輪不產生；Breakout/VXLAN 不在本輪範圍。
// VRRP 原本被 switch_analyzer 誤接成 Cisco HSRP 語法（parseVRRP(cfg,'cisco')），本輪已對外
// 查證 Arista 官方 EOS 4.36.1F "VRRP and VARP" 文件並修正為真實 EOS 語法（parseVRRP 新增
// 'arista' 分支），見 CLAUDE.md。DHCP Relay 語法查證來源為 Arista Community "DHCP Relay" 文件。
// ══════════════════════════════════════════════════════════════════

