function renderArubaVLAN(v,vxlanVnis){
  const lines=[`vlan ${v.id}`];
  if(v.name)lines.push(`    name ${v.name}`);
  // VXLAN VNI 映射內嵌進同一個 vlan 區塊（而非另開頂層 vlan 區塊），因為
  // switch_analyzer parseVXLAN() 的 vlanRe 與主 VLAN 解析用同一個 "^vlan N" 關鍵字，
  // 兩個獨立區塊會導致其一被覆蓋/漏抓
  const vni=(vxlanVnis||[]).find(x=>x.vlan===v.id);
  if(vni&&vni.vni)lines.push(`    vni ${vni.vni}`);
  return lines.join('\n');
}
function renderArubaVLANs(vlans,vxlanVnis){return vlans.map(v=>renderArubaVLAN(v,vxlanVnis)).join('\n!\n');}

// VXLAN（Aruba CX）：頂層 vxlan 區塊僅承載 source-interface/source-ip（VTEP），
// VNI 對 VLAN 的映射改內嵌進 renderArubaVLAN（見上方），三種官方語法變體裡信心最高、
// 涵蓋率最廣的一種，對應 parseVXLAN() aruba 分支的 vxMatch + vlanRe 兩段解析
function renderArubaVXLAN(vxlan){
  if(!vxlan||!vxlan.vtep)return '';
  return `vxlan\n    source-interface ${vxlan.vtep}`;
}

// vlan trunk/access（class-two 屬性）render，Aruba CX 專用；抽成獨立函式供
// renderArubaInterface() 與 renderArubaLACPExtra() 共用（後者需要把同一組屬性輸出到 lag 介面上）
function arubaVlanLines(iface){
  const lines=[];
  if(!iface)return lines;
  if(iface.mode==='trunk'){
    if(iface.nativeVlan)lines.push(`    vlan trunk native ${iface.nativeVlan}`);
    if(iface.trunkVlans)lines.push(`    vlan trunk allowed ${iface.trunkVlans}`);
  }else if(iface.mode==='access'){
    if(iface.accessVlan)lines.push(`    vlan access ${iface.accessVlan}`);
  }
  return lines;
}
function renderArubaInterface(iface,lacpList,dhcpList,aclList,securityList,stp,breakouts,areaOfIface){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(`    description ${iface.desc}`);
  const bk=findBreakoutForPort(breakouts,iface.name);
  if(bk){
    const [count,speed]=bk.mode.split('x');
    lines.push(`    split ${count} ${speed.toLowerCase()} confirm`);
  }
  // L3 欄位（2026-07-27 補上，先前完全沒有輸出：parser 端 parseArubaInterfaces() 有
  // 正確解析 ip address/vrf attach，但 generator 從未寫回設定文字）。官方文件＋真實
  // AOS-CX 設定檔確認：SVI/Loopback 直接 `ip address`；實體埠需先 `routing`（L3 模式）
  // 或顯式 `no routing`（L2 模式，真機對非路由埠一律顯式宣告，非必要但合法冗餘）。
  // IPv6（試點 5 廠牌之一，官方 AOS-CX IPv6 Quick Start Guide 確認 `ipv6 address ADDR/PREFIXLEN`，
  // 本來就是直出無遮罩換算，僅需切換關鍵字）
  // 次要IP（Secondary IP，官方 AOS-CX IP Services Guide／CLI 文件：`ip address
  // ADDR/PREFIX secondary`，Layer 3 interface（含 VLAN SVI）皆適用；僅取第一筆為
  // MVP 範圍，本來就是直出 CIDR 不需遮罩換算）
  const secLine=iface.secondaryIp&&!iface.secondaryIp.includes(':')?`    ip address ${iface.secondaryIp} secondary`:'';
  if(iface.type==='svi'||iface.type==='loopback'){
    if(iface.ip){
      lines.push(`    ${iface.ip.includes(':')?'ipv6':'ip'} address ${iface.ip}`);
      if(!iface.ip.includes(':')&&secLine)lines.push(secLine);
    }
  }else{
    // 實體埠（含未標示 type 的手動輸入資料，預設視為實體埠）
    if(iface.mode==='routed'&&iface.ip){
      lines.push('    routing');
      lines.push(`    ${iface.ip.includes(':')?'ipv6':'ip'} address ${iface.ip}`);
      if(!iface.ip.includes(':')&&secLine)lines.push(secLine);
    }else if(iface.mode==='trunk'||iface.mode==='access'){
      lines.push('    no routing');
    }
  }
  if(iface.vrf)lines.push(`    vrf attach ${iface.vrf}`);
  const lg=findLacpGroup(lacpList,iface.name);
  // vlan trunk/access（class-two 屬性）：官方 LAG Configuration Guidelines 明講，port 加入
  // LAG 時該 port 上原本的 non-default 設定（含 VLAN）會被自動移除，故 member 實體介面不再
  // 輸出這組屬性，改由 renderArubaLACPExtra() 統一輸出在 lag 介面上
  if(!lg)lines.push(...arubaVlanLines(iface));
  if(lg){
    lines.push(`    lag ${lg.id}`);
    if(lg.mode==='active')lines.push('    lacp mode active');
    else if(lg.mode==='passive')lines.push('    lacp mode passive');
  }
  if(iface.jumbo&&iface.jumbo.enabled&&iface.jumbo.mtu)lines.push(`    mtu ${iface.jumbo.mtu}`);
  if(iface.shutdown)lines.push('    shutdown');
  // OSPF area 指派（2026-07-27 對外查證後修正，見 renderArubaOSPFProcess() 上方註解）：
  // 真實語法是逐 interface `ip ospf <pid> area <area>`，areaOfIface 由 renderArubaInterfaces()
  // 從 model.ospf（Area/Network 表格，Network 欄位重新詮釋為介面名稱）建立一次查詢表傳入
  const aOf=areaOfIface&&areaOfIface[iface.name];
  if(aOf)lines.push(`    ip ospf ${aOf.pid} area ${aOf.area}`);
  findDhcpRelays(dhcpList,iface.name).forEach(rel=>lines.push(`    ip helper-address ${rel.relayServer}`));
  findAclApplications(aclList,iface.name).forEach(ap=>lines.push(`    apply access-list ip ${ap.name} ${ap.direction}`));
  // Port Security/802.1X：已查證官方 HPE Aruba Networking AOS-CX CLI Reference 後修正，
  // 真實語法是全域指令＋interface 參數，非進入 interface 區塊後執行子指令，故移至
  // renderArubaCXSecurity() 獨立頂層區塊輸出，此處不再內嵌
  const sp=findStpForPort(stp,iface.name);
  if(sp){
    if(sp.portfast)lines.push('    spanning-tree port-type admin-edge');
    if(sp.bpduguard)lines.push('    spanning-tree bpdu-guard');
    if(sp.guardRoot)lines.push('    spanning-tree root-guard');
    if(sp.cost)lines.push(`    spanning-tree cost ${sp.cost}`);
    if(sp.priority)lines.push(`    spanning-tree port-priority ${sp.priority}`);
  }
  // PoE 配置（Aruba CX）
  if(iface.poeMode&&iface.poeMode!=='none'){
    const poeStatus=iface.poeMode==='never'?'disable':'enable';
    lines.push(`    power-over-ethernet ${poeStatus}`);
  }
  return lines.join('\n');
}
function renderArubaInterfaces(ifaces,lacpList,dhcpList,aclList,securityList,stp,breakouts,ospf){
  // areaOfIface：interface 名稱 → {pid,area}，比照 renderProCurveVLANs() 的 areaOfVlan 寫法
  // 只建立一次，避免每個介面都重新掃描一次 model.ospf
  const areaOfIface={};
  const proc=ospf&&ospf[0];
  ((proc&&proc.areas)||[]).forEach(a=>{
    (a.networks||[]).forEach(n=>{ if(n.network)areaOfIface[String(n.network)]={pid:proc.pid,area:a.area}; });
  });
  return ifaces.map(i=>renderArubaInterface(i,lacpList,dhcpList,aclList,securityList,stp,breakouts,areaOfIface)).join('\n!\n');
}

// Port Security/802.1X（Aruba CX）：已查證官方 HPE Aruba Networking AOS-CX CLI
// Reference 後新增，真實語法是全域指令＋interface 參數："aaa authentication
// port-access dot1x authenticator enable interface PORT"／"...mac-auth enable
// interface PORT"，非原本假想的 Cisco 風格「進入 interface 區塊後執行 dot1x pae
// authenticator」；port-security client-limit 比照同一個 "port-access" 指令家族類推
// 同樣全域+interface 參數風格（精確巢狀寫法未能取得完整官方逐字範例，已知限制）；
// maxMac 沿用 client-limit 對應；violation/guestVlan 查無對應 AOS-CX 語法不輸出
function renderArubaCXSecurity(securityList){
  const lines=[];
  (securityList||[]).forEach(sec=>{
    if(!sec.port)return;
    if(sec.dot1x==='auth')lines.push(`aaa authentication port-access dot1x authenticator enable interface ${sec.port}`);
    if(sec.portSec)lines.push(`aaa authentication port-access mac-auth enable interface ${sec.port}`);
    if(sec.maxMac&&sec.maxMac!=='-')lines.push(`port-access port-security client-limit ${sec.maxMac} interface ${sec.port}`);
  });
  return lines.join('\n');
}

function renderArubaLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    const aggLines=[`interface lag ${l.id}`,...arubaVlanLines(refIface)];
    blocks.push(aggLines.join('\n'));
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return;
      const lines=[`interface ${mem}`,`    lag ${l.id}`];
      if(l.mode==='active')lines.push('    lacp mode active');
      else if(l.mode==='passive')lines.push('    lacp mode passive');
      blocks.push(lines.join('\n'));
    });
  });
  return blocks.join('\n!\n');
}

function renderArubaVRRPGroup(g){
  const lines=[`interface vlan${g.vlanId}`];
  if(g.ip)lines.push(`    ip address ${g.ip}`);
  g.entries.forEach(v=>{
    lines.push(`    vrrp ${v.vrid} vip ${v.vip}`);
    lines.push(`    vrrp ${v.vrid} priority ${v.priority}`);
    if(v.preempt)lines.push(`    vrrp ${v.vrid} preempt`);
  });
  return lines.join('\n');
}
function renderArubaVRRP(list){return groupVrrpByVlan(list).map(renderArubaVRRPGroup).join('\n!\n');}

function renderArubaOSPFProcess(o){
  // 2026-07-27 對外查證官方 HPE Aruba Lab Guide＋真實 AOS-CX 生產設定檔後修正：
  // router ospf 區塊只有 router-id／area（bare 宣告），不巢狀 network 或 interface；
  // 真正的介面關聯改在 renderArubaInterface() 用 `ip ospf <pid> area <area>` 逐一輸出
  // （見該函式與 renderArubaInterfaces() 的 areaOfIface 查詢表）
  const lines=[`router ospf ${o.pid}`];
  if(o.routerId)lines.push(`    router-id ${o.routerId}`);
  (o.areas||[]).forEach(a=>lines.push(`    area ${a.area}`));
  return lines.join('\n');
}
function renderArubaOSPF(list){return (list||[]).map(renderArubaOSPFProcess).join('\n!\n');}

function renderArubaBGP(b){
  const lines=[`bgp ${b.asn}`];
  if(b.routerId)lines.push(`    router-id ${b.routerId}`);
  (b.peers||[]).forEach(p=>{
    lines.push(`    neighbor ${p.ip} remote-as ${p.as}`);
    if(p.desc)lines.push(`    neighbor ${p.ip} description ${p.desc}`);
  });
  (b.networks||[]).forEach(n=>lines.push(`    network ${n}`));
  return lines.join('\n');
}
function renderArubaBGPList(list){return (list||[]).map(renderArubaBGP).join('\n!\n');}

function renderArubaRIP(r){
  const lines=['router rip'];
  if(r.version)lines.push(`    version ${r.version}`);
  (r.networks||[]).forEach(n=>lines.push(`    network ${n}`));
  (r.redistribute||[]).forEach(x=>lines.push(`    redistribute ${x}`));
  return lines.join('\n');
}
function renderArubaRIPList(list){return (list||[]).map(renderArubaRIP).join('\n!\n');}

function renderArubaRoute(r){return `ip route ${r.dst} ${r.gw}`;}
function renderArubaRoutes(list){return (list||[]).map(renderArubaRoute).join('\n!\n');}

// DHCP server pool；relay（ip helper-address）內嵌進 renderArubaInterface，不在此輸出
function renderArubaDHCPPool(d){
  const lines=[`dhcp-server pool ${d.name}`];
  if(d.network)lines.push(`    network ${d.network}`);
  if(d.gateway)lines.push(`    default-router ${d.gateway}`);
  if(d.dns)lines.push(`    dns-server ${d.dns}`);
  if(d.lease)lines.push(`    lease ${d.lease}`);
  return lines.join('\n');
}
function renderArubaDHCP(list){return (list||[]).filter(d=>d.type==='server').map(renderArubaDHCPPool).join('\n!\n');}

// ACL：access-list ip NAME 區塊；套用（apply access-list）內嵌進 renderArubaInterface。
// 區塊擷取正則以下一個 "access-list "/"interface " 判斷結尾，故需排在 interfaces 之前組裝
function renderArubaACLEntry(a){
  const lines=[`access-list ip ${a.name}`];
  (a.rules||[]).forEach(r=>lines.push(`    ${r.seq||0} ${r.action||'permit'} ${r.protocol||'any'} ${r.src||'any'} ${r.dst||'any'}`));
  return lines.join('\n');
}
function renderArubaACL(list){return (list||[]).map(renderArubaACLEntry).join('\n!\n');}

function assembleArubaConfig(model){
  const blocks=[`! ${tr('notice.disclaimer')}`,`hostname ${model.sysname||'Switch'}`];
  if(model.vlans&&model.vlans.length)blocks.push(renderArubaVLANs(model.vlans,model.vxlan&&model.vxlan.vnis));
  // VRF：官方文件確認 `vrf attach NAME` 要求該 VRF 已用裸 `vrf NAME` 建立，排在
  // Interfaces 之前輸出
  const arubaVrfNames=collectVrfNames(model.interfaces);
  if(arubaVrfNames.length)blocks.push(arubaVrfNames.map(n=>`vrf ${n}`).join('\n!\n'));
  if(model.acl&&model.acl.length)blocks.push(renderArubaACL(model.acl));
  // OSPF：官方文件將「先啟用 OSPF、指派 area」列為建議步驟順序，早於「指派介面到 area」，
  // 排在 Interfaces（內嵌逐介面 `ip ospf <pid> area <area>`）之前輸出
  if(model.ospf&&model.ospf.length)blocks.push(renderArubaOSPF(model.ospf));
  if(model.interfaces&&model.interfaces.length)blocks.push(renderArubaInterfaces(model.interfaces,model.lacp,model.dhcp,model.acl,model.security,model.stp,model.breakouts,model.ospf));
  const arubaLacpExtra=renderArubaLACPExtra(model.lacp,model.interfaces);
  if(arubaLacpExtra)blocks.push(arubaLacpExtra);
  const arSecBlock=renderArubaCXSecurity(model.security);
  if(arSecBlock)blocks.push(arSecBlock);
  if(model.vrrp&&model.vrrp.length)blocks.push(renderArubaVRRP(model.vrrp));
  if(model.dhcp&&model.dhcp.some(d=>d.type==='server'))blocks.push(renderArubaDHCP(model.dhcp));
  const arubaVxlan=renderArubaVXLAN(model.vxlan);
  if(arubaVxlan)blocks.push(arubaVxlan);
  const stpBlockAr=renderSpanningTreeGlobal(model.stp);
  if(stpBlockAr)blocks.push(stpBlockAr);
  if(model.rip&&model.rip.length)blocks.push(renderArubaRIPList(model.rip));
  if(model.routes&&model.routes.length)blocks.push(renderArubaRoutes(model.routes));
  if(model.bgp&&model.bgp.length)blocks.push(renderArubaBGPList(model.bgp));
  // QoS：2026-07-22 對外查證官方 AOS-CX QoS 文件後移除——原本沿用 Cisco 式
  // policy-map/class/police/priority/bandwidth/shape 語法完全捏造，AOS-CX 根本沒有
  // policy-map 這個容器概念，真實模型是 qos queue-profile（8 條佇列）+
  // qos schedule-profile（strict/wfq 排程演算法），與目前共用 QoS 表單（policy/class/
  // action/rate/burst 導向）架構完全不相容，需要全新表單欄位才能正確支援，
  // 本輪先移除捏造輸出不臆測，留待未來規劃 queue-profile/schedule-profile 專屬 UI
  // 本機帳號：沿用 parseArubaUsers() Style B（AOS-CX 新式語法），與 ProCurve「一律輸出新式
  // 語法」慣例一致；密碼欄位固定標記 ciphertext（parser 正則只記錄型別關鍵字，真正雜湊值
  // 落在無名 token 內，不影響 role/name round-trip）
  const arubaUsersBlock=renderArubaUsers(model.users);
  if(arubaUsersBlock)blocks.push(arubaUsersBlock);
  // 結尾補換行：Aruba 語法無 Comware(#)/FortiSwitch(end) 這類收尾關鍵字，
  // 若最後一行缺少換行字元，parseArubaBGP 等以「每行含尾端 \n」為前提的正則會漏抓最後一行內容
  return blocks.join('\n!\n')+'\n';
}
function renderArubaUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>`username ${u.name} password ciphertext ${u.password} role ${u.role||'administrators'}`).join('\n');
}

// ══════════════════════════════════════════════════════════════════
// Cisco IOS/IOS-XE render 函式
// ══════════════════════════════════════════════════════════════════

