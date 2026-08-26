// ══════════════════════════════════════════════════════════════════
// Planet Technology SGS-6341 系列 render 函式（第 18 個廠牌）
// switch_analyzer parser 範圍：Hostname／VLAN（`vlan WORD`，無 name 概念）／
// Interface(access/trunk/hybrid，hybrid 用 tag/untag 後綴語法)／OSPF（CIDR+wildcard
// 皆支援）／BGP（network 恆為 CIDR）／靜態路由／LACP（port-channel + port-group N
// mode active/passive/on）／VRRP（全域 "router vrrp N" 實例，非巢狀在 interface
// 區塊內）／802.1X+MAC port-security。ACL/QoS/STP/DHCP/Users 本輪未查證不實作。
// 官方 SGS-6341 Series Command Guide 直接 fetch 逐字查證。

// VLAN WORD 壓縮：與 Ruijie/Comware 慣用的逗號分隔不同，Planet 用分號分隔多筆、
// 連字號表示範圍（如 "3;5-7;8"），供 hybrid tag/untag 清單輸出使用
function compressPlanetVlanList(ids){
  const nums=[...new Set((ids||[]).map(Number))].filter(n=>!isNaN(n)).sort((a,b)=>a-b);
  const ranges=[]; let start=null,prev=null;
  nums.forEach(n=>{
    if(start===null){start=n;prev=n;return;}
    if(n===prev+1){prev=n;return;}
    ranges.push(start===prev?String(start):`${start}-${prev}`);
    start=n;prev=n;
  });
  if(start!==null)ranges.push(start===prev?String(start):`${start}-${prev}`);
  return ranges.join(';');
}

// VLAN：官方查證範圍內查無對應的 VLAN 命名（name）指令，故僅逐一輸出 "vlan <id>"
// 宣告行（不輸出 name，避免產生無佐證語法）
function renderPlanetVLANs(vlans){
  return (vlans||[]).map(v=>`vlan ${v.id}`).join('\n');
}

// switchport trunk/access/hybrid（VLAN 屬性）render，抽成獨立函式供
// renderPlanetInterface() 與 renderPlanetLACPExtra() 共用。屬性不一致時不會擋設定
// 匯入，但該實體埠會被判定 suspended 排除在聚合之外；為確保「能夠成功聚合」，member
// port 一律不輸出這組屬性，改由 renderPlanetLACPExtra() 統一輸出在 port-channel 介面上
function planetSwitchportLines(iface){
  const lines=[];
  if(!iface)return lines;
  if(iface.mode==='trunk'){
    lines.push(' switchport mode trunk');
    if(iface.trunkVlans)lines.push(` switchport trunk allowed vlan ${iface.trunkVlans}`);
    if(iface.nativeVlan)lines.push(` switchport trunk native vlan ${iface.nativeVlan}`);
  }else if(iface.mode==='access'){
    lines.push(' switchport mode access');
    if(iface.accessVlan)lines.push(` switchport access vlan ${iface.accessVlan}`);
  }else if(iface.mode==='hybrid'){
    lines.push(' switchport mode hybrid');
    const h=iface.hybrid||{};
    if(h.pvid)lines.push(` switchport hybrid native vlan ${h.pvid}`);
    // tag/untag 關鍵字在 WORD 之後（官方語法固定順序，與 Ruijie 的 tagged/untagged
    // 前綴語法相反），不可比照 Ruijie render 沿用前綴寫法
    if(h.untagged&&h.untagged.length)lines.push(` switchport hybrid allowed vlan ${compressPlanetVlanList(h.untagged)} untag`);
    if(h.tagged&&h.tagged.length)lines.push(` switchport hybrid allowed vlan ${compressPlanetVlanList(h.tagged)} tag`);
  }
  return lines;
}

// Security：802.1X（dot1x port-control auto／dot1x guest-vlan）+ MAC port-security
// （switchport mac-address dynamic maximum／switchport mac-address violation），
// 與其餘廠牌慣用的 "port-security"/"mac-learn limit" 關鍵字皆不同
function planetSecurityLines(sec){
  const lines=[];
  if(!sec)return lines;
  if(sec.dot1x==='auth'){
    lines.push(' dot1x port-control auto');
    if(sec.guestVlan&&sec.guestVlan!=='-')lines.push(` dot1x guest-vlan ${sec.guestVlan}`);
  }
  if(sec.portSec){
    if(sec.maxMac&&sec.maxMac!=='-')lines.push(` switchport mac-address dynamic maximum ${sec.maxMac}`);
    if(sec.violation&&sec.violation!=='-')lines.push(` switchport mac-address violation ${sec.violation}`);
  }
  return lines;
}

function renderPlanetInterface(iface,lacpList,securityList){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(` description ${iface.desc}`);
  if(iface.type==='svi'){
    if(iface.ip){
      const [ip,len]=iface.ip.split('/');
      lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
    }
    // Secondary IP：官方語法原生支援 `secondary` 關鍵字，完整輸出整個陣列（非僅第一筆）
    (iface.secondaryIps||[]).forEach(s=>{
      const [ip,len]=s.split('/');
      lines.push(` ip address ${ip} ${maskFromCidr(len)} secondary`);
    });
  }else{
    const lg=findLacpGroup(lacpList,iface.name);
    if(!lg)lines.push(...planetSwitchportLines(iface));
    if(lg){
      const modeWord=lg.mode==='passive'?'passive':lg.mode==='static'?'on':'active';
      lines.push(` port-group ${lg.id} mode ${modeWord}`);
    }
    const sec=findSecurityForPort(securityList,iface.name);
    planetSecurityLines(sec).forEach(l=>lines.push(l));
  }
  if(iface.shutdown)lines.push(' shutdown');
  return lines.join('\n');
}
function renderPlanetInterfaces(ifaces,lacpList,securityList){
  return (ifaces||[]).map(i=>renderPlanetInterface(i,lacpList,securityList)).join('\n!\n');
}

// LACP：聚合介面稱為 "port-channel N"（非 Ruijie 的 AggregatePort），成員埠語法
// "port-group N mode {active|passive|on}"（on=靜態聚合，非 LACP 協商）
function renderPlanetLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    blocks.push([`interface port-channel ${l.id}`,...planetSwitchportLines(refIface)].join('\n'));
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return;
      const modeWord=l.mode==='passive'?'passive':l.mode==='static'?'on':'active';
      blocks.push(`interface ${mem}\n port-group ${l.id} mode ${modeWord}`);
    });
  });
  return blocks.join('\n!\n');
}

// VRRP：全域實例模式，與其餘廠牌「巢狀在 interface 區塊內」完全不同架構——
// `router vrrp <vrid>` 先建立全域虛擬路由器，子模式內用 `interface Vlan <ID>` 綁定，
// SVI 自己的 ip address 屬於該介面自己的區塊，與 VRRP 區塊分開輸出（比照官方語法，
// 非與 Ruijie/Netgear 等其餘廠牌合併進同一區塊）
function renderPlanetVRRPGroup(g){
  const blocks=[];
  if(g.ip){
    const [ip,len]=g.ip.split('/');
    blocks.push(`interface vlan ${g.vlanId}\n ip address ${ip} ${maskFromCidr(len)}`);
  }
  g.entries.forEach(v=>{
    const lines=[`router vrrp ${v.vrid}`,` interface vlan ${g.vlanId}`];
    if(v.vip)lines.push(` virtual-ip ${v.vip}`);
    if(v.priority)lines.push(` priority ${v.priority}`);
    lines.push(` preempt-mode ${v.preempt===false?'false':'true'}`);
    blocks.push(lines.join('\n'));
  });
  return blocks.join('\n!\n');
}
function renderPlanetVRRP(list){return groupVrrpByVlan(list).map(renderPlanetVRRPGroup).join('\n!\n');}

// OSPF：`router ospf <process_id>`（vrf-name 選填，本工具表單無對應欄位不輸出）；
// `ospf router-id <address>`（關鍵字為 "ospf router-id"，非 Cisco 的裸 "router-id"）；
// network 統一輸出 wildcard 形式（與共用 area.networks {network,wildcard} 欄位形狀
// 一致，官方語法亦支援此寫法）
function renderPlanetOSPFProcess(o){
  const lines=[`router ospf ${o.pid}`];
  if(o.routerId)lines.push(` ospf router-id ${o.routerId}`);
  (o.areas||[]).forEach(a=>{
    (a.networks||[]).forEach(n=>lines.push(` network ${n.network} ${n.wildcard} area ${a.area}`));
  });
  return lines.join('\n');
}
function renderPlanetOSPF(list){return (list||[]).map(renderPlanetOSPFProcess).join('\n!\n');}

// BGP：network 一律是 CIDR 單一 token（與 Cisco 的「network + 選填 dotted mask」不同，
// 不可重用 renderCiscoBGP）；官方查證範圍內查無 router-id 對應指令，不輸出
function renderPlanetBGP(b){
  const lines=[`router bgp ${b.asn}`];
  (b.peers||[]).forEach(p=>{
    lines.push(` neighbor ${p.ip} remote-as ${p.as}`);
    if(p.desc)lines.push(` neighbor ${p.ip} description ${p.desc}`);
  });
  (b.networks||[]).forEach(n=>lines.push(` network ${n}`));
  return lines.join('\n');
}
function renderPlanetBGPList(list){return (list||[]).map(renderPlanetBGP).join('\n!\n');}

// 靜態路由：統一輸出「prefix + dotted mask + gateway」形式（官方語法亦支援 CIDR 單
// token 形式，但 dotted mask 形式與其餘廠牌 renderXxxRoute 慣例一致，便於閱讀）
function renderPlanetRoute(r){
  const [net,len]=r.dst.split('/');
  return `ip route ${net} ${maskFromCidr(len)} ${r.gw}`;
}
function renderPlanetRoutes(list){return (list||[]).map(renderPlanetRoute).join('\n');}

function assemblePlanetConfig(model){
  const blocks=[`! ${tr('notice.disclaimer')}`,`hostname ${model.sysname||'Switch'}`];
  const vlanBlock=renderPlanetVLANs(model.vlans);
  if(vlanBlock)blocks.push(vlanBlock);
  if(model.interfaces&&model.interfaces.length)blocks.push(renderPlanetInterfaces(model.interfaces,model.lacp,model.security));
  const lacpExtra=renderPlanetLACPExtra(model.lacp,model.interfaces);
  if(lacpExtra)blocks.push(lacpExtra);
  if(model.vrrp&&model.vrrp.length)blocks.push(renderPlanetVRRP(model.vrrp));
  if(model.ospf&&model.ospf.length)blocks.push(renderPlanetOSPF(model.ospf));
  if(model.routes&&model.routes.length)blocks.push(renderPlanetRoutes(model.routes));
  if(model.bgp&&model.bgp.length)blocks.push(renderPlanetBGPList(model.bgp));
  return blocks.join('\n!\n')+'\n';
}
