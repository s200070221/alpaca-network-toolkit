function edgeSwitchVlanLines(iface){
  const lines=[];
  if(!iface)return lines;
  if(iface.mode==='access'&&iface.accessVlan){
    lines.push(` vlan participation include ${iface.accessVlan}`);
    lines.push(` vlan pvid ${iface.accessVlan}`);
  }else if(iface.mode==='trunk'&&iface.trunkVlans){
    const tagged=iface.trunkVlans.split(/[,\s]+/).map(v=>v.trim()).filter(Boolean);
    tagged.forEach(v=>{
      lines.push(` vlan participation include ${v}`);
      lines.push(` vlan tagging ${v}`);
    });
    // native/未標記 VLAN：若有指定且不在已標記清單內，額外加入該 VLAN 的未標記成員資格
    if(iface.nativeVlan&&!tagged.includes(iface.nativeVlan)){
      lines.push(` vlan participation include ${iface.nativeVlan}`);
      lines.push(` vlan pvid ${iface.nativeVlan}`);
    }
  }
  return lines;
}
function renderEdgeSwitchInterface(iface,lacpList){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(` description ${iface.desc}`);
  const lg=findLacpGroup(lacpList,iface.name);
  if(!lg)lines.push(...edgeSwitchVlanLines(iface));
  // addport 在成員埠自己的區塊內，參數為 LAG（2026-10-07 再查證修正方向，見 switch-generator-edgeswitch 的 renderEdgeSwitchLACPExtra()）
  if(lg)lines.push(` addport ${edgeSwitchAddportRef(lg)}`);
  if(iface.shutdown)lines.push(' shutdown');
  return lines.join('\n');
}
function renderEdgeSwitchInterfaces(ifaces,lacpList){return (ifaces||[]).map(i=>renderEdgeSwitchInterface(i,lacpList)).join('\n!\n');}

// addport 方向（2026-10-07 再查證修正）：addport 在「成員埠」自己的介面區塊內執行，參數是要加入的 LAG。
// 依據：Ubiquiti 官方說明範例（interface 0/7-0/8 → addport 3/1，再 interface lag 1 設定 VLAN）、FASTPATH 指令參考
// （addport logical unit/slot/port，或 addport lag N）、Netgear 社群（interface 1/0/1-1/0/2 → addport lag 1）與 EFOS 真實錄製。
// Netgear 輸出 addport lag N；EdgeSwitch 依官方範例輸出 addport 3/N；表單填的是實體位址（含 /）時原樣輸出。
// LAG 自己的區塊只放 VLAN 設定與 port-channel static；尚未在介面表格的成員埠補一個含 addport 的區塊。
function edgeSwitchAddportRef(l){
  const gid=(l.id||'').toString().replace(/^lag\s*/i,'').trim();
  return gid.includes('/')?gid:`3/${gid}`;
}
function renderEdgeSwitchLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const gid=(l.id||'').toString().replace(/^lag\s*/i,'').trim();
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    const lines=[gid.includes('/')?`interface ${gid}`:`interface lag ${gid}`,...edgeSwitchVlanLines(refIface)];
    if(l.mode==='static')lines.push(' port-channel static');
    blocks.push(lines.join('\n'));
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return;
      blocks.push(`interface ${mem}\n addport ${edgeSwitchAddportRef(l)}`);
    });
  });
  return blocks.join('\n!\n');
}

// 本機帳號（2026-08-23 新增）：官方 EdgeSwitch Command Reference Manual 逐字確認的單行語法；
// 與 Netgear renderNetgearUsers() 邏輯完全相同，但比照本檔既有慣例（LACP 已獨立複製）
// 不共用函式
function renderEdgeSwitchUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>{
    const m=/^level-(\d+)$/.exec(u.role||'');
    const level=m?m[1]:'15';
    return `username ${u.name} password ${u.password} level ${level}`;
  }).join('\n');
}
function assembleEdgeSwitchConfig(model){
  // 真實 EdgeSwitch "show running-config" 表頭固定含 "!Current Configuration:"（與 Netgear
  // 同源 ICOS 共用），switch_analyzer 的 detectVendor() 靠內文含 "vlan participation
  // include/exclude/auto" 關鍵字（Netgear 官方文件從未出現此關鍵字，用以區分兩者）判定，
  // 缺這行會導致 round-trip 時無法被自動辨識為 edgeswitch
  const blocks=[`! ${tr('notice.disclaimer')}`,'!Current Configuration:\n!\n!System Description "UBNT EdgeSwitch 24-250W"',`snmp-server sysname ${model.sysname||'Switch'}`];
  if(model.vlans&&model.vlans.length){
    const vlanLines=['vlan database'];
    model.vlans.forEach(v=>vlanLines.push(`vlan ${v.id}`));
    vlanLines.push('exit');
    model.vlans.filter(v=>v.name).forEach(v=>vlanLines.push(`vlan name ${v.id} "${v.name}"`));
    blocks.push(vlanLines.join('\n'));
  }
  if(model.interfaces&&model.interfaces.length)blocks.push(renderEdgeSwitchInterfaces(model.interfaces,model.lacp));
  const lacpExtra=renderEdgeSwitchLACPExtra(model.lacp,model.interfaces);
  if(lacpExtra)blocks.push(lacpExtra);
  const usersBlockEs=renderEdgeSwitchUsers(model.users);
  if(usersBlockEs)blocks.push(usersBlockEs);
  return blocks.join('\n!\n')+'\n';
}

// ══════════════════════════════════════════════════════════════════
// Brocade/Ruckus ICX (FastIron) render 函式（2026-07-14 新增第 9 個廠牌）
// switch_analyzer parser 範圍：VLAN(`vlan N by port` + tagged/untagged)/
// Interface(access/trunk，trunk 的 nativeVlan 對應 dual-mode，無 hybrid)/
// LACP(`lag "NAME" dynamic|static id N` + `ports ethe ...`)/
// VRRP-E(`router vrrp-extended` 全域 + `interface ve N` 底下
// `ip vrrp-extended vrid N`)/OSPF(逐介面 `ip ospf area A.B.C.D` 指派，非
// Cisco 式 network+wildcard)/BGP(ASN 用獨立 `local-as N` 指令，非
// `router bgp N`)/靜態路由/DHCP server pool/ACL。皆已對外查證 Ruckus 官方
// FastIron 文件（Layer 2 Switching／Layer 3 Routing／Security Configuration
// Guide、Command Reference）；OSPF/BGP 語法在查證時發現 switch_analyzer 原本
// 套用未經查證的 Cisco 式假設語法，已同步修正 parseBrocadeOSPF/parseBrocadeBGP
// （見該函式上方註解與 now.md 2026-07-14 段落）。
// RIP／QoS／Port Security-802.1X／STP 已於後續批次對外查證官方 FastIron 文件並補上
// （見 renderBrocadeRIPGlobal()／renderBrocadeQoSGlobal()／renderBrocadeAuthGlobal()／
// renderBrocadeSTP() 各處註解與 now.md 對應段落），此段落原本「本輪不產生」的敘述已過時，
// 僅保留作為 Brocade 廠牌整體範圍的歷史說明。
// ══════════════════════════════════════════════════════════════════

// interfaces 表格內 iface.name 慣例存純埠號（如 "1/1/1"），去掉使用者可能誤填的
// e/ethe/ethernet 前綴，統一供 vlan-by-port 與 interface 區塊共用
