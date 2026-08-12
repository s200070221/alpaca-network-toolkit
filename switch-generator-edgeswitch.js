function edgeSwitchVlanLines(iface){
  const lines=[];
  if(!iface)return lines;
  if(iface.mode==='access'&&iface.accessVlan){
    lines.push(` vlan participation include ${iface.accessVlan}`);
    lines.push(` vlan pvid ${iface.accessVlan}`);
  }else if(iface.mode==='trunk'&&iface.trunkVlans){
    const tagged=iface.trunkVlans.split(',').map(v=>v.trim()).filter(Boolean);
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
  // 2026-08-09 對外查證官方 NETGEAR KB（kb.netgear.com/21635，逐字指令稿，EdgeSwitch 與
  // Netgear 同源 ICOS 共用同一套語法）修正：addport 是在 LAG 自己的介面區塊內宣告要加入
  // 的實體成員埠，並非「member 埠自己宣告要加入哪個 LAG」，member port 自己的介面區塊
  // 不應輸出 addport 行；已改在 renderEdgeSwitchLACPExtra() 的 LAG 區塊內輸出
  if(iface.shutdown)lines.push(' shutdown');
  return lines.join('\n');
}
function renderEdgeSwitchInterfaces(ifaces,lacpList){return (ifaces||[]).map(i=>renderEdgeSwitchInterface(i,lacpList)).join('\n!\n');}

// LACP 產生邏輯與 renderNetgearLACPExtra 完全相同（同一套 ICOS addport 語法），
// 獨立複製一份而非共用函式名稱，避免未來任一廠牌語法出現分歧時互相牽動
function renderEdgeSwitchLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const gid=(l.id||'').toString().replace(/^lag\s*/i,'').trim();
    // port-channel static 語法與 Netgear 完全共用（同源 ICOS），先前版本漏接此行，使用者
    // 在表單把 LAG 模式設為 Static 時輸出設定檔完全不反映（2026-08-01 對外查證後修正，
    // 比照 renderNetgearLACPExtra 既有寫法）
    // 2026-08-09 查證官方 KB 逐字指令稿修正：addport 一律輸出在 LAG 自己的區塊內、
    // 每個成員一行，而非先前誤植在各成員埠自己的區塊內
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    const lines=[`interface lag ${gid}`,...edgeSwitchVlanLines(refIface)];
    (l.members||[]).forEach(mem=>lines.push(` addport ${mem}`));
    if(l.mode==='static')lines.push(' port-channel static');
    blocks.push(lines.join('\n'));
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return;
      blocks.push(`interface ${mem}`);
    });
  });
  return blocks.join('\n!\n');
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
