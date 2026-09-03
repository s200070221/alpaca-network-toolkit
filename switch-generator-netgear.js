function netgearSwitchportLines(iface){
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
function renderNetgearInterface(iface,lacpList){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(` description ${iface.desc}`);
  const lg=findLacpGroup(lacpList,iface.name);
  if(!lg)lines.push(...netgearSwitchportLines(iface));
  // 官方 KB（kb.netgear.com/21969，逐字指令稿）確認 IPv6 需先 `ipv6 enable` 再 `ipv6 address
  // ADDR/PREFIXLEN`（直出完整 CIDR，不像 IPv4 需要 maskFromCidr() 換算雙 token 遮罩）
  if(iface.type==='svi'){
    if(iface.ip){
      lines.push(' routing');
      if(iface.ip.includes(':')){ lines.push(' ipv6 enable'); lines.push(` ipv6 address ${iface.ip}`); }
      else{ const [ip,len]=iface.ip.split('/'); lines.push(` ip address ${ip} ${maskFromCidr(len)}`); }
    }
  }else if(iface.type==='loopback'){
    if(iface.ip){
      if(iface.ip.includes(':')){ lines.push(' ipv6 enable'); lines.push(` ipv6 address ${iface.ip}`); }
      else{ const [ip,len]=iface.ip.includes('/')?iface.ip.split('/'):[iface.ip,'32']; lines.push(` ip address ${ip} ${maskFromCidr(len)}`); }
    }
  }else if(iface.mode==='routed'&&iface.ip){
    lines.push(' routing');
    if(iface.ip.includes(':')){ lines.push(' ipv6 enable'); lines.push(` ipv6 address ${iface.ip}`); }
    else{ const [ip,len]=iface.ip.split('/'); lines.push(` ip address ${ip} ${maskFromCidr(len)}`); }
  }
  // 2026-08-09 對外查證官方 NETGEAR KB（kb.netgear.com/21635，逐字指令稿）修正：addport
  // 是在 LAG 自己的介面區塊內宣告要加入的實體成員埠，並非「member 埠自己宣告要加入哪個
  // LAG」，故 member port 自己的介面區塊不應輸出 addport 行；已改在 renderNetgearLACPExtra()
  // 的 LAG 區塊內輸出，見該函式說明
  if(iface.shutdown)lines.push(' shutdown');
  return lines.join('\n');
}
function renderNetgearInterfaces(ifaces,lacpList){return (ifaces||[]).map(i=>renderNetgearInterface(i,lacpList)).join('\n!\n');}

function renderNetgearLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const gid=(l.id||'').toString().replace(/^lag\s*/i,'').trim();
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    // 2026-08-09 查證官方 KB 逐字指令稿（"interface 0/2" → "addport 1/1" → "exit"）修正：
    // addport 一律輸出在 LAG 自己的區塊內、每個成員一行，而非先前誤植在各成員埠自己的
    // 區塊內；member port 若尚未在 model.interfaces 有自己的顯式區塊，仍補一個空區塊
    // 確保該埠存在，但不再輸出 addport
    // gid 含 "/" 代表官方 KB 範例本身示範的 unit/slot/port 原始位址格式（如 "0/2"），與
    // "lag N" 別名是平行、互斥的兩種定址方式，原始位址本身不帶 "lag" 關鍵字（2026-09-02
    // 全功能審查發現：先前無條件輸出 "interface lag {gid}"，官方範例格式會產生真機無效
    // 語法 "interface lag 0/2"）
    const lines=[gid.includes('/')?`interface ${gid}`:`interface lag ${gid}`,...netgearSwitchportLines(refIface)];
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

function renderNetgearVRRPGroup(g){
  const lines=[`interface vlan ${g.vlanId}`];
  if(g.ip){
    const [ip,len]=g.ip.split('/');
    lines.push(' routing');
    lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
  }
  g.entries.forEach(v=>{
    lines.push(` ip vrrp ${v.vrid}`);
    lines.push(` ip vrrp ${v.vrid} mode`);
    if(v.vip)lines.push(` ip vrrp ${v.vrid} ip ${v.vip}`);
    if(v.priority)lines.push(` ip vrrp ${v.vrid} priority ${v.priority}`);
    // preempt 官方預設值為 enabled（比照既有 Arista/Extreme「預設開啟」分支慣例），
    // 顯式關閉需輸出 "no ip vrrp N preempt"，否則貼到真機上仍會維持預設的搶占行為
    // （2026-08-01 對外查證後修正，先前版本 preempt=false 時完全不輸出任何指令）
    if(v.preempt===false)lines.push(` no ip vrrp ${v.vrid} preempt`);
    else if(v.preempt)lines.push(` ip vrrp ${v.vrid} preempt`);
  });
  return lines.join('\n');
}
function renderNetgearVRRP(list){return groupVrrpByVlan(list).map(renderNetgearVRRPGroup).join('\n!\n');}

function renderNetgearOSPFProcess(o){
  const lines=['router ospf'];
  if(o.routerId)lines.push(` router-id ${o.routerId}`);
  (o.areas||[]).forEach(a=>{
    (a.networks||[]).forEach(n=>lines.push(` network ${n.network} ${n.wildcard} area ${a.area}`));
  });
  lines.push('exit');
  return lines.join('\n');
}
function renderNetgearOSPF(list){return (list||[]).map(renderNetgearOSPFProcess).join('\n!\n');}

function renderNetgearRIP(rip){return (rip&&rip.length)?'router rip\nexit':'';}

function renderNetgearRoute(r){
  const [net,len]=r.dst.split('/');
  const mask=maskFromCidr(len);
  const nh=r.gwIsInterface?`interface ${r.gw}`:r.gw;
  return `ip route ${net} ${mask} ${nh}`;
}
function renderNetgearRoutes(list){return (list||[]).map(renderNetgearRoute).join('\n');}

// 本機帳號（2026-08-23 新增）：switch_analyzer 的 parseNetgearUsers() 對應官方 EdgeSwitch
// Command Reference Manual 逐字確認的單行語法（Netgear 同源 ICOS，中信心度）；role 若是
// 'level-N' 合成字串則還原成數字層級，否則預設 15（讀寫）
function renderNetgearUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>{
    const m=/^level-(\d+)$/.exec(u.role||'');
    const level=m?m[1]:'15';
    return `username ${u.name} password ${u.password} level ${level}`;
  }).join('\n');
}
function assembleNetgearConfig(model){
  // 真實 M4300 "show running-config" 表頭固定含 "!Current Configuration:"，switch_analyzer
  // 的 detectVendor() 以此表頭 + 內文含 "NETGEAR"/"M4300" 字樣組合判定，缺這兩行會導致
  // round-trip 時無法被自動辨識為 netgear（比照既有 Ruijie/Arista 版本註解行慣例）
  const blocks=[`! ${tr('notice.disclaimer')}`,'!Current Configuration:\n!\n!System Description "NETGEAR M4300-28G"',`snmp-server sysname ${model.sysname||'Switch'}`];
  if(model.vlans&&model.vlans.length){
    const vlanLines=['vlan database'];
    model.vlans.forEach(v=>vlanLines.push(`vlan ${v.id}`));
    vlanLines.push('exit');
    model.vlans.filter(v=>v.name).forEach(v=>vlanLines.push(`vlan name ${v.id} ${v.name}`));
    blocks.push(vlanLines.join('\n'));
  }
  if(model.interfaces&&model.interfaces.length)blocks.push(renderNetgearInterfaces(model.interfaces,model.lacp));
  const lacpExtra=renderNetgearLACPExtra(model.lacp,model.interfaces);
  if(lacpExtra)blocks.push(lacpExtra);
  if(model.vrrp&&model.vrrp.length){
    // "ip vrrp"（無參數，Global Config）為 VRRP 全域啟用開關，官方手冊明確要求需開啟
    // 才會生效，先前版本從未輸出這行（2026-08-01 對外查證後修正）
    blocks.push('ip vrrp');
    blocks.push(renderNetgearVRRP(model.vrrp));
  }
  const ospfBlock=renderNetgearOSPF(model.ospf);
  if(ospfBlock)blocks.push(ospfBlock);
  const ripBlock=renderNetgearRIP(model.rip);
  if(ripBlock)blocks.push(ripBlock);
  if(model.routes&&model.routes.length)blocks.push(renderNetgearRoutes(model.routes));
  const stpBlockNg=renderSpanningTreeGlobal(model.stp);
  if(stpBlockNg)blocks.push(stpBlockNg);
  const usersBlockNg=renderNetgearUsers(model.users);
  if(usersBlockNg)blocks.push(usersBlockNg);
  return blocks.join('\n!\n')+'\n';
}

// ══════════════════════════════════════════════════════════════════
// Ubiquiti EdgeSwitch（舊款 ES-XX／EdgeSwitch X 系列，Broadcom ICOS）render 函式
// （2026-07-30 新增第 16 個廠牌）。switch_analyzer parser 範圍：VLAN(vlan database)/
// Interface(vlan participation include/tagging/pvid，原生 ICOS 語系，無 Netgear 那組
// switchport 相容別名；每個指令一次只接受一個 VLAN ID，官方查證確認不支援逗號清單，
// 故逐 VLAN 各自輸出一行)/LACP(addport lag N，與 Netgear 完全共用同一套語法與 render
// 函式)。**不支援 OSPF/RIP/BGP/VRRP/靜態路由/DHCP/STP/ACL/QoS**——並非查證不足，而是
// EdgeSwitch 的 VLAN Routing 邏輯介面 ID（如 3/1、4/1）由裝置依啟用順序動態配置產生，
// 必須連線裝置執行 show ip vlan 才能得知實際值，本工具的靜態設定檔產生模式無法可靠
// 預測或還原此 ID，故所有依賴可定址 L3 介面的功能一律不支援；STP 為官方 MST instance
// 模型（spanning-tree mst instance N + spanning-tree mst vlan N M 關聯），與本工具其餘
// 廠牌共用的扁平 STP 資料形狀不相容，本輪不實作。
// vlan participation/tagging/pvid（VLAN 屬性）render，EdgeSwitch 專用；抽成獨立函式供
// renderEdgeSwitchInterface() 與 renderEdgeSwitchLACPExtra() 共用。屬性不一致時不會擋設定
// 匯入，但該實體埠會被判定 suspended 排除在聚合之外；為確保「能夠成功聚合」，member port
// 一律不輸出這組屬性，改由 renderEdgeSwitchLACPExtra() 統一輸出在 lag 介面上
