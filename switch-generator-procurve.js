function renderProCurveVLANs(vlans,interfaces,ospf,dhcp){
  const taggedMap={},untaggedMap={};
  (interfaces||[]).forEach(iface=>{
    if(!iface.name)return;
    if(iface.mode==='trunk'){
      (iface.trunkVlans||'').split(',').map(s=>s.trim()).filter(Boolean).forEach(vid=>{
        if(!taggedMap[vid])taggedMap[vid]=[];
        taggedMap[vid].push(iface.name);
      });
    }else if(iface.mode==='access'&&iface.accessVlan){
      if(!untaggedMap[iface.accessVlan])untaggedMap[iface.accessVlan]=[];
      untaggedMap[iface.accessVlan].push(iface.name);
    }
  });
  const areaOfVlan={};
  ((ospf&&ospf[0]&&ospf[0].areas)||[]).forEach(a=>{
    (a.networks||[]).forEach(n=>{ if(n.network)areaOfVlan[String(n.network)]=a.area; });
  });
  const helperOfVlan={};
  (dhcp||[]).filter(d=>d.type==='relay'&&d.interface&&d.relayServer).forEach(d=>{
    const vid=String(d.interface).replace(/^vlan/i,'');
    if(!helperOfVlan[vid])helperOfVlan[vid]=[];
    helperOfVlan[vid].push(d.relayServer);
  });
  return (vlans||[]).map(v=>{
    const lines=[`vlan ${v.id}`];
    if(v.name)lines.push(`   name "${v.name}"`);
    const untagged=untaggedMap[String(v.id)]||[];
    const tagged=taggedMap[String(v.id)]||[];
    if(untagged.length)lines.push(`   untagged ${untagged.join(',')}`);
    if(tagged.length)lines.push(`   tagged ${tagged.join(',')}`);
    // IP（2026-08-12 補上，既有缺口——parseVlans() 早就解析 v.ip，但 renderProCurveVLANs()
    // 從未輸出過；v.ip 存的是 parser 端原樣擷取的「IP/遮罩」字串（斜線分隔但非真正 CIDR
    // prefix，因 ProCurve CLI 本身就是雙 token dotted-mask 語法），直接還原成兩個 token 輸出）
    if(v.ip){
      const [vip,vmask]=v.ip.split('/');
      if(vip&&vmask)lines.push(`   ip address ${vip} ${vmask}`);
    }
    // 次要IP（2026-08-12 新增）：ProCurve 無 secondary 關鍵字，同一 VLAN 底下再宣告一行
    // ip address（不同子網）即為次要位址，僅取第一筆為 MVP 範圍
    if(v.secondaryIp){
      const [sip,smask]=v.secondaryIp.split('/');
      if(sip&&smask)lines.push(`   ip address ${sip} ${smask}`);
    }
    if(areaOfVlan[String(v.id)])lines.push(`   ip ospf area ${areaOfVlan[String(v.id)]}`);
    (helperOfVlan[String(v.id)]||[]).forEach(ip=>lines.push(`   ip helper-address ${ip}`));
    lines.push('   exit');
    return lines.join('\n');
  }).join('\n');
}
// Option82：2026-07-24 對外查證官方 AOS-S CLI Reference 確認為全域指令
// "dhcp-relay option 82"（非逐 VLAN），只要任一 relay 列勾選就輸出一次
function renderProCurveDHCPOption82(dhcp){
  return (dhcp||[]).some(d=>d.type==='relay'&&d.option82)?'dhcp-relay option 82':'';
}

function renderProCurveInterface(iface){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(`   name "${iface.desc}"`);
  if(iface.shutdown)lines.push('   disable');
  lines.push('   exit');
  return lines.join('\n');
}
function renderProCurveInterfaces(ifaces){return (ifaces||[]).map(renderProCurveInterface).join('\n');}

// 真實語法第三個 token 只有 lacp/trunk 兩種字面值（parseTrunk() 對應把 lacp 收斂回
// 'Active'、trunk 收斂回 'Static'），故 UI 的 active/passive 兩種 mode 在輸出端
// 都對應同一個 lacp 關鍵字，屬既有解析行為的既有資訊損失，非本次新增
function renderProCurveLACPGroup(l){
  const mode=l.mode==='static'?'trunk':'lacp';
  const members=(l.members||[]).filter(Boolean);
  return `trunk ${members.join(',')} Trk${l.id} ${mode}`;
}
function renderProCurveLACP(list){return (list||[]).map(renderProCurveLACPGroup).join('\n');}

// 2026-07-22 對外查證官方 arubanetworking.hpe.com 文件後新增：ArubaOS-Switch 的
// `ip route` 支援選填 `metric <n>` 子句（與 `distance <n>` 為各自獨立的選填關鍵字），
// 解析器（parseRoutes() 的 ProCurve 分支）本來就讀得到 metric，但先前產生器完全沒有
// 輸出，造成單向資料遺失；改用獨立函式而非直接沿用共用的 renderArubaRoute()，因為
// 這是 ArubaOS-Switch 專屬查證結果，Aruba CX／Dell OS10／Brocade 尚未查證是否支援同一
// 語法，不應貿然套用到其他共用此函式的廠牌
function renderProCurveRoute(r){
  const base=`ip route ${r.dst} ${r.gw}`;
  return r.metric&&r.metric!=='1'?`${base} metric ${r.metric}`:base;
}
function renderProCurveRoutes(list){return (list||[]).map(renderProCurveRoute).join('\n');}

function renderProCurveOSPFGlobal(list){
  const o=(list||[])[0];
  if(!o)return '';
  const lines=['router ospf'];
  if(o.routerId)lines.push(`   router-id ${o.routerId}`);
  lines.push('exit');
  return lines.join('\n');
}

// 本機帳號：switch_analyzer 的 parseUsers()（ProCurve 分支）支援兩種真實並存語法，
// 產生器一律輸出新式 AAA 語法（group 欄位可接受任意名稱，彈性優於舊式語法僅能是
// operator/manager 字面值，且仍可被 parseUsers() 的 reAAA 正則完整往返解析）。
// 密碼固定是 SHA1 雜湊值，本工具不做任何加密運算，使用者需自行貼上已產生的雜湊字串
function renderProCurveUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>`aaa authentication local-user "${u.name}" group "${u.role||'operator'}" password sha1 "${u.password}"`).join('\n');
}
function assembleProCurveConfig(model){
  const blocks=[`; ${tr('notice.disclaimer')}`,`hostname "${model.sysname||'Switch'}"`];
  // OSPF：官方文件將「先啟用 OSPF」列為建議步驟順序，早於「指派介面到 area」，排在
  // VLAN 區塊（內嵌逐 VLAN `ip ospf area`）之前輸出
  const ospfBlockPC=renderProCurveOSPFGlobal(model.ospf);
  if(ospfBlockPC)blocks.push(ospfBlockPC);
  const vlanBlock=renderProCurveVLANs(model.vlans,model.interfaces,model.ospf,model.dhcp);
  if(vlanBlock)blocks.push(vlanBlock);
  const lacpBlock=renderProCurveLACP(model.lacp);
  if(lacpBlock)blocks.push(lacpBlock);
  if(model.interfaces&&model.interfaces.length)blocks.push(renderProCurveInterfaces(model.interfaces));
  if(model.routes&&model.routes.length)blocks.push(renderProCurveRoutes(model.routes));
  const dhcpOpt82BlockPC=renderProCurveDHCPOption82(model.dhcp);
  if(dhcpOpt82BlockPC)blocks.push(dhcpOpt82BlockPC);
  const usersBlock=renderProCurveUsers(model.users);
  if(usersBlock)blocks.push(usersBlock);
  if(model.snmpTrapHost)blocks.push(`snmp-server host ${model.snmpTrapHost} "public"`);
  return blocks.join('\n')+'\n';
}

// ══════════════════════════════════════════════════════════════════
// MikroTik RouterOS render 函式（switch_analyzer parser 範圍：Hostname／VLAN(bridge VLAN
// filtering table，membership 以 VLAN 為主體宣告 tagged/untagged port 清單，2026-07-15 已
// 修正 switch_analyzer 既有 parseRouterOSVLANs() 要求 tagged= 必填的 bug 並補上 VLAN
// membership 反查 interfaces[].mode/vlans)／Interface(access/trunk，無 hybrid，一律宣告在
// /interface ethernet 底下)／LACP(`/interface bonding` + slaves= 逗號清單，2026-07-15 查證
// 修正 switch_analyzer 原本誤寫的 `/interface bond` 選單路徑錯誤，該路徑真實設備完全不存在)／
// 靜態路由／OSPF(`/routing ospf instance`+`area`+`interface-template`，router-id 是 instance
// 屬性)／BGP(`/routing bgp instance`+`connection`，peer 位址/AS 用點號參數 remote.address/
// remote.as，非其餘廠牌慣用的連字號)／DHCP(僅 name+interface，parseRouterOSDHCP 不解析
// pool range)／STP(`/interface bridge` 本身的 protocol-mode/priority 屬性，priority 用十六
// 進位)。VLAN filtering 需要橋接器存在，固定使用 bridge1 作為橋接器名稱（表單無此欄位）。
// 不含 RIP/VRRP/Users/ACL/QoS/Security（switch_analyzer 尚無對應解析）。
// 查證來源：help.mikrotik.com 官方文件（Bonding／routing ospf／routing bgp／Spanning Tree
// Protocol／Bridge 各頁），詳見 now.md 對應段落。
// ══════════════════════════════════════════════════════════════════

