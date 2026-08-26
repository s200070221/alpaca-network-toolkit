// ══════════════════════════════════════════════════════════════════
// Extreme Networks ExtremeXOS (EXOS) render 函式（第 11 個廠牌，MVP 範圍）
//
// 語法已於 2026-07-15 對外查證 Extreme Networks 官方 ExtremeXOS Command Reference
// 並與 switch_analyzer 既有 parseExtremeXOS() 系列函式核對，過程中發現並修正兩處
// switch_analyzer 既有 bug（原本沿用未經查證的假設語法）：
//   1. BGP neighbor 建立指令實際是 "create bgp neighbor IP remote-AS-number N"
//      （動詞 create，原本誤寫成 "configure bgp add neighbor"）
//   2. VRRP preempt 是旗標式關鍵字 "preempt"/"dont-preempt"，原本誤寫成
//      "preempt on|off" 帶值語法
// 詳見 parseExtremeXOSBGP()/parseExtremeXOSVRRP() 修正處與 now.md 對應紀錄。
//
// 範圍：Hostname／VLAN／Interface(access/trunk，無 hybrid，membership 以 VLAN 為主體
// 宣告成員 port，語法為 "configure vlan NAME add ports P tagged/untagged"，與 Cisco 式
// interface 區塊完全不同)／OSPF(逐 vlan area 指派)／BGP／靜態路由／LACP／VRRP／DHCP
// （parseExtremeXOSDHCP() 已查證 server+relay 語法，此前 assemble 端未接線，已於後續
// 修正補上，見 renderExtremeDHCP()）／STP／Security(802.1X+MAC NetLogin)／QoS(QP1-QP8
// profile 模型，2026-07-19 對外查證新增，詳見 renderExtremeSTP()/renderExtremeSecurity()/
// renderExtremeQoS() 各處註解)／ACL render（已接線，見 renderExtremeACL()）。不含 RIP
// （switch_analyzer 尚無對應解析）；無匯入既有設定檔路徑（比照 Alcatel/Dell OS10/
// NX-OS 上市時做法，本次不擴大匯入白名單）。
// ══════════════════════════════════════════════════════════════════
function computeExtremeVlanPortMap(vlans,interfaces){
  const idToName={};
  (vlans||[]).forEach(v=>{idToName[String(v.id)]=v.name||('VLAN'+v.id);});
  const taggedMap={},untaggedMap={};
  (interfaces||[]).forEach(iface=>{
    if(!iface.name)return;
    if(iface.mode==='trunk'){
      (iface.trunkVlans||'').split(',').map(s=>s.trim()).filter(Boolean).forEach(vid=>{
        const vname=idToName[vid]; if(!vname)return;
        if(!taggedMap[vname])taggedMap[vname]=[];
        taggedMap[vname].push(iface.name);
      });
      if(iface.nativeVlan&&idToName[iface.nativeVlan]){
        const vname=idToName[iface.nativeVlan];
        if(!untaggedMap[vname])untaggedMap[vname]=[];
        untaggedMap[vname].push(iface.name);
      }
    }else if(iface.mode==='access'&&iface.accessVlan&&idToName[iface.accessVlan]){
      const vname=idToName[iface.accessVlan];
      if(!untaggedMap[vname])untaggedMap[vname]=[];
      untaggedMap[vname].push(iface.name);
    }
  });
  return {taggedMap,untaggedMap};
}

function renderExtremeVLANs(vlans,interfaces){
  const {taggedMap,untaggedMap}=computeExtremeVlanPortMap(vlans,interfaces);
  return (vlans||[]).map(v=>{
    const lines=[`create vlan "${v.name}" tag ${v.id}`];
    if(v.desc)lines.push(`configure vlan ${v.name} description "${v.desc}"`);
    (taggedMap[v.name]||[]).forEach(p=>lines.push(`configure vlan ${v.name} add ports ${p} tagged`));
    (untaggedMap[v.name]||[]).forEach(p=>lines.push(`configure vlan ${v.name} add ports ${p} untagged`));
    // IP（2026-08-12 補上，既有缺口——parseExtremeXOSVLANs() 早就解析 v.ip，但
    // renderExtremeVLANs() 從未輸出過，官方 `configure vlan NAME ipaddress A.B.C.D M.M.M.M`
    // 為 dotted-mask 雙 token 語法，與 parser 端擷取語法一致，故換算回去輸出）
    if(v.ip&&!v.ip.includes(':')){
      const [ipAddr,len]=v.ip.split('/');
      lines.push(`configure vlan ${v.name} ipaddress ${ipAddr} ${maskFromCidr(len)}`);
    }
    // 次要IP（2026-08-23 陣列化）：官方 `configure vlan NAME add secondary-ipaddress IP/N`；
    // parser 端 2026-08-17 已從「僅取第一筆」擴充為完整陣列 secondaryIps
    (v.secondaryIps||[]).filter(s=>!s.includes(':')).forEach(s=>lines.push(`configure vlan ${v.name} add secondary-ipaddress ${s}`));
    return lines.join('\n');
  }).join('\n#\n');
}

// Interface shutdown：parseExtremeXOSInterfaces() 已解析 `disable port X`（disabled
// 集合回填 iface.shutdown），但 renderExtremeVLANs()/assembleExtremeConfig() 此前完全
// 未輸出此欄位，是未文件化的真缺口
function renderExtremeInterfaceShutdown(interfaces){
  return (interfaces||[]).filter(i=>i.shutdown&&i.name).map(i=>`disable port ${i.name}`).join('\n');
}

// LACP：真實語法 "enable sharing MASTER grouping PORT_LIST algorithm ... lacp" 建立群組
// （成員第一個 port 即為邏輯 master port，須同時出現在 grouping 清單內），啟用模式另用
// 獨立一行 "configure sharing MASTER lacp activity-mode active|passive" 設定
function renderExtremeLACPGroup(l){
  const members=(l.members||[]).filter(Boolean);
  if(!members.length)return '';
  const master=members[0];
  const lines=[`enable sharing ${master} grouping ${members.join(',')} algorithm address-based L2 lacp`];
  lines.push(`configure sharing ${master} lacp activity-mode ${l.mode==='passive'?'passive':'active'}`);
  return lines.join('\n');
}
function renderExtremeLACP(list){return (list||[]).filter(l=>l.members&&l.members.length).map(renderExtremeLACPGroup).join('\n#\n');}

// VRRP：同樣以 VLAN 為主體，vlan NAME 而非 ID（比照 VLAN membership 的 idToName 對照）；
// preempt 為旗標式關鍵字，EXOS 預設本來就是 preempt 啟用，只有明確關閉才需要輸出
// dont-preempt；"enable vrrp" 為全域啟用行，只需輸出一次
function renderExtremeVRRP(vrrpList,vlans){
  const idToName={};
  (vlans||[]).forEach(v=>{idToName[String(v.id)]=v.name||('VLAN'+v.id);});
  const groups=groupVrrpByVlan(vrrpList);
  const blocks=groups.map(g=>{
    const vname=idToName[String(g.vlanId)]||('VLAN'+g.vlanId);
    const lines=[];
    (g.entries||[]).forEach(e=>{
      lines.push(`create vrrp vlan ${vname} vrid ${e.vrid}`);
      if(e.vip)lines.push(`configure vrrp vlan ${vname} vrid ${e.vrid} add ${e.vip}`);
      if(e.priority)lines.push(`configure vrrp vlan ${vname} vrid ${e.vrid} priority ${e.priority}`);
      if(e.preempt===false)lines.push(`configure vrrp vlan ${vname} vrid ${e.vrid} dont-preempt`);
    });
    return lines.join('\n');
  });
  if(blocks.length)blocks.push('enable vrrp');
  return blocks.join('\n#\n');
}

function renderExtremeRoute(r){
  const dst=r.dst==='0.0.0.0/0'?'default':r.dst;
  return `configure iproute add ${dst} ${r.gw}`;
}
function renderExtremeRoutes(list){return (list||[]).map(renderExtremeRoute).join('\n');}

// OSPF：逐 VLAN area 指派（比照 Alcatel/Brocade/Juniper 既有慣例，「Network」欄位存放
// 介面名稱字串，非 CIDR），"enable ospf" 全域啟用行放最後。2026-07-16 對外查證官方文件
// 確認：backbone area（0.0.0.0）預設存在不可刪除，但非 backbone area 須先用
// "create ospf area A.B.C.D" 宣告才能指派 VLAN（物件導向式 CLI，create 在前 configure
// 在後，與已修復的 Brocade OSPF 屬同一類型 bug），原本完全沒有輸出這行。
function renderExtremeOSPFGlobal(o){
  const lines=[];
  if(o.routerId)lines.push(`configure ospf routerid ${o.routerId}`);
  (o.areas||[]).forEach(a=>{
    if(a.area&&a.area!=='0'&&a.area!=='0.0.0.0')lines.push(`create ospf area ${a.area}`);
    (a.networks||[]).forEach(n=>lines.push(`configure ospf add vlan ${n.network} area ${a.area}`));
  });
  lines.push('enable ospf');
  return lines.join('\n');
}
function renderExtremeOSPF(list){return (list||[]).map(renderExtremeOSPFGlobal).join('\n#\n');}

// BGP：本地 ASN 用 "configure bgp as-number N"，neighbor 建立用 "create bgp neighbor"
// （2026-07-15 查證修正動詞），需搭配 "enable bgp neighbor IP" 才會生效；Networks 用
// "configure bgp add network A.B.C.D/N"（2026-07-16 對外查證官方 Command Reference 確認）
function renderExtremeBGPList(list){
  return (list||[]).map(b=>{
    const lines=[`configure bgp as-number ${b.asn}`];
    if(b.routerId)lines.push(`configure bgp routerid ${b.routerId}`);
    (b.networks||[]).forEach(n=>lines.push(`configure bgp add network ${n}`));
    (b.peers||[]).forEach(p=>{
      lines.push(`create bgp neighbor ${p.ip} remote-AS-number ${p.as}`);
      if(p.desc)lines.push(`configure bgp neighbor ${p.ip} description "${p.desc}"`);
      lines.push(`enable bgp neighbor ${p.ip}`);
    });
    lines.push('enable bgp');
    return lines.join('\n');
  }).join('\n#\n');
}

// DHCP：2026-07-16 對外查證官方 ExtremeXOS Command Reference/User Guide 與真實設定範例
// （analysisman.com 完整流程）後修正 3 處先前未查證的臆測語法：
// (1) 啟用指令不是 "enable dhcp vlan NAME"（該指令實際語意是 VLAN 自己以 DHCP Client
//     身分取得位址，並非啟用 Server），真正啟用 Server 的指令是逐 port 的
//     "enable dhcp ports P1,P2 vlan NAME"，故需要該 VLAN 的實際成員 port 清單（複用
//     computeExtremeVlanPortMap()，taggedMap/untaggedMap 合併後的所有 port）；若表單
//     沒有任何 Interface 列屬於這個 VLAN，則沒有 port 可啟用，此列會略過該行（無法產生
//     真正會生效的啟用指令，優於編造 "ports all" 之類未查證的替代寫法）
// (2) lease-time 不是 "dhcp-options lease-time N"（不存在的子選項），真實是獨立指令
//     "dhcp-lease-timer N"
// (3) dns-server 不是逗號列表，真實需要 primary/secondary 關鍵字各自一行；表單 dns
//     欄位是空白/逗號分隔的自由文字，取前兩筆分別視為 primary/secondary
// (4) relay 的 "configure bootprelay add IP vlan NAME" 關鍵字順序錯誤，真實是
//     "configure bootprelay vlan NAME add IP"
// EXOS 指令一律用 VLAN 名稱而非 ID，比照 renderExtremeOSPFGlobal() 既有慣例，DHCP
// Server/Relay 表格的「Interface」欄位視為使用者直接填寫的 VLAN 名稱；留空的列無法決定
// 要套用到哪個 VLAN，故略過不輸出。
function renderExtremeDHCPServer(d,vlanPortMap){
  if(!d.interface)return '';
  const vname=d.interface;
  const lines=[];
  if(d.range){
    const[lo,hi]=d.range.split('-').map(s=>s.trim());
    if(lo&&hi)lines.push(`configure vlan "${vname}" dhcp-address-range ${lo} - ${hi}`);
  }
  if(d.gateway)lines.push(`configure vlan "${vname}" dhcp-options default-gateway ${d.gateway}`);
  const dnsServers=(d.dns||'').split(/[\s,]+/).filter(Boolean);
  if(dnsServers[0])lines.push(`configure vlan "${vname}" dhcp-options dns-server primary ${dnsServers[0]}`);
  if(dnsServers[1])lines.push(`configure vlan "${vname}" dhcp-options dns-server secondary ${dnsServers[1]}`);
  if(d.lease)lines.push(`configure vlan "${vname}" dhcp-lease-timer ${d.lease}`);
  // bootFile/nextServer/ntpServer：2026-07-24 對外查證官方 Command Reference 確認皆掛在
  // 既有 dhcp-options 通用 numbered option 機制底下（非具名關鍵字），與 parser 端
  // parseExtremeXOSDHCP() 已查證的 code 67(bootFile)/150(nextServer 優先，與 66 相容)/
  // 42(ntpServer) 對應，此前僅解析未輸出，比照既有 range/gateway/dns/lease 慣例補上
  if(d.bootFile)lines.push(`configure vlan "${vname}" dhcp-options code 67 string "${d.bootFile}"`);
  if(d.nextServer)lines.push(`configure vlan "${vname}" dhcp-options code 150 ipaddress ${d.nextServer}`);
  if(d.ntpServer)lines.push(`configure vlan "${vname}" dhcp-options code 42 ipaddress ${d.ntpServer}`);
  const ports=[...new Set([...(vlanPortMap?.taggedMap?.[vname]||[]),...(vlanPortMap?.untaggedMap?.[vname]||[])])];
  if(ports.length)lines.push(`enable dhcp ports ${ports.join(',')} vlan "${vname}"`);
  return lines.join('\n');
}
function renderExtremeDHCPRelay(d){
  if(!d.interface||!d.relayServer)return '';
  return `configure bootprelay vlan "${d.interface}" add ${d.relayServer}`;
}
function renderExtremeDHCP(list,vlans,interfaces){
  const vlanPortMap=computeExtremeVlanPortMap(vlans,interfaces);
  const servers=(list||[]).filter(d=>d.type==='server').map(d=>renderExtremeDHCPServer(d,vlanPortMap)).filter(Boolean);
  const relayEntries=(list||[]).filter(d=>d.type==='relay'&&d.interface&&d.relayServer);
  const relays=relayEntries.map(renderExtremeDHCPRelay).filter(Boolean);
  // option82：2026-07-24 查證確認為全域指令（非逐 VLAN），只要任一 relay 列勾選就輸出
  // 一次，避免同一全域指令因多筆 relay 列而重複輸出
  if(relayEntries.some(d=>d.option82))relays.push('configure bootprelay dhcp-agent information option');
  return [...servers,...relays].join('\n');
}

// STP：2026-07-19 對外查證官方 ExtremeXOS Command Reference/User Guide 確認 STPD
// （Spanning Tree Domain）為具名網域物件，預設已存在名為 "s0" 的網域；本專案範圍限制
// 為僅支援單一預設網域 s0（不支援 create 多網域/MSTI 多實例），VLAN 成員一律簡化為
// 「已設定的所有 VLAN 全部加入 s0，ports all」（不做逐 VLAN 精細成員宣告，比照 Brocade
// STP 回合「全域單一模式」的既有簡化慣例）。逐 port 設定沿用共用 model.stp.ports 形狀
// （portfast/bpduguard/cost/priority 對應到 link-type edge/edge-safeguard+bpdu-restrict/
// cost/port-priority 四種指令，EXOS 無 interface 區塊，故用扁平獨立指令輸出，非巢狀
// interface 區塊）；root mode 未查得 EXOS 對應快捷語法，本輪不支援
function renderExtremeSTP(stp,vlans){
  if(!stp||(!stp.mode&&!(stp.instances&&stp.instances.length)&&!(stp.ports&&stp.ports.length)))return '';
  const lines=['create stpd s0'];
  if(stp.mode)lines.push(`configure stpd s0 mode ${stp.mode}`);
  (vlans||[]).forEach(v=>{
    if(v.name)lines.push(`configure stpd s0 add vlan ${v.name} ports all`);
  });
  (stp.ports||[]).forEach(p=>{
    if(!p.port)return;
    if(p.portfast)lines.push(`configure stpd s0 ports link-type edge ${p.port}`);
    if(p.bpduguard)lines.push(`configure stpd s0 ports edge-safeguard enable ${p.port} bpdu-restrict`);
    if(p.cost)lines.push(`configure stpd s0 ports cost ${p.cost} ${p.port}`);
    if(p.priority)lines.push(`configure stpd s0 ports port-priority ${p.priority} ${p.port}`);
  });
  const inst=(stp.instances||[])[0];
  if(inst&&inst.priority)lines.push(`configure stpd s0 priority ${inst.priority}`);
  lines.push('enable stpd s0');
  return lines.join('\n');
}

// Security：802.1X／MAC-based 認證統一由 NetLogin 子系統管理（2026-07-19 對外查證）。
// 全域啟用子系統（enable netlogin dot1x/mac）＋逐 port 生效指令（enable netlogin ports
// PORT_LIST dot1x mac，可複合多個方法關鍵字）；guest vlan 為全域設定，取陣列中第一筆
// 非空值輸出一次。沿用共用 model.security 形狀，MAC 方式對應 portSec 欄位（功能近似
// 對應，非逐字對應，EXOS 無 maximum/age/violation 概念）
function renderExtremeSecurity(security){
  const list=(security||[]).filter(s=>s.port&&(s.dot1x==='auth'||s.portSec));
  if(!list.length)return '';
  const lines=[];
  const vlanEntry=list.find(s=>s.guestVlan&&s.guestVlan!=='-');
  if(vlanEntry)lines.push(`configure netlogin vlan "${vlanEntry.guestVlan}"`);
  if(list.some(s=>s.dot1x==='auth'))lines.push('enable netlogin dot1x');
  if(list.some(s=>s.portSec))lines.push('enable netlogin mac');
  list.forEach(s=>{
    const methods=[s.dot1x==='auth'?'dot1x':null, s.portSec?'mac':null].filter(Boolean);
    if(methods.length)lines.push(`enable netlogin ports ${s.port} ${methods.join(' ')}`);
  });
  return lines.join('\n');
}

// QoS：8 個 egress QoS profile QP1(最低)~QP8(最高)，QP1/QP8 為預設已存在，QP2-QP7 須先
// create qosprofile 才能使用（2026-07-19 對外查證官方 Command Reference/User Guide）。
// 資料形狀與共用 policy-map/class 完全不同，不沿用共用 qos 變數（比照 Brocade brocadeQos
// 前例，命名為 extremeQos 避免撞名）。configure ports.../enable diffserv examination 為
// 兩個獨立可選開關，各自依表單是否填寫/勾選決定是否輸出
function renderExtremeQoS(qos){
  if(!qos)return '';
  const lines=[];
  (qos.profiles||[]).forEach(p=>{
    if(!p.name)return;
    lines.push(`create qosprofile ${p.name}`);
    if(p.minbw||p.maxbw){
      const parts=[];
      if(p.minbw)parts.push(`minbw ${p.minbw}`);
      if(p.maxbw)parts.push(`maxbw ${p.maxbw}`);
      lines.push(`configure qosprofile ${p.name} ${parts.join(' ')}`);
    }
  });
  (qos.dscpMap||[]).forEach(d=>{
    if(d.codePoint&&d.profile)lines.push(`configure diffserv examination code-point ${d.codePoint} qosprofile ${d.profile}`);
  });
  (qos.ports||[]).forEach(p=>{
    if(!p.port)return;
    if(p.profile)lines.push(`configure ports ${p.port} qosprofile ${p.profile}`);
    if(p.diffservExam)lines.push(`enable diffserv examination ports ${p.port}`);
  });
  return lines.join('\n');
}

// ACL：真實語法是 Dynamic ACL Rule（已查證官方 ExtremeXOS Command Reference／社群範例
// analysisman.com 後修正 switch_analyzer 既有 _parseACLExtreme() 的假想語法錯誤，詳見
// now.md）：create access-list NAME "conditions" "action"；套用用 configure access-list
// add NAME first ports LIST|vlan NAME|any ingress|egress；position 固定 first（表單無對應
// 欄位，屬已知簡化，比照 MikroTik Queue Tree 簡化先例）。沿用共用 ACL 資料形狀
// {name,rules:[{action,protocol,src,dst,dstPort}],appliedOn:[{interface,direction}]}，
// appliedOn.interface 慣例：以 "vlan " 開頭視為 VLAN 目標，空值/'any' 視為 any，其餘視為 port list
function renderExtremeACLEntry(a){
  const lines=[];
  (a.rules||[]).forEach(r=>{
    const conds=[];
    if(r.protocol&&r.protocol!=='any'&&r.protocol!=='ip')conds.push(`protocol ${r.protocol}`);
    if(r.src&&r.src!=='any')conds.push(`source-address ${r.src}`);
    if(r.dst&&r.dst!=='any'&&r.dst!=='-')conds.push(`destination-address ${r.dst}`);
    if(r.dstPort)conds.push(`destination-port ${r.dstPort}`);
    const condStr=conds.length?conds.join(';')+';':'';
    lines.push(`create access-list ${a.name} "${condStr}" "${r.action||'permit'}"`);
  });
  (a.appliedOn||[]).forEach(ap=>{
    const raw=(ap.interface||'').trim();
    const target=!raw||raw.toLowerCase()==='any'?'any':/^vlan\s+/i.test(raw)?raw:`ports ${raw}`;
    lines.push(`configure access-list add ${a.name} first ${target} ${ap.direction==='out'?'egress':'ingress'}`);
  });
  return lines.join('\n');
}
function renderExtremeACL(list){return (list||[]).map(renderExtremeACLEntry).join('\n#\n');}

// 本機帳號（2026-08-26 新增）：switch_analyzer 既有 parseExtremeXOSUsers() 語法為
// "create account admin/user/lawful-intercept NAME encrypted HASH"（Format B：name 不加
// 引號，官方文件三種帳號類型同時扮演權限等級：admin=讀寫／user=唯讀／lawful-intercept=
// 特殊唯讀），密碼固定輸出 encrypted 關鍵字（parser 端 exosPwdType() 依雜湊前綴判斷型別，
// 不驗證雜湊格式是否吻合宣告等級，比照全專案既有慣例）；role 非三選一時 fallback 'admin'
function renderExtremeUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>{
    const role=/^(admin|user|lawful-intercept)$/.test(u.role||'')?u.role:'admin';
    return `create account ${role} ${u.name} encrypted ${u.password}`;
  }).join('\n');
}

function assembleExtremeConfig(model){
  const blocks=[`# ${tr('notice.disclaimer')}`,`configure snmp sysname ${model.sysname||'Switch'}`];
  const vlanBlockEx=renderExtremeVLANs(model.vlans,model.interfaces);
  if(vlanBlockEx)blocks.push(vlanBlockEx);
  const shutdownBlockEx=renderExtremeInterfaceShutdown(model.interfaces);
  if(shutdownBlockEx)blocks.push(shutdownBlockEx);
  const lacpBlockEx=renderExtremeLACP(model.lacp);
  if(lacpBlockEx)blocks.push(lacpBlockEx);
  const vrrpBlockEx=renderExtremeVRRP(model.vrrp,model.vlans);
  if(vrrpBlockEx)blocks.push(vrrpBlockEx);
  if(model.ospf&&model.ospf.length)blocks.push(renderExtremeOSPF(model.ospf));
  if(model.routes&&model.routes.length)blocks.push(renderExtremeRoutes(model.routes));
  if(model.bgp&&model.bgp.length)blocks.push(renderExtremeBGPList(model.bgp));
  const dhcpBlockEx=renderExtremeDHCP(model.dhcp,model.vlans,model.interfaces);
  if(dhcpBlockEx)blocks.push(dhcpBlockEx);
  const secBlockEx=renderExtremeSecurity(model.security);
  if(secBlockEx)blocks.push(secBlockEx);
  const stpBlockEx=renderExtremeSTP(model.stp,model.vlans);
  if(stpBlockEx)blocks.push(stpBlockEx);
  const qosBlockEx=renderExtremeQoS(model.extremeQos);
  if(qosBlockEx)blocks.push(qosBlockEx);
  const aclBlockEx=renderExtremeACL(model.acl);
  if(aclBlockEx)blocks.push(aclBlockEx);
  const usersBlockEx=renderExtremeUsers(model.users);
  if(usersBlockEx)blocks.push(usersBlockEx);
  if(model.snmpTrapHost)blocks.push(`configure snmp add trapreceiver ${model.snmpTrapHost} community public`);
  return blocks.join('\n#\n')+'\n';
}

// ══════════════════════════════════════════════════════════════════
// Aruba ProCurve / ArubaOS-Switch render 函式（switch_analyzer parser 範圍：Hostname／
// VLAN(tagged/untagged，membership 以 VLAN 為主體宣告，無 SVI IP 表單來源可用)／
// Interface(access/trunk，無 hybrid)／LACP(`trunk <ports> TrkN lacp|trunk` 單行語法)／
// 靜態路由（CIDR 單一 token，已於 2026-07-15 對外查證 arubanetworking.hpe.com CLI-Bank
// 官方文件，修正 switch_analyzer 既有 parseProCurve() 誤寫的 Cisco 風格
// dest+dotted-mask+gateway 三段式語法錯誤）／極簡 OSPF（僅 router-id，無 area/network）。
// 不含 BGP/RIP/VRRP/Users/DHCP/ACL/QoS/Security/STP：switch_analyzer 對這些欄位在
// procurve 上要嘛無解析、要嘛落在未針對 ArubaOS-Switch 查證過的 Cisco-style 通用
// fallback（例如 Security 的 802.1X 語法實際上是 `aaa port-access authenticator`
// 全域指令而非逐 interface 區塊，通用 dispatcher 對 procurve 未開放此 fallback），
// 貿然渲染會產生「round-trip 過但真機吃不進去」的假功能，故不產生。
// ══════════════════════════════════════════════════════════════════

// 2026-07-17 對外查證官方文件確認 ArubaOS-Switch OSPF area 指派是在 VLAN context 內執行
// `ip ospf area <id>`，比照已實作的 Brocade renderBrocadeVEBlocks() 合併 VRRP+OSPF 進同一
// 區塊的既有模式，故需要 ospf 參數才能把 area 指派合併進對應 VLAN 區塊輸出
// DHCP relay：parseDhcpRelay()（switch_analyzer 內 parseProCurve() 分支）已解析
// interface/relayServer/option82，但此前 assembleProCurveConfig() 完全沒有引用
// model.dhcp，是文件（CLAUDE.md 廠牌表格宣稱已支援）與實作不符的真缺口。真實語法為
// `ip helper-address <server-ip>` 巢狀宣告在 `vlan N` 區塊內（非全域指令），比照既有
// areaOfVlan 反查慣例，用 vlan id → relay server 清單的對照表插入對應 VLAN 區塊
