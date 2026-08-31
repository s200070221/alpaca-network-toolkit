const ROUTEROS_BRIDGE='bridge1';

// lacpList（2026-08-08 新增第二用途參數）：官方文件確認 bonding slave 不可再直接掛
// bridge port／VLAN filtering table，該由 bond 介面本身承載 VLAN tagging；比照 Cisco
// renderCiscoLACPExtra() 用聚合群組第一個成員的設定當代表值（refIface）的既有慣例，
// LACP 成員埠改用 bond${id} 名稱參與 tagged/untagged 清單，成員埠本身不再逐一列出
function renderRouterOSVLANs(vlans,interfaces,lacpList){
  const taggedMap={},untaggedMap={};
  const memberNames=new Set();
  (lacpList||[]).forEach(l=>(l.members||[]).forEach(m=>memberNames.add(m)));
  const effective=(interfaces||[]).filter(iface=>iface.name&&!memberNames.has(iface.name));
  (lacpList||[]).forEach(l=>{
    const refIface=(l.members||[]).map(m=>(interfaces||[]).find(i=>i.name===m)).find(Boolean);
    if(refIface)effective.push({...refIface,name:`bond${l.id}`});
  });
  effective.forEach(iface=>{
    if(iface.mode==='trunk'){
      (iface.trunkVlans||'').split(',').map(s=>s.trim()).filter(Boolean).forEach(vid=>{
        (taggedMap[vid]=taggedMap[vid]||[]).push(iface.name);
      });
    }else if(iface.mode==='access'&&iface.accessVlan){
      (untaggedMap[iface.accessVlan]=untaggedMap[iface.accessVlan]||[]).push(iface.name);
    }
  });
  const lines=['/interface bridge vlan'];
  (vlans||[]).forEach(v=>{
    const tagged=taggedMap[String(v.id)]||[];
    const untagged=untaggedMap[String(v.id)]||[];
    if(!tagged.length&&!untagged.length)return;
    let line=`add bridge=${ROUTEROS_BRIDGE}`;
    if(tagged.length)line+=` tagged=${tagged.join(',')}`;
    if(untagged.length)line+=` untagged=${untagged.join(',')}`;
    line+=` vlan-id=${v.id}`;
    lines.push(line);
  });
  return lines.length>1?lines.join('\n'):'';
}

function renderRouterOSInterfaceDeclarations(ifaces){
  if(!ifaces||!ifaces.length)return '';
  const lines=['/interface ethernet'];
  ifaces.forEach(i=>{ if(i.name)lines.push(`add name=${i.name}`); });
  return lines.join('\n');
}

// lacpList（2026-08-08 新增，資料模型修正）：官方文件（Bonding／Bridging and Switching）
// 確認實體介面若已是 bonding slave，不可再直接加入 bridge 當 port，否則 bond 介面在不同
// port 上收到相同 MAC 會造成衝突；正確作法是只把 bond 介面本身加入 bridge，故此處排除
// 屬於任一 LACP 群組成員的實體介面，改為每個 LACP 群組輸出一行 bond 介面本身的 member
function renderRouterOSBridgeMembers(ifaces,lacpList){
  const memberNames=new Set();
  (lacpList||[]).forEach(l=>(l.members||[]).forEach(m=>memberNames.add(m)));
  const names=(ifaces||[]).filter(i=>i.name&&!memberNames.has(i.name)).map(i=>i.name);
  (lacpList||[]).forEach(l=>{ if((l.members||[]).length)names.push(`bond${l.id}`); });
  if(!names.length)return '';
  const lines=['/interface bridge member'];
  names.forEach(n=>lines.push(`add bridge=${ROUTEROS_BRIDGE} interface=${n}`));
  return lines.join('\n');
}

// STP：/interface bridge 本身就是橋接器宣告區塊（同一行帶 protocol-mode/priority），
// 與其他廠牌獨立的 STP 區塊架構不同；priority 用十六進位（真實語法慣例，如 0x8000）
function renderRouterOSBridge(stp){
  const mode=stp&&stp.mode?stp.mode:'';
  const priority=stp&&stp.instances&&stp.instances[0]&&stp.instances[0].priority;
  let line=`add name=${ROUTEROS_BRIDGE}`;
  if(mode)line+=` protocol-mode=${mode}`;
  if(priority)line+=` priority=0x${parseInt(priority,10).toString(16)}`;
  return `/interface bridge\n${line}`;
}

function renderRouterOSLACPGroup(l){
  // 真實語法第三個屬性只有 mode=（802.3ad 對應 LACP），UI 的 active/passive 皆對應 802.3ad，
  // static 對應非 LACP 的靜態聚合 balance-rr（比照 ProCurve trunk/lacp 兩態收斂的既有慣例）
  const mode=l.mode==='static'?'balance-rr':'802.3ad';
  const members=(l.members||[]).filter(Boolean);
  return `add name=bond${l.id} slaves=${members.join(',')} mode=${mode}`;
}
function renderRouterOSLACP(list){
  if(!list||!list.length)return '';
  return ['/interface bonding',...list.map(renderRouterOSLACPGroup)].join('\n');
}

// 本機帳號（2026-08-26 新增）：switch_analyzer 既有 parseRouterOSUsers() 語法為
// "/user\nadd name=NAME password=PASSWORD group=read|write|full"。**重要限制**：真實
// RouterOS `/export` 匯出檔本來就不含密碼欄位（官方文件明確記載密碼永不匯出），此為
// 裝置本身設計非本工具缺陷，故本功能僅能單向「表單→設定檔」產生，無法做「匯入既有
// 設定檔→回填密碼」的 round-trip；group 非 read/write/full 三選一時 fallback 'full'
function renderRouterOSUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return ['/user',...list.map(u=>{
    const group=/^(read|write|full)$/.test(u.role||'')?u.role:'full';
    return `add name=${u.name} password=${u.password} group=${group}`;
  })].join('\n');
}

function renderRouterOSRoutes(list){
  if(!list||!list.length)return '';
  // IPv6 靜態路由（2026-08-31 新增）：官方 MikroTik Wiki「Manual:IPv6/Route」＋
  // help.mikrotik.com 官方文件確認容器是獨立的 "/ipv6 route" 選單（非 "/ip route"），
  // 指令本身結構相同（add dst-address=X gateway=Y），依 dst 是否含冒號分流輸出到
  // 對應選單區塊；parseRouterOSRoutes() 本來就對 "add" 行做通用比對、無選單區分，
  // 天生已可正確 round-trip 兩個區塊各自的路由，本輪只需修正 render 端輸出到正確選單
  const v4=list.filter(r=>!r.dst.includes(':'));
  const v6=list.filter(r=>r.dst.includes(':'));
  const blocks=[];
  if(v4.length)blocks.push(['/ip route',...v4.map(r=>`add destination=${r.dst} gateway=${r.gw}`)].join('\n'));
  if(v6.length)blocks.push(['/ipv6 route',...v6.map(r=>`add dst-address=${r.dst} gateway=${r.gw}`)].join('\n'));
  return blocks.join('\n');
}

function renderRouterOSOSPF(list){
  const o=(list||[])[0];
  if(!o)return '';
  const lines=['/routing ospf instance',`add name=default${o.routerId?` router-id=${o.routerId}`:''}`];
  const areas=(o.areas||[]);
  if(areas.length){
    lines.push('','/routing ospf area');
    // type（default/stub/nssa）：parseRouterOSOSPF() 已解析 `type=X`，此前此處只輸出
    // area-id，未讀取 type 欄位；'default' 是官方隱含預設值，不特意輸出以維持簡潔
    areas.forEach((a,idx)=>{
      let line=`add name=area${idx} area-id=${a.area} instance=default`;
      if(a.type&&a.type!=='default')line+=` type=${a.type}`;
      lines.push(line);
    });
    const tmplLines=[];
    areas.forEach((a,idx)=>{
      const ifaces=(a.networks||[]).map(n=>n.network).filter(Boolean);
      if(ifaces.length)tmplLines.push(`add area=area${idx} interfaces=${ifaces.join(',')}`);
    });
    if(tmplLines.length)lines.push('','/routing ospf interface-template',...tmplLines);
  }
  return lines.join('\n');
}

// OSPFv3（2026-08-23 新增）：官方文件確認 RouterOS 7 把 OSPFv2/OSPFv3 統一進同一個
// /routing ospf 選單，用 instance 的 version=3 屬性區分；o.pid 就是 parser 端解析到的
// instance name= 原值（非數字流水號），areas[].interfaces 本來就是介面名稱字串陣列
// （與 IPv4 areas[].networks[].network 形狀不同，見 parseRouterOSOSPF() 分桶邏輯）
function renderRouterOSOSPFv3(list){
  const o=(list||[])[0];
  if(!o)return '';
  const iname=o.pid||'default6';
  const lines=['/routing ospf instance',`add name=${iname} version=3${o.routerId?` router-id=${o.routerId}`:''}`];
  const areas=(o.areas||[]);
  if(areas.length){
    lines.push('','/routing ospf area');
    areas.forEach((a,idx)=>lines.push(`add name=${iname}area${idx} area-id=${a.area} instance=${iname}`));
    const tmplLines=[];
    areas.forEach((a,idx)=>{
      const ifaces=(a.interfaces||[]).filter(Boolean);
      if(ifaces.length)tmplLines.push(`add area=${iname}area${idx} interfaces=${ifaces.join(',')}`);
    });
    if(tmplLines.length)lines.push('','/routing ospf interface-template',...tmplLines);
  }
  return lines.join('\n');
}

// Networks（2026-07-17 對外查證官方 MikroTik RouterOS 文件 /routing/bgp 頁面確認）：
// output.network 參數其實直接暴露在 /routing/bgp/connection 選單內（官方文件：
// "template-specific parameters are also directly exposed in this menu"），不需要
// 額外的 /routing bgp template 資源；該參數引用一個 /ip firewall address-list 位址
// 清單，且官方文件明確註記「僅在路由表內有對應 IGP 路由時才會真正廣播」，故同時加上
// output.network-blackhole=yes（官方文件：「設為 yes 會自動幫清單內每個網段建立
// blackhole 路由寫入路由表」），讓產生的設定檔本身就足以生效，不需使用者另外手動加
// 靜態路由。清單名稱固定為 bgp-networks（表單無對應欄位可自訂，比照既有 instance=default
// 固定命名慣例）
function renderRouterOSBGP(list){
  const b=(list||[])[0];
  if(!b)return '';
  const lines=[];
  const networks=b.networks||[];
  const networks6=b.networks6||[];
  if(networks.length){
    lines.push('/ip firewall address-list');
    networks.forEach(n=>lines.push(`add list=bgp-networks address=${n}`));
    lines.push('');
  }
  // IPv6（2026-08-23 新增）：官方文件確認 IPv6 版本引用獨立的 /ipv6 firewall address-list
  // （非 /ip firewall address-list），與既有 IPv4 清單並行
  if(networks6.length){
    lines.push('/ipv6 firewall address-list');
    networks6.forEach(n=>lines.push(`add list=bgp-networks6 address=${n}`));
    lines.push('');
  }
  lines.push('/routing bgp instance',`add name=default as=${b.asn}${b.routerId?` router-id=${b.routerId}`:''}`);
  const peers=(b.peers||[]);
  if(peers.length){
    // address-families=：官方文件確認逐 connection 宣告可為 ipv4/ipv6/ipv4,ipv6；本工具
    // peer 資料不分家族，依是否有對應 networks/networks6 推斷要開哪些 family。
    // output.network= 每行只能有一個（parser 端 _parseVRRPRouterOS 姊妹函式 parseBGP()
    // 用非 global 的 .match() 只取第一筆命中，若同一行輸出兩個 output.network= 會讓 v6
    // 清單名稱被誤判成 v4 清單名稱），v4/v6 皆有時優先輸出 v4，比照 parser 端既有限制
    const fams=[networks.length?'ipv4':'',networks6.length?'ipv6':''].filter(Boolean).join(',')||'ipv4';
    const outputParams=networks.length?' output.network=bgp-networks output.network-blackhole=yes':
      (networks6.length?' output.network=bgp-networks6':'');
    lines.push('','/routing bgp connection');
    peers.forEach((p,idx)=>lines.push(`add name=${p.desc||'peer'+idx} remote.address=${p.ip} remote.as=${p.as} instance=default address-families=${fams}${outputParams}`));
  }
  return lines.join('\n');
}

// DHCP server：2026-07-24 parser 端 parseRouterOSDHCP() 已整段重寫為真實 /ip pool +
// /ip dhcp-server + /ip dhcp-server network 三段式模型（range/lease/bootFile/nextServer/
// ntpServer 皆已查證），但 render 端此前只輸出 name/interface 兩個最小欄位，其餘欄位
// 全數未讀取。pool 名稱固定用 `pool-<dhcp名稱>` 命名慣例（表單無獨立 pool 名稱欄位），
// 與 address-pool= 引用一致；network 區塊需要 address=CIDR 才能與 dhcp-server 建立
// 官方文件所述的「CIDR 涵蓋比對」關聯，沒有 network 欄位的列不輸出 network 區塊。
function renderRouterOSDHCP(list){
  const servers=(list||[]).filter(d=>d.type==='server');
  if(!servers.length)return '';
  const poolLines=[],srvLines=[],netLines=[];
  servers.forEach(d=>{
    const poolName=`pool-${d.name}`;
    const rangeSeg=(d.range||'').split(';')[0].trim();
    const[lo,hi]=rangeSeg?rangeSeg.split('-').map(s=>s.trim()):['',''];
    let srvLine=`add name=${d.name} interface=${d.interface}`;
    if(lo&&hi){
      poolLines.push(`add name=${poolName} ranges=${lo}-${hi}`);
      srvLine+=` address-pool=${poolName}`;
    }
    if(d.lease)srvLine+=` lease-time=${d.lease}`;
    srvLines.push(srvLine);
    if(d.network){
      let netLine=`add address=${d.network}`;
      if(d.gateway)netLine+=` gateway=${d.gateway}`;
      const dns=Array.isArray(d.dns)?d.dns.filter(Boolean):(d.dns||'').split(/[\s,]+/).filter(Boolean);
      if(dns.length)netLine+=` dns-server=${dns.join(',')}`;
      if(d.bootFile)netLine+=` boot-file-name=${d.bootFile}`;
      if(d.nextServer)netLine+=` next-server=${d.nextServer}`;
      if(d.ntpServer)netLine+=` ntp-server=${d.ntpServer}`;
      netLines.push(netLine);
    }
  });
  const blocks=[];
  if(poolLines.length)blocks.push(['/ip pool',...poolLines].join('\n'));
  blocks.push(['/ip dhcp-server',...srvLines].join('\n'));
  if(netLines.length)blocks.push(['/ip dhcp-server network',...netLines].join('\n'));
  return blocks.join('\n\n');
}

// RIP：2026-07-19 對外查證官方 help.mikrotik.com「/routing/rip」頁確認 RouterOS v7 用
// instance+interface-template 模型（無 network 陳述式）。沿用既有共用 RIP 表單
// （#rip-pid/#rip-networks/#rip-redist），networks 欄位重新詮釋為啟用介面清單
function renderRouterOSRIP(list){
  const r=(list||[])[0];
  if(!r)return '';
  const redist=(r.redistribute||[]).join(',');
  const lines=['/routing rip instance',`add name=${r.pid}${redist?` redistribute=${redist}`:''}`];
  const ifaces=(r.networks||[]).filter(Boolean);
  if(ifaces.length)lines.push('','/routing rip interface-template',`add instance=${r.pid} interfaces=${ifaces.join(',')}`);
  return lines.join('\n');
}

// VRRP：2026-07-19 對外查證官方 help.mikrotik.com「VRRP」頁確認語法為 `/interface vrrp
// add interface=IFACE vrid=N priority=N {preemption-mode=no}`，VRRP 介面本身不帶 IP，
// VIP 需另外在 `/ip address` 區塊以 RouterOS 循序預設命名 `interface=vrrpN`（N 為建立
// 順序）宣告。沿用既有共用 VRRP 表單，`vlanId` 欄位對 RouterOS 而言儲存底層實體介面
// 名稱（如 ether3），非數字 VLAN ID（比照 parseRouterOS 端 _parseVRRPRouterOS 的
// 欄位語意，程式註解與 now.md 皆有標明）
// IPv6（2026-08-23 新增）：官方文件確認 `v3-protocol=ipv6` 旗標區分 IPv6 執行個體，VIP
// 改宣告在 `/ipv6 address`；parser 端每個 `/interface vrrp add` 行各自對應一筆獨立記錄
// （vip／vip6 互斥，非同一筆記錄合併兩者），介面命名靠「未顯式 name= 時的循序邏輯介面
// 命名」（interface=vrrpN，N 為 add 行出現順序），render 端須維持與 parser 端一致的
// forEach 順序（idx+1）才能正確 round-trip
function renderRouterOSVRRP(vrrpList){
  const list=(vrrpList||[]).filter(v=>v.vlanId&&v.vrid&&(v.vip||v.vip6));
  if(!list.length)return '';
  const vrrpLines=['/interface vrrp'];
  const addrLines=[];
  const addr6Lines=[];
  list.forEach((v,idx)=>{
    const isV6=!!v.vip6&&!v.vip;
    let line=`add interface=${v.vlanId} vrid=${v.vrid}`;
    if(isV6)line+=' v3-protocol=ipv6';
    if(v.priority)line+=` priority=${v.priority}`;
    if(v.preempt===false)line+=' preemption-mode=no';
    vrrpLines.push(line);
    if(isV6){ if(v.vip6)addr6Lines.push(`add address=${v.vip6} interface=vrrp${idx+1}`); }
    else if(v.vip)addrLines.push(`add address=${v.vip} interface=vrrp${idx+1}`);
  });
  const blocks=[vrrpLines.join('\n')];
  if(addrLines.length)blocks.push(['/ip address',...addrLines].join('\n'));
  if(addr6Lines.length)blocks.push(['/ipv6 address',...addr6Lines].join('\n'));
  return blocks.join('\n\n');
}

// Security（802.1X）：2026-07-19 對外查證官方 help.mikrotik.com「Dot1X」頁確認語法為
// `/interface dot1x server add interface=PORT`，逐 port 獨立宣告無巢狀子模式。沿用
// 既有共用 Security 表單（#security-body），MAC port-security 已知限制不支援（查無
// 官方對應語法），僅 dot1x==='auth' 的列輸出
function renderRouterOSSecurity(security){
  const list=(security||[]).filter(s=>s.port&&s.dot1x==='auth');
  if(!list.length)return '';
  return ['/interface dot1x server',...list.map(s=>`add interface=${s.port}`)].join('\n');
}

// ACL（Firewall Filter）：2026-07-19 對外查證官方 help.mikrotik.com「Filter」頁確認
// chain-based 扁平規則清單，非具名 ACL 物件，故用專屬 routerosAcl 形狀（比照 Brocade
// brocadeQos／Extreme extremeQos 命名前例，避免撞名既有共用 acl 陣列）
function renderRouterOSACL(routerosAcl){
  const list=(routerosAcl||[]).filter(r=>r.chain&&r.action);
  if(!list.length)return '';
  const lines=list.map(r=>{
    let line=`add chain=${r.chain} action=${r.action}`;
    if(r.protocol)line+=` protocol=${r.protocol}`;
    if(r.srcAddress)line+=` src-address=${r.srcAddress}`;
    if(r.dstAddress)line+=` dst-address=${r.dstAddress}`;
    if(r.dstPort)line+=` dst-port=${r.dstPort}`;
    if(r.inInterface)line+=` in-interface=${r.inInterface}`;
    if(r.comment)line+=` comment="${r.comment}"`;
    return line;
  });
  return ['/ip firewall filter',...lines].join('\n');
}

// QoS：Simple Queue／Queue Tree 兩套獨立機制，資料形狀與共用 policy-map QoS 完全不同
// （比照 Brocade/Extreme QoS 前例，專屬 routerosQos 形狀）
function renderRouterOSQoS(routerosQos){
  if(!routerosQos)return '';
  const blocks=[];
  const simple=(routerosQos.simpleQueues||[]).filter(q=>q.name);
  if(simple.length){
    const lines=simple.map(q=>{
      let line=`add name=${q.name}`;
      if(q.target)line+=` target=${q.target}`;
      if(q.maxLimitUp||q.maxLimitDown)line+=` max-limit=${q.maxLimitUp||'0'}/${q.maxLimitDown||'0'}`;
      if(q.limitAtUp||q.limitAtDown)line+=` limit-at=${q.limitAtUp||'0'}/${q.limitAtDown||'0'}`;
      return line;
    });
    blocks.push(['/queue simple',...lines].join('\n'));
  }
  const tree=(routerosQos.queueTree||[]).filter(q=>q.name);
  if(tree.length){
    const lines=tree.map(q=>{
      let line=`add name=${q.name}`;
      if(q.parent)line+=` parent=${q.parent}`;
      if(q.maxLimit)line+=` max-limit=${q.maxLimit}`;
      return line;
    });
    blocks.push(['/queue tree',...lines].join('\n'));
  }
  return blocks.join('\n\n');
}

function assembleRouterOSConfig(model){
  const blocks=[`# ${tr('notice.disclaimer')}`,`/system identity\nset name=${model.sysname||'Switch'}`];
  const ifaceBlock=renderRouterOSInterfaceDeclarations(model.interfaces);
  if(ifaceBlock)blocks.push(ifaceBlock);
  // LACP 區塊移到 bridge member／VLAN 之前（2026-08-08）：bond 介面若要被當成 bridge port／
  // VLAN tagging 對象，必須先建立才能被後面的區塊引用，符合 RouterOS 腳本逐行執行的特性
  const lacpBlock=renderRouterOSLACP(model.lacp);
  if(lacpBlock)blocks.push(lacpBlock);
  blocks.push(renderRouterOSBridge(model.stp));
  const memberBlock=renderRouterOSBridgeMembers(model.interfaces,model.lacp);
  if(memberBlock)blocks.push(memberBlock);
  const vlanBlock=renderRouterOSVLANs(model.vlans,model.interfaces,model.lacp);
  if(vlanBlock)blocks.push(vlanBlock);
  const routeBlock=renderRouterOSRoutes(model.routes);
  if(routeBlock)blocks.push(routeBlock);
  const ospfBlock=renderRouterOSOSPF(model.ospf);
  if(ospfBlock)blocks.push(ospfBlock);
  const ospf6Block=renderRouterOSOSPFv3(model.ospf6);
  if(ospf6Block)blocks.push(ospf6Block);
  const ripBlock=renderRouterOSRIP(model.rip);
  if(ripBlock)blocks.push(ripBlock);
  const vrrpBlock=renderRouterOSVRRP(model.vrrp);
  if(vrrpBlock)blocks.push(vrrpBlock);
  const bgpBlock=renderRouterOSBGP(model.bgp);
  if(bgpBlock)blocks.push(bgpBlock);
  const dhcpBlock=renderRouterOSDHCP(model.dhcp);
  if(dhcpBlock)blocks.push(dhcpBlock);
  const securityBlock=renderRouterOSSecurity(model.security);
  if(securityBlock)blocks.push(securityBlock);
  const aclBlock=renderRouterOSACL(model.routerosAcl);
  if(aclBlock)blocks.push(aclBlock);
  const qosBlock=renderRouterOSQoS(model.routerosQos);
  if(qosBlock)blocks.push(qosBlock);
  const usersBlock=renderRouterOSUsers(model.users);
  if(usersBlock)blocks.push(usersBlock);
  if(model.snmpTrapHost)blocks.push(`/snmp\nset trap-target=${model.snmpTrapHost} trap-community=public`);
  return blocks.join('\n\n')+'\n';
}

// ══════════════════════════════════════════════════════════════════
// Cisco NXOS render 函式
// ══════════════════════════════════════════════════════════════════

