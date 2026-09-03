function brocadePortName(name){
  return String(name||'').replace(/^e(?:the(?:rnet)?)?\s*/i,'').trim();
}

// 官方語法 `breakout ethernet PORT to ethernet PORT:N`，N 僅 2/4 兩種合法值；4x25G 由收發模組
// 決定速率、指令本身不區分 4x10G/4x25G，無法可靠 round-trip 故不輸出（比照 NX-OS 2x50G 排除慣例）
function renderBrocadeBreakoutBlock(breakouts){
  const brBreakouts=(breakouts||[]).filter(b=>b.vendor==='brocade');
  if(!brBreakouts.length)return '';
  const lines=brBreakouts.map(b=>{
    const port=brocadePortName(b.parentPort);
    if(!port)return '';
    if(b.mode==='2x50G')return `breakout ethernet ${port} to ethernet ${port}:2`;
    if(b.mode==='4x10G')return `breakout ethernet ${port} to ethernet ${port}:4`;
    return '';
  }).filter(Boolean);
  return lines.join('\n');
}

function renderBrocadeVLANs(vlans,interfaces){
  const taggedMap={},untaggedMap={};
  (interfaces||[]).forEach(iface=>{
    const port=brocadePortName(iface.name);
    if(!port)return;
    if(iface.mode==='trunk'){
      (iface.trunkVlans||'').split(',').map(s=>s.trim()).filter(Boolean).forEach(vid=>{
        if(!taggedMap[vid])taggedMap[vid]=[];
        taggedMap[vid].push(port);
      });
      if(iface.nativeVlan){
        if(!untaggedMap[iface.nativeVlan])untaggedMap[iface.nativeVlan]=[];
        untaggedMap[iface.nativeVlan].push(port);
      }
    }else if(iface.mode==='access'&&iface.accessVlan){
      if(!untaggedMap[iface.accessVlan])untaggedMap[iface.accessVlan]=[];
      untaggedMap[iface.accessVlan].push(port);
    }
  });
  return (vlans||[]).map(v=>{
    const lines=[`vlan ${v.id}${v.name?' name '+v.name:''} by port`];
    const tagged=taggedMap[String(v.id)]||[];
    const untagged=untaggedMap[String(v.id)]||[];
    if(tagged.length)lines.push(` tagged ${tagged.map(p=>'ethe '+p).join(' ')}`);
    if(untagged.length)lines.push(` untagged ${untagged.map(p=>'ethe '+p).join(' ')}`);
    return lines.join('\n');
  }).join('\n!\n');
}

// RIP：官方 FastIron L3 Routing Guide 確認語法無 network 陳述式，共用 RIP 卡片的
// 「Networks」欄位對 Brocade 改為填寫要啟用 RIP 的介面名稱（如 "ve10 1/1/1"）；
// distance/timer/learn-default/default-metric/redistribute 因共用表單無對應欄位，
// 本輪僅支援匯入時讀取，不支援由表單產生輸出（比照 Interface Speed 下拉既有慣例）
function renderBrocadeRIPGlobal(rip){
  return (rip&&rip.length)?'router rip':'';
}
function brocadeRipEnabledPorts(rip){
  const set=new Set();
  const r=(rip||[])[0];
  (r?.networks||[]).forEach(tok=>{
    const t=tok.trim(); if(!t)return;
    if(/^ve\d+$/i.test(t))set.add('ve'+t.replace(/^ve/i,''));
    else set.add('e'+brocadePortName(t));
  });
  return set;
}

// Security：802.1X 為全域 authentication 子模式逐 port 宣告，MAC port-security 為
// 逐 interface 巢狀 `port security` 子模式，兩者語法完全獨立（對外查證官方 FastIron
// Security Configuration Guide 確認），沿用既有共用 Security 表單資料（無需新 UI）
// 2026-07-22 對外查證官方 FastIron Security Configuration Guide 後修正：
// `dot1x enable ethernet PORT` 確認正確（保留）；`dot1x port-control auto` 原本誤加
// `ethernet PORT` 參數，真實語法是逐 interface 區塊內的裸指令（改移到
// renderBrocadeInterface()）；`dot1x guest-vlan` 原本誤植為逐 port 語法（`ethernet
// PORT vlan ID`），真實是全域指令 `dot1x guest-vlan ID`（無 port、無 vlan 關鍵字），
// 且 FastIron 只有一個全域 guest VLAN，故從所有填了 guestVlan 的項目取第一筆
function renderBrocadeAuthGlobal(securityList){
  const entries=(securityList||[]).filter(s=>s.dot1x==='auth');
  if(!entries.length)return '';
  const lines=['authentication'];
  entries.forEach(s=>lines.push(` dot1x enable ethernet ${brocadePortName(s.port)}`));
  const gv=entries.find(s=>s.guestVlan&&s.guestVlan!=='-');
  if(gv)lines.push(` dot1x guest-vlan ${gv.guestVlan}`);
  return lines.join('\n');
}
function findBrocadePortSecurity(securityList,ifaceName){
  const port=brocadePortName(ifaceName);
  return (securityList||[]).find(s=>brocadePortName(s.port)===port&&s.portSec);
}
function findBrocadeDot1x(securityList,ifaceName){
  const port=brocadePortName(ifaceName);
  return (securityList||[]).find(s=>brocadePortName(s.port)===port&&s.dot1x==='auth');
}

// QoS：Brocade 專屬形狀（見 parseBrocadeQoS 註解），全域 DSCP 對應表 + 逐 port 優先權/
// trust dscp，不沿用共用 policy-map QoS 資料形狀
function renderBrocadeQoSGlobal(qos){
  return ((qos&&qos.dscpMap)||[]).filter(m=>m.dscpValues&&m.priority!=='').map(m=>`qos-tos map dscp-priority ${m.dscpValues} to ${m.priority}`).join('\n');
}
function findBrocadeQosPort(qos,ifaceName){
  const port=brocadePortName(ifaceName);
  return ((qos&&qos.ports)||[]).find(p=>brocadePortName(p.port)===port);
}

function renderBrocadeInterface(iface,aclList,ripPorts,securityList,qos,ospfAreaOther,ospfAreaOther6){
  const port=brocadePortName(iface.name);
  const lines=[`interface ethernet ${port}`];
  if(iface.desc)lines.push(` port-name ${iface.desc}`);
  if(iface.mode==='trunk'&&iface.nativeVlan)lines.push(` dual-mode ${iface.nativeVlan}`);
  if(iface.shutdown)lines.push(' disable');
  // ACL 套用：語法與 Cisco 完全相同（parseACL 對 brocade fallback 到 _parseACLCisco），
  // 沿用既有 findAclApplications 內嵌邏輯，比照 Dell OS10 既有慣例
  findAclApplications(aclList,iface.name).forEach(ap=>lines.push(` ip access-group ${ap.name} ${ap.direction}`));
  if(ripPorts&&ripPorts.has('e'+port))lines.push(' ip rip');
  // OSPF area（2026-07-27 補上）：parseBrocadeOSPF() 的 network 欄位可以是任意介面名稱
  // （ve/loopback/實體埠皆可），先前 renderBrocadeVEBlocks() 沒有篩選介面類型，非 ve 的
  // area 指派會被誤塞進 VE 區塊產生 `interface ve e1/1/1` 這種錯誤語法；現在依名稱分流，
  // 屬於本實體埠的部分改在這裡輸出。groupBrocadeOspfAreas() 的 other map 已用
  // brocadePortName() 正規化過 key（剝除 e/ethe/ethernet 前綴），這裡用同一顆已算好的
  // port 變數查找，同時相容手動輸入（無前綴，比照 RIP Networks 既有慣例）與匯入既有設定檔
  // （parser 產生的 network 值固定帶 "e" 前綴）兩種來源格式
  const ospfArea=ospfAreaOther&&ospfAreaOther[port];
  if(ospfArea!==undefined)lines.push(` ip ospf area ${ospfArea}`);
  // OSPFv3（2026-08-23 新增）：官方語法 "ipv6 ospf area X"，無 pid 前綴，比照 IPv4 同一套
  // 依介面前綴分流查詢表模式
  const ospfArea6=ospfAreaOther6&&ospfAreaOther6[port];
  if(ospfArea6!==undefined)lines.push(` ipv6 ospf area ${ospfArea6}`);
  // dot1x port-control auto：2026-07-22 對外查證後修正為逐 interface 區塊內的裸指令
  // （無 ethernet PORT 參數），與全域 authentication 區塊內的 dot1x enable 是分開兩處
  if(findBrocadeDot1x(securityList,iface.name))lines.push(' dot1x port-control auto');
  const qosPort=findBrocadeQosPort(qos,iface.name);
  if(qosPort){
    if(qosPort.priority!=='')lines.push(` priority ${qosPort.priority}`);
    if(qosPort.trustDscp)lines.push(' trust dscp');
  }
  const sec=findBrocadePortSecurity(securityList,iface.name);
  if(sec){
    lines.push(' port security');
    if(sec.maxMac!=='-'&&sec.maxMac!=null)lines.push(`  maximum ${sec.maxMac}`);
    if(sec.violation&&sec.violation!=='-')lines.push(`  violation ${sec.violation}`);
  }
  return lines.join('\n');
}
function renderBrocadeInterfaces(ifaces,aclList,ripPorts,securityList,qos,ospfAreaOther,ospfAreaOther6){return (ifaces||[]).map(i=>renderBrocadeInterface(i,aclList,ripPorts,securityList,qos,ospfAreaOther,ospfAreaOther6)).join('\n!\n');}

// Loopback：官方 FastIron 支援 `interface loopback N` 底下設定 `ip address`，本輪新增
// （2026-07-27）——先前全檔案沒有任何輸出路徑，若誤流入 renderBrocadeInterface() 會被
// brocadePortName() 誤轉成 `interface ethernet loopbackN` 這種不存在的語法
function renderBrocadeLoopback(iface,ospfAreaOther,ospfAreaOther6){
  const lines=[`interface loopback ${iface.name.replace(/^loopback/i,'')}`];
  if(iface.ip){
    const [ip,len]=iface.ip.split('/');
    lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
  }
  // brocadePortName() 對 "loopbackN" 這種本來就不以 e 開頭的名稱無作用，套用只是為了
  // 與 renderBrocadeInterface() 用同一套正規化規則查找 groupBrocadeOspfAreas() 的 other map
  const ospfArea=ospfAreaOther&&ospfAreaOther[brocadePortName(iface.name)];
  if(ospfArea!==undefined)lines.push(` ip ospf area ${ospfArea}`);
  const ospfArea6=ospfAreaOther6&&ospfAreaOther6[brocadePortName(iface.name)];
  if(ospfArea6!==undefined)lines.push(` ipv6 ospf area ${ospfArea6}`);
  return lines.join('\n');
}
function renderBrocadeLoopbacks(ifaces,ospfAreaOther,ospfAreaOther6){return (ifaces||[]).filter(i=>i.type==='loopback').map(i=>renderBrocadeLoopback(i,ospfAreaOther,ospfAreaOther6)).join('\n!\n');}

// LACP：只產生已對外查證的主要語法（獨立 `lag "NAME" dynamic|static id N` +
// `ports ethe ...` 區塊），不產生 parseBrocadeLACP 另外兼容、但未查證來源的
// 舊式 `trunk` 語法或逐介面 `link-aggregate`/`lag` 子指令
function renderBrocadeLACPGroup(l){
  const mode=l.mode==='active'?'dynamic':'static';
  const members=(l.members||[]).map(brocadePortName).filter(Boolean);
  const lines=[`lag "${l.name||('LAG'+l.id)}" ${mode} id ${l.id}`];
  if(members.length)lines.push(` ports ${members.map(p=>'ethe '+p).join(' ')}`);
  return lines.join('\n');
}
function renderBrocadeLACP(list){return (list||[]).map(renderBrocadeLACPGroup).join('\n!\n');}

// VE(SVI) 區塊：OSPF 逐介面 area 指派、VRRP-E、DHCP Relay（`ip helper-address`，已於
// parseBrocadeDHCP() 查證）都要巢狀在同一個 `interface ve N` 區塊內（比照 Dell OS10
// VLAN+VRRP 必須合併進同一區塊的既有原則），故統一在此一次收集三者資料再輸出，不分開
// 各自產生 `interface ve N`（會產生多個同名區塊，重新解析時後者會覆蓋前者）。OSPF Area
// 表格的「Network」欄位比照既有 Juniper 慣例，存放介面名稱（"veN"）而非 CIDR；DHCP Relay
// 表格的「Interface」欄位需填寫對應的 "veN"（比照 Cisco/Aruba CX 逐介面 relay 填寫慣例）
// STP：官方 FastIron L2 Switching Configuration Guide 確認全域 `spanning-tree
// [priority N]`（classic 802.1D）或 `spanning-tree rstp [priority N]` 皆可在全域層級
// 輸入，跟 Cisco 風格的 renderSpanningTreeGlobal()（spanning-tree mode X／逐 vlan
// priority）完全不同語法，故獨立函式；本輪僅做全域單一模式，不支援逐 VLAN 多實例
function renderBrocadeSTP(stp){
  if(!stp||!stp.mode)return '';
  let line='spanning-tree'+(String(stp.mode).toLowerCase()==='rstp'?' rstp':'');
  const g=(stp.instances||[]).find(i=>!i.id||i.id==='0');
  if(g&&g.priority)line+=` priority ${g.priority}`;
  return line;
}

// OSPF area 指派依介面名稱分流成 ve（VE 區塊用）與其他（實體埠/Loopback 用）兩組，
// 2026-07-27 修正：原本 renderBrocadeVEBlocks() 只用 `.replace(/^ve/i,'')` 剝字首，
// 對 "e1/1/1"/"loopback1" 這類非 ve 介面名稱不會篩掉，會被誤塞進同一組 vlanIds 集合，
// 產生 `interface ve e1/1/1` 這種錯誤語法（P0 正確性 bug）。other map 的 key 用
// brocadePortName() 正規化（剝除 e/ethe/ethernet 前綴，對 loopbackN 這種本來就不以
// e 開頭的名稱無作用），相容手動輸入實體埠名稱（無前綴，比照 RIP Networks 既有慣例）
// 與匯入既有設定檔（parseBrocadeOSPF() 產生的 network 值固定帶 "e" 前綴）兩種來源格式
function groupBrocadeOspfAreas(ospfList){
  const ve={},other={};
  (ospfList||[]).forEach(o=>{
    (o.areas||[]).forEach(a=>{
      (a.networks||[]).forEach(n=>{
        const name=String(n.network||'').trim();
        const m=/^ve(\d+)$/i.exec(name);
        if(m)ve[m[1]]=a.area;
        else if(name)other[brocadePortName(name)]=a.area;
      });
    });
  });
  return {ve,other};
}

// OSPFv3（2026-08-23 新增）：ospf6 的 areas[].interfaces 本來就是介面名稱字串陣列
// （"veN"／"loopbackN"／"eX/Y/Z"），比照 groupBrocadeOspfAreas() 依前綴分流成 ve/其他兩組
function groupBrocadeOspfAreas6(ospf6List){
  const ve={},other={};
  (ospf6List||[]).forEach(o=>{
    (o.areas||[]).forEach(a=>{
      (a.interfaces||[]).forEach(name=>{
        const n=String(name||'').trim();
        const m=/^ve(\d+)$/i.exec(n);
        if(m)ve[m[1]]=a.area;
        else if(n)other[brocadePortName(n)]=a.area;
      });
    });
  });
  return {ve,other};
}

// VE(SVI) 區塊：2026-07-27 新增 interfaces 參數，改以 model.interfaces 裡 type==='svi' 的
// 項目為主要驅動來源（才能取得 SVI 自己的 ip/vrf），VRRP/OSPF/DHCP/RIP 反查邏輯保留作為
// fallback——確保沒有獨立 SVI 宣告、但只掛了 VRRP-E/OSPF area/DHCP relay/RIP 的介面仍能
// 正確產生 `interface ve N` 區塊（見既有 T310 測試情境）。ospfAreaVe 只含 ve 介面的 area
// 指派（見 groupBrocadeOspfAreas()），非 ve 介面已改在 renderBrocadeInterface()/
// renderBrocadeLoopback() 各自輸出，不會再混進這裡。
function renderBrocadeVEBlocks(interfaces,vrrpList,ospfAreaVe,dhcpList,ripPorts,ospfAreaVe6){
  const vrrpGroups=groupVrrpByVlan(vrrpList);
  const vrrpMap=new Map(vrrpGroups.map(g=>[String(g.vlanId),g]));
  const sviMap=new Map((interfaces||[]).filter(i=>i.type==='svi')
    .map(i=>[String((/^ve(\d+)$/i.exec(i.name)||[])[1]||''),i]));
  const dhcpVeIds=new Set();
  (dhcpList||[]).forEach(d=>{
    const m=/^ve(\d+)$/i.exec((d.interface||'').trim());
    if(d.type==='relay'&&m)dhcpVeIds.add(m[1]);
  });
  const ripVeIds=new Set([...(ripPorts||[])].filter(p=>/^ve\d+$/.test(p)).map(p=>p.replace(/^ve/,'')));
  const vlanIds=new Set([...sviMap.keys(),...vrrpMap.keys(),...Object.keys(ospfAreaVe||{}),...dhcpVeIds,...ripVeIds]);
  vlanIds.delete('');
  return [...vlanIds].sort((a,b)=>parseInt(a)-parseInt(b)).map(vid=>{
    const iface=sviMap.get(vid);
    const g=vrrpMap.get(vid);
    const lines=[`interface ve ${vid}`];
    if(iface&&iface.desc)lines.push(` port-name ${iface.desc}`);
    const ip=(iface&&iface.ip)||(g&&g.ip)||'';
    // 官方 FastIron Command Reference 確認 VE 介面 IPv6 語法 `ipv6 address ADDR/PREFIXLEN`
    // （直出完整 CIDR，不像 IPv4 需要 maskFromCidr() 換算雙 token 遮罩）
    if(ip){
      if(ip.includes(':'))lines.push(` ipv6 address ${ip}`);
      else{ const[ipAddr,len]=ip.split('/'); lines.push(` ip address ${ipAddr} ${maskFromCidr(len)}`); }
    }
    // 雙棧修復：parseBrocadeInterfaces() 早已把 IPv6 獨立無條件存進 iface.ip6（不受 ip 欄位
    // 是否已有值影響），但這裡先前只讀單一 ip 欄位，同時有 IPv4+IPv6 時 ip 固定被 IPv4 佔用，
    // iface.ip6 整個檔案零命中，IPv6 位址從未被輸出（2026-09-02 全功能審查發現）
    if(iface&&iface.ip6&&iface.ip6!==ip)lines.push(` ipv6 address ${iface.ip6}`);
    // 次要IP（2026-08-23 陣列化）：官方 `ip address A B secondary`；parser 端 2026-08-17
    // 已從「僅取第一筆」擴充為完整陣列 secondaryIps
    (iface&&iface.secondaryIps||[]).filter(s=>!s.includes(':')).forEach(s=>{
      const[secIp,secLen]=s.split('/');
      lines.push(` ip address ${secIp} ${maskFromCidr(secLen)} secondary`);
    });
    if(iface&&iface.vrf)lines.push(` vrf forwarding ${iface.vrf}`);
    if(ospfAreaVe&&ospfAreaVe[vid]!==undefined)lines.push(` ip ospf area ${ospfAreaVe[vid]}`);
    if(ospfAreaVe6&&ospfAreaVe6[vid]!==undefined)lines.push(` ipv6 ospf area ${ospfAreaVe6[vid]}`);
    if(ripVeIds.has(vid))lines.push(' ip rip');
    findDhcpRelays(dhcpList,'ve'+vid).forEach(rel=>lines.push(` ip helper-address ${rel.relayServer}`));
    if(g)g.entries.forEach(e=>{
      if(e.vip){
        lines.push(` ip vrrp-extended vrid ${e.vrid}`);
        lines.push(`  ip ${e.vip}`);
        if(e.priority)lines.push(`  priority ${e.priority}`);
        lines.push('  activate');
      }
      // vip6（2026-08-31 新增）：官方 Ruckus FastIron「Enabling an IPv6 VRRP-Ev3 device」
      // 頁面逐字查證，獨立指令族 "ipv6 vrrp-extended vrid N"，priority 關鍵字為
      // "backup priority"（與 IPv4 版本裸 "priority" 不同），需要 "version 3" 宣告，
      // VIP 用 "ipv6-address ADDR"（僅取第一筆為 MVP 範圍）
      if(e.vip6){
        lines.push(` ipv6 vrrp-extended vrid ${e.vrid}`);
        if(e.priority)lines.push(`  backup priority ${e.priority}`);
        lines.push('  version 3');
        lines.push(`  ipv6-address ${e.vip6}`);
        lines.push('  activate');
      }
    });
    return lines.join('\n');
  }).join('\n!\n');
}

// 2026-07-22 對外查證官方 FastIron 文件後移除死輸出：`router ospf` 底下沒有
// `area X normal` 這種全域宣告指令（normal 是隱含預設值，FastIron 只有 stub/nssa
// 才有對應的宣告指令，且該指令從未被解析器讀過），area 指派完全是逐介面
// `ip ospf area X`（已由 renderBrocadeVEBlocks() 處理），此函式僅需啟用 process 本身
function renderBrocadeOSPFGlobal(list){
  return (list||[]).map(()=>'router ospf').join('\n!\n');
}

// OSPFv3（2026-08-23 新增）：官方 FastIron Command Reference 確認全域啟用 "ipv6 router ospf"
// （無 pid 參數），area 指派完全逐介面 "ipv6 ospf area X"（已由 renderBrocadeVEBlocks()/
// renderBrocadeInterface()/renderBrocadeLoopback() 處理）
function renderBrocadeOSPFv3Global(list){
  return (list&&list.length)?'ipv6 router ospf':'';
}

// Networks（2026-07-17 對外查證官方 FastIron L3 Routing Configuration Guide 確認）：
// `network ip-addr ip-mask [route-map/weight/backdoor]`，點分遮罩格式非 CIDR，用既有
// maskFromCidr() 轉換
function renderBrocadeBGP(b){
  const lines=['router bgp',` local-as ${b.asn}`];
  (b.networks||[]).forEach(n=>{
    const [ip,len]=n.split('/');
    if(ip&&len)lines.push(` network ${ip} ${maskFromCidr(len)}`);
  });
  (b.peers||[]).forEach(p=>{
    lines.push(` neighbor ${p.ip} remote-as ${p.as}`);
    if(p.desc)lines.push(` neighbor ${p.ip} description ${p.desc}`);
  });
  return lines.join('\n');
}
function renderBrocadeBGPList(list){return (list||[]).map(renderBrocadeBGP).join('\n!\n');}

// router-id 為全域指令、OSPF/BGP 共用，取任一個有填的即可
function renderBrocadeRouterId(ospfList,bgpList){
  const rid=(ospfList&&ospfList[0]&&ospfList[0].routerId)||(bgpList&&bgpList[0]&&bgpList[0].routerId)||'';
  return rid?`ip router-id ${rid}`:'';
}

// 靜態路由：parseBrocadeRoutes 同時接受 CIDR 與 dotted-mask 兩種目的網段格式，
// 直接輸出 CIDR（model.routes[].dst 本來就是 CIDR 字串）較簡單
function renderBrocadeRoute(r){return renderArubaRoute(r);}
function renderBrocadeRoutes(list){return (list||[]).join?list.map(renderBrocadeRoute).join('\n'):'';}

// DHCP：此函式僅負責 server pool，relay（`ip helper-address`）已改為巢狀進
// renderBrocadeVEBlocks() 產生的 `interface ve N` 區塊內，不在此輸出（避免產生
// 兩個同名 `interface ve N` 區塊，重新解析時後者覆蓋前者）；lease-time 因
// parseBrocadeDHCP 要求純數字秒數、與本專案其餘廠牌慣用的 "24h" 字串格式不同，
// 若直接沿用會產生無法回頭解析的錯誤語法，故不輸出此欄位
// range/excluded/bootFile/nextServer/ntpServer：2026-07-27 補上（parseBrocadeDHCP() 早就
// 有解析，這裡先前只輸出 network/gateway/dns 三項）。bootFile/nextServer/ntpServer 統一
// 採用 parser 優先辨識的新版 numbered option 語法（67/150/42），與 parser 的優先順序一致
function renderBrocadeDHCPPool(d){
  const lines=[`ip dhcp-server pool ${d.name}`];
  if(d.network){
    const[net,len]=d.network.split('/');
    lines.push(` network-address ${net} ${maskFromCidr(len)}`);
  }
  if(d.range){
    const[start,end]=d.range.split('-');
    if(start&&end)lines.push(` range ${start} ${end}`);
  }
  if(d.gateway)lines.push(` default-router ${d.gateway}`);
  if(d.dns)lines.push(` dns-server ${d.dns}`);
  if(d.excluded)lines.push(` excluded-address ${d.excluded}`);
  if(d.bootFile)lines.push(` option 67 ascii ${d.bootFile}`);
  if(d.nextServer)lines.push(` option 150 ip ${d.nextServer}`);
  if(d.ntpServer)lines.push(` option 42 ip ${d.ntpServer}`);
  return lines.join('\n');
}
function renderBrocadeDHCP(list){return (list||[]).filter(d=>d.type==='server').map(renderBrocadeDHCPPool).join('\n!\n');}

// DHCP Option82（2026-07-24 新增解析，一直未接線）：官方文件明確指出「在 VLAN 上啟用
// DHCP Snooping 後 Option82 自動生效，無需額外指令」，parser 端已簡化為「任一
// `ip dhcp snooping vlan` 存在且未被全域停用」的全域訊號判斷，不逐 VLAN/介面追蹤覆蓋
// 範圍；render 端對應比照，只要有任何一筆 server/relay 要求 option82，就對 model.vlans
// 逐一輸出 `ip dhcp snooping vlan N` 啟用（真實達到啟用 Option82 的前提條件）
function renderBrocadeDHCPSnooping(dhcpList,vlans){
  const needsOption82=(dhcpList||[]).some(d=>d.option82);
  if(!needsOption82)return '';
  const ids=(vlans||[]).map(v=>v.id).filter(Boolean);
  if(!ids.length)return '';
  return ids.map(id=>`ip dhcp snooping vlan ${id}`).join('\n');
}

// ICX-Stack 堆疊（2026-09-01 新增）：官方 Ruckus/Brocade FastIron Stacking 文件確認 `stack
// unit N` 區塊內巢狀 `module 0 MODEL`（模組編號固定 0，單顆交換器僅一個模組槽位的常見機型）
// + `priority N`；links 刻意不輸出——switch_analyzer 端 parseBrocadeStack() links 恆固定
// 空陣列（官方查無宣告拓撲鏈路的指令，見該函式註解），非本輪省略
function renderBrocadeStack(stack){
  const blocks=[];
  (stack&&stack.members||[]).forEach(m=>{
    if(!m.id)return;
    const lines=[`stack unit ${m.id}`];
    if(m.model)lines.push(` module 0 ${m.model}`);
    if(m.priority)lines.push(` priority ${m.priority}`);
    blocks.push(lines.join('\n'));
  });
  return blocks.join('\n!\n');
}

function assembleBrocadeConfig(model){
  const blocks=[`! ${tr('notice.disclaimer')}`,`hostname ${model.sysname||'Switch'}`];
  const brocadeStackBlock=renderBrocadeStack(model.brocadeStack);
  if(brocadeStackBlock)blocks.push(brocadeStackBlock);
  if(model.breakouts&&model.breakouts.some(b=>b.vendor==='brocade'))blocks.push(`! ${tr('notice.brocadeBreakoutWarning')}`);
  const brocadeBreakoutBlock=renderBrocadeBreakoutBlock(model.breakouts);
  if(brocadeBreakoutBlock)blocks.push(brocadeBreakoutBlock);
  const ridLine=renderBrocadeRouterId(model.ospf,model.bgp);
  if(ridLine)blocks.push(ridLine);
  const vlanBlock=renderBrocadeVLANs(model.vlans,model.interfaces);
  if(vlanBlock)blocks.push(vlanBlock);
  // VRF：官方文件確認 `vrf forwarding NAME` 要求該 VRF 已用 `vrf NAME`＋`exit-vrf` 建立，
  // 排在 VE 區塊（巢狀輸出 vrf forwarding）之前
  const brocadeVrfNames=collectVrfNames(model.interfaces);
  if(brocadeVrfNames.length)blocks.push(brocadeVrfNames.map(n=>`vrf ${n}\nexit-vrf`).join('\n!\n'));
  const ripPorts=brocadeRipEnabledPorts(model.rip);
  // OSPF area 依介面名稱分流成 ve／其他（實體埠/loopback）兩組，避免非 ve 介面被誤塞進
  // VE 區塊（見 groupBrocadeOspfAreas() 上方註解，P0 正確性 bug 修正）
  const {ve:ospfAreaVe,other:ospfAreaOther}=groupBrocadeOspfAreas(model.ospf);
  const {ve:ospfAreaVe6,other:ospfAreaOther6}=groupBrocadeOspfAreas6(model.ospf6);
  // OSPF：官方文件將「先啟用 OSPF」列為建議步驟順序，早於「指派介面到 area」，排在
  // VE／實體埠／loopback 區塊（內嵌逐介面 `ip ospf area`）之前輸出
  const ospfBlockBr=renderBrocadeOSPFGlobal(model.ospf);
  if(ospfBlockBr)blocks.push(ospfBlockBr);
  const ospf6BlockBr=renderBrocadeOSPFv3Global(model.ospf6);
  if(ospf6BlockBr)blocks.push(ospf6BlockBr);
  // VRRP-E 需要先在全域啟用，否則真實設備會拒絕底下的 ip vrrp-extended vrid 指令
  // （已查證官方文件），parseBrocadeVRRP 不要求此行也能正確解析，純粹為真實設備
  // 正確性補上，不影響 round-trip；2026-08-06 修正：先前這行寫在 veBlock 之後，
  // 跟本段註解自己講的順序要求恰好相反，等於白寫
  if(model.vrrp&&model.vrrp.length)blocks.push('router vrrp-extended');
  // vip6 全域啟用（2026-08-31 新增）：官方文件確認獨立於 IPv4 版本的
  // "ipv6 router vrrp-extended"，非同一行/同一開關
  if(model.vrrp&&model.vrrp.some(v=>v.vip6))blocks.push('ipv6 router vrrp-extended');
  const veBlock=renderBrocadeVEBlocks(model.interfaces,model.vrrp,ospfAreaVe,model.dhcp,ripPorts,ospfAreaVe6);
  if(veBlock)blocks.push(veBlock);
  // 實體埠：排除 svi/loopback 類型（已分別由 renderBrocadeVEBlocks()/renderBrocadeLoopbacks()
  // 處理），避免同一介面被 brocadePortName() 誤轉成 `interface ethernet veN`/`loopbackN`
  // 這種不存在的語法（P0 正確性 bug 修正，見 renderBrocadeVEBlocks() 上方註解）
  const brocadePhysicalIfaces=(model.interfaces||[]).filter(i=>i.type!=='svi'&&i.type!=='loopback');
  if(brocadePhysicalIfaces.length)blocks.push(renderBrocadeInterfaces(brocadePhysicalIfaces,model.acl,ripPorts,model.security,model.brocadeQos,ospfAreaOther,ospfAreaOther6));
  const loopbackBlockBr=renderBrocadeLoopbacks(model.interfaces,ospfAreaOther,ospfAreaOther6);
  if(loopbackBlockBr)blocks.push(loopbackBlockBr);
  const lacpBlockBr=renderBrocadeLACP(model.lacp);
  if(lacpBlockBr)blocks.push(lacpBlockBr);
  if(model.routes&&model.routes.length)blocks.push(renderBrocadeRoutes(model.routes));
  if(model.bgp&&model.bgp.length)blocks.push(renderBrocadeBGPList(model.bgp));
  const ripBlockBr=renderBrocadeRIPGlobal(model.rip);
  if(ripBlockBr)blocks.push(ripBlockBr);
  const dhcpSnoopBlockBr=renderBrocadeDHCPSnooping(model.dhcp,model.vlans);
  if(dhcpSnoopBlockBr)blocks.push(dhcpSnoopBlockBr);
  if(model.dhcp&&model.dhcp.some(d=>d.type==='server'))blocks.push(renderBrocadeDHCP(model.dhcp));
  const authBlockBr=renderBrocadeAuthGlobal(model.security);
  if(authBlockBr)blocks.push(authBlockBr);
  const stpBlockBr=renderBrocadeSTP(model.stp);
  if(stpBlockBr)blocks.push(stpBlockBr);
  const qosBlockBr=renderBrocadeQoSGlobal(model.brocadeQos);
  if(qosBlockBr)blocks.push(qosBlockBr);
  // ACL 放最後：parseACL 對 brocade fallback 到 _parseACLCisco，其區塊擷取正則只認得
  // 下一個同關鍵字區塊或字串結尾，理由同 assembleCiscoConfig/assembleDellOS10Config
  if(model.acl&&model.acl.length)blocks.push(renderCiscoACL(model.acl));
  const brocadeUsersBlock=renderBrocadeUsers(model.users);
  if(brocadeUsersBlock)blocks.push(brocadeUsersBlock);
  if(model.snmpTrapHost)blocks.push(`snmp-server host ${model.snmpTrapHost}`);
  if(model.syslogServer)blocks.push(`logging host ${model.syslogServer}`);
  return blocks.join('\n!\n')+'\n';
}
// 本機帳號：switch_analyzer 的 parseBrocadeUsers() 語法為
// "username NAME privilege N password N HASH"，role 由 privilege 數字換算（0=superuser／
// 4=port-config／其餘=user），故輸出時需反查對應數字；密碼固定輸出等級 8（md5，非 weak 的
// plaintext）
function renderBrocadeUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>{
    const priv=u.role==='superuser'?'0':u.role==='port-config'?'4':'5';
    return `username ${u.name} privilege ${priv} password 8 ${u.password}`;
  }).join('\n');
}

// ══════════════════════════════════════════════════════════════════
// Alcatel OmniSwitch (AOS) render 函式（第 10 個廠牌，MVP 範圍）
// ══════════════════════════════════════════════════════════════════
// 語法已對照 switch_analyzer/test_config/alcatel_test.cfg（真實可解析範例）與對應
// parseAlcatel() 系列函式核對，非臆測。範圍：Hostname／VLAN／Interface（access/trunk，
// 無 hybrid）／OSPF／BGP／靜態路由／LACP／VRRP。OSPF area 僅比照既有 Juniper/Brocade
// 慣例引用介面名稱字串，不輸出對應的 ip interface SVI 區塊。過程中發現並修正
// switch_analyzer 既有 bug：parseAlcatelInterfaces() 的 vlan members port 判斷式原本
// 寫死要求 "->" 前綴，導致真實不帶箭頭的設定檔完全解析不到 port 的 mode/vlans（詳見
// 上方 memReA 修正處與 now.md）。VRRP 語法已於 2026-07-14 對照 Alcatel-Lucent 官方
// CLI Reference Manual 查證（vrrp <vrid> <vlan_id> enable|disable/priority/ip/preempt，
// 逐行個別指令設定），同時修正 switch_analyzer 的 parseAlcatelVRRP() 原本兩個查無來源
// 的猜測語法分支。
