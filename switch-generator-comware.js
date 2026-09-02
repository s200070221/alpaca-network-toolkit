function renderComwareVLAN(v){
  const lines=[`vlan ${v.id}`];
  if(v.name)lines.push(` name ${v.name}`);
  // ipSubnets（2026-07-27 補上）：parseVLANs() 有解析 `ip-subnet-vlan N ip A B`，但
  // render 端從未輸出過。解析正則未擷取子網編號，故此處依序自 1 開始重新編號即可
  // （官方語法僅要求編號在該 VLAN 內唯一，不影響 round-trip 比對的 network/mask 內容）
  (v.ipSubnets||[]).forEach((s,idx)=>lines.push(` ip-subnet-vlan ${idx+1} ip ${s.network} ${s.mask}`));
  lines.push('#');
  return lines.join('\n');
}
function renderComwareVLANs(vlans){return vlans.map(renderComwareVLAN).join('\n');}

// VXLAN（Comware）：interface NveN（source VTEP + vni head-end peer-list）+
// vxlan vsi NAME（vni/evpn encapsulation/default-gateway）+ evpn vpn-instance（RD/RT）；
// 三種區塊皆以單獨一行 '#' 自我終結，對應 parseVXLAN() comware 分支既有正則
function renderComwareVXLAN(vxlan){
  if(!vxlan)return '';
  const vnis=vxlan.vnis||[];
  const blocks=[];
  if(vxlan.vtep||vnis.length){
    const nveLines=['interface Nve1'];
    if(vxlan.vtep)nveLines.push(` source VTEP ${vxlan.vtep}`);
    vnis.forEach(v=>{
      if(!v.vni)return;
      const peerPart=(v.peers&&v.peers.length)?v.peers.join(' '):'protocol bgp';
      nveLines.push(` vni ${v.vni} head-end peer-list ${peerPart}`);
    });
    nveLines.push('#');
    blocks.push(nveLines.join('\n'));
  }
  vnis.forEach(v=>{
    if(!v.vni||!v.name)return;
    const vsiLines=[`vxlan vsi ${v.name}`,` vxlan vni ${v.vni}`,' evpn encapsulation vxlan'];
    if(v.gw)vsiLines.push(` default-gateway ip-address ${v.gw}`);
    vsiLines.push('#');
    blocks.push(vsiLines.join('\n'));
    if(v.rd||v.rtImport||v.rtExport){
      const evpnLines=[`evpn vpn-instance ${v.name}`];
      if(v.rd)evpnLines.push(` route-distinguisher ${v.rd}`);
      if(v.rtImport)evpnLines.push(` vpn-target ${v.rtImport} import`);
      if(v.rtExport)evpnLines.push(` vpn-target ${v.rtExport} export`);
      evpnLines.push('#');
      blocks.push(evpnLines.join('\n'));
    }
  });
  return blocks.join('\n');
}

// VLAN/link-type（class-two 屬性）render，Comware 專用；抽成獨立函式供 renderComwareInterface()
// 與 renderComwareLACPExtra() 共用（後者需要把同一組屬性輸出到 Bridge-Aggregation 介面上）
function comwareL2Lines(iface){
  const lines=[];
  if(!iface)return lines;
  if(iface.mode==='trunk'){
    lines.push(' port link-type trunk');
    if(iface.trunkVlans)lines.push(` port trunk permit vlan ${iface.trunkVlans}`);
    // 2026-07-22 對外查證官方 H3C 文件後修正：`port trunk native-vlan` 不存在，
    // 真實關鍵字是 `port trunk pvid vlan`
    if(iface.nativeVlan)lines.push(` port trunk pvid vlan ${iface.nativeVlan}`);
  }else if(iface.mode==='access'){
    lines.push(' port link-type access');
    if(iface.accessVlan)lines.push(` port access vlan ${iface.accessVlan}`);
  }else if(iface.mode==='hybrid'){
    lines.push(' port link-type hybrid');
    const h=iface.hybrid||{};
    if(h.untagged&&h.untagged.length)lines.push(` port hybrid vlan ${h.untagged.join(' ')} untagged`);
    if(h.tagged&&h.tagged.length)lines.push(` port hybrid vlan ${h.tagged.join(' ')} tagged`);
    if(h.pvid)lines.push(` port hybrid pvid vlan ${h.pvid}`);
    // QinQ／選擇性 VLAN 對應（2026-08-24 修復）：parseComwareHybrid()（switch-analyzer-parser-comware.js）
    // 早就擷取 hasQinQ（`vlan-vpn enable`）與 vlanMaps（`vlan-mapping vlan X inner-vlan Y`），
    // 但 render 端從未輸出過，匯入含 QinQ 的設定檔、編輯、重新匯出後會靜默遺失這兩項設定
    if(h.hasQinQ)lines.push(' vlan-vpn enable');
    (h.vlanMaps||[]).forEach(m=>lines.push(` vlan-mapping vlan ${m.outer} inner-vlan ${m.inner}`));
  }
  return lines;
}
// OSPFv3（2026-08-23 新增）：官方 H3C OSPFv3 手冊確認 area 在 "ospfv3 PID" 區塊內只是
// 存在宣告，真正的介面成員關係要看介面視圖的 "ospfv3 PID area AREA" 指令，故須在逐介面
// render 時反查 model.ospf6 是否有該介面被納入某個 area
function comwareOspf6IfaceLines(ospf6List,ifaceName){
  const lines=[];
  (ospf6List||[]).forEach(o=>{
    (o.areas||[]).forEach(a=>{
      if((a.interfaces||[]).includes(ifaceName))lines.push(` ospfv3 ${o.pid} area ${a.area}`);
    });
  });
  return lines;
}
function renderComwareInterface(iface,lacpList,aclList,securityList,stp,breakouts,ospf6List,qosApplyList){
  const lines=[`interface ${iface.name}`];
  if(iface.desc)lines.push(` description ${iface.desc}`);
  // Breakout：僅 FortyGigE→Ten-GigabitEthernet（4x10G）為已查證官方語法，其餘拆分比例不輸出
  const bk=findBreakoutForPort(breakouts,iface.name);
  if(bk&&bk.mode==='4x10G')lines.push(' using tengige');
  // L3 欄位（ip/vrf，2026-07-27 補上）：parseInterfaces() 對 SVI/Loopback/實體埠皆有解析
  // ip/vrf，但先前 render 完全沒有輸出。Comware 介面本身即可路由，不需要額外的 L3 啟用
  // 關鍵字；vrf 綁定須在 ip address 之前宣告（真實語法要求，變更 VRF 會清空既有 IP）。
  // SVI 的 ip 欄位在解析時已轉成 CIDR 格式，實體埠/Loopback 則保留原始「IP MASK」字串。
  if(iface.vrf)lines.push(` ip binding vpn-instance ${iface.vrf}`);
  // IPv6（試點 5 廠牌之一，已查證官方 H3C IPv6 basics commands 文件：`ipv6 address ADDR/PREFIXLEN`，
  // 與 IPv4 CIDR 慣例一致的 slash 寫法；SVI/實體埠/Loopback 皆同一指令直出，不需遮罩換算）
  // 次要IP（Secondary IP，官方 H3C IP addressing commands 文件：`ip address A B
  // sub`，僅 VLAN-interface／Loopback，不涵蓋一般物理埠；2026-08-23 陣列化：parser 端
  // 2026-08-17 已從「僅取第一筆」擴充為完整陣列 secondaryIps，render 端同步逐筆輸出）
  const secLines=(iface.secondaryIps||[]).filter(s=>!s.includes(':')).map(s=>{
    const [sip,slen]=s.split('/');
    return sip&&slen?` ip address ${sip} ${maskFromCidr(slen)} sub`:'';
  }).filter(Boolean);
  if(iface.ip){
    if(iface.ip.includes(':')){
      lines.push(` ipv6 address ${iface.ip}`);
    }else if(iface.type==='svi'){
      const [ip,len]=iface.ip.split('/');
      lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
      secLines.forEach(l=>lines.push(l));
    }else{
      lines.push(` ip address ${iface.ip}`);
      if(iface.type==='loopback')secLines.forEach(l=>lines.push(l));
    }
  }
  const lg=findLacpGroup(lacpList,iface.name);
  // VLAN/link-type 屬於官方文件定義的 class-two 屬性，member port 加入聚合組時必須與
  // Bridge-Aggregation 介面一致，否則會被拒絕（"Can't assign the port to the aggregation
  // group because its attribute configurations are different than the aggregate interface"）；
  // 官方建議做法是這組屬性只設在聚合介面上（會自動同步給 member port），member port 自己
  // 不再輸出，改由 renderComwareLACPExtra() 統一輸出在 Bridge-Aggregation 介面上
  if(!lg)lines.push(...comwareL2Lines(iface));
  if(lg){
    lines.push(` port link-aggregation group ${lg.id}`);
    if(lg.mode==='active')lines.push(' lacp mode active');
    else if(lg.mode==='passive')lines.push(' lacp mode passive');
  }
  comwareOspf6IfaceLines(ospf6List,iface.name).forEach(l=>lines.push(l));
  if(iface.jumbo&&iface.jumbo.enabled&&iface.jumbo.mtu)lines.push(` jumboframe enable ${iface.jumbo.mtu}`);
  if(iface.shutdown)lines.push(' shutdown');
  findAclApplications(aclList,iface.name).forEach(ap=>lines.push(` packet-filter ${ap.name} ${ap.direction==='out'?'outbound':'inbound'}`));
  // class-map/match 介面套用（2026-08-31 新增）：官方語法為 "qos apply policy NAME
  // {inbound|outbound}"（非 Cisco 式 "service-policy"），見 parseComwareServicePolicy()
  // 對應註解；findQosApplications() 內部方向欄位統一為 input/output，此處轉回 Comware
  // 官方字面用詞
  findQosApplications(qosApplyList,iface.name).forEach(ap=>lines.push(` qos apply policy ${ap.policy} ${ap.direction==='input'?'inbound':'outbound'}`));
  const sec=findSecurityForPort(securityList,iface.name);
  if(sec){
    // 2026-07-22 對外查證官方 H3C 802.1X 文件後修正：Comware 完全沒有 `dot1x pae`
    // 這個關鍵字（憑空捏造，可能是與 Cisco/華為 VRP 語法混淆），802.1X 只有裸 `dot1x`
    // 一種啟用形式，且不區分 authenticator/supplicant 角色（交換器埠一律是 authenticator
    // 行為）；同時真實語法要求系統視圖也要啟用一次，見 assembleComwareConfig() 開頭
    if(sec.dot1x==='auth'||sec.dot1x==='supp')lines.push(' dot1x');
    if(sec.portSec){
      lines.push(' port-security enable');
      if(sec.maxMac)lines.push(` port-security max-mac-count ${sec.maxMac}`);
      // 2026-07-22 對外查證官方文件後修正：真實關鍵字是 `port-security intrusion-mode`，
      // 且值域固定為 blockmac/disableport/disableport-temporarily 三種，非任意字串；表單
      // 沿用跨廠牌共用的 shutdown/restrict/protect 慣用詞彙輸入，此處對應到最接近的真實模式
      if(sec.violation){
        const intrusionMap={shutdown:'disableport',restrict:'blockmac',protect:'blockmac',drop:'blockmac'};
        const mode=intrusionMap[String(sec.violation).toLowerCase()]||'blockmac';
        lines.push(` port-security intrusion-mode ${mode}`);
      }
    }
    if(sec.guestVlan)lines.push(` dot1x guest-vlan ${sec.guestVlan}`);
  }
  const sp=findStpForPort(stp,iface.name);
  if(sp){
    if(sp.portfast)lines.push(' stp edged-port enable');
    if(sp.bpduguard)lines.push(' stp bpdu-protection');
    if(sp.guardRoot)lines.push(' stp root-protection');
    if(sp.cost)lines.push(` stp cost ${sp.cost}`);
    if(sp.priority)lines.push(` stp port priority ${sp.priority}`);
  }
  // PoE 配置（Comware）：2026-07-22 對外查證官方 H3C PoE 文件後修正——原本的
  // `power supply mode {auto|shutdown|fixed-max|high}` 完全是憑空捏造，官方指令是
  // `poe enable`／`poe priority {critical|high|low}`／`poe max-power N` 等，與表單原本
  // 的 auto/never/static-max/static-high 四選一模式選單無法逐字對應（沒有「模式」這個
  // 概念）。在表單未重新設計前，只輸出可確定安全對應的部分：poeMode 非 none/never 時
  // 視為「啟用 PoE」，僅輸出 `poe enable`，不臆測 priority/max-power 對應值
  if(iface.poeMode&&iface.poeMode!=='none'&&iface.poeMode!=='never'){
    lines.push(' poe enable');
  }
  lines.push('#');
  return lines.join('\n');
}
function renderComwareInterfaces(ifaces,lacpList,aclList,securityList,stp,breakouts,ospf6List,qosApplyList){return ifaces.map(i=>renderComwareInterface(i,lacpList,aclList,securityList,stp,breakouts,ospf6List,qosApplyList)).join('\n');}

// class-map/match（2026-08-31 新增）：官方 H3C QoS Commands 手冊查證，語法家族與 Cisco
// 完全不同，見 switch-analyzer-parser-comware.js 的 parseComwareClassMaps() 對應註解。
// 容器語法為 "qos policy NAME" + 巢狀 "classifier NAME behavior NAME"，但本功能範圍僅需要
// 輸出「分類器 + 比對條件」本身（traffic classifier/if-match），policy/classifier/behavior
// 三段式關聯不在本功能範圍（沿用既有 parseQoS() comware 分支已支援的 {policy,cls,behavior}
// 動作模型，避免重複定義同一個 qos policy 容器）。matchType 為內部統一命名
// （match-any/match-all），輸出時轉回 Comware 官方 "or"/"and" 運算子字面值
function renderComwareClassMapQoS(list){
  const blocks=[];
  groupClassMapMatches(list).forEach((grp,name)=>{
    const op=grp.matchType==='match-any'?'or':'and';
    const lines=[`traffic classifier ${name} operator ${op}`];
    grp.matches.forEach(mt=>{
      if(!mt.type||!mt.value)return;
      if(mt.type==='access-group')lines.push(` if-match acl ${mt.value}`);
      else if(mt.type==='dscp')lines.push(` if-match dscp ${mt.value}`);
      else if(mt.type==='ip-precedence')lines.push(` if-match ip-precedence ${mt.value}`);
      else if(mt.type==='protocol')lines.push(` if-match protocol ${mt.value}`);
      else if(mt.type==='vlan')lines.push(` if-match customer-vlan-id ${mt.value}`);
    });
    blocks.push(lines.join('\n'));
  });
  return blocks.join('\n#\n');
}

function renderComwareLACPExtra(lacpList,ifaces){
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  const blocks=[];
  (lacpList||[]).forEach(l=>{
    const aggLines=[`interface Bridge-Aggregation${l.id}`];
    // class-two（VLAN/link-type）屬性統一設在聚合介面上，來源取該群組第一個有填寫 interface
    // 設定的 member（理論上同一組所有 member 都該一致，若表單填的不一致由 validateForm() 提示，
    // 見 comwareLacpAttrWarnings()）
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    aggLines.push(...comwareL2Lines(refIface));
    if(l.mode!=='static')aggLines.push(' link-aggregation mode dynamic');
    aggLines.push('#');
    blocks.push(aggLines.join('\n'));
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return; // 已在 renderComwareInterfaces 內嵌，不需再輸出獨立區塊
      const lines=[`interface ${mem}`,` port link-aggregation group ${l.id}`];
      if(l.mode==='active')lines.push(' lacp mode active');
      else if(l.mode==='passive')lines.push(' lacp mode passive');
      lines.push('#');
      blocks.push(lines.join('\n'));
    });
  });
  return blocks.join('\n');
}

function renderComwareVRRPGroup(g){
  const lines=[`interface Vlan-interface${g.vlanId}`];
  if(g.ip){
    const [ip,len]=g.ip.split('/');
    lines.push(` ip address ${ip} ${maskFromCidr(len)}`);
  }
  g.entries.forEach(v=>{
    if(v.vip)lines.push(` vrrp vrid ${v.vrid} virtual-ip ${v.vip}`);
    // IPv6（2026-08-23 新增）：官方 H3C VRRP commands 手冊確認 `vrrp ipv6 vrid N` 是與
    // IPv4 `vrrp vrid N` 平行的獨立指令，非同一 vrid 底下的欄位差異
    if(v.vip6)lines.push(` vrrp ipv6 vrid ${v.vrid} virtual-ip ${v.vip6}`);
    lines.push(` vrrp vrid ${v.vrid} priority ${v.priority}`);
    if(v.preempt)lines.push(` vrrp vrid ${v.vrid} preempt-mode`);
    // authentication-mode/track interface 2026-07-22 對外查證官方文件後新增（先前解析器已
    // 支援讀取但產生器完全沒有對應輸出，資料單向遺失）
    if(v.authMode&&v.authKey)lines.push(` vrrp vrid ${v.vrid} authentication-mode ${v.authMode} ${v.authKey}`);
    if(v.trackIf)lines.push(` vrrp vrid ${v.vrid} track interface ${v.trackIf}${v.trackReduced?' reduced '+v.trackReduced:''}`);
  });
  lines.push('#');
  return lines.join('\n');
}
function renderComwareVRRP(list){return groupVrrpByVlan(list).map(renderComwareVRRPGroup).join('\n');}

function renderComwareOSPFProcess(o){
  const lines=[`ospf ${o.pid}${o.routerId?' router-id '+o.routerId:''}`];
  (o.redistributes||[]).forEach(r=>lines.push(` import-route ${r}`));
  (o.areas||[]).forEach(a=>{
    lines.push(` area ${a.area}`);
    (a.networks||[]).forEach(n=>lines.push(`  network ${n.network} ${n.wildcard}`));
    // stub/nssa 巢狀宣告在 area 區塊內（與 network 同縮排層級），對應 switch_analyzer parseOSPF 修正後的偵測邏輯。
    // no-summary 修飾詞 2026-07-22 對外查證官方 H3C 文件後新增（先前解析器/產生器皆未處理，資料遺失）
    if(a.type==='stub')lines.push(a.noSummary?'  stub no-summary':'  stub');
    else if(a.type==='nssa')lines.push(a.noSummary?'  nssa no-summary':'  nssa');
  });
  lines.push('#');
  return lines.join('\n');
}
function renderComwareOSPF(list){return (list||[]).map(renderComwareOSPFProcess).join('\n');}

// OSPFv3（2026-08-23 新增）：獨立頂層指令樹（非 "ospf N" 底下子模式），area 在此區塊內
// 只是存在宣告（無巢狀 network 陳述式），真正的介面成員關係由 comwareOspf6IfaceLines()
// 在逐介面 render 時輸出 "ospfv3 PID area AREA"
function renderComwareOSPFv3Process(o){
  // 注意：不同於 IPv4 renderComwareOSPFProcess，parseOSPFv3() 的頂層正則
  // `/^ospfv3\s+(\d+)\s*\n(...)/` 要求 pid 後立刻換行，router-id 必須是獨立的縮排行，
  // 不能像 v4 那樣同行輸出（v4 的 parseOSPF() 正則額外允許同行 router-id，v6 沒有這個容錯）
  const lines=[`ospfv3 ${o.pid}`];
  if(o.routerId)lines.push(` router-id ${o.routerId}`);
  (o.areas||[]).forEach(a=>lines.push(` area ${a.area}`));
  lines.push('#');
  return lines.join('\n');
}
function renderComwareOSPFv3(list){return (list||[]).map(renderComwareOSPFv3Process).join('\n');}

function renderComwareBGP(b){
  const lines=[`bgp ${b.asn}`];
  if(b.routerId)lines.push(` router-id ${b.routerId}`);
  // 2026-07-24 新增：peer-group／timer 皆為 BGP process 層級欄位（非逐 peer），比照
  // switch_analyzer parseBGP() 既有查證結果——group 語法 "group NAME [external|internal]"、
  // timer 語法 "timer keepalive N hold N"（官方查證確認關鍵字是 hold 非 holdtime）
  (b.peerGroups||[]).forEach(g=>lines.push(` group ${g.name}${g.type?' '+g.type:''}`));
  (b.peers||[]).forEach(p=>{
    lines.push(` peer ${p.ip} as-number ${p.as}`);
    if(p.desc)lines.push(` peer ${p.ip} description ${p.desc}`);
  });
  (b.networks||[]).forEach(n=>lines.push(` network ${n}`));
  // IPv6（2026-08-23 新增）：官方 H3C BGP Commands 手冊確認 network 巢狀在獨立的
  // address-family ipv6 子模式內，語法為空格分隔的 "network ADDR PREFIXLEN"（非 slash-CIDR），
  // 子模式以自己的一行 '#' 自我終結，比照本檔其餘 Comware 巢狀子模式慣例
  if(b.networks6&&b.networks6.length){
    lines.push(' address-family ipv6');
    b.networks6.forEach(n=>{
      const [addr,len]=n.split('/');
      lines.push(`  network ${addr} ${len}`);
    });
    lines.push(' #');
  }
  if(b.timers&&b.timers.keepalive&&b.timers.holdtime)lines.push(` timer keepalive ${b.timers.keepalive} hold ${b.timers.holdtime}`);
  lines.push('#');
  return lines.join('\n');
}
function renderComwareBGPList(list){return (list||[]).map(renderComwareBGP).join('\n');}

function renderComwareRIP(r){
  // vrf（2026-07-27 補上）：parseRIP() 的 "rip N vpn-instance NAME" 頭行有解析 vpn-instance，
  // render 端從未輸出過
  const lines=[`rip ${r.pid}${r.vrf?' vpn-instance '+r.vrf:''}`];
  if(r.version)lines.push(` version ${r.version}`);
  (r.networks||[]).forEach(n=>lines.push(` network ${n}`));
  (r.redistribute||[]).forEach(x=>lines.push(` import-route ${x}`));
  // 2026-07-24 新增：比照 switch_analyzer parseRIPBlock() 既有查證結果——silent-interface
  // 是 passive-interface 的 Comware 對應、裸 summary 是 auto-summary 對應、default cost N
  // 是 default-metric 對應
  (r.passive||[]).forEach(i=>lines.push(` silent-interface ${i}`));
  // peers／timers（2026-07-27 補上）：parseRIPBlock() 已解析 peer/neighbor 與 timers
  // (basic) 行，render 端從未輸出過
  (r.peers||[]).forEach(p=>lines.push(` peer ${p}`));
  if(r.autoSummary)lines.push(` summary`);
  if(r.timers)lines.push(` timers ${r.timers}`);
  if(r.defaultMetric)lines.push(` default cost ${r.defaultMetric}`);
  lines.push('#');
  return lines.join('\n');
}
function renderComwareRIPList(list){return (list||[]).map(renderComwareRIP).join('\n');}

function renderComwareRoute(r){
  const [net,len]=r.dst.split('/');
  // vrf（2026-08-08 查證修正）：H3C 官方 Command Reference 確認 vpn-instance 子句緊接在
  // "ip route-static" 關鍵字之後（該路由所屬 VRF），並非結尾子句；parseRoutes() 已同步修正
  // IPv6（2026-08-23 新增）：官方語法 "ipv6 route-static [vpn-instance NAME] ADDR PREFIXLEN
  // NEXTHOP"，token 結構與 IPv4 版本相同，僅關鍵字換成 ipv6 route-static
  const kw=r.dst.includes(':')?'ipv6 route-static':'ip route-static';
  return `${kw} ${r.vrf?'vpn-instance '+r.vrf+' ':''}${net} ${len} ${r.gw}`;
}
function renderComwareRoutes(list){return (list||[]).map(renderComwareRoute).join('\n')+'\n#';}

// DHCP：server pool（Style A）+ relay（全域層級，Comware 無逐介面 relay 概念）
function renderComwareDHCPPool(d){
  const lines=[`dhcp server ip-pool ${d.name}`];
  if(d.network){
    const [net,len]=d.network.split('/');
    lines.push(` network ${net} mask ${maskFromCidr(len)}`);
  }
  if(d.gateway)lines.push(` gateway-list ${d.gateway}`);
  if(d.dns)lines.push(` dns-list ${d.dns.trim().split(/\s+/).join(' ')}`);
  if(d.range){
    const [lo,hi]=d.range.split('-');
    lines.push(` address range ${lo} ${hi}`);
  }
  // 2026-07-22 對外查證官方 H3C 文件後修正：forbidden-ip 官方語法是「一個範圍一行、
  // 可重複」(forbidden-ip low-ip [high-ip])，不是單行空白分隔的位址清單（該假設本身
  // 也是本次查證前的誤判）。parseDHCP() 端已改用 '; ' 分隔多筆 forbidden-ip 行，這裡
  // 依相同分隔符還原成多行
  (d.excluded||'').split(';').map(s=>s.trim()).filter(Boolean).forEach(range=>{
    lines.push(` forbidden-ip ${range}`);
  });
  if(d.lease)lines.push(` expired day ${d.lease}`);
  // bootFile／nextServer／ntpServer（2026-07-27 補上）：parseDHCP() comware 分支已解析
  // bootfile-name／next-server（備援 tftp-server ip-address）／option 42 ip-address，
  // render 端一個都沒接上
  if(d.bootFile)lines.push(` bootfile-name ${d.bootFile}`);
  if(d.nextServer)lines.push(` next-server ${d.nextServer}`);
  if(d.ntpServer)lines.push(` option 42 ip-address ${d.ntpServer}`);
  lines.push('#');
  return lines.join('\n');
}
function renderComwareDHCP(list){
  const servers=(list||[]).filter(d=>d.type==='server');
  const relays=(list||[]).filter(d=>d.type==='relay'&&d.interface&&d.relayServer);
  const blocks=[];
  if(servers.length){blocks.push('dhcp enable'); blocks.push(...servers.map(renderComwareDHCPPool));}
  // 2026-07-22 對外查證官方 H3C 文件後修正：`dhcp relay server-address` 從來不是全域指令，
  // 必須巢狀在 `interface Vlan-interface X` 內（搭配 `dhcp select relay` 宣告該介面走
  // relay 模式）。原本假設的「Comware 支援全域 relay」是誤判，故 Comware 現在也和其他廠牌
  // 一樣需要填寫 Interface 欄位；接受使用者填純數字（VLAN ID）或完整介面名稱兩種輸入
  const relayGroups=new Map();
  relays.forEach(d=>{
    const ifName=/^Vlan-interface/i.test(d.interface)?d.interface:`Vlan-interface${d.interface}`;
    if(!relayGroups.has(ifName))relayGroups.set(ifName,{servers:[],option82:false});
    const g=relayGroups.get(ifName);
    g.servers.push(d.relayServer);
    if(d.option82)g.option82=true;
  });
  relayGroups.forEach((g,ifName)=>{
    const lines=[`interface ${ifName}`,' dhcp select relay'];
    g.servers.forEach(s=>lines.push(` dhcp relay server-address ${s}`));
    // option82（2026-07-27 補上）：parseDHCP() 已解析 interface 層級的
    // `dhcp relay information enable`，render 端從未輸出過
    if(g.option82)lines.push(' dhcp relay information enable');
    lines.push('#');
    blocks.push(lines.join('\n'));
  });
  return blocks.join('\n');
}

// ACL：acl number NUM name NAME 區塊；套用（packet-filter）內嵌進 renderComwareInterface。
// 2026-07-22 對外查證官方 H3C 文件後修正：`acl basic|advanced NUM name NAME` 從未真實存在，
// Comware 只有 `acl [ipv6] number NUM [name NAME]` 一種容器語法，basic/advanced 純粹依號碼
// 區間（2000-2999/3000-3999）區分，不是獨立關鍵字。Comware 語法以「數字」為主要識別碼，
// 「name」只是別名；為了讓使用者填的 ACL 名稱能完整 round-trip（parser 回傳的 name 欄位優先
// 取 alias），一律輸出 name 別名，數字則依廠牌慣例用 basic=2000+idx / advanced=3000+idx
// 自動分配，使用者不需關心實際編號
function renderComwareACLEntry(a,idx){
  // ACL Type 下拉是全廠牌共用元件（value 僅有 extended/standard 兩種，對應 Cisco 等廠牌的
  // 慣用術語），Comware 官方術語雖是 basic/advanced，但表單／collectModel()/parseAndImport()
  // 一律只會產生 'standard'/'extended' 字面值，故此處與匯入橋接改比照共用值判斷，不用
  // 'basic'（原判斷式因表單永遠不會產生 'basic'，等同永遠走 advanced 分支，見稽核記錄）
  const isBasic=a.type==='standard';
  const num=(isBasic?2000:3000)+idx;
  const lines=[`acl number ${num} name ${a.name}`];
  (a.rules||[]).forEach(r=>{
    let line=` rule ${r.seq||0} ${r.action||'permit'}`;
    if(!isBasic)line+=` ${r.protocol||'ip'}`;
    if(r.src)line+=` source ${r.src}`;
    if(r.dst)line+=` destination ${r.dst}`;
    if(r.dstPort)line+=` destination-port eq ${r.dstPort}`;
    lines.push(line);
  });
  lines.push('#');
  return lines.join('\n');
}
function renderComwareACL(list){return (list||[]).map(renderComwareACLEntry).join('\n');}

// QoS：qos policy 區塊僅記錄 classifier-behavior 名稱對應（switch_analyzer 對 Comware
// QoS 的解析本來就只到這個層級，不含實際 rate/burst 動作細節，見 parseQoS 6316-6325 行）。
// 2026-07-22 對外查證官方 H3C 文件後修正：容器關鍵字是 `qos policy`，非 `traffic policy`
// （後者從未在任何官方文件出現過）
function renderComwareQoSEntry(policy,items){
  const lines=[`qos policy ${policy}`];
  items.forEach(q=>lines.push(` classifier ${q.cls} behavior ${q.behavior||q.cls}`));
  lines.push('#');
  return lines.join('\n');
}
function renderComwareQoS(list){
  const blocks=[];
  groupQosByPolicy(list).forEach((items,policy)=>blocks.push(renderComwareQoSEntry(policy,items)));
  return blocks.join('\n');
}

// IRF 堆疊（2026-09-01 新增）：官方 H3C IRF Configuration 手冊確認語法為 `irf domain N`
// （全域，選填，未設定時裝置預設為 1）+ 逐 member `irf member N priority P`；若該 member
// 有填寫連結埠（comwareIrf.members[].ports），額外輸出 `irf-port {id}/1` 區塊（member 自己
// 的第一個 IRF-Port 編號，MVP 範圍僅支援每個 member 一個 IRF-Port，與既有 VSU 卡片
// 「一個 member 一組連結埠」的簡化慣例一致）+ 巢狀 `port group interface X`。
function renderComwareIRF(irf){
  // domain 官方語法本身是選填（未設定時裝置預設為 1，見表單 placeholder），與「完全沒有
  // IRF 設定」是兩回事——守門條件只看 members 是否有資料，domain 留空時省略該行即可，
  // 不能連 irf member 這幾行也一起砍掉（2026-09-02 審查發現的既有 bug）。
  if(!irf||!(irf.members||[]).length)return '';
  const lines=[];
  if(irf.domain)lines.push(`irf domain ${irf.domain}`);
  (irf.members||[]).forEach(m=>{
    if(m.id&&m.priority)lines.push(`irf member ${m.id} priority ${m.priority}`);
  });
  lines.push('#');
  (irf.members||[]).forEach(m=>{
    if(!(m.ports||[]).length)return;
    lines.push(`irf-port ${m.id}/1`);
    m.ports.forEach(p=>lines.push(`port group interface ${p}`));
    lines.push('#');
  });
  return lines.join('\n');
}

function assembleComwareConfig(model){
  const blocks=[`# ${tr('notice.disclaimer')}`,`sysname ${model.sysname||'Switch'}`,'#'];
  const comwareIrfBlock=renderComwareIRF(model.comwareIrf);
  if(comwareIrfBlock)blocks.push(comwareIrfBlock);
  // 802.1X 官方語法要求系統視圖也要啟用一次（裸 `dot1x`），非只在 interface 視圖內宣告
  // 即可生效；見 renderComwareInterface() 內對應說明
  if((model.security||[]).some(s=>s.dot1x==='auth'||s.dot1x==='supp'))blocks.push('dot1x','#');
  if(model.vlans&&model.vlans.length)blocks.push(renderComwareVLANs(model.vlans));
  // VRF（Comware 稱 VPN instance）：官方文件確認 `ip binding vpn-instance NAME` 要求該
  // vpn-instance 已用 `ip vpn-instance NAME` 建立，故排在所有會引用 vrf 的區塊（Interfaces/
  // RIP/Routes）之前輸出，僅建立裸 vpn-instance（不含 route-distinguisher，本工具未收集
  // 該欄位，MPLS L3VPN 情境才需要，本機 VRF 隔離不需要）
  const comwareVrfNames=collectVrfNames(model.interfaces);
  if(comwareVrfNames.length)blocks.push(comwareVrfNames.map(n=>`ip vpn-instance ${n}\n#`).join('\n'));
  if(model.acl&&model.acl.length)blocks.push(renderComwareACL(model.acl));
  // Bridge-Aggregation 必須排在 member port 之前輸出：member port 執行 port
  // link-aggregation group 那一刻，聚合介面若還沒設定 VLAN/link-type（停留在預設值），
  // 會被判定屬性不符而拒絕加入（見上方 comwareL2Lines() 說明）
  const lacpExtra=renderComwareLACPExtra(model.lacp,model.interfaces);
  if(lacpExtra)blocks.push(lacpExtra);
  if(model.interfaces&&model.interfaces.length)blocks.push(renderComwareInterfaces(model.interfaces,model.lacp,model.acl,model.security,model.stp,model.breakouts,model.ospf6,model.qosApply));
  if(model.vrrp&&model.vrrp.length)blocks.push(renderComwareVRRP(model.vrrp));
  if(model.dhcp&&model.dhcp.length)blocks.push(renderComwareDHCP(model.dhcp));
  // class-map(traffic classifier) 必須先於引用它的 qos policy 定義，比照 Cisco/Arista/
  // Dell OS10 既有慣例（2026-08-31 新增）
  if(model.classMaps&&model.classMaps.length)blocks.push(renderComwareClassMapQoS(model.classMaps));
  if(model.qos&&model.qos.length)blocks.push(renderComwareQoS(model.qos));
  const stpBlock1=renderComwareSTP(model.stp);
  if(stpBlock1)blocks.push(stpBlock1);
  if(model.ospf&&model.ospf.length)blocks.push(renderComwareOSPF(model.ospf));
  if(model.ospf6&&model.ospf6.length)blocks.push(renderComwareOSPFv3(model.ospf6));
  if(model.rip&&model.rip.length)blocks.push(renderComwareRIPList(model.rip));
  if(model.routes&&model.routes.length)blocks.push(renderComwareRoutes(model.routes));
  const comwareVxlan=renderComwareVXLAN(model.vxlan);
  if(comwareVxlan)blocks.push(comwareVxlan);
  const comwareUsersBlock=renderComwareUsers(model.users);
  if(comwareUsersBlock)blocks.push(comwareUsersBlock);
  if(model.snmpTrapHost)blocks.push(`snmp-agent target-host trap address udp-domain ${model.snmpTrapHost} params securityname public v2c`,'#');
  if(model.syslogServer)blocks.push(`info-center loghost ${model.syslogServer}`,'#');
  // bgp 放最後：其區塊擷取正則靠負向前瞻(bgp/router/interface/ip route/vlan)判斷結尾，
  // 沒有明確終止字元，若後面還接其他區塊可能被吃進 body，故排在組裝順序最後最安全
  if(model.bgp&&model.bgp.length)blocks.push(renderComwareBGPList(model.bgp));
  return blocks.join('\n');
}
// 本機帳號：switch_analyzer 的 parseUsers()（Comware 分支）以 "#" 自我終結的 local-user 區塊
// 為單位，欄位為 user-role（role）／service-type／password hash|cipher|simple；產生器固定
// 輸出 password hash（非 weak 的 simple 明文）＋ service-type ssh telnet（常見管理存取方式）
function renderComwareUsers(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  return list.map(u=>`local-user ${u.name}\n password hash ${u.password}\n service-type ssh telnet\n user-role ${u.role||'network-operator'}\n#`).join('\n');
}

// ══════════════════════════════════════════════════════════════════
// FortiSwitch standalone render 函式（FortiOS 區塊風格：config X ... edit ... next ... end）
// ══════════════════════════════════════════════════════════════════

