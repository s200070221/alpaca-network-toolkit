function renderAlcatelVLANs(vlans,interfaces){
  const taggedMap={},untaggedMap={};
  (interfaces||[]).forEach(iface=>{
    if(!iface.name)return;
    if(iface.mode==='trunk'){
      (iface.trunkVlans||'').split(',').map(s=>s.trim()).filter(Boolean).forEach(vid=>{
        if(!taggedMap[vid])taggedMap[vid]=[];
        taggedMap[vid].push(iface.name);
      });
      if(iface.nativeVlan){
        if(!untaggedMap[iface.nativeVlan])untaggedMap[iface.nativeVlan]=[];
        untaggedMap[iface.nativeVlan].push(iface.name);
      }
    }else if(iface.mode==='access'&&iface.accessVlan){
      if(!untaggedMap[iface.accessVlan])untaggedMap[iface.accessVlan]=[];
      untaggedMap[iface.accessVlan].push(iface.name);
    }
  });
  return (vlans||[]).map(v=>{
    const lines=[`vlan ${v.id} admin-state enable`];
    if(v.name)lines.push(`vlan ${v.id} name "${v.name}"`);
    (taggedMap[String(v.id)]||[]).forEach(p=>lines.push(`vlan ${v.id} members port ${p} tagged`));
    (untaggedMap[String(v.id)]||[]).forEach(p=>lines.push(`vlan ${v.id} members port ${p} untagged`));
    return lines.join('\n');
  }).join('\n!\n');
}

// LACP：AOS 用純數字 linkagg ID，無獨立名稱概念（parseAlcatelLACP 對 name 欄位固定
// 回傳 'agg'+ID、mode 固定回傳 'active'，皆非從設定檔實際解析而來，故 render 端不需
// 依賴 model 傳入的 l.mode）
// VRRP：已查證真實語法為逐行個別指令（vrrp <vrid> <vlan_id> ip/priority/preempt/enable），
// 比照既有 groupVrrpByVlan() 慣例先依 VLAN 分組，同一 VLAN 下每個 VRID 各自輸出一組指令
function renderAlcatelVRRP(vrrpList){
  const groups=groupVrrpByVlan(vrrpList);
  return groups.map(g=>{
    const lines=[];
    (g.entries||[]).forEach(e=>{
      if(e.vip)lines.push(`vrrp ${e.vrid} ${g.vlanId} ip ${e.vip}`);
      if(e.priority)lines.push(`vrrp ${e.vrid} ${g.vlanId} priority ${e.priority}`);
      if(e.preempt)lines.push(`vrrp ${e.vrid} ${g.vlanId} preempt`);
      lines.push(`vrrp ${e.vrid} ${g.vlanId} enable`);
    });
    return lines.join('\n');
  }).join('\n!\n');
}

// 官方 OmniSwitch CLI Reference Guide 確認語法：群組本身用 `linkagg lacp agg <id> ...`
// 三行各自宣告（size/admin-state/actor admin-key），成員埠透過 admin-key 數值相符達成聚合
// （IEEE 802.3ad 標準機制），用 `linkagg lacp port <slot/port> actor admin-key <id>` 逐行加入
function renderAlcatelLACPGroup(l){
  const members=l.members||[];
  const lines=[
    `linkagg lacp agg ${l.id} size ${members.length}`,
    `linkagg lacp agg ${l.id} admin-state enable`,
    `linkagg lacp agg ${l.id} actor admin-key ${l.id}`
  ];
  members.forEach(m=>lines.push(`linkagg lacp port ${m} actor admin-key ${l.id}`));
  return lines.join('\n');
}
function renderAlcatelLACP(list){return (list||[]).map(renderAlcatelLACPGroup).join('\n!\n');}

// 靜態路由：AOS 需要 dotted mask（非 CIDR），model.routes[].dst 為 CIDR 字串需轉換
// IPv6（2026-08-23 新增）：官方語法 "ipv6 static-route PREFIX/LEN gateway ADDR"，
// prefix/length 已是單一 slash-CIDR token，不需 mask 換算
function renderAlcatelRoute(r){
  if(r.dst.includes(':'))return `ipv6 static-route ${r.dst} gateway ${r.gw}`;
  const [net,len]=r.dst.split('/');
  return `ip route ${net} ${maskFromCidr(len)} ${r.gw}`;
}
function renderAlcatelRoutes(list){return (list||[]).map(renderAlcatelRoute).join('\n');}

function renderAlcatelOSPFGlobal(list){
  return (list||[]).map(o=>{
    const lines=[];
    if(o.routerId)lines.push(`ip ospf router-id ${o.routerId}`);
    (o.areas||[]).forEach(a=>{
      (a.networks||[]).forEach(n=>{
        if(n.network)lines.push(`ip ospf interface "${n.network}" area ${a.area}`);
      });
    });
    lines.push('ip ospf admin-state enable');
    return lines.join('\n');
  }).join('\n!\n');
}

// OSPFv3（2026-08-23 新增）：官方 OmniSwitch CLI Reference Guide 確認完整指令家族
// `ipv6 ospf admin-state`／`ipv6 ospf area X`（獨立宣告，與 IPv4 不同——v4 沒有裸 area
// 宣告，area 純粹靠 interface 行引用）／`ipv6 ospf interface "X" area Y`
function renderAlcatelOSPFv3Global(list){
  return (list||[]).map(o=>{
    const lines=[];
    if(o.routerId)lines.push(`ipv6 ospf router-id ${o.routerId}`);
    (o.areas||[]).forEach(a=>{
      lines.push(`ipv6 ospf area ${a.area}`);
      (a.interfaces||[]).forEach(ifname=>{ if(ifname)lines.push(`ipv6 ospf interface "${ifname}" area ${a.area}`); });
    });
    lines.push('ipv6 ospf admin-state enable');
    return lines.join('\n');
  }).join('\n!\n');
}

// BGP／user 類指令在 AOS 是獨立子模式，慣例上每行都帶 "->" 前綴（已查證真實 fixture
// 與 parseAlcatelBGP 皆要求此前綴，跟 OSPF/VLAN 的 "->" 為選填不同）
// Networks（2026-07-17 對外查證官方 OmniSwitch AOS Release 8 Advanced Routing
// Configuration Guide「Configuring Local Routes (Networks)」章節確認）：`-> ip bgp
// network <ip> <mask>` + 需額外一行 `-> ip bgp network <ip> <mask> admin-state enable`
// 才會生效（跟 neighbor 用兩個獨立指令不同，這裡是同一行接關鍵字），點分遮罩格式非
// CIDR，用既有 maskFromCidr() 轉換
function renderAlcatelBGP(b){
  const lines=[`-> ip bgp autonomous-system ${b.asn}`];
  if(b.routerId)lines.push(`-> ip bgp router-id ${b.routerId}`);
  (b.networks||[]).forEach(n=>{
    const [ip,len]=n.split('/');
    if(ip&&len){
      const mask=maskFromCidr(len);
      lines.push(`-> ip bgp network ${ip} ${mask}`);
      lines.push(`-> ip bgp network ${ip} ${mask} admin-state enable`);
    }
  });
  (b.peers||[]).forEach(p=>{
    lines.push(`-> ip bgp neighbor ${p.ip} remote-autonomous-system ${p.as}`);
    if(p.desc)lines.push(`-> ip bgp neighbor ${p.ip} description ${p.desc}`);
  });
  lines.push('-> ip bgp admin-state enable');
  return lines.join('\n');
}
function renderAlcatelBGPList(list){return (list||[]).map(renderAlcatelBGP).join('\n!\n');}

// Interface 額外欄位（desc/shutdown/SVI ip）：parseAlcatelInterfaces() 已解析
// alias（desc）、admin-state disable（shutdown）、ip interface（SVI ip，CIDR），
// 但 assembleAlcatelConfig() 此前完全未輸出，是未文件化的真缺口（非 CLAUDE.md
// 既有排除清單記載項目）。語法比照 parser 端既有正則的 "->" 前綴慣例：
//   -> interfaces PORT alias "DESC"
//   -> interfaces PORT admin-state disable
// SVI/Loopback ip 為傳統點分遮罩（非 CIDR）：ip interface "NAME" address IP mask MASK，
// 沿用既有 maskFromCidr() 轉換，不重新發明。
// 注意：parseAlcatelInterfaces() 目前完全沒有解析 vrf（interfaces 物件的 vrf 欄位
// 對 Alcatel 一律固定回傳空字串，非本次審計誤植），真實 AOS VRF-Lite 綁定語法尚未
// 對外查證，故本次僅修復 desc/shutdown/ip 三項，vrf 留待日後查證後再處理，避免
// 貿然渲染未經確認的假語法
function renderAlcatelInterfaceExtras(interfaces){
  const lines=[];
  (interfaces||[]).forEach(iface=>{
    if(!iface.name)return;
    if(iface.type==='svi'||iface.type==='loopback'){
      if(iface.ip){
        if(iface.ip.includes(':')){
          // IPv6 為兩段式指令，結構與 IPv4 單行語法不同：先建立具名 IPv6 介面
          // （綁定 VLAN 或 loopback0），再指派位址（位址在前、介面名稱在後）
          const bind=iface.type==='loopback'?'loopback0':`vlan ${iface.vlans}`;
          lines.push(`ipv6 interface "${iface.name}" ${bind}`);
          lines.push(`ipv6 address ${iface.ip} "${iface.name}"`);
        }else{
          const [ip,len]=iface.ip.split('/');
          if(ip&&len)lines.push(`ip interface "${iface.name}" address ${ip} mask ${maskFromCidr(len)}`);
        }
      }
    }else{
      if(iface.desc)lines.push(`-> interfaces ${iface.name} alias "${iface.desc}"`);
      if(iface.shutdown)lines.push(`-> interfaces ${iface.name} admin-state disable`);
    }
  });
  return lines.join('\n');
}

// DHCP：parseDHCP() 通用 dispatcher 對 alcatel 已有專屬分支（三種 server pool 寫法＋
// 三種 relay 寫法皆已查證），此前 assembleAlcatelConfig() 完全未接線。輸出端各選一種
// 有天然收尾關鍵字／欄位對應最單純的寫法：server 用「Style B」`dhcp server pool "NAME"`
// 區塊（以 `exit` 自我終結，不受「檔案最後一段」regex 邊界問題影響）；relay 用「Style A」
// `-> ip interface X helper-address Y`（與本專案 DHCP Relay 表格的 Interface 欄位一對一
// 對應，不需要額外的全域/逐 VLAN 判斷）。lease 欄位因 parser 只認純數字（`lease\s+(\d+)`，
// 語意未知，非本專案其餘廠牌慣用的 "Nh"/"Nd" 字串），故僅取開頭數字部分輸出
// DHCP server pool：2026-07-22 對外查證官方 AOS 文件後停用——真實 AOS 完全沒有
// 「dhcp server pool」這類 CLI 指令，DHCP Server 是透過上傳 ISC dhcpd 語法的
// dhcpd.conf/dhcpd.cpy 檔案設定（非逐行 CLI 指令），CLI 只有 `dhcp-server
// {enable|disable|restart}` 這種服務開關指令，本質上無法用產生設定文字的方式表達，
// 原本整段輸出完全捏造，先前解析器（parseAlcatel()）也從未支援讀取（dhcp:[] 是寫死
// 空陣列），parser/generator 兩側從未互相驗證過
function renderAlcatelDHCPPool(d){
  return '';
}
// DHCP relay：2026-07-22 對外查證官方 AOS CLI Reference 後修正——原本誤植為巢狀在
// `ip interface NAME` 底下的 `helper-address`，真實是獨立全域指令
// `ip helper address <server-ip> vlan <vlan-id>`（關鍵字是 address 非 helper-address，
// 且不巢狀在 ip interface 底下），需先執行一次 `ip helper per-vlan-only` 切換到逐 VLAN
// 模式
function renderAlcatelDHCPRelay(d){return `-> ip helper address ${d.relayServer} vlan ${d.interface}`;}
function renderAlcatelDHCP(list){
  const relays=(list||[]).filter(d=>d.type==='relay'&&d.interface&&d.relayServer);
  if(!relays.length)return '';
  return ['-> ip helper per-vlan-only',...relays.map(renderAlcatelDHCPRelay)].join('\n');
}

// Stack 堆疊（2026-09-01 新增）：官方 Alcatel-Lucent OmniSwitch 文件確認持久化格式
// `stacking slot N priority P`（boot.cfg 寫法，非互動式 `stack set slot N`）——選用此格式
// 因為它才是真正「存進設定檔」的形式，且同時帶有 priority 資訊（互動式格式無 priority 概念）
function renderAlcatelStack(stack){
  const lines=[];
  (stack&&stack.members||[]).forEach(m=>{
    if(m.id&&m.priority)lines.push(`stacking slot ${m.id} priority ${m.priority}`);
  });
  return lines.join('\n');
}

function assembleAlcatelConfig(model){
  const blocks=[`! ${tr('notice.disclaimer')}`,`system name ${model.sysname||'Switch'}`];
  const alcatelStackBlock=renderAlcatelStack(model.alcatelStack);
  if(alcatelStackBlock)blocks.push(alcatelStackBlock);
  const vlanBlockAl=renderAlcatelVLANs(model.vlans,model.interfaces);
  if(vlanBlockAl)blocks.push(vlanBlockAl);
  const ifExtrasAl=renderAlcatelInterfaceExtras(model.interfaces);
  if(ifExtrasAl)blocks.push(ifExtrasAl);
  const vrrpBlockAl=renderAlcatelVRRP(model.vrrp);
  if(vrrpBlockAl)blocks.push(vrrpBlockAl);
  const lacpBlockAl=renderAlcatelLACP(model.lacp);
  if(lacpBlockAl)blocks.push(lacpBlockAl);
  if(model.routes&&model.routes.length)blocks.push(renderAlcatelRoutes(model.routes));
  if(model.ospf&&model.ospf.length)blocks.push(renderAlcatelOSPFGlobal(model.ospf));
  if(model.ospf6&&model.ospf6.length)blocks.push(renderAlcatelOSPFv3Global(model.ospf6));
  if(model.bgp&&model.bgp.length)blocks.push(renderAlcatelBGPList(model.bgp));
  const dhcpBlockAl=renderAlcatelDHCP(model.dhcp);
  if(dhcpBlockAl)blocks.push(dhcpBlockAl);
  if(model.snmpTrapHost)blocks.push(`-> snmp station ${model.snmpTrapHost} "public" v2c enable`);
  return blocks.join('\n!\n')+'\n';
}

// ══════════════════════════════════════════════════════════════════
// SONiC (config_db.json) 產生函式（第 17 個廠牌，MVP 範圍）
//
// SONiC 設定檔本體是貨真價實的 JSON（非文字 CLI），已對外查證官方 schema 文件＋真實範例檔
// （sonic-buildimage Configuration.md、Azure/SONiC gh-pages 範例檔）交叉確認頂層表格結構。
// 這是全新的一種 assemble 函式形狀——不是字串拼接，是組一個 JS 物件，最後統一
// JSON.stringify()。範圍：Hostname／VLAN／VLAN_MEMBER（access/trunk↔untagged/tagged）／
// L3 IP（INTERFACE/VLAN_INTERFACE/PORTCHANNEL_INTERFACE，來自專屬 sonicL3Interfaces
// 卡片，通用 UI 無可重用欄位）／LACP（PORTCHANNEL+PORTCHANNEL_MEMBER，VLAN 歸屬掛在
// PortChannel 名稱下，比照 findLacpGroup 的 refIface 既有慣例）／BGP_NEIGHBOR＋
// DEVICE_METADATA.bgp_asn／STATIC_ROUTE。明確排除 OSPF／ACL／QoS／STP／Security（本輪
// 未查證或查無官方 schema 來源，不可臆測）。JSON 無註解語法，disclaimer 放進
// DEVICE_METADATA.localhost.disclaimer 自訂欄位（該表本身承載描述性中繼資料，不影響
// 任何真實表格語意）。
// ══════════════════════════════════════════════════════════════════
