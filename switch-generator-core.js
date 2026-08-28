
// ══════════════════════════════════════════════════════════════════
// 資料模型（沿用 switch_analyzer 既有 parseVLANs/parseInterfaces/parseHybrid/parseOSPF/parseBGP/parseRIP/
// parseFortiRouting/parseCisco*/parseArubaXXX/parseRoutes/parseLACP/parseVRRP 輸出形狀）:
// {
//   vendor: 'comware'|'fortiswitch'|'aruba'|'cisco', sysname,
//   vlans:[{id,name}],
//   interfaces:[{name,desc,mode,accessVlan,trunkVlans,nativeVlan,hybrid:{pvid,untagged,tagged},shutdown}],
//   ospf:[{pid,routerId,areas:[{area,type,networks:[{network,wildcard}]}],redistributes}],
//   bgp:[{asn,routerId,peers:[{ip,as,desc}],networks:[]}],
//   rip:[{pid,version,networks:[],redistribute:[]}],
//   routes:[{dst /* CIDR */, gw}],
//   lacp:[{id, mode:'static'|'active'|'passive', members:['port1','port2']}],
//   vrrp:[{vlanId, ip /* SVI 自己的 IP，CIDR */, vrid, vip, priority, preempt}],
// }
// FortiSwitch/Aruba CX 無 hybrid port 概念；FortiSwitch 無 rip pid/version、無 OSPF redistribute/type、
// BGP peer 無 desc；Aruba/Cisco OSPF 無 area type/redistribute；Cisco OSPF 為扁平 network+area 逐行宣告（非巢狀 area 區塊）；
// FortiSwitch VRRP 巢狀在 interface 區塊內（無獨立頂層清單），共用 UI 欄位但產生時忽略不適用欄位
// ══════════════════════════════════════════════════════════════════

// 前綴長度 → dotted mask（switch_analyzer 的 cidrFromMask 是反方向；Cisco/FortiSwitch 的 ip address/network 需要這個方向）
function maskFromCidr(len){
  const n=parseInt(len,10);
  if(isNaN(n)||n<0||n>32)return '255.255.255.255';
  if(n===0)return '0.0.0.0'; // JS 位移運算子對 32 取模，<<32 等同 <<0，需特別處理
  const bits=0xffffffff<<(32-n);
  return [24,16,8,0].map(s=>(bits>>>s)&0xff).join('.');
}

// 找出某介面名稱屬於哪個 LACP 群組（若有）。member port 的聚合指令要內嵌在其自己的
// interface 區塊裡（跟主要 VLAN 設定同一個區塊），而不是另外輸出獨立區塊——
// 除了 FortiSwitch 外，多數廠牌的 parser 對同名 interface 區塊的合併行為不一致
// （Comware/Aruba 會合併多個同名區塊，Cisco 不會），內嵌是唯一在所有廠牌下都正確的做法。
function findLacpGroup(lacpList,ifaceName){
  return (lacpList||[]).find(l=>(l.members||[]).includes(ifaceName))||null;
}

// VRF 名稱收集：8 家廠牌（Comware/Aruba CX/Cisco/Dell OS10/Arista/Ruijie/Brocade/NX-OS）的
// interface（含 SVI）都會輸出 `vrf attach`／`ip vrf forwarding` 之類的引用指令，但先前整份
// 產生器從未輸出建立 VRF 本身的區塊——2026-08-06 對外查證多家官方文件確認，這幾家真實設備在
// VRF 不存在時會拒絕介面上的 vrf 綁定指令（或如 NX-OS 是綁定成功但介面停留在 down 狀態直到
// VRF 建立），故新增各廠牌專屬的 VRF 建立區塊 render 函式，統一從這裡收集名稱
function collectVrfNames(interfaces){
  const names=new Set();
  (interfaces||[]).forEach(i=>{ if(i.vrf)names.add(i.vrf); });
  return [...names].sort();
}

// DHCP relay 比照 LACP 同一個內嵌邏輯：Cisco/Aruba CX 的逐介面 relay（ip helper-address）
// 要內嵌進該 port 自己的 interface 區塊，理由同上（Cisco parser 不合併同名 interface 區塊）。
// 一個介面可以有多台 relay 目標，故回傳陣列。interface 欄位留空的列（僅 Comware 全域 relay
// 適用）不會被任何介面比對到，故不影響 Cisco/Aruba 的逐介面輸出。
// 2026-07-27 修正：回傳值從純字串陣列改回傳完整 relay 物件陣列（含 option82），呼叫端改讀
// rel.relayServer——NX-OS／Arista 的 option82 信任旗標（2026-07-24 新增解析）需要這個欄位才能
// 反向輸出，原本只回傳 relayServer 字串會把 option82 資訊丟掉
function findDhcpRelays(dhcpList,ifaceName){
  return (dhcpList||[]).filter(d=>d.type==='relay'&&d.interface===ifaceName);
}

// ACL 套用比照 LACP/DHCP relay 同一個內嵌邏輯：ACL 定義本身（規則清單）是獨立頂層區塊，
// 但「套用到哪個介面」（packet-filter/ip access-group/apply access-list）要內嵌進該 port
// 自己的 interface 區塊，理由同上（Cisco parser 不合併同名 interface 區塊）。
function findAclApplications(aclList,ifaceName){
  const out=[];
  (aclList||[]).forEach(a=>(a.appliedOn||[]).forEach(ap=>{if(ap.interface===ifaceName)out.push({name:a.name,direction:ap.direction||'in'});}));
  return out;
}

// Port Security/802.1X 資料本身就是逐 port 一筆（不像 ACL/QoS 需要先分組），比照
// LACP/DHCP relay/ACL 同一套內嵌邏輯找出某介面對應的設定
function findSecurityForPort(securityList,ifaceName){
  return (securityList||[]).find(s=>s.port===ifaceName)||null;
}

// STP per-port 設定同樣比照內嵌慣例找出某介面對應的設定（stp.ports 為巢狀清單）
function findStpForPort(stp,ifaceName){
  return (stp?.ports||[]).find(p=>p.port===ifaceName)||null;
}
// Breakout：Comware/Aruba CX 的啟用指令內嵌在母埠自己的 interface 區塊，比照上述內嵌慣例查找
function findBreakoutForPort(breakouts,ifaceName){
  return (breakouts||[]).find(b=>b.parentPort===ifaceName)||null;
}
function hasGlobalStpData(stp){
  return !!(stp&&(stp.mode||stp.rootMode||(stp.instances&&stp.instances.length)||(stp.timers&&(stp.timers.hello||stp.timers.forwardDelay||stp.timers.maxAge))));
}

// Comware 全域 STP：單一 Global（id 為空或 '0'）用 "stp priority P"，其餘用
// "stp instance N priority P"（switch_analyzer parseSTP 先掃 "stp instance"，只有完全
// 沒找到時才 fallback 讀 "stp priority"，故兩者混用時 Global 列會被忽略，屬既有行為）
function renderComwareSTP(stp){
  if(!hasGlobalStpData(stp))return '';
  const lines=[];
  if(stp.mode)lines.push(`stp mode ${stp.mode}`);
  (stp.instances||[]).forEach(i=>{
    if(!i.priority)return;
    if(!i.id||i.id==='0')lines.push(`stp priority ${i.priority}`);
    else lines.push(`stp instance ${i.id} priority ${i.priority}`);
  });
  if(stp.rootMode==='primary')lines.push('stp root primary');
  else if(stp.rootMode==='secondary')lines.push('stp root secondary');
  const t=stp.timers||{};
  if(t.hello)lines.push(`stp timer hello ${t.hello}`);
  if(t.forwardDelay)lines.push(`stp timer forward-delay ${t.forwardDelay}`);
  if(t.maxAge)lines.push(`stp timer max-age ${t.maxAge}`);
  lines.push('#');
  return lines.join('\n');
}

// Cisco/Aruba CX 共用：switch_analyzer parseSTP 對這兩者用完全相同的 spanning-tree
// 語法偵測（無廠牌專屬分支），故 render 也共用同一份
function renderSpanningTreeGlobal(stp){
  if(!hasGlobalStpData(stp))return '';
  const lines=[];
  if(stp.mode)lines.push(`spanning-tree mode ${stp.mode}`);
  const vlanIds=(stp.instances||[]).map(i=>i.id).filter(Boolean);
  (stp.instances||[]).forEach(i=>{
    if(i.id&&i.priority)lines.push(`spanning-tree vlan ${i.id} priority ${i.priority}`);
  });
  if(stp.rootMode&&vlanIds.length)lines.push(`spanning-tree vlan ${vlanIds.join(',')} root ${stp.rootMode}`);
  const t=stp.timers||{};
  if(t.hello)lines.push(`spanning-tree hello-time ${t.hello}`);
  if(t.forwardDelay)lines.push(`spanning-tree forward-time ${t.forwardDelay}`);
  if(t.maxAge)lines.push(`spanning-tree max-age ${t.maxAge}`);
  return lines.join('\n');
}

// FortiSwitch：已查證官方 FortiSwitchOS Administration Guide（standalone mode）後修正，
// 真實語法 "config switch stp-settings" 沒有 priority 欄位（只有 hello-time/forward-time/
// max-age/status）；priority 實際位於具名 MSTP instance 底下的 "config switch stp
// instance"，逐 port cost/priority 也在該 instance 巢狀的 "config stp-port" 子區塊內
// （比照 Extreme XOS 單一預設網域簡化慣例：全部歸屬第一個 instance，無 instance 時
// 退回 id '0'）
function renderFortiSwitchSTP(stp){
  if(!hasGlobalStpData(stp))return '';
  const lines=[];
  const t=stp.timers||{};
  lines.push('config switch stp-settings');
  if(t.hello)lines.push(`    set hello-time ${t.hello}`);
  if(t.forwardDelay)lines.push(`    set forward-time ${t.forwardDelay}`);
  if(t.maxAge)lines.push(`    set max-age ${t.maxAge}`);
  lines.push('    set status enable');
  lines.push('end');
  const stpPorts=(stp.ports||[]).filter(p=>p.cost||p.priority);
  const inst=(stp.instances&&stp.instances[0])||null;
  if(inst||stpPorts.length){
    const instId=(inst&&inst.id)||'0';
    lines.push('config switch stp instance');
    lines.push(`    edit "${instId}"`);
    if(inst&&inst.priority)lines.push(`        set priority ${inst.priority}`);
    if(stpPorts.length){
      lines.push('        config stp-port');
      stpPorts.forEach(p=>{
        lines.push(`            edit "${p.port}"`);
        if(p.cost)lines.push(`                set cost ${p.cost}`);
        if(p.priority)lines.push(`                set priority ${p.priority}`);
        lines.push('            next');
      });
      lines.push('        end');
    }
    lines.push('    next');
    lines.push('end');
  }
  return lines.join('\n');
}

// QoS：Cisco/Aruba CX/FortiSwitch 共用同一組 policy-map/class 語法（switch_analyzer
// parseQoS 對這三個廠牌本來就是共用同一個解析分支，FortiSwitch 沒有走自己 config/edit/
// next/end 的區塊風格，這裡沿用既有 parser 的實際期待，而非重新設計語法）
function groupQosByPolicy(list){
  const map=new Map();
  (list||[]).forEach(q=>{
    if(!map.has(q.policy))map.set(q.policy,[]);
    map.get(q.policy).push(q);
  });
  return map;
}
function renderPolicyMapQoS(list){
  const blocks=[];
  groupQosByPolicy(list).forEach((items,policy)=>{
    const lines=[`policy-map ${policy}`];
    items.forEach(q=>{
      lines.push(` class ${q.cls}`);
      if(q.action==='police')lines.push(`  police rate ${q.rate||'1000000'}`);
      else if(q.action==='priority')lines.push('  priority');
      else if(q.action==='shape')lines.push(`  shape average ${q.rate||'1000000'}`);
      else if(q.action==='bandwidth')lines.push(`  bandwidth ${q.rate||'1000'}`);
      // drop：Cisco IOS 通用關鍵字（Planet 官方 SGS-6341 Command Guide 已查證同款語法），
      // Cisco/Ruijie/Planet 三家共用此函式，一併受惠
      else if(q.action==='drop')lines.push('  drop');
      if(q.burst)lines.push(`  burst ${q.burst}`);
    });
    blocks.push(lines.join('\n'));
  });
  return blocks.join('\n!\n');
}

// class-map/match 條件比對（2026-08-28（續4）新增，Cisco/Ruijie/Planet 三家共用同一套
// class-map/policy-map 語法，與上方 renderPolicyMapQoS() 相同的廠牌集合）：每一列是一條
// match 條件，依 class-map name 分組（比照 groupQosByPolicy() 樣板），同一 class-map 底下
// 可有多條 match（match-any 為 OR、match-all 為 AND，皆由使用者自行選擇，本工具不驗證邏輯
// 合理性）。務必排在 assemble 組裝順序內 policy-map 之前——class-map 必須先於引用它的
// policy-map 定義，且其收尾正則同時認 policy-map 邊界（見各廠牌 assemble 函式）。
function groupClassMapMatches(list){
  const map=new Map();
  (list||[]).forEach(cm=>{
    if(!map.has(cm.name))map.set(cm.name,{matchType:cm.matchType||'match-all',matches:[]});
    map.get(cm.name).matches.push({type:cm.type,value:cm.value});
  });
  return map;
}
function renderClassMapQoS(list){
  const blocks=[];
  groupClassMapMatches(list).forEach((grp,name)=>{
    const lines=[`class-map ${grp.matchType} ${name}`];
    grp.matches.forEach(mt=>{
      if(!mt.type||!mt.value)return;
      if(mt.type==='ip-precedence')lines.push(` match ip precedence ${mt.value}`);
      else lines.push(` match ${mt.type} ${mt.value}`);
    });
    blocks.push(lines.join('\n'));
  });
  return blocks.join('\n!\n');
}

// service-policy 介面套用（2026-08-28（續4）新增）：QoS policy-map 定義本身不會自動生效，
// 真實裝置需要 service-policy input/output 把 policy-map 套用到介面上，比照 ACL 套用同一套
// 內嵌進 interface 區塊的慣例（findAclApplications() 樣板），direction 字面值是 Cisco 標準的
// input/output（非 ACL 的 in/out）
function findQosApplications(qosApplyList,ifaceName){
  return (qosApplyList||[]).filter(ap=>ap.interface===ifaceName).map(ap=>({policy:ap.policy,direction:ap.direction||'output'}));
}

// VRRP 設定實際上位於 SVI（Layer 3 VLAN interface）區塊內，同一顆 VLAN 可能有多個 VRID，
// 故先依 vlanId 分組，每組各自輸出一個 SVI 區塊（含 IP 位址 + 底下所有 VRID 的 vrrp 指令）
function groupVrrpByVlan(vrrpList){
  const map=new Map();
  (vrrpList||[]).forEach(v=>{
    if(!map.has(v.vlanId))map.set(v.vlanId,{vlanId:v.vlanId,ip:v.ip,entries:[]});
    map.get(v.vlanId).entries.push(v);
  });
  return Array.from(map.values());
}

