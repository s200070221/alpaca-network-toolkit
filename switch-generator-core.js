
// ══════════════════════════════════════════════════════════════════
// 資料模型（沿用 switch_analyzer 既有 parseVLANs/parseInterfaces/parseHybrid/parseOSPF/parseBGP/parseRIP/
// parseFortiRouting/parseCisco*/parseArubaXXX/parseRoutes/parseLACP/parseVRRP 輸出形狀）:
// {
//   vendor: 'comware'|'fortiswitch'|'aruba'|'cisco', sysname,
//   vlans:[{id,name,ip /* 選填，CIDR，該 VLAN 的 routed IP；13 家廠牌透過 withSviInterfaces()
//     於產生設定前動態合成對應的 SVI 介面物件，ProCurve/Extreme 則直接讀這個欄位本身 */}],
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
  // ipVersion 一併帶出（2026-09-03 新增），供 Cisco/Arista/NX-OS 介面套用行切換
  // ip access-group（v4）/ipv6 traffic-filter/ipv6 port traffic-filter（v6）關鍵字；
  // 其餘廠牌沿用既有呼叫方式（不解構此欄位）不受影響
  (aclList||[]).forEach(a=>(a.appliedOn||[]).forEach(ap=>{if(ap.interface===ifaceName)out.push({name:a.name,direction:ap.direction||'in',ipVersion:a.ipVersion||'v4'});}));
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
    // 白名單限定 access-group/dscp/protocol/cos + ip-precedence（與 switch_analyzer 的
    // parseClassMaps() 正則 /match\s+(access-group|dscp|protocol|cos)/ 完全對稱），不能用
    // 通用 else 把任意 condType（如 UI 下拉選單裡本廠牌未查證的 vlan）原樣輸出成 CLI 指令——
    // 那樣會生造出從未查證過的語法，且 round-trip 讀回時會被解析器規則吃掉（2026-09-02 審查
    // 發現：Cisco/Ruijie/Planet 選了 vlan 會產生 `match vlan N` 這行未查證語法）
    grp.matches.forEach(mt=>{
      if(!mt.type||!mt.value)return;
      if(mt.type==='ip-precedence')lines.push(` match ip precedence ${mt.value}`);
      else if(['access-group','dscp','protocol','cos'].includes(mt.type))lines.push(` match ${mt.type} ${mt.value}`);
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

// VLAN IP（2026-09-08 新增，2026-09-09 補上 RouterOS）：ProCurve/Extreme 的 render 本來就
// 直接讀 VLAN 物件自己的 v.ip（非獨立介面），但其餘 14 家廠牌把 VLAN 的 L3 IP 建模成獨立的
// SVI 介面物件（如 Cisco interface Vlan10、Comware Vlan-interface10、Juniper irb.10、
// RouterOS /interface vlan），render/parser 早已支援、唯獨 UI 端只能透過直接建構 model
// （測試）或匯入既有設定檔產生，表單本身無法建立。
// key 用 <select id="vendor"> 的實際 value（非各廠牌檔名 slug）——Aruba CX 是 'aruba' 非
// 'aruba-cx'，NX-OS 是 'cisco_nxos' 非 'nxos'。SONiC 已有自己專屬的 sonicL3Interfaces 卡片
// （資料形狀通用 {name,cidr}，本函式的設計參考範本）；EdgeSwitch（VLAN Routing 邏輯介面 ID
// 由裝置動態配置產生，無法靜態預測，CLAUDE.md 已記載既有架構限制）刻意不在此白名單內。
// RouterOS 的 /interface vlan 需要 bridge VLAN filtering table 已存在的橋接器（固定
// bridge1）當掛載對象，語法與其餘廠牌不同（詳見 switch-generator-routeros.js
// renderRouterOSVlanInterfaces()／switch-analyzer-parser-routeros.js
// _parseRouterOSVlanInterfaces()）。
const SVI_NAME_FORMATTERS = {
  cisco: id => `Vlan${id}`, cisco_nxos: id => `Vlan${id}`,
  arista: id => `Vlan${id}`, ruijie: id => `Vlan${id}`,
  comware: id => `Vlan-interface${id}`, juniper: id => `irb.${id}`,
  aruba: id => `vlan${id}`, 'dell-os10': id => `vlan${id}`,
  brocade: id => `ve${id}`, alcatel: id => `VLAN${id}`,
  netgear: id => `vlan ${id}`, planet: id => `vlan ${id}`,
  fortiswitch: id => `vlan${id}`, routeros: id => `vlan${id}`,
};
// EPHEMERAL 轉換：只在即將呼叫 assembleXConfig() 產生設定文字的當下合成，不寫回
// collectModel() 的持久化結果——避免這批合成物件被存進範本 localStorage，或讓
// applyModelToForm() 反向回填時多出使用者從未新增過的介面列。固定帶上 type:'svi' + vlans
// （VLAN ID 綁定，Alcatel/FortiSwitch 的 render 需要，其餘廠牌忽略無妨）即可覆蓋全部 13 家
// 既有 render 分支的觸發條件。
//
// 與既有 VRRP 卡片的互斥處理：12/13 家（除 Juniper 不支援 VRRP）的 render 對「VRRP 已綁定的
// VLAN」是靠 groupVrrpByVlan()（見上方）另外獨立輸出一個 `interface VlanN` 區塊（含 VRRP
// 自己的 vrrp[].ip 欄位，語意上早就是「這個 VLAN 的 SVI IP」），與這裡合成的介面物件是兩條
// 完全獨立的路徑、彼此不知道對方存在。若同一顆 VLAN 兩邊都有值，會產生兩個重複的
// `interface VlanN` 區塊（2026-09-08 瀏覽器手動驗證時發現）。既有 vrrp[].ip 語意上已涵蓋
// 這顆 VLAN 的 IP，故此函式刻意跳過任何已有 VRRP 條目的 VLAN ID，避免重複輸出。
function withSviInterfaces(model){
  const fmt=SVI_NAME_FORMATTERS[model&&model.vendor];
  if(!fmt)return model;
  const vrrpVlanIds=new Set((model.vrrp||[]).map(v=>String(v.vlanId)));
  const svis=(model.vlans||[]).filter(v=>v.ip&&!vrrpVlanIds.has(String(v.id))).map(v=>({
    name:fmt(v.id), type:'svi', ip:v.ip, vlans:String(v.id),
  }));
  if(!svis.length)return model;
  return {...model, interfaces:[...(model.interfaces||[]), ...svis]};
}


// ── 增量指令（2026-09-29 新增，第六輪 WE）──────────────────────────────────
// 匯入既有設定檔後在表單上修改，只輸出「要下的差異指令」，不是整份設定。
// 範圍：VLAN（新增／刪除／改名／SVI IPv4 位址）、介面（描述、access／trunk 模式、access VLAN、
// trunk 允許清單、native VLAN、shutdown）、靜態路由（新增／刪除），Cisco IOS-XE 與 Comware 兩家。
// hybrid、IPv6 SVI 與其餘欄位列在 unsupported（以註解輸出），請手動處理。
// 語法沿用本工具既有 render 函式：Cisco `switchport …`／`no …`、Comware `port …`／`undo …`；
// Comware trunk 允許清單是累加式（port trunk permit vlan 只會增加），改清單時先
// `undo port trunk permit vlan all` 再重新 permit，讓結果與表單一致。
function _deltaKey(s){return String(s||'').trim().toLowerCase();}
function _deltaVlanList(s){return String(s||'').trim().split(/[,\s]+/).filter(Boolean);}
function buildIncrementalCommands(oldModel,newModel,vendor){
  const isCw=vendor==='comware';
  const C=isCw?'#':'!';
  const NO=isCw?'undo ':'no ';
  const EXIT=isCw?' quit':' exit';
  const sviName=id=>isCw?`Vlan-interface${id}`:`Vlan${id}`;
  const out=[], unsupported=[];
  const counts={vlanAdd:0,vlanDel:0,vlanMod:0,ifaceMod:0,routeAdd:0,routeDel:0};
  const block=(head,lines)=>{ if(lines.length) out.push(head,...lines,EXIT); };
  const ipLine=cidr=>{ const [ip,len]=cidr.split('/'); return ` ip address ${ip} ${maskFromCidr(len||'32')}`; };
  // VLAN
  const oV=new Map((oldModel.vlans||[]).map(v=>[String(v.id),v])), nV=new Map((newModel.vlans||[]).map(v=>[String(v.id),v]));
  nV.forEach((v,id)=>{
    const o=oV.get(id);
    if(!o){ counts.vlanAdd++; out.push(`vlan ${id}`,...(v.name?[` name ${v.name}`]:[]),EXIT); }
    else if((o.name||'')!==(v.name||'')){ counts.vlanMod++; block(`vlan ${id}`,[v.name?` name ${v.name}`:` ${NO}name`]); }
    const oip=(o&&o.ip)||'', nip=v.ip||'';
    if(oip!==nip){
      if(nip.includes(':')||oip.includes(':')){ unsupported.push(`${sviName(id)}: IPv6`); return; }
      if(o)counts.vlanMod++;
      block(`interface ${sviName(id)}`,[nip?ipLine(nip):` ${NO}ip address`]);
    }
  });
  oV.forEach((o,id)=>{ if(!nV.has(id)){ counts.vlanDel++; if(o.ip)out.push(`${NO}interface ${sviName(id)}`); out.push(`${NO}vlan ${id}`); } });
  // 介面
  const oI=new Map((oldModel.interfaces||[]).map(i=>[_deltaKey(i.name),i]));
  const nKeys=new Set();
  (newModel.interfaces||[]).forEach(n=>{
    const k=_deltaKey(n.name); nKeys.add(k);
    const o=oI.get(k)||{mode:'',desc:'',accessVlan:'',trunkVlans:'',nativeVlan:'',shutdown:false};
    const L=[];
    if((o.desc||'')!==(n.desc||''))L.push(n.desc?` description ${n.desc}`:` ${NO}description`);
    const om=o.mode||'', nm=n.mode||'';
    if(om==='hybrid'||nm==='hybrid'||(nm&&!['access','trunk'].includes(nm))||(om&&nm!==om&&!['access','trunk'].includes(om))){
      if(om!==nm||JSON.stringify(o.hybrid||{})!==JSON.stringify(n.hybrid||{}))unsupported.push(`${n.name}: ${om||'-'} → ${nm||'-'}`);
    }else if(nm==='access'){
      if(om!=='access'){
        L.push(isCw?' port link-type access':' switchport mode access');
        if(!isCw&&om==='trunk'){ if(o.trunkVlans)L.push(' no switchport trunk allowed vlan'); if(o.nativeVlan)L.push(' no switchport trunk native vlan'); }
      }
      if((o.accessVlan||'')!==(n.accessVlan||'')||om!=='access'){
        if(n.accessVlan)L.push(isCw?` port access vlan ${n.accessVlan}`:` switchport access vlan ${n.accessVlan}`);
        else if(om==='access'&&o.accessVlan)L.push(isCw?' undo port access vlan':' no switchport access vlan');
      }
    }else if(nm==='trunk'){
      if(om!=='trunk'){
        L.push(isCw?' port link-type trunk':' switchport mode trunk');
        if(!isCw&&om==='access'&&o.accessVlan)L.push(' no switchport access vlan');
      }
      const ol=_deltaVlanList(om==='trunk'?o.trunkVlans:''), nl=_deltaVlanList(n.trunkVlans);
      if(ol.join(' ')!==nl.join(' ')){
        if(isCw){ if(om==='trunk')L.push(' undo port trunk permit vlan all'); if(nl.length)L.push(` port trunk permit vlan ${nl.join(' ')}`); }
        else L.push(nl.length?` switchport trunk allowed vlan ${nl.join(',')}`:' no switchport trunk allowed vlan');
      }
      const on=om==='trunk'?(o.nativeVlan||''):'', nn=n.nativeVlan||'';
      if(on!==nn)L.push(nn?(isCw?` port trunk pvid vlan ${nn}`:` switchport trunk native vlan ${nn}`):(isCw?' undo port trunk pvid':' no switchport trunk native vlan'));
    }else if(om==='access'||om==='trunk'){
      unsupported.push(`${n.name}: ${om} → -`);
    }
    if(!!o.shutdown!==!!n.shutdown)L.push(n.shutdown?' shutdown':` ${NO}shutdown`);
    if(L.length){ counts.ifaceMod++; block(`interface ${n.name}`,L); }
  });
  oI.forEach((o,k)=>{ if(!nKeys.has(k))unsupported.push(`${o.name}: ${isCw?'removed from form (physical interfaces cannot be deleted)':'removed from form'}`); });
  // 靜態路由（metric 不在 render 輸出範圍，比對只看目的與下一跳）
  const rk=r=>_deltaKey(r.dst)+'|'+_deltaKey(r.gw);
  const render=r=>isCw?renderComwareRoute(r):renderCiscoRoute(r);
  const oR=new Map((oldModel.routes||[]).map(r=>[rk(r),r])), nR=new Map((newModel.routes||[]).map(r=>[rk(r),r]));
  oR.forEach((r,k)=>{ if(!nR.has(k)){ counts.routeDel++; out.push(NO+render(r)); } });
  nR.forEach((r,k)=>{ if(!oR.has(k)){ counts.routeAdd++; out.push(render(r)); } });
  const total=Object.values(counts).reduce((a,b)=>a+b,0);
  if(!total&&!unsupported.length)return {text:'',counts,unsupported,total,risks:[]};
  const head=String(tr('delta.script_header')).split('\n').map(l=>C+' '+l);
  // 斷線風險（ND）：同時放進指令檔頭註解，複製出去的指令也看得到
  const risks=deltaRiskWarnings(oldModel,newModel);
  const riskLines=risks.map(w=>`${C} ⚠ ${deltaRiskText(w)}`);
  const tail=[...riskLines,...unsupported.map(u=>`${C} ${tr('delta.manual')}: ${u}`)];
  const body=isCw?['system-view',...out,'return']:['configure terminal',...out,'end'];
  return {text:[...head,...tail,'',...(out.length?body:[]),''].join('\n'),counts,unsupported,total,risks};
}

// ── 變更計畫書（MOP，2026-09-30 新增，第八輪 XC）─────────────────────────────
// 把差異指令擴充成一份可交付的變更單（Markdown）：摘要與斷線風險 → 預檢 → 變更 → 驗證與存檔 → 回退。
// 回退指令以同一個 buildIncrementalCommands() 反向計算（新 → 舊），只涵蓋差異指令本身支援的範圍；
// 預檢／驗證只用唯讀的 show／display 指令，並依實際有變動的項目挑選：
//   Cisco：show vlan brief／show interfaces status／show interfaces trunk／show ip interface brief／
//          show ip route static／show etherchannel summary，存檔 copy running-config startup-config
//   Comware（H3C Comware V7 指令手冊）：display vlan brief／display interface brief／display port trunk／
//          display ip interface brief／display ip routing-table protocol static／display link-aggregation summary，
//          存檔 save force（存到既有的下次啟動設定檔，不詢問）
function buildChangePlan(oldModel,newModel,vendor){
  const isCw=vendor==='comware';
  const fwd=buildIncrementalCommands(oldModel,newModel,vendor);
  if(!fwd.total&&!fwd.unsupported.length)return null;
  const back=buildIncrementalCommands(newModel,oldModel,vendor);
  const body=t=>t.split('\n').filter(l=>l&&!/^[!#] /.test(l)).join('\n');
  const changed=[...new Set((fwd.text.match(/^interface \S+/gm)||[]).map(l=>l.slice(10)))];
  const c=fwd.counts;
  const vlanChg=c.vlanAdd+c.vlanDel+c.vlanMod>0, ifChg=c.ifaceMod>0, rtChg=c.routeAdd+c.routeDel>0;
  const trunkChg=/trunk/.test(fwd.text);
  const sviChg=/^interface (Vlan|Vlan-interface)\d+/m.test(fwd.text)||/^(no|undo) interface (Vlan|Vlan-interface)\d+/m.test(fwd.text);
  // 只有變動的介面本身是聚合成員時才列聚合狀態檢查
  const lagMembers=new Set([...(oldModel.lacp||[]),...(newModel.lacp||[])].flatMap(l=>(l.members||[]).map(_deltaKey)));
  const lagRisk=changed.some(n=>lagMembers.has(_deltaKey(n)));
  const pick=(cisco,comware)=>isCw?comware:cisco;
  const checks=[pick('show running-config','display current-configuration')];
  if(vlanChg)checks.push(pick('show vlan brief','display vlan brief'));
  if(ifChg)checks.push(pick('show interfaces status','display interface brief'));
  if(trunkChg)checks.push(pick('show interfaces trunk','display port trunk'));
  if(sviChg)checks.push(pick('show ip interface brief','display ip interface brief'));
  if(rtChg)checks.push(pick('show ip route static','display ip routing-table protocol static'));
  if(lagRisk)checks.push(pick('show etherchannel summary','display link-aggregation summary'));
  const verify=checks.slice(1).concat(changed.slice(0,10).map(n=>pick(`show running-config interface ${n}`,`display current-configuration interface ${n}`)));
  const save=pick('copy running-config startup-config','save force');
  const host=newModel.sysname||oldModel.sysname||'-';
  const L=[`# ${tr('mop.title')} — ${host}`,'',
    `- ${tr('mop.vendor')}: ${isCw?'H3C Comware':'Cisco IOS-XE'}`,
    `- ${tr('mop.generated')}: ${new Date().toISOString()}`,
    `- ${tr('mop.counts').replace('{vlanAdd}',c.vlanAdd).replace('{vlanDel}',c.vlanDel).replace('{vlanMod}',c.vlanMod).replace('{ifaceMod}',c.ifaceMod).replace('{routeAdd}',c.routeAdd).replace('{routeDel}',c.routeDel)}`,
    '',`> ${tr('notice.disclaimer')}`,''];
  L.push(`## 1. ${tr('mop.sec_risk')}`,'');
  if(fwd.risks&&fwd.risks.length)fwd.risks.forEach(w=>L.push('- ⚠ '+deltaRiskText(w)));
  else L.push(tr('mop.no_risk'));
  if(fwd.unsupported.length){L.push('',tr('mop.manual_hint'),'');fwd.unsupported.forEach(u=>L.push('- '+u));}
  L.push('',`## 2. ${tr('mop.sec_precheck')}`,'',tr('mop.precheck_hint'),'','```',...checks,'```','');
  L.push(`## 3. ${tr('mop.sec_change')}`,'');
  if(fwd.total)L.push('```',body(fwd.text),'```','');else L.push(tr('mop.nothing'),'');
  L.push(`## 4. ${tr('mop.sec_verify')}`,'',tr('mop.verify_hint'),'','```',...verify,'```','',tr('mop.save_hint'),'','```',save,'```','');
  L.push(`## 5. ${tr('mop.sec_rollback')}`,'',tr('mop.rollback_hint'),'');
  if(back.total)L.push('```',body(back.text),'```','');else L.push(tr('mop.nothing'),'');
  if(back.unsupported.length){L.push(tr('mop.manual_hint'),'');back.unsupported.forEach(u=>L.push('- '+u));L.push('');}
  return {text:L.join('\n'),checks,verify,rollback:back};
}

// ── 差異指令的斷線風險提示（2026-09-29 新增，第七輪 ND）──────────────────────
// 比較匯入快照與目前表單，找出可能造成斷線的變更，回傳 [{kind, target, extra}]：
//   uplink   上行／聚合相關介面有變動：原本是 trunk、描述像上聯（uplink／core／to-／上聯…）或是 LACP 成員
//   mgmt     管理 VLAN（名稱含 mgmt／manage／管理）被刪除、改名或 SVI IP 變動
//   vlanInUse VLAN 被刪除，但目前表單仍有介面以 access 或 trunk 清單使用它
//   shutdown 介面將被關閉
// 判斷刻意寬鬆（寧可多提醒），只提示不阻擋。
const DELTA_UPLINK_DESC_RE=/uplink|up-link|core|dist|to[-_ ]|trunk|上聯|上行|骨幹/i;
const DELTA_MGMT_RE=/mgmt|manage|管理/i;
function deltaRiskWarnings(oldModel,newModel){
  const out=[];
  const key=s=>String(s||'').trim().toLowerCase();
  const oI=new Map((oldModel.interfaces||[]).map(i=>[key(i.name),i]));
  const lacpMembers=new Set([...(oldModel.lacp||[]),...(newModel.lacp||[])].flatMap(l=>(l.members||[]).map(key)));
  const sameIface=(a,b)=>['desc','mode','accessVlan','trunkVlans','nativeVlan'].every(k=>String(a[k]||'')===String(b[k]||''))&&!!a.shutdown===!!b.shutdown;
  (newModel.interfaces||[]).forEach(n=>{
    const o=oI.get(key(n.name));
    if(!o)return;
    if(!!n.shutdown&&!o.shutdown)out.push({kind:'shutdown',target:n.name});
    if(sameIface(o,n))return;
    if(o.mode==='trunk'||DELTA_UPLINK_DESC_RE.test(o.desc||'')||lacpMembers.has(key(n.name)))out.push({kind:'uplink',target:n.name});
  });
  const nV=new Map((newModel.vlans||[]).map(v=>[String(v.id),v]));
  const inList=(list,id)=>String(list||'').split(/[,\s]+/).some(tok=>{const m=tok.match(/^(\d+)-(\d+)$/);return m?(+id>=+m[1]&&+id<=+m[2]):tok===id;});
  (oldModel.vlans||[]).forEach(o=>{
    const id=String(o.id), n=nV.get(id);
    if(DELTA_MGMT_RE.test(o.name||'')&&(!n||(n.name||'')!==(o.name||'')||(n.ip||'')!==(o.ip||'')))out.push({kind:'mgmt',target:'VLAN '+id});
    else if(n&&o.ip&&(n.ip||'')!==o.ip)out.push({kind:'mgmt',target:'VLAN '+id+' SVI'});
    if(!n){
      const users=(newModel.interfaces||[]).filter(i=>(i.mode==='access'&&String(i.accessVlan)===id)||(i.mode==='trunk'&&inList(i.trunkVlans,id))).map(i=>i.name);
      if(users.length)out.push({kind:'vlanInUse',target:id,extra:users.slice(0,10).join(', ')+(users.length>10?'…':'')});
    }
  });
  return out;
}
function deltaRiskText(w){
  return tr('delta.risk_'+w.kind).replace('{target}',w.target).replace('{extra}',w.extra||'');
}
