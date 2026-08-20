function sonicEmptyResult(){
  return{sys:{hostname:'unknown',version:'',platform:''},irf:null,stack:null,vlans:[],
    interfaces:[],routes:[],lacp:[],vrfs:[],users:[],ospf:[],bgp:[],rip:[],vrrp:[],vxlan:null,
    vendor:'sonic',breakouts:[],qos:{schedulers:[],apply:[]},
    stp:{mode:null,rootMode:null,timers:{hello:null,forwardDelay:null,maxAge:null},instances:[],ports:[]},
    snmp:{communities:[],v3Users:[],hosts:[]},syslog:{servers:[]}};
}
// ACL_TABLE/ACL_RULE → 共用 ACL 形狀（2026-08-08 對外查證新增，原排除項目：官方文件＋
// 真實範例確認欄位 PRIORITY/PACKET_ACTION/IP_PROTOCOL/SRC_IP/DST_IP/L4_DST_PORT/IP_TYPE，
// 複合鍵 "{ACL表名}|{規則名}"）。IP_PROTOCOL 為數字（6=tcp/17=udp/1=icmp），無此欄位代表
// 不限協定，統一回填 'ip'（比照 Cisco 慣例）。簽章比照其餘 _parseACLXxx(cfg) 慣例吃原始
// 字串（被 parseACL() 統一 dispatcher 呼叫，非從 parseSONiC() 內部呼叫——ACL 資料流走
// res.acls（parseACL 統一計算，見 parseAny()），與 parseSONiC() 自己回傳的 res 無關）
// IPv6 支援（2026-08-17 新增）：ACL_TABLE.type 官方 schema 為 L3（IPv4）/L3V6（IPv6），
// 填入 ipVersion；ACL_RULE 的 IPv6 規則用獨立欄位名 SRC_IPV6/DST_IPV6（非與 SRC_IP/DST_IP
// 同欄位混用），原本只讀 SRC_IP/DST_IP 導致 v6 規則位址靜默顯示 '-'，改為找不到 v4 欄位
// 才 fallback 讀 v6 欄位。ACL_TABLE 表名在 schema 層強制全域唯一，本質無 v4/v6 命名空間
// 碰撞風險，純粹是欄位對應缺口
const SONIC_IP_PROTO_REV={6:'tcp',17:'udp',1:'icmp'};
function _parseACLSONiC(cfg){
  let db;
  try{ db=JSON.parse(cfg); }catch(e){ return []; }
  if(!db||typeof db!=='object')return [];
  const acls=[];
  Object.entries(db.ACL_TABLE||{}).forEach(([name,t])=>{
    const ipVersion=t&&t.type==='L3V6'?'v6':t&&t.type==='L3'?'v4':'';
    acls.push({name,type:'extended',ipVersion,vendor:'sonic',rules:[],
      appliedOn:((t&&t.ports)||[]).map(p=>({interface:p,direction:'in'}))});
  });
  Object.entries(db.ACL_RULE||{}).forEach(([key,val])=>{
    const pipeIdx=key.indexOf('|');
    if(pipeIdx===-1)return;
    const acl=acls.find(a=>a.name===key.slice(0,pipeIdx));
    if(!acl)return;
    acl.rules.push({
      seq:val&&val.PRIORITY!==undefined?String(val.PRIORITY):'',
      action:val&&val.PACKET_ACTION==='DROP'?'deny':'permit',
      protocol:SONIC_IP_PROTO_REV[val&&val.IP_PROTOCOL]||'ip',
      src:(val&&(val.SRC_IP||val.SRC_IPV6))||'-',
      dst:(val&&(val.DST_IP||val.DST_IPV6))||'-',
      dstPort:val&&val.L4_DST_PORT!==undefined?String(val.L4_DST_PORT):'',
      remark:'',
    });
  });
  return acls;
}
// SCHEDULER/PORT_QOS_MAP/QUEUE → 專屬 sonicQos 形狀（2026-08-08 對外查證新增，原排除
// 項目：官方 QoS Scheduler/Shaper HLD 文件＋硬體商真實範例交叉確認欄位）。與 ACL 不同，
// QoS 資料流走「專屬 schema」模式——parseAny() 已把 sonic 排除在共用 parseQoS() dispatcher
// 之外，本函式只從 parseSONiC() 內部呼叫、結果掛在 res.qos，不接進 parseQoS() dispatcher
// （比照 RouterOS/Brocade/Extreme 專屬 QoS 形狀的既有慣例）；簽章仍吃已 parse 好的 db
// 物件（非原始字串），因為呼叫端 parseSONiC() 已經 parse 過一次，不需要重複 parse
function _parseQoSSONiC(db){
  const schedulers=Object.entries(db.SCHEDULER||{}).map(([name,v])=>({
    name, type:(v&&v.type)||'', weight:v&&v.weight!==undefined?String(v.weight):'',
    meterType:(v&&v.meter_type)||'', cir:v&&v.cir!==undefined?String(v.cir):'',
    cbs:v&&v.cbs!==undefined?String(v.cbs):'', pir:v&&v.pir!==undefined?String(v.pir):'',
    pbs:v&&v.pbs!==undefined?String(v.pbs):'',
  }));
  const apply=[];
  Object.entries(db.PORT_QOS_MAP||{}).forEach(([port,v])=>{
    if(v&&v.scheduler)apply.push({target:port,queue:'',scheduler:v.scheduler});
  });
  Object.entries(db.QUEUE||{}).forEach(([key,v])=>{
    const pipeIdx=key.indexOf('|');
    if(pipeIdx===-1)return;
    if(v&&v.scheduler)apply.push({target:key.slice(0,pipeIdx),queue:key.slice(pipeIdx+1),scheduler:v.scheduler});
  });
  return{schedulers,apply};
}
// PAC_PORT_CONFIG/HOSTAPD_GLOBAL_CONFIG → 共用 Security 形狀 {port,dot1x,portSec,maxMac,
// violation,guestVlan}（2026-08-08 對外查證新增，原排除項目：官方 Port Access Control
// HLD 文件確認 method_list/port_pae_role/port_control_mode/host_control_mode/
// max_users_per_port 欄位）。查無 guest VLAN／MAC port-security 對應欄位，比照既有其他
// 廠牌慣例明確不猜測，portSec 固定 false、violation/guestVlan 固定 '-'。與 ACL 同一種
// 「統一 dispatcher」模式：接進 parseSecurity() 開頭的 vendor 分流，簽章吃原始字串
function _parseSecuritySONiC(cfg){
  let db;
  try{ db=JSON.parse(cfg); }catch(e){ return []; }
  if(!db||typeof db!=='object')return [];
  return Object.entries(db.PAC_PORT_CONFIG||{}).map(([port,v])=>{
    const isDot1x=!!(v&&(v.method_list||'').includes('dot1x')&&v.port_pae_role==='authenticator');
    return{port,dot1x:isDot1x?'auth':'-',portSec:false,
      maxMac:v&&v.max_users_per_port!==undefined?String(v.max_users_per_port):'-',
      violation:'-',guestVlan:'-'};
  });
}
// STP/STP_VLAN/STP_INTF/STP_VLAN_INTF → 共用 STP 巢狀形狀（2026-08-08 對外查證新增，原
// 排除項目：官方 PVST HLD 文件確認完整 schema）。PVST 逐 VLAN 一個 instance，天然對應
// instances 陣列；STP_VLAN_INTF（逐 VLAN 逐 port 覆寫，2026-08-08 補上）額外掛在回傳物件
// 的 sonicStpVlanIntf 欄位（共用 STP 形狀無 VLAN 維度，其餘廠牌呼叫路徑不受影響）；
// STP.GLOBAL.priority 是 render 端複製自第一個 instance 的裝飾性欄位（非權威來源），
// 逐 VLAN priority 一律直接讀 STP_VLAN 自己的值，不需要跟 GLOBAL 對帳。簽章吃原始字串
// （被 parseSTP() 的 sonic 分流呼叫，同時也是 parseSONiC() 自己內部呼叫的來源，兩處共用
// 同一份實作，非各自維護）
function _parseSTPSONiC(cfg){
  let db;
  try{ db=JSON.parse(cfg); }catch(e){ db=null; }
  if(!db||typeof db!=='object')db={};
  const g=(db.STP&&db.STP.GLOBAL)||{};
  const instances=Object.entries(db.STP_VLAN||{}).map(([key,val])=>{
    const id=(key.match(/^Vlan(\d+)$/i)||[])[1]||key.replace(/^Vlan/i,'');
    return{id,vlan:key,priority:val&&val.priority!==undefined?String(val.priority):''};
  });
  const ports=Object.entries(db.STP_INTF||{}).map(([port,val])=>({
    port,
    portfast:!!(val&&(val.portfast==='1'||val.portfast===1)),
    bpduguard:!!(val&&(val.bpdu_guard==='1'||val.bpdu_guard===1)),
    guardRoot:!!(val&&(val.root_guard==='1'||val.root_guard===1)),
    cost:val&&val.path_cost!==undefined?String(val.path_cost):'',
    priority:val&&val.priority!==undefined?String(val.priority):'',
  }));
  const sonicStpVlanIntf=Object.entries(db.STP_VLAN_INTF||{}).map(([key,val])=>{
    const parts=key.split('|');
    const vlanKey=parts[0]||'', port=parts[1]||'';
    const vlan=(vlanKey.match(/^Vlan(\d+)$/i)||[])[1]||vlanKey.replace(/^Vlan/i,'');
    return{vlan,port,cost:val&&val.path_cost!==undefined?String(val.path_cost):'',
      priority:val&&val.priority!==undefined?String(val.priority):''};
  });
  return{mode:g.mode||null,rootMode:null,timers:{hello:null,forwardDelay:null,maxAge:null},instances,ports,sonicStpVlanIntf};
}
// SNMP_COMMUNITY → 共用 SNMP 形狀 {communities,v3Users,hosts}（2026-08-20 對外查證
// sonic-net/SONiC 設計文件 doc/snmp/snmp-schema-addition.md 新增，中高信心：此表未列入
// sonic-yang-models 正式 YANG schema，屬「已實作但未 YANG 驗證」的表格，建議日後找真實
// config_db.json 範例交叉驗證）。key 即 community 字串，值為 {TYPE:"RO"|"RW"}，本輪只
// 查證 community，v3Users/hosts 維持空陣列（未查證）
function _parseSnmpSONiC(db){
  const communities=Object.keys(db.SNMP_COMMUNITY||{}).map(name=>({name}));
  return{communities,v3Users:[],hosts:[]};
}
// SYSLOG_SERVER → 共用 Syslog 形狀 {servers:[{host,facility}]}（2026-08-20 對外查證官方
// sonic-buildimage Configuration.md 新增，高信心）。key 即遠端伺服器 IP，facility 欄位
// 本表無對應概念（有 severity/filter 但語意不同於其他廠牌的 syslog facility），固定留空
function _parseSyslogSONiC(db){
  const servers=Object.keys(db.SYSLOG_SERVER||{}).map(host=>({host,facility:''}));
  return{servers};
}
function parseSONiC(cfg){
  let db;
  try{ db=JSON.parse(cfg); }catch(e){ return sonicEmptyResult(); }
  if(!db||typeof db!=='object')return sonicEmptyResult();

  const hostname=(db.DEVICE_METADATA&&db.DEVICE_METADATA.localhost&&db.DEVICE_METADATA.localhost.hostname)||'unknown';
  const bgpAsn=db.DEVICE_METADATA&&db.DEVICE_METADATA.localhost?db.DEVICE_METADATA.localhost.bgp_asn:undefined;

  // VLAN 表格本身在已查證範例中是空物件，無 name 欄位可查證，不臆測（IP 由下面的
  // svi interface 條目承載，比照 Cisco parseCiscoVLANs 對 ipSubnets 的留空慣例）
  const vlans=Object.keys(db.VLAN||{}).map(key=>{
    const id=(key.match(/^Vlan(\d+)$/i)||[])[1]||key.replace(/^Vlan/i,'');
    return{id,name:'',ipSubnets:[]};
  }).sort((a,b)=>parseInt(a.id,10)-parseInt(b.id,10));

  // VLAN_MEMBER → 逐 port 彙整 untagged（最多1）／tagged（可多筆）
  const memberMap={};
  Object.entries(db.VLAN_MEMBER||{}).forEach(([key,val])=>{
    const pipeIdx=key.indexOf('|');
    const vlanKey=key.slice(0,pipeIdx), port=key.slice(pipeIdx+1);
    const vlanId=(vlanKey.match(/^Vlan(\d+)$/i)||[])[1]||'';
    if(!memberMap[port])memberMap[port]={untagged:null,tagged:[]};
    if(val&&val.tagging_mode==='untagged')memberMap[port].untagged=vlanId;
    else memberMap[port].tagged.push(vlanId);
  });

  // PORTCHANNEL_MEMBER → LACP members；PORTCHANNEL 本身在已查證範例中也是空物件，
  // 沒有 mode 欄位（teamd/LACP active-mode 是否可由 config_db.json 表示尚未查證，
  // 不臆測），固定回傳 mode:''
  const membersByPc={};
  Object.keys(db.PORTCHANNEL_MEMBER||{}).forEach(key=>{
    const pipeIdx=key.indexOf('|');
    const pc=key.slice(0,pipeIdx), port=key.slice(pipeIdx+1);
    (membersByPc[pc]=membersByPc[pc]||[]).push({name:port,lacpMode:null});
  });
  const lacp=Object.keys(db.PORTCHANNEL||{}).map(pc=>({name:pc,mode:'',members:membersByPc[pc]||[]}));

  // VLAN_INTERFACE（SVI IP）依 Vlan 名稱彙整
  const sviIpByVlan={};
  Object.keys(db.VLAN_INTERFACE||{}).forEach(key=>{
    const pipeIdx=key.indexOf('|');
    if(pipeIdx===-1)return; // 只有 "Vlan1000" 沒有 "|CIDR" 的條目是純佔位，略過
    const vlanName=key.slice(0,pipeIdx), cidr=key.slice(pipeIdx+1);
    (sviIpByVlan[vlanName]=sviIpByVlan[vlanName]||[]).push(cidr);
  });

  // 雙棧/次要IP 分桶修復（2026-08-13 新增，2026-08-17 次要IP 從「僅取第一筆」擴大為完整
  // 收集）：`name|cidr` 複合鍵收集到的多筆 CIDR 先前不分版本地取 cidrs[0]→ip、cidrs[1]→
  // secondaryIp，真實雙棧介面（1 個 IPv4 + 1 個 IPv6）會讓 IPv6 值被誤標成次要 IPv4。
  // 改為依內容判斷版本（含冒號即 IPv6）分桶，ip=v4[0]、secondaryIps=v4.slice(1)（完整
  // 保留）、ip6=v6[0]，三者互不覆蓋
  function classifySonicCidrs(cidrs){
    const v4=cidrs.filter(c=>!c.includes(':'));
    const v6=cidrs.filter(c=>c.includes(':'));
    return{ip:v4[0]||'',secondaryIps:v4.slice(1),ip6:v6[0]||''};
  }

  // interfaces：三個來源合併（VLAN_MEMBER port／VLAN_INTERFACE SVI／INTERFACE+
  // PORTCHANNEL_INTERFACE 的 L3 routed，比照 Cisco "no switchport" 的 mode:'routed' 慣例）
  const interfaces=[];
  const seen=new Set();
  Object.entries(memberMap).forEach(([port,m])=>{
    seen.add(port);
    let mode='',vlansStr='',nativeVlan='';
    if(m.tagged.length){
      mode='trunk';
      vlansStr=m.tagged.sort((a,b)=>parseInt(a,10)-parseInt(b,10)).join(' ');
      nativeVlan=m.untagged||'';
    }else if(m.untagged){
      mode='access';
      vlansStr=m.untagged;
    }
    interfaces.push({name:port,type:'physical',desc:'',ip:'',mode,vlans:vlansStr,
      nativeVlan,vrf:'',shutdown:false,member:'1',hybrid:null,vrrp:[]});
  });
  Object.keys(sviIpByVlan).forEach(vlanName=>{
    // 次要IP（2026-08-12 新增，2026-08-17 從「僅取第一筆」擴大為完整收集，比照
    // Cisco/Comware/Aruba-CX/FortiSwitch 既有命名慣例）；雙棧修復（2026-08-13）：
    // 改用 classifySonicCidrs() 依內容分辨版本
    const{ip,secondaryIps,ip6}=classifySonicCidrs(sviIpByVlan[vlanName]);
    interfaces.push({name:vlanName,type:'svi',desc:'',ip,ip6,secondaryIps,
      mode:'',vlans:'',nativeVlan:'',vrf:'',shutdown:false,member:'1',hybrid:null,vrrp:[]});
  });
  const routedIp={};
  Object.keys(db.INTERFACE||{}).forEach(key=>{
    const pipeIdx=key.indexOf('|');
    if(pipeIdx===-1)return;
    const name=key.slice(0,pipeIdx), cidr=key.slice(pipeIdx+1);
    (routedIp[name]=routedIp[name]||[]).push(cidr);
  });
  Object.keys(db.PORTCHANNEL_INTERFACE||{}).forEach(key=>{
    const pipeIdx=key.indexOf('|');
    if(pipeIdx===-1)return;
    const name=key.slice(0,pipeIdx), cidr=key.slice(pipeIdx+1);
    (routedIp[name]=routedIp[name]||[]).push(cidr);
  });
  Object.entries(routedIp).forEach(([name,cidrs])=>{
    if(seen.has(name))return; // 不會同時是 L2 VLAN member 又是 L3 routed
    // 次要IP（2026-08-12 新增，2026-08-17 從「僅取第一筆」擴大為完整收集）；雙棧修復
    // （2026-08-13）：改用 classifySonicCidrs() 依內容分辨版本
    const{ip,secondaryIps,ip6}=classifySonicCidrs(cidrs);
    interfaces.push({name,type:'physical',desc:'',mode:'routed',vlans:'',nativeVlan:'',
      vrf:'',ip,ip6,secondaryIps,shutdown:false,member:'1',hybrid:null,vrrp:[]});
  });

  // STATIC_ROUTE：key = "vrf-name|prefix"，'default' 正規化為 ''（比照其餘廠牌 parseXXXRoutes
  // 用空字串代表 global routing table 的既有慣例）
  const routes=Object.entries(db.STATIC_ROUTE||{}).map(([key,val])=>{
    const pipeIdx=key.indexOf('|');
    const vrf=key.slice(0,pipeIdx), dst=key.slice(pipeIdx+1);
    return{dst,gw:(val&&val.nexthop)||'',vrf:vrf==='default'?'':vrf,gwIsInterface:false};
  });

  // BGP：單一 device-level ASN＋逐 neighbor（SONiC 傳統模式無 router-id／network 宣告
  // 對應表格，routerId/networks 天生空值非缺漏）
  const bgp=[];
  if(bgpAsn!==undefined&&bgpAsn!==null&&bgpAsn!==''){
    const peers=Object.entries(db.BGP_NEIGHBOR||{}).map(([ip,val])=>({
      ip,as:String(val&&val.asn),desc:(val&&val.name)||'',
      type:String(val&&val.asn)===String(bgpAsn)?'iBGP':'eBGP'
    }));
    bgp.push({asn:String(bgpAsn),routerId:'',peers,networks:[]});
  }

  const stpFull=_parseSTPSONiC(cfg);
  const {sonicStpVlanIntf,...stp}=stpFull;
  const qos=_parseQoSSONiC(db);
  const snmp=_parseSnmpSONiC(db);
  const syslog=_parseSyslogSONiC(db);

  return{
    sys:{hostname,version:'',platform:''},irf:null,stack:null,vlans,interfaces,routes,lacp,
    vrfs:[],users:[],ospf:[],bgp,rip:[],vrrp:[],vxlan:null,vendor:'sonic',breakouts:[],stp,
    qos,sonicStpVlanIntf,snmp,syslog
  };
}


// ════════════════════════════════════
//  PARSER (embedded)
// ════════════════════════════════════


// Split cfg on "\n#\n" to get clean top-level sections
// ════════════════════════════════════
//  STATE
// ════════════════════════════════════
