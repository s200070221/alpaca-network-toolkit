function assembleSONiCConfig(model){
  const db={};
  db.DEVICE_METADATA={localhost:{hostname:model.sysname||'switch',disclaimer:tr('notice.disclaimer')}};
  if(model.bgp&&model.bgp.length&&model.bgp[0].asn)db.DEVICE_METADATA.localhost.bgp_asn=parseInt(model.bgp[0].asn,10);

  db.VLAN={};
  (model.vlans||[]).forEach(v=>{ db.VLAN[`Vlan${v.id}`]={}; });

  // VLAN_MEMBER：LACP 成員 port 一律跳過（VLAN 歸屬改記在 PortChannel 本身）
  db.VLAN_MEMBER={};
  const lacpMemberNames=new Set();
  (model.lacp||[]).forEach(l=>(l.members||[]).forEach(m=>lacpMemberNames.add(m)));
  function addSonicVlanMember(ownerName,iface){
    if(!iface)return;
    if(iface.mode==='access'&&iface.accessVlan){
      db.VLAN_MEMBER[`Vlan${iface.accessVlan}|${ownerName}`]={tagging_mode:'untagged'};
    }else if(iface.mode==='trunk'){
      (iface.trunkVlans||'').trim().split(/\s+/).filter(Boolean).forEach(vid=>{
        db.VLAN_MEMBER[`Vlan${vid}|${ownerName}`]={tagging_mode:'tagged'};
      });
      if(iface.nativeVlan)db.VLAN_MEMBER[`Vlan${iface.nativeVlan}|${ownerName}`]={tagging_mode:'untagged'};
    }
  }
  (model.interfaces||[]).forEach(iface=>{
    if(!lacpMemberNames.has(iface.name))addSonicVlanMember(iface.name,iface);
  });

  // PORTCHANNEL / PORTCHANNEL_MEMBER：比照 renderCiscoLACPExtra 的 refIface 慣例，用任一
  // 成員 port 在介面表格填的 trunk/access 設定套用到 PortChannel 本身
  db.PORTCHANNEL={};
  db.PORTCHANNEL_MEMBER={};
  (model.lacp||[]).forEach(l=>{
    const pcName=`PortChannel${l.id}`;
    db.PORTCHANNEL[pcName]={};
    (l.members||[]).forEach(mem=>{ db.PORTCHANNEL_MEMBER[`${pcName}|${mem}`]={}; });
    const refIface=(l.members||[]).map(m=>(model.interfaces||[]).find(i=>i.name===m)).find(Boolean);
    addSonicVlanMember(pcName,refIface);
  });

  // INTERFACE / VLAN_INTERFACE / PORTCHANNEL_INTERFACE：來自專屬「SONiC L3 介面 IP」卡片
  db.INTERFACE={};
  db.VLAN_INTERFACE={};
  db.PORTCHANNEL_INTERFACE={};
  (model.sonicL3Interfaces||[]).forEach(entry=>{
    if(!entry.name||!entry.cidr)return;
    const key=`${entry.name}|${entry.cidr}`;
    if(/^Vlan\d+$/i.test(entry.name))db.VLAN_INTERFACE[key]={};
    else if(/^PortChannel/i.test(entry.name))db.PORTCHANNEL_INTERFACE[key]={};
    else db.INTERFACE[key]={};
  });

  db.BGP_NEIGHBOR={};
  if(model.bgp&&model.bgp.length){
    (model.bgp[0].peers||[]).forEach(p=>{
      if(!p.ip)return;
      // local_addr 無對應表單欄位（generic BGP peer 卡片沒有「本地來源 IP」輸入），
      // MVP 不輸出，已知限制——FRR bgpd 可依直連介面自動判斷
      db.BGP_NEIGHBOR[p.ip]={asn:parseInt(p.as,10),name:p.desc||''};
    });
  }

  db.STATIC_ROUTE={};
  (model.routes||[]).forEach(r=>{
    if(!r.dst||!r.gw)return;
    const entry={nexthop:r.gw};
    if(r.metric)entry.distance=String(r.metric); // 表單欄位語意是 metric，SONiC 真實鍵名是 distance
    db.STATIC_ROUTE[`default|${r.dst}`]=entry;
  });

  // ACL_TABLE / ACL_RULE（2026-08-08 對外查證新增，原排除項目：官方文件＋真實範例確認欄位
  // PRIORITY/PACKET_ACTION/IP_PROTOCOL/SRC_IP/DST_IP/L4_DST_PORT/IP_TYPE，複合鍵
  // "{ACL表名}|{規則名}"）；與共用 ACL 表單形狀 {name,type,rules:[],appliedOn:[]} 相容，
  // type 固定輸出 'L3'（表單的 standard/extended 二分法對 SONiC 無對應概念，不臆測其他
  // type 值）；remark 列（無 action）SONiC 無對應概念，略過不輸出
  db.ACL_TABLE={};
  db.ACL_RULE={};
  (model.acl||[]).forEach(a=>{
    if(!a.name)return;
    db.ACL_TABLE[a.name]={policy_desc:a.name,type:'L3',ports:(a.appliedOn||[]).map(ap=>ap.interface).filter(Boolean)};
    (a.rules||[]).forEach((r,idx)=>{
      if(r.action!=='permit'&&r.action!=='deny')return;
      const entry={PRIORITY:parseInt(r.seq,10)||(9999-idx),PACKET_ACTION:r.action==='deny'?'DROP':'FORWARD',IP_TYPE:'IP'};
      const proto=SONIC_IP_PROTO[(r.protocol||'').toLowerCase()];
      if(proto)entry.IP_PROTOCOL=proto;
      const src=sonicAclAddr(r.src); if(src)entry.SRC_IP=src;
      const dst=sonicAclAddr(r.dst); if(dst)entry.DST_IP=dst;
      if(r.dstPort&&/^\d+$/.test(r.dstPort))entry.L4_DST_PORT=parseInt(r.dstPort,10);
      db.ACL_RULE[`${a.name}|rule_${idx+1}`]=entry;
    });
  });

  // STP / STP_VLAN / STP_INTF / STP_VLAN_INTF（2026-08-08 對外查證新增，原排除項目：官方
  // PVST HLD 文件確認完整 schema）；PVST 逐 VLAN 一個 instance，天然對應共用 STP 形狀的
  // instances 陣列設計；STP_VLAN_INTF（逐 VLAN 逐 port 覆寫，2026-08-08 補上）來自專屬
  // sonicStpVlanIntf 頂層欄位（共用 STP 形狀無 VLAN 維度，比照 sonicL3Interfaces 慣例）
  if(hasGlobalStpData(model.stp)||(model.stp&&model.stp.ports&&model.stp.ports.length)||(model.sonicStpVlanIntf&&model.sonicStpVlanIntf.length)){
    db.STP={GLOBAL:{mode:'pvst'}};
    // model.stp 可能是 undefined（例如僅填了 sonicStpVlanIntf 觸發本區塊、STP 本身未填），
    // 防禦性處理避免 model.stp.instances 對 undefined 取值噴錯
    const firstInst=(model.stp&&model.stp.instances||[])[0];
    if(firstInst&&firstInst.priority)db.STP.GLOBAL.priority=parseInt(firstInst.priority,10);
    db.STP_VLAN={};
    (model.stp&&model.stp.instances||[]).forEach(inst=>{
      if(!inst.id)return;
      const ve={enabled:'true'};
      if(inst.priority)ve.priority=parseInt(inst.priority,10);
      db.STP_VLAN[`Vlan${inst.id}`]=ve;
    });
    db.STP_INTF={};
    (model.stp&&model.stp.ports||[]).forEach(p=>{
      if(!p.port)return;
      const pe={enabled:'1'};
      if(p.bpduguard)pe.bpdu_guard='1';
      if(p.guardRoot)pe.root_guard='1';
      if(p.cost)pe.path_cost=parseInt(p.cost,10);
      if(p.priority)pe.priority=parseInt(p.priority,10);
      if(p.portfast)pe.portfast='1';
      db.STP_INTF[p.port]=pe;
    });
    db.STP_VLAN_INTF={};
    (model.sonicStpVlanIntf||[]).forEach(v=>{
      if(!v.vlan||!v.port)return;
      const e={};
      if(v.cost)e.path_cost=parseInt(v.cost,10);
      if(v.priority)e.priority=parseInt(v.priority,10);
      db.STP_VLAN_INTF[`Vlan${v.vlan}|${v.port}`]=e;
    });
  }

  // SCHEDULER / PORT_QOS_MAP / QUEUE（2026-08-08 對外查證新增，原排除項目：官方 QoS
  // Scheduler/Shaper HLD 文件＋硬體商真實範例交叉確認欄位）；DSCP→TC 分類（另一獨立功能）
  // 本輪不納入。apply 的 queue 欄位留空＝套用到 PORT_QOS_MAP（整埠），填數字＝套用到
  // QUEUE["target|queue"]（逐佇列）
  db.SCHEDULER={};
  (model.sonicQos&&model.sonicQos.schedulers||[]).forEach(s=>{
    if(!s.name)return;
    const e={};
    if(s.type)e.type=s.type;
    if(s.weight)e.weight=String(s.weight);
    if(s.meterType)e.meter_type=s.meterType;
    if(s.cir)e.cir=String(s.cir);
    if(s.cbs)e.cbs=String(s.cbs);
    if(s.pir)e.pir=String(s.pir);
    if(s.pbs)e.pbs=String(s.pbs);
    db.SCHEDULER[s.name]=e;
  });
  db.PORT_QOS_MAP={};
  db.QUEUE={};
  (model.sonicQos&&model.sonicQos.apply||[]).forEach(a=>{
    if(!a.target||!a.scheduler)return;
    if(a.queue)db.QUEUE[`${a.target}|${a.queue}`]={scheduler:a.scheduler};
    else db.PORT_QOS_MAP[a.target]={scheduler:a.scheduler};
  });

  // PAC_PORT_CONFIG / HOSTAPD_GLOBAL_CONFIG（802.1X，2026-08-08 對外查證新增，原排除項目：
  // 官方 Port Access Control HLD 文件確認欄位）；沿用共用 model.security（dot1x==='auth'
  // 才輸出該 port），guest VLAN／MAC port-security 查無官方欄位不猜測（portSec/violation/
  // guestVlan 不輸出）；任一 port 啟用即輸出全域 dot1x_system_auth_control 開關
  db.PAC_PORT_CONFIG={};
  let sonicAnyDot1x=false;
  (model.security||[]).forEach(s=>{
    if(!s.port||s.dot1x!=='auth')return;
    sonicAnyDot1x=true;
    const e={method_list:'dot1x',priority_list:'dot1x',port_pae_role:'authenticator',port_control_mode:'auto'};
    if(s.maxMac&&s.maxMac!=='-'&&/^\d+$/.test(s.maxMac)){
      e.host_control_mode='multi-auth';
      e.max_users_per_port=parseInt(s.maxMac,10);
    }else{
      e.host_control_mode='single-auth';
    }
    db.PAC_PORT_CONFIG[s.port]=e;
  });
  if(sonicAnyDot1x)db.HOSTAPD_GLOBAL_CONFIG={dot1x_system_auth_control:'enable'};

  // BREAKOUT_CFG：brkout_mode 只需簡化字串（如 "4x25G"），parser 端正則不要求 `[原始速率]`
  // 後綴即可正確解析回同一個 mode 值，故不需重建官方真實輸出常見的中括號附加資訊
  const sonicBreakouts=(model.breakouts||[]).filter(b=>b.vendor==='sonic');
  if(sonicBreakouts.length){
    db.BREAKOUT_CFG={};
    sonicBreakouts.forEach(b=>{ db.BREAKOUT_CFG[b.parentPort]={brkout_mode:b.mode}; });
  }

  return JSON.stringify(db,null,2)+'\n';
}
const SONIC_IP_PROTO={tcp:6,udp:17,icmp:1};
function sonicAclAddr(v){
  if(!v||v==='any')return '';
  const hostM=v.match(/^host\s+(\S+)/);
  return hostM?hostM[1]+'/32':v;
}

// VLAN membership 以 VLAN 為主體宣告（"configure vlan NAME add ports P tagged/untagged"），
// 需要 VLAN ID → NAME 對照表（EXOS 指令用名稱而非 ID），比照 Brocade renderBrocadeVLANs
// 的「先掃描 interfaces 依 VLAN 分組收集 tagged/untagged port，再逐 VLAN 輸出」慣例
// VLAN 名稱 -> 成員 port 清單（tagged/untagged 分開），供 renderExtremeVLANs() 與
// DHCP render（"enable dhcp ports" 需要該 VLAN 實際成員 port 清單，見下方 renderExtremeDHCPServer()）
// 共用，避免重複維護同一份 VLAN membership 推導邏輯
