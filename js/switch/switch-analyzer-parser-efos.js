// ══════════════════════════════════════════════════════════
//  Broadcom EFOS（Enhanced Fabric OS）PARSER — 2026-10-06，第十二輪 MM
// ══════════════════════════════════════════════════════════
// FASTPATH 系（與 Netgear M4300／Ubiquiti EdgeSwitch 同源），代表機型 NetApp BES-53248 叢集交換器。
// 語法依 Oxidized 的真實錄製（efos#BES-53248_3.12.0.1，存為 efos_real_oxidized.cfg）：
//   !System Description "EFOS, 3.12.0.1, …"、!System Software Version "x"
//   hostname "名稱"、serviceport ip 位址 遮罩 閘道（管理埠）
//   vlan database → vlan 10,103（逗號／範圍清單）、vlan name N "名稱"
//   username "帳號" password … encryption-type aes level 15 encrypted
//   port-channel name 1/1 名稱（LAG 以 1/x 定址）；實體埠區塊內 addport 1/1 加入 LAG；
//     LAG 區塊 no port-channel static＝LACP、port-channel static＝靜態
//   interface 0/9 … exit：description "…"、no shutdown／shutdown、mtu、switchport mode trunk|access、
//     switchport trunk allowed vlan 清單、switchport trunk native vlan N、switchport access vlan N、
//     vlan participation include 清單／vlan tagging 清單（舊式寫法，沒有 switchport 時採用）、
//     spanning-tree edgeport、service-policy in 名稱
//   spanning-tree mode pvst、spanning-tree bpduguard（全域：所有 edge port 啟用 BPDU Guard）
//   snmp-server community "名稱" ro、ntp server 主機、ip name server A B、ip ssh server enable、
//   ip telnet server enable、ip route 目的 遮罩 下一跳
// 同一介面在錄製中會出現兩個區塊（addport 一段、設定一段），依名稱合併。
// 未涵蓋：class-map／policy-map（Diffserv 語法與 Cisco 不同）、random-detect、OSPF、MLAG（mlag）。
function isEFOS(cfg){
  return /^!System Description\s+"EFOS\b/m.test(cfg)||(/^!System Software Version\s+"/m.test(cfg)&&/^serviceport\s+(?:ip|protocol)\b/m.test(cfg)&&/^port-channel\s+name\s+\d+\/\d+\s/m.test(cfg));
}
function efosVlanList(s){
  const out=[];
  String(s||'').split(',').forEach(t=>{
    const m=t.trim().match(/^(\d+)(?:-(\d+))?$/);
    if(!m)return;
    const a=+m[1],b=m[2]?+m[2]:a;
    for(let v=a;v<=Math.min(b,a+4094);v++)out.push(String(v));
  });
  return out;
}
const _efosUnq=s=>String(s||'').trim().replace(/^"(.*)"$/,'$1');
function parseEFOS(cfg){
  const val=re=>(cfg.match(re)||[])[1];
  const desc=val(/^!System Description\s+"([^"]*)"/m)||'';
  const sys={hostname:_efosUnq(val(/^hostname\s+(.+)$/m))||'EFOS',version:val(/^!System Software Version\s+"([^"]*)"/m)||(desc.split(',')[1]||'').trim(),
    model:'-',serial:'-',mgmtIp:val(/^serviceport\s+ip\s+(\d+\.\d+\.\d+\.\d+)/m)||''};
  // VLAN：vlan database 區塊內的清單與名稱
  const vdb=(cfg.match(/^vlan database\n([\s\S]*?)^exit\b/m)||[])[1]||'';
  const vids=new Set();
  vdb.split('\n').forEach(l=>{const m=l.match(/^\s*vlan\s+([\d,\-]+)\s*$/);if(m)efosVlanList(m[1]).forEach(v=>vids.add(v));});
  const declared=new Set(vids);
  const vnames={};
  [...vdb.matchAll(/^\s*vlan\s+name\s+(\d+)\s+(.+)$/gm)].forEach(m=>{vnames[m[1]]=_efosUnq(m[2]);vids.add(m[1]);declared.add(m[1]);});
  // 介面區塊（interface X … exit），同名合併
  const blocks=new Map();
  const re=/^interface\s+(\S+)\s*\n([\s\S]*?)^exit\b/gm;let m;
  while((m=re.exec(cfg))!==null)blocks.set(m[1],(blocks.get(m[1])||'')+m[2]);
  const lagNames={};
  [...cfg.matchAll(/^port-channel\s+name\s+(\d+\/\d+)\s+(.+)$/gm)].forEach(x=>{lagNames[x[1]]=_efosUnq(x[2]);});
  const members={};
  blocks.forEach((b,name)=>{const a=b.match(/^\s*addport\s+(\S+)\s*$/m);if(a)(members[a[1]]=members[a[1]]||[]).push(name);});
  const interfaces=[];
  blocks.forEach((b,name)=>{
    const g=r=>(b.match(r)||[])[1];
    const isLag=!!lagNames[name]||!!members[name];
    let mode=g(/^\s*switchport\s+mode\s+(\S+)/m)||'';
    let vlans='',nativeVlan='';
    if(mode==='trunk'){vlans=g(/^\s*switchport\s+trunk\s+allowed\s+vlan\s+(\S+)/m)||'';nativeVlan=g(/^\s*switchport\s+trunk\s+native\s+vlan\s+(\d+)/m)||'';}
    else if(mode==='access')vlans=g(/^\s*switchport\s+access\s+vlan\s+(\d+)/m)||'1';
    else if(/^\s*vlan\s+participation\s+include\s/m.test(b)){
      const tagged=g(/^\s*vlan\s+tagging\s+(\S+)/m);
      const inc=g(/^\s*vlan\s+participation\s+include\s+(\S+)/m);
      if(tagged){mode='trunk';vlans=inc;nativeVlan=g(/^\s*vlan\s+pvid\s+(\d+)/m)||'';}
      else{mode='access';vlans=g(/^\s*vlan\s+pvid\s+(\d+)/m)||inc;}
    }
    efosVlanList(vlans).forEach(v=>vids.add(v));
    interfaces.push({name,type:isLag?'lag':'physical',desc:_efosUnq(g(/^\s*description\s+(.+)$/m))||lagNames[name]||'',mode,vlans,nativeVlan,
      vrf:'',ip:'',shutdown:/^\s*shutdown\s*$/m.test(b),member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:'',
      mtu:g(/^\s*mtu\s+(\d+)/m)||''});
  });
  // LAG：port-channel name 宣告或有成員加入者；LAG 區塊的 port-channel static 決定靜態／LACP
  const lacp=[...new Set([...Object.keys(lagNames),...Object.keys(members)])].map(lag=>{
    const b=blocks.get(lag)||'';
    return {name:lag,mode:/^\s*port-channel\s+static\s*$/m.test(b)?'Static':'Active',members:(members[lag]||[]).map(n=>({name:n,lacpMode:null})),desc:lagNames[lag]||''};
  });
  // vlan database 沒宣告、只出現在介面上的 VLAN（如預設 VLAN 1）標為 implied
  const vlanList=[...vids].sort((a,b)=>a-b).map(id=>Object.assign({id,name:vnames[id]||'',ipSubnets:[]},declared.has(id)?{}:{implied:true}));
  const users=[...cfg.matchAll(/^username\s+("[^"]*"|\S+)\s+password\s+\S+(?:\s+encryption-type\s+(\S+))?\s+level\s+(\d+)/gm)]
    .map(x=>({name:_efosUnq(x[1]),role:'level-'+x[3],service:'ssh/console',hasPwd:true,pwdType:x[2]||'set',pwdWeak:false}));
  const routes=[...cfg.matchAll(/^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/gm)]
    .map(x=>({dst:x[1]+'/'+(typeof maskToCIDR==='function'?maskToCIDR(x[2]):x[2]),gw:x[3],vrf:''}));
  // STP：全域 bpduguard 套用在所有 edge port
  const bpduAll=/^spanning-tree\s+bpduguard\s*$/m.test(cfg);
  const stp={mode:val(/^spanning-tree\s+mode\s+(\S+)/m)||'',instances:[],rootMode:'',timers:{},
    ports:interfaces.filter(i=>/^\s*spanning-tree\s+edgeport\s*$/m.test(blocks.get(i.name)||'')).map(i=>({port:i.name,portfast:true,bpduguard:bpduAll,guardRoot:false,cost:null,priority:null}))};
  const snmp={communities:[...cfg.matchAll(/^snmp-server\s+community\s+("[^"]*"|\S+)(?:\s+(ro|rw))?/gm)].map(x=>({name:_efosUnq(x[1]),access:x[2]||'ro'})),v3Users:[],hosts:[]};
  const dns=[...cfg.matchAll(/^ip\s+name\s+server\s+([^\n]+)/gm)].flatMap(x=>x[1].trim().split(/\s+/)).filter(t=>/^[\d.]+$|:/.test(t));
  return {sys,irf:null,stack:null,vlans:vlanList,interfaces,routes,vrfs:[],users,ospf:[],bgp:[],rip:[],vrrp:[],vxlan:null,acls:[],
    lacp,stp,snmp,dns,dhcp:[],qos:[],breakouts:[],vendor:'efos',
    mgmtAccess:{ssh:/^ip\s+ssh\s+server\s+enable\s*$/m.test(cfg),telnet:/^ip\s+telnet\s+server\s+enable\s*$/m.test(cfg)}};
}
