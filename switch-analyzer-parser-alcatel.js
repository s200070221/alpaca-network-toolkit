function parseAlcatelSysInfo(cfg){
  const hostname=(cfg.match(/^->\s*system name\s+(.+)/m)||cfg.match(/^system name\s+(.+)/m)||[])[1]?.trim()||'unknown';
  const contact=(cfg.match(/^->\s*system contact\s+"?([^"\n]+)"?/m)||cfg.match(/^system contact\s+"?([^"\n]+)"?/m)||[])[1]?.trim()||'';
  return{hostname,version:'',contact};
}

function parseAlcatelVLANs(cfg){
  const vlans=[]; const seen=new Set(); let m;
  // Style A: -> vlan N [enable|admin-state enable] name NAME
  const reA=/^->\s*vlan\s+(\d+)(?:\s+admin-state\s+enable|\s+enable)?\s+name\s+(.+)/gm;
  while((m=reA.exec(cfg))!==null){const id=m[1],name=m[2].trim().replace(/^"|"$/g,'');if(!seen.has(id)){seen.add(id);vlans.push({id,name,ipSubnets:[]});}}
  // Style B: vlan N name "NAME"  (no arrow)
  const reB=/^vlan\s+(\d+)\s+name\s+"?([^"\n]+)"?/gm;
  while((m=reB.exec(cfg))!==null){const id=m[1],name=m[2].trim();if(!seen.has(id)){seen.add(id);vlans.push({id,name,ipSubnets:[]});}}
  // Style C: vlan N admin-state enable name "NAME"  (AOS 7/8 boot.cfg)
  const reC=/^vlan\s+(\d+)\s+admin-state\s+enable\s+name\s+"?([^"\n]+)"?/gm;
  while((m=reC.exec(cfg))!==null){const id=m[1],name=m[2].trim().replace(/^"|"$/g,'');if(!seen.has(id)){seen.add(id);vlans.push({id,name,ipSubnets:[]});}}
  // Collect from port assignments
  const memRe=/^(?:->\s*)?vlan\s+(\d+)\s+members/gm;
  while((m=memRe.exec(cfg))!==null)if(!seen.has(m[1])){seen.add(m[1]);vlans.push({id:m[1],name:'',ipSubnets:[]});}
  // "vlan N port default PORT" and "vlan N 802.1q LAGG"
  const portRe=/^vlan\s+(\d+)\s+(?:port\s+default\s+\S+|802\.1q\s+\S+)/gm;
  while((m=portRe.exec(cfg))!==null)if(!seen.has(m[1])){seen.add(m[1]);vlans.push({id:m[1],name:'',ipSubnets:[]});}
  // interface block: "  vlan N[,M...]"
  const blkRe=/^\s+vlan\s+([\d,]+)(?:\s+802\.1q)?/gm;
  while((m=blkRe.exec(cfg))!==null)m[1].split(',').forEach(v=>{const id=v.trim();if(id&&!seen.has(id)){seen.add(id);vlans.push({id,name:'',ipSubnets:[]});}});
  vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return vlans;
}

function parseAlcatelInterfaces(cfg){
  const ifaces=[],portVlans={}; let m;

  function addPort(port,vid,mode){
    if(!portVlans[port])portVlans[port]={tagged:[],untagged:[]};
    portVlans[port][mode].push(vid);
  }

  // Style A: vlan N members port P tagged|untagged（-> 前綴為選填，比照 parseAlcatelVLANs
  // 既有的 members 行判斷式 (?:->\s*)? 慣例——舊版寫死要求 -> 前綴，導致真實不帶箭頭的
  // fixture（如 alcatel_test.cfg）完全解析不到任何 port 的 mode/vlans，2026-07-14 修正）
  const memReA=/^(?:->\s*)?vlan\s+(\d+)\s+members\s+port\s+(\S+)\s+(tagged|untagged)/gm;
  while((m=memReA.exec(cfg))!==null) addPort(m[2],m[1],m[3]);

  // Style B: interface block  (vlan N inside block)
  function expandRange(range){
    const ports=[],rM=range.match(/^(\d+)\/(\d+)-(\d+)\/(\d+)$/)
                      ||range.match(/^(\d+)\/(\d+)\/(\d+)-(\d+)\/(\d+)\/(\d+)$/);
    if(rM){
      // 2-slot: s/p-s/p  or  3-slot: s/m/p-s/m/p
      if(rM.length===5){
        const s1=parseInt(rM[1]),p1=parseInt(rM[2]),s2=parseInt(rM[3]),p2=parseInt(rM[4]);
        if(s1===s2){for(let p=p1;p<=p2;p++)ports.push(s1+'/'+p);}
        else{for(let s=s1;s<=s2;s++){const st=s===s1?p1:1,en=s===s2?p2:48;for(let p=st;p<=en;p++)ports.push(s+'/'+p);}}
      }else if(rM.length===7){
        // AOS 8.x format: slot/module/port
        const [,s1,mi1,p1,s2,mi2,p2]=[...rM].map(Number);
        if(s1===s2&&mi1===mi2){for(let p=p1;p<=p2;p++)ports.push(s1+'/'+mi1+'/'+p);}
        else{ports.push(range);}
      }
    }else{ports.push(range);}
    return ports;
  }
  const blockRe=/^interface\s+(\S+)\n([\s\S]*?)^exit/gm;
  while((m=blockRe.exec(cfg))!==null){
    const rawName=m[1],body=m[2];
    const shutdown=/^\s*shutdown\b/m.test(body)&&!/no shutdown/.test(body);
    const vlanM=body.match(/^\s+vlan\s+([\d,]+)(?:\s+802\.1q)?/m);
    const vlanList=(vlanM||[])[1]||'',is8021q=!!(vlanM&&vlanM[0].includes('802.1q'));
    for(const port of(rawName.includes('-')?expandRange(rawName):[rawName])){
      if(!portVlans[port])portVlans[port]={tagged:[],untagged:[]};
      if(vlanList)vlanList.split(',').forEach(v=>{const vid=v.trim();if(vid){if(is8021q)portVlans[port].tagged.push(vid);else portVlans[port].untagged.push(vid);}});
      if(shutdown)portVlans[port]._shutdown=true;
    }
  }

  // Style C: "vlan N port default PORT"  (AOS access assignment)
  const portDefRe=/^vlan\s+(\d+)\s+port\s+default\s+(\S+)/gm;
  while((m=portDefRe.exec(cfg))!==null) addPort(m[2],m[1],'untagged');

  // Style D: "vlan N 802.1q LAGG_OR_PORT"  (AOS trunk assignment)
  const dot1qRe=/^vlan\s+(\d+)\s+802\.1q\s+(\S+)/gm;
  while((m=dot1qRe.exec(cfg))!==null){
    const vid=m[1],target=m[2];
    addPort(target,vid,'tagged');
  }

  // Aliases
  const aliases={};
  const aliasRe=/^->\s*interfaces?\s+(\S+)\s+alias\s+"?([^"\n]+)"?/gm;
  while((m=aliasRe.exec(cfg))!==null) aliases[m[1]]=m[2].trim();

  // Disabled ports
  const disabled=new Set();
  const disRe=/^->\s*interfaces?\s+(\S+)\s+admin-state\s+disable/gm;
  while((m=disRe.exec(cfg))!==null) disabled.add(m[1]);
  Object.entries(portVlans).forEach(([p,pv])=>{if(pv._shutdown)disabled.add(p);});

  // Ports that are LACP members (via interfaces P linkagg N)
  const lacpMembership={};  // port → laggId
  const ifLinkaggRe=/^interfaces\s+(\S+)\s+linkagg\s+(\d+)/gm;
  while((m=ifLinkaggRe.exec(cfg))!==null) lacpMembership[m[1]]='agg'+m[2];
  // Also arrow style
  const lacpPortRe=/^->\s*linkagg\s+lacp\s+port\s+(\S+)\s+actor\s+admin\s+key\s+(\d+)/gm;
  while((m=lacpPortRe.exec(cfg))!==null) lacpMembership[m[1]]='agg'+m[2];

  // All known ports
  const allPorts=new Set([...Object.keys(portVlans),...Object.keys(aliases),...Object.keys(lacpMembership)]);
  disabled.forEach(p=>allPorts.add(p));

  // Build physical list
  for(const port of[...allPorts].sort()){
    const pv=portVlans[port]||{tagged:[],untagged:[]};
    const desc=aliases[port]||'',shutdown=disabled.has(port)||pv._shutdown||false;
    let mode='',vlans='',nativeVlan='';
    if(pv.tagged.length&&pv.untagged.length){mode='trunk';vlans=[...new Set(pv.tagged)].join(',');nativeVlan=pv.untagged[0]||'';}
    else if(pv.tagged.length){mode='trunk';vlans=[...new Set(pv.tagged)].join(',');}
    else if(pv.untagged.length){mode='access';vlans=[...new Set(pv.untagged)][0]||'';}
    const lagMember=lacpMembership[port]||'';
    ifaces.push({name:port,type:'physical',desc,mode,vlans,nativeVlan,vrf:'',ip:'',shutdown,member:'1',hybrid:null,vrrp:[],lagMember});
  }

  // IP interfaces (SVIs) — all styles including quoted names with hyphens
  const ipRe=/^(?:->\s*)?ip interface\s+"?(\S+?)"?\s+address\s+([\d.]+)\s+mask\s+([\d.]+)(?:\s+vlan\s+(\d+))?/gm;
  while((m=ipRe.exec(cfg))!==null){
    const name=m[1].replace(/"/g,''),ip=m[2],mask=m[3],vid=m[4]||'';
    const cidr=ip+'/'+maskToCIDR(mask);
    const isLoop=name.toLowerCase().includes('loop')||mask==='255.255.255.255';
    ifaces.push({name,type:isLoop?'loopback':'svi',desc:'',mode:'',vlans:vid,nativeVlan:'',vrf:'',ip:cidr,shutdown:false,member:'1',hybrid:null,vrrp:[]});
  }

  // IPv6：兩段式指令，與上方 IPv4 單行語法結構不同（先 `ipv6 interface NAME
  // vlan N|loopback0` 建立具名介面，再 `ipv6 address CIDR NAME` 指派位址，位址
  // 在前、介面名稱在後）。先建立 name→vlanId／是否為 loopback0 對照表，再用
  // ipv6 address 行取得實際 CIDR 值。
  const v6IfRe=/^(?:->\s*)?ipv6 interface\s+"?(\S+?)"?\s+(?:vlan\s+(\d+)|(loopback0))/gm;
  const v6IfBind={};
  while((m=v6IfRe.exec(cfg))!==null){
    const name=m[1].replace(/"/g,'');
    v6IfBind[name]={vid:m[2]||'',isLoop:!!m[3]};
  }
  const v6AddrRe=/^(?:->\s*)?ipv6 address\s+(\S+\/\d+)\s+"?(\S+?)"?$/gm;
  while((m=v6AddrRe.exec(cfg))!==null){
    const ip6=m[1],name=m[2].replace(/"/g,'');
    const bind=v6IfBind[name]||{};
    const isLoop=bind.isLoop||name.toLowerCase().includes('loop');
    // 雙棧修復（2026-08-13 新增）：先前 IPv4/IPv6 兩段解析邏輯完全獨立，各自 push 出獨立的
    // ifaces 陣列元素，若同名介面同時有 IPv4+IPv6 會產生兩筆 name 相同的物件，任何用
    // .find(i=>i.name===x) 依名稱查找單一介面的下游邏輯只會取到第一筆（IPv4）、IPv6 那筆
    // 被架空。改為先查找是否已有同名的 IPv4 介面物件，有則合併進其 ip6 欄位；找不到（純
    // IPv6-only 介面）才維持 push 新物件，值存進 ip6（ip 留空字串，不塞進 ip 造成語意混淆）
    const existing=ifaces.find(i=>i.name===name);
    if(existing){
      existing.ip6=ip6;
    }else{
      ifaces.push({name,type:isLoop?'loopback':'svi',desc:'',mode:'',vlans:bind.vid||'',nativeVlan:'',vrf:'',ip:'',ip6,shutdown:false,member:'1',hybrid:null,vrrp:[]});
    }
  }
  return ifaces;
}

function parseAlcatelLACP(cfg){
  const lacp=[]; let m;
  // Collect aggregate IDs — both styles
  const aggSet=new Set();
  // Style A: -> linkagg lacp agg N actor admin key K
  const aggReA=/^->\s*linkagg\s+lacp\s+agg\s+(\d+)/gm;
  while((m=aggReA.exec(cfg))!==null) aggSet.add(m[1]);
  // Style B: linkagg lacp N admin-state enable (no "agg" keyword) — both with and without ->
  const aggReB=/^(?:->\s*)?linkagg\s+lacp\s+(\d+)\s+(?:admin-state|size|actor)/gm;
  while((m=aggReB.exec(cfg))!==null) aggSet.add(m[1]);
  // Style C: linkagg lacp agg N size/admin-state/actor（無 -> 前綴＋帶 agg 關鍵字，
  // 官方 show running-config 匯出格式，經對外查證 CLI Reference Guide PDF 原文確認）
  const aggReC=/^linkagg\s+lacp\s+agg\s+(\d+)\s+(?:size|admin-state|actor)/gm;
  while((m=aggReC.exec(cfg))!==null) aggSet.add(m[1]);

  // Build key→agg map for arrow style
  const keyToAgg={};
  aggSet.forEach(agg=>{
    const keyM=cfg.match(new RegExp('^->\\s*linkagg\\s+lacp\\s+agg\\s+'+agg+'\\s+actor\\s+admin\\s+key\\s+(\\d+)','m'));
    if(keyM) keyToAgg[keyM[1]]=agg;
    // Style B actor admin-key
    const keyM2=cfg.match(new RegExp('^linkagg\\s+lacp\\s+'+agg+'\\s+actor\\s+admin-key\\s+(\\d+)','m'));
    if(keyM2) keyToAgg[keyM2[1]]=agg;
    // Style C actor admin-key（無 ->，hyphenated，與 Style A 的 "admin key" 空格寫法不同）
    const keyM3=cfg.match(new RegExp('^linkagg\\s+lacp\\s+agg\\s+'+agg+'\\s+actor\\s+admin-key\\s+(\\d+)','m'));
    if(keyM3) keyToAgg[keyM3[1]]=agg;
  });

  const membersByAgg={};
  // Arrow style: -> linkagg lacp port P actor admin key K
  const portReA=/^->\s*linkagg\s+lacp\s+port\s+(\S+)\s+actor\s+admin\s+key\s+(\d+)/gm;
  while((m=portReA.exec(cfg))!==null){
    const agg=keyToAgg[m[2]]||m[2];
    membersByAgg[agg]=(membersByAgg[agg]||[]).concat(m[1]);
  }
  // Style C: linkagg lacp port P actor admin-key K（無 -> 前綴）
  const portReC=/^linkagg\s+lacp\s+port\s+(\S+)\s+actor\s+admin-key\s+(\d+)/gm;
  while((m=portReC.exec(cfg))!==null){
    const agg=keyToAgg[m[2]]||m[2];
    membersByAgg[agg]=(membersByAgg[agg]||[]).concat(m[1]);
  }
  // Flat style: interfaces P/S/I linkagg N  (with or without ->)
  const portReB=/^(?:->\s*)?interfaces\s+(\S+)\s+linkagg\s+(\d+)/gm;
  while((m=portReB.exec(cfg))!==null){
    const agg=m[2], port=m[1];
    membersByAgg[agg]=(membersByAgg[agg]||[]).concat(port);
  }

  // Build LACP entries
  for(const agg of aggSet){
    // Get description if available
    const descM=cfg.match(new RegExp('^linkagg\\s+lacp\\s+'+agg+'\\s+(?:admin-state\\s+enable\\s+)?name\\s+"?([^"\\n]+)"?','m'))
               ||cfg.match(new RegExp('^->\\s*linkagg\\s+lacp\\s+agg\\s+'+agg+'.*name\\s+"?([^"\\n]+)"?','m'));
    const desc=(descM||[])[1]?.trim()||'';
    lacp.push({name:'agg'+agg,mode:'active',members:membersByAgg[agg]||[],desc});
  }
  lacp.sort((a,b)=>parseInt(a.name.replace(/\D/g,''))-parseInt(b.name.replace(/\D/g,'')));
  return lacp;
}

function parseAlcatelRoutes(cfg){
  const routes=[]; let m;
  const reA=/^->\s*ip static-route\s+([\d./]+)\s+gateway\s+([\d.]+)/gm;
  while((m=reA.exec(cfg))!==null)routes.push({dst:m[1],gw:m[2],vrf:'',gwIsInterface:false});
  const reB=/^ip route\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)/gm;
  while((m=reB.exec(cfg))!==null){const dst=m[1]+'/'+maskToCIDR(m[2]),gw=m[3];if(!routes.find(r=>r.dst===dst))routes.push({dst,gw,vrf:'',gwIsInterface:false});}
  const dgRe=/^->\s*ip default-gateway\s+([\d.]+)/gm;
  while((m=dgRe.exec(cfg))!==null)if(!routes.find(r=>r.dst==='0.0.0.0/0'))routes.push({dst:'0.0.0.0/0',gw:m[1],vrf:'',gwIsInterface:false});
  // IPv6 靜態路由（2026-08-13 十一續新增）：官方語法 "ipv6 static-route PREFIX/LEN gateway ADDR"，
  // "->" 前綴設為選填，比照上方 v4 reA 的既有慣例
  const reA6=/^(?:->\s*)?ipv6 static-route\s+(\S+)\s+gateway\s+(\S+)/gm;
  while((m=reA6.exec(cfg))!==null)routes.push({dst:m[1],gw:m[2],vrf:'',gwIsInterface:false});
  return routes;
}


function parseAlcatelOSPF(cfg){
  const hasOSPF=/^->\s*ip ospf status enable/m.test(cfg)||/^ip ospf\b/m.test(cfg)||/^->\s*ip ospf\b/m.test(cfg)||/^ip\s+ospf\s+admin-state\s+enable/m.test(cfg)||/^ip\s+load\s+ospf/m.test(cfg);
  if(!hasOSPF)return[];
  const rid=(cfg.match(/^(?:->\s*)?ip ospf router-id\s+([\d.]+)/m)||[])[1]||'';
  const areas={}; let m;
  const areaRe=/^(?:->\s*)?ip ospf area\s+([\d.]+)/gm;
  while((m=areaRe.exec(cfg))!==null)areas[m[1]]=areas[m[1]]||[];
  const ifRe=/^(?:->\s*)?ip ospf interface\s+"?(\S+?)"?\s+area\s+([\d.]+)/gm;
  while((m=ifRe.exec(cfg))!==null){const iname=m[1].replace(/"/g,''),area=m[2];if(!areas[area])areas[area]=[];areas[area].push({network:iname,wildcard:'',type:'interface'});}
  const areaList=Object.entries(areas).map(([area,networks])=>({area,networks}));
  return areaList.length?[{pid:'1',routerId:rid,areas:areaList,protocol:'ospf'}]:[];
}


function parseAlcatelBGP(cfg){
  const asn=(cfg.match(/^->\s*ip bgp autonomous-system\s+(\d+)/m)||[])[1]||'';
  if(!asn)return[];
  const rid=(cfg.match(/^->\s*ip bgp router-id\s+([\d.]+)/m)||[])[1]||'';
  const peers=[]; let m;
  const re=/^->\s*ip bgp neighbor\s+([\d.]+)\s+remote-autonomous-system\s+(\d+)/gm;
  while((m=re.exec(cfg))!==null){
    const ip=m[1], peerAS=m[2];
    const desc=(cfg.match(new RegExp('^->\\s*ip bgp neighbor\\s+'+ip.replace(/\./g,'\\.')+'\\s+description\\s+"?([^"\\n]+)"?','m'))||[])[1]?.trim()||'';
    peers.push({ip,as:peerAS,desc,type:peerAS===asn?'iBGP':'eBGP'});
  }
  // 2026-07-17 對外查證官方 OmniSwitch AOS Release 8 Advanced Routing Configuration
  // Guide「Configuring Local Routes (Networks)」章節確認：`-> ip bgp network <ip> <mask>`
  // （點分遮罩格式非 CIDR，比照其餘 Alcatel BGP 指令需要 -> 前綴）
  const networks=[]; let nm;
  const nr=/^->\s*ip bgp network\s+([\d.]+)\s+([\d.]+)/gm;
  while((nm=nr.exec(cfg))!==null)networks.push(nm[1]+'/'+cidrFromMask(nm[2]));
  return peers.length?[{asn,routerId:rid,peers,networks}]:[];
}

// 已查證 Alcatel-Lucent OmniSwitch AOS 官方 CLI Reference Manual（透過 ManualsLib
// 交叉確認）真實語法：vrrp <vrid> <vlan_id> enable|disable / priority <n> /
// ip <ip_address> / preempt|no preempt，逐行個別指令設定，VRID 建立於 VLAN 之上。
// 2026-07-14 查證修正：原本兩個分支（-> 前綴 + virtual-address 的 Style A、
// admin-state/address 關鍵字的 Style B）皆查無官方來源佐證，予以移除，只保留
// 修正後對照官方文件的單一真實語法路徑。
function parseAlcatelVRRP(cfg){
  const groups=[]; let m;
  const vrids=new Set();
  const scanRe=/^vrrp\s+(\d+)\s+(\d+)\s+(?:enable|disable|priority|ip|preempt)/gm;
  while((m=scanRe.exec(cfg))!==null) vrids.add(m[1]+':'+m[2]);

  for(const key of vrids){
    const [vrid,vlanId]=key.split(':');
    const ipM=cfg.match(new RegExp('^vrrp\\s+'+vrid+'\\s+'+vlanId+'\\s+ip\\s+([\\d.]+)','m'));
    const prioM=cfg.match(new RegExp('^vrrp\\s+'+vrid+'\\s+'+vlanId+'\\s+priority\\s+(\\d+)','m'));
    const preM=cfg.match(new RegExp('^vrrp\\s+'+vrid+'\\s+'+vlanId+'\\s+preempt\\b','m'));
    const vip=(ipM||[])[1]||'';
    const prio=(prioM||[])[1]||'100';
    const preempt=!!preM;
    // Map vlanId to actual interface name via "ip interface X vlan N"
    const ifNameM=cfg.match(new RegExp('ip interface\\s+([\\S]+)\\s+address[^\\n]+vlan\\s+'+vlanId+'\\b','m'));
    const iface=(ifNameM||[])[1]?.replace(/"/g,'')||'vlan'+vlanId;
    groups.push({vrid,interface:iface,vip,priority:prio,preempt,authMode:'',trackIf:'',trackReduced:'',version:'2'});
  }
  return groups;
}

function parseAlcatelUsers(cfg){
  const users=[]; const seen=new Set(); let m;
  const reA=/^->\s*user\s+(\S+)\s+password\s+(\S+)(.*)/gm;
  while((m=reA.exec(cfg))!==null){
    const name=m[1]; if(seen.has(name))continue; seen.add(name);
    let rawPwd=m[2],rest=(m[3]||'').trim(),pwdHash=rawPwd;
    if(rawPwd==='cleartext'){const pts=rest.split(/\s+/);pwdHash=pts[0]||'';rest=pts.slice(1).join(' ');}
    const role=(rest.match(/\brole\s+(\S+)/)||[])[1]||'';
    let pwdType='',pwdWeak=false;
    if(rawPwd==='cleartext'){pwdType='cleartext';pwdWeak=true;}
    else if(pwdHash.startsWith('$2y$')||pwdHash.startsWith('$2b$')){pwdType='bcrypt';pwdWeak=false;}
    else if(pwdHash.startsWith('$1$')){pwdType='md5';pwdWeak=true;}
    else if(pwdHash.startsWith('$6$')){pwdType='sha512';pwdWeak=false;}
    else{pwdType='hash';pwdWeak=false;}
    users.push({name,role,service:'console/ssh',hasPwd:true,pwdType,pwdWeak});
  }
  const blockRe=/^user add\s+(\S+)\n([\s\S]*?)^exit/gm;
  while((m=blockRe.exec(cfg))!==null){
    const name=m[1]; if(seen.has(name))continue; seen.add(name);
    const body=m[2];
    const pwd=(body.match(/^\s*password\s+(\S+)/m)||[])[1]||'';
    const role=(body.match(/^\s*profile\s+(\S+)/m)||[])[1]||'';
    const pwdWeak=!pwd.startsWith('$');
    const pwdType=pwd.startsWith('$6$')?'sha512':pwd.startsWith('$2y$')?'bcrypt':pwd.startsWith('$1$')?'md5':pwdWeak?'plaintext':'hash';
    users.push({name,role,service:'console/ssh',hasPwd:!!pwd,pwdType,pwdWeak});
  }
  return users;
}


function parseAlcatelStack(cfg){
  // Style A: "stack set slot N"  (interactive CLI)
  // Style B: "stacking slot N priority P"  (boot.cfg)
  const hasStackA=/^stack\s+(?:enable|set\s+slot)/m.test(cfg);
  const hasStackB=/^stacking\s+slot\s+\d/m.test(cfg);
  if(!hasStackA&&!hasStackB)return null;
  const members=[]; const seen=new Set(); let m;
  if(hasStackA){
    const slotRe=/^stack\s+set\s+slot\s+(\d+)/gm;
    while((m=slotRe.exec(cfg))!==null){if(seen.has(m[1]))continue;seen.add(m[1]);members.push({id:m[1],role:m[1]==='1'?'Master':'Standby',priority:m[1]==='1'?255:200,model:'\u2014',serial:''});}
  }
  if(hasStackB){
    const slotRe=/^stacking\s+slot\s+(\d+)\s+priority\s+(\d+)/gm;
    while((m=slotRe.exec(cfg))!==null){
      if(seen.has(m[1]))continue; seen.add(m[1]);
      const prio=parseInt(m[2]);
      members.push({id:m[1],role:'',priority:prio,model:'\u2014',serial:''});
    }
    // Assign roles: highest priority = Master
    if(members.length){
      const maxPrio=Math.max(...members.map(x=>x.priority));
      members.forEach(x=>{x.role=x.priority===maxPrio?'Master':'Standby';});
    }
  }
  members.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  if(!members.length)return null;
  // Stack port info
  const linkPorts={};
  const portReA=/^stack\s+port\s+(\d+)\/(\d+)/gm;
  while((m=portReA.exec(cfg))!==null){if(!linkPorts[m[1]])linkPorts[m[1]]=[];linkPorts[m[1]].push(m[1]+'/'+m[2]);}
  const links=members.slice(0,-1).map((mem,i)=>({id:String(i+1),ports:[...(linkPorts[mem.id]||[]),...(linkPorts[members[i+1].id]||[])],desc:'M'+mem.id+'\u2194M'+members[i+1].id}));
  return{type:'Stack',members,links};
}

function parseAlcatel(cfg){
  return{
    sys:        parseAlcatelSysInfo(cfg),
    irf:null, stack:parseAlcatelStack(cfg),
    vlans:      parseAlcatelVLANs(cfg),
    interfaces: parseAlcatelInterfaces(cfg),
    lacp:       parseAlcatelLACP(cfg),
    routes:     parseAlcatelRoutes(cfg),
    vrfs:[], dhcp:[],
    users:      parseAlcatelUsers(cfg),
    ospf:       parseAlcatelOSPF(cfg),
    bgp:        parseAlcatelBGP(cfg),
    vrrp:       parseAlcatelVRRP(cfg),
    rip:[], vxlan:null,
    vendor:'alcatel'
  };
}


// ═ ExtremeXOS Parser ═
// ════════════════════════════════════════════════════════════
//  Extreme Networks ExtremeXOS (EXOS) Parser
//  CLI philosophy: "verb object parameters" (create/configure/enable)
//  Zero syntax overlap with other vendors → easiest detection
// ════════════════════════════════════════════════════════════

