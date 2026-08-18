function parseCiscoSysInfo(cfg){
  return{
    hostname:(cfg.match(/^hostname\s+(\S+)/m)||[])[1]||'unknown',
    version:(cfg.match(/^(?:!|)\s*Cisco IOS.*?Version\s+([^\s,\n]+)/m)||cfg.match(/version\s+(\S+)/)||[])[1]?.trim()||'',
    platform:(cfg.match(/^[!;]\s*(WS-C\S+|C\d{4}|catalyst)/im)||[])[1]||'',
  };
}

// ── StackWise ─────────────────────────────────────────────────
function parseCiscoStack(cfg){
  const members=[];
  let m;
  // StackWise: "switch N provision MODEL"
  const sr=/^switch\s+(\d+)\s+provision\s+(\S+)/gm;
  while((m=sr.exec(cfg))!==null)members.push({id:m[1],model:m[2],priority:null,role:null});
  // StackWise priority: "switch N priority N"
  const pr=/^switch\s+(\d+)\s+priority\s+(\d+)/gm;
  while((m=pr.exec(cfg))!==null){const mem=members.find(x=>x.id===m[1]);if(mem)mem.priority=parseInt(m[2]);}
  // StackWise role: "switch N role active|standby"
  const rr=/^switch\s+(\d+)\s+role\s+(\S+)/gm;
  while((m=rr.exec(cfg))!==null){const mem=members.find(x=>x.id===m[1]);if(mem)mem.role=m[2];}
  // Derive role by priority if not explicit
  if(members.length>0&&!members.some(x=>x.role)){
    const sorted=[...members].sort((a,b)=>(b.priority||0)-(a.priority||0));
    sorted.forEach((mem,i)=>mem.role=i===0?'Active':i===1?'Standby':'Member');
  }
  members.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  // Stack links from TenGigabit stack interfaces
  const links=[];
  const lr=/^interface\s+(TenGigabitEthernet\d+\/1\/[12])\s*\n([\s\S]*?)(?=^interface|(?![\s\S]))/gm;
  while((m=lr.exec(cfg))!==null){
    const desc=(m[2].match(/description\s+([^\n]+)/)||[])[1]||'';
    if(/stack|sw-sw|cascade/i.test(desc))links.push({id:m[1],ports:[m[1]],desc});
  }
  return members.length>0?{type:'StackWise',members,links}:null;
}

// ── VLANs ─────────────────────────────────────────────────────
function parseCiscoVLANs(cfg){
  const vlans=[];
  // VLAN database format: "vlan N" block with optional "name X"
  const re=/^vlan\s+(\d+)\s*\n([\s\S]*?)(?=^vlan\s|^!)/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const id=m[1],body=m[2]||'';
    const name=(body.match(/^\s*name\s+(.+)/m)||[])[1]?.trim()||'';
    vlans.push({id,name,ipSubnets:[]});
  }
  // Single-line "vlan N" with no body (check if not already added)
  const re2=/^vlan\s+(\d+)$/gm;
  while((m=re2.exec(cfg))!==null){if(!vlans.find(v=>v.id===m[1]))vlans.push({id:m[1],name:'',ipSubnets:[]});}
  vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return vlans;
}

// ── Interfaces ─────────────────────────────────────────────────
// vendor（2026-08-08 新增，預設 'cisco' 向下相容）：Arista EOS 4.23 train（2019-08 起）已廢棄
// Cisco 式 "ip vrf forwarding NAME"，官方確認改用裸 "vrf NAME"；parseArista() 與 parseCisco()
// 共用本函式解析 interface 區塊，故用 vendor 分流 VRF 偵測正則，其餘邏輯完全不變
function parseCiscoInterfaces(cfg,vendor){
  const vrfRe=vendor==='arista'?/^\s*vrf\s+(\S+)/m:/ip vrf forwarding\s+(\S+)/;
  const ifaces=[];
  const blocks=cfg.split(/^interface\s+/m).slice(1);
  for(const blk of blocks){
    const lines=blk.split('\n');
    const name=lines[0].trim();
    const body=lines.slice(1).join('\n');
    const desc=(body.match(/^\s*description\s+(.+)/m)||[])[1]?.trim()||'';
    // Cisco: port is shutdown if "shutdown" appears and no "no shutdown"
    const shutdown=/^\s*shutdown\s*$/m.test(body)&&!/no shutdown/.test(body);
    // Member ID from interface name: GigabitEthernet2/0/1 → member "2"
    const memberMatch=name.match(/(?:GigabitEthernet|TenGigabitEthernet|FastEthernet|HundredGigE)(\d+)\//i);
    const member=memberMatch?memberMatch[1]:'1';

    // 次要IP（Secondary IP，官方 Cisco IP Addressing Services Command Reference：
    // `ip address A.B.C.D M.M.M.M secondary`，Arista EOS 共用同一語法／同一 parser
    // 分流路徑；2026-08-17 從「僅取第一筆」擴大為完整收集）
    const secondaryIps=[...body.matchAll(/^\s*ip address\s+(\S+)\s+(\S+)\s+secondary/gm)].map(m=>m[1]+'/'+cidrFromMask(m[2]));
    // Loopback
    if(/^Loopback/i.test(name)){
      let ip=(body.match(/^\s*ip address\s+(\S+\s+\S+)/m)||[])[1]||'';
      // IPv6（試點 5 廠牌之一，標準 Cisco/Arista 語法 `ipv6 address ADDR/PREFIXLEN`）
      if(!ip)ip=(body.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增）：ip6 獨立無條件擷取，不再受 if(!ip) 影響（同一介面
      // 同時設定 IPv4+IPv6 時，原本 ipv6 只在 ip 為空時才讀取，雙棧會靜默丟失 IPv6）
      const ip6=(body.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      ifaces.push({name,type:'loopback',desc,ip,ip6,secondaryIps,mode:'',vlans:'',nativeVlan:'',vrf:'',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:'',breakoutScheme:''});
      continue;
    }
    // SVI: Vlan interface
    if(/^Vlan/i.test(name)){
      const ipRaw=(body.match(/^\s*ip address\s+(\S+)\s+(\S+)/m)||[]);
      let ip=ipRaw[1]&&ipRaw[2]?ipRaw[1]+'/'+cidrFromMask(ipRaw[2]):(body.match(/^\s*ip address\s+([\d.]+\/\d+)/m)||[])[1]||'';
      if(!ip)ip=(body.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，同 Loopback）
      const ip6=(body.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      const vrf=(body.match(vrfRe)||[])[1]||'';
      // HSRP as VRRP equivalent
      const vrrpList=[];let hm;
      const hr=/standby\s+(\d+)\s+ip\s+(\S+)/g;
      while((hm=hr.exec(body))!==null){
        const prio=(body.match(new RegExp('standby\\s+'+hm[1]+'\\s+priority\\s+(\\d+)'))||[])[1]||'100';
        vrrpList.push({vrid:hm[1],vip:hm[2],priority:prio,type:'HSRP'});
      }
      ifaces.push({name,type:'svi',desc,ip,ip6,secondaryIps,mode:'',vlans:'',nativeVlan:'',vrf,shutdown,member:'1',hybrid:null,vrrp:vrrpList,breakoutChild:false,breakoutParent:'',breakoutMode:'',breakoutScheme:''});
      continue;
    }
    // Management (no routing)
    if(/^Management/i.test(name)){
      let ip=(body.match(/^\s*ip address\s+(\S+\s+\S+)/m)||[])[1]||'';
      if(!ip)ip=(body.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，同 Loopback）
      const ip6=(body.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      ifaces.push({name,type:'physical',desc,ip,ip6,secondaryIps,mode:'',vlans:'',nativeVlan:'',vrf:'MGMT',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:'',breakoutScheme:''});
      continue;
    }
    // Physical / Stack
    let mode='',vlans='',nativeVlan='',vrf='';
    const noRouting=/no switchport/.test(body);
    if(noRouting){
      // Routed port
      let ip=(body.match(/^\s*ip address\s+(\S+(?:\s+\S+)?)/m)||[])[1]||'';
      if(!ip)ip=(body.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，同 Loopback）
      const ip6=(body.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      vrf=(body.match(vrfRe)||[])[1]||'';
      ifaces.push({name,type:'physical',desc,mode:'routed',vlans:'',nativeVlan:'',vrf,ip,ip6,secondaryIps,shutdown,member,hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:'',breakoutScheme:''});
      continue;
    }
    // Switchport
    const modeMatch=body.match(/switchport mode\s+(\S+)/);
    if(modeMatch){
      const sm=modeMatch[1];
      if(sm==='trunk'){
        mode='trunk';
        vlans=(body.match(/switchport trunk allowed vlan\s+([^\n]+)/)||[])[1]?.trim()||'all';
        nativeVlan=(body.match(/switchport trunk native vlan\s+(\d+)/)||[])[1]||'1';
      }else if(sm==='access'){
        mode='access';
        vlans=(body.match(/switchport access vlan\s+(\d+)/)||[])[1]||'1';
      }else{
        mode=sm;
      }
    }
    const channelGrp=(body.match(/channel-group\s+(\d+)/)||[])[1]||'';
    const portfast=/spanning-tree portfast/.test(body)&&!/spanning-tree portfast disable/.test(body);
    const isStack=/^TenGigabitEthernet\d+\/1\/[12]$/i.test(name);
    // Breakout Layer 1（僅 pattern B：9500-32C 型同介面類型＋第4段子埠編號可從名稱直接判斷；
    // pattern A 的模組換位編號因無法從名稱反推母埠，回填邏輯在 parseCisco() 聚合函式的 post-pass 處理）
    const bkMatch=name.match(/^HundredGigE(\d+\/\d+\/\d+)\/([1-4])$/i);
    const breakoutChild=!!bkMatch;
    const breakoutParent=bkMatch?`HundredGigE${bkMatch[1]}`:'';
    ifaces.push({name,type:isStack?'stack':'physical',desc,mode,vlans:vlans.trim(),nativeVlan,vrf,ip:'',shutdown,member,hybrid:null,vrrp:[],channelGrp,portfast,breakoutChild,breakoutParent,breakoutMode:'',breakoutScheme:bkMatch?'suffix':''});
  }
  return ifaces;
}

// Breakout（QSFP 拆分子埠）：Cisco IOS-XE 官方文件記載兩種完全不同的模式，非單一 pattern：
// pattern A（9300X-48HX + NM-4C 網路模組）：`hw-module breakout module <slot> port <range> switch <num>`，
//   子埠改用不同介面類型且重新編號（換算規則依機型差異大，僅此組合已對外查證，不套用到其他機型）；
//   port-range 官方文件定義為單一埠或範圍（如 `1-2`/`1,3`），視為對每個埠分別套用同一動作的語法糖，
//   展開成個別埠號後逐一沿用同一已查證公式，不發明新編號規則（來源見 plan.md/now.md）
// pattern B（9500-32C）：`hw-module breakout <port>`，子埠維持同介面類型＋附加第4段編號，可直接從名稱判斷
function expandPortRange(rangeStr){
  const ports=[];
  for(const part of rangeStr.split(',')){
    const m=part.match(/^(\d+)-(\d+)$/);
    if(m){for(let i=+m[1];i<=+m[2];i++)ports.push(i);}
    else if(/^\d+$/.test(part))ports.push(+part);
  }
  return ports;
}
function parseCiscoBreakout(cfg){
  const breakouts=[]; let m;
  const reA=/^hw-module breakout module\s+(\d+)\s+port\s+([\d,\-]+)\s+switch\s+(\d+)/gm;
  while((m=reA.exec(cfg))!==null){
    const [,slot,portRange,sw]=m;
    for(const portNum of expandPortRange(portRange)){
      breakouts.push({parentPort:`module${slot}/port${portNum}`,mode:'4x10G',scheme:'renumber',switchNum:sw,raw:m[0]});
    }
  }
  const reB=/^hw-module breakout\s+(\S+)\s*$/gm;
  while((m=reB.exec(cfg))!==null){
    breakouts.push({parentPort:m[1],mode:'4x10G',scheme:'suffix',raw:m[0]});
  }
  return breakouts;
}

// ── Routes ────────────────────────────────────────────────────
function parseCiscoRoutes(cfg){
  const routes=[];
  // "ip route [vrf VRF] DST MASK GW"
  const re=/^ip route(?:\s+vrf\s+(\S+))?\s+(\S+)\s+(\S+)\s+(\S+)/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const vrf=m[1]||'';
    let dst=m[2],mask=m[3],gw=m[4];
    // Fix 3: Support interface-name as next-hop (e.g. Null0, Serial0/1)
    if(mask.match(/^\d+\.\d+\.\d+\.\d+$/)){dst=dst+'/'+cidrFromMask(mask);}
    else if(/^\d+$/.test(mask)){dst=dst+'/'+mask;}
    else{const iface=mask;gw=iface+(gw?' '+gw:'');dst=dst+'/0';}
    const gwIsInterface=gw&&!gw.match(/^\d+\.\d+\.\d+\.\d+/);
    routes.push({dst,gw,vrf,gwIsInterface});
  }
  // IPv6 靜態路由（2026-08-13 十一續新增）：官方語法 "ipv6 route [vrf VRF] PREFIX/LEN NEXTHOP"，
  // 獨立關鍵字非 "ip route" 放寬字元類別可解決，prefix/length 已是單一 token 不需 mask 換算；
  // Arista EOS 委派同一函式（parseArista()→parseCiscoRoutes()）免費一起修好
  const re6=/^ipv6 route(?:\s+vrf\s+(\S+))?\s+(\S+)\s+(\S+)/gm;
  while((m=re6.exec(cfg))!==null){
    const vrf=m[1]||'';
    const dst=m[2],gw=m[3];
    const gwIsInterface=gw&&!gw.includes(':');
    routes.push({dst,gw,vrf,gwIsInterface});
  }
  return routes;
}

// ── VRFs ─────────────────────────────────────────────────────
function parseCiscoVRFs(cfg,vendor){
  const vrfs=[];let m;
  // 2026-08-09 稽核修復：Arista EOS 4.23+ 官方 VRF 建立語法是裸 "vrf instance NAME"
  // （已廢棄 "ip vrf"/"vrf definition"），先前 parseArista() 直接沿用 Cisco 專屬正則，
  // 導致 Arista 自己產生的設定（switch_config_generator assembleAristaConfig() 輸出的
  // 就是這個語法）丟回來解析永遠讀不到 VRF，round-trip 缺陷
  if(vendor==='arista'){
    const are=/^vrf instance\s+(\S+)\s*$/gm;
    while((m=are.exec(cfg))!==null)vrfs.push({name:m[1],rd:'',importRoute:''});
    return vrfs;
  }
  // "ip vrf NAME" or "vrf definition NAME"
  const re=/^(?:ip vrf|vrf definition)\s+(\S+)\s*\n([\s\S]*?)(?=^(?:ip vrf|vrf definition|interface|router|ip route|\!))/gm;
  while((m=re.exec(cfg))!==null){
    const name=m[1],body=m[2];
    const rd=(body.match(/rd\s+(\S+)/)||[])[1]||'';
    vrfs.push({name,rd,importRoute:''});
  }
  return vrfs;
}

// ── Users ─────────────────────────────────────────────────────
function parseCiscoUsers(cfg){
  const users=[];let m;
  // "username NAME privilege N secret|password N HASH"
  const re=/^username\s+(\S+)\s+privilege\s+(\d+)\s+(?:secret|password)\s+\d+\s+(\S+)/gm;
  while((m=re.exec(cfg))!==null){
    // Fix 4: Determine password strength (type 0=plain, 7=weak, 5/8/9=strong)
    const pwdLevel=(m[0].match(/(?:secret|password)\s+(\d+)/)||[])[1]||'0';
    const pwdWeak=['0','7'].includes(pwdLevel);
    const pwdType=pwdLevel==='5'?'md5':pwdLevel==='9'?'scrypt':pwdLevel==='8'?'pbkdf2':pwdLevel==='7'?'type7-weak':pwdLevel==='0'?'plaintext':'set';
    users.push({name:m[1],role:'privilege-'+m[2],service:'ssh/console',hasPwd:true,privilege:m[2],pwdType,pwdWeak,pwdLevel});
  }
  // "username NAME privilege N secret plaintext" (no hash level)
  const re2=/^username\s+(\S+)\s+privilege\s+(\d+)\s+(?:secret|password)\s+(\S+)/gm;
  while((m=re2.exec(cfg))!==null)
    if(!users.find(u=>u.name===m[1]))
      users.push({name:m[1],role:'privilege-'+m[2],service:'ssh/console',hasPwd:true,privilege:m[2]});
  return users;
}

// ── OSPF ──────────────────────────────────────────────────────
// ── Cisco BGP Parser ─────────────────────────────────────────
function parseCiscoBGP(cfg){
  const bgpList=[]; let m;
  const re=/^router bgp\s+(\d+)([\s\S]*?)(?=^router\s|^interface\s|^ip\s+route\s|^vlan\s|^end\b|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null){
    const asn=m[1], body=m[2];
    const rid=(body.match(/bgp router-id\s+(\S+)/)||[])[1]||'';
    const peers=[]; const pr=/neighbor\s+(\S+)\s+remote-as\s+(\d+)/g; let pm;
    while((pm=pr.exec(body))!==null){
      const ip=pm[1], peerAs=pm[2];
      const desc=(body.match(new RegExp('neighbor\\s+'+ip.replace(/\./g,'\\.')+'\\s+description\\s+([^\\n]+)'))||[])[1]||'';
      peers.push({ip, as:peerAs, desc:desc.trim(), type:peerAs===asn?'iBGP':'eBGP'});
    }
    // IPv6（2026-08-18 新增，官方 Cisco BGP Configuration Guide 確認 network 巢狀在獨立的
    // address-family ipv6 [unicast] 子模式內，語法為標準 slash-CIDR "network X:X::X/N"，
    // 子模式以官方 exit-address-family 關鍵字或下一個 address-family 結尾；此函式為
    // cisco/arista/ruijie 共用，惠及三家）。先算出 IPv6 子區塊範圍，再從 body 中挖除該
    // 段落後才餵給下方 IPv4 network 正則掃描——否則 IPv6 位址開頭的十進位數字（如
    // "2001:db8::"）會被 IPv4 正則的寬鬆字元類別 [\d.]+ 誤吃成一筆假的 IPv4 network
    const nets6=[]; const afv6=body.match(/^\s*address-family ipv6(?:\s+unicast)?\s*\n([\s\S]*?)(?=^\s*address-family\b|^\s*exit-address-family\b|(?![\s\S]))/m);
    if(afv6){
      const nr6=/network\s+([0-9a-fA-F:]+\/\d+)\b/g; let nm6;
      while((nm6=nr6.exec(afv6[1]))!==null)nets6.push(nm6[1]);
    }
    const bodyV4=afv6?body.slice(0,afv6.index)+body.slice(afv6.index+afv6[0].length):body;
    const nets=[]; const nr=/network\s+([\d.]+)(?:\s+mask\s+([\d.]+))?/g; let nm;
    while((nm=nr.exec(bodyV4))!==null)nets.push(nm[1]+(nm[2]?'/'+cidrFromMask(nm[2]):''));
    bgpList.push({asn, routerId:rid, peers, networks:nets, networks6:nets6});
  }
  return bgpList;
}

function parseCiscoOSPF(cfg){
  const processes=[];let m;
  const re=/^router ospf\s+(\d+)([\s\S]*?)(?=^router\s|^end\b|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null){
    const pid=m[1],body=m[2];
    const rid=(body.match(/router-id\s+(\S+)/)||[])[1]||'';
    const areas=[];const ar=/network\s+([\d.]+)\s+([\d.]+)\s+area\s+([\d.]+)/g;let am;
    while((am=ar.exec(body))!==null){
      let area=areas.find(a=>a.area===am[3]);
      if(!area){area={area:am[3],networks:[]};areas.push(area);}
      area.networks.push({network:am[1],wildcard:am[2]});
    }
    processes.push({pid,routerId:rid,areas});
  }
  return processes;
}

// ── Master Parse ──────────────────────────────────────────────
function parseCisco(cfg){
  const sys=parseCiscoSysInfo(cfg);
  const stack=parseCiscoStack(cfg);
  const vlans=parseCiscoVLANs(cfg);
  const interfaces=parseCiscoInterfaces(cfg);
  const routes=parseCiscoRoutes(cfg);
  const vrfs=parseCiscoVRFs(cfg);
  const users=parseCiscoUsers(cfg);
  const ospf=parseCiscoOSPF(cfg);
  const bgp=parseCiscoBGP(cfg);
  const rip=parseCiscoRIP(cfg);
  const vrrp=parseVRRP(cfg,'cisco');
  const breakouts=parseCiscoBreakout(cfg);
  // pattern A（9300X 模組換位編號）子埠命名無法從介面名稱本身反推母埠，需用 breakouts 裡的
  // module/port/switch 三個數字反推出預期的 4 個 TenGigabitEthernet 子埠名稱，回填到 interfaces 陣列；
  // parseCiscoBreakout() 已將 port-range 展開成個別埠號逐筆存入 breakouts，此處天然逐埠處理
  for(const b of breakouts){
    if(b.scheme!=='renumber')continue;
    const slotMatch=b.parentPort.match(/^module(\d+)\/port(\d+)$/);
    if(!slotMatch)continue;
    const slot=slotMatch[1],portNum=parseInt(slotMatch[2],10);
    const firstChild=4*portNum-3;
    for(let i=0;i<4;i++){
      const childName=`TenGigabitEthernet${b.switchNum}/${slot}/${firstChild+i}`;
      const iface=interfaces.find(f=>f.name.toLowerCase()===childName.toLowerCase());
      if(iface){iface.breakoutChild=true;iface.breakoutParent=`FortyGigabitEthernet${b.switchNum}/${slot}/${portNum}`;iface.breakoutScheme='renumber';}
    }
  }
  return{sys,irf:null,stack,vlans,interfaces,routes,vrfs,users,ospf,bgp,rip,vrrp,vxlan:null,vendor:'cisco',breakouts};
}

// ═ Dell EMC OS10 Parser ═════════════════════════════════════

