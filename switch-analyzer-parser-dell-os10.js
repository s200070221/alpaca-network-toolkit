function parseDellOS10SysInfo(cfg){
  const version=(cfg.match(/^!\s*(?:Dell[^,]*,\s*)?Version:?\s+([\d.]+)/m)||[])[1]||'';
  // 依版本號判斷，若無版本號則以介面命名格式推斷
  const osGen=version.startsWith('10')?'OS10':
              version.startsWith('9')?'OS9 (FTOS)':
              /^interface\s+ethernet\d+\/\d+\/\d+/im.test(cfg)?'OS10':
              /^interface\s+(?:TenGigabitEthernet|ManagementEthernet|fortyGigE)/m.test(cfg)?'OS9 (FTOS)':'';
  return{
    hostname:(cfg.match(/^hostname\s+(\S+)/m)||[])[1]||'unknown',
    version,
    osGen,
    model:(cfg.match(/^!\s*(?:model|platform)[:\s]+(\S+)/im)||[])[1]||'',
  };
}

function parseDellOS10Stack(cfg){
  // OS10: vlt-domain block — capture all indented/comment lines, robust to EOF
  const vlt=cfg.match(/^vlt-domain\s+(\d+)\s*\n((?:[ \t!][^\n]*\n?)*)/m);
  if(vlt){
    const body=vlt[2];
    const priority=(body.match(/priority\s+(\d+)/)||[])[1]||'';
    const unitId=(body.match(/unit-id\s+(\d+)/)||[])[1]||'';
    const peerLink=(body.match(/peer-link\s+(\S+)/)||[])[1]||'';
    return{type:'VLT',domain:vlt[1],members:[{id:unitId||'0',priority}],peerLink};
  }
  // OS9: stack-unit N ...
  // Format 1 (block):  stack-unit 0\n  priority 10\n  provision S4048-ON
  // Format 2 (inline): stack-unit 0 provision S4048-ON
  const members=[];
  const seen=new Set();
  // Block format
  const blockRe=/^stack-unit\s+(\d+)\s*\n((?:[ \t][^\n]*\n?)*)/gm;
  let sm;
  while((sm=blockRe.exec(cfg))!==null){
    if(seen.has(sm[1]))continue;
    seen.add(sm[1]);
    const body=sm[2];
    const priority=(body.match(/priority\s+(\d+)/)||[])[1]||'';
    const model=(body.match(/provision\s+(\S+)/)||[])[1]||'';
    members.push({id:sm[1],priority,model});
  }
  // Inline format (only if block format found nothing)
  if(members.length===0){
    const inlineRe=/^stack-unit\s+(\d+)\s+(?:priority\s+\d+\s+)?provision\s+(\S+)/gm;
    while((sm=inlineRe.exec(cfg))!==null){
      if(seen.has(sm[1]))continue;
      seen.add(sm[1]);
      members.push({id:sm[1],priority:'',model:sm[2]});
    }
  }
  if(members.length>0)return{type:'Stack',domain:'1',members,peerLink:''};
  return null;
}

function parseDellOS10VLANs(cfg){
  const vlans=[];
  const blocks=cfg.split(/^interface\s+/m).slice(1);
  for(const blk of blocks){
    const name=blk.split('\n')[0].trim();
    if(!/^[Vv]lan\s*\d+/i.test(name))continue;
    const id=(name.match(/(\d+)/)||[])[1]||'';
    const body=blk.split('\n').slice(1).join('\n');
    const desc=(body.match(/^\s*description\s+(.+)/m)||[])[1]?.trim().replace(/^"|"$/g,'')||'';
    const ipRaw=(body.match(/^\s*ip address\s+([\d.]+\/\d+)/m)||[])[1]||'';
    if(id&&!vlans.find(v=>v.id===id))
      vlans.push({id,name:desc,ipSubnets:ipRaw?[{cidr:ipRaw}]:[]});
  }
  vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return vlans;
}

// 支援 OS10 CIDR ("ip address 1.2.3.4/24") 及 OS9 dotted mask ("ip address 1.2.3.4 255.255.255.0")
function parseDellIP(body){
  const cidr=(body.match(/^\s*ip address\s+([\d.]+\/\d+)/m)||[])[1];
  if(cidr)return cidr;
  const m=body.match(/^\s*ip address\s+([\d.]+)\s+([\d.]+)/m);
  if(m)return m[1]+'/'+cidrFromMask(m[2]);
  // 官方 SmartFabric OS10 User Guide 確認 IPv6 語法 `ipv6 address ADDR/PREFIXLEN`
  const v6=(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1];
  if(v6)return v6;
  return'';
}
// 雙棧修復（2026-08-13 新增）：獨立無條件擷取 ipv6 address，不受 parseDellIP() 是否已抓到
// IPv4 值影響（原本 parseDellIP() 只在找不到 IPv4 時才 fallback 讀 ipv6 address，同一介面
// 同時設定 IPv4+IPv6 時 IPv6 會被靜默丟棄）
function parseDellIP6(body){
  return(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
}

// 次要IP（2026-08-12 新增，2026-08-17 從「僅取第一筆」擴大為完整收集，中信心度：官方 Dell
// SmartFabric OS10 User Guide "Assign Interface IP Address" 確認 `ip address A.B.C.D/N
// secondary` 語法，WebFetch 只拿到目錄殼，靠搜尋引擎索引摘要佐證含完整範例）
function parseDellSecondaryIPs(body){
  const out=[...body.matchAll(/^\s*ip address\s+([\d.]+)\/(\d+)\s+secondary/gm)].map(m=>m[1]+'/'+m[2]);
  if(out.length)return out;
  return [...body.matchAll(/^\s*ip address\s+([\d.]+)\s+([\d.]+)\s+secondary/gm)].map(m=>m[1]+'/'+cidrFromMask(m[2]));
}

function parseDellOS10Interfaces(cfg){
  const ifaces=[];
  const blocks=cfg.split(/^interface\s+/m).slice(1);
  for(const blk of blocks){
    const lines=blk.split('\n');
    const name=lines[0].trim();
    const body=lines.slice(1).join('\n');
    const desc=(body.match(/^\s*description\s+(.+)/m)||[])[1]?.trim().replace(/^"|"$/g,'')||'';
    const shutdown=/^\s*shutdown\s*$/m.test(body)&&!/no shutdown/.test(body);

    // Management interface (OS10: management1/1/1, OS9: ManagementEthernet 0/0)
    if(/^management/i.test(name)){
      const ip=parseDellIP(body);
      const ip6=parseDellIP6(body);
      const secondaryIps=parseDellSecondaryIPs(body);
      ifaces.push({name,type:'physical',desc,ip,ip6,secondaryIps,mode:'',vlans:'',nativeVlan:'',vrf:'MGMT',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    // SVI: interface vlan N (OS10) / interface Vlan N (OS9)
    if(/^[Vv]lan\s*\d+/i.test(name)){
      const ip=parseDellIP(body);
      const ip6=parseDellIP6(body);
      const secondaryIps=parseDellSecondaryIPs(body);
      const vrf=(body.match(/ip vrf forwarding\s+(\S+)/)||[])[1]||'';
      const vrrpList=[];
      const vgRe=/vrrp-group\s+(\d+)([\s\S]*?)(?=vrrp-group|\n\S|$)/g;let vg;
      while((vg=vgRe.exec(body))!==null){
        const vgBody=vg[2];
        const vip=(vgBody.match(/virtual-address\s+(\S+)/)||[])[1]||'';
        const prio=(vgBody.match(/priority\s+(\d+)/)||[])[1]||'100';
        if(vip)vrrpList.push({vrid:vg[1],vip,priority:prio,type:'VRRP'});
      }
      ifaces.push({name,type:'svi',desc,ip,ip6,secondaryIps,mode:'',vlans:'',nativeVlan:'',vrf,shutdown,member:'1',hybrid:null,vrrp:vrrpList,breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    // Port-channel
    if(/^[Pp]ort-[Cc]hannel/i.test(name)){
      const noRouting=/no switchport/.test(body);
      if(noRouting){
        const ip=parseDellIP(body);
        const ip6=parseDellIP6(body);
        const secondaryIps=parseDellSecondaryIPs(body);
        ifaces.push({name,type:'physical',desc,mode:'routed',vlans:'',nativeVlan:'',vrf:'',ip,ip6,secondaryIps,shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      }else{
        const mode=(body.match(/switchport mode\s+(\S+)/)||[])[1]||'';
        const vlans=(body.match(/switchport trunk allowed vlan\s+([^\n]+)/)||[])[1]?.trim()||'';
        ifaces.push({name,type:'physical',desc,mode,vlans,nativeVlan:'',vrf:'',ip:'',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      }
      continue;
    }
    // Physical: OS10 ethernet N/N/N, OS9 TenGigabitEthernet/GigabitEthernet/fortyGigE
    // Extract stack member: "ethernet1/..." → "1", "TenGigabitEthernet 0/1" → "0"
    const memberM=name.match(/(?:ethernet|GigabitEthernet|TenGigabitEthernet|fortyGigE|hundredGigE)\s*(\d+)\//i);
    const member=memberM?memberM[1]:'1';
    // Breakout: `port-group X` → `mode Eth ratio` 獨立頂層區塊啟用，子埠命名用冒號
    const bkMatch=name.match(/^ethernet(\d+\/\d+\/\d+):([1-4])$/i);
    const breakoutChild=!!bkMatch;
    const breakoutParent=bkMatch?`ethernet${bkMatch[1]}`:'';
    const noRouting=/no switchport/.test(body);
    if(noRouting){
      const ip=parseDellIP(body);
      const ip6=parseDellIP6(body);
      const secondaryIps=parseDellSecondaryIPs(body);
      const vrf=(body.match(/ip vrf forwarding\s+(\S+)/)||[])[1]||'';
      ifaces.push({name,type:'physical',desc,mode:'routed',vlans:'',nativeVlan:'',vrf,ip,ip6,secondaryIps,shutdown,member,hybrid:null,vrrp:[],breakoutChild,breakoutParent,breakoutMode:''});
      continue;
    }
    const modeM=body.match(/switchport mode\s+(\S+)/);
    let mode='',vlans='',nativeVlan='';
    if(modeM){
      if(modeM[1]==='trunk'){
        mode='trunk';
        vlans=(body.match(/switchport trunk allowed vlan\s+([^\n]+)/)||[])[1]?.trim()||'all';
        nativeVlan=(body.match(/switchport trunk native vlan\s+(\d+)/)||[])[1]||'1';
      }else if(modeM[1]==='access'){
        mode='access';
        vlans=(body.match(/switchport access vlan\s+(\d+)/)||[])[1]||'1';
      }else{mode=modeM[1];}
    }
    const channelGrp=(body.match(/channel-group\s+(\d+)/)||[])[1]||'';
    ifaces.push({name,type:'physical',desc,mode,vlans,nativeVlan,vrf:'',ip:'',shutdown,member,hybrid:null,vrrp:[],channelGrp,breakoutChild,breakoutParent,breakoutMode:''});
  }
  return ifaces;
}

function parseDellOS10Routes(cfg){
  const routes=[];
  // OS10 CIDR: "ip route DST/N GW"
  const re1=/^ip route\s+([\d.]+\/\d+)\s+(\S+)/gm;let m;
  while((m=re1.exec(cfg))!==null){
    const dst=m[1],gw=m[2];
    routes.push({dst,gw,vrf:'',gwIsInterface:!gw.match(/^\d+\.\d+\.\d+\.\d+/)});
  }
  // OS9 dotted mask: "ip route DST MASK GW [metric N]"
  const re2=/^ip route\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)/gm;
  while((m=re2.exec(cfg))!==null){
    const dst=m[1]+'/'+cidrFromMask(m[2]),gw=m[3];
    if(!routes.find(r=>r.dst===dst&&r.gw===gw))
      routes.push({dst,gw,vrf:'',gwIsInterface:false});
  }
  // management route (OS9 management VRF)
  const re3=/^management route\s+([\d.]+\/\d+)\s+(\S+)/gm;
  while((m=re3.exec(cfg))!==null)
    routes.push({dst:m[1],gw:m[2],vrf:'MGMT',gwIsInterface:false});
  // IPv6 靜態路由（2026-08-13 十一續新增）：官方語法 "ipv6 route PREFIX/MASK {NEXTHOP|IFACE}"，
  // 獨立關鍵字，不含 vrf（v4 版本本身也沒有 vrf 欄位，比照維持）
  const re4=/^ipv6 route\s+(\S+)\s+(\S+)/gm;
  while((m=re4.exec(cfg))!==null){
    const dst=m[1],gw=m[2];
    routes.push({dst,gw,vrf:'',gwIsInterface:!gw.includes(':')});
  }
  return routes;
}

function parseDellOS10VRFs(cfg){
  const vrfs=[];let m;
  const re=/^ip vrf\s+(\S+)\s*\n([\s\S]*?)(?=^[^\s])/gm;
  while((m=re.exec(cfg))!==null){
    const name=m[1],body=m[2];
    const rd=(body.match(/rd\s+(\S+)/)||[])[1]||'';
    vrfs.push({name,rd,importRoute:''});
  }
  return vrfs;
}

// Breakout：`port-group X` 獨立頂層區塊 → `mode Eth ratio`，子埠命名 `ethernetX:1`~`:4`
// lookahead 邊界比照既有 \Z fallback bug 修正慣例，額外處理「該區塊是檔案最後一段」的情況
function parseDellOS10Breakout(cfg){
  const breakouts=[];let m;
  const re=/^port-group\s+(\S+)\s*\n([\s\S]*?)(?=^[^\s]|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null){
    const pgId=m[1],body=m[2];
    const modeMatch=body.match(/^\s*mode\s+Eth\s+(10g-4x|25g-4x)/mi);
    if(!modeMatch)continue;
    breakouts.push({parentPort:`ethernet${pgId}`,mode:modeMatch[1]==='10g-4x'?'4x10G':'4x25G',raw:m[0]});
  }
  return breakouts;
}

function parseDellOS10Users(cfg){
  const users=[];let m;
  // OS10: "username NAME password N PASS role ROLE"
  const re=/^username\s+(\S+)\s+password\s+(\d+)\s+(\S+)(?:\s+role\s+(\S+))?/gm;
  while((m=re.exec(cfg))!==null){
    const pwdType=m[2]==='0'?'plaintext':m[2]==='7'?'encrypted':'hash';
    const pwdWeak=pwdType==='plaintext';
    const pwdLevel=pwdWeak?'weak':pwdType==='encrypted'?'medium':'strong';
    users.push({name:m[1],role:m[4]||'',service:'ssh/console',hasPwd:true,privilege:'',pwdType,pwdWeak,pwdLevel});
  }
  // OS9: "username NAME privilege N password N HASH" or "username NAME secret N HASH"
  const re2=/^username\s+(\S+)\s+privilege\s+(\d+)\s+(?:password|secret)\s+(\d+)\s+(\S+)/gm;
  while((m=re2.exec(cfg))!==null){
    if(users.find(u=>u.name===m[1]))continue;
    const pwdType=m[3]==='0'?'plaintext':m[3]==='7'?'encrypted':'hash';
    const pwdWeak=pwdType==='plaintext';
    const pwdLevel=pwdWeak?'weak':pwdType==='encrypted'?'medium':'strong';
    users.push({name:m[1],role:'privilege-'+m[2],service:'ssh/console',hasPwd:true,privilege:m[2],pwdType,pwdWeak,pwdLevel});
  }
  return users;
}

function parseDellOS10OSPF(cfg){
  const processes=[];let m;
  const re=/^router ospf\s+(\d+)([\s\S]*?)(?=^router\s|^interface\s|^ip\s|^!\s*$|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null){
    const pid=m[1],body=m[2];
    const rid=(body.match(/router-id\s+(\S+)/)||[])[1]||'';
    const areas=[];
    // "network DST/CIDR area AREA" (CIDR format)
    const ar=/network\s+([\d.\/]+)\s+area\s+([\d.]+)/g;let am;
    while((am=ar.exec(body))!==null){
      let area=areas.find(a=>a.area===am[2]);
      if(!area){area={area:am[2],networks:[]};areas.push(area);}
      area.networks.push({network:am[1],wildcard:''});
    }
    processes.push({pid,routerId:rid,areas});
  }
  return processes;
}

// OSPFv3（2026-08-18 新增，官方 SmartFabric OS10 User Guide 確認 `router ospfv3
// [vrf <vrf>]` 為獨立頂層指令；與 IPv4 baseline 用全域 network 陳述式不同——OSPFv3
// 協定本質是逐介面指派，真正的 area 關聯是各自 interface 區塊內用
// `ipv6 ospf <pid> area <area>` 逐一指派）
function parseDellOS10OSPFv3(cfg){
  // 2026-08-18 修復：doAnalyze() 對貼上的設定檔內容做 .trim()，若設定檔本身結尾無換行
  // 字元，下方逐行擷取正則的重複群組 [^\n]*\n 要求每一行都要有結尾換行字元才會被收進
  // 區塊內容，會導致最後一個 interface 的關聯指派靜默漏解析；統一補上結尾換行字元
  if(!cfg.endsWith('\n'))cfg=cfg+'\n';
  const processes=[];let m;
  const re=/^router ospfv3(?:\s+vrf\s+\S+)?([\s\S]*?)(?=^router\s|^interface\s|^ip\s|^!\s*$|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null){
    const body=m[1];
    const pid='1';
    const rid=(body.match(/router-id\s+(\S+)/)||[])[1]||'';
    const areaMap=new Map();
    const ifRe=/^interface\s+([^\n]+)\n((?:(?!^(?:interface|router|ip\s)\b)[^\n]*\n)*)/gm; let ifm;
    while((ifm=ifRe.exec(cfg))!==null){
      const ifName=ifm[1].trim();
      const aim=ifm[2].match(/ipv6 ospf\s+\S+\s+area\s+([\d.]+)/);
      if(!aim)continue;
      const area=aim[1];
      if(!areaMap.has(area))areaMap.set(area,{area,interfaces:[]});
      areaMap.get(area).interfaces.push(ifName);
    }
    processes.push({pid,routerId:rid,areas:Array.from(areaMap.values())});
  }
  return processes;
}

function parseDellOS10BGP(cfg){
  const bgpList=[];let m;
  const re=/^router bgp\s+(\d+)([\s\S]*?)(?=^router\s|^interface\s|^ip\s+route\s|^!\s*$|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null){
    const asn=m[1],body=m[2];
    const rid=(body.match(/bgp router-id\s+(\S+)/)||[])[1]||'';
    const peers=[];const pr=/neighbor\s+(\S+)\s+remote-as\s+(\d+)/g;let pm;
    while((pm=pr.exec(body))!==null){
      const ip=pm[1],peerAs=pm[2];
      const desc=(body.match(new RegExp('neighbor\\s+'+ip.replace(/\./g,'\\.')+'\\s+description\\s+([^\\n]+)'))||[])[1]||'';
      peers.push({ip,as:peerAs,desc:desc.trim(),type:peerAs===asn?'iBGP':'eBGP'});
    }
    // IPv6（2026-08-18 新增，官方 SmartFabric OS10 User Guide＋官方社群版主回覆確認
    // network 巢狀在獨立的 address-family ipv6 unicast 子模式內，結構與 Comware/Cisco/
    // Aruba CX 已驗證過的 bodyV4 排除模式一致）
    const nets6=[];const afv6=body.match(/^\s*address-family ipv6(?:\s+unicast)?\s*\n([\s\S]*?)(?=^\s*address-family\b|^\s*exit-address-family\b|(?![\s\S]))/m);
    if(afv6){
      const nr6=/network\s+([0-9a-fA-F:]+\/\d+)\b/g;let nm6;
      while((nm6=nr6.exec(afv6[1]))!==null)nets6.push(nm6[1]);
    }
    const bodyV4=afv6?body.slice(0,afv6.index)+body.slice(afv6.index+afv6[0].length):body;
    const nets=[];const nr=/network\s+([\d.\/]+)/g;let nm;
    while((nm=nr.exec(bodyV4))!==null)nets.push(nm[1]);
    bgpList.push({asn,routerId:rid,peers,networks:nets,networks6:nets6});
  }
  return bgpList;
}

function parseDellOS10(cfg){
  const sys=parseDellOS10SysInfo(cfg);
  const stack=parseDellOS10Stack(cfg);
  let vlans=parseDellOS10VLANs(cfg);
  const interfaces=parseDellOS10Interfaces(cfg);
  const implied=collectImpliedVLANs(vlans,interfaces);
  if(implied.length)vlans=[...vlans,...implied].sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  const routes=parseDellOS10Routes(cfg);
  const vrfs=parseDellOS10VRFs(cfg);
  const users=parseDellOS10Users(cfg);
  const ospf=parseDellOS10OSPF(cfg);
  const ospf6=parseDellOS10OSPFv3(cfg);
  const bgp=parseDellOS10BGP(cfg);
  const vrrp=parseVRRP(cfg,'dell-os10');
  const breakouts=parseDellOS10Breakout(cfg);
  breakouts.forEach(b=>{
    const iface=interfaces.find(f=>f.name.toLowerCase()===b.parentPort.toLowerCase());
    if(iface)iface.breakoutMode=b.mode;
  });
  return{sys,irf:null,stack,vlans,interfaces,routes,vrfs,users,ospf,ospf6,bgp,rip:[],vrrp,vxlan:null,vendor:'dell-os10',breakouts};
}

// class-map/match + service-policy（2026-08-28（續5）新增，範圍縮減版）：官方 SmartFabric
// OS10 User Guide 系列頁面 + 社群討論串佐證（官方文件站台直接 fetch 遭 403 擋回，信心度
// 低於本專案一貫「直接 fetch 官方 PDF/頁面逐字查證」標準，故本輪刻意縮減範圍）。官方文件
// 揭露 policy-map 實際有 qos/queuing/network-qos 三種 type，service-policy 需要帶
// "type <type>" 限定詞；本輪僅實作預設/最常用的 "qos" type（社群佐證省略 type 限定詞時
// 會自動補上 "type qos"，故明確輸出不依賴預設值），queuing/network-qos 非本輪範圍。
// class-map 標頭 "class-map type qos {match-any|match-all} NAME"（與 Arista 相同多一段
// type 限定詞，但 service-policy 語序不同——Dell 是 "service-policy {input|output} type
// qos NAME"，direction 在 type 之前，與 Arista 相反，見該廠牌 parser 對應註解）。match
// 條件本輪確認 access-group／vlan／dscp／cos 四種（2026-08-29 對外查證官方 Dell
// SmartFabric OS10 User Guide 真實設定範例後修正：dscp 正確語法是 "match ip dscp N"，
// 非先前版本誤植的裸 "match dscp N"；同批新增 cos "match cos N"），protocol／ip-precedence
// 仍查無官方逐字語法佐證，非本輪範圍
function parseDellOS10ClassMaps(cfg){
  const maps=[];
  const cmRe=/^class-map\s+type\s+qos\s+(match-any|match-all)\s+(\S+)([\s\S]*?)(?=^class-map\s+type\s+qos\s+|^policy-map\s+|(?![\s\S]))/gm;
  let m;
  while((m=cmRe.exec(cfg))!==null){
    const matchType=m[1], name=m[2], body=m[3]||'', matches=[];
    let mm;
    const agRe=/^\s*match\s+ip\s+access-group\s+(\S+)/gim;
    while((mm=agRe.exec(body))!==null)matches.push({type:'access-group',value:mm[1]});
    const vlanRe=/^\s*match\s+vlan\s+(\S+)/gim;
    while((mm=vlanRe.exec(body))!==null)matches.push({type:'vlan',value:mm[1]});
    const dscpRe=/^\s*match\s+ip\s+dscp\s+(\S+)/gim;
    while((mm=dscpRe.exec(body))!==null)matches.push({type:'dscp',value:mm[1]});
    const cosRe=/^\s*match\s+cos\s+(\S+)/gim;
    while((mm=cosRe.exec(body))!==null)matches.push({type:'cos',value:mm[1]});
    maps.push({name,matchType,matches});
  }
  return maps;
}
function parseDellOS10ServicePolicy(cfg){
  const apps=[];
  cfg.split(/(?=^interface\s)/m).forEach(blk=>{
    const ifLine=blk.match(/^interface\s+(\S.*)/m);
    if(!ifLine)return;
    const ifName=ifLine[1].trim();
    let m; const spRe=/^\s*service-policy\s+(input|output)\s+type\s+qos\s+(\S+)/gim;
    while((m=spRe.exec(blk))!==null)apps.push({policy:m[2],interface:ifName,direction:m[1].toLowerCase()});
  });
  return apps;
}

// ═ Juniper EX/QFX Parser ═
// ════════════════════════════════════════════════════════════
//  Juniper Networks EX/QFX/MX Switch Parser  v2
//  Junos hierarchical brace-style config
// ════════════════════════════════════════════════════════════

// ── Extract a named brace block from text ─────────────────
