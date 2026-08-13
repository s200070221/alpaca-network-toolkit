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

// 次要IP（2026-08-12 新增，中信心度：官方 Dell SmartFabric OS10 User Guide "Assign Interface
// IP Address" 確認 `ip address A.B.C.D/N secondary` 語法，WebFetch 只拿到目錄殼，靠搜尋引擎
// 索引摘要佐證含完整範例）：僅取第一筆次要IP為 MVP 範圍，比照其餘廠牌既有限制
function parseDellSecondaryIP(body){
  const cidr=(body.match(/^\s*ip address\s+([\d.]+\/\d+)\s+secondary/m)||[])[1];
  if(cidr)return cidr;
  const m=body.match(/^\s*ip address\s+([\d.]+)\s+([\d.]+)\s+secondary/m);
  if(m)return m[1]+'/'+cidrFromMask(m[2]);
  return'';
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
      const secondaryIp=parseDellSecondaryIP(body);
      ifaces.push({name,type:'physical',desc,ip,secondaryIp,mode:'',vlans:'',nativeVlan:'',vrf:'MGMT',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    // SVI: interface vlan N (OS10) / interface Vlan N (OS9)
    if(/^[Vv]lan\s*\d+/i.test(name)){
      const ip=parseDellIP(body);
      const secondaryIp=parseDellSecondaryIP(body);
      const vrf=(body.match(/ip vrf forwarding\s+(\S+)/)||[])[1]||'';
      const vrrpList=[];
      const vgRe=/vrrp-group\s+(\d+)([\s\S]*?)(?=vrrp-group|\n\S|$)/g;let vg;
      while((vg=vgRe.exec(body))!==null){
        const vgBody=vg[2];
        const vip=(vgBody.match(/virtual-address\s+(\S+)/)||[])[1]||'';
        const prio=(vgBody.match(/priority\s+(\d+)/)||[])[1]||'100';
        if(vip)vrrpList.push({vrid:vg[1],vip,priority:prio,type:'VRRP'});
      }
      ifaces.push({name,type:'svi',desc,ip,secondaryIp,mode:'',vlans:'',nativeVlan:'',vrf,shutdown,member:'1',hybrid:null,vrrp:vrrpList,breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    // Port-channel
    if(/^[Pp]ort-[Cc]hannel/i.test(name)){
      const noRouting=/no switchport/.test(body);
      if(noRouting){
        const ip=parseDellIP(body);
        const secondaryIp=parseDellSecondaryIP(body);
        ifaces.push({name,type:'physical',desc,mode:'routed',vlans:'',nativeVlan:'',vrf:'',ip,secondaryIp,shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
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
      const secondaryIp=parseDellSecondaryIP(body);
      const vrf=(body.match(/ip vrf forwarding\s+(\S+)/)||[])[1]||'';
      ifaces.push({name,type:'physical',desc,mode:'routed',vlans:'',nativeVlan:'',vrf,ip,secondaryIp,shutdown,member,hybrid:null,vrrp:[],breakoutChild,breakoutParent,breakoutMode:''});
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
    const nets=[];const nr=/network\s+([\d.\/]+)/g;let nm;
    while((nm=nr.exec(body))!==null)nets.push(nm[1]);
    bgpList.push({asn,routerId:rid,peers,networks:nets});
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
  const bgp=parseDellOS10BGP(cfg);
  const vrrp=parseVRRP(cfg,'dell-os10');
  const breakouts=parseDellOS10Breakout(cfg);
  breakouts.forEach(b=>{
    const iface=interfaces.find(f=>f.name.toLowerCase()===b.parentPort.toLowerCase());
    if(iface)iface.breakoutMode=b.mode;
  });
  return{sys,irf:null,stack,vlans,interfaces,routes,vrfs,users,ospf,bgp,rip:[],vrrp,vxlan:null,vendor:'dell-os10',breakouts};
}

// ═ Juniper EX/QFX Parser ═
// ════════════════════════════════════════════════════════════
//  Juniper Networks EX/QFX/MX Switch Parser  v2
//  Junos hierarchical brace-style config
// ════════════════════════════════════════════════════════════

// ── Extract a named brace block from text ─────────────────
