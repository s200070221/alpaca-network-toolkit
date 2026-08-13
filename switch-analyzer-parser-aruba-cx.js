function parseArubaSysInfo(cfg){
  return{
    hostname:(cfg.match(/^hostname\s+(\S+)/m)||[])[1]||'unknown',
    version:(cfg.match(/version\s+(\S+)/)||[])[1]||'',
  };
}

function parseArubaVSF(cfg){
  // Aruba CX VSF may appear as an indented top-level block or as command-style
  // lines.  Use a line-oriented parser to avoid regex edge cases that miss
  // member blocks when optional priority/type/link lines are reordered.
  const hasVSF=/^\s*vsf\s*$/m.test(cfg)||/^\s*vsf\s+member\s+\d+/m.test(cfg)||/\bvsf secondary-member\b/i.test(cfg);
  if(!hasVSF)return null;
  const members=[];
  const byId={};
  const ensure=id=>{
    if(!byId[id]){byId[id]={id:String(id),model:'',priority:null,role:null};members.push(byId[id]);}
    return byId[id];
  };
  const linkMap={};
  const addLink=(lid,port)=>{
    if(!lid||!port)return;
    if(!linkMap[lid])linkMap[lid]={id:String(lid),ports:[]};
    if(!linkMap[lid].ports.includes(port))linkMap[lid].ports.push(port);
  };

  const lines=cfg.split(/\r?\n/);
  let inVSF=false,current=null,currentLink=null,currentCmdMember=null;
  for(const line of lines){
    if(/^\s*vsf\s*$/.test(line)){inVSF=true;current=null;currentCmdMember=null;continue;}
    if(inVSF && /^\S/.test(line) && !/^vsf\s+/.test(line)){inVSF=false;current=null;}
    if(inVSF){
      let m=line.match(/^[ \t]*member\s+(\d+)\b/);
      if(m){
        if(currentLink){
          const lm=line.match(/^[ \t]*member\s+\d+\s+(\S+)/);
          if(lm){addLink(currentLink,lm[1]);continue;}
        }
        current=ensure(m[1]);currentLink=null;continue;
      }
      if(inVSF){
        const loneLink=line.match(/^[ \t]{2,4}link\s+(\d+)\s*$/);
        if(loneLink){currentLink=loneLink[1];current=null;continue;}
        const inlineLink=line.match(/^[ \t]*link\s+(\d+)\s+(\S+)/);
        if(inlineLink){addLink(inlineLink[1],inlineLink[2]);currentLink=null;continue;}
      }
      if(current){
        m=line.match(/^[ \t]*type\s+(\S+)/); if(m){current.model=m[1];continue;}
        m=line.match(/^[ \t]*priority\s+(\d+)/); if(m){current.priority=parseInt(m[1]);continue;}
      }
      continue;
    }
    // Command-style: reset context on non-vsf top-level line
    if(/^\S/.test(line)&&!/^vsf\s+/.test(line)){currentCmdMember=null;}
    // Command-style: parse indented sub-lines under "vsf member N" block
    if(currentCmdMember&&/^[ \t]/.test(line)){
      let m;
      m=line.match(/^[ \t]+type\s+(\S+)/); if(m){currentCmdMember.model=m[1];continue;}
      m=line.match(/^[ \t]+priority\s+(\d+)/); if(m){currentCmdMember.priority=parseInt(m[1]);continue;}
      m=line.match(/^[ \t]+link\s+(\d+)\s+(\S+)/); if(m){addLink(m[1],m[2]);continue;}
      continue;
    }
    // Command-style: "vsf member N [type X] [priority N]" or "vsf member N link N PORT"
    let cm=line.match(/^\s*vsf\s+member\s+(\d+)(?:\s+type\s+(\S+))?(?:\s+priority\s+(\d+))?/);
    if(cm){
      currentCmdMember=ensure(cm[1]);
      if(cm[2])currentCmdMember.model=cm[2];
      if(cm[3])currentCmdMember.priority=parseInt(cm[3]);
      let lm=line.match(/^\s*vsf\s+member\s+\d+\s+link\s+(\d+)\s+(\S+)/);
      if(lm)addLink(lm[1],lm[2]);
    }
  }

  const primary=(cfg.match(/^\s*vsf\s+primary-member\s+(\d+)/m)||[])[1]||'';
  const secondary=(cfg.match(/^\s*vsf\s+secondary-member\s+(\d+)/m)||[])[1]||'';
  if(primary)ensure(primary).role='Master';
  if(secondary)ensure(secondary).role='Standby';
  // 若只有 secondary 沒有 primary，自動將最高優先或最小 ID 的未分配成員設為 Master
  if(!primary&&members.some(x=>x.role)&&!members.some(x=>x.role==='Master')){
    const best=[...members].filter(x=>!x.role).sort((a,b)=>(b.priority??0)-(a.priority??0)||parseInt(a.id)-parseInt(b.id));
    if(best.length)best[0].role='Master';
  }
  if(!members.length){
    const ids=new Set();
    for(const mm of cfg.matchAll(/\b(\d+)\/\d+\/\d+\b/g))ids.add(mm[1]);
    ids.forEach(id=>ensure(id));
  }
  if(members.length&&!members.some(x=>x.role)){
    const sorted=[...members].sort((a,b)=>(b.priority??0)-(a.priority??0)||parseInt(a.id)-parseInt(b.id));
    sorted.forEach((mem,i)=>mem.role=i===0?'Master':i===1?'Standby':'Member');
  }else members.forEach(mem=>{if(!mem.role)mem.role='Member';});
  members.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  const links=Object.values(linkMap).sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return{type:'VSF',members,links};
}

function parseArubaVLANs(cfg){
  const vlans=[]; let m;
  const re=/^vlan\s+(\d+)\s*\n((?:[\s\S]*?)(?=^vlan\s+\d|^interface|^ip\s|^user\s|^vrf\s|^router\s|^bgp\s|$))/gm;
  while((m=re.exec(cfg))!==null){
    const name=(m[2].match(/^\s+name\s+(.+)/m)||[])[1]?.trim()||'';
    vlans.push({id:m[1],name,ipSubnets:[]});
  }
  vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return vlans;
}

function parseArubaInterfaces(cfg){
  const ifaces=[]; let m;
  // Merge duplicate interface blocks (same Comware pattern)
  const raw=cfg.split(/^interface\s+/m);
  const merged={};
  for(const blk of raw.slice(1)){
    const lines=blk.split('\n');
    // Normalise: "vlan 10" → "vlan10", "loopback 0" → "loopback0"
    const rawName=lines[0].trim();
    const name=rawName.replace(/^(vlan)\s+(\d+)$/i,'$1$2')
                       .replace(/^(loopback)\s+(\d+)$/i,'$1$2');
    const body=lines.slice(1).join('\n');
    merged[name]=merged[name]?merged[name]+'\n'+body:body;
  }
  for(const [name,blk] of Object.entries(merged)){
    const desc=(blk.match(/^\s*description\s+(.+)/m)||[])[1]?.trim()||'';
    const shutdown=/^\s+shutdown\s*$/m.test(blk)&&!/no shutdown/.test(blk);
    const member=(name.match(/^(\d+)\//)||[])[1]||'1';
    // 次要IP（Secondary IP，官方 AOS-CX IP Services Guide／CLI 文件：`ip address
    // ADDR/PREFIX secondary`；僅取第一筆為 MVP 範圍）
    const secondaryIp=(blk.match(/^\s+ip address\s+(\S+)\s+secondary/m)||[])[1]||'';
    // SVI: "vlan N"
    if(/^vlan\s*\d+/i.test(name)){
      const vid=(name.match(/\d+/)||[])[0]||'';
      // IPv6（試點 5 廠牌之一，官方 AOS-CX 語法 `ipv6 address ADDR/PREFIXLEN`）
      const ip=(blk.match(/^\s+ip address\s+(\S+)/m)||[])[1]||(blk.match(/^\s+ipv6 address\s+(\S+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增）：ip6 獨立無條件擷取，不再受 ip 是否已有值影響
      const ip6=(blk.match(/^\s+ipv6 address\s+(\S+)/m)||[])[1]||'';
      const vrf=(blk.match(/^\s+vrf attach\s+(\S+)/m)||[])[1]||'';
      ifaces.push({name,type:'svi',desc,ip,ip6,secondaryIp,mode:'',vlans:vid,nativeVlan:'',vrf,shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    // Loopback
    if(/^loopback/i.test(name)){
      const ip=(blk.match(/^\s+ip address\s+(\S+)/m)||[])[1]||(blk.match(/^\s+ipv6 address\s+(\S+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，同 SVI）
      const ip6=(blk.match(/^\s+ipv6 address\s+(\S+)/m)||[])[1]||'';
      ifaces.push({name,type:'loopback',desc,ip,ip6,secondaryIp,mode:'',vlans:'',nativeVlan:'',vrf:'',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    let mode='',vlans='',nativeVlan='',vrf='',ip='',ip6='';
    if(/vlan trunk/.test(blk)){
      mode='trunk';
      let rawAllowed=(blk.match(/vlan trunk allowed\s+([^\n]+)/)||[])[1]?.trim()||'';
      // 去除可選的 "vlan " 前綴（ArubaOS-CX 語法：vlan trunk allowed vlan LIST）
      rawAllowed=rawAllowed.replace(/^vlan\s+/i,'').trim();
      vlans=(/^all$/i.test(rawAllowed))?'all':rawAllowed;
      nativeVlan=(blk.match(/vlan trunk native(?:\s+vlan)?\s+(\d+)/i)||[])[1]||'1';
    }else if(/vlan access/.test(blk)){
      mode='access';
      vlans=(blk.match(/vlan access\s+(\d+)/)||[])[1]||'';
    }
    if(!/no routing/.test(blk)&&(/ip address/.test(blk)||/ipv6 address/.test(blk))){
      ip=(blk.match(/^\s+ip address\s+(\S+)/m)||[])[1]||(blk.match(/^\s+ipv6 address\s+(\S+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，同 SVI/Loopback）
      ip6=(blk.match(/^\s+ipv6 address\s+(\S+)/m)||[])[1]||'';
      vrf=(blk.match(/^\s+vrf attach\s+(\S+)/m)||[])[1]||'';
      mode=mode||'routed';
    }
    const vsfInfo=parseArubaVSF(cfg);
    const vsfPorts=new Set((vsfInfo?.links||[]).flatMap(l=>l.ports||[]));
    const isVSF=vsfPorts.has(name)||/^\d+\/1\/5[12]$/.test(name);
    // Breakout: 母埠 interface 區塊內 `split [count] [speed] [confirm]` 啟用（官方語法已查證）
    const splitMatch=blk.match(/^\s*split(?:\s+(\d+))?(?:\s+(\S+))?\s*(?:confirm)?\s*$/mi);
    const breakoutMode=splitMatch?`${splitMatch[1]||'4'}x${(splitMatch[2]||'10G').replace(/g$/i,'G')}`:'';
    const bkMatch=name.match(/^(\d+\/\d+\/\d+):([1-4])$/);
    const breakoutChild=!!bkMatch;
    const breakoutParent=bkMatch?bkMatch[1]:'';
    ifaces.push({name,type:isVSF?'stack':'physical',desc,mode,vlans,nativeVlan,vrf,ip,ip6,secondaryIp,shutdown,member,hybrid:null,vrrp:[],breakoutChild,breakoutParent,breakoutMode});
  }
  return ifaces;
}

function parseArubaRoutes(cfg){
  const routes=[]; let m;
  const lineRe=/^ip route (.+)$/gm;
  while((m=lineRe.exec(cfg))!==null){
    const parts=m[1].trim().split(/\s+/);
    let dst=parts[0],gw='',vrf='';
    if(parts.length>=2&&parts[parts.length-2]==='vrf'){vrf=parts[parts.length-1];parts.splice(-2,2);}
    if(parts.length===2)gw=parts[1];
    else if(parts.length===3){if(parts[1].match(/\d+\.\d+\.\d+\.\d+/)){dst=parts[0]+'/'+cidrFromMask(parts[1]);gw=parts[2];}else gw=parts[1];}
    const gwIsInterface=gw&&!gw.match(/^\d+\.\d+\.\d+\.\d+/);
    if(dst&&gw)routes.push({dst,gw,vrf,gwIsInterface});
  }
  return routes;
}

function parseArubaVRFs(cfg){
  const vrfs=[]; let m;
  const seenVrf={};
  // "vrf NAME" standalone blocks
  const re1=/^vrf\s+((?!attach|definition)\S+)/gm;
  while((m=re1.exec(cfg))!==null){
    if(seenVrf[m[1]])continue; seenVrf[m[1]]=1;
    // Try to find rd in next 5 lines
    const after=cfg.slice(m.index).split('\n').slice(1,6).join('\n');
    const rd=(after.match(/^\s+rd\s+(\S+)/m)||[])[1]||'';
    vrfs.push({name:m[1],rd,importRoute:''});
  }
  // "vrf attach NAME" in interfaces
  const re2=/vrf attach\s+(\S+)/g;
  while((m=re2.exec(cfg))!==null)if(!seenVrf[m[1]]){seenVrf[m[1]]=1;vrfs.push({name:m[1],rd:'',importRoute:''});}
  return vrfs;
}

function parseArubaUsers(cfg){
  const users=[]; const seen=new Set(); let m;
  // Style A: "user NAME group GROUP password TYPE HASH"
  const reA=/^user\s+(\S+)\s+group\s+(\S+)\s+password\s+(\S+)\s+(\S+)/gm;
  while((m=reA.exec(cfg))!==null){
    if(seen.has(m[1]))continue; seen.add(m[1]);
    const pwdWeak=m[3]!=='ciphertext';
    const pwdType=m[3]==='ciphertext'?'cipher':'plaintext';
    users.push({name:m[1],role:m[2],service:'ssh/console',hasPwd:true,pwdType,pwdWeak});
  }
  // Style B: "username NAME password ciphertext HASH role ROLE"  (AOS-CX)
  const reB=/^username\s+(\S+)\s+password\s+(\S+)\s+\S+\s+role\s+(\S+)/gm;
  while((m=reB.exec(cfg))!==null){
    if(seen.has(m[1]))continue; seen.add(m[1]);
    const pwdWeak=m[2]!=='ciphertext';
    const pwdType=m[2]==='ciphertext'?'cipher':'plaintext';
    users.push({name:m[1],role:m[3],service:'ssh/console',hasPwd:true,pwdType,pwdWeak});
  }
  return users;
}

function parseArubaOSPF(cfg){
  const processes=[]; let m;
  const re=/^router ospf\s+(\d+)\n((?:(?!^(?:router|bgp|interface|vlan|ip\s+route|user)\b)[^\n]*\n)*)/gm;
  while((m=re.exec(cfg))!==null){
    const pid=m[1],body=m[2];
    const rid=(body.match(/router-id\s+(\S+)/)||[])[1]||'';
    // 2026-07-27 對外查證官方 HPE Aruba Lab Guide＋真實 AOS-CX 生產設定檔後修正：
    // router ospf 區塊內的 area 只是 bare 宣告（不巢狀 network 或 interface），真正的
    // 網段/介面關聯是在各自 interface 區塊內用 `ip ospf <pid> area <area>` 逐一指派
    // （實體埠/SVI/Loopback 皆可），與 ArubaOS-Switch/ProCurve 既有的「逐 VLAN
    // ip ospf area」模式相同、只是 CX 多一個 process-id 參數且不限 VLAN 介面。
    const areaMap=new Map();
    const ar=/^\s*area\s+([\d.]+)\s*$/gm; let am;
    while((am=ar.exec(body))!==null)if(!areaMap.has(am[1]))areaMap.set(am[1],{area:am[1],networks:[]});
    // 借用既有 areas[].networks[].network 欄位存介面名稱（比照 ProCurve parseOSPF() 把
    // network 欄位重新詮釋為 VLAN ID 的既有慣例），逐 interface 區塊掃描是否有
    // `ip ospf <pid> area <area>`，找到的介面名稱視為該 area 的關聯對象。
    const ifRe=/^interface\s+([^\n]+)\n((?:(?!^(?:interface|router|vlan|ip\s+route|user)\b)[^\n]*\n)*)/gm; let ifm;
    while((ifm=ifRe.exec(cfg))!==null){
      const ifName=ifm[1].trim().replace(/^(vlan)\s+(\d+)$/i,'$1$2').replace(/^(loopback)\s+(\d+)$/i,'$1$2');
      const aim=ifm[2].match(new RegExp('ip ospf\\s+'+pid+'\\s+area\\s+([\\d.]+)'));
      if(!aim)continue;
      const area=aim[1];
      if(!areaMap.has(area))areaMap.set(area,{area,networks:[]});
      areaMap.get(area).networks.push({network:ifName,wildcard:''});
    }
    processes.push({pid,routerId:rid,areas:Array.from(areaMap.values())});
  }
  return processes;
}

function parseArubaBGP(cfg){
  const bgpList=[]; let m;
  // Match both "bgp N" (AOS-CX flat style) and "router bgp N" (IOS-like style)
  const re=/^(?:router\s+)?bgp\s+(\d+)\n((?:(?!^(?:vlan|interface|ip\s+route|user|router\s+|bgp\s+\d)\b)[^\n]*\n)*)/gm;
  while((m=re.exec(cfg))!==null){
    const asn=m[1],body=m[2];
    const rid=(body.match(/(?:bgp\s+)?router-id\s+(\S+)/)||[])[1]||'';
    const peers=[]; const pr=/neighbor\s+(\S+)\s+remote-as\s+(\d+)/g; let pm;
    while((pm=pr.exec(body))!==null){
      const ip=pm[1],peerAs=pm[2];
      const desc=(body.match(new RegExp('neighbor\\s+'+ip.replace(/\./g,'\\.')+'\\s+description\\s+([^\\n]+)'))||[])[1]||'';
      peers.push({ip,as:peerAs,desc:desc.trim(),type:peerAs===asn?'iBGP':'eBGP'});
    }
    const nets=[]; const nr=/network\s+([\d./]+)/g; let nm2;
    while((nm2=nr.exec(body))!==null)nets.push(nm2[1]);
    bgpList.push({asn,routerId:rid,peers,networks:nets});
  }
  return bgpList;
}

function parseAruba(cfg){
  const sys=parseArubaSysInfo(cfg);
  const stack=parseArubaVSF(cfg);
  const vlans=parseArubaVLANs(cfg);
  const interfaces=parseArubaInterfaces(cfg);
  const routes=parseArubaRoutes(cfg);
  const vrfs=parseArubaVRFs(cfg);
  const users=parseArubaUsers(cfg);
  const ospf=parseArubaOSPF(cfg);
  const bgp=parseArubaBGP(cfg);
  const rip=parseArubaRIP(cfg);
  const vrrpA=parseVRRP(cfg,'aruba');
  const vxlanA=parseVXLAN(cfg,'aruba');
  return{sys,irf:null,stack,vlans,interfaces,routes,vrfs,users,ospf,bgp,rip,vrrp:vrrpA,vxlan:vxlanA,vendor:'aruba'};
}


// ══════════════════════════════════════════════════════
//  FORTISWITCH (FORTIOS) PARSER
// ══════════════════════════════════════════════════════
