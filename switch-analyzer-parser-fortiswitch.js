function parseFortiSysInfo(cfg){
  const hostname=(cfg.match(/set hostname\s+"?([^"\n]+)"?/)||[])[1]||'unknown';
  const version=(cfg.match(/v\d+\.\d+\.\d+,\s*build\d+/)||[])[0]||'';
  return {hostname, version};
}

function parseFortiInterfaces(cfg){
  const ifaces=[];
  // config system interface
  const sysIfBlock=(cfg.match(/^config system interface\n([\s\S]*?)^end/m)||[])[1]||'';
  const lines=sysIfBlock.split(/\r?\n/);
  let current=null, bodyLines=[];
  for(const line of lines){
    const m=line.match(/^    edit\s+"?([^"\n]+)"?/);
    if(m){
      if(current)processBody(current, bodyLines.join('\n'));
      current=m[1]; bodyLines=[];
    }else if(line.match(/^    next\b/) && current){
      processBody(current, bodyLines.join('\n'));
      current=null; bodyLines=[];
    }else if(current){
      bodyLines.push(line);
    }
  }
  function processBody(name, body){
    const ip=(body.match(/set ip\s+([\d.]+)\s+([\d.]+)/));
    // 官方文件確認 IPv6 為巢狀 `config ipv6` / `set ip6-address ADDR/PREFIXLEN` / `end`；
    // body 本來就含 edit/next 之間的全部原始行（含巢狀 config/end 區塊），直接正則比對即可
    const ip6=(body.match(/set ip6-address\s+(\S+\/\d+)/));
    const ipStr=ip?ip[1]+'/'+cidrFromMask(ip[2]):'';
    // 雙棧修復（2026-08-13 新增）：ip6 原本已各自獨立擷取，但先前只是拿來組出單一 ipStr
    // 三元運算式（IPv4 存在時直接捨棄 ip6），從未真正存進物件；改為獨立欄位無條件保留
    const ip6Str=ip6?ip6[1]:'';
    // 次要IP（Secondary IP，官方 FortiSwitchOS Administration Guide／CLI Reference：
    // 巢狀 `config secondaryip` / `edit N` / `set ip A B`，每個 edit 為一筆次要IP；
    // 2026-08-17 從「僅取第一筆」擴大為完整收集全部 edit 的 `set ip`）
    const secBlockM=body.match(/config secondaryip\n([\s\S]*?)^[ \t]*end/m);
    const secondaryIps=secBlockM
      ? [...secBlockM[1].matchAll(/set ip\s+([\d.]+)\s+([\d.]+)/g)].map(m=>m[1]+'/'+cidrFromMask(m[2]))
      : [];
    const vrf=(body.match(/set vrf\s+(\d+)/)||[])[1]||'';
    const desc=(body.match(/set description\s+"?([^"\n]+)"?/)||[])[1]||'';
    const vlan=(body.match(/set vlanid\s+(\d+)/)||[])[1]||'';
    const status=body.includes('set status down');
    const type=vlan?'svi':'physical';
    // 修復（2026-08-18）：原本欄位命名為 id/ip，但 renderVRRP()／exportVRRPCSV() 全廠牌
    // 共用的既有慣例是 vrid/vip（含 preempt/authMode/trackIf/version 等欄位），FortiSwitch
    // 因命名不一致導致這些資料先前在畫面上完全顯示不出來（群組編號/VIP/搶佔狀態皆是
    // undefined）——本工具從未有 FortiSwitch VRRP 的測試覆蓋，此缺陷從未被發現；一併修正
    // 為與其餘廠牌一致的標準形狀，非本輪新增 IPv6 才引入的問題
    const vrrp=[];
    const vrrpRe=/config vrrp\n([\s\S]*?)^[ \t]*end/gm;
    let vm;
    while((vm=vrrpRe.exec(body))!==null){
      const vbody=vm[1];
      const vrId=(vbody.match(/edit\s+(\d+)/)||[])[1];
      const vrip=(vbody.match(/set vrip\s+(\S+)/)||[])[1]||'';
      const prio=(vbody.match(/set priority\s+(\d+)/)||[])[1]||'100';
      if(vrId)vrrp.push({vrid:vrId,vip:vrip,vip6:'',priority:prio,preempt:false,authMode:'',trackIf:'',trackReduced:'',version:'2'});
    }
    // IPv6（2026-08-18 新增，官方 FortiSwitchOS Administration Guide 確認巢狀
    // config ipv6 { ... config vrrp6 { edit N; set priority; set vrip6; } } 結構，與既有
    // config vrrp 平行；依 vrid 合併回既有 IPv4 記錄，找不到則新增獨立記錄）
    const vrrp6Re=/config vrrp6\n([\s\S]*?)^[ \t]*end/gm;
    let vm6;
    while((vm6=vrrp6Re.exec(body))!==null){
      const vbody6=vm6[1];
      const vrId6=(vbody6.match(/edit\s+(\d+)/)||[])[1];
      const vrip6=(vbody6.match(/set vrip6\s+(\S+)/)||[])[1]||'';
      if(!vrId6||!vrip6)continue;
      const existing=vrrp.find(v=>v.vrid===vrId6);
      if(existing)existing.vip6=vrip6;
      else vrrp.push({vrid:vrId6,vip:'',vip6:vrip6,priority:(vbody6.match(/set priority\s+(\d+)/)||[])[1]||'100',preempt:false,authMode:'',trackIf:'',trackReduced:'',version:'2'});
    }
    const bkMatch=name.match(/^(port\d+)\.([1-4])$/i);
    ifaces.push({name,type,desc,ip:ipStr,ip6:ip6Str,secondaryIps,mode:'',vlans:vlan,nativeVlan:'',vrf,shutdown:status,member:'1',hybrid:null,vrrp,fortilinkDiscovery:false,breakoutChild:!!bkMatch,breakoutParent:bkMatch?bkMatch[1]:'',breakoutMode:''});
  }

  // Physical ports
  const physBlock=(cfg.match(/^config switch physical-port\n([\s\S]*?)^end/m)||[])[1]||'';
  const physRe=/edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^    next|^end)/gm;
  let m;
  while((m=physRe.exec(physBlock))!==null){
    const name=m[1], body=m[2];
    if(ifaces.find(i=>i.name===name))continue;
    const desc=(body.match(/set description\s+"?([^"\n]+)"?/)||[])[1]||'';
    const status=body.includes('set status down');
    // Breakout（子埠命名用點號，非其他廠牌慣用的冒號，是 7 廠牌中唯一例外）
    const bkMatch=name.match(/^(port\d+)\.([1-4])$/i);
    ifaces.push({name,type:'physical',desc,ip:'',mode:'',vlans:'',nativeVlan:'',vrf:'',shutdown:status,member:'1',hybrid:null,vrrp:[],fortilinkDiscovery:false,breakoutChild:!!bkMatch,breakoutParent:bkMatch?bkMatch[1]:'',breakoutMode:''});
  }
  // Switch port mode/vlan from "config switch interface"
  const swIfBlock=(cfg.match(/^config switch interface\n([\s\S]*?)^end/m)||[])[1]||'';
  if(swIfBlock){
    const swIfRe=/^\s+edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^\s+next\b|^\s+edit\b|^end\b)/gm;
    while((m=swIfRe.exec(swIfBlock))!==null){
      const name=m[1].trim(), body=m[2];
      const existing=ifaces.find(i=>i.name===name);
      const native=(body.match(/set native-vlan\s+(\d+)/)||[])[1]||'';
      const allowed=(body.match(/set allowed-vlans\s+([^\n]+)/)||[])[1]?.trim()||'';
      const untagged=(body.match(/set untagged-vlans\s+([^\n]+)/)||[])[1]?.trim()||'';
      const ip=(body.match(/set ip\s+([\d.]+\/\d+)/)||body.match(/set ip\s+([\d.]+)\s+([\d.]+)/)||[])[1]||'';
      const ipStr=ip.includes('/')?ip:(()=>{const mm=body.match(/set ip\s+([\d.]+)\s+([\d.]+)/);return mm?mm[1]+'/'+cidrFromMask(mm[2]):''})();
      let mode='', vlans='', nativeVlan=native;
      if(allowed){mode='trunk';vlans=allowed;}
      else if(untagged){mode='access';vlans=untagged;}
      const fortilinkDiscovery=/set auto-discovery-fortilink\s+enable/.test(body);
      if(existing){
        if(mode)existing.mode=mode;
        if(vlans)existing.vlans=vlans;
        if(nativeVlan)existing.nativeVlan=nativeVlan;
        if(ipStr)existing.ip=ipStr;
        existing.fortilinkDiscovery=fortilinkDiscovery;
      }else{
        const bkMatch=name.match(/^(port\d+)\.([1-4])$/i);
        ifaces.push({name,type:ipStr?'svi':'physical',desc:'',ip:ipStr,mode,vlans,nativeVlan,vrf:'',shutdown:false,member:'1',hybrid:null,vrrp:[],fortilinkDiscovery,breakoutChild:!!bkMatch,breakoutParent:bkMatch?bkMatch[1]:'',breakoutMode:''});
      }
    }
  }
  return ifaces;
}

function parseFortiVLANs(cfg){
  const vlans=[];
  const vlanBlock=(cfg.match(/^config switch vlan\n([\s\S]*?)^end/m)||[])[1]||'';
  const vlanRe=/edit\s+"?(\d+)"?\n([\s\S]*?)(?=^[ \t]*next|^end)/gm;
  let m;
  while((m=vlanRe.exec(vlanBlock))!==null){
    const id=m[1], body=m[2];
    const name=(body.match(/set name\s+"?([^"\n]+)"?/)||[])[1]||'';
    vlans.push({id,name,ipSubnets:[]});
  }
  // Fallback: collect from interfaces if not in switch vlan config
  const ifVlanRe=/set vlanid\s+(\d+)/g;
  while((m=ifVlanRe.exec(cfg))!==null){
    if(!vlans.find(v=>v.id===m[1]))vlans.push({id:m[1],name:'VLAN'+m[1],ipSubnets:[]});
  }
  return vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
}

function parseFortiStack(cfg){
  // FortiSwitch uses MCLAG for stacking-like behavior
  const isMCLAG=cfg.includes('set mclag-icl enable') || cfg.includes('config switch trunk');
  if(!isMCLAG)return null;
  const members=[];
  // In standalone/manual MCLAG, we often see hostname or serial
  const sn=(cfg.match(/set serial-number\s+"?([^"\n]+)"?/)||[])[1]||'1';
  members.push({id:'1',model:sn,priority:100,role:'Master'});
  
  const trunks=[];
  const trunkBlock=(cfg.match(/^config switch trunk\n([\s\S]*?)^end/m)||[])[1]||'';
  const trunkRe=/edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^    next|^end)/gm;
  let m;
  while((m=trunkRe.exec(trunkBlock))!==null){
    const name=m[1], body=m[2];
    const membersMatch=(body.match(/set members\s+"?([^"\n]+)"?/)||[])[1]||'';
    const ports=membersMatch.split(/\s+/);
    const isICL=body.includes('set mclag-icl enable');
    if(isICL)trunks.push({id:name,ports,type:'ICL'});
  }
  return {type:'MCLAG',members,links:trunks};
}

// IPv6 靜態路由（2026-08-13 十一續新增）：官方 "config router static6" 巢狀區塊內欄位仍叫
// "set dst"／"set gateway"（非 dst6/gateway6，已查證），原本 "config router static\n" 的區塊
// 擷取正則因 "static6" 後面不是換行字元而完全比對不到，整個 IPv6 路由區塊對解析器是隱形的；
// 抽成小函式讓 static／static6 兩個區塊共用同一段內層擷取邏輯
function extractFortiStaticBlock(block){
  const routes=[];
  const re=/edit\s+(\d+)\n([\s\S]*?)(?=^[ \t]*next|^end)/gm;
  let m;
  while((m=re.exec(block))!==null){
    const body=m[2];
    const dst=(body.match(/set dst\s+(\S+)/)||[])[1]||'';
    const gw=(body.match(/set gateway\s+(\S+)/)||[])[1]||'';
    const dev=(body.match(/set device\s+"?([^"\n]+)"?/)||[])[1]||'';
    if(dst)routes.push({dst,gw,dev,proto:'Static'});
  }
  return routes;
}
function parseFortiStaticRoutes(cfg){
  const block=(cfg.match(/^config router static\n([\s\S]*?)^end/m)||[])[1]||'';
  const block6=(cfg.match(/^config router static6\n([\s\S]*?)^end/m)||[])[1]||'';
  return [...extractFortiStaticBlock(block),...extractFortiStaticBlock(block6)];
}

function parseFortiRouting(cfg){
  const result={ospf:[], ospf6:[], bgp:[], rip:[], rip6:[]};

  // OSPF
  const ospfBlock=(cfg.match(/^config router ospf\n([\s\S]*?)^end/m)||[])[1];
  if(ospfBlock){
    const rid=(ospfBlock.match(/set router-id\s+(\S+)/)||[])[1]||'';
    const areas=[];
    const areaRe=/config area\n([\s\S]*?)^    end/gm;
    let am;
    while((am=areaRe.exec(ospfBlock))!==null){
      const abody=am[1];
      const aidRe=/edit\s+(\S+)\n([\s\S]*?)(?=^\s*next|^end)/gm; let aidm;
      while((aidm=aidRe.exec(abody))!==null){
        if(!areas.find(a=>a.area===aidm[1]))areas.push({area:aidm[1],networks:[]});
      }
    }
    const netRe=/config network\n([\s\S]*?)^    end/gm;
    let nm;
    while((nm=netRe.exec(ospfBlock))!==null){
      const editRe=/edit\s+\S+\n([\s\S]*?)(?=^\s*next|^end)/gm; let em;
      while((em=editRe.exec(nm[1]))!==null){
        const ebody=em[1];
        const net=(ebody.match(/set prefix\s+(\S+)/)||[])[1];
        const naid=(ebody.match(/set area\s+(\S+)/)||[])[1];
        if(net && naid){
          let area=areas.find(a=>a.area===naid);
          if(!area){area={area:naid,networks:[]};areas.push(area);}
          area.networks.push({network:net,wildcard:''});
        }
      }
    }
    result.ospf.push({pid:'1',routerId:rid,areas});
  }

  // OSPFv3（2026-08-18 新增，官方 FortiGate/FortiOS 文件確認 `config router ospf6`
  // 巢狀 `config area`／`config ospf6-interface`，與 IPv4 baseline 用 `config network`
  // 掛 `set area` 不同——IPv6 版本改用逐介面 `config ospf6-interface` 內
  // `set interface`/`set area` 指派，比照本會話已建立的 ospf6 資料形狀（areas[].interfaces)）
  const ospf6Block=(cfg.match(/^config router ospf6\n([\s\S]*?)^end/m)||[])[1];
  if(ospf6Block){
    const rid=(ospf6Block.match(/set router-id\s+(\S+)/)||[])[1]||'';
    const areaMap=new Map();
    const areaRe=/config area\n([\s\S]*?)^    end/gm; let am6;
    while((am6=areaRe.exec(ospf6Block))!==null){
      const aidRe=/edit\s+(\S+)/gm; let aidm;
      while((aidm=aidRe.exec(am6[1]))!==null){
        if(!areaMap.has(aidm[1]))areaMap.set(aidm[1],{area:aidm[1],interfaces:[]});
      }
    }
    const if6Re=/config ospf6-interface\n([\s\S]*?)^    end/gm; let if6m;
    while((if6m=if6Re.exec(ospf6Block))!==null){
      const editRe=/edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^\s*next|^end)/gm; let em6;
      while((em6=editRe.exec(if6m[1]))!==null){
        const ifaceName=(em6[2].match(/set interface\s+"?([^"\n]+)"?/)||[])[1]||em6[1];
        const areaId=(em6[2].match(/set area\s+(\S+)/)||[])[1];
        if(!areaId)continue;
        if(!areaMap.has(areaId))areaMap.set(areaId,{area:areaId,interfaces:[]});
        areaMap.get(areaId).interfaces.push(ifaceName);
      }
    }
    result.ospf6.push({pid:'1',routerId:rid,areas:Array.from(areaMap.values())});
  }

  // RIP
  const ripBlock=(cfg.match(/^config router rip\n([\s\S]*?)^end/m)||[])[1];
  if(ripBlock){
    const nets=[];
    const netRe=/config network\n([\s\S]*?)^    end/gm;
    let nm;
    while((nm=netRe.exec(ripBlock))!==null){
      const prefixRe=/set prefix\s+(\S+)/g; let pfm;
      while((pfm=prefixRe.exec(nm[1]))!==null)nets.push(pfm[1]);
    }
    const redistribute=[];
    const redRe=/config redistribute\s+"?([^"\n]+)"?\n([\s\S]*?)^    end/gm;
    let rm;
    while((rm=redRe.exec(ripBlock))!==null){
      if(rm[2].includes('set status enable'))redistribute.push(rm[1]);
    }
    result.rip.push({pid:'1',version:'2',vrf:'',networks:nets,redistribute,passive:[],peers:[],autoSummary:null});
  }

  // RIPng（2026-08-18 新增，官方 FortiGate/FortiOS 文件確認 `config router ripng`
  // 巢狀 `config interface`，與 IPv4 baseline 用 `config network`/`set prefix` 不同——
  // RIPng 協定本質是逐介面 enable，`config interface` 底下每個 `edit <ifname>` 條目
  // 即視為該介面已啟用 RIPng）
  const ripngBlock=(cfg.match(/^config router ripng\n([\s\S]*?)^end/m)||[])[1];
  if(ripngBlock){
    const ifaces=[];
    const ifRe=/config interface\n([\s\S]*?)^    end/gm; let ifrm;
    while((ifrm=ifRe.exec(ripngBlock))!==null){
      const editRe=/edit\s+"?([^"\n]+)"?/gm; let erm;
      while((erm=editRe.exec(ifrm[1]))!==null)ifaces.push(erm[1]);
    }
    if(ifaces.length)result.rip6.push({pid:'1',interfaces:ifaces,redistribute:[]});
  }

  // BGP
  const bgpBlock=(cfg.match(/^config router bgp\n([\s\S]*?)^end/m)||[])[1];
  if(bgpBlock){
    const asn=(bgpBlock.match(/set as\s+(\d+)/)||[])[1]||'0';
    const rid=(bgpBlock.match(/set router-id\s+(\S+)/)||[])[1]||'';
    const peers=[];
    const peerRe=/config neighbor\n([\s\S]*?)^    end/gm;
    let pm;
    while((pm=peerRe.exec(bgpBlock))!==null){
      const pbody=pm[1];
      const editRe=/edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^\s*next|^end)/gm; let em;
      while((em=editRe.exec(pbody))!==null){
        const ip=em[1];
        const pasn=(em[2].match(/set remote-as\s+(\d+)/)||[])[1];
        if(ip)peers.push({ip,as:pasn,desc:'',type:pasn===asn?'iBGP':'eBGP'});
      }
    }
    result.bgp.push({asn,routerId:rid,peers,networks:[]});
  }
  
  return result;
}

// Breakout：獨立 `config switch phy-mode` 區塊，跟 `config switch interface` 是不同區塊
function parseFortiSwitchBreakout(cfg){
  const breakouts=[];
  const block=(cfg.match(/^config switch phy-mode\n([\s\S]*?)^end/m)||[])[1]||'';
  if(!block)return breakouts;
  const re=/set\s+(port\d+)-phy-mode\s+(4x10G|4x25G|2x50G)/gi;
  let m;
  while((m=re.exec(block))!==null){
    breakouts.push({parentPort:m[1],mode:m[2],raw:m[0]});
  }
  return breakouts;
}

function parseFortiSwitch(cfg){
  const sys=parseFortiSysInfo(cfg);
  const stack=parseFortiStack(cfg);
  const vlans=parseFortiVLANs(cfg);
  const interfaces=parseFortiInterfaces(cfg);
  const routing=parseFortiRouting(cfg);
  const routes=parseFortiStaticRoutes(cfg);

  // Link VLAN IP to VLANs
  vlans.forEach(v=>{
    const iface=interfaces.find(i=>i.vlans===v.id && i.ip);
    if(iface)v.ipSubnets.push(iface.ip);
  });

  const lacpFt=parseLACP(cfg,'fortiswitch');
  const dhcpFt=parseDHCP(cfg,'fortiswitch');
  return {
    sys, irf:null, stack, vlans, interfaces,
    routes, vrfs:[], users:[],
    ospf:routing.ospf, ospf6:routing.ospf6, bgp:routing.bgp, rip:routing.rip, rip6:routing.rip6,
    lacp:lacpFt, dhcp:dhcpFt,
    vrrp:interfaces.flatMap(i=>(i.vrrp||[]).map(v=>({interface:i.name, ...v}))),
    vxlan:null, vendor:'fortiswitch', breakouts:parseFortiSwitchBreakout(cfg)
  };
}

// 2026-07-24 新增：正確處理 FortiOS 巢狀 "config X ... edit N ... next ... end" 區塊邊界的通用
// helper。既有簡易 regex（比對零縮排 "^end"／不看縮排量的 "[ \t]*next"）在本體不含巢狀
// config 子區塊時安全（如既有 ACL/Security FortiSwitch parser），但 DHCP pool 底下有
// "config ip-range"/"config exclude-range" 這類巢狀子區塊時，子區塊自己的 next/end 會被誤判
// 為外層 edit 區塊的收尾、導致本體被提前截斷。改用逐行掃描＋深度計數正確追蹤巢狀邊界。
function _fortiEditEntries(block){
  const lines=block.split('\n');
  const entries=[];
  let i=0;
  while(i<lines.length){
    const m=lines[i].match(/^\s*edit\s+(\S+)/);
    if(m){
      const id=m[1];
      let depth=0,body=[],j=i+1;
      while(j<lines.length){
        const l=lines[j];
        if(/^\s*(config|edit)\b/.test(l))depth++;
        else if(/^\s*(next|end)\b/.test(l)){
          if(depth===0)break;
          depth--;
        }
        body.push(l);
        j++;
      }
      entries.push({id,body:body.join('\n')});
      i=j+1;
    }else i++;
  }
  return entries;
}

