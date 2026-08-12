function parseBrocadeSysInfo(cfg){
  const hostname=
    (cfg.match(/^hostname\s+(\S+)/m)||
     cfg.match(/^system-name\s+(\S+)/m)||[])[1]||'unknown';
  // "ver 08.0.95T213" at top, or "SW: Version X" in show version output
  const version=
    (cfg.match(/^ver\s+(\S+)/m)||
     cfg.match(/^SW:\s+Version\s+(\S+)/m)||
     cfg.match(/^!.*?Version\s+([^\s,\n]+)/m)||[])[1]?.trim()||'';
  // Ruckus 收購 Brocade 後延續同一套 FastIron CLI 語法（show run 語法不變），無法單純從
  // 版本號區分品牌；唯一可靠線索是 banner/copyright 內若含 Ruckus/CommScope 字樣，
  // 只有使用者連 `show version` 輸出一併貼上時才會出現，預設仍視為 brocade（不影響既有行為）
  const brand=/Ruckus|CommScope/i.test(cfg)?'ruckus':'brocade';
  return{hostname,version,brand};
}

function parseBrocadeStack(cfg){
  // "stack unit N" blocks indicate stacking
  if(!/^stack unit\s+\d+/m.test(cfg))return null;
  const members=[]; const seen=new Set(); let m;
  // Parse stack unit blocks
  const blockRe=/^stack unit\s+(\d+)\n((?:[ \t][^\n]*\n)*)/gm;
  while((m=blockRe.exec(cfg))!==null){
    const id=m[1]; if(seen.has(id))continue; seen.add(id);
    const body=m[2];
    const model=(body.match(/^\s+module\s+\d+\s+(\S+)/m)||[])[1]||'—';
    const priority=parseInt((body.match(/^\s+priority\s+(\d+)/m)||[])[1]||'0');
    members.push({id,model,priority,role:''});
  }
  if(!members.length)return null;
  members.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  // Active unit has highest priority; fallback to unit 1
  const maxPrio=Math.max(...members.map(x=>x.priority));
  members.forEach(x=>{
    x.role=maxPrio>0?(x.priority===maxPrio?'Active':'Standby'):(x.id==='1'?'Active':'Standby');
  });
  // 2026-07-25 對外查證官方 FastIron Stacking 文件後修正：先前假設的 "stack-port A B"
  // （兩埠一行宣告鏈路）查無此語法，真實 "stack-port" 是巢狀在 "stack unit N" 底下、
  // 只接受一個埠參數（作用是指定該 unit 用哪個實體埠做堆疊鏈路，非宣告任意兩埠間的鏈路）；
  // 官方查無任何指令能在設定檔宣告堆疊拓撲鏈路（僅能用 "show stack" 運行時查看），
  // 比照既有 parseExtremeXOSStack() 的結論，固定回傳空陣列
  const links=[];
  return{type:'ICX-Stack',members,links};
}

function parseBrocadeVLANs(cfg){
  const vlans=[]; const seen=new Set();
  // "vlan N name NAME by port" or "vlan N by port"
  const re=/^vlan\s+(\d+)(?:\s+name\s+(\S+))?\s+by\s+port/gm; let m;
  while((m=re.exec(cfg))!==null){
    if(seen.has(m[1]))continue; seen.add(m[1]);
    vlans.push({id:m[1],name:m[2]||'',ipSubnets:[]});
  }
  // Also catch "vlan N" blocks (NetIron style)
  const re2=/^vlan\s+(\d+)(?:\s+name\s+"?([^"\n]+)"?)?\s*\n((?:[ \t][^\n]*\n)*)/gm;
  while((m=re2.exec(cfg))!==null){
    if(seen.has(m[1]))continue; seen.add(m[1]);
    vlans.push({id:m[1],name:(m[2]||'').trim(),ipSubnets:[]});
  }
  vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return vlans;
}

// Expand Brocade port range strings like "e1/1/1 to e1/1/8" or "1/1 to 1/8"
function brocadeExpandPorts(str){
  const ports=[];
  // Normalize: strip keyword prefixes "ethernet", "ethe", "eth", standalone "e"
  // These appear as "ethe 1/1/1", "ethernet 1/1/1", "e 1/1/1"
  str=str.replace(/\b(?:ethernet|ethe|eth)\s+/gi,'')  // "ethernet 1/1/1" → "1/1/1"
         .replace(/\be\s+(?=\d)/gi,'')                 // "e 1/1/1" → "1/1/1" (only before digit)
         .trim();
  // Split on commas or spaces
  const toks=str.split(/[\s,]+/).filter(Boolean);
  for(let i=0;i<toks.length;i++){
    const tok=toks[i];
    // Skip leftover keyword tokens that aren't port IDs
    if(/^(?:ethernet|ethe|eth)$/i.test(tok))continue;
    // Only accept tokens that look like port IDs: digits and slashes
    const isPort=/^\d[\d/]*$/.test(tok);
    if(toks[i+1]==='to'&&toks[i+2]){
      const aM=tok.match(/^(\d+)\/(\d+)(?:\/(\d+))?$/);
      const bTok=toks[i+2].replace(/^e(?:the(?:rnet)?)?\s*/i,'');
      const bM=bTok.match(/^(\d+)\/(\d+)(?:\/(\d+))?$/);
      if(aM&&bM){
        const prefix3=aM[3]!==undefined;
        if(prefix3){
          const u=aM[1],sl=aM[2];
          for(let p=parseInt(aM[3]);p<=parseInt(bM[3]);p++)ports.push(u+'/'+sl+'/'+p);
        }else{
          const sl=aM[1];
          for(let p=parseInt(aM[2]);p<=parseInt(bM[2]);p++)ports.push(sl+'/'+p);
        }
        i+=2;
      }else if(isPort){ports.push(tok);}
    }else if(tok!=='to'&&isPort){
      ports.push(tok);
    }
  }
  return ports;
}

function parseBrocadeInterfaces(cfg){
  const ifaces=[];
  // Build VLAN membership from "vlan N by port" blocks
  const taggedMap={};   // port → [vid]
  const untaggedMap={}; // port → vid (access/native)

  const vlanBlocks=cfg.split(/^(?=vlan\s+\d)/m);
  for(const blk of vlanBlocks){
    const vm=blk.match(/^vlan\s+(\d+)/);
    if(!vm)continue;
    const vid=vm[1];
    // tagged ports
    const tR=/^\s+tagged\s+([^\n]+)/gm; let m;
    while((m=tR.exec(blk))!==null){
      brocadeExpandPorts(m[1]).forEach(p=>{
        if(!taggedMap[p])taggedMap[p]=[];
        if(!taggedMap[p].includes(vid))taggedMap[p].push(vid);
      });
    }
    // untagged ports
    const uR=/^\s+untagged\s+([^\n]+)/gm;
    while((m=uR.exec(blk))!==null){
      brocadeExpandPorts(m[1]).forEach(p=>{
        untaggedMap[p]=vid;
        if(!taggedMap[p])taggedMap[p]=[];
      });
    }
  }

  // Collect all port names
  const allPorts=new Set([...Object.keys(taggedMap),...Object.keys(untaggedMap)]);

  // Parse "interface ethernet N/N/N" or "interface ethe N/N/N" blocks
  // for desc, shutdown, dual-mode, lag membership
  const ifaceMap={};
  const ifBlocks=cfg.split(/^(?=interface\s)/m);
  for(const blk of ifBlocks){
    const im=blk.match(/^interface\s+(?:e(?:the(?:rnet)?)?\s+)?([\d][^\s]*)/i);
    if(!im)continue;
    const raw=im[1];
    ifaceMap[raw]=blk;
    allPorts.add(raw);
  }

  // Build dual-mode map from interface blocks:
  // "dual-mode [VLAN-ID]" means this port carries that VLAN untagged (native)
  // while remaining a trunk for other tagged VLANs
  const dualModeMap={}; // port → native vid from dual-mode
  for(const [port,blk] of Object.entries(ifaceMap)){
    const dm=blk.match(/^\s+dual-mode(?:\s+(\d+))?/m);
    if(dm){
      // dual-mode without VLAN-ID defaults to VLAN 1
      dualModeMap[port]=dm[1]||'1';
      allPorts.add(port);
    }
  }

  for(const port of [...allPorts].sort()){
    const blk=ifaceMap[port]||'';
    const desc=(blk.match(/^\s+port-name\s+(.+)/m)||blk.match(/^\s+description\s+(.+)/m)||[])[1]?.trim()||'';
    const shutdown=/^\s+disable\b/m.test(blk);
    const tagged=taggedMap[port]||[];
    // native VLAN resolution:
    // Priority: dual-mode in interface block > untagged in vlan block
    const dualNative=dualModeMap[port]||'';
    const vlanNative=untaggedMap[port]||'';
    const native=dualNative||vlanNative;

    let mode='',vlans='',nativeVlan='';
    if(tagged.length&&native){
      // trunk with native VLAN (dual-mode or untagged in vlan block)
      mode='trunk';
      vlans=tagged.join(',');
      nativeVlan=native;
    }else if(tagged.length){
      mode='trunk';
      vlans=tagged.join(',');
    }else if(dualNative){
      // dual-mode only (no explicit tagged VLANs declared in vlan blocks yet)
      // treat as trunk with native; tagged vlans may be implied
      mode='trunk';
      vlans='';
      nativeVlan=dualNative;
    }else if(native){
      mode='access';
      vlans=native;
    }

    // Add dual-mode native to tagged list in vlans string if not already present
    // so the UI shows it correctly (native VLAN is separate from vlans column)
    if(dualNative&&!tagged.includes(dualNative)&&tagged.length){
      // nativeVlan column handles it — don't double-add to vlans
    }

    const mem=(port.match(/^(\d+)\//)||[])[1]||'1';
    const lagM=blk.match(/^\s+link-aggregate\s+(\d+)/m)||blk.match(/^\s+lag\s+(\d+)/m);
    const lagMember=lagM?'lag'+lagM[1]:'';
    ifaces.push({name:'e'+port,type:'physical',desc,mode,vlans,nativeVlan,vrf:'',ip:'',shutdown,member:mem,hybrid:null,vrrp:[],lagMember});
  }

  // SVIs / ve interfaces  (Virtual Ethernet)
  // 2026-07-14 修正：原本用 cfg.split(/^(?=interface\s+ve\s)/im) 只在下一個 "interface ve"
  // 處切割，若檔案裡 ve 區塊後面接的是別種介面（ethernet/loopback）而非另一個 ve，該區塊
  // 會一路吃到檔案結尾，導致把後面不相干介面的 port-name 誤植成這個 ve 的 desc；改用跟
  // 上方實體埠解析一致的通用 "interface " 邊界切割，確保每個區塊只含自己的內容
  const svBlocks=cfg.split(/^(?=interface\s)/m);
  for(const blk of svBlocks){
    const vm=blk.match(/^interface\s+ve\s+(\d+)/i);
    if(!vm)continue;
    const vid=vm[1];
    const desc=(blk.match(/^\s+port-name\s+(.+)/m)||[])[1]?.trim()||'';
    const ipM=blk.match(/^\s+ip address\s+([\d.]+)\s+([\d.]+)/m);
    // 官方 FastIron Command Reference 確認 VE 介面 IPv6 語法 `ipv6 address ADDR/PREFIXLEN`
    const ip=ipM?ipM[1]+'/'+maskToCIDR(ipM[2]):(blk.match(/^\s+ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
    const vrf=(blk.match(/^\s+vrf\s+forwarding\s+(\S+)/m)||[])[1]||'';
    ifaces.push({name:'ve'+vid,type:'svi',desc,mode:'',vlans:vid,nativeVlan:'',vrf,ip,shutdown:false,member:'1',hybrid:null,vrrp:[]});
  }

  // Loopback（同一類邊界切割修正，見上方 SVI 註解）
  for(const blk of svBlocks){
    const lm=blk.match(/^interface\s+loopback\s+(\d+)/i);
    if(!lm)continue;
    const ipM=blk.match(/^\s+ip address\s+([\d.]+)\s+([\d.]+)/m);
    const ip=ipM?ipM[1]+'/'+maskToCIDR(ipM[2]):'';
    ifaces.push({name:'loopback'+lm[1],type:'loopback',desc:'',mode:'',vlans:'',nativeVlan:'',vrf:'',ip,shutdown:false,member:'1',hybrid:null,vrrp:[]});
  }

  return ifaces;
}

function parseBrocadeLACP(cfg){
  const lacp=[]; const seen=new Set();

  // ── Style 1 & 3: "lag ["]NAME["] dynamic|static id N" block ────
  // Parse line-by-line to correctly isolate each lag block
  const lines=cfg.split(/\r?\n/);
  let lagName='', lagMode='', lagId='', lagLines=[];

  const flushLag=()=>{
    if(!lagId||seen.has(lagId))return;
    seen.add(lagId);
    const body=lagLines.join('\n');
    const members=[];
    // "  ports ethe 1/1/47 to 1/1/48" — may be multiple ports lines
    const portsRe=/^\s+ports\s+([^\n]+)/gm; let pm;
    while((pm=portsRe.exec(body))!==null){
      brocadeExpandPorts(pm[1]).forEach(p=>members.push('e'+p));
    }
    // Also check "  ethernet N/N/N" direct port lines (some IOS versions)
    const portLineRe=/^\s+e(?:the(?:rnet)?)?\s+([\d/]+)/gm;
    while((pm=portLineRe.exec(body))!==null){
      const p='e'+pm[1];
      if(!members.includes(p))members.push(p);
    }
    const displayName='lag'+lagId+' ('+lagName+')';
    lacp.push({name:displayName,mode:lagMode,members,desc:''});
    lagName=''; lagMode=''; lagId=''; lagLines=[];
  };

  for(const line of lines){
    // New lag block header: "lag ["]NAME["] dynamic|static id N"
    const lm=line.match(/^lag\s+"?([^"\s]+)"?\s+(dynamic|static)\s+id\s+(\d+)/i);
    if(lm){
      flushLag();
      lagName=lm[1]; lagMode=lm[2]==='dynamic'?'Active':'Static'; lagId=lm[3];
      lagLines=[];
      continue;
    }
    if(lagId){
      // End of block: non-indented non-empty line that isn't a continuation
      if(line.length>0&&!/^\s/.test(line)&&!/^!/.test(line)){
        flushLag();
      }else{
        lagLines.push(line);
      }
    }
  }
  flushLag();

  // ── Style 2: old "trunk" syntax — "trunk ethe X [to ethe Y]" ────
  // Handles: "trunk ethe 1/1/43 to ethe 1/1/44" or "trunk ethernet 1/1/43"
  const trunkRe=/^trunk\s+((?:e(?:the(?:rnet)?)?\s+)?[\d/]+(?:\s+to\s+(?:e(?:the(?:rnet)?)?\s+)?[\d/]+)?(?:\s+ethe\s+[\d/]+)*)/gm;
  let tm;
  while((tm=trunkRe.exec(cfg))!==null){
    const portStr=tm[1];
    const members=brocadeExpandPorts(portStr).map(p=>'e'+p);
    if(!members.length)continue;
    const key='trunk-'+portStr.trim();
    if(seen.has(key))continue; seen.add(key);
    lacp.push({name:'trunk-'+members[0],mode:'Static',members,desc:''});
  }

  return lacp;
}

function parseBrocadeRoutes(cfg){
  const routes=[]; let m;
  // "ip route X.X.X.X/P G.G.G.G" or "ip route X.X.X.X M.M.M.M G.G.G.G"
  const re=/^ip route\s+([\d.]+)(?:\/(\d+)|\s+([\d.]+))\s+([\d.]+)/gm;
  while((m=re.exec(cfg))!==null){
    let dst,gw=m[4];
    if(m[2])dst=m[1]+'/'+m[2];
    else dst=m[1]+'/'+maskToCIDR(m[3]);
    routes.push({dst,gw,vrf:'',gwIsInterface:false});
  }
  return routes;
}

// 2026-07-14 修正：原本套用 Cisco 式 `router ospf N` + `network X Y area A`，
// 已對外查證 Ruckus 官方 FastIron 文件（Layer 3 Routing Configuration Guide／
// Command Reference）確認實際語法完全不同：(1) `router ospf` 本身不帶 process-id；
// (2) router-id 是全域指令 `ip router-id A.B.C.D`（OSPF/BGP 共用，不巢狀在 router
// 區塊內）；(3) area 在 `router ospf` 區塊內用 `area A.B.C.D normal|stub|nssa` 宣告，
// 但實際「哪個網段屬於哪個 area」是逐介面指派（`ip ospf area A.B.C.D`，寫在該介面/VE
// 自己的 interface 區塊內），並非 Cisco 式在 router ospf 底下用 network+wildcard 宣告。
// 資料形狀比照既有 parseJuniperOSPF 的 area-is-interface 慣例，areas[].networks 內
// 每筆改放 `{network:介面名稱, wildcard:'', type:'interface'}`。
function parseBrocadeOSPF(cfg){
  const ospfM=cfg.match(/^router ospf\s*\r?\n((?:[ \t][^\n]*\n)*)/m);
  if(!ospfM)return[];
  const rid=(cfg.match(/^ip router-id\s+([\d.]+)/m)||[])[1]||'';
  const areas={};
  // 對外查證 Ruckus FastIron 官方文件/範例確認：一般（非 stub/nssa）area 完全不需要
  // 在 router ospf 區塊內另外宣告型別關鍵字，僅靠逐介面 ip ospf area N 即可生效；
  // 原本要求 router ospf 區塊內須先有帶關鍵字的 area 宣告才繼續解析的 gate 邏輯是錯的
  // （且該邏輯的輸出從未被使用，只用來擋門檻），已移除，area 清單改為完全由下方
  // 逐介面掃描動態建立。
  const ifBlocks=cfg.split(/^(?=interface\s)/m);
  for(const blk of ifBlocks){
    const veM=blk.match(/^interface\s+ve\s+(\d+)/i);
    const loM=blk.match(/^interface\s+loopback\s+(\d+)/i);
    const ethM=blk.match(/^interface\s+(?:e(?:the(?:rnet)?)?\s+)?([\d][^\s]*)/i);
    let ifName='';
    if(veM)ifName='ve'+veM[1];
    else if(loM)ifName='loopback'+loM[1];
    else if(ethM)ifName='e'+ethM[1];
    if(!ifName)continue;
    const aM=blk.match(/^\s+ip ospf area\s+([\d.]+)/m);
    if(aM){
      const area=aM[1];
      if(!areas[area])areas[area]=[];
      areas[area].push({network:ifName,wildcard:'',type:'interface'});
    }
  }
  const areaList=Object.entries(areas).map(([area,networks])=>({area,networks}));
  return areaList.length?[{pid:'1',routerId:rid,areas:areaList,protocol:'ospf'}]:[];
}

// 2026-07-14 修正：原本套用 Cisco 式 `router bgp N`（ASN 直接接在同一行），已對外
// 查證官方文件確認實際語法是 `router bgp`（不含 ASN）進入子模式後，用獨立指令
// `local-as N` 設定 ASN；router-id 同樣是全域 `ip router-id A.B.C.D`（與 OSPF 共用），
// 不巢狀在 router bgp 區塊內。
function parseBrocadeBGP(cfg){
  const bgpM=cfg.match(/^router bgp\s*\r?\n((?:[ \t][^\n]*\n)*)/m);
  if(!bgpM)return[];
  const body=bgpM[1];
  const asn=(body.match(/^\s+local-as\s+(\d+)/m)||[])[1]||'';
  if(!asn)return[];
  const rid=(cfg.match(/^ip router-id\s+([\d.]+)/m)||[])[1]||'';
  const peers=[]; let m;
  const re=/^\s+neighbor\s+([\d.]+)\s+remote-as\s+(\d+)/gm;
  while((m=re.exec(body))!==null){
    const ip=m[1],peerAS=m[2];
    const descM=body.match(new RegExp('^\\s+neighbor\\s+'+ip.replace(/\./g,'\\.')+'\\s+description\\s+([^\\n]+)','m'));
    const desc=(descM||[])[1]?.trim()||'';
    peers.push({ip,as:peerAS,desc,type:peerAS===asn?'iBGP':'eBGP'});
  }
  // 2026-07-17 對外查證 Brocade FastIron Ethernet Switch Layer 3 Routing Configuration
  // Guide「Specifying a list of networks to advertise」章節確認：`network ip-addr ip-mask
  // [route-map map-name] | [weight num] | [backdoor]`，點分遮罩格式非 CIDR，於 BGP
  // global mode（router bgp 區塊內，與 local-as/neighbor 同層級）
  const networks=[]; let nm;
  const nr=/^\s+network\s+([\d.]+)\s+([\d.]+)/gm;
  while((nm=nr.exec(body))!==null)networks.push(nm[1]+'/'+cidrFromMask(nm[2]));
  return peers.length?[{asn,routerId:rid,peers,networks}]:[];
}

function parseBrocadeVRRP(cfg){
  const groups=[]; const seen=new Set();
  // Split on "interface ve N" blocks to find VRRP-E per-SVI
  const veBlocks=cfg.split(/^(?=interface\s+ve\s)/im);
  for(const blk of veBlocks.slice(1)){
    const ifM=blk.match(/^interface\s+ve\s+(\d+)/i);
    if(!ifM)continue;
    const iface='ve'+ifM[1];
    // Find "ip vrrp-extended vrid N" lines, then look ahead for sub-block lines
    const lines=blk.split(/\r?\n/);
    let vrid=null, subLines=[];
    const flushVRRP=()=>{
      if(!vrid)return;
      const key=iface+':'+vrid;
      if(!seen.has(key)){
        seen.add(key);
        const sub=subLines.join('\n');
        // VIP: "  ip X.X.X.X" (indented under vrid block)
        const vipM=sub.match(/^\s+ip\s+([\d.]+)/m);
        const vip=(vipM||[])[1]||'';
        const prioM=sub.match(/^\s+priority\s+(\d+)/m);
        const priority=(prioM||[])[1]||'100';
        groups.push({vrid,interface:iface,vip,priority,preempt:true,authMode:'',trackIf:'',trackReduced:'',version:'2'});
      }
      vrid=null; subLines=[];
    };
    for(const line of lines){
      const vm=line.match(/^\s+ip vrrp(?:-extended)?\s+vrid\s+(\d+)/);
      if(vm){flushVRRP(); vrid=vm[1]; subLines=[];}
      else if(vrid){
        // Collect indented sub-lines (deeper indent = part of vrid block)
        if(/^\s{2,}/.test(line)||line.trim()===''){subLines.push(line);}
        else{flushVRRP();}
      }
    }
    flushVRRP();
  }
  return groups;
}

function parseBrocadeUsers(cfg){
  const users=[]; const seen=new Set(); let m;
  // "username NAME privilege N password N HASH"
  const re=/^username\s+(\S+)(?:\s+privilege\s+(\d+))?(?:\s+password\s+(\d+)\s+(\S+))?/gm;
  while((m=re.exec(cfg))!==null){
    const name=m[1]; if(seen.has(name))continue; seen.add(name);
    const priv=m[2]||'';
    const role=priv==='0'?'superuser':priv==='4'?'port-config':'user';
    const pwdEnc=m[3]||'';
    const pwdHash=m[4]||'';
    let pwdType='none',pwdWeak=false;
    if(pwdEnc==='8'){pwdType='md5';pwdWeak=false;}
    else if(pwdEnc==='0'){pwdType='plaintext';pwdWeak=true;}
    else if(pwdHash){pwdType='hash';pwdWeak=false;}
    users.push({name,role,service:'console/ssh/telnet',hasPwd:!!pwdHash||pwdEnc==='0',pwdType,pwdWeak});
  }
  return users;
}

function parseBrocadeDHCP(cfg){
  const pools=[]; let m;
  const lines=cfg.split(/\r?\n/);

  // Parse pool blocks line by line
  let poolName='', poolLines=[];
  const flushPool=()=>{
    if(!poolName)return;
    const body=poolLines.join('\n');
    const nM=body.match(/^\s+network-address\s+([\d.]+)\s+([\d.]+)/m);
    const network=nM?nM[1]+'/'+maskToCIDR(nM[2]):'';
    const rM=body.match(/^\s+range\s+([\d.]+)\s+([\d.]+)/m);
    const range=rM?rM[1]+'-'+rM[2]:'';
    const gwM=body.match(/^\s+(?:default-router|default-gateway)\s+([\d.]+)/m);
    const gw=(gwM||[])[1]||'';
    const dnsM=body.match(/^\s+dns-server\s+([^\n]+)/m);
    const dns=dnsM?dnsM[1].trim().split(/\s+/).filter(Boolean):[];
    const leaseM=body.match(/^\s+lease-time\s+(\d+)/m);
    const leaseSec=parseInt((leaseM||[])[1]||'0');
    const lease=leaseSec?Math.floor(leaseSec/3600)+'h':'';
    const exM=body.match(/^\s+excluded-address\s+([^\n]+)/m);
    const excluded=(exM||[])[1]?.trim()||'';
    // 2026-07-24 對外查證官方 RUCKUS FastIron DHCP Configuration Guide 後新增：優先採用新版
    // numbered option 語法(150/66/67/42)，舊版 tftp-server/bootfile 指令(08.0.61前)作備援
    const bootM=body.match(/^\s+option\s+67\s+ascii\s+(\S+)/m)||body.match(/^\s+bootfile\s+(\S+)/m);
    const bootFile=(bootM||[])[1]||'';
    const nextM=body.match(/^\s+option\s+150\s+ip\s+([\d.]+)/m)||body.match(/^\s+option\s+66\s+ascii\s+(\S+)/m)||body.match(/^\s+tftp-server\s+([\d.]+)/m);
    const nextServer=(nextM||[])[1]||'';
    const ntpM=body.match(/^\s+option\s+42\s+ip\s+([^\n]+)/m);
    const ntpServer=ntpM?ntpM[1].trim().split(/\s+/)[0]:'';
    pools.push({name:poolName,network,range,gateway:gw,dns,lease,excluded,interface:'',bootFile,nextServer,ntpServer,type:'server'});
    poolName=''; poolLines=[];
  };
  for(const line of lines){
    const pm=line.match(/^ip dhcp-server pool\s+(\S+)/);
    if(pm){flushPool(); poolName=pm[1]; poolLines=[];}
    else if(poolName){
      // Stop block on non-indented non-empty line that's not part of the pool
      if(line.length>0&&!/^\s/.test(line)&&!/^!/.test(line)){flushPool();}
      else{poolLines.push(line);}
    }
  }
  flushPool();

  // DHCP Relay: "ip helper-address X.X.X.X" under ve interfaces
  // 2026-07-24 對外查證官方 FastIron DHCP Configuration Guide 後新增：Option82 在啟用 DHCP
  // Snooping 逐 VLAN 後「自動生效，無需額外指令」("DHCP option 82 is automatically enabled when
  // you enable DHCP snooping on a VLAN")；簡化為全域訊號判斷（snooping 已啟用且未被全域
  // `ip dhcp snooping relay information disable` 停用），不逐 VLAN/逐 interface 追蹤覆蓋範圍
  const option82=/^ip dhcp snooping vlan\s+/m.test(cfg)&&!/^ip dhcp snooping relay information disable\b/m.test(cfg);
  const veBlocks=cfg.split(/^(?=interface\s+ve\s)/im);
  for(const blk of veBlocks.slice(1)){
    const ifM=blk.match(/^interface\s+ve\s+(\d+)/i);
    if(!ifM)continue;
    const iface='ve'+ifM[1];
    const relayRe=/^\s+ip helper-address\s+([\d.]+)/gm;
    while((m=relayRe.exec(blk))!==null){
      pools.push({name:iface,network:'',range:'',gateway:'',dns:[],lease:'',excluded:'',interface:iface,type:'relay',relayServer:m[1],option82});
    }
  }
  return pools;
}

// 2026-07-18 修正：原本套用 Cisco 式 `router rip` 含 `network`/`passive-interface`
// 陳述式，已對外查證官方 FastIron L3 Routing Guide 確認實際語法是 `router rip`
// （不含 network 陳述式）進入 config-rip-router 子模式，全域參數為 distance/timer/
// learn-default/default-metric/redistribute；真正決定哪個介面參與 RIP 的是逐介面
// 獨立宣告的 `ip rip`（v2，預設）或 `ip rip v1-only`，兩者完全分離，跟 OSPF/BGP
// 先前修過的「逐介面才是真正生效位置」同一類既有錯誤。
function parseBrocadeRIP(cfg){
  const ripM=cfg.match(/^router rip\s*\r?\n((?:[ \t][^\n]*\n)*)/m);
  if(!ripM)return[];
  const body=ripM[1];
  const distance=(body.match(/^\s+distance\s+(\d+)/m)||[])[1]||'';
  const timerM=body.match(/^\s+timer\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m);
  const timers=timerM?timerM.slice(1,5).join(' '):'';
  const learnDefault=/^\s+learn-default\b/m.test(body);
  const defaultMetric=(body.match(/^\s+default-metric\s+(\d+)/m)||[])[1]||'';
  const redistribute=[]; let rm;
  const rr=/^\s+redistribute\s+(\S+)(?:\s+route-map\s+(\S+))?/gm;
  while((rm=rr.exec(body))!==null)redistribute.push(rm[1]+(rm[2]?' route-map '+rm[2]:''));
  // 逐介面：哪些 interface 有宣告 ip rip（含 ip rip v1-only／metric-offset 等變化）才是真正啟用 RIP
  const interfaces=[];
  const ifBlocks=cfg.split(/^(?=interface\s)/m);
  for(const blk of ifBlocks){
    const veM=blk.match(/^interface\s+ve\s+(\d+)/i);
    const ethM=blk.match(/^interface\s+(?:e(?:the(?:rnet)?)?\s+)?([\d][^\s]*)/i);
    let ifName='';
    if(veM)ifName='ve'+veM[1];
    else if(ethM)ifName='e'+ethM[1];
    if(!ifName)continue;
    if(!/^\s+ip rip\b/m.test(blk))continue;
    const v1Only=/^\s+ip rip\s+v1-only\b/m.test(blk);
    interfaces.push({name:ifName,version:v1Only?'1':'2'});
  }
  return[{pid:'default',version:'2',vrf:'',networks:[],redistribute,passive:[],peers:[],autoSummary:null,timers,distance,learnDefault,defaultMetric,interfaces}];
}

// Brocade/Ruckus ICX QoS（本次新增）：對外查證官方 FastIron QoS and Traffic Management
// Configuration Guide 確認實際模型是 8 個硬體佇列（qosp0-7）＋DSCP 對應表，跟其餘廠牌
// 共用的 policy-map/class/rate（Cisco 風格）完全不同語意，故不沿用共用 QoS 資料形狀，
// 改用 Brocade 專屬形狀：全域 dscpMap（`qos-tos map dscp-priority ... to N`）＋
// 逐 interface ports（`priority N` 預設優先權、`trust dscp` 信任旗標）
function parseBrocadeQoS(cfg){
  const dscpMap=[]; let m;
  const dmRe=/^qos-tos map dscp-priority\s+([\d\s]+?)\s+to\s+(\d)\s*$/gm;
  while((m=dmRe.exec(cfg))!==null) dscpMap.push({dscpValues:m[1].trim().replace(/\s+/g,' '),priority:m[2]});

  const ports=[];
  const ifBlocks=cfg.split(/^(?=interface\s)/m);
  for(const blk of ifBlocks){
    const veM=blk.match(/^interface\s+ve\s+(\d+)/i);
    const ethM=blk.match(/^interface\s+(?:e(?:the(?:rnet)?)?\s+)?([\d][^\s]*)/i);
    let port='';
    if(veM)port='ve '+veM[1];
    else if(ethM)port='ethernet '+ethM[1];
    if(!port)continue;
    const prM=blk.match(/^\s+priority\s+([0-7])\s*$/m);
    const trustDscp=/^\s+trust dscp\b/m.test(blk);
    if(prM||trustDscp) ports.push({port,priority:prM?prM[1]:'',trustDscp});
  }
  return {dscpMap,ports};
}

function parseBrocade(cfg){
  const stk=parseBrocadeStack(cfg);
  return{
    sys:        parseBrocadeSysInfo(cfg),
    irf:null, stack:stk,
    vlans:      parseBrocadeVLANs(cfg),
    interfaces: parseBrocadeInterfaces(cfg),
    lacp:       parseBrocadeLACP(cfg),
    routes:     parseBrocadeRoutes(cfg),
    vrfs:[], dhcp: parseBrocadeDHCP(cfg),
    users:      parseBrocadeUsers(cfg),
    ospf:       parseBrocadeOSPF(cfg),
    bgp:        parseBrocadeBGP(cfg),
    vrrp:       parseBrocadeVRRP(cfg),
    rip:        parseBrocadeRIP(cfg),
    qos:        parseBrocadeQoS(cfg),
    vxlan:null,
    vendor:'brocade'
  };
}

// ── Vendor Detection ──────────────────────────────────────────
