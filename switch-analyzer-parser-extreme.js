function parseExtremeXOSSysInfo(cfg){
  // Style A: configure snmp sysname "NAME"
  // Style B: configure sys-name "NAME"  (older EXOS)
  const hostname=
    (cfg.match(/^configure snmp sysname\s+"?([^"\n]+)"?/m)||
     cfg.match(/^configure sys-name\s+"?([^"\n]+)"?/m)||
     cfg.match(/^configure snmp sys-name\s+"?([^"\n]+)"?/m)||[])[1]?.trim()||'unknown';
  const contact=
    (cfg.match(/^configure snmp syscontact\s+"?([^"\n]+)"?/m)||
     cfg.match(/^configure snmp sys-contact\s+"?([^"\n]+)"?/m)||[])[1]?.trim()||'';
  const location=
    (cfg.match(/^configure snmp syslocation\s+"?([^"\n]+)"?/m)||
     cfg.match(/^configure snmp sys-location\s+"?([^"\n]+)"?/m)||[])[1]?.trim()||'';
  const version=(cfg.match(/^#.*ExtremeXOS.*version\s+(\S+)/m)||
                 cfg.match(/Image\s+:\s+\S+\s+(\d+\.\d+\.\d+)/m)||[])[1]||'';
  return{hostname,version,contact,location};
}

function exosExpandPorts(portStr){
  const ports=[];
  portStr.split(',').forEach(tok=>{
    const tok2=tok.trim();
    const rangeM=tok2.match(/^(\d+)-(\d+)$/);
    if(rangeM){
      for(let p=parseInt(rangeM[1]);p<=parseInt(rangeM[2]);p++) ports.push(String(p));
    } else if(tok2) {
      ports.push(tok2);
    }
  });
  return ports;
}

function parseExtremeXOSVLANs(cfg){
  const vlans=[]; const seen=new Set(); let m;
  // Style A: create vlan "NAME" tag N  (quoted)
  // Style B: create vlan NAME tag N    (unquoted, no spaces in name)
  const createRe=/^create vlan\s+"?([^"\s]+)"?\s+tag\s+(\d+)/gm;
  while((m=createRe.exec(cfg))!==null){
    const name=m[1].replace(/"/g,''),id=m[2];
    if(seen.has(id)) continue;
    seen.add(id);
    // Build name-escape for regex (handle hyphens/underscores)
    const nameEsc=name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    // Description: configure vlan NAME description "X"
    const descM=cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+description\\s+"?([^"\\n]+)"?','m'));
    // IP: configure vlan NAME ipaddress X M  OR  configure NAME ipaddress X M
    const ipM=cfg.match(new RegExp('^configure(?:\\s+vlan)?\\s+"?'+nameEsc+'"?\\s+ipaddress\\s+([\\d.]+)\\s+([\\d.]+)','m'));
    const desc=(descM||[])[1]?.trim()||'';
    const ipCidr=ipM?ipM[1]+'/'+maskToCIDR(ipM[2]):'';
    // 次要IP（2026-08-12 新增，2026-08-17 從「僅取第一筆」擴大為完整收集）：同
    // parseExtremeXOSInterfaces() 的 SVI 擷取邏輯，這裡是 vlans[] 自己獨立的 IP 擷取路徑
    // （既有程式碼本來就與 interfaces[] 各自重複 regex 一次），比照既有慣例同步補上，
    // 供 renderExtremeVLANs() 直接讀取不需跨陣列查找
    const secCidrAll=[...cfg.matchAll(new RegExp('^configure(?:\\s+vlan)?\\s+"?'+nameEsc+'"?\\s+add\\s+secondary-ipaddress\\s+([\\d.]+/\\d+)','gm'))].map(m=>m[1]);
    const secDottedAll=[...cfg.matchAll(new RegExp('^configure(?:\\s+vlan)?\\s+"?'+nameEsc+'"?\\s+add\\s+secondary-ipaddress\\s+([\\d.]+)\\s+([\\d.]+)','gm'))].map(m=>m[1]+'/'+maskToCIDR(m[2]));
    const secondaryIps=secCidrAll.length?secCidrAll:secDottedAll;
    vlans.push({id,name,desc,ip:ipCidr,secondaryIps,ipSubnets:[]});
  }
  vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return vlans;
}

function parseExtremeXOSInterfaces(cfg){
  const ifaces=[],portVlans={}; let m;

  function normPort(p){ return p.trim(); }  // keep slot:port as-is e.g. "1:1"

  function addPort(port,vid,mode){
    const key=normPort(port);
    if(!portVlans[key])portVlans[key]={tagged:[],untagged:[]};
    portVlans[key][mode].push(vid);
  }

  // Expand EXOS port list: "1:1, 2:1" or "1,2,5-8" or "1:24"
  function exosExpandPortsV2(portStr){
    const ports=[];
    portStr.split(',').forEach(tok=>{
      const t=tok.trim();
      if(!t)return;
      // Range: "5-8" or "1:1-1:8" (same slot)
      const rangeM=t.match(/^(\d+:\d+)-(\d+:\d+)$/)
                  ||t.match(/^(\d+)-(\d+)$/);
      if(rangeM){
        // Simple numeric range
        const aM=rangeM[1].match(/(\d+):(\d+)/),bM=rangeM[2].match(/(\d+):(\d+)/);
        if(aM&&bM&&aM[1]===bM[1]){
          for(let p=parseInt(aM[2]);p<=parseInt(bM[2]);p++) ports.push(aM[1]+':'+p);
        }else if(!aM&&!bM){
          for(let p=parseInt(rangeM[1]);p<=parseInt(rangeM[2]);p++) ports.push(String(p));
        }else ports.push(t);
      }else{ports.push(t);}
    });
    return ports;
  }

  // Build VLAN id lookup: name → id
  const vlanNameToId={};
  let mm;
  const createRe2=/^create vlan\s+"?([^"\s]+)"?\s+tag\s+(\d+)/gm;
  while((mm=createRe2.exec(cfg))!==null) vlanNameToId[mm[1].replace(/"/g,'')]=mm[2];

  function getVid(name){ return vlanNameToId[name]||name; }

  // Style A: configure vlan "NAME" add ports P tagged|untagged  (with vlan keyword)
  const portReA=/^configure vlan\s+"?([^"\s]+)"?\s+add ports?\s+([^u\n][^\n]*?)\s+(tagged|untagged)/gm;
  while((m=portReA.exec(cfg))!==null){
    const vid=getVid(m[1].replace(/"/g,'')),portList=m[2],mode=m[3];
    exosExpandPortsV2(portList).forEach(p=>addPort(p,vid,mode));
  }

  // Style B: configure NAME add ports P tagged|untagged  (no vlan keyword — VLAN name is first token)
  // Pattern: "configure VLANNAME add ports ..."  where VLANNAME is not a keyword
  const portReB=/^configure\s+([A-Za-z][A-Za-z0-9_\-]*)\s+add ports?\s+([^\n]+?)\s+(tagged|untagged)\s*$/gm;
  while((m=portReB.exec(cfg))!==null){
    const vname=m[1];
    if(['vlan','snmp','stacking','ospf','vrrp','bgp','iproute'].includes(vname.toLowerCase()))continue;
    const vid=getVid(vname),portList=m[2],mode=m[3];
    exosExpandPortsV2(portList).forEach(p=>addPort(p,vid,mode));
  }

  // Sharing (LAG) port membership
  const lagMembership={};
  const shareRe=/^enable sharing\s+(\S+)\s+grouping\s+([^\n]+)/gm;
  while((m=shareRe.exec(cfg))!==null){
    const master=normPort(m[1]);
    const groupStr=m[2].split(/algorithm|lacp/)[0].trim();
    exosExpandPortsV2(groupStr).forEach(p=>lagMembership[normPort(p)]=master);
  }

  // Disabled ports
  const disabled=new Set();
  const disRe=/^disable port\s+([^\n]+)/gm;
  while((m=disRe.exec(cfg))!==null) exosExpandPortsV2(m[1].trim()).forEach(p=>disabled.add(normPort(p)));

  const allPorts=new Set([...Object.keys(portVlans),...Object.keys(lagMembership)]);
  disabled.forEach(p=>allPorts.add(p));

  for(const port of [...allPorts].sort()){
    const pv=portVlans[port]||{tagged:[],untagged:[]};
    const shutdown=disabled.has(port);
    let mode='',vlans='',nativeVlan='';
    if(pv.tagged.length&&pv.untagged.length){mode='trunk';vlans=pv.tagged.join(',');nativeVlan=pv.untagged[0]||'';}
    else if(pv.tagged.length){mode='trunk';vlans=pv.tagged.join(',');}
    else if(pv.untagged.length){mode='access';vlans=pv.untagged[0]||'';}
    const lagMember=lagMembership[port]?'lag'+lagMembership[port]:'';
    ifaces.push({name:port,type:'physical',desc:'',mode,vlans,nativeVlan,vrf:'',ip:'',shutdown,member:'1',hybrid:null,vrrp:[],lagMember});
  }

  // Loopback
  const loRe=/^configure loopback add ipaddress\s+([\d./]+)/gm;
  while((m=loRe.exec(cfg))!==null)
    ifaces.push({name:'loopback0',type:'loopback',desc:'',mode:'',vlans:'',nativeVlan:'',vrf:'',ip:m[1],shutdown:false,member:'1',hybrid:null,vrrp:[]});

  // SVIs — from both "configure vlan NAME ipaddress" and "configure NAME ipaddress"
  const ipRe=/^configure(?:\s+vlan)?\s+"?([A-Za-z][A-Za-z0-9_\-]*)"?\s+ipaddress\s+([\d.]+)\s+([\d.]+)/gm;
  while((m=ipRe.exec(cfg))!==null){
    const name=m[1].replace(/"/g,'');
    if(['stacking','ospf','vrrp','bgp'].includes(name.toLowerCase()))continue;
    const ip=m[2],mask=m[3],vid=vlanNameToId[name]||'';
    const cidr=ip+'/'+maskToCIDR(mask);
    // 次要IP（2026-08-12 新增，2026-08-17 從「僅取第一筆」擴大為完整收集，中高信心度：
    // 官方 ExtremeXOS Command Reference Guide `configure {vlan} vlan_name add
    // secondary-ipaddress [ip_address {netmask}|ipNetmask]`，documentation.extremenetworks.com
    // 官方域名兩次獨立搜尋索引摘要互相印證含完整範例 `configure vlan multi add
    // secondary-ipaddress 10.1.1.1/24`；同時支援 CIDR 與 dotted-mask 兩種寫法）
    const nameEsc=name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const secCidrAll=[...cfg.matchAll(new RegExp('^configure(?:\\s+vlan)?\\s+"?'+nameEsc+'"?\\s+add\\s+secondary-ipaddress\\s+([\\d.]+/\\d+)','gm'))].map(m=>m[1]);
    const secDottedAll=[...cfg.matchAll(new RegExp('^configure(?:\\s+vlan)?\\s+"?'+nameEsc+'"?\\s+add\\s+secondary-ipaddress\\s+([\\d.]+)\\s+([\\d.]+)','gm'))].map(m=>m[1]+'/'+maskToCIDR(m[2]));
    const secondaryIps=secCidrAll.length?secCidrAll:secDottedAll;
    ifaces.push({name:'vlan.'+name,type:'svi',desc:'',mode:'',vlans:vid,nativeVlan:'',vrf:'',ip:cidr,secondaryIps,shutdown:false,member:'1',hybrid:null,vrrp:[]});
  }
  return ifaces;
}

function parseExtremeXOSLACP(cfg){
  const lacp=[]; let m;
  function exosExpandPortsV2(portStr){
    const ports=[];
    portStr.split(',').forEach(tok=>{
      const t=tok.trim();if(!t)return;
      const rangeM=t.match(/^(\d+:\d+)-(\d+:\d+)$/)||t.match(/^(\d+)-(\d+)$/);
      if(rangeM){
        const aM=rangeM[1].match(/(\d+):(\d+)/),bM=rangeM[2].match(/(\d+):(\d+)/);
        if(aM&&bM&&aM[1]===bM[1]){for(let p=parseInt(aM[2]);p<=parseInt(bM[2]);p++)ports.push(aM[1]+':'+p);}
        else if(!aM&&!bM){for(let p=parseInt(rangeM[1]);p<=parseInt(rangeM[2]);p++)ports.push(String(p));}
        else ports.push(t);
      }else{ports.push(t);}
    });
    return ports;
  }
  const shareRe=/^enable sharing\s+(\S+)\s+grouping\s+([^\n]+)/gm;
  while((m=shareRe.exec(cfg))!==null){
    const master=m[1].trim();
    const groupStr=m[2].split(/algorithm|lacp/)[0].trim();
    const members=exosExpandPortsV2(groupStr);
    // Mode from configure sharing
    const modeM=cfg.match(new RegExp('^configure sharing\\s+'+master.replace(/[.:]/g,'\\$&')+'\\s+lacp\\s+activity-mode\\s+(\\S+)','m'));
    const modeRaw=(modeM||[])[1]||'active';
    const mode=modeRaw==='active'?'Active':modeRaw==='passive'?'Passive':'Static';
    lacp.push({name:'lag'+master.replace(/:/g,'-'),mode,members,desc:''});
  }
  return lacp;
}

function parseExtremeXOSRoutes(cfg){
  const routes=[]; let m;
  // "configure iproute add X/Y GW"
  const re=/^configure iproute add\s+([\d./]+|default)\s+([\d.]+)/gm;
  while((m=re.exec(cfg))!==null){
    const dst=m[1]==='default'?'0.0.0.0/0':m[1],gw=m[2];
    routes.push({dst,gw,vrf:'',gwIsInterface:false});
  }
  // IPv6 靜態路由（2026-08-31 新增）：官方 ExtremeXOS Command Reference 查證同一個
  // "configure iproute add" 指令族支援 IPv6（"configure iproute add ipv6Netmask
  // ipv6Gateway"），與 IPv4 版本共用容器動詞、僅參數為 IPv6 CIDR＋位址，獨立正則
  // 避免與上方 IPv4 專用的點分字元類別衝突
  const re6=/^configure iproute add\s+([0-9a-f:]+\/\d+|default)\s+([0-9a-f:]+)/gim;
  while((m=re6.exec(cfg))!==null){
    if(!m[2].includes(':'))continue; // 排除已被上面 IPv4 正則處理過的行
    const dst=m[1]==='default'?'::/0':m[1],gw=m[2];
    routes.push({dst,gw,vrf:'',gwIsInterface:false});
  }
  return routes;
}

function parseExtremeXOSOSPF(cfg){
  if(!/^enable ospf/m.test(cfg)&&!/^create ospf/m.test(cfg))return[];
  const rid=(cfg.match(/^configure ospf routerid\s+([\d.]+)/m)||[])[1]||'';
  const areas={}; let m;
  // "create ospf area A.B.C.D" pre-declares area (EXOS style)
  const createAreaRe=/^create ospf area\s+([\d.]+)/gm;
  while((m=createAreaRe.exec(cfg))!==null) areas[m[1]]=areas[m[1]]||[];
  // "configure ospf add vlan NAME area A.B.C.D"
  const re=/^configure ospf add vlan\s+"?([^"\s]+)"?\s+area\s+([\d.]+)/gm;
  while((m=re.exec(cfg))!==null){
    const vname=m[1].replace(/"/g,''),area=m[2];
    if(!areas[area])areas[area]=[];
    const nameEsc=vname.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const ipM=cfg.match(new RegExp('^configure(?:\\s+vlan)?\\s+"?'+nameEsc+'"?\\s+ipaddress\\s+([\\d.]+)\\s+([\\d.]+)','m'));
    const network=ipM?ipM[1]+'/'+maskToCIDR(ipM[2]):'';
    areas[area].push({network:network||vname,wildcard:'',vlanName:vname,type:'vlan'});
  }
  const areaList=Object.entries(areas).map(([area,networks])=>({area,networks}));
  return areaList.length?[{pid:'1',routerId:rid,areas:areaList,protocol:'ospf'}]:[];
}

function parseExtremeXOSBGP(cfg){
  if(!/^enable bgp/m.test(cfg))return[];
  // 2026-07-15 對外查證 Extreme Networks 官方 ExtremeXOS Command Reference 後修正：
  // 本地 AS 號碼指令實際慣用小寫 "as-number"（原本要求大寫 "AS-number" 且無 /i，
  // 真實匯出檔可能匹配不到），改為不分大小寫比對
  const asn=(cfg.match(/^configure bgp as-number\s+(\d+)/im)||[])[1]||'';
  const rid=(cfg.match(/^configure bgp routerid\s+([\d.]+)/m)||[])[1]||'';
  const peers=[]; let m;
  // 2026-07-15 查證修正：官方文件確認建立 BGP neighbor 的指令是 "create bgp neighbor IP
  // remote-AS-number N"（動詞 create，非猜測的 "configure bgp add neighbor"），需搭配另一行
  // "enable bgp neighbor IP" 才會生效，但該啟用行不影響本解析器所需欄位故不額外檢查
  // IPv6（2026-08-18 修正）：官方文件確認真實逐字範例 "create bgp neighbor 2001:db8::1
  // remote-AS-number 64512"，與既有 IPv4 語法同一指令、僅字元類別過窄需放寬；IPv6 版本的
  // configure bgp add network 陳述式查無官方逐字語法佐證，本輪不實作，UI 端加註窄範圍警語
  const re=/^create bgp neighbor\s+(\S+)\s+remote-AS-number\s+(\d+)/gim;
  while((m=re.exec(cfg))!==null){
    const ip=m[1],peerAS=m[2];
    const descM=cfg.match(new RegExp('^configure bgp neighbor\\s+'+ip.replace(/\./g,'\\.')+'\\s+description\\s+"?([^"\\n]+)"?','m'));
    const desc=(descM||[])[1]?.trim()||'';
    peers.push({ip,as:peerAS,desc,type:peerAS===asn?'iBGP':'eBGP'});
  }
  // 2026-07-16 對外查證官方 Command Reference 確認完整語法與真實範例後新增：
  // "configure bgp add network A.B.C.D/N" 宣告要廣播的路由，networks 形狀比照
  // Comware parseBGP() 既有慣例（純字串陣列）
  const networks=[]; let nm;
  const nr=/^configure bgp add network\s+([\d./]+)/gim;
  while((nm=nr.exec(cfg))!==null)networks.push(nm[1]);
  // networks6（2026-08-31 新增）：官方 ExtremeXOS Command Reference 直接查證確認真實逐字
  // 語法 "configure bgp add network address-family ipv6-unicast IPV6/PREFIXLEN"（IPv6 版本
  // 額外多一段 address-family 限定詞，與 IPv4 裸版本不同，需獨立正則區分）
  const networks6=[]; let nm6;
  const nr6=/^configure bgp add network\s+address-family\s+ipv6-unicast\s+([0-9a-f:/]+)/gim;
  while((nm6=nr6.exec(cfg))!==null)networks6.push(nm6[1]);
  return peers.length?[{asn,routerId:rid,peers,networks,networks6}]:[];
}

function parseExtremeXOSVRRP(cfg){
  if(!/^enable vrrp|^create vrrp/m.test(cfg))return[];
  const groups=[]; let m;
  const re=/^create vrrp vlan\s+"?([^"\s]+)"?\s+vrid\s+(\d+)/gm;
  while((m=re.exec(cfg))!==null){
    const vname=m[1].replace(/"/g,''),vrid=m[2];
    const e2=vname.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    // Support both: add IP  and  add ipaddress IP
    const vipM=cfg.match(new RegExp('^configure vrrp vlan\\s+"?'+e2+'"?\\s+vrid\\s+'+vrid+'\\s+add(?:\\s+ipaddress)?\\s+([\\d.]+)','m'));
    const prioM=cfg.match(new RegExp('^configure vrrp vlan\\s+"?'+e2+'"?\\s+vrid\\s+'+vrid+'\\s+priority\\s+(\\d+)','m'));
    // 2026-07-15 對外查證 Extreme Networks 官方文件後修正：preempt 是旗標式關鍵字
    // （"configure vrrp vlan NAME vrid N preempt" 或 "dont-preempt"），不是原本猜測的
    // "preempt on|off" 帶值語法；EXOS 預設本來就是 preempt 啟用，故只有明確出現
    // dont-preempt 才視為 false，找不到任一關鍵字時維持預設 true
    const dontPreM=new RegExp('^configure vrrp vlan\\s+"?'+e2+'"?\\s+vrid\\s+'+vrid+'\\s+dont-preempt\\s*$','m').test(cfg);
    const vip=(vipM||[])[1]||'';
    const priority=(prioM||[])[1]||'100';
    const preempt=!dontPreM;
    // vip6（2026-08-31 新增）：官方 ExtremeXOS「VRRP Address Support for IPv6」文件確認真實
    // 逐字語法 "configure vrrp vlan NAME vrid N add virtual-link-local ADDR"——與 IPv4 版本
    // 關鍵字不同（virtual-link-local，非 add ipaddress），且官方文件明載該位址必須落在
    // FE80::/64 link-local 子網（非任意全域 IPv6 位址），屬本工具目前唯一一個 vip6 為
    // link-local 位址的廠牌，非查證疏漏
    const vip6M=cfg.match(new RegExp('^configure vrrp vlan\\s+"?'+e2+'"?\\s+vrid\\s+'+vrid+'\\s+add\\s+virtual-link-local\\s+(\\S+)','im'));
    const vip6=(vip6M||[])[1]||'';
    groups.push({vrid,interface:'vlan.'+vname,vip,vip6,priority,preempt,authMode:'',trackIf:'',trackReduced:'',version:'2'});
  }
  return groups;
}

function parseExtremeXOSUsers(cfg){
  const users=[]; const seen=new Set(); let m;
  // Format A: create account ROLE "NAME" encrypted "HASH"  (name quoted separately)
  const reA=/^create account\s+(\w+)\s+"([^"]+)"\s+encrypted\s+"?([^"\s]+)"?/gm;
  while((m=reA.exec(cfg))!==null){
    const role=m[1],name=m[2],hash=m[3];
    if(seen.has(name))continue; seen.add(name);
    const{pwdType,pwdWeak}=exosPwdType(hash);
    users.push({name,role,service:'ssh/console',hasPwd:true,pwdType,pwdWeak});
  }
  // Format B: create account ROLE NAME encrypted "HASH"  (name unquoted before encrypted)
  const reB=/^create account\s+(\w+)\s+(\S+)\s+encrypted\s+"?([^"\s]+)"?/gm;
  while((m=reB.exec(cfg))!==null){
    const role=m[1],name=m[2],hash=m[3];
    if(name==='encrypted')continue; // skip if name was accidentally 'encrypted'
    if(seen.has(name))continue; seen.add(name);
    const{pwdType,pwdWeak}=exosPwdType(hash);
    users.push({name,role,service:'ssh/console',hasPwd:true,pwdType,pwdWeak});
  }
  // Format C: create account ROLE encrypted "HASH"  (no separate name — use role as name)
  const reC=/^create account\s+(\w+)\s+encrypted\s+"?([^"\s]+)"?/gm;
  while((m=reC.exec(cfg))!==null){
    const role=m[1],name=role,hash=m[2];
    if(seen.has(name))continue; seen.add(name);
    const{pwdType,pwdWeak}=exosPwdType(hash);
    users.push({name,role,service:'ssh/console',hasPwd:true,pwdType,pwdWeak});
  }
  // Plain (no encrypted keyword)
  const reP=/^create account\s+(\w+)\s+"?(\S+?)"?\s*$/gm;
  while((m=reP.exec(cfg))!==null){
    const name=m[2]==='encrypted'?m[1]:m[2];
    if(seen.has(name))continue; seen.add(name);
    users.push({name,role:m[1],service:'ssh/console',hasPwd:false,pwdType:'none',pwdWeak:true});
  }
  return users;
}
function exosPwdType(hash){
  if(!hash)return{pwdType:'none',pwdWeak:true};
  if(hash.startsWith('$6$')) return{pwdType:'sha512',pwdWeak:false};
  if(hash.startsWith('$2y$'))return{pwdType:'bcrypt',pwdWeak:false};
  if(hash.startsWith('$1$')) return{pwdType:'md5',pwdWeak:true};
  if(hash.startsWith('$5$')) return{pwdType:'sha256',pwdWeak:false};
  return{pwdType:'hash',pwdWeak:false};
}

function parseExtremeXOSDHCP(cfg){
  const pools=[]; let m;

  // 2026-07-16 對外查證官方 ExtremeXOS Command Reference/User Guide 與真實設定範例後修正
  // 三處誤植語法（原本皆為未查證的臆測寫法）：
  // - 啟用指令原本誤用 "enable dhcp vlan NAME"，該指令實際語意是讓 VLAN 自己以 DHCP
  //   Client 身分取得位址，並非啟用 DHCP Server；真正啟用 Server 的指令是逐 port 啟用的
  //   "enable dhcp ports <port-list> vlan NAME"
  // - lease-time 原本誤植為 "dhcp-options lease-time N"（不存在的子選項），真實是獨立指令
  //   "dhcp-lease-timer N"
  // - dns-server 原本誤用逗號列表，真實需要 primary/secondary 關鍵字各自一行
  // EXOS DHCP Server (per-VLAN，已查證真實語法):
  // configure vlan NAME add ports P1,P2 tagged|untagged
  // enable dhcp ports P1,P2 vlan NAME
  // configure vlan NAME dhcp-address-range LOW - HIGH
  // configure vlan NAME dhcp-options default-gateway GW
  // configure vlan NAME dhcp-options dns-server primary DNS1
  // configure vlan NAME dhcp-options dns-server secondary DNS2
  // configure vlan NAME dhcp-lease-timer N
  const dhcpVlans=new Set();
  const dhcpEnabledRe=/^enable dhcp ports\s+\S+\s+vlan\s+"?([^"\s]+)"?/gm;
  while((m=dhcpEnabledRe.exec(cfg))!==null) dhcpVlans.add(m[1].replace(/"/g,''));
  // Also collect from dhcp-address-range lines even if no enable line
  const dhcpRangeRe=/^configure vlan\s+"?([^"\s]+)"?\s+dhcp-address-range/gm;
  while((m=dhcpRangeRe.exec(cfg))!==null) dhcpVlans.add(m[1].replace(/"/g,''));

  for(const vname of dhcpVlans){
    const nameEsc=vname.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    // Range: "configure vlan NAME dhcp-address-range LOW - HIGH"
    const rangeM=cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+dhcp-address-range\\s+([\\d.]+)\\s*-\\s*([\\d.]+)','m'));
    const low=(rangeM||[])[1]||'',high=(rangeM||[])[2]||'';
    // Gateway
    const gwM=cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+dhcp-options\\s+default-gateway\\s+([\\d.]+)','m'));
    const gw=(gwM||[])[1]||'';
    // DNS: primary/secondary 各自一行
    const dnsPriM=cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+dhcp-options\\s+dns-server\\s+primary\\s+([\\d.]+)','m'));
    const dnsSecM=cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+dhcp-options\\s+dns-server\\s+secondary\\s+([\\d.]+)','m'));
    const dns=[(dnsPriM||[])[1],(dnsSecM||[])[1]].filter(Boolean);
    // Lease time (獨立指令 dhcp-lease-timer，非 dhcp-options 子選項)
    const leaseM=cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+dhcp-lease-timer\\s+(\\d+)','m'));
    const leaseSec=parseInt((leaseM||[])[1]||'0');
    const lease=leaseSec?Math.floor(leaseSec/3600)+'h':'';
    // 2026-07-24 對外查證官方 ExtremeXOS Command Reference 後新增：TFTP/Bootfile/NTP 皆掛在
    // 既有 dhcp-options 通用 numbered option 機制底下（非具名關鍵字），"code 66/150 ipaddress"
    // 為 TFTP 伺服器（150 優先，66 備援）、"code 67 string" 為開機檔名（Option67）、
    // "code 42 ipaddress" 為 NTP(Option42)；next-server(BOOTP siaddr 表頭欄位)查無官方 CLI
    // 對應項目，不臆測
    const bootM=cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+dhcp-options\\s+code\\s+67\\s+string\\s+"?([^"\\n]+)"?','m'));
    const bootFile=(bootM||[])[1]||'';
    const nextM=cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+dhcp-options\\s+code\\s+150\\s+ipaddress\\s+([\\d.]+)','m'))||
                 cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+dhcp-options\\s+code\\s+66\\s+ipaddress\\s+([\\d.]+)','m'));
    const nextServer=(nextM||[])[1]||'';
    const ntpM=cfg.match(new RegExp('^configure vlan\\s+"?'+nameEsc+'"?\\s+dhcp-options\\s+code\\s+42\\s+ipaddress\\s+([\\d.]+)','m'));
    const ntpServer=(ntpM||[])[1]||'';
    // Derive network from IP
    const ipM=cfg.match(new RegExp('^configure(?:\\s+vlan)?\\s+"?'+nameEsc+'"?\\s+ipaddress\\s+([\\d.]+)\\s+([\\d.]+)','m'));
    const network=ipM?ipM[1]+'/'+maskToCIDR(ipM[2]):'';
    // VLAN id
    const vidM=cfg.match(new RegExp('^create vlan\\s+"?'+nameEsc+'"?\\s+tag\\s+(\\d+)','m'));
    const vid=(vidM||[])[1]||'';
    pools.push({name:vname,network,range:low&&high?low+'-'+high:'',gateway:gw,
      dns,lease,excluded:'',bootFile,nextServer,ntpServer,interface:'vlan.'+vname,type:'server'});
  }

  // DHCP Relay: configure bootprelay vlan NAME add IP（2026-07-16 查證修正關鍵字順序，
  // 原本誤寫成 "configure bootprelay add IP vlan NAME"）
  // 2026-07-24 對外查證官方文件後新增：Option82 為全域指令（非逐 VLAN），且與 DHCP Snooping
  // 無關、不需先啟用 snooping——"configure bootprelay dhcp-agent information option"（裸行，
  // 與帶參數的 policy/circuit-id/remote-id/check 變體用行尾錨點區分）
  const option82=/^configure bootprelay dhcp-agent information option\s*$/m.test(cfg);
  const relayRe=/^configure bootprelay vlan\s+"?([^"\s]+)"?\s+add\s+([\d.]+)/gm;
  while((m=relayRe.exec(cfg))!==null){
    const vname=m[1].trim().replace(/"/g,'');
    pools.push({name:vname,network:'',range:'',gateway:'',dns:[],lease:'',
      excluded:'',interface:'vlan.'+vname,type:'relay',relayServer:m[2],option82});
  }

  return pools;
}

function parseExtremeXOSStack(cfg){
  if(!/^enable stacking/m.test(cfg))return null;
  const members=[]; const seen=new Set(); let m;
  // 2026-07-16 對外查證官方 Command Reference 後修正三處未查證的臆測語法：
  // - "master-priority" 關鍵字查無任何官方來源，真實只有 "priority"（已移除該猜測前綴）
  // - "configure slot N module MODEL" 是機箱式產品（如 BlackDiamond）的 line-card 佈建
  //   指令，並非獨立堆疊成員（Summit 系列）的型號宣告——真實堆疊成員型號為自動偵測，
  //   非設定檔可宣告內容，故不再誤用此指令，model 固定回傳 '—'（查無型號）
  const prioRe=/^configure stacking slot\s+(\d+)\s+priority\s+(\d+)/gm;
  while((m=prioRe.exec(cfg))!==null){
    if(seen.has(m[1]))continue; seen.add(m[1]);
    members.push({id:m[1],priority:parseInt(m[2]),role:'',model:'—',serial:''});
  }
  if(!members.length)return null;
  members.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  // Master: highest priority, OR explicit master-capability, OR slot 1 if all prio=0
  const masterSlotM=cfg.match(/^configure stacking slot\s+(\d+)\s+master-capability\s+on/m);
  const masterSlot=(masterSlotM||[])[1]||'';
  if(masterSlot){
    members.forEach(x=>{x.role=x.id===masterSlot?'Master':'Standby';});
  }else{
    const maxPrio=Math.max(...members.map(x=>x.priority));
    members.forEach(x=>{x.role=(maxPrio>0?x.priority===maxPrio:x.id==='1')?'Master':'Standby';});
  }
  // "stack port N/M" \u67e5\u7121\u4efb\u4f55\u5b98\u65b9\u6587\u4ef6\u6216\u793e\u7fa4\u7bc4\u4f8b\u4f50\u8b49\u5b58\u5728\uff0c\u771f\u5be6\u5806\u758a\u57e0\u9078\u64c7\u6307\u4ee4\u662f
  // "configure stacking-support stack-ports"\uff0c\u8a9e\u610f\u8207\u6b64\u8655\u300c\u5169\u7aef slot \u9023\u7d50\u300d\u7684\u62d3\u6a38\u63a8\u5c0e
  // \u5b8c\u5168\u4e0d\u540c\u3001\u7121\u6cd5\u76f4\u63a5\u66ff\u63db\uff0c\u6545\u4e0d\u518d\u7de8\u9020 links \u8cc7\u6599\uff0c\u56fa\u5b9a\u56de\u50b3\u7a7a\u9663\u5217
  return{type:'ExtremeStack',members,links:[]};
}

// ExtremeXOS QoS（本次新增，2026-07-19 對外查證官方 ExtremeXOS Command Reference/User
// Guide 確認）：8 個 egress QoS profile QP1（最低）～QP8（最高），QP1/QP8 為預設已存在，
// QP2-QP7 須先 "create qosprofile QPn" 才能使用，"configure qosprofile QPn {minbw N}
// {maxbw N}" 設定頻寬百分比；DSCP 對應表 "configure diffserv examination code-point N
// qosprofile QPn"；逐 port 指定 "configure ports PORT_LIST qosprofile QPn" 與啟用
// DSCP 分類 "enable diffserv examination ports PORT_LIST" 為兩個獨立可選開關。與 Cisco
// policy-map/class 語意完全不同，不沿用共用 parseQoS() 的 {policy,cls,action,rate,burst}
// 形狀，改用專屬新形狀（比照 Brocade parseBrocadeQoS() 前例）
function parseExtremeQoS(cfg){
  const profiles=[];
  let m;
  const cpRe=/^configure qosprofile\s+(QP\d)\s+(?:minbw\s+(\d+)\s*)?(?:maxbw\s+(\d+)\s*)?/gm;
  while((m=cpRe.exec(cfg))!==null){ if(m[2]||m[3]) profiles.push({name:m[1],minbw:m[2]||'',maxbw:m[3]||''}); }
  const dscpMap=[];
  const dsRe=/^configure diffserv examination code-point\s+(\d+)\s+qosprofile\s+(QP\d)/gm;
  while((m=dsRe.exec(cfg))!==null) dscpMap.push({codePoint:m[1],profile:m[2]});
  const portMap={};
  const getP=p=>{if(!portMap[p])portMap[p]={port:p,profile:'',diffservExam:false};return portMap[p];};
  const pqRe=/^configure ports\s+([^\n]+?)\s+qosprofile\s+(QP\d)/gm;
  while((m=pqRe.exec(cfg))!==null){
    m[1].split(',').map(s=>s.trim()).filter(Boolean).forEach(p=>{getP(p).profile=m[2];});
  }
  const deRe=/^enable diffserv examination ports\s+([^\n]+)$/gm;
  while((m=deRe.exec(cfg))!==null){
    m[1].split(',').map(s=>s.trim()).filter(Boolean).forEach(p=>{getP(p).diffservExam=true;});
  }
  return {profiles, dscpMap, ports:Object.values(portMap)};
}

// Breakout：獨立頂層指令 `configure ports <port_list> partition [1x100G|1x40G|2x50G|4x10G|4x25G]`
// （官方 ExtremeXOS Command Reference 已查證）。子埠命名是「QSFP bank 最低編號埠起遞增」，
// 非附加尾碼，無通用公式可從介面名稱反推母子關係（每台裝置的 bank 分配不同），故本輪
// MVP 範圍僅支援啟用指令本身 round-trip（model.breakouts[]），不嘗試偵測 interfaces[]
// 上的 breakoutChild/breakoutParent（比照專案「查無佐證不猜測」慣例，非漏做）
function parseExtremeBreakout(cfg){
  const breakouts=[];
  const re=/^configure ports\s+(\S+)\s+partition\s+(\S+)/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    breakouts.push({parentPort:m[1], mode:m[2], vendor:'extreme', raw:m[0]});
  }
  return breakouts;
}

function parseExtremeXOS(cfg){
  const stk=parseExtremeXOSStack(cfg);
  return{
    sys:        parseExtremeXOSSysInfo(cfg),
    irf:null, stack:stk,
    vlans:      parseExtremeXOSVLANs(cfg),
    interfaces: parseExtremeXOSInterfaces(cfg),
    breakouts:  parseExtremeBreakout(cfg),
    lacp:       parseExtremeXOSLACP(cfg),
    routes:     parseExtremeXOSRoutes(cfg),
    vrfs:[], dhcp: parseExtremeXOSDHCP(cfg),
    users:      parseExtremeXOSUsers(cfg),
    ospf:       parseExtremeXOSOSPF(cfg),
    bgp:        parseExtremeXOSBGP(cfg),
    vrrp:       parseExtremeXOSVRRP(cfg),
    rip:[], vxlan:null,
    qos:        parseExtremeQoS(cfg),
    vendor:'extreme'
  };
}


// ════════════════════════════════════════════════════════════
//  Brocade FastIron (ICX) / NetIron Parser
//  CLI style: "vlan N by port", "tagged"/"untagged" port lists,
//             "stack unit N", verb-based commands
// ════════════════════════════════════════════════════════════

