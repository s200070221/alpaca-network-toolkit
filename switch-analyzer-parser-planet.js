// ═ Planet Technology SGS-6341 系列 Parser ═
// 查證來源：官方 SGS-6341 Series Command Guide_v2.0.pdf（直接 fetch 官方 PDF 逐字查證）。
// CLI 骨架整體近似 Cisco IOS Classic（hostname／switchport mode），VLAN 設定則是
// Comware 式子模式（`vlan WORD` 進入子模式，WORD 可用 `;`/`-` 連寫多個 VLAN ID，
// 不像 Cisco 逐一 `vlan N`/`name X`）；介面命名 `ethernet 1/0/5`（slot/port 格式，
// ethernet 與數字之間有空格，與 Dell OS10 `ethernet1/1/1`〔無空格〕不同）。
// ACL（numbered IP，100-199 標準/100-299 延伸）／QoS（policy-map/class，含 drop 動作）／
// STP（含逐 MSTP instance priority、bpduguard/rootguard 裸關鍵字）／DHCP（server+relay，
// "network-address" 關鍵字）／Users（本機帳號，沿用 parseCiscoUsers()）皆已於 2026-08-27
// 對外查證官方文件後補上。**具名擴充 MAC ACL（`mac-access-list extended <name>`，§47.16/
// 47.22）已於 2026-08-28（續4）對外查證新增**，見 `_parseMacACLPlanet()`；明確排除數字型
// MAC ACL（標準 700-799／擴充 1100-1199，含最多 4 組 offset/length/value payload 比對，
// §47.5/47.7）與 802.3/EthernetII tagged/untagged frame-type 關鍵字變體，欄位複雜度高、
// real-world 使用率低，非本輪範圍。
function parsePlanetSysInfo(cfg){
  return{
    hostname:(cfg.match(/^hostname\s+(\S+)/m)||[])[1]||'unknown',
    version:(cfg.match(/version\s+(\S+)/)||[])[1]?.trim()||'',
    platform:'',
  };
}

// VLAN WORD 展開："3;5-7;8" → ['3','5','6','7','8']（官方語法僅記載 `;` 分隔多筆、`-`
// 表示範圍，不支援逗號；非數字 token（如 "all"）直接略過，不猜測語意）
function expandPlanetVlanWord(word){
  const ids=[];
  (word||'').split(';').forEach(part=>{
    part=part.trim();
    if(!part)return;
    const rangeM=part.match(/^(\d+)-(\d+)$/);
    if(rangeM){
      const from=parseInt(rangeM[1],10),to=parseInt(rangeM[2],10);
      for(let i=from;i<=to;i++)ids.push(String(i));
    }else if(/^\d+$/.test(part)){
      ids.push(part);
    }
  });
  return ids;
}

// VLAN 清單：僅能從 `vlan WORD` 宣告行取得 ID 集合，官方文件查證範圍內查無對應的
// VLAN 命名（name）指令，故 name 欄位固定空字串（不猜測語法）
function parsePlanetVLANs(cfg){
  const ids=new Set();
  const re=/^vlan\s+([\d;\-]+)\s*$/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    expandPlanetVlanWord(m[1]).forEach(id=>ids.add(id));
  }
  return [...ids].sort((a,b)=>parseInt(a,10)-parseInt(b,10)).map(id=>({id,name:'',ipSubnets:[]}));
}

// Hybrid：官方語法 `switchport hybrid allowed vlan {WORD|all|add WORD|except WORD|
// remove WORD} {tag|untag}`——tag/untag 關鍵字在「WORD」之後（與 Ruijie 的
// tagged/untagged 前綴語法相反位置），故不可重用 parseRuijieHybrid()。add/except/裸
// WORD 皆視為對該 tag/untag 狀態新增宣告（同一狀態內多筆宣告本來就該疊加，非跨行取
// 最後一筆整批取代——與 trunk 的取代語意不同，因為這裡「tag」「untag」已經是兩個獨立
// 集合，不像 trunk 只有單一集合需要判斷取代或累加）；remove 從對應狀態集合中刪除。
// "all" 非數字 token，expandPlanetVlanWord() 會略過，屬已知限制（無法解析"all"語意）
function parsePlanetHybrid(blk){
  const pvid=(blk.match(/switchport hybrid native vlan\s+(\d+)/)||[])[1]||'';
  const untagged=new Set(),tagged=new Set();
  const opRe=/switchport hybrid allowed vlan\s+(?:(add|except|remove)\s+)?(\S+)\s+(tag|untag)/g;
  let m;
  while((m=opRe.exec(blk))!==null){
    const op=m[1],word=m[2],tu=m[3];
    const target=tu==='tag'?tagged:untagged;
    const ids=expandPlanetVlanWord(word);
    if(op==='remove')ids.forEach(id=>target.delete(id));
    else ids.forEach(id=>target.add(id));
  }
  return{pvid,untagged:[...untagged],tagged:[...tagged],hasIPSub:false,vlanMaps:[],hasQinQ:false};
}

function parsePlanetInterfaces(cfg){
  const ifaces=[];
  const blocks=cfg.split(/^interface\s+/m).slice(1);
  for(const blk of blocks){
    const lines=blk.split('\n');
    const name=lines[0].trim();
    const body=lines.slice(1).join('\n');
    const desc=(body.match(/^\s*description\s+(.+)/m)||[])[1]?.trim()||'';
    const shutdown=/^\s*shutdown\s*$/m.test(body)&&!/no shutdown/.test(body);

    // SVI: "interface vlan N"
    if(/^vlan\s+\d+\s*$/i.test(name)){
      const vid=(name.match(/\d+/)||[])[0]||'';
      // Secondary IP：官方語法原生支援 `secondary` 關鍵字（`ip address A.B.C.D M.M.M.M
      // [secondary]`），完整收集全部次要IP（非僅取第一筆）
      const ipLines=[...body.matchAll(/^\s*ip address\s+(\S+)\s+(\S+)(\s+secondary)?/gm)];
      const primary=ipLines.find(x=>!x[3]);
      const ip=primary?primary[1]+'/'+cidrFromMask(primary[2]):'';
      const secondaryIps=ipLines.filter(x=>x[3]).map(x=>x[1]+'/'+cidrFromMask(x[2]));
      ifaces.push({name:'vlan '+vid,type:'svi',desc,ip,ip6:'',secondaryIps,mode:'',vlans:vid,nativeVlan:'',vrf:'',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }

    // 實體埠（ethernet slot/port）與 port-channel 聚合介面共用同一段解析；聚合介面
    // 成員埠的 port-group 宣告由共用 parseLACP() 的 planet 分支獨立處理
    const memberMatch=name.match(/^ethernet\s+(\d+)\//i);
    const member=memberMatch?memberMatch[1]:'1';
    let mode='',vlans='',nativeVlan='',hybrid=null;
    if(/switchport mode\s+trunk/.test(body)){
      mode='trunk';
      // switchport trunk allowed vlan {WORD|all|add WORD|except WORD|remove WORD}：
      // 比照 Ruijie/Netgear 既有慣例（同一累加式語法曾在真實範例踩過雷），優先採最後
      // 一次出現的「整批取代」形式（裸 WORD／all／except WORD），add/remove 為純增量
      // 修改，若全篇只有 add/remove（無基準清單可重建）則保守回傳 'all'
      const vlanLines=[...body.matchAll(/switchport trunk allowed vlan\s+(?:(add|remove|except)\s+)?(\S+)/g)];
      const fullList=[...vlanLines].reverse().find(x=>x[1]==='except'||!x[1]);
      vlans=fullList?(fullList[1]==='except'?`except ${fullList[2]}`:fullList[2]):'all';
      nativeVlan=(body.match(/switchport trunk native vlan\s+(\d+)/)||[])[1]||'1';
    }else if(/switchport mode\s+access/.test(body)){
      mode='access';
      vlans=(body.match(/switchport access vlan\s+(\d+)/)||[])[1]||'1';
    }else if(/switchport mode\s+hybrid/.test(body)){
      mode='hybrid';
      hybrid=parsePlanetHybrid(body);
      vlans=[...hybrid.untagged,...hybrid.tagged].filter((v,i,a)=>a.indexOf(v)===i).join(' ');
      nativeVlan=hybrid.pvid;
    }
    ifaces.push({name,type:'physical',desc,mode,vlans:(vlans||'').toString().trim(),nativeVlan,vrf:'',ip:'',ip6:'',secondaryIps:[],shutdown,member,hybrid,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
  }
  return ifaces;
}

// 靜態路由：官方語法同時支援「prefix + dotted mask + gateway」與「prefix/prefixlen +
// gateway」兩種寫法，gateway 可為 IP 或介面名稱（如 "ethernet 1/0/1"，slot/port 命名
// 含空格，比照 Ruijie parseRuijieRoutes() 既有的「介面名稱含空格」處理手法，避免下一跳
// 介面被單一 \S+ token 截斷）
function parsePlanetRoutes(cfg){
  const routes=[];
  const re=/^ip route\s+(.+)$/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const tokens=m[1].trim().split(/\s+/);
    let idx=0;
    let dst=tokens[idx++];
    if(!dst.includes('/')&&tokens[idx]&&/^\d+\.\d+\.\d+\.\d+$/.test(tokens[idx])){
      dst=dst+'/'+cidrFromMask(tokens[idx]);
      idx++;
    }
    const restTokens=tokens.slice(idx);
    let gw='',gwIsInterface=false;
    if(/^(ethernet|vlan|port-channel)$/i.test(restTokens[0]||'')&&restTokens[1]){
      gw=`${restTokens[0]} ${restTokens[1]}`;
      gwIsInterface=true;
    }else{
      gw=restTokens[0]||'';
      gwIsInterface=!!gw&&!/^\d+\.\d+\.\d+\.\d+$/.test(gw);
    }
    if(dst&&gw)routes.push({dst,gw,vrf:'',gwIsInterface});
  }
  return routes;
}

// prefix-length → wildcard mask（cidrFromMask 是反方向：dotted mask → prefix-length，
// 定義於 switch-analyzer-parser-comware.js；OSPF area network 若用 CIDR 寫法需要轉換
// 成 wildcard 才能塞進與其餘廠牌共用的 area.networks {network,wildcard} 欄位形狀）
function planetCidrToWildcard(len){
  const n=parseInt(len,10);
  if(isNaN(n)||n<0||n>32)return '0.0.0.0';
  if(n===0)return '255.255.255.255';
  const bits=(0xffffffff<<(32-n))>>>0;
  const wc=(~bits)>>>0;
  return [24,16,8,0].map(s=>(wc>>>s)&0xff).join('.');
}

// OSPF：`router ospf <process_id> <vrf-name>`（vrf-name 選填，非其餘廠牌常見的獨立
// `vrf`關鍵字宣告，本工具 OSPF 表單無 VRF 概念故不保留此欄位，僅正確跳過此 token
// 避免污染 area 解析）；`ospf router-id <address>`（關鍵字為 "ospf router-id"，非
// Cisco 的裸 "router-id"）；network 同時支援 CIDR 與 wildcard 兩種寫法
function parsePlanetOSPF(cfg){
  const processes=[];
  const re=/^router ospf\s+(\d+)(?:\s+(\S+))?\s*\n([\s\S]*?)(?=^router\s|^ip route\s|(?![\s\S]))/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const pid=m[1],body=m[3];
    const rid=(body.match(/^\s*ospf router-id\s+(\S+)/m)||[])[1]||'';
    const areas=[];
    const ar=/^\s*network\s+(\S+)(?:\s+(\S+))?\s+area\s+(\S+)/gm;
    let am;
    while((am=ar.exec(body))!==null){
      let network=am[1],wildcard=am[2]||'';
      if(network.includes('/')){
        const [net,len]=network.split('/');
        network=net;
        wildcard=planetCidrToWildcard(len);
      }
      let area=areas.find(a=>a.area===am[3]);
      if(!area){area={area:am[3],networks:[]};areas.push(area);}
      area.networks.push({network,wildcard});
    }
    processes.push({pid,routerId:rid,areas});
  }
  return processes;
}

// BGP：network 一律是 CIDR 單一 token（`network <ip-address/M> [route-map WORD]
// [backdoor]`，與 Cisco 的「network + 選填 mask」兩種寫法不同）；官方查證範圍內查無
// router-id 對應指令，routerId 固定空字串（不猜測語法）
function parsePlanetBGP(cfg){
  const bgpList=[];
  const re=/^router bgp\s+(\d+)([\s\S]*?)(?=^router\s|^ip route\s|(?![\s\S]))/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const asn=m[1],body=m[2];
    const peers=[];
    const pr=/^\s*neighbor\s+(\S+)\s+remote-as\s+(\d+)/gm;
    let pm;
    while((pm=pr.exec(body))!==null){
      const ip=pm[1],peerAs=pm[2];
      const descM=body.match(new RegExp('neighbor\\s+'+ip.replace(/\./g,'\\.')+'\\s+description\\s+([^\\n]+)'));
      peers.push({ip,as:peerAs,desc:descM?descM[1].trim():'',type:peerAs===asn?'iBGP':'eBGP'});
    }
    const nets=[];
    const nr=/^\s*network\s+(\S+)/gm;
    let nm;
    while((nm=nr.exec(body))!==null)nets.push(nm[1]);
    bgpList.push({asn,routerId:'',peers,networks:nets});
  }
  return bgpList;
}

// VRRP：全域實例模式，與其餘廠牌「巢狀在 interface 區塊內」完全不同架構——
// `router vrrp <vrid>` 先建立全域虛擬路由器，其子模式內用 `interface {IFNAME|Vlan
// <ID>}` 綁定介面，再用 virtual-ip/priority/preempt-mode 設定細節。SVI 自己的 IP
// （`ip address`）屬於該介面自己的設定（見 parsePlanetInterfaces()），與 VRRP 區塊
// 完全分開宣告，故需傳入已解析好的 interfaces 陣列反查回填 ip 欄位（比照
// switch_config_generator 匯入既有設定檔時的既有 VRRP↔SVI 反查手法）。查證範圍僅涵蓋
// 綁定 VLAN 介面的官方範例，物理埠綁定 VRRP 查無官方逐字範例佐證，本輪不處理
// （vlanId 留空、不產生記錄）
function parsePlanetVRRP(cfg, interfaces){
  const groups=[];
  const re=/^router vrrp\s+(\d+)([\s\S]*?)(?=^router\s|^ip route\s|(?![\s\S]))/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const vrid=m[1],body=m[2];
    const ifaceM=body.match(/^\s*interface\s+(\S+(?:\s+\S+)?)\s*$/m);
    const ifaceName=ifaceM?ifaceM[1].trim():'';
    const vlanIdM=ifaceName.match(/^vlan\s+(\d+)/i);
    if(!vlanIdM)continue;
    const vlanId=vlanIdM[1];
    const vip=(body.match(/^\s*virtual-ip\s+(\S+)/m)||[])[1]||'';
    const priority=(body.match(/^\s*priority\s+(\d+)/m)||[])[1]||'100';
    const preemptM=body.match(/^\s*preempt-mode\s+(true|false)/m);
    const preempt=preemptM?preemptM[1]==='true':true;
    const svi=(interfaces||[]).find(i=>i.name==='vlan '+vlanId);
    const ip=svi?svi.ip:'';
    if(vip)groups.push({vrid,vlanId,interface:ifaceName,ip,vip,priority,preempt,authMode:'',authKey:'',trackIf:'',trackReduced:'',version:'2'});
  }
  return groups;
}

function parsePlanet(cfg){
  const sys=parsePlanetSysInfo(cfg);
  const vlans=parsePlanetVLANs(cfg);
  const interfaces=parsePlanetInterfaces(cfg);
  const routes=parsePlanetRoutes(cfg);
  const ospf=parsePlanetOSPF(cfg);
  const bgp=parsePlanetBGP(cfg);
  const vrrp=parsePlanetVRRP(cfg,interfaces);
  // Users：`username NAME [privilege N] [password {0|7} PWD]`（官方 SGS-6341 Command Guide
  // 已查證），parseCiscoUsers() 本來就同時接受 secret/password 兩種關鍵字、0/7 密碼等級語意
  // 與此完全吻合，Ruijie 已逐字重用同一函式，比照辦理不寫新解析邏輯。已知既有限制（非本輪
  // 引入，Cisco/Ruijie 共用）：沒有明確 privilege 子句的帳號會被靜默略過。
  const users=parseCiscoUsers(cfg);
  // MAC ACL 為 Planet 專屬資料形狀（見 _parseMacACLPlanet() 註解），不進共用 ACL dispatcher，
  // 比照 Brocade parseBrocade() 內嵌 qos:parseBrocadeQoS(cfg) 的既有慣例直接內嵌
  const macAcl=_parseMacACLPlanet(cfg);
  return{sys,irf:null,stack:null,vlans,interfaces,routes,vrfs:[],users,ospf,bgp,rip:[],vrrp,vxlan:null,vendor:'planet',breakouts:[],macAcl};
}

// DHCP：官方語法與 Cisco 幾乎相同，唯一差異是 network 關鍵字為 "network-address"（非 Cisco
// 裸 "network"）；刻意不併入既有 cisco||ruijie 共用分支，避免第三家的細微差異污染既有兩家。
// default-router／dns-server／lease／relay（ip helper-address 逐介面掃描）皆與 Cisco 語法
// 逐字相同，直接沿用相同寫法；bootFile/nextServer/ntpServer/option82 等 Cisco 擴充欄位本輪
// 未查得 Planet 官方佐證，不猜測，維持共用 DHCP 資料形狀的基本欄位集合。
function parsePlanetDHCP(cfg){
  const pools=[];
  const re=/ip dhcp pool\s+(\S+)\s*\n([\s\S]*?)(?=^ip dhcp pool|^interface|(?![\s\S]))/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const name=m[1], body=m[2];
    const network=(body.match(/network-address\s+([^\n]+)/)||[])[1]||'';
    const gateway=(body.match(/default-router\s+([^\n]+)/)||[])[1]||'';
    const dns=(body.match(/dns-server\s+([^\n]+)/)||[])[1]||'';
    const lease=(body.match(/lease\s+([^\n]+)/)||[])[1]?.trim()||'';
    pools.push({name,network:network.trim(),gateway:gateway.trim(),dns:dns.trim(),
      range:'',excluded:'',lease,interface:'',type:'server'});
  }
  cfg.split(/^interface\s+/m).slice(1).forEach(blk=>{
    const ifname=blk.split('\n')[0].trim();
    const helpers=[...blk.matchAll(/^\s*ip helper-address\s+(\S+)/gm)].map(x=>x[1]);
    helpers.forEach(srv=>pools.push({name:'relay:'+ifname,network:'',gateway:'',dns:'',
      range:'',excluded:'',lease:'',interface:ifname,type:'relay',relayServer:srv}));
  });
  return pools;
}

// ACL：官方 SGS-6341 Command Guide 直接 fetch 逐字查證（§47.3/47.4/47.15）。Standard（100-199）
// 與 Extended（100-299）共用同一個數字空間，號碼本身無法區分兩者（官方語法明載）；改依規則
// 列開頭 token 判斷——Extended 第一個 token 必是協定關鍵字（icmp/igmp/tcp/udp/eigrp/gre/igrp/
// ipinip/ip/ospf/純數字協定碼），Standard 直接接來源 token 無協定關鍵字。來源 token 為
// any-source／host-source <ip>／<ip> <mask>；官方文件本身的 Extended 範例（§47.3 Example：
// `access-list 110 deny icmp any any-destination`）用裸 "any"（非 "any-source"），故來源比對
// 同時接受兩種寫法，比官方語法定義本身更寬鬆但更貼近實際可能出現的設定檔。目的端 token 為
// any-destination／host-destination <ip>／<ip> <mask>，Standard ACL 無目的端。tcp/udp 的
// d-port <N> 單一埠號有查得語法（§47.3），僅擷取此欄位；range 形式與 precedence/tos/
// time-range 選項因共用 ACL 表單無對應欄位，解析時跳過不干擾位址判斷、不儲存。
// 介面套用語法 `{ip|mac|mac-ip|ipv6} access-group <name> {in|out} [traffic-statistic]`
// （§47.15，官方範例：`Switch(Config-If-Ethernet1/0/1)#ip access-group aaa in`）。
// MAC ACL（具名擴充 `mac-access-list extended`）欄位形狀與此處 IP ACL 表單模型
// （`{seq,action,protocol,src,dst,dstPort,remark}`）不相容，改用獨立資料形狀（比照
// RouterOS/Brocade QoS 既有的「專屬 schema」先例），見下方 `_parseMacACLPlanet()`。
function _parseACLPlanet(cfg){
  const acls=[]; const numG={};
  const PROTO_RE=/^(icmp|igmp|tcp|udp|eigrp|gre|igrp|ipinip|ip|ospf|\d{1,3})$/i;
  const srcTok=(parts,i)=>{
    if(/^(any-source|any)$/i.test(parts[i]||''))return{val:'any',next:i+1};
    if(/^host-source$/i.test(parts[i]||''))return{val:'host '+(parts[i+1]||''),next:i+2};
    if(parts[i+1]&&/^\d{1,3}(\.\d{1,3}){3}$/.test(parts[i+1]))return{val:parts[i]+' '+parts[i+1],next:i+2};
    return{val:parts[i]||'-',next:i+1};
  };
  const dstTok=(parts,i)=>{
    if(/^any-destination$/i.test(parts[i]||''))return{val:'any',next:i+1};
    if(/^host-destination$/i.test(parts[i]||''))return{val:'host '+(parts[i+1]||''),next:i+2};
    if(parts[i+1]&&/^\d{1,3}(\.\d{1,3}){3}$/.test(parts[i+1]))return{val:parts[i]+' '+parts[i+1],next:i+2};
    return{val:parts[i]||'-',next:i+1};
  };
  const re=/^access-list\s+(1\d\d|2\d\d)\s+(permit|deny)\s+(.*)/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const num=m[1],action=m[2],rest=m[3].trim();
    const parts=rest.split(/\s+/);
    const isExtended=PROTO_RE.test(parts[0]||'');
    let protocol='ip',src,dst='-',dstPort='';
    if(isExtended){
      protocol=parts[0].toLowerCase();
      const s=srcTok(parts,1); src=s.val;
      const d=dstTok(parts,s.next); dst=d.val;
      const dpM=rest.match(/\bd-port\s+(\d+)\b/);
      if(dpM)dstPort=dpM[1];
    }else{
      const s=srcTok(parts,0); src=s.val;
    }
    if(!numG[num]){
      numG[num]={name:num,type:isExtended?'extended':'standard',aclType:'ip',ipVersion:'v4',vendor:'planet',rules:[],appliedOn:[]};
      acls.push(numG[num]);
    }else if(isExtended&&numG[num].type!=='extended'){
      numG[num].type='extended'; // 官方語法允許同號碼混用兩種規則列，出現過一筆 extended 即整組標記
    }
    numG[num].rules.push({seq:'',action,protocol,src:(src||'-').trim(),dst:(dst||'-').trim(),dstPort,remark:''});
  }
  const ifBlocks=cfg.split(/(?=^interface\s+)/m);
  for(const blk of ifBlocks){
    const ifLine=blk.match(/^interface\s+(\S.*)/m);
    if(!ifLine)continue;
    const ifName=ifLine[1].trim();
    const agRe=/^\s*(?:ip|mac|mac-ip|ipv6)\s+access-group\s+(\S+)\s+(in|out)\b/gim;
    let am;
    while((am=agRe.exec(blk))!==null){
      const acl=acls.find(a=>a.name===am[1]);
      if(acl)acl.appliedOn.push({interface:ifName,direction:am[2].toLowerCase()});
    }
  }
  return acls;
}

// MAC ACL（具名擴充形式）：官方 SGS-6341 Command Guide 直接 fetch 逐字查證（§47.16/47.22/
// 47.15）。建立語法 `mac-access-list extended <name>` 進入子模式，規則列（§47.22 官方文件
// 列出多種巢狀選填組合，本輪僅取第一種——`cos`/`vlanid`/`ethertype` 依序選填、無 802.3/
// EthernetII tagged/untagged frame-type 關鍵字變體，複雜度高且 real-world 使用率低，非本輪
// 範圍）：`{deny|permit} {any-source-mac|host-source-mac <mac>|<mac> <mask>}
// {any-destination-mac|host-destination-mac <mac>|<mac> <mask>} [cos <val>] [vlanid <vid>]
// [ethertype <proto>]`。src/dst 正規化成與共用 IP ACL 表單一致的 `any`／`host <mac>`／
// `<mac> <mask>` 通用 token（`_normPlanetMacToken()`），供產生器端同一個文字欄位輸入慣例
// 使用。介面套用沿用 §47.15 `mac access-group <name> {in|out}`——`_parseACLPlanet()` 的
// `agRe` 正則本來就已接受 `mac access-group`，但先前 `acls` 陣列只存 IP ACL，真實設定檔的
// `mac access-group` 行會被靜默比對失敗（`acls.find()` 找不到同名 IP ACL），故另外在此
// 獨立掃描一次介面區塊，不與 `_parseACLPlanet()` 共用比對結果。
function _normPlanetMacToken(raw){
  const t=(raw||'').trim();
  if(/^any-(?:source|destination)-mac$/i.test(t))return 'any';
  const hm=/^host-(?:source|destination)-mac\s+(\S+)/i.exec(t);
  if(hm)return 'host '+hm[1];
  return t; // 假設已是「MAC MASK」兩個 token，原樣輸出
}
function _parseMacACLPlanet(cfg){
  const acls=[];
  // 收尾邊界比照 parseClassMaps() 等同批新增函式的既有慣例，額外納入其餘 Planet 已支援區塊
  // 的起始關鍵字（interface/class-map/policy-map/access-list），避免 MAC ACL 不是檔案最後
  // 一段、後面接的也不是另一個 mac-access-list extended 時 body 過度延伸吃到後續區塊文字
  // （2026-09-02 審查發現的理論邊界，防禦性補強，非已知會誤判的真實案例）
  const macRe=/^mac-access-list\s+extended\s+(\S+)([\s\S]*?)(?=^mac-access-list\s+extended\s+|^interface\s+|^class-map\s+|^policy-map\s+|^access-list\s+|(?![\s\S]))/gm;
  let m;
  while((m=macRe.exec(cfg))!==null){
    const name=m[1], body=m[2]||'';
    const rules=[];
    const ruleRe=/^\s*(permit|deny)\s+(any-source-mac|host-source-mac\s+\S+|\S+\s+\S+)\s+(any-destination-mac|host-destination-mac\s+\S+|\S+\s+\S+)(?:\s+cos\s+(\S+))?(?:\s+vlanid\s+(\S+))?(?:\s+ethertype\s+(\S+))?\s*$/gim;
    let rm;
    while((rm=ruleRe.exec(body))!==null){
      rules.push({
        action:rm[1].toLowerCase(), src:_normPlanetMacToken(rm[2]), dst:_normPlanetMacToken(rm[3]),
        cos:rm[4]||'', vlanId:rm[5]||'', ethertype:rm[6]||''
      });
    }
    acls.push({name,rules,appliedOn:[]});
  }
  const ifBlocks=cfg.split(/(?=^interface\s+)/m);
  for(const blk of ifBlocks){
    const ifLine=blk.match(/^interface\s+(\S.*)/m);
    if(!ifLine)continue;
    const ifName=ifLine[1].trim();
    const agRe=/^\s*mac\s+access-group\s+(\S+)\s+(in|out)\b/gim;
    let am;
    while((am=agRe.exec(blk))!==null){
      const acl=acls.find(a=>a.name===am[1]);
      if(acl)acl.appliedOn.push({interface:ifName,direction:am[2].toLowerCase()});
    }
  }
  return acls;
}

// Security：802.1X（`dot1x port-control {auto|force-authorized|force-unauthorized}`／
// `dot1x guest-vlan <vlanid>`）+ MAC port-security（`switchport mac-address dynamic
// maximum <value>`／`switchport mac-address violation {protect|shutdown} [recovery N]`），
// 與其餘廠牌慣用的 "port-security"/"mac-learn limit" 關鍵字皆不同，通用 fallback 迴圈
// 抓不到，需獨立分支（見 switch-analyzer-core.js 的 parseSecurity() dispatcher 註冊）
function _parseSecurityPlanet(cfg){
  const result=[];
  const ifRe=/^interface\s+(ethernet\s+\S+)\s*\n([\s\S]*?)(?=^interface\s|(?![\s\S]))/gm;
  let m;
  while((m=ifRe.exec(cfg))!==null){
    const port=m[1].trim(),body=m[2]||'';
    let dot1x='-',portSec=false,maxMac='-',violation='-',guestVlan='-';
    const dcM=/dot1x port-control\s+(auto|force-authorized|force-unauthorized)/i.exec(body);
    if(dcM&&dcM[1].toLowerCase()==='auto')dot1x='auth';
    const gvM=/dot1x guest-vlan\s+(\S+)/i.exec(body);
    if(gvM)guestVlan=gvM[1];
    const mmM=/switchport mac-address dynamic maximum\s+(\d+)/i.exec(body);
    if(mmM){portSec=true;maxMac=parseInt(mmM[1],10);}
    const vlM=/switchport mac-address violation\s+(protect|shutdown)/i.exec(body);
    if(vlM){portSec=true;violation=vlM[1].toLowerCase();}
    if(dot1x!=='-'||portSec)result.push({port,dot1x,portSec,maxMac,violation,guestVlan});
  }
  return result;
}
