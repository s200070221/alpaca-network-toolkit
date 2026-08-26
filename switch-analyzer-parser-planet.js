// ═ Planet Technology SGS-6341 系列 Parser ═
// 查證來源：官方 SGS-6341 Series Command Guide_v2.0.pdf（直接 fetch 官方 PDF 逐字查證）。
// CLI 骨架整體近似 Cisco IOS Classic（hostname／switchport mode），VLAN 設定則是
// Comware 式子模式（`vlan WORD` 進入子模式，WORD 可用 `;`/`-` 連寫多個 VLAN ID，
// 不像 Cisco 逐一 `vlan N`/`name X`）；介面命名 `ethernet 1/0/5`（slot/port 格式，
// ethernet 與數字之間有空格，與 Dell OS10 `ethernet1/1/1`〔無空格〕不同）。
// 本輪明確不實作：ACL／QoS／STP／DHCP／Users（本機帳號）——查無官方語法佐證，
// 不猜測，維持空陣列/預設值。
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
  return{sys,irf:null,stack:null,vlans,interfaces,routes,vrfs:[],users:[],ospf,bgp,rip:[],vrrp,vxlan:null,vendor:'planet',breakouts:[]};
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
