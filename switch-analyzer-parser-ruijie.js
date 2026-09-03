function parseRuijieSysInfo(cfg){
  return{
    hostname:(cfg.match(/^hostname\s+(\S+)/m)||[])[1]||'unknown',
    version:(cfg.match(/version\s+(\S+)/)||[])[1]?.trim()||'',
    platform:'',
  };
}
// Ruijie 產生器端 compressVlanList() 把 hybrid untagged/tagged VLAN 清單壓縮輸出成
// 「逗號分隔＋連字號範圍」格式（如 "5-7,10,12-15"），但解析端先前只用 split(/\s+/)（純空白
// 切割），完全不認得逗號與連字號範圍，會把整段壓縮字串誤當成單一 VLAN token（2026-09-02
// 全功能審查發現）；比照 switch-analyzer-parser-planet.js 既有的 expandPlanetVlanWord() 寫法
function expandRuijieHybridVlanWord(word){
  const ids=[];
  (word||'').split(/[,\s]+/).forEach(part=>{
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
function parseRuijieHybrid(blk){
  // 官方語法：switchport hybrid native vlan N（PVID）／switchport hybrid allowed vlan
  // [[add] {tagged|untagged}] X-Y ／ switchport hybrid allowed vlan remove X-Y（"add" 為可省略
  // 前綴，remove 從 tagged/untagged 兩集合同時移除；2026-08-01 對外查證官方 RGOS CLI Command
  // Reference 後補上 add/remove 語法，先前版本只認裸 tagged/untagged，remove 會被靜默忽略）。
  // 與 Comware 的 "port hybrid vlan X tagged/untagged" 用詞不同，不可重用 parseHybrid()，
  // 但回傳形狀沿用全廠牌共用的 hybrid 資料形狀（UI／匯出報告已通用支援此形狀），Ruijie 無
  // QinQ/vlan-mapping/subscriber-vlan 對應語法佐證，固定回傳空值/false
  const pvid=(blk.match(/switchport hybrid native vlan\s+(\d+)/)||[])[1]||'';
  const untagged=new Set(),tagged=new Set();
  const opRe=/switchport hybrid allowed vlan\s+(?:(?:add\s+)?(tagged|untagged)\s+([^\n]+)|(remove)\s+([^\n]+))/g;
  let m;
  while((m=opRe.exec(blk))!==null){
    if(m[1]){
      const target=m[1]==='tagged'?tagged:untagged;
      expandRuijieHybridVlanWord(m[2]).forEach(v=>target.add(v));
    }else if(m[3]){
      expandRuijieHybridVlanWord(m[4]).forEach(v=>{tagged.delete(v);untagged.delete(v);});
    }
  }
  return{
    pvid,
    untagged:[...untagged],
    tagged:[...tagged],
    hasIPSub:false,vlanMaps:[],hasQinQ:false,
  };
}
function parseRuijieInterfaces(cfg){
  const ifaces=[];
  // 官方 RG-S6120 Series RGOS Command Reference 第 7.4/7.5 節已查證：VRF 綁定語法與 Cisco
  // classic IOS 相同（"ip vrf forwarding NAME"），CLAUDE.md 廠牌表格本身已記載此依據；此正則
  // 直接沿用 switch-analyzer-parser-cisco.js 的 vrfRe 寫法，補上先前固定寫死空字串的缺口
  const vrfRe=/ip vrf forwarding\s+(\S+)/;
  const blocks=cfg.split(/^interface\s+/m).slice(1);
  for(const blk of blocks){
    const lines=blk.split('\n');
    const name=lines[0].trim();
    let body=lines.slice(1).join('\n');
    // 每個 interface 區塊在 Ruijie（Cisco-like）語法中都以獨立一行 "!" 終止；split 對「檔案中
    // 最後一次出現的區塊」沒有下一個 "interface " 可以自然定界，body 會一路延伸吃進後續
    // 不相干區塊（如 ip vrf 自己的 description），誤植進本介面的欄位值（2026-09-02 全功能
    // 審查發現）
    const bangIdx=body.search(/\n!\s*(\n|$)/);
    if(bangIdx!==-1)body=body.slice(0,bangIdx);
    const desc=(body.match(/^\s*description\s+(.+)/m)||[])[1]?.trim()||'';
    const shutdown=/^\s*shutdown\s*$/m.test(body)&&!/no shutdown/.test(body);
    // Ruijie 介面命名可能含空白（如 "GigabitEthernet 0/1"），先去除空白再取 member 編號
    const memberMatch=name.replace(/\s+/g,'').match(/^[A-Za-z]+(\d+)\//);
    const member=memberMatch?memberMatch[1]:'1';

    if(/^Loopback/i.test(name)){
      const ip=(body.match(/^\s*ip address\s+(\S+\s+\S+)/m)||[])[1]||(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增）：ip6 獨立無條件擷取，不再受 ip 是否已有值影響
      const ip6=(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      const vrf=(body.match(vrfRe)||[])[1]||'';
      ifaces.push({name,type:'loopback',desc,ip,ip6,mode:'',vlans:'',nativeVlan:'',vrf,shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    if(/^Vlan/i.test(name)){
      const ipRaw=(body.match(/^\s*ip address\s+(\S+)\s+(\S+)/m)||[]);
      const ip=ipRaw[1]&&ipRaw[2]?ipRaw[1]+'/'+cidrFromMask(ipRaw[2]):(body.match(/^\s*ip address\s+([\d.]+\/\d+)/m)||[])[1]||(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，同 Loopback）
      const ip6=(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      const vrf=(body.match(vrfRe)||[])[1]||'';
      // VRRP 由共用 parseVRRP(cfg,'ruijie') 在頂層統一解析（見 parseRuijie()），此處介面
      // 物件的 vrrp 欄位固定空陣列，比照多數非 Cisco/Comware 廠牌的既有慣例
      ifaces.push({name,type:'svi',desc,ip,ip6,mode:'',vlans:'',nativeVlan:'',vrf,shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    // 實體埠與 AggregatePort 聚合介面共用同一段解析（AggregatePort 本身也是可設定
    // switchport 的邏輯介面）；成員埠的 port-group 宣告由共用 parseLACP() 的 ruijie
    // 分支獨立處理，不在此重複解析
    let mode='',vlans='',nativeVlan='',hybrid=null;
    if(/switchport mode trunk/.test(body)){
      mode='trunk';
      // 官方語法允許 "switchport trunk allowed vlan {add|remove|only|all|except} <list>" 多行
      // 累加修改，而非單行完整清單（2026-07-29 由使用者提供的真實風格範例測出：只抓第一行會
      // 誤把 "remove 1" 這種增量修改指令當成完整清單）。only/all/except 代表「整批取代」，取
      // 最後一次出現為準；except 語意是「排除清單」而非納入清單，保留 except 前綴避免與一般
      // 納入清單混淆（2026-08-01 對外交叉查證 RG-S2600E/RG-S29/RG-WLAN 三份官方手冊後補上，
      // 先前版本缺少 except 關鍵字，會讓 except 那行被誤判成裸清單整批取代）。若全篇只有
      // add/remove（無 only/all/except/裸清單當基準），因無法重建原始基準清單，維持保守回傳
      // 'all'（與未設定時的既有預設值相同，不臆測）
      const vlanLines=[...body.matchAll(/switchport trunk allowed vlan\s+(?:(add|remove|only|all|except)\s+)?([^\n]+)/g)];
      const fullList=[...vlanLines].reverse().find(m=>m[1]==='only'||m[1]==='all'||m[1]==='except'||!m[1]);
      vlans=fullList?(fullList[1]==='except'?`except ${fullList[2].trim()}`:fullList[2].trim()):'all';
      nativeVlan=(body.match(/switchport trunk native vlan\s+(\d+)/)||[])[1]||'1';
    }else if(/switchport mode access/.test(body)){
      mode='access';
      vlans=(body.match(/switchport access vlan\s+(\d+)/)||[])[1]||'1';
    }else if(/switchport mode hybrid/.test(body)){
      mode='hybrid';
      hybrid=parseRuijieHybrid(body);
      vlans=[...hybrid.untagged,...hybrid.tagged].filter((v,i,a)=>a.indexOf(v)===i).join(' ');
      nativeVlan=hybrid.pvid;
    }
    const ip=(body.match(/^\s*ip address\s+(\S+\s+\S+)/m)||[])[1]||(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
    // 雙棧修復（2026-08-13 新增，同 Loopback/VLAN）
    const ip6=(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
    const vrf=(body.match(vrfRe)||[])[1]||'';
    ifaces.push({name,type:'physical',desc,mode,vlans:vlans.trim(),nativeVlan,vrf,ip,ip6,shutdown,member,hybrid,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
  }
  return ifaces;
}
// VSU（Virtual Switch Unit）堆疊，查證來源：官方 VSU 技術文檔
// https://www.ruijie.com.cn/fw/wt/90872/ ——尚無真實設定檔驗證，信心度較低。
// switch virtual domain <id> 宣告堆疊域；逐一 switch <n> priority <p> 決定成員編號與
// 優先權（優先權最大者判定為 Active）；VSL（Virtual Switch Link）鏈路成員埠
// "port-member interface X" 巢狀宣告於該埠自己的 interface 區塊內，依介面名稱前綴數字
// （member 編號慣例，與其餘介面 member 判斷一致）回推歸屬的 switch 成員
function parseRuijieStack(cfg){
  const domainM=cfg.match(/^switch virtual domain\s+(\d+)/m);
  if(!domainM)return null;
  const domain=domainM[1];
  const members=[]; let m;
  const prRe=/^switch\s+(\d+)\s+priority\s+(\d+)/gm;
  while((m=prRe.exec(cfg))!==null)members.push({id:m[1],priority:parseInt(m[2]),role:''});
  if(!members.length)return null;
  const maxPrio=Math.max(...members.map(x=>x.priority));
  members.forEach(x=>{x.role=x.priority===maxPrio?'Active':'Standby';});
  members.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  const vslByMember={};
  // VSL 鏈路埠獨立宣告於 "vsl-port" 子模式（2026-08-07 對外查證修正，非巢狀在各實體介面
  // 自己的 interface 區塊內），逐行 port-member interface 依介面名稱的插槽編號前綴反推所屬
  // 成員（沿用既有推斷邏輯，只是改抓取來源）
  const vslBlockM=cfg.match(/^vsl-port\n([\s\S]*?)^exit/m);
  if(vslBlockM){
    const portRe=/^port-member interface\s+(\S.*)$/gm;
    let pm;
    while((pm=portRe.exec(vslBlockM[1]))!==null){
      const name=pm[1].trim();
      const midMatch=name.replace(/\s+/g,'').match(/^[A-Za-z]+(\d+)\//);
      const mid=midMatch?midMatch[1]:members[0]?.id;
      if(!mid)continue;
      (vslByMember[mid]=vslByMember[mid]||[]).push(name);
    }
  }
  const vsl=Object.entries(vslByMember).map(([memberId,interfaces])=>({memberId,interfaces}));
  return{type:'VSU',domain,members,vsl};
}
// Ruijie 靜態路由：不可直接重用 parseCiscoRoutes()——RGOS 慣例介面名稱「類型與數字間帶空格」
// （如 "VLAN 1"／"GigabitEthernet 0/1"），若下一跳寫成介面時會多佔一個 token，Cisco 版本
// 用單一 \S+ 擷取第4個 token 會只抓到 "VLAN"，後面真正的閘道 IP 被漏解析（2026-07-29 使用者
// 提供真實裝置匯出檔測出：ip route 0.0.0.0 0.0.0.0 VLAN 1 192.168.202.1）
function parseRuijieRoutes(cfg){
  const routes=[]; let m;
  const re=/^ip route(?:\s+vrf\s+(\S+))?\s+(\S+)\s+(\S+)\s+(.+)$/gm;
  while((m=re.exec(cfg))!==null){
    const vrf=m[1]||'';
    let dst=m[2];const mask=m[3];const rest=m[4].trim();
    if(/^\d+\.\d+\.\d+\.\d+$/.test(mask)){dst=dst+'/'+cidrFromMask(mask);}
    else if(/^\d+$/.test(mask)){dst=dst+'/'+mask;}
    const ifaceMatch=rest.match(/^(VLAN|GigabitEthernet|TenGigabitEthernet|AggregatePort|Loopback|Null|MTGigabitEthernet)\s+(\S+)(?:\s+(\S+))?$/i);
    let gw,gwIsInterface;
    if(ifaceMatch){
      if(ifaceMatch[3]){gw=ifaceMatch[3];gwIsInterface=false;}
      else{gw=`${ifaceMatch[1]} ${ifaceMatch[2]}`;gwIsInterface=true;}
    }else{
      gw=rest.split(/\s+/)[0];
      gwIsInterface=!/^\d+\.\d+\.\d+\.\d+/.test(gw);
    }
    routes.push({dst,gw,vrf,gwIsInterface});
  }
  // IPv6 靜態路由（2026-08-13 十一續新增）：官方語法 "ipv6 route [vrf NAME] PREFIX/LEN {ADDR|IFACE}"，
  // prefix/length 已是單一 token；沿用上方既有「介面名稱含空格」偵測邏輯（VLAN 1 等）
  const re6=/^ipv6 route(?:\s+vrf\s+(\S+))?\s+(\S+)\s+(.+)$/gm;
  while((m=re6.exec(cfg))!==null){
    const vrf=m[1]||'';
    const dst=m[2];
    const rest=m[3].trim();
    const ifaceMatch=rest.match(/^(VLAN|GigabitEthernet|TenGigabitEthernet|AggregatePort|Loopback|Null|MTGigabitEthernet)\s+(\S+)(?:\s+(\S+))?$/i);
    let gw,gwIsInterface;
    if(ifaceMatch){
      if(ifaceMatch[3]){gw=ifaceMatch[3];gwIsInterface=false;}
      else{gw=`${ifaceMatch[1]} ${ifaceMatch[2]}`;gwIsInterface=true;}
    }else{
      gw=rest.split(/\s+/)[0];
      gwIsInterface=!gw.includes(':');
    }
    routes.push({dst,gw,vrf,gwIsInterface});
  }
  return routes;
}
function parseRuijie(cfg){
  const sys=parseRuijieSysInfo(cfg);
  const vlans=parseCiscoVLANs(cfg);
  const interfaces=parseRuijieInterfaces(cfg);
  const routes=parseRuijieRoutes(cfg);
  const vrfs=parseCiscoVRFs(cfg);
  const users=parseCiscoUsers(cfg);
  const ospf=parseCiscoOSPF(cfg);
  const ospf6=parseCiscoOSPFv3(cfg);
  const bgp=parseCiscoBGP(cfg);
  const rip=parseCiscoRIP(cfg);
  const rip6=parseCiscoRIPng(cfg);
  const vrrp=parseVRRP(cfg,'ruijie');
  const stack=parseRuijieStack(cfg);
  return{sys,irf:null,stack,vlans,interfaces,routes,vrfs,users,ospf,ospf6,bgp,rip,rip6,vrrp,vxlan:null,vendor:'ruijie',breakouts:[]};
}

// ═ Netgear M4300 (Intelligent Edge, ICOS) Parser ═
// 2026-07-30 對外查證官方 M4300 Intelligent Edge Series CLI Command Reference Manual
// （202-11997-09，2026-03 版）後新增。底層架構與 Ubiquiti EdgeSwitch 同源（Broadcom
// ICOS/FASTPATH）：VLAN 建立（vlan database）／LACP（addport／interface lag N）用
// ICOS 語系，但額外支援 switchport mode trunk/access 這組 Cisco 相容別名；OSPF（bare
// router ospf + network/wildcard/area）／RIP（bare router rip）／靜態路由與 Cisco 高度
//相似但仍有差異（ip route 的 nexthop 可以是 interface unit/slot/port 或 vlan N，Cisco
// 沒有這個寫法）。官方 202-11997-08（2022-04）版本更新記錄明確寫「We removed references
// to BGP because this protocol is not supported」——BGP 是裝置真不支援，非查無語法，已
// 同步在 switch_config_generator 標記為 VENDOR_INCAPABLE。ACL／QoS／DHCP Server／VRF
// 查無足夠把握的官方語法佐證，本輪不實作（維持空值/預設，不猜測）。無真實裝置匯出檔可
// 比對校正，信心度比照 Ruijie 初版模式（純文件為主）。
