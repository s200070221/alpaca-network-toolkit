function parseNetgearSysInfo(cfg){
  return{
    hostname:(cfg.match(/^snmp-server\s+sysname\s+(\S+)/m)||[])[1]||'unknown',
    version:(cfg.match(/!System Software Version\s+"([^"]+)"/)||[])[1]||'',
    platform:(cfg.match(/!System Description\s+"([^"]*)"/)||[])[1]||'',
  };
}

function parseNetgearVLANs(cfg){
  const vlans=[];
  const dbBlock=(cfg.match(/^vlan database\n([\s\S]*?)^exit/m)||[])[1]||'';
  const re=/^vlan\s+(\d+)\s*$/gm;
  let m;
  while((m=re.exec(dbBlock))!==null){
    const id=m[1];
    // "vlan name <id> <name>" 官方範例為不加引號的裸字（std.rocks 社群語法慣例），但保守
    // 相容可能出現的引號寫法；搜尋整份設定檔而非僅 dbBlock，因無法確認此指令是否限定要在
    // vlan database 子模式內輸入
    const nameM=cfg.match(new RegExp('^vlan name\\s+'+id+'\\s+"?([^"\\n]+?)"?\\s*$','m'));
    vlans.push({id,name:nameM?nameM[1].trim():'',ipSubnets:[]});
  }
  vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return vlans;
}

function parseNetgearInterfaces(cfg){
  const ifaces=[];
  const blocks=cfg.split(/^interface\s+/m).slice(1);
  for(const blk of blocks){
    const lines=blk.split('\n');
    const rawName=lines[0].trim();
    const body=lines.slice(1).join('\n');
    const desc=(body.match(/^\s*description\s+"?([^"\n]+?)"?\s*$/m)||[])[1]?.trim()||'';
    const shutdown=/^\s*shutdown\s*$/m.test(body)&&!/no shutdown/.test(body);

    // VLAN routing interface: "interface vlan N"
    if(/^vlan\s+\d+\s*$/i.test(rawName)){
      const vid=(rawName.match(/\d+/)||[])[0]||'';
      const ipM=body.match(/^\s*ip address\s+([\d.]+)\s+([\d.]+)/m);
      // 官方 KB（kb.netgear.com/21969）確認 IPv6 語法 `ipv6 address ADDR/PREFIXLEN`（需搭配
      // `ipv6 enable`，但該行本身不含位址值，round-trip 只需正確解析 ipv6 address 這行）
      const ip=ipM?ipM[1]+'/'+cidrFromMask(ipM[2]):(body.match(/^\s*ip address\s+([\d.]+\/\d+)/m)||[])[1]||(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增）：ip6 獨立無條件擷取，不再受 ip 是否已有值影響
      const ip6=(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      ifaces.push({name:'vlan '+vid,type:'svi',desc,ip,ip6,mode:'',vlans:vid,nativeVlan:'',vrf:'',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    // Loopback: "interface loopback N"
    if(/^loopback\s+\d+\s*$/i.test(rawName)){
      const ipM=body.match(/^\s*ip address\s+([\d.]+)\s+([\d.]+)/m);
      const ip=ipM?ipM[1]+'/'+cidrFromMask(ipM[2]):(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，同 VLAN）
      const ip6=(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      ifaces.push({name:rawName.replace(/\s+/g,' '),type:'loopback',desc,ip,ip6,mode:'',vlans:'',nativeVlan:'',vrf:'',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    // Physical port ("unit/slot/port") 或 LAG（"lag N"）
    const name=rawName;
    const member=(name.match(/^(\d+)\//)||[])[1]||'1';
    let mode='',vlans='',nativeVlan='',ip='',ip6='';
    const routed=/^\s*routing\s*$/m.test(body)&&!/no routing/m.test(body);
    if(routed){
      const ipM=body.match(/^\s*ip address\s+([\d.]+)\s+([\d.]+)/m);
      ip=ipM?ipM[1]+'/'+cidrFromMask(ipM[2]):(body.match(/^\s*ip address\s+([\d.]+\/\d+)/m)||[])[1]||(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，同 VLAN/Loopback）
      ip6=(body.match(/^\s*ipv6 address\s+(\S+\/\d+)/m)||[])[1]||'';
      mode='routed';
    }else{
      const modeM=body.match(/^\s*switchport mode\s+(\S+)/m);
      if(modeM){
        const sm=modeM[1];
        if(sm==='trunk'){
          mode='trunk';
          // switchport trunk allowed vlan 支援 {vlan-list|all|add LIST|remove LIST|except LIST}
          // 增量寫法，同一介面可能多行修改；比照 Ruijie 既有教訓（同一個累加式語法曾在真實
          // 範例踩過雷），優先採最後一次出現的「整批取代」形式（裸清單/all/except），若全篇
          // 只有 add/remove（無基準清單可重建）則保守回傳 'all'（與官方預設值相同，不臆測）
          const allMatches=[...body.matchAll(/^\s*switchport trunk allowed vlan\s+(all|except\s+\S.*|add\s+\S.*|remove\s+\S.*|[\d,\-]+)/gm)];
          let replaceForm=null;
          for(let i=allMatches.length-1;i>=0;i--){
            const v=allMatches[i][1].trim();
            if(!/^(add|remove)\s/.test(v)){replaceForm=v;break;}
          }
          vlans=replaceForm||'all';
          const nativeM=body.match(/switchport trunk native vlan\s+(\d+)/);
          nativeVlan=nativeM?nativeM[1]:'1';
        }else if(sm==='access'){
          mode='access';
          vlans=(body.match(/switchport access vlan\s+(\d+)/)||[])[1]||'1';
        }else{
          mode=sm; // 'general' 模式目前無對應共用資料形狀欄位可承接，暫存字面值本身
        }
      }
    }
    ifaces.push({name,type:'physical',desc,mode,vlans:(vlans||'').toString().trim(),nativeVlan,vrf:'',ip,ip6,shutdown,member,hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
  }
  return ifaces;
}

function parseNetgearRoutes(cfg){
  const routes=[];
  // ip route ipaddr subnetmask [nexthopip | Null0 | interface {unit/slot/port | vlan vlan-id}]
  // [preference] [description description]
  const re=/^ip route\s+([\d.]+)\s+([\d.]+)\s+(?:interface\s+(?:vlan\s+(\d+)|(\S+))|(Null0|[\d.]+))?/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const dst=m[1]+'/'+cidrFromMask(m[2]);
    let gw='',gwIsInterface=false;
    if(m[3]){gw='vlan '+m[3];gwIsInterface=true;}
    else if(m[4]){gw=m[4];gwIsInterface=true;}
    // Null0 與一般 nexthop IP 同屬這個分支（regex 裡兩者都不在 "interface" 關鍵字之後），
    // 官方語法 Null0 本身不帶 "interface" 前綴，與 unit/slot/port｜vlan 那個分支平行、互斥；
    // 先前誤把 Null0 標成 gwIsInterface=true，產生器端會多插入不存在的 "interface" 關鍵字，
    // 匯出 "ip route ... interface Null0" 這種真機會拒絕的無效語法（2026-09-02 審查發現）
    else if(m[5]){gw=m[5];gwIsInterface=false;}
    if(dst&&gw)routes.push({dst,gw,vrf:'',gwIsInterface});
  }
  return routes;
}

function parseNetgearOSPF(cfg){
  const processes=[];
  // 官方語法為 bare "router ospf"（無 process-id 參數，與 Cisco 不同，不可重用
  // parseCiscoOSPF()——其正則強制要求數字 pid）；area 底下的 network/wildcard/area
  // 語法本身與 Cisco 相同
  const m=/^router ospf\s*\n([\s\S]*?)(?=^router\s|^interface\s|^end\b|(?![\s\S]))/m.exec(cfg);
  if(!m)return processes;
  const body=m[1];
  const rid=(body.match(/router-id\s+(\S+)/)||[])[1]||'';
  const areas=[];
  const ar=/^\s*network\s+([\d.]+)\s+([\d.]+)\s+area\s+([\d.]+)/gm;
  let am;
  while((am=ar.exec(body))!==null){
    let area=areas.find(a=>a.area===am[3]);
    if(!area){area={area:am[3],networks:[]};areas.push(area);}
    area.networks.push({network:am[1],wildcard:am[2]});
  }
  processes.push({pid:'default',routerId:rid,areas});
  return processes;
}

// 本機帳號（2026-08-23 新增）：Netgear M4300／EdgeSwitch 同源 ICOS，語法比照官方
// Ubiquiti EdgeSwitch Command Reference Manual 逐字確認的單行語法
// "username NAME password PASSWORD level N"（N=1 唯讀／15 讀寫）；Netgear 官方 PDF 因
// WebFetch 無法解析二進位內容，改用社群文件交叉印證同一語法，中信心度。role 比照 Cisco
// 既有 'privilege-N' 慣例，用合成字串 'level-N' 存純數字層級
function parseNetgearUsers(cfg){
  const users=[];
  const re=/^username\s+(\S+)\s+password\s+(\S+)\s+level\s+(\d+)/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    users.push({name:m[1],role:'level-'+m[3],service:'ssh/console',hasPwd:true,pwdType:'set',pwdWeak:false});
  }
  return users;
}
function parseNetgear(cfg){
  const sys=parseNetgearSysInfo(cfg);
  const vlans=parseNetgearVLANs(cfg);
  const interfaces=parseNetgearInterfaces(cfg);
  const routes=parseNetgearRoutes(cfg);
  const ospf=parseNetgearOSPF(cfg);
  const rip=parseCiscoRIP(cfg); // bare "router rip"，語法與 Cisco 相同可直接重用
  const vrrp=parseVRRP(cfg,'netgear');
  return{sys,irf:null,stack:null,vlans,interfaces,routes,vrfs:[],users:parseNetgearUsers(cfg),ospf,bgp:[],rip,vrrp,vxlan:null,vendor:'netgear',breakouts:[]};
}

// ═ Ubiquiti EdgeSwitch (舊款 ES-XX／EdgeSwitch X 系列，Broadcom ICOS) Parser ═
// 2026-07-30 對外查證官方 EdgeSwitch CLI Command Reference（dl.ubnt.com/guides/edgemax/
// EdgeSwitch_CLI_Command_Reference_UG.pdf）＋ EdgeSwitch Administration Guide 的
// Configuration Examples 章節後新增。**僅涵蓋舊款 ES-XX／EdgeSwitch X 系列（透過序列埠/
// Telnet/SSH 的傳統 CLI 管理）**，不含現行主力產品線「UniFi Switch」（純 Controller/App
// 雲端管理，無文字化設定檔匯出，架構上不適用）。
// 與 Netgear M4300 同源 Broadcom ICOS，但沒有 switchport 相容別名，VLAN 成員用原生
// "vlan participation include/exclude/auto <單一VLAN ID>"＋"vlan tagging <單一VLAN ID>"
// （官方文件明確每個指令一次只接受一個 VLAN ID，不支援逗號清單，與 Netgear 的
// switchport trunk allowed vlan 逗號清單語法不同）＋"vlan pvid <ID>"（未標記/native VLAN）。
// **重大架構限制（非查證不足，是裝置本身特性）**：L3 VLAN Routing 的邏輯介面 ID
// （如 3/1、4/1）是裝置動態配置產生（依啟用 routing 的順序遞增），必須透過
// `show ip vlan` 才能查出實際對應值，無法從設定檔靜態預測或還原，故本工具不支援
// EdgeSwitch 的 VLAN Routing/IP 位址/OSPF/RIP/BGP/VRRP/靜態路由/DHCP（皆依賴可定址的
// L3 介面）。STP 為 MST instance 模型（`spanning-tree mst instance N`+
// `spanning-tree mst vlan N M` 關聯+`spanning-tree mst priority N P`），與本工具其餘
// 廠牌共用的扁平 STP 資料形狀不相容，本輪不實作。ACL/QoS 查無足夠把握的語法佐證不實作。
