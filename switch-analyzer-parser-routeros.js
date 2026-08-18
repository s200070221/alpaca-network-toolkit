function parseRouterOSSysInfo(cfg){
  const model=(cfg.match(/^\/system identity[\s\S]*?name=([^\n]+)/m)||[])[1]||'RouterOS';
  const isCCR=/CCR\d+/i.test(model);
  return{hostname:model,version:'',isCCR};
}
// 修正：原正則要求 "tagged=" 一定要在 "vlan-id=" 之前且必填，真實匯出設定檔常見「只有
// untagged= 沒有 tagged=」的純 access port VLAN 宣告（如既有 routeros_basic.rsc 第 10 行
// `add bridge=br-local untagged=ether5 vlan-id=1`），原正則完全比對不到、VLAN1 從未被解析到
// 過；改為對 add 整行分別擷取 tagged=/untagged=/vlan-id=，不假設參數順序或必填與否
function parseRouterOSVLANs(cfg){
  const seen=new Map();
  const block=cfg.match(/^\/interface\s+bridge\s+vlan\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  (block?block[1].split('\n'):[]).filter(l=>/^\s*add\s/.test(l)).forEach(l=>{
    const idM=l.match(/vlan-id=(\d+)/);
    if(!idM)return;
    const id=parseInt(idM[1]);
    const tagged=(l.match(/\btagged=([^\s]+)/)||[])[1]||'';
    const untagged=(l.match(/\buntagged=([^\s]+)/)||[])[1]||'';
    if(!seen.has(id))seen.set(id,{id,name:`VLAN${id}`,ports:[],status:'active',tagged:[],untagged:[]});
    const v=seen.get(id);
    if(tagged)v.tagged.push(...tagged.split(','));
    if(untagged)v.untagged.push(...untagged.split(','));
  });
  return [...seen.values()].map(v=>({id:v.id,name:v.name,ports:v.ports,status:v.status,tagged:v.tagged.join(','),untagged:v.untagged.join(',')}));
}
function parseRouterOSInterfaces(cfg){
  const intfs=[];
  // 修正：原本用 \Z（JS 正則不支援，等同字面 'Z' 字元）當字串結尾 fallback，
  // 若該 /interface 區塊剛好是檔案最後一段且內容不含字母 Z，會完全解析不到；改用既有慣例 (?![\s\S])
  const re=/^\/interface\s+(\w+(?:-\w+)*)\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const type=m[1];
    const lines=m[2].split('\n');
    for(let i=0;i<lines.length;i++){
      const addM=lines[i].match(/add\s+name=([^\s]+)(?:.*?speed=(\d+(?:\w+)?)?)?/);
      if(addM){
        const name=addM[1];
        let speed='-',portType=type;
        if(type==='sfp-sfpplus')portType='SFP+',speed='10G';
        else if(type==='qsfp28')portType='QSFP28',speed='40G';
        else if(type==='ethernet')portType='Ethernet',speed=addM[2]||'1G';
        intfs.push({name,status:'up',speed,portType,description:'',mode:'',vlans:''});
      }
    }
  }
  return intfs;
}
// VLAN membership 以 bridge VLAN filtering table 為主體宣告（`/interface bridge vlan`），
// interface 區塊本身完全不含 VLAN 資訊，比照既有 Alcatel/Extreme XOS/ProCurve 慣例反查回填
// lacpList（2026-08-08 新增第三參數）：官方文件確認 bonding slave 不可再直接掛 bridge port，
// 故 tagged/untagged 名稱可能是 bond（LACP 聚合介面）而非實體埠名稱，`ifaces` 只含
// `/interface ethernet` 的實體埠，需把命中 bond 的 tagging 結果套用到該 bond 底下的所有
// 物理成員介面，維持既有「物理介面顯示 VLAN 資訊」的 UI 慣例（與 generator 端用聚合介面
// 第一個成員的設定當代表值的邏輯對稱）
function applyRouterOSVlanMembership(vlans,ifaces,lacpList){
  const untaggedOf={},taggedOf={};
  vlans.forEach(v=>{
    (v.untagged?v.untagged.split(','):[]).forEach(p=>{untaggedOf[p]=String(v.id);});
    (v.tagged?v.tagged.split(','):[]).forEach(p=>{(taggedOf[p]=taggedOf[p]||[]).push(String(v.id));});
  });
  (lacpList||[]).forEach(l=>{
    const members=l.members||[];
    if(!members.length)return;
    if(taggedOf[l.name]){
      members.forEach(m=>{taggedOf[m]=(taggedOf[m]||[]).concat(taggedOf[l.name]);});
    }
    if(untaggedOf[l.name]!==undefined){
      members.forEach(m=>{if(untaggedOf[m]===undefined)untaggedOf[m]=untaggedOf[l.name];});
    }
  });
  ifaces.forEach(i=>{
    if(taggedOf[i.name]){
      i.mode='trunk';i.vlans=taggedOf[i.name].join(',');
      if(untaggedOf[i.name]!==undefined)i.nativeVlan=untaggedOf[i.name];
    }else if(untaggedOf[i.name]!==undefined){
      i.mode='access';i.vlans=untaggedOf[i.name];
    }
  });
}
// 欄位命名（2026-07-27 修正）：原本回傳 {destination,gateway}，是 13 家廠牌中唯一沒有
// 用共通命名 dst/gw 的孤例，導致匯入橋接 parseAndImport()/applyModelToForm()（統一讀
// r.dst/r.gw）在 RouterOS 設定檔匯入時整批路由資料消失（物件裡根本沒有 dst/gw 這兩個
// key）。改用與其餘 12 家廠牌一致的 dst/gw 命名，非新增欄位。
function parseRouterOSRoutes(cfg){
  const routes=[];
  // RouterOS 導出格式：destination= 或 dst-address= 均支持
  const re=/^add\s+.*?(?:destination|dst-address)=([^\s]+).*?gateway=([^\s]+)/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    routes.push({dst:m[1],gw:m[2],metric:0,type:'static'});
  }
  return routes;
}
// 官方文件查證（help.mikrotik.com「/routing/ospf」頁）：router-id 是 `/routing ospf instance`
// 的屬性（非獨立指令），area 用 `/routing ospf area add area-id=X instance=Y`；RouterOS 7 用
// `/routing ospf interface-template add interfaces=X area=Y` 取代舊版 `/routing ospf network`，
// 逐介面宣告所屬 area（比照既有 Juniper/Brocade「OSPF area 底下宣告介面名稱非 CIDR」慣例）。
// 原本 parseRouterOSOSPF() 只偵測關鍵字存在就回傳寫死的假資料（router-id 永遠是 '-'），
// 即使真實匯出設定檔含 router-id 也讀不到，屬未完成的殘留 stub，已修正為真實逐行解析
function parseRouterOSOSPF(cfg){
  const instBlock=cfg.match(/^\/routing\s+ospf\s+instance\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  if(!instBlock)return[];
  const instLine=(instBlock[1].split('\n').find(l=>/^add\s/.test(l))||'');
  const routerId=(instLine.match(/router-id=(\S+)/)||[])[1]||'-';
  const instName=(instLine.match(/name=(\S+)/)||[])[1]||'default';

  const areas=[];
  const areaBlock=cfg.match(/^\/routing\s+ospf\s+area\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  (areaBlock?areaBlock[1].split('\n'):[]).filter(l=>/^add\s/.test(l)).forEach(l=>{
    const areaId=(l.match(/area-id=(\S+)/)||[])[1]||'0.0.0.0';
    const areaName=(l.match(/\bname=(\S+)/)||[])[1]||'';
    const type=(l.match(/\btype=(\S+)/)||[])[1]||'default';
    areas.push({area:areaId,_name:areaName,type,networks:[]});
  });

  const tmplBlock=cfg.match(/^\/routing\s+ospf\s+interface-template\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  (tmplBlock?tmplBlock[1].split('\n'):[]).filter(l=>/^add\s/.test(l)).forEach(l=>{
    const ifaces=(l.match(/interfaces=(\S+)/)||[])[1]||'';
    const areaRef=(l.match(/\barea=(\S+)/)||[])[1]||'';
    // area-template 引用的可能是 area 的 name 也可能直接是 area-id，兩種都嘗試比對
    const area=areas.find(a=>a._name===areaRef||a.area===areaRef);
    if(area&&ifaces)ifaces.split(',').forEach(iface=>area.networks.push({network:iface,wildcard:'0.0.0.0'}));
  });

  return[{pid:instName,routerId,areas:areas.length?areas:[{area:'0.0.0.0',type:'default',networks:[]}]}];
}
// 官方文件查證（help.mikrotik.com「/routing/bgp」頁）：本地 AS 號碼與 router-id 是
// `/routing bgp instance` 的屬性；peer 建立為 `/routing bgp connection`（非舊版 `/routing bgp peer`），
// 參數用點號巢狀命名 `remote.address=`/`remote.as=`（非其餘廠牌慣用的連字號）。
// 原本 parseRouterOSBGP() 同樣只偵測關鍵字存在就回傳寫死假資料（asn 永遠是 '-'），已修正
function parseRouterOSBGP(cfg){
  const instBlock=cfg.match(/^\/routing\s+bgp\s+instance\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  if(!instBlock)return[];
  const instLine=(instBlock[1].split('\n').find(l=>/^add\s/.test(l))||'');
  const asn=(instLine.match(/\bas=(\S+)/)||[])[1]||'-';
  const routerId=(instLine.match(/router-id=(\S+)/)||[])[1]||'-';

  const peers=[]; let listName='';
  const connBlock=cfg.match(/^\/routing\s+bgp\s+connection\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  (connBlock?connBlock[1].split('\n'):[]).filter(l=>/^add\s/.test(l)).forEach(l=>{
    const ip=(l.match(/remote\.address=([^\s\/]+)/)||[])[1]||'';
    const as=(l.match(/remote\.as=(\S+)/)||[])[1]||'';
    const name=(l.match(/\bname=(\S+)/)||[])[1]||'';
    if(!listName){const lm=l.match(/output\.network=(\S+)/);if(lm)listName=lm[1];}
    if(ip)peers.push({ip,as,desc:name});
  });

  // Networks（2026-07-17 對外查證官方 MikroTik RouterOS 文件確認）：output.network=
  // 引用的是 /ip firewall address-list 位址清單名稱，須另外掃描該區塊取出同名清單的
  // 所有 address= 值
  const networks=[];
  if(listName){
    const alBlock=cfg.match(/^\/ip\s+firewall\s+address-list\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
    const listEsc=listName.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    (alBlock?alBlock[1].split('\n'):[]).filter(l=>/^add\s/.test(l)).forEach(l=>{
      if(!new RegExp('list='+listEsc+'(\\s|$)').test(l))return;
      const addr=(l.match(/\baddress=(\S+)/)||[])[1];
      if(addr)networks.push(addr);
    });
  }

  return[{asn,routerId,peers,networks}];
}
// 官方文件查證（help.mikrotik.com「Bonding」頁）：真實選單是 `/interface bonding`
// （非原本誤寫的 `/interface bond`，兩者完全不同指令，原本的正則永遠比對不到任何真實匯出
// 設定檔），member 介面清單用單一參數 `slaves=`（逗號分隔），不是逐行個別宣告
function parseRouterOSLACP(cfg){
  const lags=[];
  const bonding=cfg.match(/^\/interface\s+bonding\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  if(!bonding)return lags;
  const lines=bonding[1].split('\n');
  for(let i=0;i<lines.length;i++){
    const m=lines[i].match(/add\s+name=([^\s]+)/);
    if(!m)continue;
    const name=m[1];
    const modeM=lines[i].match(/mode=(\S+)/);
    const slavesM=lines[i].match(/slaves=([^\s]+)/);
    const members=slavesM?slavesM[1].split(','):[];
    lags.push({name,status:'up',members,mode:modeM?modeM[1]:'balance-rr',mtu:1500});
  }
  return lags;
}
// 官方文件查證（help.mikrotik.com「Spanning Tree Protocol」／「Bridge」頁）：protocol-mode／
// priority 是 `/interface bridge` 這個既有區塊本身的屬性（非獨立子選單），priority 用十六進位
// 表示（如 `0x8000`）。原本 parseRouterOSBridgeSTP() 對整份設定檔任意位置出現 "priority="
// 或 "rstp" 字樣就誤判為啟用且回傳寫死的 32768，未實際掃描 bridge 區塊、也未真正讀值
// 資料形狀（2026-07-27 修正）：原本回傳扁平 {enabled,mode,priority}，與全廠牌共用的巢狀
// STP 形狀 {mode,instances:[],ports:[],rootMode,timers:{}}（見 CLAUDE.md「DHCP/ACL/QoS/
// Security/STP 資料形狀」段落）不符，導致 renderRouterOSBridge() 讀取的 stp.instances[0].priority
// 路徑永遠讀不到值，且 switch_analyzer 自身 renderSTP() UI 對 s.instances.length/s.ports.length
// 做無條件存取，RouterOS 設定檔在 STP 頁籤會直接因 undefined.length 而拋錯。改為回傳符合共用
// 形狀的資料（priority 掛在唯一一個 instance 底下，RouterOS 無逐 port/逐 VLAN 概念，ports 固定
// 空陣列），而非要求 render 端遷就這個孤例
function parseRouterOSBridgeSTP(cfg){
  const block=cfg.match(/^\/interface\s+bridge\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  if(!block)return{mode:'',instances:[],ports:[],rootMode:'',timers:{}};
  const body=block[1];
  const modeM=body.match(/protocol-mode=(\S+)/);
  const mode=modeM?modeM[1]:'rstp'; // RouterOS 預設 protocol-mode 即為 rstp
  const prioM=body.match(/priority=(0x[0-9a-fA-F]+|\d+)/);
  const priority=prioM?parseInt(prioM[1],prioM[1].toLowerCase().startsWith('0x')?16:10):32768;
  return{mode,instances:[{id:'0',priority}],ports:[],rootMode:'',timers:{}};
}
// 2026-07-24 對外查證官方 help.mikrotik.com「DHCP」/「IP Pools」/「DNS」文件後整段重寫：原本
// 回傳的資料形狀 {name,interface,status,leaseTime,type} 與其餘 12 廠牌共用的
// {name,network,gateway,dns,range,excluded,interface,lease,type,relayServer} 完全不相容
// （UI 表格對應欄位一律顯示 "—"），leaseTime 更是寫死常數 600、從未真正解析。真實 RouterOS
// DHCP Server 設定拆成三個關聯區塊："/ip pool"(位址範圍)、"/ip dhcp-server"(interface 綁定+
// lease-time，靠 address-pool= 引用 pool 名稱)、"/ip dhcp-server network"(gateway/dns/
// next-server/boot-file-name/ntp-server，與 dhcp-server 之間沒有直接命名關聯欄位，官方文件
// 確認純靠 CIDR 網段涵蓋比對決定要套用哪一筆 network)。excluded 沒有獨立官方欄位（官方文件
// 全文查無 "excluded" 相關關鍵字），是靠 pool 的 ranges= 多組逗號分隔範圍之間的間隙達成同等
// 效果，不臆測欄位，range 改為完整列出全部範圍。Option82 (add-relay-info/relay-info-remote-id)
// 查證確認掛在 "/ip dhcp-relay"（獨立於 dhcp-server 的 Relay 角色），非 dhcp-server 底下。
function parseRouterOSDHCP(cfg){
  const pools=[];
  const ipNum=ip=>ip.split('.').reduce((n,o)=>(n<<8)+parseInt(o,10),0)>>>0;
  const inCidr=(ip,cidr)=>{
    const parts=cidr.split('/');
    if(parts.length!==2||!ip)return false;
    const bits=parseInt(parts[1]);
    const mask=bits<=0?0:(~0<<(32-bits))>>>0;
    return (ipNum(ip)&mask)===(ipNum(parts[0])&mask);
  };
  const sectionBlock=name=>(cfg.match(new RegExp('^'+name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\s*\\n([\\s\\S]*?)(?=^\\/|(?![\\s\\S]))','m'))||[])[1]||'';

  // 1) /ip pool：位址範圍（ranges= 可逗號分隔多組）
  const roPools=[];
  for(const line of sectionBlock('/ip pool').split('\n')){
    if(!/^add\s/.test(line))continue;
    const name=(line.match(/\bname=(\S+)/)||[])[1]||'';
    const rangesRaw=(line.match(/\branges=(\S+)/)||[])[1]||'';
    if(!name)continue;
    roPools.push({name,ranges:rangesRaw.split(',').filter(Boolean)});
  }

  // 2) /ip dhcp-server network：gateway/dns/next-server/boot-file-name/ntp-server，供 CIDR 涵蓋比對
  const networks=[];
  for(const line of sectionBlock('/ip dhcp-server network').split('\n')){
    if(!/^add\s/.test(line))continue;
    const address=(line.match(/\baddress=(\S+)/)||[])[1]||'';
    if(!address)continue;
    networks.push({
      address,
      gateway:(line.match(/\bgateway=(\S+)/)||[])[1]||'',
      dns:((line.match(/\bdns-server=(\S+)/)||[])[1]||'').split(',').filter(Boolean),
      nextServer:(line.match(/\bnext-server=(\S+)/)||[])[1]||'',
      bootFile:(line.match(/\bboot-file-name=(\S+)/)||[])[1]||'',
      ntpServer:((line.match(/\bntp-server=(\S+)/)||[])[1]||'').split(',')[0]||'',
    });
  }

  // 3) /ip dhcp-server：interface/lease-time，靠 address-pool= 名稱關聯 pool
  for(const line of sectionBlock('/ip dhcp-server').split('\n')){
    if(!/^add\s/.test(line))continue;
    const name=(line.match(/\bname=(\S+)/)||[])[1]||'';
    const iface=(line.match(/\binterface=(\S+)/)||[])[1]||'';
    const poolName=(line.match(/\baddress-pool=(\S+)/)||[])[1]||'';
    const lease=(line.match(/\blease-time=(\S+)/)||[])[1]||'';
    const pool=roPools.find(p=>p.name===poolName);
    const ranges=pool?pool.ranges:[];
    const firstLow=ranges.length?ranges[0].split('-')[0]:'';
    const net=firstLow?networks.find(n=>inCidr(firstLow,n.address)):null;
    pools.push({name:name||poolName||'dhcp',network:net?net.address:'',
      gateway:net?net.gateway:'',dns:net?net.dns:[],range:ranges.join('; '),excluded:'',
      interface:iface,lease,bootFile:net?net.bootFile:'',nextServer:net?net.nextServer:'',
      ntpServer:net?net.ntpServer:'',type:'server'});
  }

  // 4) /ip dhcp-relay：獨立於 Server 角色，dhcp-server= 可逗號分隔多筆轉發目標
  for(const line of sectionBlock('/ip dhcp-relay').split('\n')){
    if(!/^add\s/.test(line))continue;
    const iface=(line.match(/\binterface=(\S+)/)||[])[1]||'';
    const name=(line.match(/\bname=(\S+)/)||[])[1]||iface;
    const option82=/\badd-relay-info=yes\b/.test(line);
    const servers=((line.match(/\bdhcp-server=(\S+)/)||[])[1]||'').split(',').filter(Boolean);
    servers.forEach(srv=>pools.push({name:'relay:'+name,network:'',gateway:'',dns:[],
      range:'',excluded:'',interface:iface,lease:'',type:'relay',relayServer:srv,option82}));
  }

  return pools;
}
// QoS：2026-07-19 對外查證官方 help.mikrotik.com「Queues」頁確認 RouterOS 有兩套獨立
// 機制：/queue simple（單一 target 的頻寬限制，max-limit/limit-at 皆為 "上傳/下載"
// 兩值斜線分隔格式）與 /queue tree（階層式 parent/child，僅支援 max-limit，真實用法
// 常需搭配 /ip firewall mangle 打包標記＋packet-mark 篩選，本專案簡化為只支援
// parent+max-limit，不自動產生 mangle 規則，此為已知限制）。與其餘廠牌共用的
// policy-map QoS 形狀完全不相容，改用專屬形狀（比照 Brocade/Extreme QoS 前例）
function parseRouterOSQoS(cfg){
  const simpleQueues=[];
  const sBlock=cfg.match(/^\/queue\s+simple\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  (sBlock?sBlock[1].split('\n'):[]).filter(l=>/^add\s/.test(l)).forEach(l=>{
    const name=(l.match(/\bname=(\S+)/)||[])[1]||'';
    if(!name)return;
    const target=(l.match(/\btarget=(\S+)/)||[])[1]||'';
    const maxLimit=(l.match(/\bmax-limit=(\S+)/)||[])[1]||'';
    const limitAt=(l.match(/\blimit-at=(\S+)/)||[])[1]||'';
    const[maxUp,maxDown]=maxLimit?maxLimit.split('/'):['',''];
    const[atUp,atDown]=limitAt?limitAt.split('/'):['',''];
    simpleQueues.push({name,target,maxLimitUp:maxUp||'',maxLimitDown:maxDown||'',limitAtUp:atUp||'',limitAtDown:atDown||''});
  });
  const queueTree=[];
  const tBlock=cfg.match(/^\/queue\s+tree\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  (tBlock?tBlock[1].split('\n'):[]).filter(l=>/^add\s/.test(l)).forEach(l=>{
    const name=(l.match(/\bname=(\S+)/)||[])[1]||'';
    if(!name)return;
    const parent=(l.match(/\bparent=(\S+)/)||[])[1]||'';
    const maxLimit=(l.match(/\bmax-limit=(\S+)/)||[])[1]||'';
    queueTree.push({name,parent,maxLimit});
  });
  return{simpleQueues,queueTree};
}
function parseRouterOSUsers(cfg){
  const users=[];
  let inUser=false;
  for(const line of cfg.split('\n')){
    if(/^\/user\b/.test(line)){inUser=true;continue;}
    if(/^\//.test(line)&&!/^\/user/.test(line))inUser=false;
    if(!inUser)continue;
    const nm=line.match(/add\s+name=([^\s]+)/);
    const gm=line.match(/group=([^\s]+)/);
    if(nm)users.push({username:nm[1],group:gm?gm[1]:'full',privilege:''});
  }
  return users;
}
// RIP：2026-07-19 對外查證官方 help.mikrotik.com「/routing/rip」頁確認 RouterOS v7 用
// `/routing rip instance add name=NAME redistribute=...`（無 network 陳述式）＋
// `/routing rip interface-template add instance=NAME interfaces=...` 逐介面宣告啟用，
// 比照既有 OSPF/BGP（`parseRouterOSOSPF`/`parseRouterOSBGP`）的 instance+template 區塊
// 解析慣例；回傳沿用既有共用 RIP 形狀，`networks` 欄位重新詮釋為「啟用介面清單」
// （比照 Brocade RIP 前例，因 RouterOS v7 本來就無 CIDR network 陳述式概念）
function parseRouterOSRIP(cfg){
  const instBlock=cfg.match(/^\/routing\s+rip\s+instance\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  if(!instBlock)return[];
  const instLine=(instBlock[1].split('\n').find(l=>/^add\s/.test(l))||'');
  const name=(instLine.match(/\bname=(\S+)/)||[])[1]||'default';
  const redist=(instLine.match(/\bredistribute=(\S+)/)||[])[1];
  const redistribute=redist?redist.split(','):[];

  const networks=[];
  const tmplBlock=cfg.match(/^\/routing\s+rip\s+interface-template\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  (tmplBlock?tmplBlock[1].split('\n'):[]).filter(l=>/^add\s/.test(l)).forEach(l=>{
    const instRef=(l.match(/\binstance=(\S+)/)||[])[1]||'';
    if(instRef&&instRef!==name)return;
    const ifaces=(l.match(/\binterfaces=(\S+)/)||[])[1]||'';
    if(ifaces)ifaces.split(',').forEach(i=>networks.push(i));
  });

  return[{pid:name,networks,redistribute}];
}
// VRRP：2026-07-19 對外查證官方 help.mikrotik.com「VRRP」頁確認語法為 `/interface vrrp
// add interface=IFACE vrid=N priority=N {preemption-mode=no}`；VRRP 介面本身不帶 IP，
// VIP 需另外在 `/ip address` 區塊以 `interface=vrrpN`（RouterOS 未顯式指定 name= 時的
// 預設循序邏輯介面命名）宣告；preempt 預設啟用，僅顯式 `preemption-mode=no` 才關閉。
// 沿用既有共用 parseVRRP() dispatcher 的記錄形狀（`interface` 而非 `vlanId` 欄位，比照
// Cisco/Aruba/NX-OS 等既有分支慣例），但走 `parseRouterOS()` 自己回傳物件直接設定——
// 通用 dispatcher 沒有 routeros 分支，`parseAndImport()` 的 `vrrpBypass` 清單早已預先
// 納入 'routeros'（改讀 parsed.vrrp），只是先前 vrrp 欄位本身尚未真正解析（固定回傳 []）
function _parseVRRPRouterOS(cfg){
  const groups=[];
  const block=cfg.match(/^\/interface\s+vrrp\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  if(!block)return groups;
  const addrBlock=cfg.match(/^\/ip\s+address\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  const vipByVrrpIface={};
  (addrBlock?addrBlock[1].split('\n'):[]).filter(l=>/^add\s/.test(l)).forEach(l=>{
    const ifaceM=l.match(/\binterface=(vrrp\d+)/);
    if(!ifaceM)return;
    const addrM=l.match(/\baddress=([^\s\/]+)/);
    if(addrM)vipByVrrpIface[ifaceM[1]]=addrM[1];
  });
  // IPv6（2026-08-17 新增，官方 MikroTik VRRP 文件確認 `v3-protocol=ipv6` 旗標區分
  // IPv6 執行個體，VIP 改由 `/ipv6 address` 宣告，與既有 `/ip address` 反查機制對稱）
  const addr6Block=cfg.match(/^\/ipv6\s+address\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  const vipByVrrpIface6={};
  (addr6Block?addr6Block[1].split('\n'):[]).filter(l=>/^add\s/.test(l)).forEach(l=>{
    const ifaceM=l.match(/\binterface=(vrrp\d+)/);
    if(!ifaceM)return;
    const addrM=l.match(/\baddress=([^\s\/]+)/);
    if(addrM)vipByVrrpIface6[ifaceM[1]]=addrM[1];
  });
  let idx=0;
  block[1].split('\n').filter(l=>/^add\s/.test(l)).forEach(l=>{
    idx++;
    const iface=(l.match(/\binterface=(\S+)/)||[])[1]||'';
    const vrid=(l.match(/\bvrid=(\S+)/)||[])[1]||'';
    if(!iface||!vrid)return;
    const priority=(l.match(/\bpriority=(\d+)/)||[])[1]||'100';
    const preempt=!/preemption-mode=no/.test(l);
    const nameM=l.match(/\bname=(\S+)/);
    const vrrpIfaceName=nameM?nameM[1]:'vrrp'+idx;
    const isV6=/\bv3-protocol=ipv6/.test(l);
    const vip=isV6?'':(vipByVrrpIface[vrrpIfaceName]||'');
    const vip6=isV6?(vipByVrrpIface6[vrrpIfaceName]||''):'';
    groups.push({vrid,interface:iface,vip,vip6,priority,preempt,authMode:'',trackIf:'',trackReduced:'',version:'2'});
  });
  return groups;
}
function parseRouterOS(cfg){
  const sys=parseRouterOSSysInfo(cfg);
  const rosVlans=parseRouterOSVLANs(cfg), rosInterfaces=parseRouterOSInterfaces(cfg);
  const rosLacp=parseRouterOSLACP(cfg);
  applyRouterOSVlanMembership(rosVlans,rosInterfaces,rosLacp);
  return{
    sys,irf:null,stack:null,
    vlans:rosVlans,
    interfaces:rosInterfaces,
    lacp:rosLacp,
    routes:parseRouterOSRoutes(cfg),vrfs:[],
    users:parseRouterOSUsers(cfg),
    ospf:parseRouterOSOSPF(cfg),
    bgp:parseRouterOSBGP(cfg),
    rip:parseRouterOSRIP(cfg),vrrp:_parseVRRPRouterOS(cfg),vxlan:null,
    dhcp:parseRouterOSDHCP(cfg),
    stp:parseRouterOSBridgeSTP(cfg),
    qos:parseRouterOSQoS(cfg),
    vendor:'routeros',_ccrInfo:sys.isCCR?{model:sys.hostname}:null
  };
}


// ═ Alcatel OmniSwitch AOS Parser ═
// ════════════════════════════════════════════════════════════
//  Alcatel-Lucent OmniSwitch AOS Parser
//  Unique markers: "-> " command prefix, "vlan N enable name",
//  "ip interface NAME", "linkagg lacp", "ip ospf", "ip bgp"
// ════════════════════════════════════════════════════════════

