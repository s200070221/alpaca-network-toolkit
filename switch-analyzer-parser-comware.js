const cidrFromMask=m=>{const t={'255.255.255.0':'24','255.255.255.128':'25','255.255.255.192':'26','255.255.255.224':'27','255.255.255.240':'28','255.255.255.248':'29','255.255.255.252':'30','255.255.0.0':'16','255.0.0.0':'8','0.0.0.0':'0','255.255.128.0':'17','255.255.192.0':'18','255.255.224.0':'19','255.255.240.0':'20','255.255.248.0':'21','255.255.252.0':'22','255.255.254.0':'23','255.255.255.255':'32'};return t[m]||maskToCIDR(m)};

// Split cfg on "\n#\n" to get clean top-level sections
function getSections(cfg){return cfg.split('\n#\n').map(s=>s.trim()).filter(Boolean);}

function parseSysInfo(cfg){
  return{
    hostname:(cfg.match(/^\s*sysname\s+(\S+)/m)||[])[1]||'unknown',
    version:(cfg.match(/version\s+([^\n,#]+)/)||[])[1]?.trim()||'',
    irfDomain:(cfg.match(/irf domain\s+(\d+)/)||[])[1]||null,
  };
}

function parseIRF(cfg){
  // Fix: irf domain is optional (Comware default = 1).
  // Detect IRF by irf member OR irf-port presence, not only by irf domain.
  const dom=(cfg.match(/irf domain\s+(\d+)/)||[])[1];
  const hasIRF=dom||/irf member\s+\d+\s+priority/.test(cfg)||/^irf-port\s+\d+\/\d+/m.test(cfg);
  if(!hasIRF)return null;
  const irfDomain=dom||'1';
  const members=[]; let m;
  const mr=/irf member\s+(\d+)\s+priority\s+(\d+)/g;
  while((m=mr.exec(cfg))!==null)members.push({id:m[1],priority:parseInt(m[2])});
  members.sort((a,b)=>b.priority-a.priority);
  members.forEach((mem,i)=>mem.role=i===0?'Master':'Standby');
  members.sort((a,b)=>parseInt(a.id)-parseInt(b.id));

  // Use section-based approach to correctly isolate each irf-port block
  const sections=getSections(cfg);
  const links=[];
  for(const sec of sections){
    const pm=sec.match(/^irf-port\s+(\d+\/\d+)/);
    if(!pm)continue;
    const portId=pm[1];
    const pts=[];const pg=/port group interface\s+(\S+)/g;let pm2;
    while((pm2=pg.exec(sec))!==null)pts.push(pm2[1]);
    const shortPts=pts.map(p=>p.replace(/^(?:Ten-?GigabitEthernet|FortyGigE|HundredGigE|GigabitEthernet)/i,''));
    links.push({id:portId,ports:pts,shortPorts:shortPts,fromMember:portId.split('/')[0]});
  }
  return{domain:irfDomain,members,links,
    autoUpdate:/irf auto-update enable/.test(cfg),
    macPersist:/irf mac-address persistent/.test(cfg),
    macPersistMode:(cfg.match(/irf mac-address persistent\s+(\S+)/)||[])[1]||'',
  };
}

function parseVLANs(cfg){
  const vlans=[];
  const sections=getSections(cfg);
  for(const sec of sections){
    const vm=sec.match(/^vlan\s+(\d+)\s*$/m);
    if(!vm)continue;
    const id=vm[1];
    const name=(sec.match(/^\s*name\s+(.+)/m)||[])[1]?.trim()||'';
    const ipSubnets=[]; let m;
    const isr=/ip-subnet-vlan\s+\d+\s+ip\s+([\d.]+)\s+([\d.]+)/g;
    while((m=isr.exec(sec))!==null)ipSubnets.push({network:m[1],mask:m[2],cidr:m[1]+'/'+cidrFromMask(m[2])});
    vlans.push({id,name,ipSubnets});
  }
  vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return vlans;
}

// Fix 2: Collect VLAN IDs referenced in interfaces but not globally declared
function collectImpliedVLANs(vlans, interfaces){
  const existing=new Set(vlans.map(v=>v.id));
  const implied=[];
  for(const iface of interfaces){
    const ids=[];
    if(iface.vlans){
      const raw=iface.vlans.replace(/\s+to\s+/gi,'-').split(/[,\s]+/);
      for(const tok of raw){
        if(tok.includes('-')){const [a,b]=tok.split('-').map(Number);if(!isNaN(a)&&!isNaN(b))for(let i=a;i<=b;i++)ids.push(String(i));}
        else if(/^\d+$/.test(tok))ids.push(tok);
      }
    }
    if(iface.nativeVlan)ids.push(iface.nativeVlan);
    if(iface.hybrid){
      ids.push(...iface.hybrid.untagged,...iface.hybrid.tagged);
      if(iface.hybrid.pvid)ids.push(iface.hybrid.pvid);
    }
    for(const id of ids){
      if(id&&!existing.has(id)&&!implied.find(v=>v.id===id)){
        existing.add(id);implied.push({id,name:'',ipSubnets:[],implied:true});
      }
    }
  }
  implied.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return implied;
}

// H3C 官方 vlan-id-list 語法允許用 "to" 表示範圍（如 "2 to 4 6 to 8"），先前字元類別
// [\d ]+ 只接受數字與空白，遇到 "to" 會讓整個正則完全比對失敗（連前面能匹配的部分都因為
// 無法到達結尾的 untagged/tagged 字面值而整體落空），VLAN 清單靜默清空為空陣列
// （2026-09-02 全功能審查發現）；比照同檔案 collectImpliedVLANs() 既有處理 iface.vlans
// 的 "to"→"-" 轉換+展開邏輯
function expandComwareHybridVlanList(str){
  const ids=[];
  const raw=(str||'').replace(/\s+to\s+/gi,'-').trim().split(/[,\s]+/);
  for(const tok of raw){
    if(tok.includes('-')){const [a,b]=tok.split('-').map(Number);if(!isNaN(a)&&!isNaN(b))for(let i=a;i<=b;i++)ids.push(String(i));}
    else if(/^\d+$/.test(tok))ids.push(tok);
  }
  return ids;
}
function parseHybrid(blk){
  const pvid=(blk.match(/port hybrid pvid vlan\s+(\d+)/)||[])[1]||'';
  const untagged=[],tagged=[]; let m;
  const ur=/port hybrid vlan\s+([\d ]+(?:to[\d\s]+)*)\s+untagged/g;
  while((m=ur.exec(blk))!==null)untagged.push(...expandComwareHybridVlanList(m[1]));
  const tr=/port hybrid vlan\s+([\d ]+(?:to[\d\s]+)*)\s+tagged/g;
  while((m=tr.exec(blk))!==null)tagged.push(...expandComwareHybridVlanList(m[1]));
  const hasIPSub=/ip subscriber-vlan/.test(blk);
  const vlanMaps=[]; const vmr=/vlan-mapping vlan\s+(\d+)\s+inner-vlan\s+(\d+)/g;
  while((m=vmr.exec(blk))!==null)vlanMaps.push({outer:m[1],inner:m[2]});
  const hasQinQ=/vlan-vpn enable/.test(blk);
  return{
    pvid,
    untagged:[...new Set(untagged)],
    tagged:[...new Set(tagged)],
    hasIPSub,vlanMaps,hasQinQ,
  };
}

function parseInterfaces(cfg){
  // Merge duplicate interface blocks (same name can appear twice in Comware)
  const raw=cfg.split('\ninterface ');
  const merged={};  // name → combined body
  for(const blk of raw.slice(1)){
    const lines=blk.split('\n');
    const name=lines[0].trim();
    let body=lines.slice(1).join('\n');
    // 每個 interface 區塊在 Comware 語法中都以獨立一行 "#" 終止；naive split('\ninterface ')
    // 對「檔案中最後一次出現的區塊」沒有下一個 "interface " 可以自然定界，body 會一路延伸
    // 吃進後續不相干區塊（如 ip vpn-instance 自己的 description），誤植進本介面的欄位值
    // （2026-09-02 全功能審查發現，用真實 comware_test.cfg 的 GigabitEthernet1/0/6 重現：
    // 該介面本身無 description，卻被 30 行之後的 ip vpn-instance VRF-MGMT 污染）
    const hashIdx=body.search(/\n#\s*(\n|$)/);
    if(hashIdx!==-1)body=body.slice(0,hashIdx);
    merged[name]=merged[name]?merged[name]+'\n'+body:body;
  }

  const ifaces=[];
  for(const [name,blk] of Object.entries(merged)){
    const desc=(blk.match(/^\s*description\s+(.+)/m)||[])[1]?.trim()||'';
    const shutdown=/\bshutdown\b/.test(blk)&&!/undo shutdown/.test(blk);
    const rawMem=name.replace(/[A-Za-z\-]+/g,'');
    const mem=(rawMem.match(/^(\d+)\//)||[])[1]||'1';

    if(/^NULL/i.test(name)){
      ifaces.push({name,type:'null',desc,ip:'',mode:'',vlans:'',nativeVlan:'',vrf:'',shutdown,member:'0',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    // 次要IP（Secondary IP，官方 H3C IP addressing commands 文件：`ip address A B
    // sub`，僅 VLAN-interface／Loopback，不涵蓋一般物理埠；2026-08-17 從「僅取第一筆」
    // 擴大為完整收集）
    const secondaryIps=[...blk.matchAll(/^\s*ip address\s+(\S+)\s+(\S+)\s+sub/gm)].map(m=>m[1]+'/'+cidrFromMask(m[2]));
    if(/^Vlan-interface/i.test(name)){
      const ipRaw=(blk.match(/^\s*ip address\s+(\S+)\s+(\S+)/m)||[]);
      let ip=ipRaw[1]&&ipRaw[2]?ipRaw[1]+'/'+cidrFromMask(ipRaw[2]):(blk.match(/^\s*ip address\s+([\d.]+\/\d+)/m)||[])[1]||'';
      // IPv6（試點 5 廠牌之一，官方語法 `ipv6 address ADDR/PREFIXLEN`，不需遮罩換算）
      if(!ip)ip=(blk.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，使用者提供真實 HPE 5720 去識別化設定檔驗證發現：同一 VLAN
      // 介面若同時設定 IPv4 與 IPv6（企業網路常見雙棧設定），原本 `if(!ip)` 判斷式會讓 IPv6
      // 位址被靜默丟棄，只剩 IPv4。新增獨立 ip6 欄位，不受 ip 是否已填的條件限制，兩者可並存；
      // 僅修 Comware 這一家，其餘已完成 IPv6 的廠牌有同一模式限制，非本輪範圍）
      const ip6=(blk.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      // vrf（2026-07-27 補上）：SVI 一樣支援 `ip binding vpn-instance NAME`（與下方實體埠
      // 分支用的是同一個真實 H3C 關鍵字），先前只有實體埠分支有解析，SVI 一律回傳空字串
      const vrf=(blk.match(/ip binding vpn-instance\s+(\S+)/)||[])[1]||'';
      const vrrpList=[]; let vvm;
      const vr=/vrrp vrid\s+(\d+)\s+virtual-ip\s+(\S+)/g;
      while((vvm=vr.exec(blk))!==null){
        const prio=(blk.match(new RegExp('vrrp vrid\\s+'+vvm[1]+'\\s+priority\\s+(\\d+)'))||[])[1]||'100';
        vrrpList.push({vrid:vvm[1],vip:vvm[2],priority:prio});
      }
      ifaces.push({name,type:'svi',desc,ip,ip6,secondaryIps,mode:'',vlans:'',nativeVlan:'',vrf,shutdown,member:'1',hybrid:null,vrrp:vrrpList,breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    if(/^LoopBack/i.test(name)){
      let ip=(blk.match(/^\s*ip address\s+(\S+\s+\S+)/m)||[])[1]||'';
      if(!ip)ip=(blk.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      // 雙棧修復（2026-08-13 新增，同上 VLAN 介面）
      const ip6=(blk.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
      ifaces.push({name,type:'loopback',desc,ip,ip6,secondaryIps,mode:'',vlans:'',nativeVlan:'',vrf:'',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }
    let mode='',vlans='',nativeVlan='',hybrid=null;
    // Fix 1: Also infer mode from sub-commands when port link-type is omitted
    if(/port link-type trunk/.test(blk)||(!/port link-type/.test(blk)&&/port trunk permit vlan/.test(blk))){
      mode='trunk';
      // Comware 實機常把 permit vlan 拆成多行（例如預設的 vlan 1 單獨一行，其餘 VLAN 另一行），
      // 用單次 match 只會抓到第一行，須用 global regex 收集全部行再合併
      const vlansArr=[]; let vtm;
      const vtRe=/port trunk permit vlan\s+([^\n#]+)/g;
      while((vtm=vtRe.exec(blk))!==null)vlansArr.push(vtm[1].trim());
      vlans=vlansArr.join(' ');
      // 2026-07-22 對外查證官方 H3C 文件後修正：`port trunk native-vlan` 不存在，
      // 真實關鍵字是 `port trunk pvid vlan`
      nativeVlan=(blk.match(/port trunk pvid vlan\s+(\d+)/)||[])[1]||'';
    }else if(/port link-type access/.test(blk)||(!/port link-type/.test(blk)&&/port access vlan/.test(blk))){
      mode='access';
      vlans=(blk.match(/port access vlan\s+(\d+)/)||[])[1]||'';
    }else if(/port link-type hybrid/.test(blk)||(!/port link-type/.test(blk)&&/port hybrid pvid/.test(blk))){
      mode='hybrid';
      hybrid=parseHybrid(blk);
      vlans=[...hybrid.untagged,...hybrid.tagged].filter((v,i,a)=>a.indexOf(v)===i).join(' ');
      nativeVlan=hybrid.pvid;
    }
    const vrf=(blk.match(/ip binding vpn-instance\s+(\S+)/)||[])[1]||'';
    // 修復（2026-08-13 新增，使用者提供真實檔案發現）：`\s+` 會吃到換行，若該埠是
    // `ip address dhcp-alloc`（單 token，如 M-GigabitEthernet 管理埠常見語法）而非雙 token
    // dotted-mask 格式，原正則會誤跨行吃到下一行 `ipv6 address ...` 的第一個字當作第二個
    // token，導致 ip 欄位混入垃圾字串；改用 `[ \t]+` 限制在同一行內，並保留單 token
    // fallback（如 dhcp-alloc）
    let ip=(blk.match(/^[ \t]*ip address[ \t]+(\S+[ \t]+\S+)/m)||[])[1]||(blk.match(/^[ \t]*ip address[ \t]+(\S+)/m)||[])[1]||'';
    if(!ip)ip=(blk.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
    // 雙棧修復（2026-08-13 新增，同上 VLAN 介面）
    const ip6=(blk.match(/^\s*ipv6 address\s+(\S+)/m)||[])[1]||'';
    const isStack=/Ten-GigabitEthernet|FortyGigE|HundredGigE/i.test(name);
    // Breakout: 母埠 interface 區塊內 `using tengige` 啟用（僅 FortyGigE→Ten-GigabitEthernet 這組已查證官方語法）
    const breakoutMode=/^\s*using\s+tengige\b/mi.test(blk)?'4x10G':'';
    const bkMatch=name.match(/^Ten-GigabitEthernet(\d+\/\d+\/\d+):([1-4])$/i);
    const breakoutChild=!!bkMatch;
    const breakoutParent=bkMatch?`FortyGigE${bkMatch[1]}`:'';
    ifaces.push({name,type:isStack?'stack':'physical',desc,mode,vlans:vlans.trim(),nativeVlan,vrf,ip,ip6,shutdown,member:mem,hybrid,vrrp:[],breakoutChild,breakoutParent,breakoutMode});
  }
  return ifaces;
}

function parseRoutes(cfg){
  const routes=[]; let m;
  // Fix 3: Support interface-name as next-hop (e.g. NULL0)
  // vrf（2026-08-08 查證修正）：H3C 官方 Command Reference 確認 "ip route-static [ vpn-instance
  // s-vpn-instance-name ] dest-address ..." 的 vpn-instance 子句緊接在關鍵字之後（該路由所屬
  // VRF），原本誤植為結尾子句，兩者查無任何真實裝置匯出檔可用來偵測混用，直接改對位置
  const re=/ip route-static(?:\s+vpn-instance\s+(\S+))?\s+(\S+)\s+(\S+)\s+(\S+)/g;
  while((m=re.exec(cfg))!==null){
    const vrf=m[1]||'';
    let dst,gw=m[4];
    if(m[3].match(/^\d+\.\d+\.\d+\.\d+$/)){dst=m[2]+'/'+cidrFromMask(m[3]);}
    else if(/^\d+$/.test(m[3])){dst=m[2]+'/'+m[3];}
    else{dst=m[2]+'/0';gw=m[3]+' '+m[4];}
    const gwIsInterface=gw&&!gw.match(/^\d+\.\d+\.\d+\.\d+/);
    routes.push({dst,gw,vrf,gwIsInterface});
  }
  // IPv6 靜態路由（2026-08-13 新增，使用者提供真實 HPE 5720 去識別化設定檔驗證）：官方語法
  // `ipv6 route-static ipv6-address prefix-length [vpn-instance NAME] next-hop`，prefix-length
  // 是數字（非遮罩），與 IPv4 版本三 token 形狀相同，真實檔案內 6 筆皆為此形式（含 `::` 當
  // 預設路由位址）。介面型 next-hop 官方文件有記載但無真實範例可驗證，比照 gwIsInterface
  // 既有慣例用內容判斷（含冒號視為 IPv6 位址，否則視為介面名稱）
  const re6=/ipv6 route-static(?:\s+vpn-instance\s+(\S+))?\s+(\S+)\s+(\d+)\s+(\S+)/g;
  while((m=re6.exec(cfg))!==null){
    const vrf=m[1]||'';
    const dst=m[2]+'/'+m[3];
    const gw=m[4];
    const gwIsInterface=!!gw&&!gw.includes(':');
    routes.push({dst,gw,vrf,gwIsInterface});
  }
  return routes;
}

function parseVRFs(cfg){
  const vrfs=[];
  const sections=getSections(cfg);
  for(const sec of sections){
    const vm=sec.match(/^ip vpn-instance\s+(\S+)/m);
    if(!vm)continue;
    const name=vm[1];
    const rd=(sec.match(/route-distinguisher\s+(\S+)/)||[])[1]||'';
    const importRoute=(sec.match(/import-route\s+([^\n]+)/)||[])[1]?.trim()||'';
    vrfs.push({name,rd,importRoute});
  }
  return vrfs;
}

function parseUsers(cfg){
  const users=[];
  const sections=getSections(cfg);
  for(const sec of sections){
    const um=sec.match(/^local-user\s+(\S+)/m);
    if(!um)continue;
    const name=um[1];
    const role=(sec.match(/user-role\s+(\S+)/)||[])[1]||'';
    const svc=((sec.match(/service-type\s+([^\n]+)/)||[])[1]||'').trim();
    // Fix 4: Enhanced password security analysis
    const hasPwd=/password/.test(sec);
    let pwdType='none',pwdWeak=false;
    if(/password hash/.test(sec)||/password cipher/.test(sec)){pwdType='hash';}
    else if(/password simple/.test(sec)){pwdType='simple';pwdWeak=true;}
    else if(hasPwd){pwdType='set';}
    users.push({name,role,service:svc,hasPwd,pwdType,pwdWeak});
  }
  return users;
}

// SNMP community/v3 user 解析（2026-07-22 新增，13 廠牌逐一對外查證官方 CLI 文件後實作）。
// 資料形狀比照 firewall_analyzer 既有 parsed.snmp.communities:[{name}]／v3Users:[{name}]，
// 不重新設計 schema。稽核檢查只需要「v1/v2c community 是否存在」，v3 使用者清單為輔助資訊。
function parseSNMP(cfg, vendor){
  const communities=[], v3Users=[], hosts=[], seenC=new Set(), seenU=new Set(), seenH=new Set();
  const pushC=name=>{ if(name&&!seenC.has(name)){seenC.add(name);communities.push({name});} };
  const pushU=name=>{ if(name&&!seenU.has(name)){seenU.add(name);v3Users.push({name});} };
  const pushH=host=>{ if(host&&!seenH.has(host)){seenH.add(host);hosts.push({host});} };
  if(vendor==='comware'){
    // 官方 H3C Comware Login Management Commands 查證：
    // snmp-agent community {read|write} {simple|cipher} community-name
    let m; const reC=/^\s*snmp-agent\s+community\s+(?:read|write)\s+(?:simple|cipher)\s+(\S+)/gm;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
    const reU=/^\s*snmp-agent\s+usm-user\s+v3\s+(\S+)/gm;
    while((m=reU.exec(cfg))!==null)pushU(m[1]);
    // Trap host（2026-08-19 新增，對外查證官方 H3C SNMP Commands 確認）：
    // snmp-agent target-host trap address udp-domain ip-address [udp-port N] [dscp N]
    // params securityname security-string [v1|v2c|v3 ...]
    const reH=/^\s*snmp-agent\s+target-host\s+trap\s+address\s+udp-domain\s+(\S+)/gm;
    while((m=reH.exec(cfg))!==null)pushH(m[1]);
  }else if(vendor==='fortiswitch'){
    // 官方 FortiSwitchOS Administration Guide 查證：巢狀區塊語法
    // config system snmp community / edit N / set name "..." / next / end
    const blkC=(cfg.match(/^config system snmp community\n([\s\S]*?)^end\b/m)||[])[1]||'';
    let m; const reC=/set name\s+"?([^"\n]+)"?/g;
    while((m=reC.exec(blkC))!==null)pushC(m[1]);
    const blkU=(cfg.match(/^config system snmp user\n([\s\S]*?)^end\b/m)||[])[1]||'';
    const reEdit=/edit\s+"?([^"\n]+)"?/g;
    while((m=reEdit.exec(blkU))!==null)pushU(m[1]);
  }else if(vendor==='juniper'){
    // 官方 Junos SNMP Communities 查證：set snmp community NAME authorization ...
    let m; const reC=/set snmp community\s+(\S+)\s+authorization/g;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
    const reU=/set snmp v3 usm local-engine user\s+(\S+)/g;
    while((m=reU.exec(cfg))!==null)pushU(m[1]);
    // Trap host（2026-08-19 新增，對外查證官方 Junos SNMP Trap Groups 文件確認）：
    // set snmp trap-group NAME targets ip-address（community 即 trap-group 名稱本身）
    const reH=/set snmp trap-group\s+\S+\s+targets\s+(\S+)/g;
    while((m=reH.exec(cfg))!==null)pushH(m[1]);
  }else if(vendor==='alcatel'){
    // 官方 OmniSwitch CLI Reference 查證：snmp community map NAME [user ...] enable
    // （v3 使用者語法官方文件未能取得逐字確認，比照專案慣例不臆測，僅做 community）
    let m; const reC=/->?\s*snmp community map\s+(\S+)/g;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
    // Trap host（2026-08-19 新增，對外查證官方 OmniSwitch AOS CLI Reference 真實範例確認）：
    // snmp station ip-address [port] "user" v1|v2c|v3 enable
    const reH=/->?\s*snmp station\s+(\S+)/g;
    while((m=reH.exec(cfg))!==null)pushH(m[1]);
  }else if(vendor==='extreme'){
    // 官方 ExtremeXOS Command Reference 查證：
    // configure snmp add community {readonly|readwrite} NAME
    let m; const reC=/configure\s+snmp\s+add\s+community\s+(?:readonly|readwrite)\s+(\S+)/g;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
    const reU=/configure\s+snmpv3\s+add\s+user\s+(\S+)/g;
    while((m=reU.exec(cfg))!==null)pushU(m[1]);
    // Trap host（2026-08-19 新增，對外查證官方 ExtremeXOS Command Reference 確認，v1/v2c
    // 簡易版，與同批查證發現的 SNMPv3 target-addr 機制（需額外 target-params 交叉引用）
    // 分屬不同複雜度，此為與既有 community 語法家族（v1/v2c）相符的版本）：
    // configure snmp add trapreceiver ip-address community community-name
    const reH=/configure\s+snmp\s+add\s+trapreceiver\s+(\S+)/g;
    while((m=reH.exec(cfg))!==null)pushH(m[1]);
  }else if(vendor==='routeros'){
    // 官方 RouterOS SNMP 文件查證：/snmp community add name=NAME ...（v7 統一 v1/v2c/v3
    // 於同一物件，含 authentication-protocol=／security=authPriv|private 視為 v3）
    let m; const re=/\/snmp community add\s+([^\n]+)/g;
    while((m=re.exec(cfg))!==null){
      const line=m[1];
      const nameM=/name=(\S+)/.exec(line);
      if(!nameM)continue;
      const isV3=/authentication-protocol=|security=(private|authpriv)/i.test(line);
      if(isV3)pushU(nameM[1]); else pushC(nameM[1]);
    }
    // Trap host（2026-08-19 新增，中高信心：官方文件確認 trap-target/trap-community 為
    // /snmp 單例選單下的真實屬性，但官方文件本身未附完整逐字 set 指令範例，比照 /snmp
    // 選單本身唯一有範例的 "set enabled yes" 語法慣例推得；trap-target 為 list 型別，
    // 可能逗號分隔多筆）
    const reH=/\/snmp\s+set\s+[^\n]*trap-target=([^\s,]+)/g;
    while((m=reH.exec(cfg))!==null)pushH(m[1]);
  }else if(vendor==='procurve'){
    // 官方 ArubaOS-Switch (AOS-S) MCG 查證：snmp-server community STRING [operator|manager]。
    // 2026-07-22 對外查證真實 HPE 5412zl 匯出檔後修正：字串值真實常見帶雙引號包裹
    // （如 snmp-server community "public" unrestricted），原本 \S+ 會把引號字元一併
    // 抓進 community 名稱（"public" 含引號），改用可選雙引號的擷取群組去除引號
    let m; const reC=/^\s*snmp-server\s+community\s+"?([^"\s]+)"?/gm;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
    const reU=/^\s*snmpv3\s+user\s+(\S+)/gm;
    while((m=reU.exec(cfg))!==null)pushU(m[1]);
    // Trap host（2026-08-19 新增，對外查證官方 ArubaOS-Switch (AOS-S) MCG 真實範例確認）：
    // snmp-server host ip-address "community" [trap-level LEVEL]
    const reH=/^\s*snmp-server\s+host\s+(\S+)/gm;
    while((m=reH.exec(cfg))!==null)pushH(m[1]);
  }else if(vendor==='aruba'){
    // 官方 AOS-CX SNMP 命令查證：snmp-server community STRING（無 ro/rw 關鍵字）；
    // v3 使用者無 "v3" 標記字面，snmp-server user NAME auth ... 即代表 v3
    let m; const reC=/^\s*snmp-server\s+community\s+(\S+)/gm;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
    const reU=/^\s*snmp-server\s+user\s+(\S+)\s+auth\b/gm;
    while((m=reU.exec(cfg))!==null)pushU(m[1]);
    // Trap host（2026-08-19 新增，對外查證官方 AOS-CX 文件真實範例確認）：
    // snmp-server host ip-address trap version {v1|v2c|v3} [community STRING]
    const reH=/^\s*snmp-server\s+host\s+(\S+)\s+trap\b/gm;
    while((m=reH.exec(cfg))!==null)pushH(m[1]);
  }else if(vendor==='edgeswitch'){
    // 官方 Ubiquiti EdgeSwitch Command Reference 查證（高信心）：
    // snmp-server community NAME [ro|rw|su] [ipaddress ip-address] [view view-name]
    // 2026-08-20 從共用 else 分支移出成明確分支（原本落入 else 分支意外湊巧命中，
    // 因為真實語法恰好也是 "snmp-server community NAME" 開頭；v3/trap host 本輪未查證）
    let m; const reC=/^\s*snmp-server\s+community\s+(\S+)/gm;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
  }else if(vendor==='ruijie'){
    // 官方 RGOS Command Reference 查證（中高信心）：
    // snmp-server community community-string {ro|rw} [acl-number]
    // 2026-08-20 從共用 else 分支移出成明確分支（原理由同 edgeswitch）
    let m; const reC=/^\s*snmp-server\s+community\s+(\S+)/gm;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
  }else if(vendor==='netgear'){
    // 官方 Netgear M4300 CLI Command Reference 查證（中高信心）：
    // snmp-server community NAME {ro|rw} ipaddress ip-address ipmask mask
    // 2026-08-20 從共用 else 分支移出成明確分支（原理由同 edgeswitch；ipaddress/ipmask
    // 不進 communities schema，僅取名稱）
    let m; const reC=/^\s*snmp-server\s+community\s+(\S+)/gm;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
  }else{
    // cisco(IOS-XE)／dell-os10／nxos／arista／brocade(ICX) 共用同一套
    // "snmp-server community NAME [ro|rw]"／"snmp-server user NAME ... v3" 語法家族，
    // 皆已對外查證官方命令參考文件確認一致，共用同一組正則
    let m; const reC=/^\s*snmp-server\s+community\s+(\S+)/gm;
    while((m=reC.exec(cfg))!==null)pushC(m[1]);
    const reU=/^\s*snmp-server\s+user\s+(\S+)\s+\S+\s+v3\b/gm;
    while((m=reU.exec(cfg))!==null)pushU(m[1]);
    // Trap host（2026-08-19 新增，對外查證官方命令參考文件確認 5 家共用同一套
    // "snmp-server host ip-address ..." 語法：Cisco IOS/IOS-XE、NX-OS、Arista EOS、
    // Dell OS10（SmartFabric OS10 User Guide）、Ruckus/Brocade FastIron 皆一致）
    const reH=/^\s*snmp-server\s+host\s+(\S+)/gm;
    while((m=reH.exec(cfg))!==null)pushH(m[1]);
  }
  return {communities,v3Users,hosts};
}
// Syslog 伺服器解析（2026-08-19 新增第一階段 6 家；2026-08-20 對外查證後擴大剩餘 11 家，
// 17 家全數涵蓋，sonic 除外——sonic 走 parseSONiC()/_parseSyslogSONiC() 專屬 JSON 表格
// 解析，parseAny() 已排除不呼叫本函式，避免真實結果被此處的文字正則空結果覆蓋）：
// - cisco(IOS-XE)／arista／brocade(FastIron)：logging host ip-address [udp-port N]
// - nxos／dell-os10：logging server host [severity-level ...]（關鍵字為 server 非 host，
//   與上一組語法家族不同，官方文件已個別查證確認）
// - comware：info-center loghost host-ip [port N] [channel ... | facility local-number]
function parseSyslog(cfg, vendor){
  const servers=[], seen=new Set();
  const push=(host,facility)=>{ if(host&&!seen.has(host)){seen.add(host);servers.push({host,facility:facility||''});} };
  if(vendor==='comware'){
    let m; const re=/^\s*info-center\s+loghost\s+(\S+)(?:[^\n]*?facility\s+(local\d))?/gm;
    while((m=re.exec(cfg))!==null)push(m[1],m[2]);
  }else if(vendor==='nxos'||vendor==='dell-os10'){
    let m; const re=/^\s*logging\s+server\s+(\S+)/gm;
    while((m=re.exec(cfg))!==null)push(m[1]);
  }else if(vendor==='cisco'||vendor==='arista'||vendor==='brocade'){
    let m; const re=/^\s*logging\s+host\s+(\S+)/gm;
    while((m=re.exec(cfg))!==null)push(m[1]);
  }else if(vendor==='extreme'){
    // 官方 ExtremeXOS Command Reference 查證（高信心）：
    // configure syslog add {ipaddress[:port] | ipaddress tls_port N} {vr NAME} [localN]
    // IP 與 port 若同時存在會以冒號連接，取冒號前段避免 port 誤併入 IP；facility 為行尾
    // 可選 local0-7 字面值
    let m; const re=/configure\s+syslog\s+add\s+([^\s:]+)(?:[^\n]*?\b(local\d)\s*$)?/gm;
    while((m=re.exec(cfg))!==null)push(m[1],m[2]);
  }else if(vendor==='procurve'){
    // 官方 ArubaOS-Switch (AOS-S) MCG 查證（高信心）：logging ip-address [udp|tcp port]
    // severity/facility 為全域指令（"logging severity"/"logging facility"），非本行參數，
    // 需明確排除避免誤把這兩個關鍵字當成 host 擷取
    let m; const re=/^\s*logging\s+(?!facility\b|severity\b)(\S+)/gm;
    while((m=re.exec(cfg))!==null)push(m[1]);
  }else if(vendor==='aruba'){
    // 官方 AOS-CX logging 命令參考查證（高信心）：
    // logging TARGET [udp|tcp|tls port] [severity LEVEL] [vrf NAME] [filter NAME] ...
    // 與 ProCurve 分屬不同 vendor 分支，不會互相污染
    let m; const re=/^\s*logging\s+(\S+)/gm;
    while((m=re.exec(cfg))!==null)push(m[1]);
  }else if(vendor==='edgeswitch'||vendor==='netgear'){
    // 官方 EdgeSwitch Command Reference 查證（EdgeSwitch 高信心／Netgear 中信心，同一
    // Broadcom ICOS 平台推論，與既有 hostname/LACP 共用慣例一致）：
    // logging host hostaddress {ipv4|ipv6|dns} port severitylevel
    let m; const re=/^\s*logging\s+host\s+(\S+)/gm;
    while((m=re.exec(cfg))!==null)push(m[1]);
  }else if(vendor==='ruijie'){
    // 官方 RGOS Command Reference 查證（高信心）：logging ip-address（單行，另有獨立的
    // "logging trap severity" 全域嚴重等級指令，需明確排除避免誤把 trap 當成 host 擷取）
    let m; const re=/^\s*logging\s+(?!trap\b)(\S+)/gm;
    while((m=re.exec(cfg))!==null)push(m[1]);
  }else if(vendor==='juniper'){
    // 官方 Junos System Logging 文件查證（高信心）：階層式
    // system { syslog { host ip-address { facility severity; } } }
    // parseJuniper() 全檔案慣例僅支援階層式格式（無 flat "set" 語法），本處比照沿用同一
    // 慣例，重用已存在的平衡大括號 helper junosBlock()（定義於
    // switch-analyzer-parser-juniper.js，載入後為全域函式，此處可直接呼叫）
    const blk=typeof junosBlock==='function'?junosBlock(cfg,'syslog'):'';
    let m; const re=/^\s*host\s+(\S+)\s*\{/gm;
    while((m=re.exec(blk))!==null)push(m[1]);
  }else if(vendor==='fortiswitch'){
    // 官方 FortiSwitchOS CLI Reference 查證（高信心）：巢狀區塊語法，最多 3 組具名
    // target（syslogd/syslogd2/syslogd3），各自獨立 "set server" 一行
    // config log {syslogd|syslogd2|syslogd3} setting / set server "ip" / ... / end
    ['syslogd','syslogd2','syslogd3'].forEach(name=>{
      const blkRe=new RegExp('^config log '+name+'\\s+setting\\n([\\s\\S]*?)^end\\b','m');
      const blk=(cfg.match(blkRe)||[])[1]||'';
      const m=/set\s+server\s+"?([^"\n]+)"?/.exec(blk);
      if(m)push(m[1]);
    });
  }else if(vendor==='alcatel'){
    // Alcatel-Lucent OmniSwitch (AOS) CLI Reference 查證（中信心，僅第三方鏡射站取得
    // 原文，未見官方站台原文）：swlog output socket ip-address [remote command-log]
    let m; const re=/(?:->\s*)?swlog\s+output\s+socket\s+(\S+)/gm;
    while((m=re.exec(cfg))!==null)push(m[1]);
  }else if(vendor==='routeros'){
    // 官方 MikroTik RouterOS v7 文件查證（高信心）：兩段式，遠端 target 定義在
    // /system logging action，本身即可判斷是否為遠端 syslog server，不需要再關聯到
    // 引用它的 /system logging 規則那一行
    // /system logging action add name=NAME target=remote remote=ip-address ...
    let m; const re=/\/system logging action add\s+([^\n]+)/g;
    while((m=re.exec(cfg))!==null){
      const line=m[1];
      if(!/target=remote\b/.test(line))continue;
      const hostM=/remote=(\S+)/.exec(line);
      if(hostM)push(hostM[1]);
    }
  }
  return {servers};
}

// 管理介面 Telnet/SSH 存取解析（2026-07-22 新增，13 廠牌逐一對外查證官方 CLI 文件後實作）。
// 設計原則：查證結果顯示各廠牌「未設定時的預設行為」不同（有些預設兩者皆開放、有些預設
// 關閉），為求風險判斷貼近真實曝險，對「已查證預設為開放 telnet」的廠牌採「除非明確關閉
// 否則視為開放」；對「已查證預設關閉」或「預設未知」的廠牌則採「只認明確開啟」，避免無佐證
// 臆測導致誤報。ssh 欄位僅供輔助資訊，稽核檢查本身只判斷 telnet。
function parseMgmtAccess(cfg, vendor){
  let telnet=false, ssh=false;
  if(vendor==='comware'){
    // 官方 H3C Login Management Commands 查證：user-interface vty 下 protocol inbound
    // {telnet|ssh|all}，未設定時預設 all（兩者皆開放）
    const hasVty=/^user-interface\s+vty\b/m.test(cfg);
    const pm=/protocol inbound\s+(telnet|ssh|all)/i.exec(cfg);
    if(pm){ const v=pm[1].toLowerCase(); telnet=(v==='telnet'||v==='all'); ssh=(v==='ssh'||v==='all'); }
    else if(hasVty){ telnet=true; ssh=true; }
  }else if(vendor==='fortiswitch'){
    // 官方文件僅查得逐 interface allowaccess 清單語法，無單一全域開關；任一介面
    // allowaccess 含 telnet/ssh 即視為該介面開放（沿用 firewall_analyzer http-mgmt 慣例）
    telnet=/set allowaccess\s+[^\n]*\btelnet\b/i.test(cfg);
    ssh=/set allowaccess\s+[^\n]*\bssh\b/i.test(cfg);
  }else if(vendor==='juniper'){
    // 官方 Junos 查證：兩者預設皆關閉，須明確 set system services telnet/ssh 才開啟
    telnet=/^set system services telnet\b/m.test(cfg);
    ssh=/^set system services ssh\b/m.test(cfg);
  }else if(vendor==='aruba'){
    // 官方 AOS-CX 查證：telnet 預設關閉，須明確 telnet-server（非 no telnet-server）
    telnet=/^\s*telnet-server\b/m.test(cfg)&&!/^\s*no\s+telnet-server\b/m.test(cfg);
    ssh=/^\s*ssh server\b/m.test(cfg)&&!/^\s*no\s+ssh server\b/m.test(cfg);
  }else if(vendor==='cisco'||vendor==='ruijie'){
    // 官方 Cisco IOS-XE 查證：line vty 下 transport input {telnet|ssh|all|none}，
    // 未設定時原廠預設 all（兩者皆開放）。Ruijie RGOS 管理線路語法與 Cisco 同源，
    // 尚無真實範例逐字驗證，先併入同一套邏輯，信心度較低
    const hasVty=/^line vty\b/m.test(cfg);
    const tm=/transport input\s+([^\n]+)/i.exec(cfg);
    if(tm){ const v=tm[1].toLowerCase(); telnet=/\btelnet\b|\ball\b/.test(v); ssh=/\bssh\b|\ball\b/.test(v); }
    else if(hasVty){ telnet=true; ssh=true; }
  }else if(vendor==='dell-os10'){
    // 官方 Dell KB 查證：telnet 預設關閉、ssh 預設開啟，須明確 enable 才視為開放
    telnet=/^\s*ip telnet server enable\b/m.test(cfg);
    ssh=/^\s*ip ssh server enable\b/m.test(cfg);
  }else if(vendor==='nxos'){
    // 官方 Cisco NX-OS 查證：telnet 預設關閉，須明確 feature telnet
    telnet=/^\s*feature telnet\b/m.test(cfg);
    ssh=/^\s*feature ssh\b/m.test(cfg);
  }else if(vendor==='arista'){
    // 官方 Arista EOS 查證：telnet 預設關閉（shutdown），須 management telnet 子模式內
    // no shutdown 才視為開放；ssh 恆為開啟不需判斷
    const mtM=/^management telnet\n([\s\S]*?)(?=^\S|(?![\s\S]))/m.exec(cfg);
    telnet=!!(mtM&&/no shutdown/.test(mtM[1]));
    ssh=true;
  }else if(vendor==='brocade'){
    // 官方 Ruckus FastIron Security Guide 查證：telnet 預設開放，須明確 no telnet server
    // 才關閉；ssh 無單一全域開關（靠產生金鑰啟用），僅記錄金鑰產生指令是否存在
    telnet=!/^\s*no\s+telnet server\b/m.test(cfg);
    ssh=/crypto key generate rsa/i.test(cfg);
  }else if(vendor==='alcatel'){
    // 官方文件未查得明確預設值，僅認明確 admin-state enable
    telnet=/ip service telnet admin-state enable/i.test(cfg);
    ssh=/ip service ssh admin-state enable/i.test(cfg);
  }else if(vendor==='extreme'){
    // 官方 ExtremeXOS Command Reference 查證：telnet 預設開放，須明確 disable telnet
    telnet=!/^\s*disable telnet\b/m.test(cfg);
    ssh=/^\s*enable ssh2\b/m.test(cfg);
  }else if(vendor==='procurve'){
    // 官方 ArubaOS-Switch (AOS-S) 查證：telnet 預設開放，須明確 no telnet-server 才關閉。
    // 2026-07-22 補充查證：官方文件明確指出單獨執行 `ip ssh` 並不會真的啟用 SSH
    // （"Executing IP SSH does not enable SSH on the switch"），還需要先產生主機金鑰
    // （`crypto key generate ssh` 或舊式 `ip ssh` 之後才自動觸發金鑰產生視韌體而定），
    // 缺乏金鑰即使有 `ip ssh` 這行 SSH 服務仍是無效狀態，避免誤報「SSH 已啟用」
    telnet=!/^\s*no\s+telnet-server\b/m.test(cfg);
    ssh=/^\s*ip ssh\b/m.test(cfg)&&/^\s*crypto key generate ssh\b/m.test(cfg);
  }else if(vendor==='routeros'){
    // 官方 RouterOS Services 文件查證：telnet 預設在服務表中開啟，須明確
    // disable telnet／set telnet disabled=yes 才關閉
    telnet=!/\/ip service\s+(?:disable telnet\b|set telnet disabled=yes)/i.test(cfg);
    ssh=!/\/ip service\s+(?:disable ssh\b|set ssh disabled=yes)/i.test(cfg);
  }
  return {telnet,ssh};
}

// OSPF/BGP/RIP 路由通訊協定認證解析（2026-07-22 新增，13 廠牌逐一對外查證官方 CLI 文件後
// 實作）。設計為獨立於既有 parseOSPF()/parseBGP()/parseRIP() 之外的整體性判斷（是否「整份
// 設定檔內至少有一處」該通訊協定的認證設定），非逐 area/neighbor 精確比對——避免需要改動
// 13 個廠牌各自既有的 OSPF/BGP/RIP 資料形狀（風險較高），且稽核檢查本身也只需要「這台設備
// 的這個通訊協定有沒有設過認證」的整體訊號。查無官方佐證逐字語法的廠牌/協定組合（如
// ProCurve OSPF、多數廠牌 RIP）明確不判斷（回傳 null，代表「不評估」而非「未通過」），
// 避免臆測語法導致誤判。
function parseRoutingAuth(cfg, vendor){
  let ospf=null, bgp=null, rip=null;
  if(vendor==='comware'){
    ospf=/ospf\s+authentication-mode\s+(?:md5|simple)/i.test(cfg);
    bgp=/peer\s+\S+\s+password\s+(?:cipher|simple)/i.test(cfg);
    rip=/rip\s+authentication-mode\s+(?:simple|md5)/i.test(cfg);
  }else if(vendor==='fortiswitch'){
    const ospfBlk=(cfg.match(/^config router ospf\n([\s\S]*?)^end\b/m)||[])[1]||'';
    ospf=/set authentication\s+(?:md5|text)/i.test(ospfBlk);
    const bgpBlk=(cfg.match(/^config router bgp\n([\s\S]*?)^end\b/m)||[])[1]||'';
    bgp=/set password\s+\S+/i.test(bgpBlk);
    const ripBlk=(cfg.match(/^config router rip\n([\s\S]*?)^end\b/m)||[])[1]||'';
    rip=/set auth-mode\s+(?:md5|text)/i.test(ripBlk);
  }else if(vendor==='juniper'){
    ospf=/set protocols ospf area[^\n]*authentication|authentication\s+(?:md5|simple-password)/i.test(cfg)&&/set protocols ospf/.test(cfg);
    bgp=/set protocols bgp[\s\S]*?authentication-key\s+/i.test(cfg)&&/set protocols bgp/.test(cfg);
    rip=/set protocols rip[\s\S]*?authentication-type\s+(?:md5|simple)/i.test(cfg)&&/set protocols rip/.test(cfg);
  }else if(vendor==='aruba'){
    ospf=/ip ospf authentication message-digest|ip ospf message-digest-key/i.test(cfg);
    bgp=/neighbor\s+\S+\s+password\s+\S+/i.test(cfg)||/neighbor\s+\S+\s+ao\s+\S+/i.test(cfg);
  }else if(vendor==='cisco'||vendor==='ruijie'){
    // Ruijie RGOS OSPF/BGP/RIP 語法與 Cisco 同源，尚無真實範例逐字驗證，先併入同一套
    // 邏輯，信心度較低
    ospf=/ip ospf message-digest-key|area\s+\S+\s+authentication message-digest/i.test(cfg);
    bgp=/neighbor\s+\S+\s+password\s+\S+/i.test(cfg);
    rip=/ip rip authentication (?:mode|key-chain)/i.test(cfg);
  }else if(vendor==='dell-os10'){
    ospf=/ip ospf message-digest-key|ip ospf authentication-key/i.test(cfg);
    bgp=/neighbor\s+\S+[\s\S]{0,60}?\bpassword\s+/i.test(cfg);
  }else if(vendor==='nxos'){
    ospf=/ip ospf message-digest-key|ip ospf authentication message-digest/i.test(cfg);
    bgp=/neighbor\s+\S+\s+password\s+\S+/i.test(cfg);
    rip=/ip rip authentication (?:mode|key-chain)/i.test(cfg);
  }else if(vendor==='arista'){
    ospf=/ip ospf message-digest-key/i.test(cfg);
    bgp=/neighbor\s+\S+\s+password\s+/i.test(cfg);
  }else if(vendor==='brocade'){
    ospf=/ip ospf md5-authentication/i.test(cfg);
    bgp=/neighbor\s+\S+\s+password\s+\S+/i.test(cfg);
  }else if(vendor==='alcatel'){
    ospf=/ospf interface\s+\S+\s+md5/i.test(cfg);
    bgp=/ip bgp neighbor\s+\S+\s+md5\s+key/i.test(cfg);
  }else if(vendor==='extreme'){
    ospf=/configure ospf[^\n]*authentication\s+(?:\{?encrypted\}?\s+)?(?:simple-password|md5)/i.test(cfg);
    bgp=/configure bgp neighbor[^\n]*password\s+(?!none\b)\S+/i.test(cfg);
  }else if(vendor==='procurve'){
    // OSPF：官方查證僅得知需先設 key-chain 再套用，確切最終指令名稱未能取得逐字確認，
    // 依專案慣例不臆測，維持 null（不評估）。BGP：2026-07-22 對外查證官方文件後移除
    // 原本的 BGP 認證判斷式——ArubaOS-Switch/ProCurve 系列全域不支援 BGP（僅 AOS-CX
    // 才有），先前的 `neighbor ... password` regex 對 ProCurve 而言是誤植的死程式碼，
    // bgp 維持預設 null（不評估）
  }else if(vendor==='routeros'){
    ospf=/routing\/ospf\/interface-template[\s\S]{0,120}?auth=(?:md5|simple)|auth=(?:md5|simple)[\s\S]{0,120}?routing\/ospf/i.test(cfg);
    bgp=/tcp-md5-key=/i.test(cfg);
    rip=/routing\/rip\/interface-template[^\n]*(?:password=|key-chain=)/i.test(cfg);
  }
  return {ospf,bgp,rip};
}

function parseOSPF(cfg){
  // Comware uses "ospf N [router-id X]" (no "router" prefix)
  // Also supports "router ospf N" (Cisco-style, kept for compatibility)
  const processes=[]; let m;
  // Match both: "ospf N" and "router ospf N"
  const pr=/^(?:router )?ospf\s+(\d+)(?:\s+router-id\s+(\S+))?\n((?:[ \t][^\n]*\n)*)/gm;
  while((m=pr.exec(cfg))!==null){
    const pid=m[1];
    const ridSameLine=m[2]||'';
    const body=m[3];
    const ridInBody=(body.match(/router-id\s+(\S+)/)||[])[1]||'';
    const rid=ridSameLine||ridInBody;
    const areas=[];
    // Area blocks are indented under the ospf block
    const ar=/[ \t]area\s+([\d.]+)\n((?:[ \t]{2,}[^\n]*\n)*)/g; let am;
    while((am=ar.exec(body))!==null){
      const abody=am[2];
      const networks=[]; const nr=/network\s+([\d.]+)\s+([\d.]+)/g; let nm;
      while((nm=nr.exec(abody))!==null)networks.push({network:nm[1],wildcard:nm[2]});
      // stub/nssa 巢狀宣告在 area 區塊內（與 network 同縮排層級），例如 "  stub" / "  nssa no-summary"。
      // 2026-07-22 對外查證官方 H3C 文件後新增：no-summary 修飾詞先前只比對不擷取，
      // 資料直接遺失，現改為獨立 noSummary 布林欄位存起來
      const typeM=abody.match(/^\s*(stub|nssa)\b(\s+no-summary)?/m);
      areas.push({area:am[1],type:typeM?typeM[1]:'normal',networks,noSummary:!!(typeM&&typeM[2])});
    }
    // 相容舊式單行 "area N stub/nssa"（Cisco 風格，無 network 時該 area 不會被上面的區塊正則捕捉到）
    const atr=/[ \t]area\s+([\d.]+)\s+(stub|nssa)(\s+no-summary)?/g; let atm;
    while((atm=atr.exec(body))!==null){
      const found=areas.find(a=>a.area===atm[1]);
      if(found){ if(found.type==='normal'){found.type=atm[2]; found.noSummary=!!atm[3];} }
      else areas.push({area:atm[1],type:atm[2],networks:[],noSummary:!!atm[3]});
    }
    // Redistribute sources
    const redistributes=[]; const rr=/(?:import-route|redistribute)\s+(\S+)/g; let rm;
    while((rm=rr.exec(body))!==null)redistributes.push(rm[1].trim());
    processes.push({pid,routerId:rid,areas,redistributes});
  }
  return processes;
}

// ── OSPFv3 Parser (Comware，2026-08-18 新增) ───────────────────
// 官方 H3C OSPFv3 Commands 手冊確認：ospfv3 為獨立頂層指令樹（非 "ospf N" 底下的子模式），
// area 在 ospfv3 區塊內只是「存在宣告」（無巢狀 network 陳述式），真正的介面成員關係要看
// 介面視圖的 "ospfv3 N area X [instance Y]" 指令——已用真實去識別化範例檔
// （comware_ipv6_real_sample.cfg）交叉確認區塊結構。既有 parseOSPF() 的頂層正則要求
// "ospf" 後接空白，"ospfv3 1" 中 "ospf" 後接 "v3"（非空白）不會誤判，兩者互不衝突。
function parseOSPFv3(cfg){
  const processes=[]; let m;
  const pr=/^ospfv3\s+(\d+)\s*\n((?:[ \t][^\n]*\n)*)/gm;
  while((m=pr.exec(cfg))!==null){
    const pid=m[1], body=m[2];
    const rid=(body.match(/router-id\s+(\S+)/)||[])[1]||'';
    const areas=[]; const ar=/[ \t]area\s+(\S+)/g; let am;
    while((am=ar.exec(body))!==null){
      if(!areas.find(a=>a.area===am[1]))areas.push({area:am[1],interfaces:[]});
    }
    processes.push({pid,routerId:rid,areas});
  }
  // 逐介面反查 "ospfv3 PID area AREA"（比照 VRRP/BGP 既有的 cfg.split('\ninterface ') 慣例）
  const raw=cfg.split('\ninterface ');
  for(const blk of raw.slice(1)){
    const name=blk.split('\n')[0].trim();
    const body=blk.slice(name.length);
    const re=/ospfv3\s+(\d+)\s+area\s+(\S+)/g; let rm;
    while((rm=re.exec(body))!==null){
      const proc=processes.find(p=>p.pid===rm[1]);
      if(!proc)continue;
      let area=proc.areas.find(a=>a.area===rm[2]);
      if(!area){area={area:rm[2],interfaces:[]};proc.areas.push(area);}
      if(!area.interfaces.includes(name))area.interfaces.push(name);
    }
  }
  return processes;
}

// ── RIPng Parser (Comware，2026-08-18 新增) ────────────────────
// 官方 H3C RIPng Commands 手冊確認："ripng [ process-id ]" 為獨立頂層指令（預設值 1），
// 介面視圖 "ripng N enable" 啟用；既有 parseRIP() 的頂層正則在 "ripng 1" 位置會因
// "rip" 後直接接 "ng"（非空白/非換行）導致整段匹配失敗，兩者互不衝突。
function parseRIPng(cfg){
  const list=[]; let m;
  const pr=/^ripng(?:\s+(\d+))?\s*\n((?:[ \t][^\n]*\n)*)/gm;
  while((m=pr.exec(cfg))!==null){
    const pid=m[1]||'1', body=m[2];
    const redistribute=[]; const rr=/(?:import-route|redistribute)\s+(\S+)/g; let rm;
    while((rm=rr.exec(body))!==null)redistribute.push(rm[1].trim());
    list.push({pid,interfaces:[],redistribute});
  }
  const raw=cfg.split('\ninterface ');
  for(const blk of raw.slice(1)){
    const name=blk.split('\n')[0].trim();
    const body=blk.slice(name.length);
    const re=/ripng\s+(\d+)\s+enable/g; let rm2;
    while((rm2=re.exec(body))!==null){
      const proc=list.find(p=>p.pid===rm2[1]);
      if(proc&&!proc.interfaces.includes(name))proc.interfaces.push(name);
    }
  }
  return list;
}

// ── BGP Parser (Comware) ─────────────────────────────────────
function parseBGP(cfg){
  const bgpList=[]; let m;
  // Match "bgp ASN" top-level blocks。先前的排除清單式逐行負向前瞻收尾沒有處理 Comware
  // 自己的 "#" 區塊終止字元，若 bgp 區塊後面接的是排除清單沒列到的其他區塊（如本例的
  // dhcp server ip-pool），body 會一路吃到下一個排除清單關鍵字才停，把後面不相干的區塊
  // 內容誤植進 bgp networks（2026-09-02 全功能審查發現，用真實 comware_test.cfg 重現）；
  // 改用與同檔案 parseRIP() 完全一致的寫法——非貪婪 [\s\S]*? 搭配尾端 lookahead 找「最近」
  // 的邊界，而非先前那種「逐行負向前瞻 repetition」在多個 "#" 之間可能貪婪跳過的寫法
  const re=/^bgp\s+(\d+)\n([\s\S]*?)(?=^bgp\s+\d|^router\s|^interface\s|^ip\s+route|^vlan\s|\n#\s*\n|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null){
    const asn=m[1], body=m[2];
    const rid=(body.match(/router-id\s+(\S+)/)||[])[1]||'';
    // Peers
    const peers=[]; const pr=/[\s^]peer\s+(\S+)\s+as-number\s+(\d+)/g; let pm;
    while((pm=pr.exec(body))!==null){
      const ip=pm[1], peerAs=pm[2];
      const desc=(body.match(new RegExp('peer\\s+'+ip.replace(/\./g,'\\.')+'\\s+description\\s+([^\\n]+)'))||[])[1]||'';
      const peerType=peerAs===asn?'iBGP':'eBGP';
      peers.push({ip, as:peerAs, desc:desc.trim(), type:peerType});
    }
    // IPv6（2026-08-18 新增，官方 H3C BGP Commands 手冊確認 network 巢狀在獨立的
    // address-family ipv6 子模式內，語法為 "network ipv6-address prefix-length"——前綴
    // 長度是空格分隔的獨立參數，非 slash-CIDR，與現有 IPv4 "network A.B.C.D mask" 同款
    // 空格分隔慣例一致；子模式結尾比照 H3C 慣例，遇下一個 address-family 或單獨一行的 #
    // 即停）。先算出 IPv6 子區塊範圍，再從 body 中挖除該段落後才餵給下方 IPv4 network
    // 正則掃描——否則 IPv6 位址開頭的十進位數字（如 "2001:db8::"）會被 IPv4 正則的
    // 寬鬆字元類別 [\d./]+ 誤吃成一筆假的 IPv4 network（如 "2001"）
    const nets6=[];
    const afv6=body.match(/^\s*address-family ipv6(?:\s+unicast)?\s*\n([\s\S]*?)(?=^\s*address-family\b|^\s*#\s*$|(?![\s\S]))/m);
    if(afv6){
      const nr6=/network\s+([0-9a-fA-F:]+)\s+(\d+)\b/g; let nm6;
      while((nm6=nr6.exec(afv6[1]))!==null)nets6.push(nm6[1]+'/'+nm6[2]);
    }
    const bodyV4=afv6?body.slice(0,afv6.index)+body.slice(afv6.index+afv6[0].length):body;
    // Networks advertised (supports "network A.B.C.D mask" or "network prefix/len")
    const nets=[]; const nr=/network\s+([\d./]+)(?:\s+(\d+\.\d+\.\d+\.\d+))?/g; let nm;
    while((nm=nr.exec(bodyV4))!==null){
      const dst=nm[1];
      if(nm[2])nets.push(dst+'/'+cidrFromMask(nm[2]));
      else nets.push(dst);
    }
    // Peer groups (Comware: "group NAME external/internal" 建立群組)。regex 需錨定在行首
    // （第一個 token 必須是 group），否則會誤吃到「peer IP group NAME」這種把 peer 加入
    // 群組的指派行（H3C BGP Commands 官方文件確認兩者是各自獨立指令），導致重複/錯誤項目。
    const peerGroups=[]; const pgr=/^\s*group\s+(\S+)(?:\s+(external|internal))?/gm; let pgm;
    while((pgm=pgr.exec(body))!==null)peerGroups.push({name:pgm[1],type:pgm[2]||''});
    // Timers: 2026-07-22 對外查證官方 H3C 文件後修正：真實關鍵字是 "timer keepalive N
    // hold N"，非 "holdtime"（原始猜測與 Cisco/其他廠牌用詞混淆）；Cisco 式 "timers bgp
    // N N" 備援保留（不影響 Comware 真實匯出檔解析，純粹避免誤刪原有容錯路徑）
    const timerM=body.match(/timer\s+keepalive\s+(\d+)\s+hold\s+(\d+)/i)||body.match(/timers(?:\s+bgp)?\s+(\d+)\s+(\d+)/i);
    const timers=timerM?{keepalive:timerM[1],holdtime:timerM[2]}:null;
    bgpList.push({asn,routerId:rid,peers,networks:nets,networks6:nets6,peerGroups,timers});
  }
  return bgpList;
}

// ── RIP / RIPv2 Parsers ───────────────────────────────────────
function parseRIPBlock(body, opts={}){
  const networks=[]; let nm;
  const nr=/^\s*network\s+([^\n]+)/gm;
  while((nm=nr.exec(body))!==null)networks.push(nm[1].trim());
  const redistribute=[]; let rm;
  const rr=/^\s*(?:import-route|redistribute)\s+([^\n]+)/gm;
  while((rm=rr.exec(body))!==null)redistribute.push(rm[1].trim());
  // passive-interface 為 Cisco/Aruba CX 關鍵字，此函式為三廠牌共用 helper（Comware/
  // Cisco/Aruba CX 皆呼叫），不可直接替換，改為新增 Comware 真實關鍵字 silent-interface
  // 當作額外可接受的寫法（2026-07-22 對外查證官方 H3C 文件後新增，兩者字面不重疊不會誤判）
  const passive=[]; let pm;
  const pr=/^\s*(?:passive-interface|silent-interface)\s+(\S+)/gm;
  while((pm=pr.exec(body))!==null)passive.push(pm[1]);
  const peers=[]; let peerM;
  const peerRe=/^\s*(?:peer|neighbor)\s+(\S+)/gm;
  while((peerM=peerRe.exec(body))!==null)peers.push(peerM[1]);
  const version=(body.match(/^\s*version\s+(\d+)/m)||[])[1]||opts.version||'';
  // auto-summary 為 Cisco 關鍵字；Comware 真實關鍵字是 summary（預設啟用），2026-07-22
  // 對外查證官方文件後新增為額外可接受的「啟用」寫法（undo summary 已在既有 false 分支）
  const autoSummary=/^\s*(?:auto-summary|summary)\b/m.test(body)?true:/^\s*(?:no|undo)\s+auto-summary\b|^\s*undo\s+summary\b/m.test(body)?false:null;
  const timers=(body.match(/^\s*timers(?:\s+basic)?\s+([^\n]+)/m)||[])[1]?.trim()||'';
  // default-metric 為 Cisco 關鍵字；Comware 真實關鍵字是 default cost，2026-07-22 對外
  // 查證官方文件後新增
  const defaultMetric=(body.match(/^\s*default-metric\s+(\d+)/m)||[])[1]||(body.match(/^\s*default\s+cost\s+(\d+)/m)||[])[1]||'';
  return{pid:opts.pid||'1',version:version||'1/2',vrf:opts.vrf||'',networks,redistribute,passive,peers,autoSummary,timers,defaultMetric};
}

function parseRIP(cfg){
  const rip=[]; let m;
  // HPE Comware: "rip [process-id] [vpn-instance NAME]".
  const re=/^rip(?:\s+(\d+))?(?:\s+vpn-instance\s+(\S+))?\s*\n([\s\S]*?)(?=^rip\b|^router\b|^bgp\b|^ospf\b|^interface\b|^vlan\b|^ip\s+route|\n#\s*\n|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null)rip.push(parseRIPBlock(m[3],{pid:m[1]||'1',vrf:m[2]||''}));
  return rip;
}

function parseCiscoRIP(cfg){
  const rip=[]; let m;
  const re=/^router\s+rip\s*\n([\s\S]*?)(?=^router\s|^interface\s|^ip\s+route\s|^vlan\s|^end\b|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null)rip.push(parseRIPBlock(m[1],{pid:'default'}));
  return rip;
}

function parseArubaRIP(cfg){
  const rip=[]; let m;
  // Aruba CX configurations typically use "router rip"; keep support for
  // Comware-like "rip" as a fallback because some migrations retain that form.
  const re=/^(?:router\s+)?rip(?:\s+(\d+))?\s*\n([\s\S]*?)(?=^(?:router\s+|rip\b|interface\s+|vlan\s+|vrf\s+|ip\s+route|bgp\b|user\s+|end\b)|(?![\s\S]))/gm;
  while((m=re.exec(cfg))!==null)rip.push(parseRIPBlock(m[2],{pid:m[1]||'default'}));
  return rip;
}

function parseComware(cfg){
  const sys=parseSysInfo(cfg);
  const irf=parseIRF(cfg);
  let vlans=parseVLANs(cfg);
  const interfaces=parseInterfaces(cfg);
  // Fix 2: merge globally-declared + implied-only VLANs
  const impliedVlans=collectImpliedVLANs(vlans,interfaces);
  if(impliedVlans.length)vlans=[...vlans,...impliedVlans].sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  const routes=parseRoutes(cfg);
  const vrfs=parseVRFs(cfg);
  const users=parseUsers(cfg);
  const ospf=parseOSPF(cfg);
  const ospf6=parseOSPFv3(cfg);
  const bgp=parseBGP(cfg);
  const rip=parseRIP(cfg);
  const rip6=parseRIPng(cfg);
  const vrrp=parseVRRP(cfg,'comware');
  const vxlan=parseVXLAN(cfg,'comware');
  return{sys,irf,vlans,interfaces,routes,vrfs,users,ospf,ospf6,bgp,rip,rip6,vrrp,vxlan};
}

// class-map/match + service-policy（2026-08-31 新增）：直接 fetch 官方 H3C QoS Commands
// 手冊（h3c.com support 站台，S7500E-XS 系列 QoS Commands 頁面）逐字查證，Comware 語法
// 家族與 Cisco class-map/policy-map 完全不同——分類器（class-map 對應概念）叫
// "traffic classifier"，比對條件叫 "if-match"，容器叫 "qos policy"（非 policy-map），
// 介面套用叫 "qos apply policy"（非 service-policy）。已查證 if-match 支援的條件：
// acl（access-group）／dscp／ip-precedence／protocol／customer-vlan-id（vlan）；
// customer-dot1p/service-dot1p（802.1p，near-CoS 但非同一關鍵字，命名歧義未查證该用哪一種
// 變體，不比照其餘廠牌臆測成 cos 選項，本輪不支援）。traffic classifier 預設運算子為
// "and"（未寫 operator 時），對應共用 matchType 欄位語意上等同 match-all；"or" 對應
// match-any（僅為內部資料模型統一命名，非 Comware 官方字面用詞）。
function parseComwareClassMaps(cfg){
  const maps=[];
  const cmRe=/^traffic classifier\s+(\S+)(?:\s+operator\s+(and|or))?\s*\n([\s\S]*?)(?=^traffic classifier\s+|^traffic behavior\s+|^qos policy\s+|(?![\s\S]))/gm;
  let m;
  while((m=cmRe.exec(cfg))!==null){
    const name=m[1], op=(m[2]||'and').toLowerCase(), body=m[3]||'';
    const matchType=op==='or'?'match-any':'match-all';
    const matches=[];
    let mm;
    const aclRe=/^\s*if-match\s+acl\s+(?:ipv6\s+)?(?:name\s+)?(\S+)/gim;
    while((mm=aclRe.exec(body))!==null)matches.push({type:'access-group',value:mm[1]});
    const dscpRe=/^\s*if-match\s+dscp\s+(\S+)/gim;
    while((mm=dscpRe.exec(body))!==null)matches.push({type:'dscp',value:mm[1]});
    const precRe=/^\s*if-match\s+ip-precedence\s+(\S+)/gim;
    while((mm=precRe.exec(body))!==null)matches.push({type:'ip-precedence',value:mm[1]});
    const protoRe=/^\s*if-match\s+protocol\s+(\S+)/gim;
    while((mm=protoRe.exec(body))!==null)matches.push({type:'protocol',value:mm[1]});
    const vlanRe=/^\s*if-match\s+customer-vlan-id\s+(\S+)/gim;
    while((mm=vlanRe.exec(body))!==null)matches.push({type:'vlan',value:mm[1]});
    maps.push({name,matchType,matches});
  }
  return maps;
}
function parseComwareServicePolicy(cfg){
  const apps=[];
  cfg.split(/(?=^interface\s)/m).forEach(blk=>{
    const ifLine=blk.match(/^interface\s+(\S.*)/m);
    if(!ifLine)return;
    const ifName=ifLine[1].trim();
    let m; const spRe=/^\s*qos apply policy\s+(\S+)\s+(inbound|outbound)/gim;
    while((m=spRe.exec(blk))!==null)apps.push({policy:m[1],interface:ifName,direction:m[2].toLowerCase()==='inbound'?'input':'output'});
  });
  return apps;
}

// ═ Cisco IOS/IOS-XE Parser ═
// ════════════════════════════════════════════════════════════
//  Cisco IOS / IOS-XE Switch Parser
// ════════════════════════════════════════════════════════════

