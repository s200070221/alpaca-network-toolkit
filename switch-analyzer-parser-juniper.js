function junosBlock(cfg, keyword){
  const escaped=keyword.replace(/[.+*?^${}()|[\]\\]/g,'\\$&').replace(/\\\-/g,'[-]');
  const re=new RegExp('^[ \\t]*'+escaped+'\\s*\\{','m');
  const m=re.exec(cfg);
  if(!m)return'';
  let depth=0,i=m.index,start=-1;
  while(i<cfg.length){
    if(cfg[i]==='{'){depth++;if(start<0)start=i;}
    else if(cfg[i]==='}'){depth--;if(depth===0)return cfg.slice(start+1,i);}
    i++;
  }
  return'';
}

// ── Extract all top-level brace sub-blocks ────────────────
function junosSubBlocks(body){
  const result=[]; const lines=body.split('\n');
  let i=0;
  while(i<lines.length){
    const line=lines[i];
    const m=line.match(/^(\s*)(.+?)\s*\{\s*(?:\/\/.*)?$/);
    if(m){
      if(!m[2].trim())continue;  // skip blank or comment lines
      const name=m[2].trim(),indent=m[1];
      let depth=1,j=i+1,content=[];
      while(j<lines.length&&depth>0){
        const l=lines[j];
        for(const c of l){if(c==='{')depth++;else if(c==='}')depth--;}
        if(depth>0)content.push(l);
        j++;
      }
      result.push({name,content:content.join('\n')});
      i=j;
    }else{i++;}
  }
  return result;
}

// ── System info ───────────────────────────────────────────
function parseJuniperSysInfo(cfg){
  const hostname=
    (junosBlock(cfg,'system').match(/host-name\s+(\S+);/)||
     cfg.match(/host-name\s+(\S+);/)||[])[1]||'unknown';
  const version=(cfg.match(/^version\s+(\S+);/m)||[])[1]||'';
  const model=(cfg.match(/##\s*(?:Model|model):\s*(\S+)/)||[])[1]||
              (cfg.match(/^#\s*Model:\s*(\S+)/m)||[])[1]||'';
  return{hostname,version,model};
}

// ── VLANs ─────────────────────────────────────────────────
function parseJuniperVLANs(cfg){
  const vlansBlock=junosBlock(cfg,'vlans');
  if(!vlansBlock)return[];
  const vlans=[];
  const subs=junosSubBlocks(vlansBlock);
  for(const{name,content:body}of subs){
    const id=(body.match(/vlan-id\s+(\d+);/)||[])[1]||'';
    const desc=(body.match(/description\s+"?([^";]+)"?;/)||[])[1]?.trim()||'';
    const l3if=(body.match(/l3-interface\s+(\S+);/)||[])[1]||'';
    if(id||name.toLowerCase()!=='vlans')
      vlans.push({id:id||'',name,desc,l3Interface:l3if,ipSubnets:[]});
  }
  vlans.sort((a,b)=>parseInt(a.id||0)-parseInt(b.id||0));
  return vlans;
}

// 雙棧/次要IP 分桶修復（2026-08-13 新增，2026-08-17 次要IP 從「僅取第一筆」擴大為完整
// 收集）：`matchAll(/address\s+(\S+);/g)` 對整個介面區塊掃描時不分辨該 address statement
// 是在 `family inet {}` 還是 `family inet6 {}` 區塊裡，只依「文件出現順序」把第一筆丟進
// ip、其餘丟進 secondaryIps——真實雙棧介面（1 個 IPv4 + 1 個 IPv6）會讓 IPv6 值被誤標成
// 「IPv4 的次要位址」。改為依內容判斷版本（含冒號即 IPv6，比照專案既有慣例）分桶，
// ip=v4[0]、secondaryIps=v4.slice(1)（完整保留）、ip6=v6[0]，三者互不覆蓋
function classifyJunosAddrs(rawAddrs){
  const v4=rawAddrs.filter(a=>!a.includes(':'));
  const v6=rawAddrs.filter(a=>a.includes(':'));
  return{ip:v4[0]||'',secondaryIps:v4.slice(1),ip6:v6[0]||''};
}

// ── Interfaces ────────────────────────────────────────────
function parseJuniperInterfaces(cfg){
  const ifaces=[];
  const ifBlock=junosBlock(cfg,'interfaces');
  if(!ifBlock)return ifaces;
  const subs=junosSubBlocks(ifBlock);

  for(const{name:rawName,content:body}of subs){
    const name=rawName.trim();
    // Accept: ge-/xe-/et-/fe-/ ae0-9 / irb / lo0 / fxp / em / me / mgmt
    if(!/^(?:ge|xe|et|fe|ae|irb|lo|fxp|em|vme|me|mgmt)[\-\d]/i.test(name)&&name!=='irb')continue;

    const desc=(body.match(/description\s+"([^"]+)"/)||
                body.match(/description\s+(\S[^;]*);/)||[])[1]?.trim()||'';
    const disabled=/^\s*disable;/m.test(body);

    // ── IRB (L3 VLAN interfaces) ──────────────────────────
    if(name==='irb'){
      const unitRe=/unit\s+(\d+)\s*\{/g; let um;
      while((um=unitRe.exec(body))!==null){
        const uid=um[1];
        // Extract unit block using brace counting
        let depth=0,i=um.index,start=-1;
        while(i<body.length){
          if(body[i]==='{'){depth++;if(start<0)start=i;}
          else if(body[i]==='}'){depth--;if(depth===0)break;}
          i++;
        }
        const ubody=body.slice(start+1,i);
        const udesc=(ubody.match(/description\s+"([^"]+)"/)||[])[1]?.trim()||'';
        // 次要IP（2026-08-12 新增）：Junos 無 `secondary` 關鍵字，同一 `family inet {}` 區塊內
        // 重複宣告 `address` statement 即為附加位址（官方 Junos "Protocol Family and Interface
        // Address Properties" 文件確認，與本專案 firewall_analyzer 的 Juniper SRX parser 同一套
        // 機制）；雙棧修復（2026-08-13）：改用 classifyJunosAddrs() 依內容分辨版本，避免 IPv6
        // 誤標成次要 IPv4
        const uAddrs=[...ubody.matchAll(/address\s+(\S+);/g)].map(m=>m[1]);
        const {ip,secondaryIps,ip6}=classifyJunosAddrs(uAddrs);
        ifaces.push({name:'irb.'+uid,type:'svi',desc:udesc,mode:'',
          vlans:uid,nativeVlan:'',vrf:'',ip,ip6,secondaryIps,shutdown:false,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      }
      continue;
    }

    // ── Loopback ─────────────────────────────────────────
    if(/^lo[\d]/i.test(name)){
      // 次要IP（2026-08-12 新增）：同 IRB，附加式機制取第二筆 address statement；雙棧修復
      // （2026-08-13）：改用 classifyJunosAddrs() 依內容分辨版本
      const loAddrs=[...body.matchAll(/address\s+(\S+);/g)].map(m=>m[1]);
      const {ip,secondaryIps,ip6}=classifyJunosAddrs(loAddrs);
      ifaces.push({name,type:'loopback',desc,mode:'',vlans:'',nativeVlan:'',
        vrf:'',ip,ip6,secondaryIps,shutdown:disabled,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }

    // ── AE (Aggregated Ethernet / LAG) ───────────────────
    if(/^ae\d+$/i.test(name)){
      const lacpMode=body.includes('active')?'active':body.includes('passive')?'passive':'';
      const swMode=(body.match(/interface-mode\s+(trunk|access);/)||[])[1]||'';
      const vlanM=(body.match(/members\s+\[([^\]]+)\]/)||body.match(/members\s+(\S+);/)||[])[1]?.trim()||'';
      const native=(body.match(/native-vlan-id\s+(\d+);/)||[])[1]||'';
      // IPv6（試點 5 廠牌之一）：改用格式中立的 \S+，比照 IRB/Loopback 分支既有寫法（本來就不限定
      // IPv4 字元類別），family inet/inet6 皆可原樣擷取
      // 次要IP（2026-08-12 新增）：同 IRB，附加式機制取第二筆 address statement；雙棧修復
      // （2026-08-13）：改用 classifyJunosAddrs() 依內容分辨版本
      const aeAddrs=[...body.matchAll(/address\s+(\S+);/g)].map(m=>m[1]);
      const {ip,secondaryIps,ip6}=classifyJunosAddrs(aeAddrs);
      const mode=swMode||(ip?'routed':'');
      ifaces.push({name,type:'physical',desc,mode,vlans:vlanM,nativeVlan:native,
        vrf:'',ip,ip6,secondaryIps,shutdown:disabled,member:'1',hybrid:null,vrrp:[],lacpMode,breakoutChild:false,breakoutParent:'',breakoutMode:''});
      continue;
    }

    // ── Physical (ge/xe/et/fe/fxp/mgmt) ──────────────────
    const swMode=(body.match(/interface-mode\s+(trunk|access);/)||[])[1]||'';
    const vlanM=(body.match(/members\s+\[([^\]]+)\]/)||body.match(/members\s+(\S+);/)||[])[1]?.trim()||'';
    const native=(body.match(/native-vlan-id\s+(\d+);/)||[])[1]||'';
    // IPv6（試點 5 廠牌之一）：同上改用格式中立的 \S+
    // 次要IP（2026-08-12 新增）：同 IRB，附加式機制取第二筆 address statement；雙棧修復
    // （2026-08-13）：改用 classifyJunosAddrs() 依內容分辨版本
    const physAddrs=[...body.matchAll(/address\s+(\S+);/g)].map(m=>m[1]);
    const {ip,secondaryIps,ip6}=classifyJunosAddrs(physAddrs);
    const vrf=(body.match(/routing-instance\s+(\S+);/)||[])[1]||'';
    const lagMember=(body.match(/802\.3ad\s+(ae\d+);/)||[])[1]||'';
    const mode=swMode||(ip&&!swMode?'routed':'');
    // Breakout: 子埠命名 `xe-`/`et-` 前綴＋冒號序號（`chassis{}` 內 channel-speed 啟用，見 parseJuniperBreakout）
    const bkMatch=name.match(/^(xe|et)-(\d+\/\d+\/\d+):([0-3])$/i);
    const breakoutChild=!!bkMatch;
    const breakoutParent=bkMatch?`${bkMatch[1]}-${bkMatch[2]}`:'';

    ifaces.push({name,type:'physical',desc,mode,vlans:vlanM,nativeVlan:native,
      vrf,ip,ip6,secondaryIps,shutdown:disabled,member:'1',hybrid:null,vrrp:[],lagMember,breakoutChild,breakoutParent,breakoutMode:''});
  }
  // vrf 逆向掃描（2026-07-27 對外查證修正）：真實 Junos VRF 介面綁定語法方向是反過來的
  // routing-instances { NAME { interface X; } }，並非本函式上面 `routing-instance\s+(\S+);`
  // 這個猜測式的介面內部欄位（對外查證確認 interfaces{} 階層底下根本沒有這個關鍵字，該
  // regex 在真實設定檔上永遠不會命中）。改成逆向掃描 routing-instances{} 底下宣告的
  // interface X; 陳述式，回填對應介面的 vrf 欄位；X 可能是 unit-qualified（如 irb.20）
  // 或裸實體埠名稱（預設 unit 0，如 ge-0/0/1.0 對應到 ge-0/0/1）
  const riBlockForVrf=junosBlock(cfg,'routing-instances');
  if(riBlockForVrf){
    for(const{name:vrfName,content:vrfBody}of junosSubBlocks(riBlockForVrf)){
      const vrf=vrfName.trim();
      const refs=[...vrfBody.matchAll(/^\s*interface\s+([\w./-]+);/gm)].map(x=>x[1]);
      refs.forEach(ref=>{
        let target=ifaces.find(i=>i.name===ref);
        if(!target&&ref.endsWith('.0'))target=ifaces.find(i=>i.name===ref.slice(0,-2));
        if(target)target.vrf=vrf;
      });
    }
  }
  return ifaces;
}

// ── Breakout ─────────────────────────────────────────────
// 獨立頂層 `chassis{}` 區塊，fpc/pic/port 巢狀區塊底下的 `channel-speed`；
// 沿用既有 junosSubBlocks 的大括號深度計數邏輯逐層取值，不新寫脆弱的多層巢狀 regex
function parseJuniperBreakout(cfg){
  const breakouts=[];
  const chassisBlock=junosBlock(cfg,'chassis');
  if(!chassisBlock)return breakouts;
  for(const{name:fpcName,content:fpcBody}of junosSubBlocks(chassisBlock)){
    const fpcM=fpcName.match(/^fpc\s+(\d+)$/i);
    if(!fpcM)continue;
    for(const{name:picName,content:picBody}of junosSubBlocks(fpcBody)){
      const picM=picName.match(/^pic\s+(\d+)$/i);
      if(!picM)continue;
      for(const{name:portName,content:portBody}of junosSubBlocks(picBody)){
        const portM=portName.match(/^port\s+(\d+)$/i);
        if(!portM)continue;
        const speedM=portBody.match(/channel-speed\s+(10g|25g|40g|50g|100g);/i);
        if(!speedM)continue;
        const speed=speedM[1].toLowerCase();
        if(speed==='40g'||speed==='100g')continue; // 未拆分（unchannelized），非 breakout
        const mode=speed==='10g'?'4x10G':speed==='25g'?'4x25G':'2x50G';
        // 2026-07-22 對外查證官方 Junos 文件後修正：母埠原生前綴其實可由 channel-speed
        // 直接判斷，非「無法判斷」——40G→4x10G 拆分後子埠使用 xe- 前綴，100G→4x25G（及
        // 2x50G）拆分後子埠沿用 et- 前綴，原本一律猜測 et- 對 10g 案例是錯的
        const prefix=speed==='10g'?'xe':'et';
        breakouts.push({parentPort:`${prefix}-${fpcM[1]}/${picM[1]}/${portM[1]}`,mode,raw:portBody});
      }
    }
  }
  return breakouts;
}

// ── LACP ─────────────────────────────────────────────────
function parseJuniperLACP(cfg){
  const lacp=[];
  const ifBlock=junosBlock(cfg,'interfaces');
  if(!ifBlock)return lacp;
  const subs=junosSubBlocks(ifBlock);
  const membersByAE={}, modeByAE={}, descByAE={};

  for(const{name:rawName,content:body}of subs){
    const name=rawName.trim();
    // Physical: record lag membership
    const lagM=(body.match(/802\.3ad\s+(ae\d+);/)||[])[1];
    if(lagM) membersByAE[lagM]=(membersByAE[lagM]||[]).concat(name);
    // AE: record mode and desc
    if(/^ae\d+$/i.test(name)){
      const hasLACP=/lacp\s*\{/.test(body)||/lacp/.test(body);
      modeByAE[name]=!hasLACP?'static':
        body.includes('active')?'active':
        body.includes('passive')?'passive':'on';
      descByAE[name]=(body.match(/description\s+"([^"]+)"/)||[])[1]?.trim()||'';
    }
  }
  for(const[ae,members]of Object.entries(membersByAE)){
    lacp.push({name:ae,mode:modeByAE[ae]||'static',members,desc:descByAE[ae]||''});
  }
  // Also include AE interfaces even without members
  for(const{name:rawName}of subs){
    const n=rawName.trim();
    if(/^ae\d+$/i.test(n)&&!lacp.find(l=>l.name===n))
      lacp.push({name:n,mode:modeByAE[n]||'static',members:[],desc:descByAE[n]||''});
  }
  lacp.sort((a,b)=>parseInt(a.name.replace(/\D/g,''))-parseInt(b.name.replace(/\D/g,'')));
  return lacp;
}

// ── Static Routes ─────────────────────────────────────────
function parseJuniperRoutes(cfg){
  const routes=[];

  // Helper: parse static routes from a routing-options block
  // 字元類別放寬（2026-08-13 十一續）：[\d./]+／[\d.]+ 只認點分十進位，改成
  // [0-9a-fA-F:./]+／[0-9a-fA-F:.]+ 讓同一份邏輯能同時處理 IPv4/IPv6（十六進位+冒號）
  function extractStatic(roBlock, vrf){
    if(!roBlock)return;
    const staticBlock=junosBlock(roBlock,'static');
    if(!staticBlock)return;
    let m;
    // Single-line: "route X next-hop Y;"
    const lineRe=/route\s+([0-9a-fA-F:./]+)\s+next-hop\s+([0-9a-fA-F:.]+);/g;
    while((m=lineRe.exec(staticBlock))!==null)
      if(!routes.find(r=>r.dst===m[1]&&r.vrf===vrf))
        routes.push({dst:m[1],gw:m[2],vrf,gwIsInterface:false});
    // Single-line discard: "route X discard;"
    const discRe=/route\s+([0-9a-fA-F:./]+)\s+discard;/g;
    while((m=discRe.exec(staticBlock))!==null)
      if(!routes.find(r=>r.dst===m[1]&&r.vrf===vrf))
        routes.push({dst:m[1],gw:'discard',vrf,gwIsInterface:true});
    // Block style: "route X { next-hop Y; }" or "route X { discard; }"
    const subs=junosSubBlocks(staticBlock);
    for(const{name:rname,content:rbody}of subs){
      if(!/^route\s/i.test(rname))continue;
      const dst=rname.replace(/^route\s+/,'').trim();
      if(routes.find(r=>r.dst===dst&&r.vrf===vrf))continue;
      const nh=(rbody.match(/next-hop\s+([0-9a-fA-F:.]+);/)||
                rbody.match(/next-hop\s+([0-9a-fA-F:.]+\.\d+\.\d+\.\d+)/)||[])[1]||'';
      const disc=/\bdiscard;/.test(rbody);
      // gwIsInterface 判斷（2026-08-13 十一續修正）：原本「不是點分十進位」就視為介面名稱，
      // 會把 IPv6 位址（不含點分十進位、但含冒號）誤判成介面；改成「不是點分十進位且不含冒號」
      const gwIsIf=nh&&!nh.match(/^\d+\.\d+\.\d+\.\d+/)&&!nh.includes(':');
      if(disc) routes.push({dst,gw:'discard',vrf,gwIsInterface:true});
      else if(nh) routes.push({dst,gw:nh,vrf,gwIsInterface:gwIsIf});
    }
  }

  // Top-level routing-options
  const roBlock=junosBlock(cfg,'routing-options');
  extractStatic(roBlock,'');
  // IPv6 靜態路由（2026-08-13 十一續新增）：缺口比其餘廠牌更結構性——IPv6 靜態路由巢狀在
  // routing-options { rib inet6.0 { static { ... } } }，比 IPv4 版本多一層 rib inet6.0{}，
  // 原本 extractStatic() 只會抓到 routing-options{} 底下第一層的 static{}（IPv4）；
  // junosBlock() 本身格式中立（keyword 可含空格），直接傳入 'rib inet6.0' 即可正確比對，
  // 不需改動該函式本身
  const rib6Block=junosBlock(roBlock,'rib inet6.0');
  extractStatic(rib6Block,'');

  // Per-VRF: routing-instances { NAME { routing-options { static { ... } } } }
  const riBlock=junosBlock(cfg,'routing-instances');
  if(riBlock){
    const riSubs=junosSubBlocks(riBlock);
    for(const{name:rname,content:rbody}of riSubs){
      const vrfName=rname.trim();
      const vrfRO=junosBlock(rbody,'routing-options');
      if(vrfRO){
        extractStatic(vrfRO, vrfName);
        const vrfRib6Block=junosBlock(vrfRO,'rib inet6.0');
        extractStatic(vrfRib6Block, vrfName);
      }
    }
  }

  return routes;
}

// ── OSPF ─────────────────────────────────────────────────
function parseJuniperOSPF(cfg){
  const protoBlock=junosBlock(cfg,'protocols');
  if(!protoBlock)return[];
  const ospfBlock=junosBlock(protoBlock,'ospf')||junosBlock(cfg,'ospf');
  if(!ospfBlock)return[];
  const roBlock=junosBlock(cfg,'routing-options');
  const rid=(roBlock.match(/router-id\s+([\d.]+);/)||[])[1]||'';
  const areas=[];
  // Extract each area block
  const areaSubs=junosSubBlocks(ospfBlock);
  for(const{name,content:abody}of areaSubs){
    if(!/^area\s/i.test(name))continue;
    const areaId=name.replace(/^area\s+/,'').trim();
    const networks=[];
    // Parse interface lines inside the area block
    const ifRe=/interface\s+([\w.\-\/]+)/g; let im;
    while((im=ifRe.exec(abody))!==null){
      const iname=im[1].replace(';','').trim();
      if(iname&&!iname.includes('{'))
        networks.push({network:iname,wildcard:'',type:'interface'});
    }
    // Also nested interface sub-blocks
    const ifSubs=junosSubBlocks(abody);
    for(const{name:iname}of ifSubs){
      if(/^interface\s/i.test(iname)){
        const ifn=iname.replace(/^interface\s+/,'').trim();
        if(!networks.find(n=>n.network===ifn))
          networks.push({network:ifn,wildcard:'',type:'interface'});
      }
    }
    areas.push({area:areaId,networks});
  }
  return areas.length?[{pid:'1',routerId:rid,areas,protocol:'ospf'}]:[];
}

// OSPFv3（2026-08-18 新增，官方 Junos OSPF User Guide 確認 `protocols ospf3 { area X
// { interface Y; } }`，與 IPv4 `protocols ospf` 結構完全平行，僅頂層關鍵字換成
// `ospf3`；沿用既有 junosBlock()/junosSubBlocks() 擷取邏輯，areas[].interfaces 為介面
// 名稱字串陣列，與本會話稍早 Comware/Cisco/RouterOS 已建立的 ospf6 資料形狀一致）
function parseJuniperOSPFv3(cfg){
  const protoBlock=junosBlock(cfg,'protocols');
  if(!protoBlock)return[];
  const ospf3Block=junosBlock(protoBlock,'ospf3')||junosBlock(cfg,'ospf3');
  if(!ospf3Block)return[];
  const roBlock=junosBlock(cfg,'routing-options');
  const rid=(roBlock.match(/router-id\s+([\d.]+);/)||[])[1]||'';
  const areas=[];
  const areaSubs=junosSubBlocks(ospf3Block);
  for(const{name,content:abody}of areaSubs){
    if(!/^area\s/i.test(name))continue;
    const areaId=name.replace(/^area\s+/,'').trim();
    const interfaces=[];
    const ifRe=/interface\s+([\w.\-\/]+)/g; let im;
    while((im=ifRe.exec(abody))!==null){
      const iname=im[1].replace(';','').trim();
      if(iname&&!iname.includes('{'))
        interfaces.push(iname);
    }
    const ifSubs=junosSubBlocks(abody);
    for(const{name:iname}of ifSubs){
      if(/^interface\s/i.test(iname)){
        const ifn=iname.replace(/^interface\s+/,'').trim();
        if(!interfaces.includes(ifn))interfaces.push(ifn);
      }
    }
    areas.push({area:areaId,interfaces});
  }
  return areas.length?[{pid:'1',routerId:rid,areas}]:[];
}

// ── BGP ───────────────────────────────────────────────────
function parseJuniperBGP(cfg){
  const protoBlock=junosBlock(cfg,'protocols');
  if(!protoBlock)return[];
  const bgpBlock=junosBlock(protoBlock,'bgp')||junosBlock(cfg,'bgp');
  if(!bgpBlock)return[];
  const roBlock=junosBlock(cfg,'routing-options');
  const localAS=(roBlock.match(/autonomous-system\s+(\d+);/)||[])[1]||'';
  const rid=(roBlock.match(/router-id\s+([\d.]+);/)||[])[1]||'';
  const peers=[];

  // Extract each group using junosSubBlocks
  const groupSubs=junosSubBlocks(bgpBlock);
  for(const{name:gname,content:gbody}of groupSubs){
    if(!/^group\s/i.test(gname))continue;
    const groupName=gname.replace(/^group\s+/,'').trim();
    const gtype=(gbody.match(/type\s+(internal|external);/)||[])[1]||'';
    const groupAS=(gbody.match(/peer-as\s+(\d+);/)||[])[1]||'';

    // Extract each neighbor sub-block
    const neighSubs=junosSubBlocks(gbody);
    for(const{name:nname,content:nbody}of neighSubs){
      if(!/^neighbor\s/i.test(nname))continue;
      const ip=nname.replace(/^neighbor\s+/,'').trim();
      const desc=(nbody.match(/description\s+"([^"]+)"/)||nbody.match(/description\s+([^;{\n]+);/)  ||[])[1]?.trim()||'';
      const peerAS=(nbody.match(/peer-as\s+(\d+);/)||[null,groupAS])[1]||groupAS;
      const peerType=gtype==='internal'?'iBGP':gtype==='external'?'eBGP':
                    (peerAS===localAS?'iBGP':'eBGP');
      peers.push({ip,as:peerAS,desc,type:peerType,group:groupName});
    }
    // Also single-line neighbors (no sub-block)
    // 2026-08-18 修正：原字元類別 [\d.]+ 為 IPv4-only，子區塊內 neighbor 名稱擷取本來就用
    // .replace() 去前綴、格式已中立，此單行 fallback 正則放寬為格式中立一併涵蓋 IPv6
    const snRe=/neighbor\s+([^\s;]+);/g; let snm;
    while((snm=snRe.exec(gbody))!==null){
      if(!peers.find(p=>p.ip===snm[1]&&p.group===groupName))
        peers.push({ip:snm[1],as:groupAS,desc:'',
          type:gtype==='internal'?'iBGP':'eBGP',group:groupName});
    }
  }

  return peers.length?[{asn:localAS,routerId:rid,peers,networks:[]}]:[];
}

// ── Users ─────────────────────────────────────────────────
function parseJuniperUsers(cfg){
  const sysBlock=junosBlock(cfg,'system');
  const loginBlock=junosBlock(sysBlock||cfg,'login');
  if(!loginBlock)return[];
  const users=[];
  const userSubs=junosSubBlocks(loginBlock);
  for(const{name:uname,content:body}of userSubs){
    if(!/^user\s/i.test(uname))continue;
    const name=uname.replace(/^user\s+/,'').trim();
    const role=(body.match(/class\s+(\S+);/)||[])[1]||'';
    const authBlock=junosBlock(body,'authentication')||body;
    const encPwd=(authBlock.match(/encrypted-password\s+"([^"]+)"/)||[])[1]||'';
    const plainPwd=(authBlock.match(/plain-text-password(?:-value)?\s+"([^"]+)"/)||[])[1]||'';
    const hasPwd=!!(encPwd||plainPwd);
    let pwdType='',pwdWeak=false;
    if(plainPwd){pwdType='plaintext';pwdWeak=true;}
    else if(encPwd){
      if(encPwd.startsWith('$6$')){pwdType='sha512';pwdWeak=false;}
      else if(encPwd.startsWith('$5$')){pwdType='sha256';pwdWeak=false;}
      else if(encPwd.startsWith('$1$')){pwdType='md5';pwdWeak=true;}
      else{pwdType='hash';pwdWeak=false;}
    }
    users.push({name,role,service:'ssh/netconf',hasPwd,pwdType,pwdWeak});
  }
  return users;
}

// ── VRF / routing-instances ───────────────────────────────
function parseJuniperVRFs(cfg){
  const riBlock=junosBlock(cfg,'routing-instances');
  if(!riBlock)return[];
  const vrfs=[];
  const subs=junosSubBlocks(riBlock);
  for(const{name,content:body}of subs){
    const rd=(body.match(/route-distinguisher\s+(\S+);/)||[])[1]||'';
    const type=(body.match(/instance-type\s+(\S+);/)||[])[1]||'';
    vrfs.push({name:name.trim(),rd,importRoute:type});
  }
  return vrfs;
}

// ── Virtual Chassis (stack) ───────────────────────────────
function parseJuniperVC(cfg){
  const vcBlock=junosBlock(cfg,'virtual-chassis');
  if(!vcBlock)return null;
  const preprovisioned=/preprovisioned;/.test(vcBlock);
  const members=[];
  // Extract each "member N { role ...; serial-number "..."; }" sub-block
  const memberSubs=junosSubBlocks(vcBlock);
  for(const{name:mname,content:mbody}of memberSubs){
    if(!/^member\s/i.test(mname))continue;
    const id=mname.replace(/^member\s+/,'').trim();
    const role=(mbody.match(/role\s+(\S+);/)||[])[1]||'';
    const serial=(mbody.match(/serial-number\s+"?([^";]+)"?;/)||[])[1]?.trim()||'';
    const isRE=role.includes('routing-engine');
    members.push({
      id,
      model: serial ? 'S/N:'+serial : '—',
      priority: isRE ? (id==='0'?255:200) : 100,
      role: id==='0'&&isRE?'Master': isRE?'Standby':'Line-Card',
      serial, roleDesc:role
    });
  }
  if(!members.length)return null;
  members.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  // VC links: each member connects to neighbours via VC ports
  const links=[];
  for(let i=0;i<members.length-1;i++){
    links.push({id:String(i+1),ports:['vc-port'],
      desc:`M${members[i].id}↔M${members[i+1].id}`});
  }
  return{type:'VC', members, links, preprovisioned};
}

// ── MC-LAG（Multi-Chassis Link Aggregation，2026-08-19 新增）────────────────
// 官方 Junos MC-LAG 文件查證：mc-ae 巢狀於個別 AE 介面的 aggregated-ether-options 區塊
// 內（interfaces { aeN { aggregated-ether-options { mc-ae { mc-ae-id N; chassis-id N;
// mode active-active|active-standby; } } } }），ICCP（跨機互聯控制協定）peer 宣告於
// 獨立的 protocols iccp 區塊。與 VPC(NX-OS)/MLAG(Arista)/VLT(Dell OS10) 概念相同（雙機
// 互聯冗餘，非物理堆疊），沿用同一套 parsed.stack={type,domain,peerLink,members} 形狀，
// 取第一個找到的 mc-ae 介面代表整台裝置的 MC-LAG 身份即可
function parseJuniperMCLAG(cfg){
  const interfacesBlock=junosBlock(cfg,'interfaces');
  if(!interfacesBlock)return null;
  let mcaeId='',chassisId='',mode='';
  for(const{content:ifBody}of junosSubBlocks(interfacesBlock)){
    const aeOptBlock=junosBlock(ifBody,'aggregated-ether-options');
    const mcaeBlock=aeOptBlock?junosBlock(aeOptBlock,'mc-ae'):'';
    if(!mcaeBlock)continue;
    mcaeId=(mcaeBlock.match(/mc-ae-id\s+(\d+);/)||[])[1]||'';
    chassisId=(mcaeBlock.match(/chassis-id\s+(\d+);/)||[])[1]||'';
    mode=(mcaeBlock.match(/mode\s+(\S+);/)||[])[1]||'';
    if(mcaeId)break;
  }
  if(!mcaeId)return null;
  const protocolsBlock=junosBlock(cfg,'protocols');
  const iccpBlock=protocolsBlock?junosBlock(protocolsBlock,'iccp'):'';
  const peerLink=(iccpBlock.match(/peer\s+([\d.]+)\s*\{/)||[])[1]||'';
  return{type:'MC-LAG',domain:mcaeId,peerLink,mode,members:[{id:chassisId}]};
}

// ── DHCP (Junos: access pools + forwarding-options relay) ─
function parseJuniperDHCP(cfg){
  const pools=[];

  // A) DHCP Server pools: access { address-assignment { pool NAME { family inet { ... } } } }
  const accessBlock=junosBlock(cfg,'access');
  const aaBlock=accessBlock?junosBlock(accessBlock,'address-assignment'):'';
  if(aaBlock){
    const poolSubs=junosSubBlocks(aaBlock);
    for(const{name:pname,content:pbody}of poolSubs){
      if(!/^pool\s/i.test(pname))continue;
      const poolName=pname.replace(/^pool\s+/,'').trim();
      const inetBlock=junosBlock(pbody,'family inet')||junosBlock(pbody,'inet');
      if(!inetBlock)continue;
      const network=(inetBlock.match(/network\s+([\d./]+);/)||[])[1]||'';
      const low=(inetBlock.match(/low\s+([\d.]+);/)||[])[1]||'';
      const high=(inetBlock.match(/high\s+([\d.]+);/)||[])[1]||'';
      const gw=(inetBlock.match(/router\s*\{\s*([\d.]+);/)||[])[1]||'';
      const dnsMatch=[...inetBlock.matchAll(/(?:name-server|dns-server)\s*\{\s*([\d.]+);?\s*(?:([\d.]+);?)?\s*\}/g)];
      const dns=dnsMatch.flatMap(m=>[m[1],m[2]].filter(Boolean));
      // 2026-07-24 對外查證官方 Junos dhcp-attributes CLI Reference 後新增：boot-file(Option67)／
      // boot-server(泛用下一台伺服器)／tftp-server(Option150 備援)／option 42 ip-address(NTP，取
      // 第一筆)，皆位於同一個 family inet 區塊內（不論是否巢狀在 dhcp-attributes 子區塊，正則直接
      // 對整個 inetBlock 文字掃描，與既有 dns 寫法一致不需額外拆解子區塊）
      const bootFile=(inetBlock.match(/boot-file\s+"?([^"\n;]+)"?;/)||[])[1]||'';
      const nextServer=(inetBlock.match(/boot-server\s+([\d.]+);/)||[])[1]||(inetBlock.match(/tftp-server\s+([\d.]+);/)||[])[1]||'';
      const ntpM=inetBlock.match(/option\s+42\s+ip-address\s+([^;]+);/);
      const ntpServer=ntpM?ntpM[1].trim().split(/\s+/)[0]:'';
      // Which interface binds this pool?
      const svcBlock=junosBlock(junosBlock(cfg,'system')||'','services')||'';
      const dhcpLSBlock=junosBlock(svcBlock,'dhcp-local-server')||'';
      const ifaceM=dhcpLSBlock.match(/interface\s+([\w./-]+);/);
      const iface=ifaceM?ifaceM[1]:'';
      pools.push({name:poolName,network,range:low&&high?low+'-'+high:'',
        gateway:gw,dns,interface:iface,bootFile,nextServer,ntpServer,type:'server'});
    }
  }

  // B) DHCP Relay: forwarding-options { dhcp-relay { server-group G { IP; } group G { interface I; } } }
  const fwdBlock=junosBlock(cfg,'forwarding-options');
  const relayBlock=fwdBlock?junosBlock(fwdBlock,'dhcp-relay'):'';
  if(relayBlock){
    // 2026-07-24 對外查證官方 Junos relay-option-82 CLI Reference 後新增：Option82 掛在
    // "forwarding-options dhcp-relay relay-option-82 { circuit-id; remote-id; }" 子區塊，不需要
    // 先啟用類似 Cisco/Ruckus 的 DHCP Snooping 開關，套用到該廠牌全部 relay 條目
    const option82=/relay-option-82\s*\{/.test(relayBlock);
    // Server groups: "server-group NAME { IP; IP; }"
    const serverGroups={};
    const sgSubs=junosSubBlocks(relayBlock);
    for(const{name:sgname,content:sgbody}of sgSubs){
      if(!/^server-group\s/i.test(sgname))continue;
      const gname=sgname.replace(/^server-group\s+/,'').trim();
      const ips=[...sgbody.matchAll(/([\d.]+);/g)].map(m=>m[1]);
      serverGroups[gname]=ips;
    }
    // Relay groups: "group NAME { active-server-group G; interface I; }"
    for(const{name:rgname,content:rgbody}of sgSubs){
      if(!/^group\s/i.test(rgname))continue;
      const gname=rgname.replace(/^group\s+/,'').trim();
      const asg=(rgbody.match(/active-server-group\s+(\S+);/)||[])[1]||'';
      const servers=serverGroups[asg]||[];
      const ifaceM=[...rgbody.matchAll(/interface\s+([\w./-]+);/g)].map(m=>m[1]);
      for(const iface of ifaceM){
        pools.push({name:gname,network:'',range:'',gateway:'',
          dns:[],interface:iface,type:'relay',
          relayServer:servers.join(', '),option82});
      }
    }
  }

  return pools;
}

// ── Top-level ─────────────────────────────────────────────
function parseJuniper(cfg){
  const vc=parseJuniperVC(cfg);
  // stack for display: VC uses same structure as IRF/VSF；VC 與 MC-LAG 實務上互斥
  // （單機不會同時是實體堆疊又是雙機互聯冗餘），VC 優先，找不到 VC 才檢查 MC-LAG
  const stack=vc?{type:'VC',members:vc.members,links:vc.links,details:vc}:parseJuniperMCLAG(cfg);
  const interfaces=parseJuniperInterfaces(cfg);
  const breakouts=parseJuniperBreakout(cfg);
  breakouts.forEach(b=>{
    const iface=interfaces.find(f=>f.name.toLowerCase()===b.parentPort.toLowerCase());
    if(iface)iface.breakoutMode=b.mode;
  });
  return{
    sys:         parseJuniperSysInfo(cfg),
    irf:null, stack,
    vlans:       parseJuniperVLANs(cfg),
    interfaces,
    lacp:        parseJuniperLACP(cfg),
    routes:      parseJuniperRoutes(cfg),
    vrfs:        parseJuniperVRFs(cfg),
    users:       parseJuniperUsers(cfg),
    ospf:        parseJuniperOSPF(cfg),
    ospf6:       parseJuniperOSPFv3(cfg),
    bgp:         parseJuniperBGP(cfg),
    vrrp:[], rip:[], vxlan:null,
    dhcp:        parseJuniperDHCP(cfg),
    breakouts,
    vendor:'juniper'
  };
}


// ═ RouterOS / MikroTik Parser ═
// ════════════════════════════════════════════════════════════
