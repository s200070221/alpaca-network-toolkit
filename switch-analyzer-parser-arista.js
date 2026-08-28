function _expandVlanRange(str){
  const ids=[];
  for(const part of str.split(',')){
    const t=part.trim(); const dash=t.indexOf('-');
    if(dash>0){const a=parseInt(t.slice(0,dash)),b=parseInt(t.slice(dash+1));for(let i=a;i<=b&&i-a<2048;i++)ids.push(i);}
    else{const n=parseInt(t);if(!isNaN(n))ids.push(n);}
  }
  return ids;
}
function parseAristaSysInfo(cfg){
  return{
    hostname:(cfg.match(/^hostname\s+(\S+)/m)||[])[1]||'unknown',
    version:(cfg.match(/^!\s*Software image version:\s*(?:EOS\s+)?(\S+)/im)||cfg.match(/^version\s+(\S+)/m)||[])[1]?.trim()||'',
    platform:(cfg.match(/^!\s*(?:device|Hardware):\s*(\S+)/im)||[])[1]||'',
  };
}
function parseAristaVLANs(cfg){
  const vlans=[],seen=new Set();
  const re=/^vlan\s+([\d,\-]+)\s*\n([\s\S]*?)(?=^vlan\s|^interface\s|^router\s|^spanning-tree\b|^ip\s+routing|^!\s*$)/gm;
  let m;
  while((m=re.exec(cfg))!==null){
    const ids=_expandVlanRange(m[1]);
    const name=(m[2].match(/^\s*name\s+(.+)/m)||[])[1]?.trim()||'';
    for(const id of ids)if(!seen.has(id)){seen.add(id);vlans.push({id:String(id),name:ids.length===1?name:'',ipSubnets:[]});}
  }
  const re2=/^vlan\s+(\d+)$/gm;
  while((m=re2.exec(cfg))!==null){const n=parseInt(m[1]);if(!seen.has(n)){seen.add(n);vlans.push({id:m[1],name:'',ipSubnets:[]});}}
  return vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
}
function parseAristaMlag(cfg){
  const m=cfg.match(/^mlag\s+configuration\s*\n((?:[ \t][^\n]*\n?)*)/m);
  if(!m)return null;
  const body=m[1];
  return{type:'MLAG',
    domain:(body.match(/domain-id\s+(\S+)/)||[])[1]||'-',
    peerLink:(body.match(/peer-link\s+(\S+)/)||[])[1]||'-',
    peerAddr:(body.match(/peer-address\s+(\S+)/)||[])[1]||'-',
    localIntf:(body.match(/local-interface\s+(\S+)/)||[])[1]||'-',
    members:[{id:'1',model:'',priority:null,role:'primary'},{id:'2',model:'',priority:null,role:'secondary'}],
  };
}
// Arista EOS Breakout：母埠 interface EthernetN 區塊內 "breakout mode 4x10G/4x25G/2x50G" 啟用
// （已查證官方文件：Arista Community "Understanding interface breakout modes on Arista switches"，
// 子埠命名為 EthernetN/1~4，如 Et45 拆分後為 Et45/1~Et45/4）；因 parseArista() 的 interface 解析
// 借用 parseCiscoInterfaces()（Cisco IOS-XE 共用函式，子埠命名規則不同），breakout 偵測獨立成
// 這個函式，在 parseArista() 內做後製回填，不污染 Cisco 本身的解析路徑
function parseAristaBreakout(cfg){
  const breakouts=[];
  const blocks=cfg.split(/^interface\s+/m).slice(1);
  for(const blk of blocks){
    const lines=blk.split('\n');
    const name=lines[0].trim();
    const body=lines.slice(1).join('\n');
    const m=body.match(/^\s*breakout mode\s+(4x10G|4x25G|2x50G)\b/mi);
    if(m)breakouts.push({parentPort:name,mode:m[1],raw:m[0].trim()});
  }
  return breakouts;
}
function parseArista(cfg){
  const sys=parseAristaSysInfo(cfg);
  const vlans=parseAristaVLANs(cfg);
  const mlag=parseAristaMlag(cfg);
  const interfaces=parseCiscoInterfaces(cfg,'arista');
  // Breakout 子埠命名 pattern 偵測（EthernetN/1~4），獨立於 parseCiscoInterfaces() 的
  // HundredGigE pattern B 判斷式之外
  interfaces.forEach(i=>{
    const bkMatch=i.name.match(/^Ethernet(\d+)\/([1-4])$/i);
    if(bkMatch){ i.breakoutChild=true; i.breakoutParent=`Ethernet${bkMatch[1]}`; }
  });
  const breakouts=parseAristaBreakout(cfg);
  breakouts.forEach(b=>{
    const iface=interfaces.find(f=>f.name.toLowerCase()===b.parentPort.toLowerCase());
    if(iface)iface.breakoutMode=b.mode;
  });
  const routes=parseCiscoRoutes(cfg);
  const vrfs=parseCiscoVRFs(cfg,'arista');
  const users=parseCiscoUsers(cfg);
  const ospf=parseCiscoOSPF(cfg);
  const ospf6=parseCiscoOSPFv3(cfg);
  const bgp=parseCiscoBGP(cfg);
  const rip=parseCiscoRIP(cfg);
  const rip6=parseCiscoRIPng(cfg);
  const vrrp=parseVRRP(cfg,'arista');
  return{sys,irf:null,stack:mlag,vlans,interfaces,routes,vrfs,users,ospf,ospf6,bgp,rip,rip6,vrrp,vxlan:null,breakouts,vendor:'arista'};
}

// class-map/match + service-policy（2026-08-28（續5）新增）：官方 EOS Quality of Service／
// Traffic Management 文件直接 fetch 查證，語法比 Cisco 家族多一段 "type qos" 限定詞——
// class-map 標頭為 "class-map type qos {match-any|match-all} NAME"（比照既有 policy-map
// 已查證的 "type quality-of-service" 模式，見 renderAristaQoS() 對應註解），service-policy
// 為 "service-policy type qos {input|output} NAME"（type 限定詞在 direction 之前，與 Dell
// OS10 語序相反，見該廠牌 parser 對應註解）。match 條件本輪僅確認 "match ip access-group
// NAME"（非 Cisco 裸 "match access-group N"），dscp/cos/protocol/ip-precedence 未查得官方
// 逐字語法，非本輪範圍，不臆測
function parseAristaClassMaps(cfg){
  const maps=[];
  const cmRe=/^class-map\s+type\s+qos\s+(match-any|match-all)\s+(\S+)([\s\S]*?)(?=^class-map\s+type\s+qos\s+|^policy-map\s+|(?![\s\S]))/gm;
  let m;
  while((m=cmRe.exec(cfg))!==null){
    const matchType=m[1], name=m[2], body=m[3]||'', matches=[];
    let mm; const agRe=/^\s*match\s+ip\s+access-group\s+(\S+)/gim;
    while((mm=agRe.exec(body))!==null)matches.push({type:'access-group',value:mm[1]});
    maps.push({name,matchType,matches});
  }
  return maps;
}
function parseAristaServicePolicy(cfg){
  const apps=[];
  cfg.split(/(?=^interface\s)/m).forEach(blk=>{
    const ifLine=blk.match(/^interface\s+(\S.*)/m);
    if(!ifLine)return;
    const ifName=ifLine[1].trim();
    let m; const spRe=/^\s*service-policy\s+type\s+qos\s+(input|output)\s+(\S+)/gim;
    while((m=spRe.exec(blk))!==null)apps.push({policy:m[2],interface:ifName,direction:m[1].toLowerCase()});
  });
  return apps;
}

// ════════════════════════════════════════════════════
//  RUIJIE (RGOS) PARSER
// ════════════════════════════════════════════════════
// 依官方 RGOS Command Reference/Configuration Guide 與 VSU 技術文檔
// （https://www.ruijie.com.cn/fw/wt/90872/）語法推測實作，尚無真實匯出設定檔驗證，
// 信心度低於其他已用真實範例校正過的廠牌，待未來取得真實設定檔再校正（見 now.md）。
// RGOS 語法系出 Cisco IOS 風格，VLAN/OSPF/BGP/RIP/靜態路由重用 Cisco 對應 parser；
// LACP（AggregatePort/port-group）、hybrid port、VRRP、VSU 堆疊四項語法與 Cisco
// 實質不同，各自獨立實作。
