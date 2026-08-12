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
  const bgp=parseCiscoBGP(cfg);
  const rip=parseCiscoRIP(cfg);
  const vrrp=parseVRRP(cfg,'arista');
  return{sys,irf:null,stack:mlag,vlans,interfaces,routes,vrfs,users,ospf,bgp,rip,vrrp,vxlan:null,breakouts,vendor:'arista'};
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
