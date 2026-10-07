// ══════════════════════════════════════════════════════════
//  Netgear Smart Managed Pro（GS7xx 系列）PARSER — 2026-10-07，第十三輪 NC
// ══════════════════════════════════════════════════════════
// 與已支援的 M4300（Broadcom ICOS，`!Current Configuration:` 檔頭）是不同系統：設定檔以
// `SYSTEM CONFIG FILE ::= BEGIN` 開頭，接著 `! Model:`／`! System Description: NETGEAR …` 等註解。
// 公開可查的只有 Oxidized 的一份真實錄製（GS752TPP 6.0.10.14，存為 netgear_smart_real_oxidized.cfg），
// 官方手冊與社群站被網路政策擋下，故只解析錄製中實際出現的語法，其餘一律不處理：
//   system name "名稱"、system location "位置"
//   ip address A mask M、ip default-gateway G、ip name-server A [B …]
//   username "帳號" secret encrypted …
//   sntp N host 主機 port P ver V
//   snmp community "名稱" enable 位址 mask 遮罩 ro|rw、snmp host 位址 enable version 2c "名稱"、
//   snmp user "名稱" "群組" auth …
//   interface gN：switchport hybrid pvid N、switchport hybrid allowed vlan add N untagged|tagged、
//     switchport hybrid allowed vlan remove N（另有 GS724TPv2 範例 `add 10 untagged` 的搜尋摘要佐證）
// 錄製中沒有 vlan 宣告：VLAN 清單取自介面上出現的 VLAN（標 implied）。沒有 interface 區塊的埠不列出，
// 也不推測出廠預設的 VLAN 1 成員關係。未涵蓋：VLAN 名稱、LAG、STP（只有 spanning-tree mst configuration 一行）、ACL、QoS。
function isNetgearSmart(cfg){
  return /^SYSTEM CONFIG FILE ::= BEGIN\s*$/m.test(cfg)&&/^!\s*System Description:\s*NETGEAR\b/mi.test(cfg);
}
const _ngsUnq=s=>String(s||'').trim().replace(/^"(.*)"$/,'$1');
function parseNetgearSmart(cfg){
  const val=re=>(cfg.match(re)||[])[1];
  const ipM=cfg.match(/^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\d+\.\d+\.\d+\.\d+)/m);
  const sys={hostname:_ngsUnq(val(/^system\s+name\s+(.+)$/m))||_ngsUnq(val(/^!\s*System Name:\s*(.+)$/m))||'NETGEAR',
    version:(val(/^!\s*Firmware Version:\s*(\S+)/m)||''),model:val(/^!\s*Model:\s*(\S+)/m)||'-',serial:val(/^!\s*Serial Number:\s*(\S+)/m)||'-',
    mgmtIp:ipM?ipM[1]:'',location:_ngsUnq(val(/^system\s+location\s+(.+)$/m))||''};
  const vids=new Set();
  const interfaces=[];
  const re=/^interface\s+(\S+)\s*\n((?:[ \t]+[^\n]*(?:\n|$))*)/gm;let m;
  while((m=re.exec(cfg))!==null){
    const name=m[1], b=m[2];
    const pvid=(b.match(/^\s*switchport\s+hybrid\s+pvid\s+(\d+)/m)||[])[1]||'';
    const untagged=[], tagged=[], removed=[];
    [...b.matchAll(/^\s*switchport\s+hybrid\s+allowed\s+vlan\s+(add|remove)\s+([\d,\-]+)(?:\s+(tagged|untagged))?/gm)].forEach(x=>{
      const ids=expandL2VlanList(x[2]);
      if(x[1]==='remove'){ids.forEach(v=>{removed.push(v);[untagged,tagged].forEach(a=>{const k=a.indexOf(v);if(k>=0)a.splice(k,1);});});return;}
      ids.forEach(v=>{const a=x[3]==='tagged'?tagged:untagged;if(!a.includes(v))a.push(v);});
    });
    [...untagged,...tagged].forEach(v=>vids.add(v));
    if(pvid)vids.add(pvid);
    const hybrid=(pvid||untagged.length||tagged.length)?{pvid,untagged,tagged,vlanMaps:[],hasIPSub:false,hasQinQ:false}:null;
    interfaces.push({name,type:'physical',desc:_ngsUnq((b.match(/^\s*description\s+(.+)$/m)||[])[1]),mode:hybrid?'hybrid':'',
      vlans:hybrid?[...untagged,...tagged].join(' '):'',nativeVlan:'',vrf:'',ip:'',shutdown:/^\s*shutdown\s*$/m.test(b),member:'1',
      hybrid,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:'',removedVlans:removed});
  }
  const vlans=[...vids].sort((a,b)=>a-b).map(id=>({id,name:'',ipSubnets:[],implied:true}));
  const users=[...cfg.matchAll(/^username\s+("[^"]*"|\S+)\s+(secret|password)\s+(encrypted\s+)?\S+/gm)]
    .map(x=>({name:_ngsUnq(x[1]),role:'',service:'web/cli',hasPwd:true,pwdType:x[3]?'encrypted':'set',pwdWeak:false}));
  const gw=val(/^ip\s+default-gateway\s+(\d+\.\d+\.\d+\.\d+)/m);
  const routes=gw?[{dst:'0.0.0.0/0',gw,vrf:''}]:[];
  const communities=[], seenC=new Set();
  [...cfg.matchAll(/^snmp\s+community\s+("[^"]*"|\S+)[^\n]*?\b(ro|rw)\s*$/gm)].forEach(x=>{const n=_ngsUnq(x[1]);if(!seenC.has(n)){seenC.add(n);communities.push({name:n,access:x[2]});}});
  const snmp={communities,v3Users:[...cfg.matchAll(/^snmp\s+user\s+("[^"]*"|\S+)/gm)].map(x=>({name:_ngsUnq(x[1])})),
    hosts:[...cfg.matchAll(/^snmp\s+host\s+(\S+)/gm)].map(x=>({host:x[1]}))};
  const dns=((val(/^ip\s+name-server\s+([^\n]+)/m)||'').trim().split(/\s+/)).filter(t=>/^[\d.]+$|:/.test(t));
  return {sys,irf:null,stack:null,vlans,interfaces,routes,vrfs:[],users,ospf:[],bgp:[],rip:[],vrrp:[],vxlan:null,acls:[],
    lacp:[],stp:{mode:'',instances:[],ports:[],rootMode:'',timers:{}},snmp,dns,dhcp:[],qos:[],breakouts:[],vendor:'netgearsmart',
    ntpHosts:[...cfg.matchAll(/^sntp\s+\d+\s+host\s+(\S+)/gm)].map(x=>x[1]),
    mgmtAccess:{ssh:null,telnet:null}};
}
