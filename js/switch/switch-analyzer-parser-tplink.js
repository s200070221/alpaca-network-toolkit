// ══════════════════════════════════════════════════════════
//  TP-Link JetStream／Omada 受管交換器 PARSER（XN153）
// ══════════════════════════════════════════════════════════
// 依官方「CLI Reference Guide — Managed Switches」（1900002754 REV1.1.0，2026-04，support.omadanetworks.com
// 文件類型 CLI Reference Guide，PDF 放在 static.tp-link.com）的指令語法：
//   12.1  interface {fastEthernet|gigabitEthernet|two-gigabitEthernet|ten-gigabitEthernet} 埠（例：interface gigabitEthernet 1/0/2）
//   12.3／12.4 description、shutdown
//   20.1／20.2 vlan 清單＋子模式 name（例：vlan 2 → name group1）
//   20.5  switchport general allowed vlan 清單 {tagged|untagged}、20.6 switchport pvid N（general 埠＝PVID＋各 VLAN 出口規則）
//   17.1  channel-group N mode {on|active|passive}；42.8 interface port-channel N
//   42.2  interface vlan N＋5.x ip address 位址 遮罩 [secondary]；42.9 ip route 目的 遮罩 下一跳 [distance]
//   4.1／4.3 user name 帳號 [privilege admin|operator|power_user|user] {password [0|7] …|secret [0|5|8|9] …}
//   5.x hostname、location；system-time ntp 時區 NTP伺服器 備援伺服器
//   37.6 spanning-tree mode {stp|rstp|mstp|rpvst}；68.1 ip ssh server；69.2 telnet {enable|disable}；
//   67.1／67.5 ip http server、ip http secure-server；90.5 snmp-server community 名稱 {read-only|read-write} MIB檢視
// 手冊沒有完整的 show running-config 輸出範例：子指令的縮排與區塊分隔（# 或 !）未查證，故介面／VLAN 區塊以
// 「之後到下一個全域指令為止」判斷（縮排與否都接受），名稱的雙引號一律去掉。未涵蓋：ACL、QoS、DHCP、OSPF、
// 堆疊、MAC VLAN、Voice VLAN、802.1X（語法未逐項核對）。
(function(){
  // 介面區塊結束：下一個全域指令（非縮排、非已知子指令）
  const TPL_SUB_RE=/^\s*(?:no\s+)?(?:switchport|channel-group|description|shutdown|name|ip\s+address|ipv6|speed|duplex|flow-control|jumbo-size|spanning-tree\s+(?:portfast|bpduguard|common-config|port|tc-guard|loop-protect|root-protect|edge)|lldp|lacp\s+port-priority|storm-control|bandwidth|qos|mac\s+address-table|loopback-detection|dot1x|power\s+inline|media-type|port\s+isolation|ip\s+(?:verify|dhcp\s+filter)|eee|switchport\s+check)\b/i;
  const unq=s=>String(s||'').trim().replace(/^"(.*)"$/,'$1');
  function isTpLink(cfg){
    const port=/^interface\s+(?:fastEthernet|gigabitEthernet|two-gigabitEthernet|ten-gigabitEthernet)\s+\d+\/\d+\/\d+\s*$/m;
    const general=/^\s*switchport\s+general\s+allowed\s+vlan\s+\S+\s+(?:tagged|untagged)\s*$/m;
    const user=/^user\s+name\s+\S+\s+(?:privilege\s+(?:admin|operator|power_user|user)\s+)?(?:password|secret)\b/m;
    return port.test(cfg)&&(general.test(cfg)||user.test(cfg)||/^\s*switchport\s+pvid\s+\d+\s*$/m.test(cfg));
  }
  // 「關鍵字 … 」之後到下一個全域指令為止的區塊
  function blocks(cfg, headRe){
    const lines=cfg.split('\n'), out=[];
    for(let i=0;i<lines.length;i++){
      const m=lines[i].match(headRe);
      if(!m)continue;
      const body=[];
      for(let j=i+1;j<lines.length;j++){
        const l=lines[j];
        if(!l.trim()||/^\s*[#!]\s*$/.test(l)||/^\s*(?:exit|end)\s*$/.test(l)){ if(/^\s*(?:exit|end)\s*$/.test(l)||/^\s*[#!]/.test(l))break; continue; }
        if(/^\s/.test(l)||TPL_SUB_RE.test(l)){ body.push(l.trim()); continue; }
        break;
      }
      out.push({m, body:body.join('\n')});
    }
    return out;
  }
  const vlanList=s=>[...(typeof expandL2VlanList==='function'?expandL2VlanList(s):String(s||'').split(',').flatMap(t=>{const m=t.trim().match(/^(\d+)(?:-(\d+))?$/);if(!m)return[];const a=+m[1],b=m[2]?+m[2]:a;const o=[];for(let v=a;v<=Math.min(b,a+4094);v++)o.push(String(v));return o;}))].map(String);
  const cidr=m=>typeof cidrFromMask==='function'?cidrFromMask(m):(typeof maskToCIDR==='function'?maskToCIDR(m):m);
  function parseTpLink(cfg){
    const val=re=>(cfg.match(re)||[])[1];
    const sys={hostname:unq(val(/^hostname\s+(.+)$/m))||'TP-Link',version:'',model:unq(val(/^!\s*(T\S+|TL-\S+|SG\S+|SX\S+)\s*$/m))||'-',serial:'-',mgmtIp:'',
      location:unq(val(/^location\s+(.+)$/m))||''};
    // VLAN：vlan 清單（可為範圍）＋子模式 name
    const vids=new Set(), declared=new Set(), vnames={};
    blocks(cfg,/^vlan\s+([\d,\-]+)\s*$/).forEach(({m,body})=>{
      const ids=vlanList(m[1]); ids.forEach(v=>{vids.add(v);declared.add(v);});
      const n=body.match(/^name\s+(.+)$/m); if(n&&ids.length===1)vnames[ids[0]]=unq(n[1]);
    });
    const interfaces=[], lagMembers={};
    // 實體埠與 port-channel
    blocks(cfg,/^interface\s+(fastEthernet|gigabitEthernet|two-gigabitEthernet|ten-gigabitEthernet|port-channel)\s+(\S+)\s*$/).forEach(({m,body})=>{
      const name=m[1]+' '+m[2], isLag=m[1]==='port-channel';
      const g=re=>(body.match(re)||[])[1];
      const pvid=g(/^switchport\s+pvid\s+(\d+)\s*$/m)||'';
      const untagged=[], tagged=[];
      [...body.matchAll(/^switchport\s+general\s+allowed\s+vlan\s+(\S+)\s+(tagged|untagged)\s*$/gm)].forEach(x=>{
        if(/^all$/i.test(x[1]))return;   // all＝所有已建立的 VLAN（tagged），不展開
        vlanList(x[1]).forEach(v=>{const a=x[2]==='tagged'?tagged:untagged;if(!a.includes(v))a.push(v);});
      });
      [...untagged,...tagged,pvid].filter(Boolean).forEach(v=>vids.add(v));
      const hybrid=(pvid||untagged.length||tagged.length)?{pvid,untagged,tagged,vlanMaps:[],hasIPSub:false,hasQinQ:false}:null;
      const cg=body.match(/^channel-group\s+(\d+)\s+mode\s+(on|active|passive)\s*$/m);
      if(cg)(lagMembers[cg[1]]=lagMembers[cg[1]]||[]).push({name,lacpMode:cg[2]==='on'?null:cg[2]});
      interfaces.push({name,type:isLag?'lag':'physical',desc:unq(g(/^description\s+(.+)$/m)),mode:hybrid?'hybrid':'',
        vlans:hybrid?[...untagged,...tagged].join(' '):'',nativeVlan:'',vrf:'',ip:'',shutdown:/^shutdown\s*$/m.test(body),member:'1',
        hybrid,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:'',channelGroup:cg?cg[1]:''});
    });
    // SVI：interface vlan N＋ip address
    blocks(cfg,/^interface\s+vlan\s+(\d+)\s*$/).forEach(({m,body})=>{
      const vid=m[1];
      const ipLines=[...body.matchAll(/^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(\s+secondary)?\s*$/gm)];
      const primary=ipLines.find(x=>!x[3]);
      vids.add(vid);
      interfaces.push({name:'vlan '+vid,type:'svi',desc:unq((body.match(/^description\s+(.+)$/m)||[])[1]),ip:primary?primary[1]+'/'+cidr(primary[2]):'',ip6:'',
        secondaryIps:ipLines.filter(x=>x[3]).map(x=>x[1]+'/'+cidr(x[2])),mode:'',vlans:vid,nativeVlan:'',vrf:'',shutdown:/^shutdown\s*$/m.test(body),member:'1',
        hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      if(primary&&!sys.mgmtIp)sys.mgmtIp=primary[1];
    });
    const sviIp={}; interfaces.filter(i=>i.type==='svi'&&i.ip).forEach(i=>{sviIp[i.vlans]=i.ip;});
    const vlans=[...vids].sort((a,b)=>a-b).map(id=>Object.assign({id,name:vnames[id]||'',ipSubnets:sviIp[id]?[{cidr:sviIp[id]}]:[]},declared.has(id)?{}:{implied:true}));
    const lacp=Object.keys(lagMembers).sort((a,b)=>a-b).map(n=>({name:'port-channel '+n,mode:lagMembers[n].some(x=>x.lacpMode)?'Active':'Static',members:lagMembers[n],desc:''}));
    const routes=[...cfg.matchAll(/^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?\s*$/gm)]
      .map(x=>({dst:x[1]+'/'+cidr(x[2]),gw:x[3],vrf:'',distance:x[4]||''}));
    // 帳號：password 0＝明碼、7＝可逆加密；secret 0 會以雜湊顯示，5／8／9 為雜湊
    const users=[...cfg.matchAll(/^user\s+name\s+("[^"]*"|\S+)(?:\s+privilege\s+(admin|operator|power_user|user))?\s+(password|secret)\s+(?:(\d)\s+)?\S+/gm)]
      .map(x=>({name:unq(x[1]),role:x[2]||'',service:'web/cli',hasPwd:true,
        pwdType:x[3]==='secret'?'hash':x[4]==='7'?'type7':'plain',pwdWeak:x[3]==='password'&&x[4]!=='7'}));
    const stp={mode:val(/^spanning-tree\s+mode\s+(stp|rstp|mstp|rpvst)\s*$/m)||'',instances:[],ports:[],rootMode:'',timers:{}};
    const snmp={communities:[...cfg.matchAll(/^snmp-server\s+community\s+("[^"]*"|\S+)\s+(read-only|read-write)\b/gm)].map(x=>({name:unq(x[1]),access:x[2]==='read-write'?'rw':'ro'})),v3Users:[],hosts:[]};
    const telnet=/^telnet\s+enable\s*$/m.test(cfg)?true:/^telnet\s+disable\s*$/m.test(cfg)?false:null;
    return {sys,irf:null,stack:null,vlans,interfaces,routes,vrfs:[],users,ospf:[],bgp:[],rip:[],vrrp:[],vxlan:null,acls:[],
      lacp,stp,snmp,dns:[],dhcp:[],qos:[],breakouts:[],vendor:'tplink',
      mgmtAccess:{ssh:/^ip\s+ssh\s+server\s*$/m.test(cfg)?true:/^no\s+ip\s+ssh\s+server\s*$/m.test(cfg)?false:null,telnet}};
  }
  // 多個 classic script 共用全域：只掛出這兩個函式（測試沙箱沒有 window，掛在 globalThis）
  globalThis.isTpLink=isTpLink;
  globalThis.parseTpLink=parseTpLink;
})();
