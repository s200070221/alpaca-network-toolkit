// ══════════════════════════════════════════════════════════
//  Zyxel GS／XGS 受管交換器（ZyNOS 式 CLI）PARSER（XN155）
// ══════════════════════════════════════════════════════════
// 依官方「Ethernet Switch CLI Reference Guide」（XGS2220-30 V1.00–5.00 Ed8，download.zyxel.com）：
//   show running-config 範例（GS1350-26HP）：「; Product Name = 型號」「; Firmware Version = 版本」、
//   vlan N 子模式 name／normal ""／fixed 埠清單／forbidden ""／untagged 埠清單／ip address 位址 遮罩、exit，
//   interface port-channel N（Zyxel 的 port-channel 指實體埠）、interface route-domain 位址/遮罩、
//   timesync server …／timesync ntp、service-control http 80 55、no service-control telnet
//   Table（Port）：interface port-channel <port-list> 子模式 pvid、name、inactive
//   Trunk：trunk T1～T6（啟用）、trunk Tn interface <port-list>（成員）、trunk Tn lacp
//   logins username 名稱 password [cipher] 密碼 [privilege 0-14]、admin-password [[cipher] 密碼]
//   snmp-server get-community [cipher] 名稱、set-community；spanning-tree mode RSTP|MRSTP|MSTP
//   ip route 網段 遮罩 下一跳 [metric N] [name 名稱] [inactive]；syslog server 位址 level N；hostname 名稱
// 埠的 VLAN 成員依各 VLAN 的 fixed（成員）與 untagged（不加標籤）推得：成員但不在 untagged 者為 tagged。
// 未涵蓋：ACL（classifier／policy）、QoS、DHCP、IGMP、MRSTP 細節。
(function(){
  const unq=s=>String(s||'').trim().replace(/^["“”](.*)["“”]$/,'$1');
  function isZyxelSw(cfg){
    return (/^;\s*Product Name\s*=\s*\S/m.test(cfg)&&/^;\s*Firmware Version\s*=\s*\S/m.test(cfg))||
      (/^\s*fixed\s+[\d,\-]+\s*$/m.test(cfg)&&/^\s*forbidden\s+\S*/m.test(cfg)&&/^\s*untagged\s+[\d,\-]*\s*$/m.test(cfg));
  }
  // 「標頭 … exit」區塊（範例的子指令縮排、以 exit 結束）
  function blocks(cfg, headRe){
    const lines=cfg.split('\n'), out=[];
    for(let i=0;i<lines.length;i++){
      const m=lines[i].trim().match(headRe);
      if(!m)continue;
      const body=[];
      for(let j=i+1;j<lines.length;j++){
        const l=lines[j].trim();
        if(/^exit$/.test(l))break;
        if(l)body.push(l);
      }
      out.push({m, body:body.join('\n')});
    }
    return out;
  }
  const list=s=>[...(typeof expandL2VlanList==='function'?expandL2VlanList(unq(s)):[])].map(String);
  const cidr=m=>typeof maskToCIDR==='function'?maskToCIDR(m):m;
  function parseZyxelSw(cfg){
    // 範例的英文引號可能是「“”」（手冊排版），一律當成雙引號
    const val=re=>(cfg.match(re)||[])[1];
    const sys={hostname:unq(val(/^\s*hostname\s+(.+)$/m))||'Zyxel',version:(val(/^;\s*Firmware Version\s*=\s*(\S+)/m)||''),
      model:val(/^;\s*Product Name\s*=\s*(\S+)/m)||'-',serial:'-',mgmtIp:'',location:''};
    const ports=new Map(); // 埠號 → {untagged:[], tagged:[], pvid, name, inactive}
    const port=n=>{ if(!ports.has(n))ports.set(n,{untagged:[],tagged:[],pvid:'',name:'',inactive:false}); return ports.get(n); };
    const vlans=[], vids=new Set();
    blocks(cfg,/^vlan\s+(\d+)$/).forEach(({m,body})=>{
      const id=m[1], g=re=>(body.match(re)||[])[1];
      const fixed=list(g(/^fixed\s+(\S*)$/m)||''), untagged=new Set(list(g(/^untagged\s+(\S*)$/m)||''));
      fixed.forEach(p=>{ const o=port(p); (untagged.has(p)?o.untagged:o.tagged).push(id); });
      const ipM=body.match(/^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$/m);
      if(ipM&&!sys.mgmtIp)sys.mgmtIp=ipM[1];
      vids.add(id);
      vlans.push({id,name:unq(g(/^name\s+(.+)$/m)),ipSubnets:ipM?[{cidr:ipM[1]+'/'+cidr(ipM[2])}]:[],inactive:/^inactive$/m.test(body)});
    });
    blocks(cfg,/^interface\s+port-channel\s+([\d,\-]+)$/).forEach(({m,body})=>{
      list(m[1]).forEach(p=>{ const o=port(p);
        const pv=body.match(/^pvid\s+(\d+)$/m); if(pv)o.pvid=pv[1];
        const nm=body.match(/^name\s+(.+)$/m); if(nm)o.name=unq(nm[1]);
        if(/^inactive$/m.test(body))o.inactive=true; });
    });
    // 聚合：trunk Tn interface 埠清單、trunk Tn lacp
    const trunks={};
    [...cfg.matchAll(/^\s*trunk\s+(T\d)\s+interface\s+([\d,\-]+)\s*$/gm)].forEach(x=>{ (trunks[x[1]]=trunks[x[1]]||[]).push(...list(x[2])); });
    const lacpOn=new Set([...cfg.matchAll(/^\s*trunk\s+(T\d)\s+lacp\s*$/gm)].map(x=>x[1]));
    const memberOf={}; Object.keys(trunks).forEach(t=>trunks[t].forEach(p=>{memberOf[p]=t;port(p);}));
    const interfaces=[...ports.keys()].sort((a,b)=>a-b).map(n=>{
      const o=ports.get(n), pvid=o.pvid||(o.untagged.length===1?o.untagged[0]:'');
      const hybrid=(o.untagged.length||o.tagged.length||o.pvid)?{pvid,untagged:o.untagged,tagged:o.tagged,vlanMaps:[],hasIPSub:false,hasQinQ:false}:null;
      return {name:n,type:'physical',desc:o.name,mode:hybrid?'hybrid':'',vlans:hybrid?[...o.untagged,...o.tagged].join(' '):'',nativeVlan:'',vrf:'',ip:'',
        shutdown:o.inactive,member:'1',hybrid,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:'',channelGroup:memberOf[n]||''};
    });
    // route-domain：三層介面（位址/遮罩）
    // 名稱用序號（位址放 ip 欄位），去識別化前後介面名稱一致
    blocks(cfg,/^interface\s+route-domain\s+(\d+\.\d+\.\d+\.\d+)\/(\S+)$/).forEach(({m},k)=>{
      const bits=/^\d+$/.test(m[2])?m[2]:cidr(m[2]);
      interfaces.push({name:'route-domain '+(k+1),type:'svi',desc:'',ip:m[1]+'/'+bits,ip6:'',secondaryIps:[],mode:'',vlans:'',nativeVlan:'',vrf:'',shutdown:false,member:'1',
        hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
    });
    const lacp=Object.keys(trunks).sort().map(t=>({name:t,mode:lacpOn.has(t)?'Active':'Static',members:trunks[t].map(p=>({name:p,lacpMode:lacpOn.has(t)?'active':null})),desc:''}));
    const routes=[...cfg.matchAll(/^\s*ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+metric\s+(\d+))?(?:\s+name\s+(\S+))?(\s+inactive)?\s*$/gm)]
      .map(x=>({dst:x[1]+'/'+cidr(x[2]),gw:x[3],vrf:'',metric:x[4]||'',disabled:!!x[6]}));
    // 帳號：cipher＝加密字串，否則為明碼；admin-password 為管理者 admin 的密碼
    const users=[...cfg.matchAll(/^\s*logins\s+username\s+(\S+)\s+password\s+(cipher\s+)?\S+(?:\s+privilege\s+(\d+))?\s*$/gm)]
      .map(x=>({name:x[1],role:x[3]?'privilege-'+x[3]:'',service:'web/cli',hasPwd:true,pwdType:x[2]?'hash':'plain',pwdWeak:!x[2]}));
    const ap=cfg.match(/^\s*admin-password\s+(cipher\s+)?\S+/m);
    if(ap)users.unshift({name:'admin',role:'admin',service:'web/cli',hasPwd:true,pwdType:ap[1]?'hash':'plain',pwdWeak:!ap[1]});
    const stp={mode:(val(/^\s*spanning-tree\s+mode\s+(RSTP|MRSTP|MSTP)\s*$/mi)||'').toLowerCase(),instances:[],ports:[],rootMode:'',timers:{}};
    const comm=(kw,acc)=>[...cfg.matchAll(new RegExp('^\\s*snmp-server\\s+'+kw+'\\s+(?:cipher\\s+)?(\\S+)\\s*$','gm'))].map(x=>({name:unq(x[1]),access:acc}));
    const snmp={communities:[...comm('get-community','ro'),...comm('set-community','rw')],v3Users:[],hosts:[]};
    const svc=k=>new RegExp('^\\s*no\\s+service-control\\s+'+k+'\\b','m').test(cfg)?false:new RegExp('^\\s*service-control\\s+'+k+'\\b','m').test(cfg)?true:null;
    return {sys,irf:null,stack:null,vlans:vlans.sort((a,b)=>a.id-b.id),interfaces,routes,vrfs:[],users,ospf:[],bgp:[],rip:[],vrrp:[],vxlan:null,acls:[],
      lacp,stp,snmp,dns:[],dhcp:[],qos:[],breakouts:[],vendor:'zyxelsw',
      mgmtAccess:{ssh:svc('ssh'),telnet:svc('telnet')},zyxelSvc:{http:svc('http'),https:svc('https'),snmp:svc('snmp')}};
  }
  globalThis.isZyxelSw=isZyxelSw;
  globalThis.parseZyxelSw=parseZyxelSw;
})();
