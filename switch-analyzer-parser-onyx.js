// ══════════════════════════════════════════════════════════
//  NVIDIA Onyx（原 Mellanox MLNX-OS）交換器 PARSER（XN156）
// ══════════════════════════════════════════════════════════
// 格式：show running-config 為「單行前綴式」——每個介面子指令都寫成一整行
// （interface ethernet 1/15 shutdown、interface ethernet 1/28 ip address …），檔頭為「## Product release:」
// 「## Running database」「no cli default prefix-modes enable」；依 Oxidized 收錄的 Onyx 3.9.2504 真實錄製
// （spec/model/data/mlnxos#Onyx_3.9.2504#output.txt，內容經遮蔽、不完整）。
// 指令語法依官方 Onyx User Manual 3.10.4800（networking-docs.nvidia.com/onyxum/3.10.4800）：
//   VLANs：vlan {ID|範圍}、name 名稱、switchport mode {access|dot1q-tunnel|trunk|hybrid|access-dcb}、
//     switchport access vlan ID、switchport {hybrid|trunk} allowed-vlan {清單 | add 清單 | remove 清單 | all | except 清單 | none}
//   LAG：interface port-channel <1-4096>、channel-group <1-4096> [mode {on|active|passive}]
//   Ethernet Interfaces：description、shutdown；General IP Routing：interface vlan ID、ip address 位址 遮罩、
//     ip route [vrf 名稱] 網段 遮罩 {下一跳|null0} [distance]
//   User Management：username 名稱 [capability 能力 | nopassword | password [0|7] 密碼 …]
//   UI Commands：ssh server enable、telnet-server enable、web enable、web http enable、web https enable
//   SNMP：snmp-server community 名稱 [ro|rw]、snmp-server host [vrf 名稱] 位址 traps …；STP：spanning-tree mode {mst|rst|rpvst}
//   Logging：logging 位址（Oxidized 錄製為 logging vrf default 位址）；NTP：ntp server 位址；hostname 名稱
// 未涵蓋：MLAG、ACL、QoS、RoCE、BGP／OSPF 細節、VRF。
(function(){
  const unq=s=>String(s||'').trim().replace(/^"(.*)"$/,'$1');
  function isOnyx(cfg){
    return (/^##\s*Product release:\s*\S/m.test(cfg)&&/^##\s*Running database\b/m.test(cfg))||
      (/^\s*(?:no\s+)?cli\s+default\s+prefix-modes\s+enable\s*$/m.test(cfg)&&/^\s*interface\s+ethernet\s+\d+\/\d+(?:\/\d+)?\s+\S/m.test(cfg));
  }
  const list=s=>[...(typeof expandL2VlanList==='function'?expandL2VlanList(s):[])].map(String);
  const cidr=m=>/^\/?\d+$/.test(m)?m.replace('/',''):(typeof maskToCIDR==='function'?maskToCIDR(m):m);
  function parseOnyx(cfg){
    const lines=cfg.split('\n').map(l=>l.trim()).filter(l=>l&&!/^#/.test(l));
    const val=re=>{ for(const l of lines){ const m=l.match(re); if(m)return m[1]; } return ''; };
    const sys={hostname:unq(val(/^hostname\s+(.+)$/))||unq((cfg.match(/^##[ \t]*Hostname:[ \t]*(\S+)/m)||[])[1])||'Onyx',
      version:(cfg.match(/^##[ \t]*Product release:[ \t]*(\S+)/m)||[])[1]||'',model:(cfg.match(/^##[ \t]*Product model:[ \t]*(\S+)/m)||[])[1]||'-',serial:'-',mgmtIp:'',location:''};
    // 單行前綴式：interface <類型> <編號> <子指令>；範圍（ethernet 1/1-1/32）展開不處理，整段記在第一個埠名稱下不準確，故略過範圍行
    const ifs=new Map();
    const ifOf=(kind,id)=>{ const k=kind+' '+id; if(!ifs.has(k))ifs.set(k,{kind,id,cmds:[]}); return ifs.get(k); };
    const vids=new Set(), declared=new Set(), vnames={};
    lines.forEach(l=>{
      let m=l.match(/^interface\s+(ethernet|port-channel|vlan)\s+(\d+(?:\/\d+){0,2})(?:\s+(.+))?$/);
      if(m){ ifOf(m[1],m[2]).cmds.push(m[3]||''); return; }
      m=l.match(/^vlan\s+([\d,\-]+)(?:\s+name\s+(.+))?$/);
      if(m){ const ids=list(m[1]); ids.forEach(v=>{vids.add(v);declared.add(v);}); if(m[2]&&ids.length===1)vnames[ids[0]]=unq(m[2]); }
    });
    const interfaces=[], lagMembers={};
    [...ifs.values()].filter(o=>o.kind!=='vlan').forEach(o=>{
      const c=o.cmds, g=re=>{ for(const x of c){ const mm=x.match(re); if(mm)return mm[1]; } return ''; };
      const name=o.kind+' '+o.id, isLag=o.kind==='port-channel';
      const mode=g(/^switchport\s+mode\s+(access|trunk|hybrid|dot1q-tunnel|access-dcb)$/);
      let vlans='', nativeVlan='', hybrid=null;
      const allowed=c.map(x=>x.match(/^switchport\s+(trunk|hybrid)\s+allowed-vlan\s+(?:(add)\s+)?(\S+)$/)).filter(Boolean);
      const ids=[]; allowed.forEach(x=>{ if(/^(all|none|remove|except)$/.test(x[3]))return; list(x[3]).forEach(v=>{if(!ids.includes(v))ids.push(v);}); });
      const access=g(/^switchport\s+access\s+vlan\s+(\d+)$/);
      if(mode==='trunk'){ vlans=ids.length?ids.join(','):(allowed.some(x=>x[3]==='none')?'':'all'); ids.forEach(v=>vids.add(v)); }
      else if(mode==='hybrid'){ const pvid=access||'1'; hybrid={pvid,untagged:[pvid],tagged:ids.filter(v=>v!==pvid),vlanMaps:[],hasIPSub:false,hasQinQ:false};
        vlans=[pvid,...hybrid.tagged].join(' '); [pvid,...ids].forEach(v=>vids.add(v)); }
      else if(mode||access){ vlans=access||'1'; vids.add(vlans); }
      const cg=c.map(x=>x.match(/^channel-group\s+(\d+)(?:\s+mode\s+(on|active|passive))?$/)).find(Boolean);
      if(cg)(lagMembers[cg[1]]=lagMembers[cg[1]]||[]).push({name,lacpMode:cg[2]&&cg[2]!=='on'?cg[2]:null});
      interfaces.push({name,type:isLag?'lag':'physical',desc:unq(g(/^description\s+(.+)$/)),mode:mode==='hybrid'?'hybrid':(mode||(access?'access':'')),vlans,nativeVlan,vrf:'',ip:'',
        shutdown:c.includes('shutdown'),member:'1',hybrid,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:'',channelGroup:cg?cg[1]:''});
    });
    [...ifs.values()].filter(o=>o.kind==='vlan').forEach(o=>{
      const ipM=o.cmds.map(x=>x.match(/^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s*(\/\d+|\d+\.\d+\.\d+\.\d+)$/)).find(Boolean);
      const ip=ipM?ipM[1]+'/'+cidr(ipM[2]):'';
      vids.add(o.id);
      interfaces.push({name:'vlan '+o.id,type:'svi',desc:unq((o.cmds.find(x=>/^description\s/.test(x))||'').replace(/^description\s+/,'')),ip,ip6:'',secondaryIps:[],mode:'',vlans:o.id,nativeVlan:'',vrf:'',
        shutdown:o.cmds.includes('shutdown'),member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      if(ip&&!sys.mgmtIp)sys.mgmtIp=ipM[1];
    });
    const sviIp={}; interfaces.filter(i=>i.type==='svi'&&i.ip).forEach(i=>{sviIp[i.vlans]=i.ip;});
    const vlans=[...vids].sort((a,b)=>a-b).map(id=>Object.assign({id,name:vnames[id]||'',ipSubnets:sviIp[id]?[{cidr:sviIp[id]}]:[]},declared.has(id)?{}:{implied:true}));
    const lacp=Object.keys(lagMembers).sort((a,b)=>a-b).map(n=>({name:'port-channel '+n,mode:lagMembers[n].some(x=>x.lacpMode)?'Active':'Static',members:lagMembers[n],desc:''}));
    const routes=lines.map(l=>l.match(/^ip\s+route\s+(?:vrf\s+(\S+)\s+)?(\d+\.\d+\.\d+\.\d+)\s*(\/\d+|\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+|null0)(?:\s+(\d+))?$/)).filter(Boolean)
      .map(x=>({dst:x[2]+'/'+cidr(x[3]),gw:x[4],vrf:x[1]||'',distance:x[5]||''}));
    const users=[];
    lines.forEach(l=>{ const m=l.match(/^username\s+(\S+)\s+(?:(nopassword)|password\s+(?:([07])\s+)?\S+)$/); if(!m)return;
      users.push({name:m[1],role:'',service:'web/cli',hasPwd:!m[2],pwdType:m[2]?'none':m[3]==='7'?'hash':'plain',pwdWeak:!m[2]&&m[3]!=='7'}); });
    lines.forEach(l=>{ const m=l.match(/^username\s+(\S+)\s+capability\s+(\S+)$/); if(!m)return; const u=users.find(x=>x.name===m[1]); if(u)u.role=m[2]; });
    const stp={mode:val(/^spanning-tree\s+mode\s+(mst|rst|rpvst)$/),instances:[],ports:[],rootMode:'',timers:{}};
    const snmp={communities:lines.map(l=>l.match(/^snmp-server\s+community\s+(\S+)(?:\s+(ro|rw))?$/)).filter(Boolean).map(x=>({name:unq(x[1]),access:x[2]||'ro'})),v3Users:[],
      hosts:lines.map(l=>l.match(/^snmp-server\s+host\s+(?:vrf\s+\S+\s+)?(\d+\.\d+\.\d+\.\d+)\s+(?:traps|informs)\b/)).filter(Boolean).map(x=>({host:x[1]}))};
    const on=(en,dis)=>lines.includes(en)?true:lines.includes(dis)?false:null;
    return {sys,irf:null,stack:null,vlans,interfaces,routes,vrfs:[],users,ospf:[],bgp:[],rip:[],vrrp:[],vxlan:null,acls:[],
      lacp,stp,snmp,dns:[],dhcp:[],qos:[],breakouts:[],vendor:'onyx',
      mgmtAccess:{ssh:on('ssh server enable','no ssh server enable'),telnet:on('telnet-server enable','no telnet-server enable')}};
  }
  globalThis.isOnyx=isOnyx;
  globalThis.parseOnyx=parseOnyx;
})();
