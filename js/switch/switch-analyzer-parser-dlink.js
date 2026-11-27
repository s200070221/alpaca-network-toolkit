// ══════════════════════════════════════════════════════════
//  D-Link DGS 系列（DGS-1510 SmartPro 等，Cisco 風格 CLI）PARSER（XN154）
// ══════════════════════════════════════════════════════════
// 依官方「DGS-1510 Series Gigabit Ethernet SmartPro Switch CLI Reference Guide」1.30
// （support.dlink.com/resource/PRODUCTS/DGS-1510-28X/REVA/）的指令語法與 show running-config 範例：
//   檔頭「# DGS-1510-28XMP Gigabit Ethernet SmartPro Switch／# Configuration／# Firmware: Build 1.30.003／
//   # Copyright(C) 2015 D-Link Corporation」，各功能以「# 名稱 START／END」區段與 configure terminal … end 包住
//   34-3  interface INTERFACE-ID（範例 interface eth1/0/10）、34-2 description、34-11 shutdown
//   75-10／75-11 vlan 清單＋name；75-7 switchport mode {access|hybrid|trunk}；75-4 switchport access vlan；
//   75-8 switchport trunk allowed vlan {all | [add|remove|except] 清單}；75-9 switchport trunk native vlan；
//   75-5 switchport hybrid allowed vlan {[add] {tagged|untagged} | remove} 清單；75-6 switchport hybrid native vlan
//   42-1  channel-group N mode {on|active|passive}；9-4 interface vlanN＋ip address 位址 遮罩 [secondary]
//   55-1  ip route 網段 遮罩 下一跳 [primary|backup]；5-23 username 帳號 [privilege N] [nopassword | password [0|7|15] 密碼]
//   63-9／63-8 snmp-server name／location；63-16 snmp-server community [0|7] 名稱 [view 檢視] [ro|rw]
//   60-4 ip ssh server；5-9 ip telnet server；5-4／5-5 ip http server、ip http secure-server
//   65-11 spanning-tree mode；51-10 ntp server；72-6 sntp server；71-5 logging server
// running-config 範例只有區段骨架（未列出介面內容）：介面名稱的顯示形式（eth1/0/1 或 ethernet 1/0/1）與子指令縮排
// 未查證，兩種名稱都接受，區塊以下一個全域指令為結尾。未涵蓋：ACL、QoS、DHCP、802.1X、堆疊。
(function(){
  const SUB_RE=/^\s*(?:no\s+)?(?:switchport|channel-group|description|shutdown|name|ip\s+address|ipv6|speed|duplex|flowcontrol|mtu|spanning-tree\s+(?:portfast|bpdu|guard|cost|port-priority|link-type|tcnfilter|mst)|lldp|lacp\s+port-priority|storm-control|loopback-detection|dot1x|poe|port\s+security|ip\s+(?:dhcp\s+snooping|arp\s+inspection)|media-type)\b/i;
  const unq=s=>String(s||'').trim().replace(/^"(.*)"$/,'$1');
  function isDLink(cfg){
    return /^#\s*Copyright\(C\)\s*\d{4}\s+D-Link Corporation/mi.test(cfg)||
      (/^#\s*[A-Z][\w ]*\s+START\s*$/m.test(cfg)&&/^#\s*[A-Z][\w ]*\s+END\s*$/m.test(cfg)&&/^configure terminal\s*$/m.test(cfg)&&/^#\s*\S.*\bSwitch\s*$/m.test(cfg));
  }
  function blocks(cfg, headRe){
    const lines=cfg.split('\n'), out=[];
    for(let i=0;i<lines.length;i++){
      const m=lines[i].match(headRe);
      if(!m)continue;
      const body=[];
      for(let j=i+1;j<lines.length;j++){
        const l=lines[j];
        if(!l.trim())continue;
        if(/^\s*(?:exit|end)\s*$/.test(l)||/^\s*#/.test(l))break;
        if(/^\s/.test(l)||SUB_RE.test(l)){ body.push(l.trim()); continue; }
        break;
      }
      out.push({m, body:body.join('\n')});
    }
    return out;
  }
  const vlanList=s=>[...(typeof expandL2VlanList==='function'?expandL2VlanList(s):[])].map(String);
  const cidr=m=>typeof maskToCIDR==='function'?maskToCIDR(m):m;
  // eth1/0/1、ethernet 1/0/1 → eth1/0/1（與手冊範例相同的寫法）
  const portName=(kw,id)=>/^eth/i.test(kw)?'eth'+id:kw.toLowerCase()+id;
  function parseDLink(cfg){
    const val=re=>(cfg.match(re)||[])[1];
    const sys={hostname:unq(val(/^snmp-server\s+name\s+(.+)$/m))||'D-Link',version:val(/^#\s*Firmware:\s*Build\s+(\S+)/m)||'',
      model:val(/^#\s*(DGS-\S+|DXS-\S+|DES-\S+)\s/m)||'-',serial:'-',mgmtIp:'',location:unq(val(/^snmp-server\s+location\s+(.+)$/m))||''};
    const vids=new Set(), declared=new Set(), vnames={};
    blocks(cfg,/^vlan\s+([\d,\-]+)\s*$/).forEach(({m,body})=>{
      const ids=vlanList(m[1]); ids.forEach(v=>{vids.add(v);declared.add(v);});
      const n=body.match(/^name\s+(.+)$/m); if(n&&ids.length===1)vnames[ids[0]]=unq(n[1]);
    });
    const interfaces=[], lagMembers={};
    blocks(cfg,/^interface\s+(eth(?:ernet)?|port-channel)\s*(\d+(?:\/\d+){0,2})\s*$/i).forEach(({m,body})=>{
      const isLag=/^port-channel$/i.test(m[1]);
      const name=isLag?'port-channel'+m[2]:portName(m[1],m[2]);
      const g=re=>(body.match(re)||[])[1];
      const mode=(g(/^switchport\s+mode\s+(access|hybrid|trunk)\s*$/m)||'').toLowerCase();
      let vlans='', nativeVlan='', hybrid=null;
      if(mode==='access'){ vlans=g(/^switchport\s+access\s+vlan\s+(\d+)\s*$/m)||'1'; vids.add(vlans); }
      else if(mode==='trunk'){
        nativeVlan=g(/^switchport\s+trunk\s+native\s+vlan\s+(\d+)\s*$/m)||'';
        const al=[...body.matchAll(/^switchport\s+trunk\s+allowed\s+vlan\s+(?:(add)\s+)?(\S+)\s*$/gm)];
        // all＝全部（預設），except／remove 不展開（依現有 VLAN 計算）；只累計直接列出與 add 的清單
        const ids=[]; al.forEach(x=>{ if(/^(all|except|remove)$/i.test(x[2]))return; vlanList(x[2]).forEach(v=>{if(!ids.includes(v))ids.push(v);}); });
        vlans=ids.length?ids.join(','):(al.some(x=>/^all$/i.test(x[2]))||!al.length?'all':'');
        ids.forEach(v=>vids.add(v)); if(nativeVlan)vids.add(nativeVlan);
      } else if(mode==='hybrid'){
        const untagged=[], tagged=[];
        [...body.matchAll(/^switchport\s+hybrid\s+allowed\s+vlan\s+(?:add\s+)?(tagged|untagged)\s+(\S+)\s*$/gm)].forEach(x=>{
          vlanList(x[2]).forEach(v=>{const a=x[1]==='tagged'?tagged:untagged;if(!a.includes(v))a.push(v);});
        });
        const pvid=g(/^switchport\s+hybrid\s+native\s+vlan\s+(\d+)\s*$/m)||'';
        [...untagged,...tagged,pvid].filter(Boolean).forEach(v=>vids.add(v));
        hybrid={pvid,untagged,tagged,vlanMaps:[],hasIPSub:false,hasQinQ:false};
        vlans=[...untagged,...tagged].join(' ');
      }
      const cg=body.match(/^channel-group\s+(\d+)\s+mode\s+(on|active|passive)\s*$/m);
      if(cg)(lagMembers[cg[1]]=lagMembers[cg[1]]||[]).push({name,lacpMode:cg[2]==='on'?null:cg[2]});
      interfaces.push({name,type:isLag?'lag':'physical',desc:unq(g(/^description\s+(.+)$/m)),mode,vlans,nativeVlan,vrf:'',ip:'',
        shutdown:/^shutdown\s*$/m.test(body),member:'1',hybrid,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:'',channelGroup:cg?cg[1]:''});
    });
    blocks(cfg,/^interface\s+vlan\s*(\d+)\s*$/i).forEach(({m,body})=>{
      const vid=m[1];
      const ipLines=[...body.matchAll(/^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(\s+secondary)?\s*$/gm)];
      const primary=ipLines.find(x=>!x[3]);
      vids.add(vid);
      interfaces.push({name:'vlan'+vid,type:'svi',desc:unq((body.match(/^description\s+(.+)$/m)||[])[1]),ip:primary?primary[1]+'/'+cidr(primary[2]):'',ip6:'',
        secondaryIps:ipLines.filter(x=>x[3]).map(x=>x[1]+'/'+cidr(x[2])),mode:'',vlans:vid,nativeVlan:'',vrf:'',shutdown:/^shutdown\s*$/m.test(body),member:'1',
        hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
      if(primary&&!sys.mgmtIp)sys.mgmtIp=primary[1];
    });
    const sviIp={}; interfaces.filter(i=>i.type==='svi'&&i.ip).forEach(i=>{sviIp[i.vlans]=i.ip;});
    const vlans=[...vids].sort((a,b)=>a-b).map(id=>Object.assign({id,name:vnames[id]||'',ipSubnets:sviIp[id]?[{cidr:sviIp[id]}]:[]},declared.has(id)?{}:{implied:true}));
    const lacp=Object.keys(lagMembers).sort((a,b)=>a-b).map(n=>({name:'port-channel'+n,mode:lagMembers[n].some(x=>x.lacpMode)?'Active':'Static',members:lagMembers[n],desc:''}));
    const routes=[...cfg.matchAll(/^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(primary|backup))?\s*$/gm)]
      .map(x=>({dst:x[1]+'/'+cidr(x[2]),gw:x[3],vrf:'',role:x[4]||''}));
    // 帳號：password 0＝明碼、7＝可逆加密、15＝加密（雜湊）；nopassword＝沒有密碼
    const users=[...cfg.matchAll(/^username\s+("[^"]*"|\S+)(?:\s+privilege\s+(\d+))?(?:\s+(nopassword)|\s+password\s+(?:(0|7|15)\s+)?\S+)?\s*$/gm)]
      .map(x=>({name:unq(x[1]),role:x[2]?'level-'+x[2]:'',service:'web/cli',hasPwd:!x[3],
        pwdType:x[3]?'none':x[4]==='15'?'hash':x[4]==='7'?'type7':'plain',pwdWeak:!x[3]&&(!x[4]||x[4]==='0')}));
    const stp={mode:val(/^spanning-tree\s+mode\s+(mstp|rstp|stp)\s*$/m)||'',instances:[],ports:[],rootMode:'',timers:{}};
    const snmp={communities:[...cfg.matchAll(/^snmp-server\s+community\s+(?:[07]\s+)?("[^"]*"|\S+)(?:\s+view\s+\S+)?(?:\s+(ro|rw))?/gm)].map(x=>({name:unq(x[1]),access:x[2]||'ro'})),v3Users:[],
      hosts:[...cfg.matchAll(/^snmp-server\s+host\s+(\S+)/gm)].map(x=>({host:x[1]}))};
    const onoff=(on,off)=>on.test(cfg)?true:off.test(cfg)?false:null;
    return {sys,irf:null,stack:null,vlans,interfaces,routes,vrfs:[],users,ospf:[],bgp:[],rip:[],vrrp:[],vxlan:null,acls:[],
      lacp,stp,snmp,dns:[],dhcp:[],qos:[],breakouts:[],vendor:'dlink',
      mgmtAccess:{ssh:onoff(/^ip\s+ssh\s+server\s*$/m,/^no\s+ip\s+ssh\s+server\s*$/m),telnet:onoff(/^ip\s+telnet\s+server\s*$/m,/^no\s+ip\s+telnet\s+server\s*$/m)}};
  }
  globalThis.isDLink=isDLink;
  globalThis.parseDLink=parseDLink;
})();
