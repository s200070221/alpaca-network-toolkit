function parseEdgeSwitchSysInfo(cfg){
  return{
    hostname:(cfg.match(/^snmp-server\s+sysname\s+(\S+)/m)||[])[1]||'unknown',
    version:'',
    platform:'',
  };
}

function parseEdgeSwitchVLANs(cfg){
  const vlans=[];
  const dbBlock=(cfg.match(/^vlan database\n([\s\S]*?)^exit/m)||[])[1]||'';
  const re=/^vlan\s+(\d+)\s*$/gm;
  let m;
  while((m=re.exec(dbBlock))!==null){
    const id=m[1];
    const nameM=cfg.match(new RegExp('^vlan name\\s+'+id+'\\s+"?([^"\\n]+?)"?\\s*$','m'));
    vlans.push({id,name:nameM?nameM[1].trim():'',ipSubnets:[]});
  }
  vlans.sort((a,b)=>parseInt(a.id)-parseInt(b.id));
  return vlans;
}

function parseEdgeSwitchInterfaces(cfg){
  const ifaces=[];
  const blocks=cfg.split(/^interface\s+/m).slice(1);
  for(const blk of blocks){
    const lines=blk.split('\n');
    const name=lines[0].trim();
    // LAG 自己的區塊不當成一般 L2 埠處理（無 vlan participation 語意上的差異，但避免
    // 與成員埠混淆，交給 LACP 專屬解析）；此處仍照樣收集，因 LAG 介面本身也可以是
    // trunk/access 成員（例如上聯 LAG 也需要帶 VLAN tag）
    const body=lines.slice(1).join('\n');
    const desc=(body.match(/^\s*description\s+"?([^"\n]+?)"?\s*$/m)||[])[1]?.trim()||'';
    const shutdown=/^\s*shutdown\s*$/m.test(body)&&!/no shutdown/.test(body);
    const participation=[...body.matchAll(/^\s*vlan participation include\s+(\d+)\s*$/gm)].map(x=>x[1]);
    const tagged=new Set([...body.matchAll(/^\s*vlan tagging\s+(\d+)\s*$/gm)].map(x=>x[1]));
    const pvidM=body.match(/^\s*vlan pvid\s+(\d+)\s*$/m);
    const pvid=pvidM?pvidM[1]:'1';
    let mode='',vlans='',nativeVlan='';
    if(participation.length){
      if(tagged.size>0){
        mode='trunk';
        vlans=[...tagged].sort((a,b)=>parseInt(a)-parseInt(b)).join(',');
        // pvid 若不在 tagged 清單內，代表該 VLAN 是這個 trunk 埠上的未標記/native 成員
        nativeVlan=(!tagged.has(pvid)&&participation.includes(pvid))?pvid:(pvidM?pvid:'');
      }else{
        mode='access';
        vlans=participation[0];
      }
    }
    ifaces.push({name,type:'physical',desc,mode,vlans,nativeVlan,vrf:'',ip:'',shutdown,member:'1',hybrid:null,vrrp:[],breakoutChild:false,breakoutParent:'',breakoutMode:''});
  }
  return ifaces;
}

function parseEdgeSwitch(cfg){
  const sys=parseEdgeSwitchSysInfo(cfg);
  const vlans=parseEdgeSwitchVLANs(cfg);
  const interfaces=parseEdgeSwitchInterfaces(cfg);
  return{sys,irf:null,stack:null,vlans,interfaces,routes:[],vrfs:[],users:[],ospf:[],bgp:[],rip:[],vrrp:[],vxlan:null,vendor:'edgeswitch',breakouts:[]};
}

