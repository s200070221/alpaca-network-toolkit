function renderJuniperVLANEntry(v){
  const name=v.name||('VLAN'+v.id);
  const lines=[`    ${name} {`,`        vlan-id ${v.id};`];
  // desc／l3Interface（2026-07-27 補上）：parseJuniperVLANs() 已解析 description／
  // l3-interface 兩個欄位，render 端從未輸出過
  if(v.desc)lines.push(`        description "${v.desc}";`);
  if(v.l3Interface)lines.push(`        l3-interface ${v.l3Interface};`);
  lines.push('    }');
  return lines.join('\n');
}
function renderJuniperVLANs(vlans){
  if(!vlans||!vlans.length)return '';
  return 'vlans {\n'+vlans.map(renderJuniperVLANEntry).join('\n')+'\n}';
}

function juniperAeName(id){return /^ae\d+$/i.test(String(id))?String(id):'ae'+id;}

// PoE：2026-07-22 對外查證官方 Junos 文件後新增，真實語法是獨立頂層 `poe {}` 區塊，
// 且 PoE 預設啟用（不需要顯式 enable），只有停用時才需要輸出 `interface X disable;`
function renderJuniperPoeBlock(ifaces){
  const disabled=(ifaces||[]).filter(i=>i.poeMode==='never').map(i=>`    interface ${i.name} disable;`);
  if(!disabled.length)return '';
  return 'poe {\n'+disabled.join('\n')+'\n}';
}

// family ethernet-switching（VLAN/link-type 屬性）render，Juniper 專用；抽成獨立函式供
// renderJuniperInterface() 與 renderJuniperLACPExtra() 共用（後者需要把同一組屬性輸出到
// aeN 聚合介面上——官方文件明確禁止 802.3ad member 實體介面同時設定 family ethernet-switching，
// commit 會直接報錯，VLAN 屬性只能設在 aeN 邏輯介面上）
function juniperFamilyEthernetSwitchingLines(iface){
  const lines=[];
  if(!iface||!(iface.mode==='trunk'||iface.mode==='access'))return lines;
  lines.push('        unit 0 {');
  lines.push('            family ethernet-switching {');
  lines.push(`                interface-mode ${iface.mode};`);
  if(iface.mode==='trunk'){
    if(iface.trunkVlans)lines.push(`                vlan { members [ ${iface.trunkVlans.trim().split(/\s+/).join(' ')} ]; }`);
    if(iface.nativeVlan)lines.push(`                native-vlan-id ${iface.nativeVlan};`);
  }else{
    if(iface.accessVlan)lines.push(`                vlan { members [ ${iface.accessVlan} ]; }`);
  }
  lines.push('            }');
  lines.push('        }');
  return lines;
}
function renderJuniperInterface(iface,lacpList){
  const lines=[`    ${iface.name} {`];
  if(iface.desc)lines.push(`        description "${iface.desc}";`);
  if(iface.shutdown)lines.push('        disable;');
  // PoE：2026-07-22 對外查證官方 Junos 文件後移除——原本的 `power-management
  // enable/disable;` 內嵌在 interfaces{} 區塊完全捏造，真實語法是獨立頂層 `poe {}`
  // 區塊，且 PoE 預設就是啟用，只需要在停用時輸出 `poe { interface X disable; }`，
  // 改由 assembleJuniperConfig() 統一收集後輸出獨立區塊（見 renderJuniperPoeBlock()）
  const lg=findLacpGroup(lacpList,iface.name);
  if(lg){
    lines.push('        ether-options {');
    lines.push(`            802.3ad ${juniperAeName(lg.id)};`);
    lines.push('        }');
  }
  if(!lg)lines.push(...juniperFamilyEthernetSwitchingLines(iface));
  if(iface.mode==='routed'&&iface.ip){
    // ip（2026-07-27 補上）：parseJuniperInterfaces() 對 routed 實體埠／AE 有解析
    // "address A.B.C.D/N;"（掃描整個介面 body，不限定巢狀層級），render 端從未輸出過。
    // vrf 不在此處輸出——真實 Junos VRF 綁定語法方向是反過來的
    // routing-instances{NAME{interface X;}}，見 renderJuniperRoutingInstances()
    // IPv6（試點 5 廠牌之一，標準 Junos 語法 family inet6，與 family inet 平行）
    const fam=iface.ip.includes(':')?'inet6':'inet';
    lines.push('        unit 0 {');
    lines.push(`            family ${fam} {`);
    lines.push(`                address ${iface.ip};`);
    // 次要IP（2026-08-12 新增）：Junos 無 secondary 關鍵字，同一 family inet {} 區塊內
    // 再宣告一筆 address statement 即為附加位址，比照本專案 firewall_analyzer Juniper SRX
    // 既有慣例；僅取第一筆次要IP為 MVP 範圍
    if(iface.secondaryIp&&(iface.secondaryIp.includes(':')===iface.ip.includes(':')))lines.push(`                address ${iface.secondaryIp};`);
    lines.push('            }');
    lines.push('        }');
  }
  lines.push('    }');
  return lines.join('\n');
}

// IRB（SVI）：多筆 unit 須合併進同一個 "irb { unit N {...} unit M {...} }" 區塊，不能
//像其他介面一樣各自產生獨立頂層區塊——Junos 語法裡 irb 是單一實體介面，unit 才是邏輯
// 子介面（parseJuniperInterfaces() 的 IRB 分支就是在單一 irb body 內用大括號計數逐一
// 抓出 unit N { ... }，render 端須反向對應同一種結構）；2026-07-27 補上 ip 輸出
function renderJuniperIRB(svis){
  if(!svis||!svis.length)return '';
  const lines=['    irb {'];
  svis.forEach(i=>{
    const uid=i.name.replace(/^irb\./,'');
    lines.push(`        unit ${uid} {`);
    if(i.desc)lines.push(`            description "${i.desc}";`);
    if(i.ip){
      // IPv6（試點 5 廠牌之一）：SVI 與 routed 實體埠共用同一組 family inet/inet6 判斷邏輯
      const fam=i.ip.includes(':')?'inet6':'inet';
      lines.push(`            family ${fam} {`);
      lines.push(`                address ${i.ip};`);
      // 次要IP（2026-08-12 新增）：同 routed 實體埠，附加式機制在同一 family 區塊內再加一筆
      if(i.secondaryIp&&(i.secondaryIp.includes(':')===i.ip.includes(':')))lines.push(`                address ${i.secondaryIp};`);
      lines.push('            }');
    }
    lines.push('        }');
  });
  lines.push('    }');
  return lines.join('\n');
}

// LACP 的 aeN 聚合介面本身也是一個 interfaces{} 底下的子區塊，須跟一般實體介面
// 合併輸出（見檔案開頭說明），故只回傳子區塊文字，不包出獨立的 "interfaces{}"
function renderJuniperLACPExtra(lacpList,ifaces){
  if(!lacpList||!lacpList.length)return '';
  const blocks=lacpList.map(l=>{
    const lines=[`    ${juniperAeName(l.id)} {`];
    if(l.desc)lines.push(`        description "${l.desc}";`);
    if(l.mode==='active'||l.mode==='passive'){
      lines.push('        aggregated-ether-options {');
      lines.push(`            lacp { ${l.mode}; }`);
      lines.push('        }');
    }
    // family ethernet-switching（VLAN/link-type 屬性）統一設在 aeN 邏輯介面上，來源取該
    // 群組第一個有填寫 interface 設定的 member（member 實體介面自己不再輸出這組屬性，
    // 見 renderJuniperInterface() 上方說明）
    const refIface=(l.members||[]).map(m=>(ifaces||[]).find(i=>i.name===m)).find(Boolean);
    lines.push(...juniperFamilyEthernetSwitchingLines(refIface));
    lines.push('    }');
    return lines.join('\n');
  });
  // member fallback（2026-07-27 補上）：parseJuniperLACP() 有解析 members，但先前未獨立
  // 建列的成員埠完全遺失 802.3ad 宣告（比照 Comware/Cisco/Aruba 既有 member-fallback 慣例）
  const existingNames=new Set((ifaces||[]).map(i=>i.name));
  (lacpList||[]).forEach(l=>{
    (l.members||[]).forEach(mem=>{
      if(existingNames.has(mem))return;
      blocks.push(`    ${mem} {\n        ether-options {\n            802.3ad ${juniperAeName(l.id)};\n        }\n    }`);
    });
  });
  return blocks.join('\n');
}

function renderJuniperRoutes(routes){
  // vrf（2026-07-27 修正，P0 正確性 bug）：有 vrf 的路由不屬於頂層 routing-options{}，
  // 須巢狀輸出在對應的 routing-instances{NAME{routing-options{static{...}}}} 區塊內
  // （見 renderJuniperRoutingInstances()），否則會被錯誤攤平成全域路由
  const globalRoutes=(routes||[]).filter(r=>!r.vrf);
  if(!globalRoutes.length)return '';
  return '    static {\n'+globalRoutes.map(r=>`        route ${r.dst} next-hop ${r.gw};`).join('\n')+'\n    }';
}

// routing-instances{}：VRF 介面綁定（interface X;）與該 VRF 範圍內的靜態路由合併進同一個
// 頂層區塊（比照既有 interfaces{}/protocols{}/routing-options{} 合併慣例，junosBlock 只
// 認得第一個同名頂層區塊）。真實 Junos VRF 介面綁定語法方向是反過來的：在
// routing-instances{NAME{interface X;}} 內宣告，不是在 interfaces{} 區塊內宣告 vrf——
// 2026-07-27 對外查證修正，對應 parseJuniperInterfaces() 新增的逆向掃描邏輯
function renderJuniperRoutingInstances(ifaces,routes){
  const vrfNames=new Set();
  (ifaces||[]).forEach(i=>{ if(i.vrf)vrfNames.add(i.vrf); });
  (routes||[]).forEach(r=>{ if(r.vrf)vrfNames.add(r.vrf); });
  if(!vrfNames.size)return '';
  const blocks=[...vrfNames].sort().map(vrf=>{
    const lines=[`    ${vrf} {`];
    (ifaces||[]).filter(i=>i.vrf===vrf).forEach(i=>{
      // IRB 已是 unit-qualified 名稱（irb.20），其餘實體埠/AE 預設掛在 unit 0
      const ref=i.type==='svi'?i.name:`${i.name}.0`;
      lines.push(`        interface ${ref};`);
    });
    const vrfRoutes=(routes||[]).filter(r=>r.vrf===vrf);
    if(vrfRoutes.length){
      lines.push('        routing-options {');
      lines.push('            static {');
      vrfRoutes.forEach(r=>lines.push(`                route ${r.dst} next-hop ${r.gw};`));
      lines.push('            }');
      lines.push('        }');
    }
    lines.push('    }');
    return lines.join('\n');
  });
  return 'routing-instances {\n'+blocks.join('\n')+'\n}';
}

// ACL：set firewall filter NAME term TERM from source-address/destination-address；
// set firewall filter NAME term TERM then accept|discard；套用進介面另用
// set interfaces IFACE family inet filter {input|output} NAME。switch_analyzer 的
// _parseACLJuniper() 只認得這種逐行 flat "set" 指令格式（不是本檔其餘區塊慣用的巢狀 {}
// 階層格式），Junos "load merge" 允許同一份設定檔混合 set 指令與階層區塊，故直接以獨立
// 多行 set 指令附加在檔案結尾即可，不需要包成 {} 區塊，比照既有 Extreme XOS ACL render
// 前例（parser 有、generator 沒有的同類缺口）
function renderJuniperACL(aclList){
  if(!aclList||!aclList.length)return '';
  const lines=[];
  (aclList||[]).forEach(a=>{
    (a.rules||[]).forEach((r,idx)=>{
      const term=r.seq||('term'+(idx+1));
      // src/dst 的 'any'／'-' 皆代表「不限制」：Junos from source-address/destination-address
      // 不接受 "any" 這種字面值（跟 Cisco/Comware 不同），沒有限制時要整行省略，而非輸出
      // "source-address any" 這種真機無法接受的無效語法
      const isAny=v=>!v||v==='-'||String(v).toLowerCase()==='any';
      if(!isAny(r.src))lines.push(`set firewall filter ${a.name} term ${term} from source-address ${r.src}`);
      if(!isAny(r.dst))lines.push(`set firewall filter ${a.name} term ${term} from destination-address ${r.dst}`);
      lines.push(`set firewall filter ${a.name} term ${term} then ${r.action==='permit'?'accept':'discard'}`);
    });
    (a.appliedOn||[]).forEach(ap=>{
      lines.push(`set interfaces ${ap.interface} family inet filter ${ap.direction==='in'?'input':'output'} ${a.name}`);
    });
  });
  return lines.join('\n');
}

// Juniper DHCP：server pool 進 access{address-assignment{}}、server 綁定的介面回傳
// dhcpLocalIfaces 供 assembleJuniperConfig 合併進 system{services{dhcp-local-server{}}}
// （比照既有 Juniper 慣例，不能另開 system 區塊）；relay 進 forwarding-options{dhcp-relay{}}，
// server-group/group 名稱用 relay-N 自動編號（共用 DHCP UI 沒有提供群組名稱欄位）
function renderJuniperDHCP(list){
  const servers=(list||[]).filter(d=>d.type==='server'&&d.name);
  const relays=(list||[]).filter(d=>d.type==='relay'&&d.relayServer);

  const poolLines=servers.map(d=>{
    const inetLines=[];
    if(d.network){
      const [net,len]=d.network.split('/');
      inetLines.push(`                network ${net}${len?'/'+len:''};`);
    }
    if(d.range){
      const [lo,hi]=d.range.split('-');
      inetLines.push(`                range {\n                    low ${lo};\n                    high ${hi};\n                }`);
    }
    if(d.gateway)inetLines.push(`                router {\n                    ${d.gateway};\n                }`);
    if(d.dns){
      const dnsIps=d.dns.trim().split(/\s+/).filter(Boolean);
      if(dnsIps.length)inetLines.push(`                name-server {\n${dnsIps.map(ip=>`                    ${ip};`).join('\n')}\n                }`);
    }
    return `        pool ${d.name} {\n            family inet {\n${inetLines.join('\n')}\n            }\n        }`;
  });
  const accessBlock=poolLines.length?`access {\n    address-assignment {\n${poolLines.join('\n')}\n    }\n}`:'';
  const dhcpLocalIfaces=servers.filter(d=>d.interface).map(d=>d.interface);

  const relayLines=[];
  relays.forEach((d,idx)=>{
    const gname=`relay-${idx+1}`;
    relayLines.push(`        server-group ${gname} {\n            ${d.relayServer};\n        }`);
    relayLines.push(`        group ${gname} {\n            active-server-group ${gname};\n            interface ${d.interface||'all'};\n        }`);
  });
  const relayBlock=relayLines.length?`forwarding-options {\n    dhcp-relay {\n${relayLines.join('\n')}\n    }\n}`:'';

  return {accessBlock, relayBlock, dhcpLocalIfaces};
}

function renderJuniperOSPFBlock(ospfList){
  if(!ospfList||!ospfList.length)return '';
  const lines=['    ospf {'];
  ospfList.forEach(o=>{
    (o.areas||[]).forEach(a=>{
      lines.push(`        area ${a.area} {`);
      (a.networks||[]).forEach(n=>{ if(n.network)lines.push(`            interface ${n.network};`); });
      lines.push('        }');
    });
  });
  lines.push('    }');
  return lines.join('\n');
}

function renderJuniperBGPBlock(bgpList){
  if(!bgpList||!bgpList.length)return '';
  const b=bgpList[0];
  const lines=['    bgp {'];
  const internalPeers=(b.peers||[]).filter(p=>p.as===b.asn);
  const externalPeers=(b.peers||[]).filter(p=>p.as!==b.asn);
  if(internalPeers.length){
    lines.push('        group internal-peers {');
    lines.push('            type internal;');
    if(b.asn)lines.push(`            peer-as ${b.asn};`);
    internalPeers.forEach(p=>{
      lines.push(`            neighbor ${p.ip} {`);
      if(p.desc)lines.push(`                description "${p.desc}";`);
      lines.push('            }');
    });
    lines.push('        }');
  }
  if(externalPeers.length){
    lines.push('        group external-peers {');
    lines.push('            type external;');
    externalPeers.forEach(p=>{
      lines.push(`            neighbor ${p.ip} {`);
      if(p.as)lines.push(`                peer-as ${p.as};`);
      if(p.desc)lines.push(`                description "${p.desc}";`);
      lines.push('            }');
    });
    lines.push('        }');
  }
  lines.push('    }');
  return lines.join('\n');
}

// Breakout：獨立頂層 `chassis{}` 區塊，fpc/pic/port 巢狀，多筆母埠須合併進同一個 chassis{}
// （比照既有 Juniper 頂層區塊合併慣例，因 junosBlock 只認得第一個同名頂層區塊）
function renderJuniperBreakoutExtra(breakouts){
  const juBreakouts=(breakouts||[]).filter(b=>b.vendor==='juniper');
  if(!juBreakouts.length)return '';
  const speedMap={'4x10G':'10g','4x25G':'25g','2x50G':'50g'};
  const fpcMap=new Map();
  juBreakouts.forEach(b=>{
    const m=b.parentPort.match(/^(?:xe|et)-(\d+)\/(\d+)\/(\d+)$/i);
    if(!m)return;
    const [,fpc,pic,port]=m;
    if(!fpcMap.has(fpc))fpcMap.set(fpc,new Map());
    const picMap=fpcMap.get(fpc);
    if(!picMap.has(pic))picMap.set(pic,[]);
    picMap.get(pic).push({port,speed:speedMap[b.mode]||'10g'});
  });
  const fpcLines=[];
  fpcMap.forEach((picMap,fpc)=>{
    const picLines=[];
    picMap.forEach((ports,pic)=>{
      const portLines=ports.map(p=>`                port ${p.port} {\n                    channel-speed ${p.speed};\n                }`);
      picLines.push(`            pic ${pic} {\n${portLines.join('\n')}\n            }`);
    });
    fpcLines.push(`        fpc ${fpc} {\n${picLines.join('\n')}\n        }`);
  });
  if(!fpcLines.length)return '';
  return `chassis {\n${fpcLines.join('\n')}\n}`;
}

function renderJuniperUsersBlock(users){
  const list=(users||[]).filter(u=>u.name&&u.password);
  if(!list.length)return '';
  const userLines=list.map(u=>`            user ${u.name} {\n                class ${u.role||'operator'};\n                authentication {\n                    encrypted-password "${u.password}";\n                }\n            }`);
  return `    login {\n${userLines.join('\n')}\n    }`;
}
function assembleJuniperConfig(model){
  const dhcpInfo=renderJuniperDHCP(model.dhcp);
  const systemLines=[`    host-name ${model.sysname||'Switch'};`];
  if(dhcpInfo.dhcpLocalIfaces.length){
    const dlsIfaces=dhcpInfo.dhcpLocalIfaces.map(f=>`                interface ${f};`).join('\n');
    systemLines.push(`    services {\n        dhcp-local-server {\n${dlsIfaces}\n        }\n    }`);
  }
  // 本機帳號：巢狀在同一個頂層 system{} 區塊內的 login{} 子區塊（Juniper 同名頂層區塊只能
  // 出現一次，須合併非分開輸出，見 assembleJuniperConfig() 慣例），語法為
  // system{login{user NAME{class ROLE;authentication{encrypted-password "HASH";}}}}
  const juniperUsersBlock=renderJuniperUsersBlock(model.users);
  if(juniperUsersBlock)systemLines.push(juniperUsersBlock);
  const parts=[`# ${tr('notice.disclaimer')}`,`system {\n${systemLines.join('\n')}\n}`];
  if(dhcpInfo.accessBlock)parts.push(dhcpInfo.accessBlock);

  const breakoutBlock=renderJuniperBreakoutExtra(model.breakouts);
  if(breakoutBlock)parts.push(breakoutBlock);

  const poeBlock=renderJuniperPoeBlock(model.interfaces);
  if(poeBlock)parts.push(poeBlock);

  const vlansBlock=renderJuniperVLANs(model.vlans);
  if(vlansBlock)parts.push(vlansBlock);

  // interfaces{}：一般介面 + LACP aeN 介面 + IRB(SVI) 合併進同一個頂層區塊（見檔案開頭
  // 說明）。IRB 需獨立分組成單一 "irb{}" 區塊（見 renderJuniperIRB() 註解），不能跟其他
  // 介面一樣逐筆各自產生頂層區塊
  const ifaceLines=[];
  const svis=(model.interfaces||[]).filter(i=>i.type==='svi');
  const nonSvis=(model.interfaces||[]).filter(i=>i.type!=='svi');
  nonSvis.forEach(i=>ifaceLines.push(renderJuniperInterface(i,model.lacp)));
  const lacpExtra=renderJuniperLACPExtra(model.lacp,model.interfaces);
  if(lacpExtra)ifaceLines.push(lacpExtra);
  const irbBlock=renderJuniperIRB(svis);
  if(irbBlock)ifaceLines.push(irbBlock);
  if(ifaceLines.length)parts.push('interfaces {\n'+ifaceLines.join('\n')+'\n}');

  // routing-options{}：router-id/AS + 全域靜態路由合併進同一個頂層區塊（有 vrf 的路由
  // 改由 renderJuniperRoutingInstances() 巢狀輸出，不在此處理）
  const roLines=[];
  const routerId=model.ospf?.[0]?.routerId||model.bgp?.[0]?.routerId||'';
  if(routerId)roLines.push(`    router-id ${routerId};`);
  if(model.bgp?.[0]?.asn)roLines.push(`    autonomous-system ${model.bgp[0].asn};`);
  const staticBlock=renderJuniperRoutes(model.routes);
  if(staticBlock)roLines.push(staticBlock);
  if(roLines.length)parts.push('routing-options {\n'+roLines.join('\n')+'\n}');

  // routing-instances{}：VRF 介面綁定 + VRF 範圍內靜態路由（P0 修正：先前 VRF 路由被錯誤
  // 攤平進上面的全域 routing-options{}）
  const riBlock=renderJuniperRoutingInstances(model.interfaces,model.routes);
  if(riBlock)parts.push(riBlock);

  // protocols{}：OSPF + BGP 合併進同一個頂層區塊
  const protoLines=[];
  const ospfBlock=renderJuniperOSPFBlock(model.ospf);
  if(ospfBlock)protoLines.push(ospfBlock);
  const bgpBlock=renderJuniperBGPBlock(model.bgp);
  if(bgpBlock)protoLines.push(bgpBlock);
  if(protoLines.length)parts.push('protocols {\n'+protoLines.join('\n')+'\n}');

  if(dhcpInfo.relayBlock)parts.push(dhcpInfo.relayBlock);

  // ACL（2026-07-27 新增）：flat "set" 指令，放最後即可，不影響其餘階層區塊解析
  const aclBlock=renderJuniperACL(model.acl);
  if(aclBlock)parts.push(aclBlock);

  if(model.snmpTrapHost)parts.push(`set snmp trap-group public targets ${model.snmpTrapHost}`);

  return parts.join('\n');
}

// ── DOM 表格操作 ─────────────────────────────────────────────────
