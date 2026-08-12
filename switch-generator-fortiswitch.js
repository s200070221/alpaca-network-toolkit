function renderFortiSwitchVLANsBlock(vlans){
  if(!vlans||!vlans.length)return '';
  const lines=['config switch vlan'];
  vlans.forEach(v=>{
    lines.push(`    edit ${v.id}`);
    if(v.name)lines.push(`        set name "${v.name}"`);
    lines.push('    next');
  });
  lines.push('end');
  return lines.join('\n');
}

function renderFortiSwitchInterfaces(ifaces,securityList,stp){
  if(!ifaces||!ifaces.length)return '';
  const physLines=['config switch physical-port'];
  const swLines=['config switch interface'];
  ifaces.forEach(i=>{
    physLines.push(`    edit "${i.name}"`);
    if(i.desc)physLines.push(`        set description "${i.desc}"`);
    // Jumbo Frame／PoE：2026-07-22 對外查證官方 FortiSwitchOS Administration Guide 後
    // 修正——這兩個欄位皆屬於 "config switch physical-port"，非 "config switch
    // interface"；Jumbo Frame 關鍵字也不是 mtu，真實是 max-frame-size
    if(i.jumbo&&i.jumbo.enabled&&i.jumbo.mtu)physLines.push(`        set max-frame-size ${i.jumbo.mtu}`);
    if(i.poeMode&&i.poeMode!=='none'){
      physLines.push(`        set poe-status ${i.poeMode==='never'?'disable':'enable'}`);
    }
    physLines.push('    next');

    swLines.push(`    edit "${i.name}"`);
    if(i.mode==='trunk'){
      if(i.nativeVlan)swLines.push(`        set native-vlan ${i.nativeVlan}`);
      if(i.trunkVlans)swLines.push(`        set allowed-vlans ${i.trunkVlans.trim().split(/\s+/).filter(Boolean).join(',')}`);
    }else if(i.mode==='access'){
      if(i.accessVlan){
        swLines.push(`        set native-vlan ${i.accessVlan}`);
        swLines.push(`        set untagged-vlans ${i.accessVlan}`);
      }
    }
    // Port Security/802.1X：已查證官方 FortiSwitchOS Administration Guide 後修正，改為
    // 巢狀 "config port-security" 子區塊（內嵌進同一個既有 "config switch interface"
    // 區塊，理由同 ACL/DHCP relay：switch_analyzer 對這個區塊用非 global 的 .match()），
    // port-security-mode 為列舉值而非布林開關；maxMac/violation 真實 FortiSwitch 無
    // 對應概念不輸出（已知限制）
    const sec=findSecurityForPort(securityList,i.name);
    // guestVlan 未設定時預設是共用 sentinel 字串 '-'（真值），若不排除會誤判為
    // 「有設定 guest vlan」而產生 "set guest-vlanid -" 這種真機無法接受的無效值
    const hasGuestVlan=sec&&sec.guestVlan&&sec.guestVlan!=='-';
    if(sec&&(sec.dot1x==='auth'||sec.portSec||hasGuestVlan)){
      swLines.push('        config port-security');
      const mode=sec.portSec?'802.1X-mac-based':(sec.dot1x==='auth'?'802.1X':'none');
      swLines.push(`            set port-security-mode ${mode}`);
      if(hasGuestVlan){
        swLines.push('            set guest-vlan enable');
        swLines.push(`            set guest-vlanid ${sec.guestVlan}`);
      }
      swLines.push('        end');
    }
    // STP per-port 同樣內嵌進這個既有區塊，理由同上。已查證官方 FortiSwitchOS
    // Administration Guide 後修正：真實欄位是 edge-port（非 stp-edge）；cost/priority
    // 真實位於 MSTP instance 底下的巢狀 config stp-port（見 renderFortiSwitchSTP()），
    // 不在此處輸出
    const sp=findStpForPort(stp,i.name);
    if(sp){
      if(sp.portfast)swLines.push('        set edge-port enable');
      if(sp.bpduguard)swLines.push('        set stp-bpdu-guard enable');
      if(sp.guardRoot)swLines.push('        set stp-root-guard enable');
    }
    // Auto-Discovery FortiLink：未設定則不輸出，維持設定檔原樣
    if(i.fortilinkDiscovery==='enable')swLines.push('        set auto-discovery-fortilink enable');
    else if(i.fortilinkDiscovery==='disable')swLines.push('        set auto-discovery-fortilink disable');
    swLines.push('    next');
  });
  physLines.push('end');
  swLines.push('end');
  return physLines.join('\n')+'\n'+swLines.join('\n');
}

function renderFortiSwitchOSPF(list){
  const o=(list||[])[0];
  if(!o)return '';
  const lines=['config router ospf'];
  if(o.routerId)lines.push(`    set router-id ${o.routerId}`);
  if(o.areas&&o.areas.length){
    lines.push('    config area');
    o.areas.forEach(a=>{lines.push(`        edit ${a.area}`);lines.push('        next');});
    lines.push('    end');
    lines.push('    config network');
    let n=1;
    o.areas.forEach(a=>{
      (a.networks||[]).forEach(net=>{
        lines.push(`        edit ${n++}`);
        lines.push(`            set prefix ${net.network}`);
        lines.push(`            set area ${a.area}`);
        lines.push('        next');
      });
    });
    lines.push('    end');
  }
  lines.push('end');
  return lines.join('\n');
}

function renderFortiSwitchBGP(list){
  const b=(list||[])[0];
  if(!b)return '';
  const lines=['config router bgp'];
  if(b.asn)lines.push(`    set as ${b.asn}`);
  if(b.routerId)lines.push(`    set router-id ${b.routerId}`);
  if(b.peers&&b.peers.length){
    lines.push('    config neighbor');
    b.peers.forEach(p=>{
      lines.push(`        edit "${p.ip}"`);
      if(p.as)lines.push(`            set remote-as ${p.as}`);
      lines.push('        next');
    });
    lines.push('    end');
  }
  lines.push('end');
  return lines.join('\n');
}

function renderFortiSwitchRIP(list){
  const r=(list||[])[0];
  if(!r)return '';
  const lines=['config router rip'];
  if(r.networks&&r.networks.length){
    lines.push('    config network');
    r.networks.forEach((net,idx)=>{
      lines.push(`        edit ${idx+1}`);
      lines.push(`            set prefix ${net}`);
      lines.push('        next');
    });
    lines.push('    end');
  }
  (r.redistribute||[]).forEach(proto=>{
    lines.push(`    config redistribute "${proto}"`);
    lines.push('        set status enable');
    lines.push('    end');
  });
  lines.push('end');
  return lines.join('\n');
}

function renderFortiSwitchRoutes(list){
  if(!list||!list.length)return '';
  const lines=['config router static'];
  list.forEach((r,idx)=>{
    lines.push(`    edit ${idx+1}`);
    lines.push(`        set dst ${r.dst}`);
    if(r.gw)lines.push(`        set gateway ${r.gw}`);
    // dev（2026-07-27 補上）：parseFortiStaticRoutes() 已解析介面型下一跳 "set device"，
    // render 端從未輸出過（gw 改為選填，介面型路由無 gateway 值）
    if(r.dev)lines.push(`        set device "${r.dev}"`);
    lines.push('    next');
  });
  lines.push('end');
  return lines.join('\n');
}

function renderFortiSwitchLACP(list){
  if(!list||!list.length)return '';
  const lines=['config switch trunk'];
  list.forEach(l=>{
    lines.push(`    edit "${l.id}"`);
    if(l.members&&l.members.length){
      lines.push(`        set members ${l.members.map(m=>`"${m}"`).join(' ')}`);
    }
    if(l.mode==='active')lines.push('        set mode lacp-active');
    else if(l.mode==='passive')lines.push('        set mode lacp-passive');
    lines.push('    next');
  });
  lines.push('end');
  return lines.join('\n');
}

// FortiSwitch 的 VRRP 與 DHCP relay 都巢狀在 "config system interface" 這個 L3 interface
// 區塊內；switch_analyzer 對此區塊用非 global 的 .match()（只抓檔案裡第一段），若兩者各自
// 輸出獨立的 "config system interface ... end" 區塊，後面那個會被解析器忽略，故合併成同一個
// 區塊、依介面名稱分組（VRRP 用 vlanN 當介面名稱，relay 用使用者填的介面名稱，兩者可能是
// 同一顆介面，此時欄位會合併在同一個 edit 區塊內）
function renderFortiSwitchL3Interfaces(ifaces,vrrpList,dhcpList){
  const groups=new Map(); // ifname -> {ifname, vlanId, ip, vrrpEntries, relayServers, option82}
  // 純 SVI/routed 埠 ip（2026-07-27 補上）：parseFortiInterfaces()/processBody() 有解析
  // "set ip"，但先前只有 VRRP／DHCP relay 分組才會建立 group，純 ip 介面完全遺失。用
  // iface.name 建組，若後續 VRRP/relay 分組同名則合併進同一個 edit 區塊（避免輸出兩段
  // "config system interface"，switch_analyzer 對此區塊只用非 global 的 .match()）
  (ifaces||[]).forEach(i=>{
    if(!i.ip)return;
    groups.set(i.name,{ifname:i.name,vlanId:i.vlans||'',ip:i.ip,secondaryIp:i.secondaryIp||'',vrrpEntries:[],relayServers:[],option82:false});
  });
  groupVrrpByVlan(vrrpList).forEach(g=>{
    const ifname='vlan'+g.vlanId;
    if(groups.has(ifname)){
      const ex=groups.get(ifname);
      ex.vlanId=ex.vlanId||g.vlanId; ex.ip=ex.ip||g.ip; ex.vrrpEntries=g.entries;
    }else{
      groups.set(ifname,{ifname,vlanId:g.vlanId,ip:g.ip,vrrpEntries:g.entries,relayServers:[],option82:false});
    }
  });
  (dhcpList||[]).filter(d=>d.type==='relay'&&d.interface).forEach(d=>{
    if(!groups.has(d.interface))groups.set(d.interface,{ifname:d.interface,vlanId:'',ip:'',vrrpEntries:[],relayServers:[],option82:false});
    const g=groups.get(d.interface);
    g.relayServers.push(d.relayServer);
    if(d.option82)g.option82=true;
  });
  if(!groups.size)return '';
  const lines=['config system interface'];
  groups.forEach(g=>{
    lines.push(`    edit "${g.ifname}"`);
    if(g.vlanId)lines.push(`        set vlanid ${g.vlanId}`);
    // 官方 FortiSwitchOS Administration Guide／CLI Reference 確認 IPv6 為巢狀區塊
    // `config ipv6` / `set ip6-address ADDR/PREFIXLEN` / `end`，與 IPv4 扁平 `set ip A B`
    // 結構不同（直出完整 CIDR，不需 maskFromCidr() 換算）
    if(g.ip){
      if(g.ip.includes(':')){
        lines.push('        config ipv6');
        lines.push(`            set ip6-address ${g.ip}`);
        lines.push('        end');
      }else{
        const [ip,len]=g.ip.split('/');
        lines.push(`        set ip ${ip} ${maskFromCidr(len)}`);
        // 次要IP（Secondary IP，官方 FortiSwitchOS Administration Guide／CLI Reference：
        // `set secondary-IP enable` + 巢狀 `config secondaryip`；僅取第一筆為 MVP 範圍）
        if(g.secondaryIp&&!g.secondaryIp.includes(':')){
          const [sip,slen]=g.secondaryIp.split('/');
          if(sip&&slen){
            lines.push('        set secondary-IP enable');
            lines.push('        config secondaryip');
            lines.push('            edit 1');
            lines.push(`                set ip ${sip} ${maskFromCidr(slen)}`);
            lines.push('            next');
            lines.push('        end');
          }
        }
      }
    }
    if(g.relayServers.length){
      lines.push('        set dhcp-relay-service enable');
      lines.push(`        set dhcp-relay-ip ${g.relayServers.map(s=>`"${s}"`).join(' ')}`);
      // option82（2026-07-27 補上）：parseDHCP() fortiswitch relay 分支已解析
      // "set dhcp-relay-option82 enable"，render 端從未輸出過
      if(g.option82)lines.push('        set dhcp-relay-option82 enable');
    }
    if(g.vrrpEntries.length){
      lines.push('        config vrrp');
      g.vrrpEntries.forEach(v=>{
        lines.push(`            edit ${v.vrid}`);
        lines.push(`                set vrip ${v.vip}`);
        lines.push(`                set priority ${v.priority}`);
        lines.push('            next');
      });
      lines.push('        end');
    }
    lines.push('    next');
  });
  lines.push('end');
  return lines.join('\n');
}

// DHCP server pool（config system dhcp server 區塊，跟 L3 interface 是不同區塊類型，無合併疑慮）
function renderFortiSwitchDHCPServer(list){
  const servers=(list||[]).filter(d=>d.type==='server');
  if(!servers.length)return '';
  const lines=['config system dhcp server'];
  servers.forEach((d,idx)=>{
    lines.push(`    edit ${idx+1}`);
    if(d.network){
      const [net,len]=d.network.split('/');
      lines.push(`        set subnet ${net} ${maskFromCidr(len)}`);
    }
    if(d.gateway)lines.push(`        set default-gateway ${d.gateway}`);
    if(d.dns)lines.push(`        set dns-server1 ${d.dns.trim().split(/\s+/)[0]||''}`);
    if(d.interface)lines.push(`        set interface "${d.interface}"`);
    // bootFile／nextServer／ntpServer／range／excluded／lease（2026-07-27 補上）：
    // parseDHCP() fortiswitch 分支已解析這些欄位，render 端從未輸出過
    if(d.bootFile)lines.push(`        set filename "${d.bootFile}"`);
    if(d.nextServer)lines.push(`        set next-server ${d.nextServer}`);
    if(d.ntpServer)lines.push(`        set ntp-server1 ${d.ntpServer}`);
    if(d.lease){
      const hoursM=String(d.lease).match(/^(\d+)h/);
      if(hoursM)lines.push(`        set lease-time ${parseInt(hoursM[1],10)*3600}`);
    }
    if(d.range){
      const [lo,hi]=d.range.split('-');
      lines.push('        config ip-range');
      lines.push('            edit 1');
      lines.push(`                set start-ip ${lo}`);
      if(hi)lines.push(`                set end-ip ${hi}`);
      lines.push('            next');
      lines.push('        end');
    }
    const excludedRanges=(d.excluded||'').split(';').map(s=>s.trim()).filter(Boolean);
    if(excludedRanges.length){
      lines.push('        config exclude-range');
      excludedRanges.forEach((range,i)=>{
        const [lo,hi]=range.split('-');
        lines.push(`            edit ${i+1}`);
        lines.push(`                set start-ip ${lo}`);
        lines.push(`                set end-ip ${hi||lo}`);
        lines.push('            next');
      });
      lines.push('        end');
    }
    lines.push('    next');
  });
  lines.push('end');
  return lines.join('\n');
}

// ACL：config switch acl ingress 區塊。FortiSwitch 的 ACL 模型天生把「規則」與「套用介面」
// 綁在同一個 edit 區塊內（不像其他廠牌是分開的 rule 清單 + appliedOn 清單），故每筆 rule ×
// 套用介面 各自展開成一個獨立的 edit 項目；若某規則完全沒有套用任何介面，仍輸出但不填
// ingress-interface（僅供備查，不會實際生效，此為 FortiSwitch 模型天生的限制）
// 2026-07-22 對外查證官方 FortiSwitchOS CLI Reference 後停用：本函式原本的語法（`config
// switch acl ingress` 底下直接 set description/set ingress-interface/set srcaddr/
// set dstaddr/set service 全部平鋪）是本專案自行設計、從未對照官方文件驗證過的猜測
// （程式碼原本就有註解自承）。查證確認真實結構完全不同：規則要巢狀在 `config classifier`
// 與 `config action` 兩個子區塊內，欄位是 `src-ip-prefix`/`dst-ip-prefix`（IP+遮罩，
// 非自由格式字串），且 `service` 是參照另一個 `config switch acl service custom` 物件
// 的 ID，不是自由格式字串；沒有 description/ingress-interface 欄位（介面套用是另外
// 綁定的）。與目前共用 ACL 表單資料形狀（src/dst/protocol 皆為自由字串）架構不相容，
// 需要全新表單欄位才能正確支援，本輪先停用捏造輸出不臆測，留待未來規劃
function renderFortiSwitchACL(list){
  return '';
}

// Breakout：獨立 `config switch phy-mode` 區塊，跟 `config switch interface` 是不同區塊
function renderFortiSwitchPhyModeBlock(breakouts){
  const ftBreakouts=(breakouts||[]).filter(b=>b.vendor==='fortiswitch');
  if(!ftBreakouts.length)return '';
  const lines=['config switch phy-mode'];
  ftBreakouts.forEach(b=>lines.push(`    set ${b.parentPort}-phy-mode ${b.mode}`));
  lines.push('end');
  return lines.join('\n');
}

function assembleFortiSwitchConfig(model){
  const blocks=[`# ${tr('notice.disclaimer')}`,'config system global',`    set hostname "${model.sysname||'Switch'}"`,'end'];
  const phyModeBlock=renderFortiSwitchPhyModeBlock(model.breakouts);
  if(phyModeBlock)blocks.push(phyModeBlock);
  const vlanBlock=renderFortiSwitchVLANsBlock(model.vlans);
  if(vlanBlock)blocks.push(vlanBlock);
  const ifaceBlock=renderFortiSwitchInterfaces(model.interfaces,model.security,model.stp);
  if(ifaceBlock)blocks.push(ifaceBlock);
  const lacpBlock=renderFortiSwitchLACP(model.lacp);
  if(lacpBlock)blocks.push(lacpBlock);
  const l3Block=renderFortiSwitchL3Interfaces(model.interfaces,model.vrrp,model.dhcp);
  if(l3Block)blocks.push(l3Block);
  const dhcpServerBlock=renderFortiSwitchDHCPServer(model.dhcp);
  if(dhcpServerBlock)blocks.push(dhcpServerBlock);
  const aclBlock=renderFortiSwitchACL(model.acl);
  if(aclBlock)blocks.push(aclBlock);
  const ospfBlock=renderFortiSwitchOSPF(model.ospf);
  if(ospfBlock)blocks.push(ospfBlock);
  const ripBlock=renderFortiSwitchRIP(model.rip);
  if(ripBlock)blocks.push(ripBlock);
  const routesBlock=renderFortiSwitchRoutes(model.routes);
  if(routesBlock)blocks.push(routesBlock);
  const bgpBlock=renderFortiSwitchBGP(model.bgp);
  if(bgpBlock)blocks.push(bgpBlock);
  // QoS：2026-07-22 對外查證官方 FortiSwitchOS Administration Guide 後移除——原本沿用
  // Cisco/Aruba 共用的 policy-map/class 語法整個語法家族選錯，FortiOS 原生是
  // config/edit/set/next/end 區塊風格，真實容器是 config switch qos dot1p-map／
  // config switch qos ip-dscp-map／config switch qos qos-policy（各佇列 min/max-rate/
  // weight），與目前共用 QoS 表單（policy/class/action/rate/burst 導向）架構完全不相容，
  // 需要全新表單欄位才能正確支援，本輪先移除捏造輸出不臆測，留待未來規劃
  const stpBlockFo=renderFortiSwitchSTP(model.stp);
  if(stpBlockFo)blocks.push(stpBlockFo);
  return blocks.join('\n');
}

// ══════════════════════════════════════════════════════════════════
// Aruba CX（ArubaOS-CX）render 函式（Cisco-like 縮排區塊風格，`!` 為視覺分隔慣例）
// ══════════════════════════════════════════════════════════════════

