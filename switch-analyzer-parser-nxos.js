function parseNxosVpc(cfg){
  const dm=cfg.match(/^vpc\s+domain\s+(\d+)\s*\n((?:[ \t][^\n]*\n?)*)/m);
  if(!dm)return null;
  const domain=dm[1], body=dm[2];
  const peerKeepalive=(body.match(/peer-keepalive\s+destination\s+(\S+)/)||[])[1]||'-';
  const peerGateway=/^\s*peer-gateway\s*$/m.test(body);
  let peerLink='-';
  for(const blk of cfg.split(/^interface\s+/m).slice(1)){
    const name=blk.split('\n')[0].trim();
    if(/^\s*vpc\s+peer-link\s*$/m.test(blk)){peerLink=name;break;}
  }
  return{type:'VPC', domain, peerLink, peerKeepalive, peerGateway,
    members:[{id:'1',model:'',priority:null,role:'primary'},{id:'2',model:'',priority:null,role:'secondary'}]};
}
function parseNXOS(cfg) {
  function parseSys() {
    const hostname=(cfg.match(/^hostname\s+(\S+)/m)||[])[1]||'-';
    const version=(cfg.match(/^version\s+(\S+)/m)||[])[1]||'-';
    return { hostname, version, model:'-' };
  }
  function parseVlans() {
    const vlans=[];
    for (const b of cfg.split(/^(?=vlan\s+\d)/m)) {
      const mV=b.match(/^vlan\s+(\d+)/);
      if (!mV) continue;
      const id=parseInt(mV[1]);
      const name=(b.match(/^\s+name\s+(.+)/m)||[])[1]?.trim()||`vlan${id}`;
      vlans.push({ id, name, ports:[], tagged:[], active:!/^\s+shutdown/m.test(b) });
    }
    return vlans;
  }
  function parseInterfaces() {
    const ifaces=[];
    for (const b of cfg.split(/^(?=interface\s)/m)) {
      const mIf=b.match(/^interface\s+(.+)/);
      if (!mIf) continue;
      const name=mIf[1].trim();
      const desc=(b.match(/^\s+description\s+(.+)/m)||[])[1]?.trim()||'';
      const shut=/^\s+shutdown/m.test(b);
      const mMode=b.match(/^\s+switchport mode\s+(\S+)/m);
      const mAccess=b.match(/^\s+switchport access vlan\s+(\d+)/m);
      const mTrunk=b.match(/^\s+switchport trunk allowed vlan\s+(.+)/m);
      const mIp=b.match(/^\s+ip address\s+(\S+)\/(\d+)/m);
      const mVrf=b.match(/^\s+vrf member\s+(\S+)/m);
      const ip=mIp?`${mIp[1]}/${mIp[2]}`:'-';
      // 次要IP（2026-08-12 新增，中信心度：官方 Cisco Nexus NX-OS Unicast Routing Command
      // Reference 的 `ip address` 頁面確認 `secondary` 關鍵字，惟 WebFetch 被 Cisco WAF 擋
      // 403，僅能用搜尋引擎索引摘要佐證，建議實作後另行覆核官方頁面）：`ip address A/N secondary`，
      // 僅取第一筆次要IP為 MVP 範圍，比照其餘廠牌既有限制
      const mSecIp=b.match(/^\s+ip address\s+(\S+)\/(\d+)\s+secondary/m);
      const secondaryIp=mSecIp?`${mSecIp[1]}/${mSecIp[2]}`:'';
      const vlan=mAccess?mAccess[1]:mTrunk?mTrunk[1].trim():'';
      const type=name.startsWith('Vlan')?'svi':name.startsWith('port-channel')||name.startsWith('Port-channel')?'lag':'physical';
      // Breakout: 子埠命名為三段式 Ethernet<mod>/<port>/<1-4>（獨立 `interface breakout module...map` 指令啟用，見 parseBreakout）
      const bkMatch=name.match(/^Ethernet(\d+\/\d+)\/([1-4])$/i);
      const breakoutChild=!!bkMatch;
      const breakoutParent=bkMatch?`Ethernet${bkMatch[1]}`:'';
      // member：比照 Cisco/其他廠牌從介面名稱取模組/機箱編號的既有慣例（Ethernet<mod>/<port> 取 mod），
      // 找不到（Vlan/port-channel 等非實體埠類型）則預設 '1'；shutdown：renderPorts() 讀的是布林 i.shutdown
      // 而非這裡的 status 字串，原本沒有這個欄位導致該欄一律顯示成 enabled、down 篩選對 NX-OS 永遠篩不到
      const memberMatch=name.match(/^Ethernet(\d+)\//i);
      const member=memberMatch?memberMatch[1]:'1';
      ifaces.push({ name, desc, status:shut?'disabled':'connected', shutdown:shut, member, mode:mMode?mMode[1]:'', ip, secondaryIp, vlan, vrf:mVrf?mVrf[1]:'', type, breakoutChild, breakoutParent, breakoutMode:'' });
    }
    return ifaces;
  }
  function parseBreakout() {
    const breakouts=[];
    const re=/^interface breakout module\s+(\d+)\s+port\s+(\d+)\s+map\s+(10g-4x|25g-4x)/gm;
    let m;
    while((m=re.exec(cfg))!==null){
      const [,mod,port,map]=m;
      breakouts.push({parentPort:`Ethernet${mod}/${port}`, mode: map==='10g-4x'?'4x10G':'4x25G', raw:m[0]});
    }
    return breakouts;
  }
  function parseRoutes() {
    // 2026-07-22 修正欄位名稱不一致 bug：原本用 gateway，但共用渲染邏輯 renderRoutes()
    // （switch-config-parser.html:9250-9258）與其餘所有廠牌皆讀 gw／gwIsInterface，
    // 導致 NX-OS 路由表格「下一跳閘道」欄位一律顯示 undefined（與稍早修復的 ProCurve
    // 同一種 bug，見 CLAUDE.md/now.md 對應紀錄）
    const routes=[];
    for (const line of cfg.split('\n')) {
      const m=line.match(/^ip route\s+(\S+)\/(\d+)\s+(\S+)/);
      if (!m) continue;
      routes.push({ dst:`${m[1]}/${m[2]}`, gw:m[3], gwIsInterface:!/^\d+\.\d+\.\d+\.\d+/.test(m[3]), metric:'1', vrf:'', type:'static', iface:'' });
    }
    return routes;
  }
  function parseVRFs() {
    const vrfs=[];
    for (const b of cfg.split(/^(?=vrf context\s)/m)) {
      const m=b.match(/^vrf context\s+(\S+)/);
      if (!m||m[1]==='management') continue;
      vrfs.push({ name:m[1], rd:(b.match(/^\s+rd\s+(\S+)/m)||[])[1]||'' });
    }
    return vrfs;
  }
  // 2026-07-17 修正：原本回傳 [{neighbor,remoteAs,localAs}] 逐 neighbor 攤平的形狀，
  // 與其餘所有廠牌／switch_analyzer 自己的 BGP report／CSV 匯出（皆讀 b.asn/b.routerId/
  // b.peers，見 exportRoutingCSV()／buildOverviewReport() 等處）完全不符，也與
  // switch_config_generator renderNXOSBGPList() 產生的設定檔格式不對稱——代表匯入真實
  // NX-OS 設定檔時 BGP 報表/匯出會顯示錯誤或空白，屬既有真實 bug，非本次新增 Networks
  // 功能才產生的問題，一併修正為與其餘廠牌一致的標準形狀。Networks 用
  // `network A.B.C.D/N [route-map NAME]`，須巢狀在 `address-family ipv4 unicast` 子區塊內
  // （已對外查證官方 NX-OS Unicast Routing Configuration Guide 確認）。
  function parseBGP() {
    // 修正：同上 \Z 字串結尾 fallback bug（NX-OS router bgp 若為檔案最後一段會解析不到），改用 (?![\s\S])
    const mBlock=cfg.match(/^router bgp\s+(\d+)([\s\S]*?)(?=^router\s|(?![\s\S]))/m);
    if (!mBlock) return [];
    const asn=mBlock[1], body=mBlock[2];
    const rid=(body.match(/^\s+router-id\s+(\S+)/m)||[])[1]||'';
    // neighbor 是真實 NX-OS 的子模式語法：`neighbor <ip>` 單獨一行進入子模式，
    // remote-as/description 是巢狀在其後、縮排更深的獨立行（非同一行的
    // `neighbor <ip> remote-as <n>` IOS 經典寫法）；renderNXOSBGPList() 本就是照這個
    // 真實格式輸出，但原本這裡的正則只認單行格式，兩者對不上導致 round-trip 讀不到任何
    // peer 資料，屬既有真實 bug。同時保留對單行格式的相容（部分工具/人工撰寫的設定檔
    // 仍可能用單行寫法）。
    const peers=[]; let curIp=null, curAs='', curDesc='';
    const flush=()=>{ if(curIp&&curAs)peers.push({ ip:curIp, as:curAs, desc:curDesc, type:curAs===asn?'iBGP':'eBGP' }); curIp=null; curAs=''; curDesc=''; };
    for (const line of body.split('\n')) {
      const mInline=line.match(/^\s+neighbor\s+(\S+)\s+remote-as\s+(\d+)/);
      if (mInline) { flush(); curIp=mInline[1]; curAs=mInline[2]; continue; }
      const mStart=line.match(/^\s+neighbor\s+(\S+)\s*$/);
      if (mStart) { flush(); curIp=mStart[1]; continue; }
      if (curIp) {
        const mAs=line.match(/^\s+remote-as\s+(\d+)/);
        if (mAs) { curAs=mAs[1]; continue; }
        const mDesc=line.match(/^\s+description\s+(.+)/);
        if (mDesc) { curDesc=mDesc[1].trim(); continue; }
      }
    }
    flush();
    const networks=[]; let nm;
    const nr=/^\s*network\s+([\d./]+)/gm;
    while((nm=nr.exec(body))!==null)networks.push(nm[1]);
    return [{ asn, routerId:rid, peers, networks }];
  }
  function parseOSPF() {
    // routerId 欄位原本誤植為 rid，與其餘所有廠牌／switch_analyzer 自己的 OSPF report／
    // CSV 匯出（皆讀 o.routerId）不符，一併修正（2026-07-17，與 ProCurve 同一類型的既有 bug）
    const ospf=[];
    for (const b of cfg.split(/^(?=router ospf\s)/m)) {
      const m=b.match(/^router ospf\s+(\d+)/);
      if (!m) continue;
      ospf.push({ pid:m[1], routerId:(b.match(/^\s+router-id\s+(\S+)/m)||[])[1]||'' });
    }
    return ospf;
  }
  function parseUsers() {
    const users=[];
    for (const line of cfg.split('\n')) {
      const m=line.match(/^username\s+(\S+)\s+password\s+\d+\s+\S+\s+role\s+(\S+)/);
      if (!m) continue;
      users.push({ name:m[1], role:m[2], type:'local', groups:[] });
    }
    return users;
  }
  const interfaces=parseInterfaces();
  const breakouts=parseBreakout();
  breakouts.forEach(b=>{
    const iface=interfaces.find(f=>f.name.toLowerCase()===b.parentPort.toLowerCase());
    if(iface)iface.breakoutMode=b.mode;
  });
  return {
    sys:        parseSys(),
    irf:        null,
    stack:      parseNxosVpc(cfg),
    vlans:      parseVlans(),
    interfaces,
    // 先前寫死空陣列，實際上 parseLACP(cfg,'nxos') 早已支援 channel-group 語法（與其他
    // Cisco-like 廠牌一致），只是透過 parseAny() 聚合呼叫時事後才被覆蓋，parseNXOS() 單獨
    // 呼叫或測試時仍會誤報成完全沒有 LACP；改為直接呼叫消除此誤導性欄位
    lacp:       parseLACP(cfg,'nxos'),
    routes:     parseRoutes(),
    vrfs:       parseVRFs(),
    users:      parseUsers(),
    ospf:       parseOSPF(),
    bgp:        parseBGP(),
    rip:        [],
    vrrp:       parseVRRP(cfg,'nxos'),
    vxlan:      null,
    breakouts,
    vendor:     'nxos'
  };
}

// ══════════════════════════════════════════════════════
//  ARUBA PROCURVE / ARUBAOS-SWITCH PARSER
// ══════════════════════════════════════════════════════
