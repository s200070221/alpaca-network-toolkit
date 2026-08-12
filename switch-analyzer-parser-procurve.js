function parseProCurve(cfg) {
  function parseSys() {
    const mModel=cfg.match(/^;\s*(J\d{4}[A-Z]\S*|Aruba\s+JL\S*)/m);
    const model=mModel?mModel[1].trim():'-';
    const mHost=cfg.match(/^hostname\s+"?([^"\n]+)"?/m);
    const hostname=mHost?mHost[1].trim():'-';
    const mVer=cfg.match(/^software-version\s+(\S+)/m);
    return { hostname, version:mVer?mVer[1]:'-', model };
  }
  function parseVlans() {
    const vlans=[];
    for (const b of cfg.split(/^(?=vlan\s+\d)/m)) {
      const mV=b.match(/^vlan\s+(\d+)/);
      if (!mV) continue;
      const id=parseInt(mV[1]);
      const mName=b.match(/^\s+name\s+"?([^"\n]+)"?/m);
      const name=mName?mName[1].trim():`VLAN${id}`;
      const tagged=(b.match(/^\s+tagged\s+(.+)/m)||[])[1]?.trim()||'';
      const untagged=(b.match(/^\s+untagged\s+(.+)/m)||[])[1]?.trim()||'';
      // "no untagged PORTLIST"：把這些埠從該 VLAN 的預設 untagged 成員移除（通常是因為
      // 它們實際歸屬其他 VLAN），非成員關係宣告，故不併入 untagged 欄位；但埠名本身仍是
      // 判斷「這台設備上真的有這個實體埠」的線索之一，另存供 synthesizeMissingInterfaces() 使用
      const noUntagged=(b.match(/^\s+no untagged\s+(.+)/m)||[])[1]?.trim()||'';
      // extract IP if present (default gateway SVI)
      const mIp=b.match(/^\s+ip address\s+(\S+)\s+(\S+)/m);
      // 修正既有 bug：其餘所有廠牌的 vlan 物件皆有 ipSubnets 欄位（共用 UI 摘要卡片
      // buildSumCards() 讀 v.ipSubnets.length 判斷有 IP 的 VLAN 數），parseProCurve()
      // 原本只有單一字串 ip 欄位、從未設定 ipSubnets，導致透過真實 UI 分析流程（doAnalyze()）
      // 時 buildSumCards() 直接對 undefined.length 拋錯、整個分析結果打不開——只有繞過 UI
      // 直接呼叫 parseProCurve() 的既有測試不會觸發，故先前未被發現
      const ipSubnets=mIp?[{network:mIp[1],mask:mIp[2],cidr:`${mIp[1]}/${cidrFromMask(mIp[2])}`}]:[];
      vlans.push({ id, name, tagged, untagged, noUntagged, ports:[], ip:mIp?`${mIp[1]}/${mIp[2]}`:'', ipSubnets });
    }
    return vlans;
  }
  function parseInterfaces() {
    const ifaces=[];
    for (const b of cfg.split(/^(?=interface\s)/m)) {
      const mIf=b.match(/^interface\s+(\S+)/);
      if (!mIf) continue;
      const name=mIf[1];
      const mName=b.match(/^\s+name\s+"?([^"\n]+)"?/m);
      const desc=mName?mName[1].trim():'';
      const disabled=/^\s+disable/m.test(b);
      const mSpeed=b.match(/^\s+speed-duplex\s+(\S+)/m);
      ifaces.push({ name, desc, status:disabled?'disabled':'connected', speed:mSpeed?mSpeed[1]:'auto', mode:'access', vlans:'', type:'physical' });
    }
    return ifaces;
  }
  // 真實語法 VLAN membership 以 VLAN 區塊為主體宣告（tagged/untagged port 清單），
  // interface 區塊本身完全不含 mode/vlan 資訊，故 parseInterfaces() 單獨執行時無從得知
  // 逐 port 的 trunk/access 狀態；比照既有 Alcatel/Extreme XOS 慣例，於 parseProCurve()
  // 主體反查 parseVlans() 的 tagged/untagged 清單回填。support 連字號範圍與逗號清單
  // （如 "9-10" / "1,3"），與 VLAN 表格常見寫法一致。
  // 修正既有 bug：真實 ProCurve/ArubaOS-Switch 匯出檔的模組化埠命名範圍是「字母+數字」
  // 格式（如 "A1-A8"／"G3-G6"），原本的 `^(\d+)-(\d+)$` 只認純數字範圍，字母+數字範圍
  // 會直接落入 else 分支被當成單一（不存在的）埠名字面值，如 "A1-A8" 整段被當成一個埠
  function expandPortList(rangeStr) {
    const ports=[];
    for (const part of (rangeStr||'').split(',').map(s=>s.trim()).filter(Boolean)) {
      const m=part.match(/^([A-Za-z]*)(\d+)-(?:[A-Za-z]*)(\d+)$/);
      if (m) { const prefix=m[1]; for (let i=+m[2]; i<=+m[3]; i++) ports.push(prefix+i); }
      else ports.push(part);
    }
    return ports;
  }
  // 真實匯出常見情境：僅使用預設設定的埠完全不會出現 interface 區塊（ProCurve/ArubaOS-Switch
  // 慣例，交換器不會為「沒有任何非預設設定」的埠印出 interface 區塊），但這些埠仍會在 VLAN
  // tagged/untagged/no-untagged 清單中被提及。若不補上，這些埠會直接從畫面上消失——真實案例
  // （HPE 5412zl，J9851A，KB.16.05 韌體）匯出檔僅 2 個明確 interface 區塊（皆只為了設定 LACP
  // key），實際卻有 A/B/C/G/H 五模組近 80 個實體埠，全數只能從 VLAN 成員清單反查存在性。
  // Trk10 等邏輯 trunk 名稱已由 parseTrunk() 另外處理，此處排除避免誤當成實體埠。
  function synthesizeMissingInterfaces(vlans, ifaces) {
    const known=new Set(ifaces.map(i=>i.name));
    const TRUNK_RE=/^trk\d+$/i;
    vlans.forEach(v=>{
      [v.tagged, v.untagged, v.noUntagged].forEach(list=>{
        expandPortList(list).forEach(p=>{
          if (TRUNK_RE.test(p) || known.has(p)) return;
          known.add(p);
          ifaces.push({ name:p, desc:'', status:'connected', speed:'auto', mode:'access', vlans:'', type:'physical' });
        });
      });
    });
    ifaces.sort((a,b)=>{
      // 字母前綴用 * 而非 +：部分廠牌/測試環境的埠名稱是純數字（無模組字母前綴，如 "1".."26"），
      // 原本要求至少 1 個字母會讓這類埠名落入字串排序分支，導致 "10" 排在 "2" 之前
      const ma=a.name.match(/^([A-Za-z]*)(\d+)$/), mb=b.name.match(/^([A-Za-z]*)(\d+)$/);
      if (ma&&mb) { if (ma[1]!==mb[1]) return ma[1].localeCompare(mb[1]); return parseInt(ma[2])-parseInt(mb[2]); }
      return a.name.localeCompare(b.name);
    });
  }
  function applyVlanMembership(vlans, ifaces) {
    const untaggedOf={}, taggedOf={};
    vlans.forEach(v=>{
      expandPortList(v.untagged).forEach(p=>{ untaggedOf[p]=String(v.id); });
      expandPortList(v.tagged).forEach(p=>{ (taggedOf[p]=taggedOf[p]||[]).push(String(v.id)); });
    });
    // 一個 port 可能同時是某 VLAN 的 untagged 成員（native/PVID）又是其他 VLAN 的 tagged
    // 成員（例如語音 VLAN 疊加在一般 access port 上），此時屬於 trunk（native+tagged 並存），
    // 故 tagged 優先判斷，untagged 僅在無 tagged 時才視為單純 access
    ifaces.forEach(i=>{
      if (taggedOf[i.name]) {
        i.mode='trunk'; i.vlans=taggedOf[i.name].join(',');
        if (untaggedOf[i.name]!==undefined) i.nativeVlan=untaggedOf[i.name];
      } else if (untaggedOf[i.name]!==undefined) {
        i.mode='access'; i.vlans=untaggedOf[i.name];
      }
    });
  }
  function parseTrunk() {
    const trunks=[];
    for (const line of cfg.split('\n')) {
      const m=line.match(/^trunk\s+([\dA-Za-z,\/\-]+)\s+([Tt]rk\d+)\s+(lacp|trunk)/i);
      if (!m) continue;
      trunks.push({ name:m[2], members:m[1], mode:m[3].toLowerCase()==='lacp'?'Active':'Static' });
    }
    return trunks;
  }
  function parseRoutes() {
    // 官方語法（arubanetworking.hpe.com CLI-Bank "ip route"）：
    // ip route <dest-ip-addr>/<mask-length> <next-hop-ip-addr|vlan <id>|reject|blackhole> [metric <n>] [distance <n>]
    // 2026-07-22 對外查證真實 HPE 5412zl（J9851A，KB.16.05 韌體）匯出檔後修正：上述 CIDR-only
    // 語法並不完整，真機實際輸出是傳統「dest mask gateway」點分遮罩三段式（如
    // "ip route 0.0.0.0 0.0.0.0 203.72.48.253"），可能因韌體/型號差異兩種格式併存，
    // 故同時支援兩種寫法，避免真實匯出檔被漏解析
    // 修正既有 bug：其餘所有廠牌的路由物件欄位名稱皆為 gw／gwIsInterface（renderRoutes()
    // 共用渲染邏輯讀的就是這兩個名稱），parseProCurve() 原本用 gateway（無 gwIsInterface），
    // 導致畫面「下一跳閘道」欄位一律顯示 undefined——先前因 routes 恆為空陣列從未觸發過
    const routes=[];
    for (const line of cfg.split('\n')) {
      // 格式 A：CIDR（dest/prefixlen）
      let m=line.match(/^ip route\s+(\S+\/\d+)\s+(vlan\s+\d+|\S+)(?:\s+metric\s+(\d+))?/);
      if (m) { routes.push({ dst:m[1], gw:m[2], gwIsInterface:/^vlan\s+\d+/i.test(m[2]), metric:m[3]||'1', type:'static', iface:'', vrf:'' }); continue; }
      // 格式 B：點分遮罩三段式（dest mask gateway）
      m=line.match(/^ip route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(vlan\s+\d+|\S+)(?:\s+metric\s+(\d+))?/);
      if (m) { routes.push({ dst:`${m[1]}/${cidrFromMask(m[2])}`, gw:m[3], gwIsInterface:/^vlan\s+\d+/i.test(m[3]), metric:m[4]||'1', type:'static', iface:'', vrf:'' }); continue; }
    }
    // ip default-gateway <ip>：交換器本身管理用預設閘道（IP routing 未啟用或無更精確
    // 路由時裝置實際會採用的出口），行為等同一條預設靜態路由，比照其餘廠牌併入 routes 顯示；
    // 若已有明確 ip route 設定 0.0.0.0/0（本例即是），避免重複顯示同一條預設路由
    const dgM=cfg.match(/^ip default-gateway\s+(\S+)/m);
    if (dgM && !routes.some(r=>r.dst==='0.0.0.0/0')) {
      routes.push({ dst:'0.0.0.0/0', gw:dgM[1], gwIsInterface:false, metric:'1', type:'static', iface:'', vrf:'' });
    }
    return routes;
  }
  // 2026-07-17 對外查證 arubanetworking.hpe.com AOS-S 16.10 官方文件確認：ArubaOS-Switch
  // 完全沒有 Cisco 式 `network X wildcard area N` 語法；`router ospf` 底下的 `area <id>`
  // 只宣告該 area 存在（不含網段資訊，如 `area backbone`/`area 1`，比照已修復的 Brocade
  // OSPF 慣例不對此宣告做任何 gate 判斷，因為其輸出從未被實際使用）；真正的網段指派是在
  // VLAN context 內執行 `ip ospf area <id>`（整個 VLAN）或 `ip ospf <ip-address> area <id>`
  // （單一子網），故逐 VLAN 區塊掃描取得。routerId 欄位原本誤植為 `rid`，與其餘所有廠牌
  // ／switch_analyzer 自己的 OSPF report／CSV 匯出（皆讀 o.routerId）不符，一併修正。
  function parseOSPF() {
    if (!/^router ospf/m.test(cfg)) return [];
    const routerId=(cfg.match(/^\s+router-id\s+(\S+)/m)||[])[1]||'';
    const areas=[];
    for (const b of cfg.split(/^(?=vlan\s+\d)/m)) {
      const mV=b.match(/^vlan\s+(\d+)/);
      if (!mV) continue;
      const aM=b.match(/^\s+ip ospf(?:\s+[\d.]+)?\s+area\s+([\d.]+)/m);
      if (!aM) continue;
      const area=aM[1];
      let entry=areas.find(a=>a.area===area);
      if (!entry) { entry={ area, networks:[] }; areas.push(entry); }
      entry.networks.push({ network:mV[1] });
    }
    return [{ pid:'1', routerId, areas }];
  }
  // 2026-07-22 新增（真實 HPE 5412zl 匯出檔查證）：DHCP relay 解析。ArubaOS-Switch 真實語法
  // 是逐 VLAN 內宣告 `ip helper-address <server-ip>`（非全域設定），資料形狀比照其餘廠牌
  // parseDHCP() 既有 type:'relay' 慣例（詳見 comware 分支 pools.push 寫法），不重新設計 schema。
  // parseAny() 的共用 dispatcher 已把 procurve 排除在外（見 parseAny() 內排除清單註解），
  // 原意就是要由 parseProCurve() 自行提供，先前只排除卻從未實作，本次補上
  function parseDhcpRelay() {
    const relays=[];
    // 2026-07-24 對外查證官方 AOS-S CLI Reference 後新增：Option82 插入為全域指令
    // "dhcp-relay option 82 ..."（非逐 VLAN），與 AOS-CX 同名但關鍵字細節不同（append/mgmt-vlan
    // 等參數差異，不影響此處僅需偵測是否啟用的判斷），套用到該廠牌全部 relay 條目
    const option82=/^dhcp-relay option 82\b/m.test(cfg);
    for (const b of cfg.split(/^(?=vlan\s+\d)/m)) {
      const mV=b.match(/^vlan\s+(\d+)/);
      if (!mV) continue;
      const iface='vlan'+mV[1];
      for (const hm of b.matchAll(/^\s+ip helper-address\s+(\S+)/gm)) {
        relays.push({ name:iface, network:'', gateway:'', dns:[], range:'', excluded:'', interface:iface, lease:'', type:'relay', relayServer:hm[1], option82 });
      }
    }
    return relays;
  }
  // 2026-07-22 新增（真實 HPE 5412zl 匯出檔查證）：使用者帳號解析，涵蓋兩種真實並存語法——
  // (1) 傳統機制：password {operator|manager} [user-name "NAME"] sha1 "HASH"（user-name 子句
  //     可省略，省略時帳號名稱即固定為 operator/manager 字面值）
  // (2) 新式 AAA 本機帳號：aaa authentication local-user "NAME" group "GROUP" password sha1 "HASH"
  // 資料形狀比照既有 parseUsers()（Comware）等慣例 {name,role,service,hasPwd,pwdType,pwdWeak}，
  // 兩種語法皆為 sha1 雜湊值（非明碼），pwdType 固定 'hash'、pwdWeak 固定 false
  function parseUsers() {
    const users=[];
    const reLegacy=/^password\s+(operator|manager)(?:\s+user-name\s+"?([^"\s]+)"?)?\s+sha1\b/gm;
    let m;
    while((m=reLegacy.exec(cfg))!==null){
      users.push({ name:m[2]||m[1], role:m[1], service:'ssh/console', hasPwd:true, pwdType:'hash', pwdWeak:false });
    }
    const reAAA=/^aaa authentication local-user\s+"?([^"\s]+)"?\s+group\s+"?([^"\s]+)"?\s+password\s+sha1\b/gm;
    while((m=reAAA.exec(cfg))!==null){
      users.push({ name:m[1], role:m[2], service:'ssh/console', hasPwd:true, pwdType:'hash', pwdWeak:false });
    }
    return users;
  }
  const pcVlans=parseVlans(), pcInterfaces=parseInterfaces();
  synthesizeMissingInterfaces(pcVlans, pcInterfaces);
  applyVlanMembership(pcVlans, pcInterfaces);
  return {
    sys:        parseSys(),
    irf:        null,
    stack:      null,
    vlans:      pcVlans,
    interfaces: pcInterfaces,
    lacp:       parseTrunk(),
    routes:     parseRoutes(),
    vrfs:       [],
    users:      parseUsers(),
    dhcp:       parseDhcpRelay(),
    ospf:       parseOSPF(),
    bgp:        [],
    rip:        [],
    vrrp:       [],
    vxlan:      null,
    vendor:     'procurve'
  };
}

// ══════════════════════════════════════════════════════
//  STP / SPANNING TREE PARSER
// ══════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════
//  ACL PARSER
// ══════════════════════════════════════════════════════
