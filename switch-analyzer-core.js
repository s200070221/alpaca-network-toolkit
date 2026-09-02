let _lang = 'zhTW';
function tr(key) {
  if (_lang === 'leet') { var s=LANG_SW.en[key]||LANG_SW.zhTW[key]||key; return s.replace(/a/gi,'4').replace(/e/gi,'3').replace(/i/gi,'1').replace(/o/gi,'0').replace(/s/gi,'5').replace(/t/gi,'7').replace(/l/gi,'|'); }
  if (_lang === 'uwu')  { var s=LANG_SW.en[key]||LANG_SW.zhTW[key]||key; return s.replace(/r/g,'w').replace(/R/g,'W').replace(/l/g,'w').replace(/L/g,'W').replace(/th/g,'d').replace(/Th/g,'D').replace(/n([aeiou])/g,'ny$1').replace(/N([AEIOU])/g,'Ny$1'); }
  if (_lang === 'cat')  { var d=LANG_SW.cat&&LANG_SW.cat[key]; if(d)return d; var base=LANG_SW.zhTW[key]||LANG_SW.en[key]||key; return base+(/[一-鿿]$/.test(base)?'喵~':' nyaa~'); }
  if (_lang === 'bean') { var d=LANG_SW.bean&&LANG_SW.bean[key]; if(d)return d; var base=LANG_SW.en[key]||LANG_SW.zhTW[key]||key; var vg=['🥕','🫛','🌽']; return base.split('').map(function(c){return c===' '?' ':vg[c.charCodeAt(0)%3];}).join(''); }
  var v = LANG_SW[_lang] && LANG_SW[_lang][key];
  if (v !== undefined && v !== '') return v;
  var en = LANG_SW.en && LANG_SW.en[key];
  if (en) return en;
  return LANG_SW.zhTW[key] || key;
}
function tip(key, label) {
  var t = tr(key);
  if (!t || t === key) return label;
  return '<span data-tip="' + t.replace(/"/g,'&quot;') + '">' + label + '<sup style="font-size:8px;opacity:.45;margin-left:2px;cursor:help">ⓘ</sup></span>';
}
function setLang(code) {
  _lang = code;
  document.querySelectorAll('[data-i18n]').forEach(function(el) {
    var k = el.dataset.i18n;
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') el.placeholder = tr(k);
    else el.textContent = tr(k);
  });
  document.querySelectorAll('.lang-btn').forEach(function(b) { b.classList.toggle('active', b.dataset.lang === code); });
  _onLangChange();
}
function _onLangChange() {
  if (typeof currentView !== 'undefined' && currentView && currentView !== 'upload' && typeof navGo === 'function') {
    navGo(currentView);
  }
  if (typeof parsed !== 'undefined' && parsed && typeof buildSumCards === 'function') {
    buildSumCards();
  }
  var pa = document.getElementById('paste-area');
  if (pa) pa.placeholder = tr('paste.placeholder');
  // tooltip 更新（title 屬性無法用 data-i18n，改由此處統一刷新）
  var logoBt = document.getElementById('logo-btn');
  if (logoBt) logoBt.title = tr('egg.logo_hint');
  var sbBtn = document.getElementById('sb-toggle');
  if (sbBtn) sbBtn.title = (typeof sbMini !== 'undefined' && sbMini) ? tr('sb.expand') : tr('sb.fold');
  var alpaca = document.getElementById('mini-alpaca');
  if (alpaca) alpaca.title = tr('egg.alpaca_title');
  // 更新 nav-irf-lbl（依廠牌決定文字，不含 data-i18n）
  var irfLbl = document.getElementById('nav-irf-lbl');
  if (irfLbl && typeof parsed !== 'undefined' && parsed) {
    // 2026-08-19 補上與 switch-analyzer-app.js 的 showResultViews() 同步（doAnalyze() 結尾
    // 呼叫 setLang() 觸發本函式，會覆蓋 showResultViews() 剛設好的值，故兩處必須保持一致）：
    // 補上先前就已存在、僅這裡漏掉的 Arista MLAG 分支，以及新增的 Juniper MC-LAG 分支
    irfLbl.textContent = parsed.vendor==='arista'&&parsed.stack?'Arista MLAG':parsed.vendor==='nxos'&&parsed.stack?'Cisco NX-OS VPC':parsed.vendor==='ruijie'&&parsed.stack?'Ruijie VSU':parsed.vendor==='cisco'?tr('nav.irf.cisco'):parsed.vendor==='nxos'?tr('nav.irf.cisco'):parsed.vendor==='comware'?tr('nav.irf.comware'):parsed.vendor==='aruba'?tr('nav.irf.aruba'):parsed.vendor==='procurve'?tr('nav.irf.default'):parsed.vendor==='fortiswitch'?tr('nav.irf.forti'):parsed.vendor==='juniper'&&parsed.stack?.type==='VC'?'Virtual Chassis':parsed.vendor==='juniper'&&parsed.stack?.type==='MC-LAG'?'Juniper MC-LAG':parsed.vendor==='alcatel'&&parsed.stack?'Alcatel Stack':parsed.vendor==='extreme'&&parsed.stack?'ExtremeStack':parsed.vendor==='brocade'&&parsed.stack?tr('nav.irf.brocade'):parsed.vendor==='dell-os10'&&parsed.stack?.type==='VLT'?tr('nav.irf.dell_vlt'):parsed.vendor==='dell-os10'&&parsed.stack?tr('nav.irf.dell_stack'):tr('nav.irf.default');
  }
  // data-tip 更新（sidebar 折疊時的 CSS tooltip，attribute 無法用 data-i18n）
  [['nav-upload','nav.upload'],['nav-overview','nav.overview'],
   ['nav-ports','nav.ports'],['nav-routes','nav.routes'],
   ['nav-routing','nav.routing'],['nav-users','nav.users'],
   ['nav-lldp','nav.lldp'],
   ['nav-stp','nav.stp'],
   ['nav-vlan-matrix','nav.vlan_matrix'],
   ['nav-acl','nav.acl']
  ].forEach(function(p){var el=document.getElementById(p[0]);if(el)el.setAttribute('data-tip',tr(p[1]));});
  var irfItem=document.getElementById('nav-irf');
  if(irfItem && irfLbl) irfItem.setAttribute('data-tip', irfLbl.textContent);
}






'use strict';
// ═ HPE Comware Parser ═
// 2026-08-09 稽核修復：原本純查表法缺 /1-7、/9-15，尤其常見的點對點鏈路 /31
// (255.255.255.254)，查不到時原樣回傳字串會讓下游 switch_config_generator 的
// maskFromCidr() parseInt 失敗又被 isNaN 攔截，靜默 fallback 成語意不同的 /32。
// 改為查表命中才走 fast path，未命中改用與 maskToCIDR() 一致的位元運算，消除兩套
// 平行實作（maskToCIDR 定義於下方，因函式宣告會被提升至整個 script 作用域頂端，
// 呼叫時序上不受此處引用在前的影響）
function maskToCIDR(mask){
  if(!mask)return'';
  if(mask.includes('/'))return mask.split('/')[1];
  const parts=mask.split('.');
  let bits=0;
  for(const p of parts){let n=parseInt(p);while(n){bits+=n&1;n>>=1;}}
  return String(bits);
}

function detectVendor(cfg){
  // SONiC：config_db.json 是純 JSON，非文字 CLI，必須排在最前面（其餘 16 家皆為行首正則，
  // 不可能以 "{" 開頭，零副作用）。用 JSON.parse 而非字串比對，JSON.parse 失敗（或缺特徵
  // 頂層表格）直接落穿到下面既有文字 CLI 判斷鏈
  {
    const trimmed=cfg.trim();
    if(trimmed.charAt(0)==='{'){
      try{
        const obj=JSON.parse(trimmed);
        if(obj&&typeof obj==='object'&&obj.DEVICE_METADATA&&(obj.VLAN||obj.PORT||obj.INTERFACE))return'sonic';
      }catch(e){ /* 非合法 JSON，繼續往下走既有文字 CLI 判斷鏈 */ }
    }
  }
  if(/^\s*sysname\s+|irf domain|port link-type|undo shutdown|ip route-static|ip vpn-instance/m.test(cfg))return'comware';
  // ProCurve/ArubaOS-Switch: ; J9xxx header, oobm keyword, or trunk X trk1 lacp syntax
  if(/^;\s*(?:HP\s|Aruba\s|J\d{4}[A-Z])/m.test(cfg)||/^oobm$/m.test(cfg)||/^trunk\s+[\dA-Za-z,\/\-]+\s+[Tt]rk\d+/m.test(cfg))return'procurve';
  // NX-OS: feature command + Nexus/VDC/jumbomtu identifier (must be before cisco IOS)
  if(/^feature\s+\w+/m.test(cfg)&&(/Cisco\s+Nexus/i.test(cfg)||/^vdc\s+\S+\s+id\s+\d+/m.test(cfg)||/^system\s+jumbomtu\s+\d+/m.test(cfg)))return'nxos';
  if(/^vsf\s*$|vlan trunk allowed|vlan trunk native|vlan access\s+\d|vrf attach\s/m.test(cfg))return'aruba';
  if(/^config system global/m.test(cfg) || /^config switch physical-port/m.test(cfg) || /^config router ospf/m.test(cfg))return'fortiswitch';
  // Brocade FastIron/ICX: "vlan N by port", "tagged"/"untagged" under vlan, "stack unit"
  if(/^vlan\s+\d+\s+(?:name\s+\S+\s+)?by\s+port/m.test(cfg)||
     /^stack unit\s+\d+/m.test(cfg)||
     /^\s+tagged\s+e(?:thernet)?\s*[\d/]+/m.test(cfg)||
     /^\s+untagged\s+e(?:thernet)?\s*[\d/]+/m.test(cfg)||
     /^ip dhcp-server pool\s/m.test(cfg)||
     /^lag\s+"\S+"\s+(?:dynamic|static)\s+id\s+\d+/m.test(cfg)||
     /^ip vrrp-extended vrid\s/m.test(cfg))return'brocade';
  // Alcatel OmniSwitch AOS: -> prefix OR flat AOS style (boot.cfg / AOS 7/8)
  if(/^(?:->\s*)?system name\s+/m.test(cfg)||
     /^(?:->\s*)?stack set slot\s+/m.test(cfg)||
     /^(?:->\s*)?ip interface\s+/m.test(cfg)||
     /vlan\s+\d+\s+members\s+port/i.test(cfg)||
     /^stacking\s+slot\s+\d/m.test(cfg)||
     /^vlan\s+\d+\s+admin-state\s+enable/m.test(cfg)||
     /^dhcp-server\s+(?:admin-state|range)\s+/m.test(cfg)||
     /^linkagg\s+lacp\s+\d+\s+admin-state/m.test(cfg)||
     /^interfaces\s+\S+\s+linkagg\s+\d/m.test(cfg)){return'alcatel';}
  // Dell OS10/OS9(FTOS): ethernet N/N/N (OS10), ManagementEthernet/fortyGigE/stack-unit (OS9), vlt-domain, or version comment
  if(/^interface\s+ethernet\d+\/\d+\/\d+/im.test(cfg)||
     /^vlt-domain\s+\d+/m.test(cfg)||
     /^!\s*Dell (?:EMC )?Networking OS/m.test(cfg)||
     /^interface\s+ManagementEthernet/m.test(cfg)||
     /^interface\s+fortyGigE\s/m.test(cfg)||
     /^stack-unit\s+\d+/m.test(cfg))return'dell-os10';
  // Arista EOS: unique signatures (must be before Cisco)
  if(/^!\s*device:\s*\S+.*\(Arista\s/m.test(cfg)||/^!\s*Software image version:\s*EOS/im.test(cfg)||
     (/^interface\s+Ethernet\d+(?:\/\d+)?\s*$/m.test(cfg)&&/^ip routing$/m.test(cfg)))return'arista';
  // RouterOS / MikroTik: 必須在 cisco 之前，避免 /ip route 行觸發 cisco 誤判
  if(/^\s*\/interface|\/ip\s+(?:address|firewall|route)|\/system\s+identity/m.test(cfg))return'routeros';
  // Planet Technology SGS-6341 系列：CLI 骨架整體近似 Cisco IOS Classic（hostname／
  // switchport mode），必須在 cisco 之前判斷，否則會被下面通用的 cisco 比對誤判；也
  // 必須排在 Ruijie 之前——Ruijie 的判斷式含通用的 `switchport mode hybrid` 弱訊號，
  // Planet 設定檔若含 hybrid 介面會先被 Ruijie 判斷式攔截誤判（2026-08-26 實測踩坑
  // 修正，原本排在 Ruijie 之後）。官方 SGS-6341 Series Command Guide 直接 fetch 逐字
  // 查證，查無足夠獨特的 show running-config 表頭字樣可用，改用「hostname + ethernet
  // slot/port 命名（含空格）+ switchport mode」三重弱訊號組合判斷：介面命名
  // "ethernet 1/0/5"（ethernet 與 slot/port 之間有空格，與 Dell OS10
  // "ethernet1/1/1"〔無空格，見上方 dell-os10 判斷式〕不同）；Brocade FastIron 雖也用
  // "interface ethernet"（見下方 brocade 判斷式），但官方語法從未使用 "switchport"
  // 關鍵字（FastIron 用 tagged/untagged）；Ruijie 用 "GigabitEthernet 0/1" 命名前綴
  // （非裸 "ethernet"），三訊號組合後不會與既有 17 家任何一家碰撞
  if(/^hostname\s+\S+/m.test(cfg)&&/^interface\s+ethernet\s+\d+\/\d+\/\d+/m.test(cfg)&&/^\s*switchport mode\s+(trunk|access|hybrid)/m.test(cfg))return'planet';
  // Ruijie RGOS：語法系出 Cisco IOS 風格，必須在 cisco 之前判斷。用 Ruijie 專屬（Cisco 沒有）
  // 的關鍵字組合避免誤判其他 12 家：AggregatePort 聚合介面命名（Cisco 是 channel-group／
  // Port-channel）／switchport mode hybrid（Cisco 無 hybrid 模式）／VSU 堆疊 switch virtual domain。
  // 2026-07-29 使用者提供真實裝置匯出檔測出：不含 AggregatePort/hybrid/VSU 的一般 access
  // switch（無堆疊/聚合/hybrid 功能）原本會被誤判為 cisco，補上更通用、幾乎不會與其他廠牌
  // 碰撞的訊號——"RGOS" 字面（幾乎必然出現在 version 這行的韌體版本字串）／rldp（Ruijie
  // 自有 Loop Detection Protocol）／nfpp（Ruijie 自有 Network Foundation Protection Policy）
  if(/^interface\s+AggregatePort\s*\d+/im.test(cfg)||/switchport mode hybrid/m.test(cfg)||/^switch virtual domain\s+\d+/m.test(cfg)||/\bRGOS\b/i.test(cfg)||/^rldp\b/im.test(cfg)||/^nfpp\s*$/im.test(cfg))return'ruijie';
  // Netgear M4300（Intelligent Edge，Broadcom ICOS/FASTPATH 架構）：語法與 Cisco 相容
  // （switchport mode trunk/access 皆可用），必須在 cisco 之前判斷，否則會被下面的通用
  // cisco 比對誤判。2026-07-30 對外查證官方 M4300 Intelligent Edge Series CLI Command
  // Reference Manual（202-11997-09）後新增，官方 show running-config 範例確認表頭固定為
  // "!Current Configuration:"，此表頭為整個 ICOS 系列共用（與 Ubiquiti EdgeSwitch 同源），
  // 故必須搭配內文含 "NETGEAR"/"M4300" 字樣才判定，避免與未來若新增的其他 ICOS 廠牌衝突。
  // 已知限制：沒有真實裝置匯出檔可比對 !System Description 欄位確切文字，若使用者自訂
  // hostname 又剛好沒有其他地方出現廠牌字樣，此簽章會判斷失敗（保守寧可判斷不到，不誤判）
  if(/^!Current Configuration:/m.test(cfg)&&/(NETGEAR|M4300)/i.test(cfg))return'netgear';
  // Ubiquiti EdgeSwitch（舊款 ES-XX／EdgeSwitch X 系列，非現行 Controller 管理的 UniFi USW）：
  // 與 Netgear M4300 同源 Broadcom ICOS 架構，共用同一個 "!Current Configuration:" 表頭，
  // 但 EdgeSwitch 沒有 Netgear 那組 switchport 相容別名，VLAN 成員一律用原生
  // "vlan participation include/exclude/auto" 語法（Netgear 官方文件查證範圍內從未出現
  // 此關鍵字），以此作為兩者的區分依據
  if(/^!Current Configuration:/m.test(cfg)&&(/UBNT|EdgeSwitch/i.test(cfg)||/^\s*vlan participation (include|exclude|auto)/m.test(cfg)))return'edgeswitch';
  if(/^hostname\s+|switchport mode|ip route\s|^vlan\s+\d+\s*\n\s*name/m.test(cfg))return'cisco';
  // ExtremeXOS: verb-object CLI — zero overlap with other vendors
  if(/^create vlan\s+"?\S/m.test(cfg)||
     /^configure sys-name\s+/m.test(cfg)||
     /^enable sharing\s+\S+\s+grouping/m.test(cfg)||
     /^configure vlan\s+/m.test(cfg)||
     /^configure iproute add\s+/m.test(cfg)||
     /^enable sharing\s+[\d:]/m.test(cfg)||/^configure vlan\s+\S+\s+dhcp-address-range/m.test(cfg))return'extreme';
  // Juniper: version N.NRN, Virtual Chassis, family ethernet-switching, or Junos hierarchy
  if(/^version\s+\d+\.\d+R/m.test(cfg)||/^virtual-chassis\s*\{/m.test(cfg)||/family\s+ethernet-switching/m.test(cfg)||((/^interfaces\s*\{/m.test(cfg)||/^protocols\s*\{/m.test(cfg))&&/routing-options\s*\{/m.test(cfg)))return'juniper';
  return'unknown';
}

// ══════════════════════════════════════════════════════
//  ARUBA CX PARSER
// ══════════════════════════════════════════════════════
function parseDHCP(cfg, vendor){
  const pools=[];
  if(vendor==='comware'){
    // Style A: "dhcp server ip-pool NAME" (classic Comware)
    const re=/^dhcp server ip-pool\s+(\S+)\s*\n([\s\S]*?)(?=^dhcp server ip-pool|\n#\s*\n|(?![\s\S]))/gm;
    let m;
    while((m=re.exec(cfg))!==null){
      const name=m[1], body=m[2];
      const netM=body.match(/network\s+([\d.]+)\s+mask\s+([\d.]+)/)||body.match(/network\s+([\d.]+)\/(\d+)/);
      const network=netM?(netM[2].includes('.')?netM[1]+'/'+cidrFromMask(netM[2]):netM[1]+'/'+netM[2]):'';
      const gateway=(body.match(/gateway-list\s+([\d.]+)/)||[])[1]||'';
      const dnsLine=(body.match(/dns-list\s+([^\n]+)/)||[])[1]||'';
      const dns=dnsLine.trim().split(/\s+/).filter(Boolean);
      const rangeM=body.match(/address range\s+([\d.]+)\s+([\d.]+)/);
      const range=rangeM?rangeM[1]+'-'+rangeM[2]:'';
      // 2026-07-22 對外查證官方 H3C 文件後修正：forbidden-ip 官方語法是「一個範圍一行、
      // 可重複」(forbidden-ip low-ip [high-ip])，不是單行空白/逗號分隔的位址清單。改用
      // '; ' 分隔多筆 forbidden-ip 行（每行原始「low [high]」內容以空白保留），區隔「同一
      // 範圍內的 low/high」與「不同範圍之間的界線」，供 renderComwareDHCPPool() 正確還原
      // 成多行
      const excluded=[...body.matchAll(/forbidden-ip\s+([^\n]+)/g)].map(x=>x[1].trim()).join('; ');
      const iface=(body.match(/interface\s+(\S+)/)||[])[1]||'';
      const leaseM=body.match(/expired\s+day\s+(\d+)\s+hour\s+(\d+)/)||body.match(/expired\s+day\s+(\d+)/);
      const lease=leaseM?leaseM[1]+'d'+(leaseM[2]?' '+leaseM[2]+'h':''):'';
      // 2026-07-24 對外查證官方 H3C DHCP Commands 文件後新增：bootfile-name(Option67)／
      // next-server(泛用下一台伺服器，優先於 tftp-server ip-address)／tftp-server ip-address
      // (Option150 備援)／option 42 ip-address(NTP，取第一筆)
      const bootFile=(body.match(/bootfile-name\s+(\S+)/)||[])[1]||'';
      const nextServer=(body.match(/next-server\s+([\d.]+)/)||[])[1]||(body.match(/tftp-server ip-address\s+([\d.]+)/)||[])[1]||'';
      const ntpM=body.match(/option\s+42\s+ip-address\s+([^\n]+)/);
      const ntpServer=ntpM?ntpM[1].trim().split(/\s+/)[0]:'';
      pools.push({name,network,gateway,dns,range,excluded,interface:iface,lease,bootFile,nextServer,ntpServer,type:'server'});
    }
    // Style B: "dhcp server pool NAME" block (Comware 5.x / some variants)
    const lines=cfg.split(/\r?\n/);
    let poolName='',poolLines2=[];
    const flushPool2=()=>{
      if(!poolName)return;
      const body=poolLines2.join('\n');
      const netM=body.match(/^\s+network\s+([\d.]+)\s+mask\s+([\d.]+)/m)||body.match(/^\s+network\s+([\d.]+)\/(\d+)/m);
      const network=netM?(netM[2].includes('.')?netM[1]+'/'+cidrFromMask(netM[2]):netM[1]+'/'+netM[2]):'';
      const gateway=(body.match(/^\s+gateway-list\s+([\d.]+)/m)||[])[1]||'';
      const dnsLine=(body.match(/^\s+dns-list\s+([^\n]+)/m)||[])[1]||'';
      const dns=dnsLine.trim().split(/\s+/).filter(Boolean);
      const rangeM=body.match(/^\s+address range\s+([\d.]+)\s+([\d.]+)/m);
      const range=rangeM?rangeM[1]+'-'+rangeM[2]:'';
      const leaseM=body.match(/^\s+expired\s+day\s+(\d+)/m);
      const lease=leaseM?leaseM[1]+'d':'';
      const bootFile=(body.match(/^\s+bootfile-name\s+(\S+)/m)||[])[1]||'';
      const nextServer=(body.match(/^\s+next-server\s+([\d.]+)/m)||[])[1]||(body.match(/^\s+tftp-server ip-address\s+([\d.]+)/m)||[])[1]||'';
      const ntpM2=body.match(/^\s+option\s+42\s+ip-address\s+([^\n]+)/m);
      const ntpServer=ntpM2?ntpM2[1].trim().split(/\s+/)[0]:'';
      if(!pools.find(p=>p.name===poolName))
        pools.push({name:poolName,network,gateway,dns,range,excluded:'',interface:'',lease,bootFile,nextServer,ntpServer,type:'server'});
      poolName=''; poolLines2=[];
    };
    for(const line of lines){
      const pm=line.match(/^dhcp server pool\s+(\S+)/);
      if(pm){flushPool2(); poolName=pm[1]; poolLines2=[];}
      else if(poolName){
        if(line.length>0&&!/^\s/.test(line)&&!/^!/.test(line)){flushPool2();}
        else{poolLines2.push(line);}
      }
    }
    flushPool2();
    // DHCP relay：2026-07-22 對外查證官方 H3C 文件後修正——原本假設 "dhcp relay
    // server-address" 是全域指令，實際上是巢狀在 "interface Vlan-interface X" 內
    // （搭配 "dhcp select relay" 宣告該介面走 relay 模式），並非全域範圍
    const relayIfBlocks=cfg.split(/\ninterface /);
    for(const blk of relayIfBlocks){
      const ifM=blk.match(/^(Vlan-interface\S+)/);
      if(!ifM)continue;
      const ifName=ifM[1];
      if(!/dhcp select relay/.test(blk))continue;
      // 2026-07-24 對外查證官方 H3C DHCP snooping commands 文件後新增：Option82 插入開關
      // 為 "dhcp relay information enable"（Interface view，與此 relay 區塊同層級），非全域
      const option82=/dhcp relay information enable/.test(blk);
      let mr;
      const relayRe=/dhcp relay server-address\s+([\d.]+)/g;
      while((mr=relayRe.exec(blk))!==null)
        pools.push({name:ifName+'-relay',network:'',gateway:'',dns:[],range:'',excluded:'',interface:ifName,lease:'',type:'relay',relayServer:mr[1],option82});
    }
  }else if(vendor==='dell-os10'){
    const re=/ip dhcp pool\s+(\S+)\s*\n([\s\S]*?)(?=^ip dhcp pool|^interface|^!|(?![\s\S]))/gm;
    let m;
    while((m=re.exec(cfg))!==null){
      const name=m[1],body=m[2];
      // Dell OS10 uses "subnet A.B.C.D/N" or "subnet A.B.C.D MASK"
      const subnetRaw=(body.match(/subnet\s+([^\n]+)/)||[])[1]?.trim()||'';
      const network=subnetRaw.includes('/')?subnetRaw.split(/\s/)[0]:subnetRaw;
      const gateway=(body.match(/default-router\s+([^\n]+)/)||[])[1]?.trim()||'';
      const dns=(body.match(/dns-server\s+([^\n]+)/)||[])[1]?.trim()||'';
      const lease=(body.match(/lease\s+([^\n]+)/)||[])[1]?.trim()||'';
      pools.push({name,network,gateway,dns,range:'',excluded:'',lease,interface:'',type:'server'});
    }
    // 2026-07-24 對外查證官方 Dell SmartFabric OS10 User Guide 後新增：DHCP Relay 完整缺口
    // 補齊——"ip helper-address <addr> [vrf <name>]"（Interface config，逐介面，同介面可重複多行
    // 指向不同伺服器）。Option82/TFTP-Bootfile/NTP(Option42) 官方 DHCP server commands 章節逐一
    // 比對確認查無對應指令，不臆測實作（DHCP Snooping 章節明載 Option82 需由上游 DHCP Server 自行
    // 支援，OS10 交換器本身不執行插入）
    cfg.split(/^interface\s+/m).slice(1).forEach(blk=>{
      const ifname=blk.split('\n')[0].trim();
      const helpers=[...blk.matchAll(/^\s*ip helper-address\s+(\S+)/gm)].map(x=>x[1]);
      helpers.forEach(srv=>pools.push({name:'relay:'+ifname,network:'',gateway:'',dns:'',
        range:'',excluded:'',lease:'',interface:ifname,type:'relay',relayServer:srv}));
    });
  }else if(vendor==='cisco'||vendor==='ruijie'){
    // Ruijie RGOS 官方 DHCP 命令與 Cisco IOS 同源（"ip dhcp pool NAME"／"ip helper-address"），
    // 尚無真實範例逐字驗證，先併入 cisco 分支重用同一套邏輯，信心度較低
    const re=/ip dhcp pool\s+(\S+)\s*\n([\s\S]*?)(?=^ip dhcp pool|^interface|(?![\s\S]))/gm;
    let m;
    while((m=re.exec(cfg))!==null){
      const name=m[1], body=m[2];
      const network=(body.match(/network\s+([^\n]+)/)||[])[1]||'';
      const gateway=(body.match(/default-router\s+([^\n]+)/)||[])[1]||'';
      const dns=(body.match(/dns-server\s+([^\n]+)/)||[])[1]||'';
      const excluded=(body.match(/excluded-address[^\n]+/g)||[]).map(x=>x.replace('excluded-address','').trim()).join(', ');
      const lease=(body.match(/lease\s+([^\n]+)/)||[])[1]?.trim()||'';
      // 2026-07-24 對外查證官方 Cisco IOS DHCP Configuration Guide 後新增：bootfile(Option67)／
      // next-server(泛用，優先於 option 150 ip 備援)／option 42 ip(NTP，取第一筆)
      const bootFile=(body.match(/bootfile\s+(\S+)/)||[])[1]||'';
      const nextServer=(body.match(/next-server\s+([\d.]+)/)||[])[1]||(body.match(/option\s+150\s+ip\s+([\d.]+)/)||[])[1]||'';
      const ntpM=body.match(/option\s+42\s+ip\s+([^\n]+)/);
      const ntpServer=ntpM?ntpM[1].trim().split(/\s+/)[0]:'';
      pools.push({name,network:network.trim(),gateway:gateway.trim(),dns:dns.trim(),
        range:'',excluded,lease,interface:'',bootFile,nextServer,ntpServer,type:'server'});
    }
    // ip helper-address（DHCP relay）：逐介面，Cisco 允許同一介面多行指向不同 relay 目標
    // 2026-07-24 對外查證官方 Catalyst 9300 IP Addressing Services Configuration Guide 後新增：
    // Option82 插入為全域指令 "ip dhcp snooping information option"（非逐 interface），套用到
    // 該廠牌全部 relay 條目
    const option82=/^ip dhcp snooping information option\b/m.test(cfg);
    cfg.split(/^interface\s+/m).slice(1).forEach(blk=>{
      const ifname=blk.split('\n')[0].trim();
      const helpers=[...blk.matchAll(/^\s*ip helper-address\s+(\S+)/gm)].map(x=>x[1]);
      helpers.forEach(srv=>pools.push({name:'relay:'+ifname,network:'',gateway:'',dns:'',
        range:'',excluded:'',lease:'',interface:ifname,type:'relay',relayServer:srv,option82}));
    });
  }else if(vendor==='arista'){
    // Arista EOS：僅支援 DHCP Relay（"ip helper-address"，語法與 Cisco 相同），DHCP Server（EOS 4.22.1+ 的
    // "dhcp server" 區塊，Kea backend）本體功能已於 2026-07-24 對外查證確認真實存在，但 pool 內
    // dns/tftp/ntp 子選項關鍵字查無官方逐字佐證（僅有 AVD schema 片段線索，可信度不足），維持不解析
    // 2026-07-24 對外查證官方 Arista Community KB 後新增：Option82 插入為全域指令
    // "ip dhcp relay information option"（不含任何後綴參數的裸行，與逐 interface 的
    // "...option circuit-id X" 變體字面上不同，用行尾錨點避免誤配）
    const option82=/^ip dhcp relay information option\s*$/m.test(cfg);
    cfg.split(/^interface\s+/m).slice(1).forEach(blk=>{
      const ifname=blk.split('\n')[0].trim();
      const helpers=[...blk.matchAll(/^\s*ip helper-address\s+(\S+)/gm)].map(x=>x[1]);
      helpers.forEach(srv=>pools.push({name:'relay:'+ifname,network:'',gateway:'',dns:'',
        range:'',excluded:'',lease:'',interface:ifname,type:'relay',relayServer:srv,option82}));
    });
  }else if(vendor==='nxos'){
    // 2026-07-24 對外查證官方 Cisco NX-OS Security Configuration Guide 後新增：官方文件 "Configuring
    // DHCP" 章節僅列出 Snooping／Relay Agent／DHCPv6 Smart Relay／Client 四項，完全沒有 DHCP Server
    // （位址池）章節或指令，故僅解析 Relay，不臆測 Server pool 語法。Relay 位址指令是
    // "ip dhcp relay address <ip> [use-vrf <vrf>]"（Interface config，L3/SVI，非 Cisco IOS 式的
    // ip helper-address），Option82 信任旗標為逐介面 "ip dhcp relay information trusted" 或全域
    // "ip dhcp relay information option trust"（兩者皆查證確認，任一成立即視為啟用）
    const globalTrust=/^ip dhcp relay information option trust\b/m.test(cfg);
    cfg.split(/^interface\s+/m).slice(1).forEach(blk=>{
      const ifname=blk.split('\n')[0].trim();
      const option82=globalTrust||/^\s*ip dhcp relay information trusted\b/m.test(blk);
      const helpers=[...blk.matchAll(/^\s*ip dhcp relay address\s+(\S+)/gm)].map(x=>x[1]);
      helpers.forEach(srv=>pools.push({name:'relay:'+ifname,network:'',gateway:'',dns:'',
        range:'',excluded:'',lease:'',interface:ifname,type:'relay',relayServer:srv,option82}));
    });
  }else if(vendor==='fortiswitch'){
    // 2026-07-24 對外查證官方 Fortinet FortiSwitch Administration Guide + FortiSwitch 專屬
    // Ansible 模組（fortiswitch_system_dhcp_server／fortiswitch_system_interface，直接對應
    // FortiSwitchOS API schema）後重大修正：原本假設的 "set subnet" 欄位完全不存在，真實語法
    // 是靠 interface + netmask + 巢狀 "config ip-range" 決定位址範圍，"config exclude-range"
    // 巢狀決定排除範圍；新增 ntp-server1/tftp-server/filename(bootfile)/next-server/lease-time
    // 皆為先前完全未解析的既有欄位。
    // 巢狀 config ip-range/exclude-range 自己的 next/end 若用既有簡易 regex（比對零縮排 "^end"）
    // 擷取外層 edit 區塊本體，會被巢狀子區塊自己的 next/end 提前誤判為外層收尾（因為 FortiOS
    // 巢狀縮排通常比外層 edit 深，"next" 前面的縮排比對式 [ \t]*next 不看縮排量，會被誤配），
    // 改用逐行掃描＋深度計數的 _fortiEditEntries() 正確處理巢狀邊界
    const block=(cfg.match(/^config system dhcp server\n([\s\S]*?)^end/m)||[])[1]||'';
    for(const{id,body}of _fortiEditEntries(block)){
      const gateway=(body.match(/set default-gateway\s+(\S+)/)||[])[1]||'';
      const dns=(body.match(/set dns-server1\s+(\S+)/)||[])[1]||'';
      const ifaceName=(body.match(/set interface\s+"?([^"\n]+)"?/)||[])[1]||'';
      const bootFile=(body.match(/set filename\s+"?([^"\n]+)"?/)||[])[1]||'';
      const nextServer=(body.match(/set next-server\s+(\S+)/)||[])[1]||(body.match(/set tftp-server\s+(\S+)/)||[])[1]||'';
      const ntpServer=(body.match(/set ntp-server1\s+(\S+)/)||[])[1]||'';
      const leaseM=body.match(/set lease-time\s+(\d+)/);
      const lease=leaseM?Math.floor(parseInt(leaseM[1])/3600)+'h':'';
      const ipRangeBlock=(body.match(/config ip-range\n([\s\S]*?)\n\s*end\b/)||[])[1]||'';
      const rangeM=ipRangeBlock.match(/set start-ip\s+(\S+)[\s\S]*?set end-ip\s+(\S+)/);
      const range=rangeM?rangeM[1]+'-'+rangeM[2]:'';
      const excludeBlock=(body.match(/config exclude-range\n([\s\S]*?)\n\s*end\b/)||[])[1]||'';
      const excluded=[...excludeBlock.matchAll(/set start-ip\s+(\S+)[\s\S]*?set end-ip\s+(\S+)/g)].map(e=>e[1]+'-'+e[2]).join('; ');
      pools.push({name:'Pool'+id,network:'',gateway,dns,interface:ifaceName,
        bootFile,nextServer,ntpServer,lease,range,excluded,type:'server'});
    }
    // DHCP relay：Layer3 interface（config system interface）內的 set dhcp-relay-service enable
    // + set dhcp-relay-ip（可多台，雙引號分隔）；2026-07-24 對外查證確認語法正確（先前標註未對照
    // 實機驗證，本輪查證官方文件與 Ansible 模組交叉確認一致）。Option82 為獨立旗標
    // set dhcp-relay-option82 enable，不需要先啟用 DHCP Snooping
    const sysIfBlock=(cfg.match(/^config system interface\n([\s\S]*?)^end/m)||[])[1]||'';
    for(const{id:ifname,body}of _fortiEditEntries(sysIfBlock)){
      if(!/set dhcp-relay-service\s+enable/.test(body))continue;
      const option82=/set dhcp-relay-option82\s+enable/.test(body);
      const ipsLine=(body.match(/set dhcp-relay-ip\s+([^\n]+)/)||[])[1]||'';
      const ips=[...ipsLine.matchAll(/"([^"]+)"/g)].map(x=>x[1]);
      ips.forEach(srv=>pools.push({name:'relay:'+ifname.replace(/^"|"$/g,''),network:'',gateway:'',dns:'',
        range:'',excluded:'',lease:'',interface:ifname.replace(/^"|"$/g,''),type:'relay',relayServer:srv,option82}));
    }
  }else if(vendor==='aruba'){
    // Aruba CX: "dhcp-server pool NAME" blocks + ip helper-address relay
    const re=/^dhcp-server pool\s+(\S+)\n((?:[ \t][^\n]*\n)*)/gm; let m;
    while((m=re.exec(cfg))!==null){
      const name=m[1],body=m[2];
      const network=(body.match(/address-range\s+(\S+)\s+(\S+)/)||[])[0]||
                    (body.match(/network\s+(\S+)/)||[])[1]||'';
      const gateway=(body.match(/default-router\s+(\S+)/)||body.match(/gateway\s+(\S+)/)||[])[1]||'';
      const dns=(body.match(/dns-server\s+([^\n]+)/)||[])[1]?.trim()||'';
      const lease=(body.match(/lease\s+([^\n]+)/)||[])[1]?.trim()||'';
      // 2026-07-24 對外查證官方 AOS-CX CLI Reference 後新增：
      // - range <low> <high> [prefix-len <mask>]（IP 位址範圍；AOS-CX 是「允許清單」式 pool 模型，
      //   完全沒有 exclude/excluded-address 這個指令，不新增 excluded 欄位猜測語法）
      // - bootp tftp://{ip|host}/{file}（TFTP 伺服器與開機檔名合併成單一 URL，非 Cisco 式分開兩欄，
      //   拆解成 nextServer(host)/bootFile(file) 以沿用共用渲染欄位）
      // - option 42 ip <ip...>（NTP，無專屬關鍵字，取第一筆）
      const rangeM=body.match(/range\s+([\d.]+)\s+([\d.]+)/);
      const range=rangeM?rangeM[1]+'-'+rangeM[2]:'';
      const bootpM=body.match(/bootp\s+tftp:\/\/([^\/\s]+)\/(\S+)/);
      const nextServer=bootpM?bootpM[1]:'';
      const bootFile=bootpM?bootpM[2]:'';
      const ntpM=body.match(/option\s+42\s+ip\s+([^\n]+)/);
      const ntpServer=ntpM?ntpM[1].trim().split(/\s+/)[0]:'';
      pools.push({name,network,gateway,dns,range,excluded:'',lease,interface:'',bootFile,nextServer,ntpServer,type:'server'});
    }
    // ip helper-address (DHCP relay) on SVIs
    // 2026-07-24 對外查證官方 AOS-CX CLI Reference 後新增：Option82 插入為全域指令
    // "dhcp-relay option 82 ..."（非逐 interface），套用到該廠牌全部 relay 條目
    const option82=/^dhcp-relay option 82\b/m.test(cfg);
    cfg.split(/\ninterface /).slice(1).forEach(blk=>{
      const ifname=blk.split('\n')[0].trim().replace(/(\D)\s+(\d)/g,'$1$2');
      const helpers=[...blk.matchAll(/ip helper-address\s+(\S+)/g)].map(x=>x[1]);
      helpers.forEach(srv=>pools.push({name:'relay:'+ifname,network:'',gateway:'',dns:'',
        interface:ifname,type:'relay',relayServer:srv,option82}));
    });
  }else if(vendor==='juniper'){
    pools.push(...parseJuniperDHCP(cfg));
  }else if(vendor==='alcatel'){
    // DHCP Server：2026-07-22 對外查證官方 AOS CLI Reference 後移除——原本這裡有三組
    // 各自獨立猜測的語法（Style AA "dhcp-server range/netmask" 旗標式指令、Style A
    // "-> ip dhcp pool NAME network/range/..."、Style B "dhcp server pool NAME { ... }
    // exit"），皆從未對照官方文件驗證過。查證確認真實 AOS 完全沒有 DHCP Server 的 CLI
    // 指令可用，DHCP Server 是透過上傳 ISC dhcpd 語法的 dhcpd.conf/dhcpd.cpy 檔案設定
    // （非逐行指令），三組猜測語法皆屬捏造，一併移除不臆測；產生器端（switch_config_generator
    // renderAlcatelDHCPPool()）已於同日稍早的 Style B 修復中一併停用。
    // 2026-07-24 對外查證官方 OmniSwitch CLI Reference 後新增：Option82 掛在 DHCP Snooping
    // 子系統下（"ip helper dhcp-snooping" + "ip helper dhcp-snooping option-82 data-insertion
    // enable"），官方文件明確註記與純 "ip helper address" Relay 為互斥功能（二擇一），此處僅作
    // 偵測用途、套用到解析出的全部 relay 條目，不強制檢查互斥關係
    const option82=/^ip helper dhcp-snooping\s+enable\b/m.test(cfg)&&/^ip helper dhcp-snooping option-82 data-insertion\s+enable\b/m.test(cfg);
    const rA2=/^->\s*ip interface\s+(\S+)\s+helper-address\s+([\d.]+)/gm; let ra2;
    while((ra2=rA2.exec(cfg))!==null)pools.push({name:ra2[1],network:'',range:'',gateway:'',dns:[],lease:'',excluded:'',interface:ra2[1],type:'relay',relayServer:ra2[2],option82});
    const rSM=cfg.match(/^dhcp relay server\s+([\d.]+)/m);
    if(rSM&&/^dhcp relay enable/m.test(cfg))pools.push({name:'global-relay',network:'',range:'',gateway:'',dns:[],lease:'',excluded:'',interface:'all',type:'relay',relayServer:rSM[1],option82});
    // 2026-07-22 對外查證官方 AOS CLI Reference 後修正：真實關鍵字是空白分隔的
    // "ip helper address"（address 前無連字號），與 Cisco 的 "ip helper-address" 不同，
    // 原本猜測沿用了 Cisco 命名習慣
    const gRe=/^->\s*ip helper address\s+([\d.]+)(?:\s+vlan\s+(\d+))?/gm; let gr2;
    while((gr2=gRe.exec(cfg))!==null){const vl=gr2[2]||'';pools.push({name:'global'+(vl?'-vlan'+vl:''),network:'',range:'',gateway:'',dns:[],lease:'',excluded:'',interface:vl?'vlan'+vl:'all',type:'relay',relayServer:gr2[1],option82});}
  }else if(vendor==='planet'){
    pools.push(...parsePlanetDHCP(cfg));
  }
  return pools;
}

// 2026-07-24 新增：系統層級 DNS Server 解析（非 DHCP pool 內的 dns-server 選項，是設備本身查詢
// 上游 DNS 的全域設定）。逐廠牌 branch 皆已對外查證官方文件，回傳依原始順序（多筆時視同優先序）
// 排列的 IP 字串陣列；查無官方佐證的廠牌（juniper/dell-os10/fortiswitch/brocade/alcatel/extreme/
// routeros）留待後續批次查證，本輪維持回傳空陣列，不臆測
function parseDNSServers(cfg, vendor){
  const ipTok=/^\d{1,3}(?:\.\d{1,3}){3}$/;
  if(vendor==='comware'){
    // "dns server <ip>"，System view，一行一筆，可重複多行（查證來源：H3C Layer 3 IP Services
    // Command Reference DNS Commands）
    return [...cfg.matchAll(/^dns server\s+([\d.]+)/gm)].map(m=>m[1]);
  }
  if(vendor==='cisco'||vendor==='nxos'||vendor==='arista'||vendor==='ruijie'){
    // "ip name-server [vrf <name>] <ip1> [ip2...] [priority N] [use-vrf <vrf>] [source-interface <if>]"
    // 四廠牌語法結構相同（Global config，一行可列多筆），僅選填參數不同，用 IP 格式過濾即可通用處理。
    // Ruijie 尚無真實範例逐字驗證，比照 Cisco 語系推測，信心度較低
    return [...cfg.matchAll(/^\s*ip name-server\s+([^\n]+)/gm)].flatMap(m=>
      m[1].trim().split(/\s+/).filter(tok=>ipTok.test(tok)));
  }
  if(vendor==='aruba'){
    // Aruba CX (AOS-CX)："ip dns server-address <ip> [vrf <name>]"，一行一筆，依定義順序查詢
    return [...cfg.matchAll(/^ip dns server-address\s+(\S+)/gm)].map(m=>m[1]).filter(tok=>ipTok.test(tok));
  }
  if(vendor==='procurve'){
    // ArubaOS-Switch/ProCurve："ip dns server-address priority <1-4> <ip> [oobm]"，依 priority 排序
    const rows=[...cfg.matchAll(/^ip dns server-address priority\s+(\d+)\s+(\S+)/gm)]
      .map(m=>({p:+m[1],ip:m[2]})).filter(r=>ipTok.test(r.ip));
    rows.sort((a,b)=>a.p-b.p);
    return rows.map(r=>r.ip);
  }
  if(vendor==='juniper'){
    // "system { name-server { <ip>; <ip>; } }"（此工具 Juniper 解析全面僅支援大括號階層式，
    // 不支援 set 扁平式，比照既有 junosBlock()/junosSubBlocks() 既定範圍，不擴大）
    const sysBlock=junosBlock(cfg,'system');
    if(!sysBlock)return[];
    const nsBlock=junosBlock(sysBlock,'name-server');
    if(!nsBlock)return[];
    return [...nsBlock.matchAll(/([\d.]+);/g)].map(m=>m[1]).filter(tok=>ipTok.test(tok));
  }
  if(vendor==='dell-os10'){
    // "ip name-server <ip1> [ip2] [ip3] [vrf <name>]"，Global config，一行可列多筆，最多3筆
    return [...cfg.matchAll(/^ip name-server\s+([^\n]+)/gm)].flatMap(m=>
      m[1].trim().split(/\s+/).filter(tok=>ipTok.test(tok)));
  }
  if(vendor==='brocade'){
    // Ruckus/Brocade ICX (FastIron)："ip dns server-address <ip1> [ip2] [ip3] [ip4]"，Global，最多4筆
    return [...cfg.matchAll(/^ip dns server-address\s+([^\n]+)/gm)].flatMap(m=>
      m[1].trim().split(/\s+/).filter(tok=>ipTok.test(tok)));
  }
  if(vendor==='fortiswitch'){
    // "config system dns" 全域單一區塊（非 edit <id> 多筆），set primary/set secondary 各僅一筆
    // （查證來源：FortiSwitch 專屬 Ansible 模組 fortiswitch_system_dns，直接對應 API schema）
    const block=(cfg.match(/^config system dns\n([\s\S]*?)^end/m)||[])[1]||'';
    const primary=(block.match(/set primary\s+(\S+)/)||[])[1]||'';
    const secondary=(block.match(/set secondary\s+(\S+)/)||[])[1]||'';
    return [primary,secondary].filter(tok=>ipTok.test(tok));
  }
  if(vendor==='alcatel'){
    // "ip name-server <ip1> [ip2] [ip3]"，最多3筆，無 primary/secondary 關鍵字，純位置順序決定
    // 優先權（查證來源：官方 OmniSwitch 6250/6450 CLI Reference Guide）
    return [...cfg.matchAll(/^ip name-server\s+([^\n]+)/gm)].flatMap(m=>
      m[1].trim().split(/\s+/).filter(tok=>ipTok.test(tok)));
  }
  if(vendor==='extreme'){
    // "configure dns-client add name-server <ip> [vr <vr_name>]"，逐筆新增，最多8筆，無
    // primary/secondary 區分（查證來源：官方 ExtremeXOS Command Reference Guide）
    return [...cfg.matchAll(/^configure dns-client add name-server\s+(\S+)/gm)].map(m=>m[1]).filter(tok=>ipTok.test(tok));
  }
  if(vendor==='routeros'){
    // "/ip dns\nset servers=<ip1>,<ip2> ..."（set 非 add，全域唯一設定物件；servers= 可能不是
    // set 那行的第一個參數，如 "set servers=1.1.1.1 allow-remote-requests=yes"）
    // 查證來源：官方 help.mikrotik.com「DNS」文件
    const block=(cfg.match(/^\/ip dns\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m)||[])[1]||'';
    const m=block.match(/\bservers=(\S+)/);
    return m?m[1].split(',').filter(tok=>ipTok.test(tok)):[];
  }
  return [];
}

function parseLACP(cfg, vendor){
  const lacp=[];
  if(vendor==='comware'){
    // Step 1: split into per-interface blocks (no cross-boundary matching)
    const ifaceMap={};
    cfg.split(/\ninterface /).slice(1).forEach(blk=>{
      const name=blk.split('\n')[0].trim();
      ifaceMap[name]=blk;
    });
    // Step 2: collect member mapping gid → [physicalPort]
    const membersByGid={};
    const modeByGid={};
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      const gm=blk.match(/port link-aggregation group\s+(\d+)/);
      if(gm){const mm=blk.match(/lacp\s+mode\s+(active|passive)/i);const lm=mm?(mm[1][0].toUpperCase()+mm[1].slice(1)):null;membersByGid[gm[1]]=(membersByGid[gm[1]]||[]).concat({name,lacpMode:lm});}
    });
    // Step 3: find each Bridge-Aggregation interface
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      if(!/^Bridge-Aggregation/i.test(name))return;
      const gid=name.match(/\d+/)[0];
      const mode=blk.includes('link-aggregation mode dynamic')?'Active':'Static';
      lacp.push({name,mode,members:membersByGid[gid]||[]});
    });
    lacp.sort((a,b)=>parseInt(a.name.match(/\d+/)[0])-parseInt(b.name.match(/\d+/)[0]));
  }else if(vendor==='cisco'||vendor==='arista'||vendor==='nxos'||vendor==='dell-os10'){
    // Split into per-interface blocks
    const ifaceMap={};
    cfg.split(/\ninterface /).slice(1).forEach(blk=>{
      const name=blk.split('\n')[0].trim();
      ifaceMap[name]=blk;
    });
    const membersByGid={}, modeByGid={};
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      // mode 可選：OS9 可能只寫 "channel-group 1" 無 mode 關鍵字
      const cgm=blk.match(/channel-group\s+(\d+)(?:\s+mode\s+(\S+))?/);
      if(cgm){
        const m2=cgm[2]||'';
        const lm=m2==='active'?'Active':m2==='passive'?'Passive':null;
        membersByGid[cgm[1]]=(membersByGid[cgm[1]]||[]).concat({name,lacpMode:lm});
        if(m2&&!modeByGid[cgm[1]])modeByGid[cgm[1]]=m2;
      }
    });
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      // 支援 "Port-channel 1"（OS9 有空格）及 "Port-channel1"（OS10/Cisco）
      if(!/^[Pp]ort-[Cc]hannel/i.test(name))return;
      const gidM=name.match(/\d+/);
      if(!gidM)return;
      const gid=gidM[0];
      lacp.push({name,mode:modeByGid[gid]||'Static',members:membersByGid[gid]||[]});
    });
    lacp.sort((a,b)=>parseInt(a.name.match(/\d+/)[0])-parseInt(b.name.match(/\d+/)[0]));
  }else if(vendor==='aruba'){
    // Aruba CX: "interface lag N" + member interfaces have "lag N" in body
    const ifaceMap={};
    cfg.split(/\ninterface /).slice(1).forEach(blk=>{
      const name=blk.split('\n')[0].trim();
      ifaceMap[name]=blk;
    });
    const membersByGid={}, modeByGid={};
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      // Physical port member line: "lag N"
      const lgm=blk.match(/^\s+lag\s+(\d+)\s*$/m);
      if(lgm){
        const modeM=blk.match(/lacp mode\s+(\S+)/);
        const lm=modeM?(modeM[1]==='active'?'Active':'Passive'):null;
        membersByGid[lgm[1]]=(membersByGid[lgm[1]]||[]).concat({name,lacpMode:lm});
        if(lm&&!modeByGid[lgm[1]])modeByGid[lgm[1]]=lm;
      }
    });
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      if(!/^lag\s+\d+/i.test(name))return;
      const gid=name.match(/\d+/)[0];
      const modeInBlk=blk.includes('lacp mode active')?'Active':blk.includes('lacp mode passive')?'Passive':'Static';
      lacp.push({name,mode:modeByGid[gid]||modeInBlk,members:membersByGid[gid]||[]});
    });
    lacp.sort((a,b)=>parseInt(a.name.match(/\d+/)[0])-parseInt(b.name.match(/\d+/)[0]));
}else if(vendor==='fortiswitch'){
    const trunkBlock=(cfg.match(/^config switch trunk\n([\s\S]*?)^end/m)||[])[1]||'';
    const trunkRe=/edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^[ \t]*next|^end)/gm;
    let m;
    while((m=trunkRe.exec(trunkBlock))!==null){
      const name=m[1].trim(), body=m[2];
      // "set members "port47" "port48"" — strip quotes from each token
      const membersLine=(body.match(/set members\s+(.+)/)||[])[1]||'';
      const memberNames=membersLine.match(/"([^"]+)"|(\S+)/g)
        ?.map(t=>t.replace(/"/g,''))
        .filter(Boolean)||[];
      const mode=body.includes('set mode lacp-active')?'Active':body.includes('set mode lacp-passive')?'Passive':'Static';
      const members=memberNames.map(m=>({name:m,lacpMode:mode!=='Static'?mode:null}));
      lacp.push({name,mode,members});
    }
  }else if(vendor==='ruijie'){
    // Ruijie RGOS：聚合介面稱為 AggregatePort（AP），不是 channel-group／Port-channel。
    // 成員埠在自己的 interface 區塊內用 "port-group N mode {active|passive}" 宣告
    // （查證來源：官方 RG-S2600E CLI Reference Manual），關鍵字順序與 Cisco 完全不同，
    // 不可塞進上面 cisco/arista/nxos/dell-os10 共用分支
    const ifaceMap={};
    cfg.split(/\ninterface /).slice(1).forEach(blk=>{
      const name=blk.split('\n')[0].trim();
      ifaceMap[name]=blk;
    });
    const membersByGid={}, modeByGid={};
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      const pgm=blk.match(/port-group\s+(\d+)\s+mode\s+(active|passive)/i);
      if(pgm){
        const lm=pgm[2][0].toUpperCase()+pgm[2].slice(1).toLowerCase();
        membersByGid[pgm[1]]=(membersByGid[pgm[1]]||[]).concat({name,lacpMode:lm});
        if(!modeByGid[pgm[1]])modeByGid[pgm[1]]=lm;
      }
    });
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      if(!/^AggregatePort\s*\d+/i.test(name))return;
      const gid=name.match(/\d+/)[0];
      lacp.push({name:name.replace(/\s+/g,''),mode:modeByGid[gid]||'Static',members:membersByGid[gid]||[]});
    });
    lacp.sort((a,b)=>parseInt(a.name.match(/\d+/)[0])-parseInt(b.name.match(/\d+/)[0]));
  }else if(vendor==='netgear'||vendor==='edgeswitch'){
    // Netgear M4300／Ubiquiti EdgeSwitch 同源 Broadcom ICOS，LACP 語法完全一致（EdgeSwitch
    // 官方 CLI Command Reference 確認格式與 Netgear 逐字相同，僅介面命名少一段 unit 前綴），
    // 共用同一分支。2026-08-09 對外查證官方 NETGEAR KB（kb.netgear.com/21635，逐字指令稿）
    // 修正既有方向錯誤：`addport` 是在 **LAG 自己的介面區塊內**執行，用來加入實體成員埠，
    // 非「member 埠自己宣告要加入哪個 LAG」——原先方向理解相反，導致官方範例的原始
    // unit/slot/port 位址形式（LAG 本身用 unit/slot/port 定址，如 0/13/1，非 "lag N" 別名）
    // 完全無法正確歸群，且與 Cisco 慣例（member 埠宣告 channel-group）的類比也不成立。
    // 官方指令稿範例：`interface 0/2` → `addport 1/1` → `exit`（LAG 介面 0/2 加入實體埠 1/1）。
    // 修正後：不論 LAG 自己是用 "lag N" 別名或 unit/slot/port 原始位址命名，只要該介面
    // 區塊內含 `addport` 行就視為 LAG，直接讀出成員清單；額外保留「介面名稱本身符合
    // "lag N"」的既有 fixture 相容性（即使目前尚無成員也照舊列出該 LAG，例如剛建立但尚未
    // addport 的情境）。"port-channel static" 出現時視為 Static，未出現時視為預設值 Active
    // （官方 "port lacpmode" 預設即開啟 LACP 協商）
    const ifaceMap={};
    cfg.split(/\ninterface /).slice(1).forEach(blk=>{
      const name=blk.split('\n')[0].trim();
      ifaceMap[name]=blk;
    });
    const membersByName={};
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      const addports=[...blk.matchAll(/^\s*addport\s+(\S+)\s*$/gm)].map(m=>({name:m[1],lacpMode:null}));
      if(addports.length) membersByName[name]=addports;
    });
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      const isNamedLag=/^lag\s+\d+/i.test(name);
      if(!isNamedLag&&!membersByName[name])return;
      const mode=/^\s*port-channel static\s*$/m.test(blk)?'Static':'Active';
      lacp.push({name,mode,members:membersByName[name]||[]});
    });
    lacp.sort((a,b)=>parseInt(a.name.match(/\d+/)[0])-parseInt(b.name.match(/\d+/)[0]));
  }else if(vendor==='planet'){
    // Planet SGS-6341 系列：聚合介面稱為 "port-channel N"（非 Ruijie 的
    // AggregatePort），成員埠在自己的 interface 區塊內用 "port-group N mode
    // {active|passive|on}" 宣告（on=靜態聚合，非 LACP 協商），查證來源：官方
    // SGS-6341 Series Command Guide，關鍵字結構與 Ruijie 幾乎一致，僅容器介面
    // 名稱與 on/static 選項不同
    const ifaceMap={};
    cfg.split(/\ninterface /).slice(1).forEach(blk=>{
      const name=blk.split('\n')[0].trim();
      ifaceMap[name]=blk;
    });
    const membersByGid={}, modeByGid={};
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      const pgm=blk.match(/port-group\s+(\d+)\s+mode\s+(active|passive|on)/i);
      if(pgm){
        const raw=pgm[2].toLowerCase();
        const lm=raw==='on'?null:(raw[0].toUpperCase()+raw.slice(1));
        membersByGid[pgm[1]]=(membersByGid[pgm[1]]||[]).concat({name,lacpMode:lm});
        if(!modeByGid[pgm[1]])modeByGid[pgm[1]]=raw==='on'?'Static':lm;
      }
    });
    Object.entries(ifaceMap).forEach(([name,blk])=>{
      if(!/^port-channel\s*\d+/i.test(name))return;
      const gid=name.match(/\d+/)[0];
      lacp.push({name:name.replace(/\s+/g,''),mode:modeByGid[gid]||'Static',members:membersByGid[gid]||[]});
    });
    lacp.sort((a,b)=>parseInt(a.name.match(/\d+/)[0])-parseInt(b.name.match(/\d+/)[0]));
  }
  return lacp;
}

// ══════════════════════════════════════════════════════
//  CISCO NX-OS PARSER
// ══════════════════════════════════════════════════════
// Cisco NX-OS VPC（Virtual Port Channel）：獨立頂層 `vpc domain N` 區塊 + interface 子區塊內的
// `vpc peer-link` 標記，已查證官方 Cisco Nexus 文件（Understand and Configure Nexus 9000 vPC
// with Best Practices）語法：
//   feature vpc
//   vpc domain 1
//     peer-switch
//     peer-keepalive destination 10.201.182.26
//     peer-gateway
//   interface port-channel10
//     vpc peer-link
// 資料形狀比照既有 parseAristaMlag() 的 {type,domain,peerLink,...,members} 掛在 parsed.stack，
// 兩者概念上都是「雙機互聯冗餘」而非物理堆疊，UI 沿用同一張卡片（見 renderAristaMlag()）
function parseACL(cfg, vendor){
  if(vendor==='comware') return _parseACLComware(cfg);
  if(vendor==='aruba') return _parseACLArubaCX(cfg);
  if(vendor==='juniper') return _parseACLJuniper(cfg);
  if(vendor==='extreme') return _parseACLExtreme(cfg);
  if(vendor==='fortiswitch') return _parseACLFortiSwitch(cfg);
  if(vendor==='routeros') return _parseACLRouterOS(cfg);
  if(vendor==='sonic') return _parseACLSONiC(cfg);
  if(vendor==='alcatel') return [];
  // Netgear：2026-08-17 對外查證官方 kb.netgear.com 逐字 KB 文章（IPv4 數字型 ACL／IPv6
  // 具名 ACL 皆有完整範例）後新增，見 _parseACLNetgear() 上方註解
  if(vendor==='netgear') return _parseACLNetgear(cfg);
  // ProCurve／EdgeSwitch：本專案從未真正實作這兩家的 ACL 解析（procurve.js 甚至留了一個
  // 空的 ACL 章節標題但無函式內容），查無官方 ACL 語法佐證（EdgeSwitch 見 parser 檔頭已知
  // 限制註記）；先前沒有顯式排除，會意外落入下面的 _parseACLCisco() fallback，產生「看似
  // 有解析結果、實際語法未經驗證」的假象。2026-08-17 查證 IPv6 ACL 時意外發現此缺口，比照
  // 既有 Alcatel return [] 模式明確排除，避免虛假產出
  if(vendor==='procurve'||vendor==='edgeswitch') return [];
  // Planet：官方 SGS-6341 Command Guide 已查證 numbered IP ACL 語法（100-199 標準／
  // 100-299 延伸，共用數字空間），獨立函式處理，不落入 _parseACLCisco() fallback
  // （語法結構完全不同，見 _parseACLPlanet() 開頭註解）
  if(vendor==='planet') return _parseACLPlanet(cfg);
  // NX-OS：2026-07-22 對外查證官方 Cisco NX-OS Security Configuration Guide 後新增獨立
  // 分支——先前沿用 _parseACLCisco()（IOS-XE 語法），但真實 NX-OS 語法完全不同：容器是
  // 裸 "ip access-list NAME"（沒有 standard/extended 關鍵字），規則列是「序號在最前面、
  // 無 rule/seq 關鍵字」的 "N permit|deny protocol src dst"，來源/目的位址用 CIDR 單一
  // token（如 172.18.217.82/32），非 IOS 傳統的「網段+反向遮罩」兩個 token。原本 IOS-XE
  // 語法對 NX-OS 而言完全無法解析（要求的 standard/extended 關鍵字永遠不存在）
  if(vendor==='nxos') return _parseACLNXOS(cfg);
  return _parseACLCisco(cfg);
}
// IPv6（2026-08-17 新增，對外查證官方 Cisco NX-OS Security Command Reference 確認）：
// `ipv6 access-list NAME` 容器與規則列格式（裸序號在前、無 rule/seq 關鍵字，與既有 IPv4
// 分支同款）與 IPv4 平行、獨立命名空間；介面套用關鍵字是 "ipv6 port traffic-filter"
// （與 IPv4 的 "ip access-group" 不同字面），故新增 aclType 欄位避免同名誤配對
function _parseACLNXOS(cfg){
  const acls=[];
  const aclRe=/^ip access-list\s+(\S+)\s*\n([\s\S]*?)(?=^ip access-list\s|^ipv6 access-list\s|(?![\s\S]))/gm;
  let m;
  while((m=aclRe.exec(cfg))!==null){
    const name=m[1],body=m[2];
    const rules=[];
    const rRe=/^\s*(\d+)\s+(permit|deny)\s+(.+)/gm;
    let rm;
    while((rm=rRe.exec(body))!==null){
      const parts=rm[3].trim().split(/\s+/);
      const proto=parts[0]||'ip';
      let i=1,src,dst;
      if(parts[i]==='host'){src='host '+parts[i+1];i+=2;}else{src=parts[i];i++;}
      if(parts[i]==='host'){dst='host '+parts[i+1];i+=2;}else{dst=parts[i]||'-';i++;}
      const eqIdx=parts.indexOf('eq',i);
      const dstPort=eqIdx>-1?parts[eqIdx+1]||'':'';
      rules.push({seq:rm[1],action:rm[2],protocol:proto,src:(src||'-').trim(),dst:(dst||'-').trim(),dstPort,remark:''});
    }
    acls.push({name,type:'extended',aclType:'ip',ipVersion:'v4',vendor:'nxos',rules,appliedOn:[]});
  }
  const acl6Re=/^ipv6 access-list\s+(\S+)\s*\n([\s\S]*?)(?=^ip access-list\s|^ipv6 access-list\s|(?![\s\S]))/gm;
  while((m=acl6Re.exec(cfg))!==null){
    const name=m[1],body=m[2];
    const rules=[];
    const rRe=/^\s*(\d+)\s+(permit|deny)\s+(.+)/gm;
    let rm;
    while((rm=rRe.exec(body))!==null){
      const parts=rm[3].trim().split(/\s+/);
      const proto=parts[0]||'ipv6';
      let i=1,src,dst;
      if(parts[i]==='host'){src='host '+parts[i+1];i+=2;}else{src=parts[i];i++;}
      if(parts[i]==='host'){dst='host '+parts[i+1];i+=2;}else{dst=parts[i]||'-';i++;}
      const eqIdx=parts.indexOf('eq',i);
      const dstPort=eqIdx>-1?parts[eqIdx+1]||'':'';
      rules.push({seq:rm[1],action:rm[2],protocol:proto,src:(src||'-').trim(),dst:(dst||'-').trim(),dstPort,remark:''});
    }
    acls.push({name,type:'extended',aclType:'ipv6',ipVersion:'v6',vendor:'nxos',rules,appliedOn:[]});
  }
  const ifBlocks=cfg.split(/(?=^interface\s)/m);
  for(const blk of ifBlocks){
    const ifLine=blk.match(/^interface\s+(\S.*)/m);
    if(!ifLine)continue;
    const ifName=ifLine[1].trim();
    const agRe=/^\s*ip access-group\s+(\S+)\s+(in|out)/gim; let am;
    while((am=agRe.exec(blk))!==null){
      const acl=acls.find(a=>a.name===am[1]&&a.aclType==='ip');
      if(acl)acl.appliedOn.push({interface:ifName,direction:am[2].toLowerCase()});
    }
    const ag6Re=/^\s*ipv6 port traffic-filter\s+(\S+)\s+(in|out)/gim; let am6;
    while((am6=ag6Re.exec(blk))!==null){
      const acl=acls.find(a=>a.name===am6[1]&&a.aclType==='ipv6');
      if(acl)acl.appliedOn.push({interface:ifName,direction:am6[2].toLowerCase()});
    }
  }
  return acls;
}
// MikroTik RouterOS 支援（本次新增，2026-07-19 對外查證官方 help.mikrotik.com「Filter」
// 頁確認）：`/ip firewall filter` 是 chain-based 扁平規則清單（chain=forward/input/output，
// action=accept/drop），非 Cisco 式具名 ACL 物件，故不沿用共用 {name,rules,appliedOn}
// 巢狀形狀，改用專屬扁平陣列形狀
// IPv6 支援（2026-08-17 新增，官方 help.mikrotik.com 確認 `/ipv6 firewall filter` 與
// `/ip firewall filter` 語法平行，chain 名稱如 forward/input/output 兩邊會重複使用）：
// 這不是名稱碰撞風險（規則本身無名稱），而是 family 混淆風險——若不標記版本，UI 上無法
// 分辨同一條 "chain=forward action=accept" 規則究竟是 v4 還是 v6，故每筆規則新增 family 欄位
function _parseACLRouterOS(cfg){
  const rules=[];
  function collect(re,family){
    const block=cfg.match(re);
    if(!block)return;
    block[1].split('\n').filter(l=>/^add\s/.test(l)).forEach(l=>{
      const chain=(l.match(/\bchain=(\S+)/)||[])[1]||'';
      const action=(l.match(/\baction=(\S+)/)||[])[1]||'';
      if(!chain||!action)return;
      rules.push({
        chain,action,family,
        protocol:(l.match(/\bprotocol=(\S+)/)||[])[1]||'',
        srcAddress:(l.match(/\bsrc-address=(\S+)/)||[])[1]||'',
        dstAddress:(l.match(/\bdst-address=(\S+)/)||[])[1]||'',
        dstPort:(l.match(/\bdst-port=(\S+)/)||[])[1]||'',
        inInterface:(l.match(/\bin-interface=(\S+)/)||[])[1]||'',
        comment:(l.match(/\bcomment="([^"]*)"/)||[])[1]||'',
      });
    });
  }
  collect(/^\/ip\s+firewall\s+filter\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m,'v4');
  collect(/^\/ipv6\s+firewall\s+filter\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m,'v6');
  return rules;
}
// FortiSwitch ACL 支援（2026-08-17 改用真實語法重寫）。原本是本專案自創、未對照實機驗證的
// 扁平語法（`set action deny|allow`／`set srcaddr`／`set dstaddr`），對外查證官方
// FortiSwitchOS 7.2.10 Administration Guide "Configuring an ACL policy" 後發現與真實
// 語法完全不同——是巢狀 config classifier/config action 子區塊，且原生支援獨立的 IPv6
// 分類欄位（`set src-ip6-prefix`/`set dst-ip6-prefix`，與 IPv4 的 `set src-ip-prefix`/
// `set dst-ip-prefix` 是不同欄位，非共用同一個 srcaddr/dstaddr）：
//   config switch acl ingress
//       edit <policy_ID>
//           set description <string>
//           set ingress-interface <port_name>
//           config classifier
//               set src-ip-prefix <IPv4_address> <mask>
//               set dst-ip-prefix <IPv4_address> <mask>
//               set src-ip6-prefix <IPv6_address> <prefix>
//               set dst-ip6-prefix <IPv6_address> <prefix>
//               set src-mac <MAC_address>
//               set dst-mac <MAC_address>
//               set service <service-id>
//           end
//           config action
//               set drop {enable|disable}
//           end
//       next
//   end
// 真實模型裡一個 edit 就是一條規則（match classifier + action），沒有「一個具名 ACL 底下
// 多筆規則」這種容器概念，原本用 description 分組多筆 edit 的假設本身也是臆測；本輪改為
// 每個 edit 各自視為一筆獨立 ACL（name 優先取 description，沒有則用 policy_ID）。
// `set drop enable` 才是拒絕，未設定或 disable 視為不丟棄（即比對後放行，非傳統路由器式
// 明確 permit）。本輪僅涵蓋 ingress ACL（與既有排除範圍相同），egress/prelookup 為後續候選
function _parseACLFortiSwitch(cfg){
  const acls=[];
  const block=(cfg.match(/^config switch acl ingress\n([\s\S]*?)^end/m)||[])[1]||'';
  const re=/edit\s+(\d+)\n([\s\S]*?)(?=^[ \t]*next\b|^end\b)/gm;
  let m;
  while((m=re.exec(block))!==null){
    const policyId=m[1],body=m[2];
    const name=(body.match(/set description\s+"?([^"\n]+)"?/)||[])[1]||policyId;
    const ifaceName=(body.match(/set ingress-interface\s+"?([^"\n]+)"?/)||[])[1]||'';
    const classifierBody=(body.match(/config classifier\n([\s\S]*?)\n\s*end\b/)||[])[1]||'';
    const actionBody=(body.match(/config action\n([\s\S]*?)\n\s*end\b/)||[])[1]||'';
    const srcIp4=classifierBody.match(/set src-ip-prefix\s+(\S+)\s+(\S+)/)||[];
    const dstIp4=classifierBody.match(/set dst-ip-prefix\s+(\S+)\s+(\S+)/)||[];
    const srcIp6=classifierBody.match(/set src-ip6-prefix\s+(\S+)\s+(\S+)/)||[];
    const dstIp6=classifierBody.match(/set dst-ip6-prefix\s+(\S+)\s+(\S+)/)||[];
    const srcMac=(classifierBody.match(/set src-mac\s+(\S+)/)||[])[1];
    const dstMac=(classifierBody.match(/set dst-mac\s+(\S+)/)||[])[1];
    const service=(classifierBody.match(/set service\s+"?([^"\n]+)"?/)||[])[1]||'';
    const ipVersion=(srcIp6[1]||dstIp6[1])?'v6':(srcIp4[1]||dstIp4[1])?'v4':'';
    const src=srcIp6[1]?`${srcIp6[1]}/${srcIp6[2]}`:srcIp4[1]?`${srcIp4[1]} ${srcIp4[2]}`:(srcMac||'-');
    const dst=dstIp6[1]?`${dstIp6[1]}/${dstIp6[2]}`:dstIp4[1]?`${dstIp4[1]} ${dstIp4[2]}`:(dstMac||'-');
    const dropped=/set drop\s+enable/.test(actionBody);
    acls.push({
      name,type:'extended',ipVersion,vendor:'fortiswitch',
      rules:[{seq:policyId,action:dropped?'deny':'permit',protocol:service||'ip',src,dst,dstPort:'',remark:''}],
      appliedOn:ifaceName?[{interface:ifaceName,direction:'in'}]:[]
    });
  }
  return acls;
}
// Netgear M4300 ACL 支援（2026-08-17 新增，對外查證官方 kb.netgear.com 逐字 KB 文章確認，
// 詳見 kb.netgear.com/21730「How do I configure an IPv6 ACL」＋ kb.netgear.com/21708／
// 21713／21716 系列 IPv4 ACL 文章）：
// IPv4 僅支援數字型 ACL（`access-list N permit|deny protocol src [wildcard] dst [wildcard]
// [eq port]`，規則列格式與 Cisco extended ACL 相同——network+wildcard-mask 兩 token）；
// 對外查證未能找到具名 IPv4 ACL 的容器關鍵字逐字佐證（搜尋結果僅示範數字型），比照專案
// 「查無來源不可臆測」原則不猜測具名語法，僅支援已確認的數字型。介面套用
// `ip access-group N in`。IPv6 為具名 ACL：`ipv6 access-list NAME` 進入子模式後逐行
// `permit|deny protocol src dst [eq port]`（無 access-list 前綴，與 Cisco IOS 家族同款
// 子模式語法），介面套用 `ipv6 traffic-filter NAME in`（KB21730 逐字確認）
function _parseACLNetgear(cfg){
  const acls=[];
  const tok=(parts,i)=>{
    if(parts[i]==='host')return{val:'host '+(parts[i+1]||''),next:i+2};
    if(parts[i]==='any')return{val:'any',next:i+1};
    if(parts[i+1]&&/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parts[i+1]))return{val:parts[i]+' '+parts[i+1],next:i+2};
    return{val:parts[i]||'-',next:i+1};
  };
  // 數字型 IPv4
  const numRe=/^access-list\s+(\d+)\s+(permit|deny)\s+(.*)/gm;
  const numG={};
  let m;
  while((m=numRe.exec(cfg))!==null){
    const num=m[1],action=m[2];
    const parts=m[3].trim().split(/\s+/);
    const proto=parts[0]||'ip';
    const s=tok(parts,1);
    const d=tok(parts,s.next);
    const eq=parts.indexOf('eq',d.next);
    const dstPort=eq>-1?(parts[eq+1]||''):'';
    if(!numG[num]){numG[num]={name:num,type:'extended',aclType:'ip',ipVersion:'v4',vendor:'netgear',rules:[],appliedOn:[]};acls.push(numG[num]);}
    numG[num].rules.push({seq:'',action,protocol:proto,src:s.val,dst:d.val,dstPort,remark:''});
  }
  // 具名 IPv6
  const acl6Re=/^ipv6 access-list\s+(\S+)([\s\S]*?)(?=^access-list\s|^ipv6 access-list\s|(?![\s\S]))/gm;
  while((m=acl6Re.exec(cfg))!==null){
    const name=m[1],body=m[2];
    const rules=[];
    const rRe=/^\s*(permit|deny)\s+(.+)/gm;
    let rm;
    while((rm=rRe.exec(body))!==null){
      const parts=rm[2].trim().split(/\s+/);
      const proto=parts[0]||'ipv6';
      const s=tok(parts,1);
      const d=tok(parts,s.next);
      const eq=parts.indexOf('eq',d.next);
      const dstPort=eq>-1?(parts[eq+1]||''):'';
      rules.push({seq:'',action:rm[1],protocol:proto,src:s.val,dst:d.val,dstPort,remark:''});
    }
    acls.push({name,type:'extended',aclType:'ipv6',ipVersion:'v6',vendor:'netgear',rules,appliedOn:[]});
  }
  // Interface application
  const ifBlocks=cfg.split(/(?=^interface\s+)/m);
  for(const blk of ifBlocks){
    const ifLine=blk.match(/^interface\s+(\S.*)/m);
    if(!ifLine)continue;
    const ifName=ifLine[1].trim();
    const agRe=/^\s*ip access-group\s+(\d+)\s+(in|out)/gim;
    let am;
    while((am=agRe.exec(blk))!==null){const acl=acls.find(a=>a.name===am[1]&&a.aclType==='ip');if(acl)acl.appliedOn.push({interface:ifName,direction:am[2].toLowerCase()});}
    const ag6Re=/^\s*ipv6 traffic-filter\s+(\S+)\s+(in|out)/gim;
    let am6;
    while((am6=ag6Re.exec(blk))!==null){const acl=acls.find(a=>a.name===am6[1]&&a.aclType==='ipv6');if(acl)acl.appliedOn.push({interface:ifName,direction:am6[2].toLowerCase()});}
  }
  return acls;
}
function _parseACLCisco(cfg){
  const acls=[];
  // Named ACLs
  // 修正：原本用 \Z（JS 正則不支援，等同字面 'Z' 字元）當字串結尾 fallback，
  // 若該 ACL 剛好是檔案最後一段且內容不含字母 Z，會完全解析不到；改用既有慣例 (?![\s\S])
  // 邊界同時涵蓋 ipv6 access-list，避免 IPv4 named ACL 貪婪吃到後面的 IPv6 區塊
  const aclRe=/^ip access-list\s+(standard|extended)\s+(\S+)([\s\S]*?)(?=^ip access-list\s|^ipv6 access-list\s|(?![\s\S]))/gm;
  let m;
  while((m=aclRe.exec(cfg))!==null){
    const type=m[1],name=m[2],body=m[3];
    const rules=[];
    // Dell OS10：已查證官方 SmartFabric OS10 User Guide 後新增，真實規則列帶 "seq N"
    // 字面前綴（如 "seq 10 permit ..."），非原本假想的裸數字前綴，新增可選 "seq " 關鍵字
    // 不影響 Cisco 既有裸數字/無前綴格式
    const rRe=/^\s*(?:seq\s+)?(?:(\d+)\s+)?(permit|deny)\s+(.+)/gm;
    let rm;
    // 2026-08-17 修復：原本 extended 分支對「network wildcard-mask」兩 token 位址格式
    // （如 "10.0.0.0 0.0.0.255"）只消耗 1 個 token，wildcard mask 值被誤吃成 dst，
    // "host X"/"any"/裸 token 格式不受影響。改用明確的 token 消耗 helper，依序判斷
    // host（2 token）／any（1 token）／network+wildcard-mask（下一個 token 符合點分
    // 四段格式時消耗 2 token）／裸 token（1 token，object-group 名稱等仍為已知限制不
    // 擴大處理，與修復前行為一致）
    const _ciscoAddrTok=(parts,i)=>{
      if(parts[i]==='host')return{val:'host '+(parts[i+1]||''),next:i+2};
      if(parts[i]==='any')return{val:'any',next:i+1};
      if(parts[i+1]&&/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parts[i+1]))return{val:parts[i]+' '+parts[i+1],next:i+2};
      return{val:parts[i]||'-',next:i+1};
    };
    while((rm=rRe.exec(body))!==null){
      const parts=rm[3].trim().split(/\s+/);
      let proto='ip',src='-',dst='-',dstPort='';
      if(type==='standard'){src=parts[0]==='host'?'host '+parts[1]:parts[0]+(parts[1]&&!/^(eq|gt|lt|log)/.test(parts[1])?' '+parts[1]:'');}
      else{
        proto=parts[0]||'ip';
        const s=_ciscoAddrTok(parts,1);src=s.val;
        const d=_ciscoAddrTok(parts,s.next);dst=d.val;
        const eq=parts.indexOf('eq',d.next);if(eq>-1)dstPort=parts[eq+1]||'';
      }
      rules.push({seq:rm[1]||'',action:rm[2],protocol:proto,src:src.trim(),dst:dst.trim(),dstPort,remark:''});
    }
    // remarks
    const rkRe=/^\s*remark\s+(.*)/gm;
    while((rm=rkRe.exec(body))!==null)rules.push({seq:'',action:'remark',protocol:'',src:'',dst:'',dstPort:'',remark:rm[1]});
    acls.push({name,type,aclType:'ip',ipVersion:'v4',vendor:'cisco',rules,appliedOn:[]});
  }
  // IPv6 Named ACLs（2026-08-17 新增，對外查證官方 Cisco/Arista/Dell 文件確認：`ipv6
  // access-list NAME` 容器語法與規則列格式（permit|deny protocol src dst，無 standard/
  // extended 關鍵字）在這批共用此函式的 IOS 系語系廠牌（Cisco/Arista/Dell OS10）高度一致；
  // Cisco/Arista 介面套用關鍵字是 "ipv6 traffic-filter"，Dell OS10 官方文件確認是
  // "ipv6 access-group"（與 v4 同關鍵字），Brocade/Ruijie 未能查到介面套用關鍵字逐字佐證，
  // 兩個關鍵字都嘗試比對，對不到的廠牌僅 appliedOn 留空（不影響 ACL 本身正確解析）。
  // aclType 比照既有 Aruba CX 模式（core.js 上方 _parseACLArubaCX() 參考實作）新增，
  // 讓 IPv4/IPv6 各自獨立命名空間的廠牌（Cisco/Arista/Dell）介面套用比對時不會誤配對；
  // Ruckus/Brocade FastIron 官方文件另外確認 ACL 名稱在 v4/v6 間必須全域唯一（無碰撞
  // 風險），沿用同一份 aclType 欄位不影響其正確性
  const acl6Re=/^ipv6 access-list\s+(\S+)([\s\S]*?)(?=^ip access-list\s|^ipv6 access-list\s|(?![\s\S]))/gm;
  while((m=acl6Re.exec(cfg))!==null){
    const name=m[1],body=m[2];
    const rules=[];
    const rRe=/^\s*(?:sequence\s+)?(?:(\d+)\s+)?(permit|deny)\s+(.+)/gm;
    let rm;
    while((rm=rRe.exec(body))!==null){
      const parts=rm[3].trim().split(/\s+/);
      const proto=parts[0]||'ipv6';let i=1,src,dst,dstPort='';
      if(parts[i]==='host'){src='host '+parts[i+1];i+=2;}else{src=parts[i]||'-';i++;}
      if(parts[i]==='host'){dst='host '+parts[i+1];i+=2;}else{dst=parts[i]||'-';i++;}
      const eq=parts.indexOf('eq',i);
      if(eq>-1)dstPort=parts[eq+1]||'';
      rules.push({seq:rm[1]||'',action:rm[2],protocol:proto,src:(src||'-').trim(),dst:(dst||'-').trim(),dstPort,remark:''});
    }
    const rkRe=/^\s*remark\s+(.*)/gm;
    while((rm=rkRe.exec(body))!==null)rules.push({seq:'',action:'remark',protocol:'',src:'',dst:'',dstPort:'',remark:rm[1]});
    acls.push({name,type:'extended',aclType:'ipv6',ipVersion:'v6',vendor:'cisco',rules,appliedOn:[]});
  }
  // Numbered ACLs（傳統數字型 ACL 定義上僅 IPv4，無 IPv6 等效語法）
  const numRe=/^access-list\s+(\d+)\s+(permit|deny)\s+(.*)/gm;
  const numG={};
  while((m=numRe.exec(cfg))!==null){
    const num=m[1],type=parseInt(num)<=99?'standard':'extended';
    if(!numG[num]){numG[num]={name:num,type,aclType:'ip',ipVersion:'v4',vendor:'cisco',rules:[],appliedOn:[]};acls.push(numG[num]);}
    numG[num].rules.push({seq:'',action:m[2],protocol:'ip',src:m[3].trim(),dst:'',dstPort:'',remark:''});
  }
  // Interface application
  const ifBlocks=cfg.split(/(?=^(?:interface|Interface)\s)/m);
  for(const blk of ifBlocks){
    const ifLine=blk.match(/^(?:interface|Interface)\s+(\S.*)/m);
    if(!ifLine)continue;
    const ifName=ifLine[1].trim();
    const agRe=/ip access-group\s+(\S+)\s+(in|out)/gi;
    while((m=agRe.exec(blk))!==null){const acl=acls.find(a=>a.name===m[1]&&a.aclType==='ip');if(acl)acl.appliedOn.push({interface:ifName,direction:m[2].toLowerCase()});}
    // ipv6 traffic-filter（Cisco/Arista）／ipv6 access-group（Dell OS10）：先以 aclType
    // 限定只比對 IPv6 ACL，避免萬一同名 IPv4 ACL 誤配對
    const ag6Re=/ipv6 (?:traffic-filter|access-group)\s+(\S+)\s+(in|out)/gi;
    while((m=ag6Re.exec(blk))!==null){const acl=acls.find(a=>a.name===m[1]&&a.aclType==='ipv6');if(acl)acl.appliedOn.push({interface:ifName,direction:m[2].toLowerCase()});}
  }
  return acls;
}
function _parseACLComware(cfg){
  const acls=[];
  // acl basic/advanced NUMBER [name NAME]，或真實設備更常見的傳統寫法 acl number NUMBER
  // （含 IPv6 版本 acl ipv6 number NUMBER）——原本只認得 basic/advanced 這組較新的關鍵字
  // 寫法，真實 Comware 匯出的設定檔幾乎都是用 "acl number" 這個傳統寫法，導致完全解析
  // 不到任何 ACL（唯讀稽核／使用者回報發現的既有 bug）。"acl number" 沒有關鍵字區分
  // basic/advanced，比照官方慣例依號碼區間判斷（2000-2999 basic／其餘 advanced）
  // 同一類 \Z 字串結尾 fallback bug 修正，見上方 _parseACLCisco 註解
  const aclRe=/^acl\s+(?:(basic|advanced)\s+(\d+)|(?:ipv6\s+)?number\s+(\d+))(?:\s+name\s+(\S+))?\s*\n([\s\S]*?)(?=^acl\s|\n#\n|(?![\s\S]))/gm;
  let m;
  while((m=aclRe.exec(cfg))!==null){
    const num=m[2]||m[3];
    const typeName=m[1]||(parseInt(num)<3000?'basic':'advanced');
    const alias=m[4]||null,body=m[5];
    // ipVersion（2026-08-13 新增，使用者提供真實 HPE 5720 去識別化設定檔驗證發現：Comware
    // 的 IPv4 ACL 與 IPv6 ACL 是各自獨立的號碼空間，同一號碼可以同時是一條 IPv4 ACL 與一條
    // IPv6 ACL——真實檔案就有 "acl number 2000"（IPv4）與 "acl ipv6 number 2000"（IPv6）並存
    // 的案例。原本 name 只存號碼，兩者會撞名；依 header 是否含 ipv6 關鍵字判斷，不依賴號碼
    // 區間猜測（IPv6 basic 與 IPv4 basic 官方文件確認共用同一段 2000-2999 號碼區間）
    const ipVersion=/^acl\s+ipv6\s+/.test(m[0])?'v6':'v4';
    const rules=[];
    // 已查證真實 Comware 匯出檔後修正兩處既有 bug：
    // (1) basic ACL 規則列（如 "rule 5 permit source X Y logging"）動作後面接的是
    //     "source"/"logging" 等關鍵字而非協定名稱，但原本的協定擷取正則有 \S+ 萬用
    //     fallback，會誤把 "source" 這個字面關鍵字吞成協定名稱，導致後面 source
    //     子句因為關鍵字已被吃掉而完全比對不到、src 欄位顯示為 '-'；改用負向前瞻
    //     排除這些已知非協定關鍵字，只有 advanced ACL 真的接協定名稱時才會被擷取。
    // (2) source/destination 子句真實語法是「網段 + 反向遮罩」兩個 token（如
    //     "203.64.78.0 0.0.0.255"），原本只抓第一個 token，遮罩資訊整段遺失。
    const rRe=/^\s*rule\s+(\d+)\s+(permit|deny)(?:\s+(ip|tcp|udp|icmp|gre|ospf|(?!source\b|destination\b|logging\b|fragment\b|time-range\b|vpn-instance\b)\S+))?([^#\n]*)/gm;
    let rm;
    while((rm=rRe.exec(body))!==null){
      const proto=rm[3]||(typeName==='basic'?'ip':'ip');
      const rest=rm[4].trim();
      // 第二個可選 token 只在「不是已知修飾關鍵字／不是下一個子句關鍵字」時才視為
      // 反向遮罩一併擷取，避免（a）IPv6 ACL（位址本身即為單一 CIDR token，無反向
      // 遮罩）誤把後面的 "logging" 吞進 src/dst 欄位；（b）同一行 source+destination
      // 皆有時（如 switch_config_generator 產生的設定），src 的遮罩擷取誤把後面的
      // "destination" 子句吞掉
      const KW=/logging\b|fragment\b|time-range\b|vpn-instance\b|source\b|destination\b/;
      const srcM=rest.match(new RegExp('source\\s+(any|\\S+(?:\\s+(?!'+KW.source+')\\S+)?)'));
      const dstM=rest.match(new RegExp('destination\\s+(any|\\S+(?:\\s+(?!'+KW.source+')\\S+)?)'));
      const portM=rest.match(/destination-port\s+(?:eq|range|gt|lt)\s+(\S+)/);
      rules.push({seq:rm[1],action:rm[2],protocol:proto,src:srcM?srcM[1]:'-',dst:dstM?dstM[1]:'-',dstPort:portM?portM[1]:'',remark:''});
    }
    acls.push({name:alias||num,type:typeName==='basic'?'basic':'advanced',ipVersion,vendor:'comware',rules,appliedOn:[]});
  }
  // Interface packet-filter：裸 `packet-filter NUMBER inbound/outbound` 官方語法只套用
  // IPv4（IPv6 有獨立的 `packet-filter ipv6 NUMBER` 指令，本輪查無真實範例不猜測支援），
  // 故比對時限定 ipVersion==='v4'，避免同號碼 IPv6 ACL 造成誤配對
  const ifBlocks=cfg.split(/(?=^(?:interface|Interface)\s)/m);
  for(const blk of ifBlocks){
    const ifLine=blk.match(/^(?:interface|Interface)\s+(\S.*)/m);
    if(!ifLine)continue;
    const ifName=ifLine[1].trim();
    const pfRe=/packet-filter\s+(\S+)\s+(inbound|outbound)/gi;
    let pm;
    while((pm=pfRe.exec(blk))!==null){const acl=acls.find(a=>a.name===pm[1]&&a.ipVersion==='v4');if(acl)acl.appliedOn.push({interface:ifName,direction:pm[2].startsWith('in')?'in':'out'});}
  }
  return acls;
}
function _parseACLArubaCX(cfg){
  const acls=[];
  // 同一類 \Z 字串結尾 fallback bug 修正，見上方 _parseACLCisco 註解
  const aclRe=/^access-list\s+(ip|ipv6|mac)\s+(\S+)([\s\S]*?)(?=^access-list\s|^interface\s|(?![\s\S]))/gm;
  let m;
  while((m=aclRe.exec(cfg))!==null){
    // 命名空間碰撞修復（2026-08-13 十二續新增）：官方 AOS-CX 文件確認 ACL 有 ip／ipv6／mac
    // 三個獨立命名空間，同一 ID 可在三者間重複使用；原本第一個捕獲群組（型別）被丟棄，
    // 完全不記錄是哪一種命名空間。aclType 保留原始三值供下方比對用，ipVersion 映射給
    // renderACL() 既有的廠牌無關 IPv6 徽章判斷式沿用（v6/v4/''，比照 Comware 既有慣例）
    const aclType=m[1],name=m[2],body=m[3];
    const ipVersion=aclType==='ipv6'?'v6':aclType==='ip'?'v4':'';
    const rules=[];
    const rRe=/^\s+(\d+)\s+(permit|deny)\s+(.+)/gm;
    let rm;
    while((rm=rRe.exec(body))!==null){
      const parts=rm[3].trim().split(/\s+/);
      rules.push({seq:rm[1],action:rm[2],protocol:parts[0]||'any',src:parts[1]||'-',dst:parts[2]||'-',dstPort:'',remark:''});
    }
    acls.push({name,type:'extended',aclType,ipVersion,vendor:'aruba-cx',rules,appliedOn:[]});
  }
  // Interface apply
  const ifBlocks=cfg.split(/(?=^interface\s)/m);
  for(const blk of ifBlocks){
    const ifLine=blk.match(/^interface\s+(\S.*)/m);
    if(!ifLine)continue;
    const ifName=ifLine[1].trim();
    // 命名空間碰撞修復：原本 (?:ip|ipv6|mac) 是非捕獲群組，套用比對時完全沒有型別過濾，
    // apply access-list ipv6 X in 可能誤套用到同名的 IPv4/MAC ACL；改捕獲型別並比對 aclType
    const apRe=/apply access-list\s+(ip|ipv6|mac)\s+(\S+)\s+(in|out)/gi;
    let am;
    while((am=apRe.exec(blk))!==null){
      const wantType=am[1].toLowerCase();
      const acl=acls.find(a=>a.name===am[2]&&a.aclType===wantType);
      if(acl)acl.appliedOn.push({interface:ifName,direction:am[3].toLowerCase()});
    }
  }
  return acls;
}
function _parseACLJuniper(cfg){
  const acls=[];
  // 命名空間碰撞修復（2026-08-13 十二續新增）：Junos firewall filter 依 family inet／
  // family inet6 階層分別宣告，同名 filter 可分別存在於兩個 family 下；原本 filterNames
  // 只收集純名稱（Set），termRe 擷取規則時同樣不分 family 全文件比對，導致兩個同名 filter
  // 的規則內容被直接合併進同一個 ACL 物件（比命名衝突更嚴重，規則本身被污染）。改用
  // family+name 複合鍵區分（family 原本是非捕獲群組，改成捕獲群組）
  const filterKeys=[]; const seenKeys={};
  const fnRe=/set firewall (family \S+ )?filter\s+(\S+)\s+term\s+/g;
  let m;
  while((m=fnRe.exec(cfg))!==null){
    const family=m[1]?m[1].trim():'';
    const key=family+' '+m[2];
    if(!seenKeys[key]){seenKeys[key]=1;filterKeys.push({family,name:m[2]});}
  }
  for(const{family,name:fname}of filterKeys){
    const rules=[];
    // family 前綴限定 termRe 只比對同一個 family 下的行，family 為空字串（未宣告）時
    // 前綴同樣為空，比照原本「未宣告 family」語意獨立成一個 bucket，不會誤吃有宣告
    // family 的行（因為那些行 "firewall " 後面緊接的是 "family X"，不是 "filter"）
    const famPrefix=family?family.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\s+':'';
    const termRe=new RegExp('set firewall '+famPrefix+'filter\\s+'+fname.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\s+term\\s+(\\S+)\\s+(.*?)$','gm');
    const terms={};
    let tm;
    while((tm=termRe.exec(cfg))!==null){
      const t=tm[1];
      if(!terms[t])terms[t]={from:[],then:[]};
      // 2026-07-27 對外查證修正：原本的 `.includes(' from ')`/`.includes(' then ')` 要求
      // 子字串前面要有空格，但 tm[2] 擷取到的內容本身就是從 "from"/"then" 開頭（沒有
      // 前導空格），實機常見的逐行 "set ... term T from ...;"／"set ... term T then ...;"
      // 格式永遠不會命中，導致 rules 恆為空陣列；改用開頭比對
      if(/^from\b/.test(tm[2]))terms[t].from.push(tm[2]);
      if(/^then\b/.test(tm[2]))terms[t].then.push(tm[2]);
    }
    for(const[term,body]of Object.entries(terms)){
      const action=body.then.join(' ').includes('accept')?'permit':'deny';
      const src=(body.from.join(' ').match(/source-address\s+(\S+)/)||[])[1]||'-';
      const dst=(body.from.join(' ').match(/destination-address\s+(\S+)/)||[])[1]||'-';
      rules.push({seq:term,action,protocol:'any',src,dst,dstPort:'',remark:''});
    }
    const famName=family.replace(/^family\s+/,'');
    const ipVersion=famName==='inet6'?'v6':famName==='inet'?'v4':'';
    if(rules.length)acls.push({name:fname,type:'extended',ipVersion,vendor:'juniper',rules,appliedOn:[]});
  }
  // Interface filter：補上捕獲 family，套用比對時加上 ipVersion 條件，避免誤套到另一個
  // family 同名 filter
  const apRe=/set interfaces\s+(\S+)\s+(?:unit \d+ )?family\s+(\S+)\s+filter\s+(input|output)\s+(\S+)/g;
  while((m=apRe.exec(cfg))!==null){
    const fam=m[2];
    const wantVersion=fam==='inet6'?'v6':fam==='inet'?'v4':'';
    // fallback：filter 定義未顯式宣告 family（最常見情況，如 switch_config_generator
    // 產生的 filter）時 ipVersion 為空字串，但介面套用指令永遠顯式宣告 family，精準比對
    // 永遠對不上；找不到精準符合的才退而求其次比對未宣告 family 的同名 filter，2026-08-13
    // 命名碰撞修復（兩個同名 filter 分屬不同 family 時精準比對優先）不受影響
    const acl=acls.find(a=>a.name===m[4]&&a.ipVersion===wantVersion) || acls.find(a=>a.name===m[4]&&a.ipVersion==='');
    if(acl)acl.appliedOn.push({interface:m[1],direction:m[3]==='input'?'in':'out'});
  }
  return acls;
}
function _parseACLExtreme(cfg){
  // 已查證官方 ExtremeXOS Command Reference／社群範例（analysisman.com）後修正：
  // 真實語法是 Dynamic ACL Rule，非原本假想的裸字動作語法（真機不存在）：
  //   create access-list NAME "conditions" "action"（conditions 為分號分隔 if 短句，
  //   action 同樣以雙引號包裹，非裸字 permit|deny）
  //   configure access-list add NAME [first|last|after X|before X] [ports LIST|vlan NAME|any] {ingress|egress}
  // 原本套用正則也漏比對 "add" 關鍵字，會誤把 "add" 當成 ACL 名稱。
  const acls=[];
  let m;
  const aclRe=/create access-list\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"/gi;
  while((m=aclRe.exec(cfg))!==null){
    const name=m[1],conditions=m[2]+';',actionRaw=m[3];
    const action=/deny/i.test(actionRaw)?'deny':'permit';
    const protoM=/protocol\s+([^;]+);/i.exec(conditions);
    const srcM=/source-address\s+([^;]+);/i.exec(conditions);
    const dstM=/destination-address\s+([^;]+);/i.exec(conditions);
    const dstPortM=/destination-port\s+([^;]+);/i.exec(conditions);
    acls.push({name,type:'extended',vendor:'extreme',rules:[{seq:'1',action,protocol:protoM?protoM[1].trim():'any',src:srcM?srcM[1].trim():'any',dst:dstM?dstM[1].trim():'any',dstPort:dstPortM?dstPortM[1].trim():'',remark:''}],appliedOn:[]});
  }
  const apRe=/configure access-list add\s+(\S+)(?:\s+(?:first|last|after\s+\S+|before\s+\S+))?\s+(?:ports\s+(\S+)|vlan\s+"?([^"\s]+)"?|any)(?:\s+(ingress|egress))?/gi;
  while((m=apRe.exec(cfg))!==null){
    const acl=acls.find(a=>a.name===m[1]);
    if(acl)acl.appliedOn.push({interface:m[2]?m[2]:(m[3]?'vlan '+m[3]:'any'),direction:m[4]==='egress'?'out':'in'});
  }
  return acls;
}

function parseSecurity(cfg, vendor){
  // SONiC（2026-08-08 新增）：整份設定檔是 JSON，與下方逐行正則機制完全不相容，獨立分流；
  // 與 ACL 同一種「統一 dispatcher」模式，switch_config_generator 匯入既有設定檔直接呼叫
  // fns.parseSecurity(text,vendor)，故必須在此處也能獨立正確派送（比照 parseSTP() 的 sonic
  // 分流寫法），不能只靠 parseAny() 的排除清單
  if(vendor==='sonic')return _parseSecuritySONiC(cfg);
  // FortiSwitch 原本完全沒有支援（generic ifRe 只認 "interface X" 區塊語法，FortiSwitch
  // 用 "config switch interface / edit X" 區塊，永遠比對不到）；本次新增獨立分支
  if(vendor==='fortiswitch') return _parseSecurityFortiSwitch(cfg);
  // Brocade/Ruckus ICX 原本完全沒有支援：generic ifRe 底下比對的是 hyphenated
  // "port-security" 單行寫法（其餘廠牌慣用），但官方 FastIron Security Configuration
  // Guide 確認 802.1X 是全域 authentication 子模式內逐 port 宣告（`dot1x enable
  // ethernet X`／`dot1x port-control auto ethernet X`，非巢狀進 interface 區塊），
  // MAC port-security 則是逐 interface `interface X` → `port security`（兩個字、無
  // 連字號）進入子模式後才有 `maximum N`／`age N`／`violation X`，兩者語法皆與其餘
  // 廠牌完全不同，本次新增獨立分支
  if(vendor==='brocade') return _parseSecurityBrocade(cfg);
  // ExtremeXOS 原本完全沒有支援：generic ifRe 只認 "interface X" 區塊語法，EXOS 完全
  // 沒有 interface 區塊，永遠比對不到。2026-07-19 對外查證官方 ExtremeXOS Command
  // Reference/User Guide 確認 802.1X／MAC-based 認證統一由 NetLogin 子系統管理：全域
  // "enable netlogin dot1x"/"enable netlogin mac" 啟用子系統，逐 port 生效位置是
  // "enable netlogin ports PORT_LIST dot1x mac"（可複合多個方法關鍵字），guest vlan
  // 為全域 "configure netlogin vlan NAME"。本次新增獨立分支
  if(vendor==='extreme') return _parseSecurityExtreme(cfg);
  // MikroTik RouterOS 原本完全沒有支援：generic ifRe 只認 "interface X" 區塊語法，
  // RouterOS 完全沒有這種區塊。2026-07-19 對外查證官方 help.mikrotik.com「Dot1X」頁
  // 確認 802.1X 是逐 port 獨立宣告 `/interface dot1x server add interface=PORT`（無
  // 巢狀子模式）。MAC-based port-security 未查得對應官方語法（RouterOS 交換器晶片走
  // bridge/switch chip 層級功能，非傳統 port-security 指令），本次不猜測實作，僅做
  // 802.1X，maxMac/violation/guestVlan 維持 '-'
  if(vendor==='routeros') return _parseSecurityRouterOS(cfg);
  // Aruba CX (AOS-CX) 原本落入下面的通用 Cisco-style loop（假設「進入 interface 區塊
  // 後執行 dot1x pae authenticator」），2026-07-20 對外查證官方 HPE Aruba Networking
  // AOS-CX CLI Reference 後發現完全是錯誤結構：802.1X／MAC 認證真實語法是全域指令＋
  // interface 參數 "aaa authentication port-access dot1x authenticator enable
  // interface PORT"／"aaa authentication port-access mac-auth enable interface PORT"，
  // 本次新增獨立分支。下面原本 result.length===0 時的 "aruba" fallback（aaa port-access
  // authenticator PORT client-limit/guest-vlan）其實是 ArubaOS-Switch/ProCurve
  // （procurve 廠牌）語法，錯用在 aruba(CX) 分支上，一併移除
  if(vendor==='aruba') return _parseSecurityArubaCX(cfg);
  // Planet SGS-6341 系列：802.1X 用 "dot1x port-control auto"（generic fallback loop
  // 本來就認得這個關鍵字，但 MAC port-security 用 "switchport mac-address dynamic
  // maximum"／"switchport mac-address violation"，與其餘廠牌慣用的
  // "port-security"/"mac-learn limit" 關鍵字完全不同，generic fallback 抓不到，
  // 故新增獨立分支
  if(vendor==='planet') return _parseSecurityPlanet(cfg);
  const result=[];
  // 修正：\Z 在 JS 正則不支援（同一類 bug，見 _parseACLCisco 註解），改用 (?![\s\S])
  const ifRe=/^(?:interface|Interface)\s+(\S.*?)\s*$([\s\S]*?)(?=^(?:interface|Interface)\s|(?![\s\S]))/gm;
  let m;
  while((m=ifRe.exec(cfg))!==null){
    const port=m[1].trim(), body=m[2]||'';
    let dot1x='-', portSec=false, maxMac='-', violation='-', guestVlan='-';
    if(/dot1x\s+pae\s+authenticator/i.test(body)) dot1x='auth';
    else if(/dot1x\s+pae\s+supplicant/i.test(body)) dot1x='supp';
    else if(/^\s+dot1x\b/m.test(body)&&vendor==='comware') dot1x='auth';
    // Dell OS10：已查證官方 SmartFabric OS10 User Guide 後新增，真實最小可用設定是
    // "dot1x port-control auto"，不一定會有 pae authenticator 這行（該關鍵字本身
    // 也是真實 Cisco 語法，故此判斷式對其他廠牌無害，純新增 alternative）
    else if(/dot1x\s+port-control\s+auto/i.test(body)) dot1x='auth';
    if(/port-security/i.test(body)||/port-security\s+enable/i.test(body)) portSec=true;
    // Dell OS10：真實 port-security 語法是巢狀 "switchport port-security" 子模式，
    // maximum/violation 欄位關鍵字是 "mac-learn limit N"/"mac-learn limit violation X"
    // （已查證修正，非原本假想的攤平 Cisco "port-security maximum/violation" 寫法）；
    // 因子模式內容已包含在上層 interface 區塊擷取出的 body 內，不需另外切巢狀邊界
    const mm=/port-security\s+(?:maximum|max-mac-count)\s+(\d+)/i.exec(body)||/mac-learn limit\s+(\d+)/i.exec(body);
    if(mm) maxMac=parseInt(mm[1]);
    // Comware：真實關鍵字是 "port-security intrusion-mode {blockmac|disableport|
    // disableport-temporarily}"，2026-07-22 對外查證官方文件後新增（原本共用的
    // "port-security violation X" 是 Cisco 語法，Comware 從未支援）
    const vm=/port-security\s+intrusion-mode\s+(\S+)/i.exec(body)||/port-security\s+violation\s+(\S+)/i.exec(body)||/mac-learn limit violation\s+(\S+)/i.exec(body);
    if(vm) violation=vm[1].toLowerCase();
    const gm=/dot1x\s+guest-vlan\s+(\S+)/i.exec(body)||/aaa\s+port-access\s+\S+\s+guest-vlan\s+(\S+)/i.exec(body);
    if(gm) guestVlan=gm[1];
    if(dot1x!=='-'||portSec) result.push({port,dot1x,portSec,maxMac,violation,guestVlan});
  }
  return result;
}
// Aruba CX (AOS-CX) 支援：已查證官方 HPE Aruba Networking AOS-CX CLI Reference 後新增
// ——802.1X／MAC 認證是全域指令＋interface 參數（非進入 interface 區塊後執行子指令）；
// port-security client-limit 比照同一個 "port-access" 指令家族類推同樣的全域+interface
// 參數風格（精確巢狀寫法未能取得完整官方逐字範例，已知限制）；guest-vlan 查無對應
// AOS-CX 語法，固定回傳 '-'（已知限制）
function _parseSecurityArubaCX(cfg){
  const result={};
  const get=port=>{if(!result[port])result[port]={port,dot1x:'-',portSec:false,maxMac:'-',violation:'-',guestVlan:'-'};return result[port];};
  let m;
  const dotRe=/^aaa authentication port-access dot1x authenticator enable interface\s+(\S+)/gim;
  while((m=dotRe.exec(cfg))!==null) get(m[1]).dot1x='auth';
  const macRe=/^aaa authentication port-access mac-auth enable interface\s+(\S+)/gim;
  while((m=macRe.exec(cfg))!==null) get(m[1]).portSec=true;
  const climRe=/^port-access port-security client-limit\s+(\d+)\s+interface\s+(\S+)/gim;
  while((m=climRe.exec(cfg))!==null) get(m[2]).maxMac=parseInt(m[1]);
  return Object.values(result);
}
// FortiSwitch 支援：已查證官方 FortiSwitchOS Administration Guide（standalone mode，
// non-FortiLink）後修正——真實語法是巢狀 "config switch interface / edit PORT /
// config port-security / set ... / end / end"，port-security-mode 為列舉值
// （none/802.1X/802.1X-mac-based）而非原本假想的布林開關；guest-vlan 為
// "set guest-vlan enable"+獨立 "set guest-vlanid N" 兩行，非原本假想的單一
// port-security-guest-vlan 欄位。maxMac/violation 真實 FortiSwitch 無對應概念，
// 固定回傳 '-'（已知限制，沿用共用形狀不擴充 schema）
function _parseSecurityFortiSwitch(cfg){
  const result=[];
  const block=(cfg.match(/^config switch interface\n([\s\S]*?)^end/m)||[])[1]||'';
  const re=/edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^\s+next\b|^end\b)/gm;
  let m;
  while((m=re.exec(block))!==null){
    const port=m[1].trim(), body=m[2];
    const psM=/config port-security\n([\s\S]*?)^\s+end\b/m.exec(body);
    const psBody=psM?psM[1]:'';
    let dot1x='-', portSec=false, maxMac='-', violation='-', guestVlan='-';
    const modeM=/set port-security-mode\s+(none|802\.1X-mac-based|802\.1X)/i.exec(psBody);
    if(modeM){
      const mode=modeM[1].toLowerCase();
      if(mode==='802.1x'){dot1x='auth';}
      else if(mode==='802.1x-mac-based'){dot1x='auth';portSec=true;}
    }
    if(/set guest-vlan\s+enable/i.test(psBody)){
      const gvidM=/set guest-vlanid\s+(\S+)/i.exec(psBody);
      if(gvidM)guestVlan=gvidM[1];
    }
    if(dot1x!=='-'||portSec)result.push({port,dot1x,portSec,maxMac,violation,guestVlan});
  }
  return result;
}
// Brocade/Ruckus ICX 支援（本次新增）：802.1X 逐 port 啟用只支援 `dot1x enable
// ethernet X` 明確帶 port 參數的寫法（`dot1x enable`/`dot1x enable all` 這種套用到
// 全部 interface 的全域寫法因無對應單一 port，本次暫不處理）；MAC port-security 為
// 逐 interface 巢狀 `port security` 子模式
function _parseSecurityBrocade(cfg){
  const result=[];
  const authBlock=(cfg.match(/^authentication\s*\r?\n((?:[ \t][^\n]*\n)*)/m)||[])[1]||'';
  const dot1xPorts=new Map();
  let am;
  const enRe=/^\s+dot1x enable\s+ethernet\s+(\S+)/gm;
  while((am=enRe.exec(authBlock))!==null) dot1xPorts.set(am[1],{dot1x:'auth',guestVlan:'-'});
  // 2026-07-22 對外查證官方 FastIron Security Configuration Guide 後修正：
  // dot1x guest-vlan 是全域指令（authentication 區塊內裸 "dot1x guest-vlan ID"，
  // 無 ethernet PORT、無 vlan 關鍵字），非原本誤植的逐 port 語法；FastIron 只有一個
  // 全域 guest VLAN，故套用到所有已啟用 dot1x 的 port
  const gvM=authBlock.match(/^\s+dot1x guest-vlan\s+(\S+)/m);
  if(gvM)dot1xPorts.forEach(v=>{v.guestVlan=gvM[1];});
  dot1xPorts.forEach((v,port)=>result.push({port:'ethernet '+port,dot1x:v.dot1x,portSec:false,maxMac:'-',violation:'-',guestVlan:v.guestVlan}));

  const ifBlocks=cfg.split(/^(?=interface\s)/m);
  for(const blk of ifBlocks){
    const veM=blk.match(/^interface\s+ve\s+(\d+)/i);
    const ethM=blk.match(/^interface\s+(?:e(?:the(?:rnet)?)?\s+)?([\d][^\s]*)/i);
    let port='';
    if(veM)port='ve '+veM[1];
    else if(ethM)port='ethernet '+ethM[1];
    if(!port)continue;
    if(!/^\s+port security\s*$/m.test(blk))continue;
    const maxM=blk.match(/^\s+maximum\s+(\d+)/m);
    const violM=blk.match(/^\s+violation\s+(\S+)/m);
    const maxMac=maxM?parseInt(maxM[1]):'-';
    const violation=violM?violM[1].toLowerCase():'-';
    const existing=result.find(r=>r.port===port);
    if(existing){existing.portSec=true;existing.maxMac=maxMac;existing.violation=violation;}
    else result.push({port,dot1x:'-',portSec:true,maxMac,violation,guestVlan:'-'});
  }
  return result;
}
// ExtremeXOS NetLogin 支援（本次新增，2026-07-19 對外查證）：MAC-based 認證
// ("enable netlogin ... mac") 對應到共用形狀的 portSec 欄位，是「MAC-based 認證≒
// MAC port-security」的功能近似對應，非逐字對應——EXOS 無 Brocade 式 maximum/age/
// violation 概念，這三個欄位維持 '-'。guest vlan 是全域設定（非逐 port），映射到每筆
// 記錄的 guestVlan 欄位。
function _parseSecurityExtreme(cfg){
  const result=[];
  const vlanM=cfg.match(/^configure netlogin vlan\s+"?([^"\n]+?)"?\s*$/m);
  const guestVlan=vlanM?vlanM[1]:'-';
  const portRe=/^enable netlogin ports\s+([^\n]+)$/gm;
  let m;
  while((m=portRe.exec(cfg))!==null){
    const rest=m[1].trim();
    const methods=[];
    const methodRe=/\b(dot1x|mac|web-based)\b/g;
    let mm;
    while((mm=methodRe.exec(rest))!==null) methods.push(mm[1]);
    if(!methods.length) continue;
    const portsPart=rest.replace(/\b(dot1x|mac|web-based)\b/g,'').replace(/,\s*$/,'').trim();
    portsPart.split(',').map(s=>s.trim()).filter(Boolean).forEach(port=>{
      result.push({
        port,
        dot1x: methods.includes('dot1x')?'auth':'-',
        portSec: methods.includes('mac'),
        maxMac:'-', violation:'-', guestVlan
      });
    });
  }
  return result;
}
// MikroTik RouterOS 支援（本次新增，2026-07-19 對外查證）：`/interface dot1x server
// add interface=PORT` 逐 port 獨立宣告，無巢狀子模式；MAC port-security 已知限制
// （查無官方對應語法），對應欄位維持 '-'／false
function _parseSecurityRouterOS(cfg){
  const result=[];
  const block=cfg.match(/^\/interface\s+dot1x\s+server\s*\n([\s\S]*?)(?=^\/|(?![\s\S]))/m);
  if(!block)return result;
  block[1].split('\n').filter(l=>/^add\s/.test(l)).forEach(l=>{
    const port=(l.match(/\binterface=(\S+)/)||[])[1];
    if(port)result.push({port,dot1x:'auth',portSec:false,maxMac:'-',violation:'-',guestVlan:'-'});
  });
  return result;
}
function parseQoS(cfg, vendor){
  const result=[];
  if(vendor==='comware'){
    // 同一類 \Z 字串結尾 fallback bug 修正（見 _parseACLCisco 註解），QoS 若剛好是
    // 檔案最後一段就完全解析不到。2026-07-22 對外查證官方 H3C 文件後修正容器關鍵字：
    // 真實語法是 `qos policy NAME`，`traffic policy` 從未在任何官方文件出現過
    const tpRe=/^qos\s+policy\s+(\S+)([\s\S]*?)(?=^qos\s+policy\s+|(?![\s\S]))/gm;
    let m;
    while((m=tpRe.exec(cfg))!==null){
      const pol=m[1], body=m[2]||'';
      const clsRe=/classifier\s+(\S+)\s+behavior\s+(\S+)/g;
      let cm;
      while((cm=clsRe.exec(body))!==null)
        result.push({policy:pol,cls:cm[1],behavior:cm[2],matchType:'-',matchValue:'-',action:'-',rate:'-',burst:'-'});
    }
  } else {
    // Arista EOS：已查證官方 EOS User Manual 後新增，真實標頭多一段可選的
    // "type quality-of-service"（純新增 alternative，開頭與收尾 lookahead 皆須同步
    // 容許，否則 Arista 格式的下一個 policy-map 邊界會判斷錯誤）
    const pmRe=/^policy-map(?:\s+type\s+quality-of-service)?\s+(\S+)([\s\S]*?)(?=^policy-map(?:\s+type\s+quality-of-service)?\s+|(?![\s\S]))/gm;
    let m;
    while((m=pmRe.exec(cfg))!==null){
      const pol=m[1], body=m[2]||'';
      const clsRe=/^\s+class\s+(\S+)([\s\S]*?)(?=^\s+class\s+|(?![\s\S]))/gm;
      let cm;
      while((cm=clsRe.exec(body))!==null){
        const cls=cm[1], cb=cm[2]||'';
        let action='-', rate='-', burst='-';
        // 修正：原本用 \s*\S+ 抓取 rate 附帶的選填單位詞，\s 會跨行，若 police 後緊接
        // 下一行的 burst 陳述式，會把 "burst" 字樣也吃進 rate 欄位；改用 (?:[ \t]+\S+)?
        // 限制單位詞只能在同一行內、且整個單位詞部分改為選填（原本 \S+ 是必填，會導致
        // "police rate N" 後面沒有單位詞、直接換行的案例完全比對失敗）
        // Dell OS10：已查證官方 SmartFabric OS10 User Guide 後新增 "police cir N pir N"
        // 雙值格式（committed+peak information rate），取 cir 當 rate（pir 因共用形狀
        // 無對應欄位捨棄，已知限制）；純新增 alternative，不影響 Cisco 既有裸數字格式
        const poCirPir=/police\s+cir\s+(\d+)(?:\s+pir\s+(\d+))?/i.exec(cb);
        const po=poCirPir||/police\s+rate?[ \t]*(\d+(?:[ \t]+\S+)?)/i.exec(cb)||/police\s+(\d+(?:[ \t]+\S+)?)/i.exec(cb);
        if(po){action='police';rate=po[1].trim();}
        else if(/priority/i.test(cb)){action='priority';}
        // Planet：官方 SGS-6341 Command Guide 已查證 policy-map class 子模式支援裸 "drop"
        // 動作（本身是 Cisco IOS 通用關鍵字，非 Planet 專屬，對全廠牌皆有效無副作用風險）；
        // 錨定整行避免誤吃 "exceed-action drop" 這類子句裡的 drop 字樣
        else if(/^\s*drop\s*$/im.test(cb)){action='drop';}
        // Arista EOS：已查證新增 "shape kbps N" 格式（純新增 alternative，與 Cisco
        // "shape average N" 不同關鍵字）
        else if(/shape\s+kbps\s+(\d+)/i.exec(cb)){action='shape';rate=(/shape\s+kbps\s+(\d+)/i.exec(cb)||[])[1];}
        else if(/shape\s+average\s+(\d+)/i.exec(cb)){action='shape';rate=(/shape\s+average\s+(\d+)/i.exec(cb)||[])[1];}
        // Dell OS10：已查證新增 "bandwidth percent N" 百分比制格式；Arista EOS：已查證
        // 新增 "bandwidth kbps N" 格式（皆為純新增 alternative）
        else if(/bandwidth\s+percent\s+(\d+)/i.exec(cb)){action='bandwidth';rate=(/bandwidth\s+percent\s+(\d+)/i.exec(cb)||[])[1];}
        else if(/bandwidth\s+kbps\s+(\d+)/i.exec(cb)){action='bandwidth';rate=(/bandwidth\s+kbps\s+(\d+)/i.exec(cb)||[])[1];}
        else if(/bandwidth\s+(\d+)/i.exec(cb)){action='bandwidth';rate=(/bandwidth\s+(\d+)/i.exec(cb)||[])[1];}
        const br=/exceed-action\s+\S+|burst\s+(\d+)/i.exec(cb);
        if(br&&br[1]) burst=br[1];
        result.push({policy:pol,cls,matchType:'-',matchValue:'-',action,rate,burst});
      }
    }
  }
  return result;
}
// class-map/match 條件比對 + service-policy 介面套用：僅 Cisco/Ruijie/Planet 三家（與
// renderPolicyMapQoS() 共用同一套 policy-map/class 語法的廠牌）沿用標準 Cisco IOS class-map
// 語法（match access-group/dscp/protocol/ip precedence/cos，service-policy input/output），
// 其餘廠牌明確不呼叫，非查證不足。獨立於 parseQoS() 之外（不共用回傳形狀，避免動到既有
// policy-map/class 動作解析）；class-map 區塊收尾同時認 "class-map" 與 "policy-map" 兩種
// 下一區塊關鍵字，因為產生器端組裝順序是 class-map 緊接在 policy-map 之前（class-map 必須
// 先於被引用的 policy-map 定義）
function parseClassMaps(cfg){
  const maps=[];
  // (?!type\s) 排除 "class-map type X ..."（如 Catalyst CoPP 常見的
  // "class-map type control-plane match-any NAME"）——這是與本函式鎖定的一般 QoS
  // class-map 完全不同的語意/用途，先前沒有這道守衛時 (\S+) 會把緊接在 class-map 後面的
  // 字面 "type" 誤判成 class-map 名稱，match-any/match-all／真正名稱／match 條件全部錯位
  // 解析（2026-09-02 審查發現；Arista/Dell OS10/NX-OS 各自獨立的 class-map parser 本來就
  // 要求字面完全相符的 "type qos"，不受此問題影響）
  const cmRe=/^class-map\s+(?!type\s)(?:(match-any|match-all)\s+)?(\S+)([\s\S]*?)(?=^class-map\s+|^policy-map\s+|(?![\s\S]))/gm;
  let m;
  while((m=cmRe.exec(cfg))!==null){
    const matchType=m[1]||'match-all', name=m[2], body=m[3]||'', matches=[];
    let mm;
    const mRe=/^\s*match\s+(access-group|dscp|protocol|cos)\s+(\S+)/gim;
    while((mm=mRe.exec(body))!==null)matches.push({type:mm[1].toLowerCase(),value:mm[2]});
    const pRe=/^\s*match\s+ip\s+precedence\s+(\S+)/gim;
    while((mm=pRe.exec(body))!==null)matches.push({type:'ip-precedence',value:mm[1]});
    maps.push({name,matchType,matches});
  }
  return maps;
}
function parseServicePolicy(cfg){
  const apps=[];
  cfg.split(/(?=^(?:interface|Interface)\s)/m).forEach(blk=>{
    const ifLine=blk.match(/^(?:interface|Interface)\s+(\S.*)/m);
    if(!ifLine)return;
    const ifName=ifLine[1].trim();
    let m; const spRe=/^\s*service-policy\s+(input|output)\s+(\S+)/gim;
    while((m=spRe.exec(blk))!==null)apps.push({policy:m[2],interface:ifName,direction:m[1].toLowerCase()});
  });
  return apps;
}
function parseSTP(cfg, vendor){
  // SONiC（2026-08-08 新增）：整份設定檔是 JSON，與下方逐行正則機制完全不相容，獨立分流；
  // parseAny() 的 res.stp 也是呼叫這裡（透過 parseSONiC() 內部呼叫同一份 _parseSTPSONiC()），
  // 但 switch_config_generator 的匯入既有設定檔流程是直接呼叫 fns.parseSTP(text,vendor)，
  // 不經過 parseSONiC()，故此處必須也能獨立正確派送，不能只靠 parseAny() 的排除清單
  if(vendor==='sonic')return _parseSTPSONiC(cfg);
  const stp={mode:null,instances:[],ports:[]};

  // 全域模式偵測
  if(/^stp mode\s+(\S+)/m.test(cfg))               stp.mode=(cfg.match(/^stp mode\s+(\S+)/m)||[])[1];
  else if(/^spanning-tree mode\s+(\S+)/m.test(cfg)) stp.mode=(cfg.match(/^spanning-tree mode\s+(\S+)/m)||[])[1];
  else if(/^spantree mode\s+(\S+)/m.test(cfg))      stp.mode=(cfg.match(/^spantree mode\s+(\S+)/m)||[])[1];
  else if(/config switch stp-settings/m.test(cfg))  stp.mode='FortiSwitch STP';
  else if(/set protocols\s+(rstp|mstp|stp)\s/m.test(cfg)) stp.mode=(cfg.match(/set protocols\s+(rstp|mstp|stp)/m)||[])[1];
  else if(/configure stpd/m.test(cfg))              stp.mode='ExtremeXOS STPD';
  else if(/^spanning-tree$/m.test(cfg))             stp.mode='(enabled)';

  // Per-VLAN / Per-Instance 優先權
  let m;
  // Cisco IOS/NX-OS: spanning-tree vlan N[-N,N] priority X
  const ciscoRe=/^spanning-tree vlan ([\d\-,]+) priority (\d+)/gm;
  while((m=ciscoRe.exec(cfg))!==null) stp.instances.push({id:m[1],vlan:m[1],priority:parseInt(m[2])});
  // Comware: stp instance N priority X
  const cwRe=/^stp instance (\d+) priority (\d+)/gm;
  while((m=cwRe.exec(cfg))!==null) stp.instances.push({id:m[1],vlan:'Instance '+m[1],priority:parseInt(m[2])});
  // Planet: spanning-tree mst <instance-id> priority <bridge-priority>（關鍵字 "mst" 緊接
  // instance-id，與 Comware "stp instance N priority P"／Cisco "spanning-tree vlan N priority P"
  // 字面皆不同；官方 SGS-6341 Command Guide 已查證）
  const plMstRe=/^spanning-tree mst (\d+) priority (\d+)/gm;
  while((m=plMstRe.exec(cfg))!==null) stp.instances.push({id:m[1],vlan:'Instance '+m[1],priority:parseInt(m[2])});
  // Comware global priority (when no instance)
  if(!stp.instances.length){
    const cwG=/^stp priority (\d+)/m.exec(cfg);
    if(cwG) stp.instances.push({id:'0',vlan:'Global',priority:parseInt(cwG[1])});
  }
  // Brocade/Ruckus ICX (FastIron)：2026-07-18 對外查證官方 L2 Switching Configuration
  // Guide 確認全域 `spanning-tree [single] [forward-delay N] [hello-time N] [max-age N]
  // [priority N]`（classic 802.1D）或 `spanning-tree [single] rstp`（RSTP）皆可在全域層級
  // 輸入，同一行內可同時帶多個參數，故不能沿用下面「Aruba CX/Dell/ProCurve」共用的
  // 「priority 必須緊接在 spanning-tree 後面」窄比對，需獨立解析完整那一行
  if(vendor==='brocade'){
    const lineM=cfg.match(/^spanning-tree\b[^\n]*/m);
    if(lineM){
      const line=lineM[0];
      stp.mode=/\brstp\b/.test(line)?'rstp':'stp';
      const prM=line.match(/priority\s+(\d+)/);
      if(prM) stp.instances.push({id:'0',vlan:'Global',priority:parseInt(prM[1])});
    }
  }
  // Global priority (Aruba CX / Dell / ProCurve；Brocade 已於上方獨立處理)
  if(!stp.instances.length&&vendor!=='brocade'){
    const gP=/^spanning-tree priority (\d+)/m.exec(cfg);
    if(gP) stp.instances.push({id:'0',vlan:'Global',priority:parseInt(gP[1])});
  }
  // Alcatel: spantree N priority X
  const alcRe=/^spantree (\d+) priority (\d+)/gm;
  while((m=alcRe.exec(cfg))!==null) stp.instances.push({id:m[1],vlan:'Instance '+m[1],priority:parseInt(m[2])});
  // ExtremeXOS: configure stpd NAME priority N
  const xosRe=/configure stpd (\S+) priority (\d+)/gm;
  while((m=xosRe.exec(cfg))!==null) stp.instances.push({id:m[1],vlan:m[1],priority:parseInt(m[2])});
  // Juniper: set protocols rstp/mstp priority N
  const junRe=/set protocols (?:rstp|mstp) priority (\d+)/gm;
  while((m=junRe.exec(cfg))!==null) stp.instances.push({id:'0',vlan:'Global',priority:parseInt(m[1])});
  // FortiSwitch: 已查證官方 FortiSwitchOS Administration Guide（standalone mode）後修正，
  // 真實語法 "config switch stp-settings" 沒有 priority 欄位；priority 實際位於具名
  // MSTP instance 底下 "config switch stp instance / edit ID / set priority N"
  // 已查證後發現一個巢狀區塊邊界陷阱：instance 自己的 "edit ID"/"next" 縮排 4 格，
  // 巢狀 "config stp-port" 底下逐 port 的 "edit PORT"/"next" 縮排 12 格；若 lookahead
  // 用 "\s+next"（任意縮排）當邊界，會被巢狀更早出現的 12 格 next 提前截斷，導致
  // （a）instance 自己沒設 priority 時，被巢狀 stp-port 底下第一個 port 的 priority
  // 誤植為 instance priority；（b）多個 port 時，第二個 port 的 "edit" 會被誤判為
  // 下一個頂層 instance，產生一筆假造的 instance。改用精確 4 格縮排錨定邊界，並且
  // 只在「config stp-port 之前」的片段找 instance 自己的 priority，避免讀到巢狀值
  const fsM=/^config switch stp instance\n([\s\S]*?)^end\b/m.exec(cfg);
  if(fsM){
    const instRe=/^ {4}edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^ {4}next\b|^end\b)/gm;
    let im;
    while((im=instRe.exec(fsM[1]))!==null){
      const id=im[1].trim();
      const ownBody=im[2].split(/^\s*config stp-port\b/m)[0];
      const priM=/set priority\s+(\d+)/i.exec(ownBody);
      if(priM) stp.instances.push({id,vlan:'Instance '+id,priority:parseInt(priM[1])});
    }
  }

  // ExtremeXOS 逐 port（本次新增，2026-07-19 對外查證官方 ExtremeXOS Command Reference
  // 確認）：EXOS 無 "interface X" 區塊，逐 port STP 設定一律是 "configure stpd NAME
  // ports ..." 帶 port_list 參數的旗艦式寫法，故用獨立 port_list 為 key 的 map 彙整
  // link-type（edge≒portfast）/edge-safeguard+bpdu-restrict（≒bpduguard）/cost/
  // port-priority 四種指令，不能沿用下面「先切 interface 區塊」的通用迴圈；mode 欄位
  // 也在此改為擷取 "configure stpd NAME mode ..." 實際設定值，取代上方第一段寫死的
  // 'ExtremeXOS STPD' 字面值
  if(vendor==='extreme'){
    const modeM=cfg.match(/^configure stpd (\S+) mode\s+(\S+)(?:\s+(cist|msti\s+\S+))?/m);
    if(modeM) stp.mode=modeM[2]+(modeM[3]?(' '+modeM[3]):'');
    const xports={};
    const getP=p=>{if(!xports[p])xports[p]={port:p,portfast:false,bpduguard:false,guardRoot:false,cost:null,priority:null};return xports[p];};
    let xm;
    const ltRe=/^configure stpd (\S+) ports link-type (edge|auto|broadcast|point-to-point)\s+([^\n]+)$/gm;
    while((xm=ltRe.exec(cfg))!==null){
      xm[3].split(',').map(s=>s.trim()).filter(Boolean).forEach(p=>{if(xm[2]==='edge')getP(p).portfast=true;else getP(p);});
    }
    const bgRe=/^configure stpd (\S+) ports edge-safeguard enable\s+([^\n]+?)\s+bpdu-restrict/gm;
    while((xm=bgRe.exec(cfg))!==null){
      xm[2].split(',').map(s=>s.trim()).filter(Boolean).forEach(p=>{getP(p).bpduguard=true;});
    }
    const costRe=/^configure stpd (\S+) ports cost (?:auto|(\d+))\s+([^\n]+)$/gm;
    while((xm=costRe.exec(cfg))!==null){
      xm[3].split(',').map(s=>s.trim()).filter(Boolean).forEach(p=>{if(xm[2])getP(p).cost=xm[2];else getP(p);});
    }
    const priRe=/^configure stpd (\S+) ports port-priority (\d+)\s+([^\n]+)$/gm;
    while((xm=priRe.exec(cfg))!==null){
      xm[3].split(',').map(s=>s.trim()).filter(Boolean).forEach(p=>{getP(p).priority=xm[2];});
    }
    stp.ports=Object.values(xports);
  }

  // Per-Port STP 設定
  const ifBlocks=cfg.split(/(?=^(?:interface|Interface)\s)/m);
  for(const blk of ifBlocks){
    const ifLine=blk.match(/^(?:interface|Interface)\s+(\S.*)/m);
    if(!ifLine) continue;
    if(!/spanning-tree|stp |spantree|edgeport|802-1w/i.test(blk)) continue;
    const costM=blk.match(/spanning-tree cost (\d+)|stp cost (\d+)/i);
    const prioM=blk.match(/spanning-tree port-priority (\d+)|stp port priority (\d+)/i);
    stp.ports.push({
      port:      ifLine[1].trim(),
      portfast:  /spanning-tree portfast|stp edged-port enable|port-type admin-edge|port-type edge|spantree portfast|edgeport/i.test(blk),
      // Planet：`spanning-tree portfast bpduguard`（bpduguard 是 portfast 指令本身的旗標，
      // 非獨立指令、無 "enable" 字尾），與其餘廠牌寫法皆不同，官方 SGS-6341 Command Guide
      // 已查證；全專案無其他廠牌用此裸關鍵字語法，直接加入 alternation 不需 vendor gate
      bpduguard: /spanning-tree bpduguard enable|stp bpdu-protection|spanning-tree bpdu-guard|bpduguard enable|spanning-tree portfast[^\n]*bpduguard/i.test(blk),
      // 已查證官方 HPE Aruba Networking AOS-CX CLI Reference 後補上 "spanning-tree
      // root-guard"（無反序、連字號寫法，與 Cisco 的 "spanning-tree guard root" 不同）；
      // Planet 的 "spanning-tree rootguard"（無連字號單字）官方 SGS-6341 Command Guide 已查證
      guardRoot: /spanning-tree guard root|stp root-protection|spanning-tree root-guard|spanning-tree rootguard\b/i.test(blk),
      cost:      costM?(costM[1]||costM[2]):null,
      priority:  prioM?(prioM[1]||prioM[2]):null
    });
  }
  // FortiSwitch 逐 port STP：已查證官方 FortiSwitchOS Administration Guide（standalone
  // mode）後修正，真實欄位是 edge-port（非原本假想的 stp-edge）；cost/priority 真實位於
  // 具名 MSTP instance 底下的巢狀 "config stp-port" 子區塊（非 interface 層級攤平欄位），
  // 比照 Extreme XOS 單一預設網域簡化慣例：只讀取第一個 instance 底下的 stp-port 設定
  if(vendor==='fortiswitch'){
    const swBlock=(cfg.match(/^config switch interface\n([\s\S]*?)^end/m)||[])[1]||'';
    const fpRe=/edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^\s+next\b|^end\b)/gm;
    let fm;
    const fsPortCostPriority={};
    if(fsM){
      // 直接在整段 instance 清單文字內找第一個 "config stp-port...end" 子區塊
      // （比照單一預設 instance 簡化：不需精確切出「僅第一個 instance」的邊界，
      // 因為非貪婪比對本來就會先找到最早出現的區塊，效果相同且不受巢狀 next/end
      // 邊界影響——若改用「先切出第一個 edit 區塊」的中介步驟，會被 config stp-port
      // 自己內部更早出現的 next 提前截斷，屬已知的巢狀區塊邊界陷阱）
      const spBlockM=/config stp-port\n([\s\S]*?)^\s+end\b/m.exec(fsM[1]);
      if(spBlockM){
        const spRe=/edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^\s+next\b|^end\b)/gm;
        let spm;
        while((spm=spRe.exec(spBlockM[1]))!==null){
          const p=spm[1].trim(), pbody=spm[2];
          const cM=/set cost\s+(\d+)/i.exec(pbody), prM=/set priority\s+(\d+)/i.exec(pbody);
          fsPortCostPriority[p]={cost:cM?cM[1]:null,priority:prM?prM[1]:null};
        }
      }
    }
    const fsSeenPorts=new Set();
    while((fm=fpRe.exec(swBlock))!==null){
      const port=fm[1].trim(), body=fm[2];
      const cp=fsPortCostPriority[port];
      // 一個 port 可能只在具名 instance 的巢狀 config stp-port 子區塊內設定
      // cost/priority、而 interface 區塊本身完全沒有 edge-port/stp- 關鍵字
      // （無 portfast/bpduguard/guardRoot），若只靠 interface 區塊關鍵字判斷是否
      // 收錄該 port，會漏掉這種只有 cost/priority 的 port
      if(!/(?:edge-port|stp-)/i.test(body)&&!cp) continue;
      fsSeenPorts.add(port);
      stp.ports.push({
        port,
        portfast:  /set edge-port\s+enable/i.test(body),
        bpduguard: /set stp-bpdu-guard\s+enable/i.test(body),
        guardRoot: /set stp-root-guard\s+enable/i.test(body),
        cost:      cp?cp.cost:null,
        priority:  cp?cp.priority:null,
      });
    }
    Object.keys(fsPortCostPriority).forEach(p=>{
      if(fsSeenPorts.has(p))return;
      const cp=fsPortCostPriority[p];
      stp.ports.push({port:p,portfast:false,bpduguard:false,guardRoot:false,cost:cp.cost,priority:cp.priority});
    });
  }
  // Root Bridge 偵測
  stp.rootMode=null;
  // Comware: stp root primary/secondary
  if(/^stp root\s+primary/m.test(cfg)) stp.rootMode='primary';
  else if(/^stp root\s+secondary/m.test(cfg)) stp.rootMode='secondary';
  // Cisco: spanning-tree vlan N root primary/secondary
  if(!stp.rootMode&&/^spanning-tree vlan[\d\s,\-]+ root\s+primary/m.test(cfg)) stp.rootMode='primary';
  else if(!stp.rootMode&&/^spanning-tree vlan[\d\s,\-]+ root\s+secondary/m.test(cfg)) stp.rootMode='secondary';
  // Generic priority 0 or 4096 → likely primary root (only if explicitly set)
  if(!stp.rootMode&&stp.instances.some(i=>i.priority===0)) stp.rootMode='primary';

  // STP Timers
  stp.timers={hello:null,forwardDelay:null,maxAge:null};
  // Comware
  let _tm;
  _tm=cfg.match(/^stp timer hello\s+(\d+)/m); if(_tm)stp.timers.hello=parseInt(_tm[1]);
  _tm=cfg.match(/^stp timer forward-delay\s+(\d+)/m); if(_tm)stp.timers.forwardDelay=parseInt(_tm[1]);
  _tm=cfg.match(/^stp timer max-age\s+(\d+)/m); if(_tm)stp.timers.maxAge=parseInt(_tm[1]);
  // FortiSwitch: 已查證官方 FortiSwitchOS Administration Guide 後修正，全域 timer 位於
  // "config switch stp-settings" 區塊內（hello-time/forward-time/max-age，無 priority）
  if(vendor==='fortiswitch'){
    const fsSettingsM=/^config switch stp-settings\n([\s\S]*?)^end\b/m.exec(cfg);
    const fsBody=fsSettingsM?fsSettingsM[1]:'';
    _tm=/set hello-time\s+(\d+)/i.exec(fsBody); if(_tm)stp.timers.hello=parseInt(_tm[1]);
    _tm=/set forward-time\s+(\d+)/i.exec(fsBody); if(_tm)stp.timers.forwardDelay=parseInt(_tm[1]);
    _tm=/set max-age\s+(\d+)/i.exec(fsBody); if(_tm)stp.timers.maxAge=parseInt(_tm[1]);
  }
  // Cisco per-VLAN
  if(!stp.timers.hello){_tm=cfg.match(/^spanning-tree vlan\s+\S+\s+hello-time\s+(\d+)/m);if(_tm)stp.timers.hello=parseInt(_tm[1]);}
  if(!stp.timers.forwardDelay){_tm=cfg.match(/^spanning-tree vlan\s+\S+\s+forward-time\s+(\d+)/m);if(_tm)stp.timers.forwardDelay=parseInt(_tm[1]);}
  if(!stp.timers.maxAge){_tm=cfg.match(/^spanning-tree vlan\s+\S+\s+max-age\s+(\d+)/m);if(_tm)stp.timers.maxAge=parseInt(_tm[1]);}
  // Cisco global / Aruba CX / Dell / Brocade / ProCurve
  if(!stp.timers.hello){_tm=cfg.match(/^spanning-tree hello-time\s+(\d+)/m);if(_tm)stp.timers.hello=parseInt(_tm[1]);}
  if(!stp.timers.forwardDelay){_tm=cfg.match(/^spanning-tree forward-time\s+(\d+)/m);if(_tm)stp.timers.forwardDelay=parseInt(_tm[1]);}
  if(!stp.timers.maxAge){_tm=cfg.match(/^spanning-tree max-age\s+(\d+)/m);if(_tm)stp.timers.maxAge=parseInt(_tm[1]);}
  // Juniper
  if(!stp.timers.hello){_tm=cfg.match(/set protocols (?:rstp|mstp|stp) hello-interval\s+(\d+)/m);if(_tm)stp.timers.hello=parseInt(_tm[1]);}
  if(!stp.timers.forwardDelay){_tm=cfg.match(/set protocols (?:rstp|mstp|stp) forward-delay\s+(\d+)/m);if(_tm)stp.timers.forwardDelay=parseInt(_tm[1]);}
  if(!stp.timers.maxAge){_tm=cfg.match(/set protocols (?:rstp|mstp|stp) max-age\s+(\d+)/m);if(_tm)stp.timers.maxAge=parseInt(_tm[1]);}

  return stp;
}

// ══════════════════════════════════════════════════════
//  LLDP / CDP NEIGHBOR PARSER
// ══════════════════════════════════════════════════════
const LLDPParser = (() => {
  // ── Cisco CDP ──────────────────────────────────────
  function parseCDP(text) {
    const entries = [];
    const blocks = text.split(/(?:^-{5,}.*$|\n{2,})/m).filter(b => /Device ID:/i.test(b));
    for (const blk of blocks) {
      const neighbor   = (blk.match(/Device ID:\s*(.+)/i)||[])[1]?.trim()||'';
      const ip         = (blk.match(/IP address(?:es)?:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/Platform:\s*([^,\n]+)/i)||[])[1]?.trim()||'';
      const cap        = (blk.match(/Capabilities:\s*(.+)/i)||[])[1]?.trim()||'';
      const ifMatch    = blk.match(/Interface:\s*(\S+),\s*Port ID[^:]*:\s*(\S+)/i);
      const localPort  = ifMatch?.[1]?.replace(/,$/, '')||'';
      const remotePort = ifMatch?.[2]?.replace(/,$/, '')||'';
      if (neighbor) entries.push({localPort, neighbor, platform, remotePort, remoteDesc:'', capability:cap, ip, protocol:'CDP'});
    }
    return entries;
  }

  // ── Cisco IOS / NX-OS LLDP ─────────────────────────
  function parseLLDPCisco(text) {
    const entries = [];
    const blocks = text.split(/^(?=Local Intf:)/m).filter(b => /Local Intf:/i.test(b));
    for (const blk of blocks) {
      const localPort  = (blk.match(/Local Intf:\s*(\S+)/i)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/System Name:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/Port id:\s*(\S+)/i)||[])[1]?.trim()||'';
      const remoteDesc = (blk.match(/Port Description:\s*(.+)/i)||[])[1]?.trim()||'';
      const cap        = (blk.match(/System Capabilities:\s*(.+)/i)||[])[1]?.trim()||'';
      const ip         = (blk.match(/Management Addresses?:?\s*\n\s*IP(?:v4)?(?: Address)?:\s*([\d.]+)/i)||
                          blk.match(/IP(?:v4)?:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/System Description:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc, capability:cap, ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── HPE Comware ────────────────────────────────────
  function parseLLDPComware(text) {
    const entries = [];
    const blocks = text.split(/^(?=LLDP neighbor-information of port)/m).filter(b => /LLDP neighbor-information of port/i.test(b));
    for (const blk of blocks) {
      const localPort  = (blk.match(/LLDP neighbor-information of port\s+\d+\s+\[([^\]]+)\]/i)||
                          blk.match(/LLDP neighbor-information of port\s+(\S+)/i)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/System name\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/Port ID\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const remoteDesc = (blk.match(/Port description\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/System description\s*:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/Management address\s*:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc, capability:'', ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── HPE ProCurve / ArubaOS-Switch ─────────────────
  function parseLLDPProCurve(text) {
    const entries = [];
    const blocks = text.split(/^(?=\s*Local Port\s*:)/m).filter(b => /Local Port\s*:/i.test(b));
    for (const blk of blocks) {
      const localPort  = (blk.match(/Local Port\s*:\s*(\S+)/i)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/SysName\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/PortId\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const remoteDesc = (blk.match(/PortDescr\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/System Descr\s*:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/Address\s*:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc, capability:'', ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── Aruba CX ──────────────────────────────────────
  function parseLLDPArubaCX(text) {
    const entries = [];
    const blocks = text.split(/^(?=Port\s+:)/m).filter(b => /Port\s+:/.test(b) && /SystemName|System Name/i.test(b));
    for (const blk of blocks) {
      const localPort  = (blk.match(/Port\s*:\s*(\S+)/)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/SystemName\s*:\s*(.+)/i)||blk.match(/System Name\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/Port ID\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/System Description\s*:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/IPv4 address\s*:\s*([\d.]+)/i)||blk.match(/Management Address\s*:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc:'', capability:'', ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── Ubiquiti EdgeSwitch（Broadcom ICOS 家族，與 Dell OS10 同源系統）──
  // 官方 EdgeSwitch ES-24-250W Command Reference Manual 查證：detail 模式每筆鄰居以
  // "Remote Identifier:" 起始，區塊內未見本地介面欄位；本地介面只出現在 summary 模式
  // （"Local Interface | RemID | Chassis ID | Port ID | System Name" 表格）。故本解析器
  // 優先合併兩段輸出，用 RemID 對照回填本地介面；若使用者只貼 detail 沒有 summary，
  // 本地介面留空 '-'，不臆測（比照專案「查無佐證不猜測」慣例）。
  function parseLLDPEdgeSwitch(text) {
    const entries = [];
    const summaryMap = {}; // RemID -> Local Interface
    const summaryLineRe = /^(\S+)\s+(\d+)\s+([0-9A-Fa-f:]{17})\s+(\S+)\s+(.+)$/gm;
    let sm;
    while ((sm = summaryLineRe.exec(text)) !== null) {
      summaryMap[sm[2]] = sm[1];
    }
    const blocks = text.split(/^(?=Remote Identifier:)/m).filter(b => /Remote Identifier:/i.test(b));
    for (const blk of blocks) {
      const remId      = (blk.match(/Remote Identifier:\s*(\S+)/i)||[])[1]?.trim()||'';
      const neighbor    = (blk.match(/System Name:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort  = (blk.match(/^Port ID:\s*(.+)$/im)||[])[1]?.trim()||'';
      const platform    = (blk.match(/System Description:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      const ip          = (blk.match(/Management Address:.*?Address:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      const cap         = (blk.match(/System Capabilities(?:\s+Supported)?:\s*(.+)/i)||[])[1]?.trim()||'';
      const localPort   = summaryMap[remId] || '-';
      if (remId) entries.push({localPort, neighbor, platform, remotePort, remoteDesc:'', capability:cap, ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── Dell EMC OS10 ─────────────────────────────────
  function parseLLDPDell(text) {
    const entries = [];
    const blocks = text.split(/^(?=Interface:)/m).filter(b => /Interface:/i.test(b) && /NeighborIndex:/i.test(b));
    for (const blk of blocks) {
      const localPort  = (blk.match(/Interface:\s*(\S+)/i)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/System Name:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/Port ID:\s*(.+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/System Description:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/Management Address:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      const cap        = (blk.match(/System Capabilities(?:\s+Supported)?:\s*(.+)/i)||[])[1]?.trim()||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc:'', capability:cap, ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── FortiSwitch ───────────────────────────────────
  function parseLLDPFortiSwitch(text) {
    const entries = [];
    const blocks = text.split(/^==\s*\[/m).filter(b => b.includes(']'));
    for (const blk of blocks) {
      const localPort  = (blk.match(/^([^\]]+)\]/)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/(?:System Name|SysName)\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/Port ID\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/(?:System Descr|SysDesc)\s*:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/(?:Management Address|MgmtIPv4|MgmtAddr)\s*:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      if (localPort && neighbor) entries.push({localPort, neighbor, platform, remotePort, remoteDesc:'', capability:'', ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── Extreme Networks ExtremeXOS ───────────────────
  function parseLLDPExtreme(text) {
    const entries = [];
    const blocks = text.split(/^(?=Port:\s+\d)/m).filter(b => /LLDP Information from Neighbor/i.test(b));
    for (const blk of blocks) {
      const localPort  = (blk.match(/Port:\s*(\S+)/i)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/System Name:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/Port ID:\s*(.+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/System Description:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/Management Address:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc:'', capability:'', ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── Brocade FastIron / ICX ────────────────────────
  function parseLLDPBrocade(text) {
    const entries = [];
    const blocks = text.split(/^(?=Local port:)/m).filter(b => /Local port:/i.test(b));
    for (const blk of blocks) {
      const localPort  = (blk.match(/Local port:\s*(\S+)/i)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/Neighbor's system name:\s*"?([^"\n]+)"?/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/Neighbor's port id:\s*(\S+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/Neighbor's system description:\s*"?([^"\n]+)"?/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/Neighbor's Management IP address:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      const cap        = (blk.match(/Neighbor's enabled capabilities:\s*(.+)/i)||[])[1]?.trim()||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc:'', capability:cap, ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── Alcatel OmniSwitch ────────────────────────────
  function parseLLDPAlcatel(text) {
    const entries = [];
    const blocks = text.split(/^(?=Local Port\s+:)/m).filter(b => /Local Port\s+:/i.test(b) && /Neighbor's Chassis ID/i.test(b));
    for (const blk of blocks) {
      const localPort  = (blk.match(/Local Port\s*:\s*(\S+)/i)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/Neighbor's System Name\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/Neighbor's Port ID\s*:\s*(\S+)/i)||[])[1]?.trim()||'';
      const remoteDesc = (blk.match(/Neighbor's Port Desc\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/Neighbor's System Desc\s*:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/Management IP\s*:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc, capability:'', ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── Juniper EX / QFX ─────────────────────────────
  function parseLLDPJuniper(text) {
    const entries = [];
    const blocks = text.split(/^(?=\s*Local Interface\s*:)/m).filter(b => /Local Interface\s*:/i.test(b));
    for (const blk of blocks) {
      const localPort  = (blk.match(/Local Interface\s*:\s*(\S+)/i)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/System name\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const remotePort = (blk.match(/Port ID\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const remoteDesc = (blk.match(/Port description\s*:\s*(.+)/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/System descr\s*:\s*(.+)/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/Management IP\s*:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc, capability:'', ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── Arista EOS（2026-08-19 新增）───────────────────
  // 官方文件本身罕見附完整逐字指令輸出範例，改查證社群維護、以真實裝置輸出建置的
  // ntc-templates（network automation 界廣泛使用於 netmiko/napalm）
  // arista_eos_show_lldp_neighbors_detail.textfsm 樣板逐字確認結構：每個本地介面以
  // "<字> <介面名> <字> <鄰居數>..." 開頭的標頭行起始一個區塊，區塊內固定含
  // "Chassis ID   :"／"- Port ID type"（觸發子狀態）／"Port ID   : "值""／
  // "- <字> Name: "值""／"System Description: "值""／"<字> Address   : 值"；
  // 用標頭行位置切分區塊（而非 lookahead split），避免內文任意處誤判為區塊邊界
  function parseLLDPArista(text) {
    const entries = [];
    const hdrRe = /^\S+\s+(\S+)\s+\S+\s+\d+.*$/gm;
    const marks = [];
    let hm;
    while ((hm = hdrRe.exec(text)) !== null) marks.push({index: hm.index, localPort: hm[1]});
    for (let i = 0; i < marks.length; i++) {
      const start = marks[i].index;
      const end = i + 1 < marks.length ? marks[i+1].index : text.length;
      const blk = text.slice(start, end);
      if (!/Chassis ID\s*:/i.test(blk)) continue;
      const localPort  = marks[i].localPort;
      const remotePort = (blk.match(/Port ID\s*:\s*"?([^"\n]+?)"?\s*$/im)||[])[1]?.trim()||'';
      const neighbor   = (blk.match(/-\s+\S+\s+Name:\s*"([^"]+)"/i)||[])[1]?.trim()||'';
      const platform   = (blk.match(/System Description:\s*"?([^"\n]+)"?/i)||[])[1]?.trim().slice(0,50)||'';
      const ip         = (blk.match(/\S+\s+Address\s*:\s*([\d.]+)/i)||[])[1]?.trim()||'';
      if (localPort) entries.push({localPort, neighbor, platform, remotePort, remoteDesc:'', capability:'', ip, protocol:'LLDP'});
    }
    return entries;
  }

  // ── MikroTik RouterOS（2026-08-19 新增）───────────
  // 官方 MikroTik 文件（help.mikrotik.com "Neighbor discovery"）附逐字範例輸出，固定欄位
  // 表格 "# INTERFACE ADDRESS MAC-ADDRESS IDENTITY VERSION BOARD"；以 MAC 位址（格式明確
  // 不會與其他欄位混淆）錨定逐列擷取，避開表格欄寬不固定造成的位置誤判
  function parseLLDPRouterOS(text) {
    const entries = [];
    const re = /^\s*\d+\s+(\S+)\s+(?:(\d+\.\d+\.\d+\.\d+)\s+)?([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(\S+)\s*(.*)$/gm;
    let m;
    while ((m = re.exec(text)) !== null) {
      entries.push({localPort:m[1], neighbor:m[4], platform:(m[5]||'').trim().slice(0,50), remotePort:'', remoteDesc:'', capability:'', ip:m[2]||'', protocol:'LLDP'});
    }
    return entries;
  }

  // ── SONiC（2026-08-19 新增）────────────────────────
  // 多個獨立來源（Dell／Supermicro／Edgecore／Cisco DevNet 官方文件）交叉確認 show lldp
  // table 逐字範例輸出（開源 sonic-utilities/scripts/lldpshow 標準格式），固定欄位表格
  // LocalPort/RemoteDevice/RemotePortID/Capability/RemotePortDescr，以 --- 分隔線區分
  // 表頭與資料列
  function parseLLDPSonic(text) {
    const entries = [];
    const sepIdx = text.search(/^-{5,}/m);
    if (sepIdx < 0) return entries;
    const rows = text.slice(sepIdx).split('\n').slice(1);
    for (const row of rows) {
      const cols = row.trim().split(/\s{2,}/).filter(Boolean);
      if (cols.length < 3) continue;
      const [localPort, neighbor, remotePort, capability, ...descParts] = cols;
      entries.push({localPort, neighbor, platform:'', remotePort, remoteDesc:descParts.join(' ')||'', capability:capability||'', ip:'', protocol:'LLDP'});
    }
    return entries;
  }

  // ── Auto-detect & dispatch ────────────────────────
  function parse(text, vendor) {
    if (!text) return [];
    // 統一在此正規化 CRLF，比照 parseAny() 的既有模式，避免 parseCDP() 的 \n{2,} 區塊分隔
    // 正則在 CRLF 輸入下因空白行實際是 \r\n\r\n（中間夾 \r）而漏抓多筆鄰居
    text = text.replace(/\r\n/g, '\n');
    // 2026-08-19 新增：Arista 的 "Chassis ID   :" 格式與下方 Juniper 既有簽章
    // （/Chassis ID\s{2,}:/i）會誤撞，故 Arista 檢查必須排在 Juniper 之前
    if (/^\s+-\s+Port ID type/m.test(text))                          return parseLLDPArista(text);
    if (/^\s*#\s+INTERFACE\s+ADDRESS\s+MAC-ADDRESS\s+IDENTITY/im.test(text)) return parseLLDPRouterOS(text);
    if (/Capability codes:\s*\(R\)\s*Router/i.test(text) || /LocalPort\s+RemoteDevice/i.test(text)) return parseLLDPSonic(text);
    if (/Device ID:/i.test(text))                                    return parseCDP(text);
    if (/LLDP neighbor-information of port/i.test(text))             return parseLLDPComware(text);
    if (/LLDP Remote Device|ChassisType\s*:/i.test(text))            return parseLLDPProCurve(text);
    // 2026-08-26 新增：EdgeSwitch 的 "Chassis ID:" 大小寫不分時會被下方 Cisco 簽章
    // （/Chassis id:/i）誤撞，故 EdgeSwitch 檢查必須排在 Cisco 之前（比照上方 Arista/Juniper
    // 既有慣例）
    if (/Remote Identifier:/i.test(text))                             return parseLLDPEdgeSwitch(text);
    if (/Local Intf:/i.test(text) || /Chassis id:/i.test(text))      return parseLLDPCisco(text);
    if (/SystemName\s*:/m.test(text) && /Port\s+:/m.test(text))      return parseLLDPArubaCX(text);
    if (/NeighborIndex:/i.test(text))                                 return parseLLDPDell(text);
    if (/==\s*\[.+?\]\s*==/m.test(text))                             return parseLLDPFortiSwitch(text);
    if (/LLDP Information from Neighbor:/i.test(text))               return parseLLDPExtreme(text);
    if (/Neighbor's chassis id:/i.test(text))                        return parseLLDPBrocade(text);
    if (/Neighbor's Chassis ID\s*:/i.test(text))                     return parseLLDPAlcatel(text);
    if (/Local Interface\s*:/i.test(text) || /Chassis ID\s{2,}:/i.test(text)) return parseLLDPJuniper(text);
    // fallback by vendor
    if (vendor==='comware')                   return parseLLDPComware(text);
    if (vendor==='procurve')                  return parseLLDPProCurve(text);
    if (vendor==='aruba')                     return parseLLDPArubaCX(text);
    if (vendor==='dell-os10')                 return parseLLDPDell(text);
    if (vendor==='edgeswitch')                return parseLLDPEdgeSwitch(text);
    if (vendor==='fortiswitch')               return parseLLDPFortiSwitch(text);
    if (vendor==='extreme')                   return parseLLDPExtreme(text);
    if (vendor==='brocade')                   return parseLLDPBrocade(text);
    if (vendor==='alcatel')                   return parseLLDPAlcatel(text);
    if (vendor==='juniper')                   return parseLLDPJuniper(text);
    // 2026-08-19 新增：nxos 函式命名/註解本來就寫「Cisco IOS / NX-OS LLDP」，僅接線問題
    // （沿用 IOS 家族相容輸出格式，非新查證）；arista/routeros/sonic 上方 auto-detect
    // 已可正確命中，此處 vendor fallback 僅作為內容特徵掃描失效時的保底
    if (vendor==='nxos')                      return parseLLDPCisco(text);
    if (vendor==='arista')                    return parseLLDPArista(text);
    if (vendor==='routeros')                  return parseLLDPRouterOS(text);
    if (vendor==='sonic')                     return parseLLDPSonic(text);
    return parseLLDPCisco(text);
  }

  return { parse };
})();

// ════════════════════════════════════════════════════
//  ARISTA EOS PARSER
// ════════════════════════════════════════════════════
function parseAny(cfg,forceVendor){
  // 統一在此正規化 CRLF，避免各廠牌逐行正則（如 stack unit 區塊）因 \r 悄悄比對失敗
  cfg=cfg.replace(/\r\n/g,'\n');
  // forceVendor：使用者手動指定廠牌時略過 detectVendor() 自動判斷，直接用指定值派送
  // （detectVendor() 誤判時的 fallback，2026-07-30 新增）
  const vendor=forceVendor||detectVendor(cfg);
  let res;
  if(vendor==='comware') res=parseComware(cfg);
  else if(vendor==='dell-os10') res=parseDellOS10(cfg);
  else if(vendor==='arista') res=parseArista(cfg);
  else if(vendor==='ruijie') res=parseRuijie(cfg);
  else if(vendor==='netgear') res=parseNetgear(cfg);
  else if(vendor==='edgeswitch') res=parseEdgeSwitch(cfg);
  else if(vendor==='planet') res=parsePlanet(cfg);
  else if(vendor==='cisco') res=parseCisco(cfg);
  else if(vendor==='aruba') res=parseAruba(cfg);
  else if(vendor==='fortiswitch') res=parseFortiSwitch(cfg);
  else if(vendor==='extreme') res=parseExtremeXOS(cfg);
  else if(vendor==='alcatel') res=parseAlcatel(cfg);
  else if(vendor==='juniper') res=parseJuniper(cfg);
  else if(vendor==='brocade') res=parseBrocade(cfg);
  else if(vendor==='nxos') res=parseNXOS(cfg);
  else if(vendor==='procurve') res=parseProCurve(cfg);
  else if(vendor==='routeros') res=parseRouterOS(cfg);
  else if(vendor==='sonic') res=parseSONiC(cfg);
  else res={vendor:'unknown',sys:{hostname:'unknown',version:''},irf:null,stack:null,vlans:[],interfaces:[],routes:[],vrfs:[],users:[],ospf:[],bgp:[],rip:[],vrrp:[],vxlan:null,acls:[]};

  res.vendor=vendor;
  if(!res.breakouts)res.breakouts=[]; // 未提供 breakout 解析的廠牌維持空陣列，保持回傳形狀一致
  if(vendor==='comware') res.stack=res.irf?{type:'IRF',members:res.irf.members,links:res.irf.links,details:res.irf}:null;
  // 2026-07-19 修復既有 bug：RouterOS 的 lacp/dhcp 是 parseRouterOS() 自己算好塞回傳
  // 物件（parseRouterOSLACP/parseRouterOSDHCP，屬於「外部覆蓋」模式，與 Brocade/Extreme/
  // Juniper/ProCurve 同一類），既有排除清單原本漏了 routeros，導致這裡的共用 dispatcher
  // （routeros 無對應分支）用空/預設值蓋掉已經解析好的正確資料
  // sonic：parseSONiC() 已用 PORTCHANNEL/PORTCHANNEL_MEMBER 正確算好 res.lacp，
  // 不可被這裡的共用 regex dispatcher（對 JSON 文字必定掃不到東西）用空結果覆蓋
  if(vendor!=='juniper'&&vendor!=='alcatel'&&vendor!=='extreme'&&vendor!=='brocade'&&vendor!=='procurve'&&vendor!=='routeros'&&vendor!=='sonic')res.lacp=parseLACP(cfg, vendor);
  if(vendor!=='juniper'&&vendor!=='extreme'&&vendor!=='brocade'&&vendor!=='procurve'&&vendor!=='routeros'&&vendor!=='sonic')res.dhcp=parseDHCP(cfg, vendor);
  // 2026-07-24 新增：系統層級 DNS Server，獨立新頂層欄位，不受上方 DHCP dispatcher 排除清單影響
  // （parseDNSServers() 內部自行處理各廠牌 branch，無需比照 dhcp 那樣繞過 dispatcher）
  res.dns=parseDNSServers(cfg, vendor);
  // RouterOS 的 stp 同樣是 parseRouterOSBridgeSTP() 外部覆蓋模式（2026-07-27 起已改為
  // 回傳與共用 dispatcher 相同的 {mode,instances,ports,rootMode,timers} 巢狀形狀），此處
  // 原本對任何廠牌都無排除，會被下方共用 dispatcher 蓋掉，一併修復
  if(vendor!=='routeros'&&vendor!=='sonic')res.stp=parseSTP(cfg, vendor);
  res.acls=parseACL(cfg, vendor);
  res.security=parseSecurity(cfg, vendor);
  // sonic：parseSONiC() 已用 SNMP_COMMUNITY/SYSLOG_SERVER 兩個 JSON 表格正確算好
  // res.snmp/res.syslog（見 _parseSnmpSONiC()/_parseSyslogSONiC()），不可被這裡的共用
  // 文字正則 dispatcher（對 JSON 文字必定掃不到東西）用空結果覆蓋，比照既有 lacp/dhcp/
  // stp/qos 排除模式（2026-08-20 新增）
  if(vendor!=='sonic')res.snmp=parseSNMP(cfg, vendor);
  if(vendor!=='sonic')res.syslog=parseSyslog(cfg, vendor);
  res.mgmtAccess=parseMgmtAccess(cfg, vendor);
  res.routingAuth=parseRoutingAuth(cfg, vendor);
  // Brocade 的 qos 已在 parseBrocade() 內用專屬形狀（dscpMap/ports）設定，Extreme 的
  // qos 已在 parseExtremeXOS() 內用專屬形狀（profiles/dscpMap/ports，QP1-QP8 profile
  // 模型）設定，RouterOS 的 qos 已在 parseRouterOS() 內用專屬形狀（simpleQueues/
  // queueTree）設定，三者皆不可被這裡的共用 Cisco-style policy-map dispatcher 覆蓋
  if(vendor!=='brocade'&&vendor!=='extreme'&&vendor!=='routeros'&&vendor!=='sonic')res.qos=parseQoS(cfg, vendor);
  // class-map/match + service-policy：僅 cisco/ruijie/planet 三家已查證（見 parseClassMaps()/
  // parseServicePolicy() 註解），其餘廠牌刻意不賦值（維持 undefined，非空陣列），避免暗示
  // 未查證廠牌也支援
  if(vendor==='cisco'||vendor==='ruijie'||vendor==='planet'){
    res.classMaps=parseClassMaps(cfg);
    res.servicePolicy=parseServicePolicy(cfg);
  }
  // Arista／Dell OS10（2026-08-28（續5）新增）：語法比 Cisco 家族多一段 "type qos" 限定詞，
  // 見各自 parser 檔案內 parseAristaClassMaps()/parseDellOS10ClassMaps() 等對應註解，故獨立
  // 分支，不與上方共用 parseClassMaps()/parseServicePolicy() 混用
  else if(vendor==='arista'){
    res.classMaps=parseAristaClassMaps(cfg);
    res.servicePolicy=parseAristaServicePolicy(cfg);
  }
  else if(vendor==='dell-os10'){
    res.classMaps=parseDellOS10ClassMaps(cfg);
    res.servicePolicy=parseDellOS10ServicePolicy(cfg);
  }
  // Comware／NX-OS（2026-08-31 新增）：官方 H3C QoS Commands（Comware，`traffic
  // classifier`/`if-match`/`qos apply policy`）與 Cisco NX-OS QoS Configuration Guide／
  // Cisco Community 真實範例（NX-OS，`class-map type qos`/`service-policy type qos`）
  // 兩者皆與 Cisco classic IOS 語法家族不同，各自獨立分支，詳見對應 parser 檔案內
  // parseComwareClassMaps()/parseNxosClassMaps() 的查證來源註解
  else if(vendor==='comware'){
    res.classMaps=parseComwareClassMaps(cfg);
    res.servicePolicy=parseComwareServicePolicy(cfg);
  }
  else if(vendor==='nxos'){
    res.classMaps=parseNxosClassMaps(cfg);
    res.servicePolicy=parseNxosServicePolicy(cfg);
  }
  return res;
}

// ═ SONiC Parser（config_db.json，第 17 個廠牌，MVP 範圍）═══════════
// 涵蓋：hostname／VLAN／VLAN_MEMBER／INTERFACE＋VLAN_INTERFACE＋PORTCHANNEL_INTERFACE
// （L3 IP）／PORTCHANNEL＋PORTCHANNEL_MEMBER（LACP）／BGP_NEIGHBOR＋
// DEVICE_METADATA.bgp_asn／STATIC_ROUTE／ACL_TABLE+ACL_RULE（2026-08-08 對外查證新增，
// 見 _parseACLSONiC()）／STP+STP_VLAN+STP_INTF+STP_VLAN_INTF（2026-08-08 對外查證新增，
// 見 _parseSTPSONiC()）／QoS：SCHEDULER+PORT_QOS_MAP+QUEUE（2026-08-08 對外查證新增，見
// _parseQoSSONiC()，DSCP→TC 分類屬另一獨立功能本輪不納入）／Security 802.1X：
// PAC_PORT_CONFIG+HOSTAPD_GLOBAL_CONFIG（2026-08-08 對外查證新增，見
// _parseSecuritySONiC()，guest VLAN／MAC port-security 查無官方欄位不猜測）。明確排除：
// OSPF（架構上不適用——官方 Unified FRR Management Framework 設計文件列為未來擴充，查無
// config_db.json 表格定義，SONiC 的 OSPF 實際透過 FRR 原生設定檔管理，非本工具
// 「json↔表單」設計範圍）。
// 完全繞過逐行正則機制：整份設定檔本體就是合法 JSON，直接 JSON.parse()。
function parseVRRP(cfg, vendor){
  const groups=[];
  if(vendor==='comware'){
    // Each interface block that has vrrp config
    const raw=cfg.split('\ninterface ');
    const merged={};
    for(const blk of raw.slice(1)){
      const name=blk.split('\n')[0].trim();
      const body=blk.slice(name.length);
      merged[name]=(merged[name]||'')+body;
    }
    for(const [iface,body] of Object.entries(merged)){
      // IPv6（2026-08-17 新增，官方 H3C VRRP commands 手冊確認 `vrrp ipv6 vrid N` 是與
      // IPv4 `vrrp vrid N` 平行的獨立指令，非同一 vrid 命名空間下的欄位差異）：guard 條件
      // 一併涵蓋，避免只有 IPv6 宣告、無 IPv4 的介面被整段跳過
      if(!/vrrp (?:vrid|ipv6 vrid)/.test(body))continue;
      const vridSet={};let m;
      // Collect all fields per VRID
      const allVrids=[...body.matchAll(/vrrp vrid\s+(\d+)/g)].map(x=>x[1]);
      const uniq=[...new Set(allVrids)];
      for(const vrid of uniq){
        const re=new RegExp('vrrp vrid\\s+'+vrid+'\\s+([^\\n]+)','g');
        const rec={vrid,interface:iface,vip:'',vip6:'',priority:'100',preempt:false,authMode:'',authKey:'',trackIf:'',trackReduced:'',version:'2'};
        let line;
        while((line=re.exec(body))!==null){
          const rest=line[1].trim();
          if(/^virtual-ip\s/.test(rest))rec.vip=(rest.match(/virtual-ip\s+(\S+)/)||[])[1]||'';
          else if(/^priority\s/.test(rest))rec.priority=(rest.match(/priority\s+(\d+)/)||[])[1]||'100';
          else if(/^preempt-mode/.test(rest))rec.preempt=true;
          // authentication-mode {simple {key|plain key|cipher cipher-key} | md5 md5-key}——
          // 2026-07-22 對外查證官方文件後修正：原本只擷取到 mode 關鍵字本身，實際金鑰值
          // 完全遺失，改為擷取最後一個 token 作為金鑰（plain/cipher 皆取字面值，不逆向解密）
          else if(/^authentication-mode/.test(rest)){
            const am=rest.match(/authentication-mode\s+(simple|md5)\s+(?:plain\s+|cipher\s+)?(\S+)/);
            if(am){rec.authMode=am[1];rec.authKey=am[2];}
          }
          else if(/^track interface/.test(rest)){rec.trackIf=(rest.match(/track interface\s+(\S+)/)||[])[1]||'';rec.trackReduced=(rest.match(/reduced\s+(\d+)/)||[])[1]||'';}
        }
        groups.push(rec);
      }
      // IPv6 vrid（同一 interface+vrid 若已有 IPv4 記錄則合併 vip6，否則新增獨立記錄）
      const allVrids6=[...body.matchAll(/vrrp ipv6 vrid\s+(\d+)/g)].map(x=>x[1]);
      for(const vrid of [...new Set(allVrids6)]){
        const re6=new RegExp('vrrp ipv6 vrid\\s+'+vrid+'\\s+([^\\n]+)','g');
        let vip6='',line6;
        while((line6=re6.exec(body))!==null){
          const rest=line6[1].trim();
          if(/^virtual-ip\s/.test(rest))vip6=(rest.match(/virtual-ip\s+(\S+)/)||[])[1]||vip6;
        }
        if(!vip6)continue;
        const existing=groups.find(g=>g.interface===iface&&g.vrid===vrid);
        if(existing)existing.vip6=vip6;
        else groups.push({vrid,interface:iface,vip:'',vip6,priority:'100',preempt:false,authMode:'',authKey:'',trackIf:'',trackReduced:'',version:'2'});
      }
    }
  } else if(vendor==='dell-os10'){
    // Dell OS10: "vrrp-group N" block inside interface vlan
    // IPv6（2026-08-17 新增，官方 SmartFabric OS10 User Guide 確認 `vrrp-ipv6-group N` 是
    // 與 IPv4 `vrrp-group N` 平行的獨立關鍵字，非同一 group 命名空間下的欄位差異）：
    // 兩段正則的 lookahead 皆須互相涵蓋對方關鍵字，避免其中一段非貪婪擷取內容溢出到另一段區塊
    const raw=cfg.split('\ninterface ');
    for(const blk of raw.slice(1)){
      const name=blk.split('\n')[0].trim();
      const body=blk.slice(name.length);
      if(!/vrrp-group|vrrp-ipv6-group/.test(body))continue;
      const vgRe=/(?<!ipv6-)vrrp-group\s+(\d+)([\s\S]*?)(?=vrrp-ipv6-group|vrrp-group|\n\S|$)/g;let vg;
      while((vg=vgRe.exec(body))!==null){
        const vgBody=vg[2];
        const vip=(vgBody.match(/virtual-address\s+(\S+)/)||[])[1]||'';
        const priority=(vgBody.match(/priority\s+(\d+)/)||[])[1]||'100';
        const preempt=/preempt/.test(vgBody);
        if(vip)groups.push({vrid:vg[1],interface:name,vip,vip6:'',priority,preempt,authMode:'',trackIf:'',trackReduced:'',version:'2'});
      }
      const vg6Re=/vrrp-ipv6-group\s+(\d+)([\s\S]*?)(?=vrrp-ipv6-group|vrrp-group|\n\S|$)/g;let vg6;
      while((vg6=vg6Re.exec(body))!==null){
        const vrid=vg6[1],vip6=(vg6[2].match(/virtual-address\s+(\S+)/)||[])[1]||'';
        if(!vip6)continue;
        const priority=(vg6[2].match(/priority\s+(\d+)/)||[])[1]||'100';
        const preempt=/preempt/.test(vg6[2]);
        const existing=groups.find(g=>g.interface===name&&g.vrid===vrid);
        if(existing)existing.vip6=vip6;
        else groups.push({vrid,interface:name,vip:'',vip6,priority,preempt,authMode:'',trackIf:'',trackReduced:'',version:'2'});
      }
    }
  } else if(vendor==='cisco'){
    // Cisco HSRP: "standby N ip VIP"
    const raw=cfg.split('\ninterface ');
    for(const blk of raw.slice(1)){
      const name=blk.split('\n')[0].trim();
      const body=blk.slice(name.length);
      if(!/standby/.test(body))continue;
      const vridSet=new Set([...body.matchAll(/standby\s+(\d+)/g)].map(x=>x[1]));
      for(const vrid of vridSet){
        const re=new RegExp('standby\\s+'+vrid+'\\s+([^\\n]+)','g');
        const rec={vrid,interface:name,vip:'',vip6:'',priority:'100',preempt:false,authMode:'',trackIf:'',trackReduced:'',version:'HSRP',type:'HSRP'};
        let line;
        while((line=re.exec(body))!==null){
          const rest=line[1].trim();
          if(/^ip\s/.test(rest))rec.vip=(rest.match(/ip\s+(\S+)/)||[])[1]||'';
          // IPv6（2026-08-18 新增，官方 Cisco HSRP for IPv6 Configuration Guide 確認同一
          // standby N 指令樹的關鍵字擴充："standby N ipv6 autoconfig"（自動衍生 link-local，
          // 存字面值 "autoconfig"）或 "standby N ipv6 ADDR"（顯式位址），前提須先在介面上
          // 宣告 "standby version 2"（HSRP for IPv6 僅 v2 支援，本工具不驗證此前提條件，
          // 沿用既有專案慣例只解析欄位值不驗證裝置端合法性）
          else if(/^ipv6\s/.test(rest))rec.vip6=(rest.match(/ipv6\s+(\S+)/)||[])[1]||'';
          else if(/^priority\s/.test(rest))rec.priority=(rest.match(/priority\s+(\d+)/)||[])[1]||'100';
          else if(/^preempt/.test(rest))rec.preempt=true;
          else if(/^authentication/.test(rest))rec.authMode='configured';
          else if(/^track/.test(rest))rec.trackIf=(rest.match(/track\s+(\S+)/)||[])[1]||'';
          else if(/^version\s/.test(rest))rec.version=(rest.match(/version\s+(\d+)/)||[])[1]||'1';
        }
        groups.push(rec);
      }
    }
  } else if(vendor==='aruba'){
    // Aruba CX: "vrrp N vip X" inside interface vlan block
    const raw=cfg.split('\ninterface ');
    const merged={};
    for(const blk of raw.slice(1)){
      const name=blk.split('\n')[0].trim();
      const body=blk.slice(name.length);
      merged[name]=(merged[name]||'')+body;
    }
    for(const [iface,body] of Object.entries(merged)){
      if(!/vrrp\s+\d+\s+vip/.test(body))continue;
      const vridSet=new Set([...body.matchAll(/vrrp\s+(\d+)/g)].map(x=>x[1]));
      for(const vrid of vridSet){
        const re=new RegExp('vrrp\\s+'+vrid+'\\s+([^\\n]+)','g');
        const rec={vrid,interface:iface,vip:'',priority:'100',preempt:false,authMode:'',trackIf:'',trackReduced:'',version:'2'};
        let line;
        while((line=re.exec(body))!==null){
          const rest=line[1].trim();
          if(/^vip\s/.test(rest))rec.vip=(rest.match(/vip\s+(\S+)/)||[])[1]||'';
          else if(/^priority\s/.test(rest))rec.priority=(rest.match(/priority\s+(\d+)/)||[])[1]||'100';
          else if(/^preempt/.test(rest))rec.preempt=true;
          else if(/^version\s/.test(rest))rec.version=(rest.match(/version\s+(\d+)/)||[])[1]||'2';
          else if(/^authentication/.test(rest))rec.authMode='configured';
        }
        groups.push(rec);
      }
    }
  } else if(vendor==='arista'){
    // Arista EOS: "vrrp N ipv4 VIP" / "vrrp N priority-level P" 位於 interface Vlan 區塊內；
    // preempt 語意與其他廠牌相反，EOS 預設啟用，需比對明確的 "no vrrp N preempt" 才視為停用
    const raw=cfg.split('\ninterface ');
    const merged={};
    for(const blk of raw.slice(1)){
      const name=blk.split('\n')[0].trim();
      const body=blk.slice(name.length);
      merged[name]=(merged[name]||'')+body;
    }
    for(const [iface,body] of Object.entries(merged)){
      if(!/vrrp\s+\d+\s+ipv4\s+\d/.test(body)&&!/vrrp\s+\d+\s+ipv6\s+\S/.test(body))continue;
      const vridSet=new Set([...body.matchAll(/vrrp\s+(\d+)\s+ipv4\s+\d/g)].map(x=>x[1]));
      for(const vrid of vridSet){
        const re=new RegExp('vrrp\\s+'+vrid+'\\s+([^\\n]+)','g');
        const rec={vrid,interface:iface,vip:'',vip6:'',priority:'100',preempt:true,authMode:'',trackIf:'',trackReduced:'',version:'2'};
        let line;
        while((line=re.exec(body))!==null){
          const rest=line[1].trim();
          if(/^ipv4\s+\d/.test(rest))rec.vip=(rest.match(/ipv4\s+(\S+)/)||[])[1]||'';
          else if(/^priority-level\s/.test(rest))rec.priority=(rest.match(/priority-level\s+(\d+)/)||[])[1]||'100';
        }
        if(new RegExp('no\\s+vrrp\\s+'+vrid+'\\s+preempt').test(body))rec.preempt=false;
        if(rec.vip)groups.push(rec);
      }
      // IPv6（2026-08-18 新增，官方 Arista EOS User Manual 確認 IPv6 VRRP 用獨立的
      // "vrrp N ipv6 ADDR" 宣告——N 是該 IPv6 群組自己的 vrid（可能與同介面 IPv4 群組的
      // vrid 相同或不同，非強制共用同一 vrid 命名空間），啟用前提須先在某個 vrid 上宣告
      // "vrrp N ipv4 version 3"（v2 僅支援 IPv4，此工具不驗證此前提，僅解析欄位值）；
      // 依 interface+vrid 合併回既有 IPv4 記錄，找不到則新增獨立記錄
      const vridSet6=new Set([...body.matchAll(/vrrp\s+(\d+)\s+ipv6\s+(\S+)/g)].map(x=>x[1]));
      for(const vrid of vridSet6){
        const re6=new RegExp('vrrp\\s+'+vrid+'\\s+ipv6\\s+(\\S+)','g');
        const m6=re6.exec(body);
        if(!m6)continue;
        const vip6=m6[1];
        const existing=groups.find(g=>g.interface===iface&&g.vrid===vrid);
        if(existing)existing.vip6=vip6;
        else groups.push({vrid,interface:iface,vip:'',vip6,priority:'100',preempt:true,authMode:'',trackIf:'',trackReduced:'',version:'2'});
      }
    }
  } else if(vendor==='ruijie'){
    // Ruijie RGOS：官方語法 "vrrp N ip VIP"（VLAN/interface 子模式下），非 HSRP，
    // 不可誤用 cisco 分支解析。priority/preempt 沿用 comware/aruba 已查證過的常見寫法
    // "vrrp N priority P"／"vrrp N preempt"，尚無真實範例逐字驗證，信心度較低
    const raw=cfg.split('\ninterface ');
    const merged={};
    for(const blk of raw.slice(1)){
      const name=blk.split('\n')[0].trim();
      const body=blk.slice(name.length);
      merged[name]=(merged[name]||'')+body;
    }
    for(const [iface,body] of Object.entries(merged)){
      if(!/vrrp\s+\d+\s+ip\s+\d/.test(body))continue;
      const vridSet=new Set([...body.matchAll(/vrrp\s+(\d+)\s+ip\s+\d/g)].map(x=>x[1]));
      for(const vrid of vridSet){
        const re=new RegExp('vrrp\\s+'+vrid+'\\s+([^\\n]+)','g');
        const rec={vrid,interface:iface,vip:'',priority:'100',preempt:false,authMode:'',trackIf:'',trackReduced:'',version:'2'};
        let line;
        while((line=re.exec(body))!==null){
          const rest=line[1].trim();
          if(/^ip\s+\d/.test(rest))rec.vip=(rest.match(/ip\s+(\S+)/)||[])[1]||'';
          else if(/^priority\s/.test(rest))rec.priority=(rest.match(/priority\s+(\d+)/)||[])[1]||'100';
          else if(/^preempt/.test(rest))rec.preempt=true;
        }
        if(rec.vip)groups.push(rec);
      }
    }
  } else if(vendor==='netgear'){
    // Netgear M4300 (ICOS)：官方語法 "ip vrrp <vrid>"（interface config 建立 VRID）＋
    // "ip vrrp <vrid> mode"（啟用）／"ip vrrp <vrid> ip <vip> [secondary]"／
    // "ip vrrp <vrid> priority <n>"／"ip vrrp <vrid> preempt"／"ip vrrp <vrid>
    // authentication {none|simple key}"，與 comware/aruba/ruijie 同一種「vrid 為第二個
    // token、多行逐一設定」寫法，僅前綴多了 "ip"。preempt 官方預設值為 enabled，與
    // Arista/Extreme 同類「預設開啟」廠牌一致，需比對明確的 "no ip vrrp <vrid> preempt"
    // 才視為停用（2026-08-01 對外查證後修正，原版預設 false 且迴圈內見到 "preempt" 字樣
    // 就設 true，會把 "no ip vrrp N preempt" 誤判成啟用，比照既有 Arista 分支寫法修正）
    const raw=cfg.split('\ninterface ');
    const merged={};
    for(const blk of raw.slice(1)){
      const name=blk.split('\n')[0].trim();
      const body=blk.slice(name.length);
      merged[name]=(merged[name]||'')+body;
    }
    for(const [iface,body] of Object.entries(merged)){
      if(!/^\s*ip vrrp\s+\d+\s*$/m.test(body))continue;
      const vridSet=new Set([...body.matchAll(/^\s*ip vrrp\s+(\d+)\s*$/gm)].map(x=>x[1]));
      for(const vrid of vridSet){
        const re=new RegExp('ip vrrp\\s+'+vrid+'\\s+([^\\n]+)','g');
        const rec={vrid,interface:iface,vip:'',priority:'100',preempt:true,authMode:'',authKey:'',trackIf:'',trackReduced:'',version:'2'};
        let line;
        while((line=re.exec(body))!==null){
          const rest=line[1].trim();
          if(/^ip\s+\d/.test(rest))rec.vip=(rest.match(/^ip\s+(\S+)/)||[])[1]||'';
          else if(/^priority\s/.test(rest))rec.priority=(rest.match(/priority\s+(\d+)/)||[])[1]||'100';
          else if(/^authentication\s+simple\s/.test(rest)){rec.authMode='simple';rec.authKey=(rest.match(/simple\s+(\S+)/)||[])[1]||'';}
        }
        if(new RegExp('no\\s+ip vrrp\\s+'+vrid+'\\s+preempt').test(body))rec.preempt=false;
        if(rec.vip)groups.push(rec);
      }
    }
  } else if(vendor==='nxos'){
    // Cisco NX-OS HSRP：巢狀在 interface vlan N 區塊內的 "hsrp <group>" 子區塊
    // （非 Cisco classic HSRP 那種同層級的 "standby N ip X"），已查證官方 NX-OS
    // Unicast Routing Configuration Guide 語法：
    //   interface vlan 1
    //     hsrp 0
    //       preempt
    //       priority 100
    //       ip 192.0.2.2
    // preempt 預設關閉，需顯式 "preempt" 才開啟（比照傳統 Cisco HSRP 慣例，與 Arista VRRP 相反）
    const raw=cfg.split('\ninterface ');
    for(const blk of raw.slice(1)){
      const name=blk.split('\n')[0].trim();
      const body=blk.slice(name.length);
      if(!/^\s+hsrp\s+\d/m.test(body))continue;
      let cur=null, groupIndent=0;
      for(const line of body.split('\n')){
        const mGrp=line.match(/^(\s+)hsrp\s+(\d+)\s*$/);
        if(mGrp){
          if(cur&&(cur.vip||cur.vip6))groups.push(cur);
          groupIndent=mGrp[1].length;
          cur={vrid:mGrp[2],interface:name,vip:'',vip6:'',priority:'100',preempt:false,authMode:'',trackIf:'',trackReduced:'',version:'HSRP',type:'HSRP'};
          continue;
        }
        if(!cur)continue;
        const indentM=line.match(/^(\s*)\S/);
        const lineIndent=indentM?indentM[1].length:0;
        if(!line.trim()||lineIndent<=groupIndent){ if(cur&&(cur.vip||cur.vip6))groups.push(cur); cur=null; continue; }
        const mVip=line.match(/^\s+ip\s+(\S+)/); if(mVip){cur.vip=mVip[1]; continue;}
        // IPv6（2026-08-18 新增，NX-OS 官方文件確認 HSRP for IPv6 沿用與 Cisco IOS-XE 同款
        // "standby version 2" 前提＋"ipv6 autoconfig"／"ipv6 ADDR" 機制；NX-OS 巢狀 hsrp N {}
        // 區塊內既有 ip/priority/preempt 皆為同層級 sibling 行，ipv6 比照同一模式新增為另一
        // sibling 行，未取得 NX-OS 巢狀寫法的逐字官方範例，但與既有已查證的巢狀區塊結構
        // 一致，信心度中高）
        const mVip6=line.match(/^\s+ipv6\s+(\S+)/); if(mVip6){cur.vip6=mVip6[1]; continue;}
        const mPrio=line.match(/^\s+priority\s+(\d+)/); if(mPrio){cur.priority=mPrio[1]; continue;}
        if(/^\s+preempt\b/.test(line)){cur.preempt=true; continue;}
      }
      if(cur&&(cur.vip||cur.vip6))groups.push(cur);
    }
  }
  return groups;
}

// ══════════════════════════════════════════════════════
//  VXLAN PARSER (全廠牌)
// ══════════════════════════════════════════════════════
function parseVXLAN(cfg, vendor){
  const result={vtep:'',vnis:[],evpn:[],tunnelMode:''};
  if(vendor==='comware'){
    // VTEP source from NVE interface
    const nveMatch=cfg.match(/interface Nve\d+[\s\S]*?(?=\n#|\ninterface (?!Nve))/);
    if(nveMatch){
      const nveBlk=nveMatch[0];
      result.vtep=(nveBlk.match(/source VTEP\s+(\S+)/)||[])[1]||
                  (nveBlk.match(/source\s+(\S+)/)||[])[1]||'';
      // VNI entries under NVE
      const vniRe=/vni\s+(\d+)\s+head-end\s+peer-list\s+([^\n]+)/g;let vm;
      while((vm=vniRe.exec(nveBlk))!==null){
        const peers=vm[2].trim()==='protocol bgp'?[]:(vm[2].trim().split(/\s+/));
        result.vnis.push({vni:vm[1],mode:vm[2].includes('bgp')?'BGP-EVPN':'Static',peers,vlan:'',name:''});
      }
    }
    // If no NVE, check source from vxlan tunnel-mac-learning line
    if(!result.vtep&&/vxlan tunnel-mac-learning/.test(cfg))result.tunnelMode='vxlan';
    // VSI blocks: "vxlan vsi VSI-NAME"
    const vsiRe=/^vxlan vsi\s+(\S+)\n([\s\S]*?)(?=^vxlan vsi|\n#\s*\n|(?![\s\S]))/gm;let vsm;
    while((vsm=vsiRe.exec(cfg))!==null){
      const vsiName=vsm[1],body=vsm[2];
      const vni=(body.match(/vxlan vni\s+(\d+)/)||[])[1]||'';
      const encap=(body.match(/evpn encapsulation\s+(\S+)/)||[])[1]||'';
      const gw=(body.match(/default-gateway ip-address\s+(\S+)/)||[])[1]||'';
      // Match this VSI's VNI to an existing NVE VNI entry
      const nveEntry=result.vnis.find(v=>v.vni===vni);
      if(nveEntry){nveEntry.name=vsiName;nveEntry.encap=encap;nveEntry.gw=gw;}
      else if(vni)result.vnis.push({vni,mode:encap?'BGP-EVPN':'Static',peers:[],vlan:'',name:vsiName,encap,gw});
    }
    // EVPN vpn-instance
    const evpnRe=/^evpn vpn-instance\s+(\S+)\n([\s\S]*?)(?=^evpn|\n#\s*\n|(?![\s\S]))/gm;let evm;
    while((evm=evpnRe.exec(cfg))!==null){
      const name=evm[1],body=evm[2];
      const rd=(body.match(/route-distinguisher\s+(\S+)/)||[])[1]||'';
      const rtImport=(body.match(/vpn-target\s+(\S+)\s+import/)||[])[1]||'';
      const rtExport=(body.match(/vpn-target\s+(\S+)\s+export/)||[])[1]||'';
      result.evpn.push({name,rd,rtImport,rtExport});
    }
    // Source IP from LoopBack if NVE not found
    if(!result.vtep){const loIp=(cfg.match(/interface LoopBack\d+[\s\S]*?ip address\s+(\S+)/)||[])[1]||'';result.vtep=loIp;}
  } else if(vendor==='aruba'){
    // Aruba CX has multiple VXLAN styles:
    // 1) top-level "vxlan" block with source-interface/source-ip and vni blocks
    // 2) "interface vxlan 1" block used by AOS-CX EVPN VXLAN designs
    // 3) VLAN blocks carrying vni/vxlan vni mapping
    const addVni=(rec)=>{
      if(!rec.vni)return;
      const found=result.vnis.find(v=>v.vni===rec.vni);
      if(found){Object.assign(found,{...rec,peers:[...(found.peers||[]),...(rec.peers||[])]});found.peers=[...new Set(found.peers||[])];}
      else result.vnis.push({mode:'VXLAN',peers:[],vlan:'',name:'',encap:'vxlan',gw:'',...rec});
    };
    const parseVniBlocks=(body)=>{
      const vniBlocks=body.split(/(?=^\s+vni\s+\d+)/m).filter(b=>/^\s+vni\s+\d+/m.test(b));
      for(const blk of vniBlocks){
        const vni=(blk.match(/^\s+vni\s+(\d+)/m)||[])[1]||'';
        const name=(blk.match(/^\s+name\s+(.+)/m)||[])[1]?.trim()||'';
        const vlan=(blk.match(/^\s+vlan\s+(\d+)/m)||[])[1]||'';
        const vrf=(blk.match(/^\s+vrf\s+(\S+)/m)||[])[1]||'';
        const rd=(blk.match(/^\s+rd\s+(\S+)/m)||[])[1]||'';
        const gw=(blk.match(/^\s+(?:distributed-gateway|default-gateway)\s+(?:ip\s+)?(\S+)/m)||[])[1]||'';
        const peers=[...blk.matchAll(/^\s+(?:vtep-peer|peer)\s+(\S+)/gm)].map(x=>x[1]);
        if(vni)addVni({vni,mode:/evpn|route-target|rd\s+/i.test(blk)?'BGP-EVPN':'VXLAN',peers,vlan,name:name||vrf,encap:'vxlan',gw,rd});
      }
    };

    const vxMatch=cfg.match(/^\s*vxlan\s*$[\s\S]*?(?=^\S|(?![\s\S]))/m);
    if(vxMatch){
      const body=vxMatch[0];
      result.vtep=(body.match(/^\s*source-interface\s+(.+)$/m)||[])[1]?.trim()||
                  (body.match(/^\s*source-ip\s+(\S+)/m)||[])[1]||
                  (body.match(/^\s*source\s+ip\s+(\S+)/m)||[])[1]||result.vtep;
      result.tunnelMode='vxlan';
      parseVniBlocks(body);
    }

    const ifvxRe=/^interface\s+vxlan\s+\d+\s*\n([\s\S]*?)(?=^interface\s+|^vlan\s+|^router\s+|^vrf\s+|^bgp\s+|^user\s+|^end\b|(?![\s\S]))/gm;
    let im;
    while((im=ifvxRe.exec(cfg))!==null){
      const body=im[1];
      result.vtep=(body.match(/^\s*source\s+(?:ip\s+)?(\S+)/m)||[])[1]||
                  (body.match(/^\s*source-interface\s+(.+)$/m)||[])[1]?.trim()||result.vtep;
      result.tunnelMode='vxlan';
      parseVniBlocks(body);
    }

    // VLAN-to-VNI mappings can also be defined directly under VLAN sections.
    const vlanRe=/^vlan\s+(\d+)\s*\n([\s\S]*?)(?=^vlan\s+\d+|^interface\s+|^router\s+|^vrf\s+|^bgp\s+|^user\s+|^end\b|(?![\s\S]))/gm;
    let vm;
    while((vm=vlanRe.exec(cfg))!==null){
      const vlan=vm[1],body=vm[2];
      const vni=(body.match(/^\s*(?:vxlan\s+)?vni\s+(\d+)/m)||[])[1]||'';
      const name=(body.match(/^\s*name\s+(.+)/m)||[])[1]?.trim()||'';
      if(vni)addVni({vni,vlan,name,mode:'VXLAN',encap:'vxlan'});
    }

    // EVPN information from BGP blocks, if present.
    const bgpEvpn=cfg.match(/(?:^|\n)\s*(?:address-family\s+)?l2vpn\s+evpn[\s\S]*?(?=^\s*address-family\s+|^\S|(?![\s\S]))/m);
    if(bgpEvpn){
      result.evpn.push({name:'l2vpn evpn',rd:'',rtImport:'',rtExport:''});
      result.vnis.forEach(v=>{if(v.mode==='VXLAN')v.mode='BGP-EVPN';});
    }
  } else if(vendor==='nxos'){
    // 2026-08-20 新增，官方 Cisco NX-OS VXLAN Configuration Guide（9.2x-10.6x 多版本交叉比對，
    // cisco.com 直接 fetch 被 WAF 擋 403，改用搜尋引擎索引摘要佐證，信心度中高）確認語法：
    //   vlan N / vn-segment VNI（L2 VNI 對應）
    //   interface nve1 / source-interface loopbackX / host-reachability protocol bgp /
    //     member vni VNI [mcast-group IP | associate-vrf]（同行尾綴與換行巢狀子模式皆存在，
    //     故用區塊切片後在整段文字內搜尋關鍵字，不依賴嚴格行內/巢狀位置）
    //   evpn / vni VNI l2 / rd RD / route-target import|export RT（僅 L2 VNI；L3 VNI 的
    //     RD/RT 定義在 vrf context 內，語法不同，不納入此陣列）
    // gw（anycast gateway）查證語法片段不完整，非本輪範圍，固定留空。
    const vlanOfVni=new Map();
    for(const b of cfg.split(/^(?=vlan\s+\d)/m)){
      const vM=b.match(/^vlan\s+(\d+)/); const vnM=b.match(/^\s+vn-segment\s+(\d+)/m);
      if(vM&&vnM)vlanOfVni.set(vnM[1],vM[1]);
    }
    const vrfOfVni=new Map();
    for(const b of cfg.split(/^(?=vrf context\s)/m)){
      const nM=b.match(/^vrf context\s+(\S+)/); const vnM=b.match(/^\s+vni\s+(\d+)/m);
      if(nM&&vnM)vrfOfVni.set(vnM[1],nM[1]);
    }
    const nveM=cfg.match(/^interface\s+nve\d+\s*\n([\s\S]*?)(?=^\S|(?![\s\S]))/im);
    if(nveM){
      const nveBody=nveM[1];
      result.tunnelMode='vxlan';
      const hostReachBgp=/^\s*host-reachability protocol bgp\s*$/m.test(nveBody);
      const srcIf=(nveBody.match(/^\s*source-interface\s+(\S+)/m)||[])[1]||'';
      if(srcIf){
        const loRe=new RegExp('^interface\\s+'+srcIf.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\s*\\n([\\s\\S]*?)(?=^\\S|(?![\\s\\S]))','im');
        const loM=cfg.match(loRe);
        result.vtep=loM?(loM[1].match(/^\s*ip address\s+(\S+?)(?:\/\d+)?\s*$/m)||[])[1]||'':'';
      }
      const memberChunks=nveBody.split(/(?=^\s+member vni\s+\d+)/m).filter(c=>/^\s+member vni\s+\d+/.test(c));
      for(const chunk of memberChunks){
        const vni=(chunk.match(/^\s+member vni\s+(\d+)/)||[])[1];
        if(!vni)continue;
        const isL3=/associate-vrf/.test(chunk);
        const mcast=(chunk.match(/mcast-group\s+(\S+)/)||[])[1]||'';
        result.vnis.push({
          vni, mode:hostReachBgp?'BGP-EVPN':'Static',
          peers:mcast?[mcast]:[], vlan:vlanOfVni.get(vni)||'',
          name:isL3?(vrfOfVni.get(vni)||''):'', encap:'vxlan', gw:'',
        });
      }
    }
    const evpnM=cfg.match(/^evpn\s*\n([\s\S]*?)(?=^\S|(?![\s\S]))/im);
    if(evpnM){
      const chunks=evpnM[1].split(/(?=^\s+vni\s+\d+\s+l2)/m).filter(c=>/^\s+vni\s+\d+\s+l2/.test(c));
      for(const c of chunks){
        const vni=(c.match(/^\s+vni\s+(\d+)\s+l2/)||[])[1];
        if(!vni)continue;
        result.evpn.push({
          name:'L2VNI-'+vni,
          rd:(c.match(/^\s+rd\s+(\S+)/m)||[])[1]||'',
          rtImport:(c.match(/^\s+route-target import\s+(\S+)/m)||[])[1]||'',
          rtExport:(c.match(/^\s+route-target export\s+(\S+)/m)||[])[1]||'',
        });
      }
    }
  }
  return(result.vnis.length||result.evpn.length||result.vtep)?result:null;
}


// ── renderVRRP ───────────────────────────────────────────────
