// ═══ app.js ═══
// ═════════════════════════════════════════════════// ═══ app.js ═══
// ═══════════════════════════════════════════════════════════════
//  APP.JS — Main Controller v3.0
//  Features: 4-vendor parse, 12-path convert, user permissions
// ═══════════════════════════════════════════════════════════════
const App = (() => {
  const ST = { f:null, s:null, c:null, p:null, j:null, x:null, w:null, m:null, a:null, t:null, z:null, r:null, u:null, g:null, raw:{f:'',s:'',c:'',p:'',j:'',x:'',w:'',m:'',a:'',t:'',z:'',r:'',u:'',g:''} };
  let PARSED=null, CURRENT_SECTION=null, CURRENT_DATA=[], _renderState=null, WIFI_DATA = null, FORTISWITCH_DATA = null;
  // WiFi/WLAN 解析（2026-08-19 對外查證擴大）：sophos(s)/sonicwall(w) 查無可信 CLI/config
  // 語法佐證，維持排除；其餘企業防火牆廠牌架構上無內建 WiFi，不列入（無功能可警示，非
  // 查證不足）。用 ST.raw 的單字母 slot key（非 vendor 字串），比照 FW_SLOT_VENDOR 慣例。
  // 宣告在此共用頂層作用域（非 analyze() 內部），renderSection() 才能存取到
  const WIFI_UNSUPPORTED=['s','w'];
  // NAT/VPN/Users 查無官方 schema 佐證的廠牌白名單（2026-08-26 新增，WatchGuard 一次補齊
  // 三項；比照上方 WIFI_UNSUPPORTED 設計精神，但刻意各自獨立宣告——NAT/VPN/Users 是三個
  // 各自獨立的分頁/功能，未來若某廠牌只有其中一項查無佐證，不該被迫綁在同一份清單）。
  // 與 WIFI_UNSUPPORTED 的差異：WIFI_DATA 是完全獨立於 PARSED 之外的旁路全域變數，
  // nat/vpn/users 則是 PARSED 的核心陣列欄位，merge()/renderSection() 全部假設是陣列
  // （無 optional chaining guard），故 WatchGuardParser 對這三個欄位一律回傳 []（非 null），
  // 這份清單只影響「分頁顯示什麼文字」的判斷，不影響底層資料形狀
  const NAT_UNSUPPORTED=['g'];
  const VPN_UNSUPPORTED=['g'];
  const USERS_UNSUPPORTED=['g'];
  // Query 追蹤結果快取：畫面渲染當下的查詢結果依賴使用者當時輸入的 src/dst/proto/port，
  // 無法在匯出當下重新計算，故需快取「最近一次查詢」的結果供 CSV 匯出按鈕讀取。
  // Audit 分析（shadow/unused-addr/unused-svc/compliance）則不需要快取，因為
  // analyzeRuleShadowing()/analyzeUnusedObjects()/analyzeCompliance() 都是純函式，
  // CSV 匯出按鈕直接在點擊當下用目前的 PARSED 即時計算即可，避免「使用者尚未切到
  // Audit 分頁時得到的空白 CSV」與「切過分頁但真的 0 筆結果」兩種情況無法區分
  // （唯讀稽核發現的既有 UX 疑慮，此設計直接消除該疑慮而非加視覺提示遮蓋）
  let LAST_QUERY_TRACE = null;
  let CONV_RESULT='', CONV_TARGET='', CONV_SRC_VENDOR='';
  let ACTIVE_VDOM='__all__';  // '__all__' or specific vdom name

  const $=id=>document.getElementById(id);
  const sz=b=>b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB';
  // 2026-08-09 稽核修復：原本未跳脫雙引號，但被用在 title="${esc(r.app)}"（PaloAlto
  // application 欄位，來自上傳設定檔原始文字，未經字元白名單過濾）、<option value="${esc(v)}">
  // （VDOM 名稱）等雙引號屬性內，惡意設定檔可構造含 " 的欄位值提前結束屬性、注入事件
  // 處理器，構成儲存型 XSS；補上雙引號跳脫
  const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const ms=t=>new Promise(r=>setTimeout(r,t));
  const pill=(t,c)=>`<span class="pill ${c}">${esc(t)}</span>`;
  const nameMap={f:'fc-name',s:'sc-name',c:'cc-name',p:'pc-name',j:'jc-name',x:'xc-name',w:'wc-name',m:'mc-name',a:'ac-name',t:'tc-name',z:'zc-name',r:'rc-name',u:'uc-name',g:'gc-name'};
  const chipMap={f:'fc-chip',s:'sc-chip',c:'cc-chip',p:'pc-chip',j:'jc-chip',x:'xc-chip',w:'wc-chip',m:'mc-chip',a:'ac-chip',t:'tc-chip',z:'zc-chip',r:'rc-chip',u:'uc-chip',g:'gc-chip'};
  const inpMap ={f:'fi',s:'si',c:'ci',p:'pi',j:'ji',x:'xi',w:'wi',m:'mi',a:'ai',t:'ti',z:'zi',r:'ri',u:'ui',g:'gi'};

  // 2026-07-17 新增：上傳廠牌特徵檢查。原本 10 個上傳欄位完全沒有內容檢查，貼錯廠牌會
  // 靜默解析出空/垃圾結果（analyze() 一律用「上傳到哪個欄位」寫死對應 parser，見下方
  // parseWithYield()）。簽章規則移植自 config_anonymizer 的 VENDOR_SIGS/detectVendor()
  // （純正則比對，min 門檻已針對誤判風險調校過，此處僅取 firewall_analyzer 用得到的
  // 9 個廠牌，不含交換器廠牌），僅在偵測結果為明確的「其他」已知廠牌時警告，未命中任何
  // 簽章（unknown）維持現狀不提示，避免對合法但精簡的匯出檔誤報。
  const FW_VENDOR_SIGS = {
    fortigate:  { p:[/^#config-version=/m, /^config system global/m, /FortiGate-/i], min:1 },
    paloalto:   { p:[/^set deviceconfig system/m, /^set vsys vsys/m, /Palo Alto Networks/i], min:1 },
    // Junos 設定檔有兩種輸出風格：扁平 "set" 格式（config_anonymizer 原始簽章僅涵蓋此
    // 風格）與階層式大括號格式（"system { host-name X; }"）；JuniperParser 本身兩種皆
    // 支援解析，簽章比對若只認 set 格式會對大括號格式真實匯出檔誤判為 unknown，已補上
    // 對應訊號（2026-07-17 測試 juniper_srx_test.conf 大括號格式時發現此落差）
    juniper:    { p:[/^set system host-name/m, /^set interfaces .* family inet/m, /Juniper Networks|JUNOS/i, /^system\s*\{/m, /^\s*host-name\s+\S+;/m], min:1 },
    checkpoint: { p:[/^set hostname /m, /^set interface .* ipv4-address/m, /Check Point/i], min:2 },
    // <opnsense> 根標籤訊號：OPNsense（pfSense fork，沿用同一個 PfsenseParser，非獨立
    // vendor id）官方 config.xml.sample 已查證根標籤是 <opnsense> 非 <pfsense>，第二個
    // 訊號 /pfSense|OPNsense/i 本來就會命中 OPNsense 匯出檔內的字樣，此為額外穩健度補強
    pfsense:    { p:[/<pfsense>/i, /<opnsense>/i, /pfSense|OPNsense/i, /<version>[\d.]+<\/version>/], min:1 },
    sonicwall:  { p:[/<SonicWALLconfig/i, /SonicWall|SonicOS/i], min:1 },
    mikrotik:   { p:[/^\/ip\s+(?:firewall|address|route)/m, /^\/system\s+identity/m, /RouterOS/i], min:1 },
    ciscoasa:   { p:[/^ASA Version\s+\S+/m, /^NGFW Version\s+\S+/m, /^nameif\s+\S+/m, /^failover\s*$/m], min:1 },
    // min 由 1 提高為 2：單靠字面 "Sophos" 一個訊號太寬鬆，其他廠牌設定檔內若剛好有一行
    // 註解提到 Sophos 就會誤判；額外補上第 4 個 XML schema 訊號（Sophos XG 匯出檔特有標籤）
    sophos:     { p:[/Sophos/i, /<Configuration[^>]*SophosFirewall/, /^set admin-settings/m, /<(?:IPHostList|FirewallRuleList|WebFilterPolicy|IPsecVPNList)>/], min:2 },
    // secure-policy／address-object／service-object 為 ZLD 專屬關鍵字，其餘 9 家皆不使用，
    // min:2 要求至少命中兩個訊號（secure-policy 規則開頭 + address-object 或 service-object
    // 定義行其中之一），避免單一關鍵字巧合誤判
    zyxel:      { p:[/^secure-policy\s+(?:insert\s+)?\d+/m, /^address-object\s+\S+\s+\S+/m, /^service-object\s+\S+\s+(tcp|udp)/im, /ZyWALL|USG FLEX|Zyxel/i], min:2 },
    // EdgeOS config.boot 是巢狀大括號格式，頂層區塊名稱（system{}/interfaces{}/firewall{}）
    // 與 Junos 大括號格式重疊，故簽章刻意避開這些通用區塊名稱，只採 EdgeOS 特有關鍵字
    // （ethernet ethN 介面命名、default-action、outbound-interface、address-group 皆為
    // Junos 不會出現的寫法），min:2 確保不會與 juniper 訊號混淆
    edgerouter: { p:[/ethernet\s+eth\d+\s*\{/m, /default-action\s+(drop|accept)/m, /outbound-interface\s+\S+/m, /address-group\s+\S+\s*\{/m, /UBNT|EdgeRouter|EdgeOS|EdgeMax/i], min:2 },
    // UCI（package/config/option/list stanza 格式）與其餘 21 家皆不同語法家族，本身格式辨識度
    // 已高，仍用 min:2 避免巧合誤判：config interface／option proto／firewall 專屬區塊
    // （zone/rule/redirect/forwarding）／package 標頭字樣，任兩者命中即可
    openwrt:    { p:[/^config\s+interface(\s|$)/m, /^\s*option\s+proto\s/m, /^config\s+(zone|rule|redirect|forwarding)(\s|$)/m, /^package\s+(network|firewall|dhcp)/m], min:2 },
    // WatchGuard Firebox 匯出的扁平 XML（每種物件一個 -list 容器＋重複子節點，非 Palo Alto
    // 那種深巢狀 <entry name="">），這幾個標籤名稱為 WatchGuard 特有、其餘 22 家皆不使用
    // （官方社群 parser ins1gn1a/WatchGuard-Config-Parser 已查證），min:2 避免巧合誤判
    watchguard: { p:[/<abs-policy-list/i, /<interface-list/i, /<address-group-list/i, /<alias-member-list/i], min:2 },
  };
  // sophos 簽章相對寬鬆，排最後，讓其他更具結構特徵的廠牌訊號優先判定
  const FW_VENDOR_ORDER = ['fortigate','edgerouter','openwrt','watchguard','paloalto','juniper','checkpoint','pfsense','sonicwall','mikrotik','ciscoasa','zyxel','sophos'];
  function detectFwVendor(text) {
    for (const id of FW_VENDOR_ORDER) {
      const { p, min } = FW_VENDOR_SIGS[id];
      let m = 0;
      for (const pat of p) { if (pat.test(text)) m++; }
      if (m >= min) return id;
    }
    return 'unknown';
  }

  // Junos `display set` 扁平格式偵測（2026-08-24 新增，見 parser-juniper.js 開頭同日註解）：
  // 大括號階層格式（parseJunosTree() 支援）幾乎必含 '{'；display set 匯出是連續多行裸
  // "set ..." 指令、完全無大括號。純函式抽出以利測試（DOM 無關），呼叫端見 analyze()。
  function isJunosDisplaySet(text) {
    if (!text || /\{/.test(text)) return false;
    return (text.match(/^set\s+\S/gm) || []).length >= 3;
  }

  function pickFile(v,inp){
    if(!inp.files.length)return;
    const f=inp.files[0]; ST[v]=f;
    $(nameMap[v]).textContent=`${f.name} (${sz(f.size)})`;
    $(chipMap[v]).style.display='flex';
    updBtn();
  }
  window.pickFile=pickFile;

  function clearFile(e,v){
    e.stopPropagation(); ST[v]=null; ST.raw[v]='';
    $(inpMap[v]).value=''; $(chipMap[v]).style.display='none'; updBtn();
  }
  window.clearFile=clearFile;

  function handleDrop(e,v){
    e.preventDefault();e.stopPropagation();
    const cardMap={f:'fc',s:'sc',c:'cc',p:'pc',j:'jc',x:'xc',w:'wc',m:'mc',a:'ac',t:'tc',z:'zc',r:'rc',u:'uc',g:'gc'};
    $(cardMap[v]).classList.remove('drag-over');
    const f=e.dataTransfer.files[0]; if(!f)return;
    ST[v]=f; $(nameMap[v]).textContent=`${f.name} (${sz(f.size)})`; $(chipMap[v]).style.display='flex'; updBtn();
  }
  window.handleDrop=handleDrop;

  function updBtn(){
    const ok=ST.f||ST.s||ST.c||ST.p||ST.j||ST.x||ST.w||ST.m||ST.a||ST.t||ST.z||ST.r||ST.u||ST.g;
    $('btn-go').disabled=!ok;
    $('analyze-hint').textContent=ok?tr('analyze.selected_prefix')+[ST.f?'FortiGate':'',ST.s?'Sophos':'',ST.c?'CheckPoint':'',ST.p?'PaloAlto':'',ST.j?'Juniper':'',ST.x?'pfSense':'',ST.w?'SonicWall':'',ST.m?'MikroTik':'',ST.a?'Cisco ASA':'',ST.t?'Cisco FTD':'',ST.z?'Zyxel':'',ST.r?'EdgeRouter':'',ST.u?'OpenWrt':'',ST.g?'WatchGuard':''].filter(Boolean).join(' + '):tr('analyze.hint_none');
  }
  window.updBtn=updBtn;

  // 統一在此正規化 CRLF：此為所有上傳設定檔文字的唯一讀取入口，供 parseWithYield／parseFortigateWifi／
  // parseFortigateSwitchController／以及其他直接讀取 ST.raw.* 的側路徑共用，避免各處逐行正則因 \r 悄悄漏抓或污染擷取值
  function readFile(f){return new Promise((res,rej)=>{const r=new FileReader();r.onload=e=>res(e.target.result.replace(/\r\n/g,'\n'));r.onerror=()=>rej(new Error(tr('err.read_fail')+': '+f.name));r.readAsText(f,'UTF-8');});}

  // ── 新舊設定檔比對：上傳/廠牌選擇（獨立於 ST/PARSED，避免耦合單一設定分析流程）──
  const FW_VENDOR_META=[
    {key:'fortigate',label:'FortiGate',accept:'.conf,.txt,.cfg,.log'},
    {key:'sophos',label:'Sophos XG/XGS',accept:'.xml,.conf,.txt,.cfg'},
    {key:'checkpoint',label:'Check Point',accept:'.txt,.conf,.C,.W,.fws,.cfg'},
    {key:'paloalto',label:'Palo Alto',accept:'.xml,.txt,.conf,.cfg'},
    {key:'juniper',label:'Juniper SRX',accept:'.conf,.txt,.log,.cfg'},
    {key:'pfsense',label:'pfSense/OPNsense',accept:'.xml,.conf'},
    {key:'sonicwall',label:'SonicWall',accept:'.exp,.xml'},
    {key:'mikrotik',label:'MikroTik RouterOS',accept:'.rsc,.txt,.conf,.backup'},
    {key:'ciscoasa',label:'Cisco ASA',accept:'.txt,.conf,.cfg'},
    {key:'ciscoftd',label:'Cisco Firepower/FTD',accept:'.txt,.conf,.cfg'},
    {key:'zyxel',label:'Zyxel USG/ATP (ZLD)',accept:'.txt,.conf,.cfg'},
    {key:'edgerouter',label:'EdgeRouter (EdgeOS)',accept:'.boot,.txt,.conf,.cfg'},
    {key:'openwrt',label:'OpenWrt (UCI)',accept:'.txt,.conf,.cfg'},
    {key:'watchguard',label:'WatchGuard Firebox',accept:'.xml'},
  ];
  const FW_DIFF_PARSERS={
    fortigate:t=>FortigateParser.parse(t), sophos:t=>SophosParser.parse(t),
    checkpoint:t=>CheckpointParser.parse(t), paloalto:t=>PaloAltoParser.parse(t),
    juniper:t=>JuniperParser.parse(t), pfsense:t=>PfsenseParser.parse(t),
    sonicwall:t=>SonicWallParser.parse(t), mikrotik:t=>MikrotikParser.parse(t),
    ciscoasa:t=>CiscoASAParser.parse(t), ciscoftd:t=>CiscoFTDParser.parse(t),
    zyxel:t=>ZyxelParser.parse(t), edgerouter:t=>EdgeRouterParser.parse(t),
    openwrt:t=>OpenWrtParser.parse(t), watchguard:t=>WatchGuardParser.parse(t),
  };
  let DIFF_OLD_FILE=null, DIFF_NEW_FILE=null, DIFF_RESULT=null, _diffInited=false;
  function initDiffVendorSelect(){
    if(_diffInited)return; _diffInited=true;
    $('diff-vendor').innerHTML=FW_VENDOR_META.map(v=>`<option value="${v.key}">${esc(v.label)}</option>`).join('');
    onDiffVendorChange();
  }
  function onDiffVendorChange(){
    const meta=FW_VENDOR_META.find(v=>v.key===$('diff-vendor').value);
    if(!meta)return;
    $('diff-old-file').accept=meta.accept; $('diff-new-file').accept=meta.accept;
  }
  window.onDiffVendorChange=onDiffVendorChange;
  function _diffUpdateGoBtn(){$('diff-btn-go').disabled=!(DIFF_OLD_FILE&&DIFF_NEW_FILE);}
  function pickDiffFile(which,inp){
    if(!inp.files.length)return;
    const f=inp.files[0];
    if(which==='old')DIFF_OLD_FILE=f;else DIFF_NEW_FILE=f;
    $(`diff-${which}-name`).textContent=`${f.name} (${sz(f.size)})`;
    $(`diff-${which}-chip`).style.display='flex';
    _diffUpdateGoBtn();
  }
  window.pickDiffFile=pickDiffFile;
  function clearDiffFile(e,which){
    e.stopPropagation();
    if(which==='old')DIFF_OLD_FILE=null;else DIFF_NEW_FILE=null;
    $(`diff-${which}-file`).value=''; $(`diff-${which}-chip`).style.display='none';
    _diffUpdateGoBtn();
  }
  window.clearDiffFile=clearDiffFile;
  function handleDiffDrop(e,which){
    e.preventDefault();e.stopPropagation();
    $(`diff-${which}-card`).classList.remove('drag-over');
    const f=e.dataTransfer.files[0]; if(!f)return;
    if(which==='old')DIFF_OLD_FILE=f;else DIFF_NEW_FILE=f;
    $(`diff-${which}-name`).textContent=`${f.name} (${sz(f.size)})`;
    $(`diff-${which}-chip`).style.display='flex';
    _diffUpdateGoBtn();
  }
  window.handleDiffDrop=handleDiffDrop;
  async function runDiffCompare(){
    if(!DIFF_OLD_FILE||!DIFF_NEW_FILE)return;
    const vendor=$('diff-vendor').value;
    $('diff-result').innerHTML=`<div class="nodata">${esc(tr('diff.running'))}</div>`;
    try{
      const [oldText,newText]=await Promise.all([readFile(DIFF_OLD_FILE),readFile(DIFF_NEW_FILE)]);
      const oldParsed=FW_DIFF_PARSERS[vendor](oldText);
      const newParsed=FW_DIFF_PARSERS[vendor](newText);
      DIFF_RESULT=diffConfigs(oldParsed,newParsed);
      $('diff-result').innerHTML=buildDiffHtml(DIFF_RESULT);
    }catch(e){
      DIFF_RESULT=null;
      $('diff-result').innerHTML=`<div class="nodata" style="color:var(--red)">${esc(e.message)}</div>`;
    }
  }
  window.runDiffCompare=runDiffCompare;

  // Progress
  function setStep(n){for(let i=1;i<=8;i++){const el=$(`ps${i}`);if(!el)continue;const ico=el.querySelector('.pico');if(i<n){el.className='pstep done';ico.textContent='✓';}else if(i===n){el.className='pstep cur';ico.textContent='⏳';}else{el.className='pstep';ico.textContent='○';}}}

  // ── Analyze ──────────────────────────────────────────────────
  async function analyze(){
    hideErr();$('prog-overlay').classList.add('show');$('btn-go').disabled=true;
    try{
      setStep(1);
      // 警告訊息集中收集，最後一次顯示（避免大檔案警告與廠牌不符警告互相覆蓋）
      const warnMsgs=[];
      const totalSize = ['f','s','c','p','j','x','w','m','a','t','z','r','u','g'].reduce((s,k)=>s+(ST[k]?.size||0),0);
      if(totalSize > 5*1024*1024) {
        warnMsgs.push(tr('msg.large_file').replace('{size}', (totalSize/1024/1024).toFixed(1)));
      }
      if(ST.f)ST.raw.f=await readFile(ST.f);
      if(ST.s)ST.raw.s=await readFile(ST.s);
      if(ST.c)ST.raw.c=await readFile(ST.c);
      if(ST.p)ST.raw.p=await readFile(ST.p);
      if(ST.j)ST.raw.j=await readFile(ST.j);
      if(ST.x)ST.raw.x=await readFile(ST.x);
      if(ST.w)ST.raw.w=await readFile(ST.w);
      if(ST.m)ST.raw.m=await readFile(ST.m);
      if(ST.a)ST.raw.a=await readFile(ST.a);
      if(ST.t)ST.raw.t=await readFile(ST.t);
      if(ST.z)ST.raw.z=await readFile(ST.z);
      if(ST.r)ST.raw.r=await readFile(ST.r);
      if(ST.u)ST.raw.u=await readFile(ST.u);
      if(ST.g)ST.raw.g=await readFile(ST.g);
      // 上傳廠牌特徵檢查：偵測結果為明確的「其他」已知廠牌時警告（只警告不阻擋，
      // 分析流程照常進行），unknown（未命中任何簽章）維持現狀不提示
      const FW_SLOT_VENDOR={f:'fortigate',s:'sophos',c:'checkpoint',p:'paloalto',j:'juniper',x:'pfsense',w:'sonicwall',m:'mikrotik',a:'ciscoasa',t:'ciscoasa',z:'zyxel',r:'edgerouter',u:'openwrt',g:'watchguard'};
      const FW_SLOT_LABEL={f:'FortiGate',s:'Sophos XG/XGS',c:'Check Point',p:'Palo Alto',j:'Juniper SRX',x:'pfSense/OPNsense',w:'SonicWall',m:'MikroTik RouterOS',a:'Cisco ASA',t:'Cisco Firepower/FTD',z:'Zyxel USG/ATP',r:'EdgeRouter (EdgeOS)',u:'OpenWrt (UCI)',g:'WatchGuard Firebox'};
      const FW_DETECTED_LABEL={fortigate:'FortiGate',paloalto:'Palo Alto',juniper:'Juniper',checkpoint:'Check Point',pfsense:'pfSense/OPNsense',sonicwall:'SonicWall',mikrotik:'MikroTik RouterOS',ciscoasa:'Cisco ASA/FTD',sophos:'Sophos XG',zyxel:'Zyxel USG/ATP',edgerouter:'EdgeRouter (EdgeOS)',openwrt:'OpenWrt (UCI)',watchguard:'WatchGuard Firebox'};
      ['f','s','c','p','j','x','w','m','a','t','z','r','u','g'].forEach(v=>{
        if(!ST.raw[v])return;
        const detected=detectFwVendor(ST.raw[v]);
        if(detected!=='unknown'&&detected!==FW_SLOT_VENDOR[v]){
          warnMsgs.push(tr('msg.vendor_mismatch').replace('{slot}',FW_SLOT_LABEL[v]).replace('{detected}',FW_DETECTED_LABEL[detected]||detected));
        }
        // Junos `display set` 扁平格式（"show configuration | display set"，裸 "set ..." 行、
        // 無大括號階層）偵測：JuniperParser 的 parseJunosTree()/tokenizeJunos() 僅支援大括號
        // 階層格式（含單行變體），display set 語法完全不支援，靜默誤判/解析不完整卻無任何
        // 提示；比照上方 vendor_mismatch 慣例，非阻塞警告（解析仍會嘗試進行）
        if(v==='j'&&isJunosDisplaySet(ST.raw.j)){
          warnMsgs.push(tr('msg.junos_display_set_unsupported'));
        }
      });
      if(warnMsgs.length){
        $('err-bar').classList.add('show');
        $('err-msg').textContent=warnMsgs.join('　|　');
      }
      await ms(60);
      setStep(2);await ms(30);
      const parsedAll=[];
      // 大檔案 (>1.5MB) 使用 chunked 解析並讓 UI 保持響應
      async function parseWithYield(vendor, text) {
        await ms(0); // yield to browser
        // 統一在此正規化 CRLF，避免各廠牌解析器內上百處逐行正則因 \r 悄悄漏抓或污染擷取值
        text = text.replace(/\r\n/g, '\n');
        const parsers = {
          fortigate:  () => FortigateParser.parse(text),
          sophos:     () => SophosParser.parse(text),
          checkpoint: () => CheckpointParser.parse(text),
          paloalto:   () => PaloAltoParser.parse(text),
          juniper:    () => JuniperParser.parse(text),
          pfsense:    () => PfsenseParser.parse(text),
          sonicwall:  () => SonicWallParser.parse(text),
          mikrotik:   () => MikrotikParser.parse(text),
          ciscoasa:   () => CiscoASAParser.parse(text),
          ciscoftd:   () => CiscoFTDParser.parse(text),
          zyxel:      () => ZyxelParser.parse(text),
          edgerouter: () => EdgeRouterParser.parse(text),
          openwrt:    () => OpenWrtParser.parse(text),
          watchguard: () => WatchGuardParser.parse(text),
        };
        const result = parsers[vendor]();
        await ms(0); // yield after parse
        return result;
      }
      setStep(3);if(ST.raw.f){parsedAll.push(await parseWithYield('fortigate',ST.raw.f));}
      setStep(4);if(ST.raw.s){parsedAll.push(await parseWithYield('sophos',ST.raw.s));}
      setStep(5);if(ST.raw.c){parsedAll.push(await parseWithYield('checkpoint',ST.raw.c));}
      setStep(6);if(ST.raw.p){parsedAll.push(await parseWithYield('paloalto',ST.raw.p));}
      if(ST.raw.j){parsedAll.push(await parseWithYield('juniper',ST.raw.j));}
      if(ST.raw.x){parsedAll.push(await parseWithYield('pfsense',ST.raw.x));}
      if(ST.raw.w){parsedAll.push(await parseWithYield('sonicwall',ST.raw.w));}
      if(ST.raw.m){parsedAll.push(await parseWithYield('mikrotik',ST.raw.m));}
      if(ST.raw.a){parsedAll.push(await parseWithYield('ciscoasa',ST.raw.a));}
      if(ST.raw.t){parsedAll.push(await parseWithYield('ciscoftd',ST.raw.t));}
      if(ST.raw.z){parsedAll.push(await parseWithYield('zyxel',ST.raw.z));}
      if(ST.raw.r){parsedAll.push(await parseWithYield('edgerouter',ST.raw.r));}
      if(ST.raw.u){parsedAll.push(await parseWithYield('openwrt',ST.raw.u));}
      if(ST.raw.g){parsedAll.push(await parseWithYield('watchguard',ST.raw.g));}
      // Audit/Query 快取：重新解析新檔案時必須清除，否則使用者若先前在舊檔案上
      // 開過 Query 分頁，切換到新檔案後直接按「查詢追蹤結果」CSV 匯出按鈕會拿到
      // 舊檔案的過期查詢結果（唯讀稽核發現的既有 bug）
      LAST_QUERY_TRACE = null;
      // WiFi analysis（2026-08-19 擴大：原僅 FortiGate，對外查證後新增 mikrotik/openwrt/
      // pfsense 三家「自身即為 AP」架構的廠牌，合併各自 vaps 並重新計算共用 summary；
      // sophos/sonicwall 查證後查無語法佐證，維持排除，見下方 WIFI_UNSUPPORTED）
      WIFI_DATA = null;
      {
        const wifiParts = [];
        try { if (ST.raw.f && typeof parseFortigateWifi === 'function') wifiParts.push(parseFortigateWifi(ST.raw.f)); } catch(e) { console.warn('WiFi parse error (fortigate):', e); }
        try { if (ST.raw.m && typeof parseMikrotikWifi === 'function') wifiParts.push(parseMikrotikWifi(ST.raw.m)); } catch(e) { console.warn('WiFi parse error (mikrotik):', e); }
        try { if (ST.raw.u && typeof parseOpenWrtWifi === 'function') wifiParts.push(parseOpenWrtWifi(ST.raw.u)); } catch(e) { console.warn('WiFi parse error (openwrt):', e); }
        try { if (ST.raw.x && typeof parsePfsenseWifi === 'function') wifiParts.push(parsePfsenseWifi(ST.raw.x)); } catch(e) { console.warn('WiFi parse error (pfsense):', e); }
        if (wifiParts.length) {
          const allVaps = wifiParts.flatMap(p => p.vaps);
          const allWtpProfiles = wifiParts.flatMap(p => p.wtpProfiles);
          const allWtps = wifiParts.flatMap(p => p.wtps);
          const allWidsProfiles = wifiParts.flatMap(p => p.widsProfiles);
          const country = wifiParts.map(p => p.summary.country).find(c => c && c !== '-') || '-';
          WIFI_DATA = {
            vaps: allVaps, wtpProfiles: allWtpProfiles, wtps: allWtps, widsProfiles: allWidsProfiles,
            summary: buildWifiSummary(allVaps, allWtpProfiles, allWtps, allWidsProfiles, country),
          };
        }
        // 查證後明確排除的廠牌（非查證不足）：即使 nav-wifi 沒有真實資料，只要上傳了
        // 這些廠牌就仍顯示分頁，讓 wifi.no_data 的專屬警示文字可以被使用者看到，而非
        // 直接隱藏分頁導致使用者以為工具沒問題只是沒設定 WiFi
        const hasUnsupportedWifiUpload = WIFI_UNSUPPORTED.some(slot => ST.raw[slot]);
        const nw = $('nav-wifi');
        if (nw) nw.style.display = (WIFI_DATA && WIFI_DATA.summary.ssidCount > 0) || hasUnsupportedWifiUpload ? '' : 'none';
        const nb = $('nc-wifi');
        if (nb && WIFI_DATA && WIFI_DATA.summary.ssidCount > 0) nb.textContent = WIFI_DATA.summary.ssidCount;
        // Show WiFi export buttons in export view
        ['ec-wifi-ssid','ec-wifi-ap'].forEach(id => {
          const el = $(id);
          if (el) el.style.display = (WIFI_DATA && WIFI_DATA.summary.ssidCount > 0) ? '' : 'none';
        });
      }
      // FortiSwitch (FortiLink managed-switch) analysis (FortiGate only)
      FORTISWITCH_DATA = null;
      if (ST.raw.f && typeof parseFortigateSwitchController === 'function') {
        try {
          FORTISWITCH_DATA = parseFortigateSwitchController(ST.raw.f);
          const fsNav = $('nav-fortiswitch');
          if (fsNav) fsNav.style.display = FORTISWITCH_DATA.summary.switchCount > 0 ? '' : 'none';
          const fsCnt = $('nc-fortiswitch');
          if (fsCnt && FORTISWITCH_DATA.summary.switchCount > 0) fsCnt.textContent = FORTISWITCH_DATA.summary.switchCount;
          showEc('ec-fortiswitch-switches', (FORTISWITCH_DATA.switches?.length||0)>0);
          showEc('ec-fortiswitch-ports', (FORTISWITCH_DATA.ports?.length||0)>0);
          showEc('ec-fortiswitch-mac-policies', (FORTISWITCH_DATA.macPolicies?.length||0)>0);
          showEc('ec-fortiswitch-nac-policies', (FORTISWITCH_DATA.nacPolicies?.length||0)>0);
        } catch(e) { console.warn('FortiSwitch parse error:', e); }
      }
      setStep(7);await ms(20);setStep(8);await ms(60);
      PARSED=parsedAll.length===1?parsedAll[0]:parsedAll.reduce((a,b)=>merge(a,b));
      window._PARSED = PARSED; // 供 console 診斷：_PARSED._perVdom.map(v=>({name:v.name,routes:v.routes.length,policies:v.policies.length}))
      $('prog-overlay').classList.remove('show');
      onParsed();
      checkAnalyzeEggs(PARSED);
      clearTimeout(window._workTimer30); clearTimeout(window._workTimer60);
      window._workTimer30 = setTimeout(()=>showEggToast(tr('egg.work_30min'),5000), 1800000);
      window._workTimer60 = setTimeout(()=>showEggToast(tr('egg.work_60min'),5000), 3600000);
    }catch(err){
      $('prog-overlay').classList.remove('show');$('btn-go').disabled=false;
      showErr(err.message);console.error(err);
    }
  }
  window.analyze=analyze;

  function merge(a,b){
    return{
      vendor:[a.vendor,b.vendor].filter(Boolean).join(' + '),
      deviceInfo:{vendor:'Both',hostname:[a.deviceInfo.hostname,b.deviceInfo.hostname].filter(x=>x&&x!=='-').join(' / ')||'-',firmware:[a.deviceInfo.firmware,b.deviceInfo.firmware].filter(x=>x&&x!=='-').join(' / ')||'-',model:[a.deviceInfo.model,b.deviceInfo.model].filter(x=>x&&x!=='-').join(' / ')||'-',serial:'-',vdom:[]},
      interfaces:[...a.interfaces,...b.interfaces],policies:[...a.policies,...b.policies],routes:[...a.routes,...b.routes],
      vpn:[...a.vpn,...b.vpn],addresses:[...a.addresses,...b.addresses],services:[...a.services,...b.services],
      schedules:[...a.schedules,...b.schedules],nat:[...a.nat,...b.nat],users:[...a.users,...b.users],
      sdwan:{
        members:[...(a.sdwan?.members||[]),...(b.sdwan?.members||[])],
        healthChecks:[...(a.sdwan?.healthChecks||[]),...(b.sdwan?.healthChecks||[])],
        services:[...(a.sdwan?.services||[]),...(b.sdwan?.services||[])],
        neighbors:[...(a.sdwan?.neighbors||[]),...(b.sdwan?.neighbors||[])],
      },
      ha:(a.ha&&a.ha.enabled)?a.ha:((b.ha&&b.ha.enabled)?b.ha:(a.ha||b.ha||null)),
      dhcp:{
        servers:[...(a.dhcp?.servers||[]),...(b.dhcp?.servers||[])],
        relays:[...(a.dhcp?.relays||[]),...(b.dhcp?.relays||[])],
      },
      dns:{
        servers:[...(a.dns?.servers||[]),...(b.dns?.servers||[])],
        secondaries:[...(a.dns?.secondaries||[]),...(b.dns?.secondaries||[])],
        domain:(a.dns?.domain&&a.dns.domain!=='-')?a.dns.domain:(b.dns?.domain||'-'),
        proxy:!!(a.dns?.proxy||b.dns?.proxy),
        proxyRules:[...(a.dns?.proxyRules||[]),...(b.dns?.proxyRules||[])],
        dnsOverTls:!!(a.dns?.dnsOverTls||b.dns?.dnsOverTls),
        cacheSize:(a.dns?.cacheSize&&a.dns.cacheSize!=='-')?a.dns.cacheSize:(b.dns?.cacheSize||'-'),
        static:[...(a.dns?.static||[]),...(b.dns?.static||[])],
      },
      snmp:{
        enabled:!!(a.snmp?.enabled||b.snmp?.enabled),
        agent:a.snmp?.agent||b.snmp?.agent||{},
        communities:[...(a.snmp?.communities||[]),...(b.snmp?.communities||[])],
        v3users:[...(a.snmp?.v3users||[]),...(b.snmp?.v3users||[])],
        trapServers:[...(a.snmp?.trapServers||[]),...(b.snmp?.trapServers||[])],
      },
      logservers:{
        syslog:[...(a.logservers?.syslog||[]),...(b.logservers?.syslog||[])],
        fortianalyzer:[...(a.logservers?.fortianalyzer||[]),...(b.logservers?.fortianalyzer||[])],
        netflow:[...(a.logservers?.netflow||[]),...(b.logservers?.netflow||[])],
        logForward:[...(a.logservers?.logForward||[]),...(b.logservers?.logForward||[])],
      },
      wwan:{
        profiles:[...(a.wwan?.profiles||[]),...(b.wwan?.profiles||[])],
        lteModem:a.wwan?.lteModem||b.wwan?.lteModem||null,
        systemModem:a.wwan?.systemModem||b.wwan?.systemModem||null,
        modem5G:a.wwan?.modem5G||b.wwan?.modem5G||null,
      },
      webfilterProfiles:[...(a.webfilterProfiles||[]),...(b.webfilterProfiles||[])],
      ipsSensors:[...(a.ipsSensors||[]),...(b.ipsSensors||[])],
    };
  }

  function detectExpiredSchedules(schedules) {
  const map = {};
  const now = Date.now();
  const soon = now + 7 * 86400000;
  (schedules || []).forEach(s => {
    if (s.type !== 'onetime' || s.end === '-') { map[s.name] = 'active'; return; }
    const parseDate = str => {
      const m = /(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}):(\d{2})/.exec(str || '');
      return m ? new Date(+m[1], +m[2]-1, +m[3], +m[4], +m[5]).getTime() : null;
    };
    const endTs = parseDate(s.end);
    if (!endTs) { map[s.name] = 'active'; return; }
    if (endTs < now) map[s.name] = 'expired';
    else if (endTs < soon) map[s.name] = 'soon';
    else map[s.name] = 'active';
  });
  return map;
}

function showEc(id, cond){ const el=$(id); if(el) el.style.display = cond ? '' : 'none'; }

function onParsed(){
    const d=PARSED, info=d.deviceInfo;
    $('tb-title').textContent=`${info.vendor} — ${info.hostname}`;
    $('tb-meta').textContent=`${info.firmware} · ${new Date().toLocaleString('zh-TW')}`;
    $('tb-actions').style.display='flex';
    $('nav-data-group').style.display='block';
    $('nav-tools-group').style.display='block';
    const counts={interfaces:d.interfaces.length,policies:d.policies.length,routes:d.routes.length,vpn:d.vpn.length,nat:d.nat.length,addresses:d.addresses.length,services:d.services.length,schedules:d.schedules.length,users:d.users.length};
    Object.entries(counts).forEach(([k,v])=>{const el=$(`nc-${k}`);if(el)el.textContent=v;});
    // SD-WAN nav: show for all vendors that have SD-WAN configured
    const sdwanNav=$('nav-sdwan');
    if(sdwanNav){
      const hasSdwan=d.sdwan&&d.sdwan.enabled&&(d.sdwan.members.length>0||d.sdwan.services.length>0);
      sdwanNav.style.display=hasSdwan?'':'none';
      if(hasSdwan){const el=$('nc-sdwan');if(el)el.textContent=d.sdwan.services.length||d.sdwan.members.length;}
      showEc('ec-sdwan-members', (d.sdwan?.members?.length||0)>0);
      showEc('ec-sdwan-health', (d.sdwan?.healthChecks?.length||0)>0);
      showEc('ec-sdwan-services', (d.sdwan?.services?.length||0)>0);
      showEc('ec-sdwan-zones', (d.sdwan?.zones?.length||0)>0);
      showEc('ec-sdwan-neighbors', (d.sdwan?.neighbors?.length||0)>0);
    }
    // HA/Cluster nav：只有 5 廠牌（FortiGate/PaloAlto/pfSense/CiscoASA/JuniperSRX）有 ha 欄位，
    // 其餘廠牌 ha 為 undefined，直接隱藏
    const haNav=$('nav-ha');
    if(haNav){
      const hasHa=d.ha&&d.ha.enabled;
      haNav.style.display=hasHa?'':'none';
      if(hasHa){const el=$('nc-ha');if(el)el.textContent='1';}
      showEc('ec-ha', !!hasHa);
    }
    // DHCP nav
    const dhcpNav=$('nav-dhcp');
    if(dhcpNav){
      const hasDhcp=d.dhcp&&(d.dhcp.servers.length>0||d.dhcp.relays.length>0);
      dhcpNav.style.display=hasDhcp?'':'none';
      if(hasDhcp){const el=$('nc-dhcp');if(el)el.textContent=(d.dhcp.servers.length||0)+(d.dhcp.relays.length||0);}
      showEc('ec-dhcp-servers', (d.dhcp?.servers?.length||0)>0);
      showEc('ec-dhcp-relays', (d.dhcp?.relays?.length||0)>0);
    }
    // DNS nav
    const dnsNav=$('nav-dns');
    if(dnsNav){
      const hasDns=d.dns&&(d.dns.servers.length>0||d.dns.static.length>0||d.dns.proxyRules.length>0);
      dnsNav.style.display=hasDns?'':'none';
      if(hasDns){const el=$('nc-dns');if(el)el.textContent=(d.dns.servers.length||0)+(d.dns.static.length||0);}
      showEc('ec-dns-servers', ((d.dns?.servers?.length||0)+(d.dns?.secondaries?.length||0))>0);
      showEc('ec-dns-proxy', (d.dns?.proxyRules?.length||0)>0);
      showEc('ec-dns-static', (d.dns?.static?.length||0)>0);
    }
    // SNMP nav
    const snmpNav=$('nav-snmp');
    if(snmpNav){
      const hasSnmp=d.snmp&&(d.snmp.enabled||d.snmp.communities.length>0||d.snmp.v3users.length>0);
      snmpNav.style.display=hasSnmp?'':'none';
      if(hasSnmp){const el=$('nc-snmp');if(el)el.textContent=(d.snmp.communities.length||0)+(d.snmp.v3users.length||0);}
      showEc('ec-snmp-agent', !!hasSnmp);
      showEc('ec-snmp-communities', (d.snmp?.communities?.length||0)>0);
      showEc('ec-snmp-v3users', (d.snmp?.v3users?.length||0)>0);
      showEc('ec-snmp-traps', (d.snmp?.trapServers?.length||0)>0);
    }
    // Log Server nav
    const logNav=$('nav-log');
    if(logNav){
      const hasLog=d.logservers&&(d.logservers.syslog.length>0||d.logservers.fortianalyzer.length>0||d.logservers.netflow.length>0);
      logNav.style.display=hasLog?'':'none';
      if(hasLog){const el=$('nc-log');if(el)el.textContent=(d.logservers.syslog.length||0)+(d.logservers.fortianalyzer.length||0)+(d.logservers.netflow.length||0);}
      showEc('ec-log-syslog', (d.logservers?.syslog?.length||0)>0);
      showEc('ec-log-fortianalyzer', (d.logservers?.fortianalyzer?.length||0)>0);
      showEc('ec-log-netflow', (d.logservers?.netflow?.length||0)>0);
      showEc('ec-log-forward', (d.logservers?.logForward?.length||0)>0);
    }
    // 行動網路 nav
    const wwanNav=$('nav-wwan');
    if(wwanNav){
      const ww=d.wwan;
      // 有任何行動網路相關設定或介面即顯示
      const hasWwan=ww&&(
        (ww.profiles?.length>0)||
        ww.lteModem!=null||
        ww.systemModem!=null||
        ww.modem5G!=null||
        (ww.lteInterfaces?.length>0)||
        (d.interfaces||[]).some(i=>i.type==='wwan'||i.type==='lte'||/^(wwan|modem\d?)$/i.test(i.name))
      );
      wwanNav.style.display=hasWwan?'':'none';
      if(hasWwan){const el=$('nc-wwan');if(el)el.textContent=(ww.profiles?.length)||(ww.lteInterfaces?.length)||(ww.lteModem?'1':'0');}
      showEc('ec-wwan-profiles', (ww?.profiles?.length||0)>0);
      showEc('ec-wwan-lte-iface', (ww?.lteInterfaces?.length||0)>0);
      showEc('ec-wwan-apn-profiles', (ww?.apnProfiles?.length||0)>0);
      showEc('ec-wwan-5g-modem', ww?.modem5G!=null);
      showEc('ec-wwan-lte-modem', ww?.lteModem!=null);
    }
    // 無線 AP nav
    const wlanNav=$('nav-wlan');
    if(wlanNav){
      const wl=d.wlan;
      const hasWlan=wl&&(wl.interfaces.length>0||wl.capsmanConfigs.length>0);
      wlanNav.style.display=hasWlan?'':'none';
      if(hasWlan){const el=$('nc-wlan');if(el)el.textContent=wl.interfaces.length||wl.capsmanConfigs.length;}
      showEc('ec-wlan-interfaces', (wl?.interfaces?.length||0)>0);
      showEc('ec-wlan-capsman', (wl?.capsmanConfigs?.length||0)>0);
    }
    // 查詢 nav
    const queryNav = $('nav-query'); if(queryNav) queryNav.style.display='';
    // 稽核 nav
    const auditNav = $('nav-audit');
    if (auditNav) {
      auditNav.style.display = '';
      try {
        const _sh = analyzeRuleShadowing(d.policies || []);
        const _un = analyzeUnusedObjects(d);
        const _co = analyzeCompliance(d);
        const total = _sh.length + _un.unusedAddrs.length + _un.unusedSvcs.length +
                      _co.filter(f => f.risk === 'high' || f.risk === 'medium').length;
        const nc = $('nc-audit');
        if (nc) { nc.textContent = total; nc.style.color = total > 0 ? 'var(--red)' : 'var(--green)'; }
      } catch(e) { console.warn('audit badge error:', e); }
    }
    // Set converter source
    const srcRaw=ST.raw.f||ST.raw.s||ST.raw.c||ST.raw.p||'';
    $('conv-src').value=srcRaw;
    CONV_SRC_VENDOR=ST.raw.f?'fortigate':ST.raw.s?'sophos':ST.raw.c?'checkpoint':ST.raw.p?'paloalto':ST.raw.j?'juniper':ST.raw.x?'pfsense':ST.raw.w?'sonicwall':ST.raw.m?'mikrotik':ST.raw.a?'ciscoasa':ST.raw.t?'ciscoftd':ST.raw.z?'zyxel':ST.raw.r?'edgerouter':ST.raw.u?'openwrt':'unknown';
    updateConvButtons();
    buildVdomBar(PARSED);
    buildRefIndex(PARSED);
    showSection('policies');
  }

  function buildVdomBar(parsed) {
    const bar = $('vdom-bar');
    if (!bar) return;
    const names = parsed?._vdomNames || [];
    if (!parsed?._isMultiVdom || names.length <= 1) { bar.style.display='none'; return; }
    bar.style.display='flex';
    bar.innerHTML = ['__all__',...names].map(n=>
      `<button class="vdom-btn ${n==='__all__'?'active':''}" data-vdom="${n}"
        onclick="setVdom('${n}')">${n==='__all__'?(parsed?.vendor==='PaloAlto'?tr('conv.all_vsys_btn'):tr('conv.all_vdom_btn')):n}</button>`
    ).join('') + `<span class="vdom-label">${names.length}${tr('unit.count')} ${parsed?.vendor==="PaloAlto"?"vsys":"VDOM"}</span>`;
    // Also update conv VDOM selector
    buildConvVdomSelector(parsed);
  }
  window.buildVdomBar = buildVdomBar;

  window.setVdom = function(vdom) {
    ACTIVE_VDOM = vdom;
    document.querySelectorAll('.vdom-btn').forEach(b=>b.classList.toggle('active', b.dataset.vdom===vdom));
    if (CURRENT_SECTION) showSection(CURRENT_SECTION);
  };

  function filterByVdom(data) {
    if (ACTIVE_VDOM === '__all__' || !data.length) return data;
    return data.filter(r => !r._vdom || r._vdom === ACTIVE_VDOM);
  }

  // ── Views ─────────────────────────────────────────────────────
  function showView(v){
    document.querySelectorAll('.nav-item').forEach(el=>el.classList.remove('active'));
    ['view-upload','view-data','view-convert','view-export','view-perms','view-diff'].forEach(id=>{
      const el=$(id); if(el){el.style.display='none';el.classList.remove('show');}
    });
    // Fix: 非資料頁面隱藏 VDOM 選單列
    const bar=$('vdom-bar'); if(bar) bar.style.display='none';
    if(v==='upload'){const vu=$('view-upload');vu.style.display='flex';vu.scrollTop=0;document.querySelector('.nav-item').classList.add('active');}
    else if(v==='convert'){$('view-convert').style.display='flex';$('view-convert').classList.add('show');}
    else if(v==='export'){$('view-export').style.display='flex';}
    else if(v==='perms'){$('view-perms').style.display='flex';renderPermissions();}
    else if(v==='diff'){$('view-diff').style.display='flex';initDiffVendorSelect();}
  }
  window.showView=showView;

  function showSection(section){
    if(!PARSED)return;
    CURRENT_SECTION=section;
    document.querySelectorAll('.nav-item').forEach(el=>el.classList.toggle('active',el.getAttribute('onclick')===`showSection('${section}')`));
    ['view-upload','view-convert','view-export','view-perms','view-diff'].forEach(id=>{const el=$(id);if(el){el.style.display='none';el.classList.remove('show');}});
    $('view-data').style.display='flex';$('view-data').classList.add('show');
    $('search-inp').value='';window._searchQ='';
    $('filter-action').style.display='none';$('filter-type').style.display='none';
    // Fix: WiFi section 不套用 VDOM 篩選，隱藏 VDOM bar；其他 section 依需要顯示
    const bar = $('vdom-bar');
    const noVdomBar = section === 'sdwan' || section === 'dns' || section === 'snmp' || section === 'log' || section === 'audit' || section === 'query';
    if (bar) bar.style.display = noVdomBar ? 'none' : (PARSED?._isMultiVdom && (PARSED?._vdomNames||[]).length > 1 ? 'flex' : 'none');
    renderSection(section);
  }
  window.showSection=showSection;
  window._triggerLangRefresh=function(){
    if(CURRENT_SECTION && PARSED) showSection(CURRENT_SECTION);
    // perms view 也重繪（若已開啟）
    if(PARSED && document.getElementById('view-perms') && document.getElementById('view-perms').style.display!=='none') renderPermissions();
    // 新舊設定比對結果為靜態 innerHTML，非 data-i18n 屬性可自動翻譯，語言切換時需手動重繪
    if(DIFF_RESULT && document.getElementById('view-diff') && document.getElementById('view-diff').style.display!=='none') $('diff-result').innerHTML=buildDiffHtml(DIFF_RESULT);
    // 羊駝 tooltip 跟語言走
    var ac=document.getElementById('alpaca-corner'); if(ac) ac.setAttribute('title', tr('egg.alpaca_title'));
  };

  function analyzeNAT(nat) {
    const warnings = [];
    const vips = (nat||[]).filter(n=>n.type==='vip');
    // Duplicate extIp (no port forwarding)
    const ipMap = {};
    vips.filter(v=>v.portFwd==='disable'||!v.portFwd).forEach(v=>{
      if(v.extIp&&v.extIp!=='-'){(ipMap[v.extIp]=ipMap[v.extIp]||[]).push(v.name);}
    });
    Object.entries(ipMap).filter(([,names])=>names.length>1).forEach(([ip,names])=>warnings.push({type:'dup_ip',msg:`${tr('nat.dup_ip')}: ${ip}`,detail:names.join(', ')}));
    // Port conflict (port forwarding)
    const portMap = {};
    vips.filter(v=>v.portFwd==='enable').forEach(v=>{
      const k=`${v.extIp}:${v.extPort}:${v.proto||'tcp'}`;
      if(v.extIp&&v.extIp!=='-'&&v.extPort&&v.extPort!=='-'){(portMap[k]=portMap[k]||[]).push(v.name);}
    });
    Object.entries(portMap).filter(([,names])=>names.length>1).forEach(([k,names])=>warnings.push({type:'port_conflict',msg:`${tr('nat.port_conflict')}: ${k}`,detail:names.join(', ')}));
    return warnings;
  }

  // ── Section renderer ──────────────────────────────────────────
  const SEC_LABELS={interfaces:()=>tr('sec.interfaces'),policies:()=>tr('sec.policies'),routes:()=>tr('sec.routes'),vpn:()=>tr('sec.vpn'),nat:()=>tr('sec.nat'),addresses:()=>tr('sec.addresses'),services:()=>tr('sec.services'),schedules:()=>tr('sec.schedules'),users:()=>tr('sec.users'),audit:()=>tr('nav.audit'),query:()=>tr('nav.query'),fortiswitch:()=>tr('nav.fortiswitch')};

  function renderSection(sec){
    $('tbl-section-label').textContent=(typeof SEC_LABELS[sec]==='function'?SEC_LABELS[sec]():SEC_LABELS[sec])||sec;
    const d=PARSED;
    let data,sumCards,thead,rowFn,_extraHtml='';
    switch(sec){
      case 'interfaces':
        data=d.interfaces;
        sumCards=sumC([{l:tr('sl.total'),v:data.length,c:'var(--accent)'},{l:'WAN',v:data.filter(x=>x.role==='WAN').length,c:'var(--red)'},{l:'LAN',v:data.filter(x=>x.role==='LAN').length,c:'var(--green)'},{l:'DMZ',v:data.filter(x=>x.role==='DMZ').length,c:'var(--yellow)'},{l:tr('sl.vpn'),v:data.filter(x=>x.role==='VPN'||x.type==='tunnel').length,c:'var(--purple)'},{l:'VLAN',v:data.filter(x=>x.type==='vlan').length,c:'var(--orange)'}]);
        thead=`<tr><th>${tr('col.name')}</th><th>${tr('col.alias')}</th><th>${tr('col.ip')}</th><th>${tr('col.mask')}</th><th>${tr('col.secondaryIp')}</th><th>${tr('col.type')}</th><th>VLAN</th><th>${tip('tip.vdom','VDOM/Zone')}</th><th>${tr('col.role')}</th><th>${tip('tip.mtu','MTU')}</th><th>${tr('col.speed')}</th><th>${tr('col.mode')}</th><th>${tip('tip.status',tr('col.status'))}</th><th>${tip('tip.allowaccess',tr('col.allowaccess'))}</th><th>${tr('col.desc')}</th></tr>`;
        rowFn=r=>`<tr><td class="mono" style="color:var(--accent)">${esc(r.name)}</td><td style="color:#94a3b8;font-size:11px">${esc(r.alias)}</td><td class="mono">${esc(r.ip)}</td><td class="mono" style="color:var(--text-dim)">${esc(r.mask)}</td><td class="mono" style="color:var(--text-dim)">${esc((r.secondaryIps&&r.secondaryIps.length)?r.secondaryIps.map(s=>s.ip+(s.mask&&s.mask!=='-'?'/'+s.mask:'')).join(', '):'-')}</td><td>${pType(r.type)}</td><td class="mono" style="color:var(--text-dim)">${esc(r.vlanId)}</td><td style="color:var(--text-dim)">${esc(r.vdom)}</td><td>${pRole(r.role)}</td><td class="mono" style="color:var(--text-dim)">${esc(r.mtu)}</td><td style="color:var(--text-dim)">${esc(r.speed)}</td><td style="color:var(--text-dim)">${esc(r.mode)}</td><td>${r.status==='down'||r.status==='Disable'?pill('DOWN','p-deny'):pill('UP','p-allow')}</td><td style="font-size:11px;color:var(--text-dim)">${esc(r.allowaccess)}</td><td style="color:var(--text-dim)">${esc(r.desc)}</td></tr>`;
        break;
      case 'policies':
        data=d.policies;$('filter-action').style.display='';
        const _shadowMap = buildShadowMap(data);
        // Reverse map: shadowedRuleId → earlyRuleId (first match wins)
        const _reverseShadow = {};
        Object.entries(_shadowMap).forEach(([earlyId, sids]) => sids.forEach(sid => { if(!_reverseShadow[sid]) _reverseShadow[sid]=earlyId; }));
        const _activeCount = data.filter(p => p.status !== 'disable').length;
        let _evalOrder = 0;
        const _schedMap = detectExpiredSchedules(d.schedules);
        sumCards=sumC([{l:tip('tip.policy',tr('sl.total')),v:data.length,c:'var(--accent)',sf:{t:'clear'}},{l:tr('sl.allow'),v:data.filter(x=>x.action==='accept').length,c:'var(--green)',sf:{t:'action',v:'accept'}},{l:tr('sl.deny'),v:data.filter(x=>x.action!=='accept').length,c:'var(--red)',sf:{t:'action',v:'deny'}},{l:tip('tip.nat',tr('sl.nat_on')),v:data.filter(x=>x.nat==='enable').length,c:'var(--yellow)'},{l:tip('tip.status',tr('sl.disabled')),v:data.filter(x=>x.status==='disable').length,c:'var(--text-dim)'},{l:tr('sl.utm'),v:data.filter(x=>x.utm&&(x.utm.av!=='-'||x.utm.ips!=='-'||x.utm.webfilter!=='-')).length,c:'var(--purple)'}]);
        thead=`<tr><th>${tip('tip.eval_order',tr('col.eval_order'))}</th><th>ID</th><th>${tr('col.name')}</th><th>${tr('col.src_intf')}</th><th>${tr('col.dst_intf')}</th><th>${tip('tip.srcaddr',tr('col.src_addr'))}</th><th>${tr('policy.src_addr_v4')}</th><th>${tr('policy.src_addr_v6')}</th><th>${tip('tip.dstaddr',tr('col.dst_addr'))}</th><th>${tr('policy.dst_addr_v4')}</th><th>${tr('policy.dst_addr_v6')}</th><th>${tr('col.service')}</th><th>${tip('tip.schedule',tr('col.schedule'))}</th><th>${tip('tip.action',tr('col.action'))}</th><th>${tip('tip.nat','NAT')}</th><th>${tr('col.user')}</th><th>AV</th><th>Web</th><th>IPS</th><th>App-ID</th><th>${tip('tip.logtraffic',tr('col.log'))}</th><th>${tip('tip.status',tr('col.status'))}</th><th>${tip('tip.shadowed_count',tr('col.shadow_count'))}</th><th>${tr('col.desc')}</th></tr>`;
        rowFn = r => {
          // addr cell: all named addresses are clickable
          const addrCell = addrStr => {
            if (!addrStr || addrStr === '-') return '<td class="mono" style="color:var(--text-dim)">-</td>';
            const parts = addrStr.split(/,\s*/).map(raw => {
              const n = raw.trim();
              if (!n || n === 'all' || n === 'any') return `<span style="color:var(--text-dim)">${esc(n)}</span>`;
              const enc = btoa(unescape(encodeURIComponent(n)));
              return `<span class="clickable-cell" onclick="_showAddr('${enc}')" title="${tr('addr.click_hint')}">${esc(n)}</span>`;
            });
            return `<td class="mono">${parts.join(', ')}</td>`;
          };
          // 計算評估順序（僅啟用規則）
          if (r.status !== 'disable') _evalOrder++;
          const evalOrderDisplay = r.status === 'disable' ? '-' : String(_evalOrder);
          // NAT cell
          const natTd = r.nat === 'enable'
            ? `<td><span class="nat-badge pill p-warn" onclick="showNatById('${r.id}')" title="${tr('nat.view_tip')}">🔀 NAT</span></td>`
            : '<td>-</td>';
          // 遮蔽規則數
          const shadowedCount = _shadowMap[r.id] ? _shadowMap[r.id].length : 0;
          const shadowedDisplay = shadowedCount > 0
            ? `<td style="color:var(--red);font-weight:600"><span data-tip="${tr('shadow.tip_prefix')}：${_shadowMap[r.id].join(', ')}">${shadowedCount}${tr('unit.rules')}<sup style="font-size:8px;opacity:.45;margin-left:2px;cursor:help">ⓘ</sup></span></td>`
            : '<td style="color:var(--text-dim)">-</td>';
          return `<tr>
            <td class="mono" style="color:var(--text-dim);text-align:center">${evalOrderDisplay}</td>
            <td class="mono" style="color:var(--accent)">${esc(r.id)}</td>
            <td style="font-weight:500">${esc(r.name)}${_reverseShadow[r.id]?`<span class="pill p-deny" style="font-size:9px;padding:1px 5px;margin-left:5px;cursor:help" title="${tr('policy.shadow_by').replace('{0}',_reverseShadow[r.id])}">&#x1F534; ${tr('policy.shadowed')}</span>`:''}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(r.srcIntf)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(r.dstIntf)}</td>
            ${addrCell(r.srcAddr)}
            <td class="mono" style="color:#059669;font-size:11px">${esc(r.srcAddr4)}</td>
            <td class="mono" style="color:#0284c7;font-size:11px">${esc(r.srcAddr6)}</td>
            ${addrCell(r.dstAddr)}
            <td class="mono" style="color:#059669;font-size:11px">${esc(r.dstAddr4)}</td>
            <td class="mono" style="color:#0284c7;font-size:11px">${esc(r.dstAddr6)}</td>
            <td>${esc(r.service)}</td>
            <td>${(()=>{const sc=r.schedule;if(!sc||sc==='-'||sc==='always')return`<span style="color:var(--text-dim)">${esc(sc||'-')}</span>`;const st=_schedMap[sc];if(st==='expired')return`<span class="badge badge-deny">${esc(sc)} ${tr('sched.expired')}</span>`;if(st==='soon')return`<span class="badge badge-warn">${esc(sc)} ${tr('sched.soon')}</span>`;return`<span class="badge badge-info">${esc(sc)}</span>`;})()}</td>
            <td>${pAction(r.action)}</td>
            ${natTd}
            <td style="color:var(--text-dim);font-size:11px">${esc(r.users !== '-' ? r.users : r.groups !== '-' ? r.groups : '-')}</td>
            <td>${r.utm && r.utm.av  !== '-' ? pill('AV', 'p-purple') : '-'}</td>
            <td>${(()=>{ const n=r.utm&&r.utm.webfilter!=='-'?r.utm.webfilter:''; if(!n)return '-';
              return d.webfilterProfiles ? `<span class="clickable-cell pill p-purple" onclick="showWebfilterDetail(${JSON.stringify(n).replace(/"/g,'&quot;')})" title="${tr('wf.click_tip')}">Web</span>` : pill('Web','p-purple'); })()}</td>
            <td>${(()=>{ const n=r.utm&&r.utm.ips!=='-'?r.utm.ips:''; if(!n)return '-';
              return d.ipsSensors ? `<span class="clickable-cell pill p-orange" onclick="showIpsDetail(${JSON.stringify(n).replace(/"/g,'&quot;')})" title="${tr('ips.click_tip')}">IPS</span>` : pill('IPS','p-orange'); })()}</td>
            <td style="font-size:11px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:${r.app&&r.app!=='any'?'var(--purple)':'var(--text-dim)'}" title="${esc(r.app||'')}">${r.app&&r.app!=='any'?esc(r.app.length>35?r.app.slice(0,35)+'…':r.app):'-'}</td>
            <td style="color:var(--text-dim)">${esc(r.logtraffic)}</td>
            <td>${r.status === 'disable' ? pill(tr('wwan.pill_disable'),'p-deny') : pill(tr('wwan.pill_enable'),'p-allow')}</td>
            ${shadowedDisplay}
            <td style="color:var(--text-dim);font-size:11px">${esc(r.comments)}</td>
          </tr>`;
        };
                break;
      case 'routes':
        data=d.routes;
        sumCards=sumC([{l:tr('sl.total'),v:data.length,c:'var(--accent)'},{l:tr('sl.static'),v:data.filter(x=>x.type==='static').length,c:'var(--green)'},{l:'STATIC6',v:data.filter(x=>x.type==='static6').length,c:'var(--info)'},{l:'Policy',v:data.filter(x=>x.type==='policy').length,c:'var(--yellow)'},{l:'OSPF',v:data.filter(x=>x.type==='ospf').length,c:'var(--purple)'},{l:'BGP',v:data.filter(x=>x.type==='bgp').length,c:'var(--orange)'},{l:'RIP',v:data.filter(x=>x.type==='rip').length,c:'var(--text-dim)'}]);
        thead=`<tr><th>${tr('col.type')}</th><th>ID</th><th>${tr('col.dst_net')}</th><th>${tr('col.gateway')}</th><th>${tr('col.if_name')}</th><th>${tr('col.admin_dist')}</th><th>${tr('col.priority')}</th><th>${tr('col.status')}</th><th>${tr('col.blackhole')}</th><th>${tr('col.proto_detail')}</th><th>${tr('col.desc')}</th></tr>`;
        rowFn=r=>`<tr><td>${pRouteType(r.type)}</td><td class="mono" style="color:var(--text-dim)">${esc(r.id)}</td><td class="mono">${esc(r.dst)}</td><td class="mono">${esc(r.gateway)}</td><td style="color:var(--text-dim)">${esc(r.device)}</td><td class="mono" style="color:var(--text-dim)">${esc(r.distance)}</td><td class="mono" style="color:var(--text-dim)">${esc(r.priority)}</td><td>${r.status==='disable'||r.status==='Disable'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td><td style="color:var(--text-dim)">${esc(r.blackhole||'-')}</td><td style="color:var(--text-dim);font-size:11px">${esc(r.protocol_detail||'-')}</td><td style="color:var(--text-dim);font-size:11px">${esc(r.comment)}</td></tr>`;
        {const _bgpE=(d.routes||[]).find(r=>r.type==='bgp'&&r.neighbors&&r.neighbors.length>0);
        if(_bgpE){
          const _bs=(a)=>`padding:3px 10px;border-radius:4px;border:1px solid ${a?'var(--accent)':'var(--border)'};cursor:pointer;font-size:11px;background:${a?'var(--accent)':'var(--surface2)'};color:${a?'#fff':'var(--text-dim)'}`;
          const _bTgl=`<div style="display:flex;gap:5px;margin-bottom:8px"><button onclick="window._fwBgpView='table';renderSection('routes')" style="${_bs(!window._fwBgpView||window._fwBgpView==='table')}">${tr('routing.view_table')}</button><button onclick="window._fwBgpView='topo';renderSection('routes')" style="${_bs(window._fwBgpView==='topo')}">${tr('routing.view_topo')}</button></div>`;
          let _bBody='';
          if(window._fwBgpView==='topo'){
            const peers=_bgpE.neighbors;const cnt=peers.length||1;
            const CX=380,CY=200,R=Math.min(150,50+cnt*22),nr=30,W=760,H=400;
            const pos=peers.map((_,i)=>{const a=(2*Math.PI*i/cnt)-Math.PI/2;return{x:CX+R*Math.cos(a),y:CY+R*Math.sin(a)};});
            let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" style="width:100%;max-height:400px"><defs><filter id="fw"><feGaussianBlur stdDeviation="2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
            pos.forEach((p,i)=>{const n=peers[i];const col=n.type==='iBGP'?'var(--accent)':'var(--green)';const dx=p.x-CX,dy=p.y-CY,dist=Math.sqrt(dx*dx+dy*dy);svg+=`<line x1="${CX+dx/dist*nr}" y1="${CY+dy/dist*nr}" x2="${p.x-dx/dist*nr}" y2="${p.y-dy/dist*nr}" stroke="${col}" stroke-width="1.5" stroke-opacity="0.5"/>`;svg+=`<text x="${(CX+p.x)/2}" y="${(CY+p.y)/2}" text-anchor="middle" font-size="9" fill="${col}" opacity="0.8">AS${esc(n.as)}</text>`;svg+=`<circle cx="${p.x}" cy="${p.y}" r="${nr}" fill="var(--surface2)" stroke="${col}" stroke-width="1.5"/>`;svg+=`<text x="${p.x}" y="${p.y-5}" text-anchor="middle" font-size="9" font-weight="600" fill="var(--text)" font-family="monospace">${esc(n.ip)}</text>`;svg+=`<text x="${p.x}" y="${p.y+8}" text-anchor="middle" font-size="8" fill="${col}">${n.type}</text>`;});
            svg+=`<circle cx="${CX}" cy="${CY}" r="${nr}" fill="var(--surface2)" stroke="var(--orange)" stroke-width="2" filter="url(#fw)"/>`;svg+=`<text x="${CX}" y="${CY-4}" text-anchor="middle" font-size="9" font-weight="700" fill="var(--orange)">BGP AS${esc(_bgpE.as||'')}</text>`;svg+=`<text x="${CX}" y="${CY+8}" text-anchor="middle" font-size="8" fill="var(--text-dim)">${esc(_bgpE.routerId||'')}</text>`;svg+='</svg>';
            _bBody=`<div style="background:var(--surface2);border-radius:6px;padding:8px">${svg}</div>`;
          } else {
            _bBody=`<div style="overflow-x:auto"><table class="data-tbl"><thead><tr><th>${tr('bgp.col_peer')}</th><th>AS</th><th>${tr('bgp.col_type')}</th><th>${tr('bgp.col_desc')}</th></tr></thead><tbody>${_bgpE.neighbors.map(n=>`<tr><td class="mono">${esc(n.ip)}</td><td class="mono" style="color:var(--text-dim)">${esc(n.as)}</td><td>${pill(n.type,n.type==='iBGP'?'p-info':'p-allow')}</td><td style="color:var(--text-dim);font-size:11px">${esc(n.desc)}</td></tr>`).join('')}</tbody></table></div>`;
          }
          _extraHtml=`<div style="margin-top:20px;padding:0 2px"><div style="font-size:12px;font-weight:600;color:var(--orange);margin-bottom:6px">${tr('bgp.title')}</div>${_bTgl}${_bBody}</div>`;
        }}
        break;
      case 'vpn':
        data=d.vpn;
        // 2026-08-26 新增：上傳的廠牌若命中 VPN_UNSUPPORTED（查證後確認查無語法佐證），
        // 資料為空時顯示專屬警示文字，比照既有 WIFI_UNSUPPORTED 精神（區分「這廠牌沒設定
        // VPN」與「本工具查證後確認不支援解析」），只影響顯示文字，不影響 d.vpn 本身仍是
        // 安全的空陣列
        if(!data.length && VPN_UNSUPPORTED.some(slot=>ST.raw[slot])){
          $('sum-wrap').innerHTML='';$('tbl-wrap').innerHTML='<div class="nodata">'+tr('vpn.vendor_unsupported')+'</div>';
          return;
        }
        sumCards=sumC([{l:tr('sl.total'),v:data.length,c:'var(--accent)'},{l:'IPSec P1',v:data.filter(x=>x.type==='ipsec-p1').length,c:'var(--purple)'},{l:'IPSec P2',v:data.reduce((s,v)=>s+(v.phase2?v.phase2.length:0),0),c:'var(--purple)'},{l:'SSL-VPN',v:data.filter(x=>x.type==='ssl-vpn').length,c:'var(--green)'},{l:'SSL Portal',v:data.filter(x=>x.type==='ssl-portal').length,c:'var(--green)'},{l:'IKEv2',v:data.filter(x=>x.ikeVer==='2').length,c:'var(--orange)'}]);
        thead=`<tr><th>${tip('tip.ipsec_p1',tr('col.type'))}</th><th>${tr('col.name')}</th><th>${tr('col.remote_gw')}</th><th>${tr('col.if_name')}</th><th>IKE</th><th>${tr('col.auth')}</th><th>${tip('tip.weak_vpn',tr('col.enc_proposal'))}</th><th>${tr('col.dh_group')}</th><th>${tr('col.key_lifetime')}</th><th>${tr('col.nat_traverse')}</th><th>DPD</th><th>${tip('tip.ipsec_p2',tr('col.p2_count'))}</th><th>${tip('tip.status',tr('col.status'))}</th></tr>`;
        rowFn=r=>`<tr>
            <td>${pVpnType(r.type)}</td>
            <td class="mono" style="color:var(--accent)">
              <span class="clickable-cell" onclick="showVpnDetail(${JSON.stringify(r.name).replace(/"/g,'&quot;')})" title="${tr('vpn.click_tip')}">${esc(r.name)}</span>
            </td>
            <td class="mono">${esc(r.remote)}</td>
            <td style="color:var(--text-dim)">${esc(r.iface)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(r.ikeVer)}</td>
            <td style="color:var(--text-dim)">${esc(r.authMethod)}</td>
            <td class="mono" style="color:var(--purple)">${esc(r.proposal)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(r.dhgrp)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(r.lifetime)}</td>
            <td style="color:var(--text-dim)">${esc(r.natTraversal||'-')}</td>
            <td style="color:var(--text-dim)">${esc(r.dpd||'-')}</td>
            <td class="mono">${r.phase2&&r.phase2.length?`<span class="clickable-cell" onclick="showVpnPhase2Detail(${JSON.stringify(r.name).replace(/"/g,'&quot;')})" title="${tr('vpn.phase2_tip')}">${pill(r.phase2.length+' P2','p-info')}</span>`:'-'}</td>
            <td>${r.status==='disable'||r.status==='Disable'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td>
          </tr>`;
        break;
      case 'nat':
        data=d.nat;
        // 2026-08-26 新增：同上方 vpn case 的 UNSUPPORTED 機制
        if(!data.length && NAT_UNSUPPORTED.some(slot=>ST.raw[slot])){
          $('sum-wrap').innerHTML='';$('tbl-wrap').innerHTML='<div class="nodata">'+tr('nat.vendor_unsupported')+'</div>';
          return;
        }
        sumCards=sumC([{l:tip('tip.nat',tr('sl.total')),v:data.length,c:'var(--accent)'},{l:tip('tip.vip','VIP/DNAT'),v:data.filter(x=>x.type==='vip').length,c:'var(--yellow)'},{l:tip('tip.ippool','IP Pool'),v:data.filter(x=>x.type==='ippool').length,c:'var(--orange)'},{l:tip('tip.vipgrp','VIP Group'),v:data.filter(x=>x.type==='vipgrp').length,c:'var(--text-dim)'},{l:'NAT66',v:data.filter(x=>x.type==='vip6'||x.type==='ippool6'||x.type==='vipgrp6').length,c:'var(--info)'}]);
        thead=`<tr><th>${tip('tip.nat',tr('col.type'))}</th><th>${tr('col.name')}</th><th>${tr('col.subtype')}</th><th>${tip('tip.vip',tr('col.ext_ip'))}</th><th>${tr('col.ext_if')}</th><th>${tr('col.map_ip')}</th><th>${tr('col.port_fwd')}</th><th>${tr('col.ext_port')}</th><th>${tr('col.map_port')}</th><th>${tr('col.protocol')}</th><th>${tip('tip.status',tr('col.status'))}</th><th>${tr('col.desc')}</th></tr>`;
        rowFn=r=>`<tr><td>${pill(r.type,'p-warn')}</td><td class="mono" style="color:var(--accent)">${esc(r.name)}</td><td style="color:var(--text-dim)">${esc(r.vipType||r.poolType||'-')}</td><td class="mono">${esc(r.extIp||r.startIp||'-')}</td><td style="color:var(--text-dim)">${esc(r.extIntf||r.srcIntf||'-')}</td><td class="mono">${esc(r.mapIp||r.endIp||'-')}</td><td>${esc(r.portFwd||'-')}</td><td class="mono">${esc(r.extPort||'-')}</td><td class="mono">${esc(r.mapPort||'-')}</td><td style="color:var(--text-dim)">${esc(r.proto||'-')}</td><td>${r.status==='disable'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td><td style="color:var(--text-dim);font-size:11px">${esc(r.comment)}</td></tr>`;
        {const _natWarns=analyzeNAT(d.nat);
        if(_natWarns.length>0)_extraHtml=`<div style="margin-top:16px;padding:10px 14px;background:rgba(234,88,12,.08);border-left:3px solid var(--orange);border-radius:6px"><div style="font-size:12px;font-weight:600;color:var(--orange);margin-bottom:6px">⚠ ${tr('nat.analysis_title')}</div>${_natWarns.map(w=>`<div style="font-size:12px;color:var(--text);margin-top:4px"><span style="color:var(--orange);font-weight:600">${esc(w.msg)}</span> — ${esc(w.detail)}</div>`).join('')}</div>`;}
        break;
      case 'addresses':
        data=d.addresses;
        sumCards=sumC([{l:tr('sl.total'),v:data.length,c:'var(--accent)'},{l:'IP/Mask',v:data.filter(x=>x.type==='ipmask').length,c:'var(--info)'},{l:'IP Range',v:data.filter(x=>x.type==='iprange').length,c:'var(--green)'},{l:'FQDN',v:data.filter(x=>x.type==='fqdn').length,c:'var(--yellow)'},{l:tr('sl.group'),v:data.filter(x=>x.category==='address-group').length,c:'var(--purple)'}]);
        thead=`<tr><th>${tr('col.category')}</th><th>${tr('col.name')}</th><th>${tr('col.type')}</th><th>${tr('col.network')}</th><th>FQDN</th><th>${tr('col.start_ip')}</th><th>${tr('col.end_ip')}</th><th>${tr('col.members')}</th><th>${tr('col.if_name')}</th><th>${tr('col.desc')}</th></tr>`;
        {const _unA=new Set((analyzeUnusedObjects(d)||{}).unusedAddrs?.map(a=>a.name)||[]);
        rowFn=r=>{const enc=btoa(unescape(encodeURIComponent(r.name)));const _ub=_unA.has(r.name)?`<span class="badge badge-warn" style="margin-left:5px;font-size:9px">${tr('addr.unused_badge')}</span>`:'';return`<tr><td>${pill(r.category,'p-info')}</td><td class="mono" style="color:var(--accent)"><span class="clickable-cell" onclick="_showAddr('${enc}')" title="${tr('addr.click_hint')}">${esc(r.name)}</span>${_ub}</td><td style="color:var(--text-dim)">${esc(r.type)}</td><td class="mono">${esc(r.subnet||'-')}</td><td class="mono" style="color:var(--text-dim)">${esc(r.fqdn||'-')}</td><td class="mono">${esc(r.startIp||'-')}</td><td class="mono">${esc(r.endIp||'-')}</td><td style="max-width:200px;font-size:11px;color:var(--text-dim)">${esc(r.members||'-')}</td><td style="color:var(--text-dim)">${esc(r.iface||'-')}</td><td style="color:var(--text-dim);font-size:11px">${esc(r.comment)}</td></tr>`;}}
        break;
      case 'services':
        data=d.services;
        sumCards=sumC([{l:tr('sl.total'),v:data.length,c:'var(--accent)'},{l:'TCP',v:data.filter(x=>x.proto==='TCP').length,c:'var(--green)'},{l:'UDP',v:data.filter(x=>x.proto==='UDP').length,c:'var(--orange)'},{l:'TCP/UDP',v:data.filter(x=>x.proto==='TCP/UDP'||x.proto==='TCPUDP').length,c:'var(--yellow)'},{l:'ICMP',v:data.filter(x=>(x.proto||'').includes('ICMP')).length,c:'var(--red)'},{l:tr('sl.group'),v:data.filter(x=>x.category==='group').length,c:'var(--purple)'}]);
        thead=`<tr><th>${tr('col.category')}</th><th>${tr('col.name')}</th><th>${tr('col.protocol')}</th><th>TCP Port</th><th>UDP Port</th><th>ICMP Type</th><th>${tr('col.members')}</th><th>${tr('col.desc')}</th></tr>`;
        {const _unS=new Set((analyzeUnusedObjects(d)||{}).unusedSvcs?.map(s=>s.name)||[]);
        rowFn=r=>{const enc=btoa(unescape(encodeURIComponent(r.name)));return`<tr><td>${pill(r.category,'p-info')}</td><td class="mono" style="color:var(--accent)"><span class="clickable-cell" onclick="_showSvc('${enc}')" title="${tr('addr.click_hint')}">${esc(r.name)}</span>${_unS.has(r.name)?`<span class="badge badge-warn" style="margin-left:5px;font-size:9px">${tr('addr.unused_badge')}</span>`:''}</span></td><td>${pProto(r.proto)}</td><td class="mono">${esc(r.tcpPorts||'-')}</td><td class="mono">${esc(r.udpPorts||'-')}</td><td class="mono" style="color:var(--text-dim)">${esc(r.icmpType||'-')}</td><td style="max-width:180px;font-size:11px;color:var(--text-dim)">${esc(r.members||'-')}</td><td style="color:var(--text-dim);font-size:11px">${esc(r.comment)}</td></tr>`;}}
        break;
      case 'schedules':
        data=d.schedules;
        sumCards=sumC([{l:tr('sl.total'),v:data.length,c:'var(--accent)'},{l:tr('sl.recurring'),v:data.filter(x=>x.type==='recurring').length,c:'var(--green)'},{l:tr('sl.onetime'),v:data.filter(x=>x.type==='onetime').length,c:'var(--yellow)'}]);
        thead=`<tr><th>${tr('col.type')}</th><th>${tr('col.name')}</th><th>${tr('col.start')}</th><th>${tr('col.end')}</th><th>${tr('col.weekday')}</th></tr>`;
        rowFn=r=>`<tr><td>${pill(r.type,'p-info')}</td><td class="mono" style="color:var(--accent)">${esc(r.name)}</td><td class="mono">${esc(r.start)}</td><td class="mono">${esc(r.end)}</td><td style="color:var(--text-dim)">${esc(r.day||'-')}</td></tr>`;
        break;
      case 'sdwan': {
        $('sum-wrap').innerHTML='';$('tbl-wrap').innerHTML='';$('filter-action').style.display='none';
        const sd = d.sdwan;
        if(!sd||!sd.enabled){
          $('tbl-wrap').innerHTML='<div class="nodata">'+tr('sdwan.no_sdwan')+'</div>';
          return;
        }
        $('tbl-section-label').textContent='SD-WAN';
        // Summary cards
        const modeLabel={'source-ip-based':tr('sdwan.mode_src_ip'),'weight-based':tr('sdwan.mode_weight'),'usage-based':tr('sdwan.mode_usage'),'measured-volume-based':tr('sdwan.mode_volume'),'least-shaping':tr('sdwan.mode_min'),'auto':tr('sdwan.mode_auto')};
        $('sum-wrap').innerHTML=sumC([
          {l:tr('sdwan.wan_links'), v:sd.members.length,      c:'var(--accent)'},
          {l:tr('sdwan.rules_count'),v:sd.services.length,   c:'var(--green)'},
          {l:tr('sdwan.sla_probes'), v:sd.healthChecks.length, c:'var(--yellow)'},
          {l:tr('sdwan.zones_count'), v:sd.zones.length,        c:'var(--purple)'},
          {l:tr('sdwan.bgp_peers'), v:sd.neighbors.length,    c:'var(--orange)'},
          {l:tr('sdwan.lb_mode'), v:modeLabel[sd.lbMode]||sd.lbMode, c:'var(--info)'},
        ]);
        $('tbl-cnt').textContent=sd.services.length+' '+tr('unit.rules');

        // ── Members table ──
        const memberPill=s=>{
          if(s==='enable'||!s)return pill(tr('wwan.pill_enable'),'p-allow');
          return pill(tr('wwan.pill_disable'),'p-deny');
        };
        let html='<div style="margin-bottom:16px">';
        html+='<div style="font-size:12px;font-weight:600;color:var(--accent);margin-bottom:8px;padding:0 2px">'+tr('sdwan.members_header')+'</div>';
        html+='<div style="overflow-x:auto"><table><thead><tr>';
        ['ID',tr('sdwan.col_iface'),'Zone',tr('sdwan.col_gw'),tr('sdwan.col_gw6'),tr('sdwan.col_prio'),tr('sdwan.mode_weight'),tr('sdwan.col_cost'),tr('sdwan.link_cost'),tr('sdwan.link_status'),tr('sdwan.auto_failback'),tr('sdwan.source_ip'),tr('sdwan.col_spillover'),tr('col.status')||'Status',tr('col.comment')||'Comment'].forEach((h,i)=>html+=`<th style="cursor:pointer" onclick="_sortStaticTbl(this,${i})">${h}</th>`);
        html+='</tr></thead><tbody>';
        (filterByVdom(sd.members)).forEach(m=>{
          html+=`<tr>
            <td class="mono" style="color:var(--accent)">${esc(m.id)}</td>
            <td class="mono">${esc(m.iface)}</td>
            <td style="color:var(--text-dim)">${esc(m.zone)}</td>
            <td class="mono">${esc(m.gateway)}</td>
            <td class="mono" style="color:var(--text-dim)">${m.gateway6&&m.gateway6!=='-'?esc(m.gateway6):'-'}</td>
            <td class="mono" style="color:var(--yellow)">${m.priority}</td>
            <td class="mono" style="color:var(--text-dim)">${m.weight}</td>
            <td class="mono" style="color:var(--text-dim)">${m.cost}</td>
            <td class="mono" style="color:var(--text-dim)">${m.linkCost||0}</td>
            <td class="mono" style="color:${m.linkStatus==='online'?'var(--green)':'var(--red)'}">${esc(m.linkStatus)}</td>
            <td class="mono">${pill(m.autoFailback==='enable'?'✓':'✗',m.autoFailback==='enable'?'p-allow':'p-deny')}</td>
            <td class="mono">${esc(m.sourceIp)}</td>
            <td class="mono" style="color:var(--text-dim)">${m.spillover||0}</td>
            <td>${memberPill(m.status)}</td>
            <td style="color:var(--text-dim);font-size:11px">${esc(m.comment)}</td>
          </tr>`;
        });
        html+='</tbody></table></div></div>';

        // ── Health Checks table ──
        html+='<div style="margin-bottom:16px">';
        html+='<div style="font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px;padding:0 2px">'+tr('sdwan.health_header')+'</div>';
        html+='<div style="overflow-x:auto"><table><thead><tr>';
        [tr('col.name')||'Name',tr('sdwan.col_server'),tr('col.protocol')||'Protocol','Port',tr('sdwan.col_interval'),'Timeout',tr('sdwan.col_fail'),tr('sdwan.col_restore'),tr('sdwan.detect_mode'),tr('sdwan.password'),tr('sdwan.threshold'),tr('sdwan.col_monitor'),tr('sdwan.col_sla')].forEach((h,i)=>html+=`<th style="cursor:pointer" onclick="_sortStaticTbl(this,${i})">${h}</th>`);
        html+='</tr></thead><tbody>';
        const protoPill=p=>{
          const m={'ping':'p-info','http':'p-allow','https':'p-allow','dns':'p-purple','tcp-echo':'p-warn','udp-echo':'p-warn'};
          return pill(p,m[p]||'p-dim');
        };
        (filterByVdom(sd.healthChecks)).forEach(hc=>{
          const slaStr=hc.slaThresholds.map(s=>`SLA-${s.id}: L≤${s.latency}ms J≤${s.jitter}ms PL≤${s.packetLoss}%`).join(' | ')||'-';
          html+=`<tr>
            <td class="mono" style="color:var(--accent)">${esc(hc.name)}</td>
            <td class="mono">${esc(hc.server)}</td>
            <td>${protoPill(hc.protocol)}</td>
            <td class="mono" style="color:var(--text-dim)">${hc.port!=='-'?esc(hc.port):'-'}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(hc.interval)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(hc.timeout)}</td>
            <td class="mono" style="color:${parseInt(hc.failtime)<=3?'var(--red)':'var(--text-dim)'}">${esc(hc.failtime)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(hc.recoverytime)}</td>
            <td class="mono">${pill(hc.detectMode||'active',hc.detectMode==='active'?'p-allow':'p-dim')}</td>
            <td class="mono">${hc.passwordAuth!=='disable'?pill('✓','p-warn'):'—'}</td>
            <td class="mono" style="color:var(--text-dim)">${hc.threshold}</td>
            <td style="color:var(--text-dim)">${esc(hc.members)}</td>
            <td style="font-size:11px;color:var(--text-dim)">${esc(slaStr)}</td>
          </tr>`;
        });
        html+='</tbody></table></div></div>';

        // ── SD-WAN Rules table ──
        html+='<div style="margin-bottom:16px">';
        html+='<div style="font-size:12px;font-weight:600;color:var(--green);margin-bottom:8px;padding:0 2px">'+tr('sdwan.services_header')+'</div>';
        html+='<div style="overflow-x:auto"><table><thead><tr>';
        ['#',tr('col.name')||'Name',tr('sdwan.col_mode'),tr('sdwan.col_src'),tr('sdwan.col_dst'),tr('col.protocol')||'Protocol',tr('sdwan.route_tag'),tr('sdwan.bandwidth_min'),tr('sdwan.bandwidth_max'),tr('sdwan.application'),tr('sdwan.groups'),tr('sdwan.col_pref'),tr('sdwan.col_sla_ref'),tr('col.status')||'Status',tr('col.comment')||'Comment'].forEach((h,i)=>html+=`<th style="cursor:pointer" onclick="_sortStaticTbl(this,${i})">${h}</th>`);
        html+='</tr></thead><tbody>';
        const modePill=m=>{
          const map={'sla':'p-allow','load-balance':'p-info','measured-volume-based':'p-purple','priority':'p-warn','manual':'p-dim','auto':'p-dim'};
          return pill(m,map[m]||'p-dim');
        };
        (filterByVdom(sd.services)).forEach(svc=>{
          const slaStr=svc.slaRefs.length?svc.slaRefs.map(r=>`${r.healthCheck}#${r.id}`).join(', '):'-';
          const target=svc.priorityZone!=='-'?svc.priorityZone:svc.priorityMembers!=='-'?svc.priorityMembers:'-';
          const proto=svc.protocol==='0'?'any':svc.protocol;
          const port=svc.startPort!=='-'?`${svc.startPort}${svc.endPort!==svc.startPort?'-'+svc.endPort:''}`:'-';
          html+=`<tr>
            <td class="mono" style="color:var(--accent)">${esc(svc.id)}</td>
            <td style="font-weight:500">${esc(svc.name)}</td>
            <td>${modePill(svc.mode)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(svc.src)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(svc.dst)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(proto)}${port!=='-'?' :'+port:''}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(svc.routeTag)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(svc.minBandwidth)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(svc.maxBandwidth)}</td>
            <td class="mono" style="color:var(--text-dim);font-size:11px">${esc(svc.application)}</td>
            <td class="mono" style="color:var(--text-dim);font-size:11px">${esc(svc.groups)}</td>
            <td style="color:var(--text-dim);font-size:11px">${esc(target)}</td>
            <td style="color:var(--text-dim);font-size:11px">${esc(slaStr)}</td>
            <td>${svc.status==='disable'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td>
            <td style="color:var(--text-dim);font-size:11px">${esc(svc.comment)}</td>
          </tr>`;
        });
        html+='</tbody></table></div></div>';

        // ── Zones + Neighbors ──
        if(sd.zones.length||sd.neighbors.length){
          html+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">';
          if(sd.zones.length){
            html+='<div><div style="font-size:12px;font-weight:600;color:var(--purple);margin-bottom:8px">🏷️ Zone</div>';
            html+='<table><thead><tr><th>'+tr('sdwan.col_zone_name')+'</th><th>VDOM</th></tr></thead><tbody>';
            sd.zones.forEach(z=>{ html+=`<tr><td class="mono" style="color:var(--accent)">${esc(z.name)}</td><td style="color:var(--text-dim)">${esc(z._vdom||'-')}</td></tr>`; });
            html+='</tbody></table></div>';
          }
          if(sd.neighbors.length){
            html+='<div><div style="font-size:12px;font-weight:600;color:var(--orange);margin-bottom:8px">'+tr('sdwan.bgp_header')+'</div>';
            html+='<table><thead><tr><th>IP</th><th>Member</th><th>'+tr('sdwan.col_role')+'</th><th>VDOM</th></tr></thead><tbody>';
            sd.neighbors.forEach(n=>{ html+=`<tr><td class="mono">${esc(n.ip)}</td><td class="mono">${esc(n.member)}</td><td style="color:var(--text-dim)">${esc(n.role)}</td><td style="color:var(--text-dim)">${esc(n._vdom||'-')}</td></tr>`; });
            html+='</tbody></table></div>';
          }
          html+='</div>';
        }

        $('tbl-wrap').innerHTML=html;
        return;
      }

      case 'ha': {
        $('sum-wrap').innerHTML='';$('tbl-wrap').innerHTML='';$('filter-action').style.display='none';
        const ha = d.ha;
        if(!ha||!ha.enabled){
          $('tbl-wrap').innerHTML='<div class="nodata">'+tr('ha.no_ha')+'</div>';
          return;
        }
        $('tbl-section-label').textContent='HA / Cluster';
        $('sum-wrap').innerHTML=sumC([
          {l:tr('ha.mode'), v:ha.mode, c:'var(--accent)'},
          {l:tr('ha.group_id'), v:ha.groupId, c:'var(--green)'},
          {l:tr('ha.priority'), v:ha.priority, c:'var(--yellow)'},
        ]);
        $('tbl-cnt').textContent='1';
        // 單一設定物件（非清單），沿用既有 SNMP Agent Info 橫向資訊卡樣式，欄位依廠牌
        // 實際可得資訊部分留空（'-'），只顯示有值的欄位，不強求每廠牌欄位齊全
        let html=`<div style="background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:16px;display:flex;gap:32px;flex-wrap:wrap">`;
        const haField=(label,val)=>val&&val!=='-'?`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${label}</div><div class="mono" style="color:var(--text);margin-top:4px">${esc(val)}</div></div>`:'';
        html+=haField(tr('ha.mode'), ha.mode);
        html+=haField(tr('ha.group_id'), ha.groupId);
        html+=haField(tr('ha.priority'), ha.priority);
        html+=haField(tr('ha.peer_ip'), ha.peerIp);
        html+=haField(tr('ha.sync_interface'), ha.syncInterface);
        html+=haField(tr('ha.vip'), ha.vip);
        html+='</div>';
        $('tbl-wrap').innerHTML=html;
        return;
      }

      case 'dhcp': {
        $('sum-wrap').innerHTML=''; $('tbl-wrap').innerHTML=''; $('filter-action').style.display='none';
        const dh=d.dhcp;
        if(!dh||(!dh.servers.length&&!dh.relays.length)){
          $('tbl-wrap').innerHTML='<div class="nodata">'+tr('dhcp.no_dhcp')+'</div>'; return;
        }
        $('tbl-section-label').textContent='DHCP';
        $('sum-wrap').innerHTML=sumC([
          {l:'DHCP Server', v:dh.servers.length, c:'var(--green)'},
          {l:'DHCP Relay',  v:dh.relays.length,  c:'var(--yellow)'},
          {l:tr('sl.enabled'), v:dh.servers.filter(s=>s.status==='enable').length, c:'var(--accent)'},
          {l:tr('sl.disabled'), v:dh.servers.filter(s=>s.status!=='enable').length, c:'var(--red)'},
        ]);
        $('tbl-cnt').textContent=`${dh.servers.length} ${tr('unit.server')}, ${dh.relays.length} ${tr('unit.relay')}`;
        let html='';
        if(dh.servers.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--green);margin-bottom:8px">📡 DHCP Server</div>';
          html+='<div style="overflow-x:auto;margin-bottom:20px"><table><thead><tr>';
          [tr('col.name'),tr('col.intf'),tr('col.start_ip'),tr('col.end_ip'),tr('col.gateway'),tr('col.mask'),'DNS 1','DNS 2',tr('col.domain'),tr('col.lease'),tr('col.status'),tr('col.comment')].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          filterByVdom(dh.servers).forEach(s=>{
            html+=`<tr>
              <td class="mono" style="color:var(--accent)">${esc(s.name)}</td>
              <td class="mono">${esc(s.iface)}</td>
              <td class="mono">${esc(s.startIp)}</td>
              <td class="mono">${esc(s.endIp)}</td>
              <td class="mono">${esc(s.gateway)}</td>
              <td class="mono" style="color:var(--text-dim)">${esc(s.mask)}</td>
              <td class="mono" style="color:var(--yellow)">${esc(s.dns1)}</td>
              <td class="mono" style="color:var(--text-dim)">${esc(s.dns2)}</td>
              <td style="color:var(--text-dim)">${esc(s.domain)}</td>
              <td class="mono" style="color:var(--text-dim)">${esc(s.lease)}</td>
              <td>${s.status==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</td>
              <td style="color:var(--text-dim);font-size:11px">${esc(s.comment)}</td>
            </tr>`;
          });
          html+='</tbody></table></div>';
        }
        if(dh.relays.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px">🔀 DHCP Relay</div>';
          html+='<div style="overflow-x:auto"><table><thead><tr>';
          [tr('col.name'),tr('col.intf'),tr('dhcp.relay_server'),tr('col.status'),tr('col.comment')].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          filterByVdom(dh.relays).forEach(r=>{
            html+=`<tr>
              <td class="mono" style="color:var(--accent)">${esc(r.name)}</td>
              <td class="mono">${esc(r.iface)}</td>
              <td class="mono" style="color:var(--yellow)">${esc(r.serverIp)}</td>
              <td>${r.status==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</td>
              <td style="color:var(--text-dim);font-size:11px">${esc(r.comment)}</td>
            </tr>`;
          });
          html+='</tbody></table></div>';
        }
        $('tbl-wrap').innerHTML=html;
        return;
      }

      case 'dns': {
        $('sum-wrap').innerHTML=''; $('tbl-wrap').innerHTML=''; $('filter-action').style.display='none';
        const dn=d.dns;
        if(!dn||(!dn.servers.length&&!dn.static.length&&!dn.proxyRules.length)){
          $('tbl-wrap').innerHTML='<div class="nodata">'+tr('dns.no_dns')+'</div>'; return;
        }
        $('tbl-section-label').textContent='DNS';
        $('sum-wrap').innerHTML=sumC([
          {l:'DNS Server',    v:dn.servers.length+dn.secondaries.length, c:'var(--accent)'},
          {l:'DNS Proxy',     v:dn.proxy?1:0,    c:dn.proxy?'var(--green)':'var(--text-dim)'},
          {l:tr('dns.proxy_rules'), v:dn.proxyRules.length, c:'var(--yellow)'},
          {l:tr('dns.static_records'), v:dn.static.length, c:'var(--purple)'},
          {l:'DNS over TLS',  v:dn.dnsOverTls?1:0, c:dn.dnsOverTls?'var(--green)':'var(--text-dim)'},
          {l:tr('col.domain'), v:dn.domain&&dn.domain!=='-'?dn.domain:'—', c:'var(--info)'},
        ]);
        $('tbl-cnt').textContent=`${dn.servers.length} ${tr('unit.server')}`;
        let html='';
        // Summary info bar
        const servers_all=[...dn.servers,...dn.secondaries];
        if(servers_all.length){
          html+=`<div style="background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:16px;display:flex;gap:24px;flex-wrap:wrap">`;
          html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">DNS Server</div><div class="mono" style="color:var(--accent);font-size:14px;margin-top:4px;max-width:260px;overflow-wrap:break-word;word-break:break-word">${dn.servers.map(s=>`${esc(s)}`).join(' &nbsp;·&nbsp; ')||'-'}</div></div>`;
          if(dn.secondaries.length) html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">Secondary</div><div class="mono" style="color:var(--text-dim);font-size:14px;margin-top:4px;max-width:260px;overflow-wrap:break-word;word-break:break-word">${dn.secondaries.map(s=>esc(s)).join(' &nbsp;·&nbsp; ')}</div></div>`;
          if(dn.domain&&dn.domain!=='-') html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('col.domain')}</div><div style="color:var(--text);font-size:14px;margin-top:4px;max-width:260px;overflow-wrap:break-word;word-break:break-word">${esc(dn.domain)}</div></div>`;
          html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">DNS Proxy</div><div style="margin-top:4px">${dn.proxy?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-dim')}</div></div>`;
          html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">DNS over TLS</div><div style="margin-top:4px">${dn.dnsOverTls?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-dim')}</div></div>`;
          html+='</div>';
        }
        // Proxy rules
        if(dn.proxyRules.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px">🔀 Conditional Forwarding / '+tr('dns.proxy_rules')+'</div>';
          html+=`<div style="overflow-x:auto;margin-bottom:20px"><table><thead><tr><th>${tr('col.domain')}</th><th>${tr('dns.fwd_target')}</th></tr></thead><tbody>`;
          dn.proxyRules.forEach(r=>{
            html+=`<tr><td class="mono" style="color:var(--accent)">${esc(r.domain)}</td><td class="mono" style="color:var(--yellow)">${esc(r.target)}</td></tr>`;
          });
          html+='</tbody></table></div>';
        }
        // Static records
        if(dn.static.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--purple);margin-bottom:8px">📋 '+tr('dns.static_records')+'</div>';
          html+='<div style="overflow-x:auto"><table><thead><tr><th>'+tr('dns.col_host')+'</th><th>'+tr('dns.col_type')+'</th><th>'+tr('dns.col_ip_target')+'</th><th>'+tr('dns.col_zone_name')+'</th></tr></thead><tbody>';
          dn.static.forEach(r=>{
            html+=`<tr><td class="mono">${esc(r.name)}</td><td>${pill(r.type||'A','p-info')}</td><td class="mono" style="color:var(--accent)">${esc(r.ip)}</td><td style="color:var(--text-dim)">${esc(r.zone||'-')}</td></tr>`;
          });
          html+='</tbody></table></div>';
        }
        $('tbl-wrap').innerHTML=html;
        return;
      }

      case 'snmp': {
        $('sum-wrap').innerHTML=''; $('tbl-wrap').innerHTML=''; $('filter-action').style.display='none';
        const sn=d.snmp;
        if(!sn||(!sn.enabled&&!sn.communities.length&&!sn.v3users.length)){
          $('tbl-wrap').innerHTML='<div class="nodata">'+tr('snmp.no_snmp')+'</div>'; return;
        }
        $('tbl-section-label').textContent='SNMP';
        const verBadges=(sn.agent.version||[]).map(v=>pill(v.toUpperCase(),'p-info')).join(' ')||pill(tr('snmp.unknown'),'p-dim');
        $('sum-wrap').innerHTML=sumC([
          {l:tr('snmp.community_count'), v:sn.communities.length,   c:'var(--accent)'},
          {l:tr('snmp.v3_users'),          v:sn.v3users.length,        c:'var(--purple)'},
          {l:tr('snmp.trap_servers'),       v:sn.trapServers.length,    c:'var(--yellow)'},
          {l:tr('snmp.version'),          v:(sn.agent.version||[]).join('/'), c:'var(--green)'},
          {l:tr('col.status'),      v:sn.enabled?tr('wwan.pill_enable'):tr('wwan.pill_disable'), c:sn.enabled?'var(--green)':'var(--red)'},
        ]);
        $('tbl-cnt').textContent=`${sn.communities.length} community, ${sn.v3users.length} v3 user`;
        let html='';
        // Agent info
        html+=`<div style="background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:16px;display:flex;gap:32px;flex-wrap:wrap">`;
        html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.agent_name')}</div><div style="color:var(--text);margin-top:4px;max-width:240px;overflow-wrap:break-word;word-break:break-word">${esc(sn.agent.name)}</div></div>`;
        html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.contact')}</div><div style="color:var(--text);margin-top:4px;max-width:240px;overflow-wrap:break-word;word-break:break-word">${esc(sn.agent.contact)}</div></div>`;
        html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.location')}</div><div style="color:var(--text);margin-top:4px;max-width:240px;overflow-wrap:break-word;word-break:break-word">${esc(sn.agent.location)}</div></div>`;
        html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.desc')}</div><div style="color:var(--text-dim);margin-top:4px;max-width:240px;overflow-wrap:break-word;word-break:break-word">${esc(sn.agent.description)}</div></div>`;
        html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.col_version')}</div><div style="margin-top:4px">${verBadges}</div></div>`;
        html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('col.status')}</div><div style="margin-top:4px">${sn.enabled?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</div></div>`;
        html+='</div>';
        // v1/v2c Communities
        if(sn.communities.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--accent);margin-bottom:8px">'+tr('snmp.community_header')+'</div>';
          html+='<div style="overflow-x:auto;margin-bottom:20px"><table><thead><tr>';
          [tr('snmp.col_community'),tr('snmp.col_perm'),tr('snmp.col_hosts'),tr('snmp.col_events'),tr('col.status')||'Status'].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          sn.communities.forEach(comm=>{
            const permPill=comm.permission==='ro'?pill(tr('snmp.perm_ro'),'p-info'):pill(tr('snmp.perm_rw'),'p-warn');
            const hostStr=(comm.allowedHosts||[]).filter(h=>h&&h!=='-').join(', ')||'any';
            html+=`<tr><td class="mono" style="color:var(--accent)">${esc(comm.name)}</td><td>${permPill}</td><td class="mono" style="color:var(--text-dim)">${esc(hostStr)}</td><td style="color:var(--text-dim);font-size:11px">${esc(comm.events||'-')}</td><td>${comm.status==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</td></tr>`;
          });
          html+='</tbody></table></div>';
        }
        // v3 Users
        if(sn.v3users.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--purple);margin-bottom:8px">'+tr('snmp.v3_header')+'</div>';
          html+='<div style="overflow-x:auto;margin-bottom:20px"><table><thead><tr>';
          [tr('snmp.col_user'),tr('snmp.col_sec_level'),tr('snmp.col_auth_proto'),tr('snmp.col_priv_proto'),tr('snmp.col_notify'),tr('col.status')||'Status'].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          sn.v3users.forEach(u=>{
            const slPill={'auth-priv':pill('auth+priv','p-allow'),'auth-no-priv':pill('auth-only','p-warn'),'no-auth-no-priv':pill('no-auth','p-deny')}[u.secLevel]||pill(u.secLevel,'p-dim');
            const authColor={'sha256':'p-allow','sha512':'p-allow','sha':'p-info','md5':'p-deny'}[u.authProto?.toLowerCase()]||'p-dim';
            const privColor={'aes256':'p-allow','aes128':'p-allow','aes':'p-info','des':'p-deny'}[u.privProto?.toLowerCase()]||'p-dim';
            html+=`<tr><td class="mono" style="color:var(--purple)">${esc(u.name)}</td><td>${slPill}</td><td>${pill(u.authProto?.toUpperCase()||'-',authColor)}</td><td>${pill(u.privProto?.toUpperCase()||'-',privColor)}</td><td class="mono" style="color:var(--text-dim)">${esc(u.notifyHost||'-')}</td><td>${u.status==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</td></tr>`;
          });
          html+='</tbody></table></div>';
        }
        // Trap Servers
        if(sn.trapServers.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px">'+tr('snmp.trap_header')+'</div>';
          html+='<div style="overflow-x:auto"><table><thead><tr>';
          [tr('snmp.col_ip'),'Port','Community',tr('snmp.col_version')].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          sn.trapServers.forEach(ts=>{ html+=`<tr><td class="mono" style="color:var(--yellow)">${esc(ts.ip)}</td><td class="mono">${esc(ts.port||'162')}</td><td class="mono" style="color:var(--text-dim)">${esc(ts.community||'-')}</td><td>${pill(ts.version||'v2c','p-info')}</td></tr>`; });
          html+='</tbody></table></div>';
        }
        $('tbl-wrap').innerHTML=html;
        return;
      }

      case 'log': {
        $('sum-wrap').innerHTML=''; $('tbl-wrap').innerHTML=''; $('filter-action').style.display='none';
        const lg=d.logservers;
        if(!lg||(!lg.syslog.length&&!lg.fortianalyzer.length&&!lg.netflow.length)){
          $('tbl-wrap').innerHTML='<div class="nodata">'+tr('log.no_log')+'</div>'; return;
        }
        $('tbl-section-label').textContent='Log Server';
        $('sum-wrap').innerHTML=sumC([
          {l:'Syslog',       v:lg.syslog.length,        c:'var(--accent)'},
          {l:'FortiAnalyzer',v:lg.fortianalyzer.length,  c:'var(--orange)'},
          {l:'NetFlow',      v:lg.netflow.length,        c:'var(--purple)'},
          {l:'Log Profile',  v:lg.logForward.length,     c:'var(--info)'},
        ]);
        $('tbl-cnt').textContent=`${lg.syslog.length+lg.fortianalyzer.length} ${tr('unit.log_target')}`;
        let html='';
        if(lg.syslog.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--accent);margin-bottom:8px">📋 Syslog Server</div>';
          html+='<div style="overflow-x:auto;margin-bottom:20px"><table><thead><tr>';
          [tr('col.name')||'Name','Server IP','Port',tr('log.col_facility'),tr('log.col_format'),'Protocol',tr('log.col_level'),tr('col.status')||'Status'].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          filterByVdom(lg.syslog).forEach(s=>{
            const protoP=s.protocol==='TCP'?pill('TCP','p-allow'):pill('UDP','p-info');
            html+=`<tr><td style="color:var(--accent)">${esc(s.name)}</td><td class="mono">${esc(s.server)}</td><td class="mono">${esc(s.port||'514')}</td><td style="color:var(--text-dim)">${esc(s.facility||'local7')}</td><td style="color:var(--text-dim)">${esc(s.format||'default')}</td><td>${protoP}</td><td style="color:var(--text-dim)">${esc(s.level||'-')}</td><td>${s.status==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</td></tr>`;
          });
          html+='</tbody></table></div>';
        }
        if(lg.fortianalyzer.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--orange);margin-bottom:8px">'+tr('log.fortianalyzer_header')+'</div>';
          html+='<div style="overflow-x:auto;margin-bottom:20px"><table><thead><tr>';
          [tr('col.name')||'Name','Server IP','Port',tr('log.col_reliable'),tr('log.col_encrypt'),tr('col.status')||'Status'].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          filterByVdom(lg.fortianalyzer).forEach(f=>{
            const relP=f.reliable==='enable'?pill(tr('log.tcp_reliable'),'p-allow'):pill(tr('log.udp_label'),'p-info');
            html+=`<tr><td style="color:var(--orange)">${esc(f.name)}</td><td class="mono">${esc(f.server)}</td><td class="mono">${esc(f.port||'514')}</td><td>${relP}</td><td style="color:var(--text-dim)">${esc(f.encAlgo||'-')}</td><td>${f.status==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</td></tr>`;
          });
          html+='</tbody></table></div>';
        }
        if(lg.netflow.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--purple);margin-bottom:8px">📈 NetFlow / sFlow</div>';
          html+='<div style="overflow-x:auto;margin-bottom:20px"><table><thead><tr>';
          ['Collector IP','Port',tr('log.col_timeout'),tr('col.status')||'Status'].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          lg.netflow.forEach(n=>{ html+=`<tr><td class="mono" style="color:var(--purple)">${esc(n.collector)}</td><td class="mono">${esc(n.port||'2055')}</td><td class="mono" style="color:var(--text-dim)">${esc(n.activeTimeout||'60')}</td><td>${n.status==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</td></tr>`; });
          html+='</tbody></table></div>';
        }
        if(lg.logForward.length){
          html+='<div style="font-size:12px;font-weight:600;color:var(--info);margin-bottom:8px">🔀 Log Forwarding Profile</div>';
          html+='<div style="overflow-x:auto"><table><thead><tr><th>'+tr('col.name')+'</th><th>'+tr('popup.col_type')+'</th><th>'+tr('log.col_target')+'</th></tr></thead><tbody>';
          lg.logForward.forEach(lf=>{ html+=`<tr><td class="mono">${esc(lf.name)}</td><td style="color:var(--text-dim)">${esc(lf.type||'-')}</td><td class="mono" style="color:var(--text-dim)">${esc(lf.target||'-')}</td></tr>`; });
          html+='</tbody></table></div>';
        }
        $('tbl-wrap').innerHTML=html;
        return;
      }

      case 'wwan': {
        $('sum-wrap').innerHTML=''; $('tbl-wrap').innerHTML=''; $('filter-action').style.display='none';
        const ww=d.wwan;
        if(!ww||(!ww.profiles?.length&&!ww.lteModem&&!ww.systemModem&&!ww.modem5G&&!ww.lteInterfaces?.length)){
          $('tbl-wrap').innerHTML=`<div class="nodata">${tr('wwan.no_wwan')}</div>`; return;
        }
        $('tbl-section-label').textContent=tr('wwan.section_label');
        const dualSim=ww.profiles?.length>0&&[...new Set(ww.profiles.map(p=>p.modemId))].length>1;
        const m5g=ww.modem5G;
        const has5G=m5g&&(m5g.modem1||m5g.modem2);
        const sim1Set=has5G&&m5g.modem1?.sim1Pin==='set';
        const sim2Set=has5G&&(m5g.modem1?.sim2Pin==='set'||m5g.modem2?.sim1Pin==='set');
        $('sum-wrap').innerHTML=sumC([
          ...(has5G?[{l:'5G Modem',v:(m5g.modem1?1:0)+(m5g.modem2?1:0),c:'var(--accent)'}]:[]),
          ...(ww.profiles?.length?[{l:'WWAN Profile',v:ww.profiles.length,c:'var(--accent)'}]:[]),
          ...(has5G?[{l:'SIM1 PIN',v:sim1Set?tr('wwan.pin_set'):tr('wwan.pin_notset'),c:sim1Set?'var(--green)':'var(--text-dim)'}]:[]),
          ...(has5G?[{l:'SIM2 PIN',v:sim2Set?tr('wwan.pin_set'):tr('wwan.pin_notset'),c:sim2Set?'var(--green)':'var(--text-dim)'}]:[]),
          ...(ww.lteModem?[{l:'LTE Modem',v:ww.lteModem.status,c:ww.lteModem.status==='enable'?'var(--green)':'var(--text-dim)'}]:[]),
        ]);
        let html='';
        // ── 5G Modem ─────────────────────────────────────────────────────
        const render5GModemBlock=(m,label)=>{
          if(!m)return'';
          let r=`<div style="margin-top:20px;font-size:12px;font-weight:600;color:var(--accent);margin-bottom:8px">📶 ${label}</div>`;
          r+=`<table><thead><tr><th>APN</th><th>${tr('wwan.col_carrier')}</th><th>${tr('wwan.col_auth')}</th><th>${tr('wwan.col_user')}</th><th>${tr('wwan.col_sim1pin')}</th><th>${tr('wwan.col_sim2pin')}</th><th>${tr('wwan.col_prefer_sim')}</th><th>${tr('wwan.col_iface')}</th></tr></thead><tbody><tr>
            <td class="mono">${esc(m.apn)}</td>
            <td>${esc(m.apnProvider)}</td>
            <td>${esc(m.authType)}</td>
            <td class="mono">${esc(m.username)}</td>
            <td style="color:${m.sim1Pin==='set'?'var(--green)':'var(--text-dim)'}">${m.sim1Pin==='set'?tr('wwan.pin_set'):tr('wwan.pin_notset')}</td>
            <td style="color:${m.sim2Pin==='set'?'var(--green)':'var(--text-dim)'}">${m.sim2Pin==='set'?tr('wwan.pin_set'):tr('wwan.pin_notset')}</td>
            <td>${esc(m.preferSim)}</td>
            <td class="mono">${esc(m.interface)}</td>
          </tr></tbody></table>`;
          return r;
        };
        if(has5G){
          html+=render5GModemBlock(m5g.modem1,'5G Modem 1');
          html+=render5GModemBlock(m5g.modem2,'5G Modem 2');
        }
        // ── WWAN Profiles（舊型 wwan-profile）────────────────────────────
        if(ww.profiles?.length){
          html+='<div style="margin-top:20px;font-size:12px;font-weight:600;color:var(--accent);margin-bottom:8px">📋 WWAN Profile</div>';
          html+='<div style="overflow-x:auto"><table><thead><tr>';
          [tr('wwan.col_profile_name'),'APN',tr('wwan.col_auth'),tr('wwan.col_user'),tr('wwan.col_modem'),tr('wwan.col_simpin'),tr('wwan.col_carrier'),tr('wwan.col_dataplan'),'VDOM'].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          filterByVdom(ww.profiles).forEach(p=>{
            html+=`<tr>
              <td class="mono" style="color:var(--accent)">${esc(p.name)}</td>
              <td class="mono">${esc(p.apn)}</td>
              <td>${esc(p.authType)}</td>
              <td class="mono">${esc(p.username)}</td>
              <td style="text-align:center">${esc(p.modemId)}</td>
              <td style="color:${p.simPin==='set'?'var(--green)':'var(--text-dim)'}">${p.simPin==='set'?tr('wwan.pin_set'):tr('wwan.pin_notset')}</td>
              <td>${esc(p.provider)}</td>
              <td>${esc(p.dataplan)}</td>
              <td style="color:var(--text-dim)">${esc(p._vdom||'-')}</td>
            </tr>`;
          });
          html+='</tbody></table></div>';
        }
        // ── LTE Modem（舊型 system lte-modem）───────────────────────────
        if(ww.lteModem){
          html+=`<div style="margin-top:20px;font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px">⚙ ${tr('wwan.lte_settings')}</div>`;
          html+=`<table><thead><tr><th>${tr('col.status')}</th><th>${tr('wwan.col_port')}</th><th>APN</th><th>${tr('wwan.col_auth')}</th><th>${tr('wwan.col_autoswitch')}</th></tr></thead><tbody><tr>
            <td>${ww.lteModem.status==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</td>
            <td class="mono">${esc(ww.lteModem.modemPort)}</td>
            <td class="mono">${esc(ww.lteModem.apn)}</td>
            <td>${esc(ww.lteModem.authType)}</td>
            <td>${ww.lteModem.autoSwitch==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-dim')}</td>
          </tr></tbody></table>`;
        }
        // ── 系統 Modem（legacy）─────────────────────────────────────────
        if(ww.systemModem&&ww.systemModem.pinInit&&ww.systemModem.pinInit!=='-'){
          html+=`<div style="margin-top:16px;font-size:11px;color:var(--text-dim)">⚙ ${tr('wwan.modem_at')}：<span class="mono">${esc(ww.systemModem.pinInit)}</span></div>`;
        }
        // ── MikroTik LTE 介面 ────────────────────────────────────────────
        if(ww.lteInterfaces?.length){
          html+=`<div style="margin-top:20px;font-size:12px;font-weight:600;color:var(--accent);margin-bottom:8px">📱 ${tr('wwan.lte_iface')}</div>`;
          html+=`<table><thead><tr><th>${tr('col.name')}</th><th>${tr('wwan.col_apn_profile')}</th><th>${tr('wwan.col_roaming')}</th><th>${tr('col.status')}</th><th>${tr('wwan.col_note')}</th></tr></thead><tbody>`;
          ww.lteInterfaces.forEach(i=>{
            html+=`<tr>
              <td class="mono" style="color:var(--accent)">${esc(i.name)}</td>
              <td class="mono">${esc(i.apnProfile)}</td>
              <td>${i.allowRoaming==='yes'?pill(tr('wwan.pill_allow'),'p-warn'):pill(tr('wwan.pill_disable'),'p-dim')}</td>
              <td>${i.disabled==='yes'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td>
              <td style="color:var(--text-dim)">${esc(i.comment)}</td>
            </tr>`;
          });
          html+=`</tbody></table>`;
        }
        // ── MikroTik APN 設定檔 ──────────────────────────────────────────
        if(ww.apnProfiles?.length){
          html+=`<div style="margin-top:16px;font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px">📋 ${tr('wwan.lte_apn_profile')}</div>`;
          html+=`<table><thead><tr><th>${tr('wwan.col_apn_name')}</th><th>APN</th><th>${tr('wwan.col_auth')}</th><th>${tr('wwan.col_user')}</th><th>${tr('wwan.col_password')}</th><th>${tr('wwan.col_ip_type')}</th><th>${tr('wwan.col_distance')}</th></tr></thead><tbody>`;
          ww.apnProfiles.forEach(p=>{
            html+=`<tr>
              <td class="mono" style="color:var(--accent)">${esc(p.name)}</td>
              <td class="mono">${esc(p.apn)}</td>
              <td>${esc(p.authType)}</td>
              <td class="mono">${esc(p.username)}</td>
              <td style="color:var(--text-dim)">${p.passwd==='enc'?tr('wwan.pass_enc'):p.passwd==='plain'?tr('wwan.pass_plain'):esc(p.passwd)}</td>
              <td>${esc(p.ipType)}</td>
              <td style="text-align:center">${esc(p.distance)}</td>
            </tr>`;
          });
          html+=`</tbody></table>`;
        }
        if(!html){html=`<div class="nodata">${tr('wwan.no_modem_detail')}</div>`;}
        $('tbl-wrap').innerHTML=html;
        const cnt=(ww.profiles?.length)||(ww.lteInterfaces?.length)||(has5G?(m5g.modem1?1:0)+(m5g.modem2?1:0):0);
        $('tbl-cnt').textContent=cnt?`${cnt} ${tr('unit.modem_profile')}`:tr('unit.wwan_iface');
        return;
      }

      case 'wlan': {
        $('sum-wrap').innerHTML=''; $('tbl-wrap').innerHTML=''; $('filter-action').style.display='none';
        const wl=d.wlan;
        if(!wl||(!wl.interfaces.length&&!wl.capsmanConfigs.length)){
          $('tbl-wrap').innerHTML='<div class="nodata">'+tr('wlan.no_wlan')+'</div>'; return;
        }
        $('tbl-section-label').textContent=tr('wlan.section_label');
        const openCount=wl.interfaces.filter(i=>i.authTypes==='none'||i.authTypes==='-').length;
        $('sum-wrap').innerHTML=sumC([
          {l:tr('wifi.managed_iface'),v:wl.interfaces.length,c:'var(--accent)'},
          {l:tr('wifi.ap_mode'),v:wl.interfaces.filter(i=>/ap-bridge|ap$/.test(i.mode)).length,c:'var(--green)'},
          {l:tr('wifi.open_ssid'),v:openCount,c:openCount>0?'var(--red)':'var(--text-dim)'},
          ...(wl.capsmanEnabled?[{l:'CAPsMAN',v:tr('wwan.pill_enable'),c:'var(--yellow)'}]:[]),
        ]);
        let html='';
        if(wl.interfaces.length){
          html+='<div style="overflow-x:auto"><table><thead><tr>';
          [tr('col.name'),'SSID',tr('col.wifi_band'),tr('col.mode'),tr('col.wifi_freq'),tr('col.wifi_chan_width'),tr('col.wifi_country'),tr('col.wifi_sec_profile'),tr('col.wifi_auth'),tr('col.wifi_key'),tr('col.status'),tr('col.desc')].forEach(h=>html+=`<th>${h}</th>`);
          html+='</tr></thead><tbody>';
          wl.interfaces.forEach(i=>{
            const authColor=i.authTypes==='none'||i.authTypes==='-'?'var(--red)':'var(--green)';
            html+=`<tr>
              <td class="mono" style="color:var(--accent)">${esc(i.name)}</td>
              <td style="font-weight:600">${esc(i.ssid)}</td>
              <td>${esc(i.band)}</td>
              <td>${esc(i.mode)}</td>
              <td class="mono">${esc(i.frequency)}</td>
              <td>${esc(i.channelWidth)}</td>
              <td>${esc(i.country)}</td>
              <td class="mono" style="color:var(--text-dim)">${esc(i.secProfile)}</td>
              <td style="color:${authColor}">${esc(i.authTypes)}</td>
              <td>${i.hasKey?pill(tr('wwan.pin_set'),'p-allow'):pill(tr('wwan.pin_notset'),'p-deny')}</td>
              <td>${i.disabled==='yes'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td>
              <td style="color:var(--text-dim)">${esc(i.comment)}</td>
            </tr>`;
          });
          html+='</tbody></table></div>';
        }
        if(wl.capsmanConfigs.length){
          html+=`<div style="margin-top:20px;font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px">🗂 ${tr('wifi.capsman_title')}（${wl.capsmanConfigs.length}${tr('unit.count')}）</div>`;
          html+=`<table><thead><tr><th>${tr('wifi.config_name')}</th><th>SSID</th><th>${tr('col.wifi_band')}</th><th>${tr('col.wifi_auth')}</th><th>${tr('col.wifi_key')}</th></tr></thead><tbody>`;
          wl.capsmanConfigs.forEach(c=>{
            html+=`<tr>
              <td class="mono" style="color:var(--accent)">${esc(c.name)}</td>
              <td style="font-weight:600">${esc(c.ssid)}</td>
              <td>${esc(c.band)}</td>
              <td>${esc(c.authTypes)}</td>
              <td>${c.hasKey?pill(tr('wwan.pin_set'),'p-allow'):pill(tr('wwan.pin_notset'),'p-deny')}</td>
            </tr>`;
          });
          html+='</tbody></table>';
        }
        $('tbl-wrap').innerHTML=html;
        $('tbl-cnt').textContent=`${wl.interfaces.length} ${tr('unit.wifi_iface')}`;
        return;
      }

      case 'wifi':
        $('sum-wrap').innerHTML = '';
        if (!WIFI_DATA) {
          // 2026-08-19 新增：上傳的廠牌若命中 WIFI_UNSUPPORTED（查證後確認查無語法佐證），
          // 顯示專屬警示文字，區分「這廠牌沒設定 WiFi」與「本工具查證後確認不支援解析」
          const unsupportedMsg = WIFI_UNSUPPORTED.some(slot => ST.raw[slot]) ? tr('wifi.vendor_unsupported') : tr('wifi.no_data');
          $('tbl-wrap').innerHTML='<div class="nodata">'+unsupportedMsg+'</div>'; return;
        }
        {
          // 依 ACTIVE_VDOM 過濾 WiFi 資料
          const wv = (ACTIVE_VDOM === '__all__') ? WIFI_DATA : (() => {
            const fv = v => !v._vdom || v._vdom === ACTIVE_VDOM;
            const fVaps = WIFI_DATA.vaps.filter(fv);
            const fProfs = WIFI_DATA.wtpProfiles.filter(fv);
            const fWtps  = WIFI_DATA.wtps.filter(fv);
            const fWids  = WIFI_DATA.widsProfiles.filter(fv);
            return {
              vaps: fVaps, wtpProfiles: fProfs, wtps: fWtps, widsProfiles: fWids,
              summary: {
                ...WIFI_DATA.summary,
                ssidCount:    fVaps.length,
                apCount:      fWtps.length,
                profileCount: fProfs.length,
                widsCount:    fWids.length,
                openSsids:    fVaps.filter(v=>v.security==='open'&&!v.captivePortal).length,
                captiveSsids: fVaps.filter(v=>v.captivePortal).length,
                hiddenSsids:  fVaps.filter(v=>!v.broadcastSsid).length,
                wpa3Ssids:    fVaps.filter(v=>v.security.includes('wpa3')).length,
                wifi6Aps:     fProfs.filter(p=>p.wifiGen.includes('Wi-Fi 6')).length,
                avgSecScore:  fVaps.length ? Math.round(fVaps.reduce((s,v)=>s+v.secScore,0)/fVaps.length) : 0,
              },
            };
          })();
          $('tbl-wrap').innerHTML = renderWifiSection(wv);
          $('tbl-cnt').textContent = wv.summary.ssidCount + ' ' + tr('unit.ssid');
          $('sum-wrap').innerHTML = sumC([
            {l:'SSID',                    v:wv.summary.ssidCount,    c:'var(--accent)'},
            {l:tr('wifi.ap_count'),       v:wv.summary.apCount,      c:'var(--green)'},
            {l:tr('wifi.ap_profile_count'),v:wv.summary.profileCount, c:'var(--purple)'},
            {l:tr('wifi.open_ssid'),      v:wv.summary.openSsids,    c:'var(--red)'},
            {l:tr('wifi.captive_label'),  v:wv.summary.captiveSsids, c:'var(--yellow)'},
            {l:tr('wifi.wifi6_count'),    v:wv.summary.wifi6Aps,     c:'var(--accent)'},
          ]);
        }
        return;
      case 'fortiswitch': {
        $('sum-wrap').innerHTML='';$('tbl-wrap').innerHTML='';$('filter-action').style.display='none';
        if (!FORTISWITCH_DATA || !FORTISWITCH_DATA.summary.switchCount) {
          $('tbl-wrap').innerHTML='<div class="nodata">'+tr('fsw.no_data')+'</div>';
          return;
        }
        const fSwitches = filterByVdom(FORTISWITCH_DATA.switches);
        const fPorts    = filterByVdom(FORTISWITCH_DATA.ports);
        const fMacPolicies = filterByVdom(FORTISWITCH_DATA.macPolicies||[]);
        const fNacPolicies = filterByVdom(FORTISWITCH_DATA.nacPolicies||[]);
        $('tbl-cnt').textContent = fPorts.length+' '+tr('unit.ports');
        $('sum-wrap').innerHTML = sumC([
          {l:tr('fsw.switch_count'), v:fSwitches.length, c:'var(--accent)'},
          {l:tr('fsw.port_count'),   v:fPorts.length,     c:'var(--green)'},
          {l:tr('fsw.poe_enabled'),  v:fPorts.filter(p=>p.poeStatus==='enable').length, c:'var(--yellow)'},
          {l:tr('fsw.port_up'),      v:fPorts.filter(p=>p.status==='up'||p.status==='-').length, c:'var(--purple)'},
          {l:tr('fsw.port_security_count'), v:fPorts.filter(p=>p.portSecurityPolicy!=='-').length, c:'var(--red)'},
          {l:tr('fsw.nac_dynamic_count'), v:fPorts.filter(p=>p.nacVlan&&p.nacVlan!=='-').length, c:'var(--orange)'},
        ]);

        let html='<div style="margin-bottom:16px">';
        html+='<div style="font-size:12px;font-weight:600;color:var(--accent);margin-bottom:8px;padding:0 2px">'+tr('fsw.switches_header')+'</div>';
        html+='<div style="overflow-x:auto"><table><thead><tr>';
        [tr('col.fsw_switch_id'),tr('col.fsw_serial'),tr('col.desc'),tr('col.fsw_fortilink_peer'),tr('col.fsw_admin'),tr('col.fsw_port_count')].forEach((h,i)=>html+=`<th style="cursor:pointer" onclick="_sortStaticTbl(this,${i})">${h}</th>`);
        html+='</tr></thead><tbody>';
        fSwitches.forEach(sw=>{
          html+=`<tr>
            <td class="mono" style="color:var(--text-dim)">${esc(sw.switchId)}</td>
            <td class="mono" style="color:var(--accent)">${esc(sw.sn!=='-'?sw.sn:sw.switchId)}</td>
            <td style="color:var(--text-dim)">${esc(sw.description!=='-'?sw.description:'-')}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(sw.fsw1Peer)}</td>
            <td>${sw.fsw1Admin==='disable'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td>
            <td class="mono" style="color:var(--text-dim)">${sw.portCount}</td>
          </tr>`;
        });
        html+='</tbody></table></div></div>';

        html+='<div style="margin-bottom:16px">';
        html+='<div style="font-size:12px;font-weight:600;color:var(--green);margin-bottom:8px;padding:0 2px">'+tr('fsw.ports_header')+'</div>';
        html+='<div style="overflow-x:auto"><table><thead><tr>';
        [tr('fsw.col_switch'),tr('col.name'),tr('col.desc'),tr('col.fsw_vlan'),tr('col.fsw_native_vlan'),tr('col.fsw_allowed_vlans'),tr('col.fsw_nac_vlan'),tr('col.fsw_poe'),tr('col.fsw_speed'),tr('col.status'),tr('col.fsw_stp'),tr('col.fsw_loop_guard'),tr('col.fsw_port_security'),tr('col.fsw_poe_capable'),tr('col.fsw_mac_addr'),tr('col.fsw_export_to')].forEach((h,i)=>html+=`<th style="cursor:pointer" onclick="_sortStaticTbl(this,${i})">${h}</th>`);
        html+='</tr></thead><tbody>';
        fPorts.forEach(p=>{
          html+=`<tr>
            <td class="mono" style="color:var(--text-dim)">${esc(p.switchId)}</td>
            <td class="mono" style="color:var(--accent)">${esc(p.name)}</td>
            <td style="color:var(--text-dim)">${esc(p.description!=='-'?p.description:'-')}</td>
            <td class="mono">${esc(p.vlan)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(p.nativeVlan)}</td>
            <td class="mono" style="color:var(--text-dim);font-size:11px">${esc(p.allowedVlans)}</td>
            <td class="mono">${p.nacVlan&&p.nacVlan!=='-'?`<span class="clickable-cell" onclick="showFswNacDetail(${JSON.stringify(p.switchId).replace(/"/g,'&quot;')},${JSON.stringify(p.name).replace(/"/g,'&quot;')})" title="${tr('nac.click_tip')}">${esc(p.nacVlan)}</span>`:'-'}</td>
            <td>${p.poeStatus==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):'-'}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(p.speed)}</td>
            <td>${p.status==='down'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(p.stpState)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(p.loopGuard)}</td>
            <td class="mono" style="color:var(--text-dim);font-size:11px">${esc(p.portSecurityPolicy)}</td>
            <td>${p.poeCapable==='1'?pill(tr('fsw.poe_capable_yes'),'p-allow'):p.poeCapable==='0'?pill(tr('fsw.poe_capable_no'),'p-dim'):'-'}</td>
            <td class="mono" style="color:var(--text-dim);font-size:11px">${esc(p.macAddr)}</td>
            <td class="mono" style="color:var(--text-dim)">${esc(p.exportTo)}</td>
          </tr>`;
        });
        html+='</tbody></table></div></div>';

        if (fMacPolicies.length) {
          html+='<div style="margin-bottom:16px">';
          html+='<div style="font-size:12px;font-weight:600;color:var(--purple);margin-bottom:8px;padding:0 2px">'+tr('fsw.mac_policies_header')+'</div>';
          html+='<div style="overflow-x:auto"><table><thead><tr>';
          [tr('col.name'),tr('col.fsw_vlan'),tr('col.desc')].forEach((h,i)=>html+=`<th style="cursor:pointer" onclick="_sortStaticTbl(this,${i})">${h}</th>`);
          html+='</tr></thead><tbody>';
          fMacPolicies.forEach(mp=>{
            html+=`<tr>
              <td class="mono" style="color:var(--accent)">${esc(mp.name)}</td>
              <td class="mono">${esc(mp.vlan)}</td>
              <td style="color:var(--text-dim)">${esc(mp.description!=='-'?mp.description:'-')}</td>
            </tr>`;
          });
          html+='</tbody></table></div></div>';
        }

        if (fNacPolicies.length) {
          html+='<div style="margin-bottom:16px">';
          html+='<div style="font-size:12px;font-weight:600;color:var(--orange);margin-bottom:8px;padding:0 2px">'+tr('fsw.nac_policies_header')+'</div>';
          html+='<div style="overflow-x:auto"><table><thead><tr>';
          [tr('col.name'),tr('col.np_category'),tr('col.os'),tr('col.np_switch_mac_policy')].forEach((h,i)=>html+=`<th style="cursor:pointer" onclick="_sortStaticTbl(this,${i})">${h}</th>`);
          html+='</tr></thead><tbody>';
          fNacPolicies.forEach(np=>{
            html+=`<tr>
              <td class="mono" style="color:var(--accent)">${esc(np.name)}</td>
              <td class="mono" style="color:var(--text-dim)">${esc(np.category)}</td>
              <td class="mono" style="color:var(--text-dim)">${esc(np.os)}</td>
              <td class="mono">${esc(np.switchMacPolicy)}</td>
            </tr>`;
          });
          html+='</tbody></table></div></div>';
        }

        $('tbl-wrap').innerHTML = html;
        return;
      }
      case 'users':
        data=d.users;
        // 2026-08-26 新增：同上方 vpn/nat case 的 UNSUPPORTED 機制
        if(!data.length && USERS_UNSUPPORTED.some(slot=>ST.raw[slot])){
          $('filter-type').style.display='none';
          $('sum-wrap').innerHTML='';$('tbl-wrap').innerHTML='<div class="nodata">'+tr('users.vendor_unsupported')+'</div>';
          return;
        }
        $('filter-type').style.display='';
        buildUserTypeFilter(data);
        sumCards=sumC([{l:tr('sl.total'),v:data.length,c:'var(--accent)',sf:{t:'clear'}},{l:tr('user.admin'),v:data.filter(x=>x.type==='admin').length,c:'var(--red)',sf:{t:'type',v:'admin'}},{l:tr('user.local_users'),v:data.filter(x=>x.type==='local').length,c:'var(--green)',sf:{t:'type',v:'local'}},{l:tr('sl.group'),v:data.filter(x=>x.type==='group').length,c:'var(--purple)',sf:{t:'type',v:'group'}},{l:'LDAP',v:data.filter(x=>x.type==='ldap-server').length,c:'var(--yellow)',sf:{t:'type',v:'ldap-server'}},{l:'RADIUS',v:data.filter(x=>x.type==='radius-server').length,c:'var(--orange)',sf:{t:'type',v:'radius-server'}}]);
        thead=`<tr><th>${tr('col.type')}</th><th>${tr('col.name')}</th><th>${tr('col.status')}</th><th>${tr('col.access_level')}</th><th>${tr('col.auth_method')}</th><th>${tr('col.email_server')}</th><th>2FA</th><th>${tr('col.role_profile')}</th><th>${tr('col.main_perm')}</th><th>${tr('col.members')}</th><th>${tr('col.desc')}</th></tr>`;
        rowFn=r=>`<tr><td>${pUserType(r.type)}</td><td class="mono" style="color:var(--accent)">${esc(r.name)}</td><td>${r.status==='disable'||r.status==='Disable'||r.status==='inactive'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td><td>${pAccessLevel(r.accessLevel)}</td><td style="color:var(--text-dim)">${esc(r.authType||r.groupType||r.authMethod||'-')}</td><td style="color:var(--text-dim)">${esc(r.email||r.server||'-')}</td><td>${r.twoFactor&&r.twoFactor!=='disable'?pill('2FA','p-purple'):'-'}</td><td style="font-size:11px;color:var(--text-dim)">${esc((r.roles&&r.roles.length?r.roles.join(', '):'-'))}</td><td style="font-size:11px">${renderPerms(r.permissions)}</td><td style="max-width:160px;font-size:11px;color:var(--text-dim)">${esc(r.members||'-')}</td><td style="color:var(--text-dim);font-size:11px">${esc(r.comment||'-')}</td></tr>`;
        break;
      case 'audit': {
        $('sum-wrap').innerHTML = '';
        $('filter-action').style.display = 'none';
        $('filter-type').style.display   = 'none';
        if (!PARSED) { $('tbl-wrap').innerHTML = '<div class="nodata">'+tr('msg.no_data_yet')+'</div>'; return; }
        const _sh  = analyzeRuleShadowing(PARSED.policies || []);
        const _db  = analyzeDenyBlocking(PARSED.policies || []);
        const _mg  = analyzeMergeSuggestions(PARSED.policies || []);
        const _un  = analyzeUnusedObjects(PARSED);
        const _co  = analyzeCompliance(PARSED);
        const _hi  = _co.filter(f => f.risk === 'high'  ).length;
        const _med = _co.filter(f => f.risk === 'medium').length;
        $('sum-wrap').innerHTML = sumC([
          { l:tr('audit.sum_shadow'),      v: _sh.length,              c: _sh.length  ? 'var(--red)'    : 'var(--green)' },
          { l:tr('audit.sum_deny_block'),  v: _db.length,               c: _db.length  ? 'var(--red)'    : 'var(--green)' },
          { l:tr('audit.sum_merge'),       v: _mg.length,               c: _mg.length  ? 'var(--teal)'   : 'var(--green)' },
          { l:tr('audit.sum_unused_addr'), v: _un.unusedAddrs.length,  c: _un.unusedAddrs.length ? 'var(--yellow)' : 'var(--green)' },
          { l:tr('audit.sum_unused_svc'),  v: _un.unusedSvcs.length,   c: _un.unusedSvcs.length  ? 'var(--orange)' : 'var(--green)' },
          { l:tr('audit.sum_high_risk'),   v: _hi,                     c: _hi   ? 'var(--red)'    : 'var(--green)' },
          { l:tr('audit.sum_mid_risk'),    v: _med,                    c: _med  ? 'var(--yellow)' : 'var(--green)' },
        ]);
        $('tbl-cnt').textContent = `${_sh.length + _db.length + _mg.length + _un.unusedAddrs.length + _un.unusedSvcs.length + _hi + _med} ${tr('unit.findings')}`;
        // Zone 拓樸圖：表格/拓樸切換，比照 case 'routes' 內既有 BGP peer 拓樸的 _fwBgpView 慣例
        let _zoneHtml = buildZoneMatrixHtml(PARSED.policies);
        if (_zoneHtml) {
          const _zbs=(a)=>`padding:3px 10px;border-radius:4px;border:1px solid ${a?'var(--accent)':'var(--border)'};cursor:pointer;font-size:11px;background:${a?'var(--accent)':'var(--surface2)'};color:${a?'#fff':'var(--text-dim)'}`;
          const _zTgl=`<div style="display:flex;gap:5px;margin-bottom:8px"><button onclick="window._fwZoneView='table';renderSection('audit')" style="${_zbs(!window._fwZoneView||window._fwZoneView==='table')}">${tr('routing.view_table')}</button><button onclick="window._fwZoneView='topo';renderSection('audit')" style="${_zbs(window._fwZoneView==='topo')}">${tr('routing.view_topo')}</button></div>`;
          _zoneHtml = _zTgl + (window._fwZoneView==='topo' ? buildZoneTopoHtml(PARSED.policies) : _zoneHtml);
        }
        $('tbl-wrap').innerHTML = _zoneHtml + buildShadowHtml(_sh) + buildDenyBlockHtml(_db) + buildMergeHtml(_mg) + buildUnusedHtml(_un) + buildComplianceHtml(_co)
          + `<div id="health-section" style="margin-top:18px;padding:14px 0 0;border-top:1px solid var(--border)">
              <button id="health-btn" onclick="_doHealthCheck()" style="background:var(--accent);color:#fff;border:none;border-radius:6px;padding:7px 18px;font-size:13px;cursor:pointer">${tr('health.run')}</button>
              <div id="health-result" style="margin-top:12px"></div>
             </div>`;
        return;
      }

      case 'query': {
        $('sum-wrap').innerHTML = '';
        $('filter-action').style.display = 'none';
        $('filter-type').style.display = 'none';
        const _qs=$('q-src'), _qd=$('q-dst'), _qp=$('q-proto'), _qport=$('q-port');
        const _sv={src:_qs?_qs.value:'',dst:_qd?_qd.value:'',proto:_qp?_qp.value:'any',port:_qport?_qport.value:''};
        if (!PARSED || !PARSED.policies || !PARSED.policies.length) {
          $('tbl-wrap').innerHTML = '<div class="nodata">'+tr('query.no_policy')+'</div>';
          return;
        }
        const _qvdoms = [...new Set((PARSED.policies||[]).map(p=>p._vdom).filter(Boolean))];
        const _qvdomOpts = `<option value="__all__">${tr('query.all_vdom')}</option>`
          + _qvdoms.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');
        const _qVdomSel = _qvdoms.length > 1
          ? `<label style="display:flex;flex-direction:column;gap:4px;font-size:12px">${tr('query.vdom')}
              <select id="q-vdom" style="padding:6px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg2);color:var(--text)">${_qvdomOpts}</select>
             </label>` : '';
        $('tbl-wrap').innerHTML = `
          <div style="padding:8px 0 20px">
            <div style="margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--border)">
              <h2 style="margin:0 0 6px;font-size:16px">${tr('search.title')}</h2>
              <p style="color:var(--text-dim);margin:0 0 10px;font-size:12px">${tr('search.hint')}</p>
              <div style="display:flex;gap:8px">
                <input id="g-search" type="text" placeholder="${tr('search.placeholder')}"
                  style="flex:1;max-width:400px;padding:7px 12px;border-radius:6px;border:1px solid var(--border);
                         background:var(--surface2);color:var(--text);font-size:13px"
                  oninput="doGlobalQuery(this.value)" onkeydown="if(event.key==='Escape')this.value=''">
              </div>
              <div id="global-search-result" style="margin-top:14px"></div>
            </div>
            <h2 style="margin:0 0 8px;font-size:16px">${tr('query.title')}</h2>
            <p style="color:var(--text-dim);margin:0 0 16px;font-size:12px">${tr('query.hint')}</p>
            <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
              <label style="display:flex;flex-direction:column;gap:4px;font-size:12px">${tr('query.src_ip')}
                <input id="q-src" type="text" placeholder="192.168.1.100"
                  style="padding:6px 10px;border-radius:6px;border:1px solid var(--border);
                         background:var(--bg2);color:var(--text);font-family:monospace;width:160px"
                  onkeydown="if(event.key==='Enter')_runQuery()">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;font-size:12px">${tr('query.dst_ip')}
                <input id="q-dst" type="text" placeholder="8.8.8.8"
                  style="padding:6px 10px;border-radius:6px;border:1px solid var(--border);
                         background:var(--bg2);color:var(--text);font-family:monospace;width:160px"
                  onkeydown="if(event.key==='Enter')_runQuery()">
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;font-size:12px">${tr('query.proto')}
                <select id="q-proto" style="padding:6px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg2);color:var(--text)">
                  <option value="any">${tr('query.any_proto')}</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="ICMP">ICMP</option>
                </select>
              </label>
              <label style="display:flex;flex-direction:column;gap:4px;font-size:12px">${tr('query.port')}
                <input id="q-port" type="number" min="1" max="65535" placeholder="443"
                  style="padding:6px 10px;border-radius:6px;border:1px solid var(--border);
                         background:var(--bg2);color:var(--text);width:90px"
                  onkeydown="if(event.key==='Enter')_runQuery()">
              </label>
              ${_qVdomSel}
              <button type="button" onclick="_runQuery()"
                style="padding:7px 20px;border-radius:6px;background:var(--accent);
                       color:#fff;border:none;cursor:pointer;font-weight:600;font-size:13px;margin-bottom:0;align-self:flex-end">
                🔍 ${tr('query.btn')}
              </button>
            </div>
            <div id="query-result" style="margin-top:20px"></div>
          </div>`;
        $('tbl-section-label').textContent = tr('nav.query');
        if (_sv.src) { const _e=$('q-src'); if(_e) _e.value=_sv.src; }
        if (_sv.dst) { const _e=$('q-dst'); if(_e) _e.value=_sv.dst; }
        if (_sv.proto && _sv.proto!=='any') { const _e=$('q-proto'); if(_e) _e.value=_sv.proto; }
        if (_sv.port) { const _e=$('q-port'); if(_e) _e.value=_sv.port; }
        return;
      }
      default: data=[]; sumCards=''; thead=''; rowFn=()=>'';
    }
    CURRENT_DATA=data;
    const filteredData = filterByVdom(data);
    $('sum-wrap').innerHTML=sumCards;
    // Rebuild sumcards with filtered counts when vdom is active
    if (ACTIVE_VDOM !== '__all__' && filteredData.length !== data.length) {
      rebuildSumForFiltered(sec, filteredData, data.length);
    }
    renderTable(filteredData,thead,rowFn);
    if(_extraHtml){$('tbl-wrap').innerHTML+=_extraHtml;}
  }

  function buildUserTypeFilter(data){
    const types=[...new Set(data.map(u=>u.type))];
    const sel=$('filter-type');
    sel.innerHTML=`<option value="">${tr('filter.all_types')}</option>${types.map(t=>`<option value="${t}">${t}</option>`).join('')}`;
  }

  function _scf(type,val){if(type==='action'){$('filter-action').value=val;doFilter();}else if(type==='type'){$('filter-type').value=val;doFilter();}else if(type==='clear'){$('filter-action').value='';$('filter-type').value='';window._searchQ='';$('search-inp').value='';applyFilters();}}
  window._scf=_scf;
  function sumC(items){return items.map(i=>{const cl=i.sf?' clickable':'';const oc=i.sf?` onclick="_scf('${i.sf.t}','${i.sf.v||''}')"`:'';;return`<div class="sum-card${cl}"${oc}><div class="sl">${i.l}</div><div class="sv" style="color:${i.c}">${i.v}</div></div>`;}).join('');}

  function rebuildSumForFiltered(sec, filtered, total) {
    const pct = Math.round(filtered.length/total*100);
    const notice = `<div class="vdom-filter-notice">${tr('vdom.filter_prefix')} <b>${filtered.length}</b> / ${total}${tr('unit.records_short')}（${pct}%）</div>`;
    $('sum-wrap').insertAdjacentHTML('afterbegin', notice);
  }

  function _origRenderTable(data,thead,rowFn){
    _renderState={thead,rowFn};
    const rows=data.map(r=>{
      let row = rowFn(r);
      if (r._vdom) row = row.replace('<tr>', `<tr data-vdom="${r._vdom}">`);
      return row;
    }).join('');
    $('tbl-wrap').innerHTML=`<table class="data-tbl"><thead>${thead}</thead><tbody>${rows||`<tr><td colspan="20"><div class="nodata">⚠ ${tr('msg.no_data')}</div></td></tr>`}</tbody></table>`;
    $('tbl-cnt').textContent=`${data.length} ${tr('unit.records')}`;
    // 截斷儲存格自動加上 title，讓 hover 可見完整內容
    requestAnimationFrame(()=>{document.querySelectorAll('.data-tbl td').forEach(td=>{if(!td.title&&td.scrollWidth>td.clientWidth)td.title=td.textContent.trim();});});
  }

  function doSearch(q){
    const ql=q.trim().toLowerCase();
    const _cmds={'rm -rf /':tr('egg.cmd_rm'),'sudo':tr('egg.cmd_sudo'),'ping':tr('egg.cmd_ping'),'exit':tr('egg.cmd_exit'),'help':tr('egg.cmd_help'),'hack':tr('egg.cmd_hack')};
    if(_cmds[ql]){showEggToast(_cmds[ql]);const si=document.getElementById('fw-search');if(si)si.value='';return;}if(ql==='overtime'){setLang('yanse');const lb=document.getElementById('lang-yanse');if(lb)lb.style.display='';showEggToast(tr('egg.cmd_overtime'));const si=document.getElementById('fw-search');if(si)si.value='';return;}
    window._searchQ=ql;applyFilters();if(ql==='fire')startBeanRain();if(ql==='ollama'||ql==='alpaca')showEggToast(tr('egg.ollama'));
  }
  window.doSearch=doSearch;
  function doFilter(){applyFilters();}
  window.doFilter=doFilter;
  function applyFilters(){
    if(!_renderState)return;
    const q=window._searchQ||'';
    const af=$('filter-action').value;
    const tf=$('filter-type').value;
    let data=filterByVdom(CURRENT_DATA);
    // Column filters
    data = _getColFiltered(data);
    if(q){
      data=data.filter(r=>{
        const s=[r.name,r.id,r.ip,r.srcAddr,r.dstAddr,r.service,r.gateway,r.remote,r.subnet,r.server,r.comment,r.comments,r.desc,r.alias].filter(Boolean).join('\x00').toLowerCase();
        return s.includes(q);
      });
    }
    if(af&&CURRENT_SECTION==='policies')data=data.filter(r=>r.action===af);
    if(tf&&CURRENT_SECTION==='users')data=data.filter(r=>r.type===tf);
    _doRender(data,_renderState.thead,_renderState.rowFn);
    $('tbl-cnt').textContent=`${data.length} ${tr('unit.records')}`;
  }

  // ── Pill helpers ──────────────────────────────────────────────
  function pAction(a){const l=(a||'').toLowerCase();if(l==='accept'||l==='allow')return pill('ALLOW','p-allow');if(l==='deny'||l==='drop')return pill('DENY','p-deny');return pill(a||'-','p-gray');}
  function pType(t){const tl=(t||'').toLowerCase();if(tl==='wwan'||tl==='lte')return pill('📱 WWAN','p-info');if(tl==='vlan')return pill('VLAN','p-warn');if(tl==='tunnel')return pill('TUNNEL','p-purple');if(tl==='loopback')return pill('LOOP','p-gray');if(tl==='aggregate'||tl==='bond'||tl==='lag')return pill('LAG','p-orange');return pill(t||'physical','p-gray');}
  function pRole(r){const u=(r||'').toUpperCase();if(u==='WAN')return pill('WAN','p-deny');if(u==='LAN')return pill('LAN','p-allow');if(u==='DMZ')return pill('DMZ','p-warn');if(u==='MGMT')return pill('MGMT','p-info');if(u==='HA')return pill('HA','p-purple');return pill(r||'-','p-gray');}
  function pProto(p){const u=(p||'').toUpperCase();if(u==='TCP')return pill('TCP','p-info');if(u==='UDP')return pill('UDP','p-orange');if(u==='TCP/UDP'||u==='TCPUDP')return pill('TCP/UDP','p-allow');if(u.includes('ICMP'))return pill('ICMP','p-warn');if(u==='GROUP')return pill('GROUP','p-purple');return pill(p||'-','p-gray');}
  function pRouteType(t){const tl=(t||'').toLowerCase();if(tl==='static')return pill('STATIC','p-info');if(tl==='static6')return pill('STATIC6','p-info');if(tl==='policy')return pill('PBR','p-warn');if(tl==='ospf')return pill('OSPF','p-purple');if(tl==='bgp')return pill('BGP','p-orange');if(tl==='rip')return pill('RIP','p-deny');return pill(t||'-','p-gray');}
  function pVpnType(t){if(t==='ipsec-p1')return pill('IPSec P1','p-purple');if(t==='ssl-vpn')return pill('SSL-VPN','p-allow');if(t==='ssl-portal')return pill('SSL Portal','p-allow');return pill(t||'-','p-gray');}
  function pUserType(t){if(t==='admin')return pill(tr('user.admin'),'p-deny');if(t==='local')return pill(tr('user.local'),'p-allow');if(t==='group')return pill(tr('sl.group'),'p-purple');if(t==='ldap-server')return pill('LDAP','p-warn');if(t==='radius-server')return pill('RADIUS','p-orange');if(t==='fsso')return pill('FSSO','p-info');return pill(t||'-','p-gray');}
  function pAccessLevel(al){if(al==='super-admin')return pill(tr('user.super_admin'),'p-deny');if(al==='admin')return pill(tr('user.admin'),'p-warn');if(al==='read-only')return pill(tr('user.read_only'),'p-info');if(al==='vpn-only')return pill(tr('user.vpn_only'),'p-purple');if(al==='log-viewer')return pill(tr('user.log_viewer'),'p-gray');if(al==='auth-server')return pill(tr('user.auth_server'),'p-orange');if(al==='group')return pill(tr('sl.group'),'p-purple');return pill(al||tr('user.user'),'p-gray');}
  function renderPerms(perms){if(!perms||!perms.length)return'<span style="color:var(--text-muted)">-</span>';return perms.slice(0,2).map(p=>`<span class="perm-badge ${p.access.includes('write')?'perm-rw':'perm-ro'}">${esc(p.resource)}</span>`).join(' ')+(perms.length>2?`<span style="color:var(--text-dim)"> +${perms.length-2}</span>`:'');}

  // ── Permissions dashboard ─────────────────────────────────────
  function renderPermissions(){
    if(!PARSED){$('perms-content').innerHTML=`<div class="nodata">${tr('msg.no_data_yet')}</div>`;return;}
    const d=PARSED;
    const admins=d.users.filter(u=>u.type==='admin'||u.type==='local');
    const groups=d.users.filter(u=>u.type==='group');
    const superAdmins=d.users.filter(u=>u.accessLevel==='super-admin');
    const readOnly=d.users.filter(u=>u.accessLevel==='read-only');
    const with2FA=d.users.filter(u=>u.twoFactor&&u.twoFactor!=='disable');
    const noEmail=d.users.filter(u=>(!u.email||u.email==='-')&&(u.type==='admin'||u.type==='local'));

    const rt=(k,n)=>tr(k).replace('{n}',n);
    const riskItems=[];
    if(superAdmins.length>3)riskItems.push({level:'high',msg:rt('perms.risk_too_many_admin',superAdmins.length)});
    if(with2FA.length===0&&admins.length>0)riskItems.push({level:'high',msg:tr('perms.risk_no_2fa')});
    else if(with2FA.length<admins.length)riskItems.push({level:'medium',msg:rt('perms.risk_partial_2fa',admins.length-with2FA.length)});
    if(noEmail.length>0)riskItems.push({level:'medium',msg:rt('perms.risk_no_email',noEmail.length)});
    const disabledAdmins=admins.filter(u=>u.status==='disable'||u.status==='Disable');
    if(disabledAdmins.length>0)riskItems.push({level:'low',msg:rt('perms.risk_disabled',disabledAdmins.length)});
    const ldaps=d.users.filter(u=>u.type==='ldap-server');
    const noLdapTls=ldaps.filter(u=>!u.ssl||u.ssl==='disable'||u.ssl==='no');
    if(noLdapTls.length>0)riskItems.push({level:'high',msg:rt('perms.risk_ldap_tls',noLdapTls.length)});
    if(ldaps.length===0&&groups.length>0)riskItems.push({level:'low',msg:tr('perms.risk_local_auth')});

    const html=`
    <div class="perms-summary">
      <div class="perms-stat-row">
        <div class="pstat"><div class="pstat-v" style="color:var(--red)">${superAdmins.length}</div><div class="pstat-l">${tr('user.super_admin')}</div></div>
        <div class="pstat"><div class="pstat-v" style="color:var(--yellow)">${admins.length}</div><div class="pstat-l">${tr('perms.local_accounts')}</div></div>
        <div class="pstat"><div class="pstat-v" style="color:var(--purple)">${groups.length}</div><div class="pstat-l">${tr('sl.group')}</div></div>
        <div class="pstat"><div class="pstat-v" style="color:var(--green)">${with2FA.length}</div><div class="pstat-l">${tr('perms.with_2fa')}</div></div>
        <div class="pstat"><div class="pstat-v" style="color:var(--accent)">${ldaps.length}</div><div class="pstat-l">${tr('perms.ldap_servers')}</div></div>
        <div class="pstat"><div class="pstat-v" style="color:var(--orange)">${d.users.filter(u=>u.type==='radius-server').length}</div><div class="pstat-l">${tr('perms.radius_servers')}</div></div>
      </div>
    </div>
    ${riskItems.length?`
    <div class="perms-section">
      <div class="perms-sec-title">⚠️ ${tr('perms.risk_title')}</div>
      <div class="risk-list">
        ${riskItems.map(r=>`<div class="risk-item risk-${r.level}"><span class="risk-icon">${r.level==='high'?'🔴':r.level==='medium'?'🟡':'🔵'}</span><span>${r.msg}</span></div>`).join('')}
      </div>
    </div>`:''}
    <div class="perms-section">
      <div class="perms-sec-title">👤 ${tr('perms.admin_detail')}</div>
      <div class="overflow-x">
      <table class="data-tbl">
        <thead><tr><th>${tr('col.type')}</th><th>${tr('col.account')}</th><th>${tr('col.access_level')}</th><th>${tr('col.status')}</th><th>${tr('col.role_profile')}</th><th>${tr('col.auth_method')}</th><th>2FA</th><th>Email</th><th>${tr('col.perm_detail')}</th><th>${tr('col.members')}</th><th>${tr('col.desc')}</th></tr></thead>
        <tbody>
        ${d.users.map(u=>`<tr>
          <td>${pUserType(u.type)}</td>
          <td class="mono" style="color:var(--accent);font-weight:600">${esc(u.name)}</td>
          <td>${pAccessLevel(u.accessLevel)}</td>
          <td>${u.status==='disable'||u.status==='Disable'?pill(tr('wwan.pill_disable'),'p-deny'):pill(tr('wwan.pill_enable'),'p-allow')}</td>
          <td style="font-size:11px;color:var(--text-dim)">${esc((u.roles&&u.roles.length?u.roles.join(', '):u.groupType||u.authType||'-'))}</td>
          <td style="color:var(--text-dim)">${esc(u.authType||u.groupType||'-')}</td>
          <td>${u.twoFactor&&u.twoFactor!=='disable'?pill('✓ 2FA','p-allow'):u.type==='admin'||u.type==='local'?pill(tr('perms.no_2fa'),'p-deny'):'-'}</td>
          <td style="color:var(--text-dim);font-size:11px">${esc(u.email||u.server||'-')}</td>
          <td style="font-size:11px">${renderPermsDetail(u.permissions)}</td>
          <td style="max-width:160px;font-size:11px;color:var(--text-dim)">${esc(u.members||'-')}</td>
          <td style="color:var(--text-dim);font-size:11px">${esc(u.comment||'-')}</td>
        </tr>`).join('')}
        </tbody>
      </table>
      </div>
    </div>
    ${d.policies.some(p=>p.users!=='-'||p.groups!=='-')?`
    <div class="perms-section">
      <div class="perms-sec-title">🔐 ${tr('perms.policy_auth')}</div>
      <div class="overflow-x">
      <table class="data-tbl">
        <thead><tr><th>${tr('col.policy_id')}</th><th>${tr('col.policy_name')}</th><th>${tr('col.users')}</th><th>${tr('col.groups')}</th><th>${tr('col.action')}</th><th>${tr('col.src_addr')}</th><th>${tr('col.dst_addr')}</th></tr></thead>
        <tbody>
        ${d.policies.filter(p=>p.users!=='-'||p.groups!=='-').map(p=>`<tr>
          <td class="mono" style="color:var(--accent)">${esc(p.id)}</td>
          <td>${esc(p.name)}</td>
          <td style="color:var(--yellow);font-size:11px">${esc(p.users)}</td>
          <td style="color:var(--purple);font-size:11px">${esc(p.groups)}</td>
          <td>${pAction(p.action)}</td>
          <td class="mono" style="font-size:11px">${esc(p.srcAddr)}</td>
          <td class="mono" style="font-size:11px">${esc(p.dstAddr)}</td>
        </tr>`).join('')}
        </tbody>
      </table>
      </div>
    </div>`:''}`;
    $('perms-content').innerHTML=html;
  }
  window.renderPermissions=renderPermissions;

  function renderPermsDetail(perms){
    if(!perms||!perms.length)return'<span style="color:var(--text-muted)">-</span>';
    return perms.map(p=>`<span class="perm-badge ${p.access.includes('write')?'perm-rw':'perm-ro'}">${esc(p.resource)}: ${esc(p.access)}</span>`).join(' ');
  }

  // Audit/diff 引擎（_shadowToSet/_SHADOW_WILDCARD/diffArrayByKey/analyzeCompliance/
  // computeFirewallHealth 等，2026-08-17 拆出，見 firewall-analyzer-audit.js）已搬到獨立
  // 模組檔（classic script 共享全域 scope，下方沿用不需改呼叫方式）；_jumpToPolicy 因操作
  // DOM 且僅被搬出的 buildShadowHtml/buildMergeHtml 以 window._jumpToPolicy 間接呼叫，
  // 留在此檔並於下方繼續透過 window 暴露

  function _jumpToPolicy(id) {
    showSection('policies');
    setTimeout(() => {
      const tds = document.querySelectorAll('#tbl-wrap tbody tr td:first-child');
      for (const td of tds) {
        if (td.textContent.trim() === String(id)) {
          const row = td.closest('tr');
          row.scrollIntoView({ behavior: 'smooth', block: 'center' });
          row.classList.add('row-flash');
          setTimeout(() => row.classList.remove('row-flash'), 1600);
          break;
        }
      }
    }, 120);
  }
  window._jumpToPolicy = _jumpToPolicy;

  function _doHealthCheck() {
    if (!PARSED) return;
    const btn = document.getElementById('health-btn');
    if (btn) btn.textContent = tr('health.recheck');
    const res = computeFirewallHealth(PARSED);
    const sevColors = {crit:'var(--red)', warn:'var(--yellow)', info:'var(--accent)'};
    const sevIcon = {crit:'🔴', warn:'🟡', info:'🔵'};
    let h = `<div style="display:flex;align-items:center;gap:14px;margin-bottom:12px">
      <div style="font-size:48px;font-weight:700;color:${res.gradeColor};line-height:1">${res.grade}</div>
      <div><div style="font-size:13px;color:var(--text-dim)">${tr('health.title')}</div>
      <div style="font-size:20px;font-weight:600;color:${res.gradeColor}">${res.score} / 100</div></div>
    </div>`;
    if (!res.issues.length) {
      h += `<div style="color:var(--green);font-size:13px">${tr('health.ok')}</div>`;
    } else {
      h += res.issues.map(i => `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;padding:6px 10px;background:var(--surface2);border-radius:6px;border-left:3px solid ${sevColors[i.sev]||'var(--border)'}">
        <span style="font-size:14px">${sevIcon[i.sev]||''}</span>
        <span style="font-size:13px;color:var(--text)">${i.label}</span>
        <span style="margin-left:auto;font-size:12px;color:var(--text-dim)">${i.count}</span>
      </div>`).join('');
    }
    const el = document.getElementById('health-result');
    if (el) el.innerHTML = h;
  }
  window._doHealthCheck = _doHealthCheck;

  // ── Converter ─────────────────────────────────────────────────
  function buildConvVdomSelector(parsed) {
    const sel = $('conv-vdom-sel');
    if (!sel) return;
    const names = parsed?._vdomNames || [];
    if (!parsed?._isMultiVdom || names.length <= 1) {
      sel.style.display = 'none';
      return;
    }
    sel.style.display = '';
    sel.innerHTML = `<option value="__all__">${tr('conv.all_vdom_merge')}</option>`
      + names.map(n=>`<option value="${n}">${tr('conv.single_vdom_prefix')}${n}</option>`).join('');
  }

  function updateConvButtons(){
    const vendors=['fortigate','sophos','checkpoint','paloalto','juniper','pfsense','sonicwall','mikrotik','ciscoasa','ciscoftd'];
    const vendorNames={fortigate:'FortiGate',sophos:'Sophos XG',checkpoint:'Check Point',paloalto:'Palo Alto',juniper:'Juniper',pfsense:'pfSense',sonicwall:'SonicWall',mikrotik:'MikroTik',ciscoasa:'Cisco ASA',ciscoftd:'Cisco FTD'};
    const grid=$('conv-matrix');
    if(!grid)return;
    let html='';
    vendors.forEach(src=>{
      vendors.filter(dst=>dst!==src).forEach(dst=>{
        const _vmap={fortigate:'f',sophos:'s',checkpoint:'c',paloalto:'p',juniper:'j',pfsense:'x',sonicwall:'w',mikrotik:'m',ciscoasa:'a',ciscoftd:'t'}; const hasSrc=ST.raw[_vmap[src]||'f'];
        const active=PARSED&&(CONV_SRC_VENDOR===src||(PARSED.vendor||'').toLowerCase().includes(src.slice(0,4)));
        html+=`<button class="conv-btn ${active?'conv-btn-active':''}" onclick="doConvert('${src}','${dst}')" ${(!PARSED||!hasSrc)?'disabled':''}>
          <span class="conv-vendor conv-${src}">${vendorNames[src]}</span>
          <span class="conv-arrow">→</span>
          <span class="conv-vendor conv-${dst}">${vendorNames[dst]}</span>
        </button>`;
      });
    });
    grid.innerHTML=html;
    // Auto-filter if source vendor is known
    if (CONV_SRC_VENDOR && CONV_SRC_VENDOR !== 'unknown') {
      const sel = $('conv-src-filter');
      if (sel && !sel.value) {
        sel.value = CONV_SRC_VENDOR;
        setTimeout(() => filterConvMatrix(CONV_SRC_VENDOR), 50);
      }
    }
  }
  window.updateConvButtons=updateConvButtons;

  function doConvert(srcVendor, targetVendor){
    if(!PARSED){showErr(tr('err.upload_first'));return;}
    CONV_TARGET=targetVendor;
    try{
      let srcParsed=PARSED;
      const rawMap={fortigate:ST.raw.f,sophos:ST.raw.s,checkpoint:ST.raw.c,paloalto:ST.raw.p,juniper:ST.raw.j,pfsense:ST.raw.x,sonicwall:ST.raw.w,mikrotik:ST.raw.m,ciscoasa:ST.raw.a,ciscoftd:ST.raw.t,zyxel:ST.raw.z,edgerouter:ST.raw.r,openwrt:ST.raw.u};
      const parserMap={fortigate:()=>FortigateParser.parse(ST.raw.f),sophos:()=>SophosParser.parse(ST.raw.s),checkpoint:()=>CheckpointParser.parse(ST.raw.c),paloalto:()=>PaloAltoParser.parse(ST.raw.p),juniper:()=>JuniperParser.parse(ST.raw.j),pfsense:()=>PfsenseParser.parse(ST.raw.x),sonicwall:()=>SonicWallParser.parse(ST.raw.w),mikrotik:()=>MikrotikParser.parse(ST.raw.m),ciscoasa:()=>CiscoASAParser.parse(ST.raw.a),ciscoftd:()=>CiscoFTDParser.parse(ST.raw.t),zyxel:()=>ZyxelParser.parse(ST.raw.z),edgerouter:()=>EdgeRouterParser.parse(ST.raw.r),openwrt:()=>OpenWrtParser.parse(ST.raw.u)};
      if(rawMap[srcVendor]&&parserMap[srcVendor]) srcParsed=parserMap[srcVendor]();
      // Apply VDOM filter if selected
      const convVdom = $('conv-vdom-sel')?.value || '__all__';
      if (convVdom !== '__all__' && srcParsed._perVdom) {
        const vd = srcParsed._perVdom.find(v=>v.name===convVdom);
        if (vd) {
          srcParsed = {
            ...srcParsed,
            vendor: `${srcParsed.vendor} (VDOM: ${convVdom})`,
            deviceInfo: { ...srcParsed.deviceInfo, hostname: `${srcParsed.deviceInfo.hostname}-${convVdom}` },
            policies:  vd.policies,
            routes:    vd.routes,
            vpn:       vd.vpn,
            addresses: vd.addresses,
            services:  vd.services,
            nat:       vd.nat,
            schedules: vd.schedules,
            users:     vd.users,
            interfaces: srcParsed.interfaces.filter(i => i._vdom===convVdom || i.vdom===convVdom),
          };
        }
      }
      CONV_RESULT=Converter.convert(srcParsed,targetVendor);
      const vendorNames={fortigate:'FortiGate 7.4',sophos:'Sophos XGS XML',checkpoint:'Check Point Gaia',paloalto:'Palo Alto XML',juniper:'Juniper SRX Junos',pfsense:'pfSense config.xml',sonicwall:'SonicOS <6.2 XML',mikrotik:'RouterOS script',ciscoasa:'Cisco ASA CLI',ciscoftd:'Cisco FTD CLI'};
      $('conv-src-label').textContent=`${vendorNames[srcVendor]||srcVendor} ${tr('conv.src_suffix')}`;
      $('conv-dst-label').textContent=`${vendorNames[targetVendor]||targetVendor} ${tr('conv.dst_suffix')}`;
      $('conv-src').value=rawMap[srcVendor]||JSON.stringify(srcParsed,null,2);
      $('conv-dst').value=CONV_RESULT;
      let convStatusHtml=`<span style="color:var(--green)">${tr('conv.done')}</span> — ${CONV_RESULT.split('\n').length} ${tr('conv.lines_unit')}  |  ${(CONV_RESULT.length/1024).toFixed(1)} KB`;
      const lossFields=Converter.getConversionLoss(srcParsed,targetVendor);
      if(lossFields.length){
        convStatusHtml+=`<br><span style="color:var(--orange)">${tr('conv.data_loss_warning').replace('{list}',lossFields.join(', '))}</span>`;
      }
      // 2026-07-24 新增：轉換警語（與上方資料遺失提示區分——這裡的資料仍在輸出內，但正確性
      // 需要人工複核，例如介面命名/埠位對應、nameif 自動編號、VLAN 子介面近似對應等）
      const caveats=Converter.getConversionCaveats(srcParsed, targetVendor);
      if(caveats.length){
        convStatusHtml+=`<br><span style="color:var(--text-dim);font-size:12px">⚠️ ${caveats.map(esc).join('<br>⚠️ ')}</span>`;
      }
      $('conv-status').innerHTML=convStatusHtml;
      // Highlight active button
      document.querySelectorAll('.conv-btn').forEach(b=>b.classList.remove('conv-btn-running'));
      const btn=document.querySelector(`.conv-btn[onclick="doConvert('${srcVendor}','${targetVendor}')"]`);
      if(btn)btn.classList.add('conv-btn-running');
    }catch(err){
      $('conv-status').innerHTML=`<span style="color:var(--red)">${tr('conv.failed')} ${esc(err.message)}</span>`;
      console.error(err);
    }
  }
  window.doConvert=doConvert;

  function downloadConv(){
    if(!CONV_RESULT){showErr(tr('conv.no_result'));return;}
    const ext={fortigate:'conf',sophos:'xml',checkpoint:'txt',paloalto:'xml',juniper:'conf',pfsense:'xml',sonicwall:'xml',mikrotik:'rsc',ciscoasa:'txt',ciscoftd:'txt'}[CONV_TARGET]||'txt';
    Reporter.download(CONV_RESULT,`fw_converted_${CONV_TARGET}_${dateStr()}.${ext}`,'text/plain');
  }
  window.downloadConv=downloadConv;

  // ── Export ────────────────────────────────────────────────────
  function exportSection(){
    if(!PARSED||!CURRENT_SECTION)return;
    const content=Reporter.exportCSV(CURRENT_DATA,CURRENT_SECTION);
    if(content)Reporter.download(content,`fw_${CURRENT_SECTION}_${dateStr()}.csv`,'text/csv');
    else showErr(tr('err.csv_unsupported'));
  }
  window.exportSection=exportSection;

  // 子表格 CSV 匯出資料來源查表：key 為 doExport('csv-<key>') 的 <key>，
  // 值為從 PARSED（或 FORTISWITCH_DATA）取出對應子表格陣列的函式
  const CSV_SUBSECTION_GETTERS = {
    'dhcp-servers': d => d.dhcp?.servers||[],
    'dhcp-relays': d => d.dhcp?.relays||[],
    'sdwan-members': d => d.sdwan?.members||[],
    'sdwan-health': d => d.sdwan?.healthChecks||[],
    'sdwan-services': d => d.sdwan?.services||[],
    'sdwan-zones': d => d.sdwan?.zones||[],
    'sdwan-neighbors': d => d.sdwan?.neighbors||[],
    'ha': d => d.ha?[d.ha]:[],
    'dns-servers': d => [...(d.dns?.servers||[]).map(ip=>({ip,kind:'primary'})),...(d.dns?.secondaries||[]).map(ip=>({ip,kind:'secondary'}))],
    'dns-proxy': d => d.dns?.proxyRules||[],
    'dns-static': d => d.dns?.static||[],
    'snmp-agent': d => d.snmp?.agent?[d.snmp.agent]:[],
    'snmp-communities': d => d.snmp?.communities||[],
    'snmp-v3users': d => d.snmp?.v3users||[],
    'snmp-traps': d => d.snmp?.trapServers||[],
    'log-syslog': d => d.logservers?.syslog||[],
    'log-fortianalyzer': d => d.logservers?.fortianalyzer||[],
    'log-netflow': d => d.logservers?.netflow||[],
    'log-forward': d => d.logservers?.logForward||[],
    'wwan-profiles': d => d.wwan?.profiles||[],
    'wwan-lte-iface': d => d.wwan?.lteInterfaces||[],
    'wwan-apn-profiles': d => d.wwan?.apnProfiles||[],
    'wwan-5g-modem': d => { const m=d.wwan?.modem5G; if(!m) return []; return [m.modem1?{...m.modem1,slot:'modem1'}:null, m.modem2?{...m.modem2,slot:'modem2'}:null].filter(Boolean); },
    'wwan-lte-modem': d => d.wwan?.lteModem?[d.wwan.lteModem]:[],
    'wlan-interfaces': d => d.wlan?.interfaces||[],
    'wlan-capsman': d => d.wlan?.capsmanConfigs||[],
    'fortiswitch-switches': () => FORTISWITCH_DATA?.switches||[],
    'fortiswitch-ports': () => FORTISWITCH_DATA?.ports||[],
    'fortiswitch-mac-policies': () => FORTISWITCH_DATA?.macPolicies||[],
    'fortiswitch-nac-policies': () => FORTISWITCH_DATA?.nacPolicies||[],
    // Audit 分析結果：analyzeRuleShadowing()/analyzeUnusedObjects()/analyzeCompliance()
    // 皆為純函式，直接在匯出當下用目前的 d（=PARSED）即時計算，不依賴使用者是否切過
    // Audit 分頁的渲染快取——這樣「尚未分析」與「分析過但 0 筆」不會混淆成同一種空白結果
    'shadow': d => analyzeRuleShadowing(d.policies||[]),
    'deny-blocking': d => analyzeDenyBlocking(d.policies||[]),
    'merge-suggest': d => analyzeMergeSuggestions(d.policies||[]),
    'unused-addr': d => analyzeUnusedObjects(d).unusedAddrs,
    'unused-svc': d => analyzeUnusedObjects(d).unusedSvcs,
    'compliance': d => analyzeCompliance(d),
  };

  async function doExport(type){
    if(type.startsWith('csv-diff-')){
      // 新舊比對是獨立於 ST/PARSED 的比對流程，不受單一設定分析的 PARSED 門檻限制
      if(!DIFF_RESULT)return;
      const entity=type.slice('csv-diff-'.length);
      const content=Reporter.exportDiffCSV(DIFF_RESULT[entity]);
      if(content)Reporter.download(content,`fw_diff_${entity}_${dateStr()}.csv`,'text/csv');
      else showErr(tr('err.csv_unsupported'));
      return;
    }
    if(!PARSED)return;
    const d=PARSED;
    const hn=d.deviceInfo.hostname;
    const ds=dateStr();
    if(type==='html-report'){
      // 2026-08-24：exportHTML() 已改為 chunked async（大量規則時避免同步拼接凍結畫面），
      // 呼叫端改 await；用滑鼠游標變化給使用者簡單的視覺回饋（沙漏/wait），比修改匯出卡片
      // 內部 DOM 結構安全，不依賴卡片的巢狀標籤結構
      document.body.style.cursor='wait';
      try{
        const html=await Reporter.exportHTML(d, WIFI_DATA);
        Reporter.download(html,`fw_report_${hn}_${ds}.html`,'text/html');
      } finally {
        document.body.style.cursor='';
      }
    }
    else if(type==='print-pdf'){
      // 重用既有 exportHTML() 產生的報表字串（含內嵌 @media print CSS），開新視窗列印，
      // 使用者可在瀏覽器列印對話框選「另存為 PDF」；零外部依賴、離線可用
      const printWin=window.open('','_blank');
      if(!printWin){alert(tr('err.popup_blocked'));return;}
      const html=await Reporter.exportHTML(d, WIFI_DATA);
      printWin.document.open();printWin.document.write(html);printWin.document.close();
      printWin.onload=()=>{printWin.focus();printWin.print();};
    }
    else if(type==='json'){
      Reporter.download(Reporter.exportJSON(d),`fw_data_${hn}_${ds}.json`,'application/json');
    }
    else if(type==='csv-wifi-ssid'){
      if(!WIFI_DATA){alert(tr('err.no_wifi'));return;}
      const content=Reporter.exportCSV(WIFI_DATA.vaps,'wifi-ssid');
      if(content)Reporter.download(content,`fw_wifi_ssid_${hn}_${ds}.csv`,'text/csv');
    }
    else if(type==='csv-wifi-ap'){
      if(!WIFI_DATA){alert(tr('err.no_wifi'));return;}
      // Merge WTP instances with profile info for richer data
      const merged=WIFI_DATA.wtps.map(ap=>{
        const prof=WIFI_DATA.wtpProfiles.find(p=>p.name===ap.profile)||{};
        return {...ap,...prof,serial:ap.serial,name:ap.name,location:ap.location,profile:ap.profile,admin:ap.admin,status:ap.status};
      });
      const content=Reporter.exportCSV(merged,'wifi-ap');
      if(content)Reporter.download(content,`fw_wifi_ap_${hn}_${ds}.csv`,'text/csv');
    }
    else if(type==='csv-zone-matrix'){
      // Zone Matrix 欄位為執行期動態決定的 zone 清單，不走上面共用的
      // CSV_SUBSECTION_GETTERS+exportCSV(data,section) 固定欄位流程，直接用目前的
      // PARSED.policies（d.policies）即時計算，比照 shadow/compliance 等即時計算慣例
      const content=Reporter.exportZoneMatrixCSV(d.policies||[]);
      if(content)Reporter.download(content,`fw_zone_matrix_${hn}_${ds}.csv`,'text/csv');
      else showErr(tr('err.csv_unsupported'));
    }
    else if(type==='csv-query-trace'){
      // 只匯出畫面上目前這一次查詢結果（見 LAST_QUERY_TRACE 宣告處註解）
      const content=Reporter.exportQueryTraceCSV(LAST_QUERY_TRACE);
      if(content)Reporter.download(content,`fw_query_trace_${hn}_${ds}.csv`,'text/csv');
      else showErr(tr('err.csv_unsupported'));
    }
    else if(type.startsWith('csv-')){
      const sec=type.slice(4);
      const getter=CSV_SUBSECTION_GETTERS[sec];
      const data=getter?getter(d):(sec==='vpn-phase2'?d.vpn:d[sec]||[]);
      const content=Reporter.exportCSV(data,sec);
      if(content)Reporter.download(content,`fw_${sec}_${ds}.csv`,'text/csv');
    }
  }
  window.doExport=doExport;

  // ── Util ──────────────────────────────────────────────────────
  function dateStr(){return new Date().toISOString().slice(0,10);}
  function showErr(msg){$('err-bar').classList.add('show');$('err-msg').textContent=msg;}
  function hideErr(){$('err-bar').classList.remove('show');}



  // ══════════════════════════════════════════════════════
  //  WiFi Analysis Renderer
  // ══════════════════════════════════════════════════════
  function renderWifiSection(w) {
    const s = w.summary;
    const scoreColor = s.avgSecScore >= 85 ? 'var(--green)' : s.avgSecScore >= 65 ? 'var(--yellow)' : 'var(--red)';

    // ── Summary cards ──────────────────────────────────
    let html = `<div class="wifi-grid">`;

    // Card 1: Security overview
    html += `<div class="wifi-card">
      <h4>📡 ${tr('wifi.sec_overview')}</h4>
      <div style="font-size:28px;font-weight:800;color:${scoreColor};margin-bottom:4px">${s.avgSecScore}</div>
      <div style="font-size:11px;color:var(--text-dim);margin-bottom:10px">${tr('wifi.avg_score')}</div>
      <div style="font-size:12px">
        ${s.criticalIssues ? `<div style="color:var(--red)">🚨 ${tr('wifi.critical_issues')}：${s.criticalIssues}${tr('unit.count')}</div>` : ''}
        ${s.warnIssues     ? `<div style="color:var(--yellow)">⚠ ${tr('wifi.warn_issues')}：${s.warnIssues}${tr('unit.count')}</div>` : ''}
        ${!s.criticalIssues && !s.warnIssues ? `<div style="color:var(--green)">${tr('wifi.no_issues')}</div>` : ''}
        ${s.wpa3Ssids ? `<div style="color:var(--green)">✅ ${s.wpa3Ssids} ${tr('wifi.ssid_use_wpa3')}</div>` : `<div style="color:var(--yellow)">${tr('wifi.no_wpa3')}</div>`}
        <div style="color:var(--text-dim);margin-top:4px">${tr('wifi.hidden_ssid')}：${s.hiddenSsids}${tr('unit.count')} | ${tr('wifi.country_code')}：${s.country}</div>
      </div>
    </div>`;

    // Card 2: AP infrastructure
    html += `<div class="wifi-card">
      <h4>🏢 ${tr('wifi.ap_infra')}</h4>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:13px">
        <div><div style="font-size:22px;font-weight:700;color:var(--accent)">${s.apCount}</div><div style="color:var(--text-dim);font-size:11px">${tr('wifi.managed_ap')}</div></div>
        <div><div style="font-size:22px;font-weight:700;color:var(--purple)">${s.profileCount}</div><div style="color:var(--text-dim);font-size:11px">${tr('wifi.ap_profile_label')}</div></div>
        <div><div style="font-size:22px;font-weight:700;color:var(--green)">${s.wifi6Aps}</div><div style="color:var(--text-dim);font-size:11px">${tr('wifi.wifi6_type')}</div></div>
        <div><div style="font-size:22px;font-weight:700;color:var(--orange)">${s.dualBandAps}</div><div style="color:var(--text-dim);font-size:11px">${tr('wifi.dual_band')}</div></div>
      </div>
    </div>`;

    // Card 3: SSID breakdown
    html += `<div class="wifi-card">
      <h4>📶 ${tr('wifi.ssid_dist')}</h4>`;
    const ssidTypes = [
      { label:tr('wifi.wpa2_enc'), count: w.vaps.filter(v=>v.security==='wpa2-only'||v.security.includes('wpa2')).length, color:'var(--green)' },
      { label:tr('wifi.wpa3_enc'), count: w.vaps.filter(v=>v.security.includes('wpa3')).length, color:'var(--accent)' },
      { label:'Captive Portal', count: s.captiveSsids, color:'var(--yellow)' },
      { label:tr('wifi.vlan_iso'),  count: s.vlanSsids,    color:'var(--purple)' },
      { label:tr('wifi.fully_open'),   count: s.openSsids,    color:'var(--red)' },
    ];
    ssidTypes.forEach(t => {
      if (t.count === 0) return;
      const pct = Math.round(t.count / s.ssidCount * 100);
      html += `<div style="margin-bottom:5px">
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-dim);margin-bottom:2px">
          <span>${esc(t.label)}</span><span>${t.count} (${pct}%)</span>
        </div>
        <div style="height:5px;background:var(--border);border-radius:3px">
          <div style="width:${pct}%;height:100%;background:${t.color};border-radius:3px"></div>
        </div>
      </div>`;
    });
    html += `</div></div>`;  // close card + wifi-grid

    // ── SSID table ────────────────────────────────────
    html += `<div style="margin-bottom:16px">
      <div style="font-size:12px;font-weight:700;margin-bottom:8px;color:var(--text-dim)">📶 ${tr('wifi.ssid_analysis')}</div>
      <div style="border:1px solid var(--border);border-radius:8px;overflow:hidden">
        <div class="ssid-row hdr">
          <div>${tr('wifi.ssid_name')}</div><div>${tr('wifi.sec_mode')}</div><div>${tr('wifi.sec_grade')}</div><div>Captive</div><div>VLAN</div><div>PMF</div><div>${tr('wifi.ap_deploy')}</div>
        </div>`;
    w.vaps.forEach(v => {
      const gradeClass = `sec-${v.secGrade}`;
      const secLabel = v.security === 'wpa2-only' ? 'WPA2' : v.security === 'open' ? tr('wifi.sec_open') : v.security;
      html += `<div class="ssid-row" style="cursor:pointer" onclick="showSsidDetail('${btoa(unescape(encodeURIComponent(v.name)))}')">
        <div style="font-weight:600">
          ${!v.broadcastSsid ? `<span title="${tr('wifi.hidden_ssid_tip')}">👁‍🗨</span> ` : ''}${esc(v.ssid)}
        </div>
        <div><span class="wifi-badge ${gradeClass}">${esc(secLabel)}</span></div>
        <div><span class="wifi-badge ${gradeClass}">${v.secGrade}</span></div>
        <div>${v.captivePortal ? '✅' : '-'}</div>
        <div>${v.vlanId !== '-' ? `<span style="color:var(--purple)">VLAN ${v.vlanId}</span>` : '-'}</div>
        <div>${v.pmf !== '-' ? v.pmf : '<span style="color:var(--text-dim)">-</span>'}</div>
        <div style="color:var(--accent)">${v.deployedOnAps > 0 ? v.deployedOnAps + ' ' + tr('wifi.unit_ap') : '<span style="color:var(--text-dim)">-</span>'}</div>
      </div>`;
      // Show issues inline
      if (v.secIssues.length) {
        html += `<div style="padding:4px 12px 6px;background:rgba(0,0,0,.2)">`;
        v.secIssues.forEach(i => {
          html += `<div class="wifi-issue ${i.level}">
            <span>${i.level==='critical'?'🚨':i.level==='warn'?'⚠':'ℹ'}</span>
            <span>${esc(tr(i.msg))}</span>
          </div>`;
        });
        html += `</div>`;
      }
    });
    html += `</div></div>`;

    // ── AP Instances table ─────────────────────────────
    if (w.wtps.length) {
      html += `<div style="margin-bottom:16px">
        <div style="font-size:12px;font-weight:700;margin-bottom:8px;color:var(--text-dim)">🏢 ${tr('wifi.managed_ap_list')}</div>
        <div style="border:1px solid var(--border);border-radius:8px;overflow:hidden">
          <div class="ap-row hdr">
            <div>${tr('wifi.col_serial')}</div><div>${tr('col.name')}</div><div>${tr('wifi.col_location')}</div><div>${tr('wifi.col_profile')}</div><div>${tr('col.status')}</div>
          </div>`;
      w.wtps.forEach(ap => {
        html += `<div class="ap-row">
          <div class="mono" style="font-size:11px;color:var(--text-dim)">${esc(ap.serial)}</div>
          <div style="font-weight:600">${esc(ap.name)}</div>
          <div style="color:var(--text-dim)">${esc(ap.location !== '-' ? ap.location : '')}</div>
          <div style="color:var(--purple);font-size:11px">${esc(ap.profile)}</div>
          <div>${ap.status === 'enable' ? pill(tr('wwan.pill_enable'),'p-allow') : pill(tr('wwan.pill_disable'),'p-deny')}</div>
        </div>`;
      });
      html += `</div></div>`;
    }

    // ── WTP Profiles (AP 機型) ─────────────────────────
    html += `<div style="margin-bottom:16px">
      <div style="font-size:12px;font-weight:700;margin-bottom:8px;color:var(--text-dim)">📻 ${tr('wifi.ap_profile_config')}</div>
      <div style="border:1px solid var(--border);border-radius:8px;overflow:hidden">`;
    w.wtpProfiles.slice(0, 15).forEach((p, idx) => {
      const genBadge = p.wifiGen.includes('Wi-Fi 6') ? `<span class="wifi6-badge">Wi-Fi 6</span>` : `<span class="wifi5-badge">Wi-Fi 5</span>`;
      html += `<div style="padding:8px 12px;${idx>0?'border-top:1px solid var(--border)':''}">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
          <span style="font-weight:600;font-size:12px">${esc(p.name)}</span>
          <span style="color:var(--text-dim);font-size:11px">${esc(p.platform)}</span>
          ${genBadge}
          ${p.has2G && p.has5G ? `<span style="font-size:10px;color:var(--text-dim)">${tr('wifi.dual_band_short')}</span>` : ''}
          ${p.hasMonitor ? `<span style="font-size:10px;color:var(--orange)">${tr('wifi.monitor_radio')}</span>` : ''}
        </div>
        <div>`;
      p.radios.filter(r => r.mode !== 'monitor' && r.band !== '-').forEach(r => {
        const isAX = r.band.includes('ax');
        html += `<div class="radio-row">
          <span style="color:${r.band.includes('5G')?'var(--accent)':'var(--green)'}">Radio ${r.id} (${r.band.includes('5G')?'5GHz':'2.4GHz'})</span>
          ${isAX ? '<span class="wifi6-badge" style="font-size:9px">ax</span>' : ''}
          <span style="margin-left:6px">${r.vaps.slice(0,4).map(v=>`<span class="vap-pill">${esc(v)}</span>`).join('')}${r.vaps.length>4?`<span style="font-size:10px;color:var(--text-dim)">+${r.vaps.length-4}</span>`:''}</span>
        </div>`;
      });
      html += `</div></div>`;
    });
    if (w.wtpProfiles.length > 15) {
      html += `<div style="padding:8px 12px;color:var(--text-dim);font-size:11px;border-top:1px solid var(--border)">... ${tr('wifi.more_profiles_prefix')} ${w.wtpProfiles.length - 15} ${tr('wifi.more_profiles_suffix')}</div>`;
    }
    html += `</div></div>`;

    // ── WIDS Profiles ──────────────────────────────────
    if (w.widsProfiles.length) {
      html += `<div style="margin-bottom:16px">
        <div style="font-size:12px;font-weight:700;margin-bottom:8px;color:var(--text-dim)">🛡 ${tr('wifi.wids_title')}</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">`;
      w.widsProfiles.forEach(p => {
        const coverColor = p.coverage >= 80 ? 'var(--green)' : p.coverage >= 50 ? 'var(--yellow)' : 'var(--red)';
        html += `<div class="wifi-card">
          <h4>${esc(p.name)} ${p.comment && p.comment !== '-' ? `<span style="font-weight:400;color:var(--text-dim)">${esc(p.comment)}</span>` : ''}</h4>
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <div style="font-size:20px;font-weight:700;color:${coverColor}">${p.coverage}%</div>
            <div style="font-size:11px;color:var(--text-dim)">${tr('wifi.wids_coverage')} (${p.enabledCount}/${p.totalCount})</div>
          </div>
          <div class="wids-bar"><div class="wids-bar-fill" style="width:${p.coverage}%;background:${coverColor}"></div></div>
          <div style="margin-top:8px;font-size:10px;display:grid;grid-template-columns:1fr 1fr;gap:2px">
            ${Object.entries(p.checks).map(([k,v]) => {
              const labels = {apScan:tr('wids.ap_scan'),wirelessBridge:tr('wids.wireless_bridge'),deauthBroadcast:tr('wids.deauth_broadcast'),
                spoofedDeauth:tr('wids.spoofed_deauth'),weakWepIv:tr('wids.weak_wep_iv'),asleapAttack:tr('wids.asleap_attack'),
                nullSsidProbe:tr('wids.null_ssid'),eapolFlood:tr('wids.eapol_flood'),longDuration:tr('wids.long_duration'),invalidMacOui:tr('wids.invalid_mac_oui')};
              return `<div style="color:${v?'var(--green)':'var(--text-muted)'};">${v?'✅':'⬜'} ${esc(labels[k]||k)}</div>`;
            }).join('')}
          </div>
        </div>`;
      });
      html += `</div></div>`;
    }

    return html;
  }

  // SSID detail popup
  window.showSsidDetail = function(encoded) {
    if (!WIFI_DATA) return;
    const name = decodeURIComponent(escape(atob(encoded)));
    const v = WIFI_DATA.vaps.find(v => v.name === name || v.ssid === name);
    if (!v) return;
    const rows = [
      ['SSID', v.ssid], [tr('wifi.vap_name'), v.name],
      [tr('wifi.sec_mode'), v.security === 'wpa2-only' ? 'WPA2-Personal' : v.security],
      [tr('wifi.sec_grade_detail'), v.secGrade + ' (' + v.secScore + '/100)'],
      [tr('wifi.passphrase'), v.passphrase],
      ['Captive Portal', v.captivePortal ? tr('wwan.pill_enable') + ' (' + (v.portalType !== '-' ? v.portalType : 'default') + ')' : tr('wwan.pill_disable')],
      [tr('wifi.broadcast_ssid'), v.broadcastSsid ? tr('wifi.yes') : tr('wifi.no_hidden')],
      ['PMF (802.11w)', v.pmf !== '-' ? v.pmf : tr('wwan.pin_notset')],
      ['Intra-VAP Privacy', v.intraVapPrivacy ? tr('wwan.pill_enable') : tr('wwan.pill_disable')],
      ['VLAN ID', v.vlanId !== '-' ? v.vlanId : tr('wifi.native_vlan')],
      [tr('wifi.local_bridging'), v.localBridging === 'enable' ? tr('wwan.pill_enable') : v.localBridging !== '-' ? v.localBridging : tr('wwan.pill_disable')],
      [tr('wifi.user_groups'), v.userGroups !== '-' ? v.userGroups : '-'],
      [tr('wifi.addr_groups'), v.addrGroup !== '-' ? v.addrGroup : '-'],
      [tr('col.schedule'), v.schedule !== '-' ? v.schedule : '-'],
      [tr('wifi.ap_deploy'), v.deployedOnAps + ' ' + tr('wifi.unit_ap') + ' (' + (v.usedInProfiles || []).join(', ') + ')'],
    ];
    showPopup(tr('wifi.ssid_detail_prefix') + v.ssid, rows);
  };


  // ══════════════════════════════════════════════════════
  //  FEATURE 1+2+3: Popup helpers
  // ══════════════════════════════════════════════════════
  function showPopup(title, rows) {
    $('pop-title-text').textContent = title;
    const clean = v => String(v == null ? '-' : v);
    $('pop-body').innerHTML = '<table>' +
      rows.filter(([k,v]) => !(k==='' && v==='')).map(([k,v]) =>
        k === '' ? '<tr><td colspan="2" style="height:8px"></td></tr>'
        : `<tr><td>${esc(k)}</td><td class="mono">${esc(clean(v))}</td></tr>`
      ).join('') + '</table>';
    const p = $('detail-popup');
    p.style.cssText = 'display:block;position:fixed;left:50%;top:90px;transform:translateX(-50%);z-index:200';
  }

  window.closePopup = () => { $('detail-popup').style.display = 'none'; };
  document.addEventListener('click', e => {
    const p = $('detail-popup');
    if (p && p.style.display !== 'none' &&
        !p.contains(e.target) &&
        !e.target.classList.contains('clickable-cell') &&
        !e.target.classList.contains('nat-badge'))
      p.style.display = 'none';
  });

  // Build reverse index: address/service name → policy refs
  window.buildRefIndex = function(d) {
    window._addrRefs = {};
    window._svcRefs  = {};
    if (!d || !d.policies) return;
    const addRef = (map, key, entry) => {
      if (!key || key === '-' || key === 'all' || key === 'any') return;
      if (!map[key]) map[key] = [];
      map[key].push(entry);
    };
    d.policies.forEach(p => {
      const entry = { id: p.id, name: p.name, action: p.action };
      (p.srcAddr || '').split(/[,\s]+/).forEach(n => addRef(window._addrRefs, n.trim(), {...entry, role:'src'}));
      (p.dstAddr || '').split(/[,\s]+/).forEach(n => addRef(window._addrRefs, n.trim(), {...entry, role:'dst'}));
      (p.service  || '').split(/[,\s]+/).forEach(n => addRef(window._svcRefs,  n.trim(), entry));
    });
  };

  // Shared: render ref list HTML for modal
  function _refListHTML(refs, title) {
    if (!refs || !refs.length) return `<div class="ref-section-title">${title}</div><div class="ref-empty">${tr('ref.no_ref')}</div>`;
    return `<div class="ref-section-title">${title} (${refs.length})</div>` +
      refs.map(r => {
        const rolePill = r.role === 'src'
          ? `<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(56,189,248,.15);color:var(--info)">${tr('ref.role_src')}</span>`
          : r.role === 'dst'
          ? `<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(251,146,60,.15);color:var(--orange)">${tr('ref.role_dst')}</span>`
          : '';
        const actPill = r.action === 'accept'
          ? `<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(34,197,94,.15);color:var(--green)">✓</span>`
          : `<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(239,68,68,.15);color:var(--red)">✕</span>`;
        return `<div class="ref-row" onclick="_jumpToPolicy('${r.id}');document.getElementById('_ref-modal-overlay')?.remove()">
          <span class="ref-id">#${esc(String(r.id))}</span>
          <span class="ref-name">${esc(r.name||'-')}</span>
          ${rolePill}${actPill}
        </div>`;
      }).join('');
  }

  function _showRefModal(title, sub, bodyHTML) {
    const existing = document.getElementById('_ref-modal-overlay');
    if (existing) existing.remove();
    const ov = document.createElement('div');
    ov.className = 'ref-modal-overlay';
    ov.id = '_ref-modal-overlay';
    ov.innerHTML = `<div class="ref-modal">
      <div class="ref-modal-close" onclick="this.closest('.ref-modal-overlay').remove()">✕</div>
      <div class="ref-modal-title">${title}</div>
      <div class="ref-modal-sub">${sub}</div>
      ${bodyHTML}
    </div>`;
    ov.addEventListener('click', e => { if (e.target === ov) ov.remove(); });
    document.body.appendChild(ov);
  }


  // ── Global cross-field search ────────────────────────────────────────────
  window.doGlobalQuery = function(q) {
    const el = $('global-search-result');
    if (!el) return;
    q = (q||'').trim();
    if (!q) { el.innerHTML = ''; return; }
    if (!PARSED) { el.innerHTML = `<div class="nodata">${tr('search.no_data')}</div>`; return; }
    const ql = q.toLowerCase();
    const SECTIONS = ['interfaces','policies','routes','vpn','nat','addresses','services','users'];
    const results = SECTIONS.map(sec => {
      const arr = PARSED[sec] || [];
      const hits = arr.filter(r => Object.values(r).some(v => String(v??'').toLowerCase().includes(ql))).slice(0, 30);
      return { sec, label: SEC_LABELS[sec] ? SEC_LABELS[sec]() : sec, count: hits.length, rows: hits };
    }).filter(r => r.count > 0);
    el.innerHTML = renderGlobalResults(results, q);
  };

  function renderGlobalResults(results, q) {
    if (!results.length) return `<div class="nodata">${tr('search.no_results')}</div>`;
    // 2026-08-09 稽核修復：比照同專案其餘 esc() 定義補上雙引號跳脫，統一一致（此處目前用法
    // 皆在文字內容而非屬性語境，非立即可利用，但避免未來新增用法時被誤用於屬性內）
    const esc = s => String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    const hl = s => { const r = esc(s); const qi = r.toLowerCase().indexOf(q.toLowerCase()); if(qi<0)return r; return r.slice(0,qi)+'<mark style="background:rgba(0,212,255,.25);border-radius:2px;padding:0 2px">'+r.slice(qi,qi+q.length)+'</mark>'+r.slice(qi+q.length); };
    return results.map(({sec, label, count, rows}) => {
      const keys = Object.keys(rows[0]||{}).filter(k=>!['phase2','comment','_shadow'].includes(k)).slice(0,6);
      const rowsHtml = rows.map(r => `<tr>${keys.map(k=>`<td>${hl(r[k])}</td>`).join('')}</tr>`).join('');
      return `<div style="margin-bottom:18px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <span style="font-weight:700;color:var(--accent);font-size:13px">${esc(label)}</span>
          <span style="display:flex;align-items:center;gap:8px">
            <span style="font-size:11px;color:var(--text-dim)">${count} ${tr('search.results')}</span>
            <button type="button" onclick="showSection('${sec}')" style="padding:2px 10px;border-radius:4px;border:1px solid var(--accent);background:none;color:var(--accent);cursor:pointer;font-size:11px">${tr('search.goto')}</button>
          </span>
        </div>
        <div style="overflow-x:auto"><table>
          <thead><tr>${keys.map(k=>`<th>${esc(k)}</th>`).join('')}</tr></thead>
          <tbody>${rowsHtml}</tbody>
        </table></div>
      </div>`;
    }).join('');
  }

  // ── Packet Walk: 路由最長前綴匹配 ─────────────────────────────────────
  function _lookupRoute(dstIp, routes) {
    if (!dstIp || !routes) return null;
    let best = null, bestLen = -1;
    routes.filter(r => r.type === 'static' || r.type === 'connected').forEach(r => {
      if (!r.dst) return;
      const parts = r.dst.split('/');
      const net = parts[0]; const prefixLen = parseInt(parts[1] || '32', 10);
      try {
        if (_ipInSubnet(dstIp, net, prefixLen) && prefixLen > bestLen) {
          bestLen = prefixLen; best = r;
        }
      } catch(e) {}
    });
    return best;
  }
  function _ipInSubnet(ip, net, prefix) {
    const toInt = s => s.trim().split('.').reduce((a,b)=>(a<<8)+(+b),0)>>>0;
    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    return (toInt(ip) & mask) === (toInt(net) & mask);
  }

  function _buildPacketWalkHtml(src, dst, res, routeMatch) {
    const accepted = res.action === 'accept';
    const denied = res.action === 'deny' || (!res.matched && res.action !== 'accept');
    const pName = res.matched ? esc(res.matched.name) : '';
    const step = (icon, label, detail, color, dim) =>
      `<div class="pw-step" style="background:var(--surface2);border:1px solid ${dim?'var(--border)':'var(--accent)'};border-radius:8px;padding:8px 12px;min-width:90px;text-align:center;opacity:${dim?'0.4':'1'}">
        <div style="font-size:20px">${icon}</div>
        <div style="font-size:11px;font-weight:600;color:${color||'var(--text)'};margin-top:2px">${label}</div>
        ${detail?`<div style="font-size:10px;color:var(--text-dim);margin-top:1px">${detail}</div>`:''}
      </div>`;
    const conn = (ok) => `<div class="pw-conn" style="width:28px;height:3px;background:${ok?'var(--green)':'var(--border)'};align-self:center;flex-shrink:0"></div>`;
    const rLabel = routeMatch ? (routeMatch.device||routeMatch.gateway||'-') : tr('pw.no_route');
    const rColor = routeMatch ? 'var(--teal)' : 'var(--text-dim)';
    return `<div style="margin-bottom:12px;padding:12px 14px;background:var(--surface);border:1px solid var(--border);border-radius:8px">
      <div style="font-size:11px;font-weight:600;color:var(--text-dim);margin-bottom:10px;text-transform:uppercase;letter-spacing:.5px">${tr('pw.title')}</div>
      <div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap">
        ${step('📤', tr('pw.src'), esc(src), 'var(--text)', false)}
        ${conn(true)}
        ${step(accepted?'✅':'❌', tr('pw.policy_hit'), pName, accepted?'var(--green)':'var(--red)', false)}
        ${conn(accepted)}
        ${step('🗺️', tr('pw.route_match'), rLabel, rColor, !accepted)}
        ${conn(accepted && !!routeMatch)}
        ${step('🔌', tr('pw.egress'), routeMatch&&accepted?(routeMatch.device||'-'):'-', 'var(--accent)', !accepted||!routeMatch)}
        ${conn(accepted && !!routeMatch)}
        ${step('📥', tr('pw.dst'), esc(dst), 'var(--text)', !accepted||!routeMatch)}
      </div>
      ${denied&&!res.matched?`<div style="font-size:11px;color:var(--text-dim);margin-top:8px">${tr('pw.deny_note')}</div>`:''}
    </div>`;
  }

  // ── IP/Policy Query: run ────────────────────────────────────────────────
  window._runQuery = function() {
    const src  = ($('q-src')||{}).value||'';
    const dst  = ($('q-dst')||{}).value||'';
    const proto= ($('q-proto')||{}).value||'any';
    const port = ($('q-port')||{}).value||'';
    const vdom = $('q-vdom') ? $('q-vdom').value : '__all__';
    const el = $('query-result');
    if (!el) return;

    const res = _runPolicyQuery(src.trim(), dst.trim(), proto, port, vdom, PARSED);
    if (!res) { el.innerHTML = '<div class="nodata">'+tr('query.no_policy')+'</div>'; LAST_QUERY_TRACE = null; return; }
    if (res.error === 'invalid_ip') {
      el.innerHTML = `<div style="color:var(--red);padding:10px 0">${tr('query.invalid_ip')}</div>`; LAST_QUERY_TRACE = null; return;
    }
    // CSV 匯出按鈕快取：只保留目前畫面上的單次查詢結果（非歷史批次），見上方
    // LAST_QUERY_TRACE 宣告處註解
    LAST_QUERY_TRACE = { src: src.trim(), dst: dst.trim(), proto, port, trace: res.trace || [] };
    // Packet Walk 路由查詢
    const _pwRoutes = (PARSED && PARSED.routes) || [];
    const _pwRoute = (res.action === 'accept' && dst.trim()) ? _lookupRoute(dst.trim(), _pwRoutes) : null;
    const _pwHtml = _buildPacketWalkHtml(src.trim(), dst.trim(), res, _pwRoute);

    // 結果橫幅
    let banner = '';
    const p = res.matched;
    const _qLbl = `<span style="font-family:monospace;font-size:11px;color:var(--text-dim);display:block;margin-bottom:4px">`
      + `${esc(src)} → ${esc(dst)}`
      + (proto && proto!=='any' ? ` ${esc(proto.toUpperCase())}` : '')
      + (port ? `:${esc(port)}` : '')
      + `</span>`;
    const fqdnNote = (res.trace.find(t=>t.result==='match'&&t.hasFqdn))
      ? ` <span style="font-size:11px;color:var(--orange)">(${tr('query.fqdn_note')})</span>` : '';
    const _mt = res.trace.find(t=>t.result==='match');
    const _rSrc = _mt&&_mt.resolvedSrc;
    const _rDst = _mt&&_mt.resolvedDst;
    const resolvedDetail = (_rSrc||_rDst) ? `
      <div style="margin-top:6px;font-size:12px;font-family:monospace;line-height:1.7">
        <span style="color:var(--text-dim)">Src :</span>
        ${_rSrc ? `<b>${esc(_rSrc.display)}</b><span style="color:var(--text-dim)"> ${esc(_rSrc.detail||'')}</span>` : '<span style="color:var(--text-dim)">-</span>'}
        &nbsp;&nbsp;
        <span style="color:var(--text-dim)">Dst :</span>
        ${_rDst ? `<b>${esc(_rDst.display)}</b><span style="color:var(--text-dim)"> ${esc(_rDst.detail||'')}</span>` : '<span style="color:var(--text-dim)">-</span>'}
      </div>` : '';
    if (res.action==='accept') {
      banner = `<div style="padding:12px 16px;border-radius:8px;background:color-mix(in srgb,var(--green) 15%,var(--bg2));border:1px solid var(--green);margin-bottom:12px;font-weight:600;font-size:13px">
        ${_qLbl}${tr('query.result_accept')} — ${tr('query.result_match')}: <b>${esc(p.name)}</b>
        <span style="font-family:monospace;color:var(--text-dim)">(ID: ${esc(p.id)})</span>
        | Action: <span style="color:var(--green)">ACCEPT</span>${fqdnNote}
        ${resolvedDetail}
      </div>`;
    } else if (res.action==='deny' && p) {
      banner = `<div style="padding:12px 16px;border-radius:8px;background:color-mix(in srgb,var(--red) 15%,var(--bg2));border:1px solid var(--red);margin-bottom:12px;font-weight:600;font-size:13px">
        ${_qLbl}${tr('query.result_deny')} — ${tr('query.result_match')}: <b>${esc(p.name)}</b>
        <span style="font-family:monospace;color:var(--text-dim)">(ID: ${esc(p.id)})</span>
        | Action: <span style="color:var(--red)">DENY</span>${fqdnNote}
        ${resolvedDetail}
      </div>`;
    } else {
      banner = `<div style="padding:12px 16px;border-radius:8px;background:color-mix(in srgb,var(--text-dim) 15%,var(--bg2));border:1px solid var(--border);margin-bottom:12px;font-weight:600;font-size:13px">
        ${_qLbl}${tr('query.result_implicit')}
      </div>`;
    }

    // Trace 表格
    const traceRows = res.trace.map((t,i) => {
      const isMatch = t.result==='match';
      const bg = isMatch ? 'color-mix(in srgb,var(--green) 12%,transparent)' : '';
      let statusCell = '';
      if (t.result==='disabled') statusCell = `<span style="color:var(--text-dim)">${tr('query.trace_disabled')}</span>`;
      else if (isMatch) statusCell = `<span style="color:var(--green);font-weight:600">${tr('query.trace_match')}</span>`;
      else if (t.reason==='src_addr'||t.reason==='dst_addr') statusCell = `<span style="color:var(--text-dim)">${tr('query.trace_skip_addr')}</span>`;
      else if (t.reason==='service') statusCell = `<span style="color:var(--text-dim)">${tr('query.trace_skip_svc')}</span>`;
      const act = t.policy.action==='accept'
        ? `<span class="badge badge-allow">ACCEPT</span>`
        : `<span class="badge badge-deny">DENY</span>`;
      const mainRow = `<tr style="background:${bg}">
        <td style="padding:3px 8px;color:var(--text-dim);font-family:monospace">${i+1}</td>
        <td style="padding:3px 8px;font-family:monospace">${esc(t.policy.id)}</td>
        <td style="padding:3px 8px">${esc(t.policy.name)}</td>
        <td style="padding:3px 8px;font-family:monospace;font-size:11px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(t.policy.srcAddr)}">${esc(t.policy.srcAddr)}</td>
        <td style="padding:3px 8px;font-family:monospace;font-size:11px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(t.policy.dstAddr)}">${esc(t.policy.dstAddr)}</td>
        <td style="padding:3px 8px">${act}</td>
        <td style="padding:3px 8px">${statusCell}</td>
      </tr>`;
      let resolvedRow = '';
      if (isMatch && t.resolvedSrc) {
        const si = t.resolvedSrc, di = t.resolvedDst;
        resolvedRow = `<tr style="background:${bg}">
          <td colspan="2" style="border-top:none"></td>
          <td colspan="5" style="padding:2px 8px 6px;font-size:11px;font-family:monospace;border-top:none">
            <span style="color:var(--text-dim)">Src →</span>
            <span style="color:var(--green);font-weight:600">${si?esc(si.display):'-'}</span>
            ${si&&si.detail?`<span style="color:var(--text-dim)"> (${esc(si.detail)})</span>`:''}
            &nbsp;&nbsp;
            <span style="color:var(--text-dim)">Dst →</span>
            <span style="color:var(--green);font-weight:600">${di?esc(di.display):'-'}</span>
            ${di&&di.detail?`<span style="color:var(--text-dim)"> (${esc(di.detail)})</span>`:''}
          </td>
        </tr>`;
      }
      return mainRow + resolvedRow;
    }).join('');

    el.innerHTML = _pwHtml + banner + `
      <details open>
        <summary style="cursor:pointer;font-weight:600;margin-bottom:8px;font-size:13px;user-select:none">
          ${tr('query.trace_title')} (${res.trace.length})
        </summary>
        <div style="overflow-x:auto;border-radius:6px;border:1px solid var(--border)">
          <table style="width:100%;border-collapse:collapse;font-size:12px">
            <thead><tr style="background:var(--bg3)">
              <th style="padding:5px 8px;text-align:left;color:var(--text-dim)">#</th>
              <th style="padding:5px 8px;text-align:left">ID</th>
              <th style="padding:5px 8px;text-align:left">${tr('col.name')}</th>
              <th style="padding:5px 8px;text-align:left">Src Addr</th>
              <th style="padding:5px 8px;text-align:left">Dst Addr</th>
              <th style="padding:5px 8px;text-align:left">${tr('col.action')}</th>
              <th style="padding:5px 8px;text-align:left">${tr('col.status')}</th>
            </tr></thead>
            <tbody>${traceRows}</tbody>
          </table>
        </div>
      </details>`;
  };
  window._runQuery = window._runQuery;

  // Feature 1: Address object popup
  window._showAddr = function(encoded) {
    let name;
    try { name = decodeURIComponent(escape(atob(encoded))); }
    catch(e) { name = encoded; }
    name = String(name).trim();
    if (!PARSED) return;
    const obj = PARSED.addresses.find(a => a.name === name || a.name.trim() === name);
    const detailRows = [];
    if (obj) {
      detailRows.push([tr('popup.col_name'), obj.name], [tr('popup.col_category'), obj.category], [tr('popup.col_type'), obj.type]);
      if (obj.subnet  && obj.subnet  !== '-') detailRows.push([tr('popup.col_subnet'), obj.subnet]);
      if (obj.fqdn    && obj.fqdn    !== '-') detailRows.push([tr('popup.col_fqdn'), obj.fqdn]);
      if (obj.startIp && obj.startIp !== '-') detailRows.push([tr('popup.col_start_ip'), obj.startIp]);
      if (obj.endIp   && obj.endIp   !== '-') detailRows.push([tr('popup.col_end_ip'), obj.endIp]);
      if (obj.members && obj.members !== '-') detailRows.push([tr('popup.col_members'), obj.members]);
      if (obj.comment && obj.comment !== '-') detailRows.push([tr('popup.col_comment'), obj.comment]);
      if (obj._vdom)                          detailRows.push([tr('popup.col_vdom'), obj._vdom]);
    } else {
      detailRows.push([tr('popup.addr_name'), name], [tr('popup.desc'), tr('popup.default_obj')]);
    }
    const detailHTML = `<table style="font-size:12px;width:100%;border-collapse:collapse;margin-bottom:10px">${
      detailRows.map(([k,v])=>`<tr><td style="color:var(--text-dim);padding:2px 8px 2px 0;white-space:nowrap">${esc(k)}</td><td class="mono">${esc(String(v))}</td></tr>`).join('')
    }</table>`;
    const refs = (window._addrRefs || {})[name] || [];
    const refsHTML = _refListHTML(refs, tr('ref.title_addr'));
    _showRefModal('📦 ' + esc(name), tr('popup.addr_obj'), detailHTML + refsHTML);
  };
  window.showAddrDetail = function(name) { _showAddr(btoa(unescape(encodeURIComponent(name)))); };

  // Feature 1b: Service object popup
  window._showSvc = function(encoded) {
    let name;
    try { name = decodeURIComponent(escape(atob(encoded))); }
    catch(e) { name = encoded; }
    name = String(name).trim();
    if (!PARSED) return;
    const obj = PARSED.services.find(s => s.name === name || s.name.trim() === name);
    const detailRows = [];
    if (obj) {
      detailRows.push([tr('popup.col_name'), obj.name], [tr('popup.col_category'), obj.category], [tr('popup.col_proto'), obj.proto||'-']);
      if (obj.tcpPorts && obj.tcpPorts !== '-') detailRows.push(['TCP Ports', obj.tcpPorts]);
      if (obj.udpPorts && obj.udpPorts !== '-') detailRows.push(['UDP Ports', obj.udpPorts]);
      if (obj.icmpType && obj.icmpType !== '-') detailRows.push(['ICMP Type', obj.icmpType]);
      if (obj.members  && obj.members  !== '-') detailRows.push([tr('popup.col_members'), obj.members]);
      if (obj.comment  && obj.comment  !== '-') detailRows.push([tr('popup.col_comment'), obj.comment]);
    } else {
      detailRows.push([tr('popup.svc_name'), name], [tr('popup.desc'), tr('popup.default_obj')]);
    }
    const detailHTML = `<table style="font-size:12px;width:100%;border-collapse:collapse;margin-bottom:10px">${
      detailRows.map(([k,v])=>`<tr><td style="color:var(--text-dim);padding:2px 8px 2px 0;white-space:nowrap">${esc(k)}</td><td class="mono">${esc(String(v))}</td></tr>`).join('')
    }</table>`;
    const refs = (window._svcRefs || {})[name] || [];
    const refsHTML = _refListHTML(refs, tr('ref.title_svc'));
    _showRefModal('⚙️ ' + esc(name), tr('popup.svc_obj'), detailHTML + refsHTML);
  };

  // Print / PDF
  window.doPrint = function() {
    const hdr = document.getElementById('fw-print-header');
    if (hdr && PARSED) {
      const info = PARSED.deviceInfo || {};
      hdr.innerHTML = `<strong>${esc(info.vendor||'')} — ${esc(info.hostname||'')}</strong> &nbsp;|&nbsp; ${esc(info.firmware||'')} &nbsp;|&nbsp; ${new Date().toLocaleString('zh-TW')}`;
    }
    window.print();
  };

  // Feature 3: NAT popup — by policy ID
  window.showNatById = function(policyId) {
    if (!PARSED) return;
    const rule = PARSED.policies.find(p => String(p.id) === String(policyId));
    if (!rule) { showPopup('🔀 NAT', [[tr('nat.no_rule'), policyId]]); return; }

    const poolname = (rule.poolname && rule.poolname !== '-' && rule.poolname !== 'disable')
      ? rule.poolname : null;

    const rows = [
      [tr('nat.rule_id'),    rule.id],
      [tr('nat.rule_name'),   rule.name],
      [tr('nat.src_iface'),   rule.srcIntf],
      [tr('nat.src_addr'),   rule.srcAddr],
      [tr('nat.pool_name'),  poolname || tr('nat.iface_snat')],
      ['', ''],
    ];

    const natObjs = PARSED.nat.filter(n => poolname ? n.name === poolname : false);
    if (natObjs.length === 0) {
      rows.push([tr('nat.nat_obj'), tr('nat.iface_snat_desc')]);
    } else {
      natObjs.forEach(obj => {
        rows.push([tr('nat.nat_obj'),  obj.name]);
        rows.push([tr('popup.col_type'),      obj.type]);
        if (obj.poolType && obj.poolType !== '-') rows.push([tr('nat.pool_type'), obj.poolType]);
        if (obj.vipType  && obj.vipType  !== '-') rows.push([tr('nat.vip_type'),  obj.vipType]);
        if (obj.startIp  && obj.startIp  !== '-') rows.push([tr('nat.ip_start'),   obj.startIp]);
        if (obj.endIp    && obj.endIp    !== '-') rows.push([tr('nat.ip_end'),   obj.endIp]);
        if (obj.extIp    && obj.extIp    !== '-') rows.push([tr('nat.ext_ip'),   obj.extIp]);
        if (obj.mapIp    && obj.mapIp    !== '-') rows.push([tr('nat.map_ip'),   obj.mapIp]);
        if (obj.extPort  && obj.extPort  !== '-') rows.push([tr('nat.ext_port'), obj.extPort]);
        if (obj.mapPort  && obj.mapPort  !== '-') rows.push([tr('nat.map_port'), obj.mapPort]);
        if (obj.comment  && obj.comment  !== '-') rows.push([tr('popup.col_comment'),      obj.comment]);
      });
    }
    showPopup(tr('nat.title_prefix') + rule.id, rows);
  };

  // Feature 2: VPN Phase1 popup
  window.showVpnDetail = function(vpnName) {
    if (!PARSED) return;
    const v = PARSED.vpn.find(v => v.name === vpnName);
    if (!v) return;
    showPopup(tr('vpn.phase1_title') + vpnName, [
      [tr('col.name'),      v.name],
      [tr('popup.col_type'),      v.type],
      [tr('vpn.remote_gw'),  v.remote  || '-'],
      [tr('col.if_name'), v.iface || '-'],
      ['IKE Version',  v.ikeVer  || '-'],
      [tr('vpn.auth_method'),  v.authMethod || '-'],
      [tr('vpn.proposal'),  v.proposal || '-'],
      [tr('vpn.dhgrp'),   v.dhgrp   || '-'],
      [tr('vpn.lifetime'), (v.lifetime || '-') + ' ' + tr('vpn.sec')],
      [tr('vpn.nat_traversal'),  v.natTraversal || '-'],
      [tr('vpn.dpd'),       v.dpd || '-'],
      [tr('vpn.local_id'),   v.localId || '-'],
      [tr('vpn.peer_id'),   v.peerId  || '-'],
      [tr('vpn.split_tunnel'), v.splitTunnel || '-'],
      [tr('vpn.split_tunnel_addr'), v.splitTunnelRoutingAddr || '-'],
      [tr('vpn.phase2_count'), v.phase2 ? v.phase2.length : 0],
    ]);
  };

  // NAC 動態 VLAN 指派 detail popup：FORTISWITCH_DATA 不在 PARSED 內（獨立 module 變數），
  // 故不比照 showVpnDetail 查 PARSED，改直接查 FORTISWITCH_DATA.ports 找出該 switchId+port
  // 對應的比對細節（MAC／matched-nac-policy／mac-policy／生效 VLAN）
  window.showFswNacDetail = function(switchId, portName) {
    if (!FORTISWITCH_DATA) return;
    const p = FORTISWITCH_DATA.ports.find(p => p.switchId === switchId && p.name === portName);
    if (!p || !p.nacVlan || p.nacVlan === '-') return;
    showPopup(tr('fsw.nac_detail_title') + portName, [
      [tr('col.fsw_switch_id'), p.switchId],
      [tr('col.name'), p.name],
      [tr('col.fsw_nac_vlan'), p.nacVlan],
      [tr('col.np_switch_mac_policy'), p.nacMacPolicy || '-'],
      [tr('nac.matched_policy'), p.nacMatchedPolicy || '-'],
      [tr('col.mac'), p.nacMac || '-'],
    ]);
  };

  // Web Filter / IPS profile 內容摘要 popup（僅 FortiGate；PARSED.webfilterProfiles/ipsSensors
  // 只在 FortigateParser 有回傳，其餘廠牌因未實作 parseWebfilterProfiles/parseIpsSensors 該欄位
  // 為 undefined，policies 表格 rowFn 那端已判斷 d.webfilterProfiles 存在才輸出可點擊 pill）
  window.showWebfilterDetail = function(name) {
    if (!PARSED || !PARSED.webfilterProfiles) return;
    const w = PARSED.webfilterProfiles.find(w => w.name === name);
    if (!w) return;
    showPopup('🌐 ' + name, [
      [tr('popup.col_name'), w.name],
      [tr('wf.comment'), w.comment],
      [tr('wf.options'), w.options],
      [tr('wf.block_count'), String(w.blockCount)],
      [tr('wf.monitor_count'), String(w.monitorCount)],
      [tr('wf.allow_count'), String(w.allowCount)],
    ]);
  };

  window.showIpsDetail = function(name) {
    if (!PARSED || !PARSED.ipsSensors) return;
    const s = PARSED.ipsSensors.find(s => s.name === name);
    if (!s) return;
    const sevStr = Object.entries(s.severityCounts || {}).map(([k,v]) => `${k}:${v}`).join(', ') || '-';
    const actStr = Object.entries(s.actionCounts || {}).map(([k,v]) => `${k}:${v}`).join(', ') || '-';
    showPopup('🛡️ ' + name, [
      [tr('popup.col_name'), s.name],
      [tr('ips.comment'), s.comment],
      [tr('ips.entry_count'), String(s.entryCount)],
      [tr('ips.severity_summary'), sevStr],
      [tr('ips.action_summary'), actStr],
    ]);
  };

  // Feature 2: VPN Phase2 popup
  window.showVpnPhase2Detail = function(vpnName) {
    if (!PARSED) return;
    const v = PARSED.vpn.find(v => v.name === vpnName);
    if (!v || !v.phase2 || !v.phase2.length) return;
    $('pop-title-text').textContent = tr('vpn.phase2_title') + vpnName;
    let html = '';
    v.phase2.forEach((p2, i) => {
      html += `<div style="margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border)">
        <div style="font-size:11px;font-weight:700;color:var(--accent);margin-bottom:6px">Phase2 #${i+1}: ${esc(p2.name||'-')}</div>
        <table>`;
      [[tr('vpn.proposal'),p2.proposal],[tr('vpn.pfs'),p2.pfs],[tr('vpn.dhgrp'),p2.dhgrp],
       [tr('vpn.lifetime'),(p2.lifetime||'-')+' '+tr('vpn.sec')],[tr('vpn.local_sub'),p2.localSub],[tr('vpn.remote_sub'),p2.remoteSub]]
        .filter(([,val]) => val && val !== '-')
        .forEach(([k,val]) => { html += `<tr><td style="color:var(--text-dim);font-size:11px;width:38%;padding:3px 8px">${esc(k)}</td><td style="font-family:monospace;padding:3px 8px">${esc(val)}</td></tr>`; });
      html += '</table></div>';
    });
    $('pop-body').innerHTML = html;
    $('detail-popup').style.cssText = 'display:block;position:fixed;left:50%;top:90px;transform:translateX(-50%);z-index:200';
  };

    // ══════════════════════════════════════════════════════
  //  FEATURE 4: Column sorting + column filter
  // ══════════════════════════════════════════════════════
  let _sortCol = -1, _sortDir = 1;
  let _colFilters = {};

  function renderTable(data, thead, rowFn) {
    _renderState = { thead, rowFn, _data: data };
    _sortCol = -1; _sortDir = 1; _colFilters = {};
    _doRender(data, thead, rowFn);
  }

  function _doRender(data, thead, rowFn) {
    // Build thead with sort indicators + filter inputs per column
    let thIdx = 0;
    const sortHead = thead.replace(/<th([^>]*)>(.*?)<\/th>/g, (m, attrs, content) => {
      const i = thIdx++;
      const sortMark = i === _sortCol ? ((_sortDir === 1) ? ' ▲' : ' ▼') : '';
      const filterVal = (_colFilters[i] || '').replace(/"/g, '&quot;');
      return `<th${attrs} data-col="${i}" style="padding:0;cursor:pointer">
        <div class="th-sort" onclick="_sortBy(${i})">${content}${sortMark}</div>
        <input class="col-filter-input" placeholder="${tr('col.filter_ph')}"
          oninput="_applyColFilter(${i}, this.value)"
          onclick="event.stopPropagation()"
          value="${filterVal}">
      </th>`;
    });

    // 大量資料時只渲染前 N 筆，避免一次性建構巨大 DOM 卡頓；比照 exportHTMLReport()
    // 既有「顯示前 200 筆」慣例（rpt.show_200），互動表格本身有搜尋/篩選可縮小範圍，
    // 門檻放寬到 500
    const TABLE_ROW_CAP = 500;
    const truncated = data.length > TABLE_ROW_CAP;
    const visibleData = truncated ? data.slice(0, TABLE_ROW_CAP) : data;
    const rows = visibleData.map(r => {
      let row = rowFn(r);
      if (r._vdom) row = row.replace('<tr>', `<tr data-vdom="${r._vdom}">`);
      return row;
    }).join('');

    $('tbl-wrap').innerHTML = `<table class="data-tbl">
      <thead>${sortHead}</thead>
      <tbody>${rows || `<tr><td colspan="20"><div class="nodata">⚠ ${tr('msg.no_data')}</div></td></tr>`}</tbody>
    </table>`;
    $('tbl-cnt').textContent = truncated
      ? tr('unit.table_truncated').replace('{shown}', TABLE_ROW_CAP).replace('{total}', data.length)
      : `${data.length} ${tr('unit.records')}`;
  }

    // 靜態 HTML 表格輕量排序（用於 SD-WAN 等多表格 section）
    window._sortStaticTbl = function(th, colIdx) {
      const table = th.closest('table');
      const tbody = table.querySelector('tbody');
      if (!tbody) return;
      const dir = th.dataset.sd === '1' ? -1 : 1;
      th.dataset.sd = String(dir === 1 ? 1 : -1);
      table.querySelectorAll('th').forEach(t => { t.textContent = t.textContent.replace(/ [▲▼]$/,''); t.dataset.sd=''; });
      th.textContent = th.textContent.replace(/ [▲▼]$/,'') + (dir === 1 ? ' ▲' : ' ▼');
      const rows = Array.from(tbody.rows);
      rows.sort((a, b) => {
        const va = (a.cells[colIdx]?.textContent||'').trim();
        const vb = (b.cells[colIdx]?.textContent||'').trim();
        const na = parseFloat(va), nb = parseFloat(vb);
        if (!isNaN(na) && !isNaN(nb)) return dir * (na - nb);
        return dir * va.localeCompare(vb, 'zh-TW', {numeric:true});
      });
      rows.forEach(r => tbody.appendChild(r));
    };

    window._sortBy = function(colIdx) {
    if (!_renderState) return;
    if (_sortCol === colIdx) _sortDir = -_sortDir;
    else { _sortCol = colIdx; _sortDir = 1; }
    let data = _renderState._data || [];
    // Apply column filters first
    data = _getColFiltered(data);
    // Apply global search
    const q = window._searchQ || '';
    if (q) data = data.filter(r => {
      const s = [r.name,r.id,r.ip,r.srcAddr,r.dstAddr,r.service,r.gateway,r.remote,r.subnet,r.server,r.comment,r.comments,r.desc,r.alias].filter(Boolean).join(' ').toLowerCase();
      return s.includes(q);
    });
    // Sort by cell text
    data = [...data].sort((a, b) => {
      const ra = _renderState.rowFn(a);
      const rb = _renderState.rowFn(b);
      const getCellText = (row, idx) => {
        const cells = row.match(/<td[^>]*>([\s\S]*?)<\/td>/g) || [];
        const cell = cells[idx] || '';
        return cell.replace(/<[^>]+>/g,'').trim();
      };
      const va = getCellText(ra, colIdx);
      const vb = getCellText(rb, colIdx);
      const na = parseFloat(va), nb = parseFloat(vb);
      if (!isNaN(na) && !isNaN(nb)) return _sortDir * (na - nb);
      return _sortDir * va.localeCompare(vb, 'zh-TW');
    });
    _doRender(data, _renderState.thead, _renderState.rowFn);
  };

  window._applyColFilter = function(colIdx, val) {
    _colFilters[colIdx] = val.trim().toLowerCase();
    if (!_renderState) return;
    let data = _getColFiltered(_renderState._data || []);
    const q = window._searchQ || '';
    if (q) data = data.filter(r => {
      const s = [r.name,r.id,r.ip,r.srcAddr,r.dstAddr,r.service,r.gateway,r.remote,r.subnet,r.server,r.comment,r.comments,r.desc,r.alias].filter(Boolean).join(' ').toLowerCase();
      return s.includes(q);
    });
    _doRender(data, _renderState.thead, _renderState.rowFn);
    $('tbl-cnt').textContent = `${data.length} ${tr('unit.records')}`;
  };

  function _getColFiltered(data) {
    const activeFilters = Object.entries(_colFilters).filter(([,v]) => v);
    if (!activeFilters.length) return data;
    return data.filter(r => {
      const row = _renderState.rowFn(r);
      const cells = (row.match(/<td[^>]*>([\s\S]*?)<\/td>/g) || [])
        .map(c => c.replace(/<[^>]+>/g,'').trim().toLowerCase());
      return activeFilters.every(([idx, val]) => (cells[parseInt(idx)] || '').includes(val));
    });
  }

  // ══════════════════════════════════════════════════════
  //  FEATURE 5: Converter source filter
  // ══════════════════════════════════════════════════════
  window.filterConvMatrix = function(srcVendor) {
    const btns = document.querySelectorAll('.conv-btn');
    btns.forEach(btn => {
      const onclick = btn.getAttribute('onclick') || '';
      if (!srcVendor) {
        btn.classList.remove('conv-hidden');
      } else {
        // Show only buttons where src matches
        const matches = onclick.includes(`'${srcVendor}'`) && onclick.includes('doConvert');
        // Check if this button's first vendor argument is srcVendor
        const m = onclick.match(/doConvert\('([^']+)','([^']+)'\)/);
        if (m && m[1] === srcVendor) btn.classList.remove('conv-hidden');
        else btn.classList.add('conv-hidden');
      }
    });
  };
  window.filterConvMatrix = window.filterConvMatrix;

  // ══════════════════════════════════════════════════════
  //  FEATURE 6: Easter Egg — Bean Rain 🫘
  // ══════════════════════════════════════════════════════
  (function setupEasterEgg() {
    let clickCount = 0, clickTimer = null;
    const logo = document.querySelector('.sidebar-logo .icon');
    if (!logo) return;
    logo.addEventListener('click', () => {
      clickCount++;
      clearTimeout(clickTimer);
      clickTimer = setTimeout(() => { clickCount = 0; }, 2000);
      if (clickCount >= 5) {
        clickCount = 0;
        startBeanRain();
      }
    });
  })();

  function startBeanRain() {
    const overlay = document.createElement('div');
    overlay.className = 'bean-rain-overlay';
    document.body.appendChild(overlay);
    const beans = ['🫘','🫘','🫘','🟢','🔵','🔴','🫛','🟡','🟠'];
    const colors = ['var(--green)','var(--accent)','var(--red)','var(--yellow)','var(--purple)','var(--orange)'];
    let count = 0;
    const interval = setInterval(() => {
      if (count++ > 80) { clearInterval(interval); setTimeout(() => overlay.remove(), 3000); return; }
      const bean = document.createElement('div');
      bean.className = 'bean';
      bean.textContent = beans[Math.floor(Math.random() * beans.length)];
      bean.style.left = Math.random() * 100 + 'vw';
      bean.style.fontSize = (16 + Math.random() * 20) + 'px';
      const dur = 2 + Math.random() * 3;
      bean.style.animation = `beanFall ${dur}s linear forwards`;
      bean.style.animationDelay = Math.random() * 1.5 + 's';
      overlay.appendChild(bean);
    }, 60);
    setTimeout(() => { clearInterval(interval); setTimeout(() => overlay.remove(), 3000); }, 5000);
  }
  window.startBeanRain = startBeanRain;

  // ── Toast helper（供所有彩蛋使用）────────────────────────
  function showEggToast(msg, duration=3500) {
    const t = document.createElement('div');
    t.className = 'egg-toast';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.classList.add('show'), 20);
    setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 400); }, duration);
  }
  window.showEggToast = showEggToast;

  // ── 彩蛋：分析完成後觸發條件型彩蛋 ──────────────────────
  function checkAnalyzeEggs(p) {
    // 彩蛋2：特殊 hostname
    const h = (p.deviceInfo?.hostname || '').toLowerCase();
    const SPECIAL_HN = {
      skynet:tr('egg.skynet'), hal9000:tr('egg.hal9000'), hal9:tr('egg.hal9000'),
      jarvis:tr('egg.jarvis'), gandalf:tr('egg.gandalf'), skywalker:tr('egg.skywalker'),
      ollama:tr('egg.ollama'), alpaca:tr('egg.ollama'),
      matrix:tr('egg.matrix'), neo:tr('egg.matrix'), morpheus:tr('egg.matrix'),
      enterprise:tr('egg.enterprise'), ncc1701:tr('egg.enterprise'),
      mordor:tr('egg.mordor'), sauron:tr('egg.mordor'),
      deathstar:tr('egg.deathstar'), vader:tr('egg.deathstar'),
      terminator:tr('egg.terminator'), t800:tr('egg.terminator'), t1000:tr('egg.terminator'),
      shodan:tr('egg.shodan'),
      marvin:tr('egg.marvin'), zaphod:tr('egg.marvin'),
      wintermute:tr('egg.wintermute'),
      ultron:tr('egg.ultron'), viki:tr('egg.ultron'),
      tardis:tr('egg.tardis'), timelord:tr('egg.tardis'),
    };
    for(const [k,v] of Object.entries(SPECIAL_HN)) {
      if(h.includes(k)) { setTimeout(() => showEggToast(v), 1200); break; }
    }
    // 彩蛋3：深夜工程師模式
    const hr = new Date().getHours();
    if(hr >= 0 && hr < 5) setTimeout(() => showEggToast(tr('egg.late_night')), 2000);
    // 彩蛋4a：全部規則均為拒絕
    if(p.policies.length > 0 && p.policies.every(x => x.action !== 'accept')) {
      setTimeout(() => showEggToast(tr('egg.fortress')), 1500);
    }
    // 彩蛋4b：偵測到萬用 accept 規則
    const wildcard = p.policies.some(x => {
      if(x.action !== 'accept') return false;
      const isAll = v => v === 'all' || (Array.isArray(v) && v.some(a => a === 'all'));
      return isAll(x.srcAddr || x.srcaddr) && isAll(x.dstAddr || x.dstaddr);
    });
    if(wildcard) setTimeout(() => showEggToast(tr('egg.wildcard')), 1800);
  }

  // ── 彩蛋 2：Konami Code → Matrix Policy Rain ────────────
  (function setupKonami(){
    const SEQ=[38,38,40,40,37,39,37,39,66,65]; // ↑↑↓↓←→←→BA
    let idx=0;
    document.addEventListener('keydown',e=>{
      idx=(e.keyCode===SEQ[idx])?idx+1:0;
      if(idx===SEQ.length){idx=0;startMatrixRain();}
    });
  })();

  
// ── 彩蛋：Rage quit（連按 Esc 三次）────────────────────────
(function(){
  var _rq=0,_rqT;
  document.addEventListener('keydown',function(e){
    if(e.key!=='Escape')return;
    clearTimeout(_rqT);
    _rq++;
    _rqT=setTimeout(function(){_rq=0;},1500);
    if(_rq>=3){_rq=0;showEggToast(tr('egg.rage_quit'));resetAll();}
  });
})();

function startMatrixRain(){
    if(document.querySelector('.matrix-overlay'))return;
    const overlay=document.createElement('div');
    overlay.className='matrix-overlay';
    document.body.appendChild(overlay);
    const words=['ALLOW','DENY','DROP','REJECT','VDOM','POLICY','INTERFACE','ROUTE','VPN','NAT','IPSEC','SSL-VPN','BGP','OSPF','ZONE','UTM','IPS','REDACTED_PSK','REDACTED_HASH','192.0.2.x','10.x.x.x','██████████','░░░░░░░░░░'];
    const cols=Math.floor(window.innerWidth/96)+2;
    for(let i=0;i<cols;i++){
      const col=document.createElement('div');
      col.className='matrix-col';
      col.style.left=(i*96)+'px';
      const dur=5+Math.random()*6;
      col.style.animation=`matrixDrop ${dur}s linear forwards`;
      col.style.animationDelay=(Math.random()*2.5)+'s';
      const lines=12+Math.floor(Math.random()*10);
      for(let j=0;j<lines;j++){
        const span=document.createElement('span');
        span.textContent=words[Math.floor(Math.random()*words.length)];
        const br=0.25+Math.random()*0.75;
        span.style.color=j===lines-1?'#ffffff':`rgba(0,200,240,${br})`;
        span.style.textShadow=j===lines-1?'0 0 8px #00c8f0':'none';
        col.appendChild(span);
      }
      overlay.appendChild(col);
    }
    const close=()=>overlay.remove();
    overlay.addEventListener('click',close);
    setTimeout(close,9000);
  }
  window.startMatrixRain=startMatrixRain;

  // ── 廠牌擬人化：tb-meta 連點 3 下 → 廠牌個性 ──────────────
  // ── 廠牌擬人化（3下）+ 羊駝核可（7下）共用同一計數器 ──────────────
  (function setupMetaSecret(){
    let n=0,t=null;
    const el=$('tb-meta');
    if(!el)return;
    el.addEventListener('click',()=>{
      n++;clearTimeout(t);
      t=setTimeout(()=>{n=0;},2500);
      if(n===3){
        // 廠牌個性：n 不重置，繼續往 7 累積
        const vendor=CONV_SRC_VENDOR||'';
        const msg=vendor?tr('egg.vendor_'+vendor):'';
        if(msg)showEggToast(msg,4500);
      }
      if(n>=7){
        n=0;
        el.classList.add('rainbow-flash');
        const orig=el.textContent;
        el.textContent=tr('egg.approved');
        setTimeout(()=>{el.classList.remove('rainbow-flash');el.textContent=orig;},2000);
      }
    });
  })();

  function resetAll(){
    LAST_QUERY_TRACE = null;
    WIFI_DATA = null;
    FORTISWITCH_DATA = null;
    const navWifi = $('nav-wifi');
    if (navWifi) navWifi.style.display = 'none';
    const navWwan = $('nav-wwan');
    if (navWwan) navWwan.style.display = 'none';
    const navWlan = $('nav-wlan');
    if (navWlan) navWlan.style.display = 'none';
    const navAudit = $('nav-audit');
    if (navAudit) { navAudit.style.display = 'none'; const nc=$('nc-audit'); if(nc){nc.textContent='0';nc.style.color='';} }
    const navQuery = $('nav-query'); if(navQuery) navQuery.style.display='none';
    ['ec-wifi-ssid','ec-wifi-ap',
     'ec-dhcp-servers','ec-dhcp-relays',
     'ec-sdwan-members','ec-sdwan-health','ec-sdwan-services','ec-sdwan-zones','ec-sdwan-neighbors',
     'ec-ha',
     'ec-dns-servers','ec-dns-proxy','ec-dns-static',
     'ec-snmp-agent','ec-snmp-communities','ec-snmp-v3users','ec-snmp-traps',
     'ec-log-syslog','ec-log-fortianalyzer','ec-log-netflow','ec-log-forward',
     'ec-wwan-profiles','ec-wwan-lte-iface','ec-wwan-apn-profiles','ec-wwan-5g-modem','ec-wwan-lte-modem',
     'ec-wlan-interfaces','ec-wlan-capsman',
     'ec-fortiswitch-switches','ec-fortiswitch-ports','ec-fortiswitch-mac-policies','ec-fortiswitch-nac-policies',
    ].forEach(id => { const el=$(id); if(el) el.style.display='none'; });
    PARSED=null;CURRENT_SECTION=null;CURRENT_DATA=[];_renderState=null;
    // 2026-07-30 修復既有缺口：原本清單只有 f/s/c/p/j/x 六家，SonicWall/MikroTik/Cisco ASA/
    // Cisco FTD（w/m/a/t）自新增以來從未被 resetAll() 清除過，「清除」按鈕對這 4 個上傳槽
    // 完全無效果（檔案/chip 殘留），一併補上並加入新增的 Zyxel（z）／EdgeRouter（r）／OpenWrt（u）
    ['f','s','c','p','j','x','w','m','a','t','z','r','u','g'].forEach(v=>{ST[v]=null;ST.raw[v]='';const inp=$(inpMap[v]);if(inp)inp.value='';$(chipMap[v]).style.display='none';});
    $('nav-data-group').style.display='none';$('nav-tools-group').style.display='none';
    $('tb-actions').style.display='none';$('tb-title').textContent=tr('title');$('tb-meta').textContent='';
    ACTIVE_VDOM='__all__'; const bar=$('vdom-bar'); if(bar)bar.style.display='none';
    updBtn();showView('upload');
  }
  window.resetAll=resetAll;

  // Init
  $('view-upload').style.display='flex';
  // Alpaca corner — inject programmatically so it's always on top
  (function(){
    var el=document.getElementById('alpaca-corner');
    if(!el){
      el=document.createElement('div');
      el.id='alpaca-corner';
      document.body.appendChild(el);
    }
    el.setAttribute('style','position:fixed;bottom:16px;right:16px;z-index:2147483647;opacity:.85;transition:opacity .2s;cursor:pointer;pointer-events:auto;display:block;');
    el.setAttribute('title', tr('egg.alpaca_title'));
    el.onmouseenter=function(){this.style.opacity='1'};
    el.onmouseleave=function(){this.style.opacity='.85'};
    el.onclick=function(){startBeanRain();};
    el.innerHTML='<svg width="48" height="56" viewBox="0 0 48 56" xmlns="http://www.w3.org/2000/svg"><ellipse cx="24" cy="38" rx="14" ry="12" fill="#c8b89a"/><rect x="18" y="20" width="8" height="16" rx="4" fill="#c8b89a"/><ellipse cx="22" cy="16" rx="9" ry="8" fill="#d4c4a0"/><ellipse cx="15" cy="10" rx="3" ry="5" fill="#c8b89a"/><ellipse cx="29" cy="10" rx="3" ry="5" fill="#c8b89a"/><ellipse cx="15" cy="10" rx="1.5" ry="3" fill="#e8b4b8"/><ellipse cx="29" cy="10" rx="1.5" ry="3" fill="#e8b4b8"/><circle cx="18" cy="15" r="2" fill="#4a3728"/><circle cx="26" cy="15" r="2" fill="#4a3728"/><circle cx="18.7" cy="14.3" r=".6" fill="#fff"/><circle cx="26.7" cy="14.3" r=".6" fill="#fff"/><ellipse cx="22" cy="20" rx="3" ry="2" fill="#b09070"/><circle cx="20.5" cy="20" r=".8" fill="#7a5a40"/><circle cx="23.5" cy="20" r=".8" fill="#7a5a40"/><ellipse cx="22" cy="9" rx="7" ry="4" fill="#e8dcc8"/><ellipse cx="18" cy="8" rx="4" ry="3" fill="#e8dcc8"/><ellipse cx="26" cy="8" rx="4" ry="3" fill="#e8dcc8"/><rect x="13" y="47" width="5" height="8" rx="2.5" fill="#b09070"/><rect x="20" y="47" width="5" height="8" rx="2.5" fill="#b09070"/><rect x="28" y="47" width="5" height="8" rx="2.5" fill="#b09070"/><ellipse cx="37" cy="36" rx="4" ry="3" fill="#d4c4a0"/></svg>';
  })();
  // 稽核函式供外部呼叫（診斷 / 整合測試）
  window._auditFns = { analyzeRuleShadowing, analyzeDenyBlocking, analyzeUnusedObjects, analyzeCompliance };
  // 測試注入：直接設定 PARSED 並觸發 onParsed（供自動化測試）
  window._injectParsed = function(d) { PARSED = d; onParsed(); };
  // 入口頁拖入自動載入
  window._loadFromPending = function(text, vendor) { ST.raw[vendor] = text; analyze(); };
  return{analyze,showView,showSection,exportSection,doExport,doConvert,downloadConv,resetAll};
})();

// 頁面初始化與彩蛋（pending-load 自動載入／tooltip／羊駝-lang-egg 彩蛋／主題切換）
// 已搬到 firewall-analyzer-eggs.js（2026-08-17，本來就在此 IIFE 外，純搬移）

