let parsed=null, currentView='upload', sbMini=false;
let sortCol=null, sortDir=1; // 1=asc -1=desc
let lldpView='table'; // 'table' | 'topo' | 'multi'
let portView='table'; // 'table' | 'heatmap'
let _multiDevices=[]; // [{hostname, lldp:[]}] for cross-device topology

// ════════════════════════════════════
//  SIDEBAR
// ════════════════════════════════════
function toggleSB(){
  sbMini=!sbMini;
  document.getElementById('sidebar').classList.toggle('sb-mini',sbMini);
  const btn=document.getElementById('sb-toggle');
  btn.textContent=sbMini?'›':'‹';
  btn.title=sbMini?tr('sb.expand'):tr('sb.fold');
  try{localStorage.setItem('cw_sb',sbMini?'1':'0');}catch(e){}
}
(()=>{try{if(localStorage.getItem('cw_sb')==='1'){sbMini=true;document.getElementById('sidebar').classList.add('sb-mini');document.getElementById('sb-toggle').textContent='›';}}catch(e){}})();

// ════════════════════════════════════
//  EASTER EGG — logo click counter
// ════════════════════════════════════
let eggClicks=0,eggTimer=null,rainActive=false,alpacaPhase=false,alpacaClicks=0,alpacaTimer=null;
document.getElementById('logo-btn').addEventListener('click',()=>{
  if(rainActive&&!alpacaPhase){
    alpacaClicks++;
    clearTimeout(alpacaTimer);
    alpacaTimer=setTimeout(()=>alpacaClicks=0,1500);
    if(alpacaClicks>=3){startRain(true);alpacaClicks=0;}
    return;
  }
  eggClicks++;
  clearTimeout(eggTimer);
  eggTimer=setTimeout(()=>eggClicks=0,1500);
  if(eggClicks>=5){eggClicks=0;startRain(false);}
});
function startRain(alpaca){
  rainActive=true;alpacaPhase=alpaca;
  const items=alpaca?['🦙','🦙','🦙','🐑','🌿']:['🍎','🍎','🍎','🍏','🍎'];
  const duration=alpaca?3000:5000;
  const count=alpaca?40:60;
  for(let i=0;i<count;i++){
    setTimeout(()=>{
      const el=document.createElement('div');
      el.className='rain-item';
      if(!alpaca){el.style.filter='hue-rotate(210deg) saturate(3) brightness(.85)';el.style.display='inline-block';}
      el.textContent=items[Math.floor(Math.random()*items.length)];
      el.style.left=Math.random()*100+'vw';
      el.style.animationDuration=(1.5+Math.random()*2)+'s';
      el.style.animationDelay=(Math.random()*1.5)+'s';
      document.body.appendChild(el);
      setTimeout(()=>el.remove(),4000);
    },Math.random()*duration*0.8);
  }
  setTimeout(()=>{rainActive=false;alpacaPhase=false;},duration);
}

// ── 彩蛋 2：Konami Code → Matrix Switch Rain ────────────
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
    if(_rq>=3){_rq=0;_showSwitchToast(tr('egg.rage_quit'));resetAll();}
  });
})();

function startMatrixRain(){
  if(document.querySelector('.matrix-overlay'))return;
  const overlay=document.createElement('div');
  overlay.className='matrix-overlay';
  document.body.appendChild(overlay);
  const words=['VLAN','TRUNK','ACCESS','STP','LACP','OSPF','BGP','VRRP','VLT','IRF','VSF','MAC','ARP','ACL','QoS','PVID','TAGGED','DHCP','SNMP','REDACTED_SECRET','10.x.x.x','██████████','░░░░░░░░░░'];
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

// ── 彩蛋 3：vendor badge 連點 7 下 → 羊駝核可 ──────────
(function setupVendorBadge(){
  let n=0,t=null;
  const el=document.getElementById('tb-vendor');
  if(!el)return;
  el.style.cursor='default';
  el.addEventListener('click',()=>{
    n++;clearTimeout(t);
    t=setTimeout(()=>{n=0;},2500);
    if(n>=7){
      n=0;
      el.classList.add('rainbow-flash');
      const orig=el.innerHTML;
      el.textContent=tr('egg.approved');
      setTimeout(()=>{el.classList.remove('rainbow-flash');el.innerHTML=orig;},2000);
    }
  });
})();

// ════════════════════════════════════
//  FILE / PASTE INPUT
// ════════════════════════════════════

// 2026-08-09 稽核修復：原本未跳脫雙引號，但多處用在 title="${esc(...)}" 這類雙引號屬性內
// （VLAN name／介面名稱等解析正則未限制字元集合），惡意設定檔可構造含 " 的名稱提前結束
// 屬性、注入事件處理器（如 onmouseover=），構成儲存型 XSS；比照 switch_config_generator
// 既有的 escAttr() 補上雙引號跳脫
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const pill=(c,t)=>`<span class="pill p-${c}">${esc(t)}</span>`;
let tableData=[],tableKeys=[];
const hn=()=>parsed?.sys?.hostname||'comware';

function onFileChange(inp){if(inp.files[0])readFile(inp.files[0]);}
function readFile(f){
  document.getElementById('fname').textContent=f.name;
  document.getElementById('file-chip').style.display='flex';
  const r=new FileReader();r.onload=e=>{document.getElementById('paste-area').value=e.target.result;};
  r.readAsText(f,'UTF-8');
}
function clearFile(){
  document.getElementById('file-inp').value='';
  document.getElementById('file-chip').style.display='none';
  document.getElementById('paste-area').value='';
}
function showEggToast(msg, duration=3500) {
  const t = document.createElement('div');
  t.className = 'egg-toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.classList.add('show'), 20);
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 400); }, duration);
}

function checkSwitchEggs(p) {
  // 彩蛋2：特殊 hostname
  const h = (p.sys?.hostname || '').toLowerCase();
  const SPECIAL_HN = {
    skynet:tr('egg.skynet'), hal9000:'🔴 I\'m sorry Dave', hal9:'🔴 I\'m sorry Dave',
    jarvis:tr('egg.jarvis'), gandalf:'🧙 You shall not pass', skywalker:tr('egg.skywalker'),
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
  // 彩蛋6：VLAN 收藏家
  if(p.vlans?.length >= 100) setTimeout(() => showEggToast(tr('egg.vlan_collector').replace('{n}',p.vlans.length)), 1500);
}

function toggleLldpInput(){
  const ta=document.getElementById('lldp-area');
  const icon=document.getElementById('lldp-toggle-icon');
  const shown=ta.style.display!=='none';
  ta.style.display=shown?'none':'block';
  if(icon) icon.textContent=shown?'＋':'－';
}

// 手動指定廠牌下拉選單：detectVendor() 誤判時的 fallback（2026-07-30 新增）。
// 清單與 parseAny() 的 if-else 派送鏈完全對應，新增廠牌時務必同步更新兩處
const FORCE_VENDOR_LIST=[
  ['comware','HPE Comware'],['cisco','Cisco IOS/IOS-XE'],['aruba','Aruba CX'],
  ['fortiswitch','FortiSwitch'],['juniper','Juniper Networks'],['dell-os10','Dell EMC Networking OS'],
  ['nxos','Cisco NX-OS'],['arista','Arista EOS'],['brocade','Brocade FastIron/ICX (Ruckus)'],
  ['alcatel','Alcatel OmniSwitch'],['extreme','Extreme Networks ExtremeXOS'],
  ['procurve','Aruba ProCurve'],['routeros','MikroTik RouterOS'],['ruijie','Ruijie RGOS'],
  ['netgear','Netgear M4300'],['edgeswitch','Ubiquiti EdgeSwitch'],
  ['sonic','SONiC (config_db.json)'],
];
(function(){
  // 防護：本區塊是頂層立即執行敘述，會被不同測試腳本的最小 DOM mock 一併載入執行，
  // 兩種 mock 缺的東西不一樣，需各自防護：
  // (1) switch_config_generator/test_config/gen_test.mjs 的 vrrpSandboxFn（切到
  //     "renderVRRP" 標記為止，涵蓋範圍含本區塊）mock 完全沒有 document.createElement；
  // (2) switch_analyzer/test_config/test_export.mjs 的 mock 有 document.createElement
  //     （匯出功能需要它產生下載用的 <a> 元素），但 getElementById() 回傳的物件沒有
  //     appendChild，若不加防護會讓與本功能完全無關的測試直接拋錯中斷
  const sel=document.getElementById('force-vendor-select');
  if(!sel||typeof document.createElement!=='function'||typeof sel.appendChild!=='function')return;
  FORCE_VENDOR_LIST.forEach(([v,label])=>{
    const opt=document.createElement('option');
    opt.value=v;opt.textContent=label;
    sel.appendChild(opt);
  });
})();

function doAnalyze(){
  const cfg=document.getElementById('paste-area').value.trim();
  if(!cfg){alert(tr('msg.no_config'));return;}
  const forceVendor=document.getElementById('force-vendor-select')?.value||'';
  parsed=parseAny(cfg,forceVendor);
  const lldpText=(document.getElementById('lldp-area')?.value||'').trim();
  parsed.lldp=lldpText?LLDPParser.parse(lldpText,parsed.vendor):[];
  showResultViews();
  updateCounts();
  buildSumCards();
  navGo('overview');
  checkSwitchEggs(parsed);
  clearTimeout(window._workTimer30); clearTimeout(window._workTimer60);
  window._workTimer30 = setTimeout(()=>_showSwitchToast(tr('egg.work_30min'),5000), 1800000);
  window._workTimer60 = setTimeout(()=>_showSwitchToast(tr('egg.work_60min'),5000), 3600000);
  setLang(_lang);
}
function showResultViews(){
  document.getElementById('view-upload').classList.remove('show');
  document.getElementById('view-result').style.display='flex';
  document.getElementById('view-result').style.flexDirection='column';
  document.getElementById('tb-actions').style.display='flex';
  document.getElementById('tb-meta').textContent=parsed.sys.hostname;
  // Update dynamic title based on vendor
  const titleEl=document.getElementById('tb-title');
  if(titleEl){
    const _a=tr('title.analyzer');
    const dellTitle=parsed.sys?.osGen?`Dell EMC ${parsed.sys.osGen} ${_a}`:`Dell EMC Networking OS ${_a}`;
    // Ruckus 收購 Brocade 後延續同一套 FastIron CLI 語法，detectVendor()/parseBrocade() 仍
    // 統一回傳 'brocade'（避免動到既有派送邏輯），品牌顯示改依 parseBrocadeSysInfo() 抓到的
    // brand 欄位（cfg 內含 Ruckus/CommScope 字樣時判定）動態切換標籤
    const brocadeTitle=parsed.sys?.brand==='ruckus'?`Ruckus ICX ${_a}`:`Brocade FastIron/ICX ${_a}`;
    const titleMap={'comware':'HPE Comware '+_a,'arista':'Arista EOS '+_a,'ruijie':'Ruijie RGOS '+_a,'netgear':'Netgear M4300 '+_a,'edgeswitch':'Ubiquiti EdgeSwitch '+_a,'cisco':'Cisco IOS/IOS-XE '+_a,'nxos':'Cisco NX-OS '+_a,'aruba':'Aruba CX '+_a,'procurve':'Aruba ProCurve '+_a,'fortiswitch':'FortiSwitch '+_a,'juniper':'Juniper EX/QFX '+_a,'extreme':'Extreme Networks ExtremeXOS '+_a,'alcatel':'Alcatel OmniSwitch '+_a,'brocade':brocadeTitle,'dell-os10':dellTitle,'unknown':tr('sl.unknown_vendor')+' '+_a};
    titleEl.textContent=titleMap[parsed.vendor]||tr('sl.unknown_vendor')+' '+_a;
  }
  const vbEl=document.getElementById('tb-vendor');
  if(vbEl){
    const dellLabel=parsed.sys?.osGen?`Dell EMC ${parsed.sys.osGen}`:'Dell EMC Networking OS';
    const brocadeLabel=parsed.sys?.brand==='ruckus'?'Ruckus ICX':'Brocade FastIron/ICX';
    const vLabel={'comware':'HPE Comware','arista':'Arista EOS','ruijie':'Ruijie RGOS','netgear':'Netgear M4300','edgeswitch':'Ubiquiti EdgeSwitch','cisco':'Cisco IOS/IOS-XE','nxos':'Cisco NX-OS','aruba':'Aruba CX','procurve':'Aruba ProCurve','fortiswitch':'FortiSwitch','juniper':'Juniper Networks','extreme':'Extreme Networks','alcatel':'Alcatel OmniSwitch','brocade':brocadeLabel,'dell-os10':dellLabel,'unknown':tr('sl.unknown_vendor')}[parsed.vendor]||parsed.vendor;
    const vClass={'comware':'vb-comware','arista':'vb-cisco','ruijie':'vb-cisco','netgear':'vb-cisco','edgeswitch':'vb-cisco','cisco':'vb-cisco','nxos':'vb-cisco','aruba':'vb-aruba','procurve':'vb-aruba','fortiswitch':'vb-forti','juniper':'vb-juniper','extreme':'vb-extreme','alcatel':'vb-alcatel','brocade':'vb-brocade','dell-os10':'vb-dell','unknown':'vb-unknown'}[parsed.vendor]||'vb-unknown';
    vbEl.innerHTML=`<span class="vendor-badge ${vClass}">${vLabel}</span>`;
    _setupVendorPersona();
  }
  // Update stack nav label based on vendor
  const irfLbl=document.getElementById('nav-irf-lbl');
  if(irfLbl){
    irfLbl.textContent=parsed.vendor==='arista'&&parsed.stack?'Arista MLAG':parsed.vendor==='nxos'&&parsed.stack?'Cisco NX-OS VPC':parsed.vendor==='ruijie'&&parsed.stack?'Ruijie VSU':parsed.vendor==='cisco'?tr('nav.irf.cisco'):parsed.vendor==='nxos'?tr('nav.irf.cisco'):parsed.vendor==='comware'?tr('nav.irf.comware'):parsed.vendor==='aruba'?tr('nav.irf.aruba'):parsed.vendor==='procurve'?tr('nav.irf.default'):parsed.vendor==='fortiswitch'?tr('nav.irf.forti'):parsed.vendor==='juniper'&&parsed.stack?.type==='VC'?'Virtual Chassis':parsed.vendor==='alcatel'&&parsed.stack?'Alcatel Stack':parsed.vendor==='extreme'&&parsed.stack?'ExtremeStack':parsed.vendor==='brocade'&&parsed.stack?tr('nav.irf.brocade'):parsed.vendor==='dell-os10'&&parsed.stack?.type==='VLT'?tr('nav.irf.dell_vlt'):parsed.vendor==='dell-os10'&&parsed.stack?tr('nav.irf.dell_stack'):tr('nav.irf.default');
  }
  // Show nav items
  ['lbl-result','nav-overview','nav-irf','nav-vlans','nav-vlan-matrix','nav-ports','nav-lacp','nav-routes','nav-routing','nav-vrrp','nav-vxlan','nav-vrfs','nav-dhcp','nav-users','nav-lldp','nav-stp','nav-acl','nav-security','nav-qos','nav-audit'].forEach(id=>{
    const el=document.getElementById(id);if(el)el.style.display='';
  });
  // LLDP badge
  const ncLldp=document.getElementById('nc-lldp');
  if(ncLldp){const cnt=(parsed?.lldp||[]).length;ncLldp.textContent=cnt;ncLldp.style.display=cnt?'':'none';}
  // STP badge
  const ncStp=document.getElementById('nc-stp');
  if(ncStp){const cnt=(parsed?.stp?.ports||[]).length;ncStp.textContent=cnt;ncStp.style.display=cnt?'':'none';}
  // ACL badge
  const ncAcl=document.getElementById('nc-acl');
  if(ncAcl){const cnt=(parsed?.acls||[]).length;ncAcl.textContent=cnt;ncAcl.style.display=cnt?'':'none';}
  // Security badge
  const ncSec=document.getElementById('nc-security');
  if(ncSec){const cnt=(parsed?.security||[]).length;ncSec.textContent=cnt;ncSec.style.display=cnt?'':'none';}
  // QoS badge
  const ncQos=document.getElementById('nc-qos');
  if(ncQos){const cnt=(parsed?.qos||[]).length;ncQos.textContent=cnt;ncQos.style.display=cnt?'':'none';}
  // Audit badge
  const ncAudit=document.getElementById('nc-audit');
  if(ncAudit){const cnt=analyzeSwitchAudit(parsed).length;ncAudit.textContent=cnt;ncAudit.style.display=cnt?'':'none';}

  document.getElementById('nav-upload').classList.remove('active');
}
function updateCounts(){
  if(!parsed)return;
  const ph=parsed.interfaces.filter(i=>i.type==='physical'||i.type==='stack');
  const stackObj=parsed.stack||(parsed.irf?{members:parsed.irf.members}:null);
  setC('nc-irf',stackObj?stackObj.members.length:0);
  const ospfCount=(parsed.ospf||[]).length;
  const bgpCount=(parsed.bgp||[]).length;
  const ripCount=(parsed.rip||[]).length;
  const vrrpCount=(parsed.vrrp||[]).length;
  setC('nc-dhcp',(parsed.dhcp||[]).length);
  setC('nc-routing',ospfCount+bgpCount+ripCount);
  setC('nc-vrrp',vrrpCount);
  setC('nc-vxlan',parsed.vxlan?.vnis?.length||0);
  setC('nc-vlans',parsed.vlans.length);
  setC('nc-ports',ph.length);
  setC('nc-lacp',(parsed.lacp||[]).length);
  setC('nc-routes',parsed.routes.length);
  setC('nc-vrfs',parsed.vrfs.length);
  setC('nc-users',parsed.users.length);
  const stpPorts=(parsed?.stp?.ports||[]).length;
  const ncStp2=document.getElementById('nc-stp');
  if(ncStp2){ncStp2.textContent=stpPorts;ncStp2.style.display=stpPorts?'':'none';}
  const auditCount=analyzeSwitchAudit(parsed).length;
  const ncAudit=document.getElementById('nc-audit');
  if(ncAudit){ncAudit.textContent=auditCount;ncAudit.style.display=auditCount?'':'none';}
}

// 沿用同一張卡片渲染 Arista MLAG 與 Cisco NX-OS VPC——概念上都是「雙機互聯冗餘」而非物理堆疊，
// 差別只在欄位名稱與內容，依 parsed.stack.type 切換要顯示的卡片組
function renderAristaMlag(){
  const mlag=parsed.stack;
  if(!mlag)return'<div class="nodata">'+tr('msg.no_data')+'</div>';
  const isVpc=mlag.type==='VPC';
  const title=isVpc?'Cisco NX-OS VPC':'Arista MLAG';
  const cards=isVpc?[
    {t:'VPC Domain',v:mlag.domain,c:'var(--accent)',big:true},
    {t:'Peer Link',v:mlag.peerLink,c:'var(--teal)'},
    {t:'Peer Keepalive',v:mlag.peerKeepalive,c:'var(--green)'},
    {t:'Peer Gateway',v:mlag.peerGateway?'Enabled':'Disabled',c:'var(--purple)'},
  ]:[
    {t:'Domain ID',v:mlag.domain,c:'var(--accent)',big:true},
    {t:'Peer Link',v:mlag.peerLink,c:'var(--teal)'},
    {t:'Peer Address',v:mlag.peerAddr,c:'var(--green)'},
    {t:'Local Interface',v:mlag.localIntf,c:'var(--purple)'},
  ];
  return`<div style="padding:16px;display:flex;flex-direction:column;gap:12px">
    <div class="card"><div class="card-head">${title}</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;padding:14px 18px">
        ${cards.map(c=>`<div class="ov-card"><div class="ov-card-title">${c.t}</div><div style="font-size:${c.big?'22':'18'}px;font-weight:${c.big?'700':'600'};color:${c.c}">${esc(String(c.v))}</div></div>`).join('')}
      </div>
    </div>
  </div>`;
}
// Ruijie VSU（Virtual Switch Unit）堆疊——member+priority+role 形狀與 StackWise/VLT 較接近，
// 但目前無真實範例可支撐一套完整拓撲 SVG（如 buildStackWiseSVG／renderDellStack 那樣），
// 先用簡單卡片呈現域資訊＋成員表＋VSL 鏈路埠清單，避免對低信心度功能過度投入
function renderRuijieVSU(){
  const vsu=parsed.stack;
  if(!vsu)return'<div class="nodata">'+tr('msg.no_data')+'</div>';
  const vslMap={};
  (vsu.vsl||[]).forEach(v=>{vslMap[v.memberId]=v.interfaces;});
  return`<div style="padding:16px;display:flex;flex-direction:column;gap:12px">
    <div class="card"><div class="card-head">Ruijie VSU</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;padding:14px 18px">
        <div class="ov-card"><div class="ov-card-title">Domain</div><div style="font-size:22px;font-weight:700;color:var(--accent)">${esc(vsu.domain)}</div></div>
        <div class="ov-card"><div class="ov-card-title">${tr('stack.member_count')}</div><div style="font-size:22px;font-weight:700;color:var(--teal)">${vsu.members.length}</div></div>
      </div>
    </div>
    <div class="card"><div class="card-head">${tr('irf.member_list_card')}</div>
      <table class="data-tbl" style="margin:4px 18px 14px;width:calc(100% - 36px)">
        <tr><th>ID</th><th>${tr('col.priority')}</th><th>${tr('col.role')}</th><th>VSL</th></tr>
        ${vsu.members.map(m=>{
          const roleClass=m.role==='Active'?'p-master':'p-standby';
          const vslPorts=(vslMap[m.id]||[]).join(', ')||'—';
          return`<tr>
            <td>${pill('p-stack','VSU'+m.id)}</td>
            <td class="mono">${m.priority}</td>
            <td>${pill(roleClass,m.role||'—')}</td>
            <td class="mono">${esc(vslPorts)}</td>
          </tr>`;
        }).join('')}
      </table>
    </div>
  </div>`;
}
function renderLACP(){
  const l=parsed.lacp||[];
  if(!l.length)return'<div class="nodata">'+tr('msg.no_lacp')+'</div>';
  function _mb(m){
    const n=typeof m==='string'?m:m.name;
    const lm=typeof m==='object'?m.lacpMode:null;
    const b=lm==='Active'?`<span class="pill p-up" style="font-size:9px;padding:1px 4px;vertical-align:middle;margin-left:2px">${tr('lacp.active')}</span>`:lm==='Passive'?`<span class="pill p-warn" style="font-size:9px;padding:1px 4px;vertical-align:middle;margin-left:2px">${tr('lacp.passive')}</span>`:'';
    return`<span style="white-space:nowrap;margin-right:8px">${esc(n)}${b}</span>`;
  }
  // 修正既有 bug：ProCurve/ArubaOS-Switch 的 parseTrunk() 回傳 members 是逗號/連字號
  // 分隔字串（如 "B5,C4"），非其餘廠牌慣用的陣列形狀（比照 CLAUDE.md 已記載的
  // switch_config_generator 匯入邏輯相容做法），renderLACP() 原本假設 x.members 恆為
  // 陣列，對字串呼叫 .map() 直接拋錯，導致 ProCurve 設備切到 LACP 頁籤整頁崩潰。
  // 同一問題也出現在 exportLACPCSV()／exportHTMLReport()，三處共用 _lacpMembersArr()
  const rows=l.map(x=>{
    const memArr=_lacpMembersArr(x);
    return{
    name:x.name, mode:x.mode||'—', mtu:x.mtu||'—',
    memberCount:memArr.length, members:memArr.map(m=>typeof m==='string'?m:m.name).join(', '),
    name_html:`<span class="mono" style="color:var(--accent3);font-weight:700">${esc(x.name)}</span>`,
    mode_html:`<span class="pill p-info">${esc(x.mode||'—')}</span>`,
    mtu_html:`<span class="mono">${esc(String(x.mtu||'—'))}</span>`,
    memberCount_html:`<span style="color:var(--yellow)">${memArr.length}</span>`,
    members_html:`<div class="mono" style="max-width:420px;white-space:normal">${memArr.map(_mb).join('')}</div>`,
  };});
  const hdrs=[
    {key:'name',  label:tr('lacp.col_name')},
    {key:'mode',  label:tr('lacp.col_mode')},
    {key:'mtu',   label:'MTU'},
    {key:'memberCount',label:tr('lacp.col_members')},
    {key:'members',   label:tr('col.member_port')},
  ];
  tableData=rows; tableKeys=hdrs.map(h=>h.key);
  const {html,count,total}=renderTable(hdrs,rows,null);
  return mkTbar('search-inp',null,'exportLACPCSV')+
    `<div class="tbl-wrap">${html}</div>
     <div class="tbl-foot"><span>${count} / ${total} ${tr('unit.count')}</span></div>`;
}
function setC(id,v){const el=document.getElementById(id);if(el)el.textContent=v;}
function buildSumCards(){
  if(!parsed)return;
  const ph=parsed.interfaces.filter(i=>i.type==='physical'||i.type==='stack');
  const dn=ph.filter(i=>i.shutdown).length;
  const hyb=ph.filter(i=>i.mode==='hybrid').length;
  const ipSubVlans=parsed.vlans.filter(v=>v.ipSubnets.length>0).length;
  document.getElementById('sum-wrap').innerHTML=[
    [parsed.vendor==='arista'&&parsed.stack?'Arista MLAG':parsed.vendor==='nxos'&&parsed.stack?'Cisco NX-OS VPC':parsed.vendor==='ruijie'&&parsed.stack?'Ruijie VSU':parsed.vendor==='cisco'?tr('sl.stack_cisco'):parsed.vendor==='aruba'?tr('sl.stack_aruba'):parsed.vendor==='fortiswitch'?tr('sl.stack_forti'):parsed.vendor==='brocade'?tr('sl.stack_brocade'):parsed.vendor==='dell-os10'&&parsed.stack?.type==='VLT'?tr('sl.vlt_node'):parsed.vendor==='dell-os10'?tr('sl.dell_stack'):tr('sl.irf'),parsed.stack?.members?.length || parsed.irf?.members?.length || 0,'var(--accent)','irf'],
    ['VLAN',parsed.vlans.length,'var(--teal)','vlans'],
    [tr('sl.phy_ports'),ph.length,'var(--text)','ports'],
    [tr('sl.enabled'),ph.length-dn,'var(--green)','ports'],
    [tr('sl.disabled'),dn,'var(--red)','ports'],
    [tr('sl.hybrid_ports'),hyb,'var(--purple)','ports'],
    [tr('sl.static_routes'),parsed.routes.length,'var(--yellow)','routes'],
    ['VRF/VPN',parsed.vrfs.length,'var(--teal)','vrfs'],
    ['VLAN-by-IP',ipSubVlans,'var(--orange)','vlans'],
    [tr('sl.users'),parsed.users.length,'var(--text)','users'],
    ...((parsed.ospf||[]).length?[[ tr('sl.ospf'),(parsed.ospf||[]).length,'var(--green)','routing']]:[]),
    ...((parsed.bgp||[]).length?[['BGP AS',(parsed.bgp||[]).length,'var(--accent3)','routing']]:[]),
    ...((parsed.rip||[]).length?[['RIP/RIPv2',(parsed.rip||[]).length,'var(--yellow)','routing']]:[]),
    ...((parsed.vrrp||[]).length?[['VRRP/HSRP',(parsed.vrrp||[]).length,'var(--orange)','vrrp']]:[]),
    ...(parsed.vxlan?.vnis?.length?[['VXLAN VNI',parsed.vxlan.vnis.length,'var(--purple)','vxlan']]:[]),
    ...((parsed.lacp||[]).length?[['LACP/LAG',(parsed.lacp||[]).length,'var(--accent)','lacp']]:[]),
    ...((parsed.dhcp||[]).length?[['DHCP Pool',(parsed.dhcp||[]).length,'var(--teal)','dhcp']]:[]),
  ].map(([l,v,c,nav])=>{const cl=nav?' clickable':'';const oc=nav?` onclick="navGo('${nav}')"`:'';;return`<div class="sum-card${cl}"${oc}><div class="sl">${l}</div><div class="sv" style="color:${c}">${v}</div></div>`;}).join('');
}
function navGo(view){
  currentView=view;
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  const el=document.getElementById('nav-'+view);if(el)el.classList.add('active');
  sortCol=null;sortDir=1;
  renderView(view);
}
function resetAll(){
  parsed=null;currentView='upload';
  document.getElementById('view-upload').classList.add('show');
  document.getElementById('view-result').style.display='none';
  document.getElementById('tb-actions').style.display='none';
  document.getElementById('tb-meta').textContent='';
  const rtEl=document.getElementById('tb-title');if(rtEl)rtEl.textContent=tr('title');
  document.getElementById('paste-area').value='';
  document.getElementById('file-inp').value='';
  document.getElementById('file-chip').style.display='none';
  document.getElementById('nc-irf').textContent='0';
  const vbE=document.getElementById('tb-vendor');if(vbE)vbE.innerHTML='';
  ['lbl-result','nav-overview','nav-irf','nav-vlans','nav-vlan-matrix','nav-ports','nav-lacp','nav-routes','nav-routing','nav-vrrp','nav-vxlan','nav-vrfs','nav-users','nav-lldp','nav-stp','nav-acl','nav-security','nav-qos','nav-audit'].forEach(id=>{
    const el=document.getElementById(id);if(el)el.style.display='none';
  });
  document.getElementById('nav-upload').classList.add('active');
}
function renderView(view){
  const tc=document.getElementById('tab-content');
  if(view==='upload'){return;}
  if(!parsed){tc.innerHTML='<div class="nodata">'+tr('msg.no_config')+'</div>';return;}
  switch(view){
    case'overview': tc.innerHTML=renderOverview();break;
    case'irf':      tc.innerHTML=parsed.vendor==='cisco'?renderStackWise():parsed.vendor==='aruba'?renderVSF():parsed.vendor==='fortiswitch'?renderMCLAG():parsed.vendor==='juniper'&&parsed.stack?.type==='VC'?renderVC():parsed.vendor==='alcatel'&&parsed.stack?renderAlcatelStack():parsed.vendor==='extreme'&&parsed.stack?renderExtremeStack():parsed.vendor==='brocade'&&parsed.stack?renderBrocadeStack():parsed.vendor==='ruijie'&&parsed.stack?renderRuijieVSU():(parsed.vendor==='arista'||parsed.vendor==='nxos')&&parsed.stack?renderAristaMlag():parsed.vendor==='dell-os10'&&parsed.stack?renderDellStack():renderIRF();break;
    case'routing':  tc.innerHTML=renderRoutingProtocols();break;
    case'vrrp':    tc.innerHTML=renderVRRP();break;
    case'vxlan':   tc.innerHTML=renderVXLAN();break;
    case'dhcp':    tc.innerHTML=renderDHCP();break;
    case'vlans':    tc.innerHTML=renderVLANs();break;
    case'vlan-matrix': tc.innerHTML=renderVLANMatrix();break;
    case'ports':    tc.innerHTML=renderPorts();break;
    case'lacp':     tc.innerHTML=renderLACP();break;
    case'routes':   tc.innerHTML=renderRoutes();break;
    case'vrfs':     tc.innerHTML=renderVRFs();break;
    case'users':    tc.innerHTML=renderUsers();break;
    case'lldp':     tc.innerHTML=renderLLDP();break;
    case'stp':      tc.innerHTML=renderSTP();break;
    case'acl':      tc.innerHTML=renderACL();break;
    case'security': tc.innerHTML=renderSecurity();break;
    case'qos':      tc.innerHTML=renderQoS();break;
    case'audit':    tc.innerHTML=renderAudit();break;
  }
}
function renderOverview(){
  const p=parsed,irf=p.irf,stack=p.stack;
  const ph=p.interfaces.filter(i=>i.type==='physical'||i.type==='stack');
  const svi=p.interfaces.filter(i=>i.type==='svi');
  const stackMembers=(stack?.members||irf?.members||[]);
  const masterMem=stackMembers.find(m=>m.role==='Master'||m.role==='Active'||m.role==='Commander');
  const stackType=stack?stack.type:(irf?'IRF':null);
  let ovCards=`
  <div class="ov-card">
    <div class="ov-card-title">${tr('ov.device_info')}</div>
    <div class="ov-row"><span class="ov-key">${tr('ov.hostname')}</span><span class="ov-val">${esc(p.sys.hostname)}</span></div>
    <div class="ov-row"><span class="ov-key">${tr('col.version')}</span><span class="ov-val">${esc(p.sys.version||'—')}</span></div>
    <div class="ov-row"><span class="ov-key">${tr('ov.stack_type')}</span><span class="ov-val">${stackType?pill('info',stackType+(irf?.domain?' Domain '+irf.domain:'')):'<span style="color:var(--text-muted)">'+tr('ov.standalone')+'</span>'}</span></div>
    ${stackType?`<div class="ov-row"><span class="ov-key">Master/Active</span><span class="ov-val">${masterMem?pill('master','M'+masterMem.id+(masterMem.priority!=null?' prio:'+masterMem.priority:'')):pill('p-gray',tr('rt.auto_sum_none'))}</span></div>`:''}
    <div class="ov-row"><span class="ov-key">OSPF</span><span class="ov-val">${p.ospf.length?pill('info','PID '+p.ospf.map(o=>o.pid).join(',')):'<span style="color:var(--text-muted)">'+tr('ov.not_configured')+'</span>'}</span></div>
    <div class="ov-row"><span class="ov-key">RIP</span><span class="ov-val">${(p.rip||[]).length?pill('route',(p.rip||[]).map(r=>(r.version==='2'?'RIPv2':'RIP')+' '+r.pid).join(',')):'<span style="color:var(--text-muted)">'+tr('ov.not_configured')+'</span>'}</span></div>
  </div>
  <div class="ov-card">
    <div class="ov-card-title">${tr('ov.vlan_summary')}</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;padding-top:4px">
    ${p.vlans.slice(0,30).map(v=>`<span class="pill p-vlan">V${v.id}${v.name?' '+v.name:''}</span>`).join('')}
    ${p.vlans.length>30?`<span style="color:var(--text-muted);font-size:10px">+${p.vlans.length-30}...</span>`:''}
    </div>
  </div>
  <div class="ov-card">
    <div class="ov-card-title">${tr('ov.if_summary')}</div>
    <div class="ov-row"><span class="ov-key">${tr('sl.phy_ports')}</span><span class="ov-val">${ph.length}</span></div>
    <div class="ov-row"><span class="ov-key">Trunk</span><span class="ov-val">${ph.filter(i=>i.mode==='trunk').length}</span></div>
    <div class="ov-row"><span class="ov-key">Access</span><span class="ov-val">${ph.filter(i=>i.mode==='access').length}</span></div>
    <div class="ov-row"><span class="ov-key">Hybrid</span><span class="ov-val">${ph.filter(i=>i.mode==='hybrid').length}</span></div>
    <div class="ov-row"><span class="ov-key">L3 SVI</span><span class="ov-val">${svi.length}</span></div>
    <div class="ov-row"><span class="ov-key">${tr('sl.disabled')}</span><span class="ov-val" style="color:var(--red)">${ph.filter(i=>i.shutdown).length}</span></div>
  </div>
  <div class="ov-card">
    <div class="ov-card-title">${tr('ov.route_summary')}</div>
    <div class="ov-row"><span class="ov-key">${tr('sl.static_routes')}</span><span class="ov-val">${p.routes.length}</span></div>
    <div class="ov-row"><span class="ov-key">${tr('filter.default_route')}</span><span class="ov-val">${p.routes.filter(r=>r.dst==='0.0.0.0/0'&&!r.vrf).map(r=>pill('route',r.gw)).join(' ')||'—'}</span></div>
    <div class="ov-row"><span class="ov-key">${tr('filter.vrf_routes')}</span><span class="ov-val">${p.routes.filter(r=>r.vrf).length}</span></div>
    <div class="ov-row"><span class="ov-key">VRF/VPN</span><span class="ov-val">${p.vrfs.map(v=>pill('vrf',v.name)).join(' ')||'—'}</span></div>
  </div>`;
  // VLAN-by-IP summary
  const ipVlans=p.vlans.filter(v=>v.ipSubnets.length>0);
  if(ipVlans.length){
    // 若有長名稱或多 IP 則自動佔兩欄
    const needsWide=ipVlans.some(v=>(v.name||'').length>15||v.ipSubnets.length>1);
    ovCards+=`<div class="ov-card"${needsWide?' style="grid-column:span 2"':''}>
      <div class="ov-card-title">🌐 VLAN-by-IP (ip-subnet-vlan)</div>
      ${ipVlans.map(v=>{const label='VLAN '+v.id+(v.name?' '+v.name:'');return`<div class="ov-row" style="min-width:0">
        <span class="ov-key" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(label)}">${esc(label)}</span>
        <span class="ov-val" style="flex-shrink:0;flex:none;word-break:normal;margin-left:8px">${v.ipSubnets.map(s=>pill('ip',s.cidr)).join(' ')}</span>
      </div>`;}).join('')}
    </div>`;
  }
  // VLT summary
  if(p.vlt){
    const vlt=p.vlt;
    const vltLagCount=(vlt.vltLags||[]).length;
    ovCards+=`<div class="ov-card">
      <div class="ov-card-title">${tr('ov.vlt_topo')}</div>
      <div class="ov-row"><span class="ov-key">Domain ID</span><span class="ov-val mono" style="color:var(--accent)">${esc(vlt.domainId)}</span></div>
      <div class="ov-row"><span class="ov-key">${tr('ov.vlt_priority')}</span><span class="ov-val mono">${esc(vlt.priority||'—')}</span></div>
      <div class="ov-row"><span class="ov-key">${tr('ov.vlt_backup_dest')}</span><span class="ov-val mono">${esc(vlt.backupDest||'—')}</span></div>
      <div class="ov-row"><span class="ov-key">Virtual MAC</span><span class="ov-val mono">${esc(vlt.mac||'—')}</span></div>
      <div class="ov-row"><span class="ov-key">Peer Routing</span><span class="ov-val">${vlt.peerRouting?pill('p-up',tr('rt.auto_sum_on')):pill('p-gray',tr('rt.auto_sum_off'))}</span></div>
      <div class="ov-row"><span class="ov-key">${tr('ov.vlt_lag_count')}</span><span class="ov-val" style="color:var(--teal)">${vltLagCount}</span></div>
      ${(vlt.vltLags||[]).slice(0,4).map(l=>`<div class="ov-row"><span class="ov-key mono" style="font-size:11px">${esc(l.pcId)}</span><span class="ov-val">${pill('p-info',l.mode)} ${esc(l.vlans||'—')}</span></div>`).join('')}
    </div>`;
  }
  // VRRP/HSRP summary from dedicated parser
  const vrrpGroups=p.vrrp||[];
  if(vrrpGroups.length){
    const proto=p.vendor==='cisco'?'HSRP':'VRRP';
    ovCards+=`<div class="ov-card">
      <div class="ov-card-title">🔄 ${proto} ${tr('ov.groups')}（${vrrpGroups.length}）</div>
      ${vrrpGroups.slice(0,8).map(g=>`<div class="ov-row">
        <span class="ov-key">${pill('p-stack',proto+' '+g.vrid)}</span>
        <span class="ov-val"><span class="mono" style="font-size:11px">${esc(g.interface.replace('Vlan-interface','VLAN'))}</span> ${g.vip?pill('p-route','VIP '+g.vip):''} ${pill('p-info','prio '+g.priority)}</span>
      </div>`).join('')}
      ${vrrpGroups.length>8?`<div class="ov-row"><span style="color:var(--text-muted);font-size:11px">+ ${vrrpGroups.length-8} ${tr('ov.n_more_groups')}...</span></div>`:''}
    </div>`;
  }
  // VXLAN summary
  if(p.vxlan?.vnis?.length){
    ovCards+=`<div class="ov-card">
      <div class="ov-card-title">🌐 VXLAN / Overlay</div>
      <div class="ov-row"><span class="ov-key">${tr('ov.vtep_src')}</span><span class="ov-val mono">${esc(p.vxlan.vtep||'—')}</span></div>
      <div class="ov-row"><span class="ov-key">${tr('ov.vni_count')}</span><span class="ov-val" style="color:var(--purple)">${p.vxlan.vnis.length}</span></div>
      ${p.vxlan.vnis.some(v=>v.mode==='BGP-EVPN')?`<div class="ov-row"><span class="ov-key">${tr('ov.fwd_mode')}</span><span class="ov-val">${pill('p-info','BGP-EVPN')}</span></div>`:''}
      ${p.vxlan.evpn?.length?`<div class="ov-row"><span class="ov-key">${tr('ov.evpn_instances')}</span><span class="ov-val">${p.vxlan.evpn.length}</span></div>`:''}
      <div class="ov-row" style="flex-wrap:wrap;gap:3px">${p.vxlan.vnis.slice(0,8).map(v=>`${pill('p-vlan','VNI '+v.vni+(v.vlan?' →V'+v.vlan:'')+(v.name?' '+v.name.substring(0,10):''))}`).join(' ')}</div>
    </div>`;
  }
  return `<div class="ov-grid">${ovCards}</div>`;
}
function renderBrocadeStack(){
  const stk=parsed.stack;
  if(!stk)return'<div class="nodata">'+tr('msg.no_stack')+'</div>';
  const members=stk.members||[];
  const links=stk.links||[];
  // Build simple SVG topology
  const tc='#f87171';
  const boxW=160,boxH=130,gap=Math.max(210,760/(members.length||1));
  const W=Math.max(760,members.length*gap+100);
  const H=300;
  const startX=Math.max(28,(W-gap*(members.length-1)-boxW)/2);
  const bY=80;
  const boxes=members.map((m,i)=>({x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m}));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif">
<defs>
<marker id="arr2" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="glow2"><feGaussianBlur stdDeviation="2.8" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<linearGradient id="hg2" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="${tc}" stop-opacity=".18"/><stop offset="100%" stop-color="#7f1d1d" stop-opacity=".04"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<rect x="0" y="0" width="${W}" height="50" fill="url(#hg2)" rx="12"/>
<rect x="0" y="38" width="${W}" height="12" fill="#080c17"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">ICX STACK TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(parsed.sys.hostname)}</text>
<rect x="${W-148}" y="11" width="136" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-80}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">Brocade ICX Stack</text>`;
  // Draw stack links
  for(let i=0;i<boxes.length-1;i++){
    const a=boxes[i],b=boxes[i+1];
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".62" marker-end="url(#arr2)" filter="url(#glow2)"/>`;
    const lnk=links[i];
    if(lnk?.ports?.length){
      svg+=`<text x="${(a.cx+b.cx)/2}" y="${a.y+boxH+46}" font-size="9" fill="${tc}" text-anchor="middle" opacity=".7" font-family="JetBrains Mono,monospace">${esc(lnk.ports.slice(0,2).join(' ↔ '))}</text>`;
    }
  }
  // Draw member boxes
  for(const bx of boxes){
    const m=bx.mem;
    const roleColor=m.role==='Active'?'#00c8f0':m.role==='Standby'?'#10b981':'#94a3b8';
    const isActive=m.role==='Active';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isActive?tc:'#1e3a5f'}" stroke-width="${isActive?2:1}" ${isActive?'filter="url(#glow2)"':''}/>`;
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="32" rx="10" fill="${tc}" opacity="${isActive?.22:.1}"/>`;
    svg+=`<rect x="${bx.x}" y="${bx.y+22}" width="${boxW}" height="10" fill="#0f1629"/>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+21}" font-size="13" fill="${isActive?tc:'#dde8f5'}" font-weight="700" text-anchor="middle">Unit ${m.id}</text>`;
    svg+=`<rect x="${bx.cx-30}" y="${bx.y+38}" width="60" height="18" rx="5" fill="${roleColor}" opacity=".18" stroke="${roleColor}" stroke-width="1"/>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+51}" font-size="10" fill="${roleColor}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">${m.role||'Member'}</text>`;
    if(m.model&&m.model!=='—')svg+=`<text x="${bx.cx}" y="${bx.y+78}" font-size="10" fill="#94a3b8" text-anchor="middle">${esc(m.model)}</text>`;
    if(m.priority>0)svg+=`<text x="${bx.cx}" y="${bx.y+98}" font-size="10" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">prio: ${m.priority}</text>`;
  }
  svg+=`</svg>`;

  return`<div style="flex:1;overflow-y:auto">
    <div class="topo-wrap">${svg}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 18px 14px">
      <div class="ov-card">
        <div class="ov-card-title">📦 ${tr('stack.icx_cfg')}</div>
        <div class="ov-row"><span class="ov-key">${tr('stack.member_count')}</span><span class="ov-val">${members.length}</span></div>
        <div class="ov-row"><span class="ov-key">${tr('stack.link_count')}</span><span class="ov-val">${links.length}</span></div>
        <div class="ov-row"><span class="ov-key">Active Unit</span><span class="ov-val">${members.find(m=>m.role==='Active')?pill('p-master','Unit '+members.find(m=>m.role==='Active').id):pill('p-gray',tr('stack.not_detected'))}</span></div>
      </div>
      <div class="ov-card">
        <div class="ov-card-title">🔗 ${tr('stack.port_links')}</div>
        ${links.length?links.map(l=>`<div class="ov-row"><span class="ov-key">${tr('stack.link_line')} ${l.id}</span><span class="ov-val mono" style="font-size:10px;text-align:right">${esc(l.ports.join(' ↔ '))}</span></div>`).join(''):`<div style="color:var(--text-muted);font-size:11px">${tr('stack.no_port_cfg')}</div>`}
      </div>
    </div>
    <div style="padding:0 18px 14px">
      <div class="ov-card">
        <div class="ov-card-title">👥 ${tr('stack.member_list')}</div>
        <table class="data-tbl" style="margin-top:4px">
          <tr><th>${tr('col.unit_id')}</th><th>${tr('col.priority')}</th><th>${tr('col.role')}</th><th>${tr('col.model')}</th></tr>
          ${members.map(m=>`<tr>
            <td>${pill('p-stack','Unit '+m.id)}</td>
            <td class="mono" style="color:var(--yellow)">${m.priority||'—'}</td>
            <td>${m.role==='Active'?pill('p-master','Active'):m.role==='Standby'?pill('p-standby','Standby'):pill('p-gray',m.role||'Member')}</td>
            <td class="mono">${esc(m.model||'—')}</td>
          </tr>`).join('')}
        </table>
      </div>
    </div>
  </div>`;
}
function renderDellStack(){
  const stk=parsed.stack;
  if(!stk)return`<div class="nodata">${tr('stack.no_dell_stack')}</div>`;
  const isVLT=stk.type==='VLT';
  const members=stk.members||[];
  const tc='#0078d4';
  const boxW=160,boxH=130,gap=Math.max(220,700/(Math.max(members.length,1)));
  const W=Math.max(700,members.length*gap+120);
  const H=300;
  const startX=Math.max(30,(W-gap*(members.length-1)-boxW)/2);
  const bY=80;
  const boxes=members.map((m,i)=>({x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m}));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif">
<defs>
<marker id="arrd" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="glowd"><feGaussianBlur stdDeviation="2.8" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<linearGradient id="hgd" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="${tc}" stop-opacity=".18"/><stop offset="100%" stop-color="#001f3f" stop-opacity=".04"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<rect x="0" y="0" width="${W}" height="50" fill="url(#hgd)" rx="12"/>
<rect x="0" y="38" width="${W}" height="12" fill="#080c17"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">${isVLT?'VLT TOPOLOGY'+tr('stack.topo_sub'):'DELL STACK TOPOLOGY'+tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(parsed.sys.hostname)}</text>
<rect x="${W-160}" y="11" width="148" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-86}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">${isVLT?'Dell VLT':'Dell OS9 Stack'}</text>`;
  for(let i=0;i<boxes.length-1;i++){
    const a=boxes[i],b=boxes[i+1];
    const label=isVLT?`VLT Peer-Link${stk.peerLink?' ('+stk.peerLink+')':''}`:`Stack Link`;
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".62" marker-end="url(#arrd)" filter="url(#glowd)"/>`;
    svg+=`<text x="${(a.cx+b.cx)/2}" y="${a.y+boxH+46}" font-size="9" fill="${tc}" text-anchor="middle" opacity=".7" font-family="JetBrains Mono,monospace">${esc(label)}</text>`;
  }
  for(const bx of boxes){
    const m=bx.mem;
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${tc}" stroke-width="1.5" filter="url(#glowd)"/>`;
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="32" rx="10" fill="${tc}" opacity=".18"/>`;
    svg+=`<rect x="${bx.x}" y="${bx.y+22}" width="${boxW}" height="10" fill="#0f1629"/>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+21}" font-size="13" fill="${tc}" font-weight="700" text-anchor="middle">${isVLT?'Unit-'+m.id:'Unit '+m.id}</text>`;
    if(m.priority)svg+=`<text x="${bx.cx}" y="${bx.y+55}" font-size="10" fill="#94a3b8" text-anchor="middle" font-family="JetBrains Mono,monospace">Priority: ${m.priority}</text>`;
    if(m.model)svg+=`<text x="${bx.cx}" y="${bx.y+75}" font-size="10" fill="#64748b" text-anchor="middle">${esc(m.model)}</text>`;
  }
  svg+=`</svg>`;
  return`<div style="flex:1;overflow-y:auto">
    <div class="topo-wrap">${svg}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 18px 14px">
      <div class="ov-card">
        <div class="ov-card-title">📦 ${isVLT?tr('ds.vlt_cfg'):tr('ds.stack_cfg')}</div>
        <div class="ov-row"><span class="ov-key">${tr('col.type')}</span><span class="ov-val">${pill('p-master',isVLT?'VLT':'Traditional Stack')}</span></div>
        <div class="ov-row"><span class="ov-key">Domain</span><span class="ov-val mono">${stk.domain||'—'}</span></div>
        ${isVLT?`<div class="ov-row"><span class="ov-key">Peer-Link</span><span class="ov-val mono">${esc(stk.peerLink||'—')}</span></div>`:''}
        <div class="ov-row"><span class="ov-key">${tr('stack.member_count')}</span><span class="ov-val">${members.length}</span></div>
      </div>
      <div class="ov-card">
        <div class="ov-card-title">👥 ${tr('stack.member_list')}</div>
        ${members.map(m=>`<div class="ov-row"><span class="ov-key">Unit ${m.id}</span><span class="ov-val mono" style="font-size:10px">${m.priority?'prio: '+m.priority:''}${m.model?' · '+esc(m.model):''}</span></div>`).join('')}
      </div>
    </div>
  </div>`;
}
function renderIRF(){
  const irf=parsed.irf;
  if(!irf)return `<div class="nodata">${tr('msg.no_irf')}<br><span style="font-size:11px;color:var(--text-muted)">${tr('msg.no_irf_hint')}</span></div>`;
  const svg=buildTopoSVG(parsed);
  let html=`<div style="flex:1;overflow-y:auto">
    <div class="export-row"><button class="btn btn-ghost btn-sm" onclick="exportTopoSVG()">⬇ ${tr('irf.export_svg')}</button></div>
    <div class="topo-wrap">${svg}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 18px 14px">
      <div class="ov-card">
        <div class="ov-card-title">⚡ ${tr('stack.irf_cfg')}</div>
        <div class="ov-row"><span class="ov-key">Domain</span><span class="ov-val">${irf.domain}</span></div>
        <div class="ov-row"><span class="ov-key">${tr('stack.member_count')}</span><span class="ov-val">${irf.members.length}</span></div>
        <div class="ov-row"><span class="ov-key">${tr('stack.irf_port_links')}</span><span class="ov-val">${irf.links.length}</span></div>
        <div class="ov-row"><span class="ov-key">${tr('stack.auto_update')}</span><span class="ov-val">${irf.autoUpdate?pill('p-up',tr('rt.auto_sum_on')):pill('p-down',tr('rt.auto_sum_off'))}</span></div>
        <div class="ov-row"><span class="ov-key">${tr('irf.mac_persist')}</span><span class="ov-val">${irf.macPersist?pill('p-up',tr('rt.auto_sum_on')):pill('p-down',tr('rt.auto_sum_off'))}</span></div>
      </div>
      <div class="ov-card">
        <div class="ov-card-title">${tr('irf.port_links_card')}</div>
        ${irf.links.map(l=>`<div class="ov-row"><span class="ov-key">Port ${l.id}</span><span class="ov-val mono" style="text-align:right">${l.shortPorts.join(', ')}</span></div>`).join('')}
      </div>
    </div>
    <div style="padding:0 18px 14px">
      <div class="ov-card">
        <div class="ov-card-title">${tr('irf.member_list_card')}</div>
        <table class="data-tbl" style="margin-top:4px">
          <tr><th>${tr('col.member_id')}</th><th>${tr('col.priority')}</th><th>${tr('col.role')}</th><th>${tr('col.port_count')}</th><th>${tr('col.irf_port')}</th></tr>
          ${irf.members.map(m=>{
            const pcount=parsed.interfaces.filter(i=>i.member===m.id&&i.type==='physical').length;
            const iLinks=irf.links.filter(l=>l.fromMember===m.id);
            return`<tr>
              <td>${pill('p-stack','M'+m.id)}</td>
              <td class="mono" style="color:var(--yellow)">${m.priority}</td>
              <td>${m.role==='Master'?pill('p-master','Master'):pill('p-standby','Standby')}</td>
              <td class="mono">${pcount}</td>
              <td>${iLinks.map(l=>l.shortPorts.join(', ')).join(' | ')||'—'}</td>
            </tr>`;
          }).join('')}
        </table>
      </div>
    </div>
  </div>`;
  return html;
}
function buildTopoSVG(p){
  const irf=p.irf;
  const mems=irf?irf.members:[{id:'1',priority:0,role:'Master'}];
  const tc='#00c8f0';
  const boxW=158,boxH=196,gap=Math.max(205,720/(mems.length||1));
  const W=Math.max(720,mems.length*gap+100);
  const H=420;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2);
  const bY=106;
  const boxes=mems.map((m,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m,
    ports:p.interfaces.filter(ii=>ii.member===m.id&&ii.type==='physical').length,
    stPorts:p.interfaces.filter(ii=>ii.member===m.id&&ii.type==='stack'),
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif">
<defs>
<marker id="arr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="glow"><feGaussianBlur stdDeviation="2.8" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<filter id="glows"><feGaussianBlur stdDeviation="1.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<linearGradient id="hg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="${tc}" stop-opacity=".18"/><stop offset="100%" stop-color="#0080ff" stop-opacity=".04"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<rect x="0" y="0" width="${W}" height="50" fill="url(#hg)" rx="12"/>
<rect x="0" y="38" width="${W}" height="12" fill="#080c17"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">IRF STACK TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-120}" y="11" width="108" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-66}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">IRF · Domain ${irf?.domain||'—'}</text>`;

  // Draw links
  const isRing=mems.length>2;
  for(let i=0;i<mems.length;i++){
    if(i===mems.length-1&&!isRing)break;
    const a=boxes[i],b=boxes[(i+1)%mems.length];
    const lnk=irf?.links.find(l=>l.fromMember===a.mem.id)||(irf?.links.find(l=>l.fromMember===b.mem.id))||{ports:[],shortPorts:[]};
    const linkLabel=(lnk.shortPorts||[]).slice(0,2).join(' | ');
    if(i===mems.length-1){
      svg+=`<path d="M ${a.cx} ${a.y+boxH+8} C ${a.cx} ${a.y+boxH+82} ${b.cx} ${b.y+boxH+82} ${b.cx} ${b.y+boxH+8}" stroke="${tc}" stroke-width="2" fill="none" opacity=".38" stroke-dasharray="5,3" marker-end="url(#arr)"/>`;
      svg+=`<text x="${(a.cx+b.cx)/2}" y="${a.y+boxH+68}" font-size="9" fill="${tc}" text-anchor="middle" opacity=".55" font-family="JetBrains Mono,monospace">Ring</text>`;
    }else{
      svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+54} ${b.cx} ${b.y+boxH+54} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".62" marker-end="url(#arr)" filter="url(#glows)"/>`;
      if(linkLabel){const mx=(a.cx+b.cx)/2,my=a.y+boxH+45;svg+=`<rect x="${mx-52}" y="${my-11}" width="104" height="17" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".9"/><text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${esc(linkLabel)}</text>`;}
    }
  }

  // Draw boxes
  boxes.forEach((bx,i)=>{
    const m=bx.mem,isMaster=(m.role==='Master')||(i===0&&!m.role);
    const prio=m.priority||'—';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#1e3a5f'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#glow)"':''}/>`;
    if(isMaster)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".03"/>`;
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.18:.07}" stroke="${tc}" stroke-width=".5"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#64748b'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">M${m.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#2c3e58'}" text-anchor="end" font-weight="600">${esc(m.role||'')}</text>`;
    // Port slots
    svg+=`<rect x="${bx.x+12}" y="${bx.y+40}" width="${boxW-24}" height="48" rx="6" fill="#080c17" stroke="#1e3a5f" stroke-width="1"/>`;
    const pc=Math.min(bx.ports,16);
    for(let pi=0;pi<pc;pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+46+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.42:.2}"/>`;}
    if(bx.ports>16)svg+=`<text x="${bx.cx}" y="${bx.y+85}" font-size="8.5" fill="#2c3e58" text-anchor="middle" font-family="JetBrains Mono,monospace">+${bx.ports-16}</text>`;
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+97}" x2="${bx.x+boxW-12}" y2="${bx.y+97}" stroke="#1e3a5f" stroke-width=".5"/>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+112}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('svg.port_count')}</text><text x="${bx.x+boxW-16}" y="${bx.y+112}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports}</text>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+129}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text><text x="${bx.x+boxW-16}" y="${bx.y+129}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${esc(String(prio))}</text>`;
    // Trunk uplink indicator
    const tpCount=p.interfaces.filter(ii=>ii.member===m.id&&ii.mode==='trunk').length;
    if(tpCount){svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-26}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/>
    <polygon points="${bx.cx},${bx.y-30} ${bx.cx-5},${bx.y-22} ${bx.cx+5},${bx.y-22}" fill="${tc}" opacity=".5"/>
    <text x="${bx.cx}" y="${bx.y-35}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Trunk×${tpCount}</text>`;}
    // IRF port footer
    if(bx.stPorts&&bx.stPorts.length){const sn=bx.stPorts.map(pp=>pp.name.replace(/^(?:Ten-?GigabitEthernet|FortyGigE|HundredGigE)/i,'')).slice(0,2).join(' | ');svg+=`<text x="${bx.cx}" y="${bx.y+boxH-10}" font-size="8.5" fill="${tc}" text-anchor="middle" opacity=".65" font-family="JetBrains Mono,monospace">${esc(sn)}</text>`;}
  });

  // Legend
  const lY=H-40;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="32" rx="5" fill="#0f1629" stroke="#1e3a5f" stroke-width=".5"/>
  <rect x="24" y="${lY+9}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+18}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Master</text>
  <rect x="108" y="${lY+9}" width="10" height="10" rx="2" fill="#1e3a5f"/>
  <text x="124" y="${lY+18}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby</text>
  <line x1="196" y1="${lY+14}" x2="218" y2="${lY+14}" stroke="${tc}" stroke-width="2"/>
  <text x="224" y="${lY+18}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">${tr('svg.irf_link')}</text>
  <line x1="295" y1="${lY+14}" x2="317" y2="${lY+14}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/>
  <text x="323" y="${lY+18}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">${tr('svg.trunk_uplink')}</text>
  <text x="${W-18}" y="${lY+20}" font-size="9" fill="#2c3e58" text-anchor="end" font-family="JetBrains Mono,monospace">HPE Comware Analyzer</text>`;
  svg+=`</svg>`;
  return svg;
}
function buildTable(containerId,headers,rows,filterFn){
  tableData=rows; tableKeys=headers.map(h=>h.key);
  const tc=document.getElementById(containerId)||document.getElementById('tab-content');
  return renderTable(headers,rows,filterFn);
}
function renderTable(headers,rows,filterFn){
  const search=document.getElementById('search-inp')?.value?.toLowerCase()||'';
  let filtered=rows.filter(r=>{
    if(!search)return true;
    return headers.some(h=>String(r[h.key]||'').toLowerCase().includes(search));
  });
  if(filterFn)filtered=filtered.filter(filterFn);
  if(sortCol!==null){
    const key=tableKeys[sortCol];
    filtered=filtered.slice().sort((a,b)=>{
      const va=String(a[key]||''),vb=String(b[key]||'');
      return sortDir*(va.localeCompare(vb,undefined,{numeric:true}));
    });
  }
  const thRow=headers.map((h,i)=>{
    let cls='';
    if(sortCol===i)cls=sortDir===1?' sort-asc':' sort-desc';
    return`<th class="${cls}" onclick="doSort(${i},'${h.key}')">${h.label}</th>`;
  }).join('');
  const bodyRows=filtered.map(r=>`<tr>${headers.map(h=>`<td>${r[h.key+'_html']||esc(String(r[h.key]??''))}</td>`).join('')}</tr>`).join('');
  return{html:`<table class="data-tbl"><thead><tr>${thRow}</tr></thead><tbody>${bodyRows||'<tr><td colspan="'+headers.length+'" class="nodata">'+tr('tbl.no_match')+'</td></tr>'}</tbody></table>`,count:filtered.length,total:rows.length};
}
function doSort(idx,key){
  if(sortCol===idx)sortDir*=-1;else{sortCol=idx;sortDir=1;}
  renderView(currentView);
}
function mkTbar(searchId,filters,exportFn){
  const fOpts=filters?`<select class="filter-sel" id="filter-sel" onchange="renderView(currentView)">${filters.map(f=>`<option value="${f.v}">${f.l}</option>`).join('')}</select>`:'';
  return`<div class="tbar">
    <div class="search-wrap"><span class="search-ico">🔍</span><input class="search-inp" id="search-inp" placeholder="${tr('search.placeholder')}" oninput="onSearchInput()"></div>
    ${fOpts}
    <div class="tbar-right">
      ${exportFn?`<button class="btn btn-ghost btn-sm" onclick="${exportFn}()">${tr('btn.export')}</button>`:''}
    </div>
  </div>`;
}

function _abbrevPort(name){
  return name
    .replace(/^(\d+)\/1\/(\d+)$/,'$1/$2')  // Aruba VSF M/1/P → M/P
    .replace(/Ten-GigabitEthernet/ig,'XGE')
    .replace(/TenGigabitEthernet/ig,'XGE')
    .replace(/FortyGigabitEthernet/ig,'XLG')
    .replace(/HundredGigabitEthernet/ig,'HGE')
    .replace(/TwentyFiveGigE/ig,'XXE')
    .replace(/GigabitEthernet/ig,'GE')
    .replace(/FastEthernet/ig,'FE')
    .replace(/Ethernet/ig,'Eth')
    .replace(/management/ig,'Mgmt')
    .replace(/Eth-Trunk/ig,'Trunk')
    .replace(/Port-Channel/ig,'PO')
    .replace(/port-channel/ig,'PO');
}
function _expandVids(str){
  if(!str)return[];
  const ids=[];
  for(const tok of str.replace(/\s+to\s+/gi,'-').split(/[,\s]+/)){
    if(tok.includes('-')){const[a,b]=tok.split('-').map(Number);if(!isNaN(a)&&!isNaN(b))for(let i=a;i<=b;i++)ids.push(String(i));}
    else if(/^\d+$/.test(tok))ids.push(tok);
  }
  return ids;
}
function renderVLANMatrix(){
  const vlans=parsed.vlans;
  if(!vlans||!vlans.length)return`<div class="nodata">${tr('vlan_m.none')}</div>`;
  // Build VLAN→port mapping from interfaces
  const vp={};// vlanId→{tagged:[],untagged:[]}
  function addT(vid,name){if(!vp[vid])vp[vid]={tagged:[],untagged:[]};if(!vp[vid].tagged.includes(name))vp[vid].tagged.push(name);}
  function addU(vid,name){if(!vp[vid])vp[vid]={tagged:[],untagged:[]};if(!vp[vid].untagged.includes(name))vp[vid].untagged.push(name);}
  for(const iface of parsed.interfaces){
    if(iface.type==='null'||iface.type==='loopback'||iface.type==='svi')continue;
    const nm=iface.name;
    if(iface.mode==='trunk'){
      if(iface.vlans==='all') parsed.vlans.forEach(v=>addT(v.id,nm));
      else _expandVids(iface.vlans).forEach(v=>addT(v,nm));
      if(iface.nativeVlan)addU(iface.nativeVlan,nm);
    } else if(iface.mode==='access'){
      const vid=iface.nativeVlan||_expandVids(iface.vlans)[0];
      if(vid)addU(vid,nm);
    } else if(iface.mode==='hybrid'&&iface.hybrid){
      (iface.hybrid.tagged||[]).forEach(v=>addT(v,nm));
      (iface.hybrid.untagged||[]).forEach(v=>addU(v,nm));
      if(iface.hybrid.pvid)addU(iface.hybrid.pvid,nm);
    } else if(iface.vlans){
      _expandVids(iface.vlans).forEach(v=>addT(v,nm));
    }
  }
  // 效能優化：後續大量 port 查找改用 Set（O(1)）而非陣列 .includes()（O(n)），
  // 原陣列保留供 .length／.forEach 等既有用法，Set 僅額外附加
  for(const vid in vp){vp[vid].taggedSet=new Set(vp[vid].tagged);vp[vid].untaggedSet=new Set(vp[vid].untagged);}
  const activeVlans=vlans.filter(v=>vp[v.id]&&(vp[v.id].tagged.length||vp[v.id].untagged.length));
  if(!activeVlans.length)return`<div class="nodata">${tr('vlan_m.none')}</div>`;
  const allPorts=new Set();
  activeVlans.forEach(v=>{(vp[v.id].tagged||[]).forEach(p=>allPorts.add(p));(vp[v.id].untagged||[]).forEach(p=>allPorts.add(p));});
  const portList=[...allPorts].sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
  // 找出同時有 T 也有 U 的 port（= hybrid behavior port）
  const _pT=new Set(),_pU=new Set();
  for(const vid in vp){vp[vid].tagged.forEach(p=>_pT.add(p));vp[vid].untagged.forEach(p=>_pU.add(p));}
  const hybridPorts=new Set([..._pT].filter(p=>_pU.has(p)));
  const q=(document.getElementById('search-inp')?.value||'').toLowerCase();
  const fVlans=activeVlans.filter(v=>!q||v.id.includes(q)||(v.name||'').toLowerCase().includes(q)||portList.some(p=>p.toLowerCase().includes(q)&&(vp[v.id].taggedSet.has(p)||vp[v.id].untaggedSet.has(p))));
  const fPorts=q?portList.filter(p=>p.toLowerCase().includes(q)||fVlans.some(v=>vp[v.id].taggedSet.has(p)||vp[v.id].untaggedSet.has(p))):portList;
  let th=`<tr><th style="position:sticky;left:0;z-index:3;background:var(--bg-head);width:56px;min-width:56px">VLAN</th><th style="position:sticky;left:56px;z-index:3;background:var(--bg-head);white-space:nowrap;width:130px;min-width:130px">${tr('col.vlan_name')}</th>`;
  for(const p of fPorts){const ab=_abbrevPort(p);const lbl=esc(ab.length>10?ab.substring(0,9)+'…':ab);th+=`<th style="width:24px;min-width:24px;max-width:24px;padding:0;height:80px;vertical-align:bottom;box-sizing:border-box;overflow:hidden" title="${esc(p)}"><div style="width:24px;height:80px;overflow:hidden;display:flex;align-items:flex-end;justify-content:center;padding-bottom:2px"><span style="writing-mode:vertical-rl;text-orientation:mixed;white-space:nowrap;font-size:9px;line-height:1.2;display:block">${lbl}</span></div></th>`;}
  th+='</tr>';
  let tbody='';
  for(const v of fVlans){
    const pm=vp[v.id]||{tagged:[],untagged:[],taggedSet:new Set(),untaggedSet:new Set()};
    let row=`<tr><td style="position:sticky;left:0;z-index:1;background:var(--bg2)"><span class="pill p-vlan">V${v.id}</span></td><td style="position:sticky;left:56px;z-index:1;background:var(--bg2);white-space:nowrap;font-size:12px">${esc(v.name||'—')}</td>`;
    for(const p of fPorts){
      const isT=pm.taggedSet.has(p),isU=pm.untaggedSet.has(p);
      const isH=hybridPorts.has(p);
      if(isT&&isU)row+=`<td style="text-align:center;padding:2px"><span class="pill p-hybrid" style="font-size:10px;padding:1px 5px;cursor:default" title="${esc(p)} Tagged+Untagged">H</span></td>`;
      else if(isT)row+=`<td style="text-align:center;padding:2px"><span class="pill p-trunk" style="font-size:10px;padding:1px 5px;cursor:default" title="${esc(p)} Tagged">T</span></td>`;
      else if(isU&&isH)row+=`<td style="text-align:center;padding:2px"><span class="pill p-hybrid" style="font-size:10px;padding:1px 5px;cursor:default" title="${esc(p)} Untagged (Hybrid port)">H</span></td>`;
      else if(isU)row+=`<td style="text-align:center;padding:2px"><span class="pill p-access" style="font-size:10px;padding:1px 5px;cursor:default" title="${esc(p)} Untagged">U</span></td>`;
      else row+=`<td style="text-align:center;color:var(--text-muted);font-size:10px">·</td>`;
    }
    row+='</tr>';
    tbody+=row;
  }
  return`<div class="tbar"><div class="search-wrap"><span class="search-ico">🔍</span><input class="search-inp" id="search-inp" placeholder="${tr('vlan_m.search')}" oninput="debouncedRenderView('vlan-matrix')"></div>`
    +`<span style="font-size:11px;color:var(--text-muted);white-space:nowrap"><span class="pill p-trunk" style="font-size:10px">T</span>&nbsp;Tagged&nbsp;&nbsp;<span class="pill p-access" style="font-size:10px">U</span>&nbsp;Untagged&nbsp;&nbsp;<span class="pill p-hybrid" style="font-size:10px">H</span>&nbsp;Hybrid</span></div>`
    +`<div style="overflow-x:auto;flex:1;min-height:0"><table class="data-table" style="width:max-content;min-width:max-content;border-collapse:separate;border-spacing:0;table-layout:fixed"><thead>${th}</thead><tbody>${tbody}</tbody></table></div>`
    +`<div class="tbl-foot"><span>${fVlans.length} VLANs · ${fPorts.length} ports</span></div>`;
}
function detectVlanIslands(p){
  const ifaces = p.interfaces || [];
  return (p.vlans || []).filter(v => !v.implied).map(v => {
    const vid = String(v.id);
    const access = ifaces.filter(i => i.mode === 'access' && String(i.nativeVlan) === vid);
    const trunk = ifaces.filter(i => i.mode === 'trunk' && (i.vlans === 'all' || (i.vlans||'').split(/[\s,]+/).includes(vid)));
    return {id: v.id, name: v.name||'—', accessCount: access.length, trunkCount: trunk.length};
  }).filter(v => v.trunkCount === 0 && v.accessCount > 0);
}

function renderVLANs(){
  const rows=parsed.vlans.map(v=>({
    id:v.id,name:v.name||'—',
    ipSubnet:v.ipSubnets.length?v.ipSubnets.map(s=>s.cidr).join(', '):'—',
    ipSubnetCount:v.ipSubnets.length,
    implied:!!v.implied,
    id_html:v.implied?`<span class="pill p-vlan" style="opacity:.6">V${v.id}</span><span style="font-size:9px;color:var(--text-muted);margin-left:3px" `+tr('vlan.implied_title')+`">*</span>`:`<span class="pill p-vlan">V${v.id}</span>`,
    name_html:v.implied?`<span style="color:var(--text-muted);font-style:italic">${tr('vlan.implied_label')}</span>`:`<span style="color:var(--text)">${esc(v.name||'—')}</span>`,
    ipSubnet_html:v.ipSubnets.length?v.ipSubnets.map(s=>`<span class="pill p-ip">${esc(s.cidr)}</span>`).join(' '):'<span style="color:var(--text-muted)">—</span>',
    ipSubnetCount_html:v.ipSubnets.length?`<span style="color:var(--orange)">${v.ipSubnets.length}</span>`:'<span style="color:var(--text-muted)">0</span>',
  }));
  tableData=rows;tableKeys=['id','name','ipSubnet','ipSubnetCount'];
  const hdrs=[{key:'id',label:'VLAN ID'},{key:'name',label:tr('col.vlan_name')},{key:'ipSubnet',label:'ip-subnet-vlan (VLAN-by-IP)'},{key:'ipSubnetCount',label:tr('col.subnet_count')}];
  const fSel=document.getElementById('filter-sel');
  const fv=fSel?.value||'all';
  const filterFn={all:null,withip:r=>r.ipSubnetCount>0,declared:r=>!r.implied,implied:r=>!!r.implied}[fv]||null;
  const {html,count,total}=renderTable(hdrs,rows,filterFn);
  const impliedCount=rows.filter(r=>r.implied).length;
  const declaredCount=rows.length-impliedCount;
  const islands = detectVlanIslands(parsed);
  const islandCard = islands.length ? `<div style="margin-top:14px;border-left:3px solid var(--yellow);padding:10px 14px;background:var(--surface2);border-radius:4px">
    <div style="font-weight:600;color:var(--yellow);margin-bottom:6px">${tr('vlan.island_title')} (${islands.length})</div>
    <div style="font-size:12px;color:var(--text-dim);margin-bottom:8px">${tr('vlan.island_hint')}</div>
    <table style="border-collapse:collapse;width:100%;font-size:12px"><thead><tr>
      <th style="text-align:left;padding:3px 8px;border-bottom:1px solid var(--border)">${tr('vlan.island_col_id')}</th>
      <th style="text-align:left;padding:3px 8px;border-bottom:1px solid var(--border)">${tr('vlan.island_col_name')}</th>
      <th style="text-align:left;padding:3px 8px;border-bottom:1px solid var(--border)">${tr('vlan.island_col_access')}</th>
    </tr></thead><tbody>${islands.map(v=>`<tr>
      <td style="padding:3px 8px"><span class="pill p-vlan">V${v.id}</span></td>
      <td style="padding:3px 8px">${esc(v.name)}</td>
      <td style="padding:3px 8px"><span style="color:var(--yellow)">${v.accessCount}</span></td>
    </tr>`).join('')}</tbody></table></div>` : '';
  return mkTbar('search-inp',[{v:'all',l:tr('filter.all_vlan')},{v:'withip',l:tr('filter.withip')},{v:'declared',l:tr('filter.declared')},{v:'implied',l:tr('filter.implied_only')}],'exportVLANsCSV')+
    `<div class="tbl-wrap">${html}</div><div class="tbl-foot"><span>${count} / ${total} ${tr('unit.count')}</span><span>${tr('vlan.foot_declared')}: ${declaredCount} · ${tr('vlan.foot_implied')}: ${impliedCount}</span></div>${islandCard}`;
}
function hybridCell(iface){
  if(!iface.hybrid)return '—';
  const h=iface.hybrid;
  let s=`<div class="hyb-box">`;
  if(h.pvid)s+=`<div class="hyb-row"><span class="hyb-key">PVID</span><span class="pill p-vlan">${h.pvid}</span></div>`;
  if(h.untagged.length)s+=`<div class="hyb-row"><span class="hyb-key">Untagged</span><span class="pill p-access">${h.untagged.join(', ')}</span></div>`;
  if(h.tagged.length)s+=`<div class="hyb-row"><span class="hyb-key">Tagged</span><span class="pill p-trunk">${h.tagged.join(', ')}</span></div>`;
  if(h.hasIPSub)s+=`<div class="hyb-row"><span class="hyb-key">IP-VLAN</span><span class="pill p-ip">${tr('hybrid.subscribed')}</span></div>`;
  if(h.vlanMaps.length)h.vlanMaps.forEach(m=>{s+=`<div class="hyb-row"><span class="hyb-key">Map</span><span class="pill p-route">${m.outer}→${m.inner}</span></div>`;});
  if(h.hasQinQ)s+=`<div class="hyb-row"><span class="hyb-key">QinQ</span><span class="pill p-vrf">${tr('hybrid.qinq_on')}</span></div>`;
  return s+'</div>';
}
function renderPortHeatmap(ph){
  const physical=ph.filter(i=>i.type!=='svi'&&i.type!=='loopback'&&i.type!=='null');
  if(!physical.length)return`<div class="nodata">${tr('msg.no_ports')}</div>`;
  const col=i=>i.shutdown?'var(--red)':i.mode==='trunk'?'var(--accent)':i.mode==='access'?'var(--green)':i.mode==='hybrid'?'var(--yellow)':'var(--text-dim)';
  let html=`<div id="hm-tip" style="display:none;position:fixed;z-index:9999;pointer-events:none;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 13px;font-size:12px;min-width:180px;max-width:280px;box-shadow:0 4px 18px rgba(0,0,0,.35)"></div>`;
  html+=`<div style="display:flex;flex-wrap:wrap;gap:4px;padding:14px 0 18px" onmouseleave="_hmHide()">`;
  physical.forEach(i=>{
    const c=col(i);
    const shortName=i.name.replace(/^[A-Za-z\-]+/,'').replace(/^0\//,'');
    const d=btoa(unescape(encodeURIComponent(JSON.stringify({
      name:i.name, desc:i.desc||'', status:i.shutdown?tr('port.hm_down'):tr('port.hm_up'),
      mode:i.mode||i.type||'', vlans:i.vlans||'', native:i.nativeVlan||'',
      ip:i.ip||'', vrf:i.vrf||'', member:i.member||'', color:c
    }))));
    html+=`<div data-hm="${d}" onmouseenter="_hmShow(event,this)" style="width:38px;height:24px;border-radius:3px;background:${c}18;border:1.5px solid ${c};display:flex;align-items:center;justify-content:center;font-size:9px;font-family:monospace;color:${c};cursor:default;overflow:hidden;white-space:nowrap;transition:transform .1s" onmouseover="this.style.transform='scale(1.25)'" onmouseout="this.style.transform=''">${esc(shortName.slice(-6))}</div>`;
  });
  html+=`</div>`;
  const legend=[
    {c:'var(--green)',l:tr('port.hm_access')},
    {c:'var(--accent)',l:'Trunk'},
    {c:'var(--yellow)',l:'Hybrid'},
    {c:'var(--red)',l:tr('port.hm_down')},
    {c:'var(--text-dim)',l:tr('port.hm_other')},
  ];
  html+=`<div style="display:flex;flex-wrap:wrap;gap:14px;margin-top:4px;font-size:11px;color:var(--text-dim)">`;
  legend.forEach(l=>html+=`<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:${l.c}18;border:1.5px solid ${l.c};margin-right:4px;vertical-align:middle"></span>${esc(l.l)}</span>`);
  html+=`</div>`;
  const up=physical.filter(i=>!i.shutdown).length;
  html+=`<div class="tbl-foot"><span>${up} / ${physical.length} ${tr('port.hm_up')}</span><span>Trunk: ${physical.filter(i=>i.mode==='trunk').length} · Access: ${physical.filter(i=>i.mode==='access').length} · Hybrid: ${physical.filter(i=>i.mode==='hybrid').length} · Down: ${physical.filter(i=>i.shutdown).length}</span></div>`;
  return html;
}
function _hmShow(e,el){
  const tip=document.getElementById('hm-tip');
  if(!tip)return;
  let d;try{d=JSON.parse(decodeURIComponent(escape(atob(el.dataset.hm))));}catch(ex){return;}
  const rows=[
    ['',`<span style="font-size:13px;font-weight:600;color:${d.color};font-family:monospace">${esc(d.name)}</span>`],
    d.desc?[tr('col.desc'),esc(d.desc)]:[],
    [tr('col.status'),`<span style="color:${d.status===tr('port.hm_down')?'var(--red)':'var(--green)'}">${esc(d.status)}</span>`],
    d.mode?[tr('col.mode'),`<span style="color:${d.color}">${esc(d.mode)}</span>`]:[],
    d.vlans?['VLAN',esc(d.vlans.length>40?d.vlans.substring(0,40)+'…':d.vlans)]:[],
    d.native?[tr('port.tip_native'),esc(d.native)]:[],
    d.ip?[tr('col.ip_addr'),`<span style="font-family:monospace">${esc(d.ip)}</span>`]:[],
    d.vrf?[tr('col.vrf_name'),esc(d.vrf)]:[],
    d.member?[tr('port.tip_stack'),`M${esc(d.member)}`]:[],
  ].filter(r=>r.length);
  tip.innerHTML=rows.map(([k,v])=>k?`<div style="display:flex;gap:8px;margin:2px 0"><span style="color:var(--text-dim);min-width:46px;font-size:11px">${k}</span><span>${v}</span></div>`:v).join('');
  tip.style.display='block';
  _hmMove(e);
}
function _hmMove(e){
  const tip=document.getElementById('hm-tip');
  if(!tip||tip.style.display==='none')return;
  const vw=window.innerWidth,vh=window.innerHeight;
  let x=e.clientX+14,y=e.clientY+14;
  const tw=tip.offsetWidth||200,th=tip.offsetHeight||100;
  if(x+tw>vw-8)x=e.clientX-tw-8;
  if(y+th>vh-8)y=e.clientY-th-8;
  tip.style.left=x+'px';tip.style.top=y+'px';
}
function _hmHide(){const tip=document.getElementById('hm-tip');if(tip)tip.style.display='none';}
document.addEventListener('mousemove',_hmMove);
document.addEventListener('mouseleave',_hmHide);
function renderPorts(){
  const ph=parsed.interfaces.filter(i=>i.type!=='null');
  const btnStyle=active=>`padding:5px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;background:${active?'var(--accent)':'var(--surface2)'};color:${active?'#fff':'var(--text-dim)'}`;
  const toggleHtml=`<div style="display:flex;gap:6px;margin-bottom:10px">
    <button onclick="portView='table';navGo('ports')" style="${btnStyle(portView==='table')}">${tr('port.view_table')}</button>
    <button onclick="portView='heatmap';navGo('ports')" style="${btnStyle(portView==='heatmap')}">${tr('port.view_heatmap')}</button>
  </div>`;
  if(portView==='heatmap') return toggleHtml+renderPortHeatmap(ph);
  const rows=ph.map(i=>({
    name:i.name,member:i.member,type:i.type,desc:i.desc,
    mode:i.mode||i.type,vlans:i.vlans||'—',native:i.nativeVlan||'—',
    ip:i.ip||'—',ip6:i.ip6||'—',vrf:i.vrf||'—',_shutdown:!!i.shutdown,status:i.shutdown?tr('val.disabled'):tr('val.enabled'),
    name_html:`<span class="mono" style="color:var(--accent3)">${esc(i.name)}</span>`,
    member_html:`<span class="pill p-stack">M${i.member}</span>`,
    type_html:`<span class="pill p-${i.type==='svi'?'svi':i.type==='stack'?'stack':'info'}">${i.type==='stack'?tr('port.type_stack'):i.type}</span>`,
    mode_html:i.type==='stack'?`<span class="pill p-stack">${tr('port.type_stack')}</span>`:i.mode?`<span class="pill p-${i.mode==='trunk'?'trunk':i.mode==='hybrid'?'hybrid':'access'}">${i.mode}</span>`:`<span class="pill p-${i.type==='svi'?'svi':'gray'}">${i.type}</span>`,
    vlans_html:i.vlans?`<span class="pill p-vlan">${esc(i.vlans.substring(0,26)+(i.vlans.length>26?'…':''))}</span>`:'<span style="color:var(--text-muted)">—</span>',
    hybrid_html:i.mode==='hybrid'?hybridCell(i):'—',
    ip_html:i.ip?`<span class="mono" style="font-size:11px">${esc(i.ip)}</span>`:'—',
    ip6_html:i.ip6?`<span class="mono" style="font-size:11px">${esc(i.ip6)}</span>`:'—',
    vrf_html:i.vrf?`<span class="pill p-vrf">${esc(i.vrf)}</span>`:'—',
    status_html:`<span class="pill p-${i.shutdown?'down':'up'}">${i.shutdown?tr('port.down'):tr('port.up')}</span>`,
    vrrp_html:i.vrrp&&i.vrrp.length?i.vrrp.map(v=>`<span class="pill p-info">VRID${v.vrid}:${v.vip}</span>`).join(' '):'—',
    fortilink_html:i.fortilinkDiscovery?`<span class="pill p-up">${tr('val.enabled')}</span>`:'—',
    breakout_html:i.breakoutMode?`<span class="pill p-master" title="${esc(i.name)}">${esc(i.breakoutMode)}</span>`:i.breakoutChild?`<span class="pill p-standby">→ ${esc(i.breakoutParent)}</span>`:'—',
  }));
  tableData=rows;tableKeys=['name','member','type','mode','vlans','native','ip','ip6','vrf','status'];
  const fSel=document.getElementById('filter-sel');
  const fv=fSel?.value||'all';
  const filterFn={all:null,trunk:r=>r.mode==='trunk',access:r=>r.mode==='access',hybrid:r=>r.mode==='hybrid',svi:r=>r.type==='svi',stack:r=>r.type==='stack',down:r=>r._shutdown,vrf:r=>r.vrf!=='—'}[fv]||null;
  const hasHybrid=ph.some(i=>i.mode==='hybrid');
  const hasVRRP=ph.some(i=>i.vrrp&&i.vrrp.length);
  const hasFortilinkDiscovery=ph.some(i=>i.fortilinkDiscovery);
  const hasBreakout=ph.some(i=>i.breakoutMode||i.breakoutChild);
  const hasIPv6=ph.some(i=>i.ip6);
  const hdrs=[{key:'name',label:tr('col.iface')},{key:'member',label:'M'},{key:'type',label:tr('col.type')},{key:'mode',label:tip('tip.trunk',tr('col.mode'))},{key:'vlans',label:tip('tip.vlan_range','VLAN')},{key:'native',label:tip('tip.pvid','Native')},{key:'ip',label:tr('col.ip_addr')}];
  if(hasIPv6)hdrs.push({key:'ip6',label:tr('col.ipv6_addr')});
  hdrs.push({key:'vrf',label:'VRF'});
  if(hasHybrid)hdrs.push({key:'hybrid',label:tr('col.hybrid_info')});
  if(hasVRRP)hdrs.push({key:'vrrp',label:'VRRP'});
  if(hasFortilinkDiscovery)hdrs.push({key:'fortilink',label:tr('col.fortilink_discovery')});
  if(hasBreakout)hdrs.push({key:'breakout',label:tr('col.breakout')});
  hdrs.push({key:'status',label:tr('col.status')});
  const {html,count,total}=renderTable(hdrs,rows,filterFn);
  return toggleHtml+mkTbar('search-inp',[{v:'all',l:tr('filter.all')},{v:'trunk',l:'Trunk'},{v:'access',l:'Access'},{v:'hybrid',l:'Hybrid'},{v:'svi',l:'SVI'},{v:'stack',l:tr('filter.stack_port')},{v:'down',l:tr('filter.disabled')},{v:'vrf',l:tr('filter.has_vrf')}],'exportPortsCSV')+
    `<div class="tbl-wrap">${html}</div><div class="tbl-foot"><span>${count} / ${total} ${tr('unit.count')}</span><span>Hybrid: ${ph.filter(i=>i.mode==='hybrid').length} · SVI: ${parsed.interfaces.filter(i=>i.type==='svi').length}</span></div>`;
}
function renderRoutes(){
  const rows=parsed.routes.map(r=>({
    dst:r.dst,gw:r.gw,vrf:r.vrf||'__main__',
    gwIsInterface:r.gwIsInterface,
    dst_html:`<span class="pill p-route">${esc(r.dst)}</span>`,
    gw_html:r.gwIsInterface?`<span class="mono" style="color:var(--orange)">${esc(r.gw)} <span style="font-size:9px;opacity:.7">${tr('route.iface_gw')}</span></span>`:`<span class="mono" style="color:var(--green)">${esc(r.gw)}</span>`,
    vrf_html:r.vrf!=='__main__'?`<span class="pill p-vrf">${esc(r.vrf)}</span>`:`<span style="color:var(--text-muted)">${tr('filter.main_rt')}</span>`,
  }));
  tableData=rows;tableKeys=['dst','gw','vrf'];
  const fSel=document.getElementById('filter-sel');
  const fv=fSel?.value||'all';
  const filterFn={all:null,default:r=>r.dst.startsWith('0.0.0.0'),vrf:r=>r.vrf!=='__main__',novrf:r=>r.vrf==='__main__'}[fv]||null;
  const hdrs=[{key:'dst',label:tr('col.dst')},{key:'gw',label:tr('col.next_hop')},{key:'vrf',label:tr('col.vrf_rt')}];
  const {html,count,total}=renderTable(hdrs,rows,filterFn);
  return mkTbar('search-inp',[{v:'all',l:tr('filter.all_routes')},{v:'default',l:tr('filter.default_route')},{v:'novrf',l:tr('filter.main_rt')},{v:'vrf',l:tr('filter.vrf_routes')}],'exportRoutesCSV')+
    `<div class="tbl-wrap">${html}</div><div class="tbl-foot"><span>${count} / ${total} ${tr('unit.count')}</span><span>${tr('filter.vrf_routes')}: ${parsed.routes.filter(r=>r.vrf).length}</span></div>`;
}
function renderVRFs(){
  if(!parsed.vrfs.length)return`<div class="nodata">${tr('msg.no_vrf')}</div>`;
  const rows=parsed.vrfs.map(v=>{
    const boundIf=parsed.interfaces.filter(i=>i.vrf===v.name);
    const boundRoutes=parsed.routes.filter(r=>r.vrf===v.name);
    return{name:v.name,rd:v.rd||'—',importRoute:v.importRoute||'—',
      boundIf:boundIf.map(i=>i.name).join(', ')||'—',
      routeCount:boundRoutes.length,
      name_html:`<span class="pill p-vrf">${esc(v.name)}</span>`,
      rd_html:`<span class="mono">${esc(v.rd||'—')}</span>`,
      importRoute_html:`<span class="mono" style="color:var(--text-dim)">${esc(v.importRoute||'—')}</span>`,
      boundIf_html:boundIf.length?boundIf.map(i=>`<span class="pill p-info" style="margin:1px">${esc(i.name)}</span>`).join(''):'<span style="color:var(--text-muted)">—</span>',
      routeCount_html:`<span style="color:var(--yellow)">${boundRoutes.length}</span>`,
    };
  });
  tableData=rows;tableKeys=['name','rd','importRoute','boundIf','routeCount'];
  const hdrs=[{key:'name',label:tr('col.vrf_name')},{key:'rd',label:tr('vxlan.col_rd')},{key:'importRoute',label:tr('col.import_route')},{key:'boundIf',label:tr('col.bound_if')},{key:'routeCount',label:tr('col.route_count')}];
  const {html,count,total}=renderTable(hdrs,rows,null);
  return mkTbar('search-inp',null,'exportVRFsCSV')+
    `<div class="tbl-wrap">${html}</div><div class="tbl-foot"><span>${count} ${tr('unit.vrf_count')}</span></div>`;
}
function renderUsers(){
  const rows=parsed.users.map(u=>({
    name:u.name,role:u.role||'—',service:u.service||'—',hasPwd:u.hasPwd?tr('pwd.set_plain'):tr('pwd.notset_plain'),
    pwdType:u.pwdType||'set',pwdWeak:!!u.pwdWeak,
    name_html:`<strong>${esc(u.name)}</strong>`,
    role_html:`<span class="pill p-info">${esc(u.role||'—')}</span>`,
    service_html:`<span class="mono" style="color:var(--text-dim)">${esc(u.service||'—')}</span>`,
    hasPwd_html:`<span class="pill p-${u.hasPwd?'up':'down'}">${u.hasPwd?tr('pwd.set'):tr('pwd.notset')}</span>`,
    pwdType_html:(()=>{
      const t=u.pwdType||'set',w=u.pwdWeak;
      const typeLabel={hash:`Hash(${tr('pwd.strength_strong')})`,cipher:`Cipher(${tr('pwd.strength_strong')})`,md5:`MD5(${tr('pwd.strength_medium')})`,scrypt:`Scrypt(${tr('pwd.strength_strong')})`,pbkdf2:`PBKDF2(${tr('pwd.strength_strong')})`,'type7-weak':`Type-7(${tr('pwd.strength_weak')}⚠)`,'simple':`Simple(${tr('pwd.strength_weak')}⚠)`,plaintext:`${tr('pwd.plaintext')}(${tr('pwd.strength_danger')}⚠)`,set:tr('pwd.set_plain'),none:tr('pwd.notset_plain')}[t]||t;
      return w?`<span class="pill p-down">${typeLabel}</span>`:`<span class="pill p-up">${typeLabel}</span>`;
    })(),
  }));
  tableData=rows;tableKeys=['name','role','service','hasPwd'];
  const hdrs=[{key:'name',label:tr('col.username')},{key:'role',label:tr('col.role')},{key:'service',label:tr('col.svc_type')},{key:'hasPwd',label:tr('col.password')},{key:'pwdType',label:tr('col.enc_strength')}];
  const {html,count,total}=renderTable(hdrs,rows,null);
  return mkTbar('search-inp',null,null)+
    `<div class="tbl-wrap">${html}</div><div class="tbl-foot"><span>${count} ${tr('unit.user_count')}</span>${rows.filter(r=>r.pwdWeak).length>0?`<span style="color:var(--red)">⚠ ${rows.filter(r=>r.pwdWeak).length} ${tr('pwd.weak_msg')}</span>`:`<span style="color:var(--green)">${tr('pwd.no_weak')}</span>`}</div>`;
}
function renderLLDPTopo(nbrs){
  const nodeMap={};
  nbrs.forEach(n=>{
    if(!nodeMap[n.neighbor])nodeMap[n.neighbor]={name:n.neighbor,ip:n.ip||'',links:[]};
    nodeMap[n.neighbor].links.push({local:n.localPort,remote:n.remotePort,proto:n.protocol});
  });
  const neighbors=Object.values(nodeMap);
  const cnt=neighbors.length||1;
  const CX=420,CY=230,R=Math.min(160,60+cnt*18),nodeR=32;
  const W=840,H=460;
  const positions=neighbors.map((_,i)=>{
    const a=(2*Math.PI*i/cnt)-Math.PI/2;
    return{x:CX+R*Math.cos(a),y:CY+R*Math.sin(a)};
  });
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" style="width:100%;max-height:460px">
  <defs>
    <filter id="lg"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <marker id="la" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L6,3 z" fill="var(--accent)"/></marker>
  </defs>`;
  positions.forEach((pos,i)=>{
    const nb=neighbors[i];
    const dx=pos.x-CX,dy=pos.y-CY,dist=Math.sqrt(dx*dx+dy*dy);
    const ex=CX+dx/dist*nodeR,ey=CY+dy/dist*nodeR;
    const sx=pos.x-dx/dist*nodeR,sy=pos.y-dy/dist*nodeR;
    svg+=`<line x1="${ex}" y1="${ey}" x2="${sx}" y2="${sy}" stroke="var(--accent)" stroke-width="1.5" stroke-opacity="0.5" marker-end="url(#la)"/>`;
    const mx=(CX+pos.x)/2,my=(CY+pos.y)/2;
    nb.links.slice(0,2).forEach((lk,li)=>{
      const off=(li-(nb.links.length-1)/2)*11;
      const ang=Math.atan2(dy,dx)+Math.PI/2;
      svg+=`<text x="${mx+Math.cos(ang)*off}" y="${my+Math.sin(ang)*off}" text-anchor="middle" dominant-baseline="middle" font-size="9" fill="var(--accent)" opacity="0.85" font-family="monospace">${lk.local}→${lk.remote}</text>`;
    });
  });
  svg+=`<circle cx="${CX}" cy="${CY}" r="${nodeR}" fill="var(--surface2)" stroke="var(--accent)" stroke-width="2.5" filter="url(#lg)"/>`;
  svg+=`<text x="${CX}" y="${CY-5}" text-anchor="middle" dominant-baseline="middle" font-size="10" font-weight="700" fill="var(--accent)" font-family="monospace">${(parsed.sys?.hostname||'Local').substring(0,12)}</text>`;
  svg+=`<text x="${CX}" y="${CY+8}" text-anchor="middle" dominant-baseline="middle" font-size="8" fill="var(--text-dim)">${tr('lldp.topo_center')}</text>`;
  positions.forEach((pos,i)=>{
    const nb=neighbors[i];
    const col=nb.links.some(l=>l.proto==='CDP')?'var(--green)':'var(--purple)';
    svg+=`<circle cx="${pos.x}" cy="${pos.y}" r="${nodeR}" fill="var(--surface2)" stroke="${col}" stroke-width="1.8"/>`;
    const nm=nb.name.length>14?nb.name.substring(0,12)+'…':nb.name;
    svg+=`<text x="${pos.x}" y="${pos.y-5}" text-anchor="middle" dominant-baseline="middle" font-size="9" font-weight="600" fill="var(--text)" font-family="monospace">${nm}</text>`;
    if(nb.ip&&nb.ip!=='-')svg+=`<text x="${pos.x}" y="${pos.y+8}" text-anchor="middle" dominant-baseline="middle" font-size="8" fill="var(--text-dim)">${nb.ip}</text>`;
  });
  svg+='</svg>';
  return`<div style="background:var(--surface2);border-radius:8px;padding:12px;overflow:auto">${svg}</div>`;
}
function addMultiDevice(file){
  const reader=new FileReader();
  reader.onload=e=>{
    try{
      const p=parseAny(e.target.result);
      if(p&&p.sys&&p.sys.hostname){
        _multiDevices=_multiDevices.filter(d=>d.hostname!==p.sys.hostname);
        _multiDevices.push({hostname:p.sys.hostname,lldp:p.lldp||[]});
        navGo('lldp');
      }
    }catch(ex){console.warn('multi parse error:',ex);}
  };
  reader.readAsText(file);
}
function renderMultiTopo(){
  const allDevices=[{hostname:parsed.sys?.hostname||'Local',lldp:parsed.lldp||[]},..._multiDevices];
  const deviceNames=new Set(allDevices.map(d=>d.hostname));
  const nodeMap={};
  allDevices.forEach(d=>{if(!nodeMap[d.hostname])nodeMap[d.hostname]={name:d.hostname,known:true,links:[]};});
  allDevices.forEach(d=>{
    d.lldp.forEach(n=>{
      if(!nodeMap[n.neighbor])nodeMap[n.neighbor]={name:n.neighbor,known:false,links:[]};
      if(nodeMap[d.hostname])nodeMap[d.hostname].links.push({to:n.neighbor,local:n.localPort,remote:n.remotePort});
    });
  });
  const nodes=Object.values(nodeMap);
  if(!nodes.length)return`<div class="nodata">${tr('msg.no_lldp')}</div>`;
  const cnt=nodes.length,CX=420,CY=230,R=Math.min(180,60+cnt*20),nodeR=34,W=840,H=460;
  const pos=nodes.map((_,i)=>{const a=(2*Math.PI*i/cnt)-Math.PI/2;return{x:CX+R*Math.cos(a),y:CY+R*Math.sin(a)};});
  const seen=new Set(),edges=[];
  nodes.forEach((n,i)=>{
    n.links.forEach(lk=>{
      const j=nodes.findIndex(x=>x.name===lk.to);
      if(j<0)return;
      const key=[i,j].sort().join('-');
      if(!seen.has(key)){seen.add(key);edges.push({fi:i,ti:j,local:lk.local,remote:lk.remote});}
    });
  });
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" style="width:100%;max-height:460px">
  <defs><filter id="mg2"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
  edges.forEach(e=>{
    const p1=pos[e.fi],p2=pos[e.ti];
    svg+=`<line x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}" stroke="var(--accent)" stroke-width="1.5" stroke-opacity="0.4"/>`;
    const mx=(p1.x+p2.x)/2,my=(p1.y+p2.y)/2;
    if(e.local||e.remote)svg+=`<text x="${mx}" y="${my-4}" text-anchor="middle" font-size="9" fill="var(--text-dim)" font-family="monospace">${esc((e.local||'?')+'↔'+(e.remote||'?'))}</text>`;
  });
  nodes.forEach((n,i)=>{
    const p=pos[i];
    const isLocal=n.name===(parsed.sys?.hostname||'Local');
    const col=isLocal?'var(--accent)':n.known?'var(--green)':'var(--text-muted)';
    svg+=`<circle cx="${p.x}" cy="${p.y}" r="${nodeR}" fill="var(--surface2)" stroke="${col}" stroke-width="${isLocal?2.5:1.5}" filter="url(#mg2)"/>`;
    const lbl=n.name.length>14?n.name.slice(0,13)+'…':n.name;
    svg+=`<text x="${p.x}" y="${p.y}" text-anchor="middle" dominant-baseline="middle" font-size="10" fill="${col}" font-family="monospace">${esc(lbl)}</text>`;
    if(!n.known)svg+=`<text x="${p.x}" y="${p.y+16}" text-anchor="middle" font-size="8" fill="var(--text-muted)">LLDP only</text>`;
  });
  svg+='</svg>';
  return svg;
}
function renderLLDP(){
  const nbrs=parsed.lldp||[];
  const cmdHints=[
    'Cisco IOS/NX-OS: <code>show cdp neighbors detail</code> / <code>show lldp neighbors detail</code>',
    'HPE ProCurve: <code>show lldp info remote-device detail</code>',
    'Juniper EX: <code>show lldp neighbors detail</code>',
  ];
  if(!nbrs.length){
    return`<div class="nodata"><p>${tr('msg.no_lldp')}</p><p style="margin-top:8px;font-size:12px;color:var(--text-muted)">${tr('lldp.cmd_hint')}：</p><ul style="margin:6px 0 0 16px;font-size:12px;color:var(--text-muted);line-height:2">${cmdHints.map(c=>`<li>${c}</li>`).join('')}</ul></div>`;
  }
  const btnStyle=(active)=>`padding:4px 12px;border-radius:4px;border:1px solid ${active?'var(--accent)':'var(--border)'};cursor:pointer;font-size:12px;background:${active?'var(--accent)':'var(--surface2)'};color:${active?'#fff':'var(--text-dim)'}`;
  const toggleHtml=`<div style="display:flex;gap:6px;margin-bottom:10px;align-items:center">
    <button onclick="lldpView='table';navGo('lldp')" style="${btnStyle(lldpView==='table')}">${tr('lldp.view_table')}</button>
    <button onclick="lldpView='topo';navGo('lldp')" style="${btnStyle(lldpView==='topo')}">${tr('lldp.view_topo')}</button>
    <button onclick="lldpView='multi';navGo('lldp')" style="${btnStyle(lldpView==='multi')}">${tr('lldp.multi_title')}</button>
  </div>`;
  if(lldpView==='topo') return toggleHtml+renderLLDPTopo(nbrs);
  if(lldpView==='multi'){
    const devices=[{hostname:parsed.sys?.hostname||'Local',lldp:parsed.lldp||[]},..._multiDevices];
    const foc=`Array.from(this.files).forEach(f=>addMultiDevice(f));this.value=''`;
    return toggleHtml+
      `<div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="file" multiple accept=".txt,.cfg,.conf,.log,.rsc" onchange="${foc}" style="display:none" id="multi-lldp-inp">
        <button onclick="document.getElementById('multi-lldp-inp').click()" style="${btnStyle(false)}">${tr('lldp.multi_add')}</button>
        ${_multiDevices.length?`<button onclick="_multiDevices=[];navGo('lldp')" style="${btnStyle(false)}">${tr('lldp.multi_clear')}</button>`:''}
        <span style="font-size:11px;color:var(--text-dim)">${tr('lldp.multi_hint')}</span>
      </div>
      <div style="margin-bottom:8px;font-size:11px">${devices.map(d=>`<span style="margin-right:10px;color:var(--${d.hostname===(parsed.sys?.hostname||'Local')?'accent':'green'})">● ${esc(d.hostname)}</span>`).join('')}</div>`
      +renderMultiTopo();
  }
  const rows=nbrs.map(n=>({
    localPort: n.localPort,
    neighbor:  n.neighbor,
    platform:  n.platform||'',
    remotePort:n.remotePort,
    capability:n.capability||'',
    ip:        n.ip||'',
    protocol:  n.protocol
  }));
  tableData=rows; tableKeys=['localPort','neighbor','platform','remotePort','capability','ip','protocol'];
  const hdrs=[
    {key:'localPort', label:tr('lldp.col_local')},
    {key:'neighbor',  label:tr('lldp.col_device')},
    {key:'platform',  label:tr('lldp.col_platform')},
    {key:'remotePort',label:tr('lldp.col_remote_port')},
    {key:'capability',label:tr('lldp.col_cap')},
    {key:'ip',        label:tr('lldp.col_ip')},
    {key:'protocol',  label:tr('lldp.col_proto')},
  ];
  const fmtRows=rows.map(r=>({...r,
    protocol_html:`<span class="pill ${r.protocol==='CDP'?'p-allow':'p-info'}">${r.protocol}</span>`
  }));
  const {html,count}=renderTable(hdrs,fmtRows,null);
  return toggleHtml+mkTbar('search-inp',null,'exportLLDPCSV')+
    `<div class="tbl-wrap">${html}</div><div class="tbl-foot"><span>${count} / ${nbrs.length} ${tr('unit.count')}</span></div>`;
}
function dlCSV(rows,hdrs,fn){
  const lines=[hdrs.join(','),...rows.map(r=>r.map(c=>`"${String(c||'').replace(/"/g,'""')}"`).join(','))];
  const b=new Blob(['\uFEFF'+lines.join('\n')],{type:'text/csv;charset=utf-8;'});
  const url=URL.createObjectURL(b);const a=document.createElement('a');a.href=url;a.download=fn;a.click();URL.revokeObjectURL(url);
}
function dlTxt(t,fn){const b=new Blob([t],{type:'text/plain;charset=utf-8;'});const url=URL.createObjectURL(b);const a=document.createElement('a');a.href=url;a.download=fn;a.click();URL.revokeObjectURL(url);}
function dlHtml(t,fn){const b=new Blob([t],{type:'text/html;charset=utf-8;'});const url=URL.createObjectURL(b);const a=document.createElement('a');a.href=url;a.download=fn;a.click();URL.revokeObjectURL(url);}
function exportVLANsCSV(){if(!parsed){alert(tr('msg.no_config'));return;}dlCSV(parsed.vlans.map(v=>[v.id,v.name,v.ipSubnets.map(s=>s.cidr).join(';'),v.ipSubnets.length]),['VLAN_ID',tr('col.vlan_name'),'ip-subnet-vlan',tr('col.subnet_count')],`${hn()}_vlans.csv`);}
function exportPortsCSV(){if(!parsed){alert(tr('msg.no_config'));return;}const ph=parsed.interfaces.filter(i=>i.type!=='null');dlCSV(ph.map(i=>[i.name,i.member,i.type,i.desc,i.mode,i.vlans,i.nativeVlan,i.ip,i.ip6||'',i.vrf,i.shutdown?tr('rt.auto_sum_off'):tr('rt.auto_sum_on'),i.hybrid?[i.hybrid.pvid,...i.hybrid.untagged,...i.hybrid.tagged].join(';'):'',i.hybrid?.hasIPSub?tr('val.yes'):'',i.hybrid?.hasQinQ?tr('val.yes'):'']),[tr('col.iface'),tr('col.member'),tr('col.type'),tr('col.desc'),tr('col.mode'),'VLAN','Native','IP',tr('col.ipv6_addr'),'VRF',tr('col.status'),tr('col.hybrid_info'),'IPsub','QinQ'],`${hn()}_ports.csv`);}
function exportRoutesCSV(){if(!parsed){alert(tr('msg.no_config'));return;}dlCSV(parsed.routes.map(r=>[r.dst,r.gw,r.vrf||'']),[tr('col.dst'),tr('col.gw'),'VRF'],`${hn()}_routes.csv`);}
// 修正既有 bug（同 renderLACP()）：ProCurve/ArubaOS-Switch 的 members 是逗號分隔字串非陣列
function _lacpMembersArr(x){return Array.isArray(x.members)?x.members:String(x.members||'').split(',').map(s=>s.trim()).filter(Boolean);}
function exportLACPCSV(){if(!parsed){alert(tr('msg.no_config'));return;}dlCSV(parsed.lacp.map(x=>{const ma=_lacpMembersArr(x);return[x.name,x.mode||'—',x.mtu||'—',ma.length,ma.map(m=>typeof m==='string'?m:m.name).join(';')];}),[tr('lacp.col_name'),tr('lacp.col_mode'),'MTU',tr('lacp.col_members'),tr('col.member_port')],`${hn()}_lacp.csv`);}
function exportVRFsCSV(){if(!parsed){alert(tr('msg.no_config'));return;}dlCSV(parsed.vrfs.map(v=>[v.name,v.rd,v.importRoute,parsed.interfaces.filter(i=>i.vrf===v.name).map(i=>i.name).join(';'),parsed.routes.filter(r=>r.vrf===v.name).length]),[tr('col.vrf_name'),tr('vxlan.col_rd'),tr('col.import_route'),tr('col.bound_if'),tr('col.route_count')],`${hn()}_vrfs.csv`);}
function exportTopoSVG(){if(!parsed)return;const svg=buildTopoSVG(parsed);const b=new Blob([svg],{type:'image/svg+xml;charset=utf-8'});const url=URL.createObjectURL(b);const a=document.createElement('a');a.href=url;a.download=`${hn()}_topology.svg`;a.click();URL.revokeObjectURL(url);}
function exportLLDPCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  dlCSV(
    parsed.lldp.map(l=>[l.localPort,l.neighbor,l.platform||'',l.remotePort,l.capability||'',l.ip||'',l.protocol]),
    [tr('lldp.col_local'),tr('lldp.col_device'),tr('lldp.col_platform'),
     tr('lldp.col_remote_port'),tr('lldp.col_cap'),tr('lldp.col_ip'),tr('lldp.col_proto')],
    `${hn()}_lldp.csv`
  );
}
function exportCSV(){
  if(!parsed)return;
  const v=currentView;
  if(v==='vlans')exportVLANsCSV();
  else if(v==='ports')exportPortsCSV();
  else if(v==='routes')exportRoutesCSV();
  else if(v==='vrfs')exportVRFsCSV();
  else if(v==='lldp')exportLLDPCSV();
  else if(v==='stp')exportSTPCSV();
  else if(v==='lacp')exportLACPCSV();
  else if(v==='dhcp')exportDHCPCSV();
  else if(v==='vrrp')exportVRRPCSV();
  else if(v==='vxlan')exportVXLANCSV();
  else if(v==='acl')exportACLCSV();
  else if(v==='users')exportUsersCSV();
  else if(v==='routing')exportRoutingCSV();
  else if(v==='security')exportSecurityCSV();
  else if(v==='qos')exportQoSCSV();
  else if(v==='audit')exportAuditCSV();
  else{exportPortsCSV();exportRoutesCSV();exportVLANsCSV();}
}
function exportJSON(){
  if(!parsed)return;
  const out={
    meta:{hostname:parsed.sys.hostname,version:parsed.sys.version,vendor:parsed.vendor,exportTime:new Date().toISOString()},
    irf:parsed.irf,stack:parsed.stack,lacp:parsed.lacp,dhcp:parsed.dhcp,
    vlans:parsed.vlans,interfaces:parsed.interfaces.map(i=>({...i})),
    routes:parsed.routes,vrfs:parsed.vrfs,users:parsed.users.map(u=>({...u,hasPwd:u.hasPwd})),
    ospf:parsed.ospf,bgp:parsed.bgp,rip:parsed.rip,vrrp:parsed.vrrp,vxlan:parsed.vxlan
  };
  dlTxt(JSON.stringify(out,null,2),`${hn()}_analysis.json`);
}

function exportSTPCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  dlCSV(
    parsed.stp.ports.map(p=>[p.port,p.portfast?tr('val.yes'):tr('val.no'),p.bpduguard?tr('val.yes'):tr('val.no'),p.guardRoot?tr('val.yes'):tr('val.no'),p.cost||'',p.priority||'']),
    [tr('stp.col_port'),tr('stp.col_portfast'),tr('stp.col_bpduguard'),tr('stp.col_rootguard'),'Cost','Priority'],
    `${hn()}_stp.csv`
  );
}

function renderACL(){
  const acls=(parsed.acls||[]);
  if(!acls.length)return`<div class="nodata">${tr('acl.none')}</div>`;
  const permitCount=acls.reduce((n,a)=>n+a.rules.filter(r=>r.action==='permit').length,0);
  const denyCount=acls.reduce((n,a)=>n+a.rules.filter(r=>r.action==='deny').length,0);
  const cards=`<div class="sum-cards">
    <div class="sum-card"><div class="sv">${acls.length}</div><div class="sl">ACL</div></div>
    <div class="sum-card"><div class="sv" style="color:var(--green)">${permitCount}</div><div class="sl">Permit</div></div>
    <div class="sum-card"><div class="sv" style="color:var(--red)">${denyCount}</div><div class="sl">Deny</div></div>
  </div>`;
  const q=(document.getElementById('search-inp')?.value||'').toLowerCase();
  const filtered=acls.filter(a=>!q||a.name.toLowerCase().includes(q));
  const typeBadge=t=>{
    const m={standard:['p-info',tr('acl.type_std')],extended:['p-allow',tr('acl.type_ext')],basic:['p-info',tr('acl.type_basic')],advanced:['p-allow',tr('acl.type_adv')]};
    const[cls,lbl]=m[t]||['p-gray',t];
    return`<span class="pill ${cls}" style="font-size:10px">${lbl}</span>`;
  };
  const aclCards=filtered.map(a=>{
    const applied=a.appliedOn.length?a.appliedOn.map(ap=>`<span class="pill p-${ap.direction==='in'?'trunk':'warn'}" style="font-size:10px;margin:1px">${esc(ap.interface)} <b>${ap.direction==='in'?tr('acl.dir_in'):tr('acl.dir_out')}</b></span>`).join(''):'';
    const rulesHtml=a.rules.map(r=>{
      if(r.action==='remark')return`<tr style="color:var(--text-muted)"><td colspan="7" style="font-style:italic;padding:2px 8px">— ${esc(r.remark)}</td></tr>`;
      const aCls=r.action==='permit'?'color:var(--green)':'color:var(--red)';
      return`<tr>
        <td class="mono" style="color:var(--text-muted);font-size:11px">${esc(r.seq||'')}</td>
        <td style="${aCls};font-weight:600">${esc(r.action)}</td>
        <td class="mono" style="font-size:11px">${esc(r.protocol||'any')}</td>
        <td class="mono" style="font-size:11px">${esc(r.src||'—')}</td>
        <td class="mono" style="font-size:11px">${esc(r.dst||'—')}</td>
        <td class="mono" style="font-size:11px">${esc(r.dstPort||'—')}</td>
        <td style="color:var(--text-muted);font-size:11px">${esc(r.remark||'')}</td>
      </tr>`;
    }).join('');
    return`<details style="margin-bottom:8px;border:1px solid var(--border);border-radius:6px;overflow:hidden" open>
      <summary style="padding:8px 12px;cursor:pointer;display:flex;align-items:center;gap:8px;background:var(--bg2);list-style:none">
        <span style="color:var(--text-muted);margin-right:2px">▶</span>
        <span class="mono" style="color:var(--accent3);font-weight:600">${esc(a.name)}</span>
        ${typeBadge(a.type)}
        ${a.ipVersion==='v6'?`<span class="pill p-svi" style="font-size:9px">IPv6</span>`:''}
        ${a.vendor?`<span class="pill p-gray" style="font-size:9px">${esc(a.vendor)}</span>`:''}
        ${applied?`<span style="margin-left:8px;display:flex;flex-wrap:wrap;gap:2px">${applied}</span>`:''}
        <span style="margin-left:auto;color:var(--text-muted);font-size:11px">${a.rules.length} rules</span>
      </summary>
      <div class="tbl-wrap" style="border-radius:0;margin:0">
        <table class="data-table"><thead><tr>
          <th>${tr('acl.col_seq')}</th><th>${tr('acl.col_action')}</th><th>${tr('acl.col_proto')}</th>
          <th>${tr('acl.col_src')}</th><th>${tr('acl.col_dst')}</th><th>${tr('acl.col_port')}</th><th>${tr('acl.col_remark')}</th>
        </tr></thead><tbody>${rulesHtml}</tbody></table>
      </div>
    </details>`;
  }).join('');
  return`<div class="tbar"><div class="search-wrap"><span class="search-ico">🔍</span><input class="search-inp" id="search-inp" placeholder="${tr('search.placeholder')}" oninput="debouncedRenderView('acl')"></div></div>`
    +cards
    +`<div style="overflow-y:auto;flex:1;min-height:0;padding:8px 16px">${aclCards}</div>`
    +(filtered.length<acls.length?`<div class="tbl-foot"><span>${filtered.length} / ${acls.length} ACLs</span></div>`:'');
}
// standards：僅供參考的常見資安標準關聯條號（業界廣泛公開引用的控制編號與主題，
// 非逐字引用付費標準內容），純資訊性標籤，不代表通過此工具檢查即符合該標準認證
function analyzeSwitchAudit(parsed){
  const findings=[];
  const f=(id,check,value,risk,detail,standards)=>findings.push({id,check,value,risk,detail,standards:standards||[]});
  // standards：僅供參考的常見資安標準關聯條號，純資訊性標籤，不代表通過此工具檢查即符合該標準認證。
  // ISO27001 條號為 2022 版 Annex A 編號，依 ISMS.online／High Table／Voragosecurity 等公開次級來源
  // 交叉核對官方 2013→2022 對照表查證（2026-07-22，非直接核對付費原文），比照 firewall_analyzer
  // analyzeCompliance() 同批查證結果；NIST 800-53/CIS v8 沿用既有引用。
  // 1. 弱/明文密碼
  const users=parsed.users||[];
  const weakPwd=users.filter(u=>u.pwdWeak);
  f('weak-pwd', tr('audit.check_weak_pwd'), weakPwd.length, 'high',
    weakPwd.length ? weakPwd.map(u=>u.name).slice(0,8).join(', ')+(weakPwd.length>8?'…':'') : tr('audit.none'),
    ['ISO27001 A.8.5','NIST 800-53 IA-5','CIS v8 5.2']);
  // 2. STP Edge Port 未開 BPDU Guard（RouterOS 的 parsed.stp 形狀不同，無 ports[]，需排除）
  const stpPorts=Array.isArray(parsed?.stp?.ports)?parsed.stp.ports:[];
  const noBpduGuard=stpPorts.filter(p=>p.portfast&&!p.bpduguard);
  f('stp-no-bpduguard', tr('audit.check_stp_no_bpduguard'), noBpduGuard.length, 'medium',
    noBpduGuard.length ? noBpduGuard.map(p=>p.port).slice(0,8).join(', ')+(noBpduGuard.length>8?'…':'') : tr('audit.none'),
    ['ISO27001 A.8.20','NIST 800-53 SC-7','CIS v8 12.2']);
  // 3. VLAN 1（預設/原生 VLAN）仍用於使用者流量——空值代表未明確宣告，實際設備行為預設落在 VLAN1
  const interfaces=parsed.interfaces||[];
  const vlan1Ports=interfaces.filter(i=>(i.mode==='access'||i.mode==='trunk')&&(!i.nativeVlan||i.nativeVlan==='1'));
  f('vlan1-inuse', tr('audit.check_vlan1_inuse'), vlan1Ports.length, 'medium',
    vlan1Ports.length ? vlan1Ports.map(i=>i.name).slice(0,8).join(', ')+(vlan1Ports.length>8?'…':'') : tr('audit.none'),
    ['ISO27001 A.8.22','NIST 800-53 SC-7','CIS v8 12.2']);
  // 4. 802.1X／Port Security 均未啟用——涵蓋範圍有限（部分廠牌真實語法與通用解析不符），detail 附加警語
  const security=parsed.security||[];
  const noAuth=security.filter(s=>s.dot1x==='-'&&!s.portSec);
  f('security-off', tr('audit.check_security_off'), noAuth.length, 'medium',
    (noAuth.length ? noAuth.map(s=>s.port).slice(0,8).join(', ')+(noAuth.length>8?'…':'') : tr('audit.none'))+' '+tr('audit.security_coverage_note'),
    ['ISO27001 A.5.15','NIST 800-53 IA-3','CIS v8 13.9']);
  // 5. SNMP v1/v2c 仍啟用（2026-07-22 新增：13 廠牌逐一查證官方 CLI 文件後新增 parseSNMP()）
  const snmp=parsed.snmp;
  const hasV1v2=snmp&&snmp.communities&&snmp.communities.length>0;
  f('snmp-weak', tr('audit.check_snmp_weak'), hasV1v2?snmp.communities.length:0, 'high',
    hasV1v2?snmp.communities.map(c=>c.name).slice(0,8).join(', ')+(snmp.communities.length>8?'…':'')+' '+tr('audit.rec_snmpv3_sw'):tr('audit.none'),
    ['ISO27001 A.8.24','NIST 800-53 IA-5','CIS v8 4.8']);
  // 6. 管理介面允許 Telnet（2026-07-22 新增：13 廠牌逐一查證官方 CLI 文件後新增 parseMgmtAccess()，
  // 各廠牌「未設定時預設值」不同，已依查證結果分別處理，詳見 parseMgmtAccess() 註解）
  const mgmtAccess=parsed.mgmtAccess;
  const telnetOn=!!(mgmtAccess&&mgmtAccess.telnet);
  f('telnet-mgmt', tr('audit.check_telnet_mgmt'), telnetOn?1:0, 'high',
    telnetOn?tr('audit.telnet_enabled_detail'):tr('audit.none'),
    ['ISO27001 A.5.15','NIST 800-53 AC-17','CIS v8 12.3']);
  // 7. OSPF/BGP/RIP 未設定認證（2026-07-22 新增：13 廠牌逐一查證官方 CLI 文件後新增
  // parseRoutingAuth()。判斷粒度為整份設定檔「該通訊協定是否至少有一處認證設定」，非逐
  // area/neighbor 精確比對；查無官方佐證逐字語法的廠牌/協定組合回傳 null，視為不評估
  // （不計入分子也不計入分母），detail 附加涵蓋範圍警語）
  const _protoConfigured=p=>Array.isArray(p)?p.length>0:!!(p&&typeof p==='object'&&Object.keys(p).length>0);
  const ra=parsed.routingAuth||{};
  const noRoutingAuth=[];
  if(ra.ospf===false&&_protoConfigured(parsed.ospf))noRoutingAuth.push('OSPF');
  if(ra.bgp===false&&_protoConfigured(parsed.bgp))noRoutingAuth.push('BGP');
  if(ra.rip===false&&_protoConfigured(parsed.rip))noRoutingAuth.push('RIP');
  f('routing-no-auth', tr('audit.check_routing_no_auth'), noRoutingAuth.length, 'medium',
    (noRoutingAuth.length?noRoutingAuth.join(', '):tr('audit.none'))+' '+tr('audit.routing_auth_coverage_note'),
    ['ISO27001 A.8.20','NIST 800-53 IA-3','CIS v8 4.4']);
  return findings;
}
function renderAudit(){
  const findings=analyzeSwitchAudit(parsed);
  const hi=findings.filter(f=>f.risk==='high').length;
  const med=findings.filter(f=>f.risk==='medium').length;
  const cards=`<div class="sum-cards">
    <div class="sum-card"><div class="sv">${findings.length}</div><div class="sl">${tr('audit.sum_total')}</div></div>
    <div class="sum-card"><div class="sv" style="color:var(--red)">${hi}</div><div class="sl">${tr('audit.sum_high')}</div></div>
    <div class="sum-card"><div class="sv" style="color:var(--orange)">${med}</div><div class="sl">${tr('audit.sum_medium')}</div></div>
  </div>`;
  const disclaimer=`<div style="color:var(--text-dim);font-size:11px;margin:8px 0">${esc(tr('audit.standards_disclaimer'))}</div>`;
  const hdrs=[
    {key:'check',label:tr('audit.col_check')},
    {key:'value',label:tr('audit.col_result')},
    {key:'risk',label:tr('audit.col_risk')},
    {key:'detail',label:tr('audit.col_detail')},
    {key:'standards',label:tr('audit.col_standards')},
  ];
  const fmtRows=findings.map(f=>({...f,
    value: `<span class="mono" style="color:${f.value>0&&f.risk!=='low'?'var(--red)':'var(--green)'};font-weight:600">${f.value}</span>`,
    risk: f.risk==='high'?pill('down',tr('audit.risk_high')):f.risk==='medium'?pill('warn',tr('audit.risk_mid')):pill('info',tr('audit.risk_low')),
    detail: `<span style="color:var(--text-dim);font-size:11px">${esc(f.detail)}</span>`,
    standards: (f.standards||[]).map(s=>`<span style="display:inline-block;margin:1px 3px 1px 0;padding:1px 6px;border-radius:3px;font-size:10px;background:var(--surface2);color:var(--text-dim);border:1px solid var(--border)">${esc(s)}</span>`).join('')||'-',
  }));
  fmtRows.forEach(r=>{r.check_html=esc(r.check);r.value_html=r.value;r.risk_html=r.risk;r.detail_html=r.detail;r.standards_html=r.standards;});
  tableData=findings; tableKeys=['check','value','risk','detail','standards'];
  const {html}=renderTable(hdrs,fmtRows,null);
  return `<div style="font-size:13px;font-weight:600;color:var(--purple);margin-bottom:6px">${tr('audit.sw_title')}</div>`
    +cards+disclaimer
    +`<div style="overflow-x:auto"><div class="tbl-wrap">${html}</div></div>`;
}
function exportAuditCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  const findings=analyzeSwitchAudit(parsed);
  dlCSV(
    findings.map(f=>[f.check,f.value,f.risk,f.detail,(f.standards||[]).join('; ')]),
    [tr('audit.col_check'),tr('audit.col_result'),tr('audit.col_risk'),tr('audit.col_detail'),tr('audit.col_standards')],
    `${hn()}_audit.csv`
  );
}
function renderSecurity(){
  const rows=parsed.security||[];
  if(!rows.length)return`<div class="nodata">${tr('sec.none')}</div>`;
  const dot1xCount=rows.filter(r=>r.dot1x!=='-').length;
  const psCount=rows.filter(r=>r.portSec).length;
  const cards=`<div class="sum-cards">
    <div class="sum-card"><div class="sv">${rows.length}</div><div class="sl">${tr('sec.total')}</div></div>
    <div class="sum-card"><div class="sv" style="color:var(--purple)">${dot1xCount}</div><div class="sl">802.1X</div></div>
    <div class="sum-card"><div class="sv" style="color:var(--orange)">${psCount}</div><div class="sl">${tr('sec.port_sec')}</div></div>
  </div>`;
  const hdrs=[
    {key:'port',label:tr('col.interface')},
    {key:'dot1x',label:'802.1X'},
    {key:'portSec',label:tr('sec.port_sec')},
    {key:'maxMac',label:tr('sec.max_mac')},
    {key:'violation',label:tr('sec.violation')},
    {key:'guestVlan',label:tr('sec.guest_vlan')},
  ];
  const fmtRows=rows.map(r=>({...r,
    dot1x_html: r.dot1x!=='-'?`<span class="pill p-purple" style="font-size:10px">${r.dot1x}</span>`:'-',
    portSec_html: r.portSec?`<span class="pill p-warn" style="font-size:10px">ON</span>`:`<span style="color:var(--text-muted)">-</span>`,
    violation_html: r.violation!=='-'?`<span class="pill p-deny" style="font-size:10px">${r.violation}</span>`:'-',
  }));
  tableData=rows; tableKeys=['port','dot1x','portSec','maxMac','violation','guestVlan'];
  const {html,count}=renderTable(hdrs,fmtRows,null);
  return cards+mkTbar('search-inp',null,null)+`<div class="tbl-wrap">${html}</div><div class="tbl-foot"><span>${count} / ${rows.length} ${tr('unit.count')}</span></div>`;
}
function renderQoS(){
  const rows=parsed.qos||[];
  if(!rows.length)return`<div class="nodata">${tr('qos.none')}</div>`;
  const pols=[...new Set(rows.map(r=>r.policy))];
  const cards=`<div class="sum-cards">
    <div class="sum-card"><div class="sv">${pols.length}</div><div class="sl">${tr('qos.policies')}</div></div>
    <div class="sum-card"><div class="sv" style="color:var(--accent)">${rows.length}</div><div class="sl">${tr('qos.classes')}</div></div>
  </div>`;
  const hdrs=[
    {key:'policy',label:tr('qos.policy')},
    {key:'cls',label:tr('qos.class')},
    {key:'action',label:tr('qos.action')},
    {key:'rate',label:tr('qos.rate')},
    {key:'burst',label:tr('qos.burst')},
    {key:'behavior',label:tr('qos.behavior')},
  ];
  const fmtRows=rows.map(r=>({...r,
    action_html: r.action!=='-'?`<span class="pill p-info" style="font-size:10px">${r.action}</span>`:'-',
    rate_html: r.rate!=='-'?`<span class="mono" style="font-size:11px">${esc(String(r.rate))}</span>`:'-',
    behavior_html: r.behavior?`<span style="color:var(--text-muted);font-size:11px">${esc(r.behavior)}</span>`:'-',
  }));
  tableData=rows; tableKeys=['policy','cls','action','rate','burst','behavior'];
  const {html,count}=renderTable(hdrs,fmtRows,null);
  return cards+mkTbar('search-inp',null,null)+`<div class="tbl-wrap">${html}</div><div class="tbl-foot"><span>${count} / ${rows.length} ${tr('unit.count')}</span></div>`;
}
function renderSTP(){
  const s=parsed?.stp;
  if(!s||(!s.mode&&!s.instances.length&&!s.ports.length)){
    return `<div class="nodata">${tr('stp.no_stp')}</div>
    <div style="margin:16px;color:var(--text-muted);font-size:13px">
      <b>${tr('stp.cmd_hint')}</b><br>
      Cisco IOS/NX-OS: <code>show spanning-tree detail</code><br>
      Comware (H3C): <code>display stp brief</code><br>
      Aruba CX: <code>show spanning-tree detail</code><br>
      Dell OS10: <code>show spanning-tree</code><br>
      Juniper: <code>show spanning-tree interface</code><br>
      ExtremeXOS: <code>show stpd detail</code>
    </div>`;
  }
  const pfCount=s.ports.filter(p=>p.portfast).length;
  const bgCount=s.ports.filter(p=>p.bpduguard).length;
  const rgCount=s.ports.filter(p=>p.guardRoot).length;
  // Root Bridge Banner
  let rootBanner='';
  if(s.rootMode==='primary'){
    rootBanner=`<div style="padding:10px 16px;border-radius:8px;background:color-mix(in srgb,var(--green) 15%,var(--bg2));border:1px solid var(--green);margin-bottom:12px;font-weight:600;font-size:13px;display:flex;align-items:center;gap:8px">
      ${tr('stp.root_primary')}
    </div>`;
  } else if(s.rootMode==='secondary'){
    rootBanner=`<div style="padding:10px 16px;border-radius:8px;background:color-mix(in srgb,var(--orange) 15%,var(--bg2));border:1px solid var(--orange);margin-bottom:12px;font-weight:600;font-size:13px;display:flex;align-items:center;gap:8px">
      ${tr('stp.root_secondary')}
    </div>`;
  }
  // Timers row
  let timersRow='';
  if(s.timers&&(s.timers.hello!=null||s.timers.forwardDelay!=null||s.timers.maxAge!=null)){
    timersRow=`<div style="margin-bottom:16px;padding:8px 16px;background:var(--bg2);border-radius:6px;border:1px solid var(--border);font-size:13px;display:flex;gap:24px;flex-wrap:wrap;align-items:center">
      <span style="color:var(--text-muted);font-size:12px">${tr('stp.timers')}:</span>
      ${s.timers.hello!=null?`<span><b>${tr('stp.hello')}</b>: ${s.timers.hello}s</span>`:''}
      ${s.timers.forwardDelay!=null?`<span><b>${tr('stp.fwd_delay')}</b>: ${s.timers.forwardDelay}s</span>`:''}
      ${s.timers.maxAge!=null?`<span><b>${tr('stp.max_age')}</b>: ${s.timers.maxAge}s</span>`:''}
    </div>`;
  }
  const cards=`<div class="sum-cards">
    <div class="sum-card"><div class="sv">${esc(s.mode||'—')}</div><div class="sl">${tr('stp.mode')}</div></div>
    <div class="sum-card"><div class="sv">${s.instances.length}</div><div class="sl">${tr('stp.col_vlan')}</div></div>
    <div class="sum-card"><div class="sv">${pfCount}</div><div class="sl">${tr('stp.col_portfast')}</div></div>
    <div class="sum-card"><div class="sv">${bgCount}</div><div class="sl">${tr('stp.col_bpduguard')}</div></div>
    <div class="sum-card"><div class="sv">${rgCount}</div><div class="sl">${tr('stp.col_rootguard')}</div></div>
  </div>`;
  let instTable='';
  if(s.instances.length){
    instTable=`<h3 style="margin:16px 0 8px;font-size:14px;color:var(--text)">${tr('stp.col_vlan')} / Instance</h3>
    <div class="tbl-wrap"><table class="data-table"><thead><tr>
      <th>${tr('stp.col_vlan')}</th><th>${tr('stp.col_prio')}</th>
    </tr></thead><tbody>
    ${s.instances.map(i=>`<tr>
      <td class="mono">${esc(i.vlan)}</td>
      <td>${i.priority}${i.priority===0?` <span class="pill p-allow" style="font-size:9px">Root?</span>`:''}</td>
    </tr>`).join('')}
    </tbody></table></div>`;
  }
  let portTable='';
  if(s.ports.length){
    portTable=`<h3 style="margin:16px 0 8px;font-size:14px;color:var(--text)">${tr('stp.col_port')}</h3>
    <div class="search-wrap"><span class="search-ico">🔍</span><input class="search-inp" id="search-inp" placeholder="${tr('search.placeholder')}" oninput="debouncedRenderView('stp')"></div>
    <div class="tbl-wrap"><table class="data-table"><thead><tr>
      <th>${tr('stp.col_port')}</th>
      <th>${tr('stp.col_portfast')}</th>
      <th>${tr('stp.col_protect')}</th>
      <th>Cost</th>
      <th>${tr('stp.port_prio')}</th>
    </tr></thead><tbody>
    ${s.ports.filter(p=>{const q=(document.getElementById('search-inp')?.value||'').toLowerCase();return !q||p.port.toLowerCase().includes(q);}).map(p=>{
      const protections=[];
      if(p.bpduguard)protections.push(pill('BPDU Guard','p-warn'));
      if(p.guardRoot)protections.push(pill('Root Guard','p-info'));
      return `<tr>
        <td class="mono">${esc(p.port)}</td>
        <td>${p.portfast?pill(tr('val.yes'),'p-allow'):pill(tr('val.no'),'p-dim')}</td>
        <td>${protections.length?protections.join(' '):pill('—','p-dim')}</td>
        <td>${p.cost||'—'}</td>
        <td>${p.priority||'—'}</td>
      </tr>`;
    }).join('')}
    </tbody></table></div>`;
  }
  return `<div class="sec-title">${tr('stp.title')}</div>${rootBanner}${timersRow}${cards}${instTable}${portTable}`;
}
function doPrint(){
  const h=document.getElementById('print-header');
  if(h&&parsed)h.innerHTML=`<b>${esc(parsed.sys.hostname||'')}</b> &nbsp;·&nbsp; ${esc(parsed.vendor||'')} &nbsp;·&nbsp; ${new Date().toLocaleString('zh-TW')}`;
  window.print();
}

// ── VSF SVG for HTML report (orange theme, same structure as buildStackWiseSVG) ──
function buildVSFSVGReport(p){
  const s=p.stack;
  const mems=s.members;
  const tc='#f97316'; // Aruba orange
  const boxW=158,boxH=188,gap=Math.max(200,720/(mems.length||1));
  const W=Math.max(720,mems.length*gap+100),H=400;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2),bY=96;
  const boxes=mems.map((m,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m,
    ports:p.interfaces.filter(ii=>ii.member===m.id&&ii.type==='physical'&&ii.name.startsWith(m.id+'/')).length,
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif;max-width:100%">
<defs>
<marker id="varr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="vglow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">VSF STACK TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-110}" y="11" width="98" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-61}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">Aruba VSF</text>`;
  for(let i=0;i<mems.length;i++){
    if(i===mems.length-1)break;
    const a=boxes[i],b=boxes[i+1];
    const lnk=s.links?.[i];
    const lbl=lnk?lnk.ports.slice(0,2).join(' | '):'';
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#varr)"/>`;
    if(lbl){const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;svg+=`<rect x="${mx-50}" y="${my-10}" width="100" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/><text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${lbl}</text>`;}
  }
  boxes.forEach((bx)=>{
    const m=bx.mem,isMaster=m.role==='Master';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#1e3a5f'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#vglow)"':''}/>`;
    if(isMaster)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".025"/>`;
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.18:.07}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#64748b'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">M${m.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#2c3e58'}" text-anchor="end" font-weight="600">${m.role||''}</text>`;
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#1e3a5f" stroke-width="1"/>`;
    const pc=Math.min(bx.ports,16);
    for(let pi=0;pi<pc;pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.42:.2}"/>`;}
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#1e3a5f" stroke-width=".5"/>
    <text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.model')}</text><text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="9.5" fill="#dde8f5" text-anchor="end" font-family="JetBrains Mono,monospace">${(m.model||'—').replace(/^JL/i,'JL')}</text>
    <text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text><text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${m.priority||'—'}</text>
    <text x="${bx.x+16}" y="${bx.y+140}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.port_count')}</text><text x="${bx.x+boxW-14}" y="${bx.y+140}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports}</text>`;
    const tpCount=p.interfaces.filter(ii=>ii.member===m.id&&ii.mode==='trunk').length;
    if(tpCount)svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-24}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/><polygon points="${bx.cx},${bx.y-28} ${bx.cx-5},${bx.y-20} ${bx.cx+5},${bx.y-20}" fill="${tc}" opacity=".5"/><text x="${bx.cx}" y="${bx.y-33}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Trunk×${tpCount}</text>`;
  });
  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#1e3a5f" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Master</text>
  <rect x="100" y="${lY+8}" width="10" height="10" rx="2" fill="#1e3a5f"/>
  <text x="116" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby/Member</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#2c3e58" text-anchor="end" font-family="JetBrains Mono,monospace">Aruba CX VSF</text>`;
  svg+=`</svg>`;
  return svg;
}

// ── Stack topology section for HTML report ─────────────────
// ── VLT Topology SVG for HTML report ─────────────────────────

// ── Juniper Virtual Chassis topology ──────────────────────
function renderVC(){
  const s=parsed.stack;
  if(!s||!s.members.length)
    return`<div class="nodata">${tr('msg.no_vc')}</div>`;
  const tc='#9c27b0'; // Juniper purple
  const boxW=162,boxH=192,gap=Math.max(200,720/(s.members.length||1));
  const W=Math.max(720,s.members.length*gap+100),H=400;
  const startX=Math.max(28,(W-gap*(s.members.length-1)-boxW)/2),bY=96;
  const boxes=s.members.map((m,i)=>({x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m,
    ports:parsed.interfaces.filter(ii=>{
      const mid=m.id; return ii.type==='physical'&&(ii.name.startsWith('ge-'+mid+'/')||ii.name.startsWith('xe-'+mid+'/')||ii.name.startsWith('et-'+mid+'/'));
    }).length}));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif;max-width:100%">
<defs><marker id="vcarr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="vcglow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">VIRTUAL CHASSIS${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(parsed.sys.hostname)}</text>
<rect x="${W-120}" y="11" width="108" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-66}" y="30" font-size="11" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">Juniper VC</text>`;
  for(let i=0;i<s.members.length;i++){
    if(i===s.members.length-1)break;
    const a=boxes[i],b=boxes[i+1];
    const lnk=s.links?.[i];
    const lbl=lnk?.desc||'VC-Port';
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#vcarr)"/>`;
    const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;
    svg+=`<rect x="${mx-42}" y="${my-10}" width="84" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/>
    <text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${esc(lbl)}</text>`;
  }
  boxes.forEach((bx)=>{
    const m=bx.mem,isMaster=m.role==='Master';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#2d1b4e'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#vcglow)"':''}/>`;
    if(isMaster)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".03"/>`;
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.2:.08}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#7c3aed'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">M${m.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#4c1d95'}" text-anchor="end" font-weight="600">${esc(m.role||'')}</text>`;
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#2d1b4e" stroke-width="1"/>`;
    const pc=Math.min(bx.ports||8,16);
    for(let pi=0;pi<(pc||8);pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.45:.18}"/>`;}
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#2d1b4e" stroke-width=".5"/>
    <text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#4c1d95" font-family="JetBrains Mono,monospace">S/N</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="8.5" fill="#dde8f5" text-anchor="end" font-family="JetBrains Mono,monospace">${esc((m.serial||'—').slice(0,14))}</text>
    <text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#4c1d95" font-family="JetBrains Mono,monospace">${tr('col.role')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="10" fill="${tc}" text-anchor="end" font-weight="600" font-family="JetBrains Mono,monospace">${esc(m.roleDesc||m.role||'—')}</text>
    <text x="${bx.x+16}" y="${bx.y+140}" font-size="9" fill="#4c1d95" font-family="JetBrains Mono,monospace">${tr('col.port_count')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+140}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports||'—'}</text>`;
  });
  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#2d1b4e" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Master RE</text>
  <rect x="110" y="${lY+8}" width="10" height="10" rx="2" fill="#2d1b4e"/>
  <text x="126" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby / Line-Card</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#4c1d95" text-anchor="end" font-family="JetBrains Mono,monospace">Juniper Virtual Chassis</text>`;
  svg+=`</svg>`;
  return`<div style="flex:1;overflow-y:auto">
    <div class="export-row"><button class="btn btn-ghost btn-sm" onclick="exportTopoSVG()">⬇ ${tr('irf.export_svg')}</button></div>
    <div class="topo-wrap">${svg}</div>
    <div style="padding:0 18px 14px"><div class="ov-card">
      <div class="ov-card-title">📋 ${tr('stack.vc_list')}</div>
      <table class="data-tbl"><tr><th>${tr('col.member_id')}</th><th>${tr('col.role')}</th><th>${tr('col.serial')}</th><th>${tr('col.priority')}</th><th>${tr('col.port_count')}</th></tr>
      ${s.members.map(m=>{
        const pcount=parsed.interfaces.filter(i=>i.type==='physical'&&(i.name.startsWith('ge-'+m.id+'/')||i.name.startsWith('xe-'+m.id+'/'))).length;
        return`<tr><td>${pill('p-stack','M'+m.id)}</td>
          <td class="mono">${esc(m.roleDesc||m.role||'—')}</td>
          <td class="mono" style="font-size:11px">${esc(m.serial||'—')}</td>
          <td class="mono" style="color:var(--yellow)">${m.priority}</td>
          <td class="mono">${pcount}</td></tr>`;
      }).join('')}
      </table>
    </div></div>
  </div>`;
}

// ── Alcatel Stack SVG (teal/green theme) ──────────────────
function buildAlcatelStackSVG(p){
  const s=p.stack;
  const mems=s.members;
  const tc='#00a064'; // Alcatel green
  const boxW=160,boxH=192,gap=Math.max(200,720/(mems.length||1));
  const W=Math.max(720,mems.length*gap+100),H=400;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2),bY=96;
  const boxes=mems.map((mem,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem,
    ports:p.interfaces.filter(ii=>{
      const slot=mem.id;
      return ii.type==='physical'&&(ii.name.startsWith(slot+'/')||ii.name.startsWith(slot+'/'));
    }).length
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif;max-width:100%">
<defs>
<marker id="aarr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="aglow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">ALCATEL STACK${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-130}" y="11" width="118" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-71}" y="30" font-size="11" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">OmniSwitch Stack</text>`;

  // Draw stack links
  for(let i=0;i<boxes.length-1;i++){
    const a=boxes[i],b=boxes[i+1];
    const lnk=s.links?.[i];
    const lbl=lnk?.ports?.slice(0,2).join(' | ')||lnk?.desc||'Stack Port';
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#aarr)"/>`;
    const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;
    svg+=`<rect x="${mx-50}" y="${my-10}" width="100" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/>
    <text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${esc(lbl)}</text>`;
  }

  // Draw member boxes
  boxes.forEach((bx)=>{
    const mem=bx.mem,isMaster=mem.role==='Master';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#0d3320'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#aglow)"':''}/>`;
    if(isMaster)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".025"/>`;
    // Member badge
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.2:.07}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#1a6640'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">Slot ${mem.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#1a6640'}" text-anchor="end" font-weight="600">${esc(mem.role||'')}</text>`;
    // Port slots visual
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#0d3320" stroke-width="1"/>`;
    const pc=Math.min(bx.ports||12,16);
    for(let pi=0;pi<(pc||12);pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.45:.18}"/>`;}
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#0d3320" stroke-width=".5"/>
    <text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#1a6640" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${mem.priority||'—'}</text>
    <text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#1a6640" font-family="JetBrains Mono,monospace">${tr('col.port_count')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports||'—'}</text>
    <text x="${bx.x+16}" y="${bx.y+140}" font-size="9" fill="#1a6640" font-family="JetBrains Mono,monospace">${tr('col.model')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+140}" font-size="10" fill="#dde8f5" text-anchor="end" font-family="JetBrains Mono,monospace">${esc(mem.model||'OmniSwitch')}</text>`;
    // Trunk uplink indicator
    const tpCount=p.interfaces.filter(ii=>ii.member===mem.id&&ii.mode==='trunk').length;
    if(tpCount)svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-24}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/>
    <polygon points="${bx.cx},${bx.y-28} ${bx.cx-5},${bx.y-20} ${bx.cx+5},${bx.y-20}" fill="${tc}" opacity=".5"/>
    <text x="${bx.cx}" y="${bx.y-33}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Trunk×${tpCount}</text>`;
  });

  // Legend
  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#0d3320" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Master</text>
  <rect x="100" y="${lY+8}" width="10" height="10" rx="2" fill="#0d3320"/>
  <text x="116" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby/Member</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#1a6640" text-anchor="end" font-family="JetBrains Mono,monospace">Alcatel OmniSwitch Stack</text>`;
  svg+=`</svg>`;
  return svg;
}

// ── renderAlcatelStack (interactive view) ────────────────
function renderAlcatelStack(){
  const s=parsed.stack;
  if(!s||!s.members.length)
    return`<div class="nodata">${tr('msg.no_alcatel_pre')}<br><span style="font-size:11px;color:var(--text-muted)">${tr('msg.no_alcatel_sub')}</span></div>`;

  const svgStr=buildAlcatelStackSVG(parsed);
  return`<div style="flex:1;overflow-y:auto">
    <div class="export-row"><button class="btn btn-ghost btn-sm" onclick="exportTopoSVG()">⬇ ${tr('irf.export_svg')}</button></div>
    <div class="topo-wrap">${svgStr}</div>
    <div style="padding:0 18px 14px"><div class="ov-card">
      <div class="ov-card-title">${tr('stack.member_list_card')}</div>
      <table class="data-tbl">
        <thead><tr><th>${tr('col.slot')}</th><th>${tr('col.role')}</th><th>${tr('col.priority')}</th><th>${tr('col.model')}</th><th>${tr('col.stack_port')}</th></tr></thead>
        <tbody>
        ${s.members.map(mem=>{
          const stackPorts=s.links?.flatMap(l=>l.ports?.filter(p=>p.startsWith(mem.id+'/'))||[])||[];
          return`<tr>
            <td>${pill('p-stack','Slot '+mem.id)}</td>
            <td class="mono">${esc(mem.role||'—')}</td>
            <td class="mono" style="color:var(--yellow)">${mem.priority||'—'}</td>
            <td class="mono">${esc(mem.model||'OmniSwitch')}</td>
            <td class="mono" style="font-size:11px">${stackPorts.join(', ')||'—'}</td>
          </tr>`;
        }).join('')}
        </tbody>
      </table>
      ${s.links?.length?`
      <div class="ov-card-title" style="margin-top:14px">🔗 ${tr('stack.link_count')}</div>
      <table class="data-tbl">
        <thead><tr><th>${tr('col.link')}</th><th>${tr('col.desc_short')}</th><th>${tr('col.port_pos')}</th></tr></thead>
        <tbody>
        ${s.links.map(lnk=>`<tr>
          <td>${pill('p-stack','Link '+lnk.id)}</td>
          <td class="mono">${esc(lnk.desc||'—')}</td>
          <td class="mono" style="font-size:11px">${(lnk.ports||[]).join(', ')||'—'}</td>
        </tr>`).join('')}
        </tbody>
      </table>`:''}
    </div></div>
  </div>`;
}

// ── ExtremeXOS Stack SVG (purple theme) ─────────────────────
function buildExtremeStackSVG(p){
  const s=p.stack;
  const mems=s.members;
  const tc='#7928ca'; // Extreme purple
  const boxW=162,boxH=196,gap=Math.max(200,740/(mems.length||1));
  const W=Math.max(740,mems.length*gap+100),H=410;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2),bY=96;
  const boxes=mems.map((mem,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem,
    ports:p.interfaces.filter(ii=>ii.type==='physical').length
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif;max-width:100%">
<defs>
<marker id="earr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="eglow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">EXTREME NETWORKS  EXTREMESTACK</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-140}" y="11" width="128" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-76}" y="30" font-size="11" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">ExtremeStack</text>`;

  // Links
  for(let i=0;i<boxes.length-1;i++){
    const a=boxes[i],b=boxes[i+1];
    const lnk=s.links?.[i];
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#earr)"/>`;
    const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;
    svg+=`<rect x="${mx-55}" y="${my-10}" width="110" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/>
    <text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${esc(lnk?.desc||'SummitStack Link')}</text>`;
  }

  // Boxes
  boxes.forEach((bx)=>{
    const mem=bx.mem,isMaster=mem.role==='Master';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#2d0d5c'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#eglow)"':''}/>`;
    if(isMaster)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".025"/>`;
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.2:.07}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#4a1a8c'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">Slot ${mem.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#4a1a8c'}" text-anchor="end" font-weight="600">${esc(mem.role||'')}</text>`;
    // Port visual
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#2d0d5c" stroke-width="1"/>`;
    for(let pi=0;pi<16;pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.45:.15}"/>`;}
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#2d0d5c" stroke-width=".5"/>
    <text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#4a1a8c" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${mem.priority||'—'}</text>
    <text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#4a1a8c" font-family="JetBrains Mono,monospace">${tr('col.model')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="10" fill="#dde8f5" text-anchor="end" font-family="JetBrains Mono,monospace">${esc((mem.model||'ExtremeXOS').replace('SummitX','X'))}</text>
    <text x="${bx.x+16}" y="${bx.y+143}" font-size="9" fill="#4a1a8c" font-family="JetBrains Mono,monospace">${tr('col.full_model')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+160}" font-size="8" fill="#64748b" text-anchor="end" font-family="JetBrains Mono,monospace">${esc(mem.model||'—')}</text>`;
    if(isMaster){
      svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-24}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/>
      <polygon points="${bx.cx},${bx.y-28} ${bx.cx-5},${bx.y-20} ${bx.cx+5},${bx.y-20}" fill="${tc}" opacity=".5"/>
      <text x="${bx.cx}" y="${bx.y-33}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Master</text>`;
    }
  });

  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#2d0d5c" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Master / Primary</text>
  <rect x="120" y="${lY+8}" width="10" height="10" rx="2" fill="#2d0d5c"/>
  <text x="136" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby / Member</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#4a1a8c" text-anchor="end" font-family="JetBrains Mono,monospace">Extreme Networks ExtremeXOS</text>`;
  svg+=`</svg>`;
  return svg;
}

function renderExtremeStack(){
  const s=parsed.stack;
  if(!s||!s.members.length)
    return`<div class="nodata">${tr('msg.no_extreme_pre')}<br><span style="font-size:11px;color:var(--text-muted)">${tr('msg.no_extreme_sub')}</span></div>`;
  const svgStr=buildExtremeStackSVG(parsed);
  return`<div style="flex:1;overflow-y:auto">
    <div class="export-row"><button class="btn btn-ghost btn-sm" onclick="exportTopoSVG()">⬇ ${tr('irf.export_svg')}</button></div>
    <div class="topo-wrap">${svgStr}</div>
    <div style="padding:0 18px 14px"><div class="ov-card">
      <div class="ov-card-title">${tr('stack.member_list_card')}</div>
      <table class="data-tbl">
        <thead><tr><th>${tr('col.slot')}</th><th>${tr('col.role')}</th><th>${tr('col.priority')}</th><th>${tr('col.model')}</th></tr></thead>
        <tbody>
        ${s.members.map(mem=>`<tr>
          <td>${pill('p-stack','Slot '+mem.id)}</td>
          <td class="mono">${esc(mem.role||'—')}</td>
          <td class="mono" style="color:var(--yellow)">${mem.priority||'—'}</td>
          <td class="mono" style="font-size:11px">${esc(mem.model||'ExtremeXOS')}</td>
        </tr>`).join('')}
        </tbody>
      </table>
    </div></div>
  </div>`;
}

function buildICXStackSVG(p){
  const stk=p.stack;
  const mems=stk.members||[];
  const links=stk.links||[];
  const tc='#f87171'; // Brocade red
  const boxW=160, boxH=130, gap=Math.max(210, 760/(mems.length||1));
  const W=Math.max(760, mems.length*gap+100);
  const H=300;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2);
  const bY=80;
  const boxes=mems.map((m,i)=>({x:startX+i*gap, cx:startX+i*gap+boxW/2, y:bY, mem:m}));
  const esc2=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="max-width:100%;font-family:'JetBrains Mono',monospace">
<defs>
<marker id="icx-arr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="icx-glow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<linearGradient id="icx-hg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="${tc}" stop-opacity=".18"/><stop offset="100%" stop-color="#7f1d1d" stop-opacity=".04"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<rect x="0" y="0" width="${W}" height="50" fill="url(#icx-hg)" rx="12"/>
<rect x="0" y="38" width="${W}" height="12" fill="#080c17"/>
<text x="18" y="18" font-size="10" fill="#64748b" letter-spacing="1" font-weight="600">ICX STACK TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc2(p.sys.hostname)}</text>
<rect x="${W-156}" y="11" width="144" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-84}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle">Brocade ICX Stack</text>`;

  // Draw stack links between units
  const isRing = links.length >= mems.length;
  for(let i=0;i<boxes.length-1;i++){
    const a=boxes[i], b=boxes[i+1];
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+52} ${b.cx} ${b.y+boxH+52} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".62" marker-end="url(#icx-arr)" filter="url(#icx-glow)"/>`;
    if(links[i]?.ports?.length){
      svg+=`<text x="${(a.cx+b.cx)/2}" y="${a.y+boxH+48}" font-size="9" fill="${tc}" text-anchor="middle" opacity=".7">${esc2(links[i].ports.slice(0,2).join(' ↔ '))}</text>`;
    }
  }
  // Ring back-link if applicable
  if(isRing && boxes.length>=2){
    const a=boxes[boxes.length-1], b=boxes[0];
    svg+=`<path d="M ${a.cx} ${a.y+boxH+8} C ${a.cx} ${a.y+boxH+90} ${b.cx} ${b.y+boxH+90} ${b.cx} ${b.y+boxH+8}" stroke="${tc}" stroke-width="2" fill="none" opacity=".35" stroke-dasharray="5,3" marker-end="url(#icx-arr)"/>`;
    svg+=`<text x="${(a.cx+b.cx)/2}" y="${a.y+boxH+82}" font-size="9" fill="${tc}" text-anchor="middle" opacity=".5">Ring</text>`;
  }

  // Draw unit boxes
  for(const bx of boxes){
    const m=bx.mem;
    const isActive=m.role==='Active';
    const roleColor=isActive?'#00c8f0':m.role==='Standby'?'#10b981':'#94a3b8';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isActive?tc:'#1e3a5f'}" stroke-width="${isActive?2:1}" ${isActive?'filter="url(#icx-glow)"':''}/>`;
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="32" rx="10" fill="${tc}" opacity="${isActive?.22:.1}"/>`;
    svg+=`<rect x="${bx.x}" y="${bx.y+22}" width="${boxW}" height="10" fill="#0f1629"/>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+21}" font-size="13" fill="${isActive?tc:'#dde8f5'}" font-weight="700" text-anchor="middle">Unit ${m.id}</text>`;
    svg+=`<rect x="${bx.cx-32}" y="${bx.y+37}" width="64" height="18" rx="5" fill="${roleColor}" opacity=".18" stroke="${roleColor}" stroke-width="1"/>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+50}" font-size="10" fill="${roleColor}" font-weight="700" text-anchor="middle">${esc2(m.role||'Member')}</text>`;
    if(m.model&&m.model!=='—'){
      const shortModel=m.model.length>18?m.model.substring(0,16)+'…':m.model;
      svg+=`<text x="${bx.cx}" y="${bx.y+74}" font-size="9" fill="#94a3b8" text-anchor="middle">${esc2(shortModel)}</text>`;
    }
    if(m.priority>0)svg+=`<text x="${bx.cx}" y="${bx.y+94}" font-size="10" fill="#64748b" text-anchor="middle">prio: ${m.priority}</text>`;
  }
  svg+=`</svg>`;
  return svg;
}

function buildStackTopoSection(p){
  const hasIRF = p.vendor==='comware' && p.irf && p.irf.members.length>1;
  const hasSW  = p.vendor==='cisco'   && p.stack && p.stack.members.length>1;
  const hasVSF = p.vendor==='aruba'   && p.stack && p.stack.members.length>1;
  const hasVC  = p.vendor==='juniper'  && p.stack && p.stack.members.length>1;
  const hasALS = p.vendor==='alcatel'  && p.stack && p.stack.members.length>1;
  const hasEXS = p.vendor==='extreme'   && p.stack && p.stack.members.length>1;
  const hasICX = p.vendor==='brocade'   && p.stack && p.stack.members.length>0;
  if(!hasIRF && !hasSW && !hasVSF && !hasVC && !hasALS && !hasEXS && !hasICX) return '';

  let svgStr='', label='', memberCount=0, linkCount=0;
  if(hasIRF){
    svgStr      = buildTopoSVG(p);
    label       = tr('stack.topo_label_irf');
    memberCount = p.irf.members.length;
    linkCount   = p.irf.links.length;
  }else if(hasSW){
    svgStr      = buildStackWiseSVG(p);
    label       = tr('stack.topo_label_sw');
    memberCount = p.stack.members.length;
    linkCount   = p.stack.links.length;
  }else if(hasICX){
    svgStr      = buildICXStackSVG(p);
    label       = tr('stack.topo_label_icx');
    memberCount = p.stack.members.length;
    linkCount   = p.stack.links.length;
  }else if(p.vendor==='juniper'&&p.stack?.type==='VC'){
    svgStr      = ''; // renderVC is interactive; generate simplified SVG for report
    // Build a minimal VC SVG inline for report
    const tc='#9c27b0';
    const mems=p.stack.members;
    const bW=150,gap=Math.max(180,600/(mems.length||1));
    const W2=Math.max(600,mems.length*gap+80),H2=320;
    const sX=Math.max(20,(W2-gap*(mems.length-1)-bW)/2),bY2=80;
    let vcSvg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W2} ${H2}" width="${W2}" height="${H2}" style="max-width:100%"><rect width="${W2}" height="${H2}" fill="#080c17" rx="10"/><text x="16" y="24" font-size="11" fill="#9c27b0" font-weight="700" font-family="monospace">Virtual Chassis — ${esc(p.sys.hostname)}</text>`;
    mems.forEach((m,i)=>{const bx=sX+i*gap;const isMaster=m.role==='Master';vcSvg+=`<rect x="${bx}" y="${bY2}" width="${bW}" height="140" rx="8" fill="#0f1629" stroke="${isMaster?tc:'#2d1b4e'}" stroke-width="${isMaster?2:1}"/><text x="${bx+bW/2}" y="${bY2+26}" font-size="14" fill="${isMaster?tc:'#7c3aed'}" font-weight="700" text-anchor="middle" font-family="monospace">M${m.id}</text><text x="${bx+bW/2}" y="${bY2+48}" font-size="10" fill="#dde8f5" text-anchor="middle" font-family="monospace">${esc(m.roleDesc||m.role)}</text><text x="${bx+bW/2}" y="${bY2+70}" font-size="9" fill="#64748b" text-anchor="middle" font-family="monospace">${esc((m.serial||'').slice(0,12))}</text>`;if(i<mems.length-1){const nx=bx+bW;const nx2=sX+(i+1)*gap;vcSvg+=`<line x1="${bx+bW}" y1="${bY2+70}" x2="${nx2}" y2="${bY2+70}" stroke="${tc}" stroke-width="2" opacity=".6"/>`;}});
    vcSvg+=`</svg>`;
    svgStr      = vcSvg;
    label       = tr('stack.topo_label_vc');
    memberCount = p.stack.members.length;
    linkCount   = p.stack.links.length;
  }else if(hasALS){
    svgStr      = buildAlcatelStackSVG(p);
    label       = tr('stack.topo_label_als');
    memberCount = p.stack.members.length;
    linkCount   = p.stack.links.length;
  }else if(hasEXS){
    svgStr      = buildExtremeStackSVG(p);
    label       = tr('stack.topo_label_exs');
    memberCount = p.stack.members.length;
    linkCount   = p.stack.links.length;
  }else{
    svgStr      = buildVSFSVGReport(p);
    label       = tr('stack.topo_label_vsf');
    memberCount = p.stack.members.length;
    linkCount   = p.stack.links.length;
  }

  const masterMember =
    hasIRF  ? (p.irf.members.find(m=>m.role==='Master')  || p.irf.members[0])
    : hasSW ? (p.stack.members.find(m=>m.role==='Active') || p.stack.members[0])
    : hasICX? (p.stack.members.find(m=>m.role==='Active') || p.stack.members[0])
    :          (p.stack.members.find(m=>m.role==='Master') || p.stack.members[0]);

  const statCard = (label2, val, color) =>
    '<div style="background:#f8f9fa;border-radius:6px;padding:10px 16px;border:1px solid #e9ecef;min-width:140px">' +
    '<div style="font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#888;font-weight:600">' + label2 + '</div>' +
    '<div style="font-size:22px;font-weight:700;color:' + color + ';font-family:monospace">' + val + '</div>' +
    '</div>';

  const masterId   = masterMember ? masterMember.id       : '?';
  const masterPrio = masterMember ? (masterMember.priority||'—') : '—';

  return (
    '<div class="card" style="page-break-inside:avoid">' +
    '<h2>' + label + '</h2>' +
    '<div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap;margin-bottom:12px">' +
      statCard(tr('stack.topo_member_count'), memberCount, '#2c3e50') +
      statCard(tr('stack.topo_link_count'), linkCount, '#2c3e50') +
      statCard('Master / Active', 'M' + masterId + ' · prio:' + masterPrio, '#3498db') +
    '</div>' +
    '<div style="overflow-x:auto;border:1px solid #1e3a5f;border-radius:8px;background:#080c17;padding:8px">' +
      svgStr +
    '</div>' +
    '</div>'
  );
}

const REPORT_CSS=`*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.5;color:#333;background:#f8f9fa;padding:20px}
.wrap{max-width:1200px;margin:0 auto}
h1{color:#2c3e50;margin-bottom:20px;font-size:24px;border-left:5px solid #3498db;padding-left:12px}
h2{font-size:17px;color:#2c3e50;margin-bottom:12px;border-left:4px solid #3498db;padding-left:10px}
h3{font-size:14px;color:#555;margin:10px 0 6px;font-weight:600}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.06);padding:20px;margin-bottom:20px;border:1px solid #e8ecef}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:16px}
.meta-item{background:#f8f9fa;border-radius:6px;padding:10px 14px;border:1px solid #e9ecef}
.meta-item.clickable{cursor:pointer;transition:border-color .15s,transform .15s;border-color:#e9ecef}.meta-item.clickable:hover{border-color:#3498db;transform:translateY(-2px);box-shadow:0 4px 8px rgba(52,152,219,.15)}
.meta-label{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#888;font-weight:600}
.meta-value{font-size:18px;font-weight:700;color:#2c3e50;margin-top:2px;font-family:monospace;word-break:break-word;overflow-wrap:break-word}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
th{background:#2c3e50;color:#fff;padding:9px 10px;text-align:left;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;-webkit-print-color-adjust:exact;print-color-adjust:exact}
td{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top;word-break:break-word;overflow-wrap:break-word}
tr:nth-child(even) td{background:#f9fafb}
tr:hover td{background:#edf2f7}
.mono{font-family:'Courier New',monospace;font-size:12px}
.badge{display:inline-block;padding:1px 8px;border-radius:4px;font-size:11px;font-weight:700}
.badge-allow{background:#d1fae5;color:#065f46}.badge-deny{background:#fee2e2;color:#991b1b}
.up{color:#27ae60;font-weight:700}.down{color:#e74c3c;font-weight:700}
.empty{text-align:center;color:#aaa;font-style:italic;padding:16px 0}
b{font-weight:600}small{color:#888;font-size:11px}
.rpt-subtitle{color:#64748b;font-size:12px;margin-bottom:20px;font-family:monospace;border-left:4px solid #3498db;padding-left:8px;margin-top:4px}
@media print{body{background:#fff;padding:0}.card{box-shadow:none;break-inside:avoid}th{-webkit-print-color-adjust:exact;print-color-adjust:exact}}`;

function exportHTMLReport(mode){
  if(!parsed)return;
  const p=parsed;
  const esc=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  // Render VLAN ip-subnet-vlan properly (ipSubnets is array of objects {cidr,network,mask})
  function fmtIpSubnets(arr){
    if(!arr||!arr.length)return'—';
    return arr.map(s=>typeof s==='object'?(s.cidr||(s.network+'/'+(s.mask||'?'))):(String(s))).filter(Boolean).join('<br>');
  }
  // Mode badge
  function modeBadge(i){
    const M={'trunk':'#92400e:#fef3c7','access':'#065f46:#d1fae5','hybrid':'#5b21b6:#ede9fe','routed':'#1e40af:#dbeafe'};
    if(M[i.mode]){const[fg,bg]=M[i.mode].split(':');return`<span style="background:${bg};color:${fg};padding:1px 7px;border-radius:3px;font-size:11px;font-weight:700">${i.mode.charAt(0).toUpperCase()+i.mode.slice(1)}</span>`;}
    if(i.type==='svi')return'<span style="background:#cffafe;color:#155e75;padding:1px 7px;border-radius:3px;font-size:11px;font-weight:700">SVI</span>';
    if(i.type==='loopback')return'<span style="background:#f1f5f9;color:#475569;padding:1px 7px;border-radius:3px;font-size:11px;font-weight:700">Loopback</span>';
    return'—';
  }
  // Hybrid detail
  function fmtHybrid(h){
    if(!h)return'—';
    const pts=[];
    if(h.pvid)pts.push('<b>PVID:</b> '+h.pvid);
    if(h.untagged&&h.untagged.length)pts.push('<b>Untagged:</b> '+h.untagged.join(', '));
    if(h.tagged&&h.tagged.length)pts.push('<b>Tagged:</b> '+h.tagged.join(', '));
    if(h.hasIPSub)pts.push('<b style="color:#e67e22">IP-Subscriber</b>');
    if(h.hasQinQ)pts.push('<b style="color:#8e44ad">QinQ</b>');
    if(h.vlanMaps&&h.vlanMaps.length)pts.push('<b>VLAN-Mapping:</b> '+h.vlanMaps.map(x=>x.outer+'→'+x.inner).join(', '));
    return pts.join('<br>')||'—';
  }
  // exportHTML 內動態 vendor 標籤（含 brocade/ruckus 品牌切換）必須在 template literal
  // 外面先計算，不可用 ${(() => {...})()} 內嵌（既有慣例，見 CLAUDE.md exportHTML 規則）
  const rptVendorLabel=({'comware':'HPE Comware','arista':'Arista EOS','ruijie':'Ruijie RGOS','netgear':'Netgear M4300','edgeswitch':'Ubiquiti EdgeSwitch','cisco':'Cisco IOS/IOS-XE','nxos':'Cisco NX-OS','aruba':'Aruba CX','procurve':'Aruba ProCurve','fortiswitch':'FortiSwitch','juniper':'Juniper Networks','extreme':'Extreme Networks','alcatel':'Alcatel OmniSwitch','brocade':p.sys?.brand==='ruckus'?'Ruckus ICX':'Brocade FastIron/ICX','dell-os10':'Dell EMC Networking'})[p.vendor]||p.vendor;
  const reportHtml=`<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Switch Analysis Report - ${esc(p.sys.hostname)}</title>
<style>${REPORT_CSS}</style>
</head>
<body><div class="wrap">
<h1>🔀 ${tr('rpt.h1')}</h1>
<div class="rpt-subtitle">Generated by SW-Analyzer · ${rptVendorLabel} · ${new Date().toLocaleString(_lang==='ja'?'ja-JP':_lang==='en'?'en-US':'zh-TW')}</div>

<div class="card">
  <h2>${tr('rpt.device_overview')}</h2>
  <div class="meta-grid">
    <div class="meta-item"><div class="meta-label">${tr('rpt.meta_hostname')}</div><div class="meta-value">${esc(p.sys.hostname)}</div></div>
    <div class="meta-item"><div class="meta-label">${tr('rpt.meta_vendor')}</div><div class="meta-value">${esc(p.vendor||'—')}</div></div>
    <div class="meta-item"><div class="meta-label">${tr('rpt.meta_version')}</div><div class="meta-value" style="font-size:13px">${esc(p.sys.version||'—')}</div></div>
    ${(p.stack?.members?.length||p.irf?.members?.length)?`<div class="meta-item clickable" onclick="document.getElementById('sec-irf').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.click_to_irf')}"><div class="meta-label">${p.vendor==='arista'?'MLAG':p.vendor==='nxos'?'VPC':p.vendor==='brocade'?tr('rpt.meta_icx_members'):p.vendor==='cisco'?tr('rpt.meta_sw_members'):p.vendor==='aruba'?tr('rpt.meta_vsf_members'):p.vendor==='extreme'?tr('rpt.meta_extreme_members'):p.vendor==='alcatel'?tr('rpt.meta_als_members'):tr('rpt.meta_irf_members')}</div><div class="meta-value" style="color:#3498db">${p.stack?.members?.length||p.irf?.members?.length||0}</div></div>`:''}
    <div class="meta-item clickable" onclick="document.getElementById('sec-vlan').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.click_to_vlan')}"><div class="meta-label">${tr('rpt.meta_vlan_count')}</div><div class="meta-value">${p.vlans.length}</div></div>
    <div class="meta-item clickable" onclick="document.getElementById('sec-interfaces').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.click_to_if')}"><div class="meta-label">${tr('rpt.meta_physical_ports')}</div><div class="meta-value">${p.interfaces.filter(i=>i.type==='physical'||i.type==='stack').length}</div></div>
    ${(p.lacp&&p.lacp.length)?`<div class="meta-item clickable" onclick="document.getElementById('sec-lacp').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.click_to_lacp')}"><div class="meta-label">${tr('rpt.meta_lacp_groups')}</div><div class="meta-value">${(p.lacp||[]).length}</div></div>`:`<div class="meta-item"><div class="meta-label">${tr('rpt.meta_lacp_groups')}</div><div class="meta-value">${(p.lacp||[]).length}</div></div>`}
    <div class="meta-item clickable" onclick="document.getElementById('sec-routes').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.click_to_routes')}"><div class="meta-label">${tr('rpt.meta_static_routes')}</div><div class="meta-value">${p.routes.length}</div></div>
    ${((p.ospf&&p.ospf.length)||(p.bgp&&p.bgp.length)||(p.rip&&p.rip.length))?`<div class="meta-item clickable" onclick="document.getElementById('sec-routing').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.click_to_routing')}"><div class="meta-label">${tr('rpt.meta_ospf_proc')}</div><div class="meta-value">${(p.ospf||[]).length}</div></div>`:`<div class="meta-item"><div class="meta-label">${tr('rpt.meta_ospf_proc')}</div><div class="meta-value">${(p.ospf||[]).length}</div></div>`}
    ${((p.ospf&&p.ospf.length)||(p.bgp&&p.bgp.length)||(p.rip&&p.rip.length))?`<div class="meta-item clickable" onclick="document.getElementById('sec-routing').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.click_to_routing')}"><div class="meta-label">${tr('rpt.meta_bgp_as')}</div><div class="meta-value">${(p.bgp||[]).length}</div></div>`:`<div class="meta-item"><div class="meta-label">${tr('rpt.meta_bgp_as')}</div><div class="meta-value">${(p.bgp||[]).length}</div></div>`}
    ${(p.vrrp&&p.vrrp.length)?`<div class="meta-item clickable" onclick="document.getElementById('sec-vrrp').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.click_to_vrrp')}"><div class="meta-label">${tr('rpt.meta_vrrp_groups')}</div><div class="meta-value">${p.vrrp.length}</div></div>`:''}
    ${(p.vxlan&&p.vxlan.vnis&&p.vxlan.vnis.length)?`<div class="meta-item clickable" onclick="document.getElementById('sec-vxlan').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.click_to_vxlan')}"><div class="meta-label">${tr('rpt.meta_vxlan_vni')}</div><div class="meta-value">${p.vxlan.vnis.length}</div></div>`:''}
    ${(p.stp&&p.stp.ports&&p.stp.ports.length)?`<div class="meta-item clickable" onclick="document.getElementById('sec-stp').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.sec_stp')}"><div class="meta-label">${tr('rpt.sec_stp')}</div><div class="meta-value">${p.stp.ports.length}</div></div>`:''}
    ${(p.acls&&p.acls.length)?`<div class="meta-item clickable" onclick="document.getElementById('sec-acl').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.sec_acl')}"><div class="meta-label">${tr('rpt.sec_acl')}</div><div class="meta-value">${p.acls.length}</div></div>`:''}
    ${(p.security&&p.security.length)?`<div class="meta-item clickable" onclick="document.getElementById('sec-security').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.sec_security')}"><div class="meta-label">${tr('rpt.sec_security')}</div><div class="meta-value">${p.security.length}</div></div>`:''}
    ${(p.qos&&p.qos.length)?`<div class="meta-item clickable" onclick="document.getElementById('sec-qos').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.sec_qos')}"><div class="meta-label">${tr('rpt.sec_qos')}</div><div class="meta-value">${p.qos.length}</div></div>`:''}
    ${(p.lldp&&p.lldp.length)?`<div class="meta-item clickable" onclick="document.getElementById('sec-lldp').scrollIntoView({behavior:'smooth'})" title="${tr('rpt.sec_lldp')}"><div class="meta-label">${tr('rpt.sec_lldp')}</div><div class="meta-value">${p.lldp.length}</div></div>`:''}
  </div>
</div>

<div id="sec-irf">${buildStackTopoSection(p)}</div>

<div class="card" id="sec-interfaces">
  <h2>${tr('rpt.if_list')}</h2>
  <table>
    <thead><tr><th>${tr('col.name')}</th><th>${tr('rpt.col_desc')}</th><th>${tr('col.type')}</th><th>${tr('col.mode')}</th><th>${tr('col.vlan_native')}</th><th>${tr('rpt.col_hybrid_detail')}</th><th>${tr('rpt.col_ip')}</th>${p.interfaces.some(i=>i.ip6)?`<th>${tr('rpt.col_ipv6')}</th>`:''}<th>VRF</th><th>${tr('rpt.col_status')}</th></tr></thead>
    <tbody>
    ${p.interfaces.filter(i=>i.type!=='null').map(i=>`<tr>
      <td class="mono" style="white-space:nowrap">${esc(i.name)}</td>
      <td style="color:#555;font-size:12px">${esc(i.desc||'—')}</td>
      <td><span class="badge" style="background:#f1f5f9;color:#475569">${esc(i.type==='svi'?'SVI':i.type==='loopback'?'Loopback':i.type==='stack'?'Stack':'Physical')}</span></td>
      <td>${modeBadge(i)}</td>
      <td class="mono">${esc(i.vlans||'—')}${i.nativeVlan?'<br><small>Native:'+esc(i.nativeVlan)+'</small>':''}</td>
      <td style="font-size:11px;line-height:1.7">${fmtHybrid(i.hybrid)}</td>
      <td class="mono">${esc(i.ip||'—')}</td>
      ${p.interfaces.some(x=>x.ip6)?`<td class="mono">${esc(i.ip6||'—')}</td>`:''}
      <td class="mono" style="color:#e67e22">${esc(i.vrf||'—')}</td>
      <td class="${i.shutdown?'down':'up'}">${i.shutdown?tr('rpt.shutdown_on'):tr('rpt.shutdown_off')}</td>
    </tr>`).join('')}
    </tbody>
  </table>
</div>

<div class="card" id="sec-vlan">
  <h2>${tr('rpt.vlan_info')}</h2>
  <table>
    <thead><tr><th>${tip('tip.vlan','ID')}</th><th>${tr('col.name')}</th><th>${tr('rpt.col_ip_subnet_vlan')}</th><th>${tr('rpt.col_implied_ref')}</th></tr></thead>
    <tbody>
    ${p.vlans.map(v=>`<tr>
      <td class="mono" style="font-weight:700">${esc(v.id)}</td>
      <td>${esc(v.name||'—')}</td>
      <td class="mono">${fmtIpSubnets(v.ipSubnets)}</td>
      <td>${v.implied?`<span style="color:#e67e22;font-size:11px">${tr('rpt.implied_only')}</span>`:'—'}</td>
    </tr>`).join('')}
    </tbody>
  </table>
</div>

${(p.lacp&&p.lacp.length)?`<div class="card" id="sec-lacp">
  <h2>${tr('rpt.lacp_title')}</h2>
  <table>
    <thead><tr><th>${tip('tip.port_channel',tr('rpt.col_agg_if'))}</th><th>${tip('tip.lacp',tr('col.mode'))}</th><th>${tr('col.member_port')}</th></tr></thead>
    <tbody>
    ${p.lacp.map(l=>{
      // 修正既有 bug（同 renderLACP()／exportLACPCSV()）：ProCurve/ArubaOS-Switch 的
      // members 是逗號分隔字串非陣列；此函式的測試沙箱切片範圍不含模組層級的
      // _lacpMembersArr() 共用 helper，故就地內嵌同一份正規化邏輯，避免跨切片依賴
      const memArr=Array.isArray(l.members)?l.members:String(l.members||'').split(',').map(s=>s.trim()).filter(Boolean);
      return`<tr>
      <td class="mono" style="font-weight:700">${esc(l.name)}</td>
      <td><span class="badge" style="background:#e0f2fe;color:#0369a1">${esc(l.mode)}</span></td>
      <td class="mono">${memArr.map(m=>typeof m==='string'?m:m.name).join(', ')||'—'}</td>
    </tr>`;}).join('')}
    </tbody>
  </table>
</div>`:''}

<div class="card" id="sec-routes">
  <h2>${tr('rpt.routes_title')}</h2>
  <table>
    <thead><tr><th>${tr('rpt.col_dst')}</th><th>${tr('rpt.col_nexthop')}</th><th>VRF</th><th>${tr('rpt.col_note')}</th></tr></thead>
    <tbody>
    ${p.routes.length?p.routes.map(r=>`<tr>
      <td class="mono">${esc(r.dst)}</td>
      <td class="mono" style="color:${r.gwIsInterface?'#e67e22':'#27ae60'}">${esc(r.gw)}</td>
      <td class="mono">${esc(r.vrf||tr('rpt.main_table'))}</td>
      <td>${r.gwIsInterface?`<small>${tr('rpt.if_route')}</small>`:''}</td>
    </tr>`).join(''):`<tr><td colspan="4" class="empty">${tr('rpt.no_routes')}</td></tr>`}
    </tbody>
  </table>
</div>

${((p.ospf&&p.ospf.length)||(p.bgp&&p.bgp.length)||(p.rip&&p.rip.length))?`<div class="card" id="sec-routing">
  <h2>${tr('rpt.dyn_routing')}</h2>
  ${p.ospf&&p.ospf.length?`<h3>${tr('rpt.ospf_section')}（${p.ospf.length} ${tr('rt.n_process')}）</h3>
  <table><thead><tr><th>PID</th><th>Router-ID</th><th>Area</th><th>${tr('rpt.col_networks')}</th></tr></thead><tbody>
  ${p.ospf.flatMap(o=>o.areas&&o.areas.length?o.areas.map(a=>`<tr><td class="mono">${esc(o.pid)}</td><td class="mono">${esc(o.routerId||'—')}</td><td class="mono">${esc(a.area)}</td><td class="mono">${(a.networks||[]).map(n=>esc(n.network||n)).join(', ')||'—'}</td></tr>`):
    [`<tr><td class="mono">${esc(o.pid)}</td><td class="mono">${esc(o.routerId||'—')}</td><td colspan="2" style="color:#aaa">${tr('rpt.no_area')}</td></tr>`]).join('')}
  </tbody></table>`:''}
  ${p.bgp&&p.bgp.length?`<h3 style="margin-top:14px">${tr('rpt.bgp_section')}</h3>
  <table><thead><tr><th>AS</th><th>Router-ID</th><th>${tr('rpt.col_peer_ip')}</th><th>${tr('rpt.col_remote_as')}</th><th>${tr('col.type')}</th><th>${tr('rpt.col_desc')}</th></tr></thead><tbody>
  ${p.bgp.flatMap(b=>b.peers&&b.peers.length?b.peers.map(peer=>`<tr><td class="mono">${esc(b.asn)}</td><td class="mono">${esc(b.routerId||'—')}</td><td class="mono">${esc(peer.ip)}</td><td class="mono">${esc(peer.as)}</td><td><span class="badge" style="background:${peer.type==='iBGP'?'#d1fae5':'#fef3c7'};color:${peer.type==='iBGP'?'#065f46':'#92400e'}">${esc(peer.type)}</span></td><td style="color:#555">${esc(peer.desc||'—')}</td></tr>`):
    [`<tr><td class="mono">${esc(b.asn)}</td><td class="mono">${esc(b.routerId||'—')}</td><td colspan="4" style="color:#aaa">${tr('rpt.no_peer')}</td></tr>`]).join('')}
  </tbody></table>`:''}
  ${p.rip&&p.rip.length?`<h3 style="margin-top:14px">${tr('rpt.rip_section')}</h3>
  <table><thead><tr><th>${tr('rpt.col_version')}</th><th>${tr('rpt.col_networks')}</th></tr></thead><tbody>
  ${p.rip.map(r=>`<tr><td class="mono">${esc(r.version||'2')}</td><td class="mono">${(r.networks||[]).join(', ')||'—'}</td></tr>`).join('')}
  </tbody></table>`:''}
</div>`:''}

${(p.vrrp&&p.vrrp.length)?`<div class="card" id="sec-vrrp">
  <h2>${tr('rpt.vrrp_title')}</h2>
  <table><thead><tr><th>${tr('rpt.col_group')}</th><th>${tr('col.interface')}</th><th>${tr('rpt.col_vip')}</th><th>${tr('col.priority')}</th><th>${tr('rpt.col_preempt')}</th><th>${tr('rpt.col_auth')}</th><th>${tr('rpt.col_track_if')}</th></tr></thead><tbody>
  ${p.vrrp.map(g=>`<tr>
    <td class="mono" style="font-weight:700">${esc(g.vrid)}</td>
    <td class="mono">${esc(g.interface||'—')}</td>
    <td class="mono" style="color:#27ae60">${esc(g.vip||'—')}</td>
    <td style="color:${parseInt(g.priority||100)>100?'#e67e22':parseInt(g.priority||100)<100?'#e74c3c':'#555'};font-weight:600">${esc(g.priority||'100')}</td>
    <td>${g.preempt?`<span style="color:#27ae60;font-weight:700">${tr('rpt.preempt_on')}</span>`:'—'}</td>
    <td>${g.authMode?`<span style="color:#8e44ad">${tr('rpt.auth_set')}</span>`:'—'}</td>
    <td class="mono">${esc(g.trackIf||'—')}${g.trackReduced?' (-'+esc(g.trackReduced)+')':''}</td>
  </tr>`).join('')}
  </tbody></table>
</div>`:''}

${(p.vxlan&&p.vxlan.vnis&&p.vxlan.vnis.length)?`<div class="card" id="sec-vxlan">
  <h2>${tr('rpt.vxlan_title')}</h2>
  <table><thead><tr><th>VNI</th><th>${tr('rpt.col_vsi_name')}</th><th>${tr('rpt.col_mapped_vlan')}</th><th>${tr('col.mode')}</th><th>${tr('rpt.col_vtep_src')}</th><th>${tr('rpt.col_static_peer')}</th></tr></thead><tbody>
  ${p.vxlan.vnis.map(v=>`<tr>
    <td class="mono" style="font-weight:700">${esc(v.vni)}</td>
    <td style="color:#555">${esc(v.name||'—')}</td>
    <td class="mono">${esc(v.vlan||'—')}</td>
    <td><span class="badge" style="background:${v.mode==='BGP-EVPN'?'#dbeafe':'#f1f5f9'};color:${v.mode==='BGP-EVPN'?'#1e40af':'#475569'}">${esc(v.mode)}</span></td>
    <td class="mono">${esc(p.vxlan.vtep||'—')}</td>
    <td class="mono" style="font-size:11px">${(v.peers||[]).join(', ')||'—'}</td>
  </tr>`).join('')}
  </tbody></table>
  ${p.vxlan.evpn&&p.vxlan.evpn.length?`
  <h3 style="margin-top:16px;font-size:14px;color:#2c3e50;border-left:3px solid #3498db;padding-left:8px">${tr('rpt.evpn_instances')}（${p.vxlan.evpn.length}）</h3>
  <table style="margin-top:6px"><thead><tr><th>${tr('rpt.col_inst_name')}</th><th>${tr('vxlan.col_rd')}</th><th>${tr('vxlan.col_rt_import')}</th><th>${tr('vxlan.col_rt_export')}</th></tr></thead><tbody>
  ${p.vxlan.evpn.map(e=>`<tr>
    <td style="font-weight:700">${esc(e.name)}</td>
    <td class="mono">${esc(e.rd||'—')}</td>
    <td class="mono" style="color:#27ae60">${esc(e.rtImport||'—')}</td>
    <td class="mono" style="color:#e67e22">${esc(e.rtExport||'—')}</td>
  </tr>`).join('')}
  </tbody></table>`:''}
</div>`:''}

${(p.vrfs&&p.vrfs.length)?`<div class="card">
  <h2>${tr('rpt.vrf_title')}</h2>
  <table><thead><tr><th>${tr('col.name')}</th><th>RD</th><th>Import-Route</th></tr></thead><tbody>
  ${p.vrfs.map(v=>`<tr><td class="mono" style="font-weight:700">${esc(v.name)}</td><td class="mono">${esc(v.rd||'—')}</td><td class="mono">${esc(v.importRoute||'—')}</td></tr>`).join('')}
  </tbody></table>
</div>`:''}

${(p.dns&&p.dns.length)?`<div class="card">
  <h2>${tr('rpt.dns_title')}</h2>
  <table><thead><tr><th>#</th><th>${tr('dns.col_server')}</th></tr></thead><tbody>
  ${p.dns.map((ip,i)=>`<tr><td>${i+1}</td><td class="mono" style="color:var(--green,#27ae60)">${esc(ip)}</td></tr>`).join('')}
  </tbody></table>
</div>`:''}

${(p.dhcp&&p.dhcp.length)?`<div class="card">
  <h2>${tr('rpt.dhcp_title')}</h2>
  ${p.dhcp.filter(d=>d.type==='server').length?`<h3 style="font-size:14px;color:#2c3e50;margin:8px 0 4px">${tr('rpt.dhcp_server_pool')}</h3>
  <table><thead><tr><th>${tr('rpt.col_pool_name')}</th><th>${tr('rpt.col_network')}</th><th>${tr('rpt.col_range')}</th><th>${tr('rpt.col_gateway')}</th><th>${tr('col.interface')}</th><th>${tr('dhcp.col_boot')}</th><th>${tr('dhcp.col_next_server')}</th><th>${tr('dhcp.col_ntp')}</th></tr></thead><tbody>
  ${p.dhcp.filter(d=>d.type==='server').map(d=>`<tr>
    <td style="font-weight:700">${esc(d.name)}</td>
    <td class="mono">${esc(d.network||'—')}</td>
    <td class="mono">${esc(d.range||'—')}</td>
    <td class="mono">${esc(d.gateway||'—')}</td>
    <td class="mono">${esc(d.interface||'—')}</td>
    <td class="mono">${esc(d.bootFile||'—')}</td>
    <td class="mono">${esc(d.nextServer||'—')}</td>
    <td class="mono">${esc(d.ntpServer||'—')}</td>
  </tr>`).join('')}
  </tbody></table>`:''}
  ${p.dhcp.filter(d=>d.type==='relay').length?`<h3 style="font-size:14px;color:#2c3e50;margin:12px 0 4px">${tr('rpt.dhcp_relay')}</h3>
  <table><thead><tr><th>${tr('rpt.col_group')}</th><th>${tr('col.interface')}</th><th>${tr('dhcp.col_relay_server')}</th><th>${tr('dhcp.col_option82')}</th></tr></thead><tbody>
  ${p.dhcp.filter(d=>d.type==='relay').map(d=>`<tr>
    <td style="font-weight:700">${esc(d.name)}</td>
    <td class="mono">${esc(d.interface||'—')}</td>
    <td class="mono" style="color:var(--green,#27ae60)">${esc(d.relayServer||d.server||'—')}</td>
    <td>${d.option82?'✓':'—'}</td>
  </tr>`).join('')}
  </tbody></table>`:''}
</div>`:''}

${(p.users&&p.users.length)?`<div class="card">
  <h2>${tr('rpt.users_title')}</h2>
  <table><thead><tr><th>${tr('rpt.col_username')}</th><th>${tr('col.role')}</th><th>${tr('rpt.col_service')}</th><th>${tr('rpt.col_password')}</th><th>${tr('rpt.col_pwd_strength')}</th></tr></thead><tbody>
  ${p.users.map(u=>`<tr>
    <td style="font-weight:700">${esc(u.name)}</td>
    <td><span class="badge" style="background:#e0f2fe;color:#0369a1">${esc(u.role||'—')}</span></td>
    <td class="mono" style="font-size:12px">${esc(u.service||'—')}</td>
    <td>${u.hasPwd?`<span style="color:#27ae60">${tr('rpt.pwd_set')}</span>`:`<span style="color:#e74c3c">${tr('rpt.pwd_notset')}</span>`}</td>
    <td>${u.pwdWeak?`<span style="color:#e74c3c;font-weight:700">⚠ ${esc(u.pwdType||tr('pwd.strength_weak'))}</span>`:'<span style="color:#27ae60">'+esc(u.pwdType||'—')+'</span>'}</td>
  </tr>`).join('')}
  </tbody></table>
</div>`:''}

<p style="text-align:center;font-size:12px;color:#aaa;margin-top:16px">
  ${tr('rpt.footer')} · ${new Date().toLocaleString()}
</p>
${(p.stp&&p.stp.ports&&p.stp.ports.length)?`<div class="card" id="sec-stp">
  <h2>🌳 ${tr('rpt.sec_stp')}</h2>
  <div class="meta-grid">
    <div class="meta-item"><div class="meta-label">${tr('stp.mode')}</div><div class="meta-value">${esc(p.stp.mode||'—')}</div></div>
    <div class="meta-item"><div class="meta-label">${tr('stp.col_vlan')}</div><div class="meta-value">${(p.stp.instances||[]).length}</div></div>
    <div class="meta-item"><div class="meta-label">${tr('stp.col_portfast')}</div><div class="meta-value">${p.stp.ports.filter(s=>s.portfast).length}</div></div>
    <div class="meta-item"><div class="meta-label">${tr('stp.col_bpduguard')}</div><div class="meta-value">${p.stp.ports.filter(s=>s.bpduguard).length}</div></div>
  </div>
  <table><thead><tr><th>${tr('stp.col_port')}</th><th>${tr('stp.col_portfast')}</th><th>${tr('stp.col_bpduguard')}</th><th>${tr('stp.col_rootguard')}</th><th>Cost</th><th>${tr('stp.port_prio')}</th></tr></thead>
  <tbody>${p.stp.ports.map(sp=>`<tr>
    <td class="mono">${esc(sp.port)}</td>
    <td>${sp.portfast?'<span style="color:#22c55e">✓</span>':'—'}</td>
    <td>${sp.bpduguard?'<span style="color:#f97316">✓</span>':'—'}</td>
    <td>${sp.guardRoot?'<span style="color:#f97316">✓</span>':'—'}</td>
    <td>${esc(sp.cost||'—')}</td>
    <td>${esc(sp.priority||'—')}</td>
  </tr>`).join('')}</tbody></table>
</div>`:''}
${(p.acls&&p.acls.length)?`<div class="card" id="sec-acl">
  <h2>📋 ${tr('rpt.sec_acl')} (${p.acls.length})</h2>
  <table><thead><tr><th>${tr('col.name')}</th><th>${tr('acl.col_seq')}</th><th>${tr('acl.col_action')}</th><th>${tr('acl.col_src')}</th><th>${tr('acl.col_dst')}</th><th>${tr('acl.col_proto')}</th><th>${tr('acl.col_remark')}</th></tr></thead>
  <tbody>${p.acls.flatMap(a=>a.rules&&a.rules.length?a.rules.map(r=>`<tr>
    <td class="mono" style="font-weight:600">${esc(a.name)}</td>
    <td class="mono">${esc(r.seq||'')}</td>
    <td><span class="badge" style="background:${r.action==='permit'?'rgba(34,197,94,.2);color:#22c55e':'rgba(239,68,68,.2);color:#ef4444'}">${esc(r.action||'—')}</span></td>
    <td class="mono">${esc(r.src||'any')}</td>
    <td class="mono">${esc(r.dst||'any')}</td>
    <td>${esc(r.protocol||'—')}</td>
    <td>${esc(r.remark||'—')}</td>
  </tr>`):[`<tr><td class="mono" style="font-weight:600">${esc(a.name)}</td><td colspan="6" style="color:#64748b">(no rules)</td></tr>`]).join('')}</tbody></table>
</div>`:''}
${(p.security&&p.security.length)?`<div class="card" id="sec-security">
  <h2>🔐 ${tr('rpt.sec_security')} (${p.security.length})</h2>
  <table><thead><tr><th>${tr('col.interface')}</th><th>802.1X</th><th>${tr('sec.port_sec')}</th><th>${tr('sec.max_mac')}</th><th>${tr('sec.violation')}</th><th>${tr('sec.guest_vlan')}</th></tr></thead>
  <tbody>${p.security.map(s=>`<tr>
    <td class="mono">${esc(s.port)}</td>
    <td>${esc(s.dot1x||'—')}</td>
    <td>${s.portSec?'<span style="color:#22c55e">✓</span>':'—'}</td>
    <td>${esc(s.maxMac||'—')}</td>
    <td>${esc(s.violation||'—')}</td>
    <td>${esc(s.guestVlan||'—')}</td>
  </tr>`).join('')}</tbody></table>
</div>`:''}
${(p.qos&&p.qos.length)?`<div class="card" id="sec-qos">
  <h2>📶 ${tr('rpt.sec_qos')} (${p.qos.length})</h2>
  <table><thead><tr><th>${tr('qos.policy')}</th><th>${tr('qos.class')}</th><th>${tr('qos.action')}</th><th>${tr('qos.rate')}</th><th>${tr('qos.burst')}</th><th>${tr('qos.behavior')}</th></tr></thead>
  <tbody>${p.qos.map(q=>`<tr>
    <td class="mono">${esc(q.policy||'—')}</td>
    <td>${esc(q.cls||'default')}</td>
    <td>${esc(q.action||'—')}</td>
    <td class="mono">${esc(q.rate||'—')}</td>
    <td class="mono">${esc(q.burst||'—')}</td>
    <td class="mono">${esc(q.behavior||'—')}</td>
  </tr>`).join('')}</tbody></table>
</div>`:''}
${(p.lldp&&p.lldp.length)?`<div class="card" id="sec-lldp">
  <h2>🗺️ ${tr('rpt.sec_lldp')} (${p.lldp.length})</h2>
  <table><thead><tr><th>${tr('lldp.col_local')}</th><th>${tr('lldp.col_device')}</th><th>${tr('lldp.col_platform')}</th><th>${tr('lldp.col_remote_port')}</th><th>${tr('lldp.col_ip')}</th><th>${tr('lldp.col_proto')}</th></tr></thead>
  <tbody>${p.lldp.map(l=>`<tr>
    <td class="mono">${esc(l.localPort)}</td>
    <td style="font-weight:600">${esc(l.neighbor||'—')}</td>
    <td>${esc(l.platform||'—')}</td>
    <td class="mono">${esc(l.remotePort||'—')}</td>
    <td class="mono">${esc(l.ip||'—')}</td>
    <td>${esc(l.protocol||'—')}</td>
  </tr>`).join('')}</tbody></table>
</div>`:''}
</body></html>`;
  if(mode==='print'){
    // 重用同一份報表 HTML（含既有 REPORT_CSS 內建的 @media print），開新視窗呼叫瀏覽器列印，
    // 使用者可選「另存為 PDF」；與現有 doPrint()（僅列印當前畫面單一區塊）互補，
    // 這裡印的是完整多區塊報表
    const printWin=window.open('','_blank');
    if(!printWin){alert(tr('err.popup_blocked'));return;}
    printWin.document.open();printWin.document.write(reportHtml);printWin.document.close();
    printWin.onload=()=>{printWin.focus();printWin.print();};
  } else {
    dlHtml(reportHtml,`${hn()}_report.html`);
  }
}

function renderStackWise(){
  const s=parsed.stack;
  if(!s||!s.members.length)return`<div class="nodata">${tr('msg.no_stackwise_pre')}<br><span style="font-size:11px;color:var(--text-muted)">${tr('msg.no_stackwise_sub')}</span></div>`;
  const svg=buildStackWiseSVG(parsed);
  return`<div style="flex:1;overflow-y:auto">
    <div class="export-row"><button class="btn btn-ghost btn-sm" onclick="exportTopoSVG()">⬇ ${tr('irf.export_svg')}</button></div>
    <div class="topo-wrap">${svg}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 18px 14px">
      <div class="ov-card">
        <div class="ov-card-title">⚡ ${tr('stack.sw_cfg')}</div>
        <div class="ov-row"><span class="ov-key">${tr('col.type')}</span><span class="ov-val">${pill('info','StackWise')}</span></div>
        <div class="ov-row"><span class="ov-key">${tr('stack.member_count')}</span><span class="ov-val">${s.members.length}</span></div>
      </div>
      <div class="ov-card">
        <div class="ov-card-title">${tr('irf.member_list_card')}</div>
        ${s.members.map(m=>{
          const pcount=parsed.interfaces.filter(i=>i.member===m.id&&i.type==='physical').length;
          const roleClass=m.role==='Active'?'sw-active':m.role==='Standby'?'sw-standby':'sw-member';
          return`<div class="ov-row">
            <span class="ov-key">${pill('p-stack','SW'+m.id)}</span>
            <span class="ov-val"><span class="sw-type-badge ${roleClass}">${m.role||'—'}</span> · ${tr('stack.port_col')}${pcount} · prio:${m.priority||'—'}</span>
          </div>`;
        }).join('')}
      </div>
    </div>
    <div style="padding:0 18px 14px">
      <div class="ov-card">
        <div class="ov-card-title">🖥️ ${tr('stack.model_list')}</div>
        <table class="data-tbl" style="margin-top:4px">
          <tr><th>ID</th><th>${tr('col.model')}</th><th>${tr('col.priority')}</th><th>${tr('col.role')}</th><th>${tr('col.port_count')}</th></tr>
          ${s.members.map(m=>{
            const pcount=parsed.interfaces.filter(i=>i.member===m.id&&i.type==='physical').length;
            const roleClass=m.role==='Active'?'p-master':m.role==='Standby'?'p-up':'p-standby';
            return`<tr>
              <td>${pill('p-stack','SW'+m.id)}</td>
              <td class="mono">${m.model||'—'}</td>
              <td class="mono" style="color:var(--yellow)">${m.priority||'—'}</td>
              <td>${pill(roleClass,m.role||'—')}</td>
              <td class="mono">${pcount}</td>
            </tr>`;
          }).join('')}
        </table>
      </div>
    </div>
  </div>`;
}
function buildStackWiseSVG(p){
  const s=p.stack;
  const mems=s.members;
  const tc='#1ba0d7'; // Cisco blue
  const boxW=158,boxH=188,gap=Math.max(200,720/(mems.length||1));
  const W=Math.max(720,mems.length*gap+100);
  const H=400;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2);
  const bY=96;
  const boxes=mems.map((m,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m,
    ports:p.interfaces.filter(ii=>ii.member===m.id&&ii.type==='physical').length,
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif">
<defs>
<marker id="arr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="glow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<filter id="glows"><feGaussianBlur stdDeviation="1.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<linearGradient id="hg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="${tc}" stop-opacity=".14"/><stop offset="100%" stop-color="#0052ff" stop-opacity=".03"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<rect x="0" y="0" width="${W}" height="50" fill="url(#hg)" rx="12"/>
<rect x="0" y="38" width="${W}" height="12" fill="#080c17"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">STACKWISE TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-110}" y="11" width="98" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-61}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">StackWise</text>`;

  // Ring link for >2 members
  const isRing=mems.length>2;
  for(let i=0;i<mems.length;i++){
    if(i===mems.length-1&&!isRing)break;
    const a=boxes[i],b=boxes[(i+1)%mems.length];
    if(i===mems.length-1){
      svg+=`<path d="M ${a.cx} ${a.y+boxH+8} C ${a.cx} ${a.y+boxH+76} ${b.cx} ${b.y+boxH+76} ${b.cx} ${b.y+boxH+8}" stroke="${tc}" stroke-width="2" fill="none" opacity=".35" stroke-dasharray="5,3"/>`;
    }else{
      svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#arr)" filter="url(#glows)"/>`;
      const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;
      svg+=`<rect x="${mx-42}" y="${my-10}" width="84" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/><text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">Stack Cable</text>`;
    }
  }

  boxes.forEach((bx,i)=>{
    const m=bx.mem;
    const isActive=m.role==='Active';
    const isStandby=m.role==='Standby';
    const borderColor=isActive?tc:isStandby?'#10b981':'#1e3a5f';
    const borderW=isActive?1.8:1.2;
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${borderColor}" stroke-width="${borderW}" ${isActive?'filter="url(#glow)"':''}/>`;
    if(isActive)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".025"/>`;
    // Header badge
    const badgeColor=isActive?tc:isStandby?'#10b981':'#2c3e58';
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${badgeColor}" opacity="${isActive?.18:isStandby?.12:.08}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isActive?tc:isStandby?'#10b981':'#64748b'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">SW${m.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${badgeColor}" text-anchor="end" font-weight="600">${esc(m.role||'')}</text>`;
    // Port slots
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#1e3a5f" stroke-width="1"/>`;
    const pc=Math.min(bx.ports,16);
    for(let pi=0;pi<pc;pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isActive?.4:.18}"/>`;}
    // Info rows
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#1e3a5f" stroke-width=".5"/>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.model')}</text><text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="9.5" fill="#dde8f5" text-anchor="end" font-weight="600" font-family="JetBrains Mono,monospace">${esc((m.model||'—').replace(/^ws-c/i,''))}</text>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text><text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${m.priority||'—'}</text>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+140}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.port_count')}</text><text x="${bx.x+boxW-14}" y="${bx.y+140}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports}</text>`;
    // Trunk indicator
    const tpCount=p.interfaces.filter(ii=>ii.member===m.id&&ii.mode==='trunk').length;
    if(tpCount)svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-24}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/><polygon points="${bx.cx},${bx.y-28} ${bx.cx-5},${bx.y-20} ${bx.cx+5},${bx.y-20}" fill="${tc}" opacity=".5"/><text x="${bx.cx}" y="${bx.y-33}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Trunk×${tpCount}</text>`;
  });

  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#1e3a5f" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Active</text>
  <rect x="100" y="${lY+8}" width="10" height="10" rx="2" fill="#10b981" opacity=".7"/>
  <text x="116" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby</text>
  <rect x="186" y="${lY+8}" width="10" height="10" rx="2" fill="#1e3a5f"/>
  <text x="202" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Member</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#2c3e58" text-anchor="end" font-family="JetBrains Mono,monospace">Cisco StackWise</text>`;
  svg+=`</svg>`;
  return svg;
}

// ── INIT (runs after all functions are defined) ──
const dropZone=document.getElementById('drop-zone');
dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('drag-over');});
dropZone.addEventListener('dragleave',()=>dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop',e=>{
  e.preventDefault();dropZone.classList.remove('drag-over');
  const f=e.dataTransfer.files[0];if(f)readFile(f);
});

// ════════════════════════════════════
//  ANALYSE
// ════════════════════════════════════

// ════════════════════════════════════
//  NAVIGATION
// ════════════════════════════════════

// ════════════════════════════════════
//  RENDERING
// ════════════════════════════════════


// ─── Overview ───────────────────────

// ─── IRF Topology ────────────────────

// ─── Topology SVG ────────────────────

// ─── Sortable / Filterable Table Helper ──────────────────────




// ─── VLANs ────────────────────────────

// ─── Ports ────────────────────────────

// ─── Routes ───────────────────────────

// ─── VRFs ────────────────────────────

// ─── Users ────────────────────────────

// ════════════════════════════════════
//  EXPORTS
// ════════════════════════════════════


// ── StackWise Topology ────────────────


// Update exportTopoSVG to use correct function based on vendor



// ── StackWise Topology ────────────────

// Update exportTopoSVG to use correct function based on vendor

// ── Runtime init ─────────────────────────────────────────────

// ── Aruba VSF Topology ───────────────────────────────────────

function renderMCLAG(){
  const s=parsed.stack;
  if(!s)return `<div class="nodata">${tr('msg.no_mclag')}</div>`;
  let h=`<div style="flex:1;overflow-y:auto">
    <div class="ov-grid">
      <div class="ov-card">
        <div class="ov-card-title">🛡️ ${tr('mclag.card_title')}</div>
        <div class="ov-row"><span class="ov-key">${tr('mclag.type_label')}</span><span class="ov-val">FortiSwitch MCLAG</span></div>
        <div class="ov-row"><span class="ov-key">${tr('mclag.icl_count')}</span><span class="ov-val">${s.links.length}</span></div>
      </div>
    </div>
    <div style="padding:0 18px 10px">
      <div class="sec-title">🔗 ${tr('mclag.section_title')}</div>
      <table class="data-tbl">
        <thead><tr><th>${tr('col.name')}</th><th>${tr('col.type')}</th><th>${tr('col.member_port')}</th></tr></thead>
        <tbody>
          ${s.links.map(l=>`<tr><td>${esc(l.id)}</td><td>${pill('p-info',l.type)}</td><td class="mono">${l.ports.join(', ')}</td></tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>`;
  return h;
}

function renderVSF(){
  const s=parsed.stack;
  if(!s||!s.members.length)return`<div class="nodata">${tr('msg.no_vsf')}</div>`;
  const tc='#f97316';
  const boxW=158,boxH=188,gap=Math.max(200,720/(s.members.length||1));
  const W=Math.max(720,s.members.length*gap+100),H=400;
  const startX=Math.max(28,(W-gap*(s.members.length-1)-boxW)/2),bY=96;
  const boxes=s.members.map((m,i)=>({x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m,ports:parsed.interfaces.filter(ii=>ii.member===m.id&&ii.type==='physical'&&ii.name.startsWith(m.id+'/')).length}));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif">
<defs><marker id="arr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="glow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">VSF STACK TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(parsed.sys.hostname)}</text>
<rect x="${W-100}" y="11" width="88" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-56}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">VSF</text>`;
  for(let i=0;i<s.members.length;i++){
    if(i===s.members.length-1)break;
    const a=boxes[i],b=boxes[i+1];
    const lnk=s.links.find(l=>l.id===String(i+1));
    const lbl=lnk?lnk.ports.slice(0,2).join(' | '):'';
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#arr)"/>`;
    if(lbl){const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;svg+=`<rect x="${mx-50}" y="${my-10}" width="100" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/><text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${esc(lbl)}</text>`;}
  }
  boxes.forEach((bx,i)=>{
    const m=bx.mem,isMaster=m.role==='Master';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#1e3a5f'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#glow)"':''}/>
    <rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.18:.07}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#64748b'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">M${m.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#2c3e58'}" text-anchor="end" font-weight="600">${esc(m.role||'')}</text>`;
    const pc=Math.min(bx.ports,16);
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#1e3a5f" stroke-width="1"/>`;
    for(let pi=0;pi<pc;pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.42:.2}"/>`;}
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#1e3a5f" stroke-width=".5"/>
    <text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.model')}</text><text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="9.5" fill="#dde8f5" text-anchor="end" font-family="JetBrains Mono,monospace">${esc((m.model||'—').replace(/^JL/i,'JL'))}</text>
    <text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text><text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${m.priority||'—'}</text>
    <text x="${bx.x+16}" y="${bx.y+140}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.port_count')}</text><text x="${bx.x+boxW-14}" y="${bx.y+140}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports}</text>`;
  });
  svg+=`</svg>`;
  return`<div style="flex:1;overflow-y:auto">
    <div class="export-row"><button class="btn btn-ghost btn-sm" onclick="exportTopoSVG()">⬇ ${tr('irf.export_svg')}</button></div>
    <div class="topo-wrap">${svg}</div>
    <div style="padding:0 18px 14px"><div class="ov-card">
      <div class="ov-card-title">👥 ${tr('stack.vsf_list')}</div>
      <table class="data-tbl"><tr><th>${tr('col.member_id')}</th><th>${tr('col.model')}</th><th>${tr('col.priority')}</th><th>${tr('col.role')}</th><th>${tr('col.vsf_port')}</th><th>${tr('col.port_count')}</th></tr>
      ${s.members.map(m=>{
        const pcount=parsed.interfaces.filter(i=>i.member===m.id&&i.type==='physical'&&i.name.startsWith(m.id+'/')).length;
        const lnks=s.links.filter(l=>l.ports.some(p=>p.startsWith(m.id+'/')));
        return`<tr><td>${pill('p-stack','M'+m.id)}</td><td class="mono">${esc(m.model||'—')}</td>
        <td class="mono" style="color:var(--yellow)">${m.priority||'—'}</td>
        <td>${m.role==='Master'?pill('p-master','Master'):pill('p-standby','Standby')}</td>
        <td class="mono">${lnks.map(l=>l.ports.filter(p=>p.startsWith(m.id+'/')).join(', ')).join(' | ')||'—'}</td>
        <td class="mono">${pcount}</td></tr>`;
      }).join('')}
      </table></div></div></div>`;
}

// ── Routing Protocols (OSPF + BGP) ───────────────────────────
let _rtView='table';
function renderBGPTopo(bgpList){
  const b=bgpList[0];if(!b||!b.peers.length)return'';
  const peers=b.peers;const cnt=peers.length||1;
  const CX=420,CY=230,R=Math.min(170,60+cnt*22),nodeR=34,W=840,H=460;
  const pos=peers.map((_,i)=>{const a=(2*Math.PI*i/cnt)-Math.PI/2;return{x:CX+R*Math.cos(a),y:CY+R*Math.sin(a)};});
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" style="width:100%;max-height:460px">
  <defs><filter id="bg"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
  pos.forEach((p,i)=>{
    const peer=peers[i];const col=peer.type==='iBGP'?'var(--accent)':'var(--green)';
    const dx=p.x-CX,dy=p.y-CY,dist=Math.sqrt(dx*dx+dy*dy);
    const ex=CX+dx/dist*nodeR,ey=CY+dy/dist*nodeR,sx=p.x-dx/dist*nodeR,sy=p.y-dy/dist*nodeR;
    svg+=`<line x1="${ex}" y1="${ey}" x2="${sx}" y2="${sy}" stroke="${col}" stroke-width="1.5" stroke-opacity="0.5"/>`;
    const mx=(CX+p.x)/2,my=(CY+p.y)/2;
    svg+=`<text x="${mx}" y="${my}" text-anchor="middle" dominant-baseline="middle" font-size="9" fill="${col}" opacity="0.9">AS${peer.as}</text>`;
    svg+=`<circle cx="${p.x}" cy="${p.y}" r="${nodeR}" fill="var(--surface2)" stroke="${col}" stroke-width="1.8"/>`;
    svg+=`<text x="${p.x}" y="${p.y-6}" text-anchor="middle" dominant-baseline="middle" font-size="9" font-weight="600" fill="var(--text)" font-family="monospace">${esc(peer.ip.length>14?peer.ip.substring(0,13)+'…':peer.ip)}</text>`;
    svg+=`<text x="${p.x}" y="${p.y+7}" text-anchor="middle" dominant-baseline="middle" font-size="8" fill="${col}">${peer.type}</text>`;
    if(peer.desc&&peer.desc!=='-')svg+=`<text x="${p.x}" y="${p.y+nodeR+11}" text-anchor="middle" font-size="8" fill="var(--text-dim)">${esc(peer.desc.substring(0,16))}</text>`;
  });
  svg+=`<circle cx="${CX}" cy="${CY}" r="${nodeR}" fill="var(--surface2)" stroke="var(--accent)" stroke-width="2.5" filter="url(#bg)"/>`;
  svg+=`<text x="${CX}" y="${CY-6}" text-anchor="middle" dominant-baseline="middle" font-size="10" font-weight="700" fill="var(--accent)" font-family="monospace">${esc((parsed.sys?.hostname||'Local').substring(0,12))}</text>`;
  svg+=`<text x="${CX}" y="${CY+7}" text-anchor="middle" dominant-baseline="middle" font-size="9" fill="var(--text-dim)">AS${esc(b.asn)}</text>`;
  svg+='</svg>';
  return`<div style="background:var(--surface2);border-radius:8px;padding:12px">${svg}</div>`;
}
function renderOSPFTopo(ospfList){
  const o=ospfList[0];if(!o||!o.areas.length)return'';
  const areas=o.areas;const cnt=areas.length||1;
  const CX=420,CY=230,R=Math.min(160,60+cnt*25),nodeR=36,W=840,H=460;
  const pos=areas.map((_,i)=>{const a=(2*Math.PI*i/cnt)-Math.PI/2;return{x:CX+R*Math.cos(a),y:CY+R*Math.sin(a)};});
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" style="width:100%;max-height:460px">
  <defs><filter id="og"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
  pos.forEach((p,i)=>{
    const area=areas[i];const col=area.area==='0'||area.area==='0.0.0.0'?'var(--accent)':'var(--purple)';
    const dx=p.x-CX,dy=p.y-CY,dist=Math.sqrt(dx*dx+dy*dy);
    const ex=CX+dx/dist*nodeR,ey=CY+dy/dist*nodeR,sx=p.x-dx/dist*nodeR,sy=p.y-dy/dist*nodeR;
    svg+=`<line x1="${ex}" y1="${ey}" x2="${sx}" y2="${sy}" stroke="${col}" stroke-width="1.5" stroke-opacity="0.5"/>`;
    svg+=`<text x="${(CX+p.x)/2}" y="${(CY+p.y)/2}" text-anchor="middle" font-size="9" fill="var(--text-dim)">${area.networks.length} net</text>`;
    svg+=`<circle cx="${p.x}" cy="${p.y}" r="${nodeR}" fill="var(--surface2)" stroke="${col}" stroke-width="1.8"/>`;
    svg+=`<text x="${p.x}" y="${p.y-6}" text-anchor="middle" dominant-baseline="middle" font-size="9" font-weight="600" fill="var(--text)">Area ${esc(area.area)}</text>`;
    if(area.type&&area.type!=='normal')svg+=`<text x="${p.x}" y="${p.y+7}" text-anchor="middle" font-size="8" fill="${col}">${area.type.toUpperCase()}</text>`;
  });
  svg+=`<circle cx="${CX}" cy="${CY}" r="${nodeR}" fill="var(--surface2)" stroke="var(--accent)" stroke-width="2.5" filter="url(#og)"/>`;
  svg+=`<text x="${CX}" y="${CY-6}" text-anchor="middle" dominant-baseline="middle" font-size="10" font-weight="700" fill="var(--accent)">OSPF ${esc(o.pid)}</text>`;
  svg+=`<text x="${CX}" y="${CY+7}" text-anchor="middle" font-size="8" fill="var(--text-dim)">${o.routerId||'routerId'}</text>`;
  svg+='</svg>';
  return`<div style="background:var(--surface2);border-radius:8px;padding:12px">${svg}</div>`;
}

function renderRoutingProtocols(){
  const ospf=parsed.ospf||[];
  const bgp=parsed.bgp||[];
  const rip=parsed.rip||[];
  if(!ospf.length&&!bgp.length&&!rip.length)
    return`<div class="nodata">${tr('rt.no_dynamic')}<br><span style="font-size:11px;color:var(--text-muted)">${tr('rt.no_dynamic_sub')}</span></div>`;
  let h='';
  // OSPF section
  if(ospf.length){
    h+=`<div style="padding:12px 18px 0"><div class="sec-title">OSPF（${ospf.length} ${tr('rt.n_process')}）</div></div>`;
    ospf.forEach(p=>{
      const totalNets=p.areas.reduce((s,a)=>s+a.networks.length,0);
      h+=`<div style="padding:4px 18px 10px"><div class="ov-card">
        <div class="ov-card-title">📡 OSPF ${tr('col.process_id')} ${esc(p.pid)}${p.routerId?' · Router-ID '+esc(p.routerId):''}</div>
        <table class="data-tbl"><thead><tr><th>${tr('col.area')}</th><th>${tr('col.announced_net')}</th></tr></thead><tbody>
        ${p.areas.map(a=>`<tr>
          <td><span class="pill p-info">Area ${esc(a.area)}</span>${a.type==='stub'?'<span class="pill p-warn" style="font-size:9px;padding:1px 4px;margin-left:4px">STUB</span>':a.type==='nssa'?'<span class="pill p-orange" style="font-size:9px;padding:1px 4px;margin-left:4px">NSSA</span>':''}</td>
          <td class="mono">${a.networks.map(n=>`<span class="pill p-route">${esc(n.network||n)}</span>`).join(' ')||'—'}</td>
        </tr>`).join('')}
        </tbody></table>
        ${p.redistributes&&p.redistributes.length?`<div style="padding-top:4px;font-size:11px;color:var(--text-dim)">Redistribute: ${p.redistributes.map(r=>`<span class="pill p-gray" style="font-size:10px">${esc(r)}</span>`).join(' ')}</div>`:''}
        <div style="padding-top:6px;font-size:11px;color:var(--text-dim)">${p.areas.length} ${tr('rt.ospf_footer')} · ${totalNets} ${tr('rt.net_announced')}</div>
      </div></div>`;
    });
  }
  // RIP section
  if(rip.length){
    h+=`<div style="padding:12px 18px 0"><div class="sec-title">RIP / RIPv2（${rip.length} ${tr('rt.n_process')}）</div></div>`;
    rip.forEach(r=>{
      const ver=r.version==='2'?'RIPv2':r.version==='1'?'RIPv1':'RIP';
      h+=`<div style="padding:4px 18px 10px"><div class="ov-card">
        <div class="ov-card-title">🛰️ ${ver} ${tr('col.process_id')} ${esc(r.pid)}${r.vrf?' · VRF '+esc(r.vrf):''}</div>
        <table class="data-tbl"><thead><tr><th>${tr('col.version')}</th><th>${tr('col.announced_net')}</th><th>${tr('col.redistribute')}</th><th>${tr('col.passive_if')}</th><th>${tr('col.auto_summary')}</th></tr></thead><tbody>
          <tr>
            <td>${pill('p-info',ver)}</td>
            <td class="mono">${(r.networks||[]).map(n=>`<span class="pill p-route">${esc(n)}</span>`).join(' ')||'—'}</td>
            <td class="mono">${(r.redistribute||[]).map(x=>esc(x)).join('<br>')||'—'}</td>
            <td class="mono">${(r.passive||[]).map(x=>esc(x)).join('<br>')||'—'}</td>
            <td>${r.autoSummary===false?pill('p-down',tr('rt.auto_sum_off')):r.autoSummary===true?pill('p-up',tr('rt.auto_sum_on')):pill('p-gray',tr('rt.auto_sum_none'))}</td>
          </tr>
        </tbody></table>
        <div style="padding-top:6px;font-size:11px;color:var(--text-dim)">Network: ${(r.networks||[]).length} · Peer/Neighbor: ${(r.peers||[]).length}${r.timers?' · Timers '+esc(r.timers):''}${r.defaultMetric?' · Default metric '+esc(r.defaultMetric):''}</div>
      </div></div>`;
    });
  }
  // BGP section
  if(bgp.length){
    h+=`<div style="padding:12px 18px 0"><div class="sec-title">BGP（${bgp.length} ${tr('rt.n_as')}）</div></div>`;
    bgp.forEach(b=>{
      const ibgp=b.peers.filter(p=>p.type==='iBGP');
      const ebgp=b.peers.filter(p=>p.type==='eBGP');
      h+=`<div style="padding:4px 18px 10px"><div class="ov-card">
        <div class="ov-card-title">🌐 BGP AS ${esc(b.asn)}${b.routerId?' · Router-ID '+esc(b.routerId):''}</div>
        ${b.peers.length?`<table class="data-tbl"><thead><tr><th>${tr('col.peer_ip')}</th><th>${tr('col.remote_as')}</th><th>${tr('col.type')}</th><th>${tr('col.desc')}</th></tr></thead><tbody>
        ${b.peers.map(p=>`<tr>
          <td class="mono" style="color:var(--accent3)">${esc(p.ip)}</td>
          <td class="mono">${esc(p.as)}</td>
          <td>${p.type==='iBGP'?pill('p-up','iBGP'):pill('p-route','eBGP')}</td>
          <td style="color:var(--text-dim)">${esc(p.desc||'—')}</td>
        </tr>`).join('')}
        </tbody></table>`:'<div style="color:var(--text-muted);font-size:12px;padding:4px 0">'+tr('rt.no_peers')+'</div>'}
        <div style="padding-top:6px;font-size:11px;color:var(--text-dim)">iBGP: ${ibgp.length} · eBGP: ${ebgp.length} · ${tr('rt.bgp_net')}: ${b.networks.length}${b.timers?` · Keepalive: ${b.timers.keepalive}s · Holdtime: ${b.timers.holdtime}s`:''}</div>
        ${b.peerGroups&&b.peerGroups.length?`<div style="padding-top:2px;font-size:11px;color:var(--text-dim)">Peer Groups: ${b.peerGroups.map(g=>`<span class="pill p-gray" style="font-size:10px">${esc(g.name)}${g.type?' ('+esc(g.type)+')':''}</span>`).join(' ')}</div>`:''}
      </div></div>`;
    });
  }
  const hasTopo=(bgp.length&&bgp[0].peers.length)||(ospf.length&&ospf[0].areas.length);
  const btnS=(a)=>`padding:4px 12px;border-radius:4px;border:1px solid ${a?'var(--accent)':'var(--border)'};cursor:pointer;font-size:12px;background:${a?'var(--accent)':'var(--surface2)'};color:${a?'#fff':'var(--text-dim)'}`;
  const toggle=hasTopo?`<div style="display:flex;gap:6px;padding:12px 18px 0">
    <button onclick="_rtView='table';navGo('routing')" style="${btnS(_rtView==='table')}">${tr('routing.view_table')}</button>
    <button onclick="_rtView='topo';navGo('routing')" style="${btnS(_rtView==='topo')}">${tr('routing.view_topo')}</button>
  </div>`:'';
  if(_rtView==='topo'&&hasTopo){
    let topo='';
    if(bgp.length&&bgp[0].peers.length)topo+=`<div style="padding:12px 18px"><div class="sec-title">${tr('routing.bgp_topo')}</div>${renderBGPTopo(bgp)}</div>`;
    if(ospf.length&&ospf[0].areas.length)topo+=`<div style="padding:12px 18px"><div class="sec-title">${tr('routing.ospf_area')}</div>${renderOSPFTopo(ospf)}</div>`;
    return`<div style="flex:1;overflow-y:auto">${toggle}${topo}</div>`;
  }
  return`<div style="flex:1;overflow-y:auto">${toggle}${h}</div>`;
}


// ══════════════════════════════════════════════════════
//  VRRP PARSER (全廠牌)
// ══════════════════════════════════════════════════════

// Comware: extract VRRP from merged interface blocks
function renderVRRP(){
  const groups=parsed.vrrp||[];
  const isHSRP=parsed.vendor==='cisco';
  const proto=isHSRP?'HSRP':'VRRP';
  if(!groups.length)
    return`<div class="nodata">${tr('msg.no_vrrp_pre')}${proto}${tr('msg.no_vrrp_suf')}</div>`;

  // Sort by interface then VRID
  const sorted=[...groups].sort((a,b)=>a.interface.localeCompare(b.interface)||parseInt(a.vrid)-parseInt(b.vrid));

  const rows=sorted.map(g=>({
    vrid:g.vrid, iface:g.interface, vip:g.vip, prio:g.priority,
    preempt:g.preempt, auth:g.authMode, track:g.trackIf, ver:g.version||'2',
    vrid_html:`<span class="pill p-stack">${proto} ${esc(g.vrid)}</span>`,
    iface_html:`<span class="mono" style="color:var(--accent3)">${esc(g.interface)}</span>`,
    vip_html:g.vip?`<span class="mono" style="color:var(--green)">${esc(g.vip)}</span>`:'<span style="color:var(--text-muted)">—</span>',
    prio_html:`<span class="mono" style="color:${parseInt(g.priority)>100?'var(--yellow)':parseInt(g.priority)===100?'var(--text-dim)':'var(--red)'}">${esc(g.priority)}</span>`,
    preempt_html:g.preempt?pill('p-up',tr('vrrp.preempt_yes')):pill('p-gray',tr('vrrp.preempt_no')),
    auth_html:g.authMode?pill('p-info',g.authMode):'<span style="color:var(--text-muted)">—</span>',
    track_html:g.trackIf?`<span class="mono">${esc(g.trackIf)}${g.trackReduced?' -'+g.trackReduced:''}</span>`:'—',
    ver_html:`<span class="pill p-info">v${esc(g.version||'2')}</span>`,
  }));

  const hdrs=[
    {key:'vrid',label:proto+' '+tr('col.vrrp_group')},
    {key:'iface',label:tr('col.iface')},
    {key:'vip',label:tr('col.vrrp_vip')},
    {key:'prio',label:tr('col.vrrp_priority')},
    {key:'ver',label:tr('col.version')},
    {key:'preempt',label:tr('col.vrrp_preempt')},
    {key:'auth',label:tr('col.vrrp_auth')},
    {key:'track',label:tr('col.vrrp_track_if')},
  ];
  // Stats
  const highPrio=groups.filter(g=>parseInt(g.priority)>100);
  const tracked=groups.filter(g=>g.trackIf);
  const preempts=groups.filter(g=>g.preempt);

  tableData=rows; tableKeys=hdrs.map(h=>h.key);
  const search=document.getElementById('search-inp')?.value?.toLowerCase()||'';
  let filtered=rows.filter(r=>!search||hdrs.some(h=>String(r[h.key]||'').toLowerCase().includes(search)));
  if(sortCol!==null){const key=tableKeys[sortCol];filtered=filtered.slice().sort((a,b)=>sortDir*(String(a[key]||'').localeCompare(String(b[key]||''),undefined,{numeric:true})));}
  const thRow=hdrs.map((h,i)=>`<th class="${sortCol===i?(sortDir===1?'sort-asc':'sort-desc'):''}" onclick="doSort(${i},'${h.key}')">${h.label}</th>`).join('');
  const body=filtered.map(r=>`<tr>${hdrs.map(h=>`<td>${r[h.key+'_html']||esc(String(r[h.key]??''))}</td>`).join('')}</tr>`).join('');

  return`<div style="flex:1;display:flex;flex-direction:column;overflow:hidden">
    <div class="tbar">
      <div class="search-wrap"><span class="search-ico">🔍</span><input class="search-inp" id="search-inp" placeholder="${tr('search.prefix')} ${proto}..." oninput="debouncedRenderView('vrrp')"></div>
      <button class="btn btn-ghost btn-sm" onclick="exportVRRPCSV()">${tr('btn.export_csv')}</button>
    </div>
    <div class="tbl-wrap"><table class="data-tbl"><thead><tr>${thRow}</tr></thead><tbody>${body}</tbody></table></div>
    <div class="tbl-foot">
      <span>${filtered.length} / ${rows.length} ${tr('unit.count')}</span>
      <span>${tr('vrrp.master_cand')}: ${highPrio.length} · ${tr('col.vrrp_preempt')}: ${preempts.length} · ${tr('vrrp.track_count')}: ${tracked.length}</span>
    </div>
  </div>`;
}

function exportVRRPCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  const isHSRP=parsed.vendor==='cisco';
  dlCSV(parsed.vrrp.map(g=>[g.vrid,g.interface,g.vip,g.priority,g.version||'2',g.preempt?tr('val.yes'):tr('val.no'),g.authMode||'',g.trackIf||'',g.trackReduced||'']),
    [tr('col.vrrp_group'),tr('col.iface'),tr('col.vrrp_vip'),tr('col.vrrp_priority'),tr('col.vrrp_version'),tr('col.vrrp_preempt'),tr('col.vrrp_auth'),tr('col.vrrp_track_if'),tr('col.vrrp_track_dec')],
    `${hn()}_${isHSRP?'hsrp':'vrrp'}.csv`);
}

// ── renderVXLAN ──────────────────────────────────────────────
function renderVXLAN(){
  const vx=parsed.vxlan;
  if(!vx||(!vx.vnis?.length&&!vx.evpn?.length))
    return'<div class="nodata">'+tr('msg.no_vxlan')+'</div>';

  let h='';

  // VTEP Info card
  h+=`<div style="padding:12px 18px 0"><div class="ov-grid" style="padding:0;margin-bottom:12px">
    <div class="ov-card">
      <div class="ov-card-title">${tr('vxlan.vtep_title')}</div>
      <div class="ov-row"><span class="ov-key">${tr('vxlan.vtep_src_ip')}</span><span class="ov-val mono">${esc(vx.vtep||'—')}</span></div>
      <div class="ov-row"><span class="ov-key">${tr('vxlan.vni_count')}</span><span class="ov-val" style="color:var(--purple)">${vx.vnis.length}</span></div>
      <div class="ov-row"><span class="ov-key">${tr('vxlan.evpn_instances')}</span><span class="ov-val" style="color:var(--teal)">${vx.evpn?.length||0}</span></div>
      <div class="ov-row"><span class="ov-key">${tr('vxlan.fwd_mode')}</span><span class="ov-val">${vx.vnis.some(v=>v.mode==='BGP-EVPN')?pill('p-info','BGP-EVPN MP-BGP'):pill('p-gray','Static/Ingress')}</span></div>
    </div>
  </div></div>`;

  // VNI table
  if(vx.vnis.length){
    h+=`<div style="padding:4px 18px 10px">
    <div class="sec-title">${tr('vxlan.vni_list')}（${vx.vnis.length}）</div>
    <div class="ov-card" style="padding:0;overflow:hidden">
    <table class="data-tbl">
      <thead><tr><th>VNI</th><th>${tr('col.vxlan_name')}</th><th>${tr('vxlan.col_vlan')}</th><th>${tr('vxlan.fwd_mode')}</th><th>${tr('col.vxlan_encap')}</th><th>${tr('col.vxlan_gw')}</th><th>${tr('col.vxlan_peers')}</th></tr></thead>
      <tbody>${vx.vnis.map(v=>`<tr>
        <td><span class="pill p-purple" style="background:rgba(167,139,250,.12);color:var(--purple);border:1px solid rgba(167,139,250,.3)">${esc(v.vni)}</span></td>
        <td class="mono" style="color:var(--text-dim)">${esc(v.name||'—')}</td>
        <td>${v.vlan?pill('p-vlan','V'+v.vlan):'<span style="color:var(--text-muted)">—</span>'}</td>
        <td>${v.mode==='BGP-EVPN'?pill('p-info','BGP-EVPN'):pill('p-gray','Static')}</td>
        <td class="mono">${esc(v.encap||'vxlan')}</td>
        <td class="mono">${esc(v.gw||'—')}</td>
        <td class="mono" style="font-size:10px">${v.peers?.length?v.peers.join('<br>'):'<span style="color:var(--text-muted)">—</span>'}</td>
      </tr>`).join('')}
      </tbody>
    </table></div></div>`;
  }

  // EVPN instances
  if(vx.evpn?.length){
    h+=`<div style="padding:4px 18px 10px">
    <div class="sec-title">${tr('vxlan.evpn_list')}（${vx.evpn.length}）</div>
    <div class="ov-card" style="padding:0;overflow:hidden">
    <table class="data-tbl">
      <thead><tr><th>${tr('vxlan.col_inst_name')}</th><th>${tr('vxlan.col_rd')}</th><th>${tr('vxlan.col_rt_import')}</th><th>${tr('vxlan.col_rt_export')}</th></tr></thead>
      <tbody>${vx.evpn.map(e=>`<tr>
        <td style="font-weight:700">${esc(e.name)}</td>
        <td class="mono">${esc(e.rd||'—')}</td>
        <td class="mono" style="color:var(--green)">${esc(e.rtImport||'—')}</td>
        <td class="mono" style="color:var(--yellow)">${esc(e.rtExport||'—')}</td>
      </tr>`).join('')}
      </tbody>
    </table></div></div>`;
  }

  h+=`<div style="padding:0 18px 14px">
    <button class="btn btn-ghost btn-sm" onclick="exportVXLANCSV()">${tr('btn.export_vni_csv')}</button>
  </div>`;

  return`<div style="flex:1;overflow-y:auto">${h}</div>`;
}

function exportVXLANCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  dlCSV(parsed.vxlan.vnis.map(v=>[v.vni,v.name,v.vlan,v.mode,v.encap||'vxlan',v.gw,v.peers?.join(';')||'']),
    ['VNI',tr('col.vxlan_name'),'VLAN',tr('col.vxlan_mode'),tr('col.vxlan_encap'),tr('col.vxlan_gw'),tr('col.vxlan_peers')],
    `${hn()}_vxlan_vni.csv`);
}


// ── renderDHCP ───────────────────────────────────────────────
function renderDNS(){
  const servers=parsed.dns||[];
  if(!servers.length)return'';
  return`<div style="padding:12px 18px 0"><div class="sec-title">🌐 ${tr('dns.title')}（${servers.length}）</div></div>
  <div style="padding:4px 18px 14px"><div class="ov-card">
    <table class="data-tbl">
      <thead><tr><th>#</th><th>${tr('dns.col_server')}</th></tr></thead>
      <tbody>
      ${servers.map((ip,i)=>`<tr><td>${i+1}</td><td class="mono" style="color:var(--green)">${esc(ip)}</td></tr>`).join('')}
      </tbody>
    </table>
    <div style="padding-top:6px"><button class="btn btn-ghost btn-sm" onclick="exportDNSCSV()">⬇ CSV</button></div>
  </div></div>`;
}

function exportDNSCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  dlCSV((parsed.dns||[]).map((ip,i)=>[i+1,ip]),['#',tr('dns.col_server')],`${hn()}_dns.csv`);
}

function renderDHCP(){
  const pools=(parsed.dhcp||[]);
  const dnsServers=(parsed.dns||[]);
  if(!pools.length&&!dnsServers.length)
    return'<div class="nodata">'+tr('msg.no_dhcp')+'</div>';

  const servers=pools.filter(d=>d.type==='server'||!d.type);
  const relays =pools.filter(d=>d.type==='relay');

  let h=renderDNS();

  // ── Server pools ──────────────────────────────────────────
  if(servers.length){
    const hdrs=[
      {key:'name',   label:tr('col.dhcp_pool')},
      {key:'network',label:tr('col.dhcp_network')},
      {key:'range',  label:tr('col.dhcp_range')},
      {key:'gateway',label:tr('col.gw')},
      {key:'dns',    label:tr('col.dhcp_dns')},
      {key:'iface',  label:tr('col.iface')},
      {key:'extra',  label:tr('dhcp.col_extra')},
    ];

    const rows=servers.map(d=>{
      const rangeStr=d.range||(d.low&&d.high?d.low+' – '+d.high:'')||'—';
      const dnsStr=Array.isArray(d.dns)?d.dns.join(', '):(d.dns||'—');
      const extra=[];
      if(d.lease)extra.push(tr('dhcp.lease_label')+': '+d.lease);
      if(d.excluded)extra.push(tr('dhcp.excl_label')+': '+d.excluded);
      if(d.bootFile)extra.push(tr('dhcp.boot_label')+': '+d.bootFile);
      if(d.nextServer)extra.push(tr('dhcp.next_server_label')+': '+d.nextServer);
      if(d.ntpServer)extra.push(tr('dhcp.ntp_label')+': '+d.ntpServer);
      return{
        name:    d.name||'—',
        network: d.network||'—',
        range:   rangeStr,
        gateway: d.gateway||'—',
        dns:     dnsStr,
        iface:   d.interface||'—',
        extra:   extra.join(' | ')||'—',
      };
    });

    tableData=rows; tableKeys=hdrs.map(x=>x.key);
    const search=document.getElementById('search-inp')?.value?.toLowerCase()||'';
    let filtered=rows.filter(r=>!search||Object.values(r).some(v=>String(v).toLowerCase().includes(search)));
    if(sortCol!==null){
      const key=tableKeys[sortCol];
      filtered=filtered.slice().sort((a,b)=>sortDir*(String(a[key]||'').localeCompare(String(b[key]||''),undefined,{numeric:true})));
    }
    const thRow=hdrs.map((h2,i)=>`<th class="${sortCol===i?(sortDir===1?'sort-asc':'sort-desc'):''}" onclick="doSort(${i},'${h2.key}')">${h2.label}</th>`).join('');
    const body=filtered.map(r=>`<tr>
      <td style="font-weight:700">${esc(r.name)}</td>
      <td class="mono">${esc(r.network)}</td>
      <td class="mono" style="color:var(--green)">${esc(r.range)}</td>
      <td class="mono">${esc(r.gateway)}</td>
      <td class="mono">${esc(r.dns)}</td>
      <td class="mono">${esc(r.iface)}</td>
      <td style="font-size:11px;color:var(--text-dim)">${esc(r.extra)}</td>
    </tr>`).join('');

    h+=`<div style="padding:12px 18px 0"><div class="sec-title">🔌 ${tr('dhcp.server_title')}（${servers.length}）</div></div>
    <div style="padding:4px 18px 10px">
    <div class="tbar" style="margin-bottom:6px">
      <div class="search-wrap"><span class="search-ico">🔍</span>
        <input class="search-inp" id="search-inp" placeholder="${tr('search.placeholder')}" oninput="debouncedRenderView('dhcp')">
      </div>
      <button class="btn btn-ghost btn-sm" onclick="exportDHCPCSV()">⬇ CSV</button>
    </div>
    <div class="tbl-wrap"><table class="data-tbl">
      <thead><tr>${thRow}</tr></thead>
      <tbody>${body}</tbody>
    </table></div>
    <div class="tbl-foot"><span>${filtered.length} / ${rows.length} ${tr('unit.count')}</span></div>
    </div>`;
  }

  // ── Relay entries ─────────────────────────────────────────
  if(relays.length){
    h+=`<div style="padding:12px 18px 0"><div class="sec-title">🔀 DHCP Relay（${relays.length}）</div></div>
    <div style="padding:4px 18px 14px"><div class="ov-card">
      <table class="data-tbl">
        <thead><tr><th>${tr('dhcp.col_group')}</th><th>${tr('dhcp.col_relay_if')}</th><th>${tr('dhcp.col_relay_server')}</th><th>${tr('dhcp.col_option82')}</th></tr></thead>
        <tbody>
        ${relays.map(d=>`<tr>
          <td style="font-weight:700">${esc(d.name||d.interface||'—')}</td>
          <td class="mono">${esc(d.interface||'—')}</td>
          <td class="mono" style="color:var(--green)">${esc(d.relayServer||d.server||'—')}</td>
          <td>${d.option82?'✅':'—'}</td>
        </tr>`).join('')}
        </tbody>
      </table>
    </div></div>`;
  }

  return`<div style="flex:1;overflow-y:auto">${h}</div>`;
}

function exportACLCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  const acls=parsed.acls||[];
  const rows=[];
  acls.forEach(a=>a.rules.forEach(r=>rows.push([
    a.name,r.seq||'',r.action||'',r.src||'any',r.dst||'any',
    r.protocol||'',r.dstPort||'',r.remark||''
  ])));
  dlCSV(rows,[tr('col.name'),tr('acl.col_seq'),tr('acl.col_action'),tr('acl.col_src'),tr('acl.col_dst'),tr('acl.col_proto'),tr('acl.col_port'),tr('acl.col_remark')],`${hn()}_acl.csv`);
}
function exportUsersCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  dlCSV(parsed.users.map(u=>[u.name,u.role||'—',u.service||'—',u.hasPwd?'yes':'no',u.pwdType||'',u.pwdWeak?'weak':'']),
    [tr('col.username'),tr('col.role'),tr('col.svc_type'),tr('col.password'),tr('col.enc_strength'),tr('rpt.col_pwd_strength')],`${hn()}_users.csv`);
}
function exportRoutingCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  const rows=[];
  (parsed.ospf||[]).forEach(o=>{
    rows.push(['OSPF',o.pid||'',o.routerId||'',`Area:${(o.areas||[]).map(a=>a.area).join(';')}`,'','','',(o.redistributes||[]).join(';')]);
  });
  (parsed.bgp||[]).forEach(b=>{
    (b.peers||[]).forEach(p=>rows.push(['BGP',b.asn||'',b.routerId||'',`Peer:${p.ip}`,p.as||'',p.type||'',p.desc||'','']));
    if(!(b.peers||[]).length)rows.push(['BGP',b.asn||'',b.routerId||'','','','','','']);
  });
  (parsed.rip||[]).forEach(r=>{
    const areaPeers=`Net:${(r.networks||[]).join(';')}${(r.peers||[]).length?' Peer:'+(r.peers||[]).join(';'):''}`;
    const desc=`v${r.version||''}${r.timers?'; Timers '+r.timers:''}`;
    rows.push(['RIP',r.pid||'','',areaPeers,'','',desc,(r.redistribute||[]).join(';')]);
  });
  dlCSV(rows,['Protocol','AS/PID',tr('rt.router_id'),tr('rt.area_peers'),tr('col.remote_as'),tr('col.type'),tr('col.desc'),tr('col.redistribute')],`${hn()}_routing.csv`);
}
function exportDHCPCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  dlCSV((parsed.dhcp||[]).filter(d=>d.type==='server'||!d.type).map(d=>[
    d.name,d.network,d.range||(d.low&&d.high?d.low+'-'+d.high:''),
    d.gateway,Array.isArray(d.dns)?d.dns.join(';'):d.dns,d.interface,
    d.bootFile||'',d.nextServer||'',d.ntpServer||''
  ]),[tr('col.dhcp_pool'),tr('col.dhcp_network'),tr('col.dhcp_range'),tr('col.gw'),tr('col.dhcp_dns'),tr('col.iface'),
    tr('dhcp.col_boot'),tr('dhcp.col_next_server'),tr('dhcp.col_ntp')],`${hn()}_dhcp.csv`);
}
function exportSecurityCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  dlCSV(
    (parsed.security||[]).map(s=>[s.port,s.dot1x||'-',s.portSec?tr('val.yes'):tr('val.no'),s.maxMac||'-',s.violation||'-',s.guestVlan||'-']),
    [tr('col.interface'),'802.1X',tr('sec.port_sec'),tr('sec.max_mac'),tr('sec.violation'),tr('sec.guest_vlan')],
    `${hn()}_security.csv`
  );
}
function exportQoSCSV(){
  if(!parsed){alert(tr('msg.no_config'));return;}
  dlCSV(
    (parsed.qos||[]).map(q=>[q.policy||'-',q.cls||'-',q.action||'-',q.rate||'-',q.burst||'-',q.behavior||'-']),
    [tr('qos.policy'),tr('qos.class'),tr('qos.action'),tr('qos.rate'),tr('qos.burst'),tr('qos.behavior')],
    `${hn()}_qos.csv`
  );
}

(function(){
  // Sidebar collapse persistence
  try{
    if(localStorage.getItem('cw_sb')==='1'){
      sbMini=true;
      document.getElementById('sidebar').classList.add('sb-mini');
      const btn=document.getElementById('sb-toggle');
      if(btn){btn.textContent='›';btn.title=tr('sb.expand');}
    }
  }catch(e){}

  // Drag-drop on upload card
  const dz=document.getElementById('drop-zone');
  if(dz){
    dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('drag-over');});
    dz.addEventListener('dragleave',()=>dz.classList.remove('drag-over'));
    dz.addEventListener('drop',e=>{
      e.preventDefault();dz.classList.remove('drag-over');
      const f=e.dataTransfer.files[0];if(f)readFile(f);
    });
  }

  // Easter egg: logo click counter
  const logoBtn=document.getElementById('logo-btn');
  if(logoBtn){
    let clicks=0,timer=null,rainActive=false,alphaClicks=0,alphaTimer=null;
    logoBtn.addEventListener('click',()=>{
      if(rainActive){
        alphaClicks++;clearTimeout(alphaTimer);
        alphaTimer=setTimeout(()=>alphaClicks=0,1500);
        if(alphaClicks>=3){startRain(true);alphaClicks=0;}
        return;
      }
      clicks++;clearTimeout(timer);
      timer=setTimeout(()=>clicks=0,1500);
      if(clicks>=5){clicks=0;rainActive=true;startRain(false);setTimeout(()=>rainActive=false,5000);}
    });
  }
})();

// 彩蛋：搜尋框輸入 ollama / alpaca
(function(){
  const inp = document.getElementById('search-inp');
  if(!inp) return;
  inp.addEventListener('input', function() {
    const q = this.value.toLowerCase();
    if(q === 'ollama' || q === 'alpaca') showEggToast(tr('egg.ollama'));
  });
})();

setLang('zhTW');

(function(){
  var _p = localStorage.getItem('_netAnalyzer_pending');
  if (!_p) return;
  try {
    var d = JSON.parse(_p);
    if (Date.now() - d.ts > 10000) { localStorage.removeItem('_netAnalyzer_pending'); return; }
    localStorage.removeItem('_netAnalyzer_pending');
    var pa = document.getElementById('paste-area');
    if (pa) pa.value = d.text;
    var chip = document.getElementById('file-chip');
    var fname = document.getElementById('fname');
    if (chip) chip.style.display = '';
    if (fname) fname.textContent = d.name;
    doAnalyze();
  } catch(e) {}
})();

// 名詞解釋 tooltip
(function(){
  var _t = document.createElement('div');
  _t.className = 'global-tip';
  document.body.appendChild(_t);
  document.addEventListener('mouseover', function(e) {
    var el = e.target.closest('[data-tip]');
    if (!el) return;
    _t.textContent = el.dataset.tip;
    _t.style.display = 'block';
    var r = el.getBoundingClientRect(), tw = _t.offsetWidth, th = _t.offsetHeight;
    var x = r.left + r.width / 2 - tw / 2;
    x = Math.max(8, Math.min(x, window.innerWidth - tw - 8));
    var y = r.top - th - 8;
    _t.style.left = x + 'px';
    _t.style.top = (y < 8 ? r.bottom + 8 : y) + 'px';
  });
  document.addEventListener('mouseout', function(e) {
    if (e.target.closest('[data-tip]')) _t.style.display = 'none';
  });
  document.addEventListener('scroll', function() { _t.style.display = 'none'; }, true);
})();

// 彩蛋：羊駝 3 連擊解鎖克林貢
(function(){
  var _kN=0,_kT;
  document.addEventListener('click',function(e){
    var ac=document.getElementById('mini-alpaca');
    if(!ac||(!ac.contains(e.target)&&ac!==e.target))return;
    clearTimeout(_kT);_kN++;
    _kT=setTimeout(function(){_kN=0;},2000);
    if(_kN>=3){
      _kN=0;
      document.getElementById('lang-klingon').style.display='';
      setLang('tlh');
      var t=document.createElement('div');t.className='qapla-toast';
      t.textContent="🖖 Qapla'! tlhIngan Hol DaghojneS!";
      document.body.appendChild(t);
      t.addEventListener('animationend',function(ev){if(ev.animationName==='qapla-out')t.remove();});
    }
  });
})();

// 彩蛋：lang-egg 代表物三連擊
(function(){
  var _EGG={
    'egg-pirate':{lang:'pirate',btn:'lang-pirate',toast:"☠️ Ahoy! Ye be speakin' pirate now, matey! Arr!"},
    'egg-leet':  {lang:'leet',  btn:'lang-leet',  toast:'1337 5P34K 4C71V473D. H4X0R M0D3 0N.'},
    'egg-emoji': {lang:'emoji', btn:'lang-emoji',  toast:'🌈✨🎉 3moji mod3 4ctiv4t3d! 🦄💫🌟'},
    'egg-uwu':   {lang:'uwu',   btn:'lang-uwu',   toast:'🐾 Hewwo fwend~ UwU wanguage activeated! OwO'},
    'egg-bureau':{lang:'bureau',btn:'lang-bureau',toast:'📋 啟動跨部門作業流程。本系統正式進入公文模式。請依規定格式呈現。'},
    'egg-cat':   {lang:'cat',   btn:'lang-cat',   toast:'🐱 Nyaa~！喵語模式啟動了喵！meow meow owo'},
    'egg-bean':  {lang:'bean',  btn:'lang-bean',  toast:'🥕🫛🌽 豆語模式啟動！蔬菜智慧已降臨！🌽🫛🥕'},
    'egg-alpaca':{lang:'alpaca',btn:'lang-alpaca',toast:'🦙 咩咩咩！羊咩碼啟動-aca！上傳咩設咩定-aca！🦙'},'egg-yanse':{lang:'yanse',btn:'lang-yanse',toast:'💀 overtime detected...厭世工程師模式啟動，反正早晚都要加班'},
  };
  var _eN={},_eT={};
  document.querySelectorAll('.lang-egg').forEach(function(el){
    _eN[el.id]=0;
    el.addEventListener('click',function(){
      clearTimeout(_eT[el.id]);
      _eN[el.id]++;
      _eT[el.id]=setTimeout(function(){_eN[el.id]=0;},1500);
      if(_eN[el.id]>=3){
        _eN[el.id]=0;
        var c=_EGG[el.id];
        document.getElementById(c.btn).style.display='';
        setLang(c.lang);
        showEggToast(c.toast);
      }
    });
  });
})();

// Console 彩蛋
console.log('%c Switch Analyzer  ·  羊駝驅動的交換器解析工具 🦙','color:#00c8f0;font-family:monospace;font-size:13px;font-weight:bold');
console.log('%c 彩蛋提示 → Logo ×5 | Konami Code ↑↑↓↓←→←→BA | vendor badge ×7 | 點羊駝','color:#64748b;font-family:monospace;font-size:10px');

// ── 搜尋彩蛋 ───────────────────────────────────────────────
function _showSwitchToast(msg, duration=3500) {
  let t=document.getElementById('sw-egg-toast');
  if(!t){t=document.createElement('div');t.id='sw-egg-toast';
    Object.assign(t.style,{position:'fixed',bottom:'28px',left:'50%',transform:'translateX(-50%)',
      background:'var(--surface)',border:'1px solid var(--accent)',borderRadius:'10px',
      padding:'10px 20px',fontSize:'13px',color:'var(--text)',boxShadow:'0 4px 18px rgba(0,0,0,.35)',
      zIndex:'9999',opacity:'0',transition:'opacity .3s',maxWidth:'400px',textAlign:'center'});
    document.body.appendChild(t);}
  t.textContent=msg;t.style.opacity='1';
  clearTimeout(t._tid);t._tid=setTimeout(()=>{t.style.opacity='0';},duration);
}

// 通用 debounce 工具：搜尋輸入框每次按鍵都觸發整頁重繪，資料量大時會卡頓，
// 改為停止輸入 150ms 後才真正重繪
function debounce(fn, delay) {
  let t;
  return function (...args) {
    clearTimeout(t);
    t = setTimeout(() => fn.apply(this, args), delay);
  };
}
const debouncedRenderView = debounce((v) => renderView(v), 150);

function onSearchInputImpl() {
  const inp = document.getElementById('search-inp');
  const lc = (inp ? inp.value : '').trim().toLowerCase();
  const _cmds = {
    'rm -rf /': tr('egg.cmd_rm'), 'sudo': tr('egg.cmd_sudo'),
    'ping': tr('egg.cmd_ping'),   'exit': tr('egg.cmd_exit'),
    'help': tr('egg.cmd_help'),   'reboot': tr('egg.cmd_reboot'),
  };
  if (_cmds[lc]) { _showSwitchToast(_cmds[lc]); if(inp) inp.value=''; return; }
  if(lc==='overtime'){setLang('yanse');const lb=document.getElementById('lang-yanse');if(lb)lb.style.display='';_showSwitchToast(tr('egg.cmd_overtime'));if(inp)inp.value='';return;}
  renderView(currentView);
}
const onSearchInput = debounce(onSearchInputImpl, 150);

// ── 廠牌擬人化：triple-click vendor badge ──────────────────
function _setupVendorPersona() {
  const vbEl = document.getElementById('tb-vendor');
  if (!vbEl) return;
  let n = 0, t = null;
  vbEl.addEventListener('click', () => {
    n++; clearTimeout(t);
    t = setTimeout(() => { n = 0; }, 2500);
    if (n === 3) {
      n = 0;
      const vendor = parsed ? parsed.vendor : '';
      const msg = vendor ? tr('egg.vendor_' + vendor) : '';
      if (msg) _showSwitchToast(msg, 4500);
    }
  });
}

// 黑/白模式切換
function setTheme(t){document.body.dataset.theme=t;const b=document.getElementById('theme-btn');if(b)b.textContent=t==='light'?'🌙':'☀️';localStorage.setItem('cw_theme',t);}
function toggleTheme(){setTheme(document.body.dataset.theme==='light'?'dark':'light');}
(function(){const s=localStorage.getItem('cw_theme');const p=s||(window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');if(p==='light')setTheme('light');})();

