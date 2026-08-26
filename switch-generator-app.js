function rowsOf(sel){return Array.from(document.querySelectorAll(sel));}
function val(tr,cls){const el=tr.querySelector('.'+cls);if(!el)return'';return el.type==='checkbox'?el.checked:el.value.trim();}
function markInvalid(el){if(el)el.classList.add('invalid');}

// IPv4/CIDR 格式驗證輔助函式：取代 validateForm() 原本 4 處重複貼上的內聯正則
// （僅比對格式＋每段 0-255 範圍，不比對子網對齊等進階語意）
function isValidIPv4(s){
  const m=(s||'').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every(o=>parseInt(o,10)<=255);
}
function isValidCIDR(s){
  const m=(s||'').match(/^(\S+)\/(\d{1,2})$/);
  return !!m && isValidIPv4(m[1]) && parseInt(m[2],10)>=0 && parseInt(m[2],10)<=32;
}

// 22 個 addXxxRow() 函式逐字重複的刪除按鈕儲存格，抽成共用常數（純去重，行為不變）
const RM_BTN_TD='<td><button class="rm-btn" onclick="this.closest(\'tr\').remove()">✕</button></td>';

// addXxxRow() 系列函式一律用字串內插組 `value="${x}"` 這類雙引號屬性寫進 innerHTML，
// 範本/匯入資料若含雙引號（如備註欄位填 `Uplink to "Core-SW"`）會提前結束屬性，
// 讓後面的字元變成裸露在標籤內的內容，導致該列 HTML 結構損毀。統一escape後供全部
// addXxxRow() 函式使用，只跳脫雙引號本身（這些欄位都是塞進 value="..." 屬性，非
// innerHTML 內容本身，不需要跳脫 &/</>）
const escAttr=v=>String(v==null?'':v).replace(/"/g,'&quot;');
function addVlanRow(id='',name=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="v-id" value="${escAttr(id)}"></td><td><input class="v-name" value="${escAttr(name)}"></td>${RM_BTN_TD}`;
  document.getElementById('vlan-body').appendChild(tr);
}

function addIfaceRow(name='',mode='access',speed='1G',poeMode='none',fortilinkDiscovery='',qosPriority='',trustDscp=false){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="i-name" value="${escAttr(name)}"></td>
    <td><input class="i-desc"></td>
    <td><select class="i-speed" onchange="onSpeedChange(this)">
      <option value="1G" data-i18n="opt.speed1G">1G</option>
      <option value="10G" data-i18n="opt.speed10G">10G</option>
      <option value="25G" data-i18n="opt.speed25G">25G</option>
      <option value="40G" data-i18n="opt.speed40G">40G</option>
      <option value="100G" data-i18n="opt.speed100G">100G</option>
    </select></td>
    <td><select class="i-mode" onchange="updateIfaceRowDisplay(this)">
      <option value="access" data-i18n="opt.access">Access</option>
      <option value="trunk" data-i18n="opt.trunk">Trunk</option>
      <option value="hybrid" data-i18n="opt.hybrid">Hybrid</option>
    </select></td>
    <td class="col-access"><input class="i-access-vlan"></td>
    <td class="col-trunk"><input class="i-trunk-vlans" placeholder="10 20 30"></td>
    <td class="col-trunk"><input class="i-native-vlan"></td>
    <td class="col-hybrid"><input class="i-hy-untagged" placeholder="30"></td>
    <td class="col-hybrid"><input class="i-hy-tagged" placeholder="20"></td>
    <td class="col-hybrid"><input class="i-hy-pvid"></td>
    <td style="text-align:center"><input type="checkbox" class="i-shutdown"></td>
    <td style="text-align:center"><input type="checkbox" class="i-jumbo-en"></td>
    <td><input class="i-jumbo-mtu" placeholder="9216"></td>
    <td><select class="i-poe-mode">
      <option value="none" data-i18n="opt.poeNone">None</option>
      <option value="auto" data-i18n="opt.poeAuto">Auto</option>
      <option value="never" data-i18n="opt.poeNever">Never</option>
      <option value="static-max" data-i18n="opt.poeStaticMax">Static Max</option>
      <option value="static-high" data-i18n="opt.poeStaticHigh">Static High</option>
    </select></td>
    <td class="col-fortilink"><select class="i-fortilink">
      <option value="" data-i18n="opt.fortilinkUnset">Default</option>
      <option value="enable" data-i18n="opt.fortilinkEnable">Enable</option>
      <option value="disable" data-i18n="opt.fortilinkDisable">Disable</option>
    </select></td>
    <td class="col-brocade-qos"><select class="i-qos-priority">
      <option value="">-</option>
      <option value="0">0</option><option value="1">1</option><option value="2">2</option><option value="3">3</option>
      <option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option>
    </select></td>
    <td class="col-brocade-qos" style="text-align:center"><input type="checkbox" class="i-trust-dscp"></td>
    <td><button class="rm-btn" onclick="this.closest('tr').remove();updateIfaceTableDisplay()">✕</button></td>`;
  tr.querySelector('.i-mode').value=mode;
  tr.querySelector('.i-speed').value=speed;
  tr.querySelector('.i-poe-mode').value=poeMode;
  tr.querySelector('.i-fortilink').value=fortilinkDiscovery;
  tr.querySelector('.i-qos-priority').value=qosPriority;
  tr.querySelector('.i-trust-dscp').checked=!!trustDscp;
  document.getElementById('iface-body').appendChild(tr);
  applyI18n(tr);
  updateModeOptions();
  updateIfaceRowDisplay(tr.querySelector('.i-mode'));
}

const SPEED_PREFIX={
  comware:{'1G':'GigabitEthernet','10G':'Ten-GigabitEthernet','25G':'Twenty-FiveGigE','40G':'FortyGigE','100G':'HundredGigE'},
  cisco:{'1G':'GigabitEthernet','10G':'TenGigabitEthernet','25G':'TwentyFiveGigE','40G':'FortyGigabitEthernet','100G':'HundredGigE'},
  juniper:{'1G':'ge-','10G':'xe-','25G':'xe-','40G':'et-','100G':'et-'},
};
function onSpeedChange(sel){
  const prefixMap=SPEED_PREFIX[document.getElementById('vendor').value];
  if(!prefixMap)return;
  const nameInput=sel.closest('tr').querySelector('.i-name');
  const m=nameInput.value.match(/^[A-Za-z-]+(\d.*)$/);
  const suffix=m?m[1]:nameInput.value;
  nameInput.value=prefixMap[sel.value]+suffix;
}
// 匯入既有設定檔時，解析結果只有介面名稱字串（無獨立 speed 欄位），反查 SPEED_PREFIX
// 找出對應速度；juniper 的 10G/25G 皆為 'xe-'、40G/100G 皆為 'et-'，屬真實語法本身的
// 命名歧義（非本函式邏輯錯誤），同長度時取表內宣告順序在前者（best-effort，非精確判斷）。
function inferSpeedFromName(name,vendor){
  const prefixMap=SPEED_PREFIX[vendor];
  if(!prefixMap||!name)return '1G';
  let best=null;
  for(const [speed,prefix] of Object.entries(prefixMap)){
    if(prefix&&name.startsWith(prefix)&&(!best||prefix.length>best.prefix.length))best={speed,prefix};
  }
  return best?best.speed:'1G';
}

function updateIfaceRowDisplay(modeSelector){
  const tr=modeSelector.closest('tr');
  const mode=modeSelector.value;
  const cells=tr.querySelectorAll('td');
  cells.forEach(cell=>{
    cell.classList.remove('show');
    if((mode==='access' && cell.classList.contains('col-access'))||
       (mode==='trunk' && cell.classList.contains('col-trunk'))||
       (mode==='hybrid' && cell.classList.contains('col-hybrid'))){
      cell.classList.add('show');
    }
  });
  updateIfaceTableDisplay();
}

function updateIfaceTableDisplay(){
  const table=document.getElementById('iface-table');
  if(!table)return;
  const rows=table.querySelectorAll('tbody tr');
  const hasAccess=Array.from(rows).some(r=>r.querySelector('.i-mode').value==='access');
  const hasTrunk=Array.from(rows).some(r=>r.querySelector('.i-mode').value==='trunk');
  const hasHybrid=Array.from(rows).some(r=>r.querySelector('.i-mode').value==='hybrid');
  const headers=table.querySelectorAll('thead th');
  headers.forEach(th=>{
    th.classList.remove('show');
    if((hasAccess && th.classList.contains('col-access'))||
       (hasTrunk && th.classList.contains('col-trunk'))||
       (hasHybrid && th.classList.contains('col-hybrid'))){
      th.classList.add('show');
    }
  });
}

// 常用機種預設 Interface 清單：純前端 UI 便利功能，不涉及 switch_analyzer、不影響
// round-trip 正確性。ports 陣列每項目要嘛是 {prefix,from,to,speed}（連續編號的一般
// 埠位，展開成 prefix+N）要嘛是 {name,speed,mgmt:true}（單一命名的 mgmt 介面）
const DEVICE_MODELS={
  comware:[
    {value:'hpe5130-24',label:'HPE 5130-24S-2GT-2SFP+ (JG932A)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:25,to:26,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true},
    ],poe:false},
    {value:'hpe5130-48',label:'HPE 5130-48S (48×1G)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},{prefix:'Ten-GigabitEthernet1/0/',from:49,to:52,speed:'10G'},{name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5210',label:'HPE 5210-24 (中端模組)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},{prefix:'Ten-GigabitEthernet1/0/',from:25,to:28,speed:'10G'},{name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe12900',label:'HPE 12900 (高端模組化)',ports:[{prefix:'HundredGigabitEthernet1/0/',from:1,to:4,speed:'100G'},{name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5140-24',label:'HPE 5140-24G-2SFP+',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:25,to:26,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5140-48',label:'HPE 5140-48G-4SFP+',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:49,to:52,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5710-48',label:'HPE 5710-48G-4SFP+',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:49,to:52,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5945',label:'HPE FlexFabric 5945 (模組化核心)',ports:[
      {prefix:'HundredGigabitEthernet1/0/',from:1,to:2,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5945-2slot',label:'HPE FlexFabric 5945 2-slot (模組化核心)',ports:[
      {prefix:'HundredGigabitEthernet1/0/',from:1,to:2,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5945-4slot',label:'HPE FlexFabric 5945 4-slot (模組化核心)',ports:[
      {prefix:'HundredGigabitEthernet1/0/',from:1,to:8,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5945-48sfp28-8qsfp28',label:'HPE FlexFabric 5945 48SFP28 8QSFP28',ports:[
      {prefix:'Twenty-FiveGigE1/0/',from:1,to:48,speed:'25G'},
      {prefix:'HundredGigabitEthernet1/0/',from:49,to:56,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5720-32',label:'HPE 5720 32×SFP+ 1G/10G + 6×QSFP28 100G (S2N57A)',ports:[
      {prefix:'Ten-GigabitEthernet1/0/',from:1,to:32,speed:'10G'},
      {prefix:'HundredGigabitEthernet1/0/',from:33,to:38,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5720-48',label:'HPE 5720 48×SFP+ 1G/10G + 6×QSFP28 100G (S2N58A)',ports:[
      {prefix:'Ten-GigabitEthernet1/0/',from:1,to:48,speed:'10G'},
      {prefix:'HundredGigabitEthernet1/0/',from:49,to:54,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5720-24t',label:'HPE 5720 24×10GBASE-T + 8×SFP+ 1G/10G + 6×QSFP28 100G (S2N59A)',ports:[
      {prefix:'Ten-GigabitEthernet1/0/',from:1,to:32,speed:'10G'},
      {prefix:'HundredGigabitEthernet1/0/',from:33,to:38,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5720-40t',label:'HPE 5720 40×10GBASE-T + 8×SFP+ 1G/10G + 6×QSFP28 100G (S2N60A)',ports:[
      {prefix:'Ten-GigabitEthernet1/0/',from:1,to:48,speed:'10G'},
      {prefix:'HundredGigabitEthernet1/0/',from:49,to:54,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5510-24',label:'HPE FlexNetwork 5510 24G 4SFP+ HI (JH145A)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:25,to:28,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5510-48',label:'HPE FlexNetwork 5510 48G 4SFP+ HI (JH146A)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:49,to:52,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5510-24poe',label:'HPE FlexNetwork 5510 24G PoE+ 4SFP+ HI (JH147A)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:25,to:28,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
  ],
  cisco:[
    {value:'c9300-24',label:'Catalyst 9300-24T',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},
      {prefix:'TenGigabitEthernet1/1/',from:1,to:4,speed:'10G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true},
    ],poe:false},
    {value:'c2960-48',label:'Catalyst 2960-48 (接入層)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},{prefix:'TenGigabitEthernet1/1/',from:1,to:2,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c3650-24',label:'Catalyst 3650-24P',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},{prefix:'TenGigabitEthernet1/1/',from:1,to:2,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'c9500-40',label:'Catalyst 9500-40X (40×10G)',ports:[{prefix:'TenGigabitEthernet1/0/',from:1,to:40,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c9600-48',label:'Catalyst 9600-48LX (高性能)',ports:[{prefix:'TwentyFiveGigabitEthernet1/0/',from:1,to:48,speed:'25G'},{prefix:'FortyHundredGigabitEthernet1/1/',from:1,to:2,speed:'100G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c9300-48',label:'Catalyst 9300-48P',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},
      {prefix:'TenGigabitEthernet1/1/',from:1,to:4,speed:'10G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c9300x-48hx',label:'Catalyst 9300X-48HX (Multi-Gig PoE)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'10G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'c9500-24y4c',label:'Catalyst 9500-24Y4C (光纖骨幹，不支援 Breakout)',ports:[
      {prefix:'TwentyFiveGigabitEthernet1/0/',from:1,to:24,speed:'25G'},
      {prefix:'FortyHundredGigabitEthernet1/1/',from:1,to:4,speed:'100G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c9500-32c',label:'Catalyst 9500-32C (支援 Breakout：100G→4x25G)',ports:[
      {prefix:'HundredGigE1/0/',from:1,to:32,speed:'100G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c9200l-24p-4x',label:'Catalyst 9200L-24P-4X (存取層 PoE+)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},
      {prefix:'TenGigabitEthernet1/1/',from:1,to:4,speed:'10G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'c9200l-48p-4x',label:'Catalyst 9200L-48P-4X (存取層 PoE+)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},
      {prefix:'TenGigabitEthernet1/1/',from:1,to:4,speed:'10G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'c9400-lc-48ux',label:'Catalyst 9400 (C9400-LC-48UX 線卡，模組化核心)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'10G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'c9350-24',label:'Catalyst 9350-24 (9300 後繼機，24×up to 10G UPOE+ + 選配 40G/100G 上聯模組)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'10G'},
      {prefix:'HundredGigE1/1/',from:1,to:2,speed:'100G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'c9350-48',label:'Catalyst 9350-48 (9300 後繼機，48×up to 10G UPOE+ + 選配 40G/100G 上聯模組)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'10G'},
      {prefix:'HundredGigE1/1/',from:1,to:2,speed:'100G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'c9200cx-12p',label:'Catalyst 9200CX-12P-2X2G (緊湊桌上型 入門款，12×1G PoE+ + 2×2.5G mGig Uplink，信心中等)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:12,speed:'1G'},
      {prefix:'GigabitEthernet1/1/',from:1,to:2,speed:'2.5G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,12]},
  ],
  aruba:[
    {value:'aruba6300m-24',label:'Aruba CX 6300M-24G',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true},
    ],poe:false},
    {value:'aruba6300-48',label:'Aruba CX 6300-48G',ports:[{prefix:'1/1/',from:1,to:48,speed:'1G'},{prefix:'1/1/',from:49,to:52,speed:'10G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6200f-48',label:'Aruba CX 6200F-48 (光纖)',ports:[{prefix:'1/1/',from:1,to:48,speed:'10G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba8300',label:'Aruba CX 8300 (模組化)',ports:[{prefix:'1/',from:1,to:32,speed:'25G'},{prefix:'1/',from:33,to:40,speed:'100G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba8325',label:'Aruba CX 8325 (光纖核心)',ports:[
      {prefix:'1/',from:1,to:48,speed:'25G'},
      {prefix:'1/',from:49,to:56,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6200f-24',label:'Aruba CX 6200F-24',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6300f-48',label:'Aruba CX 6300F-48G (PoE Class 4)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/1/',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'aruba8360-24xf',label:'Aruba CX 8360-24XF (核心/匯聚)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'10G'},
      {prefix:'1/1/',from:25,to:28,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba9300-32d',label:'Aruba CX 9300-32D (新一代 400G 資料中心 leaf/spine)',ports:[
      {prefix:'1/1/',from:1,to:32,speed:'100G'},
      {prefix:'1/1/',from:33,to:34,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6100-24',label:'Aruba CX 6100-24G (分公司/SMB 入門級)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:26,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6100-48p',label:'Aruba CX 6100-48G-PoE4 (48×802.3at PoE+ 370W)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/1/',from:49,to:50,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
  ],
  fortiswitch:[
    {value:'fs-124f',label:'FortiSwitch 124F',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true},
    ],poe:false},
    {value:'fs-224f',label:'FortiSwitch 224F (2xM.2+24xG)',ports:[{prefix:'port',from:1,to:24,speed:'1G'},{prefix:'port',from:25,to:26,speed:'2.5G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-1048e',label:'FortiSwitch 1048E (48x1/10G SFP + 100G，取代原錯誤型號 324D)',ports:[{prefix:'port',from:1,to:48,speed:'10G'},{prefix:'port',from:49,to:54,speed:'40G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-3032g',label:'FortiSwitch 3032G (32x100G，高效能存取，取代原錯誤型號 5212B)',ports:[{prefix:'port',from:1,to:32,speed:'100G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-124f-poe',label:'FortiSwitch 124F-POE (24x802.3af 95W)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-124f-fpoe',label:'FortiSwitch 124F-FPOE (24x802.3at 180W)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-148f',label:'FortiSwitch 148F',ports:[
      {prefix:'port',from:1,to:48,speed:'1G'},
      {prefix:'port',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-148f-poe',label:'FortiSwitch 148F-POE (48x802.3af 370W)',ports:[
      {prefix:'port',from:1,to:48,speed:'1G'},
      {prefix:'port',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'fs-148f-fpoe',label:'FortiSwitch 148F-FPOE (48x802.3at 740W)',ports:[
      {prefix:'port',from:1,to:48,speed:'1G'},
      {prefix:'port',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'fs-424d',label:'FortiSwitch 424D',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:26,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-424d-poe',label:'FortiSwitch 424D-POE (24x802.3af 180W)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:26,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-424d-fpoe',label:'FortiSwitch 424D-FPOE (24x802.3at 370W)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:26,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-1024d',label:'FortiSwitch 1024D (24×1/10G SFP)',ports:[
      {prefix:'port',from:1,to:24,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-1024e',label:'FortiSwitch 1024E (24×1/10G SFP + 2×100G)',ports:[
      {prefix:'port',from:1,to:24,speed:'10G'},
      {prefix:'port',from:25,to:26,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-t1024e',label:'FortiSwitch T1024E (24×10G RJ45 + 2×100G)',ports:[
      {prefix:'port',from:1,to:24,speed:'10G'},
      {prefix:'port',from:25,to:26,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-124g',label:'FortiSwitch 124G (24x2.5G銅+6xSFP+)',ports:[
      {prefix:'port',from:1,to:24,speed:'10G'},
      {prefix:'port',from:25,to:30,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-424e',label:'FortiSwitch 424E (24xGE+4x10G，正確型號應為 424E 非現有的 424D)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-624f',label:'FortiSwitch 624F (24×1/2.5/5G Multi-Gig RJ45 + 4×25G SFP28 Uplink，MACsec)',ports:[
      {prefix:'port',from:1,to:24,speed:'5G'},
      {prefix:'port',from:25,to:28,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-624f-fpoe',label:'FortiSwitch 624F-FPOE (24×802.3bt Multi-Gig PoE + 4×25G SFP28 Uplink)',ports:[
      {prefix:'port',from:1,to:24,speed:'5G'},
      {prefix:'port',from:25,to:28,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-648f',label:'FortiSwitch 648F (48×1/2.5/5G Multi-Gig RJ45 + 8×25G SFP28 Uplink)',ports:[
      {prefix:'port',from:1,to:48,speed:'5G'},
      {prefix:'port',from:49,to:56,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-648f-fpoe',label:'FortiSwitch 648F-FPOE (48×802.3bt Multi-Gig PoE 1800W + 8×25G SFP28 Uplink)',ports:[
      {prefix:'port',from:1,to:48,speed:'5G'},
      {prefix:'port',from:49,to:56,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'fs-108f',label:'FortiSwitch 108F (桌上型 入門，8×1G RJ45 + 2×1G SFP)',ports:[
      {prefix:'port',from:1,to:8,speed:'1G'},
      {prefix:'port',from:9,to:10,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-108f-poe',label:'FortiSwitch 108F-POE (8×802.3at PoE+ 130W RJ45 + 2×1G SFP)',ports:[
      {prefix:'port',from:1,to:8,speed:'1G'},
      {prefix:'port',from:9,to:10,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,8]},
    {value:'fs-108f-fpoe',label:'FortiSwitch 108F-FPOE (8×802.3at PoE+ RJ45 + 2×1G SFP)',ports:[
      {prefix:'port',from:1,to:8,speed:'1G'},
      {prefix:'port',from:9,to:10,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,8]},
  ],
  juniper:[
    {value:'ex2300-24',label:'Juniper EX2300-24T',ports:[
      {prefix:'ge-0/0/',from:0,to:23,speed:'1G'},
      {prefix:'xe-0/1/',from:0,to:3,speed:'10G'},
      {name:'me0',speed:'1G',mgmt:true},
    ],poe:false},
    {value:'ex2200-24t',label:'Juniper EX2200-24T',ports:[{prefix:'ge-0/0/',from:0,to:23,speed:'1G'},{name:'me0',speed:'1G',mgmt:true}],poe:false},
    {value:'ex4100-24p',label:'Juniper EX4100-24P (接入PoE)',ports:[{prefix:'ge-0/0/',from:0,to:23,speed:'1G'},{prefix:'xe-0/1/',from:0,to:1,speed:'10G'},{name:'me0',speed:'1G',mgmt:true}],poe:true,poeRange:[0,23]},
    {value:'qfx10002',label:'Juniper QFX10002 (模組化)',ports:[{prefix:'et-0/0/',from:0,to:31,speed:'100G'},{name:'me0',speed:'1G',mgmt:true}],poe:false},
    {value:'ex4400-48f',label:'Juniper EX4400-48F (高效能存取)',ports:[
      {prefix:'ge-0/0/',from:0,to:47,speed:'1G'},
      {prefix:'xe-0/1/',from:0,to:3,speed:'10G'},
      {name:'me0',speed:'1G',mgmt:true}],poe:true,poeRange:[0,47]},
    {value:'qfx5120-48y',label:'Juniper QFX5120-48Y (光纖核心)',ports:[
      {prefix:'et-0/0/',from:0,to:47,speed:'25G'},
      {prefix:'et-0/1/',from:0,to:7,speed:'100G'},
      {name:'me0',speed:'1G',mgmt:true}],poe:false},
    {value:'ex3400-24p',label:'Juniper EX3400-24P (接入PoE，信心中等)',ports:[
      {prefix:'ge-0/0/',from:0,to:23,speed:'1G'},
      {prefix:'xe-0/1/',from:0,to:3,speed:'10G'},
      {name:'me0',speed:'1G',mgmt:true}],poe:true,poeRange:[0,23]},
    {value:'ex4300-48p',label:'Juniper EX4300-48P (接入PoE，高密度)',ports:[
      {prefix:'ge-0/0/',from:0,to:47,speed:'1G'},
      {prefix:'et-0/1/',from:0,to:3,speed:'40G'},
      {name:'me0',speed:'1G',mgmt:true}],poe:true,poeRange:[0,47]},
    {value:'qfx5100-48s',label:'Juniper QFX5100-48S (光纖核心)',ports:[
      {prefix:'xe-0/0/',from:0,to:47,speed:'10G'},
      {prefix:'et-0/1/',from:0,to:5,speed:'40G'},
      {name:'me0',speed:'1G',mgmt:true}],poe:false},
    {value:'ex4000-48mp',label:'Juniper EX4000-48MP (Wi-Fi 7 UPOE++，EX2300 後繼機，40×1G+8×2.5G PoE++ + 2×1/10G SFP+ Uplink)',ports:[
      {prefix:'ge-0/0/',from:0,to:39,speed:'1G'},
      {prefix:'ge-0/0/',from:40,to:47,speed:'2.5G'},
      {prefix:'xe-0/1/',from:0,to:1,speed:'10G'},
      {name:'me0',speed:'1G',mgmt:true}],poe:true,poeRange:[0,47]},
  ],
  cisco_nxos:[
    {value:'n3k-c3064pq-10ge',label:'Nexus 3064-PQ (48×10G)',ports:[
      {prefix:'Ethernet1/',from:1,to:48,speed:'10G'},
      {prefix:'Ethernet1/',from:49,to:52,speed:'40G'},
      {name:'mgmt0',speed:'1G',mgmt:true},
    ],poe:false},
    {value:'n3k-c3048pq',label:'Nexus 3048-PQ (48×10G)',ports:[{prefix:'Ethernet1/',from:1,to:48,speed:'10G'},{prefix:'Ethernet1/',from:49,to:52,speed:'40G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n5k-c5596up',label:'Nexus 5596UP (高端)',ports:[{prefix:'Ethernet1/',from:1,to:96,speed:'10G'},{prefix:'Ethernet1/',from:97,to:104,speed:'40G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n7k-c7018',label:'Nexus 7018 (模組化)',ports:[{prefix:'Ethernet1/',from:1,to:48,speed:'10G'},{prefix:'Ethernet1/',from:49,to:56,speed:'40G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n9k-c9396tx',label:'Nexus 9396TX (96×100G)',ports:[{prefix:'Ethernet1/',from:1,to:96,speed:'100G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n5k-c5548p-10ge',label:'Nexus 5548 (48×10G)',ports:[
      {prefix:'Ethernet1/',from:1,to:48,speed:'10G'},
      {prefix:'Ethernet1/',from:49,to:52,speed:'40G'},
      {name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n7k-c7010',label:'Nexus 7010 (模組化)',ports:[
      {prefix:'Ethernet1/',from:1,to:48,speed:'10G'},
      {name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n9k-c9372px',label:'Nexus 9372PX (72×10G)',ports:[
      {prefix:'Ethernet1/',from:1,to:72,speed:'10G'},
      {name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n9k-c93180yc-ex',label:'Nexus 93180YC-EX (48x10/25G+6x100G，現行世代)',ports:[
      {prefix:'Ethernet1/',from:1,to:48,speed:'25G'},
      {prefix:'Ethernet1/',from:49,to:54,speed:'100G'},
      {name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n9k-c9336c-fx2',label:'Nexus 9336C-FX2 (36x40/100G，光纖骨幹)',ports:[
      {prefix:'Ethernet1/',from:1,to:36,speed:'100G'},
      {name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
  ],
  'dell-os10':[
    {value:'s3048-on',label:'Dell S3048-ON (48×1G+4×10G)',ports:[
      {prefix:'ethernet1/1/',from:1,to:48,speed:'1G'},
      {prefix:'ethernet1/1/',from:49,to:52,speed:'10G'},
      {name:'management1/1/1',speed:'1G',mgmt:true}],poe:false},
    {value:'s4048-on',label:'Dell S4048-ON (48×10G+6×40G)',ports:[
      {prefix:'ethernet1/1/',from:1,to:48,speed:'10G'},
      {prefix:'ethernet1/1/',from:49,to:54,speed:'40G'},
      {name:'management1/1/1',speed:'1G',mgmt:true}],poe:false},
    {value:'s5248f-on',label:'Dell PowerSwitch S5248F-ON (48x25G+6x100G)',ports:[
      {prefix:'ethernet1/1/',from:1,to:48,speed:'25G'},
      {prefix:'ethernet1/1/',from:49,to:54,speed:'100G'},
      {name:'management1/1/1',speed:'1G',mgmt:true}],poe:false},
    {value:'z9332f-on',label:'Dell PowerSwitch Z9332F-ON (32x400G，以100G表示，光纖骨幹)',ports:[
      {prefix:'ethernet1/1/',from:1,to:32,speed:'100G'},
      {name:'management1/1/1',speed:'1G',mgmt:true}],poe:false},
  ],
  arista:[
    {value:'7010tx-48',label:'Arista 7010TX-48 (48×1G)',ports:[
      {prefix:'Ethernet',from:1,to:48,speed:'1G'},
      {name:'Management1',speed:'1G',mgmt:true}],poe:false},
    {value:'720xp-48zc2',label:'Arista 720XP-48ZC2 (48×1G/10G+2×100G)',ports:[
      {prefix:'Ethernet',from:1,to:48,speed:'10G'},
      {prefix:'Ethernet',from:49,to:50,speed:'100G'},
      {name:'Management1',speed:'1G',mgmt:true}],poe:false},
    {value:'7050sx3-48yc8',label:'Arista 7050SX3-48YC8 (48×25G+8×100G)',ports:[
      {prefix:'Ethernet',from:1,to:48,speed:'25G'},
      {prefix:'Ethernet',from:49,to:56,speed:'100G'},
      {name:'Management1',speed:'1G',mgmt:true}],poe:false},
    {value:'7060cx2-32s',label:'Arista 7060CX2-32S (32×100G Leaf)',ports:[
      {prefix:'Ethernet',from:1,to:32,speed:'100G'},
      {name:'Management1',speed:'1G',mgmt:true}],poe:false},
    {value:'arista750-48-1g',label:'Arista 750 Series 校園存取 (模組化 線卡，Wi-Fi 7，48×1G PoE 30W + 25G SFP28 Uplink)',ports:[
      {prefix:'Ethernet',from:1,to:48,speed:'1G'},
      {prefix:'Ethernet',from:49,to:50,speed:'25G'},
      {name:'Management1',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'arista750-48-10g',label:'Arista 750 Series 校園存取 (模組化 線卡，48×2.5/5/10G Multi-Gig PoE 90W + 25G SFP28 Uplink)',ports:[
      {prefix:'Ethernet',from:1,to:48,speed:'10G'},
      {prefix:'Ethernet',from:49,to:50,speed:'25G'},
      {name:'Management1',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
  ],
  brocade:[
    {value:'icx7150-48p',label:'Ruckus ICX7150-48P (48×1G PoE+ + 4×10G Uplink)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/1/',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true},
    {value:'icx7250-48',label:'Ruckus ICX7250-48 (48×1G + 8×10G Uplink)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/1/',from:49,to:56,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'icx7550-48',label:'Ruckus ICX7550-48 (48×10G + 8×25G + 2×100G)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'10G'},
      {prefix:'1/1/',from:49,to:56,speed:'25G'},
      {prefix:'1/1/',from:57,to:58,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'icx7650-48p',label:'Ruckus ICX7650-48P (48×1G/10G PoE+ + 8×25G Uplink)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'10G'},
      {prefix:'1/1/',from:49,to:56,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true},
    {value:'icx8200-24',label:'Ruckus ICX8200-24 (24×1G + 4×25G SFP28 Uplink，ICX7150 後繼機)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:28,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'icx8200-48p',label:'Ruckus ICX8200-48PF2 (48×1G PoE+ 740W + 4×25G SFP28 Uplink)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/1/',from:49,to:52,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true},
  ],
  alcatel:[
    {value:'os6560-p24',label:'Alcatel OmniSwitch 6560-P24 (24×1G PoE+ + 4×10G Uplink)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true},
    {value:'os6860-24',label:'Alcatel OmniSwitch 6860-24 (24×1G/10G + 4×10G Uplink)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true},
    {value:'os6900-x20',label:'Alcatel OmniSwitch 6900-X20 (20×10G + 4×40G Uplink)',ports:[
      {prefix:'1/1/',from:1,to:20,speed:'10G'},
      {prefix:'1/1/',from:21,to:24,speed:'40G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'os6900-x24c2',label:'Alcatel OmniSwitch 6900-X24C2 (26×SFP+ 1G/10G + 2×QSFP28 100G)',ports:[
      {prefix:'1/1/',from:1,to:26,speed:'10G'},
      {prefix:'1/1/',from:27,to:28,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'os2360-p24',label:'Alcatel OmniSwitch 2360-P24 (SMB/分公司 入門 堆疊式，24×802.3at PoE+)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:28,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'os6870-24',label:'Alcatel OmniSwitch 6870-24 (中階，24×2.5/5/10G Multi-Gig PoE 95W，信心中等)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'10G'},
      {prefix:'1/1/',from:25,to:28,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
  ],
  extreme:[
    {value:'x440-g2-48p',label:'Extreme Summit X440-G2-48p (48×1G PoE+ + 4×10G Uplink)',ports:[
      {prefix:'1:',from:1,to:48,speed:'1G'},
      {prefix:'1:',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true},
    {value:'x670-g2-48x',label:'Extreme Summit X670-G2-48x (48×10G + 4×40G Uplink)',ports:[
      {prefix:'1:',from:1,to:48,speed:'10G'},
      {prefix:'1:',from:49,to:52,speed:'40G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'x5420-24',label:'ExtremeSwitching 5420F-24 (Universal Edge，取代 Summit X440-G2)',ports:[
      {prefix:'1:',from:1,to:24,speed:'1G'},
      {prefix:'1:',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'x5420-48p',label:'ExtremeSwitching 5420F-48P (48×802.3bt PoE+ + 4×1/10G SFP+ Uplink)',ports:[
      {prefix:'1:',from:1,to:48,speed:'1G'},
      {prefix:'1:',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
  ],
  procurve:[
    {value:'aruba2530-24g',label:'Aruba 2530-24G (J9776A)',ports:[
      {prefix:'',from:1,to:24,speed:'1G'},
      {prefix:'',from:25,to:28,speed:'1G'}],poe:false},
    {value:'aruba2930f-48g',label:'Aruba 2930F-48G-4SFP+ (JL256A)',ports:[
      {prefix:'',from:1,to:48,speed:'1G'},
      {prefix:'',from:49,to:52,speed:'10G'}],poe:true},
    {value:'aruba2540-24g',label:'Aruba 2540 24G 4SFP+ (JL354A)',ports:[
      {prefix:'',from:1,to:24,speed:'1G'},
      {prefix:'',from:25,to:28,speed:'10G'}],poe:true},
    {value:'aruba2540-48g',label:'Aruba 2540 48G 4SFP+ (JL355A)',ports:[
      {prefix:'',from:1,to:48,speed:'1G'},
      {prefix:'',from:49,to:52,speed:'10G'}],poe:true},
  ],
  routeros:[
    {value:'rb4011',label:'MikroTik RB4011iGS+ (10×1G + 1×SFP+)',ports:[
      {prefix:'ether',from:1,to:10,speed:'1G'},
      {prefix:'sfp-sfpplus',from:1,to:1,speed:'10G'}],poe:false},
    {value:'ccr1072',label:'MikroTik CCR1072-1G-8S+ (8×SFP+ + 1×1G)',ports:[
      {prefix:'ether',from:1,to:1,speed:'1G'},
      {prefix:'sfp-sfpplus',from:1,to:8,speed:'10G'}],poe:false},
    {value:'crs328-24p',label:'MikroTik CRS328-24P-4S+RM (24×1G PoE+ + 4×SFP+ 10G)',ports:[
      {prefix:'ether',from:1,to:24,speed:'1G'},
      {prefix:'sfp-sfpplus',from:1,to:4,speed:'10G'}],poe:true},
    {value:'rb5009',label:'MikroTik RB5009UG+S+IN (7×1G + 1×2.5G + 1×SFP+ 10G)',ports:[
      {prefix:'ether',from:1,to:7,speed:'1G'},
      {name:'ether8',speed:'2.5G'},
      {prefix:'sfp-sfpplus',from:1,to:1,speed:'10G'}],poe:false},
    {value:'ccr2216',label:'MikroTik CCR2216-1G-12XS-2XQ (1×1G + 12×SFP28 up to 25G + 2×QSFP28 100G)',ports:[
      {name:'ether1',speed:'1G'},
      {prefix:'sfp28-',from:1,to:12,speed:'25G'},
      {prefix:'qsfp28-',from:1,to:2,speed:'100G'}],poe:false},
    {value:'crs112-8g4s',label:'MikroTik CRS112-8G-4S-IN (入門級，8×1G + 4×SFP 1G)',ports:[
      {prefix:'ether',from:1,to:8,speed:'1G'},
      {prefix:'sfp',from:1,to:4,speed:'1G'}],poe:false},
  ],
  // 2026-07-29 對外查證官方 Ruijie Networks 產品頁/datasheet 後新增：入門 access
  // （RG-S2928G-E V3，官方確認支援 VSU）／中階 aggregation（RG-S5750C-28GT4XS-H）／
  // 高階資料中心（RG-S6220-48XS6QXS-H，官方確認支援 VSU 2.0）三款代表機型
  ruijie:[
    {value:'s2928g-e',label:'Ruijie RG-S2928G-E V3 (入門級，24×1G + 4×SFP 1G，支援VSU)',ports:[
      {prefix:'GigabitEthernet 0/',from:1,to:28,speed:'1G'}],poe:false},
    {value:'s5750c-28gt4xs',label:'Ruijie RG-S5750C-28GT4XS-H (中階匯聚，28×1G + 4×SFP+ 10G)',ports:[
      {prefix:'GigabitEthernet 0/',from:1,to:28,speed:'1G'},
      {prefix:'TenGigabitEthernet 0/',from:1,to:4,speed:'10G'}],poe:false},
    {value:'s6220-48xs6qxs',label:'Ruijie RG-S6220-48XS6QXS-H (高階資料中心，48×10GBASE-T + 6×40G QSFP+，支援VSU 2.0)',ports:[
      {prefix:'TenGigabitEthernet 0/',from:1,to:48,speed:'10G'},
      {prefix:'FortyGigabitEthernet 0/',from:1,to:6,speed:'40G'}],poe:false},
  ],
  netgear:[
    {value:'m4300-28g',label:'Netgear M4300-28G (24×1G + 2×10GBASE-T + 2×SFP+ 10G)',ports:[
      {prefix:'0/',from:1,to:24,speed:'1G'},
      {prefix:'0/',from:25,to:28,speed:'10G'}],poe:false},
    {value:'m4300-52g',label:'Netgear M4300-52G (48×1G + 2×10GBASE-T + 2×SFP+ 10G)',ports:[
      {prefix:'0/',from:1,to:48,speed:'1G'},
      {prefix:'0/',from:49,to:52,speed:'10G'}],poe:false},
  ],
  edgeswitch:[
    {value:'es-24-250w',label:'Ubiquiti EdgeSwitch ES-24-250W (24×1G PoE+ + 2×SFP)',ports:[
      {prefix:'0/',from:1,to:24,speed:'1G'},
      {prefix:'0/',from:25,to:26,speed:'1G'}],poe:true},
    {value:'es-48-500w',label:'Ubiquiti EdgeSwitch ES-48-500W (48×1G PoE+ + 2×SFP + 2×SFP+ 10G)',ports:[
      {prefix:'0/',from:1,to:48,speed:'1G'},
      {prefix:'0/',from:49,to:50,speed:'1G'},
      {prefix:'0/',from:51,to:52,speed:'10G'}],poe:true},
  ],
};

function updateDeviceModelOptions(){
  const vendor=document.getElementById('vendor').value;
  const sel=document.getElementById('device-model');
  if(!sel)return;
  const models=(DEVICE_MODELS[vendor]||[]);
  const currentValue=sel.value;
  const notApplyText=(typeof tr==='function'?tr('opt.modelNone'):'不套用');
  // 先清空下拉菜單並添加"不套用"選項
  sel.innerHTML='';
  const defaultOpt=document.createElement('option');
  defaultOpt.value='';
  defaultOpt.textContent=notApplyText;
  defaultOpt.setAttribute('data-i18n','opt.modelNone');
  sel.appendChild(defaultOpt);
  // 添加該廠牌的所有設備模型
  if(models && Array.isArray(models) && models.length>0){
    models.forEach(m=>{
      const opt=document.createElement('option');
      opt.value=m.value;
      // 翻譯標籤中的中文詞彙
      let label=m.label;
      if(typeof tr==='function'){
        // 移除內嵌在 label 裡的開發備註文字（先前修正型號錯誤時遺留的 commit 附註，
        // 非使用者選型需要的資訊，不翻譯、直接清除）
        label=label.replace(/，取代原錯誤型號[^)]*/g,'');
        label=label.replace(/，正確型號應為[^)]*/g,'');
        label=label.replace(/模組化核心/g,tr('opt.modelModular'));
        label=label.replace(/光纖骨幹/g,tr('opt.modelFiber')+' '+tr('opt.modelBackbone'));
        label=label.replace(/光纖核心/g,tr('opt.modelFiber'));
        label=label.replace(/高效能存取/g,tr('opt.modelHighPerfAccess'));
        label=label.replace(/中端模組/g,tr('opt.modelMidRange'));
        label=label.replace(/高端模組化/g,tr('opt.modelHighEndModular'));
        label=label.replace(/接入層|存取層/g,tr('opt.modelAccessLayer'));
        label=label.replace(/高性能/g,tr('opt.modelHighPerf'));
        label=label.replace(/不支援 Breakout/g,tr('opt.modelNoBreakout'));
        label=label.replace(/支援 Breakout/g,tr('opt.modelBreakoutSupport'));
        label=label.replace(/核心\/匯聚/g,tr('opt.modelCoreAggregation'));
        label=label.replace(/接入PoE/g,tr('opt.modelAccessPoE'));
        label=label.replace(/高密度/g,tr('opt.modelHighDensity'));
        label=label.replace(/信心中等/g,tr('opt.modelMediumConfidence'));
        label=label.replace(/以100G表示/g,tr('opt.modelExpressedAs100G'));
        label=label.replace(/高端/g,tr('opt.modelHighEnd'));
        label=label.replace(/現行世代/g,tr('opt.modelCurrentGen'));
        label=label.replace(/模組化/g,tr('opt.modelModular'));
        label=label.replace(/光纖/g,tr('opt.modelFiber'));
        label=label.replace(/線卡/g,tr('opt.modelLineCard'));
        label=label.replace(/銅/g,tr('opt.modelCopper'));
        label=label.replace(/後繼機/g,tr('opt.modelSuccessor'));
        label=label.replace(/入門款|入門級|入門/g,tr('opt.modelEntry'));
        label=label.replace(/中階/g,tr('opt.modelMidTier'));
        label=label.replace(/校園存取/g,tr('opt.modelCampusAccess'));
        label=label.replace(/資料中心/g,tr('opt.modelDataCenter'));
        label=label.replace(/分公司/g,tr('opt.modelBranch'));
        label=label.replace(/上聯模組/g,tr('opt.modelUplinkModule'));
        label=label.replace(/選配/g,tr('opt.modelOptional'));
        label=label.replace(/緊湊桌上型/g,tr('opt.modelCompactDesktop'));
        label=label.replace(/桌上型/g,tr('opt.modelDesktop'));
        label=label.replace(/取代/g,tr('opt.modelReplaces'));
        label=label.replace(/新一代/g,tr('opt.modelNextGen'));
        label=label.replace(/堆疊式/g,tr('opt.modelStackable'));
      }
      opt.textContent=label;
      sel.appendChild(opt);
    });
  }
  // 如果當前值仍在新的選項中，保留選擇
  if(currentValue && models.some(m=>m.value===currentValue)){
    sel.value=currentValue;
  }
}

function applyDeviceModel(){
  const vendor=document.getElementById('vendor').value;
  const deviceModelSel=document.getElementById('device-model');
  const modelValue=deviceModelSel.value;
  if(!modelValue)return;
  const model=(DEVICE_MODELS[vendor]||[]).find(m=>m.value===modelValue);
  if(!model)return;
  document.getElementById('iface-body').innerHTML='';
  model.ports.forEach(p=>{
    if(p.name)addIfaceRow(p.name,'access',p.speed||'1G');
    else for(let n=p.from;n<=p.to;n++)addIfaceRow(p.prefix+n,'access',p.speed||'1G');
  });
  // 保留選擇的值，以防後續代碼重新生成下拉選單
  deviceModelSel.value=modelValue;
  updateIfaceTableDisplay();
  updateAppliedModelNotice();
}

// 展開 DEVICE_MODELS 指定型號的埠清單成一個名稱 Set，供 validateForm() 交叉驗證使用；
// 展開邏輯與 applyDeviceModel() 保持一致（同一份 ports 資料，不重寫規則）。
// modelValue 為空/找不到型號時回傳 null，代表「未套用型號」不做交叉檢查。
function getModelPortSet(vendor,modelValue){
  if(!modelValue)return null;
  const model=(DEVICE_MODELS[vendor]||[]).find(m=>m.value===modelValue);
  if(!model)return null;
  const set=new Set();
  model.ports.forEach(p=>{
    if(p.name)set.add(p.name);
    else for(let n=p.from;n<=p.to;n++)set.add(p.prefix+n);
  });
  return set;
}

// Breakout 子埠命名固定是「母埠 + 分隔符(: . /) + 數字」，只要母埠本身是合法埠位就視為合法，
// 不需要另外追蹤 _breakoutEnables 狀態
function isKnownModelPort(name,portSet){
  if(portSet.has(name))return true;
  const m=name.match(/^(.+?)([:./])(\d+)$/);
  return !!(m&&portSet.has(m[1]));
}

function updateAppliedModelNotice(){
  const vendor=document.getElementById('vendor').value;
  const modelValue=document.getElementById('device-model').value;
  const notice=document.getElementById('applied-model-notice');
  if(!notice)return;
  if(modelValue){
    const model=(DEVICE_MODELS[vendor]||[]).find(m=>m.value===modelValue);
    if(model){
      const vendorLabel=document.querySelector('#vendor option[value="'+vendor+'"]')?.textContent||vendor;
      const template=tr('msg.appliedModel')||'✓ 目前套用 {vendor} 的 {model} 之預設設定';
      notice.textContent=template.replace('{vendor}',vendorLabel).replace('{model}',model.label);
      notice.style.display='block';
    }
  }else{
    notice.style.display='none';
  }
}

// Breakout（QSFP 拆分子埠）：「同時輸出啟用指令」勾選時記錄的母埠清單，collectModel() 讀取後併入 model.breakouts
let _breakoutEnables=[];

function expandBreakoutPorts(){
  const vendor=document.getElementById('vendor').value;
  const parent=document.getElementById('breakout-parent-name').value.trim();
  const ratio=document.getElementById('breakout-ratio').value;
  if(!parent)return;
  const count=parseInt(ratio.split('x')[0],10);
  const childSpeed=ratio.split('x')[1];
  // FortiSwitch 子埠命名用點號，Arista 用斜線（已查證官方文件 Et45→Et45/1~4），
  // 其餘廠牌皆用冒號
  for(let n=1;n<=count;n++){
    const childName=vendor==='fortiswitch'?`${parent}.${n}`:vendor==='arista'?`${parent}/${n}`:`${parent}:${n}`;
    addIfaceRow(childName,'access',childSpeed);
  }
  if(document.getElementById('breakout-emit-enable').checked){
    const entry={parentPort:parent,mode:ratio,vendor};
    if(vendor==='cisco'){
      entry.scheme=document.getElementById('breakout-ios-xe-scheme').value;
      if(entry.scheme==='renumber'){
        entry.slot=document.getElementById('breakout-ios-xe-slot').value.trim();
        entry.switchNum=document.getElementById('breakout-ios-xe-switch').value.trim();
      }
    }
    // Comware/Aruba CX/Arista 的啟用指令內嵌在母埠自己的 interface 區塊，若表格內還沒有母埠這一列，
    // render 函式找不到對應介面就無法輸出這行指令，故自動補上母埠列（使用者仍可自行調整其設定）
    if((vendor==='comware'||vendor==='aruba'||vendor==='arista')&&!rowsOf('#iface-body tr').some(tr=>val(tr,'i-name')===parent)){
      addIfaceRow(parent,'access','');
    }
    _breakoutEnables.push(entry);
  }
  updateIfaceTableDisplay();
}

function addAreaRow(area='',network='',wildcard='',type='normal',noSummary=false){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="a-area" value="${escAttr(area)}"></td><td><input class="a-network" value="${escAttr(network)}"></td><td><input class="a-wildcard" value="${escAttr(wildcard)}"></td>
    <td><select class="a-type">
      <option value="normal" data-i18n="opt.typeNormal">Normal</option>
      <option value="stub" data-i18n="opt.typeStub">Stub</option>
      <option value="nssa" data-i18n="opt.typeNssa">NSSA</option>
    </select></td>
    <td><input type="checkbox" class="a-nosummary"></td>
    ${RM_BTN_TD}`;
  tr.querySelector('.a-type').value=type;
  tr.querySelector('.a-nosummary').checked=!!noSummary;
  document.getElementById('area-body').appendChild(tr);
  applyI18n(tr);
}

function addVxlanVniRow(vni='',vlan='',name='',peers='',rd='',rtImport='',rtExport='',gw=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="vx-vni" value="${escAttr(vni)}"></td><td><input class="vx-vlan" value="${escAttr(vlan)}"></td>
    <td><input class="vx-name" value="${escAttr(name)}"></td><td><input class="vx-peers" value="${escAttr(peers)}" placeholder="BGP-EVPN"></td>
    <td><input class="vx-rd" value="${escAttr(rd)}" placeholder="1:1"></td><td><input class="vx-rt-import" value="${escAttr(rtImport)}" placeholder="1:1"></td>
    <td><input class="vx-rt-export" value="${escAttr(rtExport)}" placeholder="1:1"></td><td><input class="vx-gw" value="${escAttr(gw)}"></td>
    ${RM_BTN_TD}`;
  document.getElementById('vxlan-vni-body').appendChild(tr);
}

function addQosDscpRow(dscpValues='',priority=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="qos-dscp-values" value="${escAttr(dscpValues)}" placeholder="46"></td>
    <td><input class="qos-dscp-priority" value="${escAttr(priority)}" placeholder="7"></td>
    ${RM_BTN_TD}`;
  document.getElementById('qos-dscp-body').appendChild(tr);
}

// Extreme QoS：QP1/QP8 為預設已存在，create qosprofile 只對 QP2-QP7 有意義（2026-07-19
// 對外查證），故建立列表下拉限定 QP2-QP7；DSCP 對應表／逐 port 指定則可套用全部 8 個
const EXTREME_QOS_ALL=['QP1','QP2','QP3','QP4','QP5','QP6','QP7','QP8'];
const EXTREME_QOS_CREATABLE=['QP2','QP3','QP4','QP5','QP6','QP7'];
function _exQosOptions(list,selected){
  return list.map(q=>`<option value="${q}"${q===selected?' selected':''}>${q}</option>`).join('');
}
function addExtremeQosProfileRow(name='QP2',minbw='',maxbw=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><select class="exq-profile">${_exQosOptions(EXTREME_QOS_CREATABLE,name)}</select></td>
    <td><input class="exq-minbw" value="${escAttr(minbw)}" placeholder="10"></td>
    <td><input class="exq-maxbw" value="${escAttr(maxbw)}" placeholder="80"></td>
    ${RM_BTN_TD}`;
  document.getElementById('extreme-qos-profile-body').appendChild(tr);
}
function addExtremeQosDscpRow(codePoint='',profile='QP1'){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="exq-dscp-cp" value="${escAttr(codePoint)}" placeholder="46"></td>
    <td><select class="exq-dscp-profile">${_exQosOptions(EXTREME_QOS_ALL,profile)}</select></td>
    ${RM_BTN_TD}`;
  document.getElementById('extreme-qos-dscp-body').appendChild(tr);
}
function addExtremeQosPortRow(port='',profile='QP1',diffservExam=false){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="exq-port" value="${escAttr(port)}" placeholder="1:1"></td>
    <td><select class="exq-port-profile">${_exQosOptions(EXTREME_QOS_ALL,profile)}</select></td>
    <td style="text-align:center"><input type="checkbox" class="exq-port-diffserv"${diffservExam?' checked':''}></td>
    ${RM_BTN_TD}`;
  document.getElementById('extreme-qos-port-body').appendChild(tr);
}

// RouterOS ACL：chain-based 扁平規則清單，非具名 ACL 物件
function addRouterOSAclRow(chain='forward',action='accept',protocol='',srcAddress='',dstAddress='',dstPort='',inInterface='',comment=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><select class="ros-acl-chain">
      <option value="forward"${chain==='forward'?' selected':''}>forward</option>
      <option value="input"${chain==='input'?' selected':''}>input</option>
      <option value="output"${chain==='output'?' selected':''}>output</option>
    </select></td>
    <td><select class="ros-acl-action">
      <option value="accept"${action==='accept'?' selected':''}>accept</option>
      <option value="drop"${action==='drop'?' selected':''}>drop</option>
    </select></td>
    <td><input class="ros-acl-protocol" value="${escAttr(protocol)}" placeholder="tcp"></td>
    <td><input class="ros-acl-src" value="${escAttr(srcAddress)}" placeholder="10.0.0.0/8"></td>
    <td><input class="ros-acl-dst" value="${escAttr(dstAddress)}" placeholder="10.0.0.0/8"></td>
    <td><input class="ros-acl-dstport" value="${escAttr(dstPort)}" placeholder="22"></td>
    <td><input class="ros-acl-inif" value="${escAttr(inInterface)}" placeholder="ether1"></td>
    <td><input class="ros-acl-comment" value="${escAttr(comment)}"></td>
    ${RM_BTN_TD}`;
  document.getElementById('routeros-acl-body').appendChild(tr);
}

function addSonicL3Row(name='',cidr=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="sl3-name" value="${escAttr(name)}" placeholder="Ethernet0 / Vlan1000 / PortChannel01"></td>
    <td><input class="sl3-cidr" value="${escAttr(cidr)}" placeholder="10.1.1.1/24"></td>
    ${RM_BTN_TD}`;
  document.getElementById('sonic-l3-body').appendChild(tr);
}

// SONiC QoS（2026-08-08 對外查證新增）：SCHEDULER 定義＋PORT_QOS_MAP/QUEUE 套用，專屬
// sonicQos 形狀 {schedulers:[],apply:[]}，與其餘廠牌共用 policy-map QoS 完全不同
function addSonicQosSchedRow(name='',type='DWRR',weight='',meterType='bytes',cir='',cbs='',pir='',pbs=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="sqs-name" value="${escAttr(name)}"></td>
    <td><select class="sqs-type">
      <option value="DWRR"${type==='DWRR'?' selected':''}>DWRR</option>
      <option value="WRR"${type==='WRR'?' selected':''}>WRR</option>
      <option value="STRICT"${type==='STRICT'?' selected':''}>STRICT</option>
    </select></td>
    <td><input class="sqs-weight" value="${escAttr(weight)}" placeholder="14"></td>
    <td><select class="sqs-metertype">
      <option value="bytes"${meterType==='bytes'?' selected':''}>bytes</option>
      <option value="packets"${meterType==='packets'?' selected':''}>packets</option>
    </select></td>
    <td><input class="sqs-cir" value="${escAttr(cir)}"></td>
    <td><input class="sqs-cbs" value="${escAttr(cbs)}"></td>
    <td><input class="sqs-pir" value="${escAttr(pir)}"></td>
    <td><input class="sqs-pbs" value="${escAttr(pbs)}"></td>
    ${RM_BTN_TD}`;
  document.getElementById('sonic-qos-sched-body').appendChild(tr);
}
function addSonicQosApplyRow(target='',queue='',scheduler=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="sqa-target" value="${escAttr(target)}" placeholder="Ethernet0"></td>
    <td><input class="sqa-queue" value="${escAttr(queue)}" placeholder="3"></td>
    <td><input class="sqa-scheduler" value="${escAttr(scheduler)}"></td>
    ${RM_BTN_TD}`;
  document.getElementById('sonic-qos-apply-body').appendChild(tr);
}

// SONiC STP 逐 VLAN 逐 Port 覆寫（STP_VLAN_INTF，2026-08-08 對外查證新增）：共用 STP
// 形狀無 VLAN 維度，獨立成頂層 sonicStpVlanIntf 欄位（比照 sonicL3Interfaces 慣例）
function addSonicStpVlanIntfRow(vlan='',port='',cost='',priority=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="ssvi-vlan" value="${escAttr(vlan)}" placeholder="100"></td>
    <td><input class="ssvi-port" value="${escAttr(port)}" placeholder="Ethernet0"></td>
    <td><input class="ssvi-cost" value="${escAttr(cost)}" placeholder="20000"></td>
    <td><input class="ssvi-priority" value="${escAttr(priority)}" placeholder="128"></td>
    ${RM_BTN_TD}`;
  document.getElementById('sonic-stp-vlanintf-body').appendChild(tr);
}

// RouterOS QoS：Simple Queue（單一 target 頻寬限制）與 Queue Tree（階層式 parent/child）
// 兩套獨立機制，資料形狀與其餘廠牌共用 policy-map QoS 完全不同
function addRouterOSSimpleQueueRow(name='',target='',maxUp='',maxDown='',atUp='',atDown=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="ros-qos-name" value="${escAttr(name)}"></td>
    <td><input class="ros-qos-target" value="${escAttr(target)}" placeholder="192.168.1.100/32"></td>
    <td><input class="ros-qos-maxup" value="${escAttr(maxUp)}" placeholder="10M"></td>
    <td><input class="ros-qos-maxdown" value="${escAttr(maxDown)}" placeholder="5M"></td>
    <td><input class="ros-qos-atup" value="${escAttr(atUp)}" placeholder="2M"></td>
    <td><input class="ros-qos-atdown" value="${escAttr(atDown)}" placeholder="1M"></td>
    ${RM_BTN_TD}`;
  document.getElementById('routeros-simple-queue-body').appendChild(tr);
}
function addRouterOSQueueTreeRow(name='',parent='global',maxLimit=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="ros-qtree-name" value="${escAttr(name)}"></td>
    <td><input class="ros-qtree-parent" value="${escAttr(parent)}"></td>
    <td><input class="ros-qtree-max" value="${escAttr(maxLimit)}" placeholder="50M"></td>
    ${RM_BTN_TD}`;
  document.getElementById('routeros-queue-tree-body').appendChild(tr);
}

function addUsersRow(name='',role='',password=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="user-name" value="${escAttr(name)}"></td>
    <td><input class="user-role" value="${escAttr(role)}" placeholder="operator"></td>
    <td><input class="user-password" value="${escAttr(password)}" placeholder="SHA1 hash"></td>
    ${RM_BTN_TD}`;
  document.getElementById('users-body').appendChild(tr);
}

function addBgpPeerRow(ip='',as='',desc=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="p-ip" value="${escAttr(ip)}"></td><td><input class="p-as" value="${escAttr(as)}"></td><td><input class="p-desc" value="${escAttr(desc)}"></td>${RM_BTN_TD}`;
  document.getElementById('bgp-peer-body').appendChild(tr);
}

function addRouteRow(dst='',gw='',metric=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="rt-dst" value="${escAttr(dst)}" placeholder="10.0.0.0/24"></td><td><input class="rt-gw" value="${escAttr(gw)}"></td><td><input class="rt-metric" value="${escAttr(metric)}"></td>${RM_BTN_TD}`;
  document.getElementById('route-body').appendChild(tr);
}

function addLacpRow(id='',mode='static',members=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="lg-id" value="${escAttr(id)}"></td>
    <td><select class="lg-mode">
      <option value="static" data-i18n="opt.lacpStatic">Static</option>
      <option value="active" data-i18n="opt.lacpActive">Active</option>
      <option value="passive" data-i18n="opt.lacpPassive">Passive</option>
    </select></td>
    <td><input class="lg-members" value="${escAttr(members)}" placeholder="port1 port2"></td>
    ${RM_BTN_TD}`;
  tr.querySelector('.lg-mode').value=mode;
  document.getElementById('lacp-body').appendChild(tr);
  applyI18n(tr);
}

function addVsuMemberRow(id='',priority='',vslPorts=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="vsu-mem-id" value="${escAttr(id)}"></td>
    <td><input class="vsu-mem-priority" value="${escAttr(priority)}"></td>
    <td><input class="vsu-mem-vsl" value="${escAttr(vslPorts)}" placeholder="TenGigabitEthernet 1/1"></td>
    ${RM_BTN_TD}`;
  document.getElementById('vsu-member-body').appendChild(tr);
  applyI18n(tr);
}

function addVrrpRow(vlanId='',ip='',vrid='',vip='',priority='100',preempt=false,authMode='',authKey='',trackIf='',trackReduced=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="vr-vlan" value="${escAttr(vlanId)}"></td><td><input class="vr-ip" value="${escAttr(ip)}" placeholder="192.168.10.1/24"></td><td><input class="vr-id" value="${escAttr(vrid)}"></td><td><input class="vr-vip" value="${escAttr(vip)}"></td><td><input class="vr-priority" value="${escAttr(priority)}"></td><td style="text-align:center"><input type="checkbox" class="vr-preempt"></td>
    <td><select class="vr-authmode"><option value="">-</option><option value="simple">simple</option><option value="md5">md5</option></select></td>
    <td><input class="vr-authkey" value="${escAttr(authKey)}"></td>
    <td><input class="vr-trackif" value="${escAttr(trackIf)}"></td>
    <td><input class="vr-trackreduced" value="${escAttr(trackReduced)}"></td>
    ${RM_BTN_TD}`;
  tr.querySelector('.vr-preempt').checked=!!preempt;
  tr.querySelector('.vr-authmode').value=authMode||'';
  document.getElementById('vrrp-body').appendChild(tr);
}

function addDhcpPoolRow(name='',network='',gateway='',dns='',range='',excluded='',lease='',iface=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="dp-name" value="${escAttr(name)}"></td>
    <td><input class="dp-network" value="${escAttr(network)}" placeholder="10.0.0.0/24"></td>
    <td><input class="dp-gateway" value="${escAttr(gateway)}"></td>
    <td><input class="dp-dns" value="${escAttr(dns)}" placeholder="8.8.8.8 8.8.4.4"></td>
    <td><input class="dp-range" value="${escAttr(range)}" placeholder="10.0.0.10-10.0.0.100"></td>
    <td><input class="dp-excluded" value="${escAttr(excluded)}"></td>
    <td><input class="dp-lease" value="${escAttr(lease)}" placeholder="1"></td>
    <td><input class="dp-iface" value="${escAttr(iface)}" placeholder="vlan10"></td>
    ${RM_BTN_TD}`;
  document.getElementById('dhcp-pool-body').appendChild(tr);
}

function addDhcpRelayRow(iface='',server=''){
  const relayPh=tr('ph.dhcpRelayIface');
  const tr2=document.createElement('tr');
  tr2.innerHTML=`<td><input class="dr-iface" value="${escAttr(iface)}" placeholder="${relayPh}"></td>
    <td><input class="dr-server" value="${escAttr(server)}"></td>
    ${RM_BTN_TD}`;
  document.getElementById('dhcp-relay-body').appendChild(tr2);
}

function addAclRuleRow(name='',type='extended',seq='',action='permit',protocol='ip',src='any',dst='any',dstPort='',remark=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="ar-name" value="${escAttr(name)}"></td>
    <td><select class="ar-type">
      <option value="extended" data-i18n="opt.aclExtended">Extended/Advanced</option>
      <option value="standard" data-i18n="opt.aclStandard">Standard/Basic</option>
    </select></td>
    <td><input class="ar-seq" value="${escAttr(seq)}" placeholder="10"></td>
    <td><select class="ar-action">
      <option value="permit" data-i18n="opt.aclPermit">Permit</option>
      <option value="deny" data-i18n="opt.aclDeny">Deny</option>
    </select></td>
    <td><input class="ar-protocol" value="${escAttr(protocol)}" placeholder="ip/tcp/udp"></td>
    <td><input class="ar-src" value="${escAttr(src)}" placeholder="any / host 1.2.3.4"></td>
    <td><input class="ar-dst" value="${escAttr(dst)}"></td>
    <td><input class="ar-dstport" value="${escAttr(dstPort)}" placeholder="80"></td>
    <td><input class="ar-remark" value="${escAttr(remark)}"></td>
    ${RM_BTN_TD}`;
  tr.querySelector('.ar-type').value=type;
  tr.querySelector('.ar-action').value=action;
  document.getElementById('acl-rule-body').appendChild(tr);
  applyI18n(tr);
}

function addAclApplyRow(name='',iface='',direction='in'){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="aa-name" value="${escAttr(name)}"></td>
    <td><input class="aa-iface" value="${escAttr(iface)}"></td>
    <td><select class="aa-dir">
      <option value="in" data-i18n="opt.aclIn">In</option>
      <option value="out" data-i18n="opt.aclOut">Out</option>
    </select></td>
    ${RM_BTN_TD}`;
  tr.querySelector('.aa-dir').value=direction;
  document.getElementById('acl-apply-body').appendChild(tr);
  applyI18n(tr);
}

function addQosRow(policy='',cls='',behavior='',action='police',rate='',burst=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="q-policy" value="${escAttr(policy)}"></td>
    <td><input class="q-cls" value="${escAttr(cls)}"></td>
    <td><input class="q-behavior" value="${escAttr(behavior)}"></td>
    <td><select class="q-action">
      <option value="police" data-i18n="opt.qosPolice">Police</option>
      <option value="priority" data-i18n="opt.qosPriority">Priority</option>
      <option value="shape" data-i18n="opt.qosShape">Shape</option>
      <option value="bandwidth" data-i18n="opt.qosBandwidth">Bandwidth</option>
    </select></td>
    <td><input class="q-rate" value="${escAttr(rate)}" placeholder="1000000"></td>
    <td><input class="q-burst" value="${escAttr(burst)}" placeholder="10000"></td>
    ${RM_BTN_TD}`;
  tr.querySelector('.q-action').value=action;
  document.getElementById('qos-body').appendChild(tr);
  applyI18n(tr);
}

function addSecurityRow(port='',dot1x='-',portSec=false,maxMac='',violation='',guestVlan=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="sec-port" value="${escAttr(port)}"></td>
    <td><select class="sec-dot1x">
      <option value="-" data-i18n="opt.secNone">-</option>
      <option value="auth" data-i18n="opt.secAuth">Authenticator</option>
      <option value="supp" data-i18n="opt.secSupp">Supplicant</option>
    </select></td>
    <td style="text-align:center"><input type="checkbox" class="sec-portsec"></td>
    <td><input class="sec-maxmac" value="${escAttr(maxMac)}" placeholder="1"></td>
    <td><input class="sec-violation" value="${escAttr(violation)}" placeholder="shutdown/restrict/protect"></td>
    <td><input class="sec-guestvlan" value="${escAttr(guestVlan)}"></td>
    ${RM_BTN_TD}`;
  tr.querySelector('.sec-dot1x').value=dot1x;
  tr.querySelector('.sec-portsec').checked=!!portSec;
  document.getElementById('security-body').appendChild(tr);
  applyI18n(tr);
}

function addStpInstanceRow(id='',priority=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="sti-id" value="${escAttr(id)}"></td>
    <td><input class="sti-priority" value="${escAttr(priority)}" placeholder="32768"></td>
    ${RM_BTN_TD}`;
  document.getElementById('stp-instance-body').appendChild(tr);
}

function addStpPortRow(port='',portfast=false,bpduguard=false,guardRoot=false,cost='',priority=''){
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><input class="stp-port" value="${escAttr(port)}"></td>
    <td style="text-align:center"><input type="checkbox" class="stp-portfast"></td>
    <td style="text-align:center"><input type="checkbox" class="stp-bpduguard"></td>
    <td style="text-align:center"><input type="checkbox" class="stp-rootguard"></td>
    <td><input class="stp-cost" value="${escAttr(cost)}" placeholder="20000"></td>
    <td><input class="stp-priority" value="${escAttr(priority)}" placeholder="128"></td>
    ${RM_BTN_TD}`;
  tr.querySelector('.stp-portfast').checked=!!portfast;
  tr.querySelector('.stp-bpduguard').checked=!!bpduguard;
  tr.querySelector('.stp-rootguard').checked=!!guardRoot;
  document.getElementById('stp-port-body').appendChild(tr);
}

function updateModeOptions(){
  const vendor=document.getElementById('vendor').value;
  // Cisco IOS-XE 有兩種 breakout 模式（module 換位編號 / 後綴編號），需要額外欄位；其餘廠牌不需要
  const isCiscoIosXe=vendor==='cisco';
  document.getElementById('breakout-ios-xe-scheme').style.display=isCiscoIosXe?'inline-block':'none';
  document.getElementById('breakout-ios-xe-slot').style.display=isCiscoIosXe?'inline-block':'none';
  document.getElementById('breakout-ios-xe-switch').style.display=isCiscoIosXe?'inline-block':'none';
  // Auto-FortiLink Discovery 欄位僅 FortiSwitch 適用，其他廠牌隱藏整欄（比照 col-access/col-trunk/col-hybrid 既有 show class 機制）
  const isForti=vendor==='fortiswitch';
  document.querySelectorAll('#iface-table .col-fortilink').forEach(cell=>cell.classList.toggle('show',isForti));
  // QoS Priority／Trust DSCP 兩欄與 DSCP 對應表卡片僅 Brocade/Ruckus ICX 適用
  // （真實 FastIron QoS 為 8 佇列＋DSCP 對應表模型，跟其餘廠牌共用的 policy-map
  // QoS 卡片語意完全不同，故獨立於 Interface 表格與專屬小卡片，不共用既有 QoS 卡片）
  const isBrocade=vendor==='brocade';
  document.querySelectorAll('#iface-table .col-brocade-qos').forEach(cell=>cell.classList.toggle('show',isBrocade));
  const brocadeQosCard=document.getElementById('brocade-qos-card');
  if(brocadeQosCard)brocadeQosCard.style.display=isBrocade?'':'none';
  // Extreme QoS 卡片同理，僅 ExtremeXOS 適用（QP1-QP8 profile 模型，2026-07-19 新增）
  const extremeQosCard=document.getElementById('extreme-qos-card');
  if(extremeQosCard)extremeQosCard.style.display=vendor==='extreme'?'':'none';
  // RouterOS ACL／QoS 卡片同理，僅 MikroTik RouterOS 適用（chain-based firewall filter／
  // Simple Queue+Queue Tree 模型，2026-07-19 新增）
  const rosAclCard=document.getElementById('routeros-acl-card');
  if(rosAclCard)rosAclCard.style.display=vendor==='routeros'?'':'none';
  const rosQosCard=document.getElementById('routeros-qos-card');
  if(rosQosCard)rosQosCard.style.display=vendor==='routeros'?'':'none';
  // 本機帳號卡片：ProCurve（既有）＋ 2026-08-19 新增 9 家高信心度廠牌（Cisco IOS/IOS-XE／
  // Arista／Ruijie／NX-OS／Comware／Dell OS10／Brocade／Aruba CX／Juniper，皆有真實解析
  // 邏輯且語法在 config_anonymizer 獨立第二套正則交叉驗證過）＋ 2026-08-26 新增 Extreme
  // EXOS／MikroTik RouterOS（switch_analyzer 既有 parseExtremeXOSUsers()/parseRouterOSUsers()
  // 早已存在，本輪僅補 generator 端 render；RouterOS 因真實 /export 不含密碼欄位，僅能單向
  // 產生無法 round-trip 密碼）；Alcatel 中信心度、FortiSwitch/Netgear/EdgeSwitch/SONiC 完全
  // 零解析（EdgeSwitch/FortiSwitch/Netgear 已於 2026-08-23 補上 switch_analyzer 端解析，
  // generator 端尚未接線）留待後續評估，不開放
  const USERS_CARD_VENDORS=['procurve','cisco','arista','ruijie','cisco_nxos','comware','dell-os10','brocade','aruba','juniper','extreme','routeros'];
  const usersCard=document.getElementById('users-card');
  if(usersCard)usersCard.style.display=USERS_CARD_VENDORS.includes(vendor)?'':'none';
  // SONiC L3 介面 IP 卡片僅 SONiC 適用（config_db.json 的 INTERFACE/VLAN_INTERFACE/
  // PORTCHANNEL_INTERFACE 三表在通用介面表格找不到可重用欄位，見卡片定義處說明）
  const sonicL3Card=document.getElementById('sonic-l3-card');
  if(sonicL3Card)sonicL3Card.style.display=vendor==='sonic'?'':'none';
  const sonicQosCard=document.getElementById('sonic-qos-card');
  if(sonicQosCard)sonicQosCard.style.display=vendor==='sonic'?'':'none';
  const sonicStpVlanIntfCard=document.getElementById('sonic-stp-vlanintf-card');
  if(sonicStpVlanIntfCard)sonicStpVlanIntfCard.style.display=vendor==='sonic'?'':'none';
  // MLAG 卡片僅 Arista EOS 適用（其他廠牌無此概念，collectModel() 靠 #mlag-domain 是否存在於 DOM 判斷是否讀取）
  document.getElementById('mlag-card').style.display=vendor==='arista'?'':'none';
  // VPC 卡片僅 Cisco NX-OS 適用，比照 MLAG 慣例
  document.getElementById('vpc-card').style.display=vendor==='cisco_nxos'?'':'none';
  // VXLAN 卡片僅 Comware/Aruba CX 適用（switch_analyzer parseVXLAN() 目前只支援這兩家）
  document.getElementById('vxlan-card').style.display=(vendor==='comware'||vendor==='aruba'||vendor==='cisco_nxos')?'':'none';
  // 廠牌裝置真的不支援的功能卡片直接隱藏（VENDOR_INCAPABLE，見該常數定義處的語意說明），
  // 避免使用者填根本用不到的欄位；只是本工具尚未查證語法的項目（VENDOR_UNSUPPORTED）
  // 維持卡片可見＋validateForm() 非阻擋性警告，不在此隱藏
  const FEATURE_CARD_IDS={bgp:['bgp-card'],rip:['rip-card'],vrrp:['vrrp-card'],dhcpServer:['dhcp-server-card'],dhcpRelay:['dhcp-relay-card'],acl:['acl-card','acl-apply-card'],qos:['qos-card'],security:['security-card'],stp:['stp-card']};
  const incapable=VENDOR_INCAPABLE[vendor]||[];
  Object.keys(FEATURE_CARD_IDS).forEach(key=>{
    const hide=incapable.includes(key);
    FEATURE_CARD_IDS[key].forEach(id=>{
      const card=document.getElementById(id);
      if(card)card.style.display=hide?'none':'';
    });
  });
  document.querySelectorAll('.i-mode').forEach(sel=>{
    const hybridOpt=sel.querySelector('option[value="hybrid"]');
    if(vendor!=='comware'&&vendor!=='ruijie'){
      if(sel.value==='hybrid'){
        // 目標廠牌無 hybrid 概念，強制轉為 trunk 前，把 hybrid 的 VLAN 資料搬到 trunk 對應欄位，
        // 避免介面在切換廠牌後變成完全沒有 VLAN 指定的空白 trunk port（保留原 hybrid 欄位資料，不清空）
        const row=sel.closest('tr');
        const trunkInput=row.querySelector('.i-trunk-vlans');
        const nativeInput=row.querySelector('.i-native-vlan');
        if(!trunkInput.value.trim()){
          const untagged=row.querySelector('.i-hy-untagged').value.trim();
          const tagged=row.querySelector('.i-hy-tagged').value.trim();
          const merged=[...new Set((untagged+' '+tagged).trim().split(/\s+/).filter(Boolean))];
          if(merged.length)trunkInput.value=merged.join(' ');
        }
        if(!nativeInput.value.trim()){
          const pvid=row.querySelector('.i-hy-pvid').value.trim();
          if(pvid)nativeInput.value=pvid;
        }
        sel.value='trunk';
      }
      if(hybridOpt)hybridOpt.remove();
    }else if(!hybridOpt){
      const opt=document.createElement('option');
      opt.value='hybrid'; opt.dataset.i18n='opt.hybrid'; opt.textContent=tr('opt.hybrid');
      sel.appendChild(opt);
    }
  });
  // VSU 卡片僅 Ruijie RGOS 適用（比照 MLAG/VPC 慣例）
  const vsuCard=document.getElementById('vsu-card');
  if(vsuCard)vsuCard.style.display=vendor==='ruijie'?'':'none';
  updateDeviceModelOptions();
  updateAppliedModelNotice();
}

function collectModel(){
  const vlans=rowsOf('#vlan-body tr').map(tr=>({id:val(tr,'v-id'),name:val(tr,'v-name')})).filter(v=>v.id);

  const interfaces=rowsOf('#iface-body tr').map(tr=>({
    name:val(tr,'i-name'), desc:val(tr,'i-desc'), mode:val(tr,'i-mode'),
    speed:val(tr,'i-speed')||'1G',
    accessVlan:val(tr,'i-access-vlan'),
    trunkVlans:val(tr,'i-trunk-vlans'),
    nativeVlan:val(tr,'i-native-vlan'),
    hybrid:{
      pvid:val(tr,'i-hy-pvid'),
      untagged:val(tr,'i-hy-untagged').split(/\s+/).filter(Boolean),
      tagged:val(tr,'i-hy-tagged').split(/\s+/).filter(Boolean),
    },
    shutdown:val(tr,'i-shutdown'),
    jumbo:{enabled:val(tr,'i-jumbo-en'),mtu:val(tr,'i-jumbo-mtu')},
    poeMode:val(tr,'i-poe-mode')||'none',
    fortilinkDiscovery:val(tr,'i-fortilink')||'',
  })).filter(i=>i.name);

  // Brocade/Ruckus ICX QoS 專屬形狀（見 parseBrocadeQoS 註解）：逐 port 優先權／
  // trust dscp 沿用 Interface 表格自身列（非另開一張表），全域 DSCP 對應表另有專屬小卡片。
  // 命名為 brocadeQos（非 qos）避免跟下方既有共用 Cisco-style policy-map qos 變數撞名
  const brocadeQos={
    ports: rowsOf('#iface-body tr').map(tr=>({
      port: val(tr,'i-name'), priority: val(tr,'i-qos-priority'), trustDscp: !!val(tr,'i-trust-dscp'),
    })).filter(p=>p.port&&(p.priority||p.trustDscp)),
    dscpMap: rowsOf('#qos-dscp-body tr').map(tr=>({
      dscpValues: val(tr,'qos-dscp-values'), priority: val(tr,'qos-dscp-priority'),
    })).filter(m=>m.dscpValues&&m.priority),
  };

  // Extreme QoS：命名為 extremeQos（非 qos）避免撞名，理由同 brocadeQos；QP1-QP8 profile
  // 模型與共用 policy-map qos 語意完全不同，資料來自專屬 #extreme-qos-card 三個列表
  const extremeQos={
    profiles: rowsOf('#extreme-qos-profile-body tr').map(tr=>({
      name: val(tr,'exq-profile'), minbw: val(tr,'exq-minbw'), maxbw: val(tr,'exq-maxbw'),
    })).filter(p=>p.name&&(p.minbw||p.maxbw)),
    dscpMap: rowsOf('#extreme-qos-dscp-body tr').map(tr=>({
      codePoint: val(tr,'exq-dscp-cp'), profile: val(tr,'exq-dscp-profile'),
    })).filter(m=>m.codePoint&&m.profile),
    ports: rowsOf('#extreme-qos-port-body tr').map(tr=>({
      port: val(tr,'exq-port'), profile: val(tr,'exq-port-profile'), diffservExam: !!val(tr,'exq-port-diffserv'),
    })).filter(p=>p.port&&(p.profile||p.diffservExam)),
  };

  // RouterOS ACL：chain-based 扁平規則清單，命名為 routerosAcl（非 acl）避免撞名既有
  // 共用 acl 陣列，比照 Brocade brocadeQos／Extreme extremeQos 前例
  const routerosAcl=rowsOf('#routeros-acl-body tr').map(tr=>({
    chain: val(tr,'ros-acl-chain'), action: val(tr,'ros-acl-action'), protocol: val(tr,'ros-acl-protocol'),
    srcAddress: val(tr,'ros-acl-src'), dstAddress: val(tr,'ros-acl-dst'), dstPort: val(tr,'ros-acl-dstport'),
    inInterface: val(tr,'ros-acl-inif'), comment: val(tr,'ros-acl-comment'),
  })).filter(r=>r.chain&&r.action);

  // SONiC L3 介面 IP：命名為 sonicL3Interfaces（非 interfaces）避免撞名既有共用 interface
  // 陣列——通用 #iface-table 只有 access/trunk/hybrid 三種模式、無 routed L3 埠欄位，且
  // VLAN SVI IP 目前唯一來源（VRRP 卡片）強制要求 vrid+vip 同時非空，無法乾淨重用，
  // 故新增此專屬卡片承載 INTERFACE/VLAN_INTERFACE/PORTCHANNEL_INTERFACE 三表的 L3 IP
  const sonicL3Interfaces=rowsOf('#sonic-l3-body tr').map(tr=>({
    name: val(tr,'sl3-name'), cidr: val(tr,'sl3-cidr'),
  })).filter(x=>x.name&&x.cidr);

  // SONiC QoS（2026-08-08 對外查證新增）：SCHEDULER 定義＋PORT_QOS_MAP/QUEUE 套用，命名為
  // sonicQos（非 qos）避免撞名共用 policy-map QoS 陣列，理由同 sonicL3Interfaces
  const sonicQos={
    schedulers: rowsOf('#sonic-qos-sched-body tr').map(tr=>({
      name: val(tr,'sqs-name'), type: val(tr,'sqs-type'), weight: val(tr,'sqs-weight'),
      meterType: val(tr,'sqs-metertype'), cir: val(tr,'sqs-cir'), cbs: val(tr,'sqs-cbs'),
      pir: val(tr,'sqs-pir'), pbs: val(tr,'sqs-pbs'),
    })).filter(s=>s.name),
    apply: rowsOf('#sonic-qos-apply-body tr').map(tr=>({
      target: val(tr,'sqa-target'), queue: val(tr,'sqa-queue'), scheduler: val(tr,'sqa-scheduler'),
    })).filter(a=>a.target&&a.scheduler),
  };

  // SONiC STP 逐 VLAN 逐 Port 覆寫（STP_VLAN_INTF，2026-08-08 對外查證新增）：獨立頂層欄位，
  // 理由同 sonicL3Interfaces（共用 STP 形狀無 VLAN 維度）
  const sonicStpVlanIntf=rowsOf('#sonic-stp-vlanintf-body tr').map(tr=>({
    vlan: val(tr,'ssvi-vlan'), port: val(tr,'ssvi-port'),
    cost: val(tr,'ssvi-cost'), priority: val(tr,'ssvi-priority'),
  })).filter(x=>x.vlan&&x.port);

  // RouterOS QoS：Simple Queue + Queue Tree，命名為 routerosQos（非 qos）避免撞名，理由同上
  const routerosQos={
    simpleQueues: rowsOf('#routeros-simple-queue-body tr').map(tr=>({
      name: val(tr,'ros-qos-name'), target: val(tr,'ros-qos-target'),
      maxLimitUp: val(tr,'ros-qos-maxup'), maxLimitDown: val(tr,'ros-qos-maxdown'),
      limitAtUp: val(tr,'ros-qos-atup'), limitAtDown: val(tr,'ros-qos-atdown'),
    })).filter(q=>q.name),
    queueTree: rowsOf('#routeros-queue-tree-body tr').map(tr=>({
      name: val(tr,'ros-qtree-name'), parent: val(tr,'ros-qtree-parent'), maxLimit: val(tr,'ros-qtree-max'),
    })).filter(q=>q.name),
  };

  // 本機帳號（Aruba ProCurve）：密碼欄位為使用者直接貼上的 SHA1 雜湊值，不做任何轉換
  const users=rowsOf('#users-body tr').map(tr=>({
    name: val(tr,'user-name'), role: val(tr,'user-role'), password: val(tr,'user-password'),
  })).filter(u=>u.name);

  const areaRows=rowsOf('#area-body tr').map(tr=>({
    area:val(tr,'a-area'), network:val(tr,'a-network'), wildcard:val(tr,'a-wildcard'), type:val(tr,'a-type'),
    noSummary:!!val(tr,'a-nosummary'),
  })).filter(r=>r.area&&r.network);

  const areaMap=new Map();
  areaRows.forEach(r=>{
    if(!areaMap.has(r.area))areaMap.set(r.area,{area:r.area,type:r.type||'normal',noSummary:r.noSummary,networks:[]});
    else if(r.type&&r.type!=='normal'){areaMap.get(r.area).type=r.type;areaMap.get(r.area).noSummary=r.noSummary;}
    areaMap.get(r.area).networks.push({network:r.network,wildcard:r.wildcard||'0.0.0.0'});
  });

  const pid=document.getElementById('ospf-pid').value.trim();
  const ospf=[];
  if(pid){
    ospf.push({
      pid,
      routerId:document.getElementById('ospf-rid').value.trim(),
      areas:Array.from(areaMap.values()),
      redistributes:document.getElementById('ospf-redist').value.trim().split(/\s+/).filter(Boolean),
    });
  }

  const bgpAsn=document.getElementById('bgp-asn').value.trim();
  const bgp=[];
  if(bgpAsn){
    const peers=rowsOf('#bgp-peer-body tr').map(tr=>({
      ip:val(tr,'p-ip'), as:val(tr,'p-as'), desc:val(tr,'p-desc'),
    })).filter(p=>p.ip);
    const bgpKeepalive=document.getElementById('bgp-timer-keepalive').value.trim();
    const bgpHold=document.getElementById('bgp-timer-hold').value.trim();
    bgp.push({
      asn:bgpAsn,
      routerId:document.getElementById('bgp-rid').value.trim(),
      peers,
      networks:document.getElementById('bgp-networks').value.trim().split(/\s+/).filter(Boolean),
      peerGroups:document.getElementById('bgp-peer-group').value.trim().split(/\s+/).filter(Boolean).map(name=>({name,type:''})),
      timers:(bgpKeepalive&&bgpHold)?{keepalive:bgpKeepalive,holdtime:bgpHold}:null,
    });
  }

  const ripPid=document.getElementById('rip-pid').value.trim();
  const rip=[];
  if(ripPid){
    rip.push({
      pid:ripPid,
      version:document.getElementById('rip-version').value.trim(),
      networks:document.getElementById('rip-networks').value.trim().split(/\s+/).filter(Boolean),
      redistribute:document.getElementById('rip-redist').value.trim().split(/\s+/).filter(Boolean),
      passive:document.getElementById('rip-silent').value.trim().split(/\s+/).filter(Boolean),
      autoSummary:document.getElementById('rip-summary').checked,
      defaultMetric:document.getElementById('rip-default-cost').value.trim(),
    });
  }

  const routes=rowsOf('#route-body tr').map(tr=>({
    dst:val(tr,'rt-dst'), gw:val(tr,'rt-gw'), metric:val(tr,'rt-metric'),
  })).filter(r=>r.dst&&r.gw);

  const lacp=rowsOf('#lacp-body tr').map(tr=>({
    id:val(tr,'lg-id'), mode:val(tr,'lg-mode'),
    members:val(tr,'lg-members').split(/\s+/).filter(Boolean),
  })).filter(l=>l.id);

  const vrrp=rowsOf('#vrrp-body tr').map(tr=>({
    vlanId:val(tr,'vr-vlan'), ip:val(tr,'vr-ip'), vrid:val(tr,'vr-id'),
    vip:val(tr,'vr-vip'), priority:val(tr,'vr-priority')||'100', preempt:val(tr,'vr-preempt'),
    authMode:val(tr,'vr-authmode'), authKey:val(tr,'vr-authkey'),
    trackIf:val(tr,'vr-trackif'), trackReduced:val(tr,'vr-trackreduced'),
  })).filter(v=>v.vlanId&&v.vrid&&v.vip);

  // DHCP：server pool 與 relay 各自獨立 UI 表格，但沿用 switch_analyzer parseDHCP 的
  // 共用扁平陣列形狀（type:'server'|'relay'）合併成單一 dhcp 清單
  const dhcpServers=rowsOf('#dhcp-pool-body tr').map(tr=>({
    name:val(tr,'dp-name'), network:val(tr,'dp-network'), gateway:val(tr,'dp-gateway'),
    dns:val(tr,'dp-dns'), range:val(tr,'dp-range'), excluded:val(tr,'dp-excluded'),
    lease:val(tr,'dp-lease'), interface:val(tr,'dp-iface'), type:'server',
  })).filter(d=>d.name);
  const dhcpRelays=rowsOf('#dhcp-relay-body tr').map(tr=>({
    interface:val(tr,'dr-iface'), relayServer:val(tr,'dr-server'), type:'relay',
  })).filter(d=>d.relayServer);
  const dhcp=[...dhcpServers, ...dhcpRelays];

  // ACL：規則表格 + 套用表格各自獨立 UI，依 ACL Name 分組成 switch_analyzer parseACL
  // 既有的巢狀形狀（{name,type,rules:[],appliedOn:[]}），比照 OSPF area 分組慣例
  const aclRuleRows=rowsOf('#acl-rule-body tr').map(tr=>({
    name:val(tr,'ar-name'), type:val(tr,'ar-type'), seq:val(tr,'ar-seq'), action:val(tr,'ar-action'),
    protocol:val(tr,'ar-protocol'), src:val(tr,'ar-src'), dst:val(tr,'ar-dst'),
    dstPort:val(tr,'ar-dstport'), remark:val(tr,'ar-remark'),
  })).filter(r=>r.name);
  const aclApplyRows=rowsOf('#acl-apply-body tr').map(tr=>({
    name:val(tr,'aa-name'), interface:val(tr,'aa-iface'), direction:val(tr,'aa-dir'),
  })).filter(r=>r.name&&r.interface);
  const aclMap=new Map();
  aclRuleRows.forEach(r=>{
    if(!aclMap.has(r.name))aclMap.set(r.name,{name:r.name,type:r.type||'extended',rules:[],appliedOn:[]});
    aclMap.get(r.name).rules.push({seq:r.seq,action:r.action||'permit',protocol:r.protocol||'ip',src:r.src||'any',dst:r.dst||'any',dstPort:r.dstPort,remark:r.remark});
  });
  aclApplyRows.forEach(r=>{
    if(!aclMap.has(r.name))aclMap.set(r.name,{name:r.name,type:'extended',rules:[],appliedOn:[]});
    aclMap.get(r.name).appliedOn.push({interface:r.interface,direction:r.direction||'in'});
  });
  const acl=Array.from(aclMap.values());

  const qos=rowsOf('#qos-body tr').map(tr=>({
    policy:val(tr,'q-policy'), cls:val(tr,'q-cls'), behavior:val(tr,'q-behavior'),
    action:val(tr,'q-action'), rate:val(tr,'q-rate'), burst:val(tr,'q-burst'),
  })).filter(q=>q.policy&&q.cls);

  const security=rowsOf('#security-body tr').map(tr=>({
    port:val(tr,'sec-port'), dot1x:val(tr,'sec-dot1x'), portSec:val(tr,'sec-portsec'),
    maxMac:val(tr,'sec-maxmac'), violation:val(tr,'sec-violation'), guestVlan:val(tr,'sec-guestvlan'),
  })).filter(s=>s.port&&(s.dot1x!=='-'||s.portSec));

  // STP：單一設定物件（非清單），沿用 switch_analyzer parseSTP 既有巢狀形狀
  const stpInstances=rowsOf('#stp-instance-body tr').map(tr=>({
    id:val(tr,'sti-id'), priority:val(tr,'sti-priority'),
  })).filter(i=>i.id);
  const stpPorts=rowsOf('#stp-port-body tr').map(tr=>({
    port:val(tr,'stp-port'), portfast:val(tr,'stp-portfast'), bpduguard:val(tr,'stp-bpduguard'),
    guardRoot:val(tr,'stp-rootguard'), cost:val(tr,'stp-cost'), priority:val(tr,'stp-priority'),
  })).filter(p=>p.port);
  const stpMode=document.getElementById('stp-mode').value.trim();
  const stp={
    mode:stpMode||null,
    rootMode:document.getElementById('stp-rootmode').value||null,
    timers:{
      hello:document.getElementById('stp-hello').value.trim()||null,
      forwardDelay:document.getElementById('stp-forward').value.trim()||null,
      maxAge:document.getElementById('stp-maxage').value.trim()||null,
    },
    instances:stpInstances,
    ports:stpPorts,
  };

  const breakouts=_breakoutEnables.slice();

  // MLAG：僅 Arista 使用，單一設定物件（非清單），欄位命名對齊 switch_analyzer
  // parseAristaMlag() 既有回傳形狀 {domain,peerLink,peerAddr,localIntf}
  const mlagDomainEl=document.getElementById('mlag-domain');
  const mlag=mlagDomainEl?{
    domain:mlagDomainEl.value.trim(),
    localIntf:document.getElementById('mlag-local-intf').value.trim(),
    peerAddr:document.getElementById('mlag-peer-addr').value.trim(),
    peerLink:document.getElementById('mlag-peer-link').value.trim(),
  }:null;

  // VPC：僅 Cisco NX-OS 使用，單一設定物件（非清單），欄位命名對齊 switch_analyzer
  // parseNxosVpc() 既有回傳形狀 {domain,peerLink,peerKeepalive,peerGateway}
  const vpcDomainEl=document.getElementById('vpc-domain');
  const vpc=vpcDomainEl?{
    domain:vpcDomainEl.value.trim(),
    peerKeepalive:document.getElementById('vpc-peer-keepalive').value.trim(),
    peerLink:document.getElementById('vpc-peer-link').value.trim(),
    peerGateway:document.getElementById('vpc-peer-gateway').checked,
  }:null;

  // VSU：僅 Ruijie RGOS 使用，欄位命名對齊 switch_analyzer parseRuijieStack() 既有回傳
  // 形狀 {domain,members:[{id,priority}],vsl:[{memberId,interfaces}]}——表單端 vslPorts
  // 用空白分隔字串輸入，讀取時比照 lacp.members 慣例 split 成陣列
  const vsuDomainEl=document.getElementById('vsu-domain');
  const vsuMembers=rowsOf('#vsu-member-body tr').map(tr=>({
    id:val(tr,'vsu-mem-id'), priority:val(tr,'vsu-mem-priority'),
    vslPorts:val(tr,'vsu-mem-vsl').split(/\s+/).filter(Boolean),
  })).filter(m=>m.id);
  const stack=vsuDomainEl?{domain:vsuDomainEl.value.trim(),members:vsuMembers}:null;

  // VXLAN：僅 Comware/Aruba CX 使用，單一設定物件（非清單），欄位命名對齊 switch_analyzer
  // parseVXLAN() 既有回傳形狀 {vtep, vnis:[{vni,vlan,name,peers,rd,rtImport,rtExport,gw}]}
  const vxlanVtepEl=document.getElementById('vxlan-vtep');
  const vxlanVnis=rowsOf('#vxlan-vni-body tr').map(tr=>({
    vni:val(tr,'vx-vni'), vlan:val(tr,'vx-vlan'), name:val(tr,'vx-name'),
    peers:val(tr,'vx-peers').split(/\s+/).filter(Boolean),
    rd:val(tr,'vx-rd'), rtImport:val(tr,'vx-rt-import'), rtExport:val(tr,'vx-rt-export'),
    gw:val(tr,'vx-gw'),
  })).filter(v=>v.vni);
  const vxlan=vxlanVtepEl?{vtep:vxlanVtepEl.value.trim(),vnis:vxlanVnis}:null;

  return {
    vendor:document.getElementById('vendor').value,
    sysname:document.getElementById('hostname').value.trim()||'Switch',
    snmpTrapHost:document.getElementById('snmp-trap-host').value.trim(),
    syslogServer:document.getElementById('syslog-server').value.trim(),
    vlans, interfaces, ospf, bgp, rip, routes, lacp, vrrp, dhcp, acl, qos, security, stp, breakouts, mlag, vpc, vxlan, brocadeQos, extremeQos, routerosAcl, routerosQos, stack, users, sonicL3Interfaces, sonicQos, sonicStpVlanIntf,
  };
}

// ── 設定模板庫 ──────────────────────────────────────────────────
// applyModelToForm() 是 collectModel() 的反向函式：回填順序比照既有 parseAndImport()
// 慣例——先清空各表格 → 設定 vendor（觸發 updateModeOptions()）→ 設定 scalar 欄位 →
// 逐項呼叫 addXxxRow() 重建列。儲存的 model 就是 collectModel() 的完整輸出，故欄位
// 名稱與此函式讀取的完全對稱，不需另外映射。
function applyModelToForm(model){
  ['vlan-body','iface-body','area-body','bgp-peer-body','route-body','lacp-body','vrrp-body','dhcp-pool-body','dhcp-relay-body','acl-rule-body','acl-apply-body','qos-body','security-body','stp-instance-body','stp-port-body','vxlan-vni-body','qos-dscp-body','extreme-qos-profile-body','extreme-qos-dscp-body','extreme-qos-port-body','routeros-acl-body','routeros-simple-queue-body','routeros-queue-tree-body','vsu-member-body','users-body','sonic-l3-body','sonic-qos-sched-body','sonic-qos-apply-body','sonic-stp-vlanintf-body'].forEach(id=>{
    document.getElementById(id).innerHTML='';
  });

  document.getElementById('vendor').value=model.vendor||'comware';
  updateModeOptions();
  document.getElementById('hostname').value=model.sysname||'';
  document.getElementById('snmp-trap-host').value=model.snmpTrapHost||'';
  document.getElementById('syslog-server').value=model.syslogServer||'';

  (model.vlans||[]).forEach(v=>addVlanRow(v.id,v.name));

  const brocadeQosPortMap=new Map(((model.brocadeQos&&model.brocadeQos.ports)||[]).map(p=>[p.port,p]));
  (model.interfaces||[]).forEach(i=>{
    addIfaceRow(i.name,i.mode||'access',i.speed||'1G',i.poeMode||'none',i.fortilinkDiscovery||'');
    const rows=rowsOf('#iface-body tr'); const row=rows[rows.length-1];
    row.querySelector('.i-desc').value=i.desc||'';
    row.querySelector('.i-access-vlan').value=i.accessVlan||'';
    row.querySelector('.i-trunk-vlans').value=i.trunkVlans||'';
    row.querySelector('.i-native-vlan').value=i.nativeVlan||'';
    if(i.hybrid){
      row.querySelector('.i-hy-untagged').value=(i.hybrid.untagged||[]).join(' ');
      row.querySelector('.i-hy-tagged').value=(i.hybrid.tagged||[]).join(' ');
      row.querySelector('.i-hy-pvid').value=i.hybrid.pvid||'';
    }
    row.querySelector('.i-shutdown').checked=!!i.shutdown;
    if(i.jumbo){
      row.querySelector('.i-jumbo-en').checked=!!i.jumbo.enabled;
      row.querySelector('.i-jumbo-mtu').value=i.jumbo.mtu||'';
    }
    const qp=brocadeQosPortMap.get(i.name);
    if(qp){
      row.querySelector('.i-qos-priority').value=qp.priority||'';
      row.querySelector('.i-trust-dscp').checked=!!qp.trustDscp;
    }
  });

  // Brocade/Ruckus ICX QoS DSCP 對應表（僅 Brocade 顯示，比照 MLAG/VPC/VXLAN 慣例——
  // 欄位一直存在於 DOM，只是卡片被 updateModeOptions() 隱藏）
  (model.brocadeQos&&model.brocadeQos.dscpMap||[]).forEach(m=>addQosDscpRow(m.dscpValues,m.priority));

  // Extreme QoS（僅 Extreme 顯示，理由同上）：profile／DSCP 對應／逐 port 三個獨立列表
  (model.extremeQos&&model.extremeQos.profiles||[]).forEach(p=>addExtremeQosProfileRow(p.name,p.minbw,p.maxbw));
  (model.extremeQos&&model.extremeQos.dscpMap||[]).forEach(m=>addExtremeQosDscpRow(m.codePoint,m.profile));
  (model.extremeQos&&model.extremeQos.ports||[]).forEach(p=>addExtremeQosPortRow(p.port,p.profile,p.diffservExam));

  // RouterOS ACL／QoS（僅 RouterOS 顯示，理由同上）
  (model.routerosAcl||[]).forEach(r=>addRouterOSAclRow(r.chain,r.action,r.protocol,r.srcAddress,r.dstAddress,r.dstPort,r.inInterface,r.comment));
  (model.routerosQos&&model.routerosQos.simpleQueues||[]).forEach(q=>addRouterOSSimpleQueueRow(q.name,q.target,q.maxLimitUp,q.maxLimitDown,q.limitAtUp,q.limitAtDown));
  (model.routerosQos&&model.routerosQos.queueTree||[]).forEach(q=>addRouterOSQueueTreeRow(q.name,q.parent,q.maxLimit));
  (model.users||[]).forEach(u=>addUsersRow(u.name,u.role,u.password));

  // SONiC L3／QoS／STP VLAN 覆寫（僅 SONiC 顯示，理由同上；sonicL3Interfaces 為既有欄位，
  // 先前模板載入路徑漏接，本輪一併補上，非本輪新增功能範圍擴大）
  (model.sonicL3Interfaces||[]).forEach(entry=>addSonicL3Row(entry.name,entry.cidr));
  (model.sonicQos&&model.sonicQos.schedulers||[]).forEach(s=>addSonicQosSchedRow(s.name,s.type,s.weight,s.meterType,s.cir,s.cbs,s.pir,s.pbs));
  (model.sonicQos&&model.sonicQos.apply||[]).forEach(a=>addSonicQosApplyRow(a.target,a.queue,a.scheduler));
  (model.sonicStpVlanIntf||[]).forEach(v=>addSonicStpVlanIntfRow(v.vlan,v.port,v.cost,v.priority));

  const o=(model.ospf||[])[0];
  document.getElementById('ospf-pid').value=o?.pid||'';
  document.getElementById('ospf-rid').value=o?.routerId||'';
  document.getElementById('ospf-redist').value=(o?.redistributes||[]).join(' ');
  (o?.areas||[]).forEach(a=>{
    const nets=(a.networks&&a.networks.length)?a.networks:[{network:'',wildcard:''}];
    nets.forEach(n=>addAreaRow(a.area,n.network,n.wildcard,a.type||'normal',a.noSummary));
  });

  const b=(model.bgp||[])[0];
  document.getElementById('bgp-asn').value=b?.asn||'';
  document.getElementById('bgp-rid').value=b?.routerId||'';
  document.getElementById('bgp-networks').value=(b?.networks||[]).join(' ');
  document.getElementById('bgp-peer-group').value=(b?.peerGroups||[]).map(g=>g.name).join(' ');
  document.getElementById('bgp-timer-keepalive').value=b?.timers?.keepalive||'';
  document.getElementById('bgp-timer-hold').value=b?.timers?.holdtime||'';
  (b?.peers||[]).forEach(p=>addBgpPeerRow(p.ip,p.as,p.desc||''));

  const r=(model.rip||[])[0];
  document.getElementById('rip-pid').value=r?.pid||'';
  document.getElementById('rip-version').value=r?.version||'';
  document.getElementById('rip-networks').value=(r?.networks||[]).join(' ');
  document.getElementById('rip-redist').value=(r?.redistribute||[]).join(' ');
  document.getElementById('rip-silent').value=(r?.passive||[]).join(' ');
  document.getElementById('rip-summary').checked=!!r?.autoSummary;
  document.getElementById('rip-default-cost').value=r?.defaultMetric||'';

  (model.routes||[]).forEach(rt=>addRouteRow(rt.dst,rt.gw,rt.metric));

  (model.lacp||[]).forEach(l=>addLacpRow(l.id,l.mode,(l.members||[]).join(' ')));

  (model.vrrp||[]).forEach(v=>addVrrpRow(v.vlanId,v.ip,v.vrid,v.vip,v.priority,!!v.preempt,v.authMode,v.authKey,v.trackIf,v.trackReduced));

  (model.dhcp||[]).forEach(d=>{
    if(d.type==='server')addDhcpPoolRow(d.name,d.network,d.gateway,d.dns,d.range,d.excluded,d.lease,d.interface);
    else if(d.type==='relay')addDhcpRelayRow(d.interface,d.relayServer);
  });

  (model.acl||[]).forEach(a=>{
    (a.rules||[]).forEach(r=>addAclRuleRow(a.name,a.type||'extended',r.seq,r.action,r.protocol,r.src,r.dst,r.dstPort,r.remark));
    (a.appliedOn||[]).forEach(ap=>addAclApplyRow(a.name,ap.interface,ap.direction));
  });

  (model.qos||[]).forEach(q=>addQosRow(q.policy,q.cls,q.behavior,q.action,q.rate,q.burst));

  (model.security||[]).forEach(s=>addSecurityRow(s.port,s.dot1x,!!s.portSec,s.maxMac,s.violation,s.guestVlan));

  const stp=model.stp||{};
  document.getElementById('stp-mode').value=stp.mode||'';
  document.getElementById('stp-rootmode').value=stp.rootMode||'';
  document.getElementById('stp-hello').value=stp.timers?.hello||'';
  document.getElementById('stp-forward').value=stp.timers?.forwardDelay||'';
  document.getElementById('stp-maxage').value=stp.timers?.maxAge||'';
  (stp.instances||[]).forEach(i=>addStpInstanceRow(i.id,i.priority));
  (stp.ports||[]).forEach(p=>addStpPortRow(p.port,!!p.portfast,!!p.bpduguard,!!p.guardRoot,p.cost,p.priority));

  // MLAG（僅 Arista 顯示，但 #mlag-domain 等欄位本身一直存在於 DOM，只是卡片被
  // updateModeOptions() 隱藏，故非 arista 模板時這裡單純寫入不可見欄位，無副作用）
  const mlagDomainEl=document.getElementById('mlag-domain');
  if(mlagDomainEl&&model.mlag){
    mlagDomainEl.value=model.mlag.domain||'';
    document.getElementById('mlag-local-intf').value=model.mlag.localIntf||'';
    document.getElementById('mlag-peer-addr').value=model.mlag.peerAddr||'';
    document.getElementById('mlag-peer-link').value=model.mlag.peerLink||'';
  }

  // VPC（僅 Cisco NX-OS 顯示，比照 MLAG 慣例——欄位一直存在於 DOM，只是卡片被隱藏）
  const vpcDomainEl=document.getElementById('vpc-domain');
  if(vpcDomainEl&&model.vpc){
    vpcDomainEl.value=model.vpc.domain||'';
    document.getElementById('vpc-peer-keepalive').value=model.vpc.peerKeepalive||'';
    document.getElementById('vpc-peer-link').value=model.vpc.peerLink||'';
    document.getElementById('vpc-peer-gateway').checked=!!model.vpc.peerGateway;
  }

  // VSU（僅 Ruijie RGOS 顯示，比照 MLAG/VPC 慣例——欄位一直存在於 DOM，只是卡片被隱藏）
  const vsuDomainEl=document.getElementById('vsu-domain');
  if(vsuDomainEl&&model.stack){
    vsuDomainEl.value=model.stack.domain||'';
    document.getElementById('vsu-member-body').innerHTML='';
    (model.stack.members||[]).forEach(m=>addVsuMemberRow(m.id,m.priority,(m.vslPorts||[]).join(' ')));
  }

  // VXLAN（僅 Comware/Aruba CX 顯示，比照 MLAG/VPC 慣例——欄位一直存在於 DOM，只是卡片被隱藏）
  const vxlanVtepEl=document.getElementById('vxlan-vtep');
  if(vxlanVtepEl&&model.vxlan){
    vxlanVtepEl.value=model.vxlan.vtep||'';
    (model.vxlan.vnis||[]).forEach(v=>addVxlanVniRow(v.vni,v.vlan,v.name,(v.peers||[]).join(' '),v.rd,v.rtImport,v.rtExport,v.gw));
  }

  // Breakout enable 清單：模板儲存的是產生階段當下的最終狀態，回填後維持一致，
  // 之後使用者若再用「Split-out 輔助」小工具展開子埠會繼續累加
  _breakoutEnables=(model.breakouts||[]).slice();
}

// localStorage 儲存的模板庫：{ [模板名稱]: { savedAt, model } }。這是本檔案第一次把
// 結構化 JSON 存進 localStorage（先前只有 cw_theme 這種純字串），讀取時務必 try/catch
// 包住 JSON.parse，避免使用者手動改壞 localStorage 內容導致整頁掛掉
const TEMPLATE_STORAGE_KEY='cw_templates';

function loadTemplates(){
  try{
    const raw=localStorage.getItem(TEMPLATE_STORAGE_KEY);
    if(!raw)return {};
    const parsed=JSON.parse(raw);
    return (parsed&&typeof parsed==='object')?parsed:{};
  }catch(e){
    return {};
  }
}

function saveTemplates(templates){
  try{
    localStorage.setItem(TEMPLATE_STORAGE_KEY, JSON.stringify(templates));
    return true;
  }catch(e){
    return false;
  }
}

function renderTemplateList(){
  const listEl=document.getElementById('template-list');
  const templates=loadTemplates();
  const names=Object.keys(templates).sort();
  listEl.innerHTML='';
  if(!names.length){
    const empty=document.createElement('div');
    empty.className='template-empty';
    empty.dataset.i18n='msg.noTemplates';
    listEl.appendChild(empty);
    applyI18n(listEl);
    return;
  }
  // 用 DOM API 逐一建構（而非 innerHTML 字串拼接 + inline onclick），避免模板名稱這種
  // 使用者自由輸入的字串需要同時處理 HTML 屬性跳脫與 JS 字串跳脫兩層轉義的脆弱性
  names.forEach(name=>{
    const t=templates[name];
    const item=document.createElement('div');
    item.className='template-item';
    const info=document.createElement('div');
    info.className='template-item-info';
    const nameEl=document.createElement('strong');
    nameEl.textContent=name;
    const metaEl=document.createElement('span');
    metaEl.className='template-item-meta';
    metaEl.textContent=`${t.model?.vendor||''} · ${t.savedAt||''}`;
    info.appendChild(nameEl); info.appendChild(metaEl);
    const actions=document.createElement('div');
    actions.className='template-item-actions';
    const loadBtn=document.createElement('button');
    loadBtn.className='add-btn'; loadBtn.dataset.i18n='btn.loadTemplate'; loadBtn.textContent=tr('btn.loadTemplate');
    loadBtn.onclick=()=>loadTemplate(name);
    const delBtn=document.createElement('button');
    delBtn.className='rm-btn'; delBtn.dataset.i18n='btn.deleteTemplate'; delBtn.textContent=tr('btn.deleteTemplate');
    delBtn.onclick=()=>deleteTemplate(name);
    actions.appendChild(loadBtn); actions.appendChild(delBtn);
    item.appendChild(info); item.appendChild(actions);
    listEl.appendChild(item);
  });
}

function saveTemplate(){
  const nameInput=document.getElementById('template-name');
  const name=nameInput.value.trim();
  if(!name){ showTemplateMsg(tr('msg.templateNameRequired'),true); return; }
  const templates=loadTemplates();
  if(name in templates){
    if(!confirm(tr('msg.templateOverwriteConfirm').replace('{name}',name)))return;
  }
  templates[name]={ savedAt:new Date().toLocaleString(), model:collectModel() };
  if(saveTemplates(templates)){
    nameInput.value='';
    showTemplateMsg(tr('msg.templateSaved'),false);
    renderTemplateList();
  }else{
    showTemplateMsg(tr('msg.templateSaveFailed'),true);
  }
}

function loadTemplate(name){
  const templates=loadTemplates();
  const t=templates[name];
  if(!t){ showTemplateMsg(tr('msg.templateNotFound'),true); return; }
  applyModelToForm(t.model);
  generate(true);
  showTemplateMsg(tr('msg.templateLoaded'),false);
}

function deleteTemplate(name){
  const templates=loadTemplates();
  if(!(name in templates))return;
  if(!confirm(tr('msg.templateDeleteConfirm').replace('{name}',name)))return;
  delete templates[name];
  saveTemplates(templates);
  renderTemplateList();
}

function showTemplateMsg(text,isError){
  const el=document.getElementById('template-msg');
  if(!el)return;
  el.textContent=text;
  el.style.color=isError?'var(--red)':'var(--green)';
}

// ── 表單驗證系統 ──────────────────────────────────────────────────
// 廠牌功能支援對照表：逐一 Grep 13 個 assembleXxxConfig() 函式，確認實際有沒有引用
// 對應的 model 欄位得出（非憑印象或 CLAUDE.md 文件，避免文件過時造成誤判），供
// validateForm() 提示「此廠牌不支援，欄位資料在產生時會被忽略」。DHCP 拆成
// server/relay 兩個獨立旗標，因同一廠牌兩者支援度可能不同（例如 Arista 只支援
// relay、Dell OS10 只支援 server）
// 廠牌硬體/韌體「真的不支援」（有官方文件明確佐證產品層級不具備此能力）：整張功能卡片
// 直接隱藏，不讓使用者填根本用不到的欄位。與下方 VENDOR_UNSUPPORTED（僅是本工具尚未查證
// 語法或本輪未排入範圍，裝置實際可能支援）語意不同，不可混用同一份清單（2026-07-30 拆分）。
const VENDOR_INCAPABLE={
  // ArubaOS-Switch/Provision 系列全域不支援 BGP，僅 Aruba CX 才有（CLAUDE.md 已查證）
  procurve:['bgp'],
  // Dell OS10 產品層級不支援 RIP，非解析器缺口（CLAUDE.md 已查證）
  'dell-os10':['rip'],
  // Netgear M4300 官方 CLI Command Reference Manual 版本更新記錄（202-11997-08，
  // 2022-04）明確寫「We removed references to BGP because this protocol is not
  // supported」，裝置真不支援
  netgear:['bgp'],
};
const VENDOR_UNSUPPORTED={
  comware:[], fortiswitch:[], aruba:[], cisco:[],
  // acl 已於 2026-07-27 修復 _parseACLJuniper() 並新增 renderJuniperACL() 接線，此清單原本
  // 殘留的 'acl' 已過時（真正支援），修正時一併移除
  juniper:['rip','vrrp','qos','security','stp'],
  'dell-os10':['dhcpRelay'],
  cisco_nxos:['rip','dhcpServer','dhcpRelay','qos'],
  arista:['dhcpServer'],
  brocade:[],
  alcatel:['rip','acl','qos','security','stp'],
  // qos/security/stp 已於 2026-07-19 新增支援（見 renderExtremeQoS/renderExtremeSecurity/
  // renderExtremeSTP）；acl 已於本輪查證修正 _parseACLExtreme() 語法後補上 renderExtremeACL
  // 並接線（見 now.md）；rip 本輪範圍之外維持不支援
  extreme:['rip'],
  // bgp 已移至 VENDOR_INCAPABLE（裝置真不支援）；dhcpRelay 已於 2026-07-27 修復
  // assembleProCurveConfig() 未引用 model.dhcp 的缺口，renderProCurveVLANs() 現已正確輸出
  // 逐 VLAN ip helper-address，此清單原本殘留的 'dhcpRelay' 已過時，修正時一併移除；
  // rip/vrrp/acl/qos/security/stp 仍是「查無真實語法或未驗證」而非裝置不支援，維持警告
  procurve:['rip','vrrp','dhcpServer','acl','qos','security','stp'],
  // rip/vrrp/acl/qos/security 已於 2026-07-19 新增支援（見 renderRouterOSRIP/
  // renderRouterOSVRRP/renderRouterOSACL/renderRouterOSQoS/renderRouterOSSecurity）；
  // dhcpRelay 本輪範圍外維持不支援
  routeros:['dhcpRelay'],
  // DHCP Server／DHCP Relay／ACL／QoS／802.1X-Port Security：官方 CLI Command Reference
  // Manual 查有指令存在（ip helper-address 為全域指令而非逐介面，與其餘廠牌慣例不同；
  // ACL/QoS 規則細部語法未深入查證），信心度不足以貿然渲染，本輪不輸出，維持警告而非
  // 隱藏（並非裝置真不支援，只是本工具尚未查證到足夠把握的語法）
  netgear:['dhcpServer','dhcpRelay','acl','qos','security'],
  // EdgeSwitch 的 VLAN Routing 邏輯介面 ID 由裝置動態配置，無法從設定檔靜態預測/還原
  // （架構限制，非查證不足，詳見 assembleEdgeSwitchConfig() 開頭註解），故所有依賴可定址
  // L3 介面的功能一律不支援；STP 是 MST instance 模型，與本工具共用扁平資料形狀不相容
  edgeswitch:['bgp','rip','vrrp','dhcpServer','dhcpRelay','acl','qos','security','stp','routes'],
  // OSPF：架構上不適用（非信心度不足）——SONiC 的 OSPF 是透過 FRR 原生設定檔管理，官方
  // Unified FRR Management Framework 設計文件明確列為未來擴充、config_db.json 查無表格
  // 定義，本工具「json ↔ 表單」的設計範圍天生不涵蓋（OSPF 卡片目前無對應 key，既有機制
  // 缺口，見 now.md）。ACL／STP（含 2026-08-08 續作的 STP_VLAN_INTF）已於 2026-08-08 對外
  // 查證官方 schema 後新增支援，見 assembleSONiCConfig() 對應區塊；QoS（SCHEDULER/
  // PORT_QOS_MAP/QUEUE，專屬 sonicQos 卡片，DSCP→TC 分類另一獨立功能不納入）／
  // Security 802.1X（PAC_PORT_CONFIG/HOSTAPD_GLOBAL_CONFIG，沿用共用 Security 卡片，
  // guest VLAN／MAC port-security 查無官方欄位不猜測）亦於同日對外查證後新增支援。
  // rip/vrrp/dhcpServer/dhcpRelay：SONiC 傳統模式僅單一 BGP instance、RIP v7 待查證，
  // 本輪範圍未涵蓋
  sonic:['rip','vrrp','dhcpServer','dhcpRelay'],
};
const VENDOR_FEATURE_LABEL={bgp:'BGP',rip:'RIP',vrrp:'VRRP',dhcpServer:'DHCP Server',dhcpRelay:'DHCP Relay',acl:'ACL',qos:'QoS',security:'Port Security/802.1X',stp:'STP',routes:'Static Routes'};

// Comware 專用：偵測 LACP member port 是否違反官方文件的加入條件（供 validateForm() 呼叫）。
// 條件依據：(1) class-two 屬性（VLAN/link-type）member 間需彼此一致，否則其中至少一個
// 無法達到 Selected 狀態；(2) 已啟用 802.1X／port-security 的 port 無法加入聚合組
// （查證來源：H3C 官方 Ethernet Link Aggregation Configuration 文件）
// 10 廠牌共用：LACP member port 的 VLAN/link-type 屬性一律以「該群組第一個有填寫的 member」
// 為準統一輸出到聚合介面上（Bridge-Aggregation／Port-channel／AggregatePort／lag／ae，見各廠牌
// render 函式），member 之間若彼此填的不一致，其餘 member 的設定會被無聲忽略——故 member 間
// 不一致時給非阻擋性提示，讓使用者知道實際生效的是哪一組值（函式名稱沿用 comware 前綴是歷史
// 命名，實際涵蓋全部 10 家有獨立聚合介面架構的廠牌）。802.1X／port-security 與 LACP 互斥
// 僅 Comware 官方文件明確查證過，故該子檢查維持 Comware 專屬，未擴及其他廠牌
// IPv4 點分十進位轉 32-bit 整數，供 CIDR/wildcard 網段比對用
function ipv4ToInt(ip){
  const p=(ip||'').split('.').map(Number);
  if(p.length!==4||p.some(n=>!Number.isInteger(n)||n<0||n>255))return null;
  return ((p[0]*256+p[1])*256+p[2])*256+p[3];
}

// Comware 專屬：OSPF 逐 area 填寫的 `network A.B.C.D wildcard-mask` 若沒有任何介面（含 SVI）
// 目前設定的 IP 落在該網段內，使用者實測確認真實 Comware 設備會直接報錯（比「完全沒填
// networks」的既有 val.ospf_no_network 檢查更進一步——那個檢查只抓「整個 area 空的」，
// 這裡抓「填了但網段兜不上任何一個實際介面」）
function comwareOspfNetworkWarnings(model){
  const warnings=[];
  if(!model||model.vendor!=='comware')return warnings;
  const ifaceIps=(model.interfaces||[])
    .map(i=>(i.ip||'').split('/')[0].split(' ')[0])
    .filter(ip=>isValidIPv4(ip));
  (model.ospf||[]).forEach((proc,pIdx)=>{
    (proc.areas||[]).forEach(area=>{
      (area.networks||[]).forEach(net=>{
        if(!net.network||!net.wildcard)return;
        const netInt=ipv4ToInt(net.network), wildInt=ipv4ToInt(net.wildcard);
        if(netInt===null||wildInt===null)return;
        const matched=ifaceIps.some(ip=>{
          const ipInt=ipv4ToInt(ip);
          return ipInt!==null&&(ipInt&~wildInt)===(netInt&~wildInt);
        });
        if(!matched){
          warnings.push(`⚠️ ${tr('val.comware_ospf_network_no_match').replace('{n}',pIdx+1).replace('{network}',net.network).replace('{wildcard}',net.wildcard)}`);
        }
      });
    });
  });
  return warnings;
}

const LACP_AGGREGATE_VENDORS=new Set(['comware','juniper','aruba','cisco','cisco_nxos','dell-os10','arista','ruijie','netgear','edgeswitch']);
function comwareLacpAttrWarnings(model){
  const warnings=[];
  if(!model||!LACP_AGGREGATE_VENDORS.has(model.vendor))return warnings;
  const ifaceByName={};
  (model.interfaces||[]).forEach(i=>{ifaceByName[i.name]=i;});
  (model.lacp||[]).forEach(l=>{
    const members=(l.members||[]).map(m=>ifaceByName[m]).filter(Boolean);
    if(members.length>1){
      const sig=i=>JSON.stringify([i.mode||'',i.trunkVlans||'',i.nativeVlan||'',i.accessVlan||'',i.hybrid||{}]);
      const first=sig(members[0]);
      if(members.some(m=>sig(m)!==first)){
        warnings.push(`⚠️ ${tr('val.comware_lacp_attr_mismatch').replace('{id}',l.id)}`);
      }
    }
    if(model.vendor==='comware'){
      members.forEach(m=>{
        const sec=(model.security||[]).find(s=>s.port===m.name);
        if(sec&&(sec.dot1x||sec.portSec)){
          warnings.push(`⚠️ ${tr('val.comware_lacp_security_conflict').replace('{port}',m.name).replace('{id}',l.id)}`);
        }
      });
    }
  });
  return warnings;
}
function validateForm(){
  const errors=[], warnings=[];
  const model=collectModel();

  // 清除上一輪標記，避免已修正的欄位仍殘留紅框
  document.querySelectorAll('.invalid').forEach(el=>el.classList.remove('invalid'));
  // 重新計算「已過濾 DOM 列」陣列，過濾條件務必與 collectModel() 對應區塊的 .filter(...) 完全一致，
  // 否則 model.xxx[i] 的索引會跟 DOM 第 i 個 <tr> 錯位（空欄位列在 collectModel() 已被濾掉）
  const vlanRows=rowsOf('#vlan-body tr').filter(tr=>val(tr,'v-id'));
  const ifaceRows=rowsOf('#iface-body tr').filter(tr=>val(tr,'i-name'));
  const peerRows=rowsOf('#bgp-peer-body tr').filter(tr=>val(tr,'p-ip'));
  const routeRows=rowsOf('#route-body tr').filter(tr=>val(tr,'rt-dst')&&val(tr,'rt-gw'));
  const lacpRows=rowsOf('#lacp-body tr').filter(tr=>val(tr,'lg-id'));
  const vrrpRows=rowsOf('#vrrp-body tr').filter(tr=>val(tr,'vr-vlan')&&val(tr,'vr-id')&&val(tr,'vr-vip'));
  const aclRuleRowsDom=rowsOf('#acl-rule-body tr').filter(tr=>val(tr,'ar-name'));

  // 1. 基本驗證：主機名
  if(!model.sysname||!model.sysname.trim()){
    errors.push('❌ '+tr('val.required').replace('{item}',tr('lbl.hostname')));
    markInvalid(document.getElementById('hostname'));
  }else if(!/^[a-zA-Z0-9\-_]{1,32}$/.test(model.sysname)){
    errors.push('⚠️ '+tr('val.hostname_format'));
    markInvalid(document.getElementById('hostname'));
  }

  // 2. VLAN 驗證
  const vlanIds=new Set();
  model.vlans.forEach((v,i)=>{
    if(!v.id||!/^\d+$/.test(v.id)||parseInt(v.id)<1||parseInt(v.id)>4094){
      errors.push(`⚠️ VLAN ${i+1}：${tr('val.invalid').replace('{item}','ID')} (1-4094)`);
      markInvalid(vlanRows[i]?.querySelector('.v-id'));
    }else if(vlanIds.has(v.id)){
      errors.push(`❌ ${tr('val.dup').replace('{item}','VLAN ID '+v.id)}`);
      markInvalid(vlanRows[i]?.querySelector('.v-id'));
    }else{
      vlanIds.add(v.id);
    }
  });

  // 3. Interface 驗證
  const ifNames=new Set();
  model.interfaces.forEach((iface,i)=>{
    if(!iface.name){
      errors.push(`⚠️ Interface ${i+1}：${tr('val.required').replace('{item}',tr('val.field_name'))}`);
      markInvalid(ifaceRows[i]?.querySelector('.i-name'));
    }else if(ifNames.has(iface.name)){
      errors.push(`❌ ${tr('val.dup').replace('{item}','Interface '+tr('val.field_name')+'「'+iface.name+'」')}`);
      markInvalid(ifaceRows[i]?.querySelector('.i-name'));
    }else{
      ifNames.add(iface.name);
    }

    // native VLAN 檢查
    if(iface.mode==='trunk'&&iface.nativeVlan){
      if(!/^\d+$/.test(iface.nativeVlan)){
        errors.push(`⚠️ Interface ${iface.name}：${tr('val.format_invalid').replace('{item}','Native VLAN')}`);
        markInvalid(ifaceRows[i]?.querySelector('.i-native-vlan'));
      }else if(!vlanIds.has(iface.nativeVlan)&&model.vlans.length>0){
        warnings.push(`⚠️ ${tr('val.native_vlan_not_in_list').replace('{name}',iface.name).replace('{vlan}',iface.nativeVlan)}`);
      }
    }

    // Hybrid 港口檢查（僅 Comware／Ruijie 支援）
    if(iface.mode==='hybrid'&&model.vendor!=='comware'&&model.vendor!=='ruijie'){
      errors.push(`❌ ${tr('val.vendor_no_hybrid').replace('{vendor}',model.vendor).replace('{name}',iface.name)}`);
      markInvalid(ifaceRows[i]?.querySelector('.i-mode'));
    }
  });

  // 4. OSPF 驗證
  if(model.ospf.length>0){
    model.ospf.forEach((ospf,idx)=>{
      if(!isValidIPv4(ospf.routerId)){
        errors.push(`⚠️ OSPF ${idx+1}：${tr('val.format_invalid').replace('{item}','Router ID')}`);
        markInvalid(document.getElementById('ospf-rid'));
      }
      if(ospf.areas.length>0&&ospf.areas.every(a=>!a.networks||a.networks.length===0)){
        warnings.push(`⚠️ ${tr('val.ospf_no_network').replace('{n}',idx+1)}`);
      }
    });
  }
  // Comware 專屬：OSPF network/wildcard 若沒有任何已設定 IP 的介面落在該網段內，
  // 使用者實測確認真實設備會直接報錯（非僅無法通告路由的軟性後果），故獨立於上面
  // 「完全沒填 networks」的檢查之外，額外檢查「填了但網段對不上任何介面」的情況
  comwareOspfNetworkWarnings(model).forEach(w=>warnings.push(w));

  // 5. BGP 驗證
  if(model.bgp.length>0){
    model.bgp.forEach((bgp,idx)=>{
      if(!bgp.asn||!/^\d+$/.test(bgp.asn)||parseInt(bgp.asn)<1||parseInt(bgp.asn)>4294967295){
        errors.push(`⚠️ BGP ${idx+1}：${tr('val.invalid').replace('{item}',tr('val.field_as'))} (1-4294967295)`);
        markInvalid(document.getElementById('bgp-asn'));
      }
      // SONiC 的 BGP_NEIGHBOR 表無 router-id 對應欄位（傳統模式下這是 FRR frr.conf/vtysh
      // 範疇，不在 config_db.json 內），routerId 天生空值非缺漏，不可比照其餘廠牌強制要求
      if(model.vendor!=='sonic'&&!isValidIPv4(bgp.routerId)){
        errors.push(`⚠️ BGP ${idx+1}：${tr('val.format_invalid').replace('{item}','Router ID')}`);
        markInvalid(document.getElementById('bgp-rid'));
      }
      const peerIps=new Set();
      bgp.peers.forEach((p,pi)=>{
        if(!isValidIPv4(p.ip)){
          errors.push(`⚠️ BGP ${idx+1} Peer ${pi+1}：${tr('val.format_invalid').replace('{item}','IP')}`);
          markInvalid(peerRows[pi]?.querySelector('.p-ip'));
        }else if(peerIps.has(p.ip)){
          errors.push(`❌ BGP ${idx+1}：${tr('val.dup').replace('{item}','Peer IP '+p.ip)}`);
          markInvalid(peerRows[pi]?.querySelector('.p-ip'));
        }else{
          peerIps.add(p.ip);
        }
        if(!p.as||!/^\d+$/.test(p.as)){
          errors.push(`⚠️ BGP ${idx+1} Peer ${pi+1}：${tr('val.invalid').replace('{item}',tr('val.field_as'))}`);
          markInvalid(peerRows[pi]?.querySelector('.p-as'));
        }
      });
    });
  }

  // 6. 靜態路由驗證
  model.routes.forEach((r,i)=>{
    if(!isValidCIDR(r.dst)){
      errors.push(`⚠️ ${tr('val.static_route')} ${i+1}：${tr('val.format_invalid').replace('{item}','Destination CIDR')} (${tr('val.example').replace('{example}','10.0.0.0/24')})`);
      markInvalid(routeRows[i]?.querySelector('.rt-dst'));
    }
    if(!isValidIPv4(r.gw)){
      errors.push(`⚠️ ${tr('val.static_route')} ${i+1}：${tr('val.format_invalid').replace('{item}','Gateway IP')}`);
      markInvalid(routeRows[i]?.querySelector('.rt-gw'));
    }
  });

  // 7. LACP 驗證
  const lacpNames=new Set();
  model.lacp.forEach((lag,i)=>{
    if(!lag.id){
      errors.push(`⚠️ LACP ${i+1}：${tr('val.required').replace('{item}',tr('val.field_lagid'))}`);
      markInvalid(lacpRows[i]?.querySelector('.lg-id'));
    }else if(lacpNames.has(lag.id)){
      errors.push(`❌ ${tr('val.dup').replace('{item}','LACP ID「'+lag.id+'」')}`);
      markInvalid(lacpRows[i]?.querySelector('.lg-id'));
    }else{
      lacpNames.add(lag.id);
    }
  });
  // Comware：member port 屬性不一致／已啟用安全性功能會導致實機無法加入聚合組，
  // 非阻擋性提示（見 comwareLacpAttrWarnings() 說明）
  comwareLacpAttrWarnings(model).forEach(w=>warnings.push(w));

  // 8. VRRP 驗證
  model.vrrp.forEach((v,i)=>{
    if(!v.vrid||!/^\d+$/.test(v.vrid)||parseInt(v.vrid)<1||parseInt(v.vrid)>255){
      errors.push(`⚠️ VRRP ${i+1}：${tr('val.invalid').replace('{item}','VRID')} (1-255)`);
      markInvalid(vrrpRows[i]?.querySelector('.vr-id'));
    }
    if(!isValidIPv4(v.vip)){
      errors.push(`⚠️ VRRP ${i+1}：${tr('val.format_invalid').replace('{item}',tr('val.field_vip'))}`);
      markInvalid(vrrpRows[i]?.querySelector('.vr-vip'));
    }
    if(v.ip&&!isValidCIDR(v.ip)){
      errors.push(`⚠️ VRRP ${i+1}：${tr('val.format_invalid').replace('{item}','SVI IP')} (${tr('val.example').replace('{example}','192.168.10.1/24')})`);
      markInvalid(vrrpRows[i]?.querySelector('.vr-ip'));
    }
    if(!v.priority||!/^\d+$/.test(v.priority)||parseInt(v.priority)<1||parseInt(v.priority)>254){
      errors.push(`⚠️ VRRP ${i+1}：${tr('val.invalid').replace('{item}',tr('val.field_priority'))} (1-254)`);
      markInvalid(vrrpRows[i]?.querySelector('.vr-priority'));
    }
  });

  // 9. ACL 驗證：src/dst 語意上可為 any／host X.X.X.X／IP+wildcard mask／CIDR，
  // 格式較自由（render 函式直接原文輸出，不做轉換），故僅在明顯不是上述任一種
  // 形式時給警告，不當硬性錯誤擋下產生
  const isPlausibleAclAddr=s=>{
    if(!s||s==='any')return true;
    if(/^host\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s))return isValidIPv4(s.replace(/^host\s+/,''));
    if(isValidIPv4(s)||isValidCIDR(s))return true;
    const parts=s.split(/\s+/);
    if(parts.length===2)return isValidIPv4(parts[0])&&isValidIPv4(parts[1]);
    return false;
  };
  model.acl.forEach((a,ai)=>{
    const aRows=aclRuleRowsDom.filter(tr=>val(tr,'ar-name')===a.name);
    (a.rules||[]).forEach((r,ri)=>{
      if(!isPlausibleAclAddr(r.src)){
        warnings.push(`⚠️ ${tr('val.acl_src_suspect').replace('{name}',a.name||ai+1).replace('{n}',ri+1).replace('{value}',r.src)}`);
        markInvalid(aRows[ri]?.querySelector('.ar-src'));
      }
      if(a.type!=='standard'&&!isPlausibleAclAddr(r.dst)){
        warnings.push(`⚠️ ${tr('val.acl_dst_suspect').replace('{name}',a.name||ai+1).replace('{n}',ri+1).replace('{value}',r.dst)}`);
        markInvalid(aRows[ri]?.querySelector('.ar-dst'));
      }
    });
  });

  // 10. DHCP 驗證
  model.dhcp.forEach((d,i)=>{
    if(d.type==='server'){
      if(d.network&&!isValidCIDR(d.network)){
        errors.push(`⚠️ DHCP Pool「${d.name||i+1}」：${tr('val.format_invalid').replace('{item}','Network CIDR')} (${tr('val.example').replace('{example}','10.0.0.0/24')})`);
      }
      if(d.gateway&&!isValidIPv4(d.gateway)){
        errors.push(`⚠️ DHCP Pool「${d.name||i+1}」：${tr('val.format_invalid').replace('{item}','Gateway IP')}`);
      }
    }else if(d.type==='relay'&&d.relayServer&&!isValidIPv4(d.relayServer)){
      errors.push(`⚠️ DHCP Relay ${i+1}：${tr('val.format_invalid').replace('{item}','Server IP')}`);
    }
  });

  // 11. 廠牌不支援的功能提示：資料仍會被送進 assemble 函式，但該廠牌的 render 邏輯
  // 不會輸出對應區塊（見 VENDOR_UNSUPPORTED），此前完全靜默不提示，使用者填了資料
  // 按產生卻發現整段消失、不知道發生什麼事。改為非阻擋性提示（放 warnings 不放
  // errors），維持現況「仍可正常產生」的行為，只是從「靜默丟棄」改成「明確告知」
  const unsupported=VENDOR_UNSUPPORTED[model.vendor]||[];
  if(unsupported.length){
    const filled={
      bgp:model.bgp.length>0, rip:model.rip.length>0, vrrp:model.vrrp.length>0,
      dhcpServer:model.dhcp.some(d=>d.type==='server'), dhcpRelay:model.dhcp.some(d=>d.type==='relay'),
      acl:model.acl.length>0, qos:model.qos.length>0, security:model.security.length>0,
      stp:!!(model.stp.mode||model.stp.instances.length||model.stp.ports.length||model.stp.rootMode||model.stp.timers.hello||model.stp.timers.forwardDelay||model.stp.timers.maxAge),
      routes:model.routes.length>0,
    };
    unsupported.forEach(key=>{
      if(filled[key])warnings.push(`💡 ${tr('val.vendor_unsupported_feature').replace('{vendor}',model.vendor).replace('{feature}',VENDOR_FEATURE_LABEL[key])}`);
    });
  }

  // 12. ProCurve OSPF Area/Network：已於 2026-07-17 對外查證 arubanetworking.hpe.com
  // 官方文件確認 VLAN context 內 `ip ospf area <id>` 語法並實作（renderProCurveVLANs()
  // 已支援逐 VLAN 指派），移除此警告

  // 13. BGP Networks：Brocade/Alcatel/NX-OS/RouterOS 已於 2026-07-17、Extreme 已於
  // 2026-07-16 對外查證官方文件確認語法並全數實作，清單保留空陣列供未來若有新廠牌
  // 待查證時使用，不移除整段判斷式結構
  const BGP_NETWORKS_IGNORED_VENDORS=[];
  if(BGP_NETWORKS_IGNORED_VENDORS.includes(model.vendor)&&model.bgp[0]?.networks?.length>0){
    const vendorLabel=document.querySelector('#vendor option[value="'+model.vendor+'"]')?.textContent||model.vendor;
    warnings.push(`💡 ${tr('val.bgp_networks_ignored').replace('{vendor}',vendorLabel)}`);
  }

  // 14. Extreme DHCP Interface 拼字檢查：renderExtremeDHCPServer/renderExtremeDHCPRelay
  // 直接採用使用者輸入的字串當 VLAN 名稱，不會跟 model.vlans 比對是否存在，打錯字在
  // 真機吃不進去卻毫無提示，故此處僅作提醒不阻擋產生
  if(model.vendor==='extreme'){
    const vlanNames=new Set(model.vlans.map(v=>v.name).filter(Boolean));
    model.dhcp.forEach(d=>{
      if(d.interface&&!vlanNames.has(d.interface)){
        warnings.push(`💡 ${tr('val.dhcp_iface_mismatch').replace('{iface}',d.interface)}`);
      }
    });
  }

  // 15. 埠位與所選機型交叉驗證：DEVICE_MODELS 未必窮舉真實裝置全部模組/擴充卡，
  // 故僅警告不擋（沿用第 14 項 Extreme DHCP 拼字檢查的相同「警告不擋」慣例）
  const modelPortSet=getModelPortSet(model.vendor,document.getElementById('device-model')?.value);
  if(modelPortSet){
    const modelLabel=document.querySelector('#device-model option:checked')?.textContent||document.getElementById('device-model').value;
    model.interfaces.forEach((iface,i)=>{
      if(iface.name&&!isKnownModelPort(iface.name,modelPortSet)){
        warnings.push(`💡 Interface：${tr('val.portNotInModel').replace('{port}',iface.name).replace('{model}',modelLabel)}`);
        markInvalid(ifaceRows[i]?.querySelector('.i-name'));
      }
    });
    model.lacp.forEach((lag,i)=>{
      (lag.members||[]).forEach(member=>{
        if(!isKnownModelPort(member,modelPortSet)){
          warnings.push(`💡 LACP ${lag.id||i+1}：${tr('val.portNotInModel').replace('{port}',member).replace('{model}',modelLabel)}`);
          markInvalid(lacpRows[i]?.querySelector('.lg-members'));
        }
      });
    });
    model.breakouts.forEach(b=>{
      if(b.parentPort&&!modelPortSet.has(b.parentPort)){
        warnings.push(`💡 Breakout：${tr('val.portNotInModel').replace('{port}',b.parentPort).replace('{model}',modelLabel)}`);
        markInvalid(document.getElementById('breakout-parent-name'));
      }
    });
  }

  return{errors,warnings,valid:errors.length===0,model};
}

function showValidationResults(results,fromImport=false){
  const panel=document.createElement('div');
  panel.className='validation-panel show';
  let html=`<h3 style="display:flex;justify-content:space-between;align-items:center;gap:8px"><span>${fromImport?'📥 '+tr('val.importResultTitle'):'📋 '+tr('val.generateCheckTitle')}</span><button class="rm-btn" style="flex-shrink:0" onclick="this.closest('.validation-panel').remove()">✕</button></h3>`;

  if(results.valid){
    html+=`<div class="validation-item success"><div class="msg">✅ ${tr('val.allPassed')}</div></div>`;
  }else{
    html+=`<div class="validation-item error"><div class="msg">⚠️ ${tr('val.errorsFound').replace('{n}',results.errors.length)}</div></div>`;
  }

  results.errors.forEach(err=>{
    html+=`<div class="validation-item error"><div class="msg">${err}</div></div>`;
  });

  if(results.warnings.length>0){
    html+=`<div class="validation-item warning"><div class="msg">💡 ${tr('val.tipsCount').replace('{n}',results.warnings.length)}</div></div>`;
    results.warnings.forEach(warn=>{
      html+=`<div class="validation-item warning"><div class="msg" style="font-size:10px">${warn}</div></div>`;
    });
  }

  panel.innerHTML=html;
  const old=document.querySelector('.validation-panel');
  if(old)old.remove();
  document.body.appendChild(panel);
}

function generate(fromImport=false){
  // 驗證表單
  const validation=validateForm();
  showValidationResults(validation,fromImport);
  if(!validation.valid)return;

  const model=validation.model;
  let cfg;
  if(model.vendor==='fortiswitch')cfg=assembleFortiSwitchConfig(model);
  else if(model.vendor==='aruba')cfg=assembleArubaConfig(model);
  else if(model.vendor==='cisco')cfg=assembleCiscoConfig(model);
  else if(model.vendor==='cisco_nxos')cfg=assembleNXOSConfig(model);
  else if(model.vendor==='juniper')cfg=assembleJuniperConfig(model);
  else if(model.vendor==='dell-os10')cfg=assembleDellOS10Config(model);
  else if(model.vendor==='arista')cfg=assembleAristaConfig(model);
  else if(model.vendor==='brocade')cfg=assembleBrocadeConfig(model);
  else if(model.vendor==='alcatel')cfg=assembleAlcatelConfig(model);
  else if(model.vendor==='extreme')cfg=assembleExtremeConfig(model);
  else if(model.vendor==='procurve')cfg=assembleProCurveConfig(model);
  else if(model.vendor==='routeros')cfg=assembleRouterOSConfig(model);
  else if(model.vendor==='ruijie')cfg=assembleRuijieConfig(model);
  else if(model.vendor==='netgear')cfg=assembleNetgearConfig(model);
  else if(model.vendor==='edgeswitch')cfg=assembleEdgeSwitchConfig(model);
  else if(model.vendor==='sonic')cfg=assembleSONiCConfig(model);
  else cfg=assembleComwareConfig(model);
  document.getElementById('output').value=cfg;
  checkGeneratorEggs(model.sysname);
}

// ── 彩蛋：主機名稱關鍵字 + 深夜/計時提醒（借鑑自 switch_analyzer checkSwitchEggs）───
function checkGeneratorEggs(hostname){
  const h=(hostname||'').toLowerCase();
  const SPECIAL_HN={
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
  for(const [k,v] of Object.entries(SPECIAL_HN)){
    if(h.includes(k)){setTimeout(()=>showEggToast(v),1200);break;}
  }
  const hr=new Date().getHours();
  if(hr>=0&&hr<5)setTimeout(()=>showEggToast(tr('egg.late_night')),2000);
  clearTimeout(window._workTimer30);clearTimeout(window._workTimer60);
  window._workTimer30=setTimeout(()=>showEggToast(tr('egg.work_30min'),5000),1800000);
  window._workTimer60=setTimeout(()=>showEggToast(tr('egg.work_60min'),5000),3600000);
}

// ══════════════════════════════════════════════════════════════════
// 匯入既有設定檔：動態載入 switch_analyzer 的 parser 邏輯（同目錄下的
// switch-config-parser.html），解析貼上的設定檔文字並帶入表單。
// 兩種載入路徑：(1) fetch 同目錄檔案（伺服器情境）(2) 使用者上傳 parser 檔案
// （file:// 直接開啟時 fetch 會被 CORS 擋下，此為備援）。
// 注意：只抽取 "STATE" 標記之前的純函式區段（detectVendor/parseComware/parseCisco/
// parseAruba/parseFortiSwitch/parseLACP），該標記之後的程式碼會操作 switch_analyzer
// 自己頁面的 DOM 元素，在本工具頁面執行會因找不到對應元素而出錯，故不延伸擷取範圍。
// 這也代表 VRRP（parseVRRP 定義在 STATE 之後）無法透過匯入功能自動帶入，需手動填寫。
// ══════════════════════════════════════════════════════════════════

// 讓使用者直接上傳「自己的交換器設定檔」到 textarea（跟下面 import-parser-file
// 這個給解析引擎本體備援用的檔案輸入是兩回事，容易混淆，故分開兩個欄位）
async function handleConfigFileUpload(e){
  const f=e.target.files[0];
  if(!f){
    document.getElementById('import-config-file-name').textContent=tr('btn.noFileSelected');
    return;
  }
  document.getElementById('import-config-file-name').textContent=f.name;
  document.getElementById('import-text').value=await f.text();
}

function handleParserFileUpload(e){
  const f=e.target.files[0];
  if(!f){
    document.getElementById('import-parser-file-name').textContent=tr('btn.noFileSelected');
    return;
  }
  document.getElementById('import-parser-file-name').textContent=f.name;
  const reader=new FileReader();
  reader.onload=evt=>{window._parserHTML=evt.target.result;};
  reader.readAsText(f);
}

// ══════════════════════════════════════════════════════════════════
// BasicParser：內建基礎解析（fallback 第三層）。當 loadParserFunctions() 的
// fetch + 手動上傳兩層都失敗時使用。只涵蓋 VLAN 與 Interface（access/trunk），
// 不含 hybrid/LACP/VRRP/OSPF/BGP/RIP/靜態路由——這些留給完整版 switch_analyzer。
// 語法對照本檔案自己的 renderXXXVLAN/renderXXXInterface（而非抄 switch_analyzer
// 原始碼），天生跟本工具輸出格式一致，且 VLAN/access/trunk 是最穩定多年沒變過的
// 基礎語法，不太需要跟著 switch_analyzer 的進階功能 bug 修正走。
// ══════════════════════════════════════════════════════════════════
function basicDetectVendor(cfg){
  if(/^\s*sysname\s+|port link-type|ip route-static/m.test(cfg))return'comware';
  if(/vlan trunk allowed|vlan trunk native|vlan access\s+\d/m.test(cfg))return'aruba';
  if(/^config system global/m.test(cfg)||/^config switch physical-port/m.test(cfg)||/^config switch interface/m.test(cfg))return'fortiswitch';
  if(/^hostname\s+|switchport mode|^vlan\s+\d+\s*\n\s*name/m.test(cfg))return'cisco';
  return'unknown';
}

function basicParseVLANs(cfg,vendor){
  const vlans=[];
  if(vendor==='fortiswitch'){
    const block=(cfg.match(/^config switch vlan\n([\s\S]*?)^end/m)||[])[1]||'';
    const re=/edit\s+(\d+)\n([\s\S]*?)(?=^\s*next\b)/gm;let m;
    while((m=re.exec(block))!==null){
      const name=(m[2].match(/set name\s+"?([^"\n]+)"?/)||[])[1]||'';
      vlans.push({id:m[1],name});
    }
    return vlans;
  }
  // Comware/Cisco/Aruba：`vlan N` 起始行 + 可選的 `name X`（Aruba 4 空格縮排，其餘 1 空格）
  const re=/^vlan\s+(\d+)\s*\n(?:\s*name\s+(\S+))?/gm;let m;
  while((m=re.exec(cfg))!==null)vlans.push({id:m[1],name:m[2]||''});
  return vlans;
}

function basicParseInterfaces(cfg,vendor){
  const ifaces=[];
  if(vendor==='fortiswitch'){
    const block=(cfg.match(/^config switch interface\n([\s\S]*?)^end/m)||[])[1]||'';
    const re=/edit\s+"?([^"\n]+)"?\n([\s\S]*?)(?=^\s*next\b)/gm;let m;
    while((m=re.exec(block))!==null){
      const name=m[1].trim(),body=m[2];
      const allowed=(body.match(/set allowed-vlans\s+([^\n]+)/)||[])[1]?.trim()||'';
      const untagged=(body.match(/set untagged-vlans\s+([^\n]+)/)||[])[1]?.trim()||'';
      const nativeVlan=(body.match(/set native-vlan\s+(\d+)/)||[])[1]||'';
      let mode='',vlansVal='';
      if(allowed){mode='trunk';vlansVal=allowed;}
      else if(untagged){mode='access';vlansVal=untagged;}
      ifaces.push({name,mode,vlans:vlansVal,nativeVlan,desc:'',shutdown:false,hybrid:null});
    }
    return ifaces;
  }
  const blocks=cfg.split(/^interface\s+/m).slice(1);
  for(const blk of blocks){
    const lines=blk.split('\n');
    const name=lines[0].trim();
    const body=lines.slice(1).join('\n');
    const desc=(body.match(/^\s*description\s+(.+)/m)||[])[1]?.trim()||'';
    const shutdown=/^\s*shutdown\s*$/m.test(body)&&!/no shutdown/.test(body)&&!/undo shutdown/.test(body);
    let mode='',vlansVal='',nativeVlan='';
    if(vendor==='comware'){
      if(/port link-type trunk/.test(body)){
        mode='trunk';
        // Comware 實機常把預設 vlan 1 獨立寫一行、其餘 VLAN 另外寫一行或多行，
        // 需用 global regex 收集所有 "port trunk permit vlan" 行再合併（同一類 bug
        // 已在 switch_analyzer 的 parseInterfaces 修正過，見 now.md 2026-07-03 17:56）
        const permitVlans=[];let pm;
        const permitRe=/port trunk permit vlan\s+([^\n]+)/g;
        while((pm=permitRe.exec(body))!==null)permitVlans.push(pm[1].trim());
        vlansVal=permitVlans.join(' ');
        // 2026-07-22 對外查證官方 H3C 文件後修正：`port trunk native-vlan` 不存在，
        // 真實關鍵字是 `port trunk pvid vlan`
        nativeVlan=(body.match(/port trunk pvid vlan\s+(\d+)/)||[])[1]||'';
      }else if(/port link-type access/.test(body)){
        mode='access';
        vlansVal=(body.match(/port access vlan\s+(\d+)/)||[])[1]||'';
      }
    }else if(vendor==='cisco'){
      if(/switchport mode\s+trunk/.test(body)){
        mode='trunk';
        vlansVal=(body.match(/switchport trunk allowed vlan\s+([^\n]+)/)||[])[1]?.trim()||'';
        nativeVlan=(body.match(/switchport trunk native vlan\s+(\d+)/)||[])[1]||'';
      }else if(/switchport mode\s+access/.test(body)){
        mode='access';
        vlansVal=(body.match(/switchport access vlan\s+(\d+)/)||[])[1]||'';
      }
    }else if(vendor==='aruba'){
      if(/vlan trunk/.test(body)){
        mode='trunk';
        vlansVal=(body.match(/vlan trunk allowed\s+([^\n]+)/)||[])[1]?.trim()||'';
        nativeVlan=(body.match(/vlan trunk native\s+(\d+)/)||[])[1]||'';
      }else if(/vlan access/.test(body)){
        mode='access';
        vlansVal=(body.match(/vlan access\s+(\d+)/)||[])[1]||'';
      }
    }
    ifaces.push({name,mode,vlans:vlansVal,nativeVlan,desc,shutdown,hybrid:null});
  }
  return ifaces;
}

const BasicParser={
  detectVendor:basicDetectVendor,
  parseComware(text){return{sys:{hostname:(text.match(/^sysname\s+(\S+)/m)||[])[1]||''},vlans:basicParseVLANs(text,'comware'),interfaces:basicParseInterfaces(text,'comware'),ospf:[],bgp:[],rip:[],routes:[]};},
  parseCisco(text){return{sys:{hostname:(text.match(/^hostname\s+(\S+)/m)||[])[1]||''},vlans:basicParseVLANs(text,'cisco'),interfaces:basicParseInterfaces(text,'cisco'),ospf:[],bgp:[],rip:[],routes:[]};},
  parseAruba(text){return{sys:{hostname:(text.match(/^hostname\s+(\S+)/m)||[])[1]||''},vlans:basicParseVLANs(text,'aruba'),interfaces:basicParseInterfaces(text,'aruba'),ospf:[],bgp:[],rip:[],routes:[]};},
  parseFortiSwitch(text){return{sys:{hostname:''},vlans:basicParseVLANs(text,'fortiswitch'),interfaces:basicParseInterfaces(text,'fortiswitch'),ospf:[],bgp:[],rip:[],routes:[]};},
};

let _parserFnsCache=null;

async function loadParserFunctions(){
  if(_parserFnsCache)return _parserFnsCache;
  let src=null;
  // 注：移除了 fetch() 調用，改為完全離線模式
  // 用戶必須上傳 switch-config-parser.html 檔案
  const fileInput=document.getElementById('import-parser-file');
  if(fileInput.files&&fileInput.files[0])src=await fileInput.files[0].text();
  if(!src)throw new Error('NO_PARSER_SOURCE - 請上傳 switch-config-parser.html 檔案');
  const scriptMatch=src.match(/<script>([\s\S]*)<\/script>/);
  if(!scriptMatch)throw new Error('NO_SCRIPT_TAG');
  const script=scriptMatch[1];
  const stateIdx=script.indexOf('STATE');
  const pure=stateIdx>0?script.slice(0,stateIdx):script;
  // parseComware/parseCisco/parseAruba 內部都會呼叫 parseVRRP 與 parseVXLAN，但兩者定義在 STATE
  // 標記之後；不能直接延伸擷取範圍，因為 STATE 後緊接著會操作 switch_analyzer 自己頁面 DOM 的
  // 頂層程式碼（例如 logo-btn 的 addEventListener），在本頁面執行會因找不到對應元素而拋錯。
  // parseVRRP/parseVXLAN 本身都是純函式（無 DOM 依賴），故單獨抽出兩者（到下一個會操作 DOM 的
  // renderVRRP 之前為止）後以獨立函式附加，不牽動其餘範圍。
  const extraStart=script.indexOf('function parseVRRP');
  const extraEnd=script.indexOf('function renderVRRP');
  const extraFnText=(extraStart>0&&extraEnd>extraStart)?script.slice(extraStart,extraEnd):'function parseVRRP(){return [];}\nfunction parseVXLAN(){return {vtep:"",vnis:[],evpn:[],tunnelMode:""};}';
  const sandboxFn=new Function(pure+'\n'+extraFnText+'\nreturn { detectVendor:detectVendor, parseComware:parseComware, parseCisco:parseCisco, parseAruba:parseAruba, parseFortiSwitch:parseFortiSwitch, parseJuniper:parseJuniper, parseNXOS:parseNXOS, parseArista:parseArista, parseRuijie:parseRuijie, parseNetgear:parseNetgear, parseEdgeSwitch:parseEdgeSwitch, parseDellOS10:parseDellOS10, parseBrocade:parseBrocade, parseAlcatel:parseAlcatel, parseExtremeXOS:parseExtremeXOS, parseProCurve:parseProCurve, parseRouterOS:parseRouterOS, parseSONiC:parseSONiC, parseLACP:parseLACP, parseDHCP:parseDHCP, parseACL:parseACL, parseQoS:parseQoS, parseSecurity:parseSecurity, parseSTP:parseSTP, parseVRRP:parseVRRP };');
  _parserFnsCache=sandboxFn();
  return _parserFnsCache;
}

function showImportMsg(text,isError){
  const el=document.getElementById('import-msg');
  el.textContent=text;
  el.style.color=isError?'var(--red)':'var(--green)';
}

async function parseAndImport(){
  // 統一在此正規化 CRLF，避免匯入的 CRLF 設定檔在後續逐行正則悄悄比對失敗
  const text=document.getElementById('import-text').value.replace(/\r\n/g,'\n').trim();
  if(!text){showImportMsg(tr('msg.importEmpty'),true);return;}

  let fns=null;
  try{
    fns=await loadParserFunctions();
  }catch(e){ /* 兩層都失敗，改用內建基礎解析 BasicParser */ }
  const api=fns||BasicParser;

  const vendor=api.detectVendor(text);
  if(!vendor||!['comware','cisco','aruba','fortiswitch','juniper','nxos','arista','dell-os10','brocade','alcatel','extreme','procurve','routeros','ruijie','netgear','edgeswitch','sonic'].includes(vendor)){
    showImportMsg(tr('msg.importNoVendor'),true);
    return;
  }
  // switch_analyzer 的 detectVendor()/parseNXOS() 用 'nxos'，但本工具廠牌下拉與
  // assembleXxxConfig() 派送用的是 'cisco_nxos'，兩邊命名不同，需要單獨映射；
  // 其餘（含 arista）兩邊命名一致，不需映射
  const genVendor=vendor==='nxos'?'cisco_nxos':vendor;

  let parsed;
  if(vendor==='comware')parsed=api.parseComware(text);
  else if(vendor==='cisco')parsed=api.parseCisco(text);
  else if(vendor==='aruba')parsed=api.parseAruba(text);
  else if(vendor==='juniper')parsed=api.parseJuniper(text);
  else if(vendor==='fortiswitch')parsed=api.parseFortiSwitch(text);
  else if(vendor==='arista')parsed=api.parseArista(text);
  else if(vendor==='ruijie')parsed=api.parseRuijie(text);
  else if(vendor==='netgear')parsed=api.parseNetgear(text);
  else if(vendor==='edgeswitch')parsed=api.parseEdgeSwitch(text);
  else if(vendor==='dell-os10')parsed=api.parseDellOS10(text);
  else if(vendor==='brocade')parsed=api.parseBrocade(text);
  else if(vendor==='alcatel')parsed=api.parseAlcatel(text);
  else if(vendor==='extreme')parsed=api.parseExtremeXOS(text);
  else if(vendor==='procurve')parsed=api.parseProCurve(text);
  else if(vendor==='routeros')parsed=api.parseRouterOS(text);
  else if(vendor==='sonic')parsed=api.parseSONiC(text);
  else{
    parsed=api.parseNXOS(text);
    // parseNXOS() 的 interface 物件形狀跟其餘廠牌不同（vlan 為單數欄位、無 nativeVlan/hybrid），
    // 正規化成其餘廠牌慣用的 vlans 欄位，讓下方共用的 interface 回填邏輯可以直接沿用不需另開分支
    (parsed.interfaces||[]).forEach(i=>{ i.vlans=i.vlan||''; });
  }

  // 清空既有列（含 vrrp-body：匯入功能雖不映射 VRRP 資料，但仍須清掉畫面殘留的舊資料，
  // 避免使用者誤以為初始化 demo 列是這次匯入結果的一部分）
  ['vlan-body','iface-body','area-body','bgp-peer-body','route-body','lacp-body','vrrp-body','dhcp-pool-body','dhcp-relay-body','acl-rule-body','acl-apply-body','qos-body','security-body','stp-instance-body','stp-port-body','vxlan-vni-body','qos-dscp-body','extreme-qos-profile-body','extreme-qos-dscp-body','extreme-qos-port-body','routeros-acl-body','routeros-simple-queue-body','routeros-queue-tree-body','vsu-member-body','users-body','sonic-l3-body','sonic-qos-sched-body','sonic-qos-apply-body','sonic-stp-vlanintf-body'].forEach(id=>{
    document.getElementById(id).innerHTML='';
  });

  document.getElementById('vendor').value=genVendor;
  updateModeOptions();
  document.getElementById('hostname').value=parsed.sys?.hostname||'';

  (parsed.vlans||[]).forEach(v=>addVlanRow(v.id,v.name));

  (parsed.interfaces||[]).forEach(i=>{
    if(!['trunk','access','hybrid'].includes(i.mode))return; // SVI/loopback/routed 不在本工具 Interface 表單範圍內
    addIfaceRow(i.name,i.mode,inferSpeedFromName(i.name,vendor));
    const rows=rowsOf('#iface-body tr'); const row=rows[rows.length-1];
    row.querySelector('.i-desc').value=i.desc||'';
    if(i.mode==='trunk'){
      row.querySelector('.i-trunk-vlans').value=i.vlans||'';
      row.querySelector('.i-native-vlan').value=i.nativeVlan||'';
    }else if(i.mode==='access'){
      row.querySelector('.i-access-vlan').value=i.vlans||'';
    }else if(i.mode==='hybrid'&&i.hybrid){
      row.querySelector('.i-hy-untagged').value=(i.hybrid.untagged||[]).join(' ');
      row.querySelector('.i-hy-tagged').value=(i.hybrid.tagged||[]).join(' ');
      row.querySelector('.i-hy-pvid').value=i.hybrid.pvid||'';
    }
    row.querySelector('.i-shutdown').checked=!!i.shutdown;
  });

  // SONiC L3 介面 IP 回填（2026-08-08 新增，已知缺口修復）：parseSONiC() 早就把
  // VLAN_INTERFACE／INTERFACE／PORTCHANNEL_INTERFACE 的 IP 資料併入 parsed.interfaces
  // （type:'svi' 或 mode:'routed'），但上面那個迴圈只認 trunk/access/hybrid，這些條目
  // 被直接跳過、sonic-l3-body 永遠空白；SONiC 沒有通用 Interface 表單可承接（無 routed
  // 模式），改寫進專屬 sonicL3Interfaces 卡片
  if(vendor==='sonic'){
    (parsed.interfaces||[]).forEach(i=>{
      if(!i.ip)return;
      if(i.type==='svi'||i.mode==='routed'){
        addSonicL3Row(i.name,i.ip);
        // 次要IP（2026-08-23 陣列化）：parser 端 2026-08-17 已從「僅取第一筆」擴充為完整
        // 陣列 secondaryIps，這裡逐筆加同名列——sonicL3Interfaces 本來就是靠複合鍵
        // name+cidr 支援同名多列，不需要新增 UI 欄位
        (i.secondaryIps||[]).forEach(s=>addSonicL3Row(i.name,s));
      }
    });
  }

  // VRRP：parseVRRP() 只回傳介面名稱字串，不是 VLAN ID，需要比對同一次匯入已解析出的
  // parsed.interfaces 找到同名 SVI 取得 vlans/ip；找不到就退回用介面名稱抓數字當 VLAN ID
  // （比照下方 LACP 匯入的容錯寫法）
  // Brocade：通用 fns.parseVRRP() dispatcher 沒有 brocade 分支（VRRP-E 語法特殊，parseAny()
  // 刻意排除走通用 dispatcher），改用 parseBrocade() 聚合結果自帶的 parsed.vrrp（parseBrocadeVRRP
  // 產生，已含合併在 interface ve N 區塊內的資料），否則永遠回空陣列
  // Alcatel／Extreme XOS：通用 dispatcher 同樣沒有這兩個廠牌的分支，改用各自聚合結果自帶的
  // parsed.vrrp（parseAlcatelVRRP／parseExtremeXOSVRRP 產生）
  const vrrpBypass=vendor==='brocade'||vendor==='alcatel'||vendor==='extreme'||vendor==='procurve'||vendor==='routeros';
  const vrrpList=fns?(vrrpBypass?(parsed.vrrp||[]):fns.parseVRRP(text,vendor)):[]; // BasicParser 不含 VRRP
  (vrrpList||[]).forEach(v=>{
    const svi=(parsed.interfaces||[]).find(i=>i.name===v.interface);
    const vlanId=svi?.vlans||(v.interface.match(/\d+/)||[])[0]||'';
    const sviIp=svi?.ip?svi.ip.split('/')[0]:'';
    addVrrpRow(vlanId,sviIp,v.vrid,v.vip,v.priority,!!v.preempt,v.authMode,v.authKey,v.trackIf,v.trackReduced);
  });

  const o=(parsed.ospf||[])[0];
  document.getElementById('ospf-pid').value=o?.pid||'';
  // ProCurve 的 parseOSPF() 極簡版本欄位是 rid（非其餘廠牌慣用的 routerId），需個別 fallback
  document.getElementById('ospf-rid').value=o?.routerId||o?.rid||'';
  document.getElementById('ospf-redist').value=(o?.redistributes||[]).join(' ');
  (o?.areas||[]).forEach(a=>{
    const nets=(a.networks&&a.networks.length)?a.networks:[{network:'',wildcard:''}];
    nets.forEach(n=>addAreaRow(a.area,n.network,n.wildcard,a.type||'normal',a.noSummary));
  });

  const b=(parsed.bgp||[])[0];
  document.getElementById('bgp-asn').value=b?.asn||'';
  document.getElementById('bgp-rid').value=b?.routerId||'';
  document.getElementById('bgp-networks').value=(b?.networks||[]).join(' ');
  // peerGroups/timers 僅在使用者上傳過 switch-config-parser.html（走沙箱抽取的真實
  // parseBGP()）那條匯入路徑才有資料，內建 BasicParser 對 BGP 永遠回傳空陣列，此為既有限制
  document.getElementById('bgp-peer-group').value=(b?.peerGroups||[]).map(g=>g.name).join(' ');
  document.getElementById('bgp-timer-keepalive').value=b?.timers?.keepalive||'';
  document.getElementById('bgp-timer-hold').value=b?.timers?.holdtime||'';
  (b?.peers||[]).forEach(p=>addBgpPeerRow(p.ip,p.as,p.desc||''));

  const r=(parsed.rip||[])[0];
  if(vendor==='brocade'){
    // Brocade 官方語法無 pid/network 概念，router rip 區塊本身存在即代表啟用；
    // 共用表單的 Process ID 欄位借用作為「是否啟用」觸發旗標（沿用既有 collectModel()
    // 邏輯，非其真實語意），Networks 欄位比照 renderBrocadeRIPGlobal()／
    // brocadeRipEnabledPorts() 慣例改填要啟用 RIP 的介面清單；distance/timer/
    // learn-default/default-metric/redistribute 因共用表單無對應欄位，匯入後無法回填。
    // 2026-07-24 新增的 silent-interface/summary/default-cost 三欄位同理，Brocade 語意不同
    // （FastIron 無對應概念），不映射
    document.getElementById('rip-pid').value=r?'1':'';
    document.getElementById('rip-version').value='';
    document.getElementById('rip-networks').value=(r?.interfaces||[]).map(i=>i.name).join(' ');
    document.getElementById('rip-redist').value='';
    document.getElementById('rip-silent').value='';
    document.getElementById('rip-summary').checked=false;
    document.getElementById('rip-default-cost').value='';
  }else{
    document.getElementById('rip-pid').value=r?.pid||'';
    document.getElementById('rip-version').value=r?.version||'';
    document.getElementById('rip-networks').value=(r?.networks||[]).join(' ');
    document.getElementById('rip-redist').value=(r?.redistribute||[]).join(' ');
    document.getElementById('rip-silent').value=(r?.passive||[]).join(' ');
    document.getElementById('rip-summary').checked=!!r?.autoSummary;
    document.getElementById('rip-default-cost').value=r?.defaultMetric||'';
  }

  (parsed.routes||[]).forEach(rt=>addRouteRow(rt.dst,rt.gw,rt.metric));

  // VXLAN（2026-08-20 新增）：僅 Comware/Aruba CX/NX-OS 三家 switch_analyzer 的 parseVXLAN()
  // 會回傳非 null 資料，其餘廠牌固定 vxlan:null。三家 evpn[]↔vnis[] 的配對方式不同（見
  // switch-analyzer-core.js 的 parseVXLAN()）：comware 用 evpn.name（VSI 名稱，與
  // vnis[].name 同義）配對；aruba 的 evpn[] 只是偵測旗標（rd/rtImport/rtExport 恆空字串），
  // rd 早已直接存在 vnis[].rd，不需要、也無法用 evpn[] 回填；nxos 的 evpn.name 固定是合成
  // 字串 'L2VNI-'+vni，且 L2 VNI 的 vnis[].name 是空字串（只有 L3 VNI 才有值），必須用
  // vni 比對、不能用 name。vxlan-vni-body 已在上方清空清單內，vxlan-vtep 先前完全沒被
  // 匯入邏輯寫入過，一併補上避免舊匯入殘留值誤植為新結果
  if(parsed.vxlan&&(vendor==='comware'||vendor==='aruba'||vendor==='nxos')){
    document.getElementById('vxlan-vtep').value=parsed.vxlan.vtep||'';
    const vxEvpnList=parsed.vxlan.evpn||[];
    const matchVxEvpn=v=>{
      if(vendor==='comware')return vxEvpnList.find(e=>e.name===v.name);
      if(vendor==='nxos')return vxEvpnList.find(e=>e.name==='L2VNI-'+v.vni);
      return null;
    };
    (parsed.vxlan.vnis||[]).forEach(v=>{
      const e=matchVxEvpn(v);
      addVxlanVniRow(v.vni,v.vlan,v.name,(v.peers||[]).join(' '),
        v.rd||e?.rd||'',e?.rtImport||'',e?.rtExport||'',v.gw||'');
    });
  }

  // Juniper：通用的 fns.parseLACP() dispatcher 沒有 juniper 分支（只有 comware/cisco系/
  // aruba/fortiswitch），改用 parseJuniper() 聚合結果自帶的 parsed.lacp（parseJuniperLACP
  // 產生，members 是純字串陣列，跟其他廠牌 members 為 {name} 物件陣列的形狀不同，故下面
  // map 時兩種形狀都相容處理）
  // Brocade：通用 fns.parseLACP() dispatcher 同樣沒有 brocade 分支，比照 juniper 改用
  // parseBrocade() 聚合結果自帶的 parsed.lacp（parseBrocadeLACP 產生）
  // Alcatel／Extreme XOS：通用 dispatcher 同樣沒有這兩個廠牌的分支，比照 juniper/brocade 改用
  // 各自聚合結果自帶的 parsed.lacp（parseAlcatelLACP／parseExtremeXOSLACP 產生）
  const lacpBypass=vendor==='juniper'||vendor==='brocade'||vendor==='alcatel'||vendor==='extreme'||vendor==='procurve'||vendor==='routeros';
  const lacpList=fns?(lacpBypass?(parsed.lacp||[]):fns.parseLACP(text,vendor)):[]; // BasicParser 不含 LACP
  (lacpList||[]).forEach(l=>{
    const gid=(l.name.match(/\d+/)||[])[0]||'';
    const modeLower=(l.mode||'').toLowerCase();
    const mode=modeLower==='active'||modeLower==='lacp-active'?'active':modeLower==='passive'||modeLower==='lacp-passive'?'passive':'static';
    // ProCurve 的 parseTrunk() members 是原始逗號/連字號字串（如 "25-26"），非其餘廠牌慣用的
    // 陣列形狀，直接 .map() 會拋錯（TypeError: members.map is not a function）並中止整個匯入
    // 流程；統一先正規化成陣列再處理，陣列輸入行為完全不變
    const memberList=Array.isArray(l.members)?l.members:String(l.members||'').split(/[,\s]+/).filter(Boolean);
    addLacpRow(gid,mode,memberList.map(m=>typeof m==='string'?m:m.name).join(' '));
  });

  // DHCP：BasicParser 未涵蓋此欄位，只有完整版（fns）才映射；Brocade 通用 dispatcher
  // 同樣沒有 brocade 分支，改用 parsed.dhcp（parseBrocadeDHCP 產生）。Extreme XOS 通用
  // dispatcher 也沒有分支，改用 parsed.dhcp（parseExtremeXOSDHCP 產生）；但 Alcatel 通用
  // dispatcher **有**專屬分支（dhcp-server 風格），直接走通用呼叫即可，不需比照 Brocade/Extreme
  const dhcpBypass=vendor==='brocade'||vendor==='extreme'||vendor==='procurve'||vendor==='routeros';
  const dhcpList=fns?(dhcpBypass?(parsed.dhcp||[]):fns.parseDHCP(text,vendor)):[];
  (dhcpList||[]).forEach(d=>{
    if(d.type==='server')addDhcpPoolRow(d.name,d.network,d.gateway,Array.isArray(d.dns)?d.dns.join(' '):(d.dns||''),d.range,d.excluded,d.lease,d.interface);
    else if(d.type==='relay')addDhcpRelayRow(d.interface==='all'?'':(d.interface||''),d.relayServer);
  });

  // ACL：BasicParser 未涵蓋此欄位，只有完整版（fns）才映射。Cisco 的獨立 "remark" 行
  // 會被 parseACL 拆成 action==='remark' 的獨立 rule 物件（非附加在同一筆 permit/deny 上），
  // 若照樣新增一列，UI 的 Action 下拉（僅 permit/deny）會顯示空白、造成一筆看起來壞掉的列；
  // 改為合併進上一筆規則列的 Remark 欄位，貼近使用者原本填寫時的認知
  const aclList=fns?fns.parseACL(text,vendor):[];
  (aclList||[]).forEach(a=>{
    let lastRow=null;
    // Comware parser 回傳的是官方術語 'basic'/'advanced'，但 Type 下拉是全廠牌共用元件、
    // 只有 'extended'/'standard' 兩個 <option>；'basic' 塞進 select.value 會因找不到相符
    // option 而靜默失敗（維持在預設的 extended），造成匯入的 Comware basic ACL 被誤植為
    // advanced。這裡統一轉換成表單認得的字面值，其餘廠牌（本來就是 extended/standard）不受影響
    const formType=a.type==='basic'?'standard':a.type==='advanced'?'extended':(a.type||'extended');
    (a.rules||[]).forEach(r=>{
      if(r.action==='remark'){
        if(lastRow)lastRow.querySelector('.ar-remark').value=r.remark;
        return;
      }
      addAclRuleRow(a.name,formType,r.seq,r.action,r.protocol,r.src,r.dst,r.dstPort,r.remark);
      const rows=rowsOf('#acl-rule-body tr'); lastRow=rows[rows.length-1];
    });
    (a.appliedOn||[]).forEach(ap=>addAclApplyRow(a.name,ap.interface,ap.direction));
  });

  // RouterOS ACL：fns.parseACL(text,'routeros') 回傳的是專屬扁平規則陣列（chain-based
  // firewall filter，非上面共用迴圈假設的 {name,rules,appliedOn} 具名 ACL 形狀，上面的
  // 迴圈對這個陣列會直接因為 a.rules 是 undefined 而靜默跳過，不會出錯但也不會匯入），
  // 故另外用同一個 aclList 變數做專屬映射
  if(vendor==='routeros'){
    (aclList||[]).forEach(r=>addRouterOSAclRow(r.chain,r.action,r.protocol,r.srcAddress,r.dstAddress,r.dstPort,r.inInterface,r.comment));
  }

  // 本機帳號：ProCurve（既有）＋ 2026-08-19 新增 9 家（此處用 switch_analyzer 原生 vendor
  // 字串，NX-OS 是 'nxos' 非產生器下拉選單用的 'cisco_nxos'，其餘廠牌兩邊命名一致）＋
  // 2026-08-26 新增 Extreme（parseExtremeXOSUsers() 回傳 {name,role,...}，欄位與其餘廠牌
  // 相容可共用此陣列）。parsed.users 已是各廠牌 parseXxx() 既有回傳物件的一部分，不需額外
  // 抽取；密碼欄位因雜湊值無法從 hasPwd/pwdType/role 等中繼資料還原，匯入後留空待使用者自行補上
  if(['procurve','cisco','arista','ruijie','nxos','comware','dell-os10','brocade','aruba','juniper','extreme'].includes(vendor)){
    (parsed.users||[]).forEach(u=>addUsersRow(u.name,u.role,''));
  }
  // RouterOS：parseRouterOSUsers() 回傳形狀是 {username,group,privilege}，欄位名與其餘廠牌
  // 的 {name,role} 完全不同，若塞進上面共用陣列會因 u.name/u.role 皆為 undefined 而靜默產生
  // 空白列（比照同檔案 RouterOS ACL 既有「形狀不同另開專屬分支」慣例，見上方 aclList 處理）
  if(vendor==='routeros'){
    (parsed.users||[]).forEach(u=>addUsersRow(u.username,u.group,''));
  }

  // QoS：BasicParser 未涵蓋此欄位，只有完整版（fns）才映射；Comware 沒有 action/rate/burst
  // 欄位（parseQoS 對 Comware 只回傳 policy/cls/behavior），其餘欄位留空即可
  const qosList=fns?fns.parseQoS(text,vendor):[];
  (qosList||[]).forEach(q=>addQosRow(q.policy,q.cls,q.behavior||'',q.action==='-'?'police':(q.action||'police'),q.rate==='-'?'':(q.rate||''),q.burst==='-'?'':(q.burst||'')));

  // Port Security/802.1X：BasicParser 未涵蓋此欄位，只有完整版（fns）才映射
  const securityList=fns?fns.parseSecurity(text,vendor):[];
  (securityList||[]).forEach(s=>addSecurityRow(s.port,s.dot1x||'-',!!s.portSec,s.maxMac==='-'?'':s.maxMac,s.violation==='-'?'':s.violation,s.guestVlan==='-'?'':s.guestVlan));

  // STP：BasicParser 未涵蓋此欄位，只有完整版（fns）才映射
  const stpParsed=fns?fns.parseSTP(text,vendor):null;
  document.getElementById('stp-mode').value=stpParsed?.mode||'';
  document.getElementById('stp-rootmode').value=stpParsed?.rootMode||'';
  document.getElementById('stp-hello').value=stpParsed?.timers?.hello||'';
  document.getElementById('stp-forward').value=stpParsed?.timers?.forwardDelay||'';
  document.getElementById('stp-maxage').value=stpParsed?.timers?.maxAge||'';
  (stpParsed?.instances||[]).forEach(i=>addStpInstanceRow(i.id,i.priority));
  (stpParsed?.ports||[]).forEach(p=>addStpPortRow(p.port,!!p.portfast,!!p.bpduguard,!!p.guardRoot,p.cost||'',p.priority||''));
  // SONiC STP_VLAN_INTF（2026-08-08 新增）：_parseSTPSONiC() 額外掛在回傳物件的
  // sonicStpVlanIntf 欄位（其餘廠牌的 parseSTP() 回傳物件無此欄位，安全忽略）
  if(vendor==='sonic')(stpParsed?.sonicStpVlanIntf||[]).forEach(v=>addSonicStpVlanIntfRow(v.vlan,v.port,v.cost,v.priority));

  // Brocade/Ruckus ICX QoS：parseBrocade() 聚合結果自帶 parsed.qos（parseBrocadeQoS 產生，
  // 專屬 dscpMap/ports 形狀，非共用 policy-map QoS，故不透過 fns.parseQoS() 通用 dispatcher）
  if(vendor==='brocade'&&parsed.qos){
    (parsed.qos.dscpMap||[]).forEach(m=>addQosDscpRow(m.dscpValues,m.priority));
    const qosPortMap=new Map((parsed.qos.ports||[]).map(p=>[brocadePortName(p.port),p]));
    rowsOf('#iface-body tr').forEach(row=>{
      const qp=qosPortMap.get(brocadePortName(row.querySelector('.i-name').value));
      if(qp){
        row.querySelector('.i-qos-priority').value=qp.priority||'';
        row.querySelector('.i-trust-dscp').checked=!!qp.trustDscp;
      }
    });
  }

  // Extreme QoS：parseExtremeXOS() 聚合結果自帶 parsed.qos（parseExtremeQoS 產生，QP1-QP8
  // profile 專屬形狀，非共用 policy-map QoS，故不透過 fns.parseQoS() 通用 dispatcher），
  // 三個獨立列表各自映射回專屬 UI
  if(vendor==='extreme'&&parsed.qos){
    (parsed.qos.profiles||[]).forEach(p=>addExtremeQosProfileRow(p.name,p.minbw,p.maxbw));
    (parsed.qos.dscpMap||[]).forEach(m=>addExtremeQosDscpRow(m.codePoint,m.profile));
    (parsed.qos.ports||[]).forEach(p=>addExtremeQosPortRow(p.port,p.profile,p.diffservExam));
  }

  // MikroTik RouterOS QoS：parseRouterOS() 聚合結果自帶 parsed.qos（parseRouterOSQoS
  // 產生，Simple Queue/Queue Tree 專屬形狀，非共用 policy-map QoS，故不透過
  // fns.parseQoS() 通用 dispatcher）
  if(vendor==='routeros'&&parsed.qos){
    (parsed.qos.simpleQueues||[]).forEach(q=>addRouterOSSimpleQueueRow(q.name,q.target,q.maxLimitUp,q.maxLimitDown,q.limitAtUp,q.limitAtDown));
    (parsed.qos.queueTree||[]).forEach(q=>addRouterOSQueueTreeRow(q.name,q.parent,q.maxLimit));
  }

  // SONiC QoS：parseSONiC() 聚合結果自帶 parsed.qos（_parseQoSSONiC() 產生，SCHEDULER+
  // PORT_QOS_MAP/QUEUE 專屬形狀，非共用 policy-map QoS，故不透過 fns.parseQoS() 通用
  // dispatcher，比照 Brocade/Extreme/RouterOS 既有先例）
  if(vendor==='sonic'&&parsed.qos){
    (parsed.qos.schedulers||[]).forEach(s=>addSonicQosSchedRow(s.name,s.type,s.weight,s.meterType,s.cir,s.cbs,s.pir,s.pbs));
    (parsed.qos.apply||[]).forEach(a=>addSonicQosApplyRow(a.target,a.queue,a.scheduler));
  }

  generate(true);
  showImportMsg(tr(fns?'msg.importSuccess':'msg.importBasicFallback'),false);
}

function dlTxt(t,fn){const b=new Blob([t],{type:'text/plain;charset=utf-8;'});const url=URL.createObjectURL(b);const a=document.createElement('a');a.href=url;a.download=fn;a.click();URL.revokeObjectURL(url);}

function copyOutput(){
  const t=document.getElementById('output').value;
  if(!t)return;
  const b=document.getElementById('copy-btn');
  const orig=b.textContent;
  navigator.clipboard.writeText(t).then(()=>{
    b.textContent=tr('btn.copied');
    setTimeout(()=>{b.textContent=orig;},1500);
  }).catch(()=>{
    b.textContent=tr('btn.copyFailed');
    setTimeout(()=>{b.textContent=orig;},2000);
  });
}

// ── 設定對比功能 ──────────────────────────────────────────────────
function toggleDiffCard(){
  const card=document.getElementById('diff-card');
  card.style.display=card.style.display==='none'?'block':'none';
  if(card.style.display==='block'){
    window.scrollTo({top:card.offsetTop-100,behavior:'smooth'});
  }
}

function performDiff(){
  const oldFile=document.getElementById('diff-old-file').files[0];
  const newFile=document.getElementById('diff-new-file').files[0];

  if(!oldFile||!newFile){
    alert(tr('diff.uploadBothAlert'));
    return;
  }

  Promise.all([oldFile.text(),newFile.text()]).then(([oldText,newText])=>{
    const oldLines=oldText.split('\n');
    const newLines=newText.split('\n');
    const result=computeDiff(oldLines,newLines);
    displayDiff(result);
  });
}

// 簡單的 LCS（最長公共子序列）based diff 算法
function computeDiff(oldLines,newLines){
  const n=oldLines.length,m=newLines.length;
  if(n*m>4000000){
    // 檔案過大（LCS DP table 記憶體/時間成本過高），退回簡易逐行比對，避免瀏覽器分頁卡死
    return computeDiffSimple(oldLines,newLines);
  }
  const dp=Array.from({length:n+1},()=>new Int32Array(m+1));
  for(let i=n-1;i>=0;i--){
    for(let j=m-1;j>=0;j--){
      dp[i][j]=oldLines[i]===newLines[j]?dp[i+1][j+1]+1:Math.max(dp[i+1][j],dp[i][j+1]);
    }
  }
  const diff=[];
  let i=0,j=0;
  while(i<n&&j<m){
    if(oldLines[i]===newLines[j]){diff.push({type:'same',content:oldLines[i]});i++;j++;}
    else if(dp[i+1][j]>=dp[i][j+1]){diff.push({type:'del',content:oldLines[i]});i++;}
    else{diff.push({type:'add',content:newLines[j]});j++;}
  }
  while(i<n){diff.push({type:'del',content:oldLines[i]});i++;}
  while(j<m){diff.push({type:'add',content:newLines[j]});j++;}
  return diff;
}
function computeDiffSimple(oldLines,newLines){
  // 舊版逐 index 比對邏輯，僅作超大檔案 fallback（非真正 diff，只在檔案過大無法跑 LCS 時使用）
  const diff=[];
  const maxLen=Math.max(oldLines.length,newLines.length);
  for(let i=0;i<maxLen;i++){
    const old=oldLines[i]||'';
    const newL=newLines[i]||'';
    if(old===newL)diff.push({type:'same',content:old});
    else if(!old)diff.push({type:'add',content:newL});
    else if(!newL)diff.push({type:'del',content:old});
    else{diff.push({type:'del',content:old});diff.push({type:'add',content:newL});}
  }
  return diff;
}

function displayDiff(diff){
  const resultDiv=document.getElementById('diff-result');
  resultDiv.style.display='block';
  let html='';
  let addCount=0,delCount=0;

  diff.forEach(item=>{
    if(item.type==='same'){
      html+=`<div style="color:var(--text-dim)">${escapeHtml(item.content)}</div>`;
    }else if(item.type==='add'){
      html+=`<div style="color:var(--green);background:rgba(16,185,129,.1)">+ ${escapeHtml(item.content)}</div>`;
      addCount++;
    }else if(item.type==='del'){
      html+=`<div style="color:var(--red);background:rgba(239,68,68,.1)">- ${escapeHtml(item.content)}</div>`;
      delCount++;
    }
  });

  const summary=`<div style="border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:8px;font-weight:600">
    📊 ${tr('diff.added')} ${addCount} | ${tr('diff.deleted')} ${delCount} | ${tr('diff.total')} ${diff.length}
  </div>`;

  resultDiv.innerHTML=summary+html;
}

function escapeHtml(text){
  const div=document.createElement('div');
  div.textContent=text;
  return div.innerHTML;
}

// ── 批量設定產生功能 ────────────────────────────────────────────
window.bulkConfigs={}; // 存儲已生成的配置

function toggleBulkCard(){
  const card=document.getElementById('bulk-card');
  card.style.display=card.style.display==='none'?'block':'none';
  if(card.style.display==='block'){
    window.scrollTo({top:card.offsetTop-100,behavior:'smooth'});
  }
}

function showBulkTemplate(){
  alert(tr('msg.bulkTemplate'));
}

function processBulkCSV(){
  const file=document.getElementById('bulk-csv-file').files[0];
  if(!file){
    alert(tr('msg.bulkNoFile'));
    return;
  }

  file.text().then(csvText=>{
    const lines=csvText.trim().split('\n');
    if(lines.length<2){
      alert(tr('msg.bulkNeedHeaderRow'));
      return;
    }

    const headers=lines[0].split(',').map(h=>h.trim().toLowerCase());
    const required=['devicename','vendor','hostname'];
    const hasRequired=required.every(r=>headers.includes(r));
    if(!hasRequired){
      alert(tr('msg.bulkMissingColumns').replace('{cols}',required.join(', ')));
      return;
    }

    window.bulkConfigs={};
    const results=[];
    const progressDiv=document.getElementById('bulk-progress');
    const listDiv=document.getElementById('bulk-list');

    // 批量處理前先快照原始表單狀態。原本 originalVendor/originalHostname 宣告在 for 迴圈
    // 內部（block-scoped const），迴圈結束後在外層讀取會直接拋 ReferenceError，導致下面的
    // 「恢復原始值」與完成訊息從未真正執行過；另外 updateModeOptions() 切到非 Comware 廠牌時
    // 會把 Hybrid 介面強制改成 Trunk，且事後只會補回下拉選單的 hybrid <option>、不會把
    // select 的實際選取值改回來，故一併快照每列 .i-mode 的原始值供事後手動復原
    const originalVendor=document.getElementById('vendor').value;
    const originalHostname=document.getElementById('hostname').value;
    const originalModeValues=rowsOf('#iface-body tr').map(tr=>tr.querySelector('.i-mode')?.value);

    progressDiv.innerHTML=`<div style="color:var(--accent);font-weight:600">${tr('msg.bulkProgress').replace('{current}','0').replace('{total}',lines.length-1)}</div>`;
    listDiv.innerHTML='';

    for(let i=1;i<lines.length;i++){
      if(!lines[i].trim())continue;

      const values=lines[i].split(',').map(v=>v.trim());
      const row={};
      headers.forEach((h,idx)=>{
        row[h]=values[idx]||'';
      });

      if(!row.devicename||!row.vendor||!row.hostname){
        results.push({name:row.devicename,status:tr('msg.bulkMissingFields'),color:'var(--red)'});
        continue;
      }

      // 產生設定：複製現有表單資料，改變 hostname 和 vendor（originalVendor/originalHostname
      // 已移到迴圈外快照，見上方說明）
      try{
        // 臨時改變表單值
        document.getElementById('vendor').value=row.vendor;
        document.getElementById('hostname').value=row.hostname;

        // 觸發廠牌變更（更新模式選項等）
        updateModeOptions();

        // 產生配置
        const model=collectModel();
        let cfg;
        if(model.vendor==='fortiswitch')cfg=assembleFortiSwitchConfig(model);
        else if(model.vendor==='aruba')cfg=assembleArubaConfig(model);
        else if(model.vendor==='cisco')cfg=assembleCiscoConfig(model);
        else if(model.vendor==='juniper')cfg=assembleJuniperConfig(model);
        else if(model.vendor==='dell-os10')cfg=assembleDellOS10Config(model);
        else if(model.vendor==='cisco_nxos')cfg=assembleNXOSConfig(model);
        else if(model.vendor==='arista')cfg=assembleAristaConfig(model);
        else if(model.vendor==='brocade')cfg=assembleBrocadeConfig(model);
        else if(model.vendor==='alcatel')cfg=assembleAlcatelConfig(model);
        else if(model.vendor==='extreme')cfg=assembleExtremeConfig(model);
        else if(model.vendor==='procurve')cfg=assembleProCurveConfig(model);
        else if(model.vendor==='routeros')cfg=assembleRouterOSConfig(model);
        else if(model.vendor==='ruijie')cfg=assembleRuijieConfig(model);
  else if(model.vendor==='netgear')cfg=assembleNetgearConfig(model);
  else if(model.vendor==='edgeswitch')cfg=assembleEdgeSwitchConfig(model);
        else if(model.vendor==='sonic')cfg=assembleSONiCConfig(model);
        else cfg=assembleComwareConfig(model);

        window.bulkConfigs[row.devicename]=cfg;
        results.push({
          name:row.devicename,
          status:`✅ ${row.hostname} (${row.vendor})`,
          color:'var(--green)'
        });
      }catch(e){
        results.push({
          name:row.devicename,
          status:tr('msg.bulkGenerateFailed').replace('{error}',e.message),
          color:'var(--red)'
        });
      }

      progressDiv.innerHTML=`<div style="color:var(--accent);font-weight:600">${tr('msg.bulkProgress').replace('{current}',i).replace('{total}',lines.length-1)}</div>`;
    }

    // 恢復原始值：vendor/hostname 需先復原，updateModeOptions() 才會依原本廠牌正確處理
    // hybrid 選項的顯示/隱藏；接著手動把每列 .i-mode 的實際選取值復原成快照的原始值，因為
    // updateModeOptions() 本身只會補回 hybrid <option>，不會把 select 的值改回 hybrid
    document.getElementById('vendor').value=originalVendor;
    document.getElementById('hostname').value=originalHostname;
    updateModeOptions();
    rowsOf('#iface-body tr').forEach((tr,idx)=>{
      const sel=tr.querySelector('.i-mode');
      if(sel&&originalModeValues[idx]!==undefined)sel.value=originalModeValues[idx];
    });

    // 顯示結果
    progressDiv.innerHTML=`<div style="color:var(--green);font-weight:600">${tr('msg.bulkDone').replace('{count}',Object.keys(window.bulkConfigs).length)}</div>`;
    listDiv.innerHTML=results.map(r=>`<div style="color:${r.color}">${r.name}: ${r.status}</div>`).join('');
    document.getElementById('bulk-result').style.display='block';
  });
}

function downloadBulkZip(){
  if(Object.keys(window.bulkConfigs).length===0){
    alert(tr('msg.bulkNothingToDownload'));
    return;
  }

  const timestamp=new Date().toISOString().replace(/[:\-]/g,'').slice(0,14);

  // 生成清單
  let manifest=tr('msg.bulkManifestTitle')+'\n';
  manifest+=tr('msg.bulkManifestTimestamp').replace('{time}',new Date().toLocaleString())+'\n';
  manifest+=tr('msg.bulkManifestCount').replace('{count}',Object.keys(window.bulkConfigs).length)+'\n\n';
  manifest+=tr('msg.bulkManifestHeader')+'\n';
  Object.entries(window.bulkConfigs).forEach(([name,cfg])=>{
    const lineCount=cfg.split('\n').length;
    manifest+=`${name}.txt,${lineCount}\n`;
  });

  // 使用純 JavaScript 建立 ZIP（未壓縮格式，相容所有解壓工具）
  const zipBuffer=createZip(window.bulkConfigs,manifest);
  downloadFile(zipBuffer,`switch-configs_${timestamp}.zip`,'application/zip');
}

// 純 JavaScript ZIP 生成（未壓縮格式，Uint8Array/DataView 二進位安全寫法，
// 移植自 config_anonymizer 的 makeZip()：舊版用 String.fromCharCode 拼字串
// 再 TextEncoder 編碼，byte 值 ≥128 時會被誤當 UTF-8 多位元組編碼，導致中央
// 目錄位移損毀；CRC-32 也原本恆為 0，一併修正為真正計算）
function crc32(buf){
  let c=~0;
  const t=(()=>{
    const T=new Uint32Array(256);
    for(let i=0;i<256;i++){let v=i;for(let j=0;j<8;j++)v=(v&1)?(0xEDB88320^(v>>>1)):(v>>>1);T[i]=v;}
    return T;
  })();
  for(let i=0;i<buf.length;i++)c=t[(c^buf[i])&0xFF]^(c>>>8);
  return (~c)>>>0;
}
function createZip(files,manifestContent){
  const fileObject={...files,'manifest.csv':manifestContent};
  const enc=(s)=>new TextEncoder().encode(s);
  const u16=(n)=>[n&0xFF,(n>>8)&0xFF];
  const u32=(n)=>[n&0xFF,(n>>8)&0xFF,(n>>16)&0xFF,(n>>24)&0xFF];
  const now=new Date();
  const dosTime=((now.getHours()<<11)|(now.getMinutes()<<5)|(now.getSeconds()>>1));
  const dosDate=(((now.getFullYear()-1980)<<9)|((now.getMonth()+1)<<5)|now.getDate());
  const parts=[];
  const centralDir=[];
  let offset=0;
  let numEntries=0;
  for(const [filename,content] of Object.entries(fileObject)){
    const nameBytes=enc(filename);
    const data=enc(content);
    const crc=crc32(data);
    const size=data.length;
    const lhdr=new Uint8Array([
      0x50,0x4B,0x03,0x04,
      0x14,0x00,
      0x00,0x08, // 通用旗標 bit 11 = 檔名/註解為 UTF-8（含中文檔名時避免亂碼）
      0x00,0x00,
      ...u16(dosTime),...u16(dosDate),
      ...u32(crc),
      ...u32(size),...u32(size),
      ...u16(nameBytes.length),0x00,0x00,
    ]);
    parts.push(lhdr,nameBytes,data);
    const cdEntry=new Uint8Array([
      0x50,0x4B,0x01,0x02,
      0x14,0x00,0x14,0x00,
      0x00,0x08,0x00,0x00, // 通用旗標 bit 11 = UTF-8 檔名，與 local header 一致

      ...u16(dosTime),...u16(dosDate),
      ...u32(crc),
      ...u32(size),...u32(size),
      ...u16(nameBytes.length),0x00,0x00, // filename length, extra field length
      0x00,0x00,                          // file comment length
      0x00,0x00,                          // disk number start
      0x00,0x00,                          // internal file attributes
      0x00,0x00,0x00,0x00,                // external file attributes
      ...u32(offset),                     // relative offset of local header
    ]);
    centralDir.push(cdEntry,nameBytes);
    offset+=lhdr.length+nameBytes.length+size;
    numEntries++;
  }
  const cdSize=centralDir.reduce((s,b)=>s+b.length,0);
  const eocd=new Uint8Array([
    0x50,0x4B,0x05,0x06,
    0x00,0x00,0x00,0x00,
    ...u16(numEntries),...u16(numEntries),
    ...u32(cdSize),...u32(offset),
    0x00,0x00,
  ]);
  const all=[...parts,...centralDir,eocd];
  const totalLen=all.reduce((s,b)=>s+b.length,0);
  const finalBuffer=new Uint8Array(totalLen);
  let pos=0;
  for(const b of all){finalBuffer.set(b,pos);pos+=b.length;}
  return finalBuffer;
}

// 純 JavaScript 文件下載（不依賴外部庫）
function downloadFile(data,filename,mimeType='application/octet-stream'){
  let dataUrl;

  if(data instanceof Uint8Array){
    // 二進制數據轉為 Data URL
    let binary='';
    for(let i=0;i<data.length;i++){
      binary+=String.fromCharCode(data[i]);
    }
    dataUrl='data:'+mimeType+';base64,'+btoa(binary);
  }else{
    // 文本數據
    dataUrl='data:'+mimeType+';charset=utf-8,'+encodeURIComponent(data);
  }

  // 建立下載連結
  const link=document.createElement('a');
  link.href=dataUrl;
  link.download=filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// ── 文檔自動生成功能 ────────────────────────────────────────────
function showDocExportOptions(){
  const choice=prompt(`${tr('doc.chooseFormat')}：\n1. ${tr('btn.downloadTxt')} (.txt)\n2. ${tr('btn.downloadWord')} (.docx)\n3. ${tr('btn.downloadJson')} (.json)\n\n${tr('doc.enterChoice')}：`,'1');
  if(!choice)return;

  if(choice==='1'){
    generateDocumentationAsText();
  }else if(choice==='2'){
    if(!window.docx){
      alert(tr('doc.wordError'));
      return;
    }
    generateDocumentationAsDocx();
  }else if(choice==='3'){
    generateDocumentationAsJSON();
  }else{
    alert(tr('doc.invalidChoice'));
  }
}

function buildDocData(){
  const model=collectModel();
  const docData={
    title:tr('doc.title'),
    device:{
      hostname:model.sysname||'Unknown',
      vendor:model.vendor||'N/A',
      generatedTime:new Date().toLocaleString('zh-TW'),
      disclaimer:tr('doc.disclaimerText')
    },
    sections:[]
  };

  // 1. VLAN 規劃表
  if(model.vlans.length>0){
    docData.sections.push({
      title:tr('doc.vlanTitle'),
      type:'table',
      columns:[tr('col.vlanId'),tr('col.vlanName'),tr('col.remark')],
      rows:model.vlans.map(v=>[v.id||'N/A',v.name||'N/A',''])
    });
  }

  // 2. Interface 配置表
  if(model.interfaces.length>0){
    docData.sections.push({
      title:tr('doc.ifaceTitle'),
      type:'table',
      columns:[tr('col.ifName'),tr('col.ifMode'),tr('col.ifVlan'),tr('col.ifDesc')],
      rows:model.interfaces.map(i=>[
        i.name||'N/A',
        i.mode||'N/A',
        i.mode==='access'?i.accessVlan:(i.trunkVlans||'N/A'),
        i.desc||''
      ])
    });
  }

  // 3. 路由協議摘要
  let routingInfo='';
  if(model.ospf.length>0){
    routingInfo+='🔹 OSPF：\n';
    model.ospf.forEach((o,idx)=>{
      routingInfo+=`  • Process ${o.pid}: ${tr('lbl.ospfRid')} ${o.routerId}, ${tr('doc.areaCount')}: ${o.areas.length}\n`;
    });
  }
  if(model.bgp.length>0){
    routingInfo+='🔹 BGP：\n';
    model.bgp.forEach((b,idx)=>{
      routingInfo+=`  • AS ${b.asn}: ${tr('lbl.bgpRid')} ${b.routerId}, ${tr('doc.peerCount')}: ${b.peers.length}\n`;
    });
  }
  if(model.routes.length>0){
    routingInfo+=`🔹 ${tr('sec.routes')}：\n`;
    routingInfo+=`  • ${tr('doc.routeCount')}: ${model.routes.length}\n`;
  }
  if(routingInfo){
    docData.sections.push({
      title:tr('doc.routingTitle'),
      type:'text',
      content:routingInfo
    });
  }

  // 4. 冗餘配置
  let redundancyInfo='';
  if(model.lacp.length>0){
    redundancyInfo+=`🔹 ${tr('sec.lacp')}：\n`;
    model.lacp.forEach(lag=>{
      redundancyInfo+=`  • ${lag.id} (${lag.mode || 'static'}mode): ${tr('doc.portCount')}: ${lag.members.length}\n`;
    });
  }
  if(model.vrrp.length>0){
    redundancyInfo+=`🔹 ${tr('sec.vrrp')}：\n`;
    model.vrrp.forEach(v=>{
      redundancyInfo+=`  • VRID ${v.vrid}: VIP ${v.vip}, ${tr('th.vrrpPriority')} ${v.priority}\n`;
    });
  }
  if(redundancyInfo){
    docData.sections.push({
      title:tr('doc.redundancyTitle'),
      type:'text',
      content:redundancyInfo
    });
  }

  return docData;
}

function generateDocumentationAsText(){
  const docData=buildDocData();
  downloadDocumentationAsText(docData);
}

function generateDocumentation(){
  generateDocumentationAsText();
}

function downloadDocumentationAsText(docData){
  let doc=`═══════════════════════════════════════════\n`;
  doc+=`${docData.device.hostname} - ${tr('doc.title')}\n`;
  doc+=`═══════════════════════════════════════════\n\n`;

  doc+=`📋 ${tr('doc.deviceInfo')}\n`;
  doc+=`───────────────────────────────────────────\n`;
  doc+=`${tr('lbl.hostname')}：${docData.device.hostname}\n`;
  doc+=`${tr('lbl.vendor')}：${docData.device.vendor}\n`;
  doc+=`${tr('doc.timestamp')}：${docData.device.generatedTime}\n`;
  doc+=`${docData.device.disclaimer}\n\n`;

  docData.sections.forEach(section=>{
    doc+=`📌 ${section.title}\n`;
    doc+=`───────────────────────────────────────────\n`;

    if(section.type==='table'){
      doc+=section.columns.join(' | ')+'\n';
      doc+='─'.repeat(section.columns.reduce((a,c)=>a+c.length+3,0))+'\n';
      section.rows.forEach(row=>{
        doc+=row.join(' | ')+'\n';
      });
    }else if(section.type==='text'){
      doc+=section.content;
    }
    doc+='\n\n';
  });

  // 使用純 JavaScript 下載（不依賴外部庫）
  const timestamp=new Date().toISOString().replace(/[:\-]/g,'').slice(0,14);
  const filename=`${docData.device.hostname}_${tr('doc.title')}_${timestamp}.txt`;
  dlTxt(doc,filename);
}

function generateDocumentationAsDocx(){
  if(!window.docx){
    alert(tr('doc.wordError'));
    return;
  }

  const docData=buildDocData();

  // 建構 Word 文檔的子元素（children 陣列）
  const children=[];

  // 標題
  children.push(new docx.Paragraph({
    text:docData.title,
    style:'Heading1',
    alignment:docx.AlignmentType.CENTER
  }));

  children.push(new docx.Paragraph({text:''}));

  // 設備信息表格
  const deviceRows=[
    new docx.TableRow({
      children:[
        new docx.TableCell({children:[new docx.Paragraph(tr('lbl.hostname'))],shading:{fill:'D3D3D3'}}),
        new docx.TableCell({children:[new docx.Paragraph(docData.device.hostname)]})
      ]
    }),
    new docx.TableRow({
      children:[
        new docx.TableCell({children:[new docx.Paragraph(tr('lbl.vendor'))],shading:{fill:'D3D3D3'}}),
        new docx.TableCell({children:[new docx.Paragraph(docData.device.vendor)]})
      ]
    }),
    new docx.TableRow({
      children:[
        new docx.TableCell({children:[new docx.Paragraph(tr('doc.timestamp'))],shading:{fill:'D3D3D3'}}),
        new docx.TableCell({children:[new docx.Paragraph(docData.device.generatedTime)]})
      ]
    }),
    new docx.TableRow({
      children:[
        new docx.TableCell({children:[new docx.Paragraph(tr('doc.disclaimer'))],shading:{fill:'D3D3D3'}}),
        new docx.TableCell({children:[new docx.Paragraph(docData.device.disclaimer)]})
      ]
    })
  ];

  children.push(new docx.Table({
    rows:deviceRows,
    width:{size:100,type:docx.WidthType.PERCENTAGE}
  }));

  children.push(new docx.Paragraph({text:''}));

  // 各 section（VLAN、Interface 等）
  docData.sections.forEach(section=>{
    children.push(new docx.Paragraph({
      text:section.title,
      style:'Heading2'
    }));

    if(section.type==='table'){
      // 轉換 CSV 風格的行陣列為 docx TableRow
      const tableRows=[];

      // 標題列
      const headerCells=section.columns.map(col=>
        new docx.TableCell({
          children:[new docx.Paragraph(col)],
          shading:{fill:'E8E8E8'}
        })
      );
      tableRows.push(new docx.TableRow({children:headerCells}));

      // 資料列
      section.rows.forEach(row=>{
        const dataCells=row.map(cell=>
          new docx.TableCell({
            children:[new docx.Paragraph(String(cell||''))]
          })
        );
        tableRows.push(new docx.TableRow({children:dataCells}));
      });

      children.push(new docx.Table({
        rows:tableRows,
        width:{size:100,type:docx.WidthType.PERCENTAGE}
      }));
    }else if(section.type==='text'){
      // 純文字段落（保留換行）
      section.content.split('\n').forEach(line=>{
        children.push(new docx.Paragraph(line||' '));
      });
    }

    children.push(new docx.Paragraph({text:''}));
  });

  // 建構 Word 文檔
  const doc=new docx.Document({sections:[{children}]});

  // 使用 docx.Packer 生成 Uint8Array
  docx.Packer.toBuffer(doc).then(buffer=>{
    const timestamp=new Date().toISOString().replace(/[:\-]/g,'').slice(0,14);
    const filename=`${docData.device.hostname}_${tr('doc.title')}_${timestamp}.docx`;
    downloadFile(buffer,filename,'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  }).catch(err=>{
    console.error('Word 生成失敗:',err);
    alert(tr('doc.wordGenFailed'));
  });
}

function generateDocumentationAsJSON(){
  const docData=buildDocData();
  const jsonStr=JSON.stringify(docData,null,2);
  const timestamp=new Date().toISOString().replace(/[:\-]/g,'').slice(0,14);
  const filename=`${docData.device.hostname}_${tr('doc.title')}_${timestamp}.json`;
  const blob=new Blob([jsonStr],{type:'application/json;charset=utf-8'});
  const url=URL.createObjectURL(blob);
  const link=document.createElement('a');
  link.href=url;
  link.download=filename;
  link.click();
  URL.revokeObjectURL(url);
}

// 在產生結果卡片加入批量按鈕
window.addEventListener('load',function(){
  const outActions=document.querySelector('.out-actions');
  if(outActions&&!outActions.querySelector('[onclick*="toggleBulkCard"]')){
    const bulkBtn=document.createElement('button');
    bulkBtn.className='act-btn';
    bulkBtn.style.marginLeft='auto';
    bulkBtn.innerHTML=tr('btn.bulkToggle');
    bulkBtn.setAttribute('data-i18n','btn.bulkToggle');
    bulkBtn.onclick=toggleBulkCard;
    outActions.appendChild(bulkBtn);
  }
});

function downloadOutput(){
  const t=document.getElementById('output').value;
  if(!t)return;
  const hostname=document.getElementById('hostname').value.trim()||'switch';
  if(document.getElementById('vendor').value==='sonic'){
    // config_db.json 本體就是 JSON，比照 generateDocumentationAsJSON() 既有 Blob 寫法，
    // 不可沿用下面固定 .cfg + text/plain 的 dlTxt()
    const blob=new Blob([t],{type:'application/json;charset=utf-8'});
    const url=URL.createObjectURL(blob);
    const link=document.createElement('a');
    link.href=url;
    link.download=hostname+'_config_db.json';
    link.click();
    URL.revokeObjectURL(url);
    return;
  }
  dlTxt(t,hostname+'.cfg');
}

// ── i18n ───────────────────────────────────────────────────────────
let _lang='zhTW';
function tr(k){
  if(_lang==='leet'){const s=LANG.en[k]||LANG.zhTW[k]||k;return s.replace(/a/gi,'4').replace(/e/gi,'3').replace(/i/gi,'1').replace(/o/gi,'0').replace(/s/gi,'5').replace(/t/gi,'7').replace(/l/gi,'|');}
  if(_lang==='uwu'){const s=LANG.en[k]||LANG.zhTW[k]||k;return s.replace(/r/g,'w').replace(/R/g,'W').replace(/l/g,'w').replace(/L/g,'W').replace(/th/g,'d').replace(/Th/g,'D').replace(/n([aeiou])/g,'ny$1').replace(/N([AEIOU])/g,'Ny$1');}
  return (LANG[_lang]||LANG.zhTW)[k]||LANG.en[k]||k;
}

function applyI18n(root){
  (root||document).querySelectorAll('[data-i18n]').forEach(el=>{el.textContent=tr(el.dataset.i18n);});
  (root||document).querySelectorAll('[data-i18n-ph]').forEach(el=>{el.placeholder=tr(el.dataset.i18nPh);});
}

function setLang(lang){
  _lang=lang;
  document.documentElement.lang=lang==='zhTW'?'zh-TW':lang;
  document.querySelectorAll('.lang-btn[data-lang]').forEach(b=>b.classList.toggle('active',b.dataset.lang===lang));
  // 保存當前的設備模型選擇，以防語言切換過程中遺失
  const deviceModelSel=document.getElementById('device-model');
  const savedModelValue=deviceModelSel?deviceModelSel.value:'';
  applyI18n(document);
  document.getElementById('h-title').textContent=tr('title');
  document.title=tr('title');
  // 更新文件輸入按鈕文本
  document.querySelectorAll('.file-input-btn[data-i18n]').forEach(btn=>{
    btn.textContent=tr(btn.dataset.i18n);
  });
  // 更新文件名文本（如果沒有選檔案）
  const configFileNameEl=document.getElementById('import-config-file-name');
  if(configFileNameEl && configFileNameEl.dataset.i18n && !document.getElementById('import-config-file').files.length){
    configFileNameEl.textContent=tr(configFileNameEl.dataset.i18n);
  }
  const parserFileNameEl=document.getElementById('import-parser-file-name');
  if(parserFileNameEl && parserFileNameEl.dataset.i18n && !document.getElementById('import-parser-file').files.length){
    parserFileNameEl.textContent=tr(parserFileNameEl.dataset.i18n);
  }
  // 重新應用設備型號翻譯並恢復選擇
  updateDeviceModelOptions();
  if(deviceModelSel && savedModelValue){
    deviceModelSel.value=savedModelValue;
  }
  updateAppliedModelNotice();
}

// ── theme ──────────────────────────────────────────────────────────
// ── 跨工具導覽（2026-08-24 新增）：見 switch_analyzer 同名函式註解
function toggleToolsNav(e){
  if(e)e.stopPropagation();
  const p=document.getElementById('tools-nav-panel');
  if(!p)return;
  p.style.display=(p.style.display==='none'||!p.style.display)?'block':'none';
}
document.addEventListener('click',function(e){
  const p=document.getElementById('tools-nav-panel');
  if(p&&p.style.display==='block'&&!p.contains(e.target)&&e.target.id!=='tools-nav-btn'){
    p.style.display='none';
  }
});

function setTheme(t){document.body.dataset.theme=t;const b=document.getElementById('theme-btn');if(b)b.textContent=t==='light'?'🌙':'☀️';localStorage.setItem('cw_theme',t);}
function toggleTheme(){setTheme(document.body.dataset.theme==='light'?'dark':'light');}
(function(){const s=localStorage.getItem('cw_theme');const p=s||(window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');if(p==='light')setTheme('light');})();
window.addEventListener('beforeprint',function(){
  const o=document.getElementById('output');
  if(!o)return;
  const pre=document.createElement('pre');
  pre.id='output-print';
  pre.textContent=o.value;
  pre.style.cssText="white-space:pre-wrap;word-break:break-word;font-family:Menlo,'Courier New',monospace;font-size:11px;border:1px solid #ccc;padding:12px;background:#fff;color:#000";
  o.insertAdjacentElement('afterend',pre);
});
window.addEventListener('afterprint',function(){
  const pre=document.getElementById('output-print');
  if(pre)pre.remove();
});

// ── 彩蛋 toast ─────────────────────────────────────────────────────
function showEggToast(msg, duration=3500){
  const t=document.createElement('div');
  t.className='egg-toast';
  t.textContent=msg;
  document.body.appendChild(t);
  setTimeout(()=>t.classList.add('show'),20);
  setTimeout(()=>{t.classList.remove('show');setTimeout(()=>t.remove(),400);},duration);
}

// ── 彩蛋：羊駝飄落動畫 ─────────────────────────────────────────────
function startRain(alpaca){
  const items=['🦙','🦙','🦙','🐑','🌿'];
  const duration=3000,count=40;
  for(let i=0;i<count;i++){
    setTimeout(()=>{
      const el=document.createElement('div');
      el.className='rain-item';
      el.textContent=items[Math.floor(Math.random()*items.length)];
      el.style.left=Math.random()*100+'vw';
      el.style.animationDuration=(1.5+Math.random()*2)+'s';
      el.style.animationDelay=(Math.random()*1.5)+'s';
      document.body.appendChild(el);
      setTimeout(()=>el.remove(),4000);
    },Math.random()*duration*0.8);
  }
}

function eggMouseOver(){
  const messages=['💯 純手工 — 零 AI','✨ 每一行都是血汗','🖐️ 手寫代碼無悔','🔥 真·人工智慧','💪 手指尖端的藝術'];
  const hint=document.querySelector('.mini-alpaca-hint');
  if(hint){
    hint.textContent=messages[Math.floor(Math.random()*messages.length)];
  }
}

// ── 名詞解釋 tooltip ───────────────────────────────────────────────
(function(){
  const _t=document.createElement('div');
  _t.className='global-tip';
  document.body.appendChild(_t);
  document.addEventListener('mouseover',function(e){
    const el=e.target.closest('[data-tip]');
    if(!el)return;
    _t.textContent=el.dataset.tip;
    _t.style.display='block';
    const r=el.getBoundingClientRect(),tw=_t.offsetWidth,th=_t.offsetHeight;
    let x=r.left+r.width/2-tw/2;
    x=Math.max(8,Math.min(x,window.innerWidth-tw-8));
    const y=r.top-th-8;
    _t.style.left=x+'px';
    _t.style.top=(y<8?r.bottom+8:y)+'px';
  });
  document.addEventListener('mouseout',function(e){
    if(e.target.closest('[data-tip]'))_t.style.display='none';
  });
  document.addEventListener('scroll',function(){_t.style.display='none';},true);
})();

// ── 彩蛋：羊駝 3 連擊解鎖克林貢 ─────────────────────────────────────
(function(){
  let _kN=0,_kT;
  document.addEventListener('click',function(e){
    const ac=document.getElementById('mini-alpaca');
    if(!ac||(!ac.contains(e.target)&&ac!==e.target))return;
    clearTimeout(_kT);_kN++;
    _kT=setTimeout(function(){_kN=0;},2000);
    if(_kN>=3){
      _kN=0;
      document.getElementById('lang-klingon').style.display='block';
      setLang('tlh');
      const t=document.createElement('div');t.className='qapla-toast';
      t.textContent="🖖 Qapla'! tlhIngan Hol DaghojneS!";
      document.body.appendChild(t);
      t.addEventListener('animationend',function(ev){if(ev.animationName==='qapla-out')t.remove();});
    }
  });
})();

// ── 彩蛋：Konami Code → Matrix Rain ─────────────────────────────────
(function setupKonami(){
  const SEQ=[38,38,40,40,37,39,37,39,66,65]; // ↑↑↓↓←→←→BA
  let idx=0;
  document.addEventListener('keydown',e=>{
    idx=(e.keyCode===SEQ[idx])?idx+1:0;
    if(idx===SEQ.length){idx=0;startMatrixRain();}
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

// ── 彩蛋：lang-egg 代表物三連擊 ──────────────────────────────────────
const _EGG={
  'egg-pirate':{lang:'pirate',btn:'lang-pirate',toast:"☠️ Ahoy! Ye be speakin' pirate now, matey! Arr!"},
  'egg-emoji': {lang:'emoji', btn:'lang-emoji', toast:'🌈✨🎉 3moji mod3 4ctiv4t3d! 🦄💫🌟'},
  'egg-bureau':{lang:'bureau',btn:'lang-bureau',toast:'📋 啟動跨部門作業流程。本系統正式進入公文模式。請依規定格式呈現。'},
  'egg-cat':   {lang:'cat',   btn:'lang-cat',   toast:'🐱 Nyaa~！喵語模式啟動了喵！meow meow owo'},
  'egg-bean':  {lang:'bean',  btn:'lang-bean',  toast:'🥕🫛🌽 豆語模式啟動！蔬菜智慧已降臨！🌽🫛🥕'},
  'egg-alpaca':{lang:'alpaca',btn:'lang-alpaca',toast:'🦙 咩咩咩！羊咩碼啟動-aca！上傳咩設咩定-aca！🦙'},
  'egg-yanse': {lang:'yanse', btn:'lang-yanse', toast:'💀 overtime detected...厭世工程師模式啟動，反正早晚都要加班'},
  'egg-leet':  {lang:'leet',  btn:'lang-leet',  toast:'1337 5P34K 4C71V473D. H4X0R M0D3 0N.'},
  'egg-uwu':   {lang:'uwu',   btn:'lang-uwu',   toast:'🐾 Hewwo fwend~ UwU wanguage activeated! OwO'},
  'egg-wuxia': {lang:'wuxia', btn:'lang-wuxia', toast:'⚔️ 武林秘笈已然出鞘！江湖兒女，且看今朝！'},
};
const _eN={},_eT={};
function initEggListeners(){
  const eggs=document.querySelectorAll('.lang-egg');
  eggs.forEach(function(el){
    if(!_eN[el.id]) _eN[el.id]=0;
    el.addEventListener('click',function(){
      clearTimeout(_eT[el.id]);
      _eN[el.id]++;
      _eT[el.id]=setTimeout(function(){_eN[el.id]=0;},1500);
      if(_eN[el.id]>=3){
        _eN[el.id]=0;
        const c=_EGG[el.id];
        if(c){
          const btn=document.getElementById(c.btn);
          if(btn) btn.style.display='block';
          setLang(c.lang);
          showEggToast(c.toast);
        }
      }
    });
  });
}
window.addEventListener('load',function(){
  initEggListeners();
});

// 範例資料：原本在頁面載入時無條件自動填入，會混進使用者實際輸出（不需要的 OSPF/BGP/RIP
// 等區塊被誤當成必填），改為「載入範例資料」按鈕觸發，讓表單預設維持空白
function loadExampleData(){
  addVlanRow('10','Management');
  addVlanRow('20','Server');
  addIfaceRow('GigabitEthernet1/0/1','trunk');
  rowsOf('#iface-body tr')[rowsOf('#iface-body tr').length-1].querySelector('.i-trunk-vlans').value='10 20';
  addIfaceRow('GigabitEthernet1/0/2','hybrid');
  rowsOf('#iface-body tr')[rowsOf('#iface-body tr').length-1].querySelector('.i-hy-untagged').value='10';
  rowsOf('#iface-body tr')[rowsOf('#iface-body tr').length-1].querySelector('.i-hy-tagged').value='20';
  rowsOf('#iface-body tr')[rowsOf('#iface-body tr').length-1].querySelector('.i-hy-pvid').value='10';
  addAreaRow('0.0.0.0','192.168.10.0','0.0.0.255','normal');
  addAreaRow('1.1.1.1','10.30.0.0','0.0.0.255','stub');
  document.getElementById('ospf-pid').value='1';
  document.getElementById('ospf-rid').value='1.1.1.1';
  document.getElementById('bgp-asn').value='65000';
  document.getElementById('bgp-rid').value='1.1.1.1';
  document.getElementById('bgp-networks').value='192.168.10.0/24';
  addBgpPeerRow('192.168.10.2','65001','Upstream-ISP');
  document.getElementById('rip-pid').value='1';
  document.getElementById('rip-version').value='2';
  document.getElementById('rip-networks').value='10.0.0.0';
  document.getElementById('rip-redist').value='static';
  addRouteRow('0.0.0.0/0','192.168.10.254');
  addLacpRow('1','active','GigabitEthernet1/0/3 GigabitEthernet1/0/4');
  addVrrpRow('10','192.168.10.1/24','10','192.168.10.254','150',true);
  generate();
}
window.loadExampleData=loadExampleData;

// ── init ───────────────────────────────────────────────────────────
// 初始化流程：確保所有依賴都已加載

// 第一步：設置語言，但延遲 device-model 更新
_lang='zhTW';
document.documentElement.lang='zh-TW';
document.querySelectorAll('.lang-btn[data-lang]').forEach(b=>b.classList.toggle('active',b.dataset.lang==='zhTW'));
applyI18n(document);
document.getElementById('h-title').textContent=tr('title');
document.title=tr('title');

// 第二步：確保 vendor 下拉有正確的初始值
const vendorSel=document.getElementById('vendor');
const deviceModelSel=document.getElementById('device-model');
if(!vendorSel.value) vendorSel.value='comware';

// 第三步：填充 device-model 下拉（applyI18n 後立即調用）
updateDeviceModelOptions();

// 第四步：其餘初始化
updateModeOptions();
updateIfaceTableDisplay();
updateAppliedModelNotice();
renderTemplateList();
generate();

// network_analyzer 拖放交接：比照 firewall_analyzer/switch_analyzer 既有 `_netAnalyzer_pending`
// 讀取慣例（10 秒新鮮度檢查＋讀取後即刻 removeItem，避免重複帶入）。此工具原本完全沒有接收端
// 程式碼，使用者從 network_analyzer 拖放檔案後手動選擇本工具，內容會被靜默丟棄、只看到空白表單
// （2026-07-26 全工具再稽核發現並修復）。本工具沒有像其餘三工具那樣的「view」切換機制，
// 匯入卡片本來就常駐頁面上，故只需帶入 #import-text 並呼叫既有的 parseAndImport()
(function(){
  var _p = localStorage.getItem('_netAnalyzer_pending');
  if (!_p) return;
  try {
    var d = JSON.parse(_p);
    if (Date.now() - d.ts > 10000) { localStorage.removeItem('_netAnalyzer_pending'); return; }
    localStorage.removeItem('_netAnalyzer_pending');
    var ta = document.getElementById('import-text');
    if (ta) ta.value = d.text;
    var fnameEl = document.getElementById('import-config-file-name');
    if (fnameEl && d.name) fnameEl.textContent = d.name;
    parseAndImport();
  } catch(e) {}
})();
