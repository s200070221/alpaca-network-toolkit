// ============================================================
// switch_config_generator：驗證／警告純函式（2026-09 從 switch-generator-app.js 拆出）
// ============================================================
// 純函式，零 DOM 依賴（比照 switch_analyzer 側 switch-analyzer-topology.js／
// switch-analyzer-audit.js 同批拆分先例，以及更早的 switch-analyzer-diff.js／
// firewall-analyzer-audit.js 拆分傳統）——switch-generator-app.js 本身頂層有多處立即執行的
// DOM 綁定，純函式若寫進該檔會導致 Node 測試沙箱一讀取整檔就因 document is not defined 拋錯。
// 涵蓋：IPv4/CIDR 格式驗證、常用機種 port 集合查詢、Comware OSPF network/LACP 屬性一致性警告、
// 認證金鑰弱值偵測、產生前安全稽核預覽／健康度評分、設定模板欄位級 diff（2026-09-23 新增，
// 三者皆為 vendor-agnostic 的表單/邏輯層級功能，非新查證廠牌語法，故一併收在本檔）。

function isValidIPv4(s){
  const m=(s||'').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every(o=>parseInt(o,10)<=255);
}

function isValidCIDR(s){
  const m=(s||'').match(/^(\S+)\/(\d{1,2})$/);
  return !!m && isValidIPv4(m[1]) && parseInt(m[2],10)>=0 && parseInt(m[2],10)<=32;
}

// IPv6 格式驗證（純位址，非 CIDR）：基本格式檢查，不追求完整 RFC 4291 相容
// （比照上方 isValidIPv4／isValidCIDR 的簡潔風格）——僅允許十六進位字元與冒號、
// 最多一個 "::" 縮寫、展開後 group 數不超過 8 組。
function isValidIPv6(s){
  s=(s||'').trim();
  if(!s||!/^[0-9a-fA-F:]+$/.test(s))return false;
  if(s.indexOf(':')===-1)return false;
  if((s.match(/::/g)||[]).length>1)return false;
  if(/:::/.test(s))return false;
  if(!s.includes('::')){
    const groups=s.split(':');
    return groups.length===8 && groups.every(g=>/^[0-9a-fA-F]{1,4}$/.test(g));
  }
  if(s==='::')return true;
  const sides=s.split('::');
  if(sides.length!==2)return false;
  const left=sides[0]?sides[0].split(':'):[];
  const right=sides[1]?sides[1].split(':'):[];
  if(left.length+right.length>=8)return false;
  return [...left,...right].every(g=>/^[0-9a-fA-F]{1,4}$/.test(g));
}

function isValidIPv6CIDR(s){
  const m=(s||'').match(/^(\S+)\/(\d{1,3})$/);
  return !!m && isValidIPv6(m[1]) && parseInt(m[2],10)>=0 && parseInt(m[2],10)<=128;
}

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

function isKnownModelPort(name,portSet){
  if(portSet.has(name))return true;
  const m=name.match(/^(.+?)([:./])(\d+)$/);
  return !!(m&&portSet.has(m[1]));
}

function ipv4ToInt(ip){
  const p=(ip||'').split('.').map(Number);
  if(p.length!==4||p.some(n=>!Number.isInteger(n)||n<0||n>255))return null;
  return ((p[0]*256+p[1])*256+p[2])*256+p[3];
}

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

// ── 認證金鑰弱值偵測（2026-09-23 新增，任務3）──────────────────────────
// OSPF/BGP MD5 認證金鑰（model.ospf[].authKey／model.bgp[].peers[].authKey）與 VRRP
// authentication 金鑰（model.vrrp[].authKey）皆是使用者直接輸入的明文字串（非雜湊），
// 長度過短或命中業界常見弱值字面，都有被離線字典/暴力猜測之風險；純字面比對，
// vendor-agnostic，不需新查證任何廠牌語法。
const WEAK_AUTH_KEY_VALUES=new Set(['cisco','password','123456','admin','12345678','password1','changeme','secret','default','qwerty']);
function isWeakAuthKey(key){
  const k=String(key||'').trim();
  if(!k)return false;
  if(k.length<6)return true;
  return WEAK_AUTH_KEY_VALUES.has(k.toLowerCase());
}
function weakAuthKeyWarnings(model){
  const warnings=[];
  if(!model)return warnings;
  (model.ospf||[]).forEach((o,i)=>{
    if(isWeakAuthKey(o.authKey))warnings.push(`⚠️ ${tr('val.weak_auth_key').replace('{item}','OSPF '+(i+1))}`);
  });
  (model.bgp||[]).forEach((b,i)=>{
    (b.peers||[]).forEach((p,pi)=>{
      if(isWeakAuthKey(p.authKey))warnings.push(`⚠️ ${tr('val.weak_auth_key').replace('{item}','BGP '+(i+1)+' Peer '+(p.ip||pi+1))}`);
    });
  });
  (model.vrrp||[]).forEach((v,i)=>{
    if(isWeakAuthKey(v.authKey))warnings.push(`⚠️ ${tr('val.weak_auth_key').replace('{item}','VRRP '+(i+1))}`);
  });
  return warnings;
}

// ── 產生前安全稽核預覽（2026-09-23 新增，任務1）──────────────────────────
// 概念比照 switch_analyzer 既有 analyzeSwitchAudit()/computeSwitchHealth()（見
// switch-analyzer-audit.js／CLAUDE.md「switch_analyzer 設定健康度評分」小節），但刻意不直接
// 呼叫該函式——analyzeSwitchAudit() 讀取的是「設定檔解析後」的 parsed 形狀（users[].pwdWeak／
// snmp.communities[]／mgmtAccess.telnet／interfaces[].type 等欄位），與本工具 collectModel()
// 輸出的「表單填寫中」model 形狀有多處不對稱（model 沒有 pwdWeak/pwdType，snmpCommunity 是單一
// 字串非陣列……），貿然直接餵入會讓多數檢查項目因欄位缺席而恆為 0，造成「已檢查、無問題」的
// 錯誤安全感。改為另建一組聚焦於 model 實際擁有欄位的精簡版檢查清單，並沿用
// computeSwitchHealth() 同一套權重與 A-F 門檻（WEIGHT/GRADE 邏輯直接複製一份，非跨檔案
// import，比照本專案「各工具/模組各自維護一份純函式」慣例）。
function analyzeGeneratorAudit(model){
  const findings=[];
  const f=(id,check,value,risk,detail)=>findings.push({id,check,value,risk,detail});
  const none=tr('genaudit.none');
  const ifaces=model.interfaces||[];
  // 1. 本機帳號弱密碼（password 為使用者直接輸入的字面值，重用上方 isWeakAuthKey()）
  const users=model.users||[];
  const weakPwd=users.filter(u=>isWeakAuthKey(u.password));
  f('weak-pwd', tr('genaudit.check_weak_pwd'), weakPwd.length, 'high',
    weakPwd.length?weakPwd.map(u=>u.name).join(', '):none);
  // 2. VLAN1（預設/原生 VLAN）仍用於使用者流量
  const vlan1Ports=ifaces.filter(i=>(i.mode==='access'||i.mode==='trunk')&&(!i.nativeVlan||i.nativeVlan==='1'));
  f('vlan1-inuse', tr('genaudit.check_vlan1_inuse'), vlan1Ports.length, 'medium',
    vlan1Ports.length?vlan1Ports.map(i=>i.name).join(', '):none);
  // 3. 已填寫的 access/trunk 介面未出現在 Security 表格（model.security 只收錄「有填」的列，
  // 與 switch_analyzer 掃描全部真實介面的語意略有不同——這裡僅能掃描使用者已在 Interface
  // 表格填寫的列）
  const secPorts=new Set((model.security||[]).map(s=>s.port));
  const noAuth=ifaces.filter(i=>(i.mode==='access'||i.mode==='trunk')&&!secPorts.has(i.name));
  f('security-off', tr('genaudit.check_security_off'), noAuth.length, 'medium',
    noAuth.length?noAuth.map(i=>i.name).join(', '):none);
  // 4. STP Edge Port 未啟用 BPDU Guard
  const stpPorts=(model.stp&&Array.isArray(model.stp.ports))?model.stp.ports:[];
  const noBpduGuard=stpPorts.filter(p=>p.portfast&&!p.bpduguard);
  f('stp-no-bpduguard', tr('genaudit.check_stp_no_bpduguard'), noBpduGuard.length, 'medium',
    noBpduGuard.length?noBpduGuard.map(p=>p.port).join(', '):none);
  // 5. ACL 存在允許 any-to-any 的規則
  const isAnyAddr=v=>/^any$/i.test(String(v||'').trim());
  const anyAnyRules=[];
  (model.acl||[]).forEach(acl=>{
    (acl.rules||[]).forEach(r=>{
      if(/^(permit|accept)$/i.test(r.action||'')&&isAnyAddr(r.src)&&isAnyAddr(r.dst))anyAnyRules.push(`${acl.name}${r.seq?'#'+r.seq:''}`);
    });
  });
  f('acl-any-any', tr('genaudit.check_acl_any_any'), anyAnyRules.length, 'high',
    anyAnyRules.length?anyAnyRules.join(', '):none);
  // 6. 完全未使用（無 access 埠成員）卻仍出現在某條 trunk 允許清單的 VLAN
  const unusedTrunkVlans=(model.vlans||[]).map(v=>{
    const vid=String(v.id);
    const accessCount=ifaces.filter(i=>i.mode==='access'&&String(i.accessVlan)===vid).length;
    const trunkCount=ifaces.filter(i=>i.mode==='trunk'&&(i.trunkVlans||'').split(/[\s,]+/).includes(vid)).length;
    return{id:v.id,accessCount,trunkCount};
  }).filter(v=>v.accessCount===0&&v.trunkCount>0);
  f('unused-vlan-trunk', tr('genaudit.check_unused_vlan_trunk'), unusedTrunkVlans.length, 'low',
    unusedTrunkVlans.length?unusedTrunkVlans.map(v=>`V${v.id}`).join(', '):none);
  // 7. 管理介面未停用 Telnet（僅供參考——並非所有廠牌預設就是啟用 Telnet，見
  // model.mgmtTelnetDisable 既有註解，此處僅提示「使用者尚未主動停用」）
  f('telnet-mgmt', tr('genaudit.check_telnet_mgmt'), model.mgmtTelnetDisable?0:1, 'high',
    model.mgmtTelnetDisable?none:tr('genaudit.telnet_enabled_detail'));
  // 8. SNMP Community 為業界公認預設弱名稱（public/private）
  const defaultCommunity=/^(public|private)$/i.test((model.snmpCommunity||'').trim());
  f('snmp-default-name', tr('genaudit.check_snmp_default_name'), defaultCommunity?1:0, 'high',
    defaultCommunity?model.snmpCommunity:none);
  // 9. OSPF/BGP 未設定認證金鑰（僅檢查「完全沒填」，欄位本身填了但過於簡單由上方
  // weakAuthKeyWarnings() 另行提示，兩者互補不重複）
  const noRoutingAuth=[];
  (model.ospf||[]).forEach(o=>{if(!o.authKey)noRoutingAuth.push('OSPF');});
  (model.bgp||[]).forEach(b=>{if((b.peers||[]).length&&!(b.peers||[]).some(p=>p.authKey))noRoutingAuth.push('BGP');});
  f('routing-no-auth', tr('genaudit.check_routing_no_auth'), noRoutingAuth.length, 'medium',
    noRoutingAuth.length?noRoutingAuth.join(', '):none);
  // 10. 已填寫的介面缺少描述文字
  const noDescIfaces=ifaces.filter(i=>!(i.desc||'').trim());
  f('if-no-desc', tr('genaudit.check_if_no_desc'), noDescIfaces.length, 'low',
    noDescIfaces.length?noDescIfaces.map(i=>i.name).join(', '):none);
  return findings;
}

function computeGeneratorAuditHealth(model){
  const findings=analyzeGeneratorAudit(model);
  let score=100;
  const issues=[];
  const WEIGHT={high:10,medium:5,low:3};
  const SEV={high:'crit',medium:'warn',low:'info'};
  findings.forEach(f=>{
    if(f.value>0){
      score-=f.value*(WEIGHT[f.risk]||WEIGHT.low);
      issues.push({sev:SEV[f.risk]||'info',label:f.check,count:f.value});
    }
  });
  score=Math.max(0,Math.min(100,score));
  const grade=score>=90?'A':score>=75?'B':score>=60?'C':score>=40?'D':'F';
  const gradeColor=grade==='A'?'var(--green)':grade==='B'?'var(--teal)':grade==='C'?'var(--yellow)':grade==='D'?'var(--orange)':'var(--red)';
  return {score,grade,gradeColor,issues};
}

// ── 設定模板欄位級 diff（2026-09-23 新增，任務2）──────────────────────────
// 目的僅是「正確可用、清楚呈現」，不追求 firewall_analyzer 那種陣列 key-based 精細比對——
// 把兩個 model 物件展開成 {路徑:葉值} 的扁平表後逐路徑比對，陣列以索引展開（[0]/[1]/...），
// 長度不同的陣列會讓多出的索引路徑只出現在其中一邊，同樣能正確反映出差異。
function flattenForDiff(obj, prefix, out){
  out=out||{};
  const key=prefix||'(root)';
  if(obj===null||obj===undefined){ out[key]=obj; return out; }
  if(Array.isArray(obj)){
    if(!obj.length){ out[key]=obj; return out; }
    obj.forEach((v,i)=>flattenForDiff(v, prefix?`${prefix}[${i}]`:`[${i}]`, out));
    return out;
  }
  if(typeof obj==='object'){
    const keys=Object.keys(obj);
    if(!keys.length){ out[key]=obj; return out; }
    keys.forEach(k=>flattenForDiff(obj[k], prefix?`${prefix}.${k}`:k, out));
    return out;
  }
  out[key]=obj;
  return out;
}
function diffTemplateModels(modelA, modelB){
  const flatA=flattenForDiff(modelA||{});
  const flatB=flattenForDiff(modelB||{});
  const paths=Array.from(new Set([...Object.keys(flatA), ...Object.keys(flatB)])).sort();
  const diffs=[];
  paths.forEach(path=>{
    const a=flatA[path], b=flatB[path];
    if(JSON.stringify(a)!==JSON.stringify(b))diffs.push({path, oldValue:a, newValue:b});
  });
  return diffs;
}

// VLAN 範圍輸入解析（2026-09-24 新增）：把「10-20,30」這類字串展開成 VLAN ID 陣列，供 VLAN
// 表格一次新增多列。接受逗號／空白分隔、a-b 範圍；超出 1-4094、格式錯誤、範圍顛倒的片段放進
// invalid 不中斷其餘片段；結果去重並依數字排序。純函式，不碰 DOM
function parseVlanRangeSpec(spec){
  const ids=new Set(),invalid=[];
  String(spec||'').split(/[,\s]+/).filter(Boolean).forEach(tok=>{
    const m=tok.match(/^(\d+)(?:-(\d+))?$/);
    if(!m){invalid.push(tok);return;}
    const a=Number(m[1]),b=m[2]===undefined?a:Number(m[2]);
    if(a<1||b>4094||a>b){invalid.push(tok);return;}
    for(let i=a;i<=b;i++)ids.add(i);
  });
  return {ids:[...ids].sort((x,y)=>x-y).map(String),invalid};
}

// 介面批次套用選取（2026-09-24 新增）：spec 以逗號／空白分隔多個片段，每段為「名稱結尾」加上
// 編號或編號範圍，例如 1/0/1-24、port1-8、ge-0/0/3。介面名稱需以「前綴＋編號」結尾，且前綴前
// 一個字元不是數字（避免 1/0/1 誤中 11/0/1），才算命中。回傳命中的索引（依表格順序）與無法
// 解析的片段；純函式，不碰 DOM
function matchIfaceNamesBySpec(names, spec){
  const hit=new Set(),invalid=[];
  String(spec||'').split(/[,\s]+/).filter(Boolean).forEach(tok=>{
    const m=tok.match(/^(.*?)(\d+)(?:-(\d+))?$/);
    if(!m){invalid.push(tok);return;}
    const prefix=m[1],a=Number(m[2]),b=m[3]===undefined?a:Number(m[3]);
    if(a>b){invalid.push(tok);return;}
    names.forEach((n,i)=>{
      const name=String(n||'');
      const nm=name.match(/(\d+)$/);
      if(!nm)return;
      const num=Number(nm[1]);
      if(num<a||num>b)return;
      const head=name.slice(0,name.length-nm[1].length);
      if(!head.endsWith(prefix))return;
      const before=head.slice(0,head.length-prefix.length);
      if(prefix&&/\d$/.test(before)&&/^\d/.test(prefix))return;
      hit.add(i);
    });
  });
  return {indexes:[...hit].sort((x,y)=>x-y),invalid};
}

// 表單草稿是否有實質內容（2026-09-24 新增）：有主機名稱，或任一頂層陣列欄位（VLAN／介面／
// 路由／ACL…）非空即算。用於自動暫存時避免把空白表單存成草稿、下次開頁時跳出無意義的還原提示。
// collectModel() 在主機名稱留空時會自動補 'Switch'，故該預設值視同未填
function draftModelHasContent(model){
  if(!model||typeof model!=='object')return false;
  const name=String(model.sysname||'').trim();
  if(name&&name!=='Switch')return true;
  return Object.values(model).some(v=>Array.isArray(v)&&v.length>0);
}

// 匯入原始設定 vs 產生結果比對前的正規化（2026-09-24 新增）：去掉每行首尾空白、空白行與整行註解
// （! 或 # 開頭；Comware 的區塊結尾 # 本身不帶設定內容，一併略過不影響比對），避免縮排、空行與
// 產生器自己加的免責註解讓真正的設定差異被格式差異淹沒。純函式，回傳行陣列
function normalizeConfigLinesForDiff(text){
  return String(text||'').replace(/\r\n/g,'\n').split('\n').map(l=>l.trim()).filter(l=>l&&!/^[!#]/.test(l));
}

// 介面描述命名範本（2026-09-24 新增）：替換 {name}（介面名稱）、{n}（名稱最後的編號）、
// {hostname}（主機名稱）、{vlan}（該介面 Access VLAN）；不認得的佔位符原樣保留，方便使用者
// 發現打錯字。無佔位符時原字串直接回傳。純函式
function renderIfaceDescTemplate(tpl,ctx){
  const c=ctx||{};
  const num=(String(c.name||'').match(/(\d+)$/)||[])[1]||'';
  const map={name:c.name||'',n:num,hostname:c.hostname||'',vlan:c.vlan||''};
  return String(tpl||'').replace(/\{(\w+)\}/g,(m,k)=>Object.prototype.hasOwnProperty.call(map,k)?map[k]:m);
}
