// ============================================================
// switch_analyzer：設定稽核與健康度評分（2026-09 從 switch-analyzer-app.js 拆出）
// ============================================================
// 純函式，零 DOM／parsed 全域依賴（比照 switch-analyzer-diff.js／firewall-analyzer-audit.js
// 既有拆分先例）。detectVlanIslands() 找「有 access 埠但沒被任何 trunk 攜帶」的孤島 VLAN；
// analyzeSwitchAudit() 是稽核規則清單（弱密碼/STP/VLAN1/802.1X/SNMP/Telnet/路由認證/ACL any-any/
// 未用 VLAN 仍在 trunk）；computeSwitchHealth() 依 analyzeSwitchAudit() 結果換算 A-F 健康度分數
// （比照 firewall_analyzer computeFirewallHealth() 同一套權重與門檻）。

function detectVlanIslands(p){
  const ifaces = p.interfaces || [];
  return (p.vlans || []).filter(v => !v.implied).map(v => {
    const vid = String(v.id);
    const access = ifaces.filter(i => i.mode === 'access' && String(i.nativeVlan) === vid);
    const trunk = ifaces.filter(i => i.mode === 'trunk' && (i.vlans === 'all' || (i.vlans||'').split(/[\s,]+/).includes(vid)));
    return {id: v.id, name: v.name||'—', accessCount: access.length, trunkCount: trunk.length};
  }).filter(v => v.trunkCount === 0 && v.accessCount > 0);
}

// 同裝置 IP/子網衝突偵測共用 helper（2026-09-15 新增，供 detectSameDeviceIpConflicts() 使用）。
// 不跨檔案 import 其他模組已有的 cidrFromMask()（定義在 switch-analyzer-parser-comware.js，
// 本檔案供獨立測試沙箱抽取時不見得會一併載入該檔），改用位元計數自行換算遮罩→前綴長度，
// 沿用本專案「各工具/模組各自維護一份純函式」慣例。
// _normalizeIpMask()：相容既有 parser 三種輸出格式——SVI 多半已是 "A.B.C.D/N" CIDR 字串，
// Loopback/Management/routed port 多半是尚未轉換的 "A.B.C.D M.M.M.M" 空白分隔原始格式（已於
// Cisco/Arista parser 逐一確認），裸 IP（無遮罩）視為 /32 主機路由；IPv6（含 ':'）直接排除
// 不處理，此項偵測僅涵蓋 IPv4
function _maskToPrefixLen(mask){
  return mask.split('.').reduce((acc,octet)=>acc+((parseInt(octet,10)>>>0).toString(2).match(/1/g)||[]).length,0);
}
function _normalizeIpMask(raw){
  const s=String(raw||'').trim();
  if(!s||s.includes(':'))return null;
  let m=s.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if(m)return{ip:m[1],prefixLen:parseInt(m[2],10)};
  m=s.match(/^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$/);
  if(m)return{ip:m[1],prefixLen:_maskToPrefixLen(m[2])};
  m=s.match(/^(\d+\.\d+\.\d+\.\d+)$/);
  if(m)return{ip:m[1],prefixLen:32};
  return null;
}
function _ipToInt(ip){
  const p=ip.split('.').map(Number);
  return((p[0]*256+p[1])*256+p[2])*256+p[3];
}
// 用除法/乘法算網段範圍而非位元位移——JS 的 <</>>> 位移量對 32 取模，prefixLen=0（遮罩
// 位元數=32）时若用 `x >>> 32` 會被當成 `x >>> 0`（原樣不變）而非預期的歸零，改用數值運算
// 完全避開此陷阱；ipInt 最大值 2^32-1，遠低於 Number.MAX_SAFE_INTEGER，除乘法運算安全精確
function _networkRange(o){
  const ipInt=_ipToInt(o.ip);
  const hostBits=32-o.prefixLen;
  const size=hostBits>=32?4294967296:Math.pow(2,hostBits);
  const netInt=Math.floor(ipInt/size)*size;
  return[netInt,netInt+size-1];
}
function _subnetsOverlap(a,b){
  const[aLo,aHi]=_networkRange(a);
  const[bLo,bHi]=_networkRange(b);
  return aLo<=bHi&&bLo<=aHi;
}
// 同裝置 IP/子網衝突偵測（含 VRF 感知，2026-09-15 新增）：依 interface.vrf 分組（RouterOS 無
// vrf 欄位，undefined 與空字串視為同一預設 VRF bucket），組內任兩個位址（含次要IP陣列）比對
// 子網是否重疊；同一介面自身的 primary/secondary IP 不視為衝突（本來就允許同介面掛多個子網）
function detectSameDeviceIpConflicts(parsed){
  const interfaces=parsed.interfaces||[];
  const groups=new Map();
  interfaces.forEach(iface=>{
    const vrfKey=iface.vrf||'';
    if(!groups.has(vrfKey))groups.set(vrfKey,[]);
    const addrs=[iface.ip,...(iface.secondaryIps||[])].filter(Boolean);
    addrs.forEach(raw=>{
      const norm=_normalizeIpMask(raw);
      if(norm)groups.get(vrfKey).push({iface:iface.name,ip:norm.ip,prefixLen:norm.prefixLen});
    });
  });
  const conflicts=[];
  groups.forEach(entries=>{
    for(let i=0;i<entries.length;i++){
      for(let j=i+1;j<entries.length;j++){
        const a=entries[i],b=entries[j];
        if(a.iface===b.iface)continue;
        if(_subnetsOverlap(a,b))conflicts.push({ifaceA:a.iface,ifaceB:b.iface,sameIp:a.ip===b.ip});
      }
    }
  });
  return conflicts;
}

// switch ACL 規則遮蔽/冗餘偵測共用 helper（2026-09-15 新增）。核心比對邏輯無法直接移植
// firewall_analyzer 的 analyzeRuleShadowing()（那是字串/具名物件集合相等性比對），switch ACL
// 的 src/dst 是「網段+萬用遮罩」需要真正數值位元運算，僅外層演算法骨架可移植；複用 B2 項目
// 已有的 _ipToInt()/_networkRange()。
// _aclAddrToRange()：相容三種既有 parser 輸出格式——'any'（全範圍）、'host X.X.X.X'（單一
// 位址）、'A.B.C.D W.X.Y.Z'（Cisco 傳統萬用遮罩，網段+遮罩以單一字串內含空白儲存）、
// 'A.B.C.D/N'（NX-OS 等 CIDR 格式，複用 _networkRange()）；非連續萬用遮罩（技術上合法但
// 極罕見）與其他解析失敗情況一律回傳 null 不猜測
function _aclAddrToRange(tok){
  const s=String(tok||'').trim();
  if(!s||s==='-')return null;
  if(/^any$/i.test(s))return[0,4294967295];
  let m=s.match(/^host\s+(\d+\.\d+\.\d+\.\d+)$/i);
  if(m){const ip=_ipToInt(m[1]);return[ip,ip];}
  m=s.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if(m)return _networkRange({ip:m[1],prefixLen:parseInt(m[2],10)});
  m=s.match(/^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$/);
  if(m){
    const netRaw=_ipToInt(m[1]),wildcard=_ipToInt(m[2]);
    if(wildcard===4294967295)return[0,4294967295];
    const p=wildcard+1;
    if(p<=0||(p&(p-1))!==0)return null;
    const network=(netRaw&(~wildcard))>>>0;
    return[network,network+wildcard];
  }
  return null;
}
// 區間涵蓋判斷：earlier 的比對範圍是否完全包含 later 的比對範圍
function _aclCovers(earlierRange,laterRange){
  return earlierRange[0]<=laterRange[0]&&earlierRange[1]>=laterRange[1];
}
function _aclProtoCovers(earlierProto,laterProto){
  const e=String(earlierProto||'').toLowerCase();
  if(e===''||e==='ip'||e==='any')return true;
  return e===String(laterProto||'').toLowerCase();
}
// dstPort 僅做完全比對；range/多值比對不做完整區間運算（已知不支援範圍，見計畫文件）
function _aclPortCovers(earlierPort,laterPort){
  if(!earlierPort)return true;
  return earlierPort===laterPort;
}
// 規則遮蔽偵測：依 seq 排序後，逐一檢查較晚出現的規則是否已被較早規則完全涵蓋（protocol/src/dst/
// dstPort 皆需涵蓋才算），不要求動作（action）相同——即使 earlier 是 deny、later 是 permit，
// later 依然永遠不會生效，同屬「規則不可達」訊號。RouterOS 排除：parsed.acls 本身是扁平規則
// 陣列（非巢狀 {name,rules:[]}），下方 Array.isArray(acl.rules) guard 天然排除，不需另開分支
function analyzeAclShadowing(acls){
  const shadowed=[];
  (acls||[]).forEach(acl=>{
    if(!Array.isArray(acl.rules))return;
    const rules=acl.rules.filter(r=>/^(permit|deny|accept)$/i.test(r.action||''));
    const sorted=rules.map((r,idx)=>({r,idx})).sort((a,b)=>{
      const sa=Number(a.r.seq),sb=Number(b.r.seq);
      if(Number.isFinite(sa)&&Number.isFinite(sb)&&sa!==sb)return sa-sb;
      return a.idx-b.idx;
    });
    for(let i=0;i<sorted.length;i++){
      const earlier=sorted[i].r;
      const earlierSrc=_aclAddrToRange(earlier.src),earlierDst=_aclAddrToRange(earlier.dst);
      if(!earlierSrc||!earlierDst)continue;
      for(let j=i+1;j<sorted.length;j++){
        const later=sorted[j].r;
        const laterSrc=_aclAddrToRange(later.src),laterDst=_aclAddrToRange(later.dst);
        if(!laterSrc||!laterDst)continue;
        if(!_aclCovers(earlierSrc,laterSrc))continue;
        if(!_aclCovers(earlierDst,laterDst))continue;
        if(!_aclProtoCovers(earlier.protocol,later.protocol))continue;
        if(!_aclPortCovers(earlier.dstPort,later.dstPort))continue;
        shadowed.push({acl:acl.name,earlierSeq:earlier.seq,laterSeq:later.seq});
      }
    }
  });
  return shadowed;
}
// 完全重複規則：純字串鍵值分組（action/protocol/src/dst/dstPort 完全相同），不需位元運算，
// 比照 firewall_analyzer analyzeExactDuplicates() 手法自行實作一份
function analyzeAclExactDuplicates(acls){
  const duplicates=[];
  (acls||[]).forEach(acl=>{
    if(!Array.isArray(acl.rules))return;
    const seen=new Map();
    acl.rules.forEach(r=>{
      if(!/^(permit|deny|accept)$/i.test(r.action||''))return;
      const key=[r.action,r.protocol,r.src,r.dst,r.dstPort].map(v=>String(v||'').toLowerCase().trim()).join('|');
      if(seen.has(key))duplicates.push({acl:acl.name,seq:r.seq,dupOfSeq:seen.get(key)});
      else seen.set(key,r.seq);
    });
  });
  return duplicates;
}

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
  // 5b. SNMP community 名稱為業界公認預設弱名稱（public/private，2026-08-29 新增，使用者發想
  // 5 項新功能第 4 項）：上方第 5 項「任何 v1/v2c community 存在即算 high」已涵蓋大方向，本項
  // 細分出「使用未經任何客製化的預設名稱」這個信號更明確的子集合，risk 沿用同一等級（high），
  // 與第 5 項並存、非取代——即使已改成自訂 community 名稱，第 5 項仍會提醒 v1/v2c 本身的風險
  const defaultCommunityNames=(snmp&&snmp.communities?snmp.communities:[]).filter(c=>/^(public|private)$/i.test((c.name||'').trim()));
  f('snmp-default-name', tr('audit.check_snmp_default_name'), defaultCommunityNames.length, 'high',
    defaultCommunityNames.length?defaultCommunityNames.map(c=>c.name).slice(0,8).join(', ')+(defaultCommunityNames.length>8?'…':''):tr('audit.none'),
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
  // 8. ACL 存在允許 any-to-any 的規則（2026-09 新增）。多數廠牌的 ACL rules[] 都是巢狀在
  // acls[].rules[] 底下（Cisco/NXOS/Comware/Aruba CX/Extreme/FortiSwitch/Netgear/Planet
  // 皆為此形狀，src/dst 皆可能是字面 'any'）；RouterOS 是扁平陣列（parsed.acls 本身就是
  // rule 清單，'any' 語意是「該欄位留空」而非字面 'any' 字串），語意不同、刻意用
  // Array.isArray(acl.rules) 排除，避免誤判或漏判
  const acls=parsed.acls||[];
  const isAnyAddr=v=>/^any$/i.test(String(v||'').trim());
  const anyAnyRules=[];
  acls.forEach(acl=>{
    if(!Array.isArray(acl.rules))return;
    acl.rules.forEach(r=>{
      if(/^(permit|accept)$/i.test(r.action||'')&&isAnyAddr(r.src)&&isAnyAddr(r.dst))anyAnyRules.push(`${acl.name}${r.seq?'#'+r.seq:''}`);
    });
  });
  f('acl-any-any', tr('audit.check_acl_any_any'), anyAnyRules.length, 'high',
    anyAnyRules.length?anyAnyRules.slice(0,8).join(', ')+(anyAnyRules.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.8.20','PCI-DSS 4.0 1.3.1/1.3.2','NIST 800-53 SC-7','CIS v8 12.2']);
  // 9. 完全未使用（無 access 埠成員）卻仍出現在某條 trunk allowed VLAN 清單的 VLAN
  // （2026-09 新增，鏡像既有 detectVlanIslands() 邏輯：該函式找「有 access 埠但沒被 trunk」
  // 的 VLAN，此處反過來找「沒有 access 埠卻還被 trunk 攜帶」的 VLAN，同屬設定 hygiene
  // 訊號——不必要地擴大廣播網域範圍，建議 trunk 修剪）
  const unusedTrunkVlans=(parsed.vlans||[]).filter(v=>!v.implied).map(v=>{
    const vid=String(v.id);
    const accessCount=interfaces.filter(i=>i.mode==='access'&&String(i.nativeVlan)===vid).length;
    const trunkCount=interfaces.filter(i=>i.mode==='trunk'&&(i.vlans==='all'||(i.vlans||'').split(/[\s,]+/).includes(vid))).length;
    return{id:v.id,name:v.name||'—',accessCount,trunkCount};
  }).filter(v=>v.accessCount===0&&v.trunkCount>0);
  f('unused-vlan-trunk', tr('audit.check_unused_vlan_trunk'), unusedTrunkVlans.length, 'low',
    unusedTrunkVlans.length?unusedTrunkVlans.map(v=>`V${v.id}`).slice(0,8).join(', ')+(unusedTrunkVlans.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.8.20','CIS v8 12.2']);
  // 10. LACP 群組成員埠設定不一致（2026-09-14 新增）：同一聚合群組的成員埠理論上應共用相同
  // 交換器層設定（mode/access VLAN），不一致代表設定飄移或誤將不相干埠加入群組。members 欄位
  // 正規化邏輯與 switch-analyzer-app.js 的 _lacpMembersArr() 同款複製一份（不跨檔案 import）
  const _lacpMembersArr=x=>Array.isArray(x.members)?x.members:String(x.members||'').split(',').map(s=>s.trim()).filter(Boolean);
  const lacpMismatch=[];
  (parsed.lacp||[]).forEach(l=>{
    const memNames=_lacpMembersArr(l).map(m=>typeof m==='string'?m:m.name);
    const memIfaces=memNames.map(n=>interfaces.find(i=>i.name===n)).filter(Boolean);
    if(memIfaces.length<2)return;
    const modes=new Set(memIfaces.map(i=>i.mode||''));
    const accessVlans=new Set(memIfaces.filter(i=>i.mode==='access').map(i=>String(i.nativeVlan||'')));
    if(modes.size>1||accessVlans.size>1)lacpMismatch.push(l.name);
  });
  f('lacp-member-mismatch', tr('audit.check_lacp_member_mismatch'), lacpMismatch.length, 'medium',
    lacpMismatch.length?lacpMismatch.slice(0,8).join(', ')+(lacpMismatch.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.8.20','CIS v8 4.1']);
  // 11. 實體/堆疊介面缺少描述文字（2026-09-14 新增，port==='physical'||'stack' 篩選慣例沿用
  // switch-analyzer-app.js 既有多處 `i.type==='physical'||i.type==='stack'` 寫法）
  const noDescIfaces=interfaces.filter(i=>(i.type==='physical'||i.type==='stack')&&!(i.desc||'').trim());
  f('if-no-desc', tr('audit.check_if_no_desc'), noDescIfaces.length, 'low',
    noDescIfaces.length?noDescIfaces.map(i=>i.name).slice(0,8).join(', ')+(noDescIfaces.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.5.9','CIS v8 1.1']);
  // 12-13. STP 誤設組合檢查（2026-09-14 新增，RouterOS 無 parsed.stp.ports[]，沿用既有第 2 項的
  // Array.isArray guard）：(a) PortFast 與 Trunk 模式同時啟用於同一埠——PortFast 設計前提是
  // 該埠僅接終端裝置，接在 Trunk 上聯埠會讓迴圈偵測失效；(b) 已啟用 BPDU Guard（代表設定者已
  // 意識到邊界安全）卻在 Trunk 上聯埠遺漏 Root Guard，同屬「防護不完整」訊號
  const stpPortsForCombo=Array.isArray(parsed?.stp?.ports)?parsed.stp.ports:[];
  const stpPortfastTrunk=stpPortsForCombo.filter(sp=>{
    const iface=interfaces.find(i=>i.name===sp.port);
    return sp.portfast&&iface&&iface.mode==='trunk';
  });
  f('stp-portfast-trunk', tr('audit.check_stp_portfast_trunk'), stpPortfastTrunk.length, 'medium',
    stpPortfastTrunk.length?stpPortfastTrunk.map(sp=>sp.port).slice(0,8).join(', ')+(stpPortfastTrunk.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.8.20','CIS v8 12.2']);
  const anyBpduGuard=stpPortsForCombo.some(sp=>sp.bpduguard);
  const trunkNoRootGuard=anyBpduGuard?stpPortsForCombo.filter(sp=>{
    const iface=interfaces.find(i=>i.name===sp.port);
    return iface&&iface.mode==='trunk'&&!sp.guardRoot;
  }):[];
  f('stp-uplink-no-rootguard', tr('audit.check_stp_uplink_no_rootguard'), trunkNoRootGuard.length, 'low',
    trunkNoRootGuard.length?trunkNoRootGuard.map(sp=>sp.port).slice(0,8).join(', ')+(trunkNoRootGuard.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.8.20','CIS v8 12.2']);
  // 14-15. 同裝置 IP/子網衝突（2026-09-15 新增，含 VRF 感知）：拆成兩項獨立發現而非同一項用
  // 混合風險等級——完全相同 IP（設定錯誤/直接衝突，high）與子網重疊但 IP 不同（可能是刻意
  // 規劃的次要IP或誤設，medium）本質不同，比照既有稽核項目「一項一個風險等級」慣例
  const ipConflicts=detectSameDeviceIpConflicts(parsed);
  const exactIpConflicts=ipConflicts.filter(c=>c.sameIp);
  const subnetOnlyConflicts=ipConflicts.filter(c=>!c.sameIp);
  f('ip-conflict-exact', tr('audit.check_ip_conflict_exact'), exactIpConflicts.length, 'high',
    exactIpConflicts.length?exactIpConflicts.map(c=>`${c.ifaceA}↔${c.ifaceB}`).slice(0,8).join(', ')+(exactIpConflicts.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.8.20','CIS v8 12.2']);
  f('ip-subnet-conflict', tr('audit.check_ip_subnet_conflict'), subnetOnlyConflicts.length, 'medium',
    subnetOnlyConflicts.length?subnetOnlyConflicts.map(c=>`${c.ifaceA}↔${c.ifaceB}`).slice(0,8).join(', ')+(subnetOnlyConflicts.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.8.20','CIS v8 12.2']);
  // 16-17. switch ACL 規則遮蔽/冗餘偵測（2026-09-15 新增）
  const aclShadowed=analyzeAclShadowing(parsed.acls);
  const aclExactDup=analyzeAclExactDuplicates(parsed.acls);
  f('acl-shadowed', tr('audit.check_acl_shadowed'), aclShadowed.length, 'medium',
    aclShadowed.length?aclShadowed.map(s=>`${s.acl}#${s.laterSeq}`).slice(0,8).join(', ')+(aclShadowed.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.8.20','CIS v8 12.2']);
  f('acl-exact-duplicate', tr('audit.check_acl_exact_duplicate'), aclExactDup.length, 'low',
    aclExactDup.length?aclExactDup.map(d=>`${d.acl}#${d.seq}`).slice(0,8).join(', ')+(aclExactDup.length>8?'…':''):tr('audit.none'),
    ['ISO27001 A.8.20','CIS v8 12.2']);
  return findings;
}

function computeSwitchHealth(parsed){
  const findings=analyzeSwitchAudit(parsed);
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
