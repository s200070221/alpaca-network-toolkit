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
