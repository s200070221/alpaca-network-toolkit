// ============================================================
// switch_config_generator：驗證／警告純函式（2026-09 從 switch-generator-app.js 拆出）
// ============================================================
// 純函式，零 DOM 依賴（比照 switch_analyzer 側 switch-analyzer-topology.js／
// switch-analyzer-audit.js 同批拆分先例，以及更早的 switch-analyzer-diff.js／
// firewall-analyzer-audit.js 拆分傳統）——switch-generator-app.js 本身頂層有多處立即執行的
// DOM 綁定，純函式若寫進該檔會導致 Node 測試沙箱一讀取整檔就因 document is not defined 拋錯。
// 涵蓋：IPv4/CIDR 格式驗證、常用機種 port 集合查詢、Comware OSPF network/LACP 屬性一致性警告。

function isValidIPv4(s){
  const m=(s||'').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every(o=>parseInt(o,10)<=255);
}

function isValidCIDR(s){
  const m=(s||'').match(/^(\S+)\/(\d{1,2})$/);
  return !!m && isValidIPv4(m[1]) && parseInt(m[2],10)>=0 && parseInt(m[2],10)<=32;
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
