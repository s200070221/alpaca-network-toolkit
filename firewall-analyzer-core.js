// ── IP/Policy Query: IP 比對工具 ──────────────────────────────────────────
function _ipToInt(ip) {
  const p = ip.trim().split('.');
  if (p.length !== 4) return null;
  return ((+p[0]<<24)|(+p[1]<<16)|(+p[2]<<8)|(+p[3])) >>> 0;
}
function _maskToInt(mask) {
  if (mask.includes('.')) return _ipToInt(mask);
  const bits = parseInt(mask);
  return bits === 0 ? 0 : (0xFFFFFFFF << (32-bits)) >>> 0;
}
// 2026-08-29 新增（使用者發想 5 項新功能第 3 項，過寬規則偵測用）：回傳遮罩的前綴長度
// （0-32），支援 "/N" 數字字串與點分遮罩兩種格式；點分遮罩額外驗證是否為合法的連續前綴
// （非任意位元組合，如 255.0.255.0 這種非連續遮罩回傳 null，避免誤判前綴長度）
function _cidrPrefixLen(mask) {
  if (mask == null) return null;
  const m = String(mask).trim();
  if (!m) return null;
  if (m.includes('.')) {
    const maskInt = _ipToInt(m);
    if (maskInt === null) return null;
    let bits = 0, v = maskInt >>> 0;
    while (v) { bits += v & 1; v >>>= 1; }
    const expected = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    return expected === maskInt ? bits : null;
  }
  const n = parseInt(m, 10);
  return (Number.isInteger(n) && n >= 0 && n <= 32) ? n : null;
}
// 從 srcAddr/dstAddr 欄位裡「本身就是字面 CIDR」的 token 解析前綴長度（如 MikroTik 的
// "0.0.0.0/0"），非具名 address 物件參照；解析不出（含裸 IP 無遮罩，視為 /32 非過寬）
// 或格式不符時回傳 null
function _extractLiteralCidrPrefixLen(str) {
  if (!str) return null;
  const s = String(str).trim();
  const m = s.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s*\/\s*(\d{1,2})|\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?$/);
  if (!m) return null;
  if (m[2]) return _cidrPrefixLen(m[2]);
  if (m[3]) return _cidrPrefixLen(m[3]);
  return 32;
}
function _ipInSubnet(targetInt, subnetStr) {
  const s = subnetStr.replace('/', ' ').trim();
  const parts = s.split(/\s+/);
  const ipInt = _ipToInt(parts[0]), maskInt = _maskToInt(parts[1]||'32');
  if (ipInt === null || maskInt === null) return null;
  const net = (ipInt & maskInt) >>> 0;
  return targetInt >= net && targetInt <= ((net | (~maskInt >>> 0)) >>> 0);
}
function _ipInRange(targetInt, startStr, endStr) {
  const si = _ipToInt(startStr), ei = _ipToInt(endStr);
  return si !== null && ei !== null && targetInt >= si && targetInt <= ei;
}
function _addrMatchesIp(name, targetInt, addrList, seen) {
  const nm = name.trim().toLowerCase();
  if (nm==='all'||nm==='any') return true;
  if (seen.has(nm)) return false;
  seen.add(nm);
  const obj = addrList.find(a => a.name.toLowerCase()===nm);
  if (!obj) return null;
  if (obj.type==='ipmask' && obj.subnet && obj.subnet!=='-')
    return _ipInSubnet(targetInt, obj.subnet);
  if (obj.type==='iprange')
    return _ipInRange(targetInt, obj.startIp, obj.endIp);
  if (obj.type==='fqdn') return null;
  if (obj.type==='group'||obj.category==='address-group') {
    const mems = (obj.members||'').split(',').map(s=>s.trim()).filter(Boolean);
    let fqdn = false;
    for (const m of mems) {
      const r = _addrMatchesIp(m, targetInt, addrList, seen);
      if (r===true) return true;
      if (r===null) fqdn=true;
    }
    return fqdn ? null : false;
  }
  return false;
}
function _policyAddrMatches(addrStr, targetInt, addrList) {
  const names = (addrStr||'').split(',').map(s=>s.trim()).filter(Boolean);
  let fqdn = false;
  for (const n of names) {
    const r = _addrMatchesIp(n, targetInt, addrList, new Set());
    if (r===true) return true;
    if (r===null) fqdn=true;
  }
  return fqdn ? null : false;
}
function _portInRange(port, rangeStr) {
  if (!rangeStr||rangeStr==='-') return false;
  const p = rangeStr.split('-');
  return port >= parseInt(p[0]) && port <= (p[1]?parseInt(p[1]):parseInt(p[0]));
}
function _svcMatches(name, proto, port, svcList, seen) {
  const nm = name.trim().toUpperCase();
  if (nm==='ALL'||nm==='ANY') return true;
  if (seen.has(nm)) return false;
  seen.add(nm);
  const obj = svcList.find(s=>s.name.toUpperCase()===nm);
  if (!obj) return true;
  if (obj.category==='group') {
    const mems = (obj.members||'').split(',').map(s=>s.trim()).filter(Boolean);
    return mems.some(m=>_svcMatches(m, proto, port, svcList, seen));
  }
  if (!proto||proto==='any') return true;
  const p = proto.toUpperCase();
  if (p==='ICMP'&&obj.proto==='ICMP') return true;
  const tcpOk = (p==='TCP'||p==='TCP/UDP')&&(obj.proto==='TCP'||obj.proto==='TCP/UDP')
    &&(!port||_portInRange(port,obj.tcpPorts));
  const udpOk = (p==='UDP'||p==='TCP/UDP')&&(obj.proto==='UDP'||obj.proto==='TCP/UDP')
    &&(!port||_portInRange(port,obj.udpPorts));
  return tcpOk||udpOk;
}
function _policySvcMatches(svcStr, proto, port, svcList) {
  const names = (svcStr||'ALL').split(',').map(s=>s.trim()).filter(Boolean);
  return names.some(n=>_svcMatches(n, proto, port, svcList, new Set()));
}
function _runPolicyQuery(srcStr, dstStr, proto, port, vdomFilter, PARSED) {
  if (!PARSED||!PARSED.policies) return null;
  const srcInt=_ipToInt(srcStr), dstInt=_ipToInt(dstStr);
  if (srcInt===null||dstInt===null) return {error:'invalid_ip'};
  const addrs=PARSED.addresses||[], svcs=PARSED.services||[];
  let pols = PARSED.policies;
  if (vdomFilter&&vdomFilter!=='__all__') pols=pols.filter(p=>p._vdom===vdomFilter);
  const trace=[];
  for (const p of pols) {
    if (p.status==='disable') { trace.push({policy:p,result:'disabled'}); continue; }
    const sm=_policyAddrMatches(p.srcAddr,srcInt,addrs);
    if (sm===false) { trace.push({policy:p,result:'skip',reason:'src_addr'}); continue; }
    const dm=_policyAddrMatches(p.dstAddr,dstInt,addrs);
    if (dm===false) { trace.push({policy:p,result:'skip',reason:'dst_addr'}); continue; }
    const svm=_policySvcMatches(p.service,proto,port?parseInt(port):null,svcs);
    if (!svm) { trace.push({policy:p,result:'skip',reason:'service'}); continue; }
    const resolvedSrc=_policyAddrResolve(p.srcAddr,srcInt,addrs);
    const resolvedDst=_policyAddrResolve(p.dstAddr,dstInt,addrs);
    trace.push({policy:p,result:'match',hasFqdn:sm===null||dm===null,resolvedSrc,resolvedDst});
    return {matched:p,action:p.action==='accept'?'accept':'deny',trace};
  }
  return {matched:null,action:'implicit_deny',trace};
}

function _addrResolvePath(name, targetInt, addrList, seen, pathPfx) {
  const nm = name.trim().toLowerCase(), raw = name.trim();
  if (nm==='all'||nm==='any') return {match:true, display:raw, detail:'(any)'};
  if (seen.has(nm)) return {match:false};
  seen.add(nm);
  const path = pathPfx ? pathPfx + ' → ' + raw : raw;
  const obj = addrList.find(a=>a.name.toLowerCase()===nm);
  if (!obj) return {match:null, display:path, detail:'(unresolved)'};
  if (obj.type==='ipmask'&&obj.subnet&&obj.subnet!=='-') {
    const r=_ipInSubnet(targetInt,obj.subnet);
    if (r===true)  return {match:true,  display:path, detail:obj.subnet};
    if (r===null)  return {match:null,  display:path, detail:obj.subnet};
    return {match:false};
  }
  if (obj.type==='iprange')
    return _ipInRange(targetInt,obj.startIp,obj.endIp)
      ? {match:true, display:path, detail:obj.startIp+' – '+obj.endIp}
      : {match:false};
  if (obj.type==='fqdn') return {match:null, display:path, detail:obj.fqdn+' (FQDN)'};
  if (obj.type==='group'||obj.category==='address-group') {
    const mems=(obj.members||'').split(',').map(s=>s.trim()).filter(Boolean);
    let fqdn=null;
    for(const m of mems){
      const r=_addrResolvePath(m,targetInt,addrList,seen,path);
      if(r.match===true) return r;
      if(r.match===null) fqdn=r;
    }
    return fqdn||{match:false};
  }
  return {match:false};
}
function _policyAddrResolve(addrStr, targetInt, addrList) {
  const names=(addrStr||'').split(',').map(s=>s.trim()).filter(Boolean);
  let fqdn=null;
  for(const n of names){
    const r=_addrResolvePath(n,targetInt,addrList,new Set(),'');
    if(r.match===true) return r;
    if(r.match===null) fqdn=r;
  }
  return fqdn||{match:false,display:addrStr||'-',detail:''};
}
// ── End IP/Policy Query utils ──────────────────────────────────────────────

function tr(key) {
  if (_lang === 'leet') { var s=LANG_FW.en[key]||LANG_FW.zhTW[key]||key; return s.replace(/a/gi,'4').replace(/e/gi,'3').replace(/i/gi,'1').replace(/o/gi,'0').replace(/s/gi,'5').replace(/t/gi,'7').replace(/l/gi,'|'); }
  if (_lang === 'uwu')  { var s=LANG_FW.en[key]||LANG_FW.zhTW[key]||key; return s.replace(/r/g,'w').replace(/R/g,'W').replace(/l/g,'w').replace(/L/g,'W').replace(/th/g,'d').replace(/Th/g,'D').replace(/n([aeiou])/g,'ny$1').replace(/N([AEIOU])/g,'Ny$1'); }
  if (_lang === 'cat')  { var d=LANG_FW.cat&&LANG_FW.cat[key]; if(d)return d; var base=LANG_FW.zhTW[key]||LANG_FW.en[key]||key; return base+(/[一-鿿]$/.test(base)?'喵~':' nyaa~'); }
  if (_lang === 'bean') { var d=LANG_FW.bean&&LANG_FW.bean[key]; if(d)return d; var base=LANG_FW.en[key]||LANG_FW.zhTW[key]||key; var vg=['🥕','🫛','🌽']; return base.split('').map(function(c){return c===' '?' ':vg[c.charCodeAt(0)%3];}).join(''); }
  var v = LANG_FW[_lang] && LANG_FW[_lang][key];
  if (v !== undefined && v !== '') return v;
  var en = LANG_FW.en && LANG_FW.en[key];
  if (en) return en;
  return LANG_FW.zhTW[key] || key;
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
  document.querySelectorAll('[data-i18n-title]').forEach(function(el) { el.title = tr(el.dataset.i18nTitle); });
  document.querySelectorAll('.lang-btn').forEach(function(b) { b.classList.toggle('active', b.dataset.lang === code); });
  _onLangChange();
}
function _onLangChange() {
  // 若有分析結果，重繪目前 section
  if (typeof window._triggerLangRefresh === 'function') {
    window._triggerLangRefresh();
  }
  // 更新 analyze-hint（含已選擇檔案的狀態）
  if (typeof window.updBtn === 'function') {
    window.updBtn();
  } else {
    var hint = document.getElementById('analyze-hint');
    if (hint) hint.textContent = tr('analyze.hint_none');
  }
  // 搜尋框 placeholder
  var si = document.getElementById('search-inp');
  if (si) si.placeholder = tr('search.placeholder');
}

// 位址物件名稱 → v4/v6 反查表：規則的 srcaddr/dstaddr 多數廠牌存的是物件名稱（不含冒號），
// 純字串「有沒有冒號」的判斷法對這種寫法完全失效，需要反查該名稱對應物件實際的位址型別。
// addressObjects 形狀沿用各廠牌 parseAddressObjects() 共用的 {category,name,subnet,startIp,
// endIp,fqdn,members,...}；group（address-group/address-group6）只展開一層 members，不遞迴
// 巢狀 group，與現有各廠牌 members 解析深度一致
function buildAddrTypeMap(addressObjects) {
  const map = new Map();
  (addressObjects || []).forEach(o => {
    if (o.category !== 'address' && o.category !== 'address6') return;
    const val = [o.subnet, o.startIp, o.fqdn].find(v => v && v !== '-') || '';
    map.set(o.name, val.includes(':') ? 'v6' : 'v4');
  });
  (addressObjects || []).forEach(o => {
    if (o.category !== 'address-group' && o.category !== 'address-group6') return;
    const memberTypes = new Set((o.members || '').split(/\s*,\s*/).filter(Boolean).map(m => map.get(m) || 'v4'));
    map.set(o.name, memberTypes.size > 1 ? 'mixed' : (memberTypes.values().next().value || 'v4'));
  });
  return map;
}
// addrTypeMap 未提供時維持純字串判斷（既有行為，向下相容尚未接上反查表的廠牌呼叫點）；
// 提供時，非字面 IP 的 token 依反查表分類，mixed（群組成員橫跨 v4/v6）同時歸進兩邊輸出
function _splitAddr(addrStr, addrTypeMap) {
  const addrs = (addrStr||'').split(/\s*,\s*/).filter(a=>a.trim());
  if (!addrTypeMap) {
    const v4 = addrs.filter(a => !a.includes(':')).join(', ') || '-';
    const v6 = addrs.filter(a => a.includes(':')).join(', ') || '-';
    return {v4, v6};
  }
  const v4 = [], v6 = [];
  addrs.forEach(a => {
    if (a.includes(':')) { v6.push(a); return; }
    const t = addrTypeMap.get(a);
    if (t === 'v6') v6.push(a);
    else if (t === 'mixed') { v4.push(a); v6.push(a); }
    else v4.push(a);
  });
  return { v4: v4.join(', ') || '-', v6: v6.join(', ') || '-' };
}

