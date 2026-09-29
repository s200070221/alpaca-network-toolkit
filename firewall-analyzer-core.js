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
// ── 批次 IP/Policy 查詢（2026-09-29 新增）──────────────────────────────────
// 一次查詢多組 src/dst/proto/port，逐列沿用 _runPolicyQuery()，適合變更前後驗證。
// CSV 欄位：src,dst,proto,port,expect（proto/port/expect 可省略）。第一列含 src 與 dst
// 欄名時視為表頭、依欄名對應（順序不拘）；否則依上述固定順序。# 開頭與空白列略過。
// expect 選填 accept/allow 或 deny/drop/block，有填時比對實際結果（implicit deny 也算 deny）。
const BATCH_QUERY_MAX_ROWS = 1000;
// 來源／目的支援 CIDR 與範圍（2026-09-29 新增，FF）：展開成逐一位址實際查詢，不抽代表位址猜結果；
// 每列展開後的「來源×目的」組合數上限 BATCH_EXPAND_MAX，超過列為錯誤 'range'
const BATCH_EXPAND_MAX = 256;
function _strictIpInt(s) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return null;
  const p = s.split('.').map(Number);
  if (p.some(n => n > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}
const _intToIpStr = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
// 回傳位址字串陣列；格式錯誤回傳 null；超過上限回傳 'too_large'
function _expandBatchAddr(str) {
  const t = String(str || '').trim();
  let lo, hi;
  const cidr = t.match(/^([\d.]+)\/(\d{1,2})$/);
  const range = t.match(/^([\d.]+)\s*-\s*([\d.]+)$/);
  if (cidr) {
    const base = _strictIpInt(cidr[1]), bits = +cidr[2];
    if (base === null || bits > 32) return null;
    const size = 2 ** (32 - bits);
    if (size > BATCH_EXPAND_MAX) return 'too_large';
    lo = Math.floor(base / size) * size; hi = lo + size - 1;
  } else if (range) {
    lo = _strictIpInt(range[1]); hi = _strictIpInt(range[2]);
    if (lo === null || hi === null || hi < lo) return null;
    if (hi - lo + 1 > BATCH_EXPAND_MAX) return 'too_large';
  } else {
    const n = _strictIpInt(t);
    return n === null ? null : [t];
  }
  const out = [];
  for (let n = lo; n <= hi; n++) out.push(_intToIpStr(n));
  return out;
}
function _splitCsvLine(line) {
  const out = []; let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ',') { out.push(cur.trim()); cur = ''; }
    else cur += c;
  }
  out.push(cur.trim());
  return out;
}
function parseBatchQueryCSV(text) {
  const lines = String(text || '').replace(/^﻿/, '').split(/\r?\n/);
  const rows = [], errors = [];
  let cols = ['src', 'dst', 'proto', 'port', 'expect'], started = false;
  lines.forEach((raw, i) => {
    const line = raw.trim(), lineNo = i + 1;
    if (!line || line.startsWith('#')) return;
    const cells = _splitCsvLine(line);
    if (!started) {
      started = true;
      const lower = cells.map(c => c.toLowerCase());
      if (lower.includes('src') && lower.includes('dst')) { cols = lower; return; }
    }
    const get = k => { const idx = cols.indexOf(k); return idx >= 0 ? (cells[idx] || '') : ''; };
    const src = get('src'), dst = get('dst');
    let proto = get('proto').toUpperCase() || 'any';
    if (proto === 'ANY') proto = 'any';
    const port = get('port');
    const exp = get('expect').toLowerCase();
    let expect = '';
    if (exp === 'accept' || exp === 'allow') expect = 'accept';
    else if (exp === 'deny' || exp === 'drop' || exp === 'block') expect = 'deny';
    const srcList = _expandBatchAddr(src), dstList = _expandBatchAddr(dst);
    if (srcList === null || dstList === null) { errors.push({ line: lineNo, reason: 'ip' }); return; }
    if (srcList === 'too_large' || dstList === 'too_large' || srcList.length * dstList.length > BATCH_EXPAND_MAX) { errors.push({ line: lineNo, reason: 'range' }); return; }
    if (!['any', 'TCP', 'UDP', 'ICMP'].includes(proto)) { errors.push({ line: lineNo, reason: 'proto' }); return; }
    if (port && !(/^\d+$/.test(port) && +port >= 1 && +port <= 65535)) { errors.push({ line: lineNo, reason: 'port' }); return; }
    if (exp && !expect) { errors.push({ line: lineNo, reason: 'expect' }); return; }
    if (rows.length >= BATCH_QUERY_MAX_ROWS) { errors.push({ line: lineNo, reason: 'max' }); return; }
    rows.push({ line: lineNo, src, dst, proto, port, expect, srcList, dstList });
  });
  return { rows, errors };
}
// 回傳每列 {…row, action, policyId, policyName, hasFqdn, combos, acceptCount, check}。CIDR／範圍列
// 會逐一查詢每個來源×目的組合後彙總：全部結果相同→該結果；全部不允許但拒絕方式不同→'deny'；
// 有允許也有不允許→'mixed'。命中規則只有一條時帶出 ID／名稱，多條時 policyId 為以 ; 串接的 ID。
// check：未填 expect 為 null；accept 需全部允許、deny 需全部不允許
function runBatchPolicyQuery(rows, vdomFilter, PARSED) {
  return rows.map(r => {
    const srcs = r.srcList || [r.src], dsts = r.dstList || [r.dst];
    const results = [];
    srcs.forEach(s => dsts.forEach(d => {
      const res = _runPolicyQuery(s, d, r.proto, r.port, vdomFilter, PARSED) || { matched: null, action: 'implicit_deny', trace: [] };
      const mt = (res.trace || []).find(t => t.result === 'match');
      results.push({ action: res.action, policy: res.matched, hasFqdn: !!(mt && mt.hasFqdn) });
    }));
    const acceptCount = results.filter(x => x.action === 'accept').length;
    const actions = [...new Set(results.map(x => x.action))];
    const action = actions.length === 1 ? actions[0] : (acceptCount === 0 ? 'deny' : 'mixed');
    const pols = [...new Map(results.filter(x => x.policy).map(x => [String(x.policy.id), x.policy])).values()];
    const single = pols.length === 1 && results.every(x => x.policy) ? pols[0] : null;
    const check = r.expect ? (r.expect === 'accept' ? acceptCount === results.length : acceptCount === 0) : null;
    return { ...r, action, policyId: single ? single.id : pols.map(p => p.id).join(';'), policyName: single ? (single.name || '') : '',
      hasFqdn: results.some(x => x.hasFqdn), combos: results.length, acceptCount, check };
  });
}
// 批次查詢跨版本比對（2026-09-29 新增，FE）：同一批查詢對新舊兩份設定各跑一次。
// change：'action'＝允許／拒絕結果改變（implicit deny 視同 deny）；'policy'＝結果相同但命中的
// 規則 ID 不同；''＝完全相同。回傳 [{...row, old:{action,policyId,policyName}, new:{...}, change}]
function compareBatchQuery(rows, oldParsed, newParsed) {
  const o = runBatchPolicyQuery(rows, '__all__', oldParsed);
  const n = runBatchPolicyQuery(rows, '__all__', newParsed);
  const pick = r => ({ action: r.action, policyId: r.policyId, policyName: r.policyName, acceptCount: r.acceptCount, combos: r.combos });
  return rows.map((row, i) => {
    const a = o[i], b = n[i];
    // 以「允許的組合數」判斷結果是否改變（單一位址時即允許與否；CIDR／範圍時部分允許的比例變化也算）
    const change = a.acceptCount !== b.acceptCount ? 'action' : (String(a.policyId) !== String(b.policyId) ? 'policy' : '');
    return { ...row, old: pick(a), new: pick(b), change };
  });
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
// 語言偏好跨工具共用（2026-09-29，PB）：共用 localStorage key 'cw_lang'（比照主題 'cw_theme'），
// 只記住三種正式語言；彩蛋語言需各工具各自解鎖，不跨工具帶入。未存過時依瀏覽器語言決定
function loadLangPref() {
  try { const v = localStorage.getItem('cw_lang'); if (v === 'zhTW' || v === 'en' || v === 'ja') return v; } catch (e) {}
  const n = ((typeof navigator !== 'undefined' && navigator.language) || '').toLowerCase();
  return n.indexOf('ja') === 0 ? 'ja' : (n.indexOf('zh') === 0 || !n ? 'zhTW' : 'en');
}
// 無障礙（UE，2026-09-29 新增）：沒有可存取名稱的輸入欄位，自動關聯到緊鄰的標籤——前一個兄弟元素是
// 沒有 for 的 <label> 時補 for；是 <span> 時以 aria-labelledby 指向它（語言切換後名稱跟著更新）。
// 已有 label／aria／title／placeholder（瀏覽器本身會當名稱）者不動。各工具各自一份，不跨檔引用
function autoLabelControls() {
  var n = 0;
  document.querySelectorAll('input:not([type=hidden]):not([type=file]),select,textarea').forEach(function (el) {
    if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.title || el.placeholder || el.closest('label')) return;
    if (el.id && document.querySelector('label[for="' + el.id + '"]')) return;
    var lb = el.previousElementSibling;
    if (!lb || !/^(LABEL|SPAN)$/.test(lb.tagName) || lb.querySelector('input,select,textarea')) return;
    if (lb.tagName === 'LABEL' && !lb.htmlFor && el.id) { lb.htmlFor = el.id; return; }
    if (!lb.id) lb.id = 'auto-lbl-' + (++n);
    el.setAttribute('aria-labelledby', lb.id);
  });
}
function saveLangPref(code) {
  if (code === 'zhTW' || code === 'en' || code === 'ja') { try { localStorage.setItem('cw_lang', code); } catch (e) {} }
}
// <html lang> 對應（2026-09-29，PB）：螢幕閱讀器依此決定朗讀語言；中文系彩蛋語言視為 zh-TW
function htmlLangFor(code) {
  if (code === 'ja') return 'ja';
  return ['zhTW', 'bureau', 'cat', 'bean', 'alpaca', 'yanse', 'wuxia'].indexOf(code) >= 0 ? 'zh-TW' : 'en';
}
function setLang(code) {
  _lang = code;
  saveLangPref(code);
  document.documentElement.lang = htmlLangFor(code);
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
    // 部分廠牌（如 WatchGuard 的 alias-member-list）允許成員直接是「字面 IP/CIDR 值本身」
    // 而非引用其他具名物件，此時 map.get(m) 查無此鍵，先前一律預設 'v4'，若該字面值其實是
    // IPv6 位址會被誤判（2026-09 全功能審查發現）；查無名稱對應時，改用字面值本身是否含 ":"
    // 判斷（與同檔案既有的字面 IP 判斷慣例一致），查無名稱且不含 ":" 才維持預設 v4
    const memberTypes = new Set((o.members || '').split(/\s*,\s*/).filter(Boolean).map(m => map.get(m) || (m.includes(':') ? 'v6' : 'v4')));
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

