// hub-devcheck.js — 入口頁「設備版本快速比對」卡片（XN107）：沒有設定檔時選產品、輸入版本，直接以 vuln-check.js 的
// 內建清單（vuln-seed.js，CISA KEV＋挑選的廠商公告）比對；貼上或拖放 NetScaler ns.conf 時另讀出檔頭版本並做幾項
// 對外曝險檢查（XN105）。純前端、不連網。新模組包 IIFE，給其他檔案呼叫的以 window 掛出：
//   renderDevCheckCard()（setLang 呼叫）、devCheckLoad(text)（拖放）、nsConfAudit(text)（純函式，測試用）、isNsConf(text)、
//   F5 BIG-IP（XN106）bigipConfAudit(text)／isBigipConf(text)
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const esc = s => _glEsc(s == null ? '' : s);
  const fmt = (k, p) => String(tr(k)).replace(/\{(\w+)\}/g, (m, n) => (p && p[n] != null ? p[n] : ''));
  // 產品選單：顯示名稱與版本寫法範例（範例只是格式，不是建議版本）
  const PRODUCTS = [
    ['netscaler', 'Citrix NetScaler ADC / Gateway', '14.1-43.50'], ['fortios', 'Fortinet FortiOS (FortiGate)', '7.2.5'],
    ['panos', 'Palo Alto PAN-OS', '10.2.9-h1'], ['asa', 'Cisco ASA', '9.18(4)22'], ['ftd', 'Cisco Secure Firewall (FTD)', '7.2.5.1'],
    ['iosxe', 'Cisco IOS XE', '17.9.4a'], ['ios', 'Cisco IOS', '15.2(7)E8'], ['nxos', 'Cisco NX-OS', '9.3(10)'],
    ['junos', 'Juniper Junos', '21.4R3-S5'], ['sonicos', 'SonicWall SonicOS', '7.0.1-5035'], ['gaia', 'Check Point Gaia', 'R81.20 Take 141'],
    ['eos', 'Arista EOS', '4.30.2F'], ['aoscx', 'HPE Aruba AOS-CX', '10.11.1020'], ['routeros', 'MikroTik RouterOS', '7.15.2'],
    ['os10', 'Dell SmartFabric OS10', '10.5.6.13'], ['bigip', 'F5 BIG-IP', '17.1.1.4'],
  ];
  const st = { audit: null };
  // VulnCheck 是 vuln-check.js 的頂層 const，不在 window 上，以 typeof 判斷
  const VC = () => (typeof VulnCheck !== 'undefined' ? VulnCheck : null);

  // NetScaler ns.conf 判斷（與去識別化 VENDOR_SIGS.netscaler 相同的訊號，至少 2 項）
  const NS_SIGS = [/^#NS\d+\.\d+ Build /m, /^set ns config -IPAddress /m, /^add ns ip6? /m, /^set ns hostName /m,
    /^(?:add|bind) (?:lb|cs|gslb|vpn|authentication) vserver /m, /^add ssl certKey /m, /^add (?:service|serviceGroup) \S+ /m];
  function isNsConf(text) { const t = String(text || ''); return NS_SIGS.filter(r => r.test(t)).length >= 2; }
  // 公網位址：不在私有、CGNAT、迴路、連結本機網段的 IPv4（文件用網段視為公網，方便以範例測試）
  function isPublicV4(ip) {
    const m = String(ip || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;
    const a = +m[1], b = +m[2];
    return !(a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224);
  }
  // ns.conf → {version, findings:[{id, sev, p}]}；語法依 NetScaler CLI：
  //   set ns config -IPAddress（NSIP，管理位址）、add ns ip 位址 遮罩 -type SNIP|VIP|MIP -mgmtAccess ENABLED、
  //   add vpn vserver 名稱 SSL 位址 埠（Gateway）、add authentication vserver 名稱 SSL 位址 埠（AAA）、add snmp community 名稱
  function nsConfAudit(text) {
    const t = String(text || '').replace(/\r\n/g, '\n');
    const vm = t.match(/^#NS(\d+\.\d+) Build (\d+\.\d+)/m);
    const findings = [];
    const mgmt = [];
    const nsip = t.match(/^set ns config -IPAddress (\S+)/m);
    if (nsip && isPublicV4(nsip[1])) mgmt.push(nsip[1] + ' (NSIP)');
    for (const m of t.matchAll(/^add ns ip (\S+) \S+(.*)$/gm)) {
      const type = (m[2].match(/-type (\S+)/) || [])[1] || 'SNIP';
      if (/-mgmtAccess ENABLED/i.test(m[2]) && isPublicV4(m[1])) mgmt.push(`${m[1]} (${type})`);
    }
    if (mgmt.length) findings.push({ id: 'mgmt_public', sev: 'high', p: { ips: mgmt.join(', ') } });
    const gw = [];
    for (const m of t.matchAll(/^add (vpn|authentication) vserver (\S+) (?:SSL|SSL_BRIDGE|HTTP) (\S+) (\d+)/gm)) {
      if (isPublicV4(m[3])) gw.push(`${m[2]} ${m[3]}:${m[4]}`);
    }
    if (gw.length) findings.push({ id: 'gateway_public', sev: 'medium', p: { list: gw.join(', ') } });
    const comm = [...t.matchAll(/^add snmp community (\S+)/gm)].map(m => m[1]).filter(c => /^(public|private)$/i.test(c));
    if (comm.length) findings.push({ id: 'snmp_default', sev: 'medium', p: { list: comm.join(', ') } });
    return { version: vm ? `${vm[1]}-${vm[2]}` : '', findings };
  }
  // F5 BIG-IP 設定（XN106）：bigip.conf、tmsh list 輸出或 Oxidized 錄製；以 tmsh 頂層區塊判斷，至少 2 項
  const F5_SIGS = [/^#TMSH-VERSION: /m, /^ltm (?:virtual|pool|node) \S+ \{/m, /^net self \S+ \{/m, /^net vlan \S+ \{/m, /^sys global-settings \{/m,
    /^auth user \S+ \{/m, /^sys (?:httpd|sshd|snmp) \{/m, /^sys management-ip /m, /Sys::Version/];
  function isBigipConf(text) { const t = String(text || ''); return F5_SIGS.filter(r => r.test(t)).length >= 2; }
  // tmsh 頂層區塊：以「標頭 {」開始的行起算，依大括號深度找到結尾；回傳 [{head, body}]（body 不含頭尾行）
  function f5Blocks(t, headRe) {
    const lines = t.split('\n'), out = [];
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(headRe);
      if (!m) continue;
      if (/\{\s*\}\s*$/.test(lines[i])) { out.push({ m, body: '' }); continue; }
      let depth = 0, j = i;
      for (; j < lines.length; j++) { depth += (lines[j].match(/\{/g) || []).length - (lines[j].match(/\}/g) || []).length; if (depth <= 0) break; }
      out.push({ m, body: lines.slice(i + 1, j).join('\n') });
      i = j;
    }
    return out;
  }
  // 項目依 F5 文件（K17333 port lockdown、K13309 管理介面 httpd／sshd allow、tmsh sys snmp communities）：
  //   self IP allow-service all（所有服務，含 TMUI／iControl REST）、明列 tcp:https／443／ssh／22（管理服務開在資料面）；
  //   allow-service default 依版本內容不同，不評估；httpd／sshd allow 為 All；SNMP community public／private；本機帳號 shell bash
  function bigipConfAudit(text) {
    const t = String(text || '').replace(/\r\n/g, '\n');
    const vm = t.match(/^#?\s*Version\s+(\d+(?:\.\d+){2,3})\s*$/m);
    const bm = t.match(/^#?\s*Build\s+(\d+(?:\.\d+)+)\s*$/m);
    const findings = [];
    const all = [], mgmt = [];
    let pubAll = false, pubMgmt = false;
    for (const b of f5Blocks(t, /^net self (\S+) \{/)) {
      const addr = ((b.body.match(/^\s*address (\S+)/m) || [])[1] || '').replace(/%\d+/, '');
      const ip = addr.split('/')[0], pub = isPublicV4(ip);
      const label = `${b.m[1]} ${addr}`.trim();
      const svc = b.body.match(/^\s*allow-service (?:\{([^}]*)\}|(\S+))/m);
      if (!svc) continue;
      if (svc[2] === 'all') { all.push(label); pubAll = pubAll || pub; continue; }
      const list = (svc[1] || '').trim().split(/\s+/).filter(Boolean);
      const hit = list.filter(x => /^tcp:(?:https|443|ssh|22)$/i.test(x));
      if (hit.length) { mgmt.push(`${label} (${hit.join(' ')})`); pubMgmt = pubMgmt || pub; }
    }
    if (all.length) findings.push({ id: 'selfip_allow_all', sev: pubAll ? 'high' : 'medium', p: { list: all.join(', ') } });
    if (mgmt.length) findings.push({ id: 'selfip_mgmt', sev: pubMgmt ? 'high' : 'medium', p: { list: mgmt.join(', ') } });
    const allowAll = re => f5Blocks(t, re).some(b => /^\s*allow \{[^}]*\b(?:all|0\.0\.0\.0\/0(?:\.0\.0\.0)?)\b/im.test(b.body) || /^\s*allow (?:all|ALL)\s*$/m.test(b.body));
    if (allowAll(/^sys httpd \{/)) findings.push({ id: 'httpd_allow_all', sev: 'medium', p: {} });
    if (allowAll(/^sys sshd \{/)) findings.push({ id: 'sshd_allow_all', sev: 'medium', p: {} });
    const comm = [...t.matchAll(/^\s*community-name (\S+)/gm)].map(m => m[1].replace(/"/g, '')).filter(c => /^(public|private)$/i.test(c));
    if (comm.length) findings.push({ id: 'snmp_default', sev: 'medium', p: { list: [...new Set(comm)].join(', ') } });
    const shell = f5Blocks(t, /^auth user (\S+) \{/).filter(b => /^\s*shell bash\s*$/m.test(b.body)).map(b => b.m[1]);
    if (shell.length) findings.push({ id: 'bigip_shell', sev: 'low', p: { list: shell.join(', ') } });
    return { kind: 'bigip', version: vm ? vm[1] : '', build: bm ? bm[1] : '', findings };
  }
  // 比對內建清單：回傳 {status, hits:[entry], unknown:[entry]}；status：affected｜ok｜unknown｜noVersion｜noRules
  function compare(sch, version) {
    const V = VC();
    if (!V) return { status: 'noRules', hits: [], unknown: [] };
    const rules = V.withBuiltin([]).filter(e => e.scheme === sch);
    if (!rules.length) return { status: 'noRules', hits: [], unknown: [] };
    if (!V.parse(sch, version)) return { status: 'noVersion', hits: [], unknown: [] };
    const hits = [], unknown = [];
    rules.forEach(e => { const r = V.inRange(sch, version, e.affected); if (r === true) hits.push(e); else if (r === null) unknown.push(e); });
    return { status: hits.length ? 'affected' : unknown.length ? 'unknown' : 'ok', hits, unknown };
  }

  // 只顯示命中的那一段範圍（同一筆規則常列多個版本系列）
  function hitPart(sch, version, affected) {
    const V = VC(), parts = String(affected || '').split(/[;|]/).map(x => x.trim()).filter(Boolean);
    const hit = (V && parts.find(p => V.inRange(sch, version, p) === true)) || affected;
    // 「>=14.1-0.0 <14.1-43.56」只顯示上界，手機寬度才放得下；其他寫法原樣顯示
    const up = hit.match(/(<=?)\s*(\S+)\s*$/);
    return up && /^>=/.test(hit) ? up[1] + ' ' + up[2] : hit;
  }
  function renderResult(sch, version) {
    const box = $('dc-result');
    if (!box) return;
    if (!version) { box.innerHTML = ''; return; }
    const r = compare(sch, version);
    const kev = r.hits.filter(e => e.kev).length;
    let h = '';
    if (r.status === 'affected') h += `<p class="dc-verdict dc-bad">⚠️ ${esc(fmt('dc.hits', { n: r.hits.length, k: kev, v: version }))}</p>`;
    else if (r.status === 'ok') h += `<p class="dc-verdict">✅ ${esc(fmt('dc.none', { v: version }))}</p>`;
    else if (r.status === 'noVersion') h += `<p class="dc-verdict dc-bad">${esc(fmt('dc.bad_version', { v: version }))}</p>`;
    else if (r.status === 'unknown') h += `<p class="dc-verdict">${esc(fmt('dc.unknown', { n: r.unknown.length }))}</p>`;
    else h += `<p class="dc-verdict">${esc(tr('dc.no_rules'))}</p>`;
    if (r.hits.length) {
      h += `<div class="dc-table-wrap"><table class="dc-table"><thead><tr><th>CVE</th><th>${esc(tr('dc.col_kev'))}</th><th>${esc(tr('dc.col_range'))}</th><th class="dc-note">${esc(tr('dc.col_note'))}</th></tr></thead><tbody>`
        + r.hits.map(e => `<tr><td class="dc-cve">${esc(e.cve)}</td><td>${e.kev ? '<span class="dc-kev">KEV</span>' : esc(tr('dc.advisory'))}</td><td><code>${esc(hitPart(sch, version, e.affected))}</code></td><td class="dc-note">${esc(e.note || '')}</td></tr>`).join('')
        + '</tbody></table></div>';
    }
    h += `<p class="cert-hint">${esc(fmt('dc.asof', { d: (VC() && VC().BUILTIN_ASOF) || '-' }))}</p>`;
    box.innerHTML = h;
  }
  function renderAudit() {
    const box = $('dc-audit');
    if (!box) return;
    const a = st.audit;
    if (!a) { box.innerHTML = ''; return; }
    const f5 = a.kind === 'bigip';
    let h = `<h3 class="dc-sub">${esc(tr(f5 ? 'dc.f5_audit_title' : 'dc.audit_title'))}</h3>`;
    h += `<p class="cert-hint">${esc(a.version ? fmt('dc.version_found', { v: a.version + (a.build ? ' Build ' + a.build : '') }) : tr(f5 ? 'dc.f5_version_missing' : 'dc.version_missing'))}</p>`;
    h += a.findings.length
      ? '<ul class="dc-findings">' + a.findings.map(f => `<li class="dc-sev-${f.sev}">${esc(fmt('dc.f_' + f.id, f.p))}</li>`).join('') + '</ul>'
      : `<p class="cert-hint">${esc(tr(f5 ? 'dc.f5_audit_clean' : 'dc.audit_clean'))}</p>`;
    box.innerHTML = h;
  }
  function run() {
    const sch = ($('dc-product') || {}).value || 'netscaler';
    renderResult(sch, String(($('dc-version') || {}).value || '').trim());
  }
  // ns.conf 或 show version 文字：讀出版本、填入欄位並比對；ns.conf 另做曝險檢查
  function devCheckLoad(text) {
    const t = String(text || '');
    const sec = $('devcheck');
    if (!sec) return;
    const pa = $('dc-paste');
    if (pa && pa.value !== t) pa.value = t;
    st.audit = isNsConf(t) ? nsConfAudit(t) : isBigipConf(t) ? bigipConfAudit(t) : null;
    const prod = st.audit && st.audit.kind === 'bigip' ? 'bigip' : 'netscaler';
    let ver = st.audit ? st.audit.version : '';
    if (!st.audit && VC()) {
      const m = t.match(/NS(\d+\.\d+):?\s*Build\s*(\d+\.\d+)/i);
      if (m) ver = `${m[1]}-${m[2]}`;
    }
    if (st.audit || ver) { $('dc-product').value = prod; if (ver) $('dc-version').value = ver; renderDevCheckCard(); }
    renderAudit();
    run();
    sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function renderDevCheckCard() {
    if (!$('devcheck')) return;
    const set = (id, k) => { const e = $(id); if (e) e.textContent = tr(k); };
    set('dc-title', 'dc.title'); set('dc-intro', 'dc.intro'); set('dc-product-lbl', 'dc.product'); set('dc-version-lbl', 'dc.version');
    set('dc-run', 'dc.run'); set('dc-paste-lbl', 'dc.paste'); set('dc-paste-run', 'dc.paste_run'); set('dc-note', 'dc.note');
    const sel = $('dc-product');
    if (sel && !sel.options.length) sel.innerHTML = PRODUCTS.map(([v, n]) => `<option value="${v}">${esc(n)}</option>`).join('');
    const ex = (PRODUCTS.find(p => p[0] === (sel ? sel.value : '')) || PRODUCTS[0])[2];
    const vi = $('dc-version'); if (vi) vi.placeholder = fmt('dc.version_ph', { ex });
    const pa = $('dc-paste'); if (pa) pa.placeholder = tr('dc.paste_ph');
    renderAudit();
    if (vi && vi.value.trim()) run();
  }
  function init() {
    if (!$('devcheck')) return;
    $('dc-run').addEventListener('click', run);
    $('dc-version').addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
    $('dc-product').addEventListener('change', () => { renderDevCheckCard(); if ($('dc-version').value.trim()) run(); });
    $('dc-paste-run').addEventListener('click', () => devCheckLoad(($('dc-paste') || {}).value || ''));
    renderDevCheckCard();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
  Object.assign(window, { renderDevCheckCard, devCheckLoad, nsConfAudit, isNsConf, bigipConfAudit, isBigipConf });
})();
