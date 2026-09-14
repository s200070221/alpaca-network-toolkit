// ════════════════════════════════════════════════════════════════════════
// firewall-analyzer-sections.js — renderSection() 的「儀表板型」case HTML 建構函式
// （2026-09-14 從 firewall-analyzer-app.js 拆出）。renderSection() 內 21 個 case 天然分兩類：
// 9 個「表格型」case（interfaces/policies/routes/vpn/nat/addresses/services/schedules/
// users）共用 data/sumCards/thead/rowFn 走共用尾端，policies case 另含遞迴呼叫
// renderSection('routes') 與直接 DOM 操作，耦合較深，刻意不搬；本檔案只涵蓋另外 12 個
// 「儀表板型」case（sdwan/ha/dhcp/dns/snmp/log/wwan/wlan/wifi/fortiswitch/audit/query）
// ——這些 case 各自組 HTML 字串後直接寫入 DOM、提早 return，不經過共用尾端，本來就是
// 「開頭 DOM 設定/防呆 → 純字串組裝 → 結尾寫回 DOM」的固定樣式，此檔案只搬「純字串組裝」
// 那段（改用 return 取代原本的 innerHTML 賦值），DOM 設定/防呆/寫回留在 app.js 的
// renderSection() 內。onParsed()（orchestration hub）與表格型 case 同樣刻意不搬，理由見
// now.md 對應段落評估。
// filterByVdom() 讀模組狀態 ACTIVE_VDOM，留在 app.js，此處需要時以參數傳入函式本身。
// esc()/pill()/sumC() 比照 -audit.js 對 esc()/pill() 的既有慣例，在此各自重複宣告一份
// （app.js 內原本的表格型 case 仍使用 app.js 自己的定義，兩邊互不相依）；tr()/tip() 本來
// 就是 i18n.js／core.js 頂層全域函式，不需重複宣告。
// 2026-09-14 修正：-audit.js 是本專案唯一「無巢狀 IIFE、直接頂層宣告」的既有模組，當時因為
// 是唯一一份不需要考慮跟「其他同樣頂層宣告的模組」衝突；本檔案是第二份頂層模組，esc/pill
// 若沿用同一寫法直接頂層 const 宣告，會跟 -audit.js 的 const esc/const pill 撞名（`let`/
// `const` 在多個 classic <script> 間共用同一個全域詞法作用域，會拋 SyntaxError: Identifier
// 'esc' has already been declared，瀏覽器實機驗證時才抓到，Node `new Function()` 語法檢查
// 因為只檢查單一檔案不會偵測到這類跨檔案衝突）。故改為包一層 IIFE 避免污染全域詞法作用域，
// renderSection() 需要呼叫的 11 個函式再逐一掛到 window 上（app.js 內對這些函式的呼叫本來
// 就是裸識別字查找，找到 window 上的同名屬性一樣能正確解析，不需要改動呼叫端任何寫法）。
// ════════════════════════════════════════════════════════════════════════
(function(){
const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const pill=(t,c)=>`<span class="pill ${c}">${esc(t)}</span>`;
function sumC(items){return items.map(i=>{const cl=i.sf?' clickable':'';const oc=i.sf?` onclick="_scf(${JSON.stringify(i.sf.t).replace(/"/g,'&quot;')},${JSON.stringify(i.sf.v||'').replace(/"/g,'&quot;')})"`:'';;return`<div class="sum-card${cl}"${oc}><div class="sl">${i.l}</div><div class="sv" style="color:${i.c}">${i.v}</div></div>`;}).join('');}

function buildHaSectionHtml(ha){
  const sumHtml=sumC([
    {l:tr('ha.mode'), v:ha.mode, c:'var(--accent)'},
    {l:tr('ha.group_id'), v:ha.groupId, c:'var(--green)'},
    {l:tr('ha.priority'), v:ha.priority, c:'var(--yellow)'},
  ]);
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
  return { sumHtml, html };
}

function buildDhcpSectionHtml(dh, filterByVdom){
  const sumHtml=sumC([
    {l:'DHCP Server', v:dh.servers.length, c:'var(--green)'},
    {l:'DHCP Relay',  v:dh.relays.length,  c:'var(--yellow)'},
    {l:tr('sl.enabled'), v:dh.servers.filter(s=>s.status==='enable').length, c:'var(--accent)'},
    {l:tr('sl.disabled'), v:dh.servers.filter(s=>s.status!=='enable').length, c:'var(--red)'},
  ]);
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
  return { sumHtml, html };
}

function buildDnsSectionHtml(dn){
  const sumHtml=sumC([
    {l:'DNS Server',    v:dn.servers.length+dn.secondaries.length, c:'var(--accent)'},
    {l:'DNS Proxy',     v:dn.proxy?1:0,    c:dn.proxy?'var(--green)':'var(--text-dim)'},
    {l:tr('dns.proxy_rules'), v:dn.proxyRules.length, c:'var(--yellow)'},
    {l:tr('dns.static_records'), v:dn.static.length, c:'var(--purple)'},
    {l:'DNS over TLS',  v:dn.dnsOverTls?1:0, c:dn.dnsOverTls?'var(--green)':'var(--text-dim)'},
    {l:tr('col.domain'), v:dn.domain&&dn.domain!=='-'?dn.domain:'—', c:'var(--info)'},
  ]);
  let html='';
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
  if(dn.proxyRules.length){
    html+='<div style="font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px">🔀 Conditional Forwarding / '+tr('dns.proxy_rules')+'</div>';
    html+=`<div style="overflow-x:auto;margin-bottom:20px"><table><thead><tr><th>${tr('col.domain')}</th><th>${tr('dns.fwd_target')}</th></tr></thead><tbody>`;
    dn.proxyRules.forEach(r=>{
      html+=`<tr><td class="mono" style="color:var(--accent)">${esc(r.domain)}</td><td class="mono" style="color:var(--yellow)">${esc(r.target)}</td></tr>`;
    });
    html+='</tbody></table></div>';
  }
  if(dn.static.length){
    html+='<div style="font-size:12px;font-weight:600;color:var(--purple);margin-bottom:8px">📋 '+tr('dns.static_records')+'</div>';
    html+='<div style="overflow-x:auto"><table><thead><tr><th>'+tr('dns.col_host')+'</th><th>'+tr('dns.col_type')+'</th><th>'+tr('dns.col_ip_target')+'</th><th>'+tr('dns.col_zone_name')+'</th></tr></thead><tbody>';
    dn.static.forEach(r=>{
      html+=`<tr><td class="mono">${esc(r.name)}</td><td>${pill(r.type||'A','p-info')}</td><td class="mono" style="color:var(--accent)">${esc(r.ip)}</td><td style="color:var(--text-dim)">${esc(r.zone||'-')}</td></tr>`;
    });
    html+='</tbody></table></div>';
  }
  return { sumHtml, html };
}

function buildSnmpSectionHtml(sn){
  const verBadges=(sn.agent.version||[]).map(v=>pill(v.toUpperCase(),'p-info')).join(' ')||pill(tr('snmp.unknown'),'p-dim');
  const sumHtml=sumC([
    {l:tr('snmp.community_count'), v:sn.communities.length,   c:'var(--accent)'},
    {l:tr('snmp.v3_users'),          v:sn.v3users.length,        c:'var(--purple)'},
    {l:tr('snmp.trap_servers'),       v:sn.trapServers.length,    c:'var(--yellow)'},
    {l:tr('snmp.version'),          v:(sn.agent.version||[]).join('/'), c:'var(--green)'},
    {l:tr('col.status'),      v:sn.enabled?tr('wwan.pill_enable'):tr('wwan.pill_disable'), c:sn.enabled?'var(--green)':'var(--red)'},
  ]);
  let html='';
  html+=`<div style="background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:16px;display:flex;gap:32px;flex-wrap:wrap">`;
  html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.agent_name')}</div><div style="color:var(--text);margin-top:4px;max-width:240px;overflow-wrap:break-word;word-break:break-word">${esc(sn.agent.name)}</div></div>`;
  html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.contact')}</div><div style="color:var(--text);margin-top:4px;max-width:240px;overflow-wrap:break-word;word-break:break-word">${esc(sn.agent.contact)}</div></div>`;
  html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.location')}</div><div style="color:var(--text);margin-top:4px;max-width:240px;overflow-wrap:break-word;word-break:break-word">${esc(sn.agent.location)}</div></div>`;
  html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.desc')}</div><div style="color:var(--text-dim);margin-top:4px;max-width:240px;overflow-wrap:break-word;word-break:break-word">${esc(sn.agent.description)}</div></div>`;
  html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('snmp.col_version')}</div><div style="margin-top:4px">${verBadges}</div></div>`;
  html+=`<div><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">${tr('col.status')}</div><div style="margin-top:4px">${sn.enabled?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</div></div>`;
  html+='</div>';
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
  if(sn.trapServers.length){
    html+='<div style="font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px">'+tr('snmp.trap_header')+'</div>';
    html+='<div style="overflow-x:auto"><table><thead><tr>';
    [tr('snmp.col_ip'),'Port','Community',tr('snmp.col_version')].forEach(h=>html+=`<th>${h}</th>`);
    html+='</tr></thead><tbody>';
    sn.trapServers.forEach(ts=>{ html+=`<tr><td class="mono" style="color:var(--yellow)">${esc(ts.ip)}</td><td class="mono">${esc(ts.port||'162')}</td><td class="mono" style="color:var(--text-dim)">${esc(ts.community||'-')}</td><td>${pill(ts.version||'v2c','p-info')}</td></tr>`; });
    html+='</tbody></table></div>';
  }
  return { sumHtml, html };
}

function buildLogSectionHtml(lg, filterByVdom){
  const sumHtml=sumC([
    {l:'Syslog',       v:lg.syslog.length,        c:'var(--accent)'},
    {l:'FortiAnalyzer',v:lg.fortianalyzer.length,  c:'var(--orange)'},
    {l:'NetFlow',      v:lg.netflow.length,        c:'var(--purple)'},
    {l:'Log Profile',  v:lg.logForward.length,     c:'var(--info)'},
  ]);
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
    filterByVdom(lg.netflow).forEach(n=>{ html+=`<tr><td class="mono" style="color:var(--purple)">${esc(n.collector)}</td><td class="mono">${esc(n.port||'2055')}</td><td class="mono" style="color:var(--text-dim)">${esc(n.activeTimeout||'60')}</td><td>${n.status==='enable'?pill(tr('wwan.pill_enable'),'p-allow'):pill(tr('wwan.pill_disable'),'p-deny')}</td></tr>`; });
    html+='</tbody></table></div>';
  }
  if(lg.logForward.length){
    html+='<div style="font-size:12px;font-weight:600;color:var(--info);margin-bottom:8px">🔀 Log Forwarding Profile</div>';
    html+='<div style="overflow-x:auto"><table><thead><tr><th>'+tr('col.name')+'</th><th>'+tr('popup.col_type')+'</th><th>'+tr('log.col_target')+'</th></tr></thead><tbody>';
    filterByVdom(lg.logForward).forEach(lf=>{ html+=`<tr><td class="mono">${esc(lf.name)}</td><td style="color:var(--text-dim)">${esc(lf.type||'-')}</td><td class="mono" style="color:var(--text-dim)">${esc(lf.target||'-')}</td></tr>`; });
    html+='</tbody></table></div>';
  }
  return { sumHtml, html };
}

function buildWwanSectionHtml(ww, filterByVdom){
  const dualSim=ww.profiles?.length>0&&[...new Set(ww.profiles.map(p=>p.modemId))].length>1;
  const m5g=ww.modem5G;
  const has5G=m5g&&(m5g.modem1||m5g.modem2);
  const sim1Set=has5G&&m5g.modem1?.sim1Pin==='set';
  const sim2Set=has5G&&(m5g.modem1?.sim2Pin==='set'||m5g.modem2?.sim1Pin==='set');
  const sumHtml=sumC([
    ...(has5G?[{l:'5G Modem',v:(m5g.modem1?1:0)+(m5g.modem2?1:0),c:'var(--accent)'}]:[]),
    ...(ww.profiles?.length?[{l:'WWAN Profile',v:ww.profiles.length,c:'var(--accent)'}]:[]),
    ...(has5G?[{l:'SIM1 PIN',v:sim1Set?tr('wwan.pin_set'):tr('wwan.pin_notset'),c:sim1Set?'var(--green)':'var(--text-dim)'}]:[]),
    ...(has5G?[{l:'SIM2 PIN',v:sim2Set?tr('wwan.pin_set'):tr('wwan.pin_notset'),c:sim2Set?'var(--green)':'var(--text-dim)'}]:[]),
    ...(ww.lteModem?[{l:'LTE Modem',v:ww.lteModem.status,c:ww.lteModem.status==='enable'?'var(--green)':'var(--text-dim)'}]:[]),
  ]);
  let html='';
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
  if(ww.systemModem&&ww.systemModem.pinInit&&ww.systemModem.pinInit!=='-'){
    html+=`<div style="margin-top:16px;font-size:11px;color:var(--text-dim)">⚙ ${tr('wwan.modem_at')}：<span class="mono">${esc(ww.systemModem.pinInit)}</span></div>`;
  }
  if(ww.lteInterfaces?.length){
    html+=`<div style="margin-top:20px;font-size:12px;font-weight:600;color:var(--accent);margin-bottom:8px">📱 ${tr('wwan.lte_iface')}</div>`;
    html+=`<table><thead><tr><th>${tr('col.name')}</th><th>${tr('wwan.col_apn_profile')}</th><th>${tr('wwan.col_roaming')}</th><th>${tr('col.status')}</th><th>${tr('wwan.col_note')}</th></tr></thead><tbody>`;
    filterByVdom(ww.lteInterfaces).forEach(i=>{
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
  if(ww.apnProfiles?.length){
    html+=`<div style="margin-top:16px;font-size:12px;font-weight:600;color:var(--yellow);margin-bottom:8px">📋 ${tr('wwan.lte_apn_profile')}</div>`;
    html+=`<table><thead><tr><th>${tr('wwan.col_apn_name')}</th><th>APN</th><th>${tr('wwan.col_auth')}</th><th>${tr('wwan.col_user')}</th><th>${tr('wwan.col_password')}</th><th>${tr('wwan.col_ip_type')}</th><th>${tr('wwan.col_distance')}</th></tr></thead><tbody>`;
    filterByVdom(ww.apnProfiles).forEach(p=>{
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
  const cnt=(ww.profiles?.length)||(ww.lteInterfaces?.length)||(has5G?(m5g.modem1?1:0)+(m5g.modem2?1:0):0);
  return { sumHtml, html, cnt };
}

function buildWlanSectionHtml(wl, filterByVdom){
  const openCount=wl.interfaces.filter(i=>i.authTypes==='none'||i.authTypes==='-').length;
  const sumHtml=sumC([
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
    filterByVdom(wl.interfaces).forEach(i=>{
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
    filterByVdom(wl.capsmanConfigs).forEach(c=>{
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
  return { sumHtml, html };
}

function buildFortiswitchSectionHtml(fSwitches, fPorts, fMacPolicies, fNacPolicies){
  const sumHtml=sumC([
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

  return { sumHtml, html };
}

function buildQuerySectionHtml(qvdoms){
  const qvdomOpts = `<option value="__all__">${tr('query.all_vdom')}</option>`
    + qvdoms.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');
  const qVdomSel = qvdoms.length > 1
    ? `<label style="display:flex;flex-direction:column;gap:4px;font-size:12px">${tr('query.vdom')}
        <select id="q-vdom" style="padding:6px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg2);color:var(--text)">${qvdomOpts}</select>
       </label>` : '';
  return `
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
        ${qVdomSel}
        <button type="button" onclick="_runQuery()"
          style="padding:7px 20px;border-radius:6px;background:var(--accent);
                 color:#fff;border:none;cursor:pointer;font-weight:600;font-size:13px;margin-bottom:0;align-self:flex-end">
          🔍 ${tr('query.btn')}
        </button>
      </div>
      <div id="query-result" style="margin-top:20px"></div>
    </div>`;
}

// WiFi Analysis Renderer（原封不動從 app.js 搬移，本來就是零 PARSED/ST/document. 依賴的
// 純函式，只需要 tr/esc/pill 即可安全獨立成檔案）
function renderWifiSection(w) {
  const s = w.summary;
  const scoreColor = s.avgSecScore >= 85 ? 'var(--green)' : s.avgSecScore >= 65 ? 'var(--yellow)' : 'var(--red)';

  let html = `<div class="wifi-grid">`;

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

  html += `<div class="wifi-card">
    <h4>🏢 ${tr('wifi.ap_infra')}</h4>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:13px">
      <div><div style="font-size:22px;font-weight:700;color:var(--accent)">${s.apCount}</div><div style="color:var(--text-dim);font-size:11px">${tr('wifi.managed_ap')}</div></div>
      <div><div style="font-size:22px;font-weight:700;color:var(--purple)">${s.profileCount}</div><div style="color:var(--text-dim);font-size:11px">${tr('wifi.ap_profile_label')}</div></div>
      <div><div style="font-size:22px;font-weight:700;color:var(--green)">${s.wifi6Aps}</div><div style="color:var(--text-dim);font-size:11px">${tr('wifi.wifi6_type')}</div></div>
      <div><div style="font-size:22px;font-weight:700;color:var(--orange)">${s.dualBandAps}</div><div style="color:var(--text-dim);font-size:11px">${tr('wifi.dual_band')}</div></div>
    </div>
  </div>`;

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
  html += `</div></div>`;

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

function buildSdwanSectionHtml(sd, filterByVdom){
  const modeLabel={'source-ip-based':tr('sdwan.mode_src_ip'),'weight-based':tr('sdwan.mode_weight'),'usage-based':tr('sdwan.mode_usage'),'measured-volume-based':tr('sdwan.mode_volume'),'least-shaping':tr('sdwan.mode_min'),'auto':tr('sdwan.mode_auto')};
  const sumHtml=sumC([
    {l:tr('sdwan.wan_links'), v:sd.members.length,      c:'var(--accent)'},
    {l:tr('sdwan.rules_count'),v:sd.services.length,   c:'var(--green)'},
    {l:tr('sdwan.sla_probes'), v:sd.healthChecks.length, c:'var(--yellow)'},
    {l:tr('sdwan.zones_count'), v:sd.zones.length,        c:'var(--purple)'},
    {l:tr('sdwan.bgp_peers'), v:sd.neighbors.length,    c:'var(--orange)'},
    {l:tr('sdwan.lb_mode'), v:modeLabel[sd.lbMode]||sd.lbMode, c:'var(--info)'},
  ]);
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

  return { sumHtml, html };
}

// renderSection() 呼叫的入口，掛到 window 供 app.js（另一個 IIFE 作用域）存取
window.buildHaSectionHtml=buildHaSectionHtml;
window.buildDhcpSectionHtml=buildDhcpSectionHtml;
window.buildDnsSectionHtml=buildDnsSectionHtml;
window.buildSnmpSectionHtml=buildSnmpSectionHtml;
window.buildLogSectionHtml=buildLogSectionHtml;
window.buildWwanSectionHtml=buildWwanSectionHtml;
window.buildWlanSectionHtml=buildWlanSectionHtml;
window.buildFortiswitchSectionHtml=buildFortiswitchSectionHtml;
window.buildQuerySectionHtml=buildQuerySectionHtml;
window.renderWifiSection=renderWifiSection;
window.buildSdwanSectionHtml=buildSdwanSectionHtml;
})();
