// ════════════════════════════════════════════════════
//  ALLIED TELESIS ALLIEDWARE PLUS（AW+）（2026-10-02 新增，第十輪發想 ZH）
// ════════════════════════════════════════════════════
// 語法與 Cisco IOS 相近，沿用 Cisco 解析器（vendor 仍為 cisco，sys.brand='awplus'，比照 Cisco Business 做法），
// 這裡處理不同之處。依 Allied Telesis 官方 Ansible collection（github.com/alliedtelesis/ansible_awplus）的單元測試
// 範例（tests/unit/modules/fixtures，真實 show running-config）：
// - 埠名 port1.0.1、聚合 po<N>（LACP，成員埠 `channel-group N mode active|passive`）與 sa<N>（靜態，
//   `static-channel-group N`），介面區塊可寫成範圍：`interface port1.0.5-1.0.22`、`interface po1-2`
// - VLAN 在 `vlan database` 區塊：` vlan 2 name vlan2`、` vlan 2 state enable`
// - trunk 用 `switchport trunk allowed vlan add N`、`switchport trunk native vlan none`
// - 靜態路由 `ip route [vrf X] 前綴/長度 下一跳|介面 [距離]`、syslog `log host X`、帳號 `username X privilege 15 password 8 <雜湊>`
// 測試範例多數行尾補滿空白（終端機擷取），解析前一併去除
function isAlliedWare(cfg) {
  return /^interface\s+port\d+\.\d+\.\d+/m.test(cfg) || /AlliedWare Plus/i.test(cfg) ||
    (/^vlan database\s*$/m.test(cfg) && /^\s+vlan\s+[\d,-]+\s+state\s+enable/m.test(cfg));
}
function awplusExpandIfList(spec) {
  const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
  return String(spec).split(',').flatMap(part => {
    let m = part.match(/^([a-z]+)(\d+)\.(\d+)\.(\d+)-(\d+)\.(\d+)\.(\d+)$/i);
    if (m && m[2] === m[5] && m[3] === m[6] && +m[7] >= +m[4] && +m[7] - +m[4] < 512) return range(+m[4], +m[7]).map(k => `${m[1]}${m[2]}.${m[3]}.${k}`);
    m = part.match(/^([a-z]+)(\d+)-(\d+)$/i);
    if (m && +m[3] >= +m[2] && +m[3] - +m[2] < 512) return range(+m[2], +m[3]).map(k => m[1] + k);
    return part ? [part] : [];
  });
}
// 範圍介面展開成逐埠區塊（之後所有共用解析都看到逐埠設定）；去除行尾空白
function awplusPreprocess(cfg) {
  const lines = cfg.split('\n').map(l => l.replace(/\s+$/, ''));
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^interface\s+(\S+)$/);
    const names = m && /[-,]/.test(m[1]) ? awplusExpandIfList(m[1]) : null;
    if (!names || names.length < 2) { out.push(lines[i]); continue; }
    const body = [];
    let j = i + 1;
    while (j < lines.length && /^\s/.test(lines[j])) body.push(lines[j++]);
    names.forEach(n => out.push('interface ' + n, ...body, '!'));
    i = j - 1;
  }
  return out.join('\n');
}
function applyAlliedWare(res, cfg) {
  res.sys = res.sys || {};
  res.sys.brand = 'awplus';
  if (!res.sys.platform) res.sys.platform = 'AlliedWare Plus';
  const expandVlans = s => String(s).split(',').flatMap(p => { const m = p.match(/^(\d+)-(\d+)$/); return m ? Array.from({ length: +m[2] - +m[1] + 1 }, (_, i) => String(+m[1] + i)) : [p]; }).filter(v => /^\d+$/.test(v));
  // VLAN：vlan database 的名稱與啟用宣告，加上 SVI 位址
  const vmap = new Map((res.vlans || []).map(v => [String(v.id), v]));
  const db = cfg.match(/^vlan database\s*\n((?:[ \t]+[^\n]*\n?)*)/m);
  if (db) db[1].split('\n').forEach(l => {
    const m = l.match(/^\s+vlan\s+([\d,-]+)\s+(?:name\s+(.+)|state\s+\S+)$/);
    if (!m) return;
    expandVlans(m[1]).forEach(id => {
      if (!vmap.has(id)) vmap.set(id, { id, name: '', ipSubnets: [] });
      if (m[2]) vmap.get(id).name = m[2].trim();
    });
  });
  const lags = new Map();
  (res.interfaces || []).forEach(i => {
    if (i.nativeVlan === 'none') i.nativeVlan = '';
    if (/^(?:po|sa)\d+$/i.test(i.name)) i.type = 'aggregate';
    const sm = String(i.name).match(/^vlan(\d+)$/i);
    if (sm && i.ip) {
      if (!vmap.has(sm[1])) vmap.set(sm[1], { id: sm[1], name: '', ipSubnets: [] });
      const v = vmap.get(sm[1]);
      if (!v.ipSubnets.some(x => x.cidr === i.ip)) v.ipSubnets.push({ cidr: i.ip });
    }
  });
  res.vlans = [...vmap.values()].sort((a, b) => a.id - b.id);
  const blocks = cfg.split(/^(?=interface\s)/m);
  // trunk：allowed vlan add／remove 累加（比照 Cisco Business 做法），native vlan none 表示沒有原生 VLAN
  const bodyOf = new Map(blocks.map(b => [(b.match(/^interface\s+(\S+)/) || [])[1], b]));
  (res.interfaces || []).forEach(i => {
    const body = bodyOf.get(i.name);
    if (!body || i.mode !== 'trunk') return;
    const add = [...body.matchAll(/switchport trunk allowed vlan add\s+(\S+)/g)].flatMap(m => expandVlans(m[1]));
    const rem = new Set([...body.matchAll(/switchport trunk allowed vlan remove\s+(\S+)/g)].flatMap(m => expandVlans(m[1])));
    if (add.length) i.vlans = [...new Set(add)].filter(v => !rem.has(v)).sort((a, b) => a - b).join(',');
    const nat = (body.match(/switchport trunk native vlan\s+(\S+)/) || [])[1];
    i.nativeVlan = nat === 'none' ? '' : (nat || i.nativeVlan);
  });
  // 聚合：channel-group → poN（LACP），static-channel-group → saN（靜態）
  blocks.forEach(b => {
    const n = (b.match(/^interface\s+(\S+)/) || [])[1];
    if (!n) return;
    let m = b.match(/^\s+channel-group\s+(\d+)\s+mode\s+(active|passive)/m);
    if (m) { const k = 'po' + m[1]; if (!lags.has(k)) lags.set(k, { name: k, mode: 'Active', members: [] }); lags.get(k).members.push({ name: n, lacpMode: m[2][0].toUpperCase() + m[2].slice(1) }); return; }
    m = b.match(/^\s+static-channel-group\s+(\d+)/m);
    if (m) { const k = 'sa' + m[1]; if (!lags.has(k)) lags.set(k, { name: k, mode: 'Static', members: [] }); lags.get(k).members.push({ name: n, lacpMode: null }); }
  });
  res.lacp = [...lags.values()];
  // 靜態路由（CIDR 寫法，下一跳可為介面）
  res.routes = [...cfg.matchAll(/^ip route(?:\s+vrf\s+(\S+))?\s+(\d+\.\d+\.\d+\.\d+\/\d+)\s+(\S+)/gm)]
    .map(m => ({ dst: m[2], gw: m[3], vrf: m[1] || '', gwIsInterface: !/^\d+\.\d+\.\d+\.\d+$/.test(m[3]) }));
  // syslog：log host
  res.syslog = { servers: [...new Set([...cfg.matchAll(/^log host\s+(\S+)/gm)].map(m => m[1]))].map(host => ({ host, facility: '' })) };
  // 帳號：password 8 後的雜湊格式（$1$ md5-crypt、$5$ sha256、$6$ sha512）
  (res.users || []).forEach(u => {
    const h = (cfg.match(new RegExp('^username\\s+' + String(u.name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s+.*?password\\s+\\d+\\s+(\\S+)', 'm')) || [])[1] || '';
    if (/^\$1\$/.test(h)) u.pwdType = 'md5'; else if (/^\$5\$/.test(h)) u.pwdType = 'sha256'; else if (/^\$6\$/.test(h)) u.pwdType = 'sha512';
  });
  return res;
}
