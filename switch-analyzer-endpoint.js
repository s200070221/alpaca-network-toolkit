// ── 終端定位與空 port 盤點（2026-09-29 新增，第六輪 WA/WB） ─────────────────
// 輸入：一台或多台交換器的 show 指令輸出文字（非設定檔），支援
//   Cisco IOS/IOS-XE/NX-OS：show mac address-table／show ip arp（show arp）／show interfaces status
//   Comware：display mac-address／display arp／display interface brief（bridge mode 區段）
// 以 CLI 提示字元（SW1#show ...、SW1>show ...、<SW1>display ...、[SW1]display ...）切分裝置與指令；
// 沒有提示字元時整段視為同一台（device-1），逐行依內容判斷是 MAC／ARP／介面狀態列。
// 純函式、無 DOM 依賴，頂層宣告一律用 ep 前綴避免與其他模組撞名（多個 classic <script>
// 共用同一個全域詞法作用域）。

const EP_UPLINK_MAC_MIN = 5; // 同一埠學到的 MAC 數達此門檻即視為上行／串接埠（終端不會在這裡）

// MAC 正規化為 12 碼小寫十六進位；支援 a1b2.c3d4.e5f6／0050-7966-6800／aa:bb:cc:dd:ee:ff／aa-bb-cc-dd-ee-ff
function epNormMac(s) {
  const t = String(s || '').trim().toLowerCase();
  if (/^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/.test(t) ||
      /^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/.test(t) ||
      /^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$/.test(t)) return t.replace(/[.:-]/g, '');
  return '';
}
function epFmtMac(hex) { return hex ? hex.match(/../g).join(':') : ''; }

// 介面名稱正規化：Cisco 與 Comware 的全名／縮寫對應到同一個家族代號，方便跨輸出比對
// （show interfaces status 用 Gi1/0/1、設定檔用 GigabitEthernet1/0/1、Comware 用 GE1/0/1）
const EP_IFACE_FAMILIES = [
  [/^(ten-gigabitethernet|tengigabitethernet|xge|te)/, 'xge'],
  [/^(twenty-fivegige|twentyfivegige|wge|twe)/, '25ge'],
  [/^(fortygigabitethernet|fortygige|fge|fo)/, '40ge'],
  [/^(hundredgige|hundredgigabitethernet|hge|hu)/, '100ge'],
  [/^(gigabitethernet|ge|gi)/, 'ge'],
  [/^(fastethernet|fa)/, 'fe'],
  [/^(port-channel|bridge-aggregation|bagg|po)/, 'agg'],
  [/^(vlan-interface|vlanif|vlan|vl)/, 'vlan'],
  [/^(ethernet|eth|et)/, 'eth'],
  [/^(m-gigabitethernet|mgmt|mge)/, 'mgmt'],
  [/^(loopback|lo)/, 'lo'],
];
function epNormIface(s) {
  const t = String(s || '').trim().toLowerCase().replace(/\s+/g, '');
  const m = t.match(/^([a-z][a-z\-]*)(\d.*)$/);
  if (!m) return t;
  for (const [re, fam] of EP_IFACE_FAMILIES) if (re.test(m[1]) && m[1].replace(re, '') === '') return fam + m[2];
  return t;
}
function epIsPhysical(port) {
  const fam = (epNormIface(port).match(/^([a-z]+|\d+ge)/) || [''])[0];
  return ['ge', 'xge', '25ge', '40ge', '100ge', 'fe', 'eth'].includes(fam);
}
function epIsAggregate(port) { return /^agg\d/.test(epNormIface(port)); }

// 看起來像介面名稱的 token：字母開頭、含數字（排除 DYNAMIC／Learned／ARPA 等純字母欄位）
const EP_IFACE_TOKEN_RE = /^[A-Za-z][A-Za-z\-]*\d[\d\/:.]*$/;
const EP_IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// 提示字元＋指令列
const EP_PROMPT_RES = [
  /^\s*([A-Za-z0-9][\w.\-]*)[#>]\s*((?:sh|show)\b.*)$/i,   // Cisco
  /^\s*<([\w.\-]+)>\s*((?:dis|display)\b.*)$/i,            // Comware 使用者視圖
  /^\s*\[([\w.\-~]+)\]\s*((?:dis|display)\b.*)$/i,        // Comware 系統視圖
];
function epCmdKind(cmd) {
  const c = String(cmd || '').trim().toLowerCase().replace(/\s+/g, ' ');
  if (/^(sh|show) mac(-| )address-table\b/.test(c) || /^(dis|display) mac-address\b/.test(c)) return 'mac';
  if (/^(sh|show) (ip )?arp\b/.test(c) || /^(dis|display) arp\b/.test(c)) return 'arp';
  if (/^(sh|show) int(erfaces?)? status\b/.test(c) || /^(dis|display) int(erface)? brief\b/.test(c)) return 'status';
  return 'other';
}

// Cisco show interfaces status 的 Status 欄位可能值（含被截斷的寫法）
// Name 欄位用貪婪比對，取「最後一個」狀態關鍵字，避免描述文字內剛好含 up／down 被誤判
const EP_CISCO_STATUS_RE = /^(\S+)\s+(?:(.*\S)\s+)?(connected|notconnect|notconnec|disabled|err-disabled|err-disable|inactive|monitoring|suspended|sfpAbsent|xcvrAbsen|xcvrAbsent|noOperMem|linkFlapE|channelDo|down|up)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$/;
const EP_COMWARE_BRIEF_RE = /^(\S+)\s+(UP|DOWN|ADM|Stby|\*DOWN)\s+(\S+)\s+(\S+)\s+([ATH])\s+(\d+)\s*(.*)$/;

function epStatusNorm(raw) {
  const s = String(raw || '').toLowerCase();
  if (s === 'connected' || s === 'up') return 'connected';
  if (s === 'disabled' || s === 'adm') return 'disabled';
  if (s.startsWith('err-disable')) return 'err-disabled';
  if (s === 'notconnect' || s === 'notconnec' || s === 'down' || s === '*down' || s === 'sfpabsent' || s.startsWith('xcvrabsen')) return 'notconnect';
  return s;
}

function epParseMacRow(line) {
  const toks = line.trim().split(/\s+/);
  const mi = toks.findIndex(t => epNormMac(t));
  if (mi < 0) return null;
  let vlan = '';
  for (let i = mi - 1; i >= 0; i--) if (/^\d{1,4}$/.test(toks[i])) { vlan = toks[i]; break; }
  if (!vlan && /^\d{1,4}$/.test(toks[mi + 1] || '')) vlan = toks[mi + 1];
  const after = toks.slice(mi + 1);
  const type = (after.find(t => /^[A-Za-z]+$/.test(t)) || '');
  const ports = after.filter(t => EP_IFACE_TOKEN_RE.test(t));
  if (!vlan || !ports.length) return null; // CPU／Router／All 等非終端項目
  return { mac: epNormMac(toks[mi]), vlan, type, port: ports[ports.length - 1] };
}
function epParseArpRow(line) {
  const toks = line.trim().split(/\s+/);
  const ii = toks.findIndex(t => EP_IPV4_RE.test(t));
  const mi = toks.findIndex(t => epNormMac(t));
  if (ii < 0 || mi < 0) return null;
  const after = toks.slice(mi + 1);
  let vlan = /^\d{1,4}$/.test(after[0] || '') ? after[0] : '';  // Comware：MAC 後面緊接 VLAN ID
  const iface = after.find(t => EP_IFACE_TOKEN_RE.test(t)) || '';
  if (!vlan) { const vm = epNormIface(iface).match(/^vlan(\d+)$/); if (vm) vlan = vm[1]; }
  return { ip: toks[ii], mac: epNormMac(toks[mi]), vlan, iface };
}
function epParseStatusRow(line) {
  let m = line.match(EP_COMWARE_BRIEF_RE);
  if (m) return { port: m[1], name: m[7].trim(), statusRaw: m[2], status: epStatusNorm(m[2]), vlan: m[6], duplex: m[4], speed: m[3], type: '', trunk: m[5] === 'T' || m[5] === 'H' };
  m = line.match(EP_CISCO_STATUS_RE);
  if (m && EP_IFACE_TOKEN_RE.test(m[1])) {
    const name = (m[2] || '').trim() === '--' ? '' : (m[2] || '').trim();
    return { port: m[1], name, statusRaw: m[3], status: epStatusNorm(m[3]), vlan: m[4], duplex: m[5], speed: m[6], type: m[7].trim(), trunk: m[4].toLowerCase() === 'trunk' };
  }
  return null;
}

// 主解析：回傳 {devices:[{name,macs,arps,ports}]}
function parseEndpointText(text) {
  const lines = String(text || '').replace(/\r\n/g, '\n').split('\n');
  const devices = [];
  const byName = {};
  const getDev = name => {
    const key = name.toLowerCase();
    if (!byName[key]) { byName[key] = { name, macs: [], arps: [], ports: [] }; devices.push(byName[key]); }
    return byName[key];
  };
  let dev = null, kind = 'auto', inBridgeBrief = false;
  for (const line of lines) {
    let pm = null;
    for (const re of EP_PROMPT_RES) { pm = line.match(re); if (pm) break; }
    if (pm) { dev = getDev(pm[1]); kind = epCmdKind(pm[2]); inBridgeBrief = false; continue; }
    if (!line.trim()) continue;
    if (kind === 'other') continue;
    // Comware display interface brief 先輸出 route mode 區段（Link/Protocol/IP），只取含 PVID 的 bridge mode 區段
    if (/\bPVID\b/.test(line) && /\bLink\b/.test(line)) { inBridgeBrief = true; continue; }
    if (/\bProtocol\b/.test(line) && /\bLink\b/.test(line)) { inBridgeBrief = false; continue; }
    const d = dev || getDev('device-1');
    if (kind === 'mac' || kind === 'auto') { const r = epParseMacRow(line); if (r && !(kind === 'auto' && line.split(/\s+/).some(t => EP_IPV4_RE.test(t)))) { d.macs.push(r); continue; } }
    if (kind === 'arp' || kind === 'auto') { const r = epParseArpRow(line); if (r) { d.arps.push(r); continue; } }
    if (kind === 'status' || kind === 'auto') {
      const r = epParseStatusRow(line);
      if (r && (!EP_COMWARE_BRIEF_RE.test(line) || inBridgeBrief || kind === 'auto')) d.ports.push(r);
    }
  }
  return { devices: devices.filter(d => d.macs.length || d.arps.length || d.ports.length) };
}

// 每台裝置每個埠學到幾個不同 MAC（判斷上行／串接埠用）
function epMacCountByPort(dev) {
  const cnt = {};
  const seen = {};
  for (const m of dev.macs) {
    const k = epNormIface(m.port);
    seen[k] = seen[k] || new Set();
    seen[k].add(m.mac);
  }
  for (const k in seen) cnt[k] = seen[k].size;
  return cnt;
}
function epPortInfo(dev, port) {
  const k = epNormIface(port);
  return dev.ports.find(p => epNormIface(p.port) === k) || null;
}
// cfgIfaces（選填）：已載入設定檔的 parsed.interfaces，用來補描述與辨識 trunk
function epCfgIface(cfgIfaces, port) {
  if (!Array.isArray(cfgIfaces)) return null;
  const k = epNormIface(port);
  return cfgIfaces.find(i => epNormIface(i.name) === k) || null;
}

// 查詢 IP 或 MAC（MAC 可部分比對，至少 4 碼十六進位）
// cfgByDevice（選填）：{裝置名稱小寫: parsed.interfaces}
function epLookup(model, query, cfgByDevice) {
  const q = String(query || '').trim();
  const res = { query: q, kind: '', macs: [], arpSeen: [], locations: [] };
  if (!q || !model) return res;
  const devs = model.devices || [];
  let macSet = new Set();
  if (EP_IPV4_RE.test(q)) {
    res.kind = 'ip';
    for (const d of devs) for (const a of d.arps) if (a.ip === q) { res.arpSeen.push({ device: d.name, ...a }); macSet.add(a.mac); }
  } else {
    const full = epNormMac(q);
    const part = full || q.toLowerCase().replace(/[.:\-\s]/g, '');
    if (!/^[0-9a-f]{4,12}$/.test(part)) return res;
    res.kind = 'mac';
    for (const d of devs) {
      for (const m of d.macs) if (full ? m.mac === full : m.mac.includes(part)) macSet.add(m.mac);
      for (const a of d.arps) if (full ? a.mac === full : a.mac.includes(part)) { macSet.add(a.mac); }
    }
    for (const d of devs) for (const a of d.arps) if (macSet.has(a.mac)) res.arpSeen.push({ device: d.name, ...a });
  }
  res.macs = [...macSet];
  for (const d of devs) {
    const counts = epMacCountByPort(d);
    const cfg = cfgByDevice ? cfgByDevice[d.name.toLowerCase()] : null;
    for (const m of d.macs) {
      if (!macSet.has(m.mac)) continue;
      const st = epPortInfo(d, m.port);
      const ci = epCfgIface(cfg, m.port);
      const macCount = counts[epNormIface(m.port)] || 0;
      const uplink = macCount >= EP_UPLINK_MAC_MIN || epIsAggregate(m.port) || !!(st && st.trunk) || !!(ci && ci.mode === 'trunk');
      res.locations.push({
        device: d.name, mac: m.mac, vlan: m.vlan, port: m.port, type: m.type, macCount, uplink,
        status: st ? st.status : '', desc: (st && st.name) || (ci && ci.desc) || '', speed: st ? st.speed : '',
      });
    }
  }
  // 終端埠優先，再依裝置名稱排序
  res.locations.sort((a, b) => (a.uplink - b.uplink) || a.device.localeCompare(b.device));
  return res;
}

// 空 port 盤點：只看實體埠
//   free：未連線（notconnect／disabled）、沒有描述、VLAN 為預設（1 或空）、MAC 表中沒看到任何 MAC
//   stale：未連線，但有描述或非預設 VLAN（有設定卻沒接線，可能是搬走的設備或該回收的埠）
//   errdisabled：err-disabled
// 僅反映擷取當下狀態，無法得知「多久沒接線」
function epFreePorts(model, cfgByDevice) {
  const rows = [];
  const stats = [];
  for (const d of (model && model.devices) || []) {
    const counts = epMacCountByPort(d);
    const cfg = cfgByDevice ? cfgByDevice[d.name.toLowerCase()] : null;
    const st = { device: d.name, total: 0, connected: 0, free: 0, stale: 0, errdisabled: 0 };
    for (const p of d.ports) {
      if (!epIsPhysical(p.port)) continue;
      st.total++;
      const ci = epCfgIface(cfg, p.port);
      const desc = p.name || (ci && ci.desc) || '';
      let category = '';
      if (p.status === 'connected') { st.connected++; continue; }
      if (p.status === 'err-disabled') category = 'errdisabled';
      else if (p.status === 'notconnect' || p.status === 'disabled') {
        const nonDefaultVlan = p.vlan && !/^(1|trunk|routed|unassigned)$/i.test(p.vlan);
        const hasMac = (counts[epNormIface(p.port)] || 0) > 0;
        category = (desc || nonDefaultVlan || p.trunk || hasMac) ? 'stale' : 'free';
      } else continue;
      st[category]++;
      rows.push({ device: d.name, port: p.port, status: p.status, vlan: p.vlan, speed: p.speed, type: p.type, desc, category });
    }
    if (d.ports.length) stats.push(st);
  }
  return { rows, stats };
}

// ── 配線表（2026-09-30 新增，第八輪 XD） ───────────────────────────────────
// 每個實體／聚合介面一列：描述、模式、VLAN、管理狀態，加上已解析的 LLDP／CDP 鄰居（parsed.lldp），
// 以及終端定位資料（epModel，選填）中「主機名稱與設定檔相同」那台的連線狀態與該埠學到的 MAC／IP。
// 同一埠學到的 MAC 達 EP_UPLINK_MAC_MIN 個、或是 trunk／聚合埠時不逐一列出，只標上行與數量。
// 介面名稱一律經 epNormIface() 比對（設定檔全名、LLDP 與 show 輸出的縮寫可互相對上）。
// 回傳 { rows, device }，device 為對上的終端定位裝置名稱（沒對上為空字串）。
function epBuildCablingSheet(parsed, epModel) {
  const host = String((parsed && parsed.sys && parsed.sys.hostname) || '').toLowerCase();
  const dev = host && epModel && epModel.devices ? epModel.devices.find(d => d.name.toLowerCase() === host) : null;
  const macCnt = dev ? epMacCountByPort(dev) : {};
  const ipByMac = {};
  if (epModel && epModel.devices) epModel.devices.forEach(d => d.arps.forEach(a => { if (!ipByMac[a.mac]) ipByMac[a.mac] = a.ip; }));
  const lldp = (parsed && parsed.lldp) || [];
  const rows = ((parsed && parsed.interfaces) || [])
    .filter(i => i.type !== 'svi' && i.type !== 'loopback' && !/^(vlan|lo|mgmt)\d/.test(epNormIface(i.name)))
    .map(i => {
      const k = epNormIface(i.name);
      let vlan = '';
      if (i.mode === 'access') vlan = String(i.vlans || '');
      else if (i.mode === 'trunk') vlan = String(i.vlans || 'all') + (i.nativeVlan ? ` (native ${i.nativeVlan})` : '');
      else if (i.mode === 'hybrid' && i.hybrid) vlan = 'PVID ' + (i.hybrid.pvid || '-');
      else if (i.ip) vlan = i.ip;
      const nb = lldp.filter(n => epNormIface(n.localPort) === k).map(n => n.neighbor + (n.remotePort ? ' ' + n.remotePort : ''));
      const st = dev ? epPortInfo(dev, i.name) : null;
      const macs = dev ? dev.macs.filter(m => epNormIface(m.port) === k) : [];
      const uplink = (macCnt[k] || 0) >= EP_UPLINK_MAC_MIN || epIsAggregate(i.name) || i.mode === 'trunk';
      return {
        port: i.name, desc: i.desc || '', mode: i.mode || (i.ip ? 'routed' : ''), vlan,
        shutdown: !!i.shutdown, link: st ? st.status : '',
        neighbor: nb.join('; '),
        macCount: macCnt[k] || 0, uplink,
        endpoints: uplink ? [] : macs.map(m => ({ mac: m.mac, ip: ipByMac[m.mac] || '', vlan: m.vlan })),
      };
    });
  return { rows, device: dev ? dev.name : '' };
}
