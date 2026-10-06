// ═══ wifi-parser.js ═══
/**
 * FortiGate WiFi Configuration Parser
 * Parses: wireless-controller vap, wtp-profile, wtp, wids-profile, settings
 * Returns structured WiFi analysis data
 */

// 2026-08-19 從 parseFortigateWifi() 內部抽到頂層（純函式，無外部依賴，抽出不影響既有
// 行為）：供本輪新增的 MikroTik/OpenWrt/pfSense WiFi 解析共用，避免重寫評分邏輯
function gradeVap(vap) {
  const issues = [];
  const score_deductions = [];

  if (vap.security === 'open' && !vap.captivePortal) {
    issues.push({ level: 'critical', msg: 'wifi.msg_fully_open' });
    score_deductions.push(50);
  } else if (vap.security === 'open' && vap.captivePortal) {
    issues.push({ level: 'warn', msg: 'wifi.msg_captive_open' });
    score_deductions.push(20);
  }

  // WEP 與 TKIP（WPA1）已被破解或淘汰（2026-10-05 新增，無線控制器支援時一併補上；FortiGate wep64／wep128 同樣適用）
  if (/wep/i.test(vap.security)) {
    issues.push({ level: 'critical', msg: 'wifi.msg_weak_cipher' });
    score_deductions.push(40);
  } else if (/tkip/i.test(vap.security)) {
    issues.push({ level: 'warn', msg: 'wifi.msg_weak_cipher' });
    score_deductions.push(20);
  }

  if (vap.security.includes('wpa2') && !vap.security.includes('wpa3')) {
    issues.push({ level: 'info', msg: 'wifi.msg_wpa2_only' });
    score_deductions.push(5);
  }

  if (vap.pmf === '-' || vap.pmf === 'disable') {
    issues.push({ level: 'info', msg: 'wifi.msg_no_pmf' });
    score_deductions.push(5);
  }

  if (vap.intraVapPrivacy) {
    // Good: clients can't talk to each other
  } else if (vap.security === 'open') {
    issues.push({ level: 'warn', msg: 'wifi.msg_no_intra_vap' });
    score_deductions.push(10);
  }

  const score = Math.max(0, 100 - score_deductions.reduce((a,b) => a+b, 0));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, issues };
}
// 2026-08-19 從 parseFortigateWifi() 內部的 summary 組裝區塊抽到頂層共用（純函式，無外部
// 依賴）：新增的 3 家 WiFi 解析與 firewall-analyzer-app.js 合併多廠牌 WiFi 資料時共用，
// 傳入空陣列（wtpProfiles/wtps/widsProfiles）時 AP 相關欄位自然為 0，不需另開簡化版
function buildWifiSummary(vaps, wtpProfiles, wtps, widsProfiles, country) {
  return {
    country: country || '-',
    ssidCount:    vaps.length,
    apCount:      wtps.length,
    profileCount: wtpProfiles.length,
    widsCount:    widsProfiles.length,
    openSsids:    vaps.filter(v => v.security === 'open' && !v.captivePortal).length,
    captiveSsids: vaps.filter(v => v.captivePortal).length,
    hiddenSsids:  vaps.filter(v => !v.broadcastSsid).length,
    wpa3Ssids:    vaps.filter(v => v.security.includes('wpa3')).length,
    vlanSsids:    vaps.filter(v => v.vlanId !== '-').length,
    wifi6Aps:     wtpProfiles.filter(p => p.wifiGen.includes('Wi-Fi 6')).length,
    dualBandAps:  wtpProfiles.filter(p => p.has2G && p.has5G).length,
    criticalIssues: vaps.reduce((n,v) => n + v.secIssues.filter(i=>i.level==='critical').length, 0),
    warnIssues:     vaps.reduce((n,v) => n + v.secIssues.filter(i=>i.level==='warn').length, 0),
    avgSecScore:  vaps.length ? Math.round(vaps.reduce((s,v) => s+v.secScore, 0) / vaps.length) : 0,
  };
}

function parseFortigateWifi(text) {
  text = text.replace(/\r\n/g, '\n'); // 自我防禦：不依賴呼叫端是否已正規化 CRLF

  // ── Section extractor ─────────────────────────────────────────────────────
  // VDOM 感知版：接受 sourceText 參數，從指定文字中提取 config 區塊
  function getSection(sourceText, sectionKey) {
    const escaped = sectionKey.replace(/[-]/g, '\\-');
    const re = new RegExp(`^[ \\t]*config ${escaped}[ \\t]*$`, 'gim');
    const allLines = sourceText.split('\n');
    const out = [];
    let match;
    while ((match = re.exec(sourceText)) !== null) {
      const beforeMatch = sourceText.slice(0, match.index);
      const startLineIdx = beforeMatch.split('\n').length;
      let depth = 0;
      for (let li = startLineIdx; li < allLines.length; li++) {
        const t = allLines[li].trim();
        if (t.startsWith('config ')) depth++;
        if (t === 'end') {
          if (depth === 0) break;
          depth--;
        }
        out.push(allLines[li]);
      }
    }
    return out.join('\n');
  }

  // Parse edit blocks: returns array of {name, body}
  // Fix: 去重 — multi-VDOM 合併後同名 edit 只保留第一個（wireless-controller 設定為全域，各 vdom 重複）
  function parseEdits(sectionText) {
    const result = [];
    const seen = new Set();
    const lines = sectionText.split('\n');
    let cur = null, depth = 0;
    for (const line of lines) {
      const t = line.trim();
      if (t.startsWith('edit ') && depth === 0) {
        if (cur) { if (!seen.has(cur.name)) { seen.add(cur.name); result.push(cur); } }
        cur = { name: t.slice(5).replace(/^"|"$/g, ''), body: '' };
      } else if (cur) {
        if (t.startsWith('config ')) depth++;
        if (t === 'end' && depth > 0) depth--;
        else if (t === 'next' && depth === 0) {
          if (!seen.has(cur.name)) { seen.add(cur.name); result.push(cur); }
          cur = null; continue;
        }
        cur.body += line + '\n';
      }
    }
    if (cur && !seen.has(cur.name)) result.push(cur);
    return result;
  }

  function gv(body, key) {
    const m = new RegExp(`^\\s*set ${key}\\s+(.+)$`, 'im').exec(body);
    if (!m) return '-';
    return m[1].trim().replace(/^"|"$/g, '');
  }
  function gvMulti(body, key) {
    const m = new RegExp(`^\\s*set ${key}\\s+(.+)$`, 'im').exec(body);
    if (!m) return [];
    return m[1].trim().replace(/^"|"$/g, '').split(/\s+/).map(s => s.replace(/^"|"$/g,'').trim()).filter(Boolean);
  }
  // 逐行掃描＋depth 計數抽取 config radio-N 區塊（比照同檔案 getSection()/parseEdits() 既有
  // depth-tracking 手法），取代原本依賴「end 前面剛好縮排4格」的正則收尾——真實 FortiGate
  // 匯出檔巢狀層級縮排常見是 8 格（wtp-profile→edit→config radio-N），並非固定4格，
  // 原正則在真實縮排下會整段漏解析甚至完全解析不到（2026-09 全功能審查發現）
  function extractRadioBlocks(text) {
    const lines = text.split('\n');
    const blocks = [];
    let cur = null, depth = 0;
    for (const line of lines) {
      const t = line.trim();
      const m = depth === 0 ? t.match(/^config radio-(\d+)$/) : null;
      if (m && !cur) { cur = { id: m[1], body: '' }; depth = 1; continue; }
      if (cur) {
        if (t.startsWith('config ')) depth++;
        if (t === 'end') {
          depth--;
          if (depth === 0) { blocks.push(cur); cur = null; continue; }
        }
        cur.body += line + '\n';
      }
    }
    if (cur) blocks.push(cur);
    return blocks;
  }
  function hasKey(body, key) {
    return new RegExp(`^\\s*set ${key}\\s`, 'im').test(body);
  }

  // ── Security grading：gradeVap() 已抽到檔案頂層共用，此處不再重複定義 ──────

  // ── 取得 per-VDOM 文字區塊（single-VDOM 時回傳 [{name:'root', lines:[全文]}]）
  const { vdomBlocks } = FortigateParser.splitTopLevel(text);

  // ── 1-4. 依 VDOM 解析各 wireless-controller 區塊，標記 _vdom ────────────
  const vaps = [], wtpProfiles = [], wtps = [], widsProfiles = [];

  for (const { name: _vdom, lines } of vdomBlocks) {
    const vdomText = lines.join('\n');

    // 1. VAP (SSID profiles)
    parseEdits(getSection(vdomText, 'wireless-controller vap')).forEach(e => {
      const b = e.body;
      const security   = gv(b, 'security') === '-' ? 'wpa2-only' : gv(b, 'security');
      const captive    = hasKey(b, 'captive-portal');
      const intraPriv  = hasKey(b, 'intra-vap-privacy');
      const broadcast  = gv(b, 'broadcast-ssid') !== 'disable';
      const pmf        = gv(b, 'pmf');
      const vlanId     = gv(b, 'vlanid');
      const passphrase = hasKey(b, 'passphrase') ? (gv(b, 'passphrase').startsWith('ENC') ? tr('wifi.pass_enc') : tr('wifi.pass_plain')) : '-';
      const authMode   = gv(b, 'auth');
      const radius     = gv(b, 'radius-server');
      const addrGroup  = gv(b, 'address-group');
      const userGroups = gv(b, 'selected-usergroups');
      const schedId    = gv(b, 'schedule');
      const portal     = gv(b, 'portal-type');
      const localBr    = gv(b, 'local-bridging');
      const ssid       = gv(b, 'ssid') !== '-' ? gv(b, 'ssid') : e.name;
      const vap = {
        name: e.name, ssid, security, captivePortal: captive,
        intraVapPrivacy: intraPriv, broadcastSsid: broadcast, pmf,
        vlanId, passphrase, authMode, radius, addrGroup,
        userGroups, schedule: schedId, portalType: portal,
        localBridging: localBr,
      };
      const { score, grade, issues } = gradeVap(vap);
      vaps.push({ ...vap, secScore: score, secGrade: grade, secIssues: issues, _vdom });
    });

    // 2. WTP-Profile (AP hardware profiles)
    parseEdits(getSection(vdomText, 'wireless-controller wtp-profile')).forEach(e => {
      const b = e.body;
      const platformM = /config platform[\s\S]*?set type\s+(\S+)/i.exec(b);
      const platform  = platformM ? platformM[1] : '-';
      const handoff   = gv(b, 'handoff-sta-thresh');
      const widsProf  = gv(b, 'wids-profile');
      const country   = gv(b, 'country');
      const radios = [];
      extractRadioBlocks(b).forEach(rm => {
        const rBody = rm.body;
        const band = gv(rBody, 'band');
        const mode = gv(rBody, 'mode');
        const channel = gv(rBody, 'channel');
        const txPower = gv(rBody, 'auto-tx-power-level') !== '-' ? gv(rBody, 'auto-tx-power-level') : gv(rBody, 'tx-power-level');
        const dtim   = gv(rBody, 'dtim');
        const beacon = gv(rBody, 'beacon-interval');
        const vapRefs = [];
        for (let i = 1; i <= 8; i++) {
          const v = gv(rBody, `vap${i}`);
          if (v !== '-') vapRefs.push(v);
        }
        radios.push({ id: parseInt(rm.id), band, mode, channel, txPower, dtim, beacon, vaps: vapRefs });
      });
      const has5G  = radios.some(r => r.band && r.band.includes('5G'));
      const has2G  = radios.some(r => r.band && (r.band.includes('2G') || r.band.includes('2.4')));
      const hasAX  = radios.some(r => r.band && r.band.includes('ax'));
      const hasAC  = radios.some(r => r.band && r.band.includes('ac'));
      const hasMonitor = radios.some(r => r.mode === 'monitor');
      const wifiGen = hasAX ? 'Wi-Fi 6 (802.11ax)' : hasAC ? 'Wi-Fi 5 (802.11ac)' : 'Wi-Fi 4 (802.11n)';
      wtpProfiles.push({ name: e.name, platform, wifiGen, has2G, has5G, hasMonitor, handoffThresh: handoff, widsProfile: widsProf, country, radios, _vdom });
    });

    // 3. WTP (Managed AP instances)
    parseEdits(getSection(vdomText, 'wireless-controller wtp')).forEach(e => {
      const b = e.body;
      wtps.push({
        serial: e.name, uuid: gv(b, 'uuid'), name: gv(b, 'name'),
        location: gv(b, 'location'), profile: gv(b, 'wtp-profile'),
        admin: gv(b, 'admin'), status: gv(b, 'admin') === 'enable' ? 'enable' : 'disable',
        _vdom,
      });
    });

    // 4. WIDS Profile
    parseEdits(getSection(vdomText, 'wireless-controller wids-profile')).forEach(e => {
      const b = e.body;
      const checks = {
        apScan:          hasKey(b, 'ap-scan') && gv(b,'ap-scan') !== 'disable',
        wirelessBridge:  gv(b, 'wireless-bridge') === 'enable',
        deauthBroadcast: gv(b, 'deauth-broadcast') === 'enable',
        spoofedDeauth:   gv(b, 'spoofed-deauth') === 'enable',
        weakWepIv:       gv(b, 'weak-wep-iv') === 'enable',
        asleapAttack:    gv(b, 'asleap-attack') === 'enable',
        nullSsidProbe:   gv(b, 'null-ssid-probe-resp') === 'enable',
        eapolFlood:      gv(b, 'eapol-start-flood') === 'enable',
        longDuration:    gv(b, 'long-duration-attack') === 'enable',
        invalidMacOui:   gv(b, 'invalid-mac-oui') === 'enable',
      };
      const enabled = Object.values(checks).filter(Boolean).length;
      const total   = Object.keys(checks).length;
      widsProfiles.push({ name: e.name, comment: gv(b, 'comment'), checks, enabledCount: enabled, totalCount: total, coverage: Math.round(enabled / total * 100), _vdom });
    });
  }

  // ── 5. Global settings ────────────────────────────────────────────────────
  const settingSection = getSection(text, 'wireless-controller setting');
  const country = (() => {
    const m = /set country\s+(\S+)/i.exec(settingSection);
    return m ? m[1] : '-';
  })();

  // ── 6. Cross-reference: VAP → APs ─────────────────────────────────────────
  // Build map: SSID/VAP name → which AP profiles use it
  const vapToProfiles = {};
  wtpProfiles.forEach(prof => {
    prof.radios.forEach(radio => {
      radio.vaps.forEach(vapName => {
        if (!vapToProfiles[vapName]) vapToProfiles[vapName] = new Set();
        vapToProfiles[vapName].add(prof.name);
      });
    });
  });
  // Enrich VAPs with profile references
  vaps.forEach(v => {
    v.usedInProfiles = vapToProfiles[v.name] ? [...vapToProfiles[v.name]] : [];
    v.deployedOnAps  = wtps.filter(ap => v.usedInProfiles.includes(ap.profile)).length;
  });

  // ── 7. Summary stats ──────────────────────────────────────────────────────
  const summary = buildWifiSummary(vaps, wtpProfiles, wtps, widsProfiles, country);

  return { vaps, wtpProfiles, wtps, widsProfiles, summary };
}

/**
 * FortiSwitch (FortiLink managed-switch) Analysis Parser
 * Parses: switch-controller managed-switch（含巢狀 config ports）
 * Returns structured switch/port data
 */
function parseFortigateSwitchController(text) {
  text = text.replace(/\r\n/g, '\n'); // 自我防禦：不依賴呼叫端是否已正規化 CRLF

  // ── Section extractor（同 parseFortigateWifi 的 VDOM 感知版）───────────────
  function getSection(sourceText, sectionKey) {
    const escaped = sectionKey.replace(/[-]/g, '\\-');
    const re = new RegExp(`^[ \\t]*config ${escaped}[ \\t]*$`, 'gim');
    const allLines = sourceText.split('\n');
    const out = [];
    let match;
    while ((match = re.exec(sourceText)) !== null) {
      const beforeMatch = sourceText.slice(0, match.index);
      const startLineIdx = beforeMatch.split('\n').length;
      let depth = 0;
      for (let li = startLineIdx; li < allLines.length; li++) {
        const t = allLines[li].trim();
        if (t.startsWith('config ')) depth++;
        if (t === 'end') {
          if (depth === 0) break;
          depth--;
        }
        out.push(allLines[li]);
      }
    }
    return out.join('\n');
  }

  // Parse edit blocks: returns array of {name, body}（同名 edit 去重，比照 parseFortigateWifi）
  function parseEdits(sectionText) {
    const result = [];
    const seen = new Set();
    const lines = sectionText.split('\n');
    let cur = null, depth = 0;
    for (const line of lines) {
      const t = line.trim();
      if (t.startsWith('edit ') && depth === 0) {
        if (cur) { if (!seen.has(cur.name)) { seen.add(cur.name); result.push(cur); } }
        cur = { name: t.slice(5).replace(/^"|"$/g, ''), body: '' };
      } else if (cur) {
        if (t.startsWith('config ')) depth++;
        if (t === 'end' && depth > 0) depth--;
        else if (t === 'next' && depth === 0) {
          if (!seen.has(cur.name)) { seen.add(cur.name); result.push(cur); }
          cur = null; continue;
        }
        cur.body += line + '\n';
      }
    }
    if (cur && !seen.has(cur.name)) result.push(cur);
    return result;
  }

  function gv(body, key) {
    const m = new RegExp(`^\\s*set ${key}\\s+(.+)$`, 'im').exec(body);
    if (!m) return '-';
    return m[1].trim().replace(/^"|"$/g, '');
  }

  const { vdomBlocks } = FortigateParser.splitTopLevel(text);

  const switches = [], ports = [], macPolicies = [], nacPolicies = [], nacDevices = [];

  for (const { name: _vdom, lines } of vdomBlocks) {
    const vdomText = lines.join('\n');

    // NAC 動態 VLAN 指派：管理者定義的 MAC Policy（set vlan 即生效 VLAN）與比對規則（NAC Policy），
    // 兩者皆為管理者主動配置的政策物件，一定會出現在設定檔內
    parseEdits(getSection(vdomText, 'switch-controller mac-policy')).forEach(mp => {
      macPolicies.push({
        name: mp.name,
        vlan: gv(mp.body, 'vlan'),
        description: gv(mp.body, 'description'),
        _vdom,
      });
    });

    parseEdits(getSection(vdomText, 'user nac-policy')).forEach(np => {
      nacPolicies.push({
        name: np.name,
        category: gv(np.body, 'category'),
        os: gv(np.body, 'os'),
        switchMacPolicy: gv(np.body, 'switch-mac-policy'),
        description: gv(np.body, 'description'),
        _vdom,
      });
    });

    // nac-device：FortiSwitch 學習到、比對成功的裝置清單，是執行期學習狀態序列化進設定檔的區塊，
    // 不保證所有真實環境的匯出都包含此區塊（信心中等），下方 port.nacVlan 的 post-pass 已對此做
    // graceful degradation（沒有 nac-device 資料時維持 '-'，不影響其餘顯示）
    parseEdits(getSection(vdomText, 'switch-controller nac-device')).forEach(nd => {
      nacDevices.push({
        id: nd.name,
        mac: gv(nd.body, 'mac'),
        lastKnownSwitch: gv(nd.body, 'last-known-switch'),
        lastKnownPort: gv(nd.body, 'last-known-port'),
        matchedNacPolicy: gv(nd.body, 'matched-nac-policy'),
        macPolicy: gv(nd.body, 'mac-policy'),
        status: gv(nd.body, 'status'),
        description: gv(nd.body, 'description'),
        _vdom,
      });
    });

    parseEdits(getSection(vdomText, 'switch-controller managed-switch')).forEach(sw => {
      // edit 索引鍵（switch-id）預設等於序號，但管理者可重新命名成好記代號；
      // 真正硬體序號要看 set sn（獨立欄位，未設定時代表從未被改名過，此時 switch-id 本身就是序號）
      const switchId = sw.name;
      const sn = gv(sw.body, 'sn');
      const fsw1Admin = gv(sw.body, 'fsw-wan1-admin');
      const fsw1Peer  = gv(sw.body, 'fsw-wan1-peer');
      const description = gv(sw.body, 'description');

      const swPorts = parseEdits(getSection(sw.body, 'ports'));
      swPorts.forEach(p => {
        ports.push({
          switchId,
          name: p.name,
          description: gv(p.body, 'description'),
          vlan: gv(p.body, 'vlan'),
          nativeVlan: gv(p.body, 'native-vlan'),
          allowedVlans: gv(p.body, 'allowed-vlans'),
          poeStatus: gv(p.body, 'poe-status'),
          speed: gv(p.body, 'speed'),
          status: gv(p.body, 'status'),
          stpState: gv(p.body, 'stp-state'),
          loopGuard: gv(p.body, 'loop-guard'),
          portSecurityPolicy: gv(p.body, 'port-security-policy'),
          poeCapable: gv(p.body, 'poe-capable'),
          macAddr: gv(p.body, 'mac-addr'),
          exportTo: gv(p.body, 'export-to'),
          _vdom,
        });
      });

      switches.push({
        switchId, sn, description,
        fsw1Admin: fsw1Admin === '-' ? 'enable' : fsw1Admin,
        fsw1Peer,
        portCount: swPorts.length,
        _vdom,
      });
    });
  }

  // NAC 生效 VLAN 兩級查找：nac-device 依 last-known-switch+last-known-port 對應到某個 port，
  // 該裝置的 mac-policy 欄位直接查 macPolicies 表即可得知生效 VLAN（不需要再繞經 nac-policy 比對）
  const macPolicyVlan = new Map(macPolicies.map(mp => [mp.name, mp.vlan]));
  ports.forEach(p => {
    const dev = nacDevices.find(d => d._vdom === p._vdom && d.lastKnownSwitch === p.switchId && d.lastKnownPort === p.name);
    if (dev) {
      p.nacMac = dev.mac;
      p.nacMatchedPolicy = dev.matchedNacPolicy;
      p.nacMacPolicy = dev.macPolicy;
      p.nacVlan = macPolicyVlan.has(dev.macPolicy) ? macPolicyVlan.get(dev.macPolicy) : '-';
    } else {
      p.nacVlan = '-';
    }
  });

  const summary = {
    switchCount: switches.length,
    portCount: ports.length,
    poeEnabledCount: ports.filter(p => p.poeStatus === 'enable').length,
    upPortCount: ports.filter(p => p.status === 'up' || p.status === '-').length,
    portSecurityCount: ports.filter(p => p.portSecurityPolicy !== '-').length,
    nacDeviceCount: nacDevices.length,
    nacDynamicPortCount: ports.filter(p => p.nacVlan !== '-').length,
  };

  return { switches, ports, macPolicies, nacPolicies, nacDevices, summary };
}

// ══════════════════════════════════════════════════════════════════
// 2026-08-19 新增：MikroTik／OpenWrt／pfSense 三家對外查證後確認可解析 WiFi/WLAN
// 設定，補上原本「僅 FortiGate 支援」的缺口。三者皆為「自身即為 AP」架構（非 FortiGate
// 那種控制器管理外接 AP 的模型），故只填 vaps（SSID 清單）＋summary，wtpProfiles/wtps/
// widsProfiles 固定空陣列，沿用頂層共用的 gradeVap()/buildWifiSummary()。
// Sophos／SonicWall 對外查證後查無可信 CLI/config 語法佐證，維持排除（見
// firewall-analyzer-app.js 的 WIFI_UNSUPPORTED 清單）。
// ══════════════════════════════════════════════════════════════════

// ── MikroTik RouterOS ────────────────────────────────────────────────────
// 官方 MikroTik 文件真實範例查證：RouterOS v7.13+ 統一 /interface wifi 選單，單行 set/add
// 指令內用點號巢狀屬性路徑（configuration.ssid=／security.authentication-types=／
// configuration.hide-ssid=）。舊版 /interface wireless（ssid= 直接屬性＋security-profile
// 具名物件交叉引用）語法本輪未涵蓋，MVP 範圍僅新版統一選單。
function parseMikrotikWifi(text) {
  text = text.replace(/\r\n/g, '\n');
  const vaps = [];
  // 真實 /export 輸出是「區塊標頭 + 後續裸 set/add 行」（/interface wifi 單獨一行，接著
  // 逐行 set/add 不重複路徑），非每行自帶完整路徑；同時保留對單行自帶完整路徑格式的相容
  const bodyLines = [];
  let inWifiCtx = false;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const inlineM = /^\/interface\s+(?:wifi|wifiwave2)\s+(?:set|add)\s+(.+)$/i.exec(line);
    if (inlineM) { bodyLines.push(inlineM[1]); continue; }
    if (/^\/interface\s+(?:wifi|wifiwave2)\s*$/i.test(line)) { inWifiCtx = true; continue; }
    if (/^\//.test(line)) { inWifiCtx = false; continue; }
    if (inWifiCtx && /^(?:set|add)\s+/i.test(line)) bodyLines.push(line.replace(/^(?:set|add)\s+/i, ''));
  }
  for (const line of bodyLines) {
    const ssidM = /configuration\.ssid=("([^"]*)"|\S+)/.exec(line);
    if (!ssidM) continue;
    const ssid = (ssidM[2] !== undefined ? ssidM[2] : ssidM[1]).replace(/^"|"$/g, '');
    const nameM = /default-name=([^\s\]]+)/.exec(line) || /^\[?\s*(\S+)/.exec(line);
    const name = nameM ? nameM[1].replace(/[\[\]]/g, '') : ssid;
    const authM = /security\.authentication-types=("([^"]*)"|\S+)/.exec(line);
    const authRaw = authM ? (authM[2] !== undefined ? authM[2] : authM[1]).replace(/^"|"$/g, '') : '';
    const security = /wpa3/i.test(authRaw) ? 'wpa3' : /wpa2/i.test(authRaw) ? 'wpa2-only' : authRaw ? authRaw : 'open';
    const hideM = /configuration\.hide-ssid=(\S+)/.exec(line);
    const broadcastSsid = !(hideM && /yes/i.test(hideM[1]));
    const vap = { name, ssid, security, broadcastSsid, vlanId: '-', captivePortal: false, intraVapPrivacy: false, pmf: '-' };
    const { score, grade, issues } = gradeVap(vap);
    vaps.push({ ...vap, secScore: score, secGrade: grade, secIssues: issues });
  }
  return { vaps, wtpProfiles: [], wtps: [], widsProfiles: [], summary: buildWifiSummary(vaps, [], [], [], '-') };
}

// ── OpenWrt (UCI) ────────────────────────────────────────────────────────
// 官方 UCI Wireless Configuration 文件＋社群範例查證：/etc/config/wireless 內
// config wifi-iface（option ssid／option encryption／option network／option mode），
// 與本專案既有 OpenWrtParser.parseUCI() 同一套語法家族，本函式自行輕量重掃描（避免跨
// 檔案依賴 OpenWrtParser 內部未公開的 parseUCI，該函式僅回傳 network/firewall/dhcp 三個
// package，未涵蓋 wireless）
function parseOpenWrtWifi(text) {
  text = text.replace(/\r\n/g, '\n');
  const vaps = [];
  const blocks = text.split(/^config\s+wifi-iface\b/im).slice(1);
  for (const blk of blocks) {
    const body = blk.split(/^config\s+\S/im)[0];
    const ssidM = /^\s*option\s+ssid\s+'?([^'\n]*)'?\s*$/im.exec(body);
    if (!ssidM) continue;
    const ssid = ssidM[1].trim();
    const encM = /^\s*option\s+encryption\s+'?([^'\n]*)'?\s*$/im.exec(body);
    const encRaw = encM ? encM[1].trim() : '';
    const security = /sae|wpa3/i.test(encRaw) ? 'wpa3' : /psk2|wpa2/i.test(encRaw) ? 'wpa2-only' : (!encRaw || /none/i.test(encRaw)) ? 'open' : encRaw;
    const netM = /^\s*option\s+network\s+'?([^'\n]*)'?\s*$/im.exec(body);
    const name = netM ? netM[1].trim() : ssid;
    const hideM = /^\s*option\s+hidden\s+'?1'?\s*$/im.test(body);
    const vap = { name, ssid, security, broadcastSsid: !hideM, vlanId: '-', captivePortal: false, intraVapPrivacy: false, pmf: '-' };
    const { score, grade, issues } = gradeVap(vap);
    vaps.push({ ...vap, secScore: score, secGrade: grade, secIssues: issues });
  }
  return { vaps, wtpProfiles: [], wtps: [], widsProfiles: [], summary: buildWifiSummary(vaps, [], [], [], '-') };
}

// ── pfSense ──────────────────────────────────────────────────────────────
// 官方 pfSense GitHub 原始碼（pfsense/pfsense repo interfaces.php）查證確認欄位路徑：
// 逐 <interfaces> 子節點（介面代稱如 opt1）檢查是否含 <wireless> 子區塊，取
// <wireless><mode>／<wireless><ssid>／<wireless><wpa><mode>；沿用既有 xv() 風格但本檔案
// 獨立輕量實作（不跨檔依賴 PfsenseParser 內部未公開的 xv，避免耦合）
function parsePfsenseWifi(text) {
  text = text.replace(/\r\n/g, '\n');
  const vaps = [];
  function xv1(xml, tag) {
    const m = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i').exec(xml);
    return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim() : '';
  }
  const ifacesBlock = xv1(text, 'interfaces');
  if (ifacesBlock) {
    const ifRe = /<(\w+)>([\s\S]*?)<\/\1>/g;
    let m;
    while ((m = ifRe.exec(ifacesBlock)) !== null) {
      const ifName = m[1], ifBody = m[2];
      const wlBlock = xv1(ifBody, 'wireless');
      if (!wlBlock) continue;
      const ssid = xv1(wlBlock, 'ssid');
      if (!ssid) continue;
      const wpaBlock = xv1(wlBlock, 'wpa');
      const wpaMode = wpaBlock ? xv1(wpaBlock, 'mode') : '';
      const security = !wpaBlock ? 'open' : /wpa3|sae/i.test(wpaMode) ? 'wpa3' : 'wpa2-only';
      const vap = { name: ifName, ssid, security, broadcastSsid: true, vlanId: '-', captivePortal: false, intraVapPrivacy: false, pmf: '-' };
      const { score, grade, issues } = gradeVap(vap);
      vaps.push({ ...vap, secScore: score, secGrade: grade, secIssues: issues });
    }
  }
  return { vaps, wtpProfiles: [], wtps: [], widsProfiles: [], summary: buildWifiSummary(vaps, [], [], [], '-') };
}



// ══════════════════════════════════════════════════════════════════
// 2026-10-05 新增（第十一輪 KD／KH／KI）：無線控制器設定檔 → WiFi 分析
// 與上方「自身即為 AP」的三家不同，這些是控制器（或虛擬控制器）集中管理 SSID 的設定檔，
// 由防火牆分析器的「無線控制器」上傳欄位（slot l）讀入，只產生 WiFi 資料。
//   Cisco Catalyst 9800（IOS-XE）：wlan PROFILE ID SSID 區塊；語法依 Oxidized 真實錄製
//     （C9800-L 17.06.05）與 CiscoDevNet/iPSK-Manager 的官方設定片段，其餘關鍵字依 Cisco 官方
//     文件搜尋摘要（官網被網路政策擋下）
//   Cisco AireOS：show run-config commands 的扁平 config wlan … <id> 指令（WLAN ID 為最後一欄）
//   Aruba Mobility Controller（ArubaOS 8）／Aruba Instant：wlan ssid-profile；控制器子指令不縮排、
//     以 ! 分段，Instant 縮排、以空行分段（皆依 Oxidized 真實錄製 Aruba7210 8.10／IAP-515 8.10）
//   H3C WX（Comware V7）：wlan service-template 與 wlan ap 區塊，依 H3C 官方命令參考的搜尋摘要
//     （h3c.com 被網路政策擋下，信心度中等）
// 安全性字串沿用 FortiGate 風格（wpa2-personal／wpa3-enterprise／open／owe／wep），供 gradeVap() 判斷。
// ══════════════════════════════════════════════════════════════════

function _wlcVap(fields) {
  const vap = Object.assign({ name: '-', ssid: '-', security: 'open', captivePortal: false, intraVapPrivacy: false,
    broadcastSsid: true, pmf: '-', vlanId: '-', passphrase: '-', authMode: '-', radius: '-', status: 'enable',
    usedInProfiles: [], deployedOnAps: 0 }, fields);
  const { score, grade, issues } = gradeVap(vap);
  return { ...vap, secScore: score, secGrade: grade, secIssues: issues };
}

// 由 WPA 版本與 AKM 組出安全性字串
function _wlcSecurity(wpa, ver, akm) {
  if (!wpa) return 'open';
  if (akm.owe && !akm.psk && !akm.sae && !akm.dot1x) return 'owe';
  const v = [ver.wpa1 ? 'wpa-tkip' : '', ver.wpa2 ? 'wpa2' : '', ver.wpa3 ? 'wpa3' : ''].filter(Boolean).join('-') || 'wpa2';
  const kind = (akm.dot1x && (akm.psk || akm.sae)) ? 'mixed' : akm.dot1x ? 'enterprise' : (akm.psk || akm.sae) ? 'personal' : 'enterprise';
  return v + '-' + kind;
}

function detectWlcKind(text) {
  if (/^(?:config\s+)?wlan\s+create\s+\d+\s+\S+/m.test(text)) return 'aireos';
  if (/^\s*wlan\s+service-template\s+\S+/m.test(text)) return 'h3cwx';
  if (/^\s*wlan\s+ssid-profile\s+\S+/m.test(text)) return 'aruba';
  if (/^wlan\s+\S+\s+\d{1,4}\s+\S+/m.test(text)) return 'cisco9800';
  return '';
}

// ── Cisco Catalyst 9800 ──────────────────────────────────────────────────
// 新建 WLAN 預設為 WPA2＋802.1X、SSID 廣播、PMF 停用；running-config 只列出與預設不同的指令。
// VLAN 不在 WLAN 內：wireless tag policy 把 WLAN 對到 policy profile，policy profile 的 vlan 才是 VLAN；
// AP 以 ap MAC 區塊的 policy-tag 取得要廣播的 WLAN。
function parseCisco9800Wifi(text) {
  text = text.replace(/\r\n/g, '\n');
  const lines = text.split('\n');
  const blocks = [];
  let cur = null;
  for (const line of lines) {
    if (/^\S/.test(line)) { cur = { head: line.trim(), body: [] }; blocks.push(cur); }
    else if (cur && line.trim()) cur.body.push(line.trim());
  }
  const policyVlan = {}, tagMap = {}, apTags = [];
  blocks.forEach(b => {
    let m;
    if ((m = /^wireless profile policy\s+(\S+)/.exec(b.head))) {
      const v = b.body.map(l => /^vlan\s+(\S+)/.exec(l)).find(Boolean);
      policyVlan[m[1]] = v ? v[1] : '1';
    } else if ((m = /^wireless tag policy\s+(\S+)/.exec(b.head))) {
      tagMap[m[1]] = b.body.map(l => /^wlan\s+(\S+)\s+policy\s+(\S+)/.exec(l)).filter(Boolean).map(x => ({ wlan: x[1], policy: x[2] }));
    } else if ((m = /^ap\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f:]{17})\s*$/i.exec(b.head))) {
      const t = b.body.map(l => /^policy-tag\s+(\S+)/.exec(l)).find(Boolean);
      apTags.push({ mac: m[1], tag: t ? t[1] : 'default-policy-tag', location: (b.body.map(l => /^location\s+(.+)/.exec(l)).find(Boolean) || [])[1] || '-' });
    }
  });
  const vaps = [];
  blocks.forEach(b => {
    const m = /^wlan\s+(\S+)\s+(\d{1,4})\s+(.+)$/.exec(b.head);
    if (!m) return;
    const name = m[1], ssid = m[3].trim().replace(/^"|"$/g, '');
    const has = re => b.body.some(l => re.test(l));
    const wpa = !has(/^no security wpa\s*$/);
    const ver = { wpa1: has(/^security wpa wpa1\s*$/), wpa2: !has(/^no security wpa wpa2\s*$/), wpa3: has(/^security wpa wpa3\s*$/) };
    const akm = { dot1x: !has(/^no security wpa akm dot1x\s*$/), psk: has(/^security wpa akm (?:ft )?psk\s*$/), sae: has(/^security wpa akm (?:ft )?sae\s*$/), owe: has(/^security wpa akm owe\s*$/) };
    const pmfL = b.body.map(l => /^security pmf\s+(mandatory|optional)/.exec(l)).find(Boolean);
    const keyL = b.body.map(l => /^security wpa psk set-key\s+(?:ascii|hex)\s+(\d+)\s+/.exec(l)).find(Boolean);
    const authL = b.body.map(l => /^security dot1x authentication-list\s+(\S+)/.exec(l)).find(Boolean);
    const peer = b.body.map(l => /^peer-blocking\s+(\S+)/.exec(l)).find(Boolean);
    const policies = Object.entries(tagMap).flatMap(([tag, arr]) => arr.filter(x => x.wlan === name).map(x => ({ tag, policy: x.policy })));
    const vlans = [...new Set(policies.map(p => policyVlan[p.policy]).filter(Boolean))];
    const tags = [...new Set(policies.map(p => p.tag))];
    const security = _wlcSecurity(wpa, ver, akm);
    vaps.push(_wlcVap({
      name, ssid, security,
      captivePortal: has(/^security web-auth\s*$/),
      intraVapPrivacy: !!peer && /^(?:drop|forward-upstream)$/.test(peer[1]),
      broadcastSsid: !has(/^no broadcast-ssid\s*$/),
      pmf: pmfL ? pmfL[1] : '-',
      vlanId: vlans.join(', ') || '-',
      passphrase: keyL ? (keyL[1] === '0' ? tr('wifi.pass_plain') : tr('wifi.pass_enc')) : '-',
      authMode: security === 'open' ? '-' : [akm.dot1x && '802.1X', akm.psk && 'PSK', akm.sae && 'SAE', akm.owe && 'OWE'].filter(Boolean).join('+') || '-',
      radius: authL ? authL[1] : '-',
      status: has(/^no shutdown\s*$/) ? 'enable' : 'disable',
      usedInProfiles: tags,
      deployedOnAps: apTags.filter(a => tags.includes(a.tag)).length,
    }));
  });
  const wtps = apTags.map(a => ({ serial: a.mac, name: a.mac, location: a.location, profile: a.tag, admin: 'enable', status: 'enable' }));
  return { vaps, wtpProfiles: [], wtps, widsProfiles: [], summary: buildWifiSummary(vaps, [], wtps, [], '-') };
}

// ── Cisco AireOS ─────────────────────────────────────────────────────────
// show run-config commands 為扁平 config 指令；WLAN ID 是最後一欄。新建 WLAN 預設 WPA2＋802.1X、停用狀態。
function parseAireOSWifi(text) {
  text = text.replace(/\r\n/g, '\n');
  const wl = {}, order = [];
  const get = id => wl[id];
  text.split('\n').forEach(raw => {
    const line = raw.trim().replace(/^\([^)]*\)\s*>\s*/, '').replace(/^config\s+/, '');
    let m;
    if ((m = /^wlan\s+create\s+(\d+)\s+(\S+)(?:\s+(\S+))?/.exec(line))) {
      wl[m[1]] = { name: m[2], ssid: (m[3] || m[2]).replace(/^"|"$/g, ''), wpa: true, ver: { wpa1: false, wpa2: true, wpa3: false },
        akm: { dot1x: true, psk: false, sae: false, owe: false }, web: false, bcast: true, pmf: '-', vlan: '-', key: false, peer: false, status: 'disable' };
      order.push(m[1]);
      return;
    }
    // wlan interface 的 WLAN ID 在介面名稱前，其餘指令的 WLAN ID 在最後一欄
    if ((m = /^wlan\s+interface\s+(\d+)\s+(\S+)/.exec(line))) { if (get(m[1])) get(m[1]).vlan = m[2]; return; }
    const tail = /\s(\d+)\s*$/.exec(line);
    const w = tail && get(tail[1]);
    if (!w || !/^wlan\s/.test(line)) return;
    if ((m = /^wlan\s+(enable|disable)\s+\d+$/.exec(line))) w.status = m[1];
    else if ((m = /^wlan\s+broadcast-ssid\s+(enable|disable)\s/.exec(line))) w.bcast = m[1] === 'enable';
    else if ((m = /^wlan\s+peer-blocking\s+(\S+)\s/.exec(line))) w.peer = /^(?:drop|forward-upstream)$/.test(m[1]);
    else if ((m = /^wlan\s+security\s+web-auth\s+(enable|disable)\s/.exec(line))) w.web = m[1] === 'enable';
    else if ((m = /^wlan\s+security\s+pmf\s+(disable|optional|required)\s/.exec(line))) w.pmf = m[1] === 'disable' ? '-' : m[1] === 'required' ? 'mandatory' : 'optional';
    else if ((m = /^wlan\s+security\s+wpa\s+(enable|disable)\s/.exec(line))) w.wpa = m[1] === 'enable';
    else if ((m = /^wlan\s+security\s+wpa\s+(wpa1|wpa2|wpa3)\s+(enable|disable)\s/.exec(line))) w.ver[m[1]] = m[2] === 'enable';
    else if ((m = /^wlan\s+security\s+wpa\s+akm\s+psk\s+set-key\s/.exec(line))) w.key = true;
    else if ((m = /^wlan\s+security\s+wpa\s+akm\s+(802\.1x|psk|sae|owe)\s+(enable|disable)\s/.exec(line))) w.akm[m[1] === '802.1x' ? 'dot1x' : m[1]] = m[2] === 'enable';
  });
  const vaps = order.map(id => {
    const w = wl[id];
    const security = _wlcSecurity(w.wpa, w.ver, w.akm);
    return _wlcVap({
      name: w.name, ssid: w.ssid, security, captivePortal: w.web, intraVapPrivacy: w.peer, broadcastSsid: w.bcast,
      pmf: w.pmf, vlanId: w.vlan, passphrase: w.key ? tr('wifi.pass_enc') : '-', status: w.status,
      authMode: security === 'open' ? '-' : [w.akm.dot1x && '802.1X', w.akm.psk && 'PSK', w.akm.sae && 'SAE', w.akm.owe && 'OWE'].filter(Boolean).join('+') || '-',
    });
  });
  return { vaps, wtpProfiles: [], wtps: [], widsProfiles: [], summary: buildWifiSummary(vaps, [], [], [], '-') };
}

// ── Aruba Mobility Controller（ArubaOS 8）／Aruba Instant ─────────────────
// opmode 未設定時為 opensystem。控制器的 VLAN 與使用者隔離在 wlan virtual-ap（ssid-profile 引用），
// Instant 直接寫在 ssid-profile 內。
const ARUBA_OPMODE = {
  'opensystem': 'open', 'enhanced-open': 'owe', 'static-wep': 'wep', 'dynamic-wep': 'wep-enterprise',
  'wpa-tkip': 'wpa-tkip-enterprise', 'wpa-psk-tkip': 'wpa-tkip-personal', 'wpa2-aes': 'wpa2-enterprise', 'wpa2-psk-aes': 'wpa2-personal',
  'mpsk-aes': 'wpa2-personal', 'wpa3-sae-aes': 'wpa3-personal', 'wpa3-aes-ccm-128': 'wpa3-enterprise', 'wpa3-cnsa': 'wpa3-enterprise',
  'wpa3-aes-gcm-256': 'wpa3-enterprise',
};
function _arubaBlocks(text, re) {
  const out = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = re.exec(lines[i]);
    if (!m) continue;
    const body = [];
    for (let j = i + 1; j < lines.length; j++) {
      const t = lines[j].trim();
      if (!t || t === '!' || /^wlan\s/.test(t) || (/^\S/.test(lines[j]) && /^\s/.test(lines[i + 1] || ''))) break;
      body.push(t);
    }
    out.push({ name: m[1].replace(/^"|"$/g, ''), body });
  }
  return out;
}
function parseArubaWifi(text) {
  text = text.replace(/\r\n/g, '\n');
  const unq = v => v.trim().replace(/^"|"$/g, '');
  const vapProf = _arubaBlocks(text, /^\s*wlan\s+virtual-ap\s+("[^"]+"|\S+)\s*$/).map(b => ({
    name: b.name,
    ssidProfile: unq((b.body.map(l => /^ssid-profile\s+(.+)$/.exec(l)).find(Boolean) || [, ''])[1]),
    vlan: (b.body.map(l => /^vlan\s+(.+)$/.exec(l)).find(Boolean) || [, ''])[1].trim(),
    deny: b.body.some(l => /^deny-inter-user-traffic\s*$/.test(l)),
    aaa: unq((b.body.map(l => /^aaa-profile\s+(.+)$/.exec(l)).find(Boolean) || [, ''])[1]),
  }));
  const vaps = _arubaBlocks(text, /^\s*wlan\s+ssid-profile\s+("[^"]+"|\S+)\s*$/).map(b => {
    const val = k => { const m = b.body.map(l => new RegExp('^' + k + '\\s+(.+)$').exec(l)).find(Boolean); return m ? unq(m[1]) : ''; };
    const has = k => b.body.some(l => new RegExp('^' + k + '\\s*$').test(l));
    const opmode = val('opmode') || 'opensystem';
    const modes = opmode.split(',').map(s => s.trim());
    const secs = modes.map(o => ARUBA_OPMODE[o] || o);
    const security = secs.length > 1 ? secs.join('+') : secs[0];
    const refs = vapProf.filter(v => v.ssidProfile === b.name);
    const vlan = val('vlan') || [...new Set(refs.map(v => v.vlan).filter(Boolean))].join(', ');
    const wpa3Only = /^wpa3/.test(security) && !/wpa2|tkip/.test(security);
    return _wlcVap({
      name: b.name, ssid: val('essid') || b.name, security,
      captivePortal: !!val('captive-portal') && !/^disable/.test(val('captive-portal')),
      intraVapPrivacy: has('deny-inter-user-bridging') || refs.some(v => v.deny),
      broadcastSsid: !has('hide-ssid'),
      // ArubaOS 8 依 opmode 自動設定 MFP（WPA3 為必要），Instant 可用 mfp-required／mfp-capable 指定
      pmf: has('mfp-required') || wpa3Only ? 'mandatory' : has('mfp-capable') ? 'optional' : '-',
      vlanId: vlan || '-',
      passphrase: val('wpa-passphrase') ? tr('wifi.pass_set') : '-',
      authMode: opmode, radius: val('auth-server') || [...new Set(refs.map(v => v.aaa).filter(Boolean))].join(', ') || '-',
      status: has('disable') ? 'disable' : 'enable',
      usedInProfiles: refs.map(v => v.name),
      userType: val('type') || '-',
    });
  });
  return { vaps, wtpProfiles: [], wtps: [], widsProfiles: [], summary: buildWifiSummary(vaps, [], [], [], '-') };
}

// ── H3C WX（Comware V7 無線控制器）────────────────────────────────────────
// wlan service-template 內：ssid、vlan、akm mode、cipher-suite、security-ie、preshared-key、beacon ssid-hide、
// user-isolation enable、pmf、portal enable、service-template enable。未設 akm／cipher-suite 為開放式。
// wlan ap NAME model M 區塊的 radio N 子區塊以 service-template X [vlan N] 綁定服務模板。
function parseH3CWxWifi(text) {
  text = text.replace(/\r\n/g, '\n');
  const lines = text.split('\n');
  const tops = [];
  let cur = null;
  for (const line of lines) {
    if (/^\s*#/.test(line)) { cur = null; continue; }
    if (/^\S/.test(line)) { cur = { head: line.trim(), body: [] }; tops.push(cur); continue; }
    if (cur && line.trim()) cur.body.push(line);
  }
  const aps = [];
  tops.forEach(t => {
    const m = /^wlan\s+ap\s+(\S+)(?:\s+model\s+(\S+))?/.exec(t.head);
    if (!m) return;
    const bind = [];
    t.body.forEach(l => { const b = /^\s+service-template\s+(\S+)(?:\s+vlan\s+(\d+))?/.exec(l); if (b) bind.push({ st: b[1], vlan: b[2] || '' }); });
    const sn = t.body.map(l => /^\s*serial-id\s+(\S+)/.exec(l)).find(Boolean);
    aps.push({ name: m[1], model: m[2] || '-', serial: sn ? sn[1] : '-', bind });
  });
  const vaps = [];
  tops.forEach(t => {
    const m = /^wlan\s+service-template\s+(\S+)/.exec(t.head);
    if (!m) return;
    const body = t.body.map(l => l.trim());
    const val = k => { const x = body.map(l => new RegExp('^' + k + '\\s+(.+)$').exec(l)).find(Boolean); return x ? x[1].trim() : ''; };
    const has = re => body.some(l => re.test(l));
    const akmMode = val('akm mode');
    const ciphers = body.filter(l => /^cipher-suite\s/.test(l)).map(l => l.split(/\s+/)[1]).join(' ');
    const ies = body.filter(l => /^security-ie\s/.test(l)).map(l => l.split(/\s+/)[1]).join(' ');
    let security;
    if (!akmMode && !ciphers) security = 'open';
    else if (/wep/.test(ciphers) && !akmMode) security = 'wep';
    else {
      const ver = { wpa1: /\bwpa\b/.test(ies) && /tkip/.test(ciphers), wpa2: /\brsn\b/.test(ies) || !ies, wpa3: /sae/.test(akmMode) };
      if (/\bwpa\b/.test(ies) && !/tkip/.test(ciphers)) ver.wpa2 = true;
      const akm = { dot1x: /dot1x/.test(akmMode), psk: /psk/.test(akmMode), sae: /sae/.test(akmMode), owe: /owe/.test(akmMode) };
      security = _wlcSecurity(true, ver, akm);
      if (/tkip/.test(ciphers) && !/tkip/.test(security)) security = 'wpa-tkip-' + security;
    }
    const pre = /^preshared-key\s+(?:pass-phrase|raw-key)\s+(simple|cipher)\s/.exec(body.find(l => /^preshared-key\s/.test(l)) || '');
    const bound = aps.filter(a => a.bind.some(b => b.st === m[1]));
    const vlans = [...new Set([val('vlan'), ...bound.flatMap(a => a.bind.filter(b => b.st === m[1]).map(b => b.vlan))].filter(Boolean))];
    vaps.push(_wlcVap({
      name: m[1], ssid: val('ssid').replace(/^"|"$/g, '') || m[1], security,
      captivePortal: has(/^portal\s+enable\b/),
      intraVapPrivacy: has(/^user-isolation\s+enable\s*$/),
      broadcastSsid: !has(/^beacon\s+ssid-hide\s*$/),
      pmf: val('pmf') || '-',
      vlanId: vlans.join(', ') || '-',
      passphrase: pre ? (pre[1] === 'simple' ? tr('wifi.pass_plain') : tr('wifi.pass_enc')) : '-',
      authMode: akmMode || '-',
      status: has(/^service-template\s+enable\s*$/) ? 'enable' : 'disable',
      usedInProfiles: bound.map(a => a.name),
      deployedOnAps: bound.length,
    }));
  });
  const wtps = aps.map(a => ({ serial: a.serial, name: a.name, location: '-', profile: a.model, admin: 'enable', status: 'enable' }));
  return { vaps, wtpProfiles: [], wtps, widsProfiles: [], summary: buildWifiSummary(vaps, [], wtps, [], '-') };
}

function parseWlcWifi(text) {
  const kind = detectWlcKind(text);
  const fn = { cisco9800: parseCisco9800Wifi, aireos: parseAireOSWifi, aruba: parseArubaWifi, h3cwx: parseH3CWxWifi }[kind];
  return fn ? fn(text) : { vaps: [], wtpProfiles: [], wtps: [], widsProfiles: [], summary: buildWifiSummary([], [], [], [], '-') };
}
