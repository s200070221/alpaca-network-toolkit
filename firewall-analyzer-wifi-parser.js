// ═══ wifi-parser.js ═══
/**
 * FortiGate WiFi Configuration Parser
 * Parses: wireless-controller vap, wtp-profile, wtp, wids-profile, settings
 * Returns structured WiFi analysis data
 */

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
  function hasKey(body, key) {
    return new RegExp(`^\\s*set ${key}\\s`, 'im').test(body);
  }

  // ── Security grading ──────────────────────────────────────────────────────
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

    if (vap.security.includes('wpa2') && !vap.security.includes('wpa3')) {
      issues.push({ level: 'info', msg: 'wifi.msg_wpa2_only' });
      score_deductions.push(5);
    }

    if (vap.pmf === '-' || vap.pmf === 'disable') {
      issues.push({ level: 'info', msg: 'wifi.msg_no_pmf' });
      score_deductions.push(5);
    }

    if (!vap.broadcastSsid) {
      // Hidden SSID is not actually a security feature but adds management overhead
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
      const radioRe = /config radio-(\d+)([\s\S]*?)(?=config radio-\d+|^    end)/gm;
      let rm;
      while ((rm = radioRe.exec(b)) !== null) {
        const rBody = rm[2];
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
        radios.push({ id: parseInt(rm[1]), band, mode, channel, txPower, dtim, beacon, vaps: vapRefs });
      }
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
  const summary = {
    country,
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


