// ═══ parser-fortigate.js ═══
/**
 * FortiGate 7.x Full Configuration Parser — Multi-VDOM Edition
 *
 * Handles two formats:
 *  [A] Single-VDOM  — plain top-level config sections
 *  [B] Multi-VDOM   — config global…end  +  config vdom / edit <X> / … / end / end
 *
 * Returns:
 *   result.vdoms          — array of parsed-per-vdom objects
 *   result.interfaces     — all interfaces (global, tagged with .vdom)
 *   result.policies       — merged across all vdoms, each tagged with ._vdom
 *   result.routes / vpn / addresses / services / nat / schedules / users — same
 *   result.deviceInfo.vdomNames — list of vdom names found
 */
const FortigateParser = (() => {

  // ── Low-level value helpers ───────────────────────────────────────────────
  function gv(text, key) {
    // Returns the full value string (may contain spaces, e.g. "10.0.0.1 255.255.255.0")
    const keyPat = 'set ' + key + ' ';
    const lines = text.split(/\r?\n/).map(l => l.replace(/\r$/, ''));  // Fix: \r 清除  // Fix: 支援 Windows \r\n
    for (const line of lines) {
      const t = line.trim();
      if (t.toLowerCase().startsWith(keyPat.toLowerCase())) {
        const rest = t.slice(keyPat.length).trim();
        // Quoted: return content inside first pair of quotes only
        if (rest.startsWith('"')) {
          const end = rest.indexOf('"', 1);
          return end > 0 ? rest.slice(1, end) : rest.slice(1);
        }
        // Unquoted: return full rest (handles "ip mask" two-part values)
        return rest.replace(/\r$/, '');  // Fix: Windows \r 清除
      }
    }
    return '';
  }
  function gvs(text, key) {
    // Multi-value: set srcaddr "A" "B" "C" OR unquoted: set srcaddr A B C
    const keyPat = 'set ' + key + ' ';
    const lines = text.split(/\r?\n/).map(l => l.replace(/\r$/, ''));  // Fix: \r 清除  // Fix: 支援 Windows \r\n
    for (const line of lines) {
      const t = line.trim();
      if (t.toLowerCase().startsWith(keyPat.toLowerCase())) {
        const rest = t.slice(keyPat.length).trim();
        // Handle escaped quotes \": replace \" temporarily
        const safe = rest.replace(/\\"/g, '\u0000');
        const vals = [];
        let i = 0;
        if (safe.includes('"')) {
          // Quoted values: "A" "B" "C"  (handles escaped quotes inside)
          while (i < safe.length) {
            if (safe[i] === '"') {
              const end = safe.indexOf('"', i + 1);
              if (end > i) {
                vals.push(safe.slice(i + 1, end).replace(/\u0000/g, '"'));
                i = end + 1;
              } else break;
            } else i++;
          }
        }
        if (vals.length) return vals.join(', ');
        // Unquoted multi-value: "objectA objectB" → split by whitespace
        const parts = rest.replace(/\r$/,'').trim().split(/\s+/).filter(Boolean);
        return parts.join(', ');
      }
    }
    return '';
  }
  function guessRole(name, explicit) {
    if (explicit) {
      const e = explicit.toLowerCase();
      if (e === 'wan')  return 'WAN';
      if (e === 'lan')  return 'LAN';
      if (e === 'dmz')  return 'DMZ';
      if (e === 'undefined') { /* ignore */ }
    }
    const n = (name || '').toLowerCase();
    if (/wan|internet|ext|outside|uplink/.test(n)) return 'WAN';
    if (/lan|inside|internal|trust|intra/.test(n))  return 'LAN';
    if (/dmz|server|srv/.test(n))                   return 'DMZ';
    if (/mgmt|manage|oob|admin/.test(n))             return 'MGMT';
    if (/ha|heartbeat|sync|cluster/.test(n))         return 'HA';
    if (/vpn|ipsec|ssl|tun/.test(n))                 return 'VPN';
    if (/vlan|vl\d/.test(n))                         return 'VLAN';
    return 'Unknown';
  }

  // ── Block-level text slicer ───────────────────────────────────────────────
  // Given an array of lines and a start index pointing at the line AFTER
  // "config <key>", read until matching "end" and return { sectionLines, i }.
  // Respects nesting of config/end pairs.
  function readUntilEnd(lines, start) {
    let depth = 1, i = start;
    const sectionLines = [];
    while (i < lines.length) {
      const raw = lines[i++];
      const l = raw.trim();
      if (l.startsWith('config ')) depth++;
      if (l === 'end') { depth--; if (depth === 0) break; }
      sectionLines.push(raw);
    }
    return { sectionLines, i };
  }

  // Read one "edit" block (until next/end at depth 0, respecting nesting)
  function readEditBlock(lines, start) {
    let depth = 0, i = start;
    const editLines = [];
    while (i < lines.length) {
      const raw = lines[i++];
      const l = raw.trim();
      if (l.startsWith('config ')) depth++;
      if (l === 'end') { if (depth > 0) depth--; else break; }
      if (l === 'next' && depth === 0) break;
      editLines.push(raw);
    }
    return { editLines, i };
  }

  // Parse a section's edit blocks into [{name, text}]
  function parseEdits(sectionLines) {
    const edits = [];
    let i = 0;
    while (i < sectionLines.length) {
      const l = sectionLines[i].trim();
      i++;
      if (l.startsWith('edit ')) {
        const name = l.slice(5).replace(/^"|"$/g, '').trim();
        const { editLines, i: ni } = readEditBlock(sectionLines, i);
        i = ni;
        edits.push({ name, text: editLines.join('\n') });
      }
    }
    return edits;
  }

  // Extract a named config section's lines from a block of text
  // Fix: 合併所有同名區塊（FortiGate multi-VDOM 中同名區段可能出現多次）
  function extractSection(lines, sectionKey) {
    const re = new RegExp(`^\\s*config\\s+${sectionKey.replace(/[-]/g, '\\-')}\\s*$`, 'i');
    let i = 0;
    const allLines = [];  // 收集所有同名區塊的內容
    let found = false;
    while (i < lines.length) {
      if (re.test(lines[i].trim())) {
        found = true;
        i++;  // skip the "config xxx" line
        const { sectionLines, i: ni } = readUntilEnd(lines, i);
        allLines.push(...sectionLines);  // 合併，不 return
        i = ni;
      } else {
        i++;
      }
    }
    return { sectionLines: allLines, found };
  }

  // ── Top-level split: global vs per-vdom ──────────────────────────────────
  /**
   * Returns:
   *   globalLines   — lines inside "config global…end"
   *   vdomBlocks    — [{name, lines}]  one per "edit <vdom>" inside "config vdom"
   *   isMultiVdom   — boolean
   */
  function splitTopLevel(text) {
    const lines = text.split(/\r?\n/).map(l => l.replace(/\r$/, ''));  // Fix: \r 清除
    const N = lines.length;
    let i = 0;
    let globalLines = null;
    const vdomBlocks = [];   // [{name, lines:[]}]
    let isMultiVdom = false;
    // FortiGate 7.x context-switch format: "config vdom / edit <name> / end" 切換 VDOM 後
    // 實際 config 段落出現在 config vdom 區塊外部（頂層）
    let currentVdomCtx = null;

    while (i < N) {
      const raw = lines[i]; const l = raw.trim(); i++;

      // ── config global ─────────────────────────────────────────────────
      if (l === 'config global') {
        isMultiVdom = true;
        currentVdomCtx = null;
        const { sectionLines, i: ni } = readUntilEnd(lines, i);
        globalLines = sectionLines;
        i = ni;
        continue;
      }

      // ── config vdom ───────────────────────────────────────────────────
      if (l === 'config vdom') {
        isMultiVdom = true;
        let depth = 1;
        const vdomNamesInBlock = [];
        let lastEmpty = false;

        while (i < N && depth > 0) {
          const vl = lines[i].trim(); i++;
          if (vl === 'end') { depth--; if (depth === 0) break; }
          if (vl === 'config vdom') { depth++; continue; }

          if (vl.startsWith('edit ') && depth === 1) {
            const vname = vl.slice(5).replace(/^"|"$/g, '').trim();
            const vdLines = [];
            let vd = 0;
            let terminatedByEnd = false;
            while (i < N) {
              const rawLine = lines[i]; const bdl = rawLine.trim(); i++;
              if (bdl.startsWith('config ')) vd++;
              if (bdl === 'end') {
                if (vd > 0) { vd--; vdLines.push(rawLine); }
                else { terminatedByEnd = true; break; }
              } else if (bdl === 'next' && vd === 0) {
                break;
              } else {
                vdLines.push(rawLine);
              }
            }
            vdomBlocks.push({ name: vname, lines: vdLines });
            vdomNamesInBlock.push(vname);
            lastEmpty = vdLines.length === 0;
            // 3-line context-switch ("config vdom / edit X / end")：
            // 該 end 同時關閉了外層 config vdom，補正 depth
            if (terminatedByEnd) { depth--; if (depth === 0) break; }
          }
        }

        // 判斷是否為 context-switch 格式：單一 VDOM 且空白區塊
        // 多 VDOM 宣告區塊（declaration block）或非空白內容區塊不設 context
        if (vdomNamesInBlock.length === 1 && lastEmpty) {
          currentVdomCtx = vdomNamesInBlock[0];
        } else {
          currentVdomCtx = null;
        }
        continue;
      }

      // ── Context-switch 模式：頂層 config 段落歸屬當前 VDOM ────────────
      // FortiGate 7.x 中，"config vdom / edit WIFI / end" 切換後，
      // 隨後的頂層 config 段落屬於該 VDOM
      if (isMultiVdom && currentVdomCtx && l.startsWith('config ')) {
        const { sectionLines, i: ni } = readUntilEnd(lines, i);
        i = ni;
        const targetBlock = vdomBlocks.slice().reverse().find(vb => vb.name === currentVdomCtx);
        if (targetBlock) {
          // 推入 config 標頭、內容，以及還原用的 end（供 extractSection 正確終止）
          targetBlock.lines.push(raw, ...sectionLines, 'end');
        }
        continue;
      }
    }

    // Single-VDOM: put everything into one block named "root"
    if (!isMultiVdom || (!globalLines && vdomBlocks.length === 0)) {
      return { globalLines: null, vdomBlocks: [{ name: 'root', lines }], isMultiVdom: false };
    }

    // Merge duplicate vdom blocks (first config vdom = declarations, second = actual content)
    const mergedBlocks = [];
    const seenVdoms = {};
    for (const vb of vdomBlocks) {
      if (seenVdoms[vb.name] !== undefined) {
        mergedBlocks[seenVdoms[vb.name]].lines.push(...vb.lines);
      } else {
        seenVdoms[vb.name] = mergedBlocks.length;
        mergedBlocks.push({ name: vb.name, lines: [...vb.lines] });
      }
    }
    return { globalLines, vdomBlocks: mergedBlocks, isMultiVdom };
  }

  // ── Section parsers ───────────────────────────────────────────────────────

  function parseDeviceInfo(text, isMultiVdom, vdomNames) {
    const info = { vendor: 'FortiGate', hostname: '-', firmware: '-', model: '-', serial: '-', vdom: [], vdomNames: [], isMultiVdom };

    const hm = text.match(/#config-version=([^:]+)/);
    if (hm) {
      const raw = hm[1];
      const mm = raw.match(/^([A-Za-z][A-Za-z0-9_]+?)[-_](\d+\.\d+[\d.]*)/);
      if (mm) {
        info.model = mm[1];
        info.firmware = (raw.match(/(\d+\.\d+[\d.]*)/) || [])[1] || raw;
        const build = raw.match(/build(\d+)/i);
        if (build) info.firmware += ` (build ${build[1]})`;
      } else { info.model = raw; }
    }
    const vc = text.match(/#\s*Version:\s*\S+\s+v([\d.]+)\s+build(\d+)/i);
    if (vc) info.firmware = `${vc[1]} (build ${vc[2]})`;

    const snLine = text.match(/S\/N:\s*(\S+)/i) || text.match(/#SN=(\S+)/);
    if (snLine) info.serial = snLine[1];

    // hostname from text
    const hname = text.match(/^\s*set\s+hostname\s+"?([^"\r\n]+)"?/im);
    if (hname) info.hostname = hname[1].trim();

    info.vdomNames = vdomNames || [];
    info.vdom = vdomNames || [];
    return info;
  }

  function parseInterfaces(lines, vdomName) {
    const { sectionLines } = extractSection(lines, 'system interface');
    return parseEdits(sectionLines).map(e => {
      const t = e.text;
      const ipraw = gv(t, 'ip'); const iparts = ipraw ? ipraw.split(/\s+/) : [];
      // 次要IP（Secondary IP，官方 FortiOS CLI Reference：`config secondaryip`／`edit N`／
      // `set ip A B` 巢狀區塊，每個 `edit N` 為一筆次要IP；2026-08-17 從「僅取第一筆」擴大
      // 為完整收集全部 edit 的 `set ip`）
      const secBlockM = t.match(/config secondaryip\n([\s\S]*?)^\s*end\b/m);
      const secondaryIps = secBlockM
        ? [...secBlockM[1].matchAll(/^\s*set ip\s+(\S+)\s+(\S+)/gm)].map(m => ({ ip: m[1], mask: m[2] }))
        : [];
      const explicitVdom = gv(t, 'vdom') || vdomName;
      return {
        name: e.name, alias: gv(t, 'alias') || '-',
        ip: iparts[0] || '-', mask: iparts[1] || '-',
        secondaryIps,
        type: gv(t, 'type') || 'physical',
        vlanId: gv(t, 'vlanid') || '-',
        vdom: explicitVdom,
        role: guessRole(e.name, gv(t, 'role')),
        status: gv(t, 'status') || 'up',
        speed: gv(t, 'speed') || '-',
        mtu: gv(t, 'mtu') || '1500',
        macaddr: gv(t, 'macaddr') || '-',
        mode: gv(t, 'mode') || 'static',
        gwdetect: gv(t, 'gwdetect') || 'disable',
        desc: gv(t, 'description') || gv(t, 'alias') || '-',
        allowaccess: gv(t, 'allowaccess') || '-',
        interface: gv(t, 'interface') || '-',
        gateway: '-',
        _vdom: explicitVdom,
      };
    });
  }

  function parsePolicies(lines, vdomName, addrTypeMap) {
    const { sectionLines } = extractSection(lines, 'firewall policy');
    return parseEdits(sectionLines).map(e => {
      const t = e.text;
      const srcAddrStr = gvs(t, 'srcaddr') || 'all';
      const dstAddrStr = gvs(t, 'dstaddr') || 'all';
      const srcAddrSplit = _splitAddr(srcAddrStr, addrTypeMap);
      const dstAddrSplit = _splitAddr(dstAddrStr, addrTypeMap);
      return {
        id: e.name, name: gv(t, 'name') || `Policy-${e.name}`,
        srcIntf: gvs(t, 'srcintf') || '-', dstIntf: gvs(t, 'dstintf') || '-',
        srcAddr: srcAddrStr, dstAddr: dstAddrStr,
        srcAddr4: srcAddrSplit.v4, srcAddr6: srcAddrSplit.v6,
        dstAddr4: dstAddrSplit.v4, dstAddr6: dstAddrSplit.v6,
        service: gvs(t, 'service') || 'ALL', schedule: gv(t, 'schedule') || 'always',
        action: gv(t, 'action') || 'deny',
        nat: gv(t, 'nat') || 'disable', ippool: gv(t, 'ippool') || 'disable',
        poolname: gvs(t, 'poolname') || '-',
        logtraffic: gv(t, 'logtraffic') || 'disable',
        logstart: gv(t, 'logtraffic-start') || 'disable',
        utm: {
          av: gv(t, 'av-profile') || '-', webfilter: gv(t, 'webfilter-profile') || '-',
          ips: gv(t, 'ips-sensor') || '-', ssl: gv(t, 'ssl-ssh-profile') || '-',
          appctrl: gv(t, 'application-list') || '-',
        },
        status: gv(t, 'status') === 'disable' ? 'disable' : 'enable',
        comments: gv(t, 'comments') || '-',
        users: gvs(t, 'users') || '-', groups: gvs(t, 'groups') || '-',
        _vdom: vdomName,
      };
    });
  }

  // 官方 CLI Reference 確認 firewall policy6 欄位名稱與 IPv4 firewall policy 完全相同（無 6
  // 後綴），故直接沿用同一套欄位擷取邏輯；因整張表天生只會引用 IPv6 位址物件，不透過
  // _splitAddr() 反查（該函式是為了「同一份 srcaddr 可能混合引用 v4/v6 物件」的情境設計，
  // policy6 沒有這個問題），固定 srcAddr4/dstAddr4 為 '-'。id 加 'v6/' 前綴避免與 IPv4
  // policy 的編號 id 在合併後的同一份陣列中混淆
  function parsePolicies6(lines, vdomName) {
    const { sectionLines } = extractSection(lines, 'firewall policy6');
    return parseEdits(sectionLines).map(e => {
      const t = e.text;
      const srcAddrStr = gvs(t, 'srcaddr') || 'all';
      const dstAddrStr = gvs(t, 'dstaddr') || 'all';
      return {
        id: `v6/${e.name}`, name: gv(t, 'name') || `Policy6-${e.name}`,
        srcIntf: gvs(t, 'srcintf') || '-', dstIntf: gvs(t, 'dstintf') || '-',
        srcAddr: srcAddrStr, dstAddr: dstAddrStr,
        srcAddr4: '-', srcAddr6: srcAddrStr,
        dstAddr4: '-', dstAddr6: dstAddrStr,
        service: gvs(t, 'service') || 'ALL', schedule: gv(t, 'schedule') || 'always',
        action: gv(t, 'action') || 'deny',
        nat: gv(t, 'nat') || 'disable', ippool: gv(t, 'ippool') || 'disable',
        poolname: gvs(t, 'poolname') || '-',
        logtraffic: gv(t, 'logtraffic') || 'disable',
        logstart: gv(t, 'logtraffic-start') || 'disable',
        utm: {
          av: gv(t, 'av-profile') || '-', webfilter: gv(t, 'webfilter-profile') || '-',
          ips: gv(t, 'ips-sensor') || '-', ssl: gv(t, 'ssl-ssh-profile') || '-',
          appctrl: gv(t, 'application-list') || '-',
        },
        status: gv(t, 'status') === 'disable' ? 'disable' : 'enable',
        comments: gv(t, 'comments') || '-',
        users: gvs(t, 'users') || '-', groups: gvs(t, 'groups') || '-',
        _vdom: vdomName,
      };
    });
  }

  function parseAddressObjects(lines, vdomName) {
    const objs = [];
    // subnetKey 可覆寫：FortiOS 官方 CLI Reference 確認 config firewall address6 的網段欄位是
    // `ip6`（不是 IPv4 版沿用的 `subnet`），start-ip/end-ip 則兩版共用同一欄位名（無 6 後綴）
    const add = (key, cat, subnetKey) => {
      const { sectionLines } = extractSection(lines, key);
      parseEdits(sectionLines).forEach(e => {
        const t = e.text;
        objs.push({
          category: cat, name: e.name,
          type: gv(t, 'type') || (cat.startsWith('address-group') ? 'group' : (cat === 'address6' ? 'ipprefix' : 'ipmask')),
          subnet: gv(t, subnetKey || 'subnet') || '-', fqdn: gv(t, 'fqdn') || '-',
          startIp: gv(t, 'start-ip') || '-', endIp: gv(t, 'end-ip') || '-',
          wildcard: gv(t, 'wildcard') || '-', iface: gv(t, 'associated-interface') || '-',
          color: gv(t, 'color') || '0', comment: gv(t, 'comment') || '-',
          members: gvs(t, 'member') || '-', _vdom: vdomName,
        });
      });
    };
    add('firewall address', 'address');
    add('firewall addrgrp', 'address-group');
    add('firewall address6', 'address6', 'ip6');
    add('firewall addrgrp6', 'address-group6');
    return objs;
  }

  function parseServiceObjects(lines, vdomName) {
    const svcs = [];
    const { sectionLines: cs } = extractSection(lines, 'firewall service custom');
    parseEdits(cs).forEach(e => {
      const t = e.text;
      svcs.push({ category: 'custom', name: e.name, proto: gv(t, 'protocol') || 'TCP/UDP',
        tcpPorts: gv(t, 'tcp-portrange') || '-', udpPorts: gv(t, 'udp-portrange') || '-',
        icmpType: gv(t, 'icmptype') || '-', icmpCode: gv(t, 'icmpcode') || '-',
        comment: gv(t, 'comment') || '-', color: gv(t, 'color') || '0',
        category_name: gv(t, 'category') || '-', members: '-', _vdom: vdomName });
    });
    const { sectionLines: gs } = extractSection(lines, 'firewall service group');
    parseEdits(gs).forEach(e => {
      const t = e.text;
      svcs.push({ category: 'group', name: e.name, proto: 'GROUP',
        members: gvs(t, 'member') || '-', tcpPorts: '-', udpPorts: '-',
        icmpType: '-', icmpCode: '-', comment: gv(t, 'comment') || '-', _vdom: vdomName });
    });
    return svcs;
  }

  function parseRoutes(lines, vdomName) {
    const routes = [];
    const { sectionLines: sr } = extractSection(lines, 'router static');
    parseEdits(sr).forEach(e => {
      const t = e.text;
      routes.push({ type: 'static', id: e.name,
        dst: gv(t, 'dst') || '0.0.0.0 0.0.0.0', gateway: gv(t, 'gateway') || '-',
        device: gv(t, 'device') || '-', distance: gv(t, 'distance') || '10',
        priority: gv(t, 'priority') || '0', weight: gv(t, 'weight') || '0',
        comment: gv(t, 'comment') || '-', status: gv(t, 'status') === 'disable' ? 'disable' : 'enable',
        blackhole: gv(t, 'blackhole') || 'disable', vrf: gv(t, 'vrf') || '0', _vdom: vdomName });
    });
    // 官方 CLI Reference 確認 router static6 欄位名稱與 IPv4 router static 完全相同（無 6 後綴）
    const { sectionLines: sr6 } = extractSection(lines, 'router static6');
    parseEdits(sr6).forEach(e => {
      const t = e.text;
      routes.push({ type: 'static6', id: e.name,
        dst: gv(t, 'dst') || '::/0', gateway: gv(t, 'gateway') || '-',
        device: gv(t, 'device') || '-', distance: gv(t, 'distance') || '10',
        priority: gv(t, 'priority') || '0', weight: '0',
        comment: gv(t, 'comment') || '-', status: gv(t, 'status') === 'disable' ? 'disable' : 'enable',
        blackhole: gv(t, 'blackhole') || 'disable', vrf: gv(t, 'vrf') || '0', _vdom: vdomName });
    });
    const { sectionLines: pr } = extractSection(lines, 'router policy');
    parseEdits(pr).forEach(e => {
      const t = e.text;
      routes.push({ type: 'policy', id: e.name,
        dst: gv(t, 'dst') || '-', src: gv(t, 'src') || '-',
        gateway: gv(t, 'gateway') || '-', device: gv(t, 'output-device') || '-',
        inDevice: gv(t, 'input-device') || '-', distance: '-', priority: gv(t, 'priority') || '0',
        comment: gv(t, 'comments') || '-', status: 'enable', blackhole: 'disable', vrf: '0',
        _vdom: vdomName });
    });
    const { sectionLines: ospfL, found: hasOspf } = extractSection(lines, 'router ospf');
    if (hasOspf) {
      const ospfText = ospfL.join('\n');
      routes.push({ type: 'ospf', id: 'ospf', dst: 'dynamic', gateway: '-', device: '-',
        routerId: gv(ospfText, 'router-id') || '-', distance: gv(ospfText, 'distance') || '110',
        priority: '-', weight: '-', comment: 'OSPF', status: 'enable', blackhole: 'disable', vrf: '0',
        protocol_detail: `Router-ID: ${gv(ospfText, 'router-id') || '-'}`, _vdom: vdomName });
    }
    const { sectionLines: bgpL, found: hasBgp } = extractSection(lines, 'router bgp');
    if (hasBgp) {
      const bgpText = bgpL.join('\n');
      const localAs = gv(bgpText, 'as') || '-';
      const bgpNbrs = [];
      const nbrRe = /neighbor\s+(\S+)\s+remote-as\s+(\d+)/g;
      let nm;
      while ((nm = nbrRe.exec(bgpText)) !== null) {
        const ip = nm[1], peerAs = nm[2];
        const descM = bgpText.match(new RegExp('neighbor\\s+' + ip.replace(/\./g,'\\.') + '\\s+description\\s+(.+)'));
        bgpNbrs.push({ ip, as: peerAs, desc: descM ? descM[1].trim() : '-', type: peerAs === localAs ? 'iBGP' : 'eBGP' });
      }
      routes.push({ type: 'bgp', id: 'bgp', dst: 'dynamic', gateway: '-', device: '-',
        as: localAs, routerId: gv(bgpText, 'router-id') || '-',
        distance: gv(bgpText, 'distance-ebgp') || '20', priority: '-', weight: '-',
        comment: 'BGP', status: 'enable', blackhole: 'disable', vrf: '0',
        protocol_detail: `AS: ${localAs}  Router-ID: ${gv(bgpText,'router-id')||'-'}  (${bgpNbrs.length} peers)`,
        neighbors: bgpNbrs, _vdom: vdomName });
    }
    const { found: hasRip } = extractSection(lines, 'router rip');
    if (hasRip) routes.push({ type: 'rip', id: 'rip', dst: 'dynamic', gateway: '-', device: '-',
      distance: '120', priority: '-', weight: '-', comment: 'RIP', status: 'enable',
      blackhole: 'disable', vrf: '0', protocol_detail: 'RIP v2', _vdom: vdomName });
    return routes;
  }

  function parseVPN(lines, vdomName) {
    const vpns = [];
    ['vpn ipsec phase1-interface', 'vpn ipsec phase1'].forEach(key => {
      const { sectionLines } = extractSection(lines, key);
      parseEdits(sectionLines).forEach(e => {
        const t = e.text;
        vpns.push({ type: 'ipsec-p1', name: e.name,
          mode: gv(t, 'mode') || 'main', remote: gv(t, 'remote-gw') || gv(t, 'remote-gw-ip') || '-',
          iface: gv(t, 'interface') || '-', ikeVer: gv(t, 'ike-version') || '1',
          authMethod: gv(t, 'authmethod') || 'psk', peertype: gv(t, 'peertype') || 'any',
          proposal: gv(t, 'proposal') || '-', dhgrp: gv(t, 'dhgrp') || '-',
          lifetime: gv(t, 'keylife') || '86400', natTraversal: gv(t, 'nattraversal') || 'enable',
          dpd: gv(t, 'dpd') || 'on-idle', dpdInterval: gv(t, 'dpd-retryinterval') || '20',
          localId: gv(t, 'localid') || '-', peerId: gv(t, 'peerid') || '-',
          cert: gv(t, 'certificate') || '-', status: 'enable', phase2: [], _vdom: vdomName });
      });
    });
    ['vpn ipsec phase2-interface', 'vpn ipsec phase2'].forEach(key => {
      const { sectionLines } = extractSection(lines, key);
      parseEdits(sectionLines).forEach(e => {
        const t = e.text;
        const ph1 = gv(t, 'phase1name') || '';
        const p2 = { name: e.name, phase1: ph1, proposal: gv(t, 'proposal') || '-',
          pfs: gv(t, 'pfs') || 'enable', dhgrp: gv(t, 'dhgrp') || '-',
          lifetime: gv(t, 'keylifeseconds') || '43200', replay: gv(t, 'replay') || 'enable',
          localSub: gv(t, 'src-subnet') || '-', remoteSub: gv(t, 'dst-subnet') || '-',
          autoNeg: gv(t, 'auto-negotiate') || 'disable', comment: gv(t, 'comments') || '-' };
        const found = vpns.find(v => v.name === ph1);
        if (found) found.phase2.push(p2);
        else vpns.push({ type: 'ipsec-p2-orphan', name: e.name, phase2: [p2],
          remote: '-', iface: '-', ikeVer: '-', authMethod: '-', proposal: '-', dhgrp: '-',
          status: 'enable', _vdom: vdomName });
      });
    });
    const { sectionLines: sslL, found: hasSsl } = extractSection(lines, 'vpn ssl settings');
    if (hasSsl) {
      const t = sslL.join('\n');
      vpns.push({ type: 'ssl-vpn', name: 'SSL-VPN',
        iface: gvs(t, 'source-interface') || '-', remote: '-', port: gv(t, 'port') || '443',
        tunPort: '-', addr: gvs(t, 'source-address') || '-',
        dns1: gv(t, 'dns-server1') || '-', dns2: gv(t, 'dns-server2') || '-',
        wins1: gv(t, 'wins-server1') || '-', ipPool: gvs(t, 'tunnel-ip-pools') || '-',
        algorithm: gv(t, 'algorithm') || 'high', dtls: gv(t, 'dtls-tunnel') || 'enable',
        authTimeout: gv(t, 'auth-timeout') || '28800',
        ikeVer: '-', authMethod: 'ssl', proposal: gv(t, 'algorithm') || 'high',
        dhgrp: '-', phase2: [], status: 'enable', _vdom: vdomName });
    }
    const { sectionLines: portalL } = extractSection(lines, 'vpn ssl web portal');
    parseEdits(portalL).forEach(e => {
      const t = e.text;
      vpns.push({ type: 'ssl-portal', name: `SSL-Portal: ${e.name}`,
        tunnel: gv(t, 'tunnel-mode') || 'disable', web: gv(t, 'web-mode') || 'disable',
        ipPool: gvs(t, 'ip-pools') || '-', splitTunnel: gv(t, 'split-tunneling') || 'disable',
        splitTunnelRoutingAddr: gvs(t, 'split-tunneling-routing-address') || '-',
        remote: '-', iface: '-', ikeVer: '-', authMethod: 'ssl', proposal: '-',
        dhgrp: '-', phase2: [], status: 'enable', _vdom: vdomName });
    });
    return vpns;
  }

  function parseNAT(lines, vdomName) {
    const nats = [];
    const { sectionLines: pl } = extractSection(lines, 'firewall ippool');
    parseEdits(pl).forEach(e => {
      const t = e.text;
      nats.push({ type: 'ippool', name: e.name, poolType: gv(t, 'type') || 'overload',
        startIp: gv(t, 'startip') || '-', endIp: gv(t, 'endip') || '-',
        srcIntf: gv(t, 'source-startip') || '-', arpReply: gv(t, 'arp-reply') || 'enable',
        comment: gv(t, 'comments') || '-', _vdom: vdomName });
    });
    const { sectionLines: vl } = extractSection(lines, 'firewall vip');
    parseEdits(vl).forEach(e => {
      const t = e.text;
      nats.push({ type: 'vip', name: e.name, vipType: gv(t, 'type') || 'static-nat',
        extIp: gv(t, 'extip') || '-', extIntf: gv(t, 'extintf') || '-', mapIp: gv(t, 'mappedip') || '-',
        portFwd: gv(t, 'portforward') || 'disable', extPort: gv(t, 'extport') || '-',
        mapPort: gv(t, 'mappedport') || '-', proto: gv(t, 'protocol') || '-',
        comment: gv(t, 'comment') || '-', status: gv(t, 'status') || 'enable', _vdom: vdomName });
    });
    const { sectionLines: vgl } = extractSection(lines, 'firewall vipgrp');
    parseEdits(vgl).forEach(e => {
      const t = e.text;
      nats.push({ type: 'vipgrp', name: e.name, members: gvs(t, 'member') || '-',
        extIntf: gv(t, 'interface') || '-', comment: gv(t, 'comments') || '-', _vdom: vdomName });
    });
    // IPv6 NAT66：官方 CLI Reference 確認 ippool6/vip6/vipgrp6 三段欄位名稱與 IPv4 版本幾乎
    // 相同（vip6/vipgrp6 完全同名；ippool6 僅有 startip/endip/comments，無 type/arp-reply/
    // source-startip 對應概念，故這三個欄位不填、維持 '-'，不臆測）
    const { sectionLines: pl6 } = extractSection(lines, 'firewall ippool6');
    parseEdits(pl6).forEach(e => {
      const t = e.text;
      nats.push({ type: 'ippool6', name: e.name, poolType: '-',
        startIp: gv(t, 'startip') || '-', endIp: gv(t, 'endip') || '-',
        srcIntf: '-', arpReply: '-',
        comment: gv(t, 'comments') || '-', _vdom: vdomName });
    });
    const { sectionLines: vl6 } = extractSection(lines, 'firewall vip6');
    parseEdits(vl6).forEach(e => {
      const t = e.text;
      nats.push({ type: 'vip6', name: e.name, vipType: gv(t, 'type') || 'static-nat',
        extIp: gv(t, 'extip') || '-', extIntf: gv(t, 'extintf') || '-', mapIp: gv(t, 'mappedip') || '-',
        portFwd: gv(t, 'portforward') || 'disable', extPort: gv(t, 'extport') || '-',
        mapPort: gv(t, 'mappedport') || '-', proto: gv(t, 'protocol') || '-',
        comment: gv(t, 'comment') || '-', status: gv(t, 'status') || 'enable', _vdom: vdomName });
    });
    const { sectionLines: vgl6 } = extractSection(lines, 'firewall vipgrp6');
    parseEdits(vgl6).forEach(e => {
      const t = e.text;
      nats.push({ type: 'vipgrp6', name: e.name, members: gvs(t, 'member') || '-',
        extIntf: '-', comment: gv(t, 'comments') || '-', _vdom: vdomName });
    });
    return nats;
  }

  function parseSchedules(lines, vdomName) {
    const s = [];
    const { sectionLines: ol } = extractSection(lines, 'firewall schedule onetime');
    parseEdits(ol).forEach(e => {
      const t = e.text;
      s.push({ type: 'onetime', name: e.name, start: gv(t, 'start') || '-',
        end: gv(t, 'end') || '-', day: '-', color: gv(t, 'color') || '0', _vdom: vdomName });
    });
    const { sectionLines: rl } = extractSection(lines, 'firewall schedule recurring');
    parseEdits(rl).forEach(e => {
      const t = e.text;
      s.push({ type: 'recurring', name: e.name, day: gv(t, 'day') || '-',
        start: gv(t, 'start') || '00:00', end: gv(t, 'end') || '00:00',
        color: gv(t, 'color') || '0', _vdom: vdomName });
    });
    return s;
  }

  function parseUsers(lines, vdomName, profiles) {
    const users = [];

    function mapLevel(prof) {
      const p = (prof || '').toLowerCase();
      if (p === 'prof_admin' || p === 'super_admin' || p === 'administrator') return 'super-admin';
      if (p.includes('read') && !p.includes('write')) return 'read-only';
      if (p.includes('vpn'))   return 'vpn-only';
      if (p.includes('log') || p.includes('audit')) return 'log-viewer';
      if (p.includes('wifi'))  return 'wifi-admin';
      return 'admin';
    }

    // Admins (usually in global/system admin)
    const { sectionLines: al } = extractSection(lines, 'system admin');
    parseEdits(al).forEach(e => {
      const t = e.text;
      const prof = gv(t, 'accprofile') || 'prof_admin';
      const vdomAccess = gvs(t, 'vdom') || vdomName;
      users.push({ type: 'admin', name: e.name,
        status: gv(t, 'accprofile') === 'no_access' ? 'disable' : 'enable',
        authType: gv(t, 'two-factor') && gv(t, 'two-factor') !== 'disable' ? 'two-factor' : 'password',
        email: gv(t, 'email-to') || '-',
        twoFactor: gv(t, 'two-factor') || 'disable',
        twoFType: gv(t, 'two-factor-authentication') || '-',
        ldapServer: '-', radiusServer: '-', comment: gv(t, 'comments') || '-', members: '-',
        vdom: vdomAccess,
        permissions: profiles[prof] || [{ resource: 'All', access: 'read-write' }],
        roles: [prof], accessLevel: mapLevel(prof), _vdom: vdomName });
    });

    // Local users
    const { sectionLines: ll } = extractSection(lines, 'user local');
    parseEdits(ll).forEach(e => {
      const t = e.text;
      users.push({ type: 'local', name: e.name,
        status: gv(t, 'status') || 'enable',
        authType: gv(t, 'type') || 'password',
        email: gv(t, 'email-to') || '-',
        twoFactor: gv(t, 'two-factor') || 'disable',
        twoFType: gv(t, 'two-factor-authentication') || '-',
        ldapServer: gv(t, 'ldap-server') || '-',
        radiusServer: gv(t, 'radius-server') || '-',
        comment: gv(t, 'comment') || '-', members: '-',
        permissions: [], roles: [], accessLevel: 'user', _vdom: vdomName });
    });

    // Groups
    const { sectionLines: gl } = extractSection(lines, 'user group');
    parseEdits(gl).forEach(e => {
      const t = e.text;
      users.push({ type: 'group', name: e.name,
        groupType: gv(t, 'group-type') || 'firewall',
        members: gvs(t, 'member') || '-',
        match: '-', authTimeout: gv(t, 'authtimeout') || '-',
        comment: '-', status: 'enable',
        permissions: [], roles: [], accessLevel: 'group', _vdom: vdomName });
    });

    // LDAP
    const { sectionLines: ldl } = extractSection(lines, 'user ldap');
    parseEdits(ldl).forEach(e => {
      const t = e.text;
      users.push({ type: 'ldap-server', name: e.name,
        server: gv(t, 'server') || '-', port: gv(t, 'port') || '389',
        dn: gv(t, 'dn') || '-', bindType: gv(t, 'bind-type') || 'anonymous',
        bindDn: gv(t, 'username') || '-', cnid: gv(t, 'cnid') || 'cn',
        groupFilter: gv(t, 'group-filter') || '-', ssl: gv(t, 'secure') || 'disable',
        comment: '-', status: 'enable', members: '-',
        permissions: [], roles: [], accessLevel: 'auth-server', _vdom: vdomName });
    });

    // RADIUS
    const { sectionLines: rl } = extractSection(lines, 'user radius');
    parseEdits(rl).forEach(e => {
      const t = e.text;
      users.push({ type: 'radius-server', name: e.name,
        server: gv(t, 'server') || '-', port: gv(t, 'auth-port') || '1812',
        authType: gv(t, 'auth-type') || 'auto', nasIp: gv(t, 'nas-ip') || '-',
        comment: '-', status: 'enable', members: '-',
        permissions: [], roles: [], accessLevel: 'auth-server', _vdom: vdomName });
    });

    // FSSO
    const { sectionLines: fl } = extractSection(lines, 'user fsso');
    parseEdits(fl).forEach(e => {
      const t = e.text;
      users.push({ type: 'fsso', name: e.name,
        server: gv(t, 'server') || '-', port: gv(t, 'port') || '8000',
        comment: '-', status: 'enable', members: '-',
        permissions: [], roles: [], accessLevel: 'auth-server', _vdom: vdomName });
    });

    return users;
  }

  function parseProfiles(lines) {
    const profiles = {};
    const { sectionLines } = extractSection(lines, 'system accprofile');
    parseEdits(sectionLines).forEach(e => {
      const t = e.text;
      const perms = [];
      ['secfabgrp','ftviewgrp','authgrp','sysgrp','netgrp','loggrp','fwgrp',
       'vpngrp','utmgrp','wanoptgrp','wifi'].forEach(k => {
        const v = gv(t, k);
        if (v && v !== 'none' && v !== 'disable') perms.push({ resource: k, access: v });
      });
      if (!perms.length) perms.push({ resource: 'All', access: gv(t, 'sysgrp') || 'read-write' });
      profiles[e.name] = perms;
    });
    return profiles;
  }

  // ── Main parse ────────────────────────────────────────────────────────────
  // ── SD-WAN ───────────────────────────────────────────────────────────────

  // ── DHCP Server & Relay ──────────────────────────────────────────────────
  function parseDhcp(lines, vdomName) {
    const servers = [], relays = [];
    const { sectionLines: dhcpLines, found } = extractSection(lines, 'system dhcp server');
    if (found) {
      parseEdits(dhcpLines).forEach(e => {
        const t = e.text;
        const { sectionLines: rl } = extractSection(t.split('\n'), 'ip-range');
        const ranges = parseEdits(rl);
        const startIp = ranges[0] ? gv(ranges[0].text,'start-ip') : gv(t,'start-ip');
        const endIp   = ranges[0] ? gv(ranges[0].text,'end-ip')   : gv(t,'end-ip');
        servers.push({ name:e.name, iface:gv(t,'interface')||'-',
          startIp, endIp, gateway:gv(t,'default-gateway')||'-',
          mask:gv(t,'netmask')||'-', dns1:gv(t,'dns-server1')||'-',
          dns2:gv(t,'dns-server2')||'-', domain:gv(t,'domain')||'-',
          lease:gv(t,'lease-time')||'86400', status:gv(t,'status')||'enable',
          comment:gv(t,'comments')||gv(t,'comment')||'', _vdom:vdomName });
      });
    }
    const { sectionLines: ifLines } = extractSection(lines, 'system interface');
    parseEdits(ifLines).forEach(e => {
      const t = e.text;
      if (gv(t,'dhcp-relay-service') === 'enable')
        relays.push({ name:e.name, iface:e.name, serverIp:gvs(t,'dhcp-relay-ip')||'-',
          status:'enable', comment:gv(t,'description')||'', _vdom:vdomName });
    });
    return { servers, relays };
  }

  // ── WWAN / 行動網路（4G/5G）────────────────────────────────────────────
  function parseWwan(lines, vdomName) {
    const { sectionLines } = extractSection(lines, 'wireless-controller wwan-profile');
    return {
      profiles: parseEdits(sectionLines).map(e => {
        const t = e.text;
        const pw = gv(t, 'passwd');
        return {
          name:     e.name,
          apn:      gv(t, 'apn') || '-',
          authType: gv(t, 'auth-type') || 'auto',
          username: gv(t, 'username') || '-',
          passwd:   pw ? (pw.startsWith('ENC') ? 'enc' : 'plain') : '-',
          modemId:  gv(t, 'modem-id') || '1',
          simPin:   gv(t, 'sim-pin') ? 'set' : 'notset',
          provider: gv(t, 'network-provider') || 'auto',
          dataplan: gv(t, 'dataplan') || 'auto',
          _vdom:    vdomName,
        };
      }),
    };
  }

  function parseLteModem(lines) {
    const { sectionLines, found } = extractSection(lines, 'system lte-modem');
    if (!found) return null;
    const t = sectionLines.join('\n');
    return {
      status:     gv(t, 'status') || 'disable',
      autoSwitch: gv(t, 'auto-switch') || 'disable',
      modemPort:  gv(t, 'modem-port') || '-',
      apn:        gv(t, 'apn') || '-',
      authType:   gv(t, 'authtype') || '-',
    };
  }

  function parseSystemModem(lines) {
    const { sectionLines, found } = extractSection(lines, 'system modem');
    if (!found) return null;
    const t = sectionLines.join('\n');
    return { status: gv(t, 'status') || 'enable', altMode: gv(t, 'altmode') || 'disable', pinInit: gv(t, 'pin-init') || '-' };
  }

  // FortiGate 5G/4G 型號（FG-50G-5G、FG-60G 等）
  // config system 5g-modem 內含巢狀 config modem1 / modem2 結構
  function parse5GModem(lines) {
    const { sectionLines, found } = extractSection(lines, 'system 5g-modem');
    if (!found) return null;
    function parseModemBlock(modemLines) {
      const t = modemLines.join('\n');
      const pw = gv(t, 'passwd');
      return {
        apn:        gv(t, 'apn') || '-',
        apnProvider:gv(t, 'apn-provider') || 'auto',
        authType:   gv(t, 'auth-type') || 'auto',
        username:   gv(t, 'username') || '-',
        passwd:     pw ? (pw.startsWith('ENC') ? 'enc' : 'plain') : '-',
        sim1Pin:    gv(t, 'sim1-pin') ? 'set' : 'notset',
        sim2Pin:    gv(t, 'sim2-pin') ? 'set' : 'notset',
        preferSim:  gv(t, 'preferred-sim') || 'sim1',
        interface:  gv(t, 'interface') || 'wwan',
      };
    }
    const { sectionLines: m1L, found: hasM1 } = extractSection(sectionLines, 'modem1');
    const { sectionLines: m2L, found: hasM2 } = extractSection(sectionLines, 'modem2');
    return {
      modem1: hasM1 ? parseModemBlock(m1L) : null,
      modem2: hasM2 ? parseModemBlock(m2L) : null,
    };
  }

  // ── DNS ─────────────────────────────────────────────────────────────────
  function parseDns(lines, vdomName) {
    const result = { servers:[], secondaries:[], domain:'-', proxy:false,
      proxyRules:[], dnsOverTls:false, cacheSize:'-', static:[], _vdom:vdomName };
    const { sectionLines: dl } = extractSection(lines, 'system dns');
    if (dl.length) {
      const t = dl.join('\n');
      const pri=gv(t,'primary');   if(pri&&pri!=='-') result.servers.push(pri);
      const sec=gv(t,'secondary'); if(sec&&sec!=='-') result.secondaries.push(sec);
      result.domain = gv(t,'domain')||'-';
      result.dnsOverTls = gv(t,'dns-over-tls')==='enable';
    }
    const { sectionLines: dbL } = extractSection(lines, 'system dns-database');
    parseEdits(dbL).forEach(e => {
      const t=e.text;
      const { sectionLines: eL } = extractSection(t.split('\n'), 'dns-entry');
      parseEdits(eL).forEach(en => {
        const et=en.text;
        result.static.push({ name:gv(et,'hostname')+'.'+e.name, type:gv(et,'type')||'A',
          ip:gv(et,'ip')||'-', zone:e.name });
      });
      result.proxyRules.push({ domain:e.name, target:'local', type:gv(t,'type')||'primary' });
    });
    if (extractSection(lines,'dnsfilter profile').found) result.proxy=true;
    return result;
  }


  // ── SNMP ────────────────────────────────────────────────────────────────────
  function parseSnmp(lines, vdomName) {
    const result = { enabled:false, agent:{name:'-',description:'-',location:'-',contact:'-',version:[]}, communities:[], v3users:[], trapServers:[] };
    // sysinfo
    const { sectionLines: siL } = extractSection(lines, 'system snmp sysinfo');
    if (siL.length) {
      const t=siL.join('\n');
      result.enabled = gv(t,'status')==='enable';
      result.agent.description = gv(t,'description')||'-';
      result.agent.contact     = gv(t,'contact-info')||'-';
      result.agent.location    = gv(t,'location')||'-';
      result.agent.name        = gv(t,'description')||'-';
    }
    // communities (v1/v2c)
    const { sectionLines: comL } = extractSection(lines, 'system snmp community');
    parseEdits(comL).forEach(e => {
      const t=e.text;
      const { sectionLines: hostL } = extractSection(t.split('\n'), 'hosts');
      // Strip subnet mask from host IP (FG stores 'set ip X.X.X.X 255.255.255.255')
      const hosts = parseEdits(hostL).map(h=>{ const raw=gv(h.text,'ip')||'-'; return raw.split(' ')[0]; }).filter(h=>h&&h!=='-');
      const events = gvs(t,'events');
      const trapV1 = gv(t,'trap-v1-status')==='enable';
      const trapV2 = gv(t,'trap-v2c-status')==='enable';
      if(trapV1&&!result.agent.version.includes('v1')) result.agent.version.push('v1');
      if(trapV2&&!result.agent.version.includes('v2c')) result.agent.version.push('v2c');
      // FG communities: no explicit permission field; detect from name convention
      // Community name is 'set name X' inside the edit block, not the edit number
      const commName = gv(t,'name') || e.name;
      const commPerm = /rw|write|admin/i.test(commName) ? 'rw' : 'ro';
      result.communities.push({ name:commName, permission:commPerm, allowedHosts:hosts, events:events||'-', status:gv(t,'status')||'enable' });
      // Only add trap server if trap sending is enabled for this community
      if (trapV1||trapV2) hosts.forEach(h=>{ if(h&&h!=='-') result.trapServers.push({ ip:h.split(' ')[0], port:'162', community:commName, version:trapV2?'v2c':'v1' }); });
    });
    // v3 users
    const { sectionLines: v3L } = extractSection(lines, 'system snmp user');
    parseEdits(v3L).forEach(e => {
      const t=e.text;
      if(!result.agent.version.includes('v3')) result.agent.version.push('v3');
      result.v3users.push({ name:e.name, secLevel:gv(t,'security-level')||'auth-priv', authProto:gv(t,'auth-proto')||'sha', privProto:gv(t,'priv-proto')||'aes', notifyHost:gvs(t,'notify-hosts')||(gv(t,'notify-hosts'))||'-', status:gv(t,'status')||'enable' });
    });
    return result;
  }

  // ── Log Servers ──────────────────────────────────────────────────────────────
  function parseLogServers(lines, vdomName) {
    const result = { syslog:[], fortianalyzer:[], netflow:[], logForward:[] };
    // Syslog 1-4
    ['syslogd','syslogd2','syslogd3','syslogd4'].forEach((name,i) => {
      const { sectionLines: sl, found } = extractSection(lines, `log ${name} setting`);
      if (!found) return;
      const t=sl.join('\n');
      if (gv(t,'status')!=='enable') return;
      result.syslog.push({ name:`Syslog${i+1}`, server:gv(t,'server')||'-', port:gv(t,'port')||'514', facility:gv(t,'facility')||'local7', format:gv(t,'format')||'default', protocol:gv(t,'reliable')==='enable'?'TCP':'UDP', level:gv(t,'severity')||'information', status:'enable', _vdom:vdomName });
    });
    // FortiAnalyzer
    ['fortianalyzer','fortianalyzer2','fortianalyzer3'].forEach((name,i) => {
      const { sectionLines: fl, found } = extractSection(lines, `log ${name} setting`);
      if (!found) return;
      const t=fl.join('\n');
      if (gv(t,'status')!=='enable') return;
      result.fortianalyzer.push({ name:`FortiAnalyzer${i+1}`, server:gv(t,'server')||'-', port:gv(t,'port')||'514', reliable:gv(t,'reliable')||'disable', encAlgo:gv(t,'enc-algorithm')||'high', status:'enable', _vdom:vdomName });
    });
    // NetFlow
    const { sectionLines: nfL, found: nfF } = extractSection(lines, 'log netflow setting');
    if (nfF) {
      const t=nfL.join('\n');
      if (gv(t,'status')==='enable') result.netflow.push({ collector:gv(t,'collector-ip')||'-', port:gv(t,'collector-port')||'2055', activeTimeout:gv(t,'active-timeout')||'60', status:'enable', _vdom:vdomName });
    }
    return result;
  }

  function parseSdwan(lines, vdomName) {
    const result = {
      enabled: false, lbMode: '-',
      zones: [], members: [], healthChecks: [], services: [], neighbors: [],
      _vdom: vdomName,
    };
    const { sectionLines: sdwanLines, found } = extractSection(lines, 'system sdwan');
    if (!found) return result;
    result.enabled = true;
    const sdwanText = sdwanLines.join('\n');
    result.lbMode = gv(sdwanText, 'load-balance-mode') || 'source-ip-based';

    // Zones
    const { sectionLines: zoneLines } = extractSection(sdwanLines, 'zone');
    parseEdits(zoneLines).forEach(e => {
      result.zones.push({ name: e.name, _vdom: vdomName });
    });

    // Members (WAN links)
    const { sectionLines: memberLines } = extractSection(sdwanLines, 'members');
    parseEdits(memberLines).forEach(e => {
      const t = e.text;
      result.members.push({
        id: e.name,
        iface:    gv(t,'interface')  || '-',
        zone:     gv(t,'zone')       || 'virtual-wan-link',
        gateway:  gv(t,'gateway')    || '-',
        gateway6: gv(t,'gateway6')   || '-',
        priority: parseInt(gv(t,'priority')||'0')  || 0,
        weight:   parseInt(gv(t,'weight')  ||'1')  || 1,
        cost:     parseInt(gv(t,'cost')    ||'0')  || 0,
        linkCost: parseInt(gv(t,'link-cost')||'0') || 0,
        linkStatus: gv(t,'link-status') || 'online',
        autoFailback: gv(t,'auto-failback') || 'disable',
        sourceIp: gv(t,'source-ip') || '-',
        spillover:parseInt(gv(t,'spillover-threshold')||'0') || 0,
        volumeRatio: parseInt(gv(t,'volume-ratio')||'1') || 1,
        status:   gv(t,'status') || 'enable',
        comment:  gv(t,'comment') || '',
        _vdom: vdomName,
      });
    });

    // Health Checks
    const { sectionLines: hcLines } = extractSection(sdwanLines, 'health-check');
    parseEdits(hcLines).forEach(e => {
      const t = e.text;
      const members = gvs(t,'members');
      const { sectionLines: slaLines } = extractSection(t.split('\n'), 'sla');
      const slaThresholds = [];
      parseEdits(slaLines).forEach(se => {
        const st = se.text;
        slaThresholds.push({
          id: se.name,
          latency:    gv(st,'latency-threshold')    || '250',
          jitter:     gv(st,'jitter-threshold')     || '50',
          packetLoss: gv(st,'packetloss-threshold') || '10',
        });
      });
      result.healthChecks.push({
        name:         e.name,
        server:       gv(t,'server')        || '-',
        protocol:     gv(t,'protocol')      || 'ping',
        port:         gv(t,'port')          || '-',
        interval:     gv(t,'interval')      || '500',
        timeout:      gv(t,'timeout')       || '500',
        failtime:     gv(t,'failtime')      || '5',
        recoverytime: gv(t,'recoverytime')  || '5',
        probePackets: gv(t,'probe-packets') || '5',
        http200Only:  gv(t,'http-200-only') || 'disable',
        detectMode:   gv(t,'detect-mode')   || 'active',
        passwordAuth: gv(t,'password') ? '●●●●' : 'disable',
        threshold:    gv(t,'health-check-threshold') || '-',
        members:      members && members !== '' ? members : 'all',
        slaThresholds,
        _vdom: vdomName,
      });
    });

    // SD-WAN Rules (services)
    const { sectionLines: svcLines } = extractSection(sdwanLines, 'service');
    parseEdits(svcLines).forEach(e => {
      const t = e.text;
      const { sectionLines: ruleSlaLines } = extractSection(t.split('\n'), 'sla');
      const slaRefs = [];
      parseEdits(ruleSlaLines).forEach(se => {
        slaRefs.push({ healthCheck: se.name, id: gv(se.text,'id') || '1' });
      });
      result.services.push({
        id:           e.name,
        name:         gv(t,'name')             || `Rule-${e.name}`,
        mode:         gv(t,'mode')             || 'auto',
        src:          gvs(t,'src')             || 'all',
        dst:          gvs(t,'dst')             || 'all',
        srcAddr6:     gvs(t,'src-addr6')       || 'all',
        dstAddr6:     gvs(t,'dst-addr6')       || 'all',
        srcNegate:    gv(t,'src-negate')       || 'disable',
        dstNegate:    gv(t,'dst-negate')       || 'disable',
        users:        gvs(t,'users')            || '-',
        groups:       gvs(t,'groups')           || '-',
        protocol:     gv(t,'protocol')         || '0',
        startPort:    gv(t,'start-port')       || '-',
        endPort:      gv(t,'end-port')         || '-',
        routeTag:     gv(t,'route-tag')        || '-',
        minBandwidth: gv(t,'min-bandwidth')    || '-',
        maxBandwidth: gv(t,'max-bandwidth')    || '-',
        appCategory:  gvs(t,'app-category')    || '-',
        application:  gvs(t,'application')     || '-',
        priorityMembers: gvs(t,'priority-member')  || '-',
        priorityZone:    gvs(t,'priority-zone')    || '-',
        preferredUplink: gv(t,'preferred-uplink') || '-',
        slaCompare:   gv(t,'sla-compare-method') || 'order',
        tie:          gv(t,'tie-break')        || 'zone',
        slaRefs,
        inputDevice:  gvs(t,'input-device')     || '-',
        status:       gv(t,'status') === 'disable' ? 'disable' : 'enable',
        comment:      gv(t,'comment') || '',
        _vdom: vdomName,
      });
    });

    // BGP Neighbors over SD-WAN
    const { sectionLines: nbLines } = extractSection(sdwanLines, 'neighbor');
    parseEdits(nbLines).forEach(e => {
      const t = e.text;
      result.neighbors.push({
        ip:    e.name,
        member:gv(t,'member') || '-',
        role:  gv(t,'role')   || 'primary',
        _vdom: vdomName,
      });
    });

    return result;
  }

  // HA/Cluster：已查證官方 CLI Reference（config system ha）語法，`config system ha` 是
  // device-global 區塊（非 per-VDOM，比照既有 parseSnmp 的 global-only 慣例，不走 sdwan
  // 那種 per-vdom merge）
  function parseHa(lines, vdomName) {
    const result = { enabled:false, mode:'standalone', groupId:'-', groupName:'-', priority:'-', syncInterface:'-', peerIp:'-', vip:'-', override:false, _vdom:vdomName };
    const { sectionLines: haLines, found } = extractSection(lines, 'system ha');
    if (!found) return result;
    const t = haLines.join('\n');
    const mode = gv(t,'mode') || 'standalone';
    result.mode = mode;
    result.enabled = mode !== 'standalone';
    if (!result.enabled) return result;
    result.groupId = gv(t,'group-id') || '0';
    result.groupName = gv(t,'group-name') || '-';
    result.priority = gv(t,'priority') || '128';
    result.override = gv(t,'override') === 'enable';
    result.syncInterface = gvs(t,'hbdev') || '-';
    return result;
  }

  // Web Filter profile 摘要（僅摘要層級：分類動作統計數量，不逐條展開 ftgd-wf filters）
  function parseWebfilterProfiles(lines, vdomName) {
    const { sectionLines } = extractSection(lines, 'webfilter profile');
    return parseEdits(sectionLines).map(e => {
      const t = e.text;
      const { sectionLines: ftgdLines, found: ftgdFound } = extractSection(t.split('\n'), 'ftgd-wf');
      let blockCount = 0, monitorCount = 0, allowCount = 0;
      if (ftgdFound) {
        const { sectionLines: filterLines } = extractSection(ftgdLines, 'filters');
        parseEdits(filterLines).forEach(f => {
          const action = gv(f.text, 'action');
          if (action === 'block') blockCount++;
          else if (action === 'monitor') monitorCount++;
          else if (action) allowCount++;
        });
      }
      return {
        name: e.name, comment: gv(t,'comment') || '-', options: gvs(t,'options') || '-',
        blockCount, monitorCount, allowCount, _vdom: vdomName,
      };
    });
  }

  // IPS sensor 摘要（僅摘要層級：severity/action 統計數量，不逐條展開 entries）
  function parseIpsSensors(lines, vdomName) {
    const { sectionLines } = extractSection(lines, 'ips sensor');
    return parseEdits(sectionLines).map(e => {
      const t = e.text;
      const { sectionLines: entryLines, found } = extractSection(t.split('\n'), 'entries');
      const entries = found ? parseEdits(entryLines) : [];
      const sevCount = {}, actionCount = {};
      entries.forEach(en => {
        const sevs = (gvs(en.text,'severity') || '-').split(', ').filter(Boolean);
        const act = gv(en.text,'action') || 'default';
        sevs.forEach(s => { sevCount[s] = (sevCount[s]||0) + 1; });
        actionCount[act] = (actionCount[act]||0) + 1;
      });
      return {
        name: e.name, comment: gv(t,'comment') || '-', entryCount: entries.length,
        severityCounts: sevCount, actionCounts: actionCount, _vdom: vdomName,
      };
    });
  }

  function parse(text) {
    const { globalLines, vdomBlocks, isMultiVdom } = splitTopLevel(text);

    // Parse global section (interfaces, admins, profiles)
    const globalLineArr = globalLines || text.split(/\r?\n/);
    const profiles = parseProfiles(globalLineArr);

    // Determine vdom names (from first config vdom block)
    const vdomNames = isMultiVdom
      ? [...new Set(vdomBlocks.map(v => v.name).filter(n => n !== 'root'))]
      : [];
    if (isMultiVdom && vdomBlocks.some(v => v.name === 'root')) vdomNames.unshift('root');

    // Parse per-vdom data
    // 位址物件需先解析出來，才能建 addrTypeMap 供 policies 的 srcaddr/dstaddr 名稱反查 v4/v6
    // 型別（見 _splitAddr() 上方註解）
    const perVdom = vdomBlocks.map(vb => {
      const addresses = parseAddressObjects(vb.lines, vb.name);
      const addrTypeMap = buildAddrTypeMap(addresses);
      return {
      name: vb.name,
      interfaces: parseInterfaces(vb.lines, vb.name),
      policies:   [...parsePolicies(vb.lines, vb.name, addrTypeMap), ...parsePolicies6(vb.lines, vb.name)],
      routes:     parseRoutes(vb.lines, vb.name),
      vpn:        parseVPN(vb.lines, vb.name),
      addresses,
      services:   parseServiceObjects(vb.lines, vb.name),
      nat:        parseNAT(vb.lines, vb.name),
      schedules:  parseSchedules(vb.lines, vb.name),
      users:      parseUsers(vb.lines, vb.name, profiles),
      sdwan:      parseSdwan(vb.lines, vb.name),
      dhcp:       parseDhcp(vb.lines, vb.name),
      dns:        parseDns(vb.lines, vb.name),
      snmp:       parseSnmp(vb.lines, vb.name),
      logservers: parseLogServers(vb.lines, vb.name),
      wwan:       parseWwan(vb.lines, vb.name),
      webfilterProfiles: parseWebfilterProfiles(vb.lines, vb.name),
      ipsSensors: parseIpsSensors(vb.lines, vb.name),
      };
    });

    // Global data (interfaces normally live in "config global" for multi-vdom, but some
    // exports place "config system interface" inside each vdom block instead — merge both
    // so per-vdom-only interfaces aren't silently dropped)
    const globalInterfaces = parseInterfaces(globalLineArr, 'global');
    const interfaces = isMultiVdom
      ? [...globalInterfaces, ...perVdom.flatMap(v => v.interfaces)]
      : globalInterfaces;
    const globalUsers = isMultiVdom
      ? parseUsers(globalLineArr, '__global__', profiles)
      : [];
    // SD-WAN: in single-VDOM mode parse from globalLineArr; in multi-VDOM merge from perVdom
    const globalSdwan = !isMultiVdom ? parseSdwan(globalLineArr, 'root') : null;
    const globalDhcp  = !isMultiVdom ? parseDhcp(globalLineArr, 'root')  : null;
    const globalDns   = !isMultiVdom ? parseDns(globalLineArr, 'root')   : null;
    const globalSnmp  = parseSnmp(globalLineArr, 'root');
    const globalHa    = parseHa(globalLineArr, 'root');
    const globalLog   = parseLogServers(globalLineArr, 'root');
    // LTE/5G modem 設定在 config global（multi-VDOM）或頂層（single-VDOM）
    const lteModem    = parseLteModem(globalLineArr);
    const systemModem = parseSystemModem(globalLineArr);
    const modem5G     = parse5GModem(globalLineArr);

    // Merge all vdoms
    // SD-WAN: merge per-vdom results, or use globalSdwan for single-VDOM
    const mergeSnmp = (vdoms) => ({
      enabled:      vdoms.some(v => v.snmp?.enabled),
      agent:        vdoms.find(v => v.snmp?.enabled)?.snmp?.agent || {name:'-',description:'-',location:'-',contact:'-',version:[]},
      communities:  vdoms.flatMap(v => v.snmp?.communities || []),
      v3users:      vdoms.flatMap(v => v.snmp?.v3users      || []),
      trapServers:  vdoms.flatMap(v => v.snmp?.trapServers   || []),
    });
    const mergeLog = (vdoms) => ({
      syslog:       vdoms.flatMap(v => v.logservers?.syslog       || []),
      fortianalyzer:vdoms.flatMap(v => v.logservers?.fortianalyzer|| []),
      netflow:      vdoms.flatMap(v => v.logservers?.netflow       || []),
      logForward:   vdoms.flatMap(v => v.logservers?.logForward    || []),
    });
    const mergeDhcp = (vdoms) => ({
      servers: vdoms.flatMap(v => v.dhcp?.servers || []),
      relays:  vdoms.flatMap(v => v.dhcp?.relays  || []),
    });
    const mergeDns = (vdoms) => ({
      servers:     vdoms.flatMap(v => v.dns?.servers     || []),
      secondaries: vdoms.flatMap(v => v.dns?.secondaries || []),
      domain:      vdoms.find(v => v.dns?.domain && v.dns.domain !== '-')?.dns?.domain || '-',
      proxy:       vdoms.some(v => v.dns?.proxy),
      proxyRules:  vdoms.flatMap(v => v.dns?.proxyRules  || []),
      dnsOverTls:  vdoms.some(v => v.dns?.dnsOverTls),
      cacheSize:   '-',
      static:      vdoms.flatMap(v => v.dns?.static      || []),
    });
    const mergeSdwan = (vdoms) => ({
      enabled:      vdoms.some(v => v.sdwan.enabled),
      lbMode:       vdoms.find(v => v.sdwan.enabled)?.sdwan.lbMode || '-',
      zones:        vdoms.flatMap(v => v.sdwan.zones),
      members:      vdoms.flatMap(v => v.sdwan.members),
      healthChecks: vdoms.flatMap(v => v.sdwan.healthChecks),
      services:     vdoms.flatMap(v => v.sdwan.services),
      neighbors:    vdoms.flatMap(v => v.sdwan.neighbors),
    });
    const all = {
      policies:  perVdom.flatMap(v => v.policies),
      routes:    perVdom.flatMap(v => v.routes),
      vpn:       perVdom.flatMap(v => v.vpn),
      addresses: perVdom.flatMap(v => v.addresses),
      services:  perVdom.flatMap(v => v.services),
      nat:       perVdom.flatMap(v => v.nat),
      schedules: perVdom.flatMap(v => v.schedules),
      webfilterProfiles: perVdom.flatMap(v => v.webfilterProfiles),
      ipsSensors: perVdom.flatMap(v => v.ipsSensors),
      users:     [...globalUsers, ...perVdom.flatMap(v => v.users)],
      sdwan:     isMultiVdom ? mergeSdwan(perVdom) : globalSdwan,
      dhcp:      isMultiVdom ? mergeDhcp(perVdom)  : globalDhcp,
      dns:       isMultiVdom ? mergeDns(perVdom)   : globalDns,
      // SNMP: device-global only (config system snmp is in 'config global', never per-VDOM)
      snmp:      globalSnmp,
      // HA: device-global only (config system ha is in 'config global', never per-VDOM)
      ha:        globalHa,
      // Log: merge global log + per-VDOM log (both exist in FortiGate multi-VDOM)
      logservers:isMultiVdom ? {
        syslog:        [...(globalLog.syslog||[]), ...perVdom.flatMap(v=>v.logservers?.syslog||[])],
        fortianalyzer: [...(globalLog.fortianalyzer||[]), ...perVdom.flatMap(v=>v.logservers?.fortianalyzer||[])],
        netflow:       [...(globalLog.netflow||[]), ...perVdom.flatMap(v=>v.logservers?.netflow||[])],
        logForward:    [...(globalLog.logForward||[]), ...perVdom.flatMap(v=>v.logservers?.logForward||[])],
      } : globalLog,
      wwan: {
        profiles:    perVdom.flatMap(v => v.wwan?.profiles || []),
        lteModem,
        systemModem,
        modem5G,
      },
    };

    return {
      vendor:     'FortiGate',
      deviceInfo: parseDeviceInfo(text, isMultiVdom, vdomNames),
      interfaces,
      ...all,
      // VDOM metadata for UI filtering
      _vdomNames: vdomNames,
      _isMultiVdom: isMultiVdom,
      _perVdom: perVdom,   // per-vdom breakdowns for convert
    };
  }

  return { parse, splitTopLevel };
})();


