// ══════════════════════════════════════════════════════════
//  CISCO ASA PARSER
// ══════════════════════════════════════════════════════════
const CiscoASAParser = (() => {

  function parseDeviceInfo(text) {
    const hostname = (text.match(/^hostname\s+(\S+)/m)||[])[1]||'-';
    const firmware  = (text.match(/^ASA Version\s+(\S+)/m)||[])[1]||'-';
    const model     = (text.match(/^Hardware:\s*(\S+)/m)||[])[1]||'-';
    const serial    = (text.match(/^Serial Number:\s*(\S+)/m)||[])[1]||'-';
    return { vendor:'Cisco ASA', hostname, firmware, model, serial, vdom:[] };
  }

  function parseInterfaces(text) {
    const ifaces = [];
    for (const block of text.split(/^(?=interface\s)/m)) {
      const mIf = block.match(/^interface\s+(.+)/);
      if (!mIf) continue;
      const name = mIf[1].trim();
      let ip='-', mask='-', nameif='', secLevel=-1, shutdown=false, desc='';
      for (const l of block.split('\n').slice(1)) {
        const t = l.trim();
        const mIp  = t.match(/^ip address\s+(\S+)\s+(\S+)/);
        if (mIp) { ip = mIp[1]; mask = mIp[2]; }
        const mNif = t.match(/^nameif\s+(\S+)/);
        if (mNif) nameif = mNif[1];
        const mSec = t.match(/^security-level\s+(\d+)/);
        if (mSec) secLevel = parseInt(mSec[1]);
        if (/^shutdown/.test(t)) shutdown = true;
        const mD = t.match(/^description\s+(.+)/);
        if (mD) desc = mD[1];
      }
      let role = 'internal';
      if (secLevel === 0) role = 'external';
      else if (secLevel > 0 && secLevel < 100) role = 'dmz';
      ifaces.push({ name, ip, mask, type:'physical', role, status:shutdown?'down':'up', desc, nameif, secLevel });
    }
    return ifaces;
  }

  function parsePolicies(text, addrTypeMap) {
    const policies = [];
    let id = 1;
    for (const line of text.split('\n')) {
      const m = line.match(/^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.+)/);
      if (!m) continue;
      const [, aclName, rawAction, proto, rest] = m;
      const action = rawAction === 'permit' ? 'accept' : 'deny';
      const parts = rest.trim().split(/\s+/);
      let src='any', dst='any', svc=proto, i=0;
      // parse source
      if (parts[i]==='any'||parts[i]==='any4'||parts[i]==='any6') { src='any'; i++; }
      else if (parts[i]==='host') { src=parts[i+1]||'any'; i+=2; }
      else if (parts[i]==='object'||parts[i]==='object-group') { src=parts[i+1]||'any'; i+=2; }
      else if (/^\d+\.\d+\.\d+\.\d+$/.test(parts[i])&&/^\d+\.\d+\.\d+\.\d+$/.test(parts[i+1]||'')) { src=`${parts[i]} ${parts[i+1]}`; i+=2; }
      else { src=parts[i]||'any'; i++; }
      // parse dest
      if (i<parts.length) {
        if (parts[i]==='any'||parts[i]==='any4'||parts[i]==='any6') { dst='any'; i++; }
        else if (parts[i]==='host') { dst=parts[i+1]||'any'; i+=2; }
        else if (parts[i]==='object'||parts[i]==='object-group') { dst=parts[i+1]||'any'; i+=2; }
        else if (/^\d+\.\d+\.\d+\.\d+$/.test(parts[i])&&/^\d+\.\d+\.\d+\.\d+$/.test(parts[i+1]||'')) { dst=`${parts[i]} ${parts[i+1]}`; i+=2; }
        else { dst=parts[i]||'any'; i++; }
      }
      if (parts[i]==='eq'&&parts[i+1]) svc=`${proto}/${parts[i+1]}`;
      else if (parts[i]==='range'&&parts[i+1]&&parts[i+2]) svc=`${proto}/${parts[i+1]}-${parts[i+2]}`;
      const srcAddrSplit = _splitAddr(src, addrTypeMap);
      const dstAddrSplit = _splitAddr(dst, addrTypeMap);
      // ASA 原生支援的 ACE 修飾字：行尾 `inactive` 停用該筆規則（不刪除）；`log disable`
      // 明確關閉該筆日誌（預設情況下 ASA 對每筆 ACE 皆會記錄，非顯式停用即視為有記錄）。
      // status/logtraffic 欄位值須與其餘廠牌 parser 共用慣例一致（'enable'/'disable'，全小寫），
      // 否則 analyzeCompliance()/analyzeRuleShadowing()/_runPolicyQuery()/computeFirewallHealth()
      // 等共用函式會誤判 ASA/FTD 規則永遠是「未停用」「無日誌」。utm 為固定佔位物件
      // （ASA 無 UTM profile 概念，比照 Juniper/MikroTik 等其餘無 UTM 廠牌既有慣例），
      // 避免 exportCSV('policies') 讀取 r.utm.av 時因 utm 為 undefined 而拋例外。
      const status = /\binactive\b/.test(rest) ? 'disable' : 'enable';
      const logtraffic = /\blog\s+disable\b/.test(rest) ? 'disable' : 'all';
      policies.push({ id:id++, name:aclName, srcIntf:'-', dstIntf:'-', srcAddr:src, dstAddr:dst, srcAddr4:srcAddrSplit.v4, srcAddr6:srcAddrSplit.v6, dstAddr4:dstAddrSplit.v4, dstAddr6:dstAddrSplit.v6, service:svc, action, schedule:'-', nat:'disable', ippool:'disable', poolname:'-', logtraffic, logstart:'-', utm:{av:'-',webfilter:'-',ips:'-',ssl:'-',appctrl:'-'}, status, comments:'-', users:'-', groups:'-', vdom:aclName, enabled: status==='enable', color:'0' });
    }
    return policies;
  }

  function parseAddressObjects(text) {
    const addrs = [];
    for (const block of text.split(/^(?=object(?:-group)?\s+network\s)/m)) {
      const mObj = block.match(/^object\s+network\s+(\S+)/);
      const mGrp = block.match(/^object-group\s+network\s+(\S+)/);
      const name = (mObj||mGrp)?.[1];
      if (!name) continue;
      const members = [];
      for (const l of block.split('\n').slice(1)) {
        const t = l.trim();
        if (!t||t.startsWith('!')) continue;
        const mH = t.match(/^host\s+(\S+)/);
        // 官方語法（Cisco Secure Firewall ASA CLI Configuration Guide）：
        // subnet {IPv4_address IPv4_mask | IPv6_address/IPv6_prefix} —— IPv6 是單一 token 的
        // 斜線 CIDR 寫法，與 IPv4 雙 token（位址+遮罩）不同，需分開比對，不能共用同一個正則
        const mS6 = t.match(/^subnet\s+(\S+\/\d+)$/);
        const mS4 = t.match(/^subnet\s+(\S+)\s+(\S+)/);
        const mR = t.match(/^range\s+(\S+)\s+(\S+)/);
        const mN = t.match(/^network-object\s+(.+)/);
        if (mH) members.push(mH[1]);
        else if (mS6) members.push(mS6[1]);
        else if (mS4) members.push(`${mS4[1]}/${mS4[2]}`);
        else if (mR) members.push(`${mR[1]}-${mR[2]}`);
        else if (mN) members.push(mN[1].trim());
      }
      // category：ASA 語法沒有獨立的 v4/v6 物件關鍵字（host/subnet 兩者共用，格式差異只在值
      // 本身），buildAddrTypeMap()/buildCiscoASAAddrTypeMap() 對 'address'/'address6' 一視
      // 同仁（用 colon 偵測值本身判斷型別），固定填 'address'/'address-group' 即可。
      // members 改存逗號分隔字串（比照專案既有慣例，UI 渲染與其他廠牌 parser 皆預期字串）
      addrs.push({ name, type:mGrp?'group':'host', category:mGrp?'address-group':'address', subnet:members[0]||'-', members:members.join(', '), color:'0' });
    }
    return addrs;
  }
  // ASA 的 group members 是原始片段字串（如 "host 2001:db8::1"／"192.168.1.0/24"／
  // "object WEB-SERVER"），不是共用 buildAddrTypeMap() 群組邏輯假設的「純名稱清單」，故先
  // 沿用共用函式處理好 host 型別物件的分類，再疊加一輪 ASA 專屬的 group 分類覆寫回 map
  function buildCiscoASAAddrTypeMap(addressObjects) {
    const map = buildAddrTypeMap(addressObjects);
    (addressObjects || []).forEach(o => {
      if (o.type !== 'group') return;
      const frags = (o.members || '').split(/\s*,\s*/).filter(Boolean);
      const types = new Set();
      frags.forEach(f => {
        if (f.startsWith('object ')) types.add(map.get(f.slice(7)) || 'v4');
        else types.add(f.includes(':') ? 'v6' : 'v4');
      });
      map.set(o.name, types.size > 1 ? 'mixed' : (types.values().next().value || 'v4'));
    });
    return map;
  }

  function parseServiceObjects(text) {
    const svcs = [];
    for (const block of text.split(/^(?=object-group\s+service\s)/m)) {
      const m = block.match(/^object-group\s+service\s+(\S+)(?:\s+(\S+))?/);
      if (!m) continue;
      const name=m[1], proto=m[2]||'';
      const ports = [];
      for (const l of block.split('\n').slice(1)) {
        const t = l.trim();
        const mP = t.match(/^(?:port-object|service-object\s+\S+)\s+(?:eq\s+(\S+)|range\s+(\S+)\s+(\S+))/);
        if (mP) ports.push(mP[1]||`${mP[2]}-${mP[3]}`);
      }
      svcs.push({ name, proto, port:ports.join(',')||'-', type:'group', color:'0' });
    }
    return svcs;
  }

  function parseNAT(text) {
    const nat = [];
    let id = 1;
    for (const line of text.split('\n')) {
      const mNew = line.match(/^nat\s+\(([^,]+),([^)]+)\)\s+(?:\d+\s+)?source\s+(static|dynamic)\s+(\S+)\s+(\S+)/);
      if (mNew) {
        nat.push({ id:id++, type:mNew[3], srcIf:mNew[1].trim(), dstIf:mNew[2].trim(), origSrc:mNew[4], transSrc:mNew[5] });
        continue;
      }
      const mOld = line.match(/^nat\s+\((\S+)\)\s+(\d+)\s+(\S+)\s+(\S+)/);
      if (mOld) {
        nat.push({ id:id++, type:mOld[2]==='0'?'nonat':'dynamic', srcIf:mOld[1], dstIf:'outside', origSrc:`${mOld[3]}/${mOld[4]}`, transSrc:'interface' });
      }
    }
    return nat;
  }

  function parseRoutes(text) {
    const routes = [];
    let id = 1;
    for (const line of text.split('\n')) {
      const m = line.match(/^route\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?/);
      if (!m) continue;
      // 欄位形狀比照其餘廠牌 parser 共用 schema（id/dst/device/distance/status/blackhole/
      // comment），而非自成一格的 iface/mask/metric——2026-07-21 查核發現原本自成一格的欄位名稱
      // 導致 UI 路由表/HTML 報表/CSV 匯出/跨廠牌轉換全部讀不到值（讀 r.device 卻存的是 r.iface，
      // 讀 r.distance 卻存的是 r.metric），dst 沿用「網段 遮罩」空白分隔格式（netMaskOf() 既有
      // fallback 分支已支援此格式，不需另外改動下游轉換函式）
      routes.push({
        id: String(id++), type: m[2]==='0.0.0.0'?'default':'static',
        dst: `${m[2]} ${m[3]}`, device: m[1], gateway: m[4],
        distance: m[5]||'1', priority: m[5]||'1', status:'enable',
        blackhole:'disable', comment:'-', vrf:'global', vdom:'global'
      });
    }
    return routes;
  }

  function parseVPN(text) {
    const vpn = [];
    const lines = text.split('\n');

    // Parse best crypto isakmp policy (lowest seq = highest priority)
    let bestP1 = {auth:'psk', enc:'-', hash:'-', dhgrp:'-', lifetime:'86400'};
    let inP1 = false, p1seq = Infinity, curP1 = {};
    for (const line of lines) {
      const mP1 = line.match(/^crypto isakmp policy\s+(\d+)/);
      if (mP1) { inP1=true; const seq=parseInt(mP1[1]); if(seq<p1seq){p1seq=seq;curP1={};} else inP1=false; continue; }
      if (inP1) {
        if (/^\S/.test(line)){inP1=false;bestP1={auth:curP1.auth||'psk',enc:curP1.enc||'-',hash:curP1.hash||'-',dhgrp:curP1.grp||'-',lifetime:curP1.lt||'86400'};continue;}
        const mA=line.match(/^\s+authentication\s+(\S+)/); if(mA)curP1.auth=mA[1]==='pre-share'?'psk':mA[1];
        const mE=line.match(/^\s+encryption\s+(\S+)/); if(mE)curP1.enc=mE[1];
        const mH=line.match(/^\s+hash\s+(\S+)/); if(mH)curP1.hash=mH[1];
        const mG=line.match(/^\s+group\s+(\d+)/); if(mG)curP1.grp='group'+mG[1];
        const mL=line.match(/^\s+lifetime\s+(\d+)/); if(mL)curP1.lt=mL[1];
      }
    }

    // Parse global isakmp settings
    let natTraversal = '-', dpd = '-';
    for (const line of lines) {
      if (/^crypto isakmp nat-traversal\b/.test(line)) natTraversal = 'enable';
      if (/^isakmp keepalive threshold\b/.test(line)) dpd = 'enable';
    }

    // Parse transform-sets: name → esp algorithms
    const xformSets = {};
    for (const line of lines) {
      const mX = line.match(/^crypto ipsec transform-set\s+(\S+)\s+(.+)/);
      if (mX) xformSets[mX[1]] = mX[2].trim();
    }

    // Build aclMap: ACL name → {src, dst} from "access-list NAME permit ip SRC MASK DST MASK"
    const aclMap = {};
    for (const line of lines) {
      const mA = line.match(/^access-list\s+(\S+)\s+(?:extended\s+)?permit\s+ip\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/);
      if (mA) { aclMap[mA[1]] = aclMap[mA[1]] || { src: mA[2]+'/'+mA[3], dst: mA[4]+'/'+mA[5] }; }
    }

    // Parse crypto map entries: keyed by seq (mapName+seq) to avoid peer-collision overwrite
    const mapEntries = {};
    let lastSeqKey = '';
    for (const line of lines) {
      const mPeer = line.match(/^crypto map\s+(\S+)\s+(\d+)\s+set peer\s+(\S+)/);
      if (mPeer) { const k=`${mPeer[1]}-${mPeer[2]}`; lastSeqKey=k; if(!mapEntries[k])mapEntries[k]={name:mPeer[1],seq:mPeer[2],peer:mPeer[3]}; else mapEntries[k].peer=mPeer[3]; continue; }
      const mMatch = line.match(/^crypto map\s+\S+\s+(\d+)\s+match address\s+(\S+)/);
      if (mMatch) { const k=Object.keys(mapEntries).find(x=>x.endsWith('-'+mMatch[1])); if(k)mapEntries[k].acl=mMatch[2]; continue; }
      const mXf = line.match(/^crypto map\s+\S+\s+(\d+)\s+set transform-set\s+(\S+)/);
      if (mXf) { const k=Object.keys(mapEntries).find(x=>x.endsWith('-'+mXf[1])); if(k)mapEntries[k].xform=mXf[2]; continue; }
      const mLt = line.match(/^crypto map\s+\S+\s+(\d+)\s+set security-association lifetime seconds\s+(\d+)/);
      if (mLt) { const k=Object.keys(mapEntries).find(x=>x.endsWith('-'+mLt[1])); if(k)mapEntries[k].p2lt=mLt[2]; continue; }
      const mIkev2 = line.match(/^crypto map\s+\S+\s+(\d+)\s+set ikev(\d)/);
      if (mIkev2) { const k=Object.keys(mapEntries).find(x=>x.endsWith('-'+mIkev2[1])); if(k)mapEntries[k].ikever=mIkev2[2]; continue; }
    }

    // Parse tunnel-groups: peer → {hasPsk, type, defaultGroupPolicy}
    const tunnelGroups = {};
    let inTG = false, curTG = '';
    for (const line of lines) {
      const mTG = line.match(/^tunnel-group\s+(\S+)\s+type\s+(\S+)/);
      if (mTG) { curTG=mTG[1]; tunnelGroups[curTG]={type:mTG[2],hasPsk:false}; inTG=true; continue; }
      const mTGAttr = line.match(/^tunnel-group\s+(\S+)\s+ipsec-attributes/);
      if (mTGAttr) { curTG=mTGAttr[1]; inTG=true; continue; }
      if (inTG) {
        if (/^\S/.test(line)){inTG=false;continue;}
        if (/pre-shared-key/.test(line)&&tunnelGroups[curTG])tunnelGroups[curTG].hasPsk=true;
      }
    }

    // Parse tunnel-group ... general-attributes：peer/name → default-group-policy
    let inTGGen = false, curTGGen = '';
    for (const line of lines) {
      const mTGGen = line.match(/^tunnel-group\s+(\S+)\s+general-attributes/);
      if (mTGGen) { curTGGen=mTGGen[1]; inTGGen=true; continue; }
      if (inTGGen) {
        if (/^\S/.test(line)){inTGGen=false;continue;}
        const mDGP = line.match(/^\s+default-group-policy\s+(\S+)/);
        if (mDGP) { tunnelGroups[curTGGen] = tunnelGroups[curTGGen] || {}; tunnelGroups[curTGGen].defaultGroupPolicy = mDGP[1]; }
      }
    }

    // Build standardAclMap：ACL 名稱 → CIDR 清單，來自 "access-list NAME standard permit NETWORK MASK"
    // （split-tunnel-network-list 參照的是 standard ACL，跟既有 aclMap 認得的 "permit ip SRC MASK DST MASK" 兩段式語法不同，必須是 standard，extended 會被 ASA 靜默 fallback 成 tunnelall）
    const standardAclMap = {};
    for (const line of lines) {
      const mSA = line.match(/^access-list\s+(\S+)\s+standard\s+permit\s+(\S+)\s+(\S+)/);
      if (mSA) { (standardAclMap[mSA[1]] = standardAclMap[mSA[1]] || []).push(`${mSA[2]}/${mSA[3]}`); }
    }

    // Parse group-policy ... attributes：名稱 → {splitTunnelPolicy, aclName}
    const groupPolicies = {};
    let inGP = false, curGP = '';
    for (const line of lines) {
      const mGP = line.match(/^group-policy\s+(\S+)\s+attributes/);
      if (mGP) { curGP=mGP[1]; groupPolicies[curGP]=groupPolicies[curGP]||{}; inGP=true; continue; }
      if (inGP) {
        if (/^\S/.test(line)){inGP=false;continue;}
        const mSTP = line.match(/^\s+split-tunnel-policy\s+(\S+)/); if(mSTP) groupPolicies[curGP].splitTunnelPolicy=mSTP[1];
        const mSTL = line.match(/^\s+split-tunnel-network-list\s+value\s+(\S+)/); if(mSTL) groupPolicies[curGP].aclName=mSTL[1];
      }
    }

    // Build VPN entries — collect unique peers from mapEntries + tunnelGroups
    const peerMap = {}; // peer → best mapEntry
    for (const me of Object.values(mapEntries)) {
      if (me.peer && !peerMap[me.peer]) peerMap[me.peer] = me;
    }
    const allPeers = new Set([...Object.keys(peerMap),...Object.keys(tunnelGroups)]);
    let id = 1;
    for (const peer of allPeers) {
      const me = peerMap[peer] || {};
      const tg = tunnelGroups[peer] || {};
      if (tg.type && !tg.type.includes('ipsec')) continue;
      const xformDesc = me.xform ? (xformSets[me.xform]||me.xform) : '-';
      const p2Proposal = xformDesc !== '-' ? xformDesc : 'esp-aes-256 esp-sha256-hmac';
      const proposal = bestP1.enc!=='-' ? bestP1.enc+'-'+bestP1.hash : '-';
      const acl = me.acl ? (aclMap[me.acl]||null) : null;
      vpn.push({
        id: id++,
        name:  me.name ? `${me.name}@${peer}` : `TG_${peer}`,
        type:  'ipsec-p1',
        remote: peer,
        iface: 'outside',
        ikeVer: me.ikever||'1',
        authMethod: (tg.hasPsk||true) ? 'psk' : 'certificate',
        proposal, dhgrp: bestP1.dhgrp, lifetime: bestP1.lifetime,
        natTraversal, dpd,
        status: 'enable',
        phase2: me.xform ? [{
          name: (me.name||'MAP')+'-P2',
          phase1: peer,
          proposal: p2Proposal,
          lifetime: me.p2lt||'3600',
          pfs: '-', dhgrp: '-',
          localSub:  acl ? acl.src : '-',
          remoteSub: acl ? acl.dst : '-',
          localAddr:'-', remoteAddr:'-', autoNeg:'-', comment:'-',
        }] : [],
      });
    }

    // Build SSL-VPN（AnyConnect remote-access）entries：tunnel-group type remote-access/webvpn → default-group-policy → split-tunnel-network-list → standard ACL CIDR 清單
    for (const [tgName, tg] of Object.entries(tunnelGroups)) {
      if (!tg.type || !/remote-access|webvpn/.test(tg.type)) continue;
      const gp = tg.defaultGroupPolicy ? (groupPolicies[tg.defaultGroupPolicy] || {}) : {};
      const cidrs = gp.aclName ? (standardAclMap[gp.aclName] || []) : [];
      vpn.push({
        id: id++,
        name: `AnyConnect: ${tgName}`,
        type: 'ssl-vpn',
        remote: '-', iface: 'outside', ikeVer: '-', authMethod: 'ssl',
        proposal: '-', dhgrp: '-', lifetime: '-', natTraversal: '-', dpd: '-',
        status: 'enable',
        splitTunnel: cidrs.length ? 'enable' : 'disable',
        splitTunnelRoutingAddr: cidrs.join(', ') || '-',
        phase2: [],
      });
    }
    return vpn;
  }

  function parseUsers(text) {
    const users = [];
    for (const line of text.split('\n')) {
      const m = line.match(/^username\s+(\S+)\s+password\s+\S+(?:\s+encrypted)?\s*(?:privilege\s+(\d+))?/);
      if (!m) continue;
      const priv = parseInt(m[2]||'0');
      users.push({ name:m[1], role:priv>=15?'admin':priv>=5?'operator':'readonly', type:'local', groups:[] });
    }
    return users;
  }

  function parseDhcp(text) {
    const pools = {};
    for (const line of text.split('\n')) {
      const mA = line.match(/^dhcpd address\s+(\S+)-(\S+)\s+(\S+)/);
      if (mA) pools[mA[3]] = { iface:mA[3], start:mA[1], end:mA[2], dns:[] };
      const mD = line.match(/^dhcpd dns\s+(.+)/);
      if (mD) Object.values(pools).forEach(p=>{ p.dns=mD[1].trim().split(/\s+/); });
    }
    return { servers: Object.values(pools).map(p=>({ name:p.iface, iface:p.iface, start:p.start, end:p.end, dns:p.dns.join(','), gateway:'' })), relays: [] };
  }

  function parseDns(text) {
    const servers = [];
    let inGroup = false;
    for (const line of text.split('\n')) {
      if (/^dns server-group/.test(line)) { inGroup=true; continue; }
      if (inGroup && /^\S/.test(line)) inGroup=false;
      if (inGroup) { const m=line.match(/^\s+name-server\s+(\S+)/); if(m) servers.push(m[1]); }
    }
    return { servers, secondaries:[], domain:(text.match(/^dns domain-lookup\s+(\S+)/m)||[])[1]||'',
      proxy:false, proxyRules:[], dnsOverTls:false, cacheSize:'-', static:[] };
  }

  function parseSnmp(text) {
    const hosts = [];
    for (const line of text.split('\n')) {
      const m = line.match(/^snmp-server host\s+(\S+)\s+(\S+)\s+(?:community\s+)?(\S+)/);
      if (m) hosts.push({ host:m[2], iface:m[1], community:m[3], version:'v2c' });
    }
    const globalCommunity = (text.match(/^snmp-server community\s+(\S+)/m)||[])[1]||'';
    const location = (text.match(/^snmp-server location\s+(.+)/m)||[])[1]?.trim()||'';
    const contact = (text.match(/^snmp-server contact\s+(.+)/m)||[])[1]?.trim()||'';
    const commNames = new Set(hosts.map(h=>h.community));
    if (globalCommunity) commNames.add(globalCommunity);
    const communities = [...commNames].map(name => ({ name, permission:'ro', allowedHosts:[], events:'-', status:'enable' }));
    return {
      enabled: communities.length>0,
      agent: { name:'-', description:'-', location, contact, version: hosts.length?['v2c']:[] },
      communities,
      v3users: [],
      trapServers: hosts.map(h=>({ ip:h.host, port:'162', community:h.community, version:h.version }))
    };
  }

  function parseLogServers(text) {
    const servers = [];
    for (const line of text.split('\n')) {
      const m = line.match(/^logging host\s+(\S+)\s+(\S+)(?:\s+(\d+))?/);
      if (m) servers.push({ host:m[2], iface:m[1], port:m[3]||'514', protocol:'udp' });
    }
    return servers;
  }

  // HA/Cluster：已查證官方 Failover 語法——`failover` 單獨一行代表啟用，`failover lan unit
  // primary/secondary` 決定角色，`failover lan interface NAME IFACE` 指定 LAN failover 介面，
  // `failover interface ip NAME PRIMARY_IP MASK standby STANDBY_IP` 指定雙機 IP，
  // `failover group N` 決定 Active/Active 群組（ASA 5500 Active/Active 模式才有）
  function parseHa(text) {
    const result = { enabled:false, mode:'-', groupId:'-', priority:'-', peerIp:'-', syncInterface:'-', vip:'-' };
    if (!/^failover\s*$/m.test(text)) return result;
    result.enabled = true;
    result.mode = /^failover\s+lan\s+unit\s+primary/m.test(text) ? 'primary'
      : /^failover\s+lan\s+unit\s+secondary/m.test(text) ? 'secondary' : '-';
    const lanIfaceM = text.match(/^failover\s+lan\s+interface\s+(\S+)\s+(\S+)/m);
    result.syncInterface = lanIfaceM ? `${lanIfaceM[1]} (${lanIfaceM[2]})` : '-';
    const ifIpM = text.match(/^failover\s+interface\s+ip\s+\S+\s+(\S+)\s+\S+\s+standby\s+(\S+)/m);
    if (ifIpM) { result.vip = ifIpM[1]; result.peerIp = ifIpM[2]; }
    const groupM = text.match(/^failover\s+group\s+(\d+)/m);
    result.groupId = groupM ? groupM[1] : '-';
    return result;
  }

  function parse(text) {
    const addresses = parseAddressObjects(text);
    const addrTypeMap = buildCiscoASAAddrTypeMap(addresses);
    return {
      vendor: 'Cisco ASA',
      deviceInfo:  parseDeviceInfo(text),
      interfaces:  parseInterfaces(text),
      policies:    parsePolicies(text, addrTypeMap),
      addresses,
      services:    parseServiceObjects(text),
      nat:         parseNAT(text),
      routes:      parseRoutes(text),
      vpn:         parseVPN(text),
      users:       parseUsers(text),
      schedules:   [],
      dhcp:        parseDhcp(text),
      dns:         parseDns(text),
      snmp:        parseSnmp(text),
      logServers:  parseLogServers(text),
      sdwan:       null,
      ha:          parseHa(text),
      wwan:        null,
    };
  }

  return { parse };
})();

// ═══ Cisco Firepower/FTD Parser ═══
// FTD 的 show running-config（Lina 引擎）大量重用 ASA 語法（介面/路由/基礎 NAT），
// 故直接重用 CiscoASAParser 既有解析邏輯，僅覆寫 vendor 標籤與韌體版本判斷方式
// （banner 為 "NGFW Version X.X.X"，非 ASA 的 "ASA Version X.X"）。
// ACP（Access Control Policy）/IPS(Snort)/大部分規則由 FMC 或 FDM 圖形化管理，
// 不會出現在 show running-config 裡，故 policies 僅涵蓋 CLI 可見的基礎規則
// （與 ASA 邏輯相同，屬既有 graceful degradation 慣例，非本解析器缺口）。
// 僅支援 show running-config（Lina CLI）格式，不支援 FMC 匯出的 ACP JSON/YAML 格式。
const CiscoFTDParser = (() => {
  function parse(text) {
    const r = CiscoASAParser.parse(text);
    r.vendor = 'Cisco FTD';
    r.deviceInfo.vendor = 'Cisco FTD';
    const fw = (text.match(/^NGFW Version\s+(\S+)/m)||[])[1];
    if (fw) r.deviceInfo.firmware = fw;
    return r;
  }
  return { parse };
})();

