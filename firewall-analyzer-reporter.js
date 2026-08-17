// ═══ reporter.js ═══
/**
 * Firewall Report Generator
 * Outputs: CSV, JSON, HTML Report
 */
const Reporter = (() => {

  // ─── CSV ──────────────────────────────────────────────────────────────────
  function toCSV(rows, headers) {
    const q = v => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
    return [headers, ...rows].map(row => row.map(q).join(',')).join('\r\n');
  }

  function exportCSV(data, section) {
    let headers, rows;
    switch (section) {
      case 'interfaces':
        headers = [tr('col.name'),tr('col.alias'),tr('col.ip'),tr('col.mask'),tr('col.secondaryIp'),tr('col.type'),tr('col.vlan_id'),tr('col.vdom'),tr('col.role'),tr('col.speed'),tr('col.mtu'),tr('col.mac'),tr('col.mode'),tr('col.status'),tr('col.allowaccess'),tr('col.desc')];
        rows = data.map(r => [r.name,r.alias,r.ip,r.mask,(r.secondaryIps&&r.secondaryIps.length)?r.secondaryIps.map(s=>`${s.ip}${s.mask&&s.mask!=='-'?' / '+s.mask:''}`).join('; '):'-',r.type,r.vlanId,r.vdom,r.role,r.speed,r.mtu,r.macaddr,r.mode,r.status,r.allowaccess,r.desc]);
        break;
      case 'policies':
        headers = ['ID',tr('col.name'),tr('col.src_intf'),tr('col.dst_intf'),tr('col.src_addr'),tr('col.dst_addr'),tr('col.service'),tr('col.schedule'),tr('col.action'),'NAT','IP Pool','Pool Name',tr('col.log'),'UTM-AV','UTM-Web','UTM-IPS','UTM-App',tr('col.status'),tr('col.users'),tr('col.groups'),tr('col.comments')];
        rows = data.map(r => [r.id,r.name,r.srcIntf,r.dstIntf,r.srcAddr,r.dstAddr,r.service,r.schedule,r.action,r.nat,r.ippool,r.poolname,r.logtraffic,r.utm.av,r.utm.webfilter,r.utm.ips,r.utm.appctrl,r.status,r.users,r.groups,r.comments]);
        break;
      case 'routes':
        headers = [tr('col.type'),'ID',tr('col.dst'),tr('col.gateway'),tr('col.intf'),tr('col.distance'),tr('col.priority'),tr('col.status'),tr('col.blackhole'),'VRF',tr('col.comment'),tr('col.protocol_detail')];
        rows = data.map(r => [r.type,r.id,r.dst,r.gateway,r.device,r.distance,r.priority,r.status,r.blackhole||'-',r.vrf||'-',r.comment,r.protocol_detail||'-']);
        break;
      case 'vpn':
        headers = [tr('col.type'),tr('col.name'),tr('col.remote_gw'),tr('col.intf'),tr('col.ike_ver'),tr('col.auth_method'),tr('col.proposal'),tr('col.dhgrp'),tr('col.lifetime'),tr('col.nat_traversal'),'DPD',tr('col.local_id'),tr('col.peer_id'),tr('col.cert'),tr('col.status')];
        rows = data.map(r => [r.type,r.name,r.remote,r.iface,r.ikeVer,r.authMethod,r.proposal,r.dhgrp,r.lifetime,r.natTraversal||'-',r.dpd||'-',r.localId||'-',r.peerId||'-',r.cert||'-',r.status]);
        break;
      case 'vpn-phase2':
        const ph2rows = [];
        data.filter(v => v.phase2 && v.phase2.length).forEach(v => {
          v.phase2.forEach(p => {
            ph2rows.push([v.name,p.name,p.proposal,p.pfs,p.dhgrp,p.lifetime,p.localSub,p.remoteSub,p.autoNeg||'-',p.comment||'-']);
          });
        });
        headers = [tr('col.ph1_name'),tr('col.ph2_name'),tr('col.proposal'),tr('col.pfs'),tr('col.dhgrp'),tr('col.lifetime'),tr('col.local_sub'),tr('col.remote_sub'),tr('col.auto_neg'),tr('col.comment')];
        rows = ph2rows;
        break;
      // unused-addr/unused-svc（Audit 未使用物件分析）直接沿用 addresses/services 既有
      // 形狀（analyzeUnusedObjects() 是從同一份 addresses/services 陣列篩選出未使用的
      // 項目，非另建新形狀），故用 fallthrough 共用同一組 headers/rows 邏輯
      case 'unused-addr':
      case 'addresses':
        headers = [tr('col.category'),tr('col.name'),tr('col.type'),tr('col.subnet_range'),'FQDN',tr('col.start_ip'),tr('col.end_ip'),tr('col.members'),tr('col.intf'),tr('col.comment')];
        rows = data.map(r => [r.category,r.name,r.type,r.subnet||'-',r.fqdn||'-',r.startIp||'-',r.endIp||'-',r.members||'-',r.iface||'-',r.comment]);
        break;
      case 'unused-svc':
      case 'services':
        headers = [tr('col.category'),tr('col.name'),tr('col.proto'),'TCP Port','UDP Port','ICMP Type','ICMP Code',tr('col.members'),tr('col.comment')];
        rows = data.map(r => [r.category,r.name,r.proto,r.tcpPorts||'-',r.udpPorts||'-',r.icmpType||'-',r.icmpCode||'-',r.members||'-',r.comment]);
        break;
      // shadow/compliance（Audit 分析結果，固定欄位形狀跨廠牌一致，因運作在正規化後的
      // PARSED 模型上）
      case 'shadow':
        headers = [tr('audit.col_tier'),tr('audit.col_shadowed_id'),tr('audit.col_shadowed_name'),tr('audit.col_shadow_id'),tr('audit.col_shadow_name'),tr('audit.col_reason')];
        rows = data.map(r => [r.tier,r.shadowedId,r.shadowedName,r.shadowingId,r.shadowingName,r.reason]);
        break;
      case 'merge-suggest':
        headers = [tr('audit.col_merge_field'),tr('audit.col_merge_ids'),tr('audit.col_merge_values'),tr('audit.col_merge_count')];
        rows = data.map(r => [tr(({srcAddr:'col.src_addr',dstAddr:'col.dst_addr',service:'col.service'})[r.field]),r.ids.join(';'),r.values.join(';'),r.count]);
        break;
      case 'compliance':
        headers = [tr('audit.col_check'),tr('audit.col_result'),tr('audit.col_risk'),tr('audit.col_detail'),tr('audit.col_standards')];
        rows = data.map(r => [r.check,r.value,r.risk,r.detail,(r.standards||[]).join('; ')]);
        break;
      case 'users':
        headers = [tr('col.type'),tr('col.name'),tr('col.status'),tr('col.auth_method'),'Email',tr('col.two_factor'),tr('col.ldap_server'),tr('col.radius_server'),tr('col.members'),tr('col.comment')];
        rows = data.map(r => [r.type,r.name,r.status,r.authType||r.groupType||'-',r.email||'-',r.twoFactor||'-',r.ldapServer||r.server||'-',r.radiusServer||'-',r.members||'-',r.comment]);
        break;
      case 'nat':
        headers = [tr('col.type'),tr('col.name'),tr('col.sub_type'),tr('col.ext_ip'),tr('col.ext_intf'),tr('col.map_ip'),tr('col.port_fwd'),tr('col.ext_port'),tr('col.map_port'),tr('col.proto'),tr('col.status'),tr('col.comment')];
        rows = data.map(r => [r.type,r.name,r.vipType||r.poolType||'-',r.extIp||r.startIp||'-',r.extIntf||r.srcIntf||'-',r.mapIp||r.endIp||'-',r.portFwd||'-',r.extPort||'-',r.mapPort||'-',r.proto||'-',r.status||'-',r.comment]);
        break;
      case 'schedules':
        headers = [tr('col.type'),tr('col.name'),tr('col.start'),tr('col.end'),tr('col.weekday')];
        rows = data.map(r => [r.type,r.name,r.start,r.end,r.day||'-']);
        break;
      case 'wifi-ssid':
        // data = wifiData.vaps
        headers = [tr('wifi.ssid_name'),tr('wifi.vap_name'),tr('wifi.sec_mode'),tr('wifi.sec_grade_detail'),tr('wifi.score_col'),'Captive Portal',
                   tr('wifi.broadcast_ssid'),'PMF(802.11w)','Intra-VAP Privacy','VLAN ID',tr('wifi.local_bridging'),
                   tr('wifi.user_groups'),tr('wifi.addr_groups'),tr('col.schedule'),tr('wifi.ap_deploy'),tr('wifi.issue_col')];
        rows = data.map(r => [
          r.ssid, r.name, r.security,
          r.secGrade || '-', r.secScore != null ? r.secScore : '-',
          r.captivePortal ? tr('wifi.yes') : tr('wifi.no'),
          r.broadcastSsid ? tr('wifi.yes') : tr('wifi.no_hidden'),
          r.pmf || '-',
          r.intraVapPrivacy ? tr('wifi.yes') : tr('wifi.no'),
          r.vlanId || '-', r.localBridging || '-',
          r.userGroups || '-', r.addrGroup || '-', r.schedule || '-',
          r.deployedOnAps != null ? r.deployedOnAps : '-',
          (r.secIssues || []).map(i => '[' + i.level.toUpperCase() + '] ' + i.msg).join('; ') || tr('wifi.no')
        ]);
        break;
      case 'wifi-ap':
        // data = wifiData.wtps (AP instances) combined with profile info
        headers = [tr('wifi.col_serial'),tr('col.name'),tr('wifi.col_location'),tr('wifi.col_profile'),tr('wifi.ap_platform'),tr('wifi.wifi_gen'),
                   '2.4GHz','5GHz',tr('wifi.monitor_radio'),tr('wifi.handoff_thresh'),tr('col.status')];
        rows = data.map(r => [
          r.serial, r.name, r.location || '-', r.profile,
          r.platform || '-', r.wifiGen || '-',
          r.has2G ? tr('wifi.yes') : tr('wifi.no'), r.has5G ? tr('wifi.yes') : tr('wifi.no'),
          r.hasMonitor ? tr('wifi.yes') : tr('wifi.no'),
          r.handoffThresh || '-',
          r.admin || r.status || '-'
        ]);
        break;
      case 'wifi-profile':
        // data = wifiData.wtpProfiles
        headers = [tr('wifi.col_profile'),tr('wifi.ap_platform'),tr('wifi.wifi_gen'),'2.4GHz','5GHz',tr('wifi.monitor_radio'),
                   'Radio1 Band','Radio1 VAPs','Radio2 Band','Radio2 VAPs'];
        rows = data.map(r => {
          const r1 = r.radios && r.radios[0] ? r.radios[0] : {};
          const r2 = r.radios && r.radios[1] ? r.radios[1] : {};
          return [
            r.name, r.platform, r.wifiGen,
            r.has2G ? tr('wifi.yes') : tr('wifi.no'), r.has5G ? tr('wifi.yes') : tr('wifi.no'),
            r.hasMonitor ? tr('wifi.yes') : tr('wifi.no'),
            r1.band || '-', (r1.vaps || []).join('; ') || '-',
            r2.band || '-', (r2.vaps || []).join('; ') || '-',
          ];
        });
        break;
      case 'dhcp-servers':
        headers = [tr('col.name'),tr('col.intf'),tr('col.start_ip'),tr('col.end_ip'),tr('col.gateway'),tr('col.mask'),'DNS 1','DNS 2',tr('col.domain'),tr('col.lease'),tr('col.status'),tr('col.comment')];
        rows = data.map(r => [r.name,r.iface,r.startIp,r.endIp,r.gateway,r.mask,r.dns1,r.dns2,r.domain,r.lease,r.status,r.comment]);
        break;
      case 'dhcp-relays':
        headers = [tr('col.name'),tr('col.intf'),tr('dhcp.relay_server'),tr('col.status'),tr('col.comment')];
        rows = data.map(r => [r.name,r.iface,r.serverIp,r.status,r.comment]);
        break;
      case 'sdwan-members':
        headers = ['ID',tr('sdwan.col_iface'),'Zone',tr('sdwan.col_gw'),tr('sdwan.col_gw6'),tr('sdwan.col_prio'),tr('sdwan.mode_weight'),tr('sdwan.col_cost'),tr('sdwan.link_cost'),tr('sdwan.link_status'),tr('sdwan.auto_failback'),tr('sdwan.source_ip'),tr('sdwan.col_spillover'),tr('col.status'),tr('col.comment')];
        rows = data.map(r => [r.id,r.iface,r.zone,r.gateway,r.gateway6,r.priority,r.weight,r.cost,r.linkCost||0,r.linkStatus,r.autoFailback,r.sourceIp,r.spillover||0,r.status,r.comment]);
        break;
      case 'sdwan-health':
        headers = [tr('col.name'),tr('sdwan.col_server'),tr('col.protocol'),'Port',tr('sdwan.col_interval'),'Timeout',tr('sdwan.col_fail'),tr('sdwan.col_restore'),tr('sdwan.detect_mode'),tr('sdwan.password'),tr('sdwan.threshold'),tr('sdwan.col_monitor'),tr('sdwan.col_sla')];
        rows = data.map(r => [r.name,r.server,r.protocol,r.port,r.interval,r.timeout,r.failtime,r.recoverytime,r.detectMode||'active',r.passwordAuth,r.threshold,r.members,(r.slaThresholds||[]).map(s=>`SLA-${s.id}: L<=${s.latency}ms J<=${s.jitter}ms PL<=${s.packetLoss}%`).join(' | ')||'-']);
        break;
      case 'sdwan-services':
        headers = ['#',tr('col.name'),tr('sdwan.col_mode'),tr('sdwan.col_src'),tr('sdwan.col_dst'),tr('col.protocol'),tr('sdwan.route_tag'),tr('sdwan.bandwidth_min'),tr('sdwan.bandwidth_max'),tr('sdwan.application'),tr('sdwan.groups'),tr('sdwan.col_pref'),tr('sdwan.col_sla_ref'),tr('col.status'),tr('col.comment')];
        rows = data.map(r => [r.id,r.name,r.mode,r.src,r.dst,r.protocol==='0'?'any':r.protocol,r.routeTag,r.minBandwidth,r.maxBandwidth,r.application,r.groups,r.priorityZone!=='-'?r.priorityZone:r.priorityMembers,(r.slaRefs||[]).length?r.slaRefs.map(x=>`${x.healthCheck}#${x.id}`).join(', '):'-',r.status,r.comment]);
        break;
      case 'sdwan-zones':
        headers = [tr('sdwan.col_zone_name'),'VDOM'];
        rows = data.map(r => [r.name,r._vdom||'-']);
        break;
      case 'sdwan-neighbors':
        headers = ['IP','Member',tr('sdwan.col_role'),'VDOM'];
        rows = data.map(r => [r.ip,r.member,r.role,r._vdom||'-']);
        break;
      case 'ha':
        headers = [tr('ha.mode'),tr('ha.group_id'),tr('ha.priority'),tr('ha.peer_ip'),tr('ha.sync_interface'),tr('ha.vip')];
        rows = data.map(r => [r.mode,r.groupId,r.priority,r.peerIp,r.syncInterface,r.vip]);
        break;
      case 'dns-servers':
        headers = [tr('col.ip'),tr('col.type')];
        rows = data.map(r => [r.ip,r.kind]);
        break;
      case 'dns-proxy':
        headers = [tr('col.domain'),tr('dns.fwd_target')];
        rows = data.map(r => [r.domain,r.target]);
        break;
      case 'dns-static':
        headers = [tr('dns.col_host'),tr('dns.col_type'),tr('dns.col_ip_target'),tr('dns.col_zone_name')];
        rows = data.map(r => [r.name,r.type||'A',r.ip,r.zone||'-']);
        break;
      case 'snmp-agent':
        headers = [tr('snmp.agent_name'),tr('snmp.contact'),tr('snmp.location'),tr('snmp.desc'),tr('snmp.col_version')];
        rows = data.map(r => [r.name,r.contact,r.location,r.description,(r.version||[]).join('/')]);
        break;
      case 'snmp-communities':
        headers = [tr('snmp.col_community'),tr('snmp.col_perm'),tr('snmp.col_hosts'),tr('snmp.col_events'),tr('col.status')];
        rows = data.map(r => [r.name,r.permission,(r.allowedHosts||[]).filter(h=>h&&h!=='-').join(', ')||'any',r.events||'-',r.status]);
        break;
      case 'snmp-v3users':
        headers = [tr('snmp.col_user'),tr('snmp.col_sec_level'),tr('snmp.col_auth_proto'),tr('snmp.col_priv_proto'),tr('snmp.col_notify'),tr('col.status')];
        rows = data.map(r => [r.name,r.secLevel,r.authProto,r.privProto,r.notifyHost||'-',r.status]);
        break;
      case 'snmp-traps':
        headers = [tr('snmp.col_ip'),'Port','Community',tr('snmp.col_version')];
        rows = data.map(r => [r.ip,r.port||'162',r.community||'-',r.version||'v2c']);
        break;
      case 'log-syslog':
        headers = [tr('col.name'),'Server IP','Port',tr('log.col_facility'),tr('log.col_format'),'Protocol',tr('log.col_level'),tr('col.status')];
        rows = data.map(r => [r.name,r.server,r.port||'514',r.facility||'local7',r.format||'default',r.protocol,r.level||'-',r.status]);
        break;
      case 'log-fortianalyzer':
        headers = [tr('col.name'),'Server IP','Port',tr('log.col_reliable'),tr('log.col_encrypt'),tr('col.status')];
        rows = data.map(r => [r.name,r.server,r.port||'514',r.reliable,r.encAlgo||'-',r.status]);
        break;
      case 'log-netflow':
        headers = ['Collector IP','Port',tr('log.col_timeout'),tr('col.status')];
        rows = data.map(r => [r.collector,r.port||'2055',r.activeTimeout||'60',r.status]);
        break;
      case 'log-forward':
        headers = [tr('col.name'),tr('popup.col_type'),tr('log.col_target')];
        rows = data.map(r => [r.name,r.type||'-',r.target||'-']);
        break;
      case 'wwan-profiles':
        headers = [tr('wwan.col_profile_name'),'APN',tr('wwan.col_auth'),tr('wwan.col_user'),tr('wwan.col_modem'),tr('wwan.col_simpin'),tr('wwan.col_carrier'),tr('wwan.col_dataplan'),'VDOM'];
        rows = data.map(r => [r.name,r.apn,r.authType,r.username,r.modemId,r.simPin,r.provider,r.dataplan,r._vdom||'-']);
        break;
      case 'wwan-lte-iface':
        headers = [tr('col.name'),tr('wwan.col_apn_profile'),tr('wwan.col_roaming'),tr('col.status'),tr('wwan.col_note')];
        rows = data.map(r => [r.name,r.apnProfile,r.allowRoaming,r.disabled==='yes'?'disable':'enable',r.comment]);
        break;
      case 'wwan-apn-profiles':
        headers = [tr('wwan.col_apn_name'),'APN',tr('wwan.col_auth'),tr('wwan.col_user'),tr('wwan.col_password'),tr('wwan.col_ip_type'),tr('wwan.col_distance')];
        rows = data.map(r => [r.name,r.apn,r.authType,r.username,r.passwd,r.ipType,r.distance]);
        break;
      case 'wwan-5g-modem':
        headers = ['Modem','APN',tr('wwan.col_carrier'),tr('wwan.col_auth'),tr('wwan.col_user'),tr('wwan.col_sim1pin'),tr('wwan.col_sim2pin'),tr('wwan.col_prefer_sim'),tr('wwan.col_iface')];
        rows = data.map(r => [r.slot,r.apn,r.apnProvider,r.authType,r.username,r.sim1Pin,r.sim2Pin,r.preferSim,r.interface]);
        break;
      case 'wwan-lte-modem':
        headers = [tr('col.status'),tr('wwan.col_port'),'APN',tr('wwan.col_auth'),tr('wwan.col_autoswitch')];
        rows = data.map(r => [r.status,r.modemPort,r.apn,r.authType,r.autoSwitch]);
        break;
      case 'wlan-interfaces':
        headers = [tr('col.name'),'SSID',tr('col.wifi_band'),tr('col.mode'),tr('col.wifi_freq'),tr('col.wifi_chan_width'),tr('col.wifi_country'),tr('col.wifi_sec_profile'),tr('col.wifi_auth'),tr('col.wifi_key'),tr('col.status'),tr('col.desc')];
        rows = data.map(r => [r.name,r.ssid,r.band,r.mode,r.frequency,r.channelWidth,r.country,r.secProfile,r.authTypes,r.hasKey?'set':'not-set',r.disabled==='yes'?'disable':'enable',r.comment]);
        break;
      case 'wlan-capsman':
        headers = [tr('wifi.config_name'),'SSID',tr('col.wifi_band'),tr('col.wifi_auth'),tr('col.wifi_key')];
        rows = data.map(r => [r.name,r.ssid,r.band,r.authTypes,r.hasKey?'set':'not-set']);
        break;
      case 'fortiswitch-switches':
        headers = [tr('col.fsw_switch_id'),tr('col.fsw_serial'),tr('col.desc'),tr('col.fsw_fortilink_peer'),tr('col.fsw_admin'),tr('col.fsw_port_count')];
        rows = data.map(r => [r.switchId,r.sn!=='-'?r.sn:r.switchId,r.description!=='-'?r.description:'-',r.fsw1Peer,r.fsw1Admin,r.portCount]);
        break;
      case 'fortiswitch-ports':
        headers = [tr('fsw.col_switch'),tr('col.name'),tr('col.desc'),tr('col.fsw_vlan'),tr('col.fsw_native_vlan'),tr('col.fsw_allowed_vlans'),tr('col.fsw_nac_vlan'),tr('col.fsw_poe'),tr('col.fsw_speed'),tr('col.status'),tr('col.fsw_stp'),tr('col.fsw_loop_guard'),tr('col.fsw_port_security'),tr('col.fsw_poe_capable'),tr('col.fsw_mac_addr'),tr('col.fsw_export_to')];
        rows = data.map(r => [r.switchId,r.name,r.description!=='-'?r.description:'-',r.vlan,r.nativeVlan,r.allowedVlans,r.nacVlan,r.poeStatus,r.speed,r.status,r.stpState,r.loopGuard,r.portSecurityPolicy,r.poeCapable,r.macAddr,r.exportTo]);
        break;
      case 'fortiswitch-mac-policies':
        headers = [tr('col.name'),tr('col.fsw_vlan'),tr('col.desc')];
        rows = data.map(r => [r.name,r.vlan,r.description!=='-'?r.description:'-']);
        break;
      case 'fortiswitch-nac-policies':
        headers = [tr('col.name'),tr('col.np_category'),tr('col.os'),tr('col.np_switch_mac_policy')];
        rows = data.map(r => [r.name,r.category,r.os,r.switchMacPolicy]);
        break;
      default:
        return null;
    }
    return toCSV(rows, headers);
  }

  // Zone Matrix：欄位是執行期動態決定的 zone 清單（非固定欄位形狀），不透過上面
  // exportCSV(data,section) 的固定 switch，故獨立成一個匯出函式；矩陣計算邏輯比照
  // buildZoneMatrixHtml() 既有作法（兩處分別維護，避免耦合 HTML 渲染與 CSV 匯出）
  function exportZoneMatrixCSV(policies) {
    const pols = (policies||[]).filter(p => p.srcIntf && p.srcIntf!=='-' && p.dstIntf && p.dstIntf!=='-');
    if (!pols.length) return null;
    const zones = [...new Set([...pols.map(p=>p.srcIntf), ...pols.map(p=>p.dstIntf)])].sort();
    if (zones.length > 20) return null;
    const mx = {};
    zones.forEach(z => { mx[z]={}; zones.forEach(d => { mx[z][d]={a:0,n:0}; }); });
    pols.forEach(p => { const s=p.srcIntf,d=p.dstIntf; if (mx[s]&&mx[s][d]!==undefined) { if (p.action==='accept') mx[s][d].a++; else mx[s][d].n++; } });
    const headers = [`${tr('audit.zone_src')}\\${tr('audit.zone_dst')}`, ...zones];
    const rows = zones.map(s => [s, ...zones.map(d => `${mx[s][d].a}/${mx[s][d].n}`)]);
    return toCSV(rows, headers);
  }

  // Query Trace：只匯出畫面上目前這一次查詢的結果（非歷史批次，因 _runQuery() 本身
  // 就只保留最近一次），resolved 巢狀欄位攤平成獨立字串欄位
  function exportQueryTraceCSV(q) {
    if (!q || !q.trace || !q.trace.length) return null;
    const headers = ['#','ID',tr('col.name'),'Src Addr','Dst Addr',tr('col.action'),tr('col.status'),'Resolved Src','Resolved Dst'];
    const rows = q.trace.map((t,i) => [
      i+1, t.policy.id, t.policy.name, t.policy.srcAddr, t.policy.dstAddr,
      t.policy.action==='accept'?'ACCEPT':'DENY', t.result,
      t.resolvedSrc?t.resolvedSrc.display:'', t.resolvedDst?t.resolvedDst.display:'',
    ]);
    return toCSV(rows, headers);
  }

  // 新舊設定檔比對：added/removed/changed 攤平成單一表格，四種實體型別共用同一欄位形狀
  function exportDiffCSV(result) {
    if (!result) return null;
    const total = result.added.length + result.removed.length + result.changed.length;
    if (!total) return null;
    const headers = [tr('diff.col_status'), tr('diff.col_key'), tr('diff.col_changed_fields')];
    const label = item => item.name || (item.dst !== undefined ? `${item.dst} -> ${item.gateway || '-'} (${item.device || '-'})` : (item.id !== undefined ? String(item.id) : '-'));
    const rows = [
      ...result.added.map(item => [tr('diff.status_added'), label(item), '-']),
      ...result.removed.map(item => [tr('diff.status_removed'), label(item), '-']),
      ...result.changed.map(c => [tr('diff.status_changed'), label(c.new), c.diffFields.join('; ')]),
    ];
    return toCSV(rows, headers);
  }

  // ─── JSON ─────────────────────────────────────────────────────────────────
  function exportJSON(parsed) {
    return JSON.stringify(parsed, null, 2);
  }

  // ─── HTML Report ──────────────────────────────────────────────────────────
  const REPORT_CSS_FW=`*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Noto Sans TC',system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;font-size:13px;padding:32px}
h1{font-size:24px;font-weight:700;background:linear-gradient(90deg,#00d4ff,#fff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:4px}
h2{font-size:17px;color:#00d4ff;margin-bottom:12px;border-left:4px solid #00d4ff;padding-left:10px}
h3{font-size:14px;color:#94a3b8;margin:10px 0 6px;font-weight:600}
.wrap{max-width:1200px;margin:0 auto}
.subtitle{color:#64748b;font-size:12px;margin-bottom:32px;font-family:monospace}
.section{margin-bottom:40px}
.section-title{font-size:15px;font-weight:700;color:#00d4ff;margin-bottom:12px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #1e3a5f;padding-bottom:8px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:32px}
.stat-card{background:#111827;border-radius:10px;padding:16px;border:1px solid #1e3a5f}
.stat-link{cursor:pointer;transition:opacity .15s,transform .15s}.stat-link:hover{opacity:.8;transform:translateY(-2px)}
.stat-num{font-size:28px;font-weight:700;font-family:monospace}
.stat-lbl{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.card{background:#111827;border-radius:8px;padding:20px;margin-bottom:20px;border:1px solid #1e3a5f}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:16px}
.meta-item{background:#0d1117;border:1px solid #1e3a5f;border-radius:6px;padding:10px 14px}
.meta-label{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#64748b;font-weight:600}
.meta-value{font-size:16px;font-weight:700;color:#e2e8f0;margin-top:2px;font-family:monospace;word-break:break-word}
table{width:100%;border-collapse:collapse;background:#111827;border-radius:8px;overflow:hidden;border:1px solid #1e3a5f}
th{background:#1a2235;padding:10px 14px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:#64748b;border-bottom:1px solid #1e3a5f;white-space:nowrap;-webkit-print-color-adjust:exact;print-color-adjust:exact}
td{padding:9px 14px;border-bottom:1px solid rgba(30,58,95,.4);vertical-align:middle;max-width:300px;word-break:break-all}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(0,212,255,.03)}
td:first-child,th:first-child{padding-left:16px}
.mono{font-family:'Courier New',monospace;font-size:12px}
.badge{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-family:monospace;font-weight:600}
.badge-allow{background:rgba(16,185,129,.15);color:#10b981}
.badge-deny{background:rgba(239,68,68,.15);color:#ef4444}
.badge-warn{background:rgba(217,119,6,.15);color:#d97706}
.badge-info{background:rgba(14,165,233,.15);color:#0ea5e9}
.badge-on{background:rgba(16,185,129,.1);color:#6ee7b7}
.badge-off{background:rgba(100,116,139,.15);color:#64748b}
.up{color:#10b981;font-weight:700}.down{color:#ef4444;font-weight:700}
.empty{text-align:center;color:#475569;font-style:italic;padding:16px 0}
.info-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:32px}
.info-item{background:#111827;border:1px solid #1e3a5f;border-radius:8px;padding:12px 16px}
.info-item .k{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.info-item .v{font-family:monospace;color:#e2e8f0;font-size:13px;word-break:break-word;overflow-wrap:break-word}
.overflow{overflow-x:auto}
b{font-weight:600}small{color:#64748b;font-size:11px}
@media print{body{background:#fff;color:#000}table{border:1px solid #ccc}th{background:#f5f5f5;color:#333;-webkit-print-color-adjust:exact;print-color-adjust:exact}td{border-bottom:1px solid #eee}.badge-allow{background:#d1fae5;color:#065f46}.badge-deny{background:#fee2e2;color:#991b1b}@page{margin:1.5cm}}`;

  function exportHTML(parsed, wifiData) {
    const vendor = parsed.vendor;
    const info   = parsed.deviceInfo;
    const now    = new Date().toLocaleString(_lang==='ja'?'ja-JP':_lang==='en'?'en-US':'zh-TW');
    // 設定檔內容（規則名稱/介面說明/物件備註等管理者可自由輸入的欄位）在組 HTML 報表時
    // 必須跳脫，否則含 < 等字元會破壞表格結構，畸形/惡意內容甚至可在報表於瀏覽器開啟時
    // 執行任意 JS。本函式後段的 WiFi 區塊（buildWifiSection）已有自己的 esc2()，但最早、
    // 也最核心的 policies/interfaces/routes/vpn/addresses/users 等區塊先前完全遺漏，
    // 這裡補上共用的 esc()。
    const esc = v => String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

    const stat = (label, val, color, sid='') =>
      `<div class="stat-card${sid?' stat-link':''}" style="border-top:3px solid ${color}"${sid?` onclick="document.getElementById('${sid}').scrollIntoView({behavior:'smooth'})" title="${label}"`:''}">
        <div class="stat-num" style="color:${color}">${val}</div>
        <div class="stat-lbl">${label}</div>
      </div>`;

    const policyRows = parsed.policies.map(p =>
      `<tr>
        <td>${esc(p.id)}</td><td>${esc(p.name)}</td>
        <td>${esc(p.srcIntf)}</td><td>${esc(p.dstIntf)}</td>
        <td>${esc(p.srcAddr)}</td><td>${esc(p.dstAddr)}</td>
        <td>${esc(p.service)}</td>
        <td><span class="badge ${p.action==='accept'?'badge-allow':'badge-deny'}">${esc(p.action.toUpperCase())}</span></td>
        <td>${esc(p.nat)}</td>
        <td><span class="badge ${p.status==='enable'||p.status==='Enable'?'badge-on':'badge-off'}">${esc(p.status)}</span></td>
        <td>${esc(p.comments)}</td>
      </tr>`).join('');

    const ifaceRows = parsed.interfaces.map(i =>
      `<tr>
        <td><b>${esc(i.name)}</b></td><td>${esc(i.alias)}</td>
        <td>${esc(i.ip)}</td><td>${esc(i.mask)}</td>
        <td>${esc(i.type)}</td><td>${esc(i.vlanId)}</td>
        <td><span class="badge" style="background:#334155;color:#94a3b8">${esc(i.role)}</span></td>
        <td>${esc(i.status)}</td><td>${esc(i.desc)}</td>
      </tr>`).join('');

    const routeRows = parsed.routes.map(r =>
      `<tr>
        <td><span class="badge" style="background:#1e3a5f;color:#7dd3fc">${esc(r.type.toUpperCase())}</span></td>
        <td>${esc(r.dst)}</td><td>${esc(r.gateway)}</td><td>${esc(r.device)}</td>
        <td>${esc(r.distance)}</td><td>${esc(r.status)}</td><td>${esc(r.comment)}</td>
      </tr>`).join('');

    const vpnRows = parsed.vpn.map(v =>
      `<tr>
        <td><span class="badge" style="background:#1e1b4b;color:#a78bfa">${esc(v.type)}</span></td>
        <td><b>${esc(v.name)}</b></td><td>${esc(v.remote)}</td><td>${esc(v.iface)}</td>
        <td>${esc(v.ikeVer)}</td><td>${esc(v.authMethod)}</td><td>${esc(v.proposal)}</td>
        <td>${esc(v.dhgrp)}</td><td>${esc(v.status)}</td>
      </tr>`).join('');

    const ph2Rows = parsed.vpn.filter(v => v.phase2 && v.phase2.length).flatMap(v =>
      v.phase2.map(p =>
        `<tr>
          <td>${esc(v.name)}</td><td>${esc(p.name)}</td><td>${esc(p.proposal)}</td>
          <td>${esc(p.dhgrp)}</td><td>${esc(p.lifetime)}</td>
          <td>${esc(p.localSub)}</td><td>${esc(p.remoteSub)}</td>
        </tr>`)
    ).join('');

    const addrRows = parsed.addresses.slice(0, 200).map(a =>
      `<tr>
        <td><span class="badge" style="background:#0f2027;color:#38bdf8">${esc(a.category)}</span></td>
        <td>${esc(a.name)}</td><td>${esc(a.type)}</td>
        <td>${esc(a.subnet||a.startIp+' ~ '+a.endIp||a.fqdn||'-')}</td>
        <td>${esc(a.members||'-')}</td><td>${esc(a.comment)}</td>
      </tr>`).join('');

    const userRows = parsed.users.map(u =>
      `<tr>
        <td><span class="badge" style="background:#0f2027;color:#34d399">${esc(u.type)}</span></td>
        <td>${esc(u.name)}</td><td>${esc(u.status)}</td>
        <td>${esc(u.authType||u.groupType||'-')}</td>
        <td>${esc(u.members||'-')}</td><td>${esc(u.email||u.server||'-')}</td>
      </tr>`).join('');

    // SD-WAN section for exportHTML
    const sdwanSection = (() => {
      const sd = parsed.sdwan;
      if(!sd||!sd.enabled) return '';
      const modeLabel={'source-ip-based':tr('sdwan.mode_src_ip'),'weight-based':tr('sdwan.mode_weight'),'usage-based':tr('sdwan.mode_usage'),'measured-volume-based':tr('sdwan.mode_volume'),'auto':tr('sdwan.mode_auto')};
      let h='<div class="section"><div class="section-title">🔀 SD-WAN</div>';
      h+=`<p style="margin-bottom:12px;font-size:12px;color:#94a3b8">${tr('sdwan.lb_mode_label')}：${modeLabel[sd.lbMode]||sd.lbMode} | ${tr('sdwan.wan_links_label')}：${sd.members.length} | ${tr('sdwan.sla_probes_label')}：${sd.healthChecks.length} | ${tr('sdwan.rules_label')}：${sd.services.length}</p>`;
      // Members
      h+=`<div style="font-size:11px;font-weight:600;color:#7dd3fc;margin-bottom:6px">${tr('sdwan.members_title')}</div><div class="overflow"><table>`;
      h+=`<thead><tr><th>ID</th><th>${tr('col.intf')}</th><th>Zone</th><th>${tr('col.gateway')}</th><th>${tr('col.priority')}</th><th>${tr('sdwan.col_weight')}</th><th>Cost</th><th>${tr('col.status')}</th><th>${tr('col.comment')}</th></tr></thead><tbody>`;
      sd.members.forEach(m=>{ h+=`<tr><td>${esc(m.id)}</td><td><b>${esc(m.iface)}</b></td><td>${esc(m.zone)}</td><td>${esc(m.gateway)}</td><td>${esc(m.priority)}</td><td>${esc(m.weight)}</td><td>${esc(m.cost)}</td><td>${esc(m.status)}</td><td>${esc(m.comment)}</td></tr>`; });
      h+='</tbody></table></div>';
      // Health Checks
      h+=`<div style="font-size:11px;font-weight:600;color:#fbbf24;margin-bottom:6px;margin-top:12px">${tr('sdwan.health_title')}</div><div class="overflow"><table>`;
      h+=`<thead><tr><th>${tr('col.name')}</th><th>${tr('sdwan.col_server')}</th><th>${tr('col.proto')}</th><th>${tr('sdwan.col_interval')}</th><th>Failtime</th><th>${tr('sdwan.col_members')}</th><th>SLA</th></tr></thead><tbody>`;
      sd.healthChecks.forEach(hc=>{ const sla=esc(hc.slaThresholds.map(s=>`L≤${s.latency} J≤${s.jitter} PL≤${s.packetLoss}%`).join('; ')||'-'); h+=`<tr><td><b>${esc(hc.name)}</b></td><td>${esc(hc.server)}</td><td>${esc(hc.protocol)}</td><td>${esc(hc.interval)}ms</td><td>${esc(hc.failtime)}</td><td>${esc(hc.members)}</td><td style="font-size:11px">${sla}</td></tr>`; });
      h+='</tbody></table></div>';
      // Rules
      h+=`<div style="font-size:11px;font-weight:600;color:#4ade80;margin-bottom:6px;margin-top:12px">${tr('sdwan.rules_title')}</div><div class="overflow"><table>`;
      h+=`<thead><tr><th>#</th><th>${tr('col.name')}</th><th>${tr('col.mode')}</th><th>${tr('sdwan.col_src')}</th><th>${tr('sdwan.col_dst')}</th><th>${tr('sdwan.col_priority_zone')}</th><th>SLA</th><th>${tr('col.status')}</th></tr></thead><tbody>`;
      sd.services.forEach(s=>{ const sla=esc(s.slaRefs.map(r=>r.healthCheck+'#'+r.id).join(', ')||'-'); const tgt=esc(s.priorityZone!=='-'?s.priorityZone:s.priorityMembers); h+=`<tr><td>${esc(s.id)}</td><td><b>${esc(s.name)}</b></td><td>${esc(s.mode)}</td><td>${esc(s.src)}</td><td>${esc(s.dst)}</td><td>${tgt}</td><td style="font-size:11px">${sla}</td><td>${esc(s.status)}</td></tr>`; });
      h+='</tbody></table></div></div>';
      return h;
    })();

    const haSection = (() => {
      const ha = parsed.ha;
      if(!ha||!ha.enabled) return '';
      let h='<div class="section"><div class="section-title">🔗 HA / Cluster</div>';
      h+='<div class="overflow"><table><thead><tr>';
      h+=`<th>${tr('ha.mode')}</th><th>${tr('ha.group_id')}</th><th>${tr('ha.priority')}</th><th>${tr('ha.peer_ip')}</th><th>${tr('ha.sync_interface')}</th><th>${tr('ha.vip')}</th>`;
      h+='</tr></thead><tbody>';
      h+=`<tr><td>${esc(ha.mode)}</td><td>${esc(ha.groupId)}</td><td>${esc(ha.priority)}</td><td>${esc(ha.peerIp)}</td><td>${esc(ha.syncInterface)}</td><td>${esc(ha.vip)}</td></tr>`;
      h+='</tbody></table></div></div>';
      return h;
    })();

    const allowN = parsed.policies.filter(p => p.action==='accept').length;
    const denyN  = parsed.policies.length - allowN;

    // WiFi section for HTML report (optional, injected when WIFI_DATA available)
    // Build WiFi section for HTML report (no nested template literals)
    function buildWifiSection(wifiData) {
      if (!wifiData || !wifiData.vaps || !wifiData.vaps.length) return '';
      const s = wifiData.summary;
      const esc2 = v => String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      let h = '';

      // Header + stats
      h += '<div class="section">';
      h += '<div class="section-title">&#x1F4E1; ' + tr('wifi.export_title') + '</div>';
      h += '<div class="stats" style="grid-template-columns:repeat(auto-fit,minmax(110px,1fr))">';
      [
        [tr('wifi.ssid_count'),       s.ssidCount,    '#00d4ff'],
        [tr('wifi.managed_ap_short'), s.apCount,      '#10b981'],
        [tr('wifi.ap_profile_count'), s.profileCount, '#a78bfa'],
        [tr('wifi.avg_sec_short'),    s.avgSecScore,  '#f59e0b'],
        [tr('wifi.wifi6_count'),      s.wifi6Aps,     '#4ade80'],
        ['Captive SSID',              s.captiveSsids, '#fbbf24'],
        [tr('wifi.hidden_ssid'),      s.hiddenSsids,  '#94a3b8'],
        ['&#x26A0; ' + tr('wifi.warn_issues'), s.warnIssues, '#f87171'],
      ].forEach(([lbl,val,col]) => {
        h += '<div class="stat-card" style="border-top:3px solid '+col+'">';
        h += '<div class="stat-num" style="color:'+col+'">'+val+'</div>';
        h += '<div class="stat-lbl">'+lbl+'</div></div>';
      });
      h += '</div>';

      // SSID table
      h += '<div style="color:#94a3b8;font-size:11px;margin-bottom:6px">&#x1F4F6; ' + tr('wifi.ssid_analysis') + '</div>';
      h += '<div class="overflow"><table>';
      h += '<thead><tr><th>'+tr('wifi.ssid_name')+'</th><th>'+tr('wifi.sec_mode')+'</th><th>'+tr('wifi.sec_grade')+'</th><th>'+tr('wifi.score_col')+'</th><th>Captive</th><th>'+tr('wifi.broadcast_short')+'</th><th>PMF</th><th>VLAN</th><th>'+tr('wifi.ap_deploy')+'</th><th>'+tr('wifi.issue_col')+'</th></tr></thead><tbody>';
      wifiData.vaps.forEach(v => {
        const gc = v.secGrade==='A' ? 'rgba(16,185,129,.2)' : v.secGrade==='B' ? 'rgba(59,130,246,.2)' : 'rgba(239,68,68,.2)';
        const gtc = v.secGrade==='A' ? '#10b981' : v.secGrade==='B' ? '#3b82f6' : '#ef4444';
        const secLabel = v.security === 'wpa2-only' ? 'WPA2' : v.security;
        const issues = (v.secIssues||[]);
        const issueHtml = issues.length
          ? issues.map(i=>(i.level==='critical'?'&#x1F6A8;':i.level==='warn'?'&#x26A0;':'&#x2139;')+' '+esc2(i.msg)).join('<br>')
          : tr('wifi.no_issue_short');
        h += '<tr>';
        h += '<td><b>'+esc2(v.ssid)+'</b>'+((!v.broadcastSsid)?' <span style="color:#64748b;font-size:10px">'+tr('wifi.hidden_short')+'</span>':'')+'</td>';
        h += '<td><span class="badge" style="background:#1e3a5f;color:#7dd3fc">'+esc2(secLabel)+'</span></td>';
        h += '<td><span class="badge" style="background:'+gc+';color:'+gtc+'">'+esc2(v.secGrade)+'</span></td>';
        h += '<td style="font-family:monospace">'+v.secScore+'</td>';
        h += '<td>'+( v.captivePortal ? '&#x2705;' : '-')+'</td>';
        h += '<td>'+(v.broadcastSsid ? tr('wifi.yes') : tr('wifi.no'))+'</td>';
        h += '<td style="color:'+(v.pmf&&v.pmf!=='-'&&v.pmf!=='disable'?'#10b981':'#64748b')+'">'+esc2(v.pmf!=='-'?v.pmf:'-')+'</td>';
        h += '<td>'+(v.vlanId!=='-' ? '<span style="color:#a78bfa">VLAN '+esc2(v.vlanId)+'</span>' : '-')+'</td>';
        h += '<td style="color:#00d4ff">'+(v.deployedOnAps>0 ? v.deployedOnAps+' '+tr('wifi.unit_ap') : '-')+'</td>';
        h += '<td style="font-size:11px;color:'+(issues.some(i=>i.level==='critical')?'#ef4444':issues.some(i=>i.level==='warn')?'#f59e0b':'#10b981')+'">'+issueHtml+'</td>';
        h += '</tr>';
      });
      h += '</tbody></table></div>';

      // AP instances table
      if (wifiData.wtps.length) {
        h += '<br><div style="color:#94a3b8;font-size:11px;margin-bottom:6px">&#x1F3E2; '+tr('wifi.managed_ap_list')+' ('+wifiData.wtps.length+' '+tr('wifi.unit_ap')+')</div>';
        h += '<div class="overflow"><table>';
        h += '<thead><tr><th>'+tr('wifi.col_serial')+'</th><th>'+tr('col.name')+'</th><th>'+tr('wifi.col_location')+'</th><th>'+tr('wifi.col_profile')+'</th><th>'+tr('col.status')+'</th></tr></thead><tbody>';
        wifiData.wtps.forEach(ap => {
          h += '<tr>';
          h += '<td style="font-family:monospace;font-size:11px;color:#64748b">'+esc2(ap.serial)+'</td>';
          h += '<td><b>'+esc2(ap.name)+'</b></td>';
          h += '<td style="color:#94a3b8">'+esc2(ap.location&&ap.location!=='-'?ap.location:'')+'</td>';
          h += '<td style="color:#a78bfa">'+esc2(ap.profile)+'</td>';
          h += '<td><span class="badge '+(ap.status==='enable'?'badge-on':'badge-off')+'">'+esc2(ap.status)+'</span></td>';
          h += '</tr>';
        });
        h += '</tbody></table></div>';
      }

      // WIDS profiles
      if (wifiData.widsProfiles.length) {
        h += '<br><div style="color:#94a3b8;font-size:11px;margin-bottom:6px">&#x1F6E1; '+tr('wifi.wids_short')+'</div>';
        h += '<div class="overflow"><table>';
        h += '<thead><tr><th>'+tr('col.name')+'</th><th>'+tr('wifi.wids_coverage')+'</th><th>'+tr('col.desc')+'</th></tr></thead><tbody>';
        wifiData.widsProfiles.forEach(p => {
          const barColor = p.coverage>=80 ? '#10b981' : p.coverage>=50 ? '#f59e0b' : '#ef4444';
          h += '<tr><td><b>'+esc2(p.name)+'</b></td>';
          h += '<td><div style="display:flex;align-items:center;gap:8px">';
          h += '<div style="flex:1;height:6px;background:#1e3a5f;border-radius:3px">';
          h += '<div style="width:'+p.coverage+'%;height:100%;background:'+barColor+';border-radius:3px"></div></div>';
          h += '<span style="font-family:monospace">'+p.coverage+'%</span></div></td>';
          h += '<td style="color:#64748b">'+esc2(p.comment&&p.comment!=='-'?p.comment:'-')+'</td></tr>';
        });
        h += '</tbody></table></div>';
      }

      h += '</div>';
      return h;
    }
    const wifiSection = buildWifiSection(wifiData);

    const wwanSection = (() => {
      const ww = parsed.wwan;
      if (!ww) return '';
      const m5g = ww.modem5G;
      const has5G = m5g && (m5g.modem1 || m5g.modem2);
      if (!has5G && !ww.profiles?.length && !ww.lteModem && !ww.lteInterfaces?.length) return '';
      const e2 = s => String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const fmt5G = (m, label) => {
        if (!m) return '';
        let r = '<div style="font-size:11px;color:#00d4ff;font-weight:600;margin:12px 0 6px">&#x1F4F6; ' + label + '</div>';
        r += '<div class="overflow"><table><thead><tr><th>APN</th><th>'+tr('wwan.col_carrier')+'</th><th>'+tr('wwan.col_auth')+'</th><th>'+tr('wwan.col_user')+'</th><th>SIM1 PIN</th><th>SIM2 PIN</th><th>'+tr('wwan.col_prefer_sim')+'</th><th>'+tr('wwan.col_iface')+'</th></tr></thead><tbody>';
        r += '<tr>' +
          '<td style="font-family:monospace">' + e2(m.apn) + '</td>' +
          '<td>' + e2(m.apnProvider) + '</td>' +
          '<td>' + e2(m.authType) + '</td>' +
          '<td style="font-family:monospace">' + e2(m.username) + '</td>' +
          '<td><span class="badge ' + (m.sim1Pin==='set'?'badge-on':'badge-off') + '">' + (m.sim1Pin==='set'?tr('wwan.pin_set'):tr('wwan.pin_notset')) + '</span></td>' +
          '<td><span class="badge ' + (m.sim2Pin==='set'?'badge-on':'badge-off') + '">' + (m.sim2Pin==='set'?tr('wwan.pin_set'):tr('wwan.pin_notset')) + '</span></td>' +
          '<td>' + e2(m.preferSim) + '</td>' +
          '<td style="font-family:monospace">' + e2(m.interface) + '</td>' +
          '</tr>';
        r += '</tbody></table></div>';
        return r;
      };
      let h = '<div class="section" id="sec-wwan">';
      h += '<div class="section-title">&#x1F4F1; ' + tr('wwan.section_label') + '</div>';
      if (has5G) {
        h += fmt5G(m5g.modem1, '5G Modem 1');
        h += fmt5G(m5g.modem2, '5G Modem 2');
      }
      if (ww.profiles?.length) {
        h += '<div style="font-size:11px;color:#00d4ff;font-weight:600;margin:12px 0 6px">&#x1F4CB; WWAN Profile</div>';
        h += '<div class="overflow"><table><thead><tr><th>Profile</th><th>APN</th><th>'+tr('wwan.col_auth')+'</th><th>'+tr('wwan.col_user')+'</th><th>Modem</th><th>'+tr('wwan.col_simpin')+'</th><th>'+tr('wwan.col_carrier')+'</th><th>VDOM</th></tr></thead><tbody>';
        ww.profiles.forEach(p => {
          h += '<tr><td><b>' + e2(p.name) + '</b></td><td style="font-family:monospace">' + e2(p.apn) + '</td><td>' + e2(p.authType) + '</td><td style="font-family:monospace">' + e2(p.username) + '</td><td>' + e2(p.modemId) + '</td><td><span class="badge ' + (p.simPin==='set'?'badge-on':'badge-off') + '">' + (p.simPin==='set'?tr('wwan.pin_set'):tr('wwan.pin_notset')) + '</span></td><td>' + e2(p.provider) + '</td><td style="color:#64748b">' + e2(p._vdom||'-') + '</td></tr>';
        });
        h += '</tbody></table></div>';
      }
      if (ww.lteInterfaces?.length) {
        h += '<div style="font-size:11px;color:#00d4ff;font-weight:600;margin:12px 0 6px">&#x1F4F1; ' + tr('wwan.lte_iface') + '</div>';
        h += '<div class="overflow"><table><thead><tr><th>'+tr('col.name')+'</th><th>'+tr('wwan.col_apn_profile')+'</th><th>'+tr('wwan.col_roaming')+'</th><th>'+tr('col.status')+'</th><th>'+tr('col.comment')+'</th></tr></thead><tbody>';
        ww.lteInterfaces.forEach(i => {
          h += '<tr><td style="font-family:monospace">' + e2(i.name) + '</td><td>' + e2(i.apnProfile) + '</td><td>' + (i.allowRoaming==='yes'?tr('wwan.pill_allow'):tr('wwan.pill_disable')) + '</td><td>' + (i.disabled==='yes'?tr('wwan.pill_disable'):tr('wwan.pill_enable')) + '</td><td style="color:#64748b">' + e2(i.comment) + '</td></tr>';
        });
        h += '</tbody></table></div>';
      }
      if (ww.apnProfiles?.length) {
        h += '<div style="font-size:11px;color:#fbbf24;font-weight:600;margin:12px 0 6px">&#x1F4CB; ' + tr('wwan.lte_apn_profile') + '</div>';
        h += '<div class="overflow"><table><thead><tr><th>'+tr('wwan.col_apn_name')+'</th><th>APN</th><th>'+tr('wwan.col_auth')+'</th><th>'+tr('wwan.col_user')+'</th><th>'+tr('wwan.col_password')+'</th><th>'+tr('wwan.col_ip_type')+'</th><th>'+tr('wwan.col_distance')+'</th></tr></thead><tbody>';
        ww.apnProfiles.forEach(p => {
          h += '<tr><td style="font-family:monospace">' + e2(p.name) + '</td><td>' + e2(p.apn) + '</td><td>' + e2(p.authType) + '</td><td style="font-family:monospace">' + e2(p.username) + '</td><td style="color:#64748b">' + e2(p.passwd) + '</td><td>' + e2(p.ipType) + '</td><td>' + e2(p.distance) + '</td></tr>';
        });
        h += '</tbody></table></div>';
      }
      if (ww.lteModem) {
        h += '<div style="font-size:11px;color:#fbbf24;font-weight:600;margin:16px 0 6px">&#x2699; ' + tr('wwan.lte_settings') + '</div>';
        h += '<div class="overflow"><table><thead><tr><th>'+tr('col.status')+'</th><th>'+tr('wwan.col_port')+'</th><th>APN</th><th>'+tr('wwan.col_auth')+'</th><th>'+tr('wwan.col_autoswitch')+'</th></tr></thead><tbody>';
        h += '<tr><td><span class="badge ' + (ww.lteModem.status==='enable'?'badge-on':'badge-off') + '">' + ww.lteModem.status + '</span></td><td style="font-family:monospace">' + e2(ww.lteModem.modemPort) + '</td><td style="font-family:monospace">' + e2(ww.lteModem.apn) + '</td><td>' + e2(ww.lteModem.authType) + '</td><td><span class="badge ' + (ww.lteModem.autoSwitch==='enable'?'badge-on':'badge-off') + '">' + ww.lteModem.autoSwitch + '</span></td></tr>';
        h += '</tbody></table></div>';
      }
      h += '</div>';
      return h;
    })();

    const wlanSection = (() => {
      const wl = parsed.wlan;
      if (!wl || (!wl.interfaces.length && !wl.capsmanConfigs.length)) return '';
      const e2 = s => String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      let h = '<div class="section" id="sec-wlan">';
      h += '<div class="section-title">&#x1F4F6; ' + tr('wlan.section_title') + '</div>';
      if (wl.interfaces.length) {
        h += '<div style="font-size:11px;color:#00d4ff;font-weight:600;margin:0 0 6px">&#x1F4FB; ' + tr('wlan.iface_title') + '</div>';
        h += '<div class="overflow"><table><thead><tr><th>'+tr('col.if_name')+'</th><th>SSID</th><th>'+tr('wlan.col_band')+'</th><th>'+tr('col.mode')+'</th><th>'+tr('wlan.col_freq')+'</th><th>'+tr('wlan.col_auth_types')+'</th><th>'+tr('wlan.col_key')+'</th><th>'+tr('col.status')+'</th></tr></thead><tbody>';
        wl.interfaces.forEach(i => {
          h += '<tr>' +
            '<td style="font-family:monospace">' + e2(i.name) + '</td>' +
            '<td><b>' + e2(i.ssid) + '</b></td>' +
            '<td>' + e2(i.band) + '</td>' +
            '<td>' + e2(i.mode) + '</td>' +
            '<td style="font-family:monospace">' + e2(i.frequency) + '</td>' +
            '<td>' + e2(i.authTypes) + '</td>' +
            '<td><span class="badge ' + (i.hasKey?'badge-on':'badge-off') + '">' + (i.hasKey?tr('wwan.pin_set'):tr('wwan.pin_notset')) + '</span></td>' +
            '<td><span class="badge ' + (i.disabled==='yes'?'badge-off':'badge-on') + '">' + (i.disabled==='yes'?tr('wwan.pill_disable'):tr('wwan.pill_enable')) + '</span></td>' +
            '</tr>';
        });
        h += '</tbody></table></div>';
      }
      if (wl.capsmanConfigs.length) {
        h += '<div style="font-size:11px;color:#fbbf24;font-weight:600;margin:12px 0 6px">&#x1F5C2; ' + tr('wlan.capsman_title') + '</div>';
        h += '<div class="overflow"><table><thead><tr><th>'+tr('col.name')+'</th><th>SSID</th><th>'+tr('wlan.col_band')+'</th><th>'+tr('wlan.col_auth_types')+'</th><th>'+tr('wlan.col_key')+'</th></tr></thead><tbody>';
        wl.capsmanConfigs.forEach(c => {
          h += '<tr>' +
            '<td style="font-family:monospace">' + e2(c.name) + '</td>' +
            '<td><b>' + e2(c.ssid) + '</b></td>' +
            '<td>' + e2(c.band) + '</td>' +
            '<td>' + e2(c.authTypes) + '</td>' +
            '<td><span class="badge ' + (c.hasKey?'badge-on':'badge-off') + '">' + (c.hasKey?tr('wwan.pin_set'):tr('wwan.pin_notset')) + '</span></td>' +
            '</tr>';
        });
        h += '</tbody></table></div>';
      }
      h += '</div>';
      return h;
    })();

    return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<title>${tr('rpt.fw_title')} - ${esc(info.hostname)}</title>
<style>${REPORT_CSS_FW}</style>
</head>
<body>
<h1>🛡️ ${tr('rpt.fw_title')}</h1>
<div class="subtitle">Generated by FW-Analyzer · ${esc(info.vendor||info.hostname)} · ${now}</div>

<div class="info-grid">
  <div class="info-item"><div class="k">${tr('rpt.vendor_label')}</div><div class="v">${esc(info.vendor)}</div></div>
  <div class="info-item"><div class="k">${tr('rpt.hostname_label')}</div><div class="v">${esc(info.hostname)}</div></div>
  <div class="info-item"><div class="k">${tr('rpt.firmware_label')}</div><div class="v">${esc(info.firmware)}</div></div>
  <div class="info-item"><div class="k">${tr('rpt.model_label')}</div><div class="v">${esc(info.model)}</div></div>
</div>

<div class="stats">
  ${stat(tr('rpt.stat_iface'), parsed.interfaces.length, '#00d4ff', 'sec-interfaces')}
  ${stat(tr('rpt.stat_policy'), parsed.policies.length, '#7dd3fc', 'sec-policies')}
  ${stat(tr('rpt.stat_allow'), allowN, '#10b981', 'sec-policies')}
  ${stat(tr('rpt.stat_deny'), denyN, '#ef4444', 'sec-policies')}
  ${stat(tr('rpt.stat_static_rt'), parsed.routes.filter(r=>r.type==='static').length, '#f59e0b', 'sec-routes')}
  ${stat(tr('rpt.stat_dyn_rt'), parsed.routes.filter(r=>r.type!=='static'&&r.type!=='policy').length, '#fb923c', 'sec-routes')}
  ${stat(tr('rpt.stat_vpn'), parsed.vpn.length, '#a78bfa', 'sec-vpn')}
  ${stat(tr('rpt.stat_addr'), parsed.addresses.length, '#38bdf8', 'sec-addresses')}
  ${stat(tr('rpt.stat_svc'), parsed.services.length, '#4ade80')}
  ${stat(tr('rpt.stat_user'), parsed.users.filter(u=>u.type==='local').length, '#f472b6', 'sec-users')}
  ${stat(tr('rpt.stat_group'), parsed.users.filter(u=>u.type==='group').length, '#fb923c', 'sec-users')}
  ${stat(tr('rpt.stat_nat'), parsed.nat.length, '#fbbf24')}
  ${parsed.wwan&&parsed.wwan.modem5G ? stat('5G Modem', (parsed.wwan.modem5G.modem1?1:0)+(parsed.wwan.modem5G.modem2?1:0), '#00c8f0', 'sec-wwan') : parsed.wwan&&((parsed.wwan.profiles?.length)||(parsed.wwan.lteInterfaces?.length)) ? stat('LTE/WWAN', (parsed.wwan.profiles?.length)||(parsed.wwan.lteInterfaces?.length)||0, '#00c8f0', 'sec-wwan') : ''}
  ${parsed.wlan&&parsed.wlan.interfaces.length ? stat(tr('rpt.stat_wlan'), parsed.wlan.interfaces.length, '#4ade80', 'sec-wlan') : ''}
</div>

<div class="section" id="sec-interfaces">
  <div class="section-title">🔌 ${tr('rpt.sec_interfaces')} (${parsed.interfaces.length})</div>
  <div class="overflow"><table>
    <thead><tr><th>${tr('col.name')}</th><th>${tr('col.alias')}</th><th>${tr('col.ip')}</th><th>${tr('col.mask')}</th><th>${tr('col.type')}</th><th>VLAN</th><th>${tr('col.role')}</th><th>${tr('col.status')}</th><th>${tr('col.comment')}</th></tr></thead>
    <tbody>${ifaceRows || '<tr><td colspan="9" style="text-align:center;color:#64748b">'+tr('rpt.no_data')+'</td></tr>'}</tbody>
  </table></div>
</div>

<div class="section" id="sec-policies">
  <div class="section-title">📋 ${tr('rpt.sec_policies')} (${parsed.policies.length})</div>
  <div class="overflow"><table>
    <thead><tr><th>ID</th><th>${tr('col.name')}</th><th>${tr('col.src_intf')}</th><th>${tr('col.dst_intf')}</th><th>${tr('col.src_addr')}</th><th>${tr('col.dst_addr')}</th><th>${tr('col.service')}</th><th>${tr('col.action')}</th><th>NAT</th><th>${tr('col.status')}</th><th>${tr('col.comment')}</th></tr></thead>
    <tbody>${policyRows || '<tr><td colspan="11" style="text-align:center;color:#64748b">'+tr('rpt.no_data')+'</td></tr>'}</tbody>
  </table></div>
</div>

<div class="section" id="sec-routes">
  <div class="section-title">🛤️ ${tr('rpt.sec_routes')} (${parsed.routes.length})</div>
  <div class="overflow"><table>
    <thead><tr><th>${tr('col.type')}</th><th>${tr('col.dst_net')}</th><th>${tr('col.gateway')}</th><th>${tr('col.intf')}</th><th>${tr('col.distance')}</th><th>${tr('col.status')}</th><th>${tr('col.comment')}</th></tr></thead>
    <tbody>${routeRows || '<tr><td colspan="7" style="text-align:center;color:#64748b">'+tr('rpt.no_data')+'</td></tr>'}</tbody>
  </table></div>
</div>

<div class="section" id="sec-vpn">
  <div class="section-title">🔐 ${tr('rpt.sec_vpn')} (${parsed.vpn.length})</div>
  <div class="overflow"><table>
    <thead><tr><th>${tr('col.type')}</th><th>${tr('col.name')}</th><th>${tr('col.remote_gw')}</th><th>${tr('col.intf')}</th><th>IKE</th><th>${tr('col.auth')}</th><th>${tr('col.proposal')}</th><th>${tr('col.dh_group')}</th><th>${tr('col.status')}</th></tr></thead>
    <tbody>${vpnRows || '<tr><td colspan="9" style="text-align:center;color:#64748b">'+tr('rpt.no_data')+'</td></tr>'}</tbody>
  </table></div>
  ${ph2Rows ? `<br><div style="color:#94a3b8;font-size:11px;margin-bottom:6px">${tr('rpt.ph2_detail')}</div>
  <div class="overflow"><table>
    <thead><tr><th>Phase1</th><th>Phase2</th><th>${tr('col.proposal')}</th><th>${tr('col.dh_group')}</th><th>${tr('col.lifetime')}</th><th>${tr('col.local_sub')}</th><th>${tr('col.remote_sub')}</th></tr></thead>
    <tbody>${ph2Rows}</tbody>
  </table></div>` : ''}
</div>

<div class="section" id="sec-addresses">
  <div class="section-title">📦 ${tr('rpt.sec_addresses')} (${parsed.addresses.length}${parsed.addresses.length > 200 ? ', '+tr('rpt.show_200') : ''})</div>
  <div class="overflow"><table>
    <thead><tr><th>${tr('col.category')}</th><th>${tr('col.name')}</th><th>${tr('col.type')}</th><th>${tr('col.subnet_range')}</th><th>${tr('col.members')}</th><th>${tr('col.comment')}</th></tr></thead>
    <tbody>${addrRows || '<tr><td colspan="6" style="text-align:center;color:#64748b">'+tr('rpt.no_data')+'</td></tr>'}</tbody>
  </table></div>
</div>

<div class="section" id="sec-users">
  <div class="section-title">👤 ${tr('rpt.sec_users')} (${parsed.users.length})</div>
  <div class="overflow"><table>
    <thead><tr><th>${tr('col.type')}</th><th>${tr('col.name')}</th><th>${tr('col.status')}</th><th>${tr('col.auth_method')}</th><th>${tr('col.members')}</th><th>${tr('col.server')}</th></tr></thead>
    <tbody>${userRows || '<tr><td colspan="6" style="text-align:center;color:#64748b">'+tr('rpt.no_data')+'</td></tr>'}</tbody>
  </table></div>
</div>

${sdwanSection}
${haSection}

${wifiSection}

${wwanSection}

${wlanSection}

<div style="text-align:center;color:#334155;font-size:11px;margin-top:40px;font-family:monospace">
  FW-Analyzer — Pure JS Firewall Configuration Analyzer | ${now}
</div>

<div id="alpaca-corner" style="position:fixed;bottom:16px;right:16px;z-index:999;opacity:.85;transition:opacity .2s;cursor:default" title="${tr('egg.alpaca_title').split('\n')[0]}" onmouseenter="this.style.opacity='1'" onmouseleave="this.style.opacity='.85'">
  <svg width="48" height="56" viewBox="0 0 48 56" xmlns="http://www.w3.org/2000/svg">
    <!-- body -->
    <ellipse cx="24" cy="38" rx="14" ry="12" fill="#c8b89a"/>
    <!-- neck -->
    <rect x="18" y="20" width="8" height="16" rx="4" fill="#c8b89a"/>
    <!-- head -->
    <ellipse cx="22" cy="16" rx="9" ry="8" fill="#d4c4a0"/>
    <!-- ears -->
    <ellipse cx="15" cy="10" rx="3" ry="5" fill="#c8b89a"/>
    <ellipse cx="29" cy="10" rx="3" ry="5" fill="#c8b89a"/>
    <ellipse cx="15" cy="10" rx="1.5" ry="3" fill="#e8b4b8"/>
    <ellipse cx="29" cy="10" rx="1.5" ry="3" fill="#e8b4b8"/>
    <!-- eyes -->
    <circle cx="18" cy="15" r="2" fill="#4a3728"/>
    <circle cx="26" cy="15" r="2" fill="#4a3728"/>
    <circle cx="18.7" cy="14.3" r=".6" fill="#fff"/>
    <circle cx="26.7" cy="14.3" r=".6" fill="#fff"/>
    <!-- nose -->
    <ellipse cx="22" cy="20" rx="3" ry="2" fill="#b09070"/>
    <circle cx="20.5" cy="20" r=".8" fill="#7a5a40"/>
    <circle cx="23.5" cy="20" r=".8" fill="#7a5a40"/>
    <!-- fluffy top -->
    <ellipse cx="22" cy="9" rx="7" ry="4" fill="#e8dcc8"/>
    <ellipse cx="18" cy="8" rx="4" ry="3" fill="#e8dcc8"/>
    <ellipse cx="26" cy="8" rx="4" ry="3" fill="#e8dcc8"/>
    <!-- legs -->
    <rect x="13" y="47" width="5" height="8" rx="2.5" fill="#b09070"/>
    <rect x="20" y="47" width="5" height="8" rx="2.5" fill="#b09070"/>
    <rect x="28" y="47" width="5" height="8" rx="2.5" fill="#b09070"/>
    <!-- tail -->
    <ellipse cx="37" cy="36" rx="4" ry="3" fill="#d4c4a0"/>
  </svg>
</div>

<div style="position:fixed;bottom:16px;right:16px;opacity:.75;z-index:99" title="🦙 FW Analyzer">
  <svg width="44" height="52" viewBox="0 0 48 56" xmlns="http://www.w3.org/2000/svg">
    <ellipse cx="24" cy="38" rx="14" ry="12" fill="#c8b89a"/><rect x="18" y="20" width="8" height="16" rx="4" fill="#c8b89a"/>
    <ellipse cx="22" cy="16" rx="9" ry="8" fill="#d4c4a0"/>
    <ellipse cx="15" cy="10" rx="3" ry="5" fill="#c8b89a"/><ellipse cx="29" cy="10" rx="3" ry="5" fill="#c8b89a"/>
    <ellipse cx="15" cy="10" rx="1.5" ry="3" fill="#e8b4b8"/><ellipse cx="29" cy="10" rx="1.5" ry="3" fill="#e8b4b8"/>
    <circle cx="18" cy="15" r="2" fill="#4a3728"/><circle cx="26" cy="15" r="2" fill="#4a3728"/>
    <circle cx="18.7" cy="14.3" r=".6" fill="#fff"/><circle cx="26.7" cy="14.3" r=".6" fill="#fff"/>
    <ellipse cx="22" cy="20" rx="3" ry="2" fill="#b09070"/><circle cx="20.5" cy="20" r=".8" fill="#7a5a40"/><circle cx="23.5" cy="20" r=".8" fill="#7a5a40"/>
    <ellipse cx="22" cy="9" rx="7" ry="4" fill="#e8dcc8"/><ellipse cx="18" cy="8" rx="4" ry="3" fill="#e8dcc8"/><ellipse cx="26" cy="8" rx="4" ry="3" fill="#e8dcc8"/>
    <rect x="13" y="47" width="5" height="8" rx="2.5" fill="#b09070"/><rect x="20" y="47" width="5" height="8" rx="2.5" fill="#b09070"/><rect x="28" y="47" width="5" height="8" rx="2.5" fill="#b09070"/>
    <ellipse cx="37" cy="36" rx="4" ry="3" fill="#d4c4a0"/>
  </svg>
</div>

${(parsed.nat&&parsed.nat.length)?`<div class="section" id="sec-nat">
  <div class="section-title">&#x1F504; ${tr('rpt.sec_nat')} (${parsed.nat.length})</div>
  <div class="overflow"><table>
    <thead><tr><th>${tr('col.type')}</th><th>${tr('col.name')}</th><th>Ext IP</th><th>Map IP</th><th>Ext Port</th><th>Map Port</th><th>Proto</th><th>${tr('col.status')}</th><th>${tr('col.comment')}</th></tr></thead>
    <tbody>${parsed.nat.slice(0,200).map(n=>`<tr>
      <td>${esc(n.type)||'&#x2014;'}</td><td>${esc(n.name)||'&#x2014;'}</td>
      <td class="mono">${esc(n.extIp)||'&#x2014;'}</td><td class="mono">${esc(n.mapIp)||'&#x2014;'}</td>
      <td class="mono">${esc(n.extPort)||'&#x2014;'}</td><td class="mono">${esc(n.mapPort)||'&#x2014;'}</td>
      <td>${esc(n.proto)||'&#x2014;'}</td>
      <td><span class="badge" style="background:${n.status==='enable'?'rgba(34,197,94,.2);color:#22c55e':'rgba(100,116,139,.2);color:#94a3b8'}">${esc(n.status)||'&#x2014;'}</span></td>
      <td>${esc(n.comment)||'&#x2014;'}</td>
    </tr>`).join('')}</tbody>
  </table></div>
</div>`:''}
${(parsed.services&&parsed.services.filter(s=>s.category==='custom'||s.category==='group').length)?`<div class="section" id="sec-services">
  <div class="section-title">&#x2699;&#xFE0F; ${tr('rpt.sec_services')} (${parsed.services.filter(s=>s.category==='custom'||s.category==='group').length})</div>
  <div class="overflow"><table>
    <thead><tr><th>${tr('col.category')}</th><th>${tr('col.name')}</th><th>Proto</th><th>TCP</th><th>UDP</th><th>${tr('col.members')}</th><th>${tr('col.comment')}</th></tr></thead>
    <tbody>${parsed.services.filter(s=>s.category==='custom'||s.category==='group').slice(0,200).map(s=>`<tr>
      <td><span class="badge" style="background:#0f2027;color:#38bdf8">${esc(s.category)}</span></td>
      <td>${esc(s.name)||'&#x2014;'}</td><td>${esc(s.proto)||'&#x2014;'}</td>
      <td class="mono">${esc(s.tcpPorts)||'&#x2014;'}</td><td class="mono">${esc(s.udpPorts)||'&#x2014;'}</td>
      <td>${esc(s.members)||'&#x2014;'}</td><td>${esc(s.comment)||'&#x2014;'}</td>
    </tr>`).join('')}</tbody>
  </table></div>
</div>`:''}
${(parsed.dhcp&&((parsed.dhcp.servers&&parsed.dhcp.servers.length)||(parsed.dhcp.relays&&parsed.dhcp.relays.length)))?`<div class="section" id="sec-dhcp">
  <div class="section-title">&#x1F4E1; ${tr('rpt.sec_dhcp')}</div>
  ${(parsed.dhcp.servers&&parsed.dhcp.servers.length)?`<div class="overflow"><table>
    <thead><tr><th>${tr('col.name')}</th><th>Mask</th><th>Range</th><th>Gateway</th><th>DNS</th><th>Interface</th></tr></thead>
    <tbody>${parsed.dhcp.servers.map(s=>`<tr>
      <td>${esc(s.name)||'&#x2014;'}</td><td class="mono">${esc(s.mask)||'&#x2014;'}</td>
      <td class="mono">${(s.startIp||s.start)&&(s.endIp||s.end)?esc((s.startIp||s.start)+' - '+(s.endIp||s.end)):'&#x2014;'}</td><td class="mono">${esc(s.gateway)||'&#x2014;'}</td>
      <td class="mono">${(s.dns1||s.dns2)?esc([s.dns1,s.dns2].filter(Boolean).join(', ')):(esc(s.dns)||'&#x2014;')}</td>
      <td class="mono">${esc(s.iface)||'&#x2014;'}</td>
    </tr>`).join('')}</tbody>
  </table></div>`:''}
  ${(parsed.dhcp.relays&&parsed.dhcp.relays.length)?`<p style="margin:8px 0 4px;color:#94a3b8;font-size:12px">Relay</p><div class="overflow"><table>
    <thead><tr><th>Interface</th><th>Server IP</th></tr></thead>
    <tbody>${parsed.dhcp.relays.map(r=>`<tr><td class="mono">${esc(r.iface)||'&#x2014;'}</td><td class="mono">${esc(r.serverIp)||'&#x2014;'}</td></tr>`).join('')}</tbody>
  </table></div>`:''}
</div>`:''}
${(parsed.dns&&((parsed.dns.servers&&parsed.dns.servers.length)||(parsed.dns.static&&parsed.dns.static.length)))?`<div class="section" id="sec-dns">
  <div class="section-title">&#x1F310; ${tr('rpt.sec_dns')}${parsed.dns.domain?' &#x2014; '+esc(parsed.dns.domain):''}</div>
  ${(parsed.dns.servers&&parsed.dns.servers.length)?`<div class="overflow"><table>
    <thead><tr><th>DNS Server</th></tr></thead>
    <tbody>${parsed.dns.servers.map(s=>`<tr><td class="mono">${esc(typeof s==='string'?s:(s.ip||JSON.stringify(s)))}</td></tr>`).join('')}</tbody>
  </table></div>`:''}
  ${(parsed.dns.static&&parsed.dns.static.length)?`<p style="margin:8px 0 4px;color:#94a3b8;font-size:12px">Static DNS</p><div class="overflow"><table>
    <thead><tr><th>${tr('col.name')}</th><th>IP</th><th>${tr('col.type')}</th></tr></thead>
    <tbody>${parsed.dns.static.map(s=>`<tr><td>${esc(s.fqdn||s.name)||'&#x2014;'}</td><td class="mono">${esc(s.ip)||'&#x2014;'}</td><td>${esc(s.type)||'&#x2014;'}</td></tr>`).join('')}</tbody>
  </table></div>`:''}
</div>`:''}
${(parsed.snmp&&((parsed.snmp.communities&&parsed.snmp.communities.length)||(parsed.snmp.trapServers&&parsed.snmp.trapServers.length)))?`<div class="section" id="sec-snmp">
  <div class="section-title">&#x1F4E1; ${tr('rpt.sec_snmp')}</div>
  ${(parsed.snmp.communities&&parsed.snmp.communities.length)?`<div class="overflow"><table>
    <thead><tr><th>Community</th><th>Permission</th><th>Hosts</th></tr></thead>
    <tbody>${parsed.snmp.communities.map(s=>`<tr>
      <td class="mono">${esc(s.name||s.community)||'&#x2014;'}</td>
      <td>${esc(s.permission||s.perm)||'&#x2014;'}</td>
      <td class="mono">${esc(Array.isArray(s.hosts)?s.hosts.join(', '):s.hosts)||'&#x2014;'}</td>
    </tr>`).join('')}</tbody>
  </table></div>`:''}
  ${(parsed.snmp.trapServers&&parsed.snmp.trapServers.length)?`<p style="margin:8px 0 4px;color:#94a3b8;font-size:12px">Trap Servers</p><div class="overflow"><table>
    <thead><tr><th>Server</th><th>Community</th><th>Port</th><th>Version</th></tr></thead>
    <tbody>${parsed.snmp.trapServers.map(s=>`<tr>
      <td class="mono">${esc(s.ip||s.host||s.server)||'&#x2014;'}</td>
      <td class="mono">${esc(s.community)||'&#x2014;'}</td>
      <td>${esc(s.port||'162')}</td><td>${esc(s.version||s.ver)||'&#x2014;'}</td>
    </tr>`).join('')}</tbody>
  </table></div>`:''}
</div>`:''}
${(parsed.logservers&&((parsed.logservers.syslog&&parsed.logservers.syslog.length)||(parsed.logservers.fortianalyzer&&parsed.logservers.fortianalyzer.length)||(parsed.logservers.netflow&&parsed.logservers.netflow.length)))?`<div class="section" id="sec-log">
  <div class="section-title">&#x1F4CB; ${tr('rpt.sec_log')}</div>
  ${(parsed.logservers.syslog&&parsed.logservers.syslog.length)?`<p style="margin:4px 0;color:#94a3b8;font-size:12px">Syslog (${parsed.logservers.syslog.length})</p><div class="overflow"><table>
    <thead><tr><th>Server</th><th>Port</th><th>Facility</th><th>Level</th><th>Status</th></tr></thead>
    <tbody>${parsed.logservers.syslog.map(s=>`<tr><td class="mono">${esc(s.ip||s.server)||'&#x2014;'}</td><td>${esc(s.port||'514')}</td><td>${esc(s.facility)||'&#x2014;'}</td><td>${esc(s.level||s.severity)||'&#x2014;'}</td><td>${esc(s.status||'enable')}</td></tr>`).join('')}</tbody>
  </table></div>`:''}
  ${(parsed.logservers.fortianalyzer&&parsed.logservers.fortianalyzer.length)?`<p style="margin:8px 0 4px;color:#94a3b8;font-size:12px">FortiAnalyzer</p><div class="overflow"><table>
    <thead><tr><th>Server</th><th>Status</th><th>Upload Day</th></tr></thead>
    <tbody>${parsed.logservers.fortianalyzer.map(s=>`<tr><td class="mono">${esc(s.ip||s.server)||'&#x2014;'}</td><td>${esc(s.status)||'&#x2014;'}</td><td>${esc(s.uploadDay)||'&#x2014;'}</td></tr>`).join('')}</tbody>
  </table></div>`:''}
  ${(parsed.logservers.netflow&&parsed.logservers.netflow.length)?`<p style="margin:8px 0 4px;color:#94a3b8;font-size:12px">NetFlow</p><div class="overflow"><table>
    <thead><tr><th>Collector</th><th>Port</th><th>Version</th></tr></thead>
    <tbody>${parsed.logservers.netflow.map(s=>`<tr><td class="mono">${esc(s.collector||s.ip)||'&#x2014;'}</td><td>${esc(s.port||'2055')}</td><td>${esc(s.version||s.ver)||'&#x2014;'}</td></tr>`).join('')}</tbody>
  </table></div>`:''}
</div>`:''}
${(parsed.schedules&&parsed.schedules.length)?`<div class="section" id="sec-sched">
  <div class="section-title">&#x23F0; ${tr('rpt.sec_sched')} (${parsed.schedules.length})</div>
  <div class="overflow"><table>
    <thead><tr><th>${tr('col.name')}</th><th>${tr('col.type')}</th><th>Start</th><th>End</th><th>Day</th></tr></thead>
    <tbody>${parsed.schedules.map(s=>`<tr>
      <td>${esc(s.name)||'&#x2014;'}</td>
      <td><span class="badge" style="background:#0f2027;color:#38bdf8">${esc(s.type)||'&#x2014;'}</span></td>
      <td class="mono">${esc(s.start)||'&#x2014;'}</td><td class="mono">${esc(s.end)||'&#x2014;'}</td>
      <td>${esc(s.day)||'&#x2014;'}</td>
    </tr>`).join('')}</tbody>
  </table></div>
</div>`:''}
</body>
</html>`;
  }

  // ─── Download helper ──────────────────────────────────────────────────────
  function download(content, filename, mime) {
    const bom   = mime === 'text/csv' ? '\uFEFF' : '';
    const blob  = new Blob([bom + content], { type: mime + ';charset=utf-8' });
    const url   = URL.createObjectURL(blob);
    const a     = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 500);
  }

  return { exportCSV, exportZoneMatrixCSV, exportQueryTraceCSV, exportDiffCSV, exportJSON, exportHTML, download };
})();


