// 設定逐行解說（NA）：給新手網管看「這一行在做什麼」的純函式模組
// 規則只涵蓋 Cisco IOS／IOS-XE、Comware 與 FortiGate 的常見指令；沒命中不代表有問題
// 規則格式：[id, 語法家族, 行比對正則, FortiGate 區塊條件（空字串＝不限）]，說明文字在 i18n 的 ex.<id>
// 同一語法家族內依序比對，先命中者為準（區塊限定的規則需排在同樣指令的通用規則之前）
// 包 IIFE 避免與其他頂層模組識別字衝突，對外只暴露 EX_RULES／exDetectSyntax／explainConfigLines
(function(){
const EX_RULES=[
  ["c_hostname","cisco",/^hostname\s/,""],
  ["c_enable_secret","cisco",/^enable secret\s/,""],
  ["c_enable_password","cisco",/^enable password\s/,""],
  ["c_username","cisco",/^username\s/,""],
  ["c_service_pwenc","cisco",/^service password-encryption/,""],
  ["c_aaa","cisco",/^aaa new-model/,""],
  ["c_vlan","cisco",/^vlan\s+\d/,""],
  ["c_name","cisco",/^\s+name\s/,""],
  ["c_interface","cisco",/^interface\s/,""],
  ["c_description","cisco",/^\s+description\s/,""],
  ["c_sw_access","cisco",/^\s+switchport mode access/,""],
  ["c_sw_trunk","cisco",/^\s+switchport mode trunk/,""],
  ["c_sw_access_vlan","cisco",/^\s+switchport access vlan\s/,""],
  ["c_sw_allowed","cisco",/^\s+switchport trunk allowed vlan\s/,""],
  ["c_sw_native","cisco",/^\s+switchport trunk native vlan\s/,""],
  ["c_portsec","cisco",/^\s+switchport port-security/,""],
  ["c_shutdown","cisco",/^\s+shutdown\s*$/,""],
  ["c_noshutdown","cisco",/^\s+no shutdown/,""],
  ["c_portfast","cisco",/^\s+spanning-tree portfast/,""],
  ["c_bpduguard","cisco",/^\s+spanning-tree bpduguard enable/,""],
  ["c_rootguard","cisco",/^\s+spanning-tree guard root/,""],
  ["c_stp_mode","cisco",/^spanning-tree mode\s/,""],
  ["c_channel","cisco",/^\s+channel-group\s+\d+/,""],
  ["c_ip_address","cisco",/^\s+ip address\s/,""],
  ["c_helper","cisco",/^\s+ip helper-address\s/,""],
  ["c_standby","cisco",/^\s+standby\s+\d+\s+ip\s/,""],
  ["c_vrrp","cisco",/^\s+vrrp\s+\d+\s+ip\s/,""],
  ["c_default_gw","cisco",/^ip default-gateway\s/,""],
  ["c_ip_route","cisco",/^ip route\s/,""],
  ["c_router_ospf","cisco",/^router ospf\s/,""],
  ["c_network_area","cisco",/^\s+network\s+\S+\s+\S+\s+area\s/,""],
  ["c_router_bgp","cisco",/^router bgp\s/,""],
  ["c_neighbor","cisco",/^\s+neighbor\s+\S+\s+remote-as\s/,""],
  ["c_snmp_comm","cisco",/^snmp-server community\s/,""],
  ["c_snmp_host","cisco",/^snmp-server host\s/,""],
  ["c_snmp_user","cisco",/^snmp-server (user|group)\s/,""],
  ["c_logging","cisco",/^logging (host\s|server\s|\d)/,""],
  ["c_ntp","cisco",/^ntp server\s/,""],
  ["c_line_vty","cisco",/^line vty\s/,""],
  ["c_line_con","cisco",/^line con\s/,""],
  ["c_transport","cisco",/^\s+transport input\s/,""],
  ["c_login_local","cisco",/^\s+login local/,""],
  ["c_access_class","cisco",/^\s+access-class\s/,""],
  ["c_ssh_v2","cisco",/^ip ssh version 2/,""],
  ["c_http_server","cisco",/^(no )?ip http (secure-)?server/,""],
  ["c_acl_ext","cisco",/^ip access-list (extended|standard)\s/,""],
  ["c_acl_rule","cisco",/^\s+(\d+\s+)?(permit|deny)\s/,""],
  ["c_access_list","cisco",/^access-list\s+\d+\s/,""],
  ["c_banner","cisco",/^banner\s/,""],
  ["c_domain","cisco",/^ip domain[- ]name\s/,""],
  ["c_nameserver","cisco",/^ip name-server\s/,""],
  ["c_clock","cisco",/^clock timezone\s/,""],
  ["c_end","cisco",/^end\s*$/,""],
  ["c_bang","cisco",/^\s*!/,""],
  ["w_sysname","comware",/^\s*sysname\s/,""],
  ["w_vlan","comware",/^vlan\s+\d/,""],
  ["w_name","comware",/^\s+name\s/,""],
  ["w_interface","comware",/^interface\s/,""],
  ["w_description","comware",/^\s+description\s/,""],
  ["w_linktype","comware",/^\s+port link-type\s/,""],
  ["w_access_vlan","comware",/^\s+port access vlan\s/,""],
  ["w_trunk_permit","comware",/^\s+port trunk permit vlan\s/,""],
  ["w_trunk_pvid","comware",/^\s+port trunk pvid vlan\s/,""],
  ["w_hybrid","comware",/^\s+port hybrid (vlan|pvid)\s/,""],
  ["w_shutdown","comware",/^\s+shutdown\s*$/,""],
  ["w_undo_shutdown","comware",/^\s+undo shutdown/,""],
  ["w_edged","comware",/^\s+stp edged-port/,""],
  ["w_bpduprot","comware",/^\s*stp bpdu-protection/,""],
  ["w_rootprot","comware",/^\s+stp root-protection/,""],
  ["w_stp_mode","comware",/^\s*stp (global )?(mode|enable)/,""],
  ["w_lagg","comware",/^\s+port link-aggregation group\s/,""],
  ["w_ip_address","comware",/^\s+ip address\s/,""],
  ["w_route_static","comware",/^\s*ip route-static\s/,""],
  ["w_ospf","comware",/^ospf\s+\d/,""],
  ["w_area","comware",/^\s+area\s/,""],
  ["w_network","comware",/^\s+network\s/,""],
  ["w_bgp","comware",/^bgp\s+\d/,""],
  ["w_peer","comware",/^\s+peer\s+\S+\s+as-number\s/,""],
  ["w_snmp_comm","comware",/^\s*snmp-agent community\s/,""],
  ["w_snmp_ver","comware",/^\s*snmp-agent sys-info version\s/,""],
  ["w_snmp_other","comware",/^\s*snmp-agent (usm-user|group|target-host|trap)/,""],
  ["w_loghost","comware",/^\s*info-center loghost\s/,""],
  ["w_ntp","comware",/^\s*ntp-service (unicast-server|enable)/,""],
  ["w_local_user","comware",/^local-user\s/,""],
  ["w_password","comware",/^\s+password\s/,""],
  ["w_service_type","comware",/^\s+service-type\s/,""],
  ["w_user_role","comware",/^\s+authorization-attribute user-role\s/,""],
  ["w_line","comware",/^(line|user-interface)\s+(vty|aux|con)/,""],
  ["w_auth_mode","comware",/^\s+authentication-mode\s/,""],
  ["w_protocol_in","comware",/^\s+protocol inbound\s/,""],
  ["w_telnet","comware",/^\s*(undo )?telnet server enable/,""],
  ["w_ssh","comware",/^\s*ssh server enable/,""],
  ["w_acl","comware",/^acl\s/,""],
  ["w_rule","comware",/^\s+rule\s+\d+\s+(permit|deny)/,""],
  ["w_dhcp_relay","comware",/^\s+dhcp relay server-address\s/,""],
  ["w_vrrp","comware",/^\s+vrrp vrid\s+\d+\s+virtual-ip\s/,""],
  ["w_header","comware",/^\s*header\s/,""],
  ["w_clock","comware",/^\s*clock timezone\s/,""],
  ["w_return","comware",/^return\s*$/,""],
  ["w_hash","comware",/^#/,""],
  ["f_config","fortigate",/^\s*config\s/,""],
  ["f_edit","fortigate",/^\s*edit\s/,""],
  ["f_next","fortigate",/^\s*next\s*$/,""],
  ["f_end","fortigate",/^\s*end\s*$/,""],
  ["f_hostname","fortigate",/^\s*set hostname\s/,"system global"],
  ["f_admin_port","fortigate",/^\s*set admin-(sport|port|ssh-port)\s/,"system global"],
  ["f_if_ip","fortigate",/^\s*set ip\s/,"system interface"],
  ["f_allowaccess","fortigate",/^\s*set allowaccess\s/,"system interface"],
  ["f_role","fortigate",/^\s*set role\s/,"system interface"],
  ["f_vdom","fortigate",/^\s*set vdom\s/,""],
  ["f_alias","fortigate",/^\s*set (alias|description)\s/,""],
  ["f_subnet","fortigate",/^\s*set subnet\s/,"firewall address"],
  ["f_iprange","fortigate",/^\s*set (start-ip|end-ip)\s/,"firewall address"],
  ["f_fqdn","fortigate",/^\s*set fqdn\s/,"firewall address"],
  ["f_member","fortigate",/^\s*set member\s/,""],
  ["f_portrange","fortigate",/^\s*set (tcp|udp|sctp)-portrange\s/,"firewall service"],
  ["f_srcintf","fortigate",/^\s*set (srcintf|dstintf)\s/,"firewall policy"],
  ["f_srcaddr","fortigate",/^\s*set (srcaddr|dstaddr)6?\s/,"firewall policy"],
  ["f_action","fortigate",/^\s*set action\s/,"firewall policy"],
  ["f_service","fortigate",/^\s*set service\s/,"firewall policy"],
  ["f_schedule","fortigate",/^\s*set schedule\s/,"firewall policy"],
  ["f_nat","fortigate",/^\s*set nat\s/,"firewall policy"],
  ["f_logtraffic","fortigate",/^\s*set logtraffic\s/,"firewall policy"],
  ["f_status","fortigate",/^\s*set status\s/,""],
  ["f_name","fortigate",/^\s*set name\s/,""],
  ["f_comments","fortigate",/^\s*set comments?\s/,""],
  ["f_utm","fortigate",/^\s*set (av-profile|webfilter-profile|ips-sensor|application-list|ssl-ssh-profile|utm-status)\s/,"firewall policy"],
  ["f_gateway","fortigate",/^\s*set gateway\s/,"router static"],
  ["f_dst","fortigate",/^\s*set dst\s/,"router static"],
  ["f_device","fortigate",/^\s*set device\s/,"router static"],
  ["f_accprofile","fortigate",/^\s*set accprofile\s/,"system admin"],
  ["f_trusthost","fortigate",/^\s*set (ip6-)?trusthost\d+\s/,"system admin"],
  ["f_two_factor","fortigate",/^\s*set two-factor\s/,"system admin"],
  ["f_password","fortigate",/^\s*set (password|passwd|psksecret)\s/,""],
  ["f_remote_gw","fortigate",/^\s*set remote-gw\s/,"vpn ipsec"],
  ["f_proposal","fortigate",/^\s*set proposal\s/,"vpn ipsec"],
  ["f_dhgrp","fortigate",/^\s*set dhgrp\s/,"vpn ipsec"],
  ["f_pfs","fortigate",/^\s*set pfs\s/,"vpn ipsec"],
  ["f_dns","fortigate",/^\s*set (primary|secondary)\s/,"system dns"],
  ["f_log_server","fortigate",/^\s*set server\s/,"log syslogd"],
  ["f_ntp_server","fortigate",/^\s*set server\s/,"system ntp"],
  ["f_hash_comment","fortigate",/^#/,""],
  ["c_ip_ospf","cisco",/^\s+ip ospf\s/,""],
  ["c_aaa_list","cisco",/^aaa (authentication|authorization|accounting)\s/,""],
  ["c_service_ts","cisco",/^service timestamps\s/,""],
  ["c_aaa_server","cisco",/^(radius|tacacs) server\s/,""],
  ["c_key","cisco",/^\s+key\s/,""],
  ["c_vrf","cisco",/^(ip vrf|vrf definition)\s/,""],
  ["c_ipv6_addr","cisco",/^\s+ipv6 address\s/,""],
  ["w_ipv6_addr","comware",/^\s+ipv6 address\s/,""],
  ["w_scheme","comware",/^(radius|hwtacacs) scheme\s/,""],
  ["w_key","comware",/^\s+key\s/,""],
  ["w_domain","comware",/^domain\s/,""],
  ["f_type","fortigate",/^\s*set type\s/,""],
  ["f_ip6","fortigate",/^\s*set ip6-address\s/,""],
  ["f_remote_as","fortigate",/^\s*set remote-as\s/,"router bgp"]
];
// 整份文字判斷語法家族（只用於選規則，非正式廠牌偵測）
function exDetectSyntax(text){
  if(/^config (system global|system interface|firewall )/m.test(text))return 'fortigate';
  if(/^\s*sysname\s|^\s*port link-type\s|^return\s*$/m.test(text))return 'comware';
  return 'cisco';
}
// 回傳 [{line,text,id}]，id 為 null 表示沒有對應規則
// FortiGate 以 config/end 維護區塊堆疊（edit/next 不影響），區塊條件比對堆疊中任一層
function explainConfigLines(text,syntax){
  const lines=String(text||'').replace(/\r\n/g,'\n').split('\n');
  if(lines.length&&lines[lines.length-1]==='')lines.pop();
  const vendor=syntax||exDetectSyntax(text);
  const rules=EX_RULES.filter(r=>r[1]===vendor);
  const stack=[];
  return lines.map((ln,i)=>{
    let id=null;
    if(ln.trim()){
      for(const r of rules){
        if(!r[2].test(ln))continue;
        if(r[3]&&!stack.some(s=>s.indexOf(r[3])===0))continue;
        id=r[0];break;
      }
    }
    if(vendor==='fortigate'){
      const m=ln.match(/^\s*config\s+(.+?)\s*$/);
      if(m)stack.push(m[1]);
      else if(/^\s*end\s*$/.test(ln))stack.pop();
    }
    return {line:i+1,text:ln,id};
  });
}
window.EX_RULES=EX_RULES;
window.exDetectSyntax=exDetectSyntax;
window.explainConfigLines=explainConfigLines;
})();
