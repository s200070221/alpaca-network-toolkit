// ══════════════════════════════════════════════════════════
//  雲端安全群組 PARSER（AWS Security Group／Azure NSG，2026-10-02 新增，第十輪發想 ZC）
// ══════════════════════════════════════════════════════════
// 格式來源：
// - AWS：`aws ec2 describe-security-groups` JSON，依 aws/aws-cli 官方範例（awscli/examples/ec2/
//   describe-security-groups.rst）：SecurityGroups[].{GroupId, GroupName, Description, VpcId, Tags,
//   IpPermissions[], IpPermissionsEgress[]}，每筆權限 {IpProtocol, FromPort, ToPort, IpRanges[{CidrIp,
//   Description}], Ipv6Ranges[{CidrIpv6}], PrefixListIds[{PrefixListId}], UserIdGroupPairs[{GroupId}]}；
//   IpProtocol "-1" 為全部協定，ICMP 的 FromPort／ToPort 是類型／代碼（-1 為全部）。
//   官方範例本身帶尾端逗號（非合法 JSON），解析前先去除。
// - Azure：NSG 資源 JSON，依 Azure/azure-cli 官方測試錄製的 REST 回應：{name, properties:{securityRules[],
//   defaultSecurityRules[]}}，規則 {name, properties:{protocol, sourcePortRange(s), destinationPortRange(s),
//   sourceAddressPrefix(es), destinationAddressPrefix(es), access, priority, direction, description}}；
//   `az network nsg show` 輸出沒有 properties 外層，兩種都接受，也接受 nsg list 的陣列與 ARM 範本的 resources。
// - Cisco Meraki MX（2026-10-02，第十輪發想 ZD）：Dashboard API 回應 JSON，依官方 OpenAPI 規格
//   （github.com/meraki/openapi spec3.json 的範例與欄位說明）：
//   l3FirewallRules {rules:[{comment, policy allow|deny, protocol any|tcp|udp|icmp|icmp6, srcPort, srcCidr,
//   destPort, destCidr, syslogEnabled}]}（埠與位址為逗號清單或 Any，目的可為 FQDN）、
//   portForwardingRules {rules:[{name, lanIp, uplink, publicPort, localPort, allowedIps[], protocol}]}、
//   oneToOneNatRules {rules:[{name, publicIp, lanIp, uplink, allowedInbound[{protocol, destinationPorts[], allowedIps[]}]}]}、
//   vlans [{id, name, subnet, applianceIp}]、staticRoutes [{name, subnet, gatewayIp, enabled}]。
//   設定分散在多個 API，可貼單一回應、多個回應前後相接，或以端點名稱為鍵的物件；依欄位形狀辨識各段。
//   L3 規則為 LAN 往外（WAN／VPN）由上而下比對，介面列為 any。
// - GCP VPC 防火牆規則（2026-10-13，第二十一輪 GF）：`gcloud compute firewall-rules list --format=json` 或 REST
//   firewalls.list 回應，欄位依 Compute Engine API discovery 文件的 Firewall 資源：{kind:"compute#firewall", name, network（URL）,
//   direction INGRESS|EGRESS, priority（0～65535，預設 1000，數字小者優先，同優先權拒絕優先）, sourceRanges, destinationRanges,
//   sourceTags, targetTags, sourceServiceAccounts, targetServiceAccounts, allowed|denied[{IPProtocol, ports[]}], disabled,
//   logConfig{enable}, description}。每個 VPC 網路為一個 VDOM；網路標記與服務帳戶列為位址物件不展開；
//   有目的範圍時目的取範圍、套用目標（targetTags／targetServiceAccounts）記在備註，否則目的為套用目標；
//   隱含規則（優先權 65535：入站全部拒絕、出站全部允許）列在最後並標註。
// - AWS Network ACL（2026-10-13，第二十一輪 GG）：`aws ec2 describe-network-acls`，依 aws-cli 官方範例與 botocore
//   服務模型：NetworkAcls[].{NetworkAclId, VpcId, IsDefault, Tags, Associations[{SubnetId}], Entries[{RuleNumber,
//   Egress, Protocol（-1 或協定號碼）, RuleAction allow|deny, CidrBlock|Ipv6CidrBlock, PortRange{From,To},
//   IcmpTypeCode{Type,Code}}]}。每個 NACL 為一個 VDOM，依方向、RuleNumber 由小到大比對；32767／32768 為預設
//   拒絕（*）。NACL 無狀態，回應流量需另有規則放行（查詢只看單一方向）。
// - Azure Firewall Policy 規則集合群組（2026-10-13，第二十二輪 HF）：REST／az CLI 的 ruleCollectionGroups 回應（單一或 {value:[…]}），
//   欄位依 Azure REST API 規格官方範例（FirewallPolicyRuleCollectionGroupGet／NatRuleCollectionGroupGet／WithIpGroups／WithWebCategories）：
//   properties.priority、ruleCollections[{name, priority, action.type Allow|Deny|DNAT, ruleCollectionType, rules[{ruleType NetworkRule|
//   ApplicationRule|NatRule, sourceAddresses, sourceIpGroups, destinationAddresses, destinationIpGroups, destinationFqdns, destinationPorts,
//   ipProtocols, protocols[{protocolType, port}], targetFqdns, fqdnTags, targetUrls, webCategories, translatedAddress|translatedFqdn, translatedPort}]}]。
//   評估順序依 Microsoft 文件（搜尋摘要）：DNAT → 網路規則 → 應用規則，各自依群組 priority、集合 priority；未命中為拒絕（列出隱含規則）。
//   每個 Firewall Policy 為一個 VDOM；DNAT 列在 NAT 頁；IP Group、FQDN、FQDN 標籤、網頁分類列為位址物件不展開
// - GCP network firewall policy（2026-10-13，第二十二輪 HG）：`gcloud compute network-firewall-policies describe --format=json`
//   （kind compute#firewallPolicy），欄位依 Compute API discovery 文件：rules[{priority（0 最高）, direction, action allow|deny|goto_next|
//   apply_security_profile_group, ruleName, disabled, enableLogging, targetSecureTags, targetServiceAccounts, match{srcIpRanges, destIpRanges,
//   srcAddressGroups, destAddressGroups, srcFqdns, destFqdns, srcRegionCodes, destRegionCodes, srcThreatIntelligences, destThreatIntelligences,
//   srcSecureTags, layer4Configs[{ipProtocol, ports}]}}]。每個政策為一個 VDOM，依方向＋priority 排序；goto_next 交給下一層判斷（與 VPC 防火牆
//   規則的先後由網路的 networkFirewallPolicyEnforcementOrder 決定，設定不在此檔，不合併），action 記為 accept 並標 gotoNext，查詢回傳 goto_next；自動建立的預設規則
//   （priority 2147483644 起）標為平台規則
// - Kubernetes NetworkPolicy（2026-10-13，第二十三輪 IG）：`kubectl get networkpolicy -A -o json`（List）或單筆 JSON，欄位依 kubernetes
//   staging/src/k8s.io/api/networking/v1/types.go：spec.podSelector（空為該 namespace 全部 Pod）、policyTypes（未指定時一律含 Ingress，
//   有 egress 段才含 Egress）、ingress[].from／egress[].to（peer：podSelector、namespaceSelector、ipBlock{cidr, except}；清單為空表示不限）、
//   ports[]（protocol 預設 TCP、port 數字或具名埠、endPort）。每個 namespace 一個 VDOM；各政策的規則彼此疊加（任一條允許即放行），故先列全部允許規則，
//   再列被選取 Pod 的隱含拒絕（平台規則）；未被任何政策選取的 Pod 不受限制（不在此檔判斷）。Pod／namespace 選擇器列為物件不展開
//   （查詢視為可能命中）；ipBlock 的 except 以群組排除成員表示；具名埠對應容器埠名稱，無法由設定判斷，以全部埠表示並註記。只接受 JSON
// - Oracle Cloud（OCI）安全清單與 NSG 規則（2026-10-13，第二十三輪 IH）：`oci network security-list get|list`（CLI 輸出為連字號鍵名
//   ingress-security-rules）、REST／SDK 的 camelCase（ingressSecurityRules）皆可，欄位依 oracle/oci-python-sdk core models：
//   SecurityList{displayName, id, vcnId, ingressSecurityRules[{protocol（all 或協定號碼）, source, sourceType, isStateless,
//   tcpOptions|udpOptions{destinationPortRange{min,max}}, icmpOptions{type,code}, description}], egressSecurityRules[{destination…}]}；
//   `oci network nsg rules list` 的 SecurityRule{direction INGRESS|EGRESS, source／destination, sourceType／destinationType
//   （CIDR_BLOCK、SERVICE_CIDR_BLOCK、NETWORK_SECURITY_GROUP）…}。比照 AWS 安全群組：只有允許規則、隱含拒絕不列；服務網段與 NSG 參照列為物件不展開
// 對應方式：每個安全群組／NSG 當成一個 VDOM（可用上方 VDOM 列切換）；入站規則目的介面為群組名稱、
// 出站規則來源介面為群組名稱。AWS 只有允許規則，未列出的流量一律拒絕（不另列規則，比照預設政策）；
// Azure 依方向、priority 排序，預設規則（65000 起）一併列出並標註。
// 服務標籤（VirtualNetwork、Internet…）、AWS 前綴清單與安全群組參照列為位址物件，但成員不在檔案內，
// IP 查詢不會命中這些名稱（不猜測其範圍）。
const CloudSGParser = (() => {
  const PROTO_NUM = { '6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6' };

  function loadJson(text) {
    const t = String(text || '').replace(/^﻿/, '').trim();
    try { return JSON.parse(t); } catch { /* 官方範例的尾端逗號 */ }
    try { return JSON.parse(t.replace(/,(\s*[}\]])/g, '$1')); } catch { return null; }
  }
  const isAwsGroup = o => o && typeof o === 'object' && Array.isArray(o.IpPermissions) && ('GroupId' in o || 'GroupName' in o);
  const nsgProps = o => (o && o.properties && (o.properties.securityRules || o.properties.defaultSecurityRules)) ? o.properties : o;
  const isGcpFw = o => !!o && typeof o === 'object' && !Array.isArray(o) && (o.kind === 'compute#firewall' ||
    ((Array.isArray(o.allowed) || Array.isArray(o.denied)) && typeof o.direction === 'string' && 'network' in o));
  const isGcpFwPolicy = o => !!o && typeof o === 'object' && !Array.isArray(o) && Array.isArray(o.rules) &&
    (o.kind === 'compute#firewallPolicy' || (o.rules.length > 0 && o.rules.every(r => r && r.match && 'priority' in r && 'action' in r)));
  // OCI：鍵名統一成 camelCase（CLI 為連字號、Python SDK to_dict 為底線）
  const ociCamel = o => Array.isArray(o) ? o.map(ociCamel) : (o && typeof o === 'object') ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k.replace(/[-_]([a-z])/g, (m, c) => c.toUpperCase()), ociCamel(v)])) : o;
  const isOciSecList = o => !!o && typeof o === 'object' && !Array.isArray(o) && ['ingressSecurityRules', 'ingress-security-rules', 'ingress_security_rules', 'egressSecurityRules', 'egress-security-rules', 'egress_security_rules'].some(k => Array.isArray(o[k]));
  const isOciNsgRule = o => !!o && typeof o === 'object' && /^(?:INGRESS|EGRESS)$/.test(String(o.direction || '')) && 'protocol' in o && ('source' in o || 'destination' in o);
  const isK8sNetPol = o => !!o && typeof o === 'object' && !Array.isArray(o) && o.kind === 'NetworkPolicy' && !!o.spec && typeof o.spec === 'object';
  const isAwsNacl = o => !!o && typeof o === 'object' && !Array.isArray(o) && Array.isArray(o.Entries) && 'NetworkAclId' in o;
  const azRcgProps = o => (o && o.properties && Array.isArray(o.properties.ruleCollections)) ? o.properties : o;
  const isAzureRcg = o => { const p = azRcgProps(o); return !!p && typeof p === 'object' && !Array.isArray(p) && Array.isArray(p.ruleCollections); };
  const isAzureNsg = o => { const p = nsgProps(o); return !!p && typeof p === 'object' && (Array.isArray(p.securityRules) || Array.isArray(p.defaultSecurityRules)); };

  // 從任意 JSON 結構中找出 AWS 安全群組與 Azure NSG（describe 輸出、nsg list 陣列、ARM 範本 resources）
  function collect(root) {
    const aws = [], az = [], gcp = [], nacl = [], azfw = [], gcpPol = [], k8s = [], oci = [], ociNsg = [], seen = new Set();
    (function walk(o, depth) {
      if (!o || typeof o !== 'object' || depth > 6 || seen.has(o)) return;
      seen.add(o);
      if (isAwsGroup(o)) { aws.push(o); return; }
      if (isAwsNacl(o)) { nacl.push(o); return; }
      if (isK8sNetPol(o)) { k8s.push(o); return; }
      if (isOciSecList(o)) { oci.push(ociCamel(o)); return; }
      if (Array.isArray(o) && o.length && o.every(isOciNsgRule)) { ociNsg.push(ociCamel(o)); return; }
      if (isGcpFw(o)) { gcp.push(o); return; }
      if (isGcpFwPolicy(o)) { gcpPol.push(o); return; }
      if (isAzureNsg(o)) { az.push(o); return; }
      if (isAzureRcg(o)) { azfw.push(o); return; }
      (Array.isArray(o) ? o : Object.values(o)).forEach(v => walk(v, depth + 1));
    })(root, 0);
    return { aws, az, gcp, nacl, azfw, gcpPol, k8s, oci, ociNsg };
  }

  // Meraki：依欄位形狀找出各 API 回應的項目陣列（規則陣列保留原順序）
  const has = (o, a, b) => !!o && typeof o === 'object' && !Array.isArray(o) && a in o && b in o;
  const MK = {
    l3: o => has(o, 'policy', 'destCidr'),
    pf: o => has(o, 'lanIp', 'publicPort'),
    nat11: o => has(o, 'lanIp', 'publicIp'),
    vlan: o => has(o, 'applianceIp', 'subnet'),
    route: o => has(o, 'gatewayIp', 'subnet'),
  };
  function collectMeraki(root) {
    const res = { l3: [], pf: [], nat11: [], vlan: [], route: [] }, seen = new Set();
    (function walk(o, depth) {
      if (!o || typeof o !== 'object' || depth > 5 || seen.has(o)) return;
      seen.add(o);
      if (Array.isArray(o)) {
        const k = Object.keys(MK).find(k => o.length && o.every(x => MK[k](x)));
        if (k) { res[k].push(...o); return; }
      }
      (Array.isArray(o) ? o : Object.values(o)).forEach(v => walk(v, depth + 1));
    })(root, 0);
    return res;
  }
  const merakiCount = m => m.l3.length + m.pf.length + m.nat11.length + m.vlan.length + m.route.length;
  // 精簡 YAML 讀取（Kubernetes manifest 用，功能驗證時補上）：縮排區塊對應與序列、「- 鍵: 值」、{}／[] 空集合、引號字串、數字、
  // true／false／null、| 與 > 區塊字串、註解與 --- 多文件；不支援錨點、別名、流式集合內容與多行純量
  function yamlLite(text) {
    const docs = [];
    String(text || '').replace(/\r\n/g, '\n').split(/^---[^\n]*$/m).forEach(doc => {
      const lines = doc.split('\n').filter(l => l.trim() && !/^\s*#/.test(l)).map(l => ({ ind: l.match(/^ */)[0].length, t: l.trim(), raw: l }));
      if (!lines.length) return;
      let i = 0;
      const isItem = t => t === '-' || t.startsWith('- ');
      const unq = v => (/^"[\s\S]*"$/.test(v) ? (() => { try { return JSON.parse(v); } catch (e) { return v.slice(1, -1); } })() : /^'[\s\S]*'$/.test(v) ? v.slice(1, -1).replace(/''/g, "'") : v);
      const scalar = v => {
        v = v.replace(/\s+#.*$/, '');
        if (v === '{}') return {};
        if (v === '[]') return [];
        if (/^["']/.test(v)) return unq(v);
        if (/^-?\d+(?:\.\d+)?$/.test(v)) return Number(v);
        if (/^(?:true|false)$/.test(v)) return v === 'true';
        if (/^(?:null|~)$/.test(v)) return null;
        return v;
      };
      const KEY_RE = /^("[^"]*"|'[^']*'|[^\s"'{[#-][^:]*?|-[^\s][^:]*?):(?:\s+(.*))?$/;
      function block(ind) { return isItem(lines[i].t) ? seq(ind) : map(ind); }
      function map(ind) {
        const o = {};
        while (i < lines.length && lines[i].ind === ind && !isItem(lines[i].t)) {
          const m = lines[i].t.match(KEY_RE);
          if (!m) throw new Error('YAML: ' + lines[i].t);
          i++;
          const k = unq(m[1].trim()), v = m[2] === undefined ? '' : m[2].trim();
          if (/^[|>][-+]?$/.test(v)) {
            const buf = [];
            while (i < lines.length && lines[i].ind > ind) { buf.push(lines[i].raw.slice(lines[i].ind)); i++; }
            o[k] = buf.join(v[0] === '|' ? '\n' : ' ');
          } else if (v) o[k] = scalar(v);
          else if (i < lines.length && (lines[i].ind > ind || (lines[i].ind === ind && isItem(lines[i].t)))) o[k] = block(lines[i].ind);
          else o[k] = null;
        }
        return o;
      }
      function seq(ind) {
        const a = [];
        while (i < lines.length && lines[i].ind === ind && isItem(lines[i].t)) {
          const rest = lines[i].t.replace(/^-\s*/, '');
          if (!rest) { i++; a.push(i < lines.length && lines[i].ind > ind ? block(lines[i].ind) : null); continue; }
          if (KEY_RE.test(rest)) {
            lines[i] = { ind: ind + lines[i].t.length - rest.length, t: rest, raw: ' '.repeat(ind + lines[i].t.length - rest.length) + rest };
            a.push(map(lines[i].ind));
          } else { a.push(scalar(rest)); i++; }
        }
        return a;
      }
      docs.push(block(lines[0].ind));
    });
    return docs.length === 1 ? docs[0] : docs;
  }
  // 多個 API 回應前後相接時逐段解析（每段由行首的 { 或 [ 開始）；Kubernetes NetworkPolicy 的 YAML（kubectl -o yaml、官方範例）改用 yamlLite()
  function loadAll(text) {
    const one = loadJson(text);
    if (one) return one;
    if (/^\s*kind:\s*NetworkPolicy\b/m.test(String(text || ''))) { try { return yamlLite(text); } catch (e) { return null; } }
    const parts = String(text || '').split(/\n(?=[{[])/).map(loadJson).filter(Boolean);
    return parts.length ? parts : null;
  }

  function detect(text) {
    const s = String(text || '');
    if (!/^\s*kind:\s*NetworkPolicy\b/m.test(s) && !/"(?:IpPermissions|securityRules|defaultSecurityRules|destCidr|publicPort|publicIp|applianceIp|IPProtocol|NetworkAclId|ruleCollections|layer4Configs|podSelector|ingress[-_]?[sS]ecurity[-_]?[rR]ules|egress[-_]?[sS]ecurity[-_]?[rR]ules|direction)"/.test(s)) return false;
    const d = loadAll(s);
    if (!d) return false;
    const { aws, az, gcp, nacl, azfw, gcpPol, k8s, oci, ociNsg } = collect(d);
    return aws.length + az.length + gcp.length + nacl.length + azfw.length + gcpPol.length + k8s.length + oci.length + ociNsg.length + merakiCount(collectMeraki(d)) > 0;
  }

  function basePolicy(o) {
    const sa = _splitAddr(o.src), da = _splitAddr(o.dst);
    return {
      id: o.id, name: o.name, srcIntf: o.srcIntf, dstIntf: o.dstIntf,
      srcAddr: o.src, dstAddr: o.dst, srcAddr4: sa.v4, srcAddr6: sa.v6, dstAddr4: da.v4, dstAddr6: da.v6,
      service: o.service, schedule: 'always', action: o.action, actionRaw: o.actionRaw,
      nat: 'disable', ippool: 'disable', poolname: '-', logtraffic: 'disable',
      utm: { av: '-', ips: '-', webfilter: '-', appctrl: '-' }, status: 'enable',
      users: '-', groups: '-', comments: o.comment || '', _vdom: o.vdom, chain: o.chain, ruleNum: String(o.ruleNum),
      srcPort: o.srcPort || '',
    };
  }
  const refObj = (name, comment, vdom) => ({ category: 'address-group', name, type: 'group', subnet: '-', fqdn: '-', startIp: '-', endIp: '-',
    wildcard: '-', iface: '-', color: '0', comment, members: '-', _vdom: vdom });

  // ── AWS ──────────────────────────────────────────────────
  function awsService(p) {
    const proto = String(p.IpProtocol == null ? '-1' : p.IpProtocol).toLowerCase();
    if (proto === '-1' || proto === 'all') return 'ALL';
    const name = PROTO_NUM[proto] || proto;
    const from = p.FromPort, to = p.ToPort;
    if (name === 'icmp' || name === 'icmpv6') return from == null || from === -1 ? name : `${name}/${from}`;
    if (name !== 'tcp' && name !== 'udp') return /^\d+$/.test(name) ? `proto-${name}` : name;
    if (from == null || from === -1) return `${name}/0-65535`;
    return from === to || to == null ? `${name}/${from}` : `${name}/${from}-${to}`;
  }
  function parseAws(groups, out) {
    groups.forEach(g => {
      const nameTag = (g.Tags || []).find(t => t && t.Key === 'Name');
      const vdom = g.GroupName || g.GroupId || 'sg';
      out.vdoms.push(vdom);
      [['IpPermissions', 'inbound'], ['IpPermissionsEgress', 'outbound']].forEach(([key, dir]) => {
        (g[key] || []).forEach((p, i) => {
          const peers = [], notes = [];
          (p.IpRanges || []).forEach(r => { if (r && r.CidrIp) { peers.push(r.CidrIp); if (r.Description) notes.push(r.Description); } });
          (p.Ipv6Ranges || []).forEach(r => { if (r && r.CidrIpv6) { peers.push(r.CidrIpv6); if (r.Description) notes.push(r.Description); } });
          (p.PrefixListIds || []).forEach(r => {
            if (!r || !r.PrefixListId) return;
            peers.push(r.PrefixListId); if (r.Description) notes.push(r.Description);
            out.refs.set(vdom + '/' + r.PrefixListId, refObj(r.PrefixListId, 'AWS 前綴清單（成員不在此檔）', vdom));
          });
          (p.UserIdGroupPairs || []).forEach(r => {
            const id = r && (r.GroupId || r.GroupName);
            if (!id) return;
            peers.push(id); if (r.Description) notes.push(r.Description);
            out.refs.set(vdom + '/' + id, refObj(id, '安全群組參照（成員為套用該群組的執行個體）', vdom));
          });
          if (!peers.length) return;
          const peer = peers.join(', ');
          out.policies.push(basePolicy({
            id: out.policies.length + 1, name: `${vdom}-${dir === 'inbound' ? 'in' : 'out'}-${i + 1}`, vdom, chain: dir, ruleNum: i + 1,
            srcIntf: dir === 'inbound' ? 'any' : vdom, dstIntf: dir === 'inbound' ? vdom : 'any',
            src: dir === 'inbound' ? peer : 'any', dst: dir === 'inbound' ? 'any' : peer,
            service: awsService(p), action: 'accept', actionRaw: 'allow', comment: [...new Set(notes)].join('; '),
          }));
        });
      });
      out.groups.push({ name: vdom, id: g.GroupId || '-', vpc: g.VpcId || '-', desc: g.Description || '', tag: nameTag ? nameTag.Value : '' });
    });
  }

  // ── Azure ────────────────────────────────────────────────
  const list = (one, many) => (Array.isArray(many) && many.length ? many : (one != null && one !== '' ? [one] : [])).map(String);
  function azAddr(one, many, asgs, vdom, out) {
    const vals = list(one, many);
    (asgs || []).forEach(a => { const id = a && a.id ? String(a.id).split('/').pop() : ''; if (id) vals.push(id); });
    if (!vals.length || vals.includes('*')) return 'any';
    vals.forEach(v => {
      if (/^[\d.:a-fA-F/]+$/.test(v) && /\d/.test(v)) return;
      // AzureLoadBalancer 官方定義即主機虛擬 IP 168.63.129.16（service-tags-overview）；其餘服務標籤與
      // 應用程式安全性群組範圍由 Azure 或使用者環境決定，列為位址物件但不展開
      if (v === 'AzureLoadBalancer') out.refs.set(vdom + '/' + v, { ...refObj(v, 'Azure 服務標籤：主機虛擬 IP（健康探查來源）', vdom), category: 'address', type: 'ipmask', subnet: '168.63.129.16/32' });
      else out.refs.set(vdom + '/' + v, refObj(v, 'Azure 服務標籤／應用程式安全性群組（範圍由 Azure 決定）', vdom));
    });
    return vals.join(', ');
  }
  function azService(r) {
    const proto = String(r.protocol || '*').toLowerCase();
    const ports = list(r.destinationPortRange, r.destinationPortRanges);
    const anyPort = !ports.length || ports.includes('*');
    if (proto === '*' || proto === 'any') {
      if (anyPort) return 'ALL';
      return ports.flatMap(p => [`tcp/${p}`, `udp/${p}`]).join(', ');
    }
    if (proto === 'icmp') return 'icmp';
    if (proto === 'tcp' || proto === 'udp') return anyPort ? `${proto}/0-65535` : ports.map(p => `${proto}/${p}`).join(', ');
    return proto;
  }
  function parseAzure(nsgs, out) {
    nsgs.forEach(n => {
      const p = nsgProps(n);
      const vdom = n.name || (n.id ? String(n.id).split('/').pop() : 'nsg');
      out.vdoms.push(vdom);
      const rules = [];
      (p.securityRules || []).forEach(r => rules.push({ r, def: false }));
      (p.defaultSecurityRules || []).forEach(r => rules.push({ r, def: true }));
      const norm = rules.map(({ r, def }) => ({ name: r.name, def, ...(r.properties || r) }));
      const dirRank = d => /^in/i.test(d || '') ? 0 : 1;
      norm.sort((a, b) => dirRank(a.direction) - dirRank(b.direction) || (+a.priority || 0) - (+b.priority || 0));
      norm.forEach(r => {
        const inbound = dirRank(r.direction) === 0;
        const srcPorts = list(r.sourcePortRange, r.sourcePortRanges).filter(x => x !== '*');
        const allow = /^allow$/i.test(r.access || '');
        out.policies.push(basePolicy({
          id: out.policies.length + 1, name: r.name || `${vdom}-${r.priority}`, vdom, chain: inbound ? 'Inbound' : 'Outbound', ruleNum: r.priority != null ? r.priority : '-',
          srcIntf: inbound ? 'any' : vdom, dstIntf: inbound ? vdom : 'any',
          src: azAddr(r.sourceAddressPrefix, r.sourceAddressPrefixes, r.sourceApplicationSecurityGroups, vdom, out),
          dst: azAddr(r.destinationAddressPrefix, r.destinationAddressPrefixes, r.destinationApplicationSecurityGroups, vdom, out),
          service: azService(r), action: allow ? 'accept' : 'deny', actionRaw: r.access || '',
          comment: [r.def ? '預設規則' : '', r.description || ''].filter(Boolean).join('：'), srcPort: srcPorts.join(','),
        }));
      });
      out.groups.push({ name: vdom, id: n.id || '-', vpc: n.location || '-', desc: '', tag: '' });
    });
  }

  // ── GCP VPC 防火牆規則 ───────────────────────────────────
  function gcpService(list) {
    const out = [];
    (list || []).forEach(a => {
      const proto = String(a && a.IPProtocol != null ? a.IPProtocol : 'all').toLowerCase();
      const name = PROTO_NUM[proto] || proto;
      if (name === 'all') { out.push('ALL'); return; }
      const ports = Array.isArray(a.ports) ? a.ports.map(String) : [];
      if (name === 'tcp' || name === 'udp' || name === 'sctp') out.push(...(ports.length ? ports.map(p => `${name}/${p}`) : [`${name}/0-65535`]));
      else out.push(/^\d+$/.test(name) ? `proto-${name}` : name);
    });
    return out.includes('ALL') || !out.length ? 'ALL' : out.join(', ');
  }
  function gcpRefs(tags, sas, vdom, out) {
    const vals = [];
    (tags || []).forEach(t => { const n = 'tag:' + t; vals.push(n); out.refs.set(vdom + '/' + n, refObj(n, 'GCP 網路標記（成員為帶此標記的執行個體）', vdom)); });
    (sas || []).forEach(t => { const n = 'sa:' + t; vals.push(n); out.refs.set(vdom + '/' + n, refObj(n, 'GCP 服務帳戶（成員為使用此帳戶的執行個體）', vdom)); });
    return vals;
  }
  function parseGcp(rules, out) {
    const nets = new Map();
    rules.forEach(r => {
      const net = String(r.network || 'default').split('/').pop() || 'default';
      if (!nets.has(net)) nets.set(net, []);
      nets.get(net).push(r);
    });
    for (const [vdom, list] of nets) {
      out.vdoms.push(vdom);
      const rank = r => (String(r.direction || 'INGRESS').toUpperCase() === 'EGRESS' ? 1 : 0);
      const prio = r => (r.priority == null ? 1000 : +r.priority);
      const sorted = [...list].sort((a, b) => rank(a) - rank(b) || prio(a) - prio(b) || (Array.isArray(b.denied) ? 1 : 0) - (Array.isArray(a.denied) ? 1 : 0));
      const push = (r, implied) => {
        const egress = rank(r) === 1, deny = Array.isArray(r.denied);
        const targets = gcpRefs(r.targetTags, r.targetServiceAccounts, vdom, out);
        let src, dst;
        if (egress) {
          src = targets.length ? targets.join(', ') : 'any';
          dst = (r.destinationRanges || []).length ? r.destinationRanges.join(', ') : 'any';
        } else {
          const s = [...(r.sourceRanges || []), ...gcpRefs(r.sourceTags, r.sourceServiceAccounts, vdom, out)];
          src = s.length ? s.join(', ') : 'any';
          dst = (r.destinationRanges || []).length ? r.destinationRanges.join(', ') : (targets.length ? targets.join(', ') : 'any');
        }
        const note = [implied ? '隱含規則' : '', r.description || '', targets.length && dst !== targets.join(', ') && !egress ? '套用目標：' + targets.join(', ') : ''].filter(Boolean).join('：');
        const pol = basePolicy({
          id: out.policies.length + 1, name: r.name || `${vdom}-${prio(r)}`, vdom, chain: egress ? 'EGRESS' : 'INGRESS', ruleNum: prio(r),
          srcIntf: egress ? vdom : 'any', dstIntf: egress ? 'any' : vdom, src, dst,
          service: gcpService(deny ? r.denied : r.allowed), action: deny ? 'deny' : 'accept', actionRaw: deny ? 'deny' : 'allow', comment: note,
        });
        if (implied) pol.platformRule = true;
        if (r.disabled === true) pol.status = 'disable';
        if (r.logConfig && r.logConfig.enable) pol.logtraffic = 'all';
        out.policies.push(pol);
      };
      sorted.forEach(r => push(r, false));
      push({ name: 'implied-deny-ingress', direction: 'INGRESS', priority: 65535, sourceRanges: ['0.0.0.0/0', '::/0'], denied: [{ IPProtocol: 'all' }] }, true);
      push({ name: 'implied-allow-egress', direction: 'EGRESS', priority: 65535, destinationRanges: ['0.0.0.0/0', '::/0'], allowed: [{ IPProtocol: 'all' }] }, true);
      out.groups.push({ name: vdom, id: '-', vpc: vdom, desc: 'VPC 網路', tag: '', type: 'vpc-network' });
    }
  }

  // GCP network firewall policy
  function parseGcpPolicy(pols, out) {
    pols.forEach(pol => {
      const vdom = pol.name || 'firewall-policy';
      out.vdoms.push(vdom);
      const refs = (list, prefix, note, type) => (list || []).map(v => {
        const raw = typeof v === 'object' ? String(v.name || '') : String(v);
        const name = prefix + (/^https?:\/\/|^projects\//.test(raw) ? raw.split('/').pop() : raw);
        out.refs.set(vdom + '/' + name, type === 'fqdn' ? { ...refObj(name, note, vdom), category: 'address', type: 'fqdn', fqdn: name } : refObj(name, note, vdom));
        return name;
      });
      const dirRank = r => (String(r.direction || 'INGRESS').toUpperCase() === 'EGRESS' ? 1 : 0);
      [...pol.rules].sort((a, b) => dirRank(a) - dirRank(b) || (+a.priority || 0) - (+b.priority || 0)).forEach(r => {
        const m = r.match || {}, egress = dirRank(r) === 1;
        const targets = [...refs(r.targetSecureTags, 'tag:', 'GCP 安全標記（成員為帶此標記的執行個體）'), ...refs(r.targetServiceAccounts, 'sa:', 'GCP 服務帳戶（成員為使用此帳戶的執行個體）')];
        const side = k => [...(m[k + 'IpRanges'] || []), ...refs(m[k + 'AddressGroups'], 'ag:', 'GCP 位址群組（成員不在此檔）'), ...refs(m[k + 'Fqdns'], '', 'FQDN', 'fqdn'),
          ...refs(m[k + 'RegionCodes'], 'geo:', '地區（由 Google 判定）'), ...refs(m[k + 'ThreatIntelligences'], 'ti:', 'Google 威脅情資清單'),
          ...(k === 'src' ? refs(m.srcSecureTags, 'tag:', 'GCP 安全標記（成員為帶此標記的執行個體）') : [])];
        const srcL = egress ? targets : side('src'), dstL = egress ? side('dest') : (side('dest').length ? side('dest') : targets);
        const asAny = l => (l.length ? l.join(', ') : 'any');
        const act = String(r.action || '').toLowerCase();
        const builtin = (+r.priority || 0) >= 2147483644;
        const note = [builtin ? '預設規則' : '', act === 'goto_next' ? 'goto_next：交給下一層（VPC 防火牆規則或其他政策）判斷' : '',
          act === 'apply_security_profile_group' ? '套用安全性設定檔群組（放行並檢查）' : '', r.description || ''].filter(Boolean).join('：');
        const p = basePolicy({
          id: out.policies.length + 1, name: r.ruleName || `${vdom}-${r.priority}`, vdom, chain: egress ? 'EGRESS' : 'INGRESS', ruleNum: r.priority,
          srcIntf: egress ? vdom : 'any', dstIntf: egress ? 'any' : vdom, src: asAny(srcL), dst: asAny(dstL),
          service: gcpService((m.layer4Configs || []).map(x => ({ IPProtocol: x.ipProtocol, ports: x.ports }))),
          action: act === 'deny' ? 'deny' : 'accept', actionRaw: act, comment: note,
        });
        if (r.disabled === true) p.status = 'disable';
        if (r.enableLogging) p.logtraffic = 'all';
        if (builtin) p.platformRule = true;
        // goto_next 不是放行：本層不擋、交給下一層判斷，查詢結果另外標示（動作欄維持 accept／deny 兩種）
        if (act === 'goto_next') p.gotoNext = true;
        out.policies.push(p);
      });
      out.groups.push({ name: vdom, id: pol.id || '-', vpc: (pol.associations || []).map(a => String(a.attachmentTarget || a.name || '').split('/').pop()).filter(Boolean).join(', ') || '-',
        desc: 'GCP network firewall policy', tag: '', type: 'firewall-policy' });
    });
  }

  // ── AWS Network ACL ──────────────────────────────────────
  function naclService(e) {
    const proto = String(e.Protocol == null ? '-1' : e.Protocol).toLowerCase();
    if (proto === '-1' || proto === 'all') return 'ALL';
    const name = PROTO_NUM[proto] || proto;
    if (name === 'icmp' || name === 'icmpv6') { const t = e.IcmpTypeCode && e.IcmpTypeCode.Type; return t == null || t === -1 ? name : `${name}/${t}`; }
    if (name === 'tcp' || name === 'udp') {
      const r = e.PortRange || {};
      if (r.From == null) return `${name}/0-65535`;
      return r.From === r.To || r.To == null ? `${name}/${r.From}` : `${name}/${r.From}-${r.To}`;
    }
    return /^\d+$/.test(name) ? `proto-${name}` : name;
  }
  function parseNacl(acls, out) {
    acls.forEach(a => {
      const nameTag = (a.Tags || []).find(t => t && t.Key === 'Name');
      const vdom = (nameTag && nameTag.Value) || a.NetworkAclId;
      out.vdoms.push(vdom);
      const entries = [...a.Entries].sort((x, y) => (x.Egress ? 1 : 0) - (y.Egress ? 1 : 0) || (+x.RuleNumber || 0) - (+y.RuleNumber || 0));
      entries.forEach(e => {
        const egress = e.Egress === true, peer = e.CidrBlock || e.Ipv6CidrBlock || 'any';
        const def = +e.RuleNumber >= 32767;
        const pol = basePolicy({
          id: out.policies.length + 1, name: `${vdom}-${egress ? 'out' : 'in'}-${e.RuleNumber}`, vdom, chain: egress ? 'outbound' : 'inbound', ruleNum: def ? '*' : e.RuleNumber,
          srcIntf: egress ? vdom : 'any', dstIntf: egress ? 'any' : vdom, src: egress ? 'any' : peer, dst: egress ? peer : 'any',
          service: naclService(e), action: /^allow$/i.test(e.RuleAction || '') ? 'accept' : 'deny', actionRaw: e.RuleAction || '',
          comment: def ? '預設規則（*）' : '',
        });
        if (def) pol.platformRule = true;
        out.policies.push(pol);
      });
      const subnets = (a.Associations || []).map(x => x && x.SubnetId).filter(Boolean);
      out.groups.push({ name: vdom, id: a.NetworkAclId, vpc: a.VpcId || '-', desc: (a.IsDefault ? '預設 NACL；' : '') + (subnets.length ? '子網：' + subnets.join(', ') : '未關聯子網'), tag: nameTag ? a.NetworkAclId : '', type: 'network-acl' });
    });
  }

  // ── Oracle Cloud（OCI）安全清單／NSG ───────────────────
  function ociService(r) {
    const proto = String(r.protocol == null ? 'all' : r.protocol).toLowerCase();
    if (proto === 'all') return 'ALL';
    const name = PROTO_NUM[proto] || proto;
    if (name === 'icmp' || name === 'icmpv6') { const t = r.icmpOptions && r.icmpOptions.type; return t == null ? name : `${name}/${t}`; }
    if (name === 'tcp' || name === 'udp') {
      const pr = (r[name + 'Options'] || {}).destinationPortRange;
      if (!pr || pr.min == null) return `${name}/0-65535`;
      return pr.min === pr.max || pr.max == null ? `${name}/${pr.min}` : `${name}/${pr.min}-${pr.max}`;
    }
    return /^\d+$/.test(name) ? `proto-${name}` : name;
  }
  function ociPeer(v, type, vdom, out) {
    const val = String(v || '');
    if (!val) return 'any';
    if (/^NETWORK_SECURITY_GROUP$/i.test(type || '') || /^ocid1\.networksecuritygroup\./.test(val)) {
      const n = 'nsg:' + val;
      out.refs.set(vdom + '/' + n, refObj(n, 'OCI 網路安全群組（成員為該 NSG 內的 VNIC）', vdom));
      return n;
    }
    if (/^SERVICE_CIDR_BLOCK$/i.test(type || '')) {
      out.refs.set(vdom + '/' + val, refObj(val, 'OCI 服務網段（Oracle Services Network，成員由 Oracle 定義）', vdom));
      return val;
    }
    return val;
  }
  function ociRule(r, egress, vdom, n, out) {
    const peer = ociPeer(egress ? r.destination : r.source, egress ? r.destinationType : r.sourceType, vdom, out);
    return basePolicy({
      id: out.policies.length + 1, name: `${vdom}-${egress ? 'egress' : 'ingress'}-${n}`, vdom, chain: egress ? 'EGRESS' : 'INGRESS', ruleNum: n,
      srcIntf: egress ? vdom : 'any', dstIntf: egress ? 'any' : vdom, src: egress ? 'any' : peer, dst: egress ? peer : 'any',
      service: ociService(r), action: 'accept', actionRaw: 'allow',
      comment: [r.isStateless ? '無狀態（回應流量需另有規則）' : '', r.description || ''].filter(Boolean).join('：'),
    });
  }
  function parseOci(lists, nsgRuleSets, out) {
    lists.forEach(l => {
      const vdom = l.displayName || l.id || 'security-list';
      out.vdoms.push(vdom);
      (l.ingressSecurityRules || []).forEach((r, i) => out.policies.push(ociRule(r, false, vdom, i + 1, out)));
      (l.egressSecurityRules || []).forEach((r, i) => out.policies.push(ociRule(r, true, vdom, i + 1, out)));
      out.groups.push({ name: vdom, id: l.id || '-', vpc: l.vcnId || '-', desc: 'OCI 安全清單', tag: '', type: 'security-list' });
    });
    nsgRuleSets.forEach((rules, k) => {
      const vdom = nsgRuleSets.length > 1 ? `oci-nsg-${k + 1}` : 'oci-nsg';
      out.vdoms.push(vdom);
      let ni = 0, ne = 0;
      [...rules].sort((a, b) => (a.direction === 'EGRESS' ? 1 : 0) - (b.direction === 'EGRESS' ? 1 : 0)).forEach(r => {
        const eg = r.direction === 'EGRESS';
        const p = ociRule(r, eg, vdom, eg ? ++ne : ++ni, out);
        if (r.isValid === false) p.status = 'disable';
        out.policies.push(p);
      });
      out.groups.push({ name: vdom, id: '-', vpc: '-', desc: `OCI NSG 規則 ${rules.length} 筆（規則清單不含 NSG 名稱）`, tag: '', type: 'network-security-group' });
    });
  }

  // ── Kubernetes NetworkPolicy ─────────────────────────────
  function k8sSel(sel) {
    if (!sel || typeof sel !== 'object') return '';
    const parts = Object.entries(sel.matchLabels || {}).map(([k, v]) => `${k}=${v}`);
    (sel.matchExpressions || []).forEach(e => parts.push(`${e.key} ${e.operator}${e.values && e.values.length ? ' (' + e.values.join(',') + ')' : ''}`));
    return parts.join(',');
  }
  function k8sPeer(p, ns, vdom, out) {
    if (p.ipBlock && p.ipBlock.cidr) {
      const ex = (p.ipBlock.except || []).map(String);
      if (!ex.length) return String(p.ipBlock.cidr);
      const name = `ipBlock:${p.ipBlock.cidr} except ${ex.join(',')}`;
      out.refs.set(vdom + '/' + name, { ...refObj(name, 'ipBlock（扣除 except 網段）', vdom), members: String(p.ipBlock.cidr), excludeMembers: ex.join(',') });
      return name;
    }
    const nsPart = p.namespaceSelector ? `ns(${k8sSel(p.namespaceSelector) || '全部'})` : '';
    const podPart = p.podSelector ? `pods(${k8sSel(p.podSelector) || '全部'})` : '';
    const name = nsPart && podPart ? `${nsPart}/${podPart}` : nsPart || `${ns}/${podPart || 'pods(全部)'}`;
    out.refs.set(vdom + '/' + name, refObj(name, nsPart ? '符合標籤的 namespace 內的 Pod（成員不在此檔）' : `namespace ${ns} 內符合標籤的 Pod（成員不在此檔）`, vdom));
    return name;
  }
  function k8sService(ports) {
    if (!Array.isArray(ports) || !ports.length) return { svc: 'ALL', named: [] };
    const svc = [], named = [];
    ports.forEach(p => {
      const proto = String(p.protocol || 'TCP').toLowerCase();
      if (p.port == null) { svc.push(`${proto}/0-65535`); return; }
      if (typeof p.port === 'string' && !/^\d+$/.test(p.port)) { named.push(`${proto}/${p.port}`); svc.push(`${proto}/0-65535`); return; }
      svc.push(p.endPort != null ? `${proto}/${p.port}-${p.endPort}` : `${proto}/${p.port}`);
    });
    return { svc: svc.join(', '), named };
  }
  function parseK8sNetPol(pols, out) {
    const byNs = new Map();
    pols.forEach(p => { const ns = (p.metadata && p.metadata.namespace) || 'default'; if (!byNs.has(ns)) byNs.set(ns, []); byNs.get(ns).push(p); });
    for (const [ns, list] of byNs) {
      const vdom = ns;
      out.vdoms.push(vdom);
      const allow = { ingress: [], egress: [] }, deny = { ingress: [], egress: [] };
      list.forEach(pol => {
        const name = (pol.metadata && pol.metadata.name) || 'networkpolicy';
        const sp = pol.spec;
        const selName = `${ns}/pods(${k8sSel(sp.podSelector) || '全部'})`;
        out.refs.set(vdom + '/' + selName, refObj(selName, `NetworkPolicy ${name} 選取的 Pod（成員不在此檔）`, vdom));
        const types = Array.isArray(sp.policyTypes) && sp.policyTypes.length ? sp.policyTypes.map(String) : ['Ingress', ...(sp.egress ? ['Egress'] : [])];
        ['ingress', 'egress'].forEach(dir => {
          if (!types.some(t => t.toLowerCase() === dir)) return;
          const eg = dir === 'egress';
          (sp[dir] || []).forEach((r, i) => {
            const peers = r[eg ? 'to' : 'from'];
            const pl = Array.isArray(peers) && peers.length ? peers.map(p => k8sPeer(p || {}, ns, vdom, out)) : ['any'];
            const { svc, named } = k8sService(r.ports);
            allow[dir].push({ name: `${name}/${dir}-${i + 1}`, src: eg ? selName : pl.join(', '), dst: eg ? pl.join(', ') : selName, svc,
              comment: named.length ? `具名埠 ${named.join(', ')}（對應容器埠名稱，以全部埠表示）` : '' });
          });
          deny[dir].push({ name: `${name}/${dir}-default-deny`, src: eg ? selName : 'any', dst: eg ? 'any' : selName, svc: 'ALL',
            comment: `被 ${name} 選取的 Pod：其他${eg ? '出站' : '入站'}流量拒絕（所有選取同一 Pod 的政策都沒有允許時）` });
        });
      });
      const push = (r, dir, action, n) => {
        const eg = dir === 'egress';
        const p = basePolicy({ id: out.policies.length + 1, name: r.name, vdom, chain: eg ? 'EGRESS' : 'INGRESS', ruleNum: n,
          srcIntf: eg ? vdom : 'any', dstIntf: eg ? 'any' : vdom, src: r.src, dst: r.dst, service: r.svc, action, actionRaw: action === 'accept' ? 'allow' : 'deny', comment: r.comment });
        if (action === 'deny') p.platformRule = true;
        out.policies.push(p);
      };
      let n = 0;
      ['ingress', 'egress'].forEach(dir => allow[dir].forEach(r => push(r, dir, 'accept', ++n)));
      ['ingress', 'egress'].forEach(dir => deny[dir].forEach(r => push(r, dir, 'deny', ++n)));
      out.groups.push({ name: vdom, id: '-', vpc: '-', desc: `NetworkPolicy ${list.length} 筆：${list.map(p => (p.metadata && p.metadata.name) || '-').join(', ')}`, tag: '', type: 'network-policy' });
    }
  }

  // ── Azure Firewall Policy ───────────────────────────────
  function azfwAddr(list, vdom, out, note, type) {
    const vals = [];
    (list || []).forEach(v => {
      const raw = String(v);
      if (raw === '*') { vals.push('any'); return; }
      const name = /^\/subscriptions\//i.test(raw) ? raw.split('/').pop() : raw;
      vals.push(name);
      if (/^[\d.:a-fA-F/]+$/.test(name) && /\d/.test(name)) return;
      out.refs.set(vdom + '/' + name, type === 'fqdn' ? { ...refObj(name, note, vdom), category: 'address', type: 'fqdn', fqdn: name } : refObj(name, note, vdom));
    });
    return vals;
  }
  function azfwPorts(proto, ports) {
    const p = String(proto).toLowerCase();
    const list = (ports || []).map(String);
    const any = !list.length || list.includes('*');
    if (p === 'any') return any ? ['ALL'] : list.flatMap(x => [`tcp/${x}`, `udp/${x}`]);
    if (p === 'tcp' || p === 'udp') return any ? [`${p}/0-65535`] : list.map(x => `${p}/${x}`);
    return [p === 'icmp' ? 'icmp' : p];
  }
  function parseAzureFwPolicy(groups, out) {
    const rows = [], vdoms = new Set();
    groups.forEach(g => {
      const gp = azRcgProps(g), id = String(g.id || '');
      const vdom = (id.match(/\/firewallPolicies\/([^/]+)/i) || [])[1] || 'firewallPolicy';
      vdoms.add(vdom);
      if (!out.vdoms.includes(vdom)) { out.vdoms.push(vdom); out.groups.push({ name: vdom, id: '-', vpc: '-', desc: 'Azure Firewall Policy', tag: '', type: 'firewall-policy' }); }
      (gp.ruleCollections || []).forEach(c => {
        const act = String((c.action && c.action.type) || '').toLowerCase();
        (c.rules || []).forEach((r, i) => rows.push({ vdom, group: g.name || '-', gPri: +gp.priority || 0, coll: c.name || '-', cPri: +c.priority || 0, act, r, i }));
      });
    });
    const rank = r => ({ NatRule: 0, NetworkRule: 1, ApplicationRule: 2 })[r.ruleType] ?? 3;
    rows.sort((a, b) => a.vdom.localeCompare(b.vdom) || rank(a.r) - rank(b.r) || a.gPri - b.gPri || a.cPri - b.cPri || a.i - b.i);
    rows.forEach(({ vdom, group, gPri, coll, cPri, act, r }) => {
      const src = [...azfwAddr(r.sourceAddresses, vdom, out, ''), ...azfwAddr(r.sourceIpGroups, vdom, out, 'Azure IP Group（成員不在此檔）')];
      if (r.ruleType === 'NatRule') {
        const dst = (r.destinationAddresses || [])[0] || '-';
        out.nat.push({ type: 'vip', name: r.name || '-', vipType: 'dnat', poolType: 'destination', extIp: dst, mapIp: r.translatedAddress || r.translatedFqdn || '-',
          extIntf: '-', srcIntf: '-', startIp: '-', endIp: '-', portFwd: 'enable', extPort: (r.destinationPorts || []).join(',') || '-', mapPort: r.translatedPort || '-',
          proto: (r.ipProtocols || []).join(',').toLowerCase() || '-', status: 'enable', comment: `${group}/${coll}；允許來源：${src.join(', ') || 'any'}`, _vdom: vdom });
        return;
      }
      let dst, svc;
      if (r.ruleType === 'ApplicationRule') {
        dst = [...azfwAddr(r.targetFqdns, vdom, out, 'FQDN', 'fqdn'), ...azfwAddr(r.targetUrls, vdom, out, 'URL（TLS 檢查）', 'fqdn'), ...azfwAddr(r.fqdnTags, vdom, out, 'FQDN 標籤（成員由 Azure 決定）'),
          ...azfwAddr(r.webCategories, vdom, out, '網頁分類（由 Azure 判定）'), ...azfwAddr(r.destinationAddresses, vdom, out, '')];
        svc = (r.protocols || []).map(p => `tcp/${p.port || ({ http: 80, https: 443, mssql: 1433 })[String(p.protocolType).toLowerCase()] || '0-65535'}`);
      } else {
        dst = [...azfwAddr(r.destinationAddresses, vdom, out, ''), ...azfwAddr(r.destinationIpGroups, vdom, out, 'Azure IP Group（成員不在此檔）'), ...azfwAddr(r.destinationFqdns, vdom, out, 'FQDN', 'fqdn')];
        svc = (r.ipProtocols || ['Any']).flatMap(p => azfwPorts(p, r.destinationPorts));
      }
      const asAny = l => (!l.length || l.includes('any') ? 'any' : [...new Set(l)].join(', '));
      out.policies.push(basePolicy({
        id: out.policies.length + 1, name: r.name || '-', vdom, chain: `${group}/${coll}`, ruleNum: `${gPri}/${cPri}`,
        srcIntf: 'any', dstIntf: 'any', src: asAny(src), dst: asAny(dst), service: svc.includes('ALL') || !svc.length ? 'ALL' : [...new Set(svc)].join(', '),
        action: act === 'allow' ? 'accept' : 'deny', actionRaw: act, comment: [r.ruleType === 'ApplicationRule' ? '應用規則' : '', r.description || ''].filter(Boolean).join('：'),
      }));
    });
    vdoms.forEach(vdom => {
      const pol = basePolicy({ id: out.policies.length + 1, name: 'default-deny', vdom, chain: 'implicit', ruleNum: '-', srcIntf: 'any', dstIntf: 'any',
        src: 'any', dst: 'any', service: 'ALL', action: 'deny', actionRaw: 'deny', comment: '隱含規則：未命中任何規則一律拒絕' });
      pol.platformRule = true;
      out.policies.push(pol);
    });
  }

  // ── Meraki ───────────────────────────────────────────────
  const csv = v => String(v == null ? '' : v).split(',').map(x => x.trim()).filter(Boolean);
  const isAny = v => !csv(v).length || csv(v).some(x => /^any$/i.test(x));
  function mkAddr(v, out) {
    if (isAny(v)) return 'any';
    const vals = csv(v);
    vals.forEach(x => {
      if (/^[\d.:a-fA-F/]+$/.test(x) && /\d/.test(x)) return;
      out.refs.set('/' + x, { ...refObj(x, 'Meraki 目的 FQDN', ''), category: 'address', type: 'fqdn', fqdn: x });
    });
    return vals.join(', ');
  }
  function mkService(proto, ports) {
    const p = String(proto || 'any').toLowerCase();
    const list = isAny(ports) ? [] : csv(ports);
    if (p === 'any') return list.length ? list.flatMap(x => [`tcp/${x}`, `udp/${x}`]).join(', ') : 'ALL';
    if (p === 'tcp' || p === 'udp') return list.length ? list.map(x => `${p}/${x}`).join(', ') : `${p}/0-65535`;
    return p === 'icmp6' ? 'icmpv6' : p;
  }
  function parseMeraki(m, out) {
    m.l3.forEach((r, i) => {
      const pol = basePolicy({
        id: out.policies.length + 1, name: r.comment || `L3-${i + 1}`, chain: 'L3', ruleNum: i + 1,
        srcIntf: 'any', dstIntf: 'any', src: mkAddr(r.srcCidr, out), dst: mkAddr(r.destCidr, out),
        service: mkService(r.protocol, r.destPort), action: /^allow$/i.test(r.policy || '') ? 'accept' : 'deny', actionRaw: r.policy || '',
        comment: r.comment || '', srcPort: isAny(r.srcPort) ? '' : csv(r.srcPort).join(','),
      });
      if (r.syslogEnabled) pol.logtraffic = 'all';
      out.policies.push(pol);
    });
    const allowed = a => (Array.isArray(a) && a.length ? a : ['any']).join(', ');
    m.pf.forEach((r, i) => out.nat.push({
      type: 'vip', name: r.name || `PF-${i + 1}`, vipType: 'port-forward', poolType: 'destination', extIp: r.uplink || '-', mapIp: r.lanIp || '-',
      extIntf: r.uplink || '-', srcIntf: '-', startIp: '-', endIp: '-', portFwd: 'enable', extPort: r.publicPort || '-', mapPort: r.localPort || '-',
      proto: r.protocol || '-', status: 'enable', comment: '允許來源：' + allowed(r.allowedIps),
    }));
    m.nat11.forEach((r, i) => {
      const inb = Array.isArray(r.allowedInbound) ? r.allowedInbound : [];
      out.nat.push({
        type: 'vip', name: r.name || `1to1-${i + 1}`, vipType: 'static', poolType: 'destination', extIp: r.publicIp || '-', mapIp: r.lanIp || '-',
        extIntf: r.uplink || '-', srcIntf: '-', startIp: '-', endIp: '-', portFwd: 'disable', extPort: inb.flatMap(a => a.destinationPorts || []).join(',') || '-', mapPort: '-',
        proto: [...new Set(inb.map(a => a.protocol).filter(Boolean))].join(',') || '-', status: 'enable',
        comment: inb.length ? '允許來源：' + [...new Set(inb.flatMap(a => a.allowedIps || []))].join(', ') : '',
      });
    });
    m.vlan.forEach(v => {
      const bits = parseInt(String(v.subnet || '').split('/')[1], 10);
      const mask = Number.isFinite(bits) ? [24, 16, 8, 0].map(sh => ((bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0) >>> sh) & 255).join('.') : '-';
      const v6 = ((v.ipv6 && v.ipv6.prefixAssignments) || []).map(p => p.staticApplianceIp6).filter(Boolean);
      out.ifaces.push({ name: `VLAN ${v.id}`, ip: v.applianceIp || '-', mask, ip6: v6[0] || '-', secondaryIps: [], type: 'vlan', vlanId: String(v.id || '-'),
        alias: v.name || '', desc: v.dhcpHandling || '', status: 'up', mtu: '-', speed: '-', mode: '-', vdom: '', role: 'lan', allowaccess: '-' });
    });
    m.route.forEach((r, i) => out.routes.push({
      type: r.subnet === '0.0.0.0/0' ? 'default' : 'static', id: String(i + 1), dst: r.subnet || '-', gateway: r.gatewayIp || '-', device: '-',
      distance: '-', priority: '-', blackhole: 'disable', vrf: 'main', status: r.enabled === false ? 'disable' : 'enable', comment: r.name || '',
      protocol_detail: '-', _vdom: '',
    }));
  }

  function parse(text) {
    const d = loadAll(text);
    const { aws, az, gcp, nacl, azfw, gcpPol, k8s, oci, ociNsg } = collect(d || {});
    const mk = collectMeraki(d || {});
    const out = { policies: [], refs: new Map(), vdoms: [], groups: [], nat: [], ifaces: [], routes: [] };
    parseAws(aws, out);
    parseNacl(nacl, out);
    parseAzure(az, out);
    parseGcp(gcp, out);
    parseAzureFwPolicy(azfw, out);
    parseGcpPolicy(gcpPol, out);
    parseK8sNetPol(k8s, out);
    parseOci(oci, ociNsg, out);
    parseMeraki(mk, out);
    const kinds = [aws.length && 'AWS Security Group', nacl.length && 'AWS Network ACL', az.length && 'Azure NSG', gcp.length && 'GCP VPC Firewall', azfw.length && 'Azure Firewall Policy', gcpPol.length && 'GCP Network Firewall Policy', k8s.length && 'Kubernetes NetworkPolicy', oci.length && 'OCI Security List', ociNsg.length && 'OCI NSG', merakiCount(mk) && 'Cisco Meraki MX'].filter(Boolean);
    const vendor = kinds.length === 1 ? kinds[0] : 'Cloud Security Group';
    const vpcs = [...new Set(out.groups.map(g => g.vpc).filter(v => v && v !== '-'))];
    return {
      vendor,
      deviceInfo: { vendor, hostname: '-', firmware: '-', model: vpcs.join(', ') || '-', serial: '-', vdom: out.vdoms },
      // 安全群組沒有介面；以群組本身列在介面頁，方便看出各群組套用範圍與說明
      interfaces: out.groups.map(g => ({ name: g.name, ip: '-', mask: '-', secondaryIps: [], type: g.type || 'security-group', vlanId: '-', alias: g.tag || g.id,
        desc: g.desc, status: 'up', mtu: '-', speed: '-', mode: '-', vdom: g.name, role: '-', allowaccess: '-' })).concat(out.ifaces),
      policies: out.policies, routes: out.routes, ha: null, nat: out.nat, vpn: [], addresses: [...out.refs.values()], services: [], users: [], schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      dhcp: null, dns: null, snmp: null, logservers: null, wwan: null, wlan: null,
    };
  }

  return { parse, detect, _loadJson: loadJson, _loadAll: loadAll, _yamlLite: yamlLite };
})();
