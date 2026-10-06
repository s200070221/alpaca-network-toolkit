// ═══ parser-wlc.js ═══
/**
 * 無線控制器設定檔（2026-10-05，第十一輪 KD／KH／KI）
 * Cisco Catalyst 9800／AireOS、Aruba Mobility Controller／Instant、H3C WX。
 * 這類設定檔沒有防火牆規則，此處只回傳空的防火牆資料形狀與裝置資訊，
 * SSID 解析由 firewall-analyzer-wifi-parser.js 的 parseWlcWifi() 負責（app 依 ST.raw.l 呼叫）。
 */
const WlcParser = (() => {
  const LABEL = { cisco9800: 'Cisco Catalyst 9800', aireos: 'Cisco AireOS WLC', aruba: 'Aruba Mobility Controller', instant: 'Aruba Instant', h3cwx: 'H3C WX' };

  function kind(text) {
    const k = detectWlcKind(text);
    if (k === 'aruba' && /^\s*virtual-controller-(?:ip|country|key)\b|IAP (?:MAC Address|Serial Number)/m.test(text)) return 'instant';
    return k;
  }

  function detect(text) { return !!detectWlcKind(text); }

  function hostname(text, k) {
    const re = { cisco9800: /^hostname\s+(\S+)/m, aireos: /^(?:config\s+)?sysname\s+(\S+)/m, aruba: /^hostname\s+"?([^"\n]+)"?/m,
      instant: /^name\s+(\S+)/m, h3cwx: /^\s*sysname\s+(\S+)/m }[k];
    const m = re && re.exec(text);
    return m ? m[1].trim() : '-';
  }

  function firmware(text, k) {
    const m = (k === 'cisco9800' && /^version\s+(\S+)/m.exec(text))
      || ((k === 'aruba' || k === 'instant') && (/^#\s*ArubaOS \(MODEL: [^)]+\), Version\s+(\S+)/m.exec(text) || /^version\s+(\S+)/m.exec(text)))
      || (k === 'h3cwx' && /^\s*version\s+(\S+)/m.exec(text));
    return m ? m[1].replace(/,$/, '') : '-';
  }

  function parse(text) {
    const k = kind(text);
    const vendor = LABEL[k] || 'Wireless LAN Controller';
    return {
      vendor, _wlc: true,
      deviceInfo: { vendor, hostname: hostname(text, k), firmware: firmware(text, k), model: '-', serial: '-', vdom: [] },
      interfaces: [], policies: [], routes: [], ha: null, nat: [], vpn: [], addresses: [], services: [], users: [], schedules: [],
      sdwan: { enabled: false, lbMode: '-', zones: [], members: [], healthChecks: [], services: [], neighbors: [] },
      dhcp: null, dns: null, snmp: null, logservers: null, wwan: null, wlan: null,
    };
  }

  return { parse, detect, kind };
})();
