// 離線使用的 service worker（2026-10-22，第三十三輪 XN2）
// 只在 https 且非本機開發主機時由 toolkit-version.js 註冊（GitHub Pages 或自架 https 站），file:// 與 localhost 不使用。
// 策略：連網時一律先取網路並更新快取（不會讀到舊版），取不到才用快取；安裝時預先快取下方全部檔案，
// 開過任一頁之後斷網也能使用所有工具。
// CACHE 含版本號：發版改 TOOLKIT_VERSION 時一併改這裡（qa/test_config/test_pwa.mjs 檢查兩者一致），
// sw.js 內容改變會讓瀏覽器安裝新版並重新快取整套檔案，舊快取在 activate 時刪除。
// FILES 須涵蓋 7 個頁面以 <script src> 載入的全部檔案（test_pwa.mjs 檢查）。
const CACHE = 'alpaca-toolkit-2026.10.30';
const FILES = [
  './',
  'index.html',
  'network-analyzer.html',
  'config-anonymizer.html',
  'firewall-analyzer-fixed.html',
  'switch-config-parser.html',
  'switch-config-generator.html',
  'log-analyzer.html',
  'threat-intel-builder.html',
  'manifest.webmanifest',
  'icon-192.png',
  'icon-512.png',
  'firewall-analyzer-app.js',
  'firewall-analyzer-audit.js',
  'firewall-analyzer-converter.js',
  'firewall-analyzer-core.js',
  'firewall-analyzer-eggs.js',
  'firewall-analyzer-i18n.js',
  'firewall-analyzer-models.js',
  'firewall-analyzer-parser-checkpoint.js',
  'firewall-analyzer-parser-cisco-asa.js',
  'firewall-analyzer-parser-cloud.js',
  'firewall-analyzer-parser-edgerouter.js',
  'firewall-analyzer-parser-fortigate.js',
  'firewall-analyzer-parser-h3c.js',
  'firewall-analyzer-parser-juniper.js',
  'firewall-analyzer-parser-mikrotik.js',
  'firewall-analyzer-parser-netfilter.js',
  'firewall-analyzer-parser-openwrt.js',
  'firewall-analyzer-parser-paloalto.js',
  'firewall-analyzer-parser-pfsense.js',
  'firewall-analyzer-parser-sonicwall.js',
  'firewall-analyzer-parser-sophos.js',
  'firewall-analyzer-parser-tnsr.js',
  'firewall-analyzer-parser-vyos.js',
  'firewall-analyzer-parser-watchguard.js',
  'firewall-analyzer-parser-wlc.js',
  'firewall-analyzer-parser-zyxel.js',
  'firewall-analyzer-pathchain.js',
  'firewall-analyzer-portmap.js',
  'firewall-analyzer-reporter.js',
  'firewall-analyzer-sections.js',
  'firewall-analyzer-wifi-parser.js',
  'switch-analyzer-app.js',
  'switch-analyzer-audit.js',
  'switch-analyzer-core.js',
  'switch-analyzer-diff.js',
  'switch-analyzer-endpoint.js',
  'switch-analyzer-explain.js',
  'switch-analyzer-i18n.js',
  'switch-analyzer-inventory.js',
  'switch-analyzer-parser-alcatel.js',
  'switch-analyzer-parser-arista.js',
  'switch-analyzer-parser-aruba-cx.js',
  'switch-analyzer-parser-awplus.js',
  'switch-analyzer-parser-brocade.js',
  'switch-analyzer-parser-cisco.js',
  'switch-analyzer-parser-comware.js',
  'switch-analyzer-parser-cumulus.js',
  'switch-analyzer-parser-dell-os10.js',
  'switch-analyzer-parser-edgeswitch.js',
  'switch-analyzer-parser-efos.js',
  'switch-analyzer-parser-extreme.js',
  'switch-analyzer-parser-fortiswitch.js',
  'switch-analyzer-parser-juniper.js',
  'switch-analyzer-parser-netgear.js',
  'switch-analyzer-parser-netgearsmart.js',
  'switch-analyzer-parser-nxos.js',
  'switch-analyzer-parser-planet.js',
  'switch-analyzer-parser-procurve.js',
  'switch-analyzer-parser-routeros.js',
  'switch-analyzer-parser-ruijie.js',
  'switch-analyzer-parser-sonic.js',
  'switch-analyzer-parser-voss.js',
  'switch-analyzer-topology.js',
  'switch-generator-alcatel.js',
  'switch-generator-app.js',
  'switch-generator-arista.js',
  'switch-generator-aruba-cx.js',
  'switch-generator-brocade.js',
  'switch-generator-cisco.js',
  'switch-generator-comware.js',
  'switch-generator-core.js',
  'switch-generator-dell-os10.js',
  'switch-generator-edgeswitch.js',
  'switch-generator-extreme.js',
  'switch-generator-fortiswitch.js',
  'switch-generator-i18n.js',
  'switch-generator-juniper.js',
  'switch-generator-models.js',
  'switch-generator-netgear.js',
  'switch-generator-nxos.js',
  'switch-generator-planet.js',
  'switch-generator-portmap.js',
  'switch-generator-procurve.js',
  'switch-generator-routeros.js',
  'switch-generator-ruijie.js',
  'switch-generator-sonic.js',
  'switch-generator-validate.js',
  'switch-generator-zip.js',
  'toolkit-version.js',
  'vuln-check.js',
  'vuln-seed.js',
  'payload-sniff.js',
  'alpaca-buddy.js',
  'file-howto.js',
  'https://cdn.jsdelivr.net/npm/docx@8.6.0/build/index.umd.js',
];
const EXTERNAL = new Set(FILES.filter(f => /^https:/.test(f)));

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES.map(f => new Request(f, { cache: 'reload' })))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k.startsWith('alpaca-toolkit-') && k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin && !EXTERNAL.has(req.url)) return;
  e.respondWith(fetch(req).then(res => {
    if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }
    return res;
  }).catch(() => caches.match(req, { ignoreSearch: true }).then(r => r || (req.mode === 'navigate' ? caches.match('index.html') : Response.error()))));
});
