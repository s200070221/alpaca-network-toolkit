// anon-core.js — 去識別化頁與 log 工具共用的位址替換核心（RV16 第 5 階段）
// 原本 config-anonymizer.html 與 log-analyzer-anon.js 各有一份，規則相同但分別修正（曾出現一邊修了 0.0.0.0、
// 另一邊沒同步）。這裡只收兩邊行為相同的部分：IPv4 驗證與分類、IPv4／IPv6 假位址配發、保留網段結構。
// 主機名稱、帳號、MAC 的假值格式兩邊不同（device-001／host-001 等），仍各自維護。
// 狀態（mappings、計數器等）由各工具持有，以 AnonCore.create(state) 綁定後取得函式組。以 window.AnonCore 對外。
(function () {
  const IPV4_SHAPE_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  // 允許零填補（010.020.030.040）：IPv4_RE 會比對到這種寫法，判為無效會讓真實位址原樣輸出
  function isValidIPv4(s) {
    if (!IPV4_SHAPE_RE.test(s)) return false;
    return s.split('.').every(p => +p <= 255);
  }
  // 回傳假位址所屬的 RFC 5737 網段代碼：n1＝192.0.2（192.168）、n2＝198.51.100（10）、n3＝203.0.113（172.16-31 與公網）
  function classifyIP(ip) {
    const [a, b] = ip.split('.').map(Number);
    // 0 開頭（0.0.0.0 預設路由／任意位址、0.0.0.255 萬用遮罩）、127、多播與保留位址不是主機位址，保留原樣
    if (a === 0 || a === 127 || a >= 224) return 'skip';
    if (a === 10) return 'n2';
    if (a === 172 && b >= 16 && b <= 31) return 'n3';
    if (a === 192 && b === 168) return 'n1';
    return 'n3';
  }
  // IPv6 正規化：同一位址的不同寫法（大小寫、前導零、:: 縮寫）轉成 8 組小寫、去前導零；無法解析回傳 null
  function canonIPv6(ip) {
    const s = String(ip).toLowerCase();
    if (!/^[0-9a-f:]+$/.test(s) || (s.match(/::/g) || []).length > 1) return null;
    let parts;
    if (s.includes('::')) {
      const [a, b] = s.split('::');
      const head = a ? a.split(':') : [], tail = b ? b.split(':') : [];
      const fill = 8 - head.length - tail.length;
      if (fill < 1) return null;
      parts = [...head, ...Array(fill).fill('0'), ...tail];
    } else parts = s.split(':');
    if (parts.length !== 8 || parts.some(p => !/^[0-9a-f]{1,4}$/.test(p))) return null;
    return parts.map(p => p.replace(/^0+(?=.)/, '')).join(':');
  }

  // ── 保留網段結構：第 1、2 段整組換成假 /16、第 3 段在同一假 /16 內一對一換掉、第 4 段保留；0／255 原樣保留。
  // 同一個 /8、/12、/16、/24（與更小的網段）換完仍在同一個假網段內；/17-/23 這類不在段落邊界的網段無法保證。
  // 假位址放在 241-253 開頭（Class E 保留位址，真實設定不會出現），248／252 為遮罩值不使用
  const SUBNET_PUB_FIRST = [244, 245, 246, 247, 249, 250, 251, 253];
  const SUBNET_FAKE_RE = /^(?:24[1-7]|249|25[013])\.\d+\.\d+\.\d+$/;
  const octetCandidates = v => v === 0 || v === 255 ? [v] : Array.from({ length: 254 }, (_, i) => i + 1);
  let subnetPubCands = null;
  function subnetAlloc(map, used, key, cands) {
    if (map.has(key)) return map.get(key);
    const v = cands.find(c => !used.has(c));
    if (v === undefined) return null;
    map.set(key, v); used.add(v);
    return v;
  }

  // st：{ mappings:{ip:Map}, ctrs:{n1,n2,n3,ip6}, stats:{ip}, anonOutputIPs:Set, srcIPv4:Set, srcIPv6:Set,
  //       subnetMaps:{top,topUsed,oct3,oct3Used}, bucketSeen:{n1,n2,n3} }（各工具自己的物件，函式直接讀寫）
  function create(st) {
    const { mappings, ctrs, stats, anonOutputIPs, srcIPv4, srcIPv6, subnetMaps, bucketSeen } = st;
    function anonIPSubnet(ip) {
      const [a, b, c, d] = ip.split('.').map(Number);
      let cands;
      if (a === 10) cands = octetCandidates(b).map(x => '241.' + x);
      else if (a === 172 && b >= 16 && b <= 31) cands = Array.from({ length: 16 }, (_, i) => '242.' + (16 + i));
      else if (a === 192 && b === 168) cands = ['243.168'];
      else {
        if (!subnetPubCands) subnetPubCands = SUBNET_PUB_FIRST.flatMap(f => Array.from({ length: 254 }, (_, i) => f + '.' + (i + 1)));
        cands = subnetPubCands;
      }
      const top = subnetAlloc(subnetMaps.top, subnetMaps.topUsed, a + '.' + b, cands);
      if (!top) return null; // 假網段用完，退回逐一對應
      const o3 = subnetAlloc(subnetMaps.oct3, subnetMaps.oct3Used, top + '|' + c, octetCandidates(c).map(x => top + '.' + x));
      return o3 ? o3 + '.' + d : null;
    }
    // 匯入對照表時把保留網段結構的假位址寫回配置表，之後新位址沿用同一組假網段
    function registerSubnetMapping(orig, mapped) {
      if (!isValidIPv4(orig) || !SUBNET_FAKE_RE.test(mapped)) return false;
      const [a, b, c] = orig.split('.').map(Number);
      const [x, y, z] = mapped.split('.');
      const top = x + '.' + y, k = a + '.' + b;
      if (!subnetMaps.top.has(k)) { subnetMaps.top.set(k, top); subnetMaps.topUsed.add(top); }
      if (subnetMaps.top.get(k) === top && !subnetMaps.oct3.has(top + '|' + c)) {
        subnetMaps.oct3.set(top + '|' + c, top + '.' + z); subnetMaps.oct3Used.add(top + '.' + z);
      }
      return true;
    }
    // opts.preserveSubnet：保留網段結構；opts.preserveLastOctet：保留末段（不同網段末段相同的位址會換成同一個假位址）
    function anonIP(ip, opts) {
      const hit = mappings.ip.get(ip);
      if (hit !== undefined) return hit;
      if (!isValidIPv4(ip)) return ip;
      const cls = classifyIP(ip);
      if (cls === 'skip') return ip;
      // 已配發的假位址不再換一次（同一段文字處理兩次，如 MikroTik 兩段式處理）
      if (anonOutputIPs.has(ip)) return ip;
      const sub = opts && opts.preserveSubnet ? anonIPSubnet(ip) : null;
      if (sub) {
        mappings.ip.set(ip, sub);
        anonOutputIPs.add(sub);
        stats.ip++;
        return sub;
      }
      bucketSeen[cls].add(ip);
      const lastPart = opts && opts.preserveLastOctet ? Number(ip.split('.')[3]) : null;
      let mapped;
      const pre = cls === 'n1' ? '192.0.2.' : cls === 'n2' ? '198.51.100.' : '203.0.113.';
      // 保留末段時若假位址剛好是原檔已有的位址，改用一般配發（否則兩台主機變成同一個位址）
      if (lastPart != null && !srcIPv4.has(pre + lastPart)) mapped = pre + lastPart;
      else for (let i = 0; i < 254; i++) { ctrs[cls] = (ctrs[cls] % 254) + 1; mapped = pre + ctrs[cls]; if (!srcIPv4.has(mapped)) break; }
      mappings.ip.set(ip, mapped);
      anonOutputIPs.add(mapped);
      stats.ip++;
      return mapped;
    }
    function anonIPv6(ip) {
      if (mappings.ip.has(ip)) return mappings.ip.get(ip);
      // 已配發的假值不再換一次（同一段文字處理兩次時 2001:db8::1 會再被換成 ::2）
      if (anonOutputIPs.has(String(ip).toLowerCase())) return ip;
      // 映射表裡已有同一位址的其他寫法時沿用同一個假值（匯入的對照表種子與批次共用映射也適用）
      const c = canonIPv6(ip);
      if (c) {
        for (const [k, v] of mappings.ip) {
          if (k.includes(':') && canonIPv6(k) === c) { mappings.ip.set(ip, v); return v; }
        }
      }
      // 原檔本身含 2001:db8::N 時跳過，避免兩個位址配到同一個假值
      let mapped;
      for (let i = 0; i < 1000; i++) { ctrs.ip6++; mapped = `2001:db8::${ctrs.ip6}`; if (!srcIPv6.has(mapped)) break; }
      mappings.ip.set(ip, mapped);
      anonOutputIPs.add(mapped);
      stats.ip++;
      return mapped;
    }
    return { anonIP, anonIPSubnet, registerSubnetMapping, anonIPv6 };
  }

  (typeof window !== 'undefined' ? window : globalThis).AnonCore = { isValidIPv4, classifyIP, canonIPv6, SUBNET_FAKE_RE, create };
})();
