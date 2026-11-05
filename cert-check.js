// ═══════════════════════════════════════════════════════════════════════════
// cert-check.js — 網站憑證檢查（XN101，入口頁使用）。純函式、不碰 DOM、不連網，以 window.CertCheck 對外。
// 輸入：抓取腳本輸出（fetch_cert_chain.ps1 的 JSON、fetch_cert_chain.sh 的文字）、openssl s_client 輸出或純 PEM。
// 解析 X.509（DER／ASN.1 自行解析，不依賴外部套件），建立信任鏈、以 WebCrypto 驗證每一層簽章，
// 檢查根憑證（cert-roots.js 的 Mozilla 清單＋使用者自備內部根）、效期、加密強度、主機名稱、用途與 TLS 版本。
// 撤銷狀態（OCSP／CRL）需要連網，不檢查，只列出網址。
// ═══════════════════════════════════════════════════════════════════════════
(function (root) {
  'use strict';

  // ── base64／PEM ──
  function b64ToBytes(s) {
    const bin = atob(String(s).replace(/[^A-Za-z0-9+/=]/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64(b) {
    let s = '';
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return btoa(s);
  }
  const PEM_RE = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  function pemBlocks(text) {
    const out = [];
    for (const m of String(text || '').matchAll(PEM_RE)) {
      try { out.push(b64ToBytes(m[1])); } catch (e) { /* 損壞的區塊略過 */ }
    }
    return out;
  }
  function derToPem(der) {
    const b = bytesToB64(der);
    return '-----BEGIN CERTIFICATE-----\n' + b.replace(/.{1,64}/g, '$&\n') + '-----END CERTIFICATE-----\n';
  }
  // 二進位 DER 憑證：SEQUENCE（0x30）且長度為長格式（0x82），整份長度與標頭一致
  function looksLikeDer(bytes) {
    return !!bytes && bytes.length > 16 && bytes[0] === 0x30 && bytes[1] === 0x82 && ((bytes[2] << 8) | bytes[3]) + 4 === bytes.length;
  }
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

  // ── DER 讀取 ──
  function tlv(buf, off) {
    if (off + 2 > buf.length) throw new Error('DER 截斷');
    const tag = buf[off];
    let len = buf[off + 1], p = off + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) throw new Error('DER 長度格式不支援');
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + buf[p + i];
      p += n;
    }
    if (p + len > buf.length) throw new Error('DER 長度超出範圍');
    return { tag, start: off, cs: p, end: p + len };
  }
  function kids(buf, node) {
    const out = [];
    for (let p = node.cs; p < node.end;) { const k = tlv(buf, p); out.push(k); p = k.end; }
    return out;
  }
  const content = (buf, n) => buf.subarray(n.cs, n.end);
  const raw = (buf, n) => buf.subarray(n.start, n.end);
  function oid(buf, n) {
    const b = content(buf, n), parts = [Math.floor(b[0] / 40), b[0] % 40];
    let v = 0;
    for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i] & 0x7f); if (!(b[i] & 0x80)) { parts.push(v); v = 0; } }
    return parts.join('.');
  }
  function str(buf, n) {
    const b = content(buf, n);
    if (n.tag === 0x1e) { let s = ''; for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]); return s; }
    try { return new TextDecoder('utf-8', { fatal: false }).decode(b); } catch (e) { return String.fromCharCode.apply(null, b); }
  }
  function time(buf, n) {
    const s = str(buf, n);
    const m = n.tag === 0x17 ? s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/) : s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/);
    if (!m) return null;
    let y = +m[1];
    if (n.tag === 0x17) y += y < 50 ? 2000 : 1900;
    return Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  }

  const NAME_OID = { '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC' };
  function name(buf, n) {
    const attrs = [];
    for (const rdn of kids(buf, n)) for (const atv of kids(buf, rdn)) {
      const [t, v] = kids(buf, atv);
      const o = oid(buf, t);
      attrs.push([NAME_OID[o] || o, str(buf, v)]);
    }
    return attrs;
  }
  const nameStr = attrs => attrs.map(([k, v]) => k + '=' + v).join(', ');
  const nameGet = (attrs, k) => (attrs.find(a => a[0] === k) || [])[1] || '';

  const SIG_ALGS = {
    '1.2.840.113549.1.1.2': { name: 'md2WithRSA', weak: true },
    '1.2.840.113549.1.1.4': { name: 'md5WithRSA', weak: true },
    '1.2.840.113549.1.1.5': { name: 'sha1WithRSA', weak: true, kind: 'rsa', hash: 'SHA-1' },
    '1.2.840.113549.1.1.14': { name: 'sha224WithRSA', kind: 'rsa' },
    '1.2.840.113549.1.1.11': { name: 'sha256WithRSA', kind: 'rsa', hash: 'SHA-256' },
    '1.2.840.113549.1.1.12': { name: 'sha384WithRSA', kind: 'rsa', hash: 'SHA-384' },
    '1.2.840.113549.1.1.13': { name: 'sha512WithRSA', kind: 'rsa', hash: 'SHA-512' },
    '1.2.840.113549.1.1.10': { name: 'RSASSA-PSS', kind: 'pss' },
    '1.2.840.10045.4.1': { name: 'ecdsa-with-SHA1', weak: true, kind: 'ec', hash: 'SHA-1' },
    '1.2.840.10045.4.3.2': { name: 'ecdsa-with-SHA256', kind: 'ec', hash: 'SHA-256' },
    '1.2.840.10045.4.3.3': { name: 'ecdsa-with-SHA384', kind: 'ec', hash: 'SHA-384' },
    '1.2.840.10045.4.3.4': { name: 'ecdsa-with-SHA512', kind: 'ec', hash: 'SHA-512' },
    '1.3.101.112': { name: 'Ed25519', kind: 'ed25519' },
    '1.3.101.113': { name: 'Ed448' },
  };
  const HASH_OID = { '1.3.14.3.2.26': 'SHA-1', '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512' };
  const CURVES = { '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521' };
  const CURVE_BYTES = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };

  // RSA-PSS 參數：hashAlgorithm [0]、saltLength [2]（預設 SHA-1、20）
  function pssParams(buf, algNode) {
    const r = { hash: 'SHA-1', salt: 20 };
    const k = kids(buf, algNode);
    if (k[1] && k[1].tag === 0x30) for (const p of kids(buf, k[1])) {
      if (p.tag === 0xa0) { const h = kids(buf, kids(buf, p)[0])[0]; r.hash = HASH_OID[oid(buf, h)] || ''; }
      if (p.tag === 0xa2) { const v = content(buf, kids(buf, p)[0]); r.salt = v.reduce((a, x) => a * 256 + x, 0); }
    }
    return r;
  }

  function spkiInfo(buf, spki) {
    const [alg, bits] = kids(buf, spki);
    const ak = kids(buf, alg), o = oid(buf, ak[0]);
    if (o === '1.2.840.113549.1.1.1' || o === '1.2.840.113549.1.1.10') {
      const bs = content(buf, bits), inner = bs.subarray(1);
      const seq = tlv(inner, 0), [mod] = kids(inner, seq);
      let m = content(inner, mod), i = 0;
      while (i < m.length && m[i] === 0) i++;
      m = m.subarray(i);
      const bitsLen = m.length ? (m.length - 1) * 8 + (32 - Math.clz32(m[0])) : 0;
      return { type: 'RSA', bits: bitsLen, pss: o.endsWith('.10') };
    }
    if (o === '1.2.840.10045.2.1') { const c = ak[1] && ak[1].tag === 0x06 ? oid(buf, ak[1]) : ''; return { type: 'EC', curve: CURVES[c] || c || 'unknown', curveOid: c }; }
    if (o === '1.3.101.112') return { type: 'Ed25519' };
    if (o === '1.3.101.113') return { type: 'Ed448' };
    return { type: o };
  }

  const EKU = { '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth', '2.5.29.37.0': 'any' };
  function parseExt(buf, c, extOid, valNode) {
    const v = content(buf, valNode), n = tlv(v, 0);
    switch (extOid) {
      case '2.5.29.17': { // SAN
        c.sanDns = []; c.sanIp = [];
        for (const g of kids(v, n)) {
          if (g.tag === 0x82) c.sanDns.push(str(v, g).toLowerCase());
          else if (g.tag === 0x87) c.sanIp.push(ipStr(content(v, g)));
        }
        break;
      }
      case '2.5.29.19': { // Basic Constraints
        c.bc = { ca: false, pathLen: null };
        for (const k of kids(v, n)) {
          if (k.tag === 0x01) c.bc.ca = content(v, k)[0] !== 0;
          else if (k.tag === 0x02) c.bc.pathLen = content(v, k).reduce((a, x) => a * 256 + x, 0);
        }
        break;
      }
      case '2.5.29.15': { // Key Usage（bit 0 digitalSignature … bit 5 keyCertSign）
        const b = content(v, n);
        c.ku = { keyCertSign: b.length > 1 && !!(b[1] & 0x04), digitalSignature: b.length > 1 && !!(b[1] & 0x80), keyEncipherment: b.length > 1 && !!(b[1] & 0x20) };
        break;
      }
      case '2.5.29.37': c.eku = kids(v, n).map(k => EKU[oid(v, k)] || oid(v, k)); break;
      case '2.5.29.14': c.ski = hex(content(v, n)); break;
      case '2.5.29.35': { const k = kids(v, n).find(x => x.tag === 0x80); if (k) c.aki = hex(content(v, k)); break; }
      case '1.3.6.1.5.5.7.1.1': { // AIA
        for (const ad of kids(v, n)) {
          const [m, loc] = kids(v, ad);
          if (loc.tag !== 0x86) continue;
          const mo = oid(v, m), u = str(v, loc);
          if (mo === '1.3.6.1.5.5.7.48.1') c.ocsp.push(u); else if (mo === '1.3.6.1.5.5.7.48.2') c.caIssuers.push(u);
        }
        break;
      }
      case '2.5.29.31': { // CRL 發布點：取出所有 URI
        const walk = node => { for (const k of kids(v, node)) { if (k.tag === 0x86) c.crl.push(str(v, k)); else if (k.tag & 0x20) walk(k); } };
        walk(n);
        break;
      }
    }
  }
  function ipStr(b) {
    if (b.length === 4) return Array.from(b).join('.');
    if (b.length === 16) { const p = []; for (let i = 0; i < 16; i += 2) p.push(((b[i] << 8) | b[i + 1]).toString(16)); return p.join(':'); }
    return hex(b);
  }

  // DER → 憑證物件；失敗拋例外
  function parseCert(der) {
    const top = tlv(der, 0);
    if (top.tag !== 0x30 || top.end !== der.length) throw new Error('不是 DER 憑證');
    const [tbsN, sigAlgN, sigN] = kids(der, top);
    const f = kids(der, tbsN);
    let i = 0, version = 1;
    if (f[0].tag === 0xa0) { version = content(der, kids(der, f[0])[0])[0] + 1; i = 1; }
    const serialN = f[i], issuerN = f[i + 2], validity = kids(der, f[i + 3]), subjectN = f[i + 4], spkiN = f[i + 5];
    const sigOid = oid(der, kids(der, sigAlgN)[0]);
    const c = {
      der, version,
      serial: hex(content(der, serialN)),
      issuer: name(der, issuerN), subject: name(der, subjectN),
      issuerHex: hex(raw(der, issuerN)), subjectHex: hex(raw(der, subjectN)),
      notBefore: time(der, validity[0]), notAfter: time(der, validity[1]),
      spki: raw(der, spkiN), key: spkiInfo(der, spkiN),
      sigOid, sigAlg: (SIG_ALGS[sigOid] || { name: sigOid }).name,
      pss: sigOid === '1.2.840.113549.1.1.10' ? pssParams(der, sigAlgN) : null,
      tbs: raw(der, tbsN), sig: content(der, sigN).subarray(1),
      sanDns: null, sanIp: null, bc: null, ku: null, eku: null, ski: '', aki: '', ocsp: [], caIssuers: [], crl: [],
    };
    const extWrap = f.slice(i + 6).find(x => x.tag === 0xa3);
    if (extWrap) for (const ext of kids(der, kids(der, extWrap)[0])) {
      const k = kids(der, ext);
      try { parseExt(der, c, oid(der, k[0]), k[k.length - 1]); } catch (e) { /* 個別擴充欄位格式異常不影響其他欄位 */ }
    }
    c.cn = nameGet(c.subject, 'CN') || nameGet(c.subject, 'O') || nameStr(c.subject);
    c.selfIssued = c.subjectHex === c.issuerHex;
    return c;
  }

  // ── 簽章驗證（WebCrypto；不支援的演算法回傳 null）──
  const subtle = () => (root.crypto && root.crypto.subtle) || (typeof crypto !== 'undefined' && crypto.subtle) || null;
  function ecdsaRaw(sig, size) {
    const s = tlv(sig, 0), [r, ss] = kids(sig, s);
    const fix = b => { let x = b; while (x.length > size && x[0] === 0) x = x.subarray(1); const o = new Uint8Array(size); o.set(x, size - x.length); return o; };
    const out = new Uint8Array(size * 2);
    out.set(fix(content(sig, r)), 0); out.set(fix(content(sig, ss)), size);
    return out;
  }
  async function verifySig(child, issuerSpki, issuerKey) {
    const S = subtle();
    const alg = SIG_ALGS[child.sigOid];
    if (!S || !alg || !alg.kind) return null;
    try {
      if (alg.kind === 'rsa' && issuerKey.type === 'RSA') {
        const k = await S.importKey('spki', issuerSpki, { name: 'RSASSA-PKCS1-v1_5', hash: alg.hash }, false, ['verify']);
        return await S.verify('RSASSA-PKCS1-v1_5', k, child.sig, child.tbs);
      }
      if (alg.kind === 'pss' && issuerKey.type === 'RSA' && child.pss && child.pss.hash) {
        const k = await S.importKey('spki', issuerSpki, { name: 'RSA-PSS', hash: child.pss.hash }, false, ['verify']);
        return await S.verify({ name: 'RSA-PSS', saltLength: child.pss.salt }, k, child.sig, child.tbs);
      }
      if (alg.kind === 'ec' && issuerKey.type === 'EC' && CURVE_BYTES[issuerKey.curve]) {
        const k = await S.importKey('spki', issuerSpki, { name: 'ECDSA', namedCurve: issuerKey.curve }, false, ['verify']);
        return await S.verify({ name: 'ECDSA', hash: alg.hash }, k, ecdsaRaw(child.sig, CURVE_BYTES[issuerKey.curve]), child.tbs);
      }
      if (alg.kind === 'ed25519' && issuerKey.type === 'Ed25519') {
        const k = await S.importKey('spki', issuerSpki, { name: 'Ed25519' }, false, ['verify']);
        return await S.verify('Ed25519', k, child.sig, child.tbs);
      }
    } catch (e) { return null; }
    return null;
  }

  // ── 輸入判斷與解析 ──
  const JSON_FMT_RE = /"format"\s*:\s*"alpaca-certchain"/;
  const SH_MARK_RE = /^=== alpaca-certchain host=(\S*) port=(\d*) ===\s*$/m;
  const SCLIENT_RE = /^CONNECTED\(/m;
  // 整份內容才算憑證資料；設定檔夾帶 PEM 時回傳 false（交給原本的工具與去識別化）
  function detectInput(text) {
    const t = String(text || '').replace(/^﻿/, '');
    const head = t.slice(0, 4000).trim();
    if (/^[{[]/.test(head) && JSON_FMT_RE.test(head)) return 'json';
    if (SH_MARK_RE.test(t.slice(0, 4000))) return 'sh';
    if (SCLIENT_RE.test(t.slice(0, 4000)) && t.includes('-----BEGIN CERTIFICATE-----')) return 'sclient';
    if (t.includes('-----BEGIN CERTIFICATE-----') && !t.replace(PEM_RE, '').trim()) return 'pem';
    return '';
  }
  // openssl s_client 輸出中的協商結果（OpenSSL 1.1／3：「New, TLSv1.3, Cipher is X」或 Protocol／Cipher 行）
  function sclientNegotiated(t) {
    const m = t.match(/New, (TLSv[\d.]+|SSLv3), Cipher is (\S+)/);
    const p = t.match(/^\s*Protocol\s*:\s*(\S+)/m), c = t.match(/^\s*Cipher\s*:\s*(\S+)/m);
    const protocol = (m && m[1]) || (p && p[1]) || '', cipher = (m && m[2]) || (c && c[1]) || '';
    return protocol || cipher ? { protocol, cipher } : null;
  }
  const TLS_KEYS = ['1.0', '1.1', '1.2', '1.3'];
  function normTls(o) {
    const out = {};
    for (const k of TLS_KEYS) { const v = o && o[k]; out[k] = v === true || v === 'yes' ? 'yes' : v === false || v === 'no' ? 'no' : 'untested'; }
    return out;
  }
  const HOST_RE = /^[A-Za-z0-9*_.-]+$|^\[?[0-9A-Fa-f:]+\]?$/;
  const cleanHost = h => { const s = String(h || '').trim().toLowerCase(); return HOST_RE.test(s) ? s.replace(/^\[|\]$/g, '') : ''; };
  function parseInput(text) {
    const kind = detectInput(text);
    const t = String(text || '').replace(/^﻿/, '');
    const entries = [];
    if (kind === 'json') {
      let o;
      try { o = JSON.parse(t); } catch (e) { return { kind, entries, error: 'json' }; }
      for (const h of Array.isArray(o.hosts) ? o.hosts : []) {
        if (!h || typeof h !== 'object') continue;
        const chain = [];
        for (const c of Array.isArray(h.chain) ? h.chain : []) { try { chain.push(b64ToBytes(c)); } catch (e) { /* 略過 */ } }
        entries.push({
          host: cleanHost(h.host), port: +h.port || 443, chain, chainSource: h.chainSource === 'os' ? 'os' : 'server',
          tls: normTls(h.tls), negotiated: h.negotiated && typeof h.negotiated === 'object' ? { protocol: String(h.negotiated.protocol || ''), cipher: String(h.negotiated.cipher || '') } : null,
          osTrust: h.osTrust && typeof h.osTrust === 'object' ? { ok: h.osTrust.ok === true, status: Array.isArray(h.osTrust.status) ? h.osTrust.status.map(String).slice(0, 10) : [] } : null,
          error: h.error ? String(h.error).slice(0, 300) : '', tool: String(o.tool || ''),
        });
      }
    } else if (kind === 'sh') {
      const parts = t.split(/^(?==== alpaca-certchain )/m).filter(p => SH_MARK_RE.test(p));
      for (const p of parts) {
        const m = p.match(SH_MARK_RE), tls = {};
        for (const x of p.matchAll(/^#tls (1\.[0-3]) (yes|no|untested)\s*$/gm)) tls[x[1]] = x[2];
        const err = p.match(/^#error (.+)$/m);
        entries.push({ host: cleanHost(m[1]), port: +m[2] || 443, chain: pemBlocks(p), chainSource: 'server', tls: normTls(tls), negotiated: sclientNegotiated(p), osTrust: null, error: err ? err[1].slice(0, 300) : '', tool: 'sh' });
      }
    } else if (kind === 'sclient' || kind === 'pem') {
      entries.push({ host: '', port: 443, chain: pemBlocks(t), chainSource: 'server', tls: normTls({}), negotiated: kind === 'sclient' ? sclientNegotiated(t) : null, osTrust: null, error: '', tool: kind });
    }
    return { kind, entries };
  }

  // ── 主機名稱比對（RFC 6125：萬用字元只在最左一層、只代表一層）──
  // IPv6 一律展開成 8 段、去掉前導 0 再比較（::1 與 0:0:0:0:0:0:0:1 相同）
  function normIp6(h) {
    const parts = String(h).toLowerCase().split('::');
    if (parts.length > 2) return h;
    const a = parts[0] ? parts[0].split(':') : [], b = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
    const fill = parts.length === 2 ? Array(Math.max(0, 8 - a.length - b.length)).fill('0') : [];
    return a.concat(fill, b).map(x => (parseInt(x, 16) || 0).toString(16)).join(':');
  }
  function hostMatches(cert, host) {
    if (!host) return null;
    if (host.includes(':')) return (cert.sanIp || []).map(normIp6).includes(normIp6(host));
    if (/^[\d.]+$/.test(host)) return (cert.sanIp || []).includes(host);
    for (const d of cert.sanDns || []) {
      if (d === host) return true;
      if (d.startsWith('*.')) {
        const rest = d.slice(2), i = host.indexOf('.');
        if (i > 0 && host.slice(i + 1) === rest && rest.includes('.')) return true;
      }
    }
    return false;
  }

  // CA/Browser Forum 基準要求的伺服器憑證最長效期（簽發日起算，SC-081 逐步縮短）
  const MAX_VALIDITY = [['2029-03-15', 47], ['2027-03-15', 100], ['2026-03-15', 200], ['2020-09-01', 398]];
  function maxValidityDays(notBefore) {
    for (const [d, n] of MAX_VALIDITY) if (notBefore >= Date.parse(d + 'T00:00:00Z')) return n;
    return null;
  }
  const WEAK_CIPHER_RE = /RC4|3DES|DES-CBC|_DES_|NULL|EXPORT|anon/i;
  const DAY = 86400000;

  function rootIndex(roots) {
    const idx = new Map();
    for (const r of roots || []) {
      const e = { name: r[0], sha256: r[1], subjectHex: r[2], spki: b64ToBytes(r[3]), notAfter: Date.parse(r[4]), distrustAfter: r[5] ? Date.parse(r[5]) : null };
      if (!idx.has(e.subjectHex)) idx.set(e.subjectHex, []);
      idx.get(e.subjectHex).push(e);
    }
    return idx;
  }
  let _rootIdx = null, _rootIdxSrc = null;
  function builtinIndex() {
    if (_rootIdxSrc !== API.ROOTS) { _rootIdx = rootIndex(API.ROOTS); _rootIdxSrc = API.ROOTS; }
    return _rootIdx;
  }
  const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

  // entry：parseInput() 的一筆；opts：{ extraRoots:[DER], warnDays, now }
  async function analyzeHost(entry, opts) {
    const o = opts || {}, now = o.now || Date.now(), warnDays = o.warnDays > 0 ? o.warnDays : 30;
    const findings = [], add = (id, sev, p) => findings.push({ id, sev, p: p || {} });
    const res = { host: entry.host, port: entry.port, chain: [], anchor: null, findings, tls: entry.tls, negotiated: entry.negotiated, osTrust: entry.osTrust, leaf: null, daysLeft: null };
    if (entry.error && !entry.chain.length) { add('connect-error', 'high', { msg: entry.error }); return finish(res); }
    const certs = [];
    entry.chain.forEach((der, i) => { try { certs.push(Object.assign(parseCert(der), { sentIndex: i })); } catch (e) { add('parse-error', 'medium', { n: i + 1 }); } });
    if (!certs.length) { add('no-cert', 'high'); return finish(res); }
    const extra = [];
    for (const der of o.extraRoots || []) { try { extra.push(parseCert(der)); } catch (e) { /* 略過 */ } }
    const builtin = builtinIndex();

    // 建鏈：每一層先找 Mozilla 根，再找伺服器送出的憑證，最後找使用者的內部根
    const leaf = certs[0];
    res.leaf = leaf;
    const path = [leaf], used = new Set([0]);
    let cur = leaf;
    for (let depth = 0; depth < 10; depth++) {
      const akiOk = c => !cur.aki || !c.ski || c.ski === cur.aki;
      const rootCands = (builtin.get(cur.issuerHex) || []);
      let anchored = false;
      for (const r of rootCands) {
        if (cur.selfIssued && sameBytes(cur.spki, r.spki)) { res.anchor = { type: 'mozilla', name: r.name, root: r, sent: true }; anchored = true; break; }
        if (cur.selfIssued) continue;
        // 同名但金鑰不同的根憑證（新舊版）驗證失敗時只是不採用，不算簽章錯誤
        const v = await verifySig(cur, r.spki, spkiInfo(r.spki, tlv(r.spki, 0)));
        if (v !== false) { cur.sigOk = v; res.anchor = { type: 'mozilla', name: r.name, root: r, sent: false }; anchored = true; break; }
      }
      if (anchored) break;
      if (cur.selfIssued) {
        const ex = extra.find(x => sameBytes(x.spki, cur.spki) && x.subjectHex === cur.subjectHex);
        cur.sigOk = await verifySig(cur, cur.spki, cur.key);
        res.anchor = ex ? { type: 'internal', name: ex.cn, sent: true, subjectHex: ex.subjectHex } : { type: 'untrusted', name: cur.cn, sent: true };
        break;
      }
      let next = null, nextIdx = -1;
      certs.forEach((c, i) => { if (!next && !used.has(i) && c.subjectHex === cur.issuerHex && akiOk(c)) { next = c; nextIdx = i; } });
      if (next) {
        cur.sigOk = await verifySig(cur, next.spki, next.key);
        used.add(nextIdx); path.push(next); cur = next; continue;
      }
      const ex = extra.find(x => x.subjectHex === cur.issuerHex && akiOk(x));
      if (ex) {
        cur.sigOk = await verifySig(cur, ex.spki, ex.key);
        res.anchor = { type: 'internal', name: ex.cn, sent: false, subjectHex: ex.subjectHex };
        break;
      }
      res.anchor = { type: 'incomplete', name: nameGet(cur.issuer, 'CN') || nameStr(cur.issuer) };
      break;
    }
    res.chain = path;

    // 信任鏈
    if (res.anchor.type === 'incomplete') {
      if (entry.chainSource === 'os') add('chain-from-os', 'info');
      // 只有葉憑證、找不到簽發者＝伺服器沒送中繼憑證；已有中繼憑證但找不到其簽發者＝根憑證不在信任清單（常見於內部 CA）
      else if (path.length === 1) add('missing-intermediate', 'high', { issuer: res.anchor.name, aia: (cur.caIssuers || [])[0] || '' });
      else add('unknown-root', 'high', { issuer: res.anchor.name });
    }
    if (res.anchor.type === 'untrusted') add(path.length === 1 ? 'self-signed' : 'untrusted-root', 'high', { name: res.anchor.name });
    if (res.anchor.type === 'internal') add('internal-root', 'info', { name: res.anchor.name });
    path.forEach((c, i) => { if (c.sigOk === false) add('bad-signature', 'high', { n: i + 1, cn: c.cn }); });
    if (entry.chainSource !== 'os') {
      const sentOrder = path.map(c => c.sentIndex).filter(x => x !== undefined);
      if (sentOrder.some((x, i) => i && x < sentOrder[i - 1])) add('chain-order', 'low');
      // 主體與信任錨相同、但由另一個 CA 簽發的憑證是根憑證的交叉簽署版本（給還沒內建新根憑證的舊裝置用），不算無關
      const anchorSubject = res.anchor.root ? res.anchor.root.subjectHex : res.anchor.subjectHex;
      const unused = certs.filter((c, i) => !used.has(i));
      const cross = unused.filter(c => anchorSubject && c.subjectHex === anchorSubject && !c.selfIssued);
      if (cross.length) add('cross-signed', 'info', { name: res.anchor.name, issuer: nameGet(cross[0].issuer, 'CN') || nameStr(cross[0].issuer) });
      if (unused.length > cross.length) add('unused-certs', 'info', { n: unused.length - cross.length });
      if (res.anchor.type === 'mozilla' && res.anchor.sent && path.length > 1) add('root-sent', 'info');
    }
    if (res.anchor.type === 'mozilla' && res.anchor.root.distrustAfter && leaf.notBefore > res.anchor.root.distrustAfter)
      add('root-distrusted', 'high', { name: res.anchor.name, date: new Date(res.anchor.root.distrustAfter).toISOString().slice(0, 10) });

    // 效期
    res.daysLeft = leaf.notAfter != null ? Math.floor((leaf.notAfter - now) / DAY) : null;
    if (leaf.notAfter != null && leaf.notAfter < now) add('expired', 'high', { date: iso(leaf.notAfter) });
    else if (leaf.notBefore != null && leaf.notBefore > now) add('not-yet-valid', 'high', { date: iso(leaf.notBefore) });
    else if (res.daysLeft != null && res.daysLeft <= warnDays) add('expiring', 'medium', { days: res.daysLeft, date: iso(leaf.notAfter) });
    path.slice(1).forEach(c => {
      if (c.selfIssued) return;
      if (c.notAfter < now) add('int-expired', 'high', { cn: c.cn, date: iso(c.notAfter) });
      else if ((c.notAfter - now) / DAY <= warnDays) add('int-expiring', 'medium', { cn: c.cn, date: iso(c.notAfter) });
    });
    // 沒有主機、第一張就是 CA 憑證（例如只貼中繼或根憑證）：不做只適用網站憑證的檢查
    const caOnly = !entry.host && leaf.bc && leaf.bc.ca;
    if (caOnly) add('ca-only', 'info');
    if (!caOnly && res.anchor.type === 'mozilla' && leaf.notBefore != null && leaf.notAfter != null) {
      const max = maxValidityDays(leaf.notBefore), life = (leaf.notAfter - leaf.notBefore) / DAY;
      if (max && life > max + 1) add('long-validity', 'low', { days: Math.round(life), max });
    }

    // 加密強度（信任錨本身的自簽章不算）
    path.forEach((c, i) => {
      const anchorSelf = c.selfIssued && i === path.length - 1;
      if (!anchorSelf && SIG_ALGS[c.sigOid] && SIG_ALGS[c.sigOid].weak) add('weak-sig', 'high', { n: i + 1, cn: c.cn, alg: c.sigAlg });
      if (c.key.type === 'RSA' && c.key.bits < 2048) add('weak-key', 'high', { n: i + 1, cn: c.cn, bits: c.key.bits });
      if (c.key.type === 'EC' && !CURVE_BYTES[c.key.curve]) add('odd-curve', 'medium', { n: i + 1, cn: c.cn, curve: c.key.curve });
    });

    // 名稱與用途
    const hm = caOnly ? true : hostMatches(leaf, entry.host);
    if (caOnly) { /* 略過名稱與用途 */ } else if (!leaf.sanDns && !leaf.sanIp) add('no-san', 'high');
    else if (hm === false) add('name-mismatch', 'high', { host: entry.host, names: (leaf.sanDns || []).concat(leaf.sanIp || []).slice(0, 8).join(', ') });
    if (hm === null) add('name-unchecked', 'info');
    if (!caOnly && leaf.bc && leaf.bc.ca && path.length > 1) add('leaf-is-ca', 'medium');
    if (!caOnly && leaf.eku && !leaf.eku.includes('serverAuth') && !leaf.eku.includes('any')) add('eku-no-server', 'high');
    path.slice(1).forEach(c => { if (!c.bc || !c.bc.ca || (c.ku && !c.ku.keyCertSign)) add('int-not-ca', 'high', { cn: c.cn }); });

    // TLS（有資料才判斷）
    const tls = entry.tls || {};
    const old = ['1.0', '1.1'].filter(k => tls[k] === 'yes');
    if (old.length) add('old-tls', 'medium', { list: old.map(k => 'TLS ' + k).join('、') });
    if (tls['1.3'] === 'no') add('no-tls13', 'info');
    if (entry.negotiated && WEAK_CIPHER_RE.test(entry.negotiated.cipher)) add('weak-cipher', 'high', { cipher: entry.negotiated.cipher });
    if (entry.osTrust && !entry.osTrust.ok) add('os-untrusted', 'info', { status: entry.osTrust.status.join(', ') });
    return finish(res);
  }
  const iso = t => new Date(t).toISOString().slice(0, 10);
  const SEV_ORDER = { high: 3, medium: 2, low: 1, info: 0 };
  function finish(res) {
    res.findings.sort((a, b) => SEV_ORDER[b.sev] - SEV_ORDER[a.sev]);
    res.worst = res.findings.reduce((w, f) => SEV_ORDER[f.sev] > SEV_ORDER[w] ? f.sev : w, 'info');
    return res;
  }

  async function sha256Hex(der) {
    const S = subtle();
    if (!S) return '';
    return hex(new Uint8Array(await S.digest('SHA-256', der)));
  }

  const API = {
    b64ToBytes, bytesToB64, pemBlocks, derToPem, looksLikeDer, parseCert, verifySig, detectInput, parseInput,
    hostMatches, maxValidityDays, analyzeHost, sha256Hex, nameStr, rootIndex,
    ROOTS: [], ROOTS_ASOF: '', ROOTS_SOURCE: '',
  };
  root.CertCheck = API;
})(typeof window !== 'undefined' ? window : globalThis);
