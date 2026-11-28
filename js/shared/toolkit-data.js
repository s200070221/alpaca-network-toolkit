// toolkit-data.js — 共用資料處理函式（RV16 第 4 階段）：埠對應表 CSV、轉換前後稽核比對、ZIP 寫入、逐行比對
// 原本防火牆 FwPortMap 與產生器 SwPortMap 各有一份相同的 CSV／compareAudit，防火牆、產生器、去識別化各有一份 ZIP 寫入器，
// 交換器分析與產生器各有一份 computeDiff。合併為這一份，以 ToolkitData 對外（FwPortMap／SwPortMap 的同名方法轉用這裡）。
// 純函式、無 DOM（renderDiff 除外）；Node 測試由 qa/lib/res.mjs 以全域範圍先載入。
(function () {
  // ── 埠對應表 CSV（XN44）：匯出給現場接線、同型號換多台時匯入重用 ─────────────────────────
  // 第一行為 `# target_vendor=…,target_model=…` 註解；值以 =+-@ 開頭時前綴單引號（防公式注入），匯入時去掉
  const MAP_SRC_HEADS = ['source_port', 'source', 'old_port', '來源埠', '舊埠'];
  const MAP_DST_HEADS = ['target_port', 'target', 'new_port', '目標埠', '新埠'];
  const csvQ = v => {
    let s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) || s !== s.trim() ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  // meta：{target_vendor, target_model, …}；cols：欄位名稱；rows：以欄位名稱為鍵的物件
  function buildMapCsv(meta, cols, rows) {
    const head = '# ' + Object.keys(meta || {}).map(k => k + '=' + String(meta[k] == null ? '' : meta[k]).replace(/[,\r\n]/g, ' ')).join(',');
    return [head, cols.join(','), ...(rows || []).map(r => cols.map(c => csvQ(r[c])).join(','))].join('\r\n') + '\r\n';
  }
  // 引號內可含逗號與換行，故整段解析不逐行切；回傳 [{line, cells}]
  function csvRecords(text) {
    const out = []; let row = [], cur = '', q = false, line = 1, start = 1;
    const push = () => { row.push(cur); if (row.some(x => x.trim())) out.push({ line: start, cells: row }); row = []; cur = ''; };
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '"' && text[i + 1] === '"') { cur += '"'; i++; }
        else if (c === '"') q = false;
        else { if (c === '\n') line++; cur += c; }
      } else if (c === '"') q = true;
      else if (c === ',') { row.push(cur); cur = ''; }
      else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; push(); line++; start = line; }
      else cur += c;
    }
    if (cur || row.length) push();
    return out;
  }
  const unq = s => String(s == null ? '' : s).trim().replace(/^'(?=[=+\-@\t\r])/, '');
  // 回傳 {meta, rows:[{line, source, target}], errors:[{code, line}]}
  function parseMapCsv(text) {
    const meta = Object.create(null), errors = [];
    const t = String(text || '').replace(/^﻿/, '');
    const body = t.split(/\r?\n/).map(l => {
      const m = l.match(/^\s*#(.*)$/);
      if (!m) return l;
      m[1].split(',').forEach(kv => { const i = kv.indexOf('='); if (i > 0) { const k = kv.slice(0, i).trim(); if (k && k !== '__proto__') meta[k] = kv.slice(i + 1).trim(); } });
      return '';  // 保留空行讓行號對得上
    }).join('\n');
    const recs = csvRecords(body);
    if (!recs.length) return { meta, rows: [], errors: [{ code: 'empty', line: 0 }] };
    const head = recs[0].cells.map(h => unq(h).toLowerCase().replace(/\s+/g, '_'));
    const si = head.findIndex(h => MAP_SRC_HEADS.includes(h)), di = head.findIndex(h => MAP_DST_HEADS.includes(h));
    if (si < 0 || di < 0) return { meta, rows: [], errors: [{ code: 'noHeader', line: recs[0].line }] };
    const rows = recs.slice(1).map(r => ({ line: r.line, source: unq(r.cells[si]), target: unq(r.cells[di]) }));
    return { meta, rows, errors };
  }
  // 只套用來源埠存在、目標埠屬於目前型號（或留空＝不對應）的列；回傳 {map, applied, skipped:[{line, port, code}]}
  function applyMapRows(rows, sourceNames, targetNames) {
    const src = new Set(sourceNames || []), dst = new Set(targetNames || []);
    const map = Object.create(null), usedDst = Object.create(null), seen = Object.create(null), skipped = [];
    let applied = 0;
    (rows || []).forEach(r => {
      const s = r.source, d = r.target;
      const skip = code => skipped.push({ line: r.line, port: s || d || '', code });
      if (!s) return skip('noSource');
      if (s === '__proto__' || s === 'constructor' || s === 'prototype' || !src.has(s)) return skip('unknownSource');
      if (seen[s]) return skip('dupSource');
      if (d && !dst.has(d)) return skip('unknownTarget');
      if (d && usedDst[d]) return skip('dupTarget');
      seen[s] = true;
      if (d) usedDst[d] = s;
      map[s] = d;
      applied++;
    });
    return { map, applied, skipped };
  }

  // ── 轉換前後安全稽核比對（XN45）────────────────────────────────────────────────
  // before／after：{health:{score,grade}, findings:[{id,label,risk,value}]}；findings 只含該廠牌評估過的項目（不評估的不出現）。
  // 只列有變化的項目；減少或消失常是轉換器沒帶過該設定（管理介面、帳號等），狀態標 less／gone，畫面不可說成改善
  const AUDIT_RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const AUDIT_STATUS_ORDER = { new: 0, worse: 1, noeval: 2, less: 3, gone: 4 };
  function compareAudit(before, after) {
    const idx = list => { const m = Object.create(null); (list || []).forEach(f => { if (f && f.id && f.id !== '__proto__') m[f.id] = f; }); return m; };
    const b = idx(before && before.findings), a = idx(after && after.findings);
    const rows = []; let same = 0;
    [...new Set([...Object.keys(b), ...Object.keys(a)])].forEach(id => {
      const x = b[id], y = a[id];
      const bv = x ? +x.value || 0 : 0, av = y ? +y.value || 0 : 0;
      if (!bv && !av) return;
      let status;
      if (!y) status = 'noeval';
      else if (!bv) status = 'new';
      else if (av > bv) status = 'worse';
      else if (!av) status = 'gone';
      else if (av < bv) status = 'less';
      else { same++; return; }
      rows.push({ id, label: (y && y.label) || (x && x.label) || id, risk: (y && y.risk) || (x && x.risk) || '', before: x ? bv : null, after: y ? av : null, status });
    });
    rows.sort((p, q) => AUDIT_STATUS_ORDER[p.status] - AUDIT_STATUS_ORDER[q.status] || (AUDIT_RISK_ORDER[p.risk] ?? 9) - (AUDIT_RISK_ORDER[q.risk] ?? 9) || p.id.localeCompare(q.id));
    return { health: { before: before && before.health || null, after: after && after.health || null }, rows, same };
  }


  // ── ZIP 寫入（STORED 無壓縮，檔名以 UTF-8 旗標 bit 11 寫入）──────────────────────────────
  let CRC_T = null;
  function crc32(buf) {
    if (!CRC_T) { CRC_T = new Uint32Array(256); for (let i = 0; i < 256; i++) { let v = i; for (let j = 0; j < 8; j++) v = (v & 1) ? (0xEDB88320 ^ (v >>> 1)) : (v >>> 1); CRC_T[i] = v; } }
    let c = ~0;
    for (let i = 0; i < buf.length; i++) c = CRC_T[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
    return (~c) >>> 0;
  }
  // files：[{name, text}] 或 [{name, data: Uint8Array}]（依陣列順序寫入）；when：檔案時間（預設現在）→ Uint8Array
  function createZip(files, when) {
    const enc = s => new TextEncoder().encode(s);
    const u16 = n => [n & 0xFF, (n >> 8) & 0xFF];
    const u32 = n => [n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >>> 24) & 0xFF];
    const d = when || new Date();
    const dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
    const dosDate = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    const parts = [], cd = [];
    let offset = 0;
    files.forEach(f => {
      const name = enc(f.name), data = f.data || enc(f.text == null ? '' : f.text), crc = crc32(data), size = data.length;
      const lh = new Uint8Array([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x08, 0x00, 0x00, ...u16(dosTime), ...u16(dosDate),
        ...u32(crc), ...u32(size), ...u32(size), ...u16(name.length), 0x00, 0x00]);
      parts.push(lh, name, data);
      // 中央目錄：外部屬性 4 bytes（曾誤寫 8 bytes 讓多檔 zip 損毀）
      cd.push(new Uint8Array([0x50, 0x4B, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x08, 0x00, 0x00, ...u16(dosTime), ...u16(dosDate),
        ...u32(crc), ...u32(size), ...u32(size), ...u16(name.length), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ...u32(offset)]), name);
      offset += lh.length + name.length + size;
    });
    const cdSize = cd.reduce((s, b) => s + b.length, 0);
    const eocd = new Uint8Array([0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, ...u16(files.length), ...u16(files.length), ...u32(cdSize), ...u32(offset), 0x00, 0x00]);
    const all = [...parts, ...cd, eocd];
    const out = new Uint8Array(all.reduce((s, b) => s + b.length, 0));
    let pos = 0;
    all.forEach(b => { out.set(b, pos); pos += b.length; });
    return out;
  }

  // ── 逐行比對（LCS；超過 4,000,000 格改用逐行對照，避免分頁卡住）─────────────────────────
  // 回傳 [{type:'same'|'add'|'del', content}]
  function computeDiff(oldLines, newLines) {
    const n = oldLines.length, m = newLines.length;
    if (n * m > 4000000) return computeDiffSimple(oldLines, newLines);
    const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        dp[i][j] = oldLines[i] === newLines[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
    const diff = [];
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (oldLines[i] === newLines[j]) { diff.push({ type: 'same', content: oldLines[i] }); i++; j++; }
      else if (dp[i + 1][j] >= dp[i][j + 1]) { diff.push({ type: 'del', content: oldLines[i] }); i++; }
      else { diff.push({ type: 'add', content: newLines[j] }); j++; }
    }
    while (i < n) { diff.push({ type: 'del', content: oldLines[i] }); i++; }
    while (j < m) { diff.push({ type: 'add', content: newLines[j] }); j++; }
    return diff;
  }
  // 超大檔案的退路：依行號逐行對照（不是真正的 diff）
  function computeDiffSimple(oldLines, newLines) {
    const diff = [];
    const maxLen = Math.max(oldLines.length, newLines.length);
    for (let i = 0; i < maxLen; i++) {
      const old = oldLines[i] || '', nw = newLines[i] || '';
      if (old === nw) diff.push({ type: 'same', content: old });
      else if (!old) diff.push({ type: 'add', content: nw });
      else if (!nw) diff.push({ type: 'del', content: old });
      else { diff.push({ type: 'del', content: old }); diff.push({ type: 'add', content: nw }); }
    }
    return diff;
  }
  const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  // 「上傳兩份設定檔比對」結果（交換器分析與產生器的 #diff-result）；trFn：該工具的 tr
  function renderDiff(el, diff, trFn) {
    if (!el) return;
    el.style.display = 'block';
    let html = '', addCount = 0, delCount = 0;
    diff.forEach(item => {
      if (item.type === 'same') html += `<div style="color:var(--text-dim)">${escHtml(item.content)}</div>`;
      else if (item.type === 'add') { html += `<div style="color:var(--green);background:rgba(16,185,129,.1)">+ ${escHtml(item.content)}</div>`; addCount++; }
      else if (item.type === 'del') { html += `<div style="color:var(--red);background:rgba(239,68,68,.1)">- ${escHtml(item.content)}</div>`; delCount++; }
    });
    const summary = `<div style="border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:8px;font-weight:600">
    📊 ${escHtml(trFn('diff.added'))} ${addCount} | ${escHtml(trFn('diff.deleted'))} ${delCount} | ${escHtml(trFn('diff.total'))} ${diff.length}
  </div>`;
    el.innerHTML = summary + html;
  }

  const api = { buildMapCsv, csvRecords, parseMapCsv, applyMapRows, compareAudit, crc32, createZip, computeDiff, computeDiffSimple, renderDiff };
  (typeof window !== 'undefined' ? window : globalThis).ToolkitData = api;
})();
