// ── 前面板示意圖的共用繪圖（XN190／XN191；防火牆與交換器分析共用，主控在 network_analyzer/result）──────
// 只負責把「要畫什麼」畫成 SVG 字串，不讀設定檔、不碰 DOM；所有文字一律跳脫。之後多台設備的接線拓樸（XN192）沿用同一份。
// spec = {
//   title,                                   面板左上角的型號／名稱
//   rows: [{ label, ports: [{ id, name, label（圖上顯示，預設 name）, color, dim, fiber, text, tip, stripe:{color,tip}, badge }] }],
//                                            每排一台（或一個堆疊成員），埠依陣列順序排列，超過 PER_ROW 換行
//   groups: [{ members:[id], color, dashed, label }]   同一列連續的成員各畫一框（實線＝透通、虛線＝聚合）
//   callouts: [{ port:id, lines:[], color, bg, fg }]   面板上方的說明框，以線連到該埠（WAN 等）
// }
(function () {
  'use strict';
  const PER_ROW = 16, W = 34, H = 26, GAP = 8, PAD = 16, LABEL_H = 14, ROW_LABEL_H = 14, BOX_W = 230;
  const xesc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  // 遮蔽位址（下載給他人時）：IPv4（含遮罩與前綴）與 IPv6 換成固定字樣
  const maskIp = s => String(s).replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,3}(?:\.\d{1,3}){3}|\/\d{1,2})?\b/g, 'x.x.x.x').replace(/\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:\/\d{1,3})?\b/gi, m => (m.includes('::') || m.split(':').length > 3 ? 'x:x::x' : m));
  const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

  function render(spec) {
    const rows = (spec.rows || []).filter(r => r.ports && r.ports.length);
    const callouts = spec.callouts || [];
    const boxH = callouts.length ? 90 : 0;
    const top = boxH + 10, rowH = H + LABEL_H + 18;
    const pos = Object.create(null);
    let y = top + PAD + (spec.title ? 6 : 0), maxCols = 1;
    const rowLabels = [];
    rows.forEach((r, ri) => {
      if (r.label) { rowLabels.push({ y, label: r.label }); y += ROW_LABEL_H; }
      r.ports.forEach((p, i) => {
        const line = Math.floor(i / PER_ROW), c = i % PER_ROW;
        maxCols = Math.max(maxCols, c + 1);
        pos[p.id] = { x: 10 + PAD + c * (W + GAP), y: y + line * rowH, line: ri * 1000 + line, i: ri * 100000 + i };
      });
      y += Math.ceil(r.ports.length / PER_ROW) * rowH;
    });
    const panelW = PAD * 2 + maxCols * (W + GAP) - GAP, panelH = y - top + PAD;
    const width = Math.max(panelW + 20, callouts.length * (BOX_W + 10) + 10), height = top + panelH + 10;
    let s = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="sans-serif" font-size="10">`;
    s += `<rect x="10" y="${top}" width="${panelW}" height="${panelH}" rx="6" fill="#1f2937" stroke="#4b5563"/>`;
    if (spec.title) s += `<text x="${10 + PAD}" y="${top + 12}" fill="#d1d5db" font-size="10">${xesc(spec.title)}</text>`;
    rowLabels.forEach(l => { s += `<text x="${10 + PAD}" y="${l.y + 10}" fill="#9ca3af" font-size="9">${xesc(l.label)}</text>`; });
    (spec.groups || []).forEach(g => {
      const pts = (g.members || []).map(id => pos[id]).filter(Boolean).sort((a, b) => a.i - b.i);
      let run = [];
      const flush = () => {
        if (!run.length) return;
        const a = run[0], b = run[run.length - 1];
        s += `<rect x="${a.x - 4}" y="${a.y - 4}" width="${b.x - a.x + W + 8}" height="${H + LABEL_H + 10}" rx="4" fill="none" stroke="${g.color}" stroke-width="2"${g.dashed ? ' stroke-dasharray="4 2"' : ''}/>`;
        if (g.label) s += `<text x="${a.x - 2}" y="${a.y + H + LABEL_H + 14}" fill="${g.color}" font-size="9">${xesc(g.label)}</text>`;
        run = [];
      };
      pts.forEach(q => { const prev = run[run.length - 1]; if (prev && (q.i !== prev.i + 1 || q.line !== prev.line)) flush(); run.push(q); });
      flush();
    });
    rows.forEach(r => r.ports.forEach(p => {
      const q = pos[p.id];
      s += `<rect x="${q.x}" y="${q.y}" width="${W}" height="${H}" rx="${p.fiber ? 1 : 3}" fill="${p.color}" fill-opacity="${p.dim ? 0.35 : 0.9}" stroke="#e5e7eb" stroke-width="${p.fiber ? 2 : 1}" data-port="${xesc(p.name)}"><title>${xesc(p.tip || p.name)}</title></rect>`;
      if (p.stripe) s += `<rect x="${q.x}" y="${q.y - 3}" width="${W}" height="3" fill="${p.stripe.color}"><title>${xesc(p.stripe.tip || '')}</title></rect>`;
      if (p.text) s += `<text x="${q.x + W / 2}" y="${q.y + 16}" fill="#fff" font-size="8" text-anchor="middle">${xesc(short(String(p.text), 7))}</text>`;
      if (p.badge) s += `<text x="${q.x + W - 3}" y="${q.y + 9}" fill="#fde68a" font-size="8" text-anchor="end">${xesc(p.badge)}</text>`;
      s += `<text x="${q.x + W / 2}" y="${q.y + H + 11}" fill="#e5e7eb" font-size="9" text-anchor="middle">${xesc(short(String(p.label || p.name), 10))}</text>`;
    }));
    callouts.forEach((c, i) => {
      const bx = 10 + i * (BOX_W + 10), q = pos[c.port];
      s += `<rect x="${bx}" y="4" width="${BOX_W}" height="${boxH - 14}" rx="4" fill="${c.bg || '#fff7ed'}" stroke="${c.color}"/>`;
      (c.lines || []).slice(0, 5).forEach((l, k) => { s += `<text x="${bx + 6}" y="${18 + k * 13}" fill="${c.fg || '#7c2d12'}" font-size="${k ? 9 : 10}">${xesc(short(String(l), 44))}</text>`; });
      if (q) s += `<line x1="${bx + BOX_W / 2}" y1="${boxH - 10}" x2="${q.x + W / 2}" y2="${q.y}" stroke="${c.color}" stroke-width="2"/>`;
    });
    return s + '</svg>';
  }
  // 圖例（HTML 字串）：[[顏色, 說明], …]
  function legend(items, esc) {
    const e = esc || xesc;
    return items.map(([c, label]) => `<span style="display:inline-flex;align-items:center;gap:4px;margin-right:10px"><span style="width:12px;height:12px;border-radius:2px;background:${c};display:inline-block"></span>${e(label)}</span>`).join('');
  }

  const api = { render, legend, maskIp, xesc, PER_ROW };
  if (typeof window !== 'undefined') window.PanelSvg = api;
  return api;
})();
