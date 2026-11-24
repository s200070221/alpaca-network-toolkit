// ── 前面板示意圖的共用繪圖（XN190／XN191；防火牆與交換器分析共用，主控在 network_analyzer/result）──────
// 只負責把「要畫什麼」畫成 SVG 字串，不讀設定檔、不碰 DOM；所有文字一律跳脫。之後多台設備的接線拓樸（XN192）沿用同一份。
// spec = {
//   title,                                   面板左上角的型號／名稱
//   rows: [{ label, ports: [{ id, name, label（圖上顯示，預設 name）, color, dim, fiber, text, tip, stripe:{color,tip}, badge }] }],
//                                            每排一台（或一個堆疊成員），埠依陣列順序排列，超過 PER_ROW 換行
//   groups: [{ members:[id], color, dashed, label }]   同一列連續的成員各畫一框（實線＝透通、虛線＝聚合）
//   callouts: [{ port:id, lines:[], color, bg, fg }]   面板上方的說明框，以線連到該埠（WAN 等）
//   separate: true                           每排各畫一個面板框、排與排之間留空（多台設備接線拓樸 XN192）
//   links: [{ a:id, b:id, color, dashed, tip }]  兩個埠之間的接線（曲線，畫在最上層）
// }
(function () {
  'use strict';
  const PER_ROW = 16, W = 34, H = 26, GAP = 8, PAD = 16, LABEL_H = 14, ROW_LABEL_H = 14, BOX_W = 230;
  const xesc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  // 遮蔽位址（下載給他人時）：IPv4（含遮罩與前綴）與 IPv6 換成固定字樣
  const maskIp = s => String(s).replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,3}(?:\.\d{1,3}){3}|\/\d{1,2})?\b/g, 'x.x.x.x').replace(/\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:\/\d{1,3})?\b/gi, m => (m.includes('::') || m.split(':').length > 3 ? 'x:x::x' : m));
  const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

  const SEP_GAP = 46;   // separate 模式排與排之間的空間（接線經過）
  function render(spec) {
    const rows = (spec.rows || []).filter(r => r.ports && r.ports.length);
    const callouts = spec.callouts || [], sep = !!spec.separate;
    const boxH = callouts.length ? 90 : 0;
    const top = boxH + 10, rowH = H + LABEL_H + 18;
    const pos = Object.create(null);
    let y = top + PAD + (spec.title ? 6 : 0), maxCols = 1;
    const rowLabels = [], boxes = [];
    rows.forEach((r, ri) => {
      if (sep && ri) y += SEP_GAP;
      const y0 = y;
      if (r.label) { rowLabels.push({ y, label: r.label }); y += ROW_LABEL_H; }
      r.ports.forEach((p, i) => {
        const line = Math.floor(i / PER_ROW), c = i % PER_ROW;
        maxCols = Math.max(maxCols, c + 1);
        pos[p.id] = { x: 10 + PAD + c * (W + GAP), y: y + line * rowH, line: ri * 1000 + line, i: ri * 100000 + i, row: ri };
      });
      y += Math.ceil(r.ports.length / PER_ROW) * rowH;
      boxes.push({ y0: y0 - PAD / 2, y1: y });
    });
    const panelW = PAD * 2 + maxCols * (W + GAP) - GAP, panelH = y - top + PAD;
    // separate 模式下跨過其他設備的接線改走面板右側的通道，不穿過中間的面板（每條一個通道）
    const far = sep ? (spec.links || []).filter(l => pos[l.a] && pos[l.b] && Math.abs(pos[l.a].row - pos[l.b].row) > 1) : [];
    const LANE = 8, laneX = i => 10 + panelW + 14 + i * LANE;
    const width = Math.max(panelW + 20 + (far.length ? far.length * LANE + 20 : 0), callouts.length * (BOX_W + 10) + 10), height = top + panelH + 10;
    let s = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="sans-serif" font-size="10">`;
    if (sep) boxes.forEach(b => { s += `<rect x="10" y="${b.y0}" width="${panelW}" height="${b.y1 - b.y0}" rx="6" fill="#1f2937" stroke="#4b5563"/>`; });
    else s += `<rect x="10" y="${top}" width="${panelW}" height="${panelH}" rx="6" fill="#1f2937" stroke="#4b5563"/>`;
    if (spec.title) s += `<text x="${10 + PAD}" y="${top + 12}" fill="#d1d5db" font-size="10">${xesc(spec.title)}</text>`;
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
    // 接線：上方埠的下緣接到下方埠的上緣；同一排的兩埠以往下彎的弧線相接
    (spec.links || []).forEach(l => {
      let a = pos[l.a], b = pos[l.b];
      if (!a || !b) return;
      if (b.y < a.y) { const t = a; a = b; b = t; }
      const ax = a.x + W / 2, bx = b.x + W / 2, ay = a.y + H + LABEL_H, d = l.dashed ? ' stroke-dasharray="5 3"' : '';
      const li = far.indexOf(l);
      const path = li >= 0
        // 下到 a 所在面板下方的間隙 → 右側通道 → b 所在面板上方的間隙 → b（間隙內依通道錯開高度）
        ? (() => { const off = 6 + (li % 6) * 4, gA = boxes[a.row].y1 + off, gB = boxes[b.row].y0 - off, lx = laneX(li);
          return `M${ax},${ay} L${ax},${gA} L${lx},${gA} L${lx},${gB} L${bx},${gB} L${bx},${b.y - 3}`; })()
        : a.y === b.y ? `M${ax},${ay} C${ax},${ay + 34} ${bx},${ay + 34} ${bx},${ay}` : `M${ax},${ay} C${ax},${ay + 40} ${bx},${b.y - 40} ${bx},${b.y - 3}`;
      s += `<path d="${path}" fill="none" stroke="${l.color || '#22c55e'}" stroke-width="2" stroke-opacity="0.85"${d}><title>${xesc(l.tip || '')}</title></path>`;
    });
    // 排的標籤最後畫、加深色描邊，接線經過時文字仍看得清楚
    rowLabels.forEach(l => { s += `<text x="${10 + PAD}" y="${l.y + 10}" fill="#9ca3af" font-size="9" stroke="#1f2937" stroke-width="3" paint-order="stroke">${xesc(l.label)}</text>`; });
    return s + '</svg>';
  }
  // 圖例（HTML 字串）：[[顏色, 說明], …]
  function legend(items, esc) {
    const e = esc || xesc;
    return items.map(([c, label]) => `<span style="display:inline-flex;align-items:center;gap:4px;margin-right:10px"><span style="width:12px;height:12px;border-radius:2px;background:${c};display:inline-block"></span>${e(label)}</span>`).join('');
  }

  // ── 自訂型號（XN192 前置：使用者自己寫埠清單）──────────────────────────────
  // 每行一個埠或一段埠：「名稱 [速率] [mgmt] [poe] [sfp]」，名稱可用 {起-迄} 展開（GigabitEthernet1/0/{1-48}），# 之後為註解。
  // 存在 localStorage panel_custom_models（入口頁 WS_KEYS，交換器分析與防火牆共用），只存名稱與原文，讀出時重新解析。
  const CUSTOM_KEY = 'panel_custom_models', CUSTOM_MAX = 30, CUSTOM_PORT_MAX = 256, CUSTOM_DEF_MAX = 8000;
  const SPEEDS = ['10M', '100M', '1G', '2.5G', '5G', '10G', '25G', '40G', '50G', '100G', '200G', '400G'];
  const PORT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9\/._:-]{0,63}$/;
  function parseCustomModel(text) {
    const ports = [], errors = [], seen = new Set();
    String(text || '').slice(0, CUSTOM_DEF_MAX).replace(/\r\n?/g, '\n').split('\n').forEach((raw, li) => {
      const line = raw.replace(/#.*$/, '').trim(), ln = li + 1;
      if (!line) return;
      const toks = line.split(/\s+/), spec = toks.shift();
      let speed = '', mgmt = false, poe = false, fiber = false, bad = '';
      toks.forEach(t => {
        const sp = SPEEDS.find(x => x === t.toUpperCase());
        if (sp) speed = sp; else if (/^mgmt$/i.test(t)) mgmt = true; else if (/^poe$/i.test(t)) poe = true; else if (/^(sfp|fiber)$/i.test(t)) fiber = true; else if (!bad) bad = t;
      });
      if (bad) { errors.push({ line: ln, code: 'token', tok: bad }); return; }
      const m = spec.match(/^([^{}]*)\{(\d{1,4})-(\d{1,4})\}([^{}]*)$/);
      let names;
      if (m) {
        const a = +m[2], b = +m[3];
        if (a > b || b - a >= CUSTOM_PORT_MAX) { errors.push({ line: ln, code: 'range', tok: spec }); return; }
        names = [];
        for (let n = a; n <= b; n++) names.push(m[1] + n + m[4]);
      } else names = [spec];
      const badName = names.find(n => !PORT_NAME_RE.test(n));
      if (badName) { errors.push({ line: ln, code: 'name', tok: badName }); return; }
      const dup = names.find(n => seen.has(n.toLowerCase()));
      if (dup) { errors.push({ line: ln, code: 'dup', tok: dup }); return; }
      if (ports.length + names.length > CUSTOM_PORT_MAX) { errors.push({ line: ln, code: 'max', tok: String(CUSTOM_PORT_MAX) }); return; }
      names.forEach(n => { seen.add(n.toLowerCase()); ports.push({ name: n, speed: speed || '1G', media: fiber ? 'sfp' : '', mgmt, poe, fiber }); });
    });
    if (!ports.length && !errors.length) errors.push({ line: 0, code: 'empty', tok: '' });
    return { ports, errors };
  }
  const ls = () => { try { return typeof localStorage !== 'undefined' ? localStorage : null; } catch (e) { return null; } };
  const validEntry = e => e && typeof e === 'object' && /^[a-z0-9]{1,16}$/.test(String(e.id)) && typeof e.name === 'string' && e.name.trim() && e.name.length <= 40 && typeof e.def === 'string' && e.def.length <= CUSTOM_DEF_MAX;
  function customLoad() {
    try { const a = JSON.parse((ls() && ls().getItem(CUSTOM_KEY)) || '[]'); return Array.isArray(a) ? a.filter(validEntry).slice(0, CUSTOM_MAX).map(e => ({ id: String(e.id), name: e.name.trim(), def: e.def })) : []; } catch (e) { return []; }
  }
  function customWrite(list) { try { ls().setItem(CUSTOM_KEY, JSON.stringify(list)); return true; } catch (e) { return false; } }
  // 回傳 {ok, value, errors}；同名覆寫，上限 CUSTOM_MAX 筆
  function customSave(name, def) {
    const nm = String(name || '').trim();
    if (!nm || nm.length > 40) return { ok: false, errors: [{ line: 0, code: 'noname', tok: '' }] };
    const r = parseCustomModel(def);
    if (r.errors.length) return { ok: false, errors: r.errors };
    const list = customLoad(), old = list.find(e => e.name.toLowerCase() === nm.toLowerCase());
    if (!old && list.length >= CUSTOM_MAX) return { ok: false, errors: [{ line: 0, code: 'full', tok: String(CUSTOM_MAX) }] };
    const id = old ? old.id : (Date.now().toString(36) + Math.floor(Math.random() * 1296).toString(36)).slice(-16);
    const entry = { id, name: nm, def: String(def).slice(0, CUSTOM_DEF_MAX) };
    const next = old ? list.map(e => (e.id === id ? entry : e)) : list.concat([entry]);
    if (!customWrite(next)) return { ok: false, errors: [{ line: 0, code: 'store', tok: '' }] };
    return { ok: true, value: 'cu:' + id, errors: [] };
  }
  function customDelete(id) { return customWrite(customLoad().filter(e => e.id !== String(id))); }
  // 型號物件（給兩個工具的 buildPanel）：{value:'cu:<id>', label, custom:true, ports:[{name,speed,media,mgmt,poe,fiber}]}
  function customModels() {
    return customLoad().map(e => ({ value: 'cu:' + e.id, id: 'cu:' + e.id, label: e.name, custom: true, ports: parseCustomModel(e.def).ports })).filter(m => m.ports.length);
  }
  const CUSTOM_EXAMPLE = { name: 'Example 24P+4SFP', def: '# 24 x 1G PoE + 4 x 10G SFP+ uplinks + mgmt\nGigabitEthernet1/0/{1-24} 1G poe\nTenGigabitEthernet1/1/{1-4} 10G sfp\nmgmt0 mgmt' };
  const T = (k, p) => { let s = typeof tr === 'function' ? tr(k) : k; Object.keys(p || {}).forEach(n => { s = s.split('{' + n + '}').join(String(p[n])); }); return s; };
  const errText = errs => errs.slice(0, 5).map(e => (e.line ? T('pcu.line', { n: e.line }) + ' ' : '') + T('pcu.err_' + e.code, { tok: e.tok })).join('；');
  // 自訂型號編輯區（HTML）：scope 區分工具（sw／fw），事件由本模組處理，存檔或刪除後發出 window 事件 pnl-custom {scope, value}
  function customEditorHtml(scope, open) {
    const e = typeof esc === 'function' ? esc : xesc, list = customLoad();
    const btn = 'background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:3px 10px;font-size:11px;cursor:pointer';
    let h = `<details data-pnl-cu="${xesc(scope)}" style="margin-top:6px"${open ? ' open' : ''}><summary style="cursor:pointer;font-size:12px">✏ ${e(T('pcu.title'))}</summary>`
      + `<div style="font-size:11px;color:var(--text-dim);margin:4px 0">${e(T('pcu.hint'))}</div>`
      + `<input data-pnl-cu-name maxlength="40" placeholder="${xesc(T('pcu.name_ph'))}" style="width:260px;max-width:100%;font-size:12px;margin-bottom:4px"><br>`
      + `<textarea data-pnl-cu-def rows="5" spellcheck="false" style="width:100%;max-width:520px;font-family:monospace;font-size:11px" placeholder="GigabitEthernet1/0/{1-48} 1G poe&#10;TenGigabitEthernet1/1/{1-4} 10G sfp&#10;mgmt0 mgmt"></textarea><br>`
      + `<button style="${btn}" data-pnl-cu-save>${e(T('pcu.save'))}</button> <button style="${btn}" data-pnl-cu-example>${e(T('pcu.example'))}</button> <span data-pnl-cu-msg style="font-size:11px"></span>`;
    if (list.length) h += `<div style="font-size:11px;margin-top:6px">${e(T('pcu.saved'))}` + list.map(m => `<div style="margin:2px 0"><b>${e(m.name)}</b>（${e(T('pcu.ports', { n: parseCustomModel(m.def).ports.length }))}） <button style="${btn}" data-pnl-cu-edit="${xesc(m.id)}">${e(T('pcu.edit'))}</button> <button style="${btn}" data-pnl-cu-del="${xesc(m.id)}">${e(T('pcu.del'))}</button></div>`).join('') + '</div>';
    return h + '</details>';
  }
  if (typeof document !== 'undefined' && document.addEventListener) {
    document.addEventListener('click', ev => {
      const t = ev.target && ev.target.closest ? ev.target : null;
      const box = t && t.closest('details[data-pnl-cu]');
      if (!box) return;
      const scope = box.getAttribute('data-pnl-cu');
      const fire = value => { try { window.dispatchEvent(new CustomEvent('pnl-custom', { detail: { scope, value } })); } catch (e) { /* 舊瀏覽器不支援 CustomEvent 時只存檔 */ } };
      if (t.closest('[data-pnl-cu-save]')) {
        const r = customSave(box.querySelector('[data-pnl-cu-name]').value, box.querySelector('[data-pnl-cu-def]').value);
        const msg = box.querySelector('[data-pnl-cu-msg]');
        if (!r.ok) { if (msg) { msg.textContent = errText(r.errors); msg.style.color = 'var(--red,#ef4444)'; } return; }
        fire(r.value);
      } else if (t.closest('[data-pnl-cu-example]')) {
        // 範例：24 埠 PoE＋4 個 SFP+ 上行＋管理埠（只填入編輯區，按儲存才寫入）
        box.querySelector('[data-pnl-cu-name]').value = CUSTOM_EXAMPLE.name;
        box.querySelector('[data-pnl-cu-def]').value = CUSTOM_EXAMPLE.def;
      } else if (t.closest('[data-pnl-cu-edit]')) {
        const m = customLoad().find(x => x.id === t.closest('[data-pnl-cu-edit]').getAttribute('data-pnl-cu-edit'));
        if (m) { box.querySelector('[data-pnl-cu-name]').value = m.name; box.querySelector('[data-pnl-cu-def]').value = m.def; }
      } else if (t.closest('[data-pnl-cu-del]')) {
        customDelete(t.closest('[data-pnl-cu-del]').getAttribute('data-pnl-cu-del'));
        fire(null);
      }
    });
  }

  const api = { render, legend, maskIp, xesc, PER_ROW, parseCustomModel, customLoad, customSave, customDelete, customModels, customEditorHtml, CUSTOM_EXAMPLE, CUSTOM_ERR_CODES: ['token', 'range', 'name', 'dup', 'max', 'empty', 'noname', 'full', 'store'], CUSTOM_KEY, CUSTOM_MAX, CUSTOM_PORT_MAX };
  if (typeof window !== 'undefined') window.PanelSvg = api;
  return api;
})();
