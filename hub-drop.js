// network-analyzer.html 拆出的模組（XN101）：拖放與上傳：解壓、讀檔、單檔／多檔結果畫面。
// 與其他 hub-*.js 共用全域（不包 IIFE，HTML 內嵌事件與跨檔呼叫依賴全域函式），載入順序見 network-analyzer.html。
// 多檔拖放／選取（2026-09-24 新增）：單一檔案沿用既有 _showDropResult() 行為完全不變；兩個以上
// 檔案時全部讀完後逐檔 detectTool()，依工具分組列出，每個檔案一個「開啟」按鈕。開啟時把該檔案
// 設為 _dropPending 再呼叫既有 _dispatchWithPending()，沿用同一套一次性交接 key 與彈出視窗攔截
// 偵測，不另建交接機制（交接 key 一次只存一份，故採逐檔手動開啟而非一次全部自動開啟）
let _dropMultiItems = [];
// .gz 檔（2026-10-14，JA）：開頭為 gzip 標記 1f 8b 時以瀏覽器內建 DecompressionStream 解壓後再判斷工具，
// 交接內容為解壓後文字、名稱去掉 .gz；與 log-analyzer.html 的 readTextFile() 為同一份邏輯（另行維護）
// 多個 gzip 成員串接（cat a.gz b.gz > all.gz）時 Chromium 的 DecompressionStream 會拒絕，
// 失敗時依成員檔頭（1f 8b 08）切開逐段解壓；檔頭位元組也可能出現在壓縮資料中，該處解壓失敗就繼續往後找
async function gunzipText(buf) {
  const one = b => new Response(new Blob([b]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  try { return await one(buf); } catch (e) {
    const parts = [];
    let start = 0;
    for (let i = 1; i + 2 < buf.length; i++) {
      if (buf[i] !== 0x1f || buf[i + 1] !== 0x8b || buf[i + 2] !== 0x08) continue;
      try { parts.push(await one(buf.subarray(start, i))); start = i; } catch (e2) { /* 不是成員邊界 */ }
    }
    if (!parts.length) throw e;
    parts.push(await one(buf.subarray(start)));
    return parts.join('');
  }
}
async function _decodeBytes(buf) {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) return gunzipText(buf);
  // 依 BOM 判斷 UTF-16（與 FileReader.readAsText 相同行為），其餘 UTF-8
  const enc = buf[0] === 0xff && buf[1] === 0xfe ? 'utf-16le' : (buf[0] === 0xfe && buf[1] === 0xff ? 'utf-16be' : 'utf-8');
  return new TextDecoder(enc).decode(buf);
}
// .zip（2026-10-14，第二十五輪 LC）：與 log-analyzer.html 的 readZipEntries() 為同一份邏輯（另行維護）；
// 只支援不壓縮與 deflate，加密／zip64／其他壓縮方式丟出錯誤，該檔視為讀不到
async function _readZipEntries(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) { if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; } }
  if (eocd < 0) throw new Error('zipFormat');
  const count = dv.getUint16(eocd + 10, true), cdOff = dv.getUint32(eocd + 16, true);
  if (count === 0xffff || cdOff === 0xffffffff) throw new Error('zip64');
  const out = [];
  let p = cdOff;
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || dv.getUint32(p, true) !== 0x02014b50) throw new Error('zipFormat');
    const flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true);
    const nlen = dv.getUint16(p + 28, true), elen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true), loff = dv.getUint32(p + 42, true);
    const name = new TextDecoder('utf-8').decode(buf.subarray(p + 46, p + 46 + nlen));
    p += 46 + nlen + elen + clen;
    if (name.endsWith('/') || /(^|\/)__MACOSX\//.test(name) || /(^|\/)\._/.test(name)) continue;
    if (flags & 1) throw new Error('zipEncrypted');
    if (csize === 0xffffffff || loff === 0xffffffff) throw new Error('zip64');
    const start = loff + 30 + dv.getUint16(loff + 26, true) + dv.getUint16(loff + 28, true);
    const data = buf.subarray(start, start + csize);
    let bytes;
    if (method === 0) bytes = data;
    else if (method === 8) bytes = new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).arrayBuffer());
    else throw new Error('zipMethod');
    out.push({ name, bytes });
  }
  return out;
}
// 拖放檔案展開成 [{name,text}]：zip 內每個檔案各一筆（名稱「壓縮檔/內部路徑」），.gz 解壓後名稱去掉 .gz
async function _readDropEntries(file) {
  const label = n => String(n).replace(/\.gz$/i, '');
  const buf = new Uint8Array(await file.arrayBuffer());
  // 錯誤檔案（XN53）：PDF、Office、圖片、evtx、pcap、7z 等依檔頭或副檔名先判斷，不嘗試解碼或展開（docx 本身也是 zip）
  const head = buf.subarray(0, 16);
  // 二進位 DER 憑證（XN101）：轉成 PEM 交給憑證檢查，不當成無法辨識的二進位檔
  // 只有能解析成憑證才轉換（私鑰、PKCS#7 等其他 DER 物件照原流程判斷，不當成憑證）
  if (window.CertCheck && CertCheck.looksLikeDer(buf) && (() => { try { CertCheck.parseCert(buf); return true; } catch (e) { return false; } })()) return [{ name: label(file.name), text: CertCheck.derToPem(buf) }];
  // 這一步只看檔頭與副檔名（text 給非空白的佔位字，讓 empty／binary 判斷留到解碼之後）
  const pre = window.FileHowto ? FileHowto.classify({ name: file.name, head, text: 'x' }) : 'text';
  if (pre !== 'text' && pre !== 'binary') return [{ name: label(file.name), text: '', head, kind: pre }];
  if (!(buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04)) return [{ name: label(file.name), text: await _decodeBytes(buf) }];
  const out = [];
  let entries;
  try { entries = await _readZipEntries(buf); } catch (e) { return [{ name: file.name, text: '', head, error: e.message }]; }
  for (const e of entries) out.push({ name: file.name + '/' + label(e.name), text: await _decodeBytes(e.bytes) });
  return out;
}
function _readDroppedFiles(files) {
  const myGen = ++_dropGen;
  Promise.all(files.map(f => _readDropEntries(f).catch(() => [{ name: f.name, text: '' }]))).then(lists => {
    if (myGen !== _dropGen) return;
    const items = lists.flat();
    // 彩蛋：檔名含 114514 或 1919810（第二十七輪），同一頁面只提示一次
    if (!window._smellyFileShown && items.some(it => /114514|1919810/.test(it.name || ''))) { window._smellyFileShown = true; setTimeout(() => showEggToast(tr('egg.smelly_yarimasu')), 600); }
    // 全部都是憑證資料（XN101）：多個檔案一起交給本頁的憑證檢查卡片
    const isCert = it => !!(it.text && window.CertCheck && CertCheck.detectInput(it.text));
    if (items.length > 1 && items.every(isCert)) { _dropCertTexts = items.map(it => it.text); _showDropResult(items[0].name, null, items[0].text, items[0]); return; }
    _dropCertTexts = null;
    if (items.length === 1) { _showDropResult(items[0].name, items[0].text ? detectTool(items[0].text) : null, items[0].text, items[0]); return; }
    _showDropMultiResult(items.map(it => ({ ...it, detected: it.text ? detectTool(it.text) : null })));
  });
}
function _openDropMultiItem(i) {
  const it = _dropMultiItems[i];
  if (!it) return;
  _dropPending = { name: it.name, text: it.text };
  const toolIdx = it.detected ? it.detected.idx : 2;
  const ok = _dispatchWithPending(toolIdx, it.detected ? it.detected.vendor : null, true);
  if (ok) {
    it.opened = true;
    const b = document.getElementById('drop-multi-btn-' + i);
    if (b) b.textContent = '✓ ' + b.textContent.replace(/^✓ /, '');
    _lockMultiButtonsUntilConsumed();
  }
}
// 交接競態防護（2026-09-24 新增）：交接 key 一次只存一份，若目標分頁尚未載入就再點另一個檔案，
// 新寫入會覆蓋前一份。開啟後暫停全部多檔按鈕，輪詢到目標分頁取走 key（被移除）或超過 10 秒
// 時限（與 key 本身 TTL 相同，過期後目標分頁也不會再讀取）才恢復
function _lockMultiButtonsUntilConsumed() {
  const btns = [...document.querySelectorAll('[id^="drop-multi-btn-"]')];
  btns.forEach(b => { b.disabled = true; });
  const started = Date.now();
  const timer = setInterval(() => {
    let pending = null;
    try { pending = localStorage.getItem('_netAnalyzer_pending'); } catch (e) { pending = null; }
    if (!pending || Date.now() - started > 10000) {
      clearInterval(timer);
      btns.forEach(b => { b.disabled = false; });
    }
  }, 300);
}
function _showDropMultiResult(items) {
  _dropMultiItems = items;
  _dropPending = null;
  document.getElementById('drop-box').style.display = 'none';
  const result = document.getElementById('drop-result');
  result.style.display = 'flex';
  document.getElementById('drop-chip').textContent = tr('drop.multi_found').replace('{n}', items.length);
  document.getElementById('drop-actions').innerHTML = '';
  document.getElementById('drop-manual-btn').style.display = 'none';
  document.getElementById('drop-choices').classList.remove('open');
  document.getElementById('drop-debug-toggle').style.display = 'none';
  document.getElementById('drop-debug-panel').classList.remove('open');
  const list = document.getElementById('drop-multi-list');
  list.innerHTML = '';
  list.style.display = '';
  // 依 TOOLS 順序分組，無法辨識者排最後（開啟時送往去識別化工具，與單檔「送到去識別化」一致）
  const groups = new Map();
  items.forEach((it, i) => {
    const key = it.detected ? it.detected.idx : -1;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(i);
  });
  const keys = [...groups.keys()].sort((a, b) => (a < 0) - (b < 0) || a - b);
  keys.forEach(k => {
    const h = document.createElement('div');
    h.style.cssText = 'font-weight:600;margin:10px 0 4px';
    h.textContent = k >= 0 ? `${TOOLS[k].icon} ${tr(TOOLS[k].id + '.title')}` : `❓ ${tr('drop.unknown')}`;
    list.appendChild(h);
    groups.get(k).forEach(i => {
      const it = items[i];
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border,#334155)';
      const nm = document.createElement('span');
      nm.style.cssText = 'flex:1;word-break:break-all;font-size:13px';
      nm.textContent = it.name + (it.detected && it.detected.vendor ? `（${VENDOR_NAMES[it.detected.vendor] || it.detected.vendor}）` : '')
        + (!it.detected && window.FileHowto ? ' — ' + FileHowto.explain(_dropKind(it), _lang) : '');
      const btn = document.createElement('button');
      btn.className = 'da-secondary';
      btn.id = 'drop-multi-btn-' + i;
      btn.textContent = k >= 0 ? tr('drop.open') : `🔒 ${tr('drop.to_anon')}`;
      btn.onclick = () => _openDropMultiItem(i);
      row.append(nm, btn);
      list.appendChild(row);
    });
  });
}

// 判斷不出工具時是哪一種錯誤檔案（XN53，file-howto.js）
function _dropKind(it) { return it.kind || FileHowto.classify({ name: it.name, head: it.head, text: it.text, error: it.error }); }
// 憑證資料（XN101）：拖放的內容是抓取腳本結果、openssl 輸出或純 PEM 時，提供「在本頁檢查」；多檔時存全部內容
let _dropCertTexts = null;
function _openDropCert() {
  const texts = _dropCertTexts || (_dropPending ? [_dropPending.text] : []);
  _dropCertTexts = null;
  document.getElementById('drop-overlay').classList.remove('active');
  if (window.certCheckLoad && texts.length) certCheckLoad(texts.length === 1 ? texts[0] : texts);
}
function _showDropResult(name, detected, text, entry) {
  const ml = document.getElementById('drop-multi-list');
  if (ml) { ml.style.display = 'none'; ml.innerHTML = ''; }
  const dt = document.getElementById('drop-debug-toggle');
  if (dt) dt.style.display = '';
  _dropPending = { name, text };
  const box = document.getElementById('drop-box');
  const result = document.getElementById('drop-result');
  const chip = document.getElementById('drop-chip');
  const actions = document.getElementById('drop-actions');
  const choices = document.getElementById('drop-choices');
  const manualBtn = document.getElementById('drop-manual-btn');
  box.style.display = 'none';
  result.style.display = 'flex';
  choices.classList.remove('open');
  const certInput = text && window.CertCheck && window.certCheckLoad ? CertCheck.detectInput(text) : '';
  if (certInput) {
    const C = window.CertCheck;
    const n = (_dropCertTexts || [text]).reduce((sum, t) => sum + C.parseInput(t).entries.length, 0);
    chip.textContent = tr('drop.cert_found').replace('{n}', n);
    chip.removeAttribute('data-drop-kind');
    actions.innerHTML = `<button class="da-primary" type="button" id="drop-cert-open">🔐 ${_glEsc(tr('drop.cert_open'))}</button>`;
    document.getElementById('drop-cert-open').addEventListener('click', _openDropCert);
    manualBtn.textContent = tr('drop.manual');
    manualBtn.style.display = '';
  } else if (window.isNsConf && isNsConf(text)) {
    // NetScaler ns.conf（XN105／XN107）：沒有對應的分析工具，在本頁做版本比對與曝險檢查，或交給去識別化。
    // F5 BIG-IP（XN116）改由防火牆分析處理，走下方 detected 分支並另附本頁版本比對按鈕
    chip.textContent = tr('drop.ns_found');
    chip.removeAttribute('data-drop-kind');
    actions.innerHTML = `<button class="da-primary" type="button" id="drop-dc-open">🛡 ${_glEsc(tr('drop.ns_open'))}</button>
      <button class="da-secondary" onclick="_dispatchWithPending(2,'netscaler')">🔒 ${tr('drop.to_anon')}</button>`;
    document.getElementById('drop-dc-open').addEventListener('click', () => {
      document.getElementById('drop-overlay').classList.remove('active');
      if (window.devCheckLoad) devCheckLoad(text);
    });
    manualBtn.textContent = tr('drop.manual');
    manualBtn.style.display = '';
  } else if (detected) {
    const vname = detected.vendor ? VENDOR_NAMES[detected.vendor] : null;
    chip.innerHTML = vname
      ? tr('drop.found').replace('{vendor}', `<span class="drop-vendor-badge">${vname}</span>`)
      : tr('drop.found_tool').replace('{tool}', tr(TOOLS[detected.idx].id + '.title'));
    // 2026-09-21 稽核修復：log 格式（idx:4，CEF/Syslog/WinEvent）沒有對應的去識別化轉送鏈
    // 目標——config_anonymizer 的 TOOL_HREFS 只有 3 個元素（fw/sw/gen），TOOL_HREFS[4] 為
    // undefined 會 fallback 錯誤工具，且 log_analyzer 本來就不消費 _netAnalyzer_anonThenOpen/
    // _netAnalyzer_anonResult（明確排除在匿名化轉送鏈目標之外）。故 log 格式不顯示此按鈕。
    const anonThenOpenBtn = detected.idx === 4 ? '' :
      `<button class="da-secondary" onclick='_dispatchWithAnon(${detected.idx},${JSON.stringify(detected.vendor)})'>🔒🔀 ${tr('drop.anon_then_open')}</button>`;
    actions.innerHTML = `
      <button class="da-primary" onclick='_dispatchWithPending(${detected.idx},${JSON.stringify(detected.vendor)})'>${TOOLS[detected.idx].icon} ${tr('drop.open')} ${tr(TOOLS[detected.idx].id+'.title')}</button>
      ${anonThenOpenBtn}
      <button class="da-secondary" onclick="_dispatchWithPending(2,null)">🔒 ${tr('drop.to_anon')}</button>`;
    // F5 BIG-IP（XN116）：另提供在本頁比對版本與曝險檢查
    if (detected.vendor === 'b' && window.devCheckLoad) {
      actions.insertAdjacentHTML('beforeend', `<button class="da-secondary" type="button" id="drop-dc-open">🛡 ${_glEsc(tr('drop.ns_open'))}</button>`);
      document.getElementById('drop-dc-open').addEventListener('click', () => { document.getElementById('drop-overlay').classList.remove('active'); devCheckLoad(text); });
    }
    manualBtn.textContent = tr('drop.manual');
    manualBtn.style.display = '';
  } else {
    // 說出是什麼檔、為什麼不能用、該改拿什麼（XN53）；只有看得懂的文字才預先展開手動選工具，二進位類避免誤送
    const kind = window.FileHowto ? _dropKind(entry || { name, text }) : 'text';
    chip.textContent = window.FileHowto ? FileHowto.explain(kind, _lang) : tr('drop.unknown');
    chip.setAttribute('data-drop-kind', kind);
    actions.innerHTML = window.FileHowto ? `<details class="drop-howto" style="text-align:left;max-width:560px"><summary style="cursor:pointer;font-size:13px">${_glEsc(FileHowto.title(_lang))}</summary>${FileHowto.listHtml(FileHowto.howtoKinds(kind), _lang)}</details>` : '';
    if (kind === 'text') { manualBtn.style.display = 'none'; choices.classList.add('open'); }
    else { manualBtn.textContent = tr('drop.manual'); manualBtn.style.display = ''; }
  }
  choices.innerHTML = TOOLS.map((t, i) =>
    `<button onclick="_dispatchWithPending(${i},null)">${t.icon} ${tr(t.id+'.title')}</button>`
  ).join('');
  _fillDropDebugPanel(text, detected);
}

// 任務 2（2026-09-23 新增）：拖放結果除錯面板——顯示命中規則說明（explainDetectedTool()）
// 與檔案前 8 行內容預覽。一律用 textContent 賦值（非 innerHTML），天生跳脫、無 Stored XSS
// 疑慮，比 innerHTML+esc() 更直接安全。預設收合，每次新結果一律重置為收合狀態，避免上一筆
// 展開狀態誤導使用者以為是這一筆的除錯資訊。
function _fillDropDebugPanel(text, detected) {
  const panel = document.getElementById('drop-debug-panel');
  const toggleBtn = document.getElementById('drop-debug-toggle');
  if (panel) panel.classList.remove('open');
  if (toggleBtn) toggleBtn.textContent = tr('drop.debug_toggle_show');
  const ruleLabelEl = document.getElementById('drop-debug-rule-label');
  const previewLabelEl = document.getElementById('drop-debug-preview-label');
  if (ruleLabelEl) ruleLabelEl.textContent = tr('drop.debug_rule_label');
  if (previewLabelEl) previewLabelEl.textContent = tr('drop.debug_preview_label');
  const ruleTextEl = document.getElementById('drop-debug-rule-text');
  if (ruleTextEl) {
    const reason = detected ? (explainDetectedTool(text) || tr('drop.debug_rule_fallback')) : tr('drop.unknown');
    ruleTextEl.textContent = reason;
  }
  const previewEl = document.getElementById('drop-debug-preview-text');
  if (previewEl) previewEl.textContent = text.split(/\r\n|\r|\n/).slice(0, 8).join('\n');
}
function _toggleDropDebugPanel() {
  const panel = document.getElementById('drop-debug-panel');
  const btn = document.getElementById('drop-debug-toggle');
  if (!panel) return;
  const open = panel.classList.toggle('open');
  if (btn) btn.textContent = tr(open ? 'drop.debug_toggle_hide' : 'drop.debug_toggle_show');
}

function _updateDropText() {
  const h = document.getElementById('drop-hint-txt');
  const s = document.getElementById('drop-sub-txt');
  if (h) h.textContent = tr('drop.hint');
  if (s) s.textContent = tr('drop.sub');
  const b = document.getElementById('drop-bar-txt');
  const p = document.getElementById('drop-bar-btn');
  if (b) b.textContent = tr('drop.bar');
  if (p) p.textContent = tr('drop.pick');
  // 除錯面板收合/展開按鈕文字：語言切換時也要跟著更新（比照面板未開啟的預設文案）
  const dbgBtn = document.getElementById('drop-debug-toggle');
  const dbgPanel = document.getElementById('drop-debug-panel');
  if (dbgBtn) dbgBtn.textContent = tr((dbgPanel && dbgPanel.classList.contains('open')) ? 'drop.debug_toggle_hide' : 'drop.debug_toggle_show');
}

(function(){
  let _dragCounter = 0;
  const overlay = document.getElementById('drop-overlay');
  document.addEventListener('dragenter', e => {
    if (![...e.dataTransfer.types].includes('Files')) return;
    _dragCounter++;
    overlay.classList.add('active');
    document.getElementById('drop-box').style.display = '';
    document.getElementById('drop-result').style.display = 'none';
    _dropPending = null;
  });
  document.addEventListener('dragleave', e => {
    _dragCounter--;
    if (_dragCounter <= 0) { _dragCounter = 0; overlay.classList.remove('active'); }
  });
  document.addEventListener('dragover', e => { e.preventDefault(); });
  document.addEventListener('drop', e => {
    e.preventDefault();
    _dragCounter = 0;
    const files = [...e.dataTransfer.files];
    if (!files.length) { overlay.classList.remove('active'); return; }
    _readDroppedFiles(files);
  });
})();

// 分析工具「交給入口頁判斷」（第二十九輪 NU9）：一次性交接 key `_netAnalyzer_route`（{name,text,from,ts}，TTL 30 秒），
// 取出即清除，以拖放同一套判斷（detectTool）顯示建議的工具
window.addEventListener('load', function () {
  if (/^#gl/.test(location.hash)) openGlossary();
  let d = null;
  try { d = JSON.parse(localStorage.getItem('_netAnalyzer_route') || 'null'); } catch (e) { d = null; }
  try { localStorage.removeItem('_netAnalyzer_route'); } catch (e) {}
  if (!d || typeof d.text !== 'string' || !d.text.trim() || Date.now() - d.ts > 30000) return;
  document.getElementById('drop-overlay').classList.add('active');
  _showDropResult(d.name || 'pasted.txt', detectTool(d.text), d.text);
});
document.getElementById('file-pick').addEventListener('change', function() {
  const files = [...this.files];
  if (!files.length) return;
  this.value = '';
  const overlay = document.getElementById('drop-overlay');
  overlay.classList.add('active');
  document.getElementById('drop-box').style.display = 'none';
  document.getElementById('drop-result').style.display = 'none';
  _readDroppedFiles(files);
});

