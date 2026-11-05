// hub-cert.js — 入口頁「網站憑證檢查」卡片（XN101）：下載抓取腳本與執行教學、貼上／上傳／拖放結果、
// 以 cert-check.js 離線分析並列出結果與 CSV。新模組包 IIFE，給其他檔案呼叫的函式以 window 掛出：
//   renderCertCard()（setLang 呼叫）、certCheckLoad(text)（拖放「在本頁檢查」）。
// 使用者加入的內部根憑證只存在記憶體（這個分頁），不寫入 localStorage。
(function () {
  'use strict';
  const st = { os: '', results: null, extraRoots: [], busy: false };
  const $ = id => document.getElementById(id);
  const esc = s => _glEsc(s == null ? '' : s);
  const fmt = (k, p) => String(tr(k)).replace(/\{(\w+)\}/g, (m, n) => (p && p[n] != null ? p[n] : ''));
  const SEV_RANK = { high: 3, medium: 2, low: 1, info: 0 };

  function defaultOs() {
    const p = String((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '');
    return /win/i.test(p) ? 'win' : /mac/i.test(p) ? 'mac' : 'linux';
  }
  // 教學指令中的主機：只接受主機名稱、IP 與埠號字元，其餘忽略
  function targets() {
    const v = String(($('cert-targets') || {}).value || '');
    // 主機名稱須含點（或為 localhost）、不以 - 開頭，可加 :埠號；IPv6 寫成 [位址]:埠號
    const ok = x => /^(?!-)[A-Za-z0-9._-]+(?::\d{1,5})?$/.test(x) && (/\./.test(x) || /^localhost(?::|$)/i.test(x)) || /^\[[0-9A-Fa-f:]+\](?::\d{1,5})?$/.test(x);
    const list = v.split(/[,;\s]+/).filter(ok).slice(0, 20);
    return list.length ? list : ['example.com'];
  }
  function cmdBlock(cmd) {
    return `<div class="cert-cmd"><code>${esc(cmd)}</code><button type="button" class="cert-copy" data-cert-copy="${esc(cmd)}">${esc(tr('cert.copy'))}</button></div>`;
  }
  function renderHowto() {
    const body = $('cert-howto-body');
    if (!body) return;
    document.querySelectorAll('#cert-tabs [data-cert-os]').forEach(b => {
      b.textContent = tr('cert.os_' + b.dataset.certOs);
      b.setAttribute('aria-selected', String(b.dataset.certOs === st.os));
    });
    const t = targets(), first = t[0].replace(/^\[|\]$/g, '').replace(/:\d+$/, '');
    let h;
    if (st.os === 'win') {
      h = `<ol class="cert-steps"><li>${esc(tr('cert.win_s1'))} <button type="button" class="cert-dl" data-cert-dl="ps1">⬇ ${esc(tr('cert.dl_ps1'))}</button></li>`
        + `<li>${esc(tr('cert.win_s2'))}${cmdBlock('cd $HOME\\Downloads')}</li>`
        + `<li>${esc(tr('cert.win_s3'))}${cmdBlock('powershell -ExecutionPolicy Bypass -File .\\fetch_cert_chain.ps1 -Hosts ' + t.join(','))}</li>`
        + `<li>${esc(tr('cert.win_s4'))}</li></ol>`;
    } else {
      h = `<ol class="cert-steps"><li>${esc(tr('cert.nix_s1'))} <button type="button" class="cert-dl" data-cert-dl="sh">⬇ ${esc(tr('cert.dl_sh'))}</button></li>`
        + `<li>${esc(tr('cert.nix_s2'))}${cmdBlock('cd ~/Downloads && bash fetch_cert_chain.sh ' + t.join(' '))}</li>`
        + `<li>${esc(tr('cert.nix_s3'))}</li></ol>`
        + (st.os === 'mac' ? `<p class="cert-hint">${esc(tr('cert.mac_note'))}</p>` : '')
        + `<p class="cert-hint">${esc(tr('cert.alt_openssl'))}</p>${cmdBlock(`openssl s_client -connect ${first}:443 -servername ${first} -showcerts </dev/null > ${first}.txt`)}`;
    }
    body.innerHTML = h + `<p class="cert-hint">🔒 ${esc(tr('cert.privacy'))}</p>`;
  }

  function renderCertCard() {
    if (!$('certcheck')) return;
    if (!st.os) st.os = defaultOs();
    const set = (id, k) => { const e = $(id); if (e) e.textContent = tr(k); };
    set('cert-title', 'cert.title'); set('cert-intro', 'cert.intro'); set('cert-howto-sum', 'cert.howto'); set('cert-targets-lbl', 'cert.targets');
    set('cert-step2', 'cert.step2'); set('cert-run', 'cert.run'); set('cert-upload-lbl', 'cert.upload'); set('cert-roots-lbl', 'cert.roots_btn');
    set('cert-warn-lbl', 'cert.warn_days'); set('cert-host-lbl', 'cert.host_lbl');
    const pa = $('cert-paste'); if (pa) pa.placeholder = tr('cert.paste_ph');
    const rn = $('cert-roots-n'); if (rn) rn.textContent = st.extraRoots.length ? fmt('cert.roots_n', { n: st.extraRoots.length }) : '';
    const C = window.CertCheck;
    const note = $('cert-note'); if (note && C) note.textContent = fmt('cert.note', { n: C.ROOTS.length, date: C.ROOTS_ASOF });
    renderHowto();
    renderResults();
  }

  function downloadScript(kind) {
    const S = window.CertScripts;
    if (!S) return;
    const name = kind === 'ps1' ? 'fetch_cert_chain.ps1' : 'fetch_cert_chain.sh';
    // ps1 原始檔帶 UTF-8 BOM（Windows PowerShell 5.1 沒有 BOM 會用系統字碼頁讀取，中文訊息會亂碼）
    const blob = new Blob([kind === 'ps1' ? S.ps1 : S.sh], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  function copyText(btn, text) {
    const done = () => { const o = btn.textContent; btn.textContent = tr('cert.copied'); setTimeout(() => { btn.textContent = o; }, 1200); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, () => {});
  }

  const iso = t => (t == null ? '' : new Date(t).toISOString().slice(0, 10));
  function trustText(r) {
    if (!r.anchor) return '—';
    const a = r.anchor || {};
    if (a.type === 'mozilla') return fmt('cert.trust_mozilla', { name: a.name });
    if (a.type === 'internal') return fmt('cert.trust_internal', { name: a.name });
    if (a.type === 'incomplete') return tr('cert.trust_incomplete');
    return tr('cert.trust_untrusted');
  }
  function findingText(f) {
    const p = Object.assign({}, f.p);
    if (f.id === 'missing-intermediate') p.aia = p.aia ? fmt('cert.aia_hint', { url: p.aia }) : '';
    return fmt('cert.f_' + f.id, p);
  }
  const sevBadge = sev => `<span class="cert-sev cert-sev-${esc(sev)}">${esc(tr('cert.sev_' + sev))}</span>`;
  const realFindings = r => r.findings.filter(f => f.sev !== 'info');
  function expiryCell(r) {
    if (!r.leaf || r.leaf.notAfter == null) return '';
    const d = r.daysLeft;
    return esc(iso(r.leaf.notAfter)) + ` <small>(${esc(d >= 0 ? fmt('cert.days_left', { n: d }) : fmt('cert.days_over', { n: -d }))})</small>`;
  }
  function keyText(k) { return k.type === 'RSA' ? 'RSA ' + k.bits : k.type === 'EC' ? 'ECDSA ' + k.curve : k.type; }
  function hostDetail(r) {
    let h = '<ul class="cert-findings">' + (r.findings.length ? r.findings.map(f => `<li>${sevBadge(f.sev)} ${esc(findingText(f))}</li>`).join('') : `<li>${esc(tr('cert.ok'))}</li>`) + '</ul>';
    if (r.chain.length) {
      h += `<div class="cert-sub">${esc(tr('cert.chain_title'))}</div><ol class="cert-chain">` + r.chain.map(c => {
        const sig = c.sigOk === true ? '✅ ' + tr('cert.sig_ok') : c.sigOk === false ? '❌ ' + tr('cert.sig_bad') : '— ' + tr('cert.sig_na');
        return `<li><b>${esc(c.cn)}</b><br><small>${esc(fmt('cert.c_valid', { from: iso(c.notBefore), to: iso(c.notAfter) }))} · ${esc(fmt('cert.c_key', { key: keyText(c.key), alg: c.sigAlg }))} · ${esc(sig)}</small></li>`;
      }).join('') + '</ol>';
      const a = r.anchor || {};
      if (a.type === 'mozilla' && !a.sent) h += `<div class="cert-hint">${esc(fmt('cert.anchor_mozilla', { name: a.name }))}</div>`;
      else if (a.type === 'internal' && !a.sent) h += `<div class="cert-hint">${esc(fmt('cert.anchor_internal', { name: a.name }))}</div>`;
      else if (a.type === 'incomplete') h += `<div class="cert-hint">${esc(fmt('cert.anchor_incomplete', { name: a.name }))}</div>`;
    }
    const tls = r.tls || {};
    if (Object.values(tls).some(v => v !== 'untested') || r.negotiated) {
      h += `<div class="cert-sub">${esc(tr('cert.tls_title'))}</div><div class="cert-tls">`
        + ['1.0', '1.1', '1.2', '1.3'].map(k => `<span class="cert-tls-${esc(tls[k] || 'untested')}">TLS ${k}：${esc(tr('cert.tls_' + (tls[k] || 'untested')))}</span>`).join('')
        + '</div>' + (r.negotiated && (r.negotiated.protocol || r.negotiated.cipher) ? `<div class="cert-hint">${esc(fmt('cert.negotiated', r.negotiated))}</div>` : '');
    }
    const urls = r.leaf ? r.leaf.ocsp.concat(r.leaf.crl) : [];
    if (urls.length) h += `<div class="cert-hint">${esc(fmt('cert.revocation', { urls: urls.join('、') }))}</div>`;
    return h;
  }
  function renderResults() {
    const box = $('cert-result');
    if (!box) return;
    const res = st.results;
    if (!res) { box.innerHTML = ''; return; }
    if (!res.length) { box.innerHTML = `<p class="cert-empty">${esc(tr('cert.empty'))}</p>`; return; }
    const rows = res.map((r, i) => {
      const n = realFindings(r).length;
      return `<tr><td><a href="#cert-host-${i}">${esc(r.host ? r.host + ':' + r.port : '—')}</a></td><td>${n ? sevBadge(r.worst) : '✅ ' + esc(tr('cert.ok'))}</td>`
        + `<td>${expiryCell(r)}</td><td>${esc(r.leaf ? (r.leaf.issuer.find(a => a[0] === 'CN') || r.leaf.issuer.find(a => a[0] === 'O') || ['', ''])[1] : '')}</td><td>${esc(trustText(r))}</td><td>${n}</td></tr>`;
    }).join('');
    box.innerHTML = `<div class="cert-res-bar"><button type="button" id="cert-csv">${esc(tr('cert.export_csv'))}</button></div>`
      + `<div style="overflow-x:auto"><table class="cert-table"><thead><tr>${['host', 'result', 'expiry', 'issuer', 'trust', 'findings'].map(k => `<th>${esc(tr('cert.col_' + k))}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table></div>`
      + res.map((r, i) => `<details class="cert-host" id="cert-host-${i}"${res.length === 1 || r.worst === 'high' ? ' open' : ''}><summary>${esc(r.host ? r.host + ':' + r.port : '—')} ${realFindings(r).length ? sevBadge(r.worst) : '✅'}</summary>${hostDetail(r)}</details>`).join('');
  }

  // CSV：公式注入防護（=、+、-、@ 開頭前綴單引號），與其他工具相同
  const csvCell = v => { let s = String(v == null ? '' : v); if (/^[=+\-@]/.test(s)) s = "'" + s; return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  function exportCsv() {
    if (!st.results || !st.results.length) return;
    const head = ['host', 'port', 'result', 'expires', 'days_left', 'issuer', 'trust', 'findings'];
    const lines = [head.join(',')].concat(st.results.map(r => [r.host, r.port, realFindings(r).length ? r.worst : 'ok', r.leaf ? iso(r.leaf.notAfter) : '', r.daysLeft == null ? '' : r.daysLeft,
      r.leaf ? (r.leaf.issuer.find(a => a[0] === 'CN') || ['', ''])[1] : '', trustText(r), r.findings.map(findingText).join(' / ')].map(csvCell).join(',')));
    const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'cert-check_' + new Date().toISOString().slice(0, 10) + '.csv';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  async function runCheck(text) {
    const C = window.CertCheck;
    if (!C || st.busy) return;
    st.busy = true;
    try {
      const parsed = C.parseInput(text);
      const host = String(($('cert-host') || {}).value || '').trim().toLowerCase();
      const warnDays = Math.max(1, Math.min(3650, parseInt(($('cert-warn') || {}).value, 10) || 30));
      const out = [];
      for (const e of parsed.entries) {
        if (!e.host && /^[A-Za-z0-9.\-_:]+$/.test(host)) e.host = host;
        out.push(await C.analyzeHost(e, { extraRoots: st.extraRoots, warnDays }));
      }
      out.sort((a, b) => SEV_RANK[b.worst] - SEV_RANK[a.worst] || (a.daysLeft == null ? 1 : b.daysLeft == null ? -1 : a.daysLeft - b.daysLeft));
      st.results = out;
      st.lastText = text;
    } finally { st.busy = false; }
    renderResults();
  }
  async function readFiles(files) {
    const C = window.CertCheck, texts = [];
    for (const f of files) {
      const buf = new Uint8Array(await f.arrayBuffer());
      texts.push(C && C.looksLikeDer(buf) ? C.derToPem(buf) : new TextDecoder('utf-8').decode(buf));
    }
    return texts;
  }
  // 多個檔案：各自解析後合併（不同格式可混用）
  async function runMany(texts) {
    const C = window.CertCheck;
    if (texts.length === 1) return runCheck(texts[0]);
    const entries = [];
    for (const t of texts) entries.push(...C.parseInput(t).entries);
    const doc = { format: 'alpaca-certchain', version: 1, hosts: entries.map(e => ({ host: e.host, port: e.port, chain: e.chain.map(C.bytesToB64), chainSource: e.chainSource, tls: e.tls, negotiated: e.negotiated, osTrust: e.osTrust, error: e.error })) };
    return runCheck(JSON.stringify(doc));
  }

  // text：單一內容或多個檔案內容的陣列（拖放多檔）
  function certCheckLoad(text) {
    const card = $('certcheck');
    if (!card) return;
    const pa = $('cert-paste');
    const one = Array.isArray(text) ? (text.length === 1 ? text[0] : null) : text;
    if (pa) pa.value = one && one.length <= 200000 ? one : '';
    card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return Array.isArray(text) ? runMany(text) : runCheck(text);
  }

  function init() {
    const card = $('certcheck');
    if (!card) return;
    card.addEventListener('click', e => {
      const t = e.target.closest('[data-cert-os],[data-cert-dl],[data-cert-copy],#cert-run,#cert-csv');
      if (!t) return;
      if (t.dataset.certOs) { st.os = t.dataset.certOs; renderHowto(); }
      else if (t.dataset.certDl) downloadScript(t.dataset.certDl);
      else if (t.dataset.certCopy != null) copyText(t, t.dataset.certCopy);
      else if (t.id === 'cert-run') runCheck(($('cert-paste') || {}).value || '');
      else if (t.id === 'cert-csv') exportCsv();
    });
    const tg = $('cert-targets');
    if (tg) tg.addEventListener('input', renderHowto);
    const up = $('cert-file');
    if (up) up.addEventListener('change', async () => { const files = [...up.files]; up.value = ''; if (files.length) runMany(await readFiles(files)); });
    const rf = $('cert-roots-file');
    if (rf) rf.addEventListener('change', async () => {
      const C = window.CertCheck;
      for (const t of await readFiles([...rf.files])) for (const der of C.pemBlocks(t)) { try { C.parseCert(der); st.extraRoots.push(der); } catch (e) { /* 不是憑證略過 */ } }
      rf.value = '';
      renderCertCard();
      if (st.lastText) runCheck(st.lastText);
    });
    const warn = $('cert-warn');
    if (warn) warn.addEventListener('change', () => { if (st.lastText) runCheck(st.lastText); });
  }

  window.renderCertCard = renderCertCard;
  window.certCheckLoad = certCheckLoad;
  window._certCheckState = st; // 供 e2e 檢查
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
