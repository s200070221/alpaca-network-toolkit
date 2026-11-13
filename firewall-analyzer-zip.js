// ═══════════════════════════════════════════════════════════════════════════
// firewall-analyzer-zip.js — 純 JS ZIP 寫入器（XN146，FortiGate 匯入順序包用）
// STORED（無壓縮）格式，寫法與 switch-generator-zip.js 的 createZip() 相同（另放一份並包 IIFE，
// 避免與其他頁面的頂層名稱衝突）；檔名以 UTF-8 旗標（bit 11）寫入。以 window.FwZip 對外
// ═══════════════════════════════════════════════════════════════════════════
(function () {
  let T = null;
  function crc32(buf) {
    if (!T) { T = new Uint32Array(256); for (let i = 0; i < 256; i++) { let v = i; for (let j = 0; j < 8; j++) v = (v & 1) ? (0xEDB88320 ^ (v >>> 1)) : (v >>> 1); T[i] = v; } }
    let c = ~0;
    for (let i = 0; i < buf.length; i++) c = T[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
    return (~c) >>> 0;
  }
  // files：[{name, text}]（依陣列順序寫入）→ Uint8Array
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
      const name = enc(f.name), data = enc(f.text), crc = crc32(data), size = data.length;
      const lh = new Uint8Array([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x08, 0x00, 0x00, ...u16(dosTime), ...u16(dosDate),
        ...u32(crc), ...u32(size), ...u32(size), ...u16(name.length), 0x00, 0x00]);
      parts.push(lh, name, data);
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
  window.FwZip = { crc32, createZip };
})();
