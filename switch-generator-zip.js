// ============================================================
// switch_config_generator：純 JS ZIP 寫入器（2026-09 從 switch-generator-app.js 拆出）
// ============================================================
// 純函式，零 DOM 依賴（比照同批拆分先例）。批次 CSV 匯出（#bulk-card）用，無外部依賴的
// STORED（無壓縮）格式 ZIP 產生器：crc32() 為 ZIP 格式要求的檔案校驗碼，createZip() 組裝
// local file header + central directory。

function crc32(buf){
  let c=~0;
  const t=(()=>{
    const T=new Uint32Array(256);
    for(let i=0;i<256;i++){let v=i;for(let j=0;j<8;j++)v=(v&1)?(0xEDB88320^(v>>>1)):(v>>>1);T[i]=v;}
    return T;
  })();
  for(let i=0;i<buf.length;i++)c=t[(c^buf[i])&0xFF]^(c>>>8);
  return (~c)>>>0;
}

function createZip(files,manifestContent){
  const fileObject={...files,'manifest.csv':manifestContent};
  const enc=(s)=>new TextEncoder().encode(s);
  const u16=(n)=>[n&0xFF,(n>>8)&0xFF];
  const u32=(n)=>[n&0xFF,(n>>8)&0xFF,(n>>16)&0xFF,(n>>24)&0xFF];
  const now=new Date();
  const dosTime=((now.getHours()<<11)|(now.getMinutes()<<5)|(now.getSeconds()>>1));
  const dosDate=(((now.getFullYear()-1980)<<9)|((now.getMonth()+1)<<5)|now.getDate());
  const parts=[];
  const centralDir=[];
  let offset=0;
  let numEntries=0;
  for(const [filename,content] of Object.entries(fileObject)){
    const nameBytes=enc(filename);
    const data=enc(content);
    const crc=crc32(data);
    const size=data.length;
    const lhdr=new Uint8Array([
      0x50,0x4B,0x03,0x04,
      0x14,0x00,
      0x00,0x08, // 通用旗標 bit 11 = 檔名/註解為 UTF-8（含中文檔名時避免亂碼）
      0x00,0x00,
      ...u16(dosTime),...u16(dosDate),
      ...u32(crc),
      ...u32(size),...u32(size),
      ...u16(nameBytes.length),0x00,0x00,
    ]);
    parts.push(lhdr,nameBytes,data);
    const cdEntry=new Uint8Array([
      0x50,0x4B,0x01,0x02,
      0x14,0x00,0x14,0x00,
      0x00,0x08,0x00,0x00, // 通用旗標 bit 11 = UTF-8 檔名，與 local header 一致

      ...u16(dosTime),...u16(dosDate),
      ...u32(crc),
      ...u32(size),...u32(size),
      ...u16(nameBytes.length),0x00,0x00, // filename length, extra field length
      0x00,0x00,                          // file comment length
      0x00,0x00,                          // disk number start
      0x00,0x00,                          // internal file attributes
      0x00,0x00,0x00,0x00,                // external file attributes
      ...u32(offset),                     // relative offset of local header
    ]);
    centralDir.push(cdEntry,nameBytes);
    offset+=lhdr.length+nameBytes.length+size;
    numEntries++;
  }
  const cdSize=centralDir.reduce((s,b)=>s+b.length,0);
  const eocd=new Uint8Array([
    0x50,0x4B,0x05,0x06,
    0x00,0x00,0x00,0x00,
    ...u16(numEntries),...u16(numEntries),
    ...u32(cdSize),...u32(offset),
    0x00,0x00,
  ]);
  const all=[...parts,...centralDir,eocd];
  const totalLen=all.reduce((s,b)=>s+b.length,0);
  const finalBuffer=new Uint8Array(totalLen);
  let pos=0;
  for(const b of all){finalBuffer.set(b,pos);pos+=b.length;}
  return finalBuffer;
}
