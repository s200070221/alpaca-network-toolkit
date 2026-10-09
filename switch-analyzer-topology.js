// ============================================================
// switch_analyzer：Stack/VSF/LACP 拓樸 SVG 產生（2026-09 從 switch-analyzer-app.js 拆出）
// ============================================================
// 純函式，零 DOM／parsed 全域依賴（比照 switch-analyzer-diff.js／firewall-analyzer-audit.js
// 既有拆分先例）——switch-analyzer-app.js 本身頂層有多處立即執行的 DOM 綁定，純函式若寫進該檔會
// 導致 Node 測試沙箱一讀取整檔就因 document is not defined 拋錯。涵蓋：VSF/LACP/多裝置 LLDP/
// IRF/Alcatel Stack/ExtremeStack/ICX Stack/StackWise 各廠牌拓樸圖，輸入已解析完的 parsed 物件
// （或其子欄位），輸出 SVG 字串。

function buildVSUSVG(p){
  const vsu=p.stack;
  const members=vsu.members||[];
  const vslMap={};
  (vsu.vsl||[]).forEach(v=>{vslMap[v.memberId]=v.interfaces;});
  const tc='var(--accent)';
  const boxW=150,boxH=112,gap=Math.max(200,680/(members.length||1));
  const W=Math.max(680,members.length*gap+100);
  const H=260;
  const startX=Math.max(28,(W-gap*(members.length-1)-boxW)/2);
  const bY=60;
  const boxes=members.map((m,i)=>({x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m}));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" style="width:100%;max-height:270px">`;
  const isRing=boxes.length>2;
  for(let i=0;i<boxes.length;i++){
    if(i===boxes.length-1&&!isRing)break;
    const a=boxes[i],b=boxes[(i+1)%boxes.length];
    const isWrap=i===boxes.length-1;
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+40} ${b.cx} ${b.y+boxH+40} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.2" fill="none" opacity="${isWrap?0.32:0.6}" ${isWrap?'stroke-dasharray="5,3"':''}/>`;
  }
  boxes.forEach(bx=>{
    const m=bx.mem;
    const isActive=m.role==='Active';
    const col=isActive?tc:'var(--green)';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="var(--surface2)" stroke="${col}" stroke-width="${isActive?2:1.4}"/>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+24}" text-anchor="middle" font-size="12" font-weight="700" fill="${col}" font-family="monospace">VSU${esc(m.id)}</text>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+42}" text-anchor="middle" font-size="9" fill="${col}">${esc(m.role||'—')}</text>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+60}" text-anchor="middle" font-size="9" fill="var(--text-dim)" font-family="monospace">prio ${esc(String(m.priority))}</text>`;
    const vslPorts=(vslMap[m.id]||[]).slice(0,2).join(', ');
    if(vslPorts)svg+=`<text x="${bx.cx}" y="${bx.y+80}" text-anchor="middle" font-size="8" fill="var(--text-muted)" font-family="monospace">${esc(vslPorts)}</text>`;
  });
  svg+='</svg>';
  return svg;
}

function buildOneLACPSVG(g){
  const members=_lacpMembersArr(g);
  const cnt=members.length||1;
  const CX=200,CY=150,R=Math.min(110,50+cnt*14),nodeR=30;
  const W=400,H=300;
  const positions=members.map((_,i)=>{
    const a=(2*Math.PI*i/cnt)-Math.PI/2;
    return{x:CX+R*Math.cos(a),y:CY+R*Math.sin(a)};
  });
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" style="width:100%;max-width:420px;max-height:320px">`;
  positions.forEach(pos=>{
    svg+=`<line x1="${CX}" y1="${CY}" x2="${pos.x}" y2="${pos.y}" stroke="var(--accent)" stroke-width="2" stroke-opacity="0.5"/>`;
  });
  svg+=`<circle cx="${CX}" cy="${CY}" r="${nodeR}" fill="var(--surface2)" stroke="var(--accent)" stroke-width="2.5"/>`;
  svg+=`<text x="${CX}" y="${CY-3}" text-anchor="middle" dominant-baseline="middle" font-size="11" font-weight="700" fill="var(--accent)" font-family="monospace">${esc(g.name)}</text>`;
  svg+=`<text x="${CX}" y="${CY+10}" text-anchor="middle" dominant-baseline="middle" font-size="8" fill="var(--text-dim)">${esc(g.mode||'—')}</text>`;
  positions.forEach((pos,i)=>{
    const m=members[i];
    const name=typeof m==='string'?m:m.name;
    const lm=typeof m==='object'?m.lacpMode:null;
    const col=lm==='Active'?'var(--green)':lm==='Passive'?'var(--yellow)':'var(--purple)';
    svg+=`<circle cx="${pos.x}" cy="${pos.y}" r="24" fill="var(--surface2)" stroke="${col}" stroke-width="1.8"/>`;
    svg+=`<text x="${pos.x}" y="${pos.y-2}" text-anchor="middle" dominant-baseline="middle" font-size="9" font-weight="600" fill="var(--text)" font-family="monospace">${esc((name||'').substring(0,10))}</text>`;
    if(lm)svg+=`<text x="${pos.x}" y="${pos.y+10}" text-anchor="middle" dominant-baseline="middle" font-size="7" fill="${col}">${esc(lm)}</text>`;
  });
  svg+='</svg>';
  return`<div style="background:var(--surface2);border-radius:8px;padding:10px"><div style="font-size:11px;color:var(--text-dim);padding:0 6px 4px">${esc(g.name)} · MTU ${esc(String(g.mtu||'—'))}</div>${svg}</div>`;
}

function buildLACPTopo(l){
  return`<div style="display:flex;flex-wrap:wrap;gap:14px;padding:14px 18px">${l.map(g=>buildOneLACPSVG(g)).join('')}</div>`;
}

function buildTopoSVG(p){
  const irf=p.irf;
  const mems=irf?irf.members:[{id:'1',priority:0,role:'Master'}];
  const tc='#00c8f0';
  const boxW=158,boxH=196,gap=Math.max(205,720/(mems.length||1));
  const W=Math.max(720,mems.length*gap+100);
  const H=420;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2);
  const bY=106;
  const boxes=mems.map((m,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m,
    ports:p.interfaces.filter(ii=>ii.member===m.id&&ii.type==='physical').length,
    stPorts:p.interfaces.filter(ii=>ii.member===m.id&&ii.type==='stack'),
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif">
<defs>
<marker id="arr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="glow"><feGaussianBlur stdDeviation="2.8" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<filter id="glows"><feGaussianBlur stdDeviation="1.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<linearGradient id="hg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="${tc}" stop-opacity=".18"/><stop offset="100%" stop-color="#0080ff" stop-opacity=".04"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<rect x="0" y="0" width="${W}" height="50" fill="url(#hg)" rx="12"/>
<rect x="0" y="38" width="${W}" height="12" fill="#080c17"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">IRF STACK TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-120}" y="11" width="108" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-66}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">IRF · Domain ${esc(irf?.domain||'—')}</text>`;

  // Draw links
  const isRing=mems.length>2;
  for(let i=0;i<mems.length;i++){
    if(i===mems.length-1&&!isRing)break;
    const a=boxes[i],b=boxes[(i+1)%mems.length];
    const lnk=irf?.links.find(l=>l.fromMember===a.mem.id)||(irf?.links.find(l=>l.fromMember===b.mem.id))||{ports:[],shortPorts:[]};
    const linkLabel=(lnk.shortPorts||[]).slice(0,2).join(' | ');
    if(i===mems.length-1){
      svg+=`<path d="M ${a.cx} ${a.y+boxH+8} C ${a.cx} ${a.y+boxH+82} ${b.cx} ${b.y+boxH+82} ${b.cx} ${b.y+boxH+8}" stroke="${tc}" stroke-width="2" fill="none" opacity=".38" stroke-dasharray="5,3" marker-end="url(#arr)"/>`;
      svg+=`<text x="${(a.cx+b.cx)/2}" y="${a.y+boxH+68}" font-size="9" fill="${tc}" text-anchor="middle" opacity=".55" font-family="JetBrains Mono,monospace">Ring</text>`;
    }else{
      svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+54} ${b.cx} ${b.y+boxH+54} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".62" marker-end="url(#arr)" filter="url(#glows)"/>`;
      if(linkLabel){const mx=(a.cx+b.cx)/2,my=a.y+boxH+45;svg+=`<rect x="${mx-52}" y="${my-11}" width="104" height="17" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".9"/><text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${esc(linkLabel)}</text>`;}
    }
  }

  // Draw boxes
  boxes.forEach((bx,i)=>{
    const m=bx.mem,isMaster=(m.role==='Master')||(i===0&&!m.role);
    const prio=m.priority||'—';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#1e3a5f'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#glow)"':''}/>`;
    if(isMaster)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".03"/>`;
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.18:.07}" stroke="${tc}" stroke-width=".5"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#64748b'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">M${m.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#2c3e58'}" text-anchor="end" font-weight="600">${esc(m.role||'')}</text>`;
    // Port slots
    svg+=`<rect x="${bx.x+12}" y="${bx.y+40}" width="${boxW-24}" height="48" rx="6" fill="#080c17" stroke="#1e3a5f" stroke-width="1"/>`;
    const pc=Math.min(bx.ports,16);
    for(let pi=0;pi<pc;pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+46+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.42:.2}"/>`;}
    if(bx.ports>16)svg+=`<text x="${bx.cx}" y="${bx.y+85}" font-size="8.5" fill="#2c3e58" text-anchor="middle" font-family="JetBrains Mono,monospace">+${bx.ports-16}</text>`;
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+97}" x2="${bx.x+boxW-12}" y2="${bx.y+97}" stroke="#1e3a5f" stroke-width=".5"/>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+112}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('svg.port_count')}</text><text x="${bx.x+boxW-16}" y="${bx.y+112}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports}</text>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+129}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text><text x="${bx.x+boxW-16}" y="${bx.y+129}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${esc(String(prio))}</text>`;
    // Trunk uplink indicator
    const tpCount=p.interfaces.filter(ii=>ii.member===m.id&&ii.mode==='trunk').length;
    if(tpCount){svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-26}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/>
    <polygon points="${bx.cx},${bx.y-30} ${bx.cx-5},${bx.y-22} ${bx.cx+5},${bx.y-22}" fill="${tc}" opacity=".5"/>
    <text x="${bx.cx}" y="${bx.y-35}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Trunk×${tpCount}</text>`;}
    // IRF port footer
    if(bx.stPorts&&bx.stPorts.length){const sn=bx.stPorts.map(pp=>pp.name.replace(/^(?:Ten-?GigabitEthernet|FortyGigE|HundredGigE)/i,'')).slice(0,2).join(' | ');svg+=`<text x="${bx.cx}" y="${bx.y+boxH-10}" font-size="8.5" fill="${tc}" text-anchor="middle" opacity=".65" font-family="JetBrains Mono,monospace">${esc(sn)}</text>`;}
  });

  // Legend
  const lY=H-40;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="32" rx="5" fill="#0f1629" stroke="#1e3a5f" stroke-width=".5"/>
  <rect x="24" y="${lY+9}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+18}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Master</text>
  <rect x="108" y="${lY+9}" width="10" height="10" rx="2" fill="#1e3a5f"/>
  <text x="124" y="${lY+18}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby</text>
  <line x1="196" y1="${lY+14}" x2="218" y2="${lY+14}" stroke="${tc}" stroke-width="2"/>
  <text x="224" y="${lY+18}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">${tr('svg.irf_link')}</text>
  <line x1="295" y1="${lY+14}" x2="317" y2="${lY+14}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/>
  <text x="323" y="${lY+18}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">${tr('svg.trunk_uplink')}</text>
  <text x="${W-18}" y="${lY+20}" font-size="9" fill="#2c3e58" text-anchor="end" font-family="JetBrains Mono,monospace">Comware Analyzer</text>`;
  svg+=`</svg>`;
  return svg;
}

function buildVSFSVGReport(p){
  const s=p.stack;
  const mems=s.members;
  const tc='#f97316'; // Aruba orange
  const boxW=158,boxH=188,gap=Math.max(200,720/(mems.length||1));
  const W=Math.max(720,mems.length*gap+100),H=400;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2),bY=96;
  const boxes=mems.map((m,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m,
    ports:p.interfaces.filter(ii=>ii.member===m.id&&ii.type==='physical'&&ii.name.startsWith(m.id+'/')).length,
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif;max-width:100%">
<defs>
<marker id="varr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="vglow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">VSF STACK TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-110}" y="11" width="98" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-61}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">Aruba VSF</text>`;
  for(let i=0;i<mems.length;i++){
    if(i===mems.length-1)break;
    const a=boxes[i],b=boxes[i+1];
    const lnk=s.links?.[i];
    const lbl=lnk?lnk.ports.slice(0,2).join(' | '):'';
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#varr)"/>`;
    if(lbl){const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;svg+=`<rect x="${mx-50}" y="${my-10}" width="100" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/><text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${lbl}</text>`;}
  }
  boxes.forEach((bx)=>{
    const m=bx.mem,isMaster=m.role==='Master';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#1e3a5f'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#vglow)"':''}/>`;
    if(isMaster)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".025"/>`;
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.18:.07}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#64748b'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">M${m.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#2c3e58'}" text-anchor="end" font-weight="600">${m.role||''}</text>`;
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#1e3a5f" stroke-width="1"/>`;
    const pc=Math.min(bx.ports,16);
    for(let pi=0;pi<pc;pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.42:.2}"/>`;}
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#1e3a5f" stroke-width=".5"/>
    <text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.model')}</text><text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="9.5" fill="#dde8f5" text-anchor="end" font-family="JetBrains Mono,monospace">${(m.model||'—').replace(/^JL/i,'JL')}</text>
    <text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text><text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${m.priority||'—'}</text>
    <text x="${bx.x+16}" y="${bx.y+140}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.port_count')}</text><text x="${bx.x+boxW-14}" y="${bx.y+140}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports}</text>`;
    const tpCount=p.interfaces.filter(ii=>ii.member===m.id&&ii.mode==='trunk').length;
    if(tpCount)svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-24}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/><polygon points="${bx.cx},${bx.y-28} ${bx.cx-5},${bx.y-20} ${bx.cx+5},${bx.y-20}" fill="${tc}" opacity=".5"/><text x="${bx.cx}" y="${bx.y-33}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Trunk×${tpCount}</text>`;
  });
  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#1e3a5f" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Master</text>
  <rect x="100" y="${lY+8}" width="10" height="10" rx="2" fill="#1e3a5f"/>
  <text x="116" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby/Member</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#2c3e58" text-anchor="end" font-family="JetBrains Mono,monospace">Aruba CX VSF</text>`;
  svg+=`</svg>`;
  return svg;
}

// ArubaOS-Switch（舊款 ProCurve/2930F/2930M/3810M/5400R，非 Aruba CX）VSF 拓樸（2026-09
// 新增，Phase 4 對外查證）：與上方 buildVSFSVGReport() 同屬「VSF」命名但服務不同產品線／
// 不同資料來源（parseProCurveVSF() 而非 parseArubaVSF()），故獨立成專屬函式而非參數化共用，
// 比照既有各廠牌各自一份 buildXStackSVG() 的慣例。簡化版——不畫逐埠方塊（ArubaOS-Switch
// 堆疊後的介面命名規則未經查證，貿然假設會產生誤導的埠數字），只呈現 member/role/priority
// 與 link 埠清單，並標示 domain ID
function buildProCurveVSFSVG(p){
  const s=p.stack;
  const mems=s.members;
  const tc='#22c55e'; // ProCurve/HPE green，刻意與 Aruba CX VSF 的橘色區分避免混淆
  const boxW=150,boxH=120,gap=Math.max(190,680/(mems.length||1));
  const W=Math.max(680,mems.length*gap+100),H=280;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2),bY=70;
  const boxes=mems.map((m,i)=>({x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m}));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif;max-width:100%">
<defs>
<marker id="pcvarr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">VSF STACK TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-160}" y="11" width="148" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-86}" y="30" font-size="11" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">ArubaOS-Switch VSF${s.domain?(' D'+esc(s.domain)):''}</text>`;
  for(let i=0;i<mems.length;i++){
    if(i===mems.length-1)break;
    const a=boxes[i],b=boxes[i+1];
    const lnk=s.links?.[i];
    const lbl=lnk?lnk.ports.slice(0,3).join(' | '):'';
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+40} ${b.cx} ${b.y+boxH+40} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#pcvarr)"/>`;
    if(lbl){const mx=(a.cx+b.cx)/2,my=a.y+boxH+34;svg+=`<rect x="${mx-55}" y="${my-10}" width="110" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/><text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${esc(lbl)}</text>`;}
  }
  boxes.forEach((bx)=>{
    const m=bx.mem,isMaster=m.role==='Master';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#1e3a5f'}" stroke-width="${isMaster?1.8:1}"/>`;
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.18:.07}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#64748b'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">M${esc(m.id)}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#2c3e58'}" text-anchor="end" font-weight="600">${m.role==='Master'?'Commander':'Member'}</text>`;
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+38}" x2="${bx.x+boxW-12}" y2="${bx.y+38}" stroke="#1e3a5f" stroke-width=".5"/>
    <text x="${bx.x+16}" y="${bx.y+58}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text><text x="${bx.x+boxW-14}" y="${bx.y+58}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${m.priority??128}</text>`;
  });
  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#1e3a5f" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Commander</text>
  <rect x="130" y="${lY+8}" width="10" height="10" rx="2" fill="#1e3a5f"/>
  <text x="146" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Member</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#2c3e58" text-anchor="end" font-family="JetBrains Mono,monospace">ArubaOS-Switch VSF</text>`;
  svg+=`</svg>`;
  return svg;
}

function buildAlcatelStackSVG(p){
  const s=p.stack;
  const mems=s.members;
  const tc='#00a064'; // Alcatel green
  const boxW=160,boxH=192,gap=Math.max(200,720/(mems.length||1));
  const W=Math.max(720,mems.length*gap+100),H=400;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2),bY=96;
  const boxes=mems.map((mem,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem,
    ports:p.interfaces.filter(ii=>{
      const slot=mem.id;
      return ii.type==='physical'&&(ii.name.startsWith(slot+'/')||ii.name.startsWith(slot+'/'));
    }).length
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif;max-width:100%">
<defs>
<marker id="aarr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="aglow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">ALCATEL STACK${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-130}" y="11" width="118" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-71}" y="30" font-size="11" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">OmniSwitch Stack</text>`;

  // Draw stack links
  for(let i=0;i<boxes.length-1;i++){
    const a=boxes[i],b=boxes[i+1];
    const lnk=s.links?.[i];
    const lbl=lnk?.ports?.slice(0,2).join(' | ')||lnk?.desc||'Stack Port';
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#aarr)"/>`;
    const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;
    svg+=`<rect x="${mx-50}" y="${my-10}" width="100" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/>
    <text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${esc(lbl)}</text>`;
  }

  // Draw member boxes
  boxes.forEach((bx)=>{
    const mem=bx.mem,isMaster=mem.role==='Master';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#0d3320'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#aglow)"':''}/>`;
    if(isMaster)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".025"/>`;
    // Member badge
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.2:.07}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#1a6640'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">Slot ${mem.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#1a6640'}" text-anchor="end" font-weight="600">${esc(mem.role||'')}</text>`;
    // Port slots visual
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#0d3320" stroke-width="1"/>`;
    const pc=Math.min(bx.ports||12,16);
    for(let pi=0;pi<(pc||12);pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.45:.18}"/>`;}
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#0d3320" stroke-width=".5"/>
    <text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#1a6640" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${mem.priority||'—'}</text>
    <text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#1a6640" font-family="JetBrains Mono,monospace">${tr('col.port_count')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports||'—'}</text>
    <text x="${bx.x+16}" y="${bx.y+140}" font-size="9" fill="#1a6640" font-family="JetBrains Mono,monospace">${tr('col.model')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+140}" font-size="10" fill="#dde8f5" text-anchor="end" font-family="JetBrains Mono,monospace">${esc(mem.model||'OmniSwitch')}</text>`;
    // Trunk uplink indicator
    const tpCount=p.interfaces.filter(ii=>ii.member===mem.id&&ii.mode==='trunk').length;
    if(tpCount)svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-24}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/>
    <polygon points="${bx.cx},${bx.y-28} ${bx.cx-5},${bx.y-20} ${bx.cx+5},${bx.y-20}" fill="${tc}" opacity=".5"/>
    <text x="${bx.cx}" y="${bx.y-33}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Trunk×${tpCount}</text>`;
  });

  // Legend
  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#0d3320" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Master</text>
  <rect x="100" y="${lY+8}" width="10" height="10" rx="2" fill="#0d3320"/>
  <text x="116" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby/Member</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#1a6640" text-anchor="end" font-family="JetBrains Mono,monospace">Alcatel OmniSwitch Stack</text>`;
  svg+=`</svg>`;
  return svg;
}

function buildExtremeStackSVG(p){
  const s=p.stack;
  const mems=s.members;
  const tc='#7928ca'; // Extreme purple
  const boxW=162,boxH=196,gap=Math.max(200,740/(mems.length||1));
  const W=Math.max(740,mems.length*gap+100),H=410;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2),bY=96;
  const boxes=mems.map((mem,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem,
    ports:p.interfaces.filter(ii=>ii.type==='physical').length
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif;max-width:100%">
<defs>
<marker id="earr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="eglow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">EXTREME NETWORKS  EXTREMESTACK</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-140}" y="11" width="128" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-76}" y="30" font-size="11" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">ExtremeStack</text>`;

  // Links
  for(let i=0;i<boxes.length-1;i++){
    const a=boxes[i],b=boxes[i+1];
    const lnk=s.links?.[i];
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#earr)"/>`;
    const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;
    svg+=`<rect x="${mx-55}" y="${my-10}" width="110" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/>
    <text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">${esc(lnk?.desc||'SummitStack Link')}</text>`;
  }

  // Boxes
  boxes.forEach((bx)=>{
    const mem=bx.mem,isMaster=mem.role==='Master';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isMaster?tc:'#2d0d5c'}" stroke-width="${isMaster?1.8:1}" ${isMaster?'filter="url(#eglow)"':''}/>`;
    if(isMaster)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".025"/>`;
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${tc}" opacity="${isMaster?.2:.07}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isMaster?tc:'#4a1a8c'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">Slot ${mem.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${isMaster?tc:'#4a1a8c'}" text-anchor="end" font-weight="600">${esc(mem.role||'')}</text>`;
    // Port visual
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#2d0d5c" stroke-width="1"/>`;
    for(let pi=0;pi<16;pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isMaster?.45:.15}"/>`;}
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#2d0d5c" stroke-width=".5"/>
    <text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#4a1a8c" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${mem.priority||'—'}</text>
    <text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#4a1a8c" font-family="JetBrains Mono,monospace">${tr('col.model')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="10" fill="#dde8f5" text-anchor="end" font-family="JetBrains Mono,monospace">${esc((mem.model||'ExtremeXOS').replace('SummitX','X'))}</text>
    <text x="${bx.x+16}" y="${bx.y+143}" font-size="9" fill="#4a1a8c" font-family="JetBrains Mono,monospace">${tr('col.full_model')}</text>
    <text x="${bx.x+boxW-14}" y="${bx.y+160}" font-size="8" fill="#64748b" text-anchor="end" font-family="JetBrains Mono,monospace">${esc(mem.model||'—')}</text>`;
    if(isMaster){
      svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-24}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/>
      <polygon points="${bx.cx},${bx.y-28} ${bx.cx-5},${bx.y-20} ${bx.cx+5},${bx.y-20}" fill="${tc}" opacity=".5"/>
      <text x="${bx.cx}" y="${bx.y-33}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Master</text>`;
    }
  });

  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#2d0d5c" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Master / Primary</text>
  <rect x="120" y="${lY+8}" width="10" height="10" rx="2" fill="#2d0d5c"/>
  <text x="136" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby / Member</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#4a1a8c" text-anchor="end" font-family="JetBrains Mono,monospace">Extreme Networks ExtremeXOS</text>`;
  svg+=`</svg>`;
  return svg;
}

function buildICXStackSVG(p){
  const stk=p.stack;
  const mems=stk.members||[];
  const links=stk.links||[];
  const tc='#f87171'; // Brocade red
  const boxW=160, boxH=130, gap=Math.max(210, 760/(mems.length||1));
  const W=Math.max(760, mems.length*gap+100);
  const H=300;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2);
  const bY=80;
  const boxes=mems.map((m,i)=>({x:startX+i*gap, cx:startX+i*gap+boxW/2, y:bY, mem:m}));
  const esc2=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="max-width:100%;font-family:'JetBrains Mono',monospace">
<defs>
<marker id="icx-arr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="icx-glow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<linearGradient id="icx-hg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="${tc}" stop-opacity=".18"/><stop offset="100%" stop-color="#7f1d1d" stop-opacity=".04"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<rect x="0" y="0" width="${W}" height="50" fill="url(#icx-hg)" rx="12"/>
<rect x="0" y="38" width="${W}" height="12" fill="#080c17"/>
<text x="18" y="18" font-size="10" fill="#64748b" letter-spacing="1" font-weight="600">ICX STACK TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc2(p.sys.hostname)}</text>
<rect x="${W-156}" y="11" width="144" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-84}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle">Brocade ICX Stack</text>`;

  // Draw stack links between units
  const isRing = links.length >= mems.length;
  for(let i=0;i<boxes.length-1;i++){
    const a=boxes[i], b=boxes[i+1];
    svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+52} ${b.cx} ${b.y+boxH+52} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".62" marker-end="url(#icx-arr)" filter="url(#icx-glow)"/>`;
    if(links[i]?.ports?.length){
      svg+=`<text x="${(a.cx+b.cx)/2}" y="${a.y+boxH+48}" font-size="9" fill="${tc}" text-anchor="middle" opacity=".7">${esc2(links[i].ports.slice(0,2).join(' ↔ '))}</text>`;
    }
  }
  // Ring back-link if applicable
  if(isRing && boxes.length>=2){
    const a=boxes[boxes.length-1], b=boxes[0];
    svg+=`<path d="M ${a.cx} ${a.y+boxH+8} C ${a.cx} ${a.y+boxH+90} ${b.cx} ${b.y+boxH+90} ${b.cx} ${b.y+boxH+8}" stroke="${tc}" stroke-width="2" fill="none" opacity=".35" stroke-dasharray="5,3" marker-end="url(#icx-arr)"/>`;
    svg+=`<text x="${(a.cx+b.cx)/2}" y="${a.y+boxH+82}" font-size="9" fill="${tc}" text-anchor="middle" opacity=".5">Ring</text>`;
  }

  // Draw unit boxes
  for(const bx of boxes){
    const m=bx.mem;
    const isActive=m.role==='Active';
    const roleColor=isActive?'#00c8f0':m.role==='Standby'?'#10b981':'#94a3b8';
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${isActive?tc:'#1e3a5f'}" stroke-width="${isActive?2:1}" ${isActive?'filter="url(#icx-glow)"':''}/>`;
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="32" rx="10" fill="${tc}" opacity="${isActive?.22:.1}"/>`;
    svg+=`<rect x="${bx.x}" y="${bx.y+22}" width="${boxW}" height="10" fill="#0f1629"/>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+21}" font-size="13" fill="${isActive?tc:'#dde8f5'}" font-weight="700" text-anchor="middle">Unit ${m.id}</text>`;
    svg+=`<rect x="${bx.cx-32}" y="${bx.y+37}" width="64" height="18" rx="5" fill="${roleColor}" opacity=".18" stroke="${roleColor}" stroke-width="1"/>`;
    svg+=`<text x="${bx.cx}" y="${bx.y+50}" font-size="10" fill="${roleColor}" font-weight="700" text-anchor="middle">${esc2(m.role||'Member')}</text>`;
    if(m.model&&m.model!=='—'){
      const shortModel=m.model.length>18?m.model.substring(0,16)+'…':m.model;
      svg+=`<text x="${bx.cx}" y="${bx.y+74}" font-size="9" fill="#94a3b8" text-anchor="middle">${esc2(shortModel)}</text>`;
    }
    if(m.priority>0)svg+=`<text x="${bx.cx}" y="${bx.y+94}" font-size="10" fill="#64748b" text-anchor="middle">prio: ${m.priority}</text>`;
  }
  svg+=`</svg>`;
  return svg;
}

function buildStackWiseSVG(p){
  const s=p.stack;
  const mems=s.members;
  const tc='#1ba0d7'; // Cisco blue
  const boxW=158,boxH=188,gap=Math.max(200,720/(mems.length||1));
  const W=Math.max(720,mems.length*gap+100);
  const H=400;
  const startX=Math.max(28,(W-gap*(mems.length-1)-boxW)/2);
  const bY=96;
  const boxes=mems.map((m,i)=>({
    x:startX+i*gap,cx:startX+i*gap+boxW/2,y:bY,mem:m,
    ports:p.interfaces.filter(ii=>ii.member===m.id&&ii.type==='physical').length,
  }));
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="font-family:'IBM Plex Sans TC','JetBrains Mono',sans-serif">
<defs>
<marker id="arr" markerWidth="7" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="${tc}" opacity=".8"/></marker>
<filter id="glow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<filter id="glows"><feGaussianBlur stdDeviation="1.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
<linearGradient id="hg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="${tc}" stop-opacity=".14"/><stop offset="100%" stop-color="#0052ff" stop-opacity=".03"/></linearGradient>
</defs>
<rect width="${W}" height="${H}" fill="#080c17" rx="12"/>
<rect x="0" y="0" width="${W}" height="50" fill="url(#hg)" rx="12"/>
<rect x="0" y="38" width="${W}" height="12" fill="#080c17"/>
<text x="18" y="18" font-size="10" fill="#64748b" font-family="JetBrains Mono,monospace" letter-spacing="1" font-weight="600">STACKWISE TOPOLOGY${tr('stack.topo_sub')}</text>
<text x="18" y="38" font-size="15" fill="#dde8f5" font-weight="700">${esc(p.sys.hostname)}</text>
<rect x="${W-110}" y="11" width="98" height="28" rx="7" fill="${tc}" opacity=".12" stroke="${tc}" stroke-width="1"/>
<text x="${W-61}" y="30" font-size="12" fill="${tc}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">StackWise</text>`;

  // Ring link for >2 members
  const isRing=mems.length>2;
  for(let i=0;i<mems.length;i++){
    if(i===mems.length-1&&!isRing)break;
    const a=boxes[i],b=boxes[(i+1)%mems.length];
    if(i===mems.length-1){
      svg+=`<path d="M ${a.cx} ${a.y+boxH+8} C ${a.cx} ${a.y+boxH+76} ${b.cx} ${b.y+boxH+76} ${b.cx} ${b.y+boxH+8}" stroke="${tc}" stroke-width="2" fill="none" opacity=".35" stroke-dasharray="5,3"/>`;
    }else{
      svg+=`<path d="M ${a.cx} ${a.y+boxH+6} C ${a.cx} ${a.y+boxH+50} ${b.cx} ${b.y+boxH+50} ${b.cx} ${b.y+boxH+6}" stroke="${tc}" stroke-width="2.5" fill="none" opacity=".6" marker-end="url(#arr)" filter="url(#glows)"/>`;
      const mx=(a.cx+b.cx)/2,my=a.y+boxH+42;
      svg+=`<rect x="${mx-42}" y="${my-10}" width="84" height="16" rx="4" fill="#0f1629" stroke="${tc}" stroke-width=".6" opacity=".85"/><text x="${mx}" y="${my+3}" font-size="9" fill="${tc}" text-anchor="middle" font-family="JetBrains Mono,monospace">Stack Cable</text>`;
    }
  }

  boxes.forEach((bx,i)=>{
    const m=bx.mem;
    const isActive=m.role==='Active';
    const isStandby=m.role==='Standby';
    const borderColor=isActive?tc:isStandby?'#10b981':'#1e3a5f';
    const borderW=isActive?1.8:1.2;
    svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="#0f1629" stroke="${borderColor}" stroke-width="${borderW}" ${isActive?'filter="url(#glow)"':''}/>`;
    if(isActive)svg+=`<rect x="${bx.x}" y="${bx.y}" width="${boxW}" height="${boxH}" rx="10" fill="${tc}" opacity=".025"/>`;
    // Header badge
    const badgeColor=isActive?tc:isStandby?'#10b981':'#2c3e58';
    svg+=`<rect x="${bx.x+10}" y="${bx.y+10}" width="54" height="20" rx="5" fill="${badgeColor}" opacity="${isActive?.18:isStandby?.12:.08}"/>
    <text x="${bx.x+37}" y="${bx.y+24}" font-size="11" fill="${isActive?tc:isStandby?'#10b981':'#64748b'}" font-weight="700" text-anchor="middle" font-family="JetBrains Mono,monospace">SW${m.id}</text>
    <text x="${bx.x+boxW-12}" y="${bx.y+24}" font-size="10" fill="${badgeColor}" text-anchor="end" font-weight="600">${esc(m.role||'')}</text>`;
    // Port slots
    svg+=`<rect x="${bx.x+12}" y="${bx.y+38}" width="${boxW-24}" height="46" rx="6" fill="#080c17" stroke="#1e3a5f" stroke-width="1"/>`;
    const pc=Math.min(bx.ports,16);
    for(let pi=0;pi<pc;pi++){const row=Math.floor(pi/8),col=pi%8;svg+=`<rect x="${bx.x+16+col*16}" y="${bx.y+44+row*16}" width="12" height="10" rx="2.5" fill="${tc}" opacity="${isActive?.4:.18}"/>`;}
    // Info rows
    svg+=`<line x1="${bx.x+12}" y1="${bx.y+93}" x2="${bx.x+boxW-12}" y2="${bx.y+93}" stroke="#1e3a5f" stroke-width=".5"/>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+108}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.model')}</text><text x="${bx.x+boxW-14}" y="${bx.y+108}" font-size="9.5" fill="#dde8f5" text-anchor="end" font-weight="600" font-family="JetBrains Mono,monospace">${esc((m.model||'—').replace(/^ws-c/i,''))}</text>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+124}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.priority')}</text><text x="${bx.x+boxW-14}" y="${bx.y+124}" font-size="11" fill="${tc}" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${m.priority||'—'}</text>`;
    svg+=`<text x="${bx.x+16}" y="${bx.y+140}" font-size="9" fill="#2c3e58" font-family="JetBrains Mono,monospace">${tr('col.port_count')}</text><text x="${bx.x+boxW-14}" y="${bx.y+140}" font-size="11" fill="#dde8f5" text-anchor="end" font-weight="700" font-family="JetBrains Mono,monospace">${bx.ports}</text>`;
    // Trunk indicator
    const tpCount=p.interfaces.filter(ii=>ii.member===m.id&&ii.mode==='trunk').length;
    if(tpCount)svg+=`<line x1="${bx.cx}" y1="${bx.y}" x2="${bx.cx}" y2="${bx.y-24}" stroke="${tc}" stroke-width="1.5" stroke-dasharray="3,3" opacity=".5"/><polygon points="${bx.cx},${bx.y-28} ${bx.cx-5},${bx.y-20} ${bx.cx+5},${bx.y-20}" fill="${tc}" opacity=".5"/><text x="${bx.cx}" y="${bx.y-33}" font-size="9" fill="#64748b" text-anchor="middle" font-family="JetBrains Mono,monospace">Trunk×${tpCount}</text>`;
  });

  const lY=H-38;
  svg+=`<rect x="14" y="${lY}" width="${W-28}" height="30" rx="5" fill="#0f1629" stroke="#1e3a5f" stroke-width=".5"/>
  <rect x="24" y="${lY+8}" width="10" height="10" rx="2" fill="${tc}" opacity=".9"/>
  <text x="40" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Active</text>
  <rect x="100" y="${lY+8}" width="10" height="10" rx="2" fill="#10b981" opacity=".7"/>
  <text x="116" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Standby</text>
  <rect x="186" y="${lY+8}" width="10" height="10" rx="2" fill="#1e3a5f"/>
  <text x="202" y="${lY+17}" font-size="9" fill="#64748b" font-family="JetBrains Mono,monospace">Member</text>
  <text x="${W-18}" y="${lY+18}" font-size="9" fill="#2c3e58" text-anchor="end" font-family="JetBrains Mono,monospace">Cisco StackWise</text>`;
  svg+=`</svg>`;
  return svg;
}

// ── LLDP 拓樸匯出成可編輯格式（2026-10-06，第十二輪 MI）──────────────────────
// 圖的資料模型：{nodes:[{id,label,sub,kind:'local'|'known'|'lldp'}], edges:[{a,b,labels:[]}]}，
// 同一對設備的多條連線合併成一條邊、標籤逐行列出（A 埠 ↔ B 埠，方向以邊的 a→b 為準）。
// 單台：本機＋鄰居；多設備：每台已載入的設備（known）＋只在 LLDP 中出現的設備（lldp），兩端都回報
// 同一條連線時只留一筆。輸出 draw.io（未壓縮的 mxfile XML，diagrams.net 可直接開啟）與 Mermaid flowchart
function buildLldpGraph(devices){
  const nodes=[],idx=new Map(),edgeMap=new Map(),edges=[];
  const node=(name,kind,sub)=>{
    if(!idx.has(name)){idx.set(name,nodes.length);nodes.push({id:'n'+nodes.length,label:name,sub:sub||'',kind});}
    const n=nodes[idx.get(name)];
    if(kind==='known'&&n.kind==='lldp')n.kind='known';
    if(sub&&!n.sub)n.sub=sub;
    return n;
  };
  (devices||[]).forEach((d,i)=>node(d.hostname||'Local',i===0?'local':'known'));
  (devices||[]).forEach(d=>{
    const self=node(d.hostname||'Local');
    (d.lldp||[]).forEach(l=>{
      if(!l.neighbor)return;
      const nb=node(l.neighbor,'lldp',l.ip&&l.ip!=='-'?l.ip:'');
      const key=[self.id,nb.id].sort().join('|');
      let e=edgeMap.get(key);
      if(!e){e={a:self.id,b:nb.id,labels:[]};edgeMap.set(key,e);edges.push(e);}
      const lp=l.localPort||'?',rp=l.remotePort||'?';
      const lbl=e.a===self.id?`${lp} ↔ ${rp}`:`${rp} ↔ ${lp}`;
      if(!e.labels.includes(lbl))e.labels.push(lbl);
    });
  });
  return {nodes,edges};
}
function _xmlAttr(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');}
function _htmlText(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function graphToDrawio(g,title){
  const n=g.nodes.length||1,W=160,H=56;
  const R=n<=1?0:Math.max(180,n*40),CX=R+60,CY=R+60;
  const STYLE={local:'fillColor=#dae8fc;strokeColor=#6c8ebf;strokeWidth=2;',known:'fillColor=#d5e8d4;strokeColor=#82b366;',lldp:'fillColor=#f5f5f5;strokeColor=#999999;dashed=1;'};
  const cells=[];
  g.nodes.forEach((nd,i)=>{
    // 第一個節點（單台的本機）放中央，其餘排成一圈
    const ring=n>1&&g.nodes[0].kind==='local'&&g.nodes.length>2;
    let x,y;
    if(ring&&i===0){x=CX;y=CY;}
    else{const k=ring?i-1:i,m=ring?n-1:n,a=2*Math.PI*k/m-Math.PI/2;x=CX+R*Math.cos(a);y=CY+R*Math.sin(a);}
    const val=_htmlText(nd.label)+(nd.sub?'<br>'+_htmlText(nd.sub):'');
    cells.push(`<mxCell id="${nd.id}" value="${_xmlAttr(val)}" style="rounded=1;whiteSpace=wrap;html=1;${STYLE[nd.kind]||STYLE.lldp}" vertex="1" parent="1"><mxGeometry x="${Math.round(x-W/2)}" y="${Math.round(y-H/2)}" width="${W}" height="${H}" as="geometry"/></mxCell>`);
  });
  g.edges.forEach((e,i)=>{
    const val=e.labels.map(_htmlText).join('<br>');
    cells.push(`<mxCell id="e${i}" value="${_xmlAttr(val)}" style="endArrow=none;html=1;fontSize=10;labelBackgroundColor=#ffffff;" edge="1" parent="1" source="${e.a}" target="${e.b}"><mxGeometry relative="1" as="geometry"/></mxCell>`);
  });
  return `<mxfile host="app.diagrams.net"><diagram id="lldp-topology" name="${_xmlAttr(title||'LLDP')}"><mxGraphModel grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="${Math.max(1169,2*CX)}" pageHeight="${Math.max(827,2*CY)}"><root><mxCell id="0"/><mxCell id="1" parent="0"/>${cells.join('')}</root></mxGraphModel></diagram></mxfile>\n`;
}
// Mermaid 標籤放在雙引號內，引號與角括號改用 Mermaid 實體碼（#quot; #lt; #gt;），換行用 <br/>
function _mmd(s){return String(s==null?'':s).replace(/"/g,'#quot;').replace(/</g,'#lt;').replace(/>/g,'#gt;');}
function graphToMermaid(g){
  const out=['graph LR'];
  g.nodes.forEach(nd=>out.push(`  ${nd.id}["${_mmd(nd.label)}${nd.sub?'<br/>'+_mmd(nd.sub):''}"]`));
  // 沒有標籤的連線（如堆疊鏈路未記錄埠）不輸出空的 |""|
  g.edges.forEach(e=>out.push(e.labels.length?`  ${e.a} ---|"${e.labels.map(_mmd).join('<br/>')}"| ${e.b}`:`  ${e.a} --- ${e.b}`));
  out.push('  classDef local stroke:#6c8ebf,stroke-width:3px,fill:#dae8fc;');
  out.push('  classDef known stroke:#82b366,fill:#d5e8d4;');
  out.push('  classDef lldp stroke:#999,stroke-dasharray:4 3,fill:#f5f5f5;');
  ['local','known','lldp'].forEach(k=>{const ids=g.nodes.filter(nd=>nd.kind===k).map(nd=>nd.id);if(ids.length)out.push(`  class ${ids.join(',')} ${k};`);});
  return out.join('\n')+'\n';
}

// 堆疊拓樸匯出可編輯格式（2026-10-07，第十三輪 NG）：與畫面上的堆疊 SVG 相同的連接方式——成員依序相連，
// links[i] 為第 i 與 i+1 台之間的鏈路（Comware IRF 依 fromMember 對應）；IRF 三台以上、ICX 鏈路數不少於成員數時頭尾相接成環。
// 主設備（Master／Active／Commander／Conductor 等角色）以 local 樣式標示，其餘為 known
function buildStackGraph(p){
  const irf=p&&p.vendor==='comware'?p.irf:null;
  const stack=irf||(p&&p.stack)||{};
  const mems=stack.members||[];
  const ports=l=>{const a=l&&(l.shortPorts&&l.shortPorts.length?l.shortPorts:l.ports);return Array.isArray(a)?a.slice(0,2).join(' | '):'';};
  const isMain=m=>/^(master|active|commander|conductor|primary)$/i.test(String(m.role||''));
  const hasMain=mems.some(isMain);
  const nodes=mems.map((m,i)=>({id:'n'+i,label:'Member '+(m.id!=null?m.id:i+1),
    sub:[m.role,m.priority?'prio '+m.priority:'',m.model&&m.model!=='—'&&m.model!=='-'?m.model:''].filter(Boolean).join(' · '),
    kind:(hasMain?isMain(m):i===0)?'local':'known'}));
  const edges=[];
  const linkFor=i=>irf?(irf.links||[]).find(l=>l.fromMember===mems[i].id):(stack.links||[])[i];
  for(let i=0;i+1<mems.length;i++){const lb=ports(linkFor(i));edges.push({a:'n'+i,b:'n'+(i+1),labels:lb?[lb]:[]});}
  const ring=mems.length>2&&(irf?true:p&&p.vendor==='brocade'&&(stack.links||[]).length>=mems.length);
  if(ring){const lb=ports(linkFor(mems.length-1));edges.push({a:'n'+(mems.length-1),b:'n0',labels:lb?[lb]:[]});}
  return {nodes,edges};
}

// 多設備鏈路一致性（2026-10-07，第十三輪 NJ）：devices 為 [{hostname,lldp,ifaces,lagPorts}]（ifaces 取自解析結果的
// interfaces，lagPorts 為聚合成員埠名稱）。依 LLDP 找出兩端都已載入設定的鏈路，比對兩端埠的模式（access／trunk）、
// access VLAN、trunk 允許 VLAN、native VLAN（兩端都有明確值才比）與是否同屬聚合；任一端為 hybrid 時改比 tagged／untagged／PVID（見 _ljEffective）；無模式的埠不比。
// LLDP 的埠名常為縮寫，對應順序：名稱完全相同（不分大小寫）→ 埠號路徑（1/0/1）唯一 → 埠號路徑相同且第一個字母相同；
// 對不到的鏈路只計數不判斷。鄰居名稱不分大小寫，也接受網域名稱前段（sw2.corp.local → sw2）
function _ljVlanSet(v){
  const out=new Set();
  String(v||'').replace(/\s*(?:\bto\b|-)\s*/gi,'-').split(/[\s,]+/).filter(Boolean).forEach(t=>{
    const m=t.match(/^(\d+)(?:-(\d+))?$/);if(!m)return;
    for(let k=+m[1];k<=+(m[2]||m[1])&&k-m[1]<4095;k++)out.add(String(k));
  });
  return out;
}
function _ljFindIface(dev,port){
  const ifs=(dev.ifaces||[]).filter(i=>i.type!=='svi'&&i.type!=='loopback'&&i.type!=='null');
  const p=String(port||'').trim(),pl=p.toLowerCase().replace(/\s+/g,'');
  let hit=ifs.filter(i=>String(i.name).toLowerCase().replace(/\s+/g,'')===pl);
  if(hit.length===1)return hit[0];
  const num=s=>(String(s).match(/(\d+(?:[\/:.]\d+)*)$/)||[])[1]||'';
  const pn=num(p);if(!pn)return null;
  hit=ifs.filter(i=>num(i.name)===pn);
  if(hit.length===1)return hit[0];
  hit=hit.filter(i=>String(i.name).charAt(0).toLowerCase()===pl.charAt(0));
  return hit.length===1?hit[0]:null;
}
// hybrid 比對（第十四輪 OE）：兩端任一為 hybrid 時，把各端換算成「tagged 集合／untagged 集合／PVID」再比。
// access＝untagged 只有該 VLAN；trunk＝允許清單扣掉 native 為 tagged、native 在允許清單內時為 untagged（native 未知則
// untagged 與 PVID 不比）；允許清單為 all 或 except 時無法換算不比。hybrid 物件形狀 {pvid,untagged[],tagged[]}
// 由 Comware、Cisco Business、Ruijie、Planet 解析器提供
function _ljEffective(i){
  if(i.mode==='hybrid'){
    const h=i.hybrid;if(!h)return null;
    const t=(h.tagged||[]).join(','),u=(h.untagged||[]).join(',');
    if(/\ball\b/i.test(t+','+u))return null;
    return {tagged:_ljVlanSet(t),untagged:_ljVlanSet(u),pvid:String(h.pvid||'')};
  }
  if(i.mode==='access'){const v=[..._ljVlanSet(i.vlans)][0]||'';return v?{tagged:new Set(),untagged:new Set([v]),pvid:v}:null;}
  if(i.mode==='trunk'){
    if(/\b(?:all|except)\b/i.test(String(i.vlans||'')))return null;
    const s=_ljVlanSet(i.vlans),nv=String(i.nativeVlan||'');
    if(!s.size)return null;
    return {tagged:new Set([...s].filter(v=>v!==nv)),untagged:nv?new Set(s.has(nv)?[nv]:[]):null,pvid:nv};
  }
  return null;
}
function _ljSetDiff(a,b){return [[...a].filter(v=>!b.has(v)).slice(0,10).join(','),[...b].filter(v=>!a.has(v)).slice(0,10).join(',')];}
function checkLinkConsistency(devices){
  const devs=devices||[];
  const byName=n=>{const s=String(n||'').toLowerCase();return devs.find(d=>String(d.hostname).toLowerCase()===s)||devs.find(d=>String(d.hostname).toLowerCase()===s.split('.')[0]);};
  const seen=new Set(),links=[];let unmatched=0;
  devs.forEach(a=>(a.lldp||[]).forEach(l=>{
    const b=byName(l.neighbor);if(!b||b===a)return;
    const ia=_ljFindIface(a,l.localPort),ib=_ljFindIface(b,l.remotePort);
    if(!ia||!ib){const k=[a.hostname+'|'+l.localPort,b.hostname+'|'+l.remotePort].sort().join('#');if(!seen.has(k)){seen.add(k);unmatched++;}return;}
    const key=[a.hostname+'|'+ia.name,b.hostname+'|'+ib.name].sort().join('#');
    if(seen.has(key))return;seen.add(key);
    const issues=[];
    const ma=ia.mode,mb=ib.mode,ok=m=>m==='access'||m==='trunk';
    if(ok(ma)&&ok(mb)){
      if(ma!==mb)issues.push({type:'mode',a:ma,b:mb});
      else if(ma==='access'){const va=[..._ljVlanSet(ia.vlans)][0]||'',vb=[..._ljVlanSet(ib.vlans)][0]||'';if(va&&vb&&va!==vb)issues.push({type:'access',a:va,b:vb});}
      else{
        const sa=_ljVlanSet(ia.vlans),sb=_ljVlanSet(ib.vlans);
        if(sa.size&&sb.size&&!/\ball\b/i.test(ia.vlans)&&!/\ball\b/i.test(ib.vlans)){
          const onlyA=[...sa].filter(v=>!sb.has(v)),onlyB=[...sb].filter(v=>!sa.has(v));
          if(onlyA.length||onlyB.length)issues.push({type:'trunk',a:onlyA.slice(0,10).join(','),b:onlyB.slice(0,10).join(',')});
        }
        if(ia.nativeVlan&&ib.nativeVlan&&String(ia.nativeVlan)!==String(ib.nativeVlan))issues.push({type:'native',a:String(ia.nativeVlan),b:String(ib.nativeVlan)});
      }
    }else if((ma==='hybrid'||mb==='hybrid')&&(ok(ma)||ma==='hybrid')&&(ok(mb)||mb==='hybrid')){
      const ea=_ljEffective(ia),eb=_ljEffective(ib);
      if(ea&&eb){
        const [ta,tb]=_ljSetDiff(ea.tagged,eb.tagged);
        if(ta||tb)issues.push({type:'hybridTagged',a:ta,b:tb});
        if(ea.untagged&&eb.untagged){const [ua,ub]=_ljSetDiff(ea.untagged,eb.untagged);if(ua||ub)issues.push({type:'hybridUntagged',a:ua,b:ub});}
        if(ea.pvid&&eb.pvid&&ea.pvid!==eb.pvid)issues.push({type:'native',a:ea.pvid,b:eb.pvid});
      }
    }
    const la=(a.lagPorts||[]).includes(ia.name),lb=(b.lagPorts||[]).includes(ib.name);
    if(la!==lb)issues.push({type:'lag',a:la?'LAG':'-',b:lb?'LAG':'-'});
    links.push({a:a.hostname,aPort:ia.name,b:b.hostname,bPort:ib.name,issues});
  }));
  return {links,unmatched};
}
