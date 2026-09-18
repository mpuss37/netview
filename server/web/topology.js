/*
 * NetView - Topology View (canvas 2D, real-time).
 *
 * Menampilkan graf jaringan: gateway di pusat, host mengelilingi.
 * Posisi = ESTIMASI TOPOLOGI (RTT + aktivitas ARP), bukan lokasi fisik.
 */
'use strict';

const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d');
const tooltip = document.getElementById('tooltip');
const statsEl = document.getElementById('stats');
const panelBody = document.getElementById('panel-body');
const panelTitle = document.getElementById('panel-title');
const toggleArp = document.getElementById('toggle-arp');
const toggleRings = document.getElementById('toggle-rings');

let DATA = { nodes: [], links: [], gateway: null, self: null, meta: {} };
let view = { scale: 1, offsetX: 0, offsetY: 0 };
let hoverNode = null;
let selectedIp = null;
let dragging = false;
let lastMouse = { x: 0, y: 0 };
let t0 = performance.now();
let animStart = 0;             // waktu mulai transisi posisi

const COLORS = {
  gateway: '#4a9eff',
  self: '#46c46a',
  host: '#9aa2ab',
  suspicious: '#e0a52a',
  attacker: '#e5484d',
};

function resize() {
  const wrap = document.getElementById('canvas-wrap');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = wrap.clientWidth * dpr;
  canvas.height = wrap.clientHeight * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener('resize', resize);

// ── koordinat ──────────────────────────────────────────────────────
function cssSize() {
  return { w: canvas.clientWidth, h: canvas.clientHeight };
}
function nodeColor(n) {
  if (n.kind === 'gateway') return COLORS.gateway;
  if (n.kind === 'self') return COLORS.self;
  if (n.threat === 'attacker') return COLORS.attacker;
  if (n.threat === 'suspicious') return COLORS.suspicious;
  return COLORS.host;
}
function toScreen(pos) {
  const { w, h } = cssSize();
  const base = Math.min(w, h) * 0.92;
  const cx = w / 2 + view.offsetX;
  const cy = h / 2 + view.offsetY;
  return {
    x: cx + (pos.x - 0.5) * base * view.scale,
    y: cy + (pos.y - 0.5) * base * view.scale,
  };
}
function nodeRadius(n) {
  if (n.kind === 'gateway') return 30;
  if (n.kind === 'self') return 22;
  return 18;
}

// posisi node yang sudah diinterpolasi (animasi halus antar update)
function animPos(n) {
  const p = n.pos;
  if (n._fromX == null) return p;
  const t = Math.min(1, (performance.now() - animStart) / 600);
  const e = t * (2 - t);   // easeOutQuad
  return {
    x: n._fromX + (p.x - n._fromX) * e,
    y: n._fromY + (p.y - n._fromY) * e,
    r: p.r,
  };
}

// ── render ─────────────────────────────────────────────────────────
function draw() {
  const { w, h } = cssSize();
  ctx.clearRect(0, 0, w, h);
  const now = performance.now();
  const pulse = (Math.sin((now - t0) / 320) + 1) / 2;   // 0..1

  // cincin estimasi
  if (toggleRings.checked) {
    const base = Math.min(w, h) * 0.92;
    const cx = w / 2 + view.offsetX;
    const cy = h / 2 + view.offsetY;
    // cincin sebagai skala "jarak dari router" (pusat = router)
    const rings = [0.16, 0.32, 0.48];
    const labels = ['dekat', 'sedang', 'jauh'];
    ctx.setLineDash([4, 6]);
    for (let i = 0; i < rings.length; i++) {
      ctx.strokeStyle = 'rgba(120,130,140,0.18)';
      ctx.beginPath();
      ctx.arc(cx, cy, rings[i] * base * view.scale, 0, Math.PI * 2);
      ctx.stroke();
      // label cincin
      ctx.save();
      ctx.setLineDash([]);
      ctx.fillStyle = 'rgba(139,146,154,0.7)';
      ctx.font = '11px system-ui';
      ctx.textAlign = 'left';
      ctx.fillText(labels[i], cx + rings[i] * base * view.scale + 4, cy - 4);
      ctx.restore();
    }
    ctx.setLineDash([]);
  }

  const nodeByIp = {};
  for (const n of DATA.nodes) nodeByIp[n.ip] = n;

  // links
  for (const l of DATA.links) {
    const a = nodeByIp[l.src], b = nodeByIp[l.dst];
    if (!a || !b) continue;
    if (l.kind === 'arp' && !toggleArp.checked) continue;
    const pa = toScreen(animPos(a)), pb = toScreen(animPos(b));
    const attackerLink = (a.threat === 'attacker' || b.threat === 'attacker');

    ctx.beginPath();
    if (attackerLink) {
      ctx.strokeStyle = `rgba(229,72,77,${0.5 + 0.5 * pulse})`;
      ctx.lineWidth = 2.5;
      ctx.setLineDash([7, 6]);
    } else if (l.kind === 'arp') {
      ctx.strokeStyle = 'rgba(74,158,255,0.45)';
      ctx.lineWidth = 1 + 2 * (l.strength || 0.3);
      ctx.setLineDash([]);
    } else {
      ctx.strokeStyle = 'rgba(52,58,66,0.85)';
      ctx.lineWidth = 1.2;
      ctx.setLineDash([]);
    }
    ctx.moveTo(pa.x, pa.y);
    ctx.lineTo(pb.x, pb.y);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // nodes — hitung posisi layar dulu (termasuk repulsion halus)
  const placed = [];
  for (const n of DATA.nodes) {
    const p = toScreen(animPos(n));
    placed.push({ n, x: p.x, y: p.y, r: nodeRadius(n) });
  }
  // repulsion pass: pastikan tidak bertumpuk di layar (fallback halus)
  const MIN_GAP = 46;
  for (let it = 0; it < 6; it++) {
    let moved = false;
    for (let i = 0; i < placed.length; i++) {
      for (let j = i + 1; j < placed.length; j++) {
        const a = placed[i], b = placed[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        let d = Math.hypot(dx, dy);
        if (d === 0) { a.x += 0.5; b.x -= 0.5; moved = true; continue; }
        const need = a.r + b.r + 14;   // jarak minimum
        if (d < need) {
          const push = (need - d) / 2;
          const ux = dx / d, uy = dy / d;
          a.x += ux * push; a.y += uy * push;
          b.x -= ux * push; b.y -= uy * push;
          moved = true;
        }
      }
    }
    if (!moved) break;
  }

  // gambar node
  for (const pl of placed) {
    const n = pl.n, p = { x: pl.x, y: pl.y };
    const baseR = nodeRadius(n);
    const isAtk = n.threat === 'attacker';
    const r = isAtk ? baseR + 4 * pulse : baseR;

    if (isAtk) {
      const halo = ctx.createRadialGradient(p.x, p.y, r * 0.4, p.x, p.y, r * 2.4);
      halo.addColorStop(0, `rgba(229,72,77,${0.35 + 0.3 * pulse})`);
      halo.addColorStop(1, 'rgba(229,72,77,0)');
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(p.x, p.y, r * 2.4, 0, Math.PI * 2);
      ctx.fill();
    }

    ctx.beginPath();
    ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
    ctx.fillStyle = nodeColor(n);
    ctx.fill();
    ctx.lineWidth = (n.ip === selectedIp) ? 3 : 1.5;
    ctx.strokeStyle = (n.ip === selectedIp) ? '#ffffff' : 'rgba(0,0,0,0.4)';
    ctx.stroke();

    if (n.kind === 'gateway') {
      ctx.fillStyle = '#0b1220';
      ctx.font = 'bold 13px system-ui';
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText('GW', p.x, p.y);
    } else if (n.kind === 'self') {
      ctx.fillStyle = '#0b1220';
      ctx.font = 'bold 12px system-ui';
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText('INI', p.x, p.y);
    } else if (isAtk) {
      ctx.fillStyle = '#fff';
      ctx.font = 'bold 14px system-ui';
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText('!', p.x, p.y + 1);
    }

    // label — sembunyikan kalau terlalu dekat dengan label lain
    let lbl;
    if (n.no_ip) {
      // node penyerang tanpa IP: tampilkan MAC (penanda), bukan id internal
      lbl = n.mac + '  PENYERANG';
    } else {
      lbl = n.ip + (n.label && n.label !== n.ip ? '  ' + n.label : '');
    }
    ctx.font = '12px system-ui';
    const ly = p.y + r + 4;
    const lw = ctx.measureText(lbl).width;
    const rect = { x: p.x - lw / 2, y: ly, w: lw, h: 14 };
    let clash = false;
    for (const o of placed) {
      if (o.n === n) continue;
      const lo = o._labelRect;
      if (lo && !(rect.x + rect.w < lo.x || rect.x > lo.x + lo.w ||
                  rect.y + rect.h < lo.y || rect.y > lo.y + lo.h)) {
        clash = true; break;
      }
    }
    if (!clash) {
      pl._labelRect = rect;
      ctx.fillStyle = '#e6e8ea';
      ctx.textAlign = 'center'; ctx.textBaseline = 'top';
      ctx.fillText(lbl, p.x, ly);
    } else {
      pl._labelRect = null;
    }
  }
}

function loop() { draw(); requestAnimationFrame(loop); }

// ── interaksi ──────────────────────────────────────────────────────
function hitTest(mx, my) {
  let best = null, bestD = 1e9;
  for (const n of DATA.nodes) {
    const p = toScreen(animPos(n));
    const d = Math.hypot(p.x - mx, p.y - my);
    if (d < nodeRadius(n) + 6 && d < bestD) { best = n; bestD = d; }
  }
  return best;
}

canvas.addEventListener('mousemove', (e) => {
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  if (dragging) {
    view.offsetX += e.clientX - lastMouse.x;
    view.offsetY += e.clientY - lastMouse.y;
    lastMouse = { x: e.clientX, y: e.clientY };
    return;
  }
  const n = hitTest(mx, my);
  hoverNode = n;
  canvas.style.cursor = n ? 'pointer' : 'grab';
  if (n) {
    tooltip.classList.remove('hidden');
    tooltip.style.left = (mx + 14) + 'px';
    tooltip.style.top = (my + 14) + 'px';
    const dist = n.distance && n.distance.text ? n.distance.text : '-';
    const title = n.no_ip ? `MAC palsu: ${n.mac}` : `${n.ip}`;
    let extra = '';
    if (n.no_ip) {
      const cands = (n.ip_candidates || []).join(', ');
      extra = `<br>IP asli: ${cands ? '<b>' + cands + '</b>' : '<i>belum diketahui</i>'}`;
    }
    tooltip.innerHTML =
      `<b>${title}</b><br>` +
      (n.no_ip ? `IP: <i>menyamar (tidak ada IP sendiri)</i>` +
                 `${extra}<br>` : `MAC: ${n.mac || '-'}<br>`) +
      `Vendor: ${n.vendor || '-'}<br>` +
      `RTT: ${n.rtt != null ? n.rtt + ' ms' : '-'}<br>` +
      `Estimasi jarak: <b>${dist}</b><br>` +
      `Aktivitas ARP: ${n.activity}`;
  } else {
    tooltip.classList.add('hidden');
  }
});

canvas.addEventListener('mouseleave', () => {
  tooltip.classList.add('hidden');
  hoverNode = null;
});

canvas.addEventListener('mousedown', (e) => {
  const rect = canvas.getBoundingClientRect();
  const n = hitTest(e.clientX - rect.left, e.clientY - rect.top);
  if (n) {
    selectNode(n);
  } else {
    dragging = true;
    lastMouse = { x: e.clientX, y: e.clientY };
  }
});
window.addEventListener('mouseup', () => { dragging = false; });

canvas.addEventListener('wheel', (e) => {
  e.preventDefault();
  const factor = e.deltaY < 0 ? 1.1 : 0.9;
  view.scale = Math.max(0.4, Math.min(3, view.scale * factor));
}, { passive: false });

document.getElementById('btn-reset').addEventListener('click', () => {
  view = { scale: 1, offsetX: 0, offsetY: 0 };
});

// ── panel detail ───────────────────────────────────────────────────
function selectNode(n) {
  selectedIp = n.ip;
  panelTitle.textContent = n.no_ip
    ? 'MAC Palsu ' + n.mac : 'Perangkat ' + n.ip;
  const threat = n.threat || '';
  const badgeClass = threat === 'attacker' ? 'attacker'
    : threat === 'suspicious' ? 'suspicious' : 'normal';
  const badgeText = threat === 'attacker' ? 'PENYERANG'
    : threat === 'suspicious' ? 'MENCURIGAKAN' : 'NORMAL';

  let html = `
    <div class="row"><span class="k">Status</span>
      <span class="badge ${badgeClass}">${badgeText}</span></div>
    <div class="row"><span class="k">IP</span>${n.no_ip ? '<i>menyamar (tak punya IP sendiri)</i>' : n.ip}</div>
    <div class="row"><span class="k">MAC</span>${n.mac || '-'}</div>
    <div class="row"><span class="k">Vendor</span>${n.vendor || '-'}</div>
    <div class="row"><span class="k">RTT</span>${n.rtt != null ? n.rtt + ' ms' : '-'}</div>
    <div class="row"><span class="k">Estimasi jarak</span>
      <b>${n.distance && n.distance.text ? n.distance.text : '-'}</b>
      ${n.distance && n.distance.cm != null ? `<span class="muted">(${n.distance.cm} cm / ${n.distance.mm} mm)</span>` : ''}
    </div>
    <div class="row"><span class="k">Aktivitas</span>${n.activity} paket ARP</div>
    <div class="row"><span class="k">Peran</span>${n.kind === 'gateway' ? 'Gateway'
      : n.kind === 'self' ? 'Perangkat ini' : n.kind === 'attacker' ? 'Penyerang' : 'Host'}</div>
  `;

  // pelacakan IP asli penyerang
  if (n.no_ip) {
    const cands = n.ip_candidates || [];
    const inner = cands.length
      ? `<b>${cands.join(', ')}</b>`
      : '<i>belum diketahui</i>';
    html += `<div class="row" style="margin-top:10px">
      <span class="k">IP asli</span>${inner}</div>`;
    if (n.ip_note) {
      html += `<div class="row muted" style="font-size:12px">${n.ip_note}</div>`;
    }
    if (cands.length) {
      html += `<button onclick="addWhitelist('${n.mac}','${cands[0]}')">Whitelist MAC+IP asli</button>`;
    }
  }
  if (n.alt_macs && n.alt_macs.length) {
    html += `<div class="row"><span class="k">MAC lain</span>${n.alt_macs.join(', ')}</div>`;
  }
  if (threat === 'attacker') {
    html += `<div class="row muted" style="margin-top:10px">
      ⚠️ Node ini terdeteksi melakukan ARP spoofing. Aktifkan proteksi /
      auto-defense di GUI NetView.</div>`;
  }
  html += `<button onclick="addWhitelist('${n.mac || ''}','${n.no_ip ? '' : n.ip}')">Tambah ke whitelist</button>`;
  panelBody.innerHTML = html;
}

window.addWhitelist = async function (mac, ip) {
  try {
    const cur = await (await fetch('/whitelist')).json();
    const macs = new Set(cur.macs || []);
    const ips = new Set(cur.ips || []);
    if (mac) macs.add(mac);
    if (ip) ips.add(ip);
    await fetch('/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ macs: [...macs], ips: [...ips] }),
    });
    panelBody.innerHTML += '<div class="row muted">✓ ditambahkan ke whitelist</div>';
  } catch (e) {
    panelBody.innerHTML += '<div class="row muted">gagal menambah whitelist</div>';
  }
};

// ── polling real-time ──────────────────────────────────────────────
let inFlight = false;
let lastOk = 0;
let okCount = 0;

async function refresh() {
  if (inFlight) return;          // jangan menumpuk kalau request lambat
  inFlight = true;
  try {
    const r = await fetch('/topology', { cache: 'no-store' });
    const j = await r.json();
    if (j.status === 'success' && j.topology) {
      const prevPos = {};
      for (const n of DATA.nodes) prevPos[n.ip] = { ...n.pos };
      DATA = j.topology;
      // tandai posisi lama untuk animasi transisi halus
      for (const n of DATA.nodes) {
        const p = prevPos[n.ip];
        if (p) { n._fromX = p.x; n._fromY = p.y; }
      }
      animStart = performance.now();
      lastOk = performance.now();
      okCount++;
      const threats = DATA.nodes.filter(n => n.threat === 'attacker').length;
      const susp = DATA.nodes.filter(n => n.threat === 'suspicious').length;
      const rssi = DATA.meta && DATA.meta.ap_rssi != null
        ? DATA.meta.ap_rssi + ' dBm' : '-';
      const now = new Date(lastOk);
      const hh = String(now.getHours()).padStart(2, '0');
      const mm = String(now.getMinutes()).padStart(2, '0');
      const ss = String(now.getSeconds()).padStart(2, '0');
      statsEl.innerHTML =
        `<span style="color:#46c46a">● LIVE</span>  ` +
        `Host: ${DATA.nodes.length}  |  Penyerang: ${threats}  |  ` +
        `Mencurigakan: ${susp}  |  Link: ${DATA.links.length}  |  ` +
        `Sinyal ke AP: ${rssi}  |  Update: ${hh}:${mm}:${ss}`;
    }
  } catch (e) {
    const ago = Math.round((performance.now() - lastOk) / 1000);
    statsEl.innerHTML =
      `<span style="color:#e5484d">● TERPUTUS</span>  ` +
      `gagal memuat data (${ago}s)`;
  } finally {
    inFlight = false;
  }
}

resize();
refresh();
// polling cepat (1 detik) — cukup real-time, ringan
setInterval(refresh, 1000);
loop();
