"""
Monitor NetView - mesin monitoring jaringan.

Kombinasi:
  1. Sniffer ARP real-time (scapy.sniff) di thread daemon
  2. Scanner berkala (tiap N detik): arp-scan/kernel table untuk baseline
     & peta host.

Semua pengamatan diteruskan ke Detector. Monitor juga menyimpan:
  - hosts  : {ip: {mac, hostname, vendor, ipv6, first_seen, last_seen}}
  - arp_live: ring buffer paket ARP terakhir (untuk tab Live ARP GUI)
"""
import threading
import time
import subprocess as sp
from collections import deque

from scapy.all import ARP, Ether, sniff

from utils import (logger, get_default_gw, get_my, read_arp_table,
                   arp_scan_union, resolve_hostnames_bulk, get_vendor,
                   is_random_mac, get_ipv6_of, has_ipv6_route)
from detector import Detector

SCAN_INTERVAL = 8          # detik antar scan berkala
SNIFF_TIMEOUT = 1.0        # sniff pakai timeout supaya bisa cek stop flag


class Monitor(object):
    def __init__(self):
        self.detector = Detector()
        self.lock = threading.RLock()
        self.running = False
        self._sniff_thread = None
        self._scan_thread = None
        self._stop = threading.Event()

        self.hosts = {}         # {ip: {...}}
        self.baseline_ready = False
        self.gw = {}
        self.my = {}
        self.iface = 'wlan0'
        self.ipv6_net = False
        self.started_at = None
        self.arp_live = deque(maxlen=300)   # paket ARP terakhir
        self.arp_count = 0
        self.last_scan = 0
        self.scan_count = 0

        # ── data Topology View ─────────────────────────────────────
        # relasi ARP: {ip: {peer_ip: last_seen_ts}} dari src_ip -> dst_ip
        self.arp_links = {}
        # RTT ping per host: {ip: rtt_ms}
        self.rtt = {}
        # riwayat RTT untuk smoothing (median)
        self.rtt_hist = {}
        # entri aktivitas ARP: {ip: jumlah_paket}
        self.arp_activity = {}
        # sudut node stabil (agar tidak lompat-lompat tiap refresh)
        self.node_angles = {}
        # graf relasi lama dianggap kedaluwarsa
        self._LINK_TTL = 60.0
        # mode layout: 'radial' (proporsional RTT) | 'cluster' (kedekatan)
        self.layout_mode = 'radial'
        # cache cluster stabil (histeresis)
        self._clusters = {}

        # callback dipanggil tiap ada alert baru (untuk notifikasi/auto-def)
        self.on_alerts = None

    # ── kontrol ────────────────────────────────────────────────────
    def start(self, iface=None):
        with self.lock:
            if self.running:
                return
            self.gw = get_default_gw()
            self.iface = iface or self.gw.get('iface', 'wlan0')
            self.my = get_my(self.iface)
            self.ipv6_net = has_ipv6_route()
            # reset peta host agar sisa sesi lama (termasuk MAC spoof)
            # tidak terbawa; akan diisi ulang oleh scan + sniffer
            self.hosts = {}
            self.rtt = {}
            self.rtt_hist = {}
            self.detector.set_gateway(self.gw.get('ip'), self.gw.get('mac'),
                                      self.iface)
            self.detector.set_my_ip(self.my.get('ip'))
            self._stop.clear()
            self.running = True
            self.started_at = time.time()

            self._sniff_thread = threading.Thread(
                target=self._sniff_loop, daemon=True)
            self._sniff_thread.start()
            self._scan_thread = threading.Thread(
                target=self._scan_loop, daemon=True)
            self._scan_thread.start()
            logger.info('monitor started on {}'.format(self.iface))

    def stop(self):
        with self.lock:
            if not self.running:
                return
            self._stop.set()
            self.running = False
            logger.info('monitor stopped')

    def state(self):
        with self.lock:
            return {
                'running': self.running,
                'iface': self.iface,
                'uptime': int(time.time() - self.started_at) if self.started_at else 0,
                'arp_count': self.arp_count,
                'scan_count': self.scan_count,
                'last_scan': int(self.last_scan),
                'baseline_ready': self.baseline_ready,
                'hosts': len(self.hosts),
                'ipv6_network': self.ipv6_net,
            }

    # ── sniffer ────────────────────────────────────────────────────
    def _sniff_loop(self):
        while not self._stop.is_set():
            try:
                sniff(iface=self.iface, filter='arp', prn=self._on_arp,
                      store=0, timeout=SNIFF_TIMEOUT)
            except Exception as e:
                logger.error('sniff err: {}'.format(e))
                time.sleep(1)

    def _on_arp(self, pkt):
        try:
            if not pkt.haslayer(ARP):
                return
            arp = pkt[ARP]
            self.arp_count += 1
            now = time.time()

            entry = {
                'ts': now,
                'op': int(arp.op),
                'src_mac': (arp.hwsrc or '').lower(),
                'src_ip': arp.psrc or '',
                'dst_mac': (arp.hwdst or '').lower(),
                'dst_ip': arp.pdst or '',
                'ether_src': (pkt[Ether].src or '').lower() if pkt.haslayer(Ether) else '',
            }
            self.arp_live.append(entry)

            # teruskan ke detektor
            self.detector.observe_arp(arp.psrc, arp.hwsrc, int(arp.op))

            # perbarui peta host
            with self.lock:
                self._touch_host(arp.psrc, arp.hwsrc)
                # catat relasi & aktivitas untuk Topology View
                s_ip, d_ip = arp.psrc or '', arp.pdst or ''
                self.arp_activity[s_ip] = self.arp_activity.get(s_ip, 0) + 1
                if d_ip:
                    self.arp_activity[d_ip] = self.arp_activity.get(d_ip, 0) + 1
                    # link dua arah (dari sudut pandang komunikasi ARP)
                    if s_ip and d_ip and s_ip != d_ip:
                        self.arp_links.setdefault(s_ip, {})[d_ip] = now
                        self.arp_links.setdefault(d_ip, {})[s_ip] = now

            # evaluasi deteksi (hasil dialirkan via callback)
            self._emit_alerts()
        except Exception as e:
            logger.error('on_arp err: {}'.format(e))

    def _touch_host(self, ip, mac):
        if not ip or not mac:
            return
        mac = mac.lower()
        # Jangan jadikan MAC kita sendiri sebagai "host" untuk IP lain.
        # Saat kita melakukan ARP spoof (via NetControl), MAC kita muncul
        # mengaku sebagai IP korban; itu BUKAN host asli.
        my_mac = (self.my.get('mac') or '').lower()
        if my_mac and mac == my_mac and ip != self.my.get('ip'):
            return
        h = self.hosts.get(ip)
        now = time.time()
        if h is None:
            self.hosts[ip] = {
                'ip': ip, 'mac': mac, 'hostname': '', 'vendor': get_vendor(mac),
                'ipv6': '', 'first_seen': now, 'last_seen': now,
            }
        else:
            h['last_seen'] = now
            # Only touch last_seen; do NOT overwrite mac. If a different mac
            # appears for the same IP, record it as alt (spoof indicator).
            if h['mac'] != mac:
                h.setdefault('alt_macs', [])
                if mac not in h['alt_macs']:
                    h['alt_macs'].append(mac)

    # ── scanner berkala ────────────────────────────────────────────
    def _scan_loop(self):
        # scan pertama segera (untuk baseline)
        self._do_scan(initial=True)
        while not self._stop.is_set():
            # tunggu SCAN_INTERVAL, responsif terhadap stop
            for _ in range(int(SCAN_INTERVAL * 2)):
                if self._stop.is_set():
                    return
                time.sleep(0.5)
            self._do_scan(initial=False)

    def _do_scan(self, initial=False):
        try:
            gw_ip = self.gw.get('ip')
            if not gw_ip:
                self.gw = get_default_gw()
                gw_ip = self.gw.get('ip')
            if not gw_ip:
                return
            found = arp_scan_union(gw_ip, iface=self.iface)

            # tambahkan perangkat sendiri
            if self.my.get('ip') and self.my.get('mac'):
                found.setdefault(self.my['ip'], self.my['mac'])

            names = {}
            try:
                names = resolve_hostnames_bulk(list(found.keys()))
            except Exception:
                names = {}

            now = time.time()
            # Sumber OTORITATIF untuk MAC adalah ARP table kernel
            # (`ip neigh`). Hasil scan/spoof bisa berisi MAC palsu;
            # jangan sampai menimpa MAC asli yang sudah benar.
            try:
                kernel_arp = read_arp_table()
            except Exception:
                kernel_arp = {}

            with self.lock:
                for ip, mac in found.items():
                    mac = (mac or '').lower()
                    if not mac:
                        continue
                    # utamakan MAC dari kernel ARP table kalau ada
                    kmac = (kernel_arp.get(ip) or '').lower()
                    if kmac:
                        mac = kmac
                    h = self.hosts.get(ip)
                    if h is None:
                        self.hosts[ip] = {
                            'ip': ip, 'mac': mac,
                            'hostname': names.get(ip, ''),
                            'vendor': get_vendor(mac),
                            'ipv6': get_ipv6_of(mac) if self.ipv6_net else '',
                            'first_seen': now, 'last_seen': now,
                        }
                    else:
                        h['last_seen'] = now
                        if names.get(ip):
                            h['hostname'] = names.get(ip)
                        if h['mac'] != mac:
                            # JANGAN timpa MAC yang sudah ada; simpan sbg alt.
                            # Ini mencegah MAC spoof (mis. MAC kita yang
                            # mengaku IP korban) menimpa MAC asli.
                            h.setdefault('alt_macs', [])
                            if mac not in h['alt_macs']:
                                h['alt_macs'].append(mac)
                        if self.ipv6_net:
                            try:
                                h['ipv6'] = get_ipv6_of(h['mac'])
                            except Exception:
                                pass

            # baseline pertama = peta yang dipercaya
            if initial and not self.baseline_ready:
                self.detector.set_baseline(dict(found))
                self.baseline_ready = True

            self.last_scan = now
            self.scan_count += 1
            logger.info('scan #{}: {} host'.format(self.scan_count, len(found)))

            # ukur RTT per host (untuk estimasi posisi Topology View)
            self._measure_rtt(list(found.keys()))
        except Exception as e:
            logger.error('scan err: {}'.format(e))

    def _measure_rtt(self, ips):
        """Ukur RTT (ping) paralel untuk semua host, dengan smoothing.

        RTT WiFi ber-jitter (bisa berubah 10x antar-pengukuran). Supaya
        klasifikasi kedekatan stabil, kita:
          - kirim 4 paket ping per host, ambil MINIMUM (paling stabil,
            mewakili latensi dasar tanpa antrean)
          - simpan riwayat, lalu pakai MEDIAN dari beberapa ukuran
        """
        from concurrent.futures import ThreadPoolExecutor
        gw_ip = self.gw.get('ip')
        my_ip = self.my.get('ip')
        targets = [ip for ip in ips if ip not in (gw_ip, my_ip)]

        def _one(ip):
            try:
                p = sp.Popen(['ping', '-c', '4', '-i', '0.2', '-W', '1', ip],
                             stdout=sp.PIPE, stderr=sp.PIPE)
                out, _ = p.communicate(timeout=5)
                text = out.decode('utf-8', 'ignore')
                vals = []
                for line in text.splitlines():
                    if 'time=' in line:
                        try:
                            vals.append(float(line.split('time=')[-1].split()[0]))
                        except Exception:
                            pass
                if vals:
                    return ip, min(vals)   # minimum = latensi dasar
            except Exception:
                pass
            return ip, None

        with self.lock:
            self.rtt[gw_ip] = 0.5 if gw_ip else None
            self.rtt[my_ip] = 0.0 if my_ip else None

        if not targets:
            return
        with ThreadPoolExecutor(max_workers=min(len(targets), 32)) as pool:
            for ip, rtt in pool.map(_one, targets):
                if rtt is None:
                    continue
                with self.lock:
                    hist = self.rtt_hist.setdefault(ip, [])
                    hist.append(rtt)
                    if len(hist) > 5:
                        del hist[:-5]
                    # median dari riwayat -> stabil
                    s = sorted(hist)
                    self.rtt[ip] = s[len(s) // 2]

    # ── evaluasi & alert ───────────────────────────────────────────
    def _emit_alerts(self):
        try:
            fresh = self.detector.evaluate()
            if fresh and self.on_alerts:
                try:
                    self.on_alerts([a.to_dict() for a in fresh])
                except Exception as e:
                    logger.error('on_alerts cb err: {}'.format(e))
        except Exception as e:
            logger.error('evaluate err: {}'.format(e))

    # ── data untuk API ─────────────────────────────────────────────
    def hosts_list(self):
        with self.lock:
            threats = self.detector.threat_map()
            out = []
            for ip, h in self.hosts.items():
                d = dict(h)
                d['threat'] = threats.get(ip, '')
                d['is_gateway'] = (ip == self.gw.get('ip'))
                d['is_self'] = (ip == self.my.get('ip'))
                d['alt_macs'] = h.get('alt_macs', [])
                d['vendor'] = h.get('vendor') or get_vendor(h.get('mac', ''))
                d['random_mac'] = is_random_mac(h.get('mac', ''))
                out.append(d)

            def order(x):
                if x['is_gateway']:
                    return (0, x['ip'])
                if x['is_self']:
                    return (1, x['ip'])
                return (2, x['ip'])
            out.sort(key=order)
            return out

    def live_arp(self, limit=100):
        with self.lock:
            items = list(self.arp_live)[-limit:]
        return items[::-1]

    # ── Topology View ──────────────────────────────────────────────
    def _read_ap_rssi(self):
        """RSSI (dBm) laptop ke AP yang tersambung. None jika gagal."""
        try:
            p = sp.Popen(['iw', 'dev', self.iface, 'station', 'dump'],
                         stdout=sp.PIPE, stderr=sp.PIPE)
            out, _ = p.communicate(timeout=3)
            for line in out.decode('utf-8', 'ignore').splitlines():
                line = line.strip()
                if line.startswith('signal:') or line.startswith('signal avg:'):
                    # contoh: "signal:  -50 [-50] dBm"
                    parts = line.replace(':', ' ').split()
                    for tok in parts:
                        try:
                            v = int(tok)
                            if -100 < v < 0:
                                return v
                        except ValueError:
                            continue
        except Exception:
            pass
        return None

    def estimate_distance_cm(self, ip, rtt_ms=None):
        """
        Estimasi KASAR jarak perangkat (cm) — dengan asumsi & error jelas.

        Metode: RSSI (path-loss log-distance) untuk skala, RTT untuk
        perbaikan relatif.  Karena RSSI per-device TIDAK tersedia (kita
        klien WiFi, bukan AP), kita kalibrasi dari RSSI ke AP kita.

        Rumus path loss:
            d = 10 ^ ((RSSI_ref - RSSI) / (10 * n))
        dengan RSSI_ref = -40 dBm @ 1 m, n = 2.7 (indoor kantor/rumah).

        Karena hanya RTT yang kita punya per-device, RTT dipetakan ke
        "dBm ekivalen" secara linear terhadap median RTT LAN, lalu masuk
        rumus di atas.  AKURASI: ±2–5 meter. Ini ESTIMASI, bukan ukur.
        """
        import math
        # konstanta model (indoor)
        RSSI_REF = -40.0     # dBm pada 1 m
        N = 2.7              # path loss exponent indoor

        rtt = rtt_ms if rtt_ms is not None else self.rtt.get(ip)
        if rtt is None or rtt <= 0:
            rtt = 15.0
        # RTT -> "dBm ekivalen". Sensitivitas dikurangi supaya hasil
        # tidak ekstrem (dulu 1 ms = 0.15 dB -> 500ms jadi 30 m).
        # Sekarang 1 ms = 0.05 dB, dibatasi 60 ms efeknya (jenuh).
        eff_dbm = RSSI_REF - min(rtt, 60.0) * 0.05
        ratio = (RSSI_REF - eff_dbm) / (10.0 * N)
        d_m = 10 ** ratio
        # batasi agar tetap masuk akal untuk LAN indoor
        d_m = max(0.3, min(d_m, 15.0))
        return d_m * 100.0   # cm

    def _distance_label(self, cm):
        """Label jarak: mm (sangat dekat), cm, atau m."""
        if cm is None:
            return {'cm': None, 'mm': None, 'text': 'tidak diketahui'}
        mm = int(round(cm * 10))
        if cm < 10:
            # sangat dekat -> tampilkan cm presisi
            text = '~{:.0f} cm'.format(cm)
        elif cm < 100:
            # pembulatan 5 cm
            text = '~{:.0f} cm'.format(round(cm / 5) * 5)
        else:
            text = '~{:.1f} m'.format(cm / 100.0)
        return {'cm': round(cm, 1), 'mm': mm, 'text': text}

    def _spread_nodes(self, nodes, min_dist=0.11, iterations=120):
        """
        Anti-tumpuk: pastikan jarak antar-node >= min_dist, dengan
        menggeser node secara BEBAS (radial + sudut), bukan hanya
        sepanjang busur. Node yang berdesakan didorong saling menjauh.

        Gateway & perangkat sendiri tetap sebagai acuan (tidak digeser),
        kecuali kalau dia sendiri terlalu dekat dengan node lain.

        Node punya "pinned_radius" (radius asli dari RTT) supaya saat
        sudah cukup renggang, ia kembali ke posisi proporsionalnya.
        """
        import math
        if not nodes:
            return

        # simpan radius & sudut asli (basis proporsional RTT)
        for n in nodes:
            p = n['pos']
            vx, vy = p['x'] - 0.5, p['y'] - 0.5
            p['_base_r'] = math.hypot(vx, vy)
            p['_base_a'] = math.atan2(vy, vx) if (vx or vy) else 0.0
            # posisi kerja
            p['_x'] = p['x']
            p['_y'] = p['y']

        fixed_kinds = ('gateway',)
        for it in range(iterations):
            moved = False
            for i in range(len(nodes)):
                for j in range(i + 1, len(nodes)):
                    a, b = nodes[i], nodes[j]
                    pa, pb = a['pos'], b['pos']
                    dx = pa['_x'] - pb['_x']
                    dy = pa['_y'] - pb['_y']
                    dist = math.hypot(dx, dy)
                    if dist >= min_dist:
                        continue
                    if dist < 1e-6:
                        # persis bertumpuk -> pisahkan dengan sudut tetap
                        dx, dy, dist = 0.001, 0.001, 0.001414
                    push = (min_dist - dist) / 2.0
                    ux, uy = dx / dist, dy / dist
                    for node, sgn in ((a, 1), (b, -1)):
                        # gateway tetap di pusat; hanya dorong yang lain
                        if node['kind'] in fixed_kinds:
                            continue
                        p = node['pos']
                        p['_x'] += sgn * ux * push
                        p['_y'] += sgn * uy * push
                    moved = True
            if not moved:
                break

        # tulis kembali hasil spread; TIDAK menarik kembali ke radius
        # asli kalau itu akan membuat node bertumpuk lagi.
        for n in nodes:
            p = n['pos']
            if n['kind'] == 'gateway':
                p['x'], p['y'] = 0.5, 0.5
                p['r'] = 0.0
                for k in ('_x', '_y', '_base_r', '_base_a'):
                    p.pop(k, None)
                continue
            vx, vy = p['_x'] - 0.5, p['_y'] - 0.5
            cur_a = math.atan2(vy, vx) if (vx or vy) else p['_base_a']
            r = math.hypot(vx, vy)
            r = max(0.10, min(0.49, r))
            p['x'] = 0.5 + r * math.cos(cur_a)
            p['y'] = 0.5 + r * math.sin(cur_a)
            p['r'] = r
            for k in ('_x', '_y', '_base_r', '_base_a'):
                p.pop(k, None)

        # verifikasi akhir; kalau masih ada yang < min_dist, ulangi pass
        # pemisahan sederhana tanpa blend
        for _ in range(60):
            worst = None
            for i in range(len(nodes)):
                if nodes[i]['kind'] == 'gateway':
                    continue
                for j in range(i + 1, len(nodes)):
                    a, b = nodes[i], nodes[j]
                    dx = a['pos']['x'] - b['pos']['x']
                    dy = a['pos']['y'] - b['pos']['y']
                    d = math.hypot(dx, dy)
                    if d < min_dist:
                        worst = (a, b, d)
                        break
                if worst:
                    break
            if not worst:
                break
            a, b, d = worst
            if d < 1e-6:
                dx, dy, d = 0.001, 0.001, 0.001414
            else:
                dx = a['pos']['x'] - b['pos']['x']
                dy = a['pos']['y'] - b['pos']['y']
            push = (min_dist - d) / 2.0
            ux, uy = dx / d, dy / d
            for node, sgn in ((a, 1), (b, -1)):
                if node['kind'] == 'gateway':
                    continue
                node['pos']['x'] += sgn * ux * push
                node['pos']['y'] += sgn * uy * push

    def _affinity(self, a, b):
        """
        Skor kedekatan 0..1 antara dua IP (a,b).

        Berbasis sinyal yang BENAR-BENAR tersedia:
          - selisih RTT (makin mirip -> makin dekat)   bobot 0.55
          - ada komunikasi ARP a<->b                    bobot 0.30
          - keduanya sama-sama dekat router              bobot 0.15
        """
        import math as _m
        ra, rb = self.rtt.get(a), self.rtt.get(b)

        def _logv(x):
            if x is None or x <= 0:
                return None
            return _m.log10(x)

        la, lb = _logv(ra), _logv(rb)
        # rentang log RTT
        vals = [_logv(v) for v in self.rtt.values() if v and v > 0]
        span = (max(vals) - min(vals)) if vals else 1.0
        span = max(span, 0.3)

        # 1. kemiripan RTT
        if la is None or lb is None:
            sim = 0.4   # tidak diketahui -> netral-rendah
        else:
            sim = 1.0 - min(1.0, abs(la - lb) / span)

        # 2. relasi ARP (saling bicara)
        link = 1.0 if (b in self.arp_links.get(a, {}) or
                       a in self.arp_links.get(b, {})) else 0.0

        # 3. keduanya dekat router (RTT di bawah median)
        near = 0.0
        if ra and rb and ra > 0 and rb > 0:
            med_vals = sorted(v for v in self.rtt.values() if v and v > 0)
            if med_vals:
                med = med_vals[len(med_vals) // 2]
                if ra <= med and rb <= med:
                    near = 1.0

        return 0.55 * sim + 0.30 * link + 0.15 * near

    def _layout_cluster(self, ips, gw_ip, my_ip, rtt_radius):
        """
        Tata letak BERBASIS KEDEKATAN (affinity clustering).

        - Node dikelompokkan: yang affinity-nya tinggi jadi satu cluster.
        - Tiap cluster dapat SEKTOR sudut (busur) di lingkarannya.
        - Cluster diurutkan dari atas (jam 12) searah jarum jam, mulai
          dari yang terdekat ke router.
        - Perangkat sendiri (my_ip) ikut sebagai anggota (bukan dipaku).
        - Dalam cluster, node disebar RAPAT -> tampak berkelompok.

        Mengembalikan {ip: (x, y, radius, cluster_id, cluster_label)}.
        """
        import math as _m
        res = {}
        if gw_ip:
            res[gw_ip] = (0.5, 0.5, 0.0, -1, 'Router')

        members = [ip for ip in ips if ip not in (gw_ip,)]
        if not members:
            return res

        # ── 1. clustering sederhana (agglomerative threshold) ──
        # urutkan berdasar RTT (yang diketahui dulu)
        def _rk(ip):
            r = self.rtt.get(ip)
            return r if (r is not None and r > 0) else 1e9

        members.sort(key=_rk)

        # Radius (jarak ke router) tiap node; node dengan radius mirip
        # dianggap berada di "kelas jarak" yang sama -> satu cluster.
        def _rad(ip):
            return rtt_radius(self.rtt.get(ip))

        # ambang selisih radius untuk digabung ke cluster yang sama
        # (diperbesar: device WiFi bersebelahan sering beda RTT beberapa ms)
        RAD_EPS = 0.18
        clusters = []
        for ip in members:
            ri = _rad(ip)
            placed = False
            for cl in clusters:
                # rata-rata radius cluster
                rcs = [_rad(m) for m in cl]
                if rcs and abs(ri - sum(rcs) / len(rcs)) <= RAD_EPS:
                    cl.append(ip)
                    placed = True
                    break
            if not placed:
                clusters.append([ip])

        # gabungkan juga kalau affinity tinggi (mis. sering saling ARP)
        merged = True
        while merged:
            merged = False
            for i in range(len(clusters)):
                if merged:
                    break
                for j in range(i + 1, len(clusters)):
                    affs = [self._affinity(a, b)
                            for a in clusters[i] for b in clusters[j]]
                    if affs and (sum(affs) / len(affs)) >= 0.6:
                        clusters[i] += clusters[j]
                        clusters.pop(j)
                        merged = True
                        break

        # ── 2. hitung rata-rata RTT & radius tiap cluster ──
        def _avg_radius(cl):
            rs = [self.rtt.get(ip) for ip in cl
                  if self.rtt.get(ip) and self.rtt.get(ip) > 0]
            if not rs:
                return 0.33
            return rtt_radius(sum(rs) / len(rs))

        cl_info = []
        for cl in clusters:
            cl_info.append({'members': cl, 'radius': _avg_radius(cl)})
        # urutkan cluster dari yang TERDEKAT ke router
        cl_info.sort(key=lambda c: c['radius'])

        # ── 3. tata letak: tiap cluster dapat SATU SUDUT (center),
        #    anggotanya diletakkan RAPAT mengelilingi center tsb ──
        ncl = max(len(cl_info), 1)
        step = 2 * _m.pi / ncl
        ang = -_m.pi / 2   # mulai dari atas (jam 12), searah jarum jam
        SPREAD = 0.045     # radius sebaran anggota di dalam cluster (sangat rapat)
        for ci, c in enumerate(cl_info):
            r = c['radius']              # jarak cluster-center dari router
            cx = 0.5 + r * _m.cos(ang)
            cy = 0.5 + r * _m.sin(ang)
            label = 'Dekat' if r < 0.25 else ('Sedang' if r < 0.38 else 'Jauh')
            mcl = c['members']
            cnt = len(mcl)
            if cnt == 1:
                # sendiri -> tepat di center
                ip = mcl[0]
                if self.detector.threat_map().get(ip) == 'attacker':
                    rr = 0.40
                    res[ip] = (0.5 + rr * _m.cos(ang), 0.5 + rr * _m.sin(ang),
                               rr, ci, label)
                else:
                    res[ip] = (cx, cy, r, ci, label)
            else:
                # melingkar rapat di sekitar center cluster
                for k, ip in enumerate(mcl):
                    a2 = 2 * _m.pi * k / cnt
                    x = cx + SPREAD * _m.cos(a2)
                    y = cy + SPREAD * _m.sin(a2)
                    rr = _m.hypot(x - 0.5, y - 0.5)
                    if self.detector.threat_map().get(ip) == 'attacker':
                        rr = 0.40
                        x = 0.5 + rr * _m.cos(ang)
                        y = 0.5 + rr * _m.sin(ang)
                    res[ip] = (x, y, rr, ci, label)
            ang += step

        return res

    def topology(self, mode=None):
        """
        Hasilkan graf jaringan untuk visualisasi 2D.

        mode: 'radial'  -> posisi proporsional RTT dari router (default)
              'cluster' -> dikelompokkan berdasarkan kedekatan (affinity)

        PENTING: posisi node adalah ESTIMASI, bukan lokasi fisik.
        """
        import math
        with self.lock:
            threats = self.detector.threat_map()
            gw_ip = self.gw.get('ip')
            my_ip = self.my.get('ip')
            now = time.time()

            # bersihkan link lama (TTL)
            for ip in list(self.arp_links.keys()):
                peers = self.arp_links[ip]
                for p in list(peers.keys()):
                    if now - peers[p] > self._LINK_TTL:
                        del peers[p]
                if not peers:
                    self.arp_links.pop(ip, None)

            # susun daftar node (host + gateway + self)
            ips = set(self.hosts.keys())
            if gw_ip:
                ips.add(gw_ip)
            if my_ip:
                ips.add(my_ip)

            # hitung skor aktivitas maksimum untuk normalisasi
            max_act = max(self.arp_activity.values()) if self.arp_activity else 1

            # ── penempatan sudut BERBASIS KEDEKATAN (RTT) ───────────
            # Host dengan RTT mirip diurutkan berdampingan supaya sudutnya
            # berdekatan (perangkat di kelas jarak sama tampak berkelompok).
            # Host tanpa RTT ditaruh paling akhir.
            others = [ip for ip in ips if ip not in (gw_ip, my_ip)]

            def _rtt_key(ip):
                r = self.rtt.get(ip)
                return (r if (r is not None and r > 0) else 1e9)

            others.sort(key=_rtt_key)
            n = len(others)
            for idx, ip in enumerate(others):
                if ip not in self.node_angles:
                    # sudut merata berurutan -> tetangga RTT = tetangga sudut
                    self.node_angles[ip] = (idx / max(n, 1)) * 2 * math.pi

            # ── radius PROPORSIONAL terhadap RTT ────────────────────
            # Router = titik pusat. Makin dekat ke router (RTT kecil) ->
            # makin dekat ke pusat. Makin jauh (RTT besar) -> makin ke tepi.
            # Pakai skala LOG karena RTT rentangnya lebar (1 ms .. 1000 ms),
            # supaya perbedaan kecil di RTT rendah tetap terlihat.
            import math as _m
            rtt_vals = [v for v in self.rtt.values()
                        if v is not None and v > 0]
            if rtt_vals:
                lo = max(min(rtt_vals), 0.1)
                hi = max(max(rtt_vals), lo * 1.01)
            else:
                lo, hi = 1.0, 100.0
            log_lo = _m.log10(lo)
            log_hi = _m.log10(hi)
            R_MIN, R_MAX = 0.18, 0.40   # radius dipersempit supaya device
                                          # LAN serumpun tidak terpencar

            # Noise floor: RTT di bawah ambang ini adalah noise WiFi
            # (scheduling, contention), BUKAN perbedaan jarak fisik.
            # Device bersebelahan di WiFi bisa beda 1-5ms tanpa jarak.
            NOISE_FLOOR = max(5.0, lo * 2)

            def _rtt_radius(rtt):
                if rtt is None or rtt <= 0:
                    return (R_MIN + R_MAX) / 2.0
                eff = max(rtt - NOISE_FLOOR, 0.01)
                eff_lo = max(lo - NOISE_FLOOR, 0.01)
                eff_hi = max(hi - NOISE_FLOOR, eff_lo * 1.01)
                frac = (_m.log10(eff) - _m.log10(eff_lo)) / max(
                    _m.log10(eff_hi) - _m.log10(eff_lo), 1e-6)
                frac = max(0.0, min(1.0, frac))
                return R_MIN + (R_MAX - R_MIN) * frac

            # pilih mode layout
            lay_mode = (mode or self.layout_mode or 'radial').lower()
            cluster_pos = {}
            cluster_labels = {}
            if lay_mode == 'cluster':
                cluster_pos = self._layout_cluster(ips, gw_ip, my_ip, _rtt_radius)

            gw_mac = self.gw.get('mac') or ''
            links_virtual = []
            nodes = []
            for ip in ips:
                h = self.hosts.get(ip, {})
                threat = threats.get(ip, '')
                is_gw = (ip == gw_ip)
                is_self = (ip == my_ip)

                if is_gw:
                    kind = 'gateway'
                    pos = {'x': 0.5, 'y': 0.5, 'r': 0.0, 'ring': -1}
                    label = 'Router / Gateway'
                elif lay_mode == 'cluster' and ip in cluster_pos:
                    x, y, rr, ci, cl_label = cluster_pos[ip]
                    kind = 'self' if is_self else 'host'
                    pos = {'x': x, 'y': y, 'r': rr, 'ring': round(rr, 3),
                           'cluster': ci, 'cluster_label': cl_label}
                    label = (h.get('hostname') or ip)
                    cluster_labels[ci] = cl_label
                elif is_self:
                    kind = 'self'
                    pos = {'x': 0.5, 'y': 0.5 + 0.14, 'r': 0.14, 'ring': 0}
                    label = (h.get('hostname') or 'Perangkat ini')
                else:
                    kind = 'host'
                    rtt = self.rtt.get(ip)
                    radius = _rtt_radius(rtt)   # proporsional terhadap RTT
                    if threat == 'attacker':
                        radius = R_MAX   # penyerang di tepi terluar
                    ang = self.node_angles.get(ip, 0.0)
                    pos = {
                        'x': 0.5 + radius * math.cos(ang),
                        'y': 0.5 + radius * math.sin(ang),
                        'r': radius,
                        'ring': round(radius, 3),
                    }
                    label = h.get('hostname') or ip

                nodes.append({
                    'ip': ip,
                    'mac': h.get('mac', ''),
                    'label': label,
                    'kind': kind,
                    'threat': threat,
                    'vendor': h.get('vendor') or get_vendor(h.get('mac', '')),
                    'rtt': self.rtt.get(ip),
                    'activity': self.arp_activity.get(ip, 0),
                    'pos': pos,
                    'alt_macs': h.get('alt_macs', []),
                    'distance': self._distance_label(
                        self.estimate_distance_cm(ip, self.rtt.get(ip))),
                })

            # ── node PENYERANG virtual ──────────────────────────────
            # MAC asing yang mengaku gateway/host lain sering TIDAK punya
            # IP sendiri → tidak muncul sebagai host. Kita tambahkan node
            # khusus supaya penyerang terlihat di topology.
            attacker_macs = {}
            for a in self.detector._alert_log[-300:]:
                if a.severity != 'critical':
                    continue
                am = (getattr(a, 'attacker_mac', '') or '').lower()
                if not am:
                    continue
                # jangan tandai MAC gateway asli
                if gw_mac and am == gw_mac.lower():
                    continue
                attacker_macs[am] = attacker_macs.get(am, 0) + 1

            # apakah MAC penyerang sudah tampil sebagai node (punya IP)?
            known_macs = set((n.get('mac') or '').lower() for n in nodes)
            k = len(attacker_macs)
            for idx, (am, _cnt) in enumerate(sorted(attacker_macs.items())):
                if am in known_macs:
                    continue
                # taruh di ring terluar, sudut tersebar
                ang = (idx / max(k, 1)) * 2 * math.pi + math.pi / 4
                radius = R_MAX   # konsisten dengan R_MAX baru
                # coba lacak IP asli penyerang dari data yang ada
                try:
                    cands, note = self.detector.attacker_ip_candidates(am)
                except Exception:
                    cands, note = [], ''
                # fallback: cek ARP table sistem (kalau MAC ini pernah
                # tercatat dengan IP lain)
                try:
                    for _ip, _mac in read_arp_table().items():
                        if _mac.lower() == am and _ip not in cands:
                            cands.append(_ip)
                except Exception:
                    pass

                nodes.append({
                    'ip': '@' + am,            # id unik internal (bukan IP)
                    'mac': am,
                    'label': 'PENYERANG',
                    'kind': 'attacker',
                    'threat': 'attacker',
                    'vendor': get_vendor(am),
                    'rtt': None,
                    'activity': 0,
                    'pos': {
                        'x': 0.5 + radius * math.cos(ang),
                        'y': 0.5 + radius * math.sin(ang),
                        'r': radius,
                    },
                    'alt_macs': [],
                    'virtual': True,
                    'no_ip': True,          # tidak punya IP di ARP (menyamar)
                    'display_ip': 'MAC palsu',
                    'ip_candidates': cands,   # kandidat IP asli
                    'ip_note': note,
                    'distance': self._distance_label(None),
                })
                # garis putus penyerang -> gateway
                if gw_ip:
                    links_virtual.append({'src': '@' + am, 'dst': gw_ip,
                                          'kind': 'attack', 'strength': 1.0})

            # ── anti-tumpuk (collision avoidance) ───────────────────
            # Pastikan jarak antar-node >= MIN_DIST supaya tidak bertumpuk
            # & mudah divisualisasikan. Di mode cluster, ambang lebih kecil
            # supaya anggota satu cluster tetap tampak berkelompok.
            if lay_mode == 'cluster':
                self._spread_nodes(nodes, min_dist=0.075, iterations=80)
            else:
                self._spread_nodes(nodes)

            # links: hub (semua host -> gateway) + overlay ARP nyata
            links = list(links_virtual)
            if gw_ip:
                for ip in ips:
                    if ip != gw_ip:
                        links.append({'src': ip, 'dst': gw_ip,
                                      'kind': 'hub', 'strength': 0.35})

            # overlay ARP nyata — HANYA antar host yang dikenal.
            # Catatan: scan kita sendiri mengirim ARP ke seluruh subnet
            # (.1..255), jadi banyak "link" palsu ke IP yang tak dikenal.
            # Batasi hanya pasangan yang KEDUANYA ada di daftar host.
            pair_count = {}
            for src, peers in self.arp_links.items():
                if src not in ips:
                    continue
                for dst in peers:
                    if dst not in ips or dst == src:
                        continue
                    a, b = sorted([src, dst])
                    pair_count[(a, b)] = pair_count.get((a, b), 0) + 1
            max_pair = max(pair_count.values()) if pair_count else 1
            for (a, b), cnt in pair_count.items():
                strength = min(1.0, 0.3 + 0.7 * (cnt / max_pair))
                links.append({'src': a, 'dst': b, 'kind': 'arp',
                              'strength': strength})

            ap_rssi = self._read_ap_rssi()
            return {
                'nodes': nodes,
                'links': links,
                'gateway': gw_ip,
                'self': my_ip,
                'meta': {
                    'timestamp': now,
                    'mode': lay_mode,
                    'ap_rssi': ap_rssi,          # RSSI laptop->AP (dBm)
                    'distance_note': 'Estimasi jarak KASAR berbasis RTT '
                                     '& model path-loss (akurasi ±2–5 m). '
                                     'Bukan pengukuran presisi.',
                    'disclaimer': 'Posisi & jarak adalah ESTIMASI '
                                  'berdasarkan RTT/latency — BUKAN lokasi '
                                  'fisik sebenarnya. Tidak ada RSSI '
                                  'per-perangkat pada klien WiFi.',
                },
            }


_monitor = None
_monitor_lock = threading.Lock()


def get_monitor():
    """Singleton Monitor."""
    global _monitor
    with _monitor_lock:
        if _monitor is None:
            _monitor = Monitor()
        return _monitor
