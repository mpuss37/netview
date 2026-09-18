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
        # entri aktivitas ARP: {ip: jumlah_paket}
        self.arp_activity = {}
        # sudut node stabil (agar tidak lompat-lompat tiap refresh)
        self.node_angles = {}
        # graf relasi lama dianggap kedaluwarsa
        self._LINK_TTL = 60.0

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
        h = self.hosts.get(ip)
        now = time.time()
        if h is None:
            self.hosts[ip] = {
                'ip': ip, 'mac': mac, 'hostname': '', 'vendor': get_vendor(mac),
                'ipv6': '', 'first_seen': now, 'last_seen': now,
            }
        else:
            h['last_seen'] = now
            # catat MAC tambahan (indikasi konflik/spoof)
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
            with self.lock:
                for ip, mac in found.items():
                    mac = (mac or '').lower()
                    if not mac:
                        continue
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
        """Ukur RTT (ping) paralel untuk semua host. Gateway & self di-skip."""
        from concurrent.futures import ThreadPoolExecutor
        gw_ip = self.gw.get('ip')
        my_ip = self.my.get('ip')
        targets = [ip for ip in ips if ip not in (gw_ip, my_ip)]

        def _one(ip):
            try:
                p = sp.Popen(['ping', '-c', '1', '-W', '1', ip],
                             stdout=sp.PIPE, stderr=sp.PIPE)
                out, _ = p.communicate(timeout=2)
                text = out.decode('utf-8', 'ignore')
                for line in text.splitlines():
                    if 'time=' in line:
                        val = line.split('time=')[-1].split()[0]
                        return ip, float(val)
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
                with self.lock:
                    if rtt is not None:
                        self.rtt[ip] = rtt

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
    def topology(self):
        """
        Hasilkan graf jaringan untuk visualisasi 2D.

        PENTING: posisi node adalah ESTIMASI TOPOLOGI berdasarkan RTT &
        aktivitas ARP — BUKAN lokasi fisik. Dilabeli demikian di UI.
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
            max_rtt = max([v for v in self.rtt.values() if v], default=1.0) or 1.0

            # host non-sentral untuk penempatan sudut merata
            others = sorted([ip for ip in ips if ip not in (gw_ip, my_ip)])
            n = len(others)
            # sudut stabil: pakai cache; kalau baru, sebarkan merata
            for idx, ip in enumerate(others):
                if ip not in self.node_angles:
                    self.node_angles[ip] = (idx / max(n, 1)) * 2 * math.pi

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
                    pos = {'x': 0.5, 'y': 0.5, 'r': 0.0}
                    label = 'Router / Gateway'
                elif is_self:
                    kind = 'self'
                    pos = {'x': 0.5, 'y': 0.5 + 0.14, 'r': 0.14}
                    label = (h.get('hostname') or 'Perangkat ini')
                else:
                    kind = 'host'
                    rtt = self.rtt.get(ip)
                    act = self.arp_activity.get(ip, 0)
                    # skor radius: RTT besar -> lebih jauh; aktivitas tinggi -> lebih dekat
                    rtt_score = (rtt / max_rtt) if (rtt is not None and max_rtt) else 0.3
                    act_score = 1.0 - (act / max_act if max_act else 0)
                    radius = 0.16 + 0.30 * (0.65 * rtt_score + 0.35 * act_score)
                    if threat == 'attacker':
                        radius = 0.46   # penyerang sengaja di ring terluar
                    ang = self.node_angles.get(ip, 0.0)
                    pos = {
                        'x': 0.5 + radius * math.cos(ang),
                        'y': 0.5 + radius * math.sin(ang),
                        'r': radius,
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
                radius = 0.48
                nodes.append({
                    'ip': '@' + am,            # id unik (bukan IP asli)
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
                })
                # garis putus penyerang -> gateway
                if gw_ip:
                    links_virtual.append({'src': '@' + am, 'dst': gw_ip,
                                          'kind': 'attack', 'strength': 1.0})

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

            return {
                'nodes': nodes,
                'links': links,
                'gateway': gw_ip,
                'self': my_ip,
                'meta': {
                    'timestamp': now,
                    'disclaimer': 'Posisi adalah estimasi topologi '
                                  'berdasarkan RTT & aktivitas ARP — '
                                  'BUKAN lokasi fisik sebenarnya.',
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
