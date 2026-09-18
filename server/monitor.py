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
        except Exception as e:
            logger.error('scan err: {}'.format(e))

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


_monitor = None
_monitor_lock = threading.Lock()


def get_monitor():
    """Singleton Monitor."""
    global _monitor
    with _monitor_lock:
        if _monitor is None:
            _monitor = Monitor()
        return _monitor
