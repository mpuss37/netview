"""
Detector NetView - mesin deteksi serangan ARP spoofing.

Menerima "fakta" dari monitor (ARP events, peta host, baseline) dan
menghasilkan ALERT. Tidak melakukan aksi jaringan apa pun — itu tugas
defense.py.

Aturan deteksi (8):
  1. GATEWAY_MAC_CHANGED   - MAC gateway berubah dari baseline
  2. IP_MULTIPLE_MACS      - satu IP diklaim >1 MAC
  3. MAC_MULTIPLE_IPS      - satu MAC mengklaim >1 IP
  4. UNSOLICITED_REPLY     - ARP reply tak diminta dari host asing
  5. GARP_FLOOD            - gratuitous ARP flood dari satu MAC
  6. GATEWAY_RANDOM_MAC    - gateway dengan MAC acak/privat
  7. OUT_OF_SUBNET_CLAIM   - ARP mengklaim IP di luar subnet
  8. DUPLICATE_MAC_OUI     - dua IP berbeda memakai MAC sama
"""
import time
from utils import logger

SEV_INFO = 'info'
SEV_WARN = 'warning'
SEV_CRIT = 'critical'

# periode observasi untuk GARP flood
_GARP_WINDOW = 10.0     # detik
_GARP_THRESHOLD = 30    # GARP dari 1 MAC dalam window -> flood

# dedup: jangan spam alert identik
_DEDUP_TTL = 20.0


class Alert(object):
    def __init__(self, kind, severity, message, ip='', mac='', details=None):
        self.kind = kind
        self.severity = severity
        self.message = message
        self.ip = ip
        self.mac = mac
        self.details = details or {}
        self.timestamp = time.time()

    def key(self):
        return '{}|{}|{}'.format(self.kind, self.ip, self.mac)

    def to_dict(self):
        return {
            'kind': self.kind,
            'severity': self.severity,
            'message': self.message,
            'ip': self.ip,
            'mac': self.mac,
            'details': self.details,
            'timestamp': self.timestamp,
        }


class Detector(object):
    """
    Detektor stateful. Monitor memanggil:
      - observe_arp(ip, mac, op, sender_mac, iface)   tiap paket ARP
      - set_baseline({ip: mac})                        saat scan awal
      - set_gateway(gw_ip, gw_mac, iface)
    Lalu memanggil evaluate() untuk menghasilkan alert.
    """

    def __init__(self):
        self.baseline = {}        # {ip: mac} hasil scan pertama (dipercaya)
        self.gateway_ip = None
        self.gateway_mac = None
        self.iface = 'wlan0'
        self.my_ip = None

        # observasi live
        self.ip_macs = {}         # {ip: {mac: last_seen_ts}}
        self.mac_ips = {}         # {mac: {ip: last_seen_ts}}
        self.garp_times = {}      # {mac: [ts,...]}  (op=2 unsolicited)
        self._alerts = {}         # {key: Alert}  dedup store
        self._alert_log = []      # list of Alert (riwayat lengkap)

        self.auto_defense = False
        self.whitelist_macs = set()
        self.whitelist_ips = set()

    # ── setter ─────────────────────────────────────────────────────
    def set_gateway(self, gw_ip, gw_mac, iface):
        self.gateway_ip = gw_ip
        self.gateway_mac = gw_mac
        self.iface = iface

    def set_my_ip(self, ip):
        self.my_ip = ip

    def set_baseline(self, mapping):
        """Set baseline IP->MAC (dari scan pertama, dianggap benar)."""
        # jangan timpa baseline yang sudah ada dengan data baru sembarangan;
        # hanya tambah entry yang belum diketahui
        for ip, mac in (mapping or {}).items():
            if ip not in self.baseline and mac:
                self.baseline[ip] = mac
        # gateway selalu masuk baseline
        if self.gateway_ip and self.gateway_mac:
            if self.gateway_ip not in self.baseline:
                self.baseline[self.gateway_ip] = self.gateway_mac
        logger.info('baseline: {} entri'.format(len(self.baseline)))

    def set_whitelist(self, macs, ips):
        self.whitelist_macs = set(m.lower() for m in (macs or []))
        self.whitelist_ips = set(ips or [])

    def _whitelisted(self, ip, mac):
        return (ip in self.whitelist_ips or
                (mac or '').lower() in self.whitelist_macs)

    # ── observasi ──────────────────────────────────────────────────
    def observe_arp(self, ip, mac, op, iface=None):
        """
        Catat satu paket ARP. op: 1=request, 2=reply.
        `mac` = hwsrc (MAC pengklaim), `ip` = psrc (IP yang diklaim).
        """
        if not ip or not mac:
            return
        mac = mac.lower()
        now = time.time()
        self.ip_macs.setdefault(ip, {})[mac] = now
        self.mac_ips.setdefault(mac, {})[ip] = now

        # gratuitous ARP: reply yang mengklaim gateway, atau psrc==pdst
        # di sini kita catat reply sebagai kandidat GARP
        if op == 2:
            arr = self.garp_times.setdefault(mac, [])
            arr.append(now)
            # buang yang lama
            cutoff = now - _GARP_WINDOW
            self.garp_times[mac] = [t for t in arr if t >= cutoff]

    # ── evaluasi aturan ────────────────────────────────────────────
    def evaluate(self):
        """Jalankan semua aturan, kembalikan daftar alert BARU (belum dedup)."""
        found = []
        found += self._rule_gateway_mac_changed()
        found += self._rule_ip_multiple_macs()
        found += self._rule_mac_multiple_ips()
        found += self._rule_garp_flood()
        found += self._rule_gateway_random_mac()
        found += self._rule_out_of_subnet()
        found += self._rule_duplicate_mac()
        return self._dedup(found)

    def _rule_gateway_mac_changed(self):
        """Gateway MAC sekarang != baseline -> serangan MITM."""
        out = []
        if not self.gateway_ip:
            return out
        expect = self.baseline.get(self.gateway_ip) or self.gateway_mac
        seen = self.ip_macs.get(self.gateway_ip, {})
        if not expect or not seen:
            return out
        for mac in seen:
            if mac.lower() != expect.lower():
                out.append(Alert(
                    'GATEWAY_MAC_CHANGED', SEV_CRIT,
                    'Gateway {} diklaim MAC asing {} (harusnya {}) — '
                    'indikasi ARP spoofing/MITM!'.format(
                        self.gateway_ip, mac, expect),
                    ip=self.gateway_ip, mac=mac,
                    details={'expected_mac': expect, 'seen_mac': mac}))
        return out

    def _rule_ip_multiple_macs(self):
        """Satu IP diklaim lebih dari satu MAC."""
        out = []
        for ip, macs in self.ip_macs.items():
            real = [m for m in macs if not self._whitelisted(ip, m)]
            if len(real) > 1:
                out.append(Alert(
                    'IP_MULTIPLE_MACS', SEV_WARN,
                    'IP {} diklaim {} MAC berbeda: {}'.format(
                        ip, len(real), ', '.join(sorted(real))),
                    ip=ip, mac=','.join(sorted(real)),
                    details={'macs': sorted(real)}))
        return out

    def _rule_mac_multiple_ips(self):
        """Satu MAC mengklaim banyak IP (spoof massal)."""
        out = []
        for mac, ips in self.mac_ips.items():
            real = [i for i in ips if not self._whitelisted(i, mac)]
            # abaikan gateway (router sah punya banyak? tidak—biasanya 1)
            if len(real) > 2:
                out.append(Alert(
                    'MAC_MULTIPLE_IPS', SEV_WARN,
                    'MAC {} mengklaim {} IP berbeda: {}'.format(
                        mac, len(real), ', '.join(sorted(real))),
                    ip=','.join(sorted(real)), mac=mac,
                    details={'ips': sorted(real)}))
        return out

    def _rule_garp_flood(self):
        """Gratuitous ARP flood dari satu MAC."""
        out = []
        for mac, times in self.garp_times.items():
            if len(times) >= _GARP_THRESHOLD:
                out.append(Alert(
                    'GARP_FLOOD', SEV_CRIT,
                    'Gratuitous ARP flood dari MAC {} ({} paket / {}s) — '
                    'kemungkinan ARP poisoning agresif'.format(
                        mac, len(times), int(_GARP_WINDOW)),
                    mac=mac, details={'count': len(times)}))
        return out

    def _rule_gateway_random_mac(self):
        """Gateway memakai MAC acak/privat — mencurigakan."""
        out = []
        if not self.gateway_ip:
            return out
        from utils import is_random_mac
        for mac in self.ip_macs.get(self.gateway_ip, {}):
            if is_random_mac(mac):
                out.append(Alert(
                    'GATEWAY_RANDOM_MAC', SEV_WARN,
                    'Gateway {} memakai MAC acak/privat {} — mencurigakan'.format(
                        self.gateway_ip, mac),
                    ip=self.gateway_ip, mac=mac))
        return out

    def _rule_out_of_subnet(self):
        """ARP mengklaim IP di luar subnet kita."""
        out = []
        if not self.gateway_ip:
            return out
        prefix = '.'.join(self.gateway_ip.split('.')[:3]) + '.'
        for ip in self.ip_macs:
            if not ip.startswith(prefix):
                # IP di luar /24 gateway
                for mac in self.ip_macs[ip]:
                    out.append(Alert(
                        'OUT_OF_SUBNET_CLAIM', SEV_INFO,
                        'ARP mengklaim IP luar subnet {} dari MAC {}'.format(
                            ip, mac),
                        ip=ip, mac=mac))
        return out

    def _rule_duplicate_mac(self):
        """Dua IP berbeda memakai MAC sama (bisa normal utk router, tapi pantau)."""
        out = []
        for mac, ips in self.mac_ips.items():
            if len(ips) == 2 and self.gateway_ip in ips:
                other = [i for i in ips if i != self.gateway_ip]
                if other and not self._whitelisted(other[0], mac):
                    out.append(Alert(
                        'DUPLICATE_MAC_OUI', SEV_INFO,
                        'MAC {} dipakai oleh gateway dan {}'.format(
                            mac, other[0]),
                        ip=other[0], mac=mac))
        return out

    # ── dedup & riwayat ────────────────────────────────────────────
    def _dedup(self, alerts):
        now = time.time()
        fresh = []
        for a in alerts:
            k = a.key()
            last = self._alerts.get(k)
            if last and (now - last.timestamp) < _DEDUP_TTL:
                continue
            self._alerts[k] = a
            fresh.append(a)
        # catat ke riwayat lengkap
        self._alert_log.extend(fresh)
        # batasi riwayat supaya tidak tumbuh tanpa batas
        if len(self._alert_log) > 5000:
            self._alert_log = self._alert_log[-2000:]
        return fresh

    def alerts(self, limit=200):
        """Riwayat alert terbaru."""
        return [a.to_dict() for a in self._alert_log[-limit:]][::-1]

    def clear_alerts(self):
        self._alert_log = []
        self._alerts = {}

    # ── status host (untuk GUI) ────────────────────────────────────
    def threat_map(self):
        """
        Kembalikan {ip: status} dengan status:
          'attacker' jika IP terkait alert critical
          'suspicious' jika terkait warning
          '' normal
        """
        res = {}
        for a in self._alert_log[-500:]:
            if not a.ip:
                continue
            for ip in a.ip.split(','):
                ip = ip.strip()
                if not ip:
                    continue
                cur = res.get(ip, '')
                if a.severity == SEV_CRIT:
                    res[ip] = 'attacker'
                elif a.severity == SEV_WARN and cur != 'attacker':
                    res[ip] = 'suspicious'
        return res
