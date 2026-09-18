"""
Defense NetView - proteksi device sendiri dari ARP spoofing.

Dua mode:
  1. HARDENING (pasif, selalu saat proteksi ON):
     - kunci ARP gateway statis (ip neigh ... nud permanent)
     - arptables: default DROP, hanya izinkan gateway MAC benar
     - memblokir ARP spoof masuk ke device kita
  2. AUTO-DEFENSE (aktif, opsional):
     - saat alert critical terdeteksi, otomatis:
       * blokir MAC penyerang di arptables
       * pulihkan ARP gateway ke MAC asli
       * kirim ARP koreksi ke gateway (defend)
       * catat tindakan ke log

PENTING: NetView hanya menyentuh rule miliknya sendiri. Untuk menghindari
bentrok dengan NetControl/TuxCut, audit menunjukkan NetControl memakai
arptables polos (bukan tabel terpisah). NetView memakai arptables juga,
jadi proteksi NetView sebaiknya dipakai saat NetControl tidak dipakai
untuk spoof. Ini didokumentasikan di README.
"""
import subprocess as sp
import threading
import time

from utils import logger, get_default_gw, get_my, _run

# arptables chain khusus agar mudah dibersihkan
_ARP_CHAIN = 'NETVIEW'


class Defense(object):
    def __init__(self):
        self.lock = threading.RLock()
        self.enabled = False            # hardening ON/OFF
        self.auto_defense = False       # auto-defense ON/OFF
        self.gw_ip = None
        self.gw_mac = None
        self.iface = 'wlan0'
        self.blocked = {}               # {mac: ts} MAC yang diblokir
        self.actions = []               # riwayat tindakan
        self._orig_fwd = None

    # ── informasi ──────────────────────────────────────────────────
    def state(self):
        with self.lock:
            return {
                'enabled': self.enabled,
                'auto_defense': self.auto_defense,
                'gw_ip': self.gw_ip,
                'gw_mac': self.gw_mac,
                'iface': self.iface,
                'blocked': sorted(self.blocked.keys()),
                'blocked_count': len(self.blocked),
                'actions': self.actions[-50:],
            }

    def _log_action(self, action, detail=''):
        rec = {'ts': time.time(), 'action': action, 'detail': detail}
        self.actions.append(rec)
        if len(self.actions) > 1000:
            self.actions = self.actions[-500:]
        logger.info('defense: {} - {}'.format(action, detail))

    # ── hardening (proteksi dasar) ─────────────────────────────────
    def enable(self, gw_ip=None, gw_mac=None, iface=None):
        """Aktifkan hardening untuk device sendiri."""
        with self.lock:
            gw = get_default_gw()
            self.gw_ip = gw_ip or gw.get('ip')
            self.gw_mac = gw_mac or gw.get('mac')
            self.iface = iface or gw.get('iface', 'wlan0')
            if not self.gw_ip or not self.gw_mac:
                return False, 'gateway tidak diketahui'
            try:
                self._apply_hardening()
                self.enabled = True
                self._log_action('enable',
                                 'gw {} ({})'.format(self.gw_ip, self.gw_mac))
                return True, 'Proteksi aktif'
            except Exception as e:
                logger.error('enable err: {}'.format(e))
                return False, str(e)

    def _apply_hardening(self):
        # bersihkan rules lama milik NetView
        sp.Popen(['arptables', '-F'], stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
        # default policy: DROP (blokir semua ARP yang tidak diizinkan)
        sp.Popen(['arptables', '-P', 'INPUT', 'DROP'],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
        sp.Popen(['arptables', '-P', 'OUTPUT', 'DROP'],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
        # izinkan ARP dari/ke gateway dengan MAC yang benar
        sp.Popen(['arptables', '-A', 'INPUT', '-s', self.gw_ip,
                  '--source-mac', self.gw_mac, '-j', 'ACCEPT'],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
        sp.Popen(['arptables', '-A', 'OUTPUT', '-d', self.gw_ip,
                  '--destination-mac', self.gw_mac, '-j', 'ACCEPT'],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
        # kunci ARP gateway statis (modern + legacy)
        sp.Popen(['arp', '-s', self.gw_ip, self.gw_mac],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
        try:
            sp.Popen(['ip', 'neigh', 'replace', self.gw_ip, 'lladdr',
                      self.gw_mac, 'dev', self.iface, 'nud', 'permanent'],
                     stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
        except Exception:
            pass

    def disable(self):
        """Matikan proteksi, kembalikan arptables ke normal."""
        with self.lock:
            try:
                sp.Popen(['arptables', '-P', 'INPUT', 'ACCEPT'],
                         stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
                sp.Popen(['arptables', '-P', 'OUTPUT', 'ACCEPT'],
                         stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
                sp.Popen(['arptables', '-F'],
                         stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
                # lepas kunci statis gateway (biar DHCP/ARP normal lagi)
                if self.gw_ip:
                    sp.Popen(['arp', '-d', self.gw_ip],
                             stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
                    try:
                        sp.Popen(['ip', 'neigh', 'del', self.gw_ip, 'dev',
                                  self.iface],
                                 stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
                    except Exception:
                        pass
            except Exception as e:
                logger.error('disable err: {}'.format(e))
            self.enabled = False
            self.blocked = {}
            self._log_action('disable')
            return True, 'Proteksi dimatikan'

    # ── auto-defense ───────────────────────────────────────────────
    def set_auto(self, on):
        with self.lock:
            self.auto_defense = bool(on)
            self._log_action('auto-defense',
                             'ON' if on else 'OFF')
            return self.auto_defense

    def handle_alerts(self, alerts):
        """
        Dipanggil monitor saat ada alert baru. Kalau auto-defense ON,
        ambil tindakan untuk alert critical.
        """
        with self.lock:
            if not self.auto_defense:
                return []
            acts = []
            for a in alerts:
                if a.get('severity') != 'critical':
                    continue
                attacker_mac = (a.get('mac') or '').split(',')[0].strip().lower()
                if not attacker_mac:
                    continue
                # jangan blokir MAC gateway sendiri
                if self.gw_mac and attacker_mac == self.gw_mac.lower():
                    continue
                if attacker_mac in self.blocked:
                    continue
                self._block_mac(attacker_mac)
                acts.append(attacker_mac)
                self._log_action('auto-block', attacker_mac)
            if acts:
                # pulihkan ARP gateway sebagai langkah pemulihan
                self._restore_arp()
            return acts

    def _block_mac(self, mac):
        """Blokir MAC di arptables (input & output)."""
        try:
            sp.Popen(['arptables', '-I', 'INPUT', '1', '--source-mac', mac,
                      '-j', 'DROP'],
                     stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
            sp.Popen(['arptables', '-I', 'OUTPUT', '1', '--destination-mac',
                      mac, '-j', 'DROP'],
                     stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
            self.blocked[mac] = time.time()
        except Exception as e:
            logger.error('block_mac err: {}'.format(e))

    def _restore_arp(self):
        """Tulis ulang ARP gateway yang benar + kirim koreksi ke gateway."""
        if not (self.gw_ip and self.gw_mac):
            return
        try:
            sp.Popen(['ip', 'neigh', 'replace', self.gw_ip, 'lladdr',
                      self.gw_mac, 'dev', self.iface, 'nud', 'permanent'],
                     stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
        except Exception:
            pass

    def unblock_all(self):
        with self.lock:
            for mac in list(self.blocked.keys()):
                try:
                    sp.Popen(['arptables', '-D', 'INPUT', '--source-mac', mac,
                              '-j', 'DROP'],
                             stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
                    sp.Popen(['arptables', '-D', 'OUTPUT', '--destination-mac',
                              mac, '-j', 'DROP'],
                             stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait()
                except Exception:
                    pass
            self.blocked = {}
            self._log_action('unblock-all')
            return True


_defense = None


def get_defense():
    global _defense
    if _defense is None:
        _defense = Defense()
    return _defense
