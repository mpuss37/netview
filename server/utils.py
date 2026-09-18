"""
Utils NetView - fungsi jaringan untuk monitoring & deteksi.

Berbeda dari NetControl: TIDAK ada fungsi spoofing. Fokus pada
pembacaan jaringan (scan, ARP table, vendor, hostname) dan proteksi.
"""
import os
from pathlib import Path
import sys
import subprocess as sp
import logging
import time
from scapy.all import *
import netifaces


LOG_DIR = '/var/log/netview'
if not os.path.isdir(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)
server_log = Path(os.path.join(LOG_DIR, 'netview.log'))
server_log.touch(exist_ok=True)
try:
    server_log.chmod(0o666)
except Exception:
    pass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('netview-server')
handler = logging.FileHandler(os.path.join(LOG_DIR, 'netview.log'))
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


# ── identitas jaringan ─────────────────────────────────────────────
_GW_CACHE = {'t': 0, 'v': None}
_MY_CACHE = {}


def get_default_gw(use_cache=True):
    """Default gateway (ip, mac, iface). Di-cache 30 detik."""
    now = time.time()
    if use_cache and _GW_CACHE['v'] and (now - _GW_CACHE['t']) < 30:
        return _GW_CACHE['v']
    gw = dict()
    try:
        dg = netifaces.gateways()['default'][netifaces.AF_INET]
        gw_ip, iface = dg[0], dg[1]
        gw_mac = ''
        try:
            p = sp.Popen(['ip', 'neigh', 'show', gw_ip],
                         stdout=sp.PIPE, stderr=sp.PIPE)
            out, _ = p.communicate(timeout=5)
            for tok in out.decode('utf-8', 'ignore').split():
                if ':' in tok and len(tok) == 17:
                    gw_mac = tok
                    break
        except Exception:
            pass
        if not gw_mac:
            try:
                conf.verb = 0
                res, _ = sr(ARP(op=1, psrc='8.8.8.8', pdst=gw_ip),
                            iface=iface, timeout=1.5, verbose=0)
                for _, rcv in res:
                    if rcv.psrc == gw_ip:
                        gw_mac = rcv.hwsrc
            except Exception:
                pass
        gw['ip'] = gw_ip
        gw['mac'] = gw_mac
        gw['iface'] = iface
        _GW_CACHE['t'] = now
        _GW_CACHE['v'] = gw
    except Exception:
        logger.error(sys.exc_info()[1], exc_info=True)
    return gw


def get_my(iface, use_cache=True):
    """IP & MAC interface kita. Di-cache 30 detik."""
    now = time.time()
    cached = _MY_CACHE.get(iface)
    if use_cache and cached and (now - cached['t']) < 30:
        return cached['v']
    my = dict()
    try:
        my['ip'] = get_if_addr(iface)
        my['mac'] = get_if_hwaddr(iface)
        _MY_CACHE[iface] = {'t': now, 'v': my}
    except Exception:
        logger.error(sys.exc_info()[1], exc_info=True)
    return my


def get_hostname(ip):
    """Hostname via mDNS / NetBIOS / reverse DNS."""
    try:
        ans = sp.Popen(['avahi-resolve-host-name', '-a', ip],
                       stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = ans.communicate(timeout=3)
        if ans.returncode == 0 and out:
            parts = out.decode('utf-8').strip().split('\t')
            if len(parts) >= 2 and parts[1]:
                return parts[1].split('.')[0]
    except Exception:
        pass
    return ''


def get_vendor(mac):
    """Nama vendor dari MAC via database OUI."""
    if not mac:
        return ''
    prefix = mac.replace(':', '').replace('-', '').lower()[:6]
    for f in ('/usr/share/arp-scan/ieee-oui.txt',
              '/usr/share/arp-scan/ieee-iab.txt',
              '/usr/share/hwdata/oui.txt',
              '/var/lib/misc/oui.txt'):
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    if line.startswith('#') or not line.strip():
                        continue
                    parts = line.split('\t')
                    if parts and parts[0].strip().lower() == prefix:
                        return parts[1].strip() if len(parts) > 1 else ''
        except Exception:
            continue
    return ''


def is_random_mac(mac):
    """Deteksi MAC acak/privat (bit lokal set)."""
    try:
        first = int(mac.split(':')[0], 16)
        return bool(first & 0x02)
    except Exception:
        return False


def read_arp_table():
    """Baca ARP/neighbour table kernel: {ip: mac} (IPv4)."""
    table = {}
    try:
        p = sp.Popen(['ip', '-4', 'neigh', 'show'],
                     stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = p.communicate(timeout=5)
        for line in out.decode('utf-8', 'ignore').splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            ip = parts[0]
            if 'lladdr' in parts and 'FAILED' not in parts:
                table[ip] = parts[parts.index('lladdr') + 1]
    except Exception:
        pass
    return table


def get_ipv6_of(mac):
    """Alamat IPv6 untuk sebuah MAC dari neighbour table."""
    if not mac:
        return ''
    mac = mac.lower()
    try:
        p = sp.Popen(['ip', '-6', 'neigh', 'show'],
                     stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = p.communicate(timeout=5)
        found_global = ''
        found_ll = ''
        for line in out.decode('utf-8', 'ignore').splitlines():
            parts = line.split()
            if len(parts) < 3 or 'lladdr' not in parts:
                continue
            ip6 = parts[0]
            llmac = parts[parts.index('lladdr') + 1].lower()
            if llmac == mac:
                if ip6.startswith('fe80::'):
                    found_ll = found_ll or ip6
                else:
                    found_global = ip6
        return found_global or found_ll
    except Exception:
        return ''


def has_ipv6_route():
    """True kalau ada default route IPv6."""
    try:
        p = sp.Popen(['ip', '-6', 'route', 'show', 'default'],
                     stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = p.communicate(timeout=5)
        return bool(out.decode('utf-8', 'ignore').strip())
    except Exception:
        return False


def ping_sweep_parallel(ip_list, timeout=1):
    """Ping paralel untuk membangunkan host (untuk scan ARP)."""
    from concurrent.futures import ThreadPoolExecutor

    def _ping(ip):
        try:
            p = sp.Popen(['ping', '-c', '1', '-W', str(timeout), ip],
                         stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            p.wait(timeout=timeout + 2)
        except Exception:
            pass
    if ip_list:
        with ThreadPoolExecutor(max_workers=128) as pool:
            list(pool.map(_ping, ip_list))


def arp_scan_union(gw_ip, iface=None):
    """
    Scan ARP lengkap: kernel ARP table + ping sweep + arping 2 putaran.
    Return {ip: mac}.
    """
    from scapy.all import arping as _arping
    found = {}
    for ip, mac in read_arp_table().items():
        found[ip] = mac
    if iface is None:
        try:
            iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        except Exception:
            iface = 'wlan0'
    subnet = '{}/24'.format(gw_ip)
    try:
        base = gw_ip.rsplit('.', 1)[0]
        all_ips = ['{}.{}'.format(base, i) for i in range(1, 255)]
        ping_sweep_parallel(all_ips, timeout=0.3)
    except Exception:
        pass
    for to, retry in ((1.0, 0), (1.5, 1)):
        try:
            ans, unans = _arping(subnet, timeout=to, retry=retry,
                                 iface=iface, verbose=0)
            for snd, rcv in ans:
                if rcv.psrc and rcv.hwsrc:
                    found[rcv.psrc] = rcv.hwsrc
        except Exception:
            pass
    for ip, mac in read_arp_table().items():
        found[ip] = mac
    return found


def resolve_hostnames_bulk(ip_list):
    """Resolve hostname massal: mDNS paralel + satu nmap NetBIOS."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    result = {}
    pending = list(ip_list)

    def _mdns(ip):
        try:
            ans = sp.Popen(['avahi-resolve-host-name', '-a', ip],
                           stdout=sp.PIPE, stderr=sp.PIPE)
            out, _ = ans.communicate(timeout=1.5)
            if ans.returncode == 0 and out:
                parts = out.decode('utf-8').strip().split('\t')
                if len(parts) >= 2 and parts[1]:
                    return ip, parts[1].split('.')[0]
        except Exception:
            pass
        return ip, ''

    if pending:
        with ThreadPoolExecutor(max_workers=len(pending)) as pool:
            futs = [pool.submit(_mdns, ip) for ip in pending]
            for f in as_completed(futs, timeout=3):
                try:
                    ip, name = f.result()
                except Exception:
                    continue
                if name:
                    result[ip] = name

    remaining = [ip for ip in ip_list if ip not in result]
    if remaining:
        try:
            cmd = ['nmap', '-T4', '-p', '137,139,445',
                   '--script', 'nbstat,smb-os-discovery',
                   '--host-timeout', '5s', '--max-retries', '1'] + remaining
            ans = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE)
            out, _ = ans.communicate(timeout=15)
            text = out.decode('utf-8', 'ignore')
            cur = None
            for line in text.splitlines():
                line = line.strip()
                if line.startswith('Nmap scan report for'):
                    part = line.replace('Nmap scan report for', '').strip()
                    if '(' in part and ')' in part:
                        cur = part.split('(')[-1].rstrip(')').strip()
                        nm = part.split('(')[0].strip()
                        if nm and cur in remaining and cur not in result:
                            result[cur] = nm
                    else:
                        cur = part
                elif cur:
                    if 'NetBIOS name:' in line:
                        n = line.split('NetBIOS name:')[-1].split(',')[0].strip()
                        if n and cur not in result:
                            result[cur] = n
                    elif 'Computer name:' in line:
                        n = line.split('Computer name:')[-1].strip()
                        if n and cur not in result:
                            result[cur] = n
        except Exception:
            pass
    for ip in ip_list:
        result.setdefault(ip, '')
    return result


def _run(cmd, timeout=15):
    p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE)
    out, err = p.communicate(timeout=timeout)
    return p.returncode, out.decode('utf-8', 'ignore'), err.decode('utf-8', 'ignore')


def now():
    return time.time()
