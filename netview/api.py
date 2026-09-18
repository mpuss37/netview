"""
Klien HTTP ke daemon NetView (127.0.0.1:8015).
"""
import requests

BASE = 'http://127.0.0.1:8015'


class ApiError(Exception):
    pass


def _get(path, timeout=10):
    try:
        r = requests.get(BASE + path, timeout=timeout)
    except requests.exceptions.RequestException as e:
        raise ApiError('Tidak bisa menghubungi daemon: {}'.format(e))
    try:
        return r.json()
    except ValueError:
        raise ApiError('Balasan daemon tidak valid')


def _post(path, payload=None, timeout=30):
    try:
        r = requests.post(BASE + path, json=payload or {}, timeout=timeout)
    except requests.exceptions.RequestException as e:
        raise ApiError('Tidak bisa menghubungi daemon: {}'.format(e))
    try:
        return r.json()
    except ValueError:
        raise ApiError('Balasan daemon tidak valid')


def is_up(timeout=3):
    try:
        return _get('/status', timeout=timeout).get('status') == 'success'
    except ApiError:
        return False


# ── info ───────────────────────────────────────────────────────────
def overview():
    return _get('/overview')


def get_gateway():
    d = _get('/gw')
    if d.get('status') != 'success':
        raise ApiError(d.get('msg', 'gateway tidak tersedia'))
    return d['gw']


def get_my(iface):
    d = _get('/my/{}'.format(iface))
    if d.get('status') != 'success':
        raise ApiError(d.get('msg', 'info device gagal'))
    return d['my']


# ── monitoring ─────────────────────────────────────────────────────
def monitor_start():
    return _post('/monitor/start')


def monitor_stop():
    return _post('/monitor/stop')


def monitor_state():
    return _get('/monitor/state').get('state', {})


def scan_now():
    return _post('/scan', timeout=90)


# ── data ───────────────────────────────────────────────────────────
def hosts():
    return _get('/hosts').get('hosts', [])


def live_arp(limit=100):
    return _get('/live-arp?limit={}'.format(limit)).get('packets', [])


def alerts(limit=200, severity=''):
    q = '/alerts?limit={}'.format(limit)
    if severity:
        q += '&severity={}'.format(severity)
    return _get(q).get('alerts', [])


def alerts_clear():
    return _post('/alerts/clear')


def export_log():
    return _get('/export', timeout=30)


# ── proteksi ───────────────────────────────────────────────────────
def defense_enable(host=None):
    return _post('/defense/enable', host or {})


def defense_disable():
    return _post('/defense/disable')


def defense_auto(on):
    return _post('/defense/auto', {'on': bool(on)})


def defense_state():
    return _get('/defense/state').get('state', {})


def defense_unblock():
    return _post('/defense/unblock')


# ── whitelist ──────────────────────────────────────────────────────
def whitelist_get():
    return _get('/whitelist')


def whitelist_set(macs, ips):
    return _post('/whitelist', {'macs': list(macs), 'ips': list(ips)})
