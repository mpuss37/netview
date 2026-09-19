"""
NetView daemon - server HTTP lokal (bottle + waitress) di port 8015.

Menyediakan API untuk GUI: monitoring, daftar host, alert, proteksi.
Tidak melakukan spoofing apa pun (murni defensif).
"""
import sys
import os
import json
import fcntl
import atexit
import time
from setproctitle import setproctitle
from bottle import (route, run, app as _bottle_app, request, response,
                    static_file, HTTPResponse)

from utils import logger, get_default_gw, get_my
from monitor import get_monitor
from defense import get_defense

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')

# ── single-instance guard ──────────────────────────────────────────
_LOCK_FILE = '/run/netview-server.lock'
_lock_fd = None


def _acquire_lock():
    global _lock_fd
    _lock_fd = open(_LOCK_FILE, 'w')
    try:
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_fd.write(str(os.getpid()))
        _lock_fd.flush()
    except OSError:
        print('ERROR: another netview-server is already running.',
              file=sys.stderr)
        sys.exit(1)


_acquire_lock()
setproctitle('netview-server')

monitor = get_monitor()
defense = get_defense()

# sambungkan monitor -> auto-defense
def _on_alerts(alerts):
    try:
        defense.handle_alerts(alerts)
    except Exception as e:
        logger.error('auto-defense cb err: {}'.format(e))

monitor.on_alerts = _on_alerts

_last_config = {'config_path': os.path.join(
    os.path.expanduser('~'), '.netview', 'netview.conf')}


# ── util json ──────────────────────────────────────────────────────
def jresp(obj):
    response.headers['Content-Type'] = 'application/json'
    return json.dumps(obj)


# ── status & info ──────────────────────────────────────────────────
@route('/status')
def server_status():
    return jresp({'status': 'success', 'msg': 'NetView server is running'})


@route('/gw')
def get_gw():
    gw = get_default_gw()
    if gw and gw.get('ip'):
        return jresp({'status': 'success', 'gw': gw})
    return jresp({'status': 'error', 'msg': 'gateway tidak tersedia'})


@route('/my/<iface>')
def get_my_info(iface):
    my = get_my(iface)
    return jresp({'status': 'success', 'my': my})


@route('/overview')
def overview():
    """Ringkasan untuk panel atas GUI."""
    st = monitor.state()
    df = defense.state()
    threats = monitor.detector.threat_map()
    crit = sum(1 for a in monitor.detector.alerts(limit=500)
               if a.get('severity') == 'critical')
    return jresp({
        'status': 'success',
        'monitor': st,
        'defense': {
            'enabled': df['enabled'],
            'auto_defense': df['auto_defense'],
            'blocked_count': df['blocked_count'],
        },
        'gateway': monitor.gw,
        'my': monitor.my,
        'threats': len(threats),
        'critical_alerts': crit,
    })


# ── monitoring ─────────────────────────────────────────────────────
@route('/monitor/start', method='POST')
def monitor_start():
    data = request.json or {}
    monitor.start(iface=data.get('iface'))
    return jresp({'status': 'success', 'state': monitor.state()})


@route('/monitor/stop', method='POST')
def monitor_stop():
    monitor.stop()
    return jresp({'status': 'success', 'state': monitor.state()})


@route('/monitor/state')
def monitor_state():
    return jresp({'status': 'success', 'state': monitor.state()})


@route('/scan', method='POST')
def scan_now():
    # trigger scan langsung (dijalankan sinkron, cepat)
    try:
        monitor._do_scan(initial=not monitor.baseline_ready)
    except Exception as e:
        return jresp({'status': 'error', 'msg': str(e)})
    return jresp({'status': 'success',
                  'hosts': len(monitor.hosts_list())})


# ── hosts ──────────────────────────────────────────────────────────
@route('/hosts')
def hosts():
    return jresp({'status': 'success', 'hosts': monitor.hosts_list()})


@route('/live-arp')
def live_arp():
    limit = int(request.query.get('limit', 100) or 100)
    return jresp({'status': 'success', 'packets': monitor.live_arp(limit)})


# ── alerts ─────────────────────────────────────────────────────────
@route('/alerts')
def alerts():
    limit = int(request.query.get('limit', 200) or 200)
    sev = request.query.get('severity') or ''
    items = monitor.detector.alerts(limit=limit)
    if sev:
        items = [a for a in items if a.get('severity') == sev]
    return jresp({'status': 'success', 'alerts': items})


@route('/alerts/clear', method='POST')
def alerts_clear():
    monitor.detector.clear_alerts()
    return jresp({'status': 'success', 'msg': 'alerts dibersihkan'})


@route('/export')
def export_log():
    """Export seluruh log (host + alert + defense) sebagai JSON."""
    return jresp({
        'status': 'success',
        'exported_at': time.time(),
        'hosts': monitor.hosts_list(),
        'alerts': monitor.detector.alerts(limit=5000),
        'defense': defense.state(),
        'monitor': monitor.state(),
    })


# ── proteksi ───────────────────────────────────────────────────────
@route('/defense/enable', method='POST')
def defense_enable():
    data = request.json or {}
    ok, msg = defense.enable(gw_ip=data.get('ip'), gw_mac=data.get('mac'),
                             iface=data.get('iface'))
    return jresp({'status': 'success' if ok else 'error', 'msg': msg,
                  'state': defense.state()})


@route('/defense/disable', method='POST')
def defense_disable():
    ok, msg = defense.disable()
    return jresp({'status': 'success' if ok else 'error', 'msg': msg,
                  'state': defense.state()})


@route('/defense/auto', method='POST')
def defense_auto():
    data = request.json or {}
    on = bool(data.get('on'))
    defense.set_auto(on)
    return jresp({'status': 'success', 'auto_defense': on,
                  'state': defense.state()})


@route('/defense/state')
def defense_state():
    return jresp({'status': 'success', 'state': defense.state()})


@route('/defense/unblock', method='POST')
def defense_unblock():
    defense.unblock_all()
    return jresp({'status': 'success', 'state': defense.state()})


# ── whitelist ──────────────────────────────────────────────────────
_whitelist_file = os.path.join(os.path.expanduser('~'), '.netview',
                               'whitelist.json')


def _load_whitelist():
    try:
        with open(_whitelist_file) as f:
            d = json.load(f)
            return set(m.lower() for m in d.get('macs', [])), set(d.get('ips', []))
    except Exception:
        return set(), set()


def _save_whitelist(macs, ips):
    try:
        os.makedirs(os.path.dirname(_whitelist_file), exist_ok=True)
        with open(_whitelist_file, 'w') as f:
            json.dump({'macs': sorted(macs), 'ips': sorted(ips)}, f)
    except Exception:
        pass


@route('/whitelist')
def whitelist_get():
    macs, ips = _load_whitelist()
    return jresp({'status': 'success', 'macs': sorted(macs),
                  'ips': sorted(ips)})


@route('/whitelist', method='POST')
def whitelist_set():
    data = request.json or {}
    macs = set(m.lower() for m in data.get('macs', []))
    ips = set(data.get('ips', []))
    _save_whitelist(macs, ips)
    monitor.detector.set_whitelist(macs, ips)
    return jresp({'status': 'success', 'macs': sorted(macs),
                  'ips': sorted(ips)})


# ── config (tema dll ditangani GUI; ini info path) ─────────────────
@route('/ping')
def ping():
    return jresp({'status': 'success', 'msg': 'pong'})


# ── Topology View (browser) ────────────────────────────────────────
@route('/topology')
def topology():
    """Data graf jaringan untuk Topology View.

    Query ?mode=radial | cluster memilih algoritma tata letak.
    """
    mode = request.query.get('mode') or None
    if mode:
        mode = mode.lower()
        if mode in ('radial', 'cluster'):
            monitor.layout_mode = mode
    return jresp({'status': 'success', 'topology': monitor.topology(mode)})


@route('/tv')
def tv_index():
    """Halaman Topology View (browser)."""
    return static_file('index.html', root=WEB_DIR)


@route('/tv/<filename:path>')
def tv_static(filename):
    """Aset statis Topology View (css/js)."""
    return static_file(filename, root=WEB_DIR)


# ── shutdown bersih ────────────────────────────────────────────────
def on_exit():
    logger.info('NetView server stopped')
    try:
        monitor.stop()
    except Exception:
        pass
    try:
        defense.disable()
    except Exception:
        pass
    try:
        if _lock_fd:
            fcntl.flock(_lock_fd, fcntl.LOCK_UN)
            _lock_fd.close()
        os.remove(_LOCK_FILE)
    except Exception:
        pass


atexit.register(on_exit)


if __name__ == '__main__':
    logger.info('NetView server starting ...')
    # muat whitelist
    macs, ips = _load_whitelist()
    monitor.detector.set_whitelist(macs, ips)
    # auto-start monitoring
    try:
        monitor.start()
    except Exception as e:
        logger.error('auto-start monitor gagal: {}'.format(e))
    try:
        import waitress
        waitress.serve(_bottle_app(), host='127.0.0.1', port=8015, threads=12)
    except ImportError:
        run(host='127.0.0.1', port=8015, reloader=False)
    logger.info('NetView server successfully started')
