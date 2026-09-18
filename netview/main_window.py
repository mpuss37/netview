"""
Window utama NetView (PyQt5).

Tab:
  1. Hosts        - daftar host + status ancaman
  2. Alerts       - daftar kejadian/alert
  3. Live ARP     - log paket ARP real-time

Toolbar: Refresh, Scan, Monitor ON/OFF, Proteksi, Auto-Defense,
         Notifikasi (toggle), Clear Alerts, Pengaturan, Tema, Export, Exit
"""
import os
import json
import time
from pathlib import Path

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableView,
    QToolBar, QAction, QLabel, QMessageBox, QHeaderView, QApplication,
    QStyle, QAbstractItemView, QFileDialog, QCheckBox,
)

from . import api, theme
from .host_model import HostModel, COL_IP, COL_MAC
from .alert_model import AlertModel
from .dialogs import HostDetailDialog, DefenseDialog, AlertDetailDialog

APP_DIR = os.path.join(str(Path.home()), '.netview')
NOTIFY_PREF = os.path.join(APP_DIR, 'notify.conf')


class FetchWorker(QThread):
    done = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except api.ApiError as e:
            self.failed.emit(str(e))


class SimpleWorker(QThread):
    done = pyqtSignal(str, dict)
    failed = pyqtSignal(str, str)

    def __init__(self, kind, fn):
        super().__init__()
        self.kind = kind
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.kind, self.fn())
        except api.ApiError as e:
            self.failed.emit(self.kind, str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._theme = theme.load_pref()
        self._notify = self._load_notify_pref()
        self._workers = []
        self._seen_alert_keys = set()
        self._first_fetch = True

        os.makedirs(APP_DIR, exist_ok=True)

        self._build_ui()
        self._apply_theme(self._theme)

        if not api.is_up():
            QMessageBox.critical(
                self, 'Daemon tidak berjalan',
                'Daemon NetView tidak berjalan.\n'
                'Jalankan: sudo rc-service netviewd start\n'
                'lalu buka ulang aplikasi.')
            raise SystemExit(1)

        # timer refresh periodik
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()
        self._refresh_live()

        self._live_timer = QTimer(self)
        self._live_timer.setInterval(1500)
        self._live_timer.timeout.connect(self._refresh_live)
        self._live_timer.start()

    # ── UI ─────────────────────────────────────────────────────────
    def _build_ui(self):
        self.setWindowTitle('NetView')
        self.resize(980, 560)
        self.setWindowIcon(self._icon(QStyle.SP_ComputerIcon))

        central = QWidget()
        self.setCentralWidget(central)
        v = QVBoxLayout(central)

        # panel status atas
        top = QHBoxLayout()
        self.lbl_status = QLabel('Memuat...')
        top.addWidget(self.lbl_status)
        top.addStretch(1)
        self.lbl_threats = QLabel('')
        top.addWidget(self.lbl_threats)
        v.addLayout(top)

        # tabs
        self.tabs = QTabWidget()
        v.addWidget(self.tabs, 1)

        # --- tab hosts ---
        self.host_model = HostModel(self)
        self.host_view = QTableView()
        self.host_view.setModel(self.host_model)
        self.host_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.host_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.host_view.setAlternatingRowColors(True)
        self.host_view.verticalHeader().setVisible(False)
        self.host_view.horizontalHeader().setStretchLastSection(True)
        self.host_view.doubleClicked.connect(self._on_host_detail)
        self.tabs.addTab(self.host_view, 'Hosts')

        # --- tab alerts ---
        self.alert_model = AlertModel(self)
        self.alert_view = QTableView()
        self.alert_view.setModel(self.alert_model)
        self.alert_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.alert_view.verticalHeader().setVisible(False)
        self.alert_view.horizontalHeader().setStretchLastSection(True)
        self.alert_view.doubleClicked.connect(self._on_alert_detail)
        self.tabs.addTab(self.alert_view, 'Alerts')

        # --- tab live arp ---
        self.live_model = AlertModel(self)   # reuse model sederhana? pakai tabel teks
        from PyQt5.QtWidgets import QPlainTextEdit
        self.live_text = QPlainTextEdit()
        self.live_text.setReadOnly(True)
        self.tabs.addTab(self.live_text, 'Live ARP')

        self._build_toolbar()
        self.statusBar().showMessage('Siap')

    def _icon(self, sp):
        return QApplication.style().standardIcon(sp)

    def _build_toolbar(self):
        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)

        def act(sp, tip, slot, checkable=False):
            a = QAction(self._icon(sp), tip, self)
            a.setToolTip(tip)
            a.setCheckable(checkable)
            a.triggered.connect(slot)
            tb.addAction(a)
            return a

        self.act_refresh = act(QStyle.SP_BrowserReload, 'Refresh', self.refresh)
        self.act_scan = act(QStyle.SP_FileDialogContentsView, 'Scan sekarang',
                            self._on_scan)
        self.act_monitor = act(QStyle.SP_MediaPlay, 'Stop/Start monitoring',
                               self._on_toggle_monitor)
        tb.addSeparator()
        self.act_protect = act(QStyle.SP_MessageBoxCritical,
                               'Aktifkan proteksi device ini',
                               self._on_toggle_protect)
        self.act_auto = act(QStyle.SP_DialogApplyButton,
                            'Toggle auto-defense', self._on_toggle_auto)
        tb.addSeparator()
        self.act_notify = act(QStyle.SP_MessageBoxInformation,
                              'Notifikasi desktop saat ancaman',
                              self._on_toggle_notify)
        self.act_settings = act(QStyle.SP_FileDialogDetailedView,
                                'Pengaturan proteksi & whitelist',
                                self._on_settings)
        tb.addSeparator()
        self.act_clear = act(QStyle.SP_DialogResetButton, 'Bersihkan alerts',
                             self._on_clear_alerts)
        self.act_export = act(QStyle.SP_DialogSaveButton, 'Export log (JSON)',
                              self._on_export)
        tb.addSeparator()
        self.act_topology = act(QStyle.SP_ComputerIcon,
                                'Buka Topology View (browser)',
                                self._on_open_topology)
        tb.addSeparator()
        self.act_theme = act(QStyle.SP_DesktopIcon, 'Toggle tema', self._toggle_theme)
        self.act_exit = act(QStyle.SP_DialogCloseButton, 'Exit', self.close)

    # ── preferensi notifikasi ──────────────────────────────────────
    def _load_notify_pref(self):
        try:
            with open(NOTIFY_PREF) as f:
                return 'on' in f.read()
        except Exception:
            return False

    def _save_notify_pref(self):
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            with open(NOTIFY_PREF, 'w') as f:
                f.write('on' if self._notify else 'off')
        except Exception:
            pass

    # ── tema ───────────────────────────────────────────────────────
    def _apply_theme(self, name):
        self._theme = name
        QApplication.instance().setStyleSheet(theme.qss(name))
        theme.save_pref(name)

    def _toggle_theme(self):
        new = theme.LIGHT if self._theme == theme.DARK else theme.DARK
        self._apply_theme(new)
        self.statusBar().showMessage('Tema diubah', 2000)

    # ── refresh ────────────────────────────────────────────────────
    def refresh(self):
        w = FetchWorker(self._fetch_all)
        w.done.connect(self._on_data)
        w.failed.connect(self._on_fail)
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(w)
        w.start()

    def _fetch_all(self):
        return {
            'overview': api.overview(),
            'hosts': api.hosts(),
            'alerts': api.alerts(limit=200),
        }

    def _on_data(self, data):
        ov = data.get('overview', {})
        mon = ov.get('monitor', {})
        df = ov.get('defense', {})
        gw = ov.get('gateway', {})
        my = ov.get('my', {})

        # status bar atas
        state = 'ON' if mon.get('running') else 'OFF'
        self.lbl_status.setText(
            'Monitoring: {}  |  Host: {}  |  ARP: {}  |  Scan: {}  |  '
            'GW: {} ({})  |  Ini: {}'.format(
                state, mon.get('hosts', 0), mon.get('arp_count', 0),
                mon.get('scan_count', 0), gw.get('ip', '?'), gw.get('mac', '?'),
                my.get('ip', '?')))
        self.act_monitor.setChecked(bool(mon.get('running')))
        self.act_protect.setChecked(bool(df.get('enabled')))
        self.act_auto.setChecked(bool(df.get('auto_defense')))
        self.act_notify.setChecked(bool(self._notify))

        n_threat = ov.get('threats', 0)
        n_crit = ov.get('critical_alerts', 0)
        n_block = df.get('blocked_count', 0)
        self.lbl_threats.setText(
            'Ancaman: {}  |  Alert kritis: {}  |  Diblokir: {}'.format(
                n_threat, n_crit, n_block))

        self.host_model.set_hosts(data.get('hosts', []))
        alerts = data.get('alerts', [])
        self.alert_model.set_alerts(alerts)

        # notifikasi desktop untuk alert baru (opsional)
        self._check_new_alerts(alerts)

        self._first_fetch = False

    def _on_fail(self, err):
        self.statusBar().showMessage('Gagal: {}'.format(err))

    def _check_new_alerts(self, alerts):
        new_crit = []
        for a in alerts:
            key = '{}|{}|{}|{}'.format(a.get('kind'), a.get('ip'),
                                       a.get('mac'), int(a.get('timestamp', 0)))
            if key in self._seen_alert_keys:
                continue
            self._seen_alert_keys.add(key)
            if not self._first_fetch and a.get('severity') == 'critical':
                new_crit.append(a)
        # batasi memori set
        if len(self._seen_alert_keys) > 5000:
            self._seen_alert_keys = set(list(self._seen_alert_keys)[-2000:])

        if new_crit and self._notify:
            self._desktop_notify(new_crit)

    def _desktop_notify(self, alerts):
        try:
            from PyQt5.QtDBus import QDBusInterface, QDBusConnection
            iface = QDBusInterface('org.freedesktop.Notifications',
                                   '/org/freedesktop/Notifications',
                                   'org.freedesktop.Notifications',
                                   QDBusConnection.sessionBus())
            if iface.isValid():
                msg = alerts[0].get('message', 'Ancaman terdeteksi')
                iface.call('Notify', 'NetView', 0, '', 'NetView - Peringatan',
                           msg, [], {}, 8000)
                return
        except Exception:
            pass
        # fallback: status bar
        self.statusBar().showMessage(
            'PERINGATAN: {} ancaman kritis!'.format(len(alerts)), 8000)

    def _refresh_live(self):
        try:
            pkts = api.live_arp(limit=60)
        except api.ApiError:
            return
        lines = []
        for p in pkts:
            import datetime
            try:
                t = datetime.datetime.fromtimestamp(p['ts']).strftime('%H:%M:%S')
            except Exception:
                t = ''
            op = 'reply' if p.get('op') == 2 else 'request'
            arrow = '{} -> {}'.format(p.get('src_ip', ''), p.get('dst_ip', ''))
            lines.append('{}  [{}]  {}  {}  {}'.format(
                t, op, arrow, p.get('src_mac', ''), p.get('dst_mac', '')))
        self.live_text.setPlainText('\n'.join(lines))

    # ── aksi toolbar ───────────────────────────────────────────────
    def _on_scan(self):
        self.statusBar().showMessage('Scan ...')
        w = SimpleWorker('scan', lambda: api.scan_now())
        w.done.connect(lambda k, r: (self.refresh(),
                                     self.statusBar().showMessage(
                                         'Scan selesai: {} host'.format(
                                             r.get('hosts', 0)))))
        w.failed.connect(lambda k, e: self.statusBar().showMessage('Error: ' + e))
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(w)
        w.start()

    def _on_toggle_monitor(self):
        try:
            st = api.monitor_state()
            if st.get('running'):
                api.monitor_stop()
                self.statusBar().showMessage('Monitoring dimatikan')
            else:
                api.monitor_start()
                self.statusBar().showMessage('Monitoring dijalankan')
            self.refresh()
        except api.ApiError as e:
            QMessageBox.warning(self, 'Error', str(e))

    def _on_toggle_protect(self):
        try:
            st = api.defense_state()
            if st.get('enabled'):
                api.defense_disable()
                self.statusBar().showMessage('Proteksi dimatikan')
            else:
                res = api.defense_enable()
                if res.get('status') == 'success':
                    self.statusBar().showMessage('Proteksi aktif — device dilindungi')
                else:
                    QMessageBox.warning(self, 'Gagal', str(res.get('msg')))
            self.refresh()
        except api.ApiError as e:
            QMessageBox.warning(self, 'Error', str(e))

    def _on_toggle_auto(self):
        try:
            st = api.defense_state()
            on = not st.get('auto_defense')
            api.defense_auto(on)
            self.statusBar().showMessage(
                'Auto-defense {}'.format('AKTIF' if on else 'MATI'))
            self.refresh()
        except api.ApiError as e:
            QMessageBox.warning(self, 'Error', str(e))

    def _on_toggle_notify(self):
        self._notify = not self._notify
        self._save_notify_pref()
        self.act_notify.setChecked(self._notify)
        self.statusBar().showMessage(
            'Notifikasi desktop {}'.format('aktif' if self._notify else 'mati'))

    def _on_settings(self):
        try:
            st = api.defense_state()
        except api.ApiError as e:
            QMessageBox.warning(self, 'Error', str(e))
            return
        dlg = DefenseDialog(self, st)
        dlg.exec_()
        self.refresh()

    def _on_clear_alerts(self):
        try:
            api.alerts_clear()
            self._seen_alert_keys = set()
            self.refresh()
            self.statusBar().showMessage('Alerts dibersihkan')
        except api.ApiError as e:
            QMessageBox.warning(self, 'Error', str(e))

    def _on_export(self):
        try:
            data = api.export_log()
        except api.ApiError as e:
            QMessageBox.warning(self, 'Error', str(e))
            return
        path, _ = QFileDialog.getSaveFileName(
            self, 'Simpan log', os.path.join(APP_DIR, 'netview-export.json'),
            'JSON (*.json)')
        if path:
            try:
                with open(path, 'w') as f:
                    json.dump(data, f, indent=2)
                self.statusBar().showMessage('Log disimpan: {}'.format(path))
            except Exception as e:
                QMessageBox.warning(self, 'Gagal menyimpan', str(e))

    # ── Topology View (browser) ────────────────────────────────────
    def _on_open_topology(self):
        url = 'http://127.0.0.1:8015/tv'
        try:
            from PyQt5.QtGui import QDesktopServices
            from PyQt5.QtCore import QUrl
            QDesktopServices.openUrl(QUrl(url))
            self.statusBar().showMessage('Membuka Topology View: {}'.format(url))
        except Exception:
            # fallback: buka via xdg-open
            try:
                import subprocess as sp
                sp.Popen(['xdg-open', url])
            except Exception as e:
                QMessageBox.information(
                    self, 'Topology View',
                    'Buka di browser: {}\n({})'.format(url, e))

    # ── detail ─────────────────────────────────────────────────────
    def _on_host_detail(self):
        idx = self.host_view.currentIndex()
        if not idx.isValid():
            return
        host = self.host_model.host_at(idx.row())
        if host:
            HostDetailDialog(self, host).exec_()

    def _on_alert_detail(self):
        idx = self.alert_view.currentIndex()
        if not idx.isValid():
            return
        a = self.alert_model.alert_at(idx.row())
        if a:
            AlertDetailDialog(self, a).exec_()

    def closeEvent(self, event):
        event.accept()
