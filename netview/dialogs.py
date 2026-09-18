"""Dialog-dialog NetView (PyQt5)."""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QPushButton,
    QCheckBox, QLineEdit, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QGroupBox,
)

from . import api


class HostDetailDialog(QDialog):
    """Detail satu host (info + MAC alternatif/threat)."""

    def __init__(self, parent, host):
        super().__init__(parent)
        self.setWindowTitle('Detail Host - {}'.format(host.get('ip', '')))
        self.setMinimumWidth(460)
        v = QVBoxLayout(self)

        form = QFormLayout()
        form.addRow('IP:', QLabel(host.get('ip', '-')))
        form.addRow('MAC:', QLabel(host.get('mac', '-')))
        form.addRow('Hostname:', QLabel(host.get('hostname') or '-'))
        form.addRow('Vendor:', QLabel(host.get('vendor') or '-'))
        form.addRow('IPv6:', QLabel(host.get('ipv6') or '-'))
        threat = host.get('threat', '')
        form.addRow('Status:', QLabel(threat or 'normal'))
        if host.get('is_gateway'):
            form.addRow('Peran:', QLabel('GATEWAY'))
        if host.get('is_self'):
            form.addRow('Peran:', QLabel('PERANGKAT INI'))
        v.addLayout(form)

        alt = host.get('alt_macs', [])
        if alt:
            v.addWidget(QLabel('MAC lain yang mengklaim IP ini '
                               '(indikasi spoof):'))
            tw = QTableWidget(len(alt), 1)
            tw.setHorizontalHeaderLabels(['MAC'])
            tw.horizontalHeader().setStretchLastSection(True)
            for i, m in enumerate(alt):
                tw.setItem(i, 0, QTableWidgetItem(m))
            v.addWidget(tw)

        h = QHBoxLayout()
        h.addStretch(1)
        btn = QPushButton('Tutup')
        btn.clicked.connect(self.accept)
        h.addWidget(btn)
        v.addLayout(h)


class DefenseDialog(QDialog):
    """Pengaturan proteksi & auto-defense, plus whitelist."""

    def __init__(self, parent, state):
        super().__init__(parent)
        self.setWindowTitle('Pengaturan Proteksi')
        self.setMinimumWidth(520)
        v = QVBoxLayout(self)

        # ---- proteksi ----
        g1 = QGroupBox('Proteksi device ini (ARP hardening)')
        f1 = QVBoxLayout(g1)
        self.cb_protect = QCheckBox('Aktifkan proteksi (kunci ARP gateway + arptables)')
        self.cb_protect.setChecked(bool(state.get('enabled')))
        f1.addWidget(self.cb_protect)
        self.cb_auto = QCheckBox('Auto-defense (blokir penyerang saat terdeteksi)')
        self.cb_auto.setChecked(bool(state.get('auto_defense')))
        f1.addWidget(self.cb_auto)
        info = QLabel('Gateway: {} ({})'.format(
            state.get('gw_ip', '?'), state.get('gw_mac', '?')))
        f1.addWidget(info)
        v.addWidget(g1)

        # ---- daftar blokir ----
        blocked = state.get('blocked', [])
        g2 = QGroupBox('MAC yang diblokir ({})'.format(len(blocked)))
        f2 = QVBoxLayout(g2)
        self._blocked = blocked
        if blocked:
            tw = QTableWidget(len(blocked), 1)
            tw.setHorizontalHeaderLabels(['MAC'])
            tw.horizontalHeader().setStretchLastSection(True)
            for i, m in enumerate(blocked):
                tw.setItem(i, 0, QTableWidgetItem(m))
            f2.addWidget(tw)
            b_unblock = QPushButton('Buka Semua Blokir')
            b_unblock.clicked.connect(self._unblock_all)
            f2.addWidget(b_unblock)
        else:
            f2.addWidget(QLabel('(tidak ada)'))
        v.addWidget(g2)

        # ---- whitelist ----
        g3 = QGroupBox('Whitelist (abaikan dari deteksi)')
        form3 = QFormLayout(g3)
        self.wl_macs = QLineEdit()
        self.wl_ips = QLineEdit()
        form3.addRow('MAC (pisah koma):', self.wl_macs)
        form3.addRow('IP (pisah koma):', self.wl_ips)
        v.addWidget(g3)

        # tombol
        h = QHBoxLayout()
        b_apply = QPushButton('Terapkan')
        b_close = QPushButton('Tutup')
        h.addStretch(1)
        h.addWidget(b_apply)
        h.addWidget(b_close)
        v.addLayout(h)
        b_apply.clicked.connect(self._apply)
        b_close.clicked.connect(self.reject)

        self._load_whitelist()

    def _load_whitelist(self):
        try:
            d = api.whitelist_get()
            self.wl_macs.setText(','.join(d.get('macs', [])))
            self.wl_ips.setText(','.join(d.get('ips', [])))
        except api.ApiError:
            pass

    def _unblock_all(self):
        try:
            api.defense_unblock()
            QMessageBox.information(self, 'OK', 'Semua blokir dibuka.')
        except api.ApiError as e:
            QMessageBox.warning(self, 'Error', str(e))

    def _apply(self):
        try:
            # proteksi on/off
            if self.cb_protect.isChecked():
                res = api.defense_enable()
                if res.get('status') != 'success':
                    QMessageBox.warning(self, 'Gagal', str(res.get('msg')))
            else:
                api.defense_disable()
            # auto-defense
            api.defense_auto(self.cb_auto.isChecked())
            # whitelist
            macs = [m.strip() for m in self.wl_macs.text().split(',') if m.strip()]
            ips = [i.strip() for i in self.wl_ips.text().split(',') if i.strip()]
            api.whitelist_set(macs, ips)
            QMessageBox.information(self, 'OK', 'Pengaturan diterapkan.')
            self.accept()
        except api.ApiError as e:
            QMessageBox.warning(self, 'Error', str(e))


class AlertDetailDialog(QDialog):
    """Detail satu alert."""

    def __init__(self, parent, alert):
        super().__init__(parent)
        self.setWindowTitle('Detail Alert')
        self.setMinimumWidth(520)
        v = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow('Jenis:', QLabel(alert.get('kind', '-')))
        form.addRow('Tingkat:', QLabel(alert.get('severity', '-')))
        form.addRow('IP:', QLabel(alert.get('ip') or '-'))
        form.addRow('MAC:', QLabel(alert.get('mac') or '-'))
        v.addLayout(form)
        msg = QLabel(alert.get('message', ''))
        msg.setWordWrap(True)
        v.addWidget(msg)
        h = QHBoxLayout()
        h.addStretch(1)
        b = QPushButton('Tutup')
        b.clicked.connect(self.accept)
        h.addWidget(b)
        v.addLayout(h)
