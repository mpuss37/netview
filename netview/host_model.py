"""
Model tabel host NetView.

Kolom: [Status-icon, IP, MAC, Hostname, Vendor, IPv6, Ancaman, AltMAC]
"""
from PyQt5.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt5.QtGui import QColor, QBrush
from PyQt5.QtWidgets import QApplication, QStyle

COL_ICON = 0
COL_IP = 1
COL_MAC = 2
COL_HOSTNAME = 3
COL_VENDOR = 4
COL_IPV6 = 5
COL_THREAT = 6
COL_ALT = 7

HEADERS = ['', 'IP Address', 'MAC Address', 'Hostname', 'Vendor', 'IPv6',
           'Ancaman', 'MAC lain']


class HostModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows = []
        self._ok_icon = None
        self._bad_icon = None
        self._warn_icon = None

    def _icons(self):
        if self._ok_icon is None:
            st = QApplication.style()
            self._ok_icon = st.standardIcon(QStyle.SP_DialogApplyButton)
            self._bad_icon = st.standardIcon(QStyle.SP_MessageBoxCritical)
            self._warn_icon = st.standardIcon(QStyle.SP_MessageBoxWarning)
        return self._ok_icon, self._bad_icon, self._warn_icon

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self._rows[index.row()]
        col = index.column()
        threat = r.get('threat', '')

        if role == Qt.DisplayRole:
            return {
                COL_ICON: '',
                COL_IP: r.get('ip', '') + (' (GW)' if r.get('is_gateway') else
                                           (' (INI)' if r.get('is_self') else '')),
                COL_MAC: r.get('mac', ''),
                COL_HOSTNAME: r.get('hostname', '') or '?',
                COL_VENDOR: r.get('vendor', '') or ('(MAC acak)' if r.get('random_mac') else ''),
                COL_IPV6: r.get('ipv6', '') or '',
                COL_THREAT: {'attacker': 'PENYERANG',
                             'suspicious': 'curiga',
                             'victim': 'KORBAN (diserang)'}
                            .get(threat, 'normal'),
                COL_ALT: ', '.join(r.get('alt_macs', [])) or '',
            }.get(col, '')

        if role == Qt.DecorationRole and col == COL_ICON:
            ok, bad, warn = self._icons()
            if threat == 'attacker':
                return bad
            if threat == 'victim':
                return warn
            if threat == 'suspicious':
                return warn
            return ok

        if role == Qt.BackgroundRole:
            if threat == 'attacker':
                return QBrush(QColor(120, 30, 30))
            if threat == 'victim':
                return QBrush(QColor(70, 60, 20))
            if threat == 'suspicious':
                return QBrush(QColor(110, 90, 20))
            return None

        if role == Qt.ForegroundRole:
            if threat:
                return QBrush(QColor(255, 255, 255))
            return None

        if role == Qt.TextAlignmentRole and col == COL_ICON:
            return int(Qt.AlignCenter)

        if role == Qt.ToolTipRole:
            return '{}\n{}\n{}'.format(r.get('ip', ''), r.get('mac', ''),
                                       r.get('vendor', ''))
        return None

    def set_hosts(self, hosts):
        self.beginResetModel()
        self._rows = list(hosts)
        self.endResetModel()

    def host_at(self, row):
        if 0 <= row < len(self._rows):
            return dict(self._rows[row])
        return None

    def all_hosts(self):
        return [dict(r) for r in self._rows]
