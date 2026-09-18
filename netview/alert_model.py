"""Model tabel alert NetView."""
from PyQt5.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt5.QtGui import QColor, QBrush

HEADERS = ['Waktu', 'Tingkat', 'Jenis', 'IP', 'MAC', 'Keterangan']

SEV_COLOR = {
    'critical': QColor(140, 30, 30),
    'warning': QColor(120, 95, 20),
    'info': QColor(40, 70, 110),
}


def _fmt_time(ts):
    import datetime
    try:
        return datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')
    except Exception:
        return ''


class AlertModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows = []

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
        a = self._rows[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return {
                0: _fmt_time(a.get('timestamp', 0)),
                1: a.get('severity', ''),
                2: a.get('kind', ''),
                3: a.get('ip', ''),
                4: a.get('mac', ''),
                5: a.get('message', ''),
            }.get(col, '')

        if role == Qt.BackgroundRole:
            c = SEV_COLOR.get(a.get('severity'))
            return QBrush(c) if c else None

        if role == Qt.ForegroundRole:
            return QBrush(QColor(240, 240, 240))

        if role == Qt.ToolTipRole:
            return a.get('message', '')

        return None

    def set_alerts(self, alerts):
        self.beginResetModel()
        self._rows = list(alerts)
        self.endResetModel()

    def alert_at(self, row):
        if 0 <= row < len(self._rows):
            return dict(self._rows[row])
        return None
