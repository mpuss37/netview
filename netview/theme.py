"""
Tema NetControl: stylesheet gelap & terang + helper apply/load/save.

Pilihan tema disimpan di ~/.netview/netview.conf supaya tetap
tersimpan saat aplikasi dibuka ulang.
"""
import os
from pathlib import Path

CONFIG_DIR = os.path.join(str(Path.home()), '.netview')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'netview.conf')

DARK = 'dark'
LIGHT = 'light'


DARK_QSS = """
* { font-size: 13px; }
QWidget { background-color: #1e1f22; color: #e6e6e6; }
QMainWindow, QDialog { background-color: #1e1f22; }
QToolBar { background-color: #2b2d31; border: none; padding: 4px; spacing: 4px; }
QToolButton { background: transparent; padding: 5px; border-radius: 6px; color: #e6e6e6; }
QToolButton:hover { background-color: #3a3d42; }
QToolButton:pressed { background-color: #4a4e54; }
QToolButton:checked { background-color: #3d6ea8; }
QStatusBar { background-color: #2b2d31; color: #cfcfcf; }
QTableView {
    background-color: #232428; alternate-background-color: #26272b;
    color: #e6e6e6; gridline-color: #3a3d42;
    selection-background-color: #3d6ea8; selection-color: #ffffff;
    border: 1px solid #3a3d42; border-radius: 6px;
}
QHeaderView::section {
    background-color: #2b2d31; color: #e6e6e6; padding: 6px;
    border: none; border-right: 1px solid #3a3d42; border-bottom: 1px solid #3a3d42;
    font-weight: bold;
}
QTableCornerButton::section { background-color: #2b2d31; border: none; }
QLineEdit, QComboBox, QSpinBox {
    background-color: #2b2d31; color: #e6e6e6;
    border: 1px solid #3a3d42; border-radius: 5px; padding: 4px 6px;
}
QComboBox QAbstractItemView { background-color: #2b2d31; color: #e6e6e6; selection-background-color: #3d6ea8; }
QPushButton {
    background-color: #3a3d42; color: #e6e6e6;
    border: 1px solid #4a4e54; border-radius: 5px; padding: 6px 14px;
}
QPushButton:hover { background-color: #4a4e54; }
QPushButton:pressed { background-color: #3d6ea8; }
QPushButton:disabled { color: #777; background-color: #2b2d31; }
QCheckBox { color: #e6e6e6; spacing: 6px; }
QScrollBar:vertical { background: #232428; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #4a4e54; border-radius: 6px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: #5a5e64; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QScrollBar:horizontal { background: #232428; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: #4a4e54; border-radius: 6px; min-width: 24px; }
QLabel { color: #e6e6e6; }
QMenuBar { background-color: #2b2d31; color: #e6e6e6; }
QMenuBar::item:selected { background-color: #3a3d42; }
QMenu { background-color: #2b2d31; color: #e6e6e6; border: 1px solid #3a3d42; }
QMenu::item:selected { background-color: #3d6ea8; }
"""


LIGHT_QSS = """
* { font-size: 13px; }
QWidget { background-color: #f4f5f7; color: #1f2328; }
QMainWindow, QDialog { background-color: #f4f5f7; }
QToolBar { background-color: #ffffff; border: none; padding: 4px; spacing: 4px; }
QToolButton { background: transparent; padding: 5px; border-radius: 6px; color: #1f2328; }
QToolButton:hover { background-color: #e6e8eb; }
QToolButton:pressed { background-color: #d5d8dc; }
QToolButton:checked { background-color: #bcd4f6; }
QStatusBar { background-color: #ffffff; color: #444; }
QTableView {
    background-color: #ffffff; alternate-background-color: #f7f8fa;
    color: #1f2328; gridline-color: #dfe1e4;
    selection-background-color: #bcd4f6; selection-color: #10233f;
    border: 1px solid #dfe1e4; border-radius: 6px;
}
QHeaderView::section {
    background-color: #eef0f3; color: #1f2328; padding: 6px;
    border: none; border-right: 1px solid #dfe1e4; border-bottom: 1px solid #dfe1e4;
    font-weight: bold;
}
QTableCornerButton::section { background-color: #eef0f3; border: none; }
QLineEdit, QComboBox, QSpinBox {
    background-color: #ffffff; color: #1f2328;
    border: 1px solid #cfd3d8; border-radius: 5px; padding: 4px 6px;
}
QComboBox QAbstractItemView { background-color: #ffffff; color: #1f2328; selection-background-color: #bcd4f6; }
QPushButton {
    background-color: #ffffff; color: #1f2328;
    border: 1px solid #cfd3d8; border-radius: 5px; padding: 6px 14px;
}
QPushButton:hover { background-color: #eef0f3; }
QPushButton:pressed { background-color: #bcd4f6; }
QPushButton:disabled { color: #999; background-color: #f0f1f3; }
QCheckBox { color: #1f2328; spacing: 6px; }
QScrollBar:vertical { background: #eef0f3; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #c3c7cc; border-radius: 6px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: #a9aeb4; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QScrollBar:horizontal { background: #eef0f3; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: #c3c7cc; border-radius: 6px; min-width: 24px; }
QLabel { color: #1f2328; }
QMenuBar { background-color: #ffffff; color: #1f2328; }
QMenuBar::item:selected { background-color: #e6e8eb; }
QMenu { background-color: #ffffff; color: #1f2328; border: 1px solid #cfd3d8; }
QMenu::item:selected { background-color: #bcd4f6; }
"""

STYLES = {DARK: DARK_QSS, LIGHT: LIGHT_QSS}


def qss(name):
    return STYLES.get(name, DARK_QSS)


def load_pref():
    """Baca preferensi tema; default gelap."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                if line.startswith('theme='):
                    v = line.strip().split('=', 1)[1]
                    if v in (DARK, LIGHT):
                        return v
    except Exception:
        pass
    return DARK


def save_pref(name):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            f.write('theme={}\n'.format(name))
    except Exception:
        pass
