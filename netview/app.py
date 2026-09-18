"""
Entry point NetView (PyQt5).
"""
import sys
from PyQt5.QtWidgets import QApplication

from . import __appname__
from .main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(__appname__)
    try:
        win = MainWindow()
    except SystemExit:
        return 1
    win.show()
    return app.exec_()


if __name__ == '__main__':
    sys.exit(main())
