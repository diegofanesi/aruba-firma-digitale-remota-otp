"""Entry point of the graphical interface: `firma-gui [FILE...]` or `firma gui`."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from .. import logsetup, vault
from .main_window import MainWindow

log = logging.getLogger("firmaremota.gui")
ICON = Path(__file__).with_name("firma-remota.svg")
STYLE = """
QLabel#title { font-size: 26pt; font-weight: bold; }
QLabel#subtitle { font-size: 18pt; }
QLabel#hint { color: palette(placeholder-text); margin-left: 4px; }
QLabel#drop { border: 2px dashed palette(mid); border-radius: 10px; padding: 18px; color: palette(placeholder-text); }
QPushButton#big { font-size: 18pt; padding: 14px 24px; }
QCheckBox#bigcheck { font-size: 16pt; padding: 8px 0; }
QListWidget { font-size: 13pt; }
QRadioButton::indicator, QCheckBox::indicator { width: 24px; height: 24px; }
QRadioButton, QCheckBox { spacing: 10px; }
"""


def make_api():
    from ..arss.client import ArssClient

    return ArssClient()


def _install_excepthook(window: MainWindow) -> None:
    def handler(kind, value, tb):
        log.critical("errore non gestito", exc_info=(kind, value, tb))
        QMessageBox.critical(window, "Errore imprevisto",
                             f"Si è verificato un errore imprevisto.\nI dettagli sono nel registro:\n{logsetup.log_path()}")

    sys.excepthook = handler


def create_app(argv: list[str]) -> QApplication:
    app = QApplication.instance() or QApplication(argv)
    app.setApplicationName("Firma remota")
    app.setDesktopFileName("firma-remota")  # Wayland: match the .desktop file (icon, grouping)
    app.setStyle("Fusion")
    font = app.font()
    font.setPointSize(14)
    app.setFont(font)
    app.setStyleSheet(STYLE)
    app.setWindowIcon(QIcon(str(ICON)))
    return app


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    smoke_test = "--prova-avvio" in args
    paths = [a for a in args if not a.startswith("--")]
    try:
        logsetup.setup()
    except OSError:
        pass
    try:
        vault.migrate_legacy()  # older versions kept account data in plain text
    except Exception as exc:
        log.warning("migrazione del profilo non riuscita: %s", exc)
    app = create_app(sys.argv[:1])
    window = MainWindow(make_api)
    _install_excepthook(window)
    window.resize(1100, 740)
    window.show()
    if paths:
        QTimer.singleShot(0, lambda: window.open_paths(paths))
    if smoke_test:  # installer check: the window could be built and shown
        QTimer.singleShot(800, app.quit)
    code = app.exec()
    if smoke_test:
        print("ok: interfaccia grafica avviata")
    return code
