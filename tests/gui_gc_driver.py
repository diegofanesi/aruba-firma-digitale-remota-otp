"""Run by test_gui_gc.py in a child process: a segfault there fails one test instead of killing the run.

Drives the flow that crashed on 2026-11-25 (PySide6 6.12): Impostazioni -> Modifica -> change the alias ->
"Controlla e salva", several times. The account check runs in a worker thread, and garbage collection
there used to free the previous edit dialog (marked as owned by Python after exec()) and its buttons from
that thread, so a button got deleted twice.

    python -m tests.gui_gc_driver explicit ROUNDS   the account check calls gc.collect() itself
    python -m tests.gui_gc_driver automatic ROUNDS  automatic collection only: before each round a
                                                    dialog like the crashing one is left alive by a
                                                    reference cycle; the account check drops its last
                                                    outside reference and allocates, so an automatic
                                                    collection would free it in the worker thread
    add --no-collector to run without the GUI-thread collector (to see the crash it prevents)

Prints "survived" at the end.
"""

from __future__ import annotations

import gc
import os
import sys


def main(mode: str, rounds: int, collector: bool = True) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    import keyring
    from keyring.backends import fail

    keyring.set_keyring(fail.Keyring())
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication, QDialog, QHBoxLayout, QPushButton, QVBoxLayout

    from firmaremota import credentials, service
    from firmaremota.gui.app import create_app
    from firmaremota.gui.collector import GuiThreadCollector
    from firmaremota.gui.dialogs import ProfileEditDialog, ProfilesDialog
    from firmaremota.gui.main_window import MainWindow

    from .conftest import MemoryStore, add_profile
    from .fakes import FakeArss

    store = MemoryStore()
    add_profile(store, "Papà", "mario.rossi@firma", "pw")
    add_profile(store, "Anna", "anna@firma", "pw")
    credentials.get_store = lambda: store
    real_prepare = service.prepare_account

    hazards = []

    def prepare(*args, **kwargs):  # runs in the worker thread
        if mode == "explicit":
            gc.collect()
        else:
            hazards.clear()  # the dialog is now garbage, held only by its own cycle
            for _ in range(200_000):  # enough allocation for automatic collections of every generation
                cycle = []
                cycle.append(cycle)
        return real_prepare(*args, **kwargs)

    service.prepare_account = prepare
    app = create_app([])
    if collector:
        GuiThreadCollector(app)
    window = MainWindow(lambda: FakeArss())
    window.show()

    class Hazard(QDialog):
        """Owned by Python after exec(), with a button added through a layout without a parent, and kept
        alive only by a reference cycle: what the edit dialog looked like when it crashed."""

        def __init__(self, parent):
            super().__init__(parent)
            layout = QVBoxLayout(self)
            row = QHBoxLayout()
            self.button = QPushButton("Annulla")
            row.addWidget(self.button)
            layout.addLayout(row)
            self.me = self

    def leave_hazard() -> None:
        dialog = Hazard(window)
        QTimer.singleShot(0, dialog.reject)
        dialog.exec()
        hazards.append(dialog)

    def modal():
        return QApplication.activeModalWidget()

    def drive_list(n):
        dialog = modal()
        if not isinstance(dialog, ProfilesDialog):
            QTimer.singleShot(20, lambda: drive_list(n))
            return
        dialog.list.setCurrentRow(0)
        QTimer.singleShot(20, lambda: drive_edit(n))
        dialog.edit_button.click()  # nested exec(): returns once the edit dialog is closed
        QTimer.singleShot(20, dialog.accept)

    def drive_edit(n):
        dialog = modal()
        if not isinstance(dialog, ProfileEditDialog):
            QTimer.singleShot(20, lambda: drive_edit(n))
            return
        dialog.alias.setText(f"Papà {n}")
        dialog.check.click()

    def run(n):
        if n >= rounds:
            print("survived", flush=True)
            app.quit()
            return
        if mode == "automatic":
            leave_hazard()
        QTimer.singleShot(20, lambda: drive_list(n))
        window.home.settings.click()  # modal ProfilesDialog
        QTimer.singleShot(50, lambda: run(n + 1))

    QTimer.singleShot(50, lambda: run(0))
    app.exec()


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]), collector="--no-collector" not in sys.argv)
