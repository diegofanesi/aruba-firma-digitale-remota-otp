"""Python's cyclic garbage collector, run only in the GUI thread.

Left automatic, the collector runs in whichever thread happens to be allocating, often a worker thread
(zeep, requests and pyHanko allocate a lot during an account check or a signing). The Qt objects it frees
there are not deleted on the spot: PySide queues their deletion for the GUI thread. With PySide6 6.12 that
queued path can delete a widget twice: after QDialog.exec() a dialog is marked as owned by Python, and so
are buttons added through a layout without a parent; if both are freed from a worker thread, deleting the
dialog deletes the button, and then the queued deletion of the button frees it again (a segfault; it
happened when saving an account a second time). Collected in the GUI thread, Qt objects are deleted at
once and in order, so nothing is left queued.
"""

from __future__ import annotations

import gc

from PySide6.QtCore import QObject, QTimer


class GuiThreadCollector(QObject):
    """Turns automatic collection off and runs it from a timer in the GUI thread instead, with the same
    escalation the automatic collector uses (young objects often, older generations rarely)."""

    INTERVAL_MS = 500

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        gc.disable()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check)
        self.timer.start(self.INTERVAL_MS)

    def check(self) -> int | None:
        """Collect if the automatic collector would have by now; returns the generation collected."""
        young, middle, old = gc.get_count()
        threshold0, threshold1, threshold2 = gc.get_threshold()
        if young <= threshold0:
            return None
        generation = 2 if old > threshold2 else 1 if middle > threshold1 else 0
        gc.collect(generation)
        return generation
