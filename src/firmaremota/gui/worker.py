"""Run slow work (network, signing, verification) off the GUI thread."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QThread, Signal


class Worker(QObject):
    progress = Signal(int, int, str)
    done = Signal(object)
    failed = Signal(object)

    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs

    def report(self, done: int, total: int, name: str) -> None:
        """Progress callback for code running in the worker thread; Qt queues it to the GUI thread."""
        self.progress.emit(done, total, name)

    def run(self) -> None:
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as exc:  # delivered to the GUI thread, which decides what to show
            self.failed.emit(exc)
        else:
            self.done.emit(result)


def start(owner: QObject, worker: Worker, on_done: Callable, on_error: Callable,
          on_progress: Callable | None = None) -> QThread:
    thread = QThread(owner)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.done.connect(on_done)
    worker.failed.connect(on_error)
    if on_progress:
        worker.progress.connect(on_progress)
    worker.done.connect(thread.quit)
    worker.failed.connect(thread.quit)
    thread.finished.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)
    thread._worker = worker  # keep the worker alive as long as its thread
    thread.start()
    return thread
