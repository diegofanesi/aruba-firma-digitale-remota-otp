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
    """Run `worker` on a new thread; its signals are delivered on the GUI thread.

    The owner holds Python references to the thread and the worker until the thread has finished:
    a QThread's Python wrapper can be garbage-collected while Qt keeps the thread running, and a
    worker freed that way would crash Qt. Finished pairs are released at the next start().
    """
    running = owner.__dict__.setdefault("_running_workers", [])
    running[:] = [(t, w) for t, w in running if not t.isFinished()]
    thread = QThread(owner)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.done.connect(on_done)
    worker.failed.connect(on_error)
    if on_progress:
        worker.progress.connect(on_progress)
    worker.done.connect(thread.quit)
    worker.failed.connect(thread.quit)
    running.append((thread, worker))
    thread.start()
    return thread
