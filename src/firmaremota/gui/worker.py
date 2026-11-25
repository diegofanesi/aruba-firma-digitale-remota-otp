"""Run slow work (network, signing, verification) off the GUI thread."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot


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


class _Relay(QObject):
    """Lives in the GUI thread and forwards the worker's signals to plain Python callbacks there.

    Verified with PySide6 6.12: a lambda or plain function connected to a signal runs in the
    thread that *emits* it; only a slot of a QObject living in the GUI thread is queued back.
    Going through this object makes every callback a queued call on the GUI thread, whatever
    kind of callable the caller passed.
    """

    def __init__(self, parent: QObject, on_done: Callable, on_error: Callable, on_progress: Callable | None):
        super().__init__(parent)
        self._done, self._error, self._progress = on_done, on_error, on_progress

    def _release(self) -> None:
        """The run is over: let go of the callbacks. They usually capture the window or dialog that
        started the run, which holds this relay through its thread: a reference cycle that only the
        garbage collector could break, keeping a closed dialog alive until then."""
        self._done = self._error = self._progress = None

    @Slot(object)
    def done(self, result) -> None:
        callback = self._done
        self._release()
        if callback:
            callback(result)

    @Slot(object)
    def error(self, exc) -> None:
        callback = self._error
        self._release()
        if callback:
            callback(exc)

    @Slot(int, int, str)
    def progress(self, done: int, total: int, name: str) -> None:
        if self._progress:
            self._progress(done, total, name)


def start(owner: QObject, worker: Worker, on_done: Callable, on_error: Callable,
          on_progress: Callable | None = None) -> QThread:
    """Run `worker` on a new thread; the callbacks run on the GUI thread (the thread of `owner`).

    The owner holds Python references to the thread and the worker until the thread has finished:
    a QThread's Python wrapper can be garbage-collected while Qt keeps the thread running, and a
    worker freed that way would crash Qt. Finished pairs are released at the next start().
    """
    running = owner.__dict__.setdefault("_running_workers", [])
    running[:] = [(t, w) for t, w in running if not t.isFinished()]
    thread = QThread(owner)
    relay = _Relay(thread, on_done, on_error, on_progress)  # same thread affinity as its parent: the GUI thread
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    queued = Qt.ConnectionType.QueuedConnection
    worker.done.connect(relay.done, queued)
    worker.failed.connect(relay.error, queued)
    worker.progress.connect(relay.progress, queued)
    worker.done.connect(thread.quit)
    worker.failed.connect(thread.quit)
    running.append((thread, worker))
    thread.start()
    return thread
