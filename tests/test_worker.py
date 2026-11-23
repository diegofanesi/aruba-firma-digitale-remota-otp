"""Worker threads: the work runs off the GUI thread, every callback runs on it."""

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QObject, QThread  # noqa: E402

from firmaremota.gui import worker  # noqa: E402


def test_callbacks_run_on_the_gui_thread_whatever_their_kind(qtbot):
    """A lambda connected straight to a worker signal would run in the worker thread (PySide6)."""
    owner, gui, seen = QObject(), QThread.currentThread(), {}

    def work(progress):
        seen["work"] = QThread.currentThread()
        progress(1, 2, "a.pdf")
        return "fatto"

    job = worker.Worker(work)
    job.kwargs["progress"] = job.report
    worker.start(owner, job,
                 on_done=lambda result: seen.__setitem__("done", (result, QThread.currentThread())),
                 on_error=lambda exc: seen.__setitem__("error", exc),
                 on_progress=lambda d, t, n: seen.__setitem__("progress", (d, t, n, QThread.currentThread())))
    qtbot.waitUntil(lambda: "done" in seen, timeout=5000)
    assert seen["work"] is not gui
    assert seen["done"] == ("fatto", gui) and seen["progress"] == (1, 2, "a.pdf", gui)
    assert "error" not in seen


def test_errors_reach_the_gui_thread(qtbot):
    owner, gui, seen = QObject(), QThread.currentThread(), {}

    def boom():
        raise RuntimeError("guasto")

    worker.start(owner, worker.Worker(boom), on_done=lambda r: None,
                 on_error=lambda exc: seen.__setitem__("error", (str(exc), QThread.currentThread())))
    qtbot.waitUntil(lambda: "error" in seen, timeout=5000)
    assert seen["error"] == ("guasto", gui)
