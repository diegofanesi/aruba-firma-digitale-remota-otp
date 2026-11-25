"""Garbage collection and Qt objects: the crash of 2026-11-25 (saving an account a second time) and its fixes.

The flows run in a child process (tests/gui_gc_driver.py): a segfault there fails one test, not the run.
Both were checked to crash without their fix: "explicit" with the old worker.py, "automatic" with
--no-collector.
"""

import gc
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("mode", ["explicit", "automatic"])
def test_editing_accounts_repeatedly_with_garbage_collection_does_not_crash(tmp_path, mode):
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", HOME=str(tmp_path), XDG_STATE_HOME=str(tmp_path / "s"),
               XDG_CONFIG_HOME=str(tmp_path / "c"), XDG_CACHE_HOME=str(tmp_path / "k"),
               XDG_DATA_HOME=str(tmp_path / "d"), PYTHON_KEYRING_BACKEND="keyring.backends.fail.Keyring")
    result = subprocess.run([sys.executable, "-m", "tests.gui_gc_driver", mode, "4"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=180)
    assert result.returncode == 0 and "survived" in result.stdout, (
        f"exit {result.returncode} (-11/139 = segfault)\n{result.stderr[-3000:]}")


def test_collector_takes_over_from_automatic_collection(qapp, monkeypatch):
    from firmaremota.gui.collector import GuiThreadCollector

    collected = []
    monkeypatch.setattr(gc, "collect", lambda generation=2: collected.append(generation) or 0)
    monkeypatch.setattr(gc, "get_threshold", lambda: (700, 10, 10))
    try:
        collector = GuiThreadCollector()
        assert not gc.isenabled() and collector.timer.isActive()
        for counts, expected in (((10, 0, 0), None), ((701, 3, 0), 0), ((701, 11, 0), 1), ((701, 11, 11), 2)):
            monkeypatch.setattr(gc, "get_count", lambda c=counts: c)
            assert collector.check() == expected
        assert collected == [0, 1, 2]
        collector.timer.stop()
    finally:
        gc.enable()


def test_worker_relay_lets_go_of_its_callbacks(qapp):
    """A finished run must not keep the window that started it alive through its callbacks."""
    from PySide6.QtCore import QObject

    from firmaremota.gui.worker import _Relay

    seen, owner = [], QObject()
    relay = _Relay(owner, seen.append, seen.append, seen.append)
    relay.done("risultato")
    relay.error(RuntimeError("dopo la fine"))  # a late signal is ignored, never delivered to a stale callback
    assert seen == ["risultato"] and relay._done is relay._error is relay._progress is None
