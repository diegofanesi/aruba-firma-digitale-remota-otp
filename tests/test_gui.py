"""The graphical interface, driven with pytest-qt (offscreen) against a fake Aruba service."""

import os
import subprocess
import sys

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QMimeData, QPointF, Qt, QUrl  # noqa: E402
from PySide6.QtGui import QDropEvent  # noqa: E402
from PySide6.QtWidgets import QDialog  # noqa: E402

from firmaremota import config, credentials, verify  # noqa: E402
from firmaremota.arss.client import MSG_OTP  # noqa: E402
from firmaremota.errors import CredentialsError, OtpError, ServiceError  # noqa: E402
from firmaremota.gui.dialogs import OtpDialog, SetupDialog  # noqa: E402
from firmaremota.gui.main_window import MainWindow  # noqa: E402
from firmaremota.models import Kind, Position  # noqa: E402

from .fakes import FakeArss, signer_info  # noqa: E402
from .test_cli_setup import MemoryStore  # noqa: E402
from .test_verify import PDF, RootsTrust  # noqa: E402

A4 = (595, 842, 0, None)
KEY = "mario.rossi@firma"


class Recorder:
    def __init__(self, result=None):
        self.calls, self.result = [], result

    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        return self.result


@pytest.fixture
def store(monkeypatch):
    memory = MemoryStore({KEY: "pw-salvata"})
    monkeypatch.setattr(credentials, "get_store", lambda: memory)
    return memory


@pytest.fixture
def api(make_p7m):
    return FakeArss(make_p7m=make_p7m, certs=[("NEW_2025:abc-AS0", signer_info("Mario Rossi"))])


@pytest.fixture
def window(qtbot, store, api):
    config.save(config.Settings(user="mario.rossi", domain="firma", cert_id="NEW_2025:abc-AS0", signer_name="Mario Rossi"))
    w = MainWindow(lambda: api)
    qtbot.addWidget(w)
    w.ask_otp = Recorder("12345678")
    w.show_error = Recorder()
    w.open_url = Recorder()
    w.ask_password = Recorder(None)
    return w


def wait_for(qtbot, window, page):
    qtbot.waitUntil(lambda: window.stack.currentWidget() is page, timeout=10000)
    qtbot.wait(50)  # let the worker thread finish quitting


def pdfs(folder, make_pdf, *names):
    paths = []
    for name in names:
        path = folder / name
        path.write_bytes(make_pdf(A4))
        paths.append(str(path))
    return paths


def test_sign_pdf_with_stamp(window, api, qtbot, tmp_path, make_pdf):
    window.choose_files = Recorder(pdfs(tmp_path, make_pdf, "a.pdf", "b.pdf"))
    window.home.sign_pdf.click()
    assert window.stack.currentWidget() is window.options
    window.options.stamp.setChecked(True)
    window.options.corner_buttons[Position.TOP_LEFT].setChecked(True)
    window.options.text.setText("Visto")
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.result.title.text() == "Fatto! 2 documenti firmati."
    assert (tmp_path / "a_firmato.pdf").exists() and (tmp_path / "b_firmato.pdf").exists()
    assert window.ask_otp.calls == [(2, 0)]
    assert api.names().count("open_session") == 1
    assert api.calls[1][4] == "Firmato digitalmente da Mario Rossi\nVisto"
    assert config.load().stamp == "si" and config.load().stamp_position == "alto-sinistra"
    window.result.open_folder.click()
    assert window.open_url.calls[-1] == (tmp_path,)


def test_sign_other_file_single_result(window, qtbot, tmp_path):
    (tmp_path / "fattura.xml").write_bytes(b"<f/>")
    window.choose_files = Recorder([str(tmp_path / "fattura.xml")])
    window.home.sign_other.click()
    wait_for(qtbot, window, window.result)
    assert window.result.title.text() == "Fatto! Documento firmato."
    window.result.open_document.click()
    assert window.open_url.calls[-1] == (tmp_path / "fattura.xml.p7m",)


def test_local_problem_never_asks_for_otp(window, api, tmp_path, make_pdf):
    path = tmp_path / "protetto.pdf"
    path.write_bytes(make_pdf(A4, password="x"))
    window.prepare_sign([str(path)], Kind.PADES)
    window.options.sign.click()
    assert window.show_error.calls and "password" in window.show_error.calls[0][1]
    assert "Non è stato usato nessun codice OTP" in window.show_error.calls[0][1]
    assert window.ask_otp.calls == [] and api.calls == []


def test_refused_otp_goes_home_and_warns_next_time(window, api, qtbot, tmp_path, make_pdf):
    api.open_error = OtpError(MSG_OTP)
    paths = pdfs(tmp_path, make_pdf, "a.pdf")
    window.prepare_sign(paths, Kind.PADES)
    window.options.sign.click()
    qtbot.waitUntil(lambda: bool(window.show_error.calls), timeout=10000)
    assert "ora del telefono" in window.show_error.calls[0][1]
    assert window.stack.currentWidget() is window.home
    window.prepare_sign(paths, Kind.PADES)
    window.options.sign.click()
    assert window.ask_otp.calls[-1] == (1, 1)  # the dialog now shows the warning


def test_partial_batch_and_retry(window, api, qtbot, tmp_path, make_pdf):
    api.fail_at = {1: ServiceError("guasto")}
    window.prepare_sign(pdfs(tmp_path, make_pdf, "a.pdf", "b.pdf"), Kind.PADES)
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.result.title.text() == "Attenzione: firmato 1 documento su 2."
    assert not window.result.retry.isHidden()
    window.stack.setCurrentWidget(window.home)
    window.result.retry.click()
    wait_for(qtbot, window, window.result)
    assert window.result.title.text() == "Fatto! Documento firmato."
    assert len(window.ask_otp.calls) == 2 and (tmp_path / "b_firmato.pdf").exists()


def test_password_asked_and_saved_only_after_success(window, store, api, qtbot, tmp_path, make_pdf):
    store.data.clear()
    window.ask_password = Recorder(("pw-nuova", True))
    api.open_error = OtpError(MSG_OTP)
    paths = pdfs(tmp_path, make_pdf, "a.pdf")
    window.prepare_sign(paths, Kind.PADES)
    window.options.sign.click()
    qtbot.waitUntil(lambda: bool(window.show_error.calls), timeout=10000)
    assert store.data == {}  # refused: not saved
    api.open_error = None
    window.prepare_sign(paths, Kind.PADES)
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert store.data == {KEY: "pw-nuova"}


def test_open_signed_p7m_and_extract(window, qtbot, tmp_path, make_p7m, pki, monkeypatch):
    monkeypatch.setattr(verify, "default_trust", lambda: RootsTrust(pki["ca"]))
    signed = tmp_path / "contratto.pdf.p7m"
    signed.write_bytes(make_p7m(PDF))
    window.choose_files = Recorder([str(signed)])
    window.home.open_signed.click()
    wait_for(qtbot, window, window.verify_page)
    assert window.verify_page.title.text() == "✔  Firma valida"
    window.verify_page.open_document.click()
    window.verify_page.open_document.click()
    assert window.open_url.calls == [(tmp_path / "contratto.pdf",), (tmp_path / "contratto.pdf",)]
    assert (tmp_path / "contratto.pdf").read_bytes() == PDF and not (tmp_path / "contratto (2).pdf").exists()


def test_tampered_file_is_shown_invalid(window, qtbot, tmp_path, make_p7m, pki, monkeypatch):
    monkeypatch.setattr(verify, "default_trust", lambda: RootsTrust(pki["ca"]))
    bad = tmp_path / "x.p7m"
    bad.write_bytes(make_p7m(PDF).replace(b"finto pdf", b"falso pdf"))
    window.open_paths([str(bad)])
    wait_for(qtbot, window, window.verify_page)
    assert "NON valida" in window.verify_page.title.text()
    items = [window.verify_page.details.item(i).text() for i in range(window.verify_page.details.count())]
    assert any("modificato dopo la firma" in line for line in items)


def test_drop_a_pdf_asks_what_to_do(window, tmp_path, make_pdf):
    (path,) = pdfs(tmp_path, make_pdf, "a.pdf")
    window.ask_sign_or_verify = Recorder("firma")
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(path)])
    event = QDropEvent(QPointF(10, 10), Qt.DropAction.CopyAction, mime, Qt.MouseButton.NoButton,
                       Qt.KeyboardModifier.NoModifier)
    window.dropEvent(event)
    assert window.ask_sign_or_verify.calls == [("a.pdf",)]
    assert window.stack.currentWidget() is window.options


def test_first_run_opens_setup(qtbot, store, api, tmp_path, make_pdf):
    w = MainWindow(lambda: api)
    qtbot.addWidget(w)
    w.run_setup = Recorder(False)
    w.choose_files = Recorder(pdfs(tmp_path, make_pdf, "a.pdf"))
    w.home.sign_pdf.click()
    assert w.run_setup.calls == [()]  # asked to configure first; cancelled, so nothing else happens
    assert w.stack.currentWidget() is w.home


def test_otp_dialog_validation(qtbot):
    dialog = OtpDialog(None, 3, 0)
    qtbot.addWidget(dialog)
    assert not dialog.ok.isEnabled()
    dialog.code.setText("12a34")
    assert dialog.code.text() == "1234" and not dialog.ok.isEnabled()
    dialog.code.setText("1234 5678")  # pasted with a space
    assert dialog.value() == "12345678" and dialog.ok.isEnabled()
    dialog.code.setText("123456789")
    assert dialog.value() == "12345678"
    cautious = OtpDialog(None, 1, 2)
    qtbot.addWidget(cautious)
    cautious.code.setText("12345678")
    assert not cautious.ok.isEnabled()
    cautious.confirm.setChecked(True)
    assert cautious.ok.isEnabled()


def test_setup_dialog_saves_after_aruba_accepts(qtbot, store, api):
    store.data.clear()
    dialog = SetupDialog(None, lambda: api, first_run=True)
    qtbot.addWidget(dialog)
    dialog.user.setText("mario.rossi@firma")
    dialog.domain.setText("")
    dialog.password.setText("Pw-1")
    dialog.check.click()
    qtbot.waitUntil(lambda: dialog.result() == QDialog.DialogCode.Accepted, timeout=10000)
    settings = config.load()
    assert (settings.user, settings.domain, settings.cert_id, settings.signer_name) == \
        ("mario.rossi", "firma", "NEW_2025:abc-AS0", "Mario Rossi")
    assert store.data == {KEY: "Pw-1"} and api.calls == [("list_certs", "Pw-1")]


def test_setup_dialog_refused(qtbot, store, api):
    api.certs = CredentialsError("Nome utente, dominio o password non accettati.")
    dialog = SetupDialog(None, lambda: api, first_run=True)
    qtbot.addWidget(dialog)
    dialog.user.setText("mario.rossi")
    dialog.password.setText("sbagliata")
    dialog.check.click()
    qtbot.waitUntil(lambda: "non accettati" in dialog.status.text(), timeout=10000)
    assert dialog.result() != QDialog.DialogCode.Accepted and not config.load().complete
    assert dialog.check.isEnabled()


def test_support_report(window, qtbot):
    window.show_support = Recorder()
    window.home.support.click()
    qtbot.waitUntil(lambda: bool(window.show_support.calls), timeout=10000)
    text = window.show_support.calls[0][0]
    assert "Account: mario.rossi@firma" in text and "pw-salvata" not in text


def test_startup_smoke_test(tmp_path):
    """What the installer runs: build and show the window, exit 0."""
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", XDG_STATE_HOME=str(tmp_path / "s"),
               XDG_CONFIG_HOME=str(tmp_path / "c"), XDG_CACHE_HOME=str(tmp_path / "k"))
    code = "from firmaremota.gui.app import main; raise SystemExit(main(['--prova-avvio']))"
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0 and "ok" in result.stdout
