"""The graphical interface, driven with pytest-qt (offscreen) against a fake Aruba service."""

import os
import subprocess
import sys

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QMimeData, QPointF, Qt, QUrl  # noqa: E402
from PySide6.QtGui import QDropEvent  # noqa: E402
from PySide6.QtWidgets import QDialog  # noqa: E402

from firmaremota import config, credentials, profiles, verify  # noqa: E402
from firmaremota.arss.client import MSG_OTP  # noqa: E402
from firmaremota.errors import CredentialsError, OtpError, ServiceError  # noqa: E402
from firmaremota.gui.dialogs import OtpDialog, ProfileEditDialog, ProfilesDialog  # noqa: E402
from firmaremota.gui.main_window import MainWindow  # noqa: E402
from firmaremota.models import Kind, Position  # noqa: E402

from .conftest import PASSWORD, PROFILE_ID, add_profile  # noqa: E402
from .fakes import FakeArss, signer_info  # noqa: E402
from .test_verify import PDF, RootsTrust  # noqa: E402

A4 = (595, 842, 0, None)
PW = f"password:{PROFILE_ID}"


class Recorder:
    def __init__(self, result=None):
        self.calls, self.result = [], result

    def __call__(self, *args, **kwargs):
        self.calls.append(args + tuple(kwargs.values()))
        return self.result


@pytest.fixture
def store(configured):
    return configured


@pytest.fixture
def api(make_p7m):
    return FakeArss(make_p7m=make_p7m)


def wait_for_workers(qtbot, owner):
    """No background thread may outlive its test (it would act after the test's isolation is gone)."""
    running = owner.__dict__.get("_running_workers", [])
    qtbot.waitUntil(lambda: all(thread.isFinished() for thread, _ in running), timeout=10000)


@pytest.fixture
def window(qtbot, store, api):
    w = MainWindow(lambda: api)
    qtbot.addWidget(w)
    w.ask_otp = Recorder("12345678")
    w.show_error = Recorder()
    w.open_url = Recorder()
    w.ask_login = Recorder(None)
    yield w
    wait_for_workers(qtbot, w)


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
    assert window.ask_otp.calls == [(2, 0, "", "Mario")]
    assert api.names()[:2] == ["list_certs", "open_session"]  # account checked before the OTP is used
    assert next(c for c in api.calls if c[0] == "sign_pdf")[4] == "Firmato digitalmente da Mario Rossi\nVisto"
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
    qtbot.waitUntil(lambda: len(window.show_error.calls) == 2, timeout=10000)  # second attempt fully done
    assert window.ask_otp.calls[-1] == (1, 1, "", "Mario")  # the dialog showed the warning
    assert config.load_state().auth_failures == 2


def test_wrong_password_stops_before_the_otp(window, api, qtbot, tmp_path, make_pdf):
    api.certs = CredentialsError("Nome utente, dominio o password non accettati dal servizio di firma Aruba.")
    window.prepare_sign(pdfs(tmp_path, make_pdf, "a.pdf"), Kind.PADES)
    window.options.sign.click()
    qtbot.waitUntil(lambda: bool(window.show_error.calls), timeout=10000)
    assert "non accettati" in window.show_error.calls[0][1]
    assert window.ask_otp.calls == [] and api.names() == ["list_certs"]


def test_expiring_certificate_is_mentioned_in_the_otp_dialog(window, api, qtbot, tmp_path, make_pdf):
    api.certs = [("x", signer_info("Mario Rossi", days_left=20))]
    window.prepare_sign(pdfs(tmp_path, make_pdf, "a.pdf"), Kind.PADES)
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert "certificato di firma scade il" in window.ask_otp.calls[0][2]


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


def test_missing_password_is_asked_and_remembered_after_aruba_accepts(window, store, api, qtbot, tmp_path, make_pdf):
    del store.data[PW]
    window.ask_login = Recorder((None, PASSWORD, True))
    api.open_error = OtpError(MSG_OTP)  # the OTP will fail, but Aruba has already accepted the password
    window.prepare_sign(pdfs(tmp_path, make_pdf, "a.pdf"), Kind.PADES)
    window.options.sign.click()
    qtbot.waitUntil(lambda: bool(window.show_error.calls), timeout=10000)
    assert window.ask_login.calls == [(False, "Portachiavi di prova", "Mario")]
    assert store.data[PW] == PASSWORD


def test_refused_typed_password_is_not_remembered(window, store, api, qtbot, tmp_path, make_pdf):
    del store.data[PW]
    window.ask_login = Recorder((None, "sbagliata", True))
    api.certs = CredentialsError("Nome utente, dominio o password non accettati.")
    window.prepare_sign(pdfs(tmp_path, make_pdf, "a.pdf"), Kind.PADES)
    window.options.sign.click()
    qtbot.waitUntil(lambda: bool(window.show_error.calls), timeout=10000)
    assert PW not in store.data and window.ask_otp.calls == []


def test_no_account_yet_adds_one_before_signing(window, store, api, qtbot, tmp_path, make_pdf):
    store.data.clear()
    window._load_profiles()
    assert window.profiles == [] and "Nessun account" in window.home.bar.caption.text()

    def add_one():
        profile = add_profile(store, "Mario", "mario.rossi@firma", PASSWORD, id=PROFILE_ID)
        window._set_profiles(profiles.load_all(store), profile)
        return True

    window.add_first_profile = add_one
    window.prepare_sign(pdfs(tmp_path, make_pdf, "a.pdf"), Kind.PADES)
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.ask_otp.calls[0][3] == "Mario" and window.ask_login.calls == []


def test_no_wallet_asks_everything_and_remembers_nothing(qtbot, monkeypatch, api, tmp_path, make_pdf):
    monkeypatch.setattr(credentials, "get_store", lambda: None)
    window = MainWindow(lambda: api)
    qtbot.addWidget(window)
    window.ask_otp, window.show_error = Recorder("12345678"), Recorder()
    window.ask_login = Recorder((("mario.rossi", "firma"), PASSWORD, True))
    window.prepare_sign(pdfs(tmp_path, make_pdf, "a.pdf"), Kind.PADES)
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.ask_login.calls == [(True, None)]
    assert window.ask_otp.calls[0][3] == "mario.rossi@firma"


def test_home_shows_the_accounts(window, qtbot, store, api):
    assert [b.text() for b in window.home.bar.buttons.values()] == ["Mario"]
    assert window.home.bar.buttons[PROFILE_ID].isChecked() and window.current.alias == "Mario"
    store.data.clear()
    fresh = MainWindow(lambda: api)
    qtbot.addWidget(fresh)
    assert fresh.home.bar.buttons == {} and "Nessun account" in fresh.home.bar.caption.text()


def test_switch_account_by_clicking(window, store, api, qtbot, tmp_path, make_pdf):
    anna = add_profile(store, "Anna", "anna.bianchi@frStudio", "pw-anna")
    window._load_profiles()
    assert window.current.alias == "Mario" and window.home.bar.caption.text() == "Chi firma?"
    window.home.bar.buttons[anna.id].click()
    assert window.current.alias == "Anna" and config.load().last_profile == anna.id
    window.prepare_sign(pdfs(tmp_path, make_pdf, "a.pdf"), Kind.PADES)
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.ask_otp.calls[0][3] == "Anna" and api.calls[0] == ("list_certs", "pw-anna")
    restarted = MainWindow(lambda: api)  # the choice survives a restart
    qtbot.addWidget(restarted)
    assert restarted.current.alias == "Anna" and restarted.home.bar.buttons[anna.id].isChecked()


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


def test_profile_edit_dialog_adds_an_account(qtbot, store, api):
    store.data.clear()
    dialog = ProfileEditDialog(None, lambda: api, store, [])
    qtbot.addWidget(dialog)
    dialog.user.setText("mario.rossi@firma")
    dialog.password.setText("Pw-1")
    dialog.check.click()
    qtbot.waitUntil(lambda: dialog.result() == QDialog.DialogCode.Accepted, timeout=10000)
    assert (dialog.profile.alias, dialog.profile.login) == ("mario.rossi", "mario.rossi@firma")  # alias defaults
    assert profiles.password(store, dialog.profile) == "Pw-1" and api.calls == [("list_certs", "Pw-1")]
    assert not config.config_dir().exists() or "mario" not in "".join(
        p.read_text() for p in config.config_dir().iterdir())


def test_profile_edit_dialog_refused_and_duplicate(qtbot, store, api):
    existing = profiles.load_all(store)
    api.certs = CredentialsError("Nome utente, dominio o password non accettati.")
    dialog = ProfileEditDialog(None, lambda: api, store, existing)
    qtbot.addWidget(dialog)
    dialog.alias.setText("mario")  # same as "Mario", case-insensitively
    dialog.user.setText("altro")
    dialog.password.setText("x")
    dialog.check.click()
    assert "già un account chiamato «Mario»" in dialog.status.text() and api.calls == []
    dialog.alias.setText("Altro")
    dialog.check.click()
    qtbot.waitUntil(lambda: "non accettati" in dialog.status.text(), timeout=10000)
    assert dialog.result() != QDialog.DialogCode.Accepted and len(profiles.load_all(store)) == 1
    assert dialog.check.isEnabled()


def test_profile_edit_dialog_keeps_the_saved_password(qtbot, store, api):
    (mario,) = profiles.load_all(store)
    dialog = ProfileEditDialog(None, lambda: api, store, [mario], mario)
    qtbot.addWidget(dialog)
    assert dialog.password.placeholderText().startswith("lascia vuoto")
    dialog.alias.setText("Papà")
    dialog.check.click()  # empty password field: the saved one is checked and kept
    qtbot.waitUntil(lambda: dialog.result() == QDialog.DialogCode.Accepted, timeout=10000)
    (renamed,) = profiles.load_all(store)
    assert (renamed.id, renamed.alias) == (mario.id, "Papà") and profiles.password(store, renamed) == PASSWORD
    assert api.calls == [("list_certs", PASSWORD)]


def test_profiles_dialog_remove_and_forget(qtbot, store, api):
    add_profile(store, "Anna", "anna.bianchi@firma", "pw-anna")
    dialog = ProfilesDialog(None, lambda: api, store, profiles.load_all(store))
    qtbot.addWidget(dialog)
    dialog.confirm = lambda text: True
    dialog.list.setCurrentRow(1)
    dialog.remove()
    assert [p.alias for p in dialog.profiles] == ["Mario"] and "Account «Anna» rimosso" in dialog.status.text()
    dialog.list.setCurrentRow(0)
    dialog.forget_password()
    assert PW not in store.data and "(password non salvata)" in dialog.list.item(0).text()


def test_support_report(window, qtbot, api):
    window.show_support = Recorder()
    window.home.support.click()
    qtbot.waitUntil(lambda: bool(window.show_support.calls), timeout=10000)
    text = window.show_support.calls[0][0]
    assert "Account «M***o»: m*********i@firma, password salvata" in text
    assert "Credenziali «M***o»: accettate" in text and "Mario" not in text
    assert PASSWORD not in text and "mario.rossi" not in text


def test_startup_smoke_test(tmp_path):
    """What the installer runs: build and show the window, exit 0."""
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", XDG_STATE_HOME=str(tmp_path / "s"),
               XDG_CONFIG_HOME=str(tmp_path / "c"), XDG_CACHE_HOME=str(tmp_path / "k"),
               PYTHON_KEYRING_BACKEND="keyring.backends.fail.Keyring", XDG_CURRENT_DESKTOP="none")
    code = ("from firmaremota import credentials\n"
            "credentials.KWalletStore.available = lambda self: False\n"
            "from firmaremota.gui.app import main; raise SystemExit(main(['--prova-avvio']))")
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0 and "ok" in result.stdout
