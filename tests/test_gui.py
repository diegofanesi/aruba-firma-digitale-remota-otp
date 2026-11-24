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
def api(make_p7m, sign_pdf, make_cades_t, make_tsd, make_tsr):
    return FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf, make_cades_t=make_cades_t, make_tsd=make_tsd, make_tsr=make_tsr)


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
    # In-process instead of a spawned process: the tests' monkeypatched trust must stay visible.
    w.verify_fn = lambda path, cancel=None, original=None: verify.verify_file(path, original=original)
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
    window.options.timestamp.setChecked(False)
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.result.title.text() == "Fatto! 2 documenti firmati."
    assert (tmp_path / "a_firmato.pdf").exists() and (tmp_path / "b_firmato.pdf").exists()
    assert api.tsa_seen == [(None, None)] * 2
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
    assert window.stack.currentWidget() is window.options  # also for .p7m, now: the timestamp choice lives there
    assert not window.options.stamp.isVisibleTo(window) and window.options.timestamp.isChecked()
    assert window.options.title.text() == "Firma un file (.p7m)"
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.result.title.text() == "Fatto! Documento firmato e marcato temporalmente."
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
    assert window.result.title.text() == "Fatto! Documento firmato e marcato temporalmente."  # timestamps are on by default
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
    assert window.verify_page.open_document.isVisibleTo(window) and window.verify_page.open_folder.isVisibleTo(window)
    window.verify_page.open_document.click()
    window.verify_page.open_document.click()
    assert window.open_url.calls == [(tmp_path / "contratto.pdf",), (tmp_path / "contratto.pdf",)]
    assert (tmp_path / "contratto.pdf").read_bytes() == PDF and not (tmp_path / "contratto (2).pdf").exists()
    window.verify_page.open_folder.click()
    assert window.open_url.calls[-1] == (tmp_path,) and not (tmp_path / "contratto (2).pdf").exists()


def test_executable_content_is_extracted_but_never_launched(window, qtbot, tmp_path, make_p7m, pki, monkeypatch):
    """The sender chose the inner name: a valid signature on `x.desktop` doesn't make it safe to open."""
    monkeypatch.setattr(verify, "default_trust", lambda: RootsTrust(pki["ca"]))
    signed = tmp_path / "nota.desktop.p7m"
    signed.write_bytes(make_p7m(b"[Desktop Entry]\nExec=rm -rf ~\n"))
    window.open_paths([str(signed)])
    wait_for(qtbot, window, window.verify_page)
    assert window.verify_page.title.text() == "✔  Firma valida"
    assert not window.verify_page.open_document.isVisibleTo(window) and window.verify_page.open_folder.isVisibleTo(window)
    items = [window.verify_page.details.item(i).text() for i in range(window.verify_page.details.count())]
    assert any("non viene aperto automaticamente" in line and ".desktop" in line for line in items)
    window.open_verified_document()  # even called directly
    assert window.open_url.calls == []
    window.verify_page.open_folder.click()
    assert window.open_url.calls == [(tmp_path,)] and (tmp_path / "nota.desktop").exists()


def test_unverifiable_signature_is_amber_not_green(window, qtbot, tmp_path, make_p7m, monkeypatch):
    monkeypatch.setattr(verify, "default_trust", lambda: verify.NoTrust())
    signed = tmp_path / "contratto.pdf.p7m"
    signed.write_bytes(make_p7m(PDF))
    window.open_paths([str(signed)])
    wait_for(qtbot, window, window.verify_page)
    assert window.verify_page.title.text() == "?  Firma NON verificabile"
    assert "9a6700" in window.verify_page.title.styleSheet()  # amber, neither the green nor the red
    items = [window.verify_page.details.item(i).text() for i in range(window.verify_page.details.count())]
    assert any("elenco ufficiale dei certificatori non è disponibile" in line for line in items)


def test_verification_can_be_cancelled(window, qtbot, tmp_path):
    import threading

    started = threading.Event()

    def slow_verify(path, cancel=None, original=None):
        started.set()
        cancel.wait(5)
        raise verify.FirmaError("Controllo annullato.")

    window.verify_fn = slow_verify
    window.verify(str(tmp_path / "x.p7m"))
    assert window.progress.stop.isVisibleTo(window)
    assert started.wait(5)
    window.progress.stop.click()
    qtbot.waitUntil(lambda: bool(window.show_error.calls), timeout=10000)
    assert window.show_error.calls[0][1] == "Controllo annullato." and window.stack.currentWidget() is window.home


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


def test_support_checks_only_the_selected_account(window, qtbot, api, store):
    add_profile(store, "Anna", "anna.bianchi@firma", "pw-anna")
    window.show_support = Recorder()
    window.home.support.click()
    qtbot.waitUntil(lambda: bool(window.show_support.calls), timeout=10000)
    text = window.show_support.calls[0][0]
    assert "Credenziali «M***o»: accettate" in text and "Credenziali «A**a»" not in text
    assert [c for c in api.calls if c[0] == "list_certs"] == [("list_certs", PASSWORD)]


def test_dialogs_show_account_names_literally(qtbot):
    from PySide6.QtWidgets import QLabel

    from firmaremota.gui.dialogs import LoginDialog

    for dialog in (OtpDialog(None, 1, 0, who="<b>Papà</b> <img src=x>"),
                   LoginDialog(None, True, None, who="<b>Papà</b> <img src=x>")):
        qtbot.addWidget(dialog)
        (label,) = [w for w in dialog.findChildren(QLabel) if w.text().startswith("Account:")]
        assert "&lt;b&gt;Papà&lt;/b&gt; &lt;img src=x&gt;" in label.text() and "<img" not in label.text()


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


def test_open_tsd_shows_timestamp_title(window, qtbot, tmp_path, make_tsd, make_p7m, pki, monkeypatch):
    monkeypatch.setattr(verify, "default_trust", lambda: RootsTrust(pki["ca"]))
    path = tmp_path / "contratto.pdf.p7m.tsd"
    path.write_bytes(make_tsd(make_p7m(PDF)))
    window.open_paths([str(path)])
    wait_for(qtbot, window, window.verify_page)
    assert window.verify_page.title.text() == "✔  Firma valida"  # a signature inside: the signature is the subject
    items = [window.verify_page.details.item(i).text() for i in range(window.verify_page.details.count())]
    assert any(line.startswith("Marca temporale sul documento:") for line in items)
    window.verify_page.open_document.click()
    assert window.open_url.calls == [(tmp_path / "contratto.pdf",)]
    plain = tmp_path / "nota.txt.tsd"
    plain.write_bytes(make_tsd(b"ciao"))
    window.open_paths([str(plain)])
    wait_for(qtbot, window, window.verify_page)
    assert window.verify_page.title.text() == "✔  Marca temporale valida"


def test_tsr_asks_for_the_original(window, qtbot, tmp_path, make_tsr, pki, monkeypatch):
    monkeypatch.setattr(verify, "default_trust", lambda: RootsTrust(pki["ca"]))
    (tmp_path / "altrove.txt").write_bytes(b"ciao")
    tsr = tmp_path / "nota.txt.tsr"
    tsr.write_bytes(make_tsr(b"ciao"))
    window.choose_original = Recorder(str(tmp_path / "altrove.txt"))
    window.open_paths([str(tsr)])
    wait_for(qtbot, window, window.verify_page)
    assert window.choose_original.calls == [("nota.txt.tsr",)]
    assert window.verify_page.title.text() == "✔  Marca temporale valida"
    assert not window.verify_page.open_document.isVisibleTo(window) and not window.verify_page.open_folder.isVisibleTo(window)
    window.choose_original = Recorder(None)  # cancelled: back home, no error box
    window.open_paths([str(tsr)])
    qtbot.waitUntil(lambda: window.stack.currentWidget() is window.home, timeout=10000)
    assert window.show_error.calls == []


# --- marche temporali -------------------------------------------------------------------------------

def test_sign_pdf_with_timestamp_passes_tsa_and_level(window, api, qtbot, tmp_path, make_pdf):
    from firmaremota import verify
    from firmaremota.models import TimestampType

    window.choose_files = Recorder(pdfs(tmp_path, make_pdf, "a.pdf"))
    window.home.sign_pdf.click()
    assert window.options.timestamp.isChecked() and window.options.level.isEnabled()
    assert [window.options.level.itemData(i) for i in range(window.options.level.count())] == ["T", "LT"]  # no TSD for PDFs
    window.options.level.setCurrentIndex(1)
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.result.title.text() == "Fatto! Documento firmato e marcato temporalmente."
    assert api.tsa_seen[0] == (None, TimestampType.LT)  # no TSA account: Aruba's own mark, requested with requiredmark
    assert verify.has_timestamp(Kind.PADES, (tmp_path / "a_firmato.pdf").read_bytes())


def test_options_timestamp_preset_from_profile(window, api, qtbot, store, tmp_path, make_pdf):
    import dataclasses

    from firmaremota import profiles

    (profile,) = profiles.load_all(store)
    profiles.upsert(store, [profile], dataclasses.replace(profile, timestamp=False))
    window.reload_profiles() if hasattr(window, "reload_profiles") else None
    window.current = profiles.load_all(store)[0]
    window.choose_files = Recorder(pdfs(tmp_path, make_pdf, "a.pdf"))
    window.home.sign_pdf.click()
    assert not window.options.timestamp.isChecked() and not window.options.level.isEnabled()
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert api.tsa_seen == [(None, None)] and window.result.title.text() == "Fatto! Documento firmato."


def test_p7m_tsd_level_wraps(window, api, qtbot, store, tmp_path):
    from firmaremota import profiles
    from firmaremota.models import TsaCredentials

    (tmp_path / "fattura.xml").write_bytes(b"<f/>")
    window.choose_files = Recorder([str(tmp_path / "fattura.xml")])
    window.home.sign_other.click()
    assert [window.options.level.itemData(i) for i in range(window.options.level.count())] == ["T", "LT", "TSD"]
    window.options.level.setCurrentIndex(2)
    window.options.sign.click()  # no TSA account: refused before the OTP, with the explanation
    assert "account di marca temporale" in window.show_error.calls[-1][1] and window.ask_otp.calls == []
    profiles.set_tsa(store, profiles.load_all(store)[0], TsaCredentials("tsa", "pw"))
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert (tmp_path / "fattura.xml.p7m.tsd").exists() and api.names().count("timestamp_file") == 1
    window.result.open_document.click()
    assert window.open_url.calls[-1] == (tmp_path / "fattura.xml.p7m.tsd",)


def test_timestamp_button_makes_tsd_without_otp(window, api, qtbot, store, tmp_path):
    from firmaremota import profiles, verify
    from firmaremota.models import TsaCredentials

    (tmp_path / "nota.txt").write_bytes(b"ciao")
    (tmp_path / "foto.jpg").write_bytes(b"finta")
    window.choose_files = Recorder([str(tmp_path / "nota.txt"), str(tmp_path / "foto.jpg")])
    window.ask_timestamp_format = Recorder("tsd")
    window.home.timestamp_file.click()  # Firma Remota alone: explained, nothing sent
    assert "account di marca temporale" in window.show_error.calls[-1][1] and api.calls == []
    profiles.set_tsa(store, profiles.load_all(store)[0], TsaCredentials("tsa", "pw"))
    window.home.timestamp_file.click()
    wait_for(qtbot, window, window.result)
    assert window.ask_timestamp_format.calls == [(2,)] and window.ask_otp.calls == []
    assert window.result.title.text() == "Fatto! 2 documenti marcati."
    assert api.names() == ["timestamp_file", "timestamp_file"]  # no account check with Aruba either
    assert verify.verify_file(tmp_path / "nota.txt.tsd", verify.NoTrust()).content == b"ciao"
    assert window.result.retry.text() == "Marca i rimanenti" and not window.result.retry.isVisibleTo(window)


def test_timestamp_button_tsr_shows_the_note_and_cancel(window, api, qtbot, store, tmp_path):
    from firmaremota import profiles
    from firmaremota.models import TsaCredentials

    profiles.set_tsa(store, profiles.load_all(store)[0], TsaCredentials("tsa", "pw"))
    (tmp_path / "nota.txt").write_bytes(b"ciao")
    window.choose_files = Recorder([str(tmp_path / "nota.txt")])
    window.ask_timestamp_format = Recorder(None)  # cancelled
    window.home.timestamp_file.click()
    assert api.calls == [] and window.stack.currentWidget() is window.home
    window.ask_timestamp_format = Recorder("tsr")
    window.home.timestamp_file.click()
    wait_for(qtbot, window, window.result)
    assert (tmp_path / "nota.txt.tsr").exists()
    lines = [window.result.lines.item(i).text() for i in range(window.result.lines.count())]
    assert any("documento originale" in line for line in lines)


def test_timestamp_error_offers_retry_without_timestamp(window, api, qtbot, tmp_path, make_pdf, sign_pdf):
    from firmaremota.errors import TimestampError

    api.timestamp_error = TimestampError("TSA no")
    window.choose_files = Recorder(pdfs(tmp_path, make_pdf, "a.pdf", "b.pdf"))
    window.home.sign_pdf.click()
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.result.title.text() == "Nessun documento è stato firmato."
    assert window.result.retry.isVisibleTo(window) and window.result.retry.text() == "Firma i rimanenti"
    window.result.retry.click()
    assert window.stack.currentWidget() is window.options
    assert not window.options.timestamp.isChecked() and "marca temporale" in window.options.note.text()
    assert [window.options.files.item(i).text() for i in range(window.options.files.count())] == ["a.pdf", "b.pdf"]
    window.options.sign.click()
    wait_for(qtbot, window, window.result)
    assert window.result.title.text() == "Fatto! 2 documenti firmati."


def test_timestamp_format_dialog(qtbot):
    from firmaremota.gui.dialogs import TimestampFormatDialog

    dialog = TimestampFormatDialog(None, 3)
    qtbot.addWidget(dialog)
    assert dialog.value() == "tsd" and not dialog.note.isVisibleTo(dialog)
    dialog.tsr.setChecked(True)
    assert dialog.value() == "tsr" and dialog.note.isVisibleTo(dialog)


def test_profile_dialog_timestamp_settings(qtbot, store, api):
    from firmaremota import profiles
    from firmaremota.models import TsaCredentials

    (mario,) = profiles.load_all(store)
    dialog = ProfileEditDialog(None, lambda: api, store, [mario], mario)
    qtbot.addWidget(dialog)
    assert dialog.timestamp.isChecked() and not dialog.tsa_separate.isChecked() and not dialog.tsa_user.isEnabled()
    dialog.tsa_separate.setChecked(True)
    dialog.check.click()  # separate account chosen but empty: refused before anything is sent
    assert "account TSA" in dialog.status.text() and api.calls == []
    dialog.tsa_user.setText("tsa-user")
    dialog.tsa_password.setText("tsa-pw")
    dialog.timestamp.setChecked(False)
    dialog.check.click()
    qtbot.waitUntil(lambda: dialog.result() == QDialog.DialogCode.Accepted, timeout=10000)
    saved = profiles.load_all(store)[0]
    assert saved.timestamp is False and profiles.tsa_account(store, saved) == TsaCredentials("tsa-user", "tsa-pw")
    again = ProfileEditDialog(None, lambda: api, store, [saved], saved)
    qtbot.addWidget(again)
    assert again.tsa_separate.isChecked() and again.tsa_user.text() == "tsa-user" and again.tsa_password.text() == ""
    again.tsa_separate.setChecked(False)
    again.check.click()
    qtbot.waitUntil(lambda: again.result() == QDialog.DialogCode.Accepted, timeout=10000)
    assert profiles.tsa_account(store, profiles.load_all(store)[0]) is None


def test_profiles_dialog_marks_accounts_without_timestamp(qtbot, store, api):
    add_profile(store, "Anna", "anna.bianchi@firma", "pw", timestamp=False)
    dialog = ProfilesDialog(None, lambda: api, store, profiles.load_all(store))
    qtbot.addWidget(dialog)
    assert "(senza marca temporale)" in dialog.list.item(1).text() and "senza marca" not in dialog.list.item(0).text()
