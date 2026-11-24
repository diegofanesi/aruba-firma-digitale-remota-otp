"""Regression tests for the bugs found in the code review."""

import logging

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from firmaremota import cli, credentials, logsetup, p7m, service, verify
from firmaremota.arss.client import ArssClient
from firmaremota.errors import FileError, FirmaError
from firmaremota.models import Account, AuthCtx

from .conftest import PASSWORD, MemoryStore, asn1_cert
from .fakes import FakeArss, FakeTransport, soap

ACCOUNT = Account("mario.rossi", "firma", "NEW_2025:abc-AS0")


class BrokenStore:
    """A wallet that exists but refuses every operation (locked, access denied...)."""

    name = "Portachiavi rotto"

    def get(self, key):
        raise credentials.CredentialStoreError("KWallet: accesso al portafoglio negato o annullato.")

    set = delete = get


def test_store_errors_are_firma_errors_with_a_message():
    exc = credentials.CredentialStoreError("KWallet: negato")
    assert isinstance(exc, FirmaError) and exc.message == "KWallet: negato"


def test_cli_survives_a_broken_wallet(monkeypatch, capsys, tmp_path, make_pdf):
    """Before the fix this crashed with AttributeError: 'CredentialStoreError' has no 'message'."""
    monkeypatch.setattr(credentials, "get_store", lambda: BrokenStore())
    monkeypatch.setattr(cli, "make_api", lambda: FakeArss())
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(make_pdf((595, 842, 0, None)))
    assert cli.main(["pdf", str(pdf)]) == 1
    assert "Errore: KWallet: accesso al portafoglio negato" in capsys.readouterr().err
    assert cli.main(["diagnostica"]) == 1
    assert "[ERRORE]  Portachiavi: KWallet" in capsys.readouterr().out


def test_empty_batch_never_opens_a_session():
    api = FakeArss()
    assert service.sign_batch(api, ACCOUNT, "pw", "12345678", []) == []
    assert api.calls == []


@pytest.mark.parametrize("otp", ["١٢٣٤٥٦٧٨", "１２３４５６７８", "12345678x"])
def test_cli_otp_accepts_ascii_digits_only(monkeypatch, otp):
    answers = iter([otp, "12345678"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert cli._ask_otp() == "12345678"


def test_gui_otp_field_accepts_ascii_digits_only(qtbot):
    pytest.importorskip("PySide6")
    from firmaremota.gui.dialogs import OtpDialog

    dialog = OtpDialog(None, 1, 0)
    qtbot.addWidget(dialog)
    dialog.code.setText("١٢٣٤٥٦٧٨")  # Arabic-Indic digits: \\d matches them, [0-9] doesn't
    assert dialog.value() == "" and not dialog.ok.isEnabled()


def test_unreadable_certificate_from_aruba_is_skipped(pki):
    import base64

    good = base64.b64encode(asn1_cert(pki["mario"][0]).dump()).decode()
    body = (f"<return><app1><id>rotto</id><value>{base64.b64encode(b'non sono un certificato').decode()}</value></app1>"
            f"<app1><id>buono</id><value>{good}</value></app1><status>OK</status></return>")
    api = ArssClient(transport=FakeTransport({"listCert": soap("listCert", body)}))
    assert [cert_id for cert_id, _ in api.list_certs(ACCOUNT, PASSWORD)] == ["buono"]


def test_multi_valued_name_attributes():
    """asn1crypto returns a list when an attribute appears twice in a name."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = cx509.Name([
        cx509.NameAttribute(NameOID.COMMON_NAME, "Mario Rossi"),
        cx509.NameAttribute(NameOID.COMMON_NAME, "Mario Rossi (bis)"),
        cx509.NameAttribute(NameOID.SERIAL_NUMBER, "TINIT-RSSMRA80A01H501U"),
    ])
    import datetime as dt

    now = dt.datetime.now(dt.timezone.utc)
    cert = (cx509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    info = p7m.signer_from_cert(asn1_cert(cert))
    assert info.name == "Mario Rossi" and info.fiscal_code == "RSSMRA80A01H501U"


def test_unreadable_signature_is_a_file_error(monkeypatch):
    class ExplodingTrust(verify.NoTrust):
        def offline_context(self, moment=None):
            raise RuntimeError("formato sconosciuto")

    with pytest.raises(FileError, match="non è leggibile"):
        verify.validate_in_phases(lambda ctx: None, ExplodingTrust())


def test_cli_main_handles_closed_stdin_and_surprises(monkeypatch, capsys, tmp_path):
    def eof(args):
        raise EOFError

    def boom(args):
        raise RuntimeError("inatteso")

    for handler, code, text in ((eof, 1, "Input terminato"), (boom, 1, "Errore imprevisto")):
        monkeypatch.setattr(cli, "cmd_verifica", handler)
        assert cli.main(["verifica", str(tmp_path / "x.pdf")]) == code
        assert text in capsys.readouterr().err


def test_bare_file_names_are_masked_without_a_folder_prefix():
    logsetup.register_paths("Contratto Rossi.pdf")
    assert logsetup.redact("firmo Contratto Rossi.pdf") == "firmo C*************i.pdf"


def test_network_errors_of_every_kind_are_mapped():
    import requests

    from firmaremota.errors import NetworkError

    api = ArssClient(transport=FakeTransport({"pkcs7signV2": requests.exceptions.ChunkedEncodingError("troncato")}))
    with pytest.raises(NetworkError):
        api.sign_cades(AuthCtx(ACCOUNT, PASSWORD, session_id="0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"), b"x")


def test_window_refuses_to_close_while_a_worker_runs(qtbot, monkeypatch, configured, tmp_path):
    pytest.importorskip("PySide6")
    import threading
    import time

    from firmaremota.gui.main_window import MainWindow

    release = threading.Event()

    def slow_verify(path, cancel=None, original=None):
        release.wait(5)
        raise FileError("fatto")

    window = MainWindow(lambda: FakeArss())
    window.verify_fn = slow_verify
    qtbot.addWidget(window)
    window.show_error = lambda *a: None
    window.verify(str(tmp_path / "x.p7m"))
    qtbot.waitUntil(window.busy, timeout=5000)
    assert window.close() is False and "Attendi" in window.progress.current.text()
    release.set()
    qtbot.waitUntil(lambda: not window.busy(), timeout=5000)
    qtbot.wait(50)
    assert window.close() is True
