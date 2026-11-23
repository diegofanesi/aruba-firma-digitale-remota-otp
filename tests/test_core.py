"""config, credentials and logsetup."""

import logging
import stat

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.backends import fail
from keyring.errors import PasswordDeleteError

from firmaremota import config, credentials, logsetup


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.data = {}

    def get_password(self, service, username):
        return self.data.get((service, username))

    def set_password(self, service, username, password):
        self.data[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.data:
            raise PasswordDeleteError(username)
        del self.data[(service, username)]


@pytest.fixture
def memory_keyring():
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)


def test_settings_roundtrip_private(tmp_path):
    settings = config.Settings(stamp="si", stamp_page="3", stamp_position="alto-destra")
    path = config.save(settings)
    assert path == tmp_path / "config" / "firma-remota" / "config.ini"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert config.load() == settings


def test_settings_hold_no_personal_data():
    # last_profile is a random id, never an alias or a username
    assert set(config.Settings.__dataclass_fields__) == {"type_hsm", "stamp", "stamp_page", "stamp_position", "last_profile"}


def test_settings_ignore_unknown_keys_and_rewrite_only_preferences():
    path = config.config_path()
    path.parent.mkdir(parents=True)
    path.write_text("[account]\nuser = a\n[preferenze]\nstamp = si\nvecchia_opzione = 1\n")
    assert config.load() == config.Settings(stamp="si")
    config.save(config.load())
    assert "[account]" not in path.read_text() and "user" not in path.read_text()


def test_state_roundtrip_and_corruption():
    assert config.load_state().auth_failures == 0
    config.save_state(config.State(auth_failures=2))
    assert config.load_state().auth_failures == 2
    config.state_path().write_text("{rotto")
    assert config.load_state().auth_failures == 0


def test_store_order(monkeypatch):
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "KDE")
    assert isinstance(credentials.candidate_stores()[0], credentials.KWalletStore)
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "ubuntu:GNOME")
    assert isinstance(credentials.candidate_stores()[0], credentials.SecretServiceStore)


def test_secret_service_store(memory_keyring, monkeypatch):
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "GNOME")
    store = credentials.get_store()
    assert isinstance(store, credentials.SecretServiceStore)
    key = credentials.PASSWORD_KEY
    assert store.get(key) is None
    store.set(key, "Pw-segreta")
    assert memory_keyring.data[("firma-remota", "password")] == "Pw-segreta"
    assert store.get(key) == "Pw-segreta"
    store.delete(key)
    store.delete(key)  # deleting twice is fine
    assert store.get(key) is None


def test_no_store_available(monkeypatch):
    previous = keyring.get_keyring()
    keyring.set_keyring(fail.Keyring())
    monkeypatch.setattr(credentials.KWalletStore, "available", lambda self: False)
    try:
        assert credentials.get_store() is None
    finally:
        keyring.set_keyring(previous)


def test_log_masks_secrets(tmp_path):
    log_file = logsetup.setup(directory=tmp_path / "logs")
    logsetup.register_secret("Pw-segreta-123", "12345678", None, "")
    log = logging.getLogger("firmaremota.test")
    log.info("password=%s otp=%s", "Pw-segreta-123", "12345678")
    try:
        raise RuntimeError("fallito con Pw-segreta-123")
    except RuntimeError:
        log.exception("errore")
    for handler in logging.getLogger("firmaremota").handlers:
        handler.flush()
    text = log_file.read_text()
    assert "Pw-segreta-123" not in text and "12345678" not in text
    assert text.count(logsetup.MASK) >= 3
    assert stat.S_IMODE(log_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(log_file.parent.stat().st_mode) == 0o700
    assert logging.getLogger("zeep").getEffectiveLevel() >= logging.WARNING


@pytest.mark.parametrize(
    ("value", "masked"),
    [("Mario Rossi", "M" + "*" * 9 + "i"), ("mario.rossi@firma", "m" + "*" * 15 + "a"), ("ab", "**"), ("", "")],
)
def test_partial_mask(value, masked):
    assert logsetup.partial(value) == masked


@pytest.mark.parametrize(
    ("name", "masked"),
    [("Contratto affitto.pdf", "C***************o.pdf"), ("fattura.xml.p7m", "f*********l.p7m"),
     ("senza_estensione", "s**************e"), (".bashrc", ".*****c")],
)
def test_file_names_keep_only_first_last_letter_and_extension(name, masked):
    assert logsetup.mask_file_name(name) == masked


def test_log_shows_first_and_last_letter_of_personal_data(tmp_path):
    log_file = logsetup.setup(directory=tmp_path / "logs")
    document = tmp_path / "Documenti" / "Contratto Rossi.pdf"
    logsetup.register_secret("Pw-segreta-123")
    logsetup.register_personal("mario.rossi", "Mario Rossi")
    logsetup.register_paths(document, document.parent)
    log = logging.getLogger("firmaremota.test")
    log.warning("utente %s (%s) firma %s con %s", "mario.rossi", "Mario Rossi", document.name, "Pw-segreta-123")
    try:
        raise FileNotFoundError(f"manca {document}")
    except FileNotFoundError:
        log.exception("errore")
    for handler in logging.getLogger("firmaremota").handlers:
        handler.flush()
    text = log_file.read_text()
    for clear in ("mario.rossi", "Mario Rossi", "Contratto Rossi", "Documenti", "Pw-segreta-123"):
        assert clear not in text
    assert "utente m*********i (M*********i) firma C*************i.pdf con ***" in text
    assert "manca …/C*************i.pdf" in text


def test_signing_log_has_no_file_names(tmp_path, make_pdf, make_p7m):
    from firmaremota import service
    from firmaremota.errors import ServiceError
    from firmaremota.models import Account, Kind, SignJob

    from .fakes import FakeArss

    log_file = logsetup.setup(directory=tmp_path / "logs")
    folder = tmp_path / "Pratica Bianchi"
    folder.mkdir()
    jobs = []
    for name in ("Contratto Bianchi.pdf", "Allegato Bianchi.pdf"):
        (folder / name).write_bytes(make_pdf((595, 842, 0, None)))
        jobs.append(SignJob(folder / name, Kind.PADES))
    api = FakeArss(make_p7m=make_p7m, fail_at={1: ServiceError(f"errore su {folder / 'Allegato Bianchi.pdf'}")})
    service.sign_batch(api, Account("mario.rossi", "firma", "X"), "pw", "12345678", jobs)
    for handler in logging.getLogger("firmaremota").handlers:
        handler.flush()
    text = log_file.read_text()
    assert "Bianchi" not in text
    assert "A" + "*" * 14 + "i.pdf" in text  # "Allegato Bianchi" (16 letters) -> first, 14 stars, last
