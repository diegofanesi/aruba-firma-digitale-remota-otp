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
    settings = config.Settings(user="mario.rossi", domain="firma", cert_id="NEW_2025:abc-AS0")
    path = config.save(settings)
    assert path == tmp_path / "config" / "firma-remota" / "config.ini"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert config.load() == settings
    assert config.load().complete


def test_settings_ignore_unknown_keys(tmp_path):
    path = config.config_path()
    path.parent.mkdir(parents=True)
    path.write_text("[account]\nuser = a\ndomain = firma\nvecchia_opzione = 1\n")
    assert config.load() == config.Settings(user="a", domain="firma")


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
    key = credentials.account_key("mario.rossi", "firma")
    assert store.get(key) is None
    store.set(key, "Pw-segreta")
    assert memory_keyring.data[("firma-remota", "mario.rossi@firma")] == "Pw-segreta"
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
