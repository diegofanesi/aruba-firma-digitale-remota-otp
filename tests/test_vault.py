"""The encrypted account profile (AES-256-GCM, key from scrypt over the Aruba password)."""

import base64
import json
import stat

import pytest

from firmaremota import config, credentials, logsetup, vault
from firmaremota.errors import CredentialsError
from firmaremota.vault import SCRYPT_N as PRODUCTION_N  # captured before the fast-KDF fixture patches it

PROFILE = vault.Profile("mario.rossi", "firma", "NEW_2025:abc-AS0", "Mario Rossi", "2027-09-01")


class Store:
    name = "prova"

    def __init__(self, data=None):
        self.data = dict(data or {})

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value

    def delete(self, key):
        self.data.pop(key, None)


def test_production_parameters():
    assert PRODUCTION_N >= 2**15 and vault.SCRYPT_R == 8
    assert len(vault._key("pw", b"0" * 16, 2**10, 8, 1)) == 32  # AES-256


def test_roundtrip_and_file_contents():
    path = vault.save(PROFILE, "Pw-segreta-1")
    assert path == vault.path() and stat.S_IMODE(path.stat().st_mode) == 0o600
    text = path.read_text()
    for personal in ("mario", "Rossi", "NEW_2025", "2027"):
        assert personal not in text  # nothing readable on disk
    document = json.loads(text)
    assert document["cipher"] == "AES-256-GCM" and document["kdf"]["name"] == "scrypt"
    assert len(base64.b64decode(document["kdf"]["salt"])) == 16 and len(base64.b64decode(document["nonce"])) == 12
    assert vault.load("Pw-segreta-1") == PROFILE


def test_fresh_salt_and_nonce_every_time():
    first = json.loads(vault.save(PROFILE, "pw").read_text())
    second = json.loads(vault.save(PROFILE, "pw").read_text())
    assert first["kdf"]["salt"] != second["kdf"]["salt"] and first["nonce"] != second["nonce"]
    assert first["data"] != second["data"]


def test_wrong_password():
    vault.save(PROFILE, "giusta")
    with pytest.raises(vault.VaultError, match="La password non apre il profilo"):
        vault.load("sbagliata")


@pytest.mark.parametrize("field", ["data", "nonce", "format"])
def test_tampering_is_detected(field):
    path = vault.save(PROFILE, "pw")
    document = json.loads(path.read_text())
    if field == "format":
        document["format"] = "firma-remota/profilo/2"
    else:
        raw = bytearray(base64.b64decode(document[field]))
        raw[0] ^= 1
        document[field] = base64.b64encode(bytes(raw)).decode()
    path.write_text(json.dumps(document))
    with pytest.raises(vault.VaultError):
        vault.load("pw")


def test_missing_profile():
    with pytest.raises(CredentialsError) as exc:
        vault.load("pw")
    assert "firma configura" in exc.value.message


def test_unlocking_masks_personal_values_in_the_log():
    vault.save(PROFILE, "pw")
    vault.load("pw")
    assert {"mario.rossi", "mario.rossi@firma", "Mario Rossi"} <= logsetup._secrets
    assert "firma" not in logsetup._secrets  # a generic word would mangle every log line


def legacy_ini(**extra):
    path = config.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    values = {"user": "mario.rossi", "domain": "firma", "cert_id": "NEW_2025:abc-AS0", **extra}
    path.write_text("[account]\n" + "".join(f"{k} = {v}\n" for k, v in values.items()))
    return path


def test_migration_from_plain_text(monkeypatch):
    path = legacy_ini(signer_name="Mario Rossi")
    store = Store({"mario.rossi@firma": "Pw-1"})
    monkeypatch.setattr(credentials, "get_store", lambda: store)
    assert vault.migrate_legacy() is True
    assert vault.load("Pw-1") == vault.Profile("mario.rossi", "firma", "NEW_2025:abc-AS0", "Mario Rossi", "")
    assert store.data == {credentials.PASSWORD_KEY: "Pw-1"}
    assert "mario" not in path.read_text() and "[preferenze]" in path.read_text()
    assert vault.migrate_legacy() is False  # nothing left to do


def test_migration_without_saved_password(monkeypatch):
    path = legacy_ini()
    monkeypatch.setattr(credentials, "get_store", lambda: Store())
    assert vault.migrate_legacy() is True
    assert not vault.exists()  # can't encrypt without the password: the user runs 'firma configura'
    assert "mario" not in path.read_text()
