"""Personal account data, encrypted at rest with a key derived from the Aruba password.

AES-256-GCM; the 256-bit key comes from scrypt over the password with a random salt. A new salt
and nonce are drawn on every save, and the format string is authenticated with the data, so a
wrong password and a tampered file are both rejected. The password itself is never stored here:
it lives in the system wallet (or is typed each time), and anything in the profile can be
fetched again from Aruba, so losing the password only means running `firma configura` again.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .config import config_dir
from .errors import CredentialsError
from .logsetup import register_personal as _mask_in_log

FORMAT = "firma-remota/profilo/1"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1  # ~32 MiB of memory per derivation


class VaultError(CredentialsError):
    """The profile can't be opened: wrong password, or the file is damaged."""


@dataclass
class Profile:
    user: str = ""
    domain: str = ""  # ARSS typeOtpAuth
    cert_id: str = ""
    signer_name: str = ""  # certificate holder, written in the visible stamp
    cert_expires: str = ""  # ISO date

    @property
    def complete(self) -> bool:
        return bool(self.user and self.domain and self.cert_id)

    @property
    def login(self) -> str:
        return f"{self.user}@{self.domain}"


def path() -> Path:
    return config_dir() / "profilo.enc"


def exists(location: Path | None = None) -> bool:
    return (location or path()).is_file()


def _key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def save(profile: Profile, password: str, location: Path | None = None) -> Path:
    if not password:
        raise CredentialsError("Serve la password per cifrare il profilo.")
    location = location or path()
    salt, nonce = os.urandom(16), os.urandom(12)
    plaintext = json.dumps(asdict(profile), ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(_key(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)).encrypt(nonce, plaintext, FORMAT.encode())
    document = {
        "format": FORMAT,
        "cipher": "AES-256-GCM",
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)},
        "nonce": _b64(nonce),
        "data": _b64(ciphertext),
    }
    location.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = location.with_name(location.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(document, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, location)
    return location


def load(password: str, location: Path | None = None) -> Profile:
    """Decrypt the profile. Personal values are masked in the log from then on."""
    location = location or path()
    try:
        document = json.loads(location.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CredentialsError("Account non configurato: esegui 'firma configura'.") from None
    except (OSError, ValueError) as exc:
        raise VaultError("Il profilo cifrato è danneggiato: esegui di nuovo 'firma configura'.", detail=str(exc)) from None
    try:
        if document.get("format") != FORMAT or document.get("cipher") != "AES-256-GCM":
            raise ValueError(f"formato sconosciuto: {document.get('format')}")
        kdf = document["kdf"]
        key = _key(password, base64.b64decode(kdf["salt"]), int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
        plaintext = AESGCM(key).decrypt(base64.b64decode(document["nonce"]), base64.b64decode(document["data"]),
                                        FORMAT.encode())
        data = json.loads(plaintext)
    except InvalidTag:
        raise VaultError(
            "La password non apre il profilo: è sbagliata, oppure l'hai cambiata sul sito Aruba "
            "(in quel caso esegui 'firma configura')."
        ) from None
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError("Il profilo cifrato è danneggiato: esegui di nuovo 'firma configura'.", detail=str(exc)) from None
    known = {f.name for f in fields(Profile)}
    profile = Profile(**{k: v for k, v in data.items() if k in known})
    register_personal(profile)
    return profile


def register_personal(profile: Profile) -> None:
    """From now on the log shows only the first and last letter of the username and holder name."""
    _mask_in_log(profile.login, profile.user, profile.signer_name)


def migrate_legacy() -> bool:
    """Move plain-text account data from older versions into the encrypted profile.

    Needs the old wallet entry ("utente@dominio") to encrypt with; without it the user simply
    runs `firma configura` again. Returns True if something was migrated.
    """
    from . import config, credentials

    legacy = config.legacy_account()
    if legacy is None:
        return False
    store = credentials.get_store()
    old_key = credentials.legacy_key(legacy["user"], legacy["domain"])
    password = store.get(old_key) if store else None
    if password and not exists():
        save(Profile(**legacy), password)
        store.set(credentials.PASSWORD_KEY, password)
    if password:
        store.delete(old_key)
    config.save(config.load())  # rewrites the file without the plain-text account section
    return True


def delete(location: Path | None = None) -> None:
    try:
        (location or path()).unlink()
    except FileNotFoundError:
        pass

