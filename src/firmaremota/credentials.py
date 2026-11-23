"""Password storage: KWallet on KDE, otherwise the freedesktop Secret Service.

Passwords are never written anywhere else. When no store is available the caller asks the
user every time. The OTP is never stored.
"""

from __future__ import annotations

import os
from typing import Protocol

APP_ID = "firma-remota"
SERVICE = "firma-remota"  # Secret Service "service" / KWallet folder
OPEN_TIMEOUT = 120  # seconds: opening the wallet may show an unlock or "allow access" prompt


# Fixed, anonymous entry names: the username is stored as a secret *value*, never in a name or
# attribute (Secret Service attributes are not always encrypted). Nothing else is kept anywhere.
PASSWORD_KEY = "password"
LOGIN_KEY = "utente"  # value: "username@domain"


def split_login(login: str) -> tuple[str, str]:
    """'mario.rossi@firma' -> ('mario.rossi', 'firma'); the domain defaults to 'firma'."""
    user, _, domain = login.strip().partition("@")
    return user.strip(), domain.strip() or "firma"


class CredentialStoreError(Exception):
    """The password store exists but the operation failed (denied, locked, D-Bus error)."""


class Store(Protocol):
    name: str

    def available(self) -> bool: ...
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...
    def delete(self, key: str) -> None: ...


class KWalletStore:
    """Talks to kwalletd over D-Bus with jeepney (pure Python, no dbus-python needed)."""

    name = "KWallet"
    _DAEMONS = (("org.kde.kwalletd6", "/modules/kwalletd6"), ("org.kde.kwalletd5", "/modules/kwalletd5"))

    def __init__(self):
        self._conn = None
        self._addr = None

    def _call(self, method: str, signature: str = "", body: tuple = (), timeout: float = 10):
        from jeepney import new_method_call
        from jeepney.wrappers import DBusErrorResponse, unwrap_msg

        try:
            reply = self._conn.send_and_get_reply(new_method_call(self._addr, method, signature, body), timeout=timeout)
            return unwrap_msg(reply)[0]
        except (DBusErrorResponse, TimeoutError, OSError) as exc:
            raise CredentialStoreError(f"KWallet: {method} non riuscito ({exc})") from exc

    def available(self) -> bool:
        try:
            from jeepney import DBusAddress
            from jeepney.io.blocking import open_dbus_connection
        except ImportError:
            return False
        try:
            self._conn = open_dbus_connection(bus="SESSION")
        except Exception:
            return False
        for bus_name, path in self._DAEMONS:
            self._addr = DBusAddress(path, bus_name=bus_name, interface="org.kde.KWallet")
            try:
                if self._call("isEnabled"):
                    return True
            except CredentialStoreError:
                continue
        self._conn.close()
        self._conn = None
        return False

    def _open(self) -> int:
        wallet = self._call("networkWallet")
        handle = self._call("open", "sxs", (wallet, 0, APP_ID), timeout=OPEN_TIMEOUT)
        if handle < 0:
            raise CredentialStoreError("KWallet: accesso al portafoglio negato o annullato")
        return handle

    def _close(self, handle: int) -> None:
        try:
            self._call("close", "ibs", (handle, False, APP_ID))
        except CredentialStoreError:
            pass

    def get(self, key: str) -> str | None:
        handle = self._open()
        try:
            if not self._call("hasEntry", "isss", (handle, SERVICE, key, APP_ID)):
                return None
            return self._call("readPassword", "isss", (handle, SERVICE, key, APP_ID))
        finally:
            self._close(handle)

    def set(self, key: str, value: str) -> None:
        handle = self._open()
        try:
            if not self._call("hasFolder", "iss", (handle, SERVICE, APP_ID)):
                self._call("createFolder", "iss", (handle, SERVICE, APP_ID))
            if self._call("writePassword", "issss", (handle, SERVICE, key, value, APP_ID)) != 0:
                raise CredentialStoreError("KWallet: impossibile salvare la password")
        finally:
            self._close(handle)

    def delete(self, key: str) -> None:
        handle = self._open()
        try:
            if self._call("hasEntry", "isss", (handle, SERVICE, key, APP_ID)):
                self._call("removeEntry", "isss", (handle, SERVICE, key, APP_ID))
        finally:
            self._close(handle)


class SecretServiceStore:
    """The `keyring` library (GNOME Keyring, KeePassXC, KWallet's Secret Service, ...)."""

    def __init__(self):
        self.name = "Secret Service"

    def available(self) -> bool:
        try:
            import keyring
            from keyring.backends import chainer, fail
        except ImportError:
            return False
        backend = keyring.get_keyring()
        if isinstance(backend, fail.Keyring):
            return False
        if isinstance(backend, chainer.ChainerBackend) and not backend.backends:
            return False
        self.name = f"Secret Service ({type(backend).__module__.rsplit('.', 1)[-1]})"
        return True

    def get(self, key: str) -> str | None:
        import keyring
        from keyring.errors import KeyringError
        try:
            return keyring.get_password(SERVICE, key)
        except KeyringError as exc:
            raise CredentialStoreError(f"Portachiavi: lettura non riuscita ({exc})") from exc

    def set(self, key: str, value: str) -> None:
        import keyring
        from keyring.errors import KeyringError
        try:
            keyring.set_password(SERVICE, key, value)
        except KeyringError as exc:
            raise CredentialStoreError(f"Portachiavi: salvataggio non riuscito ({exc})") from exc

    def delete(self, key: str) -> None:
        import keyring
        from keyring.errors import KeyringError, PasswordDeleteError
        try:
            keyring.delete_password(SERVICE, key)
        except PasswordDeleteError:
            pass
        except KeyringError as exc:
            raise CredentialStoreError(f"Portachiavi: cancellazione non riuscita ({exc})") from exc


def candidate_stores() -> list[Store]:
    on_kde = "KDE" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper().split(":")
    stores: list[Store] = [SecretServiceStore(), KWalletStore()]
    return stores[::-1] if on_kde else stores


def stored_password() -> str | None:
    """The Aruba password saved in the wallet, or None (no wallet, or nothing saved)."""
    store = get_store()
    return store.get(PASSWORD_KEY) if store else None


def stored_login() -> tuple[str, str] | None:
    """(username, domain) saved in the wallet, or None."""
    from .logsetup import register_personal

    store = get_store()
    login = store.get(LOGIN_KEY) if store else None
    if not login:
        return None
    user, domain = split_login(login)
    register_personal(login, user)
    return user, domain


def save_account(store: Store, user: str, domain: str, password: str) -> None:
    store.set(LOGIN_KEY, f"{user}@{domain}")
    store.set(PASSWORD_KEY, password)
    if store.get(PASSWORD_KEY) != password or store.get(LOGIN_KEY) != f"{user}@{domain}":
        raise CredentialStoreError("Il portachiavi non ha restituito i dati appena salvati.")


def forget_account(store: Store) -> None:
    store.delete(PASSWORD_KEY)
    store.delete(LOGIN_KEY)


def get_store() -> Store | None:
    """The first usable password store, or None (then the password is asked every time)."""
    for store in candidate_stores():
        if store.available():
            return store
    return None
