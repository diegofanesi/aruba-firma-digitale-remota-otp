"""Signing accounts ("profili"): an alias chosen by the user, username@domain, and a password.

Everything lives in the wallet; nothing is written to disk. Entry names are fixed or random,
never personal:

    profili         JSON list of {"id", "alias", "login", "marca"} (the value is what the wallet encrypts);
                    "marca" (default true) = sign with a timestamp, ArubaSign's "Marca sempre i file firmati"
    password:<id>   the password of that profile; absent when the user chose not to remember it
    marca:<id>      JSON {"user", "password", "url"} of a separate time-stamping (TSA) account; absent
                    when the signing credentials themselves are used for timestamps

Older versions kept a single account in the entries `utente` and `password`; it is turned into a
profile the first time the list is read.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from .credentials import LOGIN_KEY, PASSWORD_KEY, CredentialStoreError, Store, split_login
from .errors import CredentialsError
from .logsetup import register_personal, register_secret
from .models import TsaCredentials

INDEX_KEY = "profili"


@dataclass(frozen=True)
class Profile:
    id: str  # random and opaque: names the password entry and is what config.ini remembers as "last used"
    alias: str
    user: str
    domain: str
    timestamp: bool = True  # sign with a timestamp by default ("Marca sempre i file firmati")

    @property
    def login(self) -> str:
        return f"{self.user}@{self.domain}"

    @property
    def password_key(self) -> str:
        return f"password:{self.id}"

    @property
    def tsa_key(self) -> str:
        return f"marca:{self.id}"


def new_profile(alias: str, user: str, domain: str, id: str | None = None, timestamp: bool = True) -> Profile:
    if "@" in user:  # "utente@dominio" typed as the username, the way Aruba's selfcare shows it
        user, domain = split_login(user)
    alias, user, domain = alias.strip(), user.strip(), domain.strip() or "firma"
    if not alias:
        raise CredentialsError("Dai un nome all'account (per esempio il nome di chi firma).")
    if not user:
        raise CredentialsError("Serve il nome utente Aruba.")
    return Profile(id or secrets.token_hex(8), alias, user, domain, timestamp)


def _register(profile: Profile) -> None:
    register_personal(profile.alias, profile.login, profile.user)


def load_all(store: Store) -> list[Profile]:
    raw = store.get(INDEX_KEY)
    if raw is None:
        return _migrate_legacy(store)
    try:
        profiles = []
        for item in json.loads(raw):
            user, domain = split_login(item["login"])
            profiles.append(Profile(str(item["id"]), str(item["alias"]), user, domain, bool(item.get("marca", True))))
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise CredentialStoreError("L'elenco degli account nel portachiavi è danneggiato.", detail=str(exc)) from None
    for profile in profiles:
        _register(profile)
    return profiles


def save_all(store: Store, profiles: list[Profile]) -> None:
    store.set(INDEX_KEY, json.dumps([{"id": p.id, "alias": p.alias, "login": p.login, "marca": p.timestamp}
                                     for p in profiles]))


def _migrate_legacy(store: Store) -> list[Profile]:
    login = store.get(LOGIN_KEY)
    if not login:
        return []
    user, domain = split_login(login)
    profile = new_profile(user, user, domain)
    password = store.get(PASSWORD_KEY)
    if password:
        store.set(profile.password_key, password)
    save_all(store, [profile])
    store.delete(LOGIN_KEY)
    store.delete(PASSWORD_KEY)
    _register(profile)
    return [profile]


def find(profiles: list[Profile], alias: str) -> Profile | None:
    wanted = alias.strip().casefold()
    return next((p for p in profiles if p.alias.casefold() == wanted), None)


def by_id(profiles: list[Profile], id: str | None) -> Profile | None:
    return next((p for p in profiles if p.id == id), None) if id else None


def upsert(store: Store, profiles: list[Profile], profile: Profile) -> list[Profile]:
    """Add `profile`, or replace the one with the same id. Aliases must be unique."""
    clash = find(profiles, profile.alias)
    if clash is not None and clash.id != profile.id:
        raise CredentialsError(f"C'è già un account chiamato «{clash.alias}»: scegli un altro nome.")
    updated = [profile if p.id == profile.id else p for p in profiles]
    if by_id(updated, profile.id) is None:
        updated.append(profile)
    save_all(store, updated)
    _register(profile)
    return updated


def remove(store: Store, profiles: list[Profile], profile: Profile) -> list[Profile]:
    store.delete(profile.password_key)
    store.delete(profile.tsa_key)
    updated = [p for p in profiles if p.id != profile.id]
    save_all(store, updated)
    return updated


def password(store: Store, profile: Profile) -> str | None:
    return store.get(profile.password_key)


def set_password(store: Store, profile: Profile, value: str) -> None:
    store.set(profile.password_key, value)
    if store.get(profile.password_key) != value:
        raise CredentialStoreError("Il portachiavi non ha restituito la password appena salvata.")


def forget_password(store: Store, profile: Profile) -> None:
    store.delete(profile.password_key)


def forget_all(store: Store, profiles: list[Profile]) -> None:
    for profile in profiles:
        store.delete(profile.password_key)
        store.delete(profile.tsa_key)
    for key in (INDEX_KEY, LOGIN_KEY, PASSWORD_KEY):
        store.delete(key)


# --- the time-stamping account ---------------------------------------------------------------------

def tsa_account(store: Store, profile: Profile) -> TsaCredentials | None:
    """The separate TSA account saved for this profile, if any."""
    raw = store.get(profile.tsa_key)
    if not raw:
        return None
    try:
        item = json.loads(raw)
        tsa = TsaCredentials(str(item["user"]), str(item["password"]), item.get("url") or None)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise CredentialStoreError("Le credenziali della marca temporale nel portachiavi sono danneggiate.",
                                   detail=str(exc)) from None
    register_secret(tsa.password)
    register_personal(tsa.user)
    return tsa


def tsa_credentials(store: Store | None, profile: Profile | None, user: str, password: str) -> TsaCredentials:
    """What to send as the TSA account: the one saved for the profile, else the signing credentials
    (Aruba's Firma Remota includes timestamps; the live test confirms the same credentials work)."""
    saved = tsa_account(store, profile) if store is not None and profile is not None else None
    return saved or TsaCredentials(user, password)


def set_tsa(store: Store, profile: Profile, tsa: TsaCredentials) -> None:
    register_secret(tsa.password)
    store.set(profile.tsa_key, json.dumps({"user": tsa.user, "password": tsa.password, "url": tsa.url}))


def forget_tsa(store: Store, profile: Profile) -> None:
    store.delete(profile.tsa_key)
