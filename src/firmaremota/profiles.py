"""Signing accounts ("profili"): an alias chosen by the user, username@domain, and a password.

Everything lives in the wallet; nothing is written to disk. Entry names are fixed or random,
never personal:

    profili         JSON list of {"id", "alias", "login", "marca", "marca_aruba", "schema"} (the value is what
                    the wallet encrypts); "marca" = who timestamps the signatures: "automatica" (default:
                    Aruba's when the service includes it, else the free Belgian one), "aruba", "belgio",
                    "no"; older versions stored true/false (true = Aruba), and before schema 2 "belgio"
                    meant what "automatica" means now. "marca_aruba" = {"inclusa": bool, "rilevata":
                    "AAAA-MM-GG"}: whether Aruba's signatures came back with a timestamp on their own
    password:<id>   the password of that profile; absent when the user chose not to remember it
    marca:<id>      JSON {"user", "password", "url"} of a separate time-stamping (TSA) account; absent
                    when the signing credentials themselves are used for timestamps

Older versions kept a single account in the entries `utente` and `password`; it is turned into a
profile the first time the list is read.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import secrets
from dataclasses import dataclass, replace

from .credentials import LOGIN_KEY, PASSWORD_KEY, CredentialStoreError, Store, split_login
from .errors import CredentialsError
from .logsetup import register_personal, register_secret
from .models import TimestampSource, TsaCredentials

log = logging.getLogger("firmaremota.profiles")

INDEX_KEY = "profili"
SCHEMA = 2  # 2: "automatica" exists, so "belgio" is a deliberate choice


@dataclass(frozen=True)
class Profile:
    id: str  # random and opaque: names the password entry and is what config.ini remembers as "last used"
    alias: str
    user: str
    domain: str
    timestamp: TimestampSource = TimestampSource.AUTO
    aruba_marks: bool | None = None  # does the account's service include Aruba's timestamps? None: not seen yet
    aruba_marks_seen: str | None = None  # ISO date when the current `aruba_marks` value was first seen

    @property
    def login(self) -> str:
        return f"{self.user}@{self.domain}"

    @property
    def password_key(self) -> str:
        return f"password:{self.id}"

    @property
    def tsa_key(self) -> str:
        return f"marca:{self.id}"


def new_profile(alias: str, user: str, domain: str, id: str | None = None,
                timestamp: TimestampSource = TimestampSource.AUTO) -> Profile:
    if "@" in user:  # "utente@dominio" typed as the username, the way Aruba's selfcare shows it
        user, domain = split_login(user)
    alias, user, domain = alias.strip(), user.strip(), domain.strip() or "firma"
    if not alias:
        raise CredentialsError("Dai un nome all'account (per esempio il nome di chi firma).")
    if not user:
        raise CredentialsError("Serve il nome utente Aruba.")
    return Profile(id or secrets.token_hex(8), alias, user, domain, TimestampSource(timestamp))


def _register(profile: Profile) -> None:
    register_personal(profile.alias, profile.login, profile.user)


def timestamp_source(raw) -> TimestampSource:
    """The stored "marca" value: true/false from older versions (true was Aruba), or a source name."""
    if raw is True:
        return TimestampSource.ARUBA
    if raw is None or raw is False:
        return TimestampSource.NONE
    try:
        return TimestampSource(raw)
    except ValueError:
        log.warning("impostazione della marca temporale non riconosciuta: nessuna marca")
        return TimestampSource.NONE


def load_all(store: Store) -> list[Profile]:
    raw = store.get(INDEX_KEY)
    if raw is None:
        return _migrate_legacy(store)
    try:
        profiles = []
        for item in json.loads(raw):
            user, domain = split_login(item["login"])
            source = timestamp_source(item.get("marca"))
            if source is TimestampSource.BELGIUM and item.get("schema", 1) < 2:
                source = TimestampSource.AUTO  # what "belgio" did before "automatica" existed
            marks = item.get("marca_aruba") if isinstance(item.get("marca_aruba"), dict) else {}
            included = marks.get("inclusa")
            profiles.append(Profile(str(item["id"]), str(item["alias"]), user, domain, source,
                                    included if isinstance(included, bool) else None,
                                    str(marks["rilevata"]) if isinstance(included, bool) and marks.get("rilevata") else None))
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise CredentialStoreError("L'elenco degli account nel portachiavi è danneggiato.", detail=str(exc)) from None
    for profile in profiles:
        _register(profile)
    return profiles


def _item(p: Profile) -> dict:
    item = {"id": p.id, "alias": p.alias, "login": p.login, "marca": p.timestamp.value, "schema": SCHEMA}
    if p.aruba_marks is not None:
        item["marca_aruba"] = {"inclusa": p.aruba_marks, "rilevata": p.aruba_marks_seen}
    return item


def save_all(store: Store, profiles: list[Profile]) -> None:
    store.set(INDEX_KEY, json.dumps([_item(p) for p in profiles]))


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


def record_aruba_marks(store: Store, profiles: list[Profile], profile: Profile, included: bool,
                       today: dt.date | None = None) -> list[Profile]:
    """Remember whether the account's signatures come back from Aruba with a timestamp. Written only when
    it changes, so the date is when the current answer was first seen."""
    current = by_id(profiles, profile.id) or profile
    if current.aruba_marks is included:
        return profiles
    updated = replace(current, aruba_marks=included, aruba_marks_seen=(today or dt.date.today()).isoformat())
    return upsert(store, profiles, updated)


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


def tsa_credentials(store: Store | None, profile: Profile | None) -> TsaCredentials | None:
    """The TSA account saved for the profile, or None.

    None is the normal case for Aruba's Firma Remota: its included timestamps are applied by Aruba's
    server itself ("Marca Automatica" in the SelfCare, format LT), with no TSA credentials at all; a
    TSA account is a separate product (a pack of marks), needed only for standalone .tsd/.tsr marks.
    """
    if store is None or profile is None:
        return None
    return tsa_account(store, profile)


def set_tsa(store: Store, profile: Profile, tsa: TsaCredentials) -> None:
    register_secret(tsa.password)
    store.set(profile.tsa_key, json.dumps({"user": tsa.user, "password": tsa.password, "url": tsa.url}))


def forget_tsa(store: Store, profile: Profile) -> None:
    store.delete(profile.tsa_key)
