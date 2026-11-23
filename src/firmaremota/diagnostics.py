"""Support report shared by `firma diagnostica` and the GUI's "Assistenza" button. Never includes secrets."""

from __future__ import annotations

import datetime as dt
import os
import platform
from dataclasses import dataclass
from importlib import metadata

from . import __version__, credentials, logsetup, profiles, service, trustlist
from .errors import FirmaError

OK, WARNING, ERROR, INFO = "ok", "avviso", "errore", "info"
_TAGS = {OK: "[OK]", WARNING: "[AVVISO]", ERROR: "[ERRORE]", INFO: "[INFO]"}
EXPIRY_WARNING = dt.timedelta(days=60)


@dataclass(frozen=True)
class Line:
    status: str
    label: str
    text: str


def _version(package: str) -> str:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return "non installato"


def _system() -> list[Line]:
    try:
        distro = platform.freedesktop_os_release().get("PRETTY_NAME", "?")
    except OSError:
        distro = platform.platform()
    libc, libc_version = platform.libc_ver()
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "?")
    session = os.environ.get("XDG_SESSION_TYPE", "?")
    return [
        Line(INFO, "Programma", f"firma-remota {__version__}, Python {platform.python_version()}"),
        Line(INFO, "Sistema", f"{distro}, {libc or 'libc'} {libc_version or '?'}, {platform.machine()}"),
        Line(INFO, "Desktop", f"{desktop} ({session})"),
        Line(INFO, "Librerie", f"zeep {_version('zeep')}, pyHanko {_version('pyhanko')}, "
                               f"PySide6 {_version('PySide6-Essentials')}"),
    ]


def _accounts(store) -> tuple[list[Line], list[profiles.Profile]]:
    if store is None:
        return [Line(INFO, "Account", "nessun portachiavi: nome utente e password vengono chiesti a ogni firma")], []
    try:
        available = profiles.load_all(store)
        saved = {p.id: profiles.password(store, p) is not None for p in available}
    except credentials.CredentialStoreError as exc:
        return [Line(ERROR, "Portachiavi", exc.message)], []
    if not available:
        return [Line(WARNING, "Account", f"nessuno salvato in {store.name}: verrà chiesto a ogni firma "
                                         "('firma configura' per salvarlo)")], []
    lines = [Line(INFO, "Portachiavi", f"{store.name}, {len(available)} account; sul disco nulla")]
    for p in available:
        detail = "password salvata" if saved[p.id] else "password non salvata: verrà chiesta"
        lines.append(Line(OK if saved[p.id] else WARNING, f"Account «{logsetup.partial(p.alias)}»",
                          f"{logsetup.partial(p.user)}@{p.domain}, {detail}"))
    return lines, available


def _failures() -> list[Line]:
    failures = service.auth_failures()
    if not failures:
        return []
    return [Line(WARNING, "Accessi rifiutati", f"{failures} di fila: un altro errore potrebbe bloccare l'account")]


def _service(api) -> list[Line]:
    try:
        api.ping()
        return [Line(OK, "Servizio Aruba", "raggiungibile")]
    except FirmaError as exc:
        return [Line(ERROR, "Servizio Aruba", exc.message)]


def _trust_list() -> list[Line]:
    fetched = trustlist.cached_date()
    if fetched is None:
        return [Line(INFO, "Elenco certificatori", "non ancora scaricato: succederà alla prima verifica")]
    status = OK if dt.datetime.now(dt.timezone.utc) - fetched < trustlist.MAX_AGE else INFO
    return [Line(status, "Elenco certificatori", f"scaricato il {fetched.astimezone():%d/%m/%Y}")]


def _certificates(api, store, available: list[profiles.Profile]) -> list[Line]:
    """Ask Aruba (password only, no OTP) about every account with a saved password."""
    lines = []
    for p in available:
        password = profiles.password(store, p)
        if not password:
            continue
        label = f"Credenziali «{logsetup.partial(p.alias)}»"
        try:
            _, signer = service.prepare_account(api, p.user, p.domain, password)
        except FirmaError as exc:
            lines.append(Line(ERROR, label, exc.message))
            continue
        expires = signer.not_after.astimezone().date()
        if expires - dt.date.today() < EXPIRY_WARNING:
            lines.append(Line(WARNING, label, f"accettate; il certificato scade il {expires:%d/%m/%Y}: rinnovalo"))
        else:
            lines.append(Line(OK, label, f"accettate; certificato valido fino al {expires:%d/%m/%Y}"))
    return lines


def report(api, check_credentials: bool = False) -> list[Line]:
    """All local checks; with `check_credentials` it also asks Aruba about each saved account (no OTP)."""
    store = credentials.get_store()
    account_lines, available = _accounts(store)
    lines = _system() + account_lines + _failures() + _service(api) + _trust_list()
    if check_credentials and available:
        lines += _certificates(api, store, available)
    lines.append(Line(INFO, "Registro", str(logsetup.log_path())))
    return lines


def as_text(lines: list[Line]) -> str:
    width = max(len(tag) for tag in _TAGS.values())
    return "\n".join(f"{_TAGS[line.status]:<{width}}  {line.label}: {line.text}" for line in lines)


def has_errors(lines: list[Line]) -> bool:
    return any(line.status == ERROR for line in lines)
