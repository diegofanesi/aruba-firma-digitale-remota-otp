"""Support report shared by `firma diagnostica` and the GUI's "Assistenza" button. Never includes secrets."""

from __future__ import annotations

import datetime as dt
import os
import platform
from dataclasses import dataclass
from importlib import metadata

from . import __version__, config, credentials, logsetup, service, trustlist, vault
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


def _account(password: str | None) -> tuple[list[Line], vault.Profile | None]:
    if not vault.exists():
        return [Line(ERROR, "Account", "non configurato: esegui 'firma configura'")], None
    if password is None:
        return [Line(INFO, "Account", "profilo cifrato presente (si apre con la password Aruba)")], None
    try:
        profile = vault.load(password)
    except vault.VaultError as exc:
        return [Line(ERROR, "Account", exc.message)], None
    lines = [Line(OK if profile.complete else ERROR, "Account",
                  f"{profile.login}, dati cifrati con AES-256" if profile.complete
                  else "certificato non scelto: esegui 'firma configura'")]
    if profile.cert_expires:
        expires = dt.date.fromisoformat(profile.cert_expires)
        left = expires - dt.date.today()
        who = f"di {profile.signer_name}, " if profile.signer_name else ""
        if left.days < 0:
            lines.append(Line(ERROR, "Certificato", f"{who}scaduto il {expires:%d/%m/%Y}: va rinnovato"))
        elif left < EXPIRY_WARNING:
            lines.append(Line(WARNING, "Certificato", f"{who}scade il {expires:%d/%m/%Y}: rinnovalo per tempo"))
        else:
            lines.append(Line(OK, "Certificato", f"{who}valido fino al {expires:%d/%m/%Y}"))
    return lines, profile


def _password() -> list[Line]:
    try:
        store = credentials.get_store()
        if store is None:
            return [Line(WARNING, "Password", "nessun portachiavi disponibile: verrà chiesta ogni volta")]
        saved = store.get(credentials.PASSWORD_KEY) is not None
    except credentials.CredentialStoreError as exc:
        return [Line(ERROR, "Portachiavi", exc.message)]
    if saved:
        return [Line(OK, "Password", f"salvata in {store.name}")]
    return [Line(WARNING, "Password", f"non salvata ({store.name} disponibile): verrà chiesta ogni volta")]


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


def _credentials_check(api, profile: vault.Profile, password: str) -> list[Line]:
    try:
        certs = service.check_credentials(api, service.account_from(profile, config.load()), password)
    except FirmaError as exc:
        return [Line(ERROR, "Credenziali", exc.message)]
    return [Line(OK, "Credenziali", f"accettate da Aruba ({len(certs)} certificato/i)")]


def report(api, password: str | None = None, check_account: bool = False) -> list[Line]:
    """All checks. `password` opens the encrypted profile; `check_account` also asks Aruba (no OTP)."""
    account_lines, profile = _account(password)
    lines = _system() + account_lines + _password() + _failures() + _service(api) + _trust_list()
    if check_account and profile is not None and profile.complete:
        lines += _credentials_check(api, profile, password)
    lines.append(Line(INFO, "Registro", str(logsetup.log_path())))
    return lines


def as_text(lines: list[Line]) -> str:
    width = max(len(tag) for tag in _TAGS.values())
    return "\n".join(f"{_TAGS[line.status]:<{width}}  {line.label}: {line.text}" for line in lines)


def has_errors(lines: list[Line]) -> bool:
    return any(line.status == ERROR for line in lines)
