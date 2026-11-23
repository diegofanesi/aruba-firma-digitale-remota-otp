"""Logging to a private file, with every registered secret masked."""

from __future__ import annotations

import faulthandler
import logging
import logging.handlers
import os
import sys
from pathlib import Path

from .config import state_dir

MASK = "***"
# original text -> what the log shows instead; longest originals are replaced first
_replacements: dict[str, str] = {}
# zeep logs whole SOAP envelopes (password and OTP included) at DEBUG; these never go below WARNING.
_NOISY = ("zeep", "urllib3", "requests")
_LIBRARIES = ("pyhanko", "pyhanko_certvalidator")
_MIN_PERSONAL = 3  # shorter values would mangle unrelated words


def partial(text: str) -> str:
    """Only the first and last character stay readable: 'Mario Rossi' -> 'M*********i'."""
    if len(text) <= 2:
        return "*" * len(text)
    return text[0] + "*" * (len(text) - 2) + text[-1]


def mask_file_name(name: str) -> str:
    """'Contratto affitto.pdf' -> 'C***************o.pdf': the extension says nothing personal."""
    stem, ext = os.path.splitext(name)
    if not stem or not (1 < len(ext) <= 6 and ext[1:].isalnum()):
        return partial(name)
    return partial(stem) + ext


def register_secret(*values: str | None) -> None:
    """Hide these values completely in every log line (passwords, OTPs, session ids)."""
    for value in values:
        if value:
            _replacements[value] = MASK


def register_personal(*values: str | None) -> None:
    """Show only the first and last character of these values (usernames, names)."""
    for value in values:
        if value and len(value) >= _MIN_PERSONAL and _replacements.get(value) != MASK:
            _replacements[value] = partial(value)


def register_paths(*paths) -> None:
    """File names and folders the user works with: masked wherever they appear in the log."""
    for path in paths:
        if not path:
            continue
        path = Path(path)
        for candidate in (path, path.resolve()):
            text = str(candidate)
            if len(candidate.name) < _MIN_PERSONAL or _replacements.get(text) == MASK:
                continue
            masked = mask_file_name(candidate.name)
            _replacements[text] = masked if text == candidate.name else f"…/{masked}"
            _replacements.setdefault(candidate.name, masked)


def redact(text: str) -> str:
    for original in sorted(_replacements, key=len, reverse=True):
        text = text.replace(original, _replacements[original])
    return text


class RedactingFormatter(logging.Formatter):
    """Masks secrets in the final text, so messages, arguments and tracebacks are all covered."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def _private_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)  # covers the files RotatingFileHandler creates with default permissions
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
    os.chmod(path, 0o600)


def log_path() -> Path:
    return state_dir() / "firma.log"


def setup(debug: bool = False, console: bool = False, directory: Path | None = None) -> Path:
    """Configure the 'firmaremota' logger; returns the log file path."""
    log_file = directory / "firma.log" if directory else log_path()
    directory = log_file.parent
    _private_file(log_file)
    formatter = RedactingFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(formatter)
    handlers: list[logging.Handler] = [handler]
    if console:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(formatter)
        handlers.append(stream)

    logger = logging.getLogger("firmaremota")
    logger.handlers[:] = handlers
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False
    for name in _NOISY:
        logging.getLogger(name).setLevel(logging.WARNING)
    # pyHanko logs full tracebacks for expected outcomes (e.g. an untrusted chain): file only.
    for name in _LIBRARIES:
        library = logging.getLogger(name)
        library.handlers[:] = [handler]
        library.setLevel(logging.WARNING)
        library.propagate = False

    crash_file = directory / "crash.log"
    _private_file(crash_file)
    faulthandler.enable(open(crash_file, "a"))  # kept open for the process lifetime
    return log_file
