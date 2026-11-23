"""Output file names, and writing that never overwrites and never leaves half-written files."""

from __future__ import annotations

import errno
import os
import re
import tempfile
from pathlib import Path

from .errors import FileError

_P7M_SUFFIX = re.compile(r"(\.p7m)+$", re.IGNORECASE)
# Errors meaning "this filesystem can't make hard links" (FAT/exFAT, some network shares).
_NO_LINK = {errno.EPERM, errno.EOPNOTSUPP, errno.ENOTSUP, errno.ENOSYS, errno.EXDEV}
_MAX_COPIES = 999


def signed_pdf_name(src: Path) -> str:
    return f"{src.stem}_firmato{src.suffix}"


def p7m_name(src: Path) -> str:
    return f"{src.name}.p7m"


def candidates(name: str):
    """name, then 'stem (2).ext', 'stem (3).ext', ... keeping a trailing '.p7m' chain intact."""
    yield name
    p7m = _P7M_SUFFIX.search(name)
    base, tail = (name[: p7m.start()], p7m.group(0)) if p7m else (name, "")
    stem, ext = os.path.splitext(base)
    if not stem:  # dotfile like ".p7m" or ".bashrc"
        stem, ext = base, ""
    for n in range(2, _MAX_COPIES + 1):
        yield f"{stem} ({n}){ext}{tail}"


def write_new(directory: Path, name: str, data: bytes) -> Path:
    """Write `data` as a new file in `directory`; returns the path actually used.

    The data goes to a private temporary file first and is then hard-linked to the first free
    name, which is atomic and can't replace an existing file. Where hard links aren't supported
    the file is created with O_EXCL instead.
    """
    directory = Path(directory)
    try:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".firma-remota-", suffix=".tmp")
    except OSError as exc:
        raise FileError(f"Impossibile scrivere nella cartella {directory}: {exc.strerror}") from exc
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        use_links = True
        for candidate in candidates(name):
            target = directory / candidate
            if use_links:
                try:
                    os.link(tmp, target)
                    break
                except FileExistsError:
                    continue
                except OSError as exc:
                    if exc.errno not in _NO_LINK:
                        raise
                    use_links = False
            try:
                _write_exclusive(target, data)
                break
            except FileExistsError:
                continue
        else:
            raise FileError(f"Troppe copie di {name} in {directory}: scegli un'altra cartella.")
        os.chmod(target, 0o644)
        return target
    except OSError as exc:
        raise FileError(f"Impossibile salvare {name} in {directory}: {exc.strerror}") from exc
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _write_exclusive(target: Path, data: bytes) -> None:
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        os.unlink(target)
        raise


def check_writable(directory: Path) -> str | None:
    """Italian problem description, or None if files can be created in `directory`."""
    directory = Path(directory)
    if not directory.is_dir():
        return f"La cartella {directory} non esiste."
    if not os.access(directory, os.W_OK | os.X_OK):
        return f"Non hai il permesso di scrivere nella cartella {directory}."
    return None
