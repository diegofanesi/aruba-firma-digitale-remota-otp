"""Output file names, and writing that never overwrites and never leaves half-written files."""

from __future__ import annotations

import errno
import os
import re
import tempfile
from pathlib import Path

from .errors import FileError

_P7M_SUFFIX = re.compile(r"(\.(p7m|tsd|tsr))+$", re.IGNORECASE)  # envelope chain kept intact when numbering copies
# Errors meaning "this filesystem can't make hard links" (FAT/exFAT, some network shares).
_NO_LINK = {errno.EPERM, errno.EOPNOTSUPP, errno.ENOTSUP, errno.ENOSYS, errno.EXDEV}
_MAX_COPIES = 999
MAX_SIGN_SIZE = 50 * 1024 * 1024  # bytes; ARSS carries the document base64 inside a SOAP body
MAX_VERIFY_SIZE = 200 * 1024 * 1024  # bytes read into memory for verification/extraction
# Document types the GUI opens with the desktop's default application after extracting them from a
# .p7m. Anything else (.desktop, .html, .svg, .sh, ...) is only shown in its folder: the sender
# chose that name, and "the signature is valid" says nothing about the content being safe to run.
OPENABLE_EXTENSIONS = frozenset({
    ".pdf", ".p7m", ".xml", ".txt", ".csv", ".json", ".rtf",
    ".png", ".jpg", ".jpeg", ".gif", ".tif", ".tiff", ".bmp", ".webp",
    ".odt", ".ods", ".odp", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".zip",
})


def _umask() -> int:
    current = os.umask(0)
    os.umask(current)
    return current


_FILE_MODE = 0o666 & ~_umask()  # what a normal "save" would give the user (read once, at import)


def signed_pdf_name(src: Path) -> str:
    return f"{src.stem}_firmato{src.suffix}"


def p7m_name(src: Path) -> str:
    return f"{src.name}.p7m"


def tsd_name(src: Path) -> str:
    return f"{src.name}.tsd"


def tsr_name(src: Path) -> str:
    return f"{src.name}.tsr"


def candidates(name: str):
    """name, then 'stem (2).ext', 'stem (3).ext', ... keeping a trailing '.p7m'/'.tsd' chain intact."""
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
            os.fchmod(f.fileno(), _FILE_MODE)  # the mode travels with the inode: no chmod-by-path afterwards
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
            os.fchmod(f.fileno(), _FILE_MODE)
    except BaseException:
        os.unlink(target)
        raise


def check_size(path: Path, limit: int) -> str | None:
    """Italian problem description if the file is bigger than `limit` bytes (or can't be stat'ed)."""
    try:
        size = Path(path).stat().st_size
    except OSError as exc:
        return f"Impossibile leggere {Path(path).name}: {exc.strerror}."
    if size > limit:
        return (f"{Path(path).name}: il file è troppo grande ({size // (1024 * 1024)} MB; "
                f"il massimo è {limit // (1024 * 1024)} MB).")
    return None


def safe_to_open(name: str) -> bool:
    return Path(name).suffix.lower() in OPENABLE_EXTENSIONS


def check_writable(directory: Path) -> str | None:
    """Italian problem description, or None if files can be created in `directory`."""
    directory = Path(directory)
    if not directory.is_dir():
        return f"La cartella {directory} non esiste."
    if not os.access(directory, os.W_OK | os.X_OK):
        return f"Non hai il permesso di scrivere nella cartella {directory}."
    return None
