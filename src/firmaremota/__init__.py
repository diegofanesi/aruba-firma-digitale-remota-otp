"""Client per la firma digitale remota Aruba (ARSS)."""

import sys
from pathlib import Path

__version__ = "0.3.2"

# The Arch package ships the few pure-Python libraries that the official repositories lack
# (pyHanko and its helpers) in this folder. It goes *after* the normal import path, so a copy
# installed system-wide or in a virtualenv always wins over the bundled one.
VENDOR_DIR = Path("/usr/lib/aruba-firma/vendor")


def add_vendor_path(folder: Path = VENDOR_DIR) -> bool:
    """Make the bundled libraries importable if the folder exists; True if it was added now."""
    if not folder.is_dir() or str(folder) in sys.path:
        return False
    sys.path.append(str(folder))
    return True


add_vendor_path()
