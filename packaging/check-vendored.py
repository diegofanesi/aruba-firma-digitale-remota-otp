#!/usr/bin/env python3
"""Are the Python libraries bundled in the Arch package still the latest on PyPI?

They are pinned in packaging/arch/aruba-firma/PKGBUILD and do not get security updates through
`pacman -Syu`, so run this now and then (it only reads PyPI's JSON API):

    packaging/check-vendored.py

Exit code 1 if anything is outdated. To update: change the wheel file name, URL and sha256 in the
PKGBUILD (PyPI's JSON gives all three), rebuild with ./install.sh, and bump pkgrel.
"""

import json
import re
import sys
import urllib.request
from pathlib import Path

PKGBUILD = Path(__file__).resolve().parent / "arch" / "aruba-firma" / "PKGBUILD"
WHEEL = re.compile(r"^\s+([A-Za-z0-9_.]+)-([0-9][^-]*)-py3-none-any\.whl\s*$", re.MULTILINE)


def main() -> int:
    text = PKGBUILD.read_text()
    block = text[text.index("_vendored=("):text.index(")", text.index("_vendored=("))]
    outdated = 0
    for name, pinned in WHEEL.findall(block):
        project = name.replace("_", "-")
        try:
            with urllib.request.urlopen(f"https://pypi.org/pypi/{project}/json", timeout=20) as response:
                latest = json.load(response)["info"]["version"]
        except Exception as exc:  # noqa: BLE001
            print(f"{project:24} {pinned:10} ?  (PyPI non raggiungibile: {exc})")
            outdated += 1
            continue
        mark = "ok" if latest == pinned else f"AGGIORNARE -> {latest}"
        print(f"{project:24} {pinned:10} {mark}")
        outdated += latest != pinned
    return 1 if outdated else 0


if __name__ == "__main__":
    sys.exit(main())
