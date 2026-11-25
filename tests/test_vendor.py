"""The bundled-libraries folder of the Arch package (used only when a library isn't installed otherwise)."""

import importlib
import sys

from firmaremota import add_vendor_path


def test_vendor_folder_is_appended_once(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "path", list(sys.path))
    assert add_vendor_path(tmp_path / "manca") is False
    assert add_vendor_path(tmp_path) is True and sys.path[-1] == str(tmp_path)  # after everything else
    assert add_vendor_path(tmp_path) is False and sys.path.count(str(tmp_path)) == 1
    (tmp_path / "libreria_di_prova.py").write_text("VALORE = 42\n")
    try:
        assert importlib.import_module("libreria_di_prova").VALORE == 42
    finally:
        sys.modules.pop("libreria_di_prova", None)


def test_desktop_file_types_are_declared():
    """Every MIME type the launcher claims is either standard or declared by our shared-mime-info file."""
    from pathlib import Path
    from xml.etree import ElementTree

    folder = Path(__file__).resolve().parents[1] / "packaging" / "arch" / "aruba-firma"
    desktop = (folder / "aruba-firma.desktop").read_text()
    claimed = {t for t in next(l for l in desktop.splitlines() if l.startswith("MimeType=")).split("=", 1)[1].split(";") if t}
    ns = "{http://www.freedesktop.org/standards/shared-mime-info}"
    root = ElementTree.parse(folder / "aruba-firma-mime.xml").getroot()
    declared = {m.get("type"): {g.get("pattern") for g in m.findall(f"{ns}glob")} for m in root.findall(f"{ns}mime-type")}
    assert declared == {"application/timestamped-data": {"*.tsd", "*.TSD"}, "application/timestamp-reply": {"*.tsr", "*.TSR"}}
    assert claimed == {"application/pkcs7-mime", "application/pdf", *declared}  # pdf and p7m are standard types
    assert "aruba-firma-mime.xml" in (folder / "PKGBUILD").read_text()
    assert "Exec=env PYTHONNOUSERSITE=1 aruba-firma-gui %F" in desktop  # user site-packages can't shadow the vendored libs
