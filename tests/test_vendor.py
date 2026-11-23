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
