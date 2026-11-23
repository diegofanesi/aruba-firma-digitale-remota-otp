import errno
import os
import stat
from itertools import islice
from pathlib import Path

import pytest

from firmaremota import files
from firmaremota.errors import FileError


def test_output_names():
    assert files.signed_pdf_name(Path("/a/Contratto 2026.pdf")) == "Contratto 2026_firmato.pdf"
    assert files.p7m_name(Path("/a/fattura.xml")) == "fattura.xml.p7m"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("x.pdf.p7m", ["x.pdf.p7m", "x (2).pdf.p7m", "x (3).pdf.p7m"]),
        ("x_firmato.pdf", ["x_firmato.pdf", "x_firmato (2).pdf", "x_firmato (3).pdf"]),
        ("senza-estensione", ["senza-estensione", "senza-estensione (2)", "senza-estensione (3)"]),
        ("doppia.pdf.P7M.p7m", ["doppia.pdf.P7M.p7m", "doppia (2).pdf.P7M.p7m", "doppia (3).pdf.P7M.p7m"]),
    ],
)
def test_candidates(name, expected):
    assert list(islice(files.candidates(name), 3)) == expected


def test_write_new_never_overwrites(tmp_path):
    first = files.write_new(tmp_path, "Perché è così.pdf", b"uno")
    second = files.write_new(tmp_path, "Perché è così.pdf", b"due")
    third = files.write_new(tmp_path, "Perché è così.pdf", b"tre")
    assert [p.name for p in (first, second, third)] == ["Perché è così.pdf", "Perché è così (2).pdf", "Perché è così (3).pdf"]
    assert [p.read_bytes() for p in (first, second, third)] == [b"uno", b"due", b"tre"]
    assert stat.S_IMODE(first.stat().st_mode) == 0o644
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(p.name for p in (first, second, third))


def test_write_new_without_hard_links(tmp_path, monkeypatch):
    (tmp_path / "a.pdf").write_bytes(b"esistente")

    def no_links(src, dst):
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(files.os, "link", no_links)
    out = files.write_new(tmp_path, "a.pdf", b"nuovo")
    assert out.name == "a (2).pdf"
    assert out.read_bytes() == b"nuovo"
    assert (tmp_path / "a.pdf").read_bytes() == b"esistente"
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_write_new_race(tmp_path, monkeypatch):
    """Another program creates the same name between our check and our write: it must survive."""
    real_link = os.link

    def racing_link(src, dst):
        if Path(dst).name == "gara.pdf":
            Path(dst).write_bytes(b"dell'altro programma")
        return real_link(src, dst)

    monkeypatch.setattr(files.os, "link", racing_link)
    out = files.write_new(tmp_path, "gara.pdf", b"nostro")
    assert out.name == "gara (2).pdf"
    assert (tmp_path / "gara.pdf").read_bytes() == b"dell'altro programma"


def test_write_new_unwritable_folder(tmp_path):
    locked = tmp_path / "bloccata"
    locked.mkdir(mode=0o500)
    try:
        assert files.check_writable(locked) is not None
        with pytest.raises(FileError, match="Impossibile scrivere"):
            files.write_new(locked, "a.pdf", b"x")
    finally:
        locked.chmod(0o700)


def test_check_writable(tmp_path):
    assert files.check_writable(tmp_path) is None
    assert "non esiste" in files.check_writable(tmp_path / "manca")
