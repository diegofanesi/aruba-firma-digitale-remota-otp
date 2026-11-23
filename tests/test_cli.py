import pytest

from firmaremota import cli

PDF = b"%PDF-1.7\nfinto pdf\n"


def test_estrai(tmp_path, make_p7m, capsys):
    src = tmp_path / "contratto.pdf.p7m"
    src.write_bytes(make_p7m(make_p7m(PDF)))
    assert cli.main(["estrai", str(src)]) == 0
    out = capsys.readouterr().out
    assert (tmp_path / "contratto.pdf").read_bytes() == PDF
    assert "Firma 1 di 2: Mario Rossi" in out
    assert "non è stata verificata" in out
    # a second extraction never overwrites the first
    assert cli.main(["estrai", str(src)]) == 0
    assert (tmp_path / "contratto (2).pdf").read_bytes() == PDF


def test_estrai_to_folder(tmp_path, make_p7m):
    src = tmp_path / "fattura.p7m"
    src.write_bytes(make_p7m(b'<?xml version="1.0"?><f/>'))
    out_dir = tmp_path / "uscita"
    out_dir.mkdir()
    assert cli.main(["estrai", str(src), "--cartella", str(out_dir)]) == 0
    assert (out_dir / "fattura.xml").exists()


def test_estrai_errors(tmp_path, capsys):
    bad = tmp_path / "rotto.p7m"
    bad.write_bytes(b"non sono una firma")
    assert cli.main(["estrai", str(bad)]) == 1
    assert "Errore:" in capsys.readouterr().err
    assert cli.main(["estrai", str(tmp_path / "manca.p7m")]) == 1


@pytest.mark.parametrize("argv", [["--help"], ["estrai", "--help"]])
def test_help_is_italian(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("uso: firma")
    assert "opzioni:" in out and "mostra questo aiuto" in out
    for english in ("usage:", "options:", "show this help", "positional arguments"):
        assert english not in out


def test_usage_errors_are_italian(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["estrai"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "errore: mancano questi argomenti obbligatori: FILE" in err


def test_no_command_shows_help(capsys):
    assert cli.main([]) == 2
    assert "comandi:" in capsys.readouterr().out
