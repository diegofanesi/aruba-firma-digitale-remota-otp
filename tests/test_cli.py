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


# --- signing and verification ------------------------------------------------------------------

from firmaremota import config, credentials  # noqa: E402
from firmaremota.arss.client import MSG_OTP  # noqa: E402
from firmaremota.errors import OtpError, ServiceError  # noqa: E402

from .fakes import FakeArss, signer_info  # noqa: E402
from .test_verify import RootsTrust  # noqa: E402

A4 = (595, 842, 0, None)


@pytest.fixture
def api(monkeypatch, make_p7m):
    config.save(config.Settings(user="mario.rossi", domain="firma", cert_id="NEW_2025:abc-AS0", signer_name="Mario Rossi"))

    class Store:
        name = "finto"

        def get(self, key):
            return "pw-dal-portachiavi"

    monkeypatch.setattr(credentials, "get_store", lambda: Store())
    fake = FakeArss(make_p7m=make_p7m)
    monkeypatch.setattr(cli, "make_api", lambda: fake)
    return fake


def answers(monkeypatch, *values):
    asked, replies = [], iter(values)

    def fake_input(prompt=""):
        asked.append(prompt)
        return next(replies)

    monkeypatch.setattr("builtins.input", fake_input)
    return asked


def test_pdf_batch_one_otp(api, tmp_path, make_pdf, monkeypatch, capsys):
    for name in ("a.pdf", "b.pdf"):
        (tmp_path / name).write_bytes(make_pdf(A4))
    answers(monkeypatch, "1234 5678")
    assert cli.main(["pdf", str(tmp_path / "a.pdf"), str(tmp_path / "b.pdf")]) == 0
    out = capsys.readouterr().out
    assert "Firmo 2 file con un solo codice OTP" in out and out.count("Firmato:") == 2
    assert (tmp_path / "a_firmato.pdf").exists() and (tmp_path / "b_firmato.pdf").exists()
    assert api.calls[0] == ("open_session", "12345678")
    assert api.names().count("open_session") == 1


def test_p7m(api, tmp_path, monkeypatch):
    (tmp_path / "fattura.xml").write_bytes(b"<f/>")
    answers(monkeypatch, "12345678")
    assert cli.main(["p7m", str(tmp_path / "fattura.xml")]) == 0
    assert (tmp_path / "fattura.xml.p7m").exists()


def test_stamp_text_and_page(api, tmp_path, make_pdf, monkeypatch):
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4, A4))
    answers(monkeypatch, "12345678")
    assert cli.main(["pdf", "--timbro", "--pagina", "1", "--posizione", "alto-sinistra", "--testo", "Visto",
                     str(tmp_path / "a.pdf")]) == 0
    _, _, _, stamp, text = api.calls[1]
    assert stamp.page == 1 and stamp.llx == 36 and stamp.ury == 806
    assert text == "Firmato digitalmente da Mario Rossi\nVisto"


def test_signer_name_fetched_once(api, tmp_path, make_pdf, monkeypatch):
    config.save(config.Settings(user="mario.rossi", domain="firma", cert_id="NEW_2025:abc-AS0"))
    api.certs = [("NEW_2025:abc-AS0", signer_info("Mario Rossi"))]
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    answers(monkeypatch, "12345678", "12345679")
    assert cli.main(["pdf", "--timbro", str(tmp_path / "a.pdf")]) == 0
    assert config.load().signer_name == "Mario Rossi"
    assert cli.main(["pdf", "--timbro", str(tmp_path / "a.pdf")]) == 0
    assert api.names().count("list_certs") == 1


def test_local_problems_ask_for_nothing(api, tmp_path, make_pdf, monkeypatch, capsys):
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    asked = answers(monkeypatch)
    assert cli.main(["pdf", "--timbro", "--pagina", "9", str(tmp_path / "a.pdf"), str(tmp_path / "manca.pdf")]) == 1
    err = capsys.readouterr().err
    assert "La pagina 9 non esiste" in err and "manca.pdf: il file non esiste" in err
    assert "non è stato usato alcun codice OTP" in err
    assert asked == [] and api.calls == []


def test_badly_typed_otp_never_reaches_aruba(api, tmp_path, make_pdf, monkeypatch):
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    answers(monkeypatch, "abc", "12", "")
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 3
    assert api.calls == []


def test_refused_otp(api, tmp_path, make_pdf, monkeypatch, capsys):
    api.open_error = OtpError(MSG_OTP)
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    answers(monkeypatch, "12345678")
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 3
    assert "ora del telefono" in capsys.readouterr().err
    assert config.load_state().auth_failures == 1


def test_confirmation_after_two_failures(api, tmp_path, make_pdf, monkeypatch, capsys):
    config.save_state(config.State(auth_failures=2))
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    answers(monkeypatch, "no")
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 1
    assert "bloccare l'account" in capsys.readouterr().err
    assert api.calls == []


def test_partial_batch(api, tmp_path, make_pdf, monkeypatch, capsys):
    api.fail_at = {1: ServiceError("guasto")}
    for name in ("a.pdf", "b.pdf"):
        (tmp_path / name).write_bytes(make_pdf(A4))
    answers(monkeypatch, "12345678")
    assert cli.main(["pdf", str(tmp_path / "a.pdf"), str(tmp_path / "b.pdf")]) == 4
    assert "Non firmato: b.pdf: guasto" in capsys.readouterr().err


def test_not_configured(tmp_path, make_pdf, capsys):
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 3
    assert "firma configura" in capsys.readouterr().err


def test_verifica(pki, make_p7m, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.verify, "default_trust", lambda: RootsTrust(pki["ca"]))
    good = tmp_path / "contratto.pdf.p7m"
    good.write_bytes(make_p7m(PDF))
    assert cli.main(["verifica", str(good)]) == 0
    out = capsys.readouterr().out
    for expected in ("FIRMA VALIDA", "Firmatario: Mario Rossi (codice fiscale RSSMRA80A01H501U)",
                     "Documento contenuto: contratto.pdf", "aggiornato al 01/11/2026"):
        assert expected in out
    bad = tmp_path / "manomesso.p7m"
    bad.write_bytes(make_p7m(PDF).replace(b"finto pdf", b"falso pdf"))
    assert cli.main(["verifica", str(bad)]) == 1
    out = capsys.readouterr().out
    assert "FIRMA NON VALIDA" in out and "modificato dopo la firma" in out
