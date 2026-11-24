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
    assert out.startswith("uso: aruba-firma")
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

from firmaremota import config  # noqa: E402
from firmaremota.arss.client import MSG_OTP  # noqa: E402
from firmaremota.errors import OtpError, ServiceError  # noqa: E402

from .conftest import PASSWORD, add_profile  # noqa: E402
import dataclasses  # noqa: E402

from firmaremota.errors import CredentialsError  # noqa: E402
from .fakes import FakeArss, signer_info  # noqa: E402
from .test_verify import RootsTrust  # noqa: E402

A4 = (595, 842, 0, None)


@pytest.fixture
def api(monkeypatch, make_p7m, sign_pdf, make_cades_t, make_tsd, make_tsr, configured):
    fake = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf, make_cades_t=make_cades_t, make_tsd=make_tsd, make_tsr=make_tsr)
    monkeypatch.setattr(cli, "make_api", lambda: fake)
    return fake


def answers(monkeypatch, *values, password=None):
    """Scripted replies, in order, to whatever the CLI asks (input() or getpass()); `asked` records the prompts.

    The OTP is asked with getpass (never echoed), so an OTP test must not rely on input() alone.
    """
    asked, replies = [], iter(values)

    def reply(prompt=""):
        asked.append(prompt)
        if password is not None and "Password" in prompt:
            return password
        return next(replies)

    monkeypatch.setattr("builtins.input", reply)
    monkeypatch.setattr(cli.getpass, "getpass", reply)
    return asked


def test_pdf_batch_one_otp(api, tmp_path, make_pdf, monkeypatch, capsys):
    for name in ("a.pdf", "b.pdf"):
        (tmp_path / name).write_bytes(make_pdf(A4))
    answers(monkeypatch, "1234 5678")
    assert cli.main(["pdf", str(tmp_path / "a.pdf"), str(tmp_path / "b.pdf")]) == 0
    out = capsys.readouterr().out
    assert "Firmo 2 file con un solo codice OTP" in out and out.count("Firmato:") == 2
    assert (tmp_path / "a_firmato.pdf").exists() and (tmp_path / "b_firmato.pdf").exists()
    assert api.names()[:2] == ["list_certs", "open_session"]  # account checked before the OTP is used
    assert api.calls[1] == ("open_session", "12345678")
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
    _, _, _, stamp, text = next(c for c in api.calls if c[0] == "sign_pdf")
    assert stamp.page == 1 and stamp.llx == 36 and stamp.ury == 806
    assert text == "Firmato digitalmente da Mario Rossi\nVisto"


def test_nothing_saved_everything_typed(api, configured, tmp_path, make_pdf, monkeypatch):
    configured.data.clear()
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    asked = answers(monkeypatch, "mario.rossi@firma", "12345678", password=PASSWORD)
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 0
    assert asked[0].startswith("Nome utente Aruba") and api.calls[0] == ("list_certs", PASSWORD)
    assert "OTP" in asked[-1] and "non viene mostrato" in asked[-1]
    assert configured.data == {}  # typed credentials are never stored


def test_wrong_password_stops_before_the_otp(api, tmp_path, make_pdf, monkeypatch, capsys):
    api.certs = CredentialsError("Nome utente, dominio o password non accettati.")
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    asked = answers(monkeypatch)
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 3
    assert asked == [] and api.names() == ["list_certs"]  # no OTP asked, none spent
    assert config.load_state().auth_failures == 1


def test_expiring_certificate_warning(api, tmp_path, make_pdf, monkeypatch, capsys):
    api.certs = [("NEW_2025:abc-AS0", signer_info("Mario Rossi", days_left=20))]
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    answers(monkeypatch, "12345678")
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 0
    assert "certificato di firma scade il" in capsys.readouterr().err


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
    assert "open_session" not in api.names()


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


def test_verifica_without_a_trusted_list_is_unverifiable(make_p7m, tmp_path, monkeypatch, capsys):
    """Sound signature, but no way to tell whether the authority is recognised: a third verdict, exit 5."""
    monkeypatch.setattr(cli.verify, "default_trust", lambda: cli.verify.NoTrust())
    good = tmp_path / "contratto.pdf.p7m"
    good.write_bytes(make_p7m(PDF))
    assert cli.main(["verifica", str(good)]) == cli.EXIT_UNVERIFIABLE == 5
    out = capsys.readouterr().out
    assert "FIRMA NON VERIFICABILE" in out and "elenco ufficiale dei certificatori non è disponibile" in out
    assert "FIRMA VALIDA" not in out


def test_huge_files_are_refused_before_anything_else(api, tmp_path, make_pdf, monkeypatch, capsys):
    monkeypatch.setattr(cli.files, "MAX_SIGN_SIZE", 100)
    monkeypatch.setattr(cli.files, "MAX_VERIFY_SIZE", 100)
    big = tmp_path / "grande.pdf"
    big.write_bytes(make_pdf(A4))
    assert cli.main(["pdf", str(big)]) == 1 and api.calls == []
    assert "troppo grande" in capsys.readouterr().err
    for command in ("verifica", "estrai"):
        assert cli.main([command, str(big)]) == 1
        assert "troppo grande" in capsys.readouterr().err


def test_account_selection(api, configured, tmp_path, make_pdf, monkeypatch, capsys):
    anna = add_profile(configured, "Anna", "anna.bianchi@frStudio", "pw-anna")
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    answers(monkeypatch, "12345678")
    assert cli.main(["pdf", "--account", "anna", str(tmp_path / "a.pdf")]) == 0  # alias, case-insensitive
    assert api.calls[0] == ("list_certs", "pw-anna") and config.load().last_profile == anna.id
    assert cli.main(["pdf", "--account", "Luigi", str(tmp_path / "a.pdf")]) == 3
    assert "Nessun account si chiama «Luigi»" in capsys.readouterr().err
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 3  # several accounts, no flag, not a terminal
    assert "--account" in capsys.readouterr().err
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    asked = answers(monkeypatch, "", "12345678")  # menu: Enter takes the default, the account used last
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 0
    assert asked[0].startswith("Numero [2]") and [c for c in api.calls if c[0] == "list_certs"][-1][1] == "pw-anna"


def test_estrai_tsd(make_p7m, make_tsd, tmp_path, capsys):
    (tmp_path / "doc.pdf.p7m.tsd").write_bytes(make_tsd(make_p7m(PDF)))
    assert cli.main(["estrai", str(tmp_path / "doc.pdf.p7m.tsd")]) == 0
    assert (tmp_path / "doc.pdf").read_bytes() == PDF
    out = capsys.readouterr().out
    assert "Marca temporale: sì" in out and "Firmato da Mario Rossi" in out


def test_estrai_tsr_explains(make_tsr, tmp_path, capsys):
    (tmp_path / "nota.txt.tsr").write_bytes(make_tsr(b"ciao"))
    assert cli.main(["estrai", str(tmp_path / "nota.txt.tsr")]) == 1
    assert "non contiene il documento" in capsys.readouterr().err


def test_verifica_tsr_needs_original(pki, make_tsr, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.verify, "default_trust", lambda: RootsTrust(pki["ca"]))
    tsr = tmp_path / "nota.txt.tsr"
    tsr.write_bytes(make_tsr(b"ciao"))
    assert cli.main(["verifica", str(tsr)]) == 1
    assert "--originale" in capsys.readouterr().err
    (tmp_path / "altra.txt").write_bytes(b"ciao")
    assert cli.main(["verifica", str(tsr), "--originale", str(tmp_path / "altra.txt")]) == 0
    assert "MARCA TEMPORALE VALIDA" in capsys.readouterr().out


def test_verifica_tsd_and_at_date(pki, make_p7m, make_tsd, tmp_path, monkeypatch, capsys):
    from .conftest import TS_TIME

    monkeypatch.setattr(cli.verify, "default_trust", lambda: RootsTrust(pki["ca"]))
    tsd = tmp_path / "x.pdf.p7m.tsd"
    tsd.write_bytes(make_tsd(make_p7m(PDF, who="scaduto")))
    assert cli.main(["verifica", str(tsd)]) == 0
    out = capsys.readouterr().out
    assert "FIRMA VALIDA" in out and "la firma vale" in out and "Marca temporale sul documento:" in out
    plain = tmp_path / "x.p7m"
    plain.write_bytes(make_p7m(PDF, who="scaduto"))
    assert cli.main(["verifica", str(plain)]) == 1
    assert cli.main(["verifica", str(plain), "--alla-data", f"{TS_TIME:%d/%m/%Y}"]) == 0
    assert "Verifica alla data del" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:  # argparse: usage error
        cli.main(["verifica", str(plain), "--alla-data", "ieri"])
    assert exc.value.code == 2


# --- marche temporali -------------------------------------------------------------------------------

def test_timestamp_on_by_default_and_flags(api, configured, tmp_path, make_pdf, monkeypatch, capsys):
    from firmaremota import verify
    from firmaremota.models import Kind, TimestampType, TsaCredentials

    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    answers(monkeypatch, "12345678")
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 0
    assert api.tsa_seen == [(None, TimestampType.T)]  # no TSA account: Aruba's own (included) mark
    assert verify.has_timestamp(Kind.PADES, (tmp_path / "a_firmato.pdf").read_bytes())
    assert "— con marca temporale" in capsys.readouterr().out
    answers(monkeypatch, "12345678")
    assert cli.main(["pdf", "--senza-marca", str(tmp_path / "a.pdf")]) == 0
    assert api.tsa_seen[-1] == (None, None) and "marca temporale" not in capsys.readouterr().out
    answers(monkeypatch, "12345678")
    assert cli.main(["p7m", "--tipo-marca", "LT", str(tmp_path / "a.pdf")]) == 0
    assert api.tsa_seen[-1][1] == TimestampType.LT


def test_profile_setting_off_and_marca_flag_on(api, configured, tmp_path, make_pdf, monkeypatch):
    from firmaremota import profiles
    from firmaremota.models import TimestampType

    (profile,) = profiles.load_all(configured)
    profiles.upsert(configured, [profile], dataclasses.replace(profile, timestamp=False))
    (tmp_path / "a.pdf").write_bytes(make_pdf(A4))
    answers(monkeypatch, "12345678")
    assert cli.main(["pdf", str(tmp_path / "a.pdf")]) == 0 and api.tsa_seen[-1] == (None, None)
    answers(monkeypatch, "12345678")
    assert cli.main(["pdf", "--marca", str(tmp_path / "a.pdf")]) == 0 and api.tsa_seen[-1][1] == TimestampType.T


def test_p7m_tsd_level_wraps(api, configured, tmp_path, monkeypatch, capsys):
    from firmaremota import profiles
    from firmaremota.models import TsaCredentials

    (tmp_path / "fattura.xml").write_bytes(b"<f/>")
    assert cli.main(["p7m", "--tipo-marca", "TSD", str(tmp_path / "fattura.xml")]) == 1  # no TSA account yet
    assert "account di marca temporale" in capsys.readouterr().err and api.calls == []
    profiles.set_tsa(configured, profiles.load_all(configured)[0], TsaCredentials("tsa", "pw"))
    answers(monkeypatch, "12345678")
    assert cli.main(["p7m", "--tipo-marca", "TSD", str(tmp_path / "fattura.xml")]) == 0
    assert (tmp_path / "fattura.xml.p7m.tsd").exists() and api.names().count("timestamp_file") == 1


def test_tsd_level_is_not_offered_for_pdf(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["pdf", "--tipo-marca", "TSD", "x.pdf"])
    assert exc.value.code == 2


def test_marca_command_tsd_and_tsr(api, configured, tmp_path, monkeypatch, capsys):
    from firmaremota import profiles, verify
    from firmaremota.models import TsaCredentials

    (tmp_path / "nota.txt").write_bytes(b"ciao")
    (tmp_path / "foto.jpg").write_bytes(b"\xff\xd8 finta")
    assert cli.main(["marca", str(tmp_path / "nota.txt")]) == 1  # Firma Remota alone can't mark files
    assert "configura --credenziali-marca" in capsys.readouterr().err and api.calls == []
    profiles.set_tsa(configured, profiles.load_all(configured)[0], TsaCredentials("tsa", "pw"))
    assert cli.main(["marca", str(tmp_path / "nota.txt"), str(tmp_path / "foto.jpg")]) == 0
    out = capsys.readouterr().out
    assert out.count("Marcato:") == 2 and "OTP" not in out
    assert api.names() == ["timestamp_file", "timestamp_file"]  # no login check, no session
    assert verify.verify_file(tmp_path / "nota.txt.tsd", verify.NoTrust()).content == b"ciao"
    assert cli.main(["marca", "--formato", "tsr", str(tmp_path / "nota.txt")]) == 0
    out = capsys.readouterr().out
    assert "Formato TSR" in out and "documento originale" in out and (tmp_path / "nota.txt.tsr").exists()


def test_marca_with_tsa_error(api, configured, tmp_path, monkeypatch, capsys):
    from firmaremota import profiles
    from firmaremota.errors import TimestampError
    from firmaremota.models import TsaCredentials

    profiles.set_tsa(configured, profiles.load_all(configured)[0], TsaCredentials("tsa", "pw"))
    api.timestamp_error = TimestampError("Le marche temporali del tuo account sono finite")
    (tmp_path / "nota.txt").write_bytes(b"ciao")
    assert cli.main(["marca", str(tmp_path / "nota.txt")]) == 1
    assert "sono finite" in capsys.readouterr().err and not (tmp_path / "nota.txt.tsd").exists()
    assert config.load_state().auth_failures == 0
