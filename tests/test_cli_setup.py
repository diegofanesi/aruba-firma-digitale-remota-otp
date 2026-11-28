"""firma configura, firma diagnostica, and Italian help everywhere."""

import pytest

from firmaremota import cli, config, credentials, diagnostics, profiles
from firmaremota.errors import CredentialsError, NetworkError
from firmaremota.models import TimestampSource

from .conftest import PASSWORD, MemoryStore, add_profile
from .fakes import FakeArss, signer_info


@pytest.fixture
def env(monkeypatch):
    """Fake wallet, fake Aruba, a terminal, and scripted answers for input()/getpass()."""
    store, api = MemoryStore(), FakeArss()
    monkeypatch.setattr(credentials, "get_store", lambda: store)
    monkeypatch.setattr(cli, "make_api", lambda: api)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    replies = {"input": [], "getpass": []}
    monkeypatch.setattr("builtins.input", lambda prompt="": replies["input"].pop(0))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": replies["getpass"].pop(0))

    class Env:
        pass

    e = Env()
    e.store, e.api, e.replies = store, api, replies
    return e


def saved(store):
    """{alias: (login, password or None)} as the app would read it back."""
    return {p.alias: (p.login, profiles.password(store, p)) for p in profiles.load_all(store)}


def test_configura_adds_an_account(env, capsys):
    env.replies["input"] = ["mario.rossi@firma", "", ""]  # login; alias (default: the username); remember? yes
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 0
    assert saved(env.store) == {"mario.rossi": ("mario.rossi@firma", "Pw-1")}
    assert env.api.calls == [("list_certs", "Pw-1")]  # checked with Aruba, no OTP
    (profile,) = profiles.load_all(env.store)
    assert config.load().last_profile == profile.id
    assert "mario" not in config.config_path().read_text()
    out = capsys.readouterr().out
    assert "Account «mario.rossi»: certificato di Mario Rossi" in out and "sul disco non viene salvato" in out


def test_configura_with_alias_and_without_remembering_the_password(env, capsys):
    env.replies["input"] = ["mario.rossi", "", "", "n"]  # user; domain -> firma; alias -> Papà; don't remember
    env.replies["getpass"] = ["Pw-1"]
    assert cli.main(["configura", "--account", "Papà"]) == 0
    assert saved(env.store) == {"Papà": ("mario.rossi@firma", None)}
    assert "la password verrà chiesta" in capsys.readouterr().out


def test_configura_edits_an_existing_account(env):
    old = add_profile(env.store, "Mario", "mario.rossi@firma", "old")
    env.replies["input"] = ["", "", "Papà", ""]  # keep user, keep domain, new alias, remember
    env.replies["getpass"] = ["Pw-2", "Pw-2"]
    assert cli.main(["configura", "--account", "Mario"]) == 0
    (profile,) = profiles.load_all(env.store)
    assert (profile.id, profile.alias, profile.login) == (old.id, "Papà", "mario.rossi@firma")
    assert profiles.password(env.store, profile) == "Pw-2"


def test_configura_rejects_a_duplicate_alias(env):
    add_profile(env.store, "Mario", "mario.rossi@firma", "old")
    env.replies["input"] = ["anna.bianchi@firma", "mario", ""]
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 3
    assert saved(env.store) == {"Mario": ("mario.rossi@firma", "old")}


def test_configura_refused_saves_nothing(env):
    env.api.certs = CredentialsError("Nome utente, dominio o password non accettati.")
    env.replies["input"] = ["mario.rossi@firma", "", ""]
    env.replies["getpass"] = ["sbagliata", "sbagliata"]
    assert cli.main(["configura"]) == 3
    assert env.store.data == {} and config.load_state().auth_failures == 1


def test_configura_mismatched_passwords(env):
    env.replies["input"] = ["mario.rossi@firma", "", ""]
    env.replies["getpass"] = ["uno", "due"]
    assert cli.main(["configura"]) == 3
    assert env.api.calls == [] and env.store.data == {}


def test_elenco(env, capsys):
    add_profile(env.store, "Mario", "mario.rossi@firma", "pw")
    add_profile(env.store, "Anna", "anna.bianchi@frStudio")
    assert cli.main(["configura", "--elenco"]) == 0
    out = capsys.readouterr().out
    assert ("Mario: mario.rossi@firma (password salvata; marca temporale: no; marca di Aruba inclusa nel servizio: "
            "non ancora nota (si saprà alla prima firma))") in out
    assert "Anna: anna.bianchi@frStudio (password non salvata; marca temporale: no;" in out
    env.store.data.clear()
    assert cli.main(["configura", "--elenco"]) == 0
    assert "Nessun account salvato" in capsys.readouterr().out


def test_rimuovi_dimentica_and_dimentica_tutto(env):
    add_profile(env.store, "Mario", "mario.rossi@firma", "pw-m")
    add_profile(env.store, "Anna", "anna.bianchi@firma", "pw-a")
    assert cli.main(["configura", "--rimuovi", "--account", "Anna"]) == 0
    assert saved(env.store) == {"Mario": ("mario.rossi@firma", "pw-m")}
    assert cli.main(["configura", "--dimentica-password"]) == 0  # only one account left: no --account needed
    assert saved(env.store) == {"Mario": ("mario.rossi@firma", None)}
    assert cli.main(["configura", "--dimentica-tutto"]) == 0
    assert env.store.data == {}


def test_salva_password(env):
    profile = add_profile(env.store, "Mario", "mario.rossi@firma")
    env.replies["getpass"] = ["Nuova-1", "Nuova-1"]
    assert cli.main(["configura", "--salva-password"]) == 0
    assert profiles.password(env.store, profile) == "Nuova-1"
    assert env.api.calls == [("list_certs", "Nuova-1")]


def test_several_accounts_menu_and_non_tty(env, monkeypatch, capsys):
    add_profile(env.store, "Mario", "mario.rossi@firma", "pw")
    anna = add_profile(env.store, "Anna", "anna.bianchi@firma", "pw")
    config.save(config.Settings(last_profile=anna.id))
    env.replies["input"] = [""]  # the menu's default is the account used last
    assert cli.main(["configura", "--rimuovi"]) == 0
    assert list(saved(env.store)) == ["Mario"]
    add_profile(env.store, "Anna", "anna.bianchi@firma", "pw")
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.main(["configura", "--rimuovi"]) == 3
    assert "--account" in capsys.readouterr().err
    assert cli.main(["configura", "--rimuovi", "--account", "Luigi"]) == 3
    assert "Nessun account si chiama «Luigi». Account salvati: «Mario», «Anna»" in capsys.readouterr().err


def test_configura_needs_a_terminal(env, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.main(["configura"]) == 1
    assert "terminale" in capsys.readouterr().err


def test_configura_without_a_wallet(env, monkeypatch, capsys):
    monkeypatch.setattr(credentials, "get_store", lambda: None)
    assert cli.main(["configura"]) == 1
    assert "portachiavi" in capsys.readouterr().err
    assert cli.main(["configura", "--elenco"]) == 0
    assert "nulla di salvato" in capsys.readouterr().out


def test_diagnostica_all_good(env, capsys):
    add_profile(env.store, "Mario", "mario.rossi@firma", PASSWORD)
    assert cli.main(["diagnostica"]) == 0
    out = capsys.readouterr().out
    for expected in ("[INFO]    Portachiavi: Portachiavi di prova, 1 account; sul disco nulla",
                     "[OK]      Account «M***o»: m*********i@firma, password salvata",
                     "Servizio Aruba: raggiungibile"):
        assert expected in out
    assert PASSWORD not in out and "mario.rossi" not in out and "Mario" not in out
    assert env.api.calls == []  # no credentials sent without --credenziali


def test_diagnostica_checks_only_the_chosen_account(env, capsys):
    """One account per run: a run on behalf of someone else must not send every saved password to Aruba."""
    mario = add_profile(env.store, "Mario", "mario.rossi@firma", PASSWORD)
    add_profile(env.store, "Anna", "anna.bianchi@firma")  # no password: can't be checked
    add_profile(env.store, "Luigi", "luigi.verdi@firma", "pw-luigi")
    config.save(config.Settings(last_profile=mario.id))
    env.api.certs = [("x", signer_info("Mario Rossi", days_left=20))]
    assert cli.main(["diagnostica", "--credenziali"]) == 0
    out = capsys.readouterr().out
    assert "[AVVISO]  Credenziali «M***o»: accettate; il certificato scade il" in out
    assert "[AVVISO]  Account «A**a»: a**********i@firma, password non salvata" in out
    assert "Credenziali «A**a»" not in out and "Credenziali «L***i»" not in out
    assert env.api.calls == [("list_certs", PASSWORD)]
    env.api.calls.clear()
    assert cli.main(["diagnostica", "--credenziali", "--account", "luigi"]) == 0
    assert "Credenziali «L***i»: accettate" in capsys.readouterr().out
    assert env.api.calls == [("list_certs", "pw-luigi")]
    assert cli.main(["diagnostica", "--credenziali", "--account", "Nessuno"]) == 3


def test_diagnostica_problems(env, capsys, monkeypatch):
    add_profile(env.store, "Mario", "mario.rossi@firma", PASSWORD)
    config.save_state(config.State(auth_failures=1))
    monkeypatch.setattr(env.api, "ping", lambda: (_ for _ in ()).throw(NetworkError("Il servizio non risponde.")))
    assert cli.main(["diagnostica"]) == 1
    out = capsys.readouterr().out
    assert "[ERRORE]  Servizio Aruba: Il servizio non risponde." in out
    assert "[AVVISO]  Accessi rifiutati: 1 di fila" in out


def test_diagnostica_nothing_saved(env, capsys):
    assert cli.main(["diagnostica"]) == 0
    assert "nessuno salvato" in capsys.readouterr().out


def test_report_text_has_no_secrets(env):
    add_profile(env.store, "Mario", "mario.rossi@firma", PASSWORD)
    text = diagnostics.as_text(diagnostics.report(env.api, check_credentials=True))
    assert PASSWORD not in text and "mario.rossi" not in text and "Mario" not in text


def test_configura_marca_options(env, capsys):
    from firmaremota.models import TsaCredentials

    profile = add_profile(env.store, "Mario", "mario.rossi@firma", PASSWORD)
    assert cli.main(["configura", "--elenco"]) == 0
    assert "marca temporale: no" in capsys.readouterr().out  # off by default
    assert cli.main(["configura", "--marca", "automatica"]) == 0
    assert profiles.load_all(env.store)[0].timestamp is TimestampSource.AUTO and "automatica" in capsys.readouterr().out
    assert cli.main(["configura", "--elenco"]) == 0
    assert "marca temporale: automatica;" in capsys.readouterr().out
    assert cli.main(["configura", "--marca", "aruba"]) == 0
    assert profiles.load_all(env.store)[0].timestamp is TimestampSource.ARUBA and "Aruba" in capsys.readouterr().out
    assert cli.main(["configura", "--elenco"]) == 0
    assert "marca temporale: solo Aruba;" in capsys.readouterr().out
    assert cli.main(["configura", "--marca", "belgio"]) == 0
    out = capsys.readouterr().out
    assert profiles.load_all(env.store)[0].timestamp is TimestampSource.BELGIUM
    assert "gratuita" in out and "non commerciale" in out and "senza marca e viene segnalato" in out
    assert cli.main(["configura", "--elenco"]) == 0
    assert "marca temporale: solo gratuita (servizio belga);" in capsys.readouterr().out
    assert cli.main(["configura", "--marca", "no"]) == 0
    assert profiles.load_all(env.store)[0].timestamp is TimestampSource.NONE and "nessuna" in capsys.readouterr().out
    assert cli.main(["configura", "--marca", "aruba"]) == 0
    env.replies["input"] = ["", "https://tsa.example/ts"]  # Account TSA: keep the username; a server address
    env.replies["getpass"] = ["Pw-tsa"]
    assert cli.main(["configura", "--credenziali-marca"]) == 0
    assert profiles.tsa_account(env.store, profile) == TsaCredentials("mario.rossi", "Pw-tsa", "https://tsa.example/ts")
    assert env.api.calls == []  # nothing is checked with Aruba: every attempt would spend a mark
    assert "consuma una marca" in capsys.readouterr().out
    assert cli.main(["configura", "--elenco"]) == 0
    assert "marca temporale: solo Aruba (account TSA);" in capsys.readouterr().out
    assert cli.main(["configura", "--dimentica-credenziali-marca"]) == 0
    assert profiles.tsa_account(env.store, profile) is None
    assert cli.main(["configura", "--rimuovi"]) == 0 and set(env.store.data) <= {profiles.INDEX_KEY}  # tsa entry gone too


def test_configura_mentions_the_timestamp_default(env, capsys):
    env.replies["input"] = ["mario.rossi@firma", "", ""]
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 0
    out = capsys.readouterr().out
    assert "Marca temporale: automatica" in out and "configura --marca automatica|aruba|belgio|no" in out
    assert profiles.load_all(env.store)[0].timestamp is TimestampSource.AUTO  # new accounts: automatic


@pytest.mark.parametrize("command", ["pdf", "p7m", "marca", "verifica", "estrai", "configura", "diagnostica", "gui"])
def test_every_help_is_italian(command, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"uso: aruba-firma {command}")
    for english in ("usage:", "options:", "show this help", "positional arguments", "default:"):
        assert english not in out


@pytest.mark.parametrize("included", [True, False])
def test_controlla_marca_signs_a_test_text_and_remembers(env, capsys, make_p7m, make_cades_t, included):
    from firmaremota import service

    env.api.make_p7m = make_cades_t if included else make_p7m  # an account whose Aruba timestamps on its own, or not
    add_profile(env.store, "Papà", "giorgio.verdi@firma", PASSWORD)
    env.replies["getpass"] = ["87654321"]  # the OTP
    assert cli.main(["configura", "--controlla-marca"]) == 0
    out = capsys.readouterr().out
    assert ("include la marca temporale: Aruba la mette da sé" if included else "non include la marca temporale") in out
    assert [name for name, *_ in env.api.calls] == ["list_certs", "sign_cades"]  # one signature, nothing saved
    (profile,) = profiles.load_all(env.store)
    assert profile.aruba_marks is included and profile.aruba_marks_seen
    assert service.auth_failures() == 0
    assert cli.main(["configura", "--elenco"]) == 0
    assert f"marca di Aruba inclusa nel servizio: {'sì' if included else 'no'} (rilevato il" in capsys.readouterr().out
