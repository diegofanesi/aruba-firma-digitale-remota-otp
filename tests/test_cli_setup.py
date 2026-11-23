"""firma configura, firma diagnostica, and Italian help everywhere."""

import pytest

from firmaremota import cli, config, credentials, diagnostics, profiles
from firmaremota.errors import CredentialsError, NetworkError

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
    assert "Mario: mario.rossi@firma (password salvata)" in out
    assert "Anna: anna.bianchi@frStudio (password non salvata)" in out
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


def test_diagnostica_checks_every_saved_account(env, capsys):
    add_profile(env.store, "Mario", "mario.rossi@firma", PASSWORD)
    add_profile(env.store, "Anna", "anna.bianchi@firma")  # no password: can't be checked
    env.api.certs = [("x", signer_info("Mario Rossi", days_left=20))]
    assert cli.main(["diagnostica", "--credenziali"]) == 0
    out = capsys.readouterr().out
    assert "[AVVISO]  Credenziali «M***o»: accettate; il certificato scade il" in out
    assert "[AVVISO]  Account «A**a»: a**********i@firma, password non salvata" in out
    assert "Credenziali «A**a»" not in out
    assert env.api.calls == [("list_certs", PASSWORD)]


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


@pytest.mark.parametrize("command", ["pdf", "p7m", "verifica", "estrai", "configura", "diagnostica", "gui"])
def test_every_help_is_italian(command, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"uso: firma {command}")
    for english in ("usage:", "options:", "show this help", "positional arguments", "default:"):
        assert english not in out
