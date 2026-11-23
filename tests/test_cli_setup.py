"""firma configura, firma diagnostica, and Italian help everywhere."""

import pytest

from firmaremota import cli, config, credentials, diagnostics
from firmaremota.errors import CredentialsError, NetworkError

from .conftest import PASSWORD, MemoryStore
from .fakes import FakeArss, signer_info

PW, USER = credentials.PASSWORD_KEY, credentials.LOGIN_KEY


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


def files_on_disk():
    """Everything the app wrote under its config folder."""
    folder = config.config_dir()
    return sorted(p.name for p in folder.iterdir()) if folder.exists() else []


def test_configura_keeps_everything_in_the_wallet(env, capsys):
    env.replies["input"] = ["mario.rossi@firma", ""]  # username@domain, then "remember? [S/n]" -> yes
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 0
    assert env.store.data == {USER: "mario.rossi@firma", PW: "Pw-1"}
    assert env.api.calls == [("list_certs", "Pw-1")]  # checked with Aruba, no OTP
    for name in files_on_disk():  # only non-personal preferences, if anything
        assert "mario" not in (config.config_dir() / name).read_text()
    out = capsys.readouterr().out
    assert "Certificato di Mario Rossi" in out and "sul disco non viene salvato" in out


def test_configura_without_remembering_stores_nothing(env, capsys):
    env.store.data = {USER: "vecchio@firma", PW: "vecchia"}
    env.replies["input"] = ["mario.rossi", "", "n"]  # domain defaults to 'firma'; don't remember
    env.replies["getpass"] = ["Pw-1"]
    assert cli.main(["configura"]) == 0
    assert env.store.data == {}
    assert "Non è stato salvato nulla" in capsys.readouterr().out


def test_configura_refused_saves_nothing(env):
    env.api.certs = CredentialsError("Nome utente, dominio o password non accettati.")
    env.replies["input"] = ["mario.rossi@firma", ""]
    env.replies["getpass"] = ["sbagliata", "sbagliata"]
    assert cli.main(["configura"]) == 3
    assert env.store.data == {}
    assert config.load_state().auth_failures == 1


def test_configura_mismatched_passwords(env):
    env.replies["input"] = ["mario.rossi@firma", ""]
    env.replies["getpass"] = ["uno", "due"]
    assert cli.main(["configura"]) == 3
    assert env.api.calls == [] and env.store.data == {}


def test_configura_offers_the_saved_account_as_default(env):
    env.store.data = {USER: "mario.rossi@firma", PW: PASSWORD}
    env.replies["input"] = ["", "", ""]  # keep username, keep domain, remember
    env.replies["getpass"] = [PASSWORD, PASSWORD]
    assert cli.main(["configura"]) == 0
    assert env.store.data[USER] == "mario.rossi@firma"


def test_salva_password(env):
    env.store.data = {USER: "mario.rossi@firma"}
    env.replies["getpass"] = ["Nuova-1", "Nuova-1"]
    assert cli.main(["configura", "--salva-password"]) == 0
    assert env.store.data == {USER: "mario.rossi@firma", PW: "Nuova-1"}
    assert env.api.calls == [("list_certs", "Nuova-1")]


def test_dimentica(env):
    env.store.data = {USER: "mario.rossi@firma", PW: PASSWORD}
    assert cli.main(["configura", "--dimentica-password"]) == 0
    assert env.store.data == {USER: "mario.rossi@firma"}
    assert cli.main(["configura", "--dimentica-tutto"]) == 0
    assert env.store.data == {}


def test_configura_needs_a_terminal(env, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.main(["configura"]) == 1
    assert "terminale" in capsys.readouterr().err


def test_diagnostica_all_good(env, capsys):
    env.store.data = {USER: "mario.rossi@firma", PW: PASSWORD}
    assert cli.main(["diagnostica"]) == 0
    out = capsys.readouterr().out
    for expected in ("[OK]      Account: m*********i@firma (nel portachiavi; sul disco nulla)",
                     "Password: salvata in Portachiavi di prova", "Servizio Aruba: raggiungibile"):
        assert expected in out
    assert PASSWORD not in out and "mario.rossi" not in out
    assert env.api.calls == []  # no credentials sent without --account


def test_diagnostica_account_check(env, capsys):
    env.store.data = {USER: "mario.rossi@firma", PW: PASSWORD}
    env.api.certs = [("x", signer_info("Mario Rossi", days_left=20))]
    assert cli.main(["diagnostica", "--account"]) == 0
    out = capsys.readouterr().out
    assert "Credenziali: accettate da Aruba" in out
    assert "[AVVISO]  Certificato: di M*********i, scade il" in out
    assert env.api.calls == [("list_certs", PASSWORD)]


def test_diagnostica_problems(env, capsys, monkeypatch):
    env.store.data = {USER: "mario.rossi@firma", PW: PASSWORD}
    config.save_state(config.State(auth_failures=1))
    monkeypatch.setattr(env.api, "ping", lambda: (_ for _ in ()).throw(NetworkError("Il servizio non risponde.")))
    assert cli.main(["diagnostica"]) == 1
    out = capsys.readouterr().out
    assert "[ERRORE]  Servizio Aruba: Il servizio non risponde." in out
    assert "[AVVISO]  Accessi rifiutati: 1 di fila" in out


def test_diagnostica_nothing_saved(env, capsys):
    assert cli.main(["diagnostica"]) == 0
    assert "non salvato: verrà chiesto a ogni firma" in capsys.readouterr().out


def test_report_text_has_no_secrets(env):
    env.store.data = {USER: "mario.rossi@firma", PW: PASSWORD}
    text = diagnostics.as_text(diagnostics.report(env.api, PASSWORD, check_account=True))
    assert PASSWORD not in text and "mario.rossi" not in text and "Mario Rossi" not in text


@pytest.mark.parametrize("command", ["pdf", "p7m", "verifica", "estrai", "configura", "diagnostica", "gui"])
def test_every_help_is_italian(command, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"uso: firma {command}")
    for english in ("usage:", "options:", "show this help", "positional arguments", "default:"):
        assert english not in out
