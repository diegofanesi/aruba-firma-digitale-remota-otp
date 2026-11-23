"""firma configura, firma diagnostica, and Italian help everywhere."""

import datetime as dt

import pytest

from firmaremota import cli, config, credentials, diagnostics, vault
from firmaremota.errors import CredentialsError, NetworkError

from .conftest import PASSWORD, PROFILE, MemoryStore
from .fakes import FakeArss, signer_info

KEY = credentials.PASSWORD_KEY


@pytest.fixture
def env(monkeypatch):
    """Fake wallet, fake Aruba, a terminal, and scripted answers for input()/getpass()."""
    store, api = MemoryStore(), FakeArss(certs=[("NEW_2025:abc-AS0", signer_info("Mario Rossi"))])
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


def test_configura_encrypts_the_profile(env, capsys):
    env.replies["input"] = ["mario.rossi@firma", ""]  # username@domain, then "save the password? [S/n]" -> yes
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 0
    profile = vault.load("Pw-1")
    assert (profile.user, profile.domain, profile.cert_id, profile.signer_name) == \
        ("mario.rossi", "firma", "NEW_2025:abc-AS0", "Mario Rossi")
    assert profile.cert_expires
    assert env.store.data == {KEY: "Pw-1"}  # anonymous entry name
    assert env.api.calls == [("list_certs", "Pw-1")]  # checked with Aruba, no OTP
    assert "mario" not in config.config_path().read_text()
    out = capsys.readouterr().out
    assert "Certificato di Mario Rossi" in out and "cifrati (AES-256)" in out


def test_configura_without_saving_the_password(env, capsys):
    env.store.data = {KEY: "vecchia"}
    env.replies["input"] = ["mario.rossi", "", "n"]  # domain defaults to 'firma'; don't save the password
    env.replies["getpass"] = ["Pw-1"]
    assert cli.main(["configura"]) == 0
    assert vault.load("Pw-1").domain == "firma"
    assert env.store.data == {}  # the old saved password would no longer open the profile
    assert "chiesta a ogni firma" in capsys.readouterr().out


def test_configura_refused_saves_nothing(env):
    env.api.certs = CredentialsError("Nome utente, dominio o password non accettati.")
    env.replies["input"] = ["mario.rossi@firma", ""]
    env.replies["getpass"] = ["sbagliata", "sbagliata"]
    assert cli.main(["configura"]) == 3
    assert not vault.exists() and env.store.data == {}
    assert config.load_state().auth_failures == 1


def test_configura_mismatched_passwords(env):
    env.replies["input"] = ["mario.rossi@firma", ""]
    env.replies["getpass"] = ["uno", "due"]
    assert cli.main(["configura"]) == 3
    assert env.api.calls == [] and not vault.exists()


def test_configura_chooses_among_certificates(env):
    env.api.certs = [("cert-1", signer_info("Mario Rossi")), ("cert-2", signer_info("Mario Rossi (nuovo)"))]
    env.replies["input"] = ["mario.rossi@firma", "", "2"]
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 0
    assert vault.load("Pw-1").cert_id == "cert-2"


def test_configura_removes_legacy_plain_text(env):
    path = config.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[account]\nuser = mario.rossi\ndomain = firma\n")
    env.store.data = {"mario.rossi@firma": "old"}
    env.replies["input"] = ["mario.rossi@firma", ""]
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 0
    assert env.store.data == {KEY: "Pw-1"}
    assert "mario" not in path.read_text()


def test_configura_offers_current_account_as_default(env):
    vault.save(PROFILE, PASSWORD)
    env.store.data = {KEY: PASSWORD}
    env.replies["input"] = ["", "", ""]  # keep username, keep domain, save password
    env.replies["getpass"] = [PASSWORD, PASSWORD]
    assert cli.main(["configura"]) == 0
    assert vault.load(PASSWORD).user == "mario.rossi"


def test_salva_password_after_forgetting(env):
    vault.save(PROFILE, PASSWORD)
    assert cli.main(["configura", "--dimentica-password"]) == 0
    assert env.store.data == {}
    env.replies["getpass"] = [PASSWORD, PASSWORD]
    assert cli.main(["configura", "--salva-password"]) == 0
    assert env.store.data == {KEY: PASSWORD}


def test_changed_password_re_encrypts(env):
    vault.save(PROFILE, PASSWORD)
    env.store.data = {KEY: PASSWORD}
    env.replies["getpass"] = ["Nuova-1", "Nuova-1"]
    assert cli.main(["configura", "--salva-password"]) == 0
    assert env.store.data == {KEY: "Nuova-1"}
    assert vault.load("Nuova-1").user == "mario.rossi"
    with pytest.raises(vault.VaultError):
        vault.load(PASSWORD)
    assert env.api.calls == [("list_certs", "Nuova-1")]


def test_configura_needs_a_terminal(env, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.main(["configura"]) == 1
    assert "terminale" in capsys.readouterr().err


def _configured(env, expires_in_days=400):
    profile = vault.Profile(PROFILE.user, PROFILE.domain, PROFILE.cert_id, PROFILE.signer_name,
                            (dt.date.today() + dt.timedelta(days=expires_in_days)).isoformat())
    vault.save(profile, PASSWORD)
    env.store.data = {KEY: PASSWORD}


def test_diagnostica_all_good(env, capsys):
    _configured(env)
    assert cli.main(["diagnostica"]) == 0
    out = capsys.readouterr().out
    for expected in ("[OK]      Account: mario.rossi@firma, dati cifrati con AES-256",
                     "Password: salvata in Portachiavi di prova", "Servizio Aruba: raggiungibile",
                     "Certificato: di Mario Rossi, valido fino al"):
        assert expected in out
    assert PASSWORD not in out
    assert env.api.calls == []  # no credentials sent without --account


def test_diagnostica_locked_profile(env, capsys):
    _configured(env)
    env.store.data = {}
    assert cli.main(["diagnostica"]) == 0
    out = capsys.readouterr().out
    assert "profilo cifrato presente" in out and "mario" not in out


def test_diagnostica_account_check(env, capsys):
    _configured(env)
    assert cli.main(["diagnostica", "--account"]) == 0
    assert "Credenziali: accettate da Aruba" in capsys.readouterr().out
    assert env.api.calls == [("list_certs", PASSWORD)]


def test_diagnostica_problems(env, capsys, monkeypatch):
    _configured(env, expires_in_days=20)
    config.save_state(config.State(auth_failures=1))
    monkeypatch.setattr(env.api, "ping", lambda: (_ for _ in ()).throw(NetworkError("Il servizio non risponde.")))
    assert cli.main(["diagnostica"]) == 1
    out = capsys.readouterr().out
    assert "[ERRORE]  Servizio Aruba: Il servizio non risponde." in out
    assert "[AVVISO]  Certificato: di Mario Rossi, scade il" in out
    assert "[AVVISO]  Accessi rifiutati: 1 di fila" in out


def test_diagnostica_not_configured(env, capsys):
    assert cli.main(["diagnostica"]) == 1
    assert "non configurato" in capsys.readouterr().out


def test_report_text_has_no_secrets(env):
    _configured(env)
    text = diagnostics.as_text(diagnostics.report(env.api, PASSWORD, check_account=True))
    assert PASSWORD not in text


@pytest.mark.parametrize("command", ["pdf", "p7m", "verifica", "estrai", "configura", "diagnostica", "gui"])
def test_every_help_is_italian(command, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"uso: firma {command}")
    for english in ("usage:", "options:", "show this help", "positional arguments", "default:"):
        assert english not in out
