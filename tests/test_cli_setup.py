"""firma configura, firma diagnostica, and Italian help everywhere."""

import datetime as dt

import pytest

from firmaremota import cli, config, credentials, diagnostics
from firmaremota.errors import CredentialsError, NetworkError

from .fakes import FakeArss, signer_info


class MemoryStore:
    name = "Portachiavi di prova"

    def __init__(self, data=None):
        self.data = dict(data or {})

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value

    def delete(self, key):
        self.data.pop(key, None)


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


def test_configura_with_user_at_domain(env, capsys):
    env.replies["input"] = ["mario.rossi@firma", ""]  # username@domain, then "save the password? [S/n]" -> yes
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 0
    settings = config.load()
    assert (settings.user, settings.domain, settings.cert_id) == ("mario.rossi", "firma", "NEW_2025:abc-AS0")
    assert settings.signer_name == "Mario Rossi" and settings.cert_expires
    assert env.store.data == {"mario.rossi@firma": "Pw-1"}
    assert env.api.calls == [("list_certs", "Pw-1")]  # checked with Aruba, no OTP
    assert "Certificato di Mario Rossi" in capsys.readouterr().out


def test_configura_default_domain_without_saving(env, capsys):
    env.replies["input"] = ["mario.rossi", "", "n"]  # domain defaults to 'firma'; don't save the password
    env.replies["getpass"] = ["Pw-1"]
    assert cli.main(["configura"]) == 0
    assert config.load().domain == "firma"
    assert env.store.data == {}
    assert "chiesta a ogni firma" in capsys.readouterr().out


def test_configura_refused_saves_nothing(env, capsys):
    env.api.certs = CredentialsError("Nome utente, dominio o password non accettati.")
    env.replies["input"] = ["mario.rossi@firma", ""]
    env.replies["getpass"] = ["sbagliata", "sbagliata"]
    assert cli.main(["configura"]) == 3
    assert not config.load().complete and env.store.data == {}
    assert config.load_state().auth_failures == 1


def test_configura_mismatched_passwords(env):
    env.replies["input"] = ["mario.rossi@firma", ""]
    env.replies["getpass"] = ["uno", "due"]
    assert cli.main(["configura"]) == 3
    assert env.api.calls == [] and env.store.data == {}


def test_configura_chooses_among_certificates(env):
    env.api.certs = [("cert-1", signer_info("Mario Rossi")), ("cert-2", signer_info("Mario Rossi (nuovo)"))]
    env.replies["input"] = ["mario.rossi@firma", "", "2"]
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 0
    assert config.load().cert_id == "cert-2"


def test_configura_new_account_forgets_old_password(env):
    config.save(config.Settings(user="vecchio", domain="firma", cert_id="x"))
    env.store.data = {"vecchio@firma": "old"}
    env.replies["input"] = ["mario.rossi@firma", ""]
    env.replies["getpass"] = ["Pw-1", "Pw-1"]
    assert cli.main(["configura"]) == 0
    assert env.store.data == {"mario.rossi@firma": "Pw-1"}


def test_salva_and_dimentica_password(env):
    config.save(config.Settings(user="mario.rossi", domain="firma", cert_id="NEW_2025:abc-AS0"))
    env.replies["getpass"] = ["Nuova-1", "Nuova-1"]
    assert cli.main(["configura", "--salva-password"]) == 0
    assert env.store.data == {"mario.rossi@firma": "Nuova-1"}
    assert cli.main(["configura", "--dimentica-password"]) == 0
    assert env.store.data == {}


def test_configura_needs_a_terminal(env, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.main(["configura"]) == 1
    assert "terminale" in capsys.readouterr().err


def _configured(env, expires_in_days=400):
    config.save(config.Settings(user="mario.rossi", domain="firma", cert_id="NEW_2025:abc-AS0",
                                signer_name="Mario Rossi",
                                cert_expires=(dt.date.today() + dt.timedelta(days=expires_in_days)).isoformat()))
    env.store.data = {"mario.rossi@firma": "Pw-1"}


def test_diagnostica_all_good(env, capsys):
    _configured(env)
    assert cli.main(["diagnostica"]) == 0
    out = capsys.readouterr().out
    for expected in ("[OK]      Account: mario.rossi@firma", "Password: salvata in Portachiavi di prova",
                     "Servizio Aruba: raggiungibile", "Certificato: di Mario Rossi, valido fino al"):
        assert expected in out
    assert "Pw-1" not in out
    assert env.api.calls == []  # no credentials sent without --account


def test_diagnostica_account_check(env, capsys):
    _configured(env)
    assert cli.main(["diagnostica", "--account"]) == 0
    assert "Credenziali: accettate da Aruba" in capsys.readouterr().out
    assert env.api.calls == [("list_certs", "Pw-1")]


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
    text = diagnostics.as_text(diagnostics.report(env.api, password="Pw-1"))
    assert "Pw-1" not in text


@pytest.mark.parametrize("command", ["pdf", "p7m", "verifica", "estrai", "configura", "diagnostica"])
def test_every_help_is_italian(command, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"uso: firma {command}")
    for english in ("usage:", "options:", "show this help", "positional arguments", "default:"):
        assert english not in out
