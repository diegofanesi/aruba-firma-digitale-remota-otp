"""Accounts kept in the wallet: layout, migration, add/edit/remove, passwords per account."""

import json

import pytest

from firmaremota import credentials, logsetup, profiles
from firmaremota.errors import CredentialsError
from firmaremota.models import TimestampSource

from .conftest import MemoryStore


def test_nothing_saved():
    assert profiles.load_all(MemoryStore()) == []


def test_add_edit_remove_roundtrip():
    store = MemoryStore()
    mario = profiles.new_profile("Mario", "mario.rossi@firma", "")  # domain from the login
    assert (mario.user, mario.domain, mario.login) == ("mario.rossi", "firma", "mario.rossi@firma")
    saved = profiles.upsert(store, [], mario)
    anna = profiles.new_profile("Anna", "anna.bianchi", "frStudio")
    saved = profiles.upsert(store, saved, anna)
    assert [p.alias for p in profiles.load_all(store)] == ["Mario", "Anna"]
    assert set(store.data) == {profiles.INDEX_KEY}  # no passwords yet, nothing else
    profiles.set_password(store, mario, "Pw-1")
    assert profiles.password(store, mario) == "Pw-1" and profiles.password(store, anna) is None
    assert store.data[mario.password_key] == "Pw-1"
    renamed = profiles.new_profile("Papà", mario.user, mario.domain, id=mario.id)
    saved = profiles.upsert(store, saved, renamed)
    assert [p.alias for p in saved] == ["Papà", "Anna"] and profiles.password(store, renamed) == "Pw-1"
    saved = profiles.remove(store, saved, renamed)
    assert [p.alias for p in saved] == ["Anna"] and mario.password_key not in store.data


def test_entry_names_are_never_personal():
    store = MemoryStore()
    p = profiles.upsert(store, [], profiles.new_profile("Mario Rossi", "mario.rossi", "firma"))[0]
    profiles.set_password(store, p, "pw")
    for key in store.data:
        assert "mario" not in key.lower() and "rossi" not in key.lower()
    assert "mario.rossi@firma" in store.data[profiles.INDEX_KEY]  # the value is what the wallet encrypts


def test_alias_must_be_unique_case_insensitively():
    store = MemoryStore()
    saved = profiles.upsert(store, [], profiles.new_profile("Mario", "a", "firma"))
    with pytest.raises(CredentialsError, match="già un account chiamato «Mario»"):
        profiles.upsert(store, saved, profiles.new_profile("mario", "b", "firma"))
    assert profiles.find(saved, " MARIO ") is saved[0] and profiles.find(saved, "Anna") is None


@pytest.mark.parametrize(("alias", "user"), [("", "x"), ("  ", "x"), ("Mario", ""), ("Mario", "@firma")])
def test_new_profile_validation(alias, user):
    with pytest.raises(CredentialsError):
        profiles.new_profile(alias, user, "firma")


def test_migration_from_the_single_account_layout():
    store = MemoryStore({credentials.LOGIN_KEY: "mario.rossi@firma", credentials.PASSWORD_KEY: "Pw-1"})
    (p,) = profiles.load_all(store)
    assert (p.alias, p.user, p.domain) == ("mario.rossi", "mario.rossi", "firma")
    assert profiles.password(store, p) == "Pw-1"
    assert credentials.LOGIN_KEY not in store.data and credentials.PASSWORD_KEY not in store.data
    assert profiles.load_all(store) == [p]  # stable: the same id on the next read


def test_migration_without_a_saved_password():
    store = MemoryStore({credentials.LOGIN_KEY: "mario.rossi@firma"})
    (p,) = profiles.load_all(store)
    assert profiles.password(store, p) is None


def test_corrupted_index():
    store = MemoryStore({profiles.INDEX_KEY: "{non json"})
    with pytest.raises(credentials.CredentialStoreError, match="danneggiato"):
        profiles.load_all(store)
    store = MemoryStore({profiles.INDEX_KEY: json.dumps([{"alias": "x"}])})
    with pytest.raises(credentials.CredentialStoreError):
        profiles.load_all(store)


def test_forget_all_leaves_nothing():
    store = MemoryStore({credentials.LOGIN_KEY: "old@firma", credentials.PASSWORD_KEY: "old"})
    saved = profiles.load_all(store)
    saved = profiles.upsert(store, saved, profiles.new_profile("Anna", "anna", "firma"))
    profiles.set_password(store, saved[1], "pw")
    profiles.forget_all(store, saved)
    assert store.data == {}


def test_loading_registers_personal_values_for_the_log():
    store = MemoryStore()
    profiles.upsert(store, [], profiles.new_profile("Papà", "mario.rossi", "firma"))
    logsetup._replacements.clear()
    profiles.load_all(store)
    assert logsetup.redact("Papà firma come mario.rossi@firma") == "P**à firma come m" + "*" * 15 + "a"


def test_timestamp_source_roundtrip_and_default():
    store = MemoryStore()
    saved = profiles.upsert(store, [], profiles.new_profile("Mario", "mario.rossi", "firma",
                                                            timestamp=TimestampSource.BELGIUM))
    saved = profiles.upsert(store, saved, profiles.new_profile("Anna", "anna", "firma"))
    saved = profiles.upsert(store, saved, profiles.new_profile("Ugo", "ugo", "firma", timestamp=TimestampSource.ARUBA))
    assert [p.timestamp for p in profiles.load_all(store)] == [
        TimestampSource.BELGIUM, TimestampSource.NONE, TimestampSource.ARUBA]
    assert [item["marca"] for item in json.loads(store.data[profiles.INDEX_KEY])] == ["belgio", "no", "aruba"]


@pytest.mark.parametrize("stored, expected", [
    (True, TimestampSource.ARUBA),  # older versions: "Marca sempre" on meant Aruba
    (False, TimestampSource.NONE),
    (None, TimestampSource.NONE),
    ("belgio", TimestampSource.BELGIUM),
    ("qualcosa", TimestampSource.NONE),  # unknown (a newer version?): no timestamp rather than a guess
    (7, TimestampSource.NONE),
])
def test_timestamp_source_from_older_and_odd_values(stored, expected):
    store = MemoryStore()
    item = {"id": "a1", "alias": "Vecchio", "login": "x@firma"}
    if stored is not None:
        item["marca"] = stored
    store.data[profiles.INDEX_KEY] = json.dumps([item])
    assert profiles.load_all(store)[0].timestamp is expected


def test_timestamp_source_is_never_used_as_a_bool():
    """A StrEnum member is truthy, "no" included: every check must compare with the members."""
    import re
    from pathlib import Path

    import firmaremota

    root = Path(firmaremota.__file__).parent
    offenders = []
    for path in root.rglob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if re.search(r"(if|and|or|not)\s+[\w.]*\.timestamp\b(?!\s*(is|==|!=|in)\b)(?![\w(\[])", line) \
                    and "profile" in line:
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert offenders == []


def test_tsa_account_fallback_and_saved():
    from firmaremota.models import TsaCredentials

    store = MemoryStore()
    p = profiles.upsert(store, [], profiles.new_profile("Mario", "mario.rossi", "firma"))[0]
    assert profiles.tsa_account(store, p) is None
    assert profiles.tsa_credentials(store, p) is None and profiles.tsa_credentials(None, None) is None  # Aruba's own marks
    profiles.set_tsa(store, p, TsaCredentials("tsa-user", "tsa-pw", "https://tsa.example"))
    assert profiles.tsa_account(store, p) == TsaCredentials("tsa-user", "tsa-pw", "https://tsa.example")
    assert profiles.tsa_credentials(store, p).user == "tsa-user"
    assert set(store.data) == {profiles.INDEX_KEY, p.tsa_key} and "mario" not in p.tsa_key
    profiles.forget_tsa(store, p)
    assert profiles.tsa_account(store, p) is None
    store.data[p.tsa_key] = "{broken"
    with pytest.raises(credentials.CredentialStoreError):
        profiles.tsa_account(store, p)


def test_remove_and_forget_all_delete_the_tsa_entry():
    from firmaremota.models import TsaCredentials

    store = MemoryStore()
    saved = profiles.upsert(store, [], profiles.new_profile("Mario", "mario.rossi", "firma"))
    saved = profiles.upsert(store, saved, profiles.new_profile("Anna", "anna", "firma"))
    for p in saved:
        profiles.set_password(store, p, "pw")
        profiles.set_tsa(store, p, TsaCredentials("u", "p"))
    saved = profiles.remove(store, saved, saved[0])
    assert all(":" not in k or k.endswith(saved[0].id) for k in store.data if k != profiles.INDEX_KEY)
    profiles.forget_all(store, saved)
    assert store.data == {}


def test_tsa_password_is_a_secret_for_the_log():
    from firmaremota.models import TsaCredentials

    store = MemoryStore()
    p = profiles.upsert(store, [], profiles.new_profile("Mario", "mario.rossi", "firma"))[0]
    logsetup._replacements.clear()
    profiles.set_tsa(store, p, TsaCredentials("tsa-user", "Segreto-TSA"))
    assert "Segreto-TSA" not in logsetup.redact("pw Segreto-TSA") and "Segreto-TSA" not in repr(profiles.tsa_account(store, p))
