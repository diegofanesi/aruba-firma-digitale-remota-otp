import datetime as dt
import json

import pytest

from firmaremota import trustlist

TL = """<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><Ext>
  <Extension Critical="true"><TakenOverBy><URI>x</URI></TakenOverBy></Extension>
  <Extension Critical="true"><Qualifications/></Extension>
</Ext></TrustServiceStatusList>"""


def test_relax_taken_over_by_only():
    relaxed = trustlist.relax_taken_over_by(TL)
    assert relaxed.count('Critical="false"') == 1
    assert relaxed.count('Critical="true"') == 1


def test_relax_never_expands_entities(tmp_path):
    secret = tmp_path / "segreto.txt"
    secret.write_text("CONTENUTO-RISERVATO")
    evil = (f'<?xml version="1.0"?><!DOCTYPE t [<!ENTITY x SYSTEM "file://{secret}">]>'
            '<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><Ext>&x;</Ext></TrustServiceStatusList>')
    try:
        relaxed = trustlist.relax_taken_over_by(evil)
    except Exception:  # noqa: BLE001 - refusing the document outright is fine too
        return
    assert "CONTENUTO-RISERVATO" not in relaxed


class _Downloads(list):
    verified: list


@pytest.fixture
def fake_lists(monkeypatch):
    """A fake network and a fake signature check; `.verified` records every (re-)verification."""
    downloads, verified = _Downloads(), []

    def download(session=None):
        downloads.append(1)
        return "<lotl/>", {"IT": "<lista/>"}

    def verify(lotl_xml, lists):
        verified.append((lotl_xml, dict(lists)))
        if lotl_xml != "<lotl/>" or any(xml != "<lista/>" for xml in lists.values()):
            raise ValueError("firma non valida")

    monkeypatch.setattr(trustlist, "download", download)
    monkeypatch.setattr(trustlist, "verify", verify)
    monkeypatch.setattr(trustlist, "_parse", lambda lists: f"registro:{sorted(lists)}")
    downloads.verified = verified
    return downloads


def test_download_then_cache(fake_lists):
    first = trustlist.load()
    assert first.registry == "registro:['IT']" and not first.stale
    second = trustlist.load()
    assert len(fake_lists) == 1 and second.fetched_at == first.fetched_at
    assert (trustlist._dir() / "LOTL.xml").read_text() == "<lotl/>"  # the LOTL is cached too, for re-verification


def test_cache_is_reverified_on_every_load(fake_lists):
    trustlist.load()
    trustlist.load()
    assert fake_lists.verified == [("<lotl/>", {"IT": "<lista/>"})]  # once per load from the cache (download verifies itself)


def _age_cache(days):
    meta_path = trustlist._meta_path()
    meta = json.loads(meta_path.read_text())
    meta["fetched_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    meta_path.write_text(json.dumps(meta))


def test_old_cache_is_refreshed(fake_lists):
    trustlist.load()
    _age_cache(30)
    assert not trustlist.load().stale
    assert len(fake_lists) == 2


def test_stale_cache_when_offline(fake_lists, monkeypatch):
    trustlist.load()
    _age_cache(30)
    monkeypatch.setattr(trustlist, "download", lambda session=None: (_ for _ in ()).throw(OSError("offline")))
    assert trustlist.load().stale


def test_nothing_available(monkeypatch):
    monkeypatch.setattr(trustlist, "download", lambda session=None: (_ for _ in ()).throw(OSError("offline")))
    with pytest.raises(trustlist.TrustListError, match="connessione"):
        trustlist.load()


@pytest.mark.parametrize("tampered", ["IT.xml", "LOTL.xml"])
def test_tampered_cache_is_ignored(fake_lists, tampered, monkeypatch):
    """A cached list whose signature no longer verifies is never used, even when offline."""
    trustlist.load()
    (trustlist._dir() / tampered).write_text("<manomessa/>")
    trustlist.load()
    assert len(fake_lists) == 2
    (trustlist._dir() / tampered).write_text("<manomessa/>")
    monkeypatch.setattr(trustlist, "download", lambda session=None: (_ for _ in ()).throw(OSError("offline")))
    with pytest.raises(trustlist.TrustListError):
        trustlist.load()
