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


@pytest.fixture
def fake_lists(monkeypatch):
    downloads = []

    def download(session=None):
        downloads.append(1)
        return {"IT": "<lista/>"}

    monkeypatch.setattr(trustlist, "download", download)
    monkeypatch.setattr(trustlist, "_parse", lambda lists: f"registro:{sorted(lists)}")
    return downloads


def test_download_then_cache(fake_lists):
    first = trustlist.load()
    assert first.registry == "registro:['IT']" and not first.stale
    second = trustlist.load()
    assert len(fake_lists) == 1 and second.fetched_at == first.fetched_at


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


def test_corrupted_cache_is_ignored(fake_lists):
    trustlist.load()
    (trustlist._dir() / "IT.xml").write_text("<manomessa/>")
    trustlist.load()
    assert len(fake_lists) == 2
