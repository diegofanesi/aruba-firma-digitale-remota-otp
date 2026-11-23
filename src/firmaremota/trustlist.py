"""The official lists of qualified signing authorities (EU list of trusted lists -> Italian list).

A list is only cached after its XML signature has been verified (the EU list against the signer
certificates bundled with pyHanko, the Italian list against the certificates the EU list names
for it). Later runs parse the cached copy, refreshing it once it is older than MAX_AGE; when the
network is down an older copy is used and the report says so.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
from dataclasses import dataclass

import requests
from lxml import etree
from pyhanko.sign.validation.qualified import eutl_parse
from pyhanko.sign.validation.qualified.eutl_fetch import EU_LOTL_LOCATION
from pyhanko.sign.validation.qualified.tsp import TSPRegistry

from .config import cache_dir
from .errors import FirmaError

log = logging.getLogger("firmaremota.trustlist")

TERRITORIES = ("IT",)
MAX_AGE = dt.timedelta(days=7)
TIMEOUT = (10, 60)  # connect, read
_TSL_NS = "http://uri.etsi.org/02231/v2#"


class TrustListError(FirmaError):
    """No usable trusted list: never downloaded and no network now."""


@dataclass
class TrustList:
    registry: TSPRegistry
    fetched_at: dt.datetime
    stale: bool  # older than MAX_AGE because the refresh failed


def _dir():
    return cache_dir() / "trustlist"


def _meta_path():
    return _dir() / "meta.json"


def relax_taken_over_by(tl_xml: str) -> str:
    """Mark 'TakenOverBy' extensions non-critical.

    The extension only records which company took a service over; pyHanko doesn't implement it
    and, because Italy marks it critical, would otherwise skip ~30 authorities (old Postecom,
    InfoCamere, Telecom CAs...). Only applied to lists whose signature was already verified.
    """
    root = etree.fromstring(tl_xml.encode("utf-8"))
    for ext in root.iter(f"{{{_TSL_NS}}}Extension"):
        if ext.get("Critical") == "true" and any(
            isinstance(child.tag, str) and etree.QName(child).localname == "TakenOverBy" for child in ext
        ):
            ext.set("Critical", "false")
    return etree.tostring(root, encoding="unicode")


def _parse(lists: dict[str, str]) -> TSPRegistry:
    registry = TSPRegistry()
    for territory, xml in lists.items():
        _, errors = eutl_parse.trust_list_to_registry_unsafe(relax_taken_over_by(xml), registry)
        if errors:
            log.info("elenco %s: %d servizi ignorati", territory, len(errors))
    return registry


def _get(session: requests.Session, url: str) -> str:
    response = session.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    return response.content.decode("utf-8")


def download(session: requests.Session | None = None) -> dict[str, str]:
    """Fetch and verify the EU list of lists and the lists in TERRITORIES; returns their XML."""
    session = session or requests.Session()
    lotl = eutl_parse.validate_and_parse_lotl(_get(session, EU_LOTL_LOCATION), eutl_parse.latest_known_lotl_tlso_certs())
    lists = {}
    for territory in TERRITORIES:
        ref = next((r for r in lotl.references if r.territory == territory), None)
        if ref is None:
            raise TrustListError(f"L'elenco europeo non indica dove trovare l'elenco {territory}.")
        xml = _get(session, ref.location_uri)
        eutl_parse.trust_list_to_registry(xml, ref.tlso_certs)  # raises if the signature doesn't verify
        lists[territory] = xml
    return lists


def _save(lists: dict[str, str], fetched_at: dt.datetime) -> None:
    directory = _dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    meta = {"fetched_at": fetched_at.isoformat(), "lists": {}}
    for territory, xml in lists.items():
        data = xml.encode("utf-8")
        tmp = directory / f"{territory}.xml.tmp"
        tmp.write_bytes(data)
        os.replace(tmp, directory / f"{territory}.xml")
        meta["lists"][territory] = hashlib.sha256(data).hexdigest()
    tmp = directory / "meta.json.tmp"
    tmp.write_text(json.dumps(meta))
    os.replace(tmp, _meta_path())


def _load_cached() -> tuple[dict[str, str], dt.datetime] | None:
    try:
        meta = json.loads(_meta_path().read_text())
        lists = {}
        for territory in TERRITORIES:
            data = (_dir() / f"{territory}.xml").read_bytes()
            if hashlib.sha256(data).hexdigest() != meta["lists"][territory]:
                log.warning("elenco %s in cache danneggiato", territory)
                return None
            lists[territory] = data.decode("utf-8")
        return lists, dt.datetime.fromisoformat(meta["fetched_at"])
    except (OSError, ValueError, KeyError):
        return None


def cached_date() -> dt.datetime | None:
    """When the cached lists were downloaded, or None. Doesn't touch the network."""
    cached = _load_cached()
    return cached[1] if cached else None


def load(allow_network: bool = True, session: requests.Session | None = None) -> TrustList:
    now = dt.datetime.now(dt.timezone.utc)
    cached = _load_cached()
    if cached and now - cached[1] < MAX_AGE:
        return TrustList(_parse(cached[0]), cached[1], stale=False)
    if allow_network:
        try:
            lists = download(session)
            _save(lists, now)
            log.info("elenco di fiducia aggiornato")
            return TrustList(_parse(lists), now, stale=False)
        except Exception as exc:  # network, HTTP, or signature problems: fall back to the cache
            log.warning("aggiornamento elenco di fiducia non riuscito: %s", exc)
    if cached:
        return TrustList(_parse(cached[0]), cached[1], stale=True)
    raise TrustListError(
        "Non è stato possibile scaricare l'elenco ufficiale dei certificatori: "
        "controlla la connessione a Internet e riprova."
    )
