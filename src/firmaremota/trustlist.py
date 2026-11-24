"""The official lists of qualified signing authorities (EU list of trusted lists -> Italian list).

Both the EU list (LOTL) and the Italian list are downloaded over HTTPS and their XML signatures
verified (the LOTL against the signer certificates bundled with pyHanko, the Italian list against
the certificates the LOTL names for it). Both are cached, and **re-verified the same way every
time they are loaded from the cache**: the cache is just a copy, never a source of trust. The
cache is refreshed once older than MAX_AGE; when the network is down an older copy is used and
the report says so.
"""

from __future__ import annotations

import datetime as dt
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
_LOTL = "LOTL"
# Entities, DTDs and network access are never needed in a trusted list.
_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)


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
    InfoCamere, Telecom CAs...). Only applied after the list's signature has been verified.
    """
    root = etree.fromstring(tl_xml.encode("utf-8"), parser=_PARSER)
    for ext in root.iter(f"{{{_TSL_NS}}}Extension"):
        if ext.get("Critical") == "true" and any(
            isinstance(child.tag, str) and etree.QName(child).localname == "TakenOverBy" for child in ext
        ):
            ext.set("Critical", "false")
    return etree.tostring(root, encoding="unicode")


def verify(lotl_xml: str, lists: dict[str, str]) -> None:
    """Check the LOTL's signature and, with the signer certificates it names, each territory list's.

    Raises if any signature doesn't verify or a territory is missing from the LOTL.
    """
    lotl = eutl_parse.validate_and_parse_lotl(lotl_xml, eutl_parse.latest_known_lotl_tlso_certs())
    parser_log = logging.getLogger(eutl_parse.__name__)
    level = parser_log.level
    parser_log.setLevel(logging.ERROR)  # this pass is only about the signature: the TakenOverBy noise comes later
    try:
        for territory, xml in lists.items():
            ref = next((r for r in lotl.references if r.territory == territory), None)
            if ref is None:
                raise TrustListError(f"L'elenco europeo non indica dove trovare l'elenco {territory}.")
            eutl_parse.trust_list_to_registry(xml, ref.tlso_certs)  # raises if the signature doesn't verify
    finally:
        parser_log.setLevel(level)


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


def download(session: requests.Session | None = None) -> tuple[str, dict[str, str]]:
    """Fetch the EU list of lists and the lists in TERRITORIES; returns (LOTL XML, {territory: XML}), verified."""
    session = session or requests.Session()
    lotl_xml = _get(session, EU_LOTL_LOCATION)
    lotl = eutl_parse.validate_and_parse_lotl(lotl_xml, eutl_parse.latest_known_lotl_tlso_certs())
    lists = {}
    for territory in TERRITORIES:
        ref = next((r for r in lotl.references if r.territory == territory), None)
        if ref is None:
            raise TrustListError(f"L'elenco europeo non indica dove trovare l'elenco {territory}.")
        lists[territory] = _get(session, ref.location_uri)
    verify(lotl_xml, lists)
    return lotl_xml, lists


def _save(lotl_xml: str, lists: dict[str, str], fetched_at: dt.datetime) -> None:
    directory = _dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, xml in {_LOTL: lotl_xml, **lists}.items():
        tmp = directory / f"{name}.xml.tmp"
        tmp.write_bytes(xml.encode("utf-8"))
        os.replace(tmp, directory / f"{name}.xml")
    tmp = directory / "meta.json.tmp"
    tmp.write_text(json.dumps({"fetched_at": fetched_at.isoformat(), "lists": sorted(lists)}))
    os.replace(tmp, _meta_path())


def _load_cached() -> tuple[str, dict[str, str], dt.datetime] | None:
    """(LOTL XML, lists, fetched_at) from the cache, signatures re-verified; None if unusable."""
    try:
        meta = json.loads(_meta_path().read_text())
        if set(meta["lists"]) != set(TERRITORIES):
            return None
        lotl_xml = (_dir() / f"{_LOTL}.xml").read_text(encoding="utf-8")
        lists = {t: (_dir() / f"{t}.xml").read_text(encoding="utf-8") for t in TERRITORIES}
        fetched_at = dt.datetime.fromisoformat(meta["fetched_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    try:
        verify(lotl_xml, lists)
    except Exception as exc:  # tampered, truncated, or signer certificates rotated
        log.warning("elenco di fiducia in cache non valido, verrà scaricato di nuovo: %s", exc)
        return None
    return lotl_xml, lists, fetched_at


def cached_date() -> dt.datetime | None:
    """When the cached lists were downloaded, or None. Doesn't touch the network (nor verify)."""
    try:
        return dt.datetime.fromisoformat(json.loads(_meta_path().read_text())["fetched_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def load(allow_network: bool = True, session: requests.Session | None = None) -> TrustList:
    now = dt.datetime.now(dt.timezone.utc)
    cached = _load_cached()
    if cached and now - cached[2] < MAX_AGE:
        return TrustList(_parse(cached[1]), cached[2], stale=False)
    if allow_network:
        try:
            lotl_xml, lists = download(session)
            _save(lotl_xml, lists, now)
            log.info("elenco di fiducia aggiornato")
            return TrustList(_parse(lists), now, stale=False)
        except Exception as exc:  # network, HTTP, or signature problems: fall back to the cache
            log.warning("aggiornamento elenco di fiducia non riuscito: %s", exc)
    if cached:
        return TrustList(_parse(cached[1]), cached[2], stale=True)
    raise TrustListError(
        "Non è stato possibile scaricare l'elenco ufficiale dei certificatori: "
        "controlla la connessione a Internet e riprova."
    )
