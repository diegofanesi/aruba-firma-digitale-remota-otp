"""Free timestamps, added here after Aruba has signed: the qualified time-stamping service of the
Belgian federal government (FPS BOSA), recognised as qualified in every EU country (eIDAS art. 41).

Only a hash leaves the computer: of the signature value (.p7m) or of the signed PDF's byte range.
The service only speaks plain HTTP, so what makes an answer trustworthy is the token itself: its
nonce and imprint must match the request, and its signature must lead to a qualified
time-stamping service (QTST) on the EU trusted lists. Anything less is a failed attempt.

    PDF   a document timestamp appended as an incremental update (PAdES B-T with a document
          timestamp, ETSI EN 319 142-1): Aruba's signed bytes stay an untouched prefix.
    .p7m  a signature-time-stamp unsigned attribute on the outer signature (CAdES-T).

Terms of use (TERMS_URL): free, meant for non-commercial use, may stop at any time. So a failure
is expected now and then: after ATTEMPTS tries the caller keeps the signature without a timestamp.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
from collections.abc import Callable
from io import BytesIO

import requests
from asn1crypto import cms, tsp
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.general import simple_cms_attribute
from pyhanko.sign.signers.pdf_signer import PdfTimeStamper
from pyhanko.sign.timestamps.api import TimeStamper
from pyhanko.sign.timestamps.common_utils import TimestampRequestError, set_tsp_headers

from . import p7m, verify
from .errors import TimestampUnavailable
from .models import Kind

log = logging.getLogger("firmaremota.timestamping")

BELGIUM_TSA_URL = "http://tsa.belgium.be/connect"  # https fails the TLS handshake (checked 2026-11-25)
TERMS_URL = "https://repository.eid.belgium.be/downloads/timestamp/fr/timestamping.pdf"
ATTEMPTS = 3
WAITS = (2.0, 5.0)  # seconds before the 2nd and before the 3rd attempt
REQUEST_TIMEOUT = 15.0
PDF_RESERVE = 32768  # hex digits kept in the PDF for the token, i.e. 16 KB of DER
REPLY_TYPE = "application/timestamp-reply"
UNAVAILABLE = ("Il servizio gratuito di marca temporale non ha risposto ({attempts} tentativi): il documento è "
               "stato firmato senza marca temporale. La firma digitale è valida comunque.")


class AttemptFailed(Exception):
    """One attempt went wrong in a way pyHanko doesn't report itself (our own checks)."""


def _post(url: str, body: bytes) -> bytes:
    """One RFC 3161 request, through the verifier's fetcher: public hosts only, redirects checked by hand,
    size capped."""
    try:
        response = verify._fetch("POST", url, data=body, headers=set_tsp_headers({}), timeout=REQUEST_TIMEOUT)
    except (requests.RequestException, OSError) as exc:
        raise TimestampRequestError(f"servizio non raggiungibile: {exc}") from None
    content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if content_type != REPLY_TYPE:
        raise TimestampRequestError(f"risposta di tipo inatteso: {content_type or 'nessuno'}")
    return response.content


class PublicTimeStamper(TimeStamper):
    """pyHanko's timestamp client over `_post`. Remembers every token it hands out, so that each one can
    be checked against the trusted lists once the file is built (outside pyHanko's event loop)."""

    def __init__(self, url: str):
        super().__init__(include_nonce=True)
        self.url = url
        self.issued: list[tuple[bytes, str, cms.ContentInfo]] = []

    async def async_request_tsa_response(self, req: tsp.TimeStampReq) -> tsp.TimeStampResp:
        body = await asyncio.to_thread(_post, self.url, req.dump())
        try:
            response = tsp.TimeStampResp.load(body)
            response["status"]["status"].native  # a full parse of the status now: a garbled reply fails here
        except Exception as exc:  # noqa: BLE001 - asn1crypto's ValueError/TypeError on malformed input
            raise TimestampRequestError(f"risposta illeggibile: {exc}") from None
        return response

    async def async_timestamp(self, message_digest, md_algorithm) -> cms.ContentInfo:
        token = await super().async_timestamp(message_digest, md_algorithm)  # status and nonce checked here
        self.issued.append((bytes(message_digest), md_algorithm, token))
        return token


def stamp_pdf(signed: bytes, stamper: TimeStamper) -> bytes:
    """`signed` plus a document timestamp, appended as an incremental update."""
    writer = IncrementalPdfFileWriter(BytesIO(signed))
    return PdfTimeStamper(stamper).timestamp_pdf(writer, "sha256", bytes_reserved=PDF_RESERVE).getvalue()


def stamp_cades(signed: bytes, stamper: TimeStamper) -> bytes:
    """`signed` (a .p7m) with a signature timestamp on each outer signature that has none."""
    info = cms.ContentInfo.load(p7m.decode(signed))
    if info["content_type"].native != "signed_data":
        raise AttemptFailed("la busta non contiene una firma")
    added = 0
    for signer_info in info["content"]["signer_infos"]:
        if p7m.has_signature_tst(signer_info):
            continue
        digest = hashlib.sha256(signer_info["signature"].native).digest()
        token = asyncio.run(stamper.async_timestamp(digest, "sha256"))
        existing = signer_info["unsigned_attrs"]
        attributes = list(existing) if isinstance(existing, cms.CMSAttributes) else []
        signer_info["unsigned_attrs"] = cms.CMSAttributes(
            [*attributes, simple_cms_attribute("signature_time_stamp_token", token)])
        added += 1
    if not added:
        raise AttemptFailed("nessuna firma da marcare")
    return info.dump()


def _content(stamped: bytes) -> bytes | None:
    try:
        return p7m.unwrap(stamped, max_depth=1).content
    except Exception:  # noqa: BLE001 - unreadable: certainly not our document
        return None


class FreeTimestamps:
    """The free timestamps for one signing batch.

    Each file gets up to `attempts` tries; whatever goes wrong counts (network, refusal, a token that
    is not qualified or not ours, a stamped file that fails the checks). When a file has used them all,
    the service counts as down for the rest of the batch (`down`), so nobody waits again file after file.
    """

    def __init__(self, url: str = BELGIUM_TSA_URL, *, client_factory: Callable[[], PublicTimeStamper] | None = None,
                 trust_factory: Callable[[], verify.Trust] | None = None, attempts: int = ATTEMPTS,
                 waits: tuple[float, ...] = WAITS, cancel: threading.Event | None = None,
                 sleep: Callable[[float], bool] | None = None):
        self.url = url
        self.client_factory = client_factory or (lambda: PublicTimeStamper(self.url))
        self.trust_factory = trust_factory or verify.default_trust
        self.attempts = attempts
        self.waits = waits
        self.cancel = cancel
        self.sleep = sleep if sleep is not None else self._sleep
        self.down = False
        self._trust: verify.Trust | None = None

    def _sleep(self, seconds: float) -> bool:
        """Wait; False if the user cancelled meanwhile."""
        return not (self.cancel or threading.Event()).wait(seconds)

    def trust(self) -> verify.Trust:
        if self._trust is None:  # the trusted lists, loaded once per batch and only when needed
            self._trust = self.trust_factory()
        return self._trust

    def unavailable(self) -> str:
        return UNAVAILABLE.format(attempts=self.attempts)

    def stamp(self, kind: Kind, original: bytes, signed: bytes,
              on_retry: Callable[[int], None] | None = None) -> bytes:
        """`signed` with a qualified timestamp; TimestampUnavailable when every attempt failed (or was cancelled).

        `original` is the document that was sent for signing (a .p7m must still contain exactly it)."""
        if self.down:
            raise TimestampUnavailable(self.unavailable(), detail="servizio già non disponibile in questa firma")
        failures = []
        for attempt in range(1, self.attempts + 1):
            if attempt > 1:
                if on_retry:
                    on_retry(attempt)
                if not self.sleep(self.waits[min(attempt - 2, len(self.waits) - 1)]):
                    failures.append("annullato")
                    break
            try:
                return self._attempt(kind, original, signed)
            except Exception as exc:  # noqa: BLE001 - every failure counts the same: one attempt gone
                failures.append(f"{type(exc).__name__}: {exc}")
                log.warning("marca temporale gratuita, tentativo %d di %d non riuscito: %s: %s",
                            attempt, self.attempts, type(exc).__name__, exc)
            if self.cancel is not None and self.cancel.is_set():
                failures.append("annullato")
                break
        self.down = True
        raise TimestampUnavailable(self.unavailable(), detail="; ".join(failures))

    def _attempt(self, kind: Kind, original: bytes, signed: bytes) -> bytes:
        client = self.client_factory()
        if kind is Kind.PADES:
            stamped = stamp_pdf(signed, client)
            if not stamped.startswith(signed):
                raise AttemptFailed("il PDF firmato non è rimasto intatto")
        elif kind is Kind.CADES:
            stamped = stamp_cades(signed, client)
            if _content(stamped) != original:
                raise AttemptFailed("la busta non contiene più il documento inviato")
        else:
            raise AttemptFailed(f"tipo di file non previsto: {kind}")
        if not (verify.signatures_intact(kind, stamped) and verify.has_timestamp(kind, stamped)):
            raise AttemptFailed("il file marcato non supera il controllo di integrità")
        if not client.issued:
            raise AttemptFailed("nessuna marca ricevuta")
        for digest, md_algorithm, token in client.issued:
            info = verify.check_token_for_digest(token["content"], digest, md_algorithm, self.trust())
            if info is None or not (info.usable and info.qualified is True):
                raise AttemptFailed(
                    "marca non accettata ("
                    + ("nessuna" if info is None else f"integra {info.intact}, valida {info.valid}, "
                       f"riconosciuta {info.trusted}, qualificata {info.qualified}") + ")")
        return stamped
