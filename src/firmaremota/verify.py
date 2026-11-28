"""Local signature verification (ARSS `verify` returns nothing on the public endpoint).

Trust comes from the official trusted lists (see trustlist.py). Each signature is checked in
phases, so that nothing is ever fetched from the network for a document whose chain doesn't
already anchor to a trusted-list CA:

  1. offline: integrity, validity and the chain to a trusted-list anchor, using only what is
     embedded in the signature plus the trusted-list registry (no fetching at all);
  2. only if that anchors: revocation, strictly (OCSP/CRL fetched through a fetcher that refuses
     private/loopback addresses);
  3. if the strict pass fails only because revocation info couldn't be obtained: a lenient pass,
     and the result says revocation is unknown ("non verificabile", never "valida").

Timestamps (marche temporali): a signature's own RFC 3161 token, a PDF document timestamp or
the token of an enclosing .tsd/.tsr prove that the signature existed at a given time. When the
certificate is no longer trusted *now* (expired, revoked later) but a trusted timestamp exists,
the phases are run again "as of" that time: a signature made while the certificate was valid
stays valid (DPCM 22/02/2013 art. 62). `--alla-data` does the same for a user-chosen date.

Verification of untrusted files can also run in a separate process with a timeout
(`verify_file_isolated`), so a crafted file can neither hang nor crash the GUI.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import io
import ipaddress
import logging
import multiprocessing
import pickle
import socket
import threading
import time
from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from typing import Protocol
from urllib.parse import urljoin, urlsplit

import requests
from asn1crypto import cms, x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
from pyhanko.sign.validation.generic_cms import (
    async_validate_cms_signature, collect_timing_info, validate_tst_signed_data,
)
from pyhanko.sign.validation.qualified.assess import QualificationAssessor
from pyhanko.sign.validation.qualified.q_status import QcCertType, QcPrivateKeyManagementType
from pyhanko.sign.validation.qualified.tsp import QTST_URI, TSPTrustManager
from pyhanko.sign.validation.status import (
    SignatureCoverageLevel, StandardCMSSignatureStatus, TimestampSignatureStatus,
)
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.fetchers import Fetchers
from pyhanko_certvalidator.fetchers.common_utils import FetchBudget
from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsCertificateFetcher, RequestsCRLFetcher, RequestsFetcherBackend, RequestsOCSPFetcher,
)

from pyhanko.sign.ades.report import AdESIndeterminate

from . import errors, files, p7m, trustlist, tst
from .errors import FileError, FirmaError, OriginalRequired
from .logsetup import register_paths
from .models import Kind, SignatureCheck, TimestampInfo, VerifyReport

log = logging.getLogger("firmaremota.verify")

VERIFY_TIMEOUT = 180.0  # seconds, for the isolated run: first-time trusted-list download + OCSP fetches


# --- network: only to public addresses --------------------------------------------------------

def url_allowed(url: str) -> bool:
    """http(s) to a host whose every address is public: no loopback, LAN, link-local or reserved.

    OCSP/CRL/AIA addresses come from the certificate under examination, i.e. from whoever made the
    file: without this, a crafted file could make the verifier call hosts on the user's own network.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80),
                                   type=socket.SOCK_STREAM)
        return bool(infos) and all(ipaddress.ip_address(info[4][0]).is_global for info in infos)
    except (OSError, ValueError):
        return False


MAX_FETCH_BYTES = 8 * 1024 * 1024  # an OCSP response or CRL bigger than this is not something we want in memory
MAX_FETCH_HOPS = 3


def _fetch(method: str, url: str, *, data=None, headers: dict, timeout: float) -> requests.Response:
    """GET/POST with every hop checked against `url_allowed` (redirects are followed by hand, never
    automatically to an unchecked host) and the body capped at MAX_FETCH_BYTES."""
    for _ in range(MAX_FETCH_HOPS + 1):
        if not url_allowed(url):
            raise requests.RequestException(f"destinazione non consentita: {url}")
        response = requests.request(method, url, headers=headers, data=data, timeout=timeout,
                                    allow_redirects=False, stream=True)
        try:
            if response.is_redirect and response.headers.get("location"):
                url = urljoin(url, response.headers["location"])
                if response.status_code == 303:
                    method, data = "GET", None
                continue
            if response.status_code != 200:
                raise requests.RequestException(f"status code {response.status_code}")
            content = bytearray()
            for chunk in response.iter_content(64 * 1024):
                content += chunk
                if len(content) > MAX_FETCH_BYTES:
                    raise requests.RequestException("risposta troppo grande")
            response._content = bytes(content)  # what the caller reads through `.content`
            response._content_consumed = True
            return response
        finally:
            response.close()
    raise requests.RequestException("troppi reindirizzamenti")


class _PublicOnly:
    """Mixed into the requests-based fetchers: replaces their plain `requests.get/post` with `_fetch`."""

    def _get(self, url, *, acceptable_content_types):
        headers = {"Accept": ",".join(acceptable_content_types), "User-Agent": self.user_agent}
        return asyncio.to_thread(_fetch, "GET", url, headers=headers, timeout=self.per_request_timeout)

    def _post(self, url, data, *, content_type, acceptable_content_types):
        headers = {"Accept": ",".join(acceptable_content_types), "User-Agent": self.user_agent,
                   "Content-Type": content_type}
        return asyncio.to_thread(_fetch, "POST", url, data=data, headers=headers, timeout=self.per_request_timeout)


class _PublicOCSPFetcher(_PublicOnly, RequestsOCSPFetcher):
    pass


class _PublicCRLFetcher(_PublicOnly, RequestsCRLFetcher):
    pass


class _PublicCertificateFetcher(_PublicOnly, RequestsCertificateFetcher):
    pass


class PublicOnlyFetcherBackend(RequestsFetcherBackend):
    def get_fetchers(self) -> Fetchers:
        budget = FetchBudget(self.limits)
        to = self.per_request_timeout
        return Fetchers(
            ocsp_fetcher=_PublicOCSPFetcher(per_request_timeout=to, budget=budget),
            crl_fetcher=_PublicCRLFetcher(per_request_timeout=to, budget=budget),
            cert_fetcher=_PublicCertificateFetcher(per_request_timeout=to, budget=budget),
        )


# --- trust sources ------------------------------------------------------------------------------

def _meant_for_timestamping(cert: x509.Certificate) -> bool:
    try:
        return "time_stamping" in (cert.extended_key_usage_value.native or [])
    except Exception:  # noqa: BLE001 - a malformed extension just means "no"
        return False


class _TrustManager(TSPTrustManager):
    """pyHanko's manager only chains certificates to CA services; a time-stamping unit's certificate
    may instead be issued by a certificate the list names only as a qualified time-stamping service
    (QTST). Those are accepted as issuers too, but only for certificates meant for time-stamping."""

    def find_potential_issuers(self, cert: x509.Certificate):
        yield from super().find_potential_issuers(cert)
        if not _meant_for_timestamping(cert):
            return
        known_cas = set(self.tsp_registry.known_certificate_authorities)
        for authority in self.tsp_registry.known_timestamp_authorities:
            if authority in known_cas:
                continue
            anchor = self.as_trust_anchor(authority)
            if anchor and authority.is_potential_issuer_of(cert):
                yield anchor


def _at(moment: dt.datetime | None) -> dict:
    """Context arguments for validating "as of" `moment` instead of now (point-in-time validation)."""
    if moment is None:
        return {}
    return {"moment": moment, "best_signature_time": moment, "retroactive_revinfo": True}


class Trust(Protocol):
    fetched_at: dt.datetime | None
    stale: bool
    trust_checked: bool  # False: no trusted list at all, so "trusted" can never be established

    def offline_context(self, moment: dt.datetime | None = None) -> ValidationContext: ...
    def online_context(self, *, strict_revocation: bool, moment: dt.datetime | None = None) -> ValidationContext: ...
    def qualified(self, path, moment: dt.datetime | None = None) -> bool | None: ...
    def qualified_tsa(self, path, moment: dt.datetime | None = None) -> bool | None: ...


class TrustListTrust:
    """Authorities from the official trusted list; revocation fetched online, public hosts only."""

    trust_checked = True

    def __init__(self, tl: trustlist.TrustList):
        self.registry = tl.registry
        self.fetched_at = tl.fetched_at
        self.stale = tl.stale

    def offline_context(self, moment: dt.datetime | None = None) -> ValidationContext:
        return ValidationContext(trust_manager=_TrustManager(self.registry), allow_fetching=False,
                                 revocation_mode="soft-fail", **_at(moment))

    def online_context(self, *, strict_revocation: bool, moment: dt.datetime | None = None) -> ValidationContext:
        return ValidationContext(
            trust_manager=_TrustManager(self.registry),
            allow_fetching=True,
            revocation_mode="hard-fail" if strict_revocation else "soft-fail",
            fetcher_backend=PublicOnlyFetcherBackend(),
            **_at(moment),
        )

    def qualified(self, path, moment: dt.datetime | None = None) -> bool | None:
        """Qualified electronic signature: qualified e-signature certificate with the key on a QSCD."""
        try:
            status = QualificationAssessor(self.registry).check_entity_cert_qualified(path, moment=moment).status
        except Exception as exc:
            log.info("qualifica non determinabile: %s", exc)
            return None
        return bool(
            status.qualified
            and status.qc_type == QcCertType.QC_ESIGN
            and status.qc_key_security == QcPrivateKeyManagementType.QSCD
        )

    def qualified_tsa(self, path, moment: dt.datetime | None = None) -> bool | None:
        """Is the token's trust anchor listed as a qualified time-stamping service at `moment`?"""
        try:
            authority = path.trust_anchor.authority
            services = self.registry.applicable_service_definitions(authority, moment)
            return any(sd.base_info.service_type == QTST_URI for sd in services)
        except Exception as exc:
            log.info("qualifica della marca non determinabile: %s", exc)
            return None


class NoTrust:
    """No trusted list available: integrity can still be checked, trust can't (and nothing is fetched)."""

    fetched_at = None
    stale = True
    trust_checked = False

    def offline_context(self, moment: dt.datetime | None = None) -> ValidationContext:
        return ValidationContext(trust_roots=[], allow_fetching=False, revocation_mode="soft-fail", **_at(moment))

    def online_context(self, *, strict_revocation: bool, moment: dt.datetime | None = None) -> ValidationContext:
        return self.offline_context(moment)

    def qualified(self, path, moment: dt.datetime | None = None) -> bool | None:
        return None

    def qualified_tsa(self, path, moment: dt.datetime | None = None) -> bool | None:
        return None


def default_trust() -> Trust:
    try:
        return TrustListTrust(trustlist.load())
    except trustlist.TrustListError as exc:
        log.warning("%s", exc.message)
        return NoTrust()


# --- the checks ---------------------------------------------------------------------------------

def validate_in_phases(validate: Callable[[ValidationContext], object], trust: Trust,
                       moment: dt.datetime | None = None):
    """(status, revocation_checked) following the three phases described at the top of the module,
    evaluated as of `moment` (None = now).

    pyHanko reports untrusted chains and failed fetches in the status; an exception means the
    signature itself can't be read (unsupported format, signer certificate missing...).
    """
    try:
        offline = validate(trust.offline_context(moment=moment))
        if not trust.trust_checked or not (offline.trusted and offline.intact and offline.valid):
            return offline, False  # nothing to revoke-check; and no network for an unanchored chain
        strict = validate(trust.online_context(strict_revocation=True, moment=moment))
        if strict.trusted:
            return strict, True
        lenient = validate(trust.online_context(strict_revocation=False, moment=moment))
        if lenient.trusted:
            return lenient, False  # only revocation info was missing
        return strict, True
    except FileError:
        raise
    except Exception as exc:
        raise FileError("La firma non è leggibile: il file è danneggiato o usa un formato non supportato.",
                        detail=f"{type(exc).__name__}: {exc}") from None


def _unknown_issuer(status) -> bool:
    """Not trusted because no chain leads from the certificate to an authority on the trusted list (rather
    than because something along a chain that does is expired, revoked or not allowed to sign)."""
    return not status.trusted and status.trust_problem_indic is AdESIndeterminate.NO_CERTIFICATE_CHAIN_FOUND


def _timestamp_info(status, trust: Trust, revocation_checked: bool) -> TimestampInfo | None:
    """A pyHanko TimestampSignatureStatus (or None) as our plain TimestampInfo."""
    if status is None:
        return None
    return TimestampInfo(
        time=status.timestamp,
        authority=p7m.common_name(status.signing_cert),
        intact=status.intact,
        valid=status.valid,
        trusted=status.trusted,
        qualified=trust.qualified_tsa(status.validation_path, status.timestamp) if status.trusted else None,
        trust_checked=trust.trust_checked,
        revocation_checked=revocation_checked,
        unknown_issuer=_unknown_issuer(status),
    )


def _poe(*candidates: TimestampInfo | None) -> dt.datetime | None:
    """Proof of existence: the earliest time attested by a usable timestamp among `candidates`."""
    times = [c.time for c in candidates if c is not None and c.usable]
    return min(times) if times else None


def _with_poe(validate, trust: Trust, status, revocation_checked: bool, poe: dt.datetime | None):
    """Re-evaluate as of `poe` a signature that isn't trusted now (expired or revoked certificate).

    Returns (status, revocation_checked, valid_at, revoked_after_poe): `valid_at` is set only when
    the point-in-time result is what the verdict rests on.
    """
    if poe is None or not (status.intact and status.valid) or (status.trusted and not status.revoked):
        return status, revocation_checked, None, False
    then, rc_then = validate_in_phases(validate, trust, moment=poe)
    if then.trusted and not then.revoked:
        return then, rc_then, poe, bool(status.revoked)
    return status, revocation_checked, None, False


def _check(status, revocation_checked: bool, trust: Trust, signer, *, covers_document: bool = True,
           timestamp: TimestampInfo | None = None, valid_at: dt.datetime | None = None,
           revoked_after_poe: bool = False) -> SignatureCheck:
    return SignatureCheck(
        signer=signer,
        intact=status.intact,
        valid=status.valid,
        trusted=status.trusted,
        revoked=status.revoked,
        revocation_checked=revocation_checked,
        qualified=trust.qualified(status.validation_path, valid_at) if status.trusted else None,
        covers_document=covers_document,
        trust_checked=trust.trust_checked,
        timestamp=timestamp,
        valid_at=valid_at,
        revoked_after_poe=revoked_after_poe,
        unknown_issuer=_unknown_issuer(status),
    )


def check_pdf(data: bytes, trust: Trust, external_poe: TimestampInfo | None = None,
              at: dt.datetime | None = None) -> tuple[list[SignatureCheck], list[TimestampInfo]]:
    """(one check per signature, the document timestamps) of a signed PDF."""
    try:
        reader = PdfFileReader(BytesIO(data))
        signatures = reader.embedded_regular_signatures
        timestamp_fields = reader.embedded_timestamp_signatures
    except Exception as exc:
        raise FileError("Il file non è un PDF valido o è danneggiato.", detail=str(exc)) from None
    if not signatures and not timestamp_fields:
        raise FileError("Il PDF non contiene firme digitali.")
    document_timestamps = []  # (info, revision it was added at)
    for field in timestamp_fields:
        status, revocation_checked = validate_in_phases(lambda ctx, f=field: validate_pdf_timestamp(f, ctx), trust, at)
        document_timestamps.append((_timestamp_info(status, trust, revocation_checked), field.signed_revision))
    checks = []
    for sig in signatures:
        validate = lambda ctx, s=sig: validate_pdf_signature(s, ctx)  # noqa: E731
        status, revocation_checked = validate_in_phases(validate, trust, at)
        own = _timestamp_info(status.timestamp_validity, trust, revocation_checked)
        later = [info for info, revision in document_timestamps if revision > sig.signed_revision]
        status, revocation_checked, valid_at, revoked_after = _with_poe(
            validate, trust, status, revocation_checked, _poe(own, *later, external_poe))
        covered = status.coverage in (SignatureCoverageLevel.ENTIRE_FILE, SignatureCoverageLevel.ENTIRE_REVISION)
        checks.append(_check(status, revocation_checked, trust,
                             p7m.signer_from_cert(status.signing_cert, status.signer_reported_dt),
                             covers_document=covered and (status.docmdp_ok or status.modification_level is None),
                             timestamp=own, valid_at=valid_at, revoked_after_poe=revoked_after))
    return checks, [info for info, _ in document_timestamps]


def _single_signer_views(signed: cms.SignedData):
    """One SignedData per signer: pyHanko validates a single SignerInfo at a time."""
    for signer_info in signed["signer_infos"]:
        view = signed.copy()
        view["signer_infos"] = cms.SignerInfos([signer_info])
        yield view, signer_info


async def _validate_cms(view: cms.SignedData, signer_info: cms.SignerInfo, content: bytes, ctx: ValidationContext):
    """Signature plus its timestamps (pyHanko's plain CMS validation ignores the signature timestamp)."""
    timing = await collect_timing_info(signer_info, ctx, raw_digest=lambda algo: hashlib.new(algo, content).digest())
    return await async_validate_cms_signature(view, status_cls=StandardCMSSignatureStatus, validation_context=ctx,
                                              status_kwargs=timing)


def check_cms(signed: cms.SignedData, content: bytes, trust: Trust, external_poe: TimestampInfo | None = None,
              at: dt.datetime | None = None) -> list[SignatureCheck]:
    checks = []
    for view, signer_info in _single_signer_views(signed):
        validate = lambda ctx, v=view, si=signer_info: asyncio.run(_validate_cms(v, si, content, ctx))  # noqa: E731
        status, revocation_checked = validate_in_phases(validate, trust, at)
        own = _timestamp_info(status.timestamp_validity, trust, revocation_checked)
        status, revocation_checked, valid_at, revoked_after = _with_poe(
            validate, trust, status, revocation_checked, _poe(own, external_poe))
        checks.append(_check(status, revocation_checked, trust,
                             p7m.signer_from_cert(status.signing_cert, p7m.signing_time(signer_info)),
                             timestamp=own, valid_at=valid_at, revoked_after_poe=revoked_after))
    return checks


def _check_token(token: cms.SignedData, imprint: Callable[[str], bytes], trust: Trust,
                 at: dt.datetime | None = None) -> TimestampInfo:
    """One timestamp token; `imprint(algorithm)` is the digest it must carry (a mismatch: not intact)."""
    async def validate_async(ctx):
        return TimestampSignatureStatus(**await validate_tst_signed_data(token, ctx, imprint))

    status, revocation_checked = validate_in_phases(lambda ctx: asyncio.run(validate_async(ctx)), trust, at)
    return _timestamp_info(status, trust, revocation_checked)


def check_tokens(tokens: list[cms.SignedData], content: bytes, trust: Trust,
                 at: dt.datetime | None = None) -> list[TimestampInfo]:
    """Standalone timestamp tokens (.tsd / .tsr) over `content`."""
    return [_check_token(token, lambda algo: hashlib.new(algo, content).digest(), trust, at) for token in tokens]


def check_token_for_digest(token: cms.SignedData, digest: bytes, md_algorithm: str, trust: Trust) -> TimestampInfo:
    """A token just received for `digest`: it must carry exactly that digest, with that algorithm."""
    return _check_token(token, lambda algo: digest if algo == md_algorithm else b"", trust)


def _best(*infos: TimestampInfo | None) -> TimestampInfo | None:
    usable = [i for i in infos if i is not None and i.usable]
    return min(usable, key=lambda i: i.time) if usable else None


def _original_required(name: str) -> OriginalRequired:
    return OriginalRequired(f"Per controllare la marca temporale {name} serve il documento a cui si riferisce: "
                            f"mettilo nella stessa cartella con lo stesso nome senza «.tsr», oppure indicalo "
                            "(dalla riga di comando: --originale FILE).")


MAX_LAYERS = 10


def _pdf_signed(data: bytes) -> bool:
    try:
        reader = PdfFileReader(BytesIO(data))
        return bool(reader.embedded_regular_signatures or reader.embedded_timestamp_signatures)
    except Exception:  # noqa: BLE001 - unreadable as a PDF: not a signed one, at any rate
        return False


def verify_bytes(name: str, data: bytes, trust: Trust | None = None, *, original: bytes | None = None,
                 at: dt.datetime | None = None) -> VerifyReport:
    """Verify a signed/timestamped file: a PDF, a .p7m, a .tsd, a .tsr (with the `original` it refers
    to), or any nesting of them (a .p7m inside a .tsd, a .p7m inside a .p7m...).

    Timestamp containers around a signature give it a proof of existence; a PDF's own signatures
    are checked unless the PDF is itself the content of a signature (then it is "the document").
    """
    trust = trust or default_trust()
    kind: Kind | None = None
    checks: list[SignatureCheck] = []
    timestamps: list[TimestampInfo] = []
    poe: TimestampInfo | None = None
    content, wrapped, timestamped, inside_signature = data, False, False, False
    for _ in range(MAX_LAYERS):
        if not inside_signature and content.lstrip()[:5] == b"%PDF-":
            if timestamped and not _pdf_signed(content):
                break  # a plain PDF that was timestamped: it is the document
            kind = kind or Kind.PADES
            pdf_checks, doc_timestamps = check_pdf(content, trust, external_poe=poe, at=at)
            checks += pdf_checks
            timestamps += doc_timestamps
            break
        if tst.is_tsd(content):
            kind = kind or Kind.TSD
            parsed = tst.parse_tsd(content)
            infos = check_tokens(parsed.tokens, parsed.content, trust, at)
            timestamps += infos
            poe = _best(poe, *infos)
            content, wrapped, timestamped = parsed.content, True, True
        elif tst.is_tsr(content):
            kind = kind or Kind.TSR
            if original is None:
                raise _original_required(name)
            infos = check_tokens([tst.parse_tsr(content)], original, trust, at)
            timestamps += infos
            poe = _best(poe, *infos)
            content, original, timestamped = original, None, True  # the original is what the token speaks about
        elif p7m.is_p7m(content):
            kind = kind or Kind.CADES
            signed = p7m.signed_data(content)
            inner = p7m.layer_content(signed)
            checks += check_cms(signed, inner, trust, external_poe=poe, at=at)
            content, wrapped, inside_signature = inner, True, True
        else:
            break
    if kind is None:
        raise FileError("Il file non è né un PDF firmato, né una busta firmata .p7m, né una marca temporale (.tsd, .tsr).")
    if kind is Kind.TSR and not wrapped:  # a token next to its file: the file stays where it is
        return VerifyReport(kind, checks, trust.fetched_at, trust.stale, timestamps=timestamps, at=at)
    if not wrapped:  # a PDF chosen by the user: nothing to extract
        return VerifyReport(kind, checks, trust.fetched_at, trust.stale, timestamps=timestamps, at=at)
    return VerifyReport(kind, checks, trust.fetched_at, trust.stale, content, p7m.inner_name(name, content),
                        timestamps=timestamps, at=at)


def _read(path: Path) -> bytes:
    problem = files.check_size(path, files.MAX_VERIFY_SIZE)
    if problem:
        raise FileError(problem)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise FileError(f"Impossibile leggere {path}: {exc.strerror}") from exc


def verify_file(path: Path, trust: Trust | None = None, *, original: Path | None = None,
                at: dt.datetime | None = None) -> VerifyReport:
    """`original` is the file a detached .tsr refers to; by default the same name without `.tsr`, next to it."""
    path = Path(path)
    register_paths(path, path.parent)
    original = Path(original) if original else tst.original_for(path)
    original_bytes = None
    if original is not None:
        register_paths(original)
        original_bytes = _read(original)
    return verify_bytes(path.name, _read(path), trust, original=original_bytes, at=at)


def signatures_intact(kind: Kind, data: bytes, original: bytes | None = None) -> bool:
    """Cryptographic self-consistency only (no trust, no network): every signature and timestamp
    intact and valid.

    Used right after signing or timestamping, on what Aruba returned, before the file is saved.
    For a .p7m only the outer envelope is checked (the content may itself be a .p7m the user chose
    to re-sign); for a .tsd/.tsr only the token(s) (what is inside was checked when it was made).
    """
    try:
        if kind is Kind.PADES:
            checks, timestamps = check_pdf(data, NoTrust())
        elif kind is Kind.CADES:
            timestamps = []
            checks = [c for signed, content in p7m.iter_layers(data, max_depth=1)
                      for c in check_cms(signed, content, NoTrust())]
        elif kind is Kind.TSD:
            parsed = tst.parse_tsd(data)
            checks, timestamps = [], check_tokens(parsed.tokens, parsed.content, NoTrust())
            return bool(timestamps) and all(t.intact and t.valid for t in timestamps)
        else:
            if original is None:
                return False
            checks, timestamps = [], check_tokens([tst.parse_tsr(data)], original, NoTrust())
            return all(t.intact and t.valid for t in timestamps)
    except FirmaError:
        return False
    return bool(checks) and all(c.intact and c.valid for c in checks) and all(t.intact and t.valid for t in timestamps)


def has_timestamp(kind: Kind, data: bytes) -> bool:
    """Structural check (no validation): does this signed/timestamped file carry a timestamp token?"""
    try:
        if kind is Kind.PADES:
            reader = PdfFileReader(BytesIO(data))
            return bool(reader.embedded_timestamp_signatures) or any(
                p7m.has_signature_tst(sig.signer_info) for sig in reader.embedded_regular_signatures)
        if kind is Kind.CADES:
            return any(p7m.has_signature_tst(si) for si in p7m.signed_data(data)["signer_infos"])
        if kind is Kind.TSD:
            return bool(tst.parse_tsd(data).tokens)
        if kind is Kind.TSR:
            tst.parse_tsr(data)
            return True
    except Exception:  # noqa: BLE001 - unreadable means "no usable timestamp"
        return False
    return False


# --- running in a separate process ----------------------------------------------------------------

# What the verification child is allowed to send back: our own plain data types and the standard
# library pieces they contain. Anything else in the pickle (a compromised child trying `os.system`)
# is refused, so the child stays a crash/hang sandbox rather than a way back into the GUI process.
_SAFE_MODULES = {"datetime", "pathlib", "pathlib._local", "firmaremota.models"}
_SAFE_BUILTINS = {"set", "frozenset", "list", "dict", "tuple", "bytes", "bytearray", "str", "int", "float",
                  "bool", "complex", "NoneType", "range", "slice"}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module == "builtins" and name in _SAFE_BUILTINS) or module in _SAFE_MODULES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"oggetto non ammesso dal processo di verifica: {module}.{name}")


def _loads(payload: bytes):
    return RestrictedUnpickler(io.BytesIO(payload)).load()


def _child_main(conn, fn, args, kwargs) -> None:  # runs in the child process
    try:
        from . import logsetup

        logsetup.setup()
    except Exception:  # noqa: BLE001 - logging is a nicety here
        pass
    try:
        message = ("ok", fn(*args, **kwargs))
    except FirmaError as exc:
        message = ("firma", type(exc).__name__, exc.message, exc.detail)
    except BaseException as exc:  # noqa: BLE001 - everything must be reported to the parent
        message = ("error", f"{type(exc).__name__}: {exc}")
    try:
        conn.send_bytes(pickle.dumps(message, protocol=pickle.HIGHEST_PROTOCOL))
    finally:
        conn.close()


def run_isolated(fn: Callable, *args, timeout: float = VERIFY_TIMEOUT, cancel: threading.Event | None = None,
                 **kwargs):
    """Call `fn(*args, **kwargs)` in a fresh process; raise what it raised. Kills it on timeout or cancel.

    `fn` must be a module-level function and the arguments/result picklable.
    """
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_child_main, args=(child, fn, args, kwargs), daemon=True)
    process.start()
    child.close()
    deadline = time.monotonic() + timeout
    try:
        while not parent.poll(0.2):
            if cancel is not None and cancel.is_set():
                raise FirmaError("Controllo annullato.")
            if time.monotonic() > deadline:
                raise FileError(
                    f"Il controllo ha superato il tempo massimo ({int(timeout)} s): il file potrebbe essere "
                    "danneggiato o costruito apposta per bloccare il programma.")
        try:
            message = _loads(parent.recv_bytes())
        except EOFError:  # the child died without reporting: segfault, os._exit, OOM kill...
            process.join(5)
            raise FileError("Il controllo si è interrotto in modo anomalo: il file potrebbe essere "
                            "danneggiato o costruito apposta.", detail=f"exit code {process.exitcode}") from None
    finally:
        if process.is_alive():
            process.kill()
        process.join(5)
        parent.close()
    if message[0] == "ok":
        return message[1]
    if message[0] == "firma":
        _, name, text, detail = message
        cls = getattr(errors, str(name), None)
        if not (isinstance(cls, type) and issubclass(cls, FirmaError)):
            cls = FirmaError
        raise cls(str(text), detail=None if detail is None else str(detail))
    raise FileError("Il controllo non è riuscito per un errore imprevisto.", detail=str(message[1]))


def verify_file_isolated(path: Path, cancel: threading.Event | None = None, timeout: float = VERIFY_TIMEOUT, *,
                         original: Path | None = None, at: dt.datetime | None = None) -> VerifyReport:
    return run_isolated(verify_file, Path(path), timeout=timeout, cancel=cancel,
                        original=Path(original) if original else None, at=at)
