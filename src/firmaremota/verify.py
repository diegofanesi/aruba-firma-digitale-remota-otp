"""Local signature verification (ARSS `verify` returns nothing on the public endpoint).

Trust comes from the official trusted lists (see trustlist.py). Revocation is first checked
strictly; if that fails only because OCSP/CRL couldn't be fetched, the check is repeated
leniently and the result says the revocation status is unknown.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
from io import BytesIO
from pathlib import Path
from typing import Protocol

from asn1crypto import cms
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.generic_cms import async_validate_cms_signature
from pyhanko.sign.validation.qualified.assess import QualificationAssessor
from pyhanko.sign.validation.qualified.q_status import QcCertType, QcPrivateKeyManagementType
from pyhanko.sign.validation.qualified.tsp import TSPTrustManager
from pyhanko.sign.validation.status import SignatureCoverageLevel
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend

from . import p7m, trustlist
from .errors import FileError
from .logsetup import register_paths
from .models import Kind, SignatureCheck, VerifyReport

log = logging.getLogger("firmaremota.verify")


class Trust(Protocol):
    fetched_at: dt.datetime | None
    stale: bool

    def context(self, *, strict_revocation: bool) -> ValidationContext: ...
    def qualified(self, path) -> bool | None: ...


class TrustListTrust:
    """Authorities from the official trusted list; revocation fetched online."""

    def __init__(self, tl: trustlist.TrustList):
        self.registry = tl.registry
        self.fetched_at = tl.fetched_at
        self.stale = tl.stale

    def context(self, *, strict_revocation: bool) -> ValidationContext:
        return ValidationContext(
            trust_manager=TSPTrustManager(self.registry),
            allow_fetching=True,
            revocation_mode="hard-fail" if strict_revocation else "soft-fail",
            fetcher_backend=RequestsFetcherBackend(),
        )

    def qualified(self, path) -> bool | None:
        """Qualified electronic signature: qualified e-signature certificate with the key on a QSCD."""
        try:
            status = QualificationAssessor(self.registry).check_entity_cert_qualified(path).status
        except Exception as exc:
            log.info("qualifica non determinabile: %s", exc)
            return None
        return bool(
            status.qualified
            and status.qc_type == QcCertType.QC_ESIGN
            and status.qc_key_security == QcPrivateKeyManagementType.QSCD
        )


class NoTrust:
    """No trusted list available: integrity can still be checked, trust can't."""

    fetched_at = None
    stale = True

    def context(self, *, strict_revocation: bool) -> ValidationContext:
        return ValidationContext(trust_roots=[], allow_fetching=False)

    def qualified(self, path) -> bool | None:
        return None


def default_trust() -> Trust:
    try:
        return TrustListTrust(trustlist.load())
    except trustlist.TrustListError as exc:
        log.warning("%s", exc.message)
        return NoTrust()


def _with_revocation_fallback(validate, trust: Trust):
    """Run `validate(context)` strictly, then leniently if only the revocation fetch failed."""
    status = validate(trust.context(strict_revocation=True))
    if status.trusted or not status.intact or not status.valid:
        return status, True
    lenient = validate(trust.context(strict_revocation=False))
    if lenient.trusted:
        return lenient, False
    return status, True


def check_pdf(data: bytes, trust: Trust) -> list[SignatureCheck]:
    try:
        signatures = PdfFileReader(BytesIO(data)).embedded_signatures
    except Exception as exc:
        raise FileError("Il file non è un PDF valido o è danneggiato.", detail=str(exc)) from None
    if not signatures:
        raise FileError("Il PDF non contiene firme digitali.")
    checks = []
    for sig in signatures:
        status, revocation_checked = _with_revocation_fallback(lambda ctx: validate_pdf_signature(sig, ctx), trust)
        covered = status.coverage in (SignatureCoverageLevel.ENTIRE_FILE, SignatureCoverageLevel.ENTIRE_REVISION)
        checks.append(SignatureCheck(
            signer=p7m.signer_from_cert(status.signing_cert, status.signer_reported_dt),
            intact=status.intact,
            valid=status.valid,
            trusted=status.trusted,
            revoked=status.revoked,
            revocation_checked=revocation_checked,
            qualified=trust.qualified(status.validation_path) if status.trusted else None,
            covers_document=covered and (status.docmdp_ok or status.modification_level is None),
        ))
    return checks


def _single_signer_views(signed: cms.SignedData):
    """One SignedData per signer: pyHanko validates a single SignerInfo at a time."""
    for signer_info in signed["signer_infos"]:
        view = signed.copy()
        view["signer_infos"] = cms.SignerInfos([signer_info])
        yield view, signer_info


def check_cms(signed: cms.SignedData, trust: Trust) -> list[SignatureCheck]:
    checks = []
    for view, signer_info in _single_signer_views(signed):
        status, revocation_checked = _with_revocation_fallback(
            lambda ctx: asyncio.run(async_validate_cms_signature(view, validation_context=ctx)), trust
        )
        checks.append(SignatureCheck(
            signer=p7m.signer_from_cert(status.signing_cert, p7m.signing_time(signer_info)),
            intact=status.intact,
            valid=status.valid,
            trusted=status.trusted,
            revoked=status.revoked,
            revocation_checked=revocation_checked,
            qualified=trust.qualified(status.validation_path) if status.trusted else None,
        ))
    return checks


def verify_bytes(name: str, data: bytes, trust: Trust | None = None) -> VerifyReport:
    trust = trust or default_trust()
    if data.lstrip()[:5] == b"%PDF-":
        checks = check_pdf(data, trust)
        return VerifyReport(Kind.PADES, checks, trust.fetched_at, trust.stale)
    if not p7m.is_p7m(data):
        raise FileError("Il file non è né un PDF firmato né una busta firmata .p7m.")
    checks, content = [], data
    for signed, content in p7m.iter_layers(data):
        checks.extend(check_cms(signed, trust))
    return VerifyReport(Kind.CADES, checks, trust.fetched_at, trust.stale, content, p7m.inner_name(name, content))


def verify_file(path: Path, trust: Trust | None = None) -> VerifyReport:
    register_paths(path, Path(path).parent)
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise FileError(f"Impossibile leggere {path}: {exc.strerror}") from exc
    return verify_bytes(Path(path).name, data, trust)
