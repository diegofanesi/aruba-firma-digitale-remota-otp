"""Plain data types shared by the service layer, the CLI and the GUI."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .errors import FirmaError

LAST_PAGE = -1


class Kind(StrEnum):
    PADES = "pades"  # signed PDF
    CADES = "cades"  # .p7m envelope
    TSD = "tsd"  # RFC 5544 TimeStampedData: a file (or a .p7m) together with its timestamp(s)
    TSR = "tsr"  # RFC 3161 TimeStampResp saved next to the file it timestamps


class TimestampType(StrEnum):
    """How a timestamp goes with a signature (ArubaSign's "Tipo di marcatura")."""

    T = "T"  # timestamp token inside the signature
    LT = "LT"  # as T, plus the revocation data needed to verify it later
    TSD = "TSD"  # CAdES only: the signed .p7m wrapped in a .tsd envelope


class TimestampSource(StrEnum):
    """Who puts the timestamp on a signature: an account setting, overridable for one signing.

    A StrEnum member is always truthy: compare with NONE, never use it as a bool."""

    NONE = "no"
    ARUBA = "aruba"  # Aruba itself: requiredmark (+ a TSA account if saved), levels T/LT/TSD
    BELGIUM = "belgio"  # the free qualified time-stamping service of the Belgian federal government, added here


class Position(StrEnum):
    BOTTOM_RIGHT = "basso-destra"
    BOTTOM_LEFT = "basso-sinistra"
    TOP_RIGHT = "alto-destra"
    TOP_LEFT = "alto-sinistra"


@dataclass(frozen=True)
class Account:
    user: str
    domain: str
    cert_id: str
    type_hsm: str = "COSIGN"


@dataclass(frozen=True)
class TsaCredentials:
    """Account for the time-stamping service (ArubaSign: "Account TSA", "Password", "Indirizzo Server")."""

    user: str
    password: str = field(repr=False)
    url: str | None = None  # None: Aruba's default time-stamping service


@dataclass
class AuthCtx:
    account: Account
    password: str = field(repr=False)
    otp: str | None = field(default=None, repr=False)
    session_id: str | None = field(default=None, repr=False)
    tsa: TsaCredentials | None = field(default=None, repr=False)  # set when signatures must carry a timestamp
    level: TimestampType | None = None  # T or LT with `tsa`; TSD is handled by the service layer (sign, then wrap)


@dataclass(frozen=True)
class StampSpec:
    """Where and what to draw. Coordinates are as the page is seen on screen (origin bottom-left)."""

    page: int = LAST_PAGE  # 1-based, or LAST_PAGE
    position: Position = Position.BOTTOM_RIGHT
    rect: tuple[float, float, float, float] | None = None  # (x1, y1, x2, y2); overrides position
    text: str = ""
    image: bytes | None = field(default=None, repr=False)
    show_date: bool = True
    width: float = 200.0
    height: float = 70.0
    margin: float = 36.0


@dataclass(frozen=True)
class ResolvedStamp:
    """Stamp rectangle as ARSS expects it: points, 1-based page, displayed orientation (ARSS handles /Rotate)."""

    page: int
    llx: int
    lly: int
    urx: int
    ury: int


@dataclass(frozen=True)
class SignJob:
    src: Path
    kind: Kind
    stamp: StampSpec | None = None
    digest: str | None = None  # sha256 of the file when the user approved it; re-checked before sending


@dataclass
class JobResult:
    job: SignJob
    output: Path | None = None
    error: FirmaError | None = None
    timestamped: bool = False  # the saved file carries a timestamp (asked for, or applied by Aruba on its own)
    warning: str | None = None  # saved, but not quite as asked (the free timestamp couldn't be added)

    @property
    def ok(self) -> bool:
        return self.output is not None and self.error is None


@dataclass(frozen=True)
class SignerInfo:
    name: str
    fiscal_code: str | None
    serial: str
    issuer: str
    signing_time: dt.datetime | None
    not_before: dt.datetime
    not_after: dt.datetime
    qualified: bool


def _verdict(intact: bool, valid: bool, trusted: bool, trust_checked: bool, revocation_checked: bool) -> str:
    """'valida', 'non valida', or 'non verificabile' (sound, but trust or revocation unknown)."""
    if not (intact and valid):
        return "non valida"
    if not trust_checked:
        return "non verificabile"
    if not trusted:
        return "non valida"
    return "valida" if revocation_checked else "non verificabile"


@dataclass(frozen=True)
class TimestampInfo:
    """One qualified timestamp (RFC 3161 token): proof that the signed data existed at `time`."""

    time: dt.datetime
    authority: str  # the time-stamping authority's name, from its certificate
    intact: bool  # the token's imprint matches the data it is attached to
    valid: bool  # the token's own signature verifies
    trusted: bool  # the TSA chains to the trusted list and was in force
    qualified: bool | None  # a qualified time-stamping service (QTST) per the trusted list; None = can't tell
    trust_checked: bool = True
    revocation_checked: bool = True

    @property
    def verdict(self) -> str:
        return _verdict(self.intact, self.valid, self.trusted, self.trust_checked, self.revocation_checked)

    @property
    def usable(self) -> bool:
        """Good enough to serve as proof of existence (a time reference "opponibile ai terzi")."""
        return self.intact and self.valid and self.trusted


@dataclass(frozen=True)
class SignatureCheck:
    """Outcome of checking one signature."""

    signer: SignerInfo
    intact: bool  # the signed data has not changed since signing
    valid: bool  # the signature matches the signer's certificate
    trusted: bool  # the certificate chains to an authority on the trusted list and was in force at `valid_at`/now
    revoked: bool
    revocation_checked: bool  # False: revocation status could not be fetched (offline?)
    qualified: bool | None  # qualified electronic signature per the trusted list; None = can't tell
    covers_document: bool = True  # PDF: no disallowed changes after this signature
    trust_checked: bool = True  # False: no trusted list was available, so trust couldn't be assessed
    timestamp: TimestampInfo | None = None  # the signature's own timestamp, if any
    valid_at: dt.datetime | None = None  # set when trust was established at a timestamp's time, not now
    revoked_after_poe: bool = False  # the certificate was revoked, but after the timestamp: the signature stands

    @property
    def verdict(self) -> str:
        """'valida', 'non valida', or 'non verificabile' (sound, but trust or revocation unknown)."""
        if not self.covers_document or self.revoked:
            return "non valida"
        return _verdict(self.intact, self.valid, self.trusted, self.trust_checked, self.revocation_checked)

    @property
    def ok(self) -> bool:
        return self.verdict == "valida"


@dataclass(frozen=True)
class VerifyReport:
    kind: Kind
    checks: list[SignatureCheck]  # .p7m: outermost envelope first
    trust_list_date: dt.datetime | None  # when the trusted list was downloaded; None = not available
    trust_list_stale: bool = False
    content: bytes | None = field(default=None, repr=False)  # the document inside a .p7m
    content_name: str | None = None
    timestamps: list[TimestampInfo] = field(default_factory=list)  # document-level: PDF /DocTimeStamp, .tsd/.tsr tokens
    at: dt.datetime | None = None  # "verifica alla data": the moment the checks were evaluated at (None = now)

    @property
    def verdict(self) -> str:
        verdicts = {c.verdict for c in self.checks}
        if not self.checks or self.kind in (Kind.TSD, Kind.TSR):  # a timestamp-only file is judged by its timestamps
            verdicts |= {t.verdict for t in self.timestamps}
        if not verdicts or "non valida" in verdicts:
            return "non valida"
        return "non verificabile" if "non verificabile" in verdicts else "valida"

    @property
    def ok(self) -> bool:
        return self.verdict == "valida"
