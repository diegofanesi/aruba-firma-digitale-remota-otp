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


@dataclass
class AuthCtx:
    account: Account
    password: str = field(repr=False)
    otp: str | None = field(default=None, repr=False)
    session_id: str | None = field(default=None, repr=False)


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


@dataclass
class JobResult:
    job: SignJob
    output: Path | None = None
    error: FirmaError | None = None

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


@dataclass(frozen=True)
class SignatureCheck:
    """Outcome of checking one signature."""

    signer: SignerInfo
    intact: bool  # the signed data has not changed since signing
    valid: bool  # the signature matches the signer's certificate
    trusted: bool  # the certificate chains to an authority on the trusted list and is in force now
    revoked: bool
    revocation_checked: bool  # False: revocation status could not be fetched (offline?)
    qualified: bool | None  # qualified electronic signature per the trusted list; None = can't tell
    covers_document: bool = True  # PDF: no disallowed changes after this signature

    @property
    def ok(self) -> bool:
        return self.intact and self.valid and self.trusted and not self.revoked and self.covers_document


@dataclass(frozen=True)
class VerifyReport:
    kind: Kind
    checks: list[SignatureCheck]  # .p7m: outermost envelope first
    trust_list_date: dt.datetime | None  # when the trusted list was downloaded; None = not available
    trust_list_stale: bool = False
    content: bytes | None = field(default=None, repr=False)  # the document inside a .p7m
    content_name: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)
