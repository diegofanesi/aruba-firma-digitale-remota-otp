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
    """Stamp rectangle in PDF user space, as ARSS expects it (points, 1-based page)."""

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
