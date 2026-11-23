"""Stamp placement: from the page as the user sees it to the rectangle ARSS expects.

ARSS takes the stamp rectangle in PDF user space (points, origin bottom-left, 1-based page),
verified in Phase 0. Users think in terms of the page as displayed, so presets and explicit
rectangles are expressed in displayed coordinates and mapped back here, taking the page's
/Rotate and a CropBox that doesn't start at (0, 0) into account.
"""

from __future__ import annotations

from io import BytesIO

from pypdf import PageObject, PdfReader

from .errors import FileError
from .models import LAST_PAGE, Position, ResolvedStamp, StampSpec


def open_pdf(pdf: bytes) -> PdfReader:
    try:
        reader = PdfReader(BytesIO(pdf))
        if reader.is_encrypted:
            raise FileError("Il PDF è protetto da password: toglila prima di firmarlo.")
        len(reader.pages)  # parse the page tree now
        return reader
    except FileError:
        raise
    except Exception as exc:  # pypdf raises several error types on damaged files
        raise FileError("Il file non è un PDF valido o è danneggiato.", detail=str(exc)) from None


def page_count(pdf: bytes) -> int:
    return len(open_pdf(pdf).pages)


def _rotation(page: PageObject) -> int:
    return int(page.rotation) % 360


def displayed_size(page: PageObject) -> tuple[float, float]:
    box = page.cropbox
    width, height = float(box.width), float(box.height)
    return (height, width) if _rotation(page) in (90, 270) else (width, height)


def _preset(spec: StampSpec, width: float, height: float) -> tuple[float, float, float, float]:
    w, h = spec.width, spec.height
    margin = min(spec.margin, (width - w) / 2, (height - h) / 2)
    if margin < 0:
        raise FileError("La pagina è troppo piccola per il timbro di firma.")
    left = margin if spec.position in (Position.BOTTOM_LEFT, Position.TOP_LEFT) else width - margin - w
    bottom = margin if spec.position in (Position.BOTTOM_LEFT, Position.BOTTOM_RIGHT) else height - margin - h
    return left, bottom, left + w, bottom + h


def _to_user_space(page: PageObject, x: float, y: float) -> tuple[float, float]:
    """Displayed point -> PDF user space. /Rotate turns the page clockwise when it is shown."""
    box = page.cropbox
    x0, y0, w, h = float(box.left), float(box.bottom), float(box.width), float(box.height)
    rotation = _rotation(page)
    if rotation == 90:
        u, v = w - y, x
    elif rotation == 180:
        u, v = w - x, h - y
    elif rotation == 270:
        u, v = y, h - x
    else:
        u, v = x, y
    return x0 + u, y0 + v


def resolve(pdf: bytes, spec: StampSpec) -> ResolvedStamp:
    reader = open_pdf(pdf)
    count = len(reader.pages)
    number = count if spec.page == LAST_PAGE else spec.page
    if not 1 <= number <= count:
        pages = "1 pagina" if count == 1 else f"{count} pagine"
        raise FileError(f"La pagina {number} non esiste: il documento ha {pages}.")
    page = reader.pages[number - 1]
    width, height = displayed_size(page)
    x1, y1, x2, y2 = spec.rect if spec.rect else _preset(spec, width, height)
    if not (0 <= x1 < x2 <= width and 0 <= y1 < y2 <= height):
        raise FileError("Il timbro di firma esce dai bordi della pagina.")
    (ax, ay), (bx, by) = _to_user_space(page, x1, y1), _to_user_space(page, x2, y2)
    return ResolvedStamp(
        page=number,
        llx=round(min(ax, bx)),
        lly=round(min(ay, by)),
        urx=round(max(ax, bx)),
        ury=round(max(ay, by)),
    )
