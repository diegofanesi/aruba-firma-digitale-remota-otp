"""Stamp placement: from the page as the user sees it to the rectangle ARSS expects.

Verified live: ARSS takes points with the origin at the bottom-left and 1-based pages, and it
compensates a page's /Rotate itself (given displayed coordinates on a 90° page it computes the
rotated widget rectangle and an upright appearance). So we send displayed coordinates as they
are; only an unrotated page's CropBox offset is added. For rotated pages whose CropBox differs
from the MediaBox, ARSS's own mapping decides (not verified; rare).
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


def _to_arss(page: PageObject, x: float, y: float) -> tuple[float, float]:
    if _rotation(page) == 0:
        box = page.cropbox
        return float(box.left) + x, float(box.bottom) + y
    return x, y


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
    (ax, ay), (bx, by) = _to_arss(page, x1, y1), _to_arss(page, x2, y2)
    return ResolvedStamp(
        page=number,
        llx=round(min(ax, bx)),
        lly=round(min(ay, by)),
        urx=round(max(ax, bx)),
        ury=round(max(ay, by)),
    )
