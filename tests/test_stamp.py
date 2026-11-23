import pytest

from firmaremota import stamp
from firmaremota.errors import FileError
from firmaremota.models import LAST_PAGE, Position, ResolvedStamp, StampSpec

A4 = (595, 842)


def test_a4_portrait_presets(make_pdf):
    pdf = make_pdf((*A4, 0, None))
    assert stamp.resolve(pdf, StampSpec()) == ResolvedStamp(1, 359, 36, 559, 106)
    assert stamp.resolve(pdf, StampSpec(position=Position.TOP_LEFT)) == ResolvedStamp(1, 36, 736, 236, 806)
    assert stamp.resolve(pdf, StampSpec(position=Position.BOTTOM_LEFT)) == ResolvedStamp(1, 36, 36, 236, 106)
    assert stamp.resolve(pdf, StampSpec(position=Position.TOP_RIGHT)) == ResolvedStamp(1, 359, 736, 559, 806)


def test_landscape(make_pdf):
    pdf = make_pdf((842, 595, 0, None))
    assert stamp.resolve(pdf, StampSpec()) == ResolvedStamp(1, 606, 36, 806, 106)


@pytest.mark.parametrize(
    ("rotation", "expected"),
    [
        # Shown bottom-right on screen = this corner of the unrotated page.
        (90, ResolvedStamp(1, 489, 606, 559, 806)),  # top-right
        (180, ResolvedStamp(1, 36, 736, 236, 806)),  # top-left
        (270, ResolvedStamp(1, 36, 36, 106, 236)),  # bottom-left
    ],
)
def test_rotated_pages(make_pdf, rotation, expected):
    pdf = make_pdf((*A4, rotation, None))
    assert stamp.resolve(pdf, StampSpec()) == expected


def test_cropbox_offset(make_pdf):
    pdf = make_pdf((*A4, 0, (100, 100, 495, 742)))
    assert stamp.resolve(pdf, StampSpec()) == ResolvedStamp(1, 259, 136, 459, 206)


def test_last_page_uses_its_own_size(make_pdf):
    pdf = make_pdf((*A4, 0, None), (842, 595, 0, None))
    assert stamp.resolve(pdf, StampSpec(page=LAST_PAGE)) == ResolvedStamp(2, 606, 36, 806, 106)
    assert stamp.resolve(pdf, StampSpec(page=1)).page == 1


def test_explicit_rect(make_pdf):
    pdf = make_pdf((*A4, 0, None))
    assert stamp.resolve(pdf, StampSpec(page=1, rect=(50, 50, 250, 120))) == ResolvedStamp(1, 50, 50, 250, 120)
    with pytest.raises(FileError, match="esce dai bordi"):
        stamp.resolve(pdf, StampSpec(page=1, rect=(500, 50, 700, 120)))


def test_missing_page(make_pdf):
    pdf = make_pdf((*A4, 0, None), (*A4, 0, None))
    with pytest.raises(FileError, match="La pagina 5 non esiste: il documento ha 2 pagine"):
        stamp.resolve(pdf, StampSpec(page=5))


def test_tiny_page(make_pdf):
    with pytest.raises(FileError, match="troppo piccola"):
        stamp.resolve(make_pdf((150, 60, 0, None)), StampSpec())


def test_encrypted_pdf(make_pdf):
    with pytest.raises(FileError, match="password"):
        stamp.resolve(make_pdf((*A4, 0, None), password="segreta"), StampSpec())


def test_not_a_pdf():
    with pytest.raises(FileError, match="non è un PDF"):
        stamp.page_count(b"ciao")
