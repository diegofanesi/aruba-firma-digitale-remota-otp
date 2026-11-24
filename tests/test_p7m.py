import pytest

from firmaremota import p7m
from firmaremota.errors import FileError

from .conftest import FIXTURES

PDF = b"%PDF-1.7\nfinto pdf\n"


@pytest.mark.parametrize("encoding", ["der", "pem", "b64crlf"])
def test_unwrap_all_encodings(make_p7m, encoding):
    result = p7m.unwrap(make_p7m(PDF, encoding=encoding))
    assert result.content == PDF
    assert len(result.layers) == 1
    (signer,) = result.layers[0]
    assert signer.name == "Mario Rossi"
    assert signer.fiscal_code == "RSSMRA80A01H501U"
    assert signer.issuer == "CA di prova"
    assert signer.qualified is True
    assert signer.signing_time is not None


def test_unwrap_ber_indefinite_length():
    data = (FIXTURES / "ber-indefinite.txt.p7m").read_bytes()
    assert data[:2] == b"\x30\x80"  # indefinite length, like Aruba's output
    result = p7m.unwrap(data)
    assert result.content == b"contenuto di prova BER\n"
    assert result.layers[0][0].name == "Mario Rossi"
    assert result.layers[0][0].qualified is False


def test_unwrap_nested_three_levels(make_p7m):
    data = PDF
    for _ in range(3):
        data = make_p7m(data)
    result = p7m.unwrap(data)
    assert result.content == PDF
    assert len(result.layers) == 3


def test_unwrap_stops_at_max_depth(make_p7m):
    data = make_p7m(make_p7m(PDF))
    result = p7m.unwrap(data, max_depth=1)
    assert p7m.is_p7m(result.content)
    assert len(result.layers) == 1


def test_detached_signature_is_reported(make_p7m):
    with pytest.raises(FileError, match="separata"):
        p7m.unwrap(make_p7m(PDF, detached=True))


@pytest.mark.parametrize("data", [b"", b"non sono una firma", b"\x30\x03\x02\x01\x00", PDF])
def test_garbage_is_rejected(data):
    assert not p7m.is_p7m(data)
    with pytest.raises(FileError):
        p7m.unwrap(data)


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    [
        ("contratto.pdf.p7m", PDF, "contratto.pdf"),
        ("Contratto.PDF.P7M", PDF, "Contratto.PDF"),
        ("doppia.pdf.p7m.p7m", PDF, "doppia.pdf"),
        ("fattura.p7m", b'<?xml version="1.0"?><a/>', "fattura.xml"),
        ("pacchetto.p7m", b"PK\x03\x04resto", "pacchetto.zip"),
        ("ignoto.p7m", b"\x00\x01", "ignoto"),
        (".p7m", PDF, "documento.pdf"),
        ("IT01234567890_00001.xml.p7m", b"<?xml?>", "IT01234567890_00001.xml"),
    ],
)
def test_inner_name(name, content, expected):
    assert p7m.inner_name(name, content) == expected


@pytest.mark.parametrize(("name", "expected"), [
    ("contratto.pdf.tsd", "contratto.pdf"), ("contratto.pdf.p7m.tsd", "contratto.pdf"), ("X.PDF.P7M.TSD", "X.PDF"),
    ("nota.txt.tsr", "nota.txt.tsr"),  # a .tsr holds no document: nothing to strip
])
def test_inner_name_strips_tsd_too(name, expected):
    assert p7m.inner_name(name, b"") == expected


def test_tst_unwrap_mixes_envelopes(make_p7m, make_tsd):
    from firmaremota import tst

    result = tst.unwrap(make_tsd(make_p7m(make_tsd(PDF))))
    assert result.content == PDF and result.timestamps == 2 and [s.name for layer in result.layers for s in layer] == ["Mario Rossi"]
    assert tst.unwrap(b"ciao") == tst.Unwrapped(b"ciao", [], 0)
