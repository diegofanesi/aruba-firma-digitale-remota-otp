import datetime as dt

import pytest
from pyhanko_certvalidator import ValidationContext

from firmaremota import verify
from firmaremota.errors import FileError
from firmaremota.models import Kind

from .conftest import asn1_cert

PDF = b"%PDF-1.7\nfinto pdf\n"


class RootsTrust:
    """Trust exactly these roots; no network."""

    fetched_at = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
    stale = False

    def __init__(self, *roots):
        self.roots = [asn1_cert(r) for r in roots]

    def context(self, *, strict_revocation):
        if strict_revocation:  # no network: strict mode can only use (empty) revocation data we hand it
            return ValidationContext(trust_roots=self.roots, crls=[], ocsps=[], revocation_mode="hard-fail")
        return ValidationContext(trust_roots=self.roots, allow_fetching=False, revocation_mode="soft-fail")

    def qualified(self, path):
        return None


def test_p7m_trusted(pki, make_p7m):
    report = verify.verify_bytes("contratto.pdf.p7m", make_p7m(PDF), RootsTrust(pki["ca"]))
    assert report.kind is Kind.CADES and report.ok
    assert report.content == PDF and report.content_name == "contratto.pdf"
    (check,) = report.checks
    assert check.signer.name == "Mario Rossi" and check.intact and check.valid and check.trusted
    assert check.revocation_checked  # nothing to fetch: the test certificates name no OCSP/CRL server


def test_p7m_untrusted(make_p7m):
    report = verify.verify_bytes("x.p7m", make_p7m(PDF), RootsTrust())
    assert not report.ok
    assert report.checks[0].intact and not report.checks[0].trusted


def test_p7m_tampered(pki, make_p7m):
    data = make_p7m(PDF).replace(b"finto pdf", b"falso pdf")
    report = verify.verify_bytes("x.p7m", data, RootsTrust(pki["ca"]))
    assert not report.ok and not report.checks[0].intact


def test_p7m_nested_and_parallel(pki, make_p7m):
    inner = make_p7m(PDF, also=[pki["anna"]])  # two parallel signers
    report = verify.verify_bytes("x.pdf.p7m.p7m", make_p7m(inner), RootsTrust(pki["ca"]))
    outer, *inner = [c.signer.name for c in report.checks]
    assert outer == "Mario Rossi" and sorted(inner) == ["Anna Bianchi", "Mario Rossi"]  # signers are a SET
    assert report.ok and report.content == PDF and report.content_name == "x.pdf"


def test_pdf_trusted(pki, make_pdf, sign_pdf):
    report = verify.verify_bytes("a.pdf", sign_pdf(make_pdf((595, 842, 0, None))), RootsTrust(pki["ca"]))
    assert report.kind is Kind.PADES and report.ok
    assert report.checks[0].covers_document


def test_pdf_changed_after_signing(pki, make_pdf, sign_pdf):
    """An incremental update that changes the page (not just adding a signature) is not allowed."""
    from io import BytesIO

    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    writer = IncrementalPdfFileWriter(BytesIO(sign_pdf(make_pdf((595, 842, 0, None)))))
    page = writer.root["/Pages"]["/Kids"][0].get_object()
    page["/MediaBox"] = generic.ArrayObject([generic.NumberObject(n) for n in (0, 0, 300, 300)])
    writer.update_container(page)
    out = BytesIO()
    writer.write(out)
    report = verify.verify_bytes("a.pdf", out.getvalue(), RootsTrust(pki["ca"]))
    assert not report.ok and report.checks[0].intact
    assert not report.checks[0].covers_document


def test_pdf_tampered_inside_signed_bytes(pki, make_pdf, sign_pdf):
    signed = sign_pdf(make_pdf((595, 842, 0, None)))
    assert b"/Producer (pypdf)" in signed
    tampered = signed.replace(b"/Producer (pypdf)", b"/Producer (pypdX)", 1)  # same length, inside the signed range
    report = verify.verify_bytes("a.pdf", tampered, RootsTrust(pki["ca"]))
    assert not report.ok and not report.checks[0].intact


def test_unsigned_and_unknown_files(make_pdf):
    with pytest.raises(FileError, match="non contiene firme"):
        verify.verify_bytes("a.pdf", make_pdf((595, 842, 0, None)), RootsTrust())
    with pytest.raises(FileError, match="né un PDF"):
        verify.verify_bytes("a.txt", b"ciao", RootsTrust())


def test_no_trust_list_still_checks_integrity(make_p7m):
    report = verify.verify_bytes("x.p7m", make_p7m(PDF), verify.NoTrust())
    assert report.checks[0].intact and not report.checks[0].trusted
    assert report.trust_list_date is None
