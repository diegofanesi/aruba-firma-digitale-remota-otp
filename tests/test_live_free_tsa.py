"""Live check of the free timestamp service (Belgian federal TSA). No OTP, nothing from Aruba: the
signatures are made locally with the test certificates, the timestamps are real.

    FIRMA_LIVE=1 uv run pytest tests/test_live_free_tsa.py -s

Downloads the EU, Italian and Belgian trusted lists into the test sandbox, asks the service for three
timestamps (one PDF, one .p7m, one failure case) and checks that each one is qualified.
"""

import os

import pytest

from firmaremota import timestamping, verify
from firmaremota.errors import TimestampUnavailable
from firmaremota.models import Kind

from .test_verify import A4

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("FIRMA_LIVE") != "1", reason="live test: set FIRMA_LIVE=1"),
]


@pytest.fixture(scope="module")
def trust():
    loaded = verify.default_trust()
    assert loaded.trust_checked, "trusted lists not available"
    return loaded


def _recording(stamps):
    clients = []

    def factory():
        clients.append(timestamping.PublicTimeStamper(stamps.url))
        return clients[-1]

    stamps.client_factory = factory
    return clients


def test_pdf_and_p7m_get_a_qualified_belgian_timestamp(trust, sign_pdf, make_pdf, make_p7m):
    stamps = timestamping.FreeTimestamps(trust_factory=lambda: trust)
    clients = _recording(stamps)

    signed = sign_pdf(make_pdf(A4))
    stamped = stamps.stamp(Kind.PADES, b"", signed)
    assert stamped.startswith(signed)
    (timestamp,) = verify.verify_bytes("prova_firmato.pdf", stamped, trust).timestamps
    print(f"\n  [live] PDF: {timestamp.authority}, {timestamp.time:%d/%m/%Y %H:%M:%S %Z}, qualificata "
          f"{timestamp.qualified}, revoca controllata {timestamp.revocation_checked}")
    assert timestamp.trusted and timestamp.qualified is True

    stamped = stamps.stamp(Kind.CADES, b"ciao", make_p7m(b"ciao"))
    (check,) = verify.verify_bytes("nota.txt.p7m", stamped, trust).checks
    print(f"  [live] .p7m: {check.timestamp.authority}, qualificata {check.timestamp.qualified}")
    assert check.timestamp.trusted and check.timestamp.qualified is True

    sizes = [len(token.dump()) for client in clients for _, _, token in client.issued]
    print(f"  [live] token sizes (DER bytes): {sizes}; PDF reserve: {timestamping.PDF_RESERVE // 2}")
    assert len(clients) == 2 and max(sizes) * 2 <= timestamping.PDF_RESERVE // 2  # at least 2x headroom


def test_a_failing_service_is_given_up_after_three_attempts(trust, make_p7m):
    stamps = timestamping.FreeTimestamps("http://tsa.belgium.be/questo-indirizzo-non-esiste",
                                         trust_factory=lambda: trust, waits=(0.5, 0.5))
    with pytest.raises(TimestampUnavailable) as caught:
        stamps.stamp(Kind.CADES, b"ciao", make_p7m(b"ciao"))
    print(f"\n  [live] {caught.value.detail}")
    assert caught.value.detail.count("TimestampRequestError") == 3 and stamps.down
