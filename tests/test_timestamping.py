"""The free (Belgian) timestamps added after signing: requests, embedding, checks, retries."""

import threading

import pytest
import requests
from asn1crypto import tsp
from pyhanko.sign.timestamps.common_utils import TimestampRequestError

from firmaremota import p7m, timestamping, verify
from firmaremota.errors import TimestampUnavailable
from firmaremota.models import Kind

from .conftest import FIXTURES, TS_TIME, dummy_timestamper
from .test_verify import A4, RootsTrust


class QualifiedRoots(RootsTrust):
    """The test roots, with every trusted time-stamping unit listed as qualified (QTST)."""

    def qualified_tsa(self, path, moment=None):
        return True


class UnqualifiedRoots(RootsTrust):
    """The test roots, but the time-stamping unit is not a qualified service (or that can't be told)."""

    def qualified_tsa(self, path, moment=None):
        return None


class FakeTsa:
    """Stands in for the HTTP call: answers like a real TSA (status, nonce, imprint), and can fail."""

    def __init__(self, stamper, failures=0, error=None):
        self.stamper, self.failures, self.error = stamper, failures, error
        self.requests: list[tsp.TimeStampReq] = []

    def __call__(self, url, body):
        req = tsp.TimeStampReq.load(body)
        self.requests.append(req)
        if len(self.requests) <= self.failures:
            raise self.error or TimestampRequestError("servizio non raggiungibile: prova")
        return self.answer(req).dump()

    def answer(self, req):
        return self.stamper.request_tsa_response(req)


class OtherImprintTsa(FakeTsa):
    def answer(self, req):
        forged = tsp.TimeStampReq({**{k: req[k] for k in ("version", "nonce", "cert_req")},
                                   "message_imprint": {"hash_algorithm": {"algorithm": "sha256"},
                                                       "hashed_message": b"\x00" * 32}})
        return self.stamper.request_tsa_response(forged)


class OtherNonceTsa(FakeTsa):
    def answer(self, req):
        forged = tsp.TimeStampReq({"version": 1, "message_imprint": req["message_imprint"], "nonce": 12345,
                                   "cert_req": True})
        return self.stamper.request_tsa_response(forged)


@pytest.fixture
def tsa(monkeypatch, timestamper):
    def install(fake=None):
        fake = fake or FakeTsa(timestamper)
        monkeypatch.setattr(timestamping, "_post", fake)
        return fake
    return install


class Waits(list):
    def __call__(self, seconds):
        self.append(seconds)
        return True


def free(pki, trust=None, **kwargs):
    kwargs.setdefault("sleep", Waits())
    return timestamping.FreeTimestamps(trust_factory=lambda: trust or QualifiedRoots(pki["ca"]), **kwargs)


# --- the HTTP request ------------------------------------------------------------------------------

class _Response:
    def __init__(self, content_type, content=b"risposta"):
        self.headers, self.content = {"Content-Type": content_type}, content


def test_post_sends_an_rfc3161_request_through_the_checked_fetcher(monkeypatch):
    calls = []
    monkeypatch.setattr(verify, "_fetch", lambda method, url, **kw: calls.append((method, url, kw))
                        or _Response("application/timestamp-reply; charset=binary"))
    assert timestamping._post("http://tsa.example/ts", b"richiesta") == b"risposta"
    ((method, url, kw),) = calls
    assert (method, url, kw["data"], kw["timeout"]) == ("POST", "http://tsa.example/ts", b"richiesta",
                                                         timestamping.REQUEST_TIMEOUT)
    assert kw["headers"]["Content-Type"] == "application/timestamp-query"


def test_post_refuses_other_content_and_wraps_network_errors(monkeypatch):
    monkeypatch.setattr(verify, "_fetch", lambda *a, **kw: _Response("text/html"))
    with pytest.raises(TimestampRequestError, match="text/html"):
        timestamping._post("http://tsa.example/ts", b"richiesta")
    monkeypatch.setattr(verify, "_fetch", lambda *a, **kw: (_ for _ in ()).throw(requests.ConnectionError("giù")))
    with pytest.raises(TimestampRequestError, match="non raggiungibile"):
        timestamping._post("http://tsa.example/ts", b"richiesta")


def test_the_default_service_is_the_belgian_one_over_the_public_only_fetcher():
    stamps = timestamping.FreeTimestamps()
    assert stamps.url == "http://tsa.belgium.be/connect" and stamps.attempts == 3
    assert isinstance(stamps.client_factory(), timestamping.PublicTimeStamper)


# --- embedding ---------------------------------------------------------------------------------------

def test_pdf_gets_a_qualified_document_timestamp_and_keeps_its_bytes(pki, tsa, sign_pdf, make_pdf):
    fake = tsa()
    original = make_pdf(A4)
    signed = sign_pdf(original)
    stamped = free(pki).stamp(Kind.PADES, original, signed)
    assert stamped.startswith(signed) and len(fake.requests) == 1  # no extra "dummy" request for sizing
    report = verify.verify_bytes("a_firmato.pdf", stamped, RootsTrust(pki["ca"]))
    (check,) = report.checks
    assert check.intact and check.valid and check.covers_document
    (timestamp,) = report.timestamps
    assert timestamp.time == TS_TIME and timestamp.trusted and timestamp.authority == "TSA di prova"


def test_p7m_gets_a_signature_timestamp_and_keeps_its_content(pki, tsa, make_p7m):
    tsa()
    signed = make_p7m(b"contenuto firmato")
    stamped = free(pki).stamp(Kind.CADES, b"contenuto firmato", signed)
    report = verify.verify_bytes("nota.txt.p7m", stamped, RootsTrust(pki["ca"]))
    (check,) = report.checks
    assert check.intact and check.valid and report.content == b"contenuto firmato"
    assert check.timestamp is not None and check.timestamp.time == TS_TIME and check.timestamp.trusted


def test_a_signature_that_already_has_a_timestamp_is_not_stamped_again(pki, tsa, make_cades_t):
    fake = tsa()
    with pytest.raises(TimestampUnavailable) as caught:
        free(pki).stamp(Kind.CADES, b"x", make_cades_t(b"x"))
    assert fake.requests == [] and "nessuna firma da marcare" in caught.value.detail


def test_ber_p7m_survives_the_re_encoding(pki, tsa):
    tsa()
    data = (FIXTURES / "ber-indefinite.txt.p7m").read_bytes()
    original = p7m.unwrap(data).content
    stamped = free(pki).stamp(Kind.CADES, original, data)
    assert verify.signatures_intact(Kind.CADES, stamped) and verify.has_timestamp(Kind.CADES, stamped)
    assert p7m.unwrap(stamped).content == original


# --- what counts as a failure, and the retries ----------------------------------------------------------

def test_two_failures_then_success(pki, tsa, make_p7m):
    fake = tsa(FakeTsa(dummy_timestamper(pki, pki["tsa"]), failures=2))
    waits, retries = Waits(), []
    stamped = free(pki, sleep=waits).stamp(Kind.CADES, b"x", make_p7m(b"x"), on_retry=retries.append)
    assert verify.has_timestamp(Kind.CADES, stamped)
    assert len(fake.requests) == 3 and waits == [2.0, 5.0] and retries == [2, 3]


def test_three_failures_give_up_and_the_service_counts_as_down(pki, tsa, make_pdf, sign_pdf):
    fake = tsa(FakeTsa(dummy_timestamper(pki, pki["tsa"]), failures=99))
    waits = Waits()
    stamps = free(pki, sleep=waits)
    signed = sign_pdf(make_pdf(A4))
    with pytest.raises(TimestampUnavailable, match="3 tentativi") as caught:
        stamps.stamp(Kind.PADES, b"", signed)
    assert len(fake.requests) == 3 and waits == [2.0, 5.0]  # no wait after the last attempt
    assert "non raggiungibile" in caught.value.detail
    assert stamps.down
    with pytest.raises(TimestampUnavailable):
        stamps.stamp(Kind.PADES, b"", signed)
    assert len(fake.requests) == 3  # down: not tried again in the same batch


@pytest.mark.parametrize("fake_class", [OtherImprintTsa, OtherNonceTsa])
def test_a_token_not_made_for_this_request_is_refused(pki, tsa, make_p7m, timestamper, fake_class):
    fake = tsa(fake_class(timestamper))
    with pytest.raises(TimestampUnavailable):
        free(pki).stamp(Kind.CADES, b"x", make_p7m(b"x"))
    assert len(fake.requests) == 3


@pytest.mark.parametrize("which", ["non qualificata", "sconosciuta"])
def test_a_token_from_an_unqualified_or_unknown_authority_is_refused(pki, tsa, make_p7m, which):
    tsa()
    trust = UnqualifiedRoots(pki["ca"]) if which == "non qualificata" else QualifiedRoots()  # no roots: unknown
    with pytest.raises(TimestampUnavailable) as caught:
        free(pki, trust=trust).stamp(Kind.CADES, b"x", make_p7m(b"x"))
    assert "marca non accettata" in caught.value.detail


def test_a_garbled_reply_is_a_failure(pki, monkeypatch, make_p7m):
    monkeypatch.setattr(timestamping, "_post", lambda url, body: b"\x30\x03\x02\x01\x00 niente")
    with pytest.raises(TimestampUnavailable):
        free(pki).stamp(Kind.CADES, b"x", make_p7m(b"x"))


def test_cancel_stops_the_retries(pki, tsa, make_p7m):
    cancel = threading.Event()

    class CancelOnFirst(FakeTsa):
        def __call__(self, url, body):
            cancel.set()
            return super().__call__(url, body)

    fake = tsa(CancelOnFirst(dummy_timestamper(pki, pki["tsa"]), failures=99))
    with pytest.raises(TimestampUnavailable) as caught:
        free(pki, cancel=cancel, sleep=None).stamp(Kind.CADES, b"x", make_p7m(b"x"))
    assert len(fake.requests) == 1 and "annullato" in caught.value.detail


def test_trusted_lists_are_loaded_once_per_batch_and_only_when_needed(pki, tsa, make_p7m):
    tsa()
    loads = []

    def trust():
        loads.append(1)
        return QualifiedRoots(pki["ca"])

    stamps = timestamping.FreeTimestamps(trust_factory=trust, sleep=Waits())
    assert loads == []
    stamps.stamp(Kind.CADES, b"a", make_p7m(b"a"))
    stamps.stamp(Kind.CADES, b"b", make_p7m(b"b"))
    assert loads == [1]
