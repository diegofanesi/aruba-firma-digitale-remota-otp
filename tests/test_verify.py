import datetime as dt

import pytest
from pyhanko_certvalidator import ValidationContext

from firmaremota import messages, verify
from firmaremota.errors import FileError, OriginalRequired
from firmaremota.models import Kind

from .conftest import TS_TIME, asn1_cert, dummy_timestamper, with_ocsp_in_crls

PDF = b"%PDF-1.7\nfinto pdf\n"
A4 = (595, 842, 0, None)


class RootsTrust:
    """Trust exactly these roots; no network. Records which contexts were asked for, and as of when."""

    fetched_at = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
    stale = False
    trust_checked = True

    def __init__(self, *roots):
        self.roots = [asn1_cert(r) for r in roots]
        self.asked: list[str] = []
        self.moments: list[dt.datetime | None] = []

    def offline_context(self, moment=None):
        self.asked.append("offline")
        self.moments.append(moment)
        return ValidationContext(trust_roots=self.roots, allow_fetching=False, revocation_mode="soft-fail",
                                 **verify._at(moment))

    def online_context(self, *, strict_revocation, moment=None):
        self.asked.append("strict" if strict_revocation else "lenient")
        self.moments.append(moment)
        if strict_revocation:  # no network: strict mode can only use (empty) revocation data we hand it
            return ValidationContext(trust_roots=self.roots, crls=[], ocsps=[], revocation_mode="hard-fail",
                                     **verify._at(moment))
        return ValidationContext(trust_roots=self.roots, allow_fetching=False, revocation_mode="soft-fail",
                                 **verify._at(moment))

    def qualified(self, path, moment=None):
        return None

    def qualified_tsa(self, path, moment=None):
        return True  # whatever chains to our roots plays a qualified time-stamping service


def test_p7m_trusted(pki, make_p7m):
    report = verify.verify_bytes("contratto.pdf.p7m", make_p7m(PDF), RootsTrust(pki["ca"]))
    assert report.kind is Kind.CADES and report.ok
    assert report.content == PDF and report.content_name == "contratto.pdf"
    (check,) = report.checks
    assert check.signer.name == "Mario Rossi" and check.intact and check.valid and check.trusted
    assert check.revocation_checked  # nothing to fetch: the test certificates name no OCSP/CRL server


def test_p7m_untrusted_and_nothing_is_fetched(make_p7m):
    trust = RootsTrust()
    report = verify.verify_bytes("x.p7m", make_p7m(PDF), trust)
    assert not report.ok and report.verdict == "non valida"
    assert report.checks[0].intact and not report.checks[0].trusted
    assert trust.asked == ["offline"]  # an unanchored chain never triggers OCSP/CRL/AIA fetches


def test_trusted_chain_is_checked_offline_then_strictly(pki, make_p7m):
    trust = RootsTrust(pki["ca"])
    verify.verify_bytes("x.p7m", make_p7m(PDF), trust)
    assert trust.asked == ["offline", "strict"]


class RevocationUnknownTrust(RootsTrust):
    """Anchored, but the strict (hard-fail) pass can't get revocation data: like being offline."""

    def online_context(self, *, strict_revocation, moment=None):
        self.asked.append("strict" if strict_revocation else "lenient")
        if strict_revocation:
            return ValidationContext(trust_roots=[], allow_fetching=False)  # plays "revocation unavailable"
        return ValidationContext(trust_roots=self.roots, allow_fetching=False, revocation_mode="soft-fail")


def test_unknown_revocation_is_not_valid(pki, make_p7m):
    trust = RevocationUnknownTrust(pki["ca"])
    report = verify.verify_bytes("x.p7m", make_p7m(PDF), trust)
    (check,) = report.checks
    assert check.trusted and check.intact and not check.revocation_checked
    assert report.verdict == check.verdict == "non verificabile" and not report.ok
    assert trust.asked == ["offline", "strict", "lenient"]
    lines = messages.check_lines(check)
    assert lines[0] == "FIRMA NON VERIFICABILE" and any("revocato" in line and "Riprova" in line for line in lines)


def test_no_trusted_list_is_not_valid(make_p7m):
    report = verify.verify_bytes("x.p7m", make_p7m(PDF), verify.NoTrust())
    (check,) = report.checks
    assert check.intact and check.valid and not check.trust_checked
    assert report.verdict == "non verificabile" and not report.ok
    assert "elenco ufficiale dei certificatori non è disponibile" in " ".join(messages.check_lines(check))


def test_tampered_beats_unverifiable(make_p7m):
    data = make_p7m(PDF).replace(b"finto pdf", b"falso pdf")
    assert verify.verify_bytes("x.p7m", data, verify.NoTrust()).verdict == "non valida"


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



# --- network policy -----------------------------------------------------------------------------

def test_url_allowed_refuses_everything_but_public_http(monkeypatch):
    table = {"ocsp.example": "93.184.216.34", "lan.example": "192.168.1.10", "both.example": None,
             "v6.example": "2001:db8::1"}

    def getaddrinfo(host, port, **kwargs):
        if host == "both.example":
            return [(None, None, None, None, ("93.184.216.34", port)), (None, None, None, None, ("10.0.0.1", port))]
        if host not in table:
            raise OSError("nome sconosciuto")
        return [(None, None, None, None, (table[host], port))]

    monkeypatch.setattr(verify.socket, "getaddrinfo", getaddrinfo)
    assert verify.url_allowed("http://ocsp.example/x") and verify.url_allowed("https://ocsp.example:8443/x")
    for url in ("http://lan.example/x", "http://both.example/x", "http://v6.example/x", "http://127.0.0.1/x",
                "http://[::1]/x", "http://169.254.169.254/latest", "http://10.1.2.3/", "file:///etc/passwd",
                "ftp://ocsp.example/x", "ldap://ocsp.example/x", "http://unknown.example/x", "", "http:///x"):
        assert not verify.url_allowed(url), url


def test_public_only_fetchers_never_connect_to_private_hosts(monkeypatch):
    import asyncio

    import requests

    calls = []
    monkeypatch.setattr(verify.requests, "request", lambda *a, **kw: calls.append(kw) or (_ for _ in ()).throw(OSError))
    fetchers = verify.PublicOnlyFetcherBackend().get_fetchers()
    for fetcher in (fetchers.ocsp_fetcher, fetchers.crl_fetcher, fetchers.cert_fetcher):
        with pytest.raises(requests.RequestException, match="non consentita"):
            asyncio.run(fetcher._get("http://192.168.0.1/ocsp", acceptable_content_types=["*/*"]))
        with pytest.raises(requests.RequestException, match="non consentita"):
            asyncio.run(fetcher._post("http://127.0.0.1/ocsp", b"", content_type="x", acceptable_content_types=["*/*"]))
    assert calls == []


def test_trust_list_trust_uses_the_public_only_backend():
    tl = type("TL", (), {"registry": verify.trustlist.TSPRegistry(), "fetched_at": None, "stale": False})()
    trust = verify.TrustListTrust(tl)
    assert not trust.offline_context().fetching_allowed
    online = trust.online_context(strict_revocation=True)
    assert online.fetching_allowed
    fetchers = online.revinfo_manager._fetchers  # where pyHanko keeps the backend's fetchers
    for fetcher in (fetchers.ocsp_fetcher, fetchers.crl_fetcher, fetchers.cert_fetcher):
        assert isinstance(fetcher, verify._PublicOnly)


# --- what Aruba returns ---------------------------------------------------------------------------

def test_signatures_intact(make_p7m, make_pdf, sign_pdf):
    pdf = make_pdf((595, 842, 0, None))
    assert verify.signatures_intact(Kind.PADES, sign_pdf(pdf))
    assert not verify.signatures_intact(Kind.PADES, pdf)  # unsigned
    assert not verify.signatures_intact(Kind.PADES, pdf + b"\n% firmato\n")
    assert verify.signatures_intact(Kind.CADES, make_p7m(b"dati"))
    assert verify.signatures_intact(Kind.CADES, make_p7m(make_p7m(b"dati")))  # re-signing a .p7m: outer layer only
    assert not verify.signatures_intact(Kind.CADES, make_p7m(b"dati").replace(b"dati", b"datx"))
    assert not verify.signatures_intact(Kind.CADES, b"spazzatura")


# --- the separate process -------------------------------------------------------------------------

def _echo(value):
    return value


def _raise_firma():
    raise FileError("non leggibile", detail="dettaglio")


def _crash():
    import os

    os._exit(9)


def _hang(seconds):
    import time

    time.sleep(seconds)


def test_run_isolated_returns_and_raises_like_a_call():
    assert verify.run_isolated(_echo, {"a": [1, 2]}) == {"a": [1, 2]}
    with pytest.raises(FileError, match="non leggibile") as exc:
        verify.run_isolated(_raise_firma)
    assert exc.value.detail == "dettaglio"


def test_run_isolated_survives_a_crash_and_a_hang():
    with pytest.raises(FileError, match="in modo anomalo"):
        verify.run_isolated(_crash)
    with pytest.raises(FileError, match="tempo massimo"):
        verify.run_isolated(_hang, 30, timeout=1.5)


def test_run_isolated_can_be_cancelled():
    import threading

    cancel = threading.Event()
    cancel.set()
    with pytest.raises(verify.FirmaError, match="annullato"):
        verify.run_isolated(_hang, 30, cancel=cancel)


def test_verification_round_trips_through_the_child_process(make_p7m):
    """A real report (dataclasses, certificates' data, bytes) comes back intact from the spawned process."""
    report = verify.run_isolated(verify.verify_bytes, "contratto.pdf.p7m", make_p7m(PDF), verify.NoTrust())
    assert report.kind is Kind.CADES and report.content == PDF and report.content_name == "contratto.pdf"
    assert report.checks[0].intact and report.checks[0].signer.name == "Mario Rossi"
    assert report.verdict == "non verificabile"  # NoTrust: sound, but no list to anchor to


# --- timestamps (marche temporali) -------------------------------------------------------------------

def test_pdf_with_doc_timestamp_is_readable_and_covered(pki, make_pdf, sign_pdf):
    """A PDF with a document timestamp (/DocTimeStamp, what LTA updates add) used to be 'non leggibile'."""
    report = verify.verify_bytes("a.pdf", sign_pdf(make_pdf(A4), doc_timestamp=True), RootsTrust(pki["ca"]))
    assert report.ok and report.checks[0].covers_document and report.checks[0].timestamp is None
    (ts,) = report.timestamps
    assert ts.usable and ts.time == TS_TIME and ts.authority == "TSA di prova" and ts.qualified is True
    assert "Marca temporale sul documento:" in messages.timestamp_lines(report)[0]


def test_pdf_signature_timestamp_reported(pki, make_pdf, sign_pdf):
    report = verify.verify_bytes("a.pdf", sign_pdf(make_pdf(A4), timestamp=True), RootsTrust(pki["ca"]))
    (check,) = report.checks
    assert report.ok and check.timestamp.time == TS_TIME and check.timestamp.authority == "TSA di prova"
    assert check.timestamp.verdict == "valida" and check.valid_at is None  # trusted today: no need for the proof
    text = " ".join(messages.check_lines(check))
    assert "Marca temporale:" in text and "qualificata" in text and "scaduto" not in text


def test_cades_t_timestamp_reported(pki, make_cades_t):
    report = verify.verify_bytes("x.pdf.p7m", make_cades_t(PDF), RootsTrust(pki["ca"]))
    (check,) = report.checks
    assert report.ok and check.timestamp.time == TS_TIME and report.content == PDF and report.content_name == "x.pdf"


def test_expired_signer_valid_at_timestamp(pki, make_cades_t):
    """The certificate expired yesterday; the timestamp proves the signature existed while it was valid."""
    trust = RootsTrust(pki["ca"])
    report = verify.verify_bytes("x.p7m", make_cades_t(PDF, who="scaduto"), trust)
    (check,) = report.checks
    assert report.verdict == "valida" and check.trusted and check.valid_at == TS_TIME
    assert check.signer.name == "Carlo Verdi" and not check.revoked_after_poe
    assert trust.moments[0] is None and TS_TIME in trust.moments  # judged now first, then as of the timestamp
    lines = messages.check_lines(check)
    assert lines[0] == "FIRMA VALIDA" and any("la firma vale" in line and "scaduto" in line for line in lines)


def test_expired_signer_without_timestamp_stays_invalid(pki, make_p7m):
    report = verify.verify_bytes("x.p7m", make_p7m(PDF, who="scaduto"), RootsTrust(pki["ca"]))
    assert report.verdict == "non valida" and not report.checks[0].trusted and report.checks[0].valid_at is None
    assert any("scaduto il" in line for line in messages.check_lines(report.checks[0]))


def test_expired_signer_with_timestamp_after_expiry_stays_invalid(pki, make_cades_t):
    late = dummy_timestamper(pki, pki["tsa"], when=dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
    report = verify.verify_bytes("x.p7m", make_cades_t(PDF, who="scaduto", stamper=late), RootsTrust(pki["ca"]))
    (check,) = report.checks
    assert report.verdict == "non valida" and check.timestamp.usable and check.valid_at is None


def _rogue_tsa(pki):
    """A time-stamping unit under a CA nobody trusts."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Altra CA")])
    now = dt.datetime.now(dt.timezone.utc)
    (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
     .serial_number(1).not_valid_before(now - dt.timedelta(days=30)).not_valid_after(now + dt.timedelta(days=30))
     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return pki["make_tsa"]("TSA sconosciuta", issuer_name=name, issuer_key=key)


def test_untrusted_timestamp_is_reported_but_ignored(pki, make_cades_t):
    stamper = dummy_timestamper(pki, _rogue_tsa(pki))
    trust = RootsTrust(pki["ca"])
    report = verify.verify_bytes("x.p7m", make_cades_t(PDF, who="scaduto", stamper=stamper), trust)
    (check,) = report.checks
    assert check.timestamp.intact and check.timestamp.valid and not check.timestamp.trusted
    assert report.verdict == "non valida" and check.valid_at is None  # an unknown TSA proves nothing
    assert trust.asked == ["offline"]  # and nothing was fetched for either chain
    assert "NON riconosciuta" in messages.timestamp_line(check.timestamp)
    valid_now = verify.verify_bytes("y.p7m", make_cades_t(PDF, stamper=stamper), RootsTrust(pki["ca"]))
    assert valid_now.ok and not valid_now.checks[0].timestamp.trusted  # the signature is judged on its own


def test_tsa_listed_only_as_qtst_is_an_anchor(pki, make_cades_t):
    """Italian lists name time-stamping services separately from CAs: a TSU certificate must chain to them."""
    from pyhanko.sign.validation.qualified.tsp import (
        QTST_URI, BaseServiceInformation, QTSTServiceInformation, TSPRegistry,
    )

    from firmaremota import trustlist

    now = dt.datetime.now(dt.timezone.utc)
    registry = TSPRegistry()
    base = BaseServiceInformation(service_type=QTST_URI, service_name="TSA di prova", valid_from=now - dt.timedelta(days=365),
                                  valid_until=None, provider_certs=(asn1_cert(pki["ca"]),),
                                  additional_info_certificate_type=frozenset(), other_additional_info=frozenset())
    registry.register_tst(QTSTServiceInformation(base_info=base, qualifications=frozenset()))
    trust = verify.TrustListTrust(trustlist.TrustList(registry, now, stale=False))
    report = verify.verify_bytes("x.p7m", make_cades_t(PDF), trust)
    (check,) = report.checks
    assert check.timestamp.trusted and check.timestamp.qualified is True
    assert not check.trusted  # listed only as a time-stamping service: it vouches for TSUs, not for signers


def test_verify_at_date_uses_moment(pki, make_p7m):
    trust = RootsTrust(pki["ca"])
    report = verify.verify_bytes("x.p7m", make_p7m(PDF, who="scaduto"), trust, at=TS_TIME)
    assert report.verdict == "valida" and report.at == TS_TIME and trust.moments[0] == TS_TIME
    assert messages.trust_list_line(report).startswith("Verifica alla data del")


def test_pdf_with_only_a_document_timestamp(pki, make_pdf, timestamper):
    from io import BytesIO

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.signers.pdf_signer import PdfTimeStamper

    data = PdfTimeStamper(timestamper).timestamp_pdf(IncrementalPdfFileWriter(BytesIO(make_pdf(A4))), "sha256").getvalue()
    report = verify.verify_bytes("a.pdf", data, RootsTrust(pki["ca"]))
    assert report.checks == [] and len(report.timestamps) == 1 and report.verdict == "valida"
    assert messages.verdict_title(report) == "MARCA TEMPORALE VALIDA"


def test_signatures_intact_with_timestamps(make_pdf, sign_pdf, make_cades_t):
    assert verify.signatures_intact(Kind.PADES, sign_pdf(make_pdf(A4), doc_timestamp=True))
    assert verify.signatures_intact(Kind.PADES, sign_pdf(make_pdf(A4), timestamp=True))
    assert verify.signatures_intact(Kind.CADES, make_cades_t(b"dati"))
    assert not verify.signatures_intact(Kind.CADES, make_cades_t(b"dati").replace(b"dati", b"datx"))


def test_report_with_timestamps_pickles_through_run_isolated(make_pdf, sign_pdf):
    data = sign_pdf(make_pdf(A4), timestamp=True, doc_timestamp=True)
    report = verify.run_isolated(verify.verify_bytes, "a.pdf", data, verify.NoTrust())
    assert report.checks[0].timestamp is not None and len(report.timestamps) == 1
    assert report.verdict == "non verificabile" and not report.timestamps[0].trust_checked


def test_verdict_keys_are_consistent_everywhere():
    from firmaremota import cli

    keys = {"valida", "non valida", "non verificabile"}
    assert set(messages.VERDICT_TITLES) == set(messages.TIMESTAMP_TITLES) == keys
    assert set(cli.VERDICT_EXIT) | {"non valida"} == keys


# --- standalone timestamps: .tsd and .tsr -----------------------------------------------------------

def test_tsd_over_plain_file_valid(pki, make_tsd):
    report = verify.verify_bytes("nota.txt.tsd", make_tsd(b"ciao"), RootsTrust(pki["ca"]))
    assert report.kind is Kind.TSD and report.verdict == "valida" and report.checks == []
    assert report.content == b"ciao" and report.content_name == "nota.txt"
    (ts,) = report.timestamps
    assert ts.time == TS_TIME and ts.qualified is True and ts.authority == "TSA di prova"
    assert messages.verdict_title(report) == "MARCA TEMPORALE VALIDA"


def test_tsd_imprint_mismatch_is_invalid(pki, make_token):
    from firmaremota import tst

    data = tst.build_tsd(b"ciao!", [make_token(b"ciao")])  # the token speaks about other bytes
    report = verify.verify_bytes("nota.txt.tsd", data, RootsTrust(pki["ca"]))
    assert report.verdict == "non valida" and not report.timestamps[0].intact
    assert "NON VALIDA" in messages.timestamp_line(report.timestamps[0])


def test_tsd_wrapping_p7m(pki, make_p7m, make_tsd):
    report = verify.verify_bytes("x.pdf.p7m.tsd", make_tsd(make_p7m(PDF)), RootsTrust(pki["ca"]))
    assert report.kind is Kind.TSD and report.ok and len(report.checks) == 1 and len(report.timestamps) == 1
    assert report.content == PDF and report.content_name == "x.pdf"


def test_tsd_gives_poe_to_expired_inner_signature(pki, make_p7m, make_tsd):
    report = verify.verify_bytes("x.p7m.tsd", make_tsd(make_p7m(PDF, who="scaduto")), RootsTrust(pki["ca"]))
    assert report.ok and report.checks[0].valid_at == TS_TIME


def test_tsr_with_sibling_original(pki, tmp_path, make_tsr):
    (tmp_path / "nota.txt").write_bytes(b"ciao")
    (tmp_path / "nota.txt.tsr").write_bytes(make_tsr(b"ciao"))
    report = verify.verify_file(tmp_path / "nota.txt.tsr", RootsTrust(pki["ca"]))
    assert report.kind is Kind.TSR and report.verdict == "valida" and report.content is None
    assert report.timestamps[0].time == TS_TIME


def test_tsr_without_original_asks(pki, tmp_path, make_tsr):
    path = tmp_path / "nota.txt.tsr"
    path.write_bytes(make_tsr(b"ciao"))
    with pytest.raises(OriginalRequired, match="--originale"):
        verify.verify_file(path, RootsTrust(pki["ca"]))
    with pytest.raises(OriginalRequired):  # the error class survives the process boundary
        verify.run_isolated(verify.verify_bytes, "nota.txt.tsr", make_tsr(b"ciao"), verify.NoTrust())


def test_tsr_wrong_original_is_invalid(pki, tmp_path, make_tsr):
    (tmp_path / "nota.txt").write_bytes(b"altro")
    (tmp_path / "nota.txt.tsr").write_bytes(make_tsr(b"ciao"))
    report = verify.verify_file(tmp_path / "nota.txt.tsr", RootsTrust(pki["ca"]))
    assert report.verdict == "non valida" and not report.timestamps[0].intact


def test_tsr_over_a_p7m_verifies_the_signature_too(pki, tmp_path, make_p7m, make_tsr):
    envelope = make_p7m(PDF, who="scaduto")
    (tmp_path / "x.pdf.p7m").write_bytes(envelope)
    (tmp_path / "x.pdf.p7m.tsr").write_bytes(make_tsr(envelope))
    report = verify.verify_file(tmp_path / "x.pdf.p7m.tsr", RootsTrust(pki["ca"]))
    assert report.kind is Kind.TSR and report.ok and report.checks[0].valid_at == TS_TIME


def test_tsd_signatures_intact(make_tsd, make_tsr, make_token):
    from firmaremota import tst

    assert verify.signatures_intact(Kind.TSD, make_tsd(b"dati"))
    assert not verify.signatures_intact(Kind.TSD, tst.build_tsd(b"datx", [make_token(b"dati")]))
    assert verify.signatures_intact(Kind.TSR, make_tsr(b"dati"), original=b"dati")
    assert not verify.signatures_intact(Kind.TSR, make_tsr(b"dati"), original=b"datx")
    assert not verify.signatures_intact(Kind.TSR, make_tsr(b"dati"))


def test_unknown_file_message_mentions_timestamps():
    with pytest.raises(FileError, match="marca temporale"):
        verify.verify_bytes("a.txt", b"ciao", RootsTrust())


class _FakeResponse:
    def __init__(self, status, headers=None, body=b""):
        self.status_code, self.headers, self._body = status, headers or {}, body
        self.is_redirect = status in (301, 302, 303, 307, 308) and "location" in self.headers
        self.closed = False

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            yield self._body[i:i + size]

    @property
    def content(self):  # requests reads `_content` once `_fetch` has filled it
        return self._content

    def close(self):
        self.closed = True


def _public(monkeypatch):
    monkeypatch.setattr(verify, "url_allowed", lambda url: "lan." not in url and "127." not in url)


def test_fetch_follows_redirects_only_to_public_hosts(monkeypatch):
    import requests

    _public(monkeypatch)
    seen = []

    def fake_request(method, url, **kwargs):
        seen.append((method, url, kwargs["allow_redirects"]))
        if url.endswith("/start"):
            return _FakeResponse(302, {"location": "/ocsp"})
        if url.endswith("/ocsp"):
            return _FakeResponse(200, body=b"ok" * 10)
        if url.endswith("/evil"):
            return _FakeResponse(302, {"location": "http://lan.example/admin"})
        raise AssertionError(url)

    monkeypatch.setattr(verify.requests, "request", fake_request)
    response = verify._fetch("POST", "http://ocsp.example/start", data=b"q", headers={}, timeout=5)
    assert response.content == b"ok" * 10 and seen[0][2] is False and seen[1][1] == "http://ocsp.example/ocsp"
    with pytest.raises(requests.RequestException, match="non consentita"):
        verify._fetch("GET", "http://ocsp.example/evil", headers={}, timeout=5)
    assert not any("lan." in url for _, url, _ in seen)  # the private hop was never requested


def test_fetch_caps_size_and_hops(monkeypatch):
    import requests

    _public(monkeypatch)
    monkeypatch.setattr(verify, "MAX_FETCH_BYTES", 100)
    monkeypatch.setattr(verify.requests, "request", lambda m, url, **kw: _FakeResponse(200, body=b"x" * 101))
    with pytest.raises(requests.RequestException, match="troppo grande"):
        verify._fetch("GET", "http://ocsp.example/big", headers={}, timeout=5)
    monkeypatch.setattr(verify.requests, "request", lambda m, url, **kw: _FakeResponse(301, {"location": url + "/x"}))
    with pytest.raises(requests.RequestException, match="reindirizzamenti"):
        verify._fetch("GET", "http://ocsp.example/loop", headers={}, timeout=5)


def test_restricted_unpickler_refuses_code_objects():
    import os
    import pickle

    with pytest.raises(pickle.UnpicklingError, match="non ammesso"):
        verify._loads(pickle.dumps(os.system))
    with pytest.raises(pickle.UnpicklingError):
        verify._loads(pickle.dumps(verify.FirmaError))  # not even our exception classes travel as objects
    report = verify.VerifyReport(Kind.TSD, [], None, True)
    assert verify._loads(pickle.dumps(report)) == report  # our data types and datetimes do
    assert verify._loads(pickle.dumps(("firma", "OriginalRequired", "x", None))) == ("firma", "OriginalRequired", "x", None)


def test_run_isolated_only_raises_firma_errors():
    assert verify.run_isolated(_echo, [1, 2]) == [1, 2]  # lists of builtins still pass


def test_p7m_with_ocsp_in_its_revocation_data_verifies(pki, make_cades_t):
    """As Aruba's envelopes with its own timestamp: signature, timestamp and content all still checked."""
    data = with_ocsp_in_crls(make_cades_t(PDF))
    report = verify.verify_bytes("contratto.pdf.p7m", data, RootsTrust(pki["ca"]))
    (check,) = report.checks
    assert report.ok and report.content == PDF and check.timestamp is not None and check.timestamp.trusted
    assert verify.signatures_intact(Kind.CADES, data) and verify.has_timestamp(Kind.CADES, data)


def test_timestamp_token_with_revocation_data_is_readable(pki, make_token):
    from asn1crypto import cms

    from firmaremota import tst

    token = cms.ContentInfo.load(with_ocsp_in_crls(make_token(b"ciao").dump()))
    report = verify.verify_bytes("nota.txt.tsd", tst.build_tsd(b"ciao", [token]), RootsTrust(pki["ca"]))
    assert report.kind is Kind.TSD and report.ok and report.content == b"ciao"
