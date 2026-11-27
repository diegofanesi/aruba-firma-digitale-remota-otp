import threading

import pytest

from firmaremota import config, service, verify
from firmaremota.errors import CredentialsError, OtpError, ServiceError, TimestampError
from firmaremota.models import Account, Kind, Position, ResolvedStamp, SignJob, StampSpec, TimestampType, TsaCredentials

from .conftest import with_ocsp_in_crls
from .fakes import SESSION_ID, FakeArss, signer_info

ACCOUNT = Account("mario.rossi", "firma", "NEW_2025:abc-AS0")
OTP = "12345678"


@pytest.fixture
def docs(tmp_path, make_pdf):
    a4 = (595, 842, 0, None)
    (tmp_path / "a.pdf").write_bytes(make_pdf(a4))
    (tmp_path / "b.pdf").write_bytes(make_pdf(a4, a4))
    (tmp_path / "c.xml").write_bytes(b"<fattura/>")
    return tmp_path


def jobs(folder, stamp=None):
    return [SignJob(folder / "a.pdf", Kind.PADES, stamp), SignJob(folder / "b.pdf", Kind.PADES, stamp),
            SignJob(folder / "c.xml", Kind.CADES)]


def test_preflight_ok(docs):
    assert service.preflight(jobs(docs, StampSpec())) == []


def test_preflight_finds_every_problem(docs, make_pdf):
    (docs / "vuoto.pdf").write_bytes(b"")
    (docs / "protetto.pdf").write_bytes(make_pdf((595, 842, 0, None), password="x"))
    locked = docs / "bloccata"
    locked.mkdir(mode=0o500)
    try:
        problems = service.preflight([
            SignJob(docs / "manca.pdf", Kind.PADES),
            SignJob(docs / "vuoto.pdf", Kind.PADES),
            SignJob(docs / "protetto.pdf", Kind.PADES),
            SignJob(docs / "a.pdf", Kind.PADES, StampSpec(page=3)),
            SignJob(docs / "c.xml", Kind.CADES),
        ], out_dir=locked)
    finally:
        locked.chmod(0o700)
    text = "\n".join(problems)
    for expected in ("manca.pdf", "vuoto", "password", "La pagina 3 non esiste", "permesso di scrivere"):
        assert expected in text
    assert service.preflight([]) == ["Nessun file da firmare."]


def test_sign_batch_one_otp_for_everything(docs, make_p7m, sign_pdf):
    api = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf)
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs))
    assert [r.ok for r in results] == [True, True, True]
    assert [r.output.name for r in results] == ["a_firmato.pdf", "b_firmato.pdf", "c.xml.p7m"]
    assert api.names() == ["open_session", "sign_pdf", "sign_pdf", "sign_cades", "close_session"]
    assert api.calls[0] == ("open_session", OTP)
    for call in api.calls[1:4]:
        assert call[1] is None and call[2] == SESSION_ID  # signed with the session, never the OTP again
    assert config.load_state().auth_failures == 0


def test_stamp_is_resolved_and_labelled(docs, make_p7m, sign_pdf):
    api = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf)
    spec = StampSpec(position=Position.BOTTOM_LEFT, text="Per accettazione")
    service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs, spec)[:2], signer_name="Mario Rossi")
    first, second = api.calls[1], api.calls[2]
    assert first[3] == ResolvedStamp(1, 36, 36, 236, 106)
    assert second[3].page == 2  # default: last page
    assert first[4] == "Firmato digitalmente da Mario Rossi\nPer accettazione"


def test_refused_otp_counts_and_signs_nothing(docs, sign_pdf):
    api = FakeArss(open_error=OtpError("no"))
    for expected in (1, 2):
        with pytest.raises(OtpError):
            service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs))
        assert service.auth_failures() == expected
    assert set(api.names()) == {"open_session"}
    service.sign_batch(FakeArss(sign_pdf=sign_pdf), ACCOUNT, "pw", OTP, jobs(docs)[:1])  # one accepted OTP
    assert service.auth_failures() == 0


def test_service_error_stops_the_batch_and_closes_the_session(docs, make_p7m, sign_pdf):
    api = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf, fail_at={1: ServiceError("guasto")})
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs))
    assert [r.ok for r in results] == [True, False, False]
    assert results[1].error.message == "guasto"
    assert results[2].error.message == service.NOT_REACHED
    assert api.names()[-1] == "close_session"
    assert not (docs / "b_firmato.pdf").exists()


def test_local_file_problem_skips_only_that_file(docs, make_p7m, sign_pdf):
    work = jobs(docs)
    (docs / "a.pdf").unlink()  # disappeared after preflight
    results = service.sign_batch(FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf), ACCOUNT, "pw", OTP, work)
    assert [r.ok for r in results] == [False, True, True]


def test_cancel(docs, make_p7m, sign_pdf):
    cancel = threading.Event()
    cancel.set()
    api = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf)
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs), cancel=cancel)
    assert all(r.error.message == service.CANCELLED for r in results)
    assert api.names() == ["open_session", "close_session"]


def test_progress_and_output_folder(docs, make_p7m, tmp_path, sign_pdf):
    out = tmp_path / "firmati"
    out.mkdir()
    seen = []
    service.sign_batch(FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf), ACCOUNT, "pw", OTP, jobs(docs), out_dir=out,
                       progress=lambda done, total, name: seen.append((done, total, name)))
    assert seen == [(0, 3, "a.pdf"), (1, 3, "b.pdf"), (2, 3, "c.xml"), (3, 3, "")]
    assert sorted(p.name for p in out.iterdir()) == ["a_firmato.pdf", "b_firmato.pdf", "c.xml.p7m"]


def test_huge_file_is_a_preflight_problem(docs, monkeypatch):
    monkeypatch.setattr(service.files, "MAX_SIGN_SIZE", 5)
    problems = service.preflight(jobs(docs))
    assert len(problems) == 3 and all("troppo grande" in p for p in problems)


def test_file_changed_after_approval_is_not_signed(docs, make_p7m, sign_pdf, make_pdf):
    """The user approves a list of files and types the OTP; what is sent must be exactly what was approved."""
    work = service.fingerprint(jobs(docs))
    assert all(len(job.digest) == 64 for job in work)
    (docs / "a.pdf").write_bytes(make_pdf((300, 300, 0, None)))  # swapped between approval and sending
    api = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf)
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, work)
    assert [r.ok for r in results] == [False, True, True]
    assert "è cambiato dopo il controllo iniziale" in results[0].error.message
    assert api.names().count("sign_pdf") == 1 and not (docs / "a_firmato.pdf").exists()


def test_returned_document_must_be_ours(docs, make_p7m, sign_pdf, make_pdf):
    """A signed file that doesn't contain exactly the bytes we sent is never saved."""
    other = sign_pdf(make_pdf((300, 300, 0, None)))
    api = FakeArss(make_p7m=lambda d: make_p7m(d + b"!"), sign_pdf=lambda pdf: other)
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs))
    assert [r.ok for r in results] == [False, False, False]
    assert all("non corrisponde a quello inviato" in r.error.message for r in results[:1])
    assert "non corrisponde a quello inviato" in results[2].error.message or results[2].error.message == service.NOT_REACHED
    assert not any(p.name.endswith(("_firmato.pdf", ".p7m")) for p in docs.iterdir())


def test_returned_signature_must_verify(docs, make_p7m, sign_pdf):
    """Right bytes, broken signature (e.g. a damaged transfer): refused, so the user never keeps a bad file."""
    def broken_pdf(pdf):
        signed = sign_pdf(pdf)
        tail = signed[len(pdf):]
        return pdf + tail.replace(b"/ByteRange", b"/ByteRangX", 1)

    def broken_p7m(data):
        p7m = make_p7m(data)
        return p7m[:-20] + bytes(b ^ 0xFF for b in p7m[-20:])  # flip the end of the signature value

    results = service.sign_batch(FakeArss(make_p7m=broken_p7m, sign_pdf=broken_pdf), ACCOUNT, "pw", OTP, jobs(docs))
    assert not results[0].ok and "controllo di integrità" in results[0].error.message
    assert not any(p.name.endswith(("_firmato.pdf", ".p7m")) for p in docs.iterdir())


def test_returned_matches_rules(make_p7m):
    assert service.returned_matches(Kind.PADES, b"%PDF-1.7 x", b"%PDF-1.7 x\n<<firma>>")
    assert not service.returned_matches(Kind.PADES, b"%PDF-1.7 x", b"%PDF-1.7 x")  # nothing appended
    assert not service.returned_matches(Kind.PADES, b"%PDF-1.7 x", b"%PDF-1.7 y\n<<firma>>")
    assert service.returned_matches(Kind.CADES, b"dati", make_p7m(b"dati"))
    assert not service.returned_matches(Kind.CADES, b"dati", make_p7m(b"dati!"))
    assert not service.returned_matches(Kind.CADES, b"dati", b"non una busta")


def test_password_only_check_and_the_failure_counter():
    config.save_state(config.State(auth_failures=1))
    service.check_credentials(FakeArss(), ACCOUNT, "pw")
    assert service.auth_failures() == 1  # a password-only success doesn't clear an OTP failure
    with pytest.raises(CredentialsError):
        service.check_credentials(FakeArss(certs=CredentialsError("no")), ACCOUNT, "pw")
    assert service.auth_failures() == 2


def test_prepare_account_fetches_the_certificate_each_time():
    api = FakeArss(certs=[("NEW_2025:abc-AS0", signer_info("Mario Rossi"))])
    account, signer = service.prepare_account(api, "mario.rossi", "firma", "pw")
    assert (account.user, account.domain, account.cert_id, account.type_hsm) == \
        ("mario.rossi", "firma", "NEW_2025:abc-AS0", "COSIGN")
    assert signer.name == "Mario Rossi" and api.calls == [("list_certs", "pw")]


def test_pick_certificate_after_renewal():
    old, new = ("vecchio", signer_info("Mario Rossi", days_left=20)), ("nuovo", signer_info("Mario Rossi", days_left=700))
    expired = ("scaduto", signer_info("Mario Rossi", days_left=-1))
    assert service.pick_certificate([old, expired, new])[0] == "nuovo"
    with pytest.raises(CredentialsError, match="scaduto"):
        service.pick_certificate([expired])
    with pytest.raises(CredentialsError, match="non ha trovato"):
        service.pick_certificate([])


# --- timestamps -----------------------------------------------------------------------------------

TSA = TsaCredentials("mario.rossi", "pw")


@pytest.fixture
def api_t(make_p7m, sign_pdf, make_cades_t, make_tsd, make_tsr):
    return FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf, make_cades_t=make_cades_t, make_tsd=make_tsd, make_tsr=make_tsr)


@pytest.mark.parametrize("level", [TimestampType.T, TimestampType.LT])
def test_sign_batch_passes_tsa_and_level_and_outputs_have_timestamps(docs, api_t, level):
    results = service.sign_batch(api_t, ACCOUNT, "pw", OTP, jobs(docs), tsa=TSA, level=level)
    assert [r.ok for r in results] == [True, True, True] and all(r.timestamped for r in results)
    assert api_t.tsa_seen == [(TSA, level)] * 3
    for result in results:
        assert verify.has_timestamp(result.job.kind, result.output.read_bytes())
    assert [r.output.name for r in results] == ["a_firmato.pdf", "b_firmato.pdf", "c.xml.p7m"]


def test_no_timestamp_requested_means_none_asked(docs, api_t):
    results = service.sign_batch(api_t, ACCOUNT, "pw", OTP, jobs(docs))
    assert api_t.tsa_seen == [(None, None)] * 3
    assert not any(verify.has_timestamp(r.job.kind, r.output.read_bytes()) for r in results)
    assert not any(r.timestamped for r in results)


def test_a_mark_applied_by_aruba_on_its_own_is_noticed(docs, make_p7m, sign_pdf, make_cades_t):
    """Accounts with "Marca automaticamente" get a timestamp without asking: the result says so."""
    api = FakeArss(make_p7m=make_cades_t, sign_pdf=lambda pdf, timestamp=False: sign_pdf(pdf, timestamp=True))
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs))
    assert all(r.ok and r.timestamped for r in results) and api.tsa_seen == [(None, None)] * 3


def test_timestamp_without_tsa_account_relies_on_aruba(docs, api_t):
    """Firma Remota: `requiredmark` alone, no TSA credentials; Aruba applies its own (included) mark."""
    results = service.sign_batch(api_t, ACCOUNT, "pw", OTP, jobs(docs), level=TimestampType.T)
    assert all(r.ok for r in results) and api_t.tsa_seen == [(None, TimestampType.T)] * 3


def test_tsd_level_needs_a_tsa_account(docs, api_t):
    with pytest.raises(TimestampError, match="account di marca temporale"):
        service.sign_batch(api_t, ACCOUNT, "pw", OTP, [SignJob(docs / "c.xml", Kind.CADES)], level=TimestampType.TSD)
    assert api_t.calls == []  # refused before any OTP is spent
    assert service.needs_tsa_account(TimestampType.T, None) is None


def test_missing_timestamp_is_refused_and_stops_batch(docs, make_p7m, sign_pdf):
    """Aruba answers with a plain signature although a timestamp was asked for: nothing is saved."""
    api = FakeArss(make_p7m=make_p7m, sign_pdf=lambda pdf, timestamp=False: sign_pdf(pdf))  # ignores the request
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs), tsa=TSA, level=TimestampType.T)
    assert [r.ok for r in results] == [False, False, False]
    assert isinstance(results[0].error, TimestampError) and "senza la marca temporale" in results[0].error.message
    assert "selfcare" in results[0].error.message and results[1].error.message == service.NOT_REACHED
    assert not any(p.name.endswith(("_firmato.pdf", ".p7m")) for p in docs.iterdir())
    assert api.names()[-1] == "close_session"


def test_tsa_refusal_is_a_timestamp_error_and_not_an_auth_failure(docs, make_p7m, sign_pdf):
    api = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf, timestamp_error=TimestampError("TSA no"))
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs), tsa=TSA, level=TimestampType.T)
    assert isinstance(results[0].error, TimestampError) and service.auth_failures() == 0


def test_cades_tsd_wraps_the_signed_p7m(docs, api_t):
    results = service.sign_batch(api_t, ACCOUNT, "pw", OTP, [SignJob(docs / "c.xml", Kind.CADES)],
                                 tsa=TSA, level=TimestampType.TSD)
    (result,) = results
    assert result.ok and result.output.name == "c.xml.p7m.tsd"
    assert api_t.tsa_seen == [(None, None)]  # the signature itself is a plain one...
    assert api_t.names() == ["open_session", "sign_cades", "timestamp_file", "close_session"]  # ...then wrapped
    report = verify.verify_file(result.output, verify.NoTrust())
    assert report.kind is Kind.TSD and report.content == b"<fattura/>" and len(report.timestamps) == 1


def test_tsd_level_refused_for_pdf_in_preflight(docs):
    problems = service.preflight(jobs(docs), level=TimestampType.TSD)
    assert len(problems) == 1 and "TSD" in problems[0] and ".p7m" in problems[0]
    assert service.preflight([SignJob(docs / "c.xml", Kind.CADES)], level=TimestampType.TSD) == []


def test_wrapping_refuses_a_tsd_about_other_bytes(docs, make_p7m, make_tsd):
    api = FakeArss(make_p7m=make_p7m, make_tsd=lambda data: make_tsd(data + b"!"))
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, [SignJob(docs / "c.xml", Kind.CADES)],
                                 tsa=TSA, level=TimestampType.TSD)
    assert not results[0].ok and "non corrisponde" in results[0].error.message
    assert not any(p.suffix == ".tsd" for p in docs.iterdir())


def test_timestamp_batch_outputs_tsd_and_tsr(docs, api_t):
    work = service.fingerprint([SignJob(docs / "c.xml", Kind.TSD), SignJob(docs / "a.pdf", Kind.TSR)])
    assert service.preflight(work) == []
    results = service.timestamp_batch(api_t, TSA, work)
    assert [r.output.name for r in results] == ["c.xml.tsd", "a.pdf.tsr"]
    assert api_t.names() == ["timestamp_file", "timestamp_file"]  # no session, no OTP
    assert verify.verify_file(docs / "c.xml.tsd", verify.NoTrust()).content == b"<fattura/>"
    tsr = verify.verify_file(docs / "a.pdf.tsr", verify.NoTrust())  # finds a.pdf next to it
    assert tsr.kind is Kind.TSR and tsr.timestamps[0].intact


def test_timestamp_batch_refuses_mismatched_content_and_broken_tokens(docs, make_tsd, make_tsr, make_token):
    from firmaremota import tst

    api = FakeArss(make_tsd=lambda data: make_tsd(data + b"!"), make_tsr=lambda data: tst.build_tsr(make_token(data + b"!")))
    results = service.timestamp_batch(api, TSA, [SignJob(docs / "c.xml", Kind.TSD), SignJob(docs / "a.pdf", Kind.TSR)])
    assert not results[0].ok and "non corrisponde" in results[0].error.message
    assert results[1].error.message == service.NOT_REACHED  # a service problem stops the batch
    only_tsr = service.timestamp_batch(api, TSA, [SignJob(docs / "a.pdf", Kind.TSR)])
    assert not only_tsr[0].ok and "integrità" in only_tsr[0].error.message
    assert not any(p.suffix in (".tsd", ".tsr") for p in docs.iterdir())


def test_timestamp_batch_cancel_progress_and_changed_file(docs, api_t, make_pdf):
    seen = []
    cancel = threading.Event()
    cancel.set()
    results = service.timestamp_batch(api_t, TSA, [SignJob(docs / "c.xml", Kind.TSD)], cancel=cancel,
                                      progress=lambda d, t, n: seen.append((d, t, n)))
    assert results[0].error.message == service.CANCELLED and api_t.calls == [] and seen == [(1, 1, "")]
    work = service.fingerprint([SignJob(docs / "a.pdf", Kind.TSD)])
    (docs / "a.pdf").write_bytes(make_pdf((300, 300, 0, None)))
    results = service.timestamp_batch(api_t, TSA, work)
    assert not results[0].ok and "è cambiato" in results[0].error.message and api_t.calls == []


# --- the free (Belgian) timestamp ------------------------------------------------------------------------

@pytest.fixture
def free_tsa(monkeypatch, timestamper, pki):
    """The real FreeTimestamps against a fake TSA (see test_timestamping); `failures` = attempts that fail."""
    from firmaremota import timestamping

    from .test_timestamping import FakeTsa, QualifiedRoots

    def make(failures=0):
        fake = FakeTsa(timestamper, failures=failures)
        monkeypatch.setattr(timestamping, "_post", fake)
        stamps = timestamping.FreeTimestamps(trust_factory=lambda: QualifiedRoots(pki["ca"]), sleep=lambda s: True)
        return stamps, fake

    return make


def test_free_timestamp_on_every_file_and_nothing_asked_of_aruba(docs, make_p7m, sign_pdf, free_tsa):
    api = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf)
    stamps, fake = free_tsa()
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs), free=stamps)
    assert [(r.ok, r.timestamped, r.warning) for r in results] == [(True, True, None)] * 3
    assert api.tsa_seen == [(None, None)] * 3  # Aruba is asked for a plain signature
    assert len(fake.requests) == 3
    for result in results:
        kind = result.job.kind
        assert verify.has_timestamp(kind, result.output.read_bytes())
        assert verify.signatures_intact(kind, result.output.read_bytes())


def test_free_timestamp_down_signatures_saved_without_it_and_one_wait_only(docs, make_p7m, sign_pdf, free_tsa):
    api = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf)
    stamps, fake = free_tsa(failures=99)
    seen = []
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs), free=stamps,
                                 progress=lambda done, total, name: seen.append(name))
    assert [r.ok for r in results] == [True, True, True] and not any(r.timestamped for r in results)
    assert all(r.warning and "3 tentativi" in r.warning for r in results)
    assert len(fake.requests) == 3  # three attempts on the first file, none on the others
    assert "a.pdf (marca temporale, tentativo 2 di 3)" in seen and "a.pdf (marca temporale, tentativo 3 di 3)" in seen
    assert api.names()[-1] == "close_session"
    for result in results:  # the plain signatures, as Aruba returned them
        assert not verify.has_timestamp(result.job.kind, result.output.read_bytes())
        assert verify.signatures_intact(result.job.kind, result.output.read_bytes())
    assert service.auth_failures() == 0  # a timestamp problem is never a login problem


def test_free_timestamp_skipped_when_aruba_already_added_one(docs, make_cades_t, sign_pdf, free_tsa):
    api = FakeArss(make_p7m=make_cades_t, sign_pdf=lambda pdf: sign_pdf(pdf, timestamp=True))
    stamps, fake = free_tsa()
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs), free=stamps)
    assert all(r.timestamped and r.warning is None for r in results) and fake.requests == []


def test_free_timestamp_never_saves_a_broken_stamp(docs, make_p7m, sign_pdf, free_tsa, monkeypatch):
    from firmaremota import timestamping

    api = FakeArss(make_p7m=make_p7m, sign_pdf=sign_pdf)
    stamps, _ = free_tsa()
    monkeypatch.setattr(timestamping, "stamp_cades", lambda signed, client: signed[:-40] + b"\x00" * 40)
    (result,) = service.sign_batch(api, ACCOUNT, "pw", OTP, [SignJob(docs / "c.xml", Kind.CADES)], free=stamps)
    assert result.ok and not result.timestamped and result.warning
    assert verify.signatures_intact(Kind.CADES, result.output.read_bytes())  # what Aruba returned, untouched


def test_free_timestamp_excludes_the_aruba_options(docs, make_p7m, free_tsa):
    stamps, _ = free_tsa()
    with pytest.raises(ValueError):
        service.sign_batch(FakeArss(make_p7m=make_p7m), ACCOUNT, "pw", OTP, jobs(docs), free=stamps,
                           level=TimestampType.T)


def test_signed_p7m_with_revocation_data_is_saved(docs, make_p7m):
    """2026-11-27: Aruba's .p7m with OCSP responses in its revocation data was refused as "non valida"."""
    from firmaremota import p7m

    api = FakeArss(make_p7m=lambda content: with_ocsp_in_crls(make_p7m(content)))
    (result,) = service.sign_batch(api, ACCOUNT, "pw", OTP, [SignJob(docs / "c.xml", Kind.CADES)])
    assert result.ok and p7m.unwrap(result.output.read_bytes()).content == b"<fattura/>"


def test_unreadable_p7m_from_aruba_keeps_the_reason_for_the_log(docs, caplog):
    api = FakeArss(make_p7m=lambda content: b"\x30\x03\x02\x01\x00")
    (result,) = service.sign_batch(api, ACCOUNT, "pw", OTP, [SignJob(docs / "c.xml", Kind.CADES)])
    assert not result.ok and "busta .p7m non valida" in result.error.message and result.error.detail
    assert result.error.detail in caplog.text
