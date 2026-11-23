import threading

import pytest

from firmaremota import config, service
from firmaremota.errors import CredentialsError, OtpError, ServiceError
from firmaremota.models import Account, Kind, Position, ResolvedStamp, SignJob, StampSpec

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


def test_sign_batch_one_otp_for_everything(docs, make_p7m):
    api = FakeArss(make_p7m=make_p7m)
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs))
    assert [r.ok for r in results] == [True, True, True]
    assert [r.output.name for r in results] == ["a_firmato.pdf", "b_firmato.pdf", "c.xml.p7m"]
    assert api.names() == ["open_session", "sign_pdf", "sign_pdf", "sign_cades", "close_session"]
    assert api.calls[0] == ("open_session", OTP)
    for call in api.calls[1:4]:
        assert call[1] is None and call[2] == SESSION_ID  # signed with the session, never the OTP again
    assert config.load_state().auth_failures == 0


def test_stamp_is_resolved_and_labelled(docs, make_p7m):
    api = FakeArss(make_p7m=make_p7m)
    spec = StampSpec(position=Position.BOTTOM_LEFT, text="Per accettazione")
    service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs, spec)[:2], signer_name="Mario Rossi")
    first, second = api.calls[1], api.calls[2]
    assert first[3] == ResolvedStamp(1, 36, 36, 236, 106)
    assert second[3].page == 2  # default: last page
    assert first[4] == "Firmato digitalmente da Mario Rossi\nPer accettazione"


def test_refused_otp_counts_and_signs_nothing(docs):
    api = FakeArss(open_error=OtpError("no"))
    for expected in (1, 2):
        with pytest.raises(OtpError):
            service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs))
        assert service.auth_failures() == expected
    assert set(api.names()) == {"open_session"}
    service.sign_batch(FakeArss(make_p7m=lambda d: d), ACCOUNT, "pw", OTP, [])
    assert service.auth_failures() == 0


def test_service_error_stops_the_batch_and_closes_the_session(docs, make_p7m):
    api = FakeArss(make_p7m=make_p7m, fail_at={1: ServiceError("guasto")})
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs))
    assert [r.ok for r in results] == [True, False, False]
    assert results[1].error.message == "guasto"
    assert results[2].error.message == service.NOT_REACHED
    assert api.names()[-1] == "close_session"
    assert not (docs / "b_firmato.pdf").exists()


def test_local_file_problem_skips_only_that_file(docs, make_p7m):
    work = jobs(docs)
    (docs / "a.pdf").unlink()  # disappeared after preflight
    results = service.sign_batch(FakeArss(make_p7m=make_p7m), ACCOUNT, "pw", OTP, work)
    assert [r.ok for r in results] == [False, True, True]


def test_cancel(docs, make_p7m):
    cancel = threading.Event()
    cancel.set()
    api = FakeArss(make_p7m=make_p7m)
    results = service.sign_batch(api, ACCOUNT, "pw", OTP, jobs(docs), cancel=cancel)
    assert all(r.error.message == service.CANCELLED for r in results)
    assert api.names() == ["open_session", "close_session"]


def test_progress_and_output_folder(docs, make_p7m, tmp_path):
    out = tmp_path / "firmati"
    out.mkdir()
    seen = []
    service.sign_batch(FakeArss(make_p7m=make_p7m), ACCOUNT, "pw", OTP, jobs(docs), out_dir=out,
                       progress=lambda done, total, name: seen.append((done, total, name)))
    assert seen == [(0, 3, "a.pdf"), (1, 3, "b.pdf"), (2, 3, "c.xml"), (3, 3, "")]
    assert sorted(p.name for p in out.iterdir()) == ["a_firmato.pdf", "b_firmato.pdf", "c.xml.p7m"]


def test_fetch_signer_name():
    api = FakeArss(certs=[("altro", signer_info("Altro Nome")), ("NEW_2025:abc-AS0", signer_info("Mario Rossi"))])
    assert service.fetch_signer_name(api, ACCOUNT, "pw") == "Mario Rossi"
    config.save_state(config.State(auth_failures=1))
    service.fetch_signer_name(api, ACCOUNT, "pw")
    assert service.auth_failures() == 1  # a password-only success doesn't clear an OTP failure
    with pytest.raises(CredentialsError):
        service.fetch_signer_name(FakeArss(certs=CredentialsError("no")), ACCOUNT, "pw")
    assert service.auth_failures() == 2


def test_account_from_profile():
    from firmaremota import vault

    with pytest.raises(CredentialsError, match="configura"):
        service.account_from(vault.Profile("a", "firma", ""), config.Settings())
    account = service.account_from(vault.Profile("a", "firma", "X"), config.Settings(type_hsm="COSIGN"))
    assert (account.user, account.domain, account.cert_id, account.type_hsm) == ("a", "firma", "X", "COSIGN")
