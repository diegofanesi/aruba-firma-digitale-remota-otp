"""Live check against the real Aruba service. Spends ONE OTP and up to 9 timestamps; run it before a
release, not routinely.

    FIRMA_LIVE=1 uv run pytest -m live -s            # asks for the OTP in the terminal (not echoed)
    FIRMA_LIVE=1 FIRMA_OTP=<code> uv run pytest -m live   # or from the environment (visible in `ps`)

FIRMA_LIVE_DIR=<folder> keeps the outputs (useful to fill docs/arss-notes.md). Uses your real settings
(~/.config/firma-remota) and the password saved in the wallet; FIRMA_LIVE_NO_TIMESTAMPS=1 skips every
step with Aruba's timestamps (the pre-0.2.0 check); FIRMA_LIVE_NO_FREE=1 skips the free (Belgian) timestamp
on real Aruba output (a PDF and a .p7m, no marks spent).

What it confirms (docs/arss-notes.md, "Marche temporali"): A0 whether a plain signature already carries a
timestamp; A1 the signing credentials as TSA account; A2/A3 T on PDF and .p7m; A4/A5 LT; A6 bytes; A7 the
TSA chain; A8/A9 standalone .tsd/.tsr. Each step prints what it saw, so a failure half-way still teaches.
"""

import getpass
import os
import sys
from pathlib import Path

import pytest

from firmaremota import config, credentials, p7m, profiles, service, timestamping, tst, verify
from firmaremota.arss.client import ArssClient
from firmaremota.models import AuthCtx, Kind, SignJob, StampSpec, TimestampType

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("FIRMA_LIVE") != "1", reason="live test: set FIRMA_LIVE=1 and FIRMA_OTP"),
]
REAL_HOME = Path(os.environ.get("FIRMA_REAL_HOME") or Path.home())  # conftest sandboxes HOME
REAL_CONFIG = REAL_HOME / ".config" / "firma-remota" / "config.ini"
TIMESTAMPS = os.environ.get("FIRMA_LIVE_NO_TIMESTAMPS") != "1"
FREE = os.environ.get("FIRMA_LIVE_NO_FREE") != "1"


@pytest.fixture
def real_wallet(monkeypatch):
    """Undo the test isolation: this test uses the real wallet on purpose."""
    import keyring
    from keyring.core import init_backend

    keyring.set_keyring(init_backend())
    monkeypatch.undo()


def _say(label: str, value) -> None:
    print(f"\n  [live] {label}: {value}")


def _otp() -> str:
    otp = os.environ.get("FIRMA_OTP")
    if not otp:
        if not sys.stdin.isatty():
            pytest.skip("no FIRMA_OTP and no terminal to ask for one (run with -s)")
        otp = getpass.getpass("Codice OTP dall'app Aruba OTP: ").strip()
    return otp


def test_one_session_signs_timestamps_and_verifies_everything(real_wallet, tmp_path, make_pdf):
    store = credentials.get_store()
    available = profiles.load_all(store) if store else []
    profile = next((p for p in available if profiles.password(store, p)), None)
    assert profile, "no account with a saved password in the wallet: run 'aruba-firma configura' first"
    password = profiles.password(store, profile)
    api = ArssClient()
    account, signer = service.prepare_account(api, profile.user, profile.domain, password, config.load(REAL_CONFIG))
    tsa = profiles.tsa_credentials(store, profile)  # None for Firma Remota: Aruba applies its own marks
    _say("TSA account", "saved separately" if tsa else "none: relying on Aruba's automatic mark (requiredmark only)")
    out = Path(os.environ.get("FIRMA_LIVE_DIR") or tmp_path / "firmati")
    out.mkdir(parents=True, exist_ok=True)

    a4 = (595, 842, 0, None)
    normal, rotated, note = tmp_path / "normale.pdf", tmp_path / "ruotata.pdf", tmp_path / "nota.txt"
    normal.write_bytes(make_pdf(a4, a4))
    rotated.write_bytes(make_pdf((595, 842, 90, None)))
    note.write_bytes("Prova firma-remota\n".encode())
    plain_jobs = [SignJob(normal, Kind.PADES, StampSpec(text="Prova firma-remota")),  # (0) no mark asked: A0
                  SignJob(note, Kind.CADES)]
    free_jobs = [SignJob(rotated, Kind.PADES, StampSpec(text="Prova marca gratuita")), SignJob(note, Kind.CADES)]
    t_jobs = [SignJob(rotated, Kind.PADES, StampSpec()), SignJob(note, Kind.CADES)]  # (1)(2) level T: A1 A2 A3 A6 A7
    lt_jobs = [SignJob(normal, Kind.PADES), SignJob(note, Kind.CADES)]  # (3)(4) level LT: A4 A5
    tsd_jobs = [SignJob(note, Kind.CADES)]  # (5) TSD wrap
    for jobs in (plain_jobs, free_jobs, t_jobs, lt_jobs, tsd_jobs):
        assert service.preflight(jobs, out) == []

    otp = _otp()
    trust = verify.default_trust()
    session = api.open_session(AuthCtx(account, password, otp))  # one OTP for every batch below
    try:
        plain = service.sign_batch(api, account, password, None, service.fingerprint(plain_jobs), out_dir=out,
                                   signer_name=signer.name, session_id=session)
        assert all(r.ok for r in plain), [r.error for r in plain]
        a0 = verify.has_timestamp(Kind.PADES, plain[0].output.read_bytes())
        _say("A0 plain signature already timestamped (SelfCare automatic?)", a0)
        raw = p7m.decode(plain[1].output.read_bytes())
        _say("Aruba's .p7m encoding", "BER, indefinite length" if raw[1:2] == b"\x80" else "DER (definite length)")
        if FREE:  # the free Belgian timestamp on real Aruba output: document timestamp on the PDF, CAdES-T
            freed = service.sign_batch(api, account, password, None, service.fingerprint(free_jobs), out_dir=out,
                                       signer_name=signer.name, session_id=session,
                                       free=timestamping.FreeTimestamps(trust_factory=lambda: trust))
            for result in freed:
                _say(f"free {result.job.src.name}", "timestamped" if result.ok and result.timestamped
                     else f"NOT timestamped: {result.warning or result.error}")
            assert all(r.ok and r.timestamped for r in freed), "free timestamp not applied: see the messages above"
            for result in freed:
                report = verify.verify_file(result.output, trust)
                stamp = report.timestamps[-1] if result.job.kind is Kind.PADES else report.checks[0].timestamp
                _say(f"free {result.output.name}", f"verdict={report.verdict} covers={report.checks[0].covers_document} "
                                                   f"ts={stamp}")
                assert report.ok and report.checks[0].covers_document and stamp.trusted and stamp.qualified is True
        if not TIMESTAMPS:
            return
        marked = service.sign_batch(api, account, password, None, service.fingerprint(t_jobs), out_dir=out,
                                    signer_name=signer.name, tsa=tsa, level=TimestampType.T, session_id=session)
        for result in marked:
            _say(f"T {result.job.src.name}", "ok" if result.ok else f"{type(result.error).__name__}: {result.error.message}")
        assert all(r.ok for r in marked), "A1/A2/A3 failed: see the messages above and docs/arss-notes.md"
        for result in marked:
            report = verify.verify_file(result.output, trust)
            (check,) = report.checks
            _say(f"T {result.output.name}", f"verdict={report.verdict} ts={check.timestamp}")
            assert report.ok and check.timestamp is not None and check.timestamp.trusted  # A2 A3 A6 A7
            _say("A7 qualified TSA", check.timestamp.qualified)
        lt = service.sign_batch(api, account, password, None, service.fingerprint(lt_jobs), out_dir=out,
                                signer_name=signer.name, tsa=tsa, level=TimestampType.LT, session_id=session)
        for result in lt:  # A4 / A5: recorded, not required
            if result.ok:
                report = verify.verify_file(result.output, trust)
                _say(f"LT {result.output.name}", f"verdict={report.verdict} doc_timestamps={len(report.timestamps)} "
                                                 f"sig_ts={report.checks[0].timestamp is not None}")
            else:
                _say(f"LT {result.job.src.name} FAILED", f"{type(result.error).__name__}: {result.error.message}")
        if tsa is not None:
            wrapped = service.sign_batch(api, account, password, None, service.fingerprint(tsd_jobs), out_dir=out,
                                         signer_name=signer.name, tsa=tsa, level=TimestampType.TSD, session_id=session)
            _say("TSD wrap", "ok" if wrapped[0].ok else f"{type(wrapped[0].error).__name__}: {wrapped[0].error.message}")
            if wrapped[0].ok:
                report = verify.verify_file(wrapped[0].output, trust)
                _say("TSD wrap verify", f"kind={report.kind} verdict={report.verdict} timestamps={len(report.timestamps)}")
                assert report.kind is Kind.TSD and report.content == note.read_bytes()
    finally:
        api.close_session(AuthCtx(account, password), session)

    if TIMESTAMPS and tsa is None and os.environ.get("FIRMA_LIVE_PROBE_TSA") == "1":
        # A1 the other way round: are the Firma Remota credentials by any chance a TSA account too?
        # Costs nothing if refused, one mark if accepted.
        from firmaremota.models import TsaCredentials

        probe = service.timestamp_batch(api, TsaCredentials(profile.user, password),
                                        service.fingerprint([SignJob(note, Kind.TSD)]), out_dir=out)
        _say("A1 probe: signing credentials as TSA account",
             "ACCEPTED" if probe[0].ok else f"refused: {type(probe[0].error).__name__}: {probe[0].error.message}")
    if TIMESTAMPS and tsa is not None:  # standalone marks: A8 A9 (no OTP)
        standalone = service.timestamp_batch(api, tsa, service.fingerprint(
            [SignJob(note, Kind.TSD), SignJob(note, Kind.TSR)]), out_dir=out)
        for result in standalone:
            _say(f"standalone {result.job.kind}", "ok" if result.ok else f"{type(result.error).__name__}: {result.error.message}")
        assert all(r.ok for r in standalone)
        tsd_report = verify.verify_file(standalone[0].output, trust)
        assert tsd_report.kind is Kind.TSD and tsd_report.ok and tst.parse_tsd(standalone[0].output.read_bytes()).content == note.read_bytes()
        tsr_report = verify.verify_file(standalone[1].output, trust, original=note)
        assert tsr_report.kind is Kind.TSR and tsr_report.ok
    if TIMESTAMPS:
        assert p7m.unwrap(marked[1].output.read_bytes()).content == note.read_bytes()
