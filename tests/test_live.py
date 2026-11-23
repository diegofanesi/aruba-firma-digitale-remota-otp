"""Live check against the real Aruba service. Spends ONE OTP; run it before a release, not routinely.

    FIRMA_LIVE=1 FIRMA_OTP=<code> [FIRMA_LIVE_DIR=<folder to keep the outputs>] uv run pytest -m live

Uses your real settings (~/.config/firma-remota) and the password saved in the wallet.
"""

import os
from pathlib import Path

import pytest

from firmaremota import config, credentials, p7m, service, vault, verify
from firmaremota.arss.client import ArssClient
from firmaremota.models import Kind, SignJob, StampSpec

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("FIRMA_LIVE") != "1", reason="live test: set FIRMA_LIVE=1 and FIRMA_OTP"),
]
REAL_CONFIG = Path.home() / ".config" / "firma-remota" / "config.ini"
REAL_PROFILE = Path.home() / ".config" / "firma-remota" / "profilo.enc"


def test_one_session_signs_and_verifies_everything(tmp_path, make_pdf):
    password = credentials.stored_password()
    assert password, "no password in the wallet: run 'firma configura' first"
    account = service.account_from(vault.load(password, REAL_PROFILE), config.load(REAL_CONFIG))
    out = Path(os.environ.get("FIRMA_LIVE_DIR") or tmp_path / "firmati")
    out.mkdir(parents=True, exist_ok=True)

    a4 = (595, 842, 0, None)
    normal, rotated, note = tmp_path / "normale.pdf", tmp_path / "ruotata.pdf", tmp_path / "nota.txt"
    normal.write_bytes(make_pdf(a4, a4))
    rotated.write_bytes(make_pdf((595, 842, 90, None)))
    note.write_bytes("Prova firma-remota\n".encode())
    jobs = [
        SignJob(normal, Kind.PADES, StampSpec(text="Prova firma-remota")),
        SignJob(rotated, Kind.PADES, StampSpec()),
        SignJob(note, Kind.CADES),
    ]
    assert service.preflight(jobs, out) == []

    api = ArssClient()
    signer_name = service.fetch_signer_name(api, account, password)
    results = service.sign_batch(api, account, password, os.environ["FIRMA_OTP"], jobs,
                                 out_dir=out, signer_name=signer_name)
    assert [r.error.message if r.error else None for r in results] == [None, None, None]

    trust = verify.default_trust()
    for result in results:
        report = verify.verify_file(result.output, trust)
        assert report.ok, (result.output.name, report.checks)
        assert all(check.qualified for check in report.checks)
    assert p7m.unwrap(results[2].output.read_bytes()).content == note.read_bytes()
