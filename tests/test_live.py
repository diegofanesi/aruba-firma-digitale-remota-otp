"""Live check against the real Aruba service. Spends ONE OTP; run it before a release, not routinely.

    FIRMA_LIVE=1 FIRMA_OTP=<code> [FIRMA_LIVE_DIR=<folder to keep the outputs>] uv run pytest -m live

Uses your real settings (~/.config/firma-remota) and the password saved in the wallet.
"""

import os
from pathlib import Path

import pytest

from firmaremota import config, credentials, p7m, profiles, service, verify
from firmaremota.arss.client import ArssClient
from firmaremota.models import Kind, SignJob, StampSpec

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("FIRMA_LIVE") != "1", reason="live test: set FIRMA_LIVE=1 and FIRMA_OTP"),
]
REAL_HOME = Path(os.environ.get("FIRMA_REAL_HOME") or Path.home())  # conftest sandboxes HOME
REAL_CONFIG = REAL_HOME / ".config" / "firma-remota" / "config.ini"


@pytest.fixture
def real_wallet(monkeypatch):
    """Undo the test isolation: this test uses the real wallet on purpose."""
    import keyring
    from keyring.core import init_backend

    keyring.set_keyring(init_backend())
    monkeypatch.undo()


def test_one_session_signs_and_verifies_everything(real_wallet, tmp_path, make_pdf):
    store = credentials.get_store()
    available = profiles.load_all(store) if store else []
    profile = next((p for p in available if profiles.password(store, p)), None)
    assert profile, "no account with a saved password in the wallet: run 'aruba-firma configura' first"
    api = ArssClient()
    account, signer = service.prepare_account(api, profile.user, profile.domain, profiles.password(store, profile),
                                              config.load(REAL_CONFIG))
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

    results = service.sign_batch(api, account, password, os.environ["FIRMA_OTP"], jobs,
                                 out_dir=out, signer_name=signer.name)
    assert [r.error.message if r.error else None for r in results] == [None, None, None]

    trust = verify.default_trust()
    for result in results:
        report = verify.verify_file(result.output, trust)
        assert report.ok, (result.output.name, report.checks)
        assert all(check.qualified for check in report.checks)
    assert p7m.unwrap(results[2].output.read_bytes()).content == note.read_bytes()
