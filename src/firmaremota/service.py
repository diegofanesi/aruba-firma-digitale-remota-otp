"""What the CLI and the GUI call: checks before asking for an OTP, and batch signing with one OTP."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path

from . import config, files, p7m, stamp
from .arss.client import ArssApi
from .errors import CredentialsError, FileError, FirmaError, OtpError, ServiceError
from .logsetup import register_paths, register_secret
from .models import Account, AuthCtx, JobResult, Kind, SignerInfo, SignJob

log = logging.getLogger("firmaremota.service")

Progress = Callable[[int, int, str], None]  # (done, total, current file name)

NOT_REACHED = "Non firmato: la firma si è interrotta per l'errore precedente."
CANCELLED = "Non firmato: annullato."


def account_from(profile, settings: config.Settings) -> Account:
    """ARSS account from the decrypted profile (vault.Profile) and the preferences."""
    if not profile.complete:
        raise CredentialsError("Configurazione incompleta: esegui prima 'firma configura'.")
    return Account(profile.user, profile.domain, profile.cert_id, settings.type_hsm)


def stamp_text(signer_name: str | None, extra: str = "") -> str:
    first = f"Firmato digitalmente da {signer_name}" if signer_name else "Firmato digitalmente"
    return f"{first}\n{extra}" if extra else first


def output_dir(job: SignJob, out_dir: Path | None) -> Path:
    return Path(out_dir) if out_dir else job.src.resolve().parent


def preflight(jobs: list[SignJob], out_dir: Path | None = None) -> list[str]:
    """Everything that can be checked locally, so an OTP is never spent on a batch bound to fail."""
    if not jobs:
        return ["Nessun file da firmare."]
    register_paths(*(job.src for job in jobs), *(output_dir(job, out_dir) for job in jobs))
    problems: list[str] = []
    for job in jobs:
        name = job.src.name
        if not job.src.exists():
            problems.append(f"{name}: il file non esiste.")
            continue
        if not job.src.is_file():
            problems.append(f"{name}: è una cartella, non un file.")
            continue
        try:
            data = job.src.read_bytes()
        except OSError as exc:
            problems.append(f"{name}: impossibile leggerlo ({exc.strerror}).")
            continue
        if not data:
            problems.append(f"{name}: il file è vuoto.")
            continue
        if job.kind is Kind.PADES:
            try:
                stamp.resolve(data, job.stamp) if job.stamp else stamp.open_pdf(data)
            except FileError as exc:
                problems.append(f"{name}: {exc.message}")
        problem = files.check_writable(output_dir(job, out_dir))
        if problem and problem not in problems:
            problems.append(problem)
    return problems


def auth_failures() -> int:
    return config.load_state().auth_failures


def _record_auth(success: bool) -> None:
    state = config.load_state()
    state.auth_failures = 0 if success else state.auth_failures + 1
    config.save_state(state)


def check_credentials(api: ArssApi, account: Account, password: str) -> list[tuple[str, SignerInfo]]:
    """Ask Aruba to accept the password (no OTP); returns (certID, holder) for each certificate.

    A refusal counts as a failed login; a success doesn't reset the counter (the OTP is untested).
    """
    try:
        return api.list_certs(account, password)
    except CredentialsError:
        _record_auth(False)
        raise


def fetch_signer_name(api: ArssApi, account: Account, password: str) -> str | None:
    """Certificate holder's name, for the visible stamp."""
    certs = check_credentials(api, account, password)
    for cert_id, signer in certs:
        if cert_id == account.cert_id:
            return signer.name
    return certs[0][1].name if certs else None


def _sign_one(api: ArssApi, auth: AuthCtx, job: SignJob, out_dir: Path | None, signer_name: str | None) -> Path:
    try:
        data = job.src.read_bytes()
    except OSError as exc:
        raise FileError(f"Impossibile leggere {job.src.name}: {exc.strerror}") from exc
    if job.kind is Kind.PADES:
        spec = job.stamp
        signed = api.sign_pdf(
            auth, data,
            stamp=stamp.resolve(data, spec) if spec else None,
            text=stamp_text(signer_name, spec.text) if spec else "",
            image=spec.image if spec else None,
            show_date=spec.show_date if spec else True,
        )
        if not signed.lstrip()[:5] == b"%PDF-":
            raise ServiceError("Il servizio di firma ha restituito un PDF non valido.")
        name = files.signed_pdf_name(job.src)
    else:
        signed = api.sign_cades(auth, data)
        if not p7m.is_p7m(signed):
            raise ServiceError("Il servizio di firma ha restituito una busta .p7m non valida.")
        name = files.p7m_name(job.src)
    output = files.write_new(output_dir(job, out_dir), name, signed)
    register_paths(output)
    return output


def sign_batch(
    api: ArssApi,
    account: Account,
    password: str,
    otp: str,
    jobs: list[SignJob],
    *,
    out_dir: Path | None = None,
    signer_name: str | None = None,
    progress: Progress | None = None,
    cancel: threading.Event | None = None,
) -> list[JobResult]:
    """Sign every job with a single OTP. Nothing is ever retried.

    Raises OtpError/CredentialsError/NetworkError if the session can't be opened. After that,
    a local problem with one file skips just that file; any error from the service stops the
    batch and the remaining files are reported as not signed.
    """
    register_secret(password, otp)
    register_paths(*(job.src for job in jobs), *(output_dir(job, out_dir) for job in jobs))
    try:
        session_id = api.open_session(AuthCtx(account, password, otp))
    except (OtpError, CredentialsError):
        _record_auth(False)
        raise
    _record_auth(True)
    auth = AuthCtx(account, password, session_id=session_id)
    results: list[JobResult] = []
    try:
        for index, job in enumerate(jobs):
            if cancel is not None and cancel.is_set():
                results.extend(JobResult(j, error=FirmaError(CANCELLED)) for j in jobs[index:])
                break
            if progress:
                progress(index, len(jobs), job.src.name)
            try:
                results.append(JobResult(job, output=_sign_one(api, auth, job, out_dir, signer_name)))
            except FileError as exc:
                log.warning("%s: %s", job.src.name, exc.message)
                results.append(JobResult(job, error=exc))
            except FirmaError as exc:
                log.warning("%s: %s (%s)", job.src.name, exc.message, exc.detail or "-")
                results.append(JobResult(job, error=exc))
                results.extend(JobResult(j, error=FirmaError(NOT_REACHED)) for j in jobs[index + 1:])
                break
        if progress:
            progress(len(jobs), len(jobs), "")
    finally:
        try:
            api.close_session(auth, session_id)
        except FirmaError as exc:
            log.warning("chiusura della sessione non riuscita: %s", exc.message)
    log.info("firmati %d di %d file", sum(r.ok for r in results), len(jobs))
    return results
