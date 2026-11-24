"""What the CLI and the GUI call: checks before asking for an OTP, and batch signing with one OTP."""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import logging
import threading
from collections.abc import Callable
from pathlib import Path

from . import config, files, p7m, stamp, tst, verify
from .arss.client import ArssApi
from .errors import CredentialsError, FileError, FirmaError, OtpError, ServiceError, TimestampError
from .logsetup import register_paths, register_personal, register_secret
from .models import Account, AuthCtx, JobResult, Kind, SignerInfo, SignJob, TimestampType, TsaCredentials

log = logging.getLogger("firmaremota.service")

Progress = Callable[[int, int, str], None]  # (done, total, current file name)

NOT_REACHED = "Non firmato: la firma si è interrotta per l'errore precedente."
CANCELLED = "Non firmato: annullato."
NO_TIMESTAMP = (
    "Aruba ha firmato {name} ma senza la marca temporale richiesta: non salvato. Riprova, firma senza marca, "
    "oppure controlla le credenziali TSA dell'account (o attiva la marca automatica nel SelfCare di Aruba: "
    "https://selfcare.firma-remota.it)."
)
MISMATCH = ("Il documento firmato ricevuto per {name} non corrisponde a quello inviato: non salvato. "
            "Riprova; se succede ancora, contatta l'assistenza.")
BROKEN = ("La firma ricevuta per {name} non supera il controllo di integrità: non salvato. "
          "Riprova; se succede ancora, contatta l'assistenza.")


def pick_certificate(certs: list[tuple[str, SignerInfo]], now: dt.datetime | None = None) -> tuple[str, SignerInfo]:
    """The certificate valid now with the latest expiry (after a renewal both may be listed)."""
    if not certs:
        raise CredentialsError("Aruba non ha trovato certificati di firma per questo account.")
    now = now or dt.datetime.now(dt.timezone.utc)
    valid = [c for c in certs if c[1].not_before <= now <= c[1].not_after]
    if not valid:
        raise CredentialsError("Il certificato di firma è scaduto: va rinnovato con Aruba.")
    return max(valid, key=lambda c: c[1].not_after)


def prepare_account(api: ArssApi, user: str, domain: str, password: str,
                    settings: config.Settings | None = None) -> tuple[Account, SignerInfo]:
    """Ask Aruba for the certificate (password only, no OTP): nothing about it is stored locally.

    This also proves the password is right before an OTP is asked for.
    """
    settings = settings or config.load()
    register_secret(password)
    register_personal(f"{user}@{domain}", user)
    certs = check_credentials(api, Account(user, domain, cert_id="", type_hsm=settings.type_hsm), password)
    cert_id, signer = pick_certificate(certs)
    register_personal(signer.name)
    return Account(user, domain, cert_id, settings.type_hsm), signer


def stamp_text(signer_name: str | None, extra: str = "") -> str:
    first = f"Firmato digitalmente da {signer_name}" if signer_name else "Firmato digitalmente"
    return f"{first}\n{extra}" if extra else first


def output_dir(job: SignJob, out_dir: Path | None) -> Path:
    return Path(out_dir) if out_dir else job.src.resolve().parent


def preflight(jobs: list[SignJob], out_dir: Path | None = None, level: TimestampType | None = None) -> list[str]:
    """Everything that can be checked locally, so an OTP is never spent on a batch bound to fail."""
    if not jobs:
        return ["Nessun file da firmare."]
    register_paths(*(job.src for job in jobs), *(output_dir(job, out_dir) for job in jobs))
    problems: list[str] = []
    if level is TimestampType.TSD and any(job.kind is Kind.PADES for job in jobs):
        problems.append("La marca di tipo TSD vale solo per le buste .p7m: per i PDF scegli T oppure LT.")
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
        too_big = files.check_size(job.src, files.MAX_SIGN_SIZE)
        if too_big:
            problems.append(too_big)
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


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(jobs: list[SignJob]) -> list[SignJob]:
    """The jobs with the sha256 of each file as it is now: `sign_batch` refuses a file that changed
    between this moment (the user looking at the list and typing the OTP) and the moment it is sent."""
    return [dataclasses.replace(job, digest=_digest(job.src.read_bytes())) for job in jobs]


def returned_matches(kind: Kind, original: bytes, signed: bytes) -> bool:
    """Does the signed document Aruba returned contain exactly the bytes we sent?

    CAdES: the envelope's content must be the original. PAdES: ARSS appends an incremental update,
    so the original file must be an untouched prefix of the result (verified live, docs/arss-notes.md).
    """
    if kind is Kind.PADES:
        return signed.startswith(original) and len(signed) > len(original)
    try:
        return p7m.unwrap(signed, max_depth=1).content == original
    except FirmaError:
        return False


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


def _checked_input(job: SignJob) -> bytes:
    try:
        data = job.src.read_bytes()
    except OSError as exc:
        raise FileError(f"Impossibile leggere {job.src.name}: {exc.strerror}") from exc
    if job.digest is not None and _digest(data) != job.digest:
        raise FileError(f"{job.src.name} è cambiato dopo il controllo iniziale: non elaborato, per sicurezza. "
                        "Ricomincia.")
    return data


def _sign_one(api: ArssApi, auth: AuthCtx, job: SignJob, out_dir: Path | None, signer_name: str | None,
              wrap: TsaCredentials | None = None) -> Path:
    """Sign one file; with `wrap`, also put the signed .p7m into a .tsd envelope (ArubaSign's "TSD")."""
    data = _checked_input(job)
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
    # Never save something that isn't our document, signed: the result must contain exactly the
    # bytes we sent, and its signature(s) must verify cryptographically (no trust or network needed).
    if not returned_matches(job.kind, data, signed):
        raise ServiceError(MISMATCH.format(name=job.src.name))
    if not verify.signatures_intact(job.kind, signed):
        raise ServiceError(BROKEN.format(name=job.src.name))
    if auth.level in (TimestampType.T, TimestampType.LT) and not verify.has_timestamp(job.kind, signed):
        raise TimestampError(NO_TIMESTAMP.format(name=job.src.name))
    if wrap is not None:  # TSD: the signed envelope itself gets timestamped
        signed, name = _wrapped(api, wrap, signed, job.src.name), files.tsd_name(Path(name))
    output = files.write_new(output_dir(job, out_dir), name, signed)
    register_paths(output)
    return output


def _wrapped(api: ArssApi, tsa: TsaCredentials, data: bytes, name: str) -> bytes:
    """`data` inside a .tsd envelope from Aruba, checked to really contain `data` under a sound token."""
    envelope = api.timestamp_file(tsa, data, Kind.TSD)
    try:
        content = tst.parse_tsd(envelope).content
    except FileError:
        content = None
    if content != data:
        raise ServiceError(MISMATCH.format(name=name))
    if not verify.signatures_intact(Kind.TSD, envelope):
        raise ServiceError(BROKEN.format(name=name))
    return envelope


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
    tsa: TsaCredentials | None = None,
    level: TimestampType | None = None,
    session_id: str | None = None,
) -> list[JobResult]:
    """Sign every job with a single OTP. Nothing is ever retried.

    With `session_id`, an already open session is used instead of `otp` and left open (several
    batches on one OTP, as the live test does).

    With `tsa` and `level`, every signature also gets a timestamp: T or LT inside the signature,
    TSD (for .p7m only) as a .tsd envelope around the signed file. A requested timestamp that
    doesn't come back is an error: the file is not saved.

    Raises OtpError/CredentialsError/NetworkError if the session can't be opened. After that,
    a local problem with one file skips just that file; any error from the service stops the
    batch and the remaining files are reported as not signed.
    """
    if not jobs:
        return []  # never spend an OTP on nothing
    register_secret(password, otp)
    if tsa is not None:
        register_secret(tsa.password)
    register_paths(*(job.src for job in jobs), *(output_dir(job, out_dir) for job in jobs))
    own_session = session_id is None
    if own_session:
        try:
            session_id = api.open_session(AuthCtx(account, password, otp))
        except (OtpError, CredentialsError):
            _record_auth(False)
            raise
        _record_auth(True)
    wrap = tsa if tsa is not None and level is TimestampType.TSD else None
    auth = AuthCtx(account, password, session_id=session_id, tsa=tsa if tsa is not None and not wrap else None,
                   level=None if wrap or tsa is None else level)
    results: list[JobResult] = []
    try:
        for index, job in enumerate(jobs):
            if cancel is not None and cancel.is_set():
                results.extend(JobResult(j, error=FirmaError(CANCELLED)) for j in jobs[index:])
                break
            if progress:
                progress(index, len(jobs), job.src.name)
            try:
                results.append(JobResult(job, output=_sign_one(api, auth, job, out_dir, signer_name, wrap)))
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
        if own_session:
            try:
                api.close_session(auth, session_id)
            except FirmaError as exc:
                log.warning("chiusura della sessione non riuscita: %s", exc.message)
    log.info("firmati %d di %d file", sum(r.ok for r in results), len(jobs))
    return results


def _timestamp_one(api: ArssApi, tsa: TsaCredentials, job: SignJob, out_dir: Path | None) -> Path:
    data = _checked_input(job)
    output = api.timestamp_file(tsa, data, job.kind)
    if job.kind is Kind.TSD:
        try:
            content = tst.parse_tsd(output).content
        except FileError:
            content = None
        if content != data:
            raise ServiceError(MISMATCH.format(name=job.src.name))
        name = files.tsd_name(job.src)
    else:
        name = files.tsr_name(job.src)
    if not verify.signatures_intact(job.kind, output, original=data):
        raise ServiceError(BROKEN.format(name=job.src.name))
    path = files.write_new(output_dir(job, out_dir), name, output)
    register_paths(path)
    return path


def timestamp_batch(
    api: ArssApi,
    tsa: TsaCredentials,
    jobs: list[SignJob],
    *,
    out_dir: Path | None = None,
    progress: Progress | None = None,
    cancel: threading.Event | None = None,
) -> list[JobResult]:
    """Put a standalone timestamp on each file (jobs of kind TSD or TSR). No OTP, no session.

    Each timestamp is paid for separately, so, as with signing, nothing is retried and a service
    error stops the batch.
    """
    if not jobs:
        return []
    register_secret(tsa.password)
    register_paths(*(job.src for job in jobs), *(output_dir(job, out_dir) for job in jobs))
    results: list[JobResult] = []
    for index, job in enumerate(jobs):
        if cancel is not None and cancel.is_set():
            results.extend(JobResult(j, error=FirmaError(CANCELLED)) for j in jobs[index:])
            break
        if progress:
            progress(index, len(jobs), job.src.name)
        try:
            results.append(JobResult(job, output=_timestamp_one(api, tsa, job, out_dir)))
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
    log.info("marcati %d di %d file", sum(r.ok for r in results), len(jobs))
    return results
