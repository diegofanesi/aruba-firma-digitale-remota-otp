"""Command line: `firma <comando>`. All user-facing text is Italian."""

from __future__ import annotations

import argparse
import getpass
import logging
import re
import sys
from pathlib import Path

from . import __version__, config, credentials, files, logsetup, messages, p7m, service, verify
from .errors import CredentialsError, FirmaError, OtpError
from .models import LAST_PAGE, Kind, Position, SignJob, StampSpec

log = logging.getLogger("firmaremota.cli")

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_PARTIAL = 0, 1, 2, 4
_OTP = re.compile(r"\d{6,8}")


def make_api():
    from .arss.client import ArssClient

    return ArssClient()


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise FirmaError(f"Impossibile leggere {path}: {exc.strerror}") from exc


def _password(settings: config.Settings) -> str:
    try:
        store = credentials.get_store()
        password = store.get(credentials.account_key(settings.user, settings.domain)) if store else None
    except credentials.CredentialStoreError as exc:
        print(f"Avviso: {exc.message}", file=sys.stderr)
        password = None
    if password:
        return password
    if not sys.stdin.isatty():
        raise CredentialsError("La password non è salvata: esegui 'firma configura'.")
    return getpass.getpass(f"Password Aruba di {settings.user}: ")


def _ask_otp() -> str:
    for _ in range(3):
        otp = input("Codice OTP dall'app Aruba OTP: ").strip().replace(" ", "")
        if _OTP.fullmatch(otp):
            return otp
        print("Il codice OTP è fatto di sole cifre (di solito 8): riprova.", file=sys.stderr)
    raise OtpError("Codice OTP non inserito: nessuna richiesta è stata inviata.")


def _confirm_after_failures() -> None:
    failures = service.auth_failures()
    if failures >= 1:
        print("Attenzione: l'ultimo accesso al servizio di firma è stato rifiutato. "
              "Un altro errore potrebbe bloccare l'account.", file=sys.stderr)
    if failures >= 2 and input("Scrivi 'si' per riprovare comunque: ").strip().lower() not in ("si", "sì"):
        raise FirmaError("Operazione annullata.")


def _page(value: str) -> int:
    if value.lower() == "ultima":
        return LAST_PAGE
    if value.isdigit() and int(value) >= 1:
        return int(value)
    raise argparse.ArgumentTypeError("usa un numero di pagina oppure 'ultima'")


def _stamp_spec(args: argparse.Namespace) -> StampSpec | None:
    if not getattr(args, "timbro", False):
        return None
    image = _read(Path(args.immagine)) if args.immagine else None
    return StampSpec(page=args.pagina, position=Position(args.posizione), text=args.testo or "", image=image)


def _sign(args: argparse.Namespace, kind: Kind) -> int:
    settings = config.load()
    account = service.account_from(settings)
    spec = _stamp_spec(args) if kind is Kind.PADES else None
    jobs = [SignJob(Path(f), kind, spec) for f in args.file]
    out_dir = Path(args.cartella) if args.cartella else None
    problems = service.preflight(jobs, out_dir)
    if problems:
        for problem in problems:
            print(f"Errore: {problem}", file=sys.stderr)
        print("Nessun file è stato firmato e non è stato usato alcun codice OTP.", file=sys.stderr)
        return EXIT_ERROR

    api = make_api()
    password = _password(settings)
    if spec and not settings.signer_name:
        name = service.fetch_signer_name(api, account, password)
        if name:
            settings.signer_name = name
            config.save(settings)
    _confirm_after_failures()
    if len(jobs) > 1:
        print(f"Firmo {len(jobs)} file con un solo codice OTP.")
    otp = _ask_otp()

    def progress(done: int, total: int, name: str) -> None:
        if name:
            print(f"[{done + 1}/{total}] {name}")

    results = service.sign_batch(api, account, password, otp, jobs, out_dir=out_dir,
                                 signer_name=settings.signer_name or None, progress=progress)
    for result in results:
        if result.ok:
            print(f"Firmato: {result.output}")
        else:
            print(f"Non firmato: {result.job.src.name}: {result.error.message}", file=sys.stderr)
    signed = sum(r.ok for r in results)
    return EXIT_OK if signed == len(jobs) else EXIT_PARTIAL if signed else EXIT_ERROR


def cmd_pdf(args: argparse.Namespace) -> int:
    return _sign(args, Kind.PADES)


def cmd_p7m(args: argparse.Namespace) -> int:
    return _sign(args, Kind.CADES)


def cmd_verifica(args: argparse.Namespace) -> int:
    print("Verifica in corso...")
    report = verify.verify_file(Path(args.file))
    for index, check in enumerate(report.checks, start=1):
        if len(report.checks) > 1:
            print(f"\n--- Firma {index} di {len(report.checks)} ---")
        print("\n".join(messages.check_lines(check)))
    if report.content_name:
        print(f"\nDocumento contenuto: {report.content_name} (per salvarlo: firma estrai {args.file})")
    print(f"\n{messages.trust_list_line(report)}")
    return EXIT_OK if report.ok else EXIT_ERROR


def cmd_estrai(args: argparse.Namespace) -> int:
    src = Path(args.file)
    data = _read(src)
    result = p7m.unwrap(data)
    out_dir = Path(args.cartella) if args.cartella else src.resolve().parent
    problem = files.check_writable(out_dir)
    if problem:
        raise FirmaError(problem)
    out = files.write_new(out_dir, p7m.inner_name(src.name, result.content), result.content)
    for depth, signers in enumerate(result.layers, start=1):
        label = "Firmato da" if len(result.layers) == 1 else f"Firma {depth} di {len(result.layers)}:"
        print(f"{label} {messages.signers_line(signers)}")
    print("Attenzione: questa è una lettura del file, la validità della firma non è stata verificata.")
    print(f"Documento estratto: {out}")
    log.info("estratto %s -> %s (%d buste)", src.name, out.name, len(result.layers))
    return EXIT_OK


def _add_output_option(parser: argparse.ArgumentParser, default: str) -> None:
    parser.add_argument("--cartella", metavar="CARTELLA", help=f"dove salvare (predefinito: {default})")


def build_parser() -> argparse.ArgumentParser:
    messages.italian_argparse()
    parser = argparse.ArgumentParser(
        prog="firma",
        description="Firma digitale remota Aruba: firma, verifica ed estrai documenti.",
    )
    parser.add_argument("--version", action="version", version=f"firma-remota {__version__}")
    parser.add_argument("--debug", action="store_true", help="scrive dettagli tecnici anche sul terminale")
    commands = parser.add_subparsers(dest="comando", title="comandi", metavar="COMANDO")

    pdf = commands.add_parser(
        "pdf", help="firma uno o più PDF (il risultato resta un PDF)",
        description="Firma uno o più PDF con un solo codice OTP. Il file firmato si chiama nome_firmato.pdf.",
    )
    pdf.add_argument("file", nargs="+", metavar="FILE", help="i PDF da firmare")
    pdf.add_argument("--timbro", action="store_true", help="aggiunge un riquadro visibile con la firma")
    pdf.add_argument("--pagina", type=_page, default=LAST_PAGE, metavar="N|ultima",
                     help="pagina del timbro (predefinito: ultima)")
    pdf.add_argument("--posizione", choices=[p.value for p in Position], default=Position.BOTTOM_RIGHT.value,
                     help="angolo del timbro (predefinito: basso-destra)")
    pdf.add_argument("--testo", help="testo aggiuntivo nel timbro")
    pdf.add_argument("--immagine", metavar="FILE", help="immagine (PNG/JPEG) da mettere nel timbro")
    _add_output_option(pdf, "accanto a ogni PDF")
    pdf.set_defaults(handler=cmd_pdf)

    p7m_cmd = commands.add_parser(
        "p7m", help="firma uno o più file di qualsiasi tipo (crea file .p7m)",
        description="Firma uno o più file con un solo codice OTP, creando una busta nome.estensione.p7m.",
    )
    p7m_cmd.add_argument("file", nargs="+", metavar="FILE", help="i file da firmare")
    _add_output_option(p7m_cmd, "accanto a ogni file")
    p7m_cmd.set_defaults(handler=cmd_p7m)

    verifica = commands.add_parser(
        "verifica", help="verifica la firma di un PDF o di un file .p7m",
        description="Verifica le firme di un PDF firmato o di un file .p7m con l'elenco ufficiale dei certificatori.",
    )
    verifica.add_argument("file", metavar="FILE", help="il file firmato")
    verifica.set_defaults(handler=cmd_verifica)

    estrai = commands.add_parser(
        "estrai", help="estrae il documento originale da un file .p7m",
        description="Estrae il documento originale da un file .p7m (anche con più firme annidate).",
    )
    estrai.add_argument("file", metavar="FILE", help="il file .p7m")
    _add_output_option(estrai, "accanto al .p7m")
    estrai.set_defaults(handler=cmd_estrai)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        logsetup.setup(debug=args.debug, console=args.debug)
    except OSError as exc:
        print(f"Avviso: impossibile scrivere il registro ({exc.strerror}).", file=sys.stderr)
    try:
        return args.handler(args)
    except FirmaError as exc:
        log.warning("errore: %s (%s)", exc.message, exc.detail or "-")
        print(f"Errore: {exc.message}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\nInterrotto.", file=sys.stderr)
        return 130
