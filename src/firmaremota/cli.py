"""Command line: `firma <comando>`. All user-facing text is Italian."""

from __future__ import annotations

import argparse
import getpass
import logging
import re
import sys
from pathlib import Path

from . import __version__, config, credentials, diagnostics, files, logsetup, messages, p7m, service, vault, verify
from .errors import CredentialsError, FirmaError, OtpError
from .models import LAST_PAGE, Account, Kind, Position, SignJob, StampSpec

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


def _password() -> str | None:
    """The Aruba password saved in the wallet, if any."""
    try:
        return credentials.stored_password()
    except credentials.CredentialStoreError as exc:
        print(f"Avviso: {exc.message}", file=sys.stderr)
        return None


def _unlock() -> tuple[str, vault.Profile]:
    """Password (from the wallet, or typed) and the decrypted profile.

    A wrongly typed password fails here, on this computer, without contacting Aruba.
    """
    if not vault.exists():
        raise CredentialsError("Account non configurato: esegui 'firma configura'.")
    password = _password()
    if not password:
        if not sys.stdin.isatty():
            raise CredentialsError("La password non è salvata: esegui 'firma configura'.")
        password = getpass.getpass("Password Aruba: ")
    return password, vault.load(password)


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
    spec = _stamp_spec(args) if kind is Kind.PADES else None
    jobs = [SignJob(Path(f), kind, spec) for f in args.file]
    out_dir = Path(args.cartella) if args.cartella else None
    problems = service.preflight(jobs, out_dir)
    if problems:
        for problem in problems:
            print(f"Errore: {problem}", file=sys.stderr)
        print("Nessun file è stato firmato e non è stato usato alcun codice OTP.", file=sys.stderr)
        return EXIT_ERROR

    password, profile = _unlock()
    account = service.account_from(profile, settings)
    api = make_api()
    _confirm_after_failures()
    if len(jobs) > 1:
        print(f"Firmo {len(jobs)} file con un solo codice OTP.")
    otp = _ask_otp()

    def progress(done: int, total: int, name: str) -> None:
        if name:
            print(f"[{done + 1}/{total}] {name}")

    results = service.sign_batch(api, account, password, otp, jobs, out_dir=out_dir,
                                 signer_name=profile.signer_name or None, progress=progress)
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


def _yes(question: str, default: bool = True) -> bool:
    answer = input(f"{question} [{'S/n' if default else 's/N'}] ").strip().lower()
    return default if not answer else answer in ("s", "si", "sì", "y", "yes")


def _new_password() -> str:
    password = getpass.getpass("Password Aruba: ")
    if not password:
        raise CredentialsError("La password non può essere vuota.")
    if getpass.getpass("Ripeti la password: ") != password:
        raise CredentialsError("Le due password non coincidono: nulla è stato salvato.")
    return password


def _ask_account(default_user: str, default_domain: str) -> tuple[str, str]:
    """Username and domain; 'utente@dominio' (as Aruba's selfcare shows it) is accepted in one go."""
    raw = input(f"Nome utente Aruba [{default_user}]: ").strip() or default_user
    if "@" in raw:
        user, domain = (part.strip() for part in raw.split("@", 1))
        print(f"Dominio di firma: {domain}")
    else:
        user = raw
        domain = input(f"Dominio di firma (di solito 'firma') [{default_domain}]: ").strip() or default_domain
    if not (user and domain):
        raise CredentialsError("Nome utente e dominio sono obbligatori.")
    return user, domain


def _choose_certificate(certs):
    if not certs:
        raise CredentialsError("Aruba non ha trovato certificati di firma per questo account.")
    if len(certs) == 1:
        return certs[0]
    print("Questo account ha più certificati:")
    for number, (_, signer) in enumerate(certs, start=1):
        print(f"  {number}. {signer.name}, valido fino al {signer.not_after.astimezone():%d/%m/%Y}")
    choice = input(f"Quale usare? [1-{len(certs)}] ").strip() or "1"
    if not choice.isdigit() or not 1 <= int(choice) <= len(certs):
        raise FirmaError("Scelta non valida: nulla è stato salvato.")
    return certs[int(choice) - 1]


def _save_password(store, key: str, password: str) -> None:
    store.set(key, password)
    if store.get(key) != password:
        raise credentials.CredentialStoreError("Il portachiavi non ha restituito la password appena salvata.")


def _current_profile() -> vault.Profile | None:
    """The existing profile, if the saved password opens it (used for defaults only)."""
    password = _password()
    if not (password and vault.exists()):
        return None
    try:
        return vault.load(password)
    except vault.VaultError:
        return None


def _change_password(api, store) -> int:
    new = _new_password()
    try:
        profile = vault.load(new)  # same password as before: just remember it
    except vault.VaultError:
        old = _password() or getpass.getpass("Password precedente (quella che apriva il profilo): ")
        profile = vault.load(old)
    print("Controllo la password con Aruba (non serve il codice OTP)...")
    service.check_credentials(api, service.account_from(profile, config.load()), new)
    vault.save(profile, new)
    _save_password(store, credentials.PASSWORD_KEY, new)
    print(f"Password salvata in {store.name}; profilo cifrato di nuovo con la nuova password.")
    return EXIT_OK


def cmd_configura(args: argparse.Namespace) -> int:
    store = credentials.get_store()
    if args.dimentica_password:
        if store and store.get(credentials.PASSWORD_KEY):
            store.delete(credentials.PASSWORD_KEY)
            print(f"Password rimossa da {store.name}: verrà chiesta a ogni firma.")
        else:
            print("Non c'era nessuna password salvata.")
        return EXIT_OK
    if not sys.stdin.isatty():
        raise FirmaError("'firma configura' va eseguito in un terminale.")
    api = make_api()
    if args.salva_password:
        if store is None:
            raise FirmaError("Nessun portachiavi disponibile su questo computer.")
        if not vault.exists():
            raise CredentialsError("Account non configurato: esegui 'firma configura'.")
        return _change_password(api, store)

    print("Configurazione della firma remota Aruba.\n")
    current = _current_profile()
    user, domain = _ask_account(current.user if current else "", current.domain if current else "firma")
    save = store is not None and _yes(f"Salvare la password in {store.name}?")
    password = _new_password() if save else getpass.getpass("Password Aruba: ")
    print("Controllo le credenziali con Aruba (non serve il codice OTP)...")
    certs = service.check_credentials(api, Account(user, domain, cert_id=""), password)
    cert_id, signer = _choose_certificate(certs)

    profile = vault.Profile(user, domain, cert_id, signer.name, signer.not_after.date().isoformat())
    path = vault.save(profile, password)
    vault.register_personal(profile)
    if store is not None:
        if save:
            _save_password(store, credentials.PASSWORD_KEY, password)
        else:
            store.delete(credentials.PASSWORD_KEY)  # an older saved password would no longer open the profile
        store.delete(credentials.legacy_key(user, domain))
    config.save(config.load())  # drops plain-text account data left by older versions

    print(f"\nFatto. Certificato di {signer.name}, valido fino al {signer.not_after.astimezone():%d/%m/%Y}.")
    print(f"Dati dell'account cifrati (AES-256) in {path}.")
    print(f"Password salvata in {store.name}." if save else "La password verrà chiesta a ogni firma.")
    return EXIT_OK


def cmd_diagnostica(args: argparse.Namespace) -> int:
    password = _password()
    if args.account and not password and vault.exists() and sys.stdin.isatty():
        password = getpass.getpass("Password Aruba: ")
    lines = diagnostics.report(make_api(), password, check_account=args.account)
    print(diagnostics.as_text(lines))
    return EXIT_ERROR if diagnostics.has_errors(lines) else EXIT_OK


def cmd_gui(args: argparse.Namespace) -> int:
    try:
        from .gui.app import main as gui_main
    except ImportError as exc:
        raise FirmaError("L'interfaccia grafica non è installata (manca PySide6): "
                         "reinstalla firma-remota con l'opzione [gui].", detail=str(exc)) from None
    return gui_main(args.file)


def cmd_estrai(args: argparse.Namespace) -> int:
    src = Path(args.file)
    out_dir = Path(args.cartella) if args.cartella else src.resolve().parent
    logsetup.register_paths(src, out_dir)
    data = _read(src)
    result = p7m.unwrap(data)
    problem = files.check_writable(out_dir)
    if problem:
        raise FirmaError(problem)
    out = files.write_new(out_dir, p7m.inner_name(src.name, result.content), result.content)
    logsetup.register_paths(out)
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

    configura = commands.add_parser(
        "configura", help="imposta account Aruba, dominio e password",
        description="Imposta nome utente, dominio di firma e password; controlla le credenziali con Aruba "
                    "(senza codice OTP) e sceglie il certificato di firma.",
    )
    only = configura.add_mutually_exclusive_group()
    only.add_argument("--salva-password", action="store_true", help="salva (o cambia) solo la password")
    only.add_argument("--dimentica-password", action="store_true", help="cancella la password dal portachiavi")
    configura.set_defaults(handler=cmd_configura)

    diagnostica = commands.add_parser(
        "diagnostica", help="controlla che tutto funzioni (utile per l'assistenza)",
        description="Controlla configurazione, portachiavi, collegamento ad Aruba e scadenza del certificato. "
                    "Non mostra mai la password.",
    )
    diagnostica.add_argument("--account", action="store_true",
                             help="chiede anche ad Aruba di controllare le credenziali (senza codice OTP)")
    diagnostica.set_defaults(handler=cmd_diagnostica)

    gui = commands.add_parser("gui", help="apre l'interfaccia grafica",
                              description="Apre l'interfaccia grafica, eventualmente con dei file già scelti.")
    gui.add_argument("file", nargs="*", metavar="FILE", help="file da firmare o da controllare")
    gui.set_defaults(handler=cmd_gui)
    return parser


def _migrate() -> None:
    try:
        if vault.migrate_legacy():
            print(f"Nota: i dati dell'account ora sono cifrati (AES-256) in {vault.path()}.", file=sys.stderr)
    except Exception as exc:  # never block a command because of the one-time migration
        log.warning("migrazione del profilo non riuscita: %s", exc)


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
    _migrate()
    try:
        return args.handler(args)
    except FirmaError as exc:
        log.warning("errore: %s (%s)", exc.message, exc.detail or "-")
        print(f"Errore: {exc.message}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\nInterrotto.", file=sys.stderr)
        return 130
