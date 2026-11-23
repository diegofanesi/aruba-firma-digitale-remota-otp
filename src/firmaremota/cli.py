"""Command line: `firma <comando>`. All user-facing text is Italian."""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import logging
import re
import sys
from pathlib import Path

from . import __version__, config, credentials, diagnostics, files, logsetup, messages, p7m, profiles, service, verify
from .errors import CredentialsError, FirmaError, OtpError
from .models import LAST_PAGE, Kind, Position, SignerInfo, SignJob, StampSpec

log = logging.getLogger("firmaremota.cli")

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_PARTIAL = 0, 1, 2, 4
_OTP = re.compile(r"[0-9]{6,8}")  # ASCII digits only: \d would also accept e.g. Arabic-Indic numerals


def make_api():
    from .arss.client import ArssClient

    return ArssClient()


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise FirmaError(f"Impossibile leggere {path}: {exc.strerror}") from exc


def _saved_profiles() -> tuple[credentials.Store | None, list[profiles.Profile]]:
    store = credentials.get_store()
    return store, (profiles.load_all(store) if store else [])


def _choose_profile(available: list[profiles.Profile], alias: str | None,
                    settings: config.Settings) -> profiles.Profile | None:
    """The account to use, or None when nothing is saved (then everything is typed)."""
    if alias:
        profile = profiles.find(available, alias)
        if profile is None:
            names = ", ".join(f"«{p.alias}»" for p in available) or "nessuno"
            raise CredentialsError(f"Nessun account si chiama «{alias}». Account salvati: {names}.")
        return profile
    if not available:
        return None
    if len(available) == 1:
        return available[0]
    default = profiles.by_id(available, settings.last_profile) or available[0]
    if not sys.stdin.isatty():
        raise CredentialsError("Ci sono più account salvati: scegli quale usare con --account ALIAS.")
    print("Quale account?")
    for number, profile in enumerate(available, start=1):
        print(f"  {number}. {profile.alias} ({profile.login})")
    answer = input(f"Numero [{available.index(default) + 1}]: ").strip()
    if not answer:
        return default
    if answer.isdigit() and 1 <= int(answer) <= len(available):
        return available[int(answer) - 1]
    raise CredentialsError("Scelta non valida.")


def _typed_login() -> tuple[str, str]:
    if not sys.stdin.isatty():
        raise CredentialsError("Nessun account salvato: esegui 'firma configura'.")
    raw = input("Nome utente Aruba (utente@dominio): ").strip()
    if not raw:
        raise CredentialsError("Serve il nome utente.")
    user, domain = credentials.split_login(raw)
    logsetup.register_personal(f"{user}@{domain}", user)
    return user, domain


def _typed_password() -> str:
    if not sys.stdin.isatty():
        raise CredentialsError("La password non è salvata: esegui 'firma configura'.")
    return getpass.getpass("Password Aruba: ")


def _credentials(args: argparse.Namespace, settings: config.Settings) -> tuple[str, str, str, profiles.Profile | None]:
    """(user, domain, password, profile): from the wallet where possible, typed otherwise."""
    store, available = _saved_profiles()
    profile = _choose_profile(available, getattr(args, "account", None), settings)
    if profile is None:
        user, domain = _typed_login()
        return user, domain, _typed_password(), None
    password = profiles.password(store, profile) or _typed_password()
    return profile.user, profile.domain, password, profile


def _warn_expiry(signer: SignerInfo) -> None:
    left = signer.not_after - dt.datetime.now(dt.timezone.utc)
    if left < dt.timedelta(days=60):
        print(f"Attenzione: il certificato di firma scade il {signer.not_after.astimezone():%d/%m/%Y}: "
              "rinnovalo per tempo.", file=sys.stderr)


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

    user, domain, password, profile = _credentials(args, settings)
    api = make_api()
    _confirm_after_failures()
    account, signer = service.prepare_account(api, user, domain, password, settings)
    _warn_expiry(signer)
    if profile is not None and settings.last_profile != profile.id:
        settings.last_profile = profile.id
        config.save(settings)
    if len(jobs) > 1:
        print(f"Firmo {len(jobs)} file con un solo codice OTP.")
    otp = _ask_otp()

    def progress(done: int, total: int, name: str) -> None:
        if name:
            print(f"[{done + 1}/{total}] {name}")

    results = service.sign_batch(api, account, password, otp, jobs, out_dir=out_dir,
                                 signer_name=signer.name, progress=progress)
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


def _needs_profile(args: argparse.Namespace) -> bool:
    return bool(args.rimuovi or args.dimentica_password or args.salva_password)


def cmd_configura(args: argparse.Namespace) -> int:
    store = credentials.get_store()
    if store is None:
        if args.elenco or args.dimentica_tutto or _needs_profile(args):
            print("Su questo computer non c'è un portachiavi: non c'è nulla di salvato.")
            return EXIT_OK
        raise FirmaError("Su questo computer non c'è un portachiavi (KWallet o Secret Service): gli account non "
                         "si possono salvare, nome utente e password verranno chiesti a ogni firma.")
    available = profiles.load_all(store)
    settings = config.load()

    if args.elenco:
        if not available:
            print("Nessun account salvato.")
        for profile in available:
            saved = "password salvata" if profiles.password(store, profile) else "password non salvata"
            print(f"{profile.alias}: {profile.login} ({saved})")
        return EXIT_OK
    if args.dimentica_tutto:
        profiles.forget_all(store, available)
        print(f"Tutti gli account sono stati rimossi da {store.name}.")
        return EXIT_OK
    if args.rimuovi or args.dimentica_password:
        profile = _choose_profile(available, args.account, settings)
        if profile is None:
            print("Nessun account salvato.")
            return EXIT_OK
        if args.rimuovi:
            profiles.remove(store, available, profile)
            print(f"Account «{profile.alias}» rimosso da {store.name}.")
        else:
            profiles.forget_password(store, profile)
            print(f"Password di «{profile.alias}» rimossa: verrà chiesta a ogni firma.")
        return EXIT_OK

    if not sys.stdin.isatty():
        raise FirmaError("'firma configura' va eseguito in un terminale.")
    api = make_api()
    if args.salva_password:
        profile = _choose_profile(available, args.account, settings)
        if profile is None:
            raise CredentialsError("Nessun account salvato: esegui 'firma configura' senza opzioni per aggiungerne uno.")
        password = _new_password()
        print("Controllo la password con Aruba (non serve il codice OTP)...")
        service.prepare_account(api, profile.user, profile.domain, password)
        profiles.set_password(store, profile, password)
        print(f"Password di «{profile.alias}» salvata in {store.name}.")
        return EXIT_OK

    editing = profiles.find(available, args.account) if args.account else None
    print(f"Modifica dell'account «{editing.alias}».\n" if editing else "Nuovo account di firma remota Aruba.\n")
    user, domain = _ask_account(editing.user if editing else "", editing.domain if editing else "firma")
    default_alias = editing.alias if editing else (args.account or user)
    alias = input(f"Nome dell'account, come vuoi vederlo nell'elenco [{default_alias}]: ").strip() or default_alias
    remember = _yes(f"Ricordare la password in {store.name}?")
    password = _new_password() if remember else getpass.getpass("Password Aruba: ")
    print("Controllo le credenziali con Aruba (non serve il codice OTP)...")
    _, signer = service.prepare_account(api, user, domain, password)
    profile = profiles.new_profile(alias, user, domain, id=editing.id if editing else None)
    profiles.upsert(store, available, profile)
    if remember:
        profiles.set_password(store, profile, password)
    else:
        profiles.forget_password(store, profile)
    settings.last_profile = profile.id
    config.save(settings)

    print(f"\nFatto. Account «{profile.alias}»: certificato di {signer.name}, "
          f"valido fino al {signer.not_after.astimezone():%d/%m/%Y}.")
    if remember:
        print(f"Nome utente e password sono in {store.name}; sul disco non viene salvato nient'altro.")
    else:
        print(f"Nome utente in {store.name}; la password verrà chiesta a ogni firma.")
    return EXIT_OK


def cmd_diagnostica(args: argparse.Namespace) -> int:
    lines = diagnostics.report(make_api(), check_credentials=args.credenziali)
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
    pdf.add_argument("--account", metavar="ALIAS", help="con quale account firmare (se ce n'è più d'uno)")
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
    p7m_cmd.add_argument("--account", metavar="ALIAS", help="con quale account firmare (se ce n'è più d'uno)")
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
        "configura", help="aggiunge, modifica o rimuove gli account Aruba",
        description="Senza opzioni aggiunge un account (o modifica quello indicato con --account): nome utente, "
                    "dominio e password vengono controllati con Aruba (senza codice OTP) e tenuti solo nel "
                    "portachiavi, sul disco non si salva nulla. Ogni account ha un nome (alias) a tua scelta.",
    )
    configura.add_argument("--account", metavar="ALIAS", help="su quale account agire (se ce n'è più d'uno)")
    only = configura.add_mutually_exclusive_group()
    only.add_argument("--elenco", action="store_true", help="mostra gli account salvati")
    only.add_argument("--salva-password", action="store_true", help="salva (o cambia) solo la password")
    only.add_argument("--dimentica-password", action="store_true", help="cancella la password dal portachiavi")
    only.add_argument("--rimuovi", action="store_true", help="rimuove l'account dal portachiavi")
    only.add_argument("--dimentica-tutto", action="store_true", help="rimuove tutti gli account dal portachiavi")
    configura.set_defaults(handler=cmd_configura)

    diagnostica = commands.add_parser(
        "diagnostica", help="controlla che tutto funzioni (utile per l'assistenza)",
        description="Controlla configurazione, portachiavi, collegamento ad Aruba e scadenza del certificato. "
                    "Non mostra mai la password.",
    )
    diagnostica.add_argument("--credenziali", action="store_true",
                             help="chiede anche ad Aruba di controllare le credenziali salvate (senza codice OTP)")
    diagnostica.set_defaults(handler=cmd_diagnostica)

    gui = commands.add_parser("gui", help="apre l'interfaccia grafica",
                              description="Apre l'interfaccia grafica, eventualmente con dei file già scelti.")
    gui.add_argument("file", nargs="*", metavar="FILE", help="file da firmare o da controllare")
    gui.set_defaults(handler=cmd_gui)
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
    except EOFError:  # stdin closed while a question was being asked
        print("\nInput terminato: operazione annullata.", file=sys.stderr)
        return EXIT_ERROR
    except Exception:
        log.exception("errore imprevisto")
        print(f"Errore imprevisto. I dettagli sono nel registro: {logsetup.log_path()}", file=sys.stderr)
        return EXIT_ERROR
