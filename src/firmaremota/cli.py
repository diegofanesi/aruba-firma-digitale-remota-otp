"""Command line: `firma <comando>`. All user-facing text is Italian."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import getpass
import logging
import re
import sys
from pathlib import Path

from . import __version__, config, credentials, diagnostics, files, logsetup, messages, p7m, profiles, service, tst, verify
from .errors import CredentialsError, FirmaError, OtpError, TimestampError
from .models import LAST_PAGE, Kind, Position, SignerInfo, SignJob, StampSpec, TimestampType, TsaCredentials

log = logging.getLogger("firmaremota.cli")

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_PARTIAL, EXIT_UNVERIFIABLE = 0, 1, 2, 4, 5
VERDICT_EXIT = {"valida": EXIT_OK, "non verificabile": EXIT_UNVERIFIABLE}  # anything else: EXIT_ERROR
_OTP = re.compile(r"[0-9]{6,8}")  # ASCII digits only: \d would also accept e.g. Arabic-Indic numerals


def make_api():
    from .arss.client import ArssClient

    return ArssClient()


def _read(path: Path, limit: int | None = None) -> bytes:
    problem = files.check_size(path, files.MAX_VERIFY_SIZE if limit is None else limit)
    if problem:
        raise FirmaError(problem)
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
        raise CredentialsError("Nessun account salvato: esegui 'aruba-firma configura'.")
    raw = input("Nome utente Aruba (utente@dominio): ").strip()
    if not raw:
        raise CredentialsError("Serve il nome utente.")
    user, domain = credentials.split_login(raw)
    logsetup.register_personal(f"{user}@{domain}", user)
    return user, domain


def _typed_password() -> str:
    if not sys.stdin.isatty():
        raise CredentialsError("La password non è salvata: esegui 'aruba-firma configura'.")
    return getpass.getpass("Password Aruba: ")


def _credentials(args: argparse.Namespace, settings: config.Settings):
    """(user, domain, password, profile, store): from the wallet where possible, typed otherwise."""
    store, available = _saved_profiles()
    profile = _choose_profile(available, getattr(args, "account", None), settings)
    if profile is None:
        user, domain = _typed_login()
        return user, domain, _typed_password(), None, store
    password = profiles.password(store, profile) or _typed_password()
    return profile.user, profile.domain, password, profile, store


def _timestamp_wanted(args: argparse.Namespace, profile: profiles.Profile | None) -> bool:
    """--marca / --senza-marca win; otherwise the account's setting (on by default, also for typed logins)."""
    wanted = getattr(args, "marca", None)
    if wanted is not None:
        return wanted
    return profile.timestamp if profile is not None else True


def _remember_profile(settings: config.Settings, profile: profiles.Profile | None) -> None:
    if profile is not None and settings.last_profile != profile.id:
        settings.last_profile = profile.id
        config.save(settings)


def _warn_expiry(signer: SignerInfo) -> None:
    left = signer.not_after - dt.datetime.now(dt.timezone.utc)
    if left < dt.timedelta(days=60):
        print(f"Attenzione: il certificato di firma scade il {signer.not_after.astimezone():%d/%m/%Y}: "
              "rinnovalo per tempo.", file=sys.stderr)


def _ask_otp() -> str:
    for _ in range(3):
        otp = getpass.getpass("Codice OTP dall'app Aruba OTP (non viene mostrato mentre lo scrivi): ")
        otp = otp.strip().replace(" ", "")
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

    jobs = service.fingerprint(jobs)  # a file that changes from now on is refused at signing time
    user, domain, password, profile, store = _credentials(args, settings)
    level = TimestampType(args.tipo_marca) if _timestamp_wanted(args, profile) else None
    tsa = profiles.tsa_credentials(store, profile) if level else None
    problem = service.needs_tsa_account(level, tsa)
    if problem:
        raise TimestampError(problem)
    api = make_api()
    _confirm_after_failures()
    account, signer = service.prepare_account(api, user, domain, password, settings)
    _warn_expiry(signer)
    _remember_profile(settings, profile)
    with_mark = ", con marca temporale" if level else ""
    if len(jobs) > 1:
        print(f"Firmo {len(jobs)} file con un solo codice OTP{with_mark}.")
    otp = _ask_otp()
    results = service.sign_batch(api, account, password, otp, jobs, out_dir=out_dir, signer_name=signer.name,
                                 progress=_progress, tsa=tsa, level=level)
    return _report(results, "Firmato", "Non firmato", with_mark.strip(", "))


def _progress(done: int, total: int, name: str) -> None:
    if name:
        print(f"[{done + 1}/{total}] {name}")


def _report(results, done: str, failed: str, note: str = "") -> int:
    for result in results:
        if result.ok:
            print(f"{done}: {result.output}" + (f" — {note}" if note else ""))
        else:
            print(f"{failed}: {result.job.src.name}: {result.error.message}", file=sys.stderr)
    ok = sum(r.ok for r in results)
    return EXIT_OK if ok == len(results) else EXIT_PARTIAL if ok else EXIT_ERROR


def cmd_pdf(args: argparse.Namespace) -> int:
    return _sign(args, Kind.PADES)


def cmd_p7m(args: argparse.Namespace) -> int:
    return _sign(args, Kind.CADES)


TSR_NOTE = ("Formato TSR: la marca è un file separato. Se la mandi a qualcuno, manda anche il documento "
            "originale, con lo stesso nome.")


def cmd_marca(args: argparse.Namespace) -> int:
    """A standalone timestamp on each file: no signature, no OTP (ArubaSign's "Marca" tab)."""
    settings = config.load()
    fmt = Kind.TSR if args.formato == "tsr" else Kind.TSD
    jobs = [SignJob(Path(f), fmt) for f in args.file]
    out_dir = Path(args.cartella) if args.cartella else None
    problems = service.preflight(jobs, out_dir)
    if problems:
        for problem in problems:
            print(f"Errore: {problem}", file=sys.stderr)
        print("Nessun file è stato marcato.", file=sys.stderr)
        return EXIT_ERROR
    jobs = service.fingerprint(jobs)
    user, domain, password, profile, store = _credentials(args, settings)
    tsa = profiles.tsa_credentials(store, profile)
    if tsa is None:
        raise TimestampError(service.NO_TSA_ACCOUNT)
    _remember_profile(settings, profile)
    if fmt is Kind.TSR:
        print(TSR_NOTE)
    results = service.timestamp_batch(make_api(), tsa, jobs, out_dir=out_dir, progress=_progress)
    return _report(results, "Marcato", "Non marcato")


def _date_arg(text: str) -> dt.datetime:
    try:
        day = dt.datetime.strptime(text.strip(), "%d/%m/%Y")
    except ValueError:
        raise argparse.ArgumentTypeError("usa il formato GG/MM/AAAA, per esempio 31/12/2027") from None
    return day.replace(hour=23, minute=59, second=59).astimezone()  # the end of that day, local time


def cmd_verifica(args: argparse.Namespace) -> int:
    print("Verifica in corso...")
    original = Path(args.originale) if args.originale else None
    report = verify.verify_file(Path(args.file), original=original, at=args.alla_data)
    for index, check in enumerate(report.checks, start=1):
        if len(report.checks) > 1:
            print(f"\n--- Firma {index} di {len(report.checks)} ---")
        print("\n".join(messages.check_lines(check)))
    if not report.checks:
        print(messages.verdict_title(report))
    for line in messages.timestamp_lines(report):
        print(line)
    if report.content_name:
        print(f"\nDocumento contenuto: {report.content_name} (per salvarlo: aruba-firma estrai {args.file})")
    print(f"\n{messages.trust_list_line(report)}")
    return VERDICT_EXIT.get(report.verdict, EXIT_ERROR)


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
    return bool(args.rimuovi or args.dimentica_password or args.salva_password or args.marca is not None
                or args.credenziali_marca or args.dimentica_credenziali_marca)


def _timestamp_label(store, profile: profiles.Profile) -> str:
    if not profile.timestamp:
        return "marca temporale: no"
    return "marca temporale: sì (" + ("account TSA" if store.get(profile.tsa_key) else "marca automatica di Aruba") + ")"


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
            print(f"{profile.alias}: {profile.login} ({saved}; {_timestamp_label(store, profile)})")
        return EXIT_OK
    if args.dimentica_tutto:
        profiles.forget_all(store, available)
        print(f"Tutti gli account sono stati rimossi da {store.name}.")
        return EXIT_OK
    if args.rimuovi or args.dimentica_password or args.marca is not None or args.dimentica_credenziali_marca:
        profile = _choose_profile(available, args.account, settings)
        if profile is None:
            print("Nessun account salvato.")
            return EXIT_OK
        if args.rimuovi:
            profiles.remove(store, available, profile)
            print(f"Account «{profile.alias}» rimosso da {store.name}.")
        elif args.dimentica_password:
            profiles.forget_password(store, profile)
            print(f"Password di «{profile.alias}» rimossa: verrà chiesta a ogni firma.")
        elif args.marca is not None:
            wanted = args.marca == "si"
            profiles.upsert(store, available, dataclasses.replace(profile, timestamp=wanted))
            print(f"Marca temporale per «{profile.alias}»: {'attiva' if wanted else 'disattivata'}"
                  + (" (le firme avranno una marca temporale)." if wanted else " (firme senza marca)."))
        else:
            profiles.forget_tsa(store, profile)
            print(f"Credenziali TSA di «{profile.alias}» rimosse.")
        return EXIT_OK

    if not sys.stdin.isatty():
        raise FirmaError("'aruba-firma configura' va eseguito in un terminale.")
    if args.credenziali_marca:
        profile = _choose_profile(available, args.account, settings)
        if profile is None:
            raise CredentialsError("Nessun account salvato: esegui 'aruba-firma configura' senza opzioni per aggiungerne uno.")
        print("Credenziali del servizio di marca temporale (come in Aruba Sign: Account TSA, Password, Indirizzo "
              "server). Lascia vuoto l'indirizzo per usare quello di Aruba.")
        tsa_user = input(f"Account TSA [{profile.user}]: ").strip() or profile.user
        tsa_password = getpass.getpass("Password TSA: ")
        if not tsa_password:
            raise CredentialsError("Serve la password del servizio di marca temporale.")
        url = input("Indirizzo server TSA [predefinito Aruba]: ").strip() or None
        profiles.set_tsa(store, profile, TsaCredentials(tsa_user, tsa_password, url))
        print(f"Credenziali TSA di «{profile.alias}» salvate in {store.name} (verranno controllate alla prima marca: "
              "ogni prova consuma una marca).")
        return EXIT_OK
    api = make_api()
    if args.salva_password:
        profile = _choose_profile(available, args.account, settings)
        if profile is None:
            raise CredentialsError("Nessun account salvato: esegui 'aruba-firma configura' senza opzioni per aggiungerne uno.")
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
    profile = profiles.new_profile(alias, user, domain, id=editing.id if editing else None,
                                   timestamp=editing.timestamp if editing else True)
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
    if profile.timestamp:
        print("Marca temporale: attiva (le firme avranno data certa; per disattivarla: aruba-firma configura --marca no).")
    return EXIT_OK


def cmd_diagnostica(args: argparse.Namespace) -> int:
    only = None
    if args.credenziali:  # one account per run: the one asked for, else the last used, else the only one
        store, saved = _saved_profiles()
        settings = config.load()
        if args.account:
            profile = _choose_profile(saved, args.account, settings)
        else:
            usable = [p for p in saved if profiles.password(store, p)]
            profile = profiles.by_id(usable, settings.last_profile) or _choose_profile(usable, None, settings)
        only = profile.id if profile else None
    lines = diagnostics.report(make_api(), check_credentials=args.credenziali, only_profile_id=only)
    print(diagnostics.as_text(lines))
    return EXIT_ERROR if diagnostics.has_errors(lines) else EXIT_OK


def cmd_gui(args: argparse.Namespace) -> int:
    try:
        from .gui.app import main as gui_main
    except ImportError as exc:
        raise FirmaError("L'interfaccia grafica non è installata (manca PySide6): "
                         "reinstalla aruba-firma con l'opzione [gui].", detail=str(exc)) from None
    return gui_main(args.file)


def cmd_estrai(args: argparse.Namespace) -> int:
    src = Path(args.file)
    out_dir = Path(args.cartella) if args.cartella else src.resolve().parent
    logsetup.register_paths(src, out_dir)
    data = _read(src)
    if tst.is_tsr(data):
        raise FirmaError("Una marca temporale .tsr non contiene il documento: il documento è il file con lo stesso "
                         "nome senza «.tsr». Per controllarla: aruba-firma verifica FILE.tsr")
    result = tst.unwrap(data)
    if not result.layers and not result.timestamps:
        raise FirmaError("Il file non è né una busta firmata .p7m né un documento marcato .tsd.")
    problem = files.check_writable(out_dir)
    if problem:
        raise FirmaError(problem)
    out = files.write_new(out_dir, p7m.inner_name(src.name, result.content), result.content)
    logsetup.register_paths(out)
    for depth, signers in enumerate(result.layers, start=1):
        label = "Firmato da" if len(result.layers) == 1 else f"Firma {depth} di {len(result.layers)}:"
        print(f"{label} {messages.signers_line(signers)}")
    if result.timestamps:
        print(f"Marca temporale: sì ({result.timestamps} busta .tsd)" if result.timestamps == 1
              else f"Marche temporali: {result.timestamps} buste .tsd")
    print("Attenzione: questa è una lettura del file, la validità della firma e delle marche non è stata verificata.")
    print(f"Documento estratto: {out}")
    log.info("estratto %s -> %s (%d buste)", src.name, out.name, len(result.layers))
    return EXIT_OK


def _add_output_option(parser: argparse.ArgumentParser, default: str) -> None:
    parser.add_argument("--cartella", metavar="CARTELLA", help=f"dove salvare (predefinito: {default})")


def _add_timestamp_options(parser: argparse.ArgumentParser, levels: list[str]) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--marca", dest="marca", action="store_const", const=True, default=None,
                       help="aggiunge la marca temporale (data certa) alla firma")
    group.add_argument("--senza-marca", dest="marca", action="store_const", const=False,
                       help="firma senza marca temporale, qualunque sia l'impostazione dell'account")
    parser.add_argument("--tipo-marca", choices=levels, default="T",
                        help="T: marca nella firma (predefinito); LT: anche con i dati di revoca"
                             + ("; TSD: busta .p7m.tsd" if "TSD" in levels else ""))


def build_parser() -> argparse.ArgumentParser:
    messages.italian_argparse()
    parser = argparse.ArgumentParser(
        prog="aruba-firma",
        description="Firma digitale remota Aruba: firma, verifica ed estrai documenti.",
    )
    parser.add_argument("--version", action="version", version=f"aruba-firma {__version__}")
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
    _add_timestamp_options(pdf, ["T", "LT"])
    _add_output_option(pdf, "accanto a ogni PDF")
    pdf.set_defaults(handler=cmd_pdf)

    p7m_cmd = commands.add_parser(
        "p7m", help="firma uno o più file di qualsiasi tipo (crea file .p7m)",
        description="Firma uno o più file con un solo codice OTP, creando una busta nome.estensione.p7m.",
    )
    p7m_cmd.add_argument("file", nargs="+", metavar="FILE", help="i file da firmare")
    p7m_cmd.add_argument("--account", metavar="ALIAS", help="con quale account firmare (se ce n'è più d'uno)")
    _add_timestamp_options(p7m_cmd, ["T", "LT", "TSD"])
    _add_output_option(p7m_cmd, "accanto a ogni file")
    p7m_cmd.set_defaults(handler=cmd_p7m)

    marca = commands.add_parser(
        "marca", help="mette una marca temporale (data certa) su uno o più file, senza firmarli",
        description="Mette una marca temporale su uno o più file, senza firmarli e senza codice OTP: prova che il "
                    "file esisteva a quella data. Formato TSD (predefinito): nome.estensione.tsd contiene file e "
                    "marca; formato TSR: nome.estensione.tsr contiene solo la marca, da conservare insieme al file.",
    )
    marca.add_argument("file", nargs="+", metavar="FILE", help="i file da marcare")
    marca.add_argument("--formato", choices=["tsd", "tsr"], default="tsd", help="tipo di file prodotto (predefinito: tsd)")
    marca.add_argument("--account", metavar="ALIAS", help="con quale account (se ce n'è più d'uno)")
    _add_output_option(marca, "accanto a ogni file")
    marca.set_defaults(handler=cmd_marca)

    verifica = commands.add_parser(
        "verifica", help="verifica la firma di un PDF o di un file .p7m, o una marca temporale (.tsd, .tsr)",
        description="Verifica le firme di un PDF firmato o di un file .p7m, e le marche temporali (anche .tsd e "
                    ".tsr), con l'elenco ufficiale dei certificatori.",
    )
    verifica.add_argument("file", metavar="FILE", help="il file firmato o marcato")
    verifica.add_argument("--originale", metavar="FILE",
                          help="per una marca .tsr: il documento a cui si riferisce (predefinito: lo stesso nome "
                               "senza .tsr, nella stessa cartella)")
    verifica.add_argument("--alla-data", type=_date_arg, metavar="GG/MM/AAAA",
                          help="valuta la firma com'era a quella data (per esempio prima della scadenza del certificato)")
    verifica.epilog = ("Codice di uscita: 0 firma valida, 5 firma non verificabile (per esempio senza rete), "
                       "1 firma non valida o errore.")
    verifica.set_defaults(handler=cmd_verifica)

    estrai = commands.add_parser(
        "estrai", help="estrae il documento originale da un file .p7m o .tsd",
        description="Estrae il documento originale da un file .p7m o da un documento marcato .tsd (anche annidati).",
    )
    estrai.add_argument("file", metavar="FILE", help="il file .p7m o .tsd")
    _add_output_option(estrai, "accanto al file")
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
    only.add_argument("--marca", choices=["si", "no"], help="mettere la marca temporale su tutto ciò che si firma? "
                                                              "(predefinito: si)")
    only.add_argument("--credenziali-marca", action="store_true",
                      help="salva l'account di marca temporale (TSA) comprato a parte: serve per marcare file senza "
                           "firmarli e per la busta .tsd (le firme usano la marca automatica di Aruba)")
    only.add_argument("--dimentica-credenziali-marca", action="store_true", help="rimuove l'account TSA salvato")
    configura.set_defaults(handler=cmd_configura)

    diagnostica = commands.add_parser(
        "diagnostica", help="controlla che tutto funzioni (utile per l'assistenza)",
        description="Controlla configurazione, portachiavi, collegamento ad Aruba e scadenza del certificato. "
                    "Non mostra mai la password.",
    )
    diagnostica.add_argument("--credenziali", action="store_true",
                             help="chiede anche ad Aruba di controllare la password salvata dell'account usato "
                                  "per ultimo, o di quello indicato con --account (senza codice OTP)")
    diagnostica.add_argument("--account", metavar="ALIAS", help="quale account controllare con --credenziali")
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
