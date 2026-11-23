"""Command line: `firma <comando>`. All user-facing text is Italian."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__, files, logsetup, messages, p7m
from .errors import FirmaError

log = logging.getLogger("firmaremota.cli")

EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise FirmaError(f"Impossibile leggere {path}: {exc.strerror}") from exc


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


def build_parser() -> argparse.ArgumentParser:
    messages.italian_argparse()
    parser = argparse.ArgumentParser(
        prog="firma",
        description="Firma digitale remota Aruba: firma, verifica ed estrai documenti.",
    )
    parser.add_argument("--version", action="version", version=f"firma-remota {__version__}")
    parser.add_argument("--debug", action="store_true", help="scrive dettagli tecnici anche sul terminale")
    commands = parser.add_subparsers(dest="comando", title="comandi", metavar="COMANDO")

    estrai = commands.add_parser(
        "estrai",
        help="estrae il documento originale da un file .p7m",
        description="Estrae il documento originale da un file .p7m (anche con più firme annidate).",
    )
    estrai.add_argument("file", metavar="FILE", help="il file .p7m")
    estrai.add_argument("--cartella", metavar="CARTELLA", help="dove salvare il documento (predefinito: accanto al .p7m)")
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
