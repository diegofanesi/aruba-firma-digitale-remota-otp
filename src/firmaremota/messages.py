"""Italian text shared by the CLI and the GUI, and an Italian argparse."""

from __future__ import annotations

import argparse

# argparse (Python 3.12–3.14) marks its own strings with gettext; these are the ones a user can see.
_ARGPARSE_IT = {
    "usage: ": "uso: ",
    "positional arguments": "argomenti",
    "options": "opzioni",
    "subcommands": "comandi",
    "%(heading)s:": "%(heading)s:",
    "show this help message and exit": "mostra questo aiuto ed esce",
    "show program's version number and exit": "mostra la versione ed esce",
    " (default: %(default)s)": " (predefinito: %(default)s)",
    "%(prog)s: error: %(message)s\n": "%(prog)s: errore: %(message)s\n",
    "%(prog)s: warning: %(message)s\n": "%(prog)s: avviso: %(message)s\n",
    "the following arguments are required: %s": "mancano questi argomenti obbligatori: %s",
    "unrecognized arguments: %s": "argomenti non riconosciuti: %s",
    "invalid choice: %(value)r (choose from %(choices)s)": "scelta non valida: %(value)r (valori ammessi: %(choices)s)",
    "argument %(argument_name)s: %(message)s": "argomento %(argument_name)s: %(message)s",
    "invalid %(type)s value: %(value)r": "valore non valido: %(value)r",
    "expected one argument": "serve un valore",
    "expected at least one argument": "serve almeno un valore",
    "expected at most one argument": "è ammesso al massimo un valore",
    "expected %s argument": "servono %s valori",
    "expected %s arguments": "servono %s valori",
    "ambiguous option: %(option)s could match %(matches)s": "opzione ambigua: %(option)s può essere %(matches)s",
    "not allowed with argument %s": "non si può usare insieme a %s",
    "one of the arguments %s is required": "serve uno di questi argomenti: %s",
    "ignored explicit argument %r": "valore ignorato: %r",
    "can't open '%(filename)s': %(error)s": "impossibile aprire '%(filename)s': %(error)s",
    "unexpected option string: %s": "opzione inattesa: %s",
    "option '%(option)s' is deprecated": "l'opzione '%(option)s' è deprecata",
    "argument '%(argument_name)s' is deprecated": "l'argomento '%(argument_name)s' è deprecato",
    "command '%(parser_name)s' is deprecated": "il comando '%(parser_name)s' è deprecato",
    "unknown parser %(parser_name)r (choices: %(choices)s)": "comando sconosciuto %(parser_name)r (valori ammessi: %(choices)s)",
}


def _gettext(message: str) -> str:
    return _ARGPARSE_IT.get(message, message)


def _ngettext(singular: str, plural: str, n: int) -> str:
    return _gettext(singular if n == 1 else plural)


def italian_argparse() -> None:
    """Make argparse print its built-in texts (usage, errors, help headings) in Italian."""
    argparse._ = _gettext
    argparse.ngettext = _ngettext


def signers_line(signers) -> str:
    """'Mario Rossi (12/03/2026 10:15)' style summary of a list of SignerInfo."""
    parts = []
    for s in signers:
        when = f" ({s.signing_time.astimezone():%d/%m/%Y %H:%M})" if s.signing_time else ""
        parts.append(f"{s.name}{when}")
    return ", ".join(parts) or "nessun firmatario trovato"
