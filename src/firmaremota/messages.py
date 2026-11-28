"""Italian text shared by the CLI and the GUI, and an Italian argparse."""

from __future__ import annotations

import argparse
import datetime as dt

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


def _date(value: dt.datetime) -> str:
    return f"{value.astimezone():%d/%m/%Y}"


def check_lines(check) -> list[str]:
    """Italian description of one SignatureCheck: verdict first, then details and problems."""
    s = check.signer
    lines = [VERDICT_TITLES[check.verdict]]
    who = s.name + (f" (codice fiscale {s.fiscal_code})" if s.fiscal_code else "")
    lines.append(f"Firmatario: {who}")
    if s.signing_time:
        lines.append(f"Firmato il: {s.signing_time.astimezone():%d/%m/%Y alle %H:%M}")
    if check.timestamp:
        lines.append(timestamp_line(check.timestamp))
    lines.append(f"Certificato emesso da {s.issuer}, valido fino al {_date(s.not_after)}")
    if check.valid_at and check.trusted and s.not_after < dt.datetime.now(dt.timezone.utc):
        lines.append(f"Il certificato è scaduto il {_date(s.not_after)}, ma la marca temporale prova che la firma "
                     f"esisteva già il {_date(check.valid_at)}, quando era valido: la firma vale.")
    if check.revoked_after_poe:
        lines.append("Il certificato è stato revocato dopo la marca temporale: la firma, fatta prima, vale.")
    if not check.intact:
        lines.append("Problema: il documento è stato modificato dopo la firma.")
    elif not check.valid:
        lines.append("Problema: la firma non corrisponde al certificato del firmatario.")
    if check.revoked:
        lines.append("Problema: il certificato del firmatario è stato revocato.")
    elif not check.trust_checked:
        lines.append("Non verificabile: l'elenco ufficiale dei certificatori non è disponibile, quindi non si "
                     "può sapere se il certificato è di un certificatore riconosciuto.")
    elif not check.trusted and check.unknown_issuer:
        lines.append(f"Il documento non è stato modificato dopo la firma, ma il certificato è stato emesso da "
                     f"«{s.issuer}», che non fa capo a nessun certificatore dell'elenco ufficiale europeo: non "
                     "è una firma digitale qualificata e non si può confermare chi ha firmato. Può essere il "
                     "certificato interno di un ente (per esempio il sigillo di un portale pubblico).")
        if s.not_after < dt.datetime.now(dt.timezone.utc):
            lines.append(f"Il certificato è inoltre scaduto il {_date(s.not_after)}.")
    elif not check.trusted:
        if s.not_after < dt.datetime.now(dt.timezone.utc):
            lines.append(f"Problema: il certificato del firmatario è scaduto il {_date(s.not_after)}.")
        else:
            lines.append("Problema: il certificato del firmatario non supera i controlli dell'elenco ufficiale "
                         "(non valido per firmare, o non valido un certificato della sua catena).")
    if not check.covers_document:
        lines.append("Problema: il PDF è stato modificato dopo questa firma in modo non consentito.")
    if check.trust_checked and check.trusted and not check.revocation_checked:
        lines.append("Non verificabile: non è stato possibile controllare se il certificato è stato revocato "
                     "(sei offline, o il servizio del certificatore non risponde). Riprova più tardi: "
                     "finché il controllo non riesce, la firma non va considerata valida.")
    if check.qualified is True:
        lines.append("Tipo: firma elettronica qualificata (firma digitale).")
    elif check.qualified is False:
        lines.append("Tipo: firma elettronica NON qualificata.")
    return lines


VERDICT_TITLES = {
    "valida": "FIRMA VALIDA",
    "non valida": "FIRMA NON VALIDA",
    "non verificabile": "FIRMA NON VERIFICABILE",
}
TIMESTAMP_TITLES = {
    "valida": "MARCA TEMPORALE VALIDA",
    "non valida": "MARCA TEMPORALE NON VALIDA",
    "non verificabile": "MARCA TEMPORALE NON VERIFICABILE",
}
def verdict_title(report) -> str:
    """The report's headline: about the signature(s), or about the timestamp(s) when that is all there is
    (a .tsd around a .p7m is still, first of all, a signed document)."""
    return (TIMESTAMP_TITLES if not report.checks else VERDICT_TITLES)[report.verdict]


def timestamp_line(info, label: str = "Marca temporale") -> str:
    """One line about a timestamp: when, who issued it, and whether it counts."""
    line = f"{label}: {info.time.astimezone():%d/%m/%Y alle %H:%M} ({info.authority})"
    if not (info.intact and info.valid):
        return line + " — NON VALIDA: non corrisponde ai dati a cui è associata."
    if not info.trust_checked:
        return line + " — non verificabile: elenco dei certificatori non disponibile."
    if not info.trusted and info.unknown_issuer:
        return line + " — NON riconosciuta: l'autorità non è nell'elenco ufficiale, non vale come riferimento temporale."
    if not info.trusted:
        return line + " — NON VALIDA: il certificato dell'autorità non supera i controlli dell'elenco ufficiale."
    if info.qualified is True:
        line += " — qualificata"
    elif info.qualified is False:
        line += " — non qualificata"
    if not info.revocation_checked:
        line += " (revoca dell'autorità non verificata)"
    return line


def timestamp_lines(report) -> list[str]:
    """Document-level timestamps (PDF document timestamps, .tsd/.tsr tokens)."""
    return [timestamp_line(t, "Marca temporale sul documento") for t in report.timestamps]


def trust_list_line(report) -> str:
    prefix = f"Verifica alla data del {_date(report.at)}. " if report.at else ""
    if report.trust_list_date is None:
        return prefix + "Elenco ufficiale dei certificatori non disponibile: l'attendibilità non è stata verificata."
    when = f"{report.trust_list_date.astimezone():%d/%m/%Y}"
    if report.trust_list_stale:
        return prefix + f"Verifica fatta con l'elenco ufficiale dei certificatori del {when} (non è stato possibile aggiornarlo)."
    return prefix + f"Verifica fatta con l'elenco ufficiale dei certificatori (AgID) aggiornato al {when}."


TIMESTAMP_SOURCES = {  # how each choice of the account setting is called, everywhere
    "no": "nessuna marca temporale",
    "aruba": "marca temporale di Aruba",
    "belgio": "marca temporale gratuita (servizio pubblico belga, qualificato; solo uso non commerciale)",
}


def no_free_timestamp(count: int) -> str:
    """After a signing where the free timestamp service failed: what happened, and that the signature holds."""
    what = "il documento è stato firmato" if count == 1 else f"{count} documenti sono stati firmati"
    return (f"Il servizio gratuito di marca temporale non ha risposto (3 tentativi): {what} senza marca "
            "temporale. La firma digitale è valida comunque.")
