"""Reading CAdES .p7m envelopes: decoding, unwrapping nested signatures, signer details."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from asn1crypto import cms, x509

from .errors import FileError
from .models import SignerInfo

_P7M_SUFFIX = re.compile(r"(\.p7m)+$", re.IGNORECASE)
_PEM = re.compile(rb"-----BEGIN [A-Z0-9 ]+-----(.*?)-----END [A-Z0-9 ]+-----", re.DOTALL)
_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3"
_SNIFF = ((b"%PDF-", ".pdf"), (b"<?xml", ".xml"), (b"PK\x03\x04", ".zip"))


@dataclass(frozen=True)
class Unwrapped:
    content: bytes
    layers: list[list[SignerInfo]]  # outermost envelope first


def decode(data: bytes) -> bytes:
    """DER/BER bytes of an envelope saved as binary, PEM, or bare base64 (any line endings)."""
    stripped = data.strip()
    if stripped[:1] == b"\x30":
        return data
    pem = _PEM.search(stripped)
    payload = pem.group(1) if pem else stripped
    try:
        raw = base64.b64decode(b"".join(payload.split()), validate=True)
    except (binascii.Error, ValueError):
        raise FileError("Il file non è una busta firmata .p7m leggibile.") from None
    if raw[:1] != b"\x30":
        raise FileError("Il file non è una busta firmata .p7m leggibile.")
    return raw


def _signed_data(data: bytes) -> cms.SignedData:
    try:
        info = cms.ContentInfo.load(decode(data))
        if info["content_type"].native != "signed_data":
            raise FileError("Il file .p7m non contiene una firma digitale.")
        signed = info["content"]
        signed.native  # force a full parse now, so damaged files fail here and not later
        return signed
    except FileError:
        raise
    except Exception as exc:  # asn1crypto raises ValueError/TypeError on malformed input
        raise FileError("Il file .p7m è danneggiato o non è una busta firmata.", detail=str(exc)) from None


def is_p7m(data: bytes) -> bool:
    try:
        _signed_data(data)
        return True
    except FileError:
        return False


def unwrap(data: bytes, max_depth: int = 10) -> Unwrapped:
    """The original document inside one or more nested .p7m envelopes, plus who signed each layer."""
    layers: list[list[SignerInfo]] = []
    current = data
    while True:
        signed = _signed_data(current)
        layers.append(signers(signed))
        content = signed["encap_content_info"]["content"]
        if content.native is None:
            raise FileError("Firma separata: il documento originale non è incluso nel file .p7m.")
        current = content.native if isinstance(content.native, bytes) else content.contents
        if len(layers) >= max_depth or not is_p7m(current):
            return Unwrapped(current, layers)


def signers(signed: cms.SignedData) -> list[SignerInfo]:
    cert_set = signed["certificates"]
    certs = [c.chosen for c in cert_set if c.name == "certificate"] if isinstance(cert_set, cms.CertificateSet) else []
    return [_signer_info(si, certs) for si in signed["signer_infos"]]


def _find_cert(sid: cms.SignerIdentifier, certs: list[x509.Certificate]) -> x509.Certificate | None:
    for cert in certs:
        if sid.name == "issuer_and_serial_number":
            ref = sid.chosen
            if cert.issuer == ref["issuer"] and cert.serial_number == ref["serial_number"].native:
                return cert
        elif cert.key_identifier == sid.chosen.native:
            return cert
    return None


def _signer_info(si: cms.SignerInfo, certs: list[x509.Certificate]) -> SignerInfo:
    cert = _find_cert(si["sid"], certs)
    if cert is None:
        raise FileError("Il file .p7m non contiene il certificato del firmatario.")
    signing_time = None
    attrs = si["signed_attrs"]
    for attr in attrs if isinstance(attrs, cms.CMSAttributes) else []:
        if attr["type"].native == "signing_time":
            signing_time = attr["values"][0].native
    subject = cert.subject.native
    name = subject.get("common_name") or " ".join(
        p for p in (subject.get("given_name"), subject.get("surname")) if p
    ) or cert.subject.human_friendly
    serial = subject.get("serial_number")  # Italian certificates: "TINIT-<codice fiscale>"
    fiscal_code = serial.split("-", 1)[1] if serial and serial.upper().startswith("TINIT-") else None
    issuer = cert.issuer.native.get("common_name") or cert.issuer.human_friendly
    validity = cert["tbs_certificate"]["validity"]
    exts = cert["tbs_certificate"]["extensions"]
    qualified = isinstance(exts, x509.Extensions) and any(e["extn_id"].dotted == _QC_STATEMENTS for e in exts)
    return SignerInfo(
        name=name,
        fiscal_code=fiscal_code,
        serial=format(cert.serial_number, "X"),
        issuer=issuer,
        signing_time=signing_time,
        not_before=validity["not_before"].native,
        not_after=validity["not_after"].native,
        qualified=qualified,
    )


def inner_name(name: str, content: bytes) -> str:
    """'contratto.pdf.p7m' -> 'contratto.pdf'; 'fattura.p7m' with XML inside -> 'fattura.xml'."""
    base = _P7M_SUFFIX.sub("", name) or "documento"
    if "." in base.lstrip("."):
        return base
    for magic, ext in _SNIFF:
        if content.lstrip()[: len(magic)] == magic:
            return base + ext
    return base
