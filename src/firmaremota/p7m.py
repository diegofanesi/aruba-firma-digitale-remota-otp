"""Reading CAdES .p7m envelopes: decoding, unwrapping nested signatures, signer details."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator
from dataclasses import dataclass

from asn1crypto import cms, x509

from .errors import FileError
from .models import SignerInfo

# What an envelope's checks rely on, parsed in full when it is read so a damaged file fails then and not
# later. The revocation data (`crls`) is left out: optional and not covered by the signature. Aruba's
# envelopes with its own timestamp carry OCSP responses there as "other" revocation info (id-pkix-ocsp-basic,
# the form ETSI's CAdES uses), which asn1crypto doesn't know and can't parse; an envelope must not be
# "damaged" because of it (2026-11-27: every .p7m of an account with Aruba's automatic timestamp was refused).
_PARSED_FIELDS = ("version", "digest_algorithms", "encap_content_info", "certificates", "signer_infos")


def parse_fields(signed: cms.SignedData) -> None:
    """Parse everything in `signed` except its revocation data; raises asn1crypto's errors."""
    for field in _PARSED_FIELDS:
        signed[field].native


_P7M_SUFFIX = re.compile(r"(\.(p7m|tsd))+$", re.IGNORECASE)  # envelopes a document may be wrapped in
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


def signed_data(data: bytes) -> cms.SignedData:
    try:
        info = cms.ContentInfo.load(decode(data))
        if info["content_type"].native != "signed_data":
            raise FileError("Il file .p7m non contiene una firma digitale.")
        signed = info["content"]
        parse_fields(signed)
        return signed
    except FileError:
        raise
    except Exception as exc:  # asn1crypto raises ValueError/TypeError on malformed input
        raise FileError("Il file .p7m è danneggiato o non è una busta firmata.", detail=str(exc)) from None


def is_p7m(data: bytes) -> bool:
    try:
        signed_data(data)
        return True
    except FileError:
        return False


def layer_content(signed: cms.SignedData) -> bytes:
    """The bytes an envelope signs (an attached signature; detached ones are refused)."""
    content = signed["encap_content_info"]["content"]
    if content.native is None:
        raise FileError("Firma separata: il documento originale non è incluso nel file .p7m.")
    return content.native if isinstance(content.native, bytes) else content.contents


def iter_layers(data: bytes, max_depth: int = 10) -> Iterator[tuple[cms.SignedData, bytes]]:
    """(envelope, the bytes it signs) for each nested .p7m layer, outermost first."""
    current = data
    for _ in range(max_depth):
        signed = signed_data(current)
        current = layer_content(signed)
        yield signed, current
        if not is_p7m(current):
            return


def unwrap(data: bytes, max_depth: int = 10) -> Unwrapped:
    """The original document inside one or more nested .p7m envelopes, plus who signed each layer."""
    layers: list[list[SignerInfo]] = []
    content = data
    for signed, content in iter_layers(data, max_depth):
        layers.append(signers(signed))
    return Unwrapped(content, layers)


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
    return signer_from_cert(cert, signing_time(si))


def signing_time(si: cms.SignerInfo):
    attrs = si["signed_attrs"]
    for attr in attrs if isinstance(attrs, cms.CMSAttributes) else []:
        if attr["type"].native == "signing_time":
            return attr["values"][0].native
    return None


def has_signature_tst(si: cms.SignerInfo) -> bool:
    """Does this signer info carry an RFC 3161 signature timestamp (unsigned attribute)?"""
    attrs = si["unsigned_attrs"]
    return any(attr["type"].native == "signature_time_stamp_token"
               for attr in (attrs if isinstance(attrs, cms.CMSAttributes) else []))


def common_name(cert: x509.Certificate) -> str:
    return _attribute(cert.subject, "common_name") or cert.subject.human_friendly


def _attribute(name: x509.Name, key: str) -> str | None:
    """One value of a name attribute; asn1crypto gives a list when the attribute appears twice."""
    value = name.native.get(key)
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value) if value else None


def signer_from_cert(cert: x509.Certificate, signed_at=None) -> SignerInfo:
    subject = cert.subject
    name = _attribute(subject, "common_name") or " ".join(
        p for p in (_attribute(subject, "given_name"), _attribute(subject, "surname")) if p
    ) or subject.human_friendly
    serial = _attribute(subject, "serial_number")  # Italian certificates: "TINIT-<codice fiscale>"
    fiscal_code = serial.split("-", 1)[1] if serial and serial.upper().startswith("TINIT-") else None
    issuer = _attribute(cert.issuer, "common_name") or cert.issuer.human_friendly
    validity = cert["tbs_certificate"]["validity"]
    exts = cert["tbs_certificate"]["extensions"]
    qualified = isinstance(exts, x509.Extensions) and any(e["extn_id"].dotted == _QC_STATEMENTS for e in exts)
    return SignerInfo(
        name=name,
        fiscal_code=fiscal_code,
        serial=format(cert.serial_number, "X"),
        issuer=issuer,
        signing_time=signed_at,
        not_before=validity["not_before"].native,
        not_after=validity["not_after"].native,
        qualified=qualified,
    )


def inner_name(name: str, content: bytes) -> str:
    """'contratto.pdf.p7m' -> 'contratto.pdf'; 'fattura.p7m' with XML inside -> 'fattura.xml'; also strips '.tsd'."""
    base = _P7M_SUFFIX.sub("", name) or "documento"
    if "." in base.lstrip("."):
        return base
    for magic, ext in _SNIFF:
        if content.lstrip()[: len(magic)] == magic:
            return base + ext
    return base
