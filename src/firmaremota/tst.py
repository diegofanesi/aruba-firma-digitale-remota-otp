"""Standalone timestamps (marche temporali), in the two shapes ArubaSign's "Marca" produces.

  .tsd  RFC 5544 TimeStampedData: the file itself plus one or more timestamp tokens, in one
        envelope. ArubaSign also uses it around a signed .p7m (`documento.pdf.p7m.tsd`).
  .tsr  RFC 3161 TimeStampResp: just the token, saved next to the file it timestamps. The
        original file is needed to check it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from asn1crypto import cms, core, crl, tsp

from . import p7m
from .errors import FileError
from .models import SignerInfo

_GRANTED = ("granted", "granted_with_mods")


# RFC 5544 says the token is a TimeStampToken, i.e. a plain CMS ContentInfo. asn1crypto models it as an
# EncapsulatedContentInfo, which encodes differently and can't be built from a token, so the few
# structures involved are redeclared here.
class _TimeStampAndCRL(core.Sequence):
    _fields = [("time_stamp", cms.ContentInfo), ("crl", crl.CertificateList, {"optional": True})]


class _TokenEvidence(core.SequenceOf):
    _child_spec = _TimeStampAndCRL


class _Evidence(core.Choice):
    _alternatives = [
        ("tst_evidence", _TokenEvidence, {"implicit": 0}),
        ("ers_evidence", tsp.EvidenceRecord, {"implicit": 1}),
        ("other_evidence", tsp.OtherEvidence, {"implicit": 2}),
    ]


class TimeStampedData(core.Sequence):
    _fields = [
        ("version", tsp.Version),
        ("data_uri", core.IA5String, {"optional": True}),
        ("meta_data", tsp.MetaData, {"optional": True}),
        ("content", core.OctetString, {"optional": True}),
        ("temporal_evidence", _Evidence),
    ]


class _ContentInfo(core.Sequence):
    """A ContentInfo carrying our TimeStampedData (the content is only parsed when asked for)."""

    _fields = [("content_type", cms.ContentType), ("content", TimeStampedData, {"explicit": 0})]


@dataclass(frozen=True)
class Tsd:
    content: bytes
    tokens: list[cms.SignedData]


@dataclass(frozen=True)
class Unwrapped:
    content: bytes
    layers: list[list[SignerInfo]]  # signatures, outermost envelope first
    timestamps: int  # how many .tsd envelopes were peeled off


def _outer(data: bytes) -> _ContentInfo | None:
    try:
        info = _ContentInfo.load(p7m.decode(data))
        info["content_type"].native
        return info
    except Exception:  # noqa: BLE001 - FileError from decode, or asn1crypto's ValueError/TypeError: not a ContentInfo
        return None


def _token(info: cms.ContentInfo) -> cms.SignedData:
    if info["content_type"].native != "signed_data":
        raise FileError("La marca temporale non è leggibile.")
    signed = info["content"]
    p7m.parse_fields(signed)  # a full parse now (revocation data aside), so a damaged token fails here
    return signed


def is_tsd(data: bytes) -> bool:
    info = _outer(data)
    return info is not None and info["content_type"].native == "timestamped_data"


def parse_tsd(data: bytes) -> Tsd:
    info = _outer(data)
    if info is None or info["content_type"].native != "timestamped_data":
        raise FileError("Il file non è una busta .tsd (documento con marca temporale).")
    try:
        tsd = info["content"]
        content = tsd["content"].native
        evidence = tsd["temporal_evidence"]
        if evidence.name != "tst_evidence":
            raise FileError("Il file .tsd usa un tipo di prova temporale non supportato.")
        tokens = [_token(item["time_stamp"]) for item in evidence.chosen]
    except FileError:
        raise
    except Exception as exc:
        raise FileError("Il file .tsd è danneggiato.", detail=str(exc)) from None
    if content is None:
        raise FileError("Il file .tsd non contiene il documento: la marca è separata dal file.")
    if not tokens:
        raise FileError("Il file .tsd non contiene nessuna marca temporale.")
    return Tsd(content, tokens)


def build_tsd(content: bytes, tokens: list[cms.ContentInfo]) -> bytes:
    evidence = _Evidence(name="tst_evidence", value=_TokenEvidence([_TimeStampAndCRL({"time_stamp": t}) for t in tokens]))
    tsd = TimeStampedData({"version": "v1", "content": content, "temporal_evidence": evidence})
    return _ContentInfo({"content_type": "timestamped_data", "content": tsd}).dump()


def _response(data: bytes) -> tsp.TimeStampResp | None:
    try:
        response = tsp.TimeStampResp.load(p7m.decode(data))
        response["status"]["status"].native
        response["time_stamp_token"]["content_type"].native
        return response
    except Exception:  # noqa: BLE001 - not a TimeStampResp
        return None


def is_tsr(data: bytes) -> bool:
    return _response(data) is not None


def parse_tsr(data: bytes) -> cms.SignedData:
    response = _response(data)
    if response is None:
        raise FileError("Il file non è una marca temporale .tsr leggibile.")
    if response["status"]["status"].native not in _GRANTED:
        raise FileError("Il file .tsr è una risposta di rifiuto dell'autorità, non una marca temporale.")
    return _token(response["time_stamp_token"])


def build_tsr(token: cms.ContentInfo) -> bytes:
    return tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": token}).dump()


def original_for(path: Path) -> Path | None:
    """`documento.pdf` next to `documento.pdf.tsr`, if it is there."""
    path = Path(path)
    if not path.name.lower().endswith(".tsr"):
        return None
    candidate = path.with_name(path.name[:-4])
    return candidate if candidate.is_file() else None


def unwrap(data: bytes, max_depth: int = 10) -> Unwrapped:
    """The document inside any mix of .tsd envelopes and .p7m signatures, outermost first."""
    content, layers, timestamps = data, [], 0
    for _ in range(max_depth):
        if is_tsd(content):
            content = parse_tsd(content).content
            timestamps += 1
        elif p7m.is_p7m(content):
            signed = p7m.signed_data(content)
            layers.append(p7m.signers(signed))
            content = p7m.layer_content(signed)
        else:
            break
    return Unwrapped(content, layers, timestamps)
