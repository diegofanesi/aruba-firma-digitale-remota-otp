from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # GUI tests never open real windows

import base64
import datetime as dt
from io import BytesIO
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID, ObjectIdentifier
from pypdf import PdfWriter
from pypdf.generic import RectangleObject

from firmaremota import logsetup, vault

FIXTURES = Path(__file__).parent / "fixtures"
# QCStatements with a single QcCompliance (0.4.0.1862.1.1) statement: marks a qualified certificate.
QC_STATEMENTS = bytes.fromhex("300a3008060604008e460101")


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    """Config, state and logs go to a temporary folder; nothing touches the real home."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setattr(logsetup, "_replacements", {})
    monkeypatch.setattr(vault, "SCRYPT_N", 2**10)  # fast key derivation in tests (production: 2**15)


def _name(cn: str, *extra: x509.NameAttribute) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"), *extra, x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@pytest.fixture(scope="session")
def pki():
    """A throwaway CA and two signers shaped like Italian qualified signature certificates."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = _name("CA di prova")
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=30)).not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    def leaf(given: str, surname: str, cf: str):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = _name(
            f"{given} {surname}",
            x509.NameAttribute(NameOID.GIVEN_NAME, given),
            x509.NameAttribute(NameOID.SURNAME, surname),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, f"TINIT-{cf}"),
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.5.5.7.1.3"), QC_STATEMENTS), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return cert, key

    return {"ca": ca, "mario": leaf("Mario", "Rossi", "RSSMRA80A01H501U"), "anna": leaf("Anna", "Bianchi", "BNCNNA75C41F205X")}


@pytest.fixture(scope="session")
def signer(pki):
    return pki["mario"]


@pytest.fixture
def make_p7m(signer):
    def make(content: bytes, *, detached: bool = False, encoding: str = "der", also=()) -> bytes:
        cert, key = signer
        options = [pkcs7.PKCS7Options.Binary]
        if detached:
            options.append(pkcs7.PKCS7Options.DetachedSignature)
        builder = pkcs7.PKCS7SignatureBuilder().set_data(content).add_signer(cert, key, hashes.SHA256())
        for other_cert, other_key in also:
            builder = builder.add_signer(other_cert, other_key, hashes.SHA256())
        der = builder.sign(serialization.Encoding.DER, options)
        if encoding == "der":
            return der
        if encoding == "pem":
            body = base64.encodebytes(der).decode()
            return f"-----BEGIN PKCS7-----\n{body}-----END PKCS7-----\n".encode()
        if encoding == "b64crlf":
            text = base64.b64encode(der).decode()
            return "\r\n".join(text[i : i + 64] for i in range(0, len(text), 64)).encode() + b"\r\n"
        raise ValueError(encoding)

    return make


@pytest.fixture
def make_pdf():
    """PDF with one page per (width, height, rotation, cropbox-or-None) tuple."""

    def make(*pages, password: str | None = None) -> bytes:
        writer = PdfWriter()
        for width, height, rotation, cropbox in pages:
            page = writer.add_blank_page(width, height)
            if rotation:
                page.rotate(rotation)
            if cropbox:
                page.cropbox = RectangleObject(cropbox)
        if password:
            writer.encrypt(password)
        buf = BytesIO()
        writer.write(buf)
        return buf.getvalue()

    return make


def asn1_cert(cert: x509.Certificate):
    from asn1crypto import x509 as asn1_x509

    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


@pytest.fixture
def sign_pdf(pki):
    """Sign a PDF locally with pyHanko, as Mario Rossi."""
    from asn1crypto import keys
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    cert, key = pki["mario"]
    pdf_signer = signers.SimpleSigner(
        signing_cert=asn1_cert(cert),
        signing_key=keys.PrivateKeyInfo.load(
            key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        ),
        cert_registry=SimpleCertificateStore.from_certs([asn1_cert(pki["ca"])]),
    )

    def sign(pdf: bytes) -> bytes:
        out = signers.sign_pdf(IncrementalPdfFileWriter(BytesIO(pdf)), signers.PdfSignatureMetadata(field_name="Firma1"),
                               signer=pdf_signer)
        return out.getvalue()

    return sign


PASSWORD = "pw-salvata"
PROFILE = vault.Profile("mario.rossi", "firma", "NEW_2025:abc-AS0", "Mario Rossi",
                        (dt.date.today() + dt.timedelta(days=400)).isoformat())


class MemoryStore:
    """Stand-in for KWallet / Secret Service."""

    name = "Portachiavi di prova"

    def __init__(self, data=None):
        self.data = dict(data or {})

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value

    def delete(self, key):
        self.data.pop(key, None)


@pytest.fixture
def configured(monkeypatch):
    """An encrypted profile for Mario Rossi, with its password saved in a fake wallet."""
    from firmaremota import credentials

    vault.save(PROFILE, PASSWORD)
    store = MemoryStore({credentials.PASSWORD_KEY: PASSWORD})
    monkeypatch.setattr(credentials, "get_store", lambda: store)
    return store
