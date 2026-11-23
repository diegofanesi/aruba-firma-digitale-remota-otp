from __future__ import annotations

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

from firmaremota import logsetup

FIXTURES = Path(__file__).parent / "fixtures"
# QCStatements with a single QcCompliance (0.4.0.1862.1.1) statement: marks a qualified certificate.
QC_STATEMENTS = bytes.fromhex("300a3008060604008e460101")


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    """Config, state and logs go to a temporary folder; nothing touches the real home."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(logsetup, "_secrets", set())


@pytest.fixture(scope="session")
def signer():
    """Throwaway key and certificate shaped like an Italian qualified signature certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.GIVEN_NAME, "Mario"),
        x509.NameAttribute(NameOID.SURNAME, "Rossi"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "TINIT-RSSMRA80A01H501U"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mario Rossi"),
    ])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA di prova")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.5.5.7.1.3"), QC_STATEMENTS), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


@pytest.fixture
def make_p7m(signer):
    def make(content: bytes, *, detached: bool = False, encoding: str = "der") -> bytes:
        cert, key = signer
        options = [pkcs7.PKCS7Options.Binary]
        if detached:
            options.append(pkcs7.PKCS7Options.DetachedSignature)
        der = pkcs7.PKCS7SignatureBuilder().set_data(content).add_signer(cert, key, hashes.SHA256()).sign(
            serialization.Encoding.DER, options
        )
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
