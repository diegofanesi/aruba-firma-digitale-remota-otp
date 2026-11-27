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

from firmaremota import credentials, logsetup

FIXTURES = Path(__file__).parent / "fixtures"


def pytest_configure(config):
    """Sandbox the whole run: HOME and the XDG folders point to a temporary directory and are never
    restored during the session, so nothing (not even a stray background thread finishing after its
    test) can write to the real home. Per-test folders are set on top of this by `isolated_dirs`."""
    import tempfile

    sandbox = Path(tempfile.mkdtemp(prefix="firma-remota-test-"))
    os.environ["FIRMA_REAL_HOME"] = os.environ.get("HOME", "")
    os.environ["HOME"] = str(sandbox)
    for name in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        os.environ[name] = str(sandbox / name.lower())
# QCStatements with a single QcCompliance (0.4.0.1862.1.1) statement: marks a qualified certificate.
QC_STATEMENTS = bytes.fromhex("300a3008060604008e460101")
# When the test time-stamping authority says things happened: in the past, inside every test
# certificate's validity except the deliberately expired one's end.
TS_TIME = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=20)).replace(microsecond=0)


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    """Config, state and logs go to a temporary folder; nothing touches the real home."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setattr(logsetup, "_replacements", {})


@pytest.fixture(autouse=True)
def no_real_wallet(monkeypatch):
    """Tests never touch the real KWallet / GNOME Keyring: no store unless a test provides one."""
    import keyring
    from keyring.backends import fail

    previous = keyring.get_keyring()
    keyring.set_keyring(fail.Keyring())
    monkeypatch.setattr(credentials.KWalletStore, "available", lambda self: False)
    yield
    keyring.set_keyring(previous)


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

    def leaf(given: str, surname: str, cf: str, *, not_before=now - dt.timedelta(days=1),
             not_after=now + dt.timedelta(days=365)):
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
            .not_valid_before(not_before).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.5.5.7.1.3"), QC_STATEMENTS), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return cert, key

    def tsa(cn: str, issuer_name=ca_name, issuer_key=ca_key):
        """A time-stamping unit: RFC 3161 wants the timeStamping extended key usage, critical."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(issuer_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=30)).not_valid_after(now + dt.timedelta(days=3000))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
            .sign(issuer_key, hashes.SHA256())
        )
        return cert, key

    return {
        "ca": ca, "ca_key": ca_key,
        "mario": leaf("Mario", "Rossi", "RSSMRA80A01H501U"),
        "anna": leaf("Anna", "Bianchi", "BNCNNA75C41F205X"),
        # certificate expired yesterday, but in force at TS_TIME: valid only thanks to a timestamp
        "scaduto": leaf("Carlo", "Verdi", "VRDCRL70A01H501Z", not_before=now - dt.timedelta(days=400),
                        not_after=now - dt.timedelta(days=1)),
        "tsa": tsa("TSA di prova"),
        "make_tsa": tsa,
    }


@pytest.fixture(scope="session")
def signer(pki):
    return pki["mario"]


@pytest.fixture
def make_p7m(pki):
    def make(content: bytes, *, detached: bool = False, encoding: str = "der", also=(), who: str = "mario") -> bytes:
        cert, key = pki[who]
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


def asn1_key(key):
    from asn1crypto import keys

    return keys.PrivateKeyInfo.load(
        key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )


def simple_signer(pki, who: str):
    """A pyHanko signer for one of the test people, with the CA certificate alongside."""
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    cert, key = pki[who]
    return signers.SimpleSigner(signing_cert=asn1_cert(cert), signing_key=asn1_key(key),
                                cert_registry=SimpleCertificateStore.from_certs([asn1_cert(pki["ca"])]))


def dummy_timestamper(pki, cert_key, when=TS_TIME):
    """A TSA that signs any request itself, always saying it is `when`."""
    from pyhanko.sign.timestamps import DummyTimeStamper
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    cert, key = cert_key
    return DummyTimeStamper(asn1_cert(cert), asn1_key(key), fixed_dt=when,
                            certs_to_embed=SimpleCertificateStore.from_certs([asn1_cert(pki["ca"])]))


@pytest.fixture(scope="session")
def timestamper(pki):
    return dummy_timestamper(pki, pki["tsa"])


@pytest.fixture
def sign_pdf(pki, timestamper):
    """Sign a PDF locally with pyHanko (default: as Mario Rossi), optionally with a signature timestamp
    (PAdES-T style) and/or a document timestamp added afterwards (what an LTA update looks like)."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko.sign.signers.pdf_signer import PdfTimeStamper

    def sign(pdf: bytes, *, timestamp: bool = False, doc_timestamp: bool = False, who: str = "mario",
             field_name: str = "Firma1", stamper=None) -> bytes:
        stamper = stamper or timestamper
        out = signers.sign_pdf(IncrementalPdfFileWriter(BytesIO(pdf)), signers.PdfSignatureMetadata(field_name=field_name),
                               signer=simple_signer(pki, who), timestamper=stamper if timestamp else None)
        data = out.getvalue()
        if doc_timestamp:
            out = PdfTimeStamper(stamper).timestamp_pdf(IncrementalPdfFileWriter(BytesIO(data)), "sha256")
            data = out.getvalue()
        return data

    return sign


OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1"  # id-pkix-ocsp-basic


def with_ocsp_in_crls(envelope: bytes) -> bytes:
    """`envelope` (a .p7m or a timestamp token, DER) with an OCSP response in its revocation data, the way
    Aruba's envelopes with its own timestamp carry them: "other" revocation info, id-pkix-ocsp-basic, a
    BasicOCSPResponse. asn1crypto doesn't know that identifier and can't parse the entry; the signature
    doesn't cover it, so the envelope stays valid."""
    from asn1crypto import cms, core, ocsp

    basic = ocsp.BasicOCSPResponse({
        "tbs_response_data": {
            "responder_id": ocsp.ResponderId(name="by_key", value=b"\x01" * 20),
            "produced_at": TS_TIME,
            "responses": [{
                "cert_id": {"hash_algorithm": {"algorithm": "sha1"}, "issuer_name_hash": b"\x00" * 20,
                            "issuer_key_hash": b"\x00" * 20, "serial_number": 1},
                "cert_status": ocsp.CertStatus(name="good", value=core.Null()),
                "this_update": TS_TIME,
            }],
        },
        "signature_algorithm": {"algorithm": "sha256_rsa"},
        "signature": b"\x00" * 256,
    })
    info = cms.ContentInfo.load(envelope)
    info["content"]["crls"] = cms.RevocationInfoChoices([cms.RevocationInfoChoice(
        name="other", value={"other_rev_info_format": OCSP_BASIC, "other_rev_info": core.Any.load(basic.dump())})])
    return info.dump()


@pytest.fixture
def make_token(timestamper):
    """An RFC 3161 timestamp token (ContentInfo) over `content`, from the test TSA."""
    import asyncio
    import hashlib

    def make(content: bytes, *, stamper=None):
        return asyncio.run((stamper or timestamper).async_timestamp(hashlib.sha256(content).digest(), "sha256"))

    return make


@pytest.fixture
def make_tsd(make_token):
    from firmaremota import tst

    def make(content: bytes, *, stamper=None) -> bytes:
        return tst.build_tsd(content, [make_token(content, stamper=stamper)])

    return make


@pytest.fixture
def make_tsr(make_token):
    from firmaremota import tst

    def make(content: bytes, *, stamper=None) -> bytes:
        return tst.build_tsr(make_token(content, stamper=stamper))

    return make


@pytest.fixture
def make_cades_t(pki, timestamper):
    """A .p7m whose signature carries an RFC 3161 timestamp token (CAdES-T)."""
    import asyncio

    def make(content: bytes, *, who: str = "mario", stamper=None) -> bytes:
        info = asyncio.run(simple_signer(pki, who).async_sign_general_data(
            content, "sha256", detached=False, use_cades=True, timestamper=stamper or timestamper))
        return info.dump()

    return make


PASSWORD = "pw-salvata"
PROFILE_ID = "a1b2c3d4e5f60718"


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


def add_profile(store, alias, login, password=None, id=None, timestamp=False):
    """Put an account into a fake wallet the way the app lays it out; returns the Profile.

    `timestamp`: a TimestampSource, or True for Aruba / False for none (the older layout)."""
    import json

    from firmaremota import credentials, profiles

    user, domain = credentials.split_login(login)
    source = profiles.timestamp_source(timestamp)
    profile = profiles.Profile(id or f"{abs(hash(alias)) % 10**16:016x}", alias, user, domain, source)
    index = json.loads(store.data.get(profiles.INDEX_KEY, "[]"))
    index.append({"id": profile.id, "alias": profile.alias, "login": profile.login, "marca": source.value})
    store.data[profiles.INDEX_KEY] = json.dumps(index)
    if password is not None:
        store.data[profile.password_key] = password
    return profile


@pytest.fixture
def configured(monkeypatch):
    """One account, "Mario" (mario.rossi@firma), with its password, in a fake wallet."""
    from firmaremota import credentials

    store = MemoryStore()
    add_profile(store, "Mario", "mario.rossi@firma", PASSWORD, id=PROFILE_ID)
    monkeypatch.setattr(credentials, "get_store", lambda: store)
    return store
