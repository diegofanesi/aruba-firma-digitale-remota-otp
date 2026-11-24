import logging
import os

import pytest
import requests

from firmaremota import logsetup
from firmaremota.arss.client import ArssClient, map_error
from firmaremota.errors import CredentialsError, NetworkError, OtpError, ServiceError, SessionExpired, TimestampError
from firmaremota.models import Account, AuthCtx, Kind, ResolvedStamp, TimestampType, TsaCredentials

from .conftest import asn1_cert
from .fakes import SESSION_ID, FakeTransport, fault, sign_error, sign_ok, soap

ACCOUNT = Account("mario.rossi", "firma", "NEW_2025:abc-AS0")
PASSWORD, OTP = "Pw-segreta-123", "12345678"


def client(responses):
    transport = FakeTransport(responses)
    return ArssClient(transport=transport), transport


def test_wsdl_is_bundled_and_ping_works():
    api, transport = client({"ping": soap("ping", "<return>pong</return>")})
    assert api.ping() == "pong"


def test_open_session_sends_otp_and_returns_id():
    api, transport = client({"opensession": soap("opensession", f"<return>{SESSION_ID}</return>")})
    assert api.open_session(AuthCtx(ACCOUNT, PASSWORD, OTP)) == SESSION_ID
    assert transport.field(0, "otpPwd") == OTP
    assert transport.field(0, "typeOtpAuth") == "firma"
    assert transport.field(0, "typeHSM") == "COSIGN"


def test_open_session_rejects_non_id_answers():
    api, _ = client({"opensession": soap("opensession", "<return>KO-0004 Otp Credential Invalid Or Blocked</return>")})
    with pytest.raises(OtpError):
        api.open_session(AuthCtx(ACCOUNT, PASSWORD, OTP))


def test_sign_in_session_sends_session_not_otp():
    pdf = b"%PDF-1.7 firmato"
    api, transport = client({"pdfsignatureV2": sign_ok("pdfsignatureV2", pdf)})
    stamp = ResolvedStamp(2, 359, 36, 559, 106)
    auth = AuthCtx(ACCOUNT, PASSWORD, OTP, session_id=SESSION_ID)
    assert api.sign_pdf(auth, b"%PDF-1.7", stamp, "Firmato digitalmente da Mario Rossi") == pdf
    assert transport.field(0, "session_id") == SESSION_ID
    assert transport.field(0, "otpPwd") is None
    assert transport.field(0, "certID") == "NEW_2025:abc-AS0"
    assert transport.field(0, "transport") == "BYNARYNET"
    assert transport.field(0, "requiredmark") == "false"
    assert transport.field(0, "pdfprofile") == "PADESBES"
    assert [transport.field(0, f) for f in ("page", "leftx", "lefty", "rightx", "righty")] == ["2", "359", "36", "559", "106"]
    assert transport.field(0, "testo") == "Firmato digitalmente da Mario Rossi"
    assert transport.field(0, "srcName") is None


def test_sign_cades_requests_attached_der():
    api, transport = client({"pkcs7signV2": sign_ok("pkcs7signV2", b"\x30\x80p7m")})
    assert api.sign_cades(AuthCtx(ACCOUNT, PASSWORD, session_id=SESSION_ID), b"dati") == b"\x30\x80p7m"
    assert transport.field(0, "detached") == "false"
    assert transport.field(0, "returnder") == "true"


TSA = TsaCredentials("mario.rossi", "Pw-tsa-456")


@pytest.mark.parametrize(("level", "profile", "cades_level"), [
    (TimestampType.T, "PADESBES", None), (TimestampType.LT, "PADESLTV", "LT"),
])
def test_sign_with_tsa_sends_requiredmark_identity_and_level(level, profile, cades_level):
    api, transport = client({"pdfsignatureV2": sign_ok("pdfsignatureV2", b"%PDF-1.7 x"),
                             "pkcs7signV2": sign_ok("pkcs7signV2", b"\x30\x80p7m")})
    auth = AuthCtx(ACCOUNT, PASSWORD, session_id=SESSION_ID, tsa=TSA, level=level)
    api.sign_pdf(auth, b"%PDF-1.7")
    assert transport.field(0, "requiredmark") == "true" and transport.field(0, "pdfprofile") == profile
    assert transport.field(0, "tsa_identity/user") == "mario.rossi" and transport.field(0, "tsa_identity/password") == "Pw-tsa-456"
    assert transport.field(0, "tsa_identity/tsaurl") is None and transport.field(0, "signatureLevel") is None
    api.sign_cades(auth, b"dati")
    assert transport.field(1, "requiredmark") == "true" and transport.field(1, "signatureLevel") == cades_level
    assert transport.field(1, "tsa_identity/user") == "mario.rossi"


def test_tsa_server_address_is_passed_through():
    api, transport = client({"pkcs7signV2": sign_ok("pkcs7signV2", b"\x30\x80p7m")})
    tsa = TsaCredentials("tsa-user", "pw", url="https://tsa.example/ts")
    api.sign_cades(AuthCtx(ACCOUNT, PASSWORD, session_id=SESSION_ID, tsa=tsa, level=TimestampType.T), b"dati")
    assert transport.field(0, "tsa_identity/tsaurl") == "https://tsa.example/ts"


def test_tsd_level_or_no_tsa_means_no_mark():
    api, transport = client({"pkcs7signV2": sign_ok("pkcs7signV2", b"\x30\x80p7m")})
    api.sign_cades(AuthCtx(ACCOUNT, PASSWORD, session_id=SESSION_ID, tsa=TSA, level=TimestampType.TSD), b"dati")
    api.sign_cades(AuthCtx(ACCOUNT, PASSWORD, session_id=SESSION_ID, level=TimestampType.T), b"dati")  # no account
    for index in (0, 1):
        assert transport.field(index, "requiredmark") == "false" and transport.field(index, "tsa_identity") is None


@pytest.mark.parametrize(("fmt", "operation"), [(Kind.TSD, "tsd"), (Kind.TSR, "tsr")])
def test_standalone_timestamp_request_shape(fmt, operation):
    api, transport = client({operation: sign_ok(operation, b"\x30\x82marca")})
    assert api.timestamp_file(TSA, b"dati", fmt) == b"\x30\x82marca"
    assert transport.field(0, "user") == "mario.rossi" and transport.field(0, "password") == "Pw-tsa-456"
    assert transport.field(0, "transport") == "BYNARYNET" and transport.field(0, "url") is None
    assert transport.field(0, "otpPwd") is None and transport.field(0, "certID") is None


@pytest.mark.parametrize(("code", "description", "message_part"), [
    ("0049", "Credenziali errate, controlla la username e la password", "credenziali TSA"),
    ("0074", "Hai esaurito le tue marche temporali", "sono finite"),
    ("0073", "The time stamp service is not reachable", "marca temporale"),
    ("93003", "credenziali TSA errate", "marca temporale"),
    ("0001", "TSA credential invalid", "marca temporale"),
    ("0001", "Impossibile richiedere il TimeStampToken", "marca temporale"),
    ("0001", "Marche temporali esaurite", "sono finite"),
])
def test_tsa_errors_map_to_timestamp_error(code, description, message_part):
    api, _ = client({"pkcs7signV2": sign_error("pkcs7signV2", code, description)})
    with pytest.raises(TimestampError) as exc:
        api.sign_cades(AuthCtx(ACCOUNT, PASSWORD, session_id=SESSION_ID, tsa=TSA, level=TimestampType.T), b"dati")
    assert message_part in exc.value.message and exc.value.exit_code == 1


def test_otp_error_still_wins_over_tsa_words():
    assert isinstance(map_error("0004", "Otp Credential Invalid Or Blocked (timestamp)"), OtpError)
    assert isinstance(map_error("0003", "Invalid user credentials"), CredentialsError)  # untouched by the TSA rules


def test_tsd_credential_error_is_about_the_tsa():
    """A wrong TSA password on a `tsd` call must not look like (or count as) a wrong signing password."""
    api, _ = client({"tsd": sign_error("tsd", "0003", "Invalid user credentials")})
    with pytest.raises(TimestampError):
        api.timestamp_file(TSA, b"dati", Kind.TSD)


def test_tsa_password_never_reaches_the_log(tmp_path):
    log_file = logsetup.setup(debug=True, directory=tmp_path / "logs")
    api, _ = client({"tsd": sign_error("tsd", "0049", f"bad {TSA.password}")})
    with pytest.raises(TimestampError) as exc:
        api.timestamp_file(TSA, b"dati", Kind.TSD)
    auth = AuthCtx(ACCOUNT, PASSWORD, session_id=SESSION_ID, tsa=TSA, level=TimestampType.T)
    logging.getLogger("firmaremota.test").warning("dettaglio: %s / %r", exc.value.detail, auth)
    for handler in logging.getLogger("firmaremota").handlers:
        handler.flush()
    assert TSA.password not in log_file.read_text() and TSA.password not in repr(auth)


def test_large_documents():
    """lxml refuses text nodes over 10 MB unless huge_tree is on: an ~11 MB base64 answer must work."""
    big = os.urandom(8 * 1024 * 1024)
    api, _ = client({"pkcs7signV2": sign_ok("pkcs7signV2", big)})
    assert api.sign_cades(AuthCtx(ACCOUNT, PASSWORD, session_id=SESSION_ID), b"x") == big


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (sign_error("pkcs7signV2", "0004", "Otp Credential Invalid Or Blocked"), OtpError),
        (sign_error("pkcs7signV2", "0030", "Domain Not Allowed"), CredentialsError),
        (sign_error("pkcs7signV2", "0003", "Invalid user credentials"), CredentialsError),
        (sign_error("pkcs7signV2", "0099", "Session not found"), SessionExpired),
        (sign_error("pkcs7signV2", "0001", "Errore generico"), ServiceError),
        (soap("pkcs7signV2", "<return><return_code>0000</return_code><status>OK</status></return>"), ServiceError),
        (fault("Internal error"), ServiceError),
        (requests.ConnectionError("down"), NetworkError),
        (requests.Timeout("slow"), NetworkError),
    ],
)
def test_errors_are_mapped(response, error):
    api, _ = client({"pkcs7signV2": response})
    with pytest.raises(error) as exc:
        api.sign_cades(AuthCtx(ACCOUNT, PASSWORD, session_id=SESSION_ID), b"dati")
    assert exc.value.message  # always an Italian message to show


def test_responses_with_a_doctype_are_refused():
    """No DTDs, no external entities: a response can't make the parser read files or call out."""
    evil = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
            + soap("ping", "<return>&x;</return>"))
    api, _ = client({"ping": evil})
    with pytest.raises(ServiceError, match="Risposta non valida"):
        api.ping()


def test_map_error_keeps_unknown_code():
    error = map_error("0042", "Something new")
    assert isinstance(error, ServiceError) and error.code == "0042" and "0042" in error.message


def test_list_certs(pki):
    import base64

    der = asn1_cert(pki["mario"][0]).dump()
    body = (f"<return><app1><id>NEW_2025:abc-AS0</id><value>{base64.b64encode(der).decode()}</value></app1>"
            "<description>OK</description><status>OK</status></return>")
    api, transport = client({"listCert": soap("listCert", body)})
    ((cert_id, signer),) = api.list_certs(ACCOUNT, PASSWORD)
    assert cert_id == "NEW_2025:abc-AS0" and signer.name == "Mario Rossi"
    assert transport.field(0, "otpPwd") is None


def test_secrets_never_reach_the_log(tmp_path):
    log_file = logsetup.setup(debug=True, directory=tmp_path / "logs")
    api, _ = client({
        "opensession": soap("opensession", f"<return>{SESSION_ID}</return>"),
        "pdfsignatureV2": sign_error("pdfsignatureV2", "0001", f"echo {PASSWORD} {OTP}"),
        "closesession": soap("closesession", "<return>OK</return>"),
    })
    session = api.open_session(AuthCtx(ACCOUNT, PASSWORD, OTP))
    auth = AuthCtx(ACCOUNT, PASSWORD, session_id=session)
    with pytest.raises(ServiceError) as exc:
        api.sign_pdf(auth, b"%PDF-1.7")
    logging.getLogger("firmaremota.test").warning("dettaglio: %s / %r", exc.value.detail, auth)
    api.close_session(auth, session)
    for handler in logging.getLogger("firmaremota").handlers:
        handler.flush()
    text = log_file.read_text()
    for secret in (PASSWORD, OTP, SESSION_ID):
        assert secret not in text
        assert secret not in repr(auth)
    assert not logging.getLogger("zeep.transports").isEnabledFor(logging.DEBUG)
