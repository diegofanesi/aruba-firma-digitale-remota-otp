import logging
import os

import pytest
import requests

from firmaremota import logsetup
from firmaremota.arss.client import ArssClient, map_error
from firmaremota.errors import CredentialsError, NetworkError, OtpError, ServiceError, SessionExpired
from firmaremota.models import Account, AuthCtx, ResolvedStamp

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
