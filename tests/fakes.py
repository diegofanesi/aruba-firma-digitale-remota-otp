"""Stand-ins for the Aruba service: a fake API for the service layer, a fake SOAP transport for the client."""

from __future__ import annotations

import base64

import requests
from lxml import etree
from zeep.transports import Transport

from firmaremota.models import SignerInfo

SESSION_ID = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
_ENV = "http://schemas.xmlsoap.org/soap/envelope/"


class FakeArss:
    """Records every call; `fail_at` maps a sign-call number (0-based) to the error to raise."""

    def __init__(self, make_p7m=None, open_error=None, fail_at=None, certs=None):
        self.make_p7m = make_p7m
        self.open_error = open_error
        self.fail_at = fail_at or {}
        self.certs = certs or []
        self.calls: list[tuple] = []
        self._signs = 0

    def _sign_call(self):
        error = self.fail_at.get(self._signs)
        self._signs += 1
        if error:
            raise error

    def ping(self):
        return "pong"

    def list_certs(self, account, password):
        self.calls.append(("list_certs", password))
        if isinstance(self.certs, Exception):
            raise self.certs
        return self.certs

    def open_session(self, auth):
        self.calls.append(("open_session", auth.otp))
        if self.open_error:
            raise self.open_error
        return SESSION_ID

    def close_session(self, auth, session_id):
        self.calls.append(("close_session", session_id))

    def sign_pdf(self, auth, pdf, stamp=None, text="", image=None, show_date=True):
        self.calls.append(("sign_pdf", auth.otp, auth.session_id, stamp, text))
        self._sign_call()
        return pdf + b"\n% firmato\n"

    def sign_cades(self, auth, data):
        self.calls.append(("sign_cades", auth.otp, auth.session_id))
        self._sign_call()
        return self.make_p7m(data)

    def names(self):
        return [c[0] for c in self.calls]


def signer_info(name="Mario Rossi") -> SignerInfo:
    import datetime as dt

    now = dt.datetime.now(dt.timezone.utc)
    return SignerInfo(name, None, "1", "CA di prova", None, now, now, True)


def soap(operation: str, inner: str) -> bytes:
    return (
        f'<S:Envelope xmlns:S="{_ENV}"><S:Body>'
        f'<ns2:{operation}Response xmlns:ns2="http://arubasignservice.arubapec.it/">{inner}</ns2:{operation}Response>'
        f"</S:Body></S:Envelope>"
    ).encode()


def sign_ok(operation: str, output: bytes) -> bytes:
    b64 = base64.b64encode(output).decode()
    return soap(operation, f"<return><binaryoutput>{b64}</binaryoutput><return_code>0000</return_code><status>OK</status></return>")


def sign_error(operation: str, code: str, description: str) -> bytes:
    return soap(operation, f"<return><description>{description}</description><return_code>{code}</return_code><status>KO</status></return>")


def fault(message: str) -> bytes:
    return (
        f'<S:Envelope xmlns:S="{_ENV}"><S:Body><S:Fault><faultcode>S:Server</faultcode>'
        f"<faultstring>{message}</faultstring></S:Fault></S:Body></S:Envelope>"
    ).encode()


class FakeTransport(Transport):
    """Answers SOAP calls from a {operation: response bytes | exception} table; never touches the network."""

    def __init__(self, responses: dict):
        super().__init__()
        self.responses = responses
        self.sent: list[etree._Element] = []

    def load(self, url):
        if str(url).startswith(("http://", "https://")):
            raise AssertionError(f"network access attempted: {url}")
        return super().load(url)  # zeep reads local files through the transport too

    def post_xml(self, address, envelope, headers):
        self.sent.append(envelope)
        operation = etree.QName(envelope.find(f"{{{_ENV}}}Body")[0]).localname
        answer = self.responses[operation]
        if isinstance(answer, Exception):
            raise answer
        response = requests.Response()
        response.status_code = 500 if b"<S:Fault>" in answer else 200
        response._content = answer
        response.headers["Content-Type"] = "text/xml; charset=utf-8"
        response.encoding = "utf-8"
        return response

    def field(self, index: int, name: str) -> str | None:
        """Text of the first <name> element in the index-th request sent."""
        found = self.sent[index].find(f".//{name}")
        return None if found is None else found.text
