"""Thin wrapper over the ARSS SOAP API (zeep on the bundled WSDL).

Conventions verified live (see docs/arss-notes.md): domain goes in `typeOtpAuth`, `certID` comes
from `listCert`, success is `status == "OK"`, coordinates are PDF points, sessions let you sign
with `session_id` and no OTP. Only the BYNARYNET transport is used (zeep can't send MTOM).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Protocol

import requests
from asn1crypto import x509
from zeep import Client, Settings
from zeep.exceptions import Error as ZeepError
from zeep.exceptions import Fault
from zeep.transports import Transport

from .. import p7m
from ..errors import (
    CredentialsError, FirmaError, NetworkError, OtpError, ServiceError, SessionExpired, TimestampError,
)
from ..logsetup import register_secret
from ..models import Account, AuthCtx, Kind, ResolvedStamp, SignerInfo, TimestampType, TsaCredentials

log = logging.getLogger("firmaremota.arss")

WSDL = Path(__file__).with_name("ArubaSignService.wsdl")
_NS = "{http://arubasignservice.arubapec.it/}"
_SESSION_ID = re.compile(r"[0-9a-fA-F-]{16,64}")

MSG_OTP = (
    "Codice OTP non accettato: è sbagliato, scaduto, oppure l'account è bloccato. "
    "Controlla che l'ora del telefono sia esatta e usa un codice nuovo."
)
MSG_CREDENTIALS = "Nome utente, dominio o password non accettati dal servizio di firma Aruba."
MSG_SESSION = "La sessione di firma è scaduta: serve un nuovo codice OTP."
MSG_NETWORK = "Il servizio di firma Aruba non risponde: controlla la connessione a Internet."
MSG_TSA = (
    "Il servizio di marca temporale non ha accettato la richiesta. Firma senza marca temporale, oppure "
    "controlla le credenziali TSA dell'account (o attiva la marca automatica nel SelfCare di Aruba: "
    "https://selfcare.firma-remota.it)."
)
MSG_TSA_EXHAUSTED = "Le marche temporali del tuo account sono finite: ricaricale su Aruba, oppure firma senza marca."
# ArubaSign's time-stamping error codes (unconfirmed for ARSS: the live test records what really comes back).
TSA_CODES = {"0049", "93001", "93003"} | {f"{n:04d}" for n in range(73, 86)}
TSA_EXHAUSTED_CODES = {"0074"}
TSA_WORDS = ("tsa", "marca", "marche", "timestamp", "time stamp", "time-stamp", "mark")
# When the request itself is about a timestamp (tsd/tsr), even a "credentials" answer is about the TSA account.


def map_error(code: str | None, description: str | None, *, tsa_scope: bool = False) -> FirmaError:
    """ARSS return code/description -> the error to show. Never retry on any of these."""
    desc = (description or "").lower()
    detail = f"{code}: {description}"
    if code in TSA_EXHAUSTED_CODES or "esaurit" in desc:
        return TimestampError(MSG_TSA_EXHAUSTED, detail=detail)
    if code in TSA_CODES:
        return TimestampError(MSG_TSA, detail=detail)
    if code == "0004" or "otp" in desc:
        return OtpError(MSG_OTP, detail=detail)
    if tsa_scope or any(word in desc for word in TSA_WORDS):
        return TimestampError(MSG_TSA, detail=detail)
    if code == "0030" or "domain" in desc or "dominio" in desc:
        return CredentialsError("Il dominio di firma non è accettato (di solito è 'firma').", detail=detail)
    if any(word in desc for word in ("password", "credential", "credenzial", "user", "utente", "login")):
        return CredentialsError(MSG_CREDENTIALS, detail=detail)
    if "session" in desc or "sessione" in desc:
        return SessionExpired(MSG_SESSION, detail=detail)
    return ServiceError(
        f"Il servizio di firma Aruba ha risposto con un errore (codice {code or '?'}).",
        code=code,
        detail=description,
    )


def check(response, *, tsa_scope: bool = False) -> None:
    status = getattr(response, "status", None)
    if status != "OK":
        raise map_error(getattr(response, "return_code", None), getattr(response, "description", None),
                        tsa_scope=tsa_scope)


class ArssApi(Protocol):
    def ping(self) -> str: ...
    def list_certs(self, account: Account, password: str) -> list[tuple[str, SignerInfo]]: ...
    def open_session(self, auth: AuthCtx) -> str: ...
    def close_session(self, auth: AuthCtx, session_id: str) -> None: ...
    def sign_pdf(self, auth: AuthCtx, pdf: bytes, stamp: ResolvedStamp | None = None, text: str = "",
                 image: bytes | None = None, show_date: bool = True) -> bytes: ...
    def sign_cades(self, auth: AuthCtx, data: bytes) -> bytes: ...
    def timestamp_file(self, tsa: TsaCredentials, data: bytes, fmt: Kind) -> bytes: ...


class ArssClient:
    def __init__(self, wsdl: Path = WSDL, transport: Transport | None = None):
        transport = transport or Transport(timeout=30, operation_timeout=180)
        # huge_tree: lxml would refuse the base64 of PDFs over ~7.5 MB. DTDs and external resources are
        # never part of ARSS responses, so they are refused (entities already are by default).
        settings = Settings(xml_huge_tree=True, forbid_dtd=True, forbid_external=True)
        self._client = Client(str(wsdl), settings=settings, transport=transport)

    def _type(self, name: str):
        return self._client.get_type(_NS + name)

    def _call(self, operation: str, **kwargs):
        log.debug("ARSS %s", operation)
        try:
            return getattr(self._client.service, operation)(**kwargs)
        except requests.RequestException as exc:  # connection, timeout, TLS, broken transfer...
            raise NetworkError(MSG_NETWORK, detail=str(exc)) from None
        except Fault as exc:
            raise map_error(None, exc.message) from None
        except ZeepError as exc:
            raise ServiceError("Risposta non valida dal servizio di firma Aruba.", detail=str(exc)) from None

    def _identity(self, account: Account, password: str, otp: str | None = None):
        register_secret(password, otp)
        return self._type("auth")(
            user=account.user, userPWD=password, typeHSM=account.type_hsm,
            typeOtpAuth=account.domain, otpPwd=otp,
        )

    def _tsa_identity(self, tsa: TsaCredentials):
        register_secret(tsa.password)
        return self._type("tsaAuth")(user=tsa.user, password=tsa.password, tsaurl=tsa.url)

    def _sign_request(self, auth: AuthCtx, data: bytes, *, cades: bool):
        """The common part of every signing call. A timestamp (`auth.level` T or LT) is requested with
        `requiredmark=true`; `tsa_identity` goes along only when the user has a TSA account of their own
        (Firma Remota's included marks are applied by Aruba's server with no TSA credentials: this is
        how Aruba's public example calls `pdfsignatureV2`). LT on a .p7m also asks for the matching
        `signatureLevel` (PDFs get it through `pdfprofile`). The mappings are confirmed by the live test."""
        register_secret(auth.session_id)
        otp = None if auth.session_id else auth.otp
        marked = auth.level in (TimestampType.T, TimestampType.LT)
        return self._type("signRequestV2")(
            certID=auth.account.cert_id,
            identity=self._identity(auth.account, auth.password, otp),
            requiredmark=marked,
            transport="BYNARYNET",
            binaryinput=data,
            session_id=auth.session_id,
            tsa_identity=self._tsa_identity(auth.tsa) if marked and auth.tsa is not None else None,
            signatureLevel="LT" if marked and cades and auth.level is TimestampType.LT else None,
        )

    @staticmethod
    def _output(response, *, tsa_scope: bool = False) -> bytes:
        check(response, tsa_scope=tsa_scope)
        data = getattr(response, "binaryoutput", None)
        if not data:
            raise ServiceError("Il servizio di firma Aruba ha risposto senza il documento firmato.")
        return data

    def ping(self) -> str:
        return self._call("ping")

    def list_certs(self, account: Account, password: str) -> list[tuple[str, SignerInfo]]:
        """(certID, certificate holder) for each signing certificate; needs no OTP."""
        response = self._call("listCert", Identity=self._identity(account, password))
        check(response)
        certs = []
        for group in ("app1", "app2"):
            for cert in getattr(response, group, None) or []:
                if cert is None or not (cert.id and cert.value):
                    continue
                try:
                    certs.append((cert.id, p7m.signer_from_cert(x509.Certificate.load(cert.value))))
                except Exception as exc:  # a certificate Aruba sent that we can't read: skip it
                    log.warning("certificato non leggibile da listCert: %s", exc)
        return certs

    def open_session(self, auth: AuthCtx) -> str:
        session_id = self._call("opensession", Identity=self._identity(auth.account, auth.password, auth.otp))
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id.strip()):
            code = re.search(r"\d{4}", session_id or "")
            raise map_error(code.group(0) if code else None, session_id)
        session_id = session_id.strip()
        register_secret(session_id)
        return session_id

    def close_session(self, auth: AuthCtx, session_id: str) -> None:
        result = self._call("closesession", Identity=self._identity(auth.account, auth.password), sessionid=session_id)
        if result != "OK":
            log.warning("closesession: risposta inattesa")

    def sign_pdf(self, auth: AuthCtx, pdf: bytes, stamp: ResolvedStamp | None = None, text: str = "",
                 image: bytes | None = None, show_date: bool = True) -> bytes:
        appearance = None
        if stamp is not None:
            appearance = self._type("pdfSignApparence")(
                page=stamp.page, leftx=stamp.llx, lefty=stamp.lly, rightx=stamp.urx, righty=stamp.ury,
                testo=text, bShowDateTime=show_date, imageBin=image,
            )
        response = self._call("pdfsignatureV2", SignRequestV2=self._sign_request(auth, pdf, cades=False),
                              Apparence=appearance,
                              pdfprofile="PADESLTV" if auth.level is TimestampType.LT else "PADESBES")
        return self._output(response)

    def sign_cades(self, auth: AuthCtx, data: bytes) -> bytes:
        response = self._call("pkcs7signV2", SignRequestV2=self._sign_request(auth, data, cades=True),
                              detached=False, returnder=True)
        return self._output(response)

    def timestamp_file(self, tsa: TsaCredentials, data: bytes, fmt: Kind) -> bytes:
        """A standalone timestamp on `data`: a .tsd envelope (file + token) or a bare .tsr token. No OTP."""
        register_secret(tsa.password)
        request = self._type("MarkRequest")(user=tsa.user, password=tsa.password, url=tsa.url,
                                            transport="BYNARYNET", binaryinput=data)
        response = self._call("tsd" if fmt is Kind.TSD else "tsr", MarkRequest=request)
        return self._output(response, tsa_scope=True)
