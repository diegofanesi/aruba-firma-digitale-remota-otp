#!/usr/bin/env python3
"""Phase 0 live probe of Aruba ARSS (Aruba Remote Signing Service).

Run it from a real terminal (it prompts for your password and OTP codes):

    uv run python scripts/spike_arss.py               # all steps, interactively
    uv run python scripts/spike_arss.py --anonimo     # only the steps that need no credentials
    uv run python scripts/spike_arss.py --steps 1,3   # only some steps
    uv run python scripts/spike_arss.py --verifica a.pdf b.p7m   # also verify files you received

Steps:
    1  ping + getVersion                           (no credentials)
    2  verify files given with --verifica          (no credentials)
    3  listCert + auth_methods                     (password, no OTP)
    4  pdfsignatureV2 with a visible stamp         (1 OTP)
    5  session: opensession, sign several times, closesession   (1 OTP)
    6  pkcs7signV2_multiple with 2 files           (1 OTP)
    7  one deliberately wrong OTP via verifyOtp    (optional, off by default)
    8  timestamps: requiredmark + tsa_identity, tsd (optional, uses paid marks)

Safety rules: every call that carries credentials asks for confirmation first, nothing is
ever retried, and the first failed credentialed call stops the run unless you explicitly
continue. Passwords and OTPs are redacted from everything written to spike-output/.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import getpass
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

from lxml import etree
from zeep import Client, Plugin, Settings
from zeep.exceptions import Error as ZeepError
from zeep.helpers import serialize_object
from zeep.transports import Transport

from firmaremota import config, credentials

ROOT = Path(__file__).resolve().parents[1]
WSDL = ROOT / "src" / "firmaremota" / "arss" / "ArubaSignService.wsdl"
NS = "{http://arubasignservice.arubapec.it/}"

SECRET_TAGS = {"userPWD", "otpPwd", "password", "delegated_password", "dummy_otp",
               "ext_auth_value", "ext_auth_blobvalue"}
BINARY_TAGS = {"binaryinput", "binaryoutput", "stream", "imageBin", "value"}

# Reference rectangle drawn on both test pages; step 4 asks ARSS to put the stamp exactly here.
STAMP_RECT = (50, 50, 250, 120)

# zeep logs whole SOAP envelopes (passwords included) at DEBUG: keep it quiet no matter what.
for _name in ("zeep", "urllib3", "requests"):
    logging.getLogger(_name).setLevel(logging.WARNING)


class Recorder(Plugin):
    """Saves every request/response envelope with secrets and large binaries removed."""

    def __init__(self, out: Path, secrets: set[str]):
        self.out = out
        self.secrets = secrets
        self.count = 0

    def egress(self, envelope, http_headers, operation, binding_options):
        self.save(envelope, f"{operation.name}-request")
        return envelope, http_headers

    def ingress(self, envelope, http_headers, operation):
        self.save(envelope, f"{operation.name}-response")
        return envelope, http_headers

    def save(self, envelope, label: str) -> None:
        self.count += 1
        write_private(self.out / f"{self.count:03d}-{label}.xml", redact_envelope(envelope, self.secrets))


def redact_envelope(envelope, secrets: set[str]) -> bytes:
    env = copy.deepcopy(envelope)  # never touch the envelope that is actually sent
    for el in env.iter():
        if not isinstance(el.tag, str) or not el.text:
            continue
        local = etree.QName(el).localname
        if local in SECRET_TAGS:
            el.text = "REDACTED"
        elif local in BINARY_TAGS and len(el.text) > 200:
            el.text = f"[base64, {len(el.text)} chars omitted]"
    data = etree.tostring(env, pretty_print=True)
    for secret in secrets:  # belt and braces, in case a secret shows up in an unexpected field
        if secret:
            data = data.replace(secret.encode(), b"REDACTED")
    return data


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def make_test_pdf(label: str) -> bytes:
    """Two-page A4 PDF; each page shows its number and the target stamp rectangle."""
    x1, y1, x2, y2 = STAMP_RECT

    def page_content(n: int) -> bytes:
        return (
            f"BT /F1 22 Tf 72 770 Td (firma-remota - documento di prova) Tj ET\n"
            f"BT /F1 16 Tf 72 740 Td (Pagina {n} - {label}) Tj ET\n"
            f"BT /F1 9 Tf {x1} {y2 + 6} Td (rettangolo di riferimento {STAMP_RECT}) Tj ET\n"
            f"0.6 G 1 w {x1} {y1} {x2 - x1} {y2 - y1} re S\n"
        ).encode("latin-1")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [4 0 R 6 0 R] /Count 2 >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for n in (1, 2):
        content = page_content(n)
        content_obj = len(objects) + 2
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_obj} 0 R >>".encode()
        )
        objects.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"endstream")

    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


def summarize(obj):
    """Response as plain data, with bytes replaced by their length."""
    def clean(v):
        if isinstance(v, bytes):
            return f"<{len(v)} bytes>"
        if isinstance(v, dict):
            return {k: clean(x) for k, x in v.items()}
        if isinstance(v, list):
            return [clean(x) for x in v]
        return v
    return clean(serialize_object(obj, target_cls=dict))


AUTO = False  # --auto: no prompts; every question takes its (safe) default, OTP comes from stdin


def confirm(question: str, default: bool = False) -> bool:
    hint = "[S/n]" if default else "[s/N]"
    if AUTO:
        print(f"{question} {hint} -> {'yes' if default else 'no'} (auto)")
        return default
    answer = input(f"{question} {hint} ").strip().lower()
    return default if not answer else answer in ("s", "si", "sì", "y", "yes")


class Spike:
    def __init__(self, args):
        self.args = args
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.out = ROOT / "spike-output" / stamp
        self.out.mkdir(parents=True, mode=0o700)
        self.secrets: set[str] = set()
        self.results: list[dict] = []
        self.client = Client(
            str(WSDL),
            settings=Settings(xml_huge_tree=True),
            transport=Transport(timeout=30, operation_timeout=180),
            plugins=[Recorder(self.out, self.secrets)],
        )
        self.user = self.domain = self.password = None
        self.cert_id = args.cert_id
        self.stopped = False
        print(f"Output folder: {self.out}\n")

    # ---- helpers -------------------------------------------------------------------------

    def type(self, name: str):
        return self.client.get_type(NS + name)

    def record(self, step: str, operation: str, ok: bool | None, data=None, **extra) -> None:
        entry = {"step": step, "operation": operation, "ok": ok, "time": dt.datetime.now().isoformat(timespec="seconds")}
        entry.update(extra)
        if data is not None:
            entry["response"] = data
        self.results.append(entry)
        text = json.dumps(self.results, indent=2, ensure_ascii=False, default=str)
        for secret in self.secrets:
            text = text.replace(secret, "REDACTED")
        (self.out / "summary.json").write_text(text)
        os.chmod(self.out / "summary.json", 0o600)

    def call(self, step: str, operation: str, credentialed: bool, expect_failure: bool = False, **kwargs):
        """One SOAP call, never retried. Returns the response or None."""
        if self.stopped:
            return None
        if credentialed and not confirm(f"\n[{step}] Call {operation} with your credentials?", default=True):
            self.record(step, operation, None, skipped=True)
            return None
        started = time.monotonic()
        try:
            resp = getattr(self.client.service, operation)(**kwargs)
        except ZeepError as exc:
            # Fault text comes from the server; it does not contain what we sent.
            self.record(step, operation, False, error=f"{type(exc).__name__}: {exc}")
            print(f"  -> {operation} FAILED: {type(exc).__name__}: {exc}")
            self.after_failure(credentialed and not expect_failure)
            return None
        except Exception as exc:  # network errors etc.
            self.record(step, operation, False, error=f"{type(exc).__name__}: {exc}")
            print(f"  -> {operation} FAILED: {type(exc).__name__}: {exc}")
            self.after_failure(credentialed and not expect_failure)
            return None
        elapsed = round(time.monotonic() - started, 2)
        data = summarize(resp)
        status = data.get("status") if isinstance(data, dict) else None
        ok = status in (None, "OK") if isinstance(data, dict) else True
        self.record(step, operation, ok, data, seconds=elapsed)
        shown = {k: v for k, v in data.items() if k in ("status", "return_code", "description")} if isinstance(data, dict) else data
        print(f"  -> {operation}: {shown}  ({elapsed}s)")
        if not ok:
            self.after_failure(credentialed and not expect_failure)
        return resp

    def after_failure(self, credentialed: bool) -> None:
        if not credentialed:
            return
        print("  !! A call with your credentials failed. If the password or domain is wrong,")
        print("     more attempts could lock the account. Check summary.json before going on.")
        if not confirm("     Continue with the remaining steps anyway?"):
            self.stopped = True

    def ask_credentials(self) -> bool:
        if self.password is not None:
            return True
        settings = config.load()
        if settings.complete:
            try:
                store = credentials.get_store()
                password = store.get(credentials.account_key(settings.user, settings.domain)) if store else None
            except credentials.CredentialStoreError as exc:
                print(f"  {exc}")
                password = None
            if password:
                self.user, self.domain, self.password = settings.user, settings.domain, password
                if self.cert_id == "AS0" and settings.cert_id:
                    self.cert_id = settings.cert_id
                self.secrets.add(password)
                print(f"\nCredentials: user {self.user}, domain {self.domain}, password from {store.name}")
                return True
        if AUTO:
            print("  No saved credentials: run --salva-credenziali in a terminal first.")
            self.stopped = True
            return False
        print("\nCredentials for Aruba remote signature (asked once, never saved):")
        self.user = input("  Username: ").strip()
        self.domain = input("  Signing domain (typeOtpAuth) [firma]: ").strip() or "firma"
        self.password = getpass.getpass("  Password: ")
        if not (self.user and self.domain and self.password):
            print("  Missing values: skipping credentialed steps.")
            self.stopped = True
            return False
        self.secrets.add(self.password)
        return True

    def ask_otp(self) -> str | None:
        if AUTO:
            otp = sys.stdin.readline().strip()
            if not re.fullmatch(r"\d{6,8}", otp):
                print("  No valid OTP on stdin: step skipped.")
                return None
            self.secrets.add(otp)
            return otp
        while True:
            otp = input("  OTP code from the Aruba OTP app (empty = skip): ").strip()
            if not otp:
                return None
            if re.fullmatch(r"\d{6,8}", otp):
                if len(otp) != 6:
                    print("  Note: not 6 digits; recording that this length was used.")
                self.secrets.add(otp)
                return otp
            print("  Digits only, please.")

    def auth(self, otp: str | None = None):
        return self.type("auth")(
            user=self.user, userPWD=self.password, typeHSM=self.args.type_hsm,
            typeOtpAuth=self.domain, otpPwd=otp,
        )

    def sign_request(self, data: bytes, identity, session_id=None, tsa=None, mark=False):
        return self.type("signRequestV2")(
            certID=self.cert_id, identity=identity, requiredmark=mark, transport="BYNARYNET",
            binaryinput=data, session_id=session_id, tsa_identity=tsa,
        )

    def save_output(self, name: str, resp) -> Path | None:
        data = getattr(resp, "binaryoutput", None) if resp is not None else None
        if not data:
            return None
        path = self.out / name
        write_private(path, data)
        print(f"  saved {path.name} ({len(data)} bytes)")
        return path

    def verify(self, step: str, path: Path, kind: str) -> None:
        req = self.type("verifyRequest")(type=kind, transport="BYNARYNET", binaryinput=path.read_bytes())
        self.call(step, "verify", credentialed=False, request=req)

    # ---- steps ---------------------------------------------------------------------------

    def step1(self):
        print("\n== Step 1: ping + getVersion (no credentials)")
        self.call("1", "ping", credentialed=False)
        self.call("1", "getVersion", credentialed=False)

    def step2(self):
        print("\n== Step 2: verify the files given with --verifica (no credentials)")
        for f in self.args.verifica:
            p = Path(f)
            kind = "PDF" if p.suffix.lower() == ".pdf" else "PKCS7"
            print(f"  {p.name} as {kind}")
            self.verify("2", p, kind)

    def step3(self):
        print("\n== Step 3: listCert + auth_methods (password, no OTP)")
        if not self.ask_credentials():
            return
        resp = self.call("3", "listCert", credentialed=True, Identity=self.auth())
        if resp is not None:
            self.show_certs(resp)
        self.call("3", "auth_methods", credentialed=True, identity=self.auth())

    def show_certs(self, resp) -> None:
        try:
            from asn1crypto import x509
        except ImportError:
            return
        ids = []
        for group in ("app1", "app2"):
            for cert in getattr(resp, group, None) or []:
                if cert is None:
                    continue
                ids.append(cert.id)
                info = ""
                if cert.value:
                    c = x509.Certificate.load(cert.value)
                    info = f"{c.subject.human_friendly} | valid until {c['tbs_certificate']['validity']['not_after'].native:%Y-%m-%d}"
                print(f"  {group}: id={cert.id}  {info}")
        self.record("3", "listCert-ids", True, ids=ids)
        if ids and self.cert_id not in ids:
            print(f"  certID {self.cert_id!r} is not in the list; using {ids[0]!r} from now on.")
            self.cert_id = ids[0]
        settings = config.load()
        if settings.complete and settings.cert_id != self.cert_id:
            settings.cert_id = self.cert_id
            print(f"  saved certID in {config.save(settings)}")

    def step4(self):
        print("\n== Step 4: one PAdES signature with a visible stamp (1 OTP)")
        print(f"  The stamp is requested on page=1 at {STAMP_RECT} (the grey rectangle).")
        if not self.ask_credentials():
            return
        pdf = make_test_pdf("step 4")
        (self.out / "step4-input.pdf").write_bytes(pdf)
        otp = self.ask_otp()
        if not otp:
            return self.record("4", "pdfsignatureV2", None, skipped=True)
        x1, y1, x2, y2 = STAMP_RECT
        appearance = self.type("pdfSignApparence")(
            page=1, leftx=x1, lefty=y1, rightx=x2, righty=y2,
            testo="Firma di prova firma-remota", reason="Test", location="Italia", bShowDateTime=True,
        )
        resp = self.call("4", "pdfsignatureV2", credentialed=True,
                         SignRequestV2=self.sign_request(pdf, self.auth(otp)),
                         Apparence=appearance, pdfprofile="PADESBES")
        path = self.save_output("step4-signed.pdf", resp)
        if path:
            self.verify("4", path, "PDF")
            if AUTO:
                return self.record("4", "stamp-observation", None, observed="not asked (auto mode)")
            print(f"\n  Open {path} in Okular and look at the stamp.")
            seen = input("  Where is it? [1] page 1 inside the grey box, [2] page 1 elsewhere,"
                         " [3] page 2, [4] not visible, or describe: ").strip()
            self.record("4", "stamp-observation", None, observed=seen)

    def step5(self):
        print("\n== Step 5: session (1 OTP for several signatures)")
        if not self.ask_credentials():
            return
        otp = self.ask_otp()
        if not otp:
            return self.record("5", "opensession", None, skipped=True)
        resp = self.call("5", "opensession", credentialed=True, Identity=self.auth(otp))
        session_id = resp if isinstance(resp, str) else None
        if not session_id:
            return
        self.record("5", "opensession-id", True, length=len(session_id), charset=sorted(set(re.sub(r"[A-Za-z0-9]", "", session_id))))
        self.secrets.add(session_id)
        opened = time.monotonic()
        try:
            n = 0
            while not self.stopped:
                n += 1
                minutes = round((time.monotonic() - opened) / 60, 1)
                print(f"\n  Round {n}, {minutes} min after opensession: one .p7m and one PDF, no OTP")
                p7m = self.call("5", "pkcs7signV2", credentialed=False,
                                SignRequestV2=self.sign_request(f"prova sessione {n}\n".encode(), self.auth(), session_id),
                                detached=False, returnder=True)
                self.record("5", "session-round", p7m is not None and getattr(p7m, "status", None) == "OK",
                            round=n, minutes_after_open=minutes)
                saved = self.save_output(f"step5-round{n}.txt.p7m", p7m)
                if not saved:
                    break
                if n == 1:
                    self.verify("5", saved, "PKCS7")
                    pdf = self.call("5", "pdfsignatureV2", credentialed=False,
                                    SignRequestV2=self.sign_request(make_test_pdf("step 5"), self.auth(), session_id),
                                    pdfprofile="PADESBES")
                    self.save_output("step5-round1-signed.pdf", pdf)
                if AUTO:
                    if n > len(self.args.attese):
                        break
                    wait_until = opened + self.args.attese[n - 1] * 60
                    print(f"  waiting until {self.args.attese[n - 1]} min after opensession...")
                    time.sleep(max(0.0, wait_until - time.monotonic()))
                    continue
                print("  To measure how long the session lasts, wait (e.g. 3, then 10 minutes) and press Enter.")
                if input("  Enter = sign again, q = close the session: ").strip().lower() == "q":
                    break
        finally:
            was_stopped, self.stopped = self.stopped, False  # always try to close the session
            self.call("5", "closesession", credentialed=False, Identity=self.auth(), sessionid=session_id)
            self.stopped = was_stopped

    def step6(self):
        print("\n== Step 6: pkcs7signV2_multiple, 2 files in one call (1 OTP)")
        if not self.ask_credentials():
            return
        otp = self.ask_otp()
        if not otp:
            return self.record("6", "pkcs7signV2_multiple", None, skipped=True)
        identity = self.auth(otp)
        reqs = [self.sign_request(f"documento multiplo {i}\n".encode(), identity) for i in (1, 2)]
        resp = self.call("6", "pkcs7signV2_multiple", credentialed=True,
                         identity=identity, SignRequestV2=reqs, detached=False)
        for i, item in enumerate(getattr(resp, "return_signs", None) or [], start=1):
            self.save_output(f"step6-file{i}.txt.p7m", item)

    def step7(self):
        print("\n== Step 7: one deliberately wrong OTP (records the error code)")
        print("  This counts as a failed attempt on your account. It is only useful if we don't")
        print("  already know the code (a public report says 0004 = 'Otp Credential Invalid Or Blocked').")
        if not confirm("  Do it?"):
            return self.record("7", "verifyOtp-wrong", None, skipped=True)
        if not self.ask_credentials():
            return
        self.call("7", "verifyOtp", credentialed=True, expect_failure=True, Identity=self.auth("000000"))
        print("  Now a correct OTP, so the failure counter is reset straight away.")
        otp = self.ask_otp()
        if otp:
            self.call("7", "verifyOtp", credentialed=True, Identity=self.auth(otp))

    def step8(self):
        print("\n== Step 8: timestamps (each one uses a purchased mark)")
        if not confirm("  Do you have Aruba TSA (marca temporale) credentials and want to test them?"):
            return self.record("8", "timestamps", None, skipped=True)
        if not self.ask_credentials():
            return
        tsa_user = input("  TSA username: ").strip()
        tsa_password = getpass.getpass("  TSA password: ")
        self.secrets.add(tsa_password)
        tsa = self.type("tsaAuth")(user=tsa_user, password=tsa_password)
        if confirm("  8a: sign a .p7m with requiredmark + tsa_identity (1 OTP, 1 mark)?", default=True):
            otp = self.ask_otp()
            if otp:
                resp = self.call("8", "pkcs7signV2", credentialed=True,
                                 SignRequestV2=self.sign_request(b"prova marca\n", self.auth(otp), tsa=tsa, mark=True),
                                 detached=False, returnder=True)
                path = self.save_output("step8-marked.txt.p7m", resp)
                if path:
                    self.verify("8", path, "PKCS7")
        if confirm("  8b: sign a PDF as PADESLTV with requiredmark + tsa_identity (1 OTP, 1 mark)?"):
            otp = self.ask_otp()
            if otp:
                resp = self.call("8", "pdfsignatureV2", credentialed=True,
                                 SignRequestV2=self.sign_request(make_test_pdf("step 8"), self.auth(otp), tsa=tsa, mark=True),
                                 pdfprofile="PADESLTV")
                path = self.save_output("step8-ltv.pdf", resp)
                if path:
                    self.verify("8", path, "PDF")
        if confirm("  8c: standalone tsd of a small file (no OTP, 1 mark)?"):
            req = self.type("MarkRequest")(user=tsa_user, password=tsa_password, transport="BYNARYNET",
                                           binaryinput=b"prova tsd\n")
            resp = self.call("8", "tsd", credentialed=True, MarkRequest=req)
            self.save_output("step8.txt.tsd", resp)

    def run(self, steps: list[int]) -> None:
        if any(s >= 4 for s in steps):
            print("Note: if your plan has a quota, each signature in steps 4-6 and 8 counts against it.")
        try:
            for s in steps:
                if self.stopped:
                    print(f"\n(step {s} skipped: run stopped after a failure)")
                    continue
                getattr(self, f"step{s}")()
        except KeyboardInterrupt:
            print("\nInterrupted.")
        finally:
            self.record("end", "-", None)
            print(f"\nDone. Results: {self.out / 'summary.json'}")
            if not any(s >= 4 for s in steps):
                return
            print("Useful independent checks on the signed files:")
            print(f"  openssl cms -inform DER -cmsout -print -in {self.out}/step5-round1.txt.p7m | head -60")
            print(f"  uvx --from pyhanko pyhanko sign validate --pretty-print {self.out}/step4-signed.pdf")


def save_credentials() -> None:
    settings = config.load()
    print("Aruba remote-signature credentials. The password goes to the system wallet, never to a file.")
    user = input(f"  Username [{settings.user}]: ").strip() or settings.user
    default_domain = settings.domain or "firma"  # Aruba: "generally 'firma'" for signatures bought on pec.it
    domain = input(f"  Signing domain, typeOtpAuth [{default_domain}]: ").strip() or default_domain
    if not (user and domain):
        sys.exit("Username and domain are both required: nothing saved.")
    store = credentials.get_store()
    if store is None:
        sys.exit("No password store available (KWallet or Secret Service): nothing saved.")
    first = getpass.getpass("  Password: ")
    if not first or getpass.getpass("  Password again: ") != first:
        sys.exit("Passwords empty or different: nothing saved.")
    key = credentials.account_key(user, domain)
    print(f"  Saving to {store.name} (KDE may ask you to allow 'firma-remota' to use the wallet)...")
    try:
        store.set(key, first)
        if store.get(key) != first:
            sys.exit("Read-back check failed: the wallet did not return the same password.")
    except credentials.CredentialStoreError as exc:
        sys.exit(str(exc))
    settings.user, settings.domain = user, domain
    path = config.save(settings)
    print(f"  Done: username and domain in {path}, password in {store.name}.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--anonimo", action="store_true", help="only steps 1-2 (no credentials)")
    parser.add_argument("--steps", help="comma-separated step numbers, e.g. 1,3,4")
    parser.add_argument("--verifica", nargs="*", default=[], metavar="FILE", help="files to verify in step 2")
    parser.add_argument("--cert-id", default="AS0", help="certID (default AS0; step 3 picks a listed one)")
    parser.add_argument("--type-hsm", default="COSIGN")
    parser.add_argument("--salva-credenziali", action="store_true",
                        help="save username/domain (config file) and password (KWallet) once, then exit")
    parser.add_argument("--auto", action="store_true",
                        help="no prompts: saved credentials, OTP read from stdin, stop at the first failure")
    parser.add_argument("--attese", default="3,10",
                        help="auto mode, step 5: minutes after opensession at which to sign again (default 3,10)")
    args = parser.parse_args()
    args.attese = [float(m) for m in args.attese.split(",") if m]
    sys.stdout.reconfigure(line_buffering=True)

    if args.salva_credenziali:
        if not sys.stdin.isatty():
            sys.exit("--salva-credenziali needs a real terminal.")
        return save_credentials()
    global AUTO
    AUTO = args.auto

    if args.steps:
        steps = sorted({int(s) for s in args.steps.split(",")})
    elif args.anonimo:
        steps = [1, 2]
    else:
        steps = list(range(1, 9))
    if any(s >= 3 for s in steps) and not AUTO and not sys.stdin.isatty():
        sys.exit("The credentialed steps need a real terminal (password/OTP prompts).")
    Spike(args).run(steps)


if __name__ == "__main__":
    main()
