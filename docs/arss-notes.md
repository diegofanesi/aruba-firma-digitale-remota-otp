# ARSS notes (Phase 0)

Facts about Aruba Remote Signing Service that the client relies on. "Verified" means it was read
from the bundled WSDL or observed against the live service; everything marked **TBD** is filled
in from a `scripts/spike_arss.py` run (results land in `spike-output/<timestamp>/summary.json`,
which is gitignored because it contains certificate data).

## Endpoint and WSDL (verified 2026-11-23)
- SOAP address: `https://arss.arubapec.it/ArubaSignService/ArubaSignService`
- WSDL bundled at `src/firmaremota/arss/ArubaSignService.wsdl` (self-contained, JAX-WS Metro 4.0.2).
  Namespace `http://arubasignservice.arubapec.it/`.
- Live: `ping` → `pong`, `getVersion` → `1.1.1`. Neither needs credentials.

## Account facts (verified live 2026-11-23, step 3)
- A personal remote signature bought on pec.it **is accepted** by ARSS. Domain (`typeOtpAuth`) = `firma`,
  i.e. the selfcare login `username@firma`. Organisation-issued signatures use their own `fr<Name>` domain.
- `listCert` works with the password only (no OTP): useful for a lockout-free credentials check.
- `certID` is **not** `AS0` but the id listed by `listCert` under `app1`, e.g. `NEW_2025:<40 hex>-AS0`.
  The app must call `listCert` and store the id (config `cert_id`), not hard-code `AS0`.
- `auth_methods` → `methods: ["OTP"]`.
- Success = `status: "OK"`; `auth_methods` also returns `return_code: "0000"`, `description: "Success"`.
- **OTP codes from the Aruba OTP app have 8 digits** (not 6). Validate digits only, 6–8 long.

## Signing facts (verified live 2026-11-23, step 4)
- `pdfsignatureV2` with OTP, `PADESBES`, `requiredmark=false` → `status OK`, `return_code 0000`, ~0.7 s.
- Output: PAdES (`/SubFilter /ETSI.CAdES.detached`), SHA-256 + RSA, field `Signature1`. pyHanko: intact and
  cryptographically valid; signer cert is qualified (qcStatements), issuer
  "ArubaPEC EU Qualified Certificates CA G1". Trust-list check still to do locally.
- Stamp (`pdfSignApparence`): coordinates are **PDF points, origin bottom-left** (same as pypdf), `page` is
  **1-based**; `leftx/lefty/rightx/righty` = lower-left and upper-right corners. The rendered stamp shows
  `testo` plus, with `bShowDateTime`, a line like `23.11.2026 17:08:59 UTC`, top-left aligned in small type.
  `reason` and `location` are **not** drawn, and the signer's name is **not** added automatically: the app
  must put "Firmato digitalmente da <CN>" into `testo` itself. `\n` in `testo` gives separate lines.
- **Rotated pages (verified live 2026-11-23): ARSS compensates `/Rotate` itself.** Given displayed
  coordinates on a `/Rotate 90` page it writes the widget at the rotated rectangle with an upright
  appearance (`/Matrix [0 1 -1 0 0 0]`). Pre-converting to user space puts the stamp off the page.
  Send displayed coordinates; add the CropBox offset only on unrotated pages.
- **ARSS bug: dangling `/Info` after signing.** When the input PDF has an `/Info` dictionary, the
  incremental update ARSS appends sets `/Info N 0 R` with `/Size N` and never writes object N.
  Viewers repair it (poppler: "xref num N not found"); the signature stays valid (pyHanko: intact,
  whole file covered); the document's title/author metadata appears empty. Can't be fixed after
  signing (it would be a post-signature change). Seen with pypdf-made inputs; to re-check with a
  real-world PDF.
- `pkcs7signV2` (`detached=false`, `returnder=true`) → CAdES-BES, content attached, SHA-256 + RSA, signed
  attributes contentType, messageDigest, signingTime, **signingCertificateV2**. `openssl cms -verify -noverify`
  succeeds and extracts the content. The output is **BER (indefinite length, starts `30 80`) despite
  `returnder=true`**: `p7m.unwrap` must accept BER, and the file must be saved byte-for-byte as returned.
- **Sessions:** `opensession(Identity with OTP)` → a UUID string; `closesession` → `OK`. Still valid after 10 min. Signing with `session_id` and an identity
  **without** `otpPwd` works for both `pkcs7signV2` and `pdfsignatureV2`. Never log or print the session id.
- **`verify` is useless on this endpoint**: it returns an empty `<verifyResponse/>` (HTTP 200, no fault) for
  every variant tried (type PDF/PKCS7, with and without `verdate`). Verification must be done locally.

## Operations used (verified from the WSDL)
| Operation | Arguments | Returns |
|---|---|---|
| `listCert` | `Identity: auth` | `userCertList{app1[], app2[] of cert{id, value}, status, description}` |
| `auth_methods` | `identity: auth` | `authMethodsReturn{methods[], status, description, return_code}` |
| `opensession` | `Identity: auth` (with OTP) | session id (string) |
| `closesession` | `Identity: auth`, `sessionid` | string |
| `pdfsignatureV2` | `SignRequestV2`, `Apparence: pdfSignApparence`, `fieldName`, `pdfprofile` (BASIC/PADESBES/PADESLTV), `password` (of the PDF), `dict_signed_attributes` | `signReturnV2` |
| `pdfsignatureV2_multiple` | `identity`, `SignRequestV2[]`, `Apparence`, `fieldName`, `pdfprofile` | `signReturnV2Multiple{return_signs[], status, return_code, description}` |
| `pkcs7signV2` | `SignRequestV2`, `detached`!, `returnder`! | `signReturnV2` |
| `pkcs7signV2_multiple` | `identity`, `SignRequestV2[]`, `detached`! | `signReturnV2Multiple` |
| `verify` | `request: verifyRequest{type (PKCS7/PDF/XML/TSD), transport, binaryinput, verdate}` (no credentials) | `verifyReturn{status, description, result: verifySignatures{status, description, signer[]{signername, serialnumber, result, description, marks[], countersigners[]}, mark[]}, binaryoutput}` |
| `verifyOtp` | `Identity: auth` | `arssReturn{status, return_code, description}` |
| `tsd` | `MarkRequest{user!, password!, url, transport!, binaryinput}` | `markReturn{binaryoutput, status, return_code, description}` |

- `auth`: `user`, `userPWD`, `otpPwd`, `typeHSM` (`COSIGN`), `typeOtpAuth` (signing domain), `delegated_*`, `ext_auth*`.
- `signRequestV2`: `certID`!, `identity`!, `requiredmark`! (timestamp), `transport`! (only `BYNARYNET` is usable from zeep),
  `binaryinput`, `session_id`, `tsa_identity: tsaAuth{user!, password!, tsaurl}`, `signingTime`, `profile`, `signatureLevel`.
- `pdfSignApparence`: `page`, `leftx`, `lefty`, `rightx`, `righty`, `testo`, `reason`, `location`, `bShowDateTime`,
  `image`, `imageBin`, `imageOnly`, `bScaleFont`, `pageToSign`, `resizeMode`, `preservePDFA`.

## Known error codes
| Code | Meaning | Source |
|---|---|---|
| `0004` | OTP credential invalid **or blocked** (can't tell which) | public report (italia/ansc#785) |
| **TBD** | wrong password / wrong domain | step 3 (only if it happens by accident; never tested on purpose) |
| unknown | session expired (not reached in 10 min) | handle any failure mid-batch as "session may have expired" |

## To be determined by the spike
| Question | Step | Answer |
|---|---|---|
| Is a personal remote-signature account accepted? (gate) | 3, 4 | **Yes**: authentication (step 3) and PAdES signing (step 4) |
| Does `listCert` work with the password only (no OTP)? | 3 | Yes |
| Real `certID` value(s) | 3 | `NEW_2025:<hash>-AS0` (from `listCert`) |
| Success value of `status` (`OK`?) | 3, 4 | `OK` (+ `return_code` `0000` where present) |
| Stamp coordinates: origin, page numbering (0- or 1-based), default text | 4 | Points, bottom-left origin, 1-based; only `testo` + date drawn |
| Does signing with `session_id` work without `otpPwd`? | 5 | Yes (CAdES and PAdES) |
| Session lifetime | 5 | ≥ 10 min (signed OK at 0, 3 and 10 min; expiry not reached) |
| `pkcs7signV2_multiple` works and output is DER? | 6 | Not tested: not needed, sessions chosen |
| `verify` result strings for a valid signature | 4, 5 | None: `verify` returns an empty response → verify locally |
| Timestamp: `requiredmark` + `tsa_identity` on CAdES; PADESLTV on PDF; `tsd` | 8 | Out of scope (no TSA credentials) |
| Batch mechanism chosen (session vs `_multiple`) | 5, 6 | **Session**: `opensession` (1 OTP) → sign each file with `session_id` → `closesession` in `finally` |
| PySide6 line for the father's PC (6.12 needs glibc ≥ 2.34; else 6.9.3) | – | **TBD** (needs `ldd --version` there) |

## Phase 0 outcome (2026-11-23)
**Go.** Personal account accepted, PAdES and CAdES signing work, batch via session works. OTPs used: 2
(step 4, step 5). Skipped: step 6 (not needed), step 7 (wrong-OTP test: lockout risk, code 0004 already known),
step 8 (timestamps out of scope). Still open: the PySide6 line for the father's PC (needs his `ldd --version`).
