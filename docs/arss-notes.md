# ARSS notes (Phase 0)

Facts about Aruba Remote Signing Service that the client relies on. "Verified" means it was read
from the bundled WSDL or observed against the live service; everything marked **TBD** is filled
in from a `scripts/spike_arss.py` run (the script was removed on 2026-11-25 once it had served its purpose;
it is in the git history before that date; results landed in `spike-output/<timestamp>/summary.json`,
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
- **What comes back is checked before it is saved** (security review 2026-11-24): the PAdES result must
  start with the exact bytes sent (ARSS signs by appending an incremental update, see the `/Info` note
  below, so the original file is an untouched prefix) and the CAdES envelope must contain exactly the
  bytes sent; then every signature must verify cryptographically (pyHanko, no trust, no network). A
  mismatch is a `ServiceError` and nothing is written. The prefix rule rests on the live outputs of
  2026-11-23; re-check it with `FIRMA_LIVE=1 uv run pytest -m live -s` after any ARSS change.
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
| `tsd` | `MarkRequest{user!, password!, url, transport!, binaryinput}` | `markReturn{binaryoutput, status, return_code, description}` (RFC 5544 `.tsd`) |
| `tsr` | `MarkRequest` (as `tsd`) | `markReturn` (RFC 3161 `TimeStampResp`, `.tsr`) |

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
| Timestamp: `requiredmark` + `tsa_identity` on CAdES; PADESLTV on PDF; `tsd` | 8 | Skipped in 2026-11; implemented 2026-11-24 from the WSDL, see "Marche temporali" below |
| Batch mechanism chosen (session vs `_multiple`) | 5, 6 | **Session**: `opensession` (1 OTP) → sign each file with `session_id` → `closesession` in `finally` |
| PySide6 line for the father's PC (6.12 needs glibc ≥ 2.34; else 6.9.3) | – | **TBD** (needs `ldd --version` there) |

## Phase 0 outcome (2026-11-23)
**Go.** Personal account accepted, PAdES and CAdES signing work, batch via session works. OTPs used: 2
(step 4, step 5). Skipped: step 6 (not needed), step 7 (wrong-OTP test: lockout risk, code 0004 already known),
step 8 (timestamps out of scope). Still open: the PySide6 line for the father's PC (needs his `ldd --version`).

## Marche temporali (added 2026-11-24, built from the WSDL; **to be confirmed by the live test**)
Scope = what the official ArubaSign client does (read from its Electron front-end): TSA settings (Indirizzo
Server, Account TSA, Password; "Marca sempre i file firmati"), signatures with "Tipo di marcatura" T / LT /
TSD (CAdES only, `.p7m.tsd`), a standalone "Marca" producing `.tsd` or `.tsr`, verification of all of them
(a `.tsr` needs its original), "Verifica alla data". Aruba's app also relies on a **server-side automatic
timestamp** for Firma Remota users, switched on in SelfCare (`automaticTimeStamp`).

How this client maps it onto ARSS, and what `FIRMA_LIVE=1 uv run pytest -m live -s` checks (1 OTP, ≤ 9 marks):

| # | Assumption | Live check | Result |
|---|---|---|---|
| A0 | A plain signature (`requiredmark=false`) may already carry a TST (SelfCare "Marca Automatica") | `has_timestamp` on the un-marked output, recorded | **This account: no.** The SelfCare Home shows "Marca automaticamente tutti i documenti firmati" only for "Firma Remota con marcatura illimitata" (guide, 2026-11-25); the user's panel has no such option → the service doesn't include timestamps. Default therefore **off**; the app still reports a mark if one ever comes back |
| A1 | ~~The signing credentials are accepted as `tsaAuth`~~ → **No** (offline check 2026-11-24, see below; **confirmed 2026-11-25**: `servizi.arubapec.it/tsa/marcheresidue.php` answers `401 Basic realm="tsa"` to the Firma Remota credentials, both as `utente` and `utente@firma`, from the browser and from the wallet). Firma Remota's included marks are applied by Aruba's server; a TSA account is a separate product. The client sends `requiredmark=true` **without** `tsa_identity` unless a TSA account is saved | T signatures without `tsa_identity` succeed | credentials: confirmed not a TSA account |
| A2 | `PADESBES` + `requiredmark=true` (no `tsa_identity`) → signature timestamp inside the PDF (level T) | `has_timestamp(PADES)`; `checks[0].timestamp` present | TBD |
| A3 | `pkcs7signV2` + `requiredmark=true` → CAdES-T (unsigned `signature_time_stamp_token`) | same on the `.p7m` | TBD |
| A4 | `PADESLTV` + mark → LT (TST plus revocation data / DocTimeStamp), still verifiable | `verify_file(...).ok`; shape and marks spent recorded | TBD |
| A5 | `signatureLevel="LT"` accepted on `pkcs7signV2` | LT `.p7m` succeeds; else `ServiceError` → hide LT for `.p7m` | TBD |
| A6 | The original stays a prefix (PAdES) / the attached content (CAdES) with timestamps | `returned_matches` passes | TBD |
| A7 | Aruba's TSU certificate chains to an IT trusted-list anchor, listed as QTST | `timestamp.trusted and timestamp.qualified` | TBD |
| A8 | `tsd` returns RFC 5544 with the content embedded | `tst.parse_tsd(out).content == original` | TBD |
| A9 | `tsr` returns a DER `TimeStampResp` (granted) over the file | `verify_file(out, original=...)` valid | TBD |
| A10 | TSA error vocabulary: ArubaSign's 0049 / 0073–0085 / 93001 / 93003 and words like "TSA", "marca" | not provoked (marks, lockout); unit-tested mapping only | unconfirmed |

Decisions after the live run: A2 fails (no TST with `requiredmark` alone) → the account probably has no
"Marca Automatica": tell the user to enable it in the SelfCare, or fall back to ArubaSign's behaviour (no
timestamp until a TSA account is saved); A4/A5 fail → remove LT for `.p7m` / keep `PADESBES` only.

**Offline validation round (2026-11-24, before any live test).** Sources: Aruba's guides
(guide.aruba.it: "Firma Remota › Aruba Sign › configura e applica la marca temporale"; "App Firma Digitale
Aruba › configurare un account di marca temporale"; "Marca temporale › configurare l'account"), Aruba's
"Manuale d'uso Marca Temporale con Aruba Sign" (pec.it), the UNIGE "Vademecum strumenti Aruba", the public
ARSS example `gist.github.com/marcodebe/6138525`, and the ArubaSign 2 package's readable front-end sources
(`aruba-components-lib.mjs.map` embeds the TypeScript; the Java back-end is encrypted and was not touched).
- **Included marks are server-side.** "Se hai acquistato la Firma Digitale Remota con marca temporale
  incorporata, l'apposizione della marca temporale dipende dalla configurazione scelta nel pannello selfcare
  della Firma Remota. […] Il formato utilizzato è LT e non può essere modificato." The app guide: "In caso di
  Firma Digitale Remota con marcatura temporale illimitata, il formato della marca è impostato su LT e non
  può essere modificato", and to check in the SelfCare that "Marca Automatica" is enabled. ArubaSign's
  front-end mirrors this: `DeviceInfo.automaticTimeStamp` → "Il documento è stato firmato e marcato
  temporalmente" + "L'applicazione automatica della Marca Temporale è facoltativa e puoi gestirla dal
  SelfCare". Nothing in ArubaSign ever copies the signing credentials into the TSA settings.
- **TSA credentials are a separate account.** Every guide: "inserisci le credenziali del tuo account di Marca
  Temporale"; UNIGE: "in ARUBA i due servizi vengono configurati separatamente", TSA user/password
  "comunicati separatamente"; remaining marks only at `https://servizi.arubapec.it/tsa/marcheresidue.php`
  (HTTP basic auth with the TSA account). Default TSA URL for a purchased pack:
  `https://servizi.arubapec.it/tsa/ngrequest.php`; "Policy" left empty.
- **`requiredmark` alone is how ARSS is called in the wild.** The public example signs with
  `requiredmark=True` and no `tsa_identity` for a business (`frAzienda`) account.
- ArubaSign vocabulary: `SignatureLevel {BES, T, LT}` for every format (supports `signatureLevel="LT"` on
  `signRequestV2`); `TimestampType {T, LT, TSD, TSR}`; TSD = the finished `.p7m` wrapped as is; `.tsr`
  detached, verified next to its original. Error texts 0073–0085, 0049, 0081/0082, 93001–93003 as listed above.
- Consequences applied to the code: no silent fallback to the signing credentials; standalone `marca` and the
  `.p7m.tsd` wrap require a saved TSA account (as ArubaSign does), with an explanatory error before any OTP;
  signatures with a timestamp send `requiredmark=true` and, only when a TSA account is saved, `tsa_identity`.
- **Still only the live test can tell:** whether `requiredmark=true` on an account without the add-on is
  refused or ignored (A2/A3; expected: refused), what LT looks like (A4/A5), the TSU chain (A7). With no
  timestamp product on this account, the live test is now about shapes and error texts, not about a feature
  the user can use: low priority until a TSA pack or the add-on is bought.
  Zero-cost pre-checks for the user: look at the SelfCare for "Marca Automatica"; try the Firma Remota
  credentials at `marcheresidue.php` (if accepted, they are also a TSA account and A1 was wrong the other way). ArubaSign's TSA error texts: 0049 "Credenziali errate...", 0074 "Hai esaurito le tue marche
temporali", 0073/0078/0080 service unreachable, 0079 too many requests, 0081/0082 account disabled/expired,
0085 automatic timestamp failed, 93001 "Indirizzo server Timestamp non specificato", 93003 "credenziali TSA
errate".
