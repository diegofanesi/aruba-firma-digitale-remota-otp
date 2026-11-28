# What firma-remota stores, and how

The app keeps as little as possible: nothing personal is written to disk.

| What | Where | Protection |
|---|---|---|
| Accounts: for each one an alias chosen by the user, username and signing domain | system wallet (KWallet on KDE, otherwise the Secret Service), folder/service `firma-remota`, entry `profili` | one JSON list stored as the entry's encrypted **value**, with the same protection as the passwords (KWallet: Blowfish or GPG; GNOME Keyring: AES-128). The entry name says nothing about the users. |
| Aruba passwords | same wallet, one entry per account named `password:<random id>` | the wallet's encryption; the id is random, not derived from the username. |
| Who timestamps an account's signatures: automatic (default), Aruba, the free Belgian service, or nobody | inside the `profili` entry, as `"automatica"`, `"aruba"`, `"belgio"` or `"no"` | nothing personal. |
| Whether the account's Aruba service includes timestamps, as its signatures have shown | inside the `profili` entry: a yes/no and the date it was first seen | nothing personal; learnt from Aruba's answers to signatures the user made (or from the optional check, which signs a fixed test text kept in memory only). |
| A separate time-stamping (TSA) account, if the user has one | same wallet, entry `marca:<random id>` with user, password and optional server address | the wallet's encryption; absent when the user has none. Never checked with Aruba up front (each check would spend a timestamp). |
| Remaining timestamps | **nowhere** | ARSS has no way to ask; Aruba's own client doesn't show it either. |
| Which account was used last | `~/.config/firma-remota/config.ini` | the random id only, never the alias or the username. |
| Certificate ID, holder name, certificate expiry | **nowhere** | fetched from Aruba with `listCert` (password only, no OTP) at the start of each signing; this also proves the password is right before an OTP is asked for, and stays correct when the certificate is renewed. |
| OTP codes, session ids | nowhere | kept in memory for one batch only. |
| Preferences (stamp position, page) | `~/.config/firma-remota/config.ini` | nothing personal; mode 0600. |
| Consecutive refused logins | `~/.local/state/firma-remota/state.json` | a number. |
| Log | `~/.local/state/firma-remota/firma.log` (folder 0700, file 0600) | secrets (password, OTP, session id) fully replaced by `***`; personal data (username, holder name, file names, folders) keeps only the first and last letter, e.g. `M*********i`, `C*******o.pdf` (extension kept). Applied by the log formatter, so it also covers error messages and tracebacks. |
| Official trusted lists (EU list of lists + Italian and Belgian lists) | `~/.cache/firma-remota/trustlist/` | public data; their XML signatures are verified again every time they are read back, so the cache is a copy, never a source of trust. |

## Without a wallet
Nothing is stored at all: username and password are asked at every signing. A mistyped password
is then checked by Aruba (`listCert`) and counts as one refused login.

## Choosing what to remember
- `aruba-firma configura` (or *Impostazioni* in the GUI) adds or edits an account and asks whether to
  remember its password; the account itself (alias and username) is always kept in the wallet.
- `aruba-firma configura --dimentica-password` forgets one password, `--rimuovi` one account,
  `--dimentica-tutto` every account (all take `--account ALIAS` when there are several).
- In the GUI, a missing password is asked at the first signature ("Ricorda" is ticked by default)
  and reaches the wallet only after Aruba has accepted it. With no account saved, the first
  signature opens the "Nuovo account" dialog.
- Older versions kept a single account in the entries `utente` and `password`; it becomes a
  profile (alias = username) the first time the new version reads the wallet.

## The free timestamp (Belgian federal service)
Used by the automatic setting when Aruba's answer carries no timestamp of its own, or always when chosen
("Avanzate: solo quella gratuita", `--marca-gratuita`). After Aruba has signed:
- what leaves the computer is a standard RFC 3161 request: the **SHA-256 of the signature value**
  (`.p7m`) or **of the signed PDF's byte range** (PDF), plus a random nonce. Never the document, a
  file name or anything about the signer. The service (FPS BOSA, `http://tsa.belgium.be/connect`)
  necessarily sees the computer's IP address and the time of the request;
- the service only answers over **plain HTTP** (its HTTPS address fails the TLS handshake). Nothing in
  the request is secret, and the answer is not trusted because of the transport: the token must
  carry the nonce and the exact hash sent, and its signature must chain to a **qualified
  time-stamping service** on the EU trusted lists (Belgian list). Anything else counts as a failed
  attempt, and a tampered answer can only make the timestamp missing, never wrong;
- the request goes through the same fetcher as revocation checks (public addresses only, redirects
  checked one by one, size capped);
- after 3 failed attempts the signature is saved without a timestamp and the user is told so;
  nothing about the service or its answers is stored.

Terms of use: https://repository.eid.belgium.be/downloads/timestamp/fr/timestamping.pdf (free,
non-commercial use, volume limits, no guarantee of service).

## Handling files that come from others
A signed file to verify is untrusted input, so the app treats it as such:
- the verification runs in a **separate process with a time limit** (GUI); a crafted file can at
  most make that process fail, which is reported as "controllo non riuscito";
- files over 200 MB (50 MB for signing) are refused before being read;
- **nothing is fetched from the network for a file whose signature doesn't already chain to an
  authority in the official list**; revocation servers (OCSP/CRL) are contacted only after that, and
  only on public addresses (never the local network or the machine itself), because their URLs come
  from the file;
- the document extracted from a `.p7m` is opened with the system's application only for ordinary
  document types (PDF, images, office, text...). Anything else (`.desktop`, `.html`, `.sh`, `.svg`...)
  is extracted next to the `.p7m` and only its folder is opened: a valid signature says who signed,
  not that the content is safe;
- the verdict has three values: **valida**, **non valida**, and **non verificabile** when the
  signature is sound but trust or revocation could not be checked (offline, authority not answering,
  no trusted list). Non verificabile is never shown in green;
- timestamps (`.tsd`, `.tsr`, and those inside signatures) are checked like signatures: the token
  must be intact, its authority must chain to the official list (ideally as a qualified
  time-stamping service, QTST). Only a trusted timestamp is used as proof of existence: a signature
  whose certificate has since expired is judged **as of the timestamp's time** and stays valid; an
  unknown authority's timestamp is shown but proves nothing. A `.tsr` is only checked together with
  the file it refers to (same name without `.tsr`, or chosen explicitly);
- SOAP replies from Aruba are parsed with DTDs, external entities and external resources disabled.

Before a document is sent for signing its SHA-256 is taken when the user approves the list; a file that
changes before it is actually sent (e.g. swapped by another program while the OTP is being typed) is
refused. What Aruba returns is saved only if it contains exactly the bytes sent and its signature
verifies.

## Not covered
- **Signed documents** contain the signer's certificate (name, tax code): that is what a digital
  signature is. They stay wherever the user saves them.
