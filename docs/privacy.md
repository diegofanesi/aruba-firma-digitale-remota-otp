# What firma-remota stores, and how

The app keeps as little as possible: nothing personal is written to disk.

| What | Where | Protection |
|---|---|---|
| Accounts: for each one an alias chosen by the user, username and signing domain | system wallet (KWallet on KDE, otherwise the Secret Service), folder/service `firma-remota`, entry `profili` | one JSON list stored as the entry's encrypted **value**, with the same protection as the passwords (KWallet: Blowfish or GPG; GNOME Keyring: AES-128). The entry name says nothing about the users. |
| Aruba passwords | same wallet, one entry per account named `password:<random id>` | the wallet's encryption; the id is random, not derived from the username. |
| Which account was used last | `~/.config/firma-remota/config.ini` | the random id only, never the alias or the username. |
| Certificate ID, holder name, certificate expiry | **nowhere** | fetched from Aruba with `listCert` (password only, no OTP) at the start of each signing; this also proves the password is right before an OTP is asked for, and stays correct when the certificate is renewed. |
| OTP codes, session ids | nowhere | kept in memory for one batch only. |
| Preferences (stamp position, page) | `~/.config/firma-remota/config.ini` | nothing personal; mode 0600. |
| Consecutive refused logins | `~/.local/state/firma-remota/state.json` | a number. |
| Log | `~/.local/state/firma-remota/firma.log` (folder 0700, file 0600) | secrets (password, OTP, session id) fully replaced by `***`; personal data (username, holder name, file names, folders) keeps only the first and last letter, e.g. `M*********i`, `C*******o.pdf` (extension kept). Applied by the log formatter, so it also covers error messages and tracebacks. |
| Official trusted lists | `~/.cache/firma-remota/trustlist/` | public data. |

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

## Not covered
- **Signed documents** contain the signer's certificate (name, tax code): that is what a digital
  signature is. They stay wherever the user saves them.
- `scripts/spike_arss.py` (developer tool) writes raw exchanges and signed test files to
  `spike-output/`; delete that folder after reading the results.
