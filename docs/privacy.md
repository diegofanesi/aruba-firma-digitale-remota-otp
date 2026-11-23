# What firma-remota stores, and how

The app keeps as little as possible: nothing personal is written to disk.

| What | Where | Protection |
|---|---|---|
| Username and signing domain (`utente@dominio`) | system wallet (KWallet on KDE, otherwise the Secret Service), folder/service `firma-remota`, entry `utente` | stored as the entry's encrypted **value**, with the same protection as the password (KWallet: Blowfish or GPG; GNOME Keyring: AES-128). The entry name says nothing about the user. |
| Aruba password | same wallet, entry `password` | the wallet's encryption. |
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
- `firma configura` (or *Impostazioni* in the GUI) asks whether to remember username and password;
  answering no removes anything previously saved.
- `firma configura --dimentica-password` removes the password; `--dimentica-tutto` removes both.
- In the GUI, the first signature asks for username and password ("Ricorda" is ticked by default);
  they reach the wallet only after Aruba has accepted them.

## Not covered
- **Signed documents** contain the signer's certificate (name, tax code): that is what a digital
  signature is. They stay wherever the user saves them.
- `scripts/spike_arss.py` (developer tool) writes raw exchanges and signed test files to
  `spike-output/`; delete that folder after reading the results.
