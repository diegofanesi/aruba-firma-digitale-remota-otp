# What firma-remota stores, and how

| What | Where | Protection |
|---|---|---|
| Account data: username, signing domain, certificate ID, holder name, certificate expiry | `~/.config/firma-remota/profilo.enc` | **AES-256-GCM**; 256-bit key derived with scrypt (n=2^15, r=8, p=1, random 16-byte salt) from the Aruba password; fresh salt and 12-byte nonce on every save; format string authenticated. File mode 0600. |
| Aruba password | system wallet (KWallet on KDE, otherwise the Secret Service), folder/service `firma-remota`, entry `account` | the wallet's own encryption; the entry name doesn't reveal the username. Without a wallet the password is asked every time and never written anywhere. |
| OTP codes, session ids | nowhere | kept in memory for one batch only. |
| Preferences (stamp position, page) | `~/.config/firma-remota/config.ini` | nothing personal; mode 0600. |
| Consecutive refused logins | `~/.local/state/firma-remota/state.json` | a number. |
| Log | `~/.local/state/firma-remota/firma.log` (folder 0700, file 0600) | password, OTP, session id, username and holder name are masked. File names do appear. |
| Official trusted lists | `~/.cache/firma-remota/trustlist/` | public data. |

## Behaviour
- The profile is opened with the password from the wallet. When the password is typed instead,
  a wrong one fails locally (the GCM tag doesn't verify) **before Aruba is contacted**, so it
  never counts towards an account lockout.
- Changing the password with `firma configura --salva-password` re-encrypts the profile. If the
  password was changed on Aruba's website first, the old profile can't be opened: `firma configura`
  rebuilds it from Aruba (everything in it can be fetched again; no OTP needed).
- Older versions kept account data in plain text in `config.ini` with the wallet entry
  `utente@dominio`. The first run of a newer version encrypts it into the profile, moves the
  password to the `account` entry and rewrites `config.ini` without it (`vault.migrate_legacy`).

## Not covered
- **Signed documents** contain the signer's certificate (name, tax code): that is what a digital
  signature is. They stay wherever the user saves them.
- `scripts/spike_arss.py` (developer tool) writes raw exchanges and signed test files to
  `spike-output/`; delete that folder after reading the results.
