# Aruba Firma Digitale (`aruba-firma`)

Firma, verifica ed estrai documenti con la **firma digitale remota Aruba** (quella con l'app
Aruba OTP sul telefono), da riga di comando o con un'interfaccia grafica pensata per chi non
usa il terminale. Parla direttamente con il servizio pubblico ARSS di Aruba: la chiave privata
resta sui server Aruba e ogni firma è autorizzata con nome utente, password e codice OTP.

- firma di PDF (PAdES, il file resta un PDF) e di qualsiasi file (busta CAdES `.p7m`);
- più documenti con un solo codice OTP;
- timbro visibile sul PDF (pagina e angolo a scelta);
- verifica delle firme con l'elenco ufficiale dei certificatori (AgID / EU) ed estrazione del
  documento da un `.p7m`;
- più account, ognuno con un nome a scelta; credenziali solo nel portachiavi di sistema, nulla
  sul disco (vedi `docs/privacy.md`).

## Installazione su Arch Linux

Un solo pacchetto, costruito una volta con `packaging/arch/build.sh` (vedi sotto):

```bash
sudo pacman -U aruba-firma-0.1.0-1-any.pkg.tar.zst
```

Le dipendenze sono pacchetti ufficiali che pacman installa da sé; le poche librerie Python che
mancano nei repository (pyHanko e le sue, usate per verificare le firme) sono incluse nel
pacchetto in `/usr/lib/aruba-firma/vendor` e vengono usate solo se non ce n'è una copia di sistema.

Si ottengono i comandi `aruba-firma` e `aruba-firma-gui` e la voce **Aruba Firma Digitale**
nel menu delle applicazioni. Su KDE Plasma nome utente e password vengono ricordati in KWallet.

## Uso

Interfaccia grafica: menu → *Aruba Firma Digitale*, oppure `aruba-firma-gui`. La prima firma
chiede i dati dell'account (controllati con Aruba senza OTP) e li salva nel portachiavi.

Riga di comando:

```bash
aruba-firma configura                      # aggiunge un account (nome a scelta, utente@dominio, password)
aruba-firma pdf contratto.pdf              # firma un PDF  -> contratto_firmato.pdf
aruba-firma pdf --timbro --pagina ultima --posizione basso-destra a.pdf b.pdf   # più file, un solo OTP
aruba-firma p7m fattura.xml                # busta .p7m    -> fattura.xml.p7m
aruba-firma verifica documento.pdf.p7m     # firma valida? chi ha firmato? quando?
aruba-firma estrai documento.pdf.p7m       # tira fuori il documento originale
aruba-firma pdf --account Papà x.pdf       # con più account
aruba-firma diagnostica [--credenziali]    # controlli utili per l'assistenza
aruba-firma <comando> --help
```

Il dominio di firma è `firma` per le firme comprate su pec.it (il selfcare mostra
`utente@firma`); le firme rilasciate da un'organizzazione hanno il loro dominio (`frNomeEnte`).

## Sviluppo

```bash
uv sync                     # ambiente con Python 3.13 e tutte le dipendenze
uv run pytest               # test offline (nessun OTP viene mai usato)
FIRMA_LIVE=1 FIRMA_OTP=12345678 uv run pytest -m live   # un giro reale: usa un OTP
uv run aruba-firma --help
uv run aruba-firma-gui
```

Per costruire il pacchetto Arch (makepkg scarica le librerie incluse da PyPI con checksum
fissati; sudo serve solo a pacman per installare):

```bash
git commit -am "..."        # build.sh impacchetta HEAD
packaging/arch/build.sh     # risultato in dist/arch/, poi installato
```

Note tecniche sul servizio Aruba in `docs/arss-notes.md`; cosa viene salvato e dove in
`docs/privacy.md`. Le marche temporali non sono supportate.
