# Aruba Firma Digitale (`aruba-firma`)

Firma, verifica ed estrai documenti con la **firma digitale remota Aruba** (quella con l'app
Aruba OTP sul telefono), da riga di comando o con un'interfaccia grafica pensata per chi non
usa il terminale. Parla direttamente con il servizio pubblico ARSS di Aruba: la chiave privata
resta sui server Aruba e ogni firma è autorizzata con nome utente, password e codice OTP.

- firma di PDF (PAdES, il file resta un PDF) e di qualsiasi file (busta CAdES `.p7m`);
- più documenti con un solo codice OTP;
- timbro visibile sul PDF (pagina e angolo a scelta);
- **marca temporale** (data certa) sulle firme, come in Aruba Sign: attiva per impostazione
  predefinita, tipo T, LT o TSD (`.p7m.tsd`); marca temporale anche su un file da solo, senza
  firmarlo (`.tsd` o `.tsr`);
- verifica delle firme e delle marche temporali con l'elenco ufficiale dei certificatori (AgID /
  EU), anche "alla data"; una firma con certificato scaduto ma marcata nel periodo di validità
  resta valida; estrazione del documento da un `.p7m` o da un `.tsd`;
- più account, ognuno con un nome a scelta; credenziali solo nel portachiavi di sistema, nulla
  sul disco (vedi `docs/privacy.md`).

## Installazione su Arch Linux

Per installarlo sul computer di qualcun altro, un comando unico da incollare nel terminale (chiede
la password due volte: per installare `git` se manca, e per installare il pacchetto):

```bash
cd ~ && sudo pacman -S --needed --noconfirm git && if [ -d aruba-firma-digitale-remota-otp ]; then cd aruba-firma-digitale-remota-otp && git pull; else git clone https://github.com/diegofanesi/aruba-firma-digitale-remota-otp.git && cd aruba-firma-digitale-remota-otp; fi && ./install.sh
```

Crea una sola cartella, `~/aruba-firma-digitale-remota-otp`, senza toccare altro nella home. Si
può incollare di nuovo lo stesso comando in futuro per aggiornare: se la cartella esiste già fa
`git pull` invece di clonare da capo, e `./install.sh` reinstalla con il codice più recente.

Chiede la password di amministratore perché installa un programma: incolla nel terminale solo
comandi che ti manda chi ti ha dato questo, mai comandi arrivati da sconosciuti.

Lo stesso, passo per passo (più chiaro se lo esegui tu stesso):

```bash
git clone https://github.com/diegofanesi/aruba-firma-digitale-remota-otp.git
cd aruba-firma-digitale-remota-otp
./install.sh
```

Costruisce il pacchetto dal codice appena scaricato e lo installa con pacman (viene chiesta la
password di amministratore). Per aggiornare più avanti:

```bash
git pull
./install.sh --upgrade
```

Le dipendenze sono pacchetti ufficiali che pacman installa da sé; le poche librerie Python che
mancano nei repository (pyHanko e le sue, usate per verificare le firme) sono incluse nel
pacchetto in `/usr/lib/aruba-firma/vendor` e vengono usate solo se non ce n'è una copia di sistema.

Si ottengono i comandi `aruba-firma` e `aruba-firma-gui` e la voce **Aruba Firma Digitale**
nel menu delle applicazioni. Su KDE Plasma nome utente e password vengono ricordati in KWallet.

Per disinstallare: `sudo pacman -Rs aruba-firma`.

(In alternativa, se qualcuno ti ha dato solo il file `.pkg.tar.zst` senza il resto del
repository: `sudo pacman -U aruba-firma-0.2.0-1-any.pkg.tar.zst`.)

## Uso

Interfaccia grafica: menu → *Aruba Firma Digitale*, oppure `aruba-firma-gui`. La prima firma
chiede i dati dell'account (controllati con Aruba senza OTP) e li salva nel portachiavi.

Riga di comando:

```bash
aruba-firma configura                      # aggiunge un account (nome a scelta, utente@dominio, password)
aruba-firma pdf contratto.pdf              # firma un PDF  -> contratto_firmato.pdf
aruba-firma pdf --timbro --pagina ultima --posizione basso-destra a.pdf b.pdf   # più file, un solo OTP
aruba-firma p7m fattura.xml                # busta .p7m    -> fattura.xml.p7m
aruba-firma pdf --senza-marca x.pdf        # le firme hanno la marca temporale; così no (o: configura --marca no)
aruba-firma p7m --tipo-marca TSD x.xml     # T (predefinito), LT, oppure TSD: x.xml.p7m.tsd
aruba-firma marca nota.txt                 # marca temporale su un file, senza firma né OTP -> nota.txt.tsd
aruba-firma marca --formato tsr nota.txt   # solo la marca, nota.txt.tsr, da tenere insieme al file
aruba-firma verifica documento.pdf.p7m     # firma valida? chi ha firmato? quando? (uscita 0 valida, 5 non verificabile, 1 no)
aruba-firma verifica nota.txt.tsr [--originale nota.txt]   # marche .tsd/.tsr; --alla-data GG/MM/AAAA per il passato
aruba-firma estrai documento.pdf.p7m       # tira fuori il documento originale (anche da un .tsd)
aruba-firma pdf --account Papà x.pdf       # con più account
aruba-firma configura --credenziali-marca  # un account TSA separato (altrimenti si usano le credenziali di firma)
aruba-firma diagnostica [--credenziali]    # controlli utili per l'assistenza
aruba-firma <comando> --help
```

La marca temporale è inclusa nella Firma Remota Aruba (nelle altre firme Aruba si compra a pacchetti):
se Aruba la rifiuta, il file non viene salvato e il messaggio spiega cosa fare (riprovare senza marca,
attivare la marca automatica nel SelfCare, oppure salvare le credenziali TSA con `configura
--credenziali-marca`).

Il dominio di firma è `firma` per le firme comprate su pec.it (il selfcare mostra
`utente@firma`); le firme rilasciate da un'organizzazione hanno il loro dominio (`frNomeEnte`).

## Sviluppo

```bash
uv sync                     # ambiente con Python 3.13 e tutte le dipendenze
uv run pytest               # test offline (nessun OTP viene mai usato)
FIRMA_LIVE=1 uv run pytest -m live -s   # un giro reale: chiede un OTP nel terminale
packaging/check-vendored.py # le librerie incluse nel pacchetto sono all'ultima versione? (da fare ogni tanto)
uv run aruba-firma --help
uv run aruba-firma-gui
```

Per costruire il pacchetto Arch (makepkg scarica le librerie incluse da PyPI con checksum
fissati; sudo serve solo a pacman per installare):

```bash
git commit -am "..."        # build.sh impacchetta HEAD
packaging/arch/build.sh     # risultato in dist/arch/, poi installato
```

Note tecniche sul servizio Aruba in `docs/arss-notes.md` (comprese le ipotesi sulle marche temporali
da confermare con il test live); cosa viene salvato e dove, e come vengono trattati i file ricevuti da
altri, in `docs/privacy.md`.
