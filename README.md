# Aruba Firma Digitale (`aruba-firma`)

Firma, verifica ed estrai documenti con la **firma digitale remota Aruba** (quella con l'app
Aruba OTP sul telefono), da riga di comando o con un'interfaccia grafica pensata per chi non
usa il terminale. Parla direttamente con il servizio pubblico ARSS di Aruba: la chiave privata
resta sui server Aruba e ogni firma è autorizzata con nome utente, password e codice OTP.

- firma di PDF (PAdES, il file resta un PDF) e di qualsiasi file (busta CAdES `.p7m`);
- più documenti con un solo codice OTP;
- timbro visibile sul PDF (pagina e angolo a scelta);
- **marca temporale** (data certa) sulle firme, scelta per account: quella di Aruba, come in Aruba Sign
  (tipo T, LT o TSD, `.p7m.tsd`), oppure una **marca gratuita** e qualificata del servizio pubblico
  belga (vedi sotto); marca temporale anche su un file da solo, senza firmarlo (`.tsd` o `.tsr`, con
  un account di marca temporale Aruba);
- verifica delle firme e delle marche temporali con l'elenco ufficiale dei certificatori (AgID /
  EU), anche "alla data"; una firma con certificato scaduto ma marcata nel periodo di validità
  resta valida; estrazione del documento da un `.p7m` o da un `.tsd`;
- più account, ognuno con un nome a scelta; credenziali solo nel portachiavi di sistema, nulla
  sul disco (vedi `docs/privacy.md`).

## Installazione su Arch Linux

Per installarlo sul computer di qualcun altro, un comando unico da incollare nel terminale (chiede
la password due volte: per installare `git` e gli strumenti di compilazione se mancano, e per installare
il pacchetto):

```bash
cd ~ && sudo pacman -S --needed --noconfirm git base-devel && if [ -d aruba-firma-digitale-remota-otp ]; then cd aruba-firma-digitale-remota-otp && git pull --ff-only; else git clone https://github.com/diegofanesi/aruba-firma-digitale-remota-otp.git && cd aruba-firma-digitale-remota-otp; fi && ./install.sh
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
repository: `sudo pacman -U aruba-firma-0.3.1-1-any.pkg.tar.zst`.)

## Uso

Interfaccia grafica: menu → *Aruba Firma Digitale*, oppure `aruba-firma-gui`. La prima firma
chiede i dati dell'account (controllati con Aruba senza OTP) e li salva nel portachiavi.

Riga di comando:

```bash
aruba-firma configura                      # aggiunge un account (nome a scelta, utente@dominio, password)
aruba-firma pdf contratto.pdf              # firma un PDF  -> contratto_firmato.pdf
aruba-firma pdf --timbro --pagina ultima --posizione basso-destra a.pdf b.pdf   # più file, un solo OTP
aruba-firma p7m fattura.xml                # busta .p7m    -> fattura.xml.p7m
aruba-firma pdf --marca x.pdf              # firma con la marca temporale di Aruba
aruba-firma pdf --marca-gratuita x.pdf     # firma con la marca gratuita del servizio pubblico belga
aruba-firma configura --marca belgio       # per sempre, per quell'account: aruba, belgio oppure no
aruba-firma p7m --marca --tipo-marca TSD x.xml   # T (predefinito), LT, oppure TSD: x.xml.p7m.tsd
aruba-firma marca nota.txt                 # marca temporale su un file, senza firma né OTP -> nota.txt.tsd
aruba-firma marca --formato tsr nota.txt   # solo la marca, nota.txt.tsr, da tenere insieme al file
aruba-firma verifica documento.pdf.p7m     # firma valida? chi ha firmato? quando? (uscita 0 valida, 5 non verificabile, 1 no)
aruba-firma verifica nota.txt.tsr [--originale nota.txt]   # marche .tsd/.tsr; --alla-data GG/MM/AAAA per il passato
aruba-firma estrai documento.pdf.p7m       # tira fuori il documento originale (anche da un .tsd)
aruba-firma pdf --account Papà x.pdf       # con più account
aruba-firma configura --credenziali-marca  # un account TSA di Aruba comprato a parte
aruba-firma diagnostica [--credenziali]    # controlli utili per l'assistenza
aruba-firma <comando> --help
```

Le marche temporali non sono comprese in tutte le Firme Remote: lo sono nella «Firma Remota con
marcatura illimitata», che nel SelfCare (https://selfcare.firma-remota.it) mostra l'opzione «Marca
automaticamente tutti i documenti firmati» (il server di Aruba applica la marca, formato LT). Se il
SelfCare non mostra quell'opzione, il servizio non le include: si comprano a pacchetti e l'account di
marca temporale si salva con `configura --credenziali-marca`. Per questo la marca è disattivata finché
non la si attiva; quando è richiesta e non arriva, il file non viene salvato e il messaggio spiega cosa
fare. Per marcare un file **senza** firmarlo (`marca`, `.tsd`/`.tsr`) e per la busta `.p7m.tsd` serve
sempre un account di marca temporale, come in Aruba Sign.

### Marca temporale gratuita

In alternativa c'è la marca temporale del **governo federale belga** (servizio pubblico gratuito,
`http://tsa.belgium.be/connect`): è una marca **qualificata** secondo il regolamento europeo eIDAS e
per l'art. 41 vale come qualificata in tutti i paesi dell'Unione, Italia compresa. Si sceglie
nell'account («Marca temporale gratuita») o con `--marca-gratuita`. Aruba firma come sempre, poi il
programma chiede la marca e la aggiunge: ai PDF come marca sul documento (il PDF firmato da Aruba resta
intatto, la marca si aggiunge dopo), ai `.p7m` come marca sulla firma (CAdES-T). Al servizio arriva
solo un'impronta (hash) della firma, mai il documento.

Ogni marca ricevuta viene controllata prima di salvarla: deve riferirsi proprio a quella firma ed
essere firmata da un servizio qualificato presente negli elenchi ufficiali europei. Se il servizio non
risponde, o la risposta non supera i controlli, si riprova fino a 3 volte; poi il documento viene
salvato **firmato ma senza marca**, e il programma lo dice chiaramente (la firma resta valida).

Le condizioni d'uso del servizio
(https://repository.eid.belgium.be/downloads/timestamp/fr/timestamping.pdf) dicono che è gratuito,
**destinato a un uso non commerciale**, con limiti di volume, e che può essere interrotto in qualsiasi
momento senza garanzie. Per un uso professionale o commerciale conviene la marca di Aruba.

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
da confermare con il test live); cosa viene salvato e dove, cosa riceve il servizio della marca gratuita,
e come vengono trattati i file ricevuti da altri, in `docs/privacy.md`.
