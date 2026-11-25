#!/usr/bin/env bash
# Builds aruba-firma from the code in THIS checkout and installs it with pacman. No GitHub
# release or tag is needed — unlike packaging/arch/build.sh (used for AUR submission), which
# always fetches the tagged source from GitHub instead, as AUR requires.
#
#   git clone https://github.com/diegofanesi/aruba-firma-digitale-remota-otp.git
#   cd aruba-firma-digitale-remota-otp
#   ./install.sh                 # first install
#
#   git pull
#   ./install.sh --upgrade       # rebuild and reinstall whatever is now checked out
#
# Only commits already committed to git are picked up (via `git archive HEAD`, not the raw
# working tree): uncommitted edits are never installed, and the script warns if there are any.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Uso:
  ./install.sh             installa (o reinstalla) aruba-firma dal codice in questa cartella
  ./install.sh --upgrade   come sopra; usalo dopo un "git pull" per passare all'ultima versione
  ./install.sh --help      mostra questo messaggio
USAGE
}

mode=install
case "${1:-}" in
  "") ;;
  --upgrade) mode=upgrade ;;
  -h|--help) usage; exit 0 ;;
  *) echo "Opzione sconosciuta: $1" >&2; usage; exit 2 ;;
esac

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"

if ! command -v pacman >/dev/null 2>&1; then
  echo "Questo script serve solo su Arch Linux (non trovo il comando pacman)." >&2
  exit 1
fi
for tool in fakeroot strip make; do  # the base-devel group: makepkg can't build without it
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Manca «$tool»: installa prima gli strumenti di compilazione con  sudo pacman -S --needed base-devel" >&2
    exit 1
  fi
done
if [[ ! -d .git || ! -f pyproject.toml || ! -f packaging/arch/aruba-firma/PKGBUILD ]]; then
  echo "Esegui questo script dalla cartella del repository clonato con git (contiene .git e pyproject.toml)." >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Avviso: in questa cartella ci sono modifiche non salvate con 'git commit'." >&2
  echo "Verrà installato solo il codice già commesso, non le modifiche in sospeso." >&2
fi

pkgname=$(grep -m1 '^pkgname=' packaging/arch/aruba-firma/PKGBUILD | cut -d= -f2-)
reponame=$(grep -m1 '^_reponame=' packaging/arch/aruba-firma/PKGBUILD | cut -d= -f2-)
if [[ -z "$pkgname" || -z "$reponame" ]]; then
  echo "Impossibile leggere pkgname/_reponame da packaging/arch/aruba-firma/PKGBUILD." >&2
  exit 1
fi
version=$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])")
before=$(pacman -Q "$pkgname" 2>/dev/null | awk '{print $2}' || true)

if [[ "$mode" == upgrade ]]; then
  echo "Aggiornamento di $pkgname alla versione $version dal codice in questa cartella..."
else
  echo "Installazione di $pkgname $version dal codice in questa cartella..."
fi
echo "Verrà chiesta la password per installare (serve pacman/sudo)."
sudo -v

build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
cp packaging/arch/aruba-firma/PKGBUILD "$build/"

# A tarball of HEAD, with the same internal folder name GitHub's own tag archives use, so
# build()/check()/package() in the PKGBUILD work unchanged either way.
tarball="$build/$pkgname-$version.tar.gz"
git archive --format=tar.gz --prefix="$reponame-$version/" -o "$tarball" HEAD
hash=$(sha256sum "$tarball" | awk '{print $1}')

sed -i \
  -e "s/^pkgver=.*/pkgver=$version/" \
  -e "s|^_pkgsource=.*|_pkgsource=\"$pkgname-\$pkgver.tar.gz\"|" \
  -e "s/^_pkgsource_sha256=.*/_pkgsource_sha256='$hash'/" \
  "$build/PKGBUILD"

(cd "$build" && makepkg -sfi --noconfirm --nocheck)

after=$(pacman -Q "$pkgname" 2>/dev/null | awk '{print $2}' || true)
echo
if [[ -z "$before" ]]; then
  echo "Installato: $pkgname $after."
elif [[ "$before" == "$after" ]]; then
  echo "$pkgname $after era già installato: reinstallato con il codice più recente."
else
  echo "Aggiornato da $before a $after."
fi
