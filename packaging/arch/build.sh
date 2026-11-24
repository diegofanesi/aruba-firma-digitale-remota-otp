#!/usr/bin/env bash
# Builds the Arch package (one file: dist/arch/aruba-firma-<version>-<rel>-any.pkg.tar.zst) and
# installs it. makepkg downloads the tagged source from GitHub and the five bundled Python
# libraries from PyPI (all checksums pinned in the PKGBUILD); sudo is used only for pacman.
#
#   packaging/arch/release.sh             once per version: tags HEAD and pushes it to GitHub
#   packaging/arch/build.sh               build, run the tests, install (asks for sudo)
#   packaging/arch/build.sh --no-install  only check that the package builds (no tests, no
#                                         dependency checks; nothing is installed)
#
# This is also exactly what AUR's own build (and anyone running makepkg on the PKGBUILD) does:
# fetch the pushed tag over the network. There is no local/offline shortcut, by design — it is
# the actual thing being verified.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out="$root/dist/arch"
mkdir -p "$out"

install=1
flags=(-sf --noconfirm)            # -s: pacman installs the repository dependencies (sudo)
if [[ "${1:-}" == "--no-install" ]]; then
  install=0
  flags=(-fd --nocheck)             # -d: don't require the dependencies to be installed
fi

version=$(python3 -c "import tomllib; print(tomllib.load(open('$root/pyproject.toml', 'rb'))['project']['version'])")
sed -i "s/^pkgver=.*/pkgver=$version/" "$here/aruba-firma/PKGBUILD"

tag="v$version"
if ! git -C "$root" ls-remote --exit-code --tags origin "$tag" >/dev/null 2>&1; then
  echo "Tag $tag isn't on GitHub yet. Run packaging/arch/release.sh first." >&2
  exit 1
fi

(cd "$here/aruba-firma" && makepkg "${flags[@]}")
pkg=$(ls -t "$here/aruba-firma"/*.pkg.tar.zst | head -1)
rm -f "$out"/*.pkg.tar.zst           # dist/arch holds only the current package
cp "$pkg" "$out/"
if (( install )); then
  sudo pacman -U --noconfirm "$pkg"  # no --needed: a rebuild with the same version is reinstalled
fi

echo
echo "Pacchetto pronto: $out/$(basename "$pkg")"
echo "Su un altro computer Arch:  sudo pacman -U $(basename "$pkg")"
