#!/usr/bin/env bash
# Builds the Arch package (one file: dist/arch/aruba-firma-<version>-<rel>-any.pkg.tar.zst) and
# installs it. makepkg downloads the five bundled Python libraries from PyPI (checksums pinned in
# the PKGBUILD) and pacman installs the official dependencies; sudo is used only for pacman.
#
#   packaging/arch/build.sh               build, run the tests, install (asks for sudo)
#   packaging/arch/build.sh --no-install  only check that the package builds (no tests, no
#                                         dependency checks; nothing is installed)
#
# The tarball comes from `git archive HEAD`: commit before building.
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
git -C "$root" archive --format=tar.gz --prefix="aruba-firma-$version/" \
  -o "$here/aruba-firma/aruba-firma-$version.tar.gz" HEAD

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
