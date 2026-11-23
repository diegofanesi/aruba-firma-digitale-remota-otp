#!/usr/bin/env bash
# Builds the Arch packages: first the five Python libraries that are not in the official
# repositories (packaging/arch/deps), then aruba-firma itself. Every package is installed right
# after it is built, because the next ones depend on it; that is the only reason sudo is used.
# All the packages end up in dist/arch/, ready for `sudo pacman -U dist/arch/*.pkg.tar.zst`
# on another Arch machine.
#
#   packaging/arch/build.sh               build and install everything (asks for sudo)
#   packaging/arch/build.sh --no-install  only check that the packages build (skips tests and
#                                         dependency checks; nothing is installed)
#
# The aruba-firma tarball comes from `git archive HEAD`: commit before building.
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

build_one() {
  local dir=$1 pkg
  (cd "$dir" && makepkg "${flags[@]}")
  pkg=$(ls -t "$dir"/*.pkg.tar.zst | head -1)
  cp "$pkg" "$out/"
  if (( install )); then
    sudo pacman -U --needed --noconfirm "$pkg"
  fi
}

for dep in python-uritools python-signxml python-xsdata python-pyhanko-certvalidator python-pyhanko; do
  build_one "$here/deps/$dep"
done

version=$(python3 -c "import tomllib; print(tomllib.load(open('$root/pyproject.toml', 'rb'))['project']['version'])")
sed -i "s/^pkgver=.*/pkgver=$version/" "$here/aruba-firma/PKGBUILD"
git -C "$root" archive --format=tar.gz --prefix="aruba-firma-$version/" \
  -o "$here/aruba-firma/aruba-firma-$version.tar.gz" HEAD
build_one "$here/aruba-firma"

echo
echo "Pacchetti pronti in $out:"
ls -1 "$out"
echo
echo "Su un altro computer Arch:  sudo pacman -U $(basename "$out")/*.pkg.tar.zst"
