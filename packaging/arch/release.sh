#!/usr/bin/env bash
# Tags the version in pyproject.toml and pushes it to GitHub, so the PKGBUILD's source= (a GitHub
# tag archive URL) has something to fetch. Run this once per version, before packaging/arch/build.sh.
#
#   packaging/arch/release.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

if [[ -n "$(git -C "$root" status --porcelain)" ]]; then
  echo "Working tree not clean; commit first." >&2
  exit 1
fi

version=$(python3 -c "import tomllib; print(tomllib.load(open('$root/pyproject.toml', 'rb'))['project']['version'])")
tag="v$version"

if git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "Tag $tag already exists locally." >&2
else
  git -C "$root" tag -a "$tag" -m "aruba-firma $version"
fi

git -C "$root" push origin "$tag"

# Pin the checksum of the archive GitHub serves for the tag, and refresh .SRCINFO to match.
pkgbuild="$here/aruba-firma/PKGBUILD"
reponame=$(sed -n 's/^_reponame=//p' "$pkgbuild")
url="https://github.com/diegofanesi/$reponame/archive/refs/tags/$tag.tar.gz"
hash=$(curl -fsSL "$url" | sha256sum | cut -d' ' -f1)
sed -i -e "s/^pkgver=.*/pkgver=$version/" -e "s/^_pkgsource_sha256=.*/_pkgsource_sha256='$hash'/" "$pkgbuild"
(cd "$here/aruba-firma" && makepkg --printsrcinfo > .SRCINFO)
echo "Pushed $tag; PKGBUILD pinned to $hash (commit PKGBUILD and .SRCINFO). Now run:  packaging/arch/build.sh"
