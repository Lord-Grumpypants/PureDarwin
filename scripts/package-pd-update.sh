#!/bin/sh
set -eu
if [ "$#" -ne 3 ]; then
  echo "usage: $0 <system-root> <version> <ed25519-private-key>" >&2
  exit 2
fi
ROOT=$(CDPATH= cd -- "$1" && pwd)
VERSION=$2
KEY=$(CDPATH= cd -- "$(dirname -- "$3")" && pwd)/$(basename -- "$3")
OUT=${PD_UPDATE_OUT:-"$PWD/pd-update-release"}
mkdir -p "$OUT"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/pd-update.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
set --
for d in System usr bin sbin etc Applications; do
  [ ! -e "$ROOT/$d" ] || set -- "$@" "$d"
done
[ "$#" -gt 0 ] || { echo "No supported system roots found" >&2; exit 1; }
python3 - "$ROOT" "$TMP/update.tar" "$@" <<'PY'
import os
import sys
import tarfile

root, output, *names = sys.argv[1:]
def root_owner(member):
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "wheel"
    return member

with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
    for name in names:
        archive.add(os.path.join(root, name), arcname=name, recursive=True, filter=root_owner)
PY
xz -T0 -9e -c "$TMP/update.tar" > "$TMP/update.tar.xz"
HASH=$(shasum -a 256 "$TMP/update.tar.xz" | awk '{print $1}')
SIZE=$(python3 -c 'import os,sys; print(os.path.getsize(sys.argv[1]))' "$TMP/update.tar.xz")
{
  printf 'PDUPDATE1\n'
  printf 'version=%s\n' "$VERSION"
  printf 'sha256=%s\n' "$HASH"
  printf 'size=%s\n' "$SIZE"
} > "$TMP/manifest"
openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$TMP/manifest" -out "$TMP/manifest.sig"
cp "$TMP/update.tar.xz" "$OUT/update.tar.xz"
cp "$TMP/manifest" "$OUT/manifest"
cp "$TMP/manifest.sig" "$OUT/manifest.sig"
echo "Created signed update in $OUT"
echo "Publish these three files together: manifest, manifest.sig, update.tar.xz"
