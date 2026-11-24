#!/bin/sh
set -eu
if [ "$#" -ne 5 ]; then
  echo "usage: $0 <system-root> <version> <build> <ed25519-private-key> <archive-url>" >&2
  exit 2
fi
ROOT=$(CDPATH= cd -- "$1" && pwd)
VERSION=$2
BUILD=$3
KEY=$(CDPATH= cd -- "$(dirname -- "$4")" && pwd)/$(basename -- "$4")
URL=$5
case "$BUILD" in ""|*[!A-Za-z0-9._-]*) echo "invalid build identifier" >&2; exit 1 ;; esac
case "$URL" in https://github.com/Lord-Grumpypants/PureDarwin/releases/download/*/update.tar.xz) ;; *) echo "invalid GitHub Release asset URL" >&2; exit 1 ;; esac
OUT=${PD_UPDATE_OUT:-"$PWD/pd-update-release"}
mkdir -p "$OUT"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/pd-update.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
skip() { case " ${PD_UPDATE_SKIP_ROOTS:-} " in *" $1 "*) return 0 ;; esac; return 1; }
# /Applications is shared with the user. Only .app bundles are packaged,
# preserving their paths while omitting ordinary parent directories such as Utilities.
set --
for d in System usr bin sbin etc Applications; do
  skip "$d" && continue
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
        path = os.path.join(root, name)

        if name == "Applications":
            # Keep the root entry, but do not recursively archive user-owned
            # directories. Add every real .app bundle at its original path.
            archive.add(path, arcname=name, recursive=False, filter=root_owner)
            for current, dirs, _files in os.walk(path, topdown=True, followlinks=False):
                dirs.sort()
                for entry in dirs[:]:
                    app_path = os.path.join(current, entry)
                    if entry.endswith(".app") and not os.path.islink(app_path):
                        relative = os.path.relpath(app_path, root)
                        archive.add(
                            app_path,
                            arcname=relative,
                            recursive=True,
                            filter=root_owner,
                        )
                        # An app bundle is an atomic application tree. Do not
                        # separately discover nested .app directories inside it.
                        dirs.remove(entry)
            continue

        archive.add(path, arcname=name, recursive=True, filter=root_owner)
PY
xz -T0 -9e -c "$TMP/update.tar" > "$TMP/update.tar.xz"
HASH=$(shasum -a 256 "$TMP/update.tar.xz" | awk '{print $1}')
SIZE=$(python3 -c 'import os,sys; print(os.path.getsize(sys.argv[1]))' "$TMP/update.tar.xz")
{
  printf 'PDUPDATE1\n'
  printf 'version=%s\n' "$VERSION"
  printf 'build=%s\n' "$BUILD"
  printf 'sha256=%s\n' "$HASH"
  printf 'size=%s\n' "$SIZE"
  printf 'url=%s\n' "$URL"
} > "$TMP/manifest"
openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$TMP/manifest" -out "$TMP/manifest.sig"
cp "$TMP/update.tar.xz" "$OUT/update.tar.xz"
cp "$TMP/manifest" "$OUT/manifest"
cp "$TMP/manifest.sig" "$OUT/manifest.sig"
echo "Created signed update in $OUT"
echo "Publish manifest and manifest.sig to the update feed; upload update.tar.xz to the GitHub Release."
