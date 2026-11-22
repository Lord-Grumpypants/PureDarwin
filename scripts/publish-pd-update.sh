#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
  echo "usage: $0 <pd-update-release-directory>" >&2
  exit 2
fi
ROOT=$(git rev-parse --show-toplevel)
REMOTE=$(git -C "$ROOT" remote get-url fork)
RELEASE=$(CDPATH= cd -- "$1" && pwd)
for f in manifest manifest.sig update.tar.xz; do
  [ -s "$RELEASE/$f" ] || { echo "missing release file: $f" >&2; exit 1; }
done
TMP=$(mktemp -d "${TMPDIR:-/tmp}/pd-pages.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM
if git clone --quiet --depth 1 --branch gh-pages "$REMOTE" "$TMP/site" 2>/dev/null; then
  :
else
  rm -rf "$TMP/site"
  git clone --quiet --no-checkout "$REMOTE" "$TMP/site"
  git -C "$TMP/site" checkout --orphan gh-pages
  git -C "$TMP/site" rm -rf . >/dev/null 2>&1 || true
fi
mkdir -p "$TMP/site/updates/x86_64"
touch "$TMP/site/.nojekyll"
cp "$RELEASE/manifest" "$RELEASE/manifest.sig" "$RELEASE/update.tar.xz" "$TMP/site/updates/x86_64/"
cat > "$TMP/site/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>PureDarwin updates</title>
<p>PureDarwin update feed.</p>
HTML
git -C "$TMP/site" add .nojekyll updates/x86_64/manifest updates/x86_64/manifest.sig updates/x86_64/update.tar.xz index.html
git -C "$TMP/site" -c user.name="PureDarwin Update Publisher" -c user.email="noreply@users.noreply.github.com" commit -m "Publish PureDarwin update"
git -C "$TMP/site" push "$REMOTE" gh-pages
echo "Published to https://lord-grumpypants.github.io/PureDarwin/updates/x86_64/"
