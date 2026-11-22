#!/bin/sh
set -eu
umask 077
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KEYDIR="${ROOT}/keys"
mkdir -p "$KEYDIR"
PRIVATE="$KEYDIR/pd-update-ed25519.pem"
PUBLIC="$KEYDIR/pd-update-ed25519.pub"
if [ -e "$PRIVATE" ] || [ -e "$PUBLIC" ]; then
  echo "Refusing to overwrite an existing update key." >&2
  exit 1
fi
openssl genpkey -algorithm ED25519 -out "$PRIVATE"
openssl pkey -in "$PRIVATE" -pubout -out "$PUBLIC"
chmod 600 "$PRIVATE"
chmod 644 "$PUBLIC"
echo "Private signing key: $PRIVATE (keep offline; never commit)"
echo "Public verification key: $PUBLIC (commit this file)"
