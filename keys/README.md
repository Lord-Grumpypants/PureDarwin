# PureDarwin update signing key

Generate the Ed25519 keypair with:

```sh
./scripts/pd-update-keygen.sh
```

Keep `keys/pd-update-ed25519.pem` offline and out of Git. Commit only
`keys/pd-update-ed25519.pub`. The installer trusts that public key at
`/System/Library/PrivateFrameworks/PDUpdate.framework/Resources/update-ed25519.pub`.

Create a release archive with:

```sh
./scripts/package-pd-update.sh /path/to/system-root 0.1.1 keys/pd-update-ed25519.pem
```

The archive contains only the supported top-level system roots: `System`,
`usr`, `bin`, `sbin`, `etc`, and `Applications`. The installer swaps
those directories with a persistent rollback journal. Updates are currently
disabled for APFS images. Do not publish an update until its public key is
included in the image.
