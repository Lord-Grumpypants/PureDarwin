# PureDarwin update signing key

Generate the Ed25519 keypair with:

```sh
sh scripts/pd-update-keygen.sh
```

Keep `keys/pd-update-ed25519.pem` offline and out of Git. Commit only
`keys/pd-update-ed25519.pub`. The installer trusts that public key at
`/System/Library/PrivateFrameworks/PDUpdate.framework/Resources/update-ed25519.pub`.

Create a release archive with:

```sh
sh scripts/package-pd-update.sh /path/to/system-root 0.1.1 keys/pd-update-ed25519.pem
```

The archive contains only the supported top-level system roots: `System`,
`usr`, `bin`, `sbin`, `etc`, and `Applications`. The installer swaps
those directories with a persistent rollback journal. Updates are currently
disabled for APFS images. Do not publish an update until its public key is
included in the image.

After committing the public key and building an image, enable GitHub Pages for
the fork with the `gh-pages` branch and `/(root)` as its source. Publish each
signed release with:

```sh
sh scripts/publish-pd-update.sh ./pd-update-release
```

The Settings pane downloads from the matching Pages URL. The update installer
does not trust a key from the download cache; the public key must be present in
the booted system image.


## Automated GitHub Actions publishing

The `.github/workflows/publish-update.yml` workflow builds the x86_64 release image,
extracts its ext4 root filesystem, packages the supported system directories, signs
the manifest, and publishes the feed to the `gh-pages` branch.

1. Generate the Ed25519 keypair with `sh scripts/pd-update-keygen.sh`.
2. Commit `keys/pd-update-ed25519.pub` and rebuild the image with that public key embedded.
3. In the repository's **Settings → Secrets and variables → Actions**, create the
   repository secret `PD_UPDATE_ED25519_PRIVATE_KEY_B64`. Its value is the one-line
   base64 encoding of the PEM private key (for example,
   `base64 < keys/pd-update-ed25519.pem | tr -d '\\n'`). Do not commit the PEM file.
4. Enable GitHub Pages for the repository, using the `gh-pages` branch and root folder.
5. Merge this workflow into the default branch. It cannot receive release or
   manual-dispatch events until the workflow exists on the default branch.
6. Publish a GitHub Release whose tag is the update version, or run
   **Actions → Publish signed update → Run workflow** and supply the version.

The workflow verifies that the public key derived from the Actions secret matches
`keys/pd-update-ed25519.pub` before signing or publishing. It uses the repository
`GITHUB_TOKEN` to publish the feed; no separate Pages deployment token is needed.
