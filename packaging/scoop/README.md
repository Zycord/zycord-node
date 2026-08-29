# The Scoop manifest

`zycord.json` is the manifest a Scoop bucket serves. It is kept here, in the
repository it describes, so that the bucket is a mirror of a reviewed file
rather than a second place where the release is defined.

Publishing a release:

1. `make dist` and note the two Windows hashes from `dist/SHA256SUMS`.
2. Replace `0.0.0` and both `hash` fields in `zycord.json`.
3. Copy it into the bucket repository (`bucket/zycord.json`) and push.

The `autoupdate` block points at the release's own `SHA256SUMS`, so subsequent
versions are picked up by `scoop update` without anyone editing a hash by hand —
which is the step where a wrong hash gets pasted.

Every URL says `PUBLISHER`, substituted at publication ([RELEASE.md](../../docs/RELEASE.md) §3): a handle in a package URL is published to everyone who installs, and §3's identity audit is easy to run over Go source and easy to forget over a manifest.

The version placeholder is `0.0.0` rather than a real number on purpose: a
manifest committed here with a live version and a stale hash would install
something that fails verification, and a zeroed hash fails loudly instead.
