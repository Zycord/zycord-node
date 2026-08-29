# The Homebrew tap

Two formulae. Neither is a cask, and that is deliberate — the reasoning is in
the header of each file and in [docs/INSTALL.md](../../docs/INSTALL.md).

| formula | installs |
|---|---|
| `zycord.rb` | `zcd` and `zycordd`, built from source with the release's own flags |
| `zycord-wallet.rb` | the desktop application, built from source (macOS only) |

Publishing a release:

1. Tag, and let GitHub produce the source tarball for the tag.
2. `curl -fsSL <archive-url> | shasum -a 256` and put that in `sha256`.
3. Replace `0.0.0` with the version.
4. Copy both files into the tap repository (`Formula/`) and push.

A tap is `<user>/homebrew-zycord`; users add it with
`brew tap <user>/zycord <url>`.

Every URL in both files says `PUBLISHER`, substituted at publication
([RELEASE.md](../../docs/RELEASE.md) §3). A handle in a formula URL is published
to everyone who installs.

The zeroed `sha256` and the `0.0.0` version are placeholders on purpose: a
formula committed here with a real version and a stale hash would fail
verification at install time, which is a worse failure than one that never
resolves.
