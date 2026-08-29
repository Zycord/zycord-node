# Installing Zycord

Two programs and one application:

| | |
|---|---|
| `zcd` | the command-line tool: keys, wallets, genesis, the golden vectors, and `zcd ui` |
| `zycordd` | the node: validates, mines, serves peers, answers a read-only RPC |
| **Zycord Wallet** | a desktop window around the same wallet interface `zcd ui` serves |

Running a node for real is [RUNNING.md](RUNNING.md). This document is about
getting the files onto a machine and knowing what you got.

---

## Why your operating system will warn you, and why there is no certificate

An unsigned executable is blocked by SmartScreen on Windows and by Gatekeeper on
macOS. The usual fix is a code-signing certificate. That fix is unavailable here
**by construction, not by budget**, and the reason is worth understanding before
you install anything — a user who knows why the warning appears is a user who is
much harder to phish with a fake installer.

An Authenticode certificate is a certificate authority attesting to a **verified
legal identity**. That is its entire function; there is no version of it without
a legal name in it. Apple Developer ID is the same problem with a different
vendor: an individual account publishes the developer's legal name in the
certificate's Team Name field.

Zycord is published pseudonymously, and [RELEASE.md](RELEASE.md) commits the
project to keeping it that way — a pseudonym (§1), UTC-normalised timestamps
(§2), an identity audit before every release (§3), and a bootstrap list held to
the same rule (§4) — today with one declared exception, the public testnet's
launch seed, which §4 carries openly rather than quietly. Buying a certificate
would undo all of it at once.

**So the pseudonym is kept.** That is not a hole in the trust story; it selects a
different one, and for this project a stronger one:

> A certificate asserts *"this came from entity X."*
> A reproducible build asserts *"this came from this source, and anyone can check."*

For an anonymous L1 the second is the argument that carries, and it is not a
slogan here: CI rebuilds `zcd` twice on every push to `main` and every tag, and fails if the two
binaries differ by a byte (`.github/workflows/ci.yml`, job `reproducible`). You
do not have to trust the person who built the binary you downloaded. You can
build it yourself and compare hashes — and if they match, the question of who
built it stops mattering.

### Two tiers of assurance, stated rather than implied

| artefact | reproducible? | joins mainnet? | why |
|---|---|---|---|
| `zcd`, `zycordd` — plain archive | **yes**, byte-identical | **no** | pure Go, `CGO_ENABLED=0`, `-trimpath`, no build id — and therefore no RandomX engine |
| `zcd`, `zycordd` — `-randomx` archive | **no** | **yes** | cgo: RandomX is C++, so a system C toolchain ends up in the output |
| Zycord Wallet, Linux and macOS | **no** | n/a | cgo: a system C toolchain and a platform SDK end up in the output |
| Zycord Wallet, Windows | **yes**, byte-identical binary | n/a | no cgo: Wails reaches WebView2 through pure Go |

**The first two rows are disjoint sets, and that is the most important sentence
on this page.** Mainnet and the public testnet both declare
`pow_engine: randomx-v1`. RandomX is compiled only under a build tag that needs
a C compiler, and a node that cannot verify a network's engine refuses to start
on it rather than falling back to something weaker — so the archive you can
rebuild byte for byte is **not** the archive you can mine with, and the archive
you can mine with is **not** one anybody can attest. There is no third archive
that is both, and pretending otherwise would be the blur the rest of this
section exists to prevent.

What that means for you, in one line each:

- **You want to run a node or mine.** Take the archive with `-randomx` in its
  name. Verify it against `SHA256SUMS.randomx` — a transfer check, not an
  attestation — and read the source, which is the same source the attested tier
  is built from.
- **You want to check that this project's source is what it says it is.** Take
  the plain archive, rebuild it with `make build`, and compare against
  `SHA256SUMS.binaries`. That binary runs `--devnet` and refuses mainnet; what
  it is for is the check, and the check covers every line of consensus code the
  `-randomx` binary runs too. Only the work function differs, and it is the one
  part of the tree that is a vendored copy of somebody else's published,
  independently pinned implementation (`core/pow/randomx/PINNED`).
- **You do not know which you have.** Ask the binary:

  ```sh
  zcd version     # the engine THIS BINARY carries
  zcd params      # the engine the NETWORK requires
  ```

  If those two name the same engine, `zycordd` will start. If they do not, it
  will refuse — deliberately, at start-up, with the reason printed — rather than
  accepting one BLAKE3 pass as proof of work for every header it ever sees.

**Windows gets no `-randomx` archive, and it is a release-pipeline limit rather
than a code one.** A local `make build-randomx` on Windows with a MinGW-w64
toolchain does work — measured, `zcd version` on the result names `randomx-v1` —
but nothing in the release builds it: cgo cannot be cross-compiled from the
Linux runner without a mingw toolchain in the image, and the `windows-latest`
runner ships neither GNU make nor `zip` on `PATH`, which is the same wall
[RELEASE.md](RELEASE.md) §5 records for the desktop wallet. Rather than hold the
release for it, Windows ships the pure-Go archive with this note. So on Windows:
`--devnet` runs, `zcd` works for keys and wallets against somebody else's node,
and mining means building the engine yourself. That is stated here rather than
discovered at start-up.

This is the honest version and it is not a footnote. On Linux and macOS the
desktop wallet links against the platform's webview through cgo, and `-trimpath`
plus a pinned Go toolchain stop being sufficient the moment there is cgo —
[RELEASE.md](RELEASE.md) §5 said so before this application existed.

WebView2 is a runtime the machine already has rather than a library to link
against, so the Windows wallet has no cgo in it: measured, it builds at
`CGO_ENABLED=0` on a machine with no C compiler installed, and two builds of one
commit come out identical to the byte. `make dist-desktop` pins `CGO_ENABLED=0`
for that target instead of inheriting whatever the building machine happens to
have, and the Windows artefact is cross-compiled from the same Linux runner
every `zcd` artefact comes from.

Two limits on that row, stated rather than left to be discovered. It is the
**binary** that is byte-identical, not the `.zip` around it — a zip entry records
the file's modification time, so two archives of two identical binaries differ.
Compare the `.exe` after unpacking, not the archive. And the claim is about the
build being deterministic, not about the webview: the WebView2 runtime that
renders the window is Microsoft's, installed on the user's machine, and is no
more reproducible than the operating system it comes with.

**If you do not want to trust a binary you cannot reproduce, use `zcd`.** It is
a first-class interface, not a developer's fallback: `zcd ui` serves the exact
same wallet interface the desktop application shows, from a binary you can
rebuild byte for byte.

### The tactic that follows: package managers

Rather than fight SmartScreen and Gatekeeper, go through the door they leave
open. A package manager installs from a URL and a hash, requires no signature,
and does not trip either warning.

---

## Windows — Scoop

```powershell
scoop bucket add zycord https://github.com/<publisher>/scoop-zycord
scoop install zycord
```

No SmartScreen warning, and the mechanism is worth stating precisely because the
usual explanation is wrong. Scoop does **not** strip the mark of the web: there
is no `Unblock-File` and no `Zone.Identifier` handling anywhere in its source.
What happens is that the mark is never attached in the first place. Mark-of-the-
web is applied by browsers and by the Windows attachment-execution shell API, not
by raw HTTP clients, and Scoop downloads through `[Net.HttpWebRequest]` or aria2
(`lib/download.ps1`). SmartScreen's application-reputation check fires on
MOTW-tagged files launched from Explorer; a file that was never tagged, launched
through a shim from a terminal, does not reach that path at all.

The manifest is in [`packaging/scoop/zycord.json`](../packaging/scoop/zycord.json).
It pins the release URL and the SHA-256 from `SHA256SUMS`, so Scoop verifies the
download before it installs it.

**What Scoop installs runs `--devnet` and refuses mainnet and the public
testnet**, and on Windows there is no second archive that does not — see the
two-tiers table above and the Windows paragraph under it. `zcd version` prints
which engine the binary carries; on Windows it will say `dev-blake3 only`. The
manifest's notes say this at install time so it is read before a node is
started rather than after one refuses.

### Windows without Scoop

Download `zycord-<version>-windows-amd64.zip` and unzip it. A **portable zip is
deliberate**: there is no `.exe` installer and no MSI, because an unsigned
installer is precisely what triggers the worst SmartScreen path — the full-screen
"Windows protected your PC" block. Extracted files run from a terminal without
it.

The desktop wallet needs the **WebView2 runtime**, which is preinstalled on
Windows 11 and on current Windows 10. If it is missing, the window will not open
and `zcd ui` in a browser is the way round it.

## macOS — Homebrew

```sh
brew tap <publisher>/zycord https://github.com/<publisher>/homebrew-zycord
brew install <publisher>/zycord/zycord         # zcd + zycordd
brew install <publisher>/zycord/zycord-wallet  # the desktop application
```

`brew tap` names a tap as `user/repo`; a bare word is not a tap name and the
command fails before it fetches anything. The fully-qualified formula names on
the install lines are not decoration either — they are what stops a formula of
the same name in another tap from being installed instead.

Both are **formulae**, not casks, and that is the whole trick: a formula builds
from source on your machine, so the binary is not a downloaded file and has no
quarantine attribute. Gatekeeper never sees it. It also means you are not
trusting our build at all — Homebrew fetches the source tarball, checks its
SHA-256, and compiles it with your own toolchain.

**The formula builds the pure-Go binaries, so what it installs runs `--devnet`
and refuses mainnet and the public testnet.** That is the same disjointness the
two-tiers table above states, arriving through a package manager: the formula's
whole argument is that it compiles with your toolchain and needs nothing signed,
and `CGO_ENABLED=0` is part of what makes the result comparable with everybody
else's. `brew install` then `zcd version` will tell you so in as many words. To
join a network on macOS, take the `-randomx` archive for your architecture from
the releases page, or build it yourself from the tap's source with
`make build-randomx`. The formula's own caveats repeat this on install.

**A cask is the opposite and this project does not ship one:** a downloaded,
quarantined `.app` with no signature, which works only by asking people to
disable a security feature. Homebrew is closing that path deliberately —
`--no-quarantine` is deprecated in Homebrew 5.x, and unsigned, un-notarised
casks are being removed from the official tap.

### macOS from the release zip

If you download `zycord-wallet-<version>-darwin-arm64.zip` from the releases
page instead, the `.app` inside **is** quarantined and macOS will refuse to open
it. To open it anyway:

1. Double-click it. The refusal appears; dismiss it.
2. **System Settings → Privacy & Security**, scroll to the **Security** section.
3. Next to "Zycord Wallet was blocked", click **Open Anyway**.
4. Confirm, and authenticate.

Do not follow older instructions that say to right-click and choose Open.
**macOS 15 (Sequoia) removed that shortcut**; Control-click no longer overrides
Gatekeeper, and System Settings is now the only route.

The command-line tarball has no such problem: `zcd` and `zycordd` are run from
a terminal, where Gatekeeper's first-launch check applies but the `xattr -d
com.apple.quarantine` shown in the tarball's README clears it in one command.

## Linux

```sh
tar xzf zycord-<version>-linux-amd64.tar.gz
sudo install -m755 zycord-<version>-linux-amd64/zcd /usr/local/bin/
sudo install -m755 zycord-<version>-linux-amd64/zycordd /usr/local/bin/
```

No gatekeeper of any kind. Verify the checksum and the signature first — see
below.

**That archive runs `--devnet` and refuses mainnet and the public testnet.** To
join either, take the `-randomx` archive for the same platform instead — it is
the same two programs with the RandomX engine compiled in:

```sh
tar xzf zycord-<version>-linux-amd64-randomx.tar.gz
sudo install -m755 zycord-<version>-linux-amd64-randomx/zcd /usr/local/bin/
sudo install -m755 zycord-<version>-linux-amd64-randomx/zycordd /usr/local/bin/
zcd version    # must name randomx-v1
```

It is checksummed by `SHA256SUMS.randomx` and it is **not** in
`SHA256SUMS.binaries`, because it is a cgo build and nobody can rebuild it byte
for byte. Read the two-tiers table above before you decide that is acceptable;
the point of stating it is that it is your decision rather than an assumption we
made for you. `UNATTESTED.txt` inside the archive says the same thing where you
will actually be standing when you unpack it.

The desktop wallet on Linux ships as an **AppImage**, because
`libwebkit2gtk` has a different package name on every distribution and a
distro-specific package for each of them is a maintenance surface this project
does not have. See [`packaging/appimage/`](../packaging/appimage/).

## Anyone with a Go toolchain

**The Go version is `go1.26.2`, and it is part of the source.** Two Go releases
compile the same package into different machine code, so a binary is the output
of a compiler as much as of a repository — a rebuild with a different Go is a
different file, from an identical tree. `make build` therefore pins it
(`GOTOOLCHAIN=go1.26.2` in the `Makefile`) and **refuses to build** if the
toolchain in use is anything else, rather than handing you a binary whose hash
will not match and no reason why.

```sh
git clone <this repository> && cd zycord
make build
```

If you do not have `go1.26.2`, you do not have to go and find it: the pin makes
the `go` command fetch that exact toolchain on first use and check it against
Go's own checksum database. That is the only thing in this build that touches
the network.

You never have to take this page's word for which version a release used —
**the binary carries it**:

```sh
go version -m bin/zcd | head -2      # or any released zcd
```

This is also how you check a release against its own source — see
[Verifying what you downloaded](#verifying-what-you-downloaded).

**There is no `go install ...@latest` for this project, and it is not an
oversight.** `go install` resolves a module path through the module proxy, and
the root module is named `zycord` — no host, no dot in the first path element,
which the toolchain rejects outright:

```
go: zycord/cmd/zcd@latest: malformed module path "zycord/cmd/zcd": missing dot in first path element
```

The name is deliberate: `go.mod` claims no host, because a host is an identity
surface (`docs/RELEASE.md` §3). A `go install` path becomes available if and when
this repository publishes under a real module path, and not before. Until then
the clone above is the Go-toolchain route, and it is the stronger one anyway —
you build the tag you checked out rather than whatever a proxy served.

## On a server

Never `curl | sh`. Piping an unverified script into a shell is the wrong posture
for software that holds money, and it is the wrong posture even when the script
is ours — the whole argument of this page is that you should not have to trust
the publisher.

[`packaging/install.sh`](../packaging/install.sh) downloads, **verifies the
checksum and the signature, and only then installs**. Fetch it, read it, then run
it:

```sh
curl -fsSLO https://github.com/<publisher>/zycord/releases/download/v<version>/install.sh
less install.sh
sh install.sh --version v<version>
```

`install.sh` installs the **attested** archive — the pure-Go one — because that
is the tier its checksum-and-signature walk is about, and a script that verified
a signature and then installed something else would be theatre. So the binaries
it puts in `/usr/local/bin` run `--devnet` and refuse mainnet and the public
testnet, and the script says so as the last thing it prints. For a server that
is meant to join a network, unpack the `-randomx` archive by hand as shown under
[Linux](#linux) above.

To use the wallet interface on a server, do not expose a port. `zcd ui` binds
loopback and refuses anything else; forward it over ssh — the full procedure,
and what the token in the printed URL is, are in
[RUNNING.md](RUNNING.md#the-wallet-interface-over-an-ssh-tunnel).

---

## Verifying what you downloaded

### The checksum

```sh
curl -fsSLO https://github.com/<publisher>/zycord/releases/download/v<version>/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS     # shasum -a 256 --check --ignore-missing on macOS
```

`--ignore-missing` is not optional and it is not a way of being lenient.
`SHA256SUMS` covers **every** archive the release publishes — six of them — and
you downloaded one. Without the flag, the five you do not have are reported as
`FAILED open or read` and the command exits non-zero for a perfectly good
download, on the very page that tells you a mismatch means a compromised
binary. A check whose normal result is a failure is a check people learn to
ignore, so both spellings above carry the flag, and so does `install.sh`.

### The signature

`SHA256SUMS.asc` is signed with the project key. Its full fingerprint is

```
E724 39CE DD85 11F9 D607 550B 87FD 60D5 EB4A 0B29
```

and it is published in the whitepaper header ([whitepaper.md](whitepaper.md))
and in the genesis announcement ([RELEASE.md](RELEASE.md) §6). It never rotates
silently: a key that changes without a signed statement from the old one is
indistinguishable from a compromise, and should be treated as one.

**The fingerprint is the anchor, not the key file.** Get the key from wherever
is convenient and then check what you got against the line above; a key file
whose fingerprint is that one is the project key no matter which host handed it
to you, and one whose fingerprint is anything else is worthless no matter how
trustworthy the host looked.

Three places carry it. Any of them will do:

```sh
# 1. This repository, if you have a clone. No network, no keyserver.
gpg --import packaging/zycord-release-key.asc

# 2. The release page, as an asset beside the archives.
curl -fsSLO https://github.com/<publisher>/zycord/releases/download/v<version>/zycord-release-key.asc
gpg --import zycord-release-key.asc

# 3. A keyserver. Use this one.
gpg --keyserver hkps://keyserver.ubuntu.com \
    --recv-keys E72439CEDD8511F9D607550B87FD60D5EB4A0B29
```

Then confirm what entered your keyring, before you rely on it:

```sh
gpg --fingerprint E72439CEDD8511F9D607550B87FD60D5EB4A0B29
```

**Do not use `keys.openpgp.org` for this key.** It is the default keyserver in
several GnuPG builds, and it serves a stripped copy: the bare public-key packet,
with no user ID and no self-signature. GnuPG refuses that copy —

```
gpg: key 87FD60D5EB4A0B29: new key but contains no user ID - skipped
```

— and the key never enters the keyring, so the `gpg --verify` below fails with
what looks like a bad signature and is in fact a missing key. That server strips
user IDs by policy until an address is confirmed through it, which is not
something a pseudonymous project can do. The three sources above all carry the
user ID and the self-signature, and all three are the same key: check the
fingerprint and none of that has to be taken on faith.

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
```

`gpg` will add that the key is not certified with a trusted signature. That is
expected and it is not a failure: it means you have not told your keyring that
you personally vouch for this key, which is exactly what the fingerprint is
there to settle. What matters is that the signature verifies, and that the key
it verified against is the fingerprint printed above.

### The build itself — the check that actually replaces a certificate

A hash tells you the file was not altered in transit. It says nothing about what
the publisher put in it. This does:

```sh
git clone <this repository> && cd zycord
git checkout v<version>
make build
sha256sum bin/zcd bin/zycordd
```

Compare against `SHA256SUMS.binaries` from the release. They must match exactly.
If they do, the binary you downloaded contains this source and nothing else — a
claim no certificate has ever made about anything.

**The Go toolchain is part of what you are reproducing, and it is `go1.26.2`.**
The same source compiled by two different Go releases is two different binaries;
that is not a subtlety, it is measurable — this repository's own release
workflow once recorded three separate SHA-256 values for one commit and one set
of flags, one per Go version. So `make build` pins `GOTOOLCHAIN=go1.26.2` and
stops with an explanation if it cannot use that toolchain, instead of producing
a mismatch that looks like the tampering this whole section is here to detect.

Two consequences worth having:

- You do not have to trust the version written above. The released binary states
  it: `go version -m zcd` prints the toolchain that built it, next to the module
  and the build flags. If that line and the `Makefile`'s pin ever disagree, the
  binary was not built the way this page says.
- Checking out an older tag checks out its pin along with its source, so
  rebuilding an old release keeps working after the project moves to a newer Go.

**Line endings are part of the source here, and the repository settles them for
you.** `wallet/webui` embeds the wallet frontend with `//go:embed`, so those
files' line endings are bytes in the binary: a checkout converted to CRLF builds
a different `zcd`, from the same commit — a mismatch with an innocent cause and
a frightening appearance. A `.gitattributes` carrying `* text=auto eol=lf` gives
LF in the working tree on every platform and every git configuration, so a
**fresh** clone gives the same answer everywhere. Two cases it does not cover:
rebuilding a tag older than that file (set `core.autocrlf=input` before checking
out), and an existing clone made with `core.autocrlf=true`, which does not heal
on pull. [CONTRIBUTING.md](../CONTRIBUTING.md) carries the recovery and the
measurement.

This does not apply to the desktop wallet, for the reason in the two-tiers table
above.

### Independent attestations

One person rebuilding a tag proves the tag is reproducible. Several strangers
rebuilding it and signing the result proves rather more, and it is the pattern
serious projects converged on for exactly this reason. See
[`attestations/`](../attestations/) for the current signatures on each release
and how to add your own.

---

## What none of this protects you from

Stated plainly, because a security page that only lists its strengths is an
advertisement.

- **A malicious repository.** Reproducible builds prove a binary matches its
  source. They say nothing about whether the source is honest. Read it, or read
  the [adversarial reviews](adversarial/) of people who tried to break it.
- **A fake release page.** If somebody stands up a convincing clone and you never
  verify a signature, hashes matching that page's own `SHA256SUMS` proves nothing.
  The project key fingerprint is the anchor; get it from the whitepaper.
- **A compromised machine.** A wallet cannot defend a host that is already lost.
- **A lying node.** `zcd` and the wallet are not full nodes; they believe what a
  node tells them. That is why the wallet refuses a node whose chain id
  disagrees with the network you asserted, and why `--confirm-rpc` exists — see
  [WALLET.md](WALLET.md).
- **Anyone selling you ZCD.** There is no coin yet. Genesis has not happened.
