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
slogan here: the release workflow rebuilds `zcd` at every tag and fails if the
freshly built binary differs by a byte from the one it is about to publish, and
`make repro` builds it in two directories and compares — which is a command you
can run yourself, on this source, right now. You
do not have to trust the person who built the binary you downloaded. You can
build it yourself and compare hashes — and if they match, the question of who
built it stops mattering.

### Two tiers, and only one of them is a download

| artefact | published as a download? | reproducible? | joins mainnet? |
|---|---|---|---|
| `zcd`, `zycordd` — `-randomx` | **yes**, this is the download | no — cgo, RandomX is C++ | **yes** |
| `zcd`, `zycordd` — pure Go | **no**, you build it | **yes**, byte-identical | no |
| Zycord Wallet, Linux and macOS | yes | no — cgo | n/a |
| Zycord Wallet, Windows | yes | yes, the wallet binary | n/a |
| the `zycordd` inside every wallet archive | yes | no — cgo, RandomX | n/a |

Mainnet and the public testnet both declare `pow_engine: randomx-v1`. RandomX is
compiled only under a build tag that needs a C compiler, and a node that cannot
verify a network's engine refuses to start on it rather than falling back to
something weaker. So the binary you can rebuild byte for byte is **not** the
binary you can mine with. There is no third one that is both.

**What changed, and why the pure-Go archive is no longer offered.** It used to be
published beside the other, distinguished by the absence of a suffix, and it is
the one that refuses every real network. Somebody arriving to run a node had two
downloads for their platform and one of them was a dead end — not a choice
between two goods, a trap wearing the same name. So it is not published.

**Nothing about verification changed, because verification never used it.** The
check that replaces a code-signing certificate here is: clone the tag, run `make
build`, hash your own binaries, compare against `SHA256SUMS.binaries` from the
release. That list is still published. It always described binaries you build,
not binaries you fetch — you cannot verify a build by downloading its output.
What is gone is an archive nobody needed for that, and what remains is the whole
of the argument.

If you want to run the pure-Go build — to poke at `--devnet` without a C
toolchain in the picture — `make build` produces it in a few seconds. That is a
developer's errand, and a developer has a Go toolchain.

What that means for you, in one line each:

- **You want to run a node or mine.** Take the archive with `-randomx` in its
  name. Verify it with `gh attestation verify`, which says these bytes came out
  of the project's own workflow, and against `SHA256SUMS.randomx`, which says
  the file arrived intact. Neither is a rebuild — nobody can reproduce a cgo
  build and compare — so the source is what you read, and it is the same source
  the attested tier is built from.
- **You want to check that this project's source is what it says it is.** Take
  the plain archive, rebuild it with `make build`, and compare against
  `SHA256SUMS.binaries`. That build runs `--devnet` and refuses mainnet; what
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

**Windows x86-64 gets a `-randomx` archive. Windows arm64 does not.** The
x86-64 engine is cross-compiled from the Linux runner with a MinGW-w64
toolchain, and it is the one leg of the release that is not built natively:
`windows-latest` ships neither GNU make nor `zip` on `PATH`, so being the target
would cost two tools to buy one compiler. Because a cross-compiled archive
cannot be started by the job that built it, a separate `randomx-smoke-windows`
job downloads that exact archive on a Windows runner, unzips it and starts
`zycordd.exe` — the platform nobody can test locally is not the platform nobody
tested at all.

**Windows arm64 ships nothing, and the reason is narrower than this page used to
claim.** It said there was no cross-toolchain and no native runner. The first
half is true — Ubuntu's MinGW packages target i686 and x86-64 only, there is no
aarch64 one. The second half was wrong, and it was measured rather than argued:
a `windows-11-arm` runner schedules, reports `PROCESSOR_ARCHITECTURE = ARM64`,
and carries Go for windows/arm64.

What it does not carry is a compiler cgo can use for this target. Its `gcc` is an
x86-64 MinGW running under emulation, so it assembles RandomX's `gcc_arm64.S`
for the wrong architecture and fails on every ARM instruction in the file. Its
clang is native but targets `aarch64-pc-windows-msvc`, and cgo on Windows needs a
GNU-style driver; the build stops at `unsupported option '-fPIC' for target
'aarch64-pc-windows-msvc'`.

So the gap is one toolchain — `llvm-mingw`, which targets `aarch64-w64-mingw32` —
and not a missing machine. Until that is in the pipeline, mining on Windows arm64
means building the engine yourself. RandomX itself is fine on this architecture:
the same sources build on linux/arm64 and darwin/arm64 in every release.

That is stated here rather than discovered at start-up, and it is now what was
observed rather than what was assumed.

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

Every wallet archive also carries a `zycordd`: the wallet runs it as its own
full node — outbound-only, on its own data directory — so a download works
without anybody's infrastructure and without a second program to install. The
wallet offers no way to point at somebody else's node, which is deliberate:
choosing whose word your balance is should not be the first thing a wallet asks
of a person who has just installed it. That node is the RandomX build — it has to be, to
join the public networks — and is therefore in the unattested tier on every
platform, Windows included; the `UNATTESTED.txt` beside it says so. The claim
about the Windows wallet binary is unchanged and is about that one file.

**If you do not want to trust a binary you cannot reproduce, use `zcd`.** It is
a first-class interface, not a developer's fallback: `zcd ui` serves the exact
same wallet interface the desktop application shows, from a binary you can
rebuild byte for byte.

### The tactic that follows: package managers

Rather than fight SmartScreen and Gatekeeper, go through the door they leave
open. A package manager installs from a URL and a hash, requires no signature,
and does not trip either warning.

**Neither channel is live yet, and the two sections below say so where somebody
about to paste a command will read it.** The manifests are written and in
`packaging/`; the tap and bucket repositories that serve them are not published,
because each has to name a release's real hashes. Saying this here rather than
letting the commands fail is the difference between a route that is not ready and
a project that looks broken.

---

## Windows — Scoop

**The bucket is not published yet, so these two commands fail today.** The
manifest is in `packaging/scoop/` and is reviewable now; what does not exist is
the repository that serves it, because a bucket has to name a release's real
hashes and there was none to name when it was written. Until it exists, take the
release zip — [Windows without Scoop](#windows-without-scoop), two sections down
— which is a working route rather than a worse one: Scoop's advantage is that it
avoids the mark of the web, not that the bytes are different.

```powershell
scoop bucket add zycord https://github.com/Zycord/scoop-zycord
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
It pins the release URL and the SHA-256 from `SHA256SUMS.randomx`, so Scoop verifies the
download before it installs it.

**What Scoop installs runs `--devnet` and refuses mainnet and the public
testnet.** Scoop carries the pure-Go archive on both architectures, because that
is the tier a package manager can point at and a stranger can reproduce. On
x86-64 the archive that mines is on the release page beside it — take
`*-windows-amd64-randomx.zip` and unzip it yourself; Scoop does not install it.
`zcd version` prints which engine the binary carries, and what Scoop gave you
will say `dev-blake3 only`. The manifest's notes say this at install time so it
is read before a node is started rather than after one refuses.

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

**The tap is not published yet, so `brew tap` fails today.** The formulae are in
`packaging/homebrew/` and are reviewable now; what does not exist is the
repository that serves them. Until it does, take the release archive — [macOS
from the release zip](#macos-from-the-release-zip), below — and expect
Gatekeeper, which that section is about.

```sh
brew tap Zycord/zycord https://github.com/Zycord/homebrew-zycord
brew install Zycord/zycord/zycord         # zcd + zycordd
brew install Zycord/zycord/zycord-wallet  # the desktop application
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

It is checksummed by `SHA256SUMS.randomx`, it carries a build-provenance
attestation, and it is still **not** in `SHA256SUMS.binaries`, because it is a
cgo build and nobody can rebuild it byte for byte. The attestation covers where
the bytes came from, never what the binary is. Read the two-tiers table above before you decide that is acceptable;
the point of stating it is that it is your decision rather than an assumption we
made for you. `UNATTESTED.txt` inside the archive says the same thing where you
will actually be standing when you unpack it.

The desktop wallet on Linux ships as an **AppImage**, because
`libwebkit2gtk` has a different package name on every distribution and a
distro-specific package for each of them is a maintenance surface this project
does not have. See [`packaging/appimage/`](../packaging/appimage/).

### Debian and Ubuntu — the `.deb`

For a server, this is the one that does more than move files.

```sh
curl -fsSLO https://github.com/Zycord/zycord-node/releases/download/v<version>/zycord_<version>_amd64.deb
curl -fsSLO https://github.com/Zycord/zycord-node/releases/download/v<version>/SHA256SUMS.deb
sha256sum --check --ignore-missing SHA256SUMS.deb
sudo dpkg -i zycord_<version>_amd64.deb
```

It installs the RandomX binaries, a systemd unit, an unprivileged `zycord`
account and `/var/lib/zycord`. **It does not enable or start anything.** A node
needs to be told which network it is on, and a mining node needs a payout
address; a package that started one with neither would leave a service that runs,
looks healthy, and does nothing.

```sh
sudoedit /etc/zycord/zycordd.conf     # pick a network, and a payout to mine
sudo systemctl enable --now zycordd
journalctl -u zycordd -f
```

`apt purge` **leaves `/var/lib/zycord` in place**, against Debian convention and
on purpose. What is in there is a chain somebody spent time and bandwidth
synchronising; purge is a command people run while tidying up, sometimes on the
wrong host, and silently deleting a synced chain is a loss with no undo. The
removal says so instead.

The updater knows about this install and will refuse to replace it, because
rewriting a file `dpkg` owns leaves the package database describing bytes that
are no longer there — the next upgrade would overwrite the update. Take the new
`.deb` instead.

The package is byte-reproducible for a given input: it records no build time and
no builder, which a naive `dpkg-deb --build` does record. That is about what the
artefact discloses rather than about verifying the binaries inside it — those are
cgo and carry the same caveat as every `-randomx` build.

Only `amd64` and `arm64`. There is no Debian package for the platforms with no
RandomX build.

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
curl -fsSLO https://github.com/Zycord/zycord-node/releases/download/v<version>/install.sh
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
curl -fsSLO https://github.com/Zycord/zycord-node/releases/download/v<version>/SHA256SUMS.randomx
sha256sum --check --ignore-missing SHA256SUMS.randomx   # shasum -a 256 --check --ignore-missing on macOS
```

`--ignore-missing` is not optional and it is not a way of being lenient.
`SHA256SUMS` covers **every** archive the release publishes — six of them — and
you downloaded one. Without the flag, the five you do not have are reported as
`FAILED open or read` and the command exits non-zero for a perfectly good
download, on the very page that tells you a mismatch means a compromised
binary. A check whose normal result is a failure is a check people learn to
ignore, so both spellings above carry the flag, and so does `install.sh`.

### The provenance

There is no signature over `SHA256SUMS`, and that is a change made on purpose
rather than a corner cut.

A release is built by GitHub Actions and goes from there to whoever downloads
it. Nothing passes through a machine that could hold a signing key. So a key in
that path has exactly two homes and both are worse than none: an Actions secret,
which belongs to whoever can push a workflow file, or a manual step somebody
has to remember, which is a step nobody performs and a promise the documents
keep making anyway. What is published instead is produced by the build:

```sh
gh attestation verify zycord-<version>-<os>-<arch>-randomx.tar.gz --repo Zycord/zycord-node
```

That is a signed statement, made by GitHub's own infrastructure at build time,
that these exact bytes came out of **this repository's workflow, at this
commit**. It is checked against a transparency log, it needs no key of ours and
no keyring of yours, and there is nothing for anyone to leak.

**What it does not say, since the distinction is the point of this whole page.**
It does not say the bytes match the source; only a rebuild says that, and the
next section is how you do one. It says who built them and from what. Read
together — the attestation for origin, the rebuild for content — they cover
more ground than a code-signing certificate does, and neither one costs an
identity.

The project key still exists and is still used, for signed announcements and
anything else where a human statement needs an author. It simply no longer
appears in the download path.

**There is one signature in the release, and it is not for you.** Releases also
carry `update-manifest.json` and a detached signature over it, which is what the
built-in updater checks — because a standard-library client can verify an ed25519
signature and cannot verify a Sigstore attestation. That key lives in CI, so it
belongs to whoever can push a workflow file, and it defends against a mirror or a
broken TLS chain rather than against a compromise of the pipeline. Its trust root
is the same as the attestation's, and it makes no claim the attestation does not
already make to a reader who has `gh`. Verifying by hand, the commands above are
still the whole answer; [UPDATES.md](UPDATES.md) is where the other path is
spelled out.

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
