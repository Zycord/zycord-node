# Updates

How a Zycord binary learns that a newer release exists, what it will and will not
do about it, and exactly what the signature on that answer is worth.

This page is the whole trust model. If you want the short version:
`zcd update --print-source` prints where your binary would look and which keys it
trusts, and contacts nothing to do it.

---

## What this is for

`SECURITY.md` says the thing this feature exists to answer:

> After genesis: coordinated disclosure with an embargo long enough for node
> operators to upgrade, because there is no admin key, no pause button, and no
> way to protect users except by getting patched binaries into their hands
> first.

There is no admin key. There is no pause button. When something is wrong, the
only defence is that operators are running a fixed binary, and until now the only
path to that was "read an announcement and redo the install by hand". Checkpoints
alone ship on roughly a monthly cadence, so this is a recurring cost rather than
a rare one.

---

## The three modes

A node's policy lives in `<dir>/update.json` and is one of:

| mode | on start | while running |
|---|---|---|
| `auto` | check, and install a newer release **before the data directory is opened** | print a notice; never touch the binary |
| `notify` | check, and say what it found | print a notice; never touch the binary |
| `never` | contact nothing | nothing |

Set it with `zycordd --update <mode> --dir <dir>`, or `ZYCORD_UPDATE=<mode>`, or
by answering the question the node asks the first time you start it on a
terminal. `--no-update-check` suppresses one run without changing the policy —
that is the flag for a CI job or an air-gapped rehearsal.

**On a terminal, the node asks once and the default is `notify`.** Pressing Enter
does not enable automatic installs, and that is deliberate: a program that
rewrites its own executable because somebody pressed Enter has taken consent it
was not given. It does not default to `never` either, because the default has to
keep a miner reachable by a security release, and a notice does that while
touching nothing.

**Off a terminal, the node never asks and never blocks.** systemd, Docker, cron
and a pool operator all look identical from inside the process — there is no
terminal — so with no recorded choice the answer is off, with one line saying so
and how to change it. That is what makes those cases safe by construction rather
than by an operator remembering a flag.

---

## What the signature is worth

The release publishes `update-manifest.json` and a detached
`update-manifest.json.sig`. The manifest names the version and carries a SHA-256
for every archive. The signature is raw ed25519, and the public keys are compiled
into every binary.

**The signing key lives in GitHub Actions, and a key in CI belongs to whoever can
push a workflow file.** This repository has said that in several places and it is
still true. So, plainly:

- This signature does **not** defend against a compromise of the release pipeline
  or of the account that owns it. Anyone who can change the workflow can sign.
- It **does** defend against a mirror, a CDN, a fork publishing under the same
  asset names, a compromised download host, and a broken TLS chain.
- Its trust root is **identical** to the build-provenance attestation already
  shipping beside every archive: the workflow's own identity, and nothing more.

Its justification is narrower than "signed releases", and it is sufficient: **a
standard-library client can verify an ed25519 signature and cannot verify a
Sigstore attestation.** Verifying an attestation means an x.509 chain, a
transparency-log inclusion proof and a Fulcio root — which in Go means a large
dependency tree in the one package that decides whether to execute code it just
downloaded. That is the wrong shape for the argument this project makes about
being small enough to read.

So there are two verification paths to the same root, for two different readers:

| reader | path |
|---|---|
| a person, with `gh` installed | `gh attestation verify <archive> --repo Zycord/zycord-node` |
| the binary itself | the manifest signature |

Neither replaces the other, and neither claims more than that.

**None of this replaces the rebuild.** `docs/INSTALL.md` is still the page that
matters for "do these bytes match the source", and the answer there is still
`make build` and a hash comparison. A signature says who published something. It
has never said what is in it.

---

## What is checked, in order

1. The manifest and its signature are fetched from
   `releases/latest/download/`. A **404 on the manifest is quiet** — that is what
   every release published before this feature looks like. A **404 on the
   signature while the manifest is present is loud**, because that is the shape
   signature-stripping takes.
2. The signature is verified **over the exact bytes as fetched, before a JSON
   decoder sees them**. Never the other way round: a verifier that re-serialises
   before checking is a second, undocumented implementation of the format, and
   the gap between the two is where a signature can be valid over bytes nobody
   ever saw.
3. The version is compared on the parsed triple, never as strings. **A downgrade
   is refused and reported.** An attacker who cannot forge a signature can still
   replay an old, genuinely signed manifest; refusing is the mitigation, and
   reporting rather than silently doing nothing is what makes the attempt
   visible.
4. The archive is chosen by a key that includes the **tier** (below). The
   download is capped at the size the manifest declares, and its SHA-256 must
   match what the manifest signs for it.
5. Only then is anything unpacked, and only then is a binary replaced.

A build that is not exactly a release tag is never replaced automatically.
`v0.1.1-9-gab12cd3` is not a release, even though it parses like one — a
developer testing a branch must not have that binary swapped out from under them.

---

## The tier rule, which is the one that can break a miner

`docs/INSTALL.md` explains the two disjoint tiers: the plain archives are
byte-reproducible and **devnet-only**, and the `-randomx` archives are the ones
that join mainnet and the public testnet.

An updater that moved a node between them would take a machine that mines and
leave it with a binary that refuses to start on any real network.

So the tier is part of the asset key — `linux-amd64` and `linux-amd64-randomx`
are different entries — and a running binary computes exactly one key from its
own compiled-in engine. There is no fallback, and a manifest whose key and
filename disagree about the tier is refused outright. If a release publishes
nothing for your platform and tier, you are told so and nothing is changed.
Windows arm64 is the real case: it has a plain archive and no `-randomx` one.

---

## Key rotation, and its two limits

Every binary carries two keys: `current`, which signs manifests, and `next`,
which signs nothing yet. A manifest verifying under either is accepted.

That spare is what turns a key compromise from a fleet-wide hand-download into an
ordinary update. Publish a signed announcement, cut a release signed with `next`
— which every recent binary already holds — carrying `supersedes` naming the old
key, and nodes promote the spare and refuse the old key from then on, before
installing anything.

**Only the `next` key may retire the `current` key.** A general in-band
revocation would be a weapon: whoever stole the signing key could sign a manifest
retiring the *good* one and strand every node permanently. Under this rule a
stolen signing key can revoke nothing, because it is nobody's spare. The spare
also signs *only* rotations, so stealing it is not strictly better than stealing
the signing key.

Two limits, stated rather than buried:

**Promotion is a race.** A node that hears an attacker's manifest before the real
one installs the attacker's release. Nothing here fixes that. What limits it is
noticing quickly, and the fact that the attacker's release is a permanent,
public, signed forgery that anyone can point at afterwards.

**A binary older than the release that introduced the incoming key is stranded.**
It holds neither key, so it must not install, must not fall back, and must not be
quiet — and it cannot tell a rotation from an attacker, because a schema 1
manifest carries no signer id. It says so, and the answer is to download the
release by hand and verify it the way `docs/INSTALL.md` describes. A binary that
does not hold a key cannot be handed one over the channel that key protects. That
is not a gap in the design; it *is* the design, and it is why the genesis
binaries had to ship carrying these keys before anything used them.

Rotation happens on compromise or suspicion, **never on a schedule**. Scheduled
rotation of a key whose rotation strands users is a cost with no matching
benefit.

---

## What is never done in place

Some installs must not be rewritten by the process running from them, and each
one is refused with the command that actually works:

| install | why | do this instead |
|---|---|---|
| Homebrew | brew's manifest would describe a file that is no longer there, and the next `brew upgrade` would overwrite the update | `brew update && brew upgrade zycord` |
| Scoop | one directory per version; the shim would point at a binary whose version no longer matches its directory | `scoop update zycord` |
| a version-named directory | replacing the file makes the name a lie | unpack beside it and move the symlink |
| an AppImage | read-only for the life of the process | replace the file you launched |
| owned by another user | **a node runs unprivileged on purpose** | stop the service, install with the privileges the original install used, start it again |

The last one is the VPS and systemd case and it is not negotiable. A process that
could rewrite its own executable from a root-owned directory would be a privilege
escalation wearing an update's clothes.

A symlink is followed and then left alone: the resolved file is replaced, the
link is not, because overwriting it would turn a managed symlink into a regular
file and break whatever manages it.

---

## Where the check goes, and how to move it

The release host is a **constant compiled into the binary**, not a setting read
from a file beside it. `zcd update --print-source` prints the one your binary
carries, and contacts nothing to do it.

Two things override that constant:

```sh
ZYCORD_REPO_URL=https://example.org/owner/repo   # environment; every binary, every check
zcd update --repo https://example.org/owner/repo # one command only, and it wins
```

`--repo` is `zcd update`'s flag and applies to that invocation. `ZYCORD_REPO_URL`
is read by `zcd` and by `zycordd`, so it is the one that changes what a *service*
does — a node picks it up on its next start, along with `packaging/install.sh`,
which honours the same variable under the same name so an operator who sets one
does not discover a second.

### When you would use it

- **A fork or a mirror.** The ordinary case, and the one the mechanism was built
  for: you run someone else's build line, or your own.
- **A local mirror on the same machine.** `http://` is accepted for a loopback
  host and refused for every other host — a plaintext URL to `localhost` cannot
  be reached by a network attacker at all, and everything else is refused rather
  than warned about.
- **The published address has moved.** This is the case worth spelling out. A
  binary installed before a move carries the old address and its check is a dead
  request whatever mode is set. The trusted keys are compiled in and **do not
  move with the address**, so pointing an already-installed binary at the new
  host and restarting restores its update check *from the binary you already
  have*. No reinstall, no hand-download, no re-verification of anything.

`docs/RUNNING.md` has that as a one-liner for a stranded node.

### The signature is not affected by it

This is the part to be clear about, because "point it somewhere else" sounds like
it should weaken something, and it does not:

- **The keys are `go:embed`-ed into the binary** and are the only keys it can
  ever accept. A base URL is a place to fetch bytes from; it is not a place to
  fetch a key from, and there is no code path by which a host can supply one.
- **Every step of "What is checked, in order" above runs unchanged.** The
  manifest signature is verified over the exact bytes as fetched, the downgrade
  check is made on the parsed version, the archive's SHA-256 must match what the
  signed manifest declares, and the tier rule still picks the asset.
- **An overridden host that is not trusted gets nothing extra.** It can serve a
  404 or a stale signed manifest — which is refused as a downgrade and reported —
  but it cannot serve a manifest that verifies unless it holds a private key the
  embedded set names.
- **The URL itself is validated.** `https`, or `http` to a loopback address;
  anything else is refused with a reason rather than silently accepted, and a
  redirect that leaves `https` is refused at every hop.

So the override changes **where** the bytes come from and changes **nothing**
about what has to be true of them before a binary is replaced. Which is exactly
why it is safe to hand to a stranded operator over an announcement.

**The one thing that does break it: a key rotation.** The override works because
the embedded keys and the published ones still agree. If the release keys are
rotated while a fleet is pointed at a new host by an old binary, that binary
cannot verify the new manifests and there is no path back except a hand-download.
See "Key rotation, and its two limits" above.

---

## What the network sees

This is the first unprompted outbound request `zycordd` makes, and the repository
has been careful about that everywhere else, so here is the whole of it.

**What a check does.** One HTTPS request for `update-manifest.json` and one for
its signature, to the release host, at most once every six hours. If an update is
then installed, one more request for the archive the signed manifest named.

**What it sends.** A constant `User-Agent: zycord-update/1` — no version, no
operating system, no architecture, no node identity, no identifier of any kind.
Every Zycord binary in the world sends exactly the same header.

**What can be inferred anyway.** Your IP address, and a rough timezone from when
your node restarts. Which asset you request discloses your platform and tier —
that is unavoidable, and it is the same thing you disclosed when you downloaded
the binary in the first place.

**What is never sent.** Your node's identity, height, peers, payout address,
wallet, whether it mines, or anything about the machine.

**Mitigations that are in the design rather than in this paragraph.** The first
check of a running node is offset by a random interval from `crypto/rand`, so ten
thousand nodes restarted by a distribution update do not all check in the same
second — and so a synchronised fleet-wide beacon does not exist to observe.
`HTTPS_PROXY` and `NO_PROXY` are honoured explicitly, so an operator already
routing everything through a tunnel does not find this one request ignoring it.
And it is off by default on every non-interactive host.

If you are routing through a VPN, check that IPv6 is not leaving outside the
tunnel; that is a property of your machine rather than of this program, and it
applies to every outbound connection your node makes, not only this one.

**`never` means never.** It is not a reduced schedule. Nothing is contacted.

---

## Exit codes

`zcd update` is meant to be usable from cron, so its exit codes are an interface:

| code | meaning |
|---|---|
| 0 | up to date, or the update was installed |
| 10 | an update is available and was not installed |
| 11 | an update is available and this install cannot be replaced in place |
| 12 | this release publishes no manifest — not an error |
| 1 | the check or the install failed |
| 2 | usage |

10, 11 and 12 are separate from 1 because a monitoring job has to tell "there is
an update" from "this box cannot self-update" from "the check broke", and one
non-zero code collapses all of them. 1 keeps its usual meaning, so `set -e` still
trips on a real failure.

```sh
zcd update --check
case $? in
  0)     ;;              # nothing to do
  10|11) notify ;;       # an update exists
  12)    ;;              # no manifest yet
  *)     alert ;;        # something is actually wrong
esac
```

Running `zcd update` on a terminal is itself the request, so it needs no
configured policy. Off a terminal it will only ever report, never install, unless
`--yes` says otherwise in words.

---

## If an update goes wrong

The previous binary is kept, exactly one generation back:

```sh
zcd update --rollback
```

On Unix the replacement is ordered so that the destination never stops existing:
the previous file is hard-linked aside before the new one is renamed over it, so
a crash at any point leaves either the old binary or the new one, and never
nothing. Windows cannot do that — it refuses to overwrite a mapped image but
permits renaming one — so there the running executable is renamed aside and the
replacement takes the name it freed, leaving a two-syscall window in which a
failure renames the original back.

Both `zcd` and `zycordd` are replaced together, because they are one release and
a skewed pair is how you get a certificate your own node refuses. That pair is
not atomic — two renames cannot be made one — but a failure part-way restores
what already changed, so what you are left with is a matched *old* pair rather
than a mismatched one.

---

## Maintainer commands

```sh
zcd update manifest --dir <release-dir> --version vX.Y.Z [--sign]
zcd update verify   --dir <release-dir>
```

The release workflow runs both. Generation refuses to write a manifest that
disagrees with `SHA256SUMS`, `SHA256SUMS.randomx` or `SHA256SUMS.desktop` — the
manifest is a superset of those lists, never a rival — and signing refuses a key
that is not in the embedded set, because a release signed by a key no binary
carries updates nobody and does it silently.

`make release-manifest` and `make release-manifest-verify` exercise the same path
against a local `make dist`. They are not the release path.
