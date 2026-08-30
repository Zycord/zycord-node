# Release procedure

Two things have to be true of every release: it builds byte-identically from source, and it carries no identity. Neither survives being remembered at the last minute, so both are checklists.

---

## 1. The public tree

The public repository is **not** this repository with a remote added. It is a fresh tree containing only the working files.

```sh
# From a clean checkout with everything committed and CI green:
git status --porcelain          # must be empty
make ci                         # must pass

# Copy the working tree — not the history — into a new directory.
rsync -a --exclude='.git' --exclude='bin' ./ ../zycord-public/
cd ../zycord-public
git init
git config user.name  "<project pseudonym>"
git config user.email "<pseudonym>@users.noreply.github.com"
git add -A
GIT_AUTHOR_DATE="<UTC timestamp>" GIT_COMMITTER_DATE="<UTC timestamp>" \
  git commit -m "zycord v<version>"
```

**Never add the public remote to the private repository.** Not once, not to test. `git push` resolves refs against the local object store, and a single push with the wrong remote publishes every commit reachable from the pushed ref — including the ones you meant to leave behind. This is the one step where a slip undoes all the rest, and it is not recoverable: a public repository can be deleted, but a clone or a mirror bot cannot.

Verify before pushing:

```sh
git log --format='%an <%ae> %ad' --date=iso   # one line, the pseudonym, a UTC date
git count-objects -v                          # object count should match a single commit
```

## 2. Timestamps

Commit dates and push times are both timezone signals, and they compound: a hundred commits at 22:00–02:00 UTC is a longitude.

- Set `GIT_AUTHOR_DATE` and `GIT_COMMITTER_DATE` explicitly, in UTC, on every public commit.
- `genesis_time` in `spec/params.json` is already a round UTC value and must stay one.
- Prefer pushing at a time that is not correlated with your working hours. This matters more across many releases than on any one.

## 3. Fixtures and configs

Everything synthetic must be *obviously* synthetic, so that a reader can see at a glance that no real key or address was involved.

- Test and vector keys are derived from `KeyFromSeed(bytes.Repeat([]byte{n}, 32))` — seeds are `0x0101…01`, `0x0202…02`, and so on. Never a key generated from real entropy, never a key you have used anywhere.
- Genesis makes **zero allocations**: `zcd genesis` reports `allocations 0`, and `TestGenesisIsReproducible` fails if any cell lands under a non-protocol address. Nothing to leak.
- No example address in the documentation is derived from a real one.
- No default configuration points at a host, a path, or a port you use, **with one declared exception**: the public testnet's launch seed in `cmd/zycordd`, which is project infrastructure by construction and cannot be anything else on a first day. It is a DNS name so it can be moved without a release, `--no-seeds` refuses it, and §4 below carries the residual risk. Anything else — a personal host, a home address, a port you happen to run something on — is still a finding.

Audit before a release. **Both halves, and the mechanised one is an addition to
the manual one rather than a replacement for it:**

```sh
# 1. The mechanised half. Eight classes over the index: hardware models and
#    vendors, home-directory paths, machine names, e-mail addresses, timezones.
#    It does NOT cover the real name or the account handle — see below.
make wiring

# 2. The human half, and the ONLY half that covers the identity class. Over the
#    working tree rather than the index, so it also sees files you have not
#    staged yet. Read the output yourself.
#
#    The terms live outside this repository, because a file holding the real
#    name and the handle cannot be tracked by the repository it is guarding.
#    Point this at wherever you keep them.
terms=$(grep -vE '^[[:space:]]*(#|$)' "${ZYCORD_IDENTITY_TERMS:?set this to your terms file}" | paste -sd'|' -)
test -n "$terms" || { echo 'no identity terms: this audit asserted NOTHING'; false; }
grep -rniE "$terms" .
```

**Both parts of that recipe are load-bearing, and the first version of it failed
open in two independent ways.** Blank lines are stripped as well as comments,
because an empty alternative matches every line — and a file documented as
taking `#` comments will acquire a blank line. The terms are collapsed into one
alternation rather than piped in with `grep -f -`, because a recursive `grep`
reading its patterns from standard input **aborts** on at least one common
build: no findings printed, non-zero status, and a releaser scanning the output
for matches reads it as clean. The `test -n` line is the guard against the third
costume of the same failure — a pattern file that is present but says nothing.
An audit that fails open is worse than no audit at all, and this is the half
carrying the class that matters most.

The identity terms are **not written out here**, and that is not squeamishness:
this file is tracked, so a worked example naming the handle would publish the
handle. Writing the terms into the section that hunts for them is the same
mistake one layer up, and the check catches it — the first draft of this
section spelled the pattern list out, and `sim/wiring` failed on one of the
machine-name terms sitting in the audit's own instructions.

**Why the check scans what it scans.** `sim/wiring` scans what `git ls-files`
says will be published, rather than a hand-written extension list, and refuses
any tracked file it cannot read as text — because `grep -I`, and `git grep -I`,
skip binary files **in silence**. Go writes the absolute path of every compiled
source file into a binary, so a build artefact that reaches the index carries the
builder's home directory in as many places as it has source files, and every text
grep ever run against the tree walks straight past it.

**But deleting the grep in favour of the check would make coverage go down.**
The check cannot carry a pattern for the real name or the account handle,
because writing that pattern into a tracked file *publishes the string it is
looking for*. That is the class this whole section exists for, so a mechanised
check that silently dropped it would be worse than the grep it replaced.

**The mechanised half does not reach that class at all.** It covers the eight
classes a committed pattern can assert. Loading the terms from an untracked file
at run time was considered and is not done: it puts the enforcement of the class
that matters most outside the repository, where its absence is indistinguishable
from a pass.

Step 2 carries its own `test -n` guard for a reason that generalises past this
recipe: **an audit that fails open is worse than no audit at all.** A guard
whose pattern source is missing, empty, or unreadable prints the same nothing as
a guard that ran and found nothing, and `make wiring` runs without `-v`, so a
silent pass is indistinguishable from a clean tree. Step 2 is the only step
standing between the handle and a one-way door, so it fails loudly or it is not
a step.

**One shape of that class *is* tracked**, because it can be: `sim/wiring`'s
`TestNoAbsoluteGitHubURLIsPublished` refuses any absolute `github.com` URL whose
account segment is not on a short allow-list of substitution placeholders and
vendored upstreams. The literal `github.com` is a service name rather than an
identity, so that regexp is safe to commit and cannot be forgotten. Reference
issues as bare `#NNN`. It does not know the handle and never will; it refuses
every account it was not told about, which covers the handle by default.

**What neither half covers**: encoded payloads (a leak base64'd into a `.json`
passes every pattern — nothing is decoded), operating-system versions and
`GOOS/GOARCH` (a platform on which a crash reproduces is content a reader needs;
a laptop model beside a memory figure is not, and no pattern separates them —
over-sanitising is a real cost, not a safe default), §4's voice signals, and
everything outside the tree. Commit messages, PR bodies and issue text are
published too and no test in the repository can reach them. Those stay
`PROTOCOL.md` rule 4's human obligation, which is *grep before committing*: by
the time a string is in a pushed commit, the options are mitigation and
acceptance rather than removal.

## 4. Voice

The technical lineage of this design is not secret and does not need to be. What must not happen is *adding confirmation* on top of it through prose — comments, commit messages and documentation are stylistic fingerprints, and they are the cheapest possible thing to get right.

- Code comments: terse, technical, standard English.
- Watch for first-language-influenced phrasing and for personal idioms that repeat.
- Watch for repeated typos. A misspelling that appears across years of somebody's commits is a signature, not an accident.
- Before a public release, read the diff for voice as a separate pass from reading it for correctness. They are different jobs and doing them together does neither well.

### Network behaviour is a fingerprint too

Peer-to-peer code publishes more than source. Connection patterns, timing, default ports and — above all — the **bootstrap node list** are operational facts about whoever runs them.

- **A bootstrap node on infrastructure traceable to you is a deanonymisation vector that the cleanest git history cannot fix.** A VPS paid for with a card, a domain with a registrar record, a static address that also serves something personal: any of these undoes everything above, and none of them is visible in a diff.
- **The default bootstrap list must not be a map of your servers.** Bootstrap nodes should be community-operable from the first day the testnet is public, the list should be short, and it should be replaceable by configuration without a rebuild.
- **Today that rule has exactly one exception, and it is a debt rather than a revision.** The public testnet ships with a single seed the project runs, because a network nobody can join without first copying an address out of an announcement has no honest newcomers to be deanonymised by. The mitigations are real but partial: the entry is a name, so it moves without a release; `--no-seeds` refuses it; the node prints what it will dial. What none of that touches is that a registrar record and a static address exist and are ours. **The exception closes when a second seed somebody else operates is published**, and until then this bullet is a standing item rather than a satisfied one.
- Prefer bootstrap addresses contributed by others over addresses you control. A network that cannot start without you is a network with a single point of both failure and attribution.
- Default ports and protocol quirks are shared by everyone running the software, so they identify the *project* rather than a person — that is fine and unavoidable.

This is an M3 release-gate item, listed here now so it is not discovered at launch.

None of this applies to the private working repository.

## 5. Reproducible builds

```sh
make repro                        # the default build, across two paths and with/without .git
make repro-randomx                # the same for the cgo build
GOOS=windows GOARCH=amd64 make repro-desktop   # the same for the Windows wallet binary
make canonical                    # all four binaries inside the container that pins the compiler
make canonical-dist-diff          # the canonical pure-Go binaries against what `make dist` ships
```

None of those executes an artefact. They build and they compare, which is the
right shape for a reproducibility claim and the wrong shape for the question
"does this file start". That question has its own target and it takes a path:

```sh
make release-smoke ZYCORDD=dist/randomx/zycord-<version>-<os>-<arch>-randomx/zycordd
```

`repro-desktop` refuses every other target rather than checking it. On Linux and macOS the wallet is a cgo binary and is not in this tier at all, and a green check there would assert the thing the rest of this section is about not asserting. `GOARCH` is pinned for a second reason: `windows/amd64` is the only wallet any release contains, and without the pin the command follows `go env GOARCH` and compares a `windows/arm64` wallet — which on this project's own arm64 hardware made the checklist box below tickable while the shipped artefact went unchecked.

Both in the environment, not as `make` variables. A command-line variable does not reach the `$(shell …)` calls that pick this target's tags, link flags and `CGO_ENABLED`, so `make repro-desktop GOOS=windows` builds *host* flags for a Windows target — measured, a `CGO_ENABLED=1` build with no `-H windowsgui`, PE subsystem 3, the console build [INSTALL.md](INSTALL.md) and the `windows` CI job exist to keep out. The target refuses that form too, by reading the same resolved values the flags came from.

**Do not verify by building twice in one directory.** It cannot catch a difference that depends on *where* or *how* the source sits — which is exactly the difference that was there. Without `-buildvcs=false`, Go stamps `vcs.revision`, `vcs.time` and `vcs.modified` into any binary built inside a git work tree and derives the module version from the commit. §1 of this document publishes the tree **without history**, so the released binary carries no stamp; every verifier checks it from a **clone**, which has a `.git` and stamps their own revision. Measured: about a third of the binary differing, from nothing but the presence of a directory. Every third-party verification would have failed, and the failure looks like a compromised binary rather than like a missing build flag.

`make repro` exports the tree to two different paths and compares those against each other and against a build in the working tree. It is what CI runs.

**The C toolchain is pinned in `build/Dockerfile`,** which is what `-trimpath` and a pinned Go toolchain stopped covering the moment there was cgo (R1-L2, ARCHITECTURE §1 P6). Everything in it is pinned by content rather than by tag: the base image by digest, the Go toolchain by sha256 of the official tarball, and the C toolchain by a **snapshot.debian.org timestamp** rather than by hand-written package versions — a snapshot is verifiable from outside and a hand-written version string is not. `GOTOOLCHAIN=local` is set because without it a `go.mod` naming a newer toolchain makes the build silently download one, and the pinned version becomes a suggestion.

A release is built with `make canonical` and its checksums published. The container is exercised by CI on every push to `main`, every tag and on manual dispatch, so a change to it fails on the merge that lands it rather than on the day somebody tries to cut a release. It is skipped on pull requests — three full container builds is the most expensive job in the workflow — so a change to `build/Dockerfile` is one to run `workflow_dispatch` against before merging rather than after.

`canonical` builds four artefacts, not two: `bin/zcd` and `bin/zycordd` from the
pure-Go target, `bin/zcd-randomx` and `bin/zycordd-randomx` from the cgo one.
They used to be two, because `build-randomx` wrote the same two paths `build`
does and ran second in the same container invocation — so the canonical build
certified the RandomX binary, which no release contains, and destroyed the
pure-Go one, which every release does, in one command. CI diffed the survivor
against itself and had no term for what was lost.

`canonical-dist-diff` is the comparison that closes that: it builds the
canonical pair and the `dist` pair with the same pinned compiler and requires
them to be byte-identical. If the two build targets ever share an output path
again, the binary left in `bin/` is the cgo one and the hashes differ.

The `dist` half is narrowed to **one** platform and that platform is read out of
the container (`go env GOARCH`) rather than written down. `canonical` runs `make
build`, which sets no `GOOS`/`GOARCH` and so produces the container's *native*
binaries; hard-coding `linux/amd64` would compare those against a cross-compiled
amd64 archive on any arm64 host — a byte mismatch reported in the words "one
target overwriting the other's output", on the machine this project actually has
(see `repro-desktop` above for the same hazard, caught the same way). Narrowing
to one platform also keeps `zip` out of the container's dependency list.

### The two tiers, and never blurring them

That moment has already arrived for one artefact, on two of its three platforms. On Linux and macOS the desktop wallet links the platform's webview through cgo, so a system C toolchain and a platform SDK end up in its output and two machines will not agree byte for byte.

| artefact | reproducible | joins mainnet | built by |
|---|---|---|---|
| `zcd`, `zycordd` | **yes**, byte-identical | **no** | `make dist`, cross-compiled from one runner, `CGO_ENABLED=0` |
| `zcd`, `zycordd`, `-randomx` | **no** | **yes** | `make dist-randomx`, one native runner per target, `CGO_ENABLED=1 -tags randomx` |
| `zycord-wallet`, linux and darwin | **no** | n/a | `make dist-desktop`, one runner per operating system |
| `zycord-wallet`, windows | **yes**, the binary | n/a | `make dist-desktop`, cross-compiled from the Linux runner, `CGO_ENABLED=0` |

**Rows one and two are disjoint sets, and that is a sentence this table used to
be missing.** `make dist` is `CGO_ENABLED=0` with no `-tags randomx`, so
`randomx.New` returns `ErrNotBuilt` in everything it produces and `cmd/zycordd`
refuses to start on any network whose `pow_engine` is `randomx-v1` — which
`spec/params.json` and `spec/params.testnet.json` both are. For as long as that
was the whole matrix, **there was no reproducible mainnet binary at all**: the
reproducible-build story, which is this document's substitute for a
code-signing certificate, covered no binary a mainnet user could execute.
Every archive, and all three package managers, produced a start-up
refusal.

`make dist-randomx` is the other half, and it does not close the gap by merging
the tiers — it cannot, because cgo is not reproducible across C toolchains. It
closes it by making the runnable tier **exist** and by labelling it as the one
nothing attests, everywhere a user meets it: `docs/INSTALL.md`'s two-tiers
table, `packaging/install.sh`'s closing message, the Homebrew caveats, the Scoop
notes, an `UNATTESTED.txt` inside each archive, and `zcd version` on the binary
itself. It stages under `dist/randomx/` rather than beside the attested
archives, which is not tidiness: `dist`'s `SHA256SUMS.binaries` line globs
`zycord-*/zcd`, and as siblings the two tiers would have merged inside the
attested checksum file.

**Nothing from `dist-randomx` may ever appear in `SHA256SUMS.binaries`**, for
the same reason the wallet may not: there is nothing for a stranger to compare a
rebuild against. It has its own `SHA256SUMS.randomx`, which is a transfer check
and is described as one.

**That file is signed, and signing it says a third thing rather than upgrading
either of the first two.** `SHA256SUMS.binaries` answers *"rebuild this and
compare"* and no cgo artefact can ever appear in it. `SHA256SUMS.randomx`
answers *"did the file arrive intact"*. The detached signature beside it answers
*"was this list published by the holder of the project key"* — origin, not
attestation. A reader who checks it learns that the list came from the same
place every previous release came from, and learns nothing whatever about
whether the bytes it names can be rebuilt. They cannot. Publishing the tier
unsigned was leaving the only artefact most people run with no origin evidence
at all, which is a different failure from the one the tier boundary exists to
prevent.

Windows has no `-randomx` leg, and the reason is the pipeline rather than the
code: a local `make build-randomx` on Windows with a MinGW-w64 toolchain does
produce a working binary (measured — `zcd version` on it names `randomx-v1`),
but nothing in `release.yml` can build one. cgo does not cross-compile from the
Linux runner without a mingw toolchain in the image, and `windows-latest` ships
neither GNU make nor `zip` on `PATH` — the same wall this section already
records for `dist-desktop`. Holding the release for that would trade a stated
limitation for an unstated delay, so Windows ships the pure-Go archive and
`docs/INSTALL.md` and the Scoop notes say what it can and cannot do. Adding the
leg later is a line in `release.yml`'s `cli-randomx` matrix, a mingw toolchain
step, and a paragraph deleted from `INSTALL.md`.

Wails reaches WebView2 through pure Go, so the Windows build has no cgo in it: it builds at `CGO_ENABLED=0` on a machine with no C compiler, and two builds of one commit are identical to the byte. `CGO_ENABLED=0` is *pinned* for that target rather than inherited from whichever machine runs it, so the property is stated instead of accidental.

**That row buys the wallet nothing here, because checked and attested are different claims.** Being checked is a statement we make to ourselves: two builds of one commit on one machine agree — and the wallet is checked, on every push to `main` and at every tag. `make repro-desktop` exports the commit to two paths, builds the wallet in each and in the working tree with the same command `make dist-desktop` builds the artefact with, and compares the three; `ci.yml`'s `reproducible` job runs it on every push to `main`, every tag and on manual dispatch — not on pull requests, where the cost is paid over and over on bytes nothing has accepted — and `release.yml`'s Windows leg runs it before that recipe archives anything. Attestation is a statement made to a stranger — here is a hash, rebuild the tag yourself and compare — and for the wallet there is nothing for a stranger to compare against. What a release publishes for it is a `.zip`, whose hash is not reproducible even when the binary inside it is, because a zip entry records the file's mtime; and on Linux and macOS the binary is not reproducible either. One attested-looking line, for one platform of one artefact, is exactly the blur this section exists to prevent.

**Publish that distinction, do not bury it.** A release that ships both under one "reproducible builds" heading has made the phrase mean nothing, and the phrase is the entire substitute for a signature this project has. Concretely:

- `SHA256SUMS.binaries` covers `zcd` and `zycordd` only. It is the file an independent rebuilder compares against, and it **must never grow a line for the wallet** — including the Windows one, whatever this project has or has not checked about it. The rule rests on there being nothing published for a stranger to compare a rebuild against, and a check run against our own build is not such a thing.
- **`make repro-desktop` prints its verdict and writes no file.** A per-binary checksum file for the wallet, published next to the archives, reads to a downloader as precisely the attestation the bullet above says this project does not make — and a hash written by the same build that produced the binary checks nothing anyway. The verdict belongs in the CI log, where a maintainer reads it, and not in the release, where a stranger would.
- `make dist-desktop` prints its verdict every time it runs, and the verdict is per-target: the cgo disclaimer on linux and darwin, and on windows the narrower statement that the binary is byte-identical while the archive is not. Leave both there.
- The release notes name the reproducible artefacts and then say, in the same paragraph, that the desktop wallet is not one of them and that `zcd ui` serves the identical interface from a binary that is.
- Nothing in `attestations/` is ever signed for the wallet. `attestations/README.md` says so; a pull request that adds one is a review finding.

### Releasing the wallet

`.github/workflows/release.yml` runs the two as separate jobs, which is what keeps the two stories separate in the artefact list as well as in the prose. The desktop matrix is one runner per operating system *where cgo is the reason* — it cannot be cross-compiled without a per-target toolchain and SDK — so linux and darwin build on their own machines and windows, which has no cgo, is cross-compiled from the Linux runner like every `zcd` artefact. **That leg must not run on `windows-latest`**: it calls `make dist-desktop`, and that image ships neither GNU make nor Info-ZIP `zip`, while the recipe is POSIX `sh` and archives Windows with `zip`. `desktop/` is a separate Go module, so a Wails release that breaks nothing here still cannot break `make ci`.

**The release is gated on Windows.** Every build job in `release.yml` runs on Linux or macOS — `cli` cross-compiles all six platforms from one Ubuntu runner, and the wallet's Windows leg does the same — so the workflow produces Windows artefacts without ever executing one, and it does not depend on `ci.yml`, so a tag could otherwise be cut over a Windows regression that CI had caught on the same commit. `.github/workflows/windows.yml` is a reusable workflow that both `ci.yml` and `release.yml` call, and `cli` and `desktop` both `needs:` it: a red Windows job means neither build job runs and the workflow uploads nothing, rather than artefacts standing next to a red job. That is a statement about the workflow's own uploads, and about the draft its `publish` job opens from them — §1 and §8 still decide what is *published*, because a draft is not a release until somebody signs two files and presses the button. What a red Windows job denies them is §1's first precondition, *"from a clean checkout with everything committed and CI green"*: CI is not green. It does not deny §1's `make ci` line, which is a local command on the release machine and never runs this job at all — GNU make is not the entry point on Windows, which is why `windows.yml` spells its commands out. One definition of that job, called twice, rather than a second copy in `release.yml` that would agree with the first on the day it was written and on no day after.

Before tagging:

```sh
go list -m all | grep -i wails     # must print nothing: the root module is clean
make check-imports                 # unchanged
make repro                         # zcd still byte-identical
# The bridge contract. webkit2_41 is required on Linux and inert elsewhere,
# so one line is correct on every release machine.
(cd desktop && go test -tags desktop,webkit2_41 ./...)
```

The last one is not optional. The desktop frontend calls Go methods by name through a runtime bridge, so a renamed method is a button that does nothing and a green build everywhere else; `desktop/bridge_test.go` reads the names out of `transport.js` and is the only thing that checks it.

### There is no code-signing certificate, and that is a release decision

An Authenticode certificate is a CA attesting to a verified legal identity, and an Apple Developer ID publishes the developer's legal name in the certificate's Team Name field. Either one undoes §1 through §4 of this document in a single purchase. The decision taken is to keep the pseudonym and route around the warnings through package managers that install from a URL and a hash: a Homebrew **formula** (which compiles on the user's machine, so nothing is quarantined) and a Scoop bucket (whose downloads never acquire the mark of the web in the first place). The reasoning, and what it does and does not protect a user from, is in [INSTALL.md](INSTALL.md) — written for the user rather than for us, because a user who understands why the warning appears is much harder to phish with a fake installer.

## 6. The genesis announcement

A launch commits, weeks in advance, to four values. Publish all four and nothing else:

```sh
zcd genesis
```

```
network       zycord
chain id      1
params hash   0x…      ← blake3 of spec/params.json
genesis id    0x…      ← the block 0 header hash
state root    0x…      ← the state after folding block 0
genesis time  …
cells written 2
allocations   0
```

Anyone can rebuild all four from the tagged source in milliseconds.

The `params hash` line is pinned in `spec/vector_test.go`'s `TestEveryEmbeddedNetworkHasAPinnedGenesis`, for every network the binary embeds, as a written-down constant rather than as a recomputation. **A diff that changes one of those constants changes this announcement**, and it does so for prose too: `notes` is excluded from the consensus root but not from the file's bytes, so a reworded note moves the published hash while every consensus value stays put. That is the whole reason the constants are literals — the test fails with the new value printed, and updating it is the moment somebody decides the announced commitment has moved. Treat such a diff as a release event, not as a test fixup, and re-publish the value if the announcement is already out.

`allocations 0` is the line that carries the fair-launch claim, and it must stay literally true once the treasury exists. It does: the treasury cell is credited from the block subsidy, `emission(0) = 0`, and a zero cell is an absent cell — so block 0 allocates nothing to anybody, including the treasury, and the cell first appears in the state root at block 1. Publish it alongside the genesis id so "accrues from block 0" is something a reader checks rather than something we assert.

**Publish the project key alongside them**, as a fifth value: the full fingerprint of the pseudonymous signing key that signs release tags and the reproducible-build artifact (§8), printed in the announcement and carried in the whitepaper header. This is not an exception to the rule below — it is what makes the rule enforceable. A key that signs artifacts is the opposite of a contact that resolves to a person: it lets a reader verify that two releases came from the same author *without* learning who that is, and it is the only way an anonymous project can be impersonated-proof. Publish the fingerprint in full, in more than one place, and never rotate it silently; a key that changes without a signed statement from the old one is indistinguishable from a compromise.

There is nothing else to trust, and deliberately nothing else to publish **in the announcement**: no wallet address, no donation link in the same message, no contact that resolves to a person. That restriction is about the announcement, not about the project — Eras 0 and 1 are donation-funded (whitepaper §14.1), and the donation channel belongs in the repository, where it can be read in context by someone who already chose to look, rather than in a launch post where it reads as a solicitation attached to a coin that does not exist yet.

## 7. When to publish

**Testing is now.** M0 is the test surface — vectors, griefing suite, differential fold, incentive suite — and M1 and M2 extend it to a node and a private network. Nothing about testing waits for anything.

**Publication is M3, as one package.** A design published before the network exists is a design donated; a paper without a minable network dies in two weeks. So the public moment is a single release, and every part of it ships together:

- the public repository, built per §1 — fresh history, working tree only, never the private `.git`;
- the whitepaper, the architecture spec, the [wire protocol](spec/wire.md), and **every** adversarial review — R1, I1, H2-economics, R2, I2, I3, I4, I5, I6, I7, mempool, concurrency, sync, and the networking decision. For an anonymous project the review trail *is* the credibility; a design with no visible record of being attacked reads as a design nobody attacked, and the four documents that record instruments failing rather than code failing ([concurrency](adversarial/concurrency.md), [I5](adversarial/I5.md), [I6](adversarial/I6.md), [I7](adversarial/I7.md)) are the ones a serious reader will weigh most;
- a resettable public testnet running real RandomX;
- the announcement posts.

**Genesis comes later still**, after M4 and M5, announced 2–4 weeks ahead with the code tag, params hash and genesis id committed in advance (§6). Between M3 and genesis the public testnet is the community's audit window — that ordering is what makes "fair launch" checkable rather than claimed.

## 8. Release checklist

- [ ] `make ci` green on the tagged commit — which now includes `make race` and `make guard`.
- [ ] **`make soak-long` green**, for a duration measured in hours and then a multi-day run (R5-G1). Both regimes: convergence after the chaos stops, and history agreement while contention never stops. This is the gate whose evidence has historically been thinnest, and the four-minute threshold that surfaced [I4-H1](adversarial/I4.md) is the argument that duration buys findings.
- [ ] The soak reported `all nodes report the consensus-state guard armed` and crossed at least one epoch boundary — a run that did neither proves much less than it appears to.
- [ ] `go run ./spec/gen` produces no diff — the committed vectors match the implementation.
- [ ] The differential fold passes; the fuzz farm has run the current corpus without a crash.
- [ ] Byte-identical rebuild verified (§5) — for `zcd` and `zycordd`, and separately for the Windows wallet binary (`GOOS=windows GOARCH=amd64 make repro-desktop`; CI runs it, this is the by-hand confirmation). Both variables in the environment and `GOARCH` pinned, or the box gets ticked for a target no release contains (§5). The desktop wallet is **not attested on any platform**, including that one: it is labelled as unattested in the release notes, and it has no line in `SHA256SUMS.binaries` (§5). Checked is not attested.
- [ ] `make canonical-dist-diff` green on the tagged commit — the canonical container's pure-Go `zcd` and `zycordd` are byte-identical to the `linux/<container arch>` binaries `make dist` stages — the target reads that arch out of the container, so the box is tickable on this project's arm64 hardware too (§5). CI runs it; this is the by-hand confirmation. It is the check that would have caught the canonical build certifying a binary no release contains, and reading `go version -m bin/zcd bin/zcd-randomx` once after it is how you see the tags rather than infer them.
- [ ] `go list -m all` at the root does not mention Wails, and `make check-imports` is green with no edit. The desktop module is isolated or it is not.
- [ ] `SHA256SUMS` signed with the project key **by hand, off CI** — a signing key in a CI secret is a key held by whoever can push a workflow file. The workflow's `publish` job stages a **draft** release from what the build jobs produced; signing and pressing publish are what turn it into one, and they are not automatable for that reason.
- [ ] **`make dist` run locally and its hashes compared against the draft's `SHA256SUMS` before signing it.** This is the item that keeps the signature meaning what it says. The attested tier is byte-identical anywhere (§5), so a local rebuild either matches the draft exactly or the draft is not this source — and signing a list you have not reproduced is attesting to bytes somebody else built. **The `-randomx` tier cannot be checked this way and that is not a gap to be closed:** cgo builds are reproducible nowhere, so what covers them instead is the workflow's provenance attestation, which says *these bytes came out of this workflow at this commit* and is verifiable by anyone with `gh attestation verify`. Know which of the two you are relying on for which file.
- [ ] **`make dist-randomx` run on every target the release publishes it for** (linux amd64/arm64, darwin amd64/arm64 — one native runner each, because cgo needs a C++ toolchain for the target), and `SHA256SUMS.randomx` published beside the archives, **with its own detached signature `SHA256SUMS.randomx.asc`**, signed by hand off CI exactly as `SHA256SUMS` is. It is still **not** merged into `SHA256SUMS` and it still gets **no** line in `SHA256SUMS.binaries` (§5): merging it into either would say something about those bytes that nobody can check. The signature is about the list's origin and not about the bytes it names — see §5 — and it is there because this is the tier almost everyone runs, so shipping it with no origin evidence at all was the larger of the two mistakes available.
- [ ] **A released binary was started against the tagged parameters and did not refuse.** Unpack an archive — the actual published one, not `bin/zycordd` — and run `make release-smoke ZYCORDD=<path>`. It starts the node against the embedded **mainnet** set with no `--devnet` and no `--params`, waits for `cmd/zycordd`'s own `proof of work: <engine> engine` line, and fails with the process's output if the node exited instead. **Do this for the `-randomx` archive of every platform in the matrix**, and once for a plain archive to see the refusal it is supposed to produce — a check that has only ever passed is a check nobody has seen work. Every other gate in this document builds an artefact and hashes it, and a hash cannot tell you a binary starts; that is precisely how six platforms of binaries that refuse to start on mainnet passed a green pipeline and three package managers. This is the same walk the empty-keyring verification below uses: one clean host, one archive, from download to a running node.
- [ ] **The release notes name the two tiers separately and say they are disjoint.** The attested archives are byte-identical and devnet-only; the `-randomx` archives join mainnet and the public testnet and are attested by nothing. Listing both under one "reproducible builds" heading is the blur §5 exists to prevent, and here it would be worse than a blur — it would tell a miner that the binary they are about to run is one somebody rebuilt and compared.
- [ ] Scoop manifest and Homebrew formulae updated with the tag and the real hashes (`packaging/`), and installed once on a machine that has never seen this project. The test that matters is on a clean host. **Read `zcd version` on that host and check the notes it was installed with agree with it** — both package managers install the pure-Go tier, so both must say so before a user starts a node with it (§5).
- [ ] **`packaging/` carries no identity.** Every URL in there says `PUBLISHER`, substituted at publication. It is a placeholder rather than a real name because §3's audit is easy to run over Go source and easy to forget over a Scoop manifest, and a handle in a package URL is published to everyone who installs. `install.sh` refuses to run unstamped rather than fetching from a host that does not exist — a script that failed open here would download from wherever the first plausible name resolved.
- [ ] `attestations/` has at least one independent signature for the previous release, and the call for this one has gone out.
- [ ] Identity audit clean (§3), voice pass done (§4) — code comments *and* `docs/adversarial/`.
- [ ] Publishing at M3 with the full package, not before (§7).
- [ ] Bootstrap node list reviewed: community-operable, replaceable by configuration, and every entry a name rather than an address so it can be moved without a release (§4). **Anything traceable to the author is a finding, and the one standing exception — the public testnet's launch seed in `cmd/zycordd` — is re-read here rather than waved through:** confirm it still resolves, that `--no-seeds` still removes it, and record whether a second seed on somebody else's infrastructure has been published yet. That second seed is what retires this exception.
- [ ] Public tree built from the working tree with no history (§1), UTC dates (§2).
- [ ] `zcd genesis` output recorded in the release notes (§6).
- [ ] **The four genesis-irreversible numbers are re-read and re-verified at the freeze commit: `seq_gas_target_genesis` = 1,600,000 on mainnet, the `seq_gas_capacity`/`seq_gas_target_genesis` ratio = 3.2 (5,120,000 over 1,600,000), `health_gate_bps` = 200, `epoch_length` = 2880.** All four enter `ConsensusRoot()`, so the freeze commit is the last moment any of them can move. What was ratified *about* each, so that this item is a re-check rather than a fresh decision: the permanent floor `T ≥ T₀`, the 3.2 capacity ratio with its exact terminal `applied/target = 0.50` and the era-boundary re-pin named as its standing remedy, and the one-block citation window shipped knowingly permissive while Era 0 keeps the health gate inert. The derivations behind all four are in `spec/params.json`'s `notes` and in [decisions/capacity-eras.md](decisions/capacity-eras.md), which is where a reader checks them rather than taking this list on trust. **If a pre-freeze change moved any of the four, the owner re-reads and re-ratifies the target and the capacity ratio before the freeze** — the ratification is of figures, not of prose — and records the freeze commit beside them in the release notes.
- [ ] **`spec/checkpoints.json` refreshed for this release, and its hash published beside the params hash.** Both values are printed by `zycordd` at startup and served on `/status`. The schedule is v1.0.0 none, v1.0.1 (~day 3) height 2,880, v1.0.2 (~day 10) height 20,160, v1.0.3 (~day 31) heights 40,320 and 86,400, monthly thereafter, sunset at height 1,051,200 — and every release refreshes `min_chain_work` with the height it is measured at, including after the sunset, when the floor is the only layer left. **Never pin a block younger than 2,880 blocks (24 h):** `checkpoints.MaxPinnableHeight(tip)` is that rule as a function — call it against the tip the release is cut at and pin nothing above what it returns, and confirm with `checkpoints.Set.ValidateAgainstTip(tip)`. Take each `block_id` from a node you run yourself, at least two hours after the height passed, and cross-check it against a second node before committing it.

  **Where the two `min_chain_work` numbers come from:** `/status` reports `chain_work`, the accumulated work of that node's canonical chain up to `height`, decimal. `min_chain_work` and `min_chain_work_height` are **that pair, read out of a single `/status` response** on a node you run yourself — not two readings, and never work read at one height written against a different one. Cross-check it the way the block ids are cross-checked: read `/status` on a second node of your own when it reports the same `height`, and the two `chain_work` values must be identical. If they differ, the chain was mid-reorg when you read it; take the pair again at a later height. **A floor set too high refuses the honest network** — the whole network, on every node that takes the release — so if the two readings cannot be made to agree, err downwards: pairing a measured work with a *higher* height is always safe (work only grows, so the real chain arrives there with more), pairing it with a *lower* one is the mistake that partitions. There is no release in which this item is skipped: after the sunset the floor is the only layer left, and a floor left at zero is layer 1 switched off for the life of the network.

  > **This file is not a parameter set and editing it must never move the params hash** — that separation is the only reason a routine release does not fork the network. If a change here changes `ConsensusRoot()` or `MainnetParamsHash()`, stop: `node/checkpoints`'s `TestCheckpointDataDoesNotEnterTheConsensusRoot` should have failed first, and something has moved across the boundary. See ARCHITECTURE §12, "Launch checkpoints".
- [ ] **The launch-transition reset's enumeration is closed before the first block is mined.** The launch preserves genesis byte for byte, so it is the one reset that cannot retreat to a new network id — which makes every rehearsal participant a heavy peer on the same network at the moment nobody is watching the peer set. Enumerate every node ever pointed at the rehearsal network from the peers files, provisioning records and monitoring; stop each one and wipe or verify-wipe its data directory; start only from empty directories; record the enumeration list in the reset log. **The launch does not proceed until that list closes** — waiting is the remedy here, not a fresh identity. The procedure and the residual-hazard watch signal (`zycord_reorg_depth_max`, or any forward jump in `zycord_chain_height`, in the post-reset window; response is to kill the offending peer's node) are in [TESTNET.md §Resets](TESTNET.md).
- [ ] Release commit PGP-signed with the project key, not a personal one.
- [ ] Project key fingerprint published in full alongside the four genesis values (§6), and matching the one in the whitepaper header. A mismatch between the two is a release blocker, not a typo.
- [ ] **`zycord-release-key.asc` published as a release asset**, beside the archives. `make dist` stages it out of `packaging/`; it is deliberately absent from `SHA256SUMS` (hashing a key with the file its own signature authenticates is a circle) and it is checked by fingerprint instead: `gpg --show-keys --with-fingerprint dist/zycord-release-key.asc` must print the whitepaper header's fingerprint before the asset is uploaded. The reason it is an asset and not only a keyserver lookup is what a clean-host walk found: `keys.openpgp.org`, the default keyserver in several GnuPG builds, serves this key stripped to a bare public-key packet with **no user ID and no self-signature**, and `gpg --import` refuses it — `new key but contains no user ID - skipped`. A user following the published instructions could not import the key at all, and therefore could not perform the only anti-impersonation check the project offers.
- [ ] **The published verification commands were run end to end on a machine with an empty keyring.** Not a re-reading of [INSTALL.md](INSTALL.md) — a walk of it, on a host where this key has never been imported, with `export GNUPGHOME=$(mktemp -d)` if a clean host is not available. Download **one** archive and `SHA256SUMS`; run the checksum line **exactly as published**, both spellings (`sha256sum --check --ignore-missing` and `shasum -a 256 --check --ignore-missing`), and confirm it exits **0** with one archive present rather than reporting the five it did not fetch. Import the key from **each** of the three sources INSTALL.md names — the repository copy, the release asset, `hkps://keyserver.ubuntu.com` — and confirm each import succeeds and each prints the whitepaper fingerprint under `gpg --fingerprint`. Then `gpg --verify SHA256SUMS.asc SHA256SUMS` and read the output: the "not certified with a trusted signature" warning is expected, a missing public key is not. This is the same clean-host walk as the released-binary item above; do them in one pass, download to running node.
- [ ] **The keyserver copy of the key is importable, and re-uploading it is an owner action.** Whoever holds the secret key re-uploads the full public key — user ID and self-signature — so that a user who reaches for the default keyserver is not stopped. `keys.openpgp.org` strips user IDs until an address is confirmed through it, which is not something a pseudonymous project can do; if it stays stripped, that is a documented limitation and INSTALL.md must keep naming the keyserver that works. Nobody but the key holder can discharge this box.
- [ ] **Every published figure is re-derivable from the tagged public tree** (whitepaper §15). The paper no longer names a separate measurement archive identified by its hash; it says the numbers can be re-derived from the published source, and the release must make that literally true — the benchmarks that produce each figure are in the tree at the tag, runnable by the commands below, with no step that lives on the author's machine. What the dropped archive was buying is bought by the reproducible build instead: two independent rebuilds of the tagged tree, and the tag signed with the project key. An anchor nobody else can reconstruct is not an anchor.
- [ ] **No `[X]` placeholder survives in `docs/whitepaper.md`.** §3 and §15 both quote measured figures — §3 the fold's slot-operations rate, §15 the full table — and a published paper carrying an unfilled placeholder is worse than one carrying no number, because it advertises that the claim was never checked. `grep -o '\[X\]' docs/whitepaper.md | wc -l` must print `0` — occurrences, not lines, since several sit on the same line.
- [ ] **`make wiring` green, and read as the publication gate it is.** Besides the identity checks §3 describes, it refuses a document in the swept set that cites an issue number, a pull-request number or a commit hash. The tree is republished as files under a new origin — no history and no tracker come with it — so such a reference resolves to nothing for every reader of the published copy, and the sentence it was carrying has silently lost its argument. The sweep is finished: the swept set now reaches every tracked path except the three frozen parameter files, whose `notes` are inside the announced parameter hash and cannot be rewritten without a respin. Both lists, and the reason for the second, are in `sim/wiring/history_reference_test.go`.
- [ ] **`make check-links` green.** Every relative markdown link in `docs/` and the root documents resolves to a file that exists in the tree being published. An adversarial record discharges its obligation to a reader by carrying a *link* to the document that owns the mechanism today rather than a dateline, and half that argument was that a link is an artefact a machine can check while `*as of M3*` rots in silence — so the check has to exist for the argument to hold. What it does **not** say, and what stays a review obligation: a resolving link proves the target exists, not that the target still supersedes the finding citing it, and nothing forces a new record to carry a link at all.
- [ ] Every figure in §15 traces to a named benchmark in the source tree, and the hardware line describes the machine **only as far as the measurement requires** — core or thread count, and whether it was loaded. Medians over the stated run count, not best-of.

  > **A checklist that *instructs* a leak is worse than the leak**, because the leak is an accident and the instruction is a policy. "The hardware line names the exact machine" reads like rigour and is not: the repository is published at launch, so a published hardware line is a published machine identifier. The figures are what this item protects; a model number was never doing any of that work.
- [ ] **Each published figure measured in its own process**, one benchmark per invocation — never read off a single `make bench` transcript. This is not fastidiousness: the same single-signature verification measures ~70 µs alone and ~117 µs after twelve seconds of load in the same process. The error is 65%, systematic, and invisible in the variance of one pass, so a transcript read top to bottom publishes the last benchmarks slower than they are. `make bench` is for watching the shape; publishing is `go test -run XXX -bench '^BenchmarkX$' -count 5` per figure, on an otherwise idle machine.
