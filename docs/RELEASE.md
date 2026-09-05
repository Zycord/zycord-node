# Release procedure

Two things have to be true of every release: it builds byte-identically from source, and it carries no identity. Neither survives being remembered at the last minute, so both are checklists.

---

## 0. The only gate is the machine you are standing at

**Nothing checks this tree except you, before you push.** There is no CI. The release workflow builds artefacts and runs no test, no fuzzer, no benchmark, and no binary it produced.

This is worth the space because of how it happened. The project's forge account was **permanently suspended, with no appeal**: workflow jobs computed RandomX hashes — the engine test suite, and two jobs that started a released node and waited for it to print which proof-of-work engine it had selected — and the forge's abuse detection read repeated hash computation in a runner's log as using its infrastructure to mine cryptocurrency. The account is gone, and with it every check that had ever been described here as "CI runs it".

The line that replaced them is a shape, so that it still decides cases nobody thought of. **Compiling** a binary that contains the engine is not mining, and hashing a finished artefact to show that two builds of one commit agree is ordinary build practice; both stay in the workflow. **Running** the proof-of-work function is what looks like mining, whatever the job is called and whatever it is for. When a job is arguable it does not ship: the cost of dropping a build check is a rebuild, and the cost of being wrong a second time is the account. [`sim/wiring/workflow_test.go`](../sim/wiring/workflow_test.go) holds the surviving workflow to that by equality — the set of files, the set of jobs, and the Make targets a workflow may call.

So every box in §8 is ticked by a command you ran, and the ones that used to say "CI runs it; this is the by-hand confirmation" now say it plainly. Run this before the tag exists:

```sh
make ci                 # lint, imports, wiring, whole suite, race, guard, differential, bench smoke
make fuzz               # a minute per decoder
make check-links        # every relative link in the documents resolves
make test-randomx       # the engine suite, and the vendored tree against its pinned tag
make repro              # zcd and zycordd byte-identical across paths and with or without .git
make canonical-dist-diff  # the container's pure-Go binaries are the ones make dist ships
GOOS=windows GOARCH=amd64 make repro-desktop   # the wallet, byte-identical across rebuilds
```

and, once the archives exist, `make release-smoke` against each `-randomx` archive the release publishes (§8). The Windows suite has no runner at all any more — [CONTRIBUTING.md](../CONTRIBUTING.md) lists the commands to run on a Windows machine, and Windows is one of the six platforms every release ships.

---

## 1. The public tree

The public repository is **not** this repository with a remote added. It is a fresh tree containing only the working files.

```sh
# From a clean checkout with everything committed and the §0 gate run:
git status --porcelain          # must be empty
make ci                         # must pass — nothing else will run it

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

Both in the environment, not as `make` variables. A command-line variable does not reach the `$(shell …)` calls that pick this target's tags, link flags and `CGO_ENABLED`, so `make repro-desktop GOOS=windows` builds *host* flags for a Windows target — measured, a `CGO_ENABLED=1` build with no `-H windowsgui`, PE subsystem 3, the console build [INSTALL.md](INSTALL.md) and the deleted `windows` job existed to keep out. The target refuses that form too, by reading the same resolved values the flags came from.

**Do not verify by building twice in one directory.** It cannot catch a difference that depends on *where* or *how* the source sits — which is exactly the difference that was there. Without `-buildvcs=false`, Go stamps `vcs.revision`, `vcs.time` and `vcs.modified` into any binary built inside a git work tree and derives the module version from the commit. §1 of this document publishes the tree **without history**, so the released binary carries no stamp; every verifier checks it from a **clone**, which has a `.git` and stamps their own revision. Measured: about a third of the binary differing, from nothing but the presence of a directory. Every third-party verification would have failed, and the failure looks like a compromised binary rather than like a missing build flag.

`make repro` exports the tree to two different paths and compares those against each other and against a build in the working tree. It is a §0 command: run it before the tag, because nothing else will.

**The C toolchain is pinned in `build/Dockerfile`,** which is what `-trimpath` and a pinned Go toolchain stopped covering the moment there was cgo (R1-L2, ARCHITECTURE §1 P6). Everything in it is pinned by content rather than by tag: the base image by digest, the Go toolchain by sha256 of the official tarball, and the C toolchain by a **snapshot.debian.org timestamp** rather than by hand-written package versions — a snapshot is verifiable from outside and a hand-written version string is not. `GOTOOLCHAIN=local` is set because without it a `go.mod` naming a newer toolchain makes the build silently download one, and the pinned version becomes a suggestion.

A release is built with `make canonical` and its checksums published. A job used to exercise the container on every push to `main`, so a change to it failed on the merge that landed it rather than on the day somebody tried to cut a release; that job is gone (§0), and the container is now exercised only when somebody runs `make canonical` or `make canonical-dist-diff`. **So a change to `build/Dockerfile` is a change to run both against before pushing it**, and the release checklist runs them again at the tag. Three full container builds is not cheap, which is exactly why it used to be skipped on pull requests and exactly why it is now easy to skip by accident.

`canonical` builds four artefacts, not two: `bin/zcd` and `bin/zycordd` from the
pure-Go target, `bin/zcd-randomx` and `bin/zycordd-randomx` from the cgo one.
They used to be two, because `build-randomx` wrote the same two paths `build`
does and ran second in the same container invocation — so the canonical build
certified the RandomX binary, which no release contains, and destroyed the
pure-Go one, which every release does, in one command. The CI job of the day diffed the survivor
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

**What says where that file came from is the build, not a key of ours.** The
release workflow emits a provenance attestation over every archive, keylessly:
GitHub signs, at build time, that these exact bytes came out of this
repository's workflow at a named commit, and the statement lands in a public
transparency log. `gh attestation verify <archive> --repo Zycord/zycord-node`
checks it with no key of ours and no keyring of the reader's.

**Releases are not signed with the project key, and dropping that was a
decision rather than an omission.** A release is built by Actions and goes from
there to whoever downloads it; nothing passes through a machine that could hold
a key. That left two homes for one, and both are worse than none — an Actions
secret, which belongs to whoever can push a workflow file, or a manual step
that the documents describe and nobody performs. A verification instruction
nobody can follow is worse than none, because it teaches a reader that checking
is optional.

So the three claims a reader can make are now: `SHA256SUMS.binaries` for *this
is what the source compiles to*, checked by rebuilding; the checksum lists for
*the file arrived intact*; and the attestation for *these bytes came out of
that workflow*. The project key remains what signs announcements — it just has
no part in a download.

**One carve-out, and it concedes the argument above rather than arguing around
it.** The release also carries `update-manifest.json` and a detached ed25519
signature over it, made in the publish job with a key held in an Actions secret.
That key belongs to whoever can push a workflow file — the objection in the
paragraph above stands, in full, and [UPDATES.md](UPDATES.md) says so in those
words rather than implying otherwise.

What changed is not the objection but the reader. All three claims above are made
to a *person*: they need a shell, `gh`, a Go toolchain, and the patience to run
them. The updater is a program deciding whether to execute what it just
downloaded, and a program that reaches for a Sigstore verifier pulls an x.509
chain, a transparency-log inclusion proof and a Fulcio root into the one package
whose whole argument is that there is very little of it to read. An ed25519
signature is thirty lines of standard library.

So it is a fourth claim, weaker than the other three, made to a different reader,
and worth exactly what a CI-held key is worth: it separates this project's
release page from a mirror, a fork under the same asset names, and a broken TLS
chain. It does not separate it from whoever holds the pipeline. A release nobody
can verify by hand would be the failure this section exists to prevent, and this
is not that — the three commands above are unchanged and still the answer.

Windows x86-64 has a `-randomx` leg and it is the only one that is
cross-compiled. `windows-latest` ships neither GNU make nor `zip` on `PATH`, so
building natively would cost two tools to buy one compiler, while mingw on
Ubuntu has all three; `dist-randomx` treats that as a supported path rather than
a workaround, and refuses a `GOOS` assigned on the command line so the intent
has to be put in the environment. The cost of cross-compiling is that the job
cannot start what it built. A `randomx-smoke-windows` job used to download the
published archive on a Windows runner and start `zycordd.exe` there; it was the
clearest instance of the pattern that cost this project its account (§0) —
it executed the engine rather than compiling it — and it may not come back in
any form. The Windows archive is now smoke-tested by hand, on a Windows machine,
against the published `.zip`, and §8 asks for it explicitly. Windows arm64 still has no leg:
no cross-toolchain in the image, no native runner, so it ships the pure-Go
archive and `docs/INSTALL.md` and the Scoop notes say what it can and cannot
do.

Wails reaches WebView2 through pure Go, so the Windows build has no cgo in it: it builds at `CGO_ENABLED=0` on a machine with no C compiler, and two builds of one commit are identical to the byte. `CGO_ENABLED=0` is *pinned* for that target rather than inherited from whichever machine runs it, so the property is stated instead of accidental.

**That row buys the wallet nothing here, because checked and attested are different claims.** Being checked is a statement we make to ourselves: two builds of one commit on one machine agree — and the wallet is checked at every tag, and by hand before it. `make repro-desktop` exports the commit to two paths, builds the wallet in each and in the working tree with the same command `make dist-desktop` builds the artefact with, and compares the three; `release.yml`'s Windows leg runs it before that recipe archives anything, and §0 runs it by hand on the release machine. A job used to run it on every push to `main` as well; that job is gone with every other workflow but the build (§0), so the by-hand run is now the only one that happens before a tag. Attestation is a statement made to a stranger — here is a hash, rebuild the tag yourself and compare — and for the wallet there is nothing for a stranger to compare against. What a release publishes for it is a `.zip`, whose hash is not reproducible even when the binary inside it is, because a zip entry records the file's mtime; and on Linux and macOS the binary is not reproducible either. One attested-looking line, for one platform of one artefact, is exactly the blur this section exists to prevent.

**Publish that distinction, do not bury it.** A release that ships both under one "reproducible builds" heading has made the phrase mean nothing, and the phrase is the entire substitute for a signature this project has. Concretely:

- `SHA256SUMS.binaries` covers `zcd` and `zycordd` only. It is the file an independent rebuilder compares against, and it **must never grow a line for the wallet** — including the Windows one, whatever this project has or has not checked about it. The rule rests on there being nothing published for a stranger to compare a rebuild against, and a check run against our own build is not such a thing.
- **`make repro-desktop` prints its verdict and writes no file.** A per-binary checksum file for the wallet, published next to the archives, reads to a downloader as precisely the attestation the bullet above says this project does not make — and a hash written by the same build that produced the binary checks nothing anyway. The verdict belongs in the terminal of whoever ran it, where a maintainer reads it, and not in the release, where a stranger would.
- `make dist-desktop` prints its verdict every time it runs, and the verdict is per-target: the cgo disclaimer on linux and darwin, and on windows the narrower statement that the binary is byte-identical while the archive is not. Leave both there.
- The release notes name the reproducible artefacts and then say, in the same paragraph, that the desktop wallet is not one of them and that `zcd ui` serves the identical interface from a binary that is.
- Nothing in `attestations/` is ever signed for the wallet. `attestations/README.md` says so; a pull request that adds one is a review finding.

### Releasing the wallet

`.github/workflows/release.yml` runs the two as separate jobs, which is what keeps the two stories separate in the artefact list as well as in the prose. The desktop matrix is one runner per operating system *where cgo is the reason* — it cannot be cross-compiled without a per-target toolchain and SDK — so linux and darwin build on their own machines and windows, which has no cgo, is cross-compiled from the Linux runner like every `zcd` artefact. **That leg must not run on `windows-latest`**: it calls `make dist-desktop`, and that image ships neither GNU make nor Info-ZIP `zip`, while the recipe is POSIX `sh` and archives Windows with `zip`. `desktop/` is a separate Go module, so a Wails release that breaks nothing here still cannot break `make ci`.

**The release is no longer gated on anything, and that is a loss worth naming rather than glossing.** Every build job in `release.yml` runs on Linux or macOS — `cli` cross-compiles all six platforms from one Ubuntu runner, and the wallet's Windows leg does the same — so the workflow produces Windows artefacts without ever executing one. A reusable `windows.yml` used to run the whole suite natively on windows/amd64 and read the PE subsystem out of the wallet it built, and `cli`, `cli-randomx` and `desktop` all `needs:`-ed it, so a red Windows job meant no artefacts were built at all. That workflow is gone (§0): it ran tests, and nothing that runs tests may live on a hosted runner any more.

What replaces it is §1's first precondition and nothing else — a clean checkout with everything committed and the §0 gate run — plus the Windows command list in [CONTRIBUTING.md](../CONTRIBUTING.md), executed on an actual Windows machine before the tag is pushed. That is weaker than a job, because a person can skip it and a `needs:` cannot. It is also the whole of what is available: Windows is one of the six platforms every release ships, and cross-compiling produces a Windows binary without ever running one. What narrows the gap between a person and a `needs:` is that the run leaves a file: §8's item is ticked against a section appended to [`docs/localnet/soaks/windows-manual-run.md`](localnet/soaks/windows-manual-run.md), naming the commit, the machine and each line's result, so a skipped run is visible in the tree afterwards rather than only at the moment it was skipped. That is evidence rather than enforcement, and the difference is worth stating: it catches the release that forgot, not the release that decided not to.

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

**Publish the project key alongside them**, as a fifth value: the full fingerprint of the pseudonymous key that signs release tags and the announcements themselves, printed in the announcement and carried in the whitepaper header. It does not sign release artefacts — §5 says what does — and it is published for the other half of the job: letting a reader tie two statements to one author. This is not an exception to the rule below — it is what makes the rule enforceable. A key that signs artifacts is the opposite of a contact that resolves to a person: it lets a reader verify that two releases came from the same author *without* learning who that is, and it is the only way an anonymous project can be impersonated-proof. Publish the fingerprint in full, in more than one place, and never rotate it silently; a key that changes without a signed statement from the old one is indistinguishable from a compromise.

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

**Every box below is ticked by a command somebody ran on this machine.** Nothing on a hosted runner checks any of it (§0), so an unticked box is an unrun check and not a formality.

- [ ] `make ci` green on the tagged commit — lint, the import graph, the wiring guards, the whole suite, `make race`, `make guard`, the differential fold and the benchmark smoke run.
- [ ] **The Windows command list in [CONTRIBUTING.md](../CONTRIBUTING.md) run on a Windows machine**, at the tagged commit, **plus the wallet smoke test, and the run written into [`docs/localnet/soaks/windows-manual-run.md`](localnet/soaks/windows-manual-run.md)**. There is no runner left that executes a Windows binary (§5), and Windows is one of the six platforms every release ships. The list is what the deleted `windows` job ran, kept as commands rather than as YAML for exactly this; it has since grown the `make ci` targets that port — `wiring`, `guard`, `differential`, `bench-smoke` — and `./update/`, whose three `_windows.go` files no Linux run compiles at all. `check-imports` and `-race` are recorded there as deliberately absent, with the argument, so that their absence is a decision somebody made rather than something nobody noticed. **This box is not tickable from memory.** The record file is where the evidence goes, in the shape the other recorded runs in that directory use, and a box ticked with no section appended to it is the unrun check this section's opening line is about.
- [ ] **`make test-randomx` green**, which includes the vendored engine tree against its pinned upstream tag. Go's build cache does not see into `core/pow/randomx/upstream/`, so a modified vendor tree compiles in the release workflow without anything noticing — this run is what notices.
- [ ] **`make soak-long` green**, for a duration measured in hours and then a multi-day run (R5-G1). Both regimes: convergence after the chaos stops, and history agreement while contention never stops. This is the gate whose evidence has historically been thinnest, and the four-minute threshold that surfaced [I4-H1](adversarial/I4.md) is the argument that duration buys findings.
- [ ] The soak reported `all nodes report the consensus-state guard armed` and crossed at least one epoch boundary — a run that did neither proves much less than it appears to.
- [ ] `go run ./spec/gen` produces no diff — the committed vectors match the implementation.
- [ ] The differential fold passes; the fuzz farm has run the current corpus without a crash.
- [ ] Byte-identical rebuild verified (§5) — for `zcd` and `zycordd`, and separately for the Windows wallet binary (`GOOS=windows GOARCH=amd64 make repro-desktop` — nothing else runs this, §0). Both variables in the environment and `GOARCH` pinned, or the box gets ticked for a target no release contains (§5). The desktop wallet is **not attested on any platform**, including that one: it is labelled as unattested in the release notes, and it has no line in `SHA256SUMS.binaries` (§5). Checked is not attested.
- [ ] `make canonical-dist-diff` green on the tagged commit — the canonical container's pure-Go `zcd` and `zycordd` are byte-identical to the `linux/<container arch>` binaries `make dist` stages — the target reads that arch out of the container, so the box is tickable on this project's arm64 hardware too (§5). Nothing else runs it (§0). It is the check that would have caught the canonical build certifying a binary no release contains, and reading `go version -m bin/zcd bin/zcd-randomx` once after it is how you see the tags rather than infer them.
- [ ] `go list -m all` at the root does not mention Wails, and `make check-imports` is green with no edit. The desktop module is isolated or it is not.
- [ ] **The release workflow published it, and nothing was assembled by hand.** The `publish` job collects every archive, attests its provenance and opens the release. If a step of that was done manually, find out why and fix the workflow rather than the release: the whole claim is that the bytes go from Actions to the user untouched.
- [ ] **`make dist` run locally and its hashes compared against what the release published.** The attested tier is byte-identical anywhere (§5), so a local rebuild either matches exactly or the published archive is not this source. This is the check that makes the reproducibility claim true rather than asserted, and it is the one a reader is invited to repeat.
- [ ] **`gh attestation verify` run against a published archive of each tier**, from a clean checkout, exactly as `docs/INSTALL.md` publishes it. The `-randomx` tier cannot be rebuilt and compared — cgo is reproducible nowhere — so the attestation is the whole of what covers it, and a release where it does not verify is a release nobody can check.
- [ ] **`make dist-randomx` produced by the workflow on every target the release publishes it for** (linux amd64/arm64, darwin amd64/arm64 — one native runner each, because cgo needs a C++ toolchain for the target), with `SHA256SUMS.randomx` beside the archives. It is still **not** merged into `SHA256SUMS` and gets **no** line in `SHA256SUMS.binaries` (§5): merging it into either would say something about those bytes that nobody can check.
- [ ] **A released binary was started against the tagged parameters and did not refuse — including the Windows one.** Unpack an archive — the actual published one, not `bin/zycordd` — and run `make release-smoke ZYCORDD=<path>`. **This is the check that must never go back into a workflow** (§0): a job doing it is a job whose log shows the proof-of-work engine starting up, which is what the abuse detection reads as mining, and a `randomx-smoke-windows` job doing exactly this is the clearest reason the account is gone. Doing it here is not a downgrade of the check; it is the same check, at the only place it may be run. It starts the node against the embedded **mainnet** set with no `--devnet` and no `--params`, waits for `cmd/zycordd`'s own `proof of work: <engine> engine` line, and fails with the process's output if the node exited instead. **Do this for the `-randomx` archive of every platform in the matrix**, and once for a plain archive to see the refusal it is supposed to produce — a check that has only ever passed is a check nobody has seen work. Every other gate in this document builds an artefact and hashes it, and a hash cannot tell you a binary starts; that is precisely how six platforms of binaries that refuse to start on mainnet passed a green pipeline and three package managers. This is the same walk the empty-keyring verification below uses: one clean host, one archive, from download to a running node.
- [ ] **The release notes name the two tiers separately and say they are disjoint.** The attested archives are byte-identical and devnet-only; the `-randomx` archives join mainnet and the public testnet and are attested by nothing. Listing both under one "reproducible builds" heading is the blur §5 exists to prevent, and here it would be worse than a blur — it would tell a miner that the binary they are about to run is one somebody rebuilt and compared.
- [ ] Scoop manifest and Homebrew formulae updated with the tag and the real hashes (`packaging/`), and installed once on a machine that has never seen this project. The test that matters is on a clean host. **Read `zcd version` on that host and check the notes it was installed with agree with it** — both package managers install the pure-Go tier, so both must say so before a user starts a node with it (§5).
- [ ] **`packaging/` names the publishing account and nothing else.** It used to carry a `PUBLISHER` placeholder substituted here, on the argument that a handle in a package URL is published to everyone who installs. Two things retired that: the account is the one this repository is served from, so a reader who has the file already had the name, and the substitution never actually ran — `make dist` does not stage `install.sh` and the workflow does not upload it, so the copy the install docs told people to fetch has never existed. What the item checks now is that the account named is the publishing one and that **no other identity has appeared** — a personal handle, a real name, a second account. `sim/wiring`'s forge guard keeps a closed allow-list, so anything else fails the sweep rather than this checkbox, and this box is the human half: read `packaging/` and confirm nothing has been added that the sweep has no pattern for.
- [ ] **The update signing secret is configured, and the publish job proved it.** `ZYCORD_UPDATE_SIGNING_KEY` holds the 64-hex seed of the key `update/keys.json` names `current`. A tag build with it unset fails the job on purpose rather than publishing a release nobody can update to — and `zcd update manifest --sign` refuses a key that is not in the embedded set, because a release signed by a key no binary carries updates nobody and does it in silence. Both `update-manifest.json` and `update-manifest.json.sig` are among the published assets, and the workflow's own verify step ran the real reader over them before publication.
- [ ] **The key set is unchanged, or the rotation was announced first.** If `update/keys.json` moved, the GPG-signed announcement naming the new set went out before the release, and it quotes `sha256sum update/keys.json` — a value any reader can recompute. A rotation is a hard cut for anyone who has not updated since the release that introduced the incoming key; that is the design and it is written down in [UPDATES.md](UPDATES.md), but it is not something to discover at a tag.
- [ ] **No flag was removed or renamed that a released binary accepts.** The updater restarts a node with its own argument list, so a flag that disappears turns `--update auto` into a node that installs the release, restarts, and dies at flag parsing — already running the new binary, so a restart does not help. The pre-flight refuses such a release rather than installing it, which turns a fleet-wide brick into a logged refusal; that is a backstop, not a licence. Deprecate a flag by accepting and ignoring it for one release.
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
- [ ] **The published verification commands were run end to end on a clean host.** Not a re-reading of [INSTALL.md](INSTALL.md) — a walk of it. Download **one** archive and `SHA256SUMS`; run the checksum line **exactly as published**, both spellings (`sha256sum --check --ignore-missing` and `shasum -a 256 --check --ignore-missing`), and confirm it exits **0** with one archive present rather than reporting the others it did not fetch. Then run `gh attestation verify` on that archive and read the output. Then rebuild the attested tier from the tag and compare against `SHA256SUMS.binaries`. Three checks, three different claims; a page that publishes all three has to have had all three walked.
- [ ] **The key is still importable from somewhere that works.** No download is verified with it any more — §5 — but it signs announcements, and a signed announcement nobody can check is a signature that does nothing. `keys.openpgp.org` strips user IDs until an address is confirmed through it, which a pseudonymous project cannot do, and `gpg --import` refuses the stripped copy outright. So the release asset and the in-repo copy are the sources that have to keep working, and this box is confirming that at least one of them does. Nobody but the key holder can re-upload to a keyserver.
- [ ] **Every published figure is re-derivable from the tagged public tree** (whitepaper §15). The paper no longer names a separate measurement archive identified by its hash; it says the numbers can be re-derived from the published source, and the release must make that literally true — the benchmarks that produce each figure are in the tree at the tag, runnable by the commands below, with no step that lives on the author's machine. What the dropped archive was buying is bought by the reproducible build instead: two independent rebuilds of the tagged tree, and the tag signed with the project key. An anchor nobody else can reconstruct is not an anchor.
- [ ] **No `[X]` placeholder survives in `docs/whitepaper.md`.** §3 and §15 both quote measured figures — §3 the fold's slot-operations rate, §15 the full table — and a published paper carrying an unfilled placeholder is worse than one carrying no number, because it advertises that the claim was never checked. `grep -o '\[X\]' docs/whitepaper.md | wc -l` must print `0` — occurrences, not lines, since several sit on the same line.
- [ ] **`make wiring` green, and read as the publication gate it is.** Besides the identity checks §3 describes, it refuses a document in the swept set that cites an issue number, a pull-request number or a commit hash. The tree is republished as files under a new origin — no history and no tracker come with it — so such a reference resolves to nothing for every reader of the published copy, and the sentence it was carrying has silently lost its argument. The sweep is finished: the swept set now reaches every tracked path except the three frozen parameter files, whose `notes` are inside the announced parameter hash and cannot be rewritten without a respin. Both lists, and the reason for the second, are in `sim/wiring/history_reference_test.go`.
- [ ] **`make check-links` green.** Every relative markdown link in `docs/` and the root documents resolves to a file that exists in the tree being published. An adversarial record discharges its obligation to a reader by carrying a *link* to the document that owns the mechanism today rather than a dateline, and half that argument was that a link is an artefact a machine can check while `*as of M3*` rots in silence — so the check has to exist for the argument to hold. What it does **not** say, and what stays a review obligation: a resolving link proves the target exists, not that the target still supersedes the finding citing it, and nothing forces a new record to carry a link at all.
- [ ] Every figure in §15 traces to a named benchmark in the source tree, and the hardware line describes the machine **only as far as the measurement requires** — core or thread count, and whether it was loaded. Medians over the stated run count, not best-of.

  > **A checklist that *instructs* a leak is worse than the leak**, because the leak is an accident and the instruction is a policy. "The hardware line names the exact machine" reads like rigour and is not: the repository is published at launch, so a published hardware line is a published machine identifier. The figures are what this item protects; a model number was never doing any of that work.
- [ ] **Each published figure measured in its own process**, one benchmark per invocation — never read off a single `make bench` transcript. This is not fastidiousness: the same single-signature verification measures ~70 µs alone and ~117 µs after twelve seconds of load in the same process. The error is 65%, systematic, and invisible in the variance of one pass, so a transcript read top to bottom publishes the last benchmarks slower than they are. `make bench` is for watching the shape; publishing is `go test -run XXX -bench '^BenchmarkX$' -count 5` per figure, on an otherwise idle machine.
