# Zycord build.
#
# Every release must build byte-identically from source. That is the only trust
# an anonymous author can offer, so the build is boring on purpose: a pinned
# toolchain, -trimpath, no build ids, no cgo (until RandomX arrives at M3), and
# no network access at build time.

GO      ?= go

# The Go toolchain, pinned — and pinned HERE, which is the whole point.
#
# Nothing on this build path chose a compiler. `go.mod` said `go 1.25.0`,
# `build/Dockerfile` installed 1.26.2, and a stranger following docs/INSTALL.md
# got whatever was on their PATH: three answers for one source tree. This
# project's own release workflow recorded the damage as three different SHA-256
# values for one commit and one flag set (go1.25.0, go1.26.0, go1.26.6). So the
# check offered in place of a code-signing certificate FAILED BY DEFAULT for an
# honest verifier — and docs/INSTALL.md tells that verifier a mismatch "looks
# like a compromised binary", which trains people to ignore the one signal that
# would matter if a binary really had been swapped.
#
# The fix is NOT a `toolchain` directive in go.mod, and that has to be said
# because it is the obvious one. Under GOTOOLCHAIN=auto — the default — the
# `go` and `toolchain` lines are a FLOOR, never a ceiling: they say "at least
# this much", so a verifier with a newer Go installed still builds with the
# newer Go and still gets different bytes. go.mod carries the directive anyway,
# because that is the file `setup-go`'s `go-version-file:` reads, but it is not
# the pin and must not be mistaken for one.
#
# GOTOOLCHAIN is the ceiling. Exported here it reaches every `go` this file
# runs — `build`, `dist`, `dist-randomx`, the wallet, the sub-makes `repro`
# spawns into its export directories, and the `make build` that runs inside the
# canonical container — so exactly one line decides which compiler produced a
# released binary.
#
# Three files name this version and they must not drift apart:
#
#   Makefile           GO_TOOLCHAIN below   the pin (a ceiling)
#   go.mod             `toolchain` line     what CI's setup-go installs
#   build/Dockerfile   ARG GO_VERSION       the canonical container's Go
#
# sim/wiring/toolchain_test.go fails if any two of them disagree, because the
# three-way disagreement is the defect itself and not a tidiness question.
#
# Changing this version is a release decision: it moves every hash in
# SHA256SUMS.binaries. A reader who needs to know which toolchain built a
# released binary does not have to trust this line — Go stamps it into the
# artefact, and `go version -m bin/zcd` prints it back.
GO_TOOLCHAIN := go1.26.2
export GOTOOLCHAIN := $(GO_TOOLCHAIN)

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BIN     := bin

# -trimpath strips local filesystem paths; -buildid= strips the build id; both
# are what make two builds of one commit compare equal.
#
# -buildvcs=false is the third, and it is the one that was missing. Go stamps
# vcs.revision, vcs.time and vcs.modified into a binary built inside a git
# work tree, and turns the module version into a pseudo-version derived from
# the commit. So the SAME SOURCES produce different binaries depending on
# whether a .git directory happens to be next to them — measured: identical
# with it absent from both, 2.2 MB of the 6.9 MB binary differing with it
# present in one.
#
# That is not a nicety, it is the reproducible-build claim. docs/RELEASE.md §1
# publishes the tree WITHOUT history, so the released binary carries no stamp;
# anyone verifying it does so from a CLONE, which has a .git and stamps their
# own revision. Every third-party verification would have failed, and the
# failure looks like a compromised binary rather than like a build flag.
#
# Nothing is lost: the version a user sees comes from -X main.version below,
# which is explicit rather than inferred from how the source was obtained.
GOFLAGS   := -trimpath -buildvcs=false
LDFLAGS   := -s -w -buildid= -X main.version=$(VERSION)
BUILD_ENV := CGO_ENABLED=0

# The extension an executable has to carry in order to be executable.
#
# `go build -o NAME` writes exactly NAME and appends nothing -- only the
# default output, the one with no -o at all, gets the platform suffix. On
# Windows that is not a cosmetic difference: command resolution goes through
# PATHEXT, so an extensionless PE cannot be run at all. Measured, with the
# directory on PATH, `zcd version` from cmd.exe answers
#
#     'zcd' is not recognized as an internal or external command
#
# and so does the same command given the absolute path, and so does
# PowerShell, and so does any Go os/exec caller. `dist` has known this since
# it was written (ext=; if [ "$$os" = windows ]; then ext=.exe; fi); `build`
# did not -- so the from-source route docs/INSTALL.md offers "anyone with a Go
# toolchain" produced two files a Windows user cannot start, and the plain
# `zcd` / `zycordd` invocations throughout docs/RUNNING.md could not work.
#
# The bytes are identical either way -- verified by comparing a `-o zcd`
# build against a `-o zcd.exe` build of the same tree -- so this is a naming
# fix and touches nothing the reproducibility claim rests on.
EXE := $(if $(filter windows,$(shell $(GO) env GOOS)),.exe,)

.PHONY: all
all: build

# Always invoke the Go build rather than treating the binary as an up-to-date
# file target. A file target with no prerequisites is never rebuilt when the
# sources change, which is silent and — for the reproducibility check below —
# actively misleading: it would compare a stale binary against a fresh one and
# call the difference a reproducibility failure. Go's own build cache provides
# the incrementality this would have bought.
#
# require-toolchain first: a binary built by the wrong compiler is not a slower
# build, it is a different artefact, and the whole of `repro` and
# SHA256SUMS.binaries is downstream of that.
.PHONY: build
build: require-toolchain
	@mkdir -p $(BIN)
	$(BUILD_ENV) $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/zcd$(EXE) ./cmd/zcd
	$(BUILD_ENV) $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/zycordd$(EXE) ./cmd/zycordd

# The pin, checked out loud before anything is compiled.
#
# GOTOOLCHAIN above already forces the answer; this one reports it, and the
# difference matters on the machines where the force cannot land. A verifier
# whose `go` cannot become $(GO_TOOLCHAIN) — no network to fetch it, a
# GOTOOLCHAIN pinned elsewhere in their environment that make cannot see, a Go
# too old to switch toolchains at all — would otherwise get a binary that
# differs from SHA256SUMS.binaries with nothing said about why. That silence is
# the whole defect this pin exists for: docs/INSTALL.md tells them a mismatch
# "looks like a compromised binary", so the default outcome of an honest check
# is a false alarm.
#
# `go env GOVERSION` is the effective toolchain, after any switch, which is the
# compiler that will actually run. Comparing against the pin is therefore a
# statement about the bytes and not about what is on PATH.
.PHONY: require-toolchain
require-toolchain:
	@have=$$($(GO) env GOVERSION 2>/dev/null); \
	if [ "$$have" != "$(GO_TOOLCHAIN)" ]; then \
	  echo "this build is pinned to $(GO_TOOLCHAIN); the toolchain in use is [$$have]."; \
	  echo; \
	  echo "A released binary is the output of one compiler. Another one produces"; \
	  echo "different bytes from the same source, and against SHA256SUMS.binaries"; \
	  echo "that reads as a tampered download rather than as a different Go."; \
	  echo; \
	  echo "Install $(GO_TOOLCHAIN), or let the go command fetch it: this makefile"; \
	  echo "sets GOTOOLCHAIN=$(GO_TOOLCHAIN), and go downloads that toolchain on"; \
	  echo "first use and verifies it against the checksum database. Nothing else"; \
	  echo "in this build reaches the network."; \
	  echo; \
	  echo "Which toolchain built a RELEASED binary is readable out of the binary:"; \
	  echo "  go version -m bin/zcd"; \
	  exit 1; \
	fi

# Both repro targets compare a build of the WORKING TREE against builds of
# `git archive HEAD`. On a dirty tree those are different sources, so the
# comparison fails and reports a reproducibility break that is not one — noise
# with authority, which is worse than silence, and which gets a
# check ignored on the day it is right. Refuse instead.
.PHONY: require-clean-tree
require-clean-tree:
	@if [ -n "$$(git status --porcelain)" ]; then \
	  echo "repro compares the working tree against 'git archive HEAD', so it"; \
	  echo "needs a clean tree — otherwise it compares different sources and"; \
	  echo "calls the difference a reproducibility failure. Uncommitted:"; \
	  git status --short | sed 's/^/  /'; \
	  exit 1; \
	fi

# The reproducibility check, run the way a verifier will actually run it.
#
# Building twice in the same directory — which is what CI did, and all it did
# — cannot catch a difference that depends on WHERE or HOW the source sits.
# It could not have caught -buildvcs, which made the same sources produce
# different binaries depending on whether a .git directory was next to them,
# and which would have broken every third-party verification: RELEASE §1
# publishes the tree without history, and anyone checking it does so from a
# clone, which has one.
#
# So this exports the tree to two different paths, neither with a .git, and
# compares those against each other AND against a build in the working tree.
# VERSION is pinned because `git describe` is a property of the repository
# rather than of the source.
.PHONY: repro
repro: require-clean-tree
	@set -e; 	tmp=$$(mktemp -d); 	trap 'rm -rf "$$tmp"' EXIT; 	mkdir -p "$$tmp/a" "$$tmp/b-a-deliberately-longer-path"; 	git archive HEAD | tar -x -C "$$tmp/a"; 	git archive HEAD | tar -x -C "$$tmp/b-a-deliberately-longer-path"; 	$(MAKE) --no-print-directory build VERSION=repro >/dev/null; 	cp $(BIN)/zcd "$$tmp/zcd.git"; cp $(BIN)/zycordd "$$tmp/zycordd.git"; 	$(MAKE) --no-print-directory -C "$$tmp/a" build VERSION=repro >/dev/null; 	$(MAKE) --no-print-directory -C "$$tmp/b-a-deliberately-longer-path" build VERSION=repro >/dev/null; 	cmp "$$tmp/zcd.git" "$$tmp/a/bin/zcd"; 	cmp "$$tmp/zycordd.git" "$$tmp/a/bin/zycordd"; 	cmp "$$tmp/a/bin/zcd" "$$tmp/b-a-deliberately-longer-path/bin/zcd"; 	cmp "$$tmp/a/bin/zycordd" "$$tmp/b-a-deliberately-longer-path/bin/zycordd"; 	echo "reproducible: identical across two paths and with/without .git"

# The same check for the cgo build, which is where a C toolchain's own path
# and build-id leakage would show up. Separate because it needs cgo.
.PHONY: repro-randomx
repro-randomx: require-clean-tree
	@set -e; 	tmp=$$(mktemp -d); 	trap 'rm -rf "$$tmp"' EXIT; 	mkdir -p "$$tmp/a" "$$tmp/b-a-deliberately-longer-path"; 	git archive HEAD | tar -x -C "$$tmp/a"; 	git archive HEAD | tar -x -C "$$tmp/b-a-deliberately-longer-path"; 	$(MAKE) --no-print-directory -C "$$tmp/a" build-randomx VERSION=repro >/dev/null; 	$(MAKE) --no-print-directory -C "$$tmp/b-a-deliberately-longer-path" build-randomx VERSION=repro >/dev/null; 	cmp "$$tmp/a/bin/zcd-randomx" "$$tmp/b-a-deliberately-longer-path/bin/zcd-randomx"; 	cmp "$$tmp/a/bin/zycordd-randomx" "$$tmp/b-a-deliberately-longer-path/bin/zycordd-randomx"; 	echo "reproducible (randomx): identical across two paths"

# There is a third reproducibility check and it is not here: repro-desktop sits
# beside the recipe it checks, below dist-desktop, because it needs the DESKTOP_*
# variables that decide the wallet's tags, link flags and CGO_ENABLED.

# The canonical build, inside the container that pins the compiler.
#
# `make repro` above already shows the build does not depend on WHERE it runs.
# This is the other half: it does depend on WHICH compiler runs, and a C
# toolchain is not a property of this repository unless something pins it
# (ARCHITECTURE §1 P6, RELEASE §5, R1-L2).
#
# DOCKER ?= docker so a reader on podman can say `make canonical DOCKER=podman`.
DOCKER ?= docker
CANONICAL_IMAGE ?= zycord-build

# Every container run that WRITES INTO THE BIND MOUNT takes these, and the
# reason is one bug rather than a preference.
#
# The image's default user is root, and on Linux a root process writing into a
# `-v $(PWD):/src` bind mount leaves root-owned files ON THE HOST. So `bin/`
# and `dist/` came back undeletable and the next `make clean` -- which CI runs
# between the two canonical builds it compares -- died on `rm: cannot remove
# 'bin/zcd': Permission denied`, having built everything correctly first. The
# artefacts were right; the workspace was left unusable, which is why the job
# had never once completed.
#
# HOME travels with the uid because the two are one change: Go keeps its build
# and module caches under HOME, root's is /root, and a process running as
# somebody else cannot write there. /tmp is writable by any uid and dies with
# the container, so a run still fetches its own modules and stays as hermetic
# as it was.
#
# Nothing about the output moves: `-trimpath` and SOURCE_DATE_EPOCH decide what
# reaches a binary and a uid was never part of it. The comparison these targets
# exist for is what proves that, and it is the check that could never run.
#
# A run that only reads -- `go env GOARCH` below -- does not need them and does
# not take them.
DOCKER_AS_CALLER ?= --user "$(shell id -u):$(shell id -g)" -e HOME=/tmp

.PHONY: canonical-image
canonical-image:
	$(DOCKER) build -t $(CANONICAL_IMAGE) build/

# Four artefacts, not two. `build` and `build-randomx` write distinct paths
# (see build-randomx above), so this one container invocation now leaves the
# pure-Go pair AND the cgo pair on disk instead of the second silently
# replacing the first.
.PHONY: canonical
canonical: canonical-image
	$(DOCKER) run --rm -v "$(PWD):/src" $(DOCKER_AS_CALLER) $(CANONICAL_IMAGE) \
	  make build build-randomx VERSION=$(VERSION)
	@echo "canonical build complete; compare with sha256sum $(BIN)/zcd $(BIN)/zycordd $(BIN)/zcd-randomx $(BIN)/zycordd-randomx"

# The comparison nothing made, and the one that would have caught the pure-Go
# binaries being silently replaced by the cgo ones (see build-randomx below).
#
# `make canonical` certifies $(BIN)/zcd. `make dist` builds what every archive
# contains and what .github/workflows/release.yml publishes. Nothing compared
# the two: the canonical CI job of the day ran `make canonical` twice and
# diffed the results, so both sides of its diff were the same binary — and while
# build-randomx wrote $(BIN)/zcd too, that binary was the RandomX one, which no
# release ships. A comparison with no term for the pure-Go artefact cannot
# notice that the pure-Go artefact was destroyed.
#
# So it runs `canonical` itself — the real target, not a copy of its command
# line, so that whatever that target does is what gets compared — and then stages
# `dist` from the same container. What is checked is that the $(BIN)/zcd and
# $(BIN)/zycordd left behind are byte-identical to the ones `dist` produces. If
# the two build targets ever share an output path again, the file left in $(BIN)
# is the cgo binary and these hashes differ.
#
# `dist` runs in the SAME container on purpose. The property under test is that
# the canonical pure-Go artefact and the shipped one are the same bytes; running
# dist on the host would add the host's Go toolchain as a second variable and
# make this a test of the toolchain pin instead of a test of the recipes.
#
# PLATFORMS is narrowed to ONE platform, and it has to be the container's own:
# `canonical` runs `make build`, which sets no GOOS/GOARCH and so produces the
# container's NATIVE binaries. Comparing those against a cross-compiled
# linux/amd64 archive would report a byte mismatch on any arm64 host — and
# build/Dockerfile pins a Go checksum for arm64, so an arm64 host is supported
# and intended — and RELEASE §5 records that this project has arm64 hardware,
# where the same hard-coded-arch mistake already made repro-desktop tick a box
# for a target no release contains.
# That failure would be an architecture difference wearing the words "one target
# overwriting the other's output", which is the noise-with-authority that
# require-clean-tree above exists to prevent. So ask the container what it is,
# once, and use that answer on both sides. Narrowing to one platform also keeps
# `zip` out of the container's dependency list, since no `linux/*` archive
# needs it.
.PHONY: canonical-dist-diff
canonical-dist-diff: canonical
	@set -e; \
	arch=$$($(DOCKER) run --rm $(CANONICAL_IMAGE) go env GOARCH); \
	if [ -z "$$arch" ]; then echo "could not read GOARCH from $(CANONICAL_IMAGE)"; exit 1; fi; \
	echo "comparing canonical against dist for linux/$$arch (the container's own architecture)"; \
	$(DOCKER) run --rm -v "$(PWD):/src" $(DOCKER_AS_CALLER) $(CANONICAL_IMAGE) \
	  make dist PLATFORMS=linux/$$arch VERSION=$(VERSION); \
	stage=$(DIST)/zycord-$(DIST_VERSION)-linux-$$arch; \
	for pair in "$(BIN)/zcd:$$stage/zcd" "$(BIN)/zycordd:$$stage/zycordd"; do \
	  built=$${pair%%:*}; shipped=$${pair#*:}; \
	  a=$$($(SHA256) "$$built" | cut -d' ' -f1); \
	  b=$$($(SHA256) "$$shipped" | cut -d' ' -f1); \
	  if [ "$$a" != "$$b" ]; then \
	    echo "the canonical binary is not the one make dist ships:"; \
	    echo "  canonical  $$built: $$a"; \
	    echo "  dist       $$shipped: $$b"; \
	    echo "Both were built from this tree, by the same compiler, for the same"; \
	    echo "platform (linux/$$arch), so this is a difference between the two"; \
	    echo "recipes -- or one target overwriting the other's output, which is"; \
	    echo "the failure this check exists to catch."; \
	    exit 1; \
	  fi; \
	  echo "canonical == dist (linux/$$arch): $$built $$a"; \
	done

.PHONY: test
test:
	$(GO) test ./...

# The RandomX engine, which is the only cgo in the tree and is compiled only
# under this tag. Kept out of `test` and `ci` on purpose: the default build has
# no C toolchain requirement at all, and that is a property worth defending —
# the consensus rules stay auditable by anyone with a Go toolchain, and only
# the work function needs a compiler.
#
# CAUTION when mutating the vendored C++ to check a test. Go's build cache
# hashes the package directory and does not see into core/pow/randomx/upstream,
# so editing the sources there rebuilds nothing and the tests measure the
# previous contents. `-count=1` disables result caching, not build caching.
# Re-run core/pow/randomx/vendor.sh, which rewrites pinned.go and invalidates
# the cache properly.
.PHONY: test-randomx
test-randomx:
	CGO_ENABLED=1 $(GO) test -tags randomx -count=1 -timeout 30m ./core/pow/randomx/...

# The RandomX binaries carry their own names, and that is not cosmetic.
#
# They used to be written to $(BIN)/zcd and $(BIN)/zycordd — the same two paths
# `build` writes. On Linux $(EXE) is empty, so those were not similar paths, they
# were the same path, and `make build build-randomx` — which is exactly what
# `canonical` below runs, in ONE container invocation — silently replaced the
# pure-Go binaries with the cgo ones. The canonical build then certified an
# artefact no release contains and destroyed the one every release does, in the
# same command, and the canonical CI job diffed the survivor against itself, so
# it was structurally incapable of noticing.
#
# Distinct names fix that family at once: both artefacts exist at the same time,
# the hash instruction in `canonical` stops being ambiguous about which binary it
# names, and `canonical-dist-diff` can compare the pure-Go one against what
# `make dist` actually ships.
.PHONY: build-randomx
build-randomx:
	@mkdir -p $(BIN)
	CGO_ENABLED=1 $(GO) build -tags randomx $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/zcd-randomx$(EXE) ./cmd/zcd
	CGO_ENABLED=1 $(GO) build -tags randomx $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)/zycordd-randomx$(EXE) ./cmd/zycordd

.PHONY: test-short
test-short:
	$(GO) test -short ./...

# The race detector is part of `make ci`, not an optional extra.
#
# A node touches the chain from the miner, a goroutine per peer, the sync
# driver and the RPC server. An unsynchronised read there is not a stale value:
# a miner that seals an epoch state root from a torn view commits to a root no
# fold reproduces, and the divergence surfaces dozens of blocks later. That bug
# shipped and was found by the chaos soak — `-race` reported nothing, because
# every test drove the chain from one goroutine and a race detector only sees
# the concurrency the tests create.
.PHONY: race
race:
	# An explicit timeout, because Go's ten-minute default is now the wrong number
	# on both platforms this is developed on.
	#
	# **45m, raised from 30m, and the number comes from a measurement rather than
	# from taste.** The timeout here is PER PACKAGE, and `sim` is the one that
	# decides it: on the CI runner it measured 1522s under `-race` -- 85% of a
	# 30m budget -- and the next run of the same suite hit 1800.033s and was
	# killed by the alarm. Nothing had slowed down; the package was simply at the
	# edge, and runner variance carried it over. A budget a package sits at 85%
	# of is a budget that fails on load rather than on a defect, and a red build
	# nobody can attribute is worse than a slow one. 45m is 1.8x the measurement
	# and still bounded: a genuinely wedged test is still killed, with a stack.
	#
	# The race detector's cost is not portable, and it is not stable either.
	# `node/mempool` builds thousands of Ed25519-signed certificates across its
	# eviction tests, and under `-race` that measured **139s on linux/amd64 and
	# 709s on darwin/arm64** when this target was written — the same tree, the same
	# tests, a five-fold difference in the instrumentation rather than in the code.
	# The eviction suite grew since: darwin/arm64 now measures **984s**, and
	# linux/amd64 no longer finishes inside the default at all (the CI run that
	# established this was cut at exactly 600s, mid-progress, in
	# `wallet.Builder.Build`).
	# So the default now fails on the server too, and the margin this target was
	# given is the only reason the number is a ceiling rather than a limit.
	#
	# Thirty minutes is still comfortably above the slowest measurement. It is a
	# ceiling against a hang, not a budget to spend: the real cost here is re-signing the
	# same fixtures in ten separate tests, and building them once per package would
	# take this back under the default on both platforms.
	$(GO) test -race -timeout 45m ./...

# The consensus-state access guard (R5-G2).
#
# `Chain.Read` lends a borrowed reference to consensus state under two rules —
# do not keep it past the callback, do not re-enter the chain — and a violation
# of the first re-creates the worst bug this project has had. Both rules used to
# be enforced by review, in a system whose whole design assumes the reviewer
# eventually leaves.
#
# Built with -tags zcdguard the rules are machine-checked and a violation is a
# located panic. This is a separate target from `race` because the two arm the
# guard at different costs: -race changes timing enough to distort a long soak,
# so the soak builds its nodes with zcdguard alone.
# The chaos soak, in the regimes it has.
#
# `soak` runs all four regimes: convergence after the chaos stops, history
# agreement while contention never stops, long-distance catch-up, and revival of
# a node terminated from outside inside the convergence window. `soak-long` is
# the R5-G1 gate — hours, then days — and is what must be green before a public
# testnet.
#
# The default is 35 minutes because the contention regime's horizon implies a
# minimum chain length: reorgs reach ~130 blocks in that regime, so the settled
# horizon is 256, and ten comparisons need height 266. A shorter run compares
# nothing, and the regime now says so up front rather than after the fact.
#
# Both build their nodes with -tags zcdguard, so the consensus-state access
# rules are machine-checked for the whole run.
#
# ZCD_SOAK_SAMPLE=15s adds the out-of-band sampler: every node's height, trail
# behind the tip, resident memory, thread count, open descriptors and data
# directory size, written to samples.tsv beside the node logs and summarised as
# percentiles at the end. It asserts nothing — resource growth and propagation
# delay are readings, not invariants, and on a loaded machine the difference
# between a slow node and a broken one is a judgment the reader makes. Unset,
# nothing samples and a run is bit for bit what it was before the knob existed.
.PHONY: soak
soak:
	ZCD_SOAK=$${ZCD_SOAK:-35m} $(GO) test ./sim/chaos/ -run TestChaosSoak -count=1 -v -timeout 180m

.PHONY: soak-long
soak-long:
	ZCD_SOAK=$${ZCD_SOAK:-4h} $(GO) test ./sim/chaos/ -run TestChaosSoak -count=1 -v -timeout 24h

# The revival regime alone, for when the drain is what is being touched.
#
# It is one of the four `soak` runs, but it does not scale with ZCD_SOAK — its
# windows are its own — so it is worth about ninety seconds on a passing run
# rather than the thirty-five minutes the full target costs. ZCD_SOAK is set only
# because that is the gate the chaos regimes share; the value is not read here.
.PHONY: soak-revival
soak-revival:
	ZCD_SOAK=1s $(GO) test ./sim/chaos/ -run TestChaosSoakRevivesANodeKilledInsideTheConvergenceWindow -count=1 -v -timeout 20m

# "Is this connected to anything?" — asked by the build (R6 §4).
#
# Twice a piece of Zycord has been correct, complete, tested, and called from
# nowhere: node/sync (I4-H2) and mempool.Readmit (I5). Neither is visible to a
# unit test, because a unit test's subject is a piece and both pieces worked.
.PHONY: wiring
wiring:
	$(GO) test ./sim/wiring/ -count=1

.PHONY: guard
guard:
	$(GO) build -tags zcdguard ./...
	$(GO) test -tags zcdguard ./... 

# The differential runner is the release gate for core/fold: two independent
# implementations must agree on every observable of every block.
.PHONY: differential
differential:
	$(GO) test -run TestDifferential -v ./sim/

# The whitepaper's §14 publishes throughput numbers, and a published number
# needs somewhere it demonstrably came from. This is that somewhere: the fold,
# the stateless-validity pipeline, and Ed25519 on its own, so the sequential
# stage and the parallel one are measured apart rather than as a lump.
#
# BENCHTIME defaults to a second per benchmark, which is enough to read the
# shape. Publishing takes longer runs and medians across them (RELEASE.md §8),
# not one pass of this.
BENCHTIME ?= 1s
.PHONY: bench
bench:
	$(GO) test -run XXX -bench . -benchtime $(BENCHTIME) ./core/fold/ ./node/verify/

# One iteration of every benchmark in the tree, as a build-and-run smoke check
# rather than a measurement. It exists because benchmarks do not run under
# `go test`, so a benchmark that no longer executes at all is invisible to a
# green CI — which is exactly what happened when §8.1 added a protocol cell
# that `benchBlock` seeds by hand and nothing updated the list (I6-H2). The
# figures whitepaper §15 publishes come from these benchmarks, so "they still
# run" is a claim `make ci` makes on every run, and it costs seconds.
.PHONY: bench-smoke
bench-smoke:
	$(GO) test -run XXX -bench . -benchtime 1x ./... > /dev/null

# Continuous fuzzing of the decoders. FUZZTIME defaults to a minute; the fuzz
# farm runs the same targets for hours.
FUZZTIME ?= 60s

.PHONY: fuzz
fuzz:
	$(GO) test -run=XXX -fuzz=FuzzDecodeCertificate -fuzztime=$(FUZZTIME) ./core/types/
	$(GO) test -run=XXX -fuzz=FuzzDecodeBlock -fuzztime=$(FUZZTIME) ./core/types/

# Regenerate the golden vectors. A regeneration that changes an existing vector
# is a consensus change and must be reviewed as one.
.PHONY: vectors
vectors:
	$(GO) run ./spec/gen
	$(GO) test ./spec/

.PHONY: genesis
genesis: build
	./$(BIN)/zcd$(EXE) genesis

# A devnet node, mining to a throwaway address. Ctrl-C to stop.
.PHONY: devnet
devnet: build
	@mkdir -p .devnet
	./$(BIN)/zycordd$(EXE) --devnet --dir .devnet --mine \
	  --payout $$(./$(BIN)/zcd$(EXE) key new 2>/dev/null | awk '/persistent/ {print $$3}')

# A local net running the REAL work function, mining to a throwaway address.
#
# It depends on build-randomx rather than build because the parameter file names
# pow_engine randomx-v1, and a binary without the tag refuses to start against it
# rather than falling back to dev-blake3 — the one-directional safety property
# spec/params.devnet.json's pow_engine note sets out. So the -randomx binaries
# are not a preference here, they are the only pair that can run this network.
#
# Unlike devnet this passes --params, which is also what leaves the node with no
# seeds: an operator on their own parameter file is on a network this release
# knows nothing about. docs/localnet/README.md is the recipe and says what to
# watch for; the short version is that the key boundary at height 18 is the
# event the whole thing exists to make reachable.
.PHONY: localnet
localnet: build-randomx
	@mkdir -p .localnet
	./$(BIN)/zycordd-randomx$(EXE) --params docs/localnet/params.randomx-localnet.json \
	  --dir .localnet --mine \
	  --payout $$(./$(BIN)/zcd-randomx$(EXE) key new 2>/dev/null | awk '/persistent/ {print $$3}')

.PHONY: lint
lint:
	$(GO) vet ./...
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || { echo 'gofmt: files need formatting'; exit 1; }

# `make ci` enforces the import graph: arrows point inward only. core/ may import
# nothing outside itself and the standard library, and nothing in core/ may
# import the node, the wallet or the simulator.
.PHONY: check-imports
check-imports:
	@bad=$$($(GO) list -deps ./core/... | grep -E '^zycord/(node|wallet|sim|cmd)' || true); \
	if [ -n "$$bad" ]; then echo "core/ depends on outer packages:"; echo "$$bad"; exit 1; fi
	@bad=$$($(GO) list -f '{{.ImportPath}} {{join .Deps " "}}' ./core/... \
	  | tr ' ' '\n' | grep -E '^(github\.com|golang\.org|gopkg\.in)' | sort -u || true); \
	if [ -n "$$bad" ]; then echo "core/ has third-party dependencies:"; echo "$$bad"; exit 1; fi
	@bad=$$($(GO) list -deps ./node/... | grep -E '^zycord/(sim|cmd)' || true); \
	if [ -n "$$bad" ]; then echo "node/ depends on outer packages:"; echo "$$bad"; exit 1; fi
	@bad=$$($(GO) list -deps ./node/... \
	  | grep -E '^(github\.com|golang\.org|gopkg\.in)' | sort -u || true); \
	if [ -n "$$bad" ]; then echo "node/ has third-party dependencies:"; echo "$$bad"; exit 1; fi
# The updater, held to the same two rules as core/ and node/ and for the same
# two reasons.
#
# Third-party-free, because this is the package that decides whether to execute
# code it just downloaded: the argument for trusting it is that there is very
# little of it to read, and a dependency here is code in that path that nobody
# reviewed. It also compiles into the desktop wallet, which is a separate
# module, so every import added here is a new hash in a second go.sum.
#
# And unreachable from core/ and node/, because an update key is client release
# policy in the sense node/checkpoints uses the phrase. The direction of that
# rule is what this checks: cmd/ and the wallet may reach the updater, the
# protocol may not reach it back.
#
# Both stanzas capture `go list` into a file and check its STATUS before
# grepping. The `$$(... || true)` shape the rules above use fails open: if
# `go list` errors — a broken import, a missing module, a toolchain that will
# not start — the substitution is empty, the grep matches nothing, and the
# target prints "ok" having checked nothing at all. This repository has already
# paid for one guard that passed everything it could not read.
	@deps=$$(mktemp); \
	if ! $(GO) list -deps ./update/... > $$deps 2>&1; then \
	  echo "update/: go list failed, so nothing was checked:"; cat $$deps; rm -f $$deps; exit 1; fi; \
	bad=$$(grep -E '^(github\.com|golang\.org|gopkg\.in)' $$deps | sort -u); rm -f $$deps; \
	if [ -n "$$bad" ]; then echo "update/ has third-party dependencies:"; echo "$$bad"; exit 1; fi
	@deps=$$(mktemp); \
	if ! $(GO) list -deps ./core/... ./node/... > $$deps 2>&1; then \
	  echo "core//node/: go list failed, so nothing was checked:"; cat $$deps; rm -f $$deps; exit 1; fi; \
	bad=$$(grep -E '^zycord/update($$|/)' $$deps); rm -f $$deps; \
	if [ -n "$$bad" ]; then echo "core/ or node/ depends on update/:"; echo "$$bad"; exit 1; fi
# The second implementation of the epoch state root, enforced as an import rule.
#
# Every check the tree had for the state root's merkleisation was that one
# implementation agreeing with itself: sim/refold and root_identity_test.go both
# call ssz.ListRoot, so the tag, the tree, zeroHashes, MixInLength and nextPow2
# are the same code object on both sides of what looked like a differential.
# core/state/naive exists to be the other side, and it is only the other side for
# as long as it cannot reach core/ssz — by any path, not just directly, which is
# why this is a dependency-graph check and not a reading of its import block.
#
# It is the whole of what makes core/state/naive_differential_test.go evidence.
# If this stanza ever has to be relaxed, the differential stops being one, and
# the merkleisation goes back to being checked only by the code that computes
# it.
	@bad=$$($(GO) list -deps ./core/state/naive/... | grep -E '^zycord/core/ssz$$' || true); \
	if [ -n "$$bad" ]; then \
	  echo "core/state/naive reaches core/ssz, so it is no longer a second implementation:"; \
	  echo "$$bad"; \
	  echo "A differential whose two sides share the merkleisation checks nothing."; exit 1; fi
	@deps=$$($(GO) list -deps ./core/state/naive/... | grep -c '^zycord/' || true); \
	if [ "$$deps" -ne 2 ]; then \
	  echo "core/state/naive should depend on exactly itself and core/crypto/blake3, found $$deps:"; \
	  $(GO) list -deps ./core/state/naive/... | grep '^zycord/'; \
	  echo "Every in-tree package it gains is a primitive the differential stops covering."; exit 1; fi
# The second computation of whitepaper 8.1's block ceilings, enforced as an
# import rule.
#
# The sixth external audit measured that the two folds share ONE implementation
# of MaxCertsPerBlock, BlockByteLimit, SeqGasLimit, SeqGasBurst, ParGasLimit and
# ParGasTarget, so sim/refold cannot see a ceiling change: SeqGasBurst was moved
# from 4T to 8T -- B5's hard validity bound -- and `go test ./spec` stayed green.
# The golden vectors are not the second opinion either, because a vector records
# a parameter set by NAME and the name is resolved at replay back through the
# same shared function.
#
# core/params/naive is the other side, and it is only the other side for as long
# as it cannot reach core/params or core/u256 -- by any path, not just directly,
# which is why this is a dependency-graph check and not a reading of its import
# block. It is the whole of what makes core/params/ceilings_differential_test.go
# evidence.
	@bad=$$($(GO) list -deps ./core/params/naive/... | grep -E '^zycord/core/(params|u256)$$' || true); \
	if [ -n "$$bad" ]; then \
	  echo "core/params/naive reaches the implementation it checks, so it is no longer a second computation:"; \
	  echo "$$bad"; \
	  echo "A differential whose two sides share the scaling law checks nothing."; exit 1; fi
	@deps=$$($(GO) list -deps ./core/params/naive/... | grep -c '^zycord/' || true); \
	if [ "$$deps" -ne 1 ]; then \
	  echo "core/params/naive should depend on exactly itself, found $$deps:"; \
	  $(GO) list -deps ./core/params/naive/... | grep '^zycord/'; \
	  echo "Every in-tree package it gains is a constant or a primitive the differential stops covering."; exit 1; fi
# The lock order, enforced as an import rule.
#
# Six call sites take chain.mu(read) and then call into the mempool, which takes
# pool.mu. That fixes the order chain -> pool. The inverse order would be an
# ABBA deadlock, and the consensus-state guard would certify it clean because it
# only knows about one of the two locks — as would `-race`, which sees data
# races and not lock-order inversions.
#
# What makes the inversion impossible is that the mempool cannot reach the
# chain: it takes state as a parameter and holds no reference. That is a
# structural property and it was, until now, an accident nobody was defending.
	@bad=$$($(GO) list -deps ./node/mempool/... | grep -E '^zycord/node/(chain|p2p|sync|rpc|miner)' || true); 	if [ -n "$$bad" ]; then 	  echo "node/mempool must not depend on the packages that lock around it:"; echo "$$bad"; 	  echo "This fixes the lock order chain.mu -> pool.mu; the inverse is an ABBA deadlock"; 	  echo "that neither the state guard nor -race can see."; exit 1; fi
	@bad=$$($(GO) list -deps ./node/storage/... | grep -E '^zycord/node/' | grep -v 'node/storage' || true); \
	if [ -n "$$bad" ]; then echo "node/storage must depend on no other node package:"; echo "$$bad"; exit 1; fi
# cgo, scanned by hand because `go list` cannot see it.
#
# The third-party check above greps module paths, and cgo has none: a package
# that does `import "C"` adds no module and would pass every rule in this
# target. So the one thing this repository says about its own dependencies —
# "no cgo except RandomX" — was, until this rule, enforced by nobody. That is
# the shape of guard this project keeps catching itself building.
	@bad=$$(grep -rl '^import "C"' --include='*.go' core/ node/ wallet/ update/ 2>/dev/null \
	  | grep -v '^core/pow/randomx/' || true); \
	if [ -n "$$bad" ]; then \
	  echo "cgo outside core/pow/randomx:"; echo "$$bad"; \
	  echo "RandomX is the only cgo in the tree (ARCHITECTURE §3, §21)."; exit 1; fi
	@echo "cgo ok: confined to core/pow/randomx, behind the randomx build tag"
	@echo "import graph ok: core/ and node/ are third-party-free, arrows point inward"
	@echo "lock order ok: mempool and storage cannot call back into the chain"

# Every relative markdown link in docs/ and the root documents resolves.
#
# A settled convention stands behind this target: a milestone record in
# docs/adversarial/ discharges its obligation to a reader by carrying a LINK to
# the document that owns the mechanism today, rather than a dateline — and half
# the argument for that was that a link is an artefact a machine can check while
# `*as of M3*` rots in silence.
# Nothing in the tree checked it, so the property that choice rested on was
# asserted rather than held.
#
# A resolving link proves the target exists. It does not prove the target still
# supersedes the finding, and it does not force a new record to carry a link at
# all; both stay review obligations. This is the level of the three that is a
# mechanism. See the header of docs/linkcheck/links_test.go.
.PHONY: check-links
check-links:
	$(GO) test ./docs/linkcheck/ -count=1

# THE GATE. Nothing else is one.
#
# This target used to be a convenience that mirrored what a hosted runner did
# anyway. It is now the only thing that runs this tree before a push, because
# there is no CI: the project's forge account was permanently suspended, with no
# appeal, for workflow jobs that computed proof-of-work hashes -- read as mining
# on the forge's runners -- and every workflow but the release build was deleted
# in response. .github/workflows/release.yml compiles artefacts and runs
# nothing; sim/wiring/workflow_test.go holds it to that by equality.
#
# So: run this before you push, and read the output. A red run pushed anyway is
# a red `dev`, and nobody downstream will find it for you.
#
# What this target does NOT cover, because it is slow, needs Docker, or needs a
# platform this machine is not: `make fuzz`, `make soak-long`, `make canonical`
# and `canonical-dist-diff`, `make repro` and `repro-desktop`, `make
# test-randomx`, `make release-smoke`, and the Windows suite. CONTRIBUTING.md
# says which of those a contributor owes for which change; docs/RELEASE.md
# section 8 lists every one a release owes.
.PHONY: ci
ci: lint check-imports wiring test race guard differential bench-smoke

# ---------------------------------------------------------------------------
# Release artefacts.
#
# Hand-written Make rather than a release tool with its own opinions. The build
# is boring on purpose (see the header of this file) and a release path is the
# last place to stop being boring: everything below is `go build`, `tar` and a
# hash, which is a pipeline anybody can read in a minute and reproduce by hand.

DIST      := dist
# The matrix is the platforms someone can plausibly mine on. Adding one is a
# line here and a line in .github/workflows/release.yml.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# sha256sum on Linux, shasum on macOS. Detected rather than assumed, because a
# release step that only works on the maintainer's machine is a release step
# nobody else can check.
SHA256 := $(shell command -v sha256sum >/dev/null 2>&1 && echo 'sha256sum' || echo 'shasum -a 256')

# GNU tar can be told to produce a byte-identical archive from identical
# inputs; BSD tar cannot. The archives are checksummed either way, so this is
# about whether two people building the same tag get the same *archive* hash
# or only the same *binary* hashes — and the second is the claim that matters,
# so a BSD tar is a warning rather than an error.
TAR_REPRO := $(shell tar --version 2>/dev/null | grep -q GNU &&   echo '--sort=name --owner=0 --group=0 --numeric-owner --mtime=@0')

# The version as it appears in an artefact *name*, which is the tag without its
# leading `v`.
#
# VERSION comes from `git describe --tags`, so on tag v1.2.3 it is "v1.2.3" —
# right for `zcd version`, which should echo the tag a user checked out, and
# wrong for a filename. packaging/scoop/zycord.json interpolates Scoop's
# $version (the manifest's own field, which carries no v) into the asset URL,
# and packaging/install.sh strips a leading v for the same reason; both would
# fetch zycord-1.2.3-... from a release that published zycord-v1.2.3-...
# and 404 on every install. One of the three had to move, and the two that
# agree are the ones a user's package manager runs.
DIST_VERSION := $(patsubst v%,%,$(VERSION))

# The desktop wallet's target, resolved once.
#
# Every DESKTOP_* variable below and the repro-desktop guard read these two and
# nothing else, because the alternative was measured and it was wrong. They used
# to call `$(GO) env GOOS` separately, and the guard called it a third time from
# inside its recipe -- and a recipe and a `$(shell ...)` do not see the same
# environment. GNU make hands a command-line variable to recipes but not to the
# `$(shell ...)` calls it expanded while reading this file:
#
#     $ make probe GOOS=windows      GOOS at parse time = []
#                                    GOOS at recipe time = [windows]
#     $ GOOS=windows make probe      GOOS at parse time = [windows]
#                                    GOOS at recipe time = [windows]
#
# So `make repro-desktop GOOS=windows` passed a guard that asked the environment
# at recipe time, and then built with the flags this file had already chosen for
# the *host*: CGO_ENABLED=1 and no -H windowsgui. Measured on the binary that
# came out -- PE subsystem 3, IMAGE_SUBSYSTEM_WINDOWS_CUI, the console build the
# DESKTOP_LDFLAGS comment below exists to prevent, certified as reproducible by
# a check that was reading a different question's answer.
#
# One resolution, read by everything, is what makes that unrepresentable. There
# are now two cgo artefacts that need it -- the wallet and the RandomX tier
# (dist-randomx below) -- so the resolution is named once for the host and the
# DESKTOP_* names alias it rather than asking a second time. `go env GOOS` reads
# the environment, so setting GOOS/GOARCH there (and never on the make command
# line) still selects a cross target, and every consumer of these follows.
HOST_GOOS   := $(shell $(GO) env GOOS)
HOST_GOARCH := $(shell $(GO) env GOARCH)

DESKTOP_GOOS   := $(HOST_GOOS)
DESKTOP_GOARCH := $(HOST_GOARCH)

# How they were set, which repro-desktop's guard needs and nothing else does.
#
# `$(origin V)` answers `command line`, `environment` or `undefined`, and that is
# the distinction the paragraph above is about -- a command-line assignment is
# invisible to the `$(shell ...)` two lines up and visible to every recipe. Only
# the environment form keeps the two in step, so the guard refuses the other one
# by name rather than trying to detect its consequences after the fact.
GOOS_ORIGIN   := $(origin GOOS)
GOARCH_ORIGIN := $(origin GOARCH)

# The desktop wallet's build tags.
#
# webkit2_41 is required on Linux and meaningless anywhere else. Wails v2.15.0
# declares `#cgo !webkit2_41 pkg-config: webkit2gtk-4.0` across
# internal/frontend/desktop/linux/ and pkg/assetserver/webview/, and
# libwebkit2gtk-4.0-dev was dropped after Ubuntu 22.04 — so a build without the
# tag fails at pkg-config on every current distribution, including the one the
# release workflow runs on.
DESKTOP_TAGS := desktop,production
ifeq ($(DESKTOP_GOOS),linux)
DESKTOP_TAGS := $(DESKTOP_TAGS),webkit2_41
endif

# The desktop wallet's link flags.
#
# -H windowsgui sets the PE subsystem field to IMAGE_SUBSYSTEM_WINDOWS_GUI. It
# is meaningless on any other platform, and it is not optional on this one.
# `wails build` supplies it; this recipe deliberately does not use the Wails
# CLI (desktop/README.md says why), so nothing was supplying it -- measured on
# a wallet built exactly as the line below builds it, the PE optional header
# read Subsystem = 3, IMAGE_SUBSYSTEM_WINDOWS_CUI.
#
# A console-subsystem GUI application costs two things, and the second is the
# one that matters here.
#
# The visible one: launched the way a wallet is launched -- double-clicked in
# Explorer, from the Start menu, out of an unzipped release -- the loader
# allocates a console and shows a black window next to the wallet window.
#
# The one worth the branch: that console is a second exit nothing guards.
# Closing it delivers CTRL_CLOSE_EVENT and the process is terminated, so
# OnShutdown in desktop/main.go never runs -- and OnShutdown is what calls
# api.Lock(). Its own comment states the requirement: "A closed window must not
# leave a seed in memory for whatever reads the process next -- a crash
# reporter, a core file, a hibernation image." A console the user was never
# meant to see is exactly the way that gets skipped.
DESKTOP_LDFLAGS := $(LDFLAGS)
ifeq ($(DESKTOP_GOOS),windows)
DESKTOP_LDFLAGS := $(LDFLAGS) -H windowsgui
endif

# Whether the desktop wallet is a cgo binary is a property of the target, not
# of whichever C compiler the machine building it happens to have.
#
# This recipe set nothing, so the answer came from `go env CGO_ENABLED`: 1 on a
# host with a C compiler, 0 on one without, and 0 for any cross-compile. A
# release artefact whose linkage -- and therefore whose reproducibility -- is
# decided by a runner image is a property left to chance, and the header of
# .github/workflows/release.yml makes a claim about exactly this. So it is
# stated:
#
#   linux, darwin   cgo. Wails reaches the platform webview through it
#                   (webkit2gtk, WebKit), and without it the build does not
#                   link at all -- so an image with no C compiler now fails
#                   loudly here instead of failing obscurely in the linker.
#   windows         no cgo. Wails reaches WebView2 through pure Go, and
#                   WebView2 is a runtime the users already have rather than a
#                   build dependency. Measured on windows/amd64: the wallet
#                   builds at CGO_ENABLED=0 with no C compiler present, and two
#                   builds of one commit are byte-identical.
#
# The consequence is in the closing message below, and in the two-tiers table
# in docs/INSTALL.md, which said cgo made this artefact irreproducible on every
# platform and was wrong about one of them.
DESKTOP_CGO := 1
ifeq ($(DESKTOP_GOOS),windows)
DESKTOP_CGO := 0
endif

# One wallet build command, written once.
#
# dist-desktop builds the artefact and repro-desktop rebuilds it to compare, so
# the two have to *be* the same command -- otherwise the comparison certifies
# something the release does not ship. The alternative arrangement has a price
# tag already recorded in this tree: the `race` target's own comment is about a
# fix that landed in the Makefile and left CI's second copy of the same command
# still failing.
#
# The output path and the working directory are the caller's. The tags, the
# build flags, the link flags and CGO_ENABLED are not.
DESKTOP_BUILD := CGO_ENABLED=$(DESKTOP_CGO) $(GO) build -tags $(DESKTOP_TAGS) $(GOFLAGS) -ldflags '$(DESKTOP_LDFLAGS)'

# The node that ships beside the wallet.
#
# The desktop application runs a full node of its own (wallet/localnode) and
# finds it next to the executable, so every wallet artefact carries a zycordd
# built for the same target. It is the RandomX build -- the only one that can
# join mainnet or the public testnet -- and therefore cgo on every platform,
# Windows included: the Windows leg of release.yml installs mingw for exactly
# this file, while the wallet beside it stays CGO_ENABLED=0 and byte-identical.
# The two claims are about two files and the closing message below keeps them
# apart.
#
# DESKTOP_NODE=0 ships the wallet alone, for a machine with no C++ toolchain.
# The wallet then reports that no node is bundled and asks for one to talk to.
DESKTOP_NODE ?= 1
DESKTOP_NODE_BUILD := CGO_ENABLED=1 $(GO) build -tags randomx $(GOFLAGS) -ldflags '$(LDFLAGS)'

.PHONY: dist
dist: dist-clean
	@test -n "$(strip $(PLATFORMS))" || { echo 'dist: PLATFORMS is empty; nothing to build'; exit 1; }
	@mkdir -p $(DIST)
	@for platform in $(PLATFORMS); do 	  os=$${platform%/*}; arch=$${platform#*/}; 	  name=zycord-$(DIST_VERSION)-$$os-$$arch; 	  stage=$(DIST)/$$name; 	  ext=; if [ "$$os" = windows ]; then ext=.exe; fi; 	  echo "  $$name"; 	  mkdir -p $$stage; 	  GOOS=$$os GOARCH=$$arch $(BUILD_ENV) $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' 	    -o $$stage/zcd$$ext ./cmd/zcd || exit 1; 	  GOOS=$$os GOARCH=$$arch $(BUILD_ENV) $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' 	    -o $$stage/zycordd$$ext ./cmd/zycordd || exit 1; 	  cp README.md LICENSE docs/INSTALL.md docs/RUNNING.md $$stage/ || exit 1; 	  if [ "$$os" = windows ]; then 	    (cd $(DIST) && zip -qr $$name.zip $$name); 	  else 	    tar $(TAR_REPRO) -czf $(DIST)/$$name.tar.gz -C $(DIST) $$name; 	  fi; 	done
	@# Two checksum files, because they answer two questions. SHA256SUMS is
	@# over what people download. SHA256SUMS.binaries is over the binaries
	@# themselves, which is what an independent rebuilder compares against
	@# their own `make build` — the archive wrapper is not the artefact whose
	@# reproducibility is being claimed.
	@# nullglob is not portable to /bin/sh, so the globs are expanded by ls and
	@# the misses discarded: a PLATFORMS list with no Windows target in it is a
	@# narrower release, not a failed one.
	@(cd $(DIST) && $(SHA256) $$(ls *.tar.gz *.zip 2>/dev/null) > SHA256SUMS)
	@(cd $(DIST) && $(SHA256) $$(ls zycord-*/zcd zycord-*/zcd.exe 	   zycord-*/zycordd zycord-*/zycordd.exe 2>/dev/null) > SHA256SUMS.binaries)
	@# The public key travels with the release, and it is staged AFTER the two
	@# checksum files on purpose: it is not one of the things SHA256SUMS covers.
	@# Hashing a key with the same file that the key's signature authenticates
	@# would be a circle, and the key does not need a hash — it needs a
	@# fingerprint comparison against docs/whitepaper.md, which is a check no
	@# file in this directory can perform for the reader.
	@#
	@# Shipping it at all is still wanted: releases are no longer signed, but
	@# the key is what signs announcements, and an asset beside the archives is
	@# a source that needs no keyserver -- the default one serves a copy with no
	@# user ID and no self-signature, which `gpg --import` refuses outright.
	@cp packaging/zycord-release-key.asc $(DIST)/zycord-release-key.asc
	@# The installer, staged beside the archives it installs.
	@#
	@# docs/INSTALL.md has told readers to fetch this from the release page for
	@# as long as that section has existed, and nothing ever put it there: the
	@# workflow uploads what this target stages, and this target did not stage
	@# it. So the documented way to get the installer was a curl that 404s,
	@# which is a worse failure than having no installer at all -- it reads as
	@# a broken project rather than a missing feature.
	@#
	@# It is copied verbatim rather than substituted. The publishing account is
	@# written into the script itself now (RELEASE.md retired the PUBLISHER
	@# placeholder), so there is nothing left to fill in at staging time, and a
	@# copy that differs from the tracked file is a copy nobody can review by
	@# reading the repository.
	@cp packaging/install.sh $(DIST)/install.sh
	@echo
	@cat $(DIST)/SHA256SUMS
	@echo
	@echo "Nothing here is signed, and nothing is waiting to be. What says where"
	@echo "these bytes came from is the build's own provenance attestation, which"
	@echo "the release workflow produces and anyone can check:"
	@echo "  gh attestation verify <archive> --repo <publisher>/zycord"
	@echo
	@echo "This is the ATTESTED tier and it is devnet-only: CGO_ENABLED=0 and no"
	@echo "-tags randomx, so every binary above refuses to start on mainnet and on"
	@echo "the public testnet. \`make dist-randomx\` builds the tier that can join"
	@echo "them, and the two tiers are disjoint sets (docs/RELEASE.md §5)."

# The RandomX tier: the binaries that can actually join a network, and the ones
# no reproducibility claim covers.
#
# `dist` above is CGO_ENABLED=0 and carries no `-tags randomx`, so `randomx.New`
# returns ErrNotBuilt in everything it produces and cmd/zycordd refuses to start
# on any network whose pow_engine is randomx-v1 -- which spec/params.json and
# spec/params.testnet.json both are. Mainnet and the public testnet, every
# platform, every package manager. Only --devnet ran.
#
# The structural half is worse than the missing flag: the ATTESTED tier
# (CGO_ENABLED=0, byte-identical, covered by SHA256SUMS.binaries) and the
# NETWORK-CAPABLE tier were disjoint sets, so the reproducible build -- this
# project's whole substitute for a code-signing certificate -- covered no binary
# a mainnet user could run. This target does not close that gap by merging the
# two. It cannot: cgo is not reproducible across C toolchains. It closes it by
# making the second tier EXIST and by labelling it, everywhere a user meets it,
# as the one nothing attests.
#
# Two consequences follow and both are load-bearing:
#
#   - One host cannot build every platform the way `dist` does. A cgo target
#     needs a C++ toolchain for that target, so .github/workflows/release.yml
#     runs this on a NATIVE runner per target -- exactly the arrangement the
#     desktop matrix already uses, for exactly the same reason. A cross
#     toolchain works too: put GOOS/GOARCH and CC/CXX in the ENVIRONMENT (never
#     on the make command line -- see HOST_GOOS above for what that costs) and
#     the archive names itself after `go env`, so a cross build cannot mislabel
#     itself.
#
#   - Nothing produced here may ever enter SHA256SUMS.binaries. That file is
#     what an independent rebuilder compares against, and there is nothing for a
#     stranger to compare a cgo binary against (docs/RELEASE.md §5). The sums
#     file written below is its own, named for its own tier.
#
# Everything stages under $(DIST)/randomx/ rather than beside the attested
# archives, and that is the label made physical rather than a tidiness
# preference: `dist`'s SHA256SUMS.binaries line globs `zycord-*/zcd`, which
# would have swept an unattested cgo binary into the attested checksum file the
# moment the two staged as siblings.
RANDOMX_DIST := $(DIST)/randomx

.PHONY: dist-randomx
dist-randomx:
	@test '$(GOOS_ORIGIN)' != 'command line' && test '$(GOARCH_ORIGIN)' != 'command line' || { \
	  echo "dist-randomx refuses a GOOS or GOARCH assigned on the make command line."; \
	  echo "GOOS came from: $(GOOS_ORIGIN).  GOARCH: $(GOARCH_ORIGIN)."; \
	  echo; \
	  echo "A command-line variable reaches every recipe and none of the"; \
	  echo "\$$(shell ...) calls that already resolved the target this archive is"; \
	  echo "NAMED after, so the label and the bytes can be made to disagree -- an"; \
	  echo "archive called linux-arm64 holding a linux-amd64 binary. Put them in"; \
	  echo "the environment instead:"; \
	  echo; \
	  echo "  GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc \\"; \
	  echo "    CXX=aarch64-linux-gnu-g++ make dist-randomx"; \
	  exit 1; \
	}
	@mkdir -p $(RANDOMX_DIST)
	@set -e; \
	os=$(HOST_GOOS); arch=$(HOST_GOARCH); \
	name=zycord-$(DIST_VERSION)-$$os-$$arch-randomx; \
	stage=$(RANDOMX_DIST)/$$name; \
	ext=; if [ "$$os" = windows ]; then ext=.exe; fi; \
	echo "  $$name"; \
	rm -rf "$$stage"; \
	mkdir -p "$$stage"; \
	CGO_ENABLED=1 $(GO) build -tags randomx $(GOFLAGS) -ldflags '$(LDFLAGS)' \
	  -o "$$stage/zcd$$ext" ./cmd/zcd; \
	CGO_ENABLED=1 $(GO) build -tags randomx $(GOFLAGS) -ldflags '$(LDFLAGS)' \
	  -o "$$stage/zycordd$$ext" ./cmd/zycordd; \
	cp README.md LICENSE docs/INSTALL.md docs/RUNNING.md "$$stage/"; \
	cp packaging/randomx-tier.txt "$$stage/UNATTESTED.txt"; \
	if [ "$$os" = windows ]; then \
	  (cd $(RANDOMX_DIST) && zip -qr "$$name.zip" "$$name"); \
	else \
	  tar $(TAR_REPRO) -czf "$(RANDOMX_DIST)/$$name.tar.gz" -C $(RANDOMX_DIST) "$$name"; \
	fi
	@(cd $(RANDOMX_DIST) && $(SHA256) $$(ls *.tar.gz *.zip 2>/dev/null) > SHA256SUMS.randomx)
	@echo
	@cat $(RANDOMX_DIST)/SHA256SUMS.randomx
	@echo
	@echo "UNATTESTED TIER. These carry the RandomX engine and are the only"
	@echo "binaries this repository publishes that can join mainnet or the public"
	@echo "testnet. They are cgo: two machines with two C toolchains do not agree"
	@echo "byte for byte, so no line from here may ever enter SHA256SUMS.binaries"
	@echo "(docs/RELEASE.md §5). The attested tier is $(DIST)/ -- pure Go,"
	@echo "byte-identical, and devnet-only. The two tiers are disjoint sets; say"
	@echo "that in the release notes rather than listing both under one heading."
	@echo
	@echo "Before publishing, start one of these against the tagged parameters:"
	@echo "  make release-smoke ZYCORDD=$(RANDOMX_DIST)/zycord-$(DIST_VERSION)-$(HOST_GOOS)-$(HOST_GOARCH)-randomx/zycordd"

# Start a RELEASED binary against the tagged parameters and confirm it does not
# refuse.
#
# Every other gate in this file builds something and hashes it. Not one of them
# EXECUTED an artefact against the network it is for, which is how six
# platforms' worth of binaries that refuse to start on mainnet passed a green
# pipeline and three package managers. `zcd params` prints what the
# network requires; `zcd version` now prints what the binary carries; this runs
# the node and reads the answer out of the process, which is the only form of
# the question that cannot be satisfied by a build flag being written down
# twice.
#
# ZYCORDD is a path, and it is meant to be the one just unpacked from a release
# archive rather than one this tree built a moment ago:
#
#   make release-smoke ZYCORDD=./dist/randomx/zycord-1.2.3-linux-amd64-randomx/zycordd
#
# No --devnet and no --params: the embedded MAINNET set is the default, and the
# default is the thing under test. --no-rpc so nothing binds a port, and no
# --listen, so the node dials nothing and accepts nothing -- this asks whether
# the process starts, not whether it can reach a network that does not exist
# yet. The data directory is a fresh temporary one and is removed either way.
#
# The success condition is cmd/zycordd's own "proof of work: <engine> engine"
# line, which is printed after selectEngine returns and therefore cannot appear
# on the refusal path. Matching that rather than an engine name keeps this
# target correct if the tagged parameters ever name a different engine: what is
# being checked is that the binary and the parameters agree, not that a
# particular string is present.
ZYCORDD ?=

.PHONY: release-smoke
release-smoke:
	@test -n "$(ZYCORDD)" || { \
	  echo "release-smoke needs the binary to start:"; \
	  echo "  make release-smoke ZYCORDD=path/to/zycordd"; \
	  echo "Use one unpacked from a release archive, not bin/zycordd."; \
	  exit 1; \
	}
	@test -x "$(ZYCORDD)" || { echo "release-smoke: $(ZYCORDD) is not an executable file"; exit 1; }
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	"$(ZYCORDD)" --dir "$$tmp/data" --no-rpc >"$$tmp/log" 2>&1 & \
	pid=$$!; \
	i=0; \
	while [ $$i -lt 120 ]; do \
	  if grep -q 'proof of work: ' "$$tmp/log" 2>/dev/null; then break; fi; \
	  if ! kill -0 $$pid 2>/dev/null; then break; fi; \
	  sleep 1; \
	  i=$$((i + 1)); \
	done; \
	kill $$pid 2>/dev/null; \
	wait $$pid 2>/dev/null; \
	if grep -q 'proof of work: ' "$$tmp/log" 2>/dev/null; then \
	  echo "$(ZYCORDD) starts against the tagged mainnet parameters:"; \
	  grep -e 'network=' -e 'proof of work: ' "$$tmp/log" | sed 's/^/  /'; \
	  exit 0; \
	fi; \
	echo "$(ZYCORDD) REFUSED to start against the tagged mainnet parameters."; \
	echo; \
	echo "A CGO_ENABLED=0 build with no -tags randomx holds no"; \
	echo "RandomX engine, and spec/params.json and spec/params.testnet.json both"; \
	echo "declare pow_engine randomx-v1. Publish a -randomx archive (make"; \
	echo "dist-randomx) for every platform whose users are expected to join a"; \
	echo "network. What it said:"; \
	sed 's/^/  /' "$$tmp/log"; \
	exit 1

# The desktop wallet, for whatever GOOS is in effect.
#
# It used to say "for the host platform only", and to explain that cgo is why
# the release workflow runs one runner per operating system. Both were true of
# two platforms out of three and are now stated where the difference is: see
# DESKTOP_CGO above. On linux and darwin cgo is real, cross-compiling needs a
# cross C toolchain and a platform SDK per target, and the artefact is not
# byte-identical and must never be advertised as if it were (docs/RELEASE.md §5,
# docs/INSTALL.md). On windows there is no cgo, GOOS=windows works from any
# host, and the binary *is* byte-identical -- which is why release.yml
# cross-compiles that leg from the Linux runner instead of a windows-latest
# image that has neither make nor zip.
#
# Reproducible is not the same as checked, and on the one target where the first
# word applies the second one now does too: repro-desktop below rebuilds this
# artefact from two other paths and compares, and release.yml runs it on the
# windows leg before this recipe archives anything. The closing message
# below says which of the two each platform gets.
.PHONY: dist-desktop
dist-desktop:
	@mkdir -p $(DIST)
	@os=$(DESKTOP_GOOS); arch=$(DESKTOP_GOARCH); \
	name=zycord-wallet-$(DIST_VERSION)-$$os-$$arch; \
	ext=; if [ "$$os" = windows ]; then ext=.exe; fi; \
	echo "  $$name"; \
	(cd desktop && $(DESKTOP_BUILD) -o ../$(DIST)/zycord-wallet$$ext .) || exit 1; \
	files="zycord-wallet$$ext"; \
	if [ "$(DESKTOP_NODE)" != 0 ]; then \
	  echo "  $$name/zycordd$$ext (RandomX, cgo)"; \
	  $(DESKTOP_NODE_BUILD) -o $(DIST)/zycordd$$ext ./cmd/zycordd || exit 1; \
	  cp packaging/randomx-tier.txt $(DIST)/UNATTESTED.txt; \
	  files="$$files zycordd$$ext UNATTESTED.txt"; \
	fi; \
	if [ "$$os" = darwin ]; then \
	  bundle=$(DIST)/Zycord\ Wallet.app; \
	  rm -rf "$$bundle"; \
	  mkdir -p "$$bundle/Contents/MacOS" "$$bundle/Contents/Resources"; \
	  sed -e 's/@VERSION@/$(DIST_VERSION)/g' packaging/macos/Info.plist > "$$bundle/Contents/Info.plist"; \
	  mv $(DIST)/zycord-wallet "$$bundle/Contents/MacOS/zycord-wallet"; \
	  if [ "$(DESKTOP_NODE)" != 0 ]; then \
	    mv $(DIST)/zycordd "$$bundle/Contents/MacOS/zycordd"; \
	    mv $(DIST)/UNATTESTED.txt "$$bundle/Contents/Resources/UNATTESTED.txt"; \
	  fi; \
	  (cd $(DIST) && zip -qry $$name.zip "Zycord Wallet.app" && rm -rf "Zycord Wallet.app"); \
	elif [ "$$os" = windows ]; then \
	  (cd $(DIST) && zip -q $$name.zip $$files && rm $$files); \
	else \
	  tar $(TAR_REPRO) -czf $(DIST)/$$name.tar.gz -C $(DIST) $$files && (cd $(DIST) && rm $$files); \
	fi
	@(cd $(DIST) && $(SHA256) zycord-wallet-*.tar.gz zycord-wallet-*.zip 2>/dev/null > SHA256SUMS.desktop || true)
	@echo
ifeq ($(DESKTOP_GOOS),windows)
	@echo "The WALLET binary in this artefact IS byte-identical across rebuilds:"
	@echo "CGO_ENABLED=0, no platform SDK, no C toolchain -- measured, two builds"
	@echo "of one commit. The zycordd beside it is NOT: it is the RandomX build,"
	@echo "cgo through mingw. The .zip around both is not either: it records the"
	@echo "files' mtimes. Publish the claim about zycord-wallet.exe, not about"
	@echo "the archive and not about the node."
else
	@echo "This artefact is NOT byte-identical across rebuilds: the wallet uses"
	@echo "cgo for the webview and the zycordd beside it uses cgo for RandomX."
	@echo "zcd is. Do not publish a reproducibility claim for this file."
endif

# windows/amd64 exactly, and refuse anything else rather than checking it.
#
# GOOS, because on linux and darwin the wallet is a cgo binary that is not in
# the reproducible tier at all, and a green check there would assert what
# docs/RELEASE.md §5 spends a section refusing to assert.
#
# GOARCH, because windows/amd64 is the only wallet this project publishes --
# release.yml's desktop matrix has one windows leg and it is labelled
# windows-amd64. Without this line, `GOOS=windows make repro-desktop` on an
# arm64 host follows `go env GOARCH` and checks a windows/arm64 wallet that no
# release contains: measured on darwin/arm64, 666a4ba4... against the shipped
# 2dd876ad..., a green verdict for a file nobody ships. That command is the one
# docs/RELEASE.md §8 calls "the by-hand confirmation", so the checklist box was
# tickable on this project's own hardware without the artefact having been
# checked -- the same species of gap repro-desktop below exists to close.
#
# Three refusals, in the order a reader meets them, and the first two exist
# because the third one alone was not enough.
#
# The target test reads DESKTOP_GOOS/DESKTOP_GOARCH rather than `$(GO) env`,
# because those are the values that chose the flags -- see their definition for
# what asking the question twice cost. But reading the right value is only half
# of it: the *build* still obeys the environment, so anything that splits the
# two puts the guard back to certifying a different binary than it inspected.
# Assigning one variable both ways does exactly that, and it was measured:
#
#     GOOS=windows GOARCH=amd64 make repro-desktop GOARCH=arm64
#
# passed a `windows/amd64` guard and produced 666a4ba4..., a windows/arm64
# wallet. So the command-line form is refused by name (GOOS_ORIGIN above), which
# closes the way this is known to happen -- and then the two resolutions are
# asserted equal anyway, which closes the ways that are not, because a list of
# invocation forms is not a proof and this file has now been wrong about that
# twice.
#
# Named ahead of require-clean-tree in the prerequisite list so that a reader on
# the wrong target is told which platform this is about, rather than being told
# to commit their work first and then told that.
.PHONY: require-windows-target
require-windows-target:
	@test '$(GOOS_ORIGIN)' != 'command line' && test '$(GOARCH_ORIGIN)' != 'command line' || { \
	  echo "repro-desktop refuses a GOOS or GOARCH assigned on the make command"; \
	  echo "line. GOOS came from: $(GOOS_ORIGIN).  GOARCH: $(GOARCH_ORIGIN)."; \
	  echo; \
	  echo "A command-line variable reaches every recipe and none of the"; \
	  echo "\$$(shell ...) calls that already chose this target's tags, link flags"; \
	  echo "and CGO_ENABLED, so the two halves of this target can be made to"; \
	  echo "disagree -- including by assigning the same variable both ways, which"; \
	  echo "is how this refusal came to exist:"; \
	  echo; \
	  echo "  GOOS=windows GOARCH=amd64 make repro-desktop GOARCH=arm64"; \
	  echo; \
	  echo "passed a windows/amd64 guard and built a windows/arm64 wallet."; \
	  echo; \
	  echo "Run it as:  GOOS=windows GOARCH=amd64 make repro-desktop"; \
	  exit 1; \
	}
	@test '$(DESKTOP_GOOS)/$(DESKTOP_GOARCH)' = "$$($(GO) env GOOS)/$$($(GO) env GOARCH)" || { \
	  echo "repro-desktop resolved the target twice and got two answers:"; \
	  echo "  reading this makefile: $(DESKTOP_GOOS)/$(DESKTOP_GOARCH)"; \
	  echo "  running the recipe:    $$($(GO) env GOOS)/$$($(GO) env GOARCH)"; \
	  echo; \
	  echo "The flags come from the first and the compiler obeys the second, so"; \
	  echo "a check run here would certify something else. The refusal above"; \
	  echo "covers the way this is known to happen; this one covers the rest,"; \
	  echo "because enumerating invocation forms is not a guarantee."; \
	  exit 1; \
	}
	@test '$(DESKTOP_GOOS)/$(DESKTOP_GOARCH)' = windows/amd64 || { \
	  echo "repro-desktop checks the windows/amd64 wallet -- the only one any"; \
	  echo "release publishes. This tree is set up to build $(DESKTOP_GOOS)/$(DESKTOP_GOARCH)."; \
	  if [ '$(DESKTOP_GOOS)' != windows ]; then \
	    echo "On linux and darwin the wallet is a cgo binary and is NOT in the"; \
	    echo "reproducible tier (docs/RELEASE.md §5), so there is nothing to check."; \
	  else \
	    echo "No release contains a windows/$(DESKTOP_GOARCH) wallet, so comparing one"; \
	    echo "would be a green verdict about a file nobody ships."; \
	  fi; \
	  echo; \
	  echo "Run it as:  GOOS=windows GOARCH=amd64 make repro-desktop"; \
	  exit 1; \
	}

# The Windows wallet, rebuilt from two other paths and compared.
#
# docs/RELEASE.md §5 draws its line at *checked*, not at measured: zcd is in the
# reproducible tier because something rebuilds it and compares hashes, and the
# Windows wallet's byte-identity was established by measuring it once.
# A measurement is a statement about one commit on one afternoon; it does not
# survive the next commit. This is that measurement turned into a gate.
#
# windows/amd64 only, and it refuses every other target rather than passing --
# see require-windows-target above for both halves of why. GOOS and GOARCH are
# read from the environment, the same way .github/workflows/release.yml already
# drives dist-desktop.
#
# Two exported paths and the working tree, not two builds in one directory, for
# the reason `repro` gives above and RELEASE §5 repeats in bold. That is not a
# formality here: measured on this recipe with -trimpath dropped and everything
# else held, the two export paths produce two different binaries -- so the
# comparison can fail, which is the only thing that makes it worth running.
#
# VERSION is not pinned the way repro pins it, and does not need to be. repro
# invokes sub-makes inside the exports, where `git describe` answers differently
# because there is no .git beside them; every build below is issued by *this*
# make process from one expansion of DESKTOP_BUILD, so all three carry the same
# -X main.version string by construction.
#
# Nothing is written to $(DIST) and no checksum file is produced. That is the
# point rather than an omission: SHA256SUMS.binaries covers zcd and zycordd and
# must never grow a line for the wallet (RELEASE §5), and a
# SHA256SUMS.desktop.binaries published beside it would read to a downloader as
# precisely the per-binary attestation this project declines to make. The
# verdict belongs in the log, where a maintainer reads it, and not in the
# release, where a stranger would.
#
# The verdict line below asks `$(GO) env` at recipe time, which in a target whose
# bug was parse-time-versus-recipe-time divergence looks like the one read that
# was missed. It is deliberate. Everything above reports what this makefile
# decided; that line reports what the compiler was actually told, so the two
# agreeing in the log is an independent confirmation of the assertion the guard
# makes rather than a second copy of the guard's own belief.
.PHONY: repro-desktop
repro-desktop: require-windows-target require-clean-tree
	@set -e; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	mkdir -p "$$tmp/a" "$$tmp/b-a-deliberately-longer-path"; \
	git archive HEAD | tar -x -C "$$tmp/a"; \
	git archive HEAD | tar -x -C "$$tmp/b-a-deliberately-longer-path"; \
	(cd desktop && $(DESKTOP_BUILD) -o "$$tmp/wallet.worktree" .); \
	(cd "$$tmp/a/desktop" && $(DESKTOP_BUILD) -o "$$tmp/wallet.a" .); \
	(cd "$$tmp/b-a-deliberately-longer-path/desktop" && $(DESKTOP_BUILD) -o "$$tmp/wallet.b" .); \
	cmp "$$tmp/wallet.worktree" "$$tmp/wallet.a"; \
	cmp "$$tmp/wallet.a" "$$tmp/wallet.b"; \
	echo "reproducible (windows wallet): identical across two paths and with/without .git"; \
	echo "  $$($(SHA256) "$$tmp/wallet.a" | cut -d' ' -f1)  $$($(GO) env GOOS)/$$($(GO) env GOARCH), $$($(GO) version | cut -d' ' -f3)"; \
	echo "  the .zip around it is not reproducible and is not claimed to be"

# The update manifest, for testing the release path locally.
#
# NOT the release path itself: the workflow writes and signs the manifest in the
# publish job, from the archives it just staged, with no manual step. These
# targets exist so that path can be exercised against a local `make dist` before
# a tag is cut -- and so the failure they catch is caught here rather than by
# every node in the world quietly doing nothing.
MANIFEST_DIR ?= $(DIST)

.PHONY: release-manifest
release-manifest: build
	@test -d "$(MANIFEST_DIR)" || { echo "release-manifest: $(MANIFEST_DIR) is not a directory"; exit 1; }
	@case "$(VERSION)" in \
	  dev|*-dirty|*-g*) \
	    echo "release-manifest needs the tag it is describing:"; \
	    echo "  make release-manifest MANIFEST_DIR=<dir> VERSION=vX.Y.Z"; \
	    echo "A manifest naming '$(VERSION)' names no release, and zcd refuses to write one."; \
	    exit 1 ;; \
	esac
	$(BIN)/zcd update manifest --dir "$(MANIFEST_DIR)" --version "$(VERSION)"

.PHONY: release-manifest-verify
release-manifest-verify: build
	$(BIN)/zcd update verify --dir "$(MANIFEST_DIR)"

# The Debian package, for the operators this project actually wants: somebody
# putting a node on a VPS.
#
# It carries the -randomx tier, a systemd unit it does not enable, an
# unprivileged account and a data directory. What it is FOR is the system
# integration -- the service, the user, the directories, a clean removal -- not
# saving a download. install.sh already saves the download.
#
# Three things make it safe to publish, and a naive `dpkg-deb --build` gets all
# three wrong:
#
#   SOURCE_DATE_EPOCH and a zeroed mtime, because a .deb is an ar archive of
#   tarballs and tarballs store modification times. An uncontrolled build writes
#   the exact minute it ran into the package, which is activity hours and a
#   timezone, published (RELEASE.md section 2).
#
#   --root-owner-group, because the same tarballs store owner NAMES. An
#   uncontrolled build writes the build machine's account into every entry.
#   Measured, not assumed: the first build of this target recorded a real
#   username before this flag was added.
#
#   -Zxz with no threading, so the compressor's output does not depend on how
#   many cores the builder happened to have.
DEB       := $(DIST)/deb
DEB_ARCH  ?= amd64

.PHONY: dist-deb
dist-deb: build-randomx
	@command -v dpkg-deb >/dev/null || { echo "dist-deb needs dpkg-deb"; exit 1; }
	@rm -rf $(DEB)
	@mkdir -p $(DEB)/pkg/DEBIAN $(DEB)/pkg/usr/bin $(DEB)/pkg/etc/zycord \
	          $(DEB)/pkg/lib/systemd/system $(DEB)/pkg/usr/share/doc/zycord
	@cp $(BIN)/zcd-randomx      $(DEB)/pkg/usr/bin/zcd
	@cp $(BIN)/zycordd-randomx  $(DEB)/pkg/usr/bin/zycordd
	@chmod 0755 $(DEB)/pkg/usr/bin/zcd $(DEB)/pkg/usr/bin/zycordd
	@# Comments are stripped: dpkg refuses a control file with them ("field
	@# name '#' must be followed by colon"), and the reasoning belongs in the
	@# tracked source where a reviewer reads it rather than in the artefact.
	@sed -e '/^#/d' -e 's/@VERSION@/$(DIST_VERSION)/' -e 's/@ARCH@/$(DEB_ARCH)/' \
	     packaging/debian/control > $(DEB)/pkg/DEBIAN/control
	@cp packaging/debian/postinst packaging/debian/prerm packaging/debian/postrm $(DEB)/pkg/DEBIAN/
	@chmod 0755 $(DEB)/pkg/DEBIAN/postinst $(DEB)/pkg/DEBIAN/prerm $(DEB)/pkg/DEBIAN/postrm
	@cp packaging/debian/zycordd.service $(DEB)/pkg/lib/systemd/system/zycordd.service
	@cp packaging/debian/zycordd.conf    $(DEB)/pkg/etc/zycord/zycordd.conf
	@printf '/etc/zycord/zycordd.conf\n' > $(DEB)/pkg/DEBIAN/conffiles
	@cp README.md LICENSE docs/INSTALL.md docs/RUNNING.md docs/UPDATES.md \
	    $(DEB)/pkg/usr/share/doc/zycord/
	@find $(DEB)/pkg -exec touch -h -d @0 {} +
	@SOURCE_DATE_EPOCH=0 dpkg-deb --build --root-owner-group -Zxz \
	    $(DEB)/pkg $(DIST)/zycord_$(DIST_VERSION)_$(DEB_ARCH).deb >/dev/null
	@rm -rf $(DEB)
	@# A checksum, so the package can be verified like everything else beside
	@# it. The manifest does not describe it and should not: a dpkg-managed
	@# install is one the updater refuses to replace, so offering the .deb as a
	@# self-update asset would be describing a path that ends in a refusal.
	@cd $(DIST) && $(SHA256) zycord_$(DIST_VERSION)_$(DEB_ARCH).deb > SHA256SUMS.deb
	@echo "wrote $(DIST)/zycord_$(DIST_VERSION)_$(DEB_ARCH).deb"

# Proof, not assertion: unpack what was just built and look for the two things
# an uncontrolled build leaks. A package that carries the builder's username or
# the minute it was made is one this project cannot publish.
.PHONY: dist-deb-check
dist-deb-check:
	@deb=$$(ls $(DIST)/zycord_*_$(DEB_ARCH).deb 2>/dev/null | head -1); \
	test -n "$$deb" || { echo "no .deb in $(DIST); run make dist-deb"; exit 1; }; \
	bad=$$(ar p "$$deb" data.tar.xz 2>/dev/null | xz -dc | tar tvf - \
	       | grep -vE '(^|[[:space:]])root/root([[:space:]]|$$)' || true); \
	if [ -n "$$bad" ]; then echo "owner names other than root/root:"; echo "$$bad"; exit 1; fi; \
	bad=$$(ar p "$$deb" data.tar.xz 2>/dev/null | xz -dc | tar tvf - \
	       | grep -vE '1970-01-01' || true); \
	if [ -n "$$bad" ]; then echo "timestamps that are not the epoch:"; echo "$$bad"; exit 1; fi; \
	echo "deb ok: root/root and the epoch throughout, no builder identity and no build time"

.PHONY: dist-clean
dist-clean:
	rm -rf $(DIST)

.PHONY: clean
clean:
	rm -rf $(BIN)
