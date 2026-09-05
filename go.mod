// The module path is intentionally host-less: this repository claims no
// organisation, domain or vanity import path. Clone it anywhere, build it
// anywhere. Reproducible builds and the golden vectors in spec/ are the
// identity of the protocol; a hosting provider is not.
//
// The dependency list is one module and is meant to stay that way.
//
// golang.org/x/crypto supplies Argon2id for wallet key files. It is confined to
// wallet/ — core/ is standard library only, and node/ carries no third-party
// code either, both enforced by `make check-imports`. See
// docs/adversarial/I2.md for why the storage engine is written in-tree rather
// than imported, and why this one exception is not that.
module zycord

go 1.25.0

// NOT the reproducibility pin, and it is written down here so nobody reads it
// as one. Under the default GOTOOLCHAIN=auto the `go` and `toolchain` lines are
// a FLOOR: they say "at least this much", so anyone with a newer Go installed
// builds with the newer Go and gets different bytes from the same source. The
// ceiling is GOTOOLCHAIN in the Makefile, which is where the pin lives.
//
// This line exists because it is the one CI reads: every `setup-go` step in
// .github/workflows/ says `go-version-file: go.mod`, so this is what gets
// installed on the runner. It must name the same version as the Makefile's
// GO_TOOLCHAIN and build/Dockerfile's GO_VERSION;
// sim/wiring/toolchain_test.go fails if the three disagree.
toolchain go1.26.2

require (
	golang.org/x/crypto v0.54.0
	golang.org/x/term v0.45.0
)

require golang.org/x/sys v0.47.0
