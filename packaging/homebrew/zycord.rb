# The Zycord CLI and node, as a Homebrew formula.
#
# A formula rather than a cask, and the distinction is the whole point on
# macOS. A formula builds from source on the user's machine: the result is not
# a downloaded file, has no com.apple.quarantine attribute, and Gatekeeper
# never looks at it — so an unsigned, pseudonymous project installs without a
# single warning and without asking anyone to disable a security feature.
#
# It is also a strictly better trust story than shipping a binary. Homebrew
# fetches the source, checks its SHA-256, and compiles it with the user's own
# toolchain. Nobody has to believe anything about our build machine.
class Zycord < Formula
  desc "Proof-of-work-launched L1 built from self-certifying state transitions"
  homepage "https://github.com/thesimstoshi/zycord"
  url "https://github.com/thesimstoshi/zycord/archive/refs/tags/v0.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  head "https://github.com/thesimstoshi/zycord.git", branch: "main"

  depends_on "go" => :build

  def install
    # The same flags the Makefile uses, so a Homebrew build and a release
    # build of one tag produce the same bytes. -trimpath and -buildid= are
    # what make that true; CGO_ENABLED=0 is what keeps it true across
    # machines with different C toolchains.
    #
    # CGO_ENABLED=0 also means NO RANDOMX ENGINE, and that is not a side
    # effect worth leaving unstated. Mainnet and the public testnet both
    # declare pow_engine randomx-v1, so what this formula installs runs
    # --devnet and refuses both of them. The caveats below say so, because a
    # package manager that installs a binary which refuses to start is a
    # package manager whose users find out at the worst possible moment.
    # The two tiers are disjoint by construction: the reproducible
    # build is the devnet-only one, and the mainnet-capable one is cgo and
    # therefore attested by nobody. Changing this line would trade the
    # formula's entire argument — "compiled with your toolchain, comparable
    # with everyone else's" — for one of the two, so it is left alone and the
    # other route is named instead.
    ldflags = "-s -w -buildid= -X main.version=#{version}"
    ENV["CGO_ENABLED"] = "0"
    system "go", "build", "-trimpath", "-ldflags", ldflags, "-o", bin/"zcd", "./cmd/zcd"
    system "go", "build", "-trimpath", "-ldflags", ldflags, "-o", bin/"zycordd", "./cmd/zycordd"

    doc.install "README.md", "docs/INSTALL.md", "docs/RUNNING.md", "docs/WALLET.md"
  end

  def caveats
    <<~EOS
      There is no coin yet. Genesis has not happened.
      Anyone selling you ZCD today is scamming you.

      WHAT THIS FORMULA INSTALLS IS DEVNET-ONLY.

      It builds pure Go, CGO_ENABLED=0, so the binaries are byte-identical to
      anyone else's build of this tag -- and carry no RandomX engine. Mainnet
      and the public testnet both declare pow_engine randomx-v1, and a node
      that cannot verify a network's engine refuses to start on it rather
      than falling back to something weaker. So:

        zycordd --devnet --dir ./devnet    works
        zycordd --dir ./data               refuses: no randomx-v1 in this build
        zycordd --testnet --dir ./data     refuses, for the same reason

      `zcd version` prints which engine this binary carries; `zcd params`
      prints which one the network requires. They have to agree.

      To join a network, take the archive with -randomx in its name from the
      releases page, or build it here with `make build-randomx`. That binary
      is cgo, so it is NOT byte-identical across machines and has no line in
      SHA256SUMS.binaries. The two tiers are disjoint sets: the one you can
      reproduce is not the one you can mine with. docs/INSTALL.md, "Two tiers
      of assurance", is the longer version.

      This formula built from source, so nothing here is signed and nothing
      needed to be. To check that this tree is the protocol:

        zcd vectors
        zcd genesis

      A wallet in your browser: zcd ui --key wallet.json
    EOS
  end

  test do
    # `zcd genesis` rebuilds block 0 from the frozen parameters. If this
    # build disagrees with the protocol it disagrees here, in one millisecond,
    # rather than on a chain.
    assert_match "genesis id", shell_output("#{bin}/zcd genesis")
    assert_match "zcd", shell_output("#{bin}/zcd version")

    # The caveats above tell the user this install is devnet-only. Assert the
    # binary says the same thing, rather than leaving two pieces of prose to
    # drift apart from the build flags that make them true: `zcd version`
    # prints the engine THIS BINARY carries, and CGO_ENABLED=0 means it is the
    # development one. If this line ever fails, the formula started
    # shipping a cgo build and the caveats are now wrong.
    assert_match "dev-blake3", shell_output("#{bin}/zcd version")
  end
end
