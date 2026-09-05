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
  homepage "https://github.com/Zycord/zycord-node"
  url "https://github.com/Zycord/zycord-node/archive/refs/tags/v0.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  head "https://github.com/Zycord/zycord-node.git", branch: "main"

  depends_on "go" => :build

  def install
    # RandomX, which means cgo, which means this build is NOT byte-identical
    # across machines. That is a deliberate reversal of what this formula used
    # to do, and the comment it replaces argued the other way, so here is why.
    #
    # The old build was pure Go: reproducible, comparable with everyone else's,
    # and — because CGO_ENABLED=0 compiles no RandomX engine — unable to start
    # on mainnet or on the public testnet. A package manager exists to install
    # a working thing. Installing a node that refuses every real network, and
    # explaining that in the caveats afterwards, is not a trade between two
    # goods; it is a package that does not do the job, with a footnote.
    #
    # The property that was traded away is not lost, only moved to where it was
    # always exercised. "Compiled with your toolchain, comparable with everyone
    # else's" is checked by cloning the tag, running `make build`, and comparing
    # against SHA256SUMS.binaries — which the release still publishes. Nobody
    # ever verified the project by reading a Homebrew cellar. They verify by
    # building, and that path is untouched.
    #
    # So: this formula installs the tier that mines, and the tier that proves
    # the source is still one `make build` away for anyone who wants it.
    ldflags = "-s -w -buildid= -X main.version=#{version}"
    ENV["CGO_ENABLED"] = "1"
    system "go", "build", "-trimpath", "-tags", "randomx", "-ldflags", ldflags, "-o", bin/"zcd", "./cmd/zcd"
    system "go", "build", "-trimpath", "-tags", "randomx", "-ldflags", ldflags, "-o", bin/"zycordd", "./cmd/zycordd"

    doc.install "README.md", "docs/INSTALL.md", "docs/RUNNING.md", "docs/WALLET.md"
  end

  def caveats
    <<~EOS
      There is no coin yet. Genesis has not happened.
      Anyone selling you ZCD today is scamming you.

      This formula builds the RandomX engine, so these binaries join mainnet
      and the public testnet.

        zycordd --testnet --dir ./data --mine --payout <your 0x02 address>
        zycordd --dir ./data                mainnet, once genesis has happened

      `zcd version` prints which engine this binary carries; `zcd params`
      prints which one the network requires. They have to agree.

      Because RandomX is C++, this is a cgo build and is NOT byte-identical
      across machines -- it has no line in SHA256SUMS.binaries. That list is
      still published, and it is how you check the project rather than this
      package: clone the tag, run `make build`, and compare your own hashes
      against it. Those pure-Go binaries are devnet-only, which is why they are
      not offered as a download; what they are for is the comparison, and the
      comparison needs a build. It covers every line of consensus code these
      binaries run. docs/INSTALL.md, "Two tiers of assurance", is the longer
      version.

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

    # The caveats above tell the user this install joins mainnet and the public
    # testnet. Assert the binary says the same thing, rather than leaving two
    # pieces of prose to drift apart from the build flags that make them true:
    # `zcd version` prints the engine THIS BINARY carries, and the randomx build
    # tag is what puts it there.
    #
    # This assertion used to read "dev-blake3", with a comment saying that if it
    # ever failed, the formula had started shipping a cgo build and the caveats
    # were wrong. That is exactly what happened, and the guard is why the caveats
    # were rewritten in the same change rather than left behind. It now guards
    # the opposite direction: if this fails, the formula quietly stopped building
    # RandomX and is installing a node that refuses every real network.
    assert_match "randomx-v1", shell_output("#{bin}/zcd version")
  end
end
