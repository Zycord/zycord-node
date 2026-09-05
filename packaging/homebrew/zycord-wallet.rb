# The desktop wallet, as a Homebrew formula.
#
# Homebrew's own guidance is that graphical applications belong in casks, and
# for a signed and notarised application that is right. This one is neither,
# and cannot be: an Apple Developer ID publishes the developer's legal name in
# the certificate's Team Name field, and this project is pseudonymous
# (docs/INSTALL.md).
#
# A cask would therefore install a quarantined, unsigned .app that macOS
# refuses to open — and the flag that used to wave that away, --no-quarantine,
# is deprecated in Homebrew 5.x precisely to stop people being talked into
# turning Gatekeeper off. A formula sidesteps the whole argument by compiling
# on the user's machine: locally built binaries carry no quarantine attribute,
# so there is nothing for Gatekeeper to refuse.
#
# The trade is stated rather than hidden: this installs a command that opens
# the window, not an icon in /Applications. Anyone who wants the icon can
# download the .app from the releases page and take the System Settings route
# in docs/INSTALL.md.
class ZycordWallet < Formula
  desc "Desktop wallet for Zycord"
  homepage "https://github.com/Zycord/zycord-node"
  url "https://github.com/Zycord/zycord-node/archive/refs/tags/v0.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  head "https://github.com/Zycord/zycord-node.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  def install
    # cgo, unavoidably: this links the platform's webview. It is why this
    # binary is not byte-identical across rebuilds and zcd is — and why
    # building it here, on the user's own machine, is worth more than
    # shipping ours.
    cd "desktop" do
      system "go", "build", "-tags", "desktop,production", "-trimpath",
             "-ldflags", "-s -w -X main.version=#{version}",
             "-o", bin/"zycord-wallet", "."
    end
    doc.install "README.md", "docs/INSTALL.md", "desktop/README.md" => "desktop.md"
  end

  def caveats
    <<~EOS
      Run it with:  zycord-wallet

      It opens no network port. The first run asks for a key file, a node and
      a network, and remembers them in
      ~/Library/Application Support/zycord/wallet.json.

      If you would rather use a binary you can rebuild byte for byte, the CLI
      serves the same interface:  zcd ui --key wallet.json
    EOS
  end

  test do
    assert_match "zycord-wallet", shell_output("#{bin}/zycord-wallet --version")
  end
end
