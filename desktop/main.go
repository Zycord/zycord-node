// The Zycord desktop wallet.
//
// It is a native window around the frontend in zycord/wallet/webui, binding
// the same *webui.API the browser interface reaches over HTTP. Two
// consequences follow, and both are the reason this exists rather than a
// packaged browser:
//
//   - It opens no TCP port at all. `zcd ui` has to authenticate a loopback
//     socket because a socket is reachable; this has nothing to reach.
//   - The frontend is the same files, so the two interfaces cannot drift into
//     two behaviours. A JavaScript adapter of about fifty lines picks the
//     transport: fetch() in a browser, the native bridge here.
//
// Every spend still goes through zycord/wallet/session, so this window is
// structurally incapable of being more permissive than `zcd wallet send`.
//
// Honesty about the build: this binary uses cgo and is *not* byte-identical
// across rebuilds. `zcd` is, and remains the escape hatch for anyone who
// declines to trust a binary they cannot reproduce (docs/INSTALL.md).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"time"

	"zycord/core/params"
	"zycord/spec"
	"zycord/update"
	"zycord/wallet/webui"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// version is stamped by the build. An unstamped binary says so rather than
// claiming a release it is not.
var version = "dev"

func main() {
	settingsPath := flag.String("settings", "", "path to the settings file (defaults to the user configuration directory)")
	lockAfter := flag.Duration("lock-after", 15*time.Minute, "wipe the key after this much inactivity; 0 disables the idle lock")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("zycord-wallet", version)
		return
	}

	path := *settingsPath
	if path == "" {
		path = defaultSettingsPath()
	}

	saved := loadSettings(path)

	// Configurable, unlike `zcd ui`: this application is launched by
	// double-clicking an icon and has nowhere else to be told which key file,
	// which node and which network to use.
	api := webui.NewAPI(webui.Config{
		Params:       saved.params(),
		RPC:          saved.RPC,
		ConfirmRPC:   saved.ConfirmRPC,
		KeyPath:      saved.KeyPath,
		LockAfter:    *lockAfter,
		Configurable: true,
	})
	bridge := &Bridge{API: api, settingsPath: path}

	stop := make(chan struct{})
	err := wails.Run(&options.App{
		Title:  "Zycord Wallet",
		Width:  980,
		Height: 760,
		// The same bytes `zcd ui` serves. Wails' asset server applies its own
		// Content-Security-Policy over a custom scheme with no network origin
		// at all, so the page has nowhere to talk to but this process.
		AssetServer: &assetserver.Options{Assets: webui.Assets()},
		Bind:        []any{bridge},
		OnStartup: func(ctx context.Context) {
			bridge.ctx = ctx
			go watchIdle(api, *lockAfter, stop)
		},
		OnShutdown: func(context.Context) {
			close(stop)
			// A closed window must not leave a seed in memory for whatever
			// reads the process next — a crash reporter, a core file, a
			// hibernation image.
			api.Lock()
		},
		Mac: &mac.Options{
			About: &mac.AboutInfo{
				Title: "Zycord Wallet " + version,
				Message: "Reproducible builds are the trust an anonymous project can offer, and this " +
					"binary is not one of them: it uses cgo and is not byte-identical. `zcd` is. " +
					"See docs/INSTALL.md.",
			},
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "zycord-wallet:", err)
		os.Exit(1)
	}
}

// watchIdle wipes the key once nothing has used it for lockAfter.
//
// The interval that matters is the one where nobody is doing anything, so
// this runs on a timer rather than on the next call: a wallet that only locks
// when someone comes back was unlocked for the whole time nobody was
// watching it.
func watchIdle(api *webui.API, lockAfter time.Duration, stop <-chan struct{}) {
	if lockAfter <= 0 {
		return
	}
	tick := lockAfter / 10
	if tick < time.Second {
		tick = time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			api.LockIfIdle()
		}
	}
}

// Bridge is what the frontend calls.
//
// It embeds *webui.API, so every method the browser interface reaches over
// HTTP is bound here under the same name with the same arguments — that is
// what lets one JavaScript file drive both. It adds exactly two things a
// browser cannot do: open a native file dialog, and remember the choice.
type Bridge struct {
	*webui.API

	ctx          context.Context
	settingsPath string
}

// ChooseKeyFile opens the platform's file dialog and returns the chosen path.
//
// A browser has no equivalent — a page can receive a file's contents but
// never learn its path — which is why the browser build asks the person to
// type one instead, as they already did to start `zcd ui`.
func (b *Bridge) ChooseKeyFile() (string, error) {
	if b.ctx == nil {
		return "", fmt.Errorf("the window is not ready yet")
	}
	return wruntime.OpenFileDialog(b.ctx, wruntime.OpenDialogOptions{
		Title: "Choose a Zycord key file",
		Filters: []wruntime.FileFilter{
			{DisplayName: "Zycord key files (*.json)", Pattern: "*.json"},
			{DisplayName: "All files", Pattern: "*"},
		},
	})
}

// Configure applies a configuration and, if the wallet accepted it, writes it
// down. Persisting only what was accepted is what stops a bad node address
// from being reloaded on every start.
func (b *Bridge) Configure(req webui.ConfigureRequest) (*webui.WalletState, error) {
	state, err := b.API.Configure(req)
	if err != nil {
		return nil, err
	}
	if err := saveSettings(b.settingsPath, req); err != nil {
		// Not fatal: the wallet is configured and usable, and the only cost
		// is retyping this next time. Saying so beats failing a working
		// action.
		fmt.Fprintln(os.Stderr, "zycord-wallet: could not save settings:", err)
	}
	return state, nil
}

// UpdateReport is what the window is told about updates.
type UpdateReport struct {
	// Asked records whether the person has answered the one-time question.
	Asked bool `json:"asked"`
	// Enabled is their answer.
	Enabled bool `json:"enabled"`
	// Current is this build's version.
	Current string `json:"current"`
	// Available is the newer version, empty when there is none.
	Available string `json:"available"`
	// Note and Security come from the signed manifest.
	Note     string `json:"note"`
	Security bool   `json:"security"`
	// Installable is false when this wallet must not replace itself in place;
	// Reason says why, and ReleaseURL is where to get the new one by hand.
	Installable bool   `json:"installable"`
	Reason      string `json:"reason"`
	ReleaseURL  string `json:"release_url"`
	// Error is a check that did not complete. Never fatal.
	Error string `json:"error"`
}

// SetUpdateCheck records the answer to the one-time question.
func (b *Bridge) SetUpdateCheck(on bool) error {
	st := loadSettings(b.settingsPath)
	st.UpdateCheck = "off"
	if on {
		st.UpdateCheck = "on"
	}
	return saveRawSettings(b.settingsPath, st)
}

// UpdateStatus checks for a newer wallet, if the person has said it may.
//
// It contacts nothing until UpdateCheck says "on". Not-yet-asked is reported as
// not-asked rather than treated as consent.
func (b *Bridge) UpdateStatus() (*UpdateReport, error) {
	st := loadSettings(b.settingsPath)
	rep := &UpdateReport{
		Asked:      st.UpdateCheck != "",
		Enabled:    st.UpdateCheck == "on",
		Current:    version,
		ReleaseURL: update.RepoURL() + "/releases/latest",
	}
	if !rep.Enabled {
		return rep, nil
	}
	ks, err := update.Keys()
	if err != nil {
		rep.Error = err.Error()
		return rep, nil
	}
	c := &update.Checker{
		Keys: ks, Current: version,
		// The wallet carries no proof-of-work engine, so it is always the plain
		// tier and there is no tier to cross here.
		RandomX: false, Product: update.ProductWallet,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.Check(ctx)
	if err != nil {
		// Never fatal, and never a dialog. A wallet that cannot reach a release
		// host is still a wallet, and saying so quietly is the whole of what is
		// owed.
		rep.Error = err.Error()
		return rep, nil
	}
	if !res.Available() {
		return rep, nil
	}
	rep.Available = res.Manifest.Version
	rep.Note = res.Manifest.Note
	rep.Security = res.Manifest.Urgency == update.UrgencySecurity
	rep.Installable, rep.Reason = walletCanReplaceItself(res)
	return rep, nil
}

// walletCanReplaceItself answers whether this build may rewrite its own
// executable, and why not when it may not.
func walletCanReplaceItself(res *update.Result) (bool, string) {
	if goruntime.GOOS == "darwin" {
		// The macOS build ships as a .app bundle, and replacing one file inside
		// a bundle is wrong independently of everything else here: the bundle is
		// the unit the operating system tracks, quarantines and refuses. There
		// is no code-signing certificate to re-establish either, and that is a
		// release decision (docs/INSTALL.md) rather than something to work
		// around from inside the application.
		return false, "On macOS the wallet is an application bundle, so it is replaced by " +
			"downloading the new one rather than from inside this window."
	}
	if res.Refusal != nil {
		return false, res.Refusal.Error()
	}
	return true, ""
}

// InstallUpdate locks the wallet and then replaces this binary.
//
// **Locking first is not politeness.** While unlocked this process holds a
// decrypted seed in memory, and installing means downloading, unpacking and
// replacing an executable - work that has no business happening with key
// material resident. api.Lock is the same path the idle timer already uses, so
// this is a state the wallet returns to on its own anyway.
//
// It does not restart afterwards. Re-execing a window is a different problem
// from re-execing a daemon, and asking somebody to reopen an application they
// are looking at is a sentence rather than a mechanism.
func (b *Bridge) InstallUpdate() (*UpdateReport, error) {
	rep, err := b.UpdateStatus()
	if err != nil {
		return nil, err
	}
	if rep.Available == "" {
		return rep, fmt.Errorf("there is nothing to install")
	}
	if !rep.Installable {
		return rep, fmt.Errorf("%s", rep.Reason)
	}
	b.API.Lock()

	ks, err := update.Keys()
	if err != nil {
		return rep, err
	}
	c := &update.Checker{Keys: ks, Current: version, RandomX: false, Product: update.ProductWallet}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	res, err := c.Check(ctx)
	if err != nil {
		return rep, err
	}
	if _, _, err := res.Install(ctx, nil, nil); err != nil {
		return rep, err
	}
	rep.Reason = "Installed " + res.Manifest.Version + ". Close this window and open it again to use it."
	return rep, nil
}

// OpenReleasePage opens the release page in the platform's browser, for the
// installs this window must not replace itself.
func (b *Bridge) OpenReleasePage() error {
	if b.ctx == nil {
		return fmt.Errorf("the window is not ready yet")
	}
	wruntime.BrowserOpenURL(b.ctx, update.RepoURL()+"/releases/latest")
	return nil
}

// saveRawSettings persists a settings value the frontend did not send as a
// ConfigureRequest.
func saveRawSettings(path string, st settings) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeSettingsAtomic(path, append(raw, '\n'))
}

// settings is the small amount of state a desktop application is expected to
// remember between launches. It holds no secret: a key file path is not a
// key, and the passphrase is never written anywhere.
type settings struct {
	KeyPath    string `json:"key_path"`
	RPC        string `json:"rpc"`
	ConfirmRPC string `json:"confirm_rpc"`
	Network    string `json:"network"`

	// UpdateCheck is "on", "off", or "" for not yet asked. Three states rather
	// than a bool, because "nobody has been asked" and "somebody said no" are
	// different things: the first shows a one-time banner and the second must
	// not.
	UpdateCheck string `json:"update_check,omitempty"`
}

// params resolves the saved network name. An unrecognised one falls back to
// mainnet rather than refusing to start: the settings file is not a security
// boundary, the network is asserted again on every node call — the node's
// self-reported chain id is checked against it rather than trusted — and a
// window that will not open is worse than one that opens on the default and
// says so in its header.
func (s settings) params() *params.Params {
	if s.Network == spec.Devnet().Name {
		return spec.Devnet()
	}
	return spec.Mainnet()
}

func defaultSettingsPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "zycord-wallet.json"
	}
	return filepath.Join(dir, "zycord", "wallet.json")
}

// loadSettings reads the settings file, falling back to defaults that are
// safe to start from: mainnet, a local node, and no key file — which puts the
// window on its first-run screen rather than on a wallet it invented.
func loadSettings(path string) settings {
	out := settings{RPC: "http://127.0.0.1:9420", Network: "zycord"}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var got settings
	if err := json.Unmarshal(raw, &got); err != nil {
		return out
	}
	if got.RPC != "" {
		out.RPC = got.RPC
	}
	if got.Network != "" {
		out.Network = got.Network
	}
	out.KeyPath, out.ConfirmRPC, out.UpdateCheck = got.KeyPath, got.ConfirmRPC, got.UpdateCheck
	return out
}

func saveSettings(path string, req webui.ConfigureRequest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(settings{
		KeyPath:    req.KeyPath,
		RPC:        req.RPC,
		ConfirmRPC: req.ConfirmRPC,
		Network:    req.Network,
	}, "", "  ")
	if err != nil {
		return err
	}
	// Written the way the rest of this tree writes a file it would mind losing:
	// a temp file in the SAME directory, fsynced and closed under its temporary
	// name, then renamed over the target. A bare os.WriteFile can be torn by a
	// crash between the write and the flush, and what it tears is the file that
	// decides which node this wallet talks to and — now — whether it checks for
	// updates. wallet/atomicfile.go makes the same argument at more length for
	// key files; this mirrors the sequence rather than sharing it, which is what
	// that file says about its own relationship to node/storage.
	return writeSettingsAtomic(path, append(raw, '\n'))
}

// writeSettingsAtomic replaces path durably.
func writeSettingsAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op once the rename below has succeeded

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	// Before the rename: the other order publishes a name whose content is not
	// yet on the disk.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
