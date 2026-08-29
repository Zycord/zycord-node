// Package webui is the wallet's graphical interface: one frontend, served two
// ways.
//
// `zcd ui` serves the assets in this package over a loopback HTTP server and
// the frontend talks to it with fetch(). The desktop application (desktop/,
// its own Go module) embeds the same assets in a native webview and binds the
// same API type directly, so it opens no TCP port at all. The frontend is one
// set of files in both cases, which is what stops the two experiences from
// drifting apart.
//
// API holds the key and nothing else does. Every spend it performs goes
// through wallet/session, so the graphical wallet is structurally incapable of
// being more permissive than `zcd wallet send`: there is no second path for
// it to be permissive on.
package webui

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
	"zycord/wallet"
	"zycord/wallet/session"
)

// ErrLocked reports an operation that needs the key while the wallet is
// locked.
var ErrLocked = errors.New("wallet: locked")

// ErrNotConfigurable reports a Configure call against an interface that was
// told what to do on a command line. See Config.Configurable.
var ErrNotConfigurable = errors.New(
	"wallet: this wallet was configured on the command line; restart it with the flags you want")

// ErrPreviewChanged reports that the certificate about to be submitted no
// longer matches the one a person looked at and approved.
//
// This is the graphical equivalent of a hardware wallet's trusted display.
// The approval is for a specific payee and a specific amount, so if the
// source's reported balance moved between the preview and the confirmation —
// which is exactly the case a sweep is sized against — the approval does not
// carry over and the person is shown the new numbers instead.
var ErrPreviewChanged = errors.New(
	"wallet: the amounts changed between the preview and the confirmation; nothing was submitted — check the new numbers and approve again")

// ErrNotApproved reports a spend that reached the API without the explicit
// approval the interface is required to collect.
var ErrNotApproved = errors.New("wallet: this spend was not approved; nothing was submitted")

// Config is what an API needs to exist. It holds no secret: the key arrives
// later, through Unlock.
type Config struct {
	// KeyPath is the encrypted key file this wallet opens. It is displayed,
	// so that a person with several wallets can see which one is on screen.
	KeyPath string
	// Params is the network this wallet signs for — the operator's own assertion,
	// never the node's self-reported chain id.
	Params *params.Params
	// RPC is the node to ask. ConfirmRPC, when set, is a second independent node
	// whose answers must agree before an irreversible spend proceeds.
	RPC        string
	ConfirmRPC string
	// LockAfter is how long the key survives with no activity. Zero disables
	// the idle lock, which is a choice a caller has to make explicitly.
	LockAfter time.Duration

	// Configurable allows the front end to change the fields above through
	// Configure.
	//
	// It is true for the desktop application, which is launched by
	// double-clicking an icon and has nowhere else to be told which key file and
	// which node to use, and false for `zcd ui`, which was told on the command
	// line. That asymmetry is deliberate: the network a wallet signs for is the
	// operator's own assertion, and a page silently replacing an assertion that
	// was just made on a command line would be the failure that assertion exists
	// to prevent.
	Configurable bool
}

// API is the whole of what a front end can ask a wallet to do.
//
// Every exported method is safe for concurrent use and is bindable by the
// desktop application's native bridge as it stands: arguments and returns are
// JSON-shaped, and amounts are decimal strings because a u256 does not fit in
// a JavaScript number and silently rounding somebody's balance is not a
// rounding error.
type API struct {
	// cfg is guarded by mu alongside key: Configure rewrites it, and a
	// request in flight must not read half of an old configuration and half
	// of a new one.
	cfg Config

	// mu guards key. Readers — including a spend, which only reads the key —
	// take it for reading, so an idle lock can never zero the seed out from
	// under a signature in flight.
	mu   sync.RWMutex
	key  *wallet.Key
	seen time.Time
}

// NewAPI returns a locked wallet.
func NewAPI(cfg Config) *API {
	return &API{cfg: cfg, seen: time.Now()}
}

// WalletState is what the interface renders in its header: which wallet this
// is, which network it signs for, and whether the key is presently in memory.
type WalletState struct {
	Locked bool `json:"locked"`
	// NeedsKey reports that no key file has been chosen yet, which is the
	// desktop application's first run. It is a different screen from "locked".
	NeedsKey         bool   `json:"needs_key"`
	Configurable     bool   `json:"configurable"`
	KeyPath          string `json:"key_path"`
	Network          string `json:"network"`
	ChainID          uint64 `json:"chain_id"`
	RPC              string `json:"rpc"`
	ConfirmRPC       string `json:"confirm_rpc"`
	Persistent       string `json:"persistent"`
	OneShot          string `json:"one_shot"`
	LockAfterSeconds int    `json:"lock_after_seconds"`
}

// Wallet reports the current state without touching the network.
func (a *API) Wallet() *WalletState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stateLocked()
}

// Configure points this wallet at a key file, a node and a network.
//
// Changing any of them locks first. A key that was unlocked against one
// network must not survive into another: the addresses are derived from the
// key rather than from a chain, so they exist everywhere and read zero on a
// chain that has never seen them — which looks exactly like an empty wallet
// rather than like a mistake.
func (a *API) Configure(req ConfigureRequest) (*WalletState, error) {
	a.mu.RLock()
	configurable := a.cfg.Configurable
	a.mu.RUnlock()
	if !configurable {
		return nil, ErrNotConfigurable
	}

	next, err := req.resolve()
	if err != nil {
		return nil, err
	}
	if next.KeyPath != "" {
		if err := wallet.InspectKeyFile(next.KeyPath); err != nil {
			return nil, err
		}
	}
	if next.ConfirmRPC != "" && session.SameEndpoint(next.RPC, next.ConfirmRPC) {
		return nil, fmt.Errorf("%w: both name %s", session.ErrConfirmRPCNotIndependent, next.RPC)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.key != nil {
		a.key.Zero()
		a.key = nil
	}
	a.cfg.KeyPath, a.cfg.RPC, a.cfg.ConfirmRPC, a.cfg.Params = next.KeyPath, next.RPC, next.ConfirmRPC, next.Params
	a.seen = time.Now()
	return a.stateLocked(), nil
}

// Settings is the current configuration, for a front end that wants to
// pre-fill its own form.
func (a *API) Settings() ConfigureRequest {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return ConfigureRequest{
		KeyPath:    a.cfg.KeyPath,
		RPC:        a.cfg.RPC,
		ConfirmRPC: a.cfg.ConfirmRPC,
		Network:    a.cfg.Params.Name,
	}
}

// ConfigureRequest names a key file, a node and a network.
type ConfigureRequest struct {
	KeyPath    string `json:"key_path"`
	RPC        string `json:"rpc"`
	ConfirmRPC string `json:"confirm_rpc"`
	// Network is "zycord" or "zycord-devnet", matching what every other
	// zcd command calls them. An empty value means mainnet, which is the
	// default everywhere else too.
	Network string `json:"network"`
}

type resolvedConfig struct {
	KeyPath    string
	RPC        string
	ConfirmRPC string
	Params     *params.Params
}

func (r ConfigureRequest) resolve() (resolvedConfig, error) {
	out := resolvedConfig{
		KeyPath:    strings.TrimSpace(r.KeyPath),
		RPC:        strings.TrimSpace(r.RPC),
		ConfirmRPC: strings.TrimSpace(r.ConfirmRPC),
	}
	switch strings.TrimSpace(r.Network) {
	case "", spec.Mainnet().Name:
		out.Params = spec.Mainnet()
	case spec.Devnet().Name:
		out.Params = spec.Devnet()
	default:
		return out, fmt.Errorf("wallet: %q is not a network this build knows; expected %q or %q",
			r.Network, spec.Mainnet().Name, spec.Devnet().Name)
	}
	if out.RPC == "" {
		return out, errors.New("wallet: a node address is required")
	}
	return out, nil
}

func (a *API) stateLocked() *WalletState {
	s := &WalletState{
		Locked:           a.key == nil,
		NeedsKey:         a.cfg.KeyPath == "",
		Configurable:     a.cfg.Configurable,
		KeyPath:          a.cfg.KeyPath,
		Network:          a.cfg.Params.Name,
		ChainID:          a.cfg.Params.ChainID,
		RPC:              a.cfg.RPC,
		ConfirmRPC:       a.cfg.ConfirmRPC,
		LockAfterSeconds: int(a.cfg.LockAfter / time.Second),
	}
	if a.key != nil {
		s.Persistent = session.HexAddr(a.key.Persistent())
		s.OneShot = session.HexAddr(a.key.OneShot())
	}
	return s
}

// Unlock decrypts the key file into memory.
//
// The passphrase is a function argument and nothing more: it never reaches a
// command line, an environment variable, or disk. Argon2id makes a wrong one
// cost the same as a right one, which is also why this is not a rate-limited
// endpoint — the key derivation is the rate limit.
func (a *API) Unlock(passphrase string) (*WalletState, error) {
	a.mu.RLock()
	keyPath := a.cfg.KeyPath
	a.mu.RUnlock()
	if keyPath == "" {
		return nil, errors.New("wallet: no key file has been chosen yet")
	}
	pass := []byte(passphrase)
	defer func() {
		for i := range pass {
			pass[i] = 0
		}
	}()
	k, err := wallet.LoadKeyFile(keyPath, pass)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.key != nil {
		a.key.Zero()
	}
	a.key, a.seen = k, time.Now()
	return a.stateLocked(), nil
}

// Lock wipes the key. It is not a UI state: the seed is overwritten in place,
// so an attacker who reads the process's memory a second later finds zeroes.
func (a *API) Lock() *WalletState {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.key != nil {
		a.key.Zero()
		a.key = nil
	}
	return a.stateLocked()
}

// LockIfIdle wipes the key when nothing has used it for Config.LockAfter. It
// returns true if it locked something.
//
// This is called on a timer rather than on the next request, because the
// interval that matters is the one where nobody is making requests: a wallet
// that only locks when someone comes back has been unlocked the whole time
// nobody was watching it.
func (a *API) LockIfIdle() bool {
	if a.cfg.LockAfter <= 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.key == nil || time.Since(a.seen) < a.cfg.LockAfter {
		return false
	}
	a.key.Zero()
	a.key = nil
	return true
}

// watchIdle runs the idle lock until stop is closed.
//
// Unexported deliberately. Every *exported* method on this type is bound into
// the desktop application's JavaScript bridge, where arguments and returns
// cross as JSON — a channel does not, and a method that cannot be bound would
// be discovered at the moment somebody pressed a button. The desktop shell
// drives the idle lock through LockIfIdle on its own ticker instead, which is
// three lines there and keeps this type bindable in full.
func (a *API) watchIdle(stop <-chan struct{}) {
	if a.cfg.LockAfter <= 0 {
		return
	}
	// A tick well under the interval, so the lock lands near the deadline
	// rather than up to a full interval past it.
	tick := a.cfg.LockAfter / 10
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
			a.LockIfIdle()
		}
	}
}

// touch records activity, so that the idle lock measures inactivity rather
// than uptime.
func (a *API) touch() {
	a.mu.Lock()
	a.seen = time.Now()
	a.mu.Unlock()
}

// AddressBalance is one address as the interface shows it.
type AddressBalance struct {
	Address string `json:"address"`
	Kind    string `json:"kind"`
	Balance string `json:"balance"`
	Spent   bool   `json:"spent"`
}

// Balances is what this key holds, at both of its addresses.
type Balances struct {
	Addresses []AddressBalance `json:"addresses"`
	// Confirmed reports whether a second, independent node was asked and agreed.
	// The interface says which of the two it is rather than displaying a number
	// that looks the same either way.
	Confirmed  bool   `json:"confirmed"`
	ConfirmRPC string `json:"confirm_rpc"`
}

// Balances asks the node what this key's addresses hold.
func (a *API) Balances() (*Balances, error) {
	a.touch()
	cfg := a.config()
	out := &Balances{Confirmed: cfg.ConfirmRPC != "", ConfirmRPC: cfg.ConfirmRPC}
	err := a.withKey(func(s *session.Session, key *wallet.Key) error {
		for _, e := range []struct {
			addr types.Address
			kind string
		}{
			{key.Persistent(), "persistent"},
			{key.OneShot(), "one-shot"},
		} {
			b, err := s.Balance(e.addr)
			if err != nil {
				return err
			}
			out.Addresses = append(out.Addresses, AddressBalance{
				Address: session.HexAddr(e.addr),
				Kind:    e.kind,
				Balance: b.Value.String(),
				Spent:   b.Spent,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Balance asks the node what one arbitrary address holds. It needs no key,
// but it is offered only while unlocked so that a locked window is inert.
func (a *API) Balance(addr string) (*AddressBalance, error) {
	a.touch()
	parsed, err := session.ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	var b session.Balance
	if err := a.withKey(func(s *session.Session, _ *wallet.Key) error {
		var err error
		b, err = s.Balance(parsed)
		return err
	}); err != nil {
		return nil, err
	}
	return &AddressBalance{
		Address: session.HexAddr(parsed),
		Kind:    addressKind(parsed),
		Balance: b.Value.String(),
		Spent:   b.Spent,
	}, nil
}

// NodeInfo is the node screen: who this node says it is, what a block costs,
// and how it is connected.
//
// There is no transaction list here and there will not be one. The node
// retains no history (docs/RUNNING.md), so an interface that showed one would
// be promising something the network does not have.
type NodeInfo struct {
	Reachable bool   `json:"reachable"`
	Error     string `json:"error"`

	Network   string `json:"network"`
	ChainID   uint64 `json:"chain_id"`
	Height    uint64 `json:"height"`
	Tip       string `json:"tip"`
	StateRoot string `json:"state_root"`

	SeqBaseFee       string `json:"seq_base_fee"`
	ParBaseFee       string `json:"par_base_fee"`
	SkipFee          string `json:"skip_fee"`
	SeqGasTarget     uint64 `json:"seq_gas_target"`
	SeqGasLimit      uint64 `json:"seq_gas_limit"`
	ParGasLimit      uint64 `json:"par_gas_limit"`
	BlockByteLimit   uint64 `json:"block_byte_limit"`
	MaxCertsPerBlock uint64 `json:"max_certs_per_block"`

	Peers         int  `json:"peers"`
	Inbound       int  `json:"inbound"`
	Outbound      int  `json:"outbound"`
	Listening     bool `json:"listening"`
	PeerReachable bool `json:"peer_reachable"`
	P2PEnabled    bool `json:"p2p_enabled"`
}

// Node reports what the node says about itself. A node that cannot be reached
// is a state the interface renders rather than an error it throws: a wallet
// whose node is down should say so and stay usable.
func (a *API) Node() *NodeInfo {
	// Deliberately does not touch the idle timer. The interface polls this
	// every few seconds to keep the height in its header current, and an idle
	// lock that a background poll keeps resetting is an idle lock that never
	// fires while a window is open — which is exactly the situation it exists
	// for. Only what a person did counts as activity.
	cfg := a.config()
	out := &NodeInfo{}
	s, err := session.New(nil, cfg.Params, cfg.RPC, cfg.ConfirmRPC)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	// AssertChainID rather than a bare /status: a node on the wrong network
	// is not a node this wallet may show numbers from, and the header is
	// exactly where that has to be visible.
	if _, err := s.AssertChainID(s.Primary()); err != nil {
		out.Error = err.Error()
		return out
	}
	status, err := s.Primary().Status()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Reachable = true
	out.Network, out.ChainID = status.Network, status.ChainID
	out.Height, out.Tip, out.StateRoot = status.Height, status.Tip, status.StateRoot

	if fees, err := s.Primary().Fees(); err == nil {
		out.SeqBaseFee, out.ParBaseFee, out.SkipFee = fees.SeqBase.String(), fees.ParBase.String(), fees.SkipFee.String()
		out.SeqGasTarget, out.SeqGasLimit = fees.SeqGasTarget, fees.SeqGasLimit
		out.ParGasLimit, out.BlockByteLimit = fees.ParGasLimit, fees.BlockByteLimit
		out.MaxCertsPerBlock = fees.MaxCertsPerBlock
	}
	if net, err := s.Primary().Network(); err == nil {
		out.P2PEnabled = net.Enabled
		out.Peers, out.Inbound, out.Outbound = net.Peers, net.Inbound, net.Outbound
		out.Listening, out.PeerReachable = net.Listening, net.Reachable
	}
	return out
}

// SendRequest is a spend as the interface describes it. Amounts are decimal
// strings in drops.
type SendRequest struct {
	To      string `json:"to"`
	Amount  string `json:"amount"`
	OneShot bool   `json:"one_shot"`
	Sweep   bool   `json:"sweep"`
	Refund  string `json:"refund"`

	// Empty or zero means the shared default from wallet/session, which is
	// the same default `zcd wallet send` uses.
	Headroom uint64 `json:"headroom"`
	SeqTip   string `json:"seq_tip"`
	ParTip   string `json:"par_tip"`
	TTL      uint64 `json:"ttl"`

	// DryRun builds and checks and returns the numbers, submitting nothing.
	// The interface always does this first.
	DryRun bool `json:"dry_run"`

	// Approved is the person's explicit act. It carries the numbers they were
	// shown rather than a bare boolean, so an approval cannot silently apply
	// to a different certificate than the one on screen — see
	// ErrPreviewChanged.
	Approved *Approval `json:"approved"`
}

// Approval is what the confirmation dialog sends back: the payee and the
// numbers that were on the screen when the person pressed the button.
//
// Not a bare boolean, because the wallet re-reads the node before it signs and
// an approval given for one certificate must not authorise another. Every
// field is required: an absent payee is a refusal, not a check that is skipped
// because the caller left it out. The whole argument for SendOptions.Approve
// defaulting to nil is that a front end which forgets to ask must not be able
// to spend, and an approval that binds less when it says less would give that
// back on the field a hardware wallet puts on its trusted display.
type Approval struct {
	To     string `json:"to"`
	Amount string `json:"amount"`
	Held   string `json:"held"`
}

// SendResponse is one certificate, before or after submission.
type SendResponse struct {
	Certificate  string `json:"certificate"`
	From         string `json:"from"`
	To           string `json:"to"`
	Refund       string `json:"refund"`
	Amount       string `json:"amount"`
	Held         string `json:"held"`
	FeeNow       string `json:"fee_now"`
	Tip          string `json:"tip"`
	Reserved     string `json:"reserved"`
	Height       uint64 `json:"height"`
	TTL          uint64 `json:"ttl"`
	OneShotDrain bool   `json:"one_shot_drain"`
	Submitted    bool   `json:"submitted"`
	PrimaryRPC   string `json:"primary_rpc"`
	ConfirmRPC   string `json:"confirm_rpc"`
}

// Send builds, checks and — once approved — submits a transfer.
//
// It is a thin adapter over session.Send. Every docs/WALLET.md rule runs
// inside that call, so this method cannot skip one, and the irreversible
// one-shot drain is gated on an approval that names the numbers a person
// actually saw.
func (a *API) Send(req SendRequest) (*SendResponse, error) {
	a.touch()
	to, err := session.ParseAddress(req.To)
	if err != nil {
		return nil, err
	}
	opts, err := sendOptions(req)
	if err != nil {
		return nil, err
	}
	amount := u256.Zero
	if !req.Sweep {
		if amount, err = u256.FromDecimal(strings.TrimSpace(req.Amount)); err != nil {
			return nil, fmt.Errorf("amount: %w", err)
		}
	}

	if !req.DryRun {
		if req.Approved == nil {
			return nil, ErrNotApproved
		}
		approved := *req.Approved

		// The match runs in OnPreview, which session.Send calls for every
		// certificate, rather than in Approve, which it calls only for an
		// irreversible one-shot drain. The drain is where a changed balance
		// changes the *amount*, so it is the case that motivated this — but
		// an approval is an approval of a screen, and a screen that no longer
		// describes what is about to be signed has to stop the spend whatever
		// kind of address it came from.
		opts.OnPreview = func(p *session.Preview) error {
			// The payee is on the display for the same reason a hardware
			// wallet puts it on its screen: it is half of what a person is
			// approving, not merely part of what a caller requested.
			if approved.To == "" {
				return fmt.Errorf("%w: the approval names no payee", ErrNotApproved)
			}
			if !strings.EqualFold(approved.To, session.HexAddr(p.To)) {
				return fmt.Errorf("%w: approved a payment to %s, now paying %s",
					ErrPreviewChanged, approved.To, session.HexAddr(p.To))
			}
			if p.Amount.String() != approved.Amount || p.Held.String() != approved.Held {
				return fmt.Errorf("%w: approved %s drops against a balance of %s, now sending %s against %s",
					ErrPreviewChanged, approved.Amount, approved.Held, p.Amount.String(), p.Held.String())
			}
			return nil
		}
		// Reached only after the match above passed, so this is the person's
		// approval and not a rubber stamp: session.Send refuses a drain
		// outright when Approve is nil, and it never reaches Approve at all
		// when OnPreview returned an error.
		opts.Approve = func(*session.Preview) error { return nil }
	}

	var res *session.Result
	if err := a.withKey(func(s *session.Session, _ *wallet.Key) error {
		var err error
		res, err = s.Send(to, amount, opts)
		return err
	}); err != nil {
		return nil, err
	}
	return renderSend(res), nil
}

// RetireRequest burns the signing authority of one-shot addresses this key
// owns. An empty Addresses retires this key's own one-shot address.
type RetireRequest struct {
	Addresses []string `json:"addresses"`
	DryRun    bool     `json:"dry_run"`
	Approved  bool     `json:"approved"`
}

// Retire is the graphical form of `zcd wallet retire`.
func (a *API) Retire(req RetireRequest) (*SendResponse, error) {
	a.touch()
	if !req.DryRun && !req.Approved {
		return nil, ErrNotApproved
	}
	addrs := make([]types.Address, 0, len(req.Addresses))
	for _, raw := range req.Addresses {
		parsed, err := session.ParseAddress(raw)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, parsed)
	}
	opts := session.DefaultSendOptions()
	opts.DryRun = req.DryRun

	var res *session.Result
	if err := a.withKey(func(s *session.Session, key *wallet.Key) error {
		targets := addrs
		if len(targets) == 0 {
			targets = []types.Address{key.OneShot()}
		}
		var err error
		res, err = s.Retire(targets, opts)
		return err
	}); err != nil {
		return nil, err
	}
	return renderSend(res), nil
}

// config reads the configuration under the lock, for the paths that need it
// without needing the key.
func (a *API) config() Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

// withKey runs fn against the unlocked key, holding the read lock for the
// whole of it.
//
// Holding it throughout — rather than copying the pointer out and releasing —
// is what makes Lock and the idle lock safe: both take the write lock, so
// neither can zero a seed out from under a signature in flight. A wipe that
// lands mid-Sign does not produce an error, it produces a signature from
// zeroed material, which verifies against a public key nobody controls.
//
// The cost is that a spend in flight delays a lock rather than racing it, and
// that a concurrent read waits behind it. For a single-person wallet that is
// the right side of the trade.
//
// fn must not call back into a method that takes a.mu: sync.RWMutex is not
// reentrant, and a writer arriving in between would deadlock the pair.
func (a *API) withKey(fn func(*session.Session, *wallet.Key) error) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.key == nil {
		return ErrLocked
	}
	s, err := session.New(a.key, a.cfg.Params, a.cfg.RPC, a.cfg.ConfirmRPC)
	if err != nil {
		return err
	}
	return fn(s, a.key)
}

func sendOptions(req SendRequest) (session.SendOptions, error) {
	opts := session.DefaultSendOptions()
	opts.OneShot = req.OneShot
	opts.Sweep = req.Sweep
	opts.DryRun = req.DryRun
	if req.Headroom != 0 {
		opts.Headroom = req.Headroom
	}
	if req.TTL != 0 {
		opts.TTL = req.TTL
	}
	if s := strings.TrimSpace(req.SeqTip); s != "" {
		v, err := u256.FromDecimal(s)
		if err != nil {
			return opts, fmt.Errorf("seq tip: %w", err)
		}
		opts.SeqTip = v
	}
	if s := strings.TrimSpace(req.ParTip); s != "" {
		v, err := u256.FromDecimal(s)
		if err != nil {
			return opts, fmt.Errorf("par tip: %w", err)
		}
		opts.ParTip = v
	}
	if s := strings.TrimSpace(req.Refund); s != "" {
		v, err := session.ParseAddress(s)
		if err != nil {
			return opts, fmt.Errorf("refund: %w", err)
		}
		opts.Refund = v
	}
	return opts, nil
}

func renderSend(res *session.Result) *SendResponse {
	p := res.Preview
	out := &SendResponse{
		Certificate:  "0x" + hex.EncodeToString(p.ID[:]),
		From:         session.HexAddr(p.From),
		Refund:       session.HexAddr(p.Refund),
		Amount:       p.Amount.String(),
		Held:         p.Held.String(),
		FeeNow:       p.FeeNow.String(),
		Tip:          p.Tip.String(),
		Reserved:     p.Ceiling.String(),
		Height:       p.Height,
		TTL:          p.TTL,
		OneShotDrain: p.OneShotDrain,
		Submitted:    res.Submitted,
		PrimaryRPC:   p.PrimaryURL,
		ConfirmRPC:   p.ConfirmURL,
	}
	if p.To != (types.Address{}) {
		out.To = session.HexAddr(p.To)
	}
	return out
}

func addressKind(a types.Address) string {
	if a[0] == crypto.AddrVersionOneShot {
		return "one-shot"
	}
	return "persistent"
}
