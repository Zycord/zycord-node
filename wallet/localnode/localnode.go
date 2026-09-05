// Package localnode runs a zycordd beside the wallet.
//
// The wallet is a client of a node and holds no chain of its own. Asking
// somebody who downloaded an application to also run a daemon before it does
// anything is how a wallet gets uninstalled, and pointing every download at
// infrastructure the project runs is how a project becomes the thing every
// wallet trusts. So the desktop application ships the node next to itself and
// starts it: a full, non-mining node, on a data directory of its own, with its
// RPC on loopback, that the wallet then talks to exactly as it would talk to
// any other.
//
// It is a child process rather than an in-process import for three reasons,
// each sufficient on its own:
//
//   - The key lives in the wallet's memory. A node parses bytes from strangers
//     all day; keeping that out of the address space that holds a seed is the
//     cheapest isolation there is.
//   - The node that ships is the node that is tested. cmd/zycordd carries the
//     sync driver, the seeds, the checkpoints, the update policy and the
//     shutdown order, and a second copy of that wiring inside the wallet would
//     be a second place for it to be wrong.
//   - RandomX is cgo, and the Windows wallet is deliberately not. The engine
//     stays in the binary that already carries it.
//
// The one thing this package cannot do is make a node that is not there. If
// no zycordd is found beside the application, Info reports that and the
// wallet offers an external node instead; it never silently downloads one.
package localnode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"zycord/spec"
)

// DefaultPort is the port zycordd serves RPC on by default, and therefore the
// port a node somebody started by hand is most likely on. AltPort is where
// the bundled node goes when that one is taken by something that is not the
// node this wallet wants.
const (
	DefaultPort = 9420
	AltPort     = 9440
)

// ErrNoBinary reports that no zycordd was found.
var ErrNoBinary = errors.New("localnode: no zycordd binary is bundled with this wallet")

// ErrNetwork reports a network name this package cannot start a node for.
var ErrNetwork = errors.New("localnode: unknown network")

// logLines is how much of the node's output is kept for the interface. The
// full log goes to a file in the data directory.
const logLines = 200

// Manager starts, watches and stops one node.
//
// Zero value is not usable: Binary and DataRoot must be set. Find helps with
// the first.
type Manager struct {
	// Binary is the zycordd to run.
	Binary string
	// DataRoot holds one data directory per network beneath it, so a wallet
	// switched from the testnet to mainnet does not sync one chain over the
	// other's files.
	DataRoot string
	// Port is the RPC port to try first; zero means DefaultPort.
	Port int
	// Peers are extra bootstrap addresses, for networks with no seeds. Tests
	// use it; a public network has seeds in the binary.
	Peers []string
	// Stderr, if set, receives a copy of the node's output.
	Stderr io.Writer

	mu      sync.Mutex
	proc    *proc
	network string
	opts    Options
	rpc     string
	dir     string
	adopted bool
	started time.Time
	log     *ring
	logFile *os.File

	// verOnce guards the one `zycordd --version` this manager ever runs.
	verOnce sync.Once
	version string
}

// proc is one child process and how it ended.
//
// err is written by the goroutine that waits on the process and read only
// after done is closed, which is the ordering a closed channel guarantees; so
// nothing here takes Manager.mu, and Stop can hold that lock while it waits
// for done without deadlocking against the reaper.
type proc struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	// log is the ring this process wrote to, read once when it exits to
	// recover the reason it gives on its way out.
	log *ring
}

// lastLine is the final non-empty line the process wrote.
func (p *proc) lastLine() string {
	if p == nil || p.log == nil {
		return ""
	}
	lines := p.log.lines()
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			return s
		}
	}
	return ""
}

// exited reports whether the process has ended, and how.
func (p *proc) exited() (bool, error) {
	if p == nil {
		return false, nil
	}
	select {
	case <-p.done:
		return true, p.err
	default:
		return false, nil
	}
}

// Options is what a person can change about the bundled node from the
// interface. Anything else — the port, the data directory, the seeds — is the
// wallet's business and not a setting.
type Options struct {
	// Mine turns the node into a miner, paying Payout. The node refuses a
	// one-shot payout itself (docs/WALLET.md rule 3), so what the wallet
	// passes is always its persistent address.
	Mine   bool   `json:"mine"`
	Payout string `json:"payout"`
	// Threads is the nonce-search parallelism; zero is one per core.
	Threads int `json:"threads"`
}

// Info is what the interface is told.
type Info struct {
	// Available reports that a binary exists to run.
	Available bool   `json:"available"`
	Binary    string `json:"binary"`
	// Running is a child process this manager started and that has not
	// exited. Adopted is the other way to have a node: one was already
	// answering on the port, on the right network, so it is used instead.
	Running bool   `json:"running"`
	Adopted bool   `json:"adopted"`
	Network string `json:"network"`
	RPC     string `json:"rpc"`
	DataDir string `json:"data_dir"`
	PID     int    `json:"pid"`
	// UptimeSeconds is since the process started.
	UptimeSeconds int `json:"uptime_seconds"`
	// Exited says why the last process ended when it ended on its own —
	// a crash, a refused network, a port it could not bind. Empty while it
	// runs and after a Stop.
	Exited string `json:"exited"`
	// Version is what the bundled binary calls itself, so the wallet can show
	// which node it is running beside which wallet.
	Version string `json:"version"`
	// Options are what the running node was started with.
	Options Options `json:"options"`
	// Log is the tail of the node's own output.
	Log []string `json:"log"`
}

// Find returns the first zycordd in dirs, then on PATH, or "".
//
// It looks for the executable name the platform uses and nothing else: a
// wallet must not run whatever file happens to be called something similar
// next to it.
func Find(dirs ...string) string {
	name := "zycordd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// networkFlag maps a network name to the flag that selects it.
func networkFlag(network string) ([]string, error) {
	switch network {
	case spec.Mainnet().Name:
		return nil, nil
	case spec.Testnet().Name:
		return []string{"--testnet"}, nil
	case spec.Devnet().Name:
		return []string{"--devnet"}, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrNetwork, network)
}

// Start runs a node for network with opts, or adopts one already answering,
// and returns the RPC address to talk to.
//
// Calling it again with the same network and options is a no-op that returns
// the same address. Anything different stops the running node first: two
// nodes from one wallet is never what anybody meant, and mining is a flag the
// node reads at start.
func (m *Manager) Start(network string, opts Options) (string, error) {
	if m.Binary == "" {
		return "", ErrNoBinary
	}
	flags, err := networkFlag(network)
	if err != nil {
		return "", err
	}
	if opts.Mine {
		if !strings.HasPrefix(strings.ToLower(opts.Payout), "0x02") {
			return "", errors.New("localnode: mining needs a persistent (0x02) payout address")
		}
		flags = append(flags, "--mine", "--payout", opts.Payout)
		if opts.Threads > 0 {
			flags = append(flags, "--mine-threads", fmt.Sprint(opts.Threads))
		}
	} else {
		opts = Options{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if gone, _ := m.proc.exited(); m.proc != nil && !gone && m.network == network && m.opts == opts {
		return m.rpc, nil
	}
	if m.adopted && m.network == network {
		// Not ours to reconfigure: an adopted node mines or not as its
		// operator decided.
		return m.rpc, nil
	}
	if m.proc != nil {
		m.stopLocked()
	}

	port := m.Port
	if port == 0 {
		port = DefaultPort
	}
	// Somebody may already be running a node on this machine — the person
	// who mines, say. If it is on the network we want, use it: two nodes
	// syncing the same chain on one laptop is a waste, and fighting over the
	// port is worse. If it is on another network, or is not a node at all,
	// go to the alternate port.
	if name, ok := probe(port); ok {
		if name == network {
			m.adopted, m.network, m.rpc, m.proc = true, network, rpcURL(port), nil
			return m.rpc, nil
		}
		port = AltPort
		if _, busy := probe(port); busy || !free(port) {
			return "", fmt.Errorf("localnode: ports %d and %d are both in use", DefaultPort, AltPort)
		}
	} else if !free(port) {
		port = AltPort
		if !free(port) {
			return "", fmt.Errorf("localnode: ports %d and %d are both in use", DefaultPort, AltPort)
		}
	}

	dir := filepath.Join(m.DataRoot, network)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// No --listen, so the node is periphery: it dials out and can never be
	// dialled. That is what a wallet should be — it needs no forwarded port
	// and offers no inbound surface — and it is a configuration the network
	// already expects, so a seed cannot tell one of these from any other
	// outbound-only node. No --no-seeds either: the built-in bootstrap seed
	// is how a fresh install finds the network at all.
	args := append([]string{"--dir", dir, "--rpc", fmt.Sprintf("127.0.0.1:%d", port), "--no-update-check"}, flags...)
	if len(m.Peers) > 0 {
		args = append(args, "--peers", strings.Join(m.Peers, ","))
	}

	m.log = newRing(logLines)
	var sink io.Writer = m.log
	if f, err := os.OpenFile(filepath.Join(dir, "node.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
		m.logFile = f
		sink = io.MultiWriter(m.log, f)
	}
	if m.Stderr != nil {
		sink = io.MultiWriter(sink, m.Stderr)
	}

	cmd := exec.Command(m.Binary, args...)
	cmd.Stdout = sink
	cmd.Stderr = sink
	cmd.Dir = dir
	cmd.SysProcAttr = sysProcAttr()
	if err := cmd.Start(); err != nil {
		m.closeLog()
		return "", fmt.Errorf("localnode: starting %s: %w", m.Binary, err)
	}
	p := &proc{cmd: cmd, done: make(chan struct{}), log: m.log}
	m.proc, m.network, m.opts, m.rpc, m.dir = p, network, opts, rpcURL(port), dir
	m.adopted, m.started = false, time.Now()
	go func() {
		err := cmd.Wait()
		// "exit status 1" is not a reason, and the reason is right there: a
		// node that refuses to start says why on its last line before it goes.
		// Measured on a wallet packaged with the wrong node binary, where the
		// process explained itself in one clear sentence and the interface
		// showed "No node" — a wallet reporting an exit code it cannot act on,
		// beside a log holding the sentence somebody needed to read.
		if reason := p.lastLine(); reason != "" {
			if err != nil {
				err = fmt.Errorf("%s (%w)", reason, err)
			} else {
				err = errors.New(reason)
			}
		} else if err == nil {
			err = errors.New("the node exited")
		}
		p.err = err
		close(p.done)
	}()
	return m.rpc, nil
}

// Stop ends the node, gracefully first.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.adopted = false
	if m.proc == nil {
		return nil
	}
	return m.stopLocked()
}

// stopLocked is Stop under m.mu.
//
// Graceful first: zycordd flushes and closes its store on SIGTERM, and a
// store cut mid-write is repaired on the next start rather than lost, but
// "repaired" is a slower start and a line in the log nobody should have to
// read. Ten seconds is generous for a node that is not mid-dataset-fill and
// about right for one that is.
func (m *Manager) stopLocked() error {
	p := m.proc
	m.proc, m.rpc = nil, ""
	defer m.closeLog()
	if p == nil || p.cmd.Process == nil {
		return nil
	}
	if gone, _ := p.exited(); gone {
		return nil
	}
	_ = terminate(p.cmd.Process)
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	return nil
}

func (m *Manager) closeLog() {
	if m.logFile != nil {
		m.logFile.Close()
		m.logFile = nil
	}
}

// Version asks the bundled binary what it calls itself, once.
//
// Exec rather than a build-time constant: the wallet and the node are two
// binaries built from one tree and packaged together, and the whole reason to
// show this is to catch the case where they are not the pair anybody intended.
// A constant compiled into the wallet would report what the wallet believes
// rather than what is on disk, which is the opposite of the question.
func (m *Manager) Version() string {
	if m.Binary == "" {
		return ""
	}
	m.verOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, m.Binary, "--version")
		// WaitDelay, and it is load-bearing rather than tidy. Cancelling the
		// context kills the process this started; it does not close a pipe a
		// GRANDCHILD still holds, and Output waits for the pipe. A wrapper
		// script that execs something else is enough to produce that, and
		// without this the call blocks for as long as the grandchild lives --
		// measured at a full minute against a stub, past a timeout that was
		// supposed to bound it at five seconds. WaitDelay is what bounds the
		// wait itself.
		cmd.WaitDelay = 2 * time.Second
		out, err := cmd.Output()
		if err != nil && len(out) == 0 {
			return
		}
		// "zycordd v1.2.3" -> "v1.2.3"; anything else is reported whole.
		fields := strings.Fields(strings.TrimSpace(string(out)))
		if len(fields) == 2 && fields[0] == "zycordd" {
			m.version = fields[1]
			return
		}
		m.version = strings.TrimSpace(string(out))
	})
	return m.version
}

// Info reports the manager's state.
func (m *Manager) Info() Info {
	// Resolved before the lock. Version runs a program the first time it is
	// called, and a Manager whose mutex is held across an exec is a Manager
	// that a slow binary can freeze for every other caller.
	version := m.Version()

	m.mu.Lock()
	defer m.mu.Unlock()
	out := Info{
		Available: m.Binary != "",
		Binary:    m.Binary,
		Version:   version,
		Adopted:   m.adopted,
		Network:   m.network,
		Options:   m.opts,
		RPC:       m.rpc,
		DataDir:   m.dir,
	}
	if m.log != nil {
		out.Log = m.log.lines()
	}
	if m.proc != nil {
		if gone, err := m.proc.exited(); gone {
			out.Exited = err.Error()
			m.closeLog()
		} else {
			out.Running = true
			out.PID = m.proc.cmd.Process.Pid
			out.UptimeSeconds = int(time.Since(m.started) / time.Second)
		}
	}
	return out
}

// RPC is the address of the node this manager is using, or "".
func (m *Manager) RPC() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rpc
}

func rpcURL(port int) string { return fmt.Sprintf("http://127.0.0.1:%d", port) }

// probe asks whatever is on port who it is, and reports the network name if
// it answered like a zycordd.
func probe(port int) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rpcURL(port)+"/status", nil)
	if err != nil {
		return "", false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	var st struct {
		Network string `json:"network"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&st) != nil {
		return "", false
	}
	return st.Network, st.Network != ""
}

// free reports whether nothing is listening on port.
func free(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// ring keeps the last n lines written to it.
type ring struct {
	mu   sync.Mutex
	n    int
	buf  []string
	part string
}

func newRing(n int) *ring { return &ring{n: n} }

func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.part + string(p)
	for {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			break
		}
		r.push(s[:i])
		s = s[i+1:]
	}
	r.part = s
	return len(p), nil
}

func (r *ring) push(line string) {
	line = strings.TrimRight(line, "\r")
	if len(r.buf) == r.n {
		copy(r.buf, r.buf[1:])
		r.buf = r.buf[:r.n-1]
	}
	r.buf = append(r.buf, line)
}

func (r *ring) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.buf...)
}
