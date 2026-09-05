package localnode

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"zycord/spec"
)

var (
	buildOnce sync.Once
	builtNode string
	buildErr  error
)

// buildNode compiles cmd/zycordd once per test binary. The pure-Go build runs
// a devnet, which is all these tests need.
func buildNode(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "zycordd-test-")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "zycordd")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, "zycord/cmd/zycordd")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("%v\n%s", err, b)
			return
		}
		builtNode = out
	})
	if buildErr != nil {
		t.Skipf("cannot build zycordd here: %v", buildErr)
	}
	return builtNode
}

func TestMain(m *testing.M) {
	code := m.Run()
	if builtNode != "" {
		os.RemoveAll(filepath.Dir(builtNode))
	}
	os.Exit(code)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitStatus(t *testing.T, rpc string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(rpc + "/status")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no node answered at %s", rpc)
}

// waitLog polls the captured log for a line the node prints.
//
// Polling rather than asserting once, because answering RPC and having been
// LOGGED are two different clocks. os/exec hands the child's stdout to a pipe
// and copies it here on a goroutine, so waitStatus can succeed -- the listener
// is up, which is a network fact -- while the line announcing it is still in
// the pipe. Measured on the Windows runner, where that gap is wide enough to
// fail an immediate check that passes every time on Linux.
func waitLog(t *testing.T, m *Manager, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(m.Info().Log, "\n"), want) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the log tail never carried %q; got %v", want, m.Info().Log)
}

// manager returns a Manager whose node is stopped however the test ends.
//
// t.Cleanup and not a defer in each test: a t.Fatalf skips the rest of the
// function, so a Stop written at the bottom of the body does not run on the
// path where it matters most. That left a zycordd alive on the Windows runner
// after one failed assertion, and the orphan then held the temp directory open
// so that even TempDir's own cleanup failed -- one missed line reported as
// three separate failures.
func manager(t *testing.T, bin string) *Manager {
	t.Helper()
	m := &Manager{Binary: bin, DataRoot: t.TempDir(), Port: freePort(t)}
	t.Cleanup(func() { _ = m.Stop() })
	return m
}

// TestStartRunsADevnetNodeAndStopEndsIt is the whole contract: a process
// appears, answers RPC on the port it was given, writes a log, and is gone
// after Stop.
func TestStartRunsADevnetNodeAndStopEndsIt(t *testing.T) {
	bin := buildNode(t)
	m := manager(t, bin)
	rpc, err := m.Start(spec.Devnet().Name, Options{})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, rpc)

	info := m.Info()
	if !info.Running || info.Adopted || info.PID == 0 || info.Network != spec.Devnet().Name {
		t.Fatalf("after Start: %+v", info)
	}
	if _, err := os.Stat(filepath.Join(info.DataDir, "node.log")); err != nil {
		t.Fatalf("no node.log in the data directory: %v", err)
	}
	waitLog(t, m, "rpc listening")

	// Starting again for the same network is the same node.
	again, err := m.Start(spec.Devnet().Name, Options{})
	if err != nil || again != rpc || m.Info().PID != info.PID {
		t.Fatalf("a second Start must be a no-op: %v %s pid %d vs %d", err, again, m.Info().PID, info.PID)
	}

	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	info = m.Info()
	if info.Running || info.Exited != "" {
		t.Fatalf("after Stop: %+v", info)
	}
	if _, err := http.Get(rpc + "/status"); err == nil {
		t.Fatal("the node still answers after Stop")
	}
}

// TestAnExistingNodeOnTheRightNetworkIsAdopted: the person who already runs
// a node does not get a second one.
func TestAnExistingNodeOnTheRightNetworkIsAdopted(t *testing.T) {
	bin := buildNode(t)
	port := freePort(t)
	first := manager(t, bin)
	first.Port = port
	rpc, err := first.Start(spec.Devnet().Name, Options{})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, rpc)

	second := manager(t, bin)
	second.Port = port
	got, err := second.Start(spec.Devnet().Name, Options{})
	if err != nil {
		t.Fatal(err)
	}
	info := second.Info()
	if got != rpc || !info.Adopted || info.Running {
		t.Fatalf("expected adoption of %s, got %s with %+v", rpc, got, info)
	}
}

// TestANodeThatExitsIsReported: a refused start — here, a network name the
// binary knows but a data directory it cannot write — ends as Exited with the
// reason, not as a Running that answers nothing.
func TestANodeThatExitsIsReported(t *testing.T) {
	bin := buildNode(t)
	root := filepath.Join(t.TempDir(), "file-not-dir")
	if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Binary: bin, DataRoot: root, Port: freePort(t)}
	if _, err := m.Start(spec.Devnet().Name, Options{}); err == nil {
		t.Fatal("expected MkdirAll under a file to fail")
	}

	m = manager(t, bin)
	if _, err := m.Start("moonnet", Options{}); err == nil {
		t.Fatal("an unknown network must be refused before anything starts")
	}
	if _, err := (&Manager{}).Start(spec.Devnet().Name, Options{}); err != ErrNoBinary {
		t.Fatalf("no binary = %v, want ErrNoBinary", err)
	}
}

// TestMiningIsARestartWithAPayout: turning mining on is a different
// process with the flags the node reads at start, and a one-shot payout is
// refused before anything starts.
func TestMiningIsARestartWithAPayout(t *testing.T) {
	bin := buildNode(t)
	m := manager(t, bin)
	rpc, err := m.Start(spec.Devnet().Name, Options{})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, rpc)
	pid := m.Info().PID

	if _, err := m.Start(spec.Devnet().Name, Options{Mine: true, Payout: "0x01" + strings.Repeat("00", 31)}); err == nil {
		t.Fatal("a one-shot payout must be refused")
	}
	if m.Info().PID != pid {
		t.Fatal("a refused option change must not touch the running node")
	}

	payout := "0x02" + strings.Repeat("ab", 31)
	rpc2, err := m.Start(spec.Devnet().Name, Options{Mine: true, Payout: payout, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, rpc2)
	info := m.Info()
	if info.PID == pid || !info.Options.Mine || info.Options.Payout != payout {
		t.Fatalf("expected a restarted miner, got %+v (old pid %d)", info, pid)
	}
	waitLog(t, m, "mining to")
}

// TestAnExitedNodeReportsItsOwnReason: a node that refuses to start explains
// itself on its last line, and that sentence is what the wallet has to show.
// An exit status is a number nobody can act on.
func TestAnExitedNodeReportsItsOwnReason(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no shell scripts on Windows")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "zycordd")
	script := "#!/bin/sh\n" +
		"echo 'starting up'\n" +
		"echo 'zycordd: zycord requires the randomx-v2 engine' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Binary: bin, DataRoot: t.TempDir(), Port: freePort(t)}
	t.Cleanup(func() { _ = m.Stop() })
	if _, err := m.Start(spec.Devnet().Name, Options{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	var info Info
	for time.Now().Before(deadline) {
		if info = m.Info(); info.Exited != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if info.Exited == "" {
		t.Fatal("a process that exited must be reported as exited")
	}
	if !strings.Contains(info.Exited, "randomx-v2 engine") {
		t.Fatalf("Exited = %q; it must carry the node's own last line, not just a status", info.Exited)
	}
}

func TestFindLooksBesideTheApplicationFirst(t *testing.T) {
	dir := t.TempDir()
	name := "zycordd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if Find(dir) != "" && Find(dir) == filepath.Join(dir, name) {
		t.Fatal("found a binary that does not exist")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := Find("", dir); got != p {
		t.Fatalf("Find = %q, want %q", got, p)
	}
}

func TestRingKeepsTheTail(t *testing.T) {
	r := newRing(3)
	r.Write([]byte("a\nb\n"))
	r.Write([]byte("c\nd\ne"))
	if got := strings.Join(r.lines(), ","); got != "b,c,d" {
		t.Fatalf("ring = %q, want b,c,d (partial line held back)", got)
	}
	r.Write([]byte("\n"))
	if got := strings.Join(r.lines(), ","); got != "c,d,e" {
		t.Fatalf("ring = %q, want c,d,e", got)
	}
}
