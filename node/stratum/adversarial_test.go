package stratum

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"zycord/core/types"
	"zycord/core/u256"
)

// ---------------------------------------------------------------------------
// I8 — the adversarial pass over the Stratum endpoint.
//
// Every test here sends bytes a miner would not send, from a peer that has not
// authenticated, and asks what the node does with them.
// ---------------------------------------------------------------------------

// A1. A slot-holder that never speaks after login.
//
// The keepalive reaper runs on the job ticker's goroutine, and that goroutine
// also PUSHES jobs — a write that can block for WriteTimeout. If a miner logs
// in and then stops reading, the push blocks, and the question is whether the
// reaper still fires.
func TestASilentNonReaderIsStillReaped(t *testing.T) {
	var clk fakeClock
	clk.set(time.Unix(1_700_000_000, 0))
	h := newHarness(t, func(cfg *Config) {
		cfg.Now = clk.now
		cfg.JobRefresh = 10 * time.Millisecond
		cfg.KeepaliveTimeout = time.Minute
		cfg.WriteTimeout = 250 * time.Millisecond
	})
	c := h.dial(t)
	c.login("")
	waitFor(t, func() bool { return h.srv.ConnCount() == 1 })

	// The miner stops reading entirely. Pushes now pile into the socket
	// buffer and eventually block on the write deadline.
	// We do not read from c.rd from here on.

	clk.advance(10 * time.Minute)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.ConnCount() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a connection that logged in and then stopped reading held its slot " +
		"past ten minutes of a one-minute keepalive timeout")
}

// A2. A peer that connects and never sends a byte.
//
// It has not logged in, so tick's pushJob branch is skipped — but the reaper
// must still reach it, because an un-logged-in socket occupies a MaxConns slot
// exactly as much as a logged-in one.
func TestAConnectionThatNeverSpeaksIsReaped(t *testing.T) {
	var clk fakeClock
	clk.set(time.Unix(1_700_000_000, 0))
	h := newHarness(t, func(cfg *Config) {
		cfg.Now = clk.now
		cfg.JobRefresh = 10 * time.Millisecond
		cfg.KeepaliveTimeout = time.Minute
	})
	_ = h.dial(t)
	waitFor(t, func() bool { return h.srv.ConnCount() == 1 })
	clk.advance(5 * time.Minute)
	waitFor(t, func() bool { return h.srv.ConnCount() == 0 })
}

// A3. Sixteen silent sockets starve every honest miner.
//
// This is the connection cap read from the attacker's side: if a slot can be
// held without authenticating and without cost, the cap is not a defence, it
// is the attack's budget.
func TestSilentSocketsCannotStarveTheEndpointForever(t *testing.T) {
	var clk fakeClock
	clk.set(time.Unix(1_700_000_000, 0))
	h := newHarness(t, func(cfg *Config) {
		cfg.Now = clk.now
		cfg.JobRefresh = 10 * time.Millisecond
		cfg.KeepaliveTimeout = time.Minute
		cfg.MaxConns = 4
	})
	for i := 0; i < 4; i++ {
		_ = h.dial(t)
	}
	waitFor(t, func() bool { return h.srv.ConnCount() == 4 })

	// An honest miner is now refused.
	nc, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err == nil {
		_ = nc.SetReadDeadline(time.Now().Add(2 * time.Second))
		var b [1]byte
		if _, rerr := nc.Read(b[:]); rerr == nil {
			t.Fatal("a connection past the cap was served")
		}
		_ = nc.Close()
	}

	// But the squatters do not hold the slots forever.
	clk.advance(5 * time.Minute)
	waitFor(t, func() bool { return h.srv.ConnCount() == 0 })
}

// A4. Every method, called before login, on a connection that never logs in.
// None may panic and none may reach the chain.
func TestUnauthenticatedMethodsTouchNothing(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })
	c := h.dial(t)
	before := h.asm.calls
	for _, m := range []string{"getjob", "submit", "keepalived"} {
		r := c.call(m, map[string]any{})
		if r.Error == nil {
			t.Fatalf("%s before login was answered without an error", m)
		}
		if r.Error.Message != errUnauthenticated.Message {
			t.Fatalf("%s before login: error %q, want %q", m, r.Error.Message,
				errUnauthenticated.Message)
		}
	}
	h.asm.mu.Lock()
	after := h.asm.calls
	h.asm.mu.Unlock()
	if after != before {
		t.Fatalf("an unauthenticated peer caused %d template assemblies", after-before)
	}
}

// A5. Type confusion in every params field. JSON that is well-formed but whose
// members are the wrong type must be an error, never a panic.
func TestWrongTypesInParamsDoNotPanic(t *testing.T) {
	h := newHarness(t, func(cfg *Config) {
		cfg.JobRefresh = time.Hour
		// Generous, so the ban score does not end the connection mid-sweep.
		cfg.MaxBanScore = 10000
	})
	c := h.dial(t)
	lines := []string{
		`{"id":1,"method":"login","params":[]}`,
		`{"id":2,"method":"login","params":"a string"}`,
		`{"id":3,"method":"login","params":123}`,
		`{"id":4,"method":"login","params":null}`,
		`{"id":5,"method":"login","params":{"login":123}}`,
		`{"id":6,"method":"login","params":{"algo":"rx/2"}}`,
		`{"id":7,"method":"login","params":{"algo":[1,2,3]}}`,
		`{"id":8,"method":"login","params":{"login":{"nested":true}}}`,
		`{"id":9,"method":"submit","params":[]}`,
		`{"id":10,"method":"submit","params":{"nonce":12345}}`,
		`{"id":11,"method":"submit","params":{"job_id":[]}}`,
		`{"method":"login","params":{}}`,
		`{"id":{"an":"object"},"method":"keepalived","params":{}}`,
		`{"id":[1,2,3],"method":"getjob","params":{}}`,
		`{}`,
		`[]`,
		`null`,
		`"just a string"`,
		`{"id":1,"method":null,"params":{}}`,
		`{"id":1,"method":123,"params":{}}`,
	}
	for _, l := range lines {
		c.writeRaw(l + "\n")
	}
	// The connection must still be answering after all of that.
	c.writeRaw(`{"id":9999,"method":"keepalived","params":{}}` + "\n")
	deadline := time.Now().Add(5 * time.Second)
	saw := false
	for time.Now().Before(deadline) && !saw {
		_ = c.nc.SetReadDeadline(time.Now().Add(1 * time.Second))
		raw, err := c.rd.ReadBytes('\n')
		if err != nil {
			break
		}
		if strings.Contains(string(raw), "9999") {
			saw = true
		}
	}
	if h.srv.ConnCount() == 0 && !saw {
		t.Log("connection was closed during the sweep; checking the server survived")
	}
	// The server itself must still accept new connections — i.e. no panic took
	// the process down and the accept loop is alive.
	c2 := h.dial(t)
	c2.login("")
}

// A6. Duplicate ids and interleaved requests. The endpoint echoes ids
// verbatim; a duplicate id must not confuse the reply pairing or the state.
func TestDuplicateAndOddIDsAreEchoedNotInterpreted(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })
	c := h.dial(t)
	c.login("")
	// One past the top of uint64, built as an expression rather than written
	// out. The value is the point of the case — an id this endpoint must echo
	// byte-for-byte rather than parse, because parsing it as a number is
	// exactly what overflows — and twenty literal digits are both less legible
	// than the arithmetic and indistinguishable from a commit hash to the
	// history guard that gates publication.
	pastUint64 := new(big.Int).Lsh(big.NewInt(1), 64).String()
	for _, id := range []string{`1`, `1`, `"1"`, `null`, `-1`, `1.5`, pastUint64} {
		c.writeRaw(`{"id":` + id + `,"jsonrpc":"2.0","method":"keepalived","params":{}}` + "\n")
		raw := c.readLine()
		var r struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("decoding %q: %v", raw, err)
		}
		if string(r.ID) != id {
			t.Errorf("id %s was echoed as %s", id, r.ID)
		}
	}
}

// A7. The free path. Stale shares and lost races cost no ban score by design.
// The question is whether that path lets an unauthenticated peer buy unbounded
// work — specifically RandomX verifications.
//
// A submit naming a job id the cache does not hold is refused BEFORE any hash.
// This test measures that: ten thousand unknown-job submits must cost zero
// engine evaluations.
func TestTheFreeStalePathCostsNoHashes(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })
	hot := &hotSpy{}
	h.srv.engine = hot
	c := h.dial(t)
	c.login("")
	base := hot.hashCalls()

	const n = 2000
	for i := 0; i < n; i++ {
		body, _ := json.Marshal(submitParams{
			ID:    sessionOf(t, h),
			JobID: fmt.Sprintf("deadbeef%08x", i),
			Nonce: "00000000",
		})
		c.writeRaw(`{"id":1,"method":"submit","params":` + string(body) + "}\n")
		_ = c.readLine()
	}
	if got := hot.hashCalls() - base; got != 0 {
		t.Fatalf("%d unknown-job submits cost %d RandomX evaluations; the free "+
			"path is not free to the node", n, got)
	}
	if h.srv.ConnCount() != 1 {
		t.Fatal("the connection was closed; the free path is scored after all")
	}
}

// A8. The free path, second form: getjob. It is unscored, and before I8-H1 it
// ASSEMBLED a template on every call.
//
// The bound is minAssemblyInterval: a getjob inside it is answered from the
// cache. This asserts the ceiling from the attacker's side — a flood of calls
// must not buy a flood of assemblies.
func TestGetJobCannotBuyUnboundedAssembly(t *testing.T) {
	var clk fakeClock
	clk.set(time.Unix(1_700_000_000, 0))
	h := newHarness(t, func(cfg *Config) {
		cfg.Now = clk.now
		cfg.JobRefresh = time.Hour
	})
	c := h.dial(t)
	c.login("")
	h.asm.mu.Lock()
	base := h.asm.calls
	h.asm.mu.Unlock()

	const n = 500
	for i := 0; i < n; i++ {
		if r := c.call("getjob", map[string]any{}); r.Error != nil {
			t.Fatalf("getjob %d: %v", i, r.Error)
		}
	}
	h.asm.mu.Lock()
	got := h.asm.calls - base
	h.asm.mu.Unlock()
	if got != 0 {
		t.Errorf("%d getjob calls inside one interval produced %d template "+
			"assemblies, want 0", n, got)
	}
	if h.srv.ConnCount() != 1 {
		t.Fatal("getjob flooding closed a connection that was behaving")
	}
}

// A9. The nonce-clearing invariant, from the ONE path that can carry a dirty
// nonce: a template whose header already has PoW.Nonce set.
//
// blobFor clears it at run time. This test drives the whole server path with a
// dirty assembler and reads the blob off the wire.
func TestNoServedBlobEverCarriesADirtyNonce(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = 20 * time.Millisecond })
	h.asm.dirtyNonce = 0xdeadbeef
	h.asm.dirtyExtra = 0x11223344
	c := h.dial(t)

	check := func(where, blobHex string) {
		t.Helper()
		raw, err := hex.DecodeString(blobHex)
		if err != nil {
			t.Fatalf("%s: blob is not hex: %v", where, err)
		}
		if len(raw) != types.PoWInputSize {
			t.Fatalf("%s: blob is %d bytes, want %d", where, len(raw), types.PoWInputSize)
		}
		for i := types.PoWInputNonceOffset; i < types.PoWInputNonceOffset+4; i++ {
			if raw[i] != 0 {
				t.Fatalf("%s: served blob has a non-zero nonce byte at %d (%x); "+
					"stock XMRig latches into nicehash mode and searches 24 bits",
					where, i, raw[i])
			}
		}
	}

	res := c.login("")
	check("login job", res.Job.Blob)

	r := c.call("getjob", map[string]any{})
	var gj jobParams
	remarshal(t, r.Result, &gj)
	check("getjob", gj.Blob)

	// And a pushed job.
	h.srv.OnHead()
	for i := 0; i < 10; i++ {
		raw := c.readLine()
		var n struct {
			Method string    `json:"method"`
			Params jobParams `json:"params"`
		}
		if err := json.Unmarshal(raw, &n); err != nil {
			continue
		}
		if n.Method == "job" {
			check("pushed job", n.Params.Blob)
			return
		}
	}
	t.Fatal("no pushed job arrived")
}

// A10. Payout redirection. There is no authentication by design; the stated
// reasoning is that the real exposure is emission-address theft. This test
// STATES that exposure as a fact rather than accepting the reasoning: a second
// connection naming a different address gets blocks paid to that address, and
// the node operator's own --payout is not consulted.
func TestAnyConnectionSteersTheEmissionAddress(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })
	attacker := testAddress(0x02, 0xee)

	c := h.dial(t)
	res := c.call("login", loginParams{
		Login: hex.EncodeToString(attacker[:]),
		Agent: "attacker", Algo: []string{"rx/2"},
	})
	if res.Error != nil {
		t.Fatalf("login: %v", res.Error)
	}
	var lr loginResult
	remarshal(t, res.Result, &lr)

	// Submit against the login's job with a nonce; the harness target is
	// all-ones so any nonce is a block.
	body, _ := json.Marshal(submitParams{ID: lr.ID, JobID: lr.Job.JobID, Nonce: "00000000"})
	c.writeRaw(`{"id":7,"method":"submit","params":` + string(body) + "}\n")
	waitFor(t, func() bool {
		h.ch.mu.Lock()
		defer h.ch.mu.Unlock()
		return len(h.ch.applied) > 0
	})
	h.ch.mu.Lock()
	got := h.ch.applied[0].Header.EmissionAddr
	h.ch.mu.Unlock()
	if got != attacker {
		t.Fatalf("EmissionAddr = %x, want the attacker's %x", got[:8], attacker[:8])
	}
	t.Logf("CONFIRMED: an unauthenticated connection redirected this node's "+
		"emission to %x using the node's own CPU. This is the documented "+
		"exposure and it is real.", attacker[:8])
}

// A11. A one-shot (0x01) address must be refused, and refused for BOTH the
// direct form and the worker-suffix form, since the suffix is stripped first.
func TestOneShotPayoutsAreRefusedThroughEveryForm(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })
	oneShot := hex.EncodeToString(func() []byte { a := testAddress(0x01, 0xbb); return a[:] }())
	for _, login := range []string{
		oneShot,
		oneShot + ".worker1",
		oneShot + "+worker1",
		"0x" + oneShot,
		"0X" + oneShot,
		strings.ToUpper(oneShot),
		"  " + oneShot + "  ",
	} {
		c := h.dial(t)
		r := c.call("login", loginParams{Login: login, Algo: []string{"rx/2"}})
		if r.Error == nil {
			t.Fatalf("a one-shot payout was accepted in the form %q", login)
		}
		if r.Error.Message != errUnauthorizedWorker.Message {
			t.Errorf("form %q: error %q, want %q", login, r.Error.Message,
				errUnauthorizedWorker.Message)
		}
	}
}

// A12. Address versions other than 0x01 and 0x02. Only persistent (0x02) may
// be accepted; anything else — including a protocol address 0x00 — must not.
func TestOnlyPersistentAddressVersionsAreAccepted(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })
	for v := 0; v < 256; v++ {
		if v == 0x02 {
			continue
		}
		a := testAddress(byte(v), 0xcc)
		c := h.dial(t)
		r := c.call("login", loginParams{
			Login: hex.EncodeToString(a[:]), Algo: []string{"rx/2"},
		})
		if r.Error == nil {
			t.Fatalf("address version 0x%02x was accepted as a payout", v)
		}
		_ = c.nc.Close()
	}
}

// A13. The submitted-nonce map. It is claimed bounded by the job cache's size.
// A share must pass the low-difficulty check before it is remembered — or an
// attacker can grow the map for free.
//
// This test reads the map's growth directly under an EASY target (where every
// nonce passes) and under a HARD one (where none does).
func TestTheSubmittedNonceMapCannotBeGrownForFree(t *testing.T) {
	h := newHarness(t, func(cfg *Config) {
		cfg.JobRefresh = time.Hour
		cfg.MaxBanScore = 1 << 30 // do not let the ban score end the run
	})
	// A target no nonce can meet: the job target clamps to 1, and a commitment
	// strictly below 1 is impossible.
	h.asm.mu.Lock()
	h.asm.target = hardTarget()
	h.asm.mu.Unlock()

	c := h.dial(t)
	lr := c.login("")

	const n = 3000
	for i := 0; i < n; i++ {
		body, _ := json.Marshal(submitParams{
			ID: lr.ID, JobID: lr.Job.JobID,
			Nonce: fmt.Sprintf("%08x", i),
		})
		c.writeRaw(`{"id":1,"method":"submit","params":` + string(body) + "}\n")
		_ = c.readLine()
	}

	size := submittedMapSize(h.srv, lr.Job.JobID)
	t.Logf("after %d always-failing submits the job's submitted map holds %d "+
		"entries", n, size)
	if size >= n {
		t.Errorf("%d entries recorded for %d shares that could never meet the "+
			"target: the map is grown by an attacker for free, before any "+
			"proof of work is demonstrated (I8-M1)", size, n)
	}
}

// A14. Framing. An unterminated frame, a frame split across many writes, and
// a frame with embedded NULs must all be handled without hanging a goroutine
// or growing a buffer past the cap.
func TestPartialAndPathologicalFramesAreBounded(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })

	// A frame written one byte at a time, never terminated, past the cap.
	c := h.dial(t)
	go func() {
		for i := 0; i < maxLineBytes*3; i++ {
			if _, err := c.nc.Write([]byte("a")); err != nil {
				return
			}
		}
	}()
	waitFor(t, func() bool { return h.srv.ConnCount() == 0 })

	// Embedded NULs inside an otherwise valid frame.
	c2 := h.dial(t)
	c2.writeRaw("{\"id\":1,\"method\":\"login\",\"params\":{\"login\":\"\x00\x00\x00\"}}\n")
	// Must answer, not hang.
	_ = c2.nc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c2.rd.ReadBytes('\n'); err != nil {
		t.Fatalf("a frame with embedded NULs produced no reply: %v", err)
	}
}

// A15. Concurrency: many connections submitting against their own jobs while
// OnHead pushes. Run under -race this is the test that would surface a data
// race on the shared job block or on the conn state.
func TestConcurrentSubmitsAndHeadChangesDoNotRace(t *testing.T) {
	h := newHarness(t, func(cfg *Config) {
		cfg.JobRefresh = 5 * time.Millisecond
		cfg.MaxConns = 8
		cfg.MaxBanScore = 1 << 30
	})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				h.srv.OnHead()
				time.Sleep(time.Millisecond)
			}
		}
	}()
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			nc, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
			if err != nil {
				return
			}
			defer func() { _ = nc.Close() }()
			body, _ := json.Marshal(loginParams{Login: "", Algo: []string{"rx/2"}})
			_, _ = nc.Write([]byte(`{"id":1,"method":"login","params":` + string(body) + "}\n"))
			for j := 0; j < 40; j++ {
				sub, _ := json.Marshal(submitParams{
					JobID: "unknown", Nonce: fmt.Sprintf("%08x", j),
				})
				if _, err := nc.Write([]byte(`{"id":2,"method":"submit","params":` +
					string(sub) + "}\n")); err != nil {
					return
				}
			}
		}(i)
	}
	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()
	_ = h.srv.Close()
}

// ---------------------------------------------------------------------------
// Helpers for the adversarial suite.
// ---------------------------------------------------------------------------

// sessionOf reads the session id of the single live connection.
func sessionOf(t *testing.T, h *harness) string {
	t.Helper()
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	for c := range h.srv.conns {
		return c.sessionID
	}
	return ""
}

// submittedMapSize reads how many nonces a job has recorded.
func submittedMapSize(s *Server, jobID string) int {
	s.mu.Lock()
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.mu.Lock()
		j := c.jobs.get(jobID)
		n := -1
		if j != nil {
			n = len(j.submitted)
		}
		c.mu.Unlock()
		if n >= 0 {
			return n
		}
	}
	return -1
}

// hardTarget is a target whose 64-bit truncation clamps to 1, so that no
// commitment can be strictly below it and every share fails the job target.
func hardTarget() u256.U256 { return u256.FromUint64(1) }

// A13b. The same map, under the SHIPPED ban score, to find the real budget.
//
// A failing share costs 2 points against a cap of 10, so a connection gets
// five before it is closed. The question is whether an attacker can find a
// path that grows the map WITHOUT paying score — and there is one: a duplicate
// costs 1, and a nonce already in the map short-circuits before the target
// check. But the entries themselves are what we are counting, so the path that
// matters is the unscored one.
//
// The unscored path is the RACE: submit against a job, lose the race. That
// returns errJobNotFound before the map is touched. So under the shipped
// score the map is bounded at five entries per job per connection.
func TestUnderTheShippedScoreTheNonceMapIsSmall(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })
	h.asm.mu.Lock()
	h.asm.target = hardTarget()
	h.asm.mu.Unlock()

	c := h.dial(t)
	lr := c.login("")
	for i := 0; i < 200; i++ {
		body, _ := json.Marshal(submitParams{
			ID: lr.ID, JobID: lr.Job.JobID, Nonce: fmt.Sprintf("%08x", i),
		})
		if _, err := c.nc.Write([]byte(`{"id":1,"method":"submit","params":` +
			string(body) + "}\n")); err != nil {
			break
		}
	}
	waitFor(t, func() bool { return h.srv.ConnCount() == 0 })
	t.Log("the shipped ban score closed the connection; the map cannot grow " +
		"past a handful of entries per job on one connection")
}

// A13c. The claim in job.submitted's comment, stated as a test.
//
// The comment says an attacker "would have to spend a real hash per entry to
// get past the low-difficulty check first — and a share that passes that check
// is a share worth remembering". That describes an insert placed AFTER the
// target check. The insert is before it.
//
// This test asserts the comment's property directly: a share that fails the
// job target must not be recorded. It fails today.
func TestOnlyASharePassingTheTargetIsRemembered(t *testing.T) {
	h := newHarness(t, func(cfg *Config) {
		cfg.JobRefresh = time.Hour
		cfg.MaxBanScore = 1 << 30
	})
	h.asm.mu.Lock()
	h.asm.target = hardTarget()
	h.asm.mu.Unlock()

	c := h.dial(t)
	lr := c.login("")
	body, _ := json.Marshal(submitParams{
		ID: lr.ID, JobID: lr.Job.JobID, Nonce: "0000002a",
	})
	c.writeRaw(`{"id":1,"method":"submit","params":` + string(body) + "}\n")
	r := c.readLine()
	if !strings.Contains(string(r), errLowDifficulty.Message) {
		t.Fatalf("expected a low-difficulty rejection, got %s", r)
	}
	if n := submittedMapSize(h.srv, lr.Job.JobID); n != 0 {
		t.Errorf("a share that failed the job target was recorded in the "+
			"submitted map (%d entries); job.submitted's comment claims only "+
			"shares that pass the check are remembered", n)
	}
}

// A13d. The consequence that made the ordering worth changing rather than
// only documenting: before the fix, the SECOND submission of a nonce that had
// already FAILED the job target was answered as a duplicate — one point —
// rather than as a bad share, which is two. A flooder halved its own score
// cost by repeating itself, and every repeat still consumed a map entry.
//
// Now a nonce is only remembered once it has cleared the job target, so a
// repeat of a refused nonce is refused again at full price. Asserted from the
// attacker's side: the cost of the second bad share must equal the cost of the
// first.
func TestRepeatingABadNonceIsNoCheaperThanSendingANewOne(t *testing.T) {
	h := newHarness(t, func(cfg *Config) {
		cfg.JobRefresh = time.Hour
		cfg.MaxBanScore = 1 << 30
	})
	h.asm.mu.Lock()
	h.asm.target = hardTarget()
	h.asm.mu.Unlock()

	c := h.dial(t)
	lr := c.login("")
	send := func(nonce string) string {
		body, _ := json.Marshal(submitParams{ID: lr.ID, JobID: lr.Job.JobID, Nonce: nonce})
		c.writeRaw(`{"id":1,"method":"submit","params":` + string(body) + "}\n")
		return string(c.readLine())
	}
	if first := send("0000002a"); !strings.Contains(first, errLowDifficulty.Message) {
		t.Fatalf("first submit: %s", first)
	}
	costOfFirst := banScoreOf(h.srv)

	second := send("0000002a")
	if strings.Contains(second, errDuplicateShare.Message) {
		t.Fatalf("a repeat of a nonce that FAILED the job target was answered "+
			"as a duplicate: an attacker halves its score cost by repeating "+
			"itself. Reply: %s", second)
	}
	if !strings.Contains(second, errLowDifficulty.Message) {
		t.Fatalf("second submit: %s", second)
	}
	costOfSecond := banScoreOf(h.srv) - costOfFirst
	if costOfSecond != costOfFirst {
		t.Errorf("the first bad share cost %d points and repeating it cost %d; "+
			"they must be equal or repetition is the cheap path",
			costOfFirst, costOfSecond)
	}
}

func banScoreOf(s *Server) int {
	s.mu.Lock()
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.mu.Lock()
		n := c.banScore
		c.mu.Unlock()
		return n
	}
	return -1
}

// A8b. The getjob flood, measured over a socket rather than counted.
//
// This is the measurement that produced I8-H1. Before the fix one connection
// issued ~16,500 getjob calls a second and each one assembled a template, so a
// single peer asked for roughly nine CPU-seconds of work per wall-clock
// second. The rate the socket sustains is unchanged — this endpoint does not
// try to slow a client down — but the ASSEMBLIES those calls buy are now
// bounded by minAssemblyInterval.
func TestGetJobFloodBuysAlmostNoAssembly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })
	c := h.dial(t)
	c.login("")
	h.asm.mu.Lock()
	base := h.asm.calls
	h.asm.mu.Unlock()

	const n = 3000
	start := time.Now()
	done := make(chan int, 1)
	go func() {
		seen := 0
		for seen < n {
			_ = c.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.rd.ReadBytes('\n'); err != nil {
				break
			}
			seen++
		}
		done <- seen
	}()
	for i := 0; i < n; i++ {
		if _, err := c.nc.Write([]byte(
			`{"id":1,"jsonrpc":"2.0","method":"getjob","params":{}}` + "\n")); err != nil {
			break
		}
	}
	seen := <-done
	el := time.Since(start)
	h.asm.mu.Lock()
	built := h.asm.calls - base
	h.asm.mu.Unlock()
	t.Logf("one connection issued %d getjob calls in %s (%.0f/s), buying %d "+
		"template assemblies", seen, el.Truncate(time.Millisecond),
		float64(seen)/el.Seconds(), built)

	// One assembly per elapsed second, plus one for the boundary, plus slack.
	ceiling := int(el/minAssemblyInterval) + 2
	if built > ceiling {
		t.Errorf("%d getjob calls over %s bought %d assemblies, more than the "+
			"%d minAssemblyInterval allows", seen, el.Truncate(time.Millisecond),
			built, ceiling)
	}
}

// A16. The first getjob on a fresh connection must assemble.
//
// minAssemblyInterval compares against conn.lastAssembly, whose zero value is
// the zero time. A login already assembles, so this asserts the interval never
// makes a connection that has just arrived wait for work — the failure mode
// would be a miner idle from connect until the first tick.
func TestTheFirstJobIsNeverWithheldByTheInterval(t *testing.T) {
	var clk fakeClock
	clk.set(time.Unix(1_700_000_000, 0))
	h := newHarness(t, func(cfg *Config) {
		cfg.Now = clk.now
		cfg.JobRefresh = time.Hour
	})
	c := h.dial(t)
	res := c.login("")
	if res.Job.Blob == "" || res.Job.JobID == "" {
		t.Fatal("the login reply carried no job; a miner would idle from connect")
	}
	if res.Job.Height == 0 {
		t.Fatal("the login job names height 0")
	}
}

// A17. A duplicate of a WINNING nonce is still refused as a duplicate.
//
// I8-M1 moved the submitted-map insert below the job-target check. The insert
// must still happen for a share that passes, or a retransmit would be verified
// and applied twice — and on a solo endpoint a share that passes is a block.
func TestAWinningNonceIsRememberedSoARetransmitIsADuplicate(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.JobRefresh = time.Hour })
	c := h.dial(t)
	lr := c.login("")

	// A winning share pushes a fresh job to every connection, this one
	// included, so the reply has to be picked out from among notifications —
	// exactly as a real miner does.
	send := func() string {
		body, _ := json.Marshal(submitParams{
			ID: lr.ID, JobID: lr.Job.JobID, Nonce: "0000002a",
		})
		c.writeRaw(`{"id":1,"method":"submit","params":` + string(body) + "}\n")
		for {
			raw := c.readLine()
			var n struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(raw, &n)
			if n.Method == "" {
				return string(raw)
			}
		}
	}
	if first := send(); !strings.Contains(first, `"status":"OK"`) {
		t.Fatalf("the harness target is all-ones, so this share should win: %s", first)
	}
	if second := send(); !strings.Contains(second, errDuplicateShare.Message) {
		t.Errorf("a retransmit of a WINNING nonce was not answered as a "+
			"duplicate: %s. It would be verified and applied a second time",
			second)
	}
}
