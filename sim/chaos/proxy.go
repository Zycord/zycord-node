// Package chaos puts a hostile world between real nodes.
//
// The in-process harness in node/p2p makes partition and eclipse
// *deterministic*, which is the right tool for those properties: a schedule
// reproduces from a seed where a socket does not. What it cannot exercise is
// the thing the confidence section of I3 named — concurrency, latency,
// reordering, connection churn, partial writes, and an operating system's
// scheduler rather than the harness's.
//
// So this package supplies the other half: a TCP proxy that sits between real
// `zycordd` processes on real sockets and injects delay, loss, truncation and
// severed connections. The deterministic harness proves the logic; the soak
// proves the implementation of the logic under a scheduler nobody controls.
// Both, for the same reason both storage crash suites are kept.
package chaos

import (
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Config describes how hostile the link is.
type Config struct {
	// Latency and Jitter delay every chunk. Jitter is added uniformly, so
	// chunks can arrive out of the order they were sent — which is the point.
	Latency time.Duration
	Jitter  time.Duration
	// DropRate is the probability of discarding a chunk outright, in [0,1].
	// A dropped chunk inside a TLS stream tears the connection, which is
	// realistic: TLS does not tolerate gaps, so loss shows up as churn.
	DropRate float64
	// SeverRate is the probability, per chunk, of killing the connection
	// outright — the shape a flaky home connection or a NAT timeout has.
	SeverRate float64
	// BandwidthBytesPerSecond throttles each direction. Zero means unlimited.
	BandwidthBytesPerSecond int
}

// Proxy forwards a listen address to a target, applying chaos in both
// directions.
type Proxy struct {
	cfg    Config
	target string
	ln     net.Listener

	mu        sync.Mutex
	rng       *rand.Rand
	partition atomic.Bool

	conns     atomic.Int64
	severed   atomic.Int64
	bytesUp   atomic.Int64
	bytesDown atomic.Int64

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewProxy starts a chaos proxy in front of a target address.
func NewProxy(listenAddr, target string, cfg Config, seed int64) (*Proxy, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	p := &Proxy{
		cfg:    cfg,
		target: target,
		ln:     ln,
		rng:    rand.New(rand.NewSource(seed)),
		quit:   make(chan struct{}),
	}
	p.wg.Add(1)
	go p.accept()
	return p, nil
}

// Addr is the proxy's listen address.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Partition cuts the link entirely: existing connections are severed and new
// ones refused. This is how a soak opens and heals a network split without
// touching the nodes.
func (p *Proxy) Partition(on bool) { p.partition.Store(on) }

// Stats reports what the link did.
type Stats struct {
	Connections int64
	Severed     int64
	BytesUp     int64
	BytesDown   int64
}

// Stats returns a snapshot.
func (p *Proxy) Stats() Stats {
	return Stats{
		Connections: p.conns.Load(),
		Severed:     p.severed.Load(),
		BytesUp:     p.bytesUp.Load(),
		BytesDown:   p.bytesDown.Load(),
	}
}

// Close stops the proxy.
func (p *Proxy) Close() error {
	select {
	case <-p.quit:
	default:
		close(p.quit)
	}
	err := p.ln.Close()
	p.wg.Wait()
	return err
}

func (p *Proxy) accept() {
	defer p.wg.Done()
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		if p.partition.Load() {
			client.Close()
			continue
		}
		p.conns.Add(1)
		p.wg.Add(1)
		go p.pipe(client)
	}
}

func (p *Proxy) pipe(client net.Conn) {
	defer p.wg.Done()
	defer client.Close()

	server, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		return
	}
	defer server.Close()

	done := make(chan struct{}, 2)
	go func() { p.copy(server, client, &p.bytesUp); done <- struct{}{} }()
	go func() { p.copy(client, server, &p.bytesDown); done <- struct{}{} }()

	select {
	case <-done:
	case <-p.quit:
	}
}

// copy moves bytes with chaos applied per chunk.
func (p *Proxy) copy(dst, src net.Conn, counter *atomic.Int64) {
	buf := make([]byte, 4096)
	for {
		if p.partition.Load() {
			p.severed.Add(1)
			return
		}
		src.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := src.Read(buf)
		if n > 0 {
			if p.roll() < p.cfg.SeverRate {
				p.severed.Add(1)
				return
			}
			if p.roll() < p.cfg.DropRate {
				// A hole in a TLS stream is not recoverable, so a drop shows up
				// as a severed connection. That is what loss actually looks
				// like above the transport, and it is what the node must
				// survive.
				p.severed.Add(1)
				return
			}
			p.delay(n)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			counter.Add(int64(n))
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
	}
}

func (p *Proxy) delay(n int) {
	d := p.cfg.Latency
	if p.cfg.Jitter > 0 {
		d += time.Duration(p.rollInt(int64(p.cfg.Jitter)))
	}
	if p.cfg.BandwidthBytesPerSecond > 0 {
		d += time.Duration(float64(n) / float64(p.cfg.BandwidthBytesPerSecond) * float64(time.Second))
	}
	if d > 0 {
		time.Sleep(d)
	}
}

func (p *Proxy) roll() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Float64()
}

func (p *Proxy) rollInt(n int64) int64 {
	if n <= 0 {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Int63n(n)
}
