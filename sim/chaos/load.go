package chaos

// Billing-law load for the soak (R6-G2).
//
// The soak used to mine empty blocks. It converged beautifully while never once
// doing the thing the protocol exists to do — so the billing law, the fee
// markets, the mempool and the skip/drop machinery were exercised by unit tests
// and by `sim/`, and by the run that is meant to be the launch credential not at
// all. `blocks_rejected == 0` was a true statement about a network that had
// never been asked the question.
//
// This drives real certificates through real nodes over hostile sockets, so that
// the fold's economic rules meet a scheduler nobody controls, under partition
// and kill-9, rather than only a golden vector.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/wallet"
)

// Submission records one certificate the driver sent.
type Submission struct {
	ID       types.Hash
	Signer   types.Address
	Seq      uint64
	Accepted bool
}

// Driver submits certificates to a set of nodes.
type Driver struct {
	Params *params.Params
	// Endpoints are RPC addresses; submissions are spread across them so that a
	// certificate's entry point is not always the node that mines it.
	Endpoints []string

	mu          sync.Mutex
	submissions []Submission
	seq         map[types.Address]uint64
	accepted    int
	refused     map[string]int
}

// NewDriver returns a load driver.
func NewDriver(p *params.Params, endpoints []string) *Driver {
	return &Driver{
		Params:    p,
		Endpoints: endpoints,
		seq:       map[types.Address]uint64{},
		refused:   map[string]int{},
	}
}

// Transfer builds and submits one transfer, returning what happened.
//
// A refusal is not a failure of the run. Under this much chaos a node's mempool
// may be full, its tip may have moved so the deposit no longer covers, or the
// node may be dead — all ordinary, all recorded rather than swallowed, because
// the *ratio* of refusals is the signal that a run drove no real load.
func (d *Driver) Transfer(from *wallet.Key, to types.Address, amount u256.U256,
	endpoint string) (Submission, error) {
	d.mu.Lock()
	addr := from.Persistent()
	seq := d.seq[addr]
	d.seq[addr] = seq + 1
	d.mu.Unlock()

	seqBase, parBase, height, err := d.fees(endpoint)
	if err != nil {
		return Submission{}, err
	}

	b := &wallet.Builder{
		Params:  d.Params,
		Program: wallet.Tip(types.NativeAsset, addr, to, amount),
		Seq:     seq,
		TTL:     height + d.Params.TTLMax/2,
		Deposit: wallet.SelfDeposit(addr, addr),
		FeeBid:  wallet.BidWithHeadroom(seqBase, parBase, u256.FromUint64(100), u256.FromUint64(5), 16),
		Signers: []*wallet.Key{from},
	}
	cert, err := b.Build()
	if err != nil {
		return Submission{}, err
	}

	sub := Submission{ID: cert.ID(), Signer: addr, Seq: seq}
	sub.Accepted, err = d.submit(endpoint, cert)
	if err != nil {
		d.note(err.Error())
	}

	d.mu.Lock()
	d.submissions = append(d.submissions, sub)
	if sub.Accepted {
		d.accepted++
	}
	d.mu.Unlock()
	return sub, nil
}

func (d *Driver) note(reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(reason) > 60 {
		reason = reason[:60]
	}
	d.refused[reason]++
}

// Submissions returns everything sent, and how many were accepted.
func (d *Driver) Submissions() ([]Submission, int, map[string]int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Submission, len(d.submissions))
	copy(out, d.submissions)
	reasons := make(map[string]int, len(d.refused))
	for k, v := range d.refused {
		reasons[k] = v
	}
	return out, d.accepted, reasons
}

// ResetSeq drops the recorded sequence for a signer.
//
// Needed after a reorg strands a chain of certificates: the pool re-screens
// against the new tip and a gap in Seq blocks everything above it, so the driver
// re-reads the signer's position rather than counting blindly upward.
func (d *Driver) ResetSeq(addr types.Address, next uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seq[addr] = next
}

func (d *Driver) fees(endpoint string) (seqBase, parBase u256.U256, height uint64, err error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + endpoint + "/fees")
	if err != nil {
		return seqBase, parBase, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return seqBase, parBase, 0, err
	}
	var fees map[string]any
	if err := json.Unmarshal(body, &fees); err != nil {
		return seqBase, parBase, 0, err
	}
	seqBase, err = parseDrops(fees["seq_base_fee"])
	if err != nil {
		return seqBase, parBase, 0, err
	}
	parBase, err = parseDrops(fees["par_base_fee"])
	if err != nil {
		return seqBase, parBase, 0, err
	}

	resp2, err := client.Get("http://" + endpoint + "/status")
	if err != nil {
		return seqBase, parBase, 0, err
	}
	defer resp2.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp2.Body, 1<<16))
	if err != nil {
		return seqBase, parBase, 0, err
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		return seqBase, parBase, 0, err
	}
	h, _ := st["height"].(float64)
	return seqBase, parBase, uint64(h), nil
}

func (d *Driver) submit(endpoint string, cert *types.Certificate) (bool, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	payload := hex.EncodeToString(cert.MarshalSSZ())
	resp, err := client.Post("http://"+endpoint+"/submit", "text/plain",
		bytes.NewReader([]byte(payload)))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("submit: %s", bytes.TrimSpace(body))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return false, err
	}
	ok, _ := out["accepted"].(bool)
	return ok, nil
}

func parseDrops(v any) (u256.U256, error) {
	s, ok := v.(string)
	if !ok {
		return u256.Zero, fmt.Errorf("fee is not a decimal string: %v", v)
	}
	return u256.FromDecimal(s)
}
