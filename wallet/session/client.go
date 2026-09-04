// Package session is the one path from a wallet to a node.
//
// Every interface Zycord ships — `zcd wallet`, `zcd ui`, and the desktop
// application — builds, checks and submits certificates through this package
// and through nothing else. That is a structural claim rather than a
// convention: a graphical front end cannot be more permissive than the CLI,
// because there is no second code path on which it could be. The
// docs/WALLET.md rules encoded in wallet/policy.go therefore apply to all
// three by construction, not by whoever wrote the third one remembering.
//
// The trust boundary is the one wallet/policy.go describes. A wallet that is
// not itself a full node believes what a node tells it; what this package can
// do — and does — is refuse to accept a node's word on which network it is —
// the chain id it claims is checked against the caller's own assertion — and,
// when a second independent node is named, refuse to proceed when the two
// disagree.
package session

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"zycord/core/types"
	"zycord/core/u256"
)

// requestTimeout bounds every call to a node.
//
// A wallet blocked forever on a node that accepted the connection and then
// said nothing is a CLI that appears to hang and a window that appears to
// freeze. The number is generous — a node under load answers a balance in
// milliseconds — because the failure this bounds is a dead peer, not a slow
// one.
const requestTimeout = 30 * time.Second

// maxResponse bounds what a node can make a wallet buffer. Every response on
// the read surface is small; a block is not on this surface at all.
const maxResponse = 1 << 20

// Client is one node's RPC surface, as a wallet uses it.
//
// It holds no key and makes no decision. Everything policy-shaped lives on
// Session, so that a caller cannot get at the node without also getting the
// checks.
type Client struct {
	base string
	http *http.Client
}

// NewClient returns a client for a node's RPC base URL.
func NewClient(base string) *Client {
	return &Client{
		base: strings.TrimRight(base, "/"),
		http: &http.Client{Timeout: requestTimeout},
	}
}

// URL is the endpoint this client was pointed at. Error messages and
// confirmation prompts name it, because "a node disagreed" is not actionable
// and "this node disagreed" is.
func (c *Client) URL() string { return c.base }

// Status is /status: who this node thinks it is, and where its tip is.
type Status struct {
	Network   string `json:"network"`
	ChainID   uint64 `json:"chain_id"`
	NetworkID string `json:"network_id"`
	Height    uint64 `json:"height"`
	Tip       string `json:"tip"`
	StateRoot string `json:"state_root"`
	Time      uint64 `json:"time"`
	// MinChainWorkHeight is the launch checkpoint floor this node enforces;
	// a tip below it is a node that has not finished syncing, whatever else
	// it reports. Zero from a node built without checkpoints.
	MinChainWorkHeight uint64 `json:"min_chain_work_height"`
}

// Head is /head: the tip header's own fields.
type Head struct {
	Height   uint64 `json:"height"`
	ID       string `json:"id"`
	Parent   string `json:"parent"`
	Time     uint64 `json:"time"`
	CertRoot string `json:"cert_root"`
	Target   string `json:"target"`
}

// Fees is /fees: what a block costs now, and how much currently fits.
//
// The ceilings are here rather than in the parameter set because §8.1 made
// them functions of T, which is consensus state. A front end that displayed a
// genesis ceiling as "the limit" would be wrong silently, so this type has no
// field for one.
type Fees struct {
	SeqBase          u256.U256
	ParBase          u256.U256
	SkipFee          u256.U256
	SeqGasTarget     uint64
	SeqGasLimit      uint64
	ParGasLimit      uint64
	BlockByteLimit   uint64
	MaxCertsPerBlock uint64
}

// Network is /network: connection shape, including the listening share the
// networking decision's reopen condition is written against.
type Network struct {
	Enabled     bool  `json:"enabled"`
	Peers       int   `json:"peers"`
	KnownPeers  int   `json:"known_peers"`
	BannedPeers int   `json:"banned_peers"`
	Listening   bool  `json:"listening"`
	Inbound     int   `json:"inbound"`
	Outbound    int   `json:"outbound"`
	Reachable   bool  `json:"reachable"`
	MinScore    int64 `json:"min_score"`
}

// Balance is /balance for one address: what it holds, and whether its
// authority is burned.
type Balance struct {
	Value u256.U256
	Spent bool
}

// Status asks the node who it is.
func (c *Client) Status() (*Status, error) {
	var s Status
	if err := c.get("/status", &s); err != nil {
		return nil, fmt.Errorf("cannot reach a node at %s: %w", c.base, err)
	}
	return &s, nil
}

// Head asks the node for its tip header.
func (c *Client) Head() (*Head, error) {
	var h Head
	if err := c.get("/head", &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// Fees asks the node what a block costs and how much fits.
func (c *Client) Fees() (*Fees, error) {
	var raw struct {
		Seq              string `json:"seq_base_fee"`
		Par              string `json:"par_base_fee"`
		Skip             string `json:"skip_fee"`
		SeqGasTarget     uint64 `json:"seq_gas_target"`
		SeqGasLimit      uint64 `json:"seq_gas_limit"`
		ParGasLimit      uint64 `json:"par_gas_limit"`
		BlockByteLimit   uint64 `json:"block_byte_limit"`
		MaxCertsPerBlock uint64 `json:"max_certs_per_block"`
	}
	if err := c.get("/fees", &raw); err != nil {
		return nil, err
	}
	seq, err := u256.FromDecimal(raw.Seq)
	if err != nil {
		return nil, err
	}
	par, err := u256.FromDecimal(raw.Par)
	if err != nil {
		return nil, err
	}
	// A node built before /fees carried skip_fee, or a test double that only
	// serves the two base fees, leaves this empty. It is display-only, so an
	// absent value reads as zero rather than failing the call the wallet
	// actually needed.
	skip := u256.Zero
	if raw.Skip != "" {
		if skip, err = u256.FromDecimal(raw.Skip); err != nil {
			return nil, err
		}
	}
	return &Fees{
		SeqBase:          seq,
		ParBase:          par,
		SkipFee:          skip,
		SeqGasTarget:     raw.SeqGasTarget,
		SeqGasLimit:      raw.SeqGasLimit,
		ParGasLimit:      raw.ParGasLimit,
		BlockByteLimit:   raw.BlockByteLimit,
		MaxCertsPerBlock: raw.MaxCertsPerBlock,
	}, nil
}

// Network asks the node about its connections. A node built without p2p
// answers {"enabled": false} rather than failing.
func (c *Client) Network() (*Network, error) {
	var n Network
	if err := c.get("/network", &n); err != nil {
		return nil, err
	}
	return &n, nil
}

// Balance asks the node what one address holds on the native asset.
func (c *Client) Balance(a types.Address) (Balance, error) {
	var raw struct {
		Balance string `json:"balance"`
		Spent   bool   `json:"spent"`
	}
	if err := c.get("/balance?addr="+HexAddr(a), &raw); err != nil {
		return Balance{}, err
	}
	v, err := u256.FromDecimal(raw.Balance)
	if err != nil {
		return Balance{}, err
	}
	return Balance{Value: v, Spent: raw.Spent}, nil
}

// Submit hands a signed certificate to the node. The node grants it nothing:
// it is validated exactly as one arriving from a stranger would be.
func (c *Client) Submit(cert *types.Certificate) error {
	body := "0x" + hex.EncodeToString(cert.MarshalSSZ())
	resp, err := c.http.Post(c.base+"/submit", "text/plain", bytes.NewReader([]byte(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("node refused the certificate: %s", strings.TrimSpace(string(raw)))
	}
	return nil
}

func (c *Client) get(path string, out any) error {
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("node returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

// HexAddr renders an address the way every Zycord interface prints one.
func HexAddr(a types.Address) string { return "0x" + hex.EncodeToString(a[:]) }

// ParseAddress accepts a 32-byte hex address with or without the 0x prefix.
func ParseAddress(s string) (types.Address, error) {
	var a types.Address
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X"))
	if err != nil || len(raw) != 32 {
		return a, fmt.Errorf("%q is not a 32-byte hex address", s)
	}
	copy(a[:], raw)
	return a, nil
}

// SameEndpoint compares two RPC base URLs textually, after trimming a
// trailing slash. It catches the copy-paste, which is the realistic mistake;
// it cannot catch two names that resolve to one node, and nothing short of
// comparing node identities could.
func SameEndpoint(a, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}
