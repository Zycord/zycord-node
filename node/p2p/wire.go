// Package p2p is the network layer: transport, handshake, gossip and peer
// management.
//
// The decision to write this rather than import libp2p is in
// docs/decisions/networking.md, with its reopen conditions. The short version:
// 141 modules for six problems, a third of which serve needs Zycord does not
// have, and the hardest part — deciding whether a message is worth forwarding —
// is already solved by the consensus design, because a certificate is checkable
// from its bytes with no state at all.
//
// The security-critical part is *not* written here. Transport encryption and
// authentication are standard-library TLS 1.3 with Ed25519 peer identities; no
// custom handshake state machine, no custom AEAD framing, no custom key
// schedule.
package p2p

import (
	"encoding/binary"
	"errors"
	"io"

	"zycord/core/types"
)

// ProtocolVersion is the wire protocol version. A peer speaking another version
// is disconnected at the handshake rather than half-understood.
const ProtocolVersion uint32 = 1

// MessageKind tags a wire message.
type MessageKind uint8

// The message set. It is deliberately small: two gossip topics and a
// request/response pair, which is everything §13 of the architecture spec
// describes.
const (
	// KindHello is the handshake. It carries the network id — the genesis id,
	// which commits to every consensus parameter (R3-1) — so that nodes
	// configured differently disconnect instead of diverging later.
	KindHello MessageKind = 1
	// KindCertificate gossips a full certificate body.
	KindCertificate MessageKind = 2
	// KindBlockAnnounce gossips a header plus the ordered certificate-exemplar
	// list -- not ids; see BlockAnnounce below. The list exists to
	// recompute the header's CertRoot, and CertRoot is a root over exemplars.
	// Hash-first: bodies are fetched only after the header's work is verified.
	KindBlockAnnounce MessageKind = 3
	// KindGetBlock requests one chunk of a block by id. A block travels as
	// ceil(size/BlockChunkBytes) chunks, each its own request/response pair, so
	// the frame limit bounds a *message* and never a *block* — the consensus
	// byte ceiling can be re-pinned at an era boundary without touching this
	// layer. Requesting chunk 0 is how a fetch starts; the first response
	// carries the total.
	KindGetBlock MessageKind = 4
	// KindBlock answers KindGetBlock with one chunk.
	KindBlock MessageKind = 5
	// KindGetHeaders requests headers from a height.
	KindGetHeaders MessageKind = 6
	// KindHeaders answers KindGetHeaders.
	KindHeaders MessageKind = 7
	// KindGetPeers asks for known peer addresses.
	KindGetPeers MessageKind = 8
	// KindPeers answers KindGetPeers.
	KindPeers MessageKind = 9
	kindMax               = KindPeers
)

// String renders a message kind for logs and peer-score reasons.
func (k MessageKind) String() string {
	switch k {
	case KindHello:
		return "hello"
	case KindCertificate:
		return "certificate"
	case KindBlockAnnounce:
		return "block-announce"
	case KindGetBlock:
		return "get-block"
	case KindBlock:
		return "block"
	case KindGetHeaders:
		return "get-headers"
	case KindHeaders:
		return "headers"
	case KindGetPeers:
		return "get-peers"
	case KindPeers:
		return "peers"
	default:
		return "unknown"
	}
}

// Limits bound what a peer can make this node allocate. Every one of them is a
// defence against a peer that is not merely faulty but hostile.
const (
	// MaxMessageBytes caps a single framed message.
	MaxMessageBytes = 8 << 20
	// BlockChunkBytes is the data carried per block chunk: under
	// MaxMessageBytes, since the frame limit is an allocation defence rather
	// than the unit of block transfer, and over `block_byte_limit_genesis`, so
	// that a block at the genesis ceiling is one chunk and the launch network
	// pays no extra round trip.
	//
	// Chunks are fetched one round trip each, so this size is also a
	// propagation parameter: a block of N chunks costs N sequential RTTs, and
	// slower propagation raises the competing-header rate the health gate
	// reads (whitepaper §8.1). At the current byte capacity that is at most
	// two round trips. It does not stay negligible under a large capacity
	// re-pin, and pipelining the requests — which needs a serve loop that can
	// answer one message with several — is the work that must precede one.
	BlockChunkBytes = 4 << 20
	// MaxBlockChunks caps the chunk count a block transfer may claim, and with
	// it the reassembly a peer can ask this node to hold. The product
	// MaxBlockChunks × BlockChunkBytes is the transport's own ceiling on a
	// block, and the consensus byte capacity must fit under it —
	// TestBlockByteCapacityFitsChunkedTransfer pins that pair together.
	//
	// It is sized against BlockByteCapacity and not chosen for headroom
	// (ARCHITECTURE §20's M5 gate). A capacity block is two chunks, so
	// four is the pair's own slack and nothing above it is reachable: the
	// inherited 256 admitted a claimed transfer of 1 GiB, 134.2× a block
	// consensus can ever call valid, and a claim the block rules cannot
	// produce is not headroom — it is state a peer can still make this node
	// account for. The multiple is 1,073,741,824 against BlockByteCapacity's
	// 8,000,000 bytes, not against the 8 MiB frame limit — that denominator
	// gives 128 and is the arithmetic that put a slipped figure here once.
	// MaxReassemblyBytes bounds the bytes; this bounds the claim. An era
	// re-pin of the capacity raises this in the same release, which is what
	// the test's upper bound is there to force.
	MaxBlockChunks = 4
	// MaxAnnouncedCerts caps the id list in a block announcement, independently
	// of the block ceiling, so a malformed announcement cannot make a receiver
	// allocate before it has checked anything.
	MaxAnnouncedCerts = 100_000
	// MaxHeadersPerResponse caps a headers answer.
	MaxHeadersPerResponse = 512
	// MaxPeersPerResponse caps a peer-exchange answer.
	MaxPeersPerResponse = 64
	// MaxAddrLen caps an advertised address string.
	MaxAddrLen = 108
)

// Errors returned by the codec.
var (
	ErrMessageTooLarge = errors.New("p2p: message exceeds the frame limit")
	ErrMalformed       = errors.New("p2p: malformed message")
	ErrUnknownKind     = errors.New("p2p: unknown message kind")
)

// Hello is the handshake message.
type Hello struct {
	Protocol uint32
	// NetworkID is the genesis block id. Two nodes that disagree about any
	// consensus parameter derive different ids and must not talk (R3-1, M2-G6).
	NetworkID types.Hash
	// Height and Work advertise the sender's tip, so a receiver knows whether
	// it has anything to learn before asking.
	Height uint64
	Work   types.Hash
	// ListenAddr is where this node accepts connections, or empty if it does
	// not. It is what peer exchange propagates.
	ListenAddr string
}

// BlockAnnounce is hash-first relay: a header plus the ordered certificate
// exemplar hashes.
//
// The receiver verifies the header's proof of work *before* fetching any body
// (R1-M3). Ghost announcements therefore cost the announcer real work.
//
// The list is exemplar hashes and not certificate ids, because it exists for
// exactly one job — recomputing the header's CertRoot from the announcement
// alone — and CertRoot is a root over exemplars. The wire bytes are
// unchanged by that: the same 32-byte digest over the same preimage occupies
// the same slot it always did, and only its name moved. Nothing else reads
// this list; a receiver wanting the block's *authorizations* has to fetch the
// bodies, which is what it does anyway.
type BlockAnnounce struct {
	Header        types.Header
	CertExemplars []types.Hash
}

// GetHeaders requests up to Count headers starting at From.
type GetHeaders struct {
	From  uint64
	Count uint32
}

// Frame writes a length-prefixed message.
//
// The length prefix is checked against MaxMessageBytes before any allocation,
// so a peer cannot make this node reserve memory by claiming a large message.
func Frame(w io.Writer, kind MessageKind, payload []byte) error {
	if len(payload) > MaxMessageBytes {
		return ErrMessageTooLarge
	}
	var header [5]byte
	binary.LittleEndian.PutUint32(header[:4], uint32(len(payload)))
	header[4] = byte(kind)
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed message.
func ReadFrame(r io.Reader) (MessageKind, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.LittleEndian.Uint32(header[:4])
	if size > MaxMessageBytes {
		return 0, nil, ErrMessageTooLarge
	}
	kind := MessageKind(header[4])
	if kind == 0 || kind > kindMax {
		return 0, nil, ErrUnknownKind
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return kind, payload, nil
}

// ---------------------------------------------------------------------------
// Encoding
//
// Fixed-width and length-prefixed throughout, decoded with the same
// canonical-form discipline as consensus objects: a decoder that accepts two
// byte strings for one value is a decoder with an attack in it, even outside
// consensus.
// ---------------------------------------------------------------------------

// MarshalHello encodes a handshake.
func (h Hello) MarshalHello() []byte {
	out := make([]byte, 0, 4+32+8+32+4+len(h.ListenAddr))
	out = binary.LittleEndian.AppendUint32(out, h.Protocol)
	out = append(out, h.NetworkID[:]...)
	out = binary.LittleEndian.AppendUint64(out, h.Height)
	out = append(out, h.Work[:]...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(h.ListenAddr)))
	return append(out, h.ListenAddr...)
}

// UnmarshalHello decodes a handshake.
func UnmarshalHello(b []byte) (Hello, error) {
	var h Hello
	if len(b) < 4+32+8+32+4 {
		return h, ErrMalformed
	}
	h.Protocol = binary.LittleEndian.Uint32(b[:4])
	copy(h.NetworkID[:], b[4:36])
	h.Height = binary.LittleEndian.Uint64(b[36:44])
	copy(h.Work[:], b[44:76])
	n := binary.LittleEndian.Uint32(b[76:80])
	if n > MaxAddrLen || int(n) != len(b)-80 {
		return h, ErrMalformed
	}
	h.ListenAddr = string(b[80:])
	return h, nil
}

// MarshalAnnounce encodes a block announcement.
func (a BlockAnnounce) MarshalAnnounce() []byte {
	out := a.Header.MarshalSSZ()
	out = binary.LittleEndian.AppendUint32(out, uint32(len(a.CertExemplars)))
	for _, id := range a.CertExemplars {
		out = append(out, id[:]...)
	}
	return out
}

// UnmarshalAnnounce decodes a block announcement.
func UnmarshalAnnounce(b []byte) (BlockAnnounce, error) {
	var a BlockAnnounce
	if len(b) < types.HeaderSize+4 {
		return a, ErrMalformed
	}
	hdr, err := types.UnmarshalHeader(b[:types.HeaderSize])
	if err != nil {
		return a, err
	}
	a.Header = *hdr

	rest := b[types.HeaderSize:]
	n := binary.LittleEndian.Uint32(rest[:4])
	if n > MaxAnnouncedCerts {
		return a, ErrMessageTooLarge
	}
	rest = rest[4:]
	if len(rest) != int(n)*32 {
		return a, ErrMalformed
	}
	a.CertExemplars = make([]types.Hash, n)
	for i := range a.CertExemplars {
		copy(a.CertExemplars[i][:], rest[i*32:(i+1)*32])
	}
	return a, nil
}

// MarshalGetHeaders encodes a header request.
func (g GetHeaders) MarshalGetHeaders() []byte {
	out := make([]byte, 12)
	binary.LittleEndian.PutUint64(out[:8], g.From)
	binary.LittleEndian.PutUint32(out[8:], g.Count)
	return out
}

// UnmarshalGetHeaders decodes a header request, clamping the count so a peer
// cannot ask for an unbounded response.
func UnmarshalGetHeaders(b []byte) (GetHeaders, error) {
	var g GetHeaders
	if len(b) != 12 {
		return g, ErrMalformed
	}
	g.From = binary.LittleEndian.Uint64(b[:8])
	g.Count = binary.LittleEndian.Uint32(b[8:])
	if g.Count > MaxHeadersPerResponse {
		g.Count = MaxHeadersPerResponse
	}
	return g, nil
}

// MarshalHeaders encodes a headers response.
func MarshalHeaders(headers []types.Header) []byte {
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(headers)))
	for _, h := range headers {
		out = append(out, h.MarshalSSZ()...)
	}
	return out
}

// UnmarshalHeaders decodes a headers response.
func UnmarshalHeaders(b []byte) ([]types.Header, error) {
	if len(b) < 4 {
		return nil, ErrMalformed
	}
	n := binary.LittleEndian.Uint32(b[:4])
	if n > MaxHeadersPerResponse {
		return nil, ErrMessageTooLarge
	}
	rest := b[4:]
	if len(rest) != int(n)*types.HeaderSize {
		return nil, ErrMalformed
	}
	out := make([]types.Header, n)
	for i := range out {
		h, err := types.UnmarshalHeader(rest[i*types.HeaderSize : (i+1)*types.HeaderSize])
		if err != nil {
			return nil, err
		}
		out[i] = *h
	}
	return out, nil
}

// MarshalPeers encodes a peer-exchange response.
func MarshalPeers(addrs []string) []byte {
	if len(addrs) > MaxPeersPerResponse {
		addrs = addrs[:MaxPeersPerResponse]
	}
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(addrs)))
	for _, a := range addrs {
		if len(a) > MaxAddrLen {
			a = a[:MaxAddrLen]
		}
		out = binary.LittleEndian.AppendUint32(out, uint32(len(a)))
		out = append(out, a...)
	}
	return out
}

// UnmarshalPeers decodes a peer-exchange response.
func UnmarshalPeers(b []byte) ([]string, error) {
	if len(b) < 4 {
		return nil, ErrMalformed
	}
	n := binary.LittleEndian.Uint32(b[:4])
	if n > MaxPeersPerResponse {
		return nil, ErrMessageTooLarge
	}
	rest := b[4:]
	out := make([]string, 0, n)
	for i := uint32(0); i < n; i++ {
		if len(rest) < 4 {
			return nil, ErrMalformed
		}
		size := binary.LittleEndian.Uint32(rest[:4])
		if size > MaxAddrLen || int(size) > len(rest)-4 {
			return nil, ErrMalformed
		}
		out = append(out, string(rest[4:4+size]))
		rest = rest[4+size:]
	}
	if len(rest) != 0 {
		return nil, ErrMalformed
	}
	return out, nil
}

// GetBlock requests one chunk of a block.
type GetBlock struct {
	ID    types.Hash
	Chunk uint32
}

// MarshalGetBlock encodes a block-chunk request.
func (g GetBlock) MarshalGetBlock() []byte {
	out := make([]byte, 36)
	copy(out[:32], g.ID[:])
	binary.LittleEndian.PutUint32(out[32:], g.Chunk)
	return out
}

// UnmarshalGetBlock decodes a block-chunk request.
func UnmarshalGetBlock(b []byte) (GetBlock, error) {
	var g GetBlock
	if len(b) != 36 {
		return g, ErrMalformed
	}
	copy(g.ID[:], b[:32])
	g.Chunk = binary.LittleEndian.Uint32(b[32:])
	if g.Chunk >= MaxBlockChunks {
		return g, ErrMalformed
	}
	return g, nil
}

// BlockChunk is one chunk of a block body: the id it belongs to, its position,
// the total the transfer will take, and the bytes.
type BlockChunk struct {
	ID    types.Hash
	Chunk uint32
	Total uint32
	Data  []byte
}

// MarshalBlockChunk encodes a block chunk.
func (c BlockChunk) MarshalBlockChunk() []byte {
	out := make([]byte, 0, 40+len(c.Data))
	out = append(out, c.ID[:]...)
	out = binary.LittleEndian.AppendUint32(out, c.Chunk)
	out = binary.LittleEndian.AppendUint32(out, c.Total)
	return append(out, c.Data...)
}

// UnmarshalBlockChunk decodes a block chunk. Every bound is checked before the
// caller sees the value: totals beyond MaxBlockChunks, chunks at or past their
// own total, and data over BlockChunkBytes are malformed, and only the final
// chunk may run short — every earlier one carries exactly BlockChunkBytes, so
// a peer cannot stretch a transfer by sending slivers.
func UnmarshalBlockChunk(b []byte) (BlockChunk, error) {
	var c BlockChunk
	if len(b) < 40 {
		return c, ErrMalformed
	}
	copy(c.ID[:], b[:32])
	c.Chunk = binary.LittleEndian.Uint32(b[32:36])
	c.Total = binary.LittleEndian.Uint32(b[36:40])
	c.Data = b[40:]
	if c.Total == 0 || c.Total > MaxBlockChunks || c.Chunk >= c.Total {
		return c, ErrMalformed
	}
	if len(c.Data) > BlockChunkBytes {
		return c, ErrMalformed
	}
	if c.Chunk < c.Total-1 && len(c.Data) != BlockChunkBytes {
		return c, ErrMalformed
	}
	if c.Chunk == c.Total-1 && len(c.Data) == 0 {
		return c, ErrMalformed
	}
	return c, nil
}

// ChunkCount is the number of chunks a body of n bytes travels as.
func ChunkCount(n int) int { return (n + BlockChunkBytes - 1) / BlockChunkBytes }

// ChunkOf slices chunk i out of a marshalled body. i must be in range.
func ChunkOf(raw []byte, i int) []byte {
	end := (i + 1) * BlockChunkBytes
	if end > len(raw) {
		end = len(raw)
	}
	return raw[i*BlockChunkBytes : end]
}
