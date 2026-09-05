package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

// Key files.
//
// A seed on disk in the clear is a seed in every backup, every snapshot and
// every screenshot. Key files are therefore always encrypted, and there is no
// flag to turn that off (M1-G6).
//
// The format is deliberately dull and fully specified in the file itself, so
// that a user locked out of this binary can recover with any language's
// standard library: Argon2id to stretch the passphrase, AES-256-GCM to seal the
// seed, both with their parameters stored alongside.

// keyFileVersion is the on-disk format version.
const keyFileVersion = 1

// Argon2id parameters. Chosen to cost roughly a quarter-second on a laptop of
// the kind the whole project assumes people are mining on.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// maxArgonMemoryKiB caps the Argon2 memory cost accepted from a key-file
// envelope. golang.org/x/crypto/argon2 takes memory as an unchecked uint32, so
// a hostile file can name up to 4 TiB and make the derivation try to allocate
// it. The default this wallet writes is argonMemory (64 MiB); a 2 GiB ceiling
// keeps 32x of headroom for a file written with a deliberately stronger setting
// while still naming a figure a real machine can allocate, and it refuses the
// 4 TiB an unchecked uint32 allows by a factor of ~2048.
const maxArgonMemoryKiB = 2 * 1024 * 1024 // 2 GiB, in KiB

// validateArgon2Params refuses KDF parameters that cannot be handed to
// argon2.IDKey safely. The library panics on time == 0 ("number of rounds too
// small") and threads == 0 ("parallelism degree too low"), and it will try to
// allocate whatever memory it is given.
//
// These three fields ride in the key-file envelope, which on a restore-backup /
// cloud-sync / support-channel path is attacker-controlled, so they are refused
// with an error before they ever reach argon2.IDKey — recovering from the panic
// would only turn a bad file that must be *refused* into one quietly accepted.
// LoadKeyFile and InspectKeyFile share this check so the inspector keeps its
// promise that a bad file is an error at the moment of picking.
func validateArgon2Params(time, memory uint32, threads uint8) error {
	switch {
	case threads < 1:
		return fmt.Errorf("wallet: key file argon2_threads is %d; must be at least 1", threads)
	case time < 1:
		return fmt.Errorf("wallet: key file argon2_time is %d; must be at least 1", time)
	case memory > maxArgonMemoryKiB:
		return fmt.Errorf("wallet: key file argon2_memory_kib is %d KiB; exceeds this build's ceiling of %d KiB (2 GiB)", memory, maxArgonMemoryKiB)
	}
	return nil
}

// ErrBadPassphrase reports a passphrase that does not open a key file. It is
// deliberately indistinguishable from a corrupted file: telling an attacker
// which of the two they have is telling them whether to keep guessing.
var ErrBadPassphrase = errors.New("wallet: wrong passphrase or damaged key file")

type keyFile struct {
	Version int    `json:"version"`
	KDF     string `json:"kdf"`
	Time    uint32 `json:"argon2_time"`
	Memory  uint32 `json:"argon2_memory_kib"`
	Threads uint8  `json:"argon2_threads"`
	Salt    string `json:"salt"`
	Cipher  string `json:"cipher"`
	Nonce   string `json:"nonce"`
	Sealed  string `json:"sealed"`
	// Addresses are stored for convenience only; they are derivable from the
	// seed and are never trusted on load.
	Persistent string `json:"persistent_address"`
	OneShot    string `json:"one_shot_address"`
}

// InspectKeyFile reports whether a path holds a key file this build can open,
// without a passphrase and without deriving anything.
//
// It exists for the interfaces that let a person *choose* a file — the desktop
// wallet's file dialog — so that picking the wrong one is an error at the
// moment of picking rather than an indistinguishable "wrong passphrase or
// damaged key file" after a quarter-second of Argon2id.
//
// It deliberately reports nothing about the contents. The addresses stored in
// the envelope are a convenience and are never trusted on load, so showing
// them before an unlock would be showing an unauthenticated claim.
func InspectKeyFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return fmt.Errorf("wallet: %s is not a key file: %w", path, err)
	}
	if kf.Version != keyFileVersion {
		return fmt.Errorf("wallet: %s is key file version %d; this build reads version %d", path, kf.Version, keyFileVersion)
	}
	if kf.KDF == "" || kf.Sealed == "" {
		return fmt.Errorf("wallet: %s is missing the fields a key file has", path)
	}
	if err := validateArgon2Params(kf.Time, kf.Memory, kf.Threads); err != nil {
		return fmt.Errorf("wallet: %s: %w", path, err)
	}
	return nil
}

// SaveKeyFile writes an encrypted key file with 0600 permissions.
func SaveKeyFile(path string, k *Key, passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("wallet: a passphrase is required; there is no unencrypted key format")
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := newAEAD(passphrase, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	seed := k.Seed()
	sealed := aead.Seal(nil, nonce, seed, nil)
	zero(seed)

	persistent, oneShot := k.Persistent(), k.OneShot()
	body, err := json.MarshalIndent(keyFile{
		Version:    keyFileVersion,
		KDF:        "argon2id",
		Time:       argonTime,
		Memory:     argonMemory,
		Threads:    argonThreads,
		Salt:       hex.EncodeToString(salt),
		Cipher:     "aes-256-gcm",
		Nonce:      hex.EncodeToString(nonce),
		Sealed:     hex.EncodeToString(sealed),
		Persistent: "0x" + hex.EncodeToString(persistent[:]),
		OneShot:    "0x" + hex.EncodeToString(oneShot[:]),
	}, "", "  ")
	if err != nil {
		return err
	}

	// Never silently overwrite a key file, and never leave a torn one behind
	// either: write durably to a temp file and link it into place, refusing if
	// the destination already exists. See writeFileNoClobber.
	return writeFileNoClobber(path, append(body, '\n'))
}

// LoadKeyFile opens an encrypted key file.
func LoadKeyFile(path string, passphrase []byte) (*Key, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, err
	}
	if kf.Version != keyFileVersion {
		return nil, fmt.Errorf("wallet: key file version %d is not supported", kf.Version)
	}
	if kf.KDF != "argon2id" || kf.Cipher != "aes-256-gcm" {
		return nil, fmt.Errorf("wallet: key file uses %s/%s, which this build does not implement", kf.KDF, kf.Cipher)
	}
	if err := validateArgon2Params(kf.Time, kf.Memory, kf.Threads); err != nil {
		return nil, err
	}

	salt, err := hex.DecodeString(kf.Salt)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	nonce, err := hex.DecodeString(kf.Nonce)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	sealed, err := hex.DecodeString(kf.Sealed)
	if err != nil {
		return nil, ErrBadPassphrase
	}

	aead, err := newAEADWith(passphrase, salt, kf.Time, kf.Memory, kf.Threads)
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	defer zero(seed)
	return KeyFromSeed(seed)
}

func newAEAD(passphrase, salt []byte) (cipher.AEAD, error) {
	return newAEADWith(passphrase, salt, argonTime, argonMemory, argonThreads)
}

func newAEADWith(passphrase, salt []byte, time, memory uint32, threads uint8) (cipher.AEAD, error) {
	key := argon2.IDKey(passphrase, salt, time, memory, threads, argonKeyLen)
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
