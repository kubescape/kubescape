package reportcrypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	masterKeyEnvVar    = "KUBESCAPE_MASTER_KEY"
	masterKeyHexEnvVar = "KUBESCAPE_MASTER_KEY_HEX"

	// minMasterKeySize is the shortest master secret accepted. The previous
	// implementation required exactly 32 bytes and fed them to AES-256
	// unchanged, so users supplied 32 typed characters of printable ASCII —
	// well under 256 bits of entropy — as a raw key. The secret is now stretched
	// with Argon2id instead, which is what makes a human-chosen passphrase
	// viable. Widening the floor to 16 cannot break an existing configuration:
	// every previously valid key was exactly 32 bytes and is still accepted.
	minMasterKeySize = 16

	// kekPrefix opens the envelope produced by WrapDEK. It is deliberately
	// distinct from prefix so that a wrapped DEK is never mistaken for a
	// DEK-encrypted field, and so that report.go's leftover-ciphertext scan
	// (which matches on prefix) keeps meaning exactly what it meant before.
	kekPrefix = "ENC[ARGON2ID_AES256_GCM,"

	// kekVersion is the original envelope: work factors, salt, and the inner
	// ciphertext, with no associated data anywhere. Still written by the
	// deprecated WrapDEK and still read, so reports from earlier releases keep
	// opening.
	kekVersion = "v1"

	// kekVersionBound adds the per-report binding value between the salt and
	// the inner ciphertext. Every envelope written by WrapReportKey uses it.
	//
	// The version lives here rather than in the field envelope on purpose: the
	// DEK is unwrapped before any field is touched, so one version check at the
	// top of the report decides how every ciphertext in it is opened. Putting
	// it in the field envelope instead would have meant a second prefix for
	// report.go's embedded-ciphertext scan and its leftover-ciphertext
	// validator to recognise, for no extra information.
	kekVersionBound = "v2"

	kekSaltSize = 16

	// KEKAlgorithm is recorded in EncryptionMetadata.kekAlgorithm so a report
	// states how its data key is protected rather than implying bare AES.
	KEKAlgorithm = "ARGON2ID_AES256_GCM"
)

// Argon2id work factors for newly written envelopes, following the second
// recommended option of RFC 9106 (64 MiB, 3 passes, 4 lanes). That is the
// memory-constrained profile, chosen because this code also runs inside CI
// containers and in-cluster components with tight limits. The factors are
// written into every envelope, so they can be raised later without making
// already-encrypted reports undecryptable.
const (
	argon2Time      uint32 = 3
	argon2MemoryKiB uint32 = 64 * 1024
	argon2Threads   uint8  = 4
)

// Upper bounds applied to work factors read back out of an envelope. A report
// is untrusted input: without these a crafted header could request terabytes of
// memory and turn `kubescape decrypt` into a denial of service against whoever
// opens the file. The lower bounds also keep argon2.IDKey out of its panic
// range (memory < 8*threads, time < 1).
const (
	maxArgon2Time      uint32 = 16
	maxArgon2MemoryKiB uint32 = 1024 * 1024 // 1 GiB
	maxArgon2Threads   uint8  = 16
)

var (
	ErrMasterKeyNotConfigured = errors.New("master key is not configured")
	ErrMasterKeyAmbiguous     = errors.New("both " + masterKeyEnvVar + " and " + masterKeyHexEnvVar + " are set")
	ErrInvalidKEKEnvelope     = errors.New("invalid wrapped DEK envelope")
)

// ValidateMasterKey validates that a master secret is long enough to be
// stretched into a key-encryption key.
//
// This checks the secret supplied by the operator, not the AES key derived from
// it: deriveKEK always emits exactly dekSize bytes regardless of input length.
func ValidateMasterKey(masterKey []byte) error {
	if len(masterKey) < minMasterKeySize {
		return fmt.Errorf(
			"invalid master key length: got %d, want at least %d",
			len(masterKey),
			minMasterKeySize,
		)
	}

	return nil
}

// GetMasterKeyFromEnv loads and validates the master secret from the
// environment.
//
// KUBESCAPE_MASTER_KEY holds a passphrase of any length at or above
// minMasterKeySize. KUBESCAPE_MASTER_KEY_HEX holds the same secret
// hex-encoded, which is what `openssl rand -hex 32` produces and is the way to
// supply full-entropy key material without pushing raw bytes through the
// environment. Both are stretched identically; the hex form is an encoding
// choice, not a way to skip the KDF.
func GetMasterKeyFromEnv(operation string) ([]byte, error) {

	masterKey := os.Getenv(masterKeyEnvVar)
	masterKeyHex := os.Getenv(masterKeyHexEnvVar)

	if masterKey != "" && masterKeyHex != "" {
		return nil, fmt.Errorf(
			"%s cannot proceed: %w, set exactly one",
			operation,
			ErrMasterKeyAmbiguous,
		)
	}

	var keyBytes []byte

	switch {
	case masterKeyHex != "":
		decoded, err := hex.DecodeString(strings.TrimSpace(masterKeyHex))
		if err != nil {
			return nil, fmt.Errorf(
				"invalid %s configuration: value is not valid hex",
				masterKeyHexEnvVar,
			)
		}
		keyBytes = decoded

	case masterKey != "":
		keyBytes = []byte(masterKey)

	default:
		return nil, fmt.Errorf(
			"%s requires %s or %s to be configured",
			operation,
			masterKeyEnvVar,
			masterKeyHexEnvVar,
		)
	}

	if err := ValidateMasterKey(keyBytes); err != nil {
		zeroBytes(keyBytes)

		envVar := masterKeyEnvVar
		if masterKeyHex != "" {
			envVar = masterKeyHexEnvVar
		}

		return nil, fmt.Errorf("invalid %s configuration: %w", envVar, err)
	}

	return keyBytes, nil
}

// kekParams describes the Argon2id work factors and salt of one envelope.
type kekParams struct {
	time      uint32
	memoryKiB uint32
	threads   uint8
	salt      []byte
}

// newKEKParams builds the parameters for a freshly wrapped DEK, with a salt
// unique to this report so that two reports protected by the same passphrase
// never share a key-encryption key.
func newKEKParams() (kekParams, error) {
	salt := make([]byte, kekSaltSize)

	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return kekParams{}, err
	}

	return kekParams{
		time:      argon2Time,
		memoryKiB: argon2MemoryKiB,
		threads:   argon2Threads,
		salt:      salt,
	}, nil
}

// validate rejects work factors outside the supported range before they reach
// argon2.IDKey, which panics on some of them and would happily allocate on the
// rest.
func (p kekParams) validate() error {
	if p.time < 1 || p.time > maxArgon2Time {
		return fmt.Errorf(
			"%w: unsupported argon2 time cost %d",
			ErrInvalidKEKEnvelope,
			p.time,
		)
	}

	if p.threads < 1 || p.threads > maxArgon2Threads {
		return fmt.Errorf(
			"%w: unsupported argon2 parallelism %d",
			ErrInvalidKEKEnvelope,
			p.threads,
		)
	}

	if p.memoryKiB > maxArgon2MemoryKiB || p.memoryKiB < 8*uint32(p.threads) {
		return fmt.Errorf(
			"%w: unsupported argon2 memory cost %d KiB",
			ErrInvalidKEKEnvelope,
			p.memoryKiB,
		)
	}

	if len(p.salt) < kekSaltSize {
		return fmt.Errorf(
			"%w: argon2 salt is %d bytes, want at least %d",
			ErrInvalidKEKEnvelope,
			len(p.salt),
			kekSaltSize,
		)
	}

	return nil
}

// deriveKEK stretches a master secret into an AES-256 key-encryption key.
//
// The caller owns the returned key and should zero it once the wrap or unwrap
// completes.
func deriveKEK(masterKey []byte, params kekParams) ([]byte, error) {
	if err := ValidateMasterKey(masterKey); err != nil {
		return nil, err
	}

	if err := params.validate(); err != nil {
		return nil, err
	}

	return argon2.IDKey(
		masterKey,
		params.salt,
		params.time,
		params.memoryKiB,
		params.threads,
		dekSize,
	), nil
}

// formatKEKCiphertext wraps an inner ENC[AES256_GCM,...] envelope in the header
// that records how its key was derived.
//
// The inner envelope is reused verbatim rather than resealed so that the DEK is
// encrypted by exactly the same primitive as every other field in the report,
// with one implementation to audit.
// A nil binding emits the original unbound envelope, so the deprecated
// bare-DEK path keeps producing byte-identical output.
func formatKEKCiphertext(params kekParams, binding []byte, inner string) (string, error) {
	payload, err := ciphertextPayload(inner)
	if err != nil {
		return "", err
	}

	if binding == nil {
		return fmt.Sprintf(
			"%s%s,%d,%d,%d,%s,%s%s",
			kekPrefix,
			kekVersion,
			params.time,
			params.memoryKiB,
			params.threads,
			base64.StdEncoding.EncodeToString(params.salt),
			payload,
			suffix,
		), nil
	}

	return fmt.Sprintf(
		"%s%s,%d,%d,%d,%s,%s,%s%s",
		kekPrefix,
		kekVersionBound,
		params.time,
		params.memoryKiB,
		params.threads,
		base64.StdEncoding.EncodeToString(params.salt),
		base64.StdEncoding.EncodeToString(binding),
		payload,
		suffix,
	), nil
}

// parseKEKCiphertext splits an envelope into its work factors, its per-report
// binding, and the inner ENC[AES256_GCM,...] envelope that openString
// understands.
//
// The binding is nil for a v1 envelope, which is what tells the caller to open
// that report's ciphertexts with no associated data.
func parseKEKCiphertext(ciphertext string) (kekParams, []byte, string, error) {
	if !strings.HasPrefix(ciphertext, kekPrefix) ||
		!strings.HasSuffix(ciphertext, suffix) {
		return kekParams{}, nil, "", ErrInvalidKEKEnvelope
	}

	payload := strings.TrimSuffix(
		strings.TrimPrefix(ciphertext, kekPrefix),
		suffix,
	)

	// v1: version, time, memory, threads, salt, nonce, ciphertext
	// v2: version, time, memory, threads, salt, binding, nonce, ciphertext
	parts := strings.Split(payload, ",")

	var (
		binding    []byte
		nonceField string
		dataField  string
	)

	switch parts[0] {
	case kekVersion:
		if len(parts) != 7 {
			return kekParams{}, nil, "", fmt.Errorf(
				"%w: got %d fields, want 7",
				ErrInvalidKEKEnvelope,
				len(parts),
			)
		}

		nonceField, dataField = parts[5], parts[6]

	case kekVersionBound:
		if len(parts) != 8 {
			return kekParams{}, nil, "", fmt.Errorf(
				"%w: got %d fields, want 8",
				ErrInvalidKEKEnvelope,
				len(parts),
			)
		}

		decoded, err := base64.StdEncoding.DecodeString(parts[5])
		if err != nil {
			return kekParams{}, nil, "", fmt.Errorf(
				"%w: binding is not valid base64",
				ErrInvalidKEKEnvelope,
			)
		}

		// Pinned rather than range-checked: the binding is written by this
		// package alone, so any other length is a corrupt or crafted envelope,
		// not an older format.
		if len(decoded) != bindingSize {
			return kekParams{}, nil, "", fmt.Errorf(
				"%w: binding is %d bytes, want %d",
				ErrInvalidKEKEnvelope,
				len(decoded),
				bindingSize,
			)
		}

		binding = decoded
		nonceField, dataField = parts[6], parts[7]

	default:
		return kekParams{}, nil, "", fmt.Errorf(
			"%w: unsupported envelope version %q",
			ErrInvalidKEKEnvelope,
			parts[0],
		)
	}

	timeCost, err := parseUint32Field(parts[1], "argon2 time cost")
	if err != nil {
		return kekParams{}, nil, "", err
	}

	memoryCost, err := parseUint32Field(parts[2], "argon2 memory cost")
	if err != nil {
		return kekParams{}, nil, "", err
	}

	threads, err := parseUint32Field(parts[3], "argon2 parallelism")
	if err != nil {
		return kekParams{}, nil, "", err
	}
	if threads > uint32(maxArgon2Threads) {
		return kekParams{}, nil, "", fmt.Errorf(
			"%w: unsupported argon2 parallelism %d",
			ErrInvalidKEKEnvelope,
			threads,
		)
	}

	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return kekParams{}, nil, "", fmt.Errorf(
			"%w: salt is not valid base64",
			ErrInvalidKEKEnvelope,
		)
	}

	params := kekParams{
		time:      timeCost,
		memoryKiB: memoryCost,
		threads:   uint8(threads),
		salt:      salt,
	}

	return params, binding, formatCiphertext(nonceField, dataField), nil
}

func parseUint32Field(value string, name string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %s is not a number", ErrInvalidKEKEnvelope, name)
	}

	return uint32(parsed), nil
}

// ciphertextPayload returns the "<nonce>,<ciphertext>" body of an envelope
// produced by EncryptString.
func ciphertextPayload(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, prefix) ||
		!strings.HasSuffix(ciphertext, suffix) {
		return "", errors.New("invalid ciphertext format")
	}

	return strings.TrimSuffix(
		strings.TrimPrefix(ciphertext, prefix),
		suffix,
	), nil
}
