package reportcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	dekSize   = 32
	nonceSize = 12
	prefix    = "ENC[AES256_GCM,"
	suffix    = "]"
)

// ValidateDEK validates that a DEK is suitable for AES-256-GCM.
func ValidateDEK(dek []byte) error {
	if len(dek) != dekSize {
		return fmt.Errorf(
			"invalid DEK length: got %d, want %d",
			len(dek),
			dekSize,
		)
	}

	return nil
}

// GenerateDEK creates a random 256-bit Data Encryption Key.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, dekSize)

	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}

	return dek, nil
}

// formatCiphertext builds the canonical ENC[AES256_GCM,...] envelope.
func formatCiphertext(nonce string, ciphertext string) string {
	return fmt.Sprintf("%s%s,%s%s", prefix, nonce, ciphertext, suffix)
}

// EncryptString encrypts plaintext using AES-256-GCM and returns
// a SOPS-inspired ciphertext representation:
//
//	ENC[AES256_GCM,<base64 nonce>,<base64 ciphertext>]
//
// The ciphertext carries no associated data, so it is not bound to the report
// it belongs to and can be swapped with any other ciphertext under the same
// key. Prefer ReportKey.EncryptString, which binds it.
//
// Deprecated: use ReportKey.EncryptString. This remains for reading and writing
// the pre-binding envelope format.
func EncryptString(plaintext string, dek []byte) (string, error) {
	return sealString(plaintext, dek, nil)
}

// DecryptString decrypts a ciphertext produced by EncryptString.
//
// Deprecated: use ReportKey.DecryptString. This remains for reading the
// pre-binding envelope format.
func DecryptString(ciphertext string, dek []byte) (string, error) {
	return openString(ciphertext, dek, nil)
}

// sealString is the single AES-256-GCM sealing primitive in this package.
//
// additionalData is authenticated but not encrypted. Passing nil reproduces the
// pre-binding format; callers that own a ReportKey pass the report's AAD so the
// ciphertext is only valid in the report it was written for.
func sealString(plaintext string, dek []byte, additionalData []byte) (string, error) {
	if err := ValidateDEK(dek); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), additionalData)

	return formatCiphertext(base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// openString is the single AES-256-GCM opening primitive in this package.
//
// additionalData must match the value sealString was called with, or the GCM
// tag check fails. That failure is the point: it is what makes a ciphertext
// moved between reports an error rather than a clean decryption.
func openString(ciphertext string, dek []byte, additionalData []byte) (string, error) {
	if err := ValidateDEK(dek); err != nil {
		return "", err
	}

	if !strings.HasPrefix(ciphertext, prefix) ||
		!strings.HasSuffix(ciphertext, suffix) {
		return "", errors.New("invalid ciphertext format")
	}

	payload := strings.TrimSuffix(
		strings.TrimPrefix(ciphertext, prefix),
		suffix,
	)

	parts := strings.Split(payload, ",")
	if len(parts) != 2 {
		return "", errors.New("invalid ciphertext payload")
	}

	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	encryptedData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(nonce) != gcm.NonceSize() {
		return "", fmt.Errorf(
			"invalid nonce size: got %d, want %d",
			len(nonce),
			gcm.NonceSize(),
		)
	}

	plaintext, err := gcm.Open(nil, nonce, encryptedData, additionalData)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
