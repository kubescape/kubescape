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
func EncryptString(plaintext string, dek []byte) (string, error) {
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

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	return formatCiphertext(base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// DecryptString decrypts a ciphertext produced by EncryptString.
func DecryptString(ciphertext string, dek []byte) (string, error) {
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

	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
