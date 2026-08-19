package reportcrypto

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// WrapDEK encrypts a DEK using a key-encryption key derived from the supplied
// master secret and returns an envelope suitable for storing in report
// metadata.
//
// The master secret is stretched with Argon2id under a salt unique to this
// envelope; the work factors and salt are stored alongside the ciphertext so
// the envelope is self-describing and the factors can be raised in a later
// release without stranding existing reports.
func WrapDEK(dek []byte, masterKey []byte) (string, error) {

	if err := ValidateDEK(dek); err != nil {
		return "", err
	}

	if err := ValidateMasterKey(masterKey); err != nil {
		return "", err
	}

	params, err := newKEKParams()
	if err != nil {
		return "", err
	}

	kek, err := deriveKEK(masterKey, params)
	if err != nil {
		return "", err
	}
	defer zeroBytes(kek)

	encryptedDEK, err := EncryptString(
		base64.StdEncoding.EncodeToString(dek),
		kek,
	)
	if err != nil {
		return "", err
	}

	return formatKEKCiphertext(params, encryptedDEK)
}

// UnwrapDEK decrypts a wrapped DEK using the supplied master secret and returns
// the original DEK bytes.
//
// Both envelope formats are accepted. Envelopes written before key derivation
// was introduced carry no salt and used the master secret as the AES key
// directly, so they still require exactly dekSize bytes; reports produced by
// those releases stay readable.
func UnwrapDEK(wrappedDEK string, masterKey []byte) ([]byte, error) {

	if err := ValidateMasterKey(masterKey); err != nil {
		return nil, err
	}

	kek, envelope, err := resolveKEK(wrappedDEK, masterKey)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(kek)

	dekString, err := DecryptString(
		envelope,
		kek,
	)
	if err != nil {
		return nil, err
	}

	dek, err := base64.StdEncoding.DecodeString(
		dekString,
	)
	if err != nil {
		return nil, err
	}

	if err := ValidateDEK(dek); err != nil {
		return nil, err
	}

	return dek, nil
}

// resolveKEK returns the AES key that decrypts wrappedDEK together with the
// inner ENC[AES256_GCM,...] envelope DecryptString consumes.
//
// Current envelopes carry their own salt and work factors, so the key is
// derived. Legacy envelopes carry neither and used the master secret as the AES
// key directly, so it is passed through after the length check that the old
// ValidateMasterKey used to perform.
//
// The returned key is always a copy, so callers can zero it unconditionally
// without clobbering the caller's master secret.
func resolveKEK(wrappedDEK string, masterKey []byte) ([]byte, string, error) {
	if !strings.HasPrefix(wrappedDEK, kekPrefix) {
		if err := ValidateDEK(masterKey); err != nil {
			return nil, "", fmt.Errorf(
				"this report predates master key derivation and needs the original %d-byte master key: %w",
				dekSize,
				err,
			)
		}

		return append([]byte(nil), masterKey...), wrappedDEK, nil
	}

	params, inner, err := parseKEKCiphertext(wrappedDEK)
	if err != nil {
		return nil, "", err
	}

	kek, err := deriveKEK(masterKey, params)
	if err != nil {
		return nil, "", err
	}

	return kek, inner, nil
}
