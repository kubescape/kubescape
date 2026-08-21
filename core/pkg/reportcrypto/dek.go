package reportcrypto

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// WrapReportKey encrypts a report key using a key-encryption key derived from
// the supplied master secret and returns an envelope suitable for storing in
// report metadata.
//
// The master secret is stretched with Argon2id under a salt unique to this
// envelope; the work factors, the salt and the report binding are stored
// alongside the ciphertext so the envelope is self-describing and the factors
// can be raised in a later release without stranding existing reports.
//
// The wrapped DEK is sealed under its own AAD domain, so a report field can
// never be presented in place of a wrapped DEK, or the reverse - the two are
// distinguishable to the cipher, not merely by their textual prefix.
func WrapReportKey(key *ReportKey, masterKey []byte) (string, error) {

	if key == nil {
		return "", ErrNilReportKey
	}

	if err := ValidateDEK(key.dek); err != nil {
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

	encryptedDEK, err := sealString(
		base64.StdEncoding.EncodeToString(key.dek),
		kek,
		buildAAD(aadDomainDEK, key.binding),
	)
	if err != nil {
		return "", err
	}

	return formatKEKCiphertext(params, key.binding, encryptedDEK)
}

// UnwrapReportKey decrypts a wrapped report key using the supplied master
// secret and returns the DEK together with the binding recorded in the
// envelope.
//
// All three envelope formats are accepted. A v2 envelope carries a binding, so
// the report's fields are opened with associated data. A v1 envelope carries
// none, and envelopes written before key derivation was introduced carry
// neither salt nor binding and used the master secret as the AES key directly,
// so they still require exactly dekSize bytes. Reports produced by those
// releases stay readable.
func UnwrapReportKey(wrappedDEK string, masterKey []byte) (*ReportKey, error) {

	if err := ValidateMasterKey(masterKey); err != nil {
		return nil, err
	}

	kek, binding, envelope, err := resolveKEK(wrappedDEK, masterKey)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(kek)

	dekString, err := openString(
		envelope,
		kek,
		buildAAD(aadDomainDEK, binding),
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

	return &ReportKey{dek: dek, binding: binding}, nil
}

// WrapDEK wraps a bare DEK with no report binding.
//
// Deprecated: use WrapReportKey. This writes the unbound v1 envelope, whose
// ciphertexts are interchangeable with those of any other report sharing the
// key. It remains so that envelopes in that format keep round-tripping.
func WrapDEK(dek []byte, masterKey []byte) (string, error) {
	return WrapReportKey(UnboundReportKey(dek), masterKey)
}

// UnwrapDEK decrypts a wrapped DEK using the supplied master secret and returns
// the original DEK bytes, discarding any binding recorded in the envelope.
//
// Deprecated: use UnwrapReportKey. A caller that drops the binding cannot open
// the report's fields, because they were sealed against it.
func UnwrapDEK(wrappedDEK string, masterKey []byte) ([]byte, error) {
	key, err := UnwrapReportKey(wrappedDEK, masterKey)
	if err != nil {
		return nil, err
	}

	return key.dek, nil
}

// resolveKEK returns the AES key that decrypts wrappedDEK, the binding the
// envelope records, and the inner ENC[AES256_GCM,...] envelope openString
// consumes.
//
// Current envelopes carry their own salt and work factors, so the key is
// derived. Legacy envelopes carry neither and used the master secret as the AES
// key directly, so it is passed through after the length check that the old
// ValidateMasterKey used to perform.
//
// The returned key is always a copy, so callers can zero it unconditionally
// without clobbering the caller's master secret.
func resolveKEK(wrappedDEK string, masterKey []byte) ([]byte, []byte, string, error) {
	if !strings.HasPrefix(wrappedDEK, kekPrefix) {
		if err := ValidateDEK(masterKey); err != nil {
			return nil, nil, "", fmt.Errorf(
				"this report predates master key derivation and needs the original %d-byte master key: %w",
				dekSize,
				err,
			)
		}

		return append([]byte(nil), masterKey...), nil, wrappedDEK, nil
	}

	params, binding, inner, err := parseKEKCiphertext(wrappedDEK)
	if err != nil {
		return nil, nil, "", err
	}

	kek, err := deriveKEK(masterKey, params)
	if err != nil {
		return nil, nil, "", err
	}

	return kek, binding, inner, nil
}
