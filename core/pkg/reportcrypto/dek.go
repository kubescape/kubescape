package reportcrypto

import (
	"encoding/base64"
)

// WrapDEK encrypts a DEK using the provided master key
// and returns a base64-encoded encrypted representation
// suitable for storing in report metadata.
func WrapDEK(dek []byte, masterKey []byte) (string, error) {

	if err := ValidateDEK(dek); err != nil {
		return "", err
	}

	if err := ValidateMasterKey(masterKey); err != nil {
		return "", err
	}

	encryptedDEK, err := EncryptString(
		base64.StdEncoding.EncodeToString(dek),
		masterKey,
	)
	if err != nil {
		return "", err
	}

	return encryptedDEK, nil
}

// UnwrapDEK decrypts a wrapped DEK using the provided
// master key and returns the original DEK bytes.
func UnwrapDEK(wrappedDEK string, masterKey []byte) ([]byte, error) {

	if err := ValidateMasterKey(masterKey); err != nil {
		return nil, err
	}

	dekString, err := DecryptString(
		wrappedDEK,
		masterKey,
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
