package reportcrypto

import (
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

func DecryptMetadataFromEnv(
	metadata *reporthandlingv2.Metadata,
) ([]byte, error) {

	masterKey, err := GetMasterKeyFromEnv("decryption")
	if err != nil {
		return nil, err
	}

	defer func() {
		for i := range masterKey {
			masterKey[i] = 0
		}
	}()

	dek, err := DEKFromMetadata(
		metadata,
		masterKey,
	)
	if err != nil {
		return nil, err
	}

	if err := DecryptRepoContextMetadata(
		metadata,
		masterKey,
	); err != nil {
		for i := range dek {
			dek[i] = 0
		}
		return nil, err
	}

	return dek, nil
}