package reportcrypto

import (
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

func DecryptMetadataFromEnv(
	metadata *reporthandlingv2.Metadata,
) (*ReportKey, error) {

	masterKey, err := GetMasterKeyFromEnv("decryption")
	if err != nil {
		return nil, err
	}

	defer func() {
		for i := range masterKey {
			masterKey[i] = 0
		}
	}()

	key, err := DEKFromMetadata(
		metadata,
		masterKey,
	)
	if err != nil {
		return nil, err
	}

	if err := decryptRepoContextMetadata(metadata, key); err != nil {
		key.Zero()
		return nil, err
	}

	return key, nil
}
