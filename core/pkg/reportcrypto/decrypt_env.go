package reportcrypto

import (
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

func DecryptMetadataFromEnv(
	metadata *reporthandlingv2.Metadata,
) error {

	masterKey, err := GetMasterKeyFromEnv()
	if err != nil {
		return err
	}

	defer func() {
		for i := range masterKey {
			masterKey[i] = 0
		}
	}()

	return DecryptRepoContextMetadata(
		metadata,
		masterKey,
	)
}
