package anonymizer

import (
	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"

	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

func Apply(resultsHandler *resultshandling.ResultsHandler) error {
	return applyWithTransformer(
		resultsHandler,
		NewMappingTransformer(),
	)
}

func applyWithTransformer(
	resultsHandler *resultshandling.ResultsHandler,
	transformer Transformer,
) error {
	if resultsHandler == nil || resultsHandler.ScanData == nil {
		return nil
	}

	mapping := NewMapping()

	if err := anonymizeSession(
		resultsHandler.ScanData,
		mapping,
		transformer,
	); err != nil {
		return err
	}

	return nil
}

// ApplyEncrypted anonymizes a scan session while encrypting
// RepoContextMetadata using the supplied DEK.
//
// Resource identifiers, namespaces, annotations, source paths,
// and other session data continue to use mapping-based
// anonymization and remain irreversibly pseudonymized.
//
// Only repo context metadata is reversibly encrypted.
func ApplyEncrypted(
	resultsHandler *resultshandling.ResultsHandler,
	dek []byte,
	masterKey []byte,
) error {

	if err := reportcrypto.ValidateDEK(dek); err != nil {
		return err
	}

	if err := reportcrypto.ValidateMasterKey(masterKey); err != nil {
		return err
	}

	wrappedDEK, err := reportcrypto.WrapDEK(
		dek,
		masterKey,
	)
	if err != nil {
		return err
	}

	if resultsHandler != nil &&
		resultsHandler.ScanData != nil &&
		resultsHandler.ScanData.Metadata != nil {

		resultsHandler.ScanData.Metadata.EncryptionMetadata =
			&reporthandlingv2.EncryptionMetadata{
				Version:      "v1",
				DEKAlgorithm: "AES256_GCM",
				KEKAlgorithm: "AES256_GCM",
				EncryptedDEK: wrappedDEK,
			}
	}

	if resultsHandler != nil &&
		resultsHandler.ScanData != nil &&
		resultsHandler.ScanData.Report != nil {

		resultsHandler.ScanData.Report.Metadata.EncryptionMetadata =
			&reporthandlingv2.EncryptionMetadata{
				Version:      "v1",
				DEKAlgorithm: "AES256_GCM",
				KEKAlgorithm: "AES256_GCM",
				EncryptedDEK: wrappedDEK,
			}
	}

	return applyWithTransformer(
		resultsHandler,
		NewEncryptionTransformer(dek),
	)
}
