package anonymizer

import (
	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
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
) error {
	if err := reportcrypto.ValidateDEK(dek); err != nil {
		return err
	}

	return applyWithTransformer(
		resultsHandler,
		NewEncryptionTransformer(dek),
	)
}
