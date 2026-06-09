package anonymizer

import "github.com/kubescape/kubescape/v3/core/pkg/resultshandling"

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

func ApplyEncrypted(
	resultsHandler *resultshandling.ResultsHandler,
	dek []byte,
) error {
	return applyWithTransformer(
		resultsHandler,
		NewEncryptionTransformer(dek),
	)
}
