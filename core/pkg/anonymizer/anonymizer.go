package anonymizer

import (
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"

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
	if resultsHandler == nil {
		return nil
	}

	mapping := NewMapping()

	// transformSession guards a nil session itself. The nil-ScanData check
	// used to sit on this function instead, where it also skipped everything
	// below it.
	if err := transformSession(
		resultsHandler.ScanData,
		mapping,
		transformer,
	); err != nil {
		return err
	}

	// Image results hang off the handler rather than off the session, so
	// transformSession never saw them. They are transformed with the same
	// Transformer, and therefore the same mapping, because the pseudonyms
	// have to agree with the ones just written onto the workloads.
	return transformImageScanData(
		resultsHandler.ImageScanData,
		transformer,
	)
}

// ApplyEncrypted anonymizes a scan session while encrypting
// sensitive report metadata using the supplied DEK.
//
// The DEK is wrapped using the supplied master key (KEK)
// and stored in EncryptionMetadata for future decryption
// workflows.
func ApplyEncrypted(
	resultsHandler *resultshandling.ResultsHandler,
	dek []byte,
	masterKey []byte,
) error {

	// The binding is generated here, once, and shared by the wrapped DEK and
	// every field this transformer seals. That is what ties the report's
	// ciphertexts to this report rather than leaving them interchangeable.
	key, err := reportcrypto.NewReportKey(dek)
	if err != nil {
		return err
	}

	wrappedDEK, err := reportcrypto.WrapReportKey(
		key,
		masterKey,
	)
	if err != nil {
		return err
	}

	if err := applyWithTransformer(
		resultsHandler,
		NewEncryptionTransformer(key),
	); err != nil {
		return err
	}

	encryptionMetadata := &reporthandlingv2.EncryptionMetadata{
		Version:      "v1",
		DEKAlgorithm: "AES256_GCM",
		KEKAlgorithm: reportcrypto.KEKAlgorithm,
		EncryptedDEK: wrappedDEK,
	}

	if resultsHandler != nil &&
		resultsHandler.ScanData != nil &&
		resultsHandler.ScanData.Metadata != nil {

		resultsHandler.ScanData.Metadata.EncryptionMetadata =
			encryptionMetadata
	}

	if resultsHandler != nil &&
		resultsHandler.ScanData != nil &&
		resultsHandler.ScanData.Report != nil {

		resultsHandler.ScanData.Report.Metadata.EncryptionMetadata =
			encryptionMetadata
	}

	return nil
}
