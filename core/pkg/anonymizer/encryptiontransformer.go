package anonymizer

import "github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"

// EncryptionTransformer implements Transformer using AES-256-GCM encryption.
//
// Unlike MappingTransformer, which produces deterministic pseudonyms,
// EncryptionTransformer produces reversible ciphertext suitable for
// encrypted report workflows.
type EncryptionTransformer struct {
	dek []byte
}

func NewEncryptionTransformer(
	dek []byte,
) *EncryptionTransformer {
	return &EncryptionTransformer{
		dek: dek,
	}
}

// Transform encrypts the provided value using the configured DEK and
// returns a SOPS-inspired ENC[AES256_GCM,...] ciphertext representation.
func (t *EncryptionTransformer) Transform(
	prefix string,
	value string,
) (string, error) {
	return reportcrypto.EncryptString(
		value,
		t.dek,
	)
}
