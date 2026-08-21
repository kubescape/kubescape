package anonymizer

import "github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"

// EncryptionTransformer implements Transformer using AES-256-GCM encryption.
//
// Unlike MappingTransformer, which produces deterministic pseudonyms,
// EncryptionTransformer produces reversible ciphertext suitable for
// encrypted report workflows.
type EncryptionTransformer struct {
	key *reportcrypto.ReportKey
}

func NewEncryptionTransformer(
	key *reportcrypto.ReportKey,
) *EncryptionTransformer {
	return &EncryptionTransformer{
		key: key,
	}
}

// Transform encrypts the provided value using the configured report key and
// returns a SOPS-inspired ENC[AES256_GCM,...] ciphertext representation.
//
// prefix names the pseudonym namespace MappingTransformer uses and is
// deliberately not mixed into the ciphertext: it is far coarser than a field
// identity - every repository metadata field shares "git" - so binding it would
// suggest a per-field guarantee that is not there. The value is bound to the
// report instead, via the key.
func (t *EncryptionTransformer) Transform(
	prefix string,
	value string,
) (string, error) {
	return t.key.EncryptString(value)
}
