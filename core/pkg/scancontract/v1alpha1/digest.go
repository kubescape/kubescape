package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// EffectiveRunDigestSchema identifies the canonical envelope used for the
// resolved scan inputs. It is intentionally distinct from DigestSchema, which
// covers only the selected repository contract.
const EffectiveRunDigestSchema = "kubescape-effective-run:v1"

type digestInput struct {
	APIVersion              string   `json:"apiVersion"`
	Kind                    string   `json:"kind"`
	Metadata                Metadata `json:"metadata"`
	MinimumKubescapeVersion string   `json:"minimumKubescapeVersion"`
	ContractName            string   `json:"contractName"`
	Contract                Contract `json:"contract"`
}

func Digest(selected *SelectedContract) (string, error) {
	input := digestInput{
		APIVersion:              selected.APIVersion,
		Kind:                    selected.Kind,
		Metadata:                selected.Metadata,
		MinimumKubescapeVersion: selected.MinimumKubescapeVersion,
		ContractName:            selected.ContractName,
		Contract:                selected.Contract,
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("marshal selected contract for digest: %w", err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize selected contract for digest: %w", err)
	}
	return digestCanonical(DigestSchema, canonical), nil
}

// DigestEffectiveRun produces a stable digest for the post-resolution scan
// inputs. Callers provide a typed, JSON-serializable envelope so this package
// can own the canonicalization and domain separation without depending on a
// particular report schema.
func DigestEffectiveRun(input any) (string, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("marshal effective scan contract run for digest: %w", err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize effective scan contract run: %w", err)
	}
	return digestCanonical(EffectiveRunDigestSchema, canonical), nil
}

func digestCanonical(schema string, canonical []byte) string {
	hashInput := append([]byte(schema+"\x00"), canonical...)
	sum := sha256.Sum256(hashInput)
	return "sha256:" + hex.EncodeToString(sum[:])
}
