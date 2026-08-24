package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

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
	hashInput := append([]byte(DigestSchema+"\x00"), canonical...)
	sum := sha256.Sum256(hashInput)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
