package v1alpha1

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type LoadOptions struct {
	ContractName        string
	RunningVersion      string
	SupportedFormats    []string
	SupportedSeverities []string
}

func LoadFile(path string, options LoadOptions) (*SelectedContract, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scan contract: %w", err)
	}
	selected, err := Load(contents, options)
	if err != nil {
		return nil, fmt.Errorf("validate scan contract %q: %w", path, err)
	}
	return selected, nil
}

func Load(contents []byte, options LoadOptions) (*SelectedContract, error) {
	if len(bytes.TrimSpace(contents)) == 0 {
		return nil, errors.New("contract document is empty")
	}

	var envelope struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Spec       struct {
			MinimumKubescapeVersion string `yaml:"minimumKubescapeVersion"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(contents, &envelope); err != nil {
		return nil, fmt.Errorf("decode version envelope: %w", err)
	}
	if err := validateVersionEnvelope(envelope.APIVersion, envelope.Kind, envelope.Spec.MinimumKubescapeVersion, options.RunningVersion); err != nil {
		return nil, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("strictly decode %s %s: %w", APIVersion, Kind, err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("contract file must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("decode trailing YAML document: %w", err)
	}

	if err := validateDocument(&document, options); err != nil {
		return nil, err
	}

	contractName := options.ContractName
	if contractName == "" {
		contractName = document.Spec.DefaultContract
	}
	if contractName == "" {
		return nil, errors.New("no contract selected: pass --contract or set spec.defaultContract")
	}
	contract, ok := document.Spec.Contracts[contractName]
	if !ok {
		return nil, fmt.Errorf("contract %q does not exist", contractName)
	}

	selected := &SelectedContract{
		APIVersion:              document.APIVersion,
		Kind:                    document.Kind,
		Metadata:                document.Metadata,
		MinimumKubescapeVersion: document.Spec.MinimumKubescapeVersion,
		ContractName:            contractName,
		Contract:                contract,
		DigestSchema:            DigestSchema,
	}
	digest, err := Digest(selected)
	if err != nil {
		return nil, err
	}
	selected.ContractDigest = digest
	return selected, nil
}
