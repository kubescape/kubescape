package v1alpha1

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFile reads and decodes the fleet config at path.
func LoadFile(path string) (*Document, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fleet config: %w", err)
	}
	document, err := Load(contents)
	if err != nil {
		return nil, fmt.Errorf("fleet config %q: %w", path, err)
	}
	return document, nil
}

// Load decodes a fleet config strictly, so a misspelt field is an error instead of a setting that is silently ignored.
func Load(contents []byte) (*Document, error) {
	if len(bytes.TrimSpace(contents)) == 0 {
		return nil, errors.New("document is empty")
	}

	// The version is checked before the strict decode, so a file of another kind gets a clear error.
	var envelope struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
	}
	if err := yaml.Unmarshal(contents, &envelope); err != nil {
		return nil, fmt.Errorf("decode version envelope: %w", err)
	}
	if envelope.APIVersion != APIVersion {
		return nil, fmt.Errorf("unsupported apiVersion %q: this Kubescape build supports %q", envelope.APIVersion, APIVersion)
	}
	if envelope.Kind != Kind {
		return nil, fmt.Errorf("unsupported kind %q: expected %q", envelope.Kind, Kind)
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
			return nil, errors.New("file must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("decode trailing YAML document: %w", err)
	}
	return &document, nil
}
