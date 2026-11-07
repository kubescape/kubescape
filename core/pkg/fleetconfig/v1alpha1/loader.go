package v1alpha1

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"gopkg.in/yaml.v3"
)

// maxFleetConfigBytes is the maximum allowed size for fleet config files (32 MiB),
// matching cautils.DefaultMaxFileSize to prevent uncontrolled resource consumption
// from oversized inputs or decompression bombs (CWE-400).
const maxFleetConfigBytes int64 = 32 * 1024 * 1024

var (
	ErrFleetConfigNotRegular = errors.New("fleet config is not a regular file")
	ErrFleetConfigTooLarge   = errors.New("fleet config exceeds maximum size limit")
)

// openFleetConfigFile opens path for reading and rejects non-regular files (such as FIFOs,
// device nodes, or directories). O_NONBLOCK ensures that opening a FIFO without a writer
// fails or returns immediately rather than blocking the process indefinitely.
func openFleetConfigFile(path string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if info.IsDir() {
		file.Close()
		return nil, nil, fmt.Errorf("%q is a directory, not a file", path)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, fmt.Errorf("%w: %q", ErrFleetConfigNotRegular, path)
	}
	return file, info, nil
}

// readFleetConfigFile returns the contents of the fleet config at path. It bounds the read
// to at most maxFleetConfigBytes+1 bytes (32 MiB + 1 byte) for overflow detection, rejecting
// files that exceed the limit.
func readFleetConfigFile(path string) ([]byte, error) {
	file, info, err := openFleetConfigFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if info.Size() > maxFleetConfigBytes {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrFleetConfigTooLarge, path, maxFleetConfigBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxFleetConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxFleetConfigBytes {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrFleetConfigTooLarge, path, maxFleetConfigBytes)
	}
	return data, nil
}

// LoadFile reads and decodes the fleet config at path.
func LoadFile(path string) (*Document, error) {
	contents, err := readFleetConfigFile(path)
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
