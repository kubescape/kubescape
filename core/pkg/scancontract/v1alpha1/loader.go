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

// maxContractBytes is the maximum allowed size for scan contract files (32 MiB),
// matching cautils.DefaultMaxFileSize to prevent uncontrolled resource consumption
// from oversized inputs or decompression bombs (CWE-400).
const maxContractBytes int64 = 32 * 1024 * 1024

var (
	ErrContractNotRegular = errors.New("scan contract is not a regular file")
	ErrContractTooLarge   = errors.New("scan contract exceeds maximum size limit")
)

// openContractFile opens path for reading and rejects non-regular files (such as FIFOs,
// device nodes, or directories). O_NONBLOCK ensures that opening a FIFO without a writer
// fails or returns immediately rather than blocking the process indefinitely.
func openContractFile(path string) (*os.File, os.FileInfo, error) {
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
		return nil, nil, fmt.Errorf("%w: %q", ErrContractNotRegular, path)
	}
	return file, info, nil
}

// readContractFile returns the contents of the scan contract at path. It bounds the read
// to at most maxContractBytes+1 bytes (32 MiB + 1 byte) for overflow detection, rejecting
// files that exceed the limit.
func readContractFile(path string) ([]byte, error) {
	file, info, err := openContractFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if info.Size() > maxContractBytes {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrContractTooLarge, path, maxContractBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxContractBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxContractBytes {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrContractTooLarge, path, maxContractBytes)
	}
	return data, nil
}

type LoadOptions struct {
	ContractName        string
	RunningVersion      string
	SupportedFormats    []string
	SupportedSeverities []string
}

func LoadFile(path string, options LoadOptions) (*SelectedContract, error) {
	contents, err := readContractFile(path)
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
