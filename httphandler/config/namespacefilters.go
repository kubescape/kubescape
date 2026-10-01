package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"k8s.io/apimachinery/pkg/util/validation"
)

// NamespaceFiltersFileEnv opts the HTTP server into live namespace defaults.
const NamespaceFiltersFileEnv = "KS_NAMESPACE_FILTERS_FILE"

// NamespaceFilters is a complete, immutable snapshot of the scan defaults.
type NamespaceFilters struct {
	Include string
	Exclude string
}

type namespaceFiltersFile struct {
	mu        sync.Mutex
	path      string
	current   NamespaceFilters
	lastError string
}

var namespaceFiltersSource atomic.Pointer[namespaceFiltersFile]

// ConfigureNamespaceFilters validates the initial file before enabling reloads.
// An empty path disables live defaults and preserves environment-based defaults.
func ConfigureNamespaceFilters(path string) error {
	if path == "" {
		namespaceFiltersSource.Store(nil)
		return nil
	}
	filters, err := readNamespaceFilters(path)
	if err != nil {
		return fmt.Errorf("load namespace filters: %w", err)
	}
	namespaceFiltersSource.Store(&namespaceFiltersFile{path: path, current: filters})
	return nil
}

// GetNamespaceFilters reopens the projected file for each new scan, including
// Kubernetes' atomic symlink replacements. Failed updates retain the last valid
// snapshot, rather than unexpectedly broadening the scan to all namespaces.
func GetNamespaceFilters() (NamespaceFilters, bool) {
	source := namespaceFiltersSource.Load()
	if source == nil {
		return NamespaceFilters{}, false
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	filters, err := readNamespaceFilters(source.path)
	if err != nil {
		if source.lastError != err.Error() {
			logger.L().Warning("cannot reload namespace filters; retaining last valid filters", helpers.Error(err))
			source.lastError = err.Error()
		}
	} else {
		source.current = filters
		source.lastError = ""
	}
	return source.current, true
}

func readNamespaceFilters(path string) (NamespaceFilters, error) {
	f, err := os.Open(path)
	if err != nil {
		return NamespaceFilters{}, err
	}
	defer f.Close()
	// ConfigMaps are limited to 1 MiB; reject oversized standalone files too.
	const maxBytes = 1 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return NamespaceFilters{}, err
	}
	if len(data) > maxBytes {
		return NamespaceFilters{}, fmt.Errorf("namespace filters exceed 1 MiB")
	}
	var document struct {
		Include namespaceList `json:"includeNamespaces"`
		Exclude namespaceList `json:"excludeNamespaces"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return NamespaceFilters{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return NamespaceFilters{}, fmt.Errorf("namespace filters must contain exactly one JSON document")
	}
	if document.Include == nil || document.Exclude == nil {
		return NamespaceFilters{}, fmt.Errorf("includeNamespaces and excludeNamespaces are required")
	}
	return NamespaceFilters{Include: strings.Join(document.Include, ","), Exclude: strings.Join(document.Exclude, ",")}, nil
}

// namespaceList accepts Helm's comma-separated strings as well as JSON arrays.
type namespaceList []string

func (list *namespaceList) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var entries []string
	switch value := value.(type) {
	case string:
		entries = strings.Split(value, ",")
	case []any:
		for _, entry := range value {
			name, ok := entry.(string)
			if !ok {
				return fmt.Errorf("namespace list entries must be strings")
			}
			entries = append(entries, name)
		}
	default:
		return fmt.Errorf("namespace list must be a string or an array of strings")
	}
	*list = namespaceList{}
	for _, name := range entries {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if errors := validation.IsDNS1123Label(name); len(errors) != 0 {
			return fmt.Errorf("invalid namespace %q: %s", name, strings.Join(errors, "; "))
		}
		*list = append(*list, name)
	}
	return nil
}
