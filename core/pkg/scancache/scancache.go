package scancache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

type Entry struct {
	Hash    string                                       `json:"hash"`
	Verdict resourcesresults.ResourceAssociatedControl   `json:"verdict"`
}

// Store is keyed by "<controlsConfigVersion>|<controlID>|<resourceID>".
type Store struct {
	path    string
	version string // controls-config version; a mismatch invalidates everything
	mu      sync.RWMutex
	data    map[string]Entry
	dirty   bool
}

func Load(cacheDir, controlsConfigVersion string) (*Store, error) {
	path := filepath.Join(cacheDir, "incremental-scan-cache.json")
	s := &Store{path: path, version: controlsConfigVersion, data: map[string]Entry{}}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}

	var onDisk struct {
		Version string           `json:"version"`
		Entries map[string]Entry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		return s, nil // corrupt cache: treat as empty rather than fail the scan
	}
	if onDisk.Version != controlsConfigVersion {
		return s, nil // controls-config bumped: automatic invalidation
	}
	s.data = onDisk.Entries
	return s, nil
}

func (s *Store) key(controlID, resourceID string) string {
	return controlID + "|" + resourceID
}

func (s *Store) Get(controlID, resourceID, hash string) (resourcesresults.ResourceAssociatedControl, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.data[s.key(controlID, resourceID)]
	if !ok || e.Hash != hash {
		return resourcesresults.ResourceAssociatedControl{}, false
	}
	return e.Verdict, true
}

func (s *Store) Put(controlID, resourceID, hash string, verdict resourcesresults.ResourceAssociatedControl) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[s.key(controlID, resourceID)] = Entry{Hash: hash, Verdict: verdict}
	s.dirty = true
}

func (s *Store) Flush() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.dirty {
		return nil
	}
	out := struct {
		Version string           `json:"version"`
		Entries map[string]Entry `json:"entries"`
	}{Version: s.version, Entries: s.data}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

// ResourceHash hashes kind+namespace+name+spec+labels+annotations.
func ResourceHash(obj map[string]any) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	// Only hash fields that affect control evaluation; drop status/managedFields/resourceVersion.
	stripped := map[string]any{
		"kind":       obj["kind"],
		"apiVersion": obj["apiVersion"],
	}
	if md, ok := obj["metadata"].(map[string]any); ok {
		stripped["metadata"] = map[string]any{
			"name":        md["name"],
			"namespace":   md["namespace"],
			"labels":      md["labels"],
			"annotations": md["annotations"],
		}
	}
	stripped["spec"] = obj["spec"]
	stripped["data"] = obj["data"] // ConfigMaps/Secrets
	_ = enc.Encode(stripped)
	return hex.EncodeToString(h.Sum(nil))
}

func Delete(cacheDir string) error {
	return os.Remove(filepath.Join(cacheDir, "incremental-scan-cache.json"))
}
