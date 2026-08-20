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
	Hash    string                                     `json:"hash"`
	Verdict resourcesresults.ResourceAssociatedControl `json:"verdict"`
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
	return os.WriteFile(s.path, b, 0o600)
}

// ResourceHash hashes the whole object except fields known to change
// without affecting control evaluation (status and volatile metadata).
// Everything else is included, so a change to any evaluation-relevant field
// — including root-level fields like RoleBinding.roleRef/subjects or
// Role.rules — cannot be missed.
func ResourceHash(obj map[string]any) string {
	stripped := make(map[string]any, len(obj))
	for k, v := range obj {
		stripped[k] = v
	}
	delete(stripped, "status")
	if md, ok := stripped["metadata"].(map[string]any); ok {
		mdCopy := make(map[string]any, len(md))
		for k, v := range md {
			mdCopy[k] = v
		}
		delete(mdCopy, "managedFields")
		delete(mdCopy, "resourceVersion")
		stripped["metadata"] = mdCopy
	}

	h := sha256.New()
	enc := json.NewEncoder(h)
	_ = enc.Encode(stripped)
	return hex.EncodeToString(h.Sum(nil))
}

// VersionKey builds a stable content hash from the given byte slices (e.g.
// the resolved policy frameworks, optionally combined with local
// controls-config file bytes) for use as the cache's invalidation version.
// Unlike a raw pinned-version flag (empty when the user didn't pin one),
// this changes whenever the actual policy/config content changes, so
// "latest" resolutions still invalidate correctly.
func VersionKey(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func Delete(cacheDir string) error {
	err := os.Remove(filepath.Join(cacheDir, "incremental-scan-cache.json"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
