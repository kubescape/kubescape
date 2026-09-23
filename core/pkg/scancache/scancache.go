package scancache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/gofrs/flock"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const cacheFileName = "incremental-scan-cache.json"

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
	pending map[string]Entry
	dirty   bool
}

func Load(cacheDir, controlsConfigVersion string) (*Store, error) {
	path := filepath.Join(cacheDir, cacheFileName)
	s := &Store{
		path:    path,
		version: controlsConfigVersion,
		data:    map[string]Entry{},
		pending: map[string]Entry{},
	}

	// Do not create either the cache directory or its sidecar lock for a read
	// that has nothing to load. Besides keeping Load side-effect free, this
	// preserves Delete's historical idempotence for a missing cache directory.
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		return s, nil
	} else if err != nil {
		return nil, fmt.Errorf("inspect incremental scan cache directory: %w", err)
	}

	// A Windows reader keeps the destination file open while os.ReadFile runs.
	// Atomic replacement uses MoveFileEx, which can fail with a sharing
	// violation unless that read is coordinated with the publisher. The shared
	// sidecar lock also gives every platform one read/merge/write contract.
	fileLock := flock.New(path + ".lock")
	if err := fileLock.RLock(); err != nil {
		return nil, fmt.Errorf("read-lock incremental scan cache: %w", err)
	}
	defer func() { _ = fileLock.Unlock() }()

	onDisk, err := readCache(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		if isInvalidCache(err) {
			return s, nil // corrupt cache: treat as empty rather than fail the scan
		}
		return nil, err
	}
	if onDisk.Version != controlsConfigVersion {
		return s, nil // controls-config bumped: automatic invalidation
	}
	if onDisk.Entries != nil {
		s.data = onDisk.Entries
	}
	return s, nil
}

type diskCache struct {
	Version string           `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

type invalidCacheError struct {
	err error
}

func (e *invalidCacheError) Error() string {
	return "invalid incremental scan cache: " + e.err.Error()
}

func (e *invalidCacheError) Unwrap() error {
	return e.err
}

func isInvalidCache(err error) bool {
	_, ok := err.(*invalidCacheError)
	return ok
}

func readCache(path string) (diskCache, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return diskCache{}, err
	}
	var onDisk diskCache
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		return diskCache{}, &invalidCacheError{err: err}
	}
	return onDisk, nil
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
	if s.data == nil {
		s.data = map[string]Entry{}
	}
	if s.pending == nil {
		s.pending = map[string]Entry{}
	}
	key := s.key(controlID, resourceID)
	entry := Entry{Hash: hash, Verdict: verdict}
	s.data[key] = entry
	s.pending[key] = entry
	s.dirty = true
}

func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}

	// Store instances are process-local, but the cache path is shared by CLI
	// invocations. Serialize the read-merge-write transaction so two scans that
	// finish together do not silently discard each other's new verdicts.
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("create incremental scan cache directory: %w", err)
	}
	fileLock := flock.New(s.path + ".lock")
	if err := fileLock.Lock(); err != nil {
		return fmt.Errorf("lock incremental scan cache: %w", err)
	}
	defer func() { _ = fileLock.Unlock() }()

	merged := make(map[string]Entry, len(s.data)+len(s.pending))
	onDisk, readErr := readCache(s.path)
	switch {
	case readErr == nil && onDisk.Version == s.version:
		for key, entry := range onDisk.Entries {
			merged[key] = entry
		}
	case readErr == nil:
		// A different policy context owns the file. Start a fresh generation.
	case os.IsNotExist(readErr):
	case isInvalidCache(readErr):
		// Replace an incomplete or malformed generation with a valid one.
	default:
		return fmt.Errorf("reload incremental scan cache: %w", readErr)
	}
	for key, entry := range s.pending {
		merged[key] = entry
	}

	b, err := json.Marshal(diskCache{Version: s.version, Entries: merged})
	if err != nil {
		return err
	}
	if err := cautils.WriteFileAtomically(s.path, b, 0o600); err != nil {
		return err
	}
	s.data = merged
	clear(s.pending)
	s.dirty = false
	return nil
}

// ResourceHash hashes the whole object except status.
// Rules that read status are kept out of the cache by ruleCacheEligible, so
// stripping it here cannot hide an input change. Metadata must remain in the
// hash: custom policies may inspect resourceVersion or managedFields, even if
// those values are volatile from the scanner's perspective. Everything else is included,
// so a change to any evaluation-relevant field — including root-level fields
// like RoleBinding.roleRef/subjects or Role.rules — cannot be missed.
func ResourceHash(obj map[string]any) string {
	stripped := make(map[string]any, len(obj))
	for k, v := range obj {
		stripped[k] = v
	}
	delete(stripped, "status")

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
	path := filepath.Join(cacheDir, cacheFileName)
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect incremental scan cache directory for deletion: %w", err)
	}

	fileLock := flock.New(path + ".lock")
	if err := fileLock.Lock(); err != nil {
		if os.IsNotExist(err) {
			// A concurrent Delete may have removed the directory after the Stat.
			return nil
		}
		return fmt.Errorf("lock incremental scan cache for deletion: %w", err)
	}
	defer func() { _ = fileLock.Unlock() }()

	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
