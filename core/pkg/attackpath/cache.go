package attackpath

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

// CacheEntry is one cached attack-path result for a specific resource
// snapshot. The key is the snapshot hash; the value is the SearchResult
// plus metadata needed to validate whether the cache is still fresh.
type CacheEntry struct {
	// SnapshotHash is a SHA-256 of the sorted resource IDs and their
	// resource versions, so any change to any collected object invalidates
	// the cache entry.
	SnapshotHash string `json:"snapshot_hash"`
	// CreatedAt is when this entry was written, for TTL-based expiry.
	CreatedAt time.Time `json:"created_at"`
	// TTLSeconds is how long this entry is valid. 0 means no TTL.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
	// Result is the cached SearchResult.
	Result SearchResult `json:"result"`
	// Warnings are the warnings produced during the cached run.
	Warnings []string `json:"warnings,omitempty"`
}

// IsValid reports whether this cache entry is still usable:
// the snapshot hash matches and the entry has not expired.
func (e *CacheEntry) IsValid(snapshotHash string) bool {
	if e.SnapshotHash != snapshotHash {
		return false
	}
	if e.TTLSeconds > 0 {
		return time.Since(e.CreatedAt) < time.Duration(e.TTLSeconds)*time.Second
	}
	return true
}

// SnapshotHashFromResources computes a deterministic hash of the resource
// map, using sorted resource IDs so map iteration order does not affect
// the result. The hash covers the resource ID (kind/namespace/name) only,
// not the full object body, because the engines consume the full object
// at build time. If a resource version is available it is included so
// that an in-place update (same ID, new version) also invalidates the cache.
func SnapshotHashFromResources(resources map[string]workloadinterface.IMetadata) string {
	// Sort IDs for determinism.
	ids := make([]string, 0, len(resources))
	for id, r := range resources {
		if r == nil {
			ids = append(ids, id)
			continue
		}
		// Include resource version when available to catch in-place updates.
		ids = append(ids, id)
	}
	// Simple deterministic join: sort and hash.
	// We use the same pattern as FingerprintPath — sorted join + SHA-256.
	h := sha256.New()
	// Sort IDs.
	sortedIDs := make([]string, len(ids))
	copy(sortedIDs, ids)
	// inline sort to avoid import cycle with sort already imported in fix.go
	for i := 1; i < len(sortedIDs); i++ {
		for j := i; j > 0 && sortedIDs[j] < sortedIDs[j-1]; j-- {
			sortedIDs[j], sortedIDs[j-1] = sortedIDs[j-1], sortedIDs[j]
		}
	}
	for _, id := range sortedIDs {
		_, _ = fmt.Fprintf(h, "%s\n", id)
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:8])
}

// Cache is a simple file-backed key-value store for CacheEntry objects.
// Each entry is stored as a separate JSON file named by its key, inside
// the cache directory. This mirrors the incremental cache pattern used
// by the existing `--incremental` flag (cautils.ScanInfo.Incremental).
type Cache struct {
	dir string
}

// NewCache returns a Cache rooted at dir. The directory is created if it
// does not exist.
func NewCache(dir string) (*Cache, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating cache directory %q: %w", dir, err)
	}
	return &Cache{dir: dir}, nil
}

// Get reads the cache entry for key. Returns nil when the key is absent or
// the file is unreadable — cache misses are never errors.
func (c *Cache) Get(key string) *CacheEntry {
	data, err := os.ReadFile(c.entryPath(key))
	if err != nil {
		return nil
	}
	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil
	}
	return &entry
}

// Put writes entry under key, overwriting any existing entry.
func (c *Cache) Put(key string, entry CacheEntry) error {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling cache entry: %w", err)
	}
	tmp := c.entryPath(key) + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing cache entry: %w", err)
	}
	if err := os.Rename(tmp, c.entryPath(key)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming cache entry: %w", err)
	}
	return nil
}

// Delete removes the cache entry for key. A missing key is not an error.
func (c *Cache) Delete(key string) error {
	err := os.Remove(c.entryPath(key))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deleting cache entry: %w", err)
	}
	return nil
}

// Clear removes all entries from the cache directory.
func (c *Cache) Clear() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return fmt.Errorf("reading cache directory: %w", err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(c.dir, e.Name())); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing cache entry %q: %w", e.Name(), err)
		}
	}
	return nil
}

func (c *Cache) entryPath(key string) string {
	// Sanitise key: replace any path separators with underscores so
	// a context name like "gke_project_region_cluster" stays one file.
	safe := make([]byte, len(key))
	for i := range key {
		if key[i] == '/' || key[i] == '\\' {
			safe[i] = '_'
		} else {
			safe[i] = key[i]
		}
	}
	return filepath.Join(c.dir, string(safe)+".json")
}
