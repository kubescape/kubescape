package attackpath

import (
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

func TestCacheEntry_IsValid_HashMismatch(t *testing.T) {
	e := CacheEntry{SnapshotHash: "abc", CreatedAt: time.Now()}
	if e.IsValid("xyz") {
		t.Error("expected IsValid=false for hash mismatch")
	}
}

func TestCacheEntry_IsValid_HashMatch_NoTTL(t *testing.T) {
	e := CacheEntry{SnapshotHash: "abc", CreatedAt: time.Now()}
	if !e.IsValid("abc") {
		t.Error("expected IsValid=true for matching hash with no TTL")
	}
}

func TestCacheEntry_IsValid_NotExpired(t *testing.T) {
	e := CacheEntry{
		SnapshotHash: "abc",
		CreatedAt:    time.Now(),
		TTLSeconds:   3600,
	}
	if !e.IsValid("abc") {
		t.Error("expected IsValid=true for entry within TTL")
	}
}

func TestCacheEntry_IsValid_Expired(t *testing.T) {
	e := CacheEntry{
		SnapshotHash: "abc",
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		TTLSeconds:   3600,
	}
	if e.IsValid("abc") {
		t.Error("expected IsValid=false for expired entry")
	}
}

func TestSnapshotHashFromResources_DeterministicAcrossRuns(t *testing.T) {
	r1 := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "web", "namespace": "prod"},
	})
	r2 := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "web-svc", "namespace": "prod"},
	})
	resources := map[string]workloadinterface.IMetadata{
		r1.GetID(): r1,
		r2.GetID(): r2,
	}

	h1 := SnapshotHashFromResources(resources)
	h2 := SnapshotHashFromResources(resources)
	if h1 != h2 {
		t.Errorf("hash must be deterministic: %s vs %s", h1, h2)
	}
}

func TestSnapshotHashFromResources_DifferentResourcesDifferentHash(t *testing.T) {
	r1 := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "web", "namespace": "prod"},
	})
	r2 := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "api", "namespace": "prod"},
	})

	h1 := SnapshotHashFromResources(map[string]workloadinterface.IMetadata{r1.GetID(): r1})
	h2 := SnapshotHashFromResources(map[string]workloadinterface.IMetadata{r2.GetID(): r2})
	if h1 == h2 {
		t.Error("different resources must produce different hashes")
	}
}

func TestSnapshotHashFromResources_EmptyReturnsNonEmpty(t *testing.T) {
	h := SnapshotHashFromResources(map[string]workloadinterface.IMetadata{})
	if h == "" {
		t.Error("expected non-empty hash for empty resource map")
	}
}

func TestCache_PutAndGet(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	entry := CacheEntry{
		SnapshotHash: "abc123",
		CreatedAt:    time.Now(),
		Result:       SearchResult{},
	}
	if err := c.Put("prod", entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got := c.Get("prod")
	if got == nil {
		t.Fatal("expected non-nil entry after Put")
	}
	if got.SnapshotHash != "abc123" {
		t.Errorf("expected hash abc123, got %s", got.SnapshotHash)
	}
}

func TestCache_GetMissingKeyReturnsNil(t *testing.T) {
	c, _ := NewCache(t.TempDir())
	if got := c.Get("does-not-exist"); got != nil {
		t.Errorf("expected nil for missing key, got %+v", got)
	}
}

func TestCache_DeleteRemovesEntry(t *testing.T) {
	c, _ := NewCache(t.TempDir())
	entry := CacheEntry{SnapshotHash: "abc", CreatedAt: time.Now()}
	_ = c.Put("key", entry)
	_ = c.Delete("key")
	if got := c.Get("key"); got != nil {
		t.Error("expected nil after Delete")
	}
}

func TestCache_DeleteMissingKeyIsNotError(t *testing.T) {
	c, _ := NewCache(t.TempDir())
	if err := c.Delete("never-existed"); err != nil {
		t.Errorf("expected no error deleting missing key, got %v", err)
	}
}

func TestCache_ClearRemovesAllEntries(t *testing.T) {
	c, _ := NewCache(t.TempDir())
	_ = c.Put("a", CacheEntry{SnapshotHash: "a", CreatedAt: time.Now()})
	_ = c.Put("b", CacheEntry{SnapshotHash: "b", CreatedAt: time.Now()})
	if err := c.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if c.Get("a") != nil || c.Get("b") != nil {
		t.Error("expected all entries cleared")
	}
}

func TestCache_ContextNameWithSlashIsSafe(t *testing.T) {
	// A context name like "gke_project_region_cluster" or "prod/us-east"
	// must not create subdirectories or path traversal.
	c, _ := NewCache(t.TempDir())
	entry := CacheEntry{SnapshotHash: "abc", CreatedAt: time.Now()}
	if err := c.Put("gke/project/region/cluster", entry); err != nil {
		t.Fatalf("Put with slash in key: %v", err)
	}
	if got := c.Get("gke/project/region/cluster"); got == nil {
		t.Error("expected entry back for key with slashes")
	}
}
