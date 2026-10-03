package attackpath

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeExceptionsFile(t *testing.T, exceptions []Exception) string {
	t.Helper()
	data, err := json.Marshal(exceptions)
	if err != nil {
		t.Fatalf("marshal exceptions: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "exceptions.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write exceptions file: %v", err)
	}
	return path
}

func TestLoadExceptions_EmptyPathReturnsNil(t *testing.T) {
	exc, err := LoadExceptions("")
	if err != nil || exc != nil {
		t.Errorf("expected nil, nil for empty path; got %v, %v", exc, err)
	}
}

func TestLoadExceptions_MissingFileReturnsEmpty(t *testing.T) {
	exc, err := LoadExceptions("/tmp/does-not-exist-attackpath-test.json")
	if err != nil {
		t.Errorf("expected no error for missing file, got %v", err)
	}
	if exc != nil {
		t.Errorf("expected nil for missing file, got %v", exc)
	}
}

func TestLoadExceptions_ParsesValidFile(t *testing.T) {
	path := writeExceptionsFile(t, []Exception{
		{Fingerprint: "abc123", Reason: "accepted by ops"},
	})
	exc, err := LoadExceptions(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(exc) != 1 || exc[0].Fingerprint != "abc123" {
		t.Errorf("unexpected exceptions: %+v", exc)
	}
}

func TestLoadExceptions_MalformedJSONReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("not json"), 0600)
	if _, err := LoadExceptions(path); err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestActiveExceptions_NoExpiryIsAlwaysActive(t *testing.T) {
	exc := []Exception{{Fingerprint: "abc", Reason: "no expiry"}}
	active := ActiveExceptions(exc)
	if len(active) != 1 {
		t.Errorf("expected 1 active exception, got %d", len(active))
	}
}

func TestActiveExceptions_FutureExpiryIsActive(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	exc := []Exception{{Fingerprint: "abc", ExpiresAt: future}}
	active := ActiveExceptions(exc)
	if len(active) != 1 {
		t.Errorf("expected 1 active exception, got %d", len(active))
	}
}

func TestActiveExceptions_PastExpiryIsInactive(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	exc := []Exception{{Fingerprint: "abc", ExpiresAt: past}}
	active := ActiveExceptions(exc)
	if len(active) != 0 {
		t.Errorf("expected 0 active exceptions (expired), got %d", len(active))
	}
}

func TestActiveExceptions_MalformedDateIsIncluded(t *testing.T) {
	// A typo in the date must not silently suppress the exception.
	exc := []Exception{{Fingerprint: "abc", ExpiresAt: "not-a-date"}}
	active := ActiveExceptions(exc)
	if len(active) != 1 {
		t.Errorf("expected malformed-date exception to be kept, got %d active", len(active))
	}
}

func TestApplyExceptions_MatchingPathIsSuppressed(t *testing.T) {
	g := linearGraph()
	result := FindPaths(g, SearchOptions{})
	if len(result.Paths) == 0 {
		t.Skip("no paths")
	}

	fp := FingerprintPath(result.Paths[0])
	idx := NewExceptionIndex([]Exception{{Fingerprint: fp, Reason: "test"}})

	filtered, suppressed := ApplyExceptions(result, idx)

	if len(filtered.Paths) != len(result.Paths)-1 {
		t.Errorf("expected %d paths after suppression, got %d",
			len(result.Paths)-1, len(filtered.Paths))
	}
	if len(suppressed) != 1 || suppressed[0].Fingerprint != fp {
		t.Errorf("expected 1 suppressed path with fp %s, got %+v", fp, suppressed)
	}
}

func TestApplyExceptions_NonMatchingPathIsKept(t *testing.T) {
	g := linearGraph()
	result := FindPaths(g, SearchOptions{})
	if len(result.Paths) == 0 {
		t.Skip("no paths")
	}

	idx := NewExceptionIndex([]Exception{{Fingerprint: "does-not-match", Reason: "test"}})
	filtered, suppressed := ApplyExceptions(result, idx)

	if len(filtered.Paths) != len(result.Paths) {
		t.Errorf("expected all paths kept, got %d", len(filtered.Paths))
	}
	if len(suppressed) != 0 {
		t.Errorf("expected no suppressed paths, got %d", len(suppressed))
	}
}

func TestApplyExceptions_UncertainEdgeCountRecalculated(t *testing.T) {
	// Build a result with one certain path and one uncertain path.
	internet := Node{ID: nodeID(NodeInternet, "", ""), Kind: NodeInternet}
	ca := Node{ID: nodeID(NodeClusterAdmin, "", "cluster-admin"), Kind: NodeClusterAdmin, Name: "cluster-admin"}
	svc := Node{ID: nodeID(NodeService, "prod", "web"), Kind: NodeService, Namespace: "prod", Name: "web"}

	certainPath := AttackPath{
		Nodes: []Node{internet, ca},
		Edges: []Edge{{From: internet.ID, To: ca.ID, Kind: EdgeEscalates, Evidence: "e", Certain: true}},
	}
	uncertainPath := AttackPath{
		Nodes: []Node{internet, svc, ca},
		Edges: []Edge{
			{From: internet.ID, To: svc.ID, Kind: EdgeExposes, Evidence: "e", Certain: false},
			{From: svc.ID, To: ca.ID, Kind: EdgeEscalates, Evidence: "e", Certain: true},
		},
	}
	result := SearchResult{
		Paths:              []AttackPath{certainPath, uncertainPath},
		UncertainEdgeCount: 1,
	}

	// Suppress the uncertain path.
	fpUncertain := FingerprintPath(uncertainPath)
	idx := NewExceptionIndex([]Exception{{Fingerprint: fpUncertain, Reason: "accepted"}})
	filtered, _ := ApplyExceptions(result, idx)

	if filtered.UncertainEdgeCount != 0 {
		t.Errorf("expected UncertainEdgeCount=0 after suppressing the uncertain path, got %d",
			filtered.UncertainEdgeCount)
	}
}
