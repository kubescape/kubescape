package printer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
)

const attackTreeRunCount = 25

// attackTreeSession builds a session holding every resource in both the
// catalog, so the printer can resolve it, and the prioritization map, with
// the given scores.
func attackTreeSession(resourceIDs []string, scores map[string]float64) *cautils.OPASessionObj {
	session := &cautils.OPASessionObj{
		ResourcesPrioritized: map[string]prioritization.PrioritizedResource{},
		ResourceAttackTracks: map[string][]v1alpha1.IAttackTrack{},
		AllResources:         map[string]workloadinterface.IMetadata{},
	}
	for _, id := range resourceIDs {
		session.AllResources[id] = createTestWorkload(id, "Deployment", "prod")
		session.ResourcesPrioritized[id] = prioritization.PrioritizedResource{
			ResourceID: id,
			Score:      scores[id],
		}
	}
	return session
}

// captureAttackTreeOutput runs printAttackTracks into a temporary file, since
// the pretty printer writes to an *os.File.
func captureAttackTreeOutput(t *testing.T, session *cautils.OPASessionObj) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "attack-tree.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating attack tree output file: %v", err)
	}
	defer func() {
		_ = f.Close()
	}()

	prettyPrinter := &PrettyPrinter{writer: f, printAttackTree: true}
	prettyPrinter.printAttackTracks(session)

	if err := f.Sync(); err != nil {
		t.Fatalf("syncing attack tree output: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading attack tree output: %v", err)
	}
	return string(data)
}

// attackTreeNames extracts the printed resource names in output order.
func attackTreeNames(output string) []string {
	var names []string
	for _, line := range strings.Split(output, "\n") {
		if name, ok := strings.CutPrefix(line, "Name: "); ok {
			names = append(names, name)
		}
	}
	return names
}

func requireAttackTreeOrder(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("printed %d resources %v, want %d resources %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("resource %d printed %q, want %q (full order: %v, want %v)", i, got[i], want[i], got, want)
		}
	}
}

func TestPrintAttackTracksBreaksScoreTiesByResourceID(t *testing.T) {
	t.Setenv("ATTACK_TREE_TOP_RESOURCES", "3")
	t.Setenv("ATTACK_TREE_TOP_VECTORS", "0")

	// Four resources share the top score while only three slots are printed,
	// so an unbroken tie decides which resources appear at all.
	resourceIDs := []string{"res-d", "res-c", "res-a", "res-b"}
	scores := map[string]float64{"res-a": 5, "res-b": 5, "res-c": 5, "res-d": 5}
	want := []string{"res-a", "res-b", "res-c"}

	first := captureAttackTreeOutput(t, attackTreeSession(resourceIDs, scores))
	requireAttackTreeOrder(t, attackTreeNames(first), want)

	for run := 1; run < attackTreeRunCount; run++ {
		output := captureAttackTreeOutput(t, attackTreeSession(resourceIDs, scores))
		if output != first {
			t.Fatalf("attack tree output changed between runs:\nrun 0:\n%s\nrun %d:\n%s", first, run, output)
		}
	}
}

func TestPrintAttackTracksOrdersResourcesByScoreThenID(t *testing.T) {
	t.Setenv("ATTACK_TREE_TOP_RESOURCES", "15")
	t.Setenv("ATTACK_TREE_TOP_VECTORS", "0")

	resourceIDs := []string{"res-8", "res-2", "res-5", "res-9", "res-1", "res-7", "res-3", "res-6", "res-4"}
	scores := map[string]float64{
		"res-1": 3, "res-2": 3, "res-3": 3, "res-4": 3,
		"res-5": 2, "res-6": 2,
		"res-7": 1, "res-8": 1, "res-9": 1,
	}
	want := []string{"res-1", "res-2", "res-3", "res-4", "res-5", "res-6", "res-7", "res-8", "res-9"}

	first := captureAttackTreeOutput(t, attackTreeSession(resourceIDs, scores))
	requireAttackTreeOrder(t, attackTreeNames(first), want)

	for run := 1; run < attackTreeRunCount; run++ {
		output := captureAttackTreeOutput(t, attackTreeSession(resourceIDs, scores))
		if output != first {
			t.Fatalf("attack tree output changed between runs:\nrun 0:\n%s\nrun %d:\n%s", first, run, output)
		}
	}
}
