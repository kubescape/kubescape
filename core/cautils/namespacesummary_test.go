package cautils

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func namespacedPod(id, namespace string) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": id, "namespace": namespace},
	})
}

func clusterScopedNode(id string) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata":   map[string]any{"name": id},
	})
}

func withComplianceScore(ctrl reportsummary.ControlSummary, score float32) reportsummary.ControlSummary {
	ctrl.ComplianceScore = &score
	return ctrl
}

// TestBuildNamespaceSummaries_EmptyControlsReturnsNil covers the no-op input:
// no policy set means nothing to score.
func TestBuildNamespaceSummaries_EmptyControlsReturnsNil(t *testing.T) {
	assert.Nil(t, BuildNamespaceSummaries(nil, nil))
}

// TestBuildNamespaceSummaries_CountsEveryControl pins the approved
// convention: a control with no resource in a namespace still counts toward
// that namespace's score, using the control's own already-computed
// ComplianceScore, so every namespace divides by the same TotalControls and
// stays comparable to the others.
func TestBuildNamespaceSummaries_CountsEveryControl(t *testing.T) {
	prodPod := namespacedPod("prod-pod", "prod")
	devPod := namespacedPod("dev-pod", "dev")

	allResources := map[string]workloadinterface.IMetadata{
		prodPod.GetID(): prodPod,
		devPod.GetID():  devPod,
	}

	// C-FAIL fails in dev only, passes in prod.
	failInDev := reportsummary.ControlSummary{ControlID: "C-FAIL"}
	failInDev.Append(&apis.StatusInfo{InnerStatus: apis.StatusPassed}, prodPod.GetID())
	failInDev.Append(&apis.StatusInfo{InnerStatus: apis.StatusFailed}, devPod.GetID())

	// C-EMPTY has no matching resource anywhere in the cluster. It is
	// genuinely irrelevant (Passed with zero resources), so the score
	// wrapper would give it 100, and both namespaces must inherit that.
	empty := withComplianceScore(reportsummary.ControlSummary{ControlID: "C-EMPTY"}, 100)

	controls := reportsummary.ControlSummaries{"C-FAIL": failInDev, "C-EMPTY": empty}

	summaries := BuildNamespaceSummaries(controls, allResources)
	require.Len(t, summaries, 2)

	byNamespace := make(map[string]NamespaceSummary, len(summaries))
	for _, s := range summaries {
		byNamespace[s.Namespace] = s
	}

	prod := byNamespace["prod"]
	require.Equal(t, 2, prod.TotalControls)
	assert.Equal(t, float32(100), prod.ComplianceScore, "C-FAIL passed and C-EMPTY has no resource here, both score 100")
	assert.Equal(t, 0, prod.NonCompliantControls)
	assert.Equal(t, 1, prod.ResourceCount)

	dev := byNamespace["dev"]
	require.Equal(t, 2, dev.TotalControls)
	assert.Equal(t, float32(50), dev.ComplianceScore, "C-FAIL failed (0%) and C-EMPTY has no resource here (100%), averaged over 2 controls")
	assert.Equal(t, 1, dev.NonCompliantControls)
	assert.Equal(t, 1, dev.ResourceCount)

	// worst namespace first
	require.Equal(t, "dev", summaries[0].Namespace)
	require.Equal(t, "prod", summaries[1].Namespace)
}

// TestBuildNamespaceSummaries_NotEvaluatedControlScoresZero is the regression
// test for the blocker: opa-utils' GetControlComplianceScore only returns 100
// for a zero-resource control that is also Passed. A control that could not
// be evaluated (RBAC-restricted collection, a timeout) is zero-resource too
// but scores 0 at the cluster level. Every namespace must inherit that same
// 0, not a free 100, or the namespace view silently hides the coverage gap
// the cluster score is reporting right next to it.
func TestBuildNamespaceSummaries_NotEvaluatedControlScoresZero(t *testing.T) {
	pod := namespacedPod("some-pod", "prod")
	allResources := map[string]workloadinterface.IMetadata{pod.GetID(): pod}

	// C-OK passes cleanly in prod.
	ok := reportsummary.ControlSummary{ControlID: "C-OK"}
	ok.Append(&apis.StatusInfo{InnerStatus: apis.StatusPassed}, pod.GetID())

	// C-NOTEVAL could not be evaluated anywhere (e.g. its resource type
	// failed to collect): zero resources, status Skipped/NotEvaluated, so
	// GetControlComplianceScore returns 0, not 100.
	notEvaluated := withComplianceScore(reportsummary.ControlSummary{
		ControlID: "C-NOTEVAL",
		Status:    apis.StatusSkipped,
	}, 0)

	controls := reportsummary.ControlSummaries{"C-OK": ok, "C-NOTEVAL": notEvaluated}
	summaries := BuildNamespaceSummaries(controls, allResources)

	require.Len(t, summaries, 1)
	assert.Equal(t, "prod", summaries[0].Namespace)
	assert.Equal(t, float32(50), summaries[0].ComplianceScore, "C-OK scores 100, C-NOTEVAL must contribute 0, not 100")
	assert.Equal(t, 1, summaries[0].NonCompliantControls)
}

// TestBuildNamespaceSummaries_ClusterScopedBucket verifies a resource with no
// namespace is grouped under the cluster-scoped bucket rather than dropped.
func TestBuildNamespaceSummaries_ClusterScopedBucket(t *testing.T) {
	node := clusterScopedNode("node-1")
	allResources := map[string]workloadinterface.IMetadata{node.GetID(): node}

	failed := reportsummary.ControlSummary{ControlID: "C-NODE"}
	failed.Append(&apis.StatusInfo{InnerStatus: apis.StatusFailed}, node.GetID())

	summaries := BuildNamespaceSummaries(reportsummary.ControlSummaries{"C-NODE": failed}, allResources)
	require.Len(t, summaries, 1)
	assert.Equal(t, ClusterScopedNamespace, summaries[0].Namespace)
	assert.Equal(t, float32(0), summaries[0].ComplianceScore)
	assert.Equal(t, 1, summaries[0].ResourceCount)
}

// TestBuildNamespaceSummaries_UnknownResourceIDFallsBackToClusterScoped covers
// a resource ID present on a control but absent from AllResources (e.g. a
// resource evaluated in an earlier scope and later dropped from the map).
func TestBuildNamespaceSummaries_UnknownResourceIDFallsBackToClusterScoped(t *testing.T) {
	ctrl := reportsummary.ControlSummary{ControlID: "C-X"}
	ctrl.Append(&apis.StatusInfo{InnerStatus: apis.StatusFailed}, "unknown-id")

	summaries := BuildNamespaceSummaries(reportsummary.ControlSummaries{"C-X": ctrl}, map[string]workloadinterface.IMetadata{})
	require.Len(t, summaries, 1)
	assert.Equal(t, ClusterScopedNamespace, summaries[0].Namespace)
}

// TestBuildNamespaceSummaries_NamespaceWithNoMatchedResourceStillScores
// covers a namespace holding resources that no control's ResourceIDs ever
// reference (every control simply does not apply to them). It must still
// produce a summary instead of being silently absent from the rollup, and
// since the report has only this one, globally-failing control, the
// namespace inherits that same score -- consistent with the cluster number,
// which is the design goal, even though this namespace has no resource of
// its own involved in the failure.
func TestBuildNamespaceSummaries_NamespaceWithNoMatchedResourceStillScores(t *testing.T) {
	untouchedPod := namespacedPod("configmap-only", "quiet-ns")
	allResources := map[string]workloadinterface.IMetadata{untouchedPod.GetID(): untouchedPod}

	// C-OTHER has a resource, but not in quiet-ns, and that resource fails --
	// its cluster-wide ComplianceScore is 0.
	other := withComplianceScore(reportsummary.ControlSummary{ControlID: "C-OTHER"}, 0)
	other.Append(&apis.StatusInfo{InnerStatus: apis.StatusFailed}, "some-other-resource-id")

	summaries := BuildNamespaceSummaries(reportsummary.ControlSummaries{"C-OTHER": other}, allResources)

	byNamespace := make(map[string]NamespaceSummary, len(summaries))
	for _, s := range summaries {
		byNamespace[s.Namespace] = s
	}

	quiet, ok := byNamespace["quiet-ns"]
	require.True(t, ok, "a namespace with a resource must appear even if no control matched a resource in it")
	assert.Equal(t, float32(0), quiet.ComplianceScore)
	assert.Equal(t, 1, quiet.TotalControls)
	assert.Equal(t, 1, quiet.NonCompliantControls)
	assert.Equal(t, 1, quiet.ResourceCount)
}

// TestBuildNamespaceSummaries_UnsetComplianceScoreFallsBackTo100 covers a
// caller that runs BuildNamespaceSummaries before the score wrapper has set
// ControlSummary.ComplianceScore. GetComplianceScore then returns -1, which
// must not leak into the report as a negative score.
func TestBuildNamespaceSummaries_UnsetComplianceScoreFallsBackTo100(t *testing.T) {
	pod := namespacedPod("pod", "prod")
	allResources := map[string]workloadinterface.IMetadata{pod.GetID(): pod}

	// C-ELSEWHERE has no resource in prod and no ComplianceScore set.
	elsewhere := reportsummary.ControlSummary{ControlID: "C-ELSEWHERE"}

	summaries := BuildNamespaceSummaries(reportsummary.ControlSummaries{"C-ELSEWHERE": elsewhere}, allResources)
	require.Len(t, summaries, 1)
	assert.Equal(t, float32(100), summaries[0].ComplianceScore)
}
