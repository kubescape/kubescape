package resultshandling

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/webhookcoverage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func nsSelectorCollection() *webhookcoverage.Collection {
	exact := admissionregistrationv1.Exact
	return &webhookcoverage.Collection{
		Validating: []admissionregistrationv1.ValidatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{{
				Name:        "w.example",
				MatchPolicy: &exact,
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
					Rule:       admissionregistrationv1.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
				}},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			}},
		}},
		ValidatingSource: webhookcoverage.Source{Available: true},
		MutatingSource:   webhookcoverage.Source{Available: true},
	}
}

func catalogObjects() map[string]workloadinterface.IMetadata {
	deploy := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "web", "namespace": "prod", "labels": map[string]any{"app": "web"}},
	})
	otherDeploy := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "api", "namespace": "uncollected"},
	})
	ns := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": "prod", "labels": map[string]any{"env": "prod"}},
	})
	return map[string]workloadinterface.IMetadata{deploy.GetID(): deploy, otherDeploy.GetID(): otherDeploy, ns.GetID(): ns}
}

func fullyListed() map[string]bool {
	listed := map[string]bool{}
	for _, key := range webhookcoverage.WorkloadResourceKeys() {
		listed[key] = true
	}
	return listed
}

func TestBuildWebhookCoverage_NilWithoutCollection(t *testing.T) {
	assert.Nil(t, buildWebhookCoverage(nil, &cautils.ScanInfo{}))
	assert.Nil(t, buildWebhookCoverage(&cautils.OPASessionObj{AllResources: catalogObjects()}, &cautils.ScanInfo{}),
		"no collected webhook configurations means no analysis, not an empty one")
}

func TestBuildWebhookCoverage_UsesCollectedNamespaceLabels(t *testing.T) {
	scan := &cautils.OPASessionObj{
		AllResources:          catalogObjects(),
		WebhookConfigurations: nsSelectorCollection(),
		ListedGVRs:            fullyListed(),
	}

	a := buildWebhookCoverage(scan, &cautils.ScanInfo{})

	require.NotNil(t, a)
	require.Len(t, a.Workloads, 2)
	byNS := map[string]webhookcoverage.WorkloadAnalysis{}
	for _, w := range a.Workloads {
		byNS[w.Namespace] = w
	}
	prod := byNS["prod"]
	assert.True(t, prod.NamespaceLabelsKnown)
	assert.Equal(t, webhookcoverage.Matched, prod.Results[0].Verdict)

	unknown := byNS["uncollected"]
	assert.False(t, unknown.NamespaceLabelsKnown, "a namespace the scan never collected must not become empty labels")
	assert.Equal(t, webhookcoverage.Indeterminate, unknown.Results[0].Verdict)
	assert.Equal(t, []webhookcoverage.Reason{webhookcoverage.ReasonNamespaceLabelsUnknown}, unknown.Results[0].Reasons)

	// The Namespace object is context, reported as not analyzed rather than lost.
	require.Len(t, a.Skipped, 1)
	assert.Equal(t, "Namespace", a.Skipped[0].Kind)
	assert.True(t, a.Complete())
}

func TestWorkloadsFullyCollected_ConservativeConditions(t *testing.T) {
	base := func() *cautils.OPASessionObj { return &cautils.OPASessionObj{ListedGVRs: fullyListed()} }

	assert.True(t, workloadsFullyCollected(base(), &cautils.ScanInfo{}))
	assert.False(t, workloadsFullyCollected(base(), nil))

	t.Run("a workload resource no control listed", func(t *testing.T) {
		s := base()
		delete(s.ListedGVRs, "apps/v1/deployments")
		assert.False(t, workloadsFullyCollected(s, &cautils.ScanInfo{}))
	})
	t.Run("a workload resource listed only with a field selector", func(t *testing.T) {
		s := base()
		s.ListedGVRs["apps/v1/deployments"] = false
		assert.False(t, workloadsFullyCollected(s, &cautils.ScanInfo{}))
	})
	t.Run("namespace scoping", func(t *testing.T) {
		assert.False(t, workloadsFullyCollected(base(), &cautils.ScanInfo{IncludeNamespaces: "a"}))
		assert.False(t, workloadsFullyCollected(base(), &cautils.ScanInfo{ExcludedNamespaces: "a"}))
	})
	t.Run("label selector", func(t *testing.T) {
		assert.False(t, workloadsFullyCollected(base(), &cautils.ScanInfo{LabelSelector: "app=nginx"}),
			"a label-selector scan collects only matching workloads even when every GVR was listed")
		assert.True(t, workloadsFullyCollected(base(), &cautils.ScanInfo{LabelSelector: ""}))
	})
	t.Run("failed or partial pulls", func(t *testing.T) {
		s := base()
		s.PartialGVRFailures = []cautils.PartialGVRPull{{}}
		assert.False(t, workloadsFullyCollected(s, &cautils.ScanInfo{}))
		s = base()
		s.ScanCoverage.FailedGVRPulls = []cautils.FailedGVRPull{{GVR: "apps/v1/deployments"}}
		assert.False(t, workloadsFullyCollected(s, &cautils.ScanInfo{}))
	})
}

func TestHandleResults_DoesNotAlterControlResults(t *testing.T) {
	scan := &cautils.OPASessionObj{
		AllResources:          catalogObjects(),
		WebhookConfigurations: nsSelectorCollection(),
	}
	rh := &ResultsHandler{ScanData: scan, UiPrinter: &SpyPrinter{}}

	require.NoError(t, rh.HandleResults(t.Context(), &cautils.ScanInfo{}))

	require.NotNil(t, scan.WebhookCoverage)
	assert.False(t, scan.WebhookCoverage.Complete(), "GVRs were not listed, so the workload set is not known to be complete")
	assert.Nil(t, scan.VAPCoverage, "admission-policy analysis is untouched")
}

func TestHandleResults_NoWebhookConfigurationsLeavesCoverageNil(t *testing.T) {
	scan := &cautils.OPASessionObj{AllResources: catalogObjects()}
	rh := &ResultsHandler{ScanData: scan, UiPrinter: &SpyPrinter{}}

	require.NoError(t, rh.HandleResults(t.Context(), &cautils.ScanInfo{}))

	assert.Nil(t, scan.WebhookCoverage)
}

func TestBuildWebhookCoverageExported_MatchesInternalBuilder(t *testing.T) {
	scan := &cautils.OPASessionObj{
		AllResources:          catalogObjects(),
		WebhookConfigurations: nsSelectorCollection(),
		ListedGVRs:            fullyListed(),
	}
	info := &cautils.ScanInfo{}

	got := BuildWebhookCoverage(scan, info)

	require.NotNil(t, got)
	assert.Equal(t, buildWebhookCoverage(scan, info), got)
	assert.True(t, got.Complete())
}

func TestBuildWebhookCoverageExported_ScopedScanStaysIncomplete(t *testing.T) {
	// A scan that listed no workload kind (as a control-scoped scan may) must
	// still yield an analysis, marked incomplete, not a complete one or none.
	scan := &cautils.OPASessionObj{
		AllResources:          catalogObjects(),
		WebhookConfigurations: nsSelectorCollection(),
	}

	got := BuildWebhookCoverage(scan, &cautils.ScanInfo{})

	require.NotNil(t, got)
	assert.False(t, got.SubjectsComplete)
	assert.False(t, got.Complete())
}

func TestBuildWebhookCoverageExported_NilWithoutCollection(t *testing.T) {
	assert.Nil(t, BuildWebhookCoverage(nil, &cautils.ScanInfo{}))
	assert.Nil(t, BuildWebhookCoverage(&cautils.OPASessionObj{AllResources: catalogObjects()}, &cautils.ScanInfo{}))
}
