package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

var (
	sweepEarlier = time.Date(2026, time.October, 19, 4, 9, 46, 0, time.UTC)
	sweepLater   = sweepEarlier.Add(24 * time.Hour)
)

type sweepObject struct {
	kind, namespace, name string
}

func (o sweepObject) resourceID() string {
	return "v1/" + o.namespace + "/" + o.kind + "/" + o.name
}

// sweepReport builds a cluster-wide report that evaluated controls on objects.
func sweepReport(generatedAt time.Time, controls map[string]apis.ScanningStatus, objects ...sweepObject) *v2.PostureReport {
	pr := &v2.PostureReport{ReportGenerationTime: generatedAt}
	pr.SummaryDetails.Controls = reportsummary.ControlSummaries{}
	var associated []resourcesresults.ResourceAssociatedControl
	for id, status := range controls {
		pr.SummaryDetails.Controls[id] = reportsummary.ControlSummary{
			ControlID:  id,
			StatusInfo: apis.StatusInfo{InnerStatus: status},
		}
		if status != apis.StatusSkipped {
			associated = append(associated, resourcesresults.ResourceAssociatedControl{
				ControlID: id,
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
			})
		}
	}
	for _, o := range objects {
		metadata := map[string]any{"name": o.name}
		if o.namespace != "" {
			metadata["namespace"] = o.namespace
		}
		pr.Resources = append(pr.Resources, reporthandling.Resource{
			ResourceID: o.resourceID(),
			Object:     map[string]any{"apiVersion": "v1", "kind": o.kind, "metadata": metadata},
		})
		pr.Results = append(pr.Results, resourcesresults.Result{
			ResourceID:         o.resourceID(),
			AssociatedControls: associated,
		})
	}
	return pr
}

func newSweepStore() *APIServerStore {
	//nolint:staticcheck // The pinned storage client lacks the summary apply schema required by NewClientset.
	client := fake.NewSimpleClientset()
	return &APIServerStore{
		StorageClient:         client.SpdxV1beta1(),
		namespace:             "kubescape",
		continuousPostureScan: true,
	}
}

func summaryNames(t *testing.T, store *APIServerStore) []string {
	t.Helper()
	list, err := store.StorageClient.WorkloadConfigurationScanSummaries("").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	var out []string
	for _, item := range list.Items {
		out = append(out, item.Namespace+"/"+item.Name)
	}
	return out
}

func scanNames(t *testing.T, store *APIServerStore) []string {
	t.Helper()
	list, err := store.StorageClient.WorkloadConfigurationScans("").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	var out []string
	for _, item := range list.Items {
		out = append(out, item.Namespace+"/"+item.Name)
	}
	return out
}

// listedInFull is the collection of a scan that listed each resource without a
// rule field selector and without failures.
func listedInFull(gvrs ...string) Collection {
	listed := make(map[string]bool, len(gvrs))
	for _, gvr := range gvrs {
		listed[gvr] = true
	}
	return Collection{Listed: listed}
}

// Two full scans through the real persist path: one PersistentVolume is gone
// at the second scan, so its records go, and the live objects' records stay.
func TestSweepOrphanedPostureResults_DeletesRecordsOfDeletedObjects(t *testing.T) {
	ctx := context.Background()
	store := newSweepStore()
	controls := map[string]apis.ScanningStatus{"C-0264": apis.StatusFailed, "C-0012": apis.StatusPassed}
	configMap := sweepObject{kind: "ConfigMap", namespace: "default", name: "demo"}
	live := sweepObject{kind: "PersistentVolume", name: "pvc-live"}
	gone := sweepObject{kind: "PersistentVolume", name: "pvc-0806"}

	require.NoError(t, store.StorePostureReportResults(ctx, sweepReport(sweepEarlier, controls, configMap, live, gone)))
	require.Contains(t, summaryNames(t, store), "kubescape/persistentvolume-pvc-0806")

	latest := sweepReport(sweepLater, controls, configMap, live)
	require.NoError(t, store.StorePostureReportResults(ctx, latest))
	require.NoError(t, store.SweepOrphanedPostureResults(ctx, latest, listedInFull("/v1/configmaps", "/v1/persistentvolumes")))

	want := []string{"default/configmap-demo", "kubescape/persistentvolume-pvc-live"}
	assert.ElementsMatch(t, want, summaryNames(t, store))
	assert.ElementsMatch(t, want, scanNames(t, store))
}

// A resource listed in full with no objects left means the last object of
// its kind is gone, so its record goes too.
func TestSweepOrphanedPostureResults_DeletesRecordsOfTheLastObjectOfAKind(t *testing.T) {
	ctx := context.Background()
	store := newSweepStore()
	controls := map[string]apis.ScanningStatus{"C-0264": apis.StatusFailed}

	require.NoError(t, store.StorePostureReportResults(ctx,
		sweepReport(sweepEarlier, controls, sweepObject{kind: "PersistentVolume", name: "pvc-0806"})))

	latest := sweepReport(sweepLater, controls)
	require.NoError(t, store.SweepOrphanedPostureResults(ctx, latest, listedInFull("/v1/persistentvolumes")))

	assert.Empty(t, summaryNames(t, store))
}

// A record whose resource the scan did not list in full can be missing from
// the report although its object exists, so it stays.
func TestSweepOrphanedPostureResults_KeepsRecordsOfKindsNotListedInFull(t *testing.T) {
	controls := map[string]apis.ScanningStatus{"C-0264": apis.StatusFailed}
	listed := sweepObject{kind: "PersistentVolume", name: "pvc-listed"}
	missed := sweepObject{kind: "PersistentVolume", name: "pvc-missed"}

	tests := map[string]Collection{
		"not listed":                          {Listed: map[string]bool{"/v1/configmaps": true}},
		"listed only with a field selector":   {Listed: map[string]bool{"/v1/persistentvolumes": false}},
		"list failed":                         {Listed: map[string]bool{"/v1/persistentvolumes": true}, Incomplete: []string{"/v1/persistentvolumes"}},
		"discovery failed for the core group": {Listed: map[string]bool{"/v1/persistentvolumes": true}, Incomplete: []string{"discovery:v1"}},
		"discovery failed for all":            {Listed: map[string]bool{"/v1/persistentvolumes": true}, Incomplete: []string{"discovery:*"}},
	}
	for name, collection := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := newSweepStore()
			require.NoError(t, store.StorePostureReportResults(ctx, sweepReport(sweepEarlier, controls, listed, missed)))

			latest := sweepReport(sweepLater, controls, listed)
			require.NoError(t, store.StorePostureReportResults(ctx, latest))
			require.NoError(t, store.SweepOrphanedPostureResults(ctx, latest, collection))

			assert.Contains(t, summaryNames(t, store), "kubescape/persistentvolume-pvc-missed")
		})
	}
}

// Discovery can prefer another version than the one a rule listed, so the
// sweep compares group and resource only.
func TestSweepOrphanedPostureResults_MatchesListedResourceAcrossVersions(t *testing.T) {
	ctx := context.Background()
	record := &v1beta1.WorkloadConfigurationScanSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "poddisruptionbudget-default-gone",
			Namespace: "default",
			Labels: map[string]string{
				helpersv1.ApiGroupMetadataKey:    "policy",
				helpersv1.RelatedKindMetadataKey: "PodDisruptionBudget",
			},
		},
		Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
			Controls: map[string]v1beta1.ScannedControlSummary{"C-0012": {ControlID: "C-0012"}},
		},
	}
	//nolint:staticcheck // The pinned storage client lacks the summary apply schema required by NewClientset.
	client := fake.NewSimpleClientset(record)
	store := &APIServerStore{StorageClient: client.SpdxV1beta1(), namespace: "kubescape"}

	require.NoError(t, store.SweepOrphanedPostureResults(ctx,
		sweepReport(sweepLater, map[string]apis.ScanningStatus{"C-0012": apis.StatusPassed}),
		listedInFull("policy/v1/poddisruptionbudgets")))

	assert.Empty(t, summaryNames(t, store))
}

// A ServiceAccount, Role and binding record can be missing from the report
// when an RBAC resource was listed only in part, while the binding exists.
func TestSweepOrphanedPostureResults_KeepsRBACRecordsWhenRBACNotListedInFull(t *testing.T) {
	controls := map[string]apis.ScanningStatus{"C-0015": apis.StatusPassed}
	rbac := []string{
		"rbac.authorization.k8s.io/v1/roles",
		"rbac.authorization.k8s.io/v1/rolebindings",
		"rbac.authorization.k8s.io/v1/clusterroles",
		"rbac.authorization.k8s.io/v1/clusterrolebindings",
	}
	filtered := listedInFull(rbac...)
	filtered.Listed["rbac.authorization.k8s.io/v1/rolebindings"] = false
	partial := listedInFull(rbac...)
	partial.Incomplete = []string{"rbac.authorization.k8s.io/v1/rolebindings"}

	tests := map[string]struct {
		collection Collection
		want       []string
	}{
		"rolebindings listed with a field selector": {collection: filtered, want: []string{"kubescape/serviceaccount-sa-role-binding"}},
		"rolebindings partial":                      {collection: partial, want: []string{"kubescape/serviceaccount-sa-role-binding"}},
		"rbac listed in full":                       {collection: listedInFull(rbac...)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			record := &v1beta1.WorkloadConfigurationScanSummary{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "serviceaccount-sa-role-binding",
					Namespace: "kubescape",
					Labels: map[string]string{
						helpersv1.RbacResourceMetadataKey: "true",
						helpersv1.RelatedKindMetadataKey:  "ServiceAccount",
					},
				},
				Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
					Controls: map[string]v1beta1.ScannedControlSummary{"C-0015": {ControlID: "C-0015"}},
				},
			}
			//nolint:staticcheck // The pinned storage client lacks the summary apply schema required by NewClientset.
			client := fake.NewSimpleClientset(record)
			store := &APIServerStore{StorageClient: client.SpdxV1beta1(), namespace: "kubescape"}

			require.NoError(t, store.SweepOrphanedPostureResults(ctx, sweepReport(sweepLater, controls), tt.collection))

			assert.Equal(t, tt.want, summaryNames(t, store))
		})
	}
}

// A summary is the only way the sweep finds a record, so when the scan delete
// fails the summary must stay for the next sweep to retry the pair.
func TestSweepOrphanedPostureResults_KeepsSummaryWhenScanDeleteFails(t *testing.T) {
	ctx := context.Background()
	//nolint:staticcheck // The pinned storage client lacks the summary apply schema required by NewClientset.
	client := fake.NewSimpleClientset()
	deleteErr := errors.New("the server is currently unable to handle the request")
	client.PrependReactor("delete", "workloadconfigurationscans", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, deleteErr
	})
	store := &APIServerStore{StorageClient: client.SpdxV1beta1(), namespace: "kubescape", continuousPostureScan: true}
	controls := map[string]apis.ScanningStatus{"C-0264": apis.StatusFailed}

	require.NoError(t, store.StorePostureReportResults(ctx,
		sweepReport(sweepEarlier, controls, sweepObject{kind: "PersistentVolume", name: "pvc-0806"})))

	err := store.SweepOrphanedPostureResults(ctx, sweepReport(sweepLater, controls), listedInFull("/v1/persistentvolumes"))

	assert.ErrorIs(t, err, deleteErr)
	assert.Equal(t, []string{"kubescape/persistentvolume-pvc-0806"}, summaryNames(t, store))
	assert.Equal(t, []string{"kubescape/persistentvolume-pvc-0806"}, scanNames(t, store))
}

// The sweep judges the summary it reads again, not the one it listed: if the
// labels changed in between to a kind the scan did not list in full, it stays.
func TestSweepOrphanedPostureResults_JudgesTheSummaryReadAgain(t *testing.T) {
	ctx := context.Background()
	listed := &v1beta1.WorkloadConfigurationScanSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "persistentvolume-pvc-0806",
			Namespace: "kubescape",
			Labels:    map[string]string{helpersv1.RelatedKindMetadataKey: "PersistentVolume"},
		},
		Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
			Controls: map[string]v1beta1.ScannedControlSummary{"C-0264": {ControlID: "C-0264"}},
		},
	}
	//nolint:staticcheck // The pinned storage client lacks the summary apply schema required by NewClientset.
	client := fake.NewSimpleClientset(listed)
	client.PrependReactor("get", "workloadconfigurationscansummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
		reread := listed.DeepCopy()
		reread.Labels = map[string]string{helpersv1.RelatedKindMetadataKey: "Secret"}
		return true, reread, nil
	})
	store := &APIServerStore{StorageClient: client.SpdxV1beta1(), namespace: "kubescape"}

	require.NoError(t, store.SweepOrphanedPostureResults(ctx,
		sweepReport(sweepLater, map[string]apis.ScanningStatus{"C-0264": apis.StatusPassed}), listedInFull("/v1/persistentvolumes")))

	assert.Equal(t, []string{"kubescape/persistentvolume-pvc-0806"}, summaryNames(t, store))
}

// A single-object scan can rewrite the scan after the sweep read the summary.
// The newer scan stays, and so does its summary.
func TestSweepOrphanedPostureResults_KeepsScanRewrittenSinceTheSummary(t *testing.T) {
	ctx := context.Background()
	name := "persistentvolume-pvc-0806"
	summary := &v1beta1.WorkloadConfigurationScanSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kubescape",
			Labels:    map[string]string{helpersv1.RelatedKindMetadataKey: "PersistentVolume"},
		},
		Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
			Controls: map[string]v1beta1.ScannedControlSummary{"C-0264": {ControlID: "C-0264"}},
		},
	}
	scan := &v1beta1.WorkloadConfigurationScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "kubescape",
			Annotations: annotateReportTime(nil, sweepLater.Add(time.Hour)),
		},
	}
	//nolint:staticcheck // The pinned storage client lacks the summary apply schema required by NewClientset.
	client := fake.NewSimpleClientset(summary, scan)
	store := &APIServerStore{StorageClient: client.SpdxV1beta1(), namespace: "kubescape", continuousPostureScan: true}

	require.NoError(t, store.SweepOrphanedPostureResults(ctx,
		sweepReport(sweepLater, map[string]apis.ScanningStatus{"C-0264": apis.StatusPassed}), listedInFull("/v1/persistentvolumes")))

	assert.Equal(t, []string{"kubescape/" + name}, summaryNames(t, store))
	assert.Equal(t, []string{"kubescape/" + name}, scanNames(t, store))
}

// A scan with a different framework set does not vouch for controls it did
// not run, so it leaves those records alone.
func TestSweepOrphanedPostureResults_KeepsRecordsWithControlsNotEvaluated(t *testing.T) {
	ctx := context.Background()
	store := newSweepStore()

	require.NoError(t, store.StorePostureReportResults(ctx,
		sweepReport(sweepEarlier, map[string]apis.ScanningStatus{"C-0069": apis.StatusFailed}, sweepObject{kind: "Node", name: "ip-10-0-0-1"})))

	latest := sweepReport(sweepLater, map[string]apis.ScanningStatus{
		"C-0012": apis.StatusPassed,
		// Present in the report but skipped, for example for missing input.
		"C-0069": apis.StatusSkipped,
	})
	require.NoError(t, store.SweepOrphanedPostureResults(ctx, latest, listedInFull("/v1/nodes")))

	assert.Contains(t, summaryNames(t, store), "kubescape/node-ip-10-0-0-1")
}

func TestSweepOrphanedPostureResults_KeepsRecordsInExcludedNamespaces(t *testing.T) {
	ctx := context.Background()
	store := newSweepStore()
	controls := map[string]apis.ScanningStatus{"C-0012": apis.StatusPassed}

	require.NoError(t, store.StorePostureReportResults(ctx,
		sweepReport(sweepEarlier, controls, sweepObject{kind: "ConfigMap", namespace: "kube-system", name: "aws-auth"})))

	latest := sweepReport(sweepLater, controls)
	latest.Metadata.ScanMetadata.ExcludedNamespaces = []string{"kube-system"}
	require.NoError(t, store.SweepOrphanedPostureResults(ctx, latest, listedInFull("/v1/configmaps")))

	assert.Equal(t, []string{"kube-system/configmap-aws-auth"}, summaryNames(t, store))
}

func TestSweepOrphanedPostureResults_SkipsScansThatAreNotClusterWide(t *testing.T) {
	controls := map[string]apis.ScanningStatus{"C-0012": apis.StatusPassed}
	stale := sweepObject{kind: "ConfigMap", namespace: "default", name: "demo"}

	tests := map[string]func(*v2.PostureReport){
		"namespace-scoped":      func(pr *v2.PostureReport) { pr.Metadata.ScanMetadata.IncludeNamespaces = []string{"tenant-a"} },
		"not a cluster scan":    func(pr *v2.PostureReport) { pr.Metadata.ScanMetadata.ScanningTarget = v2.File },
		"no report time":        func(pr *v2.PostureReport) { pr.ReportGenerationTime = time.Time{} },
		"no evaluated controls": func(pr *v2.PostureReport) { pr.SummaryDetails.Controls = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := newSweepStore()
			require.NoError(t, store.StorePostureReportResults(ctx, sweepReport(sweepEarlier, controls, stale)))

			latest := sweepReport(sweepLater, controls)
			mutate(latest)
			require.NoError(t, store.SweepOrphanedPostureResults(ctx, latest, listedInFull("/v1/configmaps")))

			assert.Equal(t, []string{"default/configmap-demo"}, summaryNames(t, store))
		})
	}
}

// A record that a later scan wrote (for example a single-object scan that ran
// after this report was generated) is newer than the report and stays.
func TestSweepOrphanedPostureResults_KeepsRecordsNewerThanTheReport(t *testing.T) {
	ctx := context.Background()
	store := newSweepStore()
	controls := map[string]apis.ScanningStatus{"C-0012": apis.StatusPassed}

	require.NoError(t, store.StorePostureReportResults(ctx,
		sweepReport(sweepLater, controls, sweepObject{kind: "ConfigMap", namespace: "default", name: "demo"})))
	require.NoError(t, store.SweepOrphanedPostureResults(ctx, sweepReport(sweepEarlier, controls), listedInFull("/v1/configmaps")))

	assert.Equal(t, []string{"default/configmap-demo"}, summaryNames(t, store))
}

// Records written before reports carried an identity have no report-created-at
// annotation. The first full scan that evaluates their controls removes them.
func TestSweepOrphanedPostureResults_DeletesLegacyRecordsWithoutReportTime(t *testing.T) {
	ctx := context.Background()
	legacy := &v1beta1.WorkloadConfigurationScanSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "persistentvolume-pvc-0806",
			Namespace:   "kubescape",
			Labels:      map[string]string{helpersv1.RelatedKindMetadataKey: "PersistentVolume"},
			Annotations: map[string]string{helpersv1.WlidMetadataKey: "wlid://cluster-c/namespace-/persistentvolume-pvc-0806"},
		},
		Spec: v1beta1.WorkloadConfigurationScanSummarySpec{
			Controls: map[string]v1beta1.ScannedControlSummary{"C-0264": {ControlID: "C-0264"}},
		},
	}
	//nolint:staticcheck // The pinned storage client lacks the summary apply schema required by NewClientset.
	client := fake.NewSimpleClientset(legacy)
	store := &APIServerStore{StorageClient: client.SpdxV1beta1(), namespace: "kubescape"}

	require.NoError(t, store.SweepOrphanedPostureResults(ctx,
		sweepReport(sweepLater, map[string]apis.ScanningStatus{"C-0264": apis.StatusPassed}), listedInFull("/v1/persistentvolumes")))

	assert.Empty(t, summaryNames(t, store))
}
