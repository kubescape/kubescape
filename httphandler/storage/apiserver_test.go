package storage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewFakeAPIServerStorage(namespace string) *APIServerStore {
	return &APIServerStore{
		StorageClient: fake.NewSimpleClientset().SpdxV1beta1(),
		namespace:     namespace,
	}
}

func Test_getControlsMapFromResult(t *testing.T) {

	controlSummaries := map[string]reportsummary.ControlSummary{
		"C-001": {
			ControlID: "C-001", Name: "Control 1", ScoreFactor: 2.0,
		},
		"C-002": {
			ControlID: "C-002", Name: "Control 2", ScoreFactor: 4.0,
		},
		"C-003": {
			ControlID: "C-003", Name: "Control 3", ScoreFactor: 5.0,
		},
		"C-004": {
			ControlID: "C-004", Name: "Control 4", ScoreFactor: 6.0,
		},
		"C-005": {
			ControlID: "C-005", Name: "Control 5", ScoreFactor: 8.0,
		},
		"C-006": {
			ControlID: "C-006", Name: "Control 6", ScoreFactor: 10.0,
		},
	}
	scanResult := resourcesresults.Result{
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-001", Name: "XXX", Status: apis.StatusInfo{
					InnerStatus: apis.StatusFailed,
					InnerInfo:   "test",
				},
			},
			{
				ControlID: "C-002", Name: "XXX", Status: apis.StatusInfo{
					InnerStatus: apis.StatusPassed,
					SubStatus:   apis.SubStatusException,
					InnerInfo:   "",
				},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						ControlConfigurations: nil,
						Name:                  "rule-1",
						Status:                apis.StatusFailed,
						Paths: []armotypes.PosturePaths{
							{
								ResourceID: "resource-1",
								FailedPath: "failed-path",
							},
						},
						Exception: []armotypes.PostureExceptionPolicy{
							{
								PortalBase: armotypes.PortalBase{
									Name: "exception-1",
								},
							},
						},
						RelatedResourcesIDs: []string{"resource-1"},
					},
				},
			},
		},
	}

	actual := getControlsMapFromResult(context.Background(), &scanResult, controlSummaries)
	assert.Len(t, actual, len(scanResult.AssociatedControls))
	if assert.Len(t, actual["C-002"].Rules, 1) {
		assert.Equal(t, []string{"resource-1"}, actual["C-002"].Rules[0].RelatedResourcesIDs)
	}
}

func TestParseControlSeverity_Nil(t *testing.T) {
	assert.NotPanics(t, func() {
		result := parseControlSeverity(nil)
		assert.Equal(t, v1beta1.ControlSeverity{}, result)
	})
}

func TestGetControlsMapFromResult_MissingControl(t *testing.T) {
	scanResult := resourcesresults.Result{
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-MISSING",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
			},
		},
	}

	assert.NotPanics(t, func() {
		actual := getControlsMapFromResult(context.Background(), &scanResult, reportsummary.ControlSummaries{})
		assert.Contains(t, actual, "C-MISSING")
		assert.Equal(t, v1beta1.ControlSeverity{}, actual["C-MISSING"].Severity)
	})
}

type FakeMetadata struct {
	workloadinterface.IMetadata

	Namespace  string
	ApiVersion string
	Kind       string
	Name       string
	ID         string
}

func (f *FakeMetadata) GetID() string {
	return f.ID
}

func (f *FakeMetadata) GetNamespace() string {
	return f.Namespace
}

func (f *FakeMetadata) GetApiVersion() string {
	return f.ApiVersion
}

func (f *FakeMetadata) GetKind() string {
	return f.Kind
}

func (f *FakeMetadata) GetName() string {
	return f.Name
}

func TestParseWorkloadScanRelatedObjectList(t *testing.T) {
	// Mock input data
	relatedObjects := []workloadinterface.IMetadata{
		&FakeMetadata{
			Namespace:  "test-namespace",
			ApiVersion: "v1",
			Kind:       "Pod",
			Name:       "test-pod",
		},
		&FakeMetadata{
			Namespace:  "",
			ApiVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       "test-deploy",
		},
	}

	result := parseWorkloadScanRelatedObjectList(relatedObjects)

	expected := []v1beta1.WorkloadScanRelatedObject{
		{
			Namespace:  "test-namespace",
			APIGroup:   "",
			APIVersion: "v1",
			Kind:       "Pod",
			Name:       "test-pod",
		},
		{
			Namespace:  "",
			APIGroup:   "apps",
			APIVersion: "v1",
			Kind:       "Deployment",
			Name:       "test-deploy",
		},
	}
	assert.Equal(t, expected, result)

	result = parseWorkloadScanRelatedObjectList(nil)
	assert.Equal(t, []v1beta1.WorkloadScanRelatedObject{}, result)
}

func TestCalculateSeveritiesSummaryFromControls(t *testing.T) {
	fakeControl := func(status apis.ScanningStatus, scoreFactor float32) v1beta1.ScannedControlSummary {
		return v1beta1.ScannedControlSummary{
			Status: v1beta1.ScannedControlStatus{
				Status: string(status),
			},
			Severity: v1beta1.ControlSeverity{
				ScoreFactor: scoreFactor,
			},
		}
	}
	controls := map[string]v1beta1.ScannedControlSummary{
		"control1": fakeControl(apis.StatusFailed, 1.0),  // failed, low
		"control2": fakeControl(apis.StatusFailed, 4.0),  // failed, medium
		"control3": fakeControl(apis.StatusFailed, 7.0),  // failed, high
		"control4": fakeControl(apis.StatusFailed, 9.0),  // failed, critical
		"control5": fakeControl(apis.StatusFailed, 0),    // failed, unknown
		"control6": fakeControl(apis.StatusFailed, 4.0),  // failed, medium
		"control7": fakeControl(apis.StatusPassed, 4.0),  // passed, medium
		"control8": fakeControl(apis.StatusPassed, 10.0), // passed, critical
		"control9": fakeControl(apis.StatusPassed, 10.0), // passed, critical
	}

	expected := v1beta1.WorkloadConfigurationScanSeveritiesSummary{
		Critical: 1,
		High:     1,
		Medium:   2,
		Low:      1,
		Unknown:  1,
	}

	got := calculateSeveritiesSummaryFromControls(controls)
	if got != expected {
		t.Errorf("Expected %+v, but got %+v", expected, got)
	}

}

func TestGetWorkloadScanK8sResourceName(t *testing.T) {
	testCases := []struct {
		name           string
		resource       workloadinterface.IMetadata
		relatedObjects []workloadinterface.IMetadata
		expected       string
	}{
		{
			name: "",
			resource: &FakeMetadata{
				ApiVersion: "v1",
				Kind:       "Pod",
				Namespace:  "default",
				Name:       "mypod",
			},
			relatedObjects: nil,
			expected:       "pod-mypod",
		},
		{
			resource: &FakeMetadata{
				ApiVersion: "",
				Kind:       "Pod",
				Namespace:  "",
				Name:       "mypod",
			},
			relatedObjects: nil,
			expected:       "pod-mypod",
		},
		{
			name: "with related objects (role, rolebinding)",
			resource: &FakeMetadata{
				Kind:      "ServiceAccount",
				Name:      "sa-2",
				Namespace: "kubescape",
			},
			relatedObjects: []workloadinterface.IMetadata{
				&FakeMetadata{
					Kind:      "Role",
					Name:      "myrole",
					Namespace: "namespace-1",
				},
				&FakeMetadata{
					Kind:      "RoleBinding",
					Name:      "myrolebinding",
					Namespace: "namespace-2",
				},
			},
			expected: "serviceaccount-sa-2-role-myrole-rolebinding-myrolebinding",
		},
		{
			name: "with related objects (cluster role, cluster rolebinding)",
			resource: &FakeMetadata{
				Kind:      "ServiceAccount",
				Name:      "sa-1",
				Namespace: "kubescape",
			},
			relatedObjects: []workloadinterface.IMetadata{
				&FakeMetadata{
					Kind: "ClusterRole",
					Name: "myrole",
				},
				&FakeMetadata{
					Kind: "ClusterRoleBinding",
					Name: "myrolebinding",
				},
			},
			expected: "serviceaccount-sa-1-clusterrole-myrole-clusterrolebinding-myrolebinding",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := GetWorkloadScanK8sResourceName(context.Background(), tc.resource, tc.relatedObjects)
			if result != tc.expected {
				t.Errorf("Expected %s, but got %s", tc.expected, result)
			}
			assert.NoError(t, err)
		})
	}
}

func TestGetManifestObjectLabelsAndAnnotations(t *testing.T) {
	tests := []struct {
		name                string
		resource            *FakeMetadata
		relatedObjects      []workloadinterface.IMetadata
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "resource without related objects",
			resource: &FakeMetadata{
				Namespace:  "test-namespace",
				ApiVersion: "v1",
				Kind:       "Pod",
				Name:       "test-pod",
			},
			relatedObjects: []workloadinterface.IMetadata{},
			expectedLabels: map[string]string{
				"kubescape.io/workload-api-group":   "",
				"kubescape.io/workload-api-version": "v1",
				"kubescape.io/workload-kind":        "Pod",
				"kubescape.io/workload-name":        "test-pod",
				"kubescape.io/workload-namespace":   "test-namespace",
			},
			expectedAnnotations: map[string]string{
				"kubescape.io/wlid": "wlid://cluster-minikube/namespace-test-namespace/pod-test-pod",
			},
		},
		{
			name: "with related objects (role, rolebinding)",
			resource: &FakeMetadata{
				Namespace:  "test-namespace",
				ApiVersion: "v1",
				Kind:       "Pod",
				Name:       "test-pod",
			},
			relatedObjects: []workloadinterface.IMetadata{
				&FakeMetadata{
					Namespace:  "test-namespace",
					ApiVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "Role",
					Name:       "test-role",
				},
				&FakeMetadata{
					Namespace:  "test-namespace",
					ApiVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "RoleBinding",
					Name:       "test-role-binding",
				},
			},
			expectedLabels: map[string]string{
				"kubescape.io/workload-api-group":    "",
				"kubescape.io/workload-api-version":  "v1",
				"kubescape.io/workload-kind":         "Pod",
				"kubescape.io/workload-name":         "test-pod",
				"kubescape.io/workload-namespace":    "test-namespace",
				"kubescape.io/rbac-resource":         "true",
				"kubescape.io/role-name":             "test-role",
				"kubescape.io/role-namespace":        "test-namespace",
				"kubescape.io/rolebinding-name":      "test-role-binding",
				"kubescape.io/rolebinding-namespace": "test-namespace",
			},
			expectedAnnotations: map[string]string{
				"kubescape.io/wlid": "wlid://cluster-minikube/namespace-test-namespace/rolebinding-test-role-binding",
			},
		},
		{
			name: "with related objects (clusterrole, clusterrolebinding)",
			resource: &FakeMetadata{
				Namespace:  "test-namespace",
				ApiVersion: "v1",
				Kind:       "Pod",
				Name:       "test-pod",
			},
			relatedObjects: []workloadinterface.IMetadata{
				&FakeMetadata{
					ApiVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRole",
					Name:       "test-role",
				},
				&FakeMetadata{
					ApiVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRoleBinding",
					Name:       "test-role-binding",
				},
			},
			expectedLabels: map[string]string{
				"kubescape.io/workload-api-group":      "",
				"kubescape.io/workload-api-version":    "v1",
				"kubescape.io/workload-kind":           "Pod",
				"kubescape.io/workload-name":           "test-pod",
				"kubescape.io/workload-namespace":      "test-namespace",
				"kubescape.io/rbac-resource":           "true",
				"kubescape.io/clusterrole-name":        "test-role",
				"kubescape.io/clusterrolebinding-name": "test-role-binding",
			},
			expectedAnnotations: map[string]string{
				"kubescape.io/wlid": "wlid://cluster-minikube/namespace-/clusterrolebinding-test-role-binding",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, annotations, err := getManifestObjectLabelsAndAnnotations("minikube", tt.resource, tt.relatedObjects)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedLabels, labels)
			assert.Equal(t, tt.expectedAnnotations, annotations)
		})
	}
}

func Test_RoleBindingResourceTripletToSlug(t *testing.T) {
	tests := []struct {
		name          string
		role          string
		roleBinding   string
		expectedSlugs []string
	}{
		{
			name:        "clusterrolebinding with clusterrole, subject with apigroup",
			role:        "testdata/role_1.json",
			roleBinding: "testdata/rolebinding_1.json",
			expectedSlugs: []string{
				"group-system-serviceaccounts-clusterrole-system-service-account-issuer-discovery-clusterrolebinding-system-service-account-issuer-discovery",
			},
		},
		{
			name:        "clusterrolebinding with clusterrole, subject without apigroup",
			role:        "testdata/role_2.json",
			roleBinding: "testdata/rolebinding_2.json",
			expectedSlugs: []string{
				"serviceaccount-expand-controller-clusterrole-system-controller-expand-controller-clusterrolebinding-system-controller-expand-controller",
			},
		},
		{
			name:        "rolebinding with role, multiple subjects",
			role:        "testdata/role_3.json",
			roleBinding: "testdata/rolebinding_3.json",
			expectedSlugs: []string{
				"user-system-kube-scheduler-role-system--leader-locking-kube-scheduler-rolebinding-system--leader-locking-kube-scheduler",
				"serviceaccount-kube-scheduler-role-system--leader-locking-kube-scheduler-rolebinding-system--leader-locking-kube-scheduler",
			},
		},
	}

	readTestFile := func(fileName string) []byte {
		file, err := os.Open(fileName)
		if err != nil {
			panic(err)
		}
		defer file.Close()

		fileContents, err := io.ReadAll(file)
		if err != nil {
			panic(err)
		}

		return fileContents
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var obj1 map[string]any
			_ = json.Unmarshal(readTestFile(tt.role), &obj1)
			clusterRole := objectsenvelopes.NewObject(obj1)

			var obj2 map[string]any
			_ = json.Unmarshal(readTestFile(tt.roleBinding), &obj2)
			clusterRoleBinding := objectsenvelopes.NewObject(obj2)

			slugs := []string{}

			subjects, _ := workloadinterface.InspectMap(clusterRoleBinding.GetObject(), "subjects")
			if val, ok := subjects.([]any); ok {
				for _, s := range val {
					subject := workloadinterface.NewBaseObject(map[string]any{})

					if subjectObj, ok := s.(map[string]any); ok {
						if name, ok := subjectObj["name"]; ok {
							subject.SetName(name.(string))
						}
						if kind, ok := subjectObj["kind"]; ok {
							subject.SetKind(kind.(string))
						}
						if ns, ok := subjectObj["namespace"]; ok {
							subject.SetNamespace(ns.(string))
						}
						if apiGroup, ok := subjectObj["apiGroup"]; ok {
							subject.SetApiVersion(apiGroup.(string))
						}

						slug, err := names.RoleBindingResourceToSlug(subject, clusterRole, clusterRoleBinding)
						assert.NoError(t, err)
						slugs = append(slugs, slug)
					}
				}
			}

			assert.ElementsMatch(t, tt.expectedSlugs, slugs)
		})
	}
}

func TestStorePostureReportResults_SkipsOrphanedRoleBinding(t *testing.T) {
	store := NewFakeAPIServerStorage("kubescape")
	ctx := context.Background()

	// RegoResponseVector with only 1 related object (RoleBinding, no Role) — simulates an
	// orphaned binding whose referenced Role/ClusterRole has been deleted.
	orphanObj := map[string]any{
		"kind":      "ServiceAccount",
		"name":      "my-sa",
		"namespace": "default",
		"relatedObjects": []any{
			map[string]any{
				"kind":       "RoleBinding",
				"name":       "orphan-binding",
				"namespace":  "default",
				"apiVersion": "rbac.authorization.k8s.io/v1",
			},
		},
	}

	// Normal Pod resource — should be persisted regardless of the orphaned binding above.
	podObj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "test-pod",
			"namespace": "default",
		},
	}

	pr := &v2.PostureReport{
		Resources: []reporthandling.Resource{
			{ResourceID: "orphan-resource-id", Object: orphanObj},
			{ResourceID: "pod-resource-id", Object: podObj},
		},
		Results: []resourcesresults.Result{
			{ResourceID: "orphan-resource-id"},
			{ResourceID: "pod-resource-id"},
		},
	}

	err := store.StorePostureReportResults(ctx, pr)
	assert.NoError(t, err)

	// The Pod summary must be stored; the orphaned binding must be skipped, not abort the run.
	summaries, listErr := store.StorageClient.WorkloadConfigurationScanSummaries("default").List(ctx, metav1.ListOptions{})
	assert.NoError(t, listErr)
	assert.Len(t, summaries.Items, 1)
	assert.Equal(t, "pod-test-pod", summaries.Items[0].Name)
}

func TestStorePostureReportResults_NonRecoverableError(t *testing.T) {
	store := NewFakeAPIServerStorage("kubescape")
	ctx := context.Background()

	// Result whose ResourceID has no matching entry in Resources — this is a non-recoverable
	// build error (findResourceInReport fails) and must not be silently skipped.
	pr := &v2.PostureReport{
		Resources: []reporthandling.Resource{},
		Results: []resourcesresults.Result{
			{ResourceID: "missing-resource-id"},
		},
	}

	err := store.StorePostureReportResults(ctx, pr)
	assert.Error(t, err)
}

func TestMergeMaps(t *testing.T) {
	tests := []struct {
		name     string
		existing map[string]string
		new      map[string]string
		expected map[string]string
	}{
		{
			name:     "merge with no conflicts",
			existing: map[string]string{"key1": "value1"},
			new:      map[string]string{"key2": "value2"},
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "merge with conflicts",
			existing: map[string]string{"key1": "value1"},
			new:      map[string]string{"key1": "newValue1", "key2": "value2"},
			expected: map[string]string{"key1": "newValue1", "key2": "value2"},
		},
		{
			name:     "merge with empty new map",
			existing: map[string]string{"key1": "value1"},
			new:      map[string]string{},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "merge with empty existing map",
			existing: map[string]string{},
			new:      map[string]string{"key1": "value1"},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "merge with both maps empty",
			existing: map[string]string{},
			new:      map[string]string{},
			expected: map[string]string{},
		},
		{
			name:     "merge with nil existing map",
			existing: nil,
			new:      map[string]string{"key1": "value1"},
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "merge with both maps nil",
			existing: nil,
			new:      nil,
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeMaps(tt.existing, tt.new)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRoleAndRoleBindingFromRelatedObjects_SameCategory(t *testing.T) {
	testCases := []struct {
		name           string
		relatedObjects []workloadinterface.IMetadata
	}{
		{
			name: "two Role objects",
			relatedObjects: []workloadinterface.IMetadata{
				&FakeMetadata{Kind: "Role", Name: "role-a", Namespace: "ns"},
				&FakeMetadata{Kind: "Role", Name: "role-b", Namespace: "ns"},
			},
		},
		{
			name: "two RoleBinding objects",
			relatedObjects: []workloadinterface.IMetadata{
				&FakeMetadata{Kind: "RoleBinding", Name: "rb-a", Namespace: "ns"},
				&FakeMetadata{Kind: "RoleBinding", Name: "rb-b", Namespace: "ns"},
			},
		},
		{
			name: "two ClusterRole objects",
			relatedObjects: []workloadinterface.IMetadata{
				&FakeMetadata{Kind: "ClusterRole", Name: "cr-a"},
				&FakeMetadata{Kind: "ClusterRole", Name: "cr-b"},
			},
		},
		{
			name: "two ClusterRoleBinding objects",
			relatedObjects: []workloadinterface.IMetadata{
				&FakeMetadata{Kind: "ClusterRoleBinding", Name: "crb-a"},
				&FakeMetadata{Kind: "ClusterRoleBinding", Name: "crb-b"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			role, roleBinding, err := getRoleAndRoleBindingFromRelatedObjects(tc.relatedObjects)
			assert.True(t, errors.Is(err, ErrIncompleteRelatedObjects))
			assert.Nil(t, role)
			assert.Nil(t, roleBinding)
		})
	}
}

func TestStorePostureReportResults_SkipsSameCategoryRBACObjects(t *testing.T) {
	store := NewFakeAPIServerStorage("kubescape")
	ctx := context.Background()

	sameCategoryObj := map[string]any{
		"kind":      "ServiceAccount",
		"name":      "my-sa",
		"namespace": "default",
		"relatedObjects": []any{
			map[string]any{
				"kind":       "Role",
				"name":       "role-a",
				"namespace":  "default",
				"apiVersion": "rbac.authorization.k8s.io/v1",
			},
			map[string]any{
				"kind":       "Role",
				"name":       "role-b",
				"namespace":  "default",
				"apiVersion": "rbac.authorization.k8s.io/v1",
			},
		},
	}

	podObj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "test-pod",
			"namespace": "default",
		},
	}

	pr := &v2.PostureReport{
		Resources: []reporthandling.Resource{
			{ResourceID: "same-category-resource-id", Object: sameCategoryObj},
			{ResourceID: "pod-resource-id", Object: podObj},
		},
		Results: []resourcesresults.Result{
			{ResourceID: "same-category-resource-id"},
			{ResourceID: "pod-resource-id"},
		},
	}

	err := store.StorePostureReportResults(ctx, pr)
	assert.NoError(t, err)

	summaries, listErr := store.StorageClient.WorkloadConfigurationScanSummaries("default").List(ctx, metav1.ListOptions{})
	assert.NoError(t, listErr)
	assert.Len(t, summaries.Items, 1)
	assert.Equal(t, "pod-test-pod", summaries.Items[0].Name)
}
