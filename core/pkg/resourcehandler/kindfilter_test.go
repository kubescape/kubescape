package resourcehandler

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeResource(kind string) workloadinterface.IMetadata {
	obj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":      "test-" + kind,
			"namespace": "default",
		},
	}
	return workloadinterface.NewWorkloadObj(obj)
}

func TestParseKindSet(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]struct{}
	}{
		{
			name:  "empty returns nil",
			input: "",
			want:  nil,
		},
		{
			name:  "single kind",
			input: "Deployment",
			want:  map[string]struct{}{"deployment": {}},
		},
		{
			name:  "multiple kinds normalised to lowercase",
			input: "Deployment,DaemonSet,StatefulSet",
			want:  map[string]struct{}{"deployment": {}, "daemonset": {}, "statefulset": {}},
		},
		{
			name:  "whitespace trimmed",
			input: "  Pod ,  Job  ",
			want:  map[string]struct{}{"pod": {}, "job": {}},
		},
		{
			name:  "only commas returns nil",
			input: ",,,",
			want:  nil,
		},
		{
			name:  "mixed blank and valid",
			input: ",Deployment,",
			want:  map[string]struct{}{"deployment": {}},
		},
		{
			name:  "already lowercase",
			input: "deployment",
			want:  map[string]struct{}{"deployment": {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseKindSet(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKindAllowed(t *testing.T) {
	include := map[string]struct{}{"deployment": {}, "daemonset": {}}
	exclude := map[string]struct{}{"job": {}, "cronjob": {}}

	tests := []struct {
		name    string
		kind    string
		include map[string]struct{}
		exclude map[string]struct{}
		want    bool
	}{
		{"no filters allows all", "deployment", nil, nil, true},
		{"include list passes listed kind", "deployment", include, nil, true},
		{"include list blocks unlisted kind", "pod", include, nil, false},
		{"exclude list blocks excluded kind", "job", nil, exclude, false},
		{"exclude list passes non-excluded kind", "deployment", nil, exclude, true},
		{"both filters: kind in include not in exclude", "deployment", include, exclude, true},
		{"both filters: kind in include and in exclude (exclude wins)", "deployment",
			map[string]struct{}{"deployment": {}},
			map[string]struct{}{"deployment": {}},
			false,
		},
		{"both filters: kind not in include", "pod", include, exclude, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := kindAllowed(tt.kind, tt.include, tt.exclude)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestApplyKindFilter_NoOp(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-deploy": makeResource("Deployment"),
		"id-pod":    makeResource("Pod"),
	}
	k8s := cautils.K8SResources{
		"apps/v1/deployments": {"id-deploy"},
		"v1/pods":             {"id-pod"},
	}

	require.NoError(t, applyKindFilter(k8s, allResources, &cautils.ScanInfo{}, nil))

	assert.Len(t, allResources, 2)
	assert.Len(t, k8s["apps/v1/deployments"], 1)
	assert.Len(t, k8s["v1/pods"], 1)
}

func TestApplyKindFilter_IncludeOnly(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-deploy": makeResource("Deployment"),
		"id-pod":    makeResource("Pod"),
		"id-daemon": makeResource("DaemonSet"),
		"id-job":    makeResource("Job"),
	}
	k8s := cautils.K8SResources{
		"apps/v1/deployments": {"id-deploy"},
		"v1/pods":             {"id-pod"},
		"apps/v1/daemonsets":  {"id-daemon"},
		"batch/v1/jobs":       {"id-job"},
	}

	scanInfo := &cautils.ScanInfo{IncludeKinds: "Deployment,DaemonSet"}
	require.NoError(t, applyKindFilter(k8s, allResources, scanInfo, nil))

	require.Len(t, allResources, 2)
	assert.Contains(t, allResources, "id-deploy")
	assert.Contains(t, allResources, "id-daemon")
	assert.NotContains(t, allResources, "id-pod")
	assert.NotContains(t, allResources, "id-job")

	assert.Len(t, k8s["apps/v1/deployments"], 1)
	assert.Len(t, k8s["apps/v1/daemonsets"], 1)
	assert.NotContains(t, k8s, "v1/pods")
	assert.NotContains(t, k8s, "batch/v1/jobs")
}

func TestApplyKindFilter_ExcludeOnly(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-deploy": makeResource("Deployment"),
		"id-job":    makeResource("Job"),
		"id-cron":   makeResource("CronJob"),
	}
	k8s := cautils.K8SResources{
		"apps/v1/deployments": {"id-deploy"},
		"batch/v1/jobs":       {"id-job"},
		"batch/v1/cronjobs":   {"id-cron"},
	}

	scanInfo := &cautils.ScanInfo{ExcludeKinds: "Job,CronJob"}
	require.NoError(t, applyKindFilter(k8s, allResources, scanInfo, nil))

	require.Len(t, allResources, 1)
	assert.Contains(t, allResources, "id-deploy")
	assert.NotContains(t, k8s, "batch/v1/jobs")
	assert.NotContains(t, k8s, "batch/v1/cronjobs")
	assert.Len(t, k8s["apps/v1/deployments"], 1)
}

func TestApplyKindFilter_BothIncludeAndExclude(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-deploy": makeResource("Deployment"),
		"id-daemon": makeResource("DaemonSet"),
		"id-pod":    makeResource("Pod"),
	}
	k8s := cautils.K8SResources{
		"apps/v1/deployments": {"id-deploy"},
		"apps/v1/daemonsets":  {"id-daemon"},
		"v1/pods":             {"id-pod"},
	}

	scanInfo := &cautils.ScanInfo{
		IncludeKinds: "Deployment,DaemonSet",
		ExcludeKinds: "DaemonSet",
	}
	require.NoError(t, applyKindFilter(k8s, allResources, scanInfo, nil))

	require.Len(t, allResources, 1)
	assert.Contains(t, allResources, "id-deploy")
	assert.NotContains(t, allResources, "id-daemon")
	assert.NotContains(t, allResources, "id-pod")
}

func TestApplyKindFilter_CaseInsensitive(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-deploy": makeResource("Deployment"),
		"id-pod":    makeResource("Pod"),
	}
	k8s := cautils.K8SResources{
		"apps/v1/deployments": {"id-deploy"},
		"v1/pods":             {"id-pod"},
	}

	scanInfo := &cautils.ScanInfo{IncludeKinds: "DEPLOYMENT"}
	require.NoError(t, applyKindFilter(k8s, allResources, scanInfo, nil))

	assert.Len(t, allResources, 1)
	assert.Contains(t, allResources, "id-deploy")
}

func TestApplyKindFilter_EmptyAllResources(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{}
	k8s := cautils.K8SResources{}
	scanInfo := &cautils.ScanInfo{IncludeKinds: "Deployment"}
	require.NoError(t, applyKindFilter(k8s, allResources, scanInfo, nil))
	assert.Empty(t, allResources)
}

func TestApplyKindFilter_MultipleResourcesPerGVR(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-deploy-a": makeResource("Deployment"),
		"id-deploy-b": makeResource("Deployment"),
		"id-pod-a":    makeResource("Pod"),
	}
	k8s := cautils.K8SResources{
		"apps/v1/deployments": {"id-deploy-a", "id-deploy-b"},
		"v1/pods":             {"id-pod-a"},
	}

	scanInfo := &cautils.ScanInfo{ExcludeKinds: "Pod"}
	require.NoError(t, applyKindFilter(k8s, allResources, scanInfo, nil))

	assert.Len(t, allResources, 2)
	assert.Len(t, k8s["apps/v1/deployments"], 2)
	assert.NotContains(t, k8s, "v1/pods")
}

func TestApplyKindFilter_WhitespacePaddedKinds(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-deploy": makeResource("Deployment"),
		"id-pod":    makeResource("Pod"),
	}
	k8s := cautils.K8SResources{
		"apps/v1/deployments": {"id-deploy"},
		"v1/pods":             {"id-pod"},
	}

	scanInfo := &cautils.ScanInfo{IncludeKinds: "  Deployment  ,  "}
	require.NoError(t, applyKindFilter(k8s, allResources, scanInfo, nil))

	assert.Len(t, allResources, 1)
	assert.Contains(t, allResources, "id-deploy")
}

func TestApplyKindFilter_SingleScanConflict_IncludeKinds(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-pod": makeResource("Pod"),
	}
	k8s := cautils.K8SResources{
		"v1/pods": {"id-pod"},
	}
	singleScan := makeResource("Pod")

	scanInfo := &cautils.ScanInfo{IncludeKinds: "Deployment"}
	err := applyKindFilter(k8s, allResources, scanInfo, singleScan)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kind filter excludes the explicitly requested scan target")
	assert.Contains(t, err.Error(), "Pod")
}

func TestApplyKindFilter_SingleScanConflict_ExcludeKinds(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-deploy": makeResource("Deployment"),
	}
	k8s := cautils.K8SResources{
		"apps/v1/deployments": {"id-deploy"},
	}
	singleScan := makeResource("Deployment")

	scanInfo := &cautils.ScanInfo{ExcludeKinds: "Deployment"}
	err := applyKindFilter(k8s, allResources, scanInfo, singleScan)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kind filter excludes the explicitly requested scan target")
	assert.Contains(t, err.Error(), "Deployment")
}

func TestApplyKindFilter_SingleScanAllowed(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-deploy": makeResource("Deployment"),
		"id-pod":    makeResource("Pod"),
	}
	k8s := cautils.K8SResources{
		"apps/v1/deployments": {"id-deploy"},
		"v1/pods":             {"id-pod"},
	}
	singleScan := makeResource("Deployment")

	scanInfo := &cautils.ScanInfo{IncludeKinds: "Deployment"}
	require.NoError(t, applyKindFilter(k8s, allResources, scanInfo, singleScan))

	assert.Len(t, allResources, 1)
	assert.Contains(t, allResources, "id-deploy")
}

func TestApplyKindFilter_SingleScanNilNoConflict(t *testing.T) {
	allResources := map[string]workloadinterface.IMetadata{
		"id-pod": makeResource("Pod"),
	}
	k8s := cautils.K8SResources{
		"v1/pods": {"id-pod"},
	}

	scanInfo := &cautils.ScanInfo{IncludeKinds: "Deployment"}
	require.NoError(t, applyKindFilter(k8s, allResources, scanInfo, nil))
	assert.Empty(t, allResources)
}
