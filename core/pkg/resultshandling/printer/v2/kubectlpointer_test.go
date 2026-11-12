package printer

import (
	"bytes"
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/pathparse"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/jsonpath"
)

func segmentsOf(t *testing.T, path string) []pathSegment {
	t.Helper()
	segments, err := pathparse.ParsePath(path)
	require.NoError(t, err)
	return segments
}

func TestJSONPathExpr(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"spec.hostNetwork", "{.spec.hostNetwork}"},
		{"spec.containers[0].image", "{.spec.containers[0].image}"},
		{"spec.template.spec.containers[1].env[2].name", "{.spec.template.spec.containers[1].env[2].name}"},
		{"metadata.labels[app-name_1]", "{.metadata.labels.app-name_1}"},
		{"metadata.labels[app.kubernetes.io/name]", `{.metadata.labels.app\.kubernetes\.io\/name}`},
		{`metadata.annotations."foo.bar/baz"`, `{.metadata.annotations.foo\.bar\/baz}`},
		{"data['a b']", `{.data.a\ b}`},
		{"data['0']", "{.data.0}"},
		{"data['é']", `{.data.\é}`},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := jsonPathExpr(segmentsOf(t, tt.path))
			require.True(t, ok)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("a key with no spelling gets no expression", func(t *testing.T) {
		for _, path := range []string{`data['a\b']`, "data['a\tb']"} {
			_, ok := jsonPathExpr(segmentsOf(t, path))
			assert.False(t, ok, path)
		}
		_, ok := jsonPathExpr(nil)
		assert.False(t, ok, "no segments")
	})
}

// The commands are only useful if kubectl reads the field the evidence names.
// This evaluates each expression with the JSONPath engine kubectl uses, against
// an object, and compares the result with the value evidence shows for the same
// path. It covers the keys that need escaping: dots, slashes, spaces, digits.
func TestJSONPathReadsTheSameFieldAsTheEvidence(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{
			"labels": map[string]any{
				"app.kubernetes.io/name": "demo",
				"tier":                   "front",
				"with space":             "s p",
				"0":                      "zero-label",
			},
			"annotations": map[string]any{"foo.bar/baz": "annotated"},
		},
		"spec": map[string]any{
			"hostNetwork": true,
			"replicas":    float64(3),
			"containers": []any{
				map[string]any{
					"name":  "app",
					"image": "nginx:1.25",
					"env": []any{
						map[string]any{"name": "A", "value": "1"},
						map[string]any{"name": "B", "value": "two"},
					},
				},
				map[string]any{"name": "side", "image": "busybox"},
			},
		},
		"data": map[string]any{"a b": "ab", "0": "zero-data", "é": "accent"},
	}

	paths := []string{
		"spec.hostNetwork",
		"spec.replicas",
		"spec.containers[0].image",
		"spec.containers[1].name",
		"spec.containers[0].env[1].value",
		"metadata.labels.tier",
		"metadata.labels[app.kubernetes.io/name]",
		"metadata.labels['with space']",
		"metadata.labels['0']",
		`metadata.annotations."foo.bar/baz"`,
		"data['a b']",
		"data['0']",
		"data['é']",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			want, ok := extractValue("", obj, path)
			require.True(t, ok, "the evidence reads a value at this path")

			expr, ok := jsonPathExpr(segmentsOf(t, path))
			require.True(t, ok)

			parser := jsonpath.New("check")
			require.NoError(t, parser.Parse(expr))
			var out bytes.Buffer
			require.NoError(t, parser.Execute(&out, obj))
			assert.Equal(t, want, out.String(), "expression %s", expr)
		})
	}
}

func kubectlWorkload(apiVersion, kind, name, namespace string) *workloadinterface.Workload {
	metadata := map[string]any{"name": name}
	if namespace != "" {
		metadata["namespace"] = namespace
	}
	return workloadinterface.NewWorkloadObj(map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": metadata})
}

func TestKubectlGetCommand(t *testing.T) {
	const hostNetwork = "spec.template.spec.hostNetwork"

	tests := []struct {
		name       string
		resource   *workloadinterface.Workload
		context    string
		kubeconfig string
		path       string
		want       string
	}{
		{
			name:     "a namespaced workload in an API group",
			resource: kubectlWorkload("apps/v1", "Deployment", "demo", "default"),
			path:     hostNetwork,
			want:     "kubectl get deployment.apps demo -n default -o jsonpath='{.spec.template.spec.hostNetwork}'",
		},
		{
			name:     "a core resource has no group",
			resource: kubectlWorkload("v1", "Pod", "demo", "default"),
			path:     "spec.hostNetwork",
			want:     "kubectl get pod demo -n default -o jsonpath='{.spec.hostNetwork}'",
		},
		{
			name:     "a cluster-scoped resource has no namespace",
			resource: kubectlWorkload("rbac.authorization.k8s.io/v1", "ClusterRole", "admin", ""),
			path:     "rules[0].verbs",
			want:     "kubectl get clusterrole.rbac.authorization.k8s.io admin -o jsonpath='{.rules[0].verbs}'",
		},
		{
			name:     "the context the scan ran against",
			resource: kubectlWorkload("v1", "Pod", "demo", "default"),
			context:  "minikube",
			path:     "spec.hostNetwork",
			want:     "kubectl get pod demo -n default --context minikube -o jsonpath='{.spec.hostNetwork}'",
		},
		{
			name:       "the kubeconfig the scan was given",
			resource:   kubectlWorkload("v1", "Pod", "demo", "default"),
			kubeconfig: "/home/me/.kube/prod.yaml",
			context:    "prod",
			path:       "spec.hostNetwork",
			want:       "kubectl get pod demo -n default --kubeconfig /home/me/.kube/prod.yaml --context prod -o jsonpath='{.spec.hostNetwork}'",
		},
		{
			name:       "a kubeconfig path with a space or a quote is quoted for the shell",
			resource:   kubectlWorkload("v1", "Pod", "demo", "default"),
			kubeconfig: "/home/my user/it's.yaml",
			path:       "spec.hostNetwork",
			want:       `kubectl get pod demo -n default --kubeconfig '/home/my user/it'\''s.yaml' -o jsonpath='{.spec.hostNetwork}'`,
		},
		{
			name:     "a context that is a plain word list needs no quotes",
			resource: kubectlWorkload("v1", "Pod", "demo", "default"),
			context:  "arn:aws:eks:us-east-1:123456789012:cluster/prod",
			path:     "spec.hostNetwork",
			want:     "kubectl get pod demo -n default --context arn:aws:eks:us-east-1:123456789012:cluster/prod -o jsonpath='{.spec.hostNetwork}'",
		},
		{
			name:     "a context with a space is quoted",
			resource: kubectlWorkload("v1", "Pod", "demo", "default"),
			context:  "my cluster",
			path:     "spec.hostNetwork",
			want:     "kubectl get pod demo -n default --context 'my cluster' -o jsonpath='{.spec.hostNetwork}'",
		},
		{
			name:     "a label key is escaped for kubectl",
			resource: kubectlWorkload("v1", "Pod", "demo", "default"),
			path:     "metadata.labels[app.kubernetes.io/name]",
			want:     `kubectl get pod demo -n default -o jsonpath='{.metadata.labels.app\.kubernetes\.io\/name}'`,
		},
		{
			name:     "a single quote in a key is quoted for the shell",
			resource: kubectlWorkload("v1", "Pod", "demo", "default"),
			path:     `metadata.labels."it's"`,
			want:     `kubectl get pod demo -n default -o jsonpath='{.metadata.labels.it\'\''s}'`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := kubectlGetCommand(tt.resource, kubectlCluster{kubeconfig: tt.kubeconfig, context: tt.context}, tt.path)
			require.True(t, ok)
			assert.Equal(t, tt.want, got)
		})
	}

	// Values from the scanned resource end up on a command line, so anything
	// that is not a plain name is left out and no command is built.
	refused := []struct {
		name     string
		resource *workloadinterface.Workload
		path     string
	}{
		{"a name that is not a plain name", kubectlWorkload("v1", "Pod", "demo; rm -rf /", "default"), "spec.hostNetwork"},
		{"a namespace that is not a plain name", kubectlWorkload("v1", "Pod", "demo", "default $(id)"), "spec.hostNetwork"},
		{"a kind that is not a plain name", kubectlWorkload("v1", "Po d", "demo", "default"), "spec.hostNetwork"},
		{"an API group that is not a plain name", kubectlWorkload("apps;x/v1", "Deployment", "demo", "default"), "spec.hostNetwork"},
		{"a malformed path", kubectlWorkload("v1", "Pod", "demo", "default"), "spec.containers[*].image"},
		{"an empty path", kubectlWorkload("v1", "Pod", "demo", "default"), ""},
	}
	for _, tt := range refused {
		t.Run("no command for "+tt.name, func(t *testing.T) {
			got, ok := kubectlGetCommand(tt.resource, kubectlCluster{}, tt.path)
			assert.False(t, ok)
			assert.Empty(t, got)
		})
	}
}

func kubectlSummary(controls ...*resourcesresults.ResourceAssociatedControl) *reportsummary.SummaryDetails {
	summaries := reportsummary.ControlSummaries{}
	for _, control := range controls {
		summaries[control.ControlID] = reportsummary.ControlSummary{ControlID: control.ControlID, Name: control.Name, ScoreFactor: 5.0}
	}
	return &reportsummary.SummaryDetails{Controls: summaries}
}

func TestKubectlPointers(t *testing.T) {
	const (
		hostNetwork = "spec.template.spec.hostNetwork"
		readOnlyFS  = "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem"
		envName     = "spec.template.spec.containers[0].env[0].name"
		envValue    = "spec.template.spec.containers[0].env[0].value"
	)
	resource := kubectlWorkload("apps/v1", "Deployment", "demo", "default")
	command := func(path string) string {
		got, ok := kubectlGetCommand(resource, kubectlCluster{}, path)
		require.True(t, ok)
		return got
	}

	failing := shapeControl(
		armotypes.PosturePaths{DeletePath: hostNetwork},
		armotypes.PosturePaths{FixPath: armotypes.FixPath{Path: readOnlyFS, Value: "true"}},
		armotypes.PosturePaths{DeletePath: envName},
		armotypes.PosturePaths{DeletePath: envValue},
	)
	repeated := shapeControl(armotypes.PosturePaths{ReviewPath: hostNetwork})
	repeated.ControlID = "C-0002"
	passing := shapeControl(armotypes.PosturePaths{DeletePath: "spec.replicas"})
	passing.ControlID = "C-0003"
	passing.Status = apis.StatusInfo{InnerStatus: apis.StatusPassed}

	summary := kubectlSummary(failing, repeated, passing)
	controls := []resourcesresults.ResourceAssociatedControl{*failing, *repeated, *passing}

	t.Run("a command for each path, once, in order, without credential values", func(t *testing.T) {
		got := kubectlPointers(controls, summary, resource, kubectlCluster{}, false)
		assert.Equal(t, []string{command(hostNetwork), command(readOnlyFS), command(envName)}, got,
			"the repeated path appears once, the passing control is ignored, and the env value is left out")
	})

	t.Run("--show-secrets includes the credential-shaped path", func(t *testing.T) {
		got := kubectlPointers(controls, summary, resource, kubectlCluster{}, true)
		assert.Equal(t, []string{command(hostNetwork), command(readOnlyFS), command(envName), command(envValue)}, got)
	})

	t.Run("nothing for a control with no paths", func(t *testing.T) {
		none := shapeControl()
		assert.Empty(t, kubectlPointers([]resourcesresults.ResourceAssociatedControl{*none}, kubectlSummary(none), resource, kubectlCluster{}, false))
	})
}

// A cluster scan prints the commands under each resource's table, and only
// then: not for a file scan, and not without --show-evidence.
func TestResourceTableKubectlPointers(t *testing.T) {
	const fixPath = "spec.template.spec.containers[0].securityContext.privileged"
	const want = "  kubectl get deployment.apps demo -n default --context minikube -o jsonpath='{.spec.template.spec.containers[0].securityContext.privileged}'"

	// The session is the file-scan one the line-number tests use, turned into a
	// cluster scan: its resources lose their manifest and the metadata says so.
	clusterSession := func(t *testing.T) *cautils.OPASessionObj {
		t.Helper()
		s := resourceTableLineNumberSession(t, lineNumberManifest, ":0")
		for id := range s.ResourceSource {
			delete(s.ResourceSource, id)
		}
		s.Metadata = &v2.Metadata{}
		s.Metadata.ScanMetadata.ScanningTarget = v2.Cluster
		s.Metadata.ContextMetadata.ClusterContextMetadata = &v2.ClusterMetadata{ContextName: "minikube"}
		return s
	}

	t.Run("a cluster scan with --show-evidence", func(t *testing.T) {
		out := renderResourceTable(t, clusterSession(t), true)
		assert.Contains(t, out, "To see the current values on the cluster:")
		assert.Contains(t, out, want)
		assert.Contains(t, out, fixPath, "the path itself is still in the table")
	})

	t.Run("a cluster scan whose names were anonymized", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "anonymized-*.txt")
		require.NoError(t, err)
		pp := &PrettyPrinter{writer: f, showEvidence: true}
		pp.SetAnonymized(true)
		pp.resourceTable(clusterSession(t))
		require.NoError(t, f.Close())
		out, err := os.ReadFile(f.Name())
		require.NoError(t, err)
		assert.NotContains(t, string(out), "kubectl", "a pseudonym is not a name on the cluster")
	})

	t.Run("the context the scan recorded, not the ambient one", func(t *testing.T) {
		previous := k8sinterface.GetContextName()
		k8sinterface.SetClusterContextName("ambient")
		t.Cleanup(func() { k8sinterface.SetClusterContextName(previous) })

		out := renderResourceTable(t, clusterSession(t), true)
		assert.Contains(t, out, "--context minikube")
		assert.NotContains(t, out, "--context ambient")
	})

	t.Run("the deprecated context field is not read", func(t *testing.T) {
		previous := k8sinterface.GetContextName()
		k8sinterface.SetClusterContextName("ambient")
		t.Cleanup(func() { k8sinterface.SetClusterContextName(previous) })

		s := clusterSession(t)
		s.Metadata.ContextMetadata.ClusterContextMetadata = nil
		s.Metadata.ClusterMetadata.ContextName = "deprecated"
		out := renderResourceTable(t, s, true)
		assert.Contains(t, out, "--context ambient", "without a recorded context the global one is the fallback")
		assert.NotContains(t, out, "deprecated")
	})

	t.Run("a scan given --kubeconfig", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "kubeconfig-*.txt")
		require.NoError(t, err)
		pp := &PrettyPrinter{writer: f, showEvidence: true}
		pp.SetKubeconfig("/home/me/prod.yaml")
		pp.resourceTable(clusterSession(t))
		require.NoError(t, f.Close())
		out, err := os.ReadFile(f.Name())
		require.NoError(t, err)
		assert.Contains(t, string(out), "--kubeconfig /home/me/prod.yaml --context minikube")
	})

	t.Run("a cluster scan without --show-evidence", func(t *testing.T) {
		assert.NotContains(t, renderResourceTable(t, clusterSession(t), false), "kubectl")
	})

	t.Run("a file scan", func(t *testing.T) {
		s := resourceTableLineNumberSession(t, lineNumberManifest, ":0")
		s.Metadata = &v2.Metadata{}
		s.Metadata.ScanMetadata.ScanningTarget = v2.File
		out := renderResourceTable(t, s, true)
		assert.NotContains(t, out, "kubectl")
		assert.Contains(t, out, "(line ", "a file scan keeps its line numbers")
	})
}
