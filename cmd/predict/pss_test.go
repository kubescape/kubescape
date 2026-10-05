package predict

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGetPredictCmd(t *testing.T) {
	cmd := GetPredictCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "predict", cmd.Use)

	pssSubCmd, _, err := cmd.Find([]string{"pss"})
	require.NoError(t, err)
	require.NotNil(t, pssSubCmd)
	assert.Equal(t, "pss [<path>...] [flags]", pssSubCmd.Use)

	assert.NotNil(t, pssSubCmd.Flags().Lookup("namespace"))
	assert.NotNil(t, pssSubCmd.Flags().Lookup("level"))
	assert.NotNil(t, pssSubCmd.Flags().Lookup("workload"))
	assert.NotNil(t, pssSubCmd.Flags().Lookup("format"))
	assert.NotNil(t, pssSubCmd.Flags().Lookup("output"))
	assert.NotNil(t, pssSubCmd.Flags().Lookup("verbose"))
}

func TestRunPSS_FlagValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid level", func(t *testing.T) {
		flags := &pssFlags{level: "InvalidLevel"}
		err := runPSS(ctx, flags, []string{"some/file.yaml"})
		assert.ErrorContains(t, err, "invalid PSS level")
	})

	t.Run("unsupported format", func(t *testing.T) {
		flags := &pssFlags{level: "Restricted", format: "invalid-fmt"}
		err := runPSS(ctx, flags, []string{"some/file.yaml"})
		assert.ErrorContains(t, err, "unsupported format")
	})

	t.Run("cluster mode without namespace", func(t *testing.T) {
		flags := &pssFlags{level: "Restricted", format: "pretty-printer", namespace: ""}
		err := runPSS(ctx, flags, nil)
		assert.ErrorContains(t, err, "--namespace (-n) is required")
	})
}

func TestRunPSS_LocalFiles(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	compliantYAML := filepath.Join(tmpDir, "compliant.yaml")
	require.NoError(t, os.WriteFile(compliantYAML, []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: compliant-pod
  namespace: test-ns
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: c1
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
`), 0600))

	violatingYAML := filepath.Join(tmpDir, "violating.yaml")
	require.NoError(t, os.WriteFile(violatingYAML, []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: test-ns
spec:
  containers:
  - name: priv
    image: nginx
    securityContext:
      privileged: true
`), 0600))

	t.Run("all passing returns no error", func(t *testing.T) {
		flags := &pssFlags{
			level:   "Restricted",
			format:  "pretty-printer",
			verbose: true,
		}
		err := runPSS(ctx, flags, []string{compliantYAML})
		assert.NoError(t, err)
	})

	t.Run("violations return error indicating failure", func(t *testing.T) {
		flags := &pssFlags{
			level:  "Restricted",
			format: "json",
		}
		err := runPSS(ctx, flags, []string{violatingYAML})
		assert.Error(t, err)
		assert.ErrorContains(t, err, "PSS compliance check failed")
	})

	t.Run("workload filter matches", func(t *testing.T) {
		flags := &pssFlags{
			level:    "Restricted",
			format:   "table",
			workload: "Pod/compliant-pod",
		}
		err := runPSS(ctx, flags, []string{compliantYAML, violatingYAML})
		assert.NoError(t, err)
	})

	t.Run("workload filter not found returns error", func(t *testing.T) {
		flags := &pssFlags{
			level:    "Restricted",
			format:   "table",
			workload: "Deployment/missing",
		}
		err := runPSS(ctx, flags, []string{compliantYAML})
		assert.ErrorContains(t, err, "workload \"Deployment/missing\" not found")
	})

	t.Run("output to file", func(t *testing.T) {
		outFile := filepath.Join(tmpDir, "out.json")
		flags := &pssFlags{
			level:  "Restricted",
			format: "json",
			output: outFile,
		}
		err := runPSS(ctx, flags, []string{compliantYAML})
		assert.NoError(t, err)

		content, readErr := os.ReadFile(outFile)
		require.NoError(t, readErr)
		assert.Contains(t, string(content), `"total_workloads": 1`)
		assert.Contains(t, string(content), `"passing": 1`)
	})

	t.Run("namespace filter in local mode", func(t *testing.T) {
		// Multi-document file containing one prod pod (compliant) and one dev pod (violating)
		multiNamespaceYAML := filepath.Join(tmpDir, "multi-ns.yaml")
		require.NoError(t, os.WriteFile(multiNamespaceYAML, []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: prod-pod
  namespace: prod
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: c1
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
---
apiVersion: v1
kind: Pod
metadata:
  name: dev-pod
  namespace: dev
spec:
  containers:
  - name: priv
    image: nginx
    securityContext:
      privileged: true
`), 0600))

		// When filtered to namespace prod, only prod-pod is evaluated (compliant -> passes)
		flags := &pssFlags{
			namespace: "prod",
			level:     "Restricted",
			format:    "table",
		}
		err := runPSS(ctx, flags, []string{multiNamespaceYAML})
		assert.NoError(t, err)

		// When filtered to dev, dev-pod is evaluated (violating -> fails)
		flagsDev := &pssFlags{
			namespace: "dev",
			level:     "Restricted",
			format:    "table",
		}
		errDev := runPSS(ctx, flagsDev, []string{multiNamespaceYAML})
		assert.Error(t, errDev)
	})

	t.Run("all unevaluated workloads return incomplete error", func(t *testing.T) {
		malformedYAML := filepath.Join(tmpDir, "malformed.yaml")
		require.NoError(t, os.WriteFile(malformedYAML, []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: malformed-pod
spec: not-a-map
`), 0600))

		flags := &pssFlags{
			level:  "Restricted",
			format: "table",
		}
		err := runPSS(ctx, flags, []string{malformedYAML})
		assert.Error(t, err)
		assert.ErrorContains(t, err, "PSS evaluation incomplete: 1/1 workload(s) could not be evaluated")
	})

	t.Run("mixed passing and unevaluated workloads return incomplete error", func(t *testing.T) {
		mixedYAML := filepath.Join(tmpDir, "mixed-unevaluated.yaml")
		require.NoError(t, os.WriteFile(mixedYAML, []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: compliant-pod
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: c1
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
---
apiVersion: v1
kind: Pod
metadata:
  name: malformed-pod
spec: not-a-map
`), 0600))

		flags := &pssFlags{
			level:  "Restricted",
			format: "table",
		}
		err := runPSS(ctx, flags, []string{mixedYAML})
		assert.Error(t, err)
		assert.ErrorContains(t, err, "PSS evaluation incomplete: 1/2 workload(s) could not be evaluated")
	})

	t.Run("List envelope with violating pod returns compliance failure", func(t *testing.T) {
		listYAML := filepath.Join(tmpDir, "list-violating.yaml")
		require.NoError(t, os.WriteFile(listYAML, []byte(`
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Pod
  metadata:
    name: privileged-in-list
  spec:
    containers:
    - name: priv
      image: nginx
      securityContext:
        privileged: true
`), 0600))

		flags := &pssFlags{
			level:  "Restricted",
			format: "table",
		}
		err := runPSS(ctx, flags, []string{listYAML})
		assert.Error(t, err)
		assert.ErrorContains(t, err, "PSS compliance check failed: 1/1 workload(s) violated target level Restricted")
	})

	t.Run("PodList envelope with violating pod returns compliance failure", func(t *testing.T) {
		podListYAML := filepath.Join(tmpDir, "podlist-violating.yaml")
		require.NoError(t, os.WriteFile(podListYAML, []byte(`
apiVersion: v1
kind: PodList
items:
- metadata:
    name: privileged-in-podlist
  spec:
    containers:
    - name: priv
      image: nginx
      securityContext:
        privileged: true
`), 0600))

		flags := &pssFlags{
			level:  "Restricted",
			format: "table",
		}
		err := runPSS(ctx, flags, []string{podListYAML})
		assert.Error(t, err)
		assert.ErrorContains(t, err, "PSS compliance check failed: 1/1 workload(s) violated target level Restricted")
	})
}

func TestRunPSS_ClusterModeWithMock(t *testing.T) {
	origFetch := fetchClusterWorkloadsFn
	defer func() { fetchClusterWorkloadsFn = origFetch }()

	mockWorkload := unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "cluster-dep",
				"namespace": "production",
			},
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{
						"securityContext": map[string]any{
							"runAsNonRoot": true,
							"seccompProfile": map[string]any{
								"type": "RuntimeDefault",
							},
						},
						"containers": []any{
							map[string]any{
								"name":  "app",
								"image": "app:v1",
								"securityContext": map[string]any{
									"allowPrivilegeEscalation": false,
									"capabilities": map[string]any{
										"drop": []any{"ALL"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	fetchClusterWorkloadsFn = func(ctx context.Context, namespace, filter string) ([]unstructured.Unstructured, error) {
		return []unstructured.Unstructured{mockWorkload}, nil
	}

	flags := &pssFlags{
		namespace: "production",
		level:     "Restricted",
		format:    "table",
	}

	err := runPSS(context.Background(), flags, nil)
	assert.NoError(t, err)
}

func TestFilterWorkloads(t *testing.T) {
	w1 := unstructured.Unstructured{Object: map[string]any{"kind": "Deployment", "metadata": map[string]any{"name": "api"}}}
	w2 := unstructured.Unstructured{Object: map[string]any{"kind": "Pod", "metadata": map[string]any{"name": "api"}}}
	w3 := unstructured.Unstructured{Object: map[string]any{"kind": "Deployment", "metadata": map[string]any{"name": "web"}}}

	workloads := []unstructured.Unstructured{w1, w2, w3}

	// Filter by bare name
	filtered := filterWorkloads(workloads, "api")
	assert.Len(t, filtered, 2)

	// Filter by Kind/Name
	filtered = filterWorkloads(workloads, "Deployment/api")
	require.Len(t, filtered, 1)
	assert.Equal(t, "Deployment", filtered[0].GetKind())
	assert.Equal(t, "api", filtered[0].GetName())

	// Filter case-insensitive kind
	filtered = filterWorkloads(workloads, "pod/api")
	require.Len(t, filtered, 1)
	assert.Equal(t, "Pod", filtered[0].GetKind())
	assert.Equal(t, "api", filtered[0].GetName())

	// Non-matching
	filtered = filterWorkloads(workloads, "non-existent")
	assert.Empty(t, filtered)
}
