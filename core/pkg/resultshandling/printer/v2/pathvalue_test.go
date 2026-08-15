package printer

import (
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitPath(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []pathSegment
	}{
		{
			name:  "simple key",
			input: "apiVersion",
			want:  []pathSegment{{key: "apiVersion", index: -1}},
		},
		{
			name:  "dotted path",
			input: "spec.securityContext.runAsNonRoot",
			want: []pathSegment{
				{key: "spec", index: -1},
				{key: "securityContext", index: -1},
				{key: "runAsNonRoot", index: -1},
			},
		},
		{
			name:  "array index",
			input: "spec.containers[0].image",
			want: []pathSegment{
				{key: "spec", index: -1},
				{key: "containers", index: 0},
				{key: "image", index: -1},
			},
		},
		{
			name:  "second array element",
			input: "spec.containers[2].securityContext.privileged",
			want: []pathSegment{
				{key: "spec", index: -1},
				{key: "containers", index: 2},
				{key: "securityContext", index: -1},
				{key: "privileged", index: -1},
			},
		},
		{
			name:  "strip leading dot",
			input: ".spec.nodeName",
			want: []pathSegment{
				{key: "spec", index: -1},
				{key: "nodeName", index: -1},
			},
		},
		{
			name:  "strip = suffix (failed path format)",
			input: "spec.containers[0].securityContext.privileged=true",
			want: []pathSegment{
				{key: "spec", index: -1},
				{key: "containers", index: 0},
				{key: "securityContext", index: -1},
				{key: "privileged", index: -1},
			},
		},
		{
			name:  "empty path",
			input: "",
			want:  nil,
		},
		{
			name:  "empty segments from double dot",
			input: "spec..image",
			want: []pathSegment{
				{key: "spec", index: -1},
				{key: "image", index: -1},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitPath(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestAnyToString(t *testing.T) {
	cases := []struct {
		name   string
		input  any
		want   string
		wantOK bool
	}{
		{name: "nil", input: nil, want: "null", wantOK: true},
		{name: "true", input: true, want: "true", wantOK: true},
		{name: "false", input: false, want: "false", wantOK: true},
		{name: "non-empty string", input: "nginx:latest", want: "nginx:latest", wantOK: true},
		{name: "empty string", input: "", want: `""`, wantOK: true},
		{name: "integer float64", input: float64(8080), want: "8080", wantOK: true},
		{name: "fractional float64", input: float64(3.14), want: "3.14", wantOK: true},
		{name: "int", input: int(42), want: "42", wantOK: true},
		{name: "int32", input: int32(1000), want: "1000", wantOK: true},
		{name: "int64", input: int64(99), want: "99", wantOK: true},
		{name: "uint", input: uint(7), want: "7", wantOK: true},
		{name: "uint32", input: uint32(8080), want: "8080", wantOK: true},
		{name: "uint64", input: uint64(65535), want: "65535", wantOK: true},
		{name: "json.Number integer", input: json.Number("3"), want: "3", wantOK: true},
		{name: "json.Number float", input: json.Number("1.5"), want: "1.5", wantOK: true},
		{name: "map renders as compact JSON", input: map[string]any{"k": "v"}, want: `{"k":"v"}`, wantOK: true},
		{name: "map with multiple keys is sorted", input: map[string]any{"b": 1, "a": 2}, want: `{"a":2,"b":1}`, wantOK: true},
		{name: "empty map renders as {}", input: map[string]any{}, want: "{}", wantOK: true},
		{name: "slice renders as compact JSON", input: []any{"a"}, want: `["a"]`, wantOK: true},
		{name: "slice of maps", input: []any{map[string]any{"name": "x"}}, want: `[{"name":"x"}]`, wantOK: true},
		{name: "empty slice renders as []", input: []any{}, want: "[]", wantOK: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := anyToString(tc.input)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractValueAtPath(t *testing.T) {
	deploymentObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "default",
		},
		"spec": map[string]any{
			"securityContext": map[string]any{
				"runAsNonRoot": true,
			},
			"containers": []any{
				map[string]any{
					"name":  "main",
					"image": "nginx:latest",
					"securityContext": map[string]any{
						"privileged":               true,
						"allowPrivilegeEscalation": false,
					},
					"resources": map[string]any{
						"limits": map[string]any{
							"memory": "128Mi",
							"cpu":    float64(500),
						},
					},
					"ports": []any{
						map[string]any{"containerPort": float64(8080)},
						map[string]any{"containerPort": float64(9090)},
					},
				},
				map[string]any{
					"name":  "sidecar",
					"image": "envoy:v1",
					"securityContext": map[string]any{
						"privileged": false,
					},
				},
			},
		},
	}

	cases := []struct {
		name   string
		path   string
		want   string
		wantOK bool
	}{
		{
			name:   "top-level key",
			path:   "apiVersion",
			want:   "apps/v1",
			wantOK: true,
		},
		{
			name:   "nested key",
			path:   "metadata.name",
			want:   "nginx",
			wantOK: true,
		},
		{
			name:   "bool true",
			path:   "spec.securityContext.runAsNonRoot",
			want:   "true",
			wantOK: true,
		},
		{
			name:   "bool false",
			path:   "spec.containers[1].securityContext.privileged",
			want:   "false",
			wantOK: true,
		},
		{
			name:   "array index string",
			path:   "spec.containers[0].image",
			want:   "nginx:latest",
			wantOK: true,
		},
		{
			name:   "second array element",
			path:   "spec.containers[1].image",
			want:   "envoy:v1",
			wantOK: true,
		},
		{
			name:   "deeply nested string",
			path:   "spec.containers[0].resources.limits.memory",
			want:   "128Mi",
			wantOK: true,
		},
		{
			name:   "integer-valued float",
			path:   "spec.containers[0].resources.limits.cpu",
			want:   "500",
			wantOK: true,
		},
		{
			name:   "missing top-level key",
			path:   "status",
			want:   "",
			wantOK: false,
		},
		{
			name:   "missing nested key",
			path:   "spec.containers[0].securityContext.readOnlyRootFilesystem",
			want:   "",
			wantOK: false,
		},
		{
			name:   "out-of-range array index",
			path:   "spec.containers[9].image",
			want:   "",
			wantOK: false,
		},
		{
			name:   "path with = suffix stripped",
			path:   "spec.containers[0].securityContext.privileged=false",
			want:   "true",
			wantOK: true,
		},
		{
			name:   "path with leading dot",
			path:   ".metadata.namespace",
			want:   "default",
			wantOK: true,
		},
		{
			name:   "map value renders as compact JSON",
			path:   "spec.securityContext",
			want:   `{"runAsNonRoot":true}`,
			wantOK: true,
		},
		{
			name:   "nested map value renders as compact JSON",
			path:   "spec.containers[0].securityContext",
			want:   `{"allowPrivilegeEscalation":false,"privileged":true}`,
			wantOK: true,
		},
		{
			name:   "slice value renders as compact JSON",
			path:   "spec.containers[0].ports",
			want:   `[{"containerPort":8080},{"containerPort":9090}]`,
			wantOK: true,
		},
		{
			name:   "empty path",
			path:   "",
			want:   "",
			wantOK: false,
		},
		{
			name:   "empty object",
			path:   "spec.containers[0].image",
			want:   "",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := deploymentObj
			if tc.name == "empty object" {
				obj = map[string]any{}
			}
			got, ok := extractValueAtPath(obj, tc.path)
			assert.Equal(t, tc.wantOK, ok, "ok mismatch")
			assert.Equal(t, tc.want, got, "value mismatch")
		})
	}
}

func TestIsSensitivePath(t *testing.T) {
	cases := []struct {
		name string
		kind string
		path string
		want bool
	}{
		{name: "Secret data key", kind: "Secret", path: "data.password", want: true},
		{name: "Secret data root", kind: "Secret", path: "data", want: true},
		{name: "Secret stringData key", kind: "Secret", path: "stringData.token", want: true},
		{name: "Secret stringData root", kind: "Secret", path: "stringData", want: true},
		{name: "Secret data with = suffix", kind: "Secret", path: "data.password=changed", want: true},
		{name: "Secret data with leading dot", kind: "Secret", path: ".data.password", want: true},
		{name: "Secret data with two leading dots", kind: "Secret", path: "..data.password", want: true},
		{name: "Secret stringData with three leading dots", kind: "Secret", path: "...stringData.token", want: true},
		{name: "Secret non-sensitive field", kind: "Secret", path: "metadata.name", want: false},
		{name: "Deployment data field", kind: "Deployment", path: "data.key", want: false},
		{name: "ConfigMap data field", kind: "ConfigMap", path: "data.config", want: false},
		{name: "empty kind", kind: "", path: "data.key", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isSensitivePath(tc.kind, tc.path))
		})
	}
}

func TestEnrichedPathsForField(t *testing.T) {
	deploymentResource := &mockResource{
		kind: "Deployment",
		obj: map[string]any{
			"spec": map[string]any{
				"hostIPC": true,
			},
		},
	}
	ctrl := &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Paths: []armotypes.PosturePaths{
					{FailedPath: "spec.hostIPC"},
					{ReviewPath: "spec.hostIPC"},
				},
			},
		},
	}

	t.Run("getPath selects FailedPath", func(t *testing.T) {
		got := enrichedPathsForField(ctrl, deploymentResource, func(p armotypes.PosturePaths) string { return p.FailedPath })
		require.Len(t, got, 1)
		assert.Equal(t, "spec.hostIPC (current: true)", got[0])
	})

	t.Run("getPath selects ReviewPath", func(t *testing.T) {
		got := enrichedPathsForField(ctrl, deploymentResource, func(p armotypes.PosturePaths) string { return p.ReviewPath })
		require.Len(t, got, 1)
		assert.Equal(t, "spec.hostIPC (current: true)", got[0])
	})

	t.Run("empty obj produces bare path", func(t *testing.T) {
		emptyResource := &mockResource{kind: "Deployment", obj: map[string]any{}}
		got := enrichedPathsForField(ctrl, emptyResource, func(p armotypes.PosturePaths) string { return p.FailedPath })
		require.Len(t, got, 1)
		assert.Equal(t, "spec.hostIPC", got[0])
	})

	t.Run("Secret data path is suppressed", func(t *testing.T) {
		secretResource := &mockResource{
			kind: "Secret",
			obj: map[string]any{
				"data": map[string]any{
					"password": "XXXXXX",
				},
			},
		}
		secretCtrl := &resourcesresults.ResourceAssociatedControl{
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
				{Paths: []armotypes.PosturePaths{{FailedPath: "data.password"}}},
			},
		}
		got := enrichedPathsForField(secretCtrl, secretResource, func(p armotypes.PosturePaths) string { return p.FailedPath })
		require.Len(t, got, 1)
		assert.Equal(t, "data.password", got[0])
	})
}

func makeControlWithPaths(failedPaths, reviewPaths []string) *resourcesresults.ResourceAssociatedControl {
	var posturePaths []armotypes.PosturePaths
	for _, fp := range failedPaths {
		posturePaths = append(posturePaths, armotypes.PosturePaths{FailedPath: fp})
	}
	for _, rp := range reviewPaths {
		posturePaths = append(posturePaths, armotypes.PosturePaths{ReviewPath: rp})
	}
	return &resourcesresults.ResourceAssociatedControl{
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{Paths: posturePaths},
		},
	}
}

type mockResource struct {
	kind string
	obj  map[string]any
}

func (m *mockResource) GetObject() map[string]any   { return m.obj }
func (m *mockResource) GetApiVersion() string       { return "" }
func (m *mockResource) GetKind() string             { return m.kind }
func (m *mockResource) GetName() string             { return "" }
func (m *mockResource) GetNamespace() string        { return "" }
func (m *mockResource) GetID() string               { return "" }
func (m *mockResource) GetWorkload() map[string]any { return m.obj }
func (m *mockResource) GetObjectType() workloadinterface.ObjectType {
	return workloadinterface.TypeUnknown
}

func (m *mockResource) SetNamespace(string)                {}
func (m *mockResource) SetName(string)                     {}
func (m *mockResource) SetKind(string)                     {}
func (m *mockResource) SetWorkload(map[string]interface{}) {}
func (m *mockResource) SetObject(map[string]interface{})   {}
func (m *mockResource) SetApiVersion(string)               {}

func TestFailedPathsWithCurrentValues(t *testing.T) {
	obj := map[string]any{
		"spec": map[string]any{
			"hostNetwork": true,
			"containers": []any{
				map[string]any{
					"securityContext": map[string]any{
						"privileged": true,
					},
				},
			},
		},
	}
	resource := &mockResource{obj: obj}

	t.Run("value extracted", func(t *testing.T) {
		ctrl := makeControlWithPaths([]string{"spec.containers[0].securityContext.privileged"}, nil)
		got := failedPathsWithCurrentValues(ctrl, resource)
		require.Len(t, got, 1)
		assert.Equal(t, "spec.containers[0].securityContext.privileged (current: true)", got[0])
	})

	t.Run("missing path falls back to bare path", func(t *testing.T) {
		ctrl := makeControlWithPaths([]string{"spec.containers[0].securityContext.readOnlyRootFilesystem"}, nil)
		got := failedPathsWithCurrentValues(ctrl, resource)
		require.Len(t, got, 1)
		assert.Equal(t, "spec.containers[0].securityContext.readOnlyRootFilesystem", got[0])
	})

	t.Run("multiple paths", func(t *testing.T) {
		ctrl := makeControlWithPaths([]string{
			"spec.hostNetwork",
			"spec.containers[0].securityContext.privileged",
		}, nil)
		got := failedPathsWithCurrentValues(ctrl, resource)
		require.Len(t, got, 2)
		assert.Equal(t, "spec.hostNetwork (current: true)", got[0])
		assert.Equal(t, "spec.containers[0].securityContext.privileged (current: true)", got[1])
	})

	t.Run("no failed paths returns nil", func(t *testing.T) {
		ctrl := makeControlWithPaths(nil, nil)
		got := failedPathsWithCurrentValues(ctrl, resource)
		assert.Nil(t, got)
	})

	t.Run("object-valued path is rendered as JSON instead of falling back to bare path", func(t *testing.T) {
		objResource := &mockResource{
			obj: map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"securityContext": map[string]any{
								"privileged": true,
								"capabilities": map[string]any{
									"add": []any{"SYS_ADMIN"},
								},
							},
						},
					},
				},
			},
		}
		ctrl := makeControlWithPaths([]string{"spec.containers[0].securityContext"}, nil)
		got := failedPathsWithCurrentValues(ctrl, objResource)
		require.Len(t, got, 1)
		assert.Equal(t, `spec.containers[0].securityContext (current: {"capabilities":{"add":["SYS_ADMIN"]},"privileged":true})`, got[0])
	})
}

func TestReviewPathsWithCurrentValues(t *testing.T) {
	obj := map[string]any{
		"spec": map[string]any{
			"automountServiceAccountToken": true,
		},
	}
	resource := &mockResource{obj: obj}

	t.Run("value extracted", func(t *testing.T) {
		ctrl := makeControlWithPaths(nil, []string{"spec.automountServiceAccountToken"})
		got := reviewPathsWithCurrentValues(ctrl, resource)
		require.Len(t, got, 1)
		assert.Equal(t, "spec.automountServiceAccountToken (current: true)", got[0])
	})

	t.Run("missing path falls back", func(t *testing.T) {
		ctrl := makeControlWithPaths(nil, []string{"spec.serviceAccountName"})
		got := reviewPathsWithCurrentValues(ctrl, resource)
		require.Len(t, got, 1)
		assert.Equal(t, "spec.serviceAccountName", got[0])
	})
}

func TestAssistedRemediationPathsWithCurrentValues(t *testing.T) {
	obj := map[string]any{
		"spec": map[string]any{
			"hostPID": true,
		},
	}
	resource := &mockResource{obj: obj}

	t.Run("failed path annotated, fix path unchanged", func(t *testing.T) {
		ctrl := &resourcesresults.ResourceAssociatedControl{
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{FailedPath: "spec.hostPID"},
						{FixPath: armotypes.FixPath{Path: "spec.hostPID", Value: "false"}},
					},
				},
			},
		}
		got := AssistedRemediationPathsWithCurrentValues(ctrl, resource)
		assert.Contains(t, got, "spec.hostPID=false")
		assert.Contains(t, got, "spec.hostPID (current: true)")
		assert.Len(t, got, 2)
	})
}
