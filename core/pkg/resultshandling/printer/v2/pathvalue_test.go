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

	mapSliceObj := map[string]any{
		"spec": map[string]any{
			"containers": []map[string]any{
				{
					"name":  "main",
					"image": "nginx:latest",
					"securityContext": map[string]any{
						"privileged": true,
					},
				},
				{
					"name":  "sidecar",
					"image": "envoy:v1",
				},
			},
		},
	}

	cases := []struct {
		name   string
		obj    map[string]any
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
			obj:    map[string]any{},
			path:   "spec.containers[0].image",
			want:   "",
			wantOK: false,
		},
		{
			name:   "indexed path into []map[string]any",
			obj:    mapSliceObj,
			path:   "spec.containers[0].image",
			want:   "nginx:latest",
			wantOK: true,
		},
		{
			name:   "second index into []map[string]any",
			obj:    mapSliceObj,
			path:   "spec.containers[1].image",
			want:   "envoy:v1",
			wantOK: true,
		},
		{
			name:   "nested key after indexing []map[string]any",
			obj:    mapSliceObj,
			path:   "spec.containers[0].securityContext.privileged",
			want:   "true",
			wantOK: true,
		},
		{
			name:   "out-of-range index into []map[string]any",
			obj:    mapSliceObj,
			path:   "spec.containers[5].image",
			want:   "",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := deploymentObj
			if tc.obj != nil {
				obj = tc.obj
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
		{name: "container env value", kind: "Deployment", path: "spec.template.spec.containers[0].env[1].value", want: true},
		{name: "initContainer env value", kind: "Pod", path: "spec.initContainers[0].env[0].value", want: true},
		{name: "container env name is not sensitive", kind: "Deployment", path: "spec.template.spec.containers[0].env[1].name", want: false},
		{name: "container env valueFrom is not a literal", kind: "Deployment", path: "spec.containers[0].env[0].valueFrom.secretKeyRef.name", want: false},
		{name: "ConfigMap field literally named apiKey is caught", kind: "ConfigMap", path: "data.apiKey", want: true},
		{name: "Deployment field named password is caught regardless of kind", kind: "Deployment", path: "spec.auth.password", want: true},
		{name: "custom resource token field is caught", kind: "MyCustomResource", path: "spec.auth.token", want: true},
		{name: "snake_case db_password is caught after separator normalization", kind: "Deployment", path: "spec.env.db_password", want: true},
		{name: "uppercase API_KEY is caught case-insensitively", kind: "Deployment", path: "spec.API_KEY", want: true},
		{name: "clientSecret is caught", kind: "OAuthClient", path: "spec.clientSecret", want: true},
		{name: "ordinary field name is unaffected", kind: "Deployment", path: "spec.replicas", want: false},
		{name: "keyword is not a false positive for key/apikey", kind: "Deployment", path: "spec.keyword", want: false},
		// Regression: automountServiceAccountToken is a boolean toggle, not a
		// token value - "Token" is a genuine word in it, so it previously
		// matched the "token" pattern as a plain substring.
		{name: "automountServiceAccountToken boolean is not a token value", kind: "Pod", path: "spec.automountServiceAccountToken", want: false},
		{name: "automountServiceAccountToken is unaffected by case/separators", kind: "Pod", path: "spec.automount_service_account_token", want: false},
		{name: "serviceAccountToken projected volume source is not a token value", kind: "Pod", path: "spec.volumes[0].projected.sources[0].serviceAccountToken", want: false},
		{name: "secretName is a reference to a Secret object, not its value", kind: "Pod", path: "spec.volumes[0].secret.secretName", want: false},
		{name: "a field that is actually named token is still caught", kind: "MyCustomResource", path: "spec.auth.token", want: true},
		// Regression: the exceptions above are exceptions for specific
		// Kubernetes API fields, not for their names. A custom resource
		// reusing one of those names is free to store a real credential under
		// it, so it stays redacted - the exception is scoped to the kinds
		// whose schema defines the field and to the path it lives at.
		{name: "custom resource reusing serviceAccountToken is still redacted", kind: "MyCustomResource", path: "spec.serviceAccountToken", want: true},
		{name: "custom resource reusing secretName is still redacted", kind: "MyCustomResource", path: "spec.secretName", want: true},
		{name: "custom resource reusing automountServiceAccountToken is still redacted", kind: "MyCustomResource", path: "spec.automountServiceAccountToken", want: true},
		{name: "custom resource is not excused by borrowing the core path shape", kind: "MyCustomResource", path: "spec.volumes[0].projected.sources[0].serviceAccountToken", want: true},
		{name: "core kind is not excused off its documented path", kind: "Pod", path: "spec.serviceAccountToken", want: true},
		{name: "core kind is not excused for secretName outside a volume", kind: "Pod", path: "spec.containers[0].secretName", want: true},
		// The exceptions still hold where the schemas define them, and a
		// PodSpec field keeps its exception through pod-template nesting.
		{name: "automountServiceAccountToken through a pod template", kind: "Deployment", path: "spec.template.spec.automountServiceAccountToken", want: false},
		{name: "automountServiceAccountToken through a CronJob job template", kind: "CronJob", path: "spec.jobTemplate.spec.template.spec.automountServiceAccountToken", want: false},
		{name: "automountServiceAccountToken at the ServiceAccount root", kind: "ServiceAccount", path: "automountServiceAccountToken", want: false},
		{name: "tokenExpirationSeconds is a lifetime, not a token", kind: "Pod", path: "spec.volumes[0].projected.sources[0].serviceAccountToken.tokenExpirationSeconds", want: false},
		{name: "Ingress TLS secretName references a Secret by name", kind: "Ingress", path: "spec.tls[0].secretName", want: false},
		{name: "a field that is actually named secret is still caught", kind: "OAuthClient", path: "spec.secret", want: true},
		// Regression: an exception is pinned to the field's full canonical
		// parent path, not to a trailing fragment of it. The scanner reads
		// manifests without API schema admission, so a built-in kind can carry
		// a field at a path its schema never defines; matching the parents as a
		// suffix excused those, since the tail still read as PodSpec. They must
		// fail closed - this is a redaction boundary.
		{name: "off-schema PodSpec-shaped tail on a built-in kind is redacted", kind: "Pod", path: "spec.extension.spec.automountServiceAccountToken", want: true},
		{name: "off-schema projected-source tail on a built-in kind is redacted", kind: "Pod", path: "spec.extension.projected.sources[0].serviceAccountToken", want: true},
		{name: "off-schema secret-volume tail on a built-in kind is redacted", kind: "Pod", path: "spec.extension.volumes[0].secret.secretName", want: true},
		{name: "off-schema tokenExpirationSeconds on a built-in kind is redacted", kind: "Pod", path: "spec.extension.sources[0].serviceAccountToken.tokenExpirationSeconds", want: true},
		{name: "pod-template path on a kind without a pod template is redacted", kind: "Pod", path: "spec.template.spec.automountServiceAccountToken", want: true},
		{name: "Pod-shaped path on a workload kind is redacted", kind: "Deployment", path: "spec.automountServiceAccountToken", want: true},
		{name: "off-schema Ingress TLS tail is redacted", kind: "Ingress", path: "spec.extension.tls[0].secretName", want: true},
		{name: "ServiceAccount exception does not extend below the root", kind: "ServiceAccount", path: "spec.automountServiceAccountToken", want: true},
		// Regression: the schema makes volumes, sources and tls lists, so an
		// exception written for them only covers an indexed path. An
		// object-shaped path is a different field that extractValueAtPath
		// resolves perfectly well against a manifest carrying a map there, so
		// matching on keys alone handed it the list's exception.
		{name: "object-shaped volumes is not SecretVolumeSource", kind: "Pod", path: "spec.volumes.secret.secretName", want: true},
		{name: "object-shaped volumes and sources is not a projected token", kind: "Pod", path: "spec.volumes.projected.sources.serviceAccountToken", want: true},
		{name: "object-shaped sources is not a projected token", kind: "Pod", path: "spec.volumes[0].projected.sources.serviceAccountToken", want: true},
		{name: "object-shaped volumes is not a projected token", kind: "Pod", path: "spec.volumes.projected.sources[0].serviceAccountToken", want: true},
		{name: "object-shaped tokenExpirationSeconds parents are redacted", kind: "Pod", path: "spec.volumes.projected.sources.serviceAccountToken.tokenExpirationSeconds", want: true},
		{name: "object-shaped Ingress tls is not IngressTLS", kind: "Ingress", path: "spec.tls.secretName", want: true},
		{name: "object-shaped volumes through a pod template is redacted", kind: "Deployment", path: "spec.template.spec.volumes.secret.secretName", want: true},
		// The mirror of the above: a schema map reached with an index is just
		// as far off-schema as a schema list reached without one.
		{name: "indexed secret map is not SecretVolumeSource", kind: "Pod", path: "spec.volumes[0].secret[0].secretName", want: true},
		{name: "indexed projected map is not a projected token", kind: "Pod", path: "spec.volumes[0].projected[0].sources[0].serviceAccountToken", want: true},
		// An unsubstituted rule placeholder leaves splitPath with no index, so
		// it reads as unindexed and is redacted rather than excused.
		{name: "unresolved list placeholder is redacted", kind: "Pod", path: "spec.volumes[volume_ndx].secret.secretName", want: true},
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
					{ReviewPath: "spec.hostIPC"},
				},
			},
		},
	}

	t.Run("getPath selects ReviewPath", func(t *testing.T) {
		got := enrichedPathsForField(ctrl, deploymentResource, func(p armotypes.PosturePaths) string { return p.ReviewPath })
		require.Len(t, got, 1)
		assert.Equal(t, "spec.hostIPC (current: true)", got[0])
	})

	t.Run("empty obj produces bare path", func(t *testing.T) {
		emptyResource := &mockResource{kind: "Deployment", obj: map[string]any{}}
		got := enrichedPathsForField(ctrl, emptyResource, func(p armotypes.PosturePaths) string { return p.ReviewPath })
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
				{Paths: []armotypes.PosturePaths{{ReviewPath: "data.password"}}},
			},
		}
		got := enrichedPathsForField(secretCtrl, secretResource, func(p armotypes.PosturePaths) string { return p.ReviewPath })
		require.Len(t, got, 1)
		assert.Equal(t, "data.password", got[0])
	})
}

func makeControlWithPaths(failedPaths, reviewPaths []string) *resourcesresults.ResourceAssociatedControl {
	var posturePaths []armotypes.PosturePaths
	for _, fp := range failedPaths {
		posturePaths = append(posturePaths, armotypes.PosturePaths{ReviewPath: fp})
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

func TestReviewPathsWithCurrentValues(t *testing.T) {
	obj := map[string]any{
		"spec": map[string]any{
			"automountServiceAccountToken": true,
		},
	}
	resource := &mockResource{kind: "Pod", obj: obj}

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
						{ReviewPath: "spec.hostPID"},
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

	t.Run("path shared by delete and review path is printed once", func(t *testing.T) {
		// reproduces rules such as C-0012 that assign the same path to both
		// DeletePath and FailedPath - the enriched failed path must not duplicate
		// the bare delete path for the same field
		ctrl := &resourcesresults.ResourceAssociatedControl{
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
				{
					Paths: []armotypes.PosturePaths{
						{ReviewPath: "spec.hostPID", DeletePath: "spec.hostPID"},
					},
				},
			},
		}
		got := AssistedRemediationPathsWithCurrentValues(ctrl, resource)
		assert.Equal(t, []string{"spec.hostPID"}, got)
	})
}

func TestAssistedRemediationPathsWithCurrentValuesFiltered(t *testing.T) {
	secretObj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"data": map[string]any{
			"password": "test-value-for-testing",
		},
	}
	normalObj := map[string]any{
		"spec": map[string]any{
			"hostPID": true,
			"containers": []any{
				map[string]any{
					"securityContext": map[string]any{
						"privileged": true,
					},
				},
			},
		},
	}

	t.Run("non-secret path with showSecrets=false shows value", func(t *testing.T) {
		resource := &mockResource{obj: normalObj, kind: "Pod"}
		ctrl := makeControlWithPaths([]string{"spec.hostPID"}, nil)
		got := AssistedRemediationPathsWithCurrentValuesFiltered(ctrl, resource, false)
		require.Len(t, got, 1)
		assert.Equal(t, "spec.hostPID (current: true)", got[0])
	})

	t.Run("secret path with showSecrets=false is redacted", func(t *testing.T) {
		resource := &mockResource{obj: secretObj, kind: "Secret"}
		ctrl := makeControlWithPaths([]string{"data.password"}, nil)
		got := AssistedRemediationPathsWithCurrentValuesFiltered(ctrl, resource, false)
		require.Len(t, got, 1)
		assert.Equal(t, "data.password (current: "+redactedValue+")", got[0])
		assert.NotContains(t, got[0], "test-value-for-testing")
	})

	t.Run("secret path with showSecrets=true shows actual value", func(t *testing.T) {
		resource := &mockResource{obj: secretObj, kind: "Secret"}
		ctrl := makeControlWithPaths([]string{"data.password"}, nil)
		got := AssistedRemediationPathsWithCurrentValuesFiltered(ctrl, resource, true)
		require.Len(t, got, 1)
		assert.Equal(t, "data.password (current: test-value-for-testing)", got[0])
	})

	t.Run("showSecrets=true extracts non-secret values same as unfiltered", func(t *testing.T) {
		// for non-secret paths, showSecrets=true and the unfiltered variant
		// both extract the current value — result must be identical
		resource := &mockResource{obj: normalObj, kind: "Pod"}
		ctrl := makeControlWithPaths([]string{"spec.containers[0].securityContext.privileged"}, nil)
		got := AssistedRemediationPathsWithCurrentValuesFiltered(ctrl, resource, true)
		require.Len(t, got, 1)
		assert.Equal(t, "spec.containers[0].securityContext.privileged (current: true)", got[0])
	})

	t.Run("container env value with showSecrets=false is redacted", func(t *testing.T) {
		resource := &mockResource{
			kind: "Deployment",
			obj: map[string]any{
				"spec": map[string]any{
					"template": map[string]any{
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"env": []any{
										map[string]any{"name": "LOG_LEVEL", "value": "debug"},
										map[string]any{"name": "DB_PASSWORD", "value": "s3cret"},
									},
								},
							},
						},
					},
				},
			},
		}
		ctrl := makeControlWithPaths([]string{"spec.template.spec.containers[0].env[1].value"}, nil)
		got := AssistedRemediationPathsWithCurrentValuesFiltered(ctrl, resource, false)
		require.Len(t, got, 1)
		assert.Equal(t, "spec.template.spec.containers[0].env[1].value (current: "+redactedValue+")", got[0])
		assert.NotContains(t, got[0], "s3cret")
	})

	t.Run("empty paths returns nil", func(t *testing.T) {
		resource := &mockResource{obj: normalObj, kind: "Pod"}
		ctrl := makeControlWithPaths(nil, nil)
		got := AssistedRemediationPathsWithCurrentValuesFiltered(ctrl, resource, false)
		assert.Nil(t, got)
	})
}

// TestFailedPathValuesObjectShapedSafeFields pins the output boundary the
// safe-field exceptions sit behind. isSensitivePath deciding a path is safe is
// only half the story: failedPathValues then resolves that path and publishes
// the value as Evidence. extractValueAtPath walks an unindexed segment straight
// through a map, so an off-schema object where the schema defines a list
// resolves perfectly well - and if the exception written for the list-shaped
// field covered it too, the value would reach output unredacted.
func TestFailedPathValuesObjectShapedSafeFields(t *testing.T) {
	controlWithFailedPath := func(path string) *resourcesresults.ResourceAssociatedControl {
		return &resourcesresults.ResourceAssociatedControl{
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
				{Paths: []armotypes.PosturePaths{{FailedPath: path}}},
			},
		}
	}

	t.Run("object-shaped volumes does not reach Evidence", func(t *testing.T) {
		resource := &mockResource{kind: "Pod", obj: map[string]any{
			"spec": map[string]any{
				// PodSpec.volumes is a list; this manifest carries a map, so
				// this is not SecretVolumeSource.secretName at all.
				"volumes": map[string]any{
					"secret": map[string]any{"secretName": "inline-credential"},
				},
			},
		}}
		got := failedPathValues(controlWithFailedPath("spec.volumes.secret.secretName"), resource)
		assert.Empty(t, got, "an off-schema object-shaped path must be redacted, not published as Evidence")
	})

	t.Run("object-shaped projected sources does not reach Evidence", func(t *testing.T) {
		resource := &mockResource{kind: "Pod", obj: map[string]any{
			"spec": map[string]any{
				"volumes": map[string]any{
					"projected": map[string]any{
						"sources": map[string]any{"serviceAccountToken": "inline-token"},
					},
				},
			},
		}}
		got := failedPathValues(controlWithFailedPath("spec.volumes.projected.sources.serviceAccountToken"), resource)
		assert.Empty(t, got, "an off-schema object-shaped path must be redacted, not published as Evidence")
	})

	t.Run("object-shaped Ingress tls does not reach Evidence", func(t *testing.T) {
		resource := &mockResource{kind: "Ingress", obj: map[string]any{
			"spec": map[string]any{
				"tls": map[string]any{"secretName": "inline-credential"},
			},
		}}
		got := failedPathValues(controlWithFailedPath("spec.tls.secretName"), resource)
		assert.Empty(t, got, "an off-schema object-shaped path must be redacted, not published as Evidence")
	})

	// The exception still has to work where the schema actually defines it,
	// or this would be a fix by way of redacting everything.
	t.Run("canonical indexed SecretVolumeSource still resolves", func(t *testing.T) {
		resource := &mockResource{kind: "Pod", obj: map[string]any{
			"spec": map[string]any{
				"volumes": []any{
					map[string]any{"secret": map[string]any{"secretName": "referenced-secret"}},
				},
			},
		}}
		got := failedPathValues(controlWithFailedPath("spec.volumes[0].secret.secretName"), resource)
		require.Len(t, got, 1)
		assert.Equal(t, "referenced-secret", got[0].Value)
	})
}
