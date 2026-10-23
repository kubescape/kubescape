package cel

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	utiljson "k8s.io/apimachinery/pkg/util/json"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

// typedDecode is what the apiserver hands a policy for a built-in kind: the
// manifest decoded into its Go struct and converted back to unstructured.
func typedDecode(t *testing.T, manifest string) map[string]any {
	t.Helper()
	obj, _, err := clientgoscheme.Codecs.UniversalDeserializer().Decode([]byte(manifest), nil, nil)
	require.NoError(t, err)
	u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	require.NoError(t, err)
	return u
}

// rawManifest is the manifest as the scanner holds it, nulls and all.
func rawManifest(t *testing.T, manifest string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, utiljson.Unmarshal([]byte(manifest), &m))
	return m
}

// nullPaths lists every path in v whose value is null.
func nullPaths(v any, prefix []string, out *[][]string) {
	switch x := v.(type) {
	case nil:
		*out = append(*out, append([]string{}, prefix...))
	case map[string]any:
		for k, val := range x {
			nullPaths(val, append(prefix, k), out)
		}
	case []any:
		for i, val := range x {
			nullPaths(val, append(prefix, fmt.Sprintf("[%d]", i)), out)
		}
	}
}

func lookup(v any, path []string) (any, bool) {
	for _, p := range path {
		switch x := v.(type) {
		case map[string]any:
			next, ok := x[p]
			if !ok {
				return nil, false
			}
			v = next
		case []any:
			var i int
			if _, err := fmt.Sscanf(p, "[%d]", &i); err != nil || i >= len(x) {
				return nil, false
			}
			v = x[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// Every null in a built-in kind must come out exactly as the apiserver's typed
// decoding leaves it: gone, a zero value, or a key or index that is kept.
func TestNormalizeNullFieldsMatchesTypedDecoding(t *testing.T) {
	for name, manifest := range map[string]string{ // #nosec G101 -- null-valued Secret fixture, not a hardcoded credential
		"pod": `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","labels":null,"annotations":{"kept":null,"other":"x"}},
			"spec":{"hostPID":null,"volumes":null,"initContainers":null,"securityContext":null,
			"containers":[{"name":"c","image":"i","env":null,"args":["x",null],"resources":null,
				"ports":[{"containerPort":null,"hostPort":null}],
				"securityContext":{"privileged":null,"capabilities":null}}, null]}}`,
		"configmap": `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c"},"data":{"blocked":null,"ok":"v"},"binaryData":{"b":null}}`,
		"secret":    `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s"},"stringData":{"k":null},"data":{"d":null}}`,
		"service":   `{"apiVersion":"v1","kind":"Service","metadata":{"name":"s","annotations":null},"spec":{"type":"LoadBalancer","ports":[{"port":443,"targetPort":null,"nodePort":null}]}}`,
		"quantity":  `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"},"spec":{"containers":[{"name":"c","image":"i","resources":{"limits":{"cpu":null}}}]}}`,
		"deployment": `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"d"},"spec":{"replicas":null,"strategy":null,
			"selector":{"matchLabels":{"a":"b"}},"template":{"metadata":{"annotations":null},"spec":{"containers":[{"name":"c","image":"i","env":null}]}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			raw := rawManifest(t, manifest)
			want := typedDecode(t, manifest)
			got := normalizeNullFields(raw)

			var paths [][]string
			nullPaths(raw, nil, &paths)
			require.NotEmpty(t, paths)
			sort.Slice(paths, func(i, j int) bool { return strings.Join(paths[i], ".") < strings.Join(paths[j], ".") })
			for _, p := range paths {
				wantVal, wantOK := lookup(want, p)
				gotVal, gotOK := lookup(got, p)
				assert.Equalf(t, wantOK, gotOK, "%s: present after typed decoding = %v", strings.Join(p, "."), wantOK)
				assert.Equalf(t, wantVal, gotVal, "%s", strings.Join(p, "."))
			}
		})
	}
}

func TestNormalizeNullFieldsLeavesInputAlone(t *testing.T) {
	in := rawManifest(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","annotations":null},"spec":{"volumes":null,"containers":[{"name":"c","image":"i"}]}}`)
	normalizeNullFields(in)
	assert.Contains(t, in["metadata"], "annotations", "input must not be mutated")
	assert.Contains(t, in["spec"], "volumes", "input must not be mutated")
}

func TestNormalizeNullFieldsReturnsTheSameMapWithoutNulls(t *testing.T) {
	in := map[string]any{"apiVersion": "v1", "kind": "Pod", "spec": map[string]any{"containers": []any{map[string]any{"name": "c"}}}}
	out := normalizeNullFields(in)
	assert.Equal(t, reflect.ValueOf(in).Pointer(), reflect.ValueOf(out).Pointer(), "no nulls means no copy")
}

// A custom resource keeps its nulls: the CRD may declare the field nullable,
// and then admission keeps the null as well.
func TestNormalizeNullFieldsLeavesCustomResourcesAlone(t *testing.T) {
	cr := map[string]any{"apiVersion": "example.com/v1", "kind": "Widget", "metadata": map[string]any{"name": "w"}, "spec": map[string]any{"foo": nil}}
	assert.Equal(t, reflect.ValueOf(cr).Pointer(), reflect.ValueOf(normalizeNullFields(cr)).Pointer())

	e, err := NewEvaluator()
	require.NoError(t, err)
	results, err := e.EvaluateOnObject(context.Background(), cr, nil, nil, nil,
		[]Validation{{Expression: "!has(object.spec.foo) || object.spec.foo != null"}})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Err)
	assert.False(t, results[0].Passed, "an explicit null on a custom resource is still a null")
}

// A null entry in a map of strings keeps its key, so membership checks see it.
func TestNullMapEntryKeepsItsKey(t *testing.T) {
	cm := rawManifest(t, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c","namespace":"ns"},"data":{"blocked":null}}`)
	e, err := NewEvaluator()
	require.NoError(t, err)
	results, err := e.EvaluateOnObject(context.Background(), cm, nil, nil, nil,
		[]Validation{{Expression: "!('blocked' in object.data)"}, {Expression: "object.data.blocked == ''"}})
	require.NoError(t, err)
	require.Len(t, results, 2)
	for i, r := range results {
		assert.NoErrorf(t, r.Err, "validation %d", i)
	}
	assert.False(t, results[0].Passed, "the key is still there after typed decoding")
	assert.True(t, results[1].Passed, "and its value is the empty string")
}

// An empty manifest block decodes to null. At admission the typed decode drops
// it, so these bundle controls admit the pod; they must not error offline.
func TestBundleTreatsNullFieldsAsUnset(t *testing.T) {
	pod := rawManifest(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"ns"},
		"spec":{"volumes":null,"initContainers":null,"containers":[{"name":"c","image":"nginx:1.25","env":null,"ports":null}]}}`)
	e, err := NewEvaluator()
	require.NoError(t, err)
	for _, id := range []string{"C-0012", "C-0020", "C-0042", "C-0044", "C-0045", "C-0046", "C-0048", "C-0057", "C-0074", "C-0193", "C-0203", "C-0204", "C-0207", "C-0295"} {
		vap, err := loadVAP(id)
		require.NoError(t, err, id)
		params, err := resolveParams(vap)
		require.NoError(t, err, id)
		ev, err := e.EvaluateVAP(context.Background(), vap, pod, nil, params)
		require.NoError(t, err, id)
		require.True(t, ev.Applicable, id)
		for i, r := range ev.Results {
			assert.NoErrorf(t, r.Err, "%s validation %d", id, i)
			assert.Truef(t, r.Passed, "%s validation %d: %s", id, i, r.Message)
		}
	}
}

// C-0231 on a 443 LoadBalancer: with no annotations at all it denies, and with
// the AWS cert annotation present but null it admits, since the key survives
// typed decoding.
func TestC0231NullAnnotations(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)
	vap, err := loadVAP("C-0231")
	require.NoError(t, err)
	for name, tc := range map[string]struct {
		annotations string
		passed      bool
	}{
		"annotations null":      {annotations: `null`, passed: false},
		"cert annotation null":  {annotations: `{"service.beta.kubernetes.io/aws-load-balancer-ssl-cert":null}`, passed: true},
		"unrelated annotations": {annotations: `{"a":"b"}`, passed: false},
	} {
		t.Run(name, func(t *testing.T) {
			svc := rawManifest(t, `{"apiVersion":"v1","kind":"Service","metadata":{"name":"s","namespace":"ns","annotations":`+tc.annotations+`},
				"spec":{"type":"LoadBalancer","ports":[{"port":443,"targetPort":8443}]}}`)
			ev, err := e.EvaluateVAP(context.Background(), vap, svc, nil, nil)
			require.NoError(t, err)
			require.True(t, ev.Applicable)
			require.Len(t, ev.Results, 1)
			assert.NoError(t, ev.Results[0].Err)
			assert.Equal(t, tc.passed, ev.Results[0].Passed)
		})
	}
}
