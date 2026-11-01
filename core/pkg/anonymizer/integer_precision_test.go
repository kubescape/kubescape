package anonymizer

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func precisionResource(value any) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{
			"name": "private-workload", "namespace": "private-namespace",
		},
		"spec": map[string]any{
			"securityContext": map[string]any{"runAsUser": value},
			"containers": []any{map[string]any{
				"name": "worker", "image": "example.invalid/app:1",
			}},
		},
	})
}

func precisionHandler(resource workloadinterface.IMetadata) *resultshandling.ResultsHandler {
	return &resultshandling.ResultsHandler{ScanData: &cautils.OPASessionObj{
		Metadata: &reporthandlingv2.Metadata{},
		Report:   &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{
			resource.GetID(): resource,
		},
		ResourcesResult: map[string]resourcesresults.Result{
			resource.GetID(): {ResourceID: resource.GetID()},
		},
	}}
}

func precisionJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return string(raw)
}

func TestAnonymizerPreservesInt64Values(t *testing.T) {
	for _, value := range []int64{
		0, 1, -1, 1<<53 - 1, 1 << 53, 1<<53 + 1,
		-(1<<53 + 1), math.MaxInt64, math.MinInt64,
	} {
		t.Run(precisionJSON(t, value), func(t *testing.T) {
			resource := precisionResource(value)
			handler := precisionHandler(resource)
			require.NoError(t, Apply(handler))
			actual, found, err := unstructured.NestedInt64(resource.GetObject(), "spec", "securityContext", "runAsUser")
			require.NoError(t, err, "resource numbers must remain usable by Kubernetes accessors")
			require.True(t, found)
			require.Equal(t, value, actual)
			require.NotEqual(t, "private-workload", resource.GetName())
			require.NotEqual(t, "private-namespace", resource.GetNamespace())
		})
	}
}

func TestAnonymizerEncryptedRoundTripPreservesInt64(t *testing.T) {
	for _, value := range []int64{1<<53 + 1, math.MaxInt64, math.MinInt64} {
		t.Run(precisionJSON(t, value), func(t *testing.T) {
			resource := precisionResource(value)
			handler := precisionHandler(resource)
			dek, err := reportcrypto.GenerateDEK()
			require.NoError(t, err)
			masterKey := []byte("01234567890123456789012345678901")
			require.NoError(t, ApplyEncrypted(handler, dek, masterKey))
			raw, err := handler.ToJson()
			require.NoError(t, err)
			restored, err := reportcrypto.DecryptReport(raw, masterKey)
			require.NoError(t, err)
			var report struct {
				Resources []struct {
					Object struct {
						Spec struct {
							SecurityContext struct {
								RunAsUser int64 `json:"runAsUser"`
							} `json:"securityContext"`
						} `json:"spec"`
					} `json:"object"`
				} `json:"resources"`
			}
			require.NoError(t, json.Unmarshal(restored, &report))
			require.Len(t, report.Resources, 1)
			require.Equal(t, value, report.Resources[0].Object.Spec.SecurityContext.RunAsUser)
		})
	}
}

func TestAnonymizerPreservesNestedIntegerEvidence(t *testing.T) {
	const large int64 = 9007199254740993
	object := map[string]any{
		"apiVersion": "example.invalid/v1", "kind": "QuotaPolicy",
		"metadata": map[string]any{"name": "private-policy", "namespace": "prod"},
		"spec": map[string]any{
			"limit": large,
			"thresholds": []any{
				large, map[string]any{"minimum": int64(math.MinInt64), "maximum": int64(math.MaxInt64)},
			},
			"ratio":       0.125,
			"enabled":     true,
			"description": "9007199254740993",
			"optional":    nil,
		},
		"status": map[string]any{"observedGeneration": large},
	}
	resource := workloadinterface.NewWorkloadObj(object)
	wantSpec := precisionJSON(t, object["spec"])
	wantStatus := precisionJSON(t, object["status"])
	require.NoError(t, Apply(precisionHandler(resource)))
	require.Equal(t, wantSpec, precisionJSON(t, resource.GetObject()["spec"]))
	require.Equal(t, wantStatus, precisionJSON(t, resource.GetObject()["status"]))
}

func TestAnonymizerResourceCloneKeepsTypedKubernetesValues(t *testing.T) {
	const large int64 = 9007199254740993
	value := int64(large)
	object := map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "typed-pod", "namespace": "prod"},
		"spec": map[string]any{
			"containers": []corev1.Container{{
				Name: "worker", Image: "example.invalid/app:1",
				SecurityContext: &corev1.SecurityContext{RunAsUser: &value},
			}},
		},
	}
	cloned, err := cloneResourceObject(object)
	require.NoError(t, err)
	containers := cloned["spec"].(map[string]any)["containers"].([]any)
	security := containers[0].(map[string]any)["securityContext"].(map[string]any)
	require.Equal(t, int64(large), security["runAsUser"])
	security["runAsUser"] = int64(2)
	require.Equal(t, int64(large), value, "a clone must not share the typed pointer")
}

func TestAnonymizerCloningRetainsTypedStructFields(t *testing.T) {
	type typed struct {
		Count int64          `json:"count"`
		Score float64        `json:"score"`
		Extra map[string]any `json:"extra"`
	}
	original := typed{
		Count: math.MaxInt64, Score: 1.25,
		Extra: map[string]any{"large": int64(9007199254740993), "fraction": 0.25},
	}
	cloned, err := cloneJSON(original)
	require.NoError(t, err)
	require.Equal(t, original.Count, cloned.Count)
	require.Equal(t, original.Score, cloned.Score)
	require.Equal(t, int64(9007199254740993), cloned.Extra["large"])
	require.Equal(t, 0.25, cloned.Extra["fraction"])
	cloned.Extra["large"] = int64(0)
	require.Equal(t, int64(9007199254740993), original.Extra["large"])
}

func TestAnonymizerIntegerFailureIsStillTransactional(t *testing.T) {
	resource := precisionResource(int64(math.MaxInt64))
	handler := precisionHandler(resource)
	before := precisionJSON(t, resource.GetObject())
	transformer := &selectiveFailTransformer{
		delegate: NewMappingTransformer(), failPrefix: "res", failValue: "private-workload",
	}
	require.ErrorIs(t, applyWithTransformer(handler, transformer), errInjectedTransform)
	require.Equal(t, before, precisionJSON(t, resource.GetObject()))
	value, found, err := unstructured.NestedInt64(resource.GetObject(), "spec", "securityContext", "runAsUser")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(math.MaxInt64), value)
}

func TestAnonymizerCloneIsolationForIntegerCollections(t *testing.T) {
	original := map[string]any{
		"values": []any{int64(math.MaxInt64), map[string]any{"value": int64(math.MinInt64)}},
	}
	cloned, err := cloneJSON(original)
	require.NoError(t, err)
	values := cloned["values"].([]any)
	require.Equal(t, int64(math.MaxInt64), values[0])
	require.Equal(t, int64(math.MinInt64), values[1].(map[string]any)["value"])
	values[0] = int64(1)
	values[1].(map[string]any)["value"] = int64(2)
	require.Equal(t, int64(math.MaxInt64), original["values"].([]any)[0])
	require.Equal(t, int64(math.MinInt64), original["values"].([]any)[1].(map[string]any)["value"])
}

func TestAnonymizerCloneRejectsUnrepresentableJSON(t *testing.T) {
	for _, value := range []any{
		math.NaN(), math.Inf(1), math.Inf(-1), make(chan int),
	} {
		_, err := cloneJSON(map[string]any{"value": value})
		require.Error(t, err)
	}
}

func TestAnonymizerCloneRetainsIntegerArraysAndNulls(t *testing.T) {
	type configuration struct {
		Values []int64        `json:"values"`
		Extra  map[string]any `json:"extra"`
	}
	original := configuration{
		Values: []int64{math.MinInt64, 0, 1<<53 + 1, math.MaxInt64},
		Extra: map[string]any{
			"empty": []any{}, "null": nil,
			"values": []any{int64(math.MaxInt64), nil, "9223372036854775807"},
		},
	}
	cloned, err := cloneJSON(original)
	require.NoError(t, err)
	require.Equal(t, original.Values, cloned.Values)
	require.Equal(t, original.Extra, cloned.Extra)
	cloned.Values[0] = 7
	require.Equal(t, int64(math.MinInt64), original.Values[0])
}

func TestAnonymizerRepeatedTransformsDoNotAccumulateRounding(t *testing.T) {
	resource := precisionResource(int64(9007199254740993))
	handler := precisionHandler(resource)
	want := precisionJSON(t, resource.GetObject()["spec"].(map[string]any)["securityContext"])
	for range 3 {
		require.NoError(t, Apply(handler))
		require.Equal(t, want, precisionJSON(t, resource.GetObject()["spec"].(map[string]any)["securityContext"]))
	}
}

func TestAnonymizerMixedResourceCatalogKeepsEveryInteger(t *testing.T) {
	resources := map[string]workloadinterface.IMetadata{}
	want := map[workloadinterface.IMetadata]string{}
	for i, kind := range []string{"Pod", "Deployment", "ConfigMap", "CustomPolicy"} {
		resource := precisionResource(int64(math.MaxInt64) - int64(i))
		resource.SetKind(kind)
		resource.SetName("resource-" + kind)
		resources[resource.GetID()] = resource
		want[resource] = precisionJSON(t, resource.GetObject()["spec"].(map[string]any)["securityContext"])
	}
	handler := &resultshandling.ResultsHandler{ScanData: &cautils.OPASessionObj{
		AllResources: resources,
	}}
	require.NoError(t, Apply(handler))
	require.Len(t, handler.ScanData.GetCatalog().All(), len(want))
	for resource, expected := range want {
		require.Equal(t, expected, precisionJSON(t, resource.GetObject()["spec"].(map[string]any)["securityContext"]))
	}
}

func TestAnonymizerCloneNilAndTypedPointers(t *testing.T) {
	var absent *corev1.PodSecurityContext
	clonedAbsent, err := cloneJSON(absent)
	require.NoError(t, err)
	require.Nil(t, clonedAbsent)
	value := int64(math.MaxInt64)
	original := &corev1.PodSecurityContext{RunAsUser: &value}
	cloned, err := cloneJSON(original)
	require.NoError(t, err)
	require.NotSame(t, original, cloned)
	require.NotSame(t, original.RunAsUser, cloned.RunAsUser)
	require.Equal(t, value, *cloned.RunAsUser)
}

func TestAnonymizerCommitCloneRemainsIndependent(t *testing.T) {
	resource := precisionResource(int64(math.MaxInt64))
	handler := precisionHandler(resource)
	transaction, err := cloneSessionForTransform(handler.ScanData)
	require.NoError(t, err)
	workingResource := transaction.working.GetCatalog().All()[resource.GetID()]
	require.NotNil(t, workingResource)
	require.NoError(t, commitTransformedSession(handler.ScanData, transaction))
	workingSpec := workingResource.GetObject()["spec"].(map[string]any)
	workingSpec["securityContext"].(map[string]any)["runAsUser"] = int64(0)
	actual, found, err := unstructured.NestedInt64(resource.GetObject(), "spec", "securityContext", "runAsUser")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(math.MaxInt64), actual)
}

func TestAnonymizerClonePreservesNumericLookingStrings(t *testing.T) {
	original := map[string]any{
		"identifier": "9223372036854775807", "decimal": "1.25", "exponent": "1e20",
	}
	cloned, err := cloneJSON(original)
	require.NoError(t, err)
	require.Equal(t, original, cloned, "integer-preserving decoding must not coerce string fields")
}
