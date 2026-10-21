package pss

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestEmptyContainerPodSpecsAreUnevaluated(t *testing.T) {
	for _, kind := range []string{"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"} {
		for _, tc := range []struct {
			name string
			spec map[string]any
		}{
			{"missing containers", map[string]any{}},
			{"null containers", map[string]any{"containers": nil}},
			{"empty containers", map[string]any{"containers": []any{}}},
			{"init containers only", map[string]any{"initContainers": []any{map[string]any{"name": "init", "image": "test"}}}},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				object := map[string]any{"apiVersion": "apps/v1", "kind": kind, "metadata": map[string]any{"name": "empty", "namespace": "prod"}}
				switch kind {
				case "Pod":
					object["apiVersion"] = "v1"
					object["spec"] = tc.spec
				case "CronJob":
					object["spec"] = map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": tc.spec}}}}
				default:
					object["spec"] = map[string]any{"template": map[string]any{"spec": tc.spec}}
				}
				_, err := ExtractPodSpec(kind, object)
				require.Error(t, err)
				require.Contains(t, err.Error(), "container")
				for _, level := range []Level{Baseline, Restricted} {
					result := Aggregate("prod", []unstructured.Unstructured{{Object: object}}, level)
					require.Equal(t, 0, result.PassingWorkloads)
					require.Equal(t, 1, result.UnevaluatedWorkloads)
					require.Len(t, result.DecodeWarnings, 1)
					require.Empty(t, result.Results)
					require.Equal(t, false, result.ToMap()["summary"].(map[string]any)["current_effective_level_complete"])
				}
			})
		}
	}
}
