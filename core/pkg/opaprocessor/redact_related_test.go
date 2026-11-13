package opaprocessor

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

func relatedService() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"sourcePath": "app.yaml:12",
		"metadata": map[string]any{
			"name":      "api",
			"namespace": "default",
			"annotations": map[string]any{
				"example.com/auth-token": fake,
				"example.com/owner":      "team-a",
				lastApplied:              `{"token":"` + fake + `"}`,
			},
		},
		"spec": map[string]any{"type": "LoadBalancer"},
	}
}

func relatedSecret() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": "creds", "namespace": "default"},
		"data":       map[string]any{"password": fake},
		"stringData": map[string]any{"token": fake},
	}
}

func relatedPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "web", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":  "web",
				"image": "nginx",
				"args":  []any{"--db-password=" + fake},
				"env":   []any{map[string]any{"name": "DB_PASSWORD", "value": fake}},
			}},
		},
	}
}

func assertServiceRedacted(t *testing.T, service map[string]any) {
	t.Helper()
	w := workloadinterface.NewWorkloadObj(service)
	assert.Equal(t, redactedValue, w.GetAnnotations()["example.com/auth-token"])
	assert.Equal(t, "team-a", w.GetAnnotations()["example.com/owner"])
	assert.NotContains(t, w.GetAnnotations(), lastApplied)
	assert.Equal(t, "app.yaml:12", service["sourcePath"])
}

// A rule that reports through a RegoResponseVectorObject attaches whole
// objects under relatedObjects, such as the Service that exposes a workload or
// the roles and bindings of an RBAC subject. They are written to the report
// with the vector, so they must be cleaned like any other reported object.
func TestRemoveData_RedactsRelatedObjectsOfRegoResponseVector(t *testing.T) {
	t.Run("single related object", func(t *testing.T) {
		service := relatedService()
		vector := map[string]any{
			"kind": "Deployment", "name": "api", "namespace": "default",
			"relatedObjects": service,
		}
		require.Equal(t, objectsenvelopes.TypeRegoResponseVectorObject, objectsenvelopes.GetObjectType(vector))

		assert.Nil(t, removeData(objectsenvelopes.NewRegoResponseVectorObject(vector)))
		assertServiceRedacted(t, service)
		assert.Equal(t, "api", vector["name"])
		assert.Equal(t, "Deployment", vector["kind"])
	})

	t.Run("list of related objects", func(t *testing.T) {
		service, secret, pod := relatedService(), relatedSecret(), relatedPod()
		vector := map[string]any{
			"kind": "User", "name": "alice",
			"relatedObjects": []any{service, secret, pod},
		}

		removeData(objectsenvelopes.NewRegoResponseVectorObject(vector))

		assertServiceRedacted(t, service)
		assert.Equal(t, map[string]any{"password": redactedValue}, secret["data"])
		assert.Equal(t, map[string]any{"token": redactedValue}, secret["stringData"])
		containers, err := workloadinterface.NewWorkloadObj(pod).GetContainers()
		require.NoError(t, err)
		require.Len(t, containers, 1)
		assert.Equal(t, []string{"--db-password=" + redactedValue}, containers[0].Args)
		assert.NotContains(t, containers[0].Env[0].Value, fake)
	})

	t.Run("typed list and nested vector", func(t *testing.T) {
		service := relatedService()
		inner := map[string]any{"kind": "ServiceAccount", "name": "sa", "relatedObjects": []map[string]any{service}}
		vector := map[string]any{"kind": "Group", "name": "devs", "relatedObjects": []map[string]any{inner}}

		removeData(objectsenvelopes.NewRegoResponseVectorObject(vector))

		assertServiceRedacted(t, service)
	})

	t.Run("entries that are not Kubernetes objects are left alone", func(t *testing.T) {
		other := map[string]any{"note": fake}
		vector := map[string]any{"kind": "User", "name": "alice", "relatedObjects": []any{other, "text", nil}}

		assert.NotPanics(t, func() { removeData(objectsenvelopes.NewRegoResponseVectorObject(vector)) })
		assert.Equal(t, fake, other["note"])
	})
}
