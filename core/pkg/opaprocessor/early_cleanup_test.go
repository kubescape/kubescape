package opaprocessor

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEarlyCleanup_ProcessWithStreaming(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "1")

	raw := []string{
		`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-a"}}`,
		`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-b"}}`,
		`{
			"apiVersion":"v1",
			"kind":"Pod",
			"metadata":{
				"name":"app",
				"namespace":"ns-a",
				"managedFields":[{"manager":"kubectl","operation":"Update"}],
				"annotations":{
					"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\"}"
				}
			},
			"spec":{
				"containers":[{
					"name":"app",
					"image":"nginx",
					"env":[{
						"name":"SECRET_TOKEN",
						"value":"supersecret",
						"valueFrom":{"secretKeyRef":{"name":"my-secret","key":"token"}}
					}]
				}]
			}
		}`,
		`{
			"apiVersion":"v1",
			"kind":"ConfigMap",
			"metadata":{
				"name":"app-config",
				"namespace":"ns-a",
				"managedFields":[{"manager":"helm","operation":"Apply"}],
				"annotations":{
					"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\"}"
				}
			},
			"data":{"app.properties":"database=postgres"}
		}`,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"default","namespace":"ns-a"}}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"grant","namespace":"ns-b"},"subjects":[{"kind":"ServiceAccount","name":"default","namespace":"ns-a"}],"roleRef":{"kind":"ClusterRole","name":"admin"}}`,
	}

	k8sResources := make(cautils.K8SResources)
	allResources := make(map[string]workloadinterface.IMetadata, len(raw))
	for _, item := range raw {
		object := make(map[string]any)
		require.NoError(t, json.Unmarshal([]byte(item), &object))
		workload := workloadinterface.NewWorkloadObj(object)
		allResources[workload.GetID()] = workload

		var groupResource string
		switch workload.GetKind() {
		case "Namespace":
			groupResource = "/v1/namespaces"
		case "Pod":
			groupResource = "/v1/pods"
		case "ConfigMap":
			groupResource = "/v1/configmaps"
		case "ServiceAccount":
			groupResource = "/v1/serviceaccounts"
		case "RoleBinding":
			groupResource = "rbac.authorization.k8s.io/v1/rolebindings"
		}
		k8sResources[groupResource] = append(k8sResources[groupResource], workload.GetID())
	}

	control := saTokenBindingControl("C-0261")
	policies := convertFrameworksToPolicies(
		[]reporthandling.Framework{{Controls: []reporthandling.Control{control}}},
		nil, reporthandling.ScopeCluster,
	)

	sessionObj := cautils.NewOPASessionObjMock()
	sessionObj.Policies = []reporthandling.Framework{{Controls: []reporthandling.Control{control}}}

	opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.AllPolicies = policies
	opap.SetWholeClusterPolicy(cautils.WholeClusterPolicyProjected)

	const (
		podID = "/v1/ns-a/Pod/app"
		cmID  = "/v1/ns-a/ConfigMap/app-config"
	)

	var (
		batchHookRan        bool
		wholeClusterHookRan bool
	)

	// Step 1: Hook after each namespace batch. Right after ns-a finishes:
	// - ConfigMap (non-projected) must be cleaned early (managedFields stripped, data redacted).
	// - Pod (projected for whole-cluster evaluation) must remain raw (managedFields and env intact).
	opap.onBatchProcessed = func(batch *cautils.ResourceBatch) {
		if batch.Scope == "ns-a" {
			batchHookRan = true

			// ConfigMap must be cleaned early before deferred evaluation or updateResults
			assert.True(t, opap.isResourceCleaned(cmID), "ConfigMap must be cleaned right after its namespace batch")
			cmRes, ok := opap.GetCatalog().Get(cmID)
			require.True(t, ok)
			_, cmHasManaged := workloadinterface.InspectMap(cmRes.GetObject(), "metadata", "managedFields")
			assert.False(t, cmHasManaged, "ConfigMap managedFields must be stripped early")
			dataMap, hasData := workloadinterface.InspectMap(cmRes.GetObject(), "data")
			require.True(t, hasData)
			assert.Equal(t, "XXXXXX", dataMap.(map[string]any)["app.properties"])

			// Projected Pod must remain intact until deferred whole-cluster evaluation completes
			assert.False(t, opap.isResourceCleaned(podID), "Projected Pod must remain raw before whole-cluster evaluation")
			podRes, ok := opap.GetCatalog().Get(podID)
			require.True(t, ok)
			podWorkload := workloadinterface.NewWorkloadObj(podRes.GetObject())
			_, podHasManaged := workloadinterface.InspectMap(podWorkload.GetObject(), "metadata", "managedFields")
			assert.True(t, podHasManaged, "Pod managedFields must remain intact for whole-cluster evaluation")
			containers, err := podWorkload.GetContainers()
			require.NoError(t, err)
			require.Len(t, containers, 1)
			assert.Equal(t, "supersecret", containers[0].Env[0].Value, "Pod env must remain intact for whole-cluster evaluation")
		}
	}

	// Step 2: Hook right after deferred whole-cluster evaluation completes, before updateResults runs:
	// - Pod must now be cleaned before final report aggregation.
	opap.onWholeClusterProcessed = func(projectedBatch *cautils.ResourceBatch) {
		wholeClusterHookRan = true
		assert.True(t, opap.isResourceCleaned(podID), "Projected Pod must be cleaned immediately after whole-cluster evaluation")
		podRes, ok := opap.GetCatalog().Get(podID)
		require.True(t, ok)
		podWorkload := workloadinterface.NewWorkloadObj(podRes.GetObject())
		_, podHasManaged := workloadinterface.InspectMap(podWorkload.GetObject(), "metadata", "managedFields")
		assert.False(t, podHasManaged, "Pod managedFields must be stripped after whole-cluster evaluation")
		containers, err := podWorkload.GetContainers()
		require.NoError(t, err)
		require.Len(t, containers, 1)
		assert.Equal(t, "XXXXXX", containers[0].Env[0].Value)
	}

	resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources, 1)

	batchChan := make(chan *cautils.ResourceBatch, len(batches)+1)
	errChan := make(chan error, 1)
	close(errChan)
	batchChan <- resident
	for _, batch := range batches {
		batchChan <- batch
	}
	close(batchChan)

	err := opap.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), len(batches))
	require.NoError(t, err)

	require.True(t, batchHookRan, "batch hook must have executed for ns-a")
	require.True(t, wholeClusterHookRan, "whole-cluster hook must have executed before updateResults")

	// EnvVarSecretRefs must record SECRET_TOKEN for the anonymizer
	require.NotNil(t, opap.EnvVarSecretRefs)
	require.Contains(t, opap.EnvVarSecretRefs, podID)
	require.Contains(t, opap.EnvVarSecretRefs[podID], "app")
	assert.Contains(t, opap.EnvVarSecretRefs[podID]["app"], "SECRET_TOKEN")

	// Rule evaluation must have evaluated C-0261 correctly
	require.Contains(t, opap.ResourcesResult, podID)
	res := opap.ResourcesResult[podID]
	assert.True(t, res.GetStatus(nil).IsFailed())
}

func TestEarlyCleanup_ReplacementObjectIsCleaned(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	opap := NewOPAProcessor(session, nil, "test", "", "", false, nil)

	// Clean an initial object cm1 with ID "cm-1"
	raw1 := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm-1","managedFields":[{"f":1}]},"data":{"k":"initial"}}`
	obj1 := make(map[string]any)
	require.NoError(t, json.Unmarshal([]byte(raw1), &obj1))
	wl1 := workloadinterface.NewWorkloadObj(obj1)
	opap.cleanProcessedResource("/v1//ConfigMap/cm-1", wl1)
	assert.True(t, opap.isResourceCleaned("/v1//ConfigMap/cm-1"))

	// Replace the catalog entry with a fresh object wl2 of the same ID
	raw2 := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm-1","managedFields":[{"f":2}]},"data":{"k":"replacement-secret"}}`
	obj2 := make(map[string]any)
	require.NoError(t, json.Unmarshal([]byte(raw2), &obj2))
	wl2 := workloadinterface.NewWorkloadObj(obj2)
	opap.SetResource(wl2)

	// The cleanup cache must be invalidated for the replaced resource ID
	assert.False(t, opap.isResourceCleaned("/v1//ConfigMap/cm-1"))

	// Calling cleanProcessedResource or updateResults on the catalog must clean the replacement object
	opap.cleanProcessedResource("/v1//ConfigMap/cm-1", wl2)
	assert.True(t, opap.isResourceCleaned("/v1//ConfigMap/cm-1"))

	_, hasManaged := workloadinterface.InspectMap(wl2.GetObject(), "metadata", "managedFields")
	assert.False(t, hasManaged, "replacement object managedFields must be stripped")
	dataMap, hasData := workloadinterface.InspectMap(wl2.GetObject(), "data")
	require.True(t, hasData)
	assert.Equal(t, "XXXXXX", dataMap.(map[string]any)["k"], "replacement object data must be redacted")
}

func TestEarlyCleanup_SetResourceDoesNotDeadlockWithProcessorLock(t *testing.T) {
	session := &cautils.OPASessionObj{}
	opap := NewOPAProcessor(session, nil, "test", "", "", false, nil)

	raw := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm-dl","managedFields":[{"f":1}]},"data":{"k":"initial"}}`
	obj := make(map[string]any)
	require.NoError(t, json.Unmarshal([]byte(raw), &obj))
	wl := workloadinterface.NewWorkloadObj(obj)

	opap.cleanProcessedResource("/v1//ConfigMap/cm-dl", wl)
	assert.True(t, opap.isResourceCleaned("/v1//ConfigMap/cm-dl"))

	// Holding opap.mu (e.g. during a progress listener callback or rule evaluation)
	// must not deadlock when SetResource is invoked on the same goroutine.
	opap.mu.Lock()
	done := make(chan struct{})
	go func() {
		// Run SetResource which invalidates cleanedResources
		opap.SetResource(wl)
		close(done)
	}()

	select {
	case <-done:
		// Succeeded without deadlocking against opap.mu
	case <-time.After(2 * time.Second):
		t.Fatal("SetResource deadlocked while opap.mu was held")
	}
	opap.mu.Unlock()

	assert.False(t, opap.isResourceCleaned("/v1//ConfigMap/cm-dl"))
}

func TestEarlyCleanup_IdempotentAndNilSafe(t *testing.T) {
	opap := &OPAProcessor{}

	// Nil safety
	assert.NotPanics(t, func() {
		opap.cleanProcessedResource("nil-res", nil)
	})
	assert.False(t, opap.isResourceCleaned("nil-res"))

	// Idempotency on normal workload
	raw := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm","managedFields":[{"f":1}]},"data":{"k":"v"}}`
	objMap := make(map[string]any)
	require.NoError(t, json.Unmarshal([]byte(raw), &objMap))
	wl := workloadinterface.NewWorkloadObj(objMap)

	opap.cleanProcessedResource("cm-1", wl)
	assert.True(t, opap.isResourceCleaned("cm-1"))

	// Second call must be a safe no-op
	assert.NotPanics(t, func() {
		opap.cleanProcessedResource("cm-1", wl)
	})
	assert.True(t, opap.isResourceCleaned("cm-1"))
}
