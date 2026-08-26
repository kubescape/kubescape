package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// TestUpdateResults_ThenAnonymizerApply_AnonymizesReferenceBackedEnvVarName
// is a real, through-the-seam regression test for the bug reported in
// kubescape#3567: removeData (called from updateResults) clears an env
// var's ValueFrom before anonymizer.Apply ever runs, so the anonymizer's
// hasRef-gated env-var-name anonymization could never fire in the real
// scan+hide pipeline, only in isolated unit tests that call
// transformTypedEnv/transformUnstructuredEnv directly with ValueFrom still
// set.
//
// This runs the two real production functions in the real order: the
// OPAProcessor's actual updateResults (which scrubs and populates
// EnvVarSecretRefs), then the real anonymizer.Apply (--hide's entry point)
// on the resulting session -- not a synthetic object built to look like
// post-scrub state.
func TestUpdateResults_ThenAnonymizerApply_AnonymizesReferenceBackedEnvVarName(t *testing.T) {
	raw := `{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "payment-api", "namespace": "prod"},
		"spec": {
			"containers": [{
				"name": "app",
				"image": "nginx:latest",
				"env": [
					{
						"name": "DB_PASSWORD",
						"valueFrom": {"secretKeyRef": {"name": "db-creds", "key": "password"}}
					},
					{
						"name": "LOG_LEVEL",
						"value": "debug"
					}
				]
			}]
		}
	}`

	workload, err := workloadinterface.NewWorkload([]byte(raw))
	require.NoError(t, err)
	resourceID := workload.GetID()

	session := cautils.NewOPASessionObjMock()
	session.AllResources[resourceID] = workload

	opap := &OPAProcessor{OPASessionObj: session}
	opap.updateResults(context.Background())

	// Sanity: the scrub itself must still behave exactly as before this
	// change -- both env vars' values are gone, and the reference is nilled.
	scrubbed := workloadinterface.NewWorkloadObj(session.AllResources[resourceID].GetObject())
	containers, err := scrubbed.GetContainers()
	require.NoError(t, err)
	require.Len(t, containers, 1)
	require.Len(t, containers[0].Env, 2)
	require.Equal(t, "XXXXXX", containers[0].Env[0].Value, "scrub must still overwrite the value")
	require.Nil(t, containers[0].Env[0].ValueFrom, "scrub must still clear the reference")
	require.Equal(t, "XXXXXX", containers[0].Env[1].Value)

	require.Len(t, opap.EnvVarSecretRefs[resourceID], 1, "removeData must record exactly the one container that had a reference-backed env var")
	_, recorded := opap.EnvVarSecretRefs[resourceID]["app"]["DB_PASSWORD"]
	require.True(t, recorded)

	rh := &resultshandling.ResultsHandler{ScanData: session}
	require.NoError(t, anonymizer.Apply(rh))

	// Exactly one resource must survive anonymization: the fix must not
	// duplicate, drop, or misroute the resource while rekeying AllResources.
	require.Len(t, rh.ScanData.AllResources, 1)
	var anonymized *workloadinterface.Workload
	for _, resource := range rh.ScanData.AllResources {
		anonymized = workloadinterface.NewWorkloadObj(resource.GetObject())
	}
	require.NotNil(t, anonymized)

	anonContainers, err := anonymized.GetContainers()
	require.NoError(t, err)
	require.Len(t, anonContainers, 1)
	require.Len(t, anonContainers[0].Env, 2)

	// The reference-backed env var's name must now be anonymized, even
	// though ValueFrom was already nil by the time anonymizer.Apply ran --
	// this is the actual fix.
	require.NotEqual(t, "DB_PASSWORD", anonContainers[0].Env[0].Name)
	require.Contains(t, anonContainers[0].Env[0].Name, "env-")

	// The ordinary env var must be completely unaffected: its name is not a
	// secret reference and its value/name do not look sensitive, so neither
	// should change.
	require.Equal(t, "LOG_LEVEL", anonContainers[0].Env[1].Name, "an ordinary env var's name must not be anonymized")
}

// TestUpdateResults_ThenAnonymizerApply_DoesNotLeakAcrossContainers is the
// full through-the-seam version of the cross-container collision matthyx and
// CodeRabbit flagged on PR #3579: two containers in the same pod share an
// env var name, TOKEN, but only one of them is reference-backed. The other
// container's ordinary TOKEN must survive anonymizer.Apply completely
// unchanged, even though EnvVarSecretRefs has an entry for "TOKEN" somewhere
// in this resource.
func TestUpdateResults_ThenAnonymizerApply_DoesNotLeakAcrossContainers(t *testing.T) {
	raw := `{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "app", "namespace": "prod"},
		"spec": {
			"containers": [
				{
					"name": "has-ref",
					"env": [
						{"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "creds", "key": "token"}}}
					]
				},
				{
					"name": "ordinary",
					"env": [
						{"name": "TOKEN", "value": "not-a-secret-just-a-literal"}
					]
				}
			]
		}
	}`

	workload, err := workloadinterface.NewWorkload([]byte(raw))
	require.NoError(t, err)
	resourceID := workload.GetID()

	session := cautils.NewOPASessionObjMock()
	session.AllResources[resourceID] = workload

	opap := &OPAProcessor{OPASessionObj: session}
	opap.updateResults(context.Background())

	rh := &resultshandling.ResultsHandler{ScanData: session}
	require.NoError(t, anonymizer.Apply(rh))

	require.Len(t, rh.ScanData.AllResources, 1)
	var anonymized *workloadinterface.Workload
	for _, resource := range rh.ScanData.AllResources {
		anonymized = workloadinterface.NewWorkloadObj(resource.GetObject())
	}
	require.NotNil(t, anonymized)

	anonContainers, err := anonymized.GetContainers()
	require.NoError(t, err)
	require.Len(t, anonContainers, 2)

	var hasRefContainer, ordinaryContainer *corev1.Container
	for i := range anonContainers {
		switch {
		// Container names are themselves anonymized, so identify each
		// container by its (untouched) image-free structure instead: the
		// one whose env var name changed is the reference-backed one.
		case anonContainers[i].Env[0].Name != "TOKEN":
			hasRefContainer = &anonContainers[i]
		default:
			ordinaryContainer = &anonContainers[i]
		}
	}

	require.NotNil(t, hasRefContainer, "expected exactly one container with its TOKEN env var name anonymized")
	require.NotNil(t, ordinaryContainer, "expected exactly one container with TOKEN left untouched")
	assert.Equal(t, "TOKEN", ordinaryContainer.Env[0].Name, "the ordinary container's TOKEN must not be anonymized just because a different container's TOKEN is reference-backed")
}
