package anonymizer

import (
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evidencePathSession is a failed rule on a Pod with two paths: one on the Pod
// itself, which carries no ResourceID, and one on a related ConfigMap, which
// names the ConfigMap's ID.
func evidencePathSession(t *testing.T) (session *cautils.OPASessionObj, podID, configMapID string) {
	t.Helper()
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "nginx", "namespace": "default"},
	})
	configMap := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "nginx-config", "namespace": "default"},
	})
	podID, configMapID = pod.GetID(), configMap.GetID()

	session = &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{podID: pod, configMapID: configMap},
		ResourcesResult: map[string]resourcesresults.Result{
			podID: {
				ResourceID: podID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
					ControlID: "C-0017",
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
						Name: "immutable-container-filesystem",
						Paths: []armotypes.PosturePaths{
							{FailedPath: "spec.containers[0].securityContext.readOnlyRootFilesystem"},
							{FailedPath: "data.key", ResourceID: configMapID},
						},
					}},
				}},
			},
		},
		ResourceSource: map[string]reporthandling.Source{},
		Metadata:       &reporthandlingv2.Metadata{},
		Report:         &reporthandlingv2.PostureReport{},
	}
	return session, podID, configMapID
}

// A path on the scanned resource itself has no ResourceID. Anonymization must
// keep it empty: any value there names a related resource, and transforming ""
// invents one that is in neither the catalog nor the results (#4785). A path
// that does name a related resource must still point at that resource's
// transformed ID.
func TestAnonymizationKeepsEmptyEvidencePathResourceID(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	for _, tc := range []struct {
		name  string
		apply func(*resultshandling.ResultsHandler) error
	}{
		{"Apply", Apply},
		{"ApplyEncrypted", func(h *resultshandling.ResultsHandler) error {
			return ApplyEncrypted(h, dek, []byte("01234567890123456789012345678901"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, podID, configMapID := evidencePathSession(t)
			require.NoError(t, tc.apply(&resultshandling.ResultsHandler{ScanData: session}))

			var newConfigMapID string
			for id, resource := range session.AllResources {
				if resource.GetKind() == "ConfigMap" {
					newConfigMapID = id
				}
			}
			require.NotEmpty(t, newConfigMapID)
			require.NotEqual(t, configMapID, newConfigMapID)

			require.Len(t, session.ResourcesResult, 1)
			for newPodID, result := range session.ResourcesResult {
				require.NotEqual(t, podID, newPodID)
				paths := result.AssociatedControls[0].ResourceAssociatedRules[0].Paths
				assert.Empty(t, paths[0].ResourceID, "a path on the scanned resource must keep an empty ResourceID")
				assert.Equal(t, newConfigMapID, paths[1].ResourceID, "a related-resource path must point at the related resource's transformed ID")
			}
		})
	}
}

// Two --hide reports of the same Pod, before and after a control starts
// failing on it, must not attribute the new finding to a separate evidence
// resource: the failed path is on the Pod itself.
func TestHiddenReportsDiffNamesNoPhantomEvidenceResource(t *testing.T) {
	render := func(failed bool) []byte {
		const id = "/v1/default/Pod/nginx"
		status := apis.StatusPassed
		var paths []armotypes.PosturePaths
		if failed {
			status = apis.StatusFailed
			paths = []armotypes.PosturePaths{{FailedPath: "spec.containers[0].securityContext.readOnlyRootFilesystem"}}
		}
		session := &cautils.OPASessionObj{
			ResourcesResult: map[string]resourcesresults.Result{
				id: {
					ResourceID: id,
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
						ControlID: "C-0017",
						Name:      "Immutable container filesystem",
						Status:    apis.StatusInfo{InnerStatus: status},
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
							Name:   "immutable-container-filesystem",
							Status: status,
							Paths:  paths,
						}},
					}},
				},
			},
			ResourceSource: map[string]reporthandling.Source{},
			Metadata:       &reporthandlingv2.Metadata{},
			Report: &reporthandlingv2.PostureReport{SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{"C-0017": {ControlID: "C-0017", Name: "Immutable container filesystem", ScoreFactor: 3}},
			}},
		}
		handler := &resultshandling.ResultsHandler{ScanData: session}
		require.NoError(t, Apply(handler))
		data, err := handler.ToJson()
		require.NoError(t, err)
		return data
	}

	changes, err := diff.ComputeFromJSON(render(false), render(true), diff.Options{})
	require.NoError(t, err)
	require.Len(t, changes.New, 1)
	assert.Empty(t, changes.New[0].EvidenceResourceID)

	var out strings.Builder
	require.NoError(t, diff.PrintPretty(&out, changes))
	assert.NotContains(t, out.String(), "Evidence resource:")
}

func TestAnonymizationPreservesEvidenceValuesWithTransformedIdentifiers(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	masterKey := []byte("01234567890123456789012345678901")

	for _, tc := range []struct {
		name      string
		apply     func(*resultshandling.ResultsHandler) error
		isEncrypt bool
	}{
		{"hide (Apply)", Apply, false},
		{"encrypt (ApplyEncrypted)", func(h *resultshandling.ResultsHandler) error {
			return ApplyEncrypted(h, dek, masterKey)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, podID, _ := evidencePathSession(t)
			session.PreservedEvidenceValues = map[string]map[string]string{
				podID: {
					"metadata.name":                   "nginx",
					`metadata["name"]`:                "nginx",
					"metadata.namespace":              "default",
					`metadata['namespace']`:           "default",
					"metadata":                        `{"name":"nginx","namespace":"default"}`,
					"spec.template":                   `{"metadata":{"labels":{"app":"nginx"}}}`,
					`data["metadata"]`:                "config-val",
					"spec.containers[0].env[0].name":  "SECRET_KEY",
					"spec.containers[0].env[0].value": "env-payload-val",
					"spec.containers[0].env[1].value": `{"namespace":"production","setting":"val123"}`,
				},
			}
			require.NoError(t, tc.apply(&resultshandling.ResultsHandler{ScanData: session}))

			var newPodID string
			for id := range session.ResourcesResult {
				newPodID = id
			}
			require.NotEmpty(t, newPodID)
			preserved := session.PreservedEvidenceValues[newPodID]
			require.NotNil(t, preserved)

			transformedPod := session.AllResources[newPodID]
			require.NotNil(t, transformedPod)
			transformedName := transformedPod.GetName()
			transformedNamespace := transformedPod.GetNamespace()
			require.NotEmpty(t, transformedName)
			require.NotEmpty(t, transformedNamespace)

			// Require each identifier key to exist in preserved evidence
			require.Contains(t, preserved, "metadata.name")
			require.Contains(t, preserved, `metadata["name"]`)
			require.Contains(t, preserved, "metadata.namespace")
			require.Contains(t, preserved, `metadata['namespace']`)

			// Retain the check that identifiers are not the original plaintext
			assert.NotEqual(t, "nginx", preserved["metadata.name"])
			assert.NotEqual(t, "nginx", preserved[`metadata["name"]`])
			assert.NotEqual(t, "default", preserved["metadata.namespace"])
			assert.NotEqual(t, "default", preserved[`metadata['namespace']`])

			if tc.isEncrypt {
				// Under encryption, values must be valid AES256_GCM ciphertexts
				// that decrypt back to the original values using the report key.
				require.NotNil(t, session.Metadata)
				require.NotNil(t, session.Metadata.EncryptionMetadata)
				reportKey, err := reportcrypto.UnwrapReportKey(
					session.Metadata.EncryptionMetadata.EncryptedDEK,
					masterKey,
				)
				require.NoError(t, err)

				assert.Contains(t, preserved["metadata.name"], "ENC[AES256_GCM,")
				decryptedName, err := reportKey.DecryptString(preserved["metadata.name"])
				require.NoError(t, err)
				assert.Equal(t, "nginx", decryptedName)

				assert.Contains(t, preserved[`metadata["name"]`], "ENC[AES256_GCM,")
				decryptedName2, err := reportKey.DecryptString(preserved[`metadata["name"]`])
				require.NoError(t, err)
				assert.Equal(t, "nginx", decryptedName2)

				assert.Contains(t, preserved["metadata.namespace"], "ENC[AES256_GCM,")
				decryptedNs, err := reportKey.DecryptString(preserved["metadata.namespace"])
				require.NoError(t, err)
				assert.Equal(t, "default", decryptedNs)

				assert.Contains(t, preserved[`metadata['namespace']`], "ENC[AES256_GCM,")
				decryptedNs2, err := reportKey.DecryptString(preserved[`metadata['namespace']`])
				require.NoError(t, err)
				assert.Equal(t, "default", decryptedNs2)

				// Environment variable names must be encrypted under ApplyEncrypted
				assert.Contains(t, preserved["spec.containers[0].env[0].name"], "ENC[AES256_GCM,")
				decryptedEnvName, err := reportKey.DecryptString(preserved["spec.containers[0].env[0].name"])
				require.NoError(t, err)
				assert.Equal(t, "SECRET_KEY", decryptedEnvName)
			} else {
				// Under pseudonymization (--hide), values must match the exact transformed Pod name or namespace
				assert.Equal(t, transformedName, preserved["metadata.name"])
				assert.Equal(t, transformedName, preserved[`metadata["name"]`])
				assert.Equal(t, transformedNamespace, preserved["metadata.namespace"])
				assert.Equal(t, transformedNamespace, preserved[`metadata['namespace']`])

				// Environment variable names must be pseudonymized under Apply
				assert.NotEqual(t, "SECRET_KEY", preserved["spec.containers[0].env[0].name"])
				assert.Contains(t, preserved["spec.containers[0].env[0].name"], "env-")
			}

			// Parent path "metadata" must be rejected to prevent leaking plaintext JSON
			_, hasMetadataParent := preserved["metadata"]
			assert.False(t, hasMetadataParent, "parent path 'metadata' must be rejected")

			// Ancestor path "spec.template" containing metadata must also be rejected
			_, hasSpecTemplate := preserved["spec.template"]
			assert.False(t, hasSpecTemplate, "ancestor path 'spec.template' containing metadata must be rejected")

			// Secrets and ConfigMap data keys named metadata must remain preserved
			assert.Equal(t, "config-val", preserved[`data["metadata"]`])
			assert.Equal(t, "env-payload-val", preserved["spec.containers[0].env[0].value"])
			// JSON-valued environment variables must remain preserved
			assert.Equal(t, `{"namespace":"production","setting":"val123"}`, preserved["spec.containers[0].env[1].value"])
		})
	}
}
