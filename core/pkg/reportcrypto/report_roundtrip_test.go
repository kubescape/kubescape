package reportcrypto_test

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptedReportProducerConsumerRoundTrip protects the contract between
// anonymizer.ApplyEncrypted, ResultsHandler.ToJson, and DecryptReport. Unit
// fixtures cover individual JSON shapes; this test ensures the real producer
// and consumer continue to agree on transformed IDs and copied labels.
func TestEncryptedReportProducerConsumerRoundTrip(t *testing.T) {
	const masterKey = "01234567890123456789012345678901"

	workload, err := workloadinterface.NewWorkload([]byte(`{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"sourcePath": "/workspace/manifests/checkout.yaml:18",
		"metadata": {
			"name": "checkout",
			"namespace": "production",
			"labels": {
				"team": "payments",
				"environment": "production"
			},
			"annotations": {
				"owner": "payments-on-call"
			}
		},
		"spec": {
			"template": {
				"spec": {
					"serviceAccountName": "checkout-service-account",
					"imagePullSecrets": [{"name": "private-registry"}],
					"containers": [{
						"name": "checkout-api",
						"image": "registry.example.com/checkout:v2",
						"env": [{"name": "TOKEN", "value": "sensitive-value"}]
					}]
				}
			}
		}
	}`))
	require.NoError(t, err)
	originalID := workload.GetID()

	metadata := &reporthandlingv2.Metadata{
		ContextMetadata: reporthandlingv2.ContextMetadata{
			RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
				Provider:      "github",
				Repo:          "kubescape",
				Owner:         "kubescape",
				Branch:        "main",
				DefaultBranch: "main",
				RemoteURL:     "https://github.com/kubescape/kubescape.git",
				LocalRootPath: "/workspace/kubescape",
				LastCommit: reporthandling.LastCommit{
					Hash:           "0123456789abcdef",
					CommitterName:  "Kubescape Maintainer",
					CommitterEmail: "maintainer@example.com",
					Message:        "update checkout deployment",
				},
			},
		},
	}

	result := resourcesresults.Result{
		ResourceID: originalID,
		PrioritizedResource: &prioritization.PrioritizedResource{
			ResourceID: originalID,
		},
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0010",
				Name:      "Container Resources",
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Name:                "Resource limits",
						RelatedResourcesIDs: []string{originalID},
					},
				},
			},
		},
	}

	session := &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			originalID: workload,
		},
		ResourcesResult: map[string]resourcesresults.Result{
			originalID: result,
		},
		ResourcesPrioritized: map[string]prioritization.PrioritizedResource{
			originalID: *result.PrioritizedResource,
		},
		ResourceSource: map[string]reporthandling.Source{
			originalID: {
				Path:         "/workspace/manifests/checkout.yaml",
				RelativePath: "manifests/checkout.yaml",
			},
		},
		Metadata:     metadata,
		Report:       &reporthandlingv2.PostureReport{},
		LabelsToCopy: []string{"team"},
	}

	handler := &resultshandling.ResultsHandler{ScanData: session}
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	require.NoError(t, anonymizer.ApplyEncrypted(handler, dek, []byte(masterKey)))

	encryptedJSON, err := handler.ToJson()
	require.NoError(t, err)
	assert.Contains(t, string(encryptedJSON), "ENC[AES256_GCM,")
	var encryptedReport map[string]any
	require.NoError(t, json.Unmarshal(encryptedJSON, &encryptedReport))
	encryptedResources := encryptedReport["resources"].([]any)
	encryptedObject := encryptedResources[0].(map[string]any)["object"].(map[string]any)
	encryptedName := encryptedObject["metadata"].(map[string]any)["name"].(string)
	assert.NotEqual(t, "checkout", encryptedName)
	assert.Contains(t, encryptedName, "ENC[AES256_GCM,")

	decryptedJSON, err := reportcrypto.DecryptReport(encryptedJSON, []byte(masterKey))
	require.NoError(t, err)

	var report map[string]any
	require.NoError(t, json.Unmarshal(decryptedJSON, &report))
	resources := report["resources"].([]any)
	require.Len(t, resources, 1)
	resource := resources[0].(map[string]any)
	assert.Equal(t, originalID, resource["resourceID"])
	object := resource["object"].(map[string]any)
	objectMetadata := object["metadata"].(map[string]any)
	assert.Equal(t, "checkout", objectMetadata["name"])
	assert.Equal(t, "production", objectMetadata["namespace"])
	assert.Equal(t, "/workspace/manifests/checkout.yaml:18", object["sourcePath"])

	results := report["results"].([]any)
	require.Len(t, results, 1)
	decryptedResult := results[0].(map[string]any)
	assert.Equal(t, originalID, decryptedResult["resourceID"])
	prioritized := decryptedResult["prioritizedResource"].(map[string]any)
	assert.Equal(t, originalID, prioritized["resourceID"])
	controls := decryptedResult["controls"].([]any)
	rules := controls[0].(map[string]any)["rules"].([]any)
	related := rules[0].(map[string]any)["relatedResourcesIDs"].([]any)
	assert.Equal(t, originalID, related[0])

	labelsByResource := report["resourceLabels"].(map[string]any)
	require.Contains(t, labelsByResource, originalID)
	labels := labelsByResource[originalID].(map[string]any)
	assert.Equal(t, "payments", labels["team"])

	decryptedMetadata := report["metadata"].(map[string]any)
	target := decryptedMetadata["targetMetadata"].(map[string]any)
	repository := target["gitRepoContextMetadata"].(map[string]any)
	assert.Equal(t, "kubescape", repository["repo"])
	assert.Equal(t, "https://github.com/kubescape/kubescape.git", repository["remoteURL"])
}

func TestEncryptedReportRoundTripWithoutRawResources(t *testing.T) {
	const masterKey = "01234567890123456789012345678901"

	workload, err := workloadinterface.NewWorkload([]byte(`{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "checkout",
			"namespace": "production",
			"labels": {"team": "payments"}
		},
		"spec": {
			"template": {
				"spec": {
					"containers": [{"name": "api", "image": "checkout:v2"}]
				}
			}
		}
	}`))
	require.NoError(t, err)
	originalID := workload.GetID()
	relatedID := "apps/v1/production/Deployment/payments-worker"

	result := resourcesresults.Result{
		ResourceID: originalID,
		PrioritizedResource: &prioritization.PrioritizedResource{
			ResourceID: originalID,
		},
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0010",
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Name:                "Related workload",
						RelatedResourcesIDs: []string{relatedID},
					},
				},
			},
		},
	}

	session := &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			originalID: workload,
		},
		ResourcesResult: map[string]resourcesresults.Result{
			originalID: result,
		},
		ResourcesPrioritized: map[string]prioritization.PrioritizedResource{
			originalID: *result.PrioritizedResource,
		},
		ResourceSource:   map[string]reporthandling.Source{},
		Metadata:         &reporthandlingv2.Metadata{},
		Report:           &reporthandlingv2.PostureReport{},
		LabelsToCopy:     []string{"team"},
		OmitRawResources: true,
	}

	handler := &resultshandling.ResultsHandler{ScanData: session}
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	require.NoError(t, anonymizer.ApplyEncrypted(handler, dek, []byte(masterKey)))

	encryptedJSON, err := handler.ToJson()
	require.NoError(t, err)
	var encryptedReport map[string]any
	require.NoError(t, json.Unmarshal(encryptedJSON, &encryptedReport))
	assert.NotContains(t, encryptedReport, "resources")
	encryptedResult := encryptedReport["results"].([]any)[0].(map[string]any)
	encryptedID := encryptedResult["resourceID"].(string)
	assert.Contains(t, encryptedID, "ENC[AES256_GCM,")
	controls := encryptedResult["controls"].([]any)
	rules := controls[0].(map[string]any)["rules"].([]any)
	encryptedRelatedID := rules[0].(map[string]any)["relatedResourcesIDs"].([]any)[0].(string)
	assert.Contains(t, encryptedRelatedID, "ENC[AES256_GCM,")
	assert.NotContains(t, encryptedRelatedID, "ref-")

	decryptedJSON, err := reportcrypto.DecryptReport(encryptedJSON, []byte(masterKey))
	require.NoError(t, err)
	var report map[string]any
	require.NoError(t, json.Unmarshal(decryptedJSON, &report))
	assert.NotContains(t, report, "resources")
	decryptedResult := report["results"].([]any)[0].(map[string]any)
	assert.Equal(t, originalID, decryptedResult["resourceID"])
	prioritized := decryptedResult["prioritizedResource"].(map[string]any)
	assert.Equal(t, originalID, prioritized["resourceID"])
	controls = decryptedResult["controls"].([]any)
	rules = controls[0].(map[string]any)["rules"].([]any)
	related := rules[0].(map[string]any)["relatedResourcesIDs"].([]any)
	assert.Equal(t, relatedID, related[0])
	labels := report["resourceLabels"].(map[string]any)
	assert.Equal(t, "payments", labels[originalID].(map[string]any)["team"])
}
