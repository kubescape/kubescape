package reportcrypto_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encryptedReportWithExceptionAudit encrypts a scan whose exception audit
// names a namespaced Deployment, a cluster-scoped ClusterRole and a resource
// that is not in the report, and returns the report and the audit as it was
// before encryption.
func encryptedReportWithExceptionAudit(t *testing.T) ([]byte, cautils.ExceptionAudit) {
	t.Helper()
	deployment, err := workloadinterface.NewWorkload([]byte(`{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": {"name": "payments-api", "namespace": "finance-prod"}
	}`))
	require.NoError(t, err)
	clusterRole, err := workloadinterface.NewWorkload([]byte(`{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
		"metadata": {"name": "payments-admin"}
	}`))
	require.NoError(t, err)
	deploymentID, clusterRoleID := deployment.GetID(), clusterRole.GetID()

	exception := armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{Name: "accept-payments-escalation"},
		PolicyType: "postureExceptionPolicy",
		Actions:    []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
	}
	result := func(id string) resourcesresults.Result {
		return resourcesresults.Result{
			ResourceID: id,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID: "C-0016",
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
					Name: "rule-allow-privilege-escalation", Exception: []armotypes.PostureExceptionPolicy{exception},
				}},
			}},
		}
	}
	audit := cautils.ExceptionAudit{
		Summary:   cautils.ExceptionAuditSummary{Total: 2, Active: 2, Matched: 1, Unused: 1},
		Generated: true,
		Items: []cautils.ExceptionAuditItem{
			{
				Name: "accept-payments-escalation", Status: "matched", MatchCount: 3, ControlIDs: []string{"C-0016"},
				MatchedResources: []cautils.ExceptionAuditMatch{
					{ResourceID: deploymentID, Kind: "Deployment", Namespace: "finance-prod", Name: "payments-api",
						ControlID: "C-0016", RuleName: "rule-allow-privilege-escalation"},
					{ResourceID: clusterRoleID, Kind: "ClusterRole", Name: "payments-admin",
						ControlID: "C-0016", RuleName: "rule-allow-privilege-escalation"},
					{ResourceID: "apps/v1/finance-prod/Deployment/payments-worker",
						ControlID: "C-0016", RuleName: "rule-allow-privilege-escalation"},
				},
			},
			{Name: "unused-ledger-exception", Status: "unused", ControlIDs: []string{"C-0017"}},
		},
	}
	sessionAudit := audit
	sessionAudit.Items = append([]cautils.ExceptionAuditItem(nil), audit.Items...)

	session := &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{deploymentID: deployment, clusterRoleID: clusterRole},
		ResourcesResult: map[string]resourcesresults.Result{
			deploymentID: result(deploymentID), clusterRoleID: result(clusterRoleID),
		},
		ResourceSource: map[string]reporthandling.Source{},
		Metadata:       &reporthandlingv2.Metadata{},
		Report:         &reporthandlingv2.PostureReport{},
		ExceptionAudit: &sessionAudit,
	}

	handler := &resultshandling.ResultsHandler{ScanData: session}
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	require.NoError(t, anonymizer.ApplyEncrypted(handler, dek, []byte(exceptionTestMasterKey)))
	encrypted, err := handler.ToJson()
	require.NoError(t, err)
	return encrypted, audit
}

func TestEncryptedReportRoundTripRestoresExceptionAudit(t *testing.T) {
	encryptedJSON, want := encryptedReportWithExceptionAudit(t)

	for _, secret := range []string{
		"payments-api", "finance-prod", "payments-admin", "payments-worker",
		"accept-payments-escalation", "unused-ledger-exception",
	} {
		assert.NotContains(t, string(encryptedJSON), secret)
	}

	// A field from a newer version must survive decryption.
	var encrypted map[string]any
	require.NoError(t, json.Unmarshal(encryptedJSON, &encrypted))
	encryptedAudit := encrypted["exceptionAudit"].(map[string]any)
	encryptedAudit["futureAuditField"] = "kept-audit"
	firstItem := encryptedAudit["items"].([]any)[0].(map[string]any)
	firstItem["futureItemField"] = "kept-item"
	firstItem["matchedResources"].([]any)[0].(map[string]any)["futureMatchField"] = "kept-match"
	encryptedJSON, err := json.Marshal(encrypted)
	require.NoError(t, err)

	decryptedJSON, err := reportcrypto.DecryptReport(encryptedJSON, []byte(exceptionTestMasterKey))
	require.NoError(t, err)

	var decrypted struct {
		ExceptionAudit cautils.ExceptionAudit `json:"exceptionAudit"`
	}
	require.NoError(t, json.Unmarshal(decryptedJSON, &decrypted))
	assert.Equal(t, want, decrypted.ExceptionAudit)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(decryptedJSON, &raw))
	rawAudit := raw["exceptionAudit"].(map[string]any)
	assert.Equal(t, "kept-audit", rawAudit["futureAuditField"])
	rawItem := rawAudit["items"].([]any)[0].(map[string]any)
	assert.Equal(t, "kept-item", rawItem["futureItemField"])
	assert.Equal(t, "kept-match", rawItem["matchedResources"].([]any)[0].(map[string]any)["futureMatchField"])
}

func TestDecryptReportRejectsMalformedExceptionAuditCiphertext(t *testing.T) {
	encryptedJSON, _ := encryptedReportWithExceptionAudit(t)

	for field, corrupt := range map[string]func(map[string]any){
		"item name": func(item map[string]any) {
			item["name"] = strings.TrimSuffix(item["name"].(string), "]")
		},
		"match namespace": func(item map[string]any) {
			match := item["matchedResources"].([]any)[0].(map[string]any)
			ns := match["namespace"].(string)
			match["namespace"] = ns[:len(ns)-6] + "AAAA]"
		},
		"match name": func(item map[string]any) {
			match := item["matchedResources"].([]any)[1].(map[string]any)
			name := match["name"].(string)
			match["name"] = name[:len(name)-8] + "AAAAAA==]"
		},
	} {
		t.Run(field, func(t *testing.T) {
			var report map[string]any
			require.NoError(t, json.Unmarshal(encryptedJSON, &report))
			corrupt(report["exceptionAudit"].(map[string]any)["items"].([]any)[0].(map[string]any))
			tampered, err := json.Marshal(report)
			require.NoError(t, err)

			out, err := reportcrypto.DecryptReport(tampered, []byte(exceptionTestMasterKey))
			assert.Error(t, err)
			assert.Nil(t, out)
		})
	}
}
