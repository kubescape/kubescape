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
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const exceptionTestMasterKey = "01234567890123456789012345678901"

func exceptionRoundTripPolicies() []armotypes.PostureExceptionPolicy {
	inlineReason := "accepted by payments-on-call for payroll-ns-7731"
	externalReason := "legacy batch job owned by finance"
	return []armotypes.PostureExceptionPolicy{
		{
			PortalBase: armotypes.PortalBase{
				GUID: "guid-inline-9f3a",
				Name: "inline-apps/v1/Deployment/payroll-ns-7731/salary-batch-4471",
			},
			PolicyType: "postureExceptionPolicy",
			Actions:    []armotypes.PostureExceptionPolicyActions{"alertOnly"},
			Reason:     &inlineReason,
		},
		{
			PortalBase: armotypes.PortalBase{
				GUID: "guid-external-77c1",
				Name: "finance-legacy-batch",
			},
			PolicyType: "postureExceptionPolicy",
			Actions:    []armotypes.PostureExceptionPolicyActions{"disable"},
			Reason:     &externalReason,
		},
		{
			// Legitimately empty reason and name: nothing to encrypt.
			PortalBase: armotypes.PortalBase{GUID: "guid-no-reason"},
			PolicyType: "postureExceptionPolicy",
		},
	}
}

func encryptedReportWithExceptions(t *testing.T, exceptions []armotypes.PostureExceptionPolicy) []byte {
	t.Helper()

	workload, err := workloadinterface.NewWorkload([]byte(`{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {"name": "salary-batch-4471", "namespace": "payroll-ns-7731"},
		"spec": {"template": {"spec": {"containers": [{"name": "api", "image": "batch:v1"}]}}}
	}`))
	require.NoError(t, err)
	id := workload.GetID()

	result := resourcesresults.Result{
		ResourceID:          id,
		PrioritizedResource: &prioritization.PrioritizedResource{ResourceID: id},
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
			ControlID: "C-0010",
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
				Name:      "Resource limits",
				Exception: exceptions,
			}},
		}},
	}
	session := &cautils.OPASessionObj{
		AllResources:         map[string]workloadinterface.IMetadata{id: workload},
		ResourcesResult:      map[string]resourcesresults.Result{id: result},
		ResourcesPrioritized: map[string]prioritization.PrioritizedResource{id: *result.PrioritizedResource},
		ResourceSource:       map[string]reporthandling.Source{},
		Metadata:             &reporthandlingv2.Metadata{},
		Report:               &reporthandlingv2.PostureReport{},
	}

	handler := &resultshandling.ResultsHandler{ScanData: session}
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	require.NoError(t, anonymizer.ApplyEncrypted(handler, dek, []byte(exceptionTestMasterKey)))
	encrypted, err := handler.ToJson()
	require.NoError(t, err)
	return encrypted
}

func firstRule(t *testing.T, report map[string]any) map[string]any {
	t.Helper()
	result := report["results"].([]any)[0].(map[string]any)
	return result["controls"].([]any)[0].(map[string]any)["rules"].([]any)[0].(map[string]any)
}

func TestEncryptedReportRoundTripRestoresExceptionMetadata(t *testing.T) {
	policies := exceptionRoundTripPolicies()
	encryptedJSON := encryptedReportWithExceptions(t, policies)

	// Nothing sensitive may be readable before decryption.
	for _, secret := range []string{
		"salary-batch-4471", "payroll-ns-7731", "guid-inline-9f3a", "guid-external-77c1",
		"finance-legacy-batch", "payments-on-call", "legacy batch job",
	} {
		assert.NotContains(t, string(encryptedJSON), secret)
	}

	// A field from a newer version must survive decryption.
	var encrypted map[string]any
	require.NoError(t, json.Unmarshal(encryptedJSON, &encrypted))
	rule := firstRule(t, encrypted)
	rule["futureRuleField"] = "kept-rule"
	exceptions := rule["exception"].([]any)
	require.Len(t, exceptions, len(policies))
	assert.True(t, strings.HasPrefix(exceptions[0].(map[string]any)["name"].(string), "ENC["))
	exceptions[0].(map[string]any)["futureExceptionField"] = "kept-exception"
	encryptedJSON, err := json.Marshal(encrypted)
	require.NoError(t, err)

	decryptedJSON, err := reportcrypto.DecryptReport(encryptedJSON, []byte(exceptionTestMasterKey))
	require.NoError(t, err)

	var decrypted map[string]any
	require.NoError(t, json.Unmarshal(decryptedJSON, &decrypted))
	decryptedRule := firstRule(t, decrypted)
	assert.Equal(t, "kept-rule", decryptedRule["futureRuleField"])
	got := decryptedRule["exception"].([]any)
	require.Len(t, got, len(policies))

	for i, want := range policies {
		g := got[i].(map[string]any)
		assert.Equal(t, want.Name, g["name"], "exception[%d].name", i)
		assert.Equal(t, want.GUID, g["guid"], "exception[%d].guid", i)
		if want.Reason != nil {
			assert.Equal(t, *want.Reason, g["reason"], "exception[%d].reason", i)
		} else {
			assert.NotContains(t, g, "reason")
		}
		assert.Equal(t, want.PolicyType, g["policyType"])
	}
	assert.Equal(t, "kept-exception", got[0].(map[string]any)["futureExceptionField"])
}

func TestEncryptedReportRoundTripWithoutExceptions(t *testing.T) {
	encryptedJSON := encryptedReportWithExceptions(t, nil)
	decryptedJSON, err := reportcrypto.DecryptReport(encryptedJSON, []byte(exceptionTestMasterKey))
	require.NoError(t, err)

	var decrypted map[string]any
	require.NoError(t, json.Unmarshal(decryptedJSON, &decrypted))
	assert.NotContains(t, firstRule(t, decrypted), "exception")
}

func TestDecryptReportRejectsMalformedExceptionCiphertext(t *testing.T) {
	encryptedJSON := encryptedReportWithExceptions(t, exceptionRoundTripPolicies())

	for field, corrupt := range map[string]func(string) string{
		"name":   func(s string) string { return s[:len(s)-6] + "AAAA]" },
		"guid":   func(s string) string { return strings.TrimSuffix(s, "]") },
		"reason": func(s string) string { return s[:len(s)-8] + "AAAAAA==]" },
	} {
		t.Run(field, func(t *testing.T) {
			var report map[string]any
			require.NoError(t, json.Unmarshal(encryptedJSON, &report))
			exception := firstRule(t, report)["exception"].([]any)[0].(map[string]any)
			exception[field] = corrupt(exception[field].(string))
			tampered, err := json.Marshal(report)
			require.NoError(t, err)

			out, err := reportcrypto.DecryptReport(tampered, []byte(exceptionTestMasterKey))
			assert.Error(t, err)
			assert.Nil(t, out)
		})
	}
}
