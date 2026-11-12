package anonymizer

import (
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exceptionAuditFixture is a scan in which one exception matched a namespaced
// Deployment and a cluster-scoped ClusterRole, plus an audit entry for a
// resource the scan did not keep in its catalog.
func exceptionAuditFixture(t *testing.T) (*cautils.OPASessionObj, string, string) {
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
		PortalBase:      armotypes.PortalBase{Name: "accept-payments-escalation", GUID: "guid-payments"},
		PolicyType:      "postureExceptionPolicy",
		Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
		PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0016"}},
	}
	result := func(id string) resourcesresults.Result {
		return resourcesresults.Result{
			ResourceID: id,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID: "C-0016",
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
					Name:      "rule-allow-privilege-escalation",
					Exception: []armotypes.PostureExceptionPolicy{exception},
				}},
			}},
		}
	}

	session := &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{deploymentID: deployment, clusterRoleID: clusterRole},
		ResourcesResult: map[string]resourcesresults.Result{
			deploymentID:  result(deploymentID),
			clusterRoleID: result(clusterRoleID),
		},
		ResourceSource: map[string]reporthandling.Source{},
		Metadata:       &reporthandlingv2.Metadata{},
		Report:         &reporthandlingv2.PostureReport{},
		ExceptionAudit: &cautils.ExceptionAudit{
			Summary:   cautils.ExceptionAuditSummary{Total: 2, Active: 2, Matched: 1, Unused: 1},
			Generated: true,
			Items: []cautils.ExceptionAuditItem{
				{
					Name: "accept-payments-escalation", Status: "matched", MatchCount: 3,
					ControlIDs: []string{"C-0016"},
					MatchedResources: []cautils.ExceptionAuditMatch{
						{ResourceID: deploymentID, Kind: "Deployment", Namespace: "finance-prod", Name: "payments-api",
							ControlID: "C-0016", RuleName: "rule-allow-privilege-escalation"},
						{ResourceID: clusterRoleID, Kind: "ClusterRole", Name: "payments-admin",
							ControlID: "C-0016", RuleName: "rule-allow-privilege-escalation"},
						{ResourceID: "apps/v1/finance-prod/Deployment/payments-worker",
							ControlID: "C-0016", RuleName: "rule-allow-privilege-escalation"},
					},
				},
				{Name: "unused-ledger-exception", Status: "unused", ControlIDs: []string{"C-0017"}, InvalidControls: []string{"C-9999"}},
			},
		},
	}
	return session, deploymentID, clusterRoleID
}

var exceptionAuditSecrets = []string{
	"payments-api", "finance-prod", "payments-admin", "payments-worker",
	"accept-payments-escalation", "unused-ledger-exception",
}

func TestApplyHidesExceptionAudit(t *testing.T) {
	session, deploymentID, _ := exceptionAuditFixture(t)
	original, err := cloneJSON(*session.ExceptionAudit)
	require.NoError(t, err)

	require.NoError(t, Apply(&resultshandling.ResultsHandler{ScanData: session}))

	audit := session.ExceptionAudit
	require.NotNil(t, audit)
	encoded, err := json.Marshal(audit)
	require.NoError(t, err)
	for _, secret := range exceptionAuditSecrets {
		assert.NotContains(t, string(encoded), secret, "--hide must not leave %q in the exception audit", secret)
	}

	// Everything without an identity is reported unchanged.
	assert.Equal(t, original.Summary, audit.Summary)
	assert.Equal(t, original.Generated, audit.Generated)
	require.Len(t, audit.Items, len(original.Items))
	for i := range original.Items {
		assert.Equal(t, original.Items[i].Status, audit.Items[i].Status)
		assert.Equal(t, original.Items[i].MatchCount, audit.Items[i].MatchCount)
		assert.Equal(t, original.Items[i].ControlIDs, audit.Items[i].ControlIDs)
		assert.Equal(t, original.Items[i].InvalidControls, audit.Items[i].InvalidControls)
		require.Len(t, audit.Items[i].MatchedResources, len(original.Items[i].MatchedResources))
		for j, want := range original.Items[i].MatchedResources {
			got := audit.Items[i].MatchedResources[j]
			assert.Equal(t, want.Kind, got.Kind)
			assert.Equal(t, want.ControlID, got.ControlID)
			assert.Equal(t, want.RuleName, got.RuleName)
		}
	}

	matches := audit.Items[0].MatchedResources
	// An audited resource must still be found among the results it suppressed.
	for _, match := range matches[:2] {
		assert.Contains(t, session.ResourcesResult, match.ResourceID, "audit entry must point at the anonymized result")
	}
	deployment, ok := session.GetCatalog().Get(matches[0].ResourceID)
	require.True(t, ok, "audit entry must point at the anonymized resource")
	assert.Equal(t, deployment.GetName(), matches[0].Name)
	assert.Equal(t, deployment.GetNamespace(), matches[0].Namespace)
	assert.NotEqual(t, deploymentID, matches[0].ResourceID)
	// A cluster-scoped resource has no namespace to hide.
	assert.Empty(t, matches[1].Namespace)
	assert.NotEmpty(t, matches[1].Name)
	// A resource outside the catalog is still pseudonymized, not dropped.
	assert.NotEmpty(t, matches[2].ResourceID)

	// The audit names the exception the same way the results do.
	rule := session.ResourcesResult[matches[0].ResourceID].AssociatedControls[0].ResourceAssociatedRules[0]
	require.Len(t, rule.Exception, 1)
	assert.Equal(t, rule.Exception[0].Name, audit.Items[0].Name)
}

func TestApplyEncryptedEncryptsExceptionAudit(t *testing.T) {
	session, _, _ := exceptionAuditFixture(t)
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}

	require.NoError(t, ApplyEncrypted(&resultshandling.ResultsHandler{ScanData: session}, dek, []byte("01234567890123456789012345678901")))

	encoded, err := json.Marshal(session.ExceptionAudit)
	require.NoError(t, err)
	for _, secret := range exceptionAuditSecrets {
		assert.NotContains(t, string(encoded), secret, "--encrypt must not leave %q in the exception audit", secret)
	}
	matches := session.ExceptionAudit.Items[0].MatchedResources
	for _, match := range matches[:2] {
		assert.Contains(t, session.ResourcesResult, match.ResourceID, "audit entry must point at the encrypted result")
	}
	require.Contains(t, session.ResourcesResult, matches[0].ResourceID)
	rule := session.ResourcesResult[matches[0].ResourceID].AssociatedControls[0].ResourceAssociatedRules[0]
	assert.Equal(t, rule.Exception[0].Name, session.ExceptionAudit.Items[0].Name,
		"one exception must carry one ciphertext, so readers can tell it is the same exception")
}

func TestApplyLeavesAbsentExceptionAuditAbsent(t *testing.T) {
	session, _, _ := exceptionAuditFixture(t)
	session.ExceptionAudit = nil
	require.NoError(t, Apply(&resultshandling.ResultsHandler{ScanData: session}))
	assert.Nil(t, session.ExceptionAudit)
}

// A failed transformation must leave the audit exactly as it was, like every
// other part of the session.
func TestTransformSessionRollsBackExceptionAudit(t *testing.T) {
	for _, tc := range []struct{ prefix, value string }{
		{"res", "payments-api"},                                    // fails while transforming the catalog
		{"exception", "unused-ledger-exception"},                   // fails inside the audit itself
		{"ref", "apps/v1/finance-prod/Deployment/payments-worker"}, // fails on an uncatalogued ID
	} {
		t.Run(tc.prefix+"/"+tc.value, func(t *testing.T) {
			session, _, _ := exceptionAuditFixture(t)
			before, err := json.Marshal(session.ExceptionAudit)
			require.NoError(t, err)
			auditPointer := session.ExceptionAudit

			err = transformSession(session, nil, &selectiveFailTransformer{
				delegate: NewMappingTransformer(), failPrefix: tc.prefix, failValue: tc.value,
			})
			require.ErrorIs(t, err, errInjectedTransform)

			assert.Same(t, auditPointer, session.ExceptionAudit)
			after, err := json.Marshal(session.ExceptionAudit)
			require.NoError(t, err)
			assert.JSONEq(t, string(before), string(after))
		})
	}
}
