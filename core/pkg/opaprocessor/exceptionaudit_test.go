package opaprocessor

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildExceptionAudit(t *testing.T) {
	expiredAt := time.Now().Add(-time.Hour)
	matchedException := auditException("matched-exception", "C-0001", nil)
	unusedException := auditException("unused-exception", "C-0002", nil)
	expiredException := auditException("expired-exception", "C-0003", &expiredAt)
	invalidControlException := auditException("invalid-control-exception", "C-9999", nil)

	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "default",
		},
	})

	audit := buildExceptionAudit(
		[]armotypes.PostureExceptionPolicy{matchedException, unusedException, expiredException, invalidControlException},
		[]armotypes.PostureExceptionPolicy{matchedException, unusedException, invalidControlException},
		map[string]resourcesresults.Result{
			resource.GetID(): {
				ResourceID: resource.GetID(),
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0001",
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Name:      "rule-a",
								Exception: []armotypes.PostureExceptionPolicy{matchedException},
							},
						},
					},
				},
			},
		},
		map[string]workloadinterface.IMetadata{resource.GetID(): resource},
		&cautils.Policies{
			Controls: map[string]reporthandling.Control{
				"C-0001": {ControlID: "C-0001"},
				"C-0002": {ControlID: "C-0002"},
				"C-0003": {ControlID: "C-0003"},
			},
		},
		exceptions.NewProcessor(),
	)

	require.NotNil(t, audit)
	assert.True(t, audit.Generated)
	assert.Equal(t, 4, audit.Summary.Total)
	assert.Equal(t, 3, audit.Summary.Active)
	assert.Equal(t, 1, audit.Summary.Expired)
	assert.Equal(t, 1, audit.Summary.Matched)
	assert.Equal(t, 1, audit.Summary.Unused)
	assert.Equal(t, 1, audit.Summary.InvalidControl)

	items := map[string]cautils.ExceptionAuditItem{}
	for _, item := range audit.Items {
		items[item.Name] = item
	}

	assert.Equal(t, exceptionAuditStatusMatched, items["matched-exception"].Status)
	assert.Equal(t, 1, items["matched-exception"].MatchCount)
	require.Len(t, items["matched-exception"].MatchedResources, 1)
	assert.Equal(t, "Deployment", items["matched-exception"].MatchedResources[0].Kind)
	assert.Equal(t, "default", items["matched-exception"].MatchedResources[0].Namespace)
	assert.Equal(t, "nginx", items["matched-exception"].MatchedResources[0].Name)
	assert.Equal(t, "C-0001", items["matched-exception"].MatchedResources[0].ControlID)
	assert.Equal(t, "rule-a", items["matched-exception"].MatchedResources[0].RuleName)

	assert.Equal(t, exceptionAuditStatusUnused, items["unused-exception"].Status)
	assert.Equal(t, exceptionAuditStatusExpired, items["expired-exception"].Status)
	assert.True(t, items["expired-exception"].Expired)
	assert.Equal(t, exceptionAuditStatusInvalidControl, items["invalid-control-exception"].Status)
	assert.Equal(t, []string{"C-9999"}, items["invalid-control-exception"].InvalidControls)
}

func TestBuildExceptionAuditTreatsRegexControlAsValid(t *testing.T) {
	regexException := auditException("regex-exception", "C-000[12]", nil)

	audit := buildExceptionAudit(
		[]armotypes.PostureExceptionPolicy{regexException},
		[]armotypes.PostureExceptionPolicy{regexException},
		nil,
		nil,
		&cautils.Policies{
			Controls: map[string]reporthandling.Control{
				"C-0001": {ControlID: "C-0001"},
			},
		},
		exceptions.NewProcessor(),
	)

	require.NotNil(t, audit)
	require.Len(t, audit.Items, 1)
	assert.Empty(t, audit.Items[0].InvalidControls)
	assert.Equal(t, exceptionAuditStatusUnused, audit.Items[0].Status)
}

func TestBuildExceptionAuditDoesNotCollapseDuplicateNamesWithDifferentGUIDs(t *testing.T) {
	firstException := auditExceptionWithGUID("guid-1", "dup-name", "C-0001", nil)
	secondException := auditExceptionWithGUID("guid-2", "dup-name", "C-0002", nil)

	audit := buildExceptionAudit(
		[]armotypes.PostureExceptionPolicy{firstException, secondException},
		[]armotypes.PostureExceptionPolicy{firstException, secondException},
		nil,
		nil,
		&cautils.Policies{
			Controls: map[string]reporthandling.Control{
				"C-0001": {ControlID: "C-0001"},
				"C-0002": {ControlID: "C-0002"},
			},
		},
		exceptions.NewProcessor(),
	)

	require.NotNil(t, audit)
	require.Len(t, audit.Items, 2)
	assert.Equal(t, 2, audit.Summary.Total)
	assert.Equal(t, 2, audit.Summary.Active)

	var gotControlIDs []string
	for _, item := range audit.Items {
		assert.Equal(t, "dup-name", item.Name)
		require.Len(t, item.ControlIDs, 1)
		gotControlIDs = append(gotControlIDs, item.ControlIDs[0])
	}
	assert.ElementsMatch(t, []string{"C-0001", "C-0002"}, gotControlIDs)
}

func auditException(name, controlID string, expirationDate *time.Time) armotypes.PostureExceptionPolicy {
	return auditExceptionWithGUID("", name, controlID, expirationDate)
}

func auditExceptionWithGUID(guid, name, controlID string, expirationDate *time.Time) armotypes.PostureExceptionPolicy {
	return armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{GUID: guid, Name: name},
		PosturePolicies: []armotypes.PosturePolicy{
			{ControlID: controlID},
		},
		ExpirationDate: expirationDate,
	}
}
