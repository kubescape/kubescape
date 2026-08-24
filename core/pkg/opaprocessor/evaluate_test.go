package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const denyAllPodsRule = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Deployment"
	msga := {
		"alertMessage": sprintf("deployment %v denied", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"fixPaths": [],
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [pod]}
	}
}
`

// TestEvaluateRule_ReturnsFailureForMatchingResource verifies that
// EvaluateRule runs a standalone rule against a resource list and produces
// the same violation a real scan would, without needing a full scan session.
func TestEvaluateRule_ReturnsFailureForMatchingResource(t *testing.T) {
	deployment := mocks.MockDevelopmentWithHostpath()

	sessionObj := cautils.NewOPASessionObjMock()
	proc := NewOPAProcessor(sessionObj, &resources.RegoDependenciesData{}, "", "", "", false, nil)

	rule := &reporthandling.PolicyRule{
		PortalBase: armotypes.PortalBase{
			Name: "deny-all-deployments",
		},
		Rule:         denyAllPodsRule,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{
				APIGroups:   []string{"apps"},
				APIVersions: []string{"v1"},
				Resources:   []string{"Deployment"},
			},
		},
	}

	responses, err := proc.EvaluateRule(context.Background(), rule, []workloadinterface.IMetadata{deployment}, "C-TEST")
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Contains(t, responses[0].AlertMessage, "denied")
}

func TestEvaluateRule_NoMatchingResourcesReturnsEmpty(t *testing.T) {
	sessionObj := cautils.NewOPASessionObjMock()
	proc := NewOPAProcessor(sessionObj, &resources.RegoDependenciesData{}, "", "", "", false, nil)

	rule := &reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "deny-all-deployments"},
		Rule:         denyAllPodsRule,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"Deployment"}},
		},
	}

	responses, err := proc.EvaluateRule(context.Background(), rule, nil, "C-TEST")
	require.NoError(t, err)
	assert.Empty(t, responses)
}
