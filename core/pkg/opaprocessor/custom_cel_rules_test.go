package opaprocessor

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomCELRuleEvaluation(t *testing.T) {
	vapYAML := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: disallow-host-ipc
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "!has(object.spec.hostIPC) || !object.spec.hostIPC"
      message: "hostIPC is forbidden"
`

	pod := func(name string, hostIPC bool) map[string]any {
		spec := map[string]any{}
		if hostIPC {
			spec["hostIPC"] = true
		}
		return map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": name, "namespace": "default"},
			"spec":       spec,
		}
	}

	objects := []map[string]any{
		pod("bad-pod", true),
		pod("good-pod", false),
	}

	scanner := newParityScanner(t, objects, nil)
	rule := reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "custom-disallow-host-ipc"},
		RuleLanguage: reporthandling.CELLanguage,
		Rule:         vapYAML,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"},
		}},
	}
	control := reporthandling.Control{
		ControlID: "custom-disallow-host-ipc",
		Rules:     []reporthandling.PolicyRule{rule},
	}

	results, err := scanner.processRule(context.Background(), &rule, nil, evaluationScope{}, &control)
	require.NoError(t, err)
	require.Len(t, results, 2)

	badResult := results["/v1/default/Pod/bad-pod"]
	require.NotNil(t, badResult)
	assert.Equal(t, apis.StatusFailed, badResult.Status)

	goodResult := results["/v1/default/Pod/good-pod"]
	require.NotNil(t, goodResult)
	assert.Equal(t, apis.StatusPassed, goodResult.Status)
}
