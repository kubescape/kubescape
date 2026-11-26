package policytest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyTestValidatingAdmissionPolicy(t *testing.T) {
	const policy = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-team-label
spec:
  matchConstraints:
    resourceRules:
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      operations: ["CREATE"]
      resources: ["deployments"]
  validations:
  - expression: "has(object.metadata.labels) && 'team' in object.metadata.labels"
    message: "team label is required"
`
	const manifests = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: compliant
  labels:
    team: platform
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: missing-label
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: unrelated
`

	root := t.TempDir()
	dir := filepath.Join(root, "require-team-label")
	input := filepath.Join(dir, "test", "mixed", "input")
	require.NoError(t, os.MkdirAll(input, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(policy), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(input, "objects.yaml"), []byte(manifests), 0644))

	rules, err := DiscoverPath(root)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	direct, err := DiscoverPath(dir)
	require.NoError(t, err)
	require.Equal(t, direct, rules)
	rule := rules[0]
	require.Len(t, rule.Cases, 1)

	responses, err := EvaluateCase(t.Context(), rule, rule.Cases[0])
	require.NoError(t, err)
	require.Len(t, responses, 1)
	require.Equal(t, "team label is required", responses[0].AlertMessage)
	require.Len(t, responses[0].AlertObject.K8SApiObjects, 1)
	require.Equal(t, "missing-label", responses[0].AlertObject.K8SApiObjects[0]["metadata"].(map[string]any)["name"])

	updates := UpdateRule(t.Context(), rule)
	require.Len(t, updates, 1)
	require.NoError(t, updates[0].Err)
	require.True(t, updates[0].Changed)
	results := RunRule(t.Context(), rule)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Err)
	require.True(t, results[0].Passed, results[0].Diff)
}
