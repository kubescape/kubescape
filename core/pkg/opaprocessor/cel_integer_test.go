package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCELIntegerHandlingFromManifestReaders(t *testing.T) {
	const manifest = `{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": {"name": "integers", "namespace": "default"},
		"spec": {
			"replicas": 3,
			"selector": {"matchLabels": {"app": "integers"}},
			"template": {
				"metadata": {"labels": {"app": "integers"}},
				"spec": {
					"activeDeadlineSeconds": 9007199254740993,
					"terminationGracePeriodSeconds": 9007199254740992,
					"containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": 8080}]}]
				}
			}
		}
	}`
	rule := reporthandling.PolicyRule{
		RuleLanguage: reporthandling.CELLanguage,
		Rule: `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: integer-handling
spec:
  matchConditions:
  - name: integer-arithmetic
    expression: object.spec.replicas + 1 == 4
  validations:
  - expression: type(object.spec.replicas) == int
  - expression: object.spec.template.spec.activeDeadlineSeconds != object.spec.template.spec.terminationGracePeriodSeconds
  - expression: object.spec.template.spec.activeDeadlineSeconds == 9007199254740993
  - expression: object.spec.template.spec.containers.all(c, c.ports.all(p, p.containerPort + 1 == 8081))
`,
	}
	for _, format := range []cautils.FileFormat{cautils.JSON_FILE_FORMAT, cautils.YAML_FILE_FORMAT} {
		t.Run(string(format), func(t *testing.T) {
			workloads, err := cautils.ReadFile([]byte(manifest), format)
			require.NoError(t, err)
			require.Len(t, workloads, 1)
			objects := []map[string]any{workloads[0].GetObject()}
			scanner := newParityScanner(t, objects, nil)

			responses, outcome, err := scanner.runCELOnK8s(context.Background(), &rule, objects, nil, "C-integers")
			require.NoError(t, err)
			assert.Empty(t, responses, "all integer validations must pass")
			assert.Empty(t, outcome.excluded, "integer arithmetic must admit the object through the gate")
			assert.Empty(t, outcome.skipped)
		})
	}
}
