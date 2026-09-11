package printer

import (
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The value a C-0012 finding points at. Named rather than inlined so the
// assertions below read as "this must not appear anywhere in the output".
const envFixtureValue = "fixture-value-that-must-not-be-printed"

// envCredentialResource builds a Deployment carrying a plaintext credential in
// a container environment variable, the shape C-0012 reports.
func envCredentialResource() *mockResource {
	return &mockResource{kind: "Deployment", obj: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "payments-api"},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name": "api",
							"env": []any{
								map[string]any{"name": "PORT", "value": "8080"},
								map[string]any{"name": "DB_PASSWORD", "value": envFixtureValue},
							},
						},
					},
				},
			},
		},
	}}
}

// envValueSpellings are the ways a rule can name the same container env value.
// Extraction resolves all of them, so each has to be classified as sensitive;
// one that is not is a credential printed without --show-secrets.
var envValueSpellings = []struct {
	name string
	path string
}{
	{name: "plain", path: "spec.template.spec.containers[0].env[1].value"},
	{name: "single-quoted bracket", path: "spec.template.spec.containers[0]['env'][1].value"},
	{name: "double-quoted bracket", path: `spec.template.spec.containers[0]["env"][1].value`},
}

// TestEnvValueNeverReachesEvidenceOutput is the output-level guard: whatever
// spelling a rule uses, the credential must not appear in the Evidence a
// report carries.
func TestEnvValueNeverReachesEvidenceOutput(t *testing.T) {
	for _, spelling := range envValueSpellings {
		t.Run(spelling.name, func(t *testing.T) {
			control := &resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{Paths: []armotypes.PosturePaths{{FailedPath: spelling.path}}},
				},
			}

			got := failedPathValues(control, envCredentialResource())

			for _, pv := range got {
				assert.NotContains(t, pv.Value, envFixtureValue,
					"env value reached Evidence through the %s spelling", spelling.name)
			}
		})
	}
}

// TestEnvValueNeverReachesRemediationOutput is the same guard on the column
// --show-evidence prints. The value must be redacted by default and appear only
// when --show-secrets is passed, in every spelling.
func TestEnvValueNeverReachesRemediationOutput(t *testing.T) {
	for _, spelling := range envValueSpellings {
		t.Run(spelling.name, func(t *testing.T) {
			control := &resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{Paths: []armotypes.PosturePaths{{ReviewPath: spelling.path}}},
				},
			}
			resource := envCredentialResource()

			redacted := strings.Join(
				AssistedRemediationPathsWithCurrentValuesFiltered(control, resource, false), "\n")
			assert.NotContains(t, redacted, envFixtureValue,
				"env value printed by default through the %s spelling", spelling.name)
			assert.Contains(t, redacted, redactedValue)

			shown := strings.Join(
				AssistedRemediationPathsWithCurrentValuesFiltered(control, resource, true), "\n")
			assert.Contains(t, shown, envFixtureValue,
				"--show-secrets must still opt back in")
		})
	}
}

// TestEnvValueSpellingsAllResolve is what makes the two tests above meaningful.
// If extraction could not resolve a spelling there would be nothing to leak and
// they would pass vacuously; this pins that every spelling really does reach
// the credential, so redaction is doing the work.
func TestEnvValueSpellingsAllResolve(t *testing.T) {
	obj := envCredentialResource().GetObject()
	for _, spelling := range envValueSpellings {
		t.Run(spelling.name, func(t *testing.T) {
			got, ok := extractValueAtPath(obj, spelling.path)
			require.True(t, ok, "spelling should resolve, or the redaction test is vacuous")
			assert.Equal(t, envFixtureValue, got)
		})
	}
}
