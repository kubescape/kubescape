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

// malformedKeyedSegmentPaths name a field of a list, which no resource has:
// "env['ignored'][1]" asks for the key "ignored" on the env slice and then its
// element 1. Traversal used to satisfy that by discarding the key and indexing
// anyway, which resolved the credential - while isSensitivePath, reading the
// same segments, saw "ignored" rather than "env" and judged the path harmless.
// Traversal now fails closed, so both agree the path means nothing.
var malformedKeyedSegmentPaths = []string{
	"spec.template.spec.containers[0].env['ignored'][1].value",
	`spec.template.spec.containers[0].env["ignored"][1].value`,
	"spec.template.spec.containers[0].env[ignored][1].value",
}

func TestMalformedKeyedSegmentResolvesNothing(t *testing.T) {
	obj := envCredentialResource().GetObject()
	for _, path := range malformedKeyedSegmentPaths {
		t.Run(path, func(t *testing.T) {
			got, ok := extractValueAtPath(obj, path)
			assert.False(t, ok, "a keyed segment on a list must not resolve")
			assert.Empty(t, got)
		})
	}
}

// TestMalformedKeyedSegmentNeverReachesOutput is the output-level guard for the
// same paths: whatever the classifier makes of them, nothing may reach Evidence
// or the --show-evidence column.
func TestMalformedKeyedSegmentNeverReachesOutput(t *testing.T) {
	for _, path := range malformedKeyedSegmentPaths {
		t.Run(path, func(t *testing.T) {
			resource := envCredentialResource()

			evidence := failedPathValues(&resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{Paths: []armotypes.PosturePaths{{FailedPath: path}}},
				},
			}, resource)
			for _, pv := range evidence {
				assert.NotContains(t, pv.Value, envFixtureValue,
					"malformed path reached Evidence")
			}

			control := &resourcesresults.ResourceAssociatedControl{
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{Paths: []armotypes.PosturePaths{{ReviewPath: path}}},
				},
			}
			for _, showSecrets := range []bool{false, true} {
				out := strings.Join(
					AssistedRemediationPathsWithCurrentValuesFiltered(control, resource, showSecrets), "\n")
				assert.NotContains(t, out, envFixtureValue,
					"malformed path reached the evidence column (showSecrets=%v)", showSecrets)
			}
		})
	}
}
