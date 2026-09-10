package fixhandler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const jsonDeployment = `{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {
    "name": "api"
  },
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "app",
            "securityContext": {
              "allowPrivilegeEscalation": true
            }
          }
        ]
      }
    }
  }
}
`

const privilegeEscalationFix = `select(di==0) | .spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation |= false`

func TestApplyFixToJSONContentRewritesTheValue(t *testing.T) {
	fixed, err := applyFixToJSONContent(context.Background(), jsonDeployment, privilegeEscalationFix)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(fixed), &decoded), "the fixed file must still parse as JSON")

	containers := decoded["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	securityContext := containers[0].(map[string]any)["securityContext"].(map[string]any)
	assert.Equal(t, false, securityContext["allowPrivilegeEscalation"])
}

func TestApplyFixToJSONContentAddsAMissingField(t *testing.T) {
	fixed, err := applyFixToJSONContent(context.Background(), jsonDeployment,
		`select(di==0) | .spec.template.spec.automountServiceAccountToken |= false`)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(fixed), &decoded))

	podSpec := decoded["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	assert.Equal(t, false, podSpec["automountServiceAccountToken"])
	assert.Equal(t, "api", decoded["metadata"].(map[string]any)["name"], "untouched fields must survive the round trip")
}

func TestApplyFixToJSONContentKeepsTheOriginalIndent(t *testing.T) {
	fourSpace := strings.ReplaceAll(jsonDeployment, "  ", "    ")

	fixed, err := applyFixToJSONContent(context.Background(), fourSpace, privilegeEscalationFix)
	require.NoError(t, err)

	require.Contains(t, fixed, "\n    \"apiVersion\"")
	assert.NotContains(t, fixed, "\n  \"apiVersion\"")
}

func TestApplyFixToJSONContentRejectsMalformedInput(t *testing.T) {
	_, err := applyFixToJSONContent(context.Background(), `{"kind": `, privilegeEscalationFix)
	assert.Error(t, err)
}

func TestDetectJSONIndent(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "two spaces", in: "{\n  \"a\": 1\n}", want: 2},
		{name: "four spaces", in: "{\n    \"a\": 1\n}", want: 4},
		{name: "tabs fall back to the default", in: "{\n\t\"a\": 1\n}", want: defaultJSONIndent},
		{name: "minified falls back to the default", in: `{"a":1}`, want: defaultJSONIndent},
		{name: "empty falls back to the default", in: "", want: defaultJSONIndent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, detectJSONIndent(tt.in))
		})
	}
}

func TestIsJSONSource(t *testing.T) {
	assert.True(t, isJSONSource("/tmp/deploy.json"))
	assert.True(t, isJSONSource("/tmp/Deploy.JSON"))
	assert.False(t, isJSONSource("/tmp/deploy.yaml"))
	assert.False(t, isJSONSource("/tmp/deploy.yml"))
	assert.False(t, isJSONSource("/tmp/deploy"))
	assert.False(t, isJSONSource("/tmp/json/deploy.yaml"))
}

func TestIsFixableSourceType(t *testing.T) {
	assert.True(t, isFixableSourceType(reporthandling.SourceTypeYaml))
	assert.True(t, isFixableSourceType(reporthandling.SourceTypeJson))
	assert.False(t, isFixableSourceType(reporthandling.SourceTypeHelmChart))
	assert.False(t, isFixableSourceType(""))
}

// TestApplyFixToFileContentPreservesTheSourceFormat is the reason the dispatch
// exists: emitting YAML into a .json manifest would break every tool that reads
// it back.
func TestApplyFixToFileContentPreservesTheSourceFormat(t *testing.T) {
	fixedJSON, err := applyFixToFileContent(context.Background(), "/tmp/deploy.json", jsonDeployment, privilegeEscalationFix)
	require.NoError(t, err)
	assert.NoError(t, json.Unmarshal([]byte(fixedJSON), &map[string]any{}))

	yamlDeployment := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          securityContext:\n            allowPrivilegeEscalation: true\n"

	fixedYAML, err := applyFixToFileContent(context.Background(), "/tmp/deploy.yaml", yamlDeployment, privilegeEscalationFix)
	require.NoError(t, err)
	assert.Contains(t, fixedYAML, "allowPrivilegeEscalation: false")
	assert.Error(t, json.Unmarshal([]byte(fixedYAML), &map[string]any{}), "the YAML path must not emit JSON")
}
