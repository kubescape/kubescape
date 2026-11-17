package fixhandler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
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
	fixed, err := applyFixToJSONContent(context.Background(), jsonDeployment, privilegeEscalationFix, nil)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(fixed), &decoded), "the fixed file must still parse as JSON")

	containers := decoded["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	securityContext := containers[0].(map[string]any)["securityContext"].(map[string]any)
	assert.Equal(t, false, securityContext["allowPrivilegeEscalation"])
}

func TestApplyFixToJSONContentAddsAMissingField(t *testing.T) {
	fixed, err := applyFixToJSONContent(context.Background(), jsonDeployment,
		`select(di==0) | .spec.template.spec.automountServiceAccountToken |= false`, nil)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(fixed), &decoded))

	podSpec := decoded["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	assert.Equal(t, false, podSpec["automountServiceAccountToken"])
	assert.Equal(t, "api", decoded["metadata"].(map[string]any)["name"], "untouched fields must survive the round trip")
}

func TestApplyFixToJSONContentKeepsTheOriginalIndent(t *testing.T) {
	fourSpace := strings.ReplaceAll(jsonDeployment, "  ", "    ")

	fixed, err := applyFixToJSONContent(context.Background(), fourSpace, privilegeEscalationFix, nil)
	require.NoError(t, err)

	require.Contains(t, fixed, "\n    \"apiVersion\"")
	assert.NotContains(t, fixed, "\n  \"apiVersion\"")
}

func TestApplyFixToJSONContentRejectsMalformedInput(t *testing.T) {
	_, err := applyFixToJSONContent(context.Background(), `{"kind": `, privilegeEscalationFix, nil)
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
	var scanned map[string]any
	require.NoError(t, json.Unmarshal([]byte(jsonDeployment), &scanned))
	fixes := []ResourceFixInfo{{
		Resource:        reporthandling.NewResource(scanned),
		YamlExpressions: map[string]armotypes.FixPath{privilegeEscalationFix: {}},
	}}
	fixedJSON, err := applyFixToFileContent(context.Background(), "/tmp/deploy.json", jsonDeployment, fixes)
	require.NoError(t, err)
	assert.NoError(t, json.Unmarshal([]byte(fixedJSON), &map[string]any{}))
	assert.Contains(t, fixedJSON, "\"allowPrivilegeEscalation\": false")

	yamlDeployment := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          securityContext:\n            allowPrivilegeEscalation: true\n"

	fixedYAML, err := applyFixToFileContent(context.Background(), "/tmp/deploy.yaml", yamlDeployment, fixes)
	require.NoError(t, err)
	assert.Contains(t, fixedYAML, "allowPrivilegeEscalation: false")
	assert.Error(t, json.Unmarshal([]byte(fixedYAML), &map[string]any{}), "the YAML path must not emit JSON")
}

// podWithALargeInteger is a JSON Pod with inline objects and an integer above
// 2^53, which a float64 can't hold. Re-encoding the file rewrites its layout
// and rounds the integer, though the fix touches neither.
const podWithALargeInteger = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "first", "generation": 9007199254740993},
  "spec": {"containers": [{"name": "c", "image": "nginx"}]}
}
`

func TestApplyChangesKeepsWhatTheFixDoesNotTouchInAJSONManifest(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.json", podWithALargeInteger)

	count, errs := outputDirHandler(baseDir, "").ApplyChanges(context.Background(), []ResourceFixInfo{imageFix(source, "pod.json", 0)})

	require.Empty(t, errs)
	assert.Equal(t, 1, count)
	assert.Equal(t, strings.Replace(podWithALargeInteger, `"image": "nginx"`, `"image": "nginx:1.25"`, 1), readText(t, source))
}

func TestBuildPatchKeepsWhatTheFixDoesNotTouchInAJSONManifest(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.json", podWithALargeInteger)

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pod.json", 0)})

	require.NoError(t, err)
	var removed, added []string
	for _, line := range strings.Split(result.Patch, "\n") {
		switch {
		case strings.HasPrefix(line, "---"), strings.HasPrefix(line, "+++"):
		case strings.HasPrefix(line, "-"):
			removed = append(removed, line[1:])
		case strings.HasPrefix(line, "+"):
			added = append(added, line[1:])
		}
	}
	assert.Equal(t, []string{`  "spec": {"containers": [{"name": "c", "image": "nginx"}]}`}, removed, "the patch:\n%s", result.Patch)
	assert.Equal(t, []string{`  "spec": {"containers": [{"name": "c", "image": "nginx:1.25"}]}`}, added)
}

// A field a fix adds can't be written into JSON in place, so the file is
// re-encoded then, and stays JSON.
func TestApplyFixToFileContentReEncodesAJSONManifestWhenAFixAddsAField(t *testing.T) {
	const expression = `select(di==0) | .spec.containers[0].securityContext.privileged |= false`
	fixes := []ResourceFixInfo{{
		Resource:        podResource("first"),
		YamlExpressions: map[string]armotypes.FixPath{expression: {}},
	}}

	fixed, err := applyFixToFileContent(context.Background(), "/tmp/pod.json", podWithALargeInteger, fixes)

	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(fixed), &decoded), "the fixed file must still parse as JSON:\n%s", fixed)
	container := decoded["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	assert.Equal(t, map[string]any{"privileged": false}, container["securityContext"])
}
