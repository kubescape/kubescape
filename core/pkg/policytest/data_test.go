package policytest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/ruledir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// controlInputsRuleMetadata declares the untrustedRegistries posture input,
// so a scan, and policy test, hand the rule only that input.
const controlInputsRuleMetadata = `{
  "name": "control-inputs",
  "ruleLanguage": "Rego",
  "match": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["Pod"]}],
  "controlConfigInputs": [
    {
      "path": "settings.postureControlInputs.untrustedRegistries",
      "name": "Untrusted registries",
      "description": "Registries no image may come from."
    }
  ],
  "ruleQuery": "armo_builtins"
}
`

// controlInputsRuleRego flags a container whose image comes from an untrusted
// registry, and any Pod on EKS, so each kind of control input changes the
// outcome of evaluating the same Pod.
const controlInputsRuleRego = `package armo_builtins

import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	registry := data.postureControlInputs.untrustedRegistries[_]
	startswith(container.image, registry)
	msga := {
		"alertMessage": sprintf("container %v uses untrusted registry %v", [container.name, registry]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"reviewPaths": [sprintf("spec.containers[%v].image", [i])],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	data.dataControlInputs.cloudProvider == "eks"
	msga := {
		"alertMessage": sprintf("Pod %v runs on EKS", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 1,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}
`

const controlInputsPod = `apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: evil.example.com/app:1.0
`

// controlInputsCase writes a rule that reads control inputs, with one case
// whose input is controlInputsPod and whose data.json is data, or which has no
// data.json when data is empty.
func controlInputsCase(t *testing.T, data string) (RuleUnderTest, Case) {
	t.Helper()
	ruleDir := filepath.Join(t.TempDir(), "control-inputs")
	caseDir := filepath.Join(ruleDir, "test", "pod")
	require.NoError(t, os.MkdirAll(filepath.Join(caseDir, "input"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(ruleDir, ruledir.MetadataFileName), []byte(controlInputsRuleMetadata), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(ruleDir, ruledir.RegoFileName), []byte(controlInputsRuleRego), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(caseDir, "input", "pod.yaml"), []byte(controlInputsPod), 0o600))
	if data != "" {
		require.NoError(t, os.WriteFile(filepath.Join(caseDir, dataFileName), []byte(data), 0o600))
	}

	rules, err := DiscoverPath(ruleDir)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	return rules[0], caseByName(t, rules[0], "pod")
}

// TestLoadCaseData verifies that data.json is optional and that a broken one
// is reported by name instead of being evaluated as no inputs.
func TestLoadCaseData(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		data, err := LoadCaseData(t.TempDir())
		require.NoError(t, err)
		assert.Equal(t, cautils.RegoInputData{}, data)
	})

	t.Run("posture and data inputs", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, dataFileName), []byte(`{
			"postureControlInputs": {"untrustedRegistries": ["evil.example.com/"]},
			"dataControlInputs": {"cloudProvider": "eks"}
		}`), 0o600))
		data, err := LoadCaseData(dir)
		require.NoError(t, err)
		assert.Equal(t, cautils.RegoInputData{
			PostureControlInputs: map[string][]string{"untrustedRegistries": {"evil.example.com/"}},
			DataControlInputs:    map[string]string{"cloudProvider": "eks"},
		}, data)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, dataFileName), []byte(`{"postureControlInputs":`), 0o600))
		_, err := LoadCaseData(dir)
		require.Error(t, err)
		assert.ErrorContains(t, err, dataFileName)
	})
}

// TestEvaluateCaseControlInputs verifies that a case's data.json reaches the
// rule the way a scan's control inputs do.
func TestEvaluateCaseControlInputs(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		messages []string
	}{
		{
			name: "no data.json",
		},
		{
			name: "posture input",
			data: `{"postureControlInputs": {"untrustedRegistries": ["evil.example.com/"]}}`,
			messages: []string{
				"container app uses untrusted registry evil.example.com/",
			},
		},
		{
			name: "posture input the rule does not declare",
			data: `{"postureControlInputs": {"publicRegistries": ["evil.example.com/"]}}`,
		},
		{
			name: "cloud provider",
			data: `{"dataControlInputs": {"cloudProvider": "eks"}}`,
			messages: []string{
				"Pod app runs on EKS",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, c := controlInputsCase(t, tt.data)
			responses, err := EvaluateCase(context.Background(), rule, c)
			require.NoError(t, err)
			var messages []string
			for _, r := range responses {
				messages = append(messages, r.AlertMessage)
			}
			assert.Equal(t, tt.messages, messages)
		})
	}

	t.Run("invalid data.json", func(t *testing.T) {
		rule, c := controlInputsCase(t, `{"postureControlInputs":`)
		_, err := EvaluateCase(context.Background(), rule, c)
		require.Error(t, err)
		assert.ErrorContains(t, err, dataFileName)
	})
}
