package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentRuntimeFrameworkFileScanProducesFindings(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "agent-runtime.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(`apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: unsafe-sandbox
  namespace: agents
spec:
  podTemplate:
    spec:
      runtimeClassName: runc
---
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: isolated-sandbox
  namespace: agents
spec:
  podTemplate:
    spec:
      runtimeClassName: gvisor
---
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxTemplate
metadata:
  name: unmanaged-template
  namespace: agents
spec:
  networkPolicyManagement: Unmanaged
---
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxTemplate
metadata:
  name: managed-template
  namespace: agents
spec:
  networkPolicyManagement: Managed
---
apiVersion: ate.dev/v1alpha1
kind: WorkerPool
metadata:
  name: unbounded-pool
  namespace: agents
spec:
  replicas: 1
  workerImage: example.test/worker:latest
  template:
    resources:
      limits:
        cpu: "4"
---
apiVersion: ate.dev/v1alpha1
kind: WorkerPool
metadata:
  name: bounded-pool
  namespace: agents
spec:
  replicas: 1
  workerImage: example.test/worker:latest
  template:
    resources:
      limits:
        cpu: "1"
`), 0o600))

	controls := []reporthandling.Control{
		agentRuntimeIntegrationControl("C-0297", "Agent Sandbox hardened runtime class", "agent-sandbox-hardened-runtime-class", reporthandling.RuleMatchObjects{
			APIGroups: []string{"agents.x-k8s.io"}, APIVersions: []string{"v1beta1"}, Resources: []string{"Sandbox"},
		}, `podSpec := object.get(object.get(resource.spec, "podTemplate", {}), "spec", {})
	object.get(podSpec, "runtimeClassName", "") != "gvisor"`, "spec.podTemplate.spec.runtimeClassName"),
		agentRuntimeIntegrationControl("C-0314", "Agent Sandbox managed network policy", "agent-sandbox-managed-networking", reporthandling.RuleMatchObjects{
			APIGroups: []string{"extensions.agents.x-k8s.io"}, APIVersions: []string{"v1beta1"}, Resources: []string{"SandboxTemplate"},
		}, `object.get(resource.spec, "networkPolicyManagement", "Managed") != "Managed"`, "spec.networkPolicyManagement"),
		agentRuntimeIntegrationControl("C-0317", "Agent Substrate Worker Pod resource ceilings", "worker-pod-resource-ceilings", reporthandling.RuleMatchObjects{
			APIGroups: []string{"ate.dev"}, APIVersions: []string{"v1alpha1"}, Resources: []string{"WorkerPool"},
		}, `limits := object.get(object.get(object.get(resource.spec, "template", {}), "resources", {}), "limits", {})
	object.get(limits, "cpu", "") == "4"`, "spec.template.resources.limits.cpu"),
	}
	framework := reporthandling.Framework{Controls: controls}
	framework.Name = "AgentRuntimeHardening"

	frameworkPath := filepath.Join(dir, "framework.json")
	frameworkBytes, err := json.Marshal(framework)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(frameworkPath, frameworkBytes, 0o600))

	controlsInputsPath := writeAgentRuntimeScanFile(t, dir, "controls-inputs.json", `{}`)
	exceptionsPath := writeAgentRuntimeScanFile(t, dir, "exceptions.json", `[]`)
	attackTracksPath := writeAgentRuntimeScanFile(t, dir, "attack-tracks.json", `[]`)
	for _, test := range []struct {
		name             string
		omitRawResources bool
	}{
		{name: "include raw resources", omitRawResources: false},
		{name: "omit raw resources", omitRawResources: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				UseFrom:          []string{frameworkPath},
				ControlsInputs:   controlsInputsPath,
				UseExceptions:    exceptionsPath,
				AttackTracks:     attackTracksPath,
				InputPatterns:    []string{manifestPath},
				Local:            true,
				FrameworkScan:    true,
				ScanType:         cautils.ScanTypeFramework,
				OmitRawResources: test.omitRawResources,
			}
			scanInfo.Submit.SetBool(false)

			results, err := NewKubescape(context.Background()).Scan(scanInfo, []cautils.PolicyIdentifier{{
				Identifier: framework.Name,
				Kind:       apisv1.KindFramework,
			}})

			require.NoError(t, err)
			require.NotNil(t, results)
			require.NotNil(t, results.GetData())
			data := results.GetData()
			require.Len(t, data.ResourcesResult, 6)

			for _, control := range controls {
				summary, ok := data.Report.SummaryDetails.Controls[control.ControlID]
				require.Truef(t, ok, "missing summary for %s", control.ControlID)
				assert.Equal(t, apis.StatusFailed, summary.GetStatus().Status())
				assert.Equal(t, 1, summary.StatusCounters.FailedResources)
				assert.Equal(t, 1, summary.StatusCounters.PassedResources)
			}

			assertAgentRuntimeResourceResults(t, data.ResourcesResult)
			assertAgentRuntimeSerializedResources(t, data, test.omitRawResources)
		})
	}
}

type agentRuntimeExpectedResult struct {
	controlID  string
	status     apis.ScanningStatus
	failedPath string
}

func assertAgentRuntimeResourceResults(t *testing.T, resources map[string]resourcesresults.Result) {
	t.Helper()
	expected := map[string]agentRuntimeExpectedResult{
		"path=2781081350/api=agents.x-k8s.io/v1beta1/agents/Sandbox/unsafe-sandbox":                        {"C-0297", apis.StatusFailed, "spec.podTemplate.spec.runtimeClassName"},
		"path=2797858969/api=agents.x-k8s.io/v1beta1/agents/Sandbox/isolated-sandbox":                      {"C-0297", apis.StatusPassed, ""},
		"path=2747526112/api=extensions.agents.x-k8s.io/v1beta1/agents/SandboxTemplate/unmanaged-template": {"C-0314", apis.StatusFailed, "spec.networkPolicyManagement"},
		"path=2764303731/api=extensions.agents.x-k8s.io/v1beta1/agents/SandboxTemplate/managed-template":   {"C-0314", apis.StatusPassed, ""},
		"path=2848191826/api=ate.dev/v1alpha1/agents/WorkerPool/unbounded-pool":                            {"C-0317", apis.StatusFailed, "spec.template.resources.limits.cpu"},
		"path=2864969445/api=ate.dev/v1alpha1/agents/WorkerPool/bounded-pool":                              {"C-0317", apis.StatusPassed, ""},
	}
	require.Equal(t, len(expected), len(resources))
	for resourceID, want := range expected {
		resource, ok := resources[resourceID]
		require.Truef(t, ok, "missing resource result %q", resourceID)
		assert.Equal(t, resourceID, resource.ResourceID)
		require.Len(t, resource.AssociatedControls, 1)
		associatedControl := resource.AssociatedControls[0]
		assert.Equal(t, want.controlID, associatedControl.ControlID)
		assert.Equal(t, want.status, associatedControl.Status.Status())
		if want.status == apis.StatusFailed {
			require.Len(t, associatedControl.ResourceAssociatedRules, 1)
			require.Len(t, associatedControl.ResourceAssociatedRules[0].Paths, 1)
			assert.Equal(t, want.failedPath, associatedControl.ResourceAssociatedRules[0].Paths[0].ReviewPath)
		}
	}
}

func assertAgentRuntimeSerializedResources(t *testing.T, data *cautils.OPASessionObj, omitRawResources bool) {
	t.Helper()
	serialized, err := json.Marshal(printerv2.FinalizeResults(data))
	require.NoError(t, err)

	var report map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(serialized, &report))
	if omitRawResources {
		assert.NotContains(t, report, "resources")
		return
	}

	require.Contains(t, report, "resources")
	var resources []json.RawMessage
	require.NoError(t, json.Unmarshal(report["resources"], &resources))
	assert.Len(t, resources, 6)
}

func agentRuntimeIntegrationControl(controlID, controlName, ruleName string, match reporthandling.RuleMatchObjects, condition, failedPath string) reporthandling.Control {
	rule := reporthandling.PolicyRule{
		RuleLanguage: reporthandling.RegoLanguage,
		Match:        []reporthandling.RuleMatchObjects{match},
		Rule: `package armo_builtins

import rego.v1

deny contains message if {
	resource := input[_]
	` + condition + `
	message := {
		"alertMessage": "agent runtime posture check failed",
		"packagename": "armo_builtins",
		"failedPaths": ["` + failedPath + `"],
		"reviewPaths": ["` + failedPath + `"],
		"fixPaths": [],
		"alertScore": 7,
		"alertObject": {"k8sApiObjects": [resource]}
	}
}
`,
	}
	rule.Name = ruleName
	control := reporthandling.Control{ControlID: controlID, BaseScore: 7, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = controlName
	return control
}

func writeAgentRuntimeScanFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}
