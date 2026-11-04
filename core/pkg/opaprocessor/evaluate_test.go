package opaprocessor

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/opa-utils/objectsenvelopes"
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

// anonymousRequestsToKubeletRule is the pinned regolibrary v2.0.38 rule for
// C-0069 (rules/anonymous-requests-to-kubelet-updated/raw.rego).
const anonymousRequestsToKubeletRule = `package armo_builtins

import rego.v1

deny contains msga if {
	obj := input[_]
	is_kubelet_info(obj)
	command := obj.data.cmdLine

	contains(command, "--anonymous-auth")
	contains(command, "--anonymous-auth=true")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Anonymous requests is enabled.",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

deny contains msga if {
	obj := input[_]
	is_kubelet_info(obj)
	command := obj.data.cmdLine

	not contains(command, "--anonymous-auth")
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.authentication.anonymous.enabled == true

	msga := {
		"alertMessage": "Anonymous requests is enabled.",
		"alertScore": 7,
		"reviewPaths": ["authentication.anonymous.enabled"],
		"failedPaths": ["authentication.anonymous.enabled"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"metadata": obj.metadata,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}

deny contains msga if {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--anonymous-auth")
	contains(command, "--config")

	not obj.data.configFile.content

	msga := {
		"alertMessage": "Failed to analyze config file",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"data": obj.data,
		}},
	}
}

is_kubelet_info(obj) if {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
`

// TestEvaluateRule_KubeletYAMLBooleanCompatibility verifies that host-scan rules
// using yaml.unmarshal preserve Kubernetes YAML 1.1 boolean semantics (yes/no/on/off)
// alongside canonical true/false when evaluating KubeletConfiguration files.
func TestEvaluateRule_KubeletYAMLBooleanCompatibility(t *testing.T) {
	rule := &reporthandling.PolicyRule{
		PortalBase: armotypes.PortalBase{
			Name: "anonymous-requests-to-kubelet-updated",
		},
		Rule:         anonymousRequestsToKubeletRule,
		RuleLanguage: reporthandling.RegoLanguage,
		DynamicMatch: []reporthandling.RuleMatchObjects{
			{
				APIGroups:   []string{"hostdata.kubescape.cloud"},
				APIVersions: []string{"v1beta0"},
				Resources:   []string{"KubeletInfo"},
			},
		},
	}

	testCases := []struct {
		scalar       string
		wantFindings int
	}{
		{scalar: "true", wantFindings: 1},
		{scalar: "yes", wantFindings: 1},
		{scalar: "on", wantFindings: 1},
		{scalar: "false", wantFindings: 0},
		{scalar: "no", wantFindings: 0},
		{scalar: "off", wantFindings: 0},
	}

	for _, tc := range testCases {
		t.Run(tc.scalar, func(t *testing.T) {
			configYAML := fmt.Sprintf("authentication:\n  anonymous:\n    enabled: %s\n", tc.scalar)
			kubeletInfo := objectsenvelopes.NewObject(map[string]any{
				"apiVersion": "hostdata.kubescape.cloud/v1beta0",
				"kind":       "KubeletInfo",
				"metadata": map[string]any{
					"name": "node-1",
				},
				"data": map[string]any{
					"cmdLine": "kubelet --config=/var/lib/kubelet/config.yaml",
					"configFile": map[string]any{
						"content": base64.StdEncoding.EncodeToString([]byte(configYAML)),
					},
				},
			})
			require.NotNil(t, kubeletInfo)

			sessionObj := cautils.NewOPASessionObjMock()
			proc := NewOPAProcessor(sessionObj, &resources.RegoDependenciesData{}, "", "", "", false, nil)

			responses, err := proc.EvaluateRule(context.Background(), rule, []workloadinterface.IMetadata{kubeletInfo}, "C-0069")
			require.NoError(t, err)
			assert.Len(t, responses, tc.wantFindings)
		})
	}
}
