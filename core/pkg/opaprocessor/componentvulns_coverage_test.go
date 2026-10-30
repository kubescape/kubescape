package opaprocessor

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/clustercomponents"
	"github.com/kubescape/kubescape/v4/core/pkg/componentvulns"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type containerdMatcher struct{}

func (containerdMatcher) MatchPackages(packages []pkg.Package, _ pkg.Context, _, _ []string) (match.Matches, []match.IgnoredMatch, error) {
	matches := match.NewMatches()
	for _, p := range packages {
		if p.Version != "v1.7.11" {
			continue
		}
		matches.Add(match.Match{Package: p, Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2024-40635"},
			Fix:       vulnerability.Fix{Versions: []string{"1.7.27"}, State: vulnerability.FixStateFixed},
			Metadata:  &vulnerability.Metadata{ID: "CVE-2024-40635", Severity: "Medium"},
		}})
	}
	return matches, nil, nil
}

// A runtime control selected on its own, over one vulnerable node, one clean
// node and one node whose runtime cannot be assessed: the vulnerable node
// fails, and the clean node's pass is marked incomplete because of the gap.
func TestComponentVulnerabilitiesMixedNodes(t *testing.T) {
	runtime := func(v string) *clustercomponents.ComponentVersion {
		return &clustercomponents.ComponentVersion{Component: clustercomponents.Containerd, Version: v, RawVersion: "containerd://" + v, Assessment: clustercomponents.Verified}
	}
	inv := clustercomponents.Inventory{
		Nodes: []clustercomponents.Node{
			{Name: "vulnerable", OperatingSystem: "linux", Runtime: runtime("1.7.11")},
			{Name: "patched", OperatingSystem: "linux", Runtime: runtime("1.7.27")},
			{Name: "unknown", OperatingSystem: "linux"},
		},
		Gaps: []clustercomponents.Gap{{Component: clustercomponents.ContainerRuntime, Node: "unknown", Reason: `unsupported container runtime "docker"`}},
	}
	built, err := componentvulns.Build(inv, containerdMatcher{}, componentvulns.Options{Kinds: []componentvulns.Kind{componentvulns.ContainerRuntimeVulnerabilities}})
	require.NoError(t, err)
	require.Len(t, built.Resources, 2)

	gvr := componentvulns.APIVersion + "/" + string(componentvulns.ContainerRuntimeVulnerabilities)
	all := map[string]any{}
	var ids []string
	partials := []cautils.PartialGVRPull{}
	for _, r := range built.Resources {
		all[r.GetID()] = r.GetObject()
		ids = append(ids, r.GetID())
	}
	for _, g := range built.Gaps {
		partials = append(partials, cautils.PartialGVRPull{GVR: gvr, Selector: g.Selector, Error: g.Reason})
	}
	resourcesJSON, err := json.Marshal(all)
	require.NoError(t, err)
	sessionJSON, err := json.Marshal(map[string]any{
		"ResourceToControlsMap": map[string][]string{gvr: {"C-RUNTIME"}},
		"PartialGVRFailures":    partials,
		"ExternalResources":     map[string][]string{gvr: ids},
	})
	require.NoError(t, err)

	rule := reporthandling.PolicyRule{
		PortalBase: armotypes.PortalBase{Name: "container-runtime-vulnerable"},
		Rule: `package armo_builtins
import rego.v1
deny contains msga if {
	r := input[_]
	r.kind == "ContainerRuntimeVulnerabilities"
	count(r.data.vulnerabilities) > 0
	msga := {
		"alertMessage": sprintf("%s %s has known vulnerabilities", [r.data.component, r.data.version]),
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"externalObjects": r},
	}
}`,
		DynamicMatch: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{componentvulns.Group},
			APIVersions: []string{componentvulns.Version},
			Resources:   []string{string(componentvulns.ContainerRuntimeVulnerabilities)},
		}},
		RuleLanguage: reporthandling.RegoLanguage,
	}
	opap := NewOPAProcessorMock(string(sessionJSON), resourcesJSON)
	opap.Report = &reporthandlingv2.PostureReport{}
	control := &reporthandling.Control{ControlID: "C-RUNTIME", Rules: []reporthandling.PolicyRule{rule}}

	scopes := opap.evaluationScopes()
	require.NotEmpty(t, scopes)
	got, err := opap.processRule(context.Background(), &rule, nil, scopes[0], control)
	require.NoError(t, err)

	byNode := map[string]apis.ScanningStatus{}
	subStatus := map[string]apis.ScanningSubStatus{}
	for id, r := range got {
		name := opap.AllResources[id].GetName()
		byNode[name] = r.Status
		subStatus[name] = r.SubStatus
	}
	assert.Equal(t, apis.StatusFailed, byNode["vulnerable"])
	assert.Equal(t, apis.StatusPassed, byNode["patched"])
	assert.Equal(t, apis.SubStatusIncompleteCoverage, subStatus["patched"])
	assert.NotContains(t, byNode, "unknown")
}
