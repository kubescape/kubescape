package resourcehandler

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func TestRecordDiscoveryFailureDependencies_GroupSpecificAndWildcardMatches(t *testing.T) {
	framework := reporthandling.Framework{Controls: []reporthandling.Control{
		discoveryDependencyControl("C-EXACT", "example.com", "v1", "Widget"),
		discoveryDependencyControl("C-WILDCARD-GROUP", "*", "v1", "Widget"),
		discoveryDependencyControl("C-WILDCARD-VERSION", "example.com", "*", "Widget"),
		discoveryDependencyControl("C-WILDCARD-WITH-SUCCESS", "*", "v1", "Gadget"),
		discoveryDependencyControl("C-RESOLVED-IN-FAILED-GV", "example.com", "v1", "KnownWidget"),
		discoveryDependencyControl("C-UNRELATED", "other.com", "v1", "Widget"),
	}}
	resolver := func(group, version, resource string) []resolvedResource {
		switch resource {
		case "Gadget":
			return []resolvedResource{{groupVersionResourceTriplet: "other.com/v1/gadgets"}}
		case "KnownWidget":
			return []resolvedResource{{groupVersionResourceTriplet: "example.com/v1/knownwidgets"}}
		default:
			return nil
		}
	}
	resourceToControls := map[string][]string{
		"other.com/v1/gadgets":        {"C-WILDCARD-WITH-SUCCESS"},
		"example.com/v1/knownwidgets": {"C-RESOLVED-IN-FAILED-GV"},
	}

	recordDiscoveryFailureDependencies(
		[]reporthandling.Framework{framework}, nil, reporthandling.ScopeCluster, resolver,
		[]cautils.PartialGVRPull{{GVR: "discovery:example.com/v1", Selector: "discovery", Error: "forbidden"}},
		resourceToControls, make(map[string]struct{}),
	)

	assert.ElementsMatch(t, []string{
		"C-EXACT",
		"C-WILDCARD-GROUP",
		"C-WILDCARD-VERSION",
		"C-WILDCARD-WITH-SUCCESS",
	}, resourceToControls["discovery:example.com/v1"])
	assert.NotContains(t, resourceToControls["discovery:example.com/v1"], "C-RESOLVED-IN-FAILED-GV")
	assert.NotContains(t, resourceToControls["discovery:example.com/v1"], "C-UNRELATED")
}

func TestRecordDiscoveryFailureDependencies_DoesNotGuessUntypedDiscoveryFailure(t *testing.T) {
	framework := reporthandling.Framework{Controls: []reporthandling.Control{
		discoveryDependencyControl("C-WIDGET", "example.com", "v1", "Widget"),
	}}
	resourceToControls := make(map[string][]string)

	recordDiscoveryFailureDependencies(
		[]reporthandling.Framework{framework}, nil, reporthandling.ScopeCluster,
		func(string, string, string) []resolvedResource { return nil },
		[]cautils.PartialGVRPull{{GVR: "discovery:*", Selector: "discovery", Error: "discovery unavailable"}},
		resourceToControls, make(map[string]struct{}),
	)

	assert.Empty(t, resourceToControls)
}

func TestRecordDiscoveryFailureDependencies_PreservesBuiltInFallback(t *testing.T) {
	framework := reporthandling.Framework{Controls: []reporthandling.Control{
		discoveryDependencyControl("C-POD", "core", "v1", "Pod"),
	}}
	resourceToControls := map[string][]string{"core/v1/pods": {"C-POD"}}

	recordDiscoveryFailureDependencies(
		[]reporthandling.Framework{framework}, nil, reporthandling.ScopeCluster,
		func(string, string, string) []resolvedResource {
			return []resolvedResource{{groupVersionResourceTriplet: "core/v1/pods"}}
		},
		[]cautils.PartialGVRPull{{GVR: "discovery:v1", Selector: "discovery", Error: "forbidden"}},
		resourceToControls, make(map[string]struct{}),
	)

	assert.NotContains(t, resourceToControls, "discovery:v1")
}

func discoveryDependencyControl(controlID, group, version, resource string) reporthandling.Control {
	rule := reporthandling.PolicyRule{
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{group},
			APIVersions: []string{version},
			Resources:   []string{resource},
		}},
	}
	rule.Name = controlID + "-rule"
	return reporthandling.Control{
		ControlID: controlID,
		Rules:     []reporthandling.PolicyRule{rule},
	}
}
