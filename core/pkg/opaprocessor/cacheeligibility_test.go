package opaprocessor

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func cacheEligibilityRule(name, rego string, kinds ...string) reporthandling.PolicyRule {
	return reporthandling.PolicyRule{
		PortalBase: armotypes.PortalBase{Name: name, Attributes: map[string]any{}},
		Rule:       "package armo_builtins\nimport rego.v1\n\n" + rego,
		Match:      []reporthandling.RuleMatchObjects{{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: kinds}},
	}
}

func TestRuleCacheEligibleStatusReadingRule(t *testing.T) {
	tests := []struct {
		name string
		rego string
		want bool
	}{
		{
			name: "spec-only rule stays cacheable",
			rego: "deny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n}",
			want: true,
		},
		{
			name: "kubelet version from node status",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tcurrent_version := node.status.nodeInfo.kubeletVersion\n}",
			want: false,
		},
		{
			name: "os image from node status",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tnot startswith(node.status.nodeInfo.osImage, \"Container-Optimized OS\")\n}",
			want: false,
		},
		{
			name: "status reached by string index",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tnode[\"status\"].nodeInfo.osImage == \"x\"\n}",
			want: false,
		},
		{
			name: "status reached through an object.get path",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tobject.get(node, [\"status\", \"nodeInfo\"], {}) != {}\n}",
			want: false,
		},
		{
			name: "whitespace inside the index cannot hide the read",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tnode[ \"status\" ].nodeInfo.osImage == \"x\"\n}",
			want: false,
		},
		{
			name: "whitespace inside an object.get path cannot hide the read",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tobject.get(node, [ \"status\" , \"nodeInfo\" ], {}) != {}\n}",
			want: false,
		},
		{
			name: "dotted status inside a string literal is not a read",
			rego: "deny contains msga if {\n\tinput[_].spec.hostPID == true\n\tmsga := {\"alertMessage\": \"input.status changed\"}\n}",
			want: true,
		},
		{
			name: "status reached through a constant alias",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tkey := \"status\"\n\tnode[key].nodeInfo.osImage == \"x\"\n}",
			want: false,
		},
		{
			name: "status alias inside an object.get path",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tkey := \"status\"\n\tobject.get(node, [key, \"nodeInfo\"], {}) != {}\n}",
			want: false,
		},
		{
			name: "an unrelated alias leaves the rule cacheable",
			rego: "deny contains msga if {\n\tpod := input[_]\n\tkey := \"spec\"\n\tpod[key].hostPID == true\n}",
			want: true,
		},
		{
			name: "unparseable rego is treated as reading status",
			rego: "deny contains msga if { this is not rego ((",
			want: false,
		},
		{
			name: "status only as an alert field name stays cacheable",
			rego: "deny contains msga if {\n\tinput[_].spec.hostPID == true\n\tmsga := {\"alertMessage\": \"status: bad\"}\n}",
			want: true,
		},
		{
			name: "container runtime from node status",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tstartswith(node.status.nodeInfo.containerRuntimeVersion, \"containerd://\")\n}",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := cacheEligibilityRule("rule", tt.rego, "nodes")
			control := &reporthandling.Control{ControlID: "C-0001", Rules: []reporthandling.PolicyRule{rule}}

			assert.Equal(t, tt.want, ruleCacheEligible(control, &control.Rules[0]))
			assert.Equal(t, tt.want, controlCacheEligible(control))
		})
	}
}

func TestControlCacheEligibleOneStatusRuleDisqualifiesTheControl(t *testing.T) {
	control := &reporthandling.Control{
		ControlID: "C-0002",
		Rules: []reporthandling.PolicyRule{
			cacheEligibilityRule("spec-only", "deny if { input[_].spec.hostPID == true }", "pods"),
			cacheEligibilityRule("status-reader", "deny if { input[_].status.nodeInfo.osImage == \"x\" }", "nodes"),
		},
	}

	assert.False(t, controlCacheEligible(control))
}
