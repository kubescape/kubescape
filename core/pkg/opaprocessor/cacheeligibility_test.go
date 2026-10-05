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
			name: "status reached through a single object.get key",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tobject.get(node, \"status\", {}) != {}\n}",
			want: false,
		},
		{
			name: "status reached through an aliased object.get key",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tkey := \"status\"\n\tobject.get(node, key, {}) != {}\n}",
			want: false,
		},
		{
			name: "status reached by standalone object.get call",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tobject.get(node, \"status\", {}, true)\n}",
			want: false,
		},
		{
			name: "status as object.get default is not a read",
			rego: "deny contains msga if {\n\tnode := input[_]\n\tobject.get(node, \"spec\", \"status\") != {}\n}",
			want: true,
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

func TestRuleCacheEligibleCorrelatedInputRule(t *testing.T) {
	tests := []struct {
		name string
		rego string
		want bool
	}{
		{
			name: "one iteration per body stays cacheable",
			rego: "deny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n}",
			want: true,
		},
		{
			name: "separate bodies each iterating once stay cacheable",
			rego: "deny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n}\n\ndeny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostIPC == true\n}",
			want: true,
		},
		{
			name: "helper function on the bound element stays cacheable",
			rego: "deny contains msga if {\n\tpod := input[_]\n\tshares_host(pod)\n}\n\nshares_host(pod) if pod.spec.hostPID == true",
			want: true,
		},
		{
			name: "two iterations in one body pair objects",
			rego: "deny contains msga if {\n\ta := input[_]\n\tb := input[_]\n\ta.metadata.name != b.metadata.name\n\ta.spec.nodeName == b.spec.nodeName\n}",
			want: false,
		},
		{
			name: "comprehension over input, as in etcd-unique-ca",
			rego: "deny contains msga if {\n\tetcd := [p | p := input[_]; p.metadata.name == \"etcd\"]\n\tcount(etcd) > 0\n}",
			want: false,
		},
		{
			name: "some x in input binds one element and stays cacheable",
			rego: "deny contains msga if {\n\tsome pod in input\n\tpod.spec.hostPID == true\n}",
			want: true,
		},
		{
			name: "some i, x in input exposes the element's position",
			rego: "deny contains msga if {\n\tsome i, pod in input\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "some i, x in input with the index constrained",
			rego: "deny contains msga if {\n\tsome i, pod in input\n\ti == 1\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "some _, x in input is not cleared either",
			rego: "deny contains msga if {\n\tsome _, pod in input\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "named index into input",
			rego: "deny contains msga if {\n\tpod := input[i]\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "index bound to a constant",
			rego: "deny contains msga if {\n\ti := 1\n\tpod := input[i]\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "declared index compared after the lookup",
			rego: "deny contains msga if {\n\tsome i\n\tpod := input[i]\n\ti > 0\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "arithmetic on the index",
			rego: "deny contains msga if {\n\tpod := input[i]\n\tnext := input[i + 1]\n\tpod.spec.nodeName == next.spec.nodeName\n}",
			want: false,
		},
		{
			name: "index reported in the verdict",
			rego: "deny contains msga if {\n\tpod := input[i]\n\tpod.spec.hostPID == true\n\tmsga := {\"alertMessage\": sprintf(\"pod %d\", [i])}\n}",
			want: false,
		},
		{
			name: "computed index into input",
			rego: "deny contains msga if {\n\tpod := input[count(input) - 1]\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "index observed inside a comprehension",
			rego: "deny contains msga if {\n\tpod := input[i]\n\tcount([j | j := i; j > 0]) > 0\n}",
			want: false,
		},
		{
			name: "input imported under an alias",
			rego: "import input as pods\n\ndeny contains msga if {\n\tpod := pods[_]\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "aliased input compared across objects",
			rego: "import input as pods\n\ndeny contains msga if {\n\tetcd := [p | p := pods[_]; p.metadata.name == \"etcd\"]\n\tcount(etcd) > 0\n}",
			want: false,
		},
		{
			name: "input imported under its own name",
			rego: "import input\n\ndeny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "part of input imported",
			rego: "import input.items\n\ndeny contains msga if {\n\tpod := items[_]\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "part of input imported under an alias",
			rego: "import input.items as pods\n\ndeny contains msga if {\n\tpod := pods[_]\n\tpod.spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "imports outside input leave the rule cacheable",
			rego: "import data.settings as settings\nimport future.keywords.in\n\ndeny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == settings.hostPID\n}",
			want: true,
		},
		{
			name: "some x in input next to a second iteration pairs objects",
			rego: "deny contains msga if {\n\tsome a in input\n\tb := input[_]\n\ta.spec.nodeName == b.spec.nodeName\n}",
			want: false,
		},
		{
			name: "membership test reads input as a whole",
			rego: "deny contains msga if {\n\tpod := input[_]\n\tpod.metadata.ownerReferences[0] in input\n}",
			want: false,
		},
		{
			name: "every block over input",
			rego: "deny contains msga if {\n\tevery pod in input {\n\t\tpod.spec.hostPID == false\n\t}\n}",
			want: false,
		},
		{
			name: "fixed position in input",
			rego: "deny contains msga if {\n\tinput[0].spec.hostPID == true\n}",
			want: false,
		},
		{
			name: "input counted as a whole",
			rego: "deny contains msga if {\n\tcount(input) > 1\n}",
			want: false,
		},
		{
			name: "function reading input",
			rego: "deny contains msga if {\n\tpod := input[_]\n\tshares_node(pod)\n}\n\nshares_node(pod) if {\n\tother := input[_]\n\tother.spec.nodeName == pod.spec.nodeName\n}",
			want: false,
		},
		{
			name: "helper rule iterating input",
			rego: "deny contains msga if {\n\tpod := input[_]\n\tpod.spec.hostPID == true\n\thas_daemonset\n}\n\nhas_daemonset if {\n\tinput[_].kind == \"DaemonSet\"\n}",
			want: false,
		},
		{
			name: "helper rule gathering input",
			rego: "pods := [p | p := input[_]]\n\ndeny contains msga if {\n\tpod := input[_]\n\tcount(pods) > 1\n}",
			want: false,
		},
		{
			name: "unparseable rego is treated as correlating",
			rego: "deny contains msga if { this is not rego ((",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := cacheEligibilityRule("rule", tt.rego, "pods")
			control := &reporthandling.Control{ControlID: "C-0003", Rules: []reporthandling.PolicyRule{rule}}

			assert.Equal(t, tt.want, ruleCacheEligible(control, &control.Rules[0]))
			assert.Equal(t, tt.want, controlCacheEligible(control))
		})
	}
}
