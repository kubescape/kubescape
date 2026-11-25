package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/require"
)

// denyNamespaceObjectsRule fails every object it is given, so an object's presence or
// absence in the result map is purely a question of whether the namespace
// selectors scoped it in.
const denyNamespaceObjectsRule = `package armo_builtins
import rego.v1

deny contains msga if {
	obj := input[_]
	msga := {
		"alertMessage": sprintf("%v denied", [obj.metadata.name]),
		"packagename":  "armo_builtins",
		"alertScore":   5,
		"fixPaths":     [],
		"failedPaths":  [],
		"alertObject":  {"k8sApiObjects": [obj]},
	}
}
`

// namespaceObjectSession builds a session with two Namespace objects, one
// Pod in each of them and one ClusterRole, all matched by a single rule.
func namespaceObjectSession(t *testing.T) (sess *cautils.OPASessionObj, ids map[string]string) {
	t.Helper()
	objects := map[string]workloadinterface.IMetadata{
		"ns-prod": workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1", "kind": "Namespace",
			"metadata": map[string]any{"name": "prod"},
		}),
		"ns-dev": workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1", "kind": "Namespace",
			"metadata": map[string]any{"name": "dev"},
		}),
		"pod-prod": workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": "p-prod", "namespace": "prod"},
		}),
		"pod-dev": workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": "p-dev", "namespace": "dev"},
		}),
		"clusterrole": workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
			"metadata": map[string]any{"name": "reader"},
		}),
	}

	sess = cautils.NewOPASessionObjMock()
	ids = make(map[string]string, len(objects))
	for key, obj := range objects {
		ids[key] = obj.GetID()
		sess.AllResources[obj.GetID()] = obj
	}
	sess.K8SResources = cautils.K8SResources{
		"/v1/namespaces": {ids["ns-prod"], ids["ns-dev"]},
		"/v1/pods":       {ids["pod-prod"], ids["pod-dev"]},
		"rbac.authorization.k8s.io/v1/clusterroles": {ids["clusterrole"]},
	}

	rule := reporthandling.PolicyRule{
		Rule:         denyNamespaceObjectsRule,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Namespace", "Pod"}},
			{APIGroups: []string{"rbac.authorization.k8s.io"}, APIVersions: []string{"v1"}, Resources: []string{"ClusterRole"}},
		},
	}
	rule.Name = "deny-every-input"
	ctrl := &reporthandling.Control{ControlID: "C-NSOBJECT", Rules: []reporthandling.PolicyRule{rule}}
	ctrl.Name = "deny every input"
	sess.AllPolicies = cautils.NewPolicies()
	sess.AllPolicies.Controls[ctrl.ControlID] = *ctrl

	return sess, ids
}

// TestNamespaceSelectorsApplyToNamespaceObjects checks that --include-namespaces
// and --exclude-namespaces decide about a Namespace object by its name, the way
// the cluster collector does with a metadata.name field selector, instead of
// leaving every Namespace object in the report because its metadata has no
// namespace.
func TestNamespaceSelectorsApplyToNamespaceObjects(t *testing.T) {
	tests := []struct {
		name    string
		exclude string
		include string
		want    []string
	}{
		{
			name: "no selector keeps everything",
			want: []string{"ns-prod", "ns-dev", "pod-prod", "pod-dev", "clusterrole"},
		},
		{
			name:    "include keeps the named Namespace and what lives in it",
			include: "prod",
			want:    []string{"ns-prod", "pod-prod", "clusterrole"},
		},
		{
			name:    "exclude drops the named Namespace and what lives in it",
			exclude: "dev",
			want:    []string{"ns-prod", "pod-prod", "clusterrole"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, ids := namespaceObjectSession(t)
			opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", tt.exclude, tt.include, false, nil)

			got, err := opap.processControl(context.Background(), nsObjectControl(sess), evaluationScope{})
			require.NoError(t, err)

			want := make(map[string]struct{}, len(tt.want))
			for _, key := range tt.want {
				want[ids[key]] = struct{}{}
			}
			for key, id := range ids {
				_, inResult := got[id]
				_, expected := want[id]
				require.Equal(t, expected, inResult, "%s: reported=%v, want reported=%v", key, inResult, expected)
			}
		})
	}
}

func nsObjectControl(sess *cautils.OPASessionObj) *reporthandling.Control {
	ctrl := sess.AllPolicies.Controls["C-NSOBJECT"]
	return &ctrl
}
