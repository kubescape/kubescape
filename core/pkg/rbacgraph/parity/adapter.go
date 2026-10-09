package parity

import (
	"errors"
	"fmt"
	"slices"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
)

// Kubescape answers a fixture's questions with rbacgraph.
type Kubescape struct {
	idx *rbacgraph.Index
}

// NewKubescape indexes the fixture's objects the way the
// analyze_rbac_escalation_paths tool indexes a cluster's.
func NewKubescape(f Fixture) (*Kubescape, error) {
	resources := map[string]workloadinterface.IMetadata{}
	for _, obj := range f.Objects {
		w := workloadinterface.NewWorkloadObj(obj)
		resources[w.GetID()] = w
	}
	roles, clusterRoles, roleBindings, clusterRoleBindings, serviceAccounts, errs := rbacgraph.FromResources(resources)
	if len(errs) > 0 {
		return nil, fmt.Errorf("fixture %q: %w", f.Name, errors.Join(errs...))
	}
	return &Kubescape{idx: rbacgraph.NewIndex(roles, clusterRoles, roleBindings, clusterRoleBindings, serviceAccounts)}, nil
}

// Answer reports whether rbacgraph finds the one-hop escalation edge that
// corresponds to q. It reads the subject's direct edges rather than the
// transitive closure: a Question is a single request to the API server, and
// a multi-hop verdict has no single request to compare with.
//
// An edge is an escalation, which is narrower than an authorization: rbacgraph
// drops an edge that leads back to the subject, so a ServiceAccount minting a
// token for itself is a request Kubernetes allows and no edge describes.
// Fixture validation refuses that question rather than let it be answered
// "denied" here.
func (k *Kubescape) Answer(q Question) Answer {
	subject := rbacgraph.Subject{Kind: rbacgraph.KindServiceAccount, Namespace: q.ServiceAccount.Namespace, Name: q.ServiceAccount.Name}
	rules := k.idx.DirectRules(subject)
	if q.RewriteRole != nil {
		// rbacgraph asks whether a Role can be rewritten at all, so one
		// escalate-verb edge stands for update and patch alike. The question
		// is one request, made with one of them. rbacgraph is therefore asked
		// about the subject as it would be without the other verb, and an
		// edge it still finds rests on the verb the request uses.
		other := "patch"
		if q.RewriteRole.Verb == "patch" {
			other = "update"
		}
		rules = withoutVerb(rules, other)
	}
	for _, edge := range k.idx.DirectEscalationEdges(subject, rules) {
		if answers(edge, q) {
			return Allowed
		}
	}
	return Denied
}

func answers(edge rbacgraph.EscalationEdge, q Question) bool {
	switch {
	case q.MintToken != nil:
		want := rbacgraph.Subject{Kind: rbacgraph.KindServiceAccount, Namespace: q.MintToken.Namespace, Name: q.MintToken.Name}
		return edge.Primitive == rbacgraph.PrimitiveMintServiceAccountToken && edge.ToSubject != nil && *edge.ToSubject == want
	case q.RewriteRole != nil:
		return edge.Primitive == rbacgraph.PrimitiveEscalateVerb && edge.Target != nil &&
			edge.Target.Covers("Role", q.RewriteRole.Namespace, q.RewriteRole.Name)
	case q.BindClusterRole != nil:
		return edge.Primitive == rbacgraph.PrimitiveBindVerb && edge.Target != nil &&
			edge.Target.Covers("ClusterRole", "", q.BindClusterRole.Name) &&
			edge.Scope == q.BindClusterRole.Namespace
	}
	return false
}

// withoutVerb returns rules with verb taken out of every rule that lists it.
// A rule granting "*" is left as it is: it grants every verb, so whatever it
// allows with verb it allows with any other too. The rules are copied, since
// they share their slices with the Index.
func withoutVerb(rules []rbacgraph.ScopedRule, verb string) []rbacgraph.ScopedRule {
	out := slices.Clone(rules)
	for i := range out {
		out[i].Rule.Verbs = slices.DeleteFunc(slices.Clone(out[i].Rule.Verbs), func(v string) bool { return v == verb })
	}
	return out
}
