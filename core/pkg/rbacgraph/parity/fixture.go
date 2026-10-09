// Package parity compares the RBAC semantics core/pkg/rbacgraph implements
// with the ones Kubernetes itself enforces.
//
// rbacgraph is a hand-written model of the RBAC authorizer and of the
// escalation checks in the RBAC registry. A model like that is only right
// for the cases its author thought of, and a unit test that asserts what the
// author expected Kubernetes to do passes whether or not the expectation is
// true. So the cases here are not written as expectations about rbacgraph.
// Each one is a question with a single recorded answer, Kubernetes' own:
//
//   - The ordinary unit tests (fixtures_test.go) put every question to
//     rbacgraph and require the recorded Kubernetes answer. They need no
//     cluster.
//   - The reference tests (reference_test.go, build tag rbacparity) put the
//     same questions to a real kube-apiserver at the version pinned in
//     reference.env and require the recorded answer to be what the server
//     says. That run is what makes the recorded answers trustworthy.
//
// A fixture has no separate "expected rbacgraph answer". rbacgraph must
// agree with Kubernetes unless the question carries an intentionalDifference
// with a written reason, and a recorded difference that no longer exists
// fails too, so the list cannot go stale.
//
// See README.md for how to run the reference tests and add a case.
package parity

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// Answer is the outcome of one Question, on either side of the comparison.
type Answer string

const (
	Allowed Answer = "allowed"
	Denied  Answer = "denied"
)

// Fixture is one RBAC scenario: a set of objects and the questions asked
// about them.
type Fixture struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Objects are plain manifests. Only the kinds rbacgraph collects, and
	// Namespace, are accepted: anything else would exist for Kubernetes but
	// not for rbacgraph, and the two sides would be answering about
	// different clusters.
	Objects   []map[string]any `json:"objects"`
	Questions []Question       `json:"questions"`
}

// Question asks whether a ServiceAccount can perform one request. Exactly one
// of MintToken, RewriteRole and BindClusterRole is set.
type Question struct {
	ID             string            `json:"id"`
	ServiceAccount ServiceAccountRef `json:"serviceAccount"`

	// MintToken asks whether the subject can create a token for another
	// ServiceAccount.
	//
	// Kubernetes: a POST to that ServiceAccount's token subresource.
	// rbacgraph: a mint-serviceaccount-token edge to it.
	//
	// It must not name the subject itself. Kubernetes authorizes that request
	// like any other, but a ServiceAccount gains nothing from a token for
	// itself, so rbacgraph, which reports escalation and not authorization,
	// has no edge for it. The two sides would be answering different
	// questions, and validate rejects the fixture.
	MintToken       *ServiceAccountRef `json:"mintToken,omitempty"`
	RewriteRole     *RewriteRole       `json:"rewriteRole,omitempty"`
	BindClusterRole *BindClusterRole   `json:"bindClusterRole,omitempty"`

	// Kubernetes is the answer kube-apiserver gives. It is the only recorded
	// answer, and the reference tests hold it to a real server.
	Kubernetes Answer `json:"kubernetes"`
	// IntentionalDifference records that rbacgraph deliberately answers the
	// opposite of Kubernetes, and why.
	IntentionalDifference *IntentionalDifference `json:"intentionalDifference,omitempty"`
}

// ServiceAccountRef names a ServiceAccount.
type ServiceAccountRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func (r ServiceAccountRef) String() string {
	return fmt.Sprintf("ServiceAccount %s/%s", r.Namespace, r.Name)
}

// RewriteRole asks whether the subject can replace the rules of an existing
// Role with rules it does not hold.
//
// Kubernetes: a dry-run PUT (verb "update") or PATCH (verb "patch") of the
// Role with a rule granting everything. rbacgraph: an escalate-verb edge
// whose Target covers the Role. rbacgraph does not distinguish the two verbs:
// one edge stands for both. Answer therefore looks for the edge with the
// verb the question does not use taken out of the subject's rules.
type RewriteRole struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Verb      string `json:"verb"`
}

// BindClusterRole asks whether the subject can bind a ClusterRole to itself.
//
// Kubernetes: a dry-run POST of a ClusterRoleBinding when Namespace is empty,
// or of a RoleBinding in Namespace otherwise, naming the subject. rbacgraph:
// a bind-verb edge whose Target is the ClusterRole and whose Scope is
// Namespace.
//
// Kubernetes also admits the binding when the subject already holds every
// permission in the ClusterRole, which rbacgraph does not treat as an
// escalation. The ClusterRole must therefore grant something the subject
// does not hold, or the two sides answer different questions.
type BindClusterRole struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// IntentionalDifference documents a difference from Kubernetes that
// rbacgraph keeps on purpose.
type IntentionalDifference struct {
	Reason string `json:"reason"`
}

// String describes the question in words, for failure messages.
func (q Question) String() string {
	switch {
	case q.MintToken != nil:
		return fmt.Sprintf("can %s create a token for %s", q.ServiceAccount, q.MintToken)
	case q.RewriteRole != nil:
		return fmt.Sprintf("can %s %s Role %s/%s with rules it does not hold", q.ServiceAccount, q.RewriteRole.Verb, q.RewriteRole.Namespace, q.RewriteRole.Name)
	case q.BindClusterRole != nil && q.BindClusterRole.Namespace == "":
		return fmt.Sprintf("can %s bind ClusterRole %s to itself with a ClusterRoleBinding", q.ServiceAccount, q.BindClusterRole.Name)
	case q.BindClusterRole != nil:
		return fmt.Sprintf("can %s bind ClusterRole %s to itself with a RoleBinding in namespace %s", q.ServiceAccount, q.BindClusterRole.Name, q.BindClusterRole.Namespace)
	}
	return "unknown question"
}

// supportedKinds are the object kinds a fixture may contain.
var supportedKinds = map[string]bool{
	"Namespace":          true,
	"ServiceAccount":     true,
	"Role":               true,
	"ClusterRole":        true,
	"RoleBinding":        true,
	"ClusterRoleBinding": true,
}

// LoadFixtures reads every *.yaml file in dir, in name order, and validates
// each one. Unknown fields are an error: a misspelt key would otherwise
// silently drop a question or an intentionalDifference.
func LoadFixtures(dir string) ([]Fixture, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	seen := map[string]string{}
	fixtures := make([]Fixture, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var f Fixture
		if err := yaml.UnmarshalStrict(raw, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := f.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if other, dup := seen[f.Name]; dup {
			return nil, fmt.Errorf("%s: fixture name %q is already used by %s", path, f.Name, other)
		}
		seen[f.Name] = path
		fixtures = append(fixtures, f)
	}
	return fixtures, nil
}

func (f Fixture) validate() error {
	if f.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(f.Questions) == 0 {
		return fmt.Errorf("fixture %q has no questions", f.Name)
	}

	serviceAccounts := map[ServiceAccountRef]bool{}
	for i, obj := range f.Objects {
		kind, _ := obj["kind"].(string)
		if !supportedKinds[kind] {
			return fmt.Errorf("fixture %q: object %d has kind %q; only %s are supported", f.Name, i, kind, strings.Join(sortedKeys(supportedKinds), ", "))
		}
		metadata, _ := obj["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if name == "" {
			return fmt.Errorf("fixture %q: object %d (%s) has no metadata.name", f.Name, i, kind)
		}
		if kind == "ServiceAccount" {
			namespace, _ := metadata["namespace"].(string)
			serviceAccounts[ServiceAccountRef{Namespace: namespace, Name: name}] = true
		}
	}

	ids := map[string]bool{}
	for _, q := range f.Questions {
		if q.ID == "" {
			return fmt.Errorf("fixture %q: a question has no id", f.Name)
		}
		if ids[q.ID] {
			return fmt.Errorf("fixture %q: question id %q is used twice", f.Name, q.ID)
		}
		ids[q.ID] = true

		// The reference asks as the ServiceAccount itself, with a token issued
		// for it, so it has to exist.
		if !serviceAccounts[q.ServiceAccount] {
			return fmt.Errorf("fixture %q, question %q: %s is not among the fixture's objects", f.Name, q.ID, q.ServiceAccount)
		}

		kinds := 0
		if q.MintToken != nil {
			kinds++
			if *q.MintToken == q.ServiceAccount {
				return fmt.Errorf("fixture %q, question %q: mintToken must name a ServiceAccount other than the subject: rbacgraph reports escalation, and a token for the subject itself is none, so this request has no edge to compare with", f.Name, q.ID)
			}
		}
		if q.RewriteRole != nil {
			kinds++
			if v := q.RewriteRole.Verb; v != "update" && v != "patch" {
				return fmt.Errorf("fixture %q, question %q: rewriteRole.verb must be update or patch, got %q", f.Name, q.ID, v)
			}
		}
		if q.BindClusterRole != nil {
			kinds++
		}
		if kinds != 1 {
			return fmt.Errorf("fixture %q, question %q: exactly one of mintToken, rewriteRole and bindClusterRole must be set, got %d", f.Name, q.ID, kinds)
		}

		if q.Kubernetes != Allowed && q.Kubernetes != Denied {
			return fmt.Errorf("fixture %q, question %q: kubernetes must be %q or %q, got %q", f.Name, q.ID, Allowed, Denied, q.Kubernetes)
		}
		if d := q.IntentionalDifference; d != nil && strings.TrimSpace(d.Reason) == "" {
			return fmt.Errorf("fixture %q, question %q: an intentionalDifference needs a reason", f.Name, q.ID)
		}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
