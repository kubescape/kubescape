package parity

import (
	"strings"
	"testing"
)

// The parity rule is exercised here on its own, with invented answers, so
// that the three outcomes that matter are covered whatever the real fixtures
// currently contain: none of them records an intentional difference today.

func ruleQuestion(difference *IntentionalDifference) Question {
	return Question{
		ID:                    "q",
		ServiceAccount:        ServiceAccountRef{Namespace: "ns", Name: "subject"},
		MintToken:             &ServiceAccountRef{Namespace: "ns", Name: "target"},
		Kubernetes:            Allowed,
		IntentionalDifference: difference,
	}
}

func TestCompare_AgreementPasses(t *testing.T) {
	if err := Compare("f", ruleQuestion(nil), Allowed, Allowed); err != nil {
		t.Errorf("Compare() = %v, want nil when both sides agree", err)
	}
}

func TestCompare_UndocumentedDifferenceFails(t *testing.T) {
	err := Compare("f", ruleQuestion(nil), Allowed, Denied)
	if err == nil {
		t.Fatal("Compare() = nil, want an error: Kubernetes allows and Kubescape denies with nothing recorded")
	}
	// The message has to be enough to act on without opening the fixture.
	for _, want := range []string{`fixture "f"`, `question "q"`, "ServiceAccount ns/subject", "ServiceAccount ns/target", "Kubernetes: allowed", "Kubescape:  denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestCompare_DocumentedDifferencePasses(t *testing.T) {
	q := ruleQuestion(&IntentionalDifference{Reason: "deliberate over-approximation"})
	if err := Compare("f", q, Allowed, Denied); err != nil {
		t.Errorf("Compare() = %v, want nil: the difference is recorded with a reason", err)
	}
}

func TestCompare_StaleDocumentedDifferenceFails(t *testing.T) {
	q := ruleQuestion(&IntentionalDifference{Reason: "deliberate over-approximation"})
	err := Compare("f", q, Allowed, Allowed)
	if err == nil {
		t.Fatal("Compare() = nil, want an error: a difference is recorded but both sides agree")
	}
	if !strings.Contains(err.Error(), "deliberate over-approximation") || !strings.Contains(err.Error(), "remove it") {
		t.Errorf("error %q should quote the recorded reason and say to remove it", err)
	}
}

func TestCheckRecorded(t *testing.T) {
	q := ruleQuestion(nil)
	if err := CheckRecorded("f", q, Allowed, "v1.2.3"); err != nil {
		t.Errorf("CheckRecorded() = %v, want nil when the server gives the recorded answer", err)
	}
	err := CheckRecorded("f", q, Denied, "v1.2.3")
	if err == nil {
		t.Fatal("CheckRecorded() = nil, want an error: the server denies what the fixture records as allowed")
	}
	for _, want := range []string{`fixture "f"`, `question "q"`, "recorded Kubernetes answer: allowed", "kube-apiserver v1.2.3", "denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// A recorded difference cannot hide a wrong recorded answer: the reference
// run checks the recording first, independently of what Kubescape says.
func TestCheckRecorded_IgnoresIntentionalDifference(t *testing.T) {
	q := ruleQuestion(&IntentionalDifference{Reason: "deliberate"})
	if err := CheckRecorded("f", q, Denied, "v1.2.3"); err == nil {
		t.Error("CheckRecorded() = nil, want an error: an intentionalDifference must not excuse a wrong recorded answer")
	}
}

func TestLoadFixtures_RejectsInvalidFixtures(t *testing.T) {
	const objects = `
objects:
  - {apiVersion: v1, kind: ServiceAccount, metadata: {name: subject, namespace: ns}}
`
	const subject = "serviceAccount: {namespace: ns, name: subject}"
	cases := map[string]struct{ fixture, want string }{
		"unknown field": {
			"name: f" + objects + "questions:\n  - {id: q, " + subject + ", mintToken: {namespace: ns, name: t}, kubernetes: allowed, kubescape: denied}\n",
			"unknown field",
		},
		"no question kind": {
			"name: f" + objects + "questions:\n  - {id: q, " + subject + ", kubernetes: allowed}\n",
			"exactly one of",
		},
		"two question kinds": {
			"name: f" + objects + "questions:\n  - {id: q, " + subject + ", mintToken: {namespace: ns, name: t}, bindClusterRole: {name: c}, kubernetes: allowed}\n",
			"exactly one of",
		},
		"answer is not allowed or denied": {
			"name: f" + objects + "questions:\n  - {id: q, " + subject + ", mintToken: {namespace: ns, name: t}, kubernetes: maybe}\n",
			"kubernetes must be",
		},
		"difference without a reason": {
			"name: f" + objects + "questions:\n  - {id: q, " + subject + ", mintToken: {namespace: ns, name: t}, kubernetes: allowed, intentionalDifference: {reason: \" \"}}\n",
			"needs a reason",
		},
		"duplicate question id": {
			"name: f" + objects + "questions:\n  - {id: q, " + subject + ", mintToken: {namespace: ns, name: t}, kubernetes: allowed}\n  - {id: q, " + subject + ", mintToken: {namespace: ns, name: t}, kubernetes: allowed}\n",
			"used twice",
		},
		"subject is not an object of the fixture": {
			"name: f" + objects + "questions:\n  - {id: q, serviceAccount: {namespace: ns, name: missing}, mintToken: {namespace: ns, name: t}, kubernetes: allowed}\n",
			"not among the fixture's objects",
		},
		"object kind rbacgraph does not collect": {
			"name: f\nobjects:\n  - {apiVersion: v1, kind: Pod, metadata: {name: p, namespace: ns}}\nquestions:\n  - {id: q, " + subject + ", mintToken: {namespace: ns, name: t}, kubernetes: allowed}\n",
			`kind "Pod"`,
		},
		"rewriteRole verb": {
			"name: f" + objects + "questions:\n  - {id: q, " + subject + ", rewriteRole: {namespace: ns, name: r, verb: delete}, kubernetes: allowed}\n",
			"must be update or patch",
		},
		// Kubernetes allows this request when the grant covers it, and rbacgraph
		// has no edge for it, so it must be refused here and not left to fail
		// as a difference somebody then records as intentional.
		"mintToken for the subject itself": {
			"name: f" + objects + "questions:\n  - {id: q, " + subject + ", mintToken: {namespace: ns, name: subject}, kubernetes: allowed}\n",
			"mintToken must name a ServiceAccount other than the subject",
		},
		"no questions": {
			"name: f" + objects,
			"has no questions",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "fixture.yaml", tc.fixture)
			_, err := LoadFixtures(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("LoadFixtures() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadFixtures_RejectsDuplicateFixtureNames(t *testing.T) {
	const fixture = `name: same
objects:
  - {apiVersion: v1, kind: ServiceAccount, metadata: {name: subject, namespace: ns}}
questions:
  - {id: q, serviceAccount: {namespace: ns, name: subject}, mintToken: {namespace: ns, name: t}, kubernetes: denied}
`
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", fixture)
	writeFile(t, dir, "b.yaml", fixture)
	if _, err := LoadFixtures(dir); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("LoadFixtures() error = %v, want a duplicate fixture name error", err)
	}
}
