package webhookcoverage

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func appsRule(resources ...string) admissionregistrationv1.RuleWithOperations {
	return admissionregistrationv1.RuleWithOperations{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
		Rule: admissionregistrationv1.Rule{
			APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: resources,
		},
	}
}

func exactPolicy() *admissionregistrationv1.MatchPolicyType {
	p := admissionregistrationv1.Exact
	return &p
}

func validating(name string, webhooks ...admissionregistrationv1.ValidatingWebhook) admissionregistrationv1.ValidatingWebhookConfiguration {
	return admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: name}, Webhooks: webhooks}
}

func mutating(name string, webhooks ...admissionregistrationv1.MutatingWebhook) admissionregistrationv1.MutatingWebhookConfiguration {
	return admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: name}, Webhooks: webhooks}
}

func available() Source { return Source{Available: true} }

func deployment(ns, name string, labels map[string]string) Subject {
	return Subject{APIVersion: "apps/v1", Kind: "Deployment", Namespace: ns, Name: name, Labels: labels, LabelsKnown: true}
}

func collection(v []admissionregistrationv1.ValidatingWebhookConfiguration, m []admissionregistrationv1.MutatingWebhookConfiguration) *Collection {
	return &Collection{Validating: v, Mutating: m, ValidatingSource: available(), MutatingSource: available()}
}

func find(t *testing.T, w WorkloadAnalysis, typ WebhookType, cfg, webhook string) Result {
	t.Helper()
	for _, r := range w.Results {
		if r.Type == typ && r.Configuration == cfg && r.Webhook == webhook {
			return r
		}
	}
	t.Fatalf("no result for %s %s/%s in %+v", typ, cfg, webhook, w.Results)
	return Result{}
}

func TestAnalyze_NilCollectionIsNil(t *testing.T) {
	assert.Nil(t, Analyze(Input{Subjects: []Subject{deployment("a", "d", nil)}}))
	assert.False(t, (*Analysis)(nil).Complete())
}

func TestAnalyze_VerdictsReasonsAndIdentity(t *testing.T) {
	c := collection(
		[]admissionregistrationv1.ValidatingWebhookConfiguration{
			validating("val-cfg",
				admissionregistrationv1.ValidatingWebhook{Name: "match.example", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy()},
				admissionregistrationv1.ValidatingWebhook{Name: "other-resource.example", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("statefulsets")}, MatchPolicy: exactPolicy()},
				admissionregistrationv1.ValidatingWebhook{
					Name: "ns-labels.example", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy(),
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				},
			),
		},
		[]admissionregistrationv1.MutatingWebhookConfiguration{
			mutating("mut-cfg", admissionregistrationv1.MutatingWebhook{Name: "match.example", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy()}),
		},
	)

	a := Analyze(Input{
		Collection:       c,
		Subjects:         []Subject{deployment("known", "d", nil), deployment("unknown", "d", nil)},
		NamespaceLabels:  map[string]map[string]string{"known": {"env": "dev"}},
		SubjectsComplete: true,
	})

	require.Len(t, a.Workloads, 2)
	known, unknown := a.Workloads[0], a.Workloads[1]
	require.Equal(t, "known", known.Namespace)
	assert.True(t, known.NamespaceLabelsKnown)
	assert.False(t, unknown.NamespaceLabelsKnown)

	assert.Equal(t, Matched, find(t, known, ValidatingWebhook, "val-cfg", "match.example").Verdict)
	assert.Equal(t, Matched, find(t, known, MutatingWebhook, "mut-cfg", "match.example").Verdict,
		"validating and mutating webhooks of the same name stay distinct")

	r := find(t, known, ValidatingWebhook, "val-cfg", "other-resource.example")
	assert.Equal(t, NotMatched, r.Verdict)
	assert.Equal(t, []Reason{ReasonRulesDoNotMatch}, r.Reasons)

	r = find(t, known, ValidatingWebhook, "val-cfg", "ns-labels.example")
	assert.Equal(t, NotMatched, r.Verdict)
	assert.Equal(t, []Reason{ReasonNamespaceSelectorExcludes}, r.Reasons)

	// Unavailable namespace labels must not be read as an empty label set.
	r = find(t, unknown, ValidatingWebhook, "val-cfg", "ns-labels.example")
	assert.Equal(t, Indeterminate, r.Verdict)
	assert.Equal(t, []Reason{ReasonNamespaceLabelsUnknown}, r.Reasons)

	assert.True(t, a.Complete())
	assert.Equal(t, 1, a.ValidatingConfigurations)
	assert.Equal(t, 1, a.MutatingConfigurations)
}

func TestAnalyze_KnownEmptyNamespaceLabelsDifferFromUnavailable(t *testing.T) {
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{validating("c", admissionregistrationv1.ValidatingWebhook{
		Name: "w", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy(),
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	})}, nil)

	a := Analyze(Input{
		Collection:      c,
		Subjects:        []Subject{deployment("empty", "d", nil), deployment("missing", "d", nil)},
		NamespaceLabels: map[string]map[string]string{"empty": nil},
	})

	assert.Equal(t, NotMatched, a.Workloads[0].Results[0].Verdict, "a namespace known to have no labels is excluded")
	assert.Equal(t, Indeterminate, a.Workloads[1].Results[0].Verdict, "a namespace that was not collected is undecided")
}

func TestAnalyze_UnknownObjectLabelsAreIndeterminate(t *testing.T) {
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{validating("c", admissionregistrationv1.ValidatingWebhook{
		Name: "w", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy(),
		ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
	})}, nil)
	s := deployment("n", "d", nil)
	s.LabelsKnown = false

	a := Analyze(Input{Collection: c, Subjects: []Subject{s}, NamespaceLabels: map[string]map[string]string{"n": nil}})

	assert.Equal(t, Indeterminate, a.Workloads[0].Results[0].Verdict)
	assert.Equal(t, []Reason{ReasonObjectLabelsUnknown}, a.Workloads[0].Results[0].Reasons)
}

func TestAnalyze_EquivalentPolicyIndeterminateReasonKept(t *testing.T) {
	// Default matchPolicy (Equivalent): a rule for another version cannot be
	// ruled out without the apiserver's registry.
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{validating("c", admissionregistrationv1.ValidatingWebhook{
		Name: "w", Rules: []admissionregistrationv1.RuleWithOperations{{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
			Rule:       admissionregistrationv1.Rule{APIGroups: []string{"extensions"}, APIVersions: []string{"v1beta1"}, Resources: []string{"deployments"}},
		}},
	})}, nil)

	a := Analyze(Input{Collection: c, Subjects: []Subject{deployment("n", "d", nil)}, NamespaceLabels: map[string]map[string]string{"n": nil}})

	r := a.Workloads[0].Results[0]
	assert.Equal(t, Indeterminate, r.Verdict)
	assert.Equal(t, []Reason{ReasonEquivalentResources}, r.Reasons)
}

func TestAnalyze_MatchConditionsNeverMatched(t *testing.T) {
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{validating("c", admissionregistrationv1.ValidatingWebhook{
		Name: "w", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy(),
		MatchConditions: []admissionregistrationv1.MatchCondition{{Name: "x", Expression: "true"}},
	})}, nil)

	a := Analyze(Input{Collection: c, Subjects: []Subject{deployment("n", "d", nil)}, NamespaceLabels: map[string]map[string]string{"n": nil}})

	assert.Equal(t, Indeterminate, a.Workloads[0].Results[0].Verdict)
	assert.Equal(t, []Reason{ReasonMatchConditions}, a.Workloads[0].Results[0].Reasons)
}

func TestAnalyze_MalformedWebhookDoesNotStopOthers(t *testing.T) {
	bad := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "Bogus"}}}
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{
		validating("c",
			admissionregistrationv1.ValidatingWebhook{Name: "broken", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy(), NamespaceSelector: bad},
			admissionregistrationv1.ValidatingWebhook{Name: "fine", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy()},
		),
	}, nil)

	a := Analyze(Input{Collection: c, Subjects: []Subject{deployment("n", "d", nil)}, NamespaceLabels: map[string]map[string]string{"n": nil}})

	w := a.Workloads[0]
	broken := find(t, w, ValidatingWebhook, "c", "broken")
	assert.Equal(t, Indeterminate, broken.Verdict)
	assert.Equal(t, []Reason{ReasonInvalidNamespaceSelector}, broken.Reasons)
	assert.Equal(t, Matched, find(t, w, ValidatingWebhook, "c", "fine").Verdict)
	require.Len(t, a.ConfigurationIssues, 1)
	assert.Contains(t, a.ConfigurationIssues[0], "broken")
}

func TestAnalyze_NoConfigurationsDiffersFromFailedCollection(t *testing.T) {
	subjects := []Subject{deployment("n", "d", nil)}

	none := Analyze(Input{Collection: collection(nil, nil), Subjects: subjects, SubjectsComplete: true})
	assert.True(t, none.Complete())
	assert.True(t, none.ValidatingSource.Available)
	assert.Zero(t, none.ValidatingConfigurations)
	assert.Empty(t, none.Workloads[0].Results)

	failed := Analyze(Input{
		Collection:       &Collection{ValidatingSource: Source{Err: ErrForbidden}, MutatingSource: Source{Err: ErrUnsupported}},
		Subjects:         subjects,
		SubjectsComplete: true,
	})
	assert.False(t, failed.Complete())
	assert.ErrorIs(t, failed.ValidatingSource.Err, ErrForbidden)
	assert.ErrorIs(t, failed.MutatingSource.Err, ErrUnsupported)
}

func TestAnalyze_PartialCollectionKeepsAvailableResultsButIsIncomplete(t *testing.T) {
	c := &Collection{
		Mutating:         []admissionregistrationv1.MutatingWebhookConfiguration{mutating("m", admissionregistrationv1.MutatingWebhook{Name: "w", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy()})},
		ValidatingSource: Source{Err: ErrForbidden},
		MutatingSource:   available(),
	}

	a := Analyze(Input{Collection: c, Subjects: []Subject{deployment("n", "d", nil)}, NamespaceLabels: map[string]map[string]string{"n": nil}, SubjectsComplete: true})

	require.Len(t, a.Workloads[0].Results, 1)
	assert.Equal(t, MutatingWebhook, a.Workloads[0].Results[0].Type)
	assert.False(t, a.Complete())
}

func TestAnalyze_IncompleteInputsAreNeverComplete(t *testing.T) {
	c := collection(nil, nil)
	assert.False(t, Analyze(Input{Collection: c}).Complete(), "unknown whether all workloads were collected")
	assert.True(t, Analyze(Input{Collection: c, SubjectsComplete: true}).Complete())

	c.MutatingSource.DecodeErrs = []error{fmt.Errorf("skipped")}
	assert.False(t, Analyze(Input{Collection: c, SubjectsComplete: true}).Complete(), "a skipped configuration is a gap")
}

func TestAnalyze_UnsupportedSubjectsAreCountedNotDropped(t *testing.T) {
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{validating("c", admissionregistrationv1.ValidatingWebhook{
		Name: "w", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy(),
	})}, nil)

	a := Analyze(Input{Collection: c, Subjects: []Subject{
		deployment("n", "d", nil),
		{APIVersion: "extensions/v1beta1", Kind: "Deployment", Namespace: "n", Name: "old"},
		{APIVersion: "v1", Kind: "ConfigMap", Namespace: "n", Name: "a"},
		{APIVersion: "v1", Kind: "ConfigMap", Namespace: "n", Name: "b"},
		{APIVersion: "example.com/v1", Kind: "Widget", Namespace: "n", Name: "w"},
	}})

	require.Len(t, a.Workloads, 1)
	assert.Equal(t, []SkippedKind{
		{APIVersion: "example.com/v1", Kind: "Widget", Reason: SkipNotAWorkload, Count: 1},
		{APIVersion: "extensions/v1beta1", Kind: "Deployment", Reason: SkipUnsupportedVersion, Count: 1},
		{APIVersion: "v1", Kind: "ConfigMap", Reason: SkipNotAWorkload, Count: 2},
	}, a.Skipped)
}

func TestAnalyze_NamespacelessNamespacedWorkloadIsIndeterminate(t *testing.T) {
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{validating("c", admissionregistrationv1.ValidatingWebhook{
		Name: "w", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy(),
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	})}, nil)

	a := Analyze(Input{Collection: c, Subjects: []Subject{deployment("", "d", nil)}, NamespaceLabels: map[string]map[string]string{"": {"env": "prod"}}})

	assert.False(t, a.Workloads[0].NamespaceLabelsKnown, "labels cannot belong to no namespace")
	assert.Equal(t, Indeterminate, a.Workloads[0].Results[0].Verdict)
}

func TestAnalyze_OrderingAndSummariesAreDeterministic(t *testing.T) {
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{validating("c",
		admissionregistrationv1.ValidatingWebhook{Name: "w1", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy()},
		admissionregistrationv1.ValidatingWebhook{Name: "w2", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("jobs")}, MatchPolicy: exactPolicy()},
	)}, nil)
	subjects := []Subject{deployment("b", "z", nil), deployment("a", "y", nil), deployment("a", "x", nil)}
	ns := map[string]map[string]string{"a": nil, "b": nil}

	first := Analyze(Input{Collection: c, Subjects: subjects, NamespaceLabels: ns})
	// Reversing the input must not change the output.
	reversed := []Subject{subjects[2], subjects[1], subjects[0]}
	second := Analyze(Input{Collection: c, Subjects: reversed, NamespaceLabels: ns})

	assert.Equal(t, first, second)
	assert.Equal(t, "x", first.Workloads[0].Name)
	assert.Equal(t, "z", first.Workloads[2].Name)
	require.Len(t, first.Webhooks, 2)
	assert.Equal(t, WebhookSummary{Type: ValidatingWebhook, Configuration: "c", Webhook: "w1", Matched: 3}, first.Webhooks[0])
	assert.Equal(t, WebhookSummary{Type: ValidatingWebhook, Configuration: "c", Webhook: "w2", NotMatched: 3}, first.Webhooks[1])
}

func TestAnalyze_NotMatchedAloneIsNotAFinding(t *testing.T) {
	// The analysis type carries no finding, severity or status field: a
	// NotMatched webhook must stay a neutral verdict.
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{validating("c", admissionregistrationv1.ValidatingWebhook{
		Name: "w", Rules: []admissionregistrationv1.RuleWithOperations{appsRule("jobs")}, MatchPolicy: exactPolicy(),
	})}, nil)

	a := Analyze(Input{Collection: c, Subjects: []Subject{deployment("n", "d", nil)}, NamespaceLabels: map[string]map[string]string{"n": nil}, SubjectsComplete: true})

	assert.Equal(t, NotMatched, a.Workloads[0].Results[0].Verdict)
	assert.True(t, a.Complete(), "complete collection is not a claim about protection")
}

func TestWorkloadResourceKeys(t *testing.T) {
	keys := WorkloadResourceKeys()
	assert.Len(t, keys, len(workloadResources))
	assert.Contains(t, keys, "/v1/pods")
	assert.Contains(t, keys, "apps/v1/deployments")
	assert.IsIncreasing(t, keys)
}

func BenchmarkAnalyze(b *testing.B) {
	var webhooks []admissionregistrationv1.ValidatingWebhook
	for i := range 50 {
		webhooks = append(webhooks, admissionregistrationv1.ValidatingWebhook{
			Name: fmt.Sprintf("w%d", i), Rules: []admissionregistrationv1.RuleWithOperations{appsRule("deployments")}, MatchPolicy: exactPolicy(),
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		})
	}
	c := collection([]admissionregistrationv1.ValidatingWebhookConfiguration{validating("c", webhooks...)}, nil)
	ns := map[string]map[string]string{}
	var subjects []Subject
	for i := range 5000 {
		n := fmt.Sprintf("ns%d", i%100)
		ns[n] = map[string]string{"env": "prod"}
		subjects = append(subjects, deployment(n, fmt.Sprintf("d%d", i), map[string]string{"app": "x"}))
	}
	b.ReportAllocs()
	for b.Loop() {
		Analyze(Input{Collection: c, Subjects: subjects, NamespaceLabels: ns})
	}
}
