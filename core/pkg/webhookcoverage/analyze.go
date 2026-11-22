package webhookcoverage

import (
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

// This file runs collected workloads through the matcher in index.go. It adds
// no matching logic of its own: every verdict and reason comes from
// Index.Matches.
//
// What an Analysis means. For each workload it answers, per webhook, whether a
// synthetic CREATE request for that workload satisfies the webhook's matching
// criteria. Matched is not a promise that the webhook is called or that it
// enforces anything, and NotMatched is not a statement that the workload is
// unprotected: other webhooks, admission policies and built-in admission
// plugins are out of view, and so is the health of any backend. Nothing here
// is a security finding.

// analyzedOperation is the operation every workload is analyzed under: its
// creation, which is also how controllers create the pods they manage.
const analyzedOperation = admissionregistrationv1.Create

// workloadResources maps the (apiVersion, kind) of each workload type that can
// be analyzed to its resource coordinates. Only versions whose plural resource
// name and scope are certain are listed; any other version of these kinds is
// reported as skipped rather than guessed at.
var workloadResources = map[string]struct{ group, version, resource string }{
	"v1|Pod":                   {"", "v1", "pods"},
	"v1|ReplicationController": {"", "v1", "replicationcontrollers"},
	"apps/v1|Deployment":       {"apps", "v1", "deployments"},
	"apps/v1|StatefulSet":      {"apps", "v1", "statefulsets"},
	"apps/v1|DaemonSet":        {"apps", "v1", "daemonsets"},
	"apps/v1|ReplicaSet":       {"apps", "v1", "replicasets"},
	"batch/v1|Job":             {"batch", "v1", "jobs"},
	"batch/v1|CronJob":         {"batch", "v1", "cronjobs"},
}

// workloadKinds is the set of kinds in workloadResources, to tell an
// unsupported version of a workload kind from a kind that is not a workload.
var workloadKinds = map[string]struct{}{
	"Pod": {}, "ReplicationController": {}, "Deployment": {}, "StatefulSet": {},
	"DaemonSet": {}, "ReplicaSet": {}, "Job": {}, "CronJob": {},
}

// WorkloadResourceKeys returns the <group>/<version>/<resource> key of every
// analyzable workload type, sorted, in the form a scan uses to name a queried
// resource. A caller uses it to check that a scan listed all of them.
func WorkloadResourceKeys() []string {
	keys := make([]string, 0, len(workloadResources))
	for _, r := range workloadResources {
		keys = append(keys, r.group+"/"+r.version+"/"+r.resource)
	}
	sort.Strings(keys)
	return keys
}

// Why a kind was not analyzed.
const (
	// SkipNotAWorkload: the kind is not one of the analyzed workload types.
	SkipNotAWorkload = "NotAnalyzedWorkloadKind"
	// SkipUnsupportedVersion: a workload kind served under an apiVersion whose
	// plural resource name or scope this analysis does not assume.
	SkipUnsupportedVersion = "UnsupportedAPIVersion"
)

// Subject is one collected resource offered for analysis.
type Subject struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	// Labels are the object's own labels. They are used only when LabelsKnown
	// is true: an object with no labels and an object whose labels were not
	// collected are different things.
	Labels      map[string]string
	LabelsKnown bool
}

// Input is everything Analyze needs.
type Input struct {
	// Collection is the webhook configurations read from the cluster.
	Collection *Collection
	// Subjects are the collected resources. Kinds that are not analyzable are
	// counted in Analysis.Skipped, not dropped silently.
	Subjects []Subject
	// NamespaceLabels maps a namespace name to its labels. A namespace absent
	// from the map has unknown labels; a namespace present with no labels is
	// known to have none.
	NamespaceLabels map[string]map[string]string
	// SubjectsComplete says whether collecting Subjects succeeded in full. The
	// caller knows this; Analyze cannot tell a missing workload from one that
	// does not exist.
	SubjectsComplete bool
}

// WorkloadAnalysis is the per-webhook outcome for one workload.
type WorkloadAnalysis struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	// NamespaceLabelsKnown records whether the namespace's labels were
	// available. When false, a namespaceSelector on a custom label can only be
	// Indeterminate.
	NamespaceLabelsKnown bool
	// Results has one entry per webhook, validating configurations first, then
	// mutating, in the order of the configurations.
	Results []Result
}

// SkippedKind counts resources of one kind that were not analyzed.
type SkippedKind struct {
	APIVersion string
	Kind       string
	Reason     string
	Count      int
}

// WebhookSummary tallies verdicts for one webhook across all analyzed
// workloads.
type WebhookSummary struct {
	Type          WebhookType
	Configuration string
	Webhook       string
	Matched       int
	NotMatched    int
	Indeterminate int
}

// Analysis is the structured outcome of analyzing workloads against webhook
// configurations. It is neutral: it contains no findings, and a clean-looking
// Analysis is not proof of coverage; check Complete.
type Analysis struct {
	// Operation is the synthetic request operation every workload was
	// analyzed under.
	Operation admissionregistrationv1.OperationType

	// ValidatingSource and MutatingSource report whether each kind of
	// configuration could be read. When one is unavailable no result mentions
	// that kind, which says nothing about whether such webhooks exist.
	ValidatingSource Source
	MutatingSource   Source
	// ValidatingConfigurations and MutatingConfigurations count the
	// configurations analyzed; zero with an available source means the cluster
	// has none.
	ValidatingConfigurations int
	MutatingConfigurations   int
	// ConfigurationIssues are malformed parts of webhook configurations. Such
	// a webhook is still analyzed and answers Indeterminate wherever the
	// broken part would have to be evaluated.
	ConfigurationIssues []string

	// SubjectsComplete is Input.SubjectsComplete.
	SubjectsComplete bool

	// Workloads are the analyzed workloads, ordered by apiVersion, kind,
	// namespace and name.
	Workloads []WorkloadAnalysis
	// Webhooks has one summary per webhook, in the order of the results.
	Webhooks []WebhookSummary
	// Skipped lists the kinds that were not analyzed, ordered by apiVersion
	// and kind.
	Skipped []SkippedKind
}

// Complete reports whether both webhook lists and the workloads were collected
// in full. An incomplete Analysis can still hold valid results for what was
// collected, but must not be read as covering the whole cluster. Complete does
// not mean every verdict is definite.
func (a *Analysis) Complete() bool {
	return a != nil && a.ValidatingSource.Complete() && a.MutatingSource.Complete() && a.SubjectsComplete
}

// Analyze matches every analyzable subject against the collected webhook
// configurations with Index.Matches. It returns nil when in.Collection is nil.
//
// A kind of configuration that could not be read contributes no webhooks and is
// reported through the Sources, so unrelated results are kept while the gap
// stays visible. Output ordering is deterministic.
func Analyze(in Input) *Analysis {
	if in.Collection == nil {
		return nil
	}
	c := in.Collection
	a := &Analysis{
		Operation:        analyzedOperation,
		ValidatingSource: c.ValidatingSource,
		MutatingSource:   c.MutatingSource,
		SubjectsComplete: in.SubjectsComplete,
	}

	var validating []admissionregistrationv1.ValidatingWebhookConfiguration
	if c.ValidatingSource.Available {
		validating = c.Validating
		a.ValidatingConfigurations = len(validating)
	}
	var mutating []admissionregistrationv1.MutatingWebhookConfiguration
	if c.MutatingSource.Available {
		mutating = c.Mutating
		a.MutatingConfigurations = len(mutating)
	}
	idx, errs := NewIndex(validating, mutating)
	for _, err := range errs {
		a.ConfigurationIssues = append(a.ConfigurationIssues, err.Error())
	}

	subjects, skipped := selectSubjects(in.Subjects)
	a.Skipped = skipped

	a.Workloads = make([]WorkloadAnalysis, 0, len(subjects))
	summaries := map[int]*WebhookSummary{}
	for _, s := range subjects {
		res := workloadResources[s.APIVersion+"|"+s.Kind]
		nsLabels, nsKnown := in.NamespaceLabels[s.Namespace]
		results := idx.Matches(Request{
			Group:                res.group,
			Version:              res.version,
			Resource:             res.resource,
			Kind:                 s.Kind,
			Operation:            analyzedOperation,
			Name:                 s.Name,
			Namespace:            s.Namespace,
			ObjectLabels:         s.Labels,
			ObjectLabelsKnown:    s.LabelsKnown,
			NamespaceLabels:      nsLabels,
			NamespaceLabelsKnown: nsKnown && s.Namespace != "",
		})
		for i, r := range results {
			sum := summaries[i]
			if sum == nil {
				sum = &WebhookSummary{Type: r.Type, Configuration: r.Configuration, Webhook: r.Webhook}
				summaries[i] = sum
			}
			switch r.Verdict {
			case Matched:
				sum.Matched++
			case NotMatched:
				sum.NotMatched++
			default:
				sum.Indeterminate++
			}
		}
		a.Workloads = append(a.Workloads, WorkloadAnalysis{
			APIVersion:           s.APIVersion,
			Kind:                 s.Kind,
			Namespace:            s.Namespace,
			Name:                 s.Name,
			NamespaceLabelsKnown: nsKnown && s.Namespace != "",
			Results:              results,
		})
	}

	// With no workloads there is nothing to tally, but the webhooks still
	// exist and are listed, with zero counts.
	for i := range len(idx.webhooks) {
		sum, ok := summaries[i]
		if !ok {
			w := idx.webhooks[i]
			sum = &WebhookSummary{Type: w.kind, Configuration: w.configuration, Webhook: w.name}
		}
		a.Webhooks = append(a.Webhooks, *sum)
	}
	return a
}

// selectSubjects splits subjects into the analyzable ones, sorted, and a count
// of the others by kind.
func selectSubjects(all []Subject) (analyzable []Subject, skipped []SkippedKind) {
	type kindKey struct{ apiVersion, kind, reason string }
	counts := map[kindKey]int{}
	for _, s := range all {
		if _, ok := workloadResources[s.APIVersion+"|"+s.Kind]; ok {
			analyzable = append(analyzable, s)
			continue
		}
		reason := SkipNotAWorkload
		if _, isWorkload := workloadKinds[s.Kind]; isWorkload {
			reason = SkipUnsupportedVersion
		}
		counts[kindKey{s.APIVersion, s.Kind, reason}]++
	}
	sort.SliceStable(analyzable, func(i, j int) bool {
		x, y := analyzable[i], analyzable[j]
		if x.APIVersion != y.APIVersion {
			return x.APIVersion < y.APIVersion
		}
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		if x.Namespace != y.Namespace {
			return x.Namespace < y.Namespace
		}
		return x.Name < y.Name
	})
	for k, n := range counts {
		skipped = append(skipped, SkippedKind{APIVersion: k.apiVersion, Kind: k.kind, Reason: k.reason, Count: n})
	}
	sort.Slice(skipped, func(i, j int) bool {
		if skipped[i].APIVersion != skipped[j].APIVersion {
			return skipped[i].APIVersion < skipped[j].APIVersion
		}
		return strings.Compare(skipped[i].Kind, skipped[j].Kind) < 0
	})
	return analyzable, skipped
}
