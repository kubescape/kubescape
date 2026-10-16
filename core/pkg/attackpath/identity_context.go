package attackpath

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
)

// IdentityStatus says how far the correlation of one vulnerable workload got.
// It is never a statement about safety: every status other than
// IdentityAnalyzed means a part of the join could not be established, and
// IdentityAnalyzed itself only describes the collected RBAC objects.
type IdentityStatus string

const (
	// IdentityAnalyzed: the workload resolved to a ServiceAccount, RBAC was
	// collected completely, and the escalation analysis ran.
	IdentityAnalyzed IdentityStatus = "analyzed"
	// IdentityTokenNotMounted: as IdentityAnalyzed, but the resolver reports
	// that no ServiceAccount token reaches the workload. The escalation
	// analysis still ran and is attached: the resolver's token verdict can be
	// wrong, and a wrong "not mounted" must not hide what the ServiceAccount
	// can do.
	IdentityTokenNotMounted IdentityStatus = "token-not-mounted"
	// IdentityWorkloadUnresolved: no ServiceAccount could be established for
	// the workload. Nothing is known about its identity or RBAC.
	IdentityWorkloadUnresolved IdentityStatus = "workload-unresolved"
	// IdentityRBACUnavailable: RBAC objects were not collected, so no
	// analysis ran. This is not an empty analysis.
	IdentityRBACUnavailable IdentityStatus = "rbac-unavailable"
	// IdentityRBACIncomplete: RBAC collection was partial. The analysis ran
	// over what was collected and is attached, but it cannot establish a
	// negative.
	IdentityRBACIncomplete IdentityStatus = "rbac-incomplete"
)

// TokenState is whether the resolver found a ServiceAccount token mounted
// into the workload. TokenUnknown is the zero value and must not be read as
// TokenNotMounted.
type TokenState string

const (
	TokenUnknown    TokenState = "unknown"
	TokenMounted    TokenState = "mounted"
	TokenNotMounted TokenState = "not-mounted"
)

// ServiceAccountOrigin is whether the ServiceAccount name was written in the
// workload or filled in as "default". OriginUnknown is the zero value: a
// resolver that cannot tell an omitted name from an explicit "default"
// reports it, rather than guessing.
type ServiceAccountOrigin string

const (
	OriginUnknown   ServiceAccountOrigin = "unknown"
	OriginExplicit  ServiceAccountOrigin = "explicit"
	OriginDefaulted ServiceAccountOrigin = "defaulted"
)

// ObjectPresence is whether the ServiceAccount object itself was in the
// collected RBAC snapshot. Bindings can name a ServiceAccount that was not
// collected, so the analysis runs either way.
type ObjectPresence string

const (
	ObjectPresenceUnknown ObjectPresence = "unknown"
	ObjectPresent         ObjectPresence = "present"
	ObjectAbsent          ObjectPresence = "absent"
)

// RBACState is how complete the collected RBAC objects are. The zero value is
// RBACUnavailable, so a caller that forgets to say anything gets the
// conservative reading.
type RBACState string

const (
	RBACUnavailable RBACState = ""
	RBACPartial     RBACState = "partial"
	RBACComplete    RBACState = "complete"
)

// VulnerabilityRef is one vulnerability on a workload, carried as the
// existing findings report it. Severity is the original string, not
// re-derived.
type VulnerabilityRef struct {
	ID           string
	Severity     string
	FixAvailable bool
}

// WorkloadVulns is the vulnerability findings of one workload.
type WorkloadVulns struct {
	Workload        vulnexposure.Workload
	Vulnerabilities []VulnerabilityRef
}

// WorkloadIdentity is the resolved ServiceAccount of one workload, as the
// canonical workload-to-ServiceAccount resolver reports it. A caller adapts
// the resolver's output into this type; nothing here reads a workload spec.
type WorkloadIdentity struct {
	// Namespace is the ServiceAccount's namespace; empty means the
	// workload's. A ServiceAccount is always in its pod's namespace, so any
	// other value is inconsistent input and leaves the workload unresolved.
	Namespace          string
	ServiceAccountName string
	Origin             ServiceAccountOrigin
	Token              TokenState
	// TokenReason explains a not-mounted or unknown Token.
	TokenReason string
}

// RBACInput is the RBAC snapshot, indexed once and shared by every workload.
type RBACInput struct {
	Index *rbacgraph.Index
	State RBACState
	// Reason says why State is not RBACComplete.
	Reason string
}

// IdentityInput is everything CorrelateIdentity joins.
type IdentityInput struct {
	Workloads []WorkloadVulns
	// Identities is keyed by the exact workload identity. A workload that is
	// not in it is unresolved; it is never matched by name.
	Identities map[vulnexposure.Workload]WorkloadIdentity
	// UnresolvedReasons optionally says why a workload has no identity.
	UnresolvedReasons map[vulnexposure.Workload]string
	RBAC              RBACInput
}

// PermissionSummary separates the things a ServiceAccount's RBAC analysis
// says that are easy to run together. The first three answer different
// questions and none implies another:
//
//   - DirectRules: what it holds through its own bindings.
//   - GainedRules: finite rules it can additionally adopt (bind/escalate),
//     or inherits from an identity it can reach. These leave Reached,
//     Unbounded and ClusterAdmin untouched.
//   - IdentitiesReached, Unbounded, ClusterAdmin: other power it can reach.
//
// Nothing here is a statement about exploitation.
type PermissionSummary struct {
	DirectRules []rbacgraph.ScopedRule
	// GainedRules is the analysis's effective rules that are not direct
	// rules, deduplicated and sorted. Granted on the Escalation explains
	// them. When ClusterAdmin is true it is not a complete enumeration.
	GainedRules    []rbacgraph.ScopedRule
	PermissionGain bool

	IdentitiesReached int
	// Unbounded is true when any unenumerable grant, or a missing-target
	// warning, was found; ScopeUnknown narrows it to the latter kind.
	Unbounded    bool
	ScopeUnknown bool
	ClusterAdmin bool
	Truncated    bool

	// NoAdditionalReachabilityFound is true only when the RBAC input is
	// complete, the search was not truncated, and no other identity,
	// unbounded grant, scope warning or cluster-admin power was found. It
	// says nothing about GainedRules, and it is not "safe".
	NoAdditionalReachabilityFound bool
}

// IdentityContext is the ServiceAccount context of one vulnerable workload.
// It never changes the severity of its vulnerabilities.
type IdentityContext struct {
	Workload        vulnexposure.Workload
	Vulnerabilities []VulnerabilityRef

	Status IdentityStatus
	Reason string

	// ServiceAccount is nil only when the workload is unresolved.
	ServiceAccount       *rbacgraph.Subject
	ServiceAccountOrigin ServiceAccountOrigin
	ServiceAccountObject ObjectPresence
	// Token is the resolver's static assessment of whether a token reaches
	// the workload. It is separate from, and never alters, the RBAC analysis.
	Token       TokenState
	TokenReason string
	RBAC        RBACState

	// Escalation and Permissions are nil unless the analysis ran. Contexts
	// that share a ServiceAccount share these values; treat them as read-only.
	Escalation  *rbacgraph.EscalationResult
	Permissions *PermissionSummary
}

type analyzed struct {
	escalation  *rbacgraph.EscalationResult
	permissions *PermissionSummary
}

// CorrelateIdentity joins each workload's vulnerabilities to the RBAC
// analysis of its ServiceAccount: one context per workload, sorted by
// workload, with AnalyzeEscalation run at most once per distinct
// ServiceAccount. Workloads are matched on their exact (namespace, kind,
// name); duplicates of one workload in the input are merged.
func CorrelateIdentity(in IdentityInput) []IdentityContext {
	byWorkload := make(map[vulnexposure.Workload][]VulnerabilityRef, len(in.Workloads))
	for _, w := range in.Workloads {
		byWorkload[w.Workload] = append(byWorkload[w.Workload], w.Vulnerabilities...)
	}
	workloads := make([]vulnexposure.Workload, 0, len(byWorkload))
	for w := range byWorkload {
		workloads = append(workloads, w)
	}
	slices.SortFunc(workloads, compareWorkloads)

	rbacState := in.RBAC.State
	if in.RBAC.Index == nil {
		rbacState = RBACUnavailable
	}
	cache := map[rbacgraph.Subject]analyzed{}

	out := make([]IdentityContext, 0, len(workloads))
	for _, w := range workloads {
		ctx := IdentityContext{
			Workload:             w,
			Vulnerabilities:      mergeVulnerabilities(byWorkload[w]),
			ServiceAccountOrigin: OriginUnknown,
			ServiceAccountObject: ObjectPresenceUnknown,
			Token:                TokenUnknown,
			RBAC:                 rbacState,
		}

		id, resolved := in.Identities[w]
		if reason := unresolvedReason(w, id, resolved, in.UnresolvedReasons[w]); reason != "" {
			ctx.Status = IdentityWorkloadUnresolved
			ctx.Reason = reason
			out = append(out, ctx)
			continue
		}

		subject := rbacgraph.Subject{Kind: rbacgraph.KindServiceAccount, Namespace: w.Namespace, Name: id.ServiceAccountName}
		ctx.ServiceAccount = &subject
		if id.Origin != "" {
			ctx.ServiceAccountOrigin = id.Origin
		}
		if id.Token != "" {
			ctx.Token = id.Token
			ctx.TokenReason = id.TokenReason
		}

		if rbacState == RBACUnavailable {
			ctx.Status = IdentityRBACUnavailable
			ctx.Reason = withDefault(in.RBAC.Reason, "RBAC objects were not collected, so no escalation analysis ran")
			out = append(out, ctx)
			continue
		}

		ctx.ServiceAccountObject = ObjectAbsent
		if in.RBAC.Index.HasServiceAccount(subject.Namespace, subject.Name) {
			ctx.ServiceAccountObject = ObjectPresent
		}

		a, ok := cache[subject]
		if !ok {
			esc := in.RBAC.Index.AnalyzeEscalation(subject)
			a = analyzed{
				escalation:  &esc,
				permissions: summarize(esc, in.RBAC.Index.DirectRules(subject), rbacState),
			}
			cache[subject] = a
		}
		ctx.Escalation = a.escalation
		ctx.Permissions = a.permissions

		switch {
		case rbacState == RBACPartial:
			ctx.Status = IdentityRBACIncomplete
			ctx.Reason = withDefault(in.RBAC.Reason, "RBAC collection was partial; the analysis covers only the collected objects")
		case ctx.Token == TokenNotMounted:
			ctx.Status = IdentityTokenNotMounted
			ctx.Reason = "no ServiceAccount token is mounted according to the workload spec; the ServiceAccount's own analysis is attached because token status does not change what the ServiceAccount is authorized to do"
		default:
			ctx.Status = IdentityAnalyzed
		}
		out = append(out, ctx)
	}
	return out
}

func unresolvedReason(w vulnexposure.Workload, id WorkloadIdentity, resolved bool, given string) string {
	switch {
	case !resolved || id.ServiceAccountName == "":
		return withDefault(given, "no ServiceAccount binding was resolved for this workload")
	case id.Namespace != "" && id.Namespace != w.Namespace:
		return fmt.Sprintf("resolved ServiceAccount namespace %q differs from the workload's %q", id.Namespace, w.Namespace)
	}
	return ""
}

func withDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// summarize derives the PermissionSummary of one analysis. It is pure so the
// truncated and scope-unknown shapes can be exercised without a fixture the
// size of rbacgraph's hop budget.
func summarize(esc rbacgraph.EscalationResult, direct []rbacgraph.ScopedRule, state RBACState) *PermissionSummary {
	directKeys := make(map[string]bool, len(direct))
	for _, r := range direct {
		directKeys[ruleKey(r)] = true
	}
	gainedByKey := map[string]rbacgraph.ScopedRule{}
	for _, r := range esc.EffectiveRules {
		k := ruleKey(r)
		if !directKeys[k] {
			gainedByKey[k] = r
		}
	}
	keys := make([]string, 0, len(gainedByKey))
	for k := range gainedByKey {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	gained := make([]rbacgraph.ScopedRule, 0, len(keys))
	for _, k := range keys {
		gained = append(gained, gainedByKey[k])
	}

	s := &PermissionSummary{
		DirectRules:       direct,
		GainedRules:       gained,
		PermissionGain:    len(gained) > 0,
		IdentitiesReached: len(esc.Reached),
		Unbounded:         len(esc.Unbounded) > 0,
		ClusterAdmin:      esc.ClusterAdmin,
		Truncated:         esc.Truncated,
	}
	for _, u := range esc.Unbounded {
		if u.Edge.ScopeUnknown {
			s.ScopeUnknown = true
		}
	}
	s.NoAdditionalReachabilityFound = state == RBACComplete && !s.Truncated && !s.ClusterAdmin &&
		s.IdentitiesReached == 0 && !s.Unbounded
	return s
}

// ruleKey is a canonical, lossless identity of a ScopedRule. The slices of a
// PolicyRule are sets, so they are sorted; JSON keeps every element and
// boundary, unlike joining them into one string.
func ruleKey(r rbacgraph.ScopedRule) string {
	sorted := func(in []string) []string {
		out := slices.Clone(in)
		if out == nil {
			out = []string{}
		}
		slices.Sort(out)
		return out
	}
	b, _ := json.Marshal(struct {
		Namespace       string
		APIGroups       []string
		Resources       []string
		ResourceNames   []string
		Verbs           []string
		NonResourceURLs []string
	}{
		r.Namespace,
		sorted(r.Rule.APIGroups),
		sorted(r.Rule.Resources),
		sorted(r.Rule.ResourceNames),
		sorted(r.Rule.Verbs),
		sorted(r.Rule.NonResourceURLs),
	})
	return string(b)
}

// mergeVulnerabilities removes repeats of one vulnerability ID (the same CVE
// reported by several containers or manifests) without dropping distinct
// ones. A repeat keeps the highest severity any copy reports, by
// vulnexposure.ParseSeverity's ordering, and is fixable if any copy is, so the
// result does not depend on the order the copies arrived in. An unrecognized or
// empty severity never replaces a recognized one. The input is not modified,
// and the findings the tool reports elsewhere keep each source's own severity.
func mergeVulnerabilities(in []VulnerabilityRef) []VulnerabilityRef {
	byID := map[string]int{}
	out := make([]VulnerabilityRef, 0, len(in))
	for _, v := range in {
		i, ok := byID[v.ID]
		if !ok {
			byID[v.ID] = len(out)
			out = append(out, v)
			continue
		}
		out[i].FixAvailable = out[i].FixAvailable || v.FixAvailable
		out[i].Severity = higherSeverity(out[i].Severity, v.Severity)
	}
	slices.SortStableFunc(out, func(a, b VulnerabilityRef) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return out
}

// higherSeverity returns the more severe of two severity strings as they were
// reported. Equal ranks (including two unrecognized values) resolve to a
// non-empty value first, then to the lexicographically smaller one, so the
// choice never depends on argument order.
func higherSeverity(a, b string) string {
	ra, rb := vulnexposure.ParseSeverity(a), vulnexposure.ParseSeverity(b)
	switch {
	case ra > rb:
		return a
	case rb > ra:
		return b
	case a == "":
		return b
	case b == "":
		return a
	}
	return min(a, b)
}

func compareWorkloads(a, b vulnexposure.Workload) int {
	return cmp.Or(
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Name, b.Name),
	)
}
