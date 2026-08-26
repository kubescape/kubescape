package getter

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const exceptionKeySeparator = "/"

var _ IExceptionsGetter = &MergedExceptionsGetter{}

// MergedExceptionsGetter combines exceptions from a primary source and a secondary source.
// Primary source failures are returned as errors; secondary source failures are logged and ignored.
type MergedExceptionsGetter struct {
	primary   IExceptionsGetter
	secondary IExceptionsGetter
}

func NewMergedExceptionsGetter(primary, secondary IExceptionsGetter) *MergedExceptionsGetter {
	return &MergedExceptionsGetter{primary: primary, secondary: secondary}
}

func (g *MergedExceptionsGetter) GetExceptions(ctx context.Context, clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	if g == nil || g.primary == nil {
		return []armotypes.PostureExceptionPolicy{}, nil
	}

	exceptions, err := g.primary.GetExceptions(ctx, clusterName)
	if err != nil {
		return nil, err
	}

	if g.secondary == nil {
		return exceptions, nil
	}

	crdExceptions, err := g.secondary.GetExceptions(ctx, clusterName)
	if err != nil {
		if isContextErr(err) {
			return nil, err
		}
		// Secondary (CRD) failures must not break the scan, but a swallowed error hides
		// version skew or RBAC gaps; surface it at Warning so it is observable.
		logger.L().Ctx(ctx).Warning("failed to get CRD security exceptions; continuing with primary exceptions only",
			helpers.Error(err))
		return exceptions, nil
	}

	if len(crdExceptions) == 0 {
		return exceptions, nil
	}

	return deduplicateExceptions(exceptions, crdExceptions), nil
}

// deduplicateExceptions enforces the design review's precedence rule: cloud/file
// (primary) exceptions are added first, and a CRD exception is appended only for the
// control+workload designators not already covered by a primary exception. Partial
// overlaps keep the non-overlapping designators of the CRD exception.
func deduplicateExceptions(
	cloudExceptions []armotypes.PostureExceptionPolicy,
	crdExceptions []armotypes.PostureExceptionPolicy,
) []armotypes.PostureExceptionPolicy {
	if len(cloudExceptions) == 0 && len(crdExceptions) == 0 {
		return []armotypes.PostureExceptionPolicy{}
	}

	merged := make([]armotypes.PostureExceptionPolicy, 0, len(cloudExceptions)+len(crdExceptions))
	merged = append(merged, cloudExceptions...)
	if len(crdExceptions) == 0 {
		return merged
	}

	covered, global := coveredPostureScopes(cloudExceptions)
	matcher := newScopeMatcher()

	for _, crd := range crdExceptions {
		// Exceptions without resolvable control+workload keys can't be deduped; keep them.
		if len(crd.Resources) == 0 || len(crd.PosturePolicies) == 0 {
			merged = append(merged, crd)
			continue
		}

		for _, policy := range crd.PosturePolicies {
			if matcher.coveredBy(global, policy) {
				// A cloud exception with no Resources at all applies with no scope
				// constraint - the same convention hasExplicitControlException uses
				// for manual controls - so it already covers this policy everywhere
				// and fully subsumes the CRD policy, not just designators it happens
				// to share a resource key with.
				continue
			}
			filteredResources := make([]identifiers.PortalDesignator, 0, len(crd.Resources))
			for _, resource := range crd.Resources {
				if !matcher.coveredBy(covered[designatorDedupKey(resource)], policy) {
					filteredResources = append(filteredResources, resource)
				}
			}
			if len(filteredResources) == 0 {
				continue
			}
			filteredPolicy := crd
			filteredPolicy.Resources = filteredResources
			filteredPolicy.PosturePolicies = []armotypes.PosturePolicy{policy}
			merged = append(merged, filteredPolicy)
		}
	}

	return merged
}

// coveredPostureScopes indexes the primary posture-policy scopes by workload
// designator, and separately collects policies from a primary exception that has
// no Resources at all into global. Such an exception applies with no scope
// constraint - the same convention hasExplicitControlException already uses for
// manual controls - so it covers every designator for a matching control/framework/
// rule scope, not just one indexed by a specific resource key. A policy without a
// control ID carries nothing to measure a CRD policy against, so it never
// suppresses one.
func coveredPostureScopes(exceptions []armotypes.PostureExceptionPolicy) (covered map[string][]armotypes.PosturePolicy, global []armotypes.PosturePolicy) {
	covered = make(map[string][]armotypes.PosturePolicy, len(exceptions))
	for _, exception := range exceptions {
		for _, policy := range exception.PosturePolicies {
			if policy.ControlID == "" {
				continue
			}
			if len(exception.Resources) == 0 {
				if !slices.Contains(global, policy) {
					global = append(global, policy)
				}
				continue
			}
			for _, resource := range exception.Resources {
				key := designatorDedupKey(resource)
				if !slices.Contains(covered[key], policy) {
					covered[key] = append(covered[key], policy)
				}
			}
		}
	}
	return covered, global
}

// scopeMatcher compares posture-policy scopes the way the exception processor does
// at evaluation time: a case-insensitive literal or anchored case-insensitive
// pattern. Compiled patterns are reused across the whole merge.
type scopeMatcher struct {
	patterns map[string]*regexp.Regexp
}

func newScopeMatcher() *scopeMatcher {
	return &scopeMatcher{patterns: make(map[string]*regexp.Regexp)}
}

// coveredBy reports whether any primary scope already applies everywhere policy does.
// A primary exception that does not reach the CRD policy's framework or rule cannot
// take precedence over it.
func (m *scopeMatcher) coveredBy(primaries []armotypes.PosturePolicy, policy armotypes.PosturePolicy) bool {
	for _, primary := range primaries {
		if m.covers(primary.FrameworkName, policy.FrameworkName) &&
			m.covers(primary.ControlID, policy.ControlID) &&
			m.covers(primary.RuleName, policy.RuleName) {
			return true
		}
	}
	return false
}

// covers reports whether a primary scope field applies wherever the CRD one does. An
// empty primary field is unscoped and covers any value; a named one cannot cover an
// empty CRD field, which is broader.
func (m *scopeMatcher) covers(primary, crd string) bool {
	if primary == "" {
		return true
	}
	if crd == "" {
		return false
	}
	if strings.EqualFold(primary, crd) {
		return true
	}
	pattern, compiled := m.patterns[primary]
	if !compiled {
		// A pattern that does not compile is cached as nil and read as a
		// non-match, which is how the exception processor treats it.
		pattern, _ = regexp.Compile("(?i)^" + primary + "$")
		m.patterns[primary] = pattern
	}
	return pattern != nil && pattern.MatchString(crd)
}

func designatorDedupKey(designator identifiers.PortalDesignator) string {
	apiGroup := ""
	if designator.Attributes != nil {
		apiGroup = designator.Attributes[identifiers.AttributeApiGroup]
	}
	return strings.Join([]string{
		designator.GetNamespace(),
		designator.GetName(),
		designator.GetKind(),
		apiGroup,
	}, exceptionKeySeparator)
}
