package getter

import (
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

func (g *MergedExceptionsGetter) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	if g == nil || g.primary == nil {
		return []armotypes.PostureExceptionPolicy{}, nil
	}

	exceptions, err := g.primary.GetExceptions(clusterName)
	if err != nil {
		return nil, err
	}

	if g.secondary == nil {
		return exceptions, nil
	}

	crdExceptions, err := g.secondary.GetExceptions(clusterName)
	if err != nil {
		// Secondary (CRD) failures must not break the scan, but a swallowed error hides
		// version skew or RBAC gaps; surface it at Warning so it is observable.
		logger.L().Warning("failed to get CRD security exceptions; continuing with primary exceptions only",
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

	covered := make(map[string]struct{}, len(cloudExceptions))
	for _, cloud := range cloudExceptions {
		for _, policy := range cloud.PosturePolicies {
			if policy.ControlID == "" {
				continue
			}
			for _, resource := range cloud.Resources {
				covered[exceptionDedupKey(policy.ControlID, resource)] = struct{}{}
			}
		}
	}

	merged := make([]armotypes.PostureExceptionPolicy, 0, len(cloudExceptions)+len(crdExceptions))
	merged = append(merged, cloudExceptions...)
	if len(crdExceptions) == 0 {
		return merged
	}

	for _, crd := range crdExceptions {
		// Exceptions without resolvable control+workload keys can't be deduped; keep them.
		if len(crd.Resources) == 0 || len(crd.PosturePolicies) == 0 {
			merged = append(merged, crd)
			continue
		}
		filteredResources := make([]identifiers.PortalDesignator, 0, len(crd.Resources))
		for _, resource := range crd.Resources {
			if !isResourceCovered(crd.PosturePolicies, resource, covered) {
				filteredResources = append(filteredResources, resource)
			}
		}
		if len(filteredResources) == 0 {
			continue
		}
		filteredPolicy := crd
		filteredPolicy.Resources = filteredResources
		merged = append(merged, filteredPolicy)
	}

	return merged
}

func isResourceCovered(
	policies []armotypes.PosturePolicy,
	resource identifiers.PortalDesignator,
	covered map[string]struct{},
) bool {
	for _, policy := range policies {
		if policy.ControlID == "" {
			continue
		}
		if _, found := covered[exceptionDedupKey(policy.ControlID, resource)]; found {
			return true
		}
	}
	return false
}

func exceptionDedupKey(controlID string, designator identifiers.PortalDesignator) string {
	apiGroup := ""
	if designator.Attributes != nil {
		apiGroup = designator.Attributes[identifiers.AttributeApiGroup]
	}
	return controlID + exceptionKeySeparator +
		designator.GetNamespace() + exceptionKeySeparator +
		designator.GetName() + exceptionKeySeparator +
		designator.GetKind() + exceptionKeySeparator +
		apiGroup
}
