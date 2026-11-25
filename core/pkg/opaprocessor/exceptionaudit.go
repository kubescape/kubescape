package opaprocessor

import (
	"reflect"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	exceptionAuditStatusExpired        = "expired"
	exceptionAuditStatusInvalidControl = "invalid-control"
	exceptionAuditStatusMatched        = "matched"
	exceptionAuditStatusUnused         = "unused"
)

func buildExceptionAudit(
	loadedExceptions []armotypes.PostureExceptionPolicy,
	activeExceptions []armotypes.PostureExceptionPolicy,
	results map[string]resourcesresults.Result,
	catalog cautils.ResourceCatalog,
	policies *cautils.Policies,
	processor *exceptions.Processor,
	manualControlMatches []manualControlExceptionMatch,
	summary *reportsummary.SummaryDetails,
) *cautils.ExceptionAudit {
	items := make(map[string]*cautils.ExceptionAuditItem, len(loadedExceptions))
	active := make(map[string]struct{}, len(activeExceptions))
	// sources groups the distinct exceptions sharing an exceptionAuditKey. Exceptions
	// without a GUID (local files, SecurityException CRDs) are keyed by name, which is
	// not unique, so each distinct one gets its own item.
	sources := make(map[string][]exceptionAuditSource, len(loadedExceptions))

	add := func(exception armotypes.PostureExceptionPolicy) string {
		key := exceptionAuditKey(exception)
		id := key
		if n := len(sources[key]); n > 0 {
			// "\x00" sorts first, keeping same-named items together.
			id = key + "\x00" + strconv.Itoa(n)
		}
		sources[key] = append(sources[key], exceptionAuditSource{id: id, exception: exception})
		item := exceptionAuditItem(exception, policies, processor)
		items[id] = &item
		return id
	}
	// resolve returns the item of the loaded exception that exception was derived from.
	resolve := func(exception armotypes.PostureExceptionPolicy) string {
		candidates := sources[exceptionAuditKey(exception)]
		if len(candidates) == 1 {
			return candidates[0].id
		}
		for _, candidate := range candidates {
			if exceptionDerivedFrom(exception, candidate.exception) {
				return candidate.id
			}
		}
		return add(exception)
	}

	for _, exception := range loadedExceptions {
		key := exceptionAuditKey(exception)
		if exception.GUID != "" && len(sources[key]) > 0 {
			continue
		}
		if slices.ContainsFunc(sources[key], func(s exceptionAuditSource) bool { return reflect.DeepEqual(s.exception, exception) }) {
			continue
		}
		add(exception)
	}

	for _, exception := range activeExceptions {
		active[resolve(exception)] = struct{}{}
	}

	for resourceID, result := range results {
		var resource workloadinterface.IMetadata
		if catalog != nil {
			resource, _ = catalog.Get(resourceID)
		}
		for _, control := range result.AssociatedControls {
			controlID := control.GetID()
			for _, rule := range control.ResourceAssociatedRules {
				for _, exception := range rule.Exception {
					// Match with framework context, but retain the original policy's
					// identity and tuples in the audit entry.
					if len(exceptions.FilterExceptionsByFrameworks([]armotypes.PostureExceptionPolicy{exception}, cautils.ControlFilters(summary, controlID).FrameworkNames, controlID, rule.GetName())) == 0 {
						continue
					}
					key := resolve(exception)
					items[key].MatchCount++
					items[key].MatchedResources = append(items[key].MatchedResources, exceptionAuditMatch(resourceID, controlID, rule.GetName(), resource))
				}
			}
		}
	}

	// Manual controls never appear in results (they have no resourcesresults.Result
	// entries at all), so without this an exception that only suppresses a manual
	// control is reported as unused even though it is actively applied.
	for _, match := range manualControlMatches {
		key := resolve(match.exception)
		items[key].MatchCount++
		items[key].MatchedResources = append(items[key].MatchedResources, cautils.ExceptionAuditMatch{ControlID: match.controlID})
	}

	audit := &cautils.ExceptionAudit{
		Generated: true,
		Items:     make([]cautils.ExceptionAuditItem, 0, len(items)),
	}

	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	audit.Summary.Total = len(keys)
	for _, key := range keys {
		item := items[key]
		if _, ok := active[key]; ok {
			audit.Summary.Active++
		}
		if item.Expired {
			item.Status = exceptionAuditStatusExpired
			audit.Summary.Expired++
		} else if len(item.InvalidControls) > 0 {
			item.Status = exceptionAuditStatusInvalidControl
			audit.Summary.InvalidControl++
		} else if item.MatchCount > 0 {
			item.Status = exceptionAuditStatusMatched
			audit.Summary.Matched++
		} else {
			item.Status = exceptionAuditStatusUnused
			audit.Summary.Unused++
		}
		sort.Strings(item.ControlIDs)
		sort.Strings(item.InvalidControls)
		sort.Slice(item.MatchedResources, func(i, j int) bool {
			if item.MatchedResources[i].ResourceID == item.MatchedResources[j].ResourceID {
				if item.MatchedResources[i].ControlID == item.MatchedResources[j].ControlID {
					return item.MatchedResources[i].RuleName < item.MatchedResources[j].RuleName
				}
				return item.MatchedResources[i].ControlID < item.MatchedResources[j].ControlID
			}
			return item.MatchedResources[i].ResourceID < item.MatchedResources[j].ResourceID
		})
		audit.Items = append(audit.Items, *item)
	}

	return audit
}

func exceptionAuditItem(exception armotypes.PostureExceptionPolicy, policies *cautils.Policies, processor *exceptions.Processor) cautils.ExceptionAuditItem {
	item := cautils.ExceptionAuditItem{
		Name:       exceptionAuditName(exception),
		Expired:    exceptionIsExpired(exception),
		ControlIDs: exceptionControlIDs(exception),
	}
	item.InvalidControls = invalidExceptionControls(item.ControlIDs, policies, processor)
	return item
}

func exceptionAuditKey(exception armotypes.PostureExceptionPolicy) string {
	if exception.GUID != "" {
		return exception.GUID
	}
	return exceptionAuditName(exception)
}

type exceptionAuditSource struct {
	id        string
	exception armotypes.PostureExceptionPolicy
}

// exceptionDerivedFrom reports whether match, an exception copy attached to a rule
// result, came from loaded. The exceptions processor narrows PosturePolicies to the
// ones matching the rule, and resourceScopedExceptions gives scope-less exceptions a
// resource designator; every other field is copied unchanged.
func exceptionDerivedFrom(match, loaded armotypes.PostureExceptionPolicy) bool {
	if len(loaded.Resources) > 0 && !reflect.DeepEqual(match.Resources, loaded.Resources) {
		return false
	}
	for _, policy := range match.PosturePolicies {
		if !slices.ContainsFunc(loaded.PosturePolicies, func(p armotypes.PosturePolicy) bool { return reflect.DeepEqual(p, policy) }) {
			return false
		}
	}
	match.Resources, loaded.Resources = nil, nil
	match.PosturePolicies, loaded.PosturePolicies = nil, nil
	return reflect.DeepEqual(match, loaded)
}

func exceptionAuditName(exception armotypes.PostureExceptionPolicy) string {
	if exception.Name != "" {
		return exception.Name
	}
	return exception.GetName()
}

func exceptionIsExpired(exception armotypes.PostureExceptionPolicy) bool {
	return exception.ExpirationDate != nil && !exception.ExpirationDate.After(time.Now())
}

func exceptionControlIDs(exception armotypes.PostureExceptionPolicy) []string {
	seen := map[string]struct{}{}
	var controlIDs []string
	for _, posturePolicy := range exception.PosturePolicies {
		if posturePolicy.ControlID == "" {
			continue
		}
		if _, ok := seen[posturePolicy.ControlID]; ok {
			continue
		}
		seen[posturePolicy.ControlID] = struct{}{}
		controlIDs = append(controlIDs, posturePolicy.ControlID)
	}
	return controlIDs
}

func invalidExceptionControls(controlIDs []string, policies *cautils.Policies, processor *exceptions.Processor) []string {
	if len(controlIDs) == 0 || policies == nil || len(policies.Controls) == 0 {
		return nil
	}
	if processor == nil {
		processor = exceptions.NewProcessor()
	}

	var invalid []string
	for _, controlID := range controlIDs {
		found := false
		for existingID := range policies.Controls {
			if processor.RegexCompareControlID(controlID, existingID) {
				found = true
				break
			}
		}
		if !found {
			invalid = append(invalid, controlID)
		}
	}
	return invalid
}

func exceptionAuditMatch(resourceID, controlID, ruleName string, resource workloadinterface.IMetadata) cautils.ExceptionAuditMatch {
	match := cautils.ExceptionAuditMatch{
		ResourceID: resourceID,
		ControlID:  controlID,
		RuleName:   ruleName,
	}
	if resource == nil {
		return match
	}
	match.Kind = resource.GetKind()
	match.Namespace = resource.GetNamespace()
	match.Name = resource.GetName()
	return match
}
