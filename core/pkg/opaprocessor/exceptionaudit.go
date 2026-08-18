package opaprocessor

import (
	"sort"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/exceptions"
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
	allResources map[string]workloadinterface.IMetadata,
	policies *cautils.Policies,
	processor *exceptions.Processor,
) *cautils.ExceptionAudit {
	items := make(map[string]*cautils.ExceptionAuditItem, len(loadedExceptions))
	active := make(map[string]struct{}, len(activeExceptions))

	for _, exception := range loadedExceptions {
		key := exceptionAuditKey(exception)
		item := exceptionAuditItem(exception, policies, processor)
		items[key] = &item
	}

	for _, exception := range activeExceptions {
		active[exceptionAuditKey(exception)] = struct{}{}
	}

	for resourceID, result := range results {
		resource := allResources[resourceID]
		for _, control := range result.AssociatedControls {
			controlID := control.GetID()
			for _, rule := range control.ResourceAssociatedRules {
				for _, exception := range rule.Exception {
					key := exceptionAuditKey(exception)
					if _, ok := items[key]; !ok {
						item := exceptionAuditItem(exception, policies, processor)
						items[key] = &item
					}
					items[key].MatchCount++
					items[key].MatchedResources = append(items[key].MatchedResources, exceptionAuditMatch(resourceID, controlID, rule.GetName(), resource))
				}
			}
		}
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
