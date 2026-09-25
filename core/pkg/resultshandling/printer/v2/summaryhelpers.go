package printer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type skippedControlInfo struct {
	controlID   string
	name        string
	description string
	remediation string
	scoreFactor float32
	reason      string
}

// buildSkipMessage constructs a human-readable skip reason from IStatus.
// It uses SubStatus (e.g. "configuration", "irrelevant") and appends Info when available.
func buildSkipMessage(status apis.IStatus) string {
	if status == nil {
		return ""
	}
	subStatus := strings.TrimSpace(string(status.GetSubStatus()))
	info := strings.TrimSpace(status.Info())
	if subStatus != "" && info != "" {
		return fmt.Sprintf("%s: %s", subStatus, info)
	}
	if info != "" {
		return info
	}
	return subStatus
}

// collectSkippedControls collects and sorts (by controlID) skipped and unevaluated controls
// and their diagnostic reasons from SummaryDetails.Controls, Frameworks, and ScanCoverage.NotEvaluatedControls.
func collectSkippedControls(opaSessionObj *cautils.OPASessionObj) []skippedControlInfo {
	if opaSessionObj == nil {
		return nil
	}

	skippedMap := make(map[string]skippedControlInfo)

	extractReason := func(status apis.IStatus) string {
		if status == nil {
			return ""
		}
		if status.GetSubStatus() == apis.SubStatusNotEvaluated {
			if info := strings.TrimSpace(status.Info()); info != "" {
				return info
			}
			return "not evaluated"
		}
		return buildSkipMessage(status)
	}

	if opaSessionObj.Report != nil {
		for _, ctl := range opaSessionObj.Report.SummaryDetails.Controls {
			if ctl.GetStatus() != nil && ctl.GetStatus().IsSkipped() {
				reason := extractReason(ctl.GetStatus())
				name := ctl.GetName()
				if name == "" {
					name = ctl.GetID()
				}
				skippedMap[ctl.GetID()] = skippedControlInfo{
					controlID:   ctl.GetID(),
					name:        name,
					description: ctl.GetDescription(),
					remediation: ctl.GetRemediation(),
					scoreFactor: ctl.GetScoreFactor(),
					reason:      reason,
				}
			}
		}

		if len(skippedMap) == 0 && len(opaSessionObj.Report.SummaryDetails.Frameworks) > 0 {
			for _, fw := range opaSessionObj.Report.SummaryDetails.Frameworks {
				for _, ctl := range fw.Controls {
					if ctl.GetStatus() != nil && ctl.GetStatus().IsSkipped() {
						if _, exists := skippedMap[ctl.GetID()]; !exists {
							reason := extractReason(ctl.GetStatus())
							name := ctl.GetName()
							if name == "" {
								name = ctl.GetID()
							}
							skippedMap[ctl.GetID()] = skippedControlInfo{
								controlID:   ctl.GetID(),
								name:        name,
								description: ctl.GetDescription(),
								remediation: ctl.GetRemediation(),
								scoreFactor: ctl.GetScoreFactor(),
								reason:      reason,
							}
						}
					}
				}
			}
		}
	}

	for _, nec := range opaSessionObj.ScanCoverage.NotEvaluatedControls {
		reason := nec.ReasonString()
		if reason == "" {
			reason = "not evaluated"
		}
		if existing, exists := skippedMap[nec.ControlID]; exists {
			if existing.reason == "" || existing.reason == "not evaluated" || existing.reason == "skipped" {
				existing.reason = reason
				skippedMap[nec.ControlID] = existing
			}
		} else {
			name := nec.ControlID
			var desc, rem string
			var score float32
			if opaSessionObj.AllPolicies != nil {
				if pCtrl, ok := opaSessionObj.AllPolicies.Controls[nec.ControlID]; ok {
					if pCtrl.Name != "" {
						name = pCtrl.Name
					}
					desc = pCtrl.Description
					rem = pCtrl.Remediation
					score = pCtrl.BaseScore
				}
			}
			if (name == nec.ControlID || score == 0) && opaSessionObj.Report != nil {
				if ctrl := opaSessionObj.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, nec.ControlID); ctrl != nil {
					if name == nec.ControlID && ctrl.GetName() != "" {
						name = ctrl.GetName()
					}
					if desc == "" {
						desc = ctrl.GetDescription()
					}
					if rem == "" {
						rem = ctrl.GetRemediation()
					}
					if score == 0 {
						score = ctrl.GetScoreFactor()
					}
				}
			}
			skippedMap[nec.ControlID] = skippedControlInfo{
				controlID:   nec.ControlID,
				name:        name,
				description: desc,
				remediation: rem,
				scoreFactor: score,
				reason:      reason,
			}
		}
	}

	results := make([]skippedControlInfo, 0, len(skippedMap))
	for _, info := range skippedMap {
		results = append(results, info)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].controlID < results[j].controlID
	})
	return results
}

type WorkloadSummary struct {
	resource            workloadinterface.IMetadata
	status              apis.ScanningStatus
	assistedRemediation string
}

func workloadSummaryFailed(workloadSummary *WorkloadSummary) bool {
	return workloadSummary.status == apis.StatusFailed
}

func workloadSummaryPassed(workloadSummary *WorkloadSummary) bool {
	return workloadSummary.status == apis.StatusPassed
}

func workloadSummarySkipped(workloadSummary *WorkloadSummary) bool {
	return workloadSummary.status == apis.StatusSkipped
}

// Group workloads by namespace - return {"namespace": <[]WorkloadSummary>}
func groupByNamespaceOrKind(resources []WorkloadSummary, status func(workloadSummary *WorkloadSummary) bool) map[string][]WorkloadSummary {
	mapResources := make(map[string][]WorkloadSummary)
	for i := range resources {
		if !status(&resources[i]) {
			continue
		}
		t := resources[i].resource.GetObjectType()
		if t == objectsenvelopes.TypeRegoResponseVectorObject && !isKindToBeGrouped(resources[i].resource.GetKind()) {
			t = workloadinterface.TypeWorkloadObject
		}
		group := groupKey(resources[i].resource, t)
		mapResources[group] = append(mapResources[group], resources[i])
	}
	return mapResources
}

func groupKey(resource workloadinterface.IMetadata, t workloadinterface.ObjectType) string {
	switch t {
	case workloadinterface.TypeWorkloadObject:
		if resource.GetNamespace() != "" {
			return "Namespace " + resource.GetNamespace()
		}
	case objectsenvelopes.TypeRegoResponseVectorObject:
		return resource.GetKind() + "s"
	default:
		group, _ := k8sinterface.SplitApiVersion(resource.GetApiVersion())
		return group
	}
	return ""
}

func isKindToBeGrouped(kind string) bool {
	if kind == "Group" || kind == "User" {
		return true
	}
	return false
}

func listResultSummary(controlSummary reportsummary.IControlSummary, allResources map[string]workloadinterface.IMetadata) []WorkloadSummary {
	return listResultSummaryFromCatalog(controlSummary, cautils.NewMapResourceCatalog(allResources))
}

func listResultSummaryFromCatalog(controlSummary reportsummary.IControlSummary, catalog cautils.ResourceCatalog) []WorkloadSummary {
	resourceIds := helpersv1.GetAllListsFromPool()
	defer helpersv1.PutAllListsToPool(resourceIds)

	resourceIds = controlSummary.ListResourcesIDs(resourceIds)
	workloadsSummary := make([]WorkloadSummary, 0, resourceIds.Len())
	for rId, status := range resourceIds.All() {
		if status == apis.StatusUnknown {
			continue
		}

		if catalog != nil {
			if r, ok := catalog.Get(rId); ok && r != nil {
				workloadsSummary = append(workloadsSummary, WorkloadSummary{
					resource: r,
					status:   status,
				})
			}
		}
	}

	return workloadsSummary
}
