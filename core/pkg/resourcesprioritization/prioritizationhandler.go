package resourcesprioritization

import (
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
)

type ResourcesPrioritizationHandler struct {
	skipZeroScores bool
}

func NewResourcesPrioritizationHandler(skipZeroScore bool) *ResourcesPrioritizationHandler {
	return &ResourcesPrioritizationHandler{
		skipZeroScores: skipZeroScore,
	}
}

func (handler *ResourcesPrioritizationHandler) PrioritizeResources(sessionObj *cautils.OPASessionObj) error {
	for resourceId, result := range sessionObj.ResourcesResult {
		resourcePriorityVector := []prioritization.ControlsVector{}
		resource, exist := sessionObj.AllResources[resourceId]
		if !exist {
			return fmt.Errorf("expected to find resource id '%s' in scanned resources map", resourceId)
		}

		workload := workloadinterface.NewWorkloadObj(resource.GetObject())

		if workload != nil && handler.isSupportedKind(workload) {
			for _, resourceAssociatedControl := range result.ListControls() {
				if !resourceAssociatedControl.GetStatus(nil).IsFailed() {
					continue
				}

				controlSummary := sessionObj.Report.SummaryDetails.Controls.GetControl("ID", resourceAssociatedControl.ControlID)
				if controlSummary == nil {
					return fmt.Errorf("expected to find control id '%s' in summary details", resourceAssociatedControl.ControlID)
				}

				controlScoreFactor := controlSummary.GetScoreFactor()
				replicaCount := float64(workload.GetReplicas())

				cVector := prioritization.NewControlsVector()
				cVector.AddControl(prioritization.PriorityVectorControl{
					ControlID: resourceAssociatedControl.ControlID,
					Category:  "",
				})

				cVector.SetSeverity(apis.ControlSeverityToInt(controlScoreFactor))
				cVector.SetScore(float64(controlScoreFactor) + (replicaCount / 10))
				resourcePriorityVector = append(resourcePriorityVector, *cVector)
			}
		}

		prioritizedResource := prioritization.PrioritizedResource{
			ResourceID:     resourceId,
			PriorityVector: resourcePriorityVector,
		}

		prioritizedResource.SetSeverity(prioritizedResource.CalculateSeverity())
		prioritizedResource.SetScore(prioritizedResource.CalculateScore())

		if handler.skipZeroScores && prioritizedResource.GetScore() == 0 {
			continue
		}

		sessionObj.ResourcesPrioritized[resourceId] = prioritizedResource
	}

	return nil
}

func (handler *ResourcesPrioritizationHandler) isSupportedKind(obj workloadinterface.IMetadata) bool {
	if obj != nil {
		switch obj.GetKind() {
		case "Deployment",
			"Pod",
			"ReplicaSet",
			"Node",
			"DaemonSet",
			"StatefulSet",
			"Job",
			"CronJob":
			return true
		}
	}
	return false
}
