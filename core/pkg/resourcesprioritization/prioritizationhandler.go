package resourcesprioritization

import (
	"context"
	"encoding/json"
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
)

type ResourcesPrioritizationHandler struct {
	resourceToAttackTracks map[string]v1alpha1.IAttackTrack
	attackTracks           []v1alpha1.IAttackTrack
	buildResourcesMap      bool
}

var supportedKinds = []string{
	"Deployment",
	"Pod",
	"ReplicaSet",
	"Node",
	"DaemonSet",
	"StatefulSet",
	"Job",
	"CronJob",
}

func NewResourcesPrioritizationHandler(ctx context.Context, attackTracksGetter getter.IAttackTracksGetter, buildResourcesMap bool) (*ResourcesPrioritizationHandler, error) {
	handler := &ResourcesPrioritizationHandler{
		attackTracks:           make([]v1alpha1.IAttackTrack, 0),
		resourceToAttackTracks: make(map[string]v1alpha1.IAttackTrack),
		buildResourcesMap:      buildResourcesMap,
	}

	tracks, err := attackTracksGetter.GetAttackTracks()
	if err != nil {
		return nil, err
	} else {
		for _, attackTrack := range tracks {
			if !attackTrack.IsValid() {
				return nil, fmt.Errorf("invalid attack track: %s", attackTrack.GetName())
			}

			t := attackTrack
			handler.attackTracks = append(handler.attackTracks, &t)
		}
	}

	if len(handler.attackTracks) == 0 {
		return nil, fmt.Errorf("expected to find at least one attack track")
	}

	// Store attack tracks in cache
	cache := getter.GetDefaultPath(cautils.LocalAttackTracksFilename)
	if err := getter.SaveInFile(tracks, cache); err != nil {
		logger.L().Ctx(ctx).Warning("failed to cache file", helpers.String("file", cache), helpers.Error(err))
	}

	return handler, nil
}

func (handler *ResourcesPrioritizationHandler) PrioritizeResources(sessionObj *cautils.OPASessionObj) error {
	if sessionObj.AllPolicies == nil {
		return fmt.Errorf("expected to find policies map")
	} else if len(sessionObj.AllPolicies.Controls) == 0 {
		return fmt.Errorf("expected to find controls in policies map")
	}
	allControls := make(map[string]v1alpha1.IAttackTrackControl, len(sessionObj.AllPolicies.Controls))
	for id := range sessionObj.AllPolicies.Controls {
		ctrl := sessionObj.AllPolicies.Controls[id]
		allControls[id] = &ctrl
	}

	for resourceId, result := range sessionObj.ResourcesResult {
		resourcePriorityVector := []prioritization.ControlsVector{}
		resource, exist := sessionObj.AllResources[resourceId]
		if !exist {
			continue
		}

		workload := workloadinterface.NewWorkloadObj(resource.GetObject())

		if workload != nil && handler.isSupportedKind(workload) {
			// build a map of attack track categories to a list of failed controls for the specific resource
			controlsIds := result.ListControlsIDs(nil)
			if controlsIds.Failed() > 0 {
				failedControls := controlsIds.GetItems(apis.StatusFailed)
				controlsLookup := v1alpha1.NewAttackTrackControlsLookup(handler.attackTracks, failedControls, allControls)
				replicaCount := workload.GetReplicas()

				for _, attackTrack := range handler.attackTracks {
					if !controlsLookup.HasAssociatedControls(attackTrack.GetName()) {
						continue
					}

					// Load the failed controls into the attack track
					allPathsHandler := v1alpha1.NewAttackTrackAllPathsHandler(attackTrack, &controlsLookup)

					// only build the map if the user requested it
					if handler.buildResourcesMap {
						// Store the attack track for returning to the caller
						handler.resourceToAttackTracks[resourceId] = handler.copyAttackTrack(attackTrack, &controlsLookup)
					}

					// Calculate all the paths for the attack track
					allAttackPaths := allPathsHandler.CalculateAllPaths()

					// Create priority vectors from every attack path
					controlsVectors := prioritization.ControlsVectorFromAttackTrackPaths(attackTrack, allAttackPaths)

					// Calculate the score and severity for every priority vector, and add it to the resource priority vector
					for _, controlsVector := range controlsVectors {
						if score, err := controlsVector.CalculateScore(allControls, replicaCount); err == nil {
							controlsVector.SetScore(score)
						} else {
							return err
						}

						if severity, err := controlsVector.CalculateSeverity(allControls); err == nil {
							controlsVector.SetSeverity(severity)
						} else {
							return err
						}

						resourcePriorityVector = append(resourcePriorityVector, controlsVector)
					}
				}
			}
		}

		// Resource priority vector is ready, add it to the session object
		prioritizedResource := prioritization.PrioritizedResource{
			ResourceID:     resourceId,
			PriorityVector: resourcePriorityVector,
		}

		prioritizedResource.SetSeverity(prioritizedResource.CalculateSeverity())
		prioritizedResource.SetScore(prioritizedResource.CalculateScore())

		if prioritizedResource.GetScore() == 0 {
			continue
		}

		sessionObj.ResourcesPrioritized[resourceId] = prioritizedResource
	}

	sessionObj.ResourceAttackTracks = handler.resourceToAttackTracks

	return nil
}

func (handler *ResourcesPrioritizationHandler) isSupportedKind(obj workloadinterface.IMetadata) bool {
	if obj != nil {
		for _, kind := range supportedKinds {
			if obj.GetKind() == kind {
				return true
			}
		}
	}
	return false
}

func (handler *ResourcesPrioritizationHandler) copyAttackTrack(attackTrack v1alpha1.IAttackTrack, lookup v1alpha1.IAttackTrackControlsLookup) v1alpha1.IAttackTrack {
	copyBytes, _ := json.Marshal(attackTrack)
	var copyObj v1alpha1.AttackTrack
	json.Unmarshal(copyBytes, &copyObj)

	iter := copyObj.Iterator()
	for iter.HasNext() {
		step := iter.Next()
		failedControls := lookup.GetAssociatedControls(copyObj.GetName(), step.GetName())
		step.SetControls(failedControls)
	}

	return &copyObj
}
