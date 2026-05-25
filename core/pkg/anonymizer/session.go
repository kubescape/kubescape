package anonymizer

import (
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

// anonymizeSession rewrites sensitive resource identifiers and metadata while
// preserving internal referential integrity across the full OPA session.
func anonymizeSession(session *cautils.OPASessionObj, mapping *Mapping) {
	if session == nil {
		return
	}

	idMapping := make(map[string]string)

	newAllResources := make(map[string]workloadinterface.IMetadata, len(session.AllResources))
	for oldID, resource := range session.AllResources {
		if name := resource.GetName(); name != "" {
			resource.SetName(mapping.GetOrCreate("res", name))
		}

		if namespace := resource.GetNamespace(); namespace != "" {
			resource.SetNamespace(mapping.GetOrCreate("ns", namespace))
		}

		// Annotations may contain infrastructure identifiers, secret paths, or
		// other sensitive metadata at both top-level and nested workload templates.
		anonymizeResourceAnnotations(resource, mapping)

		// Container-related anonymization is handled separately to preserve the
		// existing typed/unstructured traversal behavior.
		anonymizeContainerMetadata(resource, mapping)

		if len(session.LabelsToCopy) > 0 {
			anonymizeResourceLabels(resource, session.LabelsToCopy, mapping)
		}

		newID := resource.GetID()
		idMapping[oldID] = newID
		newAllResources[newID] = resource
	}
	session.AllResources = newAllResources

	newResourcesResult := make(map[string]resourcesresults.Result, len(session.ResourcesResult))
	for oldID, result := range session.ResourcesResult {
		newID := resolveMappedID(mapping, idMapping, oldID, "ref")
		result.ResourceID = newID

		if result.PrioritizedResource != nil {
			result.PrioritizedResource.ResourceID = newID
		}

		for controlIndex := range result.AssociatedControls {
			for ruleIndex := range result.AssociatedControls[controlIndex].ResourceAssociatedRules {
				rule := &result.AssociatedControls[controlIndex].ResourceAssociatedRules[ruleIndex]

				for pathIndex := range rule.Paths {
					rule.Paths[pathIndex].ResourceID = resolveMappedID(
						mapping,
						idMapping,
						rule.Paths[pathIndex].ResourceID,
						"ref",
					)
				}

				for relatedIndex := range rule.RelatedResourcesIDs {
					rule.RelatedResourcesIDs[relatedIndex] = resolveMappedID(
						mapping,
						idMapping,
						rule.RelatedResourcesIDs[relatedIndex],
						"ref",
					)
				}
			}
		}

		newResourcesResult[newID] = result
	}
	session.ResourcesResult = newResourcesResult

	newResourceSource := make(map[string]reporthandling.Source, len(session.ResourceSource))
	for oldID, source := range session.ResourceSource {
		newID := resolveMappedID(mapping, idMapping, oldID, "ref")
		newResourceSource[newID] = source
	}
	session.ResourceSource = newResourceSource

	newResourcesPrioritized := make(map[string]prioritization.PrioritizedResource, len(session.ResourcesPrioritized))
	for oldID, prioritized := range session.ResourcesPrioritized {
		newID := resolveMappedID(mapping, idMapping, oldID, "ref")
		prioritized.ResourceID = newID
		newResourcesPrioritized[newID] = prioritized
	}
	session.ResourcesPrioritized = newResourcesPrioritized

	newResourceAttackTracks := make(map[string]v1alpha1.IAttackTrack, len(session.ResourceAttackTracks))
	for oldID, attackTrack := range session.ResourceAttackTracks {
		newID := resolveMappedID(mapping, idMapping, oldID, "ref")
		newResourceAttackTracks[newID] = attackTrack
	}
	session.ResourceAttackTracks = newResourceAttackTracks

	if session.Report != nil {
		for controlID, control := range session.Report.SummaryDetails.Controls {
			remappedResourceIDs := control.ResourceIDs

			originalResourceIDs := make(map[string]apis.ScanningStatus, len(control.ResourceIDs.All()))
			for resourceID, status := range control.ResourceIDs.All() {
				originalResourceIDs[resourceID] = status
			}

			remappedResourceIDs.Clear()

			for oldID, status := range originalResourceIDs {
				newID := resolveMappedID(mapping, idMapping, oldID, "ref")
				remappedResourceIDs.Append(status, newID)
			}

			control.ResourceIDs = remappedResourceIDs
			session.Report.SummaryDetails.Controls[controlID] = control
		}
	}
}

// resolveMappedID preserves referential integrity when IDs are rewritten during
// anonymization, ensuring cross-references remain valid.
func resolveMappedID(mapping *Mapping, idMapping map[string]string, originalID, prefix string) string {
	if mappedID, ok := idMapping[originalID]; ok {
		return mappedID
	}

	return mapping.GetOrCreate(prefix, originalID)
}

// anonymizeResourceLabels anonymizes only labels explicitly configured for
// copying into reports, preserving existing --hide behavior.
func anonymizeResourceLabels(resource workloadinterface.IMetadata, labelsToCopy []string, mapping *Mapping) {
	bw, ok := resource.(workloadinterface.IWorkload)
	if !ok {
		return
	}

	labels := bw.GetLabels()
	if len(labels) == 0 {
		return
	}

	for _, key := range labelsToCopy {
		if val, exists := labels[key]; exists && val != "" {
			bw.SetLabel(key, mapping.GetOrCreate("lbl", val))
		}
	}
}

// anonymizeResourceAnnotations walks the full resource object and anonymizes
// annotation values anywhere metadata.annotations appears, including nested
// workload templates such as Deployment pod specs.
func anonymizeResourceAnnotations(resource workloadinterface.IMetadata, mapping *Mapping) {
	if resource == nil {
		return
	}

	obj := resource.GetObject()
	if obj == nil {
		return
	}

	anonymizeAnnotationNodes(obj, mapping)
	resource.SetObject(obj)
}

// anonymizeAnnotationNodes recursively traverses unstructured resource objects
// to locate metadata blocks regardless of workload nesting depth.
func anonymizeAnnotationNodes(node interface{}, mapping *Mapping) {
	switch v := node.(type) {
	case map[string]interface{}:
		anonymizeAnnotationMap(v, mapping)

		for _, child := range v {
			anonymizeAnnotationNodes(child, mapping)
		}

	case []interface{}:
		for _, item := range v {
			anonymizeAnnotationNodes(item, mapping)
		}
	}
}

// anonymizeAnnotationMap anonymizes string annotation values while preserving
// annotation keys, which remain meaningful Kubernetes identifiers.
func anonymizeAnnotationMap(obj map[string]interface{}, mapping *Mapping) {
	rawMetadata, ok := obj["metadata"]
	if !ok || rawMetadata == nil {
		return
	}

	metadata, ok := rawMetadata.(map[string]interface{})
	if !ok {
		return
	}

	rawAnnotations, ok := metadata["annotations"]
	if !ok || rawAnnotations == nil {
		return
	}

	annotations, ok := rawAnnotations.(map[string]interface{})
	if !ok {
		return
	}

	for key, val := range annotations {
		str, ok := val.(string)
		if !ok || str == "" {
			continue
		}

		annotations[key] = mapping.GetOrCreate("ann", str)
	}
}