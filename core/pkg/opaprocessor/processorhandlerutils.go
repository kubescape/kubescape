package opaprocessor

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	resources "github.com/kubescape/opa-utils/resources"
	"go.opentelemetry.io/otel"
	corev1 "k8s.io/api/core/v1"
)

// updateResults updates the results objects and report objects. This is a critical function - DO NOT CHANGE
//
// The function:
//   - removes sensible data
//   - adds exceptions (and updates controls status)
//   - summarizes results
func (opap *OPAProcessor) updateResults(ctx context.Context) {
	_, span := otel.Tracer("").Start(ctx, "OPAProcessor.updateResults")
	defer span.End()
	defer logger.L().Ctx(ctx).Success("Done aggregating results")

	cautils.StartSpinner()
	defer cautils.StopSpinner()

	// remove data from all objects
	for i := range opap.AllResources {
		removeData(opap.AllResources[i])
	}

	processor := exceptions.NewProcessor()
	loadedExceptions := append([]armotypes.PostureExceptionPolicy(nil), opap.Exceptions...)

	// filter expired exceptions before applying them
	opap.Exceptions = filterExpiredExceptions(opap.Exceptions)

	// set exceptions
	for i := range opap.ResourcesResult {
		t := opap.ResourcesResult[i]

		// first set exceptions (reuse the same exceptions processor)
		if resource, ok := opap.AllResources[i]; ok {
			t.SetExceptions(
				resource,
				opap.Exceptions,
				opap.clusterName,
				opap.AllPolicies.Controls, // update status depending on action required
				resourcesresults.WithExceptionsProcessor(processor),
			)
			opap.emitExceptionMatchEvents(resource, t)
		}

		// summarize the resources
		opap.Report.AppendResourceResultToSummary(&t)

		// save changes
		opap.ResourcesResult[i] = t
	}

	// manual controls have no resource results, so exceptions must be applied directly on the summary.
	applyExceptionsToManualControls(&opap.Report.SummaryDetails, opap.Exceptions, opap.clusterName, processor)

	// set result summary
	// map control to error
	controlToInfoMap := mapControlToInfo(opap.ResourceToControlsMap, opap.InfoMap, opap.Report.SummaryDetails.Controls)
	opap.Report.SummaryDetails.InitResourcesSummary(controlToInfoMap)

	if opap.AuditExceptions {
		opap.ExceptionAudit = buildExceptionAudit(loadedExceptions, opap.Exceptions, opap.ResourcesResult, opap.AllResources, opap.AllPolicies, processor)
	}
}

// applyExceptionsToManualControls marks manual controls as passed+w/exceptions when
// an explicit exception exists for them. Updates both the top-level and per-framework
// control maps since manual controls produce no resource results for the normal exception loop.
func applyExceptionsToManualControls(
	summaryDetails *reportsummary.SummaryDetails,
	exceptionPolicies []armotypes.PostureExceptionPolicy,
	clusterName string,
	processor *exceptions.Processor,
) {
	if len(exceptionPolicies) == 0 {
		return
	}

	applyExceptionsToControlSummaries(summaryDetails.Controls, exceptionPolicies, clusterName, processor)

	for i := range summaryDetails.Frameworks {
		applyExceptionsToControlSummaries(summaryDetails.Frameworks[i].Controls, exceptionPolicies, clusterName, processor)
	}
}

// applyExceptionsToControlSummaries updates manual controls in a single ControlSummaries map.
func applyExceptionsToControlSummaries(
	controlSummaries reportsummary.ControlSummaries,
	exceptionPolicies []armotypes.PostureExceptionPolicy,
	clusterName string,
	processor *exceptions.Processor,
) {
	for controlID, ctrl := range controlSummaries {
		if ctrl.GetSubStatus() != apis.SubStatusManualReview {
			continue
		}

		if !hasExplicitControlException(exceptionPolicies, controlID, clusterName, processor) {
			continue
		}

		ctrl.SetStatus(&apis.StatusInfo{
			InnerStatus: apis.StatusPassed,
			SubStatus:   apis.SubStatusException,
		})
		controlSummaries[controlID] = ctrl
	}
}

// requiresResourceMatch reports whether the designator has constraints
// (namespace, name, kind, labels, path, resourceID, WLID/WildWLID) that
// require a real workload — manual controls have none.
func requiresResourceMatch(designator identifiers.PortalDesignator) bool {
	if designator.WLID != "" || designator.WildWLID != "" {
		return true
	}
	return designator.GetNamespace() != "" ||
		designator.GetName() != "" ||
		designator.GetKind() != "" ||
		designator.GetPath() != "" ||
		designator.GetResourceID() != "" ||
		len(designator.GetLabels()) != 0
}

// filterExpiredExceptions removes exception policies whose ExpirationDate has passed.
// Policies with a nil ExpirationDate (no expiration) are kept.
func filterExpiredExceptions(exceptions []armotypes.PostureExceptionPolicy) []armotypes.PostureExceptionPolicy {
	if len(exceptions) == 0 {
		return exceptions
	}
	now := time.Now()
	var valid []armotypes.PostureExceptionPolicy
	for _, e := range exceptions {
		if e.ExpirationDate == nil || e.ExpirationDate.After(now) {
			valid = append(valid, e)
		}
	}
	return valid
}

// hasExplicitControlException reports whether an exception policy targets controlID
// with a cluster-or-global-only designator matching clusterName.
func hasExplicitControlException(exceptionPolicies []armotypes.PostureExceptionPolicy, controlID, clusterName string, processor *exceptions.Processor) bool {
	for _, policy := range exceptionPolicies {
		for _, pp := range policy.PosturePolicies {
			if !processor.RegexCompareControlID(pp.ControlID, controlID) {
				continue
			}
			// no resources = no scope constraint, matches any cluster
			if len(policy.Resources) == 0 {
				return true
			}
			for _, resource := range policy.Resources {
				if requiresResourceMatch(resource) {
					continue
				}
				if processor.MatchesCluster(&resource, clusterName) {
					return true
				}
			}
		}
	}
	return false
}

func mapControlToInfo(mapResourceToControls map[string][]string, infoMap map[string]apis.StatusInfo, controlSummary reportsummary.ControlSummaries) map[string]apis.StatusInfo {
	controlToInfoMap := make(map[string]apis.StatusInfo)
	for resource, statusInfo := range infoMap {
		controlIDs := mapResourceToControls[resource]
		for _, controlID := range controlIDs {
			ctrl := controlSummary.GetControl(reportsummary.EControlCriteriaID, controlID)
			if ctrl != nil {
				resources := ctrl.NumberOfResources()
				// Check that there are no K8s resources too
				if isEmptyResources(resources) {
					controlToInfoMap[controlID] = statusInfo
				}
			}

		}
	}
	return controlToInfoMap
}

func isEmptyResources(counters reportsummary.ICounters) bool {
	return counters.Failed() == 0 && counters.Skipped() == 0 && counters.Passed() == 0
}

// indexedObject is one resolved object in a resourceGroupIndex. kind is cached
// so matching does not re-read it, and ordinal is the object's slot in the
// index's de-duplicated ID space.
type indexedObject struct {
	object  workloadinterface.IMetadata
	kind    string
	ordinal int
}

// resourceGroup is one collected GVR key, parsed, with the objects under it.
type resourceGroup struct {
	group    string
	version  string
	resource string
	objects  []indexedObject
}

// resourceGroupIndex holds a scope's resources ready for matching: GVR keys
// parsed and sorted, IDs resolved to objects, ordinals assigned.
//
// Matching runs once per rule per scope, but none of that work depends on the
// rule, and a scope's resources do not change during a scan. Doing it per call
// made it the scan's dominant source of allocations on large clusters, so it is
// done once per scope instead (see newEvaluationScope).
type resourceGroupIndex struct {
	groups []resourceGroup
	// objectCount is the number of distinct objects, sizing the emitted bitset.
	objectCount int
}

// newResourceGroupIndex parses and sorts a scope's GVR keys and resolves the IDs
// under them. Keys are sorted raw, the order the match loop used to establish,
// so a rule's input array keeps the same resource ordering. An ID that
// allResources does not hold is dropped, as the per-match lookup used to.
func newResourceGroupIndex(k8sResources cautils.K8SResources, allResources map[string]workloadinterface.IMetadata) resourceGroupIndex {
	keys := make([]string, 0, len(k8sResources))
	for key := range k8sResources {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	index := resourceGroupIndex{groups: make([]resourceGroup, 0, len(keys))}
	// One ID can be collected under several GVR keys, so ordinals are assigned
	// per ID rather than per slot, keeping the dedup in getKubernetesObjects.
	ordinals := make(map[string]int)

	for _, key := range keys {
		// Match the collected GVR keys directly. Re-resolving policy matches
		// through k8s-interface here would make file scans depend on its
		// discovery snapshot again and would lose manifest versions that the
		// snapshot does not contain.
		group, version, resource := k8sinterface.StringToResourceGroup(key)
		ids := k8sResources[key]

		objects := make([]indexedObject, 0, len(ids))
		for _, id := range ids {
			object, ok := allResources[id]
			if !ok || object == nil {
				continue
			}
			ordinal, seen := ordinals[id]
			if !seen {
				ordinal = index.objectCount
				ordinals[id] = ordinal
				index.objectCount++
			}
			objects = append(objects, indexedObject{
				object:  object,
				kind:    object.GetKind(),
				ordinal: ordinal,
			})
		}

		index.groups = append(index.groups, resourceGroup{
			group:    group,
			version:  version,
			resource: resource,
			objects:  objects,
		})
	}

	return index
}

// getKubernetesObjects returns the objects of a single scope that the rule
// matches, in match-declaration order. Callers evaluate one scope at a time,
// so no per-namespace bucketing happens here: the caller's batch already is
// the bucket (see cautils.PartitionResources).
func getKubernetesObjects(index resourceGroupIndex, match []reporthandling.RuleMatchObjects) []workloadinterface.IMetadata {
	k8sObjects := []workloadinterface.IMetadata{}
	// A match block often names the same object under several combinations, so
	// emitted objects are tracked by ordinal to keep the input free of
	// duplicates. Allocated on first emission: most rules match nothing in a
	// given scope, and those must not pay for a buffer sized to the index.
	var emitted []bool

	for m := range match {
		mt := &match[m]
		for _, groups := range mt.APIGroups {
			for _, version := range mt.APIVersions {
				for _, resource := range mt.Resources {
					for g := range index.groups {
						group := &index.groups[g]
						if !matchesKubernetesObjectValue(groups, group.group) || !matchesKubernetesObjectValue(version, group.version) {
							continue
						}

						directResourceMatch := resource == "*" || strings.EqualFold(resource, group.resource)
						for i := range group.objects {
							object := &group.objects[i]
							if len(emitted) != 0 && emitted[object.ordinal] {
								continue
							}
							if !directResourceMatch && !strings.EqualFold(resource, object.kind) {
								continue
							}
							if emitted == nil {
								emitted = make([]bool, index.objectCount)
							}
							k8sObjects = append(k8sObjects, object.object)
							emitted[object.ordinal] = true
						}
					}
				}
			}
		}
	}

	return k8sObjects
}

func matchesKubernetesObjectValue(policyValue, objectValue string) bool {
	if policyValue == "*" || policyValue == objectValue {
		return true
	}
	return policyValue == "core" && objectValue == ""
}
func getRuleDependencies(ctx context.Context) (map[string]string, error) {
	modules := resources.LoadRegoModules()
	if len(modules) == 0 {
		logger.L().Ctx(ctx).Warning("failed to load rule dependencies")
	}
	return modules, nil
}

func removeData(obj workloadinterface.IMetadata) {
	if !k8sinterface.IsTypeWorkload(obj.GetObject()) {
		return // remove data only from kubernetes objects
	}
	workload := workloadinterface.NewWorkloadObj(obj.GetObject())
	switch workload.GetKind() {
	case "Secret":
		removeSecretData(workload)
	case "ConfigMap":
		removeConfigMapData(workload)
	default:
		removePodData(workload)
	}
}

func removeConfigMapData(workload workloadinterface.IWorkload) {
	workload.RemoveAnnotation("kubectl.kubernetes.io/last-applied-configuration")
	workloadinterface.RemoveFromMap(workload.GetObject(), "metadata", "managedFields")
	overrideSensitiveData(workload)
	overrideMapField(workload, "binaryData")
}

func overrideSensitiveData(workload workloadinterface.IWorkload) {
	overrideMapField(workload, "data")
}

func overrideStringData(workload workloadinterface.IWorkload) {
	overrideMapField(workload, "stringData")
}

func overrideMapField(workload workloadinterface.IWorkload, field string) {
	dataInterface, ok := workloadinterface.InspectMap(workload.GetObject(), field)
	if !ok {
		return
	}
	data, ok := dataInterface.(map[string]any)
	if !ok {
		return
	}
	for key := range data {
		workloadinterface.SetInMap(workload.GetObject(), []string{field}, key, "XXXXXX")
	}
}

func removeSecretData(workload workloadinterface.IWorkload) {
	workload.RemoveAnnotation("kubectl.kubernetes.io/last-applied-configuration")
	workloadinterface.RemoveFromMap(workload.GetObject(), "metadata", "managedFields")
	overrideSensitiveData(workload)
	overrideStringData(workload)
}

func removePodData(workload workloadinterface.IWorkload) {
	workload.RemoveAnnotation("kubectl.kubernetes.io/last-applied-configuration")
	workloadinterface.RemoveFromMap(workload.GetObject(), "metadata", "managedFields")
	workloadinterface.RemoveFromMap(workload.GetObject(), "status")

	// containers
	if containers, err := workload.GetContainers(); err == nil && len(containers) > 0 {
		removeContainersData(containers)
		workloadinterface.SetInMap(workload.GetObject(), workloadinterface.PodSpec(workload.GetKind()), "containers", containers)
	}

	// init containers

	if initContainers, err := workload.GetInitContainers(); err == nil && len(initContainers) > 0 {
		removeContainersData(initContainers)
		workloadinterface.SetInMap(workload.GetObject(), workloadinterface.PodSpec(workload.GetKind()), "initContainers", initContainers)
	}

	// ephemeral containers
	if ephemeralContainers, err := workload.GetEphemeralContainers(); err == nil && len(ephemeralContainers) > 0 {
		removeEphemeralContainersData(ephemeralContainers)
		workloadinterface.SetInMap(workload.GetObject(), workloadinterface.PodSpec(workload.GetKind()), "ephemeralContainers", ephemeralContainers)
	}
}

func removeContainersData(containers []corev1.Container) {
	for i := range containers {
		container := &containers[i]
		for j := range container.Env {
			container.Env[j].Value = "XXXXXX"
			container.Env[j].ValueFrom = nil
		}
		container.EnvFrom = nil
	}
}
func removeEphemeralContainersData(containers []corev1.EphemeralContainer) {
	for i := range containers {
		container := &containers[i]
		for j := range container.Env {
			container.Env[j].Value = "XXXXXX"
			container.Env[j].ValueFrom = nil
		}
		container.EnvFrom = nil
	}
}

func ruleData(rule *reporthandling.PolicyRule) string {
	return rule.Rule
}

func ruleEnumeratorData(rule *reporthandling.PolicyRule) string {
	return rule.ResourceEnumerator
}
