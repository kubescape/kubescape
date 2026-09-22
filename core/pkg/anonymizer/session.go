package anonymizer

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"k8s.io/apimachinery/pkg/runtime"
)

// transformSession applies the supplied Transformer to sensitive resource
// identifiers and metadata while preserving referential integrity across
// the full OPA session. Transformation is transactional: callers either get
// a completely transformed session or the original session remains untouched.
func transformSession(session *cautils.OPASessionObj, _ *Mapping, transformer Transformer) error {
	if session == nil {
		return nil
	}
	if transformer == nil {
		return errors.New("transformer is required")
	}

	transaction, err := cloneSessionForTransform(session)
	if err != nil {
		return err
	}
	if err := transformSessionInPlace(transaction.working, transformer); err != nil {
		return err
	}
	commitTransformedSession(session, transaction)
	return nil
}

type sessionTransform struct {
	working         *cautils.OPASessionObj
	originalByClone map[workloadinterface.IMetadata]workloadinterface.IMetadata
}

// cloneSessionForTransform copies every field transformSessionInPlace may
// mutate. It intentionally does not copy OPASessionObj itself because it owns
// synchronization primitives. Read-only configuration is assigned directly.
func cloneSessionForTransform(session *cautils.OPASessionObj) (*sessionTransform, error) {
	working := &cautils.OPASessionObj{
		LabelsToCopy:          append([]string(nil), session.LabelsToCopy...),
		EnvVarSecretRefs:      session.EnvVarSecretRefs,
		SourcePathsAnonymized: session.SourcePathsAnonymized,
	}

	resourcesResult, err := cloneJSON(session.ResourcesResult)
	if err != nil {
		return nil, fmt.Errorf("clone resource results: %w", err)
	}
	working.ResourcesResult = resourcesResult

	resourceSource, err := cloneJSON(session.ResourceSource)
	if err != nil {
		return nil, fmt.Errorf("clone resource sources: %w", err)
	}
	working.ResourceSource = resourceSource

	resourcesPrioritized, err := cloneJSON(session.ResourcesPrioritized)
	if err != nil {
		return nil, fmt.Errorf("clone prioritized resources: %w", err)
	}
	working.ResourcesPrioritized = resourcesPrioritized

	// Attack-track values are not mutated by anonymization. Copy the map and
	// each slice so key remapping cannot affect the caller before commit.
	working.ResourceAttackTracks = make(map[string][]v1alpha1.IAttackTrack, len(session.ResourceAttackTracks))
	for resourceID, tracks := range session.ResourceAttackTracks {
		working.ResourceAttackTracks[resourceID] = append([]v1alpha1.IAttackTrack(nil), tracks...)
	}

	metadata, err := cloneJSON(session.Metadata)
	if err != nil {
		return nil, fmt.Errorf("clone report metadata: %w", err)
	}
	working.Metadata = metadata

	report, err := clonePostureReport(session.Report)
	if err != nil {
		return nil, fmt.Errorf("clone posture report: %w", err)
	}
	working.Report = report

	namespaceSummaries, err := cloneJSON(session.NamespaceSummaries)
	if err != nil {
		return nil, fmt.Errorf("clone namespace summaries: %w", err)
	}
	working.NamespaceSummaries = namespaceSummaries

	resources, originalByClone, err := cloneCatalog(session.GetCatalog())
	if err != nil {
		return nil, err
	}
	working.SetCatalog(cautils.NewMapResourceCatalog(resources))
	return &sessionTransform{working: working, originalByClone: originalByClone}, nil
}

func cloneJSON[T any](value T) (T, error) {
	var cloned T
	raw, err := json.Marshal(value)
	if err != nil {
		return cloned, err
	}
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return cloned, err
	}
	return cloned, nil
}

func clonePostureReport(report *reporthandlingv2.PostureReport) (*reporthandlingv2.PostureReport, error) {
	cloned, err := cloneJSON(report)
	if err != nil || report == nil {
		return cloned, err
	}
	cloneControlResourceIDs(report.SummaryDetails.Controls, cloned.SummaryDetails.Controls)
	for frameworkIndex, originalFramework := range report.SummaryDetails.Frameworks {
		if frameworkIndex >= len(cloned.SummaryDetails.Frameworks) {
			continue
		}
		cloneControlResourceIDs(
			originalFramework.Controls,
			cloned.SummaryDetails.Frameworks[frameworkIndex].Controls,
		)
	}
	return cloned, nil
}

// cloneControlResourceIDs restores AllLists after JSON cloning. AllLists has
// an unexported backing map, so encoding/json cannot retain its entries.
func cloneControlResourceIDs(original, cloned reportsummary.ControlSummaries) {
	for controlID, originalControl := range original {
		clonedControl, ok := cloned[controlID]
		if !ok {
			continue
		}
		resourceIDs := helpersv1.AllLists{}
		resourceIDs.Initialize(len(originalControl.ResourceIDs.All()))
		for resourceID, status := range originalControl.ResourceIDs.All() {
			resourceIDs.Append(status, resourceID)
		}
		clonedControl.ResourceIDs = resourceIDs
		cloned[controlID] = clonedControl
	}
}

func cloneCatalog(catalog cautils.ResourceCatalog) (map[string]workloadinterface.IMetadata, map[workloadinterface.IMetadata]workloadinterface.IMetadata, error) {
	resources := make(map[string]workloadinterface.IMetadata)
	originalByClone := make(map[workloadinterface.IMetadata]workloadinterface.IMetadata)
	if catalog == nil {
		return resources, originalByClone, nil
	}

	var cloneErr error
	catalog.ForEach(func(resourceID string, resource workloadinterface.IMetadata) bool {
		if resource == nil {
			return true
		}
		object := resource.GetObject()
		if object == nil {
			cloneErr = fmt.Errorf("clone resource %q: object is unavailable", resourceID)
			return false
		}
		cloned := workloadinterface.NewWorkloadObj(runtime.DeepCopyJSON(object))
		resources[resourceID] = cloned
		originalByClone[cloned] = resource
		return true
	})
	if cloneErr != nil {
		return nil, nil, cloneErr
	}
	return resources, originalByClone, nil
}

func commitTransformedSession(session *cautils.OPASessionObj, transaction *sessionTransform) {
	working := transaction.working
	committedResources := make(map[string]workloadinterface.IMetadata, len(transaction.originalByClone))
	working.GetCatalog().ForEach(func(_ string, transformed workloadinterface.IMetadata) bool {
		original, ok := transaction.originalByClone[transformed]
		if !ok {
			return true
		}
		original.SetObject(runtime.DeepCopyJSON(transformed.GetObject()))
		committedResources[original.GetID()] = original
		return true
	})
	session.SetCatalog(cautils.NewMapResourceCatalog(committedResources))
	session.ResourcesResult = working.ResourcesResult
	session.ResourceSource = working.ResourceSource
	session.SourcePathsAnonymized = working.SourcePathsAnonymized
	session.ResourcesPrioritized = working.ResourcesPrioritized
	session.ResourceAttackTracks = working.ResourceAttackTracks
	session.Metadata = working.Metadata
	session.Report = working.Report
	session.NamespaceSummaries = working.NamespaceSummaries
}

func transformSessionInPlace(session *cautils.OPASessionObj, transformer Transformer) error {

	idMapping := make(map[string]string)

	newCatalog := cautils.NewMapResourceCatalog()
	catalog := session.GetCatalog()
	var transformErr error
	if catalog != nil {
		catalog.ForEach(func(oldID string, resource workloadinterface.IMetadata) bool {
			if resource == nil {
				return true
			}

			if err := transformResourceMetadata(resource, transformer); err != nil {
				transformErr = err
				return false
			}

			// sourcePath may expose manifest filenames and line references
			// (for example test-anonymize.yaml:1), so transform it alongside
			// other resource-local metadata.
			if err := transformResourceObjectSourcePath(resource, transformer); err != nil {
				transformErr = err
				return false
			}

			// Annotations may contain infrastructure identifiers, secret paths, or
			// other sensitive metadata at both top-level and nested workload templates.
			if err := transformResourceAnnotations(resource, transformer); err != nil {
				transformErr = err
				return false
			}

			// Container-related metadata is transformed separately to preserve the
			// existing typed/unstructured traversal behavior while supporting
			// multiple transformation strategies. session.EnvVarSecretRefs[oldID]
			// is nil for a resource whose removeData pass found no reference-backed
			// env vars; transformTypedEnv/transformUnstructuredEnv treat that the
			// same as "no additional names to anonymize", which is correct.
			if err := transformContainerMetadata(resource, session.EnvVarSecretRefs[oldID], transformer); err != nil {
				transformErr = err
				return false
			}

			if len(session.LabelsToCopy) > 0 {
				if err := transformResourceLabels(resource, session.LabelsToCopy, transformer); err != nil {
					transformErr = err
					return false
				}
			}

			newID := resource.GetID()
			idMapping[oldID] = newID
			newCatalog.Add(resource)
			return true
		})
	}
	if transformErr != nil {
		return transformErr
	}
	session.SetCatalog(newCatalog)

	newResourcesResult := make(map[string]resourcesresults.Result, len(session.ResourcesResult))
	for oldID, result := range session.ResourcesResult {
		newID, err := resolveMappedID(transformer, idMapping, oldID, "ref")
		if err != nil {
			return err
		}
		result.ResourceID = newID

		if result.PrioritizedResource != nil {
			result.PrioritizedResource.ResourceID = newID
		}

		for controlIndex := range result.AssociatedControls {
			for ruleIndex := range result.AssociatedControls[controlIndex].ResourceAssociatedRules {
				rule := &result.AssociatedControls[controlIndex].ResourceAssociatedRules[ruleIndex]

				for pathIndex := range rule.Paths {
					mappedID, err := resolveMappedID(
						transformer,
						idMapping,
						rule.Paths[pathIndex].ResourceID,
						"ref",
					)
					if err != nil {
						return err
					}
					rule.Paths[pathIndex].ResourceID = mappedID
				}

				for relatedIndex := range rule.RelatedResourcesIDs {
					mappedID, err := resolveMappedID(
						transformer,
						idMapping,
						rule.RelatedResourcesIDs[relatedIndex],
						"ref",
					)
					if err != nil {
						return err
					}
					rule.RelatedResourcesIDs[relatedIndex] = mappedID
				}
			}
		}

		newResourcesResult[newID] = result
	}
	session.ResourcesResult = newResourcesResult

	newResourceSource := make(map[string]reporthandling.Source, len(session.ResourceSource))

	for oldID, source := range session.ResourceSource {
		newID, err := resolveMappedID(transformer, idMapping, oldID, "ref")
		if err != nil {
			return err
		}

		if err := transformResourceSource(
			&source,
			transformer,
		); err != nil {
			return err
		}

		newResourceSource[newID] = source
	}
	session.ResourceSource = newResourceSource

	// Every source path is now a pseudonym, so nothing downstream can open the
	// manifest it came from. The evidence column reads these paths to resolve a
	// finding's line, and recording the fact here - rather than re-deriving it
	// from --hide or --encrypt at each reader - keeps it true by construction:
	// whatever anonymizes the session says so.
	session.SourcePathsAnonymized = true

	newResourcesPrioritized := make(map[string]prioritization.PrioritizedResource, len(session.ResourcesPrioritized))
	for oldID, prioritized := range session.ResourcesPrioritized {
		newID, err := resolveMappedID(transformer, idMapping, oldID, "ref")
		if err != nil {
			return err
		}
		prioritized.ResourceID = newID
		newResourcesPrioritized[newID] = prioritized
	}
	session.ResourcesPrioritized = newResourcesPrioritized

	newResourceAttackTracks := make(map[string][]v1alpha1.IAttackTrack, len(session.ResourceAttackTracks))
	for oldID, attackTracks := range session.ResourceAttackTracks {
		newID, err := resolveMappedID(transformer, idMapping, oldID, "ref")
		if err != nil {
			return err
		}
		newResourceAttackTracks[newID] = attackTracks
	}
	session.ResourceAttackTracks = newResourceAttackTracks

	if session.Metadata != nil {
		if err := transformRepoContextMetadata(session.Metadata.ContextMetadata.RepoContextMetadata, transformer); err != nil {
			return err
		}
		if err := transformDirectoryContextMetadata(session.Metadata.ContextMetadata.DirectoryContextMetadata, transformer); err != nil {
			return err
		}
		if err := transformFileContextMetadata(session.Metadata.ContextMetadata.FileContextMetadata, transformer); err != nil {
			return err
		}
		if err := transformClusterMetadata(session.Metadata.ContextMetadata.ClusterContextMetadata, transformer); err != nil {
			return err
		}
		if err := transformClusterMetadata(&session.Metadata.ClusterMetadata, transformer); err != nil {
			return err
		}
	}

	if session.Report != nil {

		if err := transformRepoContextMetadata(session.Report.Metadata.ContextMetadata.RepoContextMetadata, transformer); err != nil {
			return err
		}

		if err := transformDirectoryContextMetadata(session.Report.Metadata.ContextMetadata.DirectoryContextMetadata, transformer); err != nil {
			return err
		}

		if err := transformFileContextMetadata(session.Report.Metadata.ContextMetadata.FileContextMetadata, transformer); err != nil {
			return err
		}

		if err := transformClusterMetadata(session.Report.Metadata.ContextMetadata.ClusterContextMetadata, transformer); err != nil {
			return err
		}

		if err := transformClusterMetadata(&session.Report.Metadata.ClusterMetadata, transformer); err != nil {
			return err
		}

		if err := remapControlResourceIDs(session.Report.SummaryDetails.Controls, transformer, idMapping); err != nil {
			return err
		}
		for frameworkIndex := range session.Report.SummaryDetails.Frameworks {
			if err := remapControlResourceIDs(session.Report.SummaryDetails.Frameworks[frameworkIndex].Controls, transformer, idMapping); err != nil {
				return err
			}
		}
	}

	if err := transformNamespaceSummaries(session.NamespaceSummaries, transformer); err != nil {
		return err
	}

	return nil
}

func remapControlResourceIDs(controls reportsummary.ControlSummaries, transformer Transformer, idMapping map[string]string) error {
	for controlID, control := range controls {
		remappedResourceIDs := control.ResourceIDs
		originalResourceIDs := make(map[string]apis.ScanningStatus, len(control.ResourceIDs.All()))
		maps.Copy(originalResourceIDs, control.ResourceIDs.All())
		remappedResourceIDs.Clear()

		for oldID, status := range originalResourceIDs {
			newID, err := resolveMappedID(transformer, idMapping, oldID, "ref")
			if err != nil {
				return err
			}
			remappedResourceIDs.Append(status, newID)
		}

		control.ResourceIDs = remappedResourceIDs
		controls[controlID] = control
	}
	return nil
}

// transformNamespaceSummaries anonymizes the namespace name in each
// NamespaceSummary in place. It reuses the "ns" prefix transformResourceMetadata
// uses for a resource's own namespace, so a namespace gets the same pseudonym
// here as everywhere else in the report. ClusterScopedNamespace is a
// Kubescape-internal marker, not a real namespace, so it is left untouched.
func transformNamespaceSummaries(summaries cautils.NamespaceSummaries, transformer Transformer) error {
	for i := range summaries {
		if summaries[i].Namespace == cautils.ClusterScopedNamespace {
			continue
		}
		namespace, err := transformValue(transformer, "ns", summaries[i].Namespace)
		if err != nil {
			return err
		}
		summaries[i].Namespace = namespace
	}
	return nil
}

// resolveMappedID preserves referential integrity when IDs are rewritten during
// anonymization, ensuring cross-references remain valid.
func resolveMappedID(transformer Transformer, idMapping map[string]string, originalID, prefix string) (string, error) {

	// Exact match (most common case)
	if mappedID, ok := idMapping[originalID]; ok {
		return mappedID, nil
	}

	// IDs that are not backed by a resource object still need the active
	// transformation. In encrypted reports this keeps the fallback reversible;
	// in hidden reports the mapping transformer retains deterministic aliases.
	// Cache the fallback so every reference to the same missing resource uses
	// one value even when the transformer uses randomized encryption.
	mappedID, err := transformer.Transform(prefix, originalID)
	if err != nil {
		return "", err
	}
	idMapping[originalID] = mappedID
	return mappedID, nil
}

// transformResourceLabels applies the supplied Transformer to labels
// explicitly configured for copying into reports while preserving the
// existing label selection behavior.
func transformResourceLabels(resource workloadinterface.IMetadata, labelsToCopy []string, transformer Transformer) error {

	bw, ok := resource.(workloadinterface.IWorkload)
	if !ok {
		return nil
	}

	labels := bw.GetLabels()
	if len(labels) == 0 {
		return nil
	}

	for _, key := range labelsToCopy {
		if val, exists := labels[key]; exists && val != "" {

			transformedValue, err := transformValue(
				transformer,
				"lbl",
				val,
			)
			if err != nil {
				return err
			}

			bw.SetLabel(
				key,
				transformedValue,
			)
		}
	}

	return nil
}

// transformResourceAnnotations applies the supplied Transformer to
// annotation values throughout a resource object, including nested
// workload templates such as Deployment pod specs.
func transformResourceAnnotations(resource workloadinterface.IMetadata, transformer Transformer) error {

	if resource == nil {
		return nil
	}

	obj := resource.GetObject()
	if obj == nil {
		return nil
	}

	if err := transformAnnotationNodes(obj, transformer); err != nil {
		return err
	}

	resource.SetObject(obj)

	return nil
}

// transformResourceObjectSourcePath applies the supplied Transformer to
// object.sourcePath while preserving trailing line-number context (for
// example src-xxxx:12).
func transformResourceObjectSourcePath(resource workloadinterface.IMetadata, transformer Transformer) error {

	if resource == nil {
		return nil
	}

	obj := resource.GetObject()
	if obj == nil {
		return nil
	}

	rawSourcePath, ok := obj["sourcePath"]
	if !ok {
		return nil
	}

	sourcePath, ok := rawSourcePath.(string)
	if !ok || sourcePath == "" {
		return nil
	}

	transformedSourcePath, err := transformSourcePath(
		sourcePath,
		transformer,
	)
	if err != nil {
		return err
	}

	obj["sourcePath"] = transformedSourcePath
	resource.SetObject(obj)

	return nil
}

// transformSourcePath applies the supplied Transformer to the path portion
// of a sourcePath while preserving any trailing line number (for example
// src-xxxx:12).
func transformSourcePath(sourcePath string, transformer Transformer) (string, error) {

	lastColon := lastSourcePathColon(sourcePath)
	if lastColon == -1 {
		return transformValue(transformer, "src", sourcePath)
	}

	pathPart := sourcePath[:lastColon]
	linePart := sourcePath[lastColon:]

	if pathPart == "" {
		return transformValue(transformer, "src", sourcePath)
	}

	transformedPath, err := transformValue(transformer, "src", pathPart)
	if err != nil {
		return "", err
	}

	return transformedPath + linePart, nil
}

// lastSourcePathColon returns the index of the colon separating a
// sourcePath's file path from its trailing document-index suffix (for
// example the ":12" in "src-xxxx:12"), or -1 if there is none. A leading
// Windows drive letter (for example "C:\...") is skipped so it is never
// mistaken for that separator, which would otherwise leave everything past
// the drive letter untransformed.
func lastSourcePathColon(sourcePath string) int {
	searchFrom := 0
	if len(sourcePath) >= 2 && sourcePath[1] == ':' && isASCIILetter(sourcePath[0]) {
		searchFrom = 2
	}

	idx := strings.LastIndex(sourcePath[searchFrom:], ":")
	if idx == -1 {
		return -1
	}

	return idx + searchFrom
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// transformAnnotationNodes recursively traverses unstructured resource
// objects, applying the supplied Transformer to annotation values
// wherever metadata.annotations appears regardless of workload nesting.
func transformAnnotationNodes(node any, transformer Transformer) error {

	switch v := node.(type) {
	case map[string]any:
		if err := transformAnnotationMap(v, transformer); err != nil {
			return err
		}

		for _, child := range v {
			if err := transformAnnotationNodes(child, transformer); err != nil {
				return err
			}
		}

	case []any:
		for _, item := range v {
			if err := transformAnnotationNodes(item, transformer); err != nil {
				return err
			}
		}
	}

	return nil
}

// transformAnnotationMap applies the supplied Transformer to annotation
// values while preserving annotation keys, which remain meaningful
// Kubernetes identifiers.
func transformAnnotationMap(obj map[string]any, transformer Transformer) error {

	rawMetadata, ok := obj["metadata"]
	if !ok || rawMetadata == nil {
		return nil
	}

	metadata, ok := rawMetadata.(map[string]any)
	if !ok {
		return nil
	}

	rawAnnotations, ok := metadata["annotations"]
	if !ok || rawAnnotations == nil {
		return nil
	}

	annotations, ok := rawAnnotations.(map[string]any)
	if !ok {
		return nil
	}

	for key, val := range annotations {
		str, ok := val.(string)
		if !ok || str == "" {
			continue
		}

		transformedValue, err := transformValue(transformer, "ann", str)
		if err != nil {
			return err
		}

		annotations[key] = transformedValue
	}

	return nil
}

func transformValue(transformer Transformer, prefix string, value string) (string, error) {
	if value == "" {
		return value, nil
	}

	return transformer.Transform(prefix, value)
}

func transformResourceMetadata(
	resource workloadinterface.IMetadata,
	transformer Transformer,
) error {

	if resource == nil {
		return nil
	}

	var err error

	if name := resource.GetName(); name != "" {
		name, err = transformValue(transformer, "res", name)
		if err != nil {
			return err
		}

		resource.SetName(name)
	}

	if namespace := resource.GetNamespace(); namespace != "" {
		namespace, err = transformValue(transformer, "ns", namespace)
		if err != nil {
			return err
		}

		resource.SetNamespace(namespace)
	}

	return nil
}

func transformRepoContextMetadata(repo *reporthandlingv2.RepoContextMetadata, transformer Transformer) error {
	if repo == nil {
		return nil
	}

	repoCopy := *repo

	var err error

	repoCopy.Repo, err = transformValue(transformer, "git", repoCopy.Repo)
	if err != nil {
		return err
	}

	repoCopy.Owner, err = transformValue(transformer, "git", repoCopy.Owner)
	if err != nil {
		return err
	}

	repoCopy.Branch, err = transformValue(transformer, "git", repoCopy.Branch)
	if err != nil {
		return err
	}

	repoCopy.DefaultBranch, err = transformValue(transformer, "git", repoCopy.DefaultBranch)
	if err != nil {
		return err
	}

	repoCopy.RemoteURL, err = transformValue(transformer, "git", repoCopy.RemoteURL)
	if err != nil {
		return err
	}

	repoCopy.LocalRootPath, err = transformValue(transformer, "git", repoCopy.LocalRootPath)
	if err != nil {
		return err
	}

	if err := transformLastCommit(&repoCopy.LastCommit, transformer); err != nil {
		return err
	}

	*repo = repoCopy

	return nil
}

// transformClusterMetadata hides which cluster a report came from. The context
// name is the entry the user selected in their kubeconfig, and the cloud names
// are parsed straight out of it: for a GKE cluster "gke_project_zone_name" the
// prefix is "gke_project_zone", so PrefixName and FullName carry the project
// and, on EKS, the account ID out of the ARN. The provider and worker count
// stay in cleartext - they describe the shape of the environment rather than
// name it, and are what a shared report is usually read for.
//
// Namespace keys use the "ns" prefix so that under --hide they come out
// string-identical to the namespaces transformResourceMetadata writes onto the
// resources themselves; the per-namespace counts are only worth keeping if they
// still join. Under --encrypt the two sides are separate ciphertexts, as every
// repeated value in a report is, and the join reappears once both are
// decrypted.
func transformClusterMetadata(cluster *reporthandlingv2.ClusterMetadata, transformer Transformer) error {
	if cluster == nil {
		return nil
	}

	clusterCopy := *cluster

	var err error

	clusterCopy.ContextName, err = transformValue(transformer, "cluster", clusterCopy.ContextName)
	if err != nil {
		return err
	}

	if clusterCopy.CloudMetadata != nil {
		cloudCopy := *clusterCopy.CloudMetadata

		cloudCopy.FullName, err = transformValue(transformer, "cluster", cloudCopy.FullName)
		if err != nil {
			return err
		}

		cloudCopy.ShortName, err = transformValue(transformer, "cluster", cloudCopy.ShortName)
		if err != nil {
			return err
		}

		cloudCopy.PrefixName, err = transformValue(transformer, "cluster", cloudCopy.PrefixName)
		if err != nil {
			return err
		}

		clusterCopy.CloudMetadata = &cloudCopy
	}

	if clusterCopy.MapNamespaceToNumberOfResources != nil {
		namespaceCounts := make(map[string]int, len(clusterCopy.MapNamespaceToNumberOfResources))

		for namespace, count := range clusterCopy.MapNamespaceToNumberOfResources {
			namespace, err = transformValue(transformer, "ns", namespace)
			if err != nil {
				return err
			}

			namespaceCounts[namespace] += count
		}

		clusterCopy.MapNamespaceToNumberOfResources = namespaceCounts
	}

	*cluster = clusterCopy

	return nil
}

// transformDirectoryContextMetadata and transformFileContextMetadata hide where
// the scan ran: the absolute path the user pointed at, which on most machines
// carries their account name, and the machine itself. A directory scan records
// the one, a single-file scan the other, and both survive into a report whose
// whole purpose is to be shareable. The host uses a shared prefix so the same
// machine reads as the same pseudonym either way.
func transformDirectoryContextMetadata(directory *reporthandlingv2.DirectoryContextMetadata, transformer Transformer) error {
	if directory == nil {
		return nil
	}

	directoryCopy := *directory

	var err error

	directoryCopy.BasePath, err = transformValue(transformer, "dir", directoryCopy.BasePath)
	if err != nil {
		return err
	}

	directoryCopy.HostName, err = transformValue(transformer, "host", directoryCopy.HostName)
	if err != nil {
		return err
	}

	*directory = directoryCopy

	return nil
}

func transformFileContextMetadata(file *reporthandlingv2.FileContextMetadata, transformer Transformer) error {
	if file == nil {
		return nil
	}

	fileCopy := *file

	var err error

	fileCopy.FilePath, err = transformValue(transformer, "file", fileCopy.FilePath)
	if err != nil {
		return err
	}

	fileCopy.HostName, err = transformValue(transformer, "host", fileCopy.HostName)
	if err != nil {
		return err
	}

	*file = fileCopy

	return nil
}

func transformLastCommit(commit *reporthandling.LastCommit, transformer Transformer) error {
	if commit == nil {
		return nil
	}

	commitCopy := *commit

	var err error

	commitCopy.Hash, err = transformValue(transformer, "git", commitCopy.Hash)
	if err != nil {
		return err
	}

	commitCopy.CommitterName, err = transformValue(transformer, "git", commitCopy.CommitterName)
	if err != nil {
		return err
	}

	commitCopy.CommitterEmail, err = transformValue(transformer, "git", commitCopy.CommitterEmail)
	if err != nil {
		return err
	}

	commitCopy.Message, err = transformValue(transformer, "git", commitCopy.Message)
	if err != nil {
		return err
	}

	*commit = commitCopy

	return nil
}

func transformResourceSource(
	source *reporthandling.Source,
	transformer Transformer,
) error {
	if source == nil {
		return nil
	}

	sourceCopy := *source

	if source.HelmValuesPaths != nil {
		sourceCopy.HelmValuesPaths = append(
			[]string(nil),
			source.HelmValuesPaths...,
		)
	}

	var err error

	sourceCopy.Path, err = transformValue(transformer, "src", sourceCopy.Path)
	if err != nil {
		return err
	}

	sourceCopy.RelativePath, err = transformValue(transformer, "src", sourceCopy.RelativePath)
	if err != nil {
		return err
	}

	sourceCopy.HelmPath, err = transformValue(transformer, "src", sourceCopy.HelmPath)
	if err != nil {
		return err
	}

	sourceCopy.HelmChartName, err = transformValue(transformer, "src", sourceCopy.HelmChartName)
	if err != nil {
		return err
	}

	sourceCopy.HelmTemplateFile, err = transformValue(transformer, "src", sourceCopy.HelmTemplateFile)
	if err != nil {
		return err
	}

	sourceCopy.KustomizeDirectoryName, err = transformValue(transformer, "src", sourceCopy.KustomizeDirectoryName)
	if err != nil {
		return err
	}

	for i := range sourceCopy.HelmValuesPaths {
		sourceCopy.HelmValuesPaths[i], err = transformValue(transformer, "src", sourceCopy.HelmValuesPaths[i])
		if err != nil {
			return err
		}
	}

	if err := transformLastCommit(
		&sourceCopy.LastCommit,
		transformer,
	); err != nil {
		return err
	}

	*source = sourceCopy

	return nil
}
