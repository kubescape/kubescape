package anonymizer

import (
	"maps"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// anonymizeSession rewrites sensitive resource identifiers and metadata while
// preserving internal referential integrity across the full OPA session.
func anonymizeSession(session *cautils.OPASessionObj, mapping *Mapping, repoTransformer Transformer) error {
	if session == nil {
		return nil
	}

	idMapping := make(map[string]string)

	newAllResources := make(map[string]workloadinterface.IMetadata, len(session.AllResources))
	for oldID, resource := range session.AllResources {

		if err := transformResourceMetadata(resource, repoTransformer); err != nil {
			return err
		}
		// sourcePath leaks manifest filenames/line references in hidden output
		// (for example test-anonymize.yaml:1), so anonymize it alongside other
		// resource-local metadata.
		anonymizeResourceObjectSourcePath(resource, mapping)

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

		if err := transformResourceSource(
			&source,
			repoTransformer,
		); err != nil {
			return err
		}

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

	if session.Metadata != nil {
		if err := transformRepoContextMetadata(session.Metadata.ContextMetadata.RepoContextMetadata, repoTransformer); err != nil {
			return err
		}
	}

	if session.Report != nil {

		if err := transformRepoContextMetadata(
			session.Report.Metadata.ContextMetadata.RepoContextMetadata,
			repoTransformer,
		); err != nil {
			return err
		}

		for controlID, control := range session.Report.SummaryDetails.Controls {
			remappedResourceIDs := control.ResourceIDs

			originalResourceIDs := make(
				map[string]apis.ScanningStatus,
				len(control.ResourceIDs.All()),
			)

			maps.Copy(originalResourceIDs, control.ResourceIDs.All())

			remappedResourceIDs.Clear()

			for oldID, status := range originalResourceIDs {
				newID := resolveMappedID(
					mapping,
					idMapping,
					oldID,
					"ref",
				)

				remappedResourceIDs.Append(
					status,
					newID,
				)
			}

			control.ResourceIDs = remappedResourceIDs
			session.Report.SummaryDetails.Controls[controlID] = control
		}
	}
	return nil
}

// resolveMappedID preserves referential integrity when IDs are rewritten during
// anonymization, ensuring cross-references remain valid.
func resolveMappedID(mapping *Mapping, idMapping map[string]string, originalID, prefix string) string {

	// Exact match (most common case)
	if mappedID, ok := idMapping[originalID]; ok {
		return mappedID
	}

	// Fallback for IDs that are not backed by a resource object.
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

// anonymizeResourceObjectSourcePath anonymizes object.sourcePath while
// preserving line number context (e.g. src-xxxx:12).
func anonymizeResourceObjectSourcePath(resource workloadinterface.IMetadata, mapping *Mapping) {
	if resource == nil {
		return
	}

	obj := resource.GetObject()
	if obj == nil {
		return
	}

	rawSourcePath, ok := obj["sourcePath"]
	if !ok {
		return
	}

	sourcePath, ok := rawSourcePath.(string)
	if !ok || sourcePath == "" {
		return
	}

	obj["sourcePath"] = anonymizeSourcePath(sourcePath, mapping)
	resource.SetObject(obj)
}

// anonymizeSourcePath preserves trailing line numbers while anonymizing the
// underlying file path.
func anonymizeSourcePath(sourcePath string, mapping *Mapping) string {
	lastColon := strings.LastIndex(sourcePath, ":")
	if lastColon == -1 {
		return mapping.GetOrCreate("src", sourcePath)
	}

	pathPart := sourcePath[:lastColon]
	linePart := sourcePath[lastColon:]

	if pathPart == "" {
		return mapping.GetOrCreate("src", sourcePath)
	}

	return mapping.GetOrCreate("src", pathPart) + linePart
}

// anonymizeAnnotationNodes recursively traverses unstructured resource objects
// to locate metadata blocks regardless of workload nesting depth.
func anonymizeAnnotationNodes(node any, mapping *Mapping) {
	switch v := node.(type) {
	case map[string]any:
		anonymizeAnnotationMap(v, mapping)

		for _, child := range v {
			anonymizeAnnotationNodes(child, mapping)
		}

	case []any:
		for _, item := range v {
			anonymizeAnnotationNodes(item, mapping)
		}
	}
}

// anonymizeAnnotationMap anonymizes string annotation values while preserving
// annotation keys, which remain meaningful Kubernetes identifiers.
func anonymizeAnnotationMap(obj map[string]any, mapping *Mapping) {
	rawMetadata, ok := obj["metadata"]
	if !ok || rawMetadata == nil {
		return
	}

	metadata, ok := rawMetadata.(map[string]any)
	if !ok {
		return
	}

	rawAnnotations, ok := metadata["annotations"]
	if !ok || rawAnnotations == nil {
		return
	}

	annotations, ok := rawAnnotations.(map[string]any)
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
