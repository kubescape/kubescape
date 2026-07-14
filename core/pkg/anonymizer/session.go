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

// transformSession applies the supplied Transformer to sensitive resource
// identifiers and metadata while preserving referential integrity across
// the full OPA session.

func transformSession(session *cautils.OPASessionObj, mapping *Mapping, transformer Transformer) error {
	if session == nil {
		return nil
	}

	idMapping := make(map[string]string)

	newAllResources := make(map[string]workloadinterface.IMetadata, len(session.AllResources))
	for oldID, resource := range session.AllResources {

		if err := transformResourceMetadata(resource, transformer); err != nil {
			return err
		}

		// sourcePath may expose manifest filenames and line references
		// (for example test-anonymize.yaml:1), so transform it alongside
		// other resource-local metadata.

		if err := transformResourceObjectSourcePath(resource, transformer); err != nil {
			return err
		}

		// Annotations may contain infrastructure identifiers, secret paths, or
		// other sensitive metadata at both top-level and nested workload templates.

		if err := transformResourceAnnotations(resource, transformer); err != nil {
			return err
		}

		// Container-related metadata is transformed separately to preserve the
		// existing typed/unstructured traversal behavior while supporting
		// multiple transformation strategies.
		if err := transformContainerMetadata(resource, transformer); err != nil {
			return err
		}

		if len(session.LabelsToCopy) > 0 {
			if err := transformResourceLabels(resource, session.LabelsToCopy, transformer); err != nil {
				return err
			}
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
			transformer,
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
		if err := transformRepoContextMetadata(session.Metadata.ContextMetadata.RepoContextMetadata, transformer); err != nil {
			return err
		}
	}

	if session.Report != nil {

		if err := transformRepoContextMetadata(session.Report.Metadata.ContextMetadata.RepoContextMetadata, transformer); err != nil {
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

	lastColon := strings.LastIndex(sourcePath, ":")
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

func transformResourceMetadata(resource workloadinterface.IMetadata, transformer Transformer) error {

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

func transformResourceSource(source *reporthandling.Source, transformer Transformer) error {
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
