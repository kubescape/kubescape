package fixhandler

import (
	"bytes"
	"context"
	"fmt"

	"gopkg.in/yaml.v3"
)

// lastAppliedConfigAnnotation duplicates the whole object as a JSON blob. It is
// written by `kubectl apply`, is frequently the largest thing in the manifest,
// and would still describe the *unfixed* object after the patch is applied.
const lastAppliedConfigAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// serverManagedTopLevelFields are set by the API server and mean nothing in a
// manifest being applied back.
var serverManagedTopLevelFields = []string{"status"}

// serverManagedMetadataFields are assigned by the API server on admission. A
// manifest carrying them is not cleanly applyable: resourceVersion in
// particular makes the apply fail outright if the live object has moved on.
var serverManagedMetadataFields = []string{
	"managedFields",
	"resourceVersion",
	"uid",
	"generation",
	"creationTimestamp",
	"selfLink",
}

// stripServerManagedFields returns a copy of obj without the fields the API
// server owns, leaving something that can be applied back to a cluster.
//
// Only the maps this function edits are copied — the object's own top level,
// metadata, and metadata.annotations. Everything below that (spec and friends)
// is shared with the caller's map by reference, which is safe because the
// result is only ever serialized, never mutated. A full deep copy would buy
// nothing and cost a walk of every workload in a cluster-sized report.
func stripServerManagedFields(obj map[string]any) map[string]any {
	stripped := make(map[string]any, len(obj))
	for k, v := range obj {
		stripped[k] = v
	}
	for _, field := range serverManagedTopLevelFields {
		delete(stripped, field)
	}

	metadata, ok := stripped["metadata"].(map[string]any)
	if !ok {
		return stripped
	}

	metadataCopy := make(map[string]any, len(metadata))
	for k, v := range metadata {
		metadataCopy[k] = v
	}
	for _, field := range serverManagedMetadataFields {
		delete(metadataCopy, field)
	}

	if annotations, ok := metadataCopy["annotations"].(map[string]any); ok {
		annotationsCopy := make(map[string]any, len(annotations))
		for k, v := range annotations {
			annotationsCopy[k] = v
		}
		delete(annotationsCopy, lastAppliedConfigAnnotation)
		// An annotations map that held only the last-applied blob would
		// otherwise serialize as an empty `annotations: {}`.
		if len(annotationsCopy) == 0 {
			delete(metadataCopy, "annotations")
		} else {
			metadataCopy["annotations"] = annotationsCopy
		}
	}

	stripped["metadata"] = metadataCopy
	return stripped
}

// manifestIndent matches what kubectl emits and what hand-written Kubernetes
// manifests use. yaml.Marshal defaults to four spaces, which parses identically
// but makes every line of a rendered manifest differ from the file a user is
// comparing it against.
const manifestIndent = 2

func marshalManifest(obj map[string]any) (string, error) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(manifestIndent)
	if err := encoder.Encode(obj); err != nil {
		encoder.Close()
		return "", err
	}
	// Close flushes the trailing document; a deferred close would hide a write
	// error behind a manifest that looks complete but is truncated.
	if err := encoder.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderFixedManifest serializes a scanned resource to YAML and applies
// yamlExpression to it in memory, returning the patched manifest. Nothing is
// read from or written to disk.
//
// This is the counterpart to the file path in ApplyChanges, for resources that
// have no file to rewrite — a cluster scan records live objects, not manifests.
// The patching itself goes through the same ApplyFixToContent the file path
// uses, so both paths share one implementation of the yaml.Node surgery.
//
// The object comes from the scan report, which records each resource as it was
// when scanned, so the result reflects that snapshot rather than a live read.
func RenderFixedManifest(ctx context.Context, obj map[string]any, yamlExpression string) (string, error) {
	if len(obj) == 0 {
		return "", fmt.Errorf("cannot render a fix for an empty resource")
	}
	if yamlExpression == "" {
		// Emitting the unpatched manifest here would look like a successful fix
		// while changing nothing, which is the one failure mode this package
		// must never have.
		return "", fmt.Errorf("cannot render a fix without a yaml expression")
	}

	manifest, err := marshalManifest(stripServerManagedFields(obj))
	if err != nil {
		return "", fmt.Errorf("failed to serialize resource: %w", err)
	}

	fixed, err := ApplyFixToContent(ctx, manifest, yamlExpression)
	if err != nil {
		return "", fmt.Errorf("failed to apply fix: %w", err)
	}

	return fixed, nil
}
