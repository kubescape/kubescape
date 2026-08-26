package opaprocessor

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/require"
)

// inlineAnnotatedWorkload builds a manifest-sourced Deployment, optionally
// carrying the kubescape.io/skip-controls annotation. sourcePath is shared by
// every document in one file, mirroring a rendered multi-document manifest.
func inlineAnnotatedWorkload(sourcePath, name string, skip bool) workloadinterface.IMetadata {
	metadata := map[string]any{"name": name, "namespace": "prod"}
	if skip {
		metadata["annotations"] = map[string]any{skipControlsAnnotation: "C-0057"}
	}
	return localworkload.NewLocalWorkload(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   metadata,
		"sourcePath": sourcePath,
	})
}

// TestInlineExceptionDoesNotLeakToSiblingResource pins that an inline exception
// applies only to the resource that carries the annotation. The exceptions
// processor matches designator attributes as anchored regular expressions, so
// an unquoted name is a pattern: "web.api" would also match the sibling
// "web-api" and silently suppress the annotated control on a workload nobody
// asked to exempt.
func TestInlineExceptionDoesNotLeakToSiblingResource(t *testing.T) {
	const manifest = "/repo/rendered.yaml"

	annotated := inlineAnnotatedWorkload(manifest, "web.api", true)
	sibling := inlineAnnotatedWorkload(manifest, "web-api", false)

	policies := inlineExceptionFromResource(annotated, "cluster")
	require.Len(t, policies, 1)

	processor := exceptions.NewProcessor()
	require.Len(t, processor.GetResourceExceptions(policies, annotated, "cluster"), 1,
		"the annotated resource must still be exempted")
	require.Empty(t, processor.GetResourceExceptions(policies, sibling, "cluster"),
		"a resource without the annotation must never be exempted by a sibling's inline exception")
}

// TestInlineExceptionMatchesDottedNameItself guards the other direction: quoting
// the attributes must not stop an inline exception from matching the resource it
// was authored on.
func TestInlineExceptionMatchesDottedNameItself(t *testing.T) {
	workload := inlineAnnotatedWorkload("/repo/rendered.yaml", "app.kubernetes.io", true)

	policies := inlineExceptionFromResource(workload, "cluster")
	require.Len(t, policies, 1)

	processor := exceptions.NewProcessor()
	require.Len(t, processor.GetResourceExceptions(policies, workload, "cluster"), 1)
}
