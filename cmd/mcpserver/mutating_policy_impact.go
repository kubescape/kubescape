package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/mapreconcile"
	"github.com/mark3labs/mcp-go/mcp"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var mutatingAdmissionPolicyOperations = map[string]admissionregistrationv1alpha1.OperationType{
	"CREATE":  admissionregistrationv1alpha1.Create,
	"UPDATE":  admissionregistrationv1alpha1.Update,
	"CONNECT": admissionregistrationv1alpha1.Connect,
}

// createMutatingAdmissionPolicyTools registers
// analyze_mutating_admission_policy_impact, which reports which of a
// cluster's live MutatingAdmissionPolicy objects would mutate a specific
// resource -- and with what raw CEL mutation expression -- surfacing
// implicit, in-cluster mutation that never appears in the manifest a user
// applied. See core/pkg/mapreconcile for the matching model and its
// documented limits (it reports a match and its expression, it does not
// evaluate the expression to compute the mutated object).
func createMutatingAdmissionPolicyTools(ksServer *KubescapeMcpserver) {
	tool := mcp.NewTool(
		"analyze_mutating_admission_policy_impact",
		mcp.WithDescription("Determine which of the cluster's live MutatingAdmissionPolicy objects would mutate a specific resource on a given operation (default CREATE), and what each one's raw CEL mutation expression is. This surfaces implicit mutation that happens at admission time and never appears in the manifest a user applied -- it reports that a policy's mutation would run and what its expression is, it does not evaluate the expression to compute the resulting object."),
		mcp.WithString("namespace", mcp.Description("Namespace of the resource (omit for a cluster-scoped resource)")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of the resource")),
		mcp.WithString("api_group", mcp.Description("API group of the resource (omit or empty for the core group, e.g. Pod/ConfigMap)")),
		mcp.WithString("api_version", mcp.Required(), mcp.Description("API version of the resource, e.g. v1")),
		mcp.WithString("resource", mcp.Required(), mcp.Description("Plural resource name, e.g. pods, deployments")),
		mcp.WithString("subresource", mcp.Description("Subresource the request targets, e.g. status or scale (omit for the resource itself). A policy scoped to the resource does not cover its subresources, and the reverse, so this changes which policies match")),
		mcp.WithString("operation", mcp.Description("Admission operation to check: CREATE, UPDATE, or CONNECT (default CREATE)")),
		mcp.WithBoolean("cluster_scoped", mcp.Description("Set true for a cluster-scoped resource (namespace is ignored, and any namespaceSelector is treated as non-restricting, matching the Kubernetes API's own documented behavior)")),
	)

	ksServer.s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		name, ok := args["name"].(string)
		if !ok || name == "" {
			return mcp.NewToolResultError("name is required"), nil
		}
		apiVersion, ok := args["api_version"].(string)
		if !ok || apiVersion == "" {
			return mcp.NewToolResultError("api_version is required"), nil
		}
		resource, ok := args["resource"].(string)
		if !ok || resource == "" {
			return mcp.NewToolResultError("resource is required"), nil
		}
		apiGroup, _ := args["api_group"].(string)
		namespace, _ := args["namespace"].(string)
		clusterScoped, _ := args["cluster_scoped"].(bool)

		// A subresource is one path segment: "status", not "pods/status". A
		// caller repeating the parent would otherwise match no rule at all and
		// read as "nothing mutates this".
		subresource, _ := args["subresource"].(string)
		if strings.Contains(subresource, "/") {
			return mcp.NewToolResultError(fmt.Sprintf("subresource must name one subresource without the parent resource (got %q, want e.g. %q)", subresource, "status")), nil
		}

		// A Namespace object is itself cluster-scoped ("Namespace API
		// objects are cluster-scoped", per Rule.Scope's own doc comment)
		// regardless of what the caller passed for cluster_scoped, and its
		// namespaceSelector matching is special (see mapreconcile.ObjectInfo
		// .IsNamespaceObject) -- so this is derived from the real API shape,
		// not trusted from the argument.
		isNamespaceResource := apiGroup == "" && resource == "namespaces"
		effectiveClusterScoped := clusterScoped || isNamespaceResource

		if !effectiveClusterScoped && namespace == "" {
			return mcp.NewToolResultError("namespace is required unless cluster_scoped is true"), nil
		}

		operation := admissionregistrationv1alpha1.Create
		if rawOp, ok := args["operation"].(string); ok && rawOp != "" {
			normalized := strings.ToUpper(rawOp)
			op, known := mutatingAdmissionPolicyOperations[normalized]
			if !known {
				return mcp.NewToolResultError(fmt.Sprintf("operation must be one of CREATE, UPDATE, CONNECT (got %q)", rawOp)), nil
			}
			operation = op
		}

		k8sClient, err := ksServer.getK8sClient()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get k8s client: %v", err)), nil
		}

		policies, bindings, decodeErrs, err := mapreconcile.Collect(ctx, k8sClient)
		if err != nil {
			if errors.Is(err, mapreconcile.ErrUnsupported) {
				return mcp.NewToolResultText(`{"supported":false,"reason":"cluster does not serve MutatingAdmissionPolicy resources"}`), nil
			}
			return mcp.NewToolResultError(fmt.Sprintf("failed to collect MutatingAdmissionPolicy resources: %v", err)), nil
		}

		gvr := schema.GroupVersionResource{Group: apiGroup, Version: apiVersion, Resource: resource}
		dynClient := k8sClient.DynamicClient

		resourceInterface := dynClient.Resource(gvr)
		var obj *unstructured.Unstructured
		var getErr error
		if effectiveClusterScoped {
			obj, getErr = resourceInterface.Get(ctx, name, metav1.GetOptions{})
		} else {
			obj, getErr = resourceInterface.Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		}
		if getErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get resource %s/%s (%s): %v", namespace, name, gvr.String(), getErr)), nil
		}

		info := mapreconcile.ObjectInfo{
			Group:             apiGroup,
			Version:           apiVersion,
			Resource:          resource,
			Subresource:       subresource,
			Name:              name,
			Namespace:         namespace,
			Labels:            obj.GetLabels(),
			Operation:         operation,
			ClusterScoped:     effectiveClusterScoped,
			IsNamespaceObject: isNamespaceResource,
		}

		if !effectiveClusterScoped {
			nsObj, nsErr := dynClient.Resource(namespaceGVR).Get(ctx, namespace, metav1.GetOptions{})
			if nsErr == nil {
				info.NamespaceLabels = nsObj.GetLabels()
				info.NamespaceLabelsKnown = true
			} else if !apierrors.IsNotFound(nsErr) {
				return mcp.NewToolResultError(fmt.Sprintf("failed to get namespace %s: %v", namespace, nsErr)), nil
			}
		}

		idx, indexErrs := mapreconcile.NewIndex(policies, bindings)
		matches := idx.Matches(info)

		result := map[string]any{
			"supported": true,
			"matches":   buildMatchSummaries(matches),
		}
		allWarnings := append(append([]error{}, decodeErrs...), indexErrs...)
		if len(allWarnings) > 0 {
			msgs := make([]string, len(allWarnings))
			for i, e := range allWarnings {
				msgs[i] = e.Error()
			}
			result["decode_warnings"] = msgs
		}

		resBytes, err := json.Marshal(result)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal result: %v", err)), nil
		}
		return mcp.NewToolResultText(string(resBytes)), nil
	})
}

func buildMatchSummaries(matches []mapreconcile.MatchedPolicy) []map[string]any {
	out := make([]map[string]any, 0, len(matches))
	for _, m := range matches {
		mutations := make([]map[string]any, 0, len(m.Mutations))
		for _, mut := range m.Mutations {
			mutations = append(mutations, map[string]any{
				"patch_type": string(mut.PatchType),
				"expression": mut.Expression,
			})
		}
		out = append(out, map[string]any{
			"policy_name":    m.PolicyName,
			"binding_name":   m.BindingName,
			"mutations":      mutations,
			"failure_policy": string(m.FailurePolicy),
			"has_params":     m.HasParams,
			"determinable":   m.Determinable,
		})
	}
	return out
}
