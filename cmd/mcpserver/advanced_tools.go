package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/mark3labs/mcp-go/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func createAdvancedTools(ksServer *KubescapeMcpserver) {
	// Tool 1: scan_resource_slice
	scanResourceSliceTool := mcp.NewTool(
		"scan_resource_slice",
		mcp.WithDescription("Scan a slice of resources to support granular, token-budgeted chunks. Used to avoid overloading context windows for large clusters."),
		mcp.WithString("resource_kind", mcp.Required(), mcp.Description("Kind of resource (e.g. pods, deployments)")),
		mcp.WithString("namespace", mcp.Description("Namespace (optional, defaults to all)")),
		mcp.WithNumber("limit", mcp.Description("Number of resources to fetch in this slice (default 10)")),
		mcp.WithString("continue", mcp.Description("Continue token for pagination (optional)")),
	)

	ksServer.s.AddTool(scanResourceSliceTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		kind, ok := args["resource_kind"].(string)
		if !ok || kind == "" {
			return mcp.NewToolResultError("resource_kind is required"), nil
		}
		namespace, _ := args["namespace"].(string)

		limit := int64(10)
		if l, ok := args["limit"].(float64); ok {
			limit = int64(l)
		}
		continueToken, _ := args["continue"].(string)

		k8sClient, err := ksServer.getK8sClient()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get k8s client: %v", err)), nil
		}

		// Simplified mapping for common kinds, to support granular resource fetching
		var gvr schema.GroupVersionResource
		switch strings.ToLower(kind) {
		case "pods", "pod":
			gvr = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
		case "deployments", "deployment":
			gvr = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
		case "daemonsets", "daemonset":
			gvr = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
		case "statefulsets", "statefulset":
			gvr = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
		default:
			// Defaulting to try core v1
			gvr = schema.GroupVersionResource{Group: "", Version: "v1", Resource: strings.ToLower(kind)}
		}

		listOpts := metav1.ListOptions{
			Limit:    limit,
			Continue: continueToken,
		}

		dynClient := k8sClient.DynamicClient
		var list *unstructured.UnstructuredList
		if namespace != "" {
			list, err = dynClient.Resource(gvr).Namespace(namespace).List(ctx, listOpts)
		} else {
			list, err = dynClient.Resource(gvr).List(ctx, listOpts)
		}

		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list resources: %v", err)), nil
		}

		nextContinueToken := list.GetContinue()

		// strip out noisy fields to save tokens
		var simplifiedItems []map[string]any
		for _, item := range list.Items {
			simplifiedItems = append(simplifiedItems, map[string]any{
				"apiVersion": item.GetAPIVersion(),
				"kind":       item.GetKind(),
				"metadata": map[string]any{
					"name":      item.GetName(),
					"namespace": item.GetNamespace(),
				},
				"spec": item.Object["spec"],
			})
		}

		result := map[string]any{
			"resources": simplifiedItems,
			"continue":  nextContinueToken,
			"count":     len(simplifiedItems),
		}

		resBytes, _ := json.Marshal(result)
		return mcp.NewToolResultText(string(resBytes)), nil
	})

	// Tool 2: evaluate_cel_rule
	evaluateCelRuleTool := mcp.NewTool(
		"evaluate_cel_rule",
		mcp.WithDescription("Evaluate a CEL (Common Expression Language) rule against a JSON resource object."),
		mcp.WithString("cel_expression", mcp.Required(), mcp.Description("The CEL expression to evaluate (e.g. 'object.metadata.name == \"test\"')")),
		mcp.WithString("resource_json", mcp.Required(), mcp.Description("The JSON representation of the resource to evaluate against")),
	)

	ksServer.s.AddTool(evaluateCelRuleTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		celExpr, ok := args["cel_expression"].(string)
		if !ok || celExpr == "" {
			return mcp.NewToolResultError("cel_expression is required"), nil
		}
		resourceJSON, ok := args["resource_json"].(string)
		if !ok || resourceJSON == "" {
			return mcp.NewToolResultError("resource_json is required"), nil
		}

		var resourceObj map[string]any
		if err := json.Unmarshal([]byte(resourceJSON), &resourceObj); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to parse resource_json: %v", err)), nil
		}

		env, err := cel.NewEnv(
			cel.Variable("object", cel.DynType),
		)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create CEL env: %v", err)), nil
		}

		ast, issues := env.Compile(celExpr)
		if issues != nil && issues.Err() != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to compile CEL expression: %v", issues.Err())), nil
		}

		prg, err := env.Program(ast)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create CEL program: %v", err)), nil
		}

		out, _, err := prg.Eval(map[string]any{
			"object": resourceObj,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to evaluate CEL rule: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("%v", out.Value())), nil
	})

	// Tool 3: dry_run_remediation
	dryRunRemediationTool := mcp.NewTool(
		"dry_run_remediation",
		mcp.WithDescription("Propose and dry-run a YAML/JSON patch against a cluster resource. Includes strict validation barriers."),
		mcp.WithString("resource_kind", mcp.Required(), mcp.Description("Kind of resource to patch (e.g. pods)")),
		mcp.WithString("namespace", mcp.Description("Namespace of the resource (optional for cluster-scoped)")),
		mcp.WithString("resource_name", mcp.Required(), mcp.Description("Name of the resource to patch")),
		mcp.WithString("patch_json", mcp.Required(), mcp.Description("JSON representation of the patch to apply")),
	)

	ksServer.s.AddTool(dryRunRemediationTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		kind, _ := args["resource_kind"].(string)
		namespace, _ := args["namespace"].(string)
		name, _ := args["resource_name"].(string)
		patchJSON, _ := args["patch_json"].(string)

		if kind == "" || name == "" || patchJSON == "" {
			return mcp.NewToolResultError("resource_kind, resource_name, and patch_json are required"), nil
		}

		// Security/Privilege Drop checks: deny operations on Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, etc.
		restrictedKinds := map[string]bool{
			"role": true, "clusterrole": true, "rolebinding": true, "clusterrolebinding": true,
			"secret": true, "serviceaccount": true,
		}
		if restrictedKinds[strings.ToLower(kind)] {
			return mcp.NewToolResultError(fmt.Sprintf("security barrier: patching kind '%s' is not permitted", kind)), nil
		}

		k8sClient, err := ksServer.getK8sClient()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get k8s client: %v", err)), nil
		}

		var gvr schema.GroupVersionResource
		switch strings.ToLower(kind) {
		case "pods", "pod":
			gvr = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
		case "deployments", "deployment":
			gvr = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
		case "daemonsets", "daemonset":
			gvr = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
		case "statefulsets", "statefulset":
			gvr = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
		default:
			gvr = schema.GroupVersionResource{Group: "", Version: "v1", Resource: strings.ToLower(kind)}
		}

		dynClient := k8sClient.DynamicClient

		patchType := types.StrategicMergePatchType

		var patchedObj *unstructured.Unstructured
		patchOptions := metav1.PatchOptions{
			DryRun: []string{metav1.DryRunAll}, // Dry-Run barrier
		}

		if namespace != "" {
			patchedObj, err = dynClient.Resource(gvr).Namespace(namespace).Patch(ctx, name, patchType, []byte(patchJSON), patchOptions)
		} else {
			patchedObj, err = dynClient.Resource(gvr).Patch(ctx, name, patchType, []byte(patchJSON), patchOptions)
		}

		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("dry-run patch failed: %v", err)), nil
		}

		resBytes, _ := json.Marshal(patchedObj.Object)
		return mcp.NewToolResultText(string(resBytes)), nil
	})
}
