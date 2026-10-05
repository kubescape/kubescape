package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/pss"
	"github.com/mark3labs/mcp-go/mcp"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	deploymentGVR  = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	daemonSetGVR   = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
	statefulSetGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
	replicaSetGVR  = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	jobGVR         = schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}
	cronJobGVR     = schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}
)

type pssWorkloadTarget struct {
	gvr  schema.GroupVersionResource
	kind string
}

var pssWorkloadTargets = []pssWorkloadTarget{
	{gvr: deploymentGVR, kind: "Deployment"},
	{gvr: daemonSetGVR, kind: "DaemonSet"},
	{gvr: statefulSetGVR, kind: "StatefulSet"},
	{gvr: replicaSetGVR, kind: "ReplicaSet"},
	{gvr: jobGVR, kind: "Job"},
	{gvr: cronJobGVR, kind: "CronJob"},
	{gvr: podGVR, kind: "Pod"},
}

// createPSSPredictorTools registers predict_pss_compliance, which evaluates
// workloads in a namespace against Kubernetes Pod Security Standards (Privileged,
// Baseline, Restricted) and reports which workloads would fail, what specifically
// violates, and overall namespace readiness. The description names the policy
// version through pss.PolicyVersion, since the verdicts come from that package.
func createPSSPredictorTools(ksServer *KubescapeMcpserver) {
	tool := mcp.NewTool(
		"predict_pss_compliance",
		mcp.WithDescription("Predict which workloads in a namespace would fail Pod Security Standards (PSS "+pss.PolicyVersion+") enforcement at a given level (Privileged, Baseline, or Restricted) and report exactly what violates per container. Use this to assess the blast radius before enabling PSS enforcement — answers 'what would break if I enforced Baseline/Restricted on this namespace?' without touching the cluster's admission configuration. Reports namespace-level summary (total/passing/failing/current effective level) and per-workload violation details. Evaluates Deployments, DaemonSets, StatefulSets, ReplicaSets, Jobs, CronJobs, and standalone Pods."),
		mcp.WithString("namespace", mcp.Required(), mcp.Description("Namespace to analyze")),
		mcp.WithString("level", mcp.Description("Target PSS level: Privileged, Baseline, or Restricted (optional; defaults to Restricted)")),
		mcp.WithString("workload_name", mcp.Description("Name of a specific workload to check (optional; omit to report on every workload in the namespace)")),
	)

	ksServer.s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		namespace, toolErr := mcpRequiredStringArg(args, "namespace")
		if toolErr != nil {
			return toolErr, nil
		}

		levelStr, toolErr := mcpStringArg(args, "level")
		if toolErr != nil {
			return toolErr, nil
		}
		targetLevel := pss.Restricted
		if levelStr != "" {
			parsedLevel, ok := pss.ParseLevel(levelStr)
			if !ok {
				return mcpToolError(ErrCodeInvalidArgument,
					fmt.Sprintf("invalid PSS level %q; must be one of Privileged, Baseline, Restricted", levelStr),
					map[string]any{"argument": "level", "supported_values": []string{"Privileged", "Baseline", "Restricted"}}), nil
			}
			targetLevel = parsedLevel
		}

		workloadName, toolErr := mcpStringArg(args, "workload_name")
		if toolErr != nil {
			return toolErr, nil
		}

		k8sClient, err := ksServer.getK8sClient()
		if err != nil {
			return mcpToolError(ErrCodeK8sClientError, fmt.Sprintf("failed to get k8s client: %v", err), nil), nil
		}
		dynClient := k8sClient.DynamicClient

		listTargets := pssWorkloadTargets
		var filterKind, filterName string
		if workloadName != "" {
			if strings.Contains(workloadName, "/") {
				parts := strings.SplitN(workloadName, "/", 2)
				filterKind = strings.TrimSpace(parts[0])
				filterName = strings.TrimSpace(parts[1])
				if filterKind != "" {
					listTargets = nil
					for _, target := range pssWorkloadTargets {
						if strings.EqualFold(target.kind, filterKind) {
							listTargets = []pssWorkloadTarget{target}
							break
						}
					}
				}
			} else {
				filterName = workloadName
			}
		}

		workloads, listToolErr := listPSSWorkloads(ctx, dynClient, namespace, listTargets)
		if listToolErr != nil {
			return listToolErr, nil
		}

		var selected []unstructured.Unstructured
		if workloadName != "" {
			for _, w := range workloads {
				nameMatches := w.GetName() == filterName
				kindMatches := filterKind == "" || strings.EqualFold(w.GetKind(), filterKind)
				if nameMatches && kindMatches {
					selected = append(selected, w)
				}
			}

			if len(selected) == 0 {
				return mcpToolError(ErrCodeResourceNotFound,
					fmt.Sprintf("workload %q not found in namespace %q", workloadName, namespace),
					map[string]any{"argument": "workload_name", "namespace": namespace, "workload_name": workloadName}), nil
			}
		} else {
			selected = deduplicateWorkloads(workloads)
		}

		nsResult := pss.Aggregate(namespace, selected, targetLevel)
		result := nsResult.ToMap()

		resBytes, err := jsonMarshal(result)
		if err != nil {
			return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal result: %v", err), nil), nil
		}
		return mcp.NewToolResultText(string(resBytes)), nil
	})
}

func listPSSWorkloads(ctx context.Context, dynClient dynamic.Interface, namespace string, targets []pssWorkloadTarget) ([]unstructured.Unstructured, *mcp.CallToolResult) {
	pssTargets := make([]pss.WorkloadTarget, len(targets))
	for i, t := range targets {
		pssTargets[i] = pss.WorkloadTarget{GVR: t.gvr, Kind: t.kind}
	}
	workloads, err := pss.FetchNamespaceWorkloads(ctx, dynClient, namespace, pssTargets)
	if err != nil {
		var listErr *pss.ListResourceError
		if errors.As(err, &listErr) {
			return nil, mcpToolError(classifyScanError(listErr.Err),
				fmt.Sprintf("failed to list %s objects: %v", listErr.Kind, listErr.Err),
				map[string]any{"resource_type": listErr.Kind, "namespace": namespace})
		}
		return nil, mcpToolError(classifyScanError(err), fmt.Sprintf("failed to list workloads: %v", err), nil)
	}
	return workloads, nil
}

func deduplicateWorkloads(workloads []unstructured.Unstructured) []unstructured.Unstructured {
	return pss.DeduplicateWorkloads(workloads)
}
