package mcpserver

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/pss"
	"github.com/mark3labs/mcp-go/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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
// violates, and overall namespace readiness.
func createPSSPredictorTools(ksServer *KubescapeMcpserver) {
	tool := mcp.NewTool(
		"predict_pss_compliance",
		mcp.WithDescription("Predict which workloads in a namespace would fail Pod Security Standards (PSS v1.31) enforcement at a given level (Privileged, Baseline, or Restricted) and report exactly what violates per container. Use this to assess the blast radius before enabling PSS enforcement — answers 'what would break if I enforced Baseline/Restricted on this namespace?' without touching the cluster's admission configuration. Reports namespace-level summary (total/passing/failing/current effective level) and per-workload violation details. Evaluates Deployments, DaemonSets, StatefulSets, ReplicaSets, Jobs, CronJobs, and standalone Pods."),
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

		sort.Slice(selected, func(i, j int) bool {
			if selected[i].GetKind() != selected[j].GetKind() {
				return selected[i].GetKind() < selected[j].GetKind()
			}
			return selected[i].GetName() < selected[j].GetName()
		})

		var (
			totalCount            = len(selected)
			passingCount          = 0
			failingCount          = 0
			unevaluatedCount      = 0
			currentEffectiveLevel = pss.Restricted
			failingWorkloads      = make([]map[string]any, 0)
			decodeWarnings        []string
		)

		for _, item := range selected {
			kind := item.GetKind()
			name := item.GetName()

			res, err := pss.WorkloadResultFromUnstructured(kind, name, namespace, item.Object, targetLevel)
			if err != nil {
				decodeWarnings = append(decodeWarnings, fmt.Sprintf("%s/%s: %v", kind, name, err))
				unevaluatedCount++
				continue
			}

			if res.PassesAt < currentEffectiveLevel {
				currentEffectiveLevel = res.PassesAt
			}

			if len(res.Violations) > 0 {
				failingCount++
				vSummaries := make([]map[string]any, 0, len(res.Violations))
				for _, v := range res.Violations {
					vSummaries = append(vSummaries, map[string]any{
						"check":       v.Check,
						"container":   v.Container,
						"level":       v.Level.String(),
						"description": v.Description,
					})
				}
				failingWorkloads = append(failingWorkloads, map[string]any{
					"kind":       res.Kind,
					"name":       res.Name,
					"violations": vSummaries,
					"passes_at":  res.PassesAt.String(),
				})
			} else {
				passingCount++
			}
		}

		summary := map[string]any{
			"total_workloads":         totalCount,
			"passing":                 passingCount,
			"failing":                 failingCount,
			"current_effective_level": currentEffectiveLevel.String(),
		}
		if unevaluatedCount > 0 {
			summary["unevaluated"] = unevaluatedCount
			summary["current_effective_level_complete"] = false
		}

		result := map[string]any{
			"namespace":         namespace,
			"target_level":      targetLevel.String(),
			"summary":           summary,
			"failing_workloads": failingWorkloads,
		}

		if len(decodeWarnings) > 0 {
			result["decode_warnings"] = decodeWarnings
		}

		resBytes, err := jsonMarshal(result)
		if err != nil {
			return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal result: %v", err), nil), nil
		}
		return mcp.NewToolResultText(string(resBytes)), nil
	})
}

func listPSSWorkloads(ctx context.Context, dynClient dynamic.Interface, namespace string, targets []pssWorkloadTarget) ([]unstructured.Unstructured, *mcp.CallToolResult) {
	var all []unstructured.Unstructured
	for _, target := range targets {
		list, err := dynClient.Resource(target.gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, mcpToolError(classifyScanError(err),
				fmt.Sprintf("failed to list %s objects: %v", target.kind, err),
				map[string]any{"resource_type": target.kind, "namespace": namespace})
		}
		for i := range list.Items {
			if list.Items[i].GetKind() == "" {
				list.Items[i].SetKind(target.kind)
			}
			all = append(all, list.Items[i])
		}
	}
	return all, nil
}

// deduplicateWorkloads filters workloads for namespace-wide scans, deduplicating child
// workloads (e.g., ReplicaSets and Pods) only when an evaluated supported ancestor
// actually represents the workload. Custom-owned workloads (e.g., Deployments or Pods
// managed by CRD operators) and workloads whose controller owners are absent from the
// scan are retained as roots.
func deduplicateWorkloads(workloads []unstructured.Unstructured) []unstructured.Unstructured {
	byUID := make(map[types.UID]int, len(workloads))
	byKindName := make(map[string]int, len(workloads))

	for i, w := range workloads {
		if uid := w.GetUID(); uid != "" {
			byUID[uid] = i
		}
		key := fmt.Sprintf("%s/%s", strings.ToLower(w.GetKind()), w.GetName())
		byKindName[key] = i
	}

	var selected []unstructured.Unstructured
	for i, w := range workloads {
		if hasEvaluatedAncestor(i, workloads, byUID, byKindName) {
			continue
		}
		selected = append(selected, w)
	}
	return selected
}

func getControllerRef(obj unstructured.Unstructured) *metav1.OwnerReference {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			r := ref
			return &r
		}
	}
	return nil
}

func findParentInWorkloads(ref metav1.OwnerReference, workloads []unstructured.Unstructured, byUID map[types.UID]int, byKindName map[string]int) (int, bool) {
	if ref.UID != "" {
		if idx, ok := byUID[ref.UID]; ok {
			if strings.EqualFold(workloads[idx].GetKind(), ref.Kind) {
				return idx, true
			}
		}
	}
	key := fmt.Sprintf("%s/%s", strings.ToLower(ref.Kind), ref.Name)
	if idx, ok := byKindName[key]; ok {
		parent := workloads[idx]
		if ref.UID != "" && parent.GetUID() != "" && ref.UID != parent.GetUID() {
			return -1, false
		}
		return idx, true
	}
	return -1, false
}

func hasEvaluatedAncestor(idx int, workloads []unstructured.Unstructured, byUID map[types.UID]int, byKindName map[string]int) bool {
	visited := make(map[int]int) // workload index -> step in traversal path
	var path []int

	curr := idx
	for {
		if step, seen := visited[curr]; seen {
			// Cycle detected in ancestor chain. Designate the lowest index in the cycle
			// as the evaluated root so that cyclic workloads are not dropped entirely.
			cycle := path[step:]
			minIdx := cycle[0]
			for _, c := range cycle[1:] {
				if c < minIdx {
					minIdx = c
				}
			}
			return idx != minIdx
		}

		visited[curr] = len(path)
		path = append(path, curr)

		ref := getControllerRef(workloads[curr])
		if ref == nil {
			// No controller parent. If curr != idx, curr is the evaluated root ancestor.
			return curr != idx
		}

		parentIdx, found := findParentInWorkloads(*ref, workloads, byUID, byKindName)
		if !found {
			// Controller parent is an unsupported kind (custom resource) or absent from the scan.
			// If curr != idx, curr is the evaluated root ancestor.
			return curr != idx
		}

		curr = parentIdx
	}
}
