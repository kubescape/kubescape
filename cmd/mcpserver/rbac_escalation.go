package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
	"github.com/mark3labs/mcp-go/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var roleGVR = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}
var clusterRoleGVR = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}
var roleBindingGVR = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}
var clusterRoleBindingGVR = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}
var serviceAccountGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}

// createRBACEscalationTools registers analyze_rbac_escalation_paths, which
// reports every privilege-escalation technique reachable from a starting
// RBAC identity (ServiceAccount, User, or Group): every other identity it
// can assume, and whether it can reach full cluster-admin-equivalent power,
// via the graph model in core/pkg/rbacgraph. See that package's doc comment
// for the escalation primitives modeled and its trust model.
//
// Unlike this repo's other exposure/reachability MCP tools, RBAC objects
// are always collected cluster-wide, not scoped to a single namespace: an
// escalation edge can lead into any namespace (a ServiceAccount can be
// impersonated, assigned via pod creation, or have its token minted from
// any namespace a subject holds the right primitive in), so a
// namespace-scoped collection would silently hide real paths the same way
// the namespace-scoped Gateway listing bug in analyze_service_exposure did
// before it was fixed.
func createRBACEscalationTools(ksServer *KubescapeMcpserver) {
	tool := mcp.NewTool(
		"analyze_rbac_escalation_paths",
		mcp.WithDescription("Determine every privilege-escalation path reachable from a starting RBAC identity (ServiceAccount, User, or Group) via graph analysis of the cluster's Roles/ClusterRoles/RoleBindings/ClusterRoleBindings -- not just a single-object posture check. Detects impersonation, the escalate/bind verb self-escalation-prevention bypasses, gaining a ServiceAccount's token by scheduling a Pod as it, and minting a ServiceAccount token directly via the TokenRequest API, chained across multiple hops. Reports every other identity reachable and whether cluster-admin-equivalent power is reachable at all, however indirectly."),
		mcp.WithString("subject_kind", mcp.Required(), mcp.Description("Kind of the starting identity: ServiceAccount, User, or Group")),
		mcp.WithString("namespace", mcp.Description("Namespace of the starting ServiceAccount (required when subject_kind is ServiceAccount; ignored otherwise)")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of the starting identity")),
	)

	ksServer.s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		subjectKindStr, _ := args["subject_kind"].(string)
		name, ok := args["name"].(string)
		if !ok || name == "" {
			return mcp.NewToolResultError("name is required"), nil
		}
		namespace, _ := args["namespace"].(string)

		var kind rbacgraph.SubjectKind
		switch subjectKindStr {
		case string(rbacgraph.KindServiceAccount):
			kind = rbacgraph.KindServiceAccount
			if namespace == "" {
				return mcp.NewToolResultError("namespace is required when subject_kind is ServiceAccount"), nil
			}
		case string(rbacgraph.KindUser):
			kind = rbacgraph.KindUser
		case string(rbacgraph.KindGroup):
			kind = rbacgraph.KindGroup
		default:
			return mcp.NewToolResultError(fmt.Sprintf("subject_kind must be one of ServiceAccount, User, Group; got %q", subjectKindStr)), nil
		}

		k8sClient, err := ksServer.getK8sClient()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get k8s client: %v", err)), nil
		}

		resources, err := listRBACResources(ctx, k8sClient.DynamicClient)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		roles, clusterRoles, roleBindings, clusterRoleBindings, serviceAccounts, decodeErrs := rbacgraph.FromResources(resources)
		idx := rbacgraph.NewIndex(roles, clusterRoles, roleBindings, clusterRoleBindings, serviceAccounts)

		start := rbacgraph.Subject{Kind: kind, Namespace: namespace, Name: name}
		result := idx.AnalyzeEscalation(start)

		out := map[string]any{
			"subject":                  start.String(),
			"cluster_admin_equivalent": result.ClusterAdmin,
			"reached":                  buildReachedSummaries(result.Reached),
			"unbounded_findings":       buildUnboundedSummaries(result.Unbounded),
		}
		if result.Truncated {
			out["truncated"] = "the search hit its safety bound before confirming cluster_admin_equivalent one way or the other -- this result may be an incomplete negative, not a confirmed one"
		}
		if len(decodeErrs) > 0 {
			msgs := make([]string, len(decodeErrs))
			for i, e := range decodeErrs {
				msgs[i] = e.Error()
			}
			out["decode_warnings"] = msgs
		}

		resBytes, err := json.Marshal(out)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal result: %v", err)), nil
		}
		return mcp.NewToolResultText(string(resBytes)), nil
	})
}

// listRBACResources collects every Role, ClusterRole, RoleBinding,
// ClusterRoleBinding, and ServiceAccount in the cluster. All five GVRs are
// core Kubernetes API types always served by every cluster (unlike the
// Gateway API), so any list error here is fatal, not a missing-API signal
// to swallow. Roles and RoleBindings are namespaced but listed without a
// namespace filter (cluster-wide), same reasoning as the Gateway/HTTPRoute
// listing fix in analyze_service_exposure: an escalation edge can name a
// ServiceAccount or Role in any namespace.
func listRBACResources(ctx context.Context, dynClient dynamic.Interface) (map[string]workloadinterface.IMetadata, error) {
	gvrs := []schema.GroupVersionResource{roleGVR, clusterRoleGVR, roleBindingGVR, clusterRoleBindingGVR, serviceAccountGVR}
	resources := map[string]workloadinterface.IMetadata{}
	for _, gvr := range gvrs {
		list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list %s objects: %w", gvr.Resource, err)
		}
		for i := range list.Items {
			w := workloadinterface.NewWorkloadObj(list.Items[i].Object)
			resources[w.GetID()] = w
		}
	}
	return resources, nil
}

func buildReachedSummaries(paths []rbacgraph.EscalationPath) []map[string]any {
	out := make([]map[string]any, 0, len(paths))
	for _, p := range paths {
		if len(p.Edges) == 0 {
			continue
		}
		last := p.Edges[len(p.Edges)-1]
		hops := make([]map[string]any, 0, len(p.Edges))
		for _, e := range p.Edges {
			hops = append(hops, map[string]any{
				"primitive": string(e.Primitive),
				"detail":    e.Detail,
			})
		}
		var subject string
		if last.ToSubject != nil {
			subject = last.ToSubject.String()
		}
		out = append(out, map[string]any{
			"subject": subject,
			"path":    hops,
		})
	}
	return out
}

func buildUnboundedSummaries(findings []rbacgraph.UnboundedFinding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		scope := f.Edge.Scope
		if scope == "" {
			scope = "cluster-wide"
		}
		out = append(out, map[string]any{
			"subject":   f.Subject.String(),
			"primitive": string(f.Edge.Primitive),
			"detail":    f.Edge.Detail,
			"scope":     scope,
		})
	}
	return out
}
