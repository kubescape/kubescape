package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	"github.com/mark3labs/mcp-go/mcp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var networkPolicyGVR = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
var namespaceGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
var podGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

// createNetworkReachabilityTools registers analyze_network_reachability, a
// real reachability query (not a policy-existence check) answering whether
// a specific source pod can reach a specific destination pod, evaluating
// every NetworkPolicy in the cluster the same way the Kubernetes API's own
// semantics compose them. See core/pkg/networkpolicy for the model.
func createNetworkReachabilityTools(ksServer *KubescapeMcpserver) {
	tool := mcp.NewTool(
		"analyze_network_reachability",
		mcp.WithDescription("Determine whether a specific source pod can reach a specific destination pod (optionally on a given port/protocol), by evaluating every NetworkPolicy in the cluster together -- not just whether a blocking policy exists. Reports allowed, denied, or unknown (when a rule cannot be resolved statically, e.g. a named container port or an IP-block peer) with the specific policy responsible."),
		mcp.WithString("source_namespace", mcp.Required(), mcp.Description("Namespace of the source pod")),
		mcp.WithString("source_pod", mcp.Required(), mcp.Description("Name of the source pod")),
		mcp.WithString("destination_namespace", mcp.Required(), mcp.Description("Namespace of the destination pod")),
		mcp.WithString("destination_pod", mcp.Required(), mcp.Description("Name of the destination pod")),
		mcp.WithNumber("port", mcp.Description("Destination port to check (optional; omit to check reachability without regard to port)")),
		mcp.WithString("protocol", mcp.Description("Protocol for the port check: TCP, UDP, or SCTP (optional, defaults to TCP)")),
	)

	ksServer.s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		srcNS, ok := args["source_namespace"].(string)
		if !ok || srcNS == "" {
			return mcp.NewToolResultError("source_namespace is required"), nil
		}
		srcName, ok := args["source_pod"].(string)
		if !ok || srcName == "" {
			return mcp.NewToolResultError("source_pod is required"), nil
		}
		dstNS, ok := args["destination_namespace"].(string)
		if !ok || dstNS == "" {
			return mcp.NewToolResultError("destination_namespace is required"), nil
		}
		dstName, ok := args["destination_pod"].(string)
		if !ok || dstName == "" {
			return mcp.NewToolResultError("destination_pod is required"), nil
		}

		var port *networkpolicy.PortSpec
		if raw, ok := args["port"]; ok {
			f, ok := raw.(float64)
			if !ok || f <= 0 || f != float64(int64(f)) {
				return mcp.NewToolResultError("port must be a positive integer"), nil
			}
			proto := corev1.ProtocolTCP
			if rawProto, ok := args["protocol"].(string); ok && rawProto != "" {
				proto = corev1.Protocol(rawProto)
			}
			port = &networkpolicy.PortSpec{Protocol: proto, Port: int32(f)}
		}

		k8sClient, err := ksServer.getK8sClient()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get k8s client: %v", err)), nil
		}
		dynClient := k8sClient.DynamicClient

		policyList, err := dynClient.Resource(networkPolicyGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list NetworkPolicy objects: %v", err)), nil
		}
		namespaceList, err := dynClient.Resource(namespaceGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list Namespace objects: %v", err)), nil
		}
		srcPodObj, err := dynClient.Resource(podGVR).Namespace(srcNS).Get(ctx, srcName, metav1.GetOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get source pod %s/%s: %v", srcNS, srcName, err)), nil
		}
		dstPodObj, err := dynClient.Resource(podGVR).Namespace(dstNS).Get(ctx, dstName, metav1.GetOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get destination pod %s/%s: %v", dstNS, dstName, err)), nil
		}

		resources := make(map[string]workloadinterface.IMetadata, len(policyList.Items)+len(namespaceList.Items))
		for i := range policyList.Items {
			w := workloadinterface.NewWorkloadObj(policyList.Items[i].Object)
			resources[w.GetID()] = w
		}
		for i := range namespaceList.Items {
			w := workloadinterface.NewWorkloadObj(namespaceList.Items[i].Object)
			resources[w.GetID()] = w
		}

		policies, namespaces, decodeErrs := networkpolicy.FromResources(resources)

		idx := networkpolicy.NewIndex(policies, namespaces)

		src := networkpolicy.EndpointFromResource(workloadinterface.NewWorkloadObj(srcPodObj.Object))
		dst := networkpolicy.EndpointFromResource(workloadinterface.NewWorkloadObj(dstPodObj.Object))
		if ip, found := unstructuredNestedString(srcPodObj.Object, "status", "podIP"); found {
			src.IP = ip
		}
		if ip, found := unstructuredNestedString(dstPodObj.Object, "status", "podIP"); found {
			dst.IP = ip
		}

		verdict, egress, ingress := idx.Reaches(src, dst, port)

		result := map[string]any{
			"verdict": verdict.String(),
			"egress": map[string]any{
				"verdict":        egress.Verdict.String(),
				"reason":         egress.Reason,
				"matched_policy": egress.MatchedPolicy,
			},
			"ingress": map[string]any{
				"verdict":        ingress.Verdict.String(),
				"reason":         ingress.Reason,
				"matched_policy": ingress.MatchedPolicy,
			},
		}
		if len(decodeErrs) > 0 {
			msgs := make([]string, len(decodeErrs))
			for i, e := range decodeErrs {
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

// unstructuredNestedString reads a nested string field from an unstructured
// object without pulling in the full unstructured helper package's error
// semantics for a lookup this shallow. found is false if any segment of the
// path is absent or not a string; that is not an error, just "unknown IP,"
// which the caller already treats as an absent IP.
func unstructuredNestedString(obj map[string]any, path ...string) (value string, found bool) {
	cur := any(obj)
	for _, segment := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = m[segment]
		if !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	if !ok {
		return "", false
	}
	return s, true
}
