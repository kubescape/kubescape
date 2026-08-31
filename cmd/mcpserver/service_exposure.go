package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/exposure"
	"github.com/mark3labs/mcp-go/mcp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var serviceGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}
var ingressGVR = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}
var httpRouteGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
var gatewayGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}

// createServiceExposureTools registers analyze_service_exposure, which
// reports whether a Service (or every Service in a namespace) is reachable
// from outside the cluster, and by what mechanism -- a Service of type
// LoadBalancer/NodePort directly, or a networking.k8s.io/v1 Ingress or
// Gateway API HTTPRoute naming it as a backend. See core/pkg/exposure for
// the matching model and its documented trust model (existence of an
// exposing object is treated as intent, the same way this repo's
// NetworkPolicy reachability engine treats a NetworkPolicy's existence).
func createServiceExposureTools(ksServer *KubescapeMcpserver) {
	tool := mcp.NewTool(
		"analyze_service_exposure",
		mcp.WithDescription("Determine whether a Service (or every Service in a namespace, if service_name is omitted) is reachable from outside the cluster, and by what mechanism: the Service itself being type LoadBalancer or NodePort, spec.externalIPs being set, a networking.k8s.io/v1 Ingress naming it as a backend, or a Gateway API HTTPRoute naming it as a backend through an attached Gateway. Existence of an exposing object is treated as intent to expose -- this does not verify an Ingress controller or Gateway implementation is actually running. Each Service's result carries an 'unclear' note when a cross-namespace HTTPRoute backendRef (ReferenceGrant-authorized cross-namespace references are not modeled) names it, since in that case an empty paths list is not a confirmed all-clear."),
		mcp.WithString("namespace", mcp.Required(), mcp.Description("Namespace to analyze")),
		mcp.WithString("service_name", mcp.Description("Name of a specific Service to check (optional; omit to report on every Service in the namespace)")),
	)

	ksServer.s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		namespace, ok := args["namespace"].(string)
		if !ok || namespace == "" {
			return mcp.NewToolResultError("namespace is required"), nil
		}
		serviceName, _ := args["service_name"].(string)

		k8sClient, err := ksServer.getK8sClient()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get k8s client: %v", err)), nil
		}
		dynClient := k8sClient.DynamicClient

		serviceList, err := dynClient.Resource(serviceGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list Service objects: %v", err)), nil
		}
		ingressList, err := dynClient.Resource(ingressGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list Ingress objects: %v", err)), nil
		}
		namespaceList, err := dynClient.Resource(namespaceGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list Namespace objects: %v", err)), nil
		}

		resources := make(map[string]workloadinterface.IMetadata, len(serviceList.Items)+len(ingressList.Items)+len(namespaceList.Items))
		for i := range serviceList.Items {
			w := workloadinterface.NewWorkloadObj(serviceList.Items[i].Object)
			resources[w.GetID()] = w
		}
		for i := range ingressList.Items {
			w := workloadinterface.NewWorkloadObj(ingressList.Items[i].Object)
			resources[w.GetID()] = w
		}
		for i := range namespaceList.Items {
			w := workloadinterface.NewWorkloadObj(namespaceList.Items[i].Object)
			resources[w.GetID()] = w
		}

		services, ingresses, namespaces, decodeErrs := exposure.FromResources(resources)

		// The Gateway API CRDs may not be installed on this cluster at all;
		// that is not a tool error, just an empty set of routes/gateways --
		// every service simply reports no ExposureHTTPRoute paths.
		//
		// HTTPRoutes are listed cluster-wide, not scoped to namespace, same as
		// Gateways below: a Service is exposed via any HTTPRoute naming it as
		// a backend, including one that lives in another namespace and
		// reaches in via a ReferenceGrant this package doesn't evaluate.
		// Index.ServiceExposure still only builds an actual ExposurePath from
		// a route in the Service's own namespace (that part is unaffected),
		// but it uses this wider collection to report unclear=true when a
		// cross-namespace backendRef exists that it cannot confirm one way or
		// the other -- collecting only the queried namespace would make that
		// signal silently unreachable.
		gatewayResources := map[string]workloadinterface.IMetadata{}
		routeList, routeErr := dynClient.Resource(httpRouteGVR).List(ctx, metav1.ListOptions{})
		if routeErr != nil && !isMissingAPIErr(routeErr) {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list HTTPRoute objects: %v", routeErr)), nil
		}
		if routeErr == nil {
			for i := range routeList.Items {
				w := workloadinterface.NewWorkloadObj(routeList.Items[i].Object)
				gatewayResources[w.GetID()] = w
			}
		}
		// Gateways are listed cluster-wide, not scoped to namespace: the
		// dominant real-world topology puts the Gateway in an infra
		// namespace (e.g. istio-system) with an HTTPRoute in an app
		// namespace referencing it cross-namespace via parentRefs, and
		// AllowedRoutes deciding whether that attachment is admitted.
		// Scoping this list to namespace would make every such Gateway
		// invisible to idx.routeAttachesToAGateway.
		gwList, gwErr := dynClient.Resource(gatewayGVR).List(ctx, metav1.ListOptions{})
		if gwErr != nil && !isMissingAPIErr(gwErr) {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list Gateway objects: %v", gwErr)), nil
		}
		if gwErr == nil {
			for i := range gwList.Items {
				w := workloadinterface.NewWorkloadObj(gwList.Items[i].Object)
				gatewayResources[w.GetID()] = w
			}
		}
		httpRoutes, gateways, gwDecodeErrs := exposure.FromUnstructuredGatewayAPI(gatewayResources)
		decodeErrs = append(decodeErrs, gwDecodeErrs...)

		idx := exposure.NewIndex(services, ingresses, httpRoutes, gateways, namespaces)

		var targets []string
		if serviceName != "" {
			targets = []string{serviceName}
		} else {
			for _, s := range services {
				targets = append(targets, s.Name)
			}
		}

		findings := make(map[string]any, len(targets))
		for _, name := range targets {
			paths, unclear := idx.ServiceExposure(exposure.ServiceRef{Namespace: namespace, Name: name})
			finding := map[string]any{"paths": buildExposurePathSummaries(paths)}
			if unclear {
				finding["unclear"] = "a cross-namespace Gateway API HTTPRoute backendRef references this Service; whether it is authorized by a ReferenceGrant is not modeled, so an empty paths here is not a confirmed all-clear"
			}
			findings[name] = finding
		}

		result := map[string]any{
			"namespace": namespace,
			"services":  findings,
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

// isMissingAPIErr reports whether err indicates the API group/resource
// itself is not served (e.g. the Gateway API CRDs are not installed on this
// cluster), as opposed to a real query failure. A List against a resource
// the API server does not serve at all returns a NotFound; a List against a
// GVR the dynamic client's RESTMapper has no discovery data for at all
// returns a meta.NoMatchError instead, which does not implement the
// apierrors.APIStatus interface IsNotFound checks.
func isMissingAPIErr(err error) bool {
	return apierrors.IsNotFound(err) || meta.IsNoMatchError(err)
}

func buildExposurePathSummaries(paths []exposure.ExposurePath) []map[string]any {
	out := make([]map[string]any, 0, len(paths))
	for _, p := range paths {
		out = append(out, map[string]any{
			"kind":   p.Kind.String(),
			"source": p.Source,
			"host":   p.Host,
		})
	}
	return out
}
