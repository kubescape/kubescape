package mcpserver

import (
	"context"
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/exposure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// ReferenceGrant is served as v1 from Gateway API v1.5 and as v1beta1 from at
// least v0.7.0; both share one spec shape, so they are interchangeable here.
// The pre-v0.7 v1alpha2 version is not supported.
var referenceGrantGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "referencegrants"}
var referenceGrantGVRv1beta1 = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "referencegrants"}

// collectReferenceGrants lists the cluster's ReferenceGrants for the exposure
// Index, shared by analyze_service_exposure and analyze_vulnerability_exposure.
//
// It returns either an Index option (grants were listed and decoded in full --
// possibly zero of them, which is a real answer: no cross-namespace reference
// is authorized) or a non-empty unavailable reason. The two are mutually
// exclusive. A served-but-failed list (RBAC, connectivity), an API that is not
// served at all, and a grant that cannot be decoded all yield a reason and no
// option, so the Index keeps reporting cross-namespace references as unclear
// rather than treating missing data as "no grants".
func collectReferenceGrants(ctx context.Context, dynClient dynamic.Interface) (opt exposure.Option, unavailable string) {
	var served bool
	resources := map[string]workloadinterface.IMetadata{}
	for _, gvr := range []schema.GroupVersionResource{referenceGrantGVR, referenceGrantGVRv1beta1} {
		list, err := dynClient.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			if isMissingAPIErr(err) {
				continue
			}
			return nil, fmt.Sprintf("ReferenceGrants could not be listed (%s)", classifyScanErrorMessage(classifyScanError(err), "ReferenceGrant", err))
		}
		served = true
		for i := range list.Items {
			w := workloadinterface.NewWorkloadObj(list.Items[i].Object)
			resources[w.GetID()] = w
		}
		break
	}
	if !served {
		return nil, "the ReferenceGrant API is not served by this cluster, so grants could not be collected"
	}
	opt, errs := exposure.ReferenceGrantsOption(resources)
	if len(errs) > 0 {
		return nil, fmt.Sprintf("%d ReferenceGrant(s) could not be decoded (first: %v)", len(errs), errs[0])
	}
	return opt, ""
}

// referenceGrantUnclearNote explains an unclear result. unavailable is the
// collectReferenceGrants reason; it is non-empty whenever unclear is possible.
func referenceGrantUnclearNote(unavailable string) string {
	return "a cross-namespace Gateway API HTTPRoute/GRPCRoute backendRef (or request mirror) references this Service, and whether a ReferenceGrant authorizes it is unknown: " + unavailable + ". An empty paths here is not a confirmed all-clear"
}
