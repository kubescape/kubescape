package cautils

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
)

// EnterClusterContext switches the active kube context to targetContext and returns a
// leave function that restores whatever context was active before this call.
//
// Callers running a sequence of single-cluster scans in one process (e.g. a fleet scan
// over several kubeconfig contexts) must defer leave() immediately, before running the
// scan against targetContext, not call it after the scan returns: a scan that errors,
// panics, or returns early must still restore the previous context, and deferring before
// the scan runs is what guarantees that regardless of how it exits.
//
// k8sinterface.SetClusterContextName invalidates the cached client config and connection
// state for the previous context on any actual context change, and NewKubernetesApi
// refreshes the API discovery snapshot from the live discovery client it is given, so
// entering a new context here is enough for the next scan built against it (via
// k8sinterface.NewKubernetesApi) to see that cluster's own config and resources rather
// than a previous cluster's leftover state.
func EnterClusterContext(targetContext string) (leave func()) {
	previous := k8sinterface.GetContextName()
	k8sinterface.SetClusterContextName(targetContext)
	return func() {
		k8sinterface.SetClusterContextName(previous)
	}
}
