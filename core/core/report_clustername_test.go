package core

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setAmbientContext pins the process-global context name so these tests do not
// depend on the machine having a kubeconfig. k8sinterface.GetContextName()
// returns clusterContextName when it is set, and only falls back to loading a
// kubeconfig otherwise — which yields "" on a CI runner.
func setAmbientContext(t *testing.T, name string) {
	t.Helper()
	original := k8sinterface.GetContextName()
	t.Cleanup(func() { k8sinterface.SetClusterContextName(original) })
	k8sinterface.SetClusterContextName(name)
	require.Equal(t, name, k8sinterface.GetContextName())
}

// #2841 made scan attribution follow the kubeconfig the scan selected, via
// ScanInfo.GetClusterContextName(), and records it on the session metadata.
// #2866 merged 22 minutes later and populated the report's clusterName from
// the process-global k8sinterface.GetContextName() instead.
//
// When --kubeconfig or --kube-context selects a context other than the ambient
// one, those disagree: the tenant config attributes the scan to the selected
// context while the emitted report is labelled with the ambient one. A report
// labelled with the wrong cluster is worse than the empty field #2866
// replaced, because it looks authoritative.
func TestFinalizeResults_ClusterNameFollowsScanSelectedContext(t *testing.T) {
	setAmbientContext(t, "context-b")

	explicitPath := writeContextKubeconfig(t, "context-a", "https://a.example")
	scanInfo := &cautils.ScanInfo{}
	scanInfo.SetKubeconfigSelection(explicitPath, "")
	require.NoError(t, scanInfo.ResolveClusterContextName())
	require.Equal(t, "context-a", scanInfo.GetClusterContextName(),
		"the scan selected context-a via --kubeconfig")

	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	report := printerv2.FinalizeResults(session)

	assert.Equal(t, "context-a", report.ClusterName,
		"the report must be labelled with the context the scan actually used, not the ambient one")
}

// The same holds for an explicit --kube-context override.
func TestFinalizeResults_ClusterNameFollowsContextOverride(t *testing.T) {
	setAmbientContext(t, "context-b")

	multiPath := writeContextKubeconfig(t, "context-a", "https://a.example")
	scanInfo := &cautils.ScanInfo{}
	scanInfo.SetKubeconfigSelection(multiPath, "context-a")
	require.NoError(t, scanInfo.ResolveClusterContextName())

	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	report := printerv2.FinalizeResults(session)

	assert.Equal(t, "context-a", report.ClusterName)
}

// A scan that made no explicit kubeconfig selection must keep the behaviour
// #2866 introduced: fall back to the ambient context name.
func TestFinalizeResults_ClusterNameFallsBackToAmbientContext(t *testing.T) {
	setAmbientContext(t, "context-b")

	scanInfo := &cautils.ScanInfo{}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	report := printerv2.FinalizeResults(session)

	assert.Equal(t, "context-b", report.ClusterName)
}

// An already-populated cluster name must still win, as #2866 established.
func TestFinalizeResults_ClusterNameDoesNotOverwriteExisting(t *testing.T) {
	setAmbientContext(t, "context-b")

	scanInfo := &cautils.ScanInfo{}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	session.Report.ClusterName = "already-set"

	report := printerv2.FinalizeResults(session)

	assert.Equal(t, "already-set", report.ClusterName)
}
