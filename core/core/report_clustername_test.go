package core

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	printerv2 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
)

// #2841 made scan attribution follow the kubeconfig the scan actually selected,
// via ScanInfo.GetClusterContextName(). #2866 then populated the report's
// clusterName from the process-global k8sinterface.GetContextName() instead.
//
// When --kubeconfig selects a file whose current-context differs from the
// ambient kubeconfig, those two disagree: the tenant config attributes the scan
// to the selected context while the emitted report is labelled with the ambient
// one. A report labelled with the wrong cluster is worse than the empty field
// #2866 replaced, because it looks authoritative.
func TestFinalizeResults_ClusterNameFollowsScanSelectedContext(t *testing.T) {
	ambientPath := writeContextKubeconfig(t, "context-b", "https://b.example")
	explicitPath := writeContextKubeconfig(t, "context-a", "https://a.example")

	t.Setenv("KUBECONFIG", ambientPath)
	ambientConfig, err := clientcmd.LoadFromFile(ambientPath)
	require.NoError(t, err)
	k8sinterface.SetClusterContextName("")
	k8sinterface.SetClientConfigAPI(ambientConfig)
	t.Cleanup(func() {
		k8sinterface.SetClientConfigAPI(nil)
		k8sinterface.SetClusterContextName("")
	})

	// Sanity: the ambient global really does resolve to the other context.
	require.Equal(t, "context-b", k8sinterface.GetContextName())

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

// A scan that made no explicit kubeconfig selection must keep the existing
// behaviour introduced by #2866: fall back to the ambient context name.
func TestFinalizeResults_ClusterNameFallsBackToAmbientContext(t *testing.T) {
	ambientPath := writeContextKubeconfig(t, "context-b", "https://b.example")
	t.Setenv("KUBECONFIG", ambientPath)
	ambientConfig, err := clientcmd.LoadFromFile(ambientPath)
	require.NoError(t, err)
	k8sinterface.SetClusterContextName("")
	k8sinterface.SetClientConfigAPI(ambientConfig)
	t.Cleanup(func() {
		k8sinterface.SetClientConfigAPI(nil)
		k8sinterface.SetClusterContextName("")
	})

	scanInfo := &cautils.ScanInfo{}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	report := printerv2.FinalizeResults(session)

	assert.Equal(t, "context-b", report.ClusterName)
}

// An explicitly supplied cluster name must still win, as before.
func TestFinalizeResults_ClusterNameDoesNotOverwriteExisting(t *testing.T) {
	scanInfo := &cautils.ScanInfo{}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	session.Report.ClusterName = "already-set"

	report := printerv2.FinalizeResults(session)

	assert.Equal(t, "already-set", report.ClusterName)
}
