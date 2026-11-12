package printer

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setAmbientContext(t *testing.T, name string) {
	t.Helper()
	previous := k8sinterface.GetContextName()
	k8sinterface.SetClusterContextName(name)
	t.Cleanup(func() { k8sinterface.SetClusterContextName(previous) })
}

// A file, directory or repository scan never connects to a cluster, so its
// report must not be labelled with whatever context the user's kubeconfig
// happens to select. That ambient name also bypassed --hide and --encrypt,
// which only transform the cluster metadata a scan recorded.
func TestScanContextName_NonClusterScanDoesNotReportAmbientContext(t *testing.T) {
	setAmbientContext(t, "prod-ambient-context")

	targets := map[string]reporthandlingv2.ScanningTarget{
		"file":      reporthandlingv2.File,
		"directory": reporthandlingv2.Directory,
		"repo":      reporthandlingv2.Repo,
		"git-local": reporthandlingv2.GitLocal,
	}
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			session := cautils.NewOPASessionObjMock()
			session.Metadata.ScanMetadata.ScanningTarget = target

			assert.Empty(t, scanContextName(session))

			var output bytes.Buffer
			require.NoError(t, writeConfigurationJSON(&output, session, nil))
			var doc PostureReportWithSeverity
			require.NoError(t, json.Unmarshal(output.Bytes(), &doc))
			assert.Empty(t, doc.ClusterName, "JSON header")
			assert.NotContains(t, output.String(), "prod-ambient-context")

			report := FinalizeResults(session)
			require.NotNil(t, report)
			assert.Empty(t, report.ClusterName, "finalized report")
		})
	}
}

// Cluster scans keep reporting their context: the recorded (and, under --hide,
// already anonymized) context first, the ambient one only when none was
// recorded.
func TestScanContextName_ClusterScan(t *testing.T) {
	setAmbientContext(t, "ambient")

	t.Run("recorded context wins", func(t *testing.T) {
		session := cautils.NewOPASessionObjMock()
		session.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Cluster
		session.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{ContextName: "cluster-a1b2c3"}
		assert.Equal(t, "cluster-a1b2c3", scanContextName(session))
	})

	t.Run("falls back to ambient context", func(t *testing.T) {
		session := cautils.NewOPASessionObjMock()
		session.Metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Cluster
		assert.Equal(t, "ambient", scanContextName(session))
	})

	t.Run("no metadata falls back to ambient context", func(t *testing.T) {
		session := cautils.NewOPASessionObjMock()
		session.Metadata = nil
		assert.Equal(t, "ambient", scanContextName(session))
	})
}
