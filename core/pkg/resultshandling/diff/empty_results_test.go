package diff

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// noResultsReport is what `kubescape scan --format json` writes when no
// control matched any scanned resource (for example a control scan of
// manifests that contain none of the kinds it checks): the printer writes the
// results key only when there is at least one result, as PostureReport's own
// `results,omitempty` tag does.
const noResultsReport = `{"generationTime":"2026-11-10T11:31:19Z","clusterAPIServerInfo":null,"clusterCloudProvider":"","customerGUID":"","clusterName":"","reportGUID":"","summaryDetails":{"controls":{"C-0035":{"statusInfo":{},"controlID":"C-0035","name":"Administrative Roles","status":"","scoreFactor":6,"severity":"Medium"}},"status":"","frameworks":null},"attributes":null,"metadata":{"targetMetadata":{},"clusterMetadata":{},"scanMetadata":{}}}`

func TestCompute_ReportWithoutResultsHasNoFailures(t *testing.T) {
	head := scanReport{
		Results: []resultEntry{makeResult("rbac.authorization.k8s.io/v1//ClusterRole/admin",
			makeControl("C-0035", "Administrative Roles", "failed"))},
		SummaryDetails: summaryDetails{Controls: map[string]controlSummary{"C-0035": {Severity: "Medium"}}},
	}

	cs, err := Compute(writeRawReport(t, noResultsReport), writeTempReport(t, head))
	require.NoError(t, err)
	require.Len(t, cs.New, 1)
	require.Equal(t, "C-0035", cs.New[0].ControlID)
	require.Empty(t, cs.Resolved)

	cs, err = Compute(writeTempReport(t, head), writeRawReport(t, noResultsReport))
	require.NoError(t, err)
	require.Len(t, cs.Resolved, 1)
	require.Empty(t, cs.New)
}
