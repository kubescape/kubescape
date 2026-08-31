package core

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforceBaseline_NoBaselineConfiguredIsNoOp(t *testing.T) {
	results := &resultshandling.ResultsHandler{ScanData: cautils.NewOPASessionObjMock()}
	newFailures, err := EnforceBaseline(context.Background(), results, &cautils.ScanInfo{})
	require.NoError(t, err)
	assert.Zero(t, newFailures)
}

func TestEnforceBaseline_MissingResultsReturnsError(t *testing.T) {
	_, err := EnforceBaseline(context.Background(), nil, &cautils.ScanInfo{Baseline: "some-baseline.json"})
	assert.Error(t, err)
}

// Regression for issue-3409: writeBaselineHeadReport previously ignored
// JsonPrinter.SetWriter's error, so a genuine failure to open the temp head
// report surfaced only as ActionPrint's generic write error - losing the
// specific "open output file <path>: <reason>" context SetWriter itself
// reports. This reproduces the exact call sequence writeBaselineHeadReport
// runs (SetWriter, then ActionPrint) against the real JsonPrinter, on a path
// that makes SetWriter fail with a real OS-level error, and confirms
// SetWriter's own error is now what a caller checking it (as
// writeBaselineHeadReport now does) actually sees.
func TestScratchRepro_SetWriterErrorIsNoLongerDiscarded(t *testing.T) {
	jsonPrinter := printerv2.NewJsonPrinter()

	setWriterErr := jsonPrinter.SetWriter(context.Background(), "/tmp/bad\x00path.json")
	require.Error(t, setWriterErr, "SetWriter must fail for this repro to be meaningful")
	assert.Contains(t, setWriterErr.Error(), "open output file",
		"SetWriter's own error names the path it tried to open - exactly the context writeBaselineHeadReport now preserves by checking this return value instead of discarding it")
}
