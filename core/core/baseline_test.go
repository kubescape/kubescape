package core

import (
	"context"
	"errors"
	"os"
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

func TestWriteBaselineHeadReport_Success(t *testing.T) {
	results := &resultshandling.ResultsHandler{ScanData: cautils.NewOPASessionObjMock()}
	tmpPath, cleanup, err := writeBaselineHeadReport(context.Background(), results)
	require.NoError(t, err)
	defer cleanup()
	assert.FileExists(t, tmpPath)
}

func TestCloseWriter_ErrorReturnedOnFailedClose(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-close-writer-*.json")
	require.NoError(t, err)
	tmpPath := tmp.Name()
	require.NoError(t, tmp.Close())
	defer os.Remove(tmpPath)

	jsonPrinter := printerv2.NewJsonPrinter()
	err = jsonPrinter.SetWriter(context.Background(), tmpPath)
	require.NoError(t, err)

	// Close the writer once successfully
	err = jsonPrinter.CloseWriter()
	require.NoError(t, err)

	// An explicit subsequent close on the underlying file descriptor returns an error,
	// verifying that CloseWriter preserves and returns errors from the underlying Close call.
	err = jsonPrinter.CloseWriter()
	require.Error(t, err)
}

type failingCloseBaselinePrinter struct {
	baselineReportPrinter
	closeErr    error
	createdFile string
}

func (f *failingCloseBaselinePrinter) SetWriter(ctx context.Context, outputFile string) error {
	f.createdFile = outputFile
	return f.baselineReportPrinter.SetWriter(ctx, outputFile)
}

func (f *failingCloseBaselinePrinter) CloseWriter() error {
	_ = f.baselineReportPrinter.CloseWriter()
	return f.closeErr
}

func TestWriteBaselineHeadReport_CloseWriterError(t *testing.T) {
	expectedErr := errors.New("simulated close failure")
	var injected *failingCloseBaselinePrinter

	origNewPrinter := newBaselineReportPrinter
	defer func() { newBaselineReportPrinter = origNewPrinter }()

	newBaselineReportPrinter = func() baselineReportPrinter {
		injected = &failingCloseBaselinePrinter{
			baselineReportPrinter: printerv2.NewJsonPrinter(),
			closeErr:              expectedErr,
		}
		return injected
	}

	results := &resultshandling.ResultsHandler{ScanData: cautils.NewOPASessionObjMock()}
	path, cleanup, err := writeBaselineHeadReport(context.Background(), results)
	defer cleanup()

	require.ErrorIs(t, err, expectedErr)
	assert.Empty(t, path)
	require.NotNil(t, injected)
	assert.NotEmpty(t, injected.createdFile)
	assert.NoFileExists(t, injected.createdFile)
}
