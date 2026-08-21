package printer

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicyReportPrinter(t *testing.T) {
	pp := NewPolicyReportPrinter()
	assert.NotNil(t, pp)
	assert.Nil(t, pp.writer)
}

func TestCloseWriter_PolicyReport(t *testing.T) {
	pp := NewPolicyReportPrinter()
	require.NoError(t, pp.SetWriter(context.TODO(), ""))
	assert.NotNil(t, pp.writer)
	assert.NoError(t, pp.CloseWriter())
}

// Regression for issue-3407: PolicyReportPrinter previously implemented the
// void CloseWriter() signature every other v2 printer moved away from in
// #3214, so a real close failure had no way to reach the caller. CloseWriter
// must now return the error, matching every sibling printer.
func TestCloseWriter_PolicyReport_ReturnsCloseError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "policyreport-*.yaml")
	require.NoError(t, err)
	require.NoError(t, f.Close()) // pre-close so the printer's own Close() call fails

	pp := &PolicyReportPrinter{writer: f}
	err = pp.CloseWriter()

	require.Error(t, err, "a genuine close failure must be surfaced, not silently discarded")
	assert.ErrorIs(t, err, os.ErrClosed)
}

func TestCloseWriter_PolicyReport_NilWriter(t *testing.T) {
	pp := NewPolicyReportPrinter()
	assert.NoError(t, pp.CloseWriter())
}

func TestCloseWriter_PolicyReport_Stdout(t *testing.T) {
	pp := &PolicyReportPrinter{writer: os.Stdout}
	assert.NoError(t, pp.CloseWriter(), "must never close stdout")
}
