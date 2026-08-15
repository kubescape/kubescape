package mcpserver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanControls_EmptyInput(t *testing.T) {
	srv := &KubescapeMcpserver{}
	_, err := srv.ScanControls(context.Background(), "", []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one control ID")
}

func TestScanControls_WhitespaceOnlyIDs(t *testing.T) {
	srv := &KubescapeMcpserver{}
	_, err := srv.ScanControls(context.Background(), "", []string{"  ", "\t", ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one control ID")
}

func TestScanControls_TrimsIDs(t *testing.T) {
	srv := &KubescapeMcpserver{}
	_, err := srv.ScanControls(context.Background(), "", []string{" C-0012 ", "  C-0017"})
	if err != nil {
		assert.NotContains(t, err.Error(), "at least one control ID",
			"trim should pass validation even if the scan itself fails due to no cluster")
	}
}
