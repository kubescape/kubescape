package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Compare identical resources under full serialization and budgeted preparation.
// The callback counts resource encoding, independently of machine timing.
func TestSnapshotBudgetBeforeAfter(t *testing.T) {
	const total = 160
	large := json.RawMessage(`{"payload":"` + strings.Repeat("x", 1<<20) + `"}`)
	resources := make([]any, total)
	for i := range resources {
		if i < maxFailedResources {
			resources[i] = json.RawMessage(fmt.Sprintf(`{"resourceID":"resource-%03d"}`, i))
		} else {
			resources[i] = large
		}
	}
	response := scanResponse{
		TotalFailed: total, ReturnedFailed: total,
		FailedResources: resources, FrameworkName: "nsa",
	}
	// Baseline: complete result encoding necessarily visits every resource.
	full, err := json.Marshal(response)
	require.NoError(t, err)
	require.Greater(t, len(full), scanResultsMaxBytes)
	t.Logf("full encoding: resources=%d JSON_bytes=%d", total, len(full))

	ks := &KubescapeMcpserver{}
	encoded := 0
	ctx := resultTestContext("budget-proof")
	value, err := ks.doResultScan(ctx, "budget-proof", func(scanCtx context.Context) (interface{}, error) {
		prepared := scanCtx.Value(preparedScanResultsKey{}).(*preparedScanResults)
		err := prepared.buildSnapshot(response, total, func(i int) any {
			encoded++
			return resources[i]
		})
		if err != nil {
			return nil, err
		}
		require.True(t, prepared.oversized)
		require.Nil(t, prepared.document.Resources)
		first := response
		first.FailedResources = resources[:maxFailedResources]
		first.ReturnedFailed = maxFailedResources
		first.Truncated = true
		if prepared.oversized {
			first.PaginationWarning = "retention limit exceeded"
		}
		return json.Marshal(first)
	}, 50)
	require.NoError(t, err)
	require.Less(t, encoded, total, "encoding must stop before visiting the remaining findings")
	page := decodeResultPage(t, value.([]byte))
	require.Len(t, page.Resources, 50)
	require.Equal(t, total, page.TotalFailed)
	require.Equal(t, 50, page.ReturnedFailed)
	require.True(t, page.Truncated)
	require.NotEmpty(t, page.PaginationWarning)
	require.Empty(t, page.ScanID)
	require.Nil(t, page.NextOffset)
	require.Empty(t, ks.scanResults.entries)
	t.Logf("budgeted encoding: resources_visited=%d/%d returned=%d total_failed=%d warning=%q",
		encoded, total, page.ReturnedFailed, page.TotalFailed, page.PaginationWarning)
}
