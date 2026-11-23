package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
)

type resultTestSession struct {
	server.ClientSession
	id string
}

func (s resultTestSession) SessionID() string { return s.id }

func resultTestContext(id string) context.Context {
	s := server.NewMCPServer("test", "test")
	return s.WithContext(context.Background(), resultTestSession{id: id})
}

func resultTestDocument(t *testing.T) (scanResultDocument, []byte) {
	t.Helper()
	doc := scanResultDocument{scanResponse: scanResponse{
		TotalFailed: 120, ReturnedFailed: 120, Degraded: true,
		NotEvaluatedControls: 2, TotalControls: 10, FrameworkName: "nsa",
		Warning: "original warning",
	}}
	for i := 0; i < 120; i++ {
		doc.Resources = append(doc.Resources, json.RawMessage(fmt.Sprintf(`{"resourceID":"resource-%03d","large":9007199254740993}`, i)))
	}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	return doc, data
}

func decodeResultPage(t *testing.T, data []byte) scanResultDocument {
	t.Helper()
	var doc scanResultDocument
	require.NoError(t, json.Unmarshal(data, &doc))
	return doc
}

func TestScanResultPages(t *testing.T) {
	var store scanResultStore
	now := time.Now()
	doc, data := resultTestDocument(t)
	first, err := store.firstPage("alice", doc, len(data), now)
	require.NoError(t, err)
	page := decodeResultPage(t, first)
	require.Len(t, page.Resources, 100)
	require.Equal(t, 100, *page.NextOffset)
	require.NotEmpty(t, page.ScanID)

	second, err := store.page("alice", page.ScanID, 100, 100, now)
	require.NoError(t, err)
	last := decodeResultPage(t, second)
	require.Len(t, last.Resources, 20)
	require.Nil(t, last.NextOffset)
	require.True(t, last.Truncated)
	require.True(t, last.Degraded)
	require.Equal(t, 120, last.TotalFailed)
	require.Equal(t, 2, last.NotEvaluatedControls)
	require.Equal(t, "original warning", last.Warning)
	require.Contains(t, string(last.Resources[0]), "9007199254740993")
	all := append(page.Resources, last.Resources...)
	require.Equal(t, doc.Resources, all)

	_, err = store.page("bob", page.ScanID, 100, 100, now)
	require.ErrorIs(t, err, errScanResultsUnavailable)
	_, err = store.page("alice", page.ScanID, 121, 100, now)
	require.Error(t, err)
	_, err = store.page("alice", page.ScanID, 0, 100, now.Add(scanResultsTTL))
	require.ErrorIs(t, err, errScanResultsUnavailable)
	require.Zero(t, store.bytes)
}

func TestScanResultRetentionLimits(t *testing.T) {
	doc, data := resultTestDocument(t)
	now := time.Now()
	for _, owner := range []string{"", "alice"} {
		var store scanResultStore
		page, err := store.firstPage(owner, doc, scanResultsMaxBytes+1, now)
		require.NoError(t, err)
		result := decodeResultPage(t, page)
		require.Len(t, result.Resources, 100)
		require.NotEmpty(t, result.PaginationWarning)
		require.Empty(t, result.ScanID)
		require.Nil(t, result.NextOffset)
		require.Empty(t, store.entries)
	}
	var store scanResultStore
	first, err := store.firstPage("alice", doc, len(data), now)
	require.NoError(t, err)
	id := decodeResultPage(t, first).ScanID
	for i := 1; i <= scanResultsMaxSnapshots; i++ {
		_, err := store.firstPage("alice", doc, len(data), now.Add(time.Duration(i)*time.Second))
		require.NoError(t, err)
	}
	require.Len(t, store.entries, scanResultsMaxSnapshots)
	_, err = store.page("alice", id, 0, 100, now)
	require.ErrorIs(t, err, errScanResultsUnavailable)

	var byteLimited scanResultStore
	_, err = byteLimited.firstPage("alice", doc, scanResultsMaxBytes, now)
	require.NoError(t, err)
	_, err = byteLimited.firstPage("alice", doc, scanResultsMaxBytes, now)
	require.NoError(t, err)
	require.Len(t, byteLimited.entries, 1)
	require.Equal(t, scanResultsMaxBytes, byteLimited.bytes)
}

func TestScanResultConcurrentClients(t *testing.T) {
	ks := &KubescapeMcpserver{}
	_, data := resultTestDocument(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := resultTestContext(fmt.Sprintf("client-%d", i))
			v, err := ks.doResultScan(ctx, "same-scan", func(ctx context.Context) (interface{}, error) {
				require.Equal(t, true, ctx.Value(fullScanResultsKey{}))
				return data, nil
			})
			require.NoError(t, err)
			page := decodeResultPage(t, v.([]byte))
			result, err := ks.CallTool(ctx, "get_scan_results", map[string]any{
				"scan_id": page.ScanID, "offset": float64(100),
			})
			require.NoError(t, err)
			require.False(t, result.IsError)
			last := decodeResultPage(t, []byte(toolResultText(t, result)))
			require.Len(t, last.Resources, 20)
		}(i)
	}
	wg.Wait()
}

func TestScanResultToolValidation(t *testing.T) {
	ks := &KubescapeMcpserver{}
	for _, args := range []map[string]any{
		{}, {"scan_id": "id", "offset": -1.0},
		{"scan_id": "id", "limit": 101.0}, {"scan_id": "id", "limit": 1.5},
		{"scan_id": "id", "offset": "100"},
	} {
		result, err := ks.CallTool(context.Background(), "get_scan_results", args)
		require.NoError(t, err)
		require.True(t, result.IsError)
		require.Contains(t, toolResultText(t, result), "INVALID_ARGUMENT")
	}
	result, err := ks.CallTool(context.Background(), "get_scan_results", map[string]any{"scan_id": "unknown"})
	require.NoError(t, err)
	require.Contains(t, toolResultText(t, result), "SCAN_RESULTS_UNAVAILABLE")
}
