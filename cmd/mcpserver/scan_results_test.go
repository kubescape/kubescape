package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
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

	before, err := snapshotMetadataSize(doc)
	require.NoError(t, err)
	registered := doc
	registered.ScanID = strings.Repeat("0", 64)
	expiry := now.Add(scanResultsTTL)
	registered.ExpiresAt = &expiry
	after, err := snapshotMetadataSize(registered)
	require.NoError(t, err)
	baseSize := scanResultsMaxBytes - (after - before)

	var byteLimited scanResultStore
	for i := 0; i < 2; i++ {
		data, err := byteLimited.firstPage("alice", doc, baseSize, now)
		require.NoError(t, err)
		require.NotEmpty(t, decodeResultPage(t, data).ScanID)
	}
	require.Len(t, byteLimited.entries, 1)
	require.Equal(t, scanResultsMaxBytes, byteLimited.bytes)

	var overBudget scanResultStore
	data, err = overBudget.firstPage("alice", doc, baseSize+1, now)
	require.NoError(t, err)
	require.Empty(t, decodeResultPage(t, data).ScanID)
	require.Empty(t, overBudget.entries)

}

func TestScanResultConcurrentClients(t *testing.T) {
	ks := &KubescapeMcpserver{}
	doc, _ := resultTestDocument(t)
	data, err := marshalScanPage(doc, 0, maxFailedResources)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := resultTestContext(fmt.Sprintf("client-%d", i))
			v, err := ks.doResultScan(ctx, "same-scan", func(ctx context.Context) (interface{}, error) {
				prepared := ctx.Value(preparedScanResultsKey{}).(*preparedScanResults)
				return data, prepared.buildSnapshot(doc.scanResponse, len(doc.Resources), func(i int) any {
					return doc.Resources[i]
				})
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

func TestScanResultConcurrentClientLimits(t *testing.T) {
	const totalFailed = 80
	manifests := make([]string, totalFailed)
	for i := range manifests {
		name := fmt.Sprintf("privileged-pod-%03d", i)
		manifests[i] = strings.Replace(samplePrivilegedPodManifest, "name: privileged-pod", "name: "+name, 1)
	}
	manifest := strings.Join(manifests, "---\n")
	policyGetter := getSharedLiveClusterPolicyGetter(t)

	for _, firstLimit := range []int{100, 50} {
		t.Run(fmt.Sprintf("first-limit-%d", firstLimit), func(t *testing.T) {
			ks := &KubescapeMcpserver{policyGetter: policyGetter}
			const key = "shared-client-limits"
			started := make(chan struct{})
			var scans atomic.Int32
			run := func(ctx context.Context, limit int) (interface{}, error) {
				if scans.Add(1) == 1 {
					close(started)
				}
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					ks.scanCtxMu.Lock()
					state := ks.scanCtxs[key]
					joined := state != nil && state.count == 2
					ks.scanCtxMu.Unlock()
					if joined {
						return ks.runManifestScan(ctx, manifest, "", []string{"C-0017"}, scanFilterArgs{limit: limit})
					}
					time.Sleep(time.Millisecond)
				}
				return nil, fmt.Errorf("both callers did not join the shared scan")
			}

			type scanReply struct {
				value interface{}
				err   error
			}
			first := make(chan scanReply, 1)
			firstCtx := resultTestContext("first")
			secondCtx := resultTestContext("second")
			go func() {
				value, err := ks.doResultScan(firstCtx, key, func(ctx context.Context) (interface{}, error) {
					return run(ctx, firstLimit)
				}, firstLimit)
				first <- scanReply{value, err}
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("first scan did not start")
			}
			secondLimit := 150 - firstLimit
			secondValue, err := ks.doResultScan(secondCtx, key, func(ctx context.Context) (interface{}, error) {
				return run(ctx, secondLimit)
			}, secondLimit)
			require.NoError(t, err)
			firstReply := <-first
			require.NoError(t, firstReply.err)
			require.EqualValues(t, 1, scans.Load())

			full := decodeResultPage(t, firstReply.value.([]byte))
			limited := decodeResultPage(t, secondValue.([]byte))
			limitedCtx := secondCtx
			if firstLimit == 50 {
				full, limited = limited, full
				limitedCtx = firstCtx
			}
			require.Len(t, full.Resources, totalFailed)
			require.Equal(t, totalFailed, full.TotalFailed)
			require.Equal(t, totalFailed, full.ReturnedFailed)
			require.False(t, full.Truncated)
			require.Empty(t, full.ScanID)
			require.Equal(t, full.Resources[:50], limited.Resources)
			require.Equal(t, totalFailed, limited.TotalFailed)
			require.Equal(t, 50, limited.ReturnedFailed)
			require.True(t, limited.Truncated)
			require.NotNil(t, limited.NextOffset)
			require.Equal(t, 50, *limited.NextOffset)
			next, err := ks.scanResults.page(scanResultOwner(limitedCtx), limited.ScanID, 50, 100, time.Now())
			require.NoError(t, err)
			require.Equal(t, full.Resources[50:], decodeResultPage(t, next).Resources)
		})
	}
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

func TestDoResultScan_WithPagination(t *testing.T) {
	ks := &KubescapeMcpserver{}
	_, data := resultTestDocument(t) // 120 resources

	// Test 1: doResultScan with custom first-page limit=50
	ctx := resultTestContext("client-pagination")
	v, err := ks.doResultScan(ctx, "scan-paginated", func(scanCtx context.Context) (interface{}, error) {
		require.Equal(t, true, scanCtx.Value(fullScanResultsKey{}))
		return data, nil
	}, 50)
	require.NoError(t, err)

	page := decodeResultPage(t, v.([]byte))
	require.Len(t, page.Resources, 50)
	require.Equal(t, 50, page.ReturnedFailed)
	require.Equal(t, 120, page.TotalFailed)
	require.True(t, page.Truncated)
	require.NotNil(t, page.NextOffset)
	require.Equal(t, 50, *page.NextOffset)
	require.NotEmpty(t, page.ScanID)
	for i := 0; i < 50; i++ {
		assert.Contains(t, string(page.Resources[i]), fmt.Sprintf("resource-%03d", i))
	}

	// Fetch subsequent page via get_scan_results
	vPage2, err := ks.getScanResults(ctx, map[string]any{
		"scan_id": page.ScanID,
		"offset":  *page.NextOffset,
		"limit":   50,
	})
	require.NoError(t, err)
	require.False(t, vPage2.IsError)
	page2 := decodeResultPage(t, []byte(toolResultText(t, vPage2)))
	require.Len(t, page2.Resources, 50)
	require.Equal(t, 50, page2.ReturnedFailed)
	require.Equal(t, 120, page2.TotalFailed)
	require.True(t, page2.Truncated)
	require.NotNil(t, page2.NextOffset)
	require.Equal(t, 100, *page2.NextOffset)
	for i := 0; i < 50; i++ {
		assert.Contains(t, string(page2.Resources[i]), fmt.Sprintf("resource-%03d", 50+i))
	}

	// Final page
	vPage3, err := ks.getScanResults(ctx, map[string]any{
		"scan_id": page.ScanID,
		"offset":  *page2.NextOffset,
		"limit":   50,
	})
	require.NoError(t, err)
	require.False(t, vPage3.IsError)
	page3 := decodeResultPage(t, []byte(toolResultText(t, vPage3)))
	require.Len(t, page3.Resources, 20)
	require.Equal(t, 20, page3.ReturnedFailed)
	require.Nil(t, page3.NextOffset)
	for i := 0; i < 20; i++ {
		assert.Contains(t, string(page3.Resources[i]), fmt.Sprintf("resource-%03d", 100+i))
	}

	// Test 2: doResultScan with default limit (100)
	vDefault, err := ks.doResultScan(ctx, "scan-default", func(scanCtx context.Context) (interface{}, error) {
		require.Equal(t, true, scanCtx.Value(fullScanResultsKey{}))
		return data, nil
	})
	require.NoError(t, err)

	pageDefault := decodeResultPage(t, vDefault.([]byte))
	require.Len(t, pageDefault.Resources, 100)
	require.Equal(t, 100, pageDefault.ReturnedFailed)
	require.Equal(t, 120, pageDefault.TotalFailed)
	require.True(t, pageDefault.Truncated)
	require.NotNil(t, pageDefault.NextOffset)
	require.Equal(t, 100, *pageDefault.NextOffset)
}

func oversizedTestPayload(totalResources int) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, `{"total_failed":%d,"framework_name":"nsa","degraded":true,"warning":"oversized warning","failed_resources":[`, totalResources)
	for i := 0; i < totalResources; i++ {
		if i > 0 {
			buf.WriteString(",")
		}
		fmt.Fprintf(&buf, `{"resourceID":"res-%03d"}`, i)
	}
	buf.WriteString(`],"padding":"`)
	// Ensure total payload size exceeds 32 MiB retention bound
	paddingLen := scanResultsMaxBytes - buf.Len() + 1024
	if paddingLen > 0 {
		buf.Write(bytes.Repeat([]byte{'x'}, paddingLen))
	}
	buf.WriteString(`"}`)
	return buf.Bytes()
}

// oversizedResourceArrayPayload constructs a fixture where the failed_resources array itself
// exceeds scanResultsMaxBytes, without relying on top-level padding fields.
func oversizedResourceArrayPayload(totalResources int) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, `{"total_failed":%d,"framework_name":"nsa","degraded":true,"warning":"oversized array","failed_resources":[`, totalResources)
	resourcePadding := (scanResultsMaxBytes / totalResources) + 512
	padBytes := bytes.Repeat([]byte{'a'}, resourcePadding)
	for i := 0; i < totalResources; i++ {
		if i > 0 {
			buf.WriteString(",")
		}
		fmt.Fprintf(&buf, `{"resourceID":"res-%03d","payload":"%s"}`, i, padBytes)
	}
	buf.WriteString(`]}`)
	return buf.Bytes()
}

func TestScanResultOversizedPayload(t *testing.T) {
	ks := &KubescapeMcpserver{}
	data := oversizedTestPayload(150)
	require.Greater(t, len(data), scanResultsMaxBytes)

	ctx := resultTestContext("alice")
	v, err := ks.doResultScan(ctx, "oversized-scan", func(scanCtx context.Context) (interface{}, error) {
		require.Equal(t, true, scanCtx.Value(fullScanResultsKey{}))
		return data, nil
	})
	require.NoError(t, err)

	page := decodeResultPage(t, v.([]byte))
	require.Len(t, page.Resources, 100)
	require.Equal(t, 100, page.ReturnedFailed)
	require.Equal(t, 150, page.TotalFailed)
	require.True(t, page.Truncated)
	require.NotEmpty(t, page.PaginationWarning)
	require.Empty(t, page.ScanID)
	require.Nil(t, page.NextOffset)
	require.Empty(t, ks.scanResults.entries)

	// Custom limit on oversized payload
	vLimited, err := ks.doResultScan(ctx, "oversized-scan-limited", func(scanCtx context.Context) (interface{}, error) {
		return data, nil
	}, 50)
	require.NoError(t, err)
	pageLimited := decodeResultPage(t, vLimited.([]byte))
	require.Len(t, pageLimited.Resources, 50)
	require.Equal(t, 50, pageLimited.ReturnedFailed)
	require.Equal(t, 150, pageLimited.TotalFailed)
	require.True(t, pageLimited.Truncated)
	require.NotEmpty(t, pageLimited.PaginationWarning)
	require.Empty(t, pageLimited.ScanID)
	require.Nil(t, pageLimited.NextOffset)
}

func TestScanResultOversizedConcurrentClients(t *testing.T) {
	ks := &KubescapeMcpserver{}
	data := oversizedTestPayload(120)
	require.Greater(t, len(data), scanResultsMaxBytes)

	const callers = 6
	key := "oversized-concurrent"
	var scanInvocations atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := resultTestContext(fmt.Sprintf("client-%d", i))
			v, err := ks.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
				// Hold execution until the coordinator records all waiting callers,
				// ensuring they join the single shared execution.
				require.Eventually(t, func() bool {
					ks.scanCtxMu.Lock()
					defer ks.scanCtxMu.Unlock()
					if state, ok := ks.scanCtxs[key]; ok {
						return state.count >= callers
					}
					return false
				}, 5*time.Second, 5*time.Millisecond)
				scanInvocations.Add(1)
				return data, nil
			})
			require.NoError(t, err)
			page := decodeResultPage(t, v.([]byte))
			require.Len(t, page.Resources, 100)
			require.NotEmpty(t, page.PaginationWarning)
			require.Empty(t, page.ScanID)
			require.Nil(t, page.NextOffset)
		}(i)
	}
	wg.Wait()
	require.Equal(t, int32(1), scanInvocations.Load(), "scan callback should be invoked exactly once for all joined callers")
	require.Empty(t, ks.scanResults.entries)
}

func TestScanResultSharedDecodingAcrossSnapshots(t *testing.T) {
	ks := &KubescapeMcpserver{}
	doc, data := resultTestDocument(t)
	require.LessOrEqual(t, len(data), scanResultsMaxBytes)

	const callers = 4
	key := "shared-snapshots-test"
	var scanInvocations atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := resultTestContext(fmt.Sprintf("client-%d", i))
			v, err := ks.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
				// Hold execution until the coordinator records all waiting callers.
				require.Eventually(t, func() bool {
					ks.scanCtxMu.Lock()
					defer ks.scanCtxMu.Unlock()
					if state, ok := ks.scanCtxs[key]; ok {
						return state.count >= callers
					}
					return false
				}, 5*time.Second, 5*time.Millisecond)
				scanInvocations.Add(1)
				return data, nil
			})
			require.NoError(t, err)
			page := decodeResultPage(t, v.([]byte))
			require.NotEmpty(t, page.ScanID)
		}(i)
	}
	wg.Wait()

	require.Equal(t, int32(1), scanInvocations.Load(), "scan callback should be invoked exactly once across all callers")
	require.Len(t, ks.scanResults.entries, callers, "each caller session must have its own retained snapshot")

	// Verify that all retained snapshots share the exact same underlying decoded resource array
	// memory rather than each caller decoding its own copy.
	var firstResourcePtr *json.RawMessage
	for _, snapshot := range ks.scanResults.entries {
		require.Len(t, snapshot.document.Resources, len(doc.Resources))
		ptr := &snapshot.document.Resources[0]
		if firstResourcePtr == nil {
			firstResourcePtr = ptr
		} else {
			require.Same(t, firstResourcePtr, ptr, "snapshots must share the same decoded slice memory")
		}
	}
}

func BenchmarkScanResultParallelPageReads(b *testing.B) {
	const owner = "alice"
	const resourceCount = 2 * maxFailedResources
	now := time.Now()
	payload := json.RawMessage(`{"detail":"` + strings.Repeat("x", 4096) + `"}`)
	doc := scanResultDocument{
		scanResponse: scanResponse{TotalFailed: resourceCount},
		Resources:    make([]json.RawMessage, resourceCount),
	}
	for i := range doc.Resources {
		doc.Resources[i] = payload
	}
	encoded, err := json.Marshal(doc)
	require.NoError(b, err)
	var store scanResultStore
	first, err := store.firstPage(owner, doc, len(encoded), now)
	require.NoError(b, err)
	var firstPage scanResultDocument
	require.NoError(b, json.Unmarshal(first, &firstPage))
	require.NotEmpty(b, firstPage.ScanID)
	require.NotNil(b, firstPage.NextOffset)
	offset := *firstPage.NextOffset
	page, err := store.page(owner, firstPage.ScanID, offset, maxFailedResources, now)
	require.NoError(b, err)
	b.SetBytes(int64(len(page)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := store.page(owner, firstPage.ScanID, offset, maxFailedResources, now); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkScanResultOversizedDecoding(b *testing.B) {
	ks := &KubescapeMcpserver{}
	data := oversizedResourceArrayPayload(2000)
	if len(data) <= scanResultsMaxBytes {
		b.Fatalf("expected payload > %d bytes, got %d", scanResultsMaxBytes, len(data))
	}
	ctx := resultTestContext("bench-user")

	b.Run("FirstPageExtraction", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			v, err := ks.doResultScan(ctx, fmt.Sprintf("bench-oversized-%d", i), func(scanCtx context.Context) (interface{}, error) {
				return data, nil
			})
			if err != nil {
				b.Fatal(err)
			}
			if len(v.([]byte)) == 0 {
				b.Fatal("empty response")
			}
		}
	})

	b.Run("FullArrayDecoding", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var doc scanResultDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				b.Fatal(err)
			}
			if len(doc.Resources) == 0 {
				b.Fatal("empty resources")
			}
		}
	})
}
