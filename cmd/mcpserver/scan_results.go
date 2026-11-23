package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	scanResultsTTL          = 10 * time.Minute
	scanResultsMaxSnapshots = 16
	scanResultsMaxBytes     = 32 << 20
)

type fullScanResultsKey struct{}

// Raw messages preserve resource JSON, including numeric values, across pages.
type scanResultDocument struct {
	scanResponse
	Resources []json.RawMessage `json:"failed_resources"`
}

type scanResultSnapshot struct {
	owner    string
	expires  time.Time
	document scanResultDocument
	size     int
}

// scanResultStore bounds retained serialized JSON and snapshot count. It is
// process-local; entries expire on access and may be evicted sooner for space.
// Its zero value is usable. Idle expired entries remain within these bounds.
type scanResultStore struct {
	mu      sync.Mutex
	entries map[string]scanResultSnapshot
	bytes   int
}

var errScanResultsUnavailable = errors.New("scan results are unavailable; run the scan again")

func scanResultOwner(ctx context.Context) string {
	if session := server.ClientSessionFromContext(ctx); session != nil {
		return session.SessionID()
	}
	return ""
}

// firstPage takes ownership of doc's immutable decoded JSON. Callers must not
// mutate it afterwards. Failure to retain results must not discard a good scan.
func (s *scanResultStore) firstPage(owner string, doc scanResultDocument, size int, now time.Time, limitOpt ...int) ([]byte, error) {
	limit := maxFailedResources
	if len(limitOpt) > 0 && limitOpt[0] > 0 {
		limit = limitOpt[0]
	}
	if len(doc.Resources) <= limit {
		return json.Marshal(doc)
	}
	if owner == "" || size > scanResultsMaxBytes {
		doc.PaginationWarning = "Full results could not be retained (missing session or retention limit exceeded); narrow the scan scope."
		return marshalScanPage(doc, 0, limit)
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		doc.PaginationWarning = "Full results could not be retained; narrow the scan scope or retry."
		return marshalScanPage(doc, 0, limit)
	}
	id := hex.EncodeToString(token[:])
	expires := now.Add(scanResultsTTL)
	doc.ScanID, doc.ExpiresAt = id, &expires

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	if s.entries == nil {
		s.entries = make(map[string]scanResultSnapshot)
	}
	for len(s.entries) >= scanResultsMaxSnapshots || s.bytes > scanResultsMaxBytes-size {
		var oldest string
		for key, entry := range s.entries {
			if oldest == "" || entry.expires.Before(s.entries[oldest].expires) ||
				(entry.expires.Equal(s.entries[oldest].expires) && key < oldest) {
				oldest = key
			}
		}
		s.removeLocked(oldest)
	}
	s.entries[id] = scanResultSnapshot{owner: owner, expires: expires, document: doc, size: size}
	s.bytes += size
	return marshalScanPage(doc, 0, limit)
}

func (s *scanResultStore) page(owner, id string, offset, limit int, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	entry, ok := s.entries[id]
	if !ok || owner == "" || owner != entry.owner {
		return nil, errScanResultsUnavailable
	}
	if offset < 0 || offset > len(entry.document.Resources) || limit < 1 || limit > maxFailedResources {
		return nil, fmt.Errorf("offset must be between 0 and total_failed; limit must be between 1 and %d", maxFailedResources)
	}
	return marshalScanPage(entry.document, offset, limit)
}

func marshalScanPage(doc scanResultDocument, offset, limit int) ([]byte, error) {
	total := len(doc.Resources)
	if offset > total {
		offset = total
	}
	count := min(limit, total-offset)
	end := offset + count
	doc.Resources = doc.Resources[offset:end]
	doc.ReturnedFailed = count
	// A page is an incomplete view even when it is the final page.
	doc.Truncated = count < total
	doc.NextOffset = nil
	if end < total && doc.ScanID != "" {
		doc.NextOffset = &end
	}
	return json.Marshal(doc)
}

func (s *scanResultStore) expireLocked(now time.Time) {
	for id, entry := range s.entries {
		if !now.Before(entry.expires) {
			s.removeLocked(id)
		}
	}
}

func (s *scanResultStore) removeLocked(id string) {
	s.bytes -= s.entries[id].size
	delete(s.entries, id)
}

// doResultScan retains ownership only after shared execution has returned to
// each caller. A shared scan must never inherit its first caller's session.
func (ksServer *KubescapeMcpserver) doResultScan(ctx context.Context, key string, run func(context.Context) (interface{}, error), limitOpt ...int) (interface{}, error) {
	v, err := ksServer.doScanChan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
		return run(context.WithValue(scanCtx, fullScanResultsKey{}, true))
	})
	if err != nil {
		return nil, err
	}
	data, ok := v.([]byte)
	if !ok {
		return nil, errors.New("unexpected scan result type")
	}
	var doc scanResultDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode scan results: %w", err)
	}
	if doc.Resources == nil {
		return data, nil
	}
	if doc.TotalFailed != len(doc.Resources) {
		return nil, errors.New("scan returned incomplete results before pagination")
	}
	return ksServer.scanResults.firstPage(scanResultOwner(ctx), doc, len(data), time.Now(), limitOpt...)
}

func createScanResultsTool(ksServer *KubescapeMcpserver) {
	tool := mcp.NewTool("get_scan_results",
		mcp.WithDescription("Read another page of a completed scan without rescanning. Use scan_id and next_offset from a scan response, in the same MCP session. Results expire after 10 minutes and may be evicted sooner. Absence of next_offset means there are no more pages."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithString("scan_id", mcp.Required(), mcp.Description("Scan identifier from the initial response")),
		mcp.WithNumber("offset", mcp.Description("Offset from next_offset (default 0)")),
		mcp.WithNumber("limit", mcp.Description("Page size, 1–100 (default 100)")),
	)
	ksServer.s.AddTool(tool, ksServer.toolHandler(tool.Name))
}

func (ksServer *KubescapeMcpserver) getScanResults(ctx context.Context, arguments map[string]any) (*mcp.CallToolResult, error) {
	id, toolErr := mcpRequiredStringArg(arguments, "scan_id")
	if toolErr != nil {
		return toolErr, nil
	}
	offset, _, toolErr := mcpIntArg(arguments, "offset")
	if toolErr != nil {
		return toolErr, nil
	}
	limit, set, toolErr := mcpIntArg(arguments, "limit")
	if toolErr != nil {
		return toolErr, nil
	}
	if !set {
		limit = maxFailedResources
	}
	if offset < 0 || limit < 1 || limit > maxFailedResources {
		return mcpToolError(ErrCodeInvalidArgument, "offset must be nonnegative and limit must be between 1 and 100", nil), nil
	}
	data, err := ksServer.scanResults.page(scanResultOwner(ctx), id, offset, limit, time.Now())
	if errors.Is(err, errScanResultsUnavailable) {
		return mcpToolError(ErrCodeScanResultsUnavailable, err.Error(), nil), nil
	}
	if err != nil {
		return mcpToolError(ErrCodeInvalidArgument, err.Error(), nil), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}
