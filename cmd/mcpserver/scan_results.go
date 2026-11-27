package mcpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

type preparedScanResultsKey struct{}

// Supports scan callbacks that still return complete serialized results.
type fullScanResultsKey struct{}

// The scan goroutine builds this once. Waiting callers share its immutable
// payload and attach session ownership only when registering a snapshot.
type preparedScanResults struct {
	document  scanResultDocument
	size      int
	oversized bool
}

func (p *preparedScanResults) buildSnapshot(response scanResponse, count int, resourceAt func(int) any) error {
	response.FailedResources = nil
	doc := scanResultDocument{scanResponse: response, Resources: []json.RawMessage{}}
	metadata, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode scan metadata: %w", err)
	}
	size := len(metadata)
	// IDs always contain 64 hex characters. A UTC timestamp without fractional
	// seconds is the shortest expiry representation registration can produce.
	// Reserve that minimum here and check the exact expiry at registration.
	reserved := doc
	reserved.ScanID = strings.Repeat("0", 64)
	expiry := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	reserved.ExpiresAt = &expiry
	reservedMetadata, err := json.Marshal(reserved)
	if err != nil {
		return fmt.Errorf("encode snapshot registration metadata: %w", err)
	}
	overhead := len(reservedMetadata) - len(metadata)
	for i := 0; i < count; i++ {
		data, err := json.Marshal(resourceAt(i))
		if err != nil {
			return fmt.Errorf("encode scan resource: %w", err)
		}
		cost := len(data)
		if i > 0 {
			cost++ // Comma between entries.
		}
		if cost > scanResultsMaxBytes-size-overhead {
			p.oversized = true
			return nil
		}
		doc.Resources = append(doc.Resources, data)
		size += cost
	}
	p.document, p.size = doc, size
	return nil
}

type sharedScanResults struct {
	preparedScanResults
	firstPage []byte
}

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
	total := len(doc.Resources)
	if doc.TotalFailed > total {
		total = doc.TotalFailed
	}
	if total <= limit {
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
	before, err := snapshotMetadataSize(doc)
	if err != nil {
		return nil, err
	}
	doc.ScanID, doc.ExpiresAt = id, &expires
	after, err := snapshotMetadataSize(doc)
	if err != nil {
		return nil, err
	}
	size += after - before
	if size > scanResultsMaxBytes {
		doc.ScanID, doc.ExpiresAt = "", nil
		doc.PaginationWarning = "Full results could not be retained (retention limit exceeded); narrow the scan scope."
		return marshalScanPage(doc, 0, limit)
	}

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

// Count metadata without copying or re-encoding the retained resource payload.
func snapshotMetadataSize(doc scanResultDocument) (int, error) {
	doc.Resources = []json.RawMessage{}
	data, err := json.Marshal(doc)
	if err != nil {
		return 0, fmt.Errorf("encode snapshot metadata: %w", err)
	}
	return len(data), nil
}

func (s *scanResultStore) page(owner, id string, offset, limit int, now time.Time) ([]byte, error) {
	s.mu.Lock()
	s.expireLocked(now)
	entry, ok := s.entries[id]
	if !ok || owner == "" || owner != entry.owner {
		s.mu.Unlock()
		return nil, errScanResultsUnavailable
	}
	if offset < 0 || offset > len(entry.document.Resources) || limit < 1 || limit > maxFailedResources {
		s.mu.Unlock()
		return nil, fmt.Errorf("offset must be between 0 and total_failed; limit must be between 1 and %d", maxFailedResources)
	}
	s.mu.Unlock()

	// The local entry keeps the immutable document alive even if the store evicts it.
	return marshalScanPage(entry.document, offset, limit)
}

func marshalScanPage(doc scanResultDocument, offset, limit int) ([]byte, error) {
	total := len(doc.Resources)
	if doc.TotalFailed > total {
		total = doc.TotalFailed
	}
	available := len(doc.Resources)
	if offset > available {
		offset = available
	}
	count := min(limit, available-offset)
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

type discardJSON struct{}

func (d *discardJSON) UnmarshalJSON([]byte) error {
	return nil
}

func extractFirstResources(data []byte, limit int) ([]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected '{', got %v", tok)
	}

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %v", tok)
		}
		if key == "failed_resources" {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if d, ok := tok.(json.Delim); !ok || d != '[' {
				return nil, fmt.Errorf("expected '[', got %v", tok)
			}
			resources := make([]json.RawMessage, 0)
			for dec.More() {
				if limit < 0 || len(resources) < limit {
					var raw json.RawMessage
					if err := dec.Decode(&raw); err != nil {
						return nil, err
					}
					resources = append(resources, raw)
				} else {
					return resources, nil
				}
			}
			return resources, nil
		}
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func decodeOversizedScanDocument(data []byte, limit int) (scanResultDocument, error) {
	var discard struct {
		scanResponse
		FailedResources *discardJSON `json:"failed_resources,omitempty"`
	}
	if err := json.Unmarshal(data, &discard); err != nil {
		return scanResultDocument{}, fmt.Errorf("decode scan results: %w", err)
	}
	resources, err := extractFirstResources(data, limit)
	if err != nil {
		return scanResultDocument{}, fmt.Errorf("decode scan results: %w", err)
	}
	return scanResultDocument{
		scanResponse: discard.scanResponse,
		Resources:    resources,
	}, nil
}

// doResultScan retains ownership only after shared execution has returned to
// each caller. A shared scan must never inherit its first caller's session.
func (ksServer *KubescapeMcpserver) doResultScan(ctx context.Context, key string, run func(context.Context) (interface{}, error), limitOpt ...int) (interface{}, error) {
	v, err := ksServer.doScanChan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
		var result sharedScanResults
		value, err := run(context.WithValue(context.WithValue(scanCtx, fullScanResultsKey{}, true), preparedScanResultsKey{}, &result.preparedScanResults))
		if err != nil {
			return nil, err
		}
		data, ok := value.([]byte)
		if !ok {
			return nil, errors.New("unexpected scan result type")
		}
		result.firstPage = data
		if result.document.Resources == nil {
			var doc scanResultDocument
			if len(data) > scanResultsMaxBytes {
				decoded, err := decodeOversizedScanDocument(data, maxFailedResources)
				if err != nil {
					return nil, err
				}
				doc = decoded
			} else if err := json.Unmarshal(data, &doc); err != nil {
				return nil, fmt.Errorf("decode scan results: %w", err)
			}
			result.document, result.size = doc, len(data)
		}
		return result, nil
	})
	if err != nil {
		return nil, err
	}
	result, ok := v.(sharedScanResults)
	if !ok {
		return nil, errors.New("unexpected shared scan result type")
	}
	if result.document.Resources == nil {
		return result.firstPage, nil
	}
	if result.oversized {
		// The serialized first page may fit even when the full snapshot did not.
		result.size = scanResultsMaxBytes + 1
	}
	return ksServer.scanResults.firstPage(scanResultOwner(ctx), result.document, result.size, time.Now(), limitOpt...)
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
