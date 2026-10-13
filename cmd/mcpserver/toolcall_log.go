package mcpserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Tool-call outcomes. The set is closed so a log pipeline can aggregate on it.
const (
	toolCallOutcomeOK    = "ok"
	toolCallOutcomeError = "error"
	toolCallOutcomePanic = "panic"
)

const (
	// toolCallErrorHandler marks a handler that returned a Go error rather than
	// an error result; mcp-go turns that into a JSON-RPC internal error.
	toolCallErrorHandler = "HANDLER_ERROR"
	// toolCallErrorUnclassified marks an error result whose payload is not one
	// of the structured ToolError codes this package defines.
	toolCallErrorUnclassified = "UNCLASSIFIED"

	// maxToolErrorPayloadBytes bounds how much of an error result is inspected
	// for its code. Structured ToolError payloads are far smaller; anything
	// larger is not one and is not worth parsing.
	maxToolErrorPayloadBytes = 4096

	// fingerprintBytes is how much of the HMAC is kept: enough to tell calls
	// apart in a log, short enough not to invite use as an identifier.
	fingerprintBytes = 8
)

// knownToolErrorCodes bounds the error_code value to the codes mcperror.go
// defines, so an arbitrary string from a tool can never reach a log line.
var knownToolErrorCodes = map[ErrorCode]struct{}{
	ErrCodeMalformedIdentifier: {},
	ErrCodeResourceNotFound:    {},
	ErrCodeAmbiguousResource:   {},
	ErrCodeRBACDenied:          {},
	ErrCodeInvalidArgument:     {},
	ErrCodeScanFailed:          {},
	ErrCodeK8sClientError:      {},
	ErrCodeMarshalError:        {},
	ErrCodeTimeout:             {},
	ErrCodeResourceHasParent:   {},
	ErrCodeNotWorkload:         {},
	ErrCodeSecretScanDenied:    {},
	ErrCodeUnsupportedResource: {},
}

// toolCallRecord is the metadata recorded for one tools/call. It deliberately
// carries no argument values, no result content and no error text: the point
// is to learn how often tools are called, how long they take, and whether
// identical calls overlap -- not what was asked.
type toolCallRecord struct {
	Tool      string
	Transport string
	Outcome   string
	// ErrorCode is set only when Outcome is "error", and is always one of
	// knownToolErrorCodes, toolCallErrorHandler or toolCallErrorUnclassified.
	ErrorCode string
	Duration  time.Duration
	// InFlightIdentical is how many calls with the same tool and the same
	// arguments were already running when this one started.
	InFlightIdentical int
	// Fingerprint is a keyed hash of the tool and its arguments. Empty when
	// the arguments could not be encoded.
	Fingerprint string
}

// toolCallObserver records toolCallRecords for tool calls passing through its
// middleware. It never changes a call's result, error or panic behavior.
type toolCallObserver struct {
	transport string
	emit      func(toolCallRecord)
	now       func() time.Time

	// key makes fingerprints unguessable: a plain hash of a low-entropy
	// namespace or name could be reversed by dictionary. It is generated per
	// process and never written anywhere, so fingerprints are comparable only
	// within one server run -- which is all overlap detection needs.
	key []byte

	mu       sync.Mutex
	inflight map[string]int
}

func newToolCallObserver(transport string, emit func(toolCallRecord)) (*toolCallObserver, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate tool call fingerprint key: %w", err)
	}
	return &toolCallObserver{
		transport: transport,
		emit:      emit,
		now:       time.Now,
		key:       key,
		inflight:  make(map[string]int),
	}, nil
}

// middleware implements server.ToolHandlerMiddleware.
func (o *toolCallObserver) middleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tool := request.Params.Name
		fingerprint, concurrent := o.begin(tool, request.Params.Arguments)
		start := o.now()

		// completed distinguishes a panic from a normal return without
		// recovering: the panic must keep propagating to WithRecovery.
		completed := false
		var result *mcp.CallToolResult
		var err error
		defer func() {
			o.finish(toolCallRecord{
				Tool:              tool,
				Transport:         o.transport,
				Duration:          o.now().Sub(start),
				InFlightIdentical: concurrent,
				Fingerprint:       fingerprint,
			}, completed, result, err)
		}()

		result, err = next(ctx, request)
		completed = true
		return result, err
	}
}

// begin registers a call as in flight and returns its fingerprint and the
// number of identical calls already running. It cannot fail the call.
func (o *toolCallObserver) begin(tool string, args any) (fingerprint string, concurrent int) {
	defer func() {
		if recover() != nil {
			fingerprint, concurrent = "", 0
		}
	}()

	fingerprint = o.fingerprint(tool, args)
	if fingerprint == "" {
		return "", 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	concurrent = o.inflight[fingerprint]
	o.inflight[fingerprint] = concurrent + 1
	return fingerprint, concurrent
}

// finish completes a call's bookkeeping and emits its record. Failures in
// here, including a panicking emit function, are contained so they can never
// alter what the tool returns.
func (o *toolCallObserver) finish(rec toolCallRecord, completed bool, result *mcp.CallToolResult, err error) {
	defer func() { _ = recover() }()

	if rec.Fingerprint != "" {
		o.mu.Lock()
		if o.inflight[rec.Fingerprint] <= 1 {
			delete(o.inflight, rec.Fingerprint)
		} else {
			o.inflight[rec.Fingerprint]--
		}
		o.mu.Unlock()
	}

	switch {
	case !completed:
		rec.Outcome = toolCallOutcomePanic
	case err != nil:
		rec.Outcome = toolCallOutcomeError
		rec.ErrorCode = toolCallErrorHandler
	case result != nil && result.IsError:
		rec.Outcome = toolCallOutcomeError
		rec.ErrorCode = toolResultErrorCode(result)
	default:
		rec.Outcome = toolCallOutcomeOK
	}

	if o.emit != nil {
		o.emit(rec)
	}
}

// fingerprint returns a keyed hash of the tool name and its arguments, or ""
// when the arguments cannot be encoded.
//
// The arguments are hashed as the client sent them (encoding/json orders map
// keys, so key order does not matter). They are not normalized with the
// defaults each handler applies, so a call that omits an argument and one that
// passes its default explicitly hash differently. Equal fingerprints therefore
// always mean equal effective arguments; the reverse does not hold, which makes
// overlap counts a lower bound.
func (o *toolCallObserver) fingerprint(tool string, args any) string {
	if args == nil {
		args = map[string]any{}
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, o.key)
	mac.Write([]byte(tool))
	mac.Write([]byte{0})
	mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)[:fingerprintBytes])
}

// toolResultErrorCode extracts the structured error code from an error
// result. It reads only the code and only when it is one this package defines,
// so error text (which can carry names and namespaces) never leaves here.
func toolResultErrorCode(result *mcp.CallToolResult) string {
	if len(result.Content) != 1 {
		return toolCallErrorUnclassified
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok || len(text.Text) > maxToolErrorPayloadBytes {
		return toolCallErrorUnclassified
	}
	var payload struct {
		Code ErrorCode `json:"code"`
	}
	if json.Unmarshal([]byte(text.Text), &payload) != nil {
		return toolCallErrorUnclassified
	}
	if _, known := knownToolErrorCodes[payload.Code]; !known {
		return toolCallErrorUnclassified
	}
	return string(payload.Code)
}

// toolCallFields renders a record as log fields.
func toolCallFields(rec toolCallRecord) []helpers.IDetails {
	fields := []helpers.IDetails{
		helpers.String("tool", rec.Tool),
		helpers.String("transport", rec.Transport),
		helpers.String("outcome", rec.Outcome),
		helpers.Interface("durationMs", float64(rec.Duration.Microseconds())/1000),
		helpers.Int("inFlightIdentical", rec.InFlightIdentical),
	}
	if rec.ErrorCode != "" {
		fields = append(fields, helpers.String("errorCode", rec.ErrorCode))
	}
	if rec.Fingerprint != "" {
		fields = append(fields, helpers.String("argsFingerprint", rec.Fingerprint))
	}
	return fields
}

func logToolCall(rec toolCallRecord) {
	logger.L().Debug("MCP tool call", toolCallFields(rec)...)
}

// toolCallObserverOptions returns the server options that install tool-call
// recording, or nil when it is not wanted. Recording is a debug-level
// diagnostic: it is installed only when the logger is already at debug, so the
// default configuration pays nothing for it.
func toolCallObserverOptions(logLevel, transport string) []server.ServerOption {
	if logLevel != helpers.DebugLevel.String() {
		return nil
	}
	observer, err := newToolCallObserver(transport, logToolCall)
	if err != nil {
		logger.L().Warning("MCP tool call logging disabled", helpers.Error(err))
		return nil
	}
	return []server.ServerOption{server.WithToolHandlerMiddleware(observer.middleware)}
}
