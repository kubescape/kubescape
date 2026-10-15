package mcpserver

import (
	"context"
	"fmt"
	"net/url"
	"runtime/debug"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/mark3labs/mcp-go/mcp"
)

// analysisOutput is the only value shared between callers of one in-flight
// analysis: an immutable string and a flag. Each caller rebuilds its own
// *mcp.CallToolResult from it, so no caller can observe or cause a mutation
// of another caller's result.
type analysisOutput struct {
	text       string
	isError    bool
	structured analysisStructured
}

// analysisStructured is implemented by structured tool results that know how
// to deep-copy themselves. Structured content is arbitrary and may hold
// slices, maps or pointers, so a result is only shared when each caller can be
// given its own copy, and with the same concrete type, so the encoded
// response is unchanged.
type analysisStructured interface {
	cloneStructured() any
}

// analysisKey builds the coalescing key for one analysis request. params must
// hold every argument that can change the result, already validated and
// normalized; url.Values encodes names and values unambiguously, and an
// optional argument that was not supplied is simply absent, so it cannot
// collide with one supplied as an empty value.
//
// The server holds exactly one Kubernetes client and one storage client, so
// the key needs no cluster or identity component. If per-request credentials
// are ever introduced, the caller identity must become part of the key.
func analysisKey(tool string, params url.Values) string {
	return "analysis:" + url.QueryEscape(tool) + "?" + params.Encode()
}

// doAnalysis runs run for a read-only analysis tool, sharing one execution
// among overlapping calls with an identical key. It is deliberately not
// behind the scan semaphore, and nothing is retained once the last waiter has
// returned: a later call always executes again.
//
// run receives the shared execution's context, which is cancelled when every
// caller has gone, not the context of whichever caller happened to start it.
// It must return a single text result (as produced by mcp.NewToolResultText
// or mcpToolError), optionally with structured content that implements
// analysisStructured; anything else is reported as an error rather than
// shared.
func (ksServer *KubescapeMcpserver) doAnalysis(ctx context.Context, tool string, params url.Values, run func(context.Context) *mcp.CallToolResult) *mcp.CallToolResult {
	v, err := ksServer.doSharedChan(ctx, analysisKey(tool, params), false, func(runCtx context.Context) (out interface{}, err error) {
		// The shared function runs on a goroutine owned by the shared execution, where
		// an unrecovered panic would terminate the whole process and bypass the
		// server's recovery middleware. Report it to every waiter as an error,
		// with its stack in the log.
		defer func() {
			if r := recover(); r != nil {
				logger.L().Error("panic in MCP analysis tool",
					helpers.String("tool", tool),
					helpers.Interface("panic", fmt.Sprint(r)),
					helpers.String("stack", string(debug.Stack())))
				out, err = nil, fmt.Errorf("analysis tool %s panicked: %v", tool, r)
			}
		}()
		return snapshotAnalysisResult(run(runCtx))
	})
	if err != nil {
		code := classifyScanError(err)
		return mcpToolError(code, classifyScanErrorMessage(code, "analysis", err), map[string]any{"tool": tool})
	}
	out := v.(analysisOutput)
	result := &mcp.CallToolResult{
		Content: []mcp.Content{mcp.TextContent{Type: mcp.ContentTypeText, Text: out.text}},
		IsError: out.isError,
	}
	if out.structured != nil {
		result.StructuredContent = out.structured.cloneStructured()
	}
	return result
}

func snapshotAnalysisResult(res *mcp.CallToolResult) (analysisOutput, error) {
	if res == nil || len(res.Content) != 1 || res.Meta != nil {
		return analysisOutput{}, fmt.Errorf("analysis result is not a single plain text content and cannot be shared")
	}
	var structured analysisStructured
	if res.StructuredContent != nil {
		c, ok := res.StructuredContent.(analysisStructured)
		if !ok {
			return analysisOutput{}, fmt.Errorf("analysis structured content of type %T cannot be shared", res.StructuredContent)
		}
		// Keep a private copy so nothing the producer still references is shared.
		structured, ok = c.cloneStructured().(analysisStructured)
		if !ok {
			return analysisOutput{}, fmt.Errorf("analysis structured content of type %T must clone to its own type", res.StructuredContent)
		}
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok || text.Meta != nil || text.Annotations != nil {
		return analysisOutput{}, fmt.Errorf("analysis result is not a single plain text content and cannot be shared")
	}
	return analysisOutput{text: text.Text, isError: res.IsError, structured: structured}, nil
}
