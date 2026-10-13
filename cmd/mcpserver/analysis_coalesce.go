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
	text    string
	isError bool
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
// or mcpToolError); anything else is reported as an error rather than shared.
func (ksServer *KubescapeMcpserver) doAnalysis(ctx context.Context, tool string, params url.Values, run func(context.Context) *mcp.CallToolResult) *mcp.CallToolResult {
	v, err := ksServer.doSharedChan(ctx, analysisKey(tool, params), false, func(runCtx context.Context) (out interface{}, err error) {
		// The shared function runs on a goroutine owned by singleflight, where
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
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.TextContent{Type: mcp.ContentTypeText, Text: out.text}},
		IsError: out.isError,
	}
}

func snapshotAnalysisResult(res *mcp.CallToolResult) (analysisOutput, error) {
	if res == nil || len(res.Content) != 1 || res.StructuredContent != nil || res.Meta != nil {
		return analysisOutput{}, fmt.Errorf("analysis result is not a single plain text content and cannot be shared")
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok || text.Meta != nil || text.Annotations != nil {
		return analysisOutput{}, fmt.Errorf("analysis result is not a single plain text content and cannot be shared")
	}
	return analysisOutput{text: text.Text, isError: res.IsError}, nil
}
