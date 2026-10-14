package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePolicyGetter serves a fixed framework list. The embedded nil interface
// makes any other policy call fail loudly instead of returning plausible data.
type fakePolicyGetter struct {
	getter.IPolicyGetter
	frameworks   []string
	controls     []string
	getFramework atomic.Int32
}

func (f *fakePolicyGetter) ListFrameworks() ([]string, error) { return f.frameworks, nil }
func (f *fakePolicyGetter) ListControls() ([]string, error)   { return f.controls, nil }
func (f *fakePolicyGetter) GetFramework(name string) (*reporthandling.Framework, error) {
	f.getFramework.Add(1)
	return nil, fmt.Errorf("framework %q not found", name)
}

// fakeStoreLoader is a policyStoreLoader with a scripted outcome.
type fakeStoreLoader struct {
	getter.IPolicyGetter
	fallback bool
	err      error
	calls    atomic.Int32
}

func (f *fakeStoreLoader) SetRegoObjectsWithFallback() (bool, error) {
	f.calls.Add(1)
	return f.fallback, f.err
}

// blockedLoad returns a loader that blocks until release is closed, and a
// counter of how many times it ran.
func blockedLoad(pg getter.IPolicyGetter, release <-chan struct{}) (func() getter.IPolicyGetter, *atomic.Int32) {
	var calls atomic.Int32
	return func() getter.IPolicyGetter {
		calls.Add(1)
		<-release
		return pg
	}, &calls
}

func TestMCPInitializeAndToolDiscoveryDoNotWaitForPolicyLoad(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	ks := &KubescapeMcpserver{s: server.NewMCPServer("test", "0")}
	load, _ := blockedLoad(&fakePolicyGetter{}, release)
	ks.startPolicyLoad(load)
	createPolicyListingTools(ks)

	done := make(chan struct{})
	var initResp, listResp any
	go func() {
		defer close(done)
		initResp = ks.s.HandleMessage(context.Background(), json.RawMessage(
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`))
		listResp = ks.s.HandleMessage(context.Background(), json.RawMessage(
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("initialize / tools/list blocked while the policy load was still running")
	}

	b, err := json.Marshal(initResp)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"serverInfo"`)
	b, err = json.Marshal(listResp)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"list_frameworks"`)
}

func TestPolicyToolsReturnBoundedErrorBeforeReadiness(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	ks := &KubescapeMcpserver{policyReadyWait: 50 * time.Millisecond}
	load, _ := blockedLoad(&fakePolicyGetter{frameworks: []string{"nsa"}}, release)
	ks.startPolicyLoad(load)

	start := time.Now()
	_, err := ks.ListFrameworks(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, errPolicyNotReady)
	assert.Less(t, time.Since(start), 5*time.Second, "wait must be bounded")
	assert.Equal(t, ErrCodeTimeout, classifyScanError(err))

	_, err = ks.ListControls(context.Background())
	assert.ErrorIs(t, err, errPolicyNotReady)

	// executeScan must refuse rather than evaluate against an unloaded store.
	// A file resource handler keeps the test away from any cluster.
	_, _, err = executeScan(context.Background(), ks, scanRequest{
		label:       "test",
		rsrcHandler: resourcehandler.NewFileResourceHandler(),
	})
	assert.ErrorIs(t, err, errPolicyNotReady)
}

func TestPolicyToolsSucceedAfterReadiness(t *testing.T) {
	release := make(chan struct{})
	ks := &KubescapeMcpserver{}
	load, calls := blockedLoad(&fakePolicyGetter{frameworks: []string{"nsa", "mitre"}}, release)
	ks.startPolicyLoad(load)

	// A call racing the load completes once the load finishes, whether or not
	// it had already started waiting.
	type result struct {
		out []byte
		err error
	}
	res := make(chan result, 1)
	go func() {
		out, err := ks.ListFrameworks(context.Background())
		res <- result{out, err}
	}()
	close(release)

	select {
	case r := <-res:
		require.NoError(t, r.err)
		assert.JSONEq(t, `["mitre","nsa"]`, string(r.out))
	case <-time.After(5 * time.Second):
		t.Fatal("waiting call did not complete after the policy load finished")
	}

	// And calls made afterwards do not wait or reload.
	out, err := ks.ListFrameworks(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `["mitre","nsa"]`, string(out))
	assert.EqualValues(t, 1, calls.Load(), "policy store must be initialized exactly once")
}

func TestStartPolicyLoadRunsOnce(t *testing.T) {
	release := make(chan struct{})
	ks := &KubescapeMcpserver{}
	load, calls := blockedLoad(&fakePolicyGetter{}, release)
	for i := 0; i < 5; i++ {
		ks.startPolicyLoad(load)
	}
	close(release)
	_, err := ks.readyPolicyGetter(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, 1, calls.Load())
}

func TestLoadPolicyGetterDownloadSuccess(t *testing.T) {
	drp := &fakeStoreLoader{}
	pg := loadPolicyGetter(drp)
	assert.Same(t, drp, pg, "a successful download keeps the downloader as the getter")
	assert.EqualValues(t, 1, drp.calls.Load())
}

func TestLoadPolicyGetterFallsBackToLocalCache(t *testing.T) {
	drp := &fakeStoreLoader{fallback: true}
	pg := loadPolicyGetter(drp)
	_, isLocal := pg.(*getter.LoadPolicy)
	assert.True(t, isLocal, "download failure with fallback must switch to the local policy cache, got %T", pg)
}

func TestLoadPolicyGetterKeepsDownloaderOnHardError(t *testing.T) {
	drp := &fakeStoreLoader{err: errors.New("pinned release unavailable")}
	pg := loadPolicyGetter(drp)
	assert.Same(t, drp, pg, "a hard error keeps the downloader, matching the previous startup behavior")
}

func TestFallbackGetterIsPublishedBeforeReadiness(t *testing.T) {
	ks := &KubescapeMcpserver{}
	drp := &fakeStoreLoader{fallback: true}
	ks.startPolicyLoad(func() getter.IPolicyGetter { return loadPolicyGetter(drp) })

	pg, err := ks.readyPolicyGetter(context.Background())
	require.NoError(t, err)
	_, isLocal := pg.(*getter.LoadPolicy)
	assert.True(t, isLocal, "callers must observe the fallback getter, not the downloader, got %T", pg)
}

func TestReadyPolicyGetterCancellation(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ks := &KubescapeMcpserver{policyReadyWait: time.Minute}
	load, _ := blockedLoad(&fakePolicyGetter{}, release)
	ks.startPolicyLoad(load)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := ks.readyPolicyGetter(ctx)
		errCh <- err
	}()
	cancel()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, ErrCodeTimeout, classifyScanError(err))
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt the wait")
	}
}

func TestReadyPolicyGetterConcurrentCalls(t *testing.T) {
	release := make(chan struct{})
	pg := &fakePolicyGetter{frameworks: []string{"nsa"}}
	ks := &KubescapeMcpserver{}
	load, calls := blockedLoad(pg, release)
	ks.startPolicyLoad(load)

	const n = 32
	var wg sync.WaitGroup
	got := make([]getter.IPolicyGetter, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = ks.readyPolicyGetter(context.Background())
		}(i)
	}
	close(release)
	wg.Wait()

	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
		assert.Same(t, pg, got[i])
	}
	assert.EqualValues(t, 1, calls.Load())
}

func TestReadyPolicyGetterWithoutLoadIsImmediate(t *testing.T) {
	pg := &fakePolicyGetter{}
	ks := &KubescapeMcpserver{policyGetter: pg}
	got, err := ks.readyPolicyGetter(context.Background())
	require.NoError(t, err)
	assert.Same(t, pg, got)
}

// toolErrorOf decodes the structured error payload of an error result.
func toolErrorOf(t *testing.T, res *mcp.CallToolResult) ToolError {
	t.Helper()
	require.NotNil(t, res)
	require.True(t, res.IsError, "expected an error result")
	require.Len(t, res.Content, 1)
	text, ok := res.Content[0].(mcp.TextContent)
	require.True(t, ok)
	var te ToolError
	require.NoError(t, json.Unmarshal([]byte(text.Text), &te))
	return te
}

func TestCallTool_ListToolsReportTimeoutBeforePolicyReadiness(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ks := &KubescapeMcpserver{policyReadyWait: 25 * time.Millisecond}
	load, _ := blockedLoad(&fakePolicyGetter{}, release)
	ks.startPolicyLoad(load)

	for _, tool := range []string{"list_frameworks", "list_controls"} {
		t.Run(tool, func(t *testing.T) {
			res, err := ks.CallTool(context.Background(), tool, map[string]any{})
			require.NoError(t, err)
			te := toolErrorOf(t, res)
			assert.Equal(t, ErrCodeTimeout, te.Code)
			assert.Contains(t, te.Message, "policy bundle is still loading")
		})
	}
}

func TestCallTool_ScanToolReportsTimeoutBeforePolicyReadiness(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	pg := &fakePolicyGetter{}
	ks := &KubescapeMcpserver{policyReadyWait: 25 * time.Millisecond}
	load, _ := blockedLoad(pg, release)
	ks.startPolicyLoad(load)

	// scan_local_iac uses the file resource handler, so no cluster client is
	// ever built on this path.
	res, err := ks.CallTool(context.Background(), "scan_local_iac", map[string]any{
		"path": "testdata/privileged-pod.yaml",
	})
	require.NoError(t, err)
	te := toolErrorOf(t, res)
	assert.Equal(t, ErrCodeTimeout, te.Code)
	assert.Contains(t, te.Message, "policy bundle is still loading")
	assert.Zero(t, pg.getFramework.Load(), "no policy may be read before the load finishes")
}

func TestCallTool_PolicyToolsSucceedOnRetryAfterLoadCompletes(t *testing.T) {
	release := make(chan struct{})
	pg := &fakePolicyGetter{frameworks: []string{"nsa", "mitre"}, controls: []string{"C-0001|Forbidden container registries|nsa"}}
	ks := &KubescapeMcpserver{policyReadyWait: 25 * time.Millisecond}
	load, calls := blockedLoad(pg, release)
	ks.startPolicyLoad(load)

	// First attempt: still loading.
	res, err := ks.CallTool(context.Background(), "list_frameworks", map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, ErrCodeTimeout, toolErrorOf(t, res).Code)

	// Let the load finish, then wait for the gate with a generous bound.
	close(release)
	ks.policyReadyWait = 0
	_, err = ks.readyPolicyGetter(context.Background())
	require.NoError(t, err)

	// Retry: every policy-dependent tool now works.
	res, err = ks.CallTool(context.Background(), "list_frameworks", map[string]any{})
	require.NoError(t, err)
	require.False(t, res.IsError)
	assert.JSONEq(t, `["mitre","nsa"]`, res.Content[0].(mcp.TextContent).Text)

	res, err = ks.CallTool(context.Background(), "list_controls", map[string]any{})
	require.NoError(t, err)
	require.False(t, res.IsError)
	assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "C-0001")

	// A scan tool now gets past the gate and reaches the policy getter. The
	// fake has no framework, so it fails there, and not with "still loading".
	res, err = ks.CallTool(context.Background(), "scan_local_iac", map[string]any{
		"path": "testdata/privileged-pod.yaml",
	})
	require.NoError(t, err)
	te := toolErrorOf(t, res)
	assert.NotContains(t, te.Message, "still loading")
	assert.NotZero(t, pg.getFramework.Load(), "scan must have reached the policy getter")
	assert.EqualValues(t, 1, calls.Load(), "policy store must be initialized exactly once")
}

func TestMCPToolsCallWhileLoadingReturnsStructuredTimeoutOverJSONRPC(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ks := &KubescapeMcpserver{s: server.NewMCPServer("test", "0"), policyReadyWait: 25 * time.Millisecond}
	load, _ := blockedLoad(&fakePolicyGetter{}, release)
	ks.startPolicyLoad(load)
	createPolicyListingTools(ks)

	// Initialize and discovery stay responsive while the load is blocked...
	ctx := context.Background()
	require.NotNil(t, ks.s.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`)))
	list, err := json.Marshal(ks.s.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)))
	require.NoError(t, err)
	assert.Contains(t, string(list), `"list_frameworks"`)
	assert.Contains(t, string(list), `"list_controls"`)

	// ...and a policy tool called through the registered handler reports the
	// bounded, structured error instead of hanging or returning an empty list.
	resp, err := json.Marshal(ks.s.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_frameworks","arguments":{}}}`)))
	require.NoError(t, err)
	assert.Contains(t, string(resp), `TIMEOUT`)
	assert.Contains(t, string(resp), `policy bundle is still loading`)
}
