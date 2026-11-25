package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/webhookcoverage"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func createRule(group, resource string) admissionregistrationv1.RuleWithOperations {
	return admissionregistrationv1.RuleWithOperations{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
		Rule:       admissionregistrationv1.Rule{APIGroups: []string{group}, APIVersions: []string{"v1"}, Resources: []string{resource}},
	}
}

func webhookTestCollection() *webhookcoverage.Collection {
	exact := admissionregistrationv1.Exact
	return &webhookcoverage.Collection{
		Validating: []admissionregistrationv1.ValidatingWebhookConfiguration{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "val-a"},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{Name: "all.example", MatchPolicy: &exact, Rules: []admissionregistrationv1.RuleWithOperations{createRule("apps", "deployments")}},
					{
						Name: "prod-only.example", MatchPolicy: &exact,
						Rules:             []admissionregistrationv1.RuleWithOperations{createRule("apps", "deployments")},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "val-b"},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{Name: "pods.example", MatchPolicy: &exact, Rules: []admissionregistrationv1.RuleWithOperations{createRule("", "pods")}},
				},
			},
		},
		Mutating: []admissionregistrationv1.MutatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "mut-a"},
			Webhooks: []admissionregistrationv1.MutatingWebhook{{
				Name: "cel.example", MatchPolicy: &exact,
				Rules:           []admissionregistrationv1.RuleWithOperations{createRule("apps", "deployments")},
				MatchConditions: []admissionregistrationv1.MatchCondition{{Name: "c", Expression: "true"}},
			}},
		}},
		ValidatingSource: webhookcoverage.Source{Available: true},
		MutatingSource:   webhookcoverage.Source{Available: true},
	}
}

func webhookTestSubjects() []webhookcoverage.Subject {
	return []webhookcoverage.Subject{
		{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "prod", Name: "web", LabelsKnown: true},
		{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "uncollected", Name: "api", LabelsKnown: true},
		{APIVersion: "v1", Kind: "ConfigMap", Namespace: "prod", Name: "cm"},
	}
}

func webhookTestAnalysis(c *webhookcoverage.Collection, complete bool) *webhookcoverage.Analysis {
	return webhookcoverage.Analyze(webhookcoverage.Input{
		Collection:       c,
		Subjects:         webhookTestSubjects(),
		NamespaceLabels:  map[string]map[string]string{"prod": {"env": "prod"}},
		SubjectsComplete: complete,
	})
}

func decodeWebhookResponse(t *testing.T, a *webhookcoverage.Analysis, limit int) webhookCoverageResponse {
	t.Helper()
	raw, err := buildWebhookCoverageResponse(a, limit)
	require.NoError(t, err)
	var resp webhookCoverageResponse
	require.NoError(t, json.Unmarshal(raw, &resp), string(raw))
	return resp
}

func findResult(t *testing.T, w webhookWorkloadJSON, webhook string) webhookResultJSON {
	t.Helper()
	for _, r := range w.Results {
		if r.Webhook == webhook {
			return r
		}
	}
	require.Failf(t, "result not found", "webhook %q for %s/%s", webhook, w.Namespace, w.Name)
	return webhookResultJSON{}
}

func TestWebhookCoverageTool_RegisteredOnceWithValidSchema(t *testing.T) {
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	registerTools(ksServer)

	raw, err := json.Marshal(ksServer.s.HandleMessage(context.Background(), json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	require.NoError(t, err)
	var list struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &list))

	var found []map[string]any
	for _, tool := range list.Result.Tools {
		if tool["name"] == webhookCoverageToolName {
			found = append(found, tool)
		}
	}
	require.Len(t, found, 1)
	assert.Empty(t, toolSchemaViolations(found))

	schema := found[0]["inputSchema"].(map[string]any)
	props := schema["properties"].(map[string]any)
	assert.Equal(t, []string{"limit"}, mapKeys(props), "only the limit argument is accepted")
	assert.Empty(t, schema["required"], "no argument is required")
	assert.Equal(t, true, found[0]["annotations"].(map[string]any)["readOnlyHint"])
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestBuildWebhookCoverageResponse_ValidatingAndMutatingPreserved(t *testing.T) {
	resp := decodeWebhookResponse(t, webhookTestAnalysis(webhookTestCollection(), true), 100)

	assert.Equal(t, "complete", resp.Status)
	assert.True(t, resp.Complete)
	assert.True(t, resp.WorkloadsComplete)
	assert.Equal(t, "CREATE", resp.Operation)
	assert.Equal(t, 2, resp.ValidatingSource.Configurations)
	assert.Equal(t, 1, resp.MutatingSource.Configurations)

	// Two Deployments; the ConfigMap is skipped, not dropped.
	require.Len(t, resp.Workloads, 2)
	require.Len(t, resp.Skipped, 1)
	assert.Equal(t, webhookSkippedJSON{APIVersion: "v1", Kind: "ConfigMap", Reason: webhookcoverage.SkipNotAWorkload, Count: 1}, resp.Skipped[0])

	// Ordered by namespace and name: prod/web is after uncollected/api? No: "prod" < "uncollected".
	web, api := resp.Workloads[0], resp.Workloads[1]
	assert.Equal(t, "web", web.Name)
	assert.Equal(t, "prod", web.Namespace)
	assert.Equal(t, "api", api.Name)

	// Four webhooks across three configurations, validating before mutating.
	require.Len(t, web.Results, 4)
	var types []string
	for _, r := range web.Results {
		types = append(types, r.Type)
	}
	assert.Equal(t, []string{"Validating", "Validating", "Validating", "Mutating"}, types)
	assert.Equal(t, "val-a", web.Results[0].Configuration)
	assert.Equal(t, "val-b", web.Results[2].Configuration)
	assert.Equal(t, "mut-a", web.Results[3].Configuration)

	require.Len(t, resp.Webhooks, 4)
}

func TestBuildWebhookCoverageResponse_VerdictsAndReasonsPreserved(t *testing.T) {
	a := webhookTestAnalysis(webhookTestCollection(), true)
	resp := decodeWebhookResponse(t, a, 100)
	web, api := resp.Workloads[0], resp.Workloads[1]

	matched := findResult(t, web, "all.example")
	assert.Equal(t, string(webhookcoverage.Matched), matched.Verdict)
	assert.Empty(t, matched.Reasons)
	assert.NotNil(t, matched.Reasons, "reasons is an array, never null")

	notMatched := findResult(t, web, "pods.example")
	assert.Equal(t, string(webhookcoverage.NotMatched), notMatched.Verdict)
	assert.Equal(t, []string{string(webhookcoverage.ReasonRulesDoNotMatch)}, notMatched.Reasons)

	cel := findResult(t, web, "cel.example")
	assert.Equal(t, string(webhookcoverage.Indeterminate), cel.Verdict)
	assert.Equal(t, []string{string(webhookcoverage.ReasonMatchConditions)}, cel.Reasons)

	// A namespace whose labels were never collected stays unknown: the
	// namespaceSelector webhook is Indeterminate, not NotMatched.
	assert.True(t, web.NamespaceLabelsKnown)
	assert.False(t, api.NamespaceLabelsKnown)
	unknown := findResult(t, api, "prod-only.example")
	assert.Equal(t, string(webhookcoverage.Indeterminate), unknown.Verdict)
	assert.Equal(t, []string{string(webhookcoverage.ReasonNamespaceLabelsUnknown)}, unknown.Reasons)
	assert.Equal(t, string(webhookcoverage.Matched), findResult(t, web, "prod-only.example").Verdict)

	// Every verdict equals the one the analysis holds.
	for i, w := range a.Workloads {
		for j, r := range w.Results {
			assert.Equal(t, string(r.Verdict), resp.Workloads[i].Results[j].Verdict)
		}
	}
}

func TestBuildWebhookCoverageResponse_SummariesCountEveryWorkload(t *testing.T) {
	resp := decodeWebhookResponse(t, webhookTestAnalysis(webhookTestCollection(), true), 1)

	assert.True(t, resp.Truncated)
	assert.Equal(t, 2, resp.TotalWorkloads)
	assert.Equal(t, 1, resp.ReturnedWorkloads)
	require.Len(t, resp.Workloads, 1)
	for _, s := range resp.Webhooks {
		assert.Equal(t, 2, s.Matched+s.NotMatched+s.Indeterminate, "summary for %s covers both workloads", s.Webhook)
	}
}

func TestBuildWebhookCoverageResponse_IncompleteWorkloads(t *testing.T) {
	resp := decodeWebhookResponse(t, webhookTestAnalysis(webhookTestCollection(), false), 100)

	assert.Equal(t, "incomplete", resp.Status)
	assert.False(t, resp.Complete)
	assert.False(t, resp.WorkloadsComplete)
	assert.True(t, resp.ValidatingSource.Complete)
	assert.True(t, resp.MutatingSource.Complete)
	assert.Len(t, resp.Workloads, 2, "results for what was collected are kept")
}

func TestBuildWebhookCoverageResponse_FailedValidatingKeepsMutating(t *testing.T) {
	c := webhookTestCollection()
	c.Validating = nil
	c.ValidatingSource = webhookcoverage.Source{Err: fmt.Errorf("list: %w", webhookcoverage.ErrForbidden)}

	resp := decodeWebhookResponse(t, webhookTestAnalysis(c, true), 100)

	assert.Equal(t, "incomplete", resp.Status)
	assert.False(t, resp.ValidatingSource.Available)
	assert.False(t, resp.ValidatingSource.Complete)
	assert.Equal(t, "forbidden", resp.ValidatingSource.ErrorKind)
	assert.Contains(t, resp.ValidatingSource.Error, "not permitted")
	assert.Zero(t, resp.ValidatingSource.Configurations)
	assert.True(t, resp.MutatingSource.Complete)
	assert.Equal(t, 1, resp.MutatingSource.Configurations)
	require.Len(t, resp.Workloads, 2)
	require.Len(t, resp.Workloads[0].Results, 1)
	assert.Equal(t, "cel.example", resp.Workloads[0].Results[0].Webhook)
}

func TestBuildWebhookCoverageResponse_FailedMutatingKeepsValidating(t *testing.T) {
	c := webhookTestCollection()
	c.Mutating = nil
	c.MutatingSource = webhookcoverage.Source{Err: errors.New("boom")}

	resp := decodeWebhookResponse(t, webhookTestAnalysis(c, true), 100)

	assert.Equal(t, "incomplete", resp.Status)
	assert.Equal(t, "other", resp.MutatingSource.ErrorKind)
	assert.Equal(t, "boom", resp.MutatingSource.Error)
	assert.True(t, resp.ValidatingSource.Complete)
	require.Len(t, resp.Workloads[0].Results, 3)
}

func TestBuildWebhookCoverageResponse_UnsupportedAndDecodeErrors(t *testing.T) {
	c := webhookTestCollection()
	c.MutatingSource = webhookcoverage.Source{Err: webhookcoverage.ErrUnsupported}
	c.Mutating = nil
	c.ValidatingSource.DecodeErrs = []error{errors.New("cannot decode val-x")}

	resp := decodeWebhookResponse(t, webhookTestAnalysis(c, true), 100)

	assert.Equal(t, "unsupported", resp.MutatingSource.ErrorKind)
	assert.True(t, resp.ValidatingSource.Available)
	assert.False(t, resp.ValidatingSource.Complete, "a listed but undecodable configuration makes the source incomplete")
	assert.Equal(t, []string{"cannot decode val-x"}, resp.ValidatingSource.DecodeErrors)
	assert.Equal(t, "incomplete", resp.Status)
}

func TestBuildWebhookCoverageResponse_NoWebhooksIsNotAnError(t *testing.T) {
	c := &webhookcoverage.Collection{
		ValidatingSource: webhookcoverage.Source{Available: true},
		MutatingSource:   webhookcoverage.Source{Available: true},
	}

	resp := decodeWebhookResponse(t, webhookTestAnalysis(c, true), 100)

	assert.Equal(t, "complete", resp.Status)
	assert.Empty(t, resp.Webhooks)
	for _, w := range resp.Workloads {
		assert.NotNil(t, w.Results)
	}
}

func TestBuildWebhookCoverageResponse_MissingAnalysisIsUnavailable(t *testing.T) {
	raw, err := buildWebhookCoverageResponse(nil, 100)

	assert.Nil(t, raw)
	assert.ErrorIs(t, err, errWebhookAnalysisUnavailable)
}

func TestBuildWebhookCoverageResponse_Deterministic(t *testing.T) {
	first, err := buildWebhookCoverageResponse(webhookTestAnalysis(webhookTestCollection(), true), 100)
	require.NoError(t, err)
	for range 5 {
		next, err := buildWebhookCoverageResponse(webhookTestAnalysis(webhookTestCollection(), true), 100)
		require.NoError(t, err)
		assert.Equal(t, string(first), string(next))
	}
}

func TestBuildWebhookCoverageResponse_StatesLimitations(t *testing.T) {
	resp := decodeWebhookResponse(t, webhookTestAnalysis(webhookTestCollection(), true), 100)

	joined := ""
	for _, l := range resp.Limitations {
		joined += l + "\n"
	}
	for _, want := range []string{"CREATE", "Matched does not prove", "NotMatched does not prove", "Indeterminate means", "Deployment", "CronJob"} {
		assert.Contains(t, joined, want)
	}
}

func TestCallTool_WebhookCoverage(t *testing.T) {
	orig := webhookCoverageScanFn
	t.Cleanup(func() { webhookCoverageScanFn = orig })

	t.Run("success passes the default limit and returns the scan JSON", func(t *testing.T) {
		var gotLimit int
		webhookCoverageScanFn = func(_ context.Context, _ *KubescapeMcpserver, limit int) ([]byte, error) {
			gotLimit = limit
			return buildWebhookCoverageResponse(webhookTestAnalysis(webhookTestCollection(), false), limit)
		}
		res, err := (&KubescapeMcpserver{}).CallTool(t.Context(), webhookCoverageToolName, map[string]any{})
		require.NoError(t, err)
		require.False(t, res.IsError)
		assert.Equal(t, defaultWebhookWorkloadLimit, gotLimit)
		var resp webhookCoverageResponse
		require.NoError(t, json.Unmarshal([]byte(res.Content[0].(mcp.TextContent).Text), &resp))
		assert.Equal(t, "incomplete", resp.Status)
	})

	t.Run("explicit limit is forwarded", func(t *testing.T) {
		var gotLimit int
		webhookCoverageScanFn = func(_ context.Context, _ *KubescapeMcpserver, limit int) ([]byte, error) {
			gotLimit = limit
			return []byte(`{}`), nil
		}
		res, err := (&KubescapeMcpserver{}).CallTool(t.Context(), webhookCoverageToolName, map[string]any{"limit": float64(7)})
		require.NoError(t, err)
		require.False(t, res.IsError)
		assert.Equal(t, 7, gotLimit)
	})

	invalid := map[string]map[string]any{
		"limit zero":       {"limit": float64(0)},
		"limit too large":  {"limit": float64(maxWebhookWorkloadLimit + 1)},
		"limit fraction":   {"limit": 1.5},
		"limit string":     {"limit": "10"},
		"unknown arg":      {"namespace": "default"},
		"update operation": {"operation": "UPDATE"},
	}
	for name, args := range invalid {
		t.Run("rejects "+name, func(t *testing.T) {
			called := false
			webhookCoverageScanFn = func(context.Context, *KubescapeMcpserver, int) ([]byte, error) {
				called = true
				return nil, nil
			}
			res, err := (&KubescapeMcpserver{}).CallTool(t.Context(), webhookCoverageToolName, args)
			require.NoError(t, err)
			require.True(t, res.IsError)
			assert.Contains(t, res.Content[0].(mcp.TextContent).Text, string(ErrCodeInvalidArgument))
			assert.False(t, called, "no scan runs for invalid arguments")
		})
	}

	t.Run("missing analysis is an error, not an empty success", func(t *testing.T) {
		webhookCoverageScanFn = func(context.Context, *KubescapeMcpserver, int) ([]byte, error) {
			return nil, fmt.Errorf("wrapped: %w", errWebhookAnalysisUnavailable)
		}
		res, err := (&KubescapeMcpserver{}).CallTool(t.Context(), webhookCoverageToolName, map[string]any{})
		require.NoError(t, err)
		require.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, string(ErrCodeAnalysisUnavailable))
	})

	t.Run("scan failure keeps the existing classification", func(t *testing.T) {
		webhookCoverageScanFn = func(context.Context, *KubescapeMcpserver, int) ([]byte, error) {
			return nil, context.DeadlineExceeded
		}
		res, err := (&KubescapeMcpserver{}).CallTool(t.Context(), webhookCoverageToolName, map[string]any{})
		require.NoError(t, err)
		require.True(t, res.IsError)
		text := res.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, string(ErrCodeTimeout))
		assert.NotContains(t, text, string(ErrCodeAnalysisUnavailable))
	})

	t.Run("scan initialization failure is a scan error", func(t *testing.T) {
		webhookCoverageScanFn = func(context.Context, *KubescapeMcpserver, int) ([]byte, error) {
			return nil, errors.New("failed to collect Webhook coverage policies: no policies")
		}
		res, err := (&KubescapeMcpserver{}).CallTool(t.Context(), webhookCoverageToolName, map[string]any{})
		require.NoError(t, err)
		require.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, string(ErrCodeScanFailed))
	})

	// One caller only: this covers a canceled caller returning promptly and the
	// execution stopping once no caller is left. It does not cover a second
	// caller keeping a shared execution alive after the first one leaves.
	t.Run("caller context cancellation stops the wait", func(t *testing.T) {
		started := make(chan struct{})
		finished := make(chan struct{})
		webhookCoverageScanFn = func(ctx context.Context, _ *KubescapeMcpserver, _ int) ([]byte, error) {
			defer close(finished)
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		type callOutcome struct {
			res *mcp.CallToolResult
			err error
		}
		outcome := make(chan callOutcome, 1)
		go func() {
			res, err := (&KubescapeMcpserver{}).CallTool(ctx, webhookCoverageToolName, map[string]any{})
			outcome <- callOutcome{res, err}
		}()

		select {
		case <-started:
		case <-time.After(lifecycleWait):
			cancel()
			t.Fatal("the shared scan never started")
		}
		// The shared execution has read webhookCoverageScanFn and is running
		// the stub. Cancel the only caller; it must stop waiting, and the
		// execution is then cancelled with it.
		cancel()

		select {
		case got := <-outcome:
			require.NoError(t, got.err)
			require.True(t, got.res.IsError)
			assert.Contains(t, got.res.Content[0].(mcp.TextContent).Text, string(ErrCodeTimeout))
		case <-time.After(lifecycleWait):
			t.Fatal("the canceled caller did not return")
		}
		// Wait for the stub to finish so the parent cleanup does not restore
		// webhookCoverageScanFn while the execution can still use it.
		select {
		case <-finished:
		case <-time.After(lifecycleWait):
			t.Fatal("the shared scan did not stop after its only caller left")
		}
	})
}

func TestExistingScanToolsUnaffectedByWebhookCoverage(t *testing.T) {
	orig := webhookCoverageScanFn
	t.Cleanup(func() { webhookCoverageScanFn = orig })
	webhookCoverageScanFn = func(context.Context, *KubescapeMcpserver, int) ([]byte, error) {
		t.Fatal("webhook coverage must not run for other tools")
		return nil, nil
	}
	origRBAC := rbacScanFn
	t.Cleanup(func() { rbacScanFn = origRBAC })
	rbacScanFn = func(*KubescapeMcpserver, context.Context, string, ...scanFilterArgs) ([]byte, error) {
		return []byte(`{"ok":true}`), nil
	}

	res, err := (&KubescapeMcpserver{}).CallTool(t.Context(), "run_rbac_security_scan", map[string]any{})

	require.NoError(t, err)
	assert.False(t, res.IsError)
}

func webhookScanSession(listAll bool) *cautils.OPASessionObj {
	deploy := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "web", "namespace": "prod"},
	})
	ns := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": "prod", "labels": map[string]any{"env": "prod"}},
	})
	scan := &cautils.OPASessionObj{
		AllResources:          map[string]workloadinterface.IMetadata{deploy.GetID(): deploy, ns.GetID(): ns},
		WebhookConfigurations: webhookTestCollection(),
	}
	if listAll {
		scan.ListedGVRs = map[string]bool{}
		for _, key := range webhookcoverage.WorkloadResourceKeys() {
			scan.ListedGVRs[key] = true
		}
	}
	return scan
}

func TestWebhookCoverageScanRequest_IsClusterWideAndUnfiltered(t *testing.T) {
	req := webhookCoverageScanRequest()

	require.Len(t, req.policyIdentifiers, 1)
	assert.Equal(t, webhookCoverageControl, req.policyIdentifiers[0].Identifier)
	assert.Equal(t, apisv1.KindControl, req.policyIdentifiers[0].Kind)

	info := buildScanInfo(req)
	assert.Empty(t, info.IncludeNamespaces)
	assert.Empty(t, info.ExcludedNamespaces)
	assert.Empty(t, info.LabelSelector)
	assert.Empty(t, info.IncludeKinds)
	assert.Empty(t, info.ExcludeKinds)
	assert.Nil(t, info.ScanObject)
}

func TestWebhookCoverageFromScan_UsesTheScanAnalysis(t *testing.T) {
	req := webhookCoverageScanRequest()

	raw, err := webhookCoverageFromScan(t.Context(), webhookScanSession(true), req, 100)
	require.NoError(t, err)
	var resp webhookCoverageResponse
	require.NoError(t, json.Unmarshal(raw, &resp))

	assert.Equal(t, "complete", resp.Status)
	require.Len(t, resp.Workloads, 1)
	assert.Equal(t, "web", resp.Workloads[0].Name)
	assert.True(t, resp.Workloads[0].NamespaceLabelsKnown, "namespace labels come from the scan's collected Namespace")
	assert.Equal(t, string(webhookcoverage.Matched), findResult(t, resp.Workloads[0], "prod-only.example").Verdict)
	require.Len(t, resp.Skipped, 1)
	assert.Equal(t, "Namespace", resp.Skipped[0].Kind)
}

func TestWebhookCoverageFromScan_ScopedScanIsIncomplete(t *testing.T) {
	// A scan that did not list every workload kind keeps its analysis and
	// reports it as incomplete; it is not widened or reported as complete.
	raw, err := webhookCoverageFromScan(t.Context(), webhookScanSession(false), webhookCoverageScanRequest(), 100)
	require.NoError(t, err)
	var resp webhookCoverageResponse
	require.NoError(t, json.Unmarshal(raw, &resp))

	assert.Equal(t, "incomplete", resp.Status)
	assert.False(t, resp.WorkloadsComplete)
	assert.True(t, resp.ValidatingSource.Complete)
	assert.Len(t, resp.Workloads, 1)
}

func TestWebhookCoverageFromScan_NoCollectedConfigurationsIsUnavailable(t *testing.T) {
	scan := webhookScanSession(true)
	scan.WebhookConfigurations = nil

	raw, err := webhookCoverageFromScan(t.Context(), scan, webhookCoverageScanRequest(), 100)

	assert.Nil(t, raw)
	assert.ErrorIs(t, err, errWebhookAnalysisUnavailable)

	raw, err = webhookCoverageFromScan(t.Context(), nil, webhookCoverageScanRequest(), 100)
	assert.Nil(t, raw)
	assert.ErrorIs(t, err, errWebhookAnalysisUnavailable)
}

func TestWebhookCoverageFromScan_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	raw, err := webhookCoverageFromScan(ctx, webhookScanSession(true), webhookCoverageScanRequest(), 100)

	assert.Nil(t, raw)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRunWebhookCoverageScan_ClusterUnreachable(t *testing.T) {
	origLoad := loadK8sConfig
	t.Cleanup(func() { loadK8sConfig = origLoad })
	loadK8sConfig = func() error { return errors.New("no kubeconfig in test") }

	raw, err := (&KubescapeMcpserver{}).RunWebhookCoverageScan(t.Context(), 100)

	assert.Nil(t, raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no reachable kubernetes cluster")
	assert.NotErrorIs(t, err, errWebhookAnalysisUnavailable, "a failed scan is not an unavailable analysis")
}
