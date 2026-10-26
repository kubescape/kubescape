package opaprocessor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The logger is global, so callers must not run in parallel.
func captureCELWarnings(t *testing.T) func() string {
	t.Helper()
	logFile, err := os.CreateTemp(t.TempDir(), "cel-log-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = logFile.Close() })
	log := logger.L()
	previousWriter, previousLevel := log.GetWriter(), log.GetLevel()
	log.SetWriter(logFile)
	require.NoError(t, log.SetLevel("warning"))
	t.Cleanup(func() {
		log.SetWriter(previousWriter)
		_ = log.SetLevel(previousLevel)
	})
	return func() string {
		t.Helper()
		output, err := os.ReadFile(logFile.Name())
		require.NoError(t, err)
		return string(output)
	}
}

// Issue #4336: both Services fail C-0042, but only web encounters an
// expression error. Users must see that error without enabling debug logging.
func TestCELValidationErrorWarningPreservesScanVerdicts(t *testing.T) {
	readWarnings := captureCELWarnings(t)
	service := func(name string, port map[string]any) map[string]any {
		return map[string]any{
			"apiVersion": "v1", "kind": "Service",
			"metadata": map[string]any{"name": name, "namespace": "default"},
			"spec":     map[string]any{"ports": []any{port}},
		}
	}
	objects := []map[string]any{
		service("web", map[string]any{"port": int64(80)}),
		service("ssh", map[string]any{"port": int64(22)}),
		service("safe", map[string]any{"port": int64(80), "targetPort": int64(8080)}),
	}
	scanner := newParityScanner(t, objects, nil)
	rule := reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: "cel-c-0042"},
		RuleLanguage: reporthandling.CELLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Service"},
		}},
	}
	control := reporthandling.Control{ControlID: "C-0042", Rules: []reporthandling.PolicyRule{rule}}
	results, err := scanner.processRule(context.Background(), &rule, nil, evaluationScope{}, &control)
	require.NoError(t, err)
	require.Len(t, results, 3)
	for name, status := range map[string]apis.ScanningStatus{
		"web": apis.StatusFailed, "ssh": apis.StatusFailed, "safe": apis.StatusPassed,
	} {
		result := results["/v1/default/Service/"+name]
		require.NotNil(t, result)
		assert.Equal(t, status, result.Status, name)
		assert.Empty(t, result.SubStatus, "error reporting must not turn a failure into requires-review")
	}
	assert.Empty(t, results["/v1/default/Service/web"].Paths, "an expression error offers no remediation")

	warnings := readWarnings()
	assert.Contains(t, warnings, "CEL evaluation error")
	assert.Contains(t, warnings, "C-0042")
	assert.Contains(t, warnings, rule.Name)
	assert.Contains(t, warnings, "/v1/default/Service/web")
	assert.Contains(t, warnings, "no such key: targetPort")
	assert.Equal(t, 1, strings.Count(warnings, "CEL evaluation error"), "one warning per errored resource")
	assert.NotContains(t, warnings, "/v1/default/Service/ssh")
	assert.NotContains(t, warnings, "/v1/default/Service/safe")
}

func TestCELValidationErrorWarningWithSiblingResults(t *testing.T) {
	for _, tc := range []struct {
		name          string
		invalidLimit  bool
		budget        int64
		wantSkipped   bool
		wantErrorText string
		wantErrors    int
	}{
		{name: "error alongside a violation", wantErrorText: "quantities must match", wantErrors: 1},
		{name: "multiple errors in one warning", invalidLimit: true, wantErrorText: "quantities must match", wantErrors: 2},
		{name: "offline budget error remains skipped", budget: 1, wantSkipped: true, wantErrorText: "cost budget", wantErrors: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readWarnings := captureCELWarnings(t)
			containerResources := map[string]any{
				"requests": map[string]any{"memory": "invalid-memory"},
			}
			if tc.invalidLimit {
				containerResources["limits"] = map[string]any{"memory": "invalid-memory"}
			}
			pod := map[string]any{
				"apiVersion": "v1", "kind": "Pod",
				"metadata": map[string]any{"name": "memory", "namespace": "default"},
				"spec": map[string]any{"containers": []any{map[string]any{
					"name": "c", "image": "nginx", "resources": containerResources,
				}}},
			}
			scanner := &OPAProcessor{}
			if tc.budget > 0 {
				scanner.celEvaluatorOnce.Do(func() {
					scanner.celEvaluator, scanner.celEvaluatorErr = cel.NewEvaluator(cel.WithCostBudget(tc.budget))
				})
			}
			rule := &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{Name: "cel-c-0004"}}
			responses, outcome, err := scanner.runCELOnK8s(context.Background(), rule, []map[string]any{pod}, nil, "C-0004")
			require.NoError(t, err)
			if tc.wantSkipped {
				assert.Empty(t, responses)
				require.Len(t, outcome.skipped, 1)
				assert.Contains(t, outcome.skipped[0].err.Error(), tc.wantErrorText)
			} else {
				assert.Empty(t, outcome.skipped)
				require.Len(t, responses, 1)
				assert.Equal(t, reporthandling.StatusFailed, responses[0].RuleStatus)
				if tc.invalidLimit {
					assert.Contains(t, responses[0].AlertMessage, tc.wantErrorText)
				} else {
					assert.Contains(t, responses[0].AlertMessage, "memory limit not set", "keep the confirmed violation's message")
				}
			}
			warnings := readWarnings()
			assert.Equal(t, 1, strings.Count(warnings, "CEL evaluation error"))
			assert.Equal(t, tc.wantErrors, strings.Count(warnings, tc.wantErrorText))
			assert.Contains(t, warnings, "C-0004")
			assert.Contains(t, warnings, rule.Name)
			assert.Contains(t, warnings, "/v1/default/Pod/memory")
		})
	}
}
