package policytest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/ruledir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const extraCaseManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: extra
  namespace: default
spec:
  selector:
    matchLabels:
      app: extra
  template:
    metadata:
      labels:
        app: extra
    spec:
      containers:
        - name: app
          image: nginx:1.25
`

func scaffoldRule(t *testing.T, name string, opts ScaffoldOptions) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	_, err := Scaffold(context.Background(), dir, opts)
	require.NoError(t, err)
	return dir
}

func TestScaffold_WritesRuleDirectory(t *testing.T) {
	dir := scaffoldRule(t, "no-privileged-containers", ScaffoldOptions{})

	assert.True(t, ruledir.Is(dir))
	for _, rel := range []string{
		ruledir.RegoFileName,
		ruledir.MetadataFileName,
		filepath.Join("test", "flagged", "input", "resource.yaml"),
		filepath.Join("test", "clean", "input", "resource.yaml"),
	} {
		assert.FileExists(t, filepath.Join(dir, rel))
	}

	rule, ok, err := ruledir.Load(dir)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "no-privileged-containers", rule.Rule.Name)
	assert.Equal(t, []string{"Deployment"}, rule.Rule.Match[0].Resources)
	assert.Contains(t, rule.Rule.Rule, "package armo_builtins")
}

func TestScaffold_EverySupportedKindProducesPassingCases(t *testing.T) {
	for _, kind := range SupportedKinds() {
		t.Run(kind, func(t *testing.T) {
			dir := scaffoldRule(t, "check-"+strings.ToLower(kind), ScaffoldOptions{Kind: kind})

			rules, err := DiscoverPath(dir)
			require.NoError(t, err)
			require.Len(t, rules, 1)
			require.Len(t, rules[0].Cases, 2)

			ctx := context.Background()
			for _, result := range UpdateRule(ctx, rules[0]) {
				require.NoError(t, result.Err)
			}

			byCase := map[string][]byte{}
			for _, c := range rules[0].Cases {
				raw, err := os.ReadFile(filepath.Join(c.Dir, expectedFileName))
				require.NoError(t, err)
				byCase[c.Name] = raw
			}

			var flagged, clean []map[string]any
			require.NoError(t, json.Unmarshal(byCase[flaggedCaseName], &flagged))
			require.NoError(t, json.Unmarshal(byCase[cleanCaseName], &clean))
			assert.Len(t, flagged, 1, "the flagged fixture must trigger the rule")
			assert.Empty(t, clean, "the clean fixture must not trigger the rule")

			for _, result := range RunRule(ctx, rules[0]) {
				require.NoError(t, result.Err)
				assert.True(t, result.Passed, result.Diff)
			}
		})
	}
}

func TestScaffold_RejectsInvalidName(t *testing.T) {
	_, err := Scaffold(context.Background(), filepath.Join(t.TempDir(), "Bad_Name"), ScaffoldOptions{})
	require.ErrorContains(t, err, "must be lowercase alphanumeric")
}

func TestScaffold_RejectsUnsupportedKind(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "check-service")
	_, err := Scaffold(context.Background(), dir, ScaffoldOptions{Kind: "Service"})
	require.ErrorContains(t, err, "unsupported kind")
	assert.NoDirExists(t, dir, "nothing should be written when the kind is rejected")
}

func TestScaffold_RefusesExistingRuleWithoutForce(t *testing.T) {
	dir := scaffoldRule(t, "already-here", ScaffoldOptions{})

	_, err := Scaffold(context.Background(), dir, ScaffoldOptions{})
	require.ErrorContains(t, err, "--force")

	_, err = Scaffold(context.Background(), dir, ScaffoldOptions{Force: true})
	require.NoError(t, err)
}

func TestScaffold_UsesSuppliedDescriptionAndRemediation(t *testing.T) {
	dir := scaffoldRule(t, "custom-text", ScaffoldOptions{
		Description: "fails when the workload is bad",
		Remediation: "make it good",
	})

	rule, ok, err := ruledir.Load(dir)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "fails when the workload is bad", rule.Rule.Description)
	assert.Equal(t, "make it good", rule.Rule.Remediation)
}

func TestScaffold_ForceReportsOnlyTheFilesItRewrote(t *testing.T) {
	dir := scaffoldRule(t, "force-target", ScaffoldOptions{})

	extraCase := filepath.Join(dir, "test", "extra", "input")
	require.NoError(t, os.MkdirAll(extraCase, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(extraCase, "resource.yaml"), []byte(extraCaseManifest), 0o600))

	first, err := Scaffold(context.Background(), dir, ScaffoldOptions{Force: true})
	require.NoError(t, err)
	extraExpected := filepath.Join(dir, "test", "extra", expectedFileName)
	assert.Contains(t, first, extraExpected, "a newly written expectation must be reported")

	second, err := Scaffold(context.Background(), dir, ScaffoldOptions{Force: true})
	require.NoError(t, err)
	assert.NotContains(t, second, extraExpected, "an expectation left untouched must not be reported as written")
}

func TestScaffold_UnevaluableCaseDoesNotStopTheGeneratedOnes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my-rule")
	brokenInput := filepath.Join(dir, "test", "broken", "input")
	require.NoError(t, os.MkdirAll(brokenInput, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(brokenInput, "bad.yaml"), []byte("this: [is: not valid yaml\n"), 0o600))

	files, err := Scaffold(context.Background(), dir, ScaffoldOptions{})
	require.ErrorContains(t, err, `evaluate case "broken"`)

	for _, name := range []string{flaggedCaseName, cleanCaseName} {
		expected := filepath.Join(dir, "test", name, expectedFileName)
		assert.FileExists(t, expected, "the generated cases must still be recorded")
		assert.Contains(t, files, expected)
	}

	rules, err := DiscoverPath(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	for _, result := range RunRule(context.Background(), rules[0]) {
		if result.CaseName == "broken" {
			continue
		}
		require.NoError(t, result.Err)
		assert.True(t, result.Passed, result.Diff)
	}
}

func TestScaffold_ReportsEveryUnevaluableCase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my-rule")
	for _, name := range []string{"broken-one", "broken-two"} {
		input := filepath.Join(dir, "test", name, "input")
		require.NoError(t, os.MkdirAll(input, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(input, "bad.yaml"), []byte("bad: [yaml\n"), 0o600))
	}

	_, err := Scaffold(context.Background(), dir, ScaffoldOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken-one")
	assert.Contains(t, err.Error(), "broken-two")
}
