package diff

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintGitHubActions_Posture(t *testing.T) {
	summaryFile := filepath.Join(t.TempDir(), "step-summary.md")
	t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

	cs := &ChangeSet{
		New: []ControlChange{
			{
				ResourceID:  "apps/v1/default/Deployment/web",
				ControlID:   "C-0017",
				ControlName: "Immutable container filesystem",
				Severity:    "High",
				BaseStatus:  "passed",
				HeadStatus:  "failed",
				Path:        "deploy/web,1:app.yaml",
			},
			{
				ResourceID: "v1/default/Pod/low-pod",
				ControlID:  "C-LOW",
				Severity:   "Low",
				BaseStatus: "passed",
				HeadStatus: "failed",
			},
		},
		Incomparable: []ControlChange{
			{
				ResourceID: "apps/v1/default/Deployment/api",
				ControlID:  "C-CRIT",
				Severity:   "Critical",
				HeadStatus: "failed",
				Reason:     "line1\nline2\x1b[31m",
			},
		},
	}

	var out bytes.Buffer
	require.NoError(t, PrintGitHubActions(&out, cs, "High"))

	got := out.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	require.Len(t, lines, 2, "Low finding must be filtered out; expected 1 incomparable + 1 new")

	assert.Contains(t, lines[0], "::error title=Kubescape incomparable regression%3A C-CRIT (Critical)::")
	assert.Contains(t, lines[0], "line1%0Aline2[31m")
	assert.NotContains(t, lines[0], "\x1b")

	assert.Contains(t, lines[1], "::error file=deploy/web%2C1%3Aapp.yaml,title=Kubescape new regression%3A C-0017 (High)::")
	assert.Contains(t, lines[1], "resource=apps/v1/default/Deployment/web")

	summaryBytes, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	assert.Contains(t, string(summaryBytes), "# Kubescape Diff Regressions")
	assert.Contains(t, string(summaryBytes), "C-0017")
	assert.Contains(t, string(summaryBytes), "C-CRIT")
	assert.NotContains(t, string(summaryBytes), "C-LOW")
}

func TestPrintGitHubActions_AnnotationCapAndTruncationWarning(t *testing.T) {
	t.Setenv(githubActionsStepSummaryEnvVar, "")

	cs := &ChangeSet{}
	for i := 0; i < 12; i++ {
		cs.New = append(cs.New, ControlChange{
			ResourceID: fmt.Sprintf("v1/default/Pod/p-%02d", i),
			ControlID:  "C-0017",
			Severity:   "High",
			BaseStatus: "passed",
			HeadStatus: "failed",
		})
	}

	var out bytes.Buffer
	require.NoError(t, PrintGitHubActions(&out, cs, "High"))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 11)
	for i := 0; i < 10; i++ {
		assert.True(t, strings.HasPrefix(lines[i], "::error "))
	}
	assert.Equal(t, "::warning title=Kubescape Diff::Showing 10 of 12 regressions; see the step summary or rerun with --format markdown for the full list.", lines[10])
}

func TestPrintVulnerabilityGitHubActions(t *testing.T) {
	summaryFile := filepath.Join(t.TempDir(), "vuln-summary.md")
	t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

	cs := &VulnerabilityChangeSet{
		BaseImages: []string{"app:1.0"},
		HeadImages: []string{"app:1.1"},
		New: []VulnerabilityChange{
			{ID: "CVE-LOW", Severity: "Low", Package: "zlib", Version: "1.0"},
			{ID: "CVE-CRIT", Severity: "Critical", Package: "openssl", Version: "3.0.1", FixedIn: []string{"3.0.2"}},
			{ID: "CVE-HIGH", Severity: "High", Package: "curl", Version: "8.0.0"},
		},
	}

	var out bytes.Buffer
	require.NoError(t, PrintVulnerabilityGitHubActions(&out, cs, "High"))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "::error title=Kubescape new vulnerability%3A CVE-CRIT (Critical)::package=openssl version=3.0.1 fix=3.0.2")
	assert.Contains(t, lines[1], "::error title=Kubescape new vulnerability%3A CVE-HIGH (High)::package=curl version=8.0.0 fix=none")

	summaryBytes, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	assert.Contains(t, string(summaryBytes), "CVE-CRIT")
	assert.Contains(t, string(summaryBytes), "CVE-HIGH")
	assert.NotContains(t, string(summaryBytes), "CVE-LOW")
}

func TestAppendStepSummary_ExistingFileSizeBudget(t *testing.T) {
	t.Run("truncates append to remaining capacity", func(t *testing.T) {
		summaryFile := filepath.Join(t.TempDir(), "step-summary.md")
		existing := strings.Repeat("a", 600*1024)
		require.NoError(t, os.WriteFile(summaryFile, []byte(existing), 0o600))
		t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

		payload := strings.Repeat("b", 600*1024)
		require.NoError(t, appendStepSummary(func() (string, error) {
			return payload, nil
		}))

		got, err := os.ReadFile(summaryFile)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(got), githubActionsMaxStepSummaryBytes)
		assert.True(t, strings.HasPrefix(string(got), existing))
		assert.True(t, strings.HasSuffix(string(got), githubActionsSummaryTruncatedNote))
	})

	t.Run("preserves existing content when no capacity remains", func(t *testing.T) {
		summaryFile := filepath.Join(t.TempDir(), "step-summary.md")
		existing := strings.Repeat("x", githubActionsMaxStepSummaryBytes)
		require.NoError(t, os.WriteFile(summaryFile, []byte(existing), 0o600))
		t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

		require.NoError(t, appendStepSummary(func() (string, error) {
			return "extra summary", nil
		}))

		got, err := os.ReadFile(summaryFile)
		require.NoError(t, err)
		assert.Equal(t, existing, string(got))
	})
}

func TestAppendStepSummary_TruncatesAtUTF8RuneBoundary(t *testing.T) {
	summaryFile := filepath.Join(t.TempDir(), "step-summary.md")
	// Leave room for 4 bytes of content plus the truncation note, then supply
	// a payload larger than remaining starting with two 3-byte UTF-8 runes ("€€", 6 bytes)
	// so byte offset 4 splits the second rune.
	existingLen := githubActionsMaxStepSummaryBytes - len(githubActionsSummaryTruncatedNote) - 4
	existing := strings.Repeat("a", existingLen)
	require.NoError(t, os.WriteFile(summaryFile, []byte(existing), 0o600))
	t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

	payload := "€€" + strings.Repeat("z", len(githubActionsSummaryTruncatedNote)+10)
	require.NoError(t, appendStepSummary(func() (string, error) {
		return payload, nil
	}))

	got, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	assert.True(t, utf8.Valid(got), "truncated summary must remain valid UTF-8")
	assert.LessOrEqual(t, len(got), githubActionsMaxStepSummaryBytes)
	assert.Equal(t, existing+"€"+githubActionsSummaryTruncatedNote, string(got))
}
