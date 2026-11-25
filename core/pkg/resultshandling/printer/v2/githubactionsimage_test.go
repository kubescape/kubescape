package printer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func printGitHubActionsImageScan(t *testing.T, imageScanData []cautils.ImageScanData) (string, string) {
	t.Helper()
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "step-summary.md")
	gp := NewGitHubActionsPrinter()
	gp.stepSummaryPath = summaryPath
	require.NoError(t, gp.SetWriter(context.Background(), filepath.Join(dir, "github-actions.txt")))
	require.NoError(t, gp.ActionPrint(context.Background(), nil, imageScanData))
	require.NoError(t, gp.CloseWriter())

	annotations, err := os.ReadFile(filepath.Join(dir, "github-actions.txt"))
	require.NoError(t, err)
	summary, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	return string(annotations), string(summary)
}

func errorLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "::error ") {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestGitHubActionsPrinter_ImageScanAnnotations(t *testing.T) {
	exploited := containerScanningMatch("CVE-2024-0001", "Critical", "openssl", "a", "3.3.2")
	exploited.Vulnerability.Metadata.KnownExploited = []vulnerability.KnownExploited{{CVE: "CVE-2024-0001"}}
	likely := containerScanningMatch("CVE-2024-0002", "Critical", "zlib", "a")
	likely.Vulnerability.Metadata.EPSS = []vulnerability.EPSS{{CVE: "CVE-2024-0002", EPSS: 0.42, Percentile: 0.97}}
	plain := containerScanningMatch("CVE-2024-0003", "Critical", "busybox", "a")
	high := containerScanningMatch("CVE-2024-0004", "High", "curl", "a", "8.9.1")
	medium := containerScanningMatch("CVE-2024-0005", "Medium", "musl", "a")
	notAffected := containerScanningMatch("CVE-2024-0006", "Critical", "libxml2", "a")

	annotations, summary := printGitHubActionsImageScan(t, []cautils.ImageScanData{{
		Image:       "nginx:1.27",
		Matches:     match.NewMatches(plain, high, medium, notAffected, likely, exploited),
		VexStatuses: map[string]cautils.VexStatus{"CVE-2024-0006": {Status: "not_affected"}},
	}})

	assert.Equal(t, []string{
		"::error title=CVE-2024-0001 in openssl 1.0.0::Critical vulnerability CVE-2024-0001 in openssl 1.0.0 (image nginx:1.27). Fixed in 3.3.2. Exploit signals: CISA KEV.",
		"::error title=CVE-2024-0002 in zlib 1.0.0::Critical vulnerability CVE-2024-0002 in zlib 1.0.0 (image nginx:1.27). No fix is available. Exploit signals: EPSS 42.0%25 (97th).",
		"::error title=CVE-2024-0003 in busybox 1.0.0::Critical vulnerability CVE-2024-0003 in busybox 1.0.0 (image nginx:1.27). No fix is available.",
		"::error title=CVE-2024-0004 in curl 1.0.0::High vulnerability CVE-2024-0004 in curl 1.0.0 (image nginx:1.27). Fixed in 8.9.1.",
	}, errorLines(annotations))
	assert.Contains(t, annotations, "Kubescape: 4 of 4 High/Critical vulnerability(ies) annotated; 0 suppressed by GitHub's 10-annotation step limit; 1 vulnerability(ies) below the High severity threshold; 1 marked not affected or fixed by VEX.")
	assert.NotContains(t, annotations, "CVE-2024-0006")

	assert.Contains(t, summary, "### Kubescape Image Scan Summary")
	assert.Contains(t, summary, "| nginx:1.27 | 3 | 1 | 1 | 0 | 0 | 1 |")
	assert.Contains(t, summary, "| Critical | CVE-2024-0001 | openssl | 1.0.0 | 3.3.2 | CISA KEV | nginx:1.27 |")
	assert.Contains(t, summary, "| High | CVE-2024-0004 | curl | 1.0.0 | 8.9.1 | - | nginx:1.27 |")
	assert.NotContains(t, summary, "CVE-2024-0006")
}

func TestGitHubActionsPrinter_ImageScanCapsAnnotationsButSummarizesAll(t *testing.T) {
	matches := make([]match.Match, 0, 12)
	for i := range 12 {
		matches = append(matches, containerScanningMatch(fmt.Sprintf("CVE-2024-1%03d", i), "High", fmt.Sprintf("pkg%02d", i), "a"))
	}

	annotations, summary := printGitHubActionsImageScan(t, []cautils.ImageScanData{{Image: "app:1.0", Matches: match.NewMatches(matches...)}})

	assert.Len(t, errorLines(annotations), githubActionsMaxAnnotations)
	assert.Contains(t, annotations, "Kubescape: 10 of 12 High/Critical vulnerability(ies) annotated; 2 suppressed by GitHub's 10-annotation step limit")
	assert.Contains(t, summary, "CVE-2024-1011")
}

func TestGitHubActionsPrinter_ImageScanMergesDuplicateMatches(t *testing.T) {
	first := containerScanningMatch("CVE-2024-0007", "High", "openssl", "a", "3.3.2")
	second := containerScanningMatch("CVE-2024-0007", "High", "openssl", "b", "3.4.1", "3.3.2")

	annotations, summary := printGitHubActionsImageScan(t, []cautils.ImageScanData{{Image: "app:1.0", Matches: match.NewMatches(first, second)}})

	lines := errorLines(annotations)
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "Fixed in 3.3.2, 3.4.1.")
	assert.Contains(t, summary, "| app:1.0 | 0 | 1 | 0 | 0 | 0 | 0 |")
}

func TestGitHubActionsPrinter_ImageScanKeepsHighestRiskAcrossDuplicates(t *testing.T) {
	low := containerScanningMatch("CVE-2024-0010", "Medium", "openssl", "a", "3.3.2")
	low.Vulnerability.Metadata.EPSS = []vulnerability.EPSS{{CVE: "CVE-2024-0010", EPSS: 0.3, Percentile: 0.9}}
	critical := containerScanningMatch("CVE-2024-0010", "Critical", "openssl", "b", "3.4.1")
	critical.Vulnerability.Metadata.KnownExploited = []vulnerability.KnownExploited{{CVE: "CVE-2024-0010"}}
	critical.Vulnerability.Metadata.EPSS = []vulnerability.EPSS{{CVE: "CVE-2024-0010", EPSS: 0.1, Percentile: 0.5}}

	annotations, summary := printGitHubActionsImageScan(t, []cautils.ImageScanData{{Image: "app:1.0", Matches: match.NewMatches(low, critical)}})

	assert.Equal(t, []string{
		"::error title=CVE-2024-0010 in openssl 1.0.0::Critical vulnerability CVE-2024-0010 in openssl 1.0.0 (image app:1.0). Fixed in 3.3.2, 3.4.1. Exploit signals: CISA KEV, EPSS 30.0%25 (90th).",
	}, errorLines(annotations))
	assert.Contains(t, annotations, "Kubescape: 1 of 1 High/Critical vulnerability(ies) annotated; 0 suppressed by GitHub's 10-annotation step limit; 0 vulnerability(ies) below the High severity threshold;")
	assert.Contains(t, summary, "| app:1.0 | 1 | 0 | 0 | 0 | 0 | 0 |")
}

func TestGitHubActionsPrinter_ImageScanKeepsPlatformsApart(t *testing.T) {
	vuln := containerScanningMatch("CVE-2024-0008", "Critical", "glibc", "a")

	annotations, summary := printGitHubActionsImageScan(t, []cautils.ImageScanData{
		{Image: "app:1.0", Platform: "linux/amd64", Matches: match.NewMatches(vuln)},
		{Image: "app:1.0", Platform: "linux/arm64", Matches: match.NewMatches(vuln)},
	})

	lines := errorLines(annotations)
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "(image app:1.0 (linux/amd64))")
	assert.Contains(t, lines[1], "(image app:1.0 (linux/arm64))")
	assert.Contains(t, summary, "| app:1.0 (linux/amd64) | 1 | 0 | 0 | 0 | 0 | 0 |")
	assert.Contains(t, summary, "| app:1.0 (linux/arm64) | 1 | 0 | 0 | 0 | 0 | 0 |")
}

func TestGitHubActionsPrinter_CleanImageScan(t *testing.T) {
	annotations, summary := printGitHubActionsImageScan(t, []cautils.ImageScanData{{Image: "distroless:latest"}})

	assert.Empty(t, errorLines(annotations))
	assert.Contains(t, annotations, "Kubescape: 0 of 0 High/Critical vulnerability(ies) annotated")
	assert.Contains(t, summary, "| distroless:latest | 0 | 0 | 0 | 0 | 0 | 0 |")
	assert.NotContains(t, summary, "#### High/Critical Vulnerabilities")
}

func TestGitHubActionsPrinter_ImageScanEscapesWorkflowCommands(t *testing.T) {
	vuln := containerScanningMatch("CVE-2024-0009", "High", "evil,pkg:x%y", "a")

	annotations, _ := printGitHubActionsImageScan(t, []cautils.ImageScanData{{Image: "app:1.0\n::warning::spoofed", Matches: match.NewMatches(vuln)}})

	lines := errorLines(annotations)
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "title=CVE-2024-0009 in evil%2Cpkg%3Ax%25y 1.0.0::")
	assert.Contains(t, lines[0], "app:1.0%0A::warning::spoofed")
	assert.NotContains(t, annotations, "\n::warning::spoofed")
}

func TestGenerateImageStepSummary_TruncatesWithinBudget(t *testing.T) {
	matches := make([]match.Match, 0, 50)
	for i := range 50 {
		matches = append(matches, containerScanningMatch(fmt.Sprintf("CVE-2024-2%03d", i), "Critical", fmt.Sprintf("package-%02d", i), "a"))
	}
	findings, counts := collectImageFindings([]cautils.ImageScanData{{Image: "app:1.0", Matches: match.NewMatches(matches...)}})

	full := generateImageStepSummary(counts, findings, githubActionsMaxStepSummaryBytes)
	require.Contains(t, full, "CVE-2024-2049")

	budget := len(full) / 2
	truncated := generateImageStepSummary(counts, findings, budget)
	assert.LessOrEqual(t, len(truncated), budget)
	assert.Contains(t, truncated, "### Kubescape Image Scan Summary")
	assert.Contains(t, truncated, "entries omitted")
	assert.Empty(t, generateImageStepSummary(counts, findings, 0))
}
