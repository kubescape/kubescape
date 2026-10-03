package attackpath

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintMarkdown_ContainsHeading(t *testing.T) {
	var buf bytes.Buffer
	if err := printMarkdown(&buf, singlePathResult(), nil); err != nil {
		t.Fatalf("printMarkdown error: %v", err)
	}
	if !strings.Contains(buf.String(), "# Kubescape Attack-Path Report") {
		t.Errorf("missing H1 heading, got:\n%s", buf.String())
	}
}

func TestPrintMarkdown_ContainsSummaryTable(t *testing.T) {
	var buf bytes.Buffer
	_ = printMarkdown(&buf, singlePathResult(), nil)
	if !strings.Contains(buf.String(), "| # | Score |") {
		t.Errorf("missing summary table header, got:\n%s", buf.String())
	}
}

func TestPrintMarkdown_NoPathsMessage(t *testing.T) {
	var buf bytes.Buffer
	_ = printMarkdown(&buf, SearchResult{}, nil)
	if !strings.Contains(buf.String(), "No attack paths found") {
		t.Errorf("expected no-paths message, got:\n%s", buf.String())
	}
}

func TestPrintMarkdown_TruncatedAppearsInNotices(t *testing.T) {
	result := singlePathResult()
	result.Truncated = true
	var buf bytes.Buffer
	_ = printMarkdown(&buf, result, nil)
	out := buf.String()
	if !strings.Contains(out, "Notices") || !strings.Contains(out, "Truncated") {
		t.Errorf("expected Notices section with Truncated warning, got:\n%s", out)
	}
}

func TestPrintMarkdown_UncertainEdgeCountInNotices(t *testing.T) {
	result := singlePathResult()
	result.UncertainEdgeCount = 2
	var buf bytes.Buffer
	_ = printMarkdown(&buf, result, nil)
	if !strings.Contains(buf.String(), "2 uncertain edge") {
		t.Errorf("expected uncertain edge count in output, got:\n%s", buf.String())
	}
}

func TestPrintMarkdown_WarningsAppearInNotices(t *testing.T) {
	var buf bytes.Buffer
	_ = printMarkdown(&buf, SearchResult{}, []string{"workload prod/web skipped"})
	if !strings.Contains(buf.String(), "prod/web skipped") {
		t.Errorf("expected warning in notices, got:\n%s", buf.String())
	}
}

func TestPrintMarkdown_PathDetailSection(t *testing.T) {
	var buf bytes.Buffer
	_ = printMarkdown(&buf, singlePathResult(), nil)
	if !strings.Contains(buf.String(), "## Path #1") {
		t.Errorf("expected path detail heading, got:\n%s", buf.String())
	}
}

func TestParseFormat_SARIFAndMarkdown(t *testing.T) {
	cases := map[string]Format{
		"sarif":    FormatSARIF,
		"SARIF":    FormatSARIF,
		"markdown": FormatMarkdown,
		"md":       FormatMarkdown,
	}
	for input, want := range cases {
		got, err := ParseFormat(input)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %v, %v; want %v, nil", input, got, err, want)
		}
	}
}
