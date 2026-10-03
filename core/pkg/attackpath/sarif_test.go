package attackpath

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrintSARIF_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := printSARIF(&buf, singlePathResult(), nil); err != nil {
		t.Fatalf("printSARIF error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, buf.String())
	}
}

func TestPrintSARIF_VersionIs2_1_0(t *testing.T) {
	var buf bytes.Buffer
	_ = printSARIF(&buf, singlePathResult(), nil)
	var out map[string]any
	_ = json.Unmarshal(buf.Bytes(), &out)
	if out["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", out["version"])
	}
}

func TestPrintSARIF_HasRunsAndResults(t *testing.T) {
	var buf bytes.Buffer
	_ = printSARIF(&buf, singlePathResult(), nil)
	var out map[string]any
	_ = json.Unmarshal(buf.Bytes(), &out)
	runs, _ := out["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]any)
	results, _ := run["results"].([]any)
	if len(results) != 1 {
		t.Errorf("expected 1 result for 1 path, got %d", len(results))
	}
}

func TestPrintSARIF_HighScoreIsErrorLevel(t *testing.T) {
	result := singlePathResult()
	result.Paths[0].Score = 9.0
	var buf bytes.Buffer
	_ = printSARIF(&buf, result, nil)
	if !strings.Contains(buf.String(), `"error"`) {
		t.Error("expected level 'error' for score >= 8.0")
	}
}

func TestPrintSARIF_TruncatedAddsNoteResult(t *testing.T) {
	result := singlePathResult()
	result.Truncated = true
	var buf bytes.Buffer
	_ = printSARIF(&buf, result, nil)
	var out map[string]any
	_ = json.Unmarshal(buf.Bytes(), &out)
	runs := out["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	// 1 path result + 1 truncation note
	if len(results) != 2 {
		t.Errorf("expected 2 results (path + truncation note), got %d", len(results))
	}
}

func TestPrintSARIF_EmptyResultHasNoResults(t *testing.T) {
	var buf bytes.Buffer
	_ = printSARIF(&buf, SearchResult{}, nil)
	var out map[string]any
	_ = json.Unmarshal(buf.Bytes(), &out)
	runs := out["runs"].([]any)
	run := runs[0].(map[string]any)
	results, _ := run["results"].([]any)
	if len(results) != 0 {
		t.Errorf("expected no results for empty SearchResult, got %d", len(results))
	}
}

func TestScoreToSARIFLevel(t *testing.T) {
	cases := map[float64]string{
		9.5: "error",
		8.0: "error",
		7.9: "warning",
		5.0: "warning",
		4.9: "note",
		0.0: "note",
	}
	for score, want := range cases {
		if got := scoreToSARIFLevel(score); got != want {
			t.Errorf("scoreToSARIFLevel(%.1f) = %q, want %q", score, got, want)
		}
	}
}
