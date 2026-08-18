package printer

import (
	"bytes"
	"context"
	"encoding/base64"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
)

func TestNewHtmlPrinter(t *testing.T) {
	hp := NewHtmlPrinter()
	assert.NotNil(t, hp)
	assert.Nil(t, hp.writer)
}

func TestSetWriter_Html(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		expected   string
	}{
		{
			name:       "Output file name doesn't contain any extension",
			outputFile: "customFilename",
			expected:   "customFilename.html",
		},
		{
			name:       "Output file name already contains .html",
			outputFile: "customFilename.html",
			expected:   "customFilename.html",
		},
		{
			// Regression for issue-6: empty --output must NOT fall through to
			// stdout — default to ./report.html instead.
			name:       "Output file name is empty defaults to report.html",
			outputFile: "",
			expected:   "report.html",
		},
		{
			name:       "Whitespace-only output file is treated as empty",
			outputFile: "   ",
			expected:   "report.html",
		},
		{
			name:       "Surrounding whitespace is trimmed",
			outputFile: "  myfile  ",
			expected:   "myfile.html",
		},
	}

	ctx := context.Background()

	tmp := t.TempDir()
	origWd, err := os.Getwd()
	assert.NoError(t, err)
	assert.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hp := NewHtmlPrinter()
			hp.SetWriter(ctx, tt.outputFile)
			t.Cleanup(func() {
				_ = hp.writer.Close()
			})
			assert.Equal(t, tt.expected, hp.writer.Name())
			assert.NotEqual(t, "/dev/stdout", hp.writer.Name(),
				"HTML printer must never write to stdout")
		})
	}
}

func TestBuildResourceControlResultTable_MissingControl(t *testing.T) {
	ac := resourcesresults.ResourceAssociatedControl{
		ControlID: "C-MISSING",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}

	summaryDetails := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{},
	}

	assert.NotPanics(t, func() {
		results := buildResourceControlResultTable([]resourcesresults.ResourceAssociatedControl{ac}, summaryDetails, nil)
		assert.Empty(t, results)
	})
}

func TestBuildResourceTableView_SkipsMissingResource(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.ResourcesResult = map[string]resourcesresults.Result{
		"r-1": {
			ResourceID: "r-1",
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				},
			},
		},
	}
	// Do not populate session.AllResources["r-1"]

	view := buildResourceTableView(session)
	assert.Empty(t, view, "missing resource should be skipped, not included with nil")
}

func TestHtmlPrinter_ActionPrint_RiskScoreRounding(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter()
	hp.SetWriter(ctx, out)

	// Fixture counters (FailedResources: 2, AllResources: 100) are intentionally
	// distinct from the expected risk score (1) so no other numeric cell renders 0 or 1.
	session := cautils.NewOPASessionObjMock()
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		"C-0001": reportsummary.ControlSummary{
			ControlID:   "C-0001",
			Name:        "Test Fractional Risk Control",
			Score:       0.4,
			ScoreFactor: 1.0,
			StatusCounters: reportsummary.StatusCounters{
				FailedResources: 2,
				PassedResources: 98,
			},
		},
	}

	hp.ActionPrint(ctx, session, nil)
	hp.CloseWriter()

	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	htmlContent := string(content)

	// Fractional risk score 0.4% must round to 1% display, not 0%
	assert.Contains(t, htmlContent, `<td class="controlRiskCell numericCell">1</td>`)
	assert.NotContains(t, htmlContent, `<td class="controlRiskCell numericCell">0</td>`)
}

func TestHtmlPrinter_ActionPrint_LogoEmbeddedNotFetched(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "report.html")

	hp := NewHtmlPrinter()
	hp.SetWriter(ctx, out)

	session := cautils.NewOPASessionObjMock()

	hp.ActionPrint(ctx, session, nil)
	hp.CloseWriter()

	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	htmlContent := string(content)

	// Report must never depend on a live, branch-tracking GitHub URL to render its logo.
	assert.NotContains(t, htmlContent, "raw.githubusercontent.com",
		"HTML report must not fetch its logo from a live GitHub URL")

	// html/template HTML-entity-escapes some base64 characters (e.g. '+') in
	// attribute values, so the raw payload never appears verbatim in the rendered
	// HTML; unescape it back before decoding and comparing against the logo bytes.
	match := regexp.MustCompile(`<img class="logo" src="data:image/png;base64,([^"]+)">`).FindStringSubmatch(htmlContent)
	if assert.Len(t, match, 2, "HTML report must embed its logo as a data URI") {
		payload, err := base64.StdEncoding.DecodeString(html.UnescapeString(match[1]))
		assert.NoError(t, err, "embedded logo payload must be valid base64")
		assert.True(t, bytes.HasPrefix(payload, []byte("\x89PNG\r\n\x1a\n")), "embedded logo payload must be a valid PNG")
		assert.Equal(t, kubescapeLogoPNG, payload, "embedded logo payload must match the embedded kubescape logo")
	}
}
