package printer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPdfPrinter(t *testing.T) {
	pp := NewPdfPrinter()
	assert.NotNil(t, pp)
	assert.Empty(t, pp)
}

func TestScore_Pdf(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{
			name:  "Score not an integer",
			score: 20.7,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 21\n",
		},
		{
			name:  "Fractional score below perfect",
			score: 99.5,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 99\n",
		},
		{
			name:  "Score less than 0",
			score: -20.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
		{
			name:  "Score 50",
			score: 50.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 50\n",
		},
		{
			name:  "Zero Score",
			score: 0.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
	}

	pp := NewPdfPrinter()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "pdfPrinter-score-output")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			pp.Score(tt.score)

			f.Seek(0, 0)
			got, err := io.ReadAll(f)
			if err != nil {
				panic(err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestSetWriter_Pdf(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		expected   string
	}{
		{
			name:       "Output file name contains doesn't contain any extension",
			outputFile: "customFilename",
			expected:   "customFilename.pdf",
		},
		{
			name:       "Output file name contains .pdf",
			outputFile: "customFilename.pdf",
			expected:   "customFilename.pdf",
		},
		{
			name:       "Output file name is empty defaults to report.pdf",
			outputFile: "",
			expected:   "report.pdf",
		},
		{
			name:       "Whitespace-only output file is treated as empty",
			outputFile: "   ",
			expected:   "report.pdf",
		},
		{
			name:       "Surrounding whitespace is trimmed",
			outputFile: "  myfile  ",
			expected:   "myfile.pdf",
		},
	}

	pp := NewPdfPrinter()
	ctx := context.Background()

	tmp := t.TempDir()
	origWd, err := os.Getwd()
	assert.NoError(t, err)
	assert.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pp.SetWriter(ctx, tt.outputFile)
			// Each call opens a new file and overwrites the previous writer,
			// so every iteration leaks a handle. Windows will not remove the
			// temp dir these land in while any of them is still open.
			w := pp.writer
			defer w.Close()
			assert.Equal(t, tt.expected, pp.writer.Name())
			assert.NotEqual(t, "/dev/stdout", pp.writer.Name(),
				"PDF printer must never write to stdout")
		})
	}
}

func TestGetImageTableObjects_EmptyCVEs(t *testing.T) {
	pp := NewPdfPrinter()
	rows, fixableCVEs := pp.getImageTableObjects(nil)

	if rows == nil {
		t.Fatal("expected non-nil rows for empty CVE list, got nil")
	}
	if len(*rows) != 1 {
		t.Fatalf("expected 1 placeholder row for empty CVE list, got %d", len(*rows))
	}
	if fixableCVEs != 0 {
		t.Fatalf("expected 0 fixable CVEs, got %d", fixableCVEs)
	}
}

func TestGenerateImagePdf_NoVulnerabilities(t *testing.T) {
	pp := NewPdfPrinter()
	data := []cautils.ImageScanData{
		{Image: "clean-image:latest", Matches: match.NewMatches()},
	}
	out, err := pp.generateImagePdf(data)
	if err != nil {
		t.Fatalf("expected no error generating PDF for clean image, got: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty PDF bytes for clean image")
	}
}

// TestGeneratePdf_CombinedScanIncludesImageFindings checks that a combined PDF contains posture findings, image CVEs, and the clean-image placeholder.
func TestGeneratePdf_CombinedScanIncludesImageFindings(t *testing.T) {
	pp := NewPdfPrinter()
	summary := postureSummaryForPDF()
	reportTime := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	images := []cautils.ImageScanData{
		{
			Image:   "combined:first",
			Matches: match.NewMatches(pdfCVEMatch("CVE-COMBINED", "High")),
		},
	}

	postureOnly, err := pp.generatePdfAt(summary, nil, nil, reportTime)
	require.NoError(t, err)
	combined, err := pp.generatePdfAt(summary, nil, images, reportTime)
	require.NoError(t, err)
	require.NotEmpty(t, postureOnly)
	require.NotEmpty(t, combined)
	assert.NotEqual(t, postureOnly, combined, "combined PDF must include the image CVE table")
	assert.Contains(t, string(combined), "CVE-COMBINED")
	assert.Contains(t, string(combined), "C-COMBINED")
	assert.NotContains(t, string(postureOnly), "CVE-COMBINED")

	cleanCombined, err := pp.generatePdfAt(summary, nil, []cautils.ImageScanData{
		{Image: "clean-image:latest", Matches: match.NewMatches()},
	}, reportTime)
	require.NoError(t, err)
	require.NotEmpty(t, cleanCombined)
	assert.NotEqual(t, postureOnly, cleanCombined, "a clean image still adds the image section")
	assert.Contains(t, string(cleanCombined), "No vulnerabilities found")
}

// TestActionPrint_PdfCombinedWritesBothSections checks that ActionPrint writes posture and image findings into the PDF file.
func TestActionPrint_PdfCombinedWritesBothSections(t *testing.T) {
	pp := NewPdfPrinter()
	outputPath := filepath.Join(t.TempDir(), "combined.pdf")
	require.NoError(t, pp.SetWriter(context.Background(), outputPath))
	t.Cleanup(func() { _ = pp.CloseWriter() })

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{SummaryDetails: *postureSummaryForPDF()},
	}
	images := []cautils.ImageScanData{
		{
			Image:   "combined:first",
			Matches: match.NewMatches(pdfCVEMatch("CVE-COMBINED", "High")),
		},
	}
	require.NoError(t, pp.ActionPrint(context.Background(), session, images))
	require.NoError(t, pp.CloseWriter())

	raw, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	assert.Contains(t, string(raw), "CVE-COMBINED")
	assert.Contains(t, string(raw), "C-COMBINED")
}

// TestActionPrint_PdfMissingData checks that ActionPrint returns an error when neither posture nor image data is present.
func TestActionPrint_PdfMissingData(t *testing.T) {
	pp := NewPdfPrinter()
	err := pp.ActionPrint(context.Background(), nil, nil)
	require.EqualError(t, err, "failed to print results, missing data")
}

// postureSummaryForPDF returns a one-control posture summary for PDF printer tests.
func postureSummaryForPDF() *reportsummary.SummaryDetails {
	return &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-COMBINED": {
				ControlID:  "C-COMBINED",
				Name:       "Combined posture control",
				Status:     apis.StatusFailed,
				StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusFailed},
			},
		},
	}
}

// pdfCVEMatch builds a Grype vulnerability match for a PDF image-scan fixture.
func pdfCVEMatch(id, severity string) match.Match {
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: id, Namespace: "nvd"},
			Metadata:  &vulnerability.Metadata{ID: id, Severity: severity},
		},
		Package: grypepkg.Package{
			ID:      grypepkg.ID("pkg-" + id),
			Name:    "pkg-" + id,
			Version: "1.0.0",
		},
	}
}

// TestGeneratePdf_WithScanCoverageDegradedAndSkippedControls checks that degraded scan coverage and skipped controls are rendered in the PDF.
func TestGeneratePdf_WithScanCoverageDegradedAndSkippedControls(t *testing.T) {
	pp := NewPdfPrinter()
	reportTime := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					"C-0001": {
						ControlID:  "C-0001",
						Name:       "Evaluated control",
						Status:     apis.StatusPassed,
						StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusPassed},
					},
					"C-0002": {
						ControlID:   "C-0002",
						Name:        "Skipped daemonset control",
						ScoreFactor: 7.0,
						Status:      apis.StatusSkipped,
						StatusInfo: apis.StatusInfo{
							InnerStatus: apis.StatusSkipped,
							SubStatus:   apis.SubStatusConfiguration,
							InnerInfo:   "missing required daemonset permission",
						},
					},
				},
			},
		},
		ScanCoverage: cautils.ScanCoverage{
			CoverageScore:     50.0,
			EvaluatedControls: 1,
			TotalControls:     2,
			Degraded:          true,
		},
	}

	pdfBytes, err := pp.generatePdfAt(&session.Report.SummaryDetails, session, nil, reportTime)
	require.NoError(t, err)
	require.NotEmpty(t, pdfBytes)

	content := string(pdfBytes)
	assert.Contains(t, content, "Scan coverage", "PDF should render scan coverage row")
	assert.Contains(t, content, "1 evaluated")
	assert.Contains(t, content, "2 total")
	assert.Contains(t, content, "50.00%", "coverage percentage should be rendered")
	assert.Contains(t, content, "Degraded", "degraded badge should appear in scan coverage row")
	assert.Contains(t, content, "Skipped controls", "skipped controls section title should be present")
	assert.Contains(t, content, "C-0002", "skipped control ID should be listed in table")
	assert.Contains(t, content, "Skipped daemonset control", "skipped control name should be listed")
	assert.Contains(t, content, "missing required daemonset permission", "skip reason should be visible")
}

// TestGeneratePdf_CoverageOmittedWhenPerfect checks that a clean scan with 100% coverage and no skipped controls omits the coverage section.
func TestGeneratePdf_CoverageOmittedWhenPerfect(t *testing.T) {
	pp := NewPdfPrinter()
	reportTime := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					"C-0001": {
						ControlID:  "C-0001",
						Name:       "Evaluated control",
						Status:     apis.StatusPassed,
						StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusPassed},
					},
				},
			},
		},
		ScanCoverage: cautils.ScanCoverage{
			CoverageScore:     100.0,
			EvaluatedControls: 1,
			TotalControls:     1,
			Degraded:          false,
		},
	}

	pdfBytes, err := pp.generatePdfAt(&session.Report.SummaryDetails, session, nil, reportTime)
	require.NoError(t, err)
	require.NotEmpty(t, pdfBytes)

	content := string(pdfBytes)
	assert.NotContains(t, content, "Skipped controls", "clean scan must omit skipped controls section")
	assert.NotContains(t, content, "Degraded", "clean scan must not mention degraded coverage")
	assert.NotContains(t, content, "Scan coverage", "clean scan must omit scan coverage section")
}

// TestGeneratePdf_UnexaminedKindsTriggersCoverageRow checks that unexamined kinds trigger the coverage summary row even when score is 100.
func TestGeneratePdf_UnexaminedKindsTriggersCoverageRow(t *testing.T) {
	pp := NewPdfPrinter()
	reportTime := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					"C-0001": {
						ControlID:  "C-0001",
						Name:       "Evaluated control",
						Status:     apis.StatusPassed,
						StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusPassed},
					},
				},
			},
		},
		ScanCoverage: cautils.ScanCoverage{
			CoverageScore:     100.0,
			EvaluatedControls: 1,
			TotalControls:     1,
			Degraded:          false,
			UnexaminedKinds: []cautils.UnexaminedKind{
				{GroupVersionResource: "batch/v1/cronjobs", Kind: "CronJob"},
			},
		},
	}

	pdfBytes, err := pp.generatePdfAt(&session.Report.SummaryDetails, session, nil, reportTime)
	require.NoError(t, err)
	require.NotEmpty(t, pdfBytes)

	content := string(pdfBytes)
	assert.Contains(t, content, "Scan coverage", "unexamined kinds should trigger scan coverage summary row")
	assert.Contains(t, content, "Unexamined resource kinds:", "unexamined kinds diagnostic should identify kind and GVR")
	assert.Contains(t, content, "CronJob", "unexamined kinds diagnostic should name the kind")
	assert.Contains(t, content, "batch/v1/cronjobs", "unexamined kinds diagnostic should name the GVR")
	assert.NotContains(t, content, "Skipped controls", "no controls were skipped so table is omitted")
}

// TestGeneratePdf_UnexaminedKindsLargeListPaginates verifies that large lists of unexamined kinds
// paginate across multiple pages so the final kind remains visible in the PDF output (#3958).
func TestGeneratePdf_UnexaminedKindsLargeListPaginates(t *testing.T) {
	pp := NewPdfPrinter()
	reportTime := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	var unexamined []cautils.UnexaminedKind
	for i := 0; i < 500; i++ {
		unexamined = append(unexamined, cautils.UnexaminedKind{
			Kind:                 fmt.Sprintf("ReviewKind%d", i),
			GroupVersionResource: fmt.Sprintf("custom.example.com/v1/reviewkinds%d", i),
		})
	}

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					"C-0001": {
						ControlID:  "C-0001",
						Name:       "Evaluated control",
						Status:     apis.StatusPassed,
						StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusPassed},
					},
				},
			},
		},
		ScanCoverage: cautils.ScanCoverage{
			CoverageScore:     100.0,
			EvaluatedControls: 1,
			TotalControls:     1,
			Degraded:          false,
			UnexaminedKinds:   unexamined,
		},
	}

	pdfBytes, err := pp.generatePdfAt(&session.Report.SummaryDetails, session, nil, reportTime)
	require.NoError(t, err)
	require.NotEmpty(t, pdfBytes)

	content := string(pdfBytes)
	assert.Contains(t, content, "ReviewKind0", "first unexamined kind must be rendered")
	assert.Contains(t, content, "ReviewKind499", "final unexamined kind must be visible across page boundaries")
	assert.Contains(t, content, "custom.example.com/v1/reviewkinds499", "final GVR must be visible")
}

func TestActionPrint_PdfWithScanCoverage(t *testing.T) {
	pp := NewPdfPrinter()
	outputPath := filepath.Join(t.TempDir(), "coverage_report.pdf")
	require.NoError(t, pp.SetWriter(context.Background(), outputPath))
	t.Cleanup(func() { _ = pp.CloseWriter() })

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					"C-0010": {
						ControlID:   "C-0010",
						Name:        "Skipped cronjob check",
						ScoreFactor: 4.0,
						Status:      apis.StatusSkipped,
						StatusInfo: apis.StatusInfo{
							InnerStatus: apis.StatusSkipped,
							SubStatus:   apis.SubStatusConfiguration,
							InnerInfo:   "cronjobs API unavailable",
						},
					},
				},
			},
		},
		ScanCoverage: cautils.ScanCoverage{
			CoverageScore:     0.0,
			EvaluatedControls: 0,
			TotalControls:     1,
			Degraded:          true,
		},
	}

	require.NoError(t, pp.ActionPrint(context.Background(), session, nil))
	require.NoError(t, pp.CloseWriter())

	raw, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	content := string(raw)
	assert.Contains(t, content, "Scan coverage")
	assert.Contains(t, content, "Skipped controls")
	assert.Contains(t, content, "C-0010")
	assert.Contains(t, content, "cronjobs API unavailable")
}
