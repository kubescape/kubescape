package printer

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	htmlOutputFile = "report"
)

//go:embed html/report.gohtml
var reportTemplate string

var _ printer.IPrinter = &HtmlPrinter{}

type HTMLReportingCtx struct {
	OPASessionObj     *cautils.OPASessionObj
	ResourceTableView ResourceTableView
	// ImageScanSummary is set instead of the two fields above when this report
	// is for an image scan rather than a posture scan (#2782).
	ImageScanSummary *imageprinter.ImageScanSummary
}

type HtmlPrinter struct {
	writer *os.File
}

func NewHtmlPrinter() *HtmlPrinter {
	return &HtmlPrinter{}
}

func (hp *HtmlPrinter) SetWriter(ctx context.Context, outputFile string) {
	outputFile = strings.TrimSpace(outputFile)
	if outputFile == "" {
		// Raw HTML markup must never fall back to stdout on a TTY.
		outputFile = htmlOutputFile + printer.HtmlOutputExt
		logger.L().Info("no --output specified for html format; writing to default file",
			helpers.String("filename", outputFile))
	} else if filepath.Ext(outputFile) != printer.HtmlOutputExt {
		outputFile = outputFile + printer.HtmlOutputExt
	}
	// HTML must never fall back to stdout on file-create errors either
	// (e.g. read-only cwd) — use the no-stdout-fallback helper.
	hp.writer = printer.GetWriterNoStdoutFallback(ctx, outputFile, "kubescape-report-*"+printer.HtmlOutputExt)
}

func (hp *HtmlPrinter) PrintNextSteps() {

}

func (hp *HtmlPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj == nil && len(imageScanData) == 0 {
		return fmt.Errorf("failed to print results, missing data")
	}

	tplFuncMap := template.FuncMap{
		"sum": func(nums ...int) int {
			total := 0
			for _, n := range nums {
				total += n
			}
			return total
		},
		"riskScoreToInt": cautils.RiskScoreToInt,
		"lower":          strings.ToLower,
		"sortByNamespace": func(resourceTableView ResourceTableView) ResourceTableView {
			sortedResourceTableView := make(ResourceTableView, len(resourceTableView))
			copy(sortedResourceTableView, resourceTableView)

			sort.SliceStable(
				sortedResourceTableView,
				func(i, j int) bool {
					return sortedResourceTableView[i].Resource.GetNamespace() < sortedResourceTableView[j].Resource.GetNamespace()
				},
			)
			return sortedResourceTableView
		},
		"controlSeverityToString": apis.ControlSeverityToString,
		"sortBySeverityName": func(controlSummaries map[string]reportsummary.ControlSummary) []reportsummary.ControlSummary {
			sortedSlice := make([]reportsummary.ControlSummary, 0, len(controlSummaries))
			for _, val := range controlSummaries {
				sortedSlice = append(sortedSlice, val)
			}

			sort.SliceStable(
				sortedSlice,
				func(i, j int) bool {
					//First sort by Severity descending
					iSeverity := apis.ControlSeverityToInt(sortedSlice[i].GetScoreFactor())
					jSeverity := apis.ControlSeverityToInt(sortedSlice[j].GetScoreFactor())
					if iSeverity > jSeverity {
						return true
					}
					if iSeverity < jSeverity {
						return false
					}
					//And then by Name ascending
					return sortedSlice[i].GetName() < sortedSlice[j].GetName()
				},
			)

			return sortedSlice
		},
	}
	tpl := template.Must(
		template.New("htmlReport").Funcs(tplFuncMap).Parse(reportTemplate),
	)

	var resourceTableView ResourceTableView
	var imageScanSummary *imageprinter.ImageScanSummary
	if opaSessionObj != nil {
		resourceTableView = buildResourceTableView(opaSessionObj)
	} else {
		imageScanSummary = buildImageScanSummary(imageScanData)
	}

	reportingCtx := HTMLReportingCtx{opaSessionObj, resourceTableView, imageScanSummary}
	err := tpl.Execute(hp.writer, reportingCtx)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to render template", helpers.Error(err))
		return fmt.Errorf("failed to render template: %w", err)
	}
	printer.LogOutputFile(hp.writer.Name())

	return nil
}

func (hp *HtmlPrinter) Score(score float32) {
}

func buildResourceTableView(opaSessionObj *cautils.OPASessionObj) ResourceTableView {
	resourceTableView := make(ResourceTableView, 0)
	for resourceID, result := range opaSessionObj.ResourcesResult {
		if result.GetStatus(nil).IsFailed() {
			resource, ok := opaSessionObj.AllResources[resourceID]
			if !ok {
				logger.L().Debug("resource missing from AllResources, skipping",
					helpers.String("resourceID", resourceID))
				continue
			}
			ctlResults := buildResourceControlResultTable(result.AssociatedControls, &opaSessionObj.Report.SummaryDetails)
			resourceTableView = append(resourceTableView, ResourceResult{resource, ctlResults})
		}
	}

	return resourceTableView
}

// buildImageScanSummary aggregates CVE, package-score, and severity data for an image scan report (#2782)
func buildImageScanSummary(imageScanData []cautils.ImageScanData) *imageprinter.ImageScanSummary {
	imageScanSummary := &imageprinter.ImageScanSummary{
		CVEs:                  []imageprinter.CVE{},
		PackageScores:         map[string]*imageprinter.PackageScore{},
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{},
	}

	for i := range imageScanData {
		if !slices.Contains(imageScanSummary.Images, imageScanData[i].Image) {
			imageScanSummary.Images = append(imageScanSummary.Images, imageScanData[i].Image)
		}

		cves := extractCVEs(imageScanData[i].Matches, imageScanData[i].Image)
		imageScanSummary.CVEs = append(imageScanSummary.CVEs, cves...)

		setPkgNameToScoreMap(imageScanData[i].Matches, imageScanSummary.PackageScores)
		setSeverityToSummaryMap(cves, imageScanSummary.MapsSeverityToSummary)
	}

	return imageScanSummary
}

func buildResourceControlResult(resourceControl resourcesresults.ResourceAssociatedControl, control reportsummary.IControlSummary) ResourceControlResult {
	ctlSeverity := apis.ControlSeverityToString(control.GetScoreFactor())
	ctlName := resourceControl.GetName()
	ctlID := resourceControl.GetID()
	ctlURL := cautils.GetControlLink(resourceControl.GetID())
	failedPaths := AssistedRemediationPathsToString(&resourceControl)

	return ResourceControlResult{ctlSeverity, ctlName, ctlID, ctlURL, failedPaths}
}

func buildResourceControlResultTable(resourceControls []resourcesresults.ResourceAssociatedControl, summaryDetails *reportsummary.SummaryDetails) []ResourceControlResult {
	var ctlResults []ResourceControlResult
	for _, resourceControl := range resourceControls {
		if resourceControl.GetStatus(nil).IsFailed() {
			control := summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, resourceControl.GetID())
			if control == nil {
				continue
			}
			ctlResult := buildResourceControlResult(resourceControl, control)

			ctlResults = append(ctlResults, ctlResult)
		}
	}

	return ctlResults
}

func (p *HtmlPrinter) CloseWriter() {
	if p.writer != nil && p.writer != os.Stdout {
		p.writer.Close()
	}
}
