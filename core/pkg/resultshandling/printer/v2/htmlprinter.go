package printer

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	htmlOutputFile = "report"
)

//go:embed html/report.gohtml
var reportTemplate string

// The HTML report previously loaded this logo from raw.githubusercontent.com
// at view time, so the report only rendered correctly with network access
// and leaked the viewer's IP/UA to GitHub every time an offline scan report
// was opened. Embed the same logo the PDF printer already ships
// (pdf/logo.png) and inline it as a data URI instead.
//
//go:embed pdf/logo.png
var htmlLogoPNG []byte

// logoDataURI returns the embedded Kubescape logo as a data: URI. It is
// returned as template.URL, not a plain string, so html/template's URL
// sanitizer (which rejects the data: scheme by default) doesn't replace it
// with "#ZgotmplZ" when used as an <img src>.
func logoDataURI() template.URL {
	// #nosec G203 -- the input is our own go:embed'd logo.png, not
	// attacker-controlled data, so bypassing the URL sanitizer here is safe.
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(htmlLogoPNG))
}

var _ printer.IPrinter = &HtmlPrinter{}

type HTMLReportingCtx struct {
	OPASessionObj     *cautils.OPASessionObj
	ResourceTableView ResourceTableView
	// ImageScanSummary is set instead of the two fields above when this report
	// is for an image scan rather than a posture scan (#2782).
	ImageScanSummary *imageprinter.ImageScanSummary
	// LogoDataURI is the embedded Kubescape logo, inlined so the report
	// renders correctly without network access.
	LogoDataURI template.URL
}

type HtmlPrinter struct {
	writer *os.File
}

func NewHtmlPrinter() *HtmlPrinter {
	return &HtmlPrinter{}
}

func (hp *HtmlPrinter) SetWriter(ctx context.Context, outputFile string) error {
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.HtmlFormat, outputFile, htmlOutputFile)
	if !explicitOutput {
		// Raw HTML markup must never fall back to stdout on a TTY.
		outputFile = printer.ResolveDefaultOutputFile(printer.HtmlFormat, htmlOutputFile)
		logger.L().Info("no --output specified for html format; writing to default file",
			helpers.String("filename", outputFile))
	}
	if explicitOutput {
		var err error
		hp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	// Preserve the temp-file fallback for the implicit HTML destination.
	hp.writer = printer.GetWriterNoStdoutFallback(ctx, outputFile, "kubescape-report-*"+printer.HtmlOutputExt)
	return nil
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

	reportingCtx := HTMLReportingCtx{opaSessionObj, resourceTableView, imageScanSummary, logoDataURI()}
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
			ctlResults := buildResourceControlResultTable(result.AssociatedControls, &opaSessionObj.Report.SummaryDetails, resource)
			resourceTableView = append(resourceTableView, ResourceResult{resource, ctlResults})
		}
	}

	return resourceTableView
}

func buildResourceControlResult(resourceControl resourcesresults.ResourceAssociatedControl, control reportsummary.IControlSummary, resource workloadinterface.IMetadata) ResourceControlResult {
	ctlSeverity := apis.ControlSeverityToString(control.GetScoreFactor())
	ctlName := resourceControl.GetName()
	ctlID := resourceControl.GetID()
	ctlURL := cautils.GetControlLink(resourceControl.GetID())
	failedPaths := AssistedRemediationPathsWithCurrentValues(&resourceControl, resource)
	addContainerNameToAssistedRemediation(resource, &failedPaths)

	return ResourceControlResult{ctlSeverity, ctlName, ctlID, ctlURL, failedPaths}
}

func buildResourceControlResultTable(resourceControls []resourcesresults.ResourceAssociatedControl, summaryDetails *reportsummary.SummaryDetails, resource workloadinterface.IMetadata) []ResourceControlResult {
	var ctlResults []ResourceControlResult
	for _, resourceControl := range resourceControls {
		if resourceControl.GetStatus(nil).IsFailed() {
			control := summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, resourceControl.GetID())
			if control == nil {
				continue
			}
			ctlResult := buildResourceControlResult(resourceControl, control, resource)

			ctlResults = append(ctlResults, ctlResult)
		}
	}

	return ctlResults
}

// CloseWriter closes the HTML output writer, returning any error from flushing or closing.
func (p *HtmlPrinter) CloseWriter() error {
	if p.writer != nil && p.writer != os.Stdout {
		return p.writer.Close()
	}
	return nil
}
