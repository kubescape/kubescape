package printer

import (
	"context"
	_ "embed"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	htmlOutputFile = "report"
	htmlOutputExt  = ".html"
)

//go:embed html/report.gohtml
var reportTemplate string

var _ printer.IPrinter = &HtmlPrinter{}

type HTMLReportingCtx struct {
	OPASessionObj     *cautils.OPASessionObj
	ResourceTableView ResourceTableView
}

type HtmlPrinter struct {
	writer *os.File
}

func NewHtmlPrinter() *HtmlPrinter {
	return &HtmlPrinter{}
}

func (hp *HtmlPrinter) SetWriter(ctx context.Context, outputFile string) {
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = htmlOutputFile
		}
		if filepath.Ext(strings.TrimSpace(outputFile)) != htmlOutputExt {
			outputFile = outputFile + htmlOutputExt
		}
	}
	hp.writer = printer.GetWriter(ctx, outputFile)
}

func (hp *HtmlPrinter) PrintNextSteps() {

}

func (hp *HtmlPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	if opaSessionObj == nil {
		logger.L().Ctx(ctx).Error("failed to print results, missing data")
		return
	}

	tplFuncMap := template.FuncMap{
		"sum": func(nums ...int) int {
			total := 0
			for _, n := range nums {
				total += n
			}
			return total
		},
		"float32ToInt": cautils.Float32ToInt,
		"lower":        strings.ToLower,
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

	resourceTableView := buildResourceTableView(opaSessionObj)
	reportingCtx := HTMLReportingCtx{opaSessionObj, resourceTableView}
	err := tpl.Execute(hp.writer, reportingCtx)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to render template", helpers.Error(err))
		return
	}
	printer.LogOutputFile(hp.writer.Name())

}

func (hp *HtmlPrinter) Score(score float32) {
}

func buildResourceTableView(opaSessionObj *cautils.OPASessionObj) ResourceTableView {
	resourceTableView := make(ResourceTableView, 0)
	for resourceID, result := range opaSessionObj.ResourcesResult {
		if result.GetStatus(nil).IsFailed() {
			resource := opaSessionObj.AllResources[resourceID]
			ctlResults := buildResourceControlResultTable(result.AssociatedControls, &opaSessionObj.Report.SummaryDetails)
			resourceTableView = append(resourceTableView, ResourceResult{resource, ctlResults})
		}
	}

	return resourceTableView
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
			ctlResult := buildResourceControlResult(resourceControl, control)

			ctlResults = append(ctlResults, ctlResult)
		}
	}

	return ctlResults
}
