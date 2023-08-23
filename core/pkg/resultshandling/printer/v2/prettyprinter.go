package printer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/enescakir/emoji"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"k8s.io/utils/strings/slices"
)

const (
	prettyPrinterOutputFile             = "report"
	prettyPrinterOutputExt              = ".txt"
	clusterScanningScopeInformationLink = "https://github.com/kubescape/regolibrary/tree/master#add-a-framework"
)

var _ printer.IPrinter = &PrettyPrinter{}

type PrettyPrinter struct {
	writer          *os.File
	formatVersion   string
	viewType        cautils.ViewTypes
	verboseMode     bool
	printAttackTree bool
	scanType        cautils.ScanTypes
	inputPatterns   []string
	mainPrinter     prettyprinter.MainPrinter
	clusterName     string
}

func NewPrettyPrinter(verboseMode bool, formatVersion string, attackTree bool, viewType cautils.ViewTypes, scanType cautils.ScanTypes, inputPatterns []string, clusterName string) *PrettyPrinter {
	prettyPrinter := &PrettyPrinter{
		verboseMode:     verboseMode,
		formatVersion:   formatVersion,
		viewType:        viewType,
		printAttackTree: attackTree,
		scanType:        scanType,
		inputPatterns:   inputPatterns,
		clusterName:     clusterName,
	}

	return prettyPrinter
}

func (pp *PrettyPrinter) SetMainPrinter() {
	switch pp.scanType {
	case cautils.ScanTypeCluster:
		pp.mainPrinter = prettyprinter.NewClusterPrinter(pp.writer)
	case cautils.ScanTypeRepo:
		pp.mainPrinter = prettyprinter.NewRepoPrinter(pp.writer, pp.inputPatterns)
	case cautils.ScanTypeImage:
		pp.mainPrinter = prettyprinter.NewImagePrinter(pp.writer, pp.verboseMode)
	case cautils.ScanTypeWorkload:
		pp.mainPrinter = prettyprinter.NewWorkloadPrinter(pp.writer)
	default:
		pp.mainPrinter = prettyprinter.NewSummaryPrinter(pp.writer, pp.verboseMode)
	}
}

func (pp *PrettyPrinter) PrintNextSteps() {
	pp.mainPrinter.PrintNextSteps()
}

// convertToImageScanSummary takes a list of image scan data and converts it to a single image scan summary
func (pp *PrettyPrinter) convertToImageScanSummary(imageScanData []cautils.ImageScanData) (*imageprinter.ImageScanSummary, error) {
	imageScanSummary := imageprinter.ImageScanSummary{
		CVEs:                  []imageprinter.CVE{},
		PackageScores:         map[string]*imageprinter.PackageScore{},
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{},
	}

	for i := range imageScanData {
		if !slices.Contains(imageScanSummary.Images, imageScanData[i].Image) {
			imageScanSummary.Images = append(imageScanSummary.Images, imageScanData[i].Image)
		}

		presenterConfig := imageScanData[i].PresenterConfig
		doc, err := models.NewDocument(presenterConfig.Packages, presenterConfig.Context, presenterConfig.Matches, presenterConfig.IgnoredMatches, presenterConfig.MetadataProvider, nil, presenterConfig.DBStatus)
		if err != nil {
			logger.L().Error(fmt.Sprintf("failed to create document for image: %v", imageScanData[i].Image), helpers.Error(err))
			continue
		}

		CVEs := extractCVEs(doc.Matches)
		imageScanSummary.CVEs = append(imageScanSummary.CVEs, CVEs...)

		setPkgNameToScoreMap(doc.Matches, imageScanSummary.PackageScores)

		setSeverityToSummaryMap(CVEs, imageScanSummary.MapsSeverityToSummary)
	}

	return &imageScanSummary, nil
}

func (pp *PrettyPrinter) PrintImageScan(imageScanData []cautils.ImageScanData) {
	imageScanSummary, err := pp.convertToImageScanSummary(imageScanData)
	if err != nil {
		logger.L().Error("failed to convert to image scan summary", helpers.Error(err))
		return
	}
	pp.mainPrinter.PrintImageScanning(imageScanSummary)
}

func (pp *PrettyPrinter) ActionPrint(_ context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	if opaSessionObj != nil {
		if isPrintSeparatorType(pp.scanType) {
			fmt.Fprintf(pp.writer, "\n"+getSeparator("^")+"\n")
		} else {
			fmt.Fprintf(pp.writer, "\n")
		}

		sortedControlIDs := getSortedControlsIDs(opaSessionObj.Report.SummaryDetails.Controls) // ListControls().All())

		switch pp.viewType {
		case cautils.ControlViewType:
			pp.printResults(&opaSessionObj.Report.SummaryDetails.Controls, opaSessionObj.AllResources, sortedControlIDs)
		case cautils.ResourceViewType:
			if pp.verboseMode {
				pp.resourceTable(opaSessionObj)
			}
		}

		pp.printOverview(opaSessionObj, pp.verboseMode)

		pp.mainPrinter.PrintConfigurationsScanning(&opaSessionObj.Report.SummaryDetails, sortedControlIDs, opaSessionObj.TopWorkloadsByScore)

		// When writing to Stdout, we aren’t really writing to an output file,
		// so no need to print that we are
		if pp.writer.Name() != os.Stdout.Name() {
			printer.LogOutputFile(pp.writer.Name())
		}

		pp.printAttackTracks(opaSessionObj)
	}

	if len(imageScanData) > 0 {
		pp.PrintImageScan(imageScanData)
	}
}

func (pp *PrettyPrinter) printOverview(opaSessionObj *cautils.OPASessionObj, printExtraLine bool) {
	if printExtraLine {
		fmt.Fprintf(pp.writer, "\n")
	}

	pp.printHeader(opaSessionObj)
}

func (pp *PrettyPrinter) printHeader(opaSessionObj *cautils.OPASessionObj) {
	if pp.scanType == cautils.ScanTypeCluster || pp.scanType == cautils.ScanTypeRepo {
		cautils.InfoDisplay(pp.writer, fmt.Sprintf("\nKubescape security posture overview for cluster: %s\n\n", pp.clusterName))
		cautils.SimpleDisplay(pp.writer, "In this overview, Kubescape shows you a summary of your cluster security posture, including the number of users who can perform administrative actions. For each result greater than 0, you should evaluate its need, and then define an exception to allow it. This baseline can be used to detect drift in future.\n\n")
	} else if pp.scanType == cautils.ScanTypeWorkload {
		ns := opaSessionObj.SingleResourceScan.GetNamespace()
		if ns == "" {
			cautils.InfoDisplay(pp.writer, "Workload - Kind: %s, Name: %s\n\n", opaSessionObj.SingleResourceScan.GetKind(), opaSessionObj.SingleResourceScan.GetName())
		} else {
			cautils.InfoDisplay(pp.writer, "Workload - Namespace: %s, Kind: %s, Name: %s\n\n", opaSessionObj.SingleResourceScan.GetNamespace(), opaSessionObj.SingleResourceScan.GetKind(), opaSessionObj.SingleResourceScan.GetName())
		}
	}
}

func (pp *PrettyPrinter) SetWriter(ctx context.Context, outputFile string) {
	// PrettyPrinter should accept Stdout at least by its full name (path)
	// and follow the common behavior of outputting to a default filename
	// otherwise
	if outputFile == os.Stdout.Name() {
		pp.writer = printer.GetWriter(ctx, "")
		pp.SetMainPrinter()
		return
	}

	if strings.TrimSpace(outputFile) == "" {
		outputFile = prettyPrinterOutputFile
	}
	if filepath.Ext(strings.TrimSpace(outputFile)) != junitOutputExt {
		outputFile = outputFile + prettyPrinterOutputExt
	}

	pp.writer = printer.GetWriter(ctx, outputFile)

	pp.SetMainPrinter()
}

func (pp *PrettyPrinter) Score(score float32) {
}

func (pp *PrettyPrinter) printResults(controls *reportsummary.ControlSummaries, allResources map[string]workloadinterface.IMetadata, sortedControlIDs [][]string) {
	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			controlSummary := controls.GetControl(reportsummary.EControlCriteriaID, c) //  summaryDetails.Controls ListControls().All() Controls.GetControl(ca)
			pp.printTitle(controlSummary)
			pp.printResources(controlSummary, allResources)
			pp.printSummary(c, controlSummary)
		}
	}
}

func (prettyPrinter *PrettyPrinter) printSummary(controlName string, controlSummary reportsummary.IControlSummary) {
	cautils.SimpleDisplay(prettyPrinter.writer, "Summary - ")
	cautils.SuccessDisplay(prettyPrinter.writer, "Passed:%v   ", controlSummary.NumberOfResources().Passed())
	cautils.WarningDisplay(prettyPrinter.writer, "Action Required:%v   ", controlSummary.NumberOfResources().Skipped())
	cautils.FailureDisplay(prettyPrinter.writer, "Failed:%v   ", controlSummary.NumberOfResources().Failed())
	cautils.InfoDisplay(prettyPrinter.writer, "Total:%v\n", controlSummary.NumberOfResources().All())
	if controlSummary.GetStatus().IsFailed() {
		cautils.DescriptionDisplay(prettyPrinter.writer, "Remediation: %v\n", controlSummary.GetRemediation())
	}
	cautils.DescriptionDisplay(prettyPrinter.writer, "\n")

}

func (prettyPrinter *PrettyPrinter) printTitle(controlSummary reportsummary.IControlSummary) {
	cautils.InfoDisplay(prettyPrinter.writer, "[control: %s - %s] ", controlSummary.GetName(), cautils.GetControlLink(controlSummary.GetID()))
	statusDetails := ""
	if controlSummary.GetSubStatus() != apis.SubStatusUnknown {
		statusDetails = fmt.Sprintf(" (%s)", controlSummary.GetSubStatus())
	}
	switch controlSummary.GetStatus().Status() {
	case apis.StatusSkipped:
		cautils.InfoDisplay(prettyPrinter.writer, "action required%s %v\n", statusDetails, emoji.ConfusedFace)
	case apis.StatusFailed:
		cautils.FailureDisplay(prettyPrinter.writer, "failed%s %v\n", statusDetails, emoji.SadButRelievedFace)
	default:
		cautils.SuccessDisplay(prettyPrinter.writer, "passed%s %v\n", statusDetails, emoji.ThumbsUp)
	}
	cautils.DescriptionDisplay(prettyPrinter.writer, "Description: %s\n", controlSummary.GetDescription())
	if controlSummary.GetStatus().Info() != "" {
		cautils.WarningDisplay(prettyPrinter.writer, "Reason: %v\n", controlSummary.GetStatus().Info())
	}
}

func (pp *PrettyPrinter) printResources(controlSummary reportsummary.IControlSummary, allResources map[string]workloadinterface.IMetadata) {

	workloadsSummary := listResultSummary(controlSummary, allResources)

	failedWorkloads := groupByNamespaceOrKind(workloadsSummary, workloadSummaryFailed)
	skippedWorkloads := groupByNamespaceOrKind(workloadsSummary, workloadSummarySkipped)

	var passedWorkloads map[string][]WorkloadSummary
	if pp.verboseMode {
		passedWorkloads = groupByNamespaceOrKind(workloadsSummary, workloadSummaryPassed)
	}
	if len(failedWorkloads) > 0 {
		cautils.FailureDisplay(pp.writer, "Failed:\n")
		pp.printGroupedResources(failedWorkloads)
	}
	if len(skippedWorkloads) > 0 {
		cautils.WarningDisplay(pp.writer, "Action required:\n")
		pp.printGroupedResources(skippedWorkloads)
	}
	if len(passedWorkloads) > 0 {
		cautils.SuccessDisplay(pp.writer, "Passed:\n")
		pp.printGroupedResources(passedWorkloads)
	}

}

func (pp *PrettyPrinter) printGroupedResources(workloads map[string][]WorkloadSummary) {
	indent := "  "
	for title, rsc := range workloads {
		pp.printGroupedResource(indent, title, rsc)
	}
}

func (pp *PrettyPrinter) printGroupedResource(indent string, title string, rsc []WorkloadSummary) {
	if title != "" {
		cautils.SimpleDisplay(pp.writer, "%s%s\n", indent, title)
		indent += indent
	}

	resources := []string{}
	for r := range rsc {
		relatedObjectsStr := generateRelatedObjectsStr(rsc[r]) // TODO -
		resources = append(resources, fmt.Sprintf("%s%s - %s %s", indent, rsc[r].resource.GetKind(), rsc[r].resource.GetName(), relatedObjectsStr))
	}

	sort.Strings(resources)
	for i := range resources {
		cautils.SimpleDisplay(pp.writer, resources[i]+"\n")
	}
}

func generateRelatedObjectsStr(workload WorkloadSummary) string {
	relatedStr := ""
	if workload.resource.GetObjectType() == workloadinterface.TypeWorkloadObject {
		relatedObjects := objectsenvelopes.NewRegoResponseVectorObject(workload.resource.GetObject()).GetRelatedObjects()
		for i, related := range relatedObjects {
			if ns := related.GetNamespace(); i == 0 && ns != "" {
				relatedStr += fmt.Sprintf("Namespace - %s, ", ns)
			}
			relatedStr += fmt.Sprintf("%s - %s, ", related.GetKind(), related.GetName())
		}
	}
	if relatedStr != "" {
		relatedStr = fmt.Sprintf(" [%s]", relatedStr[:len(relatedStr)-2])
	}
	return relatedStr
}

func frameworksScoresToString(frameworks []reportsummary.IFrameworkSummary) string {
	if len(frameworks) == 1 {
		if frameworks[0].GetName() != "" {
			return fmt.Sprintf("FRAMEWORK %s\n", frameworks[0].GetName())
			// cautils.InfoTextDisplay(prettyPrinter.writer, ))
		}
	} else if len(frameworks) > 1 {
		p := "FRAMEWORKS: "
		i := 0
		for ; i < len(frameworks)-1; i++ {
			p += fmt.Sprintf("%s (compliance: %.2f), ", frameworks[i].GetName(), frameworks[i].GetComplianceScore())
		}
		p += fmt.Sprintf("%s (compliance: %.2f)\n", frameworks[i].GetName(), frameworks[i].GetComplianceScore())
		return p
	}
	return ""
}

func getSeparator(sep string) string {
	s := ""
	for i := 0; i < 80; i++ {
		s += sep
	}
	return s
}

func isPrintSeparatorType(scanType cautils.ScanTypes) bool {
	switch scanType {
	case cautils.ScanTypeCluster, cautils.ScanTypeRepo, cautils.ScanTypeImage, cautils.ScanTypeWorkload:
		return false
	default:
		return true
	}
}
