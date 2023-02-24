package printer

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	sarifOutputFile = "report"
	sarifOutputExt  = ".sarif"

	toolName    = "kubescape"
	toolInfoURI = "https://armosec.io"
)

// sarifSeverityLevel is a SARIF-specific severity level for Rules and Results
type sarifSeverityLevel string

const (
	sarifSeverityLevelNote    sarifSeverityLevel = "note"
	sarifSeverityLevelWarning sarifSeverityLevel = "warning"
	sarifSeverityLevelError   sarifSeverityLevel = "error"
)

// scoreFactorToSARIFSeverityLevel returns a SARIF severity level that matches
// a given Kubescape severity score
func scoreFactorToSARIFSeverityLevel(score float32) sarifSeverityLevel {
	switch {
	case score >= 9.0:
		return sarifSeverityLevelError
	case score >= 4.0:
		return sarifSeverityLevelWarning
	}

	return sarifSeverityLevelNote
}

var _ printer.IPrinter = &SARIFPrinter{}

// SARIFPrinter is a printer that emits the report in the SARIF format
type SARIFPrinter struct {
	// outputFile is the name of the output file
	writer *os.File
}

// NewSARIFPrinter returns a new SARIF printer instance
func NewSARIFPrinter() *SARIFPrinter {
	return &SARIFPrinter{}
}

func (sp *SARIFPrinter) Score(score float32) {
}

func (sp *SARIFPrinter) SetWriter(ctx context.Context, outputFile string) {
	if strings.TrimSpace(outputFile) == "" {
		outputFile = sarifOutputFile
	}
	if filepath.Ext(strings.TrimSpace(outputFile)) != sarifOutputExt {
		outputFile = outputFile + sarifOutputExt
	}
	sp.writer = printer.GetWriter(ctx, outputFile)
}

// addRule adds a rule description to the scan run based on the given control summary
func (sp *SARIFPrinter) addRule(scanRun *sarif.Run, control reportsummary.IControlSummary) {
	controlSARIFSeverity := string(scoreFactorToSARIFSeverityLevel(control.GetScoreFactor()))

	configuration := sarif.NewReportingConfiguration().WithLevel(controlSARIFSeverity)

	scanRun.AddRule(control.GetID()).
		WithDefaultConfiguration(configuration).
		WithShortDescription(sarif.NewMultiformatMessageString(control.GetName())).
		WithFullDescription(sarif.NewMultiformatMessageString(control.GetDescription())).
		WithHelp(sarif.NewMultiformatMessageString(sp.generateRemediationMessage(control)))
}

// addResult adds a result of checking a rule to the scan run based on the given control summary
func (sp *SARIFPrinter) addResult(scanRun *sarif.Run, ctl reportsummary.IControlSummary, filepath string, location locationresolver.Location) {
	scanRun.CreateResultForRule(ctl.GetID()).
		WithMessage(sarif.NewTextMessage(ctl.GetDescription())).
		AddLocation(
			sarif.NewLocationWithPhysicalLocation(
				sarif.NewPhysicalLocation().
					WithArtifactLocation(
						sarif.NewSimpleArtifactLocation(filepath),
					).WithRegion(
					sarif.NewRegion().WithStartLine(location.Line).WithStartColumn(location.Column),
				),
			),
		)
}

func (sp *SARIFPrinter) ActionPrint(_ context.Context, opaSessionObj *cautils.OPASessionObj) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		panic(err)
	}

	run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)
	basePath := getBasePathFromMetadata(*opaSessionObj)

	for resourceID, result := range opaSessionObj.ResourcesResult {
		if result.GetStatus(nil).IsFailed() {
			resourceSource := opaSessionObj.ResourceSource[resourceID]
			filepath := resourceSource.RelativePath

			// Github Code Scanning considers results not associated to a file path meaningless and invalid when uploading
			if filepath == "" || basePath == "" {
				continue
			}

			rsrcAbsPath := path.Join(basePath, filepath)
			locationResolver, err := locationresolver.NewFixPathLocationResolver(rsrcAbsPath)
			if err != nil {
				logger.L().Debug("failed to create location resolver", helpers.Error(err))
			}

			for _, toPin := range result.AssociatedControls {
				ac := toPin

				if ac.GetStatus(nil).IsFailed() {
					ctl := opaSessionObj.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ac.GetID())
					location := sp.resolveFixLocation(opaSessionObj, locationResolver, &ac, resourceID)

					sp.addRule(run, ctl)
					sp.addResult(run, ctl, filepath, location)
				}
			}
		}
	}

	report.AddRun(run)

	report.PrettyWrite(sp.writer)

	printer.LogOutputFile(sp.writer.Name())
}

func (sp *SARIFPrinter) resolveFixLocation(opaSessionObj *cautils.OPASessionObj, locationResolver *locationresolver.FixPathLocationResolver, ac *resourcesresults.ResourceAssociatedControl, resourceID string) locationresolver.Location {
	defaultLocation := locationresolver.Location{Line: 1, Column: 1}
	if locationResolver == nil {
		return defaultLocation
	}

	fixPaths := failedPathsToString(ac)
	if len(fixPaths) == 0 {
		fixPaths = fixPathsToString(ac)
	}
	var fixPath string
	if len(fixPaths) > 0 {
		fixPath = fixPaths[0]
	}

	var location locationresolver.Location
	if fixPath == "" {
		return defaultLocation
	}

	resource := opaSessionObj.AllResources[resourceID]
	localworkload, ok := resource.(*localworkload.LocalWorkload)
	if !ok {
		return defaultLocation
	}

	splittedPath := strings.Split(localworkload.GetPath(), ":")
	if len(splittedPath) <= 1 {
		return defaultLocation
	}

	docIndex, _ := strconv.Atoi(splittedPath[1])
	location, _ = locationResolver.ResolveLocation(fixPath, docIndex)
	if location.Line == 0 {
		return defaultLocation
	}

	return location
}

func getBasePathFromMetadata(opaSessionObj cautils.OPASessionObj) string {
	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget == v2.GitLocal {
		return opaSessionObj.Metadata.ContextMetadata.RepoContextMetadata.LocalRootPath
	}

	if opaSessionObj.Metadata.ScanMetadata.ScanningTarget == v2.Directory {
		return opaSessionObj.Metadata.ContextMetadata.DirectoryContextMetadata.BasePath
	}

	return ""
}

// generateRemediationMessage generates a remediation message for the given control summary
func (sp *SARIFPrinter) generateRemediationMessage(control reportsummary.IControlSummary) string {
	return fmt.Sprintf("Remediation: %s", control.GetRemediation())
}
