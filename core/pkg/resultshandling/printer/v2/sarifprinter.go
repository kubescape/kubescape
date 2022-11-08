package v2

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
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
	return
}

func (sp *SARIFPrinter) SetWriter(outputFile string) {
	if outputFile == "" {
		outputFile = sarifOutputFile
	}
	if filepath.Ext(strings.TrimSpace(outputFile)) != sarifOutputExt {
		outputFile = outputFile + sarifOutputExt
	}
	sp.writer = printer.GetWriter(outputFile)
}

// addRule adds a rule description to the scan run based on the given control summary
func (sp *SARIFPrinter) addRule(scanRun *sarif.Run, control reportsummary.IControlSummary) {
	controlSARIFSeverity := string(scoreFactorToSARIFSeverityLevel(control.GetScoreFactor()))

	configuration := sarif.NewReportingConfiguration().WithLevel(controlSARIFSeverity)

	scanRun.AddRule(control.GetID()).
		WithDefaultConfiguration(configuration).
		WithShortDescription(sarif.NewMultiformatMessageString(control.GetName())).
		WithFullDescription(sarif.NewMultiformatMessageString(control.GetDescription())).
		WithHelp(sarif.NewMultiformatMessageString(control.GetRemediation()))
}

// addResult adds a result of checking a rule to the scan run based on the given control summary
func (sp *SARIFPrinter) addResult(scanRun *sarif.Run, ctl reportsummary.IControlSummary, filepath string) {
	scanRun.CreateResultForRule(ctl.GetID()).
		WithMessage(sarif.NewTextMessage(ctl.GetDescription())).
		AddLocation(
			sarif.NewLocationWithPhysicalLocation(
				sarif.NewPhysicalLocation().
					WithArtifactLocation(
						sarif.NewSimpleArtifactLocation(filepath),
					).WithRegion(
					sarif.NewSimpleRegion(1, 1),
				),
			),
		)
}

func (sp *SARIFPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj, imageScan bool) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		panic(err)
	}

	run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)

	for resourceID, result := range opaSessionObj.ResourcesResult {
		if result.GetStatus(nil).IsFailed() {
			resourceSource := opaSessionObj.ResourceSource[resourceID]
			filepath := resourceSource.RelativePath

			// Github Code Scanning considers results not associated to a file path meaningless and invalid when uploading
			if filepath == "" {
				continue
			}

			for _, ac := range result.AssociatedControls {
				if ac.GetStatus(nil).IsFailed() {
					ctl := opaSessionObj.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ac.GetID())
					sp.addRule(run, ctl)
					sp.addResult(run, ctl, filepath)
				}
			}
		}
	}

	report.AddRun(run)

	report.PrettyWrite(sp.writer)
}
