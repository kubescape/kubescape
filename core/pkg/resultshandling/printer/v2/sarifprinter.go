package printer

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/presenter/models"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/fixhandler"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/sergi/go-diff/diffmatchpatch"
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
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = sarifOutputFile
		}
		if filepath.Ext(strings.TrimSpace(outputFile)) != sarifOutputExt {
			outputFile = outputFile + sarifOutputExt
		}
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
func (sp *SARIFPrinter) addResult(scanRun *sarif.Run, ctl reportsummary.IControlSummary, filepath string, location locationresolver.Location) *sarif.Result {
	return scanRun.CreateResultForRule(ctl.GetID()).
		WithMessage(sarif.NewTextMessage(ctl.GetDescription())).
		WithLocations([]*sarif.Location{
			sarif.NewLocationWithPhysicalLocation(
				sarif.NewPhysicalLocation().
					WithArtifactLocation(
						sarif.NewSimpleArtifactLocation(filepath),
					).WithRegion(
					sarif.NewRegion().WithStartLine(location.Line).WithStartColumn(location.Column),
				),
			),
		})
}

func (sp *SARIFPrinter) printImageScan(ctx context.Context, scanResults *models.PresenterConfig) error {
	if scanResults == nil {
		return fmt.Errorf("no no image vulnerability data provided")
	}

	pres := presenter.GetPresenter(printer.SARIFFormat, "", false, *scanResults)
	if err := pres.Present(sp.writer); err != nil {
		return err
	}

	// Change driver name to Kubescape

	jsonReport, err := os.ReadFile(sp.writer.Name())
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to read json file - results will not be patched", helpers.Error(err))
		return nil
	}

	var sarifReport sarif.Report
	if err := json.Unmarshal(jsonReport, &sarifReport); err != nil {
		return err
	}

	// Patch driver name
	for i := range sarifReport.Runs {
		sarifReport.Runs[i].Tool.Driver.Name = "Kubescape"
	}

	// Write back to file
	updatedSarifReport, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(sp.writer.Name(), updatedSarifReport, os.ModePerm)
}

func (sp *SARIFPrinter) PrintNextSteps() {

}

func (sp *SARIFPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	if opaSessionObj == nil {
		if len(imageScanData) == 0 {
			logger.L().Ctx(ctx).Fatal("failed to write results in sarif format: no data provided")
			return
		}

		// image scan
		if err := sp.printImageScan(ctx, imageScanData[0].PresenterConfig); err != nil {
			logger.L().Ctx(ctx).Error("failed to write results in sarif format", helpers.Error(err))
			return
		}
	} else {
		// configuration scan
		if err := sp.printConfigurationScan(ctx, opaSessionObj); err != nil {
			logger.L().Ctx(ctx).Error("failed to write results in sarif format", helpers.Error(err))
			return
		}

	}
	printer.LogOutputFile(sp.writer.Name())
}

func (sp *SARIFPrinter) printConfigurationScan(ctx context.Context, opaSessionObj *cautils.OPASessionObj) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)
	basePath := getBasePathFromMetadata(*opaSessionObj)

	for resourceID, result := range opaSessionObj.ResourcesResult { //
		if result.GetStatus(nil).IsFailed() {
			helmChartFileType := false
			var mappingnodes []map[string]cautils.MappingNode
			resourceSource := opaSessionObj.ResourceSource[resourceID]
			filepath := resourceSource.RelativePath

			// Github Code Scanning considers results not associated to a file path meaningless and invalid when uploading
			if filepath == "" || basePath == "" {
				continue
			}

			// If the fileType is helm chart
			if templateNodes, ok := opaSessionObj.TemplateMapping[resourceID]; ok {
				mappingnodes = templateNodes.Nodes
				helmChartFileType = true
			}

			rsrcAbsPath := path.Join(basePath, filepath)
			locationResolver, err := locationresolver.NewFixPathLocationResolver(rsrcAbsPath) //
			if err != nil && !helmChartFileType {
				logger.L().Debug("failed to create location resolver", helpers.Error(err))
				continue
			}

			for _, toPin := range result.AssociatedControls {
				ac := toPin

				if ac.GetStatus(nil).IsFailed() {
					var location locationresolver.Location

					ctl := opaSessionObj.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ac.GetID())
					if helmChartFileType {
						for _, subfileNodes := range mappingnodes {
							// first get the failed path, then if cannot find it, use the Fix path, cui it to find the closest error.
							location, split := resolveFixLocation(subfileNodes, &ac)
							sp.addRule(run, ctl)
							r := sp.addResult(run, ctl, filepath, location)
							collectFixesFromMappingNodes(r, ac, opaSessionObj, resourceID, filepath, rsrcAbsPath, location, subfileNodes, split)
						}
					} else {
						location = sp.resolveFixLocation(opaSessionObj, locationResolver, &ac, resourceID)
						sp.addRule(run, ctl)
						r := sp.addResult(run, ctl, filepath, location)
						collectFixes(ctx, r, ac, opaSessionObj, resourceID, filepath, rsrcAbsPath)
					}

				}
			}
		}
	}

	report.AddRun(run)

	report.PrettyWrite(sp.writer)

	return nil
}

func (sp *SARIFPrinter) resolveFixLocation(opaSessionObj *cautils.OPASessionObj, locationResolver *locationresolver.FixPathLocationResolver, ac *resourcesresults.ResourceAssociatedControl, resourceID string) locationresolver.Location {
	defaultLocation := locationresolver.Location{Line: 1, Column: 1}
	if locationResolver == nil {
		return defaultLocation
	}

	fixPaths := AssistedRemediationPathsToString(ac)
	var fixPath string
	if len(fixPaths) > 0 {
		fixPath = fixPaths[0]
	}

	var location locationresolver.Location
	if fixPath == "" {
		return defaultLocation
	}

	docIndex, ok := getDocIndex(opaSessionObj, resourceID)

	if !ok {
		return defaultLocation
	}

	location, _ = locationResolver.ResolveLocation(fixPath, docIndex)
	if location.Line == 0 {
		return defaultLocation
	}

	return location
}

func getFixPath(ac *resourcesresults.ResourceAssociatedControl, onlyPath bool) string {
	fixPaths := failedPathsToString(ac)
	if len(fixPaths) == 0 {
		fixPaths = fixPathsToString(ac, onlyPath)
	}
	var fixPath string
	if len(fixPaths) > 0 {
		fixPath = fixPaths[0]
	}
	return fixPath
}

func resolveFixLocation(mappingnodes map[string]cautils.MappingNode, ac *resourcesresults.ResourceAssociatedControl) (locationresolver.Location, int) {
	defaultLocation := locationresolver.Location{Line: 1, Column: 1}
	fixPath := getFixPath(ac, true)
	if fixPath == "" {
		return defaultLocation, -1
	}
	location, split := getLocationFromMappingNodes(mappingnodes, fixPath)
	return location, split
}

func getLocationFromNode(node cautils.MappingNode, path string) locationresolver.Location {
	line := node.TemplateLineNumber
	column := (len(strings.Split(path, "."))-1)*2 + 1 //column begins with 1 instead of 0
	return locationresolver.Location{Line: line, Column: column}
}

func getLocationFromMappingNodes(mappingnodes map[string]cautils.MappingNode, fixPath string) (locationresolver.Location, int) {
	var location locationresolver.Location
	// If cannot match any node, return default location
	location = locationresolver.Location{Line: 1, Column: 1}
	split := -1
	if node, ok := mappingnodes[fixPath]; ok {
		location = getLocationFromNode(node, fixPath)
	} else {
		fields := strings.Split(fixPath, ".")
		for i := len(fields) - 1; i >= 0; i-- {
			field := fields[:i]
			closestPath := strings.Join(field, ".")
			if node, ok := mappingnodes[closestPath]; ok {
				location = getLocationFromNode(node, closestPath)
				split = i
				break
			}
		}
	}
	return location, split
}

func addFix(result *sarif.Result, filepath string, startLine, startColumn, endLine, endColumn int, text string) {
	// Create a new replacement with the specified start and end lines and columns, and the inserted text.
	replacement := sarif.NewReplacement(
		sarif.NewRegion().
			WithStartLine(startLine).
			WithStartColumn(startColumn).
			WithEndLine(endLine).
			WithEndColumn(endColumn),
	).WithInsertedContent(sarif.NewArtifactContent().WithText(text))

	// Create a new artifact change with the specified file path and replacement.
	artifactChange := sarif.NewArtifactChange(
		sarif.NewSimpleArtifactLocation(filepath),
	).WithReplacement(replacement)

	// check if the fix is already added
	for _, fix := range result.Fixes {
		for _, ac := range fix.ArtifactChanges {
			if hashArtifactChange(ac) == hashArtifactChange(artifactChange) {
				return
			}
		}
	}

	// Add the artifact change to the result's fixes.
	result.AddFix(sarif.NewFix().WithArtifactChanges([]*sarif.ArtifactChange{artifactChange}))
}

func calculateMove(str string, file []string, endColumn int, endLine int) (int, int, bool) {
	num, err := strconv.Atoi(str)
	if err != nil {
		logger.L().Debug(fmt.Sprintf("failed to get move from string %s", str), helpers.Error(err))
		return 0, 0, false
	}
	if endLine > len(file) {
		return 0, 0, false
	}
	for num+endColumn-1 > len(file[endLine-1]) {
		num -= len(file[endLine-1]) - endColumn + 2
		endLine++
		endColumn = 1
	}
	endColumn += num
	return endLine, endColumn, true
}

func collectDiffs(dmp *diffmatchpatch.DiffMatchPatch, diffs []diffmatchpatch.Diff, result *sarif.Result, filepath string, fileAsString string) {
	file := strings.Split(fileAsString, "\n")
	text := ""
	startLine := 1
	startColumn := 1
	endLine := 1
	endColumn := 1

	delta := strings.Split(dmp.DiffToDelta(diffs), "\t")
	for index, seg := range delta {
		switch seg[0] {
		case '+':
			var err error
			text, err = url.QueryUnescape(seg[1:])
			if err != nil {
				logger.L().Debug("failed to unescape string", helpers.Error(err))
				continue
			}
			if index >= len(delta)-1 || delta[index+1][0] == '=' {
				addFix(result, filepath, startLine, startColumn, endLine, endColumn, text)
			}
		case '-':
			var ok bool
			endLine, endColumn, ok = calculateMove(seg[1:], file, endColumn, endLine)
			if !ok {
				continue
			}
			if index >= len(delta)-1 || delta[index+1][0] == '=' {
				addFix(result, filepath, startLine, startColumn, endLine, endColumn, text)
			}
		case '=':
			var ok bool
			endLine, endColumn, ok = calculateMove(seg[1:], file, endColumn, endLine)
			if !ok {
				continue
			}
			startLine = endLine
			startColumn = endColumn
			text = ""
		}
	}
}

func collectFixes(ctx context.Context, result *sarif.Result, ac resourcesresults.ResourceAssociatedControl, opaSessionObj *cautils.OPASessionObj, resourceID string, filepath string, rsrcAbsPath string) {
	for _, rule := range ac.ResourceAssociatedRules {
		if !rule.GetStatus(nil).IsFailed() {
			continue
		}

		for _, rulePaths := range rule.Paths {
			fixPath := rulePaths.FixPath.Path
			if fixPath == "" {
				continue
			}

			fileAsString, err := fixhandler.GetFileString(rsrcAbsPath)
			if err != nil {
				logger.L().Debug("failed to access "+filepath, helpers.Error(err))
				continue
			}

			var fixedYamlString string

			documentIndex, ok := getDocIndex(opaSessionObj, resourceID)
			if !ok {
				continue
			}

			yamlExpression := fixhandler.FixPathToValidYamlExpression(fixPath, rulePaths.FixPath.Value, documentIndex)

			fixedYamlString, err = fixhandler.ApplyFixToContent(ctx, fileAsString, yamlExpression)
			if err != nil {
				logger.L().Debug("failed to fix "+filepath+" with "+yamlExpression, helpers.Error(err))
				continue
			}

			dmp := diffmatchpatch.New()
			diffs := dmp.DiffMain(fileAsString, fixedYamlString, false)
			collectDiffs(dmp, diffs, result, filepath, fileAsString)
		}
	}
}

func collectFixesFromMappingNodes(result *sarif.Result, ac resourcesresults.ResourceAssociatedControl, opaSessionObj *cautils.OPASessionObj, resourceID string, filepath string, rsrcAbsPath string, location locationresolver.Location, subFileNodes map[string]cautils.MappingNode, split int) {
	for _, rule := range ac.ResourceAssociatedRules {
		if !rule.GetStatus(nil).IsFailed() {
			continue
		}

		for _, rulePaths := range rule.Paths {
			fixPath := rulePaths.FixPath.Path
			if fixPath == "" {
				continue
			}

			fileAsString, err := fixhandler.GetFileString(rsrcAbsPath)
			if err != nil {
				logger.L().Debug("failed to access "+filepath, helpers.Error(err))
				continue
			}

			var fixedYamlString string
			fixValue := rulePaths.FixPath.Value
			if split == -1 { //replaceNode
				node := subFileNodes[fixPath]
				fixedYamlString = formReplaceFixedYamlString(node, fileAsString, location, fixValue, fixPath)
			} else { //insertNode
				maxLineNumber := getTheLocationOfAddPart(split, fixPath, subFileNodes)
				fixedYamlString = applyFixToContent(split, fixPath, fileAsString, maxLineNumber, fixValue)
			}

			dmp := diffmatchpatch.New()
			diffs := dmp.DiffMain(fileAsString, fixedYamlString, false)
			collectDiffs(dmp, diffs, result, filepath, fileAsString)
		}
	}
}

func applyFixToContent(split int, fixPath string, fileAsString string, addLine int, value string) string {
	addLines := make([]string, 0)
	fields := strings.Split(fixPath, ".")
	for i := split; i < len(fields); i++ {
		field := fields[i]
		var addedLine string
		if i != len(fields)-1 {
			addedLine = strings.Repeat(" ", (i*2)) + field + ":"
		} else {
			addedLine = strings.Repeat(" ", (i*2)) + field + ": " + value
		}
		addLines = append(addLines, addedLine)
	}
	fixedYamlString := formAddFixedYamlString(fileAsString, addLine, addLines)

	return fixedYamlString
}

func formReplaceFixedYamlString(node cautils.MappingNode, fileAsString string, location locationresolver.Location, fixValue string, fixPath string) string {
	replcaedValue := node.Value
	yamlLines := strings.Split(fileAsString, "\n")
	if replcaedValue == "" {
		yamlLines[location.Line] = yamlLines[location.Line] + " # This is the suggested modification, the value for " + fixPath + " is " + fixValue + "\n"
	} else {
		replacedLine := "# This is the suggested modification\n" + yamlLines[location.Line]
		newLine := strings.Replace(replacedLine, replcaedValue, fixValue, -1)
		yamlLines[location.Line] = newLine
	}
	fixedYamlString := strings.Join(yamlLines, "\n")
	return fixedYamlString
}

func formAddFixedYamlString(fileAsString string, addLine int, addLines []string) string {
	yamlLines := strings.Split(fileAsString, "\n")
	newYamlLines := append(yamlLines[:addLine], "# This is the suggested modification")
	newYamlLines = append(newYamlLines, addLines...)
	yamlLines = strings.Split(fileAsString, "\n")
	newYamlLines = append(newYamlLines, yamlLines[addLine:]...)
	fixedYamlString := strings.Join(newYamlLines, "\n")
	return fixedYamlString
}

func getTheLocationOfAddPart(split int, fixPath string, mappingnodes map[string]cautils.MappingNode) int {
	fields := strings.Split(fixPath, ".")
	field := fields[:split]
	closestPath := strings.Join(field, ".")
	maxLineNumber := -1
	for k, v := range mappingnodes {
		if strings.Index(k, closestPath) == 0 {
			if v.TemplateLineNumber > maxLineNumber {
				maxLineNumber = v.TemplateLineNumber
			}
		}
	}
	return maxLineNumber
}

func getDocIndex(opaSessionObj *cautils.OPASessionObj, resourceID string) (int, bool) {
	resource := opaSessionObj.AllResources[resourceID]
	localworkload, ok := resource.(*localworkload.LocalWorkload)
	if !ok {
		return 0, false
	}

	splittedPath := strings.Split(localworkload.GetPath(), ":")
	if len(splittedPath) <= 1 {
		return 0, false
	}

	docIndex, err := strconv.Atoi(splittedPath[1])
	if err != nil {
		return 0, false
	}
	return docIndex, true
}

func getBasePathFromMetadata(opaSessionObj cautils.OPASessionObj) string {
	switch opaSessionObj.Metadata.ScanMetadata.ScanningTarget {
	case v2.GitLocal:
		return opaSessionObj.Metadata.ContextMetadata.RepoContextMetadata.LocalRootPath
	case v2.Directory:
		return opaSessionObj.Metadata.ContextMetadata.DirectoryContextMetadata.BasePath
	default:
		return ""
	}
}

// generateRemediationMessage generates a remediation message for the given control summary
func (sp *SARIFPrinter) generateRemediationMessage(control reportsummary.IControlSummary) string {
	return fmt.Sprintf("Remediation: %s", control.GetRemediation())
}
func hashArtifactChange(artifactChange *sarif.ArtifactChange) [32]byte {
	acJson, _ := json.Marshal(artifactChange)
	return sha256.Sum256(acJson)
}
