package printer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/models"
	grypesarif "github.com/anchore/grype/grype/presenter/sarif"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/fixhandler"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/sergi/go-diff/diffmatchpatch"
)

const (
	sarifOutputFile = "report"

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
		if filepath.Ext(strings.TrimSpace(outputFile)) != printer.SARIFOutputExt {
			outputFile = outputFile + printer.SARIFOutputExt
		}
	}
	sp.writer = printer.GetWriter(ctx, outputFile)
}

// addRule adds a rule description to the scan run based on the given control summary
func (sp *SARIFPrinter) addRule(scanRun *sarif.Run, control reportsummary.IControlSummary) {
	scoreFactor := control.GetScoreFactor()
	controlSARIFSeverity := string(scoreFactorToSARIFSeverityLevel(scoreFactor))

	configuration := sarif.NewReportingConfiguration().WithLevel(controlSARIFSeverity)

	scanRun.AddRule(control.GetID()).
		WithDefaultConfiguration(configuration).
		WithShortDescription(sarif.NewMultiformatMessageString(control.GetName())).
		WithFullDescription(sarif.NewMultiformatMessageString(control.GetDescription())).
		WithHelp(sarif.NewMultiformatMessageString(sp.generateRemediationMessage(control))).
		// security-severity lets GitHub Code Scanning render and filter findings by
		// severity. It mirrors the CVSS-style score band already used to pick the
		// SARIF level above, formatted as grype does it. See #2394.
		WithProperties(sarif.Properties{
			"security-severity": fmt.Sprintf("%.1f", scoreFactor),
		})
}

// addResult adds a result of checking a rule to the scan run based on the given control summary
func (sp *SARIFPrinter) addResult(scanRun *sarif.Run, ctl reportsummary.IControlSummary, filepath string, location locationresolver.Location, ac *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) *sarif.Result {
	msg := ctl.GetDescription()
	if resource != nil {
		if paths := AssistedRemediationPathsWithCurrentValues(ac, resource); len(paths) > 0 {
			msg += "\n\nAffected fields:\n" + strings.Join(paths, "\n")
		}
	}
	return scanRun.CreateResultForRule(ctl.GetID()).
		WithMessage(sarif.NewTextMessage(msg)).
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

func (sp *SARIFPrinter) printImageScan(scanResults cautils.ImageScanData) error {
	model, err := models.NewDocument(clio.Identification{}, scanResults.Packages, scanResults.Context,
		scanResults.Matches, scanResults.IgnoredMatches, scanResults.VulnerabilityProvider, nil, nil, models.DefaultSortStrategy, false)
	if err != nil {
		return fmt.Errorf("failed to create document: %w", err)
	}

	// Render into an in-memory buffer rather than sp.writer directly: when no
	// --output file is given, sp.writer is os.Stdout, and reopening it by
	// name below to patch the driver name would deadlock if stdout is a pipe
	// (this process still holds the write end open, so a second reader on
	// the same pipe never sees EOF). Rendering and patching in memory, then
	// writing to sp.writer exactly once, avoids that entirely.
	var rendered bytes.Buffer
	pres := grypesarif.NewPresenter(models.PresenterConfig{Document: model, SBOM: scanResults.SBOM})
	if err := pres.Present(&rendered); err != nil {
		return err
	}

	var sarifReport sarif.Report
	if err := json.Unmarshal(rendered.Bytes(), &sarifReport); err != nil {
		return err
	}

	// Patch driver name to Kubescape
	for i := range sarifReport.Runs {
		sarifReport.Runs[i].Tool.Driver.Name = "Kubescape"
	}

	updatedSarifReport, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return err
	}

	if _, err := sp.writer.Write(updatedSarifReport); err != nil {
		return fmt.Errorf("failed to write SARIF report: %w", err)
	}

	return nil
}

func (sp *SARIFPrinter) PrintNextSteps() {

}

func (sp *SARIFPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj == nil {
		if len(imageScanData) == 0 {
			return fmt.Errorf("failed to write results in sarif format: no data provided")
		}

		// image scan
		if err := sp.printImageScan(imageScanData[0]); err != nil {
			logger.L().Ctx(ctx).Error("failed to write results in sarif format", helpers.Error(err))
			return fmt.Errorf("failed to write results in sarif format: %w", err)
		}
	} else {
		// configuration scan
		if err := sp.printConfigurationScan(ctx, opaSessionObj); err != nil {
			logger.L().Ctx(ctx).Error("failed to write results in sarif format", helpers.Error(err))
			return fmt.Errorf("failed to write results in sarif format: %w", err)
		}

	}
	printer.LogOutputFile(sp.writer.Name())
	return nil
}

func (sp *SARIFPrinter) printConfigurationScan(ctx context.Context, opaSessionObj *cautils.OPASessionObj) error {
	startedAt := opaSessionObj.Report.ReportGenerationTime
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}

	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)
	basePath := getBasePathFromMetadata(*opaSessionObj)
	failed := make([]scannedResource, 0, len(opaSessionObj.ResourcesResult))
	for resourceID, result := range opaSessionObj.ResourcesResult {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}

		resourceSource := opaSessionObj.ResourceSource[resourceID]
		relPath := resourceSource.RelativePath

		// Github Code Scanning considers results not associated to a file path
		// meaningless and invalid when uploading, and the location written to the
		// report is the relative path alone, so a base path cannot stand in for a
		// missing one
		if relPath == "" {
			continue
		}

		failed = append(failed, scannedResource{
			resourceID: resourceID,
			relPath:    relPath,
			absPath:    filepath.Join(effectiveBasePath(resourceSource, basePath), relPath),
		})
	}

	var caches manifestCache
	for _, resource := range groupByManifest(failed) {
		cache := caches.get(resource.absPath)
		locationResolver := cache.locationResolver(resource.absPath, "SARIF")

		for _, toPin := range opaSessionObj.ResourcesResult[resource.resourceID].AssociatedControls {
			ac := toPin

			if ac.GetStatus(nil).IsFailed() {
				ctl := opaSessionObj.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ac.GetID())
				if ctl == nil {
					logger.L().Debug("control not found in summary details, skipping", helpers.String("controlID", ac.GetID()))
					continue
				}
				location := resolveFixLocation(opaSessionObj, locationResolver, &ac, resource.resourceID)
				sp.addRule(run, ctl)
				rsrc := opaSessionObj.AllResources[resource.resourceID]
				r := sp.addResult(run, ctl, resource.relPath, location, &ac, rsrc)
				collectFixes(ctx, cache, r, ac, opaSessionObj, resource.resourceID, resource.relPath, resource.absPath)
			}
		}
	}

	finishedAt := time.Now().UTC()
	executionSuccessful := true
	run.Invocations = append(run.Invocations, &sarif.Invocation{
		StartTimeUTC:        &startedAt,
		EndTimeUTC:          &finishedAt,
		ExecutionSuccessful: &executionSuccessful,
	})

	report.AddRun(run)

	// Surface write failures instead of silently leaving an empty/partial file.
	if err := report.PrettyWrite(sp.writer); err != nil {
		return fmt.Errorf("failed to write SARIF report: %w", err)
	}

	return nil
}

// resolveFixLocation resolves a failed control's location in the manifest, falling back to line 1. Shared by the SARIF and GitLab SAST printers
func resolveFixLocation(opaSessionObj *cautils.OPASessionObj, locationResolver *locationresolver.FixPathLocationResolver, ac *resourcesresults.ResourceAssociatedControl, resourceID string) locationresolver.Location {
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

	// check if the fix is already added. The incoming change is hashed once, not
	// per comparison: the hash marshals and SHA-256s the same value every time.
	changeHash := hashArtifactChange(artifactChange)
	for _, fix := range result.Fixes {
		for _, ac := range fix.ArtifactChanges {
			if hashArtifactChange(ac) == changeHash {
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
	// endLine is 1-indexed, so 0 is as out of range as len(file)+1
	if endLine < 1 || endLine > len(file) {
		return 0, 0, false
	}
	for num+endColumn-1 > utf8.RuneCountInString(file[endLine-1]) {
		num -= utf8.RuneCountInString(file[endLine-1]) - endColumn + 2
		endLine++
		endColumn = 1
		// the delta can claim more characters than the file holds, so the
		// bound needs re-checking on every step of the walk
		if endLine > len(file) {
			return 0, 0, false
		}
	}
	endColumn += num
	return endLine, endColumn, true
}

func collectDiffs(dmp *diffmatchpatch.DiffMatchPatch, diffs []diffmatchpatch.Diff, result *sarif.Result, filepath string, fileAsString string) {
	addFixRegions(result, filepath, diffRegions(dmp, diffs, fileAsString))
}

// diffRegions walks the diff delta and returns the replacement regions it
// describes. Kept separate from attaching them to a result so the walk depends on
// nothing but the manifest and the diff, which is what lets it be cached per
// (manifest, fix expression) and reused across controls (see fixReportCache).
func diffRegions(dmp *diffmatchpatch.DiffMatchPatch, diffs []diffmatchpatch.Diff, fileAsString string) []fixRegion {
	file := strings.Split(fileAsString, "\n")
	regions := []fixRegion{}
	text := ""
	startLine := 1
	startColumn := 1
	endLine := 1
	endColumn := 1

	delta := strings.Split(dmp.DiffToDelta(diffs), "\t")
	for index, seg := range delta {
		// DiffToDelta returns "" for an empty diff set, which Split turns into
		// a single empty segment carrying no operation byte
		if seg == "" {
			continue
		}
		switch seg[0] {
		case '+':
			var err error
			text, err = url.QueryUnescape(seg[1:])
			if err != nil {
				logger.L().Debug("failed to unescape string", helpers.Error(err))
				continue
			}
			if closesFixRegion(delta, index) {
				regions = append(regions, fixRegion{startLine, startColumn, endLine, endColumn, text})
			}
		case '-':
			// commit the position only on success: the (0, 0) failure return
			// is not a valid SARIF location and breaks the next move
			newLine, newColumn, ok := calculateMove(seg[1:], file, endColumn, endLine)
			if !ok {
				continue
			}
			endLine, endColumn = newLine, newColumn
			if closesFixRegion(delta, index) {
				regions = append(regions, fixRegion{startLine, startColumn, endLine, endColumn, text})
			}
		case '=':
			newLine, newColumn, ok := calculateMove(seg[1:], file, endColumn, endLine)
			if !ok {
				continue
			}
			endLine, endColumn = newLine, newColumn
			startLine = endLine
			startColumn = endColumn
			text = ""
		}
	}

	return regions
}

// addFixRegions attaches regions to a result in delta-walk order, so the
// duplicate check in addFix sees them as it did when the walk added them itself.
func addFixRegions(result *sarif.Result, filepath string, regions []fixRegion) {
	for _, region := range regions {
		addFix(result, filepath, region.startLine, region.startColumn, region.endLine, region.endColumn, region.text)
	}
}

// closesFixRegion reports whether the segment at index ends the replacement region:
// the next operation segment resumes unchanged content, or there is none left
func closesFixRegion(delta []string, index int) bool {
	for i := index + 1; i < len(delta); i++ {
		// empty segments carry no operation and are skipped by the walk too,
		// so they cannot hold the region open
		if delta[i] == "" {
			continue
		}
		return delta[i][0] == '='
	}
	return true
}

func collectFixes(ctx context.Context, cache *fixReportCache, result *sarif.Result, ac resourcesresults.ResourceAssociatedControl, opaSessionObj *cautils.OPASessionObj, resourceID string, filepath string, rsrcAbsPath string) {
	// the index is the resource's, not a fix path's, so without one there is
	// nothing to report
	documentIndex, ok := getDocIndex(opaSessionObj, resourceID)
	if !ok {
		return
	}

	for _, rule := range ac.ResourceAssociatedRules {
		if !rule.GetStatus(nil).IsFailed() {
			continue
		}

		for _, rulePaths := range rule.Paths {
			fixPath := rulePaths.FixPath.Path
			if fixPath == "" {
				continue
			}

			yamlExpression := fixhandler.FixPathToValidYamlExpression(fixPath, rulePaths.FixPath.Value, documentIndex)
			addFixRegions(result, filepath, cache.fixRegions(ctx, rsrcAbsPath, yamlExpression))
		}
	}
}

func getDocIndex(opaSessionObj *cautils.OPASessionObj, resourceID string) (int, bool) {
	resource := opaSessionObj.AllResources[resourceID]
	localworkload, ok := resource.(*localworkload.LocalWorkload)
	if !ok {
		return 0, false
	}

	// GetPath() is "<file path>:<document index>". Split on the *last* colon,
	// not the first/second: strings.Split(path, ":")[1] silently picks the
	// wrong segment for any path containing more than one colon (e.g. a
	// Windows path like "C:\repo\deploy.yaml:0"), producing a non-numeric
	// value that Atoi rejects and this function reporting "no doc index"
	// even though one exists. This matches how fixhandler.getFilePathAndIndex
	// parses the same convention.
	path := localworkload.GetPath()
	lastColon := strings.LastIndex(path, ":")
	if lastColon == -1 {
		return 0, false
	}

	docIndex, err := strconv.Atoi(path[lastColon+1:])
	if err != nil {
		return 0, false
	}
	return docIndex, true
}

func getBasePathFromMetadata(opaSessionObj cautils.OPASessionObj) string {
	if opaSessionObj.Metadata == nil {
		return ""
	}
	switch opaSessionObj.Metadata.ScanMetadata.ScanningTarget {
	case v2.GitLocal:
		if repo := opaSessionObj.Metadata.ContextMetadata.RepoContextMetadata; repo != nil {
			return repo.LocalRootPath
		}
		return ""
	case v2.Directory:
		return opaSessionObj.Metadata.ContextMetadata.DirectoryContextMetadata.BasePath
	case v2.File:
		if opaSessionObj.Metadata.ContextMetadata.FileContextMetadata != nil {
			return cautils.FileScanRootPath(opaSessionObj.Metadata.ContextMetadata.FileContextMetadata.FilePath)
		}
		return ""
	default:
		return ""
	}
}

// effectiveBasePath returns the root a resource's RelativePath resolves against. The
// resource's own Source.Path is authoritative because it is the root the relative path
// was computed from, which the scan-wide base path is not: it covers only the first
// input pattern of a multi-input scan. Sources that intentionally carry no path
// (cloned repos) fall back to it.
func effectiveBasePath(resourceSource reporthandling.Source, basePath string) string {
	if resourceSource.Path != "" {
		return resourceSource.Path
	}
	return basePath
}

// generateRemediationMessage generates a remediation message for the given control summary
func (sp *SARIFPrinter) generateRemediationMessage(control reportsummary.IControlSummary) string {
	return fmt.Sprintf("Remediation: %s", control.GetRemediation())
}
func hashArtifactChange(artifactChange *sarif.ArtifactChange) [32]byte {
	acJson, _ := json.Marshal(artifactChange)
	return sha256.Sum256(acJson)
}

func (p *SARIFPrinter) CloseWriter() {
	if p.writer != nil && p.writer != os.Stdout {
		p.writer.Close()
	}
}
