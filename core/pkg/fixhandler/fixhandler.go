package fixhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"gopkg.in/op/go-logging.v1"
)

const UserValuePrefix = "YOUR_"

const windowsNewline = "\r\n"
const unixNewline = "\n"
const oldMacNewline = "\r"

func NewFixHandler(fixInfo *metav1.FixInfo) (*FixHandler, error) {
	if info, err := os.Stat(fixInfo.ReportFile); err == nil && info.IsDir() {
		return nil, fmt.Errorf("%q is a directory, not a file. Please provide a JSON report file path", fixInfo.ReportFile)
	}
	jsonFile, err := os.Open(fixInfo.ReportFile)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	byteValue, _ := io.ReadAll(jsonFile)

	var reportObj reporthandlingv2.PostureReport
	if err = json.Unmarshal(byteValue, &reportObj); err != nil {
		// Heuristic: if the file looks like YAML rather than JSON, give the
		// user a clearer message than the raw json decoder error.
		trimmed := strings.TrimPrefix(string(byteValue), "\ufeff")
		trimmed = strings.TrimLeft(trimmed, " \t\r\n")
		if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
			return nil, fmt.Errorf("%q does not look like a kubescape JSON scan report. Run `kubescape scan --format json --output <file>` first and pass that file to `kubescape fix`", fixInfo.ReportFile)
		}
		return nil, fmt.Errorf("failed to parse %q as a kubescape JSON scan report: %w", fixInfo.ReportFile, err)
	}

	if err = isSupportedScanningTarget(&reportObj); err != nil {
		return nil, err
	}

	localPath := getLocalPath(&reportObj)
	if _, err = os.Stat(localPath); err != nil {
		return nil, err
	}

	backendLoggerLeveled := logging.AddModuleLevel(logging.NewLogBackend(logger.L().GetWriter(), "", 0))
	backendLoggerLeveled.SetLevel(logging.ERROR, "")
	yqlib.GetLogger().SetBackend(backendLoggerLeveled)

	return &FixHandler{
		fixInfo:       fixInfo,
		reportObj:     &reportObj,
		localBasePath: localPath,
	}, nil
}

func isSupportedScanningTarget(report *reporthandlingv2.PostureReport) error {
	scanningTarget := report.Metadata.ScanMetadata.ScanningTarget
	if scanningTarget == reporthandlingv2.GitLocal || scanningTarget == reporthandlingv2.Directory || scanningTarget == reporthandlingv2.File {
		return nil
	}

	return fmt.Errorf("unsupported scanning target. Supported scanning targets are: a local git repo, a directory or a file")
}

func getLocalPath(report *reporthandlingv2.PostureReport) string {

	switch report.Metadata.ScanMetadata.ScanningTarget {
	case reporthandlingv2.GitLocal:
		return report.Metadata.ContextMetadata.RepoContextMetadata.LocalRootPath
	case reporthandlingv2.Directory:
		return report.Metadata.ContextMetadata.DirectoryContextMetadata.BasePath
	case reporthandlingv2.File:
		return filepath.Dir(report.Metadata.ContextMetadata.FileContextMetadata.FilePath)
	default:
		return ""
	}
}

func (h *FixHandler) buildResourcesMap() map[string]*reporthandling.Resource {
	resourceIdToRawResource := make(map[string]*reporthandling.Resource)
	for i := range h.reportObj.Resources {
		resourceIdToRawResource[h.reportObj.Resources[i].GetID()] = &h.reportObj.Resources[i]
	}
	for i := range h.reportObj.Results {
		if h.reportObj.Results[i].RawResource == nil {
			continue
		}
		resourceIdToRawResource[h.reportObj.Results[i].RawResource.GetID()] = h.reportObj.Results[i].RawResource
	}

	return resourceIdToRawResource
}

func (h *FixHandler) getPathFromRawResource(obj map[string]interface{}) string {
	if localworkload.IsTypeLocalWorkload(obj) {
		localwork := localworkload.NewLocalWorkload(obj)
		return localwork.GetPath()
	} else if objectsenvelopes.IsTypeRegoResponseVector(obj) {
		regoResponseVectorObject := objectsenvelopes.NewRegoResponseVectorObject(obj)
		relatedObjects := regoResponseVectorObject.GetRelatedObjects()
		for _, relatedObject := range relatedObjects {
			if localworkload.IsTypeLocalWorkload(relatedObject.GetObject()) {
				return relatedObject.(*localworkload.LocalWorkload).GetPath()
			}
		}
	}

	return ""
}

func (h *FixHandler) PrepareResourcesToFix(ctx context.Context) []ResourceFixInfo {
	resourceIdToResource := h.buildResourcesMap()

	resourcesToFix := make([]ResourceFixInfo, 0)
	h.unfixedControls = h.unfixedControls[:0]
	h.fixedControlsCount = 0

	for _, result := range h.reportObj.Results {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}

		resourceID := result.ResourceID
		resourceObj := resourceIdToResource[resourceID]
		resourcePath := h.getPathFromRawResource(resourceObj.GetObject())

		// Determine an upfront reason if we already know this resource is not
		// fixable, so we can still surface its failed controls as "unfixed".
		skipReason := ""
		if resourcePath == "" {
			skipReason = "skipped: resource has no local file path"
		} else if resourceObj.Source == nil || resourceObj.Source.FileType != reporthandling.SourceTypeYaml {
			skipReason = "skipped: source is not a YAML file"
		}

		var absolutePath string
		var documentIndex int
		if skipReason == "" {
			relativePath, idx, err := h.getFilePathAndIndex(resourcePath)
			if err != nil {
				logger.L().Ctx(ctx).Warning("Skipping invalid resource path: " + resourcePath)
				skipReason = "skipped: invalid resource path"
			} else {
				absolutePath = path.Join(h.localBasePath, relativePath)
				documentIndex = idx
				if _, err := os.Stat(absolutePath); err != nil {
					logger.L().Ctx(ctx).Warning("Skipping missing file: " + absolutePath)
					skipReason = "skipped: file not found"
				}
			}
		}

		if skipReason != "" {
			for i := range result.AssociatedControls {
				ac := &result.AssociatedControls[i]
				if !ac.GetStatus(nil).IsFailed() {
					continue
				}
				h.unfixedControls = append(h.unfixedControls, UnfixedControl{
					ControlID:    ac.GetID(),
					ControlName:  ac.GetName(),
					ResourceName: resourceObj.GetName(),
					ResourceKind: resourceObj.GetKind(),
					FilePath:     resourcePath,
					Reason:       skipReason,
				})
			}
			continue
		}

		rfi := ResourceFixInfo{
			FilePath:        absolutePath,
			Resource:        resourceObj,
			YamlExpressions: make(map[string]armotypes.FixPath, 0),
			DocumentIndex:   documentIndex,
		}

		for i := range result.AssociatedControls {
			ac := &result.AssociatedControls[i]
			if !ac.GetStatus(nil).IsFailed() {
				continue
			}

			added, skipped := rfi.addYamlExpressionsFromResourceAssociatedControl(documentIndex, ac, h.fixInfo.SkipUserValues)

			// Fully auto-remediated: every failed path produced an expression.
			if added > 0 && len(skipped) == 0 {
				h.fixedControlsCount++
				continue
			}

			// Partial or fully unfixed — surface as needing manual work. The
			// concrete fixes (if any) are still applied via rfi.YamlExpressions,
			// but the control is not counted as fully fixed because rules under
			// it remain unaddressed.
			reason := "no auto-fix available for this control"
			if len(skipped) > 0 {
				reason = skipped[0]
			}
			if added > 0 {
				reason = "partial: " + reason
			}
			h.unfixedControls = append(h.unfixedControls, UnfixedControl{
				ControlID:    ac.GetID(),
				ControlName:  ac.GetName(),
				ResourceName: resourceObj.GetName(),
				ResourceKind: resourceObj.GetKind(),
				FilePath:     absolutePath,
				Reason:       reason,
			})
		}

		if len(rfi.YamlExpressions) > 0 {
			resourcesToFix = append(resourcesToFix, rfi)
		}
	}

	return resourcesToFix
}

// UnfixedControls returns the failed (resource, control) tuples discovered during
// the most recent call to PrepareResourcesToFix that the fixer did not auto-remediate.
func (h *FixHandler) UnfixedControls() []UnfixedControl {
	out := make([]UnfixedControl, len(h.unfixedControls))
	copy(out, h.unfixedControls)
	return out
}

// FixedControlsCount returns the number of failed (resource, control) tuples that
// the fixer produced at least one yaml edit for during the most recent call to
// PrepareResourcesToFix.
func (h *FixHandler) FixedControlsCount() int {
	return h.fixedControlsCount
}

// Phase tells PrintUnfixedControls whether the fixer has already written the
// planned changes to disk or is still in a planning state (dry-run, declined
// confirm, partial apply). The summary line phrases the verb accordingly.
type Phase int

const (
	// PhasePlanned: fixes have been planned but not (fully) written. Use for
	// --dry-run, declined confirm, and partial-apply paths.
	PhasePlanned Phase = iota
	// PhaseApplied: every planned fix was successfully written to disk.
	PhaseApplied
)

// dedupUnfixedControls returns a deduplicated copy of the unfixed controls
// slice, using ControlID|Kind/Name|FilePath as the dedup key.
func dedupUnfixedControls(controls []UnfixedControl) []UnfixedControl {
	seen := make(map[string]bool, len(controls))
	out := make([]UnfixedControl, 0, len(controls))
	for _, u := range controls {
		key := u.ControlID + "|" + u.ResourceKind + "/" + u.ResourceName + "|" + u.FilePath
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, u)
	}
	return out
}

// PrintUnfixedControls logs the failed (resource, control) tuples that require
// manual remediation, deduplicating entries across multiple identical failures.
// The verb on the summary line reflects phase: "Auto-fixed" only when every
// planned fix was actually written; otherwise "Would auto-fix".
func (h *FixHandler) PrintUnfixedControls(phase Phase) {
	if len(h.unfixedControls) == 0 {
		return
	}

	deduped := dedupUnfixedControls(h.unfixedControls)
	var sb strings.Builder
	totalFailed := h.fixedControlsCount + len(deduped)
	verb := "Would auto-fix"
	if phase == PhaseApplied {
		verb = "Auto-fixed"
	}
	sb.WriteString(fmt.Sprintf("%s %d of %d flagged control instances. The following require manual remediation:\n",
		verb, h.fixedControlsCount, totalFailed))

	for _, u := range deduped {
		location := u.FilePath
		if location == "" {
			location = "<unknown>"
		}
		sb.WriteString(fmt.Sprintf("  - %s %s on %s/%s (%s) — %s\n",
			u.ControlID, u.ControlName, u.ResourceKind, u.ResourceName, location, u.Reason))
	}

	logger.L().Warning(sb.String())
}

func (h *FixHandler) PrintExpectedChanges(resourcesToFix []ResourceFixInfo) {
	var sb strings.Builder
	sb.WriteString("The following changes will be applied:\n")

	for _, resourceFixInfo := range resourcesToFix {
		sb.WriteString(fmt.Sprintf("File: %s\n", resourceFixInfo.FilePath))
		sb.WriteString(fmt.Sprintf("Resource: %s\n", resourceFixInfo.Resource.GetName()))
		sb.WriteString(fmt.Sprintf("Kind: %s\n", resourceFixInfo.Resource.GetKind()))
		sb.WriteString("Changes:\n")

		i := 1
		for _, fixPath := range resourceFixInfo.YamlExpressions {
			sb.WriteString(fmt.Sprintf("\t%d) %s = %s\n", i, fixPath.Path, fixPath.Value))
			i++
		}
		sb.WriteString("\n------\n")
	}

	logger.L().Info(sb.String())
}

func (h *FixHandler) ApplyChanges(ctx context.Context, resourcesToFix []ResourceFixInfo) (int, []error) {
	updatedFiles := make(map[string]bool)
	errors := make([]error, 0)

	fileYamlExpressions := h.getFileYamlExpressions(resourcesToFix)

	for filepath, yamlExpression := range fileYamlExpressions {
		fileAsString, err := GetFileString(filepath)

		if err != nil {
			errors = append(errors, err)
			continue
		}

		fixedYamlString, err := ApplyFixToContent(ctx, fileAsString, yamlExpression)

		if err != nil {
			errors = append(errors, fmt.Errorf("failed to fix file %s: %w ", filepath, err))
			continue
		}

		if err := writeFixesToFile(filepath, fixedYamlString); err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("Failed to write fixes to file %s, %v", filepath, err.Error()))
			errors = append(errors, err)
			continue
		}

		updatedFiles[filepath] = true
	}

	return len(updatedFiles), errors
}

func (h *FixHandler) getFilePathAndIndex(filePathWithIndex string) (filePath string, documentIndex int, err error) {
	splittedPath := strings.Split(filePathWithIndex, ":")
	if len(splittedPath) <= 1 {
		return "", 0, fmt.Errorf("expected to find ':' in file path")
	}

	filePath = splittedPath[0]
	if documentIndex, err := strconv.Atoi(splittedPath[1]); err != nil {
		return "", 0, err
	} else {
		return filePath, documentIndex, nil
	}
}

func ApplyFixToContent(ctx context.Context, yamlAsString, yamlExpression string) (fixedString string, err error) {
	yamlAsString = sanitizeYaml(yamlAsString)
	newline := determineNewlineSeparator(yamlAsString)

	yamlLines := strings.Split(yamlAsString, newline)

	originalRootNodes, err := decodeDocumentRoots(yamlAsString)

	if err != nil {
		return "", err
	}

	fixedRootNodes, err := getFixedNodes(ctx, yamlAsString, yamlExpression)

	if err != nil {
		return "", err
	}

	fixInfo := getFixInfo(ctx, originalRootNodes, fixedRootNodes)

	fixedYamlLines := getFixedYamlLines(yamlLines, fixInfo, newline)

	fixedString = getStringFromSlice(fixedYamlLines, newline)
	fixedString = revertSanitizeYaml(fixedString)

	return fixedString, nil
}

func (h *FixHandler) getFileYamlExpressions(resourcesToFix []ResourceFixInfo) map[string]string {
	fileYamlExpressions := make(map[string]string, 0)
	for _, toPin := range resourcesToFix {
		resourceToFix := toPin

		singleExpression := reduceYamlExpressions(&resourceToFix)
		resourceFilePath := resourceToFix.FilePath

		if _, pathExistsInMap := fileYamlExpressions[resourceFilePath]; !pathExistsInMap {
			fileYamlExpressions[resourceFilePath] = singleExpression
		} else {
			fileYamlExpressions[resourceFilePath] = joinStrings(fileYamlExpressions[resourceFilePath], " | ", singleExpression)
		}

	}

	return fileYamlExpressions
}

// addYamlExpressionsFromResourceAssociatedControl appends one yaml expression
// for every failed-rule FixPath that produces a concrete remediation. It returns
// per-path counters so callers can distinguish fully-fixable controls from
// partially-fixable controls (some paths fixable, some skipped/unfixable) from
// fully-unfixable ones. skippedReasons describes paths that could not be
// auto-remediated, in classification order.
func (rfi *ResourceFixInfo) addYamlExpressionsFromResourceAssociatedControl(documentIndex int, ac *resourcesresults.ResourceAssociatedControl, skipUserValues bool) (added int, skippedReasons []string) {
	for _, rule := range ac.ResourceAssociatedRules {
		if !rule.GetStatus(nil).IsFailed() {
			continue
		}

		ruleHadFixPath := false
		for _, rulePaths := range rule.Paths {
			if rulePaths.FixPath.Path == "" {
				continue
			}
			ruleHadFixPath = true

			if strings.HasPrefix(rulePaths.FixPath.Value, UserValuePrefix) && skipUserValues {
				skippedReasons = append(skippedReasons, "skipped: auto-fix requires a user-supplied value (--skip-user-values is set)")
				continue
			}

			yamlExpression := FixPathToValidYamlExpression(rulePaths.FixPath.Path, rulePaths.FixPath.Value, documentIndex)
			rfi.YamlExpressions[yamlExpression] = rulePaths.FixPath
			added++
		}

		// A failed rule with no FixPath at all is a check we don't know how to
		// remediate automatically — still surface it as needing manual work.
		if !ruleHadFixPath {
			skippedReasons = append(skippedReasons, "no auto-fix available for this control")
		}
	}
	return added, skippedReasons
}

// reduceYamlExpressions reduces the number of yaml expressions to a single one
func reduceYamlExpressions(resource *ResourceFixInfo) string {
	expressions := make([]string, 0, len(resource.YamlExpressions))
	for expr := range resource.YamlExpressions {
		expressions = append(expressions, expr)
	}
	sort.Strings(expressions)
	return strings.Join(expressions, " | ")
}

func FixPathToValidYamlExpression(fixPath, value string, documentIndexInYaml int) string {
	isStringValue := true
	if _, err := strconv.ParseBool(value); err == nil {
		isStringValue = false
	} else if _, err := strconv.ParseFloat(value, 64); err == nil {
		isStringValue = false
	} else if _, err := strconv.Atoi(value); err == nil {
		isStringValue = false
	}

	// Strings should be quoted
	if isStringValue {
		value = fmt.Sprintf("\"%s\"", value)
	}

	// select document index and add a dot for the root node
	return fmt.Sprintf("select(di==%d).%s |= %s", documentIndexInYaml, fixPath, value)
}

func joinStrings(inputStrings ...string) string {
	return strings.Join(inputStrings, "")
}

func GetFileString(filepath string) (string, error) {
	bytes, err := os.ReadFile(filepath)

	if err != nil {
		return "", fmt.Errorf("error reading file %s", filepath)
	}

	return string(bytes), nil
}

func writeFixesToFile(filepath, content string) error {
	err := os.WriteFile(filepath, []byte(content), 0644) //nolint:gosec

	if err != nil {
		return fmt.Errorf("error writing fixes to file: %w", err)
	}

	return nil
}

func determineNewlineSeparator(contents string) string {
	switch {
	case strings.Contains(contents, windowsNewline):
		return windowsNewline
	default:
		return unixNewline
	}
}

// sanitizeYaml receives a YAML file as a string, sanitizes it and returns the result
//
// Callers should remember to call the corresponding revertSanitizeYaml function.
//
// It applies the following sanitization:
//
// - Since `yaml/v3` fails to serialize documents starting with a document
// separator, we comment it out to be compatible.
func sanitizeYaml(fileAsString string) string {
	if len(fileAsString) < 3 {
		return fileAsString
	}

	if fileAsString[:3] == "---" {
		fileAsString = "# " + fileAsString
	}
	return fileAsString
}

// revertSanitizeYaml receives a sanitized YAML file as a string and reverts the applied sanitization
//
// For sanitization details, refer to the sanitizeYaml() function.
func revertSanitizeYaml(fixedYamlString string) string {
	if len(fixedYamlString) < 3 {
		return fixedYamlString
	}

	if fixedYamlString[:5] == "# ---" {
		fixedYamlString = fixedYamlString[2:]
	}
	return fixedYamlString
}
