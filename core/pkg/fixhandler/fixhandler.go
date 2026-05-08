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

	return fmt.Errorf("unsupported scanning target %d: the report must be generated from a local git repo, directory, or file scan. Run: kubescape scan <path> --format json --output report.json", scanningTarget)
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

// PrepareResourcesToFix returns the YAML-source resources that the existing
// yq-based pipeline can patch. Helm-rendered resources are split off into
// PrepareHelmSuggestions because their fix paths reference rendered output
// that has no reliable line mapping back to the source template.
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

		// Tentative unfixed entries for this resource. We collect them locally
		// so a post-loop reconciliation pass can promote controls whose failed
		// paths are covered by another control's planned YamlExpressions.
		type pendingUnfixed struct {
			entry UnfixedControl
			ac    *resourcesresults.ResourceAssociatedControl
		}
		var tentativeUnfixed []pendingUnfixed

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
			tentativeUnfixed = append(tentativeUnfixed, pendingUnfixed{
				entry: UnfixedControl{
					ControlID:    ac.GetID(),
					ControlName:  ac.GetName(),
					ResourceName: resourceObj.GetName(),
					ResourceKind: resourceObj.GetKind(),
					FilePath:     absolutePath,
					Reason:       reason,
				},
				ac: ac,
			})
		}

		// Reconcile tentative-unfixed entries against the final set of planned
		// YamlExpressions for this resource: a control's failed paths may be
		// covered by another control's FixPath (e.g. C-0016's
		// "privileged = false" also remediates C-0057). Promote those to
		// fixed instead of misleading the user with "no auto-fix available".
		plannedPaths := plannedPathsFromExpressions(rfi.YamlExpressions)
		for _, pu := range tentativeUnfixed {
			if len(plannedPaths) > 0 && controlIsCoveredByPlannedPaths(pu.ac, plannedPaths) {
				h.fixedControlsCount++
				continue
			}
			h.unfixedControls = append(h.unfixedControls, pu.entry)
		}

		if len(rfi.YamlExpressions) > 0 {
			resourcesToFix = append(resourcesToFix, rfi)
		}
	}

	return resourcesToFix
}

// PrepareHelmSuggestions collects fix guidance for resources whose Source is a
// Helm chart. We never auto-edit template files for these: the fix paths are
// keyed against rendered YAML, and the previous attempts at mapping rendered
// lines back to template lines (#1215/#1551/#1620/#1628) all foundered on
// range, conditionals, whitespace trimming, and partials. Instead we surface
// the rule's intent plus the .Values.* keys the template statically reads, so
// the user can edit values.yaml themselves.
func (h *FixHandler) PrepareHelmSuggestions(ctx context.Context) []HelmFixSuggestion {
	resourceIdToResource := h.buildResourcesMap()
	suggestions := make([]HelmFixSuggestion, 0)

	for _, result := range h.reportObj.Results {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}
		resourceObj := resourceIdToResource[result.ResourceID]
		if resourceObj == nil || resourceObj.Source == nil {
			continue
		}
		if resourceObj.Source.FileType != reporthandling.SourceTypeHelmChart {
			continue
		}

		var fixPaths []armotypes.FixPath
		for i := range result.AssociatedControls {
			ac := &result.AssociatedControls[i]
			if !ac.GetStatus(nil).IsFailed() {
				continue
			}
			for _, rule := range ac.ResourceAssociatedRules {
				if !rule.GetStatus(nil).IsFailed() {
					continue
				}
				for _, rp := range rule.Paths {
					if rp.FixPath.Path == "" {
						continue
					}
					if strings.HasPrefix(rp.FixPath.Value, UserValuePrefix) && h.fixInfo.SkipUserValues {
						continue
					}
					fixPaths = append(fixPaths, rp.FixPath)
				}
			}
		}
		if len(fixPaths) == 0 {
			continue
		}

		suggestions = append(suggestions, HelmFixSuggestion{
			Resource:     resourceObj,
			ChartPath:    resourceObj.Source.HelmPath,
			ChartName:    resourceObj.Source.HelmChartName,
			TemplateFile: resourceObj.Source.HelmTemplateFile,
			ValuesPaths:  resourceObj.Source.HelmValuesPaths,
			FixPaths:     fixPaths,
		})
	}
	return suggestions
}

// PrintHelmSuggestions renders the Helm fix guidance to the logger. It is
// always print-only — we never write edits for Helm sources because we cannot
// guarantee the .Values key for a given fix path. The user opens values.yaml
// and applies the change deliberately.
func (h *FixHandler) PrintHelmSuggestions(suggestions []HelmFixSuggestion) {
	if len(suggestions) == 0 {
		return
	}
	var sb strings.Builder
	sb.WriteString("\nHelm-rendered resources cannot be patched in place. Suggested values.yaml edits:\n\n")
	for _, s := range suggestions {
		fmt.Fprintf(&sb, "Chart: %s (%s)\n", s.ChartName, s.ChartPath)
		if s.TemplateFile != "" {
			fmt.Fprintf(&sb, "Template: %s\n", s.TemplateFile)
		}
		fmt.Fprintf(&sb, "Resource: %s/%s\n", s.Resource.GetKind(), s.Resource.GetName())
		sb.WriteString("Required changes (rendered-YAML paths):\n")
		for i, fp := range s.FixPaths {
			fmt.Fprintf(&sb, "\t%d) %s = %s\n", i+1, fp.Path, fp.Value)
		}
		if len(s.ValuesPaths) > 0 {
			sb.WriteString("Candidate .Values keys referenced by this template:\n")
			for _, v := range s.ValuesPaths {
				fmt.Fprintf(&sb, "\t- .Values.%s\n", v)
			}
			sb.WriteString("Edit one of these in values.yaml to satisfy the change above.\n")
		} else {
			sb.WriteString("(No .Values.* references could be statically traced for this template — edit the template directly.)\n")
		}
		sb.WriteString("\n------\n")
	}
	logger.L().Info(sb.String())
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
	fmt.Fprintf(&sb, "%s %d of %d flagged control instances. The following require manual remediation:\n",
		verb, h.fixedControlsCount, totalFailed)

	for _, u := range deduped {
		location := u.FilePath
		if location == "" {
			location = "<unknown>"
		}
		fmt.Fprintf(&sb, "  - %s %s on %s/%s (%s) — %s\n",
			u.ControlID, u.ControlName, u.ResourceKind, u.ResourceName, location, u.Reason)
	}

	logger.L().Warning(sb.String())
}

func (h *FixHandler) PrintExpectedChanges(resourcesToFix []ResourceFixInfo) {
	var sb strings.Builder
	sb.WriteString("The following changes will be applied:\n")

	for _, resourceFixInfo := range resourcesToFix {
		fmt.Fprintf(&sb, "File: %s\n", resourceFixInfo.FilePath)
		fmt.Fprintf(&sb, "Resource: %s\n", resourceFixInfo.Resource.GetName())
		fmt.Fprintf(&sb, "Kind: %s\n", resourceFixInfo.Resource.GetKind())
		sb.WriteString("Changes:\n")

		i := 1
		for _, fixPath := range resourceFixInfo.YamlExpressions {
			fmt.Fprintf(&sb, "\t%d) %s = %s\n", i, fixPath.Path, fixPath.Value)
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
	lastColon := strings.LastIndex(filePathWithIndex, ":")
	if lastColon == -1 {
		return "", 0, fmt.Errorf("expected to find ':' in file path")
	}

	filePath = filePathWithIndex[:lastColon]
	indexStr := filePathWithIndex[lastColon+1:]

	documentIndex, err = strconv.Atoi(indexStr)
	if err != nil {
		return "", 0, err
	}

	return filePath, documentIndex, nil
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

// plannedPathsFromExpressions returns the distinct, non-empty FixPath.Path
// values from a YamlExpressions map. Used by the unfixed-control reconciliation
// pass to test whether a control's failed paths are covered by some planned
// edit.
func plannedPathsFromExpressions(exprs map[string]armotypes.FixPath) []string {
	if len(exprs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(exprs))
	out := make([]string, 0, len(exprs))
	for _, fp := range exprs {
		if fp.Path == "" || seen[fp.Path] {
			continue
		}
		seen[fp.Path] = true
		out = append(out, fp.Path)
	}
	return out
}

// normalizeFailedPath strips an "=<expected>" suffix that some FailedPath
// values carry to encode the value the check expected (e.g.
// "spec.…runAsNonRoot=true"). The reconciliation pass compares pure YAML
// paths, so the suffix must not participate in the segment-boundary check.
func normalizeFailedPath(p string) string {
	if i := strings.IndexByte(p, '='); i >= 0 {
		return p[:i]
	}
	return p
}

// yamlPathCovers reports whether setting `planned` necessarily satisfies a
// check that observed `failed`. Coverage holds when planned == failed, or
// planned is an ancestor of failed on YAML-segment boundaries — segments are
// separated by '.' or '['. String prefix alone is not enough: "spec.host" must
// not be treated as covering "spec.hostNetwork". Callers must pass a
// normalized `failed` (see normalizeFailedPath) since FailedPath values may
// carry "=<expected>" suffixes.
func yamlPathCovers(planned, failed string) bool {
	if planned == "" || failed == "" {
		return false
	}
	if planned == failed {
		return true
	}
	if !strings.HasPrefix(failed, planned) {
		return false
	}
	next := failed[len(planned)]
	return next == '.' || next == '['
}

// actionableLocation returns the YAML location a path entry describes,
// regardless of which remediation field it was stored in. PosturePaths
// entries carry exactly one of FailedPath / DeletePath / ReviewPath / FixPath
// in practice (see appendPaths in opa-utils), so taking the first non-empty
// one yields the location the check was actually pointing at.
func actionableLocation(p armotypes.PosturePaths) string {
	if p.FailedPath != "" {
		return normalizeFailedPath(p.FailedPath)
	}
	if p.DeletePath != "" {
		return normalizeFailedPath(p.DeletePath)
	}
	if p.ReviewPath != "" {
		return normalizeFailedPath(p.ReviewPath)
	}
	if p.FixPath.Path != "" {
		return p.FixPath.Path
	}
	return ""
}

// controlIsCoveredByPlannedPaths reports whether every actionable path entry
// on the control's failed rules is covered by some planned FixPath. Every
// entry counts — FailedPath, DeletePath, and ReviewPath alike — so a control
// that requires (for example) deleting `spec.hostNetwork` cannot be promoted
// just because an unrelated FailedPath happens to overlap with a planned
// edit. A control whose rules carry no actionable locations at all is not
// promoted either (nothing concrete to match against).
func controlIsCoveredByPlannedPaths(ac *resourcesresults.ResourceAssociatedControl, plannedPaths []string) bool {
	sawActionablePath := false
	for _, rule := range ac.ResourceAssociatedRules {
		if !rule.GetStatus(nil).IsFailed() {
			continue
		}
		for _, p := range rule.Paths {
			loc := actionableLocation(p)
			if loc == "" {
				continue
			}
			sawActionablePath = true
			covered := false
			for _, planned := range plannedPaths {
				if yamlPathCovers(planned, loc) {
					covered = true
					break
				}
			}
			if !covered {
				return false
			}
		}
	}
	return sawActionablePath
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
	perm := os.FileMode(0644)
	if info, err := os.Stat(filepath); err == nil {
		perm = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error reading file permissions: %w", err)
	}

	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("error writing fixes to file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
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
