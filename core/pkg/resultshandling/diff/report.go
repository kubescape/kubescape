package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling/apis"
)

// These intentionally small report types parse only fields that affect diff
// identity, severity, scope, and evaluation completeness. Unknown fields from
// newer Kubescape versions remain forward compatible.
type scanReport struct {
	Results        []resultEntry  `json:"results"`
	SummaryDetails summaryDetails `json:"summaryDetails"`
	Metadata       reportMetadata `json:"metadata,omitempty"`
	ScanCoverage   scanCoverage   `json:"scanCoverage,omitempty"`
}

type resultEntry struct {
	ResourceID         string         `json:"resourceID"`
	AssociatedControls []controlEntry `json:"controls"`
}

type controlEntry struct {
	ControlID string      `json:"controlID"`
	Name      string      `json:"name"`
	Status    statusInfo  `json:"status"`
	Rules     []ruleEntry `json:"rules,omitempty"`
}

type statusInfo struct {
	InnerStatus string `json:"status"`
	SubStatus   string `json:"subStatus,omitempty"`
}

type ruleEntry struct {
	Name                string         `json:"name"`
	Status              string         `json:"status"`
	SubStatus           string         `json:"subStatus,omitempty"`
	Paths               []evidencePath `json:"paths,omitempty"`
	RelatedResourcesIDs []string       `json:"relatedResourcesIDs,omitempty"`
}

type evidencePath struct {
	ResourceID string  `json:"resourceID,omitempty"`
	FailedPath string  `json:"failedPath,omitempty"`
	ReviewPath string  `json:"reviewPath,omitempty"`
	DeletePath string  `json:"deletePath,omitempty"`
	FixPath    fixPath `json:"fixPath,omitempty"`
	FixCommand string  `json:"fixCommand,omitempty"`
}

type fixPath struct {
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

type summaryDetails struct {
	Controls map[string]controlSummary `json:"controls"`
}

type controlSummary struct {
	ScoreFactor float32 `json:"scoreFactor"`
	Severity    string  `json:"severity"`
}

type reportMetadata struct {
	TargetMetadata contextMetadata `json:"targetMetadata,omitempty"`
	ScanMetadata   scanMetadata    `json:"scanMetadata,omitempty"`
}

type contextMetadata struct {
	Cluster *clusterContext `json:"clusterContextMetadata,omitempty"`
	Repo    *repoContext    `json:"gitRepoContextMetadata,omitempty"`
}

type clusterContext struct {
	ContextName string `json:"contextName,omitempty"`
}

type repoContext struct {
	Provider  string `json:"provider,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Owner     string `json:"owner,omitempty"`
	RemoteURL string `json:"remoteURL,omitempty"`
	Branch    string `json:"branch,omitempty"`
}

type scanMetadata struct {
	TargetType         string   `json:"targetType,omitempty"`
	ScanningTarget     *uint16  `json:"scanningTarget,omitempty"`
	IncludeNamespaces  []string `json:"includeNamespaces,omitempty"`
	ExcludedNamespaces []string `json:"excludedNamespaces,omitempty"`
	TargetNames        []string `json:"targetNames,omitempty"`
}

type scanCoverage struct {
	FailedGVRPulls       []json.RawMessage     `json:"failedGVRPulls,omitempty"`
	PartialGVRPulls      []json.RawMessage     `json:"partialGVRPulls,omitempty"`
	PolicyDegradations   []json.RawMessage     `json:"policyDegradations,omitempty"`
	NotEvaluatedControls []notEvaluatedControl `json:"notEvaluatedControls,omitempty"`
	Degraded             bool                  `json:"degraded,omitempty"`
}

type notEvaluatedControl struct {
	ControlID string `json:"controlID"`
	Reason    string `json:"reason,omitempty"`
}

func loadReport(path string) (*scanReport, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("invalid report: expected a JSON object")
	}

	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if topLevel == nil {
		return nil, fmt.Errorf("invalid report: expected a JSON object")
	}

	resultsJSON, exists := topLevel["results"]
	if !exists {
		return nil, fmt.Errorf("invalid report: missing required results field; provide JSON output from kubescape scan")
	}
	if isJSONNull(resultsJSON) {
		return nil, fmt.Errorf("invalid report: results must be an array, not null")
	}
	summaryJSON, exists := topLevel["summaryDetails"]
	if !exists {
		return nil, fmt.Errorf("invalid report: missing required summaryDetails field; provide JSON output from kubescape scan")
	}
	if isJSONNull(summaryJSON) {
		return nil, fmt.Errorf("invalid report: summaryDetails must be an object, not null")
	}

	var report scanReport
	if err := json.Unmarshal(resultsJSON, &report.Results); err != nil {
		return nil, fmt.Errorf("invalid report results: %w", err)
	}
	if err := validateSummary(&report, summaryJSON); err != nil {
		return nil, err
	}
	if metadataJSON, exists := topLevel["metadata"]; exists && !isJSONNull(metadataJSON) {
		if err := json.Unmarshal(metadataJSON, &report.Metadata); err != nil {
			return nil, fmt.Errorf("invalid report metadata: %w", err)
		}
	}
	if coverageJSON, exists := topLevel["scanCoverage"]; exists && !isJSONNull(coverageJSON) {
		if err := json.Unmarshal(coverageJSON, &report.ScanCoverage); err != nil {
			return nil, fmt.Errorf("invalid report scanCoverage: %w", err)
		}
	}
	if err := validateReport(&report); err != nil {
		return nil, err
	}
	return &report, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func validateSummary(report *scanReport, summaryJSON json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(summaryJSON, &fields); err != nil {
		return fmt.Errorf("invalid report summaryDetails: %w", err)
	}
	if fields == nil {
		return fmt.Errorf("invalid report: summaryDetails must be an object")
	}
	controlsJSON, exists := fields["controls"]
	if !exists {
		return fmt.Errorf("invalid report: summaryDetails is missing required controls field")
	}
	if isJSONNull(controlsJSON) {
		return fmt.Errorf("invalid report: summaryDetails.controls must be an object, not null")
	}
	var controls map[string]controlSummary
	if err := json.Unmarshal(controlsJSON, &controls); err != nil {
		return fmt.Errorf("invalid report summaryDetails.controls: %w", err)
	}
	report.SummaryDetails.Controls = controls
	return nil
}

func validateReport(report *scanReport) error {
	seen := make(map[key]struct{})
	for resultIndex, result := range report.Results {
		if strings.TrimSpace(result.ResourceID) == "" {
			return fmt.Errorf("invalid report: results[%d].resourceID is empty", resultIndex)
		}
		for controlIndex, control := range result.AssociatedControls {
			if strings.TrimSpace(control.ControlID) == "" {
				return fmt.Errorf("invalid report: results[%d].controls[%d].controlID is empty", resultIndex, controlIndex)
			}
			if strings.TrimSpace(control.Status.InnerStatus) == "" {
				return fmt.Errorf("invalid report: results[%d].controls[%d].status.status is empty", resultIndex, controlIndex)
			}
			controlKey := key{resourceID: result.ResourceID, controlID: control.ControlID}
			if _, exists := seen[controlKey]; exists {
				return fmt.Errorf("invalid report: duplicate resource and control pair %q / %q", result.ResourceID, control.ControlID)
			}
			seen[controlKey] = struct{}{}
			for ruleIndex, rule := range control.Rules {
				if strings.TrimSpace(rule.Name) == "" {
					return fmt.Errorf("invalid report: results[%d].controls[%d].rules[%d].name is empty", resultIndex, controlIndex, ruleIndex)
				}
				if strings.TrimSpace(rule.Status) == "" {
					return fmt.Errorf("invalid report: results[%d].controls[%d].rules[%d].status is empty", resultIndex, controlIndex, ruleIndex)
				}
			}
		}
	}
	return nil
}

func buildMap(report *scanReport) map[key]controlEntry {
	controls := make(map[key]controlEntry)
	for _, result := range report.Results {
		for _, control := range result.AssociatedControls {
			controls[key{resourceID: result.ResourceID, controlID: control.ControlID}] = control
		}
	}
	return controls
}

func buildSeverityMap(report *scanReport) map[string]string {
	severities := make(map[string]string, len(report.SummaryDetails.Controls))
	for controlID, summary := range report.SummaryDetails.Controls {
		severity := summary.Severity
		if severity == "" {
			severity = apis.ControlSeverityToString(summary.ScoreFactor)
		}
		severities[controlID] = severity
	}
	return severities
}

func incompatibleScopeReasons(base, head *scanReport) []string {
	reasons := make([]string, 0)
	baseScan, headScan := base.Metadata.ScanMetadata, head.Metadata.ScanMetadata
	if differentNonEmpty(baseScan.TargetType, headScan.TargetType) {
		reasons = append(reasons, fmt.Sprintf("scan target types differ: base=%q head=%q", baseScan.TargetType, headScan.TargetType))
	}
	if baseScan.ScanningTarget != nil && headScan.ScanningTarget != nil && *baseScan.ScanningTarget != *headScan.ScanningTarget {
		reasons = append(reasons, fmt.Sprintf("scanning targets differ: base=%d head=%d", *baseScan.ScanningTarget, *headScan.ScanningTarget))
	}
	compareStringSet(&reasons, "included namespaces", baseScan.IncludeNamespaces, headScan.IncludeNamespaces)
	compareStringSet(&reasons, "excluded namespaces", baseScan.ExcludedNamespaces, headScan.ExcludedNamespaces)
	compareStringSet(&reasons, "target names", baseScan.TargetNames, headScan.TargetNames)

	baseContext, headContext := base.Metadata.TargetMetadata, head.Metadata.TargetMetadata
	if baseContext.Cluster != nil && headContext.Cluster != nil && differentNonEmpty(baseContext.Cluster.ContextName, headContext.Cluster.ContextName) {
		reasons = append(reasons, fmt.Sprintf("cluster contexts differ: base=%q head=%q", baseContext.Cluster.ContextName, headContext.Cluster.ContextName))
	}
	if baseContext.Repo != nil && headContext.Repo != nil {
		baseIdentity, headIdentity := repositoryIdentity(baseContext.Repo), repositoryIdentity(headContext.Repo)
		if differentNonEmpty(baseIdentity, headIdentity) {
			reasons = append(reasons, fmt.Sprintf("repository identities differ: base=%q head=%q", baseIdentity, headIdentity))
		}
	}
	return reasons
}

func differentNonEmpty(left, right string) bool {
	return strings.TrimSpace(left) != "" && strings.TrimSpace(right) != "" && strings.TrimSpace(left) != strings.TrimSpace(right)
}

func compareStringSet(reasons *[]string, label string, left, right []string) {
	if len(left) == 0 && len(right) == 0 {
		return
	}
	leftCanonical, rightCanonical := canonicalSet(left), canonicalSet(right)
	if strings.Join(leftCanonical, "\x00") != strings.Join(rightCanonical, "\x00") {
		*reasons = append(*reasons, fmt.Sprintf("%s differ: base=%v head=%v", label, leftCanonical, rightCanonical))
	}
}

func canonicalSet(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func repositoryIdentity(repo *repoContext) string {
	if repo == nil {
		return ""
	}
	if repo.Owner != "" || repo.Repo != "" {
		return strings.Trim(strings.ToLower(strings.TrimSpace(repo.Provider)+"/"+strings.TrimSpace(repo.Owner)+"/"+strings.TrimSpace(repo.Repo)), "/")
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(repo.RemoteURL)), ".git")
}

func controlDefinitelyOutOfScope(report *scanReport, controlID string) bool {
	return len(report.SummaryDetails.Controls) > 0 && !summaryContainsControl(report, controlID)
}

func absentNewFailureRisk(report *scanReport, controlID string) string {
	for _, control := range report.ScanCoverage.NotEvaluatedControls {
		if control.ControlID == controlID {
			return "control was not evaluated in the base report, so the head failure cannot be classified as new"
		}
	}
	coverage := report.ScanCoverage
	if coverage.Degraded || len(coverage.FailedGVRPulls) > 0 || len(coverage.PartialGVRPulls) > 0 || len(coverage.PolicyDegradations) > 0 {
		return "base report has degraded scan coverage, so the head failure cannot be classified as new"
	}
	return ""
}

func summaryContainsControl(report *scanReport, controlID string) bool {
	_, exists := report.SummaryDetails.Controls[controlID]
	return exists
}

func absentResolutionRisk(report *scanReport, controlID string) string {
	if controlDefinitelyOutOfScope(report, controlID) {
		return "control is not present in the head report's declared control scope"
	}
	for _, control := range report.ScanCoverage.NotEvaluatedControls {
		if control.ControlID == controlID {
			return "control was not evaluated in the head report"
		}
	}
	coverage := report.ScanCoverage
	if coverage.Degraded || len(coverage.FailedGVRPulls) > 0 || len(coverage.PartialGVRPulls) > 0 || len(coverage.PolicyDegradations) > 0 {
		return "head report has degraded scan coverage, so an absent failure is not a conclusive resolution"
	}
	return ""
}
