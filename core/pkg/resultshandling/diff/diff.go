package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling/apis"
)

const statusAbsent = "absent"

// Granularity selects the unit used to compare failures.
type Granularity string

const (
	// GranularityEvidence compares failed rules and their failed/review paths.
	// It is the default because a control can gain a regression while remaining
	// failed at the aggregate level.
	GranularityEvidence Granularity = "evidence"
	// GranularityControl preserves the pre-evidence resource+control behavior.
	GranularityControl Granularity = "control"
)

// Options controls the comparison without changing report parsing.
type Options struct {
	Granularity Granularity
}

// ControlChange represents one comparable failure unit. The first six fields
// are retained for compatibility with consumers of the original diff format.
type ControlChange struct {
	ResourceID         string `json:"resourceID"`
	ControlID          string `json:"controlID"`
	ControlName        string `json:"controlName"`
	Severity           string `json:"severity"`
	BaseStatus         string `json:"baseStatus"`
	HeadStatus         string `json:"headStatus"`
	RuleName           string `json:"ruleName,omitempty"`
	EvidenceType       string `json:"evidenceType,omitempty"`
	Path               string `json:"path,omitempty"`
	EvidenceResourceID string `json:"evidenceResourceID,omitempty"`
	Reason             string `json:"reason,omitempty"`
}

// ChangeSet groups comparable regressions and explicitly separates results
// that cannot be classified safely. Incomparable failures never appear as
// resolved, avoiding false-green output when scan scope or coverage changed.
type ChangeSet struct {
	New          []ControlChange `json:"new"`
	Resolved     []ControlChange `json:"resolved"`
	Unchanged    []ControlChange `json:"unchanged"`
	Incomparable []ControlChange `json:"incomparable,omitempty"`
	Warnings     []string        `json:"warnings,omitempty"`
}

type key struct {
	resourceID string
	controlID  string
}

// Compute loads two scan JSON reports and compares failed evidence. It keeps
// the existing signature while making the safe evidence behavior the default.
func Compute(basePath, headPath string) (*ChangeSet, error) {
	return ComputeWithOptions(basePath, headPath, Options{Granularity: GranularityEvidence})
}

// ComputeWithOptions loads and compares two scan reports.
func ComputeWithOptions(basePath, headPath string, options Options) (*ChangeSet, error) {
	granularity, err := normalizeGranularity(options.Granularity)
	if err != nil {
		return nil, err
	}

	base, err := loadReport(basePath)
	if err != nil {
		return nil, fmt.Errorf("loading base report: %w", err)
	}
	head, err := loadReport(headPath)
	if err != nil {
		return nil, fmt.Errorf("loading head report: %w", err)
	}

	return compareReports(base, head, granularity), nil
}

// ValidateGranularity validates a CLI/API value without reading reports.
func ValidateGranularity(value string) error {
	_, err := normalizeGranularity(Granularity(value))
	return err
}

func normalizeGranularity(value Granularity) (Granularity, error) {
	if value == "" {
		return GranularityEvidence, nil
	}
	value = Granularity(strings.ToLower(strings.TrimSpace(string(value))))
	switch value {
	case GranularityEvidence, GranularityControl:
		return value, nil
	default:
		return "", fmt.Errorf("invalid diff granularity %q, supported granularities: evidence, control", value)
	}
}

func compareReports(base, head *scanReport, granularity Granularity) *ChangeSet {
	cs := &ChangeSet{}
	baseMap := buildMap(base)
	headMap := buildMap(head)
	baseSeverity := buildSeverityMap(base)
	headSeverity := buildSeverityMap(head)

	if reasons := incompatibleScopeReasons(base, head); len(reasons) > 0 {
		cs.Warnings = append(cs.Warnings, reasons...)
		markAllFailuresIncomparable(cs, base, head, granularity, reasons[0])
		sortChangeSet(cs)
		return cs
	}

	keys := unionKeys(baseMap, headMap)
	for _, controlKey := range keys {
		baseControl, inBase := baseMap[controlKey]
		headControl, inHead := headMap[controlKey]
		baseStatus := statusOf(baseControl, inBase)
		headStatus := statusOf(headControl, inHead)

		switch {
		case baseStatus == string(apis.StatusFailed) && headStatus == string(apis.StatusFailed):
			compareFailedPair(cs, base, head, controlKey, baseControl, headControl, baseSeverity, headSeverity, granularity)
		case headStatus == string(apis.StatusFailed):
			classifyHeadFailure(cs, base, controlKey, baseControl, headControl, inBase, baseStatus, headSeverity, granularity)
		case baseStatus == string(apis.StatusFailed):
			classifyBaseFailure(cs, head, controlKey, baseControl, headControl, inHead, headStatus, baseSeverity, granularity)
		}
	}

	sortChangeSet(cs)
	return cs
}

func compareFailedPair(cs *ChangeSet, base, head *scanReport, controlKey key, baseControl, headControl controlEntry, baseSeverity, headSeverity map[string]string, granularity Granularity) {
	baseFindings := findingsForControl(controlKey, baseControl, baseSeverity[controlKey.controlID], granularity)
	headFindings := findingsForControl(controlKey, headControl, headSeverity[controlKey.controlID], granularity)

	if granularity == GranularityEvidence && evidenceDetailMismatch(baseFindings, headFindings) {
		reason := "reports use different failed evidence detail; aggregate, rule-level, and path-level failures cannot be compared safely"
		appendFindings(&cs.Incomparable, baseFindings, string(apis.StatusFailed), string(apis.StatusFailed), reason)
		appendFindings(&cs.Incomparable, headFindings, string(apis.StatusFailed), string(apis.StatusFailed), reason)
		return
	}

	baseByFingerprint := indexFindings(baseFindings)
	headByFingerprint := indexFindings(headFindings)
	for fingerprint, finding := range headByFingerprint {
		if _, exists := baseByFingerprint[fingerprint]; exists {
			cs.Unchanged = append(cs.Unchanged, finding.change(string(apis.StatusFailed), string(apis.StatusFailed), ""))
		} else {
			if reason := existingFailureNewRisk(base, baseControl, controlKey.controlID, finding.fingerprint.ruleName); reason != "" {
				cs.Incomparable = append(cs.Incomparable, finding.change(string(apis.StatusFailed), string(apis.StatusFailed), reason))
				continue
			}
			cs.New = append(cs.New, finding.change(string(apis.StatusFailed), string(apis.StatusFailed), ""))
		}
	}
	for fingerprint, finding := range baseByFingerprint {
		if _, exists := headByFingerprint[fingerprint]; !exists {
			if reason := existingFailureResolutionRisk(head, headControl, controlKey.controlID, finding.fingerprint.ruleName); reason != "" {
				cs.Incomparable = append(cs.Incomparable, finding.change(string(apis.StatusFailed), string(apis.StatusFailed), reason))
				continue
			}
			cs.Resolved = append(cs.Resolved, finding.change(string(apis.StatusFailed), string(apis.StatusFailed), ""))
		}
	}
}

func classifyHeadFailure(cs *ChangeSet, base *scanReport, controlKey key, baseControl, headControl controlEntry, inBase bool, baseStatus string, severity map[string]string, granularity Granularity) {
	findings := findingsForControl(controlKey, headControl, severity[controlKey.controlID], granularity)
	if inBase && !isConclusiveNonFailure(baseControl) {
		reason := fmt.Sprintf("base control status %q is not a conclusive non-failure", displayStatus(baseStatus))
		appendFindings(&cs.Incomparable, findings, baseStatus, string(apis.StatusFailed), reason)
		return
	}
	if !inBase && controlDefinitelyOutOfScope(base, controlKey.controlID) {
		reason := "control is not present in the base report's declared control scope"
		appendFindings(&cs.Incomparable, findings, statusAbsent, string(apis.StatusFailed), reason)
		return
	}
	if !inBase {
		if reason := absentNewFailureRisk(base, controlKey.controlID); reason != "" {
			appendFindings(&cs.Incomparable, findings, statusAbsent, string(apis.StatusFailed), reason)
			return
		}
	}
	appendFindings(&cs.New, findings, baseStatus, string(apis.StatusFailed), "")
}

func classifyBaseFailure(cs *ChangeSet, head *scanReport, controlKey key, baseControl, headControl controlEntry, inHead bool, headStatus string, severity map[string]string, granularity Granularity) {
	findings := findingsForControl(controlKey, baseControl, severity[controlKey.controlID], granularity)
	if inHead {
		if !isConclusiveNonFailure(headControl) {
			reason := fmt.Sprintf("head control status %q is not a conclusive resolution", displayStatus(headStatus))
			appendFindings(&cs.Incomparable, findings, string(apis.StatusFailed), headStatus, reason)
			return
		}
		appendFindings(&cs.Resolved, findings, string(apis.StatusFailed), headStatus, "")
		return
	}

	if reason := absentResolutionRisk(head, controlKey.controlID); reason != "" {
		appendFindings(&cs.Incomparable, findings, string(apis.StatusFailed), statusAbsent, reason)
		return
	}
	appendFindings(&cs.Resolved, findings, string(apis.StatusFailed), statusAbsent, "")
}

func isConclusiveNonFailure(control controlEntry) bool {
	return control.Status.InnerStatus == string(apis.StatusPassed) && control.Status.SubStatus != string(apis.SubStatusNotEvaluated)
}

func existingFailureNewRisk(report *scanReport, control controlEntry, controlID, ruleName string) string {
	if reason := absentNewFailureRisk(report, controlID); reason != "" {
		return reason
	}
	return notEvaluatedRuleReason(control, ruleName, "base", "new")
}

func existingFailureResolutionRisk(report *scanReport, control controlEntry, controlID, ruleName string) string {
	if reason := absentResolutionRisk(report, controlID); reason != "" {
		return reason
	}
	return notEvaluatedRuleReason(control, ruleName, "head", "resolved")
}

func notEvaluatedRuleReason(control controlEntry, ruleName, side, action string) string {
	if control.Status.SubStatus == string(apis.SubStatusNotEvaluated) {
		return fmt.Sprintf("%s control was not evaluated, so missing evidence cannot be classified as %s", side, action)
	}
	for _, rule := range control.Rules {
		if rule.Name == ruleName && rule.SubStatus == string(apis.SubStatusNotEvaluated) {
			return fmt.Sprintf("%s rule %q was not evaluated, so missing evidence cannot be classified as %s", side, ruleName, action)
		}
	}
	return ""
}

func displayStatus(status string) string {
	if status == "" {
		return "unknown"
	}
	return status
}

func statusOf(control controlEntry, exists bool) string {
	if !exists {
		return statusAbsent
	}
	return control.Status.InnerStatus
}

func unionKeys(base, head map[key]controlEntry) []key {
	set := make(map[key]struct{}, len(base)+len(head))
	for k := range base {
		set[k] = struct{}{}
	}
	for k := range head {
		set[k] = struct{}{}
	}
	keys := make([]key, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].resourceID != keys[j].resourceID {
			return keys[i].resourceID < keys[j].resourceID
		}
		return keys[i].controlID < keys[j].controlID
	})
	return keys
}

func markAllFailuresIncomparable(cs *ChangeSet, base, head *scanReport, granularity Granularity, reason string) {
	seen := make(map[findingFingerprint]struct{})
	for _, side := range []struct {
		report     *scanReport
		baseStatus string
		headStatus string
	}{
		{base, string(apis.StatusFailed), statusAbsent},
		{head, statusAbsent, string(apis.StatusFailed)},
	} {
		severity := buildSeverityMap(side.report)
		for controlKey, control := range buildMap(side.report) {
			if control.Status.InnerStatus != string(apis.StatusFailed) {
				continue
			}
			for _, finding := range findingsForControl(controlKey, control, severity[controlKey.controlID], granularity) {
				if _, exists := seen[finding.fingerprint]; exists {
					continue
				}
				seen[finding.fingerprint] = struct{}{}
				cs.Incomparable = append(cs.Incomparable, finding.change(side.baseStatus, side.headStatus, reason))
			}
		}
	}
}

func appendFindings(destination *[]ControlChange, findings []finding, baseStatus, headStatus, reason string) {
	for _, item := range findings {
		*destination = append(*destination, item.change(baseStatus, headStatus, reason))
	}
}

func sortChangeSet(cs *ChangeSet) {
	sortChanges(cs.New)
	sortChanges(cs.Resolved)
	sortChanges(cs.Unchanged)
	sortChanges(cs.Incomparable)
	sort.Strings(cs.Warnings)
}

func sortChanges(changes []ControlChange) {
	sort.Slice(changes, func(i, j int) bool {
		left, right := changes[i], changes[j]
		if leftRank, rightRank := severityRank(left.Severity), severityRank(right.Severity); leftRank != rightRank {
			return leftRank > rightRank
		}
		if left.ResourceID != right.ResourceID {
			return left.ResourceID < right.ResourceID
		}
		if left.ControlID != right.ControlID {
			return left.ControlID < right.ControlID
		}
		if left.RuleName != right.RuleName {
			return left.RuleName < right.RuleName
		}
		if left.EvidenceType != right.EvidenceType {
			return left.EvidenceType < right.EvidenceType
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.EvidenceResourceID != right.EvidenceResourceID {
			return left.EvidenceResourceID < right.EvidenceResourceID
		}
		return left.Reason < right.Reason
	})
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// FilterBySeverity returns changes at or above the requested threshold. A
// change whose severity cannot be resolved to a known bucket (severityRank
// returns 0 for anything other than low/medium/high/critical, e.g. a control
// with a zero or missing baseScore) is treated as at or above any threshold
// rather than silently excluded - the same fail-closed policy
// enforceSeverityThresholds already applies to the plain scan gate for the
// identical case (see countFailedResourcesWithUnbucketedSeverity in
// cmd/scan/framework.go). Dropping a finding whose real severity is simply
// unknown would be the exact "false-green output" ChangeSet's own doc
// comment says Incomparable findings exist to prevent.
func FilterBySeverity(changes []ControlChange, threshold string) []ControlChange {
	if threshold == "" {
		return changes
	}
	minimum := severityRank(threshold)
	filtered := make([]ControlChange, 0, len(changes))
	for _, change := range changes {
		if rank := severityRank(change.Severity); rank == 0 || rank >= minimum {
			filtered = append(filtered, change)
		}
	}
	return filtered
}
