package printer

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/kubescape/kubescape/v4/core/cautils"
)

const (
	// gitLabMessageWarn is the scan.messages level for a condition that does not
	// fail the scan but means the report may be incomplete. The schema allows
	// info, warn and fatal; scan.status is deliberately left alone.
	gitLabMessageWarn = "warn"

	// maxGitLabScanMessages bounds scan.messages, the final entry included, so a
	// scan with thousands of unreadable manifests cannot bloat the report.
	maxGitLabScanMessages = 25

	// maxGitLabMessageLen bounds one message value, which can embed a multi-line
	// error returned by the Kubernetes API or a YAML parser.
	maxGitLabMessageLen = 500
)

// gitLabScanMessage is one entry of the GitLab report's scan.messages array.
// Both fields are required by the schema and value must not be empty.
type gitLabScanMessage struct {
	Level string `json:"level"`
	Value string `json:"value"`
}

// gitLabOmittedResources counts failed resources the report could not carry,
// because GitLab can only anchor a finding to a file inside the repository.
type gitLabOmittedResources struct {
	withoutFilePath   int
	outsideRepository int
}

// buildGitLabScanMessages turns the gaps in a scan into scan.messages warnings.
// An empty report is otherwise indistinguishable from a clean scan, and GitLab
// shows scan.status "success" either way.
//
// A complete scan with nothing omitted returns nil, so its output is unchanged.
// Messages come out in a fixed category order and sorted within a category,
// so identical scans produce identical reports.
func buildGitLabScanMessages(opaSessionObj *cautils.OPASessionObj, omitted gitLabOmittedResources, basePath string) []gitLabScanMessage {
	if opaSessionObj == nil {
		return nil
	}
	coverage := opaSessionObj.ScanCoverage

	var messages []gitLabScanMessage
	add := func(format string, args ...any) {
		messages = append(messages, gitLabScanMessage{Level: gitLabMessageWarn, Value: boundGitLabMessage(fmt.Sprintf(format, args...))})
	}

	if coverage.Degraded {
		add("Scan coverage is degraded: coverage score %s%% (%d of %d controls evaluated); the findings in this report may be incomplete",
			cautils.ComplianceScoreToString(coverage.CoverageScore, 2), coverage.EvaluatedControls, coverage.TotalControls)
	}

	if omitted.withoutFilePath > 0 {
		add("%d failed resource(s) were left out of this report because they are not associated with a file", omitted.withoutFilePath)
	}
	if omitted.outsideRepository > 0 {
		add("%d failed resource(s) were left out of this report because their paths are outside the repository root", omitted.outsideRepository)
	}

	manifests := append([]cautils.SkippedManifest(nil), coverage.SkippedManifests...)
	sort.Slice(manifests, func(i, j int) bool {
		if manifests[i].Path != manifests[j].Path {
			return manifests[i].Path < manifests[j].Path
		}
		return manifests[i].Reason < manifests[j].Reason
	})
	for _, m := range manifests {
		add("Manifest %s was skipped: %s", gitLabDisplayPath(m.Path, basePath), m.Reason)
	}

	// A control that could not be evaluated only because a GVR failed to pull is
	// named on that GVR's message instead of getting a second warning of its own.
	failedGVRs := make(map[string]bool, len(coverage.FailedGVRPulls))
	for _, f := range coverage.FailedGVRPulls {
		failedGVRs[f.GVR] = true
	}
	controlsByGVR := make(map[string][]string)
	explained := make(map[string]bool)
	for _, nec := range coverage.NotEvaluatedControls {
		if nec.Reason != "" || len(nec.MissingGVRs) == 0 {
			continue
		}
		covered := true
		for _, gvr := range nec.MissingGVRs {
			if !failedGVRs[gvr] {
				covered = false
			}
		}
		if !covered {
			continue
		}
		explained[nec.ControlID] = true
		for _, gvr := range nec.MissingGVRs {
			controlsByGVR[gvr] = append(controlsByGVR[gvr], nec.ControlID)
		}
	}

	failed := append([]cautils.FailedGVRPull(nil), coverage.FailedGVRPulls...)
	sort.Slice(failed, func(i, j int) bool { return failed[i].GVR < failed[j].GVR })
	for _, f := range failed {
		if ids := controlsByGVR[f.GVR]; len(ids) > 0 {
			sort.Strings(ids)
			add("Resources of %s could not be collected: %s (controls not evaluated: %s)", f.GVR, f.Error, strings.Join(ids, ", "))
			continue
		}
		add("Resources of %s could not be collected: %s", f.GVR, f.Error)
	}

	partial := append([]cautils.PartialGVRPull(nil), coverage.PartialGVRPulls...)
	sort.Slice(partial, func(i, j int) bool {
		if partial[i].GVR != partial[j].GVR {
			return partial[i].GVR < partial[j].GVR
		}
		if partial[i].Selector != partial[j].Selector {
			return partial[i].Selector < partial[j].Selector
		}
		return partial[i].Error < partial[j].Error
	})
	for _, p := range partial {
		add("Resources of %s were only partially collected (selector %q): %s", p.GVR, p.Selector, p.Error)
	}

	degradations := append([]cautils.PolicyDegradation(nil), coverage.PolicyDegradations...)
	sort.Slice(degradations, func(i, j int) bool {
		if degradations[i].Component != degradations[j].Component {
			return degradations[i].Component < degradations[j].Component
		}
		return degradations[i].Reason < degradations[j].Reason
	})
	for _, d := range degradations {
		add("Policy input %s was not loaded from its configured source and a fallback was used: %s", d.Component, d.Reason)
	}

	if coverage.Degraded {
		// collectSkippedControls already merges the summary's skipped controls with
		// ScanCoverage.NotEvaluatedControls, one entry per control ID, and sorts them.
		for _, sc := range collectSkippedControls(opaSessionObj) {
			if explained[sc.controlID] {
				continue
			}
			if sc.reason == "" {
				add("Control %s was not evaluated", sc.controlID)
				continue
			}
			add("Control %s was not evaluated: %s", sc.controlID, sc.reason)
		}
	}

	return capGitLabScanMessages(messages)
}

// capGitLabScanMessages keeps the first maxGitLabScanMessages-1 messages and
// replaces the rest with one line saying how many were left out.
func capGitLabScanMessages(messages []gitLabScanMessage) []gitLabScanMessage {
	if len(messages) <= maxGitLabScanMessages {
		return messages
	}
	kept := messages[:maxGitLabScanMessages-1]
	omitted := len(messages) - len(kept)
	return append(kept, gitLabScanMessage{
		Level: gitLabMessageWarn,
		Value: fmt.Sprintf("%d additional warning(s) were omitted from this report; use --format json for the complete scan coverage", omitted),
	})
}

// boundGitLabMessage collapses whitespace, so an embedded newline cannot split a
// message, and truncates the result to maxGitLabMessageLen runes.
func boundGitLabMessage(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= maxGitLabMessageLen {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxGitLabMessageLen-1]) + "…"
}

// gitLabDisplayPath shows a skipped manifest relative to the scan root when it
// lies inside it, so the report does not carry the CI runner's absolute paths.
func gitLabDisplayPath(p, basePath string) string {
	if basePath != "" {
		if rel, err := filepath.Rel(basePath, p); err == nil && isRepositoryRelative(rel) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(p)
}
