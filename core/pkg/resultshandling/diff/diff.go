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

// statusAbsent marks a resource+control pair that is missing from one side of the diff
// (it is not one of the apis.ScanningStatus values).
const statusAbsent = "absent"

// minimal structs for reading the v2 JSON scan output produced by jsonprinter.go
type scanReport struct {
	Results        []resultEntry  `json:"results"`
	SummaryDetails summaryDetails `json:"summaryDetails"`
}

type resultEntry struct {
	ResourceID         string         `json:"resourceID"`
	AssociatedControls []controlEntry `json:"controls"`
}

type controlEntry struct {
	ControlID string     `json:"controlID"`
	Name      string     `json:"name"`
	Status    statusInfo `json:"status"`
}

type statusInfo struct {
	InnerStatus string `json:"status"`
}

type summaryDetails struct {
	Controls map[string]controlSummary `json:"controls"`
}

type controlSummary struct {
	ScoreFactor float32 `json:"scoreFactor"`
	Severity    string  `json:"severity"`
}

// ControlChange represents a single resource+control pair whose status changed (or stayed failed).
type ControlChange struct {
	ResourceID  string `json:"resourceID"`
	ControlID   string `json:"controlID"`
	ControlName string `json:"controlName"`
	Severity    string `json:"severity"`
	BaseStatus  string `json:"baseStatus"`
	HeadStatus  string `json:"headStatus"`
}

// ChangeSet groups the diff results into three buckets.
type ChangeSet struct {
	New       []ControlChange `json:"new"`
	Resolved  []ControlChange `json:"resolved"`
	Unchanged []ControlChange `json:"unchanged"`
}

type key struct {
	resourceID string
	controlID  string
}

// Compute loads two scan JSON reports and returns the diff.
func Compute(basePath, headPath string) (*ChangeSet, error) {
	base, err := loadReport(basePath)
	if err != nil {
		return nil, fmt.Errorf("loading base report: %w", err)
	}
	head, err := loadReport(headPath)
	if err != nil {
		return nil, fmt.Errorf("loading head report: %w", err)
	}

	baseMap := buildMap(base)
	headMap := buildMap(head)
	baseSev := buildSeverityMap(base)
	headSev := buildSeverityMap(head)

	cs := &ChangeSet{}

	// walk head: find new and unchanged failures
	for k, hc := range headMap {
		if hc.Status.InnerStatus != string(apis.StatusFailed) {
			continue
		}
		change := ControlChange{
			ResourceID:  k.resourceID,
			ControlID:   k.controlID,
			ControlName: hc.Name,
			Severity:    headSev[k.controlID],
			BaseStatus:  statusAbsent,
			HeadStatus:  hc.Status.InnerStatus,
		}
		if bc, ok := baseMap[k]; ok {
			change.BaseStatus = bc.Status.InnerStatus
		}
		if change.BaseStatus == string(apis.StatusFailed) {
			cs.Unchanged = append(cs.Unchanged, change)
		} else {
			cs.New = append(cs.New, change)
		}
	}

	// walk base: find resolved (was failed, now not failed or absent)
	for k, bc := range baseMap {
		if bc.Status.InnerStatus != string(apis.StatusFailed) {
			continue
		}
		hc, inHead := headMap[k]
		if !inHead || hc.Status.InnerStatus != string(apis.StatusFailed) {
			headStatus := statusAbsent
			if inHead {
				headStatus = hc.Status.InnerStatus
			}
			cs.Resolved = append(cs.Resolved, ControlChange{
				ResourceID:  k.resourceID,
				ControlID:   k.controlID,
				ControlName: bc.Name,
				Severity:    baseSev[k.controlID],
				BaseStatus:  string(apis.StatusFailed),
				HeadStatus:  headStatus,
			})
		}
	}
	// Go randomizes map iteration order per run, so kubescape diff returned the
	// same findings in a different order on every invocation over the same two reports.
	sortChanges(cs.New)
	sortChanges(cs.Resolved)
	sortChanges(cs.Unchanged)

	return cs, nil
}

func sortChanges(changes []ControlChange) {
	sort.Slice(changes, func(i, j int) bool {
		if iRank, jRank := severityRank(changes[i].Severity), severityRank(changes[j].Severity); iRank != jRank {
			return iRank > jRank
		}
		if changes[i].ResourceID != changes[j].ResourceID {
			return changes[i].ResourceID < changes[j].ResourceID
		}
		return changes[i].ControlID < changes[j].ControlID
	})
}

func loadReport(path string) (*scanReport, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("invalid report: expected a JSON object")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if fields == nil {
		return nil, fmt.Errorf("invalid report: expected a JSON object")
	}

	resultsJSON, ok := fields["results"]
	if !ok {
		return nil, fmt.Errorf("invalid report: missing required results field; provide JSON output from kubescape scan")
	}
	if isJSONNull(resultsJSON) {
		return nil, fmt.Errorf("invalid report: results must be an array, not null")
	}

	summaryJSON, ok := fields["summaryDetails"]
	if !ok {
		return nil, fmt.Errorf("invalid report: missing required summaryDetails field; provide JSON output from kubescape scan")
	}
	if isJSONNull(summaryJSON) {
		return nil, fmt.Errorf("invalid report: summaryDetails must be an object, not null")
	}

	var r scanReport
	if err := json.Unmarshal(resultsJSON, &r.Results); err != nil {
		return nil, fmt.Errorf("invalid report results: %w", err)
	}
	if err := validateReport(&r, summaryJSON); err != nil {
		return nil, err
	}
	return &r, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func validateReport(r *scanReport, summaryJSON json.RawMessage) error {
	var summaryFields map[string]json.RawMessage
	if err := json.Unmarshal(summaryJSON, &summaryFields); err != nil {
		return fmt.Errorf("invalid report summaryDetails: %w", err)
	}
	if summaryFields == nil {
		return fmt.Errorf("invalid report: summaryDetails must be an object")
	}
	controlsJSON, ok := summaryFields["controls"]
	if !ok {
		return fmt.Errorf("invalid report: summaryDetails is missing required controls field")
	}
	if isJSONNull(controlsJSON) {
		return fmt.Errorf("invalid report: summaryDetails.controls must be an object, not null")
	}
	var controls map[string]controlSummary
	if err := json.Unmarshal(controlsJSON, &controls); err != nil {
		return fmt.Errorf("invalid report summaryDetails.controls: %w", err)
	}
	r.SummaryDetails.Controls = controls

	seen := make(map[key]struct{})
	for resultIndex, result := range r.Results {
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
		}
	}
	return nil
}

func buildMap(r *scanReport) map[key]controlEntry {
	m := make(map[key]controlEntry)
	for _, res := range r.Results {
		for _, ctrl := range res.AssociatedControls {
			m[key{res.ResourceID, ctrl.ControlID}] = ctrl
		}
	}
	return m
}

func buildSeverityMap(r *scanReport) map[string]string {
	m := make(map[string]string, len(r.SummaryDetails.Controls))
	for id, cs := range r.SummaryDetails.Controls {
		sev := cs.Severity
		if sev == "" {
			sev = apis.ControlSeverityToString(cs.ScoreFactor)
		}
		m[id] = sev
	}
	return m
}

// severityRank maps severity strings to comparable ints (higher = more severe).
func severityRank(s string) int {
	switch strings.ToLower(s) {
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

// FilterBySeverity returns only the changes at or above the given severity threshold string.
// An empty threshold returns all changes unchanged.
func FilterBySeverity(changes []ControlChange, threshold string) []ControlChange {
	if threshold == "" {
		return changes
	}
	min := severityRank(threshold)
	out := changes[:0:0]
	for _, c := range changes {
		if severityRank(c.Severity) >= min {
			out = append(out, c)
		}
	}
	return out
}
