package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling/apis"
)

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
		if hc.Status.InnerStatus != "failed" {
			continue
		}
		change := ControlChange{
			ResourceID:  k.resourceID,
			ControlID:   k.controlID,
			ControlName: hc.Name,
			Severity:    headSev[k.controlID],
			HeadStatus:  hc.Status.InnerStatus,
		}
		if bc, ok := baseMap[k]; ok {
			change.BaseStatus = bc.Status.InnerStatus
		}
		if change.BaseStatus == "failed" {
			cs.Unchanged = append(cs.Unchanged, change)
		} else {
			cs.New = append(cs.New, change)
		}
	}

	// walk base: find resolved (was failed, now not failed or absent)
	for k, bc := range baseMap {
		if bc.Status.InnerStatus != "failed" {
			continue
		}
		hc, inHead := headMap[k]
		if !inHead || hc.Status.InnerStatus != "failed" {
			headStatus := "absent"
			if inHead {
				headStatus = hc.Status.InnerStatus
			}
			cs.Resolved = append(cs.Resolved, ControlChange{
				ResourceID:  k.resourceID,
				ControlID:   k.controlID,
				ControlName: bc.Name,
				Severity:    baseSev[k.controlID],
				BaseStatus:  "failed",
				HeadStatus:  headStatus,
			})
		}
	}

	return cs, nil
}

func loadReport(path string) (*scanReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var r scanReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return &r, nil
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
