package attackpath

import (
	"encoding/json"
	"fmt"
	"io"
)

// sarifLog is the minimal SARIF 2.1.0 document shape needed to represent
// attack paths. It follows the same structure as the existing
// core/pkg/resultshandling/printer/v2/sarifprinter.go.
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
	// Locations is intentionally minimal: attack paths are graph-level
	// findings, not tied to a single source file line.
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifRuleID  = "ATTACK-PATH"
)

// scoreToSARIFLevel maps an attack-path score to a SARIF level,
// mirroring the existing scoreFactorToSARIFSeverityLevel pattern.
func scoreToSARIFLevel(score float64) string {
	switch {
	case score >= 8.0:
		return "error"
	case score >= 5.0:
		return "warning"
	default:
		return "note"
	}
}

// printSARIF writes a SARIF 2.1.0 document representing the SearchResult
// to w. Each AttackPath becomes one SARIF result under the rule
// "ATTACK-PATH".
func printSARIF(w io.Writer, result SearchResult, warnings []string) error {
	rule := sarifRule{
		ID:   sarifRuleID,
		Name: "AttackPath",
		ShortDescription: sarifMessage{
			Text: "An end-to-end attack path from Internet to cluster-admin was found.",
		},
	}

	var results []sarifResult

	for i, p := range result.Paths {
		certainLabel := "certain"
		if !p.Certain {
			certainLabel = "uncertain"
		}
		msg := fmt.Sprintf(
			"PATH #%d (score %.1f, %s): %s",
			i+1, p.Score, certainLabel, summarisePath(p),
		)
		if p.CVESeverity != "" {
			msg += fmt.Sprintf("; CVE severity on path: %s", p.CVESeverity)
		}

		results = append(results, sarifResult{
			RuleID:  sarifRuleID,
			Level:   scoreToSARIFLevel(p.Score),
			Message: sarifMessage{Text: msg},
		})
	}

	// Truncation and uncertain edges as informational results.
	if result.Truncated {
		results = append(results, sarifResult{
			RuleID: sarifRuleID,
			Level:  "note",
			Message: sarifMessage{
				Text: "Result is truncated — more paths may exist beyond the cap.",
			},
		})
	}
	for _, w2 := range warnings {
		results = append(results, sarifResult{
			RuleID:  sarifRuleID,
			Level:   "note",
			Message: sarifMessage{Text: "WARN: " + w2},
		})
	}

	log := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "kubescape",
						InformationURI: "https://github.com/kubescape/kubescape",
						Rules:          []sarifRule{rule},
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// summarisePath builds a one-line human-readable path summary for SARIF.
func summarisePath(p AttackPath) string {
	var parts []string
	for _, n := range p.Nodes {
		parts = append(parts, fmt.Sprintf("[%s]%s", n.Kind, labelOf(n)))
	}
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += " → "
		}
		out += part
	}
	return out
}
