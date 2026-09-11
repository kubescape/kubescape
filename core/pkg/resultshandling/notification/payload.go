package notification

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	maxFailingControls          = 10
	maxSlackSectionTextLength   = 3000
	maxSlackControlIDTextLength = 80
	slackTopControlsHeading     = "*Top failing controls*"

	maxTeamsControlIDLength   = 80
	maxTeamsControlNameLength = 160
	teamsCardVersion          = "1.4"
	teamsTopControlsHeading   = "Top failing controls"
)

var slackTextEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

type slackPayload struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type   string      `json:"type"`
	Text   *slackText  `json:"text,omitempty"`
	Fields []slackText `json:"fields,omitempty"`
}

type slackText struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	Verbatim bool   `json:"verbatim,omitempty"`
}

// IsSlackEndpoint reports whether endpoint is an official Slack or GovSlack
// incoming webhook URL. Matching the exact hostname avoids treating lookalike
// domains as Slack destinations.
func IsSlackEndpoint(endpoint string) bool {
	u, err := validateEndpoint(endpoint)
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "hooks.slack.com", "hooks.slack-gov.com":
		return true
	default:
		return false
	}
}

// MarshalPayload formats summary for endpoint. Slack incoming webhooks receive
// a compact Block Kit message, Microsoft Teams webhooks an Adaptive Card, and
// every other endpoint the existing generic SummaryDetails JSON object.
func MarshalPayload(endpoint string, summary *reportsummary.SummaryDetails) ([]byte, error) {
	if summary == nil {
		return nil, fmt.Errorf("marshal notification payload: summary is nil")
	}
	switch {
	case IsSlackEndpoint(endpoint):
		return json.Marshal(newSlackPayload(summary))
	case IsTeamsEndpoint(endpoint):
		return json.Marshal(newTeamsPayload(summary))
	default:
		return json.Marshal(summary)
	}
}

func newSlackPayload(summary *reportsummary.SummaryDetails) slackPayload {
	controls := summarizeControls(summary.Controls)
	fallback := fmt.Sprintf(
		"Kubescape scan completed: %.1f%% compliance; %d of %d controls failed.",
		summary.ComplianceScore,
		controls.failed,
		controls.total,
	)

	payload := slackPayload{
		Text: fallback,
		Blocks: []slackBlock{
			{
				Type: "header",
				Text: &slackText{Type: "plain_text", Text: "Kubescape scan results"},
			},
			{
				Type: "section",
				Fields: []slackText{
					{Type: "mrkdwn", Text: fmt.Sprintf("*Controls*\n%d failed / %d total\n%d passed · %d skipped", controls.failed, controls.total, controls.passed, controls.skipped), Verbatim: true},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Compliance score*\n%.1f%%", summary.ComplianceScore), Verbatim: true},
				},
			},
		},
	}
	if len(controls.topFailing) > 0 {
		lines := make([]string, 0, len(controls.topFailing)+1)
		lines = append(lines, slackTopControlsHeading)
		for _, control := range controls.topFailing {
			lines = append(lines, slackControlLine(control))
		}
		payload.Blocks = append(payload.Blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: strings.Join(lines, "\n"), Verbatim: true},
		})
	}
	return payload
}

type controlSummary struct {
	total      int
	failed     int
	passed     int
	skipped    int
	topFailing []reportsummary.ControlSummary
}

func summarizeControls(controls reportsummary.ControlSummaries) controlSummary {
	result := controlSummary{total: len(controls)}
	for key, control := range controls {
		if control.ControlID == "" {
			control.ControlID = key
		}
		switch control.GetStatus().Status() {
		case apis.StatusFailed:
			result.failed++
			result.topFailing = append(result.topFailing, control)
		case apis.StatusPassed:
			result.passed++
		case apis.StatusSkipped:
			result.skipped++
		}
	}
	sort.Slice(result.topFailing, func(i, j int) bool {
		left, right := result.topFailing[i], result.topFailing[j]
		leftSeverity := apis.ControlSeverityToInt(left.ScoreFactor)
		rightSeverity := apis.ControlSeverityToInt(right.ScoreFactor)
		if leftSeverity != rightSeverity {
			return leftSeverity > rightSeverity
		}
		if left.StatusCounters.FailedResources != right.StatusCounters.FailedResources {
			return left.StatusCounters.FailedResources > right.StatusCounters.FailedResources
		}
		if left.ControlID != right.ControlID {
			return left.ControlID < right.ControlID
		}
		return left.Name < right.Name
	})
	if len(result.topFailing) > maxFailingControls {
		result.topFailing = result.topFailing[:maxFailingControls]
	}
	return result
}

func escapeSlackText(value string) string {
	return slackTextEscaper.Replace(value)
}

func slackControlLine(control reportsummary.ControlSummary) string {
	id := control.ControlID
	if id == "" {
		id = "unknown"
	}
	name := control.Name
	if name == "" {
		name = "Unnamed control"
	}

	severity := escapeSlackText(apis.ControlSeverityToString(control.ScoreFactor))
	prefix := fmt.Sprintf("• *%s* · `", severity)
	separator := "` — "
	lineLength := maxSlackControlLineLength()
	idBudget := min(maxSlackControlIDTextLength, lineLength-utf8.RuneCountInString(prefix+separator)-1)
	renderedID := escapeAndTruncateSlackText(id, idBudget)
	nameBudget := lineLength - utf8.RuneCountInString(prefix+renderedID+separator)
	renderedName := escapeAndTruncateSlackText(name, nameBudget)
	return prefix + renderedID + separator + renderedName
}

func maxSlackControlLineLength() int {
	// Reserve one newline for each possible entry. Bounding every line to the
	// remaining equal share guarantees the complete section stays within Slack's
	// 3,000-character section text limit even when all ten entries are present.
	return (maxSlackSectionTextLength - utf8.RuneCountInString(slackTopControlsHeading) - maxFailingControls) / maxFailingControls
}

func escapeAndTruncateSlackText(value string, maxLength int) string {
	return escapeAndTruncate(slackTextEscaper, value, maxLength)
}

func escapeAndTruncate(escaper *strings.Replacer, value string, maxLength int) string {
	if maxLength <= 0 {
		return ""
	}
	escaped := escaper.Replace(value)
	if utf8.RuneCountInString(escaped) <= maxLength {
		return escaped
	}
	if maxLength == 1 {
		return "…"
	}

	var result strings.Builder
	used := 0
	for _, r := range value {
		piece := escaper.Replace(string(r))
		pieceLength := utf8.RuneCountInString(piece)
		if used+pieceLength > maxLength-1 {
			break
		}
		result.WriteString(piece)
		used += pieceLength
	}
	result.WriteRune('…')
	return result.String()
}
