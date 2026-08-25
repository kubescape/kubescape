package notification

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const maxSlackFailingControls = 10

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
	Type string `json:"type"`
	Text string `json:"text"`
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
// a compact Block Kit message; every other endpoint receives the existing
// generic SummaryDetails JSON object.
func MarshalPayload(endpoint string, summary *reportsummary.SummaryDetails) ([]byte, error) {
	if summary == nil {
		return nil, fmt.Errorf("marshal notification payload: summary is nil")
	}
	if IsSlackEndpoint(endpoint) {
		return json.Marshal(newSlackPayload(summary))
	}
	return json.Marshal(summary)
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
					{Type: "mrkdwn", Text: fmt.Sprintf("*Controls*\n%d failed / %d total\n%d passed · %d skipped", controls.failed, controls.total, controls.passed, controls.skipped)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Compliance score*\n%.1f%%", summary.ComplianceScore)},
				},
			},
		},
	}
	if len(controls.topFailing) > 0 {
		lines := make([]string, 0, len(controls.topFailing)+1)
		lines = append(lines, "*Top failing controls*")
		for _, control := range controls.topFailing {
			id := control.ControlID
			if id == "" {
				id = "unknown"
			}
			name := control.Name
			if name == "" {
				name = "Unnamed control"
			}
			lines = append(lines, fmt.Sprintf(
				"• *%s* · `%s` — %s",
				escapeSlackText(apis.ControlSeverityToString(control.ScoreFactor)),
				escapeSlackText(id),
				escapeSlackText(name),
			))
		}
		payload.Blocks = append(payload.Blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: strings.Join(lines, "\n")},
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
	if len(result.topFailing) > maxSlackFailingControls {
		result.topFailing = result.topFailing[:maxSlackFailingControls]
	}
	return result
}

func escapeSlackText(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(value)
}
