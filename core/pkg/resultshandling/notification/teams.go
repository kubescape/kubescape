package notification

import (
	"fmt"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

var teamsTextEscaper = strings.NewReplacer(
	"\\", "\\\\",
	"*", "\\*",
	"_", "\\_",
	"[", "\\[",
	"]", "\\]",
)

type teamsPayload struct {
	Type        string            `json:"type"`
	Attachments []teamsAttachment `json:"attachments"`
}

type teamsAttachment struct {
	ContentType string            `json:"contentType"`
	ContentURL  *string           `json:"contentUrl"`
	Content     teamsAdaptiveCard `json:"content"`
}

type teamsAdaptiveCard struct {
	Schema  string           `json:"$schema"`
	Type    string           `json:"type"`
	Version string           `json:"version"`
	Body    []teamsCardBlock `json:"body"`
}

type teamsCardBlock struct {
	Type   string      `json:"type"`
	Text   string      `json:"text,omitempty"`
	Size   string      `json:"size,omitempty"`
	Weight string      `json:"weight,omitempty"`
	Wrap   bool        `json:"wrap,omitempty"`
	Facts  []teamsFact `json:"facts,omitempty"`
}

type teamsFact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

// IsTeamsEndpoint reports whether endpoint is a Microsoft Teams incoming
// webhook URL. Only the documented Teams connector hosts are matched, so a
// Power Automate workflow URL on a shared Azure domain falls through to the
// generic JSON payload rather than being guessed at.
func IsTeamsEndpoint(endpoint string) bool {
	u, err := validateEndpoint(endpoint)
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "outlook.office.com", "outlook.office365.com":
		return true
	}
	return strings.HasSuffix(host, ".webhook.office.com")
}

func newTeamsPayload(summary *reportsummary.SummaryDetails) teamsPayload {
	controls := summarizeControls(summary.Controls)

	body := []teamsCardBlock{
		{
			Type:   "TextBlock",
			Text:   "Kubescape scan results",
			Size:   "Large",
			Weight: "Bolder",
			Wrap:   true,
		},
		{
			Type: "FactSet",
			Facts: []teamsFact{
				{Title: "Compliance score", Value: fmt.Sprintf("%.1f%%", summary.ComplianceScore)},
				{Title: "Controls failed", Value: fmt.Sprintf("%d of %d", controls.failed, controls.total)},
				{Title: "Passed", Value: fmt.Sprintf("%d", controls.passed)},
				{Title: "Skipped", Value: fmt.Sprintf("%d", controls.skipped)},
			},
		},
	}

	if len(controls.topFailing) > 0 {
		facts := make([]teamsFact, 0, len(controls.topFailing))
		for _, control := range controls.topFailing {
			facts = append(facts, teamsControlFact(control))
		}
		body = append(body,
			teamsCardBlock{
				Type:   "TextBlock",
				Text:   teamsTopControlsHeading,
				Weight: "Bolder",
				Wrap:   true,
			},
			teamsCardBlock{Type: "FactSet", Facts: facts},
		)
	}

	return teamsPayload{
		Type: "message",
		Attachments: []teamsAttachment{{
			ContentType: "application/vnd.microsoft.card.adaptive",
			Content: teamsAdaptiveCard{
				Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
				Type:    "AdaptiveCard",
				Version: teamsCardVersion,
				Body:    body,
			},
		}},
	}
}

func teamsControlFact(control reportsummary.ControlSummary) teamsFact {
	id := control.ControlID
	if id == "" {
		id = "unknown"
	}
	name := control.Name
	if name == "" {
		name = "Unnamed control"
	}

	severity := teamsTextEscaper.Replace(apis.ControlSeverityToString(control.ScoreFactor))
	return teamsFact{
		Title: escapeAndTruncateTeamsText(id, maxTeamsControlIDLength),
		Value: fmt.Sprintf("%s — %s", severity, escapeAndTruncateTeamsText(name, maxTeamsControlNameLength)),
	}
}

func escapeAndTruncateTeamsText(value string, maxLength int) string {
	return escapeAndTruncate(teamsTextEscaper, value, maxLength)
}
