package notification

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeTeamsCard(t *testing.T, payload []byte) teamsAdaptiveCard {
	t.Helper()

	var decoded teamsPayload
	require.NoError(t, json.Unmarshal(payload, &decoded))
	assert.Equal(t, "message", decoded.Type)
	require.Len(t, decoded.Attachments, 1)
	assert.Equal(t, "application/vnd.microsoft.card.adaptive", decoded.Attachments[0].ContentType)
	return decoded.Attachments[0].Content
}

func teamsFactsByBlock(card teamsAdaptiveCard) [][]teamsFact {
	var sets [][]teamsFact
	for _, block := range card.Body {
		if block.Type == "FactSet" {
			sets = append(sets, block.Facts)
		}
	}
	return sets
}

func TestIsTeamsEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"https://contoso.webhook.office.com/webhookb2/guid@guid/IncomingWebhook/id/key",
		"https://CONTOSO.WEBHOOK.OFFICE.COM/webhookb2/guid@guid/IncomingWebhook/id/key",
		"https://outlook.office.com/webhook/guid@guid/IncomingWebhook/id/key",
		"https://outlook.office365.com/webhook/guid@guid/IncomingWebhook/id/key",
	} {
		assert.True(t, IsTeamsEndpoint(endpoint), endpoint)
	}

	for _, endpoint := range []string{
		"http://contoso.webhook.office.com/webhookb2/id",
		"https://user:secret@contoso.webhook.office.com/webhookb2/id",
		"https://contoso.webhook.office.com/webhookb2/id#fragment",
		"https://webhook.office.com.example.com/webhookb2/id",
		"https://example.com/contoso.webhook.office.com",
		"https://prod-12.westus.logic.azure.com/workflows/id/triggers/manual/paths/invoke",
		"https://hooks.slack.com/services/T000/B000/secret",
		"not a URL",
	} {
		assert.False(t, IsTeamsEndpoint(endpoint), endpoint)
	}
}

func TestMarshalPayloadBuildsDeterministicTeamsAdaptiveCard(t *testing.T) {
	summary := &reportsummary.SummaryDetails{
		ComplianceScore: 73.25,
		Controls: reportsummary.ControlSummaries{
			"C-CRITICAL": failedControl("C-CRITICAL", "Critical control", 9.5, 1),
			"C-HIGH-C":   failedControl("C-HIGH-C", "High with most failures", 8, 4),
			"C-HIGH-A":   failedControl("C-HIGH-A", "High alpha", 8, 2),
			"C-LOW":      failedControl("C-LOW", "Low control", 2, 20),
			"C-PASSED":   {ControlID: "C-PASSED", Name: "Passed", Status: apis.StatusPassed},
			"C-SKIPPED":  {ControlID: "C-SKIPPED", Name: "Skipped", Status: apis.StatusSkipped},
		},
	}

	payload, err := MarshalPayload("https://contoso.webhook.office.com/webhookb2/id", summary)
	require.NoError(t, err)

	card := decodeTeamsCard(t, payload)
	assert.Equal(t, "AdaptiveCard", card.Type)
	assert.Equal(t, teamsCardVersion, card.Version)
	require.NotEmpty(t, card.Body)
	assert.Equal(t, "Kubescape scan results", card.Body[0].Text)

	sets := teamsFactsByBlock(card)
	require.Len(t, sets, 2)
	assert.Equal(t, []teamsFact{
		{Title: "Compliance score", Value: "73.2%"},
		{Title: "Controls failed", Value: "4 of 6"},
		{Title: "Passed", Value: "1"},
		{Title: "Skipped", Value: "1"},
	}, sets[0])

	ids := make([]string, 0, len(sets[1]))
	for _, fact := range sets[1] {
		ids = append(ids, fact.Title)
	}
	assert.Equal(t, []string{"C-CRITICAL", "C-HIGH-C", "C-HIGH-A", "C-LOW"}, ids)
	assert.Equal(t, "Critical — Critical control", sets[1][0].Value)
}

func TestMarshalPayloadLimitsTeamsCardToTopTenFailingControls(t *testing.T) {
	controls := reportsummary.ControlSummaries{}
	for i := 0; i < maxFailingControls+5; i++ {
		id := fmt.Sprintf("C-%03d", i)
		controls[id] = failedControl(id, fmt.Sprintf("Control %d", i), 8, i)
	}

	payload, err := MarshalPayload("https://outlook.office.com/webhook/id", &reportsummary.SummaryDetails{Controls: controls})
	require.NoError(t, err)

	sets := teamsFactsByBlock(decodeTeamsCard(t, payload))
	require.Len(t, sets, 2)
	assert.Len(t, sets[1], maxFailingControls)
}

func TestMarshalPayloadBoundsLongTeamsControlText(t *testing.T) {
	longID := strings.Repeat("I", maxTeamsControlIDLength*2)
	longName := strings.Repeat("N", maxTeamsControlNameLength*2)

	payload, err := MarshalPayload("https://contoso.webhook.office.com/webhookb2/id", &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{longID: failedControl(longID, longName, 8, 1)},
	})
	require.NoError(t, err)

	sets := teamsFactsByBlock(decodeTeamsCard(t, payload))
	require.Len(t, sets, 2)
	require.Len(t, sets[1], 1)

	fact := sets[1][0]
	assert.LessOrEqual(t, utf8.RuneCountInString(fact.Title), maxTeamsControlIDLength)
	assert.True(t, strings.HasSuffix(fact.Title, "…"))
	assert.True(t, strings.HasSuffix(fact.Value, "…"))
}

func TestMarshalPayloadTeamsEscapesMarkdownInControlText(t *testing.T) {
	payload, err := MarshalPayload("https://contoso.webhook.office.com/webhookb2/id", &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-0001": failedControl("C-0001", "Uses *bold* and _underscore_ and [link]", 8, 1),
		},
	})
	require.NoError(t, err)

	sets := teamsFactsByBlock(decodeTeamsCard(t, payload))
	require.Len(t, sets, 2)
	assert.Contains(t, sets[1][0].Value, `\*bold\*`)
	assert.Contains(t, sets[1][0].Value, `\_underscore\_`)
	assert.Contains(t, sets[1][0].Value, `\[link\]`)
}

func TestMarshalPayloadTeamsOmitsFailingSectionWhenAllControlsPass(t *testing.T) {
	payload, err := MarshalPayload("https://contoso.webhook.office.com/webhookb2/id", &reportsummary.SummaryDetails{
		ComplianceScore: 100,
		Controls: reportsummary.ControlSummaries{
			"C-0001": {ControlID: "C-0001", Name: "Passed", Status: apis.StatusPassed},
		},
	})
	require.NoError(t, err)

	card := decodeTeamsCard(t, payload)
	assert.Len(t, teamsFactsByBlock(card), 1)
	for _, block := range card.Body {
		assert.NotEqual(t, teamsTopControlsHeading, block.Text)
	}
}

func TestMarshalPayloadTeamsFallsBackForUnknownControlText(t *testing.T) {
	payload, err := MarshalPayload("https://contoso.webhook.office.com/webhookb2/id", &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{"": failedControl("", "", 8, 1)},
	})
	require.NoError(t, err)

	sets := teamsFactsByBlock(decodeTeamsCard(t, payload))
	require.Len(t, sets, 2)
	assert.Equal(t, "unknown", sets[1][0].Title)
	assert.Contains(t, sets[1][0].Value, "Unnamed control")
}

func TestTeamsEscaperLeavesUninterpretedMarkdownAlone(t *testing.T) {
	payload, err := MarshalPayload("https://contoso.webhook.office.com/webhookb2/id", &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-0001": failedControl("C-0001", "Issue #12 ~approx~ `code`", 8, 1),
		},
	})
	require.NoError(t, err)

	sets := teamsFactsByBlock(decodeTeamsCard(t, payload))
	require.Len(t, sets, 2)
	assert.Contains(t, sets[1][0].Value, "Issue #12 ~approx~ `code`")
	assert.NotContains(t, sets[1][0].Value, `\`)
}

func TestMarshalPayloadTeamsTruncatesMultiByteNamesOnRuneBoundaries(t *testing.T) {
	name := strings.Repeat("日本語テスト🔒", 60)

	payload, err := MarshalPayload("https://contoso.webhook.office.com/webhookb2/id", &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{"C-0001": failedControl("C-0001", name, 9, 1)},
	})
	require.NoError(t, err)
	require.True(t, json.Valid(payload))

	sets := teamsFactsByBlock(decodeTeamsCard(t, payload))
	require.Len(t, sets, 2)

	value := sets[1][0].Value
	assert.True(t, utf8.ValidString(value))
	assert.True(t, strings.HasSuffix(value, "…"))
	assert.NotContains(t, value, "�")
	assert.LessOrEqual(t, utf8.RuneCountInString(value), utf8.RuneCountInString("Critical — ")+maxTeamsControlNameLength)
}
