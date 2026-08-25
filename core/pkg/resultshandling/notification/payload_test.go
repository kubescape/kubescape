package notification

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSlackEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"https://hooks.slack.com/services/T000/B000/secret",
		"https://hooks.slack-gov.com/services/T000/B000/secret",
		"https://HOOKS.SLACK.COM/services/T000/B000/secret",
	} {
		assert.True(t, IsSlackEndpoint(endpoint), endpoint)
	}

	for _, endpoint := range []string{
		"http://hooks.slack.com/services/T000/B000/secret",
		"https://user:secret@hooks.slack.com/services/T000/B000/secret",
		"https://hooks.slack.com/services/T000/B000/secret#fragment",
		"https://hooks.slack.com.example.com/services/T000/B000/secret",
		"https://example.com/hooks.slack.com",
		"not a URL",
	} {
		assert.False(t, IsSlackEndpoint(endpoint), endpoint)
	}
}

func TestMarshalPayloadKeepsGenericSummaryJSON(t *testing.T) {
	summary := &reportsummary.SummaryDetails{
		ComplianceScore: 82.5,
		Controls: reportsummary.ControlSummaries{
			"C-0001": {ControlID: "C-0001", Name: "Generic webhook control"},
		},
	}

	got, err := MarshalPayload("https://example.com/webhook", summary)
	require.NoError(t, err)
	want, err := json.Marshal(summary)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(got))
}

func TestMarshalPayloadBuildsDeterministicSlackBlockKit(t *testing.T) {
	summary := &reportsummary.SummaryDetails{
		ComplianceScore: 73.25,
		Controls: reportsummary.ControlSummaries{
			"C-CRITICAL": failedControl("C-CRITICAL", "Critical <control>", 9.5, 1),
			"C-HIGH-C":   failedControl("C-HIGH-C", "High with most failures", 8, 4),
			"C-HIGH-B":   failedControl("C-HIGH-B", "High & beta", 8, 2),
			"C-HIGH-A":   failedControl("C-HIGH-A", "High alpha", 7, 2),
			"C-MEDIUM":   failedControl("C-MEDIUM", "Medium", 5, 10),
			"C-LOW":      failedControl("C-LOW", "Low control", 2, 20),
			"C-UNKNOWN":  failedControl("C-UNKNOWN", "Unknown control", 0, 30),
			"C-PASSED": {
				ControlID: "C-PASSED",
				Name:      "Passed",
				Status:    apis.StatusPassed,
			},
			"C-SKIPPED": {
				ControlID: "C-SKIPPED",
				Name:      "Skipped",
				Status:    apis.StatusSkipped,
			},
		},
	}

	raw, err := MarshalPayload("https://hooks.slack.com/services/T000/B000/secret", summary)
	require.NoError(t, err)

	var got slackPayload
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "Kubescape scan completed: 73.2% compliance; 7 of 9 controls failed.", got.Text)
	require.Len(t, got.Blocks, 3)
	assert.Equal(t, slackBlock{
		Type: "header",
		Text: &slackText{Type: "plain_text", Text: "Kubescape scan results"},
	}, got.Blocks[0])
	assert.Equal(t, []slackText{
		{Type: "mrkdwn", Text: "*Controls*\n7 failed / 9 total\n1 passed · 1 skipped"},
		{Type: "mrkdwn", Text: "*Compliance score*\n73.2%"},
	}, got.Blocks[1].Fields)
	require.NotNil(t, got.Blocks[2].Text)
	assert.Equal(t, "mrkdwn", got.Blocks[2].Text.Type)
	assert.Equal(t, "*Top failing controls*\n"+
		"• *Critical* · `C-CRITICAL` — Critical &lt;control&gt;\n"+
		"• *High* · `C-HIGH-C` — High with most failures\n"+
		"• *High* · `C-HIGH-A` — High alpha\n"+
		"• *High* · `C-HIGH-B` — High &amp; beta\n"+
		"• *Medium* · `C-MEDIUM` — Medium\n"+
		"• *Low* · `C-LOW` — Low control\n"+
		"• *Unknown* · `C-UNKNOWN` — Unknown control", got.Blocks[2].Text.Text)
}

func TestMarshalPayloadLimitsSlackMessageToTopTenFailingControls(t *testing.T) {
	controls := make(reportsummary.ControlSummaries, maxSlackFailingControls+1)
	for i := 0; i <= maxSlackFailingControls; i++ {
		id := fmt.Sprintf("C-%02d", i)
		controls[id] = failedControl(id, "Failed control", 7, 1)
	}

	raw, err := MarshalPayload("https://hooks.slack.com/services/T000/B000/secret", &reportsummary.SummaryDetails{Controls: controls})
	require.NoError(t, err)
	var got slackPayload
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Len(t, got.Blocks, 3)
	require.NotNil(t, got.Blocks[2].Text)
	assert.Equal(t, maxSlackFailingControls, strings.Count(got.Blocks[2].Text.Text, "\n• "))
	assert.Contains(t, got.Blocks[2].Text.Text, "C-09")
	assert.NotContains(t, got.Blocks[2].Text.Text, "C-10")
}

func TestMarshalPayloadSlackOmitsFailingSectionWhenAllControlsPass(t *testing.T) {
	summary := &reportsummary.SummaryDetails{
		ComplianceScore: 100,
		Controls: reportsummary.ControlSummaries{
			"C-0001": {ControlID: "C-0001", Status: apis.StatusPassed},
		},
	}

	raw, err := MarshalPayload("https://hooks.slack-gov.com/services/T000/B000/secret", summary)
	require.NoError(t, err)
	var got slackPayload
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Len(t, got.Blocks, 2)
	assert.Contains(t, got.Text, "0 of 1 controls failed")
}

func TestMarshalPayloadRejectsNilSummary(t *testing.T) {
	_, err := MarshalPayload("https://example.com/webhook", nil)
	require.EqualError(t, err, "marshal notification payload: summary is nil")
}

func failedControl(id, name string, score float32, failedResources int) reportsummary.ControlSummary {
	return reportsummary.ControlSummary{
		ControlID:   id,
		Name:        name,
		Status:      apis.StatusFailed,
		ScoreFactor: score,
		StatusCounters: reportsummary.StatusCounters{
			FailedResources: failedResources,
		},
	}
}
