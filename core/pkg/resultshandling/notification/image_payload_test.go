package notification

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleImageScanSummary() *imageprinter.ImageScanSummary {
	dbTime := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	return &imageprinter.ImageScanSummary{
		Images:      []string{"nginx:1.21.0"},
		VulnDBBuilt: &dbTime,
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{
			"Critical":   {NumberOfCVEs: 2, NumberOfFixableCVEs: 1},
			"High":       {NumberOfCVEs: 5, NumberOfFixableCVEs: 3},
			"Medium":     {NumberOfCVEs: 10, NumberOfFixableCVEs: 4},
			"Low":        {NumberOfCVEs: 1, NumberOfFixableCVEs: 0},
			"Negligible": {NumberOfCVEs: 0, NumberOfFixableCVEs: 0},
		},
		CVEs: []imageprinter.CVE{
			{
				ID:          "CVE-2023-0001",
				Severity:    "Critical",
				Package:     "libcrypto",
				Version:     "1.1.1",
				FixedState:  "fixed",
				FixVersions: []string{"1.1.2"},
				Image:       "nginx:1.21.0",
			},
			{
				ID:         "CVE-2023-0002",
				Severity:   "Critical",
				Package:    "glibc",
				Version:    "2.31",
				FixedState: "not-fixed",
				Image:      "nginx:1.21.0",
			},
			{
				ID:          "CVE-2023-0003",
				Severity:    "High",
				Package:     "openssl",
				Version:     "1.1.1",
				FixedState:  "fixed",
				FixVersions: []string{"1.1.2"},
				Image:       "nginx:1.21.0",
			},
		},
	}
}

func TestMarshalImagePayload_NilSummary(t *testing.T) {
	_, err := MarshalImagePayload("https://hooks.slack.com/services/T00/B00/X00", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "summary is nil")
}

func TestMarshalImagePayload_Slack(t *testing.T) {
	summary := sampleImageScanSummary()
	raw, err := MarshalImagePayload("https://hooks.slack.com/services/T00/B00/X00", summary)
	require.NoError(t, err)

	var payload slackPayload
	require.NoError(t, json.Unmarshal(raw, &payload))

	assert.Contains(t, payload.Text, "Kubescape image scan completed for nginx:1.21.0")
	assert.Contains(t, payload.Text, "18 vulnerabilities (2 Critical, 5 High, 8 fixable)")
	require.GreaterOrEqual(t, len(payload.Blocks), 2)
	assert.Equal(t, "header", payload.Blocks[0].Type)
	assert.Equal(t, "Kubescape image scan results", payload.Blocks[0].Text.Text)

	// Section fields
	assert.Equal(t, "section", payload.Blocks[1].Type)
	require.Len(t, payload.Blocks[1].Fields, 2)
	assert.Contains(t, payload.Blocks[1].Fields[0].Text, "nginx:1.21.0")
	assert.Contains(t, payload.Blocks[1].Fields[1].Text, "18 total · 8 fixable")

	// Top vulnerabilities section
	require.Len(t, payload.Blocks, 3)
	assert.Equal(t, "section", payload.Blocks[2].Type)
	assert.Contains(t, payload.Blocks[2].Text.Text, "*Top vulnerabilities*")
	assert.Contains(t, payload.Blocks[2].Text.Text, "CVE-2023-0001")
	assert.Contains(t, payload.Blocks[2].Text.Text, "fixed in 1.1.2")
}

func TestMarshalImagePayload_SlackZeroVulns(t *testing.T) {
	summary := &imageprinter.ImageScanSummary{
		Images: []string{"alpine:latest"},
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{
			"Critical": {NumberOfCVEs: 0},
		},
	}

	raw, err := MarshalImagePayload("https://hooks.slack.com/services/T00/B00/X00", summary)
	require.NoError(t, err)

	var payload slackPayload
	require.NoError(t, json.Unmarshal(raw, &payload))
	assert.Contains(t, payload.Text, "no vulnerabilities found")
	require.Len(t, payload.Blocks, 2) // Header + summary section, no top CVEs
}

func TestMarshalImagePayload_Teams(t *testing.T) {
	summary := sampleImageScanSummary()
	raw, err := MarshalImagePayload("https://outlook.office.com/webhook/test", summary)
	require.NoError(t, err)

	var payload teamsPayload
	require.NoError(t, json.Unmarshal(raw, &payload))

	assert.Equal(t, "message", payload.Type)
	require.Len(t, payload.Attachments, 1)
	card := payload.Attachments[0].Content
	assert.Equal(t, "AdaptiveCard", card.Type)
	require.GreaterOrEqual(t, len(card.Body), 2)

	assert.Equal(t, "TextBlock", card.Body[0].Type)
	assert.Equal(t, "Kubescape image scan results", card.Body[0].Text)

	// Summary FactSet
	assert.Equal(t, "FactSet", card.Body[1].Type)
	facts := card.Body[1].Facts
	foundImage := false
	foundCritical := false
	for _, f := range facts {
		if f.Title == "Image" && f.Value == "nginx:1.21.0" {
			foundImage = true
		}
		if f.Title == "Critical" && f.Value == "2" {
			foundCritical = true
		}
	}
	assert.True(t, foundImage)
	assert.True(t, foundCritical)

	// Top CVEs
	require.Len(t, card.Body, 4) // Title + Facts + Heading + CVE Facts
	assert.Equal(t, "Top vulnerabilities", card.Body[2].Text)
	require.Len(t, card.Body[3].Facts, 3)
	assert.Equal(t, "CVE-2023-0001", card.Body[3].Facts[0].Title)
	assert.Contains(t, card.Body[3].Facts[0].Value, "Critical — libcrypto 1.1.1 (fixed in 1.1.2)")
}

func TestMarshalImagePayload_GenericJSON(t *testing.T) {
	summary := sampleImageScanSummary()
	raw, err := MarshalImagePayload("https://example.com/webhook", summary)
	require.NoError(t, err)

	var payload ImageNotificationSummary
	require.NoError(t, json.Unmarshal(raw, &payload))

	assert.Equal(t, []string{"nginx:1.21.0"}, payload.Images)
	assert.Equal(t, 18, payload.TotalVulnerabilities)
	assert.Equal(t, 8, payload.FixableVulnerabilities)
	assert.Equal(t, 2, payload.SeverityCounts["Critical"])
	assert.Equal(t, 5, payload.SeverityCounts["High"])
	require.Len(t, payload.TopVulnerabilities, 3)
	assert.Equal(t, "CVE-2023-0001", payload.TopVulnerabilities[0].ID)
	assert.NotNil(t, payload.VulnDBBuilt)
}

func TestMarshalImagePayload_CappingTopCVEs(t *testing.T) {
	cves := make([]imageprinter.CVE, 25)
	for i := range cves {
		cves[i] = imageprinter.CVE{
			ID:          fmt.Sprintf("CVE-2024-%04d", i),
			Severity:    "High",
			Package:     "pkg",
			Version:     "1.0",
			FixedState:  "fixed",
			FixVersions: []string{"1.1"},
		}
	}

	summary := &imageprinter.ImageScanSummary{
		Images: []string{"test-img"},
		CVEs:   cves,
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{
			"High": {NumberOfCVEs: 25, NumberOfFixableCVEs: 25},
		},
	}

	raw, err := MarshalImagePayload("https://example.com/webhook", summary)
	require.NoError(t, err)

	var payload ImageNotificationSummary
	require.NoError(t, json.Unmarshal(raw, &payload))
	assert.Len(t, payload.TopVulnerabilities, maxFailingCVEs)
}
