package notification

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
)

const (
	maxFailingCVEs          = 10
	maxSlackImageNameLength = 200
	maxSlackCVEIDLength     = 40
	maxSlackCVEPkgLength    = 80
	slackTopCVEsHeading     = "*Top vulnerabilities*"
	teamsTopCVEsHeading     = "Top vulnerabilities"
)

// ImageNotificationSummary represents the generic JSON webhook payload for image scans.
type ImageNotificationSummary struct {
	Images                 []string                         `json:"images"`
	TotalVulnerabilities   int                              `json:"totalVulnerabilities"`
	FixableVulnerabilities int                              `json:"fixableVulnerabilities"`
	SeverityCounts         map[string]int                   `json:"severityCounts"`
	TopVulnerabilities     []ImageNotificationVulnerability `json:"topVulnerabilities,omitempty"`
	VulnDBBuilt            *time.Time                       `json:"vulnDBBuilt,omitempty"`
}

// ImageNotificationVulnerability represents a vulnerability entry in generic webhook summaries.
type ImageNotificationVulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Package     string   `json:"package"`
	Version     string   `json:"version,omitempty"`
	FixVersions []string `json:"fixVersions,omitempty"`
	FixedState  string   `json:"fixedState,omitempty"`
	Image       string   `json:"image,omitempty"`
}

// MarshalImagePayload formats image scan summary for endpoint. Slack incoming webhooks
// receive a compact Block Kit message, Microsoft Teams webhooks an Adaptive Card, and
// every other endpoint a generic JSON image scan summary.
func MarshalImagePayload(endpoint string, summary *imageprinter.ImageScanSummary) ([]byte, error) {
	if summary == nil {
		return nil, fmt.Errorf("marshal image notification payload: summary is nil")
	}
	switch {
	case IsSlackEndpoint(endpoint):
		return json.Marshal(newImageSlackPayload(summary))
	case IsTeamsEndpoint(endpoint):
		return json.Marshal(newImageTeamsPayload(summary))
	default:
		return json.Marshal(newImageGenericPayload(summary))
	}
}

type imageStats struct {
	total      int
	fixable    int
	bySeverity map[string]int
	topFailing []imageprinter.CVE
	imagesStr  string
}

func summarizeImageScan(summary *imageprinter.ImageScanSummary) imageStats {
	stats := imageStats{
		bySeverity: make(map[string]int),
	}

	for sev, sevSummary := range summary.MapsSeverityToSummary {
		if sevSummary != nil {
			stats.total += sevSummary.NumberOfCVEs
			stats.fixable += sevSummary.NumberOfFixableCVEs
			stats.bySeverity[sev] += sevSummary.NumberOfCVEs
		}
	}

	stats.topFailing = sortAndFilterTopCVEs(summary.CVEs, maxFailingCVEs)

	if len(summary.Images) > 0 {
		stats.imagesStr = strings.Join(summary.Images, ", ")
	} else {
		stats.imagesStr = "unknown image"
	}

	return stats
}

func sortAndFilterTopCVEs(cves []imageprinter.CVE, maxCount int) []imageprinter.CVE {
	sorted := make([]imageprinter.CVE, len(cves))
	copy(sorted, cves)

	sort.SliceStable(sorted, func(i, j int) bool {
		wi := cveSeverityWeight(sorted[i].Severity)
		wj := cveSeverityWeight(sorted[j].Severity)
		if wi != wj {
			return wi > wj
		}
		fixI := isCVEFixable(sorted[i])
		fixJ := isCVEFixable(sorted[j])
		if fixI != fixJ {
			return fixI
		}
		if sorted[i].ID != sorted[j].ID {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].Package < sorted[j].Package
	})

	if len(sorted) > maxCount {
		sorted = sorted[:maxCount]
	}
	return sorted
}

func cveSeverityWeight(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "negligible":
		return 1
	default:
		return 0
	}
}

func isCVEFixable(cve imageprinter.CVE) bool {
	return strings.EqualFold(cve.FixedState, "fixed") || len(cve.FixVersions) > 0
}

func newImageSlackPayload(summary *imageprinter.ImageScanSummary) slackPayload {
	stats := summarizeImageScan(summary)

	criticalCount := stats.bySeverity["Critical"]
	highCount := stats.bySeverity["High"]

	var fallback string
	if stats.total == 0 {
		fallback = fmt.Sprintf("Kubescape image scan completed for %s: no vulnerabilities found.", stats.imagesStr)
	} else {
		fallback = fmt.Sprintf(
			"Kubescape image scan completed for %s: %d vulnerabilities (%d Critical, %d High, %d fixable).",
			stats.imagesStr,
			stats.total,
			criticalCount,
			highCount,
			stats.fixable,
		)
	}

	mediumCount := stats.bySeverity["Medium"]
	vulnField := fmt.Sprintf(
		"*Vulnerabilities*\n%d total · %d fixable\n%d Critical · %d High · %d Medium",
		stats.total,
		stats.fixable,
		criticalCount,
		highCount,
		mediumCount,
	)

	payload := slackPayload{
		Text: fallback,
		Blocks: []slackBlock{
			{
				Type: "header",
				Text: &slackText{Type: "plain_text", Text: "Kubescape image scan results"},
			},
			{
				Type: "section",
				Fields: []slackText{
					{Type: "mrkdwn", Text: fmt.Sprintf("*Image*\n%s", escapeAndTruncateSlackText(stats.imagesStr, maxSlackImageNameLength)), Verbatim: true},
					{Type: "mrkdwn", Text: vulnField, Verbatim: true},
				},
			},
		},
	}

	if len(stats.topFailing) > 0 {
		lines := make([]string, 0, len(stats.topFailing)+1)
		lines = append(lines, slackTopCVEsHeading)
		for _, cve := range stats.topFailing {
			lines = append(lines, slackCVELine(cve))
		}
		payload.Blocks = append(payload.Blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: strings.Join(lines, "\n"), Verbatim: true},
		})
	}

	return payload
}

func slackCVELine(cve imageprinter.CVE) string {
	sev := cve.Severity
	if sev == "" {
		sev = "Unknown"
	}
	id := cve.ID
	if id == "" {
		id = "Unknown"
	}
	pkg := cve.Package
	if cve.Version != "" {
		pkg = fmt.Sprintf("%s %s", pkg, cve.Version)
	}

	fixInfo := ""
	if len(cve.FixVersions) > 0 {
		fixInfo = fmt.Sprintf(" — fixed in %s", strings.Join(cve.FixVersions, ", "))
	} else if strings.EqualFold(cve.FixedState, "fixed") {
		fixInfo = " — fix available"
	}

	renderedID := escapeAndTruncateSlackText(id, maxSlackCVEIDLength)
	renderedPkg := escapeAndTruncateSlackText(pkg, maxSlackCVEPkgLength)
	renderedFix := escapeAndTruncateSlackText(fixInfo, 60)

	return fmt.Sprintf("• *%s* · `%s` (%s)%s",
		escapeAndTruncateSlackText(sev, 20),
		renderedID,
		renderedPkg,
		renderedFix,
	)
}

func newImageTeamsPayload(summary *imageprinter.ImageScanSummary) teamsPayload {
	stats := summarizeImageScan(summary)

	facts := []teamsFact{
		{Title: "Image", Value: escapeAndTruncateTeamsText(stats.imagesStr, maxTeamsControlNameLength)},
		{Title: "Total vulnerabilities", Value: fmt.Sprintf("%d", stats.total)},
		{Title: "Fixable", Value: fmt.Sprintf("%d", stats.fixable)},
		{Title: "Critical", Value: fmt.Sprintf("%d", stats.bySeverity["Critical"])},
		{Title: "High", Value: fmt.Sprintf("%d", stats.bySeverity["High"])},
		{Title: "Medium", Value: fmt.Sprintf("%d", stats.bySeverity["Medium"])},
	}
	if low := stats.bySeverity["Low"]; low > 0 {
		facts = append(facts, teamsFact{Title: "Low", Value: fmt.Sprintf("%d", low)})
	}

	body := []teamsCardBlock{
		{
			Type:   "TextBlock",
			Text:   "Kubescape image scan results",
			Size:   "Large",
			Weight: "Bolder",
			Wrap:   true,
		},
		{
			Type:  "FactSet",
			Facts: facts,
		},
	}

	if len(stats.topFailing) > 0 {
		cveFacts := make([]teamsFact, 0, len(stats.topFailing))
		for _, cve := range stats.topFailing {
			cveFacts = append(cveFacts, teamsCVEFact(cve))
		}
		body = append(body,
			teamsCardBlock{
				Type:   "TextBlock",
				Text:   teamsTopCVEsHeading,
				Weight: "Bolder",
				Wrap:   true,
			},
			teamsCardBlock{Type: "FactSet", Facts: cveFacts},
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

func teamsCVEFact(cve imageprinter.CVE) teamsFact {
	id := cve.ID
	if id == "" {
		id = "Unknown"
	}
	sev := cve.Severity
	if sev == "" {
		sev = "Unknown"
	}
	pkg := cve.Package
	if cve.Version != "" {
		pkg = fmt.Sprintf("%s %s", pkg, cve.Version)
	}
	fix := ""
	if len(cve.FixVersions) > 0 {
		fix = fmt.Sprintf(" (fixed in %s)", strings.Join(cve.FixVersions, ", "))
	}

	return teamsFact{
		Title: escapeAndTruncateTeamsText(id, maxTeamsControlIDLength),
		Value: escapeAndTruncateTeamsText(fmt.Sprintf("%s — %s%s", sev, pkg, fix), maxTeamsControlNameLength),
	}
}

func newImageGenericPayload(summary *imageprinter.ImageScanSummary) ImageNotificationSummary {
	stats := summarizeImageScan(summary)

	topVulns := make([]ImageNotificationVulnerability, 0, len(stats.topFailing))
	for _, cve := range stats.topFailing {
		topVulns = append(topVulns, ImageNotificationVulnerability{
			ID:          cve.ID,
			Severity:    cve.Severity,
			Package:     cve.Package,
			Version:     cve.Version,
			FixVersions: cve.FixVersions,
			FixedState:  cve.FixedState,
			Image:       cve.Image,
		})
	}

	return ImageNotificationSummary{
		Images:                 summary.Images,
		TotalVulnerabilities:   stats.total,
		FixableVulnerabilities: stats.fixable,
		SeverityCounts:         stats.bySeverity,
		TopVulnerabilities:     topVulns,
		VulnDBBuilt:            summary.VulnDBBuilt,
	}
}
