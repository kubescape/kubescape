package imagescan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUntriagedSeverityRemainsUnknown(t *testing.T) {
	for _, input := range []string{
		"Untriaged", "UNTRIAGED", "untriaged", "Unassigned", "UNASSIGNED", "unassigned",
	} {
		t.Run(input, func(t *testing.T) {
			require.Equal(t, "Unknown", NormalizeSeverity(input))
			require.Equal(t, "Unknown", normalizeQuaySeverity(input))
		})
	}
}

func TestUntriagedSeverityDoesNotChangeAssessedLabels(t *testing.T) {
	for _, tc := range []struct {
		input, want string
	}{
		{"Critical", "Critical"}, {"CRITICAL", "Critical"},
		{"high", "High"}, {"Important", "High"},
		{"medium", "Medium"}, {"Moderate", "Medium"},
		{"low", "Low"}, {"minimal", "Negligible"},
		{"informational", "Negligible"}, {"negligible", "Negligible"},
		{"none", "Negligible"}, {"unknown", "Unknown"},
		{"", "Unknown"}, {"unrecognized", "Unknown"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			require.Equal(t, tc.want, NormalizeSeverity(tc.input))
			require.Equal(t, tc.want, normalizeQuaySeverity(tc.input))
		})
	}
	require.Equal(t, "Critical", normalizeQuaySeverity("Defcon1"))
}

func untriagedQuayReport(t *testing.T, labels ...string) []byte {
	t.Helper()
	var features []any
	for i, label := range labels {
		features = append(features, map[string]any{
			"Name": "package-" + strings.Repeat("x", i+1), "Version": "1.0",
			"Vulnerabilities": []any{map[string]any{
				"Name": "CVE-2026-1000", "Severity": label,
				"Description": "Unassessed advisory", "Link": "https://example.invalid/advisory",
			}},
		})
	}
	raw, err := json.Marshal(map[string]any{
		"status": "scanned", "data": map[string]any{
			"Layer": map[string]any{"Features": features},
		},
	})
	require.NoError(t, err)
	return raw
}

func TestUntriagedSeverityFromQuayAPI(t *testing.T) {
	for _, label := range []string{"Untriaged", "Unassigned", " untriaged ", "\tUNASSIGNED\n"} {
		t.Run(label, func(t *testing.T) {
			mock := newMockQuayAPI()
			mock.responses[quayManifestSecurityPath("team", "app", "sha256:fixture", true)] = untriagedQuayReport(t, label)
			adaptor := NewQuayAdaptor()
			adaptor.client = mock
			images := []ContainerImageIdentifier{{Registry: "quay.io", Repository: "team/app", Hash: "sha256:fixture"}}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
			require.NoError(t, err)
			require.Len(t, reports, 1)
			require.Equal(t, images[0], reports[0].ImageID)
			require.Equal(t, ScanStatusScanned, reports[0].Status)
			require.Len(t, reports[0].Vulnerabilities, 1)
			finding := reports[0].Vulnerabilities[0]
			require.Equal(t, "CVE-2026-1000", finding.ID)
			require.Equal(t, "Unknown", finding.Severity)
			require.Equal(t, "Unassessed advisory", finding.Description)
			require.Equal(t, []string{"https://example.invalid/advisory"}, finding.Links)
		})
	}
}

func TestUntriagedSeverityAcrossDuplicateUnknownOccurrences(t *testing.T) {
	for _, labels := range [][]string{
		{"Untriaged", "Unassigned"}, {"Unassigned", "Untriaged"},
		{"Unknown", "Untriaged"}, {"Untriaged", "Unknown"},
	} {
		t.Run(strings.Join(labels, "/"), func(t *testing.T) {
			mock := newMockQuayAPI()
			mock.responses[quayManifestSecurityPath("team", "app", "sha256:fixture", true)] = untriagedQuayReport(t, labels...)
			adaptor := NewQuayAdaptor()
			adaptor.client = mock
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
				{Registry: "quay.io", Repository: "team/app", Hash: "sha256:fixture"},
			})
			require.NoError(t, err)
			require.Len(t, reports[0].Vulnerabilities, 1)
			require.Equal(t, "Unknown", reports[0].Vulnerabilities[0].Severity)
			require.Contains(t, reports[0].Vulnerabilities[0].Description, "package-xx")
		})
	}
}

func TestUntriagedSeverityRetainsAssessedDuplicatePrecedence(t *testing.T) {
	for _, assessed := range []string{"Low", "Medium", "High", "Critical", "Negligible"} {
		for _, labels := range [][]string{{"Untriaged", assessed}, {assessed, "Untriaged"}} {
			t.Run(strings.Join(labels, "/"), func(t *testing.T) {
				mock := newMockQuayAPI()
				mock.responses[quayManifestSecurityPath("team", "app", "sha256:fixture", true)] = untriagedQuayReport(t, labels...)
				adaptor := NewQuayAdaptor()
				adaptor.client = mock
				reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
					{Registry: "quay.io", Repository: "team/app", Hash: "sha256:fixture"},
				})
				require.NoError(t, err)
				require.Len(t, reports[0].Vulnerabilities, 1)
				require.Equal(t, assessed, reports[0].Vulnerabilities[0].Severity,
					"this change does not redefine the existing highest-assessed-severity merge")
			})
		}
	}
}

func TestUntriagedSeverityBatchKeepsResultStatusAndOrder(t *testing.T) {
	mock := newMockQuayAPI()
	adaptor := NewQuayAdaptor()
	adaptor.client = mock
	labels := []string{"Untriaged", "Negligible", "Unassigned", "Critical"}
	var images []ContainerImageIdentifier
	for i, label := range labels {
		repo := "app" + strings.Repeat("x", i+1)
		images = append(images, ContainerImageIdentifier{Registry: "quay.io", Repository: "team/" + repo, Hash: "sha256:fixture"})
		mock.responses[quayManifestSecurityPath("team", repo, "sha256:fixture", true)] = untriagedQuayReport(t, label)
	}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, reports, len(images))
	for i, want := range []string{"Unknown", "Negligible", "Unknown", "Critical"} {
		require.Equal(t, images[i], reports[i].ImageID)
		require.Equal(t, ScanStatusScanned, reports[i].Status)
		require.Len(t, reports[i].Vulnerabilities, 1)
		require.Equal(t, want, reports[i].Vulnerabilities[0].Severity)
	}
}

func TestUntriagedSeverityFromHarborAPI(t *testing.T) {
	for _, label := range []string{"Untriaged", "Unassigned", "UNTRIAGED", "UNASSIGNED"} {
		t.Run(label, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0": map[string]any{
					"vulnerabilities": []any{map[string]any{
						"id": "CVE-2026-1000", "severity": label,
						"description": "Assessment pending", "links": []string{"https://example.invalid/advisory"},
					}},
				},
			})
			require.NoError(t, err)
			mock := &mockHarborAPI{responses: map[string][]byte{
				"/api/v2.0/projects/team/repositories/app/artifacts/latest/additions/vulnerabilities": body,
			}}
			adaptor := NewHarborAdaptor()
			adaptor.client = mock
			images := []ContainerImageIdentifier{{Registry: "harbor.example", Repository: "team/app", Tag: "latest"}}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
			require.NoError(t, err)
			require.Len(t, reports, 1)
			require.Equal(t, images[0], reports[0].ImageID)
			require.Equal(t, ScanStatusScanned, reports[0].Status)
			require.Len(t, reports[0].Vulnerabilities, 1)
			require.Equal(t, "Unknown", reports[0].Vulnerabilities[0].Severity)
			require.Equal(t, "Assessment pending", reports[0].Vulnerabilities[0].Description)
			require.Equal(t, []string{"https://example.invalid/advisory"}, reports[0].Vulnerabilities[0].Links)
		})
	}
}

func TestUntriagedSeverityHarborKeepsNegligibleSeparate(t *testing.T) {
	const body = `{"scanner": {"vulnerabilities": [
		{"id":"CVE-2026-1000","severity":"Untriaged"},
		{"id":"CVE-2026-1001","severity":"Negligible"},
		{"id":"CVE-2026-1002","severity":"Critical"}
	]}}`
	adaptor := NewHarborAdaptor()
	adaptor.client = &mockHarborAPI{responses: map[string][]byte{
		"/api/v2.0/projects/team/repositories/app/artifacts/latest/additions/vulnerabilities": []byte(body),
	}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "harbor.example", Repository: "team/app", Tag: "latest"},
	})
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Len(t, reports[0].Vulnerabilities, 3)
	for i, want := range []string{"Unknown", "Negligible", "Critical"} {
		require.Equal(t, want, reports[0].Vulnerabilities[i].Severity)
	}
}

func TestUntriagedSeverityStaysUnknownInSerializedReport(t *testing.T) {
	for _, label := range []string{"Untriaged", "Unassigned"} {
		t.Run(label, func(t *testing.T) {
			mock := newMockQuayAPI()
			mock.responses[quayManifestSecurityPath("team", "app", "sha256:fixture", true)] = untriagedQuayReport(t, label)
			adaptor := NewQuayAdaptor()
			adaptor.client = mock
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
				{Registry: "quay.io", Repository: "team/app", Hash: "sha256:fixture"},
			})
			require.NoError(t, err)
			raw, err := json.Marshal(reports)
			require.NoError(t, err)
			var restored []ContainerImageVulnerabilityReport
			require.NoError(t, json.Unmarshal(raw, &restored))
			require.Len(t, restored, 1)
			require.Len(t, restored[0].Vulnerabilities, 1)
			require.Equal(t, "Unknown", restored[0].Vulnerabilities[0].Severity)
			require.Equal(t, reports[0].ImageID, restored[0].ImageID)
			require.Equal(t, ScanStatusScanned, restored[0].Status)
		})
	}
}

func TestUntriagedSeverityCanonicalMappingIsIdempotent(t *testing.T) {
	for _, label := range []string{"Untriaged", "Unassigned", "Unknown", "Negligible", "High"} {
		canonical := NormalizeSeverity(label)
		require.Equal(t, canonical, NormalizeSeverity(canonical))
		require.Equal(t, canonical, normalizeQuaySeverity(canonical))
	}
}
