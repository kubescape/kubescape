package imagescan

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/docker/distribution/manifest/schema2"
)

func TestContainerImageIdentifierJSON(t *testing.T) {
	id := ContainerImageIdentifier{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "latest",
		Hash:       "sha256:12345",
	}

	b, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("Failed to marshal ContainerImageIdentifier: %v", err)
	}

	var parsed ContainerImageIdentifier
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal ContainerImageIdentifier: %v", err)
	}

	if parsed.Registry != id.Registry || parsed.Repository != id.Repository || parsed.Tag != id.Tag || parsed.Hash != id.Hash {
		t.Errorf("Unmarshalled object %v does not match original %v", parsed, id)
	}
}

func TestContainerImageScanStatusJSON(t *testing.T) {
	now := time.Now().Truncate(time.Second) // JSON serialization may truncate fractional seconds
	status := ContainerImageScanStatus{
		ImageID: ContainerImageIdentifier{
			Registry:   "docker.io",
			Repository: "library/nginx",
			Tag:        "latest",
			Hash:       "sha256:12345",
		},
		IsScanAvailable: true,
		IsBomAvailable:  false,
		LastScanDate:    now,
	}

	b, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Failed to marshal ContainerImageScanStatus: %v", err)
	}

	var parsed ContainerImageScanStatus
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal ContainerImageScanStatus: %v", err)
	}

	if parsed.IsScanAvailable != status.IsScanAvailable || !parsed.LastScanDate.Equal(status.LastScanDate) {
		t.Errorf("Unmarshalled object %v does not match original %v", parsed, status)
	}
}

func TestContainerImageVulnerabilityReportJSON(t *testing.T) {
	report := ContainerImageVulnerabilityReport{
		ImageID: ContainerImageIdentifier{
			Registry:   "docker.io",
			Repository: "library/nginx",
			Tag:        "latest",
		},
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2023-1234", Severity: "HIGH"},
		},
	}

	b, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to marshal ContainerImageVulnerabilityReport: %v", err)
	}

	var parsed ContainerImageVulnerabilityReport
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal ContainerImageVulnerabilityReport: %v", err)
	}

	if len(parsed.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(parsed.Vulnerabilities))
	}
}

func TestContainerImageInformationJSON(t *testing.T) {
	info := ContainerImageInformation{
		ImageID: ContainerImageIdentifier{
			Registry:   "docker.io",
			Repository: "library/nginx",
			Tag:        "latest",
		},
		Bom: []string{"pkg1", "pkg2"},
		ImageManifest: schema2.Manifest{
			Versioned: schema2.SchemaVersion,
		},
	}

	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Failed to marshal ContainerImageInformation: %v", err)
	}

	var parsed ContainerImageInformation
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal ContainerImageInformation: %v", err)
	}

	if len(parsed.Bom) != 2 {
		t.Errorf("Expected 2 bom items, got %d", len(parsed.Bom))
	}
}
