package printer_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const privateTestImage = "registry.internal.example.com:5000/payments/api:v1.4.2"

// podResourceWithImage creates a mock Pod workload containing a container with the given image reference.
func podResourceWithImage(name, namespace, image string) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":  "api",
					"image": image,
				},
			},
		},
	})
}

// buildTestImageScanDataWithSource creates test image scan data populated with source image metadata.
func buildTestImageScanDataWithSource(image string) cautils.ImageScanData {
	scan := printerv2.BuildSeverityExceptionImageScanDataForTest()
	scan.Image = image
	scan.SBOM.Source = source.Description{
		Name: image,
		Metadata: source.ImageMetadata{
			UserInput:    image,
			Tags:         []string{image},
			RepoDigests:  []string{"registry.internal.example.com:5000/payments/api@sha256:abcdef1234567890"},
			RawManifest:  []byte(`{"schemaVersion": 2}`),
			RawConfig:    []byte(`{"architecture": "amd64"}`),
			Architecture: "amd64",
			OS:           "linux",
		},
	}
	return scan
}

// TestSARIFActionPrint_PreservesAnonymizationWithImageSourceMetadata_Hide verifies that
// when --hide (anonymization) is applied to combined scans with non-empty SBOM image
// source metadata, the emitted SARIF report does not leak private image references and
// uses the anonymized image pseudonym.
func TestSARIFActionPrint_PreservesAnonymizationWithImageSourceMetadata_Hide(t *testing.T) {
	tmp, err := os.CreateTemp("", "sarif-anonymized-hide-*.sarif")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	pod := podResourceWithImage("payments-api", "prod", privateTestImage)
	session := printerv2.ConfigurationOutputFixtureForTest(t, 1)
	session.AllResources[pod.GetID()] = pod

	imageScan := buildTestImageScanDataWithSource(privateTestImage)
	handler := &resultshandling.ResultsHandler{
		ScanData:      session,
		ImageScanData: []cautils.ImageScanData{imageScan},
	}

	require.NoError(t, anonymizer.Apply(handler))

	anonymizedImage := handler.ImageScanData[0].Image
	require.NotEmpty(t, anonymizedImage)
	require.NotEqual(t, privateTestImage, anonymizedImage)
	require.True(t, strings.HasPrefix(anonymizedImage, "img-"))

	sp := printerv2.NewSARIFPrinter(false)
	require.NoError(t, sp.SetWriter(context.Background(), tmp.Name()))

	err = sp.ActionPrint(context.Background(), handler.ScanData, handler.ImageScanData)
	require.NoError(t, err)

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	reportStr := string(raw)

	// Privacy assertions: verify original image reference is not exposed
	assert.NotContains(t, reportStr, privateTestImage, "raw private image reference must not leak in SARIF output")
	assert.NotContains(t, reportStr, "registry.internal.example.com", "private registry host must not leak in SARIF output")
	assert.NotContains(t, reportStr, "payments/api", "private image path must not leak in SARIF output")
	assert.NotContains(t, reportStr, "v1.4.2", "private image tag must not leak in SARIF output")

	// Verify the anonymized image pseudonym is present
	assert.Contains(t, reportStr, anonymizedImage, "anonymized image pseudonym must be emitted in SARIF output")

	// Structural assertions: verify both posture and image runs exist
	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 2, "SARIF report must aggregate both posture and image runs")

	// Posture run
	postureRun := report.Runs[0]
	require.NotNil(t, postureRun.Tool.Driver)
	assert.Equal(t, "kubescape", postureRun.Tool.Driver.Name)

	// Image run
	imageRun := report.Runs[1]
	require.NotNil(t, imageRun.Tool.Driver)
	assert.Equal(t, "Kubescape", imageRun.Tool.Driver.Name)
	require.NotEmpty(t, imageRun.Results)

	foundAnonymizedInResult := false
	for _, res := range imageRun.Results {
		if res.Message.Text != nil && strings.Contains(*res.Message.Text, anonymizedImage) {
			foundAnonymizedInResult = true
			break
		}
	}
	assert.True(t, foundAnonymizedInResult, "image run finding message must reference the anonymized image pseudonym")
}

// TestSARIFActionPrint_PreservesAnonymizationWithImageSourceMetadata_Encrypt verifies that
// when --encrypt is applied to combined scans with non-empty SBOM image source metadata,
// the emitted SARIF report does not leak private image references and uses the encrypted
// ciphertext reference.
func TestSARIFActionPrint_PreservesAnonymizationWithImageSourceMetadata_Encrypt(t *testing.T) {
	tmp, err := os.CreateTemp("", "sarif-anonymized-encrypt-*.sarif")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	masterKey, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	pod := podResourceWithImage("payments-api", "prod", privateTestImage)
	session := printerv2.ConfigurationOutputFixtureForTest(t, 1)
	session.AllResources[pod.GetID()] = pod

	imageScan := buildTestImageScanDataWithSource(privateTestImage)
	handler := &resultshandling.ResultsHandler{
		ScanData:      session,
		ImageScanData: []cautils.ImageScanData{imageScan},
	}

	require.NoError(t, anonymizer.ApplyEncrypted(handler, dek, masterKey))

	encryptedImage := handler.ImageScanData[0].Image
	require.NotEmpty(t, encryptedImage)
	require.NotEqual(t, privateTestImage, encryptedImage)
	require.Contains(t, encryptedImage, "ENC[AES256_GCM,")

	sp := printerv2.NewSARIFPrinter(false)
	require.NoError(t, sp.SetWriter(context.Background(), tmp.Name()))

	err = sp.ActionPrint(context.Background(), handler.ScanData, handler.ImageScanData)
	require.NoError(t, err)

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	reportStr := string(raw)

	// Privacy assertions: verify original image reference is not exposed
	assert.NotContains(t, reportStr, privateTestImage, "raw private image reference must not leak in encrypted SARIF output")
	assert.NotContains(t, reportStr, "registry.internal.example.com", "private registry host must not leak in encrypted SARIF output")
	assert.NotContains(t, reportStr, "payments/api", "private image path must not leak in encrypted SARIF output")
	assert.NotContains(t, reportStr, "v1.4.2", "private image tag must not leak in encrypted SARIF output")

	// Verify encrypted image reference is present
	assert.Contains(t, reportStr, encryptedImage, "encrypted image ciphertext must be emitted in SARIF output")

	// Structural assertions: verify both posture and image runs exist
	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 2, "SARIF report must aggregate both posture and image runs")

	// Posture run
	postureRun := report.Runs[0]
	require.NotNil(t, postureRun.Tool.Driver)
	assert.Equal(t, "kubescape", postureRun.Tool.Driver.Name)

	// Image run
	imageRun := report.Runs[1]
	require.NotNil(t, imageRun.Tool.Driver)
	assert.Equal(t, "Kubescape", imageRun.Tool.Driver.Name)
	require.NotEmpty(t, imageRun.Results)

	foundEncryptedInResult := false
	for _, res := range imageRun.Results {
		if res.Message.Text != nil && strings.Contains(*res.Message.Text, encryptedImage) {
			foundEncryptedInResult = true
			break
		}
	}
	assert.True(t, foundEncryptedInResult, "image run finding message must reference the encrypted image reference")
}

// buildTestImageScanDataWithPointerSource constructs test image scan data using pointer-form source metadata.
func buildTestImageScanDataWithPointerSource(image string) cautils.ImageScanData {
	scan := printerv2.BuildSeverityExceptionImageScanDataForTest()
	scan.Image = image
	scan.SBOM.Source = source.Description{
		Name: image,
		Metadata: &source.ImageMetadata{
			UserInput:    image,
			Tags:         []string{image},
			RepoDigests:  []string{"registry.internal.example.com:5000/payments/api@sha256:abcdef1234567890"},
			RawManifest:  []byte(`{"schemaVersion": 2}`),
			RawConfig:    []byte(`{"architecture": "amd64"}`),
			Architecture: "amd64",
			OS:           "linux",
		},
	}
	return scan
}

// TestSARIFActionPrint_PreservesImageMetadataWithPointerSourceMetadata verifies that when
// image source metadata is provided as a pointer (*source.ImageMetadata), the SARIF printer
// converts it to value-form source.ImageMetadata so Grype recognizes the image metadata,
// preserving image-specific finding messages, locations, and fingerprints.
func TestSARIFActionPrint_PreservesImageMetadataWithPointerSourceMetadata(t *testing.T) {
	tmp, err := os.CreateTemp("", "sarif-pointer-metadata-*.sarif")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	pod := podResourceWithImage("payments-api", "prod", privateTestImage)
	session := printerv2.ConfigurationOutputFixtureForTest(t, 1)
	session.AllResources[pod.GetID()] = pod

	imageScan := buildTestImageScanDataWithPointerSource(privateTestImage)
	handler := &resultshandling.ResultsHandler{
		ScanData:      session,
		ImageScanData: []cautils.ImageScanData{imageScan},
	}

	require.NoError(t, anonymizer.Apply(handler))

	anonymizedImage := handler.ImageScanData[0].Image
	require.NotEmpty(t, anonymizedImage)
	require.NotEqual(t, privateTestImage, anonymizedImage)

	sp := printerv2.NewSARIFPrinter(false)
	require.NoError(t, sp.SetWriter(context.Background(), tmp.Name()))

	err = sp.ActionPrint(context.Background(), handler.ScanData, handler.ImageScanData)
	require.NoError(t, err)

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	reportStr := string(raw)
	assert.NotContains(t, reportStr, privateTestImage)
	assert.Contains(t, reportStr, anonymizedImage)

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 2)

	imageRun := report.Runs[1]
	require.NotEmpty(t, imageRun.Results)

	foundAnonymizedInResult := false
	for _, res := range imageRun.Results {
		if res.Message.Text != nil && strings.Contains(*res.Message.Text, anonymizedImage) {
			foundAnonymizedInResult = true
			break
		}
	}
	assert.True(t, foundAnonymizedInResult, "image run finding message must retain the sanitized image name from pointer metadata")
}

// TestSARIFActionPrint_ShortImageNamesNotCorruptedByAnonymization verifies that
// combined SARIF reports for short image names (such as "run", "tool", "result", "s")
// do not corrupt JSON structure or drop runs, tool metadata, or results when anonymization
// is active, ensuring sanitization is strictly structured and does not perform broad substring replacements.
func TestSARIFActionPrint_ShortImageNamesNotCorruptedByAnonymization(t *testing.T) {
	shortNames := []string{"run", "tool", "result", "s"}
	for _, name := range shortNames {
		t.Run(name, func(t *testing.T) {
			tmp, err := os.CreateTemp("", "sarif-short-name-*.sarif")
			require.NoError(t, err)
			defer func() { _ = os.Remove(tmp.Name()) }()

			pod := podResourceWithImage("test-workload", "default", name)
			session := printerv2.ConfigurationOutputFixtureForTest(t, 1)
			session.AllResources[pod.GetID()] = pod

			imageScan := buildTestImageScanDataWithSource(name)
			handler := &resultshandling.ResultsHandler{
				ScanData:      session,
				ImageScanData: []cautils.ImageScanData{imageScan},
			}

			require.NoError(t, anonymizer.Apply(handler))

			anonymizedImage := handler.ImageScanData[0].Image
			require.NotEmpty(t, anonymizedImage)
			require.NotEqual(t, name, anonymizedImage)

			sp := printerv2.NewSARIFPrinter(false)
			require.NoError(t, sp.SetWriter(context.Background(), tmp.Name()))

			err = sp.ActionPrint(context.Background(), handler.ScanData, handler.ImageScanData)
			require.NoError(t, err)

			raw, err := os.ReadFile(tmp.Name())
			require.NoError(t, err)

			var report sarif.Report
			require.NoError(t, json.Unmarshal(raw, &report))
			require.Len(t, report.Runs, 2, "SARIF report must aggregate both posture and image runs without dropping runs")

			postureRun := report.Runs[0]
			require.NotNil(t, postureRun.Tool.Driver)
			assert.Equal(t, "kubescape", postureRun.Tool.Driver.Name)

			imageRun := report.Runs[1]
			require.NotNil(t, imageRun.Tool.Driver, "tool driver must not be corrupted by short image name")
			assert.Equal(t, "Kubescape", imageRun.Tool.Driver.Name)
			require.NotEmpty(t, imageRun.Results, "results array must not be dropped by short image name")

			foundAnonymizedInResult := false
			for _, res := range imageRun.Results {
				if res.Message.Text != nil && strings.Contains(*res.Message.Text, anonymizedImage) {
					foundAnonymizedInResult = true
					break
				}
			}
			assert.True(t, foundAnonymizedInResult, "image run finding message must reference the anonymized image pseudonym")
		})
	}
}

// TestSARIFActionPrint_PreservesSourceNameForUntransformedScans verifies that for
// untransformed (non-anonymized) scans, the SBOM source name is preserved as-is
// (e.g. "nginx") rather than being overwritten with the full image reference and tag
// (e.g. "nginx:1.25"). This ensures finding locations and fingerprints do not churn
// across tag updates.
func TestSARIFActionPrint_PreservesSourceNameForUntransformedScans(t *testing.T) {
	tmp, err := os.CreateTemp("", "sarif-untransformed-*.sarif")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp.Name()) }()

	session := printerv2.ConfigurationOutputFixtureForTest(t, 1)

	imageScan := printerv2.BuildSeverityExceptionImageScanDataForTest()
	imageScan.Image = "nginx:1.25"
	imageScan.SBOM.Source = source.Description{
		Name: "nginx",
		Metadata: source.ImageMetadata{
			UserInput:    "nginx:1.25",
			Tags:         []string{"nginx:1.25"},
			RepoDigests:  []string{"nginx@sha256:1234567890abcdef"},
			Architecture: "amd64",
			OS:           "linux",
		},
	}

	sp := printerv2.NewSARIFPrinter(false)
	require.NoError(t, sp.SetWriter(context.Background(), tmp.Name()))

	err = sp.ActionPrint(context.Background(), session, []cautils.ImageScanData{imageScan})
	require.NoError(t, err)

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 2)

	imageRun := report.Runs[1]
	require.NotEmpty(t, imageRun.Results)

	// Verify that physical artifact location URIs preserve the original source name "nginx" without tag churn
	foundOriginalSourceName := false
	for _, res := range imageRun.Results {
		for _, loc := range res.Locations {
			if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil && loc.PhysicalLocation.ArtifactLocation.URI != nil {
				if strings.HasPrefix(*loc.PhysicalLocation.ArtifactLocation.URI, "nginx") && !strings.Contains(*loc.PhysicalLocation.ArtifactLocation.URI, "1.25") {
					foundOriginalSourceName = true
					break
				}
			}
		}
	}
	assert.True(t, foundOriginalSourceName, "artifact locations must preserve original source name 'nginx' without tag churn")

	// Also verify that tag updates keep the finding identity/location stable
	imageScanUpdatedTag := imageScan
	imageScanUpdatedTag.Image = "nginx:1.26"
	imageScanUpdatedTag.SBOM.Source.Metadata = source.ImageMetadata{
		UserInput:    "nginx:1.26",
		Tags:         []string{"nginx:1.26"},
		RepoDigests:  []string{"nginx@sha256:abcdef1234567890"},
		Architecture: "amd64",
		OS:           "linux",
	}

	tmp2, err := os.CreateTemp("", "sarif-untransformed-tag2-*.sarif")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmp2.Name()) }()

	sp2 := printerv2.NewSARIFPrinter(false)
	require.NoError(t, sp2.SetWriter(context.Background(), tmp2.Name()))
	require.NoError(t, sp2.ActionPrint(context.Background(), session, []cautils.ImageScanData{imageScanUpdatedTag}))

	raw2, err := os.ReadFile(tmp2.Name())
	require.NoError(t, err)

	var report2 sarif.Report
	require.NoError(t, json.Unmarshal(raw2, &report2))
	require.Len(t, report2.Runs, 2)

	imageRun2 := report2.Runs[1]
	require.NotEmpty(t, imageRun2.Results)

	// Ensure finding fingerprints for unchanged vulnerabilities remain identical despite tag update
	fingerprints1 := make(map[string]any)
	for _, res := range imageRun.Results {
		if res.RuleID != nil && res.PartialFingerprints != nil {
			fingerprints1[*res.RuleID] = res.PartialFingerprints["primaryLocationLineHash"]
		}
	}
	for _, res := range imageRun2.Results {
		if res.RuleID != nil && res.PartialFingerprints != nil {
			if fp1, ok := fingerprints1[*res.RuleID]; ok {
				assert.Equal(t, fp1, res.PartialFingerprints["primaryLocationLineHash"],
					"finding fingerprint for %s must remain stable across tag updates", *res.RuleID)
			}
		}
	}

	t.Run("source_qualified_registry_prefix", func(t *testing.T) {
		tmp1, err := os.CreateTemp("", "sarif-untransformed-sq1-*.sarif")
		require.NoError(t, err)
		defer func() { _ = os.Remove(tmp1.Name()) }()

		imageScan1 := printerv2.BuildSeverityExceptionImageScanDataForTest()
		imageScan1.Image = "registry:nginx:1.25"
		imageScan1.SBOM.Source = source.Description{
			Name: "nginx",
			Metadata: source.ImageMetadata{
				UserInput:    "nginx:1.25",
				Tags:         []string{"nginx:1.25"},
				RepoDigests:  []string{"nginx@sha256:1234567890abcdef"},
				Architecture: "amd64",
				OS:           "linux",
			},
		}

		sp1 := printerv2.NewSARIFPrinter(false)
		require.NoError(t, sp1.SetWriter(context.Background(), tmp1.Name()))
		require.NoError(t, sp1.ActionPrint(context.Background(), session, []cautils.ImageScanData{imageScan1}))

		raw1, err := os.ReadFile(tmp1.Name())
		require.NoError(t, err)

		var report1 sarif.Report
		require.NoError(t, json.Unmarshal(raw1, &report1))
		require.Len(t, report1.Runs, 2)
		imageRun1 := report1.Runs[1]
		require.NotEmpty(t, imageRun1.Results)

		foundOriginalName := false
		for _, res := range imageRun1.Results {
			for _, loc := range res.Locations {
				if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil && loc.PhysicalLocation.ArtifactLocation.URI != nil {
					if strings.HasPrefix(*loc.PhysicalLocation.ArtifactLocation.URI, "nginx") && !strings.Contains(*loc.PhysicalLocation.ArtifactLocation.URI, "registry:") {
						foundOriginalName = true
						break
					}
				}
			}
		}
		assert.True(t, foundOriginalName, "source name 'nginx' must be preserved for source-qualified scan")

		imageScan2 := imageScan1
		imageScan2.Image = "registry:nginx:1.26"
		imageScan2.SBOM.Source.Metadata = source.ImageMetadata{
			UserInput:    "nginx:1.26",
			Tags:         []string{"nginx:1.26"},
			RepoDigests:  []string{"nginx@sha256:abcdef1234567890"},
			Architecture: "amd64",
			OS:           "linux",
		}

		tmp2, err := os.CreateTemp("", "sarif-untransformed-sq2-*.sarif")
		require.NoError(t, err)
		defer func() { _ = os.Remove(tmp2.Name()) }()

		sp2 := printerv2.NewSARIFPrinter(false)
		require.NoError(t, sp2.SetWriter(context.Background(), tmp2.Name()))
		require.NoError(t, sp2.ActionPrint(context.Background(), session, []cautils.ImageScanData{imageScan2}))

		raw2, err := os.ReadFile(tmp2.Name())
		require.NoError(t, err)

		var report2 sarif.Report
		require.NoError(t, json.Unmarshal(raw2, &report2))
		require.Len(t, report2.Runs, 2)
		imageRun2 := report2.Runs[1]
		require.NotEmpty(t, imageRun2.Results)

		fingerprints := make(map[string]any)
		for _, res := range imageRun1.Results {
			if res.RuleID != nil && res.PartialFingerprints != nil {
				fingerprints[*res.RuleID] = res.PartialFingerprints["primaryLocationLineHash"]
			}
		}
		for _, res := range imageRun2.Results {
			if res.RuleID != nil && res.PartialFingerprints != nil {
				if fp1, ok := fingerprints[*res.RuleID]; ok {
					assert.Equal(t, fp1, res.PartialFingerprints["primaryLocationLineHash"],
						"finding fingerprint for %s must remain stable across tag updates on source-qualified images", *res.RuleID)
				}
			}
		}
	})

	t.Run("non_pseudonym_with_img_prefix", func(t *testing.T) {
		tmp1, err := os.CreateTemp("", "sarif-untransformed-imgprefix-*.sarif")
		require.NoError(t, err)
		defer func() { _ = os.Remove(tmp1.Name()) }()

		imageScan1 := printerv2.BuildSeverityExceptionImageScanDataForTest()
		imageScan1.Image = "img-service:v1.0.0"
		imageScan1.SBOM.Source = source.Description{
			Name: "img-service",
			Metadata: source.ImageMetadata{
				UserInput:    "img-service:v1.0.0",
				Tags:         []string{"img-service:v1.0.0"},
				RepoDigests:  []string{"img-service@sha256:1122334455667788"},
				Architecture: "amd64",
				OS:           "linux",
			},
		}

		sp1 := printerv2.NewSARIFPrinter(false)
		require.NoError(t, sp1.SetWriter(context.Background(), tmp1.Name()))
		require.NoError(t, sp1.ActionPrint(context.Background(), session, []cautils.ImageScanData{imageScan1}))

		raw1, err := os.ReadFile(tmp1.Name())
		require.NoError(t, err)

		var report1 sarif.Report
		require.NoError(t, json.Unmarshal(raw1, &report1))
		require.Len(t, report1.Runs, 2)
		imageRun1 := report1.Runs[1]
		require.NotEmpty(t, imageRun1.Results)

		foundOriginalName := false
		for _, res := range imageRun1.Results {
			for _, loc := range res.Locations {
				if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil && loc.PhysicalLocation.ArtifactLocation.URI != nil {
					if strings.HasPrefix(*loc.PhysicalLocation.ArtifactLocation.URI, "img-service") && !strings.Contains(*loc.PhysicalLocation.ArtifactLocation.URI, "v1.0.0") {
						foundOriginalName = true
						break
					}
				}
			}
		}
		assert.True(t, foundOriginalName, "source name 'img-service' must be preserved without tag churn")
	})
}
