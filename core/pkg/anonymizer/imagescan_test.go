package anonymizer

import (
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// privateImage is deliberately a private-registry reference: the host, the
// project path and the tag are all things --hide exists to keep out of a
// shared report.
const privateImage = "registry.internal.example.com:5000/payments/api:v1.4.2"

func podWithImage(name, namespace, image string) workloadinterface.IMetadata {
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

func containerImageOf(t *testing.T, resource workloadinterface.IMetadata) string {
	t.Helper()

	obj := resource.GetObject()
	spec, ok := obj["spec"].(map[string]any)
	require.True(t, ok, "resource has no spec")

	containers, ok := spec["containers"].([]any)
	require.True(t, ok, "resource has no containers")
	require.NotEmpty(t, containers)

	container, ok := containers[0].(map[string]any)
	require.True(t, ok, "container is not an object")

	image, _ := container["image"].(string)
	return image
}

// TestApply_HidesImageScanReferences is the regression test for the leak:
// --scan-images results live on ResultsHandler.ImageScanData, not on the OPA
// session, so applyWithTransformer never reached them and the image reference
// was written out verbatim next to an already-anonymized workload.
func TestApply_HidesImageScanReferences(t *testing.T) {
	pod := podWithImage("payments-api", "prod", privateImage)

	handler := &resultshandling.ResultsHandler{
		ScanData: &cautils.OPASessionObj{
			AllResources: map[string]workloadinterface.IMetadata{
				pod.GetID(): pod,
			},
		},
		ImageScanData: []cautils.ImageScanData{
			{Image: privateImage, Platform: "linux/amd64"},
		},
	}

	require.NoError(t, Apply(handler))

	got := handler.ImageScanData[0].Image

	assert.NotEqual(t, privateImage, got, "image reference left in cleartext")
	assert.NotContains(t, got, "registry.internal.example.com")
	assert.NotContains(t, got, "payments")
	assert.NotContains(t, got, "v1.4.2")
	assert.True(t, strings.HasPrefix(got, "img-"), "expected an img- pseudonym, got %q", got)

	// The same image on the workload side must produce the same pseudonym, or
	// the report no longer joins a CVE to the workload it came from.
	assert.Equal(t, got, containerImageOf(t, pod),
		"image-scan and workload pseudonyms diverged")

	// Platform describes the shape of what was scanned, not its identity, and
	// is kept for the same reason transformClusterMetadata keeps the provider.
	assert.Equal(t, "linux/amd64", handler.ImageScanData[0].Platform)
}

// TestApplyEncrypted_EncryptsImageScanReferences covers the same leak on the
// --encrypt path.
func TestApplyEncrypted_EncryptsImageScanReferences(t *testing.T) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	masterKey, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	handler := &resultshandling.ResultsHandler{
		ScanData: &cautils.OPASessionObj{
			AllResources: map[string]workloadinterface.IMetadata{},
		},
		ImageScanData: []cautils.ImageScanData{
			{Image: privateImage},
		},
	}

	require.NoError(t, ApplyEncrypted(handler, dek, masterKey))

	got := handler.ImageScanData[0].Image
	assert.NotEqual(t, privateImage, got)
	assert.NotContains(t, got, "registry.internal.example.com")
	assert.Contains(t, got, "ENC[AES256_GCM,")
}

// TestApply_ImageScanDataWithoutSession guards the widened entry condition:
// applyWithTransformer used to return early whenever ScanData was nil, which
// skipped image results entirely.
func TestApply_ImageScanDataWithoutSession(t *testing.T) {
	handler := &resultshandling.ResultsHandler{
		ImageScanData: []cautils.ImageScanData{
			{Image: privateImage},
		},
	}

	require.NoError(t, Apply(handler))
	assert.NotEqual(t, privateImage, handler.ImageScanData[0].Image)
}

func TestApply_NilHandlerAndEmptyImageScanData(t *testing.T) {
	assert.NoError(t, Apply(nil))

	handler := &resultshandling.ResultsHandler{
		ScanData: &cautils.OPASessionObj{},
	}
	assert.NoError(t, Apply(handler))
}

func TestTransformImageScanData_EmptyImageIsLeftAlone(t *testing.T) {
	imageScanData := []cautils.ImageScanData{{Image: ""}}

	require.NoError(t, transformImageScanData(imageScanData, NewMappingTransformer()))
	assert.Empty(t, imageScanData[0].Image)
}

// TestTransformImageScanData_Error checks that a transformer failure
// propagates rather than being swallowed. The caller (core/core/scan.go)
// aborts the scan on it, so nothing is printed and the partially-applied
// field is never observed - the same contract transformContainerMetadata
// already relies on.
func TestTransformImageScanData_Error(t *testing.T) {
	imageScanData := []cautils.ImageScanData{{Image: privateImage}}

	err := transformImageScanData(imageScanData, &failingTransformer{})
	require.Error(t, err)
	assert.NotEqual(t, privateImage, imageScanData[0].Image,
		"a failed transform must not leave the cleartext image in place")
}

// TestApply_FailedTransformPropagates is the end-to-end shape of the above:
// Apply must surface the error so ScanContext aborts before any printer runs.
func TestApply_FailedTransformPropagates(t *testing.T) {
	handler := &resultshandling.ResultsHandler{
		ScanData: &cautils.OPASessionObj{},
		ImageScanData: []cautils.ImageScanData{
			{Image: privateImage},
		},
	}

	require.Error(t, applyWithTransformer(handler, &failingTransformer{}))
}
