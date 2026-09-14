package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyImageInput(t *testing.T) {
	statWith := func(existing ...string) func(string) bool {
		set := map[string]struct{}{}
		for _, p := range existing {
			set[p] = struct{}{}
		}
		return func(p string) bool {
			_, ok := set[p]
			return ok
		}
	}

	tests := []struct {
		name         string
		image        string
		statExisting []string
		wantRegistry bool
		wantScheme   string
		wantEmptyErr bool
	}{
		{name: "registry simple", image: "nginx:1.27", wantRegistry: true},
		{name: "registry with port and tar-like repo keeps registry", image: "myregistry.io:5000/team/my.tar:v1", wantRegistry: true},
		{name: "docker-archive scheme", image: "docker-archive:/tmp/x.tar", wantRegistry: false, wantScheme: "docker-archive"},
		{name: "uppercase scheme", image: "DOCKER-ARCHIVE:/tmp/x.tar", wantRegistry: false, wantScheme: "DOCKER-ARCHIVE"},
		{name: "oci-archive scheme", image: "oci-archive:/tmp/x.tar", wantRegistry: false, wantScheme: "oci-archive"},
		{name: "oci-dir scheme", image: "oci-dir:/tmp/layout", wantRegistry: false, wantScheme: "oci-dir"},
		{name: "dir scheme", image: "dir:/tmp/rootfs", wantRegistry: false, wantScheme: "dir"},
		{name: "sbom scheme", image: "sbom:/tmp/sbom.json", wantRegistry: false, wantScheme: "sbom"},
		{name: "purl scheme reads a local file", image: "purl:/tmp/purls.txt", wantRegistry: false, wantScheme: "purl"},
		{name: "local-directory scheme", image: "local-directory:/tmp/rootfs", wantRegistry: false, wantScheme: "local-directory"},
		{name: "local-file scheme", image: "local-file:/tmp/sbom.json", wantRegistry: false, wantScheme: "local-file"},
		{name: "singularity scheme", image: "singularity:/tmp/img.sif", wantRegistry: false, wantScheme: "singularity"},
		{name: "uppercase local alias", image: "LOCAL-FILE:/tmp/sbom.json", wantRegistry: false, wantScheme: "LOCAL-FILE"},
		// "purl" as a scheme always denotes grype's local purl-list path
		// (grype opens the remainder as a file), never a registry repo.
		{name: "purl repo-like input still local", image: "purl:latest", wantRegistry: false, wantScheme: "purl"},
		{name: "bare tar existing file", image: "/tmp/x.tar", statExisting: []string{"/tmp/x.tar"}, wantRegistry: false},
		{name: "absolute tar missing file still non-registry", image: "/tmp/missing.tar", wantRegistry: false},
		{name: "bare tgz path", image: "./rel/a.tgz", statExisting: []string{"./rel/a.tgz"}, wantRegistry: false},
		{name: "bare dir existing", image: "./mydir", statExisting: []string{"./mydir"}, wantRegistry: false},
		{name: "bare dirname without slash or dot", image: "rootfs", statExisting: []string{"rootfs"}, wantRegistry: false},
		{name: "bare sbom filename without slash", image: "sbom.json", statExisting: []string{"sbom.json"}, wantRegistry: false},
		{name: "tagged ref unaffected by colliding local file", image: "team/my.tar:v1", statExisting: []string{"team/my.tar"}, wantRegistry: true},
		{name: "untagged ref matching local file prefers loud error", image: "team/my.tar", statExisting: []string{"team/my.tar"}, wantRegistry: false},
		{name: "nonexistent relative no slash stays registry", image: "myimage", wantRegistry: true},
		{name: "empty", image: "   ", wantRegistry: false, wantEmptyErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, scheme, errEmpty := classifyImageInput(tt.image, statWith(tt.statExisting...))
			assert.Equal(t, tt.wantRegistry, registry)
			assert.Equal(t, tt.wantScheme, scheme)
			if tt.wantEmptyErr {
				assert.Error(t, errEmpty)
			} else {
				assert.NoError(t, errEmpty)
			}
		})
	}
}

func TestGetAttributesFromImageRejectsArchive(t *testing.T) {
	_, err := getAttributesFromImage("docker-archive:/tmp/x.tar")
	assert.Error(t, err)
}

func TestGetUniqueExceptionsRejectsNonRegistry(t *testing.T) {
	policies := []VulnerabilitiesIgnorePolicy{
		{
			Metadata:        Metadata{Name: "x"},
			Kind:            "VulnerabilitiesIgnorePolicy",
			Targets:         []Target{{DesignatorType: "Attributes", Attributes: Attributes{Registry: "quay.io"}}},
			Vulnerabilities: []string{"CVE-2023-42365"},
		},
	}
	_, _, err := getUniqueVulnerabilitiesAndSeverities(policies, "docker-archive:/tmp/x.tar", true)
	assert.ErrorContains(t, err, "non-registry input")
	_, _, err = getUniqueVulnerabilitiesAndSeverities(policies, "oci-dir:/tmp/layout", true)
	assert.ErrorContains(t, err, "non-registry input")
	// No flag → no error, archives still scannable.
	_, _, err = getUniqueVulnerabilitiesAndSeverities(nil, "docker-archive:/tmp/x.tar", false)
	assert.NoError(t, err)
}

func TestBuildImageScanJobsMixedArchive(t *testing.T) {
	policies := []VulnerabilitiesIgnorePolicy{
		{
			Metadata:        Metadata{Name: "x"},
			Kind:            "VulnerabilitiesIgnorePolicy",
			Targets:         []Target{{DesignatorType: "Attributes", Attributes: Attributes{Registry: "quay.io"}}},
			Vulnerabilities: []string{"CVE-2023-42365"},
		},
	}
	imgScanInfo := &ksmetav1.ImageScanInfo{
		Images:     []string{"docker-archive:/tmp/x.tar", "quay.io/kubescape/kubescape-cli:v3.0.0"},
		Exceptions: "/tmp/exc.json",
	}
	jobs := buildImageScanJobs(imgScanInfo, &cautils.ScanInfo{}, policies)
	assert.Len(t, jobs, 2)
	assert.ErrorContains(t, jobs[0].ExceptionErr, "non-registry input")
	assert.ErrorContains(t, jobs[0].ExceptionErr, "/tmp/exc.json")
	assert.NoError(t, jobs[1].ExceptionErr)
	assert.Contains(t, jobs[1].VulnerabilityExceptions, "CVE-2023-42365")
}

func TestCategorizeScanError_PreservesExceptionUnsupported(t *testing.T) {
	assert.NotEqual(t, ErrCategoryExceptionUnsupported, CategorizeScanError(assert.AnError))

	// Same wrapping the worker applies: the category prefix must survive
	// aggregation instead of collapsing to General.
	wrapped := NewScanErrorAggregator()
	wrapped.Add("docker-archive:/tmp/x.tar", formatExceptionUnsupportedError(assert.AnError))
	assert.Equal(t, map[ScanErrorCategory]int{ErrCategoryExceptionUnsupported: 1}, wrapped.Summary())
}

func TestExceptionUnsupportedErrorCategoryRoundTrip(t *testing.T) {
	policies := []VulnerabilitiesIgnorePolicy{
		{
			Metadata:        Metadata{Name: "x"},
			Kind:            "VulnerabilitiesIgnorePolicy",
			Targets:         []Target{{DesignatorType: "Attributes", Attributes: Attributes{Registry: "quay.io"}}},
			Vulnerabilities: []string{"CVE-2023-42365"},
		},
	}
	_, _, err := getUniqueVulnerabilitiesAndSeverities(policies, "docker-archive:/tmp/x.tar", true)
	require.Error(t, err)
	// The reporting layers (worker, fail-fast) tag the error via
	// formatExceptionUnsupportedError; the tagged form must survive
	// categorization instead of collapsing to General.
	assert.Equal(t, ErrCategoryExceptionUnsupported, CategorizeScanError(formatExceptionUnsupportedError(err)))
}

// An explicitly configured but empty exceptions file (valid [] or null)
// loads zero policies without error, yet must still trigger source
// validation for non-registry inputs. Flag presence and policy count are
// tracked separately; unconfigured runs keep the lenient path.
func TestEmptyExceptionsFileStillValidatesSources(t *testing.T) {
	writeExceptions := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "exc.json")
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		return path
	}

	for _, body := range []string{"[]", "null"} {
		path := writeExceptions(t, body)
		policies, err := GetImageExceptionsFromFile(path)
		require.NoError(t, err, "empty file %q must load", body)
		assert.Empty(t, policies)

		// Resolver: archive rejected, registry clean.
		_, _, err = getUniqueVulnerabilitiesAndSeverities(policies, "docker-archive:/tmp/x.tar", true)
		assert.ErrorContains(t, err, "non-registry input", "body %q", body)
		_, _, err = getUniqueVulnerabilitiesAndSeverities(policies, "nginx:1.27", true)
		assert.NoError(t, err, "body %q", body)

		// Unconfigured flag keeps the old lenient path even for archives.
		_, _, err = getUniqueVulnerabilitiesAndSeverities(policies, "docker-archive:/tmp/x.tar", false)
		assert.NoError(t, err, "body %q", body)
	}
}

func TestBuildImageScanJobsEmptyExceptionsFile(t *testing.T) {
	newInfo := func(images ...string) *ksmetav1.ImageScanInfo {
		return &ksmetav1.ImageScanInfo{Images: images, Exceptions: "/tmp/empty.json"}
	}

	t.Run("single archive errors", func(t *testing.T) {
		jobs := buildImageScanJobs(newInfo("docker-archive:/tmp/x.tar"), &cautils.ScanInfo{}, nil)
		require.Len(t, jobs, 1)
		assert.ErrorContains(t, jobs[0].ExceptionErr, "non-registry input")
		assert.ErrorContains(t, jobs[0].ExceptionErr, "/tmp/empty.json")
	})

	t.Run("single registry stays clean", func(t *testing.T) {
		jobs := buildImageScanJobs(newInfo("nginx:1.27"), &cautils.ScanInfo{}, nil)
		require.Len(t, jobs, 1)
		assert.NoError(t, jobs[0].ExceptionErr)
	})

	t.Run("mixed keeps sibling scanning", func(t *testing.T) {
		jobs := buildImageScanJobs(newInfo("docker-archive:/tmp/x.tar", "nginx:1.27"), &cautils.ScanInfo{}, nil)
		require.Len(t, jobs, 2)
		assert.ErrorContains(t, jobs[0].ExceptionErr, "non-registry input")
		assert.NoError(t, jobs[1].ExceptionErr)
	})

	t.Run("no flag keeps archive scannable", func(t *testing.T) {
		info := &ksmetav1.ImageScanInfo{Images: []string{"docker-archive:/tmp/x.tar"}}
		jobs := buildImageScanJobs(info, &cautils.ScanInfo{}, nil)
		require.Len(t, jobs, 1)
		assert.NoError(t, jobs[0].ExceptionErr)
	})
}
