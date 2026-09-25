package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	stereoscopefile "github.com/anchore/stereoscope/pkg/file"
	ociprovider "github.com/anchore/stereoscope/pkg/image/oci"
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
		// "snap" sources never provide OCI registry attributes: syft resolves
		// the remainder through its local (.snap file) or remote (Snap Store)
		// providers, and grype strips the tag in both forms.
		{name: "snap local file", image: "snap:/tmp/img.snap", wantRegistry: false, wantScheme: "snap"},
		{name: "snap remote store name", image: "snap:firefox", wantRegistry: false, wantScheme: "snap"},
		{name: "uppercase snap scheme", image: "SNAP:/tmp/img.snap", wantRegistry: false, wantScheme: "SNAP"},
		{name: "snap-named repo in registry stays registry", image: "example.io/snap/image:v1", wantRegistry: true},
		// Generic "image:" selector (Syft's ImageTag): peel once, reclassify.
		{name: "image selector with registry remainder", image: "image:nginx", wantRegistry: true},
		{name: "image selector with nested registry ref", image: "image:image:nginx", wantRegistry: true},
		{name: "image-named repo in registry stays registry", image: "example.io/image/foo:v1", wantRegistry: true},
		{name: "image-named repo in registry stays registry", image: "example.io/image/foo:v1", wantRegistry: true},
		{name: "bare tar existing file", image: "/tmp/x.tar", statExisting: []string{"/tmp/x.tar"}, wantRegistry: false},
		{name: "absolute tar missing file still non-registry", image: "/tmp/missing.tar", wantRegistry: false},
		{name: "bare tgz path", image: "./rel/a.tgz", statExisting: []string{"./rel/a.tgz"}, wantRegistry: false},
		{name: "bare dir existing", image: "./mydir", statExisting: []string{"./mydir"}, wantRegistry: false},
		{name: "bare dirname without slash or dot", image: "rootfs", statExisting: []string{"rootfs"}, wantRegistry: false},
		{name: "bare sbom filename without slash", image: "sbom.json", statExisting: []string{"sbom.json"}, wantRegistry: false},
		{name: "tagged ref unaffected by colliding local file", image: "team/my.tar:v1", statExisting: []string{"team/my.tar"}, wantRegistry: true},
		{name: "untagged ref matching local file prefers loud error", image: "team/my.tar", statExisting: []string{"team/my.tar"}, wantRegistry: false},
		{name: "nonexistent relative no slash stays registry", image: "myimage", wantRegistry: true},
		// "oci-layout" is not a tag/provider in the pinned stack (oci-dir
		// is), so grype never strips it: a repo/tag spelling stays registry.
		{name: "oci-layout repo and tag stays registry", image: "oci-layout:latest", wantRegistry: true},
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
	_, _, err = getUniqueVulnerabilitiesAndSeverities(policies, "snap:/tmp/img.snap", true)
	assert.ErrorContains(t, err, "non-registry input")
	_, _, err = getUniqueVulnerabilitiesAndSeverities(policies, "snap:firefox", true)
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

// Syft's generic "image:" selector peels once and passes the remainder
// literally to the narrowed image providers (no second scheme strip):
// "image:nginx" matches nginx-targeted policies, an existing archive is
// local content, and "image:dir:latest" stays a registry identity exactly
// as grype resolves it.
func TestImageSelectorResolvesStrippedIdentity(t *testing.T) {
	policies := []VulnerabilitiesIgnorePolicy{
		{
			Metadata:        Metadata{Name: "x"},
			Kind:            "VulnerabilitiesIgnorePolicy",
			Targets:         []Target{{DesignatorType: "Attributes", Attributes: Attributes{ImageName: "nginx"}}},
			Vulnerabilities: []string{"CVE-2023-42365"},
		},
	}
	vulns, _, err := getUniqueVulnerabilitiesAndSeverities(policies, "image:nginx", true)
	require.NoError(t, err)
	assert.Contains(t, vulns, "CVE-2023-42365")

	// A remainder with a scheme prefix is not re-stripped: grype passes
	// "dir:latest" literally to the image providers, whose daemon parser
	// treats it as a registry ref for repo "dir".
	vulns, _, err = getUniqueVulnerabilitiesAndSeverities(policies, "image:dir:latest", true)
	require.NoError(t, err, "dir:latest is a registry identity for the narrowed providers")
	assert.Empty(t, vulns, "dir:latest does not identity-match nginx CVEs (different repo)")
}

// writeDockerTarball writes the smallest archive the docker tarball provider
// accepts (manifest.json plus its config), so fixtures exercise provider
// acceptance instead of asserting a suffix heuristic.
func writeDockerTarball(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	tw := tar.NewWriter(f)
	defer func() { _ = tw.Close() }()
	manifest := `[{"Config":"config.json","RepoTags":["test:latest"],"Layers":[]}]`
	config := `{}`
	for name, body := range map[string]string{"manifest.json": manifest, "config.json": config} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}))
		_, err = tw.Write([]byte(body))
		require.NoError(t, err)
	}
}

// sha256Digest returns the "sha256:<hex>" digest of content, the addressing
// the OCI layout uses for blobs.
func sha256Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeBlob stores content under blobs/<algo>/<hex> for digest, creating the
// directory the layout reader expects.
func writeBlob(t *testing.T, layoutPath, digest string, content []byte) {
	t.Helper()
	algo, hexPart, ok := strings.Cut(digest, ":")
	require.True(t, ok, "digest %q must be algo:hex", digest)
	dir := filepath.Join(layoutPath, "blobs", algo)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, hexPart), content, 0o600))
}

// ociLayoutContent builds a minimal but genuinely provider-accepted layout:
// index.json pointing at a real manifest blob pointing at a real config
// blob. Digests are computed over the bytes written, so the fixture passes
// the provider's own reads — not just the classifier's shape check.
func ociLayoutContent() (index, manifest, config []byte, manifestDigest string) {
	config = []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	configDigest := sha256Digest(config)
	manifest = []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[]}`, configDigest, len(config)))
	manifestDigest = sha256Digest(manifest)
	index = []byte(fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d}]}`, manifestDigest, len(manifest)))
	return index, manifest, config, manifestDigest
}

// writeOCILayoutDir writes the smallest directory the OCI directory provider
// accepts: oci-layout, an index.json carrying exactly one manifest, and the
// manifest plus config blobs it references. It returns the manifest digest
// so tests can name same/differing multi-manifest variants.
func writeOCILayoutDir(t *testing.T, path string) string {
	t.Helper()
	index, manifest, config, manifestDigest := ociLayoutContent()
	configDigest := sha256Digest(config)
	writeBlob(t, path, manifestDigest, manifest)
	writeBlob(t, path, configDigest, config)
	require.NoError(t, os.WriteFile(filepath.Join(path, "index.json"), index, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(path, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))
	return manifestDigest
}

// writeOCILayoutDirMissingBlob writes a well-formed layout whose manifest
// blob is absent: the provider rejects it (its manifest read fails) and
// Syft falls through to daemon/registry. This is the incomplete-layout
// probe the classifier must agree with.
func writeOCILayoutDirMissingBlob(t *testing.T, path string) {
	t.Helper()
	index, _, config, _ := ociLayoutContent()
	writeBlob(t, path, sha256Digest(config), config)
	require.NoError(t, os.WriteFile(filepath.Join(path, "index.json"), index, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(path, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))
}

// writeOCIArchive tars a provider-accepted layout without extracting it:
// indexEntryName controls the index.json entry spelling (e.g. "././index.json"
// exercises the provider's path cleaning), indexPad inflates the index past
// any size cap while keeping it decodable, and dropManifest omits the
// manifest blob to model the incomplete-archive probe.
func writeOCIArchive(t *testing.T, path, indexEntryName, indexPad string, dropManifest bool) {
	t.Helper()
	index, manifest, config, manifestDigest := ociLayoutContent()
	if indexPad != "" {
		padded := fmt.Sprintf(`{"schemaVersion":2,"annotations":{"pad":%q},"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d}]}`, indexPad, manifestDigest, len(manifest))
		index = []byte(padded)
	}
	configDigest := sha256Digest(config)
	entries := map[string][]byte{
		"oci-layout":   []byte(`{"imageLayoutVersion":"1.0.0"}`),
		indexEntryName: index,
		"blobs/sha256/" + strings.TrimPrefix(configDigest, "sha256:"):   config,
		"blobs/sha256/" + strings.TrimPrefix(manifestDigest, "sha256:"): manifest,
	}
	if dropManifest {
		delete(entries, "blobs/sha256/"+strings.TrimPrefix(manifestDigest, "sha256:"))
	}
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	tw := tar.NewWriter(f)
	defer func() { _ = tw.Close() }()
	// Explicit directory entries first: the provider's extraction only
	// creates parents for listed directories, like real buildah archives.
	for _, dirEntry := range []string{"blobs/", "blobs/sha256/"} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: dirEntry, Typeflag: tar.TypeDir, Mode: 0o755}))
	}
	for _, name := range sortedBlobKeys(entries) {
		body := entries[name]
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}))
		_, err = tw.Write(body)
		require.NoError(t, err)
	}
}

func sortedBlobKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// ociLayoutContentWithLayers builds layout content whose manifest references
// the given layer bodies: index, manifest, and config bytes, the manifest
// digest, and every blob body keyed by digest.
func ociLayoutContentWithLayers(layerBodies ...[]byte) (index, manifest, config []byte, manifestDigest, configDigest string, blobs map[string][]byte) {
	config = []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	configDigest = sha256Digest(config)
	blobs = make(map[string][]byte)
	var layersJSON strings.Builder
	for i, body := range layerBodies {
		digest := sha256Digest(body)
		blobs[digest] = body
		if i > 0 {
			layersJSON.WriteString(",")
		}
		fmt.Fprintf(&layersJSON, `{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}`, digest, len(body))
	}
	manifest = []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[%s]}`,
		sha256Digest(config), len(config), layersJSON.String()))
	manifestDigest = sha256Digest(manifest)
	blobs[manifestDigest] = manifest
	blobs[configDigest] = config
	index = []byte(fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d}]}`, manifestDigest, len(manifest)))
	return index, manifest, config, manifestDigest, configDigest, blobs
}

// tarMember is one ordered tar member; repeating a name models duplicate
// entries exactly as the extractor replays them.
type tarMember struct {
	name string
	body []byte
}

// writeTarOrdered tars members in order. With dirHeaders it adds explicit
// blob directories like real buildah archives (the provider's extraction
// only creates parents for listed directories); without them it models a
// parentless archive, whose regular blob members the extractor cannot open.
func writeTarOrdered(t *testing.T, path string, members []tarMember) {
	t.Helper()
	writeTarMembers(t, path, members, true)
}

// writeTarMembers tars members in order, optionally omitting explicit
// directory headers.
func writeTarMembers(t *testing.T, path string, members []tarMember, dirHeaders bool) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	tw := tar.NewWriter(f)
	defer func() { _ = tw.Close() }()
	if dirHeaders {
		for _, dirEntry := range []string{"blobs/", "blobs/sha256/"} {
			require.NoError(t, tw.WriteHeader(&tar.Header{Name: dirEntry, Typeflag: tar.TypeDir, Mode: 0o755}))
		}
	}
	for _, m := range members {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o600, Size: int64(len(m.body))}))
		_, err = tw.Write(m.body)
		require.NoError(t, err)
	}
}

// blobEntry maps a digest to its layout-relative tar entry name.
func blobEntry(digest string) string {
	return "blobs/" + digestPath(digest)
}

// gzipBytes compresses content.
func gzipBytes(t *testing.T, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(content)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// tinyLayerTar builds the smallest valid layer content: a tar with one file,
// returned compressed and uncompressed.
func tinyLayerTar(t *testing.T) (compressed, uncompressed []byte) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("hello")
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "hello.txt", Mode: 0o600, Size: int64(len(content))}))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	return gzipBytes(t, buf.Bytes()), buf.Bytes()
}

// requireDirectoryProviderVerdict runs the real OCI directory provider over
// path: the ground truth the classifier must agree with.
func requireDirectoryProviderVerdict(t *testing.T, path string, accept bool) {
	t.Helper()
	gen := stereoscopefile.NewTempDirGenerator("classify-probe")
	defer func() { _ = gen.Cleanup() }()
	_, err := ociprovider.NewDirectoryProvider(gen, path).Provide(context.Background())
	if accept {
		require.NoError(t, err, "provider must accept %q", path)
	} else {
		require.Error(t, err, "provider must reject %q", path)
	}
}

// requireArchiveProviderVerdict runs the real OCI archive provider over
// path: the ground truth the tarball classifier must agree with.
func requireArchiveProviderVerdict(t *testing.T, path string, accept bool) {
	t.Helper()
	gen := stereoscopefile.NewTempDirGenerator("classify-probe")
	defer func() { _ = gen.Cleanup() }()
	_, err := ociprovider.NewArchiveProvider(gen, path).Provide(context.Background())
	if accept {
		require.NoError(t, err, "provider must accept %q", path)
	} else {
		require.Error(t, err, "provider must reject %q", path)
	}
}

// Real-fixture rows for the provider-backed image-remainder check: each
// fixture is content the narrowed providers genuinely accept or reject, so
// the tests pin resolution instead of the old suffix heuristic.
func TestImageRemainderLocalFixtures(t *testing.T) {
	dir := t.TempDir()
	validTar := filepath.Join(dir, "imagetar")
	writeDockerTarball(t, validTar)
	colonTar := filepath.Join(dir, "dir:latest")
	writeDockerTarball(t, colonTar)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "plainrootfs"), 0o755))
	writeOCILayoutDir(t, filepath.Join(dir, "ocilayout"))
	plainFile := filepath.Join(dir, "nginx")
	require.NoError(t, os.WriteFile(plainFile, []byte("x"), 0o600))
	corruptTar := filepath.Join(dir, "bad.tar")
	require.NoError(t, os.WriteFile(corruptTar, []byte("not a tarball at all"), 0o600))

	// Valid extensionless tarball -> local (tarball provider has no ext gate).
	registry, scheme, err := classifyImageInput("image:"+validTar, osStatExists)
	assert.False(t, registry)
	assert.Equal(t, "image", scheme)
	assert.NoError(t, err)

	// Valid colon-named tarball -> local (literal path tried before any parse).
	registry, scheme, err = classifyImageInput("image:"+colonTar, osStatExists)
	assert.False(t, registry)
	assert.Equal(t, "image", scheme)
	assert.NoError(t, err)

	// Valid OCI layout dir -> local.
	registry, scheme, err = classifyImageInput("image:"+filepath.Join(dir, "ocilayout"), osStatExists)
	assert.False(t, registry)
	assert.Equal(t, "image", scheme)
	assert.NoError(t, err)

	// Plain directory and corrupt archive are rejected by the local
	// providers and fall through to daemon/registry: the temp paths are not
	// lowercase-parseable, so both land loud-invalid (loud either way).
	registry, _, err = classifyImageInput("image:"+filepath.Join(dir, "plainrootfs"), osStatExists)
	assert.False(t, registry)
	assert.NoError(t, err)
	registry, _, err = classifyImageInput("image:"+corruptTar, osStatExists)
	assert.False(t, registry)
	assert.NoError(t, err)

	// A plain local file named exactly like the remainder must NOT shadow
	// a parseable registry identity: grype's narrowed file providers reject
	// non-archives and fall through to the daemon pull.
	registry, _, err = classifyImageInput("image:nginx", osStatExists)
	assert.True(t, registry)
	assert.NoError(t, err)

	// Scheme-like remainder is never re-interpreted as local.
	registry, _, err = classifyImageInput("image:dir:latest", osStatExists)
	assert.True(t, registry)
	assert.NoError(t, err)

	// Missing absolute archive stays loud-local (scanner fails on the open).
	registry, _, err = classifyImageInput("image:"+filepath.Join(dir, "missing.tar"), osStatExists)
	assert.False(t, registry)
	assert.NoError(t, err)
}

// TestImageRemainderOCIDirectoryParity pins the classifier to the real OCI
// directory provider: every layout the provider accepts must classify
// local, and every layout it rejects must not.
func TestImageRemainderOCIDirectoryParity(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "ocivalid")
	writeOCILayoutDir(t, valid)
	incomplete := filepath.Join(dir, "ociincomplete")
	writeOCILayoutDirMissingBlob(t, incomplete)

	requireDirectoryProviderVerdict(t, valid, true)
	requireDirectoryProviderVerdict(t, incomplete, false)

	assert.True(t, isOCILayoutDir(valid), "provider-accepted layout must classify local")
	assert.False(t, isOCILayoutDir(incomplete), "provider-rejected layout (missing manifest blob) must not classify local")

	registry, scheme, err := classifyImageInput("image:"+valid, osStatExists)
	assert.False(t, registry)
	assert.Equal(t, "image", scheme)
	assert.NoError(t, err)
}

// TestImageRemainderOCIArchiveParity pins the tarball classifier to the
// real OCI archive provider across the exact gaps reported: normalized
// entry spellings (././index.json), indexes past the old 1 MiB cap,
// incomplete archives, and gzipped streams (the provider never gunzips).
func TestImageRemainderOCIArchiveParity(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.tar")
	writeOCIArchive(t, valid, "index.json", "", false)
	normalized := filepath.Join(dir, "normalized.tar")
	writeOCIArchive(t, normalized, "././index.json", "", false)
	large := filepath.Join(dir, "large.tar")
	writeOCIArchive(t, large, "index.json", strings.Repeat("p", 2<<20), false)
	incomplete := filepath.Join(dir, "incomplete.tar")
	writeOCIArchive(t, incomplete, "index.json", "", true)
	gzipped := filepath.Join(dir, "gzipped.tar")
	gzipFile(t, valid, gzipped)

	for path, accept := range map[string]bool{valid: true, normalized: true, large: true, incomplete: false, gzipped: false} {
		requireArchiveProviderVerdict(t, path, accept)
		assert.Equal(t, accept, isOCILayoutTarball(path), "classifier must agree with the provider on %q", path)
	}
}

// TestImageRemainderOCIDuplicateEntries pins the extractor's no-truncate
// overwrite semantics: duplicates replay in order at offset zero, so the
// first entry never wins by position and the last never wins by truncation.
func TestImageRemainderOCIDuplicateEntries(t *testing.T) {
	dir := t.TempDir()

	// Later valid index over an initial "{}": the provider materializes the
	// later content and accepts; first-wins would say registry.
	validIndex, _, _, validDigest, validConfigDigest, validBlobs := ociLayoutContentWithLayers()
	members := []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: []byte(`{}`)},
		{name: blobEntry(validDigest), body: validBlobs[validDigest]},
	}
	for digest, body := range validBlobs {
		if digest == validDigest {
			continue
		}
		members = append(members, tarMember{name: blobEntry(digest), body: body})
	}
	members = append(members, tarMember{name: "index.json", body: validIndex})
	dupValid := filepath.Join(dir, "dupvalid.tar")
	writeTarOrdered(t, dupValid, members)

	// Later truncated index (valid minus its last byte): the shorter body
	// overwrites the prefix and keeps the earlier tail, so the materialized
	// file is still the valid index. Last-wins would say registry.
	dupTruncated := filepath.Join(dir, "duptruncated.tar")
	writeTarOrdered(t, dupTruncated, []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: validIndex},
		{name: blobEntry(validDigest), body: validBlobs[validDigest]},
		{name: blobEntry(validConfigDigest), body: validBlobs[validConfigDigest]},
		{name: "index.json", body: validIndex[:len(validIndex)-1]},
	})

	// Later "{}" over a valid index: the materialized file is "{}" plus the
	// valid tail — undecodable — so both reject.
	dupBroken := filepath.Join(dir, "dupbroken.tar")
	writeTarOrdered(t, dupBroken, []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: validIndex},
		{name: blobEntry(validDigest), body: validBlobs[validDigest]},
		{name: blobEntry(validConfigDigest), body: validBlobs[validConfigDigest]},
		{name: "index.json", body: []byte(`{}`)},
	})

	// Duplicated layer blob (identical content twice): exercises the
	// temp-file overlay branch for layers; both accept.
	layerCompressed, _ := tinyLayerTar(t)
	layerIndex, _, _, _, _, layerBlobs := ociLayoutContentWithLayers(layerCompressed)
	dupLayerMembers := []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: layerIndex},
	}
	for digest, body := range layerBlobs {
		dupLayerMembers = append(dupLayerMembers, tarMember{name: blobEntry(digest), body: body})
	}
	for digest, body := range layerBlobs {
		dupLayerMembers = append(dupLayerMembers, tarMember{name: blobEntry(digest), body: body})
	}
	dupLayer := filepath.Join(dir, "duplayer.tar")
	writeTarOrdered(t, dupLayer, dupLayerMembers)

	for path, accept := range map[string]bool{dupValid: true, dupTruncated: true, dupBroken: false, dupLayer: true} {
		requireArchiveProviderVerdict(t, path, accept)
		assert.Equal(t, accept, isOCILayoutTarball(path), "classifier must agree with the provider on %q", path)
	}
}

// TestImageRemainderOCIParentDirectories pins the extractor's parent rule:
// regular members land only where a directory was materialized, because the
// extractor opens them without creating parents. An otherwise valid archive
// without blob directory headers is rejected by the provider and must be
// rejected here — under both absolute and registry-parseable relative names,
// since Syft falls through to the registry for such a local file.
func TestImageRemainderOCIParentDirectories(t *testing.T) {
	dir := t.TempDir()
	index, _, _, manifestDigest, _, blobs := ociLayoutContentWithLayers()
	members := []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: index},
	}
	for digest, body := range blobs {
		members = append(members, tarMember{name: blobEntry(digest), body: body})
	}
	_ = manifestDigest

	withDirs := filepath.Join(dir, "withdirs.tar")
	writeTarMembers(t, withDirs, members, true)
	parentless := filepath.Join(dir, "parentless.tar")
	writeTarMembers(t, parentless, members, false)

	requireArchiveProviderVerdict(t, withDirs, true)
	assert.True(t, isOCILayoutTarball(withDirs))
	requireArchiveProviderVerdict(t, parentless, false)
	assert.False(t, isOCILayoutTarball(parentless),
		"parentless blob members fail extraction, so the classifier must fall through")

	// Relative collision names: the parentless file resolves registry (the
	// scan Syft actually performs), the headed one stays local.
	relDir := t.TempDir()
	writeTarMembers(t, filepath.Join(relDir, "headed"), members, true)
	writeTarMembers(t, filepath.Join(relDir, "parentless"), members, false)
	t.Chdir(relDir)

	registry, _, err := classifyImageInput("image:headed", osStatExists)
	assert.False(t, registry)
	assert.NoError(t, err)
	registry, _, err = classifyImageInput("image:parentless", osStatExists)
	assert.True(t, registry, "parentless archive must fall through to registry")
	assert.NoError(t, err)
}

// TestImageRemainderOCICorruptContent pins the content-validation direction:
// present-but-corrupt configs and layers are rejected by the provider's
// reads, so the classifier must fall through instead of taking local
// identity for a registry-resolved scan.
func TestImageRemainderOCICorruptContent(t *testing.T) {
	dir := t.TempDir()
	layerCompressed, _ := tinyLayerTar(t)

	// Baseline with a real layer: both accept.
	goodIndex, _, _, _, goodConfigDigest, goodBlobs := ociLayoutContentWithLayers(layerCompressed)
	goodMembers := []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: goodIndex},
	}
	for digest, body := range goodBlobs {
		goodMembers = append(goodMembers, tarMember{name: blobEntry(digest), body: body})
	}
	goodArchive := filepath.Join(dir, "goodlayer.tar")
	writeTarOrdered(t, goodArchive, goodMembers)

	goodDir := filepath.Join(dir, "goodlayerdir")
	require.NoError(t, os.MkdirAll(goodDir, 0o755))
	for digest, body := range goodBlobs {
		writeBlob(t, goodDir, digest, body)
	}
	require.NoError(t, os.WriteFile(filepath.Join(goodDir, "index.json"), goodIndex, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(goodDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))

	// Corrupt config (present, undecodable).
	badConfigMembers := []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: goodIndex},
	}
	for digest, body := range goodBlobs {
		if digest == goodConfigDigest {
			body = []byte(`{invalid json`)
		}
		badConfigMembers = append(badConfigMembers, tarMember{name: blobEntry(digest), body: body})
	}
	badConfigArchive := filepath.Join(dir, "badconfig.tar")
	writeTarOrdered(t, badConfigArchive, badConfigMembers)

	badConfigDir := filepath.Join(dir, "badconfigdir")
	require.NoError(t, os.MkdirAll(badConfigDir, 0o755))
	for digest, body := range goodBlobs {
		if digest == goodConfigDigest {
			body = []byte(`{invalid json`)
		}
		writeBlob(t, badConfigDir, digest, body)
	}
	require.NoError(t, os.WriteFile(filepath.Join(badConfigDir, "index.json"), goodIndex, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(badConfigDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))

	// Corrupt layers (present, unreadable): raw garbage and gzip-wrapped garbage.
	layerDigest := ""
	for digest, body := range goodBlobs {
		if !bytes.Equal(body, layerCompressed) {
			continue
		}
		layerDigest = digest
	}
	require.NotEmpty(t, layerDigest, "layer blob must be addressable")

	badLayerRawMembers := []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: goodIndex},
	}
	for digest, body := range goodBlobs {
		if digest == layerDigest {
			body = []byte("not a tarball at all")
		}
		badLayerRawMembers = append(badLayerRawMembers, tarMember{name: blobEntry(digest), body: body})
	}
	badLayerRawArchive := filepath.Join(dir, "badlayerraw.tar")
	writeTarOrdered(t, badLayerRawArchive, badLayerRawMembers)

	badLayerGzipMembers := []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: goodIndex},
	}
	for digest, body := range goodBlobs {
		if digest == layerDigest {
			body = gzipBytes(t, []byte("decompresses fine, parses as nothing"))
		}
		badLayerGzipMembers = append(badLayerGzipMembers, tarMember{name: blobEntry(digest), body: body})
	}
	badLayerGzipArchive := filepath.Join(dir, "badlayergzip.tar")
	writeTarOrdered(t, badLayerGzipArchive, badLayerGzipMembers)

	badLayerDir := filepath.Join(dir, "badlayerdir")
	require.NoError(t, os.MkdirAll(badLayerDir, 0o755))
	for digest, body := range goodBlobs {
		if digest == layerDigest {
			body = []byte("not a tarball at all")
		}
		writeBlob(t, badLayerDir, digest, body)
	}
	require.NoError(t, os.WriteFile(filepath.Join(badLayerDir, "index.json"), goodIndex, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(badLayerDir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))

	requireDirectoryProviderVerdict(t, goodDir, true)
	assert.True(t, isOCILayoutDir(goodDir))
	requireDirectoryProviderVerdict(t, badConfigDir, false)
	assert.False(t, isOCILayoutDir(badConfigDir), "undecodable config must not classify local")
	requireDirectoryProviderVerdict(t, badLayerDir, false)
	assert.False(t, isOCILayoutDir(badLayerDir), "unreadable layer must not classify local")

	for path, accept := range map[string]bool{
		goodArchive: true, badConfigArchive: false,
		badLayerRawArchive: false, badLayerGzipArchive: false,
	} {
		requireArchiveProviderVerdict(t, path, accept)
		assert.Equal(t, accept, isOCILayoutTarball(path), "classifier must agree with the provider on %q", path)
	}
}

// TestImageRemainderOCIRelativeParity is the collision scenario: relative
// names that also parse as registry references, so a detection miss yields
// registry identity (not a loud-local absolute path that proves nothing).
// A colliding relative directory the provider rejects must resolve registry
// — the scan Grype actually performs — instead of taking local identity.
func TestImageRemainderOCIRelativeParity(t *testing.T) {
	dir := t.TempDir()
	writeOCILayoutDir(t, filepath.Join(dir, "nginx"))
	writeOCILayoutDirMissingBlob(t, filepath.Join(dir, "brokenimg"))
	writeOCIArchive(t, filepath.Join(dir, "pkg"), "index.json", "", false)
	writeOCIArchive(t, filepath.Join(dir, "normimg"), "././index.json", "", false)
	writeOCIArchive(t, filepath.Join(dir, "holeimg"), "index.json", "", true)
	writeMultiManifestLayout(t, filepath.Join(dir, "twinequal"), true)
	writeMultiManifestLayout(t, filepath.Join(dir, "twindiffer"), false)

	// Duplicate index (initial "{}", later valid) under a parseable name:
	// the provider materializes the later content, so this stays local.
	dupRelIndex, _, _, dupRelDigest, _, dupRelBlobs := ociLayoutContentWithLayers()
	dupRelMembers := []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: []byte(`{}`)},
	}
	for digest, body := range dupRelBlobs {
		dupRelMembers = append(dupRelMembers, tarMember{name: blobEntry(digest), body: body})
	}
	dupRelMembers = append(dupRelMembers, tarMember{name: "index.json", body: dupRelIndex})
	writeTarOrdered(t, filepath.Join(dir, "duprel"), dupRelMembers)
	_ = dupRelDigest

	// Corrupt config and corrupt layer under parseable names: the provider
	// rejects both, so both resolve registry.
	layerCompressed, _ := tinyLayerTar(t)
	badRelIndex, _, _, _, badRelConfigDigest, badRelBlobs := ociLayoutContentWithLayers(layerCompressed)
	badRelConfigMembers := []tarMember{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", body: badRelIndex},
	}
	for digest, body := range badRelBlobs {
		if digest == badRelConfigDigest {
			body = []byte(`{invalid json`)
		}
		badRelConfigMembers = append(badRelConfigMembers, tarMember{name: blobEntry(digest), body: body})
	}
	writeTarOrdered(t, filepath.Join(dir, "badrelconfig"), badRelConfigMembers)
	t.Chdir(dir)

	cases := []struct {
		input string
		local bool
	}{
		{"image:nginx", true},         // valid layout under a registry-parseable name
		{"image:pkg", true},           // valid extensionless archive
		{"image:normimg", true},       // normalized index entry spelling
		{"image:twinequal", true},     // several manifests, equal digests
		{"image:duprel", true},        // duplicate index, later valid wins
		{"image:brokenimg", false},    // missing blob: provider rejects, name parses registry
		{"image:holeimg", false},      // missing manifest blob in archive
		{"image:twindiffer", false},   // several manifests, differing digests
		{"image:badrelconfig", false}, // corrupt config: provider rejects
	}
	for _, tc := range cases {
		registry, _, err := classifyImageInput(tc.input, osStatExists)
		assert.Equal(t, !tc.local, registry, "%s must resolve %s", tc.input, map[bool]string{true: "local", false: "registry"}[tc.local])
		assert.NoError(t, err)
	}

	// A gzipped OCI stream is rejected by the provider (no gunzip) and must
	// resolve registry under a parseable relative name.
	gzipFile(t, filepath.Join(dir, "pkg"), filepath.Join(dir, "gzipimg"))
	registry, _, err := classifyImageInput("image:gzipimg", osStatExists)
	assert.True(t, registry, "gzipped OCI archive must fall through to registry")
	assert.NoError(t, err)
}

// writeMultiManifestLayout writes a layout whose index carries two
// manifests: the same digest twice when equal (provider-accepted) or two
// distinct digests (provider-rejected).
func writeMultiManifestLayout(t *testing.T, path string, equal bool) {
	t.Helper()
	_, manifest, config, manifestDigest := ociLayoutContent()
	configDigest := sha256Digest(config)
	writeBlob(t, path, manifestDigest, manifest)
	writeBlob(t, path, configDigest, config)
	second := manifestDigest
	if !equal {
		other := sha256Digest(append(manifest, byte('x')))
		writeBlob(t, path, other, append(manifest, byte('x')))
		second = other
	}
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d}]}`,
		manifestDigest, len(manifest), second, len(manifest)))
	require.NoError(t, os.WriteFile(filepath.Join(path, "index.json"), index, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(path, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))
	if equal {
		requireDirectoryProviderVerdict(t, path, true)
	} else {
		requireDirectoryProviderVerdict(t, path, false)
	}
}

// gzipFile compresses src to dst.
func gzipFile(t *testing.T, src, dst string) {
	t.Helper()
	content, err := os.ReadFile(src)
	require.NoError(t, err)
	f, err := os.Create(dst)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	gz := gzip.NewWriter(f)
	defer func() { _ = gz.Close() }()
	_, err = gz.Write(content)
	require.NoError(t, err)
}

// Grype resolves raw SBOM content before selector extraction: a valid SBOM
// file is scanned locally whatever its name — including selector-shaped
// spellings like "docker:nginx" that the selector branches would otherwise
// strip into a synthetic registry identity.
func TestRawSBOMInputTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	sbomDoc := `{"spdxVersion": "SPDX-2.3", "name": "test", "packages": []}`
	for _, name := range []string{"docker:nginx", "registry:nginx", "image:nginx", "report.json"} {
		path := filepath.Join(dir, name)
		// Colon-named files need their parent to exist; Join keeps them flat.
		require.NoError(t, os.WriteFile(path, []byte(sbomDoc), 0o600))

		registry, scheme, err := classifyImageInput(path, osStatExists)
		assert.False(t, registry, "raw SBOM %q must be non-registry", name)
		assert.Equal(t, "sbom", scheme)
		assert.NoError(t, err)

		assert.True(t, isNonRegistryForExceptions(path, osStatExists))

		_, scheme, err = imageAttributesForExceptions(path, osStatExists)
		assert.ErrorContains(t, err, "non-registry input")
		assert.Equal(t, "sbom", scheme)
	}

	// A non-text file of selector-shaped spelling keeps selector semantics:
	// grype's MIME gate rejects it before any SBOM decode is attempted.
	binPath := filepath.Join(dir, "docker:binary")
	require.NoError(t, os.WriteFile(binPath, []byte{0x00, 0x01, 0x02, 0x1f, 0x8b, 0x08}, 0o600))
	registry, scheme, err := classifyImageInput(binPath, osStatExists)
	assert.False(t, registry, "binary content is still non-registry via existence")
	assert.NotEqual(t, "sbom", scheme)
	assert.NoError(t, err)
}

// Explicit daemon/registry selectors resolve exception identity from the
// stripped remainder: "docker:nginx" shares CVEs with "nginx", and tagged
// forms like "docker:nginx:1.27" parse instead of failing as unparseable.
// The generic "registry", "daemon" and "pull" tags behave identically: grype
// strips every registered tag before resolution.
func TestRegistrySelectorResolvesStrippedIdentity(t *testing.T) {
	policies := []VulnerabilitiesIgnorePolicy{
		{
			Metadata:        Metadata{Name: "x"},
			Kind:            "VulnerabilitiesIgnorePolicy",
			Targets:         []Target{{DesignatorType: "Attributes", Attributes: Attributes{ImageName: "nginx"}}},
			Vulnerabilities: []string{"CVE-2023-42365"},
		},
	}
	for _, input := range []string{"docker:nginx", "docker:nginx:1.27", "podman:nginx", "containerd:nginx", "oci-registry:nginx", "oci-model:nginx", "registry:nginx", "registry:nginx:1.27", "daemon:nginx", "pull:nginx"} {
		vulns, _, err := getUniqueVulnerabilitiesAndSeverities(policies, input, true)
		require.NoError(t, err, "input %q must resolve", input)
		assert.Contains(t, vulns, "CVE-2023-42365", "input %q must share nginx CVEs", input)
	}
	_, _, err := getUniqueVulnerabilitiesAndSeverities(policies, "docker:!!!", true)
	assert.Error(t, err, "unparseable remainder must fail loudly")
}

// The preflight fail-fast mirror must agree with the resolver: stripped
// selectors that resolve must not trigger it, unresolvable ones must.
func TestIsNonRegistryForExceptionsMirrorsResolver(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"nginx:1.27", false},
		{"docker-archive:/tmp/x.tar", true},
		{"image:nginx", false},
		{"image:docker-archive:/tmp/x.tar", true},
		{"docker:nginx", false},
		{"docker:nginx:1.27", false},
		{"docker:!!!", true},
		{"podman:nginx", false},
		{"registry:nginx", false},
		{"registry:nginx:1.27", false},
		{"daemon:nginx", false},
		{"pull:nginx", false},
		{"registry:!!!", true},
		{"example.io/pull/nginx:v1", false},
		{"   ", true},
	}
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			assert.Equal(t, tt.want, isNonRegistryForExceptions(tt.image, osStatExists))
		})
	}
}

// Daemon/registry selectors never consult the filesystem at all: a local
// file named exactly like the stripped remainder must not shadow the daemon
// identity (grype narrows daemon selectors to daemon/pull providers, never
// file stat). The image-remainder path uses os.Stat directly instead of the
// injected bool, so a shadowing fixture proves nothing there — real-fixture
// shadowing is covered by TestImageRemainderLocalFixtures.
func TestDaemonSelectorIgnoresCollidingLocalFile(t *testing.T) {
	shadow := func(string) bool { return true } // every path "exists"
	attrs, _, err := imageAttributesForExceptions("docker:nginx", shadow)
	require.NoError(t, err)
	assert.Equal(t, "nginx", attrs.ImageName)
	assert.False(t, isNonRegistryForExceptions("docker:nginx", shadow))
}
