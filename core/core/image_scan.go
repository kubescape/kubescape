package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/anchore/go-homedir"
	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
	"github.com/distribution/reference"
	"github.com/gabriel-vasile/mimetype"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/sylabs/sif/v2/pkg/sif"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v4/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
)

// Data structure to represent attributes
type Attributes struct {
	Registry     string `json:"registry"`
	Organization string `json:"organization,omitempty"`
	ImageName    string `json:"imageName"`
	ImageTag     string `json:"imageTag,omitempty"`
}

// Data structure for a target
type Target struct {
	DesignatorType string     `json:"designatorType"`
	Attributes     Attributes `json:"attributes"`
}

// Data structure for metadata
type Metadata struct {
	Name string `json:"name"`
}

// Data structure for vulnerabilities and severities
type VulnerabilitiesIgnorePolicy struct {
	Metadata        Metadata `json:"metadata"`
	Kind            string   `json:"kind"`
	Targets         []Target `json:"targets"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Severities      []string `json:"severities"`
}

// Loads exception policies from exceptions json object.
func GetImageExceptionsFromFile(filePath string) ([]VulnerabilitiesIgnorePolicy, error) {
	// Read the JSON file
	jsonFile, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, fmt.Errorf("error reading exceptions file: %w", err)
	}

	// Unmarshal the JSON data into an array of VulnerabilitiesIgnorePolicy
	var policies []VulnerabilitiesIgnorePolicy
	err = json.Unmarshal(jsonFile, &policies)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling exceptions file: %w", err)
	}
	if err := validateImageExceptionTargetRegexes(policies); err != nil {
		return nil, fmt.Errorf("error validating exceptions file: %w", err)
	}

	return policies, nil
}

func validateImageExceptionTargetRegexes(policies []VulnerabilitiesIgnorePolicy) error {
	for policyIndex := range policies {
		policyName := policies[policyIndex].Metadata.Name
		if policyName == "" {
			policyName = fmt.Sprintf("#%d", policyIndex)
		}
		for targetIndex := range policies[policyIndex].Targets {
			attributes := policies[policyIndex].Targets[targetIndex].Attributes
			fields := []struct {
				name  string
				value string
			}{
				{name: "registry", value: attributes.Registry},
				{name: "organization", value: attributes.Organization},
				{name: "imageName", value: attributes.ImageName},
				{name: "imageTag", value: attributes.ImageTag},
			}
			for _, field := range fields {
				if _, err := regexp.Compile(field.value); err != nil {
					return fmt.Errorf("image exception policy %q target %d field %s contains an invalid regular expression: %w", policyName, targetIndex, field.name, err)
				}
			}
		}
	}
	return nil
}

// isRawSBOMInput mirrors grype's raw-SBOM resolution, which runs before any
// selector extraction (getSBOMReader: stdin → purl: → sbom: → isPossibleSBOM
// on the raw spelling → default). A literal file — including one whose name
// carries a scheme-shaped prefix such as "docker:nginx" — is opened and MIME
// sniffed; text/plain descendants decode as SBOM documents. The check is a
// single open plus a prefix sample, so misses cost one failed open.
func isRawSBOMInput(trimmed string) bool {
	expandedPath, err := homedir.Expand(trimmed)
	if err != nil {
		return false
	}
	f, err := os.Open(expandedPath)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	mType, err := mimetype.DetectReader(f)
	if err != nil {
		return false
	}
	for cur := mType; cur != nil; cur = cur.Parent() {
		if cur.Is("text/plain") {
			return true
		}
	}
	return false
}

// classifyImageInput reports whether img is a registry reference or a
// non-registry input (archive, local directory, SBOM, ...). It returns the
// detected scheme ("" when none) for error messages. stat reports local path
// existence and is injectable so tests stay hermetic; callers pass osStatExists.
//
// Classification uses exact input semantics in this order:
//
//	-1. raw SBOM content (grype's isPossibleSBOM runs before selector
//	   extraction): an existing text/plain-descendant file — whatever its
//	   name, including selector-shaped spellings like "docker:nginx" —
//	   decodes as an SBOM document → non-registry;
//	0. generic "image:" prefix (Syft's ImageTag; every stereoscope archive/SIF/
//	   OCI-directory provider is tagged "image" and grype strips that tag via
//	   ExtractSchemeSource before resolution) — peel exactly once, then
//	   resolve the remainder the way the narrowed image providers do (content
//	   validation, not a second scheme pass). Peeling once reproduces grype
//	   for every shape, including "image:image:nginx" where the remainder
//	   "image:nginx" correctly derives the synthetic identity
//	   docker.io/library/image:nginx.
//	1. known local-source scheme (docker-archive:, oci-dir:, dir:, purl:,
//	   local-file:, local-directory:, singularity:, snap:, ...) → non-registry;
//	2. the RAW trimmed input exists on disk → non-registry. Checking the raw
//	   string before any tag/digest stripping is deliberate: stripping first
//	   would let an unrelated local "team/my.tar" reject the valid registry
//	   reference "team/my.tar:v1", and would miss bare names like "rootfs" or
//	   "sbom.json". An existing local path always wins over registry
//	   interpretation — a loud error beats a silent exception skip;
//	3. unambiguous tarball path (absolute or ./-relative .tar/.tgz) →
//	   non-registry even when the file is absent (the scan itself will then
//	   fail loudly on the missing file, not silently on exceptions);
//	4. unparseable as a registry reference → non-registry;
//	5. otherwise registry.
func classifyImageInput(img string, stat func(string) bool) (registry bool, scheme string, errEmpty error) {
	trimmed := strings.TrimSpace(img)
	if trimmed == "" {
		return false, "", fmt.Errorf("image name cannot be empty")
	}
	if isRawSBOMInput(trimmed) {
		return false, "sbom", nil
	}
	if rest, prefix := peelGenericImageSelector(trimmed); prefix != "" {
		// Grype strips "image:" once and passes the remainder literally to
		// the narrowed image providers — no second scheme pass. Locality is
		// decided the way those providers decide it (content, not suffixes):
		// an ordinary local file (e.g. "nginx") is rejected by the file
		// providers and falls through to the daemon pull, while "dir:latest"
		// is never re-interpreted as a local dir source.
		if strings.TrimSpace(rest) == "" {
			return false, prefix, fmt.Errorf("image name cannot be empty")
		}
		if isImageRemainderLocal(rest) {
			return false, prefix, nil
		}
		if _, err := reference.ParseNormalizedNamed(rest); err != nil {
			return false, prefix, nil
		}
		return true, "", nil
	}
	return classifyRemainder(trimmed, stat)
}

// isImageRemainderLocal reports whether the remainder after a generic
// "image:" strip would be handled by grype's narrowed image providers as
// local content. It mirrors provider acceptance instead of guessing from
// suffixes or bare existence, because both directions disagree silently
// otherwise: an extensionless or colon-named tarball must be local, while a
// plain directory or corrupt archive must fall through to daemon/registry.
// Accepts: OCI-layout directories (layout + index with one manifest, or
// several with equal digests, plus a decoding config and layer reads for
// everything referenced — mirroring the OCI directory provider's gate and
// content validation), docker tarballs (tarball.ImageFromPath reads
// manifest+config only — no layer unpack), SIF images (header load), and
// OCI-layout tarballs (the provider's untar-then-directory-gate reproduced
// as an entry walk: cleaned names, duplicate overwrite with no truncation,
// complete index, decoding config, streamed layer reads, no gunzip).
// Anything else defers to the daemon parser, exactly like the providers'
// fallthrough.
func isImageRemainderLocal(rest string) bool {
	if rest == "" {
		return false
	}
	info, err := os.Stat(rest)
	if err != nil {
		// Absent absolute archive-ish path stays loud-local (the scanner
		// fails on the open, never silently), matching the bare pipeline's
		// tarball rule.
		lower := strings.ToLower(rest)
		isArchive := strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tgz") ||
			strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".sif")
		return isArchive && (strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "./") || strings.HasPrefix(rest, "../"))
	}
	if info.IsDir() {
		return isOCILayoutDir(rest)
	}
	return isTarballFile(rest) || isSIFFile(rest) || isOCILayoutTarball(rest)
}

// isOCILayoutDir mirrors the OCI directory provider's acceptance gate
// (pkg/image/oci directoryImageProvider.Provide) without unpacking layers
// to disk: a readable layout whose index carries exactly one manifest — or
// several with equal digests — whose manifest reads, whose config decodes,
// and whose layers all read as tar streams. Corrupt-but-present blobs are
// rejected and Syft falls through to daemon/registry; accepting them here
// would hand a registry-resolved scan a local identity.
func isOCILayoutDir(path string) bool {
	pathObj, err := layout.FromPath(path)
	if err != nil {
		return false
	}
	index, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return false
	}
	manifest, err := index.IndexManifest()
	if err != nil || len(manifest.Manifests) == 0 {
		return false
	}
	first := manifest.Manifests[0].Digest
	for _, m := range manifest.Manifests[1:] {
		if m.Digest != first {
			return false
		}
	}
	img, err := pathObj.Image(first)
	if err != nil {
		return false
	}
	raw, err := img.RawManifest()
	if err != nil {
		return false
	}
	var desc ociManifestBlobDescriptor
	if err := json.Unmarshal(raw, &desc); err != nil {
		return false
	}
	configBody, err := os.ReadFile(filepath.Join(path, "blobs", digestPath(desc.Config.Digest)))
	if err != nil {
		return false
	}
	var config v1.ConfigFile
	if err := json.Unmarshal(configBody, &config); err != nil {
		return false
	}
	for _, layer := range desc.Layers {
		f, err := os.Open(filepath.Join(path, "blobs", digestPath(layer.Digest)))
		if err != nil {
			return false
		}
		err = validateLayerStream(f)
		_ = f.Close()
		if err != nil {
			return false
		}
	}
	return true
}

// validateLayerStream validates one layer the way the provider's layer Read
// does: the blob must decompress (when compressed) and walk as a tar stream
// to EOF, and an entry escaping the layer root fails the read. Bodies stream
// without buffering and never touch disk.
func validateLayerStream(r io.Reader) error {
	head := make([]byte, 2)
	n, err := io.ReadFull(r, head)
	if err != nil {
		// Empty layers carry no content; anything else truncated is corrupt.
		return err
	}
	body := io.MultiReader(bytes.NewReader(head[:n]), r)
	if n == 2 && head[0] == 0x1f && head[1] == 0x8b {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		defer func() { _ = gz.Close() }()
		body = gz
	}
	return walkLayerTar(body)
}

// layerReadLimit bounds one layer-entry stream the way the provider bounds
// its per-file extraction reads (2 GiB): reaching it fails the read on both
// sides, and it keeps classification from unpacking bombs.
const layerReadLimit = 2 << 30

// walkLayerTar consumes a layer tar stream the way the provider's unpack
// does: every entry must parse, and an entry escaping the layer root fails
// the whole read.
func walkLayerTar(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, ok := tarEntryRelPath(hdr.Name); !ok {
			return fmt.Errorf("layer entry escapes layer root: %q", hdr.Name)
		}
		// Cap each entry like the provider caps each extracted file; the
		// cap resets per entry so large multi-file layers match provider
		// acceptance instead of failing stricter.
		n, err := io.Copy(io.Discard, io.LimitReader(tr, layerReadLimit+1))
		if err != nil {
			return err
		}
		if n > layerReadLimit {
			return fmt.Errorf("layer entry exceeds read limit")
		}
	}
}

// ociManifestBlobDescriptor is the minimal manifest shape needed to verify
// the blobs the provider's Read would unpack, without unpacking them.
type ociManifestBlobDescriptor struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

// isTarballFile mirrors the docker-archive provider: manifest.json plus its
// config must read. Reads metadata only, never layers.
func isTarballFile(path string) bool {
	img, err := tarball.ImageFromPath(path, nil)
	return err == nil && img != nil
}

// isSIFFile mirrors the SIF provider's acceptance: the container header must
// load read-only. UnloadContainer closes the handle immediately.
func isSIFFile(path string) bool {
	f, err := sif.LoadContainerFromPath(path, sif.OptLoadWithFlag(os.O_RDONLY))
	if err != nil {
		return false
	}
	_ = f.UnloadContainer()
	return true
}

// ociIndexManifestDescriptor is the minimal index.json shape needed to apply
// the manifest-count gate without a full layout parse.
type ociIndexManifestDescriptor struct {
	Manifests []struct {
		Digest string `json:"digest"`
	} `json:"manifests"`
}

// isOCILayoutTarball mirrors the OCI-archive provider without extracting:
// the provider untars to a temp dir (no gunzip — a gzipped stream fails the
// tar parse and falls through) and applies the directory gate there, so the
// walk reproduces both: entry names cleaned exactly the way filepath.Join
// cleans them on extraction, duplicates overlaid with the extractor's
// no-truncate semantics, the complete index decoded, the config decoded,
// and every layer streamed as a tar stream. Anything else fails closed to
// the daemon path.
func isOCILayoutTarball(path string) bool {
	indexBody, ok := walkTarEntries(path)
	if !ok {
		return false
	}
	var desc ociIndexManifestDescriptor
	if err := json.Unmarshal(indexBody, &desc); err != nil || len(desc.Manifests) == 0 {
		return false
	}
	first := desc.Manifests[0].Digest
	for _, m := range desc.Manifests[1:] {
		if m.Digest != first {
			return false
		}
	}
	manifestBody, err := overlayTarEntryBody(path, "blobs/"+digestPath(first))
	if err != nil {
		return false
	}
	var blobDesc ociManifestBlobDescriptor
	if err := json.Unmarshal(manifestBody, &blobDesc); err != nil {
		return false
	}
	configBody, err := overlayTarEntryBody(path, "blobs/"+digestPath(blobDesc.Config.Digest))
	if err != nil {
		return false
	}
	var config v1.ConfigFile
	if err := json.Unmarshal(configBody, &config); err != nil {
		return false
	}
	for _, layer := range blobDesc.Layers {
		if err := validateTarLayer(path, "blobs/"+digestPath(layer.Digest)); err != nil {
			return false
		}
	}
	return true
}

// digestPath maps an "algo:hex" digest to its layout-relative blob path.
// Malformed digests map to a path no entry can hold.
func digestPath(digest string) string {
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || hex == "" || strings.ContainsAny(hex, `/\.`) {
		return "\x00invalid"
	}
	return algo + "/" + hex
}

// overlayNoTruncate replays the provider's extraction write for one entry:
// the body lands at offset zero of the same path without truncation, so a
// longer body replaces the file while a shorter body overwrites the prefix
// and keeps the earlier tail.
func overlayNoTruncate(cur, body []byte) []byte {
	if len(body) >= len(cur) {
		out := make([]byte, len(body))
		copy(out, body)
		return out
	}
	out := make([]byte, len(cur))
	copy(out, cur)
	copy(out, body)
	return out
}

// walkTarEntries returns the final materialized index.json body of one
// plain-tar stream — duplicates overlaid with the extractor's no-truncate
// semantics, so the first entry never wins by position. ok is false when the
// stream is not a readable tar, an entry would escape the extraction root
// (the provider hard-fails the whole extraction on those), or no index.json
// is present. The index entry is bounded by the archive itself and the
// provider reads the extracted index.json whole, so no size cap applies
// here either.
func walkTarEntries(path string) (indexBody []byte, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false
		}
		rel, ok := tarEntryRelPath(hdr.Name)
		if !ok {
			return nil, false
		}
		if hdr.Typeflag != tar.TypeReg {
			// Only regular files are materialized by the provider's
			// extraction switch (directories are created, links skipped,
			// other types dropped), so only they satisfy anything.
			continue
		}
		if rel != "index.json" {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, false
		}
		indexBody = overlayNoTruncate(indexBody, body)
	}
	if indexBody == nil {
		return nil, false
	}
	return indexBody, true
}

// overlayTarEntryBody returns the final materialized body of the regular
// file at rel: every occurrence overlaid in order with the extractor's
// no-truncate semantics.
func overlayTarEntryBody(path, rel string) ([]byte, error) {
	var final []byte
	found := false
	err := streamTarEntryBodies(path, rel, func(body io.Reader) error {
		chunk, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		final = overlayNoTruncate(final, chunk)
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("entry not found: %q", rel)
	}
	return final, nil
}

// validateTarLayer validates the final materialized bytes of one layer
// entry the way the provider's layer Read does. A single occurrence streams
// straight through; duplicates overlay to a temp file first so validation
// sees exactly what extraction materialized, without buffering layers in
// memory.
func validateTarLayer(path, rel string) error {
	occurrences := 0
	err := streamTarEntryBodies(path, rel, func(io.Reader) error {
		occurrences++
		return nil
	})
	if err != nil {
		return err
	}
	if occurrences == 0 {
		return fmt.Errorf("entry not found: %q", rel)
	}
	if occurrences == 1 {
		return streamTarEntryBodies(path, rel, func(body io.Reader) error {
			return validateLayerStream(body)
		})
	}
	tmp, err := os.CreateTemp("", "oci-classify-layer-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		_ = tmp.Close()
		return err
	}
	err = streamTarEntryBodies(path, rel, func(body io.Reader) error {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		_, err = io.Copy(tmp, body)
		return err
	})
	if closeErr := tmp.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	f, err := os.Open(tmpName)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return validateLayerStream(f)
}

// streamTarEntryBodies calls fn with the body of every regular-file
// occurrence of rel in order, mirroring the same cleaning and rejection
// walkTarEntries applies. Bodies stream bounded by their entries.
func streamTarEntryBodies(path, rel string, fn func(io.Reader) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		entryRel, ok := tarEntryRelPath(hdr.Name)
		if !ok {
			return fmt.Errorf("entry escapes extraction root: %q", hdr.Name)
		}
		if entryRel != rel || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := fn(tr); err != nil {
			return err
		}
	}
}

// tarEntryRelPath cleans a tar entry name exactly the way the provider's
// extraction does (filepath.Join with the destination) and reports the path
// relative to the extraction root. ok is false when the entry would escape
// the root — the provider hard-fails the whole extraction on such an entry,
// so the archive is not a usable OCI layout.
func tarEntryRelPath(name string) (rel string, ok bool) {
	const dst = string(filepath.Separator) + "oci-classify"
	target := filepath.Join(dst, name)
	rel, err := filepath.Rel(dst, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// classifyRemainder runs steps 1-5 of the pipeline on an already-trimmed,
// already-peeled input. Split from classifyImageInput so the generic "image:"
// peel happens exactly once: a nested "image:image:nginx" remainder keeps its
// inner prefix and derives docker.io/library/image:nginx, matching grype.
func classifyRemainder(trimmed string, stat func(string) bool) (registry bool, scheme string, errEmpty error) {
	if scheme := detectScheme(trimmed); scheme != "" {
		return false, scheme, nil
	}
	if stat != nil && stat(trimmed) {
		return false, "", nil
	}
	lower := strings.ToLower(trimmed)
	isTar := strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz")
	if isTar && (strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "./") || strings.HasPrefix(trimmed, "../")) {
		return false, "", nil
	}
	if _, err := reference.ParseNormalizedNamed(trimmed); err != nil {
		return false, "", nil
	}
	return true, "", nil
}

// peelGenericImageSelector detects Syft's unstripped generic "image:" prefix
// (all stereoscope-backed providers are tagged "image" and grype strips that
// tag via SplitN on the first colon) without treating registry refs that
// merely contain a slash before the colon as selectors. One peel only.
func peelGenericImageSelector(trimmed string) (string, string) {
	lower := strings.ToLower(trimmed)
	idx := strings.Index(lower, ":")
	if idx < 0 {
		return "", ""
	}
	candidate := lower[:idx]
	// No slash guard needed: the only accepted candidate is the bare word
	// "image", which cannot contain one — so "example.io/image/foo:v1"
	// never peels.
	if candidate != "image" {
		return "", ""
	}
	rest := strings.TrimSpace(trimmed[idx+1:])
	return rest, trimmed[:idx]
}

// selectorKind classifies how grype resolves an explicit source selector
// after ExtractSchemeSource strips it.
type selectorKind int

const (
	selectorNone selectorKind = iota
	// selectorLocal: the remainder is opaque local content; the input is
	// fail-closed non-registry for exception purposes.
	selectorLocal
	// selectorRegistry: the remainder must parse as a registry reference;
	// exception identity derives from it.
	selectorRegistry
	// selectorImage: Syft's generic tag; the remainder goes to the narrowed
	// image providers (see classifyImageInput step 0).
	selectorImage
)

// sourceSelectors is the effective provider contract, enumerated once and
// shared by classification (detectScheme), preflight
// (isNonRegistryForExceptions) and attribute derivation
// (imageAttributesForExceptions). Verified against grype v0.104.1 / syft
// v1.42.3 and the replaced Stereoscope: FileTag..RegistryTag, provider
// Names, syft local-file/local-directory/snap/oci-model, and ImageTag on
// every stereoscope-backed provider. Daemon/registry schemes ("docker",
// "podman", "containerd", "oci-registry", "oci-model") plus the generic
// "registry", "daemon" and "pull" tags resolve to registry pulls, so their
// remainders carry derivable registry identity.
var sourceSelectors = []struct {
	name string
	kind selectorKind
}{
	{"docker-archive", selectorLocal},
	{"oci-archive", selectorLocal},
	{"oci-dir", selectorLocal},
	{"dir", selectorLocal},
	{"file", selectorLocal},
	{"sbom", selectorLocal},
	{"purl", selectorLocal},
	{"local-file", selectorLocal},
	{"local-directory", selectorLocal},
	{"singularity", selectorLocal},
	{"snap", selectorLocal},
	{"docker", selectorRegistry},
	{"podman", selectorRegistry},
	{"containerd", selectorRegistry},
	{"oci-registry", selectorRegistry},
	{"oci-model", selectorRegistry},
	{"registry", selectorRegistry},
	{"daemon", selectorRegistry},
	{"pull", selectorRegistry},
	{"image", selectorImage},
}

// lookupSourceSelector returns the contract kind for a lowercased,
// slash-free scheme candidate, or selectorNone when it is not a selector.
func lookupSourceSelector(s string) selectorKind {
	for _, sel := range sourceSelectors {
		if sel.name == s {
			return sel.kind
		}
	}
	return selectorNone
}

// isKnownInputScheme reports whether s is a local-source scheme that can
// never denote a registry reference.
func isKnownInputScheme(s string) bool {
	return lookupSourceSelector(s) == selectorLocal
}

// isRegistrySelectorScheme reports whether s is a selector whose remainder
// must parse as a registry reference (daemon/registry pulls and the generic
// registry/daemon/pull tags).
func isRegistrySelectorScheme(s string) bool {
	return lookupSourceSelector(s) == selectorRegistry
}

// detectScheme extracts a known local-source scheme prefix (preserving the
// original casing for error messages), or "" when the input has none. A
// registry port (myregistry.io:5000/...) never qualifies: its prefix contains
// "/" (or is not a known scheme), so tagged registry refs stay registry.
func detectScheme(trimmed string) string {
	lower := strings.ToLower(trimmed)
	if i := strings.Index(lower, ":"); i != -1 {
		candidate := lower[:i]
		if !strings.Contains(candidate, "/") && isKnownInputScheme(candidate) {
			return trimmed[:i]
		}
	}
	return ""
}

// osStatExists is the production existence check passed as classifyImageInput's stat.
func osStatExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// isNonRegistryInput is the production wrapper around classifyImageInput.
func isNonRegistryInput(img string) bool {
	return isNonRegistryInputWithStat(img, osStatExists)
}

// isNonRegistryInputWithStat is the injectable-stat variant so exception
// plumbing stays hermetic in tests; production passes osStatExists.
func isNonRegistryInputWithStat(img string, stat func(string) bool) bool {
	registry, _, errEmpty := classifyImageInput(img, stat)
	return errEmpty != nil || !registry
}

func stripRegistrySelectorScheme(trimmed string) (string, string, bool) {
	idx := strings.Index(trimmed, ":")
	if idx < 0 {
		return "", "", false
	}
	candidateLower := strings.ToLower(trimmed[:idx])
	if strings.Contains(candidateLower, "/") || !isRegistrySelectorScheme(candidateLower) {
		return "", "", false
	}
	rest := strings.TrimSpace(trimmed[idx+1:])
	return rest, trimmed[:idx], true
}

func imageAttributesForExceptions(image string, stat func(string) bool) (Attributes, string, error) {
	trimmed := strings.TrimSpace(image)
	// Raw-SBOM content wins before any selector handling, mirroring grype's
	// getSBOMReader order (purl:/sbom: cases operate on stripped paths and
	// cannot collide with a literal existing file of the full spelling).
	if isRawSBOMInput(trimmed) {
		return Attributes{}, "sbom", fmt.Errorf("image exceptions cannot target non-registry input %q (detected %q): scan by registry reference or remove --exceptions", image, "sbom")
	}
	if rest, scheme, ok := stripRegistrySelectorScheme(trimmed); ok {
		// Daemon/registry selectors never touch the filesystem (grype
		// narrows to daemon/pull providers), so the remainder skips the
		// existence/archive pipeline and goes straight to registry parse:
		// a local file named like the remainder must not shadow it.
		if rest == "" {
			return Attributes{}, scheme, fmt.Errorf("image name cannot be empty")
		}
		if attrs, err := getAttributesFromImage(rest); err == nil {
			return attrs, "", nil
		}
		return Attributes{}, scheme, fmt.Errorf("image exceptions cannot target non-registry input %q (detected %q): scan by registry reference or remove --exceptions", image, scheme)
	}
	if rest, _ := peelGenericImageSelector(trimmed); rest != "" {
		if rest == "" {
			return Attributes{}, "", fmt.Errorf("image name cannot be empty")
		}
		if isImageRemainderLocal(rest) {
			_, scheme, _ := classifyImageInput(image, stat)
			return Attributes{}, scheme, fmt.Errorf("image exceptions cannot target non-registry input %q (detected %q): scan by registry reference or remove --exceptions", image, scheme)
		}
		if attrs, err := getAttributesFromImage(rest); err == nil {
			return attrs, "", nil
		}
		return Attributes{}, "", fmt.Errorf("failed to generate image attributes for %q: %w", image, fmt.Errorf("unable to parse stripped remainder %q", rest))
	}
	if _, _, errEmpty := classifyImageInput(image, stat); errEmpty != nil {
		return Attributes{}, "", errEmpty
	}
	if isNonRegistryInputWithStat(image, stat) {
		_, scheme, _ := classifyImageInput(image, stat)
		return Attributes{}, scheme, fmt.Errorf("image exceptions cannot target non-registry input %q (detected %q): scan by registry reference or remove --exceptions", image, scheme)
	}
	attrs, err := getAttributesFromImage(image)
	if err != nil {
		return Attributes{}, "", fmt.Errorf("failed to generate image attributes for %q: %w", image, err)
	}
	return attrs, "", nil
}

func matchPolicies(policies []VulnerabilitiesIgnorePolicy, attrs Attributes) ([]string, []string) {
	uniqueVulns := make(map[string][]string)
	uniqueSevers := make(map[string][]string)
	for _, policy := range policies {
		if isTargetImage(policy.Targets, attrs) {
			for _, vulnerability := range policy.Vulnerabilities {
				// grype's IgnoreRule matching is case-sensitive and advisory
				// sources do not share a single casing convention: CVE IDs
				// are uppercase, while GHSA IDs keep a lowercase suffix
				// (e.g. "GHSA-jc7w-c686-c4v9"). Emit the trimmed original
				// casing plus the uppercased and lowercased forms so users
				// can list the ID in any casing without the filter silently
				// missing the match (kubescape issue #1870).
				vulnerability = strings.TrimSpace(vulnerability)
				if vulnerability == "" {
					continue
				}
				uniqueVulns[vulnerability] = append(uniqueVulns[vulnerability], vulnerability)
				vulnerabilityUppercase := strings.ToUpper(vulnerability)
				if vulnerabilityUppercase != vulnerability {
					uniqueVulns[vulnerabilityUppercase] = append(uniqueVulns[vulnerabilityUppercase], vulnerability)
				}
				vulnerabilityLowercase := strings.ToLower(vulnerability)
				if vulnerabilityLowercase != vulnerability && vulnerabilityLowercase != vulnerabilityUppercase {
					uniqueVulns[vulnerabilityLowercase] = append(uniqueVulns[vulnerabilityLowercase], vulnerability)
				}
			}
			for _, severity := range policy.Severities {
				severityUppercase := strings.ToUpper(severity)
				uniqueSevers[severityUppercase] = append(uniqueSevers[severityUppercase], severity)
			}
		}
	}
	uniqueVulnsList := make([]string, 0, len(uniqueVulns))
	for vuln := range uniqueVulns {
		uniqueVulnsList = append(uniqueVulnsList, vuln)
	}
	uniqueSeversList := make([]string, 0, len(uniqueSevers))
	for sever := range uniqueSevers {
		uniqueSeversList = append(uniqueSeversList, sever)
	}
	return uniqueVulnsList, uniqueSeversList
}

func isNonRegistryForExceptions(img string, stat func(string) bool) bool {
	trimmed := strings.TrimSpace(img)
	if isRawSBOMInput(trimmed) {
		return true
	}
	if rest, _, ok := stripRegistrySelectorScheme(trimmed); ok {
		// Mirror the resolver: daemon/registry selectors skip the
		// filesystem pipeline; only an unparseable remainder is loud.
		if rest == "" {
			return true
		}
		_, err := getAttributesFromImage(rest)
		return err != nil
	}
	if rest, _ := peelGenericImageSelector(trimmed); rest != "" {
		if rest == "" {
			return true
		}
		if isImageRemainderLocal(rest) {
			return true
		}
		_, err := getAttributesFromImage(rest)
		return err != nil
	}
	if _, _, errEmpty := classifyImageInput(img, stat); errEmpty != nil {
		return true
	}
	return isNonRegistryInputWithStat(img, stat)
}

// getAttributesFromImage identifies registry, organization, image name and
// tag from a registry-style image reference. Non-registry inputs fail here;
// callers must not fall back to zero-value attributes (see
// getUniqueVulnerabilitiesAndSeverities for the fail-closed contract).
func getAttributesFromImage(imgName string) (Attributes, error) {
	ref, err := reference.ParseNormalizedNamed(imgName)
	if err != nil {
		return Attributes{}, err
	}

	registry := reference.Domain(ref)
	path := reference.Path(ref)

	organization := ""
	imageName := path
	if idx := strings.LastIndex(path, "/"); idx != -1 {
		organization = path[:idx]
		imageName = path[idx+1:]
	}

	imageTag := "latest"
	if tagged, ok := ref.(reference.Tagged); ok {
		imageTag = tagged.Tag()
	} else if digested, ok := ref.(reference.Digested); ok {
		// No explicit tag on a digest-pinned reference: fall back to the
		// digest as ImageTag (deliberate choice, not Docker/OCI reference
		// semantics - Docker resolves a "name:tag@digest" reference by the
		// digest, ignoring the tag, but for *exception-policy matching* the
		// tag the user wrote is what they meant to target). This means an
		// exception policy that targets a specific ImageTag (e.g. "v3.*")
		// cannot match a purely digest-pinned scan, since ImageTag will be
		// the digest instead; only Registry/Organization/ImageName targets
		// (and an ImageTag target of "" - "any tag") can match it.
		imageTag = digested.Digest().String()
	}

	attributes := Attributes{
		Registry:     registry,
		Organization: organization,
		ImageName:    imageName,
		ImageTag:     imageTag,
	}

	return attributes, nil
}

// regexStringMatch reports whether pattern matches target. Unanchored
// matching is intentional (exception targets use partial regexes); an
// invalid pattern logs and returns false rather than panicking.
func regexStringMatch(pattern, target string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to generate regular expression: %s", err))
		return false
	}

	if re.MatchString(target) {
		return true
	}

	return false
}

// isTargetImage reports whether the image attributes match any exception
// policy target (registry, organization, image name, tag — all regex).
func isTargetImage(targets []Target, attributes Attributes) bool {
	for _, target := range targets {
		if regexStringMatch(target.Attributes.Registry, attributes.Registry) && regexStringMatch(target.Attributes.Organization, attributes.Organization) && regexStringMatch(target.Attributes.ImageName, attributes.ImageName) && regexStringMatch(target.Attributes.ImageTag, attributes.ImageTag) {
			return true
		}
	}

	return false
}

// Generates a list of unique CVE-IDs and the severities which are to be excluded for
// the image being scanned. Returns an error when exceptions are configured for
// a non-registry input (archive, local directory, SBOM, ...), where exception
// targets are undefinable — callers must surface it per image, never swallow it.
//
// exceptionsConfigured tracks whether --exceptions was explicitly passed,
// independently of how many policies the file held: an explicitly configured
// but empty file (valid [] or null) must still reject non-registry inputs,
// while an unconfigured run keeps the old lenient path.
func getUniqueVulnerabilitiesAndSeverities(policies []VulnerabilitiesIgnorePolicy, image string, exceptionsConfigured bool) ([]string, []string, error) {
	if len(policies) == 0 && !exceptionsConfigured {
		return nil, nil, nil
	}

	// Derive the registry identity grype resolves after stripping any
	// Syft/stereoscope selector; the raw input is preserved for scanner
	// dispatch (job.Image keeps the original).
	imageAttributes, _, err := imageAttributesForExceptions(image, osStatExists)
	if err != nil {
		return nil, nil, err
	}

	// Iterate over each policy and its vulnerabilities/severities.
	// Include the exceptions only if the image is one of the targets.
	vulns, severs := matchPolicies(policies, imageAttributes)

	return vulns, severs, nil
}

// applyRegistryMapping replaces the registry part of the image name if a match
// is found in the provided mapping. The returned bool indicates whether a
// mapping key actually matched; callers should only retry when matched is true.
// Non-registry inputs are never mapped (a mapping key can never match them).
func applyRegistryMapping(imgName string, registryMapping map[string]string) (string, bool, error) {
	if len(registryMapping) == 0 {
		return imgName, false, nil
	}
	// Registry mapping can never match a non-registry input; skip parsing so
	// archives don't produce confusing mapping errors.
	if isNonRegistryInput(imgName) {
		return imgName, false, nil
	}
	canonicalImageName, err := cautils.NormalizeImageName(imgName)
	if err != nil {
		return "", false, err
	}
	tokens := strings.Split(canonicalImageName, "/")
	registry := tokens[0]
	if altRegistry, ok := registryMapping[registry]; ok {
		tokens[0] = altRegistry
		mappedName := strings.Join(tokens, "/")
		if _, err := reference.ParseNormalizedNamed(mappedName); err != nil {
			return "", false, fmt.Errorf("invalid image reference after applying registry mapping: %w", err)
		}
		return mappedName, true, nil
	}
	return imgName, false, nil
}

// isResolutionError checks if the error is related to unreachable registry hosts
// (DNS resolution failures, connection refused, timeouts). It uses typed error
// checks first and falls back to substring matching for wrapped errors.
func isResolutionError(err error) bool {
	if err == nil {
		return false
	}

	// Typed error checks — stable across Go and library versions.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Belt-and-braces: substring fallback for deeply wrapped errors where
	// the typed original has been lost.
	errStr := err.Error()
	return strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout")
}

// scanWithRegistryMapping attempts to scan an image and, on a resolution error,
// retries using a mapped registry if one is configured. It returns the scan
// results or a combined error preserving both the original and fallback context.
type imageScanService interface {
	Scan(context.Context, string, imagescan.RegistryCredentials, []string, []string) (*cautils.ImageScanData, error)
}

type platformImageScanService interface {
	ScanWithOptions(context.Context, string, imagescan.RegistryCredentials, []string, []string, imagescan.ScanOptions) (*cautils.ImageScanData, error)
}

func scanImageForPlatform(
	ctx context.Context,
	svc imageScanService,
	img string,
	creds imagescan.RegistryCredentials,
	vulnExceptions, sevExceptions []string,
	platform string,
) (*cautils.ImageScanData, error) {
	if platform == "" {
		return svc.Scan(ctx, img, creds, vulnExceptions, sevExceptions)
	}

	platformSvc, ok := svc.(platformImageScanService)
	if !ok {
		return nil, fmt.Errorf("image scanner does not support target platform %q", platform)
	}
	return platformSvc.ScanWithOptions(ctx, img, creds, vulnExceptions, sevExceptions, imagescan.ScanOptions{Platform: platform})
}

func scanWithRegistryMapping(
	ctx context.Context,
	svc imageScanService,
	img string,
	credsList []imagescan.RegistryCredentials,
	registryMapping map[string]string,
	vulnExceptions, sevExceptions []string,
	platform string,
) (*cautils.ImageScanData, error) {
	if len(credsList) == 0 {
		credsList = []imagescan.RegistryCredentials{{}}
	}

	var lastErr error
	var scanData *cautils.ImageScanData

	for _, creds := range credsList {
		scanData, lastErr = scanImageForPlatform(ctx, svc, img, creds, vulnExceptions, sevExceptions, platform)
		if lastErr == nil {
			return scanData, nil
		}

		if len(registryMapping) > 0 && isResolutionError(lastErr) {
			logger.L().Warning(fmt.Sprintf("Failed to scan image %s: %s. Trying registry mapping...", img, lastErr))

			mappedImage, matched, mapErr := applyRegistryMapping(img, registryMapping)
			if mapErr == nil && matched {
				logger.L().Info(fmt.Sprintf("Scanning mapped image %s (original: %s)...", mappedImage, img))
				scanData, fallbackErr := scanImageForPlatform(ctx, svc, mappedImage, creds, vulnExceptions, sevExceptions, platform)
				if fallbackErr == nil {
					return scanData, nil
				}
				lastErr = fmt.Errorf("scan failed for %s (%w) and for mapped image %s: %w", img, lastErr, mappedImage, fallbackErr)
			} else if mapErr != nil {
				lastErr = fmt.Errorf("scan failed for %s (%w) and failed to construct mapped image: %w", img, lastErr, mapErr)
			}
		}
	}

	return nil, lastErr
}

// ScanImage scans imgScanInfo.Image using ks.Context() as the operation's
// context. It is a compatibility wrapper around ScanImageContext for callers
// that have not migrated to passing their own context explicitly; see
// ScanImageContext's documentation for why that matters when a *Kubescape
// instance is reused or scan operations can overlap.
func (ks *Kubescape) ScanImage(imgScanInfo *ksmetav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error) {
	return ks.ScanImageContext(ks.Context(), imgScanInfo, scanInfo)
}

// ScanImageContext scans every image in imgScanInfo.Images bound to the given
// ctx for its complete execution, rather than re-reading ks.Context() at each
// stage as ScanImage's predecessor did (matching Kubescape.Scan's own
// ScanContext migration, #3237). Callers that need a deadline or cancellation
// should derive ctx themselves and pass it in directly, instead of calling
// ks.SetContext beforehand: mutating the shared *Kubescape's context is not
// safe if the instance is reused or another operation could run
// concurrently against it. The images share one vulnerability database load
// and the worker pool the cluster scan already uses, so an image that fails
// never hides the results of the ones that succeeded.
//
// Image exceptions (--exceptions) require registry references. A non-registry
// input (archive, local directory, SBOM) combined with exceptions is reported
// as a per-image "Image Exceptions/Unsupported Input" error: siblings still
// scan, the report covers succeeded images, and the returned error keeps the
// exit code non-zero. Thresholds are evaluated over succeeded scans only.
func (ks *Kubescape) ScanImageContext(ctx context.Context, imgScanInfo *ksmetav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error) {
	images := imgScanInfo.Images
	if len(images) == 0 {
		return false, fmt.Errorf("no image provided to scan")
	}

	logger.L().Start(imageScanStartMessage(images))

	var exceptionPolicies []VulnerabilitiesIgnorePolicy
	var err error
	if imgScanInfo.Exceptions != "" {
		exceptionPolicies, err = GetImageExceptionsFromFile(imgScanInfo.Exceptions)
		if err != nil {
			logger.L().StopError(fmt.Sprintf("Failed to load exceptions from file: %s", imgScanInfo.Exceptions))
			return false, err
		}
	}

	// Fail fast before the Grype DB download when every image is a
	// non-registry input combined with --exceptions. The guard keys on flag
	// presence, not policy count: an explicitly configured empty file still
	// rejects. Source selection mirrors the resolver (isNonRegistryForExceptions)
	// so stripped selectors (image:, docker:, ...) never false-trigger here
	// while producing per-image errors later. Mixed scans fall through
	// to per-image errors so valid registry siblings still scan. Every image
	// gets its own categorized error (with its own scheme) so multi-archive
	// runs report each offender, not just the first.
	if imgScanInfo.Exceptions != "" {
		allNonRegistry := true
		for _, image := range images {
			if _, _, errEmpty := classifyImageInput(image, osStatExists); errEmpty != nil {
				allNonRegistry = false
				break
			}
			if !isNonRegistryForExceptions(image, osStatExists) {
				allNonRegistry = false
				break
			}
		}
		if allNonRegistry {
			errs := make([]error, 0, len(images))
			for _, image := range images {
				// Scheme comes from the resolver so stripped selectors
				// report the same detected value as per-job errors.
				_, scheme, _ := imageAttributesForExceptions(image, osStatExists)
				errs = append(errs, fmt.Errorf("[%s] image exceptions cannot target non-registry input %q (detected %q): scan by registry reference or remove --exceptions %q", ErrCategoryExceptionUnsupported, image, scheme, imgScanInfo.Exceptions))
			}
			err := errors.Join(errs...)
			logger.L().StopError(err.Error())
			return false, err
		}
	}

	failOnStale, maxDBAge := imagescan.ResolveDBAgeGate(scanInfo.FailOnStaleDB, scanInfo.FailOnStaleDBSet, scanInfo.MaxDBAge, scanInfo.MaxDBAgeSet)
	distCfg, installCfg, shouldUpdate, err := imagescan.NewDefaultDBConfig(scanInfo.ListingURL, scanInfo.SkipDBUpdate, failOnStale)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Invalid Grype database URL '%s': %v", scanInfo.ListingURL, err))
		return false, err
	}
	svc, err := imagescan.NewScanServiceWithMatchersAndSources(distCfg, installCfg, imgScanInfo.UseDefaultMatchers, nil, shouldUpdate)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to initialize image scanner: %s", err))
		return false, err
	}
	defer svc.Close()

	// Warn on a stale vulnerability DB (always); fail only with --fail-on-stale-db.
	// The failure is deferred until after results are printed so the user keeps the report.
	staleDBErr := imagescan.EnforceDBAge(svc, shouldUpdate, failOnStale, maxDBAge)

	jobs := buildImageScanJobs(imgScanInfo, scanInfo, exceptionPolicies)

	resultsHandler := resultshandling.NewResultsHandler(nil, nil, nil)
	scanErr := scanImageJobs(ctx, svc, scanInfo.ImageScanConcurrency, jobs, resultsHandler)
	scanErr = unwrapSingleImageError(scanErr)
	if len(resultsHandler.ImageScanData) == 0 {
		logger.L().StopError(imageScanFailureMessage(images))
		return false, scanErr
	}
	logger.L().StopSuccess(imageScanSuccessMessage(images, resultsHandler.ImageScanData))

	scanInfo.SetScanType(cautils.ScanTypeImage)

	// Printers open their output files on construction, so they are built only
	// once at least one image has produced results.
	outputPrinters, err := GetOutputPrinters(scanInfo, ctx, "")
	if err != nil {
		return false, errors.Join(scanErr, err)
	}
	resultsHandler.PrinterObjs = outputPrinters
	resultsHandler.UiPrinter = GetUIPrinter(ctx, scanInfo, "")

	threshold := imagescan.ParseSeverity(scanInfo.FailThresholdSeverity)
	exceedsSeverityThreshold := false
	for i := range resultsHandler.ImageScanData {
		if svc.ExceedsSeverityThreshold(threshold, resultsHandler.ImageScanData[i].Matches, scanInfo.OnlyFixable) {
			exceedsSeverityThreshold = true
			break
		}
	}

	return exceedsSeverityThreshold, errors.Join(scanErr, staleDBErr, resultsHandler.HandleResults(ctx, scanInfo))
}

// buildImageScanJobs converts imgScanInfo.Images into per-image scan jobs.
// Exceptions are resolved per image; resolution failures are stored on the
// job (ExceptionErr) rather than aborting the whole run, so a non-registry
// input never poisons sibling registry images.
func buildImageScanJobs(imgScanInfo *ksmetav1.ImageScanInfo, scanInfo *cautils.ScanInfo, exceptionPolicies []VulnerabilitiesIgnorePolicy) []ImageScanJob {
	creds := imagescan.RegistryCredentials{
		Authority: imgScanInfo.Authority,
		Username:  imgScanInfo.Username,
		Password:  imgScanInfo.Password,
		Token:     imgScanInfo.Token,
	}

	jobs := make([]ImageScanJob, 0, len(imgScanInfo.Images))
	for _, image := range imgScanInfo.Images {
		// Resolving exceptions parses the image as a registry reference, which
		// archive and directory references are not, so it stays behind the
		// check for the explicitly configured flag — not the parsed policy
		// count, so an empty-but-configured file still validates. Resolution
		// failures are stored per job so one archive never poisons sibling
		// registry images.
		var vulnerabilityExceptions, severityExceptions []string
		var exceptionErr error
		if imgScanInfo.Exceptions != "" {
			vulnerabilityExceptions, severityExceptions, exceptionErr = getUniqueVulnerabilitiesAndSeverities(exceptionPolicies, image, true)
			if exceptionErr != nil {
				exceptionErr = fmt.Errorf("%w (exceptions from %q)", exceptionErr, imgScanInfo.Exceptions)
			}
		}
		jobs = append(jobs, ImageScanJob{
			Image:                   image,
			Platform:                imgScanInfo.Platform,
			RegistryCredentials:     []imagescan.RegistryCredentials{creds},
			VulnerabilityExceptions: vulnerabilityExceptions,
			SeverityExceptions:      severityExceptions,
			RegistryMapping:         scanInfo.RegistryMapping,
			ExceptionErr:            exceptionErr,
		})
	}
	return jobs
}

// imageScanStartMessage renders the progress message for the image list.
func imageScanStartMessage(images []string) string {
	if len(images) == 1 {
		return fmt.Sprintf("Scanning image %s...", images[0])
	}
	return fmt.Sprintf("Scanning %s...", countedNoun(len(images), "image"))
}

// unwrapSingleImageError reports the cause directly when an aggregate holds a
// single image failure, so scanning one image keeps the plain error it
// reported before the command grew multi-image support.
func unwrapSingleImageError(err error) error {
	var aggregated *ScanErrorAggregator
	if !errors.As(err, &aggregated) {
		return err
	}
	failure, ok := aggregated.SingleError()
	if !ok {
		return err
	}
	return fmt.Errorf("failed to scan image %s: %w", failure.Image, failure.Err)
}

// imageScanFailureMessage carries no cause: scanImageJobs has already logged
// every per-image error, and the failure itself is returned to the caller to
// be reported once more.
func imageScanFailureMessage(images []string) string {
	if len(images) == 1 {
		return fmt.Sprintf("Failed to scan image %s", images[0])
	}
	return fmt.Sprintf("Failed to scan %s", countedNoun(len(images), "image"))
}

// imageScanSuccessMessage renders the final message; it reflects partial
// success when fewer images produced results than were requested.
func imageScanSuccessMessage(images []string, scanned []cautils.ImageScanData) string {
	switch {
	case len(images) == 1:
		return fmt.Sprintf("Successfully scanned image: %s", images[0])
	case len(scanned) < len(images):
		return fmt.Sprintf("Successfully scanned %d of %s", len(scanned), countedNoun(len(images), "image"))
	default:
		return fmt.Sprintf("Successfully scanned %s", countedNoun(len(images), "image"))
	}
}

// countedNoun renders "1 image" / "3 images" for log and CLI messages.
func countedNoun(n int, singular string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %ss", n, singular)
}

// ScanErrorCategory defines distinct vulnerability scan failure categories.
type ScanErrorCategory string

const (
	ErrCategoryDNSTimeout  ScanErrorCategory = "Registry DNSTimeout/Unreachable"
	ErrCategoryCredentials ScanErrorCategory = "Registry Credentials/Authentication" // #nosec G101 -- descriptive error category label, not a hardcoded credential
	ErrCategoryParser      ScanErrorCategory = "Image Manifest/Parser Issue"
	ErrCategoryGeneral     ScanErrorCategory = "General Error"
	// ErrCategoryExceptionUnsupported groups per-image failures where image
	// exceptions were requested for a non-registry input (archive, local
	// directory, SBOM, ...). Kept distinct from General Error so dashboards
	// can tell "user asked for the impossible" apart from scanner breakage.
	ErrCategoryExceptionUnsupported ScanErrorCategory = "Image Exceptions/Unsupported Input"
)

// formatExceptionUnsupportedError tags err with the category prefix that
// CategorizeScanError recognizes, keeping these failures distinct from
// General errors in aggregator summaries. Single formatting site for the
// worker, the fail-fast branch, and tests.
func formatExceptionUnsupportedError(err error) error {
	return fmt.Errorf("[%s] %w", ErrCategoryExceptionUnsupported, err)
}

// CategorizeScanError inspects an error and assigns a ScanErrorCategory.
// Explicit "[Category] ..." prefixes (emitted by this package's own error
// paths) win over the heuristic substring checks below, so intentionally
// categorized failures survive aggregation instead of collapsing to General.
func CategorizeScanError(err error) ScanErrorCategory {
	if err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "["+string(ErrCategoryExceptionUnsupported)+"]") {
		return ErrCategoryExceptionUnsupported
	}
	if isResolutionError(err) {
		return ErrCategoryDNSTimeout
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "authentication required") ||
		strings.Contains(errStr, "forbidden") ||
		strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "credentials") ||
		strings.Contains(errStr, "login") ||
		strings.Contains(errStr, "auth") {
		return ErrCategoryCredentials
	}
	if strings.Contains(errStr, "manifest") ||
		strings.Contains(errStr, "parse") ||
		strings.Contains(errStr, "syntax") ||
		strings.Contains(errStr, "unmarshal") ||
		strings.Contains(errStr, "decode") ||
		strings.Contains(errStr, "unknown format") ||
		strings.Contains(errStr, "invalid") ||
		strings.Contains(errStr, "malformed") {
		return ErrCategoryParser
	}
	return ErrCategoryGeneral
}

// CategorizedScanError groups an error with its target image and classification.
type CategorizedScanError struct {
	Image    string
	Category ScanErrorCategory
	Err      error
}

// ScanErrorAggregator collects and aggregates categorized errors across concurrent worker scans.
type ScanErrorAggregator struct {
	mu     sync.Mutex
	Errors []CategorizedScanError
}

// NewScanErrorAggregator creates a new thread-safe error aggregator.
func NewScanErrorAggregator() *ScanErrorAggregator {
	return &ScanErrorAggregator{
		Errors: make([]CategorizedScanError, 0),
	}
}

// Add appends a categorized error to the aggregator.
func (a *ScanErrorAggregator) Add(image string, err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Errors = append(a.Errors, CategorizedScanError{
		Image:    image,
		Category: CategorizeScanError(err),
		Err:      err,
	})
}

// Summary returns the tally of errors grouped by category.
func (a *ScanErrorAggregator) Summary() map[ScanErrorCategory]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	summary := make(map[ScanErrorCategory]int)
	for _, e := range a.Errors {
		summary[e.Category]++
	}
	return summary
}

// SingleError returns the only collected failure when exactly one was recorded,
// letting callers that scanned a single image report its cause directly.
func (a *ScanErrorAggregator) SingleError() (CategorizedScanError, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.Errors) != 1 {
		return CategorizedScanError{}, false
	}
	return a.Errors[0], true
}

// HasErrors indicates whether any scan errors occurred.
func (a *ScanErrorAggregator) HasErrors() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.Errors) > 0
}

// Error formats the aggregated scan errors as a multiline string.
func (a *ScanErrorAggregator) Error() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.Errors) == 0 {
		return ""
	}
	summary := make(map[ScanErrorCategory][]string)
	for _, e := range a.Errors {
		summary[e.Category] = append(summary[e.Category], fmt.Sprintf("%s (%v)", e.Image, e.Err))
	}
	var b strings.Builder
	b.WriteString("Aggregated image scan errors:\n")
	for cat, list := range summary {
		fmt.Fprintf(&b, "[%s]: %d errors\n", cat, len(list))
		for _, msg := range list {
			fmt.Fprintf(&b, "  - %s\n", msg)
		}
	}
	return b.String()
}

// ImageScanJob represents an item of work for the concurrent scanner.
type ImageScanJob struct {
	Image                   string
	Platform                string
	SkipUnavailablePlatform bool
	RegistryCredentials     []imagescan.RegistryCredentials
	VulnerabilityExceptions []string
	SeverityExceptions      []string
	RegistryMapping         map[string]string
	// ExceptionErr carries a per-image exception-resolution failure (e.g.
	// exceptions requested for a non-registry input). Workers surface it as
	// the job result without invoking the scanner.
	ExceptionErr error
}

// ImageScanResult conveys the scan output and categorized errors from a worker.
type ImageScanResult struct {
	Image      string
	Platform   string
	ScanData   *cautils.ImageScanData
	Error      error
	SkipReason error
}

func imageScanTarget(image, platform string) string {
	return cautils.ImageScanTarget(image, platform)
}

const defaultImageScanConcurrency = 5

func imageScanWorkers(concurrency int) int {
	if concurrency <= 0 {
		return defaultImageScanConcurrency
	}
	return concurrency
}

// ImageScanOrchestrator coordinates concurrent image scan execution across a worker pool.
type ImageScanOrchestrator struct {
	concurrency     int
	svc             imageScanService
	errorAggregator *ScanErrorAggregator
}

// NewImageScanOrchestrator instantiates an orchestrator with a worker pool size.
func NewImageScanOrchestrator(svc imageScanService, concurrency int) *ImageScanOrchestrator {
	return &ImageScanOrchestrator{
		concurrency:     imageScanWorkers(concurrency),
		svc:             svc,
		errorAggregator: NewScanErrorAggregator(),
	}
}

// ScanImages processes multiple image scanning jobs concurrently using the worker pool.
func (o *ImageScanOrchestrator) ScanImages(ctx context.Context, jobs []ImageScanJob) []ImageScanResult {
	if len(jobs) == 0 {
		return nil
	}

	jobChan := make(chan ImageScanJob, len(jobs))
	resultChan := make(chan ImageScanResult, len(jobs))

	for _, job := range jobs {
		jobChan <- job
	}
	close(jobChan)

	var wg sync.WaitGroup
	workers := o.concurrency
	if workers > len(jobs) {
		workers = len(jobs)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				target := imageScanTarget(job.Image, job.Platform)
				// Exception-resolution failures surface first: an archive with
				// --exceptions must report as unsupported even if it also has
				// a platform hint or mapping that would otherwise skip it.
				if job.ExceptionErr != nil {
					if o.errorAggregator != nil {
						o.errorAggregator.Add(target, formatExceptionUnsupportedError(job.ExceptionErr))
					}
					resultChan <- ImageScanResult{
						Image:    job.Image,
						Platform: job.Platform,
						Error:    formatExceptionUnsupportedError(job.ExceptionErr),
					}
					continue
				}
				select {
				case <-ctx.Done():
					cancelErr := fmt.Errorf("scan canceled: %w", ctx.Err())
					if o.errorAggregator != nil {
						o.errorAggregator.Add(target, cancelErr)
					}
					resultChan <- ImageScanResult{
						Image:    job.Image,
						Platform: job.Platform,
						Error:    cancelErr,
					}
					continue
				default:
				}

				scanData, err := scanWithRegistryMapping(
					ctx, o.svc, job.Image, job.RegistryCredentials,
					job.RegistryMapping, job.VulnerabilityExceptions, job.SeverityExceptions, job.Platform,
				)
				if scanData != nil && scanData.Platform == "" {
					scanData.Platform = job.Platform
				}
				if err != nil && job.SkipUnavailablePlatform && isUnavailablePlatformError(err) {
					resultChan <- ImageScanResult{
						Image: job.Image, Platform: job.Platform, SkipReason: err,
					}
					continue
				}
				if err != nil {
					if o.errorAggregator != nil {
						o.errorAggregator.Add(target, err)
					}
				}
				resultChan <- ImageScanResult{
					Image:    job.Image,
					Platform: job.Platform,
					ScanData: scanData,
					Error:    err,
				}
			}
		}()
	}

	wg.Wait()
	close(resultChan)

	results := make([]ImageScanResult, 0, len(jobs))
	for res := range resultChan {
		results = append(results, res)
	}
	return results
}

func isUnavailablePlatformError(err error) bool {
	if err == nil {
		return false
	}
	var platformMismatch *stereoscopeimage.ErrPlatformMismatch
	if errors.As(err, &platformMismatch) {
		return true
	}

	message := strings.ToLower(err.Error())
	return (strings.Contains(message, "no child with platform ") && strings.Contains(message, " in index ")) ||
		strings.Contains(message, "no manifest found in manifest list for platform ")
}

// GetErrorAggregator returns the orchestrator's scan error aggregator.
func (o *ImageScanOrchestrator) GetErrorAggregator() *ScanErrorAggregator {
	return o.errorAggregator
}
