package locationresolver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/kubescape/kubescape/v4/core/pkg/filesizelimit"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/pathparse"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
)

const (
	// defaultMaxFileSize bounds manifest files parsed from disk (32 MiB), preventing
	// uncontrolled memory allocation from oversized inputs or decompression bombs (CWE-400).
	defaultMaxFileSize = filesizelimit.DefaultMaxFileSize
	maxFileSizeEnvVar  = filesizelimit.MaxFileSizeEnvVar
)

var (
	// ErrManifestNotRegular is returned when a manifest file is not a regular file (e.g. FIFO, directory, device).
	ErrManifestNotRegular = errors.New("manifest is not a regular file")
	// ErrManifestTooLarge is returned when a manifest file exceeds the maximum allowed size limit.
	ErrManifestTooLarge = errors.New("manifest exceeds maximum size limit")
)

// getMaxFileSize returns the maximum allowed size in bytes for a manifest file,
// configurable via KUBESCAPE_MAX_FILE_SIZE, defaulting to defaultMaxFileSize (32 MiB).
// math.MaxInt64 is rejected to avoid integer overflow in limit+1 calculations.
func getMaxFileSize() int64 {
	return filesizelimit.GetMaxFileSize()
}

func openManifestFile(path string) (*os.File, error) {
	cleanPath := filepath.Clean(path)
	preStat, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}
	if preStat.IsDir() {
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrManifestNotRegular)
	}
	if !preStat.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", ErrManifestNotRegular, path)
	}

	file, err := os.OpenFile(cleanPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrManifestNotRegular)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %q", ErrManifestNotRegular, path)
	}
	return file, nil
}

// PathLocationResolver finds where in a manifest a rule's path points. It
// decodes every document in the file once and resolves paths against a chosen
// document by index.
//
// It resolves any path a rule emits - fix, review, delete or failed - which is
// why it is no longer named for fix paths alone. SARIF's related locations
// already sent review paths through it before the rename.
type PathLocationResolver struct {
	yqlibEvaluator yqlib.Evaluator
	yamlPath       string
	yamlNodes      []*yqlib.CandidateNode
	// workloadDocuments maps the index the scanner gives a workload to its
	// document in yamlNodes, -1 for one in a List; see IndexedByWorkload.
	workloadDocuments []int
	// unmatched is why an indexed file's workloads couldn't be matched to its
	// documents. Its workloads then have no location rather than another's.
	unmatched error
}

// Option configures a PathLocationResolver.
type Option func(l *PathLocationResolver, data []byte)

// IndexedByWorkload makes ResolveLocation take the index the scanner gives a
// workload ("<path>:<n>") rather than a document's position in the file. The two
// differ once a document yields no workload, such as an empty or comment-only
// one, or several, as a List does. workloadDocuments maps one to the other for
// the file's content; cautils.WorkloadDocuments is the scanner's own mapping.
func IndexedByWorkload(workloadDocuments func(data []byte) ([]int, error)) Option {
	return func(l *PathLocationResolver, data []byte) {
		l.workloadDocuments, l.unmatched = workloadDocuments(data)
	}
}

// FixPathLocationResolver is the resolver's previous name, kept so code
// importing this package keeps compiling.
//
// Deprecated: use PathLocationResolver.
type FixPathLocationResolver = PathLocationResolver

// NewFixPathLocationResolver is the constructor's previous name.
//
// Deprecated: use NewPathLocationResolver.
func NewFixPathLocationResolver(yamlPath string) (*PathLocationResolver, error) {
	return NewPathLocationResolver(yamlPath)
}

type Location struct {
	Line   int
	Column int
}

func NewPathLocationResolver(yamlPath string, opts ...Option) (*PathLocationResolver, error) {
	file, err := openManifestFile(yamlPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	limit := getMaxFileSize()
	info, err := file.Stat()
	if err == nil && info.Size() > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrManifestTooLarge, yamlPath, limit)
	}

	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}

	data, err := io.ReadAll(io.LimitReader(file, readLimit))
	if err != nil {
		return nil, fmt.Errorf("error reading manifest %s: %w", yamlPath, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrManifestTooLarge, yamlPath, limit)
	}

	yamlNodes := make([]*yqlib.CandidateNode, 0)

	yamlDecoder := yqlib.NewYamlDecoder(yqlib.ConfiguredYamlPreferences)
	if err = yamlDecoder.Init(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	for {
		yamlNode, err := yamlDecoder.Decode()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		yamlNode.EvaluateTogether = true
		yamlNodes = append(yamlNodes, yamlNode)
	}

	evaluator := yqlib.NewAllAtOnceEvaluator()
	yqlib.GetLogger().SetLevel(slog.LevelError)

	resolver := &PathLocationResolver{
		yamlPath:       yamlPath,
		yqlibEvaluator: evaluator,
		yamlNodes:      yamlNodes,
	}
	for _, opt := range opts {
		opt(resolver, data)
	}
	return resolver, nil
}

// ResolveLocation returns where in the manifest the given path points.
//
// A path whose field is absent is the normal case rather than an error: a fix
// path routinely names a field that has to be *added*. Resolution then walks
// back up a segment at a time until something exists, so the caller is pointed
// at the enclosing block. A path that resolves to nothing at all yields the
// zero Location, which callers read as "no line".
//
// With IndexedByWorkload, nodeIndex is the index the scanner gives the workload
// ("<path>:<n>"), and names its document even when an empty, comment-only or
// non-Kubernetes document comes before it; a workload inside a List has no
// document of its own and no location, and neither has one of a file whose
// workloads can't be matched to its documents. Otherwise, and in a file without
// workloads, nodeIndex is the document's position in the file.
func (l *PathLocationResolver) ResolveLocation(path string, nodeIndex int) (Location, error) {
	if l.unmatched != nil {
		return Location{}, l.unmatched
	}
	if nodeIndex >= 0 && nodeIndex < len(l.workloadDocuments) {
		document := l.workloadDocuments[nodeIndex]
		if document < 0 {
			return Location{}, fmt.Errorf("workload [%d] is inside a List and has no document of its own", nodeIndex)
		}
		nodeIndex = document
	}
	if nodeIndex < 0 || nodeIndex >= len(l.yamlNodes) {
		return Location{}, fmt.Errorf("node index [%d] out of range [%d]", nodeIndex, len(l.yamlNodes))
	}
	return l.ResolveDocumentLocation(path, nodeIndex)
}

// ResolveDocumentLocation resolves path in the document at docIndex (its position
// in yamlNodes, as returned by FindDocumentIndex) directly, without remapping through
// workloadDocuments.
func (l *PathLocationResolver) ResolveDocumentLocation(path string, docIndex int) (Location, error) {
	if docIndex < 0 || docIndex >= len(l.yamlNodes) {
		return Location{}, fmt.Errorf("document index [%d] out of range [%d]", docIndex, len(l.yamlNodes))
	}

	// A malformed path is rejected before any walking up. Walking up exists for
	// a well-formed path whose field is absent; applied to a path that could
	// not be read, it would hand back the line of some ancestor as though the
	// rule had named it.
	segments, err := pathparse.ParsePath(path)
	if err != nil {
		return Location{}, err
	}

	// Walking up drops a parsed segment rather than trimming text off the
	// expression. A trailing ".<segment>" regex cannot see that a bracketed key
	// holds dots of its own, so on
	// metadata.labels[app.kubernetes.io/name] it would peel the key apart one
	// fragment at a time and ask yq about paths that never existed.
	for len(segments) > 0 {
		yamlExpression := segmentsToYamlExpression(segments)

		candidateNodes, err := l.yqlibEvaluator.EvaluateNodes(yamlExpression, l.yamlNodes[docIndex])
		if err != nil {
			return Location{}, fmt.Errorf("failed to evaluate yaml expression %q: %w", yamlExpression, err)
		}

		if backElement := candidateNodes.Back(); backElement != nil {
			candidateNode := backElement.Value.(*yqlib.CandidateNode)
			if candidateNode.Line != 0 {
				return Location{Line: candidateNode.Line, Column: candidateNode.Column}, nil
			}
		}

		segments = segments[:len(segments)-1]
	}
	return Location{}, nil
}

// segmentsToYamlExpression renders parsed segments as a yq expression.
//
// Every key is bracketed and quoted, including ones that would be legal bare.
// Kubernetes label and annotation keys carry dots and slashes -
// "app.kubernetes.io/name" - and yq reads a bare dot as a path separator, so
// the unquoted spelling is either a different path or a parse error. Quoting
// uniformly means one rendering to reason about instead of a rule about which
// keys need it.
func segmentsToYamlExpression(segments []pathparse.Segment) string {
	if len(segments) == 0 {
		return "."
	}

	var b strings.Builder
	b.WriteByte('.')
	for _, segment := range segments {
		b.WriteByte('[')
		b.WriteString(quoteYamlKey(segment.Key))
		b.WriteByte(']')
		if segment.Index >= 0 {
			b.WriteByte('[')
			b.WriteString(strconv.Itoa(segment.Index))
			b.WriteByte(']')
		}
	}
	return b.String()
}

// quoteYamlKey renders a map key as a double-quoted yq string, escaping the two
// characters that would otherwise end the string early or start an escape.
func quoteYamlKey(key string) string {
	return `"` + yamlKeyEscaper.Replace(key) + `"`
}

var yamlKeyEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// FixPathToValidYamlExpression renders a path as the yq expression that selects
// it, or "" for a malformed path - the same convention fixhandler's function of
// this name uses for input it refuses. Retained for callers outside this
// package; ResolveLocation works from the parsed segments directly.
func FixPathToValidYamlExpression(fixPath string) string {
	segments, err := pathparse.ParsePath(fixPath)
	if err != nil {
		return ""
	}
	return segmentsToYamlExpression(segments)
}

// DocumentCount returns the number of YAML documents in the resolved file.
func (l *PathLocationResolver) DocumentCount() int {
	return len(l.yamlNodes)
}

// FindDocumentIndex returns the index of the document matching the given kind,
// name, and optional namespace. It returns ok=true only when exactly one document
// in the manifest matches. If zero or multiple documents match, it returns false.
func (l *PathLocationResolver) FindDocumentIndex(kind, name, namespace string) (int, bool) {
	if len(l.yamlNodes) == 0 || kind == "" || name == "" {
		return 0, false
	}
	matched := -1
	count := 0
	for i, node := range l.yamlNodes {
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
		}
		if err := decodeCandidateNode(node, &doc); err != nil {
			continue
		}
		if doc.Kind == kind && doc.Metadata.Name == name {
			if namespace == "" || doc.Metadata.Namespace == "" || doc.Metadata.Namespace == namespace {
				matched = i
				count++
			}
		}
	}
	if count == 1 {
		return matched, true
	}
	return 0, false
}

// RawDocument decodes and returns the document at docIndex as a map.
func (l *PathLocationResolver) RawDocument(docIndex int) (map[string]any, error) {
	if docIndex < 0 || docIndex >= len(l.yamlNodes) {
		return nil, fmt.Errorf("document index [%d] out of range [%d]", docIndex, len(l.yamlNodes))
	}
	var doc map[string]any
	if err := decodeCandidateNode(l.yamlNodes[docIndex], &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func decodeCandidateNode(node *yqlib.CandidateNode, out any) error {
	yamlNode, err := node.MarshalYAML()
	if err != nil {
		return err
	}
	return yamlNode.Decode(out)
}
