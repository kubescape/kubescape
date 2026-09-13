package locationresolver

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/pathparse"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"gopkg.in/op/go-logging.v1"
	"gopkg.in/yaml.v3"
)

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
	yamlNodes      []*yaml.Node
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

func NewPathLocationResolver(yamlPath string) (*PathLocationResolver, error) {
	file, err := os.Open(filepath.Clean(yamlPath))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	yamlNodes := make([]*yaml.Node, 0)

	yamlDecoder := yaml.NewDecoder(file)
	for {
		var yamlNode yaml.Node
		err = yamlDecoder.Decode(&yamlNode)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		} else {
			yamlNodes = append(yamlNodes, &yamlNode)
		}
	}

	evaluator := yqlib.NewAllAtOnceEvaluator()
	backendLoggerLeveled := logging.AddModuleLevel(logging.NewLogBackend(logger.L().GetWriter(), "", 0))
	backendLoggerLeveled.SetLevel(logging.ERROR, "")
	yqlib.GetLogger().SetBackend(backendLoggerLeveled)

	return &PathLocationResolver{
		yamlPath:       yamlPath,
		yqlibEvaluator: evaluator,
		yamlNodes:      yamlNodes,
	}, nil
}

// ResolveLocation returns where in the manifest the given path points.
//
// A path whose field is absent is the normal case rather than an error: a fix
// path routinely names a field that has to be *added*. Resolution then walks
// back up a segment at a time until something exists, so the caller is pointed
// at the enclosing block. A path that resolves to nothing at all yields the
// zero Location, which callers read as "no line".
func (l *PathLocationResolver) ResolveLocation(path string, nodeIndex int) (Location, error) {
	if nodeIndex >= len(l.yamlNodes) {
		return Location{}, fmt.Errorf("node index [%d] out of range [%d]", nodeIndex, len(l.yamlNodes))
	}

	// Walking up drops a parsed segment rather than trimming text off the
	// expression. A trailing ".<segment>" regex cannot see that a bracketed key
	// holds dots of its own, so on
	// metadata.labels[app.kubernetes.io/name] it would peel the key apart one
	// fragment at a time and ask yq about paths that never existed.
	segments := pathparse.ParsePath(path)
	for len(segments) > 0 {
		yamlExpression := segmentsToYamlExpression(segments)

		candidateNodes, err := l.yqlibEvaluator.EvaluateNodes(yamlExpression, l.yamlNodes[nodeIndex])
		if err != nil {
			return Location{}, fmt.Errorf("failed to evaluate yaml expression %q: %w", yamlExpression, err)
		}

		if backElement := candidateNodes.Back(); backElement != nil {
			candidateNode := backElement.Value.(*yqlib.CandidateNode).Node
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
// it. Retained for callers outside this package; ResolveLocation works from the
// parsed segments directly.
func FixPathToValidYamlExpression(fixPath string) string {
	return segmentsToYamlExpression(pathparse.ParsePath(fixPath))
}
