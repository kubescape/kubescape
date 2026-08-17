package locationresolver

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"gopkg.in/op/go-logging.v1"
	"gopkg.in/yaml.v3"
)

// lastPathSegment matches an expression's trailing ".<segment>", stripped to walk
// back up a path that does not exist. Compiled once rather than per step.
var lastPathSegment = regexp.MustCompile(`(.*)(\.[^.]*)`)

type FixPathLocationResolver struct {
	yqlibEvaluator yqlib.Evaluator
	yamlPath       string
	yamlNodes      []*yaml.Node
}

type Location struct {
	Line   int
	Column int
}

func NewFixPathLocationResolver(yamlPath string) (*FixPathLocationResolver, error) {
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

	return &FixPathLocationResolver{
		yamlPath:       yamlPath,
		yqlibEvaluator: evaluator,
		yamlNodes:      yamlNodes,
	}, nil
}

func (l *FixPathLocationResolver) ResolveLocation(fixPath string, nodeIndex int) (Location, error) {
	if nodeIndex >= len(l.yamlNodes) {
		return Location{}, fmt.Errorf("node index [%d] out of range [%d]", nodeIndex, len(l.yamlNodes))
	}

	yamlExpression := FixPathToValidYamlExpression(fixPath)
	for strings.HasPrefix(yamlExpression, ".") && len(yamlExpression) > 1 {
		candidateNodes, err := l.yqlibEvaluator.EvaluateNodes(yamlExpression, l.yamlNodes[nodeIndex])
		if err != nil {
			return Location{}, fmt.Errorf("failed to evaluate yaml expression %q: %w", yamlExpression, err)
		}

		if backElement := candidateNodes.Back(); backElement != nil {
			candidateNode := backElement.Value.(*yqlib.CandidateNode).Node

			if candidateNode.Line != 0 || len(yamlExpression) <= 1 {
				return Location{Line: candidateNode.Line, Column: candidateNode.Column}, nil
			}
		}

		// for non-existent yaml expressions, remove the last part of the expression and try again
		yamlExpression = lastPathSegment.ReplaceAllString(yamlExpression, `${1}`)
	}
	return Location{}, nil

}

func FixPathToValidYamlExpression(fixPath string) string {
	// Remove everything after the first "=": assisted-remediation strings are built
	// as "<path>=<value>" by fixPathsToString in printer/v2/resourcetable.go, and
	// only the path half is a valid yaml expression.
	//
	// This must split on the *first* separator. Fix values routinely contain "="
	// themselves — the CIS control-plane rules emit values such as
	// "--anonymous-auth=false" and "--authorization-mode=RBAC" — so a greedy match
	// keeps part of the value in the path and produces an unusable expression.
	if i := strings.Index(fixPath, "="); i >= 0 {
		fixPath = fixPath[:i]
	}

	// add a dot for the root node
	return "." + fixPath
}
