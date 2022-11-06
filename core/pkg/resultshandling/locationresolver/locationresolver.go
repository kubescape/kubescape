package locationresolver

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/mikefarah/yq/v4/pkg/yqlib"

	"gopkg.in/op/go-logging.v1"
	"gopkg.in/yaml.v3"
)

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
	file, err := os.Open(yamlPath)
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
			return Location{}, err
		}

		candidateNode := candidateNodes.Back().Value.(*yqlib.CandidateNode).Node

		if candidateNode.Line != 0 || len(yamlExpression) <= 1 {
			return Location{Line: candidateNode.Line, Column: candidateNode.Column}, nil
		}

		// for non-existent yaml expressions, remove the last part of the expression and try again
		yamlExpression = regexp.MustCompile(`(.*)(\.[^.]*)`).ReplaceAllString(yamlExpression, `${1}`)
	}
	return Location{}, nil
}

func FixPathToValidYamlExpression(fixPath string) string {
	// remove everything after the first =
	yamlExpression := regexp.MustCompile(`(.*)=.*`).ReplaceAllString(fixPath, `${1}`)

	// add a dot for the root node
	yamlExpression = "." + yamlExpression
	return yamlExpression
}
