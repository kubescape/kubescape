package fixhandler

import (
	"bytes"
	"container/list"
	"context"
	"fmt"
	"strings"

	"github.com/mikefarah/yq/v4/pkg/yqlib"
)

const defaultJSONIndent = 2

// applyFixToJSONContent evaluates the same expression the YAML path uses and
// re-encodes the document. The YAML path splices the fixed lines back into the
// original text to keep comments and layout; JSON carries neither, so
// re-encoding loses nothing but the original whitespace.
func applyFixToJSONContent(ctx context.Context, jsonAsString, yamlExpression string) (string, error) {
	documents, err := readDocuments(ctx, strings.NewReader(jsonAsString), yqlib.NewJSONDecoder())
	if err != nil {
		return "", err
	}

	allDocuments := list.New()
	allDocuments.PushBackList(documents)

	fixedNodes, err := yqlib.NewAllAtOnceEvaluator().EvaluateCandidateNodes(yamlExpression, allDocuments)
	if err != nil {
		return "", fmt.Errorf("error fixing JSON, %w", err)
	}

	var fixed bytes.Buffer
	printer := yqlib.NewPrinter(
		yqlib.NewJSONEncoder(detectJSONIndent(jsonAsString), false),
		yqlib.NewSinglePrinterWriter(&fixed),
	)
	if err := printer.PrintResults(fixedNodes); err != nil {
		return "", fmt.Errorf("error encoding JSON, %w", err)
	}

	return fixed.String(), nil
}

// detectJSONIndent reads the indentation of the first nested line so a fixed
// file keeps the spacing it was written with. A minified document has none, and
// re-encoding it pretty-printed is preferable to emitting a single line the
// user then has to read.
func detectJSONIndent(jsonAsString string) int {
	for _, line := range strings.Split(jsonAsString, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || len(trimmed) == len(line) {
			continue
		}
		if strings.HasPrefix(trimmed, "\t") {
			return defaultJSONIndent
		}
		return len(line) - len(trimmed)
	}
	return defaultJSONIndent
}

// isJSONSource reports whether a scanned file is JSON rather than YAML. The
// report records the type it parsed, and the extension is the fallback for a
// caller that only has the path.
func isJSONSource(filePath string) bool {
	return strings.EqualFold(strings.TrimPrefix(pathExtension(filePath), "."), "json")
}

func pathExtension(filePath string) string {
	if idx := strings.LastIndex(filePath, "."); idx != -1 {
		return filePath[idx:]
	}
	return ""
}

// countDocuments reports how many documents a manifest holds. JSON is always a
// single document; YAML separates them with ---.
func countDocuments(ctx context.Context, filePath string) (int, error) {
	content, err := GetFileString(filePath)
	if err != nil {
		return 0, err
	}

	decoder := yqlib.NewYamlDecoder(yqlib.ConfiguredYamlPreferences)
	if isJSONSource(filePath) {
		decoder = yqlib.NewJSONDecoder()
	}

	documents, err := readDocuments(ctx, strings.NewReader(content), decoder)
	if err != nil {
		return 0, err
	}
	return documents.Len(), nil
}
