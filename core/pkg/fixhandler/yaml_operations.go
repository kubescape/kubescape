package fixhandler

import (
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type yamlPathPart struct {
	key                string
	index              int
	sequence, wildcard bool
}

type yamlOperation struct {
	document int
	path     []yamlPathPart
	kind     string
	value    *yaml.Node
}

var documentSelector = regexp.MustCompile(`^select\(di==([0-9]+)\)\.`)
var separateDocumentSelector = regexp.MustCompile(`^select\(di==[0-9]+\)$`)

// parseYAMLOperations is a compatibility adapter, not a yq evaluator. Only
// document-selected assignment, sequence append, and deletion are accepted.
func parseYAMLOperations(expression string) ([]yamlOperation, error) {
	if strings.TrimSpace(expression) == "" {
		return nil, nil
	}
	parts, err := splitYAMLPipeline(expression)
	if err != nil {
		return nil, err
	}
	var result []yamlOperation
	for i, part := range parts {
		part = strings.TrimSpace(part)
		// The JSON/YAML dispatch fixture uses the equivalent select(...) | .path
		// spelling. Fold that exact pair before parsing the operation.
		if separateDocumentSelector.MatchString(part) && i+1 < len(parts) && strings.HasPrefix(strings.TrimSpace(parts[i+1]), ".") {
			parts[i+1] = part + strings.TrimSpace(parts[i+1])
			continue
		}
		op := yamlOperation{kind: "|=", document: -1}
		if strings.HasPrefix(part, "del(") && strings.HasSuffix(part, ")") {
			op.kind = "del"
			part = part[4 : len(part)-1]
		}
		selector := documentSelector.FindStringSubmatch(part)
		path := strings.TrimPrefix(part, ".")
		if selector != nil {
			op.document, err = strconv.Atoi(selector[1])
			if err != nil {
				return nil, fmt.Errorf("invalid document index")
			}
			path = part[len(selector[0]):]
		} else if !strings.HasPrefix(part, ".") {
			return nil, fmt.Errorf("unsupported YAML edit: expected a path")
		}
		if op.kind != "del" {
			pos := -1
			quoted := false
			width := 1
			for i := 0; i < len(path); i++ {
				if path[i] == '"' {
					quoted = !quoted
				}
				if !quoted && i+1 < len(path) && (path[i:i+2] == "|=" || path[i:i+2] == "+=") {
					pos = i
					width = 2
					break
				}
				if !quoted && path[i] == '=' {
					pos = i
					break
				}
			}
			if pos < 0 {
				return nil, fmt.Errorf("unsupported YAML edit: expected assignment or append")
			}
			op.kind = path[pos : pos+width]
			op.value, err = parseYAMLLiteral(strings.TrimSpace(path[pos+width:]))
			if err != nil {
				return nil, err
			}
			path = strings.TrimSpace(path[:pos])
		}
		op.path, err = parseYAMLPath(path)
		if err != nil {
			return nil, err
		}
		result = append(result, op)
	}
	return result, nil
}

func splitYAMLPipeline(s string) ([]string, error) {
	var parts []string
	start, depth := 0, 0
	quoted := false
	for i := 0; i < len(s); i++ {
		if quoted {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if s[i] == '"' {
				quoted = false
			}
			continue
		}
		switch s[i] {
		case '"':
			quoted = true
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			depth--
		case '|':
			if depth == 0 && (i+1 == len(s) || s[i+1] != '=') {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
		if depth < 0 {
			return nil, fmt.Errorf("unbalanced YAML edit")
		}
	}
	if quoted || depth != 0 {
		return nil, fmt.Errorf("unterminated YAML edit")
	}
	return append(parts, s[start:]), nil
}

func parseYAMLPath(path string) ([]yamlPathPart, error) {
	if !safeFixPath.MatchString(path) {
		return nil, fmt.Errorf("unsupported YAML fix path")
	}
	var parts []yamlPathPart
	for i := 0; i < len(path); {
		if path[i] == '.' {
			i++
			continue
		}
		if path[i] == '[' {
			end := strings.IndexByte(path[i:], ']') + i
			p := yamlPathPart{sequence: true, wildcard: path[i+1:end] == "*"}
			if !p.wildcard {
				var err error
				p.index, err = strconv.Atoi(path[i+1 : end])
				if err != nil {
					return nil, fmt.Errorf("invalid sequence index")
				}
			}
			parts = append(parts, p)
			i = end + 1
			continue
		}
		start := i
		if path[i] == '"' {
			i++
			start = i
			for path[i] != '"' {
				i++
			}
			parts = append(parts, yamlPathPart{key: path[start:i]})
			i++
		} else {
			for i < len(path) && path[i] != '.' && path[i] != '[' {
				i++
			}
			parts = append(parts, yamlPathPart{key: path[start:i]})
		}
	}
	return parts, nil
}

// The expression builder escapes only double quotes. In particular, \n in
// an expression string denotes a backslash followed by n, not a newline.
func parseYAMLLiteral(s string) (*yaml.Node, error) {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		parts, err := splitYAMLPipeline(s)
		if err != nil || len(parts) != 1 {
			return nil, fmt.Errorf("invalid string literal")
		}
		// Ensure this is one quoted token rather than a quoted expression.
		for i := 1; i < len(s)-1; i++ {
			if s[i] == '\\' && i+1 < len(s)-1 {
				i++
				continue
			}
			if s[i] == '"' {
				return nil, fmt.Errorf("unsupported string expression")
			}
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: strings.ReplaceAll(s[1:len(s)-1], `\"`, `"`)}, nil
	}
	if s == "true" || s == "false" || s == "True" || s == "False" || s == "TRUE" || s == "FALSE" {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strings.ToLower(s)}, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(s), &node); err == nil && len(node.Content) == 1 {
			n := node.Content[0]
			if n.Tag == "!!int" || n.Tag == "!!float" {
				return n, nil
			}
		}
	}
	// Collection literals are data only. Decode after requiring flow syntax,
	// then reject tags, aliases, nulls and unquoted string expressions.
	if len(s) >= 2 && ((s[0] == '[' && s[len(s)-1] == ']') || (s[0] == '{' && s[len(s)-1] == '}')) {
		// Match the existing expression string contract inside collections too:
		// only escaped quotes are unescaped; YAML must not interpret backslashes.
		var literal strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] != '"' {
				literal.WriteByte(s[i])
				continue
			}
			start := i
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
			}
			if i == len(s) {
				return nil, fmt.Errorf("unterminated collection string")
			}
			literal.WriteString(strconv.Quote(strings.ReplaceAll(s[start+1:i], `\"`, `"`)))
		}
		var node yaml.Node
		decoder := yaml.NewDecoder(strings.NewReader(literal.String()))
		if err := decoder.Decode(&node); err == nil && len(node.Content) == 1 && literalCollection(node.Content[0]) {
			var value any
			var trailing yaml.Node
			if err := node.Decode(&value); err == nil && decoder.Decode(&trailing) == io.EOF {
				return node.Content[0], nil
			}
		}
	}
	return nil, fmt.Errorf("unsupported YAML edit value: expected a literal")
}

func literalCollection(n *yaml.Node) bool {
	if n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 {
		return false
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!float" {
			var value float64
			return n.Decode(&value) == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
		}
		return n.Tag == "!!bool" || n.Tag == "!!int" || (n.Tag == "!!str" && n.Style == yaml.DoubleQuotedStyle)
	case yaml.SequenceNode, yaml.MappingNode:
		for _, child := range n.Content {
			if !literalCollection(child) {
				return false
			}
		}
		return true
	}
	return false
}
