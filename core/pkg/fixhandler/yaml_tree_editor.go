package fixhandler

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"gopkg.in/yaml.v3"
)

// DocumentFix contains a fix path and the document index it applies to.
type DocumentFix struct {
	DocumentIndex int
	Fix           armotypes.FixPath
}

// YAMLEdit represents a text edit to apply to the original YAML string.
type YAMLEdit struct {
	Line   int    // 1-indexed line number
	Column int    // 1-indexed column number (for updates)
	Text   string // Text to insert or replace
	Remove int    // Number of characters to remove
	Insert bool   // True if it's a line insertion after the specified line
}

// YAMLTreeEditor provides AST-preserving mutations for YAML documents.
type YAMLTreeEditor struct{}

func NewYAMLTreeEditor() *YAMLTreeEditor {
	return &YAMLTreeEditor{}
}

// ApplyFixes applies a list of fixes to the YAML string and returns the patched string.
func (e *YAMLTreeEditor) ApplyFixes(yamlAsString string, fixes []DocumentFix) (string, error) {
	currentYaml := yamlAsString

	for _, fix := range fixes {
		docs, err := decodeDocumentRoots(currentYaml)
		if err != nil {
			return "", err
		}

		if fix.DocumentIndex < 0 || fix.DocumentIndex >= len(docs) {
			continue // Skip if document doesn't exist
		}
		docNode := docs[fix.DocumentIndex]

		if len(docNode.Content) == 0 {
			continue 
		}

		edit, err := e.calculateEdit(docNode.Content[0], fix.Fix)
		if err != nil {
			continue // Skip if path not applicable
		}
		if edit != nil {
			currentYaml = e.applyEdits(currentYaml, []YAMLEdit{*edit})
		}
	}

	return currentYaml, nil
}

func (e *YAMLTreeEditor) applyEdits(yaml string, edits []YAMLEdit) string {
	lines := strings.Split(yaml, "\n")
	newlineSeq := "\n"
	if strings.Contains(yaml, "\r\n") {
		newlineSeq = "\r\n"
		for i := range lines {
			lines[i] = strings.TrimSuffix(lines[i], "\r")
		}
	}

	editsByLine := make(map[int][]YAMLEdit)
	for _, edit := range edits {
		editsByLine[edit.Line] = append(editsByLine[edit.Line], edit)
	}

	var result []string
	for i := 0; i < len(lines); i++ {
		lineNum := i + 1
		lineText := lines[i]

		if lineEdits, ok := editsByLine[lineNum]; ok {
			for _, edit := range lineEdits {
				if !edit.Insert {
					colIndex := edit.Column - 1
					if colIndex < 0 {
						colIndex = 0
					}
					if colIndex > len(lineText) {
						colIndex = len(lineText)
					}
					
					removeEnd := colIndex + edit.Remove
					if removeEnd > len(lineText) {
						removeEnd = len(lineText)
					}

					lineText = lineText[:colIndex] + edit.Text + lineText[removeEnd:]
				}
			}
		}
		
		result = append(result, lineText)

		if lineEdits, ok := editsByLine[lineNum]; ok {
			for _, edit := range lineEdits {
				if edit.Insert {
					if strings.Contains(edit.Text, "\n") {
						result = append(result, strings.Split(edit.Text, "\n")...)
					} else {
						result = append(result, edit.Text)
					}
				}
			}
		}
	}

	maxLine := len(lines)
	for ln, lineEdits := range editsByLine {
		if ln > maxLine {
			for _, edit := range lineEdits {
				if edit.Insert {
					if strings.Contains(edit.Text, "\n") {
						result = append(result, strings.Split(edit.Text, "\n")...)
					} else {
						result = append(result, edit.Text)
					}
				}
			}
		}
	}

	return strings.Join(result, newlineSeq)
}

func parsePath(path string) []string {
	var tokens []string
	parts := strings.Split(path, ".")
	for _, part := range parts {
		if part == "" {
			continue
		}
		if strings.HasSuffix(part, "]") {
			idx := strings.Index(part, "[")
			if idx != -1 {
				if idx > 0 {
					tokens = append(tokens, part[:idx])
				}
				tokens = append(tokens, part[idx:])
				continue
			}
		}
		tokens = append(tokens, part)
	}
	return tokens
}

func (e *YAMLTreeEditor) calculateEdit(root *yaml.Node, fix armotypes.FixPath) (*YAMLEdit, error) {
	tokens := parsePath(fix.Path)
	return e.traverse(root, tokens, fix.Value, 0)
}

func (e *YAMLTreeEditor) traverse(node *yaml.Node, tokens []string, value string, parentIndent int) (*YAMLEdit, error) {
	if len(tokens) == 0 {
		return nil, nil
	}

	token := tokens[0]
	isLast := len(tokens) == 1

	if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
		idxStr := token[1 : len(token)-1]
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			return nil, fmt.Errorf("invalid array index: %s", token)
		}

		if node.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("expected sequence node for token %s", token)
		}

		if idx < 0 || idx >= len(node.Content) {
			return nil, fmt.Errorf("appending to array not fully implemented")
		}

		if isLast {
			valNode := node.Content[idx]
			removeLen := len(valNode.Value)
			if valNode.Style == yaml.DoubleQuotedStyle || valNode.Style == yaml.SingleQuotedStyle {
				removeLen += 2
			}
			return &YAMLEdit{
				Line:   valNode.Line,
				Column: valNode.Column,
				Text:   value,
				Remove: removeLen,
			}, nil
		} else {
			return e.traverse(node.Content[idx], tokens[1:], value, node.Column)
		}
	} else {
		if node.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("expected mapping node")
		}

		cleanToken := strings.Trim(token, `"'`)

		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]

			if keyNode.Value == cleanToken {
				if isLast {
					if valNode.Kind == yaml.ScalarNode {
						removeLen := len(valNode.Value)
						if valNode.Style == yaml.DoubleQuotedStyle || valNode.Style == yaml.SingleQuotedStyle {
							removeLen += 2
						}
						return &YAMLEdit{
							Line:   valNode.Line,
							Column: valNode.Column,
							Text:   value,
							Remove: removeLen,
						}, nil
					}
					return nil, fmt.Errorf("cannot replace non-scalar node yet")
				} else {
					return e.traverse(valNode, tokens[1:], value, node.Column)
				}
			}
		}

		indent := parentIndent + 2
		if len(node.Content) > 0 {
			indent = node.Content[0].Column - 1 
		}

		indentStr := strings.Repeat(" ", indent)
		
		lastLine := node.Line
		if len(node.Content) > 0 {
			lastNode := node.Content[len(node.Content)-1]
			lastLine = e.getDeepestLine(lastNode)
		}

		if isLast {
			return &YAMLEdit{
				Line:   lastLine,
				Insert: true,
				Text:   fmt.Sprintf("%s%s: %s", indentStr, cleanToken, value),
			}, nil
		} else {
			return e.buildNestedInsertion(tokens, value, lastLine, indent)
		}
	}
}

func (e *YAMLTreeEditor) getDeepestLine(node *yaml.Node) int {
	maxLine := node.Line
	for _, child := range node.Content {
		childMax := e.getDeepestLine(child)
		if childMax > maxLine {
			maxLine = childMax
		}
	}
	return maxLine
}

func (e *YAMLTreeEditor) buildNestedInsertion(tokens []string, value string, line int, indent int) (*YAMLEdit, error) {
	var sb strings.Builder
	currentIndent := indent

	for i, token := range tokens {
		indentStr := strings.Repeat(" ", currentIndent)
		cleanToken := strings.Trim(token, `"'`)
		
		isLast := i == len(tokens)-1
		
		if strings.HasPrefix(token, "[") {
			sb.WriteString(fmt.Sprintf("\n%s- ", indentStr))
			currentIndent += 2
		} else {
			if i > 0 {
				sb.WriteString("\n")
			}
			if isLast {
				sb.WriteString(fmt.Sprintf("%s%s: %s", indentStr, cleanToken, value))
			} else {
				sb.WriteString(fmt.Sprintf("%s%s:", indentStr, cleanToken))
				currentIndent += 2
			}
		}
	}

	return &YAMLEdit{
		Line:   line,
		Insert: true,
		Text:   sb.String(),
	}, nil
}

func decodeDocumentRoots(yamlAsString string) ([]*yaml.Node, error) {
	var docs []*yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(yamlAsString))
	for {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		docs = append(docs, &doc)
	}
	return docs, nil
}
