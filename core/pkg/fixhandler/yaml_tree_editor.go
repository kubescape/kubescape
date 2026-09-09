package fixhandler

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/kubescape/opa-utils/objectsenvelopes"
	"gopkg.in/yaml.v3"
)

// YAMLTreeEditor edits source spans selected through yaml.Node trees. The
// encoder is used only for new fragments, never for untouched documents.
type YAMLTreeEditor struct{}

type yamlSourceEdit struct {
	start, end int
	text       string
}

type yamlSource struct {
	text    string
	lines   []int
	parents map[*yaml.Node]*yaml.Node
}

// Apply preserves pipeline order. Each operation is resolved against a fresh
// tree, so insertions cannot leave stale offsets for subsequent operations.
// All work is in memory: an error returns no partially remediated content.
func (YAMLTreeEditor) Apply(ctx context.Context, source, expression string) (string, error) {
	ops, err := parseYAMLOperations(expression)
	if err != nil {
		return "", err
	}
	docs, err := decodeDocumentRoots(source)
	if err != nil {
		return "", err
	}
	if len(ops) == 0 {
		return source, nil
	}
	indices, err := yamlWorkloadDocuments(docs)
	if err != nil {
		return "", err
	}
	var expanded []yamlOperation
	for _, op := range ops {
		if op.document < 0 {
			for i := range indices {
				copy := op
				copy.document = i
				expanded = append(expanded, copy)
			}
		} else {
			expanded = append(expanded, op)
		}
	}
	ops = expanded
	for i, op := range ops {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if op.document >= len(indices) {
			return "", fmt.Errorf("YAML edit %d: document index %d out of range", i+1, op.document)
		}
		s := newYAMLSource(source, docs)
		root := docs[indices[op.document]].Content[0]
		edits, err := s.walk(root, op.path, op)
		if err != nil {
			return "", fmt.Errorf("YAML edit %d in document %d: %w", i+1, op.document, err)
		}
		sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
		last := len(source)
		for _, edit := range edits {
			if edit.start < 0 || edit.end < edit.start || edit.end > last {
				return "", fmt.Errorf("overlapping or invalid YAML source edits")
			}
			source = source[:edit.start] + edit.text + source[edit.end:]
			last = edit.start
		}
		docs, err = decodeDocumentRoots(source)
		if err != nil {
			return "", fmt.Errorf("YAML edit %d produced invalid YAML: %w", i+1, err)
		}
	}
	return source, nil
}

// Scanner paths index the workloads produced by a file, not empty documents.
// Keep this translation within remediation. Generic YAML remains supported
// for the public editor's existing callers and fixtures when no workload exists.
func yamlWorkloadDocuments(docs []yaml.Node) ([]int, error) {
	var workloads, nonempty []int
	for i := range docs {
		if len(docs[i].Content) == 0 {
			continue
		}
		n := docs[i].Content[0]
		if n.Tag == "!!null" {
			continue
		}
		nonempty = append(nonempty, i)
		if n.Kind != yaml.MappingNode {
			continue
		}
		var obj map[string]any
		if err := n.Decode(&obj); err != nil {
			return nil, fmt.Errorf("invalid YAML document %d: %w", i, err)
		}
		kind, _ := obj["kind"].(string)
		metadata, _ := obj["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		generateName, _ := metadata["generateName"].(string)
		if kind == "List" || (strings.HasSuffix(kind, "List") && name == "" && generateName == "") {
			return nil, fmt.Errorf("unsupported YAML edit: resources inside a List wrapper")
		}
		if objectsenvelopes.NewObject(obj) != nil {
			workloads = append(workloads, i)
		}
	}
	if len(workloads) > 0 {
		return workloads, nil
	}
	return nonempty, nil
}

func newYAMLSource(text string, docs []yaml.Node) *yamlSource {
	s := &yamlSource{text: text, lines: []int{0}, parents: make(map[*yaml.Node]*yaml.Node)}
	for i := range text {
		if text[i] == '\n' {
			s.lines = append(s.lines, i+1)
		}
	}
	var visit func(*yaml.Node)
	visit = func(n *yaml.Node) {
		for _, c := range n.Content {
			s.parents[c] = n
			visit(c)
		}
	}
	for i := range docs {
		visit(&docs[i])
	}
	return s
}

func (s *yamlSource) offset(n *yaml.Node) int {
	if n.Line < 1 || n.Line > len(s.lines) {
		return -1
	}
	i := s.lines[n.Line-1]
	for column := 1; column < n.Column && i < len(s.text); column++ {
		_, size := utf8.DecodeRuneInString(s.text[i:])
		i += size
	}
	return i
}

func (s *yamlSource) lineEnd(offset int) int {
	if i := strings.IndexByte(s.text[offset:], '\n'); i >= 0 {
		return offset + i + 1
	}
	return len(s.text)
}

func (s *yamlSource) afterLine(end int) int {
	if end > 0 && s.text[end-1] == '\n' {
		return end
	}
	return s.lineEnd(end)
}

func (s *yamlSource) inFlow(n *yaml.Node) bool {
	for p := s.parents[n]; p != nil; p = s.parents[p] {
		if p.Style&yaml.FlowStyle != 0 {
			return true
		}
	}
	return false
}

func editableYAMLNode(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 {
		return fmt.Errorf("unsupported YAML edit of an alias, anchor or explicit tag")
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Tag == "!!merge" {
				return fmt.Errorf("unsupported YAML edit through a merge key")
			}
		}
	}
	return nil
}

func (s *yamlSource) walk(n *yaml.Node, path []yamlPathPart, op yamlOperation) ([]yamlSourceEdit, error) {
	if err := editableYAMLNode(n); err != nil {
		return nil, err
	}
	if n.Tag == "!!null" && len(path) > 0 && op.kind != "del" {
		value, err := missingYAMLPath(path, op)
		if err != nil {
			return nil, err
		}
		return s.replace(n, value)
	}
	if len(path) == 0 {
		if op.kind == "+=" {
			if n.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("append requires a sequence")
			}
			values := []*yaml.Node{op.value}
			if op.value.Kind == yaml.SequenceNode {
				values = op.value.Content
			}
			return s.insert(n, values)
		}
		return s.replace(n, op.value)
	}
	p := path[0]
	if p.sequence {
		if n.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("path requires a sequence")
		}
		if p.wildcard {
			if len(n.Content) == 0 {
				return nil, fmt.Errorf("wildcard has no targets")
			}
			if len(path) == 1 && op.kind == "del" {
				return s.replace(n, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"})
			}
			var edits []yamlSourceEdit
			for i := range n.Content {
				concrete := append([]yamlPathPart{{sequence: true, index: i}}, path[1:]...)
				x, err := s.walk(n, concrete, op)
				if err != nil {
					return nil, err
				}
				edits = append(edits, x...)
			}
			return edits, nil
		}
		if p.index > len(n.Content) || (p.index == len(n.Content) && op.kind == "del") {
			return nil, fmt.Errorf("sequence index %d out of range", p.index)
		}
		if p.index == len(n.Content) {
			value, err := missingYAMLPath(path[1:], op)
			if err != nil {
				return nil, err
			}
			return s.insert(n, []*yaml.Node{value})
		}
		if len(path) == 1 && op.kind == "del" {
			return s.remove(n, p.index)
		}
		return s.walk(n.Content[p.index], path[1:], op)
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("path requires a mapping")
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == p.key {
			if len(path) == 1 && op.kind == "del" {
				return s.remove(n, i)
			}
			return s.walk(n.Content[i+1], path[1:], op)
		}
	}
	if op.kind == "del" {
		return nil, fmt.Errorf("delete path does not exist")
	}
	value, err := missingYAMLPath(path[1:], op)
	if err != nil {
		return nil, err
	}
	return s.insert(n, []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: p.key}, value})
}

func missingYAMLPath(path []yamlPathPart, op yamlOperation) (*yaml.Node, error) {
	if len(path) == 0 {
		if op.kind == "+=" && op.value.Kind != yaml.SequenceNode {
			return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{op.value}}, nil
		}
		return op.value, nil
	}
	child, err := missingYAMLPath(path[1:], op)
	if err != nil {
		return nil, err
	}
	p := path[0]
	if p.sequence {
		if p.wildcard || p.index != 0 {
			return nil, fmt.Errorf("cannot create a sparse sequence or wildcard target")
		}
		return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{child}}, nil
	}
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: p.key}, child}}, nil
}

func sameYAMLValue(a, b *yaml.Node) bool {
	if a.Kind != b.Kind || a.Tag != b.Tag || a.Value != b.Value || len(a.Content) != len(b.Content) {
		return false
	}
	for i := range a.Content {
		if !sameYAMLValue(a.Content[i], b.Content[i]) {
			return false
		}
	}
	return true
}

func copyYAMLValue(n *yaml.Node) *yaml.Node {
	c := *n
	c.Style = 0
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, child := range n.Content {
		c.Content[i] = copyYAMLValue(child)
	}
	return &c
}

func renderYAMLFragment(n *yaml.Node, indent int) (string, error) {
	var buf bytes.Buffer
	e := yaml.NewEncoder(&buf)
	e.SetIndent(indent)
	if err := e.Encode(n); err != nil {
		return "", err
	}
	if err := e.Close(); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func (s *yamlSource) replace(n, value *yaml.Node) ([]yamlSourceEdit, error) {
	if sameYAMLValue(n, value) {
		return nil, nil
	}
	if err := safeYAMLSubtree(n); err != nil {
		return nil, err
	}
	start, end, err := s.span(n)
	if err != nil {
		return nil, err
	}
	if n.Kind == yaml.ScalarNode && n.Tag != "!!null" {
		var token yaml.Node
		if err := yaml.Unmarshal([]byte(s.text[start:end]), &token); err != nil || len(token.Content) != 1 || !sameYAMLValue(n, token.Content[0]) {
			return nil, fmt.Errorf("unsupported multiline plain scalar edit")
		}
	}
	v := copyYAMLValue(value)
	if v.Kind == yaml.ScalarNode {
		if n.Tag == "!!str" && v.Tag == "!!str" {
			v.Style = n.Style & (yaml.SingleQuotedStyle | yaml.DoubleQuotedStyle)
		}
		// Multiline strings are emitted as quoted tokens, never block scalars
		// whose indentation could change the surrounding mapping.
		if strings.ContainsAny(v.Value, "\r\n") {
			v.Style = yaml.DoubleQuotedStyle
		}
	} else {
		v.Style = n.Style & yaml.FlowStyle
		if s.inFlow(n) || n.Kind == yaml.ScalarNode {
			v.Style = yaml.FlowStyle
		}
	}
	fragment := v
	if v.Kind == yaml.ScalarNode && s.inFlow(n) {
		// Standalone plain scalars may contain commas/brackets that become
		// syntax in a flow collection. Let the encoder quote in that context.
		fragment = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle, Content: []*yaml.Node{v}}
	}
	text, err := renderYAMLFragment(fragment, s.indent(n))
	if err != nil {
		return nil, err
	}
	if fragment != v {
		text = text[1 : len(text)-1]
	}
	column := s.blockColumn(n)
	// An indentless sequence belongs to its mapping key even though both
	// start in the same column. Other replacement kinds need indentation.
	extra := 0
	if p := s.parents[n]; p != nil && p.Kind == yaml.MappingNode && n.Kind == yaml.SequenceNode && n.Style&yaml.FlowStyle == 0 && (v.Kind != yaml.SequenceNode || len(v.Content) == 0) {
		for i := 1; i < len(p.Content); i += 2 {
			if p.Content[i] == n && n.Column == p.Content[i-1].Column {
				extra = s.indent(n)
			}
		}
	}
	if strings.Contains(text, "\n") {
		if n.Kind == yaml.ScalarNode || n.Style&yaml.FlowStyle != 0 {
			return nil, fmt.Errorf("unsupported scalar/flow to block collection replacement")
		}
		text = strings.ReplaceAll(text, "\n", s.newline(start)+strings.Repeat(" ", column+extra))
	}
	text = strings.Repeat(" ", extra) + text
	if start == end && start > 0 && (s.text[start-1] == ':' || s.text[start-1] == '-') {
		text = " " + text
	}
	return []yamlSourceEdit{{start, end, text}}, nil
}

func safeYAMLSubtree(n *yaml.Node) error {
	if err := editableYAMLNode(n); err != nil {
		return err
	}
	if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return fmt.Errorf("unsupported targeted block scalar edit")
	}
	for _, child := range n.Content {
		if err := safeYAMLSubtree(child); err != nil {
			return err
		}
	}
	return nil
}

// span finds source-token boundaries, not the length of decoded Node.Value.
func (s *yamlSource) span(n *yaml.Node) (int, int, error) {
	start := s.offset(n)
	if start < 0 || start > len(s.text) {
		return 0, 0, fmt.Errorf("missing YAML source position")
	}
	if n.Tag == "!!null" && n.Value == "" {
		return start, start, nil
	}
	// Positions include node properties. Untouched anchored/tagged siblings
	// still need accurate spans when inserting after their containing node.
	tokenStart := start
	for tokenStart < len(s.text) && (s.text[tokenStart] == '&' || s.text[tokenStart] == '!') {
		for tokenStart < len(s.text) && !strings.ContainsRune(" \t\r\n", rune(s.text[tokenStart])) {
			tokenStart++
		}
		for tokenStart < len(s.text) && strings.ContainsRune(" \t\r\n", rune(s.text[tokenStart])) {
			tokenStart++
		}
	}
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		end := tokenStart + 1
		if len(n.Content) > 0 {
			_, last, err := s.span(n.Content[len(n.Content)-1])
			if err != nil {
				return 0, 0, err
			}
			end = last
		}
		if n.Style&yaml.FlowStyle == 0 {
			return start, end, nil
		}
		// yaml.Node already tells us where the last child is. Only separators,
		// comments and the closing delimiter can follow it; do not rescan tokens.
		close := byte('}')
		if n.Kind == yaml.SequenceNode {
			close = ']'
		}
		for end < len(s.text) {
			switch s.text[end] {
			case ' ', '\t', '\r', '\n', ',':
				end++
			case '#':
				end = s.lineEnd(end)
			default:
				if s.text[end] == close {
					return start, end + 1, nil
				}
				return 0, 0, fmt.Errorf("unsupported flow collection boundary")
			}
		}
		return 0, 0, fmt.Errorf("unterminated flow collection")
	}
	if tokenStart == len(s.text) {
		return 0, 0, fmt.Errorf("missing scalar token")
	}
	if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) != 0 {
		quote := s.text[tokenStart]
		for i := tokenStart + 1; i < len(s.text); i++ {
			if quote == '"' && s.text[i] == '\\' {
				i++
				continue
			}
			if s.text[i] == quote {
				if quote == '\'' && i+1 < len(s.text) && s.text[i+1] == '\'' {
					i++
					continue
				}
				return start, i + 1, nil
			}
		}
		return 0, 0, fmt.Errorf("unterminated quoted scalar")
	}
	end := start
	for end < len(s.text) {
		ch := s.text[end]
		if ch == '\r' || ch == '\n' || (ch == '#' && (end == start || s.text[end-1] == ' ' || s.text[end-1] == '\t')) || (s.inFlow(n) && strings.ContainsRune(",]}", rune(ch))) {
			break
		}
		end++
	}
	end = start + len(strings.TrimRight(s.text[start:end], " \t"))
	if n.Kind == yaml.AliasNode {
		return start, end, nil
	}
	// A plain scalar may continue on following lines. Match the parsed value
	// before accepting an end position, stopping before the next syntax node.
	limit := len(s.text)
	for other := range s.parents {
		if other.Line > n.Line && other.Line <= len(s.lines) && s.lines[other.Line-1] < limit {
			limit = s.lines[other.Line-1]
		}
	}
	for {
		var token yaml.Node
		if err := yaml.Unmarshal([]byte(s.text[start:end]), &token); err == nil && len(token.Content) == 1 && sameYAMLValue(n, token.Content[0]) {
			return start, end, nil
		}
		next := s.lineEnd(end)
		if next <= end || next > limit {
			break
		}
		if next == limit {
			// Block scalar chomping can require its terminating newline.
			end = next
			var token yaml.Node
			if err := yaml.Unmarshal([]byte(s.text[start:end]), &token); err == nil && len(token.Content) == 1 && sameYAMLValue(n, token.Content[0]) {
				return start, end, nil
			}
			break
		}
		nextEnd := s.lineEnd(next)
		if nextEnd > limit {
			break
		}
		if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) == 0 {
			nextEnd = start + len(strings.TrimRight(s.text[start:nextEnd], " \t\r\n"))
		}
		if nextEnd <= end {
			break
		}
		end = nextEnd
	}
	return 0, 0, fmt.Errorf("unsupported scalar source span")
}

func (s *yamlSource) newline(at int) string {
	end := s.lineEnd(at)
	if end > 1 && s.text[end-2:end] == "\r\n" {
		return "\r\n"
	}
	if end > 0 && s.text[end-1] == '\n' {
		return "\n"
	}
	return determineNewlineSeparator(s.text)
}

func (s *yamlSource) blockColumn(n *yaml.Node) int {
	if n.Kind == yaml.SequenceNode {
		return n.Column - 1
	}
	if n.Kind == yaml.MappingNode && len(n.Content) > 0 {
		return n.Content[0].Column - 1
	}
	return n.Column - 1
}

func (s *yamlSource) indent(n *yaml.Node) int {
	for p := n; p != nil; p = s.parents[p] {
		if p.Kind != yaml.MappingNode {
			continue
		}
		for i := 1; i < len(p.Content); i += 2 {
			child, key := p.Content[i], p.Content[i-1]
			if child.Kind == yaml.MappingNode && child.Style&yaml.FlowStyle == 0 && child.Line > key.Line && child.Column > key.Column {
				return child.Column - key.Column
			}
		}
	}
	return 2
}

func (s *yamlSource) insert(n *yaml.Node, values []*yaml.Node) ([]yamlSourceEdit, error) {
	if len(values) == 0 {
		return nil, nil
	}
	fragment := &yaml.Node{Kind: n.Kind, Tag: n.Tag}
	for _, v := range values {
		fragment.Content = append(fragment.Content, copyYAMLValue(v))
	}
	start, end, err := s.span(n)
	if err != nil {
		return nil, err
	}
	if n.Style&yaml.FlowStyle != 0 {
		fragment.Style = yaml.FlowStyle
		text, err := renderYAMLFragment(fragment, s.indent(n))
		if err != nil {
			return nil, err
		}
		text = text[1 : len(text)-1]
		if len(n.Content) > 0 {
			_, last, err := s.span(n.Content[len(n.Content)-1])
			if err != nil {
				return nil, err
			}
			tail := strings.TrimSpace(s.text[last : end-1])
			if strings.HasPrefix(tail, ",") {
				text = " " + text
			} else {
				text = ", " + text
			}
		}
		return []yamlSourceEdit{{end - 1, end - 1, text}}, nil
	}
	text, err := renderYAMLFragment(fragment, s.indent(n))
	if err != nil {
		return nil, err
	}
	column := s.blockColumn(n)
	nl := s.newline(start)
	text = withNewline(text, nl)
	text = strings.Repeat(" ", column) + strings.ReplaceAll(text, nl, nl+strings.Repeat(" ", column))
	at := s.afterLine(end)
	if at == len(s.text) && !strings.HasSuffix(s.text, "\n") {
		text = nl + text
	} else {
		text += nl
	}
	return []yamlSourceEdit{{at, at, text}}, nil
}

func (s *yamlSource) remove(parent *yaml.Node, index int) ([]yamlSourceEdit, error) {
	n := parent.Content[index]
	last := n
	stride := 1
	if parent.Kind == yaml.MappingNode {
		last = parent.Content[index+1]
		stride = 2
	}
	if err := safeYAMLSubtree(last); err != nil {
		return nil, err
	}
	start := s.offset(n)
	_, end, err := s.span(last)
	if err != nil {
		return nil, err
	}
	if parent.Style&yaml.FlowStyle != 0 {
		if index+stride < len(parent.Content) {
			end = s.offset(parent.Content[index+stride])
		} else if index > 0 {
			_, previousEnd, err := s.span(parent.Content[index-1])
			if err != nil {
				return nil, err
			}
			start = previousEnd
		}
	} else {
		if index == 0 && parent.Kind == yaml.MappingNode && len(parent.Content) > stride {
			lineStart := s.lines[n.Line-1]
			prefix := s.text[lineStart:start]
			if strings.TrimSpace(prefix) == "-" {
				// The first key can share its line with a sequence indicator.
				// Move that indicator to the next key, preserving comments between.
				next := parent.Content[stride]
				return []yamlSourceEdit{
					{lineStart, s.afterLine(end), ""},
					{s.lines[next.Line-1], s.offset(next), prefix},
				}, nil
			}
		}
		if len(parent.Content) == stride {
			// An empty block container needs an explicit {} or [] value.
			empty := "{}"
			if parent.Kind == yaml.SequenceNode {
				empty = "[]"
			}
			start = s.offset(parent)
			if owner := s.parents[parent]; owner != nil && owner.Kind == yaml.MappingNode {
				for i := 1; i < len(owner.Content); i += 2 {
					if owner.Content[i] == parent {
						key := owner.Content[i-1]
						// Empty containers must remain values of their key, including
						// when the original sequence used indentless dashes.
						keyEnd := s.lineEnd(s.offset(key))
						if parent.Line > key.Line && strings.TrimSpace(s.text[s.offset(key):keyEnd]) == key.Value+":" {
							return []yamlSourceEdit{{s.offset(key) + len(key.Value) + 1, end, " " + empty}}, nil
						}
						if parent.Kind == yaml.SequenceNode && parent.Column == key.Column {
							empty = strings.Repeat(" ", s.indent(parent)) + empty
						}
					}
				}
			}
			return []yamlSourceEdit{{start, end, empty}}, nil
		}
		start = s.lines[n.Line-1]
		end = s.afterLine(end)
		// Keep the file's final-newline convention when removing its last item.
		if end == len(s.text) && !strings.HasSuffix(s.text, "\n") && start > 0 {
			start--
			if start > 0 && s.text[start-1] == '\r' {
				start--
			}
		}
	}
	return []yamlSourceEdit{{start, end, ""}}, nil
}
