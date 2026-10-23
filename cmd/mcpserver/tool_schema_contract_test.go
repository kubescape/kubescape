package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// toolNamePattern is the tool-name charset recommended by the MCP
// specification (1-128 characters of A-Z, a-z, 0-9, '_', '-' and '.').
var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

var jsonSchemaTypes = map[string]bool{
	"string": true, "number": true, "integer": true, "boolean": true,
	"object": true, "array": true, "null": true,
}

// schemaCombinators are keywords that let a property carry its type through
// sub-schemas (or a reference) instead of a top-level "type", as the
// control_ids arguments do with anyOf.
var schemaCombinators = []string{"anyOf", "oneOf", "allOf", "$ref", "enum", "const"}

// TestRegisteredToolSchemasHonourContract enumerates every tool the server
// registers (through registerTools, the same path mcpServerEntrypoint uses)
// and checks the schema each one advertises over tools/list. A tool added to
// any registrar is covered without touching this test.
func TestRegisteredToolSchemasHonourContract(t *testing.T) {
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	require.NotPanics(t, func() { registerTools(ksServer) })

	resp := ksServer.s.HandleMessage(context.Background(), json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	var list struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &list), "tools/list response: %s", raw)
	require.NotEmpty(t, list.Result.Tools, "registerTools registered no tools")

	assert.Empty(t, toolSchemaViolations(list.Result.Tools))
}

func TestToolSchemaViolations(t *testing.T) {
	str := map[string]any{"type": "string", "description": "d"}
	tool := func(name string, schema map[string]any) map[string]any {
		return map[string]any{"name": name, "description": "does a thing", "inputSchema": schema}
	}
	object := func(props map[string]any, required ...any) map[string]any {
		schema := map[string]any{"type": "object", "properties": props}
		if required != nil {
			schema["required"] = required
		}
		return schema
	}

	tests := []struct {
		name  string
		tools []map[string]any
		want  []string // substrings, one per expected violation, in order
	}{
		{
			name: "valid: plain, optional, anyOf and enum properties",
			tools: []map[string]any{
				tool("scan", object(map[string]any{
					"namespace": str,
					"ids": map[string]any{"description": "d", "anyOf": []any{
						map[string]any{"type": "string"},
						map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					}},
					"level": map[string]any{"type": "string", "description": "d", "enum": []any{"a", "b"}},
				}, "ids")),
				tool("noargs", map[string]any{"type": "object", "properties": map[string]any{}, "required": []any{}}),
			},
		},
		{
			name:  "no tools",
			tools: nil,
			want:  []string{"no tools"},
		},
		{
			name:  "empty and invalid names",
			tools: []map[string]any{tool("", object(nil)), tool("has space", object(nil))},
			want:  []string{"empty name", `"has space": name`},
		},
		{
			name:  "duplicate name",
			tools: []map[string]any{tool("dup", object(nil)), tool("dup", object(nil))},
			want:  []string{`"dup": registered more than once`},
		},
		{
			name: "blank description",
			tools: []map[string]any{{
				"name": "blank", "description": "  ", "inputSchema": object(nil),
			}},
			want: []string{`"blank": description is empty`},
		},
		{
			name:  "root is not an object schema",
			tools: []map[string]any{tool("root", map[string]any{"type": "array"}), tool("missing", nil)},
			want:  []string{`"root": inputSchema.type is "array"`, `"missing": inputSchema is missing`},
		},
		{
			name:  "required names an undeclared property, or repeats one",
			tools: []map[string]any{tool("req", object(map[string]any{"a": str}, "a", "a", "b"))},
			want:  []string{`"req": required "a" is listed more than once`, `"req": required "b" is not in properties`},
		},
		{
			name: "property without type, description or items",
			tools: []map[string]any{tool("props", object(map[string]any{
				"untyped":   map[string]any{"description": "d"},
				"bogus":     map[string]any{"type": "text", "description": "d"},
				"nodesc":    map[string]any{"type": "string"},
				"noitems":   map[string]any{"type": "array", "description": "d"},
				"notobj":    "string",
				"emptyenum": map[string]any{"type": "string", "description": "d", "enum": []any{}},
				"dupenum":   map[string]any{"type": "string", "description": "d", "enum": []any{"a", "a"}},
			}))},
			want: []string{
				`"props": property "bogus": unknown type "text"`,
				`"props": property "dupenum": enum value "a" is repeated`,
				`"props": property "emptyenum": enum is empty`,
				`"props": property "nodesc": description is empty`,
				`"props": property "noitems": array has no items`,
				`"props": property "notobj": schema is not an object`,
				`"props": property "untyped": no type`,
			},
		},
		{
			name: "anyOf branches are checked too",
			tools: []map[string]any{tool("branch", object(map[string]any{
				"x": map[string]any{"description": "d", "anyOf": []any{
					map[string]any{"type": "string"},
					map[string]any{"minLength": 1},
				}},
			}))},
			want: []string{`"branch": property "x": anyOf[1]: no type`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toolSchemaViolations(tt.tools)
			require.Len(t, got, len(tt.want), "violations: %v", got)
			for i, want := range tt.want {
				assert.Contains(t, got[i], want)
			}
		})
	}
}

// toolSchemaViolations returns one message per contract violation found in the
// tools of a tools/list response, ordered deterministically.
func toolSchemaViolations(tools []map[string]any) []string {
	var out []string
	if len(tools) == 0 {
		return []string{"tools/list returned no tools"}
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		label := fmt.Sprintf("tool %q", name)
		switch {
		case name == "":
			out = append(out, "tool with an empty name")
			label = "tool with an empty name"
		case !toolNamePattern.MatchString(name):
			out = append(out, label+": name does not match "+toolNamePattern.String())
		case seen[name]:
			out = append(out, label+": registered more than once")
		}
		seen[name] = true

		if desc, _ := tool["description"].(string); strings.TrimSpace(desc) == "" {
			out = append(out, label+": description is empty")
		}

		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok || schema == nil {
			out = append(out, label+": inputSchema is missing")
			continue
		}
		if typ := schema["type"]; typ != "object" {
			out = append(out, fmt.Sprintf("%s: inputSchema.type is %q, want \"object\"", label, typ))
		}
		props, _ := schema["properties"].(map[string]any)

		reqSeen := map[string]bool{}
		required, _ := schema["required"].([]any)
		for _, r := range required {
			arg, _ := r.(string)
			if reqSeen[arg] {
				out = append(out, fmt.Sprintf("%s: required %q is listed more than once", label, arg))
				continue
			}
			reqSeen[arg] = true
			if _, declared := props[arg]; !declared {
				out = append(out, fmt.Sprintf("%s: required %q is not in properties", label, arg))
			}
		}

		for _, prop := range sortedKeys(props) {
			for _, msg := range propertyViolations(props[prop], true) {
				out = append(out, fmt.Sprintf("%s: property %q: %s", label, prop, msg))
			}
		}
	}
	return out
}

// propertyViolations checks one property schema. Descriptions are required on
// the property itself (every argument documents itself for the model) but not
// on the sub-schemas of a combinator.
func propertyViolations(v any, top bool) []string {
	schema, ok := v.(map[string]any)
	if !ok {
		return []string{"schema is not an object"}
	}
	var out []string
	if desc, _ := schema["description"].(string); top && strings.TrimSpace(desc) == "" {
		out = append(out, "description is empty")
	}

	hasCombinator := false
	for _, k := range schemaCombinators {
		if _, ok := schema[k]; ok {
			hasCombinator = true
		}
	}
	if typ, ok := schema["type"]; ok {
		for _, t := range typeNames(typ) {
			if !jsonSchemaTypes[t] {
				out = append(out, fmt.Sprintf("unknown type %q", t))
			}
		}
		if contains(typeNames(typ), "array") && schema["items"] == nil {
			out = append(out, "array has no items")
		}
	} else if !hasCombinator {
		out = append(out, "no type")
	}

	if enum, ok := schema["enum"].([]any); ok {
		if len(enum) == 0 {
			out = append(out, "enum is empty")
		}
		seen := map[string]bool{}
		for _, e := range enum {
			key := fmt.Sprintf("%v", e)
			if seen[key] {
				out = append(out, fmt.Sprintf("enum value %q is repeated", key))
			}
			seen[key] = true
		}
	}

	for _, k := range []string{"anyOf", "oneOf", "allOf"} {
		branches, _ := schema[k].([]any)
		for i, b := range branches {
			for _, msg := range propertyViolations(b, false) {
				out = append(out, fmt.Sprintf("%s[%d]: %s", k, i, msg))
			}
		}
	}
	return out
}

// typeNames returns the names in a JSON Schema "type", which is either a
// string or an array of strings.
func typeNames(typ any) []string {
	switch t := typ.(type) {
	case string:
		return []string{t}
	case []any:
		var names []string
		for _, e := range t {
			s, _ := e.(string)
			names = append(names, s)
		}
		return names
	}
	return []string{fmt.Sprintf("%v", typ)}
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
