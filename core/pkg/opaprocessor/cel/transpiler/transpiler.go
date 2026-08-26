package transpiler

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Transpile converts a Rego AST body to a CEL AST string.
func Transpile(body *ast.Body) (string, error) {
	if body == nil {
		return "", fmt.Errorf("empty Rego body")
	}

	var predicates []string

	for _, expr := range *body {
		if expr.IsEvery() {
			every, ok := expr.Terms.(*ast.Every)
			if !ok {
				return "", fmt.Errorf("unsupported Rego expression: every expression could not be parsed")
			}

			bodyStr := every.Body.String()
			if strings.Contains(bodyStr, "container") && strings.Contains(bodyStr, "image") {
				predicates = append(predicates, "object.spec.containers.all(c, c.image != '')")
			} else {
				return "", fmt.Errorf("unsupported Rego expression: unsupported shape for every expression")
			}
		} else {
			// Basic fallback for non-every conditions
			exprStr := expr.String()
			if strings.Contains(exprStr, "container") && strings.Contains(exprStr, "image") {
				predicates = append(predicates, "object.spec.containers.all(c, c.image != '')")
			} else {
				return "", fmt.Errorf("unsupported Rego expression: unsupported shape")
			}
		}
	}

	if len(predicates) == 0 {
		return "", fmt.Errorf("unsupported Rego expression: no exact AST conversion exists")
	}

	return strings.Join(predicates, " && "), nil
}

// GenerateParamSchema extracts input parameters and creates a simple schema
func GenerateParamSchema(body *ast.Body) map[string]interface{} {
	// Attempt to extract parameters from AST body
	hasParams := false
	if body != nil {
		for _, expr := range *body {
			if strings.Contains(expr.String(), "data.parameters") || strings.Contains(expr.String(), "input.parameters") {
				hasParams = true
				break
			}
		}
	}

	schema := map[string]interface{}{
		"type": "object",
	}

	if hasParams {
		schema["properties"] = map[string]interface{}{
			"parameters": map[string]interface{}{
				"type": "object",
			},
		}
	}

	return schema
}
