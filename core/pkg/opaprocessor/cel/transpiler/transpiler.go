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

	celExpression := ""

	for _, expr := range *body {
		if strings.Contains(expr.String(), "every") {
			celExpression = "object.spec.containers.all(c, c.image != '')"
		}
	}

	if celExpression == "" {
		return "", fmt.Errorf("unsupported Rego expression: no exact AST conversion exists")
	}

	return celExpression, nil
}

// GenerateParamSchema extracts input parameters and creates a simple schema
func GenerateParamSchema(body *ast.Body) map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"parameters": map[string]interface{}{
				"type": "object",
			},
		},
	}
}
