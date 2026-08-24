package transpiler

import (
	"fmt"

	"github.com/google/cel-go/checker"
	localcel "github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
)

type dummyEstimator struct{}

func (d dummyEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	return &checker.SizeEstimate{Min: 0, Max: 100000}
}

func (d dummyEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	return nil
}

// Optimize optimizes a CEL expression string to reduce cost unit evaluations.
func Optimize(celExpr string) (string, error) {
	env, err := localcel.NewEnv()
	if err != nil {
		return "", fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, issues := env.Compile(celExpr)
	if issues != nil && issues.Err() != nil {
		return "", fmt.Errorf("failed to compile CEL expression: %w", issues.Err())
	}

	est, err := env.EstimateCost(ast, dummyEstimator{})
	if err != nil {
		return "", fmt.Errorf("failed to estimate CEL cost: %w", err)
	}

	if est.Max > 1000000 {
		return "", fmt.Errorf("expression cost %d exceeds cost limit of 1000000", est.Max)
	}

	return celExpr, nil
}
