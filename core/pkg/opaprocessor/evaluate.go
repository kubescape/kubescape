package opaprocessor

import (
	"context"
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
)

// EvaluateRule runs a single policy rule against resourcesToScan end-to-end:
// resource aggregation, the ResourceEnumerator pre-pass, and Rego/CEL
// evaluation, the same path a real scan takes for one rule. It exists so
// callers outside a full scan session, such as a policy-testing harness, can
// validate a rule's behavior in isolation.
func (opap *OPAProcessor) EvaluateRule(ctx context.Context, rule *reporthandling.PolicyRule, resourcesToScan []workloadinterface.IMetadata, controlID string) ([]reporthandling.RuleResponse, error) {
	inputResources, err := reporthandling.RegoResourcesAggregator(rule, resourcesToScan)
	if err != nil {
		return nil, fmt.Errorf("aggregator failed: %w", err)
	}
	if len(inputResources) == 0 {
		return nil, nil
	}

	inputRawResources := workloadinterface.ListMetaToMap(inputResources)

	enumeratedData, err := opap.enumerateData(ctx, rule, inputRawResources, controlID)
	if err != nil {
		return nil, fmt.Errorf("enumerator failed: %w", err)
	}

	ruleRegoDependenciesData := opap.makeRegoDeps(rule.ControlConfigInputs, nil)
	ruleResponses, _, err := opap.runOPAOnSingleRule(ctx, rule, enumeratedData, ruleData, ruleRegoDependenciesData, controlID)
	return ruleResponses, err
}
