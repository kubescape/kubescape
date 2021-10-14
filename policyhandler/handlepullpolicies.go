package policyhandler

import (
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
)

func (policyHandler *PolicyHandler) GetPoliciesFromBackend(notification *reporthandling.PolicyNotification) ([]reporthandling.Framework, []armotypes.PostureExceptionPolicy, error) {
	var errs error
	frameworks := []reporthandling.Framework{}
	exceptionPolicies := []armotypes.PostureExceptionPolicy{}

	// Get - cacli opa get
	for _, rule := range notification.Rules {
		switch rule.Kind {
		case reporthandling.KindFramework:
			receivedFramework, recExceptionPolicies, err := policyHandler.getFrameworkPolicies(rule.Name)
			if receivedFramework != nil {
				frameworks = append(frameworks, *receivedFramework)
				if recExceptionPolicies != nil {
					exceptionPolicies = append(exceptionPolicies, recExceptionPolicies...)
				}
			} else if err != nil {
				if strings.Contains(err.Error(), "unsupported protocol scheme") {
					err = fmt.Errorf("failed to download from GitHub release, try running with `--use-default` flag")
				}
				return nil, nil, fmt.Errorf("kind: %v, name: %s, error: %s", rule.Kind, rule.Name, err.Error())
			}

		default:
			err := fmt.Errorf("missing rule kind, expected: %s", reporthandling.KindFramework)
			errs = fmt.Errorf("%s", err.Error())
		}
	}
	return frameworks, exceptionPolicies, errs
}

func (policyHandler *PolicyHandler) getFrameworkPolicies(policyName string) (*reporthandling.Framework, []armotypes.PostureExceptionPolicy, error) {
	receivedFramework, err := policyHandler.getters.PolicyGetter.GetFramework(policyName)
	if err != nil {
		return nil, nil, err
	}

	receivedException, err := policyHandler.getters.ExceptionsGetter.GetExceptions(cautils.CustomerGUID, cautils.ClusterName)
	if err != nil {
		return receivedFramework, nil, err
	}

	return receivedFramework, receivedException, nil
}
