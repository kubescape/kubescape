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
	rule := GetScanKind(notification)

	switch rule.Kind {
	case reporthandling.KindFramework:
		for _, rule := range notification.Rules {
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
		}
	case reporthandling.KindControl:
		f := reporthandling.Framework{}
		var receivedControl *reporthandling.Control
		var recExceptionPolicies []armotypes.PostureExceptionPolicy
		var err error
		for _, rule := range notification.Rules {
			receivedControl, recExceptionPolicies, err = policyHandler.getControl(rule.Name)
			if receivedControl != nil {
				f.Controls = append(f.Controls, *receivedControl)
				if recExceptionPolicies != nil {
					exceptionPolicies = append(exceptionPolicies, recExceptionPolicies...)
				}

			} else if err != nil {
				if strings.Contains(err.Error(), "unsupported protocol scheme") {
					err = fmt.Errorf("failed to download from GitHub release, try running with `--use-default` flag")
				}
				return nil, nil, fmt.Errorf("error: %s", err.Error())
			}
		}
		frameworks = append(frameworks, f)
		// TODO: add case for control from file
	default:
		err := fmt.Errorf("missing rule kind, expected: %s", reporthandling.KindFramework)
		errs = fmt.Errorf("%s", err.Error())
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

func GetScanKind(notification *reporthandling.PolicyNotification) *reporthandling.PolicyIdentifier {
	if len(notification.Rules) > 0 {
		return &notification.Rules[0]
	}
	return nil
}

// Get control by name
func (policyHandler *PolicyHandler) getControl(policyName string) (*reporthandling.Control, []armotypes.PostureExceptionPolicy, error) {

	control := &reporthandling.Control{}
	var err error
	control, err = policyHandler.getters.PolicyGetter.GetControl(policyName)
	if err != nil {
		return control, nil, err
	}
	// if control == nil {
	// 	return control, nil, fmt.Errorf("control not found")
	// }

	exceptions, err := policyHandler.getters.ExceptionsGetter.GetExceptions(cautils.CustomerGUID, cautils.ClusterName)
	if err != nil {
		return control, nil, err
	}

	return control, exceptions, nil
}
