package policyhandler

import (
	"fmt"
	"strings"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
)

func (policyHandler *PolicyHandler) getPolicies(policyIdentifier []cautils.PolicyIdentifier, policiesAndResources *cautils.OPASessionObj) error {
	logger.L().Info("Downloading/Loading policy definitions")

	cautils.StartSpinner()
	defer cautils.StopSpinner()

	policies, err := policyHandler.getScanPolicies(policyIdentifier)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return fmt.Errorf("failed to download policies: '%s'. Make sure the policy exist and you spelled it correctly. For more information, please feel free to contact ARMO team", strings.Join(policyIdentifierToSlice(policyIdentifier), ", "))
	}

	policiesAndResources.Policies = policies

	// get exceptions
	exceptionPolicies, err := policyHandler.getters.ExceptionsGetter.GetExceptions(cautils.ClusterName)
	if err == nil {
		policiesAndResources.Exceptions = exceptionPolicies
	} else {
		logger.L().Error("failed to load exceptions", helpers.Error(err))
	}

	// get account configuration
	controlsInputs, err := policyHandler.getters.ControlsInputsGetter.GetControlsInputs(cautils.ClusterName)
	if err == nil {
		policiesAndResources.RegoInputData.PostureControlInputs = controlsInputs
	} else {
		logger.L().Error(err.Error())
	}
	cautils.StopSpinner()

	logger.L().Success("Downloaded/Loaded policy")
	return nil
}

func (policyHandler *PolicyHandler) getScanPolicies(policyIdentifier []cautils.PolicyIdentifier) ([]reporthandling.Framework, error) {
	frameworks := []reporthandling.Framework{}

	switch getScanKind(policyIdentifier) {
	case apisv1.KindFramework: // Download frameworks
		for _, rule := range policyIdentifier {
			receivedFramework, err := policyHandler.getters.PolicyGetter.GetFramework(rule.Identifier)
			if err != nil {
				return frameworks, policyDownloadError(err)
			}
			if err := validateFramework(receivedFramework); err != nil {
				return frameworks, err
			}
			if receivedFramework != nil {
				frameworks = append(frameworks, *receivedFramework)
				cache := getter.GetDefaultPath(rule.Identifier + ".json")
				if err := getter.SaveInFile(receivedFramework, cache); err != nil {
					logger.L().Warning("failed to cache file", helpers.String("file", cache), helpers.Error(err))
				}
			}
		}
	case apisv1.KindControl: // Download controls
		f := reporthandling.Framework{}
		var receivedControl *reporthandling.Control
		var err error
		for _, policy := range policyIdentifier {
			receivedControl, err = policyHandler.getters.PolicyGetter.GetControl(policy.Identifier)
			if err != nil {
				return frameworks, policyDownloadError(err)
			}
			if receivedControl != nil {
				f.Controls = append(f.Controls, *receivedControl)

				cache := getter.GetDefaultPath(policy.Identifier + ".json")
				if err := getter.SaveInFile(receivedControl, cache); err != nil {
					logger.L().Warning("failed to cache file", helpers.String("file", cache), helpers.Error(err))
				}
			}
		}
		frameworks = append(frameworks, f)
		// TODO: add case for control from file
	default:
		return frameworks, fmt.Errorf("unknown policy kind")
	}
	return frameworks, nil
}

func policyIdentifierToSlice(rules []cautils.PolicyIdentifier) []string {
	s := []string{}
	for i := range rules {
		s = append(s, fmt.Sprintf("%s: %s", rules[i].Kind, rules[i].Identifier))
	}
	return s
}
