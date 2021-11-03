package policyhandler

import (
	"fmt"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
)

func (policyHandler *PolicyHandler) getPolicies(notification *reporthandling.PolicyNotification, policiesAndResources *cautils.OPASessionObj) error {
	cautils.ProgressTextDisplay("Downloading/Loading policy definitions")

	frameworks, err := policyHandler.getScanPolicies(notification)
	if err != nil {
		return err
	}
	if len(frameworks) == 0 {
		return fmt.Errorf("failed to download policies, please ARMO team for more information")
	}

	policiesAndResources.Frameworks = frameworks

	// get exceptions
	exceptionPolicies, err := policyHandler.getters.ExceptionsGetter.GetExceptions(cautils.CustomerGUID, cautils.ClusterName)
	if err == nil {
		policiesAndResources.Exceptions = exceptionPolicies
	}

	// get account configuration
	controlsInputs, err := policyHandler.getters.ControlsInputsGetter.GetControlsInputs(cautils.CustomerGUID, cautils.ClusterName)
	if err == nil {
		policiesAndResources.RegoInputData.PostureControlInputs = controlsInputs
	}

	cautils.SuccessTextDisplay("Downloaded/Loaded policy")
	return nil
}

func (policyHandler *PolicyHandler) getScanPolicies(notification *reporthandling.PolicyNotification) ([]reporthandling.Framework, error) {
	frameworks := []reporthandling.Framework{}

	switch getScanKind(notification) {
	case reporthandling.KindFramework: // Download frameworks
		for _, rule := range notification.Rules {
			receivedFramework, err := policyHandler.getters.PolicyGetter.GetFramework(rule.Name)
			if err != nil {
				return frameworks, policyDownloadError(err)
			}
			if receivedFramework != nil {
				frameworks = append(frameworks, *receivedFramework)
			}
		}
	case reporthandling.KindControl: // Download controls
		f := reporthandling.Framework{}
		var receivedControl *reporthandling.Control
		var err error
		for _, rule := range notification.Rules {
			receivedControl, err = policyHandler.getters.PolicyGetter.GetControl(rule.Name)
			if err != nil {
				return frameworks, policyDownloadError(err)
			}

			if receivedControl != nil {
				f.Controls = append(f.Controls, *receivedControl)
			}
		}
		frameworks = append(frameworks, f)
		// TODO: add case for control from file
	default:
		return frameworks, fmt.Errorf("unknown policy kind")
	}
	return frameworks, nil
}
