package policyhandler

import (
	"fmt"
	"strings"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"

	"github.com/kubescape/kubescape/v2/core/cautils"
)

func getScanKind(policyIdentifier []cautils.PolicyIdentifier) apisv1.NotificationPolicyKind {
	if len(policyIdentifier) > 0 {
		return policyIdentifier[0].Kind
	}
	return "unknown"
}
func policyDownloadError(err error) error {
	if strings.Contains(err.Error(), "unsupported protocol scheme") {
		err = fmt.Errorf("failed to download from GitHub release, try running with `--use-default` flag")
	}
	return err
}

// validate the framework
func validateFramework(framework *reporthandling.Framework) error {
	if framework == nil {
		return fmt.Errorf("received empty framework")
	}

	// validate the controls are not empty
	if len(framework.Controls) == 0 {
		return fmt.Errorf("failed to load controls for framework: %s: empty list of controls", framework.Name)
	}
	return nil
}
