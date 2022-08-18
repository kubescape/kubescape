package policyhandler

import (
	"fmt"
	"strings"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"

	"github.com/armosec/kubescape/v2/core/cautils"
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
