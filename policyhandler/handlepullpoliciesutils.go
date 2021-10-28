package policyhandler

import (
	"fmt"
	"strings"

	"github.com/armosec/opa-utils/reporthandling"
)

func getScanKind(notification *reporthandling.PolicyNotification) reporthandling.NotificationPolicyKind {
	if len(notification.Rules) > 0 {
		return notification.Rules[0].Kind
	}
	return "unknown"
}
func policyDownloadError(err error) error {
	if strings.Contains(err.Error(), "unsupported protocol scheme") {
		err = fmt.Errorf("failed to download from GitHub release, try running with `--use-default` flag")
	}
	return err
}
