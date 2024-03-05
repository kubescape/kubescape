package policyhandler

import (
	"fmt"
	"strings"
	"time"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"

	"github.com/kubescape/kubescape/v3/core/cautils"
)

func getScanKind(policyIdentifier []cautils.PolicyIdentifier) apisv1.NotificationPolicyKind {
	if len(policyIdentifier) > 0 {
		return policyIdentifier[0].Kind
	}
	return "unknown"
}
func frameworkDownloadError(err error, fwName string) error {
	if strings.Contains(err.Error(), "unsupported protocol scheme") {
		err = fmt.Errorf("failed to download from GitHub release, try running with `--use-default` flag")
	}
	if strings.Contains(err.Error(), "not found") {
		err = fmt.Errorf("framework '%s' not found, run `kubescape list frameworks` for available frameworks", fwName)
	}
	return err
}
func controlDownloadError(err error, controls string) error {
	if strings.Contains(err.Error(), "unsupported protocol scheme") {
		err = fmt.Errorf("failed to download from GitHub release, try running with `--use-default` flag")
	}
	if strings.Contains(err.Error(), "not found") {
		err = fmt.Errorf("control '%s' not found, run `kubescape list controls` for available controls", controls)
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

// getPoliciesCacheTtl - get policies cache TTL from environment variable or return 0 if not set
func getPoliciesCacheTtl() time.Duration {
	if val, err := cautils.ParseIntEnvVar(PoliciesCacheTtlEnvVar, 0); err == nil {
		return time.Duration(val) * time.Minute
	}

	return 0
}

func policyIdentifierToSlice(rules []cautils.PolicyIdentifier) []string {
	s := []string{}
	for i := range rules {
		s = append(s, fmt.Sprintf("%s: %s", rules[i].Kind, rules[i].Identifier))
	}
	return s
}
