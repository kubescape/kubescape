package policyhandler

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/opa-utils/reporthandling"
)

func frameworkDownloadError(err error, fwName string) error {
	if strings.Contains(err.Error(), "unsupported protocol scheme") {
		err = fmt.Errorf("failed to download from GitHub release, try running with `--use-default` flag")
	}
	if strings.Contains(err.Error(), "not found") {
		err = fmt.Errorf("framework '%s' not found, run `kubescape list frameworks` for available frameworks", fwName)
	}
	return err
}

// controlLookupError carries a user-facing message while keeping the error it
// replaced reachable through errors.Is and errors.As, so callers can still tell
// an unknown control from a catalog failure.
type controlLookupError struct {
	msg   string
	cause error
}

func (e *controlLookupError) Error() string { return e.msg }
func (e *controlLookupError) Unwrap() error { return e.cause }

func controlDownloadError(err error, controls string) error {
	if strings.Contains(err.Error(), "unsupported protocol scheme") {
		err = fmt.Errorf("failed to download from GitHub release, try running with `--use-default` flag")
	}
	// Only a genuine unknown control is reworded: a catalog failure never
	// carries the sentinel, whatever its text says.
	if errors.Is(err, getter.ErrControlNotFound) && strings.Contains(err.Error(), "not found") {
		err = &controlLookupError{
			msg:   fmt.Sprintf("control '%s' not found, run `kubescape list controls` for available controls", controls),
			cause: err,
		}
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

// getPoliciesCacheTtl returns the policy cache TTL from the POLICIES_CACHE_TTL
// environment variable. It first tries to parse the value as a Go duration
// string (e.g. "5m", "90s", "1h30m"). If that fails it falls back to treating
// the value as an integer number of minutes for backwards compatibility with
// callers that set POLICIES_CACHE_TTL=5 (meaning 5 minutes).
func getPoliciesCacheTtl() time.Duration {
	if d, err := cautils.ParseDurationEnvVar(PoliciesCacheTtlEnvVar, 0); err == nil {
		return d
	}

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
