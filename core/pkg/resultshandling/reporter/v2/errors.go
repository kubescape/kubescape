package reporter

import (
	"errors"
	"fmt"
)

var (
	// ErrRequireAccountID complains that an account ID is required to post reports.
	ErrRequireAccountID = errors.New("failed to publish results. Reason: Unknown account ID. Run kubescape with the '--account <account ID>' flag. Contact ARMO team for more details")

	// ErrRequireClusterName complaines that a cluster name is required to post reports with a scanning target set to Cluster.
	ErrRequireClusterName = errors.New("failed to publish results because the cluster name is Unknown. If you are scanning YAML files the results are not submitted to the Kubescape SaaS")
)

func errMarshal(id string, cause error) error {
	return fmt.Errorf("failed to marshal resource '%s' to JSON, reason: %w", id, cause)
}

func errSubmit(url string, cause error) error {
	return fmt.Errorf("failed to submit scan results. url: '%s', reason: %w", url, cause)
}
