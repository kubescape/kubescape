package mcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// classifyScanError maps a raw error from the scan pipeline to a
// machine-readable ErrorCode. Uses only errors.Is and typed error
// checks — no string matching.
//
// Ordering safety: sentinels are errors.New values (never
// *apierrors.StatusError), so they cannot match apierrors.IsForbidden
// or apierrors.IsNotFound. Conversely, apierrors checks only match
// *apierrors.StatusError, which no sentinel wraps. The two groups are
// type-disjoint, so no cross-matching is possible.
func classifyScanError(err error) ErrorCode {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, cautils.ErrInvalidWorkloadIdentifier):
		return ErrCodeMalformedIdentifier

	case errors.Is(err, resourcehandler.ErrResourceNotFound),
		errors.Is(err, resourcehandler.ErrResourceNotInDiscovery):
		return ErrCodeResourceNotFound
	case errors.Is(err, resourcehandler.ErrAmbiguousResource):
		return ErrCodeAmbiguousResource
	case errors.Is(err, resourcehandler.ErrResourceHasParent):
		return ErrCodeResourceHasParent
	case errors.Is(err, resourcehandler.ErrNotWorkload):
		return ErrCodeNotWorkload
	case errors.Is(err, resourcehandler.ErrSecretScanDenied):
		return ErrCodeSecretScanDenied

	case apierrors.IsForbidden(err):
		return ErrCodeRBACDenied
	case apierrors.IsNotFound(err):
		return ErrCodeResourceNotFound

	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled):
		return ErrCodeTimeout

	default:
		var statusErr *apierrors.StatusError
		if errors.As(err, &statusErr) {
			return ErrCodeK8sClientError
		}
		return ErrCodeScanFailed
	}
}

// classifyScanErrorMessage returns a cause-specific human-readable
// message prefix for a classified scan error. The caller appends
// the original err.Error() for full context.
func classifyScanErrorMessage(code ErrorCode, label string, err error) string {
	switch code {
	case ErrCodeMalformedIdentifier:
		return fmt.Sprintf("invalid workload identifier: %v", err)
	case ErrCodeResourceNotFound:
		return fmt.Sprintf("resource not found: %v", err)
	case ErrCodeAmbiguousResource:
		return fmt.Sprintf("ambiguous resource match: %v", err)
	case ErrCodeResourceHasParent:
		return fmt.Sprintf("resource has a parent controller and cannot be scanned directly: %v", err)
	case ErrCodeNotWorkload:
		return fmt.Sprintf("resource is not a scannable workload: %v", err)
	case ErrCodeSecretScanDenied:
		return fmt.Sprintf("scanning Secret resources is not supported: %v", err)
	case ErrCodeRBACDenied:
		return fmt.Sprintf("insufficient permissions: %v", err)
	case ErrCodeK8sClientError:
		return fmt.Sprintf("kubernetes client error during %s scan: %v", label, err)
	case ErrCodeTimeout:
		return fmt.Sprintf("%s scan timed out: %v", label, err)
	default:
		return fmt.Sprintf("failed to run %s scan: %v", label, err)
	}
}
