package getter

import (
	"context"
	"errors"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
)

type (
	// IPolicyGetter knows how to retrieve policies, i.e. frameworks and their controls.
	IPolicyGetter interface {
		GetFramework(name string) (*reporthandling.Framework, error)
		GetFrameworks() ([]reporthandling.Framework, error)
		GetControl(ID string) (*reporthandling.Control, error)

		ListFrameworks() ([]string, error)
		ListControls() ([]string, error)
	}

	// IExceptionsGetter knows how to retrieve exceptions.
	IExceptionsGetter interface {
		GetExceptions(ctx context.Context, clusterName string) ([]armotypes.PostureExceptionPolicy, error)
	}

	// IControlsInputsGetter knows how to retrieve controls inputs.
	IControlsInputsGetter interface {
		GetControlsInputs(ctx context.Context, clusterName string) (map[string][]string, error)
	}

	// IAttackTracksGetter knows how to retrieve attack tracks.
	IAttackTracksGetter interface {
		GetAttackTracks() ([]v1alpha1.AttackTrack, error)
	}
)

// isContextErr reports whether err was caused by context cancellation or a deadline.
func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
