package getter

import (
	"context"
	"errors"
	"fmt"

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

	// ConsumedFileDigester is implemented by local getters that retain the
	// digest of the exact file bytes they successfully consumed. It is optional
	// so remote and CRD-backed getters keep their existing interfaces.
	ConsumedFileDigester interface {
		ConsumedFileDigest() (path, digest string, ok bool)
	}

	// CacheSourcer is implemented by getters whose type alone does not say
	// which source they read, such as one getter type over different files.
	CacheSourcer interface {
		CacheSource() string
	}
)

// CacheSourceOf identifies the source a getter reads, so a cache shared by
// scans with different sources only serves an entry to the source that
// produced it. Getters without a CacheSource are identified by their type.
func CacheSourceOf(g any) string {
	if s, ok := g.(CacheSourcer); ok {
		return s.CacheSource()
	}
	return fmt.Sprintf("%T", g)
}

// isContextErr reports whether err was caused by context cancellation or a deadline.
func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
