package getter

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling"
)

// ErrControlNotFound is matched, with errors.Is, by the error a getter returns
// when no control carries the requested identifier. It is distinct from a
// failure to read the policy catalog, which never matches it.
var ErrControlNotFound = errors.New("control not found")

// controlNotFoundError marks cause as ErrControlNotFound without changing its
// message, so existing output and the original sentinel (for example
// ErrControlNotMatching) keep working.
type controlNotFoundError struct{ cause error }

func (e *controlNotFoundError) Error() string   { return e.cause.Error() }
func (e *controlNotFoundError) Unwrap() []error { return []error{ErrControlNotFound, e.cause} }

// AmbiguousControlError reports a section number carried by more than one
// control. It matches ErrControlAmbiguous with errors.Is.
type AmbiguousControlError struct {
	// Identifier is the normalized section number that was requested.
	Identifier string
	// Matches holds the control IDs that carry it.
	Matches []string
}

func (e *AmbiguousControlError) Error() string {
	return fmt.Sprintf("%v: %q is the section number of %s", ErrControlAmbiguous, e.Identifier, strings.Join(e.Matches, ", "))
}

func (e *AmbiguousControlError) Unwrap() error { return ErrControlAmbiguous }

// ResolveControl resolves one user-supplied control identifier, a control ID
// or a framework section number, with the policy getter's own GetControl, so
// every caller sees the same matching rules. It returns:
//
//   - ErrIDRequired for an empty or whitespace-only identifier, as the getters
//     report it;
//   - an error matching ErrControlNotFound when no control carries it;
//   - an *AmbiguousControlError when several controls share the section number;
//   - any other getter error unchanged, for example a catalog failure, so it
//     can never be mistaken for an unknown control.
func ResolveControl(pg IPolicyGetter, identifier string) (*reporthandling.Control, error) {
	control, err := pg.GetControl(identifier)
	if err != nil {
		return nil, err
	}
	if control == nil {
		return nil, &controlNotFoundError{cause: fmt.Errorf("control '%s' not found", strings.TrimSpace(identifier))}
	}
	return control, nil
}
