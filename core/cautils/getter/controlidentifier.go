package getter

import (
	"strings"

	"github.com/kubescape/opa-utils/reporthandling"
)

// controlMatcher resolves a user-supplied control identifier against candidate
// controls. It accepts the two identifiers of cautils.ControlIdentifiers (which
// getter cannot import): the Kubescape control ID (ControlID, e.g. "C-0286")
// and, where the control carries one, its framework section number (Control_ID,
// e.g. "CIS-3.1.1"). It also accepts the control name (e.g. "Privileged
// container"), which the scan control help advertises. Matching is
// case-insensitive and ignores surrounding whitespace.
//
// A control ID is unique, so it always wins. A section number or a name is only
// accepted when every control that carries it is the same control; two
// different controls sharing one is reported as ErrControlAmbiguous rather than
// resolved to whichever was seen first.
type controlMatcher struct {
	id       string
	sections []reporthandling.Control // distinct by ControlID; matched by section number or name
}

func newControlMatcher(id string) *controlMatcher {
	return &controlMatcher{id: normalizeControlIdentifier(id)}
}

func normalizeControlIdentifier(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

// offer considers one candidate. It reports true when the candidate's control
// ID is the identifier, in which case the caller can stop searching.
func (m *controlMatcher) offer(control *reporthandling.Control) bool {
	if normalizeControlIdentifier(control.ControlID) == m.id {
		return true
	}
	if normalizeControlIdentifier(control.Control_ID) != m.id && normalizeControlIdentifier(control.Name) != m.id {
		return false
	}
	for i := range m.sections {
		if strings.EqualFold(m.sections[i].ControlID, control.ControlID) {
			return false
		}
	}
	m.sections = append(m.sections, *control)
	return false
}

// bySection returns the control the identifier names by section number or
// name. It returns (nil, nil) when no candidate carried it.
func (m *controlMatcher) bySection() (*reporthandling.Control, error) {
	switch len(m.sections) {
	case 0:
		return nil, nil
	case 1:
		control := m.sections[0]
		return &control, nil
	}
	ids := make([]string, len(m.sections))
	for i := range m.sections {
		ids[i] = m.sections[i].ControlID
	}
	return nil, &AmbiguousControlError{Identifier: strings.TrimSpace(m.id), Matches: ids}
}
