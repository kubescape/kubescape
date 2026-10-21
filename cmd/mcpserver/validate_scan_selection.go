package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
)

// resolvedControl is one identifier that resolved to a control.
type resolvedControl struct {
	Input     string `json:"input"`
	ControlID string `json:"control_id"`
}

// ambiguousControl is an identifier that names more than one control.
type ambiguousControl struct {
	Input   string   `json:"input"`
	Matches []string `json:"matches"`
}

// duplicateControl is an identifier for a control that an earlier identifier
// in the same selection already named.
type duplicateControl struct {
	Input        string `json:"input"`
	MatchesInput string `json:"matches_input"`
	ControlID    string `json:"control_id"`
}

// scanSelectionValidation is the validate_scan_selection result. Valid is true
// when every identifier resolved to exactly one control; duplicates alone do
// not make a selection invalid, because scan_controls scans such a control once.
type scanSelectionValidation struct {
	Valid      bool               `json:"valid"`
	Resolved   []resolvedControl  `json:"resolved"`
	Unknown    []string           `json:"unknown"`
	Ambiguous  []ambiguousControl `json:"ambiguous"`
	Duplicates []duplicateControl `json:"duplicates"`
}

// ValidateScanSelection reports how each of controlIDs resolves against the
// server's policy catalog, with the resolver scan_controls uses
// (getter.ResolveControl). It runs no scan and builds no Kubernetes client.
//
// Unknown and ambiguous identifiers are reported and do not stop the check. Any
// other failure, including the catalog still loading, is returned as an error:
// it says nothing about the identifiers, so it must not be reported as one.
func (ksServer *KubescapeMcpserver) ValidateScanSelection(ctx context.Context, controlIDs []string) ([]byte, error) {
	pg, err := ksServer.readyPolicyGetter(ctx)
	if err != nil {
		return nil, err
	}

	result := scanSelectionValidation{
		Resolved:   []resolvedControl{},
		Unknown:    []string{},
		Ambiguous:  []ambiguousControl{},
		Duplicates: []duplicateControl{},
	}
	firstInput := map[string]string{} // lowercased ControlID -> first input naming it
	seenUnknown := map[string]bool{}
	for _, id := range controlIDs {
		control, err := getter.ResolveControl(pg, id)
		var ambiguous *getter.AmbiguousControlError
		switch {
		case err == nil:
			key := strings.ToLower(control.ControlID)
			if first, dup := firstInput[key]; dup {
				result.Duplicates = append(result.Duplicates, duplicateControl{Input: id, MatchesInput: first, ControlID: control.ControlID})
				continue
			}
			firstInput[key] = id
			result.Resolved = append(result.Resolved, resolvedControl{Input: id, ControlID: control.ControlID})
		case errors.Is(err, getter.ErrControlNotFound):
			if key := strings.ToLower(id); !seenUnknown[key] {
				seenUnknown[key] = true
				result.Unknown = append(result.Unknown, id)
			}
		case errors.As(err, &ambiguous):
			result.Ambiguous = append(result.Ambiguous, ambiguousControl{Input: id, Matches: ambiguous.Matches})
		default:
			return nil, err
		}
	}
	result.Valid = len(result.Unknown) == 0 && len(result.Ambiguous) == 0
	return json.MarshalIndent(result, "", "  ")
}

// controlSelectionErrorDetails adds the offending argument, and for an
// ambiguous section number its candidate control IDs, to an INVALID_ARGUMENT
// result. Other errors carry no details.
func controlSelectionErrorDetails(code ErrorCode, err error) map[string]any {
	if code != ErrCodeInvalidArgument {
		return nil
	}
	details := map[string]any{"argument": "control_ids"}
	var ambiguous *getter.AmbiguousControlError
	if errors.As(err, &ambiguous) {
		details["matches"] = ambiguous.Matches
	}
	return details
}
