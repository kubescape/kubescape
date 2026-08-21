package policyhandler

import (
	"errors"
	"strconv"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling"
)

var errAllControlsExcluded = errors.New("--exclude-controls left no controls to scan")

type controlExclusionResult struct {
	policies  []reporthandling.Framework
	excluded  int
	unmatched []string
}

func excludeControls(policies []reporthandling.Framework, exclusions []string) (controlExclusionResult, error) {
	order, display := normalizeExclusions(exclusions)
	if len(order) == 0 {
		return controlExclusionResult{policies: policies}, nil
	}

	wanted := make(map[string]struct{}, len(order))
	for _, token := range order {
		wanted[token] = struct{}{}
	}

	matched := make(map[string]struct{}, len(order))
	filtered := make([]reporthandling.Framework, 0, len(policies))
	excluded, remaining := 0, 0

	for _, framework := range policies {
		kept := make([]reporthandling.Control, 0, len(framework.Controls))
		for _, control := range framework.Controls {
			if markControlMatches(control, wanted, matched) {
				excluded++
				continue
			}
			kept = append(kept, control)
		}
		framework.Controls = kept
		remaining += len(kept)
		filtered = append(filtered, framework)
	}

	if remaining == 0 {
		return controlExclusionResult{}, errAllControlsExcluded
	}

	unmatched := make([]string, 0, len(order))
	for _, token := range order {
		if _, ok := matched[token]; !ok {
			unmatched = append(unmatched, display[token])
		}
	}

	return controlExclusionResult{policies: filtered, excluded: excluded, unmatched: unmatched}, nil
}

func quoteIdentifiers(identifiers []string) string {
	quoted := make([]string, 0, len(identifiers))
	for _, identifier := range identifiers {
		quoted = append(quoted, strconv.Quote(identifier))
	}
	return strings.Join(quoted, ", ")
}

func normalizeExclusions(exclusions []string) ([]string, map[string]string) {
	order := make([]string, 0, len(exclusions))
	display := make(map[string]string, len(exclusions))

	for _, exclusion := range exclusions {
		trimmed := strings.TrimSpace(exclusion)
		if trimmed == "" {
			continue
		}
		token := strings.ToLower(trimmed)
		if _, ok := display[token]; ok {
			continue
		}
		display[token] = trimmed
		order = append(order, token)
	}

	return order, display
}

func markControlMatches(control reporthandling.Control, wanted, matched map[string]struct{}) bool {
	found := false
	for _, identifier := range [2]string{control.ControlID, control.Control_ID} {
		if token, ok := matchIdentifier(identifier, wanted); ok {
			matched[token] = struct{}{}
			found = true
		}
	}
	return found
}

func matchIdentifier(identifier string, wanted map[string]struct{}) (string, bool) {
	token := strings.ToLower(strings.TrimSpace(identifier))
	if token == "" {
		return "", false
	}
	_, ok := wanted[token]
	return token, ok
}
