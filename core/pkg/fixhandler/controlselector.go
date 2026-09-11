package fixhandler

import "strings"

// controlSelector decides which failed controls a fix run remediates. A nil
// include set selects every control; skip always wins over include, matching
// the scan-side --include-controls/--skip-controls precedence.
type controlSelector struct {
	include map[string]struct{}
	skip    map[string]struct{}
}

func newControlSelector(include, skip []string) controlSelector {
	return controlSelector{
		include: normalizeControlIDs(include),
		skip:    normalizeControlIDs(skip),
	}
}

func normalizeControlIDs(ids []string) map[string]struct{} {
	if len(ids) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if token := strings.ToLower(strings.TrimSpace(id)); token != "" {
			set[token] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func (cs controlSelector) selects(controlID string) bool {
	token := strings.ToLower(strings.TrimSpace(controlID))
	if _, skipped := cs.skip[token]; skipped {
		return false
	}
	if cs.include == nil {
		return true
	}
	_, included := cs.include[token]
	return included
}

func (cs controlSelector) active() bool {
	return cs.include != nil || cs.skip != nil
}

func (cs controlSelector) describe() string {
	switch {
	case cs.include != nil && cs.skip != nil:
		return "--include-controls/--skip-controls"
	case cs.include != nil:
		return "--include-controls"
	default:
		return "--skip-controls"
	}
}
