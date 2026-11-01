package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
)

const (
	defaultControlsListLimit = 100
	maxControlsListLimit     = 500
)

type controlsListResponse struct {
	Total      int                       `json:"total"`
	Returned   int                       `json:"returned"`
	Truncated  bool                      `json:"truncated"`
	NextOffset *int                      `json:"next_offset,omitempty"`
	Controls   []metav1.ControlListEntry `json:"controls"`
}

func (ksServer *KubescapeMcpserver) ListFrameworks(ctx context.Context) ([]byte, error) {
	pg, err := ksServer.readyPolicyGetter(ctx)
	if err != nil {
		return nil, err
	}
	names, err := pg.ListFrameworks()
	if err != nil {
		names = getter.NativeFrameworks
	}
	sorted := make([]string, len(names))
	copy(sorted, names)
	sort.Strings(sorted)
	return json.Marshal(sorted)
}

// ListControls lists a page of available controls, sorted by ID. When
// framework is set, only the controls that belong to it are returned; an
// unknown framework is an *unknownFrameworkError.
func (ksServer *KubescapeMcpserver) ListControls(ctx context.Context, framework string, limit, offset int) ([]byte, error) {
	if limit < 1 || limit > maxControlsListLimit {
		return nil, fmt.Errorf("limit must be between 1 and %d", maxControlsListLimit)
	}
	if offset < 0 {
		return nil, fmt.Errorf("offset must not be negative")
	}
	pg, err := ksServer.readyPolicyGetter(ctx)
	if err != nil {
		return nil, err
	}
	pipes, err := pg.ListControls()
	if err != nil {
		return nil, err
	}
	entries := make([]metav1.ControlListEntry, 0, len(pipes))
	for _, pipe := range pipes {
		entries = append(entries, parsePolicyPipe(pipe))
	}
	if framework != "" {
		// The catalog can name a framework that no control is tagged with
		// yet; that is an empty result, not an unknown framework.
		catalog, catalogErr := pg.ListFrameworks()
		if catalogErr != nil {
			catalog = getter.NativeFrameworks
		}
		entries, err = filterControlsByFramework(entries, framework, catalog)
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})
	response := controlsListResponse{
		Total:    len(entries),
		Controls: []metav1.ControlListEntry{},
	}
	if offset < len(entries) {
		end := len(entries)
		if limit < len(entries)-offset {
			end = offset + limit
		}
		response.Controls = entries[offset:end]
		if end < len(entries) {
			response.Truncated = true
			next := end
			response.NextOffset = &next
		}
	}
	response.Returned = len(response.Controls)
	return json.Marshal(response)
}

// unknownFrameworkError reports a framework name that is neither in the
// catalog nor on any control.
type unknownFrameworkError struct {
	framework string
	supported []string
}

func (e *unknownFrameworkError) Error() string {
	return fmt.Sprintf("unknown framework %q; use one of: %s", e.framework, strings.Join(e.supported, ", "))
}

// filterControlsByFramework keeps the controls that belong to framework,
// matched case-insensitively. An empty framework keeps every control. A
// framework is known if the catalog lists it or a control is tagged with it:
// controls also carry tags such as ClusterScan that list_frameworks does not
// return. A known framework with no controls gives an empty list.
//
// AllControls is every control. It is not matched by tag, because the local
// policy getter used when the released bundle cannot be downloaded leaves the
// AllControls tag off its control entries.
func filterControlsByFramework(entries []metav1.ControlListEntry, framework string, catalog []string) ([]metav1.ControlListEntry, error) {
	if framework == "" || strings.EqualFold(framework, "allcontrols") {
		return entries, nil
	}
	known := map[string]bool{}
	for _, fw := range catalog {
		known[fw] = true
	}
	out := make([]metav1.ControlListEntry, 0)
	for _, e := range entries {
		matched := false
		for _, fw := range e.Frameworks {
			known[fw] = true
			if strings.EqualFold(fw, framework) {
				matched = true
			}
		}
		if matched {
			out = append(out, e)
		}
	}
	for fw := range known {
		if strings.EqualFold(fw, framework) {
			return out, nil
		}
	}
	supported := make([]string, 0, len(known))
	for fw := range known {
		supported = append(supported, fw)
	}
	sort.Strings(supported)
	return nil, &unknownFrameworkError{framework: framework, supported: supported}
}

func parsePolicyPipe(pipe string) metav1.ControlListEntry {
	entry := metav1.ControlListEntry{Frameworks: []string{}}
	if pipe == "" {
		return entry
	}
	before, rest, ok := strings.Cut(pipe, "|")
	if !ok {
		entry.ID = pipe
		return entry
	}
	entry.ID = before
	last := strings.LastIndex(rest, "|")
	if last == -1 {
		entry.Name = rest
		return entry
	}
	entry.Name = rest[:last]
	for _, fw := range strings.Split(rest[last+1:], ",") {
		if fw = strings.TrimSpace(fw); fw != "" {
			entry.Frameworks = append(entry.Frameworks, fw)
		}
	}
	return entry
}
