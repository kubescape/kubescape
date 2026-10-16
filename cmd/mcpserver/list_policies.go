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

// ListControls lists the available controls, sorted by ID. When framework is
// set, only the controls that belong to it are returned; an unknown framework
// is an *unknownFrameworkError.
func (ksServer *KubescapeMcpserver) ListControls(ctx context.Context, framework string) ([]byte, error) {
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
	entries, err = filterControlsByFramework(entries, framework)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})
	return json.Marshal(entries)
}

// unknownFrameworkError reports a framework name that no control belongs to.
type unknownFrameworkError struct {
	framework string
	supported []string
}

func (e *unknownFrameworkError) Error() string {
	return fmt.Sprintf("framework %q has no controls; use one of: %s", e.framework, strings.Join(e.supported, ", "))
}

// filterControlsByFramework keeps the controls that belong to framework,
// matched case-insensitively. An empty framework keeps every control. The
// accepted names are the frameworks that appear on the controls themselves,
// which covers everything list_frameworks returns.
func filterControlsByFramework(entries []metav1.ControlListEntry, framework string) ([]metav1.ControlListEntry, error) {
	if framework == "" {
		return entries, nil
	}
	known := map[string]bool{}
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
	if len(out) == 0 {
		supported := make([]string, 0, len(known))
		for fw := range known {
			supported = append(supported, fw)
		}
		sort.Strings(supported)
		return nil, &unknownFrameworkError{framework: framework, supported: supported}
	}
	return out, nil
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
