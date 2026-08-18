package mcpserver

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
)

func (ksServer *KubescapeMcpserver) ListFrameworks(ctx context.Context) ([]byte, error) {
	pg := ksServer.policyGetter
	if pg == nil {
		pg = getter.NewDownloadReleasedPolicy()
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

func (ksServer *KubescapeMcpserver) ListControls(ctx context.Context) ([]byte, error) {
	pg := ksServer.policyGetter
	if pg == nil {
		pg = getter.NewDownloadReleasedPolicy()
	}
	pipes, err := pg.ListControls()
	if err != nil {
		return nil, err
	}
	entries := make([]metav1.ControlListEntry, 0, len(pipes))
	for _, pipe := range pipes {
		entries = append(entries, parsePolicyPipe(pipe))
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})
	return json.Marshal(entries)
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
