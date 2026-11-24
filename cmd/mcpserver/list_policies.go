package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/core"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/maruel/natural"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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

func (ksServer *KubescapeMcpserver) ListFrameworks(ctx context.Context, search string) ([]byte, error) {
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
	sort.Slice(sorted, func(i, j int) bool {
		return natural.Less(sorted[i], sorted[j])
	})
	if term := strings.ToLower(strings.TrimSpace(search)); term != "" {
		filtered := make([]string, 0, len(sorted))
		for _, name := range sorted {
			if strings.Contains(strings.ToLower(name), term) {
				filtered = append(filtered, name)
			}
		}
		sorted = filtered
	}
	return json.Marshal(sorted)
}

// ListControlsConfig lists configurable control parameters, their resolved
// values, descriptions, and the security controls that consume them.
// Optional controlID filters to entries affecting a specific control;
// optional search filters across name, title, description, or control IDs.
func (ksServer *KubescapeMcpserver) ListControlsConfig(ctx context.Context, search, controlID string) ([]byte, error) {
	pg, err := ksServer.readyPolicyGetter(ctx)
	if err != nil {
		return nil, err
	}

	var values map[string][]string
	if k8sClient, err := ksServer.getK8sClient(); err == nil && k8sClient != nil {
		crdInputs, err := getter.NewCRDControlInputsWithClient(k8sClient.DynamicClient)
		if err != nil {
			return nil, err
		}
		crdValues, err := crdInputs.GetControlsInputs(ctx, "")
		if err != nil {
			if !isMissingCRDErr(err) {
				return nil, err
			}
		} else {
			values = crdValues
		}
	}
	if values == nil {
		if cig, ok := pg.(getter.IControlsInputsGetter); ok {
			v, err := cig.GetControlsInputs(ctx, "")
			if err != nil {
				return nil, err
			}
			values = v
		}
	}
	if values == nil {
		values = make(map[string][]string)
	}

	frameworks, err := pg.GetFrameworks()
	if err != nil {
		return nil, err
	}

	entries := core.BuildControlsConfigEntries(values, frameworks)
	if controlID != "" {
		entries = filterControlsConfigByControlID(entries, controlID)
	}
	if search != "" {
		entries = filterControlsConfigBySearch(entries, search)
	}

	return json.Marshal(entries)
}

func isMissingCRDErr(err error) bool {
	if err == nil {
		return false
	}
	if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
		return true
	}
	var noResMatch *meta.NoResourceMatchError
	if errors.As(err, &noResMatch) {
		return true
	}
	var noKindMatch *meta.NoKindMatchError
	return errors.As(err, &noKindMatch)
}

func filterControlsConfigByControlID(entries []metav1.ControlConfigEntry, controlID string) []metav1.ControlConfigEntry {
	normID := strings.TrimSpace(controlID)
	if normID == "" {
		return entries
	}
	filtered := make([]metav1.ControlConfigEntry, 0, len(entries))
	for _, entry := range entries {
		for _, cid := range entry.Controls {
			if strings.EqualFold(cid, normID) {
				filtered = append(filtered, entry)
				break
			}
		}
	}
	return filtered
}

func filterControlsConfigBySearch(entries []metav1.ControlConfigEntry, search string) []metav1.ControlConfigEntry {
	term := strings.ToLower(strings.TrimSpace(search))
	if term == "" {
		return entries
	}
	filtered := make([]metav1.ControlConfigEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Name), term) ||
			strings.Contains(strings.ToLower(entry.Title), term) ||
			strings.Contains(strings.ToLower(entry.Description), term) {
			filtered = append(filtered, entry)
			continue
		}
		matchedControl := false
		for _, cid := range entry.Controls {
			if strings.Contains(strings.ToLower(cid), term) {
				matchedControl = true
				break
			}
		}
		if matchedControl {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// ListControls lists a page of available controls, naturally sorted by ID. When
// framework is set, only the controls that belong to it are returned; an
// unknown framework is an *unknownFrameworkError. When search is set, only
// controls matching the query in ID, name, or framework tags are returned.
func (ksServer *KubescapeMcpserver) ListControls(ctx context.Context, framework, search string, limit, offset int) ([]byte, error) {
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
	if search = strings.TrimSpace(search); search != "" {
		entries = filterControlsBySearch(entries, search)
	}
	sort.Slice(entries, func(i, j int) bool {
		return natural.Less(entries[i].ID, entries[j].ID)
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

// filterControlsBySearch filters control entries matching search in their ID,
// name, or framework tags, case-insensitively.
func filterControlsBySearch(entries []metav1.ControlListEntry, search string) []metav1.ControlListEntry {
	searchLower := strings.ToLower(strings.TrimSpace(search))
	if searchLower == "" {
		return entries
	}
	out := make([]metav1.ControlListEntry, 0, len(entries))
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.ID), searchLower) || strings.Contains(strings.ToLower(e.Name), searchLower) {
			out = append(out, e)
			continue
		}
		for _, fw := range e.Frameworks {
			if strings.Contains(strings.ToLower(fw), searchLower) {
				out = append(out, e)
				break
			}
		}
	}
	return out
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
