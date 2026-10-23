package mcpserver

import (
	"sort"
	"strings"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// configScanSummaryEntry is the configuration scan result of one resource,
// read from its WorkloadConfigurationScanSummary. Summaries are stored on
// every install; the full WorkloadConfigurationScan is stored only when
// continuous posture scanning is on.
type configScanSummaryEntry struct {
	Namespace    string `json:"namespace"`
	ManifestName string `json:"manifest_name"`
	// Kind, Name and WorkloadNamespace identify the scanned resource. For
	// RBAC and cluster-scoped resources the summary is stored in the
	// Kubescape namespace, so Namespace is not the resource's namespace.
	Kind string `json:"kind,omitempty"`
	// Name is the exact resource name, set only when the WLID annotation
	// names the resource. Otherwise NameLabel holds the name label, which
	// the producer turns into a valid label value (invalid characters
	// replaced, lowercased, cut to 63 characters), so it may differ.
	Name              string                  `json:"name,omitempty"`
	NameLabel         string                  `json:"name_label,omitempty"`
	WorkloadNamespace string                  `json:"workload_namespace,omitempty"`
	FailedControls    []configScanFailedEntry `json:"failed_controls"`
	// StatusCounts counts every control in the summary by status, before
	// min_severity is applied.
	StatusCounts map[string]int `json:"status_counts"`
}

type configScanFailedEntry struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
}

type configScanSummaryListResponse struct {
	Summaries []configScanSummaryEntry `json:"summaries"`
	Continue  string                   `json:"continue,omitempty"`
}

// listConfigScanSummaryEntries turns summaries into entries, most severe
// failed control first. With a minimum severity, failed controls below it
// are left out, and so are resources with no failed control left.
func listConfigScanSummaryEntries(items []v1beta1.WorkloadConfigurationScanSummary, minSeverity vulnexposure.Severity) []configScanSummaryEntry {
	entries := make([]configScanSummaryEntry, 0, len(items))
	for _, item := range items {
		failed := []configScanFailedEntry{}
		counts := map[string]int{}
		for id, control := range item.Spec.Controls {
			status := strings.ToLower(control.Status.Status)
			counts[status]++
			if status != string(apis.StatusFailed) {
				continue
			}
			if vulnexposure.ParseSeverity(control.Severity.Severity) < minSeverity {
				continue
			}
			failed = append(failed, configScanFailedEntry{ID: id, Severity: control.Severity.Severity})
		}
		if minSeverity != vulnexposure.SeverityUnknown && len(failed) == 0 {
			continue
		}
		sort.Slice(failed, func(i, j int) bool {
			si, sj := vulnexposure.ParseSeverity(failed[i].Severity), vulnexposure.ParseSeverity(failed[j].Severity)
			if si != sj {
				return si > sj
			}
			return failed[i].ID < failed[j].ID
		})
		labels := item.GetLabels()
		entry := configScanSummaryEntry{
			Namespace:         item.Namespace,
			ManifestName:      item.Name,
			Kind:              labels[helpersv1.RelatedKindMetadataKey],
			WorkloadNamespace: labels[helpersv1.RelatedNamespaceMetadataKey],
			FailedControls:    failed,
			StatusCounts:      counts,
		}
		if name, ok := resourceNameFromWlid(item.GetAnnotations()[helpersv1.WlidMetadataKey], entry.Kind); ok {
			entry.Name = name
		} else {
			entry.NameLabel = labels[helpersv1.RelatedNameMetadataKey]
		}
		entries = append(entries, entry)
	}
	return entries
}

// resourceNameFromWlid returns the name in a WLID such as
// wlid://cluster-c/namespace-ns/deployment-web if the WLID is of the given
// kind. RBAC summaries carry the WLID of the binding, not of the subject.
func resourceNameFromWlid(wlid, kind string) (string, bool) {
	if wlid == "" || kind == "" {
		return "", false
	}
	// Resource names cannot contain "/"; cluster names can.
	last := wlid[strings.LastIndex(wlid, "/")+1:]
	name, ok := strings.CutPrefix(last, strings.ToLower(kind)+"-")
	if !ok || name == "" {
		return "", false
	}
	return name, true
}
