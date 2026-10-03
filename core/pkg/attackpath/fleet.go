package attackpath

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// ClusterPathResult holds the attack-path SearchResult for one cluster,
// alongside the cluster's context name and any warnings produced during
// collection. It is the attack-path equivalent of fleet.ClusterResult.
type ClusterPathResult struct {
	// Context is the kubeconfig context name that was scanned.
	Context string `json:"context"`
	// Status mirrors fleet.ClusterScanStatus semantics: scanned, error,
	// unreachable, or cancelled.
	Status string `json:"status"`
	// Error is the scan error message when Status != "scanned".
	Error string `json:"error,omitempty"`
	// Result is populated only when Status == "scanned".
	Result SearchResult `json:"result,omitempty"`
	// Warnings are non-fatal collection warnings for this cluster.
	Warnings []string `json:"warnings,omitempty"`
	// Fingerprints is FingerprintResult(Result), pre-computed for the
	// rollup so the rollup never needs to recompute them.
	Fingerprints []Fingerprint `json:"fingerprints,omitempty"`
}

// FleetPathReport is the cross-cluster attack-path view produced by
// RollupFleetPaths. It mirrors the shape of fleet.FleetReport but
// contains attack paths instead of posture controls.
type FleetPathReport struct {
	Metadata FleetPathMetadata   `json:"metadata"`
	Clusters []ClusterPathResult `json:"clusters"`
	// SharedPaths lists fingerprints that appear in every scanned cluster,
	// sorted for determinism. A path that is universal is the highest
	// priority to fix: it is not confined to one cluster.
	SharedPaths []Fingerprint `json:"shared_paths"`
	// UniquePaths maps each fingerprint to the list of contexts it appears
	// in, for fingerprints that do not appear in every cluster. Sorted by
	// fingerprint for determinism.
	UniquePaths map[Fingerprint][]string `json:"unique_paths"`
	// TotalPathsAcrossClusters is the sum of paths found across all
	// scanned clusters before deduplication.
	TotalPathsAcrossClusters int `json:"total_paths_across_clusters"`
	// Truncated is true when any cluster's SearchResult was truncated.
	Truncated bool `json:"truncated"`
}

// FleetPathMetadata describes the fleet-path scan run.
type FleetPathMetadata struct {
	GeneratedAt time.Time `json:"generated_at"`
	Contexts    []string  `json:"contexts"`
}

// RollupFleetPaths aggregates per-cluster attack-path results into one
// FleetPathReport. It follows the same design principles as
// core/pkg/fleet.BuildComplianceRollup:
//   - A cluster that was not scanned keeps its entry (Status != "scanned")
//     so the report is visibly incomplete rather than silently so.
//   - Measurements never taken are absent, not zero.
//   - All output is sorted for determinism.
func RollupFleetPaths(contexts []string, results []ClusterPathResult) FleetPathReport {
	report := FleetPathReport{
		Metadata: FleetPathMetadata{
			GeneratedAt: time.Now().UTC(),
			Contexts:    contexts,
		},
		UniquePaths: make(map[Fingerprint][]string),
	}

	// Sort clusters by context for determinism.
	sorted := make([]ClusterPathResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Context < sorted[j].Context
	})
	report.Clusters = sorted

	// Build fingerprint → []context index across scanned clusters only.
	fpContexts := make(map[Fingerprint][]string)
	scannedContexts := make([]string, 0)

	for _, cr := range sorted {
		if cr.Status != "scanned" {
			continue
		}
		scannedContexts = append(scannedContexts, cr.Context)
		report.TotalPathsAcrossClusters += len(cr.Result.Paths)
		if cr.Result.Truncated {
			report.Truncated = true
		}
		for _, fp := range cr.Fingerprints {
			fpContexts[fp] = append(fpContexts[fp], cr.Context)
		}
	}

	// Classify: shared (in every scanned cluster) vs unique.
	total := len(scannedContexts)
	for fp, ctxs := range fpContexts {
		// Sort context list for determinism.
		sort.Strings(ctxs)
		if total > 0 && len(ctxs) == total {
			report.SharedPaths = append(report.SharedPaths, fp)
		} else {
			report.UniquePaths[fp] = ctxs
		}
	}
	sort.Slice(report.SharedPaths, func(i, j int) bool {
		return report.SharedPaths[i] < report.SharedPaths[j]
	})

	return report
}

// WriteFleetPathReport serialises report as indented JSON to path.
// The file is written atomically via a temp file so a partial write
// cannot corrupt an existing report.
func WriteFleetPathReport(path string, report FleetPathReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling fleet path report: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing fleet path report to %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming fleet path report to %q: %w", path, err)
	}
	return nil
}
