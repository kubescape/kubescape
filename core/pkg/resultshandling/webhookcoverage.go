package resultshandling

import (
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/vapreconcile"
	"github.com/kubescape/kubescape/v4/core/pkg/webhookcoverage"
)

// BuildWebhookCoverage runs the resources collected in scanData through the
// admission webhook matcher, exactly as HandleResults does, so a caller that
// does not go through HandleResults (such as the MCP server) gets the same
// analysis. It returns nil when no webhook configurations were collected.
func BuildWebhookCoverage(scanData *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) *webhookcoverage.Analysis {
	return buildWebhookCoverage(scanData, scanInfo)
}

// buildWebhookCoverage runs the collected resources through the admission
// webhook matcher. It returns nil when no webhook configurations were
// collected. The analysis is informational: it is stored on the session and
// never changes control results or exit codes.
func buildWebhookCoverage(scanData *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) *webhookcoverage.Analysis {
	if scanData == nil || scanData.WebhookConfigurations == nil {
		return nil
	}
	catalog := scanData.GetCatalog()

	var subjects []webhookcoverage.Subject
	if catalog != nil {
		catalog.ForEach(func(_ string, res workloadinterface.IMetadata) bool {
			if res == nil {
				return true
			}
			s := webhookcoverage.Subject{
				APIVersion: res.GetApiVersion(),
				Kind:       res.GetKind(),
				Namespace:  res.GetNamespace(),
				Name:       res.GetName(),
			}
			// A collected object's labels are known even when there are none.
			if basic, ok := res.(workloadinterface.IBasicWorkload); ok {
				s.Labels = basic.GetLabels()
				s.LabelsKnown = true
			}
			subjects = append(subjects, s)
			return true
		})
	}

	return webhookcoverage.Analyze(webhookcoverage.Input{
		Collection:       scanData.WebhookConfigurations,
		Subjects:         subjects,
		NamespaceLabels:  vapreconcile.CollectNamespaceLabelsFromCatalog(catalog),
		SubjectsComplete: workloadsFullyCollected(scanData, scanInfo),
	})
}

// workloadsFullyCollected reports whether the scan listed every analyzable
// workload type across the whole cluster. A scan only lists the resources its
// controls query, may be narrowed to some namespaces or by a label selector,
// and may have lost some lists, so absence from the catalog is not absence from the
// cluster unless all of that is ruled out.
func workloadsFullyCollected(scanData *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) bool {
	if scanInfo == nil || scanInfo.IncludeNamespaces != "" || scanInfo.ExcludedNamespaces != "" ||
		scanInfo.LabelSelector != "" || scanInfo.ScanObject != nil || scanData.SingleResourceScan != nil {
		return false
	}
	if len(scanData.PartialGVRFailures) > 0 || len(scanData.ScanCoverage.FailedGVRPulls) > 0 || len(scanData.ScanCoverage.PartialGVRPulls) > 0 {
		return false
	}
	for _, key := range webhookcoverage.WorkloadResourceKeys() {
		if !scanData.ListedGVRs[key] {
			return false
		}
	}
	return true
}
