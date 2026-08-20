package scan

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
)

// fleetScan runs securityScan's per-cluster behavior once for every context
// in baseScanInfo.KubeContexts, sequentially, writing one report per
// context. It's the --kube-contexts entry point invoked from securityScan.
//
// Contexts are scanned one at a time, not concurrently: k8sinterface's
// process-global connection state (K8SConfig, clientConfigAPI,
// clusterContextName) has no locking around it, confirmed by go test -race
// while working on #3237 — running two contexts' scans concurrently would
// race on that state regardless of cautils.EnterClusterContext, which only
// makes *sequential* context switches safe.
//
// One context failing (connection error, threshold breach, degraded policy
// inputs, etc.) does not stop the remaining contexts from being attempted:
// a fleet scan should surface as much of the fleet's posture as it can
// rather than aborting on the first bad cluster. The command's overall
// error - and therefore its exit code - reflects whether any context
// failed, matching the single-context command's existing all-or-nothing
// exit-code semantics from the caller's point of view.
func fleetScan(baseScanInfo cautils.ScanInfo, ks meta.IKubescape, policyIdentifiers []cautils.PolicyIdentifier) error {
	if baseScanInfo.GetScanningContext() != cautils.ContextCluster {
		return fmt.Errorf("--kube-contexts requires a live-cluster scan: it selects which cluster to connect to, so it can't be combined with scanning local files/directories")
	}
	if strings.TrimSpace(baseScanInfo.Output) == "" {
		return fmt.Errorf("--kube-contexts requires --output: each context's report is written to its own file, derived from --output, since only one context's results can be printed to stdout at a time")
	}

	var failed []string
	for _, kubeContext := range baseScanInfo.KubeContexts {
		outputPath, err := perContextOutputPath(baseScanInfo.Output, kubeContext)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %s", kubeContext, err))
			logger.L().Error("fleet scan: skipping context, could not derive an output path", helpers.String("context", kubeContext), helpers.Error(err))
			continue
		}

		contextScanInfo := baseScanInfo.CloneForContext(kubeContext, outputPath)

		logger.L().Info("fleet scan: scanning context", helpers.String("context", kubeContext), helpers.String("output", outputPath))

		leave := cautils.EnterClusterContext(kubeContext)
		ctx, cancel := deriveTimeoutContext(contextScanInfo, ks)
		err = runSecurityScan(ctx, contextScanInfo, ks, policyIdentifiers)
		cancel()
		leave()

		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %s", kubeContext, err))
			logger.L().Error("fleet scan: context failed", helpers.String("context", kubeContext), helpers.Error(err))
			continue
		}
		logger.L().Success("fleet scan: context completed", helpers.String("context", kubeContext))
	}

	if len(failed) > 0 {
		return fmt.Errorf("fleet scan: %d of %d context(s) failed:\n%s", len(failed), len(baseScanInfo.KubeContexts), strings.Join(failed, "\n"))
	}
	return nil
}

// perContextOutputPath derives context's own report path from the
// --output the user gave for the fleet as a whole, by inserting a
// filesystem-safe form of context before the final extension: report.json +
// "kind-fleet-test-a" -> report.kind-fleet-test-a.json. Path separators in
// context (which kube context names can technically contain, e.g. some
// cloud-provider-generated names) are replaced so the result can't escape
// the output directory or be misread as one.
func perContextOutputPath(output, kubeContext string) (string, error) {
	sanitized := strings.NewReplacer("/", "_", "\\", "_", string(filepath.Separator), "_").Replace(kubeContext)
	sanitized = strings.TrimSpace(sanitized)
	if sanitized == "" {
		return "", fmt.Errorf("empty kube context name")
	}

	dir, base := filepath.Split(output)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, stem+"."+sanitized+ext), nil
}
