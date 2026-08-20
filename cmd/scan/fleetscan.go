package scan

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/spf13/cobra"
)

// validateKubeContextsSupported rejects --kube-contexts up front for any
// invocation that won't actually reach fleetScan, instead of silently
// accepting the flag and scanning only one (default) context - the same
// silently-wrong-cluster failure mode #3217/#3218 closed for sequential
// scans in one process, recurring here as "the flag had no effect."
//
// --kube-contexts is registered on scanCmd's persistent flags, so cobra
// inherits it onto every subcommand (control/framework/workload/image) and
// it's accepted by --view=resource|control too, but only the default
// security view's securityScan currently calls fleetScan. cmd here is the
// actual leaf command being invoked (cobra passes the target command to an
// inherited PersistentPreRunE, not the command it's defined on), so
// cmd.Name() reliably reports which one that is.
func validateKubeContextsSupported(cmd *cobra.Command, scanInfo *cautils.ScanInfo) error {
	if len(scanInfo.KubeContexts) == 0 {
		return nil
	}
	switch cmd.Name() {
	case "scan":
		if scanInfo.View != string(cautils.SecurityViewType) {
			return fmt.Errorf("--kube-contexts is not yet supported with --view=%s; only the default security view (no --view, or --view=%s) supports scanning multiple contexts in one run", scanInfo.View, cautils.SecurityViewType)
		}
	default:
		return fmt.Errorf("--kube-contexts is not yet supported for 'scan %s'; only the default 'scan' command (security view) supports scanning multiple contexts in one run", cmd.Name())
	}
	return nil
}

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

	outputPaths, err := perContextOutputPaths(baseScanInfo.Output, baseScanInfo.KubeContexts)
	if err != nil {
		return err
	}

	var failed []string
	for _, kubeContext := range baseScanInfo.KubeContexts {
		outputPath := outputPaths[kubeContext]

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

// perContextOutputPaths derives every context's own report path from the
// --output the user gave for the fleet as a whole, and rejects the whole
// batch up front if any two contexts would derive the same path. Two
// distinct context names can sanitize to the same string (e.g.
// "prod/us-east-1" and "prod_us-east-1" both become "prod_us-east-1"), which
// would otherwise make the second scan's report silently overwrite the
// first's - both scans "succeed" from fleetScan's point of view, so nothing
// would ever surface the clobbered report as an error. Failing fast here
// with the colliding context names named explicitly is far more useful than
// discovering it later from a report that doesn't match its own context.
func perContextOutputPaths(output string, kubeContexts []string) (map[string]string, error) {
	paths := make(map[string]string, len(kubeContexts))
	collisions := make(map[string][]string) // output path -> contexts that derived it

	for _, kubeContext := range kubeContexts {
		path, err := perContextOutputPath(output, kubeContext)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", kubeContext, err)
		}
		paths[kubeContext] = path
		collisions[path] = append(collisions[path], kubeContext)
	}

	var conflicts []string
	for path, contexts := range collisions {
		if len(contexts) > 1 {
			conflicts = append(conflicts, fmt.Sprintf("%s -> %s", strings.Join(contexts, ", "), path))
		}
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return nil, fmt.Errorf("--kube-contexts: %d context(s) derive a colliding --output path with another context, so their reports would silently overwrite each other:\n%s", len(conflicts), strings.Join(conflicts, "\n"))
	}

	return paths, nil
}

// perContextOutputPath derives context's own report path from the
// --output the user gave for the fleet as a whole, by inserting a
// filesystem-safe form of context before the final extension: report.json +
// "kind-fleet-test-a" -> report.kind-fleet-test-a.json. Path separators in
// context (which kube context names can technically contain, e.g. some
// cloud-provider-generated names) are replaced so the result can't escape
// the output directory or be misread as one. Callers scanning a batch of
// contexts should use perContextOutputPaths instead, which also rejects
// collisions between two different contexts' derived paths.
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
