package scan

import (
	"context"
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

func validateKubeContextsSupported(cmd *cobra.Command, scanInfo *cautils.ScanInfo) error {
	if len(scanInfo.KubeContexts) == 0 {
		return nil
	}
	switch cmd.Name() {
	case "scan":
		if scanInfo.View != string(cautils.SecurityViewType) {
			return fmt.Errorf("--kube-contexts is not yet supported with --view=%s; only the default security view (no --view, or --view=%s) supports scanning multiple contexts in one run", scanInfo.View, cautils.SecurityViewType)
		}
	case "framework", "control", "workload":
		// supported
	default:
		return fmt.Errorf("--kube-contexts is not yet supported for 'scan %s'", cmd.Name())
	}
	return nil
}

type fleetRunner func(ctx context.Context, scanInfo *cautils.ScanInfo, ks meta.IKubescape, policyIdentifiers []cautils.PolicyIdentifier) error

func fleetScan(baseScanInfo cautils.ScanInfo, ks meta.IKubescape, policyIdentifiers []cautils.PolicyIdentifier, run fleetRunner) error {
	if baseScanInfo.GetScanningContext() != cautils.ContextCluster {
		return fmt.Errorf("--kube-contexts requires a live-cluster scan")
	}
	if strings.TrimSpace(baseScanInfo.Output) == "" {
		return fmt.Errorf("--kube-contexts requires --output")
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
		err = run(ctx, contextScanInfo, ks, policyIdentifiers)
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

func perContextOutputPaths(output string, kubeContexts []string) (map[string]string, error) {
	paths := make(map[string]string, len(kubeContexts))
	collisions := make(map[string][]string)

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
		return nil, fmt.Errorf("--kube-contexts: %d context(s) derive a colliding --output path with another context:\n%s", len(conflicts), strings.Join(conflicts, "\n"))
	}

	return paths, nil
}

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
