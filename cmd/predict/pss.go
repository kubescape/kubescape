package predict

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/pss"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type pssFlags struct {
	namespace string
	level     string
	workload  string
	format    string
	output    string
	verbose   bool
}

var pssCmdExamples = fmt.Sprintf(`
  Predict Pod Security Standards compliance for workloads.

  # Predict Restricted compliance for all workloads in production namespace
  %[1]s predict pss -n production

  # Predict Baseline compliance only
  %[1]s predict pss -n production --level Baseline

  # Check a specific workload
  %[1]s predict pss -n production --workload Deployment/legacy-api

  # Scan local manifest files
  %[1]s predict pss ./manifests/

  # Scan and output JSON
  %[1]s predict pss -n production -f json -o pss-report.json

  # Scan and output JUnit XML for CI/CD
  %[1]s predict pss ./manifests/ -f junit -o pss-results.xml

  # Scan and output SARIF for GitHub Code Scanning
  %[1]s predict pss ./manifests/ -f sarif -o pss.sarif
`, cautils.ExecName())

func getPSSCmd() *cobra.Command {
	flags := &pssFlags{}

	pssCmd := &cobra.Command{
		Use:   "pss [<path>...] [flags]",
		Short: "Predict Pod Security Standards (PSS) compliance for workloads",
		Long: `Evaluate workloads against the Kubernetes Pod Security Standards (Privileged,
Baseline, Restricted) and report which workloads would fail at the target
level, what specifically violates, and overall namespace readiness.

When run without positional arguments, scans live cluster workloads in the
specified namespace. When given file paths or directories, scans local YAML
manifests instead.

This helps answer: "What would break if I enforced Baseline/Restricted on
this namespace?" — without touching the cluster's admission configuration.`,
		Example: pssCmdExamples,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runPSS(cmd.Context(), flags, args)
		},
	}

	pssCmd.Flags().StringVarP(&flags.namespace, "namespace", "n", "", "Namespace to evaluate (cluster mode; required when no paths are given)")
	pssCmd.Flags().StringVar(&flags.level, "level", "Restricted", "Target PSS level: Privileged, Baseline, or Restricted")
	pssCmd.Flags().StringVar(&flags.workload, "workload", "", "Filter to a specific workload (Kind/Name or bare Name)")
	pssCmd.Flags().StringVarP(&flags.format, "format", "f", "pretty-printer", `Output format: "pretty-printer", "json", "table", "sarif", "junit"`)
	pssCmd.Flags().StringVarP(&flags.output, "output", "o", "", "Output file path (default: stdout)")
	pssCmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Show passing workloads in addition to failing ones")

	return pssCmd
}

// pssFormats lists supported output formats for the predict pss command.
var pssFormats = []string{"pretty-printer", "json", "table", "sarif", "junit"}

func runPSS(ctx context.Context, flags *pssFlags, args []string) error {
	// Validate level
	targetLevel, ok := pss.ParseLevel(flags.level)
	if !ok {
		return fmt.Errorf("invalid PSS level %q; must be one of Privileged, Baseline, Restricted", flags.level)
	}

	// Validate format
	formatLower := strings.ToLower(flags.format)
	validFormat := false
	for _, f := range pssFormats {
		if formatLower == f {
			validFormat = true
			break
		}
	}
	if !validFormat {
		return fmt.Errorf("unsupported format %q; supported: %s", flags.format, strings.Join(pssFormats, ", "))
	}

	// Determine mode: cluster vs. local
	isClusterMode := len(args) == 0

	var workloads []unstructured.Unstructured
	var namespace string
	var err error

	if isClusterMode {
		if flags.namespace == "" {
			return fmt.Errorf("--namespace (-n) is required when scanning a live cluster (no file paths provided)")
		}
		namespace = flags.namespace
		workloads, err = fetchClusterWorkloadsFn(ctx, namespace, flags.workload)
		if err != nil {
			return err
		}
	} else {
		workloads, err = pss.ParseLocalWorkloads(args)
		if err != nil {
			return err
		}
		namespace = flags.namespace // may be empty for local scans
		if namespace != "" {
			var scoped []unstructured.Unstructured
			for _, w := range workloads {
				if w.GetNamespace() == "" || w.GetNamespace() == namespace {
					scoped = append(scoped, w)
				}
			}
			workloads = scoped
		}

		// Apply workload filter if specified
		if flags.workload != "" {
			workloads = filterWorkloads(workloads, flags.workload)
			if len(workloads) == 0 {
				return fmt.Errorf("workload %q not found in the provided manifests", flags.workload)
			}
		}
	}

	// Deduplicate in cluster mode (local files rarely have owner refs)
	if isClusterMode && flags.workload == "" {
		workloads = pss.DeduplicateWorkloads(workloads)
	}

	// Sort for deterministic output
	sort.Slice(workloads, func(i, j int) bool {
		if workloads[i].GetKind() != workloads[j].GetKind() {
			return workloads[i].GetKind() < workloads[j].GetKind()
		}
		return workloads[i].GetName() < workloads[j].GetName()
	})

	// Aggregate results
	result := pss.Aggregate(namespace, workloads, targetLevel)

	// Write output
	if err := writeOutput(result, formatLower, flags.output, flags.verbose); err != nil {
		return err
	}

	// Return error if any workloads fail (triggers exit code 1)
	if result.HasFailures() {
		return fmt.Errorf("PSS compliance check failed: %d/%d workload(s) violated target level %s",
			result.FailingWorkloads, result.TotalWorkloads, result.TargetLevel.String())
	}
	if result.UnevaluatedWorkloads > 0 {
		return fmt.Errorf("PSS evaluation incomplete: %d/%d workload(s) could not be evaluated",
			result.UnevaluatedWorkloads, result.TotalWorkloads)
	}
	return nil
}

// fetchClusterWorkloads connects to the cluster and lists workloads.
func fetchClusterWorkloads(ctx context.Context, namespace, workloadFilter string) ([]unstructured.Unstructured, error) {
	if err := k8sinterface.LoadK8sConfig(); err != nil {
		return nil, fmt.Errorf("cannot connect to cluster: ensure KUBECONFIG is set or running inside a cluster: %w", err)
	}
	k8sinterface.SetConnectedToCluster(true)
	k8sClient := k8sinterface.NewKubernetesApi()

	targets := pss.DefaultWorkloadTargets
	var filterKind string
	if workloadFilter != "" && strings.Contains(workloadFilter, "/") {
		parts := strings.SplitN(workloadFilter, "/", 2)
		filterKind = strings.TrimSpace(parts[0])
		if filterKind != "" {
			if filtered := pss.FilterTargetsByKind(targets, filterKind); filtered != nil {
				targets = filtered
			}
		}
	}

	workloads, err := pss.FetchNamespaceWorkloads(
		ctx,
		k8sClient.DynamicClient,
		namespace,
		targets,
	)
	if err != nil {
		return nil, err
	}

	// Apply workload name filter
	if workloadFilter != "" {
		workloads = filterWorkloads(workloads, workloadFilter)
		if len(workloads) == 0 {
			return nil, fmt.Errorf("workload %q not found in namespace %q", workloadFilter, namespace)
		}
	}

	return workloads, nil
}

// filterWorkloads filters workloads by a "Kind/Name" or bare "Name" string.
func filterWorkloads(workloads []unstructured.Unstructured, filter string) []unstructured.Unstructured {
	var filterKind, filterName string
	if strings.Contains(filter, "/") {
		parts := strings.SplitN(filter, "/", 2)
		filterKind = strings.TrimSpace(parts[0])
		filterName = strings.TrimSpace(parts[1])
	} else {
		filterName = filter
	}

	var selected []unstructured.Unstructured
	for _, w := range workloads {
		nameMatches := w.GetName() == filterName
		kindMatches := filterKind == "" || strings.EqualFold(w.GetKind(), filterKind)
		if nameMatches && kindMatches {
			selected = append(selected, w)
		}
	}
	return selected
}
